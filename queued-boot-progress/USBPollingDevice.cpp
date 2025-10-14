/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "BootProgressManager.hpp"
#include "PollingDevice.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>

USBPollingDevice::USBPollingDevice(const uint8_t& bus,
                                   const uint8_t& deviceAddress) :
    bus(bus), deviceAddress(deviceAddress), ctx(nullptr), devHandle(nullptr)
{
    if (libusb_init(&ctx) < 0)
    {
        lg2::error("USBPollingDevice: Failed to initialize libusb");
        ctx = nullptr;
        return;
    }
    libusb_device** deviceList = nullptr;
    ssize_t count = libusb_get_device_list(ctx, &deviceList);
    if (count < 0)
    {
        lg2::error("USBPollingDevice: Failed to get USB device list");
        libusb_exit(ctx);
        ctx = nullptr;
        return;
    }
    libusb_device* device = nullptr;
    bool found = false;
    for (ssize_t i = 0; i < count; ++i)
    {
        device = deviceList[i];
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(device, &desc) == 0 &&
            libusb_get_bus_number(device) == bus &&
            libusb_get_device_address(device) == deviceAddress)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        lg2::error(
            "USBPollingDevice: No USB device found with bus {BUS} and address {ADDRESS}",
            "BUS", this->bus, "ADDRESS", this->deviceAddress);
        libusb_free_device_list(deviceList, 1);
        libusb_exit(ctx);
        ctx = nullptr;
        return;
    }
    if (libusb_open(device, &devHandle) < 0)
    {
        lg2::error("USBPollingDevice: Failed to open USB device");
        libusb_free_device_list(deviceList, 1);
        libusb_exit(ctx);
        ctx = nullptr;
        return;
    }
    libusb_free_device_list(deviceList, 1);
}

USBPollingDevice::~USBPollingDevice()
{
    if (devHandle)
    {
        libusb_close(devHandle);
    }
    if (ctx)
    {
        libusb_exit(ctx);
        ctx = nullptr;
    }
}

bool USBPollingDevice::readRegisterValue(uint32_t regAddr, uint32_t& regValue)
{
    if (!devHandle)
    {
        lg2::error("USB device not opened");
        return false;
    }
    static constexpr uint8_t readLength = 4;
    std::string regAddrStr = std::format("0x{:08X}", regAddr);
    std::array<uint8_t, readLength> readData{};
    constexpr uint8_t bmRequestType = 0xC0;
    constexpr uint8_t bRequest = 0x00;
    uint16_t wValue = static_cast<uint16_t>((regAddr >> 16) & 0xFFFF);
    uint16_t wIndex = static_cast<uint16_t>(regAddr & 0xFFFF);
    constexpr unsigned int timeoutMs = 1000;
    int transferLength =
        libusb_control_transfer(devHandle, bmRequestType, bRequest, wValue,
                                wIndex, readData.data(), readLength, timeoutMs);
    if (transferLength < 0)
    {
        lg2::error("Failed to read register {REG_ADDR}: {ERROR}", "REG_ADDR",
                   regAddrStr, "ERROR", transferLength);
        return false;
    }
    if (transferLength != readLength)
    {
        lg2::error("Failed to read register {REG_ADDR}: {ERROR}", "REG_ADDR",
                   regAddrStr, "ERROR", transferLength);
        return false;
    }
    regValue = (static_cast<uint32_t>(readData[3]) << 24) |
               (static_cast<uint32_t>(readData[2]) << 16) |
               (static_cast<uint32_t>(readData[1]) << 8) |
               static_cast<uint32_t>(readData[0]);
    return true;
}

USBDeviceEnumerator::USBDeviceEnumerator(
    sdbusplus::async::context& ctx, std::shared_ptr<BootProgressManager> mgr,
    uint16_t vendorId, uint16_t productId,
    std::chrono::seconds rescanInterval) :
    PollingDeviceEnumerator(ctx, mgr), vendorId(vendorId), productId(productId),
    rescanInterval(rescanInterval)
{
    if (libusb_init(&usbCtx) < 0)
    {
        lg2::error("USBDeviceEnumerator: failed to init libusb");
        usbCtx = nullptr;
    }
    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG))
    {
        lg2::error("USBDeviceEnumerator: hotplug not supported");
        hotplugSupported = false;
        return;
    }
    hotplugSupported = true;
    int rc = libusb_hotplug_register_callback(
        usbCtx,
        (libusb_hotplug_event)(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
                               LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
        (libusb_hotplug_flag)0, vendorId, productId, LIBUSB_HOTPLUG_MATCH_ANY,
        hotplugCallback, this, &cbHandle);
    if (rc != LIBUSB_SUCCESS)
    {
        lg2::error("USBDeviceEnumerator: failed to register hotplug callback");
        return;
    }
}

USBDeviceEnumerator::~USBDeviceEnumerator()
{
    if (cbHandle)
    {
        libusb_hotplug_deregister_callback(usbCtx, cbHandle);
    }
    if (usbCtx)
    {
        libusb_exit(usbCtx);
    }
}

int LIBUSB_CALL USBDeviceEnumerator::hotplugCallback(
    libusb_context*, libusb_device* dev, libusb_hotplug_event event,
    void* userData)
{
    auto* self = static_cast<USBDeviceEnumerator*>(userData);
    self->handleHotplug(dev, event);
    return 0;
}

void USBDeviceEnumerator::handleHotplug(libusb_device* dev,
                                        libusb_hotplug_event event)
{
    libusb_device_descriptor desc{};
    if (libusb_get_device_descriptor(dev, &desc) != 0)
    {
        lg2::error("USBEnumerator: failed to get device descriptor");
        return;
    }

    if (desc.idVendor != vendorId || desc.idProduct != productId)
    {
        return;
    }

    uint8_t bus = libusb_get_bus_number(dev);
    uint8_t addr = libusb_get_device_address(dev);

    if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED)
    {
        lg2::info("USB device arrived: bus {BUS}, addr {ADDR}", "BUS",
                  static_cast<int>(bus), "ADDR", static_cast<int>(addr));
        int socketId = addDeviceAndGetSocketId(bus, addr);
        manager->onDeviceAdded(TransportInterface::USB, bus, addr, socketId);
    }
    else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT)
    {
        lg2::info("USB device removed: bus {BUS}, addr {ADDR}", "BUS",
                  static_cast<int>(bus), "ADDR", static_cast<int>(addr));
        int socketId = removeDeviceAndGetSocketId(bus, addr);
        if (socketId == -1)
        {
            lg2::warning(
                "USB device bus {BUS} address {ADDRESS} not found in device mapping",
                "BUS", static_cast<int>(bus), "ADDRESS",
                static_cast<int>(addr));
            return;
        }
        manager->onDeviceRemoved(TransportInterface::USB, bus, addr, socketId);
    }
}

void USBDeviceEnumerator::scanDeviceList()
{
    libusb_device** devs = nullptr;
    ssize_t cnt = libusb_get_device_list(usbCtx, &devs);
    if (cnt < 0)
    {
        lg2::error("USBDeviceEnumerator: libusb_get_device_list failed");
        return;
    }

    for (ssize_t i = 0; i < cnt; ++i)
    {
        libusb_device* dev = devs[i];
        libusb_device_descriptor desc{};
        if (libusb_get_device_descriptor(dev, &desc) != 0)
        {
            lg2::error("USBDeviceEnumerator: failed to get device descriptor");
            continue;
        }
        if (desc.idVendor == vendorId && desc.idProduct == productId)
        {
            uint8_t bus = libusb_get_bus_number(dev);
            uint8_t addr = libusb_get_device_address(dev);
            int socketId = addDeviceAndGetSocketId(bus, addr);
            manager->onDeviceAdded(TransportInterface::USB, bus, addr,
                                   socketId);
        }
    }
    libusb_free_device_list(devs, 1);
}

sdbusplus::async::task<void> USBDeviceEnumerator::run()
{
    if (!usbCtx)
    {
        lg2::error("USBDeviceEnumerator: libusb context not initialized");
        co_return;
    }
    while (!ctx.stop_requested())
    {
        if (hotplugSupported)
        {
            libusb_handle_events(usbCtx);
        }
        else
        {
            scanDeviceList();
        }

        co_await sdbusplus::async::sleep_for(ctx, rescanInterval);
    }
    co_return;
}
