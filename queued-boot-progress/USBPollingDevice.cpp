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

#include "USBPollingDevice.hpp"

#include "BootProgressManager.hpp"

#include <sys/time.h>

#include <phosphor-logging/lg2.hpp>

#include <format>
#include <functional>

USBPollingDevice::USBPollingDevice(libusb_device_handle* handle, uint8_t busNum,
                                   uint8_t deviceAddr) :
    bus(busNum), deviceAddress(deviceAddr), devHandle(handle)
{}

USBPollingDevice::~USBPollingDevice()
{
    if (devHandle)
    {
        libusb_close(devHandle);
        devHandle = nullptr;
    }
}

bool USBPollingDevice::readRegisterValue(uint32_t regAddr, uint32_t& regValue)
{
    if (!devHandle)
    {
        lg2::debug("USB device not opened");
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
        lg2::debug("Failed to read register {REG_ADDR}: {ERROR}", "REG_ADDR",
                   regAddrStr, "ERROR", transferLength);
        return false;
    }
    if (transferLength != readLength)
    {
        lg2::debug("Failed to read register {REG_ADDR}: {ERROR}", "REG_ADDR",
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
    PollingDeviceEnumerator(
        ctx, std::bind_front(&BootProgressManager::onDeviceAdded, mgr),
        std::bind_front(&BootProgressManager::onDeviceRemoved, mgr)),
    vendorId(vendorId), productId(productId), rescanInterval(rescanInterval)
{
    libusb_context* raw = nullptr;
    if (libusb_init(&raw) < 0)
    {
        lg2::debug("USBDeviceEnumerator: failed to init libusb");
        return;
    }
    usbCtx.reset(raw);
    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG))
    {
        lg2::debug("USBDeviceEnumerator: hotplug not supported");
        hotplugSupported = false;
        return;
    }
    hotplugSupported = true;
    int rc = libusb_hotplug_register_callback(
        usbCtx.get(),
        (libusb_hotplug_event)(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
                               LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
        (libusb_hotplug_flag)0, vendorId, productId, LIBUSB_HOTPLUG_MATCH_ANY,
        hotplugCallback, this, &cbHandle);
    if (rc != LIBUSB_SUCCESS)
    {
        lg2::error("USBDeviceEnumerator: failed to register hotplug callback");
        return;
    }
    scanDeviceList();
    libusb_set_pollfd_notifiers(usbCtx.get(), pollfdAddedCallback,
                                pollfdRemovedCallback, this);
    attachFirstPollfd(true);
}

USBDeviceEnumerator::~USBDeviceEnumerator()
{
    if (cbHandle && usbCtx)
    {
        libusb_hotplug_deregister_callback(usbCtx.get(), cbHandle);
        cbHandle = 0;
    }
    if (usbCtx)
    {
        libusb_set_pollfd_notifiers(usbCtx.get(), nullptr, nullptr, nullptr);
        libusbBell.reset();
        libusbBellFd = -1;
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
        tryAddDevice(dev);
    }
    else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT)
    {
        lg2::info("USB device removed: bus {BUS}, addr {ADDR}", "BUS",
                  static_cast<int>(bus), "ADDR", static_cast<int>(addr));
        notifyDeviceRemoved(TransportInterface::USB, bus, addr);
    }
}

void USBDeviceEnumerator::tryAddDevice(libusb_device* dev)
{
    uint8_t busNum = libusb_get_bus_number(dev);
    uint8_t addr = libusb_get_device_address(dev);
    libusb_device_handle* handle = nullptr;
    if (libusb_open(dev, &handle) != 0)
    {
        lg2::error(
            "USBDeviceEnumerator: failed to open device bus {BUS} addr {ADDR}",
            "BUS", static_cast<int>(busNum), "ADDR", static_cast<int>(addr));
        return;
    }
    auto device = std::make_shared<USBPollingDevice>(handle, busNum, addr);
    if (!device)
    {
        lg2::error(
            "USBDeviceEnumerator: failed to create USB polling device for bus {BUS}, address {ADDRESS}",
            "BUS", busNum, "ADDRESS", addr);
        libusb_close(handle);
        return;
    }
    notifyDeviceAdded(std::move(device), TransportInterface::USB, busNum, addr);
}

void USBDeviceEnumerator::scanDeviceList()
{
    libusb_device** devs = nullptr;
    ssize_t cnt = libusb_get_device_list(usbCtx.get(), &devs);
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
            tryAddDevice(dev);
        }
    }
    libusb_free_device_list(devs, 1);
}

sdbusplus::async::task<void> USBDeviceEnumerator::run()
{
    if (!usbCtx.get())
    {
        lg2::error("USBDeviceEnumerator: libusb context not initialized");
        co_return;
    }
    while (!ctx.stop_requested())
    {
        if (!libusbBell)
        {
            processLibusbEvents();
            co_await sdbusplus::async::sleep_for(ctx, rescanInterval);
            continue;
        }

        co_await libusbBell->next();
        processLibusbEvents();
    }
    co_return;
}

void USBDeviceEnumerator::pollfdAddedCallback(int fd, short /* events */,
                                              void* userData)
{
    auto* self = static_cast<USBDeviceEnumerator*>(userData);
    if (self)
    {
        self->addWatcher(fd);
    }
}

void USBDeviceEnumerator::pollfdRemovedCallback(int fd, void* userData)
{
    auto* self = static_cast<USBDeviceEnumerator*>(userData);
    if (self)
    {
        self->removeWatcher(fd);
    }
}

void USBDeviceEnumerator::addWatcher(int fd)
{
    if (libusbBell)
    {
        return;
    }
    try
    {
        libusbBell = std::make_unique<sdbusplus::async::fdio>(ctx, fd);
        libusbBellFd = fd;
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "USBDeviceEnumerator: Failed to create fdio for FD {FD}: {ERROR}",
            "FD", fd, "ERROR", e.what());
    }
}

void USBDeviceEnumerator::removeWatcher(int fd)
{
    if (fd != libusbBellFd)
    {
        return;
    }
    libusbBell.reset();
    libusbBellFd = -1;
    attachFirstPollfd();
}

void USBDeviceEnumerator::attachFirstPollfd(bool warnIfNull)
{
    const libusb_pollfd** pfds = libusb_get_pollfds(usbCtx.get());
    if (!pfds)
    {
        if (warnIfNull)
        {
            lg2::warning(
                "USBDeviceEnumerator: libusb_get_pollfds returned null");
        }
        return;
    }
    if (*pfds != nullptr)
    {
        addWatcher((*pfds)->fd);
    }
    libusb_free_pollfds(pfds);
}

void USBDeviceEnumerator::processLibusbEvents()
{
    struct timeval tv = {0, 0};
    libusb_handle_events_timeout_completed(usbCtx.get(), &tv, nullptr);
    if (!hotplugSupported)
    {
        scanDeviceList();
    }
}
