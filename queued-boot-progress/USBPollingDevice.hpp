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

#pragma once

#include "PollingDevice.hpp"

#include <libusb-1.0/libusb.h>

#include <sdbusplus/async/fdio.hpp>

#include <chrono>
#include <cstdint>
#include <memory>

class BootProgressManager;

class USBPollingDevice : public PollingDevice
{
  public:
    USBPollingDevice(libusb_device_handle* handle, uint8_t bus,
                     uint8_t deviceAddress);
    ~USBPollingDevice() override;

    USBPollingDevice(const USBPollingDevice&) = delete;
    USBPollingDevice& operator=(const USBPollingDevice&) = delete;
    USBPollingDevice(USBPollingDevice&&) = delete;
    USBPollingDevice& operator=(USBPollingDevice&&) = delete;

    bool readRegisterValue(uint32_t regAddr, uint32_t& regValue) override;

  private:
    uint8_t bus;
    uint8_t deviceAddress;
    libusb_device_handle* devHandle = nullptr;
};

class USBDeviceEnumerator : public PollingDeviceEnumerator
{
  public:
    USBDeviceEnumerator(sdbusplus::async::context& ctx,
                        std::shared_ptr<BootProgressManager> mgr,
                        uint16_t vendorId, uint16_t productId,
                        std::chrono::seconds rescanInterval);
    ~USBDeviceEnumerator() override;

    USBDeviceEnumerator(const USBDeviceEnumerator&) = delete;
    USBDeviceEnumerator& operator=(const USBDeviceEnumerator&) = delete;
    USBDeviceEnumerator(USBDeviceEnumerator&&) = delete;
    USBDeviceEnumerator& operator=(USBDeviceEnumerator&&) = delete;

    sdbusplus::async::task<void> run() override;

  private:
    struct LibusbContextDeleter
    {
        void operator()(libusb_context* p) const
        {
            if (p)
            {
                libusb_exit(p);
            }
        }
    };
    using UsbContextPtr = std::unique_ptr<libusb_context, LibusbContextDeleter>;

    uint16_t vendorId;
    uint16_t productId;
    std::chrono::seconds rescanInterval;

    UsbContextPtr usbCtx;
    libusb_hotplug_callback_handle cbHandle = 0;
    bool hotplugSupported = false;

    static int LIBUSB_CALL hotplugCallback(
        libusb_context* ctx, libusb_device* dev, libusb_hotplug_event event,
        void* userData);

    void handleHotplug(libusb_device* dev, libusb_hotplug_event event);
    void tryAddDevice(libusb_device* dev);

    void scanDeviceList();
    static void pollfdAddedCallback(int fd, short events, void* userData);
    static void pollfdRemovedCallback(int fd, void* userData);
    void addWatcher(int fd);
    void removeWatcher(int fd);
    void attachFirstPollfd(bool warnIfNull = false);
    void processLibusbEvents();

    std::unique_ptr<sdbusplus::async::fdio> libusbBell;
    int libusbBellFd = -1;
};
