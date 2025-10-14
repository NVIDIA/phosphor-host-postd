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

#include <libusb-1.0/libusb.h>

#include <sdbusplus/async.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

enum class TransportInterface
{
    I2C,
    USB
};

struct PairHash
{
    std::size_t operator()(const std::pair<uint8_t, uint8_t>& p) const noexcept
    {
        return static_cast<std::size_t>(p.first) << 8 |
               static_cast<std::size_t>(p.second);
    }
};

class PollingDevice
{
  public:
    virtual ~PollingDevice() = default;

    virtual bool readRegisterValue(uint32_t regAddr, uint32_t& regValue) = 0;
};

class I2CPollingDevice : public PollingDevice
{
  public:
    I2CPollingDevice(const uint8_t& i2cBus, const uint8_t& deviceAddress);
    ~I2CPollingDevice() override;

    I2CPollingDevice(const I2CPollingDevice&) = delete;
    I2CPollingDevice& operator=(const I2CPollingDevice&) = delete;
    I2CPollingDevice(I2CPollingDevice&&) = delete;
    I2CPollingDevice& operator=(I2CPollingDevice&&) = delete;

    bool readRegisterValue(uint32_t regAddr, uint32_t& regValue) override;

  private:
    std::string busPath;
    uint8_t deviceAddress;
    int i2cFileDescriptor = -1;

    bool i2cWriteRead(std::vector<uint8_t> writeData,
                      std::vector<uint8_t>& readBuf);
};

class USBPollingDevice : public PollingDevice
{
  public:
    USBPollingDevice(const uint8_t& bus, const uint8_t& deviceAddress);
    ~USBPollingDevice() override;

    USBPollingDevice(const USBPollingDevice&) = delete;
    USBPollingDevice& operator=(const USBPollingDevice&) = delete;
    USBPollingDevice(USBPollingDevice&&) = delete;
    USBPollingDevice& operator=(USBPollingDevice&&) = delete;

    bool readRegisterValue(uint32_t regAddr, uint32_t& regValue) override;

  private:
    uint8_t bus;
    uint8_t deviceAddress;

    libusb_context* ctx = nullptr;
    libusb_device_handle* devHandle = nullptr;
};

class BootProgressManager;

class PollingDeviceEnumerator
{
  public:
    virtual ~PollingDeviceEnumerator() = default;
    virtual sdbusplus::async::task<void> run() = 0;

  protected:
    PollingDeviceEnumerator(sdbusplus::async::context& ctx,
                            std::shared_ptr<BootProgressManager> mgr);

    sdbusplus::async::context& ctx;
    std::shared_ptr<BootProgressManager> manager;
    std::unordered_map<std::pair<uint8_t /* bus */, uint8_t /* address */>, int,
                       PairHash>
        deviceToSocketMap;
    int nextSocketId = 0;
    int addDeviceAndGetSocketId(uint8_t bus, uint8_t address);
    int removeDeviceAndGetSocketId(uint8_t bus, uint8_t address);
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
    uint16_t vendorId;
    uint16_t productId;
    std::chrono::seconds rescanInterval;

    libusb_context* usbCtx = nullptr;
    libusb_hotplug_callback_handle cbHandle = 0;
    bool hotplugSupported = false;

    static int LIBUSB_CALL hotplugCallback(
        libusb_context* ctx, libusb_device* dev, libusb_hotplug_event event,
        void* userData);

    void handleHotplug(libusb_device* dev, libusb_hotplug_event event);

    void scanDeviceList();
};

std::shared_ptr<PollingDevice> getPollingDevice(
    TransportInterface transportInterface, const uint8_t& bus,
    const uint8_t& address);

using I2CDeviceList =
    std::vector<std::pair<uint8_t /* bus */, uint8_t /* address */>>;

std::shared_ptr<PollingDeviceEnumerator> getPollingDeviceEnumerator(
    sdbusplus::async::context& ctx, std::shared_ptr<BootProgressManager> mgr,
    TransportInterface transportInterface, uint16_t vendorId,
    uint16_t productId, std::chrono::seconds rescanInterval);

void initializeI2CDevices(std::shared_ptr<BootProgressManager> mgr,
                          const I2CDeviceList& deviceList);
