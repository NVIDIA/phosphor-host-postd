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

#include <linux/i2c-dev.h>
#include <linux/i2c.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class BootProgressManager;

using I2CDeviceList =
    std::vector<std::pair<uint8_t /* bus */, uint8_t /* address */>>;

void initializeI2CDevices(std::shared_ptr<BootProgressManager> mgr,
                          const I2CDeviceList& deviceList);

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

    bool openDevice();
    void closeDevice();
    /** 0xF3 block read only; does not retry F1. Ctor + readRegisterValue on F1
     * failure. */
    void discardStaleBlockReadIfAny();
    bool performIoctlWithRetry(i2c_rdwr_ioctl_data& msgReadWrite);
    bool i2cWriteRead(std::vector<uint8_t> writeData,
                      std::vector<uint8_t>& readBuf);
};
