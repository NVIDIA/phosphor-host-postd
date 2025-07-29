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

#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>

#include <format>

I2CPollingDevice::I2CPollingDevice(const uint8_t& i2cBus,
                                   const uint8_t& address) :
    busPath(std::format("/dev/i2c-{}", i2cBus)), deviceAddress(address)
{
    i2cFileDescriptor = ::open(busPath.c_str(), O_RDWR | O_CLOEXEC);
    if (i2cFileDescriptor < 0)
    {
        lg2::error("Failed to open i2c bus: {BUS_PATH}", "BUS_PATH", busPath);
    }
}

I2CPollingDevice::~I2CPollingDevice()
{
    if (i2cFileDescriptor >= 0)
    {
        ::close(i2cFileDescriptor);
        i2cFileDescriptor = -1;
    }
}

bool I2CPollingDevice::readRegisterValue(uint32_t regAddr, uint32_t& regValue)
{
    static constexpr uint8_t readLength = 4;
    static constexpr uint8_t blockRead = 0xf3;
    static constexpr uint8_t setReadAddress = 0xf1;

    std::string regAddrStr = std::format("0x{:08X}", regAddr);
    std::vector<uint8_t> writeData = {
        setReadAddress,
        readLength + 1,
        static_cast<uint8_t>(regAddr & 0xFF),
        static_cast<uint8_t>((regAddr >> 8) & 0xFF),
        static_cast<uint8_t>((regAddr >> 16) & 0xFF),
        static_cast<uint8_t>((regAddr >> 24) & 0xFF),
        readLength};
    std::vector<uint8_t> dummyRead;
    if (!i2cWriteRead(writeData, dummyRead))
    {
        lg2::error("SET_READ_ADDR failed for register {REG_ADDR}", "REG_ADDR",
                   regAddrStr);
        return false;
    }
    std::vector<uint8_t> blockReadCmd = {blockRead};
    std::vector<uint8_t> readBuf(5);
    if (!i2cWriteRead(blockReadCmd, readBuf))
    {
        lg2::error("BLOCK_READ failed for register {REG_ADDR}", "REG_ADDR",
                   regAddrStr);
        return false;
    }
    if (readBuf.size() < 5)
    {
        lg2::error("Too few bytes returned: {BYTES}", "BYTES",
                   static_cast<int>(readBuf[0]));
        return false;
    }

    regValue = (static_cast<uint32_t>(readBuf[4]) << 24) |
               (static_cast<uint32_t>(readBuf[3]) << 16) |
               (static_cast<uint32_t>(readBuf[2]) << 8) |
               static_cast<uint32_t>(readBuf[1]);
    return true;
}

bool I2CPollingDevice::i2cWriteRead(std::vector<uint8_t> writeData,
                                    std::vector<uint8_t>& readBuf)
{
    if (i2cFileDescriptor < 0)
    {
        lg2::error("I2C device not open: {BUS_PATH}", "BUS_PATH", busPath);
        return false;
    }

    const size_t writeCount = writeData.size();
    const size_t readCount = readBuf.size();
    int msgCount = 0;
    i2c_msg i2cmsg[2] = {};
    if (writeCount)
    {
        i2cmsg[msgCount].addr = deviceAddress;
        i2cmsg[msgCount].flags = 0x00;
        i2cmsg[msgCount].len = writeCount;
        i2cmsg[msgCount].buf = writeData.data();
        msgCount++;
    }

    if (readCount)
    {
        i2cmsg[msgCount].addr = deviceAddress;
        i2cmsg[msgCount].flags = I2C_M_RD;
        i2cmsg[msgCount].len = readCount;
        i2cmsg[msgCount].buf = readBuf.data();
        msgCount++;
    }

    i2c_rdwr_ioctl_data msgReadWrite = {};
    msgReadWrite.msgs = i2cmsg;
    msgReadWrite.nmsgs = msgCount;
    // Perform the combined write/read
    int ret = ::ioctl(i2cFileDescriptor, I2C_RDWR, &msgReadWrite);
    if (ret < 0)
    {
        lg2::error("I2C combined WR/RD Failed! {RET}", "RET", ret);
        return false;
    }
    if (readCount && msgCount > 0)
    {
        readBuf.resize(msgReadWrite.msgs[msgCount - 1].len);
    }
    return true;
}

void initializeI2CDevices(std::shared_ptr<BootProgressManager> mgr,
                          const I2CDeviceList& deviceList)
{
    int socketId = 0;
    for (const auto& device : deviceList)
    {
        mgr->onDeviceAdded(TransportInterface::I2C, device.first, device.second,
                           socketId);
        socketId++;
    }
}
