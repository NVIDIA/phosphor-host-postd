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

#include "I2CPollingDevice.hpp"

#include "BootProgressManager.hpp"

#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>

#include <cerrno>
#include <format>

I2CPollingDevice::I2CPollingDevice(const uint8_t& i2cBus,
                                   const uint8_t& address) :
    busPath(std::format("/dev/i2c-{}", i2cBus)), deviceAddress(address)
{
    discardStaleBlockReadIfAny();
    if (i2cFileDescriptor < 0)
    {
        openDevice();
    }
}

I2CPollingDevice::~I2CPollingDevice()
{
    closeDevice();
}

bool I2CPollingDevice::openDevice()
{
    if (i2cFileDescriptor >= 0)
    {
        return true;
    }

    i2cFileDescriptor = ::open(busPath.c_str(), O_RDWR | O_CLOEXEC);
    if (i2cFileDescriptor < 0)
    {
        lg2::debug("Failed to open i2c bus: {BUS_PATH}, errno: {ERRNO}",
                   "BUS_PATH", busPath, "ERRNO", errno);
        return false;
    }

    if (::ioctl(i2cFileDescriptor, I2C_SLAVE, deviceAddress) < 0)
    {
        lg2::debug(
            "Failed to set I2C slave address: {BUS_PATH}, errno: {ERRNO}",
            "BUS_PATH", busPath, "ERRNO", errno);
        closeDevice();
        return false;
    }
    return true;
}

void I2CPollingDevice::closeDevice()
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
        discardStaleBlockReadIfAny();
        openDevice();
        if (!i2cWriteRead(writeData, dummyRead))
        {
            lg2::debug("SET_READ_ADDR failed for register {REG_ADDR}",
                       "REG_ADDR", regAddrStr);
            return false;
        }
    }
    std::vector<uint8_t> blockReadCmd = {blockRead};
    std::vector<uint8_t> readBuf(5);
    if (!i2cWriteRead(blockReadCmd, readBuf))
    {
        lg2::debug("BLOCK_READ failed for register {REG_ADDR}", "REG_ADDR",
                   regAddrStr);
        return false;
    }
    if (readBuf.size() < 5)
    {
        lg2::debug("Too few bytes returned: {BYTES}", "BYTES",
                   static_cast<int>(readBuf[0]));
        return false;
    }

    regValue = (static_cast<uint32_t>(readBuf[4]) << 24) |
               (static_cast<uint32_t>(readBuf[3]) << 16) |
               (static_cast<uint32_t>(readBuf[2]) << 8) |
               static_cast<uint32_t>(readBuf[1]);
    if (!deviceHealthy)
    {
        lg2::info("I2C device {BUS_PATH} recovered", "BUS_PATH", busPath);
        deviceHealthy = true;
    }
    return true;
}

bool I2CPollingDevice::performIoctlWithRetry(i2c_rdwr_ioctl_data& msgReadWrite)
{
    if (!openDevice())
    {
        if (deviceHealthy)
        {
            lg2::error("Failed to open I2C device: {BUS_PATH}", "BUS_PATH",
                       busPath);
            deviceHealthy = false;
        }
        return false;
    }

    int ret = ::ioctl(i2cFileDescriptor, I2C_RDWR, &msgReadWrite);
    if (ret >= 0)
    {
        return true;
    }
    closeDevice();
    if (deviceHealthy)
    {
        lg2::error(
            "I2C ioctl failed (errno: {ERRNO}), closed fd to release kernel reference: {BUS_PATH}",
            "ERRNO", errno, "BUS_PATH", busPath);
        deviceHealthy = false;
    }
    return false;
}

bool I2CPollingDevice::i2cWriteRead(std::vector<uint8_t> writeData,
                                    std::vector<uint8_t>& readBuf)
{
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

    if (!performIoctlWithRetry(msgReadWrite))
    {
        return false;
    }
    if (readCount && msgCount > 0)
    {
        readBuf.resize(msgReadWrite.msgs[msgCount - 1].len);
    }
    return true;
}

void I2CPollingDevice::discardStaleBlockReadIfAny()
{
    static constexpr uint8_t blockRead = 0xf3;
    static constexpr size_t blockReadPayloadLen = 5;

    openDevice();
    if (i2cFileDescriptor < 0)
    {
        return;
    }

    std::vector<uint8_t> blockReadCmd = {blockRead};
    std::vector<uint8_t> readBuf(blockReadPayloadLen);
    i2cWriteRead(blockReadCmd, readBuf);
}

bool I2CPollingDevice::doL1Reset()
{
    // L1 SW main reset via EXT_Messaging I2C frames.
    // Two-frame sequence sets PMC_IMPL_SW_MAIN_RST_0.rst_req = 1:
    //   F0 frame: set write address to 0x00004000 (sw_main_rst register)
    //     { 0xF0, 0x04, <addr_LE_4bytes> }
    //   F2 frame: block write value 0x00000001 (trigger reset)
    //     { 0xF2, 0x04, <data_LE_4bytes> }
    // Always flush (F2 zero-write) first to discard any stale pending write
    // from a previous failed attempt.  The flush is a no-op on a clean bus.
    static constexpr std::array<uint8_t, 6> setAddrFrame = {
        0xF0, 0x04, 0x00, 0x40, 0x00, 0x00}; // addr 0x00004000 LE
    static constexpr std::array<uint8_t, 6> writeFrame = {
        0xF2, 0x04, 0x01, 0x00, 0x00, 0x00}; // value 0x00000001 LE
    static constexpr std::array<uint8_t, 6> flushFrame = {
        0xF2, 0x04, 0x00, 0x00, 0x00, 0x00}; // zero-write flush

    lg2::debug("I2C L1 reset: {BUS_PATH} sw_main_rst=0x00000001", "BUS_PATH",
               busPath);

    // Flush any stale pending write before attempting the reset
    std::vector<uint8_t> flush(flushFrame.begin(), flushFrame.end());
    std::vector<uint8_t> dummy;
    i2cWriteRead(flush, dummy);

    std::vector<uint8_t> setAddr(setAddrFrame.begin(), setAddrFrame.end());
    std::vector<uint8_t> dummy1;
    if (!i2cWriteRead(setAddr, dummy1))
    {
        lg2::warning("I2C L1 reset: F0 (set-addr) failed on {BUS_PATH}",
                     "BUS_PATH", busPath);
        return false;
    }

    std::vector<uint8_t> write(writeFrame.begin(), writeFrame.end());
    std::vector<uint8_t> dummy2;
    if (!i2cWriteRead(write, dummy2))
    {
        lg2::warning("I2C L1 reset: F2 (block-write) failed on {BUS_PATH}",
                     "BUS_PATH", busPath);
        return false;
    }

    lg2::info("I2C L1 reset: sw_main_rst=0x00000001 sent via {BUS_PATH}",
              "BUS_PATH", busPath);
    return true;
}

void initializeI2CDevices(std::shared_ptr<BootProgressManager> mgr,
                          const I2CDeviceList& deviceList)
{
    for (const auto& [bus, address] : deviceList)
    {
        auto device = std::make_shared<I2CPollingDevice>(bus, address);
        if (!device)
        {
            lg2::error(
                "Failed to create I2C polling device for bus {BUS}, address {ADDRESS}",
                "BUS", bus, "ADDRESS", address);
            continue;
        }
        mgr->onDeviceAdded(std::move(device), TransportInterface::I2C, bus,
                           address);
    }
}
