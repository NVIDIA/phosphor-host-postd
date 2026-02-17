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

#include "lpcsnoop/snoop.hpp"
#include "polling_device_factory.hpp"
#include "queued-boot-progress/BootProgressManager.hpp"
#include "queued-boot-progress/BootProgressPublisher.hpp"
#include "queued-boot-progress/PollingDevice.hpp"
#include "queued-boot-progress/USBPollingDevice.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <chrono>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;

namespace
{

class USBPollingDeviceTest : public ::testing::Test
{
  protected:
    USBPollingDeviceTest() :
        bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock))
    {}

    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus;
};

TEST_F(USBPollingDeviceTest, GetPollingDeviceUSBReturnsDevice)
{
    uint8_t bus_num = 255;
    uint8_t addr = 255;
    auto device = getPollingDevice(TransportInterface::USB, bus_num, addr);
    ASSERT_NE(device, nullptr);
    uint32_t value = 0xdeadbeef;
    EXPECT_FALSE(device->readRegisterValue(0, value));
    EXPECT_EQ(value, 0xdeadbeef);
}

TEST_F(USBPollingDeviceTest, USBPollingDeviceNonexistentDeviceReadReturnsFalse)
{
    USBPollingDevice device(nullptr, 255, 255);
    uint32_t value = 0xdeadbeef;
    EXPECT_FALSE(device.readRegisterValue(0, value));
    EXPECT_EQ(value, 0xdeadbeef);
}

TEST_F(USBPollingDeviceTest, GetPollingDeviceEnumeratorUSBReturnsNonNull)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject));
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));

    auto enumerator =
        getPollingDeviceEnumerator(ctx, mgr, TransportInterface::USB, 0x0955,
                                   0x7410, std::chrono::seconds(10));
    ASSERT_NE(enumerator, nullptr);
    ctx.request_stop();
    ctx.run();
}

} // namespace
