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
#include "mock_polling_device.hpp"
#include "polling_device_factory.hpp"
#include "queued-boot-progress/BootProgressManager.hpp"
#include "queued-boot-progress/BootProgressPublisher.hpp"
#include "queued-boot-progress/PollingDevice.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <chrono>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace phosphor_host_postd_test;

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{

/** Exposes protected notifyDeviceAdded/notifyDeviceRemoved for branch coverage.
 */
class TestableEnumerator : public PollingDeviceEnumerator
{
  public:
    TestableEnumerator(sdbusplus::async::context& ctx,
                       OnDeviceAddedCallback onAdded,
                       OnDeviceRemovedCallback onRemoved) :
        PollingDeviceEnumerator(ctx, std::move(onAdded), std::move(onRemoved))
    {}
    sdbusplus::async::task<void> run() override
    {
        co_return;
    }
    void callNotifyDeviceAdded(std::shared_ptr<PollingDevice> device,
                               TransportInterface t, uint8_t bus, uint8_t addr)
    {
        notifyDeviceAdded(std::move(device), t, bus, addr);
    }
    void callNotifyDeviceRemoved(TransportInterface t, uint8_t bus,
                                 uint8_t addr)
    {
        notifyDeviceRemoved(t, bus, addr);
    }
};

class PollingDeviceEnumeratorTest : public ::testing::Test
{
  protected:
    PollingDeviceEnumeratorTest() :
        bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock))
    {}

    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus;
};

TEST_F(PollingDeviceEnumeratorTest, GetPollingDeviceEnumeratorI2CReturnsNull)
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
        getPollingDeviceEnumerator(ctx, mgr, TransportInterface::I2C, 0x0955,
                                   0x7410, std::chrono::seconds(100));
    EXPECT_EQ(enumerator, nullptr);
    ctx.request_stop();
    ctx.run();
}

TEST_F(PollingDeviceEnumeratorTest, GetPollingDeviceUnsupportedReturnsNull)
{
    auto unsupported = static_cast<TransportInterface>(99);
    auto device = getPollingDevice(unsupported, 0, 0x50);
    EXPECT_EQ(device, nullptr);
}

TEST_F(PollingDeviceEnumeratorTest, GetPollingDeviceI2CReturnsDevice)
{
    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    ASSERT_NE(device, nullptr);
    uint32_t value = 0xdeadbeef;
    EXPECT_FALSE(device->readRegisterValue(0, value));
    EXPECT_EQ(value, 0xdeadbeef);
}

TEST_F(PollingDeviceEnumeratorTest, GetPollingDeviceUSBReturnsDevice)
{
    uint8_t bus = 255;
    uint8_t addr = 255;
    auto device = getPollingDevice(TransportInterface::USB, bus, addr);
    ASSERT_NE(device, nullptr);
    uint32_t value = 0xdeadbeef;
    EXPECT_FALSE(device->readRegisterValue(0, value));
    EXPECT_EQ(value, 0xdeadbeef);
}

TEST_F(PollingDeviceEnumeratorTest, GetPollingDeviceEnumeratorUSBReturnsNonNull)
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
    EXPECT_NE(enumerator, nullptr);
    ctx.request_stop();
    ctx.run();
}

// Branch coverage: notifyDeviceAdded/notifyDeviceRemoved with null callbacks
TEST_F(PollingDeviceEnumeratorTest, NotifyDeviceAddedWithNullCallback)
{
    sdbusplus::async::context ctx;
    TestableEnumerator enumerator(ctx, nullptr, nullptr);
    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    ASSERT_NE(device, nullptr);
    enumerator.callNotifyDeviceAdded(std::move(device), TransportInterface::I2C,
                                     0, 0x50);
}

TEST_F(PollingDeviceEnumeratorTest, NotifyDeviceRemovedWithNullCallback)
{
    sdbusplus::async::context ctx;
    TestableEnumerator enumerator(ctx, nullptr, nullptr);
    enumerator.callNotifyDeviceRemoved(TransportInterface::I2C, 0, 0x50);
}

// Branch coverage: notifyDeviceAdded/notifyDeviceRemoved with non-null
// callbacks
TEST_F(PollingDeviceEnumeratorTest, NotifyDeviceAddedWithCallback)
{
    sdbusplus::async::context ctx;
    bool addedCalled = false;
    OnDeviceAddedCallback onAdded =
        [&addedCalled](std::shared_ptr<PollingDevice> /*dev*/,
                       TransportInterface /*t*/, uint8_t /*bus*/,
                       uint8_t /*addr*/) { addedCalled = true; };
    TestableEnumerator enumerator(ctx, std::move(onAdded), nullptr);
    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    ASSERT_NE(device, nullptr);
    enumerator.callNotifyDeviceAdded(std::move(device), TransportInterface::I2C,
                                     0, 0x50);
    EXPECT_TRUE(addedCalled);
}

TEST_F(PollingDeviceEnumeratorTest, NotifyDeviceRemovedWithCallback)
{
    sdbusplus::async::context ctx;
    bool removedCalled = false;
    OnDeviceRemovedCallback onRemoved =
        [&removedCalled](TransportInterface /*t*/, uint8_t /*bus*/,
                         uint8_t /*addr*/) { removedCalled = true; };
    TestableEnumerator enumerator(ctx, nullptr, std::move(onRemoved));
    enumerator.callNotifyDeviceRemoved(TransportInterface::I2C, 0, 0x50);
    EXPECT_TRUE(removedCalled);
}

// Use PollingDevice interface with mock implementation for branch coverage
TEST_F(PollingDeviceEnumeratorTest, NotifyDeviceAddedWithMockPollingDevice)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    bool addedCalled = false;
    OnDeviceAddedCallback onAdded =
        [&addedCalled](std::shared_ptr<PollingDevice> dev,
                       TransportInterface /*t*/, uint8_t /*bus*/,
                       uint8_t /*addr*/) {
            addedCalled = true;
            EXPECT_NE(dev, nullptr);
        };
    TestableEnumerator enumerator(ctx, std::move(onAdded), nullptr);
    enumerator.callNotifyDeviceAdded(mockDevice, TransportInterface::USB, 1,
                                     0x51);
    EXPECT_TRUE(addedCalled);
}

} // namespace
