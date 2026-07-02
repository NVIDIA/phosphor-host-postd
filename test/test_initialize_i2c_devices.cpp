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
#include "null_property_access.hpp"
#include "queued-boot-progress/BootProgressManager.hpp"
#include "queued-boot-progress/BootProgressPublisher.hpp"
#include "queued-boot-progress/I2CPollingDevice.hpp"
#include "queued-boot-progress/PollingDevice.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <cerrno>
#include <chrono>
#include <system_error>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{

struct PipeFdGuard
{
    int fd[2];
    PipeFdGuard()
    {
        if (pipe2(fd, O_CLOEXEC) != 0)
        {
            throw std::system_error(errno, std::generic_category(), "pipe2");
        }
    }
    ~PipeFdGuard()
    {
        close(fd[0]);
        close(fd[1]);
    }
};

class InitializeI2CDevicesTest : public ::testing::Test
{
  protected:
    InitializeI2CDevicesTest() :
        bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock))
    {
        EXPECT_CALL(bus_mock, sd_bus_get_fd(_))
            .WillRepeatedly(Return(pipe.fd[0]));
    }

    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus;
};

TEST_F(InitializeI2CDevicesTest, EmptyDeviceListDoesNotCallOnDeviceAdded)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));

    I2CDeviceList emptyList;
    initializeI2CDevices(mgr, emptyList);
    ctx.request_stop();
    ctx.run();
}

TEST_F(InitializeI2CDevicesTest, NonEmptyDeviceListCallsOnDeviceAdded)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));

    I2CDeviceList list = {{0, 0x50}, {1, 0x51}};
    initializeI2CDevices(mgr, list);
    ctx.request_stop();
    ctx.run();
}

} // namespace
