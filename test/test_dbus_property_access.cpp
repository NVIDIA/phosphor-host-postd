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
#include "queued-boot-progress/dbus_utils.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <cerrno>
#include <system_error>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{

/* sd_event_add_io rejects regular files (e.g. /dev/null used as stdin on
 * CI).  NiceMock returns 0 for sd_bus_get_fd by default, which is stdin
 * and hits EPERM.  Create a real pipe read-end so context construction
 * succeeds; close it after the context is destroyed. */
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

/* All four DbusPropertyAccess methods are thin coroutine wrappers around
 * free-function helpers (getDbusProperty / setDbusProperty /
 * waitForDbusPropertiesChanged).  We exercise each by making the first
 * outgoing sd_bus call fail with -ENOENT so the coroutine body executes
 * and the exception path is taken immediately — no 25-second D-Bus
 * timeout. */

TEST(DbusPropertyAccess, SetPropertyStringThrowsOnBusError)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    EXPECT_CALL(bus_mock, sd_bus_message_new_method_call(_, _, _, _, _, _))
        .WillRepeatedly(Return(-ENOENT));

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    DbusPropertyAccess access(ctx);

    bool caught = false;
    auto run = [&]() -> sdbusplus::async::task<void> {
        try
        {
            co_await access.setProperty(
                "xyz.openbmc_project.State.Host",
                "/xyz/openbmc_project/state/host0",
                "xyz.openbmc_project.State.Boot.Progress", "BootProgress",
                std::string{"None"});
        }
        catch (const std::exception&)
        {
            caught = true;
        }
        ctx.request_stop();
    };
    ctx.spawn(run());
    ctx.run();
    EXPECT_TRUE(caught);
}

TEST(DbusPropertyAccess, SetPropertyUint64ThrowsOnBusError)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    EXPECT_CALL(bus_mock, sd_bus_message_new_method_call(_, _, _, _, _, _))
        .WillRepeatedly(Return(-ENOENT));

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    DbusPropertyAccess access(ctx);

    bool caught = false;
    auto run = [&]() -> sdbusplus::async::task<void> {
        try
        {
            co_await access.setProperty(
                "xyz.openbmc_project.State.Host",
                "/xyz/openbmc_project/state/host0",
                "xyz.openbmc_project.State.Boot.Progress",
                "BootProgressLastUpdate", uint64_t{0});
        }
        catch (const std::exception&)
        {
            caught = true;
        }
        ctx.request_stop();
    };
    ctx.spawn(run());
    ctx.run();
    EXPECT_TRUE(caught);
}

TEST(DbusPropertyAccess, GetPropertyThrowsOnBusError)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    EXPECT_CALL(bus_mock, sd_bus_message_new_method_call(_, _, _, _, _, _))
        .WillRepeatedly(Return(-ENOENT));

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    DbusPropertyAccess access(ctx);

    bool caught = false;
    auto run = [&]() -> sdbusplus::async::task<void> {
        try
        {
            co_await access.getProperty(
                "xyz.openbmc_project.State.Host",
                "/xyz/openbmc_project/state/host0",
                "xyz.openbmc_project.State.Boot.Progress", "BootProgress");
        }
        catch (const std::exception&)
        {
            caught = true;
        }
        ctx.request_stop();
    };
    ctx.spawn(run());
    ctx.run();
    EXPECT_TRUE(caught);
}

TEST(DbusPropertyAccess, WaitForPropertiesChangedThrowsOnBusError)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    EXPECT_CALL(bus_mock, sd_bus_add_match(_, _, _, _, _))
        .WillRepeatedly(Return(-ENOENT));

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    DbusPropertyAccess access(ctx);

    bool caught = false;
    auto run = [&]() -> sdbusplus::async::task<void> {
        try
        {
            co_await access.waitForPropertiesChanged(
                "/xyz/openbmc_project/state/host0",
                "xyz.openbmc_project.State.Boot.Progress");
        }
        catch (const std::exception&)
        {
            caught = true;
        }
        ctx.request_stop();
    };
    ctx.spawn(run());
    ctx.run();
    EXPECT_TRUE(caught);
}

} // namespace
