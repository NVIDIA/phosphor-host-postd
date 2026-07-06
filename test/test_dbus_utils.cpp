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
#include <string>
#include <system_error>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
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

// Exercise getSubTreePaths: mock the bus so the ObjectMapper call fails
// immediately, verifying the coroutine body is entered and the exception
// propagates correctly.
TEST(GetSubTreePaths, ThrowsOnBusError)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    EXPECT_CALL(bus_mock, sd_bus_message_new_method_call(_, _, _, _, _, _))
        .WillRepeatedly(Return(-ENOENT));

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));

    bool caught = false;
    auto run = [&]() -> sdbusplus::async::task<void> {
        try
        {
            co_await getSubTreePaths(
                ctx, "/xyz/openbmc_project/inventory", 0,
                {"xyz.openbmc_project.Inventory.Item.Cpu"});
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

TEST(CountUniqueLeafPaths, EmptyReturnsZero)
{
    EXPECT_EQ(countUniqueLeafPaths({}), 0u);
}

TEST(CountUniqueLeafPaths, SinglePathWithSlash)
{
    EXPECT_EQ(countUniqueLeafPaths({"/xyz/openbmc_project/inventory/CPU_0"}),
              1u);
}

// Branch: pos == npos — path has no '/' so the whole string is the leaf
TEST(CountUniqueLeafPaths, SinglePathWithoutSlash)
{
    EXPECT_EQ(countUniqueLeafPaths({"CPU_0"}), 1u);
}

TEST(CountUniqueLeafPaths, DuplicateLeafPathsDeduplicated)
{
    std::vector<std::string> paths = {
        "/xyz/openbmc_project/inventory/component/CPU_0",
        "/xyz/openbmc_project/inventory/cpu/CPU_0",
    };
    EXPECT_EQ(countUniqueLeafPaths(paths), 1u);
}

TEST(CountUniqueLeafPaths, TwoDifferentLeafs)
{
    std::vector<std::string> paths = {
        "/xyz/openbmc_project/inventory/CPU_0",
        "/xyz/openbmc_project/inventory/CPU_1",
    };
    EXPECT_EQ(countUniqueLeafPaths(paths), 2u);
}

TEST(CountUniqueLeafPaths, MixedSlashAndNoSlash)
{
    std::vector<std::string> paths = {
        "/xyz/openbmc_project/inventory/CPU_0",
        "CPU_0",
    };
    // Both have leaf "CPU_0" — deduplicated to 1
    EXPECT_EQ(countUniqueLeafPaths(paths), 1u);
}

} // namespace
