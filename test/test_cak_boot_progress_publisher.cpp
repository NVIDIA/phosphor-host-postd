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
#include "queued-boot-progress/CakBootProgressPublisher.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <cerrno>
#include <memory>
#include <system_error>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{

static void setupBusMock(NiceMock<sdbusplus::SdBusMock>& bus_mock)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);
}

/** Run context until stop; takes pointer so worker threads don't capture stack.
 */
static void runContextUntilStop(sdbusplus::async::context* ctx)
{
    auto fn = [ctx]() -> sdbusplus::async::task<void> {
        ctx->request_stop();
        co_return;
    };
    ctx->spawn(fn());
    ctx->run();
}

/* sd_event_add_io rejects regular files (e.g. /dev/null on CI). Mock
 * sd_bus_get_fd to return a real pipe read-end so context construction
 * succeeds; the pipe is closed after the context is destroyed. */
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

/* Fixture shared by all CakBootProgressPublisher tests.
 * Members are declared in construction order; destruction is the reverse,
 * so ctx is destroyed before bus_mock and pipe. */
class CakTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        EXPECT_CALL(bus_mock, sd_bus_get_fd(_))
            .WillRepeatedly(Return(pipe.fd[0]));
        setupBusMock(bus_mock);
        ctx = std::make_unique<sdbusplus::async::context>(
            sdbusplus::get_mocked_new(&bus_mock));
    }

    void TearDown() override
    {
        ctx.reset();
    }

    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    std::unique_ptr<sdbusplus::async::context> ctx;
};

TEST_F(CakTest, ConstructWithZeroCpuCount)
{
    CakBootProgressPublisher cak(*ctx, 0);
    cak.resetCachedState();
    cak.onProgressCode(0x70C0C001u);
    runContextUntilStop(ctx.get());
}

TEST_F(CakTest, ConstructWithOneCpu)
{
    CakBootProgressPublisher cak(*ctx, 1);
    runContextUntilStop(ctx.get());
}

TEST_F(CakTest, ResetCachedStateWithNonZeroCpu)
{
    CakBootProgressPublisher cak(*ctx, 1);
    cak.resetCachedState();
    runContextUntilStop(ctx.get());
}

TEST_F(CakTest, OnProgressCodeCpu0BootStart)
{
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x70C0C001u);
    runContextUntilStop(ctx.get());
}

TEST_F(CakTest, OnProgressCodeCakEnterThenExit)
{
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x70C1C08Au);
    cak.onProgressCode(0x70C1C089u);
    runContextUntilStop(ctx.get());
}

TEST_F(CakTest, OnProgressCodeCpu1BootStart)
{
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x71C0C001u);
    runContextUntilStop(ctx.get());
}

// Branch: publishCakStageFromStates all Complete
TEST_F(CakTest, PublishCakStageFromStatesAllComplete)
{
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x70C1C08Au);
    cak.onProgressCode(0x70C1C089u);
    cak.onProgressCode(0x71C1C08Au);
    cak.onProgressCode(0x71C1C089u);
    runContextUntilStop(ctx.get());
}

// Branch: publishCakStageFromStates all Waiting
TEST_F(CakTest, PublishCakStageFromStatesAllWaiting)
{
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x70C1C08Au);
    cak.onProgressCode(0x71C1C08Au);
    runContextUntilStop(ctx.get());
}

// Branch: publishCakStageFromStates mixed -> EarlyBoot
TEST_F(CakTest, PublishCakStageFromStatesMixedEarlyBoot)
{
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x70C1C08Au);
    runContextUntilStop(ctx.get());
}

// Branch: updateCakState when cpuIndex >= cakCpuStages.size() (no-op)
TEST_F(CakTest, OnProgressCodeCpuIndexOutOfRangeIgnored)
{
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x71C1C08Au);
    cak.onProgressCode(0x71C1C089u);
    runContextUntilStop(ctx.get());
}

// Branch: updateCakState unknown progress code returns early
TEST_F(CakTest, OnProgressCodeUnknownCodeIgnored)
{
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x12345678u);
    runContextUntilStop(ctx.get());
}

// Branch: updateCakState valid CPU index but unrecognised event code → else
TEST(CakBootProgressPublisher, OnProgressCodeValidCpuUnknownEventIgnored)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 1);
    // highByte=0x70 (CPU 0, in range), eventCode=0x00AABBCC (not known)
    cak.onProgressCode(0x70AABBCCu);
    runContextUntilStop(ctx.get());
}

// Branch: publishCakStageIfChanged when stage == lastPublishedStage (no update)
TEST_F(CakTest, OnProgressCodeSameStageTwice_SecondCallSkipsPublish)
{
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x70C0C001u); // EarlyBoot
    cak.onProgressCode(
        0x70C0C001u); // same stage again -> publishCakStageIfChanged no-op
    runContextUntilStop(ctx.get());
}

// Branch: updateCakState cpu0BootStart when cpuIndex < size (and
// publishCakStageFromStates)
TEST_F(CakTest, OnProgressCodeCpu0BootStartWithTwoCpus)
{
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x70C0C001u);
    cak.onProgressCode(0x71C0C001u);
    runContextUntilStop(ctx.get());
}

} // namespace
