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

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;

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

TEST(CakBootProgressPublisher, ConstructWithZeroCpuCount)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 0);
    cak.resetCachedState();
    cak.onProgressCode(0x70C0C001u);
    runContextUntilStop(ctx.get());
}

TEST(CakBootProgressPublisher, ConstructWithOneCpu)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 1);
    runContextUntilStop(ctx.get());
}

TEST(CakBootProgressPublisher, ResetCachedStateWithNonZeroCpu)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 1);
    cak.resetCachedState();
    runContextUntilStop(ctx.get());
}

TEST(CakBootProgressPublisher, OnProgressCodeCpu0BootStart)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x70C0C001u);
    runContextUntilStop(ctx.get());
}

TEST(CakBootProgressPublisher, OnProgressCodeCakEnterThenExit)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x70C1C08Au);
    cak.onProgressCode(0x70C1C089u);
    runContextUntilStop(ctx.get());
}

TEST(CakBootProgressPublisher, OnProgressCodeCpu1BootStart)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x71C0C001u);
    runContextUntilStop(ctx.get());
}

// Branch: publishCakStageFromStates all Complete
TEST(CakBootProgressPublisher, PublishCakStageFromStatesAllComplete)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x70C1C08Au);
    cak.onProgressCode(0x70C1C089u);
    cak.onProgressCode(0x71C1C08Au);
    cak.onProgressCode(0x71C1C089u);
    runContextUntilStop(ctx.get());
}

// Branch: publishCakStageFromStates all Waiting
TEST(CakBootProgressPublisher, PublishCakStageFromStatesAllWaiting)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x70C1C08Au);
    cak.onProgressCode(0x71C1C08Au);
    runContextUntilStop(ctx.get());
}

// Branch: publishCakStageFromStates mixed -> EarlyBoot
TEST(CakBootProgressPublisher, PublishCakStageFromStatesMixedEarlyBoot)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x70C1C08Au);
    runContextUntilStop(ctx.get());
}

// Branch: updateCakState when cpuIndex >= cakCpuStages.size() (no-op)
TEST(CakBootProgressPublisher, OnProgressCodeCpuIndexOutOfRangeIgnored)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x71C1C08Au);
    cak.onProgressCode(0x71C1C089u);
    runContextUntilStop(ctx.get());
}

// Branch: updateCakState unknown progress code returns early
TEST(CakBootProgressPublisher, OnProgressCodeUnknownCodeIgnored)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x12345678u);
    runContextUntilStop(ctx.get());
}

// Branch: publishCakStageIfChanged when stage == lastPublishedStage (no update)
TEST(CakBootProgressPublisher,
     OnProgressCodeSameStageTwice_SecondCallSkipsPublish)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 1);
    cak.onProgressCode(0x70C0C001u); // EarlyBoot
    cak.onProgressCode(
        0x70C0C001u); // same stage again -> publishCakStageIfChanged no-op
    runContextUntilStop(ctx.get());
}

// Branch: updateCakState cpu0BootStart when cpuIndex < size (and
// publishCakStageFromStates)
TEST(CakBootProgressPublisher, OnProgressCodeCpu0BootStartWithTwoCpus)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    setupBusMock(bus_mock);

    auto ctx = std::make_unique<sdbusplus::async::context>();
    CakBootProgressPublisher cak(*ctx, 2);
    cak.onProgressCode(0x70C0C001u);
    cak.onProgressCode(0x71C0C001u);
    runContextUntilStop(ctx.get());
}

} // namespace
