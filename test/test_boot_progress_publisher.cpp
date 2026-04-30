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
#include "queued-boot-progress/BootProgressPublisher.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <chrono>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{

TEST(BootProgressPublisher, Construct)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
}

TEST(BootProgressPublisher, UpdateEmptyReturnsEarly)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    auto run_update_then_stop = [&ctx, &pub]() -> sdbusplus::async::task<void> {
        co_await pub.update({});
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

TEST(BootProgressPublisher, UpdateWithProgressCodeExercisesStageDetection)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    const uint32_t pciInitCode = 0x42010110u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{1000u, pciInitCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

TEST(BootProgressPublisher, UpdateWithAllEfiStagesExercisesStageBranches)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    const uint32_t systemInitComplete = 0x43041001u;
    const uint32_t systemSetup = 0x43050007u;
    const uint32_t osStart = 0x43058000u;
    const uint32_t osRunning = 0x43101019u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {
        {100u, systemInitComplete},
        {200u, systemSetup},
        {300u, osStart},
        {400u, osRunning},
    };
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

TEST(BootProgressPublisher, OSRunningIsImmutableAfterPublish)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    const uint32_t osRunningCode = 0x43101019u;
    const uint32_t pciInitCode = 0x42010110u;
    auto run_two_updates = [&ctx, &pub, osRunningCode,
                            pciInitCode]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, osRunningCode}});
        co_await pub.update({{200u, pciInitCode}});
        ctx.request_stop();
        co_return;
    };
    ctx.spawn(run_two_updates());
    ctx.run();
}

TEST(BootProgressPublisher, UpdateWithOemCodeExercisesOemBranch)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    uint32_t oemCode = 0u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{500u, oemCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

TEST(BootProgressPublisher, UpdateAfterResetCachedStateHitsFirstPublishPaths)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    const uint32_t pciInitCode = 0x42010110u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, pciInitCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: getSbmrBootProgressStage codeType != efiProgressCode returns OEM
TEST(BootProgressPublisher, NonEfiCodeTypeReturnsOem)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    // (progressCode >> 24) & 0xFF = 0x00 -> codeType = 0 != efiProgressCode(1)
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x00010110u}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: getSbmrBootProgressStage codeClass == efiIoBus but wrong subClass/op
// -> OEM
TEST(BootProgressPublisher, IoBusClassUnmatchedSubClassReturnsOem)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    // type 1, class 2 (IoBus), subClass 2, operation 0x200 (not PCI init)
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x42020000u}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: getSbmrBootProgressStage codeClass != efiSoftware && != efiIoBus ->
// OEM
TEST(BootProgressPublisher, UnknownCodeClassReturnsOem)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    // codeClass 4 (neither 2 IoBus nor 3 Software), valid codeType
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x44010110u}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: update() flush logic when shouldFlush is false and OEM throttle
TEST(BootProgressPublisher, UpdateWithOemOnlyDoesNotFlushImmediately)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    // Single OEM code; first update flushes
    // (firstPublish/lastPublishedOem.empty())
    std::vector<std::pair<uint32_t, uint32_t>> data = {{500u, 0x0000ABCDu}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: getSbmrBootProgressStage codeClass == efiSoftware but no matching
// subClass/operation (fallthrough to OEM)
TEST(BootProgressPublisher, SoftwareClassUnmatchedSubClassReturnsOem)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    // type 1, class 3 (Software), subClass 0, operation 0 -> no match
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x43000000u}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: update() OEM throttle - second update after interval flushes
TEST(BootProgressPublisher, SecondOemUpdateAfterThrottleIntervalFlushes)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    auto run_two_oem_updates = [&ctx, &pub]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, 0x0000AAAAu}});
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(150));
        co_await pub.update({{200u, 0x0000BBBBu}});
        ctx.request_stop();
    };
    ctx.spawn(run_two_oem_updates());
    ctx.run();
}

// Branch: flushPendingUpdates skips OEM update when oem == lastPublishedOem
TEST(BootProgressPublisher, FlushSkipsOemUpdateWhenUnchanged)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    const uint32_t oemCode = 0x0000CCCCu;
    auto run_same_oem_twice =
        [&ctx, &pub, oemCode]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, oemCode}});
        co_await pub.update({{200u, oemCode}});
        ctx.request_stop();
    };
    ctx.spawn(run_same_oem_twice());
    ctx.run();
}

// Branch: getSbmrBootProgressStage when codeType != efiProgressCode (0x01)
TEST(BootProgressPublisher, GetSbmrBootProgressStage_CodeTypeNonEfi_ReturnsOem)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    // typeClassByte = 0x00 -> codeType = 0 != efiProgressCode(1)
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x00ABCDEFu}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: update() latestStage.empty() and detectedStage==OEM sets stage to OEM
TEST(BootProgressPublisher, UpdateOemCodeWhenNoStageSet_UsesOemAsInitialStage)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    // Single OEM code (e.g. codeClass not Software/IoBus) -> latestStage empty,
    // use OEM
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x01001122u}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// BootProgressPublisher uses optional CakBootProgressPublisher (abstraction);
// with null, resetCachedState skips calling cak->resetCachedState
TEST(BootProgressPublisher, ResetCachedStateWithNullCak_DoesNotCallCak)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject)); // null cak
    pub.resetCachedState();
}

TEST(BootProgressPublisher,
     WithNonNullCakPublisher_ForwardsUpdateAndResetCachedState)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    auto cakPublisher = std::make_shared<CakBootProgressPublisher>(ctx, 1);
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject), cakPublisher);
    auto run_update_then_stop = [&ctx, &pub]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, 0x70C0C001u}});
        pub.resetCachedState();
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Update() with non-null CakBootProgressPublisher calls onProgressCode per code
TEST(BootProgressPublisher,
     UpdateWithNonNullCak_CallsOnProgressCodeForEachEntry)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    auto cakPublisher = std::make_shared<CakBootProgressPublisher>(ctx, 2);
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject), cakPublisher);
    std::vector<std::pair<uint32_t, uint32_t>> data = {
        {100u, 0x42010110u},
        {200u, 0x43041001u},
    };
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: update() loop - OEM then non-OEM in same batch overwrites stage
TEST(BootProgressPublisher, UpdateOemThenNonOemInSameBatch_OverwritesStage)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    std::vector<std::pair<uint32_t, uint32_t>> data = {
        {100u, 0x0000AAAAu}, // OEM
        {200u, 0x42010110u}, // PCIInit -> overwrites OEM
    };
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// Branch: flushPendingUpdates when lastPublishedStage == OSRunning skips
// BootProgress update (OSRunning is final)
TEST(BootProgressPublisher, FlushWhenOSRunningAlreadySkipsStageUpdate)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    const uint32_t osRunningCode = 0x43101019u;
    const uint32_t pciInitCode = 0x42010110u;
    auto run_os_then_pci = [&ctx, &pub, osRunningCode,
                            pciInitCode]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, osRunningCode}});
        co_await pub.update({{200u, pciInitCode}});
        ctx.request_stop();
    };
    ctx.spawn(run_os_then_pci());
    ctx.run();
}

// IST boot POST code 0xC0C2 (socket 0: 0x70C1C0C2)
TEST(BootProgressPublisher, IstBootCodeC0C2Socket0_SetsOemStage)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    const uint32_t istCode = 0x70C1C0C2u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, istCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// IST boot POST code 0xC0C2 (socket 1: 0x71C1C0C2)
TEST(BootProgressPublisher, IstBootCodeC0C2Socket1_SetsOemStage)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    const uint32_t istCode = 0x71C1C0C2u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, istCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// IST boot POST code 0xC748 (socket 0: 0x70C1C748)
TEST(BootProgressPublisher, IstBootCodeC748Socket0_SetsOemStage)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    const uint32_t istCode = 0x70C1C748u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, istCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// IST boot POST code 0xC748 (socket 1: 0x71C1C748)
TEST(BootProgressPublisher, IstBootCodeC748Socket1_SetsOemStage)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    const uint32_t istCode = 0x71C1C748u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, istCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// IST boot POST code 0xC349 (socket 0: 0x70C1C349)
TEST(BootProgressPublisher, IstBootCodeC349Socket0_SetsOemStage)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    const uint32_t istCode = 0x70C1C349u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, istCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

// IST boot POST code 0xC349 (socket 1: 0x71C1C349)
TEST(BootProgressPublisher, IstBootCodeC349Socket1_SetsOemStage)
{
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus(sdbusplus::get_mocked_new(&bus_mock));
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillRepeatedly(slotcb);

    sdbusplus::async::context ctx;
    BootProgressPublisher pub(ctx, std::string(snoopDbus),
                              std::string(snoopObject));
    pub.resetCachedState();
    const uint32_t istCode = 0x71C1C349u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, istCode}};
    auto run_update_then_stop =
        [&ctx, &pub, &data]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx.request_stop();
    };
    ctx.spawn(run_update_then_stop());
    ctx.run();
}

} // namespace
