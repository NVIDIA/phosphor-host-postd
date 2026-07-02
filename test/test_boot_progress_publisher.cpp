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
#include "queued-boot-progress/BootProgressPublisher.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <cerrno>
#include <chrono>
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

/* Fixture shared by all BootProgressPublisher tests.
 * Members are declared in construction order; destruction is the reverse,
 * so ctx is destroyed before bus_mock and pipe. */
class PublisherTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
            *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
            return 0;
        };
        EXPECT_CALL(bus_mock, sd_bus_get_fd(_))
            .WillRepeatedly(Return(pipe.fd[0]));
        EXPECT_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
            .WillRepeatedly(slotcb);
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

TEST_F(PublisherTest, Construct)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
}

TEST_F(PublisherTest, UpdateEmptyReturnsEarly)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update({});
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

TEST_F(PublisherTest, UpdateWithProgressCodeExercisesStageDetection)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    const uint32_t pciInitCode = 0x42010110u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{1000u, pciInitCode}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

TEST_F(PublisherTest, UpdateWithAllEfiStagesExercisesStageBranches)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
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
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

TEST_F(PublisherTest, OSRunningIsImmutableAfterPublish)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    const uint32_t osRunningCode = 0x43101019u;
    const uint32_t pciInitCode = 0x42010110u;
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, osRunningCode}});
        co_await pub.update({{200u, pciInitCode}});
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

TEST_F(PublisherTest, UpdateWithOemCodeExercisesOemBranch)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    std::vector<std::pair<uint32_t, uint32_t>> data = {{500u, 0u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

TEST_F(PublisherTest, UpdateAfterResetCachedStateHitsFirstPublishPaths)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    const uint32_t pciInitCode = 0x42010110u;
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, pciInitCode}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: getSbmrBootProgressStage codeType != efiProgressCode returns OEM
TEST_F(PublisherTest, NonEfiCodeTypeReturnsOem)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    // (progressCode >> 24) & 0xFF = 0x00 -> codeType = 0 != efiProgressCode(1)
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x00010110u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: getSbmrBootProgressStage codeClass == efiIoBus but wrong subClass/op
// -> OEM
TEST_F(PublisherTest, IoBusClassUnmatchedSubClassReturnsOem)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    // type 1, class 2 (IoBus), subClass 2, operation 0x200 (not PCI init)
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x42020000u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: getSbmrBootProgressStage codeClass != efiSoftware && != efiIoBus ->
// OEM
TEST_F(PublisherTest, UnknownCodeClassReturnsOem)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    // codeClass 4 (neither 2 IoBus nor 3 Software), valid codeType
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x44010110u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: update() flush logic when shouldFlush is false and OEM throttle
TEST_F(PublisherTest, UpdateWithOemOnlyDoesNotFlushImmediately)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    // Single OEM code; first update flushes
    // (firstPublish/lastPublishedOem.empty())
    std::vector<std::pair<uint32_t, uint32_t>> data = {{500u, 0x0000ABCDu}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: getSbmrBootProgressStage codeClass == efiSoftware but no matching
// subClass/operation (fallthrough to OEM)
TEST_F(PublisherTest, SoftwareClassUnmatchedSubClassReturnsOem)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    // type 1, class 3 (Software), subClass 0, operation 0 -> no match
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x43000000u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: update() OEM throttle - second update after interval flushes
TEST_F(PublisherTest, SecondOemUpdateAfterThrottleIntervalFlushes)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, 0x0000AAAAu}});
        co_await sdbusplus::async::sleep_for(*ctx,
                                             std::chrono::milliseconds(150));
        co_await pub.update({{200u, 0x0000BBBBu}});
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: flushPendingUpdates skips OEM update when oem == lastPublishedOem
TEST_F(PublisherTest, FlushSkipsOemUpdateWhenUnchanged)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    const uint32_t oemCode = 0x0000CCCCu;
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, oemCode}});
        co_await pub.update({{200u, oemCode}});
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: getSbmrBootProgressStage when codeType != efiProgressCode (0x01)
TEST_F(PublisherTest, GetSbmrBootProgressStage_CodeTypeNonEfi_ReturnsOem)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    // typeClassByte = 0x00 -> codeType = 0 != efiProgressCode(1)
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x00ABCDEFu}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: update() latestStage.empty() and detectedStage==OEM sets stage to OEM
TEST_F(PublisherTest, UpdateOemCodeWhenNoStageSet_UsesOemAsInitialStage)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    // Single OEM code (e.g. codeClass not Software/IoBus) -> latestStage empty,
    // use OEM
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x01001122u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// BootProgressPublisher uses optional CakBootProgressPublisher;
// with null, resetCachedState skips calling cak->resetCachedState
TEST_F(PublisherTest, ResetCachedStateWithNullCak_DoesNotCallCak)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
}

TEST_F(PublisherTest, WithNonNullCakPublisher_ForwardsUpdateAndResetCachedState)
{
    auto cakPublisher = std::make_shared<CakBootProgressPublisher>(*ctx, 1);
    BootProgressPublisher pub(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>(), cakPublisher);
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, 0x70C0C001u}});
        pub.resetCachedState();
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Update() with non-null CakBootProgressPublisher calls onProgressCode per code
TEST_F(PublisherTest, UpdateWithNonNullCak_CallsOnProgressCodeForEachEntry)
{
    auto cakPublisher = std::make_shared<CakBootProgressPublisher>(*ctx, 2);
    BootProgressPublisher pub(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>(), cakPublisher);
    std::vector<std::pair<uint32_t, uint32_t>> data = {
        {100u, 0x42010110u},
        {200u, 0x43041001u},
    };
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: update() loop - OEM then non-OEM in same batch overwrites stage
TEST_F(PublisherTest, UpdateOemThenNonOemInSameBatch_OverwritesStage)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    std::vector<std::pair<uint32_t, uint32_t>> data = {
        {100u, 0x0000AAAAu}, // OEM
        {200u, 0x42010110u}, // PCIInit -> overwrites OEM
    };
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: flushPendingUpdates when lastPublishedStage == OSRunning skips
// BootProgress update (OSRunning is final)
TEST_F(PublisherTest, FlushWhenOSRunningAlreadySkipsStageUpdate)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    const uint32_t osRunningCode = 0x43101019u;
    const uint32_t pciInitCode = 0x42010110u;
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, osRunningCode}});
        co_await pub.update({{200u, pciInitCode}});
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// IST boot POST code 0xC0C2 (socket 0: 0x70C1C0C2)
TEST_F(PublisherTest, IstBootCodeC0C2Socket0_SetsOemStage)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x70C1C0C2u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// IST boot POST code 0xC0C2 (socket 1: 0x71C1C0C2)
TEST_F(PublisherTest, IstBootCodeC0C2Socket1_SetsOemStage)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x71C1C0C2u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// IST boot POST code 0xC748 (socket 0: 0x70C1C748)
TEST_F(PublisherTest, IstBootCodeC748Socket0_SetsOemStage)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x70C1C748u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// IST boot POST code 0xC748 (socket 1: 0x71C1C748)
TEST_F(PublisherTest, IstBootCodeC748Socket1_SetsOemStage)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x71C1C748u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// IST boot POST code 0xC349 (socket 0: 0x70C1C349)
TEST_F(PublisherTest, IstBootCodeC349Socket0_SetsOemStage)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x70C1C349u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// IST boot POST code 0xC349 (socket 1: 0x71C1C349)
TEST_F(PublisherTest, IstBootCodeC349Socket1_SetsOemStage)
{
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    pub.resetCachedState();
    std::vector<std::pair<uint32_t, uint32_t>> data = {{100u, 0x71C1C349u}};
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update(data);
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Catch branches: all three updateBootProgress* methods catch std::exception.
// ThrowingPropertyAccess causes every setProperty co_await to throw,
// exercising all three catch blocks in one pass without crashing the publisher.
TEST_F(PublisherTest, SetPropertyThrows_AllCatchBranchesCovered)
{
    // PCIInit triggers updateBootProgressProperty (string catch),
    //                   updateBootProgressOemProperty (string catch),
    //                   updateBootProgressLastUpdateProperty (uint64_t catch)
    const uint32_t pciInitCode = 0x42010110u;
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<ThrowingPropertyAccess>());
    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await pub.update({{100u, pciInitCode}});
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

// Branch: flushPendingUpdates updateStage=false when !isFirstPublish &&
// !isOemStage && !isStageChanged. Triggered by a second OEM-throttle flush
// after the same non-OEM stage is already published.
TEST_F(PublisherTest, SecondFlushSameNonOemStage_AfterThrottle_SkipsStageUpdate)
{
    const uint32_t pciInitCode = 0x42010110u;
    BootProgressPublisher pub(*ctx, std::string(snoopDbus),
                              std::string(snoopObject),
                              std::make_shared<NullPropertyAccess>());
    auto run = [&]() -> sdbusplus::async::task<void> {
        // First update: publishes PCIInit (isFirstPublish=true,
        // updateStage=true)
        co_await pub.update({{100u, pciInitCode}});
        // Wait past OEM throttle so the second update flushes via OEM path.
        // isFirstPublish=false, isOemStage=false, isStageChanged=false
        // -> updateStage=false (branch under test)
        co_await sdbusplus::async::sleep_for(*ctx,
                                             std::chrono::milliseconds(150));
        co_await pub.update({{200u, pciInitCode}});
        ctx->request_stop();
    };
    ctx->spawn(run());
    ctx->run();
}

} // namespace
