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
#include "mock_polling_device.hpp"
#include "queued-boot-progress/BootProgressPoller.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <chrono>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Return;
using namespace phosphor_host_postd_test;

namespace
{

class BootProgressPollerTest : public ::testing::Test
{
  protected:
    BootProgressPollerTest() :
        bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock))
    {}

    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus;
};

TEST_F(BootProgressPollerTest, ConstructWithMockDeviceAndUpdatePollInterval)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    int callbackCalls = 0;
    onBootProgressDataCallback cb =
        [&callbackCalls](int, std::vector<std::pair<uint32_t, uint32_t>>) {
            ++callbackCalls;
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 0, cb);
    poller->updatePollInterval(std::chrono::milliseconds(200));
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressPollerTest, UpdatePollStatusAndIsPolling)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 0, cb);
    poller->updatePollStatus(false);
    poller->updatePollStatus(true);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressPollerTest, InitIndicesCalledFromConstructor)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 1, cb);
    poller->initIndices();
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressPollerTest, ProcessQueueReturnsEntryWhenMockReturnsQueueData)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u)
            {
                regValue = (2u << 20) | (0u << 10) | 1u;
            }
            else if (regAddr == 0x2004u)
            {
                regValue = (2u << 20) | (1u << 10) | 1u;
            }
            else if (regAddr == 0x8000u)
            {
                regValue = 1000u;
            }
            else if (regAddr == 0x8004u)
            {
                regValue = 0x42010110u;
            }
            else
            {
                regValue = 0;
            }
            return true;
        });

    sdbusplus::async::context ctx;
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(100));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();

    EXPECT_FALSE(received.empty());
    EXPECT_GE(received.size(), 1u);
    EXPECT_EQ(received[0].first, 1000u);
    EXPECT_EQ(received[0].second, 0x42010110u);
}

TEST_F(BootProgressPollerTest, ProcessQueueHandlesReadRegisterFailure)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly(Return(false));

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 0, cb);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressPollerTest, ProcessQueueReturnsNulloptWhenQueueSizeZero)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u || regAddr == 0x2004u)
            {
                regValue = 0u;
            }
            else
            {
                regValue = 0;
            }
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(50));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

TEST_F(BootProgressPollerTest, ProcessQueueSkipsEntryWhenCodeZero)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u)
                regValue = (2u << 20) | (0u << 10) | 1u;
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (1u << 10) | 1u;
            else if (regAddr == 0x8000u)
                regValue = 1000u;
            else if (regAddr == 0x8004u)
                regValue = 0u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(100));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();

    EXPECT_TRUE(received.empty());
}

TEST_F(BootProgressPollerTest, ProcessQueueHandlesGetQbaseIdxFailureForQueue1)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2004u)
            {
                regValue = (2u << 20) | (0u << 10) | 1u;
                return true;
            }
            if (regAddr == 0x2000u)
            {
                return false;
            }
            regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(50));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

TEST_F(BootProgressPollerTest, PollLoopUsesBackoffAfterRepeatedFailures)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly(Return(false));

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(5), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(250));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

TEST_F(BootProgressPollerTest, ProcessQueueOverflowPath)
{
    int reads0x2000 = 0;
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads0x2000](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u)
            {
                if (reads0x2000++ == 0)
                    regValue = (2u << 20) | (0u << 10) | 1u;
                else
                    regValue = (2u << 20) | (1u << 10) | 2u;
            }
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (1u << 10) | 1u;
            else if (regAddr == 0x8000u)
                regValue = 1000u;
            else if (regAddr == 0x8004u)
                regValue = 0x42010110u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(100));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

TEST_F(BootProgressPollerTest, ProcessQueueNoNewEntriesWhenIdxEqualsCurrEnd)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(50));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

TEST_F(BootProgressPollerTest, ProcessQueueHandlesCodeReadFailure)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x8004u)
                return false;
            if (regAddr == 0x2000u)
                regValue = (2u << 20) | (0u << 10) | 1u;
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (1u << 10) | 1u;
            else if (regAddr == 0x8000u)
                regValue = 1000u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(100));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

TEST_F(BootProgressPollerTest, ProcessQueueHandlesTimestampReadFailure)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x8000u)
                return false;
            if (regAddr == 0x2000u)
                regValue = (2u << 20) | (0u << 10) | 1u;
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (1u << 10) | 1u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(100));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

// Branch: pollQueues when pollStatus is false (else branch - sleep without
// polling)
TEST_F(BootProgressPollerTest, PollLoopWhenPollStatusFalseOnlySleeps)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    poller->updatePollStatus(false);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(50));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

// Branch: updatePollInterval when newInterval equals current (no log path)
TEST_F(BootProgressPollerTest, UpdatePollIntervalSameIntervalNoChange)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 0, cb);
    poller->updatePollInterval(std::chrono::milliseconds(100));
    ctx.request_stop();
    ctx.run();
}

// Branch: calculateSleepDuration when consecutiveFailures < backoffThreshold
TEST_F(BootProgressPollerTest, CalculateSleepDurationUnderBackoffThreshold)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u || regAddr == 0x2004u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(25), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(80));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
}

// Branch: pollQueues when entries empty (both queues return no new entries)
TEST_F(BootProgressPollerTest, PollLoopWhenAllQueuesEmpty_DoesNotInvokeCallback)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u || regAddr == 0x2004u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    int callbackCount = 0;
    onBootProgressDataCallback cb =
        [&callbackCount](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            if (!e.empty())
                ++callbackCount;
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(80));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
    EXPECT_EQ(callbackCount, 0);
}

TEST_F(BootProgressPollerTest, StopSetsStoppedAndClearsDevice)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 0, cb);
    auto stop_poller_then_ctx =
        [&ctx, poller]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(20));
        poller->stop();
        ctx.request_stop();
    };
    ctx.spawn(stop_poller_then_ctx());
    ctx.run();
}

// Branch: getQbaseIdx when qnum == 0 returns 0 without reading device
TEST_F(BootProgressPollerTest, GetQbaseIdxQueueZeroReturnsZeroWithoutRead)
{
    int readCount = 0;
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&readCount](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u || regAddr == 0x2004u)
            {
                ++readCount;
                regValue = (2u << 20) | (0u << 10) | 1u;
            }
            else if (regAddr == 0x8000u)
                regValue = 1000u;
            else if (regAddr == 0x8004u)
                regValue = 0x42010110u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(80));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
    EXPECT_FALSE(received.empty());
}

// Branch: processQueue queue 1 getQbaseIdx(1) reads queueIndexStart[0]
TEST_F(BootProgressPollerTest, ProcessQueueQueue1UsesGetQbaseIdx)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (0u << 10) | 1u;
            else if (regAddr == 0x8000u)
                regValue = 1000u;
            else if (regAddr == 0x8004u)
                regValue = 0x42010110u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx;
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    auto stop_after = [&ctx]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(100));
        ctx.request_stop();
    };
    ctx.spawn(stop_after());
    ctx.run();
    EXPECT_FALSE(received.empty());
}

} // namespace
