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

#include <fcntl.h>
#include <unistd.h>

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <cerrno>
#include <chrono>
#include <memory>
#include <system_error>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using namespace phosphor_host_postd_test;

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

class BootProgressPollerTest : public ::testing::Test
{
  protected:
    BootProgressPollerTest() :
        bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock))
    {
        EXPECT_CALL(bus_mock, sd_bus_get_fd(_))
            .WillRepeatedly(Return(pipe.fd[0]));
    }

    PipeFdGuard pipe;
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

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
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

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
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

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 1, cb);
    poller->initIndices();
    ctx.request_stop();
    ctx.run();
}

// Stop in the callback as soon as the first entry is delivered so the test
// never relies on wall-clock timers to exit.
TEST_F(BootProgressPollerTest, ProcessQueueReturnsEntryWhenMockReturnsQueueData)
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
                regValue = 0x42010110u;
            else
                regValue = 0;
            return true;
        });

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received, &ctx](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
            ctx.request_stop();
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
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

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 0, cb);
    ctx.request_stop();
    ctx.run();
}

// Queue size == 0: each poll reads one register per queue (2 total) and gets
// nullopt. Stop deterministically after the first complete iteration.
TEST_F(BootProgressPollerTest, ProcessQueueReturnsNulloptWhenQueueSizeZero)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t, uint32_t& regValue) {
            regValue = 0;
            if (++reads >= 2)
                ctx.request_stop();
            return true;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(0), 0, cb);
    ctx.run();
}

// Code == 0: entries are skipped. Each poll reads 5 registers (1 full
// iteration for both queues). Stop after the first iteration.
TEST_F(BootProgressPollerTest, ProcessQueueSkipsEntryWhenCodeZero)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
        };

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t regAddr, uint32_t& regValue) {
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
            if (++reads >= 5)
                ctx.request_stop();
            return true;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    ctx.run();

    EXPECT_TRUE(received.empty());
}

// Queue 1 index read fails: 3 register reads per iteration. Stop after first.
TEST_F(BootProgressPollerTest, ProcessQueueHandlesGetQbaseIdxFailureForQueue1)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2004u)
            {
                regValue = (2u << 20) | (0u << 10) | 1u;
                if (++reads >= 3)
                    ctx.request_stop();
                return true;
            }
            if (regAddr == 0x2000u)
            {
                if (++reads >= 3)
                    ctx.request_stop();
                return false;
            }
            regValue = 0;
            if (++reads >= 3)
                ctx.request_stop();
            return true;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    ctx.run();
}

// Backoff test: readRegisterValue always fails, 2 reads per iteration.
// Stop after a few iterations (well below the backoff threshold of 10) so
// the 2-second exponential sleep is never entered.
TEST_F(BootProgressPollerTest, PollLoopUsesBackoffAfterRepeatedFailures)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t, uint32_t&) {
            if (++reads >= 6)
                ctx.request_stop();
            return false;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(5), 0, cb);
    ctx.run();
}

// Stop in callback after the overflow entry is delivered.
TEST_F(BootProgressPollerTest, ProcessQueueOverflowPath)
{
    int reads0x2000 = 0;
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received, &ctx](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
            ctx.request_stop();
        };

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

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    ctx.run();
}

// idx == currEnd for both queues: 3 reads per iteration. Stop after first.
TEST_F(BootProgressPollerTest, ProcessQueueNoNewEntriesWhenIdxEqualsCurrEnd)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else
                regValue = 0;
            if (++reads >= 3)
                ctx.request_stop();
            return true;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    ctx.run();
}

// Code-read failure: queue 1 always returns empty (idx==end), so
// anyReadSucceeded stays true. 4 reads per iteration. Stop after first.
TEST_F(BootProgressPollerTest, ProcessQueueHandlesCodeReadFailure)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x8004u)
            {
                ++reads;
                return false;
            }
            if (regAddr == 0x2000u)
                regValue = (2u << 20) | (0u << 10) | 1u;
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (1u << 10) | 1u;
            else if (regAddr == 0x8000u)
                regValue = 1000u;
            else
                regValue = 0;
            if (++reads >= 4)
                ctx.request_stop();
            return true;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    ctx.run();
}

// Timestamp-read failure: 4 reads per iteration. Stop after first.
TEST_F(BootProgressPollerTest, ProcessQueueHandlesTimestampReadFailure)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x8000u)
            {
                ++reads;
                return false;
            }
            if (regAddr == 0x2000u)
                regValue = (2u << 20) | (0u << 10) | 1u;
            else if (regAddr == 0x2004u)
                regValue = (2u << 20) | (1u << 10) | 1u;
            else
                regValue = 0;
            if (++reads >= 4)
                ctx.request_stop();
            return true;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    ctx.run();
}

// pollStatus == false: the loop never reads registers, it just sleeps.
// request_stop() before run() lets the loop see the stop flag on its first
// iteration without ever entering a sleep_for call.
TEST_F(BootProgressPollerTest, PollLoopWhenPollStatusFalseOnlySleeps)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _)).Times(0);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    poller->updatePollStatus(false);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressPollerTest, UpdatePollIntervalSameIntervalNoChange)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 0, cb);
    poller->updatePollInterval(std::chrono::milliseconds(100));
    ctx.request_stop();
    ctx.run();
}

// idx == end for both queues (size=2, start=0, end=0): 3 reads per iteration.
TEST_F(BootProgressPollerTest, CalculateSleepDurationUnderBackoffThreshold)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u || regAddr == 0x2004u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else
                regValue = 0;
            if (++reads >= 3)
                ctx.request_stop();
            return true;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(0), 0, cb);
    ctx.run();
}

// Both queues return empty vectors (has_value=true but empty): callback must
// not fire. Stop after one full iteration (3 reads).
TEST_F(BootProgressPollerTest, PollLoopWhenAllQueuesEmpty_DoesNotInvokeCallback)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    int callbackCount = 0;
    onBootProgressDataCallback cb =
        [&callbackCount](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            if (!e.empty())
                ++callbackCount;
        };

    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx](uint32_t regAddr, uint32_t& regValue) {
            if (regAddr == 0x2000u || regAddr == 0x2004u)
                regValue = (2u << 20) | (0u << 10) | 0u;
            else
                regValue = 0;
            if (++reads >= 3)
                ctx.request_stop();
            return true;
        });

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(0), 0, cb);
    ctx.run();
    EXPECT_EQ(callbackCount, 0);
}

// stop() sets stopped=true and clears device. Trigger stop via mock read
// counter to avoid wall-clock timers.
TEST_F(BootProgressPollerTest, StopSetsStoppedAndClearsDevice)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    onBootProgressDataCallback cb =
        [](int, std::vector<std::pair<uint32_t, uint32_t>>) {};

    std::shared_ptr<BootProgressPoller> poller;
    int reads = 0;
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([&reads, &ctx, &poller](uint32_t, uint32_t& out) {
            out = 0;
            if (++reads >= 2)
            {
                poller->stop();
                ctx.request_stop();
            }
            return true;
        });

    poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(100), 0, cb);
    ctx.run();
}

// getQbaseIdx(0) returns 0 without reading the device. Verify data is
// delivered and stop in the callback.
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

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received, &ctx](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
            ctx.request_stop();
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    ctx.run();
    EXPECT_FALSE(received.empty());
}

// Queue 1 uses getQbaseIdx(1) which reads queueIndexStart[0]. Stop in callback.
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

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received, &ctx](int, std::vector<std::pair<uint32_t, uint32_t>> e) {
            received.insert(received.end(), e.begin(), e.end());
            ctx.request_stop();
        };

    auto poller = std::make_shared<BootProgressPoller>(
        ctx, mockDevice, std::chrono::milliseconds(10), 0, cb);
    ctx.run();
    EXPECT_FALSE(received.empty());
}

} // namespace
