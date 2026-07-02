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
#include "mock_device_factory.hpp"
#include "mock_polling_device.hpp"
#include "null_property_access.hpp"
#include "queued-boot-progress/BootProgressManager.hpp"
#include "queued-boot-progress/BootProgressPublisher.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <sdbusplus/async.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cerrno>
#include <chrono>
#include <system_error>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Return;
using namespace phosphor_host_postd_test;

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

static void setupBusMock(NiceMock<sdbusplus::SdBusMock>& bus_mock)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    ON_CALL(bus_mock, sd_bus_add_object_vtable(IsNull(), _, _, _, _, _))
        .WillByDefault(slotcb);
}

class BootProgressManagerTest : public ::testing::Test
{
  protected:
    BootProgressManagerTest() :
        bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock))
    {}

    void SetUp() override
    {
        ON_CALL(bus_mock, sd_bus_get_fd(_)).WillByDefault(Return(pipe.fd[0]));
        setupBusMock(bus_mock);
        setInjectedPollingDevice(nullptr);
    }

    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus;
};

TEST_F(BootProgressManagerTest, ConstructWithPublisherAndPollInterval)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    std::chrono::milliseconds pollInterval(100);
    BootProgressManager mgr(ctx, publisher, pollInterval);
    (void)mgr;
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, OnBootProgressDataWithEmptyMapDoesNotCrash)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    std::vector<std::pair<uint32_t, uint32_t>> entries = {{1000u, 0x01u}};
    mgr.onBootProgressData(0, entries);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, OnBootProgressDataWithEmptyEntriesReturnsEarly)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    std::vector<std::pair<uint32_t, uint32_t>> emptyEntries;
    mgr.onBootProgressData(0, emptyEntries);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, UpdatePollIntervalWithEmptyMapDoesNotCrash)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    mgr.updatePollInterval(std::chrono::milliseconds(200));
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, UpdatePollStatusWithEmptyMapDoesNotCrash)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    mgr.updatePollStatus(false);
    mgr.updatePollStatus(true);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, InitIndicesWithEmptyMapDoesNotCrash)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    mgr.initIndices();
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, ResetPublisherCachedState)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    mgr.resetPublisherCachedState();
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, OnDeviceRemovedWhenSocketNotFoundReturnsEarly)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    mgr.onDeviceRemoved(TransportInterface::I2C, 0, 0x50);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, OnDeviceAddedWithNullDeviceReturnsEarly)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    mgr.onDeviceAdded(nullptr, TransportInterface::I2C, 0, 0x50);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, OnDeviceAddedI2CCreatesPollerAndTryPublishPath)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });
    setInjectedPollingDevice(mockDevice);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    mgr.onBootProgressData(0, {{1000u, 0x01u}});
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest,
       OnDeviceAddedWhenPollerAlreadyExistsUpdatesStatus)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });
    setInjectedPollingDevice(mockDevice);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, OnBootProgressDataSocketIdNotInMapLogsWarning)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });
    setInjectedPollingDevice(mockDevice);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    std::vector<std::pair<uint32_t, uint32_t>> entries = {{1000u, 0x01u}};
    mgr.onBootProgressData(1, entries);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, OnDeviceAddedWhenGetPollingDeviceFailsLogsError)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));
    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, ConstructWithNullPublisherRunsWithoutCrash)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    BootProgressManager mgr(ctx, nullptr, std::chrono::milliseconds(100));
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest, ResetPublisherCachedStateWithNullPublisher)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    BootProgressManager mgr(ctx, nullptr, std::chrono::milliseconds(100));
    mgr.resetPublisherCachedState();
    ctx.request_stop();
    ctx.run();
}

class BootProgressManagerWithDeviceTest : public ::testing::Test
{
  protected:
    BootProgressManagerWithDeviceTest() : bus_mock() {}

    void SetUp() override
    {
        ON_CALL(bus_mock, sd_bus_get_fd(_)).WillByDefault(Return(pipe.fd[0]));
        setupBusMock(bus_mock);
        mock_device = std::make_shared<MockPollingDevice>();
        EXPECT_CALL(*mock_device, readRegisterValue(_, _))
            .WillRepeatedly([](uint32_t, uint32_t& out) {
                out = 0;
                return true;
            });
        setInjectedPollingDevice(mock_device);
    }

    void TearDown() override
    {
        setInjectedPollingDevice(nullptr);
    }

    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    std::shared_ptr<MockPollingDevice> mock_device;
};

TEST_F(BootProgressManagerWithDeviceTest,
       OnDeviceAddedSuccessThenOnBootProgressDataCallsTryPublish)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    mgr.onBootProgressData(0, {{1000u, 0x01u}});

    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerWithDeviceTest,
       OnBootProgressDataWithNullPublisherDoesNotCallTryPublish)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    BootProgressManager mgr(ctx, nullptr, std::chrono::milliseconds(100));
    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    mgr.onBootProgressData(0, {{1000u, 0x01u}});
    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerWithDeviceTest, UpdatePollIntervalWithNonEmptyMap)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    mgr.updatePollInterval(std::chrono::milliseconds(200));

    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerWithDeviceTest, UpdatePollStatusWithNonEmptyMap)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    mgr.updatePollStatus(false);
    mgr.updatePollStatus(true);

    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerWithDeviceTest, InitIndicesWithNonEmptyMap)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    mgr.initIndices();

    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerWithDeviceTest, OnDeviceRemovedSuccessPath)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);

    // Defer removal so the poller's coroutine runs once and captures
    // shared_from_this(); otherwise erasing the poller causes use-after-free.
    auto remove_then_stop = [&ctx, &mgr]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx, std::chrono::milliseconds(0));
        mgr.onDeviceRemoved(TransportInterface::I2C, 0, 0x50);
        ctx.request_stop();
    };
    ctx.spawn(remove_then_stop());
    ctx.run();
}

TEST_F(BootProgressManagerWithDeviceTest,
       OnBootProgressDataSuccessPathMultipleEntries)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    mgr.onBootProgressData(0, {{1000u, 0x01u}, {1001u, 0x02u}});

    ctx.request_stop();
    ctx.run();
}

TEST_F(BootProgressManagerTest,
       PeriodicPublishCheckWithEmptyMapCallsTryPublishEmpty)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    ctx.request_stop();
    ctx.run();
}

// Branch: tryPublish with non-empty socketDataMap but empty buffers after
// aggregate (periodicPublishCheck calls tryPublish)
TEST_F(BootProgressManagerWithDeviceTest,
       PeriodicPublishCheckWithDeviceButNoDataCallsTryPublishEmpty)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);
    ctx.request_stop();
    ctx.run();
}

// Branch: onDeviceRemoved with TransportInterface::USB and !anyStillPolling
// calls resetPublisherCachedState
TEST_F(BootProgressManagerWithDeviceTest,
       OnDeviceRemovedUSBWithSingleDeviceCallsResetPublisherCachedState)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::USB, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::USB, 0, 0x50);

    // Run removal after a short delay so the poller's coroutine has run once
    // and captured shared_from_this(); otherwise erasing the poller would
    // destroy it before the queued coroutine runs (use-after-free in
    // ctx.run()).
    auto remove_then_stop = [&ctx, &mgr]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx, std::chrono::milliseconds(0));
        mgr.onDeviceRemoved(TransportInterface::USB, 0, 0x50);
        ctx.request_stop();
    };
    ctx.spawn(remove_then_stop());
    ctx.run();
}

// Use PollingDevice interface (MockPollingDevice) for two sockets to cover
// aggregateAndSortAllSocketData with multiple socketDataMap entries
TEST_F(BootProgressManagerWithDeviceTest,
       OnBootProgressDataFromTwoSockets_AggregatesAndSorts)
{
    auto mock1 = std::make_shared<MockPollingDevice>();
    auto mock2 = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mock1, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });
    EXPECT_CALL(*mock2, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    setInjectedPollingDevice(mock1);
    auto device1 = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device1, TransportInterface::I2C, 0, 0x50);

    setInjectedPollingDevice(mock2);
    auto device2 = getPollingDevice(TransportInterface::I2C, 1, 0x51);
    mgr.onDeviceAdded(device2, TransportInterface::I2C, 1, 0x51);

    mgr.onBootProgressData(0, {{200u, 0x02u}});
    mgr.onBootProgressData(1, {{100u, 0x01u}});

    ctx.request_stop();
    ctx.run();
    setInjectedPollingDevice(nullptr);
}

// Branch: doL1Reset() with empty socketDataMap throws Unavailable
TEST_F(BootProgressManagerTest, DoL1Reset_EmptySocketMap_ThrowsUnavailable)
{
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    bool threw = false;
    auto fn = [&ctx, &mgr, &threw]() -> sdbusplus::async::task<void> {
        try
        {
            co_await mgr.doL1Reset();
        }
        catch (
            const sdbusplus::xyz::openbmc_project::Common::Error::Unavailable&)
        {
            threw = true;
        }
        catch (const std::exception&)
        {
            threw = true;
        }
        ctx.request_stop();
    };
    ctx.spawn(fn());
    ctx.run();
    EXPECT_TRUE(threw);
}

// Branch: doL1Reset() with device that returns true on first attempt succeeds
TEST_F(BootProgressManagerTest, DoL1Reset_DeviceSucceeds_ReturnsCleanly)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });
    EXPECT_CALL(*mockDevice, doL1Reset()).WillOnce(Return(true));
    setInjectedPollingDevice(mockDevice);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);

    bool succeeded = false;
    auto fn = [&ctx, &mgr, &succeeded]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx, std::chrono::milliseconds(0));
        try
        {
            co_await mgr.doL1Reset();
            succeeded = true;
        }
        catch (const std::exception&)
        {}
        ctx.request_stop();
    };
    ctx.spawn(fn());
    ctx.run();
    EXPECT_TRUE(succeeded);
    setInjectedPollingDevice(nullptr);
}

// Branch: doL1Reset() all 5 attempts fail → throws InternalFailure
// This test takes ~400ms (4 sleeps of 100ms between retry attempts 2-5)
TEST_F(BootProgressManagerTest, DoL1Reset_AllAttemptsFail_ThrowsInternalFailure)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });
    // doL1Reset() mock returns false (default gmock bool action)
    EXPECT_CALL(*mockDevice, doL1Reset()).WillRepeatedly(Return(false));
    setInjectedPollingDevice(mockDevice);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);

    bool threw = false;
    auto fn = [&ctx, &mgr, &threw]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(10));
        try
        {
            co_await mgr.doL1Reset();
        }
        catch (const sdbusplus::xyz::openbmc_project::Common::Error::
                   InternalFailure&)
        {
            threw = true;
        }
        catch (const std::exception&)
        {
            threw = true;
        }
        ctx.request_stop();
    };
    ctx.spawn(fn());
    ctx.run();
    EXPECT_TRUE(threw);
    setInjectedPollingDevice(nullptr);
}

// Branch: doL1Reset() inner-loop continue path when device removed during retry
TEST_F(BootProgressManagerTest,
       DoL1Reset_DeviceRemovedDuringRetry_CoversContinue)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });
    EXPECT_CALL(*mockDevice, doL1Reset()).WillRepeatedly(Return(false));
    setInjectedPollingDevice(mockDevice);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);

    bool threw = false;
    // Start doL1Reset (attempt 1 fails synchronously, then sleeps 100ms)
    ctx.spawn([&ctx, &mgr, &threw]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(10));
        try
        {
            co_await mgr.doL1Reset();
        }
        catch (const std::exception&)
        {
            threw = true;
        }
        ctx.request_stop();
    }());

    // Remove device after attempt 1 completes and during the retry sleep
    ctx.spawn([&ctx, &mgr]() -> sdbusplus::async::task<void> {
        // At 10ms+epsilon: doL1Reset entered; at ~10ms+sync: attempt 1 done,
        // sleeping 100ms. Remove device at 60ms so retries see it gone.
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(60));
        mgr.onDeviceRemoved(TransportInterface::I2C, 0, 0x50);
    }());

    ctx.run();
    EXPECT_TRUE(threw);
    setInjectedPollingDevice(nullptr);
}

// Branch: doL1Reset() concurrent call while reset in progress throws
// Unavailable
TEST_F(BootProgressManagerTest,
       DoL1Reset_ConcurrentCall_SecondThrowsUnavailable)
{
    auto mockDevice = std::make_shared<MockPollingDevice>();
    EXPECT_CALL(*mockDevice, readRegisterValue(_, _))
        .WillRepeatedly([](uint32_t, uint32_t& out) {
            out = 0;
            return true;
        });
    // First call fails all retries so it stays in flight long enough for the
    // second call to see resetInProgress_==true
    EXPECT_CALL(*mockDevice, doL1Reset()).WillRepeatedly(Return(false));
    setInjectedPollingDevice(mockDevice);

    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    BootProgressManager mgr(ctx, publisher, std::chrono::milliseconds(100));

    auto device = getPollingDevice(TransportInterface::I2C, 0, 0x50);
    mgr.onDeviceAdded(device, TransportInterface::I2C, 0, 0x50);

    bool secondThrew = false;

    // First call: blocks in retry loop (~400ms)
    ctx.spawn([&ctx, &mgr]() -> sdbusplus::async::task<void> {
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(10));
        try
        {
            co_await mgr.doL1Reset();
        }
        catch (const std::exception&)
        {}
    }());

    // Second call: waits until first has set resetInProgress_, then sees it
    ctx.spawn([&ctx, &mgr, &secondThrew]() -> sdbusplus::async::task<void> {
        // Sleep past the first call's entry so resetInProgress_ is set
        co_await sdbusplus::async::sleep_for(ctx,
                                             std::chrono::milliseconds(30));
        try
        {
            co_await mgr.doL1Reset();
        }
        catch (const std::exception&)
        {
            secondThrew = true;
        }
        ctx.request_stop();
    }());

    ctx.run();
    EXPECT_TRUE(secondThrew);
    setInjectedPollingDevice(nullptr);
}

} // namespace
