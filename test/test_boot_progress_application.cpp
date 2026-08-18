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
#include "queued-boot-progress/BootProgressApplication.hpp"
#include "queued-boot-progress/BootProgressManager.hpp"
#include "queued-boot-progress/BootProgressPublisher.hpp"

#include <fcntl.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

#include <sdbusplus/async.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/slot.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
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

/** Fake D-Bus access for tests; configurable getProperty and
 * waitForPropertiesChanged. */
class FakeDbusPropertyAccess : public IDbusPropertyAccess
{
  public:
    explicit FakeDbusPropertyAccess(sdbusplus::async::context& ctx) : ctx(ctx)
    {}

    std::string getPropertyOsState;
    std::string getPropertyHostState;
    std::string getPropertyBootProgress;
    bool getPropertyHostStateThrows = false;
    bool getPropertyBootProgressThrows = false;
    bool getPropertyOsStateThrows = false;
    int waitForPropertiesChangedCallCount = 0;
    std::optional<PropertiesChangedTuple> waitForPropertiesChangedResult;
    bool waitForPropertiesChangedThrows = false;

    sdbusplus::async::task<std::string> getProperty(
        const char* service, const char* path, const char* interface,
        const char* property) override
    {
        (void)service;
        (void)path;
        if (interface == std::string(dbusOSStatusInterface) &&
            property == std::string("OperatingSystemState"))
        {
            if (getPropertyOsStateThrows)
                throw std::runtime_error("test getProperty OS state error");
            co_return getPropertyOsState;
        }
        if (interface == std::string(dbusHostStateInterface) &&
            property == std::string("CurrentHostState"))
        {
            if (getPropertyHostStateThrows)
                throw std::runtime_error("test getProperty host state error");
            co_return getPropertyHostState;
        }
        if (interface == std::string(dbusBootProgressInterface) &&
            property == std::string("BootProgress"))
        {
            if (getPropertyBootProgressThrows)
                throw std::runtime_error(
                    "test getProperty boot progress error");
            co_return getPropertyBootProgress;
        }
        throw std::runtime_error("test getProperty unknown");
    }

    sdbusplus::async::task<PropertiesChangedTuple> waitForPropertiesChanged(
        const std::string& path, const std::string& interface) override
    {
        (void)path;
        (void)interface;
        ++waitForPropertiesChangedCallCount;
        if (waitForPropertiesChangedThrows &&
            waitForPropertiesChangedCallCount == 1)
            throw std::runtime_error("test waitForPropertiesChanged error");
        if (waitForPropertiesChangedResult)
        {
            auto result = *waitForPropertiesChangedResult;
            waitForPropertiesChangedResult.reset();
            co_return result;
        }
        // Cap iterations so tests that spawn monitor loops finish quickly
        // (avoids timeout when scheduler delays the task that calls
        // request_stop()). 15 is enough for tests that need one result.
        constexpr int maxCallsBeforeStop = 15;
        if (waitForPropertiesChangedCallCount >= maxCallsBeforeStop)
        {
            ctx.request_stop();
        }
        co_await sdbusplus::async::sleep_for(ctx, std::chrono::milliseconds(1));
        co_return PropertiesChangedTuple{std::string{}, {}, {}};
    }

    std::vector<std::string> bootProgressWrites;

    sdbusplus::async::task<void> setProperty(const char*, const char*,
                                             const char*, const char* property,
                                             const std::string& value) override
    {
        if (property == std::string("BootProgress"))
        {
            bootProgressWrites.push_back(value);
        }
        co_return;
    }
    sdbusplus::async::task<void> setProperty(
        const char*, const char*, const char*, const char*, uint64_t) override
    {
        co_return;
    }

  private:
    sdbusplus::async::context& ctx;
};

class TestableApplication : public Application
{
  public:
    using Application::Application;
    using Application::isHostPowerStateOff;
    using Application::onBootProgressChange;
    using Application::onHostPowerStateChange;
    using Application::onOSStateChange;
};

constexpr const char* stateHostService = "xyz.openbmc_project.State.Host";
constexpr const char* stateHostPath = "/xyz/openbmc_project/state/host0";
constexpr const char* ifaceOSStatus =
    "xyz.openbmc_project.State.OperatingSystem.Status";
constexpr const char* ifaceHostState = "xyz.openbmc_project.State.Host";
constexpr const char* ifaceBootProgress =
    "xyz.openbmc_project.State.Boot.Progress";
constexpr const char* propOSState = "OperatingSystemState";
constexpr const char* propHostState = "CurrentHostState";
constexpr const char* propBootProgress = "BootProgress";

static const std::string testOSState =
    "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby";
static const std::string testHostState =
    "xyz.openbmc_project.State.Host.HostState.Running";
static const std::string testBootProgress =
    "xyz.openbmc_project.State.Boot.Progress.ProgressStages.OSRunning";

static int propertiesGetCallback(sd_bus_message* m, void*,
                                 sd_bus_error* retError)
{
    try
    {
        sdbusplus::message_t msg(m);
        std::string iface;
        std::string prop;
        msg.read(iface, prop);

        std::string value;
        if (iface == ifaceOSStatus && prop == propOSState)
            value = testOSState;
        else if (iface == ifaceHostState && prop == propHostState)
            value = testHostState;
        else if (iface == ifaceBootProgress && prop == propBootProgress)
            value = testBootProgress;
        else
            return sd_bus_error_set(retError,
                                    "org.freedesktop.DBus.Unknown.Property",
                                    "Unknown property");

        auto reply = msg.new_method_return();
        reply.append(std::variant<std::string>(value));
        reply.method_return();
        return 0;
    }
    catch (const std::exception&)
    {
        return sd_bus_error_set(retError, "org.freedesktop.DBus.Error.Failed",
                                "Properties.Get failed");
    }
}

static const sd_bus_vtable propertiesVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Get", "ss", "v", propertiesGetCallback, 0),
    SD_BUS_VTABLE_END,
};

class StateHostServer
{
  public:
    StateHostServer()
    {
        sd_bus* bus_ptr = nullptr;
        int r = sd_bus_open_user(&bus_ptr);
        if (r < 0)
            throw std::runtime_error("sd_bus_open_user failed");
        bus.reset(bus_ptr);

        sd_bus_slot* rawSlot = nullptr;
        r = sdbusplus::sdbus_impl.sd_bus_add_object_vtable(
            bus.get(), &rawSlot, stateHostPath,
            "org.freedesktop.DBus.Properties", propertiesVtable, nullptr);
        if (r < 0)
            throw std::runtime_error("sd_bus_add_object_vtable failed");
        slot = sdbusplus::slot_t(rawSlot, &sdbusplus::sdbus_impl);

        r = sdbusplus::sdbus_impl.sd_bus_request_name(
            bus.get(), stateHostService,
            SD_BUS_NAME_ALLOW_REPLACEMENT | SD_BUS_NAME_REPLACE_EXISTING);
        if (r < 0)
            throw std::runtime_error("sd_bus_request_name failed");

        thread = std::thread([this]() {
            while (!stopRequested())
            {
                sd_bus_wait(bus.get(), 100 * 1000);
                sd_bus_process(bus.get(), nullptr);
            }
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ~StateHostServer()
    {
        requestStop();
        if (thread.joinable())
            thread.join();
    }

    void requestStop()
    {
        std::lock_guard<std::mutex> lock(mutex);
        stopped = true;
    }

  private:
    bool stopRequested()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return stopped;
    }

    struct BusDeleter
    {
        void operator()(sd_bus* b) const
        {
            if (b)
            {
                sd_bus_flush(b);
                sd_bus_close(b);
                sd_bus_unref(b);
            }
        }
    };
    std::unique_ptr<sd_bus, BusDeleter> bus;
    sdbusplus::slot_t slot;
    std::thread thread;
    std::mutex mutex;
    bool stopped = false;
};

/** Free function coroutine: ctx parameter is copied into the heap-allocated
 * coroutine frame, avoiding the lambda-closure lifetime issue. */
static sdbusplus::async::task<void> stopContextTask(
    sdbusplus::async::context* ctx)
{
    ctx->request_stop();
    co_return;
}

static void stopContext(sdbusplus::async::context* ctx)
{
    ctx->spawn(stopContextTask(ctx));
}

TEST(BootProgressApplication, OsStateConstants)
{
    EXPECT_EQ(
        osStateBootComplete,
        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby");
    EXPECT_EQ(
        osStateInactive,
        "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive");
}

TEST(BootProgressApplication, HostPowerStateConstants)
{
    EXPECT_EQ(hostPowerStateRunning,
              "xyz.openbmc_project.State.Host.HostState.Running");
    EXPECT_EQ(hostPowerStateOff,
              "xyz.openbmc_project.State.Host.HostState.Off");
    EXPECT_EQ(hostPowerStateQuiesced,
              "xyz.openbmc_project.State.Host.HostState.Quiesced");
    EXPECT_EQ(hostPowerStateTransition,
              "xyz.openbmc_project.State.Host.HostState.TransitioningToOff");
    EXPECT_EQ(
        hostPowerStateTransitionToRunning,
        "xyz.openbmc_project.State.Host.HostState.TransitioningToRunning");
}

TEST(BootProgressApplication, DbusConstants)
{
    EXPECT_EQ(dbusHostStateService, "xyz.openbmc_project.State.Host");
    EXPECT_EQ(dbusHostStatePath, "/xyz/openbmc_project/state/host0");
    EXPECT_EQ(dbusOSStatusInterface,
              "xyz.openbmc_project.State.OperatingSystem.Status");
    EXPECT_EQ(dbusBootProgressInterface,
              "xyz.openbmc_project.State.Boot.Progress");
}

TEST(BootProgressApplication, IsHostPowerStateOff_WhenOff)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);
    EXPECT_TRUE(app.isHostPowerStateOff());
    app.onHostPowerStateChange(std::string(hostPowerStateOff));
    EXPECT_TRUE(app.isHostPowerStateOff());
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, IsHostPowerStateOff_WhenRunning)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);
    app.onHostPowerStateChange(std::string(hostPowerStateRunning));
    EXPECT_FALSE(app.isHostPowerStateOff());
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, IsHostPowerStateOff_WhenQuiesced)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);
    app.onHostPowerStateChange(std::string(hostPowerStateQuiesced));
    EXPECT_TRUE(app.isHostPowerStateOff());
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, IsHostPowerStateOff_WhenTransitioning)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);
    app.onHostPowerStateChange(std::string(hostPowerStateTransition));
    EXPECT_TRUE(app.isHostPowerStateOff());
    ctx.request_stop();
    ctx.run();
}

namespace
{
constexpr uint32_t osRunningCode = 0x43101019u;
constexpr uint32_t earlierStageCode = 0x42010110u;

/* Drives publisher->update(OSRunning), optionally signals a host state, then
 * publishes an earlier stage. Returns the BootProgress values written. */
std::vector<std::string> publishAcrossHostState(
    const std::optional<std::string>& hostState)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject), fake);
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    TestableApplication app(ctx, config, mgr, fake);

    auto run = [&]() -> sdbusplus::async::task<void> {
        co_await publisher->update({{100u, osRunningCode}});
        if (hostState)
        {
            app.onHostPowerStateChange(*hostState);
        }
        co_await publisher->update({{200u, earlierStageCode}});
        ctx.request_stop();
    };
    ctx.spawn(run());
    ctx.run();
    return fake->bootProgressWrites;
}
} // namespace

TEST(BootProgressApplication, TransitioningToRunningClearsOsRunningLatch)
{
    auto writes =
        publishAcrossHostState(std::string(hostPowerStateTransitionToRunning));
    ASSERT_EQ(writes.size(), 2u);
    EXPECT_EQ(writes[1],
              "xyz.openbmc_project.State.Boot.Progress.ProgressStages.PCIInit");
}

TEST(BootProgressApplication, OsRunningLatchHoldsWithoutHostStateChange)
{
    auto writes = publishAcrossHostState(std::nullopt);
    ASSERT_EQ(writes.size(), 1u);
}

TEST(BootProgressApplication, OsRunningLatchHoldsOnRunningState)
{
    auto writes = publishAcrossHostState(std::string(hostPowerStateRunning));
    ASSERT_EQ(writes.size(), 1u);
}

TEST(BootProgressApplication, IsHostPowerStateOff_WhenEmpty)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);
    EXPECT_TRUE(app.isHostPowerStateOff());
    app.onHostPowerStateChange(std::string(""));
    EXPECT_TRUE(app.isHostPowerStateOff());
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, GetInitialOsStateSuccessLogsState)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsState = std::string(testOSState);
    fake->getPropertyHostState = std::string(testHostState);
    fake->getPropertyBootProgress = std::string(testBootProgress);
    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);

    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
}

TEST(BootProgressApplication, GetInitialHostPowerStateSuccessLogsState)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsState = std::string(testOSState);
    fake->getPropertyHostState = std::string(hostPowerStateRunning);
    fake->getPropertyBootProgress = std::string(testBootProgress);
    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);

    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
}

TEST(BootProgressApplication, GetInitialBootProgressSuccessLogsState)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsState = std::string(testOSState);
    fake->getPropertyHostState = std::string(testHostState);
    fake->getPropertyBootProgress = std::string(bootProgressOsRunningStage);
    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);

    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
}

TEST(BootProgressApplication, UpdatePollIntervalWhenHostOffDisablesPolling)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);

    app.onHostPowerStateChange(std::string(hostPowerStateOff));
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, Initialize_GetPropertyOsStateThrows_LogsError)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsStateThrows = true;
    fake->getPropertyHostState = std::string(testHostState);
    fake->getPropertyBootProgress = std::string(testBootProgress);
    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);

    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
}

TEST(BootProgressApplication,
     Initialize_GetPropertyBootProgressThrows_ClearsState)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsState = std::string(testOSState);
    fake->getPropertyHostState = std::string(testHostState);
    fake->getPropertyBootProgressThrows = true;
    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);

    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
}

// Branch: monitor loops catch block when waitForPropertiesChanged throws
TEST(BootProgressApplication, MonitorLoop_WhenWaitThrows_LogsAndContinues)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsState = std::string(testOSState);
    fake->getPropertyHostState = std::string(testHostState);
    fake->getPropertyBootProgress = std::string(testBootProgress);
    fake->waitForPropertiesChangedThrows = true;

    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);
    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        co_await sdbusplus::async::sleep_for(*ctx,
                                             std::chrono::milliseconds(50));
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
}

TEST(BootProgressApplication, HandleHostPowerStateRunning_EnablesPolling)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);

    app.onHostPowerStateChange(std::string(hostPowerStateRunning));
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication,
     HandleHostPowerStateOff_CallsUpdatePollStatusFalse)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    config.transportInterface = TransportInterface::I2C;
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);

    app.onHostPowerStateChange(std::string(hostPowerStateOff));
    ctx.request_stop();
    ctx.run();
}

// Branch: updatePollInterval when OS boot complete and OSRunning (increased
// interval)
TEST(BootProgressApplication,
     OnBootProgressOsRunning_WhenBootComplete_CallsUpdatePollIntervalIncreased)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(1000);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);

    app.onOSStateChange(std::string(osStateBootComplete));
    app.onHostPowerStateChange(std::string(hostPowerStateRunning));
    app.onBootProgressChange(std::string(bootProgressOsRunningStage));
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, HandleHostPowerStateOff_CallsInitIndicesAndReset)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);

    app.onHostPowerStateChange(std::string(hostPowerStateOff));
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, HandleBootComplete_CallsUpdatePollIntervalLong)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(100);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);

    app.onOSStateChange(std::string(osStateBootComplete));
    app.onHostPowerStateChange(std::string(hostPowerStateRunning));
    app.onBootProgressChange(std::string(bootProgressOsRunningStage));
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, HandleOSStateChange_UpdatesPollInterval)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(150);
    auto fake = std::make_shared<FakeDbusPropertyAccess>(ctx);
    TestableApplication app(ctx, config, mgr, fake);
    app.onHostPowerStateChange(std::string(hostPowerStateRunning));

    app.onOSStateChange("SomeOSState");
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, Initialize_WithGetPropertyOverride_SetsState)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    config.transportInterface = TransportInterface::I2C;
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsState = std::string(testOSState);
    fake->getPropertyHostState = std::string(testHostState);
    fake->getPropertyBootProgress = std::string(testBootProgress);
    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);

    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
}

TEST(BootProgressApplication,
     Initialize_GetPropertyHostStateThrows_DefaultsRunning)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    config.transportInterface = TransportInterface::I2C;
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsState = std::string(testOSState);
    fake->getPropertyHostStateThrows = true;
    fake->getPropertyBootProgress = std::string(testBootProgress);
    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);

    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
}

TEST(BootProgressApplication, MonitorLoop_ProcessesFakeSignal)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    auto ctx = std::make_unique<sdbusplus::async::context>(
        sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        *ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *ctx, publisher, std::chrono::milliseconds(100));
    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    config.transportInterface = TransportInterface::I2C;
    auto fake = std::make_shared<FakeDbusPropertyAccess>(*ctx);
    fake->getPropertyOsState = std::string(testOSState);
    fake->getPropertyHostState = std::string(testHostState);
    fake->getPropertyBootProgress = std::string(testBootProgress);
    fake->waitForPropertiesChangedResult = PropertiesChangedTuple{
        std::string(dbusOSStatusInterface),
        std::map<std::string,
                 std::variant<std::string, int32_t, uint32_t, bool>>{
            {"OperatingSystemState", std::string(testOSState)}},
        std::vector<std::string>{}};
    auto app = std::make_shared<TestableApplication>(*ctx, config, mgr, fake);

    auto fn = [ctx = ctx.get(), app]() -> sdbusplus::async::task<void> {
        co_await app->initialize();
        co_await sdbusplus::async::sleep_for(*ctx,
                                             std::chrono::milliseconds(50));
        ctx->request_stop();
    };
    ctx->spawn(fn());
    ctx->run();
    EXPECT_GE(fake->waitForPropertiesChangedCallCount, 1);
}

TEST(BootProgressApplication, ConstructThenStopRun)
{
    PipeFdGuard pipe;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    EXPECT_CALL(bus_mock, sd_bus_get_fd(_)).WillRepeatedly(Return(pipe.fd[0]));
    sdbusplus::async::context ctx(sdbusplus::get_mocked_new(&bus_mock));
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        ctx, publisher, std::chrono::milliseconds(100));

    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    config.transportInterface = TransportInterface::I2C;

    Application application(ctx, config, mgr,
                            std::make_shared<DbusPropertyAccess>(ctx));
    ctx.request_stop();
    ctx.run();
}

TEST(BootProgressApplication, InitializeWithStateHostServerCompletes)
{
    std::unique_ptr<StateHostServer> server;
    try
    {
        server = std::make_unique<StateHostServer>();
    }
    catch (...)
    {
        GTEST_SKIP()
            << "State.Host server requires session D-Bus (skip if unavailable)";
    }

    auto clientCtx = std::make_unique<sdbusplus::async::context>();
    auto publisher = std::make_shared<BootProgressPublisher>(
        *clientCtx, std::string(snoopDbus), std::string(snoopObject),
        std::make_shared<NullPropertyAccess>());
    auto mgr = std::make_shared<BootProgressManager>(
        *clientCtx, publisher, std::chrono::milliseconds(100));

    Configuration config{};
    config.pollInterval = std::chrono::milliseconds(200);
    config.transportInterface = TransportInterface::I2C;

    auto application = std::make_shared<Application>(
        *clientCtx, config, mgr,
        std::make_shared<DbusPropertyAccess>(*clientCtx));

    auto fn = [ctx = clientCtx.get(),
               application]() -> sdbusplus::async::task<void> {
        co_await application->initialize();
        stopContext(ctx);
    };
    clientCtx->spawn(fn());
    clientCtx->run();
}

} // namespace
