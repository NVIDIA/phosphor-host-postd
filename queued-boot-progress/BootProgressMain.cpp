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

#include "BootProgressApplication.hpp"
#include "BootProgressManager.hpp"
#include "CakBootProgressPublisher.hpp"
#include "ConfigReader.hpp"
#include "I2CPollingDevice.hpp"
#include "L1ResetHandler.hpp"
#include "PollingDevice.hpp"
#include "USBPollingDevice.hpp"
#include "dbus_utils.hpp"
#include "lpcsnoop/snoop.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <exception>
#include <optional>
#include <string>
#include <vector>

using namespace std::chrono_literals;

static constexpr auto cpuIface = "xyz.openbmc_project.Inventory.Item.Cpu";

static sdbusplus::async::task<size_t> queryCpuCount(
    sdbusplus::async::context& ctx)
{
    try
    {
        auto paths = co_await getSubTreePaths(
            ctx, "/xyz/openbmc_project/inventory", 0, {cpuIface});
        co_return countUniqueLeafPaths(paths);
    }
    catch (const std::exception& e)
    {
        lg2::debug("CPU detection: ObjectMapper query failed: {ERROR}", "ERROR",
                   e.what());
        co_return 0;
    }
}

static sdbusplus::async::task<size_t> detectCpuCount(
    sdbusplus::async::context& ctx,
    std::chrono::seconds timeout = std::chrono::seconds(120))
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    size_t count = co_await queryCpuCount(ctx);
    if (count > 0)
    {
        co_await sdbusplus::async::sleep_for(ctx, 3s);
        count = std::max(count, co_await queryCpuCount(ctx));
        lg2::info("CPU detection: settled at {COUNT} CPU(s)", "COUNT", count);
        co_return count;
    }

    lg2::debug("CPU detection: Entity Manager not ready, polling every 3s "
               "for up to {TIMEOUT}s",
               "TIMEOUT", timeout.count());

    while (std::chrono::steady_clock::now() < deadline)
    {
        co_await sdbusplus::async::sleep_for(ctx, 3s);

        count = co_await queryCpuCount(ctx);
        if (count > 0)
        {
            co_await sdbusplus::async::sleep_for(ctx, 3s);
            count = std::max(count, co_await queryCpuCount(ctx));
            lg2::info("CPU detection: settled at {COUNT} CPU(s)", "COUNT",
                      count);
            co_return count;
        }
    }

    lg2::warning("CPU detection timed out waiting for Entity Manager; "
                 "defaulting to 2 CPUs");
    co_return 2;
}

static sdbusplus::async::task<void> runSnoopd(
    sdbusplus::async::context& ctx, const Configuration& config,
    std::optional<Application>& application,
    std::shared_ptr<PollingDeviceEnumerator>& deviceEnumerator,
    [[maybe_unused]] std::shared_ptr<L1ResetHandler>& l1ResetHandler)
{
    size_t cpuCount = 0;
    if (config.cakEnabled)
    {
        if (config.cakCpuCount > 0)
        {
            cpuCount = config.cakCpuCount;
            lg2::info("CAK monitoring: using static {COUNT} CPU(s)", "COUNT",
                      cpuCount);
        }
        else
        {
            cpuCount = co_await detectCpuCount(ctx);
            lg2::info("CAK monitoring: detected {COUNT} CPU(s)", "COUNT",
                      cpuCount);
        }
    }

    auto cakPublisher =
        std::make_shared<CakBootProgressPublisher>(ctx, cpuCount);
    auto dbusAccess = std::make_shared<DbusPropertyAccess>(ctx);
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject), dbusAccess,
        cakPublisher);
    auto bootProgressManager = std::make_shared<BootProgressManager>(
        ctx, publisher, config.pollInterval);

    if (config.transportInterface == TransportInterface::I2C)
    {
        initializeI2CDevices(bootProgressManager, config.i2cInterfaceConfigMap);
    }
    else
    {
        // USB needs enumerator for hotplug support
        deviceEnumerator = std::make_shared<USBDeviceEnumerator>(
            ctx, bootProgressManager, config.usbVendorId, config.usbProductId,
            config.usbRescanInterval);
        ctx.spawn(deviceEnumerator->run());
    }

    if (config.l1ResetEnabled)
    {
        // Register the com.nvidia.L1Reset D-Bus interface under snoopd's own
        // service name (xyz.openbmc_project.State.Boot.Raw) so we do not
        // conflict with phosphor-host-state-manager's ownership of
        // xyz.openbmc_project.State.Host.
        lg2::info("L1Reset: registering com.nvidia.L1Reset interface");
        l1ResetHandler = std::make_shared<L1ResetHandler>(
            ctx, "/xyz/openbmc_project/state/host0", bootProgressManager);
        lg2::info("L1Reset: D-Bus interface registered");
    }

    application.emplace(ctx, config, bootProgressManager, dbusAccess);
    co_await application->initialize();
}

int main(int argc, char* argv[])
{
    Configuration config;
    if (!ConfigReader::readConfig(argc, argv, config))
    {
        lg2::error("Failed to read configuration");
        return EXIT_FAILURE;
    }

    sdbusplus::async::context ctx;
    std::optional<Application> application;
    std::shared_ptr<PollingDeviceEnumerator> deviceEnumerator;
    std::shared_ptr<L1ResetHandler> l1ResetHandler;

    ctx.spawn(
        runSnoopd(ctx, config, application, deviceEnumerator, l1ResetHandler));
    ctx.run();

    return EXIT_SUCCESS;
}
