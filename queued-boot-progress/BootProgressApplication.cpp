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

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus/match.hpp>

#include <variant>

namespace rulesInterface = sdbusplus::bus::match::rules;

sdbusplus::async::task<void> Application::getInitialOsState()
{
    try
    {
        auto osStateProxy =
            sdbusplus::async::proxy()
                .service("xyz.openbmc_project.State.Host")
                .path("/xyz/openbmc_project/state/host0")
                .interface("xyz.openbmc_project.State.OperatingSystem.Status");
        currentOSState = co_await osStateProxy.get_property<std::string>(
            ctx, "OperatingSystemState");
        lg2::info("Initial OS state: {STATE}", "STATE", currentOSState);
    }
    catch (const std::exception& e)
    {
        lg2::error("Error getting initial OS state: {ERROR}", "ERROR",
                   e.what());
    }
}

sdbusplus::async::task<void> Application::monitorOSState()
{
    auto osStateMatch = sdbusplus::async::match(
        ctx, rulesInterface::propertiesChanged(
                 "/xyz/openbmc_project/state/host0",
                 "xyz.openbmc_project.State.OperatingSystem.Status"));
    while (!ctx.stop_requested())
    {
        try
        {
            auto [iface, changed, invalidated] = co_await osStateMatch.next<
                std::string,
                std::map<std::string,
                         std::variant<std::string, int32_t, uint32_t, bool>>,
                std::vector<std::string>>();
            auto it = changed.find("OperatingSystemState");
            if (it != changed.end())
            {
                currentOSState = std::get<std::string>(it->second);
                lg2::info("OS state changed to: {STATE}", "STATE",
                          currentOSState);
                onOSStateChange();
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Error monitoring OS state: {ERROR}", "ERROR", e.what());
        }
    }
}

sdbusplus::async::task<void> Application::getInitialHostPowerState()
{
    try
    {
        auto hostStateProxy = sdbusplus::async::proxy()
                                  .service("xyz.openbmc_project.State.Host")
                                  .path("/xyz/openbmc_project/state/host0")
                                  .interface("xyz.openbmc_project.State.Host");
        currentHostPowerState =
            co_await hostStateProxy.get_property<std::string>(
                ctx, "CurrentHostState");
        lg2::info("Initial host power state: {STATE}", "STATE",
                  currentHostPowerState);
    }
    catch (const std::exception& e)
    {
        lg2::error("Error getting initial host power state: {ERROR}", "ERROR",
                   e.what());
        currentHostPowerState = std::string(hostPowerStateRunning);
        lg2::warning("Defaulting to RUNNING state due to error");
    }
}

sdbusplus::async::task<void> Application::monitorHostPowerState()
{
    auto powerStateMatch = sdbusplus::async::match(
        ctx,
        rulesInterface::propertiesChanged("/xyz/openbmc_project/state/host0",
                                          "xyz.openbmc_project.State.Host"));
    while (!ctx.stop_requested())
    {
        try
        {
            auto [iface, changed, invalidated] = co_await powerStateMatch.next<
                std::string,
                std::map<std::string,
                         std::variant<std::string, int32_t, uint32_t, bool>>,
                std::vector<std::string>>();
            auto it = changed.find("CurrentHostState");
            if (it != changed.end())
            {
                currentHostPowerState = std::get<std::string>(it->second);
                lg2::info("Host power state changed to: {STATE}", "STATE",
                          currentHostPowerState);
                onHostPowerStateChange();
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Error monitoring host power state: {ERROR}", "ERROR",
                       e.what());
        }
    }
}

void Application::onOSStateChange()
{
    updatePollInterval();
}

void Application::updatePollInterval()
{
    bool isHostOff = (currentHostPowerState == hostPowerStateOff ||
                      currentHostPowerState == hostPowerStateQuiesced ||
                      currentHostPowerState == hostPowerStateTransition ||
                      currentHostPowerState.empty());
    const auto baseInterval = config.pollInterval;
    std::chrono::milliseconds calculatedInterval = baseInterval;

    if (isHostOff)
    {
        lg2::info("Host is off - disabling boot progress polling");
        constexpr int disabledCheckMultiplier = 10;
        calculatedInterval = baseInterval * disabledCheckMultiplier;
        lg2::debug(
            "Setting polling interval to {INTERVAL}ms (host off, base * {MULT})",
            "INTERVAL", calculatedInterval.count(), "MULT",
            disabledCheckMultiplier);
        bootProgressManager->updatePollInterval(calculatedInterval);
        bootProgressManager->updatePollStatus(false);
        return;
    }
    if (currentOSState == osStateBootComplete &&
        currentHostPowerState == hostPowerStateRunning)
    {
        constexpr int bootCompleteMultiplier = 100;
        constexpr std::chrono::milliseconds maxPollInterval{3600000};
        calculatedInterval =
            std::min(baseInterval * bootCompleteMultiplier, maxPollInterval);
    }

    lg2::debug("Setting polling interval to {INTERVAL}ms", "INTERVAL",
               calculatedInterval.count());
    bootProgressManager->updatePollInterval(calculatedInterval);
    bootProgressManager->updatePollStatus(true);
}

void Application::onHostPowerStateChange()
{
    if (currentHostPowerState == hostPowerStateOff)
    {
        bootProgressManager->initIndices();
        bootProgressManager->resetPublisherCachedState();
    }
    else if (currentHostPowerState == hostPowerStateRunning)
    {
        lg2::info("Host is on - enabling boot progress polling");
    }
    updatePollInterval();
}

Application::Application(
    sdbusplus::async::context& ctx, const Configuration& configuration,
    std::shared_ptr<BootProgressManager> bootProgressManager) :
    ctx(ctx), config(configuration), bootProgressManager(bootProgressManager)
{}

sdbusplus::async::task<void> Application::initialize()
{
    co_await getInitialOsState();
    co_await getInitialHostPowerState();
    ctx.spawn(monitorOSState());
    ctx.spawn(monitorHostPowerState());
    updatePollInterval();
    co_return;
}
