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

#include <variant>

sdbusplus::async::task<void> Application::getInitialOsState()
{
    try
    {
        currentOSState = co_await dbusAccess->getProperty(
            dbusHostStateService.data(), dbusHostStatePath.data(),
            dbusOSStatusInterface.data(), "OperatingSystemState");
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
    while (!ctx.stop_requested())
    {
        try
        {
            PropertiesChangedTuple result =
                co_await dbusAccess->waitForPropertiesChanged(
                    std::string(dbusHostStatePath),
                    std::string(dbusOSStatusInterface));
            const auto& changed = std::get<1>(result);
            auto it = changed.find("OperatingSystemState");
            if (it != changed.end())
            {
                lg2::info("OS state changed to: {STATE}", "STATE",
                          std::get<std::string>(it->second));
                onOSStateChange(std::get<std::string>(it->second));
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
        currentHostPowerState = co_await dbusAccess->getProperty(
            dbusHostStateService.data(), dbusHostStatePath.data(),
            dbusHostStateInterface.data(), "CurrentHostState");
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
    while (!ctx.stop_requested())
    {
        try
        {
            PropertiesChangedTuple result =
                co_await dbusAccess->waitForPropertiesChanged(
                    std::string(dbusHostStatePath),
                    std::string(dbusHostStateInterface));
            const auto& changed = std::get<1>(result);
            auto it = changed.find("CurrentHostState");
            if (it != changed.end())
            {
                lg2::info("Host power state changed to: {STATE}", "STATE",
                          std::get<std::string>(it->second));
                onHostPowerStateChange(std::get<std::string>(it->second));
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Error monitoring host power state: {ERROR}", "ERROR",
                       e.what());
        }
    }
}

void Application::onOSStateChange(std::string newValue)
{
    currentOSState = std::move(newValue);
    updatePollInterval();
}

sdbusplus::async::task<void> Application::monitorBootProgress()
{
    while (!ctx.stop_requested())
    {
        try
        {
            PropertiesChangedTuple result =
                co_await dbusAccess->waitForPropertiesChanged(
                    std::string(dbusHostStatePath),
                    std::string(dbusBootProgressInterface));
            const auto& changed = std::get<1>(result);
            auto it = changed.find("BootProgress");
            if (it != changed.end())
            {
                onBootProgressChange(std::get<std::string>(it->second));
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Error monitoring BootProgress: {ERROR}", "ERROR",
                       e.what());
        }
    }
}

sdbusplus::async::task<void> Application::getInitialBootProgress()
{
    try
    {
        currentBootProgress = co_await dbusAccess->getProperty(
            dbusHostStateService.data(), dbusHostStatePath.data(),
            dbusBootProgressInterface.data(), "BootProgress");
        lg2::info("Initial BootProgress: {BOOT_PROGRESS}", "BOOT_PROGRESS",
                  currentBootProgress);
    }
    catch (const std::exception& e)
    {
        lg2::error("Error getting initial BootProgress: {ERROR}", "ERROR",
                   e.what());
        currentBootProgress.clear();
    }
}

void Application::onBootProgressChange(std::string newValue)
{
    currentBootProgress = std::move(newValue);
    updatePollInterval();
}

void Application::updatePollInterval()
{
    const auto baseInterval = config.pollInterval;
    std::chrono::milliseconds calculatedInterval = baseInterval;

    if (isHostPowerStateOff())
    {
        constexpr int disabledCheckMultiplier = 10;
        calculatedInterval = baseInterval * disabledCheckMultiplier;
        lg2::info(
            "Host off: boot progress polling disabled, update poll interval to {INTERVAL} ms",
            "INTERVAL", calculatedInterval.count());
        bootProgressManager->updatePollInterval(calculatedInterval);
        bootProgressManager->updatePollStatus(false);
        return;
    }
    if (currentOSState == osStateBootComplete &&
        currentHostPowerState == hostPowerStateRunning &&
        currentBootProgress == bootProgressOsRunningStage)
    {
        constexpr int bootCompleteMultiplier = 100;
        constexpr std::chrono::milliseconds maxPollInterval{3600000};
        calculatedInterval =
            std::min(baseInterval * bootCompleteMultiplier, maxPollInterval);
        lg2::info("Boot complete - update poll interval to {INTERVAL}ms",
                  "INTERVAL", calculatedInterval.count());
    }
    else
    {
        lg2::info("Host on - polling at base interval {INTERVAL}ms", "INTERVAL",
                  calculatedInterval.count());
    }
    bootProgressManager->updatePollInterval(calculatedInterval);
    bootProgressManager->updatePollStatus(true);
}

void Application::onHostPowerStateChange(std::string newValue)
{
    currentHostPowerState = std::move(newValue);
    if (isHostPowerStateOff())
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
    std::shared_ptr<BootProgressManager> bootProgressManager,
    std::shared_ptr<IDbusPropertyAccess> dbusAccess) :
    ctx(ctx), dbusAccess(std::move(dbusAccess)), config(configuration),
    bootProgressManager(bootProgressManager)
{}

sdbusplus::async::task<void> Application::initialize()
{
    co_await getInitialOsState();
    co_await getInitialHostPowerState();
    co_await getInitialBootProgress();
    ctx.spawn(monitorOSState());
    ctx.spawn(monitorHostPowerState());
    ctx.spawn(monitorBootProgress());
    updatePollInterval();
    co_return;
}

bool Application::isHostPowerStateOff() const
{
    return (currentHostPowerState == hostPowerStateOff ||
            currentHostPowerState == hostPowerStateQuiesced ||
            currentHostPowerState == hostPowerStateTransition ||
            currentHostPowerState.empty());
}
