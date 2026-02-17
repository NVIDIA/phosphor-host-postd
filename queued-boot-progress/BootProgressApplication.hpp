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

#pragma once

#include "BootProgressManager.hpp"
#include "BootProgressPoller.hpp"
#include "BootProgressPublisher.hpp"
#include "ConfigReader.hpp"
#include "dbus_utils.hpp"

#include <sdbusplus/async.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>

constexpr std::string_view osStateBootComplete =
    "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Standby";
constexpr std::string_view osStateInactive =
    "xyz.openbmc_project.State.OperatingSystem.Status.OSStatus.Inactive";

constexpr std::string_view hostPowerStateRunning =
    "xyz.openbmc_project.State.Host.HostState.Running";
constexpr std::string_view hostPowerStateOff =
    "xyz.openbmc_project.State.Host.HostState.Off";
constexpr std::string_view hostPowerStateQuiesced =
    "xyz.openbmc_project.State.Host.HostState.Quiesced";
constexpr std::string_view hostPowerStateTransition =
    "xyz.openbmc_project.State.Host.HostState.TransitioningToOff";

constexpr std::string_view bootProgressOsRunningStage =
    "xyz.openbmc_project.State.Boot.Progress.ProgressStages.OSRunning";

constexpr std::string_view dbusHostStateService =
    "xyz.openbmc_project.State.Host";
constexpr std::string_view dbusHostStatePath =
    "/xyz/openbmc_project/state/host0";
constexpr std::string_view dbusOSStatusInterface =
    "xyz.openbmc_project.State.OperatingSystem.Status";
constexpr std::string_view dbusHostStateInterface =
    "xyz.openbmc_project.State.Host";
constexpr std::string_view dbusBootProgressInterface =
    "xyz.openbmc_project.State.Boot.Progress";

class Application
{
  public:
    Application(sdbusplus::async::context& ctx, const Configuration& config,
                std::shared_ptr<BootProgressManager> bootProgressManager,
                std::shared_ptr<IDbusPropertyAccess> dbusAccess);

    sdbusplus::async::task<void> initialize();

  protected:
    void onOSStateChange(std::string newValue);
    void onHostPowerStateChange(std::string newValue);
    void onBootProgressChange(std::string newValue);
    bool isHostPowerStateOff() const;

  private:
    sdbusplus::async::task<void> monitorOSState();
    sdbusplus::async::task<void> getInitialOsState();
    sdbusplus::async::task<void> monitorHostPowerState();
    sdbusplus::async::task<void> getInitialHostPowerState();
    sdbusplus::async::task<void> monitorBootProgress();
    sdbusplus::async::task<void> getInitialBootProgress();
    void updatePollInterval();

  protected:
    sdbusplus::async::context& ctx;

  private:
    std::shared_ptr<IDbusPropertyAccess> dbusAccess;
    Configuration config;
    std::string currentOSState;
    std::string currentHostPowerState;
    std::string currentBootProgress;
    std::shared_ptr<BootProgressManager> bootProgressManager;
};
