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

#include <sdbusplus/async.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/State/Boot/Progress/server.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

/**
 * Publishes CAK (CPU Authentication Key) boot progress to a dedicated D-Bus
 * object. Tracks CAK-specific progress codes and aggregates per-CPU state into
 * a single published stage (EarlyBoot, Waiting, Complete).
 */
class CakBootProgressPublisher
{
  public:
    CakBootProgressPublisher(sdbusplus::async::context& ctx,
                             size_t cakCpuCount);

    void onProgressCode(uint32_t progressCode);
    void resetCachedState();

  private:
    enum class CakStage
    {
        EarlyBoot,
        Waiting,
        Complete,
    };

    using BootProgressInterface =
        sdbusplus::xyz::openbmc_project::State::Boot::server::Progress;
    using BootProgressObject =
        sdbusplus::server::object_t<BootProgressInterface>;

    sdbusplus::async::context& ctx;
    const size_t cakCpuCount;
    std::unique_ptr<BootProgressObject> bootProgressObj;
    std::vector<CakStage> cakCpuStages;
    std::string lastPublishedStage;

    void updateCakState(uint32_t progressCode);
    void publishCakStageIfChanged(const std::string& stage);
    void publishCakStageFromStates();
};
