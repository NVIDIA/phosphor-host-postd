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

#include "CakBootProgressPublisher.hpp"

#include <phosphor-logging/lg2.hpp>

static constexpr auto cakBootProgressObject =
    "/xyz/openbmc_project/state/boot/cak0";

// CAK-specific progress codes — CPU index encoded in high byte as (0x70 +
// cpuIndex); lower 3 bytes identify the event type.
static constexpr uint32_t cpuIndexBase = 0x70u;
static constexpr uint32_t cpuBootStart = 0x00C0C001u;
static constexpr uint32_t cpuCakEnter = 0x00C1C08Au;
static constexpr uint32_t cpuCakExit = 0x00C1C089u;

CakBootProgressPublisher::CakBootProgressPublisher(
    sdbusplus::async::context& context, size_t cakCpuCount) :
    ctx(context), cakCpuCount(cakCpuCount)
{
    if (cakCpuCount == 0)
    {
        return;
    }
    bootProgressObj = std::make_unique<BootProgressObject>(
        ctx.get_bus(), cakBootProgressObject,
        BootProgressObject::action::emit_object_added);
    bootProgressObj->bootProgress(BootProgressInterface::ProgressStages::OEM);
    cakCpuStages.assign(cakCpuCount, CakStage::EarlyBoot);
    publishCakStageIfChanged("EarlyBoot");
}

void CakBootProgressPublisher::onProgressCode(uint32_t progressCode)
{
    if (cakCpuCount == 0)
    {
        return;
    }
    updateCakState(progressCode);
}

void CakBootProgressPublisher::resetCachedState()
{
    if (cakCpuCount == 0)
    {
        return;
    }
    lg2::debug("Reset cached CAK BootProgress state");
    cakCpuStages.assign(cakCpuCount, CakStage::EarlyBoot);
    lastPublishedStage.clear();
    publishCakStageIfChanged("EarlyBoot");
}

void CakBootProgressPublisher::publishCakStageFromStates()
{
    bool allComplete = true;
    bool allWaiting = true;
    for (CakStage s : cakCpuStages)
    {
        allComplete = allComplete && (s == CakStage::Complete);
        allWaiting = allWaiting && (s == CakStage::Waiting);
        if (!allComplete && !allWaiting)
        {
            break;
        }
    }
    publishCakStageIfChanged(allComplete  ? "Complete"
                             : allWaiting ? "Waiting"
                                          : "EarlyBoot");
}

void CakBootProgressPublisher::updateCakState(uint32_t progressCode)
{
    const uint32_t highByte = progressCode >> 24;
    if (highByte < cpuIndexBase)
    {
        return;
    }

    const size_t cpuIndex = highByte - cpuIndexBase;
    if (cpuIndex >= cakCpuStages.size())
    {
        return;
    }

    const uint32_t eventCode = progressCode & 0x00FFFFFFu;
    if (eventCode == cpuBootStart)
    {
        cakCpuStages[cpuIndex] = CakStage::EarlyBoot;
    }
    else if (eventCode == cpuCakEnter)
    {
        cakCpuStages[cpuIndex] = CakStage::Waiting;
    }
    else if (eventCode == cpuCakExit)
    {
        cakCpuStages[cpuIndex] = CakStage::Complete;
    }
    else
    {
        return;
    }

    publishCakStageFromStates();
}

void CakBootProgressPublisher::publishCakStageIfChanged(
    const std::string& stage)
{
    if (!bootProgressObj || stage == lastPublishedStage)
    {
        return;
    }

    lg2::info("CAK BootProgress stage: {OLD} -> {NEW}", "OLD",
              lastPublishedStage.empty() ? "(none)" : lastPublishedStage, "NEW",
              stage);
    bootProgressObj->bootProgress(BootProgressInterface::ProgressStages::OEM);
    bootProgressObj->bootProgressOem(stage);
    lastPublishedStage = stage;
}
