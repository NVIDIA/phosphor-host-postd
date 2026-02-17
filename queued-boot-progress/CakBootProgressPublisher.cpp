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

// CAK-specific progress codes
static constexpr uint32_t cpu0BootStart = 0x70C0C001;
static constexpr uint32_t cpu1BootStart = 0x71C0C001;
static constexpr uint32_t cpu0CakEnter = 0x70C1C08A;
static constexpr uint32_t cpu1CakEnter = 0x71C1C08A;
static constexpr uint32_t cpu0CakExit = 0x70C1C089;
static constexpr uint32_t cpu1CakExit = 0x71C1C089;

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
    cakEnterSeen = false;
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
    cakEnterSeen = false;
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
    if (progressCode == cpu0BootStart || progressCode == cpu1BootStart)
    {
        const size_t cpuIndex = (progressCode == cpu0BootStart) ? 0U : 1U;
        if (cpuIndex < cakCpuStages.size())
        {
            cakCpuStages[cpuIndex] = CakStage::EarlyBoot;
        }
        publishCakStageFromStates();
        return;
    }

    size_t cpuIndex;
    CakStage newStage;
    if (progressCode == cpu0CakEnter)
    {
        cpuIndex = 0;
        newStage = CakStage::Waiting;
        cakEnterSeen = true;
    }
    else if (progressCode == cpu0CakExit)
    {
        cpuIndex = 0;
        newStage = CakStage::Complete;
    }
    else if (progressCode == cpu1CakEnter)
    {
        cpuIndex = 1;
        newStage = CakStage::Waiting;
        cakEnterSeen = true;
    }
    else if (progressCode == cpu1CakExit)
    {
        cpuIndex = 1;
        newStage = CakStage::Complete;
    }
    else
    {
        return;
    }

    if (cpuIndex >= cakCpuStages.size())
    {
        return;
    }

    cakCpuStages[cpuIndex] = newStage;
    publishCakStageFromStates();
}

void CakBootProgressPublisher::publishCakStageIfChanged(
    const std::string& stage)
{
    if (!bootProgressObj || stage == lastPublishedStage)
    {
        return;
    }

    bootProgressObj->bootProgress(BootProgressInterface::ProgressStages::OEM);
    bootProgressObj->bootProgressOem(stage);
    lastPublishedStage = stage;
}
