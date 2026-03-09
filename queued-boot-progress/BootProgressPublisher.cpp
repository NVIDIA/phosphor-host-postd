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

#include "BootProgressPublisher.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>

constexpr auto bootProgressOem = "OEM";
constexpr auto bootProgressOsRunning = "OSRunning";
constexpr auto bootProgressOsStart = "OSStart";
constexpr auto bootProgressPciInit = "PCIInit";
constexpr auto bootProgressSystemInitComplete = "SystemInitComplete";
constexpr auto bootProgressSystemSetup = "SystemSetup";

// EFI_STATUS_CODE_TYPE
constexpr auto efiProgressCode = 0x01;

// EFI_STATUS_CODE_CLASS
constexpr auto efiIoBus = 0x02;
constexpr auto efiSoftware = 0x03;

// EFI_STATUS_CODE_SUBCLASS
constexpr auto efiIoBusPci = 0x01;
constexpr auto efiSoftwareDxeCore = 0x04;
constexpr auto efiSoftwareDxeBsDriver = 0x05;
constexpr auto efiSoftwareEfiBootService = 0x10;

// EFI_STATUS_CODE_OPERATION
constexpr auto efiIoBusPciResAlloc = 0x0110;
constexpr auto efiSwDxeCorePcHandoffToNext = 0x1001;
constexpr auto efiSwPcUserSetup = 0x0007;
constexpr auto efiSwOsLoaderStart = 0x8000;
constexpr auto efiSwBsPcExitBootServices = 0x1019;

constexpr auto bootProgressService = "xyz.openbmc_project.State.Host";
constexpr auto bootProgressObject = "/xyz/openbmc_project/state/host0";
constexpr auto bootProgressInf = "xyz.openbmc_project.State.Boot.Progress";

BootProgressPublisher::BootProgressPublisher(
    sdbusplus::async::context& ctx, const std::string& snoopDbus,
    const std::string& snoopObject,
    std::shared_ptr<CakBootProgressPublisher> cakPublisher) :
    PostObject(ctx.get_bus(), snoopObject.c_str()), ctx(ctx),
    cakBootProgressPublisher(std::move(cakPublisher))
{
    this->emit_object_added();
    ctx.get_bus().request_name(snoopDbus.c_str());
}

std::vector<uint8_t> bytesToVector(uint32_t value)
{
    return {static_cast<uint8_t>((value >> 24) & 0xFF),
            static_cast<uint8_t>((value >> 16) & 0xFF),
            static_cast<uint8_t>((value >> 8) & 0xFF),
            static_cast<uint8_t>(value & 0xFF)};
}

sdbusplus::async::task<void> BootProgressPublisher::update(
    const std::vector<std::pair<uint32_t, uint32_t>> progressCodeData)
{
    try
    {
        if (progressCodeData.empty())
        {
            co_return;
        }
        /* Initialize with last published stage to preserve OSRunning state
         * (OSRunning is final and should never be overwritten) */
        std::string latestStage = lastPublishedStage;
        std::string latestOem;
        for (const auto& [offset, progressCode] : progressCodeData)
        {
            auto code = bytesToVector(progressCode);
            auto timeStampOffset = bytesToVector(offset);
            code[0] = ~code[0];
            this->value(std::make_tuple(code, timeStampOffset), true);
            code[0] = ~code[0];
            this->value(std::make_tuple(code, timeStampOffset));

            latestOem = std::format("0x{:08X}", progressCode);

            if (cakBootProgressPublisher)
            {
                cakBootProgressPublisher->onProgressCode(progressCode);
            }

            /* Stage arbitration logic:
             * - Non-OEM stages (PCIInit, SystemInitComplete, etc.) take
             * precedence
             * - OEM codes only set the stage if no valid stage has been
             * detected yet
             * - Once OSRunning is reached, it becomes immutable (final state)
             */
            std::string detectedStage = getSbmrBootProgressStage(progressCode);
            if (latestStage != bootProgressOsRunning)
            {
                if (detectedStage != bootProgressOem)
                {
                    /* Non-OEM stage: always update (overwrites OEM or previous
                     * stage) */
                    latestStage = detectedStage;
                }
                else if (latestStage.empty())
                {
                    /* OEM code and no stage set yet: use OEM as initial stage
                     * This ensures BootProgress property gets updated from
                     * "None" to "OEM" at boot start when only OEM codes are
                     * present */
                    latestStage = bootProgressOem;
                }
            }
        }

        lg2::debug("Processed {COUNT} codes, latest: Stage={STAGE}, OEM={OEM}",
                   "COUNT", progressCodeData.size(), "STAGE", latestStage,
                   "OEM", latestOem);

        /* Flush decision logic:
         * 1. Non-OEM stage changes are always flushed immediately (unless
         * OSRunning already published)
         * 2. OEM codes are throttled to reduce D-Bus traffic (flushed
         * periodically or on first update) */
        auto now = std::chrono::steady_clock::now();
        bool isNonOemStage =
            (!latestStage.empty() && latestStage != bootProgressOem &&
             latestStage != lastPublishedStage);

        /* Immediate flush for non-OEM stage changes (unless OSRunning is
         * already published) */
        bool shouldFlush =
            (isNonOemStage && lastPublishedStage != bootProgressOsRunning);

        /* For OEM codes: flush if throttling interval elapsed, first update, or
         * first OEM code */
        if (!shouldFlush && !latestOem.empty())
        {
            auto timeSinceLastUpdate =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - lastDbusUpdateTime);

            shouldFlush =
                (timeSinceLastUpdate.count() >= dbusUpdateIntervalMs ||
                 lastDbusUpdateTime ==
                     std::chrono::steady_clock::time_point{} ||
                 lastPublishedOem.empty());
        }

        if (shouldFlush)
        {
            co_await flushPendingUpdates(latestStage, latestOem);
            lastDbusUpdateTime = now;
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to update D-Bus properties: {ERROR}", "ERROR",
                   e.what());
    }
    co_return;
}

std::string BootProgressPublisher::getSbmrBootProgressStage(
    const uint32_t& progressCode)
{
    const uint8_t typeClassByte = (progressCode >> 24) & 0xFF;
    const uint8_t codeType = (typeClassByte >> 6) & 0x03;
    const uint8_t codeClass = typeClassByte & 0x3F;
    const uint8_t codeSubClass = (progressCode >> 16) & 0xFF;
    const uint16_t codeOperation = progressCode & 0xFFFF;

    std::string progressCodeStr = std::format("0x{:08X}", progressCode);
    lg2::debug(
        "DEBUG: Progress Code: {PROGRESS_CODE}, Code Type: {CODE_TYPE}, Code Class: {CODE_CLASS}, Code SubClass: {CODE_SUB_CLASS}, Code Operation: {CODE_OPERATION}",
        "PROGRESS_CODE", progressCodeStr, "CODE_TYPE", codeType, "CODE_CLASS",
        codeClass, "CODE_SUB_CLASS", codeSubClass, "CODE_OPERATION",
        codeOperation);
    // Return OEM if code type is unexpected
    if (codeType != efiProgressCode)
    {
        return bootProgressOem;
    }

    // Code Class Software
    if (codeClass == efiSoftware)
    {
        if (codeSubClass == efiSoftwareDxeCore &&
            codeOperation == efiSwDxeCorePcHandoffToNext)
        {
            return bootProgressSystemInitComplete;
        }
        else if (codeSubClass == efiSoftwareDxeBsDriver &&
                 codeOperation == efiSwPcUserSetup)
        {
            return bootProgressSystemSetup;
        }
        else if (codeSubClass == efiSoftwareDxeBsDriver &&
                 codeOperation == efiSwOsLoaderStart)
        {
            return bootProgressOsStart;
        }
        else if (codeSubClass == efiSoftwareEfiBootService &&
                 codeOperation == efiSwBsPcExitBootServices)
        {
            return bootProgressOsRunning;
        }
    }
    // Code Class IO Bus
    else if (codeClass == efiIoBus)
    {
        if (codeSubClass == efiIoBusPci && codeOperation == efiIoBusPciResAlloc)
        {
            return bootProgressPciInit;
        }
    }
    // Fallback to OEM if no conditions met
    return bootProgressOem;
}

sdbusplus::async::task<void> BootProgressPublisher::updateBootProgressProperty(
    const std::string& progressStage)
{
    std::string stage =
        "xyz.openbmc_project.State.Boot.Progress.ProgressStages." +
        progressStage;
    auto bootProgressProxy = sdbusplus::async::proxy()
                                 .service(bootProgressService)
                                 .path(bootProgressObject)
                                 .interface(bootProgressInf);

    try
    {
        co_await bootProgressProxy.set_property(ctx, "BootProgress", stage);
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "D-Bus Call failed to set BootProgress property to '{STAGE}': {ERROR}",
            "STAGE", progressStage, "ERROR", e.what());
    }
    co_return;
}

sdbusplus::async::task<void>
    BootProgressPublisher::updateBootProgressLastUpdateProperty(
        uint64_t bootProgressLastUpdate)
{
    auto bootProgressProxy = sdbusplus::async::proxy()
                                 .service(bootProgressService)
                                 .path(bootProgressObject)
                                 .interface(bootProgressInf);

    try
    {
        co_await bootProgressProxy.set_property(ctx, "BootProgressLastUpdate",
                                                bootProgressLastUpdate);
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "D-Bus Call failed to set BootProgressLastUpdate property to {TS}: {ERROR}",
            "TS", bootProgressLastUpdate, "ERROR", e.what());
    }
    co_return;
}

sdbusplus::async::task<void>
    BootProgressPublisher::updateBootProgressOemProperty(
        const std::string& oemLastState)
{
    auto bootProgressProxy = sdbusplus::async::proxy()
                                 .service(bootProgressService)
                                 .path(bootProgressObject)
                                 .interface(bootProgressInf);

    try
    {
        co_await bootProgressProxy.set_property(ctx, "BootProgressOem",
                                                oemLastState);
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "D-Bus Call failed to set BootProgressOem property to '{OEM}': {ERROR}",
            "OEM", oemLastState, "ERROR", e.what());
    }
    co_return;
}

sdbusplus::async::task<void> BootProgressPublisher::flushPendingUpdates(
    const std::string& stage, const std::string& oem)
{
    /* BootProgress update rules:
     * - Non-empty stage required, OSRunning is final (immutable once published)
     * - Non-OEM stages: update on change or first publish
     * - OEM stage: update only on first publish (initial state) */
    bool isFirstPublish = lastPublishedStage.empty();
    bool isOemStage = (stage == bootProgressOem);
    bool isStageChanged = (stage != lastPublishedStage);

    /* Update BootProgress if:
     * - Stage is non-empty AND
     * - OSRunning not already published AND
     * - (First publish OR (non-OEM stage changed)) */
    bool updateStage = !stage.empty() &&
                       lastPublishedStage != bootProgressOsRunning &&
                       (isFirstPublish || (!isOemStage && isStageChanged));

    if (updateStage)
    {
        co_await updateBootProgressProperty(stage);
        lastPublishedStage = stage;
    }

    /* BootProgressOem property: update whenever OEM code changes or on first
     * update */
    if (!oem.empty() && (oem != lastPublishedOem || lastPublishedOem.empty()))
    {
        co_await updateBootProgressOemProperty(oem);
        lastPublishedOem = oem;
    }

    uint64_t currentTimestamp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    if (currentTimestamp != lastPublishedTimestamp)
    {
        co_await updateBootProgressLastUpdateProperty(currentTimestamp);
        lastPublishedTimestamp = currentTimestamp;
    }
}

void BootProgressPublisher::resetCachedState()
{
    lg2::debug("Reset cached BootProgress state");
    lastPublishedStage.clear();
    lastPublishedOem.clear();
    lastPublishedTimestamp = 0;
    lastDbusUpdateTime = std::chrono::steady_clock::time_point{};

    if (cakBootProgressPublisher)
    {
        cakBootProgressPublisher->resetCachedState();
    }
}
