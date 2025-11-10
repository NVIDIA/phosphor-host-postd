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
#include <fstream>
#include <unordered_map>

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
constexpr auto efiSwDxeCorePcHandoffToNext = 0x0110;
constexpr auto efiSwPcUserSetup = 0x0700;
constexpr auto efiSwOsLoaderStart = 0x0180;
constexpr auto efiSwBsPcExitBootServices = 0x1910;

constexpr auto bootProgressService = "xyz.openbmc_project.State.Host";
constexpr auto bootProgressObject = "/xyz/openbmc_project/state/host0";
constexpr auto bootProgressInf = "xyz.openbmc_project.State.Boot.Progress";

BootProgressPublisher::BootProgressPublisher(sdbusplus::async::context& ctx,
                                             const std::string& snoopDbus,
                                             const std::string& snoopObject) :
    PostObject(ctx.get_bus(), snoopObject.c_str()), ctx(ctx)
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

        auto now = std::chrono::steady_clock::now();
        auto timeSinceLastUpdate =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastDbusUpdateTime);

        lg2::debug(
            "Processing {COUNT} boot progress codes, time since last D-Bus update: {TIME}ms",
            "COUNT", progressCodeData.size(), "TIME",
            timeSinceLastUpdate.count());

        // Process ALL entries - publish to PostCode interface
        for (const auto& [offset, progressCode] : progressCodeData)
        {
            uint64_t timestamp =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
            timestamp += (static_cast<uint64_t>(offset) * 1000ULL);
            auto code = bytesToVector(progressCode);
            code[0] = ~code[0];
            this->value(std::make_tuple(code, secondary_post_code_t{}), true);
            code[0] = ~code[0];
            this->value(std::make_tuple(code, secondary_post_code_t{}));

            // Store the latest state for batched D-Bus updates
            pendingStage = getSbmrBootProgressStage(progressCode);
            pendingOem = std::format("0x{:016X}", progressCode);
            pendingTimestamp = timestamp;
            hasPendingUpdates = true;
        }

        lg2::debug(
            "DEBUG: Published {COUNT} codes to PostCode interface, latest: Stage={STAGE}, OEM={OEM}",
            "COUNT", progressCodeData.size(), "STAGE", pendingStage, "OEM",
            pendingOem);

        // Flush D-Bus updates if enough time has passed OR if this is the first
        // batch
        if (hasPendingUpdates &&
            (timeSinceLastUpdate.count() >= dbusUpdateIntervalMs ||
             lastDbusUpdateTime == std::chrono::steady_clock::time_point{}))
        {
            lg2::debug(
                "Flushing D-Bus updates (interval {INTERVAL}ms exceeded or first batch)",
                "INTERVAL", dbusUpdateIntervalMs);
            co_await flushPendingUpdates();
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
    uint8_t b1 = progressCode & 0xFF;
    uint8_t codeType = (b1 >> 6) & 0x03;
    uint8_t codeClass = b1 & 0x3F;
    uint8_t codeSubClass = (progressCode >> 8) & 0xFF;
    uint16_t codeOperation = (progressCode >> 16) & 0xFFFF;

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

sdbusplus::async::task<void> BootProgressPublisher::flushPendingUpdates()
{
    if (!hasPendingUpdates)
    {
        lg2::debug("flushPendingUpdates called but no pending updates");
        co_return;
    }
    uint32_t dbusCallCount = 0;

    // Spawn D-Bus updates asynchronously (fire-and-forget)
    // This prevents blocking and avoids contention with bmcweb
    if (pendingStage != lastPublishedStage)
    {
        ctx.spawn(updateBootProgressProperty(pendingStage));
        lastPublishedStage = pendingStage;
        dbusCallCount++;
    }
    else
    {
        lg2::info("DEBUG: Stage unchanged ('{STAGE}'), skipping D-Bus call",
                  "STAGE", pendingStage);
    }

    if (pendingOem != lastPublishedOem)
    {
        ctx.spawn(updateBootProgressOemProperty(pendingOem));
        lastPublishedOem = pendingOem;
        dbusCallCount++;
    }

    if (pendingTimestamp != lastPublishedTimestamp)
    {
        lg2::debug(
            "Timestamp changed: {OLDTS} -> {NEWTS}, spawning async D-Bus call",
            "OLDTS", lastPublishedTimestamp, "NEWTS", pendingTimestamp);
        ctx.spawn(updateBootProgressLastUpdateProperty(pendingTimestamp));
        lastPublishedTimestamp = pendingTimestamp;
        dbusCallCount++;
    }
    hasPendingUpdates = false;
    co_return;
}
