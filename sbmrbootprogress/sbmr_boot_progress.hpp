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

#include "nlohmann/json.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/State/Boot/Raw/server.hpp>

#include <chrono>
#include <fstream>

constexpr auto sbmrBootProgressSize = 9;
constexpr auto bootProgressCode = 0x01;
constexpr auto bootErrorCode = 0x02;
constexpr auto bootDebugCode = 0x03;
constexpr auto severityByte = 8;
constexpr auto operationByte = 10;
constexpr auto errorMinor = 0x40;
constexpr auto errorMajor = 0x80;
constexpr auto errorUnrecoverd = 0x90;
constexpr auto errorUncontained = 0xA0;
constexpr auto socketMask = 0xC0;
constexpr auto instanceMask = 0x3F;

constexpr auto subClassNvFwBoot = 0x01;
constexpr auto classNvFw = 0xc1;
constexpr auto nvFwBootJsonKey = 0xff0f;
constexpr auto opByte1BinLoadFailed = 0x01;
constexpr auto opByte2BinLoadFailed = 0x00;
constexpr auto opByte1ConfigReset = 0x08;
constexpr auto opByte2BootSerice = 0x10;
constexpr auto subClassSpecific = 0x10;
constexpr auto classSoftware = 0x03;

constexpr auto sbmrBootProgressService = "xyz.openbmc_project.State.Boot.Raw";
constexpr auto sbmrBootProgressObj = "/xyz/openbmc_project/state/boot/raw0";
constexpr auto bootProgressService = "xyz.openbmc_project.State.Host";
constexpr auto bootProgressObject = "/xyz/openbmc_project/state/host0";
constexpr auto bootProgressInf = "xyz.openbmc_project.State.Boot.Progress";
constexpr auto loggingService = "xyz.openbmc_project.Logging";
constexpr auto loggingObject = "/xyz/openbmc_project/logging";
constexpr auto loggingInterface = "xyz.openbmc_project.Logging.Create";
constexpr auto warnSeverity = "xyz.openbmc_project.Logging.Entry.Level.Warning";
constexpr auto errorSeverity = "xyz.openbmc_project.Logging.Entry.Level.Error";
constexpr auto postCodeService = "xyz.openbmc_project.State.Boot.PostCode0";
constexpr auto postCodeObject = "/xyz/openbmc_project/State/Boot/PostCode0";
constexpr auto postCodeInterface = "xyz.openbmc_project.State.Boot.PostCode";

static const std::map<std::string, std::string> sbmrBootProgressStages{
    {"0x01000000050001c100", "PrimaryProcInit"},
    {"0x01000000060001c100", "SecondaryProcInit"},
    {"0x010000000110010200", "PCIInit"},
    {"0x010000000110040300", "SystemInitComplete"},
    {"0x010000000700050300", "SystemSetup"},
    {"0x010000000180050300", "OSStart"},
    {"0x010000001910100300", "OSRunning"}};

constexpr auto oemSbmrBootStage = "OEM";
constexpr auto valueProperty = "Value";
constexpr auto bootProgressSizeWithoutInstance = 8;
constexpr auto progressCodeJson =
    "/usr/share/sbmrbootprogress/sbmr_boot_progress_code.json";

boost::asio::io_context io;
auto conn = std::make_shared<sdbusplus::asio::connection>(io);

constexpr auto dbusOrgPropertyInterface = "org.freedesktop.DBus.Properties";
using PrimaryCode_t = uint64_t;
using SecondaryCode_t = std::vector<uint8_t>;
using BootProgress_t = std::tuple<PrimaryCode_t, SecondaryCode_t>;
using Json = nlohmann::json;
using RawInterface = sdbusplus::xyz::openbmc_project::State::Boot::server::Raw;

struct SbmrBootProgress
{
    SbmrBootProgress()
    {
        // parse JSON file when Service started
        errorLog = parseJSONConfig(progressCodeJson);
    }

    ~SbmrBootProgress() {}
    Json parseJSONConfig(const std::string& configFile);
    void updateBootProgressProperties(BootProgress_t sbmrBootProgressCode,
                                      uint64_t tsUS);

  private:
    void updateBootProgressOem(const std::string& oemLastState);
    void updateBootProgressLastUpdate(uint64_t tsUS);
    void updatePropertyBootProgress(const std::string& sbmrBootProgressStage);
    Json errorLog;
    bool ResetToDefault = false;
};

Json SbmrBootProgress::parseJSONConfig(const std::string& configFile)
{
    std::ifstream jsonFile(configFile);
    if (!jsonFile.is_open())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Boot progress JSON file not found");
    }
    auto data = Json::parse(jsonFile, nullptr, false);
    if (data.is_discarded())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Boot progress JSON parser failure");
    }
    return data;
}

void SbmrBootProgress::updateBootProgressProperties(
    BootProgress_t sbmrBootProgressCode, uint64_t tsUS)
{
    auto logEvent = 0;
    auto bootProgressRecord =
        std::get<std::vector<uint8_t>>(sbmrBootProgressCode);

    if (bootProgressRecord.empty() ||
        bootProgressRecord.size() != sbmrBootProgressSize)
    {
        return;
    }
    if (!tsUS)
    {
        tsUS = std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
        logEvent = 1;
    }
    std::stringstream hexCode;
    hexCode << "0x" << std::hex << std::setfill('0');

    for (auto iterator = 0; iterator < bootProgressSizeWithoutInstance;
         iterator++)
    {
        hexCode << std::setw(2) << std::setfill('0')
                << static_cast<int>(bootProgressRecord[iterator]);
    }
    // Filter Severity to the bootProgressJsonKey
    auto bootProgressJsonKey = hexCode.str().replace(severityByte, 2, "00");

    // add instance to the hexCode
    hexCode << std::setw(2) << std::setfill('0')
            << static_cast<int>(bootProgressRecord[8]);
    auto bootProgressStage = hexCode.str();

    updateBootProgressOem(bootProgressStage);
    updateBootProgressLastUpdate(tsUS);
    // Find the mapping
    auto found = sbmrBootProgressStages.find(bootProgressStage);
    if (found == sbmrBootProgressStages.end())
    {
        updatePropertyBootProgress(oemSbmrBootStage);
    }
    else
    {
        updatePropertyBootProgress(found->second);
    }

    // Don't log event when BMC rebooted/Service start
    if (!errorLog.is_discarded() && logEvent)
    {
        if (bootProgressRecord[0] == bootProgressCode)
        {
            // Check the ResetToDefault progress code
            if ((bootProgressRecord[4] == opByte1ConfigReset) &&
                (bootProgressRecord[5] == opByte2BootSerice) &&
                (bootProgressRecord[6] == subClassSpecific) &&
                (bootProgressRecord[7] == classSoftware))
            {
                ResetToDefault = true;
            }
        }
        if (bootProgressRecord[0] == bootErrorCode)
        {
            // Handle the specific cases
            if ((bootProgressRecord[6] == subClassNvFwBoot) &&
                (bootProgressRecord[7] == classNvFw))
            {
                // EFI_NV_FW_BOOT_EC_LAST_BOOT_ERROR
                // Their operation code is **8*, **9*, **A*
                // * means that it could be 0~F
                if (bootProgressRecord[5])
                {
                    hexCode.str("");
                    hexCode.clear();
                    hexCode << std::setw(4)
                            << (nvFwBootJsonKey | bootProgressRecord[5]);
                    bootProgressJsonKey = bootProgressJsonKey.replace(
                        operationByte, 4, hexCode.str());
                }
                // EFI_NV_FW_BOOT_EC_BINARY_LOAD_FAILED
                else if ((bootProgressRecord[4] == opByte1BinLoadFailed) &&
                         (bootProgressRecord[5] == opByte2BinLoadFailed))
                {
                    // If ResetToDefualt flag is true
                    // skip reporting this boot error
                    // it is expected if the MB1 cannot
                    // find the varstore at that time.
                    if (ResetToDefault)
                    {
                        ResetToDefault = false;
                        return;
                    }
                }
            }
            auto message = errorLog.value(bootProgressJsonKey, "");
            if (!message.empty())
            {
                try
                {
                    std::map<std::string, std::string> additionData = {};
                    std::stringstream logMessage;
                    auto socket = (bootProgressRecord[8] & socketMask) >> 6;
                    auto instance = bootProgressRecord[8] & instanceMask;
                    logMessage << message << ", Socket 0x" << std::hex << socket
                               << ", Instance 0x" << std::hex << instance;
                    auto method =
                        conn->new_method_call(loggingService, loggingObject,
                                              loggingInterface, "Create");
                    method.append(logMessage.str());
                    if (bootProgressRecord[3] == errorMinor)
                    {
                        method.append(warnSeverity);
                    }
                    else
                    {
                        method.append(errorSeverity);
                    }
                    method.append(additionData);
                    auto reply = conn->call(method);
                }
                catch (const std::exception& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        e.what());
                }
            }
        }
    }

    return;
}
void SbmrBootProgress::updateBootProgressOem(const std::string& oemLastState)
{
    try
    {
        std::variant<std::string> variantStringValue(oemLastState);
        auto method =
            conn->new_method_call(bootProgressService, bootProgressObject,
                                  dbusOrgPropertyInterface, "Set");
        method.append(bootProgressInf, "BootProgressOem", variantStringValue);
        auto reply = conn->call(method);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
    }
    return;
}
void SbmrBootProgress::updatePropertyBootProgress(
    const std::string& sbmrBootProgressStage)
{
    try
    {
        auto enumValue =
            "xyz.openbmc_project.State.Boot.Progress.ProgressStages." +
            sbmrBootProgressStage;
        std::variant<std::string> variantValue(enumValue);
        auto method =
            conn->new_method_call(bootProgressService, bootProgressObject,
                                  dbusOrgPropertyInterface, "Set");

        method.append(bootProgressInf, "BootProgress", variantValue);
        auto reply = conn->call(method);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
    }

    return;
}
void SbmrBootProgress::updateBootProgressLastUpdate(uint64_t tsUS)
{
    try
    {
        std::variant<uint64_t> variantTimeValue(tsUS);
        auto method =
            conn->new_method_call(bootProgressService, bootProgressObject,
                                  dbusOrgPropertyInterface, "Set");
        method.append(bootProgressInf, "BootProgressLastUpdate",
                      variantTimeValue);
        auto reply = conn->call(method);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
    }
    return;
}
