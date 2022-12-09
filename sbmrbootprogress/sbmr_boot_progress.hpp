#pragma once

#include "nlohmann/json.hpp"

#include <chrono>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/State/Boot/Raw/server.hpp>

constexpr auto sbmrBootProgressSize = 9;
constexpr auto bootProgressCode = 0x01;
constexpr auto bootErrorCode = 0x02;
constexpr auto bootDebugCode = 0x03;
constexpr auto severityByte = 8;
constexpr auto errorMinor = 0x40;
constexpr auto errorMajor = 0x80;
constexpr auto errorUnrecoverd = 0x90;
constexpr auto errorUncontained = 0xA0;
constexpr auto socketMask = 0xC0;
constexpr auto instanceMask = 0x3F;

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
    {"0x010000000008050300", "OSStart"},
    {"0x010000001910100300", "OSRunning"}};

constexpr auto oemSbmrBootStage = "OEM";
constexpr auto valueProperty = "Value";
constexpr auto bootProgressSizeWithoutInstance = 8;
constexpr auto progressCodeJson =
    "/usr/share/sbmrbootprogress/sbmr_boot_progress_code.json";

boost::asio::io_context io;
auto conn = std::make_shared<sdbusplus::asio::connection>(io);

constexpr auto dbusOrgPropertyInterface =
    "org.freedesktop.DBus.Properties";
using PrimaryCode_t = uint64_t;
using SecondaryCode_t = std::vector<uint8_t>;
using BootProgress_t = std::tuple<PrimaryCode_t, SecondaryCode_t>;
using Json = nlohmann::json;
using RawInterface = sdbusplus::xyz::openbmc_project::State::Boot::server::Raw;
Json errorLog;

struct SbmrBootProgress : sdbusplus::server::object_t<RawInterface>
{
    SbmrBootProgress(sdbusplus::bus::bus& bus, const char* path) :
        sdbusplus::server::object_t<RawInterface>(bus, path)
    {
        // Updating Boot progress Dbus Properties on reboot
        updateBootProgress();
    }
    ~SbmrBootProgress()
    {
    }
    virtual std::tuple<uint64_t, std::vector<uint8_t>>
        value(std::tuple<uint64_t, std::vector<uint8_t>> value) override;
    virtual std::tuple<uint64_t, std::vector<uint8_t>> value();
    Json parseJSONConfig(const std::string& configFile);

  private:
    void updateBootProgress();
    void updateBootProgressProperties(BootProgress_t sbmrBootProgressCode,
                                      uint64_t tsUS);
    void updateBootProgressOem(const std::string& oemLastState);
    void updateBootProgressLastUpdate(uint64_t tsUS);
    void updatePropertyBootProgress(const std::string& sbmrBootProgressStage);
};
void SbmrBootProgress::updateBootProgress()
{

    uint16_t mostRecentBootCodeIndex = 1;
    // parse JSON file when Service starts
    errorLog = parseJSONConfig(progressCodeJson);
    try
    {
        auto method = conn->new_method_call(postCodeService, postCodeObject,
                                            postCodeInterface,
                                            "GetPostCodesWithTimeStamp");
        method.append(mostRecentBootCodeIndex);
        auto reply = conn->call(method);
        if (reply.is_method_error())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "updateBootProgress:Failed to call method "
                "GetPostCodesWithTimestamp",
                phosphor::logging::entry("SERVICE=%s", postCodeService));
            return;
        }
        std::map<uint64_t, BootProgress_t> postCode;
        reply.read(postCode);
        // skip the empty postcode boots
        if (postCode.empty())
        {
            return;
        }
        // Get the last item from the map
        auto lastRecord = postCode.rbegin();
        // Getting the timestamp
        auto tsUS = lastRecord->first;
        // Getting the  Record
        auto lastElement = lastRecord->second;

        updateBootProgressProperties(lastElement, tsUS);
        // Update the Boot.Raw.Value when BMC reboots
        RawInterface::value(lastElement, true);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "updateBootProgress:Failed to get GetPostCodesWithTimestamp",
            phosphor::logging::entry("ERROR=%s", e.what()));
    }
    return;
}
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

std::tuple<uint64_t, std::vector<uint8_t>>
    SbmrBootProgress::value(std::tuple<uint64_t, std::vector<uint8_t>> value)
{
    updateBootProgressProperties(value, 0);
    return RawInterface::value(value, false);
}
std::tuple<uint64_t, std::vector<uint8_t>> SbmrBootProgress::value()
{
    return std::get<std::tuple<uint64_t, std::vector<uint8_t>>>(
        RawInterface::getPropertyByName(valueProperty));
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
    auto bootProgressJsonKey = hexCode.str().replace(severityByte,2,"00");

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
        if (bootProgressRecord[0] == bootErrorCode)
        {
            auto message = errorLog.value(bootProgressJsonKey, "");
            if (!message.empty())
            {
                try
                {
                    std::map<std::string, std::string> additionData = {};
                    std::stringstream logMessage;
                    auto socket = (bootProgressRecord[8] & socketMask) >> 6;
                    auto instance = bootProgressRecord[8] & instanceMask;
                    logMessage << message << ", Socket 0x" << std::hex << socket << ", Instance 0x"<< std::hex << instance;
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
        auto method = conn->new_method_call(bootProgressService, bootProgressObject,
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
        auto method = conn->new_method_call(bootProgressService, bootProgressObject,
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
        auto method = conn->new_method_call(bootProgressService, bootProgressObject,
                                            dbusOrgPropertyInterface, "Set");
        method.append(bootProgressInf, "BootProgressLastUpdate", variantTimeValue);
        auto reply = conn->call(method);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
    }
    return;
}
