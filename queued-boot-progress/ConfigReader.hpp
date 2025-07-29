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
#include <getopt.h>

#include <phosphor-logging/lg2.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

// Forward declaration - will be included from PollingDevice.hpp
enum class TransportInterface;

struct Configuration
{
    std::chrono::milliseconds pollInterval;
    TransportInterface transportInterface;
    std::vector<std::pair<uint8_t /*bus*/, uint8_t /*address*/>>
        i2cInterfaceConfigMap;
    uint16_t usbVendorId = 0x0955;
    uint16_t usbProductId = 0x7410;
    std::chrono::seconds usbRescanInterval = std::chrono::seconds(100);
};

class ConfigReader
{
  public:
    ConfigReader() = default;
    static bool readConfig(int argc, char* argv[], Configuration& config)
    {
        int opt;
        static const struct option long_options[] = {
            {"poll-interval", required_argument, NULL, 'p'},
            {"transport-interface", required_argument, NULL, 'i'},
            {"i2c-bus", required_argument, NULL, 'b'},
            {"i2c-address", required_argument, NULL, 'a'},
            {0, 0, 0, 0}};
        std::vector<int> busList;
        std::vector<int> addrList;
        while ((opt = getopt_long(argc, argv, "p:i:b:a:", long_options,
                                  NULL)) != -1)
        {
            switch (opt)
            {
                case 'p':
                    try
                    {
                        config.pollInterval =
                            std::chrono::milliseconds(std::stoi(optarg));
                        if (config.pollInterval.count() < 1)
                        {
                            lg2::error("Invalid poll interval: {INTERVAL}",
                                       "INTERVAL", optarg);
                            return false;
                        }
                    }
                    catch (const std::exception& e)
                    {
                        lg2::error("Invalid poll interval: {INTERVAL}",
                                   "INTERVAL", optarg);
                        return false;
                    }
                    break;
                case 'i':
                    if (std::string(optarg) == "i2c")
                    {
                        config.transportInterface = TransportInterface::I2C;
                    }
                    else if (std::string(optarg) == "usb")
                    {
                        config.transportInterface = TransportInterface::USB;
                    }
                    else
                    {
                        lg2::error("Invalid transport interface: {INTERFACE}",
                                   "INTERFACE", optarg);
                        return false;
                    }
                    break;
                case 'b':
                    try
                    {
                        auto busId = std::stoi(optarg);
                        if (busId < 0 || busId > 255)
                        {
                            lg2::error("Invalid i2c bus: {BUS}", "BUS", optarg);
                            return false;
                        }
                        busList.push_back(busId);
                    }
                    catch (const std::exception& e)
                    {
                        lg2::error("Invalid i2c bus: {BUS}", "BUS", optarg);
                        return false;
                    }
                    break;
                case 'a':
                    try
                    {
                        auto addrId = std::stoi(optarg);
                        if (addrId < 0 || addrId > 255)
                        {
                            lg2::error("Invalid i2c address: {ADDRESS}",
                                       "ADDRESS", optarg);
                            return false;
                        }
                        addrList.push_back(addrId);
                    }
                    catch (const std::exception& e)
                    {
                        lg2::error("Invalid i2c address: {ADDRESS}", "ADDRESS",
                                   optarg);
                        return false;
                    }
                    break;
                default:
                    lg2::error("Invalid option: {OPTION}", "OPTION", opt);
                    return false;
            }
        }
        if (busList.size() != addrList.size())
        {
            lg2::error("Invalid i2c bus and address sizes: {BUS} {ADDRESS}",
                       "BUS", busList.size(), "ADDRESS", addrList.size());
            return false;
        }
        for (size_t i = 0; i < busList.size(); ++i)
        {
            config.i2cInterfaceConfigMap.emplace_back(
                static_cast<uint8_t>(busList[i]),
                static_cast<uint8_t>(addrList[i]));
        }
        if (!validateTransportConfiguration(config))
        {
            return false;
        }
        return true;
    }

  private:
    static bool validateTransportConfiguration(const Configuration& config)
    {
        switch (config.transportInterface)
        {
            case TransportInterface::I2C:
            {
                if (config.i2cInterfaceConfigMap.empty())
                {
                    lg2::error(
                        "I2C transport selected but no I2C devices configured");
                    return false;
                }
                return true;
            }
            case TransportInterface::USB:
            {
                if (config.usbVendorId == 0 || config.usbProductId == 0)
                {
                    lg2::error(
                        "USB transport selected but invalid vendor/product IDs: vendor={VENDOR_ID}, product={PRODUCT_ID}",
                        "VENDOR_ID", config.usbVendorId, "PRODUCT_ID",
                        config.usbProductId);
                    return false;
                }
                return true;
            }
            default:
            {
                lg2::error("Unsupported transport interface: {INTERFACE}",
                           "INTERFACE",
                           static_cast<int>(config.transportInterface));
                return false;
            }
        }
    }
};
