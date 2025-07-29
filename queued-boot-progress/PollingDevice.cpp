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

#include "PollingDevice.hpp"

#include "BootProgressManager.hpp"

#include <phosphor-logging/lg2.hpp>

PollingDeviceEnumerator::PollingDeviceEnumerator(
    sdbusplus::async::context& ctx, std::shared_ptr<BootProgressManager> mgr) :
    ctx(ctx), manager(mgr)
{}

int PollingDeviceEnumerator::addDeviceAndGetSocketId(uint8_t bus,
                                                     uint8_t address)
{
    int socketId = nextSocketId++;
    deviceToSocketMap[std::make_pair(bus, address)] = socketId;
    lg2::debug(
        "Added device mapping: bus {BUS} address {ADDRESS} -> socket {SOCKET_ID}",
        "BUS", static_cast<int>(bus), "ADDRESS", static_cast<int>(address),
        "SOCKET_ID", socketId);
    return socketId;
}

int PollingDeviceEnumerator::removeDeviceAndGetSocketId(uint8_t bus,
                                                        uint8_t address)
{
    auto deviceKey = std::make_pair(bus, address);
    auto it = deviceToSocketMap.find(deviceKey);

    if (it == deviceToSocketMap.end())
    {
        lg2::warning(
            "Device mapping not found for removal: bus {BUS} address {ADDRESS}",
            "BUS", static_cast<int>(bus), "ADDRESS", static_cast<int>(address));
        return -1;
    }

    int socketId = it->second;
    lg2::debug(
        "Removed device mapping: bus {BUS} address {ADDRESS} -> socket {SOCKET_ID}",
        "BUS", static_cast<int>(bus), "ADDRESS", static_cast<int>(address),
        "SOCKET_ID", socketId);
    deviceToSocketMap.erase(it);
    return socketId;
}

std::shared_ptr<PollingDevice>
    getPollingDevice(TransportInterface transportInterface, const uint8_t& bus,
                     const uint8_t& address)
{
    switch (transportInterface)
    {
        case TransportInterface::I2C:
        {
            lg2::info(
                "Creating I2CPollingDevice for bus {BUS} and address {ADDRESS}",
                "BUS", static_cast<int>(bus), "ADDRESS",
                static_cast<int>(address));
            return std::make_shared<I2CPollingDevice>(bus, address);
        }
        case TransportInterface::USB:
        {
            lg2::info(
                "Creating USBPollingDevice for bus {BUS} and address {ADDRESS}",
                "BUS", static_cast<int>(bus), "ADDRESS",
                static_cast<int>(address));
            return std::make_shared<USBPollingDevice>(bus, address);
        }
        default:
        {
            lg2::error("Unsupported transport interface: {INTERFACE}",
                       "INTERFACE", static_cast<int>(transportInterface));
            return nullptr;
        }
    }
}

std::shared_ptr<PollingDeviceEnumerator> getPollingDeviceEnumerator(
    sdbusplus::async::context& ctx, std::shared_ptr<BootProgressManager> mgr,
    TransportInterface transportInterface, uint16_t vendorId,
    uint16_t productId, std::chrono::seconds rescanInterval)
{
    switch (transportInterface)
    {
        case TransportInterface::USB:
        {
            return std::make_shared<USBDeviceEnumerator>(
                ctx, mgr, vendorId, productId, rescanInterval);
        }
        default:
        {
            lg2::error("Unsupported transport interface: {INTERFACE}",
                       "INTERFACE", static_cast<int>(transportInterface));
            return nullptr;
        }
    }
}
