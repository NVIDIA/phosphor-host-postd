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

#include "BootProgressPoller.hpp"
#include "BootProgressPublisher.hpp"
#include "BootProgressTypes.hpp"
#include "PollingDevice.hpp"

#include <sdbusplus/async.hpp>

#include <chrono>
#include <memory>
#include <unordered_map>
#include <vector>

struct DeviceIdentity
{
    TransportInterface transport;
    uint8_t bus;
    uint8_t address;
    bool operator==(const DeviceIdentity& other) const
    {
        return transport == other.transport && bus == other.bus &&
               address == other.address;
    }
};

struct SocketData
{
    DeviceIdentity identity;
    std::shared_ptr<BootProgressPoller> poller;
    std::shared_ptr<PollingDevice> device; // retained for L1 reset
    std::vector<std::pair<uint32_t, uint32_t>> buffer;
    SocketData() = default;
    SocketData(DeviceIdentity id, std::shared_ptr<BootProgressPoller> p,
               std::shared_ptr<PollingDevice> d) :
        identity(id), poller(std::move(p)), device(std::move(d))
    {}
};

class BootProgressManager
{
  public:
    BootProgressManager(sdbusplus::async::context& ctx,
                        std::shared_ptr<BootProgressPublisher> publisher,
                        std::chrono::milliseconds pollInterval);

    void onBootProgressData(
        int socketId,
        std::vector<std::pair<uint32_t, uint32_t>> bootProgressEntries);

    void onDeviceAdded(std::shared_ptr<PollingDevice> device,
                       TransportInterface transportInterface,
                       const uint8_t& bus, const uint8_t& address);

    void onDeviceRemoved(TransportInterface transportInterface,
                         const uint8_t& bus, const uint8_t& address);

    void updatePollInterval(std::chrono::milliseconds newPollInterval);

    void updatePollStatus(bool enablePolling);

    /** Perform an L1 SW main reset on the first available polling device.
     *  Pauses boot-progress polling for the duration to avoid concurrent
     *  device access.  Throws sdbusplus Common errors on failure. */
    sdbusplus::async::task<> doL1Reset();

    void initIndices();

    void resetPublisherCachedState();

  private:
    sdbusplus::async::context& ctx;
    std::shared_ptr<BootProgressPublisher> publisher;
    std::chrono::milliseconds pollInterval;
    std::unordered_map<int, SocketData> socketDataMap;
    int nextSocketId = 0;
    std::vector<std::pair<uint32_t, uint32_t>> allSocketProgressEntries;
    bool resetInProgress_ = false;

    void aggregateAndSortAllSocketData();
    sdbusplus::async::task<void> periodicPublishCheck();
    void tryPublish();
};
