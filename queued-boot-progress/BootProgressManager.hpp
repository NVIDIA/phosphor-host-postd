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
#include <unordered_map>
#include <vector>

struct SocketData
{
    std::shared_ptr<BootProgressPoller> poller;
    std::vector<std::pair<uint32_t, uint32_t>> buffer;
    SocketData() = default;
    SocketData(std::shared_ptr<BootProgressPoller> poller) : poller(poller) {}
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

    void onDeviceAdded(TransportInterface transportInterface,
                       const uint8_t& bus, const uint8_t& address,
                       int socketId);

    void onDeviceRemoved(TransportInterface transportInterface,
                         const uint8_t& bus, const uint8_t& address,
                         int socketId);

    void updatePollInterval(std::chrono::milliseconds newPollInterval);

    void updatePollStatus(bool enablePolling);

    void initIndices();

  private:
    sdbusplus::async::context& ctx;
    std::shared_ptr<BootProgressPublisher> publisher;
    std::chrono::milliseconds pollInterval;
    std::unordered_map<int, SocketData> socketDataMap;
    std::vector<std::pair<uint32_t, uint32_t>> allSocketProgressEntries;

    bool isAllSocketDataReady();
    void aggregateAndSortAllSocketData();
    sdbusplus::async::task<void> periodicPublishCheck();
    void tryPublish();
};
