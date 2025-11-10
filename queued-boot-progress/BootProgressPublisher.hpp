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

#include "lpcsnoop/snoop.hpp"

#include <sdbusplus/async.hpp>

#include <chrono>
#include <map>
#include <string>
#include <vector>

class BootProgressPublisher : public PostObject
{
  public:
    BootProgressPublisher(sdbusplus::async::context& ctx,
                          const std::string& snoopDbus,
                          const std::string& snoopObject);

    sdbusplus::async::task<void> update(
        const std::vector<std::pair<uint32_t, uint32_t>> progressCodeData);

  private:
    sdbusplus::async::context& ctx;
    // Cache last published values to avoid redundant D-Bus updates
    std::string lastPublishedStage;
    std::string lastPublishedOem;
    uint64_t lastPublishedTimestamp = 0;
    // Batching state for reducing D-Bus update frequency
    std::chrono::steady_clock::time_point lastDbusUpdateTime;
    std::string pendingStage;
    std::string pendingOem;
    uint64_t pendingTimestamp = 0;
    bool hasPendingUpdates = false;
    // Minimum interval between D-Bus property updates (milliseconds)
    static constexpr uint32_t dbusUpdateIntervalMs = 100;

    sdbusplus::async::task<void> updateBootProgressProperty(
        const std::string& progressStage);
    sdbusplus::async::task<void> updateBootProgressLastUpdateProperty(
        uint64_t bootProgressLastUpdate);
    sdbusplus::async::task<void> updateBootProgressOemProperty(
        const std::string& oemLastState);
    std::string getSbmrBootProgressStage(const uint32_t& progressCode);
    sdbusplus::async::task<void> flushPendingUpdates();
};
