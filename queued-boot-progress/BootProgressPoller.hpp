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
#include "BootProgressTypes.hpp"
#include "PollingDevice.hpp"

#include <sdbusplus/async.hpp>

#include <array>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <vector>

class BootProgressPoller :
    public std::enable_shared_from_this<BootProgressPoller>
{
  public:
    BootProgressPoller(sdbusplus::async::context& ctx,
                       std::shared_ptr<PollingDevice> device,
                       std::chrono::milliseconds pollInterval, int socketId,
                       onBootProgressDataCallback processBootProgressData);

    void initIndices();

    void updatePollInterval(std::chrono::milliseconds newInterval);

    void updatePollStatus(bool pollStatus);

    void stop();

  private:
    sdbusplus::async::context& ctx;
    std::shared_ptr<PollingDevice> device;
    std::chrono::milliseconds pollInterval;
    int socketId;
    onBootProgressDataCallback processBootProgressData = nullptr;
    bool pollStatus;
    bool stopped = false;
    uint32_t consecutiveFailures = 0;

    static constexpr int numberOfQueues = 2;

    std::array<uint32_t, numberOfQueues> readIdx{};
    std::array<uint32_t, numberOfQueues> prevStart{};

    static constexpr uint32_t scratchRamGroup0 = 0x8000;
    static constexpr uint32_t queue0IndexRegister = 0x2000;
    static constexpr uint32_t queue1IndexRegister = 0x2004;

    static constexpr std::array<uint32_t, numberOfQueues> queueIndexStart = {
        queue0IndexRegister, queue1IndexRegister};

    sdbusplus::async::task<void> pollQueues();
    sdbusplus::async::task<std::optional<uint32_t>> readRegister(
        uint32_t regAddr, const std::shared_ptr<PollingDevice>& dev);
    sdbusplus::async::task<
        std::optional<std::vector<std::pair<uint32_t, uint32_t>>>>
        processQueue(int queueNumber,
                     const std::shared_ptr<PollingDevice>& dev);
    sdbusplus::async::task<std::optional<uint32_t>> getQbaseIdx(
        int qnum, const std::shared_ptr<PollingDevice>& dev);
    void parseQueueIndices(uint32_t regVal, uint32_t& start, uint32_t& end,
                           uint32_t& size);
    std::chrono::milliseconds calculateSleepDuration() const;
};
