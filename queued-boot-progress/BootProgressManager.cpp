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

#include "BootProgressManager.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <algorithm>

BootProgressManager::BootProgressManager(
    sdbusplus::async::context& ctx,
    std::shared_ptr<BootProgressPublisher> publisher,
    std::chrono::milliseconds pollInterval) :
    ctx(ctx), publisher(publisher), pollInterval(pollInterval)
{
    ctx.spawn(periodicPublishCheck());
}

void BootProgressManager::onBootProgressData(
    int socketId,
    std::vector<std::pair<uint32_t, uint32_t>> bootProgressEntries)
{
    if (bootProgressEntries.empty() || socketDataMap.empty())
    {
        lg2::info("onBootProgressData queues on socket {SOCKET_ID} empty",
                  "SOCKET_ID", socketId);
        return;
    }
    auto it = socketDataMap.find(socketId);
    if (it == socketDataMap.end())
    {
        lg2::warning("Socket ID {SOCKET_ID} not found in socketDataMap",
                     "SOCKET_ID", socketId);
        return;
    }
    it->second.buffer.insert(it->second.buffer.end(),
                             bootProgressEntries.begin(),
                             bootProgressEntries.end());
    if (publisher)
    {
        tryPublish();
    }
}

void BootProgressManager::onDeviceAdded(std::shared_ptr<PollingDevice> device,
                                        TransportInterface transportInterface,
                                        const uint8_t& bus,
                                        const uint8_t& address)
{
    DeviceIdentity identity{transportInterface, bus, address};
    if (!device)
    {
        lg2::error("onDeviceAdded: device is null");
        return;
    }

    int socketId = nextSocketId++;
    auto deviceRef = device; // retain reference before move
    auto poller = std::make_shared<BootProgressPoller>(
        ctx, std::move(device), pollInterval, socketId,
        std::bind(&BootProgressManager::onBootProgressData, this,
                  std::placeholders::_1, std::placeholders::_2));
    socketDataMap.emplace(socketId,
                          SocketData(identity, poller, std::move(deviceRef)));
    lg2::info(
        "Device added: transportInterface {TRANSPORT_INTERFACE}, bus {BUS}, address {ADDRESS}, socketId {SOCKET_ID}",
        "TRANSPORT_INTERFACE", static_cast<int>(transportInterface), "BUS", bus,
        "ADDRESS", address, "SOCKET_ID", socketId);
}

void BootProgressManager::onDeviceRemoved(TransportInterface transportInterface,
                                          const uint8_t& bus,
                                          const uint8_t& address)
{
    DeviceIdentity identity{transportInterface, bus, address};
    auto dataIt = std::find_if(socketDataMap.begin(), socketDataMap.end(),
                               [&identity](const auto& pair) {
                                   return pair.second.identity == identity;
                               });
    if (dataIt == socketDataMap.end())
    {
        lg2::warning(
            "Device not found for removal: transport {TRANSPORT}, bus {BUS}, address {ADDRESS}",
            "TRANSPORT", static_cast<int>(transportInterface), "BUS", bus,
            "ADDRESS", address);
        return;
    }
    lg2::info(
        "Device removed: transportInterface {TRANSPORT_INTERFACE}, bus {BUS}, address {ADDRESS}, socketId {SOCKET_ID}",
        "TRANSPORT_INTERFACE", static_cast<int>(transportInterface), "BUS", bus,
        "ADDRESS", address, "SOCKET_ID", dataIt->first);

    dataIt->second.poller->stop();
    socketDataMap.erase(dataIt);

    if (transportInterface == TransportInterface::USB && socketDataMap.empty())
    {
        resetPublisherCachedState();
    }
}

void BootProgressManager::updatePollInterval(
    std::chrono::milliseconds newPollInterval)
{
    pollInterval = newPollInterval;
    for (const auto& [socketId, socketData] : socketDataMap)
    {
        socketData.poller->updatePollInterval(pollInterval);
    }
}

void BootProgressManager::updatePollStatus(bool enable)
{
    for (const auto& [socketId, socketData] : socketDataMap)
    {
        socketData.poller->updatePollStatus(enable);
    }
}

void BootProgressManager::initIndices()
{
    for (const auto& [socketId, socketData] : socketDataMap)
    {
        socketData.poller->initIndices();
    }
}

void BootProgressManager::aggregateAndSortAllSocketData()
{
    allSocketProgressEntries.clear();
    for (auto& [socketId, socketData] : socketDataMap)
    {
        allSocketProgressEntries.insert(allSocketProgressEntries.end(),
                                        socketData.buffer.begin(),
                                        socketData.buffer.end());
        socketData.buffer.clear();
    }
    std::stable_sort(
        allSocketProgressEntries.begin(), allSocketProgressEntries.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });
}

void BootProgressManager::tryPublish()
{
    aggregateAndSortAllSocketData();
    if (!publisher || allSocketProgressEntries.empty())
    {
        lg2::debug(
            "tryPublish: publisher or allSocketProgressEntries is empty");
        return;
    }
    ctx.spawn(publisher->update(allSocketProgressEntries));
}

sdbusplus::async::task<void> BootProgressManager::periodicPublishCheck()
{
    const auto publishInterval = std::chrono::seconds(10);
    // Sleep in small chunks so the coroutine exits promptly when the context
    // is stopped, rather than waiting up to publishInterval for the timer.
    const auto sleepChunk = std::chrono::milliseconds(100);
    std::chrono::milliseconds elapsed{0};
    while (!ctx.stop_requested())
    {
        co_await sdbusplus::async::sleep_for(ctx, sleepChunk);
        elapsed += sleepChunk;
        if (elapsed >= publishInterval && !ctx.stop_requested())
        {
            elapsed = std::chrono::milliseconds{0};
            if (publisher)
            {
                tryPublish();
            }
        }
    }
    co_return;
}

sdbusplus::async::task<> BootProgressManager::doL1Reset()
{
    if (socketDataMap.empty())
    {
        lg2::error("L1Reset: no polling devices available");
        throw sdbusplus::xyz::openbmc_project::Common::Error::Unavailable();
    }

    if (resetInProgress_)
    {
        lg2::warning(
            "L1Reset: reset already in progress, rejecting concurrent call");
        throw sdbusplus::xyz::openbmc_project::Common::Error::Unavailable();
    }
    resetInProgress_ = true;

    // Pause boot-progress polling to avoid concurrent device access during
    // the reset operation.
    lg2::info("L1Reset: pausing boot-progress polling");
    updatePollStatus(false);

    struct PollResumeGuard
    {
        BootProgressManager& mgr;
        ~PollResumeGuard()
        {
            mgr.resetInProgress_ = false;
            lg2::info("L1Reset: resuming boot-progress polling");
            mgr.updatePollStatus(true);
        }
    } pollGuard{*this};

    // Retry loop with async sleep so the event loop is not blocked between
    // attempts.  Device doL1Reset() tries once synchronously (no sleep).
    constexpr int maxAttempts = 5;
    constexpr auto retryDelay = std::chrono::milliseconds(100);
    bool success = false;

    // Snapshot IDs before any co_await: onDeviceRemoved can erase from
    // socketDataMap while the coroutine is suspended, invalidating iterators.
    std::vector<int> socketIds;
    socketIds.reserve(socketDataMap.size());
    for (const auto& [id, _] : socketDataMap)
    {
        socketIds.push_back(id);
    }

    for (int attempt = 1; attempt <= maxAttempts && !success; ++attempt)
    {
        if (attempt > 1)
        {
            lg2::debug("L1Reset: retry {ATTEMPT}/{MAX} after delay", "ATTEMPT",
                       attempt, "MAX", maxAttempts);
            co_await sdbusplus::async::sleep_for(ctx, retryDelay);
        }

        for (int socketId : socketIds)
        {
            auto it = socketDataMap.find(socketId);
            if (it == socketDataMap.end() || !it->second.device)
            {
                continue;
            }
            auto& socketData = it->second;
            lg2::info("L1Reset: attempt {ATTEMPT}/{MAX} on socket {SOCKET}",
                      "ATTEMPT", attempt, "MAX", maxAttempts, "SOCKET",
                      socketId);
            if (socketData.device->doL1Reset())
            {
                lg2::info(
                    "L1Reset: succeeded on attempt {ATTEMPT} socket {SOCKET}",
                    "ATTEMPT", attempt, "SOCKET", socketId);
                success = true;
                break;
            }
            lg2::warning(
                "L1Reset: attempt {ATTEMPT}/{MAX} failed on socket {SOCKET}",
                "ATTEMPT", attempt, "MAX", maxAttempts, "SOCKET", socketId);
        }
    }

    if (!success)
    {
        lg2::error("L1Reset: all {MAX} attempts failed", "MAX", maxAttempts);
        throw sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure();
    }
    co_return;
}

void BootProgressManager::resetPublisherCachedState()
{
    if (publisher)
    {
        publisher->resetCachedState();
    }
}
