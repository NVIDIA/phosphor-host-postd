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

#include "BootProgressPoller.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>

BootProgressPoller::BootProgressPoller(
    sdbusplus::async::context& ctx, std::shared_ptr<PollingDevice> device,
    std::chrono::milliseconds pollInterval, int socketId,
    onBootProgressDataCallback onBootProgressDataCb) :
    ctx(ctx), device(std::move(device)), pollInterval(pollInterval),
    socketId(socketId), processBootProgressData(onBootProgressDataCb)
{
    initIndices();
    pollStatus = true;
    ctx.spawn(pollQueues());
}

void BootProgressPoller::initIndices()
{
    readIdx.fill(0);
    prevStart.fill(0);
}

sdbusplus::async::task<std::optional<uint32_t>>
    BootProgressPoller::readRegister(uint32_t regAddr)
{
    uint32_t regValue = 0;
    if (!device->readRegisterValue(regAddr, regValue))
    {
        lg2::debug("Failed to read register {REG_ADDR}", "REG_ADDR",
                   std::format("0x{:08X}", regAddr));
        co_return std::nullopt;
    }
    co_return regValue;
}

void BootProgressPoller::parseQueueIndices(uint32_t regVal, uint32_t& start,
                                           uint32_t& end, uint32_t& size)
{
    end = (regVal & 0x3FF);
    start = ((regVal >> 10) & 0x3FF);
    size = ((regVal >> 20) & 0x7FF);
}

sdbusplus::async::task<std::optional<uint32_t>> BootProgressPoller::getQbaseIdx(
    int qnum)
{
    if (qnum == 0)
    {
        co_return 0;
    }

    auto regResult = co_await readRegister(queueIndexStart.at(0));
    if (!regResult.has_value())
    {
        lg2::debug("Failed to read queue base index for qnum {QNUM}", "QNUM",
                   qnum);
        co_return std::nullopt;
    }

    uint32_t currStart = 0, currEnd = 0, size = 0;
    parseQueueIndices(regResult.value(), currStart, currEnd, size);
    co_return size;
}

sdbusplus::async::task<
    std::optional<std::vector<std::pair<uint32_t, uint32_t>>>>
    BootProgressPoller::processQueue(int queueNumber)
{
    std::vector<std::pair<uint32_t, uint32_t>> bootProgressEntries;
    uint32_t currStart = 0, currEnd = 0, queueSize = 0;

    auto regResult = co_await readRegister(queueIndexStart[queueNumber]);
    if (!regResult.has_value())
    {
        lg2::debug(
            "Failed to read queue index for queue {QUEUE_NUMBER} on socket {SOCKET_ID}",
            "QUEUE_NUMBER", queueNumber, "SOCKET_ID", socketId);
        co_return std::nullopt;
    }

    parseQueueIndices(regResult.value(), currStart, currEnd, queueSize);

    if (queueSize == 0)
    {
        lg2::debug("Queue {QUEUE_NUMBER} on socket {SOCKET_ID} size is zero",
                   "QUEUE_NUMBER", queueNumber, "SOCKET_ID", socketId);
        co_return std::nullopt;
    }

    auto qbase = co_await getQbaseIdx(queueNumber);
    if (!qbase.has_value())
    {
        co_return std::nullopt;
    }

    const uint32_t qbaseIdx = qbase.value();
    uint32_t& idx = readIdx[queueNumber];
    uint32_t& lastStart = prevStart[queueNumber];

    if (idx == 0 && lastStart == 0)
    {
        idx = currStart;
        lastStart = currStart;
        lg2::debug(
            "Initialising queue {QUEUE_NUMBER} on socket {SOCKET_ID}: start={START}, end={END}",
            "QUEUE_NUMBER", queueNumber, "SOCKET_ID", socketId, "START",
            currStart, "END", currEnd);
    }

    if (idx == currEnd)
    {
        lg2::debug(
            "No new entries for queue {QUEUE_NUMBER} on socket {SOCKET_ID}: idx={IDX}, end={END}",
            "QUEUE_NUMBER", queueNumber, "SOCKET_ID", socketId, "IDX", idx,
            "END", currEnd);
        co_return bootProgressEntries;
    }

    uint32_t iterations = 0;
    const uint32_t maxIterations = queueSize;

    while (idx != currEnd)
    {
        if (currStart != lastStart)
        {
            idx = currStart;
            lastStart = currStart;
            bootProgressEntries.emplace_back(
                std::make_pair(0xFFFFFFFF, 0xFFFFFFFF));
            lg2::info(
                "Queue {QUEUE_NUMBER} on socket {SOCKET_ID} overflow detected: new start={START}",
                "QUEUE_NUMBER", queueNumber, "SOCKET_ID", socketId, "START",
                currStart);
        }

        const uint32_t tsAddr = scratchRamGroup0 + (8 * idx);
        const uint32_t codeAddr = tsAddr + 4;

        auto tsResult = co_await readRegister(tsAddr);
        if (!tsResult.has_value())
        {
            lg2::debug(
                "Failed to read timestamp at {TS_ADDR} for socket {SOCKET_ID} queue {QUEUE_NUMBER}",
                "TS_ADDR", std::format("0x{:08X}", tsAddr), "SOCKET_ID",
                socketId, "QUEUE_NUMBER", queueNumber);
            co_return std::nullopt;
        }

        auto codeResult = co_await readRegister(codeAddr);
        if (!codeResult.has_value())
        {
            lg2::debug(
                "Failed to read progress code at {CODE_ADDR} for socket {SOCKET_ID} queue {QUEUE_NUMBER}",
                "CODE_ADDR", std::format("0x{:08X}", codeAddr), "SOCKET_ID",
                socketId, "QUEUE_NUMBER", queueNumber);
            co_return std::nullopt;
        }
        std::string tsResultStr = std::format("0x{:08X}", tsResult.value());
        std::string codeResultStr = std::format("0x{:08X}", codeResult.value());
        lg2::debug(
            "Read timestamp {TS_RESULT} and code {CODE_RESULT} on socket {SOCKET_ID}, queue {QUEUE_NUMBER}",
            "TS_RESULT", tsResultStr, "CODE_RESULT", codeResultStr, "SOCKET_ID",
            socketId, "QUEUE_NUMBER", queueNumber);
        if (codeResult.value() != 0x00000000)
        {
            bootProgressEntries.emplace_back(
                std::make_pair(tsResult.value(), codeResult.value()));
        }

        idx = ((idx - qbaseIdx + 1) % queueSize) + qbaseIdx;
        ++iterations;

        if (iterations > maxIterations)
        {
            lg2::error(
                "Queue {QUEUE_NUMBER} on socket {SOCKET_ID} exceeded expected iterations: idx={IDX}, end={END}, iterations={ITER}, size={SIZE}",
                "QUEUE_NUMBER", queueNumber, "SOCKET_ID", socketId, "IDX", idx,
                "END", currEnd, "ITER", iterations, "SIZE", queueSize);
            break;
        }
    }
    lastStart = currStart;
    co_return bootProgressEntries;
}

sdbusplus::async::task<void> BootProgressPoller::pollQueues()
{
    while (!ctx.stop_requested())
    {
        if (pollStatus)
        {
            bool anyReadSucceeded = false;
            std::vector<std::pair<uint32_t, uint32_t>> entries;

            for (int qnum = 0; qnum < numberOfQueues; ++qnum)
            {
                auto queueResults = co_await processQueue(qnum);
                if (queueResults.has_value())
                {
                    anyReadSucceeded = true;
                    entries.insert(entries.end(), queueResults.value().begin(),
                                   queueResults.value().end());
                }
            }
            consecutiveFailures =
                anyReadSucceeded ? 0 : (consecutiveFailures + 1);

            if (!entries.empty())
            {
                processBootProgressData(socketId, entries);
            }
            co_await sdbusplus::async::sleep_for(ctx, calculateSleepDuration());
        }
        else
        {
            co_await sdbusplus::async::sleep_for(ctx, pollInterval);
        }
    }
    co_return;
}

void BootProgressPoller::updatePollInterval(
    std::chrono::milliseconds newInterval)
{
    if (pollInterval != newInterval)
    {
        lg2::debug(
            "Polling interval changed for socket {SOCKET_ID}: {OLD}ms -> {NEW}ms",
            "SOCKET_ID", socketId, "OLD", pollInterval.count(), "NEW",
            newInterval.count());
    }
    pollInterval = newInterval;
}

void BootProgressPoller::updatePollStatus(bool newPollStatus)
{
    pollStatus = newPollStatus;
    consecutiveFailures = 0;
}

bool BootProgressPoller::isPolling() const
{
    return pollStatus;
}

std::chrono::milliseconds BootProgressPoller::calculateSleepDuration() const
{
    constexpr int backoffThreshold = 10;
    if (consecutiveFailures >= backoffThreshold)
    {
        // When device is not present, use exponential backoff with seconds as
        // base Exponential backoff: baseSeconds * 2^(failures - threshold)
        // (capped)
        constexpr int baseSeconds = 2;
        constexpr int maxBackoffMultiplier = 10;
        int backoffFailures = consecutiveFailures - backoffThreshold;
        int multiplier = 1 << std::min(backoffFailures, maxBackoffMultiplier);
        int sleepSeconds = baseSeconds * multiplier;
        return std::chrono::milliseconds(sleepSeconds * 1000);
    }
    return pollInterval;
}
