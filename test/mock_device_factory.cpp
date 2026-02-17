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
#include "mock_device_factory.hpp"

#include "queued-boot-progress/BootProgressManager.hpp"
#include "queued-boot-progress/PollingDevice.hpp"

#include <sdbusplus/async.hpp>

#include <chrono>
#include <memory>

namespace
{
std::shared_ptr<PollingDevice> g_injected;
}

void setInjectedPollingDevice(std::shared_ptr<PollingDevice> device)
{
    g_injected = std::move(device);
}

std::shared_ptr<PollingDevice> getPollingDevice(TransportInterface,
                                                const uint8_t&, const uint8_t&)
{
    return g_injected;
}

std::shared_ptr<PollingDeviceEnumerator> getPollingDeviceEnumerator(
    sdbusplus::async::context&, std::shared_ptr<BootProgressManager>,
    TransportInterface, uint16_t, uint16_t, std::chrono::seconds)
{
    return nullptr;
}
