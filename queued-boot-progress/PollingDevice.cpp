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

PollingDeviceEnumerator::PollingDeviceEnumerator(
    sdbusplus::async::context& ctx, OnDeviceAddedCallback onAdded,
    OnDeviceRemovedCallback onRemoved) :
    ctx(ctx), onDeviceAdded(std::move(onAdded)),
    onDeviceRemoved(std::move(onRemoved))
{}

void PollingDeviceEnumerator::notifyDeviceAdded(
    std::shared_ptr<PollingDevice> device, TransportInterface transport,
    uint8_t bus, uint8_t address)
{
    if (onDeviceAdded)
    {
        onDeviceAdded(std::move(device), transport, bus, address);
    }
}

void PollingDeviceEnumerator::notifyDeviceRemoved(TransportInterface transport,
                                                  uint8_t bus, uint8_t address)
{
    if (onDeviceRemoved)
    {
        onDeviceRemoved(transport, bus, address);
    }
}
