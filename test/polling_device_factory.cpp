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
#include "polling_device_factory.hpp"

#include "queued-boot-progress/BootProgressManager.hpp"
#include "queued-boot-progress/I2CPollingDevice.hpp"
#include "queued-boot-progress/USBPollingDevice.hpp"

#include <chrono>

std::shared_ptr<PollingDevice> getPollingDevice(TransportInterface transport,
                                                uint8_t bus, uint8_t address)
{
    switch (transport)
    {
        case TransportInterface::I2C:
            return std::make_shared<I2CPollingDevice>(bus, address);
        case TransportInterface::USB:
            return std::make_shared<USBPollingDevice>(nullptr, bus, address);
        default:
            return nullptr;
    }
}

std::shared_ptr<PollingDeviceEnumerator> getPollingDeviceEnumerator(
    sdbusplus::async::context& ctx, std::shared_ptr<BootProgressManager> mgr,
    TransportInterface transport, uint16_t vendorId, uint16_t productId,
    std::chrono::seconds rescanInterval)
{
    switch (transport)
    {
        case TransportInterface::I2C:
            return nullptr;
        case TransportInterface::USB:
            return std::make_shared<USBDeviceEnumerator>(
                ctx, std::move(mgr), vendorId, productId, rescanInterval);
        default:
            return nullptr;
    }
}
