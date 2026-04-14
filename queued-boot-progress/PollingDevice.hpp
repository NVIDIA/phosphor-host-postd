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

#include <sdbusplus/async.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

enum class TransportInterface
{
    I2C,
    USB
};

struct PairHash
{
    std::size_t operator()(const std::pair<uint8_t, uint8_t>& p) const noexcept
    {
        return static_cast<std::size_t>(p.first) << 8 |
               static_cast<std::size_t>(p.second);
    }
};

class PollingDevice
{
  public:
    virtual ~PollingDevice() = default;

    virtual bool readRegisterValue(uint32_t regAddr, uint32_t& regValue) = 0;

    /** Trigger an L1 SW main reset of the CPU.
     *  Writes 0x00000001 to the sw_main_rst register (PMC_IMPL_SW_MAIN_RST_0)
     *  via the transport-specific protocol.  Returns true on success.
     *  Default implementation returns false (not supported). */
    virtual bool doL1Reset()
    {
        return false;
    }

    /** Returns false once the underlying transport handle has been closed
     *  (e.g. after invalidate() or device removal). */
    virtual bool isOpen() const
    {
        return true;
    }

    /** Close the transport handle immediately without waiting for the OS
     *  removal event.  Safe to call more than once. */
    virtual void invalidate() {}

  protected:
    bool deviceHealthy = true;
};

using OnDeviceAddedCallback = std::function<void(
    std::shared_ptr<PollingDevice>, TransportInterface, uint8_t, uint8_t)>;
using OnDeviceRemovedCallback =
    std::function<void(TransportInterface, uint8_t, uint8_t)>;

class PollingDeviceEnumerator
{
  public:
    virtual ~PollingDeviceEnumerator() = default;
    virtual sdbusplus::async::task<void> run() = 0;

  protected:
    PollingDeviceEnumerator(sdbusplus::async::context& ctx,
                            OnDeviceAddedCallback onAdded,
                            OnDeviceRemovedCallback onRemoved);

    void notifyDeviceAdded(std::shared_ptr<PollingDevice> device,
                           TransportInterface transport, uint8_t bus,
                           uint8_t address);
    void notifyDeviceRemoved(TransportInterface transport, uint8_t bus,
                             uint8_t address);

    sdbusplus::async::context& ctx;
    OnDeviceAddedCallback onDeviceAdded;
    OnDeviceRemovedCallback onDeviceRemoved;
};
