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

#include "BootProgressManager.hpp"

#include <com/nvidia/L1Reset/aserver.hpp>
#include <sdbusplus/async.hpp>

#include <memory>

/**
 * Implements the com.nvidia.L1Reset D-Bus interface at
 * /xyz/openbmc_project/state/host0 under the
 * xyz.openbmc_project.State.Host well-known service name.
 *
 * When Reset() is called, boot-progress polling is suspended, the
 * L1 SW main reset is issued over the active transport (USB or I2C),
 * and polling is resumed.  Throws Common::Error::Unavailable when
 * no polling device is available, or Common::Error::InternalFailure
 * when the reset attempt fails.
 */
class L1ResetHandler :
    public sdbusplus::aserver::com::nvidia::L1Reset<L1ResetHandler>
{
  public:
    using Base = sdbusplus::aserver::com::nvidia::L1Reset<L1ResetHandler>;

    L1ResetHandler(sdbusplus::async::context& ctx, const char* path,
                   std::shared_ptr<BootProgressManager> mgr);

    /** Called by the generated aserver vtable when Reset() is invoked. */
    sdbusplus::async::task<> method_call(reset_t);

  private:
    std::shared_ptr<BootProgressManager> mgr_;
};
