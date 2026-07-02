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

#include "BootProgressApplication.hpp"
#include "BootProgressManager.hpp"
#include "CakBootProgressPublisher.hpp"
#include "ConfigReader.hpp"
#include "I2CPollingDevice.hpp"
#include "PollingDevice.hpp"
#include "USBPollingDevice.hpp"
#include "dbus_utils.hpp"
#include "lpcsnoop/snoop.hpp"
#ifdef ENABLE_L1RESET
#include "L1ResetHandler.hpp"
#endif

#include <phosphor-logging/lg2.hpp>

int main(int argc, char* argv[])
{
    sdbusplus::async::context ctx;
    Configuration config;
    if (!ConfigReader::readConfig(argc, argv, config))
    {
        lg2::error("Failed to read configuration");
        return EXIT_FAILURE;
    }

    std::shared_ptr<CakBootProgressPublisher> cakPublisher = nullptr;
    if (config.cakCpuCount)
    {
        cakPublisher =
            std::make_shared<CakBootProgressPublisher>(ctx, config.cakCpuCount);
    }

    auto dbusAccess = std::make_shared<DbusPropertyAccess>(ctx);
    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject), dbusAccess,
        cakPublisher);
    auto bootProgressManager = std::make_shared<BootProgressManager>(
        ctx, publisher, config.pollInterval);

    std::shared_ptr<PollingDeviceEnumerator> deviceEnumerator = nullptr;
    if (config.transportInterface == TransportInterface::I2C)
    {
        initializeI2CDevices(bootProgressManager, config.i2cInterfaceConfigMap);
    }
    else
    {
        // USB needs enumerator for hotplug support
        deviceEnumerator = std::make_shared<USBDeviceEnumerator>(
            ctx, bootProgressManager, config.usbVendorId, config.usbProductId,
            config.usbRescanInterval);
        if (!deviceEnumerator)
        {
            lg2::error("Failed to create USB device enumerator");
            return EXIT_FAILURE;
        }
    }

    if (deviceEnumerator)
    {
        ctx.spawn(deviceEnumerator->run());
    }

#ifdef ENABLE_L1RESET
    // Register the com.nvidia.L1Reset D-Bus interface under snoopd's own
    // service name (xyz.openbmc_project.State.Boot.Raw) so we do not
    // conflict with phosphor-host-state-manager's ownership of
    // xyz.openbmc_project.State.Host.
    lg2::info("L1Reset: registering com.nvidia.L1Reset interface");
    auto l1ResetHandler = std::make_shared<L1ResetHandler>(
        ctx, "/xyz/openbmc_project/state/host0", bootProgressManager);
    lg2::info("L1Reset: D-Bus interface registered");
#endif

    Application application(ctx, config, bootProgressManager, dbusAccess);

    ctx.spawn(application.initialize());

    ctx.run();

    return EXIT_SUCCESS;
}
