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
#include "lpcsnoop/snoop.hpp"

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

    auto publisher = std::make_shared<BootProgressPublisher>(
        ctx, std::string(snoopDbus), std::string(snoopObject), cakPublisher);
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

    Application application(ctx, config, bootProgressManager);
    ctx.spawn(application.initialize());

    ctx.run();

    return EXIT_SUCCESS;
}
