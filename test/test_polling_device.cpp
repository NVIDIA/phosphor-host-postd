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
#include "queued-boot-progress/BootProgressManager.hpp"
#include "queued-boot-progress/BootProgressPoller.hpp"
#include "queued-boot-progress/BootProgressPublisher.hpp"
#include "queued-boot-progress/I2CPollingDevice.hpp"
#include "queued-boot-progress/PollingDevice.hpp"

#include <chrono>
#include <memory>

#include <gtest/gtest.h>

namespace
{

TEST(PollingDevice, SocketDataDefaultConstruct)
{
    SocketData sd;
    EXPECT_EQ(sd.poller, nullptr);
    EXPECT_TRUE(sd.buffer.empty());
}

TEST(PollingDevice, SocketDataConstructWithPoller)
{
    DeviceIdentity identity{TransportInterface::I2C, 0, 0x50};
    std::shared_ptr<BootProgressPoller> nullPoller = nullptr;
    SocketData sd(identity, nullPoller, nullptr);
    EXPECT_EQ(sd.poller, nullptr);
    EXPECT_TRUE(sd.buffer.empty());
}

TEST(PollingDevice, I2CDeviceListType)
{
    I2CDeviceList list = {{0, 0x50}, {1, 0x51}};
    EXPECT_EQ(list.size(), 2u);
    EXPECT_EQ(list[0].first, 0);
    EXPECT_EQ(list[0].second, 0x50);
}

} // namespace
