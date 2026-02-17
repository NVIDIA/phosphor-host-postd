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
#include "queued-boot-progress/BootProgressTypes.hpp"

#include <gtest/gtest.h>

namespace
{

TEST(BootProgressTypes, CallbackTypeIsInvokable)
{
    int callCount = 0;
    onBootProgressDataCallback cb =
        [&callCount](int socketId, std::vector<std::pair<uint32_t, uint32_t>>) {
            callCount++;
            EXPECT_EQ(socketId, 42);
        };
    std::vector<std::pair<uint32_t, uint32_t>> data = {{1000u, 0x01u}};
    cb(42, data);
    EXPECT_EQ(callCount, 1);
}

TEST(BootProgressTypes, CallbackAcceptsEmptyData)
{
    int callCount = 0;
    onBootProgressDataCallback cb =
        [&callCount](int, std::vector<std::pair<uint32_t, uint32_t>> v) {
            callCount++;
            EXPECT_TRUE(v.empty());
        };
    cb(0, {});
    EXPECT_EQ(callCount, 1);
}

TEST(BootProgressTypes, CallbackAcceptsMultiplePairs)
{
    std::vector<std::pair<uint32_t, uint32_t>> received;
    onBootProgressDataCallback cb =
        [&received](int, std::vector<std::pair<uint32_t, uint32_t>> v) {
            received = std::move(v);
        };
    std::vector<std::pair<uint32_t, uint32_t>> data = {{1000u, 0x01u},
                                                       {2000u, 0x02u}};
    cb(0, data);
    ASSERT_EQ(received.size(), 2u);
    EXPECT_EQ(received[0].first, 1000u);
    EXPECT_EQ(received[0].second, 0x01u);
    EXPECT_EQ(received[1].first, 2000u);
    EXPECT_EQ(received[1].second, 0x02u);
}

} // namespace
