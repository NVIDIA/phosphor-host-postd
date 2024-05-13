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
#include "sbmrbootprogress/sbmr_boot_progress.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrEq;
using RawInterfaceTest =
    sdbusplus::xyz::openbmc_project::State::Boot::server::Raw;

namespace
{

// Fixture for testing class SbmrBootProgressTestReporter
class SbmrBootProgressTestReporter : public ::testing::Test
{
  protected:
    SbmrBootProgressTestReporter() :
        bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock))
    {}

    ~SbmrBootProgressTestReporter() {}

    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus::bus bus;
};

TEST_F(SbmrBootProgressTestReporter, testJson)
{
    SbmrBootProgress testReporter;
    auto defaultData1 = R"(
        {
            "0x01000000000007c0":"0x01000000000007c0",
            "0x01000000050000c1":"0x01000000050000c1",
            "0x03000000000000c1":"0x03000000000000c1"
        }
    )"_json;

    std::FILE* tmpf = fopen("/tmp/sbmrBootProgress.json", "w");
    std::fputs(defaultData1.dump().c_str(), tmpf);
    std::fclose(tmpf);

    auto filePaths = "/tmp/sbmrBootProgress.json";

    Json targetData = testReporter.parseJSONConfig(filePaths);

    EXPECT_NE(targetData.find("0x01000000000007c0"), targetData.end());
    EXPECT_NE(targetData.find("0x01000000050000c1"), targetData.end());
    EXPECT_NE(targetData.find("0x03000000000000c1"), targetData.end());
    EXPECT_EQ(targetData.find("0x02030000000000a1"), targetData.end());
}

TEST_F(SbmrBootProgressTestReporter, InvalidErrorToMonitor1)
{
    SbmrBootProgress testReporter;

    std::FILE* tmpf = fopen("/tmp/sbmrBootProgress.json", "w");
    std::fputs("{\"0x02030000000000a1\":\"0x02030000000000c1\"", tmpf);
    std::fputs("\"0x02030000000045a1\":\"0x02030000000045c1\"", tmpf);
    std::fclose(tmpf);

    auto filePaths = "/tmp/sbmrBootProgress.json";
    // Verify exception thrown on invalid errorsToMonitor
    Json targetData = testReporter.parseJSONConfig(filePaths);
    EXPECT_EQ(targetData.is_discarded(), true);
}

} // namespace
