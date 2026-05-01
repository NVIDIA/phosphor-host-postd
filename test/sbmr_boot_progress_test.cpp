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

#include <sys/stat.h>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <cstdio>

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
    Json targetData = testReporter.parseJSONConfig(filePaths);
    EXPECT_EQ(targetData.is_discarded(), true);
}

TEST_F(SbmrBootProgressTestReporter, ParseEmptyObject)
{
    SbmrBootProgress testReporter;
    const char* path = "/tmp/sbmrBootProgress_empty.json";
    std::FILE* f = fopen(path, "w");
    ASSERT_NE(f, nullptr);
    std::fputs("{}", f);
    std::fclose(f);

    Json targetData = testReporter.parseJSONConfig(path);
    EXPECT_FALSE(targetData.is_discarded());
    EXPECT_TRUE(targetData.is_object());
    EXPECT_TRUE(targetData.empty());
}

TEST_F(SbmrBootProgressTestReporter, ParseSingleKeyObject)
{
    SbmrBootProgress testReporter;
    const char* path = "/tmp/sbmrBootProgress_single.json";
    std::FILE* f = fopen(path, "w");
    ASSERT_NE(f, nullptr);
    std::fputs(R"({"0x01000000000007c0":"0x01000000000007c0"})", f);
    std::fclose(f);

    Json targetData = testReporter.parseJSONConfig(path);
    EXPECT_FALSE(targetData.is_discarded());
    EXPECT_NE(targetData.find("0x01000000000007c0"), targetData.end());
    EXPECT_EQ(targetData["0x01000000000007c0"], "0x01000000000007c0");
}

TEST_F(SbmrBootProgressTestReporter, ParseNonExistentFileReturnsDiscarded)
{
    SbmrBootProgress testReporter;
    Json targetData =
        testReporter.parseJSONConfig("/nonexistent/sbmrBootProgress.json");
    EXPECT_TRUE(targetData.is_discarded());
}

// updateBootProgressProperties: empty primary code vector returns early
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_EmptyRecord_ReturnsEarly)
{
    SbmrBootProgress sbmr;
    PrimaryCode_t emptyCode;
    BootProgress_t bp(emptyCode, {});
    sbmr.updateBootProgressProperties(bp, 1000);
}

// updateBootProgressProperties: wrong-size record (8 bytes, not 9) returns
// early
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_WrongSize_ReturnsEarly)
{
    SbmrBootProgress sbmr;
    PrimaryCode_t code8 = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    BootProgress_t bp(code8, {});
    sbmr.updateBootProgressProperties(bp, 1000);
}

// updateBootProgressProperties: valid record, OEM stage, non-zero tsUS
// Exercises hex-string building, map lookup (not found), D-Bus calls
// (fail/caught)
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_OemStage_NonZeroTimestamp)
{
    SbmrBootProgress sbmr;
    // byte[0]=0x04: unknown code type, not in sbmrBootProgressStages → OEM
    PrimaryCode_t code = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 1000);
}

// updateBootProgressProperties: valid record, OEM stage, tsUS==0 →
// auto-generate
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_OemStage_ZeroTimestamp_GeneratesTs)
{
    SbmrBootProgress sbmr;
    PrimaryCode_t code = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 0);
}

// updateBootProgressProperties: record maps to PCIInit in
// sbmrBootProgressStages Key "0x010000000110010200" → bytes: 0x01 0x00 0x00
// 0x00 0x01 0x10 0x01 0x02 0x00
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_MappedStage_PCIInit)
{
    SbmrBootProgress sbmr;
    PrimaryCode_t code = {0x01, 0x00, 0x00, 0x00, 0x01, 0x10, 0x01, 0x02, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 1000);
}

// updateBootProgressProperties: record maps to PrimaryProcInit
// Key "0x01000000050001c100" → bytes: 0x01 0x00 0x00 0x00 0x05 0x00 0x01 0xc1
// 0x00
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_MappedStage_PrimaryProcInit)
{
    SbmrBootProgress sbmr;
    PrimaryCode_t code = {0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0xc1, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 500);
}

// updateBootProgressProperties: record maps to OSRunning
// Key "0x010000001910100300" → bytes: 0x01 0x00 0x00 0x00 0x19 0x10 0x10 0x03
// 0x00
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_MappedStage_OSRunning)
{
    SbmrBootProgress sbmr;
    PrimaryCode_t code = {0x01, 0x00, 0x00, 0x00, 0x19, 0x10, 0x10, 0x03, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 750);
}

// updateBootProgressProperties: mapped stage with tsUS==0 (generates timestamp
// + logEvent, but errorLog discarded so logging block skipped)
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_MappedStage_ZeroTimestamp)
{
    SbmrBootProgress sbmr;
    PrimaryCode_t code = {0x01, 0x00, 0x00, 0x00, 0x01, 0x10, 0x01, 0x02, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 0);
}

// updateBootProgressProperties: SecondaryProcInit
// Key "0x01000000060001c100" → bytes: 0x01 0x00 0x00 0x00 0x06 0x00 0x01 0xc1
// 0x00
TEST_F(SbmrBootProgressTestReporter,
       UpdateBootProgressProperties_MappedStage_SecondaryProcInit)
{
    SbmrBootProgress sbmr;
    PrimaryCode_t code = {0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0xc1, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 1000);
}

// Fixture that writes a minimal valid JSON to the hardcoded sbmr path.
// Tests are skipped in environments where the path is not writable.
class SbmrBootProgressWithErrorLogTest : public ::testing::Test
{
  protected:
    static constexpr const char* sbmrDir = "/usr/share/sbmrbootprogress";
    static constexpr const char* sbmrJsonPath =
        "/usr/share/sbmrbootprogress/sbmr_boot_progress_code.json";

    void SetUp() override
    {
        ::mkdir(sbmrDir, 0755);
        FILE* f = fopen(sbmrJsonPath, "w");
        if (!f)
        {
            GTEST_SKIP() << "Cannot write to " << sbmrJsonPath
                         << " (needs root)";
        }
        std::fputs(R"({"0x02000000000007c0":"EFI_NV_HW_CPU_EC_INIT_FAILED"})",
                   f);
        std::fclose(f);
        jsonWritten_ = true;
    }

    void TearDown() override
    {
        if (jsonWritten_)
        {
            std::remove(sbmrJsonPath);
        }
    }

    bool jsonWritten_ = false;
    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus::bus bus{sdbusplus::get_mocked_new(&bus_mock)};
};

// bootErrorCode with valid errorLog and tsUS==0 → enters errorLog block,
// looks up key, finds message, attempts D-Bus log call (fail/caught)
TEST_F(SbmrBootProgressWithErrorLogTest,
       UpdateBootProgressProperties_BootErrorCode_ErrorSeverity)
{
    SbmrBootProgress sbmr;
    // byte[0]=0x02 (bootErrorCode), byte[3]=0x00 (not errorMinor),
    // byte[6]=0x07, byte[7]=0xc0 → key "0x02000000000007c0" in JSON
    PrimaryCode_t code = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xc0, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 0); // tsUS==0 → logEvent=1
}

// bootErrorCode with errorMinor severity → warnSeverity path
TEST_F(SbmrBootProgressWithErrorLogTest,
       UpdateBootProgressProperties_BootErrorCode_WarnSeverity)
{
    SbmrBootProgress sbmr;
    // byte[3]=0x40 (errorMinor) → replace(8,2,"00") zeroes byte[3] in key
    // so key is still "0x02000000000007c0"
    PrimaryCode_t code = {0x02, 0x00, 0x00, 0x40, 0x00, 0x00, 0x07, 0xc0, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 0);
}

// bootProgressCode (0x01) path with valid errorLog → enters bootProgressCode
// branch, no special pattern → falls through without setting ResetToDefault
TEST_F(SbmrBootProgressWithErrorLogTest,
       UpdateBootProgressProperties_BootProgressCode_NoSpecialPattern)
{
    SbmrBootProgress sbmr;
    // byte[0]=0x01 (bootProgressCode), no matching ConfigReset or
    // ValidateBootChain pattern
    PrimaryCode_t code = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 0);
}

// ConfigReset sets ResetToDefault; subsequent BinLoadFailed returns early
TEST_F(SbmrBootProgressWithErrorLogTest,
       UpdateBootProgressProperties_ConfigReset_ThenBinLoadFailed_ReturnsEarly)
{
    SbmrBootProgress sbmr;
    // First call: ConfigReset → sets ResetToDefault=true
    // byte[4]=opByte1ConfigReset(0x08), byte[5]=opByte2BootSerice(0x10),
    // byte[6]=subClassSpecific(0x10), byte[7]=classSoftware(0x03)
    PrimaryCode_t configReset = {0x01, 0x00, 0x00, 0x00, 0x08,
                                 0x10, 0x10, 0x03, 0x00};
    sbmr.updateBootProgressProperties(BootProgress_t(configReset, {}), 0);

    // Second call: BinLoadFailed with ResetToDefault=true → early return
    // byte[0]=0x02 (bootErrorCode), byte[4]=opByte1BinLoadFailed(0x01),
    // byte[5]=opByte2BinLoadFailed(0x00), byte[6]=subClassNvFwBoot(0x01),
    // byte[7]=classNvFw(0xc1)
    PrimaryCode_t binLoad = {0x02, 0x00, 0x00, 0x00, 0x01,
                             0x00, 0x01, 0xc1, 0x00};
    sbmr.updateBootProgressProperties(BootProgress_t(binLoad, {}), 0);
}

// NvFwBoot subclass with non-zero byte[5] → covers the nvFwBootJsonKey path
TEST_F(SbmrBootProgressWithErrorLogTest,
       UpdateBootProgressProperties_NvFwBoot_NonZeroByte5)
{
    SbmrBootProgress sbmr;
    // byte[0]=0x02, byte[6]=subClassNvFwBoot(0x01), byte[7]=classNvFw(0xc1),
    // byte[5]=0x8f (non-zero) → uses nvFwBootJsonKey|byte[5] path
    PrimaryCode_t code = {0x02, 0x00, 0x00, 0x00, 0x00, 0x8f, 0x01, 0xc1, 0x00};
    BootProgress_t bp(code, {});
    sbmr.updateBootProgressProperties(bp, 0);
}

} // namespace
