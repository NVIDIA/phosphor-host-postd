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
    {
    }

    ~SbmrBootProgressTestReporter()
    {
    }

    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus::bus bus;
};

TEST_F(SbmrBootProgressTestReporter, EmitsObjectsOnExpectedDbusPath)
{

    EXPECT_CALL(bus_mock, sd_bus_emit_object_added(
                              IsNull(), StrEq(sbmrBootProgressService)))
        .WillOnce(Return(0));

    SbmrBootProgress testReporter(bus, sbmrBootProgressService);
    testReporter.emit_object_added();
}

TEST_F(SbmrBootProgressTestReporter, ValueReadsDefaultToZero)
{
    SbmrBootProgress testReporter(bus, sbmrBootProgressService);
    EXPECT_EQ(0, std::get<PrimaryCode_t>(testReporter.value()));
}

TEST_F(SbmrBootProgressTestReporter, SetValueToPositiveValueWorks)
{
    SbmrBootProgress testReporter(bus, sbmrBootProgressService);
    SecondaryCode_t secondaryCode = {123, 124, 125};
    testReporter.value(std::make_tuple(65537, secondaryCode));
    EXPECT_EQ(65537, std::get<PrimaryCode_t>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<SecondaryCode_t>(testReporter.value()));
}

TEST_F(SbmrBootProgressTestReporter, SetValueMultipleTimesWorks)
{
    SbmrBootProgress testReporter(bus, sbmrBootProgressService);
    SecondaryCode_t secondaryCode = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    testReporter.value(std::make_tuple(65537, secondaryCode));
    EXPECT_EQ(65537, std::get<PrimaryCode_t>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<SecondaryCode_t>(testReporter.value()));

    secondaryCode = {0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x2, 0x3, 0x1};
    testReporter.value(std::make_tuple(2432, secondaryCode));
    EXPECT_EQ(2432, std::get<PrimaryCode_t>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<SecondaryCode_t>(testReporter.value()));

    secondaryCode = {0x2, 0x0, 0x0, 0x90, 0x6, 0x5, 0x2, 0x3, 0x0};
    testReporter.value(std::make_tuple(20012, secondaryCode));
    EXPECT_EQ(20012, std::get<PrimaryCode_t>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<SecondaryCode_t>(testReporter.value()));
}

TEST_F(SbmrBootProgressTestReporter, testJson)
{
    SbmrBootProgress testReporter(bus, sbmrBootProgressService);
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
    SbmrBootProgress testReporter(bus, sbmrBootProgressService);

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
