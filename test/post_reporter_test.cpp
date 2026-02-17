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
#include "lpcsnoop/snoop.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::IsNull;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrEq;

namespace
{

class PostReporterTest : public ::testing::Test
{
  protected:
    PostReporterTest() : bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock))
    {}

    ~PostReporterTest() {}

    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus;
};

TEST_F(PostReporterTest, EmitsObjectsOnExpectedDbusPath)
{
    EXPECT_CALL(bus_mock,
                sd_bus_emit_object_added(IsNull(), StrEq(snoopObject)))
        .WillOnce(Return(0));

    PostReporter testReporter(bus, snoopObject, true);
    testReporter.emit_object_added();
}

TEST_F(PostReporterTest, AddsObjectWithExpectedName)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xdefa);
        return 0;
    };

    EXPECT_CALL(bus_mock,
                sd_bus_add_object_vtable(IsNull(), _, StrEq(snoopObject),
                                         StrEq(snoopDbus), _, _))
        .WillOnce(slotcb);

    PostReporter testReporter(bus, snoopObject, true);
}

TEST_F(PostReporterTest, ValueReadsDefaultToEmpty)
{
    PostReporter testReporter(bus, snoopObject, true);
    EXPECT_TRUE(std::get<0>(testReporter.value()).empty());
}

TEST_F(PostReporterTest, SetValueToPositiveValueWorks)
{
    PostReporter testReporter(bus, snoopObject, true);
    primary_post_code_t primaryCode = {122, 126, 127};
    secondary_post_code_t secondaryCode = {123, 124, 125};
    testReporter.value(std::make_tuple(primaryCode, secondaryCode));
    EXPECT_EQ(primaryCode, std::get<0>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<1>(testReporter.value()));
}

TEST_F(PostReporterTest, SetValueMultipleTimesWorks)
{
    PostReporter testReporter(bus, snoopObject, true);
    primary_post_code_t primaryCode = {20, 21, 0, 123};
    secondary_post_code_t secondaryCode = {10, 40, 0, 245, 56};
    testReporter.value(std::make_tuple(primaryCode, secondaryCode));
    EXPECT_EQ(primaryCode, std::get<0>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<1>(testReporter.value()));

    primaryCode = {44, 45};
    secondaryCode = {0, 0, 0, 0, 0};
    testReporter.value(std::make_tuple(primaryCode, secondaryCode));
    EXPECT_EQ(primaryCode, std::get<0>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<1>(testReporter.value()));

    primaryCode = {0};
    secondaryCode = {23, 200, 0, 45, 2};
    testReporter.value(std::make_tuple(primaryCode, secondaryCode));
    EXPECT_EQ(primaryCode, std::get<0>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<1>(testReporter.value()));

    primaryCode = {46};
    secondaryCode = {10, 40, 0, 35, 78};
    testReporter.value(std::make_tuple(primaryCode, secondaryCode));
    EXPECT_EQ(primaryCode, std::get<0>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<1>(testReporter.value()));

    primaryCode = {46};
    secondaryCode = {10, 40, 0, 35, 78};
    testReporter.value(std::make_tuple(primaryCode, secondaryCode));
    EXPECT_EQ(primaryCode, std::get<0>(testReporter.value()));
    EXPECT_EQ(secondaryCode, std::get<1>(testReporter.value()));
}

TEST_F(PostReporterTest, ConstructorWithDeferFalseEmitsObjectAdded)
{
    EXPECT_CALL(bus_mock,
                sd_bus_emit_object_added(IsNull(), StrEq(snoopObject)))
        .WillOnce(Return(0));

    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xdefa);
        return 0;
    };
    EXPECT_CALL(bus_mock,
                sd_bus_add_object_vtable(IsNull(), _, StrEq(snoopObject),
                                         StrEq(snoopDbus), _, _))
        .WillOnce(slotcb);

    PostReporter testReporter(bus, snoopObject, false);
    (void)testReporter;
}

TEST_F(PostReporterTest, RateLimitMemberDefaultAndSet)
{
    PostReporter testReporter(bus, snoopObject, true);
    EXPECT_EQ(testReporter.rateLimit, 0u);
    testReporter.rateLimit = 100u;
    EXPECT_EQ(testReporter.rateLimit, 100u);
}

TEST_F(PostReporterTest, ValueWithEmptySecondary)
{
    PostReporter testReporter(bus, snoopObject, true);
    primary_post_code_t primaryCode = {0xAA};
    secondary_post_code_t secondaryCode = {};
    testReporter.value(std::make_tuple(primaryCode, secondaryCode));
    EXPECT_EQ(std::get<0>(testReporter.value()), primaryCode);
    EXPECT_TRUE(std::get<1>(testReporter.value()).empty());
}

} // namespace
