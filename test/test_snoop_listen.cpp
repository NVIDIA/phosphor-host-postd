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
#include "lpcsnoop/snoop_listen.hpp"

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

class SnoopListenTest : public ::testing::Test
{
  protected:
    SnoopListenTest() : bus_mock(), bus(sdbusplus::get_mocked_new(&bus_mock)) {}

    NiceMock<sdbusplus::SdBusMock> bus_mock;
    sdbusplus::bus_t bus;
};

TEST_F(SnoopListenTest, ConstructWithMessageHandlerRegistersMatch)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_match(IsNull(), _, _, _, _))
        .WillOnce(slotcb);

    lpcsnoop::SnoopListen listen(bus, [](sdbusplus::message_t&) {});
    (void)listen;
}

TEST_F(SnoopListenTest, ConstructWithRawSdBusMessageHandler)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_match(IsNull(), _, _, _, _))
        .WillOnce(slotcb);

    auto rawHandler = [](sd_bus_message*, void*, sd_bus_error*) { return 0; };
    lpcsnoop::SnoopListen listen(bus, rawHandler);
    (void)listen;
}

TEST_F(SnoopListenTest, MatchRuleContainsSnoopObjectPath)
{
    std::string capturedRule;
    auto slotcb = [&capturedRule](sd_bus*, sd_bus_slot** slot, const char* rule,
                                  auto&&...) {
        if (rule)
            capturedRule = rule;
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_match(IsNull(), _, _, _, _))
        .WillOnce(slotcb);

    lpcsnoop::SnoopListen listen(bus, [](sdbusplus::message_t&) {});
    (void)listen;

    EXPECT_THAT(capturedRule, ::testing::HasSubstr(snoopObject));
    EXPECT_THAT(capturedRule, ::testing::HasSubstr("PropertiesChanged"));
    EXPECT_THAT(capturedRule,
                ::testing::HasSubstr("org.freedesktop.DBus.Properties"));
}

TEST_F(SnoopListenTest, ConstructWithPostcodeHandler)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_match(IsNull(), _, _, _, _))
        .WillOnce(slotcb);

    lpcsnoop::SnoopListen listen(bus, [](FILE*, postcode_t) {}, nullptr);
    (void)listen;
}

TEST_F(SnoopListenTest, MoveConstructor)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_match(IsNull(), _, _, _, _))
        .WillOnce(slotcb);

    lpcsnoop::SnoopListen listen(bus, [](sdbusplus::message_t&) {});
    lpcsnoop::SnoopListen listen2(std::move(listen));
    (void)listen2;
}

TEST_F(SnoopListenTest, MoveAssignment)
{
    auto slotcb = [](sd_bus*, sd_bus_slot** slot, auto&&...) {
        *slot = reinterpret_cast<sd_bus_slot*>(0xbeef);
        return 0;
    };
    EXPECT_CALL(bus_mock, sd_bus_add_match(IsNull(), _, _, _, _))
        .WillRepeatedly(slotcb);

    lpcsnoop::SnoopListen listen(bus, [](sdbusplus::message_t&) {});
    lpcsnoop::SnoopListen listen2(bus, [](sdbusplus::message_t&) {});
    listen2 = std::move(listen);
}

} // namespace
