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

#include "queued-boot-progress/dbus_utils.hpp"

/** No-op IDbusPropertyAccess for tests that construct BootProgressPublisher
 *  but don't need real D-Bus property writes. */
struct NullPropertyAccess : IDbusPropertyAccess
{
    sdbusplus::async::task<std::string> getProperty(
        const char*, const char*, const char*, const char*) override
    {
        co_return std::string{};
    }
    sdbusplus::async::task<PropertiesChangedTuple> waitForPropertiesChanged(
        const std::string&, const std::string&) override
    {
        co_return PropertiesChangedTuple{};
    }
    sdbusplus::async::task<void> setProperty(const char*, const char*,
                                             const char*, const char*,
                                             const std::string&) override
    {
        co_return;
    }
    sdbusplus::async::task<void> setProperty(
        const char*, const char*, const char*, const char*, uint64_t) override
    {
        co_return;
    }
};

/** IDbusPropertyAccess that throws on every setProperty call.
 *  Use to exercise the catch branches in updateBootProgress* methods. */
struct ThrowingPropertyAccess : IDbusPropertyAccess
{
    sdbusplus::async::task<std::string> getProperty(
        const char*, const char*, const char*, const char*) override
    {
        co_return std::string{};
    }
    sdbusplus::async::task<PropertiesChangedTuple> waitForPropertiesChanged(
        const std::string&, const std::string&) override
    {
        co_return PropertiesChangedTuple{};
    }
    sdbusplus::async::task<void> setProperty(const char*, const char*,
                                             const char*, const char*,
                                             const std::string&) override
    {
        throw std::runtime_error("test D-Bus write error");
        co_return;
    }
    sdbusplus::async::task<void> setProperty(
        const char*, const char*, const char*, const char*, uint64_t) override
    {
        throw std::runtime_error("test D-Bus write error");
        co_return;
    }
};
