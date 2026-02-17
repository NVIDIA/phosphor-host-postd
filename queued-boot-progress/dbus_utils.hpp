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

#include <sdbusplus/async.hpp>

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

using PropertiesChangedTuple = std::tuple<
    std::string,
    std::map<std::string, std::variant<std::string, int32_t, uint32_t, bool>>,
    std::vector<std::string>>;

sdbusplus::async::task<std::string> getDbusProperty(
    sdbusplus::async::context& ctx, const char* service, const char* path,
    const char* interface, const char* property);

sdbusplus::async::task<PropertiesChangedTuple> waitForDbusPropertiesChanged(
    sdbusplus::async::context& ctx, const std::string& path,
    const std::string& interface);

/** Set a property on a D-Bus object. */
template <typename T>
inline sdbusplus::async::task<void> setDbusProperty(
    sdbusplus::async::context& ctx, const char* service, const char* path,
    const char* interface, const char* property, const T& value)
{
    auto proxy =
        sdbusplus::async::proxy().service(service).path(path).interface(
            interface);
    co_await proxy.set_property(ctx, property, value);
}

struct IDbusPropertyAccess
{
    virtual sdbusplus::async::task<std::string> getProperty(
        const char* service, const char* path, const char* interface,
        const char* property) = 0;
    virtual sdbusplus::async::task<PropertiesChangedTuple>
        waitForPropertiesChanged(const std::string& path,
                                 const std::string& interface) = 0;
    virtual ~IDbusPropertyAccess() = default;
};

std::shared_ptr<IDbusPropertyAccess> makeDefaultDbusPropertyAccess(
    sdbusplus::async::context& ctx);
