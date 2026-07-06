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

#include "dbus_utils.hpp"

#include <sdbusplus/bus/match.hpp>

#include <unordered_set>

namespace rulesInterface = sdbusplus::bus::match::rules;

sdbusplus::async::task<std::string> getDbusProperty(
    sdbusplus::async::context& ctx, const char* service, const char* path,
    const char* interface, const char* property)
{
    auto proxy =
        sdbusplus::async::proxy().service(service).path(path).interface(
            interface);
    co_return co_await proxy.get_property<std::string>(ctx, property);
}

sdbusplus::async::task<PropertiesChangedTuple> waitForDbusPropertiesChanged(
    sdbusplus::async::context& ctx, const std::string& path,
    const std::string& interface)
{
    auto m = sdbusplus::async::match(
        ctx, rulesInterface::propertiesChanged(path, interface));
    co_return co_await m
        .next<std::tuple_element_t<0, PropertiesChangedTuple>,
              std::tuple_element_t<1, PropertiesChangedTuple>,
              std::tuple_element_t<2, PropertiesChangedTuple>>();
}

sdbusplus::async::task<std::vector<std::string>> getSubTreePaths(
    sdbusplus::async::context& ctx, const std::string& subtree, int32_t depth,
    const std::vector<std::string>& interfaces)
{
    co_return co_await sdbusplus::async::proxy()
        .service("xyz.openbmc_project.ObjectMapper")
        .path("/xyz/openbmc_project/object_mapper")
        .interface("xyz.openbmc_project.ObjectMapper")
        .call<std::vector<std::string>>(ctx, "GetSubTreePaths", subtree, depth,
                                        interfaces);
}

size_t countUniqueLeafPaths(const std::vector<std::string>& paths)
{
    std::unordered_set<std::string> unique;
    for (const auto& p : paths)
    {
        auto pos = p.rfind('/');
        unique.insert(pos != std::string::npos ? p.substr(pos + 1) : p);
    }
    return unique.size();
}

sdbusplus::async::task<std::string> DbusPropertyAccess::getProperty(
    const char* service, const char* path, const char* interface,
    const char* property)
{
    co_return co_await getDbusProperty(ctx, service, path, interface, property);
}

sdbusplus::async::task<PropertiesChangedTuple>
    DbusPropertyAccess::waitForPropertiesChanged(const std::string& path,
                                                 const std::string& interface)
{
    co_return co_await waitForDbusPropertiesChanged(ctx, path, interface);
}

sdbusplus::async::task<void> DbusPropertyAccess::setProperty(
    const char* service, const char* path, const char* interface,
    const char* property, const std::string& value)
{
    co_await setDbusProperty(ctx, service, path, interface, property, value);
}

sdbusplus::async::task<void> DbusPropertyAccess::setProperty(
    const char* service, const char* path, const char* interface,
    const char* property, uint64_t value)
{
    co_await setDbusProperty(ctx, service, path, interface, property, value);
}
