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

std::shared_ptr<IDbusPropertyAccess> makeDefaultDbusPropertyAccess(
    sdbusplus::async::context& ctx)
{
    struct DefaultImpl : IDbusPropertyAccess
    {
        explicit DefaultImpl(sdbusplus::async::context& c) : ctx(c) {}

        sdbusplus::async::task<std::string> getProperty(
            const char* service, const char* path, const char* interface,
            const char* property) override
        {
            co_return co_await getDbusProperty(ctx, service, path, interface,
                                               property);
        }

        sdbusplus::async::task<PropertiesChangedTuple> waitForPropertiesChanged(
            const std::string& path, const std::string& interface) override
        {
            co_return co_await waitForDbusPropertiesChanged(ctx, path,
                                                            interface);
        }

        sdbusplus::async::context& ctx;
    };
    return std::make_shared<DefaultImpl>(ctx);
}
