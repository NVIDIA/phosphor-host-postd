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
#include "queued-boot-progress/ConfigReader.hpp"

#include <getopt.h>

#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace
{

static void resetGetopt()
{
    optind = 0;
    optarg = nullptr;
    optopt = 0;
}

static std::pair<int, std::vector<char*>> makeArgv(
    const std::vector<std::string>& args)
{
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& s : args)
    {
        argv.push_back(const_cast<char*>(s.data()));
    }
    argv.push_back(nullptr);
    return {static_cast<int>(args.size()), argv};
}

TEST(ConfigReader, NoArgsDefaultsToI2CAndFailsValidation)
{
    Configuration config{};
    std::vector<std::string> args = {"prog"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, ValidPollIntervalI2CWithOneDevice)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "100", "-i",  "i2c",
                                     "-b",   "0",  "-a",  "0x50"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    ASSERT_TRUE(ok);
    EXPECT_EQ(config.pollInterval.count(), 100);
    EXPECT_EQ(config.transportInterface, TransportInterface::I2C);
    ASSERT_EQ(config.i2cInterfaceConfigMap.size(), 1u);
    EXPECT_EQ(config.i2cInterfaceConfigMap[0].first, 0);
    EXPECT_EQ(config.i2cInterfaceConfigMap[0].second, 0x50);
}

TEST(ConfigReader, ValidTransportUSB)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "200", "-i", "usb"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    ASSERT_TRUE(ok);
    EXPECT_EQ(config.pollInterval.count(), 200);
    EXPECT_EQ(config.transportInterface, TransportInterface::USB);
}

TEST(ConfigReader, InvalidPollIntervalZero)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "0"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidPollIntervalNegative)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "-1"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidPollIntervalNonNumeric)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "abc"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidTransportInterface)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i", "spi"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidI2CBusOutOfRange)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p",  "50", "-i",  "i2c",
                                     "-b",   "300", "-a", "0x50"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidI2CAddressOutOfRange)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i", "i2c",
                                     "-b",   "0",  "-a", "256"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, BusAddressCountMismatch)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i", "i2c", "-b",
                                     "0",    "-b", "1",  "-a", "0x50"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidI2CBusNonNumeric)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p",  "50", "-i",  "i2c",
                                     "-b",   "abc", "-a", "0x50"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidI2CAddressNonNumeric)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i", "i2c",
                                     "-b",   "0",  "-a", "xyz"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidCakCpuCountTooLarge)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i",
                                     "usb",  "-c", "3"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, InvalidCakCpuCountNonNumeric)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i",
                                     "usb",  "-c", "two"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, ValidCakCpuCountZeroAndTwo)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i",
                                     "usb",  "-c", "0"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    ASSERT_TRUE(ok);
    EXPECT_EQ(config.cakCpuCount, 0u);
}

TEST(ConfigReader, ValidCakCpuCountOne)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i",
                                     "usb",  "-c", "1"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    ASSERT_TRUE(ok);
    EXPECT_EQ(config.cakCpuCount, 1u);
}

TEST(ConfigReader, ValidCakCpuCountTwo)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "50", "-i",
                                     "usb",  "-c", "2"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    ASSERT_TRUE(ok);
    EXPECT_EQ(config.cakCpuCount, 2u);
}

// Branch: switch(opt) default - unknown option
TEST(ConfigReader, InvalidOptionReturnsFalse)
{
    Configuration config{};
    static std::vector<std::string> args = {"prog", "-p", "100", "-x"};
    static std::vector<char*> argvStorage;
    argvStorage.clear();
    for (const auto& s : args)
    {
        argvStorage.push_back(const_cast<char*>(s.data()));
    }
    argvStorage.push_back(nullptr);
    resetGetopt();

    bool ok = ConfigReader::readConfig(static_cast<int>(args.size()),
                                       argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(ConfigReader, MultipleI2CDevices)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "100", "-i",   "i2c",
                                     "-b",   "0",  "-a",  "0x50", "-b",
                                     "1",    "-a", "0x51"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    ASSERT_TRUE(ok);
    ASSERT_EQ(config.i2cInterfaceConfigMap.size(), 2u);
    EXPECT_EQ(config.i2cInterfaceConfigMap[0].first, 0);
    EXPECT_EQ(config.i2cInterfaceConfigMap[0].second, 0x50);
    EXPECT_EQ(config.i2cInterfaceConfigMap[1].first, 1);
    EXPECT_EQ(config.i2cInterfaceConfigMap[1].second, 0x51);
}

// validateTransportConfiguration: I2C with empty device list
TEST(ConfigReader, I2CTransportEmptyDeviceListFailsValidation)
{
    Configuration config{};
    std::vector<std::string> args = {"prog", "-p", "100", "-i", "i2c"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

// validateTransportConfiguration: USB with zero vendor ID
TEST(ConfigReader, USBTransportZeroVendorIdFailsValidation)
{
    Configuration config{};
    config.usbVendorId = 0;
    config.usbProductId = 0x7410;
    std::vector<std::string> args = {"prog", "-p", "100", "-i", "usb"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

// validateTransportConfiguration: USB with zero product ID
TEST(ConfigReader, USBTransportZeroProductIdFailsValidation)
{
    Configuration config{};
    config.usbVendorId = 0x0955;
    config.usbProductId = 0;
    std::vector<std::string> args = {"prog", "-p", "100", "-i", "usb"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

// validateTransportConfiguration: default (unsupported) transport
TEST(ConfigReader, UnsupportedTransportFailsValidation)
{
    Configuration config{};
    config.transportInterface =
        static_cast<TransportInterface>(99); // not I2C or USB
    std::vector<std::string> args = {"prog", "-p", "100"};
    auto [argc, argvStorage] = makeArgv(args);
    resetGetopt();

    bool ok = ConfigReader::readConfig(argc, argvStorage.data(), config);
    EXPECT_FALSE(ok);
}

TEST(PollingDeviceTypes, TransportInterfaceValues)
{
    EXPECT_EQ(static_cast<int>(TransportInterface::I2C), 0);
    EXPECT_EQ(static_cast<int>(TransportInterface::USB), 1);
}

TEST(PollingDeviceTypes, PairHashSamePairSameHash)
{
    PairHash hasher;
    auto p = std::make_pair(static_cast<uint8_t>(1), static_cast<uint8_t>(2));
    std::size_t h1 = hasher(p);
    std::size_t h2 = hasher(p);
    EXPECT_EQ(h1, h2);
}

TEST(PollingDeviceTypes, PairHashDifferentPairsDifferentHash)
{
    PairHash hasher;
    auto p1 = std::make_pair(static_cast<uint8_t>(0), static_cast<uint8_t>(0));
    auto p2 = std::make_pair(static_cast<uint8_t>(1), static_cast<uint8_t>(0));
    EXPECT_NE(hasher(p1), hasher(p2));
}

TEST(PollingDeviceTypes, PairHashOrderMatters)
{
    PairHash hasher;
    auto p1 = std::make_pair(static_cast<uint8_t>(1), static_cast<uint8_t>(2));
    auto p2 = std::make_pair(static_cast<uint8_t>(2), static_cast<uint8_t>(1));
    EXPECT_NE(hasher(p1), hasher(p2));
}

TEST(PollingDeviceTypes, PairHashFormula)
{
    PairHash hasher;
    auto p = std::make_pair(static_cast<uint8_t>(2), static_cast<uint8_t>(3));
    std::size_t h = hasher(p);
    EXPECT_EQ(h, (static_cast<std::size_t>(2) << 8) | 3);
}

} // namespace
