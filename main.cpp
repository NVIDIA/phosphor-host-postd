/**
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef ENABLE_IPMI_SNOOP
#include "ipmisnoop/ipmisnoop.hpp"
#endif
#include "lpcsnoop/snoop.hpp"

#include <endian.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <systemd/sd-event.h>
#include <unistd.h>

#include <sdeventplus/event.hpp>
#include <sdeventplus/source/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <sdeventplus/source/signal.hpp>
#include <sdeventplus/source/time.hpp>
#include <sdeventplus/utility/sdbus.hpp>
#include <stdplus/signal.hpp>

#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <optional>
#include <thread>

#ifdef REPORT_SBMR
#include "sbmrbootprogress/sbmr_boot_progress.hpp"
#endif // ifdef REPORT_SBMR

static size_t codeSize = 1; /* Size of each POST code in bytes */
#ifdef READ_FROM_PCC
static uint64_t prevPostCode{0};
#endif
#define POST_CODE_MAX 256
uint8_t postCodeBuffer[POST_CODE_MAX];
static bool verbose = false;
static std::function<bool(uint64_t&, ssize_t)> procPostCode;

static void usage(const char* name)
{
    fprintf(stderr,
            "Usage: %s\n"
#ifdef ENABLE_IPMI_SNOOP
            "  -h, --host <host instances>  Default is '0'\n"
#else
            "  -d, --device <DEVICE>  use <DEVICE> file.\n"
            "  -r, --rate-limit=<N>   Only process N POST codes from the "
            "device per second.\n"
            "  -b, --bytes <SIZE>     set POST code length to <SIZE> bytes. "
            "Default is 1\n"
#endif
            "  -v, --verbose  Prints verbose information while running\n\n",
            name);
}

/**
 * Call once for each POST code received. If the number of POST codes exceeds
 * the configured rate limit, this function will disable the snoop device IO
 * source until the end of the 1 second interval, then re-enable it.
 *
 * @return Whether the rate limit is exceeded.
 */
bool rateLimit(PostReporter& reporter, sdeventplus::source::IO& ioSource)
{
    if (reporter.rateLimit == 0)
    {
        // Rate limiting is disabled.
        return false;
    }

    using Clock = sdeventplus::Clock<sdeventplus::ClockId::Monotonic>;

    static constexpr std::chrono::seconds rateLimitInterval(1);
    static unsigned int rateLimitCount = 0;
    static Clock::time_point rateLimitEndTime;

    const sdeventplus::Event& event = ioSource.get_event();

    if (rateLimitCount == 0)
    {
        // Initialize the end time when we start a new interval
        rateLimitEndTime = Clock(event).now() + rateLimitInterval;
    }

    if (++rateLimitCount < reporter.rateLimit)
    {
        return false;
    }

    rateLimitCount = 0;

    if (rateLimitEndTime < Clock(event).now())
    {
        return false;
    }

    if (verbose)
    {
        fprintf(stderr, "Hit POST code rate limit - disabling temporarily\n");
    }

    ioSource.set_enabled(sdeventplus::source::Enabled::Off);
    sdeventplus::source::Time<sdeventplus::ClockId::Monotonic>(
        event, rateLimitEndTime, std::chrono::milliseconds(100),
        [&ioSource](auto&, auto) {
        if (verbose)
        {
            fprintf(stderr, "Reenabling POST code handler\n");
        }
        ioSource.set_enabled(sdeventplus::source::Enabled::On);
    }).set_floating(true);
    return true;
}

/*
 * Split input code into multiple 2 bytes PCC code, If the PCC code prefix
 * matches the check code, store each PCC code in aspeedPCCBuffer, or clear
 * aspeedPCCBuffer if the prefix does not match.
 *
 * Each PCC code contains one byte of port number (MSB) and another byte of
 * partial postcode (LSB). To get a complete postcode, the PCC code should
 * followed the sequence of 0x40AA, 0x41BB, 0x42CC & 0x43DD. When
 * aspeedPCCBuffer contains enough PCC codes, the postcode will be assigned as
 * 0xDDCCBBAA.
 */
bool aspeedPCC(uint64_t& code, ssize_t readb)
{
    // Size of data coming from the PCC hardware
    constexpr size_t pccSize = sizeof(uint16_t);
    // Required PCC count of a full postcode, if codeSize is 8 bytes, it means
    // it require 4 PCC codes in correct sequence to get a complete postcode.
    const size_t fullPostPCCCount = codeSize / pccSize;
    // A PCC buffer for storing PCC code in sequence.
    static std::vector<uint16_t> aspeedPCCBuffer;
    constexpr uint16_t firstPCCPortNumber = 0x4000;
    constexpr uint16_t pccPortNumberMask = 0xFF00;
    constexpr uint16_t pccPostCodeMask = 0x00FF;
    constexpr uint8_t byteShift = 8;

    uint16_t* codePtr = reinterpret_cast<uint16_t*>(&code);

    for (size_t i = 0; i < (readb / pccSize); i++)
    {
        uint16_t checkCode = firstPCCPortNumber +
                             ((aspeedPCCBuffer.size() % fullPostPCCCount)
                              << byteShift);

        if (checkCode == (codePtr[i] & pccPortNumberMask))
        {
            aspeedPCCBuffer.emplace_back(codePtr[i]);
        }
        else
        {
            aspeedPCCBuffer.clear();

            // keep the PCC code if codePtr[i] matches with 0x40XX as first PCC
            // code in buffer.
            if ((codePtr[i] & pccPortNumberMask) == firstPCCPortNumber)
            {
                aspeedPCCBuffer.emplace_back(codePtr[i]);
            }
        }
    }

    if (aspeedPCCBuffer.size() < fullPostPCCCount)
    {
        // not receive full postcode yet.
        return false;
    }

    // Remove the prefix bytes and combine the partial postcodes together.
    code = 0;
    for (size_t i = 0; i < fullPostPCCCount; i++)
    {
        code |= static_cast<uint64_t>(aspeedPCCBuffer[i] & pccPostCodeMask)
                << (byteShift * i);
    }
    aspeedPCCBuffer.erase(aspeedPCCBuffer.begin(),
                          aspeedPCCBuffer.begin() + fullPostPCCCount);

    return true;
}

/*
 * Callback handling IO event from the POST code fd. i.e. there is new
 * POST code available to read.
 */
#ifdef REPORT_SBMR
void PostCodeEventHandler(PostReporter* reporter, bool verbose,
                          SbmrBootProgress& sbmr, sdeventplus::source::IO& s,
                          int postFd, uint32_t)
#else
void PostCodeEventHandler(PostReporter* reporter, bool verbose,
                          sdeventplus::source::IO& s, int postFd, uint32_t)
#endif // ifdef REPORT_SBMR
{
    uint64_t code = 0;
    ssize_t readb;
    secondary_post_code_t secondary_code;

    while ((readb = read(postFd, postCodeBuffer, codeSize)) > 0)
    {
        // if (procPostCode && procPostCode(code, readb) == false)
        // {
        //     return;
        // }

        if (codeSize <= sizeof(code))
        {
            memcpy(&code, postCodeBuffer, codeSize);
            code = le64toh(code);
            if (verbose)
            {
                fprintf(stderr, "Code: 0x%" PRIx64 "\n", code);
            }
        }
        else
        {
            code = 0;
            for (uint16_t i = 0; i < codeSize; i++)
            {
                secondary_code.push_back(postCodeBuffer[i]);
                if (verbose)
                    fprintf(stderr, "Secondary Code[%u]: 0x%x\n",i, postCodeBuffer[i]);
            }
        }
        // HACK: Always send property changed signal even for the same code
        // since we are single threaded, external users will never see the
        // first value.
        reporter->value(std::make_tuple(~code, secondary_code), true);
        reporter->value(std::make_tuple(code, secondary_code));
        postcode_t post_code{code, secondary_code};
#ifdef REPORT_SBMR
        sbmr.updateBootProgressProperties(post_code, 0);
#endif // ifdef REPORT_SBMR
        secondary_code.clear();
        // read depends on old data being cleared since it doens't always read
        // the full code size
        code = 0;

        if (rateLimit(*reporter, s))
        {
            return;
        }
    }

    if (readb < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        return;
    }

    /* Read failure. */
    if (readb == 0)
    {
        fprintf(stderr, "Unexpected EOF reading postcode\n");
    }
    else
    {
        fprintf(stderr, "Failed to read postcode: %s\n", strerror(errno));
    }
    s.get_event().exit(1);
}

#ifdef READ_FROM_PCC

/*
 * Callback handling IO event from the POST code fd. i.e. there is new
 * POST code available to read.For PCC the codesize must be 8 bytes.
 * Following is the data input and the expected output(postcode)
 * a) 4098 41e0 4200 43ea  ==> E098
 * b) 4000 40bc 4100 4200  ==> 00BC
 * c) 43ee 40ff 4100 4200  ==> 00FF
 * d) 43b0 4070 4155 4016  ==> 5570
 * e) Following is the case where post code is divided into two post codes
 *    41af 4200 43b0 4017   ==> Can not form any thing as we need byte having 41
 *    after 40 41af 4200 43b0 4004   ==> AF17.
 * f) Following is the case where we can form two post codes from
 *    8 bytes + previous post code last two bytes.
 *     43b0 4092 4155 4092  ==> 5592
 *     4155 4092 4155 4092  ==> 5592 5592
 *
 */
void PostCodePCCEventHandler(PostReporter* reporter, bool verbose,
                             sdeventplus::source::IO& s, int postFd, uint32_t)
{
    uint64_t currentPostCode = 0;
    uint64_t extractedPostCode = 0;
    uint8_t* ptrToNewCode = (uint8_t*)&extractedPostCode;
    ssize_t readb;
    while ((readb = read(postFd, &currentPostCode, codeSize)) > 0)
    {
        currentPostCode = le64toh(currentPostCode);
        if (verbose)
        {
            fprintf(stderr, "Code: 0x%" PRIx64 "\n", currentPostCode);
        }
        int index = 0;

        uint8_t* p = (uint8_t*)&currentPostCode;
        // if first byte starts with 41 then we need the last byte of the
        // previous post code.
        if (*(p + 1) == 0x41)
        {
            uint8_t* lastByte = (uint8_t*)&prevPostCode;
            lastByte = lastByte + 7;
            fprintf(stderr, "Last Byte of previous code 1: 0x%X \n", *lastByte);
            if (*lastByte == 0x40)
            {
                mempcpy(ptrToNewCode, (lastByte - 1), 1);
                memcpy(ptrToNewCode + 1, (p + 1), 1);
                fprintf(stderr, "Changed Code 1: 0x%" PRIx64 "\n",
                        extractedPostCode);
                reporter->value(std::make_tuple(~extractedPostCode,
                                                secondary_post_code_t{}),
                                true);
                reporter->value(std::make_tuple(extractedPostCode,
                                                secondary_post_code_t{}));
                extractedPostCode = 0;
            }
        }

        for (index = 2; index < readb; index += 2)
        {
            // we are only intertested in bytes which starts with 41.
            // Find the previous byte and it should be start with 40 if not
            // proceed for next which starts with 41 This condition also
            // handles the case when the incoming data is like below 0x40AA
            // 0x41BB 0x40CC 0x41DD
            if (*(p + index + 1) == 0x41)
            {
                uint8_t* lastByte = (uint8_t*)(p + index - 1);
                fprintf(stderr, "Last Byte of previous code 2: 0x%X \n",
                        *lastByte);
                if (*lastByte == 0x40)
                {
                    mempcpy(ptrToNewCode, lastByte - 1, 1);
                    memcpy(ptrToNewCode + 1, (p + index), 1);
                    fprintf(stderr, "Changed Code 2: 0x%" PRIx64 "\n",
                            extractedPostCode);
                    reporter->value(std::make_tuple(~extractedPostCode,
                                                    secondary_post_code_t{}),
                                    true);
                    reporter->value(std::make_tuple(extractedPostCode,
                                                    secondary_post_code_t{}));

                    extractedPostCode = 0;
                }
            }
            // No need to do any processing for the rest of bytes.
        }
        prevPostCode = currentPostCode;
        // HACK: Always send property changed signal even for the same code
        // since we are single threaded, external users will never see the
        // first value.
        // reporter->value(std::make_tuple(~code, secondary_post_code_t{}),
        // true); reporter->value(std::make_tuple(code,
        // secondary_post_code_t{}));

        // read depends on old data being cleared since it doens't always read
        // the full code size
        extractedPostCode = 0;
        currentPostCode = 0;
    }

    if (readb < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        return;
    }

    /* Read failure. */
    if (readb == 0)
    {
        fprintf(stderr, "Unexpected EOF reading postcode\n");
    }
    else
    {
        fprintf(stderr, "Failed to read postcode: %s\n", strerror(errno));
    }
    s.get_event().exit(1);
}
#endif

/*
 * TODO(venture): this only listens one of the possible snoop ports, but
 * doesn't share the namespace.
 *
 * This polls() the lpc snoop character device and it owns the dbus object
 * whose value is the latest port 80h value.
 */
int main(int argc, char* argv[])
{
    int postFd = -1;
    unsigned int rateLimit = 0;

    int opt;

    std::vector<std::string> host;

    // clang-format off
    static const struct option long_options[] = {
#ifdef ENABLE_IPMI_SNOOP
        {"host", optional_argument, NULL, 'h'},
#else
        {"device", optional_argument, NULL, 'd'},
        {"rate-limit", optional_argument, NULL, 'r'},
        {"bytes",  required_argument, NULL, 'b'},
#endif
        {"verbose", no_argument, NULL, 'v'},
        {0, 0, 0, 0}
    };
    // clang-format on

    constexpr const char* optstring =
#ifdef ENABLE_IPMI_SNOOP
        "h:"
#else
        "d:r:b:"
#endif
        "v";

    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 0:
                break;
            case 'h':
            {
                std::string_view instances = optarg;
                size_t pos = 0;

                while ((pos = instances.find(" ")) != std::string::npos)
                {
                    host.emplace_back(instances.substr(0, pos));
                    instances.remove_prefix(pos + 1);
                }
                host.emplace_back(instances);
                break;
            }
            case 'b':
            {
                codeSize = atoi(optarg);

                if (codeSize < 1 || codeSize > 256)
                {
                    fprintf(stderr,
                            "Invalid POST code size '%s'. Must be "
                            "an integer from 1 to 256.\n",
                            optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            }
            case 'd':
                if (std::string(optarg).starts_with("/dev/aspeed-lpc-pcc"))
                {
                    procPostCode = aspeedPCC;
                }

                postFd = open(optarg, O_NONBLOCK);
                if (postFd < 0)
                {
                    fprintf(stderr, "Unable to open: %s\n", optarg);
                    return -1;
                }
                break;
            case 'r':
            {
                int argVal = -1;
                try
                {
                    argVal = std::stoi(optarg);
                }
                catch (...)
                {}

                if (argVal < 1)
                {
                    fprintf(stderr, "Invalid rate limit '%s'. Must be >= 1.\n",
                            optarg);
                    return EXIT_FAILURE;
                }

                rateLimit = static_cast<unsigned int>(argVal);
                fprintf(stderr, "Rate limiting to %d POST codes per second.\n",
                        argVal);
                break;
            }
            case 'v':
                verbose = true;
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    auto bus = sdbusplus::bus::new_default();

#ifdef ENABLE_IPMI_SNOOP
    std::cout << "Verbose = " << verbose << std::endl;
    int ret = postCodeIpmiHandler(ipmiSnoopObject, snoopDbus, bus, host);
    if (ret < 0)
    {
        fprintf(stderr, "Error in postCodeIpmiHandler\n");
        return ret;
    }
    return 0;
#endif

    bool deferSignals = true;

    // Add systemd object manager.
    sdbusplus::server::manager_t snoopdManager(bus, snoopObject);

    PostReporter reporter(bus, snoopObject, deferSignals);
    reporter.emit_object_added();
    bus.request_name(snoopDbus);

    // Create sdevent and add IO source
    try
    {
        sdeventplus::Event event = sdeventplus::Event::get_default();
        std::optional<sdeventplus::source::IO> reporterSource;
        if (postFd > 0)
        {
            reporter.rateLimit = rateLimit;
#ifdef READ_FROM_PCC
            reporterSource.emplace(
                event, postFd, EPOLLIN,
                std::bind_front(PostCodePCCEventHandler, &reporter, verbose));
#else
#ifdef REPORT_SBMR
            SbmrBootProgress sbmrBootProgress;
            reporterSource.emplace(event, postFd, EPOLLIN,
                                   std::bind_front(PostCodeEventHandler,
                                                   &reporter, verbose,
                                                   sbmrBootProgress));
#else
            reporterSource.emplace(
                event, postFd, EPOLLIN,
                std::bind_front(PostCodeEventHandler, &reporter, verbose));
#endif // ifdef REPORT_SBMR
#endif
        }
        // Enable bus to handle incoming IO and bus events
        auto intCb = [](sdeventplus::source::Signal& source,
                        const struct signalfd_siginfo*) {
            source.get_event().exit(0);
        };
        stdplus::signal::block(SIGINT);
        sdeventplus::source::Signal(event, SIGINT, intCb).set_floating(true);
        stdplus::signal::block(SIGTERM);
        sdeventplus::source::Signal(event, SIGTERM, std::move(intCb))
            .set_floating(true);
        return sdeventplus::utility::loopWithBus(event, bus);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "%s\n", e.what());
    }

    if (postFd > -1)
    {
        close(postFd);
    }

    return 0;
}
