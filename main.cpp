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

#include "lpcsnoop/snoop.hpp"

#include <endian.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <systemd/sd-event.h>
#include <unistd.h>

#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <thread>

static size_t codeSize = 1; /* Size of each POST code in bytes */
#ifdef READ_FROM_PCC
static uint64_t prevPostCode{0};
#endif

static void usage(const char* name)
{
    fprintf(stderr,
            "Usage: %s [-d <DEVICE>]\n"
            "  -b, --bytes <SIZE>     set POST code length to <SIZE> bytes. "
            "Default is %zu\n"
            "  -d, --device <DEVICE>  use <DEVICE> file.\n"
            "  -v, --verbose  Prints verbose information while running\n\n",
            name, codeSize);
}

/*
 * Callback handling IO event from the POST code fd. i.e. there is new
 * POST code available to read.
 */
void PostCodeEventHandler(sdeventplus::source::IO& s, int postFd, uint32_t,
                          PostReporter* reporter, bool verbose)
{
    uint64_t code = 0;
    ssize_t readb;
    while ((readb = read(postFd, &code, codeSize)) > 0)
    {
        code = le64toh(code);
        if (verbose)
        {
            fprintf(stderr, "Code: 0x%" PRIx64 "\n", code);
        }
        // HACK: Always send property changed signal even for the same code
        // since we are single threaded, external users will never see the
        // first value.
        reporter->value(std::make_tuple(~code, secondary_post_code_t{}), true);
        reporter->value(std::make_tuple(code, secondary_post_code_t{}));

        // read depends on old data being cleared since it doens't always read
        // the full code size
        code = 0;
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
void PostCodePCCEventHandler(sdeventplus::source::IO& s, int postFd, uint32_t,
                             PostReporter* reporter, bool verbose)
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
    int rc = 0;
    int opt;
    int postFd = -1;

    /*
     * These string constants are only used in this method within this object
     * and this object is the only object feeding into the final binary.
     *
     * If however, another object is added to this binary it would be proper
     * to move these declarations to be global and extern to the other object.
     */
    const char* snoopObject = SNOOP_OBJECTPATH;
    const char* snoopDbus = SNOOP_BUSNAME;

    bool deferSignals = true;
    bool verbose = false;

    // clang-format off
    static const struct option long_options[] = {
        {"bytes",  required_argument, NULL, 'b'},
        {"device", optional_argument, NULL, 'd'},
        {"verbose", no_argument, NULL, 'v'},
        {0, 0, 0, 0}
    };
    // clang-format on

    while ((opt = getopt_long(argc, argv, "b:d:v", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 0:
                break;
            case 'b':
                codeSize = atoi(optarg);

                if (codeSize < 1 || codeSize > 8)
                {
                    fprintf(stderr,
                            "Invalid POST code size '%s'. Must be "
                            "an integer from 1 to 8.\n",
                            optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'd':
                postFd = open(optarg, O_NONBLOCK);
                if (postFd < 0)
                {
                    fprintf(stderr, "Unable to open: %s\n", optarg);
                    return -1;
                }

                break;
            case 'v':
                verbose = true;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    auto bus = sdbusplus::bus::new_default();

    // Add systemd object manager.
    sdbusplus::server::manager::manager(bus, snoopObject);

    PostReporter reporter(bus, snoopObject, deferSignals);
    reporter.emit_object_added();
    bus.request_name(snoopDbus);

    // Create sdevent and add IO source
    try
    {
        sdeventplus::Event event = sdeventplus::Event::get_default();
        std::unique_ptr<sdeventplus::source::IO> reporterSource;
        if (postFd > 0)
        {
	    #ifdef READ_FROM_PCC
            reporterSource = std::make_unique<sdeventplus::source::IO>(
                event, postFd, EPOLLIN | EPOLLET,
                std::bind(PostCodePCCEventHandler, std::placeholders::_1,
                          std::placeholders::_2, std::placeholders::_3,
                          &reporter, verbose));
            #else
            reporterSource = std::make_unique<sdeventplus::source::IO>(
                event, postFd, EPOLLIN | EPOLLET,
                std::bind(PostCodeEventHandler, std::placeholders::_1,
                          std::placeholders::_2, std::placeholders::_3,
                          &reporter, verbose));
            #endif
        }
        // Enable bus to handle incoming IO and bus events
        bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
        rc = event.loop();
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "%s\n", e.what());
    }

    if (postFd > -1)
    {
        close(postFd);
    }

    return rc;
}
