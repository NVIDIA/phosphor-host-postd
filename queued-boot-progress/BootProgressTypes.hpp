#pragma once
#include <cstdint>
#include <functional>
#include <vector>

// Generic callback type for delivering poller data
using onBootProgressDataCallback = std::function<void(
    int socketId, std::vector<std::pair<uint32_t /*timestamp*/,
                                        uint32_t /*progresscodes*/>>)>;
