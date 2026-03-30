// Copyright 2026 Sendspin Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file time.h
/// @brief Platform-abstracted monotonic time source providing microsecond resolution

#pragma once

#include <cstdint>

#ifdef ESP_PLATFORM

#include <esp_timer.h>

namespace sendspin {

/// @brief Returns monotonic time in microseconds
inline int64_t platform_time_us() {
    return esp_timer_get_time();
}

}  // namespace sendspin

#else  // Host

#include <chrono>

namespace sendspin {

inline int64_t platform_time_us() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

}  // namespace sendspin

#endif  // ESP_PLATFORM
