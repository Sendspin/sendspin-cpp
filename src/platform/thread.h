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

/// @file thread.h
/// @brief Platform-abstracted thread configuration helper for setting stack size, priority, name,
/// and PSRAM stack allocation before spawning a std::thread, and the yield-window sleep

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef ESP_PLATFORM

#include "platform/logging.h"
#include "platform/time.h"
#include <esp_heap_caps.h>
#include <esp_pthread.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

namespace sendspin {

/// @brief Configures the next std::thread created on this calling thread
/// On ESP-IDF, sets stack size, priority, name, and optionally SPIRAM stack allocation
/// via esp_pthread_set_cfg.
/// @param name Thread name shown in the RTOS task list.
/// @param stack_size Stack size in bytes.
/// @param priority FreeRTOS task priority.
/// @param stack_in_psram If true, allocates the stack in PSRAM.
inline void platform_configure_thread(const char* name, size_t stack_size, int priority,
                                      bool stack_in_psram) {
    esp_pthread_cfg_t cfg = esp_pthread_get_default_config();
    cfg.stack_size = stack_size;
    cfg.prio = priority;
    cfg.thread_name = name;
    if (stack_in_psram) {
        // esp_pthread_set_cfg() rejects stack caps without MALLOC_CAP_8BIT.
        cfg.stack_alloc_caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    }
    // A rejected config leaves the calling thread's previous (or the default) one in place.
    if (esp_pthread_set_cfg(&cfg) != ESP_OK) {
        SS_LOGE("sendspin.thread",
                "%s config rejected; it starts with the previous or default config", name);
    }
}

/// @brief Blocks the calling thread for at least `duration_us`, and at least until the next tick,
/// so the tasks below its priority run; it wakes at the first tick at or after the deadline.
/// vTaskDelay() ends at a tick interrupt, up to a tick short of the time asked for, so the
/// remaining time is rechecked after each delay, as newlib's usleep() does.
/// std::this_thread::sleep_for() would busy-wait a duration shorter than a tick period (usleep()),
/// which would keep the core.
/// @param duration_us Time to block for.
inline void platform_sleep_blocking_us(int64_t duration_us) {
    constexpr int64_t US_PER_SECOND = 1000000;
    const int64_t deadline_us = platform_time_us() + duration_us;
    int64_t remaining_us = duration_us;
    do {
        const int64_t ticks =
            (remaining_us * configTICK_RATE_HZ + US_PER_SECOND - 1) / US_PER_SECOND;
        vTaskDelay(ticks > 0 ? static_cast<TickType_t>(ticks) : 1);
        remaining_us = deadline_us - platform_time_us();
    } while (remaining_us > 0);
}

/// @brief Whether the yield windows apply (see yield_window.h): the library's threads run above a
/// consumer's main loop here
inline constexpr bool PLATFORM_YIELD_WINDOWS = true;

/// @brief Blocks the calling thread for the rest of a yield window (see yield_window.h)
/// @param duration_us Time left in the window.
inline void platform_yield_window_sleep(int64_t duration_us) {
    platform_sleep_blocking_us(duration_us);
}

}  // namespace sendspin

#else  // Host

#include <chrono>
#include <thread>

namespace sendspin {

/// @brief No-op on host; std::thread uses OS-default stack and scheduling
/// @param name Ignored on host.
/// @param stack_size Ignored on host.
/// @param priority Ignored on host.
/// @param stack_in_psram Ignored on host.
inline void platform_configure_thread(const char* /*name*/, size_t /*stack_size*/, int /*priority*/,
                                      bool /*stack_in_psram*/) {
    // No-op on host - std::thread uses OS defaults.
}

/// @brief Blocks the calling thread for at least `duration_us`
/// @param duration_us Time to block for.
inline void platform_sleep_blocking_us(int64_t duration_us) {
    std::this_thread::sleep_for(std::chrono::microseconds(duration_us));
}

/// @brief Whether the yield windows apply (see yield_window.h): not on host, where the OS
/// scheduler time-slices every thread
inline constexpr bool PLATFORM_YIELD_WINDOWS = false;

/// @brief No-op on host (PLATFORM_YIELD_WINDOWS)
/// @param duration_us Ignored on host.
inline void platform_yield_window_sleep(int64_t /*duration_us*/) {}

}  // namespace sendspin

#endif  // ESP_PLATFORM
