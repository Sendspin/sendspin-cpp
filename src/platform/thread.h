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

/// @brief Blocks the calling thread for at least `duration_us`, rounded up to whole ticks and never
/// less than one, so the tasks below its priority run. std::this_thread::sleep_for() busy-waits a
/// duration shorter than a tick period (newlib's usleep()), which would keep the core.
/// @param duration_us Time to block for.
inline void platform_sleep_blocking_us(int64_t duration_us) {
    const int64_t ticks = (duration_us * configTICK_RATE_HZ + 999999) / 1000000;
    vTaskDelay(ticks > 0 ? static_cast<TickType_t>(ticks) : 1);
}

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

/// @brief No-op on host, where the OS scheduler time-slices every thread
/// @param duration_us Ignored on host.
inline void platform_yield_window_sleep(int64_t /*duration_us*/) {}

}  // namespace sendspin

#endif  // ESP_PLATFORM
