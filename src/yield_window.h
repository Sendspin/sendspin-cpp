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

/// @file yield_window.h
/// @brief The yield windows the library's busy threads leave the tasks below their priorities

#pragma once

#include "platform/thread.h"

#include <cstdint>

namespace sendspin {

/// @brief Period (us) of the yield windows. A burst of inbound audio keeps the receive transport
/// and the protocol task busy for seconds; each keeps its work out of the window at the end of
/// every period (YieldPacer), so both leave the CPU at the same moments, the server's sends wait
/// behind the paused receive, and a consumer's lower-priority main loop runs.
static constexpr int64_t YIELD_WINDOW_PERIOD_US = 100000;

/// @brief Length (us) of the yield window that ends each YIELD_WINDOW_PERIOD_US: what the tasks
/// below get of each core while a burst lasts. On an ESP32 at 160 MHz a quarter of the period held
/// the longest a priority-1 task went without a core to about 200 ms, against seconds without
/// windows, and still worked off a backlog at about twice real time.
static constexpr int64_t YIELD_WINDOW_LENGTH_US = 25000;

/// @brief Longest unit of work (us) a YieldPacer plans around. Decrypting or receiving one large
/// frame on a slow chip takes over 10 ms; a unit taken as longer (a preemption inflated it) would
/// only idle the thread for more of each period.
static constexpr int64_t YIELD_MAX_UNIT_US = 20000;

/// @brief A frame whose receive starts within this long (us) of the previous frame's end found its
/// data already waiting, so the connection is receiving a burst. Only then does a receive
/// transport pause, so a time reply arriving on an idle connection is never stamped late.
static constexpr int64_t BACK_TO_BACK_RECEIVE_US = 1000;

/// @brief How long (us) a thread must have been busy, never finding its input empty, before it
/// yields. Steady playback never stays busy this long (frames that reach the socket together in one
/// TCP segment are read within microseconds), so the yield windows only ever touch a burst and
/// audio arriving at its own pace is never held back.
static constexpr int64_t YIELD_MIN_BUSY_US = 50000;

/// @brief Returns how long (us) a thread about to start a unit of work expected to take
/// `expected_unit_us` should sleep first: the rest of the window when `now_us` is in one, and up to
/// the end of the next window when the unit would run into it, so the window stays free
constexpr int64_t yield_pause_us(int64_t now_us, int64_t expected_unit_us) {
    const int64_t phase = now_us % YIELD_WINDOW_PERIOD_US;
    const int64_t window_start = YIELD_WINDOW_PERIOD_US - YIELD_WINDOW_LENGTH_US;
    if (phase >= window_start || expected_unit_us > window_start - phase) {
        return YIELD_WINDOW_PERIOD_US - phase;
    }
    return 0;
}

/// @brief True when a receive starting at `now_us` follows the previous frame's end
/// (`previous_end_us`, 0 before the first) within BACK_TO_BACK_RECEIVE_US
constexpr bool receive_is_back_to_back(int64_t previous_end_us, int64_t now_us) {
    return previous_end_us != 0 && now_us - previous_end_us < BACK_TO_BACK_RECEIVE_US;
}

/// @brief True once a thread busy since `busy_since_us` (0 while it is not busy) has stayed busy
/// for YIELD_MIN_BUSY_US at `now_us`
constexpr bool busy_long_enough_to_yield(int64_t busy_since_us, int64_t now_us) {
    return busy_since_us != 0 && now_us - busy_since_us >= YIELD_MIN_BUSY_US;
}

/// @brief Keeps a thread working off a burst out of the yield windows. Once the thread has been
/// busy for YIELD_MIN_BUSY_US, pause() sleeps when the coming unit of work, expected to take as
/// long as the last one, would start in or run into the next window. One per thread loop; not
/// thread-safe. The longest sleep is YIELD_WINDOW_LENGTH_US + YIELD_MAX_UNIT_US.
class YieldPacer {
public:
    /// @brief Call when the thread finds its input empty, or arriving at its own pace: ends the
    /// busy stretch
    void note_idle() {
        this->busy_since_us_ = 0;
    }

    /// @brief Call before a unit of work whose input was already waiting. Starts a busy stretch,
    /// and once it has lasted YIELD_MIN_BUSY_US sleeps out the next yield window when the unit
    /// would start in or run into it (the sleep is a no-op on host).
    /// @param now_us The current platform_time_us().
    void pause(int64_t now_us) {
        if (this->busy_since_us_ == 0) {
            this->busy_since_us_ = now_us;
            return;
        }
        if (!busy_long_enough_to_yield(this->busy_since_us_, now_us)) {
            return;
        }
        const int64_t pause_us = yield_pause_us(now_us, this->last_unit_us_);
        if (pause_us > 0) {
            platform_yield_window_sleep(pause_us);
        }
    }

    /// @brief Marks the start of a unit of work
    /// @param now_us The current platform_time_us().
    void start_unit(int64_t now_us) {
        this->unit_start_us_ = now_us;
    }

    /// @brief Marks the end of the unit start_unit() began; its length guides the next pause()
    /// @param now_us The current platform_time_us().
    void end_unit(int64_t now_us) {
        const int64_t unit_us = now_us - this->unit_start_us_;
        this->last_unit_us_ = unit_us < YIELD_MAX_UNIT_US ? unit_us : YIELD_MAX_UNIT_US;
    }

private:
    // 64-bit fields
    int64_t busy_since_us_{0};
    int64_t unit_start_us_{0};
    int64_t last_unit_us_{0};
};

}  // namespace sendspin
