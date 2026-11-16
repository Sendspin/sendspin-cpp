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

/// @file test_yield_window.cpp
/// @brief Tests for the yield windows: when a unit of work waits one out, which receives count as
/// a burst, and how long a thread must stay busy before it yields

#include "yield_window.h"

#include <gtest/gtest.h>

#include <cstdint>

namespace sendspin {
namespace {

// Every paced thread keeps out of the same window, the last YIELD_WINDOW_LENGTH_US of each period:
// inside it a thread sleeps to its end, and a unit of work that would run into it waits it out too,
// so every thread is out of the window together.
TEST(YieldWindow, AUnitThatWouldRunIntoTheWindowWaitsItOut) {
    constexpr int64_t PERIOD = YIELD_WINDOW_PERIOD_US;
    constexpr int64_t START = PERIOD - YIELD_WINDOW_LENGTH_US;
    constexpr int64_t BASE = 1'000'000 * PERIOD;
    constexpr int64_t UNIT = 5'000;
    struct Row {
        const char* what;
        int64_t now;
        int64_t unit;
        int64_t pause;
    };
    const Row rows[] = {
        {"Control: a short unit well before the window", BASE, UNIT, 0},
        {"Control: a unit that ends exactly at the window", BASE + START - UNIT, UNIT, 0},
        {"a unit that would end inside the window", BASE + START - UNIT + 1, UNIT,
         PERIOD - START + UNIT - 1},
        {"inside the window", BASE + START + 1'000, UNIT, PERIOD - START - 1'000},
        {"the window's start, nothing measured yet", BASE + START, 0, PERIOD - START},
        {"the window's last microsecond", BASE + PERIOD - 1, UNIT, 1},
        {"Control: the next period's start", BASE + PERIOD, UNIT, 0},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.what);
        EXPECT_EQ(yield_pause_us(row.now, row.unit), row.pause);
    }
}

// A receive transport pauses only while frames arrive back to back: a frame on an otherwise idle
// connection, such as a time reply, is read at once so its receive stamp stays exact.
TEST(YieldWindow, OnlyAReceiveRightAfterTheLastFramePauses) {
    constexpr int64_t END = 5'000'000;
    struct Row {
        const char* what;
        int64_t previous_end;
        int64_t now;
        bool back_to_back;
    };
    const Row rows[] = {
        {"right after the previous frame", END, END + 10, true},
        {"just inside the limit", END, END + BACK_TO_BACK_RECEIVE_US - 1, true},
        {"Control: at the limit", END, END + BACK_TO_BACK_RECEIVE_US, false},
        {"Control: after an idle stretch", END, END + 20'000, false},
        {"Control: the connection's first frame", 0, 10, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.what);
        EXPECT_EQ(receive_is_back_to_back(row.previous_end, row.now), row.back_to_back);
    }
}

// Steady playback must never yield: only a thread that has stayed busy, its input never found
// empty, for YIELD_MIN_BUSY_US paces itself.
TEST(YieldWindow, OnlyALongBusyStretchYields) {
    constexpr int64_t SINCE = 7'000'000;
    struct Row {
        const char* what;
        int64_t busy_since;
        int64_t now;
        bool yields;
    };
    const Row rows[] = {
        {"Control: not busy", 0, SINCE, false},
        {"Control: just became busy", SINCE, SINCE, false},
        {"Control: busy just short of the minimum", SINCE, SINCE + YIELD_MIN_BUSY_US - 1, false},
        {"busy for the minimum", SINCE, SINCE + YIELD_MIN_BUSY_US, true},
        {"busy for seconds", SINCE, SINCE + 5'000'000, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.what);
        EXPECT_EQ(busy_long_enough_to_yield(row.busy_since, row.now), row.yields);
    }
}

}  // namespace
}  // namespace sendspin
