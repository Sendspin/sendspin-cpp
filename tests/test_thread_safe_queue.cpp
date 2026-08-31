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

/// @file test_thread_safe_queue.cpp
/// @brief Tests for the host ThreadSafeQueue wake_receiver() contract, which the artwork
/// role's stop and parked-slot recheck paths depend on

#include "platform/thread_safe_queue.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <thread>

namespace sendspin {
namespace {

// Long enough that a receive still parked when the assertion fires is an unambiguous
// failure, far above any scheduling noise.
constexpr uint32_t BLOCKED_RECEIVE_TIMEOUT_MS = 10000;
// Any wake-induced return completes in microseconds; the generous bound only filters
// out the full BLOCKED_RECEIVE_TIMEOUT_MS park a lost wake would cause.
constexpr int64_t WAKE_LATENCY_BOUND_MS = 2000;

int64_t elapsed_ms_since(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                 start)
        .count();
}

// wake_receiver() must pull a consumer out of an in-progress blocking receive without
// handing it an item. The sleep only makes the consumer *likely* to be parked when the
// wake fires; the wake contract covers both orderings (a wake before the park is held
// pending), so the test cannot race, it just usually exercises the parked path.
TEST(ThreadSafeQueue, WakeReceiverUnblocksBlockedReceive) {
    ThreadSafeQueue<int> queue;
    ASSERT_TRUE(queue.create(4));

    bool received = true;  // Poisoned so a skipped receive is visible
    int64_t elapsed_ms = 0;
    std::thread consumer([&] {
        auto start = std::chrono::steady_clock::now();
        int item = 0;
        received = queue.receive(item, BLOCKED_RECEIVE_TIMEOUT_MS);
        elapsed_ms = elapsed_ms_since(start);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    queue.wake_receiver();
    consumer.join();

    EXPECT_FALSE(received);
    EXPECT_LT(elapsed_ms, WAKE_LATENCY_BOUND_MS);
}

// A wake issued while no receive is in progress is held pending: the next blocking
// receive returns immediately instead of parking. Role stop() paths rely on this to
// close the set-flag-then-wake race with a thread that has not parked yet.
TEST(ThreadSafeQueue, WakeBeforeReceiveReturnsImmediately) {
    ThreadSafeQueue<int> queue;
    ASSERT_TRUE(queue.create(4));

    queue.wake_receiver();

    auto start = std::chrono::steady_clock::now();
    int item = 0;
    EXPECT_FALSE(queue.receive(item, BLOCKED_RECEIVE_TIMEOUT_MS));
    EXPECT_LT(elapsed_ms_since(start), WAKE_LATENCY_BOUND_MS);
}

// Control: a wake never consumes an item, and a surviving item does not consume the
// wake. With both an item and a wake pending, the item is delivered and the wake still
// interrupts the following blocking receive -- so a stop signal cannot be lost behind a
// racing send.
TEST(ThreadSafeQueue, WakeDoesNotDropItemAndItemDoesNotDropWake) {
    ThreadSafeQueue<int> queue;
    ASSERT_TRUE(queue.create(4));

    ASSERT_TRUE(queue.send(42, 0));
    queue.wake_receiver();

    int item = 0;
    ASSERT_TRUE(queue.receive(item, BLOCKED_RECEIVE_TIMEOUT_MS));
    EXPECT_EQ(item, 42);

    auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(queue.receive(item, BLOCKED_RECEIVE_TIMEOUT_MS));
    EXPECT_LT(elapsed_ms_since(start), WAKE_LATENCY_BOUND_MS);
}

}  // namespace
}  // namespace sendspin
