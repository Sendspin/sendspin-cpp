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

// wake_receiver() is the only way out of an infinite park, so a returning receive is itself
// the proof the wake landed. The sleep only makes the consumer likely to be parked; a wake
// before the park is held pending, so either ordering passes.
TEST(ThreadSafeQueue, WakeReceiverUnblocksBlockedReceive) {
    ThreadSafeQueue<int> queue;
    ASSERT_TRUE(queue.create(4));

    bool received = true;  // Poisoned so a skipped receive is visible
    std::thread consumer([&] {
        int item = 0;
        received = queue.receive(item, UINT32_MAX);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    queue.wake_receiver();
    consumer.join();

    EXPECT_FALSE(received);
}

// A wake with no receive in progress is held pending, closing the set-flag-then-wake race
// with a role stop() whose thread has not parked yet.
TEST(ThreadSafeQueue, WakeBeforeReceiveIsHeldPending) {
    ThreadSafeQueue<int> queue;
    ASSERT_TRUE(queue.create(4));

    queue.wake_receiver();

    int item = 0;
    EXPECT_FALSE(queue.receive(item, UINT32_MAX));
}

// Control: with both an item and a wake pending, the item is delivered intact and the wake
// still interrupts the next receive, so a stop cannot be lost behind a racing send.
TEST(ThreadSafeQueue, WakeDoesNotDropItemAndItemDoesNotDropWake) {
    ThreadSafeQueue<int> queue;
    ASSERT_TRUE(queue.create(4));

    ASSERT_TRUE(queue.send(42, 0));
    queue.wake_receiver();

    int item = 0;
    ASSERT_TRUE(queue.receive(item, UINT32_MAX));
    EXPECT_EQ(item, 42);

    EXPECT_FALSE(queue.receive(item, UINT32_MAX));
}

// The wake is one-shot: the receive it interrupts consumes it, and the next one parks again.
// An unconsumed wake would return false before the send below ever runs.
TEST(ThreadSafeQueue, WakeIsConsumedByTheReceiveItInterrupts) {
    ThreadSafeQueue<int> queue;
    ASSERT_TRUE(queue.create(4));

    queue.wake_receiver();
    int item = 0;
    ASSERT_FALSE(queue.receive(item, UINT32_MAX));

    bool received = false;
    int got = 0;
    std::thread consumer([&] { received = queue.receive(got, UINT32_MAX); });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ASSERT_TRUE(queue.send(42, 0));
    consumer.join();

    EXPECT_TRUE(received);
    EXPECT_EQ(got, 42);
}

}  // namespace
}  // namespace sendspin
