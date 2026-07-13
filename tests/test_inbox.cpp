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

/// @file test_inbox.cpp
/// @brief Tests for the Inbox/InboxSlot primitives: slot write/take/merge semantics, event ring
/// FIFO and overflow behavior, and a concurrent producer/consumer smoke test

#include "inbox.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <thread>

namespace sendspin {
namespace {

bool has_bit(uint32_t bits, uint32_t bit) {
    return (bits & bit) != 0;
}

// Simple two-field aggregate used to exercise InboxSlot::merge() with a non-scalar type.
struct IntPair {
    int a{0};
    int b{0};
};

void merge_int_pair(IntPair& current, IntPair&& delta) {
    current.a += delta.a;
    current.b += delta.b;
}

TEST(InboxSlot, WriteTakeRoundtrip) {
    Inbox inbox;
    InboxSlot<int> slot(inbox, INBOX_TOPIC_GROUP);

    slot.write(42);

    int value = 0;
    ASSERT_TRUE(slot.take(value));
    EXPECT_EQ(value, 42);
}

TEST(InboxSlot, TakeOnCleanSlotReturnsFalseWithNoBitSet) {
    Inbox inbox;
    InboxSlot<int> slot(inbox, INBOX_TOPIC_GROUP);

    int value = -1;
    EXPECT_FALSE(slot.take(value));
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));
}

TEST(InboxSlot, WriteSetsTopicBitAndTakeClearsIt) {
    Inbox inbox;
    InboxSlot<int> slot(inbox, INBOX_TOPIC_GROUP);

    slot.write(7);
    EXPECT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));

    int value = 0;
    ASSERT_TRUE(slot.take(value));
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));
}

TEST(InboxSlot, ResetClearsContentAndBit) {
    Inbox inbox;
    InboxSlot<int> slot(inbox, INBOX_TOPIC_GROUP);

    slot.write(99);
    ASSERT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));

    slot.reset();
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));

    int value = -1;
    EXPECT_FALSE(slot.take(value));
}

TEST(InboxSlot, MergeAccumulatesAcrossCalls) {
    Inbox inbox;
    InboxSlot<IntPair> slot(inbox, INBOX_TOPIC_METADATA);

    slot.merge(merge_int_pair, IntPair{1, 10});
    slot.merge(merge_int_pair, IntPair{2, 20});
    slot.merge(merge_int_pair, IntPair{3, 30});

    IntPair result{};
    ASSERT_TRUE(slot.take(result));
    EXPECT_EQ(result.a, 6);
    EXPECT_EQ(result.b, 60);

    // The merged value is delivered exactly once.
    IntPair second{};
    EXPECT_FALSE(slot.take(second));
}

TEST(InboxSlot, DrainingOneSlotLeavesOtherSlotBitSet) {
    Inbox inbox;
    InboxSlot<int> group_slot(inbox, INBOX_TOPIC_GROUP);
    InboxSlot<int> controller_slot(inbox, INBOX_TOPIC_CONTROLLER);

    group_slot.write(1);
    controller_slot.write(2);
    EXPECT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));
    EXPECT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_CONTROLLER));

    int value = 0;
    ASSERT_TRUE(group_slot.take(value));
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));
    EXPECT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_CONTROLLER));
}

TEST(Inbox, RingPreservesFifoOrder) {
    Inbox inbox;

    for (uint8_t i = 0; i < 5; ++i) {
        InboxEvent event{};
        event.type = InboxEventType::CONTROLLER_CLEARED;
        event.code = i;
        ASSERT_TRUE(inbox.push_event(event));
    }

    InboxEvent out[5];
    ASSERT_EQ(inbox.take_events(out, 5), 5u);
    for (uint8_t i = 0; i < 5; ++i) {
        EXPECT_EQ(out[i].code, i);
    }
}

TEST(Inbox, PartialDrainKeepsEventsBitSetUntilEmptied) {
    Inbox inbox;

    for (uint8_t i = 0; i < 5; ++i) {
        InboxEvent event{};
        event.type = InboxEventType::CONTROLLER_CLEARED;
        event.code = i;
        ASSERT_TRUE(inbox.push_event(event));
    }

    // Drain fewer than are pending: the bit must stay set so the rest are not missed.
    InboxEvent first_batch[3];
    ASSERT_EQ(inbox.take_events(first_batch, 3), 3u);
    for (uint8_t i = 0; i < 3; ++i) {
        EXPECT_EQ(first_batch[i].code, i);
    }
    EXPECT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_EVENTS));

    // Draining the remainder empties the ring and clears the bit.
    InboxEvent second_batch[2];
    ASSERT_EQ(inbox.take_events(second_batch, 2), 2u);
    EXPECT_EQ(second_batch[0].code, 3);
    EXPECT_EQ(second_batch[1].code, 4);
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_EVENTS));
}

TEST(Inbox, OverflowDropsNewestPushKeepsExistingContentsIntact) {
    Inbox inbox;

    for (size_t i = 0; i < Inbox::EVENT_CAPACITY; ++i) {
        InboxEvent event{};
        event.type = InboxEventType::CONTROLLER_CLEARED;
        event.code = static_cast<uint8_t>(i);
        ASSERT_TRUE(inbox.push_event(event)) << "push " << i << " should have succeeded";
    }

    // The ring is full: the next push must be rejected (drop-newest) without disturbing content.
    InboxEvent overflow_event{};
    overflow_event.type = InboxEventType::METADATA_CLEARED;
    overflow_event.code = 0xFF;
    EXPECT_FALSE(inbox.push_event(overflow_event));

    InboxEvent out[Inbox::EVENT_CAPACITY];
    ASSERT_EQ(inbox.take_events(out, Inbox::EVENT_CAPACITY), Inbox::EVENT_CAPACITY);
    for (size_t i = 0; i < Inbox::EVENT_CAPACITY; ++i) {
        EXPECT_EQ(out[i].type, InboxEventType::CONTROLLER_CLEARED);
        EXPECT_EQ(out[i].code, static_cast<uint8_t>(i));
    }
}

TEST(Inbox, ResetEventsEmptiesRingAndClearsBit) {
    Inbox inbox;

    for (int i = 0; i < 3; ++i) {
        InboxEvent event{};
        event.type = InboxEventType::COLOR_CLEARED;
        ASSERT_TRUE(inbox.push_event(event));
    }
    ASSERT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_EVENTS));

    inbox.reset_events();
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_EVENTS));

    InboxEvent out[4];
    EXPECT_EQ(inbox.take_events(out, 4), 0u);
}

TEST(Inbox, TimeResponsePayloadRoundtrips) {
    Inbox inbox;

    InboxEvent event{};
    event.type = InboxEventType::TIME_RESPONSE;
    event.time = TimeResponsePayload{/*offset=*/12345, /*max_error=*/678, /*timestamp=*/91011,
                                     /*source_id=*/42};
    ASSERT_TRUE(inbox.push_event(event));

    InboxEvent out[1];
    ASSERT_EQ(inbox.take_events(out, 1), 1u);
    EXPECT_EQ(out[0].type, InboxEventType::TIME_RESPONSE);
    EXPECT_EQ(out[0].time.offset, 12345);
    EXPECT_EQ(out[0].time.max_error, 678);
    EXPECT_EQ(out[0].time.timestamp, 91011);
    EXPECT_EQ(out[0].time.source_id, 42u);
}

// Concurrency smoke test: one producer thread interleaves slot merges and event pushes while the
// main thread polls and drains until it has observed everything the producer sent. Overflow
// (drop-newest) is allowed to happen -- the producer only counts pushes that actually succeeded,
// so the assertions hold whether or not the ring ever fills up under scheduling pressure.
TEST(Inbox, ConcurrentProducerDrainedWithoutLossOrDuplication) {
    constexpr int kIterations = 10000;

    Inbox inbox;
    InboxSlot<int64_t> counter_slot(inbox, INBOX_TOPIC_METADATA);

    std::atomic<uint64_t> produced_merges{0};
    std::atomic<uint64_t> produced_events{0};
    std::atomic<bool> producer_done{false};

    std::thread producer([&] {
        auto sum_merge = [](int64_t& current, int64_t&& delta) { current += delta; };
        uint64_t next_seq = 0;
        for (int i = 0; i < kIterations; ++i) {
            if ((i % 2) == 0) {
                counter_slot.merge(sum_merge, int64_t{1});
                produced_merges.fetch_add(1, std::memory_order_relaxed);
            } else {
                InboxEvent event{};
                event.type = InboxEventType::TIME_RESPONSE;
                event.time = TimeResponsePayload{0, 0, 0, next_seq};
                ++next_seq;
                if (inbox.push_event(event)) {
                    produced_events.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
        producer_done.store(true, std::memory_order_release);
    });

    int64_t drained_sum = 0;
    uint64_t drained_event_count = 0;
    bool have_last_seq = false;
    uint64_t last_seq = 0;

    InboxEvent batch[Inbox::EVENT_CAPACITY];
    for (;;) {
        bool did_work = false;
        const uint32_t bits = inbox.poll();

        if (has_bit(bits, INBOX_TOPIC_METADATA)) {
            int64_t value = 0;
            if (counter_slot.take(value)) {
                drained_sum += value;
                did_work = true;
            }
        }

        if (has_bit(bits, INBOX_TOPIC_EVENTS)) {
            size_t n = inbox.take_events(batch, Inbox::EVENT_CAPACITY);
            for (size_t i = 0; i < n; ++i) {
                ASSERT_EQ(batch[i].type, InboxEventType::TIME_RESPONSE);
                const uint64_t seq = batch[i].time.source_id;
                if (have_last_seq) {
                    ASSERT_GT(seq, last_seq) << "ring must deliver events in FIFO order with no "
                                                 "duplicates";
                }
                last_seq = seq;
                have_last_seq = true;
                ++drained_event_count;
            }
            if (n > 0) {
                did_work = true;
            }
        }

        if (!did_work) {
            // Nothing was pending this pass. Stop only once the producer has finished and a
            // fresh poll() still finds nothing, so a last-moment write cannot be missed.
            //
            // This is race-free across the two atomics: the producer sets every pending_ bit
            // (release RMW) before storing producer_done with release, so observing
            // producer_done == true here (acquire) synchronizes-with that store and makes all of
            // the producer's prior pending_ writes visible to the poll() sequenced after it. A
            // bit set right before the producer finished is therefore guaranteed to be seen by
            // this re-poll -- release/acquire publishes every prior write, not just the flag.
            if (producer_done.load(std::memory_order_acquire) && inbox.poll() == 0) {
                break;
            }
            std::this_thread::yield();
        }
    }

    producer.join();

    EXPECT_EQ(static_cast<uint64_t>(drained_sum), produced_merges.load());
    EXPECT_EQ(drained_event_count, produced_events.load());
}

}  // namespace
}  // namespace sendspin
