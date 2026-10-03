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
/// @brief Tests for the Inbox/InboxSlot primitives: slot write/take/merge semantics, the
/// generation-stamped slot and the teardown tracker, event ring FIFO and overflow behavior, and
/// a concurrent producer/consumer smoke test

#include "inbox.h"
#include "teardown_tracker.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <thread>

namespace sendspin {
namespace {

bool has_bit(uint32_t bits, uint32_t bit) {
    return (bits & bit) != 0;
}

// One slot's whole lifecycle: a clean slot holds nothing and sets no bit, a write publishes the
// value under this slot's topic bit alone, a take hands the value back and clears that bit, and
// reset drops both. The steps are one behavior because each is only meaningful against the state
// the previous one left.
TEST(InboxSlot, SlotLifecycle) {
    Inbox inbox;
    InboxSlot<int> slot(inbox, INBOX_TOPIC_GROUP);
    InboxSlot<int> other(inbox, INBOX_TOPIC_CONTROLLER);

    int value = -1;
    EXPECT_FALSE(slot.take(value)) << "a clean slot handed out content";
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));

    slot.write(42);
    other.write(7);
    EXPECT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));

    ASSERT_TRUE(slot.take(value));
    EXPECT_EQ(value, 42);
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));
    // Draining one slot leaves every other topic's bit standing, so the main loop still visits it.
    EXPECT_TRUE(has_bit(inbox.poll(), INBOX_TOPIC_CONTROLLER));

    slot.write(99);
    slot.reset();
    EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_GROUP));
    EXPECT_FALSE(slot.take(value)) << "reset left content behind";
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

// A GenerationSlot hands its payload out with the teardown generation it was written under, and
// keeps the newest generation's content: a write from a later generation replaces what is
// pending, one from an earlier generation (a producer that lost a race with a teardown) is
// dropped, and once the slot is taken any generation starts it afresh. Each row writes two deltas
// with an appending merge, so a replaced payload is told apart from a merged one.
TEST(GenerationSlot, KeepsTheNewestGenerationsContent) {
    struct Row {
        const char* name;
        uint32_t first;
        uint32_t second;
        bool take_between;
        int expected_value;
        uint32_t expected_generation;
    };
    const Row rows[] = {
        {"Control: same generation merges", 3, 3, false, 12, 3},
        {"a later generation replaces the pending payload", 3, 4, false, 2, 4},
        {"an earlier generation is dropped", 4, 3, false, 1, 4},
        {"an earlier generation is taken once the slot is clean", 4, 3, true, 2, 3},
        {"ordered across the counter's wrap", UINT32_MAX, 0, false, 2, 0},
    };
    const auto append = [](int& current, int&& delta) { current = current * 10 + delta; };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        Inbox inbox;
        GenerationSlot<int> slot;
        slot.bind(inbox, INBOX_TOPIC_CONTROLLER);
        int value = 0;
        uint32_t generation = 0;

        slot.merge(append, 1, row.first);
        if (row.take_between) {
            ASSERT_TRUE(slot.take(value, generation));
        }
        slot.merge(append, 2, row.second);

        ASSERT_TRUE(slot.take(value, generation));
        EXPECT_EQ(value, row.expected_value);
        EXPECT_EQ(generation, row.expected_generation);
        EXPECT_FALSE(has_bit(inbox.poll(), INBOX_TOPIC_CONTROLLER));
    }
}

// TeardownTracker::advance() reports a teardown generation pending exactly once, so a role's
// main-loop half runs once per teardown however many paths (stamped events, slot payloads) carry
// that generation, and never for a generation a later catch-up already passed.
TEST(TeardownTracker, AdvancesOncePerGenerationAndNeverBackwards) {
    TeardownTracker tracker;
    EXPECT_FALSE(tracker.advance(0)) << "Control: a role never torn down has nothing pending";
    EXPECT_TRUE(tracker.advance(1));
    EXPECT_FALSE(tracker.advance(1)) << "the same teardown caught up twice";
    EXPECT_TRUE(tracker.advance(3)) << "two teardowns between catch-ups collapse into one";
    EXPECT_FALSE(tracker.advance(2)) << "an older stamp caught up after a newer one";
    EXPECT_TRUE(tracker.pending(4));
    EXPECT_FALSE(tracker.pending(3));
}

// The epoch a producer stamps must reach the consumer per event, not per ring: it is what
// event_is_current() compares against, and an epoch that did not survive the round trip would
// read as 0, which is the fail-open direction ("the role was never torn down").
TEST(Inbox, EventEpochRoundtripsPerEvent) {
    Inbox inbox;

    for (uint32_t epoch : {7U, 0U, 8U}) {
        InboxEvent event{};
        event.type = InboxEventType::PLAYER_STREAM;
        event.epoch = epoch;
        ASSERT_TRUE(inbox.push_event(event)) << "epoch=" << epoch;
    }

    InboxEvent out[3];
    ASSERT_EQ(inbox.take_events(out, 3), 3u);
    EXPECT_EQ(out[0].epoch, 7u);
    EXPECT_EQ(out[1].epoch, 0u);
    EXPECT_EQ(out[2].epoch, 8u);
}

// push_event_or_log() stamps the epoch its caller passes, and event_is_current() admits only the
// event whose epoch still matches the role's teardown generation. Together they are the discard
// that keeps a lifecycle event queued before a teardown from acting after it; the dispatch that
// acts on the predicate is covered by
// RoleDeactivation.StreamStartQueuedBeforeARemovalNeverStarts.
TEST(Inbox, OnlyTheEventStampedWithTheCurrentGenerationPassesTheCurrencyCheck) {
    Inbox inbox;

    push_event_or_log(&inbox, InboxEventType::PLAYER_STREAM, /*code=*/1, "test", "STREAM_START",
                      /*epoch=*/4);
    push_event_or_log(&inbox, InboxEventType::PLAYER_STREAM, /*code=*/2, "test", "STREAM_END",
                      /*epoch=*/5);

    InboxEvent out[2];
    ASSERT_EQ(inbox.take_events(out, 2), 2u);
    EXPECT_EQ(out[0].epoch, 4u);
    EXPECT_EQ(out[1].epoch, 5u);

    // The role has since been torn down once, so its generation is 5.
    EXPECT_FALSE(event_is_current(out[0].epoch, /*role_epoch=*/5, "test", "STREAM_START"));
    // Control: the event queued after that teardown is dispatched.
    EXPECT_TRUE(event_is_current(out[1].epoch, /*role_epoch=*/5, "test", "STREAM_END"));
}

// Concurrency smoke test: one producer thread interleaves slot merges and event pushes while the
// main thread polls and drains until it has observed everything the producer sent. Overflow
// (drop-newest) is allowed to happen: the producer only counts pushes that actually succeeded,
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
        uint32_t next_seq = 0;
        for (int i = 0; i < kIterations; ++i) {
            if ((i % 2) == 0) {
                counter_slot.merge(sum_merge, int64_t{1});
                produced_merges.fetch_add(1, std::memory_order_relaxed);
            } else {
                InboxEvent event{};
                event.type = InboxEventType::PLAYER_STREAM;
                event.epoch = next_seq;  // Carries the sequence number the drain checks
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
    uint32_t last_seq = 0;

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
                ASSERT_EQ(batch[i].type, InboxEventType::PLAYER_STREAM);
                const uint32_t seq = batch[i].epoch;
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
            // this re-poll: release/acquire publishes every prior write, not just the flag.
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
