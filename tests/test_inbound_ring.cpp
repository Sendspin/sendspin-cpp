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

/// @file test_inbound_ring.cpp
/// @brief Tests for the shared inbound ring's pieces: InboundRing's take after a wrap and its
/// quota charge and return path, the intrusive per-consumer item list (order, blocking take,
/// wake, recall), the outstanding-byte quota, the per-connection gate, and the ring size
/// derivation

#include "inbound_ring.h"
#include "sendspin/config.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <thread>
#include <vector>

namespace sendspin {
namespace {

// How long a test lets another thread reach its blocking call before triggering what should end
// it. Ordering only: a thread that arrives late makes the test pass without exercising the wake,
// never fail.
constexpr int PARK_MS = 50;

// Acquires an item as a transport does; the header is whatever acquire() leaves.
void* acquire_item(InboundRing& ring, size_t len) {
    return ring.acquire(len, 0);
}

// Writes, completes and takes one message of `len` bytes, as a transport and the protocol task
// would, tagging its header so it can be identified when it comes back out.
void* routed_item(InboundRing& ring, uint32_t tag, size_t len = 16) {
    void* item = ring.acquire(len, 0);
    EXPECT_NE(item, nullptr);
    if (item == nullptr) {
        return nullptr;
    }
    inbound_item_header(item)->generation = tag;
    ring.complete(item);
    size_t taken_len = 0;
    void* taken = ring.take(&taken_len, 0);
    EXPECT_EQ(taken, item);
    EXPECT_EQ(taken_len, len);
    return taken;
}

// A ring plus a list bound to it, the way a consumer pairing is set up.
struct Fixture {
    explicit Fixture(size_t ring_bytes) {
        EXPECT_TRUE(this->ring.create(ring_bytes, MemoryLocation::PREFER_EXTERNAL));
        EXPECT_TRUE(this->list.create(&this->ring));
    }
    InboundRing ring;
    InboundItemList list;
};

// After a wrap, take() never hands out the item at the start of the storage before its producer
// completes it, and nothing behind it is taken first. Trace: X sits at the tail, Y wraps to the
// start, Z follows Y; X and Z are completed while Y is still being written. On host the
// SharedRingBuffer refuses Y itself, so this test does not run InboundRing's count of
// completions at the storage start: that path, the one ESP depends on, runs only when the host
// check is removed (as a mutation check does) and is otherwise an untested ESP gap.
TEST(InboundRing, TakeHoldsBackAWrappedItemUntilItIsCompleted) {
    constexpr size_t RING_BYTES = 264;
    InboundRing ring;
    ASSERT_TRUE(ring.create(RING_BYTES, MemoryLocation::PREFER_EXTERNAL));
    size_t len = 0;

    // A and B store 108 bytes each, leaving a 48-byte tail.
    void* a = acquire_item(ring, 72);
    void* b = acquire_item(ring, 72);
    ring.complete(a);
    ring.complete(b);
    ASSERT_EQ(ring.take(&len, 0), a);
    ring.return_item(a);

    void* x = acquire_item(ring, 4);   // 40 stored, at the tail
    void* y = acquire_item(ring, 32);  // 68 stored: does not fit the 8 bytes left, wraps
    void* z = acquire_item(ring, 0);   // behind Y
    ASSERT_NE(x, nullptr);
    ASSERT_NE(y, nullptr);
    ASSERT_NE(z, nullptr);
    ASSERT_EQ(static_cast<uint8_t*>(y), ring.storage() + SharedRingLayout::ITEM_HEADER_BYTES);

    ASSERT_EQ(ring.take(&len, 0), b);
    ring.return_item(b);
    ring.complete(x);
    EXPECT_EQ(ring.take(&len, 0), x);
    ring.complete(z);

    EXPECT_EQ(ring.take(&len, 0), nullptr) << "Y is still being written";
    EXPECT_EQ(ring.take(&len, 0), nullptr) << "and Z must not overtake it";
    ring.complete(y);
    EXPECT_EQ(ring.take(&len, 0), y);
    EXPECT_EQ(len, 32U);
    EXPECT_EQ(ring.take(&len, 0), z);
    EXPECT_EQ(len, 0U);
}

// acquire() hands out a zeroed header even where the storage holds stale bytes, so an item the
// protocol task never charged releases nothing when it is returned. The storage is filled with
// garbage while the ring is empty, which on a device is what earlier items leave behind.
TEST(InboundRing, AcquireZeroesTheHeaderOverStaleStorage) {
    constexpr size_t RING_BYTES = 1024;
    InboundRing ring;
    ASSERT_TRUE(ring.create(RING_BYTES, MemoryLocation::PREFER_EXTERNAL));
    ring.quota(InboundHolder::PLAYER).set_limit(RING_BYTES);
    ring.quota(InboundHolder::VISUALIZER).set_limit(RING_BYTES);
    std::memset(ring.storage(), 0xA5, RING_BYTES);

    void* item = ring.acquire(16, 0);
    ASSERT_NE(item, nullptr);
    const InboundItemHeader zero{};
    EXPECT_EQ(std::memcmp(inbound_item_header(item), &zero, sizeof(zero)), 0);

    ring.complete(item);
    size_t len = 0;
    ASSERT_EQ(ring.take(&len, 0), item);
    ring.return_item(item);
    EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(), 0U);
    EXPECT_EQ(ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U);
}

// An item the transport marked DISCARD is completed like any other but never handed out: take()
// returns it to the ring and hands out the next one. Control: the BINARY item behind it.
TEST(InboundRing, TakeReturnsDiscardedItemsWithoutHandingThemOut) {
    constexpr size_t RING_BYTES = 512;
    InboundRing ring;
    ASSERT_TRUE(ring.create(RING_BYTES, MemoryLocation::PREFER_EXTERNAL));
    void* discarded = ring.acquire(100, 0);
    void* kept = ring.acquire(100, 0);
    ASSERT_NE(discarded, nullptr);
    ASSERT_NE(kept, nullptr);
    inbound_item_header(discarded)->kind = InboundKind::DISCARD;
    inbound_item_header(kept)->kind = InboundKind::BINARY;
    ring.complete(discarded);
    ring.complete(kept);

    size_t len = 0;
    EXPECT_EQ(ring.take(&len, 0), kept) << "Control";
    EXPECT_EQ(ring.take(&len, 0), nullptr);
    ring.return_item(kept);
    // Both are reclaimed: the largest item the ring accepts fits again.
    EXPECT_NE(ring.acquire(SharedRingLayout::max_item_size(RING_BYTES) - sizeof(InboundItemHeader),
                           0),
              nullptr);
}

// reset() returns every item still in the ring, so a restart begins with all of it free.
// Control: before the reset the queued items pin the ring.
TEST(InboundRing, ResetReturnsEverythingStillQueued) {
    constexpr size_t RING_BYTES = 512;
    InboundRing ring;
    ASSERT_TRUE(ring.create(RING_BYTES, MemoryLocation::PREFER_EXTERNAL));
    for (int i = 0; i < 3; ++i) {
        void* item = ring.acquire(60, 0);
        ASSERT_NE(item, nullptr);
        ring.complete(item);
    }
    const size_t largest = SharedRingLayout::max_item_size(RING_BYTES) - sizeof(InboundItemHeader);
    EXPECT_EQ(ring.acquire(largest, 0), nullptr) << "Control";

    ring.reset();
    EXPECT_EQ(ring.items_waiting(), 0U);
    EXPECT_NE(ring.acquire(largest, 0), nullptr);
}

// charge() admits an item only while its holder is within quota, records the charge in the item,
// and return_item() releases exactly that charge. Rows walk one ring through a sequence; the
// quota is sized for two 16-byte items (52 stored bytes each).
TEST(InboundRing, ChargeAndReturnKeepTheHolderQuotaExact) {
    constexpr size_t STORED = SharedRingLayout::stored_size(sizeof(InboundItemHeader) + 16);
    Fixture f(1024);
    f.ring.quota(InboundHolder::PLAYER).set_limit(2 * STORED);
    f.ring.quota(InboundHolder::VISUALIZER).set_limit(STORED);

    void* first = routed_item(f.ring, 1);
    void* second = routed_item(f.ring, 2);
    void* third = routed_item(f.ring, 3);
    void* vis = routed_item(f.ring, 4);

    EXPECT_TRUE(f.ring.charge(first, 16, InboundHolder::PLAYER)) << "Control: within quota";
    EXPECT_EQ(inbound_item_header(first)->charge, STORED);
    EXPECT_TRUE(f.ring.charge(second, 16, InboundHolder::PLAYER));
    EXPECT_FALSE(f.ring.charge(third, 16, InboundHolder::PLAYER)) << "player over quota";
    EXPECT_TRUE(f.ring.charge(vis, 16, InboundHolder::VISUALIZER))
        << "another holder keeps flowing";
    EXPECT_EQ(f.ring.quota(InboundHolder::PLAYER).outstanding(), 2 * STORED);

    f.ring.return_item(third);  // never charged: releases nothing
    EXPECT_EQ(f.ring.quota(InboundHolder::PLAYER).outstanding(), 2 * STORED);
    f.ring.return_item(first);
    EXPECT_EQ(f.ring.quota(InboundHolder::PLAYER).outstanding(), STORED);
    f.ring.return_item(vis);
    EXPECT_EQ(f.ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U);
    f.ring.return_item(second);
    EXPECT_EQ(f.ring.quota(InboundHolder::PLAYER).outstanding(), 0U);
}

// Items come out of the list in the order the protocol task appended them, each the ring item
// itself (no copy), with the consumer fields it was given.
TEST(InboundItemList, TakesItemsInAppendOrder) {
    Fixture f(1024);
    std::vector<void*> appended;
    for (uint32_t tag = 1; tag <= 4; ++tag) {
        appended.push_back(routed_item(f.ring, tag));
        f.list.append(appended.back());
    }
    for (uint32_t tag = 1; tag <= 4; ++tag) {
        void* item = f.list.take(0);
        ASSERT_EQ(item, appended[tag - 1]);
        EXPECT_EQ(inbound_item_header(item)->generation, tag);
        f.ring.return_item(item);
    }
    EXPECT_EQ(f.list.take(0), nullptr);
    EXPECT_TRUE(f.list.is_empty());
}

// A take waiting on an empty list returns the item appended from another thread. The future has
// no timeout: an append that does not wake the consumer hangs here and the watchdog names it.
TEST(InboundItemList, BlockingTakeReceivesAnItemAppendedLater) {
    Fixture f(1024);
    void* item = routed_item(f.ring, 7);
    std::future<void*> taken = std::async(std::launch::async, [&] {
        void* got = nullptr;
        while (got == nullptr) {
            got = f.list.take(UINT32_MAX);
        }
        return got;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(PARK_MS));
    f.list.append(item);
    EXPECT_EQ(taken.get(), item);
}

// wake_receiver() ends a blocking take on an empty list with nothing; the join has no timeout.
TEST(InboundItemList, WakeReceiverEndsABlockingTake) {
    Fixture f(1024);
    void* got = reinterpret_cast<void*>(1);  // poisoned so a take that never ran is visible
    std::thread consumer([&] { got = f.list.take(UINT32_MAX); });
    std::this_thread::sleep_for(std::chrono::milliseconds(PARK_MS));
    f.list.wake_receiver();
    consumer.join();
    EXPECT_EQ(got, nullptr);
}

// recall() unlinks every item not yet taken and returns each through the ring's return path:
// the space is reclaimed (with an unlisted item returned at once between them, as a JSON message
// is, recalling the listed items frees the whole ring) and their quota charges are released.
// Control: before the recall the held items pin the ring.
TEST(InboundItemList, RecallReturnsEveryLinkedItemAndReleasesItsCharge) {
    constexpr size_t RING_BYTES = 512;
    // Three items of 112 stored bytes leave a 176-byte tail, too small for the largest item,
    // which can then only go to the start once the oldest items are reclaimed.
    constexpr size_t LEN = 76;
    Fixture f(RING_BYTES);
    f.ring.quota(InboundHolder::PLAYER).set_limit(RING_BYTES);
    void* first = routed_item(f.ring, 1, LEN);
    void* passthrough = routed_item(f.ring, 2, LEN);
    void* second = routed_item(f.ring, 3, LEN);
    ASSERT_TRUE(f.ring.charge(first, LEN, InboundHolder::PLAYER));
    ASSERT_TRUE(f.ring.charge(second, LEN, InboundHolder::PLAYER));
    f.list.append(first);
    f.list.append(second);
    f.ring.return_item(passthrough);

    const size_t largest = SharedRingLayout::max_item_size(RING_BYTES) - sizeof(InboundItemHeader);
    EXPECT_EQ(f.ring.acquire(largest, 0), nullptr) << "Control: the held items pin the ring";

    EXPECT_EQ(f.list.recall(), 2U);
    EXPECT_TRUE(f.list.is_empty());
    EXPECT_EQ(f.list.take(0), nullptr);
    EXPECT_EQ(f.ring.quota(InboundHolder::PLAYER).outstanding(), 0U);
    EXPECT_NE(f.ring.acquire(largest, 0), nullptr);
}

// A recall leaves the list usable: an item appended afterwards is taken normally.
TEST(InboundItemList, AppendAfterRecallStartsAFreshList) {
    Fixture f(1024);
    f.list.append(routed_item(f.ring, 1));
    ASSERT_EQ(f.list.recall(), 1U);
    void* item = routed_item(f.ring, 2);
    f.list.append(item);
    EXPECT_EQ(f.list.take(0), item);
}

// The quota admits a charge only while the outstanding total stays within the limit, and a
// release makes room again. One table walks a single quota through a sequence of operations.
TEST(InboundQuota, ChargesWithinTheLimitOnly) {
    enum class Op { CHARGE, RELEASE };
    struct Row {
        const char* name;
        Op op;
        size_t bytes;
        bool accepted;  // CHARGE only
        size_t outstanding_after;
    };
    const std::vector<Row> rows = {
        {"Control: charge below the limit", Op::CHARGE, 60, true, 60},
        {"charge up to exactly the limit", Op::CHARGE, 40, true, 100},
        {"one byte over the limit", Op::CHARGE, 1, false, 100},
        {"release part", Op::RELEASE, 40, true, 60},
        {"charge that would cross the limit", Op::CHARGE, 41, false, 60},
        {"charge that fits again", Op::CHARGE, 40, true, 100},
        {"release all", Op::RELEASE, 100, true, 0},
        {"single charge larger than the limit", Op::CHARGE, 101, false, 0},
    };
    InboundQuota quota(100);
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        if (row.op == Op::CHARGE) {
            EXPECT_EQ(quota.try_charge(row.bytes), row.accepted);
        } else {
            quota.release(row.bytes);
        }
        EXPECT_EQ(quota.outstanding(), row.outstanding_after);
    }
}

// Concurrent charges and releases never let the outstanding total past the limit and leave it at
// zero once every charge is released. Under TSan this also proves the accounting race-free.
TEST(InboundQuota, ConcurrentChargesNeverExceedTheLimit) {
    constexpr size_t LIMIT = 1000;
    constexpr size_t CHARGE = 30;
    InboundQuota quota(LIMIT);
    std::atomic<bool> exceeded{false};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 5000; ++i) {
                if (quota.try_charge(CHARGE)) {
                    if (quota.outstanding() > LIMIT) {
                        exceeded = true;
                    }
                    quota.release(CHARGE);
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    EXPECT_FALSE(exceeded.load());
    EXPECT_EQ(quota.outstanding(), 0U);
}

// While a pre-admission message is pending the transport may write nowhere: a second publish
// and a ring write are refused until the protocol task consumes it. Control: a fresh gate
// accepts both.
TEST(InboundGate, NothingIsWrittenWhileAPreAdmissionMessageIsPending) {
    InboundGate gate;
    EXPECT_TRUE(gate.may_write()) << "Control";
    EXPECT_TRUE(gate.begin_ring_write()) << "Control";
    gate.note_item_taken();

    EXPECT_TRUE(gate.publish_pending_message());
    EXPECT_TRUE(gate.has_pending_message());
    EXPECT_FALSE(gate.may_write());
    EXPECT_FALSE(gate.publish_pending_message());
    EXPECT_FALSE(gate.begin_ring_write());
    EXPECT_EQ(gate.in_flight(), 0U);

    gate.consume_pending_message();
    EXPECT_FALSE(gate.has_pending_message());
    EXPECT_TRUE(gate.may_write());
    EXPECT_TRUE(gate.begin_ring_write());
    EXPECT_EQ(gate.in_flight(), 1U);
}

// A pre-admission message is accepted up to PRE_ADMISSION_MESSAGE_BYTES and refused past it.
TEST(InboundGate, PreAdmissionMessageCap) {
    struct Row {
        const char* name;
        size_t len;
        bool fits;
    };
    const std::vector<Row> rows = {
        {"Control: a small message", 64, true},
        {"exactly the cap", InboundGate::PRE_ADMISSION_MESSAGE_BYTES, true},
        {"one byte past the cap", InboundGate::PRE_ADMISSION_MESSAGE_BYTES + 1, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(InboundGate::pre_admission_message_fits(row.len), row.fits);
    }
}

// An indefinite wait survives a CONSUMED bit left over from the previous message (the protocol
// task cleared the pending flag, the transport published again, then the task's bit landed): it
// keeps waiting until the new message is actually consumed, and never returns false. The late
// bit is set directly, since the interleaving that leaves it cannot be staged through the public
// surface (hence -fno-access-control for this file). The join has no timeout; the sleep only
// makes it likely the waiter has already absorbed the leftover bit before the consume.
TEST(InboundGate, IndefiniteWaitOutlastsALeftoverConsumedBit) {
    InboundGate gate;
    ASSERT_TRUE(gate.is_created());
    ASSERT_TRUE(gate.publish_pending_message());
    gate.consumed_flags_.set(InboundGate::CONSUMED);

    std::atomic<bool> returned{false};
    bool writable = false;
    std::thread transport([&] {
        writable = gate.wait_until_writable(UINT32_MAX);
        returned = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(PARK_MS));
    EXPECT_FALSE(returned.load()) << "the leftover bit ended the wait";
    gate.consume_pending_message();
    transport.join();
    EXPECT_TRUE(writable);
}

// A transport waiting for its pending message to be consumed is woken by the consume. The join
// has no timeout: a consume that does not wake it hangs here and the watchdog names the test.
TEST(InboundGate, ConsumeWakesATransportWaitingToWrite) {
    InboundGate gate;
    ASSERT_TRUE(gate.publish_pending_message());
    bool writable = false;
    std::thread transport([&] { writable = gate.wait_until_writable(UINT32_MAX); });
    std::this_thread::sleep_for(std::chrono::milliseconds(PARK_MS));
    gate.consume_pending_message();
    transport.join();
    EXPECT_TRUE(writable);

    // A consume left over from that message does not end the next message's wait early.
    ASSERT_TRUE(gate.publish_pending_message());
    EXPECT_FALSE(gate.wait_until_writable(0));
    EXPECT_FALSE(gate.wait_until_writable(1));
}

// A transport close is honoured only once the flag is set, every ring item the transport began
// has been taken (a failed acquire counts as never begun), and no pre-admission message waits.
TEST(InboundGate, CloseIsHonouredOnlyOnceNothingIsInFlight) {
    struct Row {
        const char* name;
        int begun;
        int abandoned;
        int taken;
        bool pending;
        bool closed;
        bool ready;
    };
    const std::vector<Row> rows = {
        {"Control: closed, everything taken", 2, 0, 2, false, true, true},
        {"not closed", 0, 0, 0, false, false, false},
        {"closed with an item not yet taken", 2, 0, 1, false, true, false},
        {"closed with an item begun and abandoned", 2, 1, 1, false, true, true},
        {"closed with a pre-admission message waiting", 0, 0, 0, true, true, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundGate gate;
        for (int i = 0; i < row.begun; ++i) {
            gate.begin_ring_write();
        }
        for (int i = 0; i < row.abandoned; ++i) {
            gate.abandon_ring_write();
        }
        for (int i = 0; i < row.taken; ++i) {
            gate.note_item_taken();
        }
        if (row.pending) {
            gate.publish_pending_message();
        }
        if (row.closed) {
            gate.mark_transport_closed();
        }
        EXPECT_EQ(gate.close_ready(), row.ready);
    }
}

// The buffers a shared ring stands in for, at their worst case: each open connection's
// WebSocket payload buffer grown to one maximal message, a player encoded ring of
// audio_hold_bytes, and a visualizer frame ring of visualizer_hold_bytes.
constexpr size_t separate_inbound_buffer_bytes(const InboundRingBudget& budget,
                                               size_t open_connections) {
    return budget.audio_hold_bytes + budget.visualizer_hold_bytes +
           open_connections * INBOUND_MAX_MESSAGE_BYTES;
}

// The derived ring always satisfies the FreeRTOS storage rule, accepts a maximal message, holds
// every term of the derivation, and stays within the separate per-role and per-connection buffers
// for the same configuration at the default connection budget. Rows cover each role mix; the
// first is the controller-only floor.
TEST(InboundRingSize, DerivationIsValidAndWithinTheSeparateBuffers) {
    constexpr size_t OPEN_CONNECTIONS = SendspinClientConfig::DEFAULT_SERVER_MAX_CONNECTIONS;
    struct Row {
        const char* name;
        InboundRingBudget budget;
    };
    const std::vector<Row> rows = {
        {"Control: no holding role, no artwork", {0, 0, 0}},
        {"default player", {PlayerRoleConfig::DEFAULT_AUDIO_BUFFER_CAPACITY, 0, 0}},
        {"default player and artwork",
         {PlayerRoleConfig::DEFAULT_AUDIO_BUFFER_CAPACITY, 0,
          ImageSlotPreference::DEFAULT_MAX_IMAGE_BYTES}},
        {"small player, visualizer, artwork", {100000, 8192, 64 * 1024}},
        {"player size not a multiple of 4", {100001, 0, 0}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        const size_t bytes = derive_inbound_ring_bytes(row.budget);
        EXPECT_EQ(bytes % SharedRingLayout::STORAGE_ALIGNMENT, 0U);
        EXPECT_GE(SharedRingLayout::max_item_size(bytes),
                  sizeof(InboundItemHeader) + INBOUND_MAX_MESSAGE_BYTES);
        const size_t passthrough = row.budget.largest_image_bytes > 0
                                       ? row.budget.largest_image_bytes
                                       : INBOUND_PASSTHROUGH_MESSAGES * INBOUND_MAX_ITEM_STORED_BYTES;
        EXPECT_GE(bytes,
                  row.budget.audio_hold_bytes + row.budget.visualizer_hold_bytes + passthrough);
        EXPECT_LE(bytes, separate_inbound_buffer_bytes(row.budget, OPEN_CONNECTIONS));

        InboundRing ring;
        EXPECT_TRUE(ring.create(bytes, MemoryLocation::PREFER_EXTERNAL));
    }
}

// A run of frames is stored as whole items: each maximal frame and the final partial one pays
// its own header, tag and alignment. Control: a payload of zero needs no frame.
TEST(InboundRingSize, FramesAreStoredAsWholeItems) {
    constexpr size_t PER_FRAME = MAX_TRANSPORT_PLAINTEXT - INBOUND_ROLE_HEADER_ALLOWANCE;
    constexpr size_t OVERHEAD =
        sizeof(InboundItemHeader) + AEAD_TAG_SIZE + INBOUND_ROLE_HEADER_ALLOWANCE;
    EXPECT_EQ(inbound_frames_stored_bytes(0), 0U);
    EXPECT_EQ(inbound_frames_stored_bytes(1), SharedRingLayout::stored_size(1 + OVERHEAD));
    EXPECT_EQ(inbound_frames_stored_bytes(PER_FRAME),
              SharedRingLayout::stored_size(PER_FRAME + OVERHEAD));
    EXPECT_EQ(inbound_frames_stored_bytes(PER_FRAME + 3),
              SharedRingLayout::stored_size(PER_FRAME + OVERHEAD) +
                  SharedRingLayout::stored_size(3 + OVERHEAD));
}

}  // namespace
}  // namespace sendspin
