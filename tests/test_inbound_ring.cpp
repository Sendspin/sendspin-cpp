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
/// wake, recall), a consumer's hand-overs, the outstanding-byte quota, the per-connection gate,
/// and the ring size derivation

#include "inbound_ring.h"
#include "sendspin/config.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
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
        EXPECT_TRUE(this->list.create(&this->ring, InboundHolder::PLAYER));
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
    void* a = acquire_item(ring, 68);
    void* b = acquire_item(ring, 68);
    ring.complete(a);
    ring.complete(b);
    ASSERT_EQ(ring.take(&len, 0), a);
    ring.return_item(a);

    void* x = acquire_item(ring, 4);   // 44 stored, at the tail
    void* y = acquire_item(ring, 28);  // 68 stored: does not fit the 4 bytes left, wraps
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
    EXPECT_EQ(len, 28U);
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

// A LOCAL item (one the protocol task wrote itself) goes back to the ring only on the second of
// its two returns: the protocol task's take in ring order and its holder's return, in either
// order. Its quota charge is released on the holder's return, whichever comes first, so the
// quota never counts an item its holder is done with. Two pass-through items written behind it
// are returned at once, so only the LOCAL item can keep the largest item from fitting (three
// 112-byte items leave a 176-byte tail).
TEST(InboundRing, ALocalItemGoesBackOnItsSecondReturn) {
    constexpr size_t RING_BYTES = 512;
    constexpr size_t LEN = 72;
    struct Row {
        const char* name;
        bool holder_first;
        bool charged;
    };
    const Row rows[] = {
        {"holder returns first", true, true},
        {"take comes first", false, true},
        {"never charged (both parties are the protocol task)", true, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        Fixture f(RING_BYTES);
        f.ring.quota(InboundHolder::PLAYER).set_limit(RING_BYTES);
        const size_t largest =
            SharedRingLayout::max_item_size(RING_BYTES) - sizeof(InboundItemHeader);

        void* local = f.ring.acquire_local(LEN, 0);
        ASSERT_NE(local, nullptr);
        EXPECT_EQ(inbound_item_header(local)->kind, InboundKind::LOCAL);
        f.ring.complete(local);
        if (row.charged) {
            ASSERT_TRUE(f.ring.charge(local, LEN, InboundHolder::PLAYER, false));
        }
        void* passthrough[2] = {f.ring.acquire(LEN, 0), f.ring.acquire(LEN, 0)};
        for (void* item : passthrough) {
            ASSERT_NE(item, nullptr);
            f.ring.complete(item);
        }
        // The protocol task's pass: the LOCAL item is counted, never handed out.
        const auto take_in_order = [&] {
            size_t len = 0;
            for (void* expected : passthrough) {
                EXPECT_EQ(f.ring.take(&len, 0), expected);
                f.ring.return_item(expected);
            }
        };

        if (row.holder_first) {
            f.ring.return_item(local);
            EXPECT_EQ(inbound_item_header(local)->local_returns, 1U);
            EXPECT_EQ(f.ring.quota(InboundHolder::PLAYER).outstanding(), 0U)
                << "the holder's return releases the charge";
            take_in_order();
        } else {
            take_in_order();
            EXPECT_EQ(inbound_item_header(local)->local_returns, 1U);
            EXPECT_EQ(f.ring.quota(InboundHolder::PLAYER).outstanding() > 0, row.charged)
                << "the take does not release the holder's charge";
            EXPECT_EQ(f.ring.acquire(largest, 0), nullptr) << "one return is not enough";
            f.ring.return_item(local);
            EXPECT_EQ(f.ring.quota(InboundHolder::PLAYER).outstanding(), 0U);
        }
        EXPECT_NE(f.ring.acquire(largest, 0), nullptr) << "the second return reclaims it";
    }
}

// reset() supplies the protocol task's half of a LOCAL item's two returns: an item its holder
// returned but the task never reached in ring order is reclaimed. Control: before the reset the
// queued items pin the ring.
TEST(InboundRing, ResetSuppliesTheMissingHalfOfALocalItem) {
    constexpr size_t RING_BYTES = 512;
    constexpr size_t LEN = 72;
    Fixture f(RING_BYTES);
    f.ring.quota(InboundHolder::PLAYER).set_limit(RING_BYTES);
    const size_t largest = SharedRingLayout::max_item_size(RING_BYTES) - sizeof(InboundItemHeader);

    void* local = f.ring.acquire_local(LEN, 0);
    ASSERT_NE(local, nullptr);
    f.ring.complete(local);
    ASSERT_TRUE(f.ring.charge(local, LEN, InboundHolder::PLAYER, false));
    for (int i = 0; i < 2; ++i) {
        void* item = f.ring.acquire(LEN, 0);
        ASSERT_NE(item, nullptr);
        f.ring.complete(item);
    }
    f.ring.return_item(local);
    EXPECT_EQ(f.ring.acquire(largest, 0), nullptr) << "Control: the queued items pin the ring";

    f.ring.reset();
    EXPECT_NE(f.ring.acquire(largest, 0), nullptr);
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
    size_t len = 0;
    EXPECT_EQ(ring.take(&len, 0), nullptr);
    EXPECT_NE(ring.acquire(largest, 0), nullptr);
}

// charge() admits an item only while its holder is within quota, records the charge in the item,
// and return_item() releases exactly that charge; the quota underneath admits a charge only while
// the outstanding total stays within the limit, to the byte, and a release makes room again. One
// table walks one ring through a sequence: the player's quota is sized for two 16-byte items, the
// visualizer's for one, and the TRY/RELEASE rows drive the player's quota directly for the
// byte-granular boundaries a stored item size cannot reach.
TEST(InboundRing, ChargeAndReturnKeepTheHolderQuotaExact) {
    constexpr size_t STORED = SharedRingLayout::stored_size(sizeof(InboundItemHeader) + 16);
    enum class Op : uint8_t { CHARGE, RETURN, TRY, RELEASE };
    struct Row {
        const char* name;
        Op op;
        size_t item;  // CHARGE, RETURN: index into `items`
        InboundHolder holder;
        bool exempt;
        size_t bytes;   // TRY, RELEASE
        bool accepted;  // CHARGE, TRY
        size_t player_after;
        size_t visualizer_after;
    };
    constexpr InboundHolder PLAYER = InboundHolder::PLAYER;
    constexpr InboundHolder VISUALIZER = InboundHolder::VISUALIZER;
    const Row rows[] = {
        {"Control: an item within the quota is charged", Op::CHARGE, 0, PLAYER, false, 0, true,
         STORED, 0},
        {"a charge up to exactly the limit", Op::CHARGE, 1, PLAYER, false, 0, true, 2 * STORED, 0},
        {"an item over the quota is refused", Op::CHARGE, 2, PLAYER, false, 0, false, 2 * STORED,
         0},
        {"one byte over the limit is refused", Op::TRY, 0, PLAYER, false, 1, false, 2 * STORED, 0},
        {"another holder keeps flowing", Op::CHARGE, 3, VISUALIZER, false, 0, true, 2 * STORED,
         STORED},
        {"an exempt item passes a holder over its quota, uncharged", Op::CHARGE, 2, PLAYER, true, 0,
         true, 2 * STORED, STORED},
        {"returning the exempt item releases nothing", Op::RETURN, 2, PLAYER, false, 0, true,
         2 * STORED, STORED},
        {"a return releases exactly its item's charge", Op::RETURN, 0, PLAYER, false, 0, true,
         STORED, STORED},
        {"a charge that would cross the limit is refused", Op::TRY, 0, PLAYER, false, STORED + 1,
         false, STORED, STORED},
        {"Control: a charge that fits again is admitted", Op::TRY, 0, PLAYER, false, STORED, true,
         2 * STORED, STORED},
        {"a release frees exactly its bytes", Op::RELEASE, 0, PLAYER, false, STORED, true, STORED,
         STORED},
        {"the other holder's return releases its own quota", Op::RETURN, 3, VISUALIZER, false, 0,
         true, STORED, 0},
        {"the last return empties the quota", Op::RETURN, 1, PLAYER, false, 0, true, 0, 0},
        {"a single charge larger than the limit is refused", Op::TRY, 0, PLAYER, false,
         2 * STORED + 1, false, 0, 0},
    };

    Fixture f(1024);
    InboundQuota& player = f.ring.quota(PLAYER);
    player.set_limit(2 * STORED);
    f.ring.quota(VISUALIZER).set_limit(STORED);
    void* items[] = {routed_item(f.ring, 1), routed_item(f.ring, 2), routed_item(f.ring, 3),
                     routed_item(f.ring, 4)};

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        switch (row.op) {
            case Op::CHARGE:
                EXPECT_EQ(f.ring.charge(items[row.item], 16, row.holder, row.exempt), row.accepted);
                if (row.accepted) {
                    EXPECT_EQ(inbound_item_header(items[row.item])->charge, row.exempt ? 0U : STORED)
                        << "the charge the item records, which its return releases";
                }
                break;
            case Op::RETURN:
                f.ring.return_item(items[row.item]);
                break;
            case Op::TRY:
                EXPECT_EQ(player.try_charge(row.bytes), row.accepted);
                break;
            case Op::RELEASE:
                player.release(row.bytes);
                break;
        }
        EXPECT_EQ(player.outstanding(), row.player_after);
        EXPECT_EQ(f.ring.quota(VISUALIZER).outstanding(), row.visualizer_after);
    }
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

// The list's flags are its consumer's one event group: signal() sets a consumer bit and ends a
// blocking take with nothing, and the bit stays pending for the consumer's own take_signals(),
// which reports it once. The list's own bits are not consumer signals, and clear_signals() (a
// start) drops a pending one. The blocking take has no timeout: a signal that does not wake it
// hangs here and the watchdog names it.
TEST(InboundItemList, ASignalEndsATakeAndStaysPendingForItsOwnWait) {
    constexpr uint32_t BIT = InboundItemList::FIRST_CONSUMER_BIT;
    enum class Step { NONE, SIGNAL, APPEND, SIGNAL_THEN_CLEAR };
    struct Row {
        const char* name;
        Step step;
        uint32_t first;
    };
    const Row rows[] = {
        {"Control: nothing signalled", Step::NONE, 0},
        {"a signal is reported once", Step::SIGNAL, BIT},
        {"an append is not a consumer signal", Step::APPEND, 0},
        {"clear_signals() drops a pending signal", Step::SIGNAL_THEN_CLEAR, 0},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        Fixture f(1024);
        switch (row.step) {
            case Step::NONE:
                break;
            case Step::SIGNAL:
                f.list.signal(BIT);
                EXPECT_EQ(f.list.take(UINT32_MAX), nullptr);
                break;
            case Step::APPEND:
                f.list.append(routed_item(f.ring, 1));
                break;
            case Step::SIGNAL_THEN_CLEAR:
                f.list.signal(BIT);
                f.list.clear_signals();
                break;
        }
        EXPECT_EQ(f.list.take_signals(BIT, 0), row.first);
        EXPECT_EQ(f.list.take_signals(BIT, 0), 0U) << "a signal was reported twice";
        f.list.recall();
    }
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
    ASSERT_TRUE(f.ring.charge(first, LEN, InboundHolder::PLAYER, false));
    ASSERT_TRUE(f.ring.charge(second, LEN, InboundHolder::PLAYER, false));
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

// unbind() unregisters a list from its ring before the list goes away. A LOCAL item its holder
// returned but the protocol task never took in ring order is counted on the ring's reset: through
// the holder's list while it is registered, directly once it is unbound. Without the unbind the
// reset reaches the destroyed list. The reset reclaiming the item is the Control.
TEST(InboundItemList, TheRingResetNeverReachesAnUnboundList) {
    constexpr size_t RING_BYTES = 512;
    constexpr size_t LEN = 72;
    InboundRing ring;
    ASSERT_TRUE(ring.create(RING_BYTES, MemoryLocation::PREFER_EXTERNAL));
    ring.quota(InboundHolder::PLAYER).set_limit(RING_BYTES);
    const size_t largest = SharedRingLayout::max_item_size(RING_BYTES) - sizeof(InboundItemHeader);

    auto list = std::make_unique<InboundItemList>();
    ASSERT_TRUE(list->create(&ring, InboundHolder::PLAYER));
    void* local = ring.acquire_local(LEN, 0);
    ASSERT_NE(local, nullptr);
    ring.complete(local);
    ASSERT_TRUE(ring.charge(local, LEN, InboundHolder::PLAYER, false));
    list->append(local);
    ASSERT_EQ(list->take(0), local);
    ring.return_item(local);  // the holder's return; the ring-order one never came

    list->unbind();  // what a role's stop() does once its consumer is joined
    list.reset();

    ring.reset();
    EXPECT_NE(ring.acquire(largest, 0), nullptr) << "Control: the reset reclaimed the item";
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

// InboundConsumer's hand-overs: hand_message() takes a received message's ring item over in place
// (no copy) and copies only a message that is not in a ring item, into a LOCAL item keeping its
// receive stamp; it charges the quota and drops, returning false with nothing charged or listed,
// a message too long for any item or over the quota. hand_local() hands its copy over exempt from
// the quota, and hands nothing while the consumer is bound to no ring (the bound row beside it is
// its control). Every handed item carries the caller's fields and generation.
TEST(InboundConsumer, HandMessageKeepsRingItemsAndCopiesTheRest) {
    constexpr size_t RING_BYTES = 1024;
    constexpr size_t LEN = 40;
    constexpr uint32_t GENERATION = 7;
    constexpr uint32_t RECEIVE_STAMP = 0x12345678;
    constexpr InboundItemFields FIELDS{.data_len = 30, .serial = 3, .type = 9, .data_offset = 10};
    enum class Source : uint8_t { RING_ITEM, OUTSIDE_THE_RING, TOO_LONG, HAND_LOCAL, UNBOUND };
    struct Row {
        const char* name;
        Source source;
        size_t quota;
        bool handed;
        bool in_place;  // the ring item itself was handed, rather than a LOCAL copy
        bool charged;
    };
    const Row rows[] = {
        {"Control: a ring item is handed in place", Source::RING_ITEM, RING_BYTES, true, true,
         true},
        {"a message outside the ring is copied into a LOCAL item", Source::OUTSIDE_THE_RING,
         RING_BYTES, true, false, true},
        {"a message longer than the ring's largest item is dropped", Source::TOO_LONG, RING_BYTES,
         false, false, false},
        {"a ring item over the quota is dropped", Source::RING_ITEM, 0, false, false, false},
        {"hand_local() passes a zero quota, exempt", Source::HAND_LOCAL, 0, true, false, false},
        {"hand_local() on a consumer never bound to a ring hands nothing", Source::UNBOUND, 0,
         false, false, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundRing ring;
        ASSERT_TRUE(ring.create(RING_BYTES, MemoryLocation::PREFER_EXTERNAL));
        ring.quota(InboundHolder::PLAYER).set_limit(row.quota);
        InboundConsumer consumer;
        const bool bound = row.source != Source::UNBOUND;
        if (bound) {
            ASSERT_TRUE(consumer.bind(&ring, InboundHolder::PLAYER));
        }

        const size_t len = row.source == Source::TOO_LONG ? ring.max_item_message_bytes() + 1 : LEN;
        std::vector<uint8_t> outside(len);
        for (size_t i = 0; i < len; ++i) {
            outside[i] = static_cast<uint8_t>(i);
        }
        void* ring_item = nullptr;
        bool handed = false;
        if (row.source == Source::HAND_LOCAL || row.source == Source::UNBOUND) {
            handed = consumer.hand_local(outside.data(), len, FIELDS, GENERATION);
        } else {
            InboundMessage message;
            if (row.source == Source::RING_ITEM) {
                ring_item = routed_item(ring, 0, LEN);
                ASSERT_NE(ring_item, nullptr);
                message.item = ring_item;
                message.item_len = LEN;
                message.data = inbound_item_bytes(ring_item);
            } else {
                message.data = outside.data();
            }
            message.len = len;
            message.receive_time_us = RECEIVE_STAMP;
            handed = consumer.hand_message(message, FIELDS, GENERATION);
            EXPECT_EQ(message.item, nullptr)
                << "a ring item is the consumer's to hand over or return, never the caller's";
        }
        EXPECT_EQ(handed, row.handed);
        EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding() > 0, row.charged)
            << ring.quota(InboundHolder::PLAYER).outstanding() << " bytes outstanding";

        void* taken = consumer.items().take(0);
        EXPECT_EQ(taken != nullptr, row.handed) << "only a handed message is listed";
        if (taken != nullptr) {
            const InboundItemHeader* header = inbound_item_header(taken);
            EXPECT_EQ(taken == ring_item, row.in_place);
            EXPECT_EQ(header->kind == InboundKind::LOCAL, !row.in_place);
            if (!row.in_place) {
                EXPECT_EQ(std::memcmp(inbound_item_bytes(taken), outside.data(), len), 0);
                EXPECT_EQ(header->receive_time_us,
                          row.source == Source::HAND_LOCAL ? 0U : RECEIVE_STAMP);
            }
            EXPECT_EQ(header->data_len, FIELDS.data_len);
            EXPECT_EQ(header->serial, FIELDS.serial);
            EXPECT_EQ(header->type, FIELDS.type);
            EXPECT_EQ(header->data_offset, FIELDS.data_offset);
            EXPECT_EQ(header->generation, GENERATION);
            consumer.return_item(taken);
            EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(), 0U);
        }
        if (bound) {
            consumer.unbind();
        }
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

// A transport parked waiting for its pending message to be consumed is released by the consume,
// and also by a detach: a connection released or stopped while its transport waits detaches the
// gate before anything joins the transport thread, and the detach ends the wait so the join
// completes. The wait has no timeout and neither has the join: a consume or a detach that does
// not wake the transport hangs here and the watchdog names the test. The consume row is the
// Control: only it leaves the transport free to write.
TEST(InboundGate, AConsumeOrADetachReleasesATransportWaitingToWrite) {
    struct Row {
        const char* name;
        bool detach;
        bool expected_writable;
    };
    const Row rows[] = {
        {"Control: the protocol task consumes the message", false, true},
        {"the connection is released and its gate detached", true, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundGate gate;
        ASSERT_TRUE(gate.publish_pending_message());
        bool writable = !row.expected_writable;
        std::thread transport([&] { writable = gate.wait_until_writable(UINT32_MAX); });
        std::this_thread::sleep_for(std::chrono::milliseconds(PARK_MS));
        if (row.detach) {
            gate.detach();
        } else {
            gate.consume_pending_message();
        }
        transport.join();
        EXPECT_EQ(writable, row.expected_writable);
    }

    // A consume left over from a message does not end the next message's wait early.
    InboundGate gate;
    ASSERT_TRUE(gate.publish_pending_message());
    gate.consume_pending_message();
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

// An artwork image's quota is its data plus a part's stored overhead for each part it can take
// at INBOUND_ARTWORK_MIN_PART_BYTES, which covers the image sent in parts of that size or larger
// (the item headers, part header, tag and alignment of each received part), and not one sent in
// smaller parts. Control: maximal parts, as the reference server sends.
TEST(InboundRingSize, AnArtworkImageQuotaCoversPartsOfTheMinimumSize) {
    // The ring storage `image_bytes` takes received in parts of `part_bytes`, the last one taking
    // the remainder.
    const auto stored_as_parts = [](size_t image_bytes, size_t part_bytes) {
        size_t stored = 0;
        for (size_t offset = 0; offset < image_bytes; offset += part_bytes) {
            const size_t data = std::min(part_bytes, image_bytes - offset);
            stored += inbound_item_stored_bytes(INBOUND_ARTWORK_PART_HEADER_BYTES + data +
                                                AEAD_TAG_SIZE);
        }
        return stored;
    };
    constexpr size_t MIN_PART = INBOUND_ARTWORK_MIN_PART_BYTES;
    constexpr size_t MAX_PART = MAX_TRANSPORT_PLAINTEXT - INBOUND_ARTWORK_PART_HEADER_BYTES;
    struct Row {
        const char* name;
        size_t image_bytes;
        size_t part_bytes;
        bool fits;
    };
    const Row rows[] = {
        {"Control: a 128 KiB image in maximal parts", 128 * 1024, MAX_PART, true},
        {"a 128 KiB image in parts of the minimum size", 128 * 1024, MIN_PART, true},
        {"a 128 KiB image in parts three bytes over the minimum, three pad bytes each", 128 * 1024,
         MIN_PART + 3, true},
        {"a 40,000-byte image in parts of the minimum size", 40000, MIN_PART, true},
        {"a one-byte image", 1, 1, true},
        {"a 128 KiB image in parts one byte under the minimum", 128 * 1024, MIN_PART - 1, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(stored_as_parts(row.image_bytes, row.part_bytes) <=
                      inbound_artwork_image_stored_bytes(row.image_bytes),
                  row.fits);
    }
    EXPECT_EQ(inbound_artwork_image_stored_bytes(0), 0U) << "an empty budget holds no part";
}

}  // namespace
}  // namespace sendspin
