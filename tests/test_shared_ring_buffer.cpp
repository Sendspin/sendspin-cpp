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

/// @file test_shared_ring_buffer.cpp
/// @brief Tests for the host SharedRingBuffer: ring-order reclamation under out-of-order
/// returns, no-split wrap placement, the full-ring acquire policies, completion order, and
/// multi-producer safety (run under TSan in CI)

#include "platform/shared_ring_buffer.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

namespace sendspin {
namespace {

// 4-byte-aligned storage owned by the test, as platform_malloc would provide.
struct RingStorage {
    explicit RingStorage(size_t size) : bytes(size / 4 + 1) {}
    uint8_t* data() {
        return reinterpret_cast<uint8_t*>(this->bytes.data());
    }
    std::vector<uint32_t> bytes;
};

// Three 76-byte items occupy 3 * (8 + 76) = 252 of 256 bytes; the 4 bytes left cannot hold a
// header, so the ring is full and a fourth item can only go where the oldest items were.
constexpr size_t SMALL_RING = 256;
constexpr size_t ITEM = 76;

// How long a test lets another thread reach its blocking call before triggering what should end
// it. Ordering only: a thread that arrives late makes the test pass without exercising the wake,
// never fail.
constexpr int PARK_MS = 50;

// Space is reclaimed in ring order: returning newer items out of order frees nothing until the
// oldest is returned too, at which point the whole returned run is reclaimed. This is the rule
// the shared inbound ring is sized by, and the FreeRTOS no-split behavior the host ring mirrors.
TEST(SharedRingBuffer, ReclaimsSpaceOnlyInRingOrder) {
    struct Row {
        const char* name;
        std::vector<size_t> returned;  // indices into {A, B, C}, in return order
        bool fourth_fits;
    };
    const std::vector<Row> rows = {
        {"Control: oldest returned", {0}, true},
        {"newer returned out of order, oldest held", {2, 1}, false},
        {"newest returned, older two held", {2}, false},
        {"newer returned first, then the oldest", {2, 1, 0}, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        RingStorage storage(SMALL_RING);
        SharedRingBuffer ring;
        ASSERT_TRUE(ring.create(SMALL_RING, storage.data()));

        std::array<void*, 3> taken{};
        for (size_t i = 0; i < taken.size(); ++i) {
            void* item = ring.acquire(ITEM, 0);
            ASSERT_NE(item, nullptr);
            ring.complete(item);
        }
        for (void*& item : taken) {
            size_t size = 0;
            item = ring.take(&size, 0);
            ASSERT_NE(item, nullptr);
        }
        ASSERT_EQ(ring.acquire(ITEM, 0), nullptr) << "the ring must start full";

        for (size_t index : row.returned) {
            ring.return_item(taken[index]);
        }
        void* fourth = ring.acquire(ITEM, 0);
        EXPECT_EQ(fourth != nullptr, row.fourth_fits);
    }
}

// An item that does not fit between the write position and the end of the storage is placed at
// the start, as a FreeRTOS no-split ring places it, once the start is reclaimed. Control: an item
// that fits the tail is placed there.
TEST(SharedRingBuffer, PlacesAnItemThatCannotFitTheTailAtTheStart) {
    RingStorage storage(SMALL_RING);
    SharedRingBuffer ring;
    ASSERT_TRUE(ring.create(SMALL_RING, storage.data()));
    uint8_t* base = storage.data();

    // A and B take 2 * (8 + 100) = 216 bytes, leaving a 40-byte tail.
    void* a = ring.acquire(100, 0);
    void* b = ring.acquire(100, 0);
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(static_cast<uint8_t*>(a), base + SharedRingLayout::ITEM_HEADER_BYTES);
    ring.complete(a);
    ring.complete(b);
    size_t size = 0;
    ASSERT_EQ(ring.take(&size, 0), a);
    ring.return_item(a);

    // Control: 24 bytes (32 stored) fit the 40-byte tail.
    void* tail_item = ring.acquire(24, 0);
    ASSERT_NE(tail_item, nullptr);
    EXPECT_EQ(static_cast<uint8_t*>(tail_item), base + 216 + SharedRingLayout::ITEM_HEADER_BYTES);
    ring.complete(tail_item);

    // 60 bytes (68 stored) do not fit the 8 bytes now left at the tail: they go to the start,
    // into the 108 bytes A gave back.
    void* wrapped = ring.acquire(60, 0);
    ASSERT_NE(wrapped, nullptr);
    EXPECT_EQ(static_cast<uint8_t*>(wrapped), base + SharedRingLayout::ITEM_HEADER_BYTES);
    ring.complete(wrapped);

    // Taken in ring order across the wrap.
    EXPECT_EQ(ring.take(&size, 0), b);
    EXPECT_EQ(ring.take(&size, 0), tail_item);
    EXPECT_EQ(ring.take(&size, 0), wrapped);
    EXPECT_EQ(size, 60U);
}

// A full ring refuses an acquire it cannot satisfy: at once with a zero timeout, after the
// timeout with a finite one, and at once whatever the timeout for an item larger than the ring
// ever accepts (an indefinite wait there would hang and the suite watchdog would name the test).
// Control: an item that fits is granted.
TEST(SharedRingBuffer, FullRingAcquirePolicies) {
    struct Row {
        const char* name;
        bool fill_first;
        size_t len;
        uint32_t timeout_ms;
        bool granted;
    };
    const std::vector<Row> rows = {
        {"Control: fits an empty ring", false, ITEM, 0, true},
        {"full ring, zero timeout", true, ITEM, 0, false},
        {"full ring, finite timeout", true, ITEM, 5, false},
        {"over the largest item, empty ring, indefinite wait", false,
         SharedRingLayout::max_item_size(SMALL_RING) + 1, UINT32_MAX, false},
        {"exactly the largest item, empty ring", false, SharedRingLayout::max_item_size(SMALL_RING),
         UINT32_MAX, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        RingStorage storage(SMALL_RING);
        SharedRingBuffer ring;
        ASSERT_TRUE(ring.create(SMALL_RING, storage.data()));
        if (row.fill_first) {
            for (int i = 0; i < 3; ++i) {
                void* item = ring.acquire(ITEM, 0);
                ASSERT_NE(item, nullptr);
                ring.complete(item);
            }
        }
        EXPECT_EQ(ring.acquire(row.len, row.timeout_ms) != nullptr, row.granted);
    }
}

// The size rule FreeRTOS asserts at creation is refused here instead. Control: a valid size.
TEST(SharedRingBuffer, CreateRefusesSizesFreeRtosWouldAssertOn) {
    struct Row {
        const char* name;
        size_t size;
        bool created;
    };
    const std::vector<Row> rows = {
        {"Control: multiple of 4", SMALL_RING, true},
        {"not a multiple of 4", SMALL_RING - 2, false},
        {"too small for two items", 16, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        RingStorage storage(SMALL_RING);
        SharedRingBuffer ring;
        EXPECT_EQ(ring.create(row.size, storage.data()), row.created);
        EXPECT_EQ(ring.is_created(), row.created);
    }
}

// After a wrap, the item placed at the start of the storage is not handed out before its
// producer completes it, even once the filler marking the wrap has been passed. (FreeRTOS checks
// only the filler there; InboundRing covers that on ESP.) Trace: X sits at the tail, Y wraps to
// the start, Z follows Y; X and Z are completed and Y is still being written.
TEST(SharedRingBuffer, WrappedItemIsNotTakenBeforeItIsCompleted) {
    RingStorage storage(SMALL_RING);
    SharedRingBuffer ring;
    ASSERT_TRUE(ring.create(SMALL_RING, storage.data()));
    size_t size = 0;

    void* a = ring.acquire(100, 0);
    void* b = ring.acquire(100, 0);
    ring.complete(a);
    ring.complete(b);
    ASSERT_EQ(ring.take(&size, 0), a);
    ring.return_item(a);

    void* x = ring.acquire(24, 0);  // the 40-byte tail
    void* y = ring.acquire(60, 0);  // does not fit the tail: filler, then the start
    void* z = ring.acquire(24, 0);  // behind Y
    ASSERT_NE(x, nullptr);
    ASSERT_NE(y, nullptr);
    ASSERT_NE(z, nullptr);
    ASSERT_TRUE(ring.is_storage_head(y));

    ASSERT_EQ(ring.take(&size, 0), b);
    ring.return_item(b);
    ring.complete(x);
    EXPECT_EQ(ring.take(&size, 0), x);
    ring.complete(z);

    EXPECT_EQ(ring.take(&size, 0), nullptr) << "Y is still being written";
    ring.complete(y);
    EXPECT_EQ(ring.take(&size, 0), y);
    EXPECT_EQ(ring.take(&size, 0), z);
}

// Items are taken in acquire order: an item completed ahead of an older one still being written
// waits behind it. Control: once the older one completes, both come out, oldest first.
TEST(SharedRingBuffer, AnUncompletedItemHoldsBackLaterCompletedOnes) {
    RingStorage storage(SMALL_RING);
    SharedRingBuffer ring;
    ASSERT_TRUE(ring.create(SMALL_RING, storage.data()));
    void* older = ring.acquire(8, 0);
    void* newer = ring.acquire(8, 0);
    ring.complete(newer);
    size_t size = 0;
    EXPECT_EQ(ring.take(&size, 0), nullptr);

    ring.complete(older);
    EXPECT_EQ(ring.take(&size, 0), older);
    EXPECT_EQ(ring.take(&size, 0), newer);
    EXPECT_EQ(ring.take(&size, 0), nullptr);
}

// A producer waiting for room is released by the return that reclaims it. The join has no
// timeout: a return that does not wake the producer hangs here and the watchdog names the test.
TEST(SharedRingBuffer, ReturnReleasesAProducerWaitingForRoom) {
    RingStorage storage(SMALL_RING);
    SharedRingBuffer ring;
    ASSERT_TRUE(ring.create(SMALL_RING, storage.data()));
    for (int i = 0; i < 3; ++i) {
        void* item = ring.acquire(ITEM, 0);
        ring.complete(item);
    }
    size_t size = 0;
    void* oldest = ring.take(&size, 0);
    ASSERT_NE(oldest, nullptr);

    void* granted = nullptr;
    std::thread producer([&] { granted = ring.acquire(ITEM, UINT32_MAX); });
    // Only makes it likely the producer is parked before the return; a late producer finds the
    // room already there and passes, so the sleep can cause a false pass, never a false failure.
    std::this_thread::sleep_for(std::chrono::milliseconds(PARK_MS));
    ring.return_item(oldest);
    producer.join();
    EXPECT_NE(granted, nullptr);
}

// wake_receiver() ends a blocking take with no item; the join has no timeout.
TEST(SharedRingBuffer, WakeReceiverEndsABlockingTake) {
    RingStorage storage(SMALL_RING);
    SharedRingBuffer ring;
    ASSERT_TRUE(ring.create(SMALL_RING, storage.data()));
    void* taken = reinterpret_cast<void*>(1);  // poisoned so a take that never ran is visible
    std::thread consumer([&] {
        size_t size = 0;
        taken = ring.take(&size, UINT32_MAX);
    });
    // Makes it likely the consumer is parked; a wake that lands first is held pending, so a late
    // consumer passes either way.
    std::this_thread::sleep_for(std::chrono::milliseconds(PARK_MS));
    ring.wake_receiver();
    consumer.join();
    EXPECT_EQ(taken, nullptr);
}

// Several producers acquire and complete concurrently while one consumer takes and a separate
// thread returns items out of order (each pass's batch in reverse). Every item arrives exactly
// once, each producer's items in the order it wrote them, with its bytes intact. Run under TSan
// this also proves the ring's accounting is race-free.
TEST(SharedRingBuffer, ConcurrentProducersWithOutOfOrderReturns) {
    constexpr size_t RING_BYTES = 4096;
    constexpr uint32_t PRODUCERS = 4;
    constexpr uint32_t ITEMS_PER_PRODUCER = 2000;

    RingStorage storage(RING_BYTES);
    SharedRingBuffer ring;
    ASSERT_TRUE(ring.create(RING_BYTES, storage.data()));

    auto item_len = [](uint32_t producer, uint32_t seq) -> size_t {
        return 8 + (producer * 37 + seq * 13) % 180;
    };
    auto pattern = [](uint32_t producer, uint32_t seq, size_t i) -> uint8_t {
        return static_cast<uint8_t>(producer * 71 + seq * 31 + i);
    };

    std::vector<std::thread> producers;
    for (uint32_t p = 0; p < PRODUCERS; ++p) {
        producers.emplace_back([&, p] {
            for (uint32_t seq = 0; seq < ITEMS_PER_PRODUCER; ++seq) {
                const size_t len = item_len(p, seq);
                auto* bytes = static_cast<uint8_t*>(ring.acquire(len, UINT32_MAX));
                std::memcpy(bytes, &p, sizeof(p));
                std::memcpy(bytes + 4, &seq, sizeof(seq));
                for (size_t i = 8; i < len; ++i) {
                    bytes[i] = pattern(p, seq, i);
                }
                ring.complete(bytes);
            }
        });
    }

    // Hand-off from the consumer to the returner.
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<void*> to_return;
    bool consumer_done = false;

    // Returns everything handed over since its last pass, newest first, so every pass of two or
    // more items returns out of order. It never holds an item back waiting for more: a held
    // oldest item would pin the whole ring and stall the producers.
    std::thread returner([&] {
        std::vector<void*> batch;
        for (;;) {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [&] { return !to_return.empty() || consumer_done; });
            batch.assign(to_return.begin(), to_return.end());
            to_return.clear();
            const bool done = consumer_done;
            lock.unlock();
            for (auto it = batch.rbegin(); it != batch.rend(); ++it) {
                ring.return_item(*it);
            }
            if (done) {
                return;
            }
        }
    });

    std::array<uint32_t, PRODUCERS> next_seq{};
    bool intact = true;
    bool in_order = true;
    uint32_t bad_producer = 0;
    uint32_t bad_seq = 0;
    for (uint32_t received = 0; received < PRODUCERS * ITEMS_PER_PRODUCER;) {
        size_t size = 0;
        auto* bytes = static_cast<uint8_t*>(ring.take(&size, UINT32_MAX));
        if (bytes == nullptr) {
            continue;
        }
        // Failures are recorded, not asserted: an assert here would return with the producer
        // and returner threads still joinable. The loop keeps draining so they finish.
        uint32_t p = 0;
        uint32_t seq = 0;
        std::memcpy(&p, bytes, sizeof(p));
        std::memcpy(&seq, bytes + 4, sizeof(seq));
        bool this_intact = p < PRODUCERS;
        if (this_intact) {
            in_order = in_order && seq == next_seq[p];
            ++next_seq[p];
            this_intact = size == item_len(p, seq);
            for (size_t i = 8; i < size && this_intact; ++i) {
                this_intact = bytes[i] == pattern(p, seq, i);
            }
        }
        if (!this_intact && intact) {
            intact = false;
            bad_producer = p;
            bad_seq = seq;
        }
        {
            std::lock_guard<std::mutex> lock(mutex);
            to_return.push_back(bytes);
        }
        cv.notify_one();
        ++received;
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        consumer_done = true;
    }
    cv.notify_one();
    returner.join();
    for (std::thread& producer : producers) {
        producer.join();
    }

    EXPECT_TRUE(intact) << "first damaged item: producer " << bad_producer << ", sequence "
                        << bad_seq;
    EXPECT_TRUE(in_order) << "an item arrived out of its producer's order or twice";
    for (uint32_t p = 0; p < PRODUCERS; ++p) {
        EXPECT_EQ(next_seq[p], ITEMS_PER_PRODUCER);
    }
    // Everything returned: the whole ring is reclaimed, so the largest item fits again.
    EXPECT_NE(ring.acquire(SharedRingLayout::max_item_size(RING_BYTES), 0), nullptr);
}

}  // namespace
}  // namespace sendspin
