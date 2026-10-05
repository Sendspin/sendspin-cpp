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

/// @file test_outbound_ring.cpp
/// @brief Tests for OutboundRing: the size derivation, the item round trip and the item size
/// limit

#include "crypto/constants.h"
#include "outbound_ring.h"
#include "outbound_test_helpers.h"
#include "platform/crypto.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace sendspin {
namespace {

// The derived storage holds exactly the items asked for at the largest message size, never fewer
// than the two the ring's largest-item rule needs, and keeps holding them as items wrap around
// the storage. Odd sizes check the padding to the ring's alignment.
TEST(OutboundRing, DerivedStorageHoldsTheItemCountThroughWraps) {
    struct Row {
        const char* name;
        size_t largest_message_bytes;
        size_t item_count;
        size_t expected_items;
    };
    const Row rows[] = {
        {"Control: a small message", 64, OUTBOUND_RING_ITEM_COUNT, OUTBOUND_RING_ITEM_COUNT},
        {"an odd length", 1001, OUTBOUND_RING_ITEM_COUNT, OUTBOUND_RING_ITEM_COUNT},
        {"a one-byte message", 1, OUTBOUND_RING_ITEM_COUNT, OUTBOUND_RING_ITEM_COUNT},
        {"a maximal Noise frame", MAX_TRANSPORT_PLAINTEXT + AEAD_TAG_SIZE,
         OUTBOUND_RING_ITEM_COUNT, OUTBOUND_RING_ITEM_COUNT},
        {"one item floors at the two the largest-item rule needs", 333, 1, 2},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        const size_t storage = derive_outbound_ring_bytes(row.largest_message_bytes, row.item_count);
        EXPECT_GE(SharedRingLayout::max_item_size(storage),
                  OUTBOUND_ITEM_HEADER_BYTES + row.largest_message_bytes);
        OutboundRing ring;
        ASSERT_TRUE(ring.create(storage, MemoryLocation::PREFER_EXTERNAL));
        EXPECT_GE(ring.max_message_bytes(), row.largest_message_bytes);

        // Several passes, each returning its items in reverse, carry the positions around the
        // storage and back.
        for (int pass = 0; pass < 5; ++pass) {
            std::vector<void*> items;
            while (items.size() <= row.expected_items) {
                void* item = ring.acquire(row.largest_message_bytes, 0);
                if (item == nullptr) {
                    break;
                }
                ring.complete(item);
                items.push_back(item);
            }
            EXPECT_EQ(items.size(), row.expected_items) << "pass " << pass;
            for (size_t i = 0; i < items.size(); ++i) {
                size_t capacity = 0;
                EXPECT_EQ(ring.take(&capacity, 0), items[i]);
            }
            for (auto it = items.rbegin(); it != items.rend(); ++it) {
                ring.return_item(*it);
            }
        }
    }
}

// An item comes back from take() as the producer completed it, with the capacity it was acquired
// with; a reused item's header starts zeroed whatever the previous one held; and an empty ring's
// non-blocking take returns nothing.
TEST(OutboundRing, ItemRoundTripsWithItsHeaderZeroedOnReuse) {
    constexpr size_t CAPACITY = 40;
    // Room for two items, so the third lands where the first was.
    OutboundRing ring;
    ASSERT_TRUE(ring.create(derive_outbound_ring_bytes(CAPACITY, 2), MemoryLocation::PREFER_EXTERNAL));
    size_t capacity = 0;
    EXPECT_EQ(ring.take(&capacity, 0), nullptr);

    void* first = ring.acquire(CAPACITY, 0);
    ASSERT_NE(first, nullptr);
    const OutboundItemHeader zero = outbound_item_header(first);
    EXPECT_EQ(zero.capture_time_us, 0);
    EXPECT_EQ(zero.generation, 0U);
    EXPECT_EQ(zero.data_len, 0U);
    set_outbound_item_header(first, OutboundItemHeader{-123456789012345, 7, 5});
    const uint8_t message[] = {9, 8, 7, 6, 5};
    std::memcpy(outbound_item_message(first), message, sizeof(message));
    ring.complete(first);

    void* taken = ring.take(&capacity, 0);
    ASSERT_EQ(taken, first);
    EXPECT_EQ(capacity, CAPACITY);
    const OutboundItemHeader header = outbound_item_header(taken);
    EXPECT_EQ(header.capture_time_us, -123456789012345);
    EXPECT_EQ(header.generation, 7U);
    EXPECT_EQ(header.data_len, 5U);
    EXPECT_EQ(std::memcmp(outbound_item_message(taken), message, sizeof(message)), 0);
    ring.return_item(taken);

    void* second = ring.acquire(CAPACITY, 0);
    ASSERT_NE(second, nullptr);
    ring.complete(second);
    ASSERT_EQ(ring.take(&capacity, 0), second);
    ring.return_item(second);

    void* reused = ring.acquire(CAPACITY, 0);
    ASSERT_EQ(reused, first) << "the third item did not land on the first one's storage";
    const OutboundItemHeader fresh = outbound_item_header(reused);
    EXPECT_EQ(fresh.capture_time_us, 0);
    EXPECT_EQ(fresh.generation, 0U);
    EXPECT_EQ(fresh.data_len, 0U);
    ring.complete(reused);
    ASSERT_EQ(ring.take(&capacity, 0), reused);
    ring.return_item(reused);
}

// An item larger than max_message_bytes() is refused at once, even by an acquire that would wait
// indefinitely for room.
TEST(OutboundRing, AnItemOverTheLargestSizeIsRefusedAtOnce) {
    TestOutboundRing test(64);
    EXPECT_EQ(test.ring.acquire(test.ring.max_message_bytes() + 1, UINT32_MAX), nullptr);
    // A capacity whose size with the header would wrap around.
    EXPECT_EQ(test.ring.acquire(SIZE_MAX, UINT32_MAX), nullptr);

    // Control: the largest size is accepted by the empty ring.
    void* item = test.ring.acquire(test.ring.max_message_bytes(), 0);
    ASSERT_NE(item, nullptr);
    test.ring.complete(item);
    size_t capacity = 0;
    ASSERT_EQ(test.ring.take(&capacity, 0), item);
    EXPECT_EQ(capacity, test.ring.max_message_bytes());
    test.ring.return_item(item);
}

}  // namespace
}  // namespace sendspin
