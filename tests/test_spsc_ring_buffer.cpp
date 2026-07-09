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

/// @file test_spsc_ring_buffer.cpp
/// @brief Tests for the host SpscRingBuffer, focused on wrap-around accounting with
/// storage sizes that are not a multiple of the internal alignment

#include "platform/spsc_ring_buffer.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace sendspin {
namespace {

// Fills each item with a pattern derived from its sequence number so corruption from
// overlapping writer/reader accounting is detected on read-back.
void fill_pattern(uint8_t* dst, size_t size, uint32_t seq) {
    for (size_t i = 0; i < size; ++i) {
        dst[i] = static_cast<uint8_t>((seq * 31 + i) & 0xFF);
    }
}

bool check_pattern(const uint8_t* src, size_t size, uint32_t seq) {
    for (size_t i = 0; i < size; ++i) {
        if (src[i] != static_cast<uint8_t>((seq * 31 + i) & 0xFF)) {
            return false;
        }
    }
    return true;
}

// Repeatedly fills the buffer to capacity with varying item sizes, then drains and
// verifies every item. Cycling many times forces the write offset through every
// wrap position, including tails smaller than the item header.
void run_fill_drain_cycles(size_t storage_size) {
    std::vector<uint8_t> storage(storage_size);
    SpscRingBuffer rb;
    ASSERT_TRUE(rb.create(storage_size, storage.data()));

    uint32_t write_seq = 0;
    uint32_t read_seq = 0;
    uint8_t item[97];

    for (int cycle = 0; cycle < 200; ++cycle) {
        // Vary the item size per cycle so wrap points shift around the storage.
        size_t item_size = 1 + ((cycle * 13) % sizeof(item));

        // Fill until the buffer rejects a non-blocking write.
        int wrote = 0;
        for (;;) {
            fill_pattern(item, item_size, write_seq);
            if (!rb.send(item, item_size, 0)) {
                break;
            }
            ++write_seq;
            ++wrote;
        }
        // An empty-drained buffer must always accept at least one small item; a
        // failure here means the accounting stalled permanently.
        ASSERT_GT(wrote, 0) << "buffer stalled at cycle " << cycle
                            << " storage_size=" << storage_size;

        // Drain everything and verify content and ordering.
        for (;;) {
            size_t got_size = 0;
            void* got = rb.receive(&got_size, 0);
            if (got == nullptr) {
                break;
            }
            ASSERT_EQ(got_size, item_size);
            ASSERT_TRUE(check_pattern(static_cast<uint8_t*>(got), got_size, read_seq))
                << "corrupt item seq=" << read_seq << " cycle=" << cycle
                << " storage_size=" << storage_size;
            ++read_seq;
            rb.return_item(got);
        }
        ASSERT_EQ(read_seq, write_seq);
        ASSERT_TRUE(rb.is_empty());
    }
}

TEST(SpscRingBuffer, AlignedStorageSize) {
    run_fill_drain_cycles(4096);
}

// Regression: storage sizes that are not a multiple of the 8-byte alignment used to
// corrupt data (unaligned dummy-filler size credited back rounded up) or stall forever
// (tail too small for a dummy header). create() now rounds the usable size down.
TEST(SpscRingBuffer, UnalignedStorageSizeOddByOne) {
    run_fill_drain_cycles(4097);
}

TEST(SpscRingBuffer, UnalignedStorageSizeOddByFour) {
    run_fill_drain_cycles(4100);
}

TEST(SpscRingBuffer, UnalignedStorageSizeJustUnderAligned) {
    run_fill_drain_cycles(4093);
}

TEST(SpscRingBuffer, CreateRejectsTooSmallStorage) {
    std::vector<uint8_t> storage(16);
    SpscRingBuffer rb;
    // After rounding down, less than one header plus one aligned byte of payload fits.
    EXPECT_FALSE(rb.create(15, storage.data()));
    EXPECT_FALSE(rb.create(8, storage.data()));
    EXPECT_TRUE(rb.create(16, storage.data()));
}

}  // namespace
}  // namespace sendspin
