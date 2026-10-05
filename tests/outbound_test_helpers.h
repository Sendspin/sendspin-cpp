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

// Test helpers that play the producer and the protocol task around an outbound ring.

#pragma once

#include "outbound_ring.h"
#include "sendspin/types.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace sendspin {

/// An outbound ring sized for OUTBOUND_RING_ITEM_COUNT items of `capacity` message bytes, with the
/// test thread as its producer and its protocol task.
struct TestOutboundRing {
    explicit TestOutboundRing(size_t capacity) : capacity(capacity) {
        EXPECT_TRUE(this->ring.create(derive_outbound_ring_bytes(capacity, OUTBOUND_RING_ITEM_COUNT),
                                      MemoryLocation::PREFER_EXTERNAL));
    }

    /// Writes `message` into a fresh item, completes it and takes it back, as the protocol task
    /// would before a lent send. Returns nullptr when the ring has no room.
    void* take_filled(const std::vector<uint8_t>& message) {
        void* item = this->ring.acquire(this->capacity, 0);
        if (item == nullptr) {
            return nullptr;
        }
        if (!message.empty()) {
            std::memcpy(outbound_item_message(item), message.data(), message.size());
        }
        this->ring.complete(item);
        size_t taken_capacity = 0;
        void* taken = this->ring.take(&taken_capacity, 0);
        EXPECT_EQ(taken, item);
        EXPECT_EQ(taken_capacity, this->capacity);
        return taken;
    }

    /// How many items of `capacity` the ring can hand out right now; each is completed, taken and
    /// returned again, so the ring is left as it was. OUTBOUND_RING_ITEM_COUNT once every item
    /// lent out has come back.
    size_t free_items() {
        std::vector<void*> items;
        while (items.size() <= OUTBOUND_RING_ITEM_COUNT) {
            void* item = this->ring.acquire(this->capacity, 0);
            if (item == nullptr) {
                break;
            }
            this->ring.complete(item);
            items.push_back(item);
        }
        for (size_t i = 0; i < items.size(); ++i) {
            size_t taken_capacity = 0;
            EXPECT_EQ(this->ring.take(&taken_capacity, 0), items[i]);
        }
        for (void* item : items) {
            this->ring.return_item(item);
        }
        return items.size();
    }

    OutboundRing ring;
    size_t capacity;
};

}  // namespace sendspin
