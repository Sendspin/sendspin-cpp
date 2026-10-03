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

// Test helpers that stand in for a transport and the protocol task around the shared inbound
// ring, so a role's protocol-task handlers can be driven on the test thread.

#pragma once

#include "inbound_ring.h"
#include "sendspin/types.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace sendspin {

/// Ring storage for a role test: the smallest ring that accepts a maximal message.
static constexpr size_t TEST_INBOUND_RING_BYTES = INBOUND_RING_MIN_STORAGE_BYTES;

/// Creates `ring` with every holder's quota set to its whole storage.
inline void create_test_ring(InboundRing& ring) {
    ASSERT_TRUE(ring.create(TEST_INBOUND_RING_BYTES, MemoryLocation::PREFER_EXTERNAL));
    ring.quota(InboundHolder::PLAYER).set_limit(TEST_INBOUND_RING_BYTES);
    ring.quota(InboundHolder::VISUALIZER).set_limit(TEST_INBOUND_RING_BYTES);
}

/// A message received into a ring item and taken off the ring, as the protocol task hands it to
/// a role: the transport writes the bytes and the receive stamp, then the task takes the item.
/// The bytes are already plaintext (the decrypt in place is not under test here).
inline InboundMessage receive_into_ring(InboundRing& ring, const std::vector<uint8_t>& bytes,
                                        uint32_t receive_time_us) {
    InboundMessage message;
    void* item = ring.acquire(bytes.size(), 0);
    EXPECT_NE(item, nullptr);
    if (item == nullptr) {
        return message;
    }
    std::memcpy(inbound_item_bytes(item), bytes.data(), bytes.size());
    inbound_item_header(item)->receive_time_us = receive_time_us;
    inbound_item_header(item)->kind = InboundKind::BINARY;
    ring.complete(item);
    size_t item_len = 0;
    void* taken = ring.take(&item_len, 0);
    EXPECT_EQ(taken, item);
    message.item = taken;
    message.data = inbound_item_bytes(taken);
    message.item_len = item_len;
    message.len = item_len;
    message.receive_time_us = receive_time_us;
    return message;
}

/// The protocol task's ring-order pass over what a handler under test wrote: take() counts the
/// task's return of each LOCAL item (a codec header, a marker, a copied chunk), which the
/// production task makes on its next tick, so the holder's return then reclaims it. Call after
/// a handler that can acquire a LOCAL item, once every received item has been taken.
inline void take_in_ring_order(InboundRing& ring) {
    size_t len = 0;
    void* item = nullptr;
    while ((item = ring.take(&len, 0)) != nullptr) {
        ADD_FAILURE() << "an item was left untaken behind the handler's LOCAL items";
        ring.return_item(item);
    }
}

/// A message outside any ring item (a reassembled or pre-admission one), backed by `bytes`.
inline InboundMessage message_over(std::vector<uint8_t>& bytes, uint32_t receive_time_us = 0) {
    InboundMessage message;
    message.data = bytes.data();
    message.len = bytes.size();
    message.receive_time_us = receive_time_us;
    return message;
}

/// Whether `p` lies inside the ring's storage.
inline bool in_ring_storage(const InboundRing& ring, const uint8_t* p) {
    return p >= ring.storage() && p < ring.storage() + TEST_INBOUND_RING_BYTES;
}

}  // namespace sendspin
