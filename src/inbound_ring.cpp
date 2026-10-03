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

#include "inbound_ring.h"

#include "platform/logging.h"
#include "platform/time.h"

namespace sendspin {

static const char* const TAG = "sendspin.inbound";

// ============================================================================
// InboundRing
// ============================================================================

bool InboundRing::create(size_t storage_bytes, MemoryLocation location) {
    if (!this->storage_.allocate(storage_bytes, location)) {
        SS_LOGE(TAG, "Failed to allocate %zu bytes for the inbound ring", storage_bytes);
        return false;
    }
    if (!this->ring_.create(storage_bytes, this->storage_.data())) {
        SS_LOGE(TAG, "Failed to create the inbound ring over %zu bytes", storage_bytes);
        this->storage_.reset();
        return false;
    }
    return true;
}

void* InboundRing::acquire(size_t message_len, uint32_t timeout_ms) {
    void* item = this->ring_.acquire(sizeof(InboundItemHeader) + message_len, timeout_ms);
    if (item != nullptr) {
        // The storage is reused, so without this the header would carry whatever an earlier item
        // left there, including a charge that return_item() would release.
        *inbound_item_header(item) = InboundItemHeader{};
    }
    return item;
}

void InboundRing::complete(void* item) {
    // Counted before the item is published, so a take woken by the publish sees the count.
    if (this->ring_.is_storage_head(item)) {
        this->head_completions_.fetch_add(1, std::memory_order_release);
    }
    this->ring_.complete(item);
}

void* InboundRing::take(size_t* message_len, uint32_t timeout_ms) {
    for (;;) {
        void* item = this->take_one(message_len, timeout_ms);
        if (item == nullptr || inbound_item_header(item)->kind != InboundKind::DISCARD) {
            return item;
        }
        this->return_item(item);
    }
}

void InboundRing::reset() {
    for (;;) {
        if (this->pending_ != nullptr) {
            // Every producer has stopped, so the pending item's completion has happened; wait
            // for it to be visible rather than return an item that might still be written.
            while (!this->head_takes_completed()) {
                this->ring_.wait_for_completion(UINT32_MAX);
            }
            void* item = this->pending_;
            this->pending_ = nullptr;
            this->pending_len_ = 0;
            this->return_item(item);
        }
        size_t len = 0;
        void* item = this->take_one(&len, 0);
        if (item != nullptr) {
            this->return_item(item);
        } else if (this->pending_ == nullptr) {
            return;
        }
    }
}

void* InboundRing::take_one(size_t* message_len, uint32_t timeout_ms) {
    if (this->pending_ != nullptr) {
        return this->take_pending(message_len, timeout_ms);
    }
    size_t item_size = 0;
    void* item = this->ring_.take(&item_size, timeout_ms);
    if (item == nullptr) {
        return nullptr;
    }
    const size_t len = item_size - sizeof(InboundItemHeader);
    if (!this->ring_.is_storage_head(item)) {
        *message_len = len;
        return item;
    }
    ++this->head_takes_;
    this->pending_ = item;
    this->pending_len_ = len;
    return this->take_pending(message_len, timeout_ms);
}

void* InboundRing::take_pending(size_t* message_len, uint32_t timeout_ms) {
    if (!this->head_takes_completed()) {
        // complete() always wakes the consumer, so this wait ends on the pending item's own
        // completion (or an earlier one's leftover token, after which the caller retries).
        this->ring_.wait_for_completion(timeout_ms);
        if (!this->head_takes_completed()) {
            return nullptr;
        }
    }
    void* item = this->pending_;
    *message_len = this->pending_len_;
    this->pending_ = nullptr;
    this->pending_len_ = 0;
    return item;
}

bool InboundRing::charge(void* item, size_t message_len, InboundHolder holder) {
    const size_t stored = SharedRingLayout::stored_size(sizeof(InboundItemHeader) + message_len);
    if (!this->quota(holder).try_charge(stored)) {
        return false;
    }
    InboundItemHeader* header = inbound_item_header(item);
    header->charge = static_cast<uint32_t>(stored);
    header->holder = holder;
    return true;
}

void InboundRing::return_item(void* item) {
    InboundItemHeader* header = inbound_item_header(item);
    if (header->charge != 0) {
        this->quota(header->holder).release(header->charge);
        header->charge = 0;
    }
    this->ring_.return_item(item);
}

// ============================================================================
// InboundGate
// ============================================================================

bool InboundGate::wait_until_writable(uint32_t timeout_ms) {
    const bool forever = timeout_ms == UINT32_MAX;
    const int64_t deadline_us = platform_time_us() + static_cast<int64_t>(timeout_ms) * 1000;
    while (!this->may_write()) {
        uint32_t wait_ms = UINT32_MAX;
        if (!forever) {
            const int64_t remaining_us = deadline_us - platform_time_us();
            if (remaining_us <= 0) {
                return false;
            }
            wait_ms = static_cast<uint32_t>((remaining_us + 999) / 1000);
        }
        this->consumed_flags_.wait(CONSUMED, false, true, wait_ms);
    }
    return true;
}

// ============================================================================
// InboundItemList
// ============================================================================

bool InboundItemList::create(InboundRing* ring) {
    if (!this->flags_.is_created() && !this->flags_.create()) {
        return false;
    }
    this->ring_ = ring;
    this->storage_ = ring->storage();
    return true;
}

void InboundItemList::append(void* item) {
    const auto offset = static_cast<uint32_t>(static_cast<uint8_t*>(item) - this->storage_);
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        inbound_item_header(item)->next = INBOUND_LIST_END;
        if (this->tail_ == INBOUND_LIST_END) {
            this->head_ = offset;
        } else {
            inbound_item_header(this->item_at(this->tail_))->next = offset;
        }
        this->tail_ = offset;
    }
    this->flags_.set(ITEMS_APPENDED);
}

void* InboundItemList::take(uint32_t timeout_ms) {
    void* item = this->pop();
    if (item != nullptr || timeout_ms == 0) {
        return item;
    }
    // An append between the pop above and this wait has already set ITEMS_APPENDED, so the wait
    // returns at once rather than missing it. A bit left by an append whose item an earlier pop
    // took returns here with nothing to pop, which the caller treats as a retry.
    this->flags_.wait(ITEMS_APPENDED | WAKE, false, true, timeout_ms);
    return this->pop();
}

size_t InboundItemList::recall() {
    uint32_t offset = INBOUND_LIST_END;
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        offset = this->head_;
        this->head_ = INBOUND_LIST_END;
        this->tail_ = INBOUND_LIST_END;
    }
    // The detached chain is reachable from nowhere else, so it is walked and returned outside
    // the list's lock; the ring's lock is never taken under it.
    size_t returned = 0;
    while (offset != INBOUND_LIST_END) {
        void* item = this->item_at(offset);
        offset = inbound_item_header(item)->next;
        this->ring_->return_item(item);
        ++returned;
    }
    return returned;
}

void* InboundItemList::pop() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    if (this->head_ == INBOUND_LIST_END) {
        return nullptr;
    }
    void* item = this->item_at(this->head_);
    this->head_ = inbound_item_header(item)->next;
    if (this->head_ == INBOUND_LIST_END) {
        this->tail_ = INBOUND_LIST_END;
    }
    return item;
}

}  // namespace sendspin
