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

/// @file json_arena.h
/// @brief Bounded internal-RAM bump-arena ArduinoJson allocator with PSRAM fallback

#pragma once

#include "platform/memory.h"
#include "sendspin/types.h"
#include <ArduinoJson.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace sendspin {

/**
 * @brief ArduinoJson allocator backed by a fixed internal-RAM byte buffer, falling back to the
 * PSRAM-preferring platform allocator when the buffer is exhausted
 *
 * ArduinoJson allocates a document's variant pool and copied strings out of its Allocator; on
 * ESP32 those land in slow PSRAM (see PsramJsonAllocator). Routing the short-lived
 * protocol-parse documents to internal RAM removes that traffic on every message. Internal RAM
 * is scarce, so the buffer is a hard budget: an allocation that does not fit falls back to
 * platform_malloc, and an unexpectedly large message still parses, just slowly.
 * deallocate()/reallocate() route each pointer back by checking whether it lies in the buffer.
 *
 * Bump allocator: ArduinoJson frees in LIFO order, so a finished document drains the arena on its
 * own. ArduinoJson::Allocator has no "document destroyed" hook, so the owner calls reset() between
 * documents as a safety net for any non-LIFO leftover; it does not touch blocks that escaped to
 * PSRAM. Not thread-safe: the parser's one instance is serialized by json_processing_mutex_.
 *
 * If the backing buffer cannot be allocated, every request falls back to PSRAM, i.e. it behaves
 * like PsramJsonAllocator.
 */
class SendspinArenaAllocator final : public ArduinoJson::Allocator {
public:
    /// @brief Constructs an arena with a buffer of @p capacity bytes in internal RAM (PSRAM
    /// fallback). A capacity of 0, or a failed allocation, makes every request fall back to the
    /// PSRAM-preferring platform allocator
    explicit SendspinArenaAllocator(size_t capacity) {
        if (capacity == 0 || !this->buffer_.allocate(capacity, MemoryLocation::PREFER_INTERNAL)) {
            return;
        }
        // Align the usable base up to ALIGNMENT so every returned block is aligned without a
        // per-allocation fixup; trim the capacity by however much was skipped, then down to a
        // multiple of ALIGNMENT.
        const auto raw = reinterpret_cast<uintptr_t>(this->buffer_.data());
        const auto aligned = (raw + (ALIGNMENT - 1)) & ~static_cast<uintptr_t>(ALIGNMENT - 1);
        const size_t skip = static_cast<size_t>(aligned - raw);
        if (skip < this->buffer_.size()) {
            this->base_ = reinterpret_cast<uint8_t*>(aligned);
            this->cap_ = (this->buffer_.size() - skip) & ~(ALIGNMENT - 1);
        }
    }

    SendspinArenaAllocator(const SendspinArenaAllocator&) = delete;
    SendspinArenaAllocator& operator=(const SendspinArenaAllocator&) = delete;

    /// @brief Allocates @p size bytes from the arena, or via platform_malloc if it does not fit
    void* allocate(size_t size) override {
        const size_t need = HEADER_SIZE + align_up(size);
        if (need <= this->cap_ - this->offset_) {  // cap_ - offset_ is 0 when cap_ == 0
            uint8_t* hdr = this->base_ + this->offset_;
            store_size(hdr, align_up(size));
            this->offset_ += need;
            this->note_high_water();
            return hdr + HEADER_SIZE;
        }
        return platform_malloc(size);
    }

    /// @brief Frees a block previously returned by allocate() or reallocate(); null is a no-op
    void deallocate(void* ptr) override {
        if (ptr == nullptr) {
            return;
        }
        if (!this->in_arena(ptr)) {
            platform_free(ptr);
            return;
        }
        // If this block sits on top of the bump pointer, pop it; otherwise it stays stranded until
        // reset(). ArduinoJson frees in LIFO order, so popping usually chains all the way down.
        uint8_t* hdr = static_cast<uint8_t*>(ptr) - HEADER_SIZE;
        const size_t block = load_size(hdr);
        if (static_cast<size_t>(hdr - this->base_) + HEADER_SIZE + block == this->offset_) {
            this->offset_ = static_cast<size_t>(hdr - this->base_);
        }
    }

    /// @brief Reallocates a block to a new size, preserving its existing contents
    void* reallocate(void* ptr, size_t new_size) override {
        if (ptr == nullptr) {
            return this->allocate(new_size);
        }
        if (!this->in_arena(ptr)) {
            return platform_realloc(ptr, new_size);
        }
        uint8_t* hdr = static_cast<uint8_t*>(ptr) - HEADER_SIZE;
        const size_t old_block = load_size(hdr);
        const size_t hdr_off = static_cast<size_t>(hdr - this->base_);
        const size_t new_block = align_up(new_size);
        const bool is_top = hdr_off + HEADER_SIZE + old_block == this->offset_;

        if (is_top) {
            // Grow or shrink in place if the new size still fits the buffer.
            if (HEADER_SIZE + new_block <= this->cap_ - hdr_off) {
                store_size(hdr, new_block);
                this->offset_ = hdr_off + HEADER_SIZE + new_block;
                this->note_high_water();
                return ptr;
            }
            // Top block, but the grown size overflows the buffer: move to PSRAM, pop the old top.
            void* moved = platform_malloc(new_size);
            if (moved == nullptr) {
                return nullptr;
            }
            std::memcpy(moved, ptr, std::min(new_size, old_block));
            this->offset_ = hdr_off;
            return moved;
        }

        // Interior block.
        if (new_block <= old_block) {
            return ptr;  // shrink (or no change): leave it in place; the tail can't be reclaimed
        }
        // Interior grow: move to fresh space (arena if it fits, else PSRAM). The old block stays
        // stranded until reset(). Only reachable for pathologically large messages.
        void* moved = this->allocate(new_size);
        if (moved == nullptr) {
            return nullptr;
        }
        std::memcpy(moved, ptr, std::min(new_size, old_block));
        return moved;
    }

    /// @brief Discards all arena allocations; call between documents, after the previous
    /// JsonDocument has been destroyed. Does not affect (or free) blocks that escaped to PSRAM
    void reset() {
        this->offset_ = 0;
    }

    /// @brief Usable arena capacity in bytes; 0 if the backing buffer could not be allocated
    size_t capacity() const {
        return this->cap_;
    }

    /// @brief Largest number of arena bytes in use at once since construction, for tuning the
    /// budget; not cleared by reset()
    size_t high_water() const {
        return this->high_water_;
    }

private:
    /// Alignment of every block returned to ArduinoJson (matches malloc semantics).
    static constexpr size_t ALIGNMENT = alignof(std::max_align_t);
    /// Bytes reserved before each block to record its size (used by deallocate/reallocate).
    static constexpr size_t HEADER_SIZE = ALIGNMENT;
    static_assert(HEADER_SIZE >= sizeof(size_t), "block header must hold a size_t");
    static_assert((ALIGNMENT & (ALIGNMENT - 1)) == 0, "ALIGNMENT must be a power of two");

    static constexpr size_t align_up(size_t n) {
        return (n + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
    }
    static void store_size(uint8_t* hdr, size_t value) {
        std::memcpy(hdr, &value, sizeof(value));
    }
    static size_t load_size(const uint8_t* hdr) {
        size_t value = 0;
        std::memcpy(&value, hdr, sizeof(value));
        return value;
    }
    /// @brief Whether @p p was bump-allocated from the backing buffer
    bool in_arena(const void* p) const {
        if (this->cap_ == 0) {
            return false;
        }
        // p may come from platform_malloc, an unrelated allocation; relational comparison of
        // pointers into different objects is UB, so compare the integer addresses instead.
        const auto addr = reinterpret_cast<uintptr_t>(p);
        const auto begin = reinterpret_cast<uintptr_t>(this->base_);
        return addr >= begin && addr < begin + this->cap_;
    }
    void note_high_water() {
        if (this->offset_ > this->high_water_) {
            this->high_water_ = this->offset_;
        }
    }

    // Struct fields
    PlatformBuffer buffer_;

    // Pointer fields
    uint8_t* base_{nullptr};

    // size_t fields
    size_t cap_{0};
    size_t high_water_{0};
    size_t offset_{0};
};

/// @brief Creates a JsonDocument that allocates from the given arena, which must outlive it
inline JsonDocument make_json_document(SendspinArenaAllocator& arena) {
    return JsonDocument(&arena);
}

}  // namespace sendspin
