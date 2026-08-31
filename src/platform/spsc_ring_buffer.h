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

/// @file spsc_ring_buffer.h
/// @brief Platform-abstracted single-producer/single-consumer ring buffer backed by a FreeRTOS
/// NOSPLIT ring buffer on ESP and a mutex/condition-variable implementation on host

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef ESP_PLATFORM

// ESP-IDF: thin wrapper around FreeRTOS NOSPLIT ring buffer (uses direct task notifications)
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <freertos/semphr.h>

namespace sendspin {

/**
 * @brief Single-producer/single-consumer ring buffer with caller-provided storage
 *
 * Backed by a FreeRTOS NOSPLIT ring buffer on ESP and a mutex/condition-variable
 * implementation on host. Items are written as contiguous blobs and read back in
 * the same order. Supports both a one-phase send() and a two-phase acquire()/commit()
 * path for zero-copy writes.
 *
 * A blocking receive() can be interrupted from any thread with wake_receiver(): the
 * blocked (or next blocking) receive returns nullptr immediately without consuming
 * data. Callers must therefore treat a nullptr return as "re-check state and retry",
 * not as proof the timeout elapsed.
 *
 * Usage:
 * 1. Allocate a storage buffer, then call create() with a pointer to it
 * 2. Write data with send() or acquire()/commit() from the producer thread
 * 3. Read data with receive() from the consumer thread
 * 4. Call return_item() after processing each received item
 *
 * @code
 * static uint8_t buf[4096];
 * SpscRingBuffer rb;
 * rb.create(sizeof(buf), buf);
 *
 * rb.send(data, data_len, 100);
 *
 * size_t sz;
 * void* item = rb.receive(&sz, UINT32_MAX);
 * // process item...
 * rb.return_item(item);
 * @endcode
 */
class SpscRingBuffer {
public:
    SpscRingBuffer() = default;
    ~SpscRingBuffer() {
        if (this->handle_ != nullptr) {
            vRingbufferDelete(this->handle_);
        }
        if (this->items_or_wake_sem_ != nullptr) {
            vSemaphoreDelete(this->items_or_wake_sem_);
        }
    }

    // Not copyable or movable
    SpscRingBuffer(const SpscRingBuffer&) = delete;
    SpscRingBuffer& operator=(const SpscRingBuffer&) = delete;

    /// @brief Creates the ring buffer with caller-provided storage
    /// @param size Total storage size in bytes.
    /// @param storage Pointer to pre-allocated storage (must outlive this object).
    /// @return true on success.
    bool create(size_t size, uint8_t* storage) {
        this->handle_ =
            xRingbufferCreateStatic(size, RINGBUF_TYPE_NOSPLIT, storage, &this->structure_);
        if (this->handle_ == nullptr) {
            return false;
        }
        this->items_or_wake_sem_ = xSemaphoreCreateBinary();
        if (this->items_or_wake_sem_ == nullptr) {
            vRingbufferDelete(this->handle_);
            this->handle_ = nullptr;
            return false;
        }
        return true;
    }

    /// @brief Returns true if the ring buffer has been successfully created
    /// @return true if the ring buffer is ready for use.
    bool is_created() const {
        return this->handle_ != nullptr;
    }

    /// @brief Returns the number of committed items waiting to be received
    /// @return Count of items written and committed but not yet received by the consumer.
    size_t items_waiting() const {
        if (this->handle_ == nullptr) {
            return 0;
        }
        UBaseType_t items = 0;
        vRingbufferGetInfo(this->handle_, nullptr, nullptr, nullptr, nullptr, &items);
        return static_cast<size_t>(items);
    }

    /// @brief Returns true if no committed items are waiting to be received
    /// @return true if the ring buffer has no items pending for the consumer.
    bool is_empty() const {
        return this->items_waiting() == 0;
    }

    /// @brief Two-phase write: acquire contiguous space
    /// @param size Number of bytes to acquire.
    /// @param timeout_ms Milliseconds to wait if space is unavailable (UINT32_MAX = wait forever).
    /// @return Pointer to acquired space, or nullptr on timeout.
    void* acquire(size_t size, uint32_t timeout_ms) {
        void* ptr = nullptr;
        if (xRingbufferSendAcquire(this->handle_, &ptr, size, pdMS_TO_TICKS(timeout_ms)) !=
            pdTRUE) {
            return nullptr;
        }
        return ptr;
    }

    /// @brief Two-phase write: commit previously acquired space
    /// @param ptr Pointer returned by a prior call to acquire().
    /// @return true on success.
    bool commit(void* ptr) {
        bool ok = xRingbufferSendComplete(this->handle_, ptr) == pdTRUE;
        if (ok) {
            xSemaphoreGive(this->items_or_wake_sem_);
        }
        return ok;
    }

    /// @brief One-phase write: copy data into the ring buffer
    /// @param data Pointer to the data to copy.
    /// @param size Number of bytes to copy.
    /// @param timeout_ms Milliseconds to wait if space is unavailable (UINT32_MAX = wait forever).
    /// @return true if the data was written successfully.
    bool send(const void* data, size_t size, uint32_t timeout_ms) {
        bool ok = xRingbufferSend(this->handle_, data, size, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
        if (ok) {
            xSemaphoreGive(this->items_or_wake_sem_);
        }
        return ok;
    }

    /// @brief Receive the next item; caller must call return_item() when done
    /// @param[out] item_size Set to the size of the received item.
    /// @param timeout_ms Milliseconds to wait if no item is available (UINT32_MAX = wait forever).
    /// @return Pointer to item data, or nullptr on timeout or wake_receiver() interruption.
    void* receive(size_t* item_size, uint32_t timeout_ms) {
        // The blocking wait goes through items_or_wake_sem_, not the ring buffer's own
        // blocking receive, so wake_receiver() can interrupt it. The semaphore is binary,
        // so a burst of sends collapses into one token; the non-blocking poll below (before
        // the wait, and again for every call while data remains) is what guarantees items
        // are never stranded behind a collapsed token.
        void* item = xRingbufferReceive(this->handle_, item_size, 0);
        if (item != nullptr || timeout_ms == 0) {
            return item;
        }
        TickType_t ticks = timeout_ms == UINT32_MAX ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
        if (xSemaphoreTake(this->items_or_wake_sem_, ticks) != pdTRUE) {
            return nullptr;  // Timed out
        }
        // Woken by a send or by wake_receiver(); either way report what the buffer holds now.
        return xRingbufferReceive(this->handle_, item_size, 0);
    }

    /// @brief Wakes the consumer out of a blocking receive() without providing data
    ///
    /// One-shot: the blocked (or next blocking) receive() returns early. Redundant wakes
    /// collapse into one, and a wake that races an arriving item may be absorbed by that
    /// item's delivery -- so callers must re-check their stop/command state after every
    /// receive() return, not only after nullptr returns. Safe to call from any thread.
    void wake_receiver() {
        xSemaphoreGive(this->items_or_wake_sem_);
    }

    /// @brief Return a previously received item to the ring buffer
    /// @param ptr Pointer returned by a prior call to receive().
    void return_item(void* ptr) {
        vRingbufferReturnItem(this->handle_, ptr);
    }

private:
    // Struct fields
    StaticRingbuffer_t structure_;

    // Pointer fields
    RingbufHandle_t handle_{nullptr};
    // Given by every send()/commit() and by wake_receiver(); receive() blocks on this
    // instead of on the ring buffer so it stays interruptible.
    SemaphoreHandle_t items_or_wake_sem_{nullptr};
};

}  // namespace sendspin

#else  // Host

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>

namespace sendspin {

/**
 * @brief Single-producer/single-consumer ring buffer with caller-provided storage
 *
 * Backed by a mutex/condition-variable implementation on host. Items are written as
 * contiguous blobs and read back in the same order. Supports both a one-phase send()
 * and a two-phase acquire()/commit() path for zero-copy writes.
 *
 * A blocking receive() can be interrupted from any thread with wake_receiver(): the
 * blocked (or next blocking) receive returns nullptr immediately without consuming
 * data. Callers must therefore treat a nullptr return as "re-check state and retry",
 * not as proof the timeout elapsed.
 *
 * Usage:
 * 1. Allocate a storage buffer, then call create() with a pointer to it
 * 2. Write data with send() or acquire()/commit() from the producer thread
 * 3. Read data with receive() from the consumer thread
 * 4. Call return_item() after processing each received item
 *
 * @code
 * static uint8_t buf[4096];
 * SpscRingBuffer rb;
 * rb.create(sizeof(buf), buf);
 *
 * rb.send(data, data_len, 100);
 *
 * size_t sz;
 * void* item = rb.receive(&sz, UINT32_MAX);
 * // process item...
 * rb.return_item(item);
 * @endcode
 */
class SpscRingBuffer {
public:
    SpscRingBuffer() = default;
    ~SpscRingBuffer() = default;

    // Not copyable or movable
    SpscRingBuffer(const SpscRingBuffer&) = delete;
    SpscRingBuffer& operator=(const SpscRingBuffer&) = delete;

    /// @brief Creates the ring buffer with caller-provided storage
    /// @param size Total storage size in bytes.
    /// @param storage Pointer to pre-allocated storage (must outlive this object).
    /// @return true on success.
    bool create(size_t size, uint8_t* storage) {
        // Item offsets always advance in ALIGNMENT multiples, so an unaligned tail would
        // desynchronize the writer/reader dummy-filler accounting (and a tail smaller than
        // ItemHeader can never hold the wrap marker). Ignore any trailing remainder.
        size &= ~(ALIGNMENT - 1);
        if (size < sizeof(ItemHeader) + ALIGNMENT) {
            return false;
        }
        this->storage_ = storage;
        this->storage_size_ = size;
        this->write_offset_ = 0;
        this->read_offset_ = 0;
        this->free_bytes_ = size;
        this->items_waiting_ = 0;
        this->created_ = true;
        return true;
    }

    /// @brief Returns true if the ring buffer has been successfully created
    /// @return true if the ring buffer is ready for use.
    bool is_created() const {
        return this->created_;
    }

    /// @brief Returns the number of committed items waiting to be received
    /// @return Count of items written and committed but not yet received by the consumer.
    size_t items_waiting() const {
        std::lock_guard<std::mutex> lock(this->mtx_);
        return this->items_waiting_;
    }

    /// @brief Returns true if no committed items are waiting to be received
    /// @return true if the ring buffer has no items pending for the consumer.
    bool is_empty() const {
        std::lock_guard<std::mutex> lock(this->mtx_);
        return this->items_waiting_ == 0;
    }

    /// @brief Two-phase write: acquire contiguous space
    /// @param size Number of bytes to acquire.
    /// @param timeout_ms Milliseconds to wait if space is unavailable (UINT32_MAX = wait forever).
    /// @return Pointer to acquired space, or nullptr on timeout.
    void* acquire(size_t size, uint32_t timeout_ms) {
        size_t total = item_total_size(size);
        std::unique_lock<std::mutex> lock(this->mtx_);

        size_t offset = try_acquire(total);
        if (offset == SIZE_MAX) {
            if (timeout_ms == 0) {
                return nullptr;
            }
            if (timeout_ms == UINT32_MAX) {
                this->cv_write_.wait(lock, [&] {
                    offset = try_acquire(total);
                    return offset != SIZE_MAX;
                });
            } else {
                bool ok =
                    this->cv_write_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
                        offset = try_acquire(total);
                        return offset != SIZE_MAX;
                    });
                if (!ok) {
                    return nullptr;
                }
            }
        }

        auto* header = reinterpret_cast<ItemHeader*>(this->storage_ + offset);
        header->size = static_cast<uint32_t>(size);
        header->flags = FLAG_ACQUIRED;

        void* ptr = this->storage_ + offset + sizeof(ItemHeader);
        this->write_offset_ = offset + total;
        if (this->write_offset_ >= this->storage_size_) {
            this->write_offset_ = 0;
        }
        this->free_bytes_ -= total;

        return ptr;
    }

    /// @brief Two-phase write: commit previously acquired space
    /// @param ptr Pointer returned by a prior call to acquire().
    /// @return true on success.
    bool commit(void* ptr) {
        std::lock_guard<std::mutex> lock(this->mtx_);
        auto* header =
            reinterpret_cast<ItemHeader*>(static_cast<uint8_t*>(ptr) - sizeof(ItemHeader));
        header->flags = FLAG_WRITTEN;
        ++this->items_waiting_;
        this->cv_read_.notify_all();
        return true;
    }

    /// @brief One-phase write: copy data into the ring buffer
    /// @param data Pointer to the data to copy.
    /// @param size Number of bytes to copy.
    /// @param timeout_ms Milliseconds to wait if space is unavailable (UINT32_MAX = wait forever).
    /// @return true if the data was written successfully.
    bool send(const void* data, size_t size, uint32_t timeout_ms) {
        void* dest = acquire(size, timeout_ms);
        if (dest == nullptr) {
            return false;
        }
        std::memcpy(dest, data, size);
        return commit(dest);
    }

    /// @brief Receive the next item; caller must call return_item() when done
    /// @param[out] item_size Set to the size of the received item.
    /// @param timeout_ms Milliseconds to wait if no item is available (UINT32_MAX = wait forever).
    /// @return Pointer to item data, or nullptr on timeout or wake_receiver() interruption.
    void* receive(size_t* item_size, uint32_t timeout_ms) {
        std::unique_lock<std::mutex> lock(this->mtx_);

        void* result = try_read(item_size);
        if (result != nullptr) {
            return result;
        }

        if (timeout_ms == 0) {
            return nullptr;
        }

        auto pred = [&] {
            result = try_read(item_size);
            return result != nullptr || this->wake_pending_;
        };
        if (timeout_ms == UINT32_MAX) {
            this->cv_read_.wait(lock, pred);
        } else {
            this->cv_read_.wait_for(lock, std::chrono::milliseconds(timeout_ms), pred);
        }

        // A pending wake is consumed by whichever blocking receive it terminates, even when
        // an item arrived in the same window (mirroring the ESP binary-semaphore collapse);
        // callers re-check their stop/command state after every return.
        this->wake_pending_ = false;
        return result;
    }

    /// @brief Wakes the consumer out of a blocking receive() without providing data
    ///
    /// One-shot: the blocked (or next blocking) receive() returns early. Redundant wakes
    /// collapse into one, and a wake that races an arriving item may be absorbed by that
    /// item's delivery -- so callers must re-check their stop/command state after every
    /// receive() return, not only after nullptr returns. Safe to call from any thread.
    void wake_receiver() {
        {
            std::lock_guard<std::mutex> lock(this->mtx_);
            this->wake_pending_ = true;
        }
        this->cv_read_.notify_all();
    }

    /// @brief Return a previously received item to the ring buffer
    /// @param ptr Pointer returned by a prior call to receive().
    void return_item(void* ptr) {
        std::lock_guard<std::mutex> lock(this->mtx_);
        auto* header =
            reinterpret_cast<ItemHeader*>(static_cast<uint8_t*>(ptr) - sizeof(ItemHeader));
        size_t total = item_total_size(header->size);

        header->flags = FLAG_FREE;
        this->read_offset_ += total;
        if (this->read_offset_ >= this->storage_size_) {
            this->read_offset_ = 0;
        }
        this->free_bytes_ += total;

        this->cv_write_.notify_all();
    }

private:
    /// @brief Per-item metadata stored inline in the ring buffer ahead of each item's payload
    struct ItemHeader {
        uint32_t size;
        uint32_t flags;
    };

    static constexpr uint32_t FLAG_FREE = 0;
    static constexpr uint32_t FLAG_ACQUIRED = 1;
    static constexpr uint32_t FLAG_DUMMY = 2;
    static constexpr uint32_t FLAG_WRITTEN = 3;

    static constexpr size_t ALIGNMENT = 8;
    static_assert(sizeof(ItemHeader) % ALIGNMENT == 0,
                  "ItemHeader size must be a multiple of ALIGNMENT");

    /// @brief Rounds n up to the nearest multiple of ALIGNMENT
    static size_t align(size_t n) {
        return (n + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
    }

    /// @brief Returns the total storage occupied by one item including its header and alignment
    static size_t item_total_size(size_t data_size) {
        return sizeof(ItemHeader) + align(data_size);
    }

    /// @brief Attempts to reserve space for an item of total bytes; returns offset or SIZE_MAX
    size_t try_acquire(size_t total) {
        if (this->free_bytes_ < total) {
            return SIZE_MAX;
        }

        // Fits at current write offset?
        if (this->write_offset_ + total <= this->storage_size_) {
            return this->write_offset_;
        }

        // Need to wrap -- insert dummy to fill tail
        size_t tail_space = this->storage_size_ - this->write_offset_;
        if (tail_space >= sizeof(ItemHeader)) {
            if (this->free_bytes_ >= tail_space + total && total <= this->storage_size_) {
                auto* dummy = reinterpret_cast<ItemHeader*>(this->storage_ + this->write_offset_);
                dummy->size = static_cast<uint32_t>(tail_space - sizeof(ItemHeader));
                dummy->flags = FLAG_DUMMY;
                this->write_offset_ = 0;
                this->free_bytes_ -= tail_space;
                return 0;
            }
        }

        return SIZE_MAX;
    }

    /// @brief Attempts to read the next committed item; returns a pointer or nullptr if none ready
    void* try_read(size_t* item_size) {
        while (this->read_offset_ != this->write_offset_ || this->free_bytes_ == 0) {
            if (this->read_offset_ >= this->storage_size_) {
                this->read_offset_ = 0;
            }
            auto* header = reinterpret_cast<ItemHeader*>(this->storage_ + this->read_offset_);
            if (header->flags == FLAG_DUMMY) {
                size_t skip = sizeof(ItemHeader) + align(header->size);
                this->read_offset_ += skip;
                this->free_bytes_ += skip;
                this->cv_write_.notify_all();
                continue;
            }
            if (header->flags == FLAG_WRITTEN) {
                *item_size = header->size;
                --this->items_waiting_;
                return this->storage_ + this->read_offset_ + sizeof(ItemHeader);
            }
            // ACQUIRED but not yet committed -- wait
            break;
        }
        return nullptr;
    }

    // Struct fields
    std::condition_variable cv_read_;
    std::condition_variable cv_write_;
    mutable std::mutex mtx_;

    // Pointer fields
    uint8_t* storage_{nullptr};

    // size_t fields
    size_t free_bytes_{0};
    size_t items_waiting_{0};
    size_t read_offset_{0};
    size_t storage_size_{0};
    size_t write_offset_{0};

    // 8-bit fields
    bool created_{false};
    bool wake_pending_{false};
};

}  // namespace sendspin

#endif  // ESP_PLATFORM
