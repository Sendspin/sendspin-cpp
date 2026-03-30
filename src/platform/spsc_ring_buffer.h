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

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef ESP_PLATFORM

// ESP-IDF: thin wrapper around FreeRTOS NOSPLIT ring buffer (uses direct task notifications)
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>

namespace sendspin {

class SpscRingBuffer {
public:
    SpscRingBuffer() = default;
    ~SpscRingBuffer() {
        if (this->handle_ != nullptr) {
            vRingbufferDelete(this->handle_);
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
        return this->handle_ != nullptr;
    }

    /// @brief Returns true if the ring buffer has been successfully created.
    /// @return true if the ring buffer is ready for use.
    bool is_created() const {
        return this->handle_ != nullptr;
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
        return xRingbufferSendComplete(this->handle_, ptr) == pdTRUE;
    }

    /// @brief One-phase write: copy data into the ring buffer
    /// @param data Pointer to the data to copy.
    /// @param size Number of bytes to copy.
    /// @param timeout_ms Milliseconds to wait if space is unavailable (UINT32_MAX = wait forever).
    /// @return true if the data was written successfully.
    bool send(const void* data, size_t size, uint32_t timeout_ms) {
        return xRingbufferSend(this->handle_, data, size, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
    }

    /// @brief Receive the next item; caller must call return_item() when done
    /// @param[out] item_size Set to the size of the received item.
    /// @param timeout_ms Milliseconds to wait if no item is available (UINT32_MAX = wait forever).
    /// @return Pointer to item data, or nullptr on timeout.
    void* receive(size_t* item_size, uint32_t timeout_ms) {
        return xRingbufferReceive(this->handle_, item_size, pdMS_TO_TICKS(timeout_ms));
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
};

}  // namespace sendspin

#else  // Host

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>

namespace sendspin {

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
        this->storage_ = storage;
        this->storage_size_ = size;
        this->write_offset_ = 0;
        this->read_offset_ = 0;
        this->free_bytes_ = size;
        this->created_ = true;
        return true;
    }

    /// @brief Returns true if the ring buffer has been successfully created.
    /// @return true if the ring buffer is ready for use.
    bool is_created() const {
        return this->created_;
    }

    /// @brief Two-phase write: acquire contiguous space
    /// @param size Number of bytes to acquire.
    /// @param timeout_ms Milliseconds to wait if space is unavailable (UINT32_MAX = wait forever).
    /// @return Pointer to acquired space, or nullptr on timeout.
    void* acquire(size_t size, uint32_t timeout_ms) {
        size_t total = item_total_size_(size);
        std::unique_lock<std::mutex> lock(this->mtx_);

        size_t offset = try_acquire_(total);
        if (offset == SIZE_MAX) {
            if (timeout_ms == 0) {
                return nullptr;
            }
            if (timeout_ms == UINT32_MAX) {
                this->cv_write_.wait(lock, [&] {
                    offset = try_acquire_(total);
                    return offset != SIZE_MAX;
                });
            } else {
                bool ok =
                    this->cv_write_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
                        offset = try_acquire_(total);
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
    /// @return Pointer to item data, or nullptr on timeout.
    void* receive(size_t* item_size, uint32_t timeout_ms) {
        std::unique_lock<std::mutex> lock(this->mtx_);

        void* result = try_read_(item_size);
        if (result != nullptr) {
            return result;
        }

        if (timeout_ms == 0) {
            return nullptr;
        }

        if (timeout_ms == UINT32_MAX) {
            this->cv_read_.wait(lock, [&] {
                result = try_read_(item_size);
                return result != nullptr;
            });
        } else {
            this->cv_read_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
                result = try_read_(item_size);
                return result != nullptr;
            });
        }

        return result;
    }

    /// @brief Return a previously received item to the ring buffer
    /// @param ptr Pointer returned by a prior call to receive().
    void return_item(void* ptr) {
        std::lock_guard<std::mutex> lock(this->mtx_);
        auto* header =
            reinterpret_cast<ItemHeader*>(static_cast<uint8_t*>(ptr) - sizeof(ItemHeader));
        size_t total = item_total_size_(header->size);

        header->flags = FLAG_FREE;
        this->read_offset_ += total;
        if (this->read_offset_ >= this->storage_size_) {
            this->read_offset_ = 0;
        }
        this->free_bytes_ += total;

        this->cv_write_.notify_all();
    }

private:
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

    static size_t align_(size_t n) {
        return (n + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
    }

    static size_t item_total_size_(size_t data_size) {
        return sizeof(ItemHeader) + align_(data_size);
    }

    size_t try_acquire_(size_t total) {
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

    void* try_read_(size_t* item_size) {
        while (this->read_offset_ != this->write_offset_ || this->free_bytes_ == 0) {
            if (this->read_offset_ >= this->storage_size_) {
                this->read_offset_ = 0;
            }
            auto* header = reinterpret_cast<ItemHeader*>(this->storage_ + this->read_offset_);
            if (header->flags == FLAG_DUMMY) {
                size_t skip = sizeof(ItemHeader) + align_(header->size);
                this->read_offset_ += skip;
                this->free_bytes_ += skip;
                this->cv_write_.notify_all();
                continue;
            }
            if (header->flags == FLAG_WRITTEN) {
                *item_size = header->size;
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
    std::mutex mtx_;

    // Pointer fields
    uint8_t* storage_{nullptr};

    // size_t fields
    size_t free_bytes_{0};
    size_t read_offset_{0};
    size_t storage_size_{0};
    size_t write_offset_{0};

    // 8-bit fields
    bool created_{false};
};

}  // namespace sendspin

#endif  // ESP_PLATFORM
