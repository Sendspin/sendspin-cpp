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

/// @file thread_safe_queue.h
/// @brief Platform-abstracted bounded thread-safe queue backed by a FreeRTOS queue on ESP and a
/// mutex/condition-variable deque on host

#pragma once

#include <cstddef>
#include <cstdint>

#ifdef ESP_PLATFORM

// ESP-IDF: thin wrapper around FreeRTOS queue (uses direct task notifications, no std::deque)
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

#include <cstring>

namespace sendspin {

/**
 * @brief Bounded FIFO queue that is safe to use from multiple threads
 *
 * Backed by a FreeRTOS queue on ESP and a mutex/condition-variable deque on host.
 * Blocking send() and receive() calls wait up to a caller-specified timeout when
 * the queue is full or empty. A non-blocking overwrite() path is available for
 * single-item mailbox use.
 *
 * A blocking receive() can be interrupted from any thread with wake_receiver(): the
 * blocked (or next blocking) receive returns false immediately without consuming an
 * item. Callers must therefore treat a false return as "re-check state and retry",
 * not as proof the timeout elapsed. Blocking receive() assumes a single consumer
 * thread: with multiple concurrent receivers, one send may wake only one of them.
 *
 * Usage:
 * 1. Declare a ThreadSafeQueue<T> member and call create() with the desired depth
 * 2. Push items with send() from producer threads
 * 3. Pop items with receive() from consumer threads
 * 4. Call reset() to discard all pending items if needed
 *
 * @code
 * ThreadSafeQueue<int> q;
 * q.create(8);
 *
 * q.send(42, 100);
 *
 * int val;
 * q.receive(val, UINT32_MAX);
 * @endcode
 */
template <typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue() = default;
    ~ThreadSafeQueue() {
        if (this->handle_ != nullptr) {
            vQueueDelete(this->handle_);
        }
        if (this->items_or_wake_sem_ != nullptr) {
            vSemaphoreDelete(this->items_or_wake_sem_);
        }
    }

    // Not copyable or movable
    ThreadSafeQueue(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    /// @brief Creates the queue with the given maximum depth
    /// @param max_depth Maximum number of items the queue can hold.
    /// @param memory_caps ESP-IDF memory capability flags (e.g., MALLOC_CAP_SPIRAM).
    /// @return true on success.
    bool create(size_t max_depth, uint32_t memory_caps = 0) {
        if (memory_caps != 0) {
            this->handle_ = xQueueCreateWithCaps(max_depth, sizeof(T), memory_caps);
        } else {
            this->handle_ = xQueueCreate(max_depth, sizeof(T));
        }
        if (this->handle_ == nullptr) {
            return false;
        }
        this->items_or_wake_sem_ = xSemaphoreCreateBinary();
        if (this->items_or_wake_sem_ == nullptr) {
            vQueueDelete(this->handle_);
            this->handle_ = nullptr;
            return false;
        }
        return true;
    }

    /// @brief Returns true if the queue has been successfully created
    /// @return true if the queue is ready for use.
    bool is_created() const {
        return this->handle_ != nullptr;
    }

    /// @brief Sends an item to the back of the queue; blocks up to timeout_ms if full
    /// @param item Item to send.
    /// @param timeout_ms Milliseconds to wait if the queue is full (UINT32_MAX = wait forever).
    /// @return true if the item was sent successfully.
    bool send(const T& item, uint32_t timeout_ms) {
        bool ok = xQueueSend(this->handle_, &item, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
        if (ok) {
            xSemaphoreGive(this->items_or_wake_sem_);
        }
        return ok;
    }

    /// @brief Receives an item from the front of the queue; blocks up to timeout_ms if empty
    /// @param[out] item Populated with the received item on success.
    /// @param timeout_ms Milliseconds to wait if the queue is empty (UINT32_MAX = wait forever).
    /// @return true if an item was received successfully; false on timeout, on wake_receiver()
    /// interruption, or (at most once after a burst is drained) on a token a send left behind
    /// after its item was taken by the non-blocking poll. Callers must treat every false return
    /// as "re-check state and retry", never as proof the timeout elapsed.
    bool receive(T& item, uint32_t timeout_ms) {
        // The blocking wait goes through items_or_wake_sem_, not the queue's own blocking
        // receive, so wake_receiver() can interrupt it. The semaphore is binary, so a burst
        // of sends collapses into one token; the non-blocking poll below (before the wait,
        // and again for every call while items remain) is what guarantees items are never
        // stranded behind a collapsed token.
        if (xQueueReceive(this->handle_, &item, 0) == pdTRUE) {
            return true;
        }
        if (timeout_ms == 0) {
            return false;
        }
        TickType_t ticks = timeout_ms == UINT32_MAX ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
        if (xSemaphoreTake(this->items_or_wake_sem_, ticks) != pdTRUE) {
            return false;  // Timed out
        }
        // Woken by a send or by wake_receiver(); either way report what the queue holds now.
        return xQueueReceive(this->handle_, &item, 0) == pdTRUE;
    }

    /// @brief Wakes the consumer out of a blocking receive() without providing an item
    ///
    /// One-shot: the blocked (or next blocking) receive() returns early. Redundant wakes
    /// collapse into one, and a wake that races an arriving item may be absorbed by that
    /// item's delivery -- so callers must re-check their stop/command state after every
    /// receive() return, not only after false returns. Safe to call from any thread.
    void wake_receiver() {
        xSemaphoreGive(this->items_or_wake_sem_);
    }

    /// @brief Peeks at the front item without removing it; returns false if empty
    /// @param[out] item Populated with the front item on success.
    /// @return true if the queue was non-empty.
    bool peek(T& item) const {
        return xQueuePeek(this->handle_, &item, 0) == pdTRUE;
    }

    /// @brief Overwrites the back item (or enqueues if empty); never blocks
    /// @param item Item to write.
    /// @return true on success.
    bool overwrite(const T& item) {
        bool ok = xQueueOverwrite(this->handle_, &item) == pdTRUE;
        if (ok) {
            xSemaphoreGive(this->items_or_wake_sem_);
        }
        return ok;
    }

    /// @brief Discards all items in the queue
    void reset() {
        xQueueReset(this->handle_);
    }

private:
    // Pointer fields
    QueueHandle_t handle_{nullptr};
    // Given by every send()/overwrite() and by wake_receiver(); receive() blocks on this
    // instead of on the queue so it stays interruptible.
    SemaphoreHandle_t items_or_wake_sem_{nullptr};
};

}  // namespace sendspin

#else  // Host

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>

namespace sendspin {

/**
 * @brief Bounded FIFO queue that is safe to use from multiple threads
 *
 * Backed by a mutex/condition-variable deque on host. Blocking send() and receive()
 * calls wait up to a caller-specified timeout when the queue is full or empty. A
 * non-blocking overwrite() path is available for single-item mailbox use.
 *
 * A blocking receive() can be interrupted from any thread with wake_receiver(): the
 * blocked (or next blocking) receive returns false immediately without consuming an
 * item. Callers must therefore treat a false return as "re-check state and retry",
 * not as proof the timeout elapsed. Blocking receive() assumes a single consumer
 * thread: with multiple concurrent receivers, one send may wake only one of them.
 *
 * Usage:
 * 1. Declare a ThreadSafeQueue<T> member and call create() with the desired depth
 * 2. Push items with send() from producer threads
 * 3. Pop items with receive() from consumer threads
 * 4. Call reset() to discard all pending items if needed
 *
 * @code
 * ThreadSafeQueue<int> q;
 * q.create(8);
 *
 * q.send(42, 100);
 *
 * int val;
 * q.receive(val, UINT32_MAX);
 * @endcode
 */
template <typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue() = default;
    ~ThreadSafeQueue() = default;

    // Not copyable or movable
    ThreadSafeQueue(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    /// @brief Creates the queue with the given maximum depth
    /// @param max_depth Maximum number of items the queue can hold.
    /// @param memory_caps Ignored on host.
    /// @return true on success.
    bool create(size_t max_depth, uint32_t /*memory_caps*/ = 0) {
        this->max_depth_ = max_depth;
        this->created_ = true;
        return true;
    }

    /// @brief Returns true if the queue has been successfully created
    /// @return true if the queue is ready for use.
    bool is_created() const {
        return this->created_;
    }

    /// @brief Sends an item to the back of the queue; blocks up to timeout_ms if full
    /// @param item Item to send.
    /// @param timeout_ms Milliseconds to wait if the queue is full (UINT32_MAX = wait forever).
    /// @return true if the item was sent successfully.
    bool send(const T& item, uint32_t timeout_ms) {
        std::unique_lock<std::mutex> lock(this->mtx_);
        if (this->items_.size() >= this->max_depth_) {
            if (timeout_ms == 0) {
                return false;
            }
            auto pred = [&] { return this->items_.size() < this->max_depth_; };
            if (timeout_ms == UINT32_MAX) {
                this->cv_.wait(lock, pred);
            } else {
                if (!this->cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), pred)) {
                    return false;
                }
            }
        }
        this->items_.push_back(item);
        this->cv_.notify_all();
        return true;
    }

    /// @brief Receives an item from the front of the queue; blocks up to timeout_ms if empty
    /// @param[out] item Populated with the received item on success.
    /// @param timeout_ms Milliseconds to wait if the queue is empty (UINT32_MAX = wait forever).
    /// @return true if an item was received successfully; false on timeout or wake_receiver()
    /// interruption.
    bool receive(T& item, uint32_t timeout_ms) {
        std::unique_lock<std::mutex> lock(this->mtx_);
        if (this->items_.empty()) {
            if (timeout_ms == 0) {
                return false;
            }
            auto pred = [&] { return !this->items_.empty() || this->wake_pending_; };
            if (timeout_ms == UINT32_MAX) {
                this->cv_.wait(lock, pred);
            } else {
                this->cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), pred);
            }
            // A pending wake is consumed by whichever blocking receive it terminates, even
            // when an item arrived in the same window (mirroring the ESP binary-semaphore
            // collapse); callers re-check their stop/command state after every return.
            this->wake_pending_ = false;
        }
        if (this->items_.empty()) {
            return false;
        }
        item = this->items_.front();
        this->items_.pop_front();
        this->cv_.notify_all();
        return true;
    }

    /// @brief Wakes the consumer out of a blocking receive() without providing an item
    ///
    /// One-shot: the blocked (or next blocking) receive() returns early. Redundant wakes
    /// collapse into one, and a wake that races an arriving item may be absorbed by that
    /// item's delivery -- so callers must re-check their stop/command state after every
    /// receive() return, not only after false returns. Safe to call from any thread.
    void wake_receiver() {
        {
            std::lock_guard<std::mutex> lock(this->mtx_);
            this->wake_pending_ = true;
        }
        this->cv_.notify_all();
    }

    /// @brief Peeks at the front item without removing it; returns false if empty
    /// @param[out] item Populated with the front item on success.
    /// @return true if the queue was non-empty.
    bool peek(T& item) const {
        std::lock_guard<std::mutex> lock(this->mtx_);
        if (this->items_.empty()) {
            return false;
        }
        item = this->items_.front();
        return true;
    }

    /// @brief Overwrites the back item (or enqueues if empty); never blocks
    /// @param item Item to write.
    /// @return true on success.
    bool overwrite(const T& item) {
        std::lock_guard<std::mutex> lock(this->mtx_);
        if (this->items_.empty()) {
            this->items_.push_back(item);
        } else {
            this->items_.back() = item;
        }
        this->cv_.notify_all();
        return true;
    }

    /// @brief Discards all items in the queue
    void reset() {
        std::lock_guard<std::mutex> lock(this->mtx_);
        this->items_.clear();
        this->cv_.notify_all();
    }

private:
    // Struct fields
    std::condition_variable cv_;
    std::deque<T> items_;
    mutable std::mutex mtx_;

    // size_t fields
    size_t max_depth_{0};

    // 8-bit fields
    bool created_{false};
    bool wake_pending_{false};
};

}  // namespace sendspin

#endif  // ESP_PLATFORM
