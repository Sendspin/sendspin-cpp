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

#include <cstdint>

#ifdef ESP_PLATFORM

// ESP-IDF: thin wrapper around FreeRTOS event group (uses direct task notifications)
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>

namespace sendspin {

class EventFlags {
public:
    EventFlags() = default;
    ~EventFlags() {
        if (this->handle_ != nullptr) {
            vEventGroupDelete(this->handle_);
        }
    }

    // Not copyable or movable
    EventFlags(const EventFlags&) = delete;
    EventFlags& operator=(const EventFlags&) = delete;

    /// Creates the event flags group.
    /// @return true on success.
    bool create() {
        this->handle_ = xEventGroupCreate();
        return this->handle_ != nullptr;
    }

    bool is_created() const {
        return this->handle_ != nullptr;
    }

    /// @brief Sets the specified bits. Returns the resulting bit pattern
    uint32_t set(uint32_t bits) {
        return xEventGroupSetBits(this->handle_, bits);
    }

    /// @brief Clears the specified bits. Returns the bits BEFORE clearing
    uint32_t clear(uint32_t bits) {
        return xEventGroupClearBits(this->handle_, bits);
    }

    /// @brief Returns the current bit pattern
    uint32_t get() const {
        return xEventGroupGetBits(this->handle_);
    }

    /// Waits for bits to be set.
    /// @param bits_to_wait Bitmask of bits to wait for.
    /// @param wait_all If true, wait for ALL bits; if false, wait for ANY bit.
    /// @param clear_on_exit If true, clear the waited bits before returning.
    /// @param timeout_ms Milliseconds to wait (UINT32_MAX = wait forever).
    /// @return The bit pattern at the time the wait completed or timed out.
    uint32_t wait(uint32_t bits_to_wait, bool wait_all, bool clear_on_exit, uint32_t timeout_ms) {
        return xEventGroupWaitBits(this->handle_, bits_to_wait, clear_on_exit ? pdTRUE : pdFALSE,
                                   wait_all ? pdTRUE : pdFALSE, pdMS_TO_TICKS(timeout_ms));
    }

private:
    // Pointer fields
    EventGroupHandle_t handle_{nullptr};
};

}  // namespace sendspin

#else  // Host

#include <chrono>
#include <condition_variable>
#include <mutex>

namespace sendspin {

class EventFlags {
public:
    EventFlags() = default;
    ~EventFlags() = default;

    // Not copyable or movable
    EventFlags(const EventFlags&) = delete;
    EventFlags& operator=(const EventFlags&) = delete;

    bool create() {
        this->created_ = true;
        return true;
    }

    bool is_created() const {
        return this->created_;
    }

    uint32_t set(uint32_t bits) {
        std::lock_guard<std::mutex> lock(this->mtx_);
        this->bits_ |= bits;
        this->cv_.notify_all();
        return this->bits_;
    }

    uint32_t clear(uint32_t bits) {
        std::lock_guard<std::mutex> lock(this->mtx_);
        uint32_t old = this->bits_;
        this->bits_ &= ~bits;
        return old;
    }

    uint32_t get() const {
        std::lock_guard<std::mutex> lock(this->mtx_);
        return this->bits_;
    }

    uint32_t wait(uint32_t bits_to_wait, bool wait_all, bool clear_on_exit, uint32_t timeout_ms) {
        std::unique_lock<std::mutex> lock(this->mtx_);

        auto pred = [&]() -> bool {
            if (wait_all) {
                return (this->bits_ & bits_to_wait) == bits_to_wait;
            } else {
                return (this->bits_ & bits_to_wait) != 0;
            }
        };

        if (!pred()) {
            if (timeout_ms == 0) {
                return this->bits_;
            }
            if (timeout_ms == UINT32_MAX) {
                this->cv_.wait(lock, pred);
            } else {
                this->cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), pred);
            }
        }

        uint32_t result = this->bits_;
        if (clear_on_exit && pred()) {
            this->bits_ &= ~bits_to_wait;
        }
        return result;
    }

private:
    // Struct fields
    std::condition_variable cv_;
    mutable std::mutex mtx_;

    // 32-bit fields
    uint32_t bits_{0};

    // 8-bit fields
    bool created_{false};
};

}  // namespace sendspin

#endif  // ESP_PLATFORM
