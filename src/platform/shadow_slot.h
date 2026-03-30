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

#include <mutex>
#include <utility>

namespace sendspin {

/// @brief Thread-safe shadow slot for passing state between threads
/// The writer (e.g., network thread) locks briefly to write or merge a value.
/// The reader (e.g., main loop) locks briefly to move the value out if dirty.
template <typename T>
class ShadowSlot {
public:
    ShadowSlot() = default;
    ~ShadowSlot() = default;

    // Not copyable or movable
    ShadowSlot(const ShadowSlot&) = delete;
    ShadowSlot& operator=(const ShadowSlot&) = delete;

    /// @brief Overwrite the slot with a new value (latest-wins)
    void write(T value) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->slot_ = std::move(value);
        this->dirty_ = true;
    }

    /// @brief Merge a delta into the slot using a callable: fn(T& current, T&& delta)
    template <typename MergeFn>
    void merge(MergeFn&& fn, T delta) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        fn(this->slot_, std::move(delta));
        this->dirty_ = true;
    }

    /// @brief Move the accumulated value out if dirty. Returns true if a value was taken
    bool take(T& out) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        if (!this->dirty_) {
            return false;
        }
        out = std::move(this->slot_);
        this->slot_ = T{};
        this->dirty_ = false;
        return true;
    }

    /// @brief Discard any pending value
    void reset() {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->slot_ = T{};
        this->dirty_ = false;
    }

private:
    // Struct fields
    std::mutex mutex_;
    T slot_{};

    // 8-bit fields
    bool dirty_{false};
};

}  // namespace sendspin
