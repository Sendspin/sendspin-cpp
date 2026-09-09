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

/// @file binary_send_registry.h
/// @brief Owner-scoped keep-alive registry for work queued into a queue with no cancellation
/// hook (ESP httpd_queue_work); platform-free so its transitions are unit-tested on host

#pragma once

#include <algorithm>
#include <memory>
#include <mutex>
#include <vector>

namespace sendspin {

/// @brief Keeps queued work blocks alive until their worker claims them or their owner's queue
/// is reclaimed
///
/// A Block must carry a `std::shared_ptr<Block> self` member. engage() parks the block's
/// self-reference (keeping it alive independently of everything else) and records it under an
/// opaque owner; claim() atomically takes the self-reference back for the worker that is about
/// to run; reclaim() breaks the self-references of ONE owner's still-engaged blocks. Scoping
/// discipline is the safety contract: reclaim an owner only once its queue can no longer run
/// workers (after httpd_stop for that handle), so a claim() against a reclaimed block never
/// happens with a dangling pointer, and other owners' queued work is never touched.
template <typename Block>
class BinarySendRegistry {
public:
    /// @brief Parks the block's self-reference and records it under the owner
    void engage(const std::shared_ptr<Block>& block, const void* owner) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        block->self = block;
        this->entries_.push_back(Entry{owner, block});
    }

    /// @brief Takes the self-reference back for the worker about to run
    /// @return The keep-alive reference, or empty if the block is no longer engaged (already
    ///         claimed, or its owner was reclaimed).
    std::shared_ptr<Block> claim(Block* raw) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        auto it = std::find_if(this->entries_.begin(), this->entries_.end(),
                               [&](const Entry& e) { return e.block.get() == raw; });
        if (it == this->entries_.end()) {
            return {};
        }
        std::shared_ptr<Block> keep = std::move(it->block->self);
        this->entries_.erase(it);
        return keep;
    }

    /// @brief Breaks the self-references of every block engaged under the owner
    /// @return Number of blocks reclaimed.
    size_t reclaim(const void* owner) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        size_t count = 0;
        for (auto it = this->entries_.begin(); it != this->entries_.end();) {
            if (it->owner == owner) {
                it->block->self.reset();
                it = this->entries_.erase(it);
                ++count;
            } else {
                ++it;
            }
        }
        return count;
    }

private:
    struct Entry {
        const void* owner;
        std::shared_ptr<Block> block;
    };

    std::mutex mutex_;
    std::vector<Entry> entries_;
};

}  // namespace sendspin
