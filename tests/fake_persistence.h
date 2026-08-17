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

/// @file fake_persistence.h
/// @brief Shared in-memory SendspinPersistenceProvider fake for tests.
///
/// A std::map<key, blob> plus fail-injection switches for save_blob()/erase_blob(), since
/// several tests exercise persist-failure paths (a rejected pairing record,
/// revocation-durability warnings). Prefer this over a bespoke per-file provider when a test
/// only needs a generic blob store with optional failure injection; keep a bespoke fake when a
/// test needs to observe or shape a specific call in a way this one does not (e.g. distinguishing
/// an add from a removal on the "records" key, or serving canned/mismatched codec content).

#pragma once

#include "sendspin/client.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace sendspin {

/// @brief In-memory blob store: every key/value survives only for the life of the fake (no real
/// file or NVS backing), with optional per-key or blanket save/erase rejection.
class InMemoryPersistenceProvider : public SendspinPersistenceProvider {
public:
    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        std::lock_guard<std::mutex> lock(this->mutex_);
        auto it = this->blobs_.find(key);
        if (it == this->blobs_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->save_attempts_[key]++;
        if (this->reject_all_saves || this->reject_save_keys.count(key) > 0) {
            return false;
        }
        this->blobs_[key] = std::vector<uint8_t>(data, data + len);
        return true;
    }

    bool erase_blob(const std::string& key) override {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->erase_attempts_[key]++;
        if (this->reject_all_erases || this->reject_erase_keys.count(key) > 0) {
            return false;
        }
        this->blobs_.erase(key);
        return true;
    }

    // ========================================
    // Test-only inspection helpers
    // ========================================

    /// @brief Directly seed a key's blob, bypassing save_blob() (and its fail-injection).
    void seed_blob(const std::string& key, std::vector<uint8_t> bytes) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->blobs_[key] = std::move(bytes);
    }

    /// @brief Read back the current raw blob for a key, or nullopt if absent.
    [[nodiscard]] std::optional<std::vector<uint8_t>> blob(const std::string& key) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        auto it = this->blobs_.find(key);
        if (it == this->blobs_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] int save_attempts(const std::string& key) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        auto it = this->save_attempts_.find(key);
        return it == this->save_attempts_.end() ? 0 : it->second;
    }

    [[nodiscard]] int erase_attempts(const std::string& key) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        auto it = this->erase_attempts_.find(key);
        return it == this->erase_attempts_.end() ? 0 : it->second;
    }

    // ========================================
    // Fail injection
    // ========================================

    bool reject_all_saves{false};
    bool reject_all_erases{false};
    std::set<std::string> reject_save_keys;
    std::set<std::string> reject_erase_keys;

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<uint8_t>> blobs_;
    std::map<std::string, int> save_attempts_;
    std::map<std::string, int> erase_attempts_;
};

}  // namespace sendspin
