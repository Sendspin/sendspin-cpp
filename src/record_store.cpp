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

#include "record_store.h"

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "platform/crypto.h"
#include "platform/logging.h"

#include <algorithm>
#include <cstring>
#include <utility>

static const char* const TAG = "sendspin.record_store";

namespace sendspin {

// ============================================================================
// Constructor
// ============================================================================

RecordStore::RecordStore(SendspinPersistenceProvider* provider) : provider_(provider) {
    // Try loading persisted records and config first.
    bool loaded_config = false;
    if (provider_ != nullptr) {
        auto stored_records = provider_->load_pairing_records();
        for (auto& rec : stored_records) {
            records_.push_back(std::move(rec));
        }

        auto pairing_psk = provider_->load_pairing_psk();
        if (pairing_psk.has_value()) {
            pairing_psk_ = std::move(pairing_psk);
        }

        auto static_pin = provider_->load_static_pin();
        if (static_pin.has_value()) {
            static_pin_ = std::move(static_pin);
        }

        auto config = provider_->load_pairing_config();
        if (config.has_value()) {
            pairing_psk_enabled_ = config->pairing_psk_enabled;
            unpaired_access_enabled_ = config->unpaired_access_enabled;
            dynamic_pin_enabled_ = config->dynamic_pin_enabled;
            static_pin_enabled_ = config->static_pin_enabled;
            dynamic_pin_min_length_ = config->dynamic_pin_min_length;
            record_mode_psk_id_ = config->record_mode_psk_id;
            loaded_config = true;
            SS_LOGD(TAG, "Loaded pairing config: record_mode_psk_id=%s",
                    record_mode_psk_id_.c_str());
        }
    }

    // First-boot provisioning: if no config was loaded (or the referenced shared
    // record is missing), generate a fresh shared-PSK fallback record.
    if (!loaded_config || record_mode_psk_id_.empty() ||
        record_by_psk_id(record_mode_psk_id_) == nullptr) {
        SS_LOGD(TAG, "First-boot provisioning: generating shared-PSK fallback record");

        std::array<uint8_t, NOISE_PSK_SIZE> shared_psk{};
        platform_random_bytes(shared_psk.data(), shared_psk.size());
        std::string shared_psk_id = psk_id_for(shared_psk);

        SendspinPairingRecord shared_record;
        shared_record.psk_id = shared_psk_id;
        shared_record.psk = shared_psk;
        // server_id absent = shared record

        records_.push_back(shared_record);
        record_mode_psk_id_ = shared_psk_id;

        // Persist the new record and config.
        if (provider_ != nullptr) {
            provider_->save_pairing_record(shared_record);
            persist_config();
        }

        SS_LOGI(TAG, "Provisioned shared-PSK fallback record: %s", shared_psk_id.c_str());
    }
}

// ============================================================================
// PSK resolution
// ============================================================================

std::optional<ResolvedPsk> RecordStore::resolve_by_psk_id(const std::string& psk_id) const {
    // Runs on the network thread; lock against main-loop mutations of records_/pairing_psk_.
    // Calls the unlocked record_by_psk_id() helper, so no recursive acquisition occurs.
    std::lock_guard<std::mutex> lock(this->mutex_);

    // 1. Long-term records (highest priority).
    const SendspinPairingRecord* rec = record_by_psk_id(psk_id);
    if (rec != nullptr) {
        ResolvedPsk r;
        r.psk_id = rec->psk_id;
        r.psk = rec->psk;
        r.category = PskCategory::LONG_TERM;
        r.counterparty_id = rec->server_id;
        return r;
    }

    // 2. Accepted Pairing PSK.
    if (pairing_psk_.has_value() && pairing_psk_->psk_id == psk_id) {
        ResolvedPsk r;
        r.psk_id = pairing_psk_->psk_id;
        r.psk = pairing_psk_->psk;
        r.category = PskCategory::PAIRING;
        return r;
    }

    // 3. Sentinel PSK.
    if (psk_id == SENTINEL_PSK_ID) {
        ResolvedPsk r;
        r.psk_id = SENTINEL_PSK_ID;
        r.psk = SENTINEL_PSK;
        r.category = PskCategory::SENTINEL;
        return r;
    }

    return std::nullopt;
}

// ============================================================================
// Long-term record management
// ============================================================================

size_t RecordStore::find_index(const std::string& psk_id) const {
    for (size_t i = 0; i < records_.size(); ++i) {
        if (records_[i].psk_id == psk_id) {
            return i;
        }
    }
    return static_cast<size_t>(-1);
}

const SendspinPairingRecord* RecordStore::record_by_psk_id(const std::string& psk_id) const {
    size_t idx = find_index(psk_id);
    if (idx == static_cast<size_t>(-1)) {
        return nullptr;
    }
    return &records_[idx];
}

const SendspinPairingRecord* RecordStore::record_by_server_id(const std::string& server_id) const {
    for (const auto& rec : records_) {
        if (rec.server_id.has_value() && rec.server_id.value() == server_id) {
            return &rec;
        }
    }
    return nullptr;
}

bool RecordStore::store_record(SendspinPairingRecord record) {
    // Persist first: when the provider rejects the write, leave the in-memory store
    // untouched so the pairing fails closed (see the header contract). A deferred
    // provider (e.g. one that queues the flash write) reports success here and owns
    // the durability of the queued data.
    if (provider_ != nullptr && !provider_->save_pairing_record(record)) {
        SS_LOGW(TAG, "Provider rejected pairing record %s; not storing", record.psk_id.c_str());
        return false;
    }
    std::lock_guard<std::mutex> lock(this->mutex_);
    size_t idx = find_index(record.psk_id);
    if (idx != static_cast<size_t>(-1)) {
        records_[idx] = std::move(record);
    } else {
        records_.push_back(std::move(record));
    }
    return true;
}

void RecordStore::remove_record(const std::string& psk_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    size_t idx = find_index(psk_id);
    if (idx == static_cast<size_t>(-1)) {
        return;  // No-op if absent.
    }
    records_.erase(records_.begin() + static_cast<ptrdiff_t>(idx));
    if (provider_ != nullptr) {
        provider_->remove_pairing_record(psk_id);
    }
}

void RecordStore::mark_record_used(const std::string& psk_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    size_t idx = find_index(psk_id);
    if (idx == static_cast<size_t>(-1) || records_[idx].used) {
        return;
    }
    records_[idx].used = true;
    if (provider_ != nullptr) {
        provider_->save_pairing_record(records_[idx]);
    }
}

bool RecordStore::can_remove_record(const std::string& psk_id) const {
    return psk_id != record_mode_psk_id_;
}

// ============================================================================
// Pairing PSK
// ============================================================================

void RecordStore::set_pairing_psk(SendspinPairingPsk psk) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    pairing_psk_ = std::move(psk);
    if (provider_ != nullptr) {
        provider_->save_pairing_psk(pairing_psk_.value());
    }
}

void RecordStore::clear_pairing_psk() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    pairing_psk_.reset();
    if (provider_ != nullptr) {
        provider_->clear_pairing_psk();
    }
}

// ============================================================================
// Pairing config
// ============================================================================

bool RecordStore::is_shared_record(const ResolvedPsk& r) {
    return r.category == PskCategory::LONG_TERM && !r.counterparty_id.has_value();
}

bool RecordStore::set_record_mode_psk_id(const std::string& psk_id) {
    auto resolved = resolve_by_psk_id(psk_id);
    if (!resolved.has_value()) {
        SS_LOGE(TAG, "record_mode psk_id '%s' references no record", psk_id.c_str());
        return false;
    }
    if (!is_shared_record(resolved.value())) {
        SS_LOGE(TAG, "record_mode psk_id '%s' must reference a shared-PSK record", psk_id.c_str());
        return false;
    }
    record_mode_psk_id_ = psk_id;
    persist_config();
    return true;
}

void RecordStore::set_pairing_psk_enabled(bool enabled) {
    pairing_psk_enabled_ = enabled;
    persist_config();
}

void RecordStore::set_unpaired_access_enabled(bool enabled) {
    unpaired_access_enabled_ = enabled;
    persist_config();
}

void RecordStore::set_dynamic_pin_enabled(bool enabled) {
    dynamic_pin_enabled_ = enabled;
    persist_config();
}

void RecordStore::set_dynamic_pin_min_length(int length) {
    dynamic_pin_min_length_ = length;
    persist_config();
}

// ============================================================================
// PIN lockout (Phase 8b/8c)
// ============================================================================

void RecordStore::record_pin_failure(SendspinPairMethod method) {
    pin_failures_[method]++;
    SS_LOGW(TAG, "PIN failure recorded for %s (count=%d, threshold=%d)", to_cstr(method),
            pin_failures_[method], PIN_LOCKOUT_THRESHOLD);
}

void RecordStore::reset_pin_failures(SendspinPairMethod method) {
    pin_failures_.erase(method);
}

// ============================================================================
// Static PIN (Phase 8c)
// ============================================================================

void RecordStore::set_static_pin(const std::string& pin) {
    static_pin_ = pin;
    if (provider_ != nullptr) {
        provider_->save_static_pin(pin);
    }
}

void RecordStore::clear_static_pin() {
    static_pin_.reset();
    if (provider_ != nullptr) {
        provider_->clear_static_pin();
    }
}

void RecordStore::set_static_pin_enabled(bool enabled) {
    static_pin_enabled_ = enabled;
    persist_config();
}

// ============================================================================
// Pairing outcome
// ============================================================================

std::optional<RecordStore::PairingOutcome> RecordStore::resolve_pairing_outcome(
    const std::string& server_id, const std::optional<std::string>& label) {
    if (can_store_record()) {
        std::array<uint8_t, NOISE_PSK_SIZE> psk{};
        platform_random_bytes(psk.data(), psk.size());
        std::string pid = psk_id_for(psk);

        SendspinPairingRecord record;
        record.psk_id = pid;
        record.psk = psk;
        record.server_id = server_id;
        record.label = label;

        PairingOutcome outcome;
        outcome.psk = psk;
        outcome.record = std::move(record);
        return outcome;
    }

    // Storage exhausted: fall back to the shared-PSK record.
    auto resolved = resolve_by_psk_id(record_mode_psk_id_);
    if (!resolved.has_value() || !is_shared_record(resolved.value())) {
        SS_LOGE(TAG, "shared-PSK fallback record '%s' is missing or not shared",
                record_mode_psk_id_.c_str());
        return std::nullopt;
    }

    PairingOutcome outcome;
    outcome.psk = resolved->psk;
    // outcome.record is nullopt - caller should not store a new record.
    return outcome;
}

// ============================================================================
// Private helpers
// ============================================================================

void RecordStore::persist_config() {
    if (provider_ == nullptr) {
        return;
    }
    SendspinPairingConfig config;
    config.pairing_psk_enabled = pairing_psk_enabled_;
    config.unpaired_access_enabled = unpaired_access_enabled_;
    config.dynamic_pin_enabled = dynamic_pin_enabled_;
    config.static_pin_enabled = static_pin_enabled_;
    config.dynamic_pin_min_length = dynamic_pin_min_length_;
    config.record_mode_psk_id = record_mode_psk_id_;
    provider_->save_pairing_config(config);
}

}  // namespace sendspin
