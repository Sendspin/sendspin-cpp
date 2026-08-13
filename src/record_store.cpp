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

#include <cstddef>
#include <cstring>
#include <utility>

static const char* const TAG = "sendspin.record_store";

namespace sendspin {

// ============================================================================
// Constructor
// ============================================================================

RecordStore::RecordStore(SendspinPersistenceProvider* provider,
                         bool initial_unpaired_access_enabled)
    : provider_(provider) {
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
            // psk_id is a pure function of the PSK, and the server derives it the same way to
            // reference the key in its handshake. A stored id that disagrees with the secret
            // (hand-provisioned by an application, or corrupted) would never resolve, so correct
            // it here rather than advertising a method that cannot complete.
            std::string derived = psk_id_for(pairing_psk_->psk);
            if (pairing_psk_->psk_id != derived) {
                SS_LOGW(TAG, "Stored Pairing PSK id %s does not match the PSK; using %s",
                        pairing_psk_->psk_id.c_str(), derived.c_str());
                pairing_psk_->psk_id = std::move(derived);
            }
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
            dynamic_pin_failures_ = config->dynamic_pin_failures;
            record_mode_psk_id_ = config->record_mode_psk_id;
            loaded_config = true;
            SS_LOGD(TAG, "Loaded pairing config: record_mode_psk_id=%s",
                    record_mode_psk_id_.c_str());
        }
    }

    // First-boot seed: the application's configured default for unpaired access applies only on
    // a genuine first boot. A loaded config always wins, so a server that turned unpaired access
    // off through management/set-pairing-config keeps it off across reboots. The value is
    // persisted below by the first-boot provisioning branch, which the !loaded_config condition
    // always enters.
    //
    // !loaded_config alone is NOT sufficient evidence of a first boot, and getting that wrong
    // fails open. load_pairing_config() returns nullopt both when nothing was ever stored and
    // when the stored config could not be read back -- the interface gives a provider no way to
    // distinguish the two, and the bundled FilePersistenceProvider collapses a JSON parse error
    // into "nothing stored". Records and config are separate provider calls, so a provider that
    // loses only the config blob (independent NVS keys, a torn write) would otherwise re-seed
    // unpaired access ON for a device that is still paired and had it deliberately turned off.
    // Any surviving provisioned material therefore vetoes the seed: this is a reboot with a
    // damaged config, not a first boot, and the safe default is the restrictive one.
    //
    // A store that lost EVERYTHING is indistinguishable from a factory-fresh device by
    // construction, so the seed does apply there -- as it does when there is no provider at all.
    const bool previously_provisioned = !records_.empty() || pairing_psk_.has_value();
    if (!loaded_config && !previously_provisioned) {
        unpaired_access_enabled_ = initial_unpaired_access_enabled;
    } else if (!loaded_config) {
        SS_LOGW(TAG,
                "No pairing config loaded but %zu record(s) survived; ignoring the unpaired-"
                "access seed and leaving unpaired access disabled",
                records_.size());
    }
    // Scope note: only unpaired_access_enabled_ is protected this way, and deliberately so. It
    // defaults to false, so declining to seed it can only ever withhold a permission -- it
    // cannot break a working device. The sibling flags (pairing_psk_enabled_,
    // dynamic_pin_enabled_) default to TRUE, so a config that fails to load does resurrect a
    // pairing method an operator had turned off, and the provisioning branch below persists
    // that. Forcing those to false here is not a correct fix: a provider that seeds records or a
    // Pairing PSK without implementing config persistence at all returns nullopt for exactly the
    // same reason a damaged one does, and disabling pairing for it would break a legitimate
    // integration. Closing that hole properly needs the provider interface to distinguish
    // "never stored" from "could not be read" -- a tri-state load result -- rather than more
    // guessing here.

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

        // Persist the new record and config. A rejected write leaves the record RAM-only for
        // this boot: the device stays usable (pairing_token() etc. still work against the
        // in-memory record), but the record will be regenerated on the next reboot, so any
        // token printed before persistence is fixed would silently stop working. Surface that
        // instead of logging success unconditionally.
        bool record_persisted = true;
        if (provider_ != nullptr) {
            record_persisted = provider_->save_pairing_record(shared_record);
            persist_config();
        }

        if (record_persisted) {
            SS_LOGI(TAG, "Provisioned shared-PSK fallback record: %s", shared_psk_id.c_str());
        } else {
            SS_LOGW(TAG,
                    "Provisioned shared-PSK fallback record %s but failed to persist it; it is "
                    "RAM-only for this boot and will be replaced (invalidating this token) on "
                    "the next reboot",
                    shared_psk_id.c_str());
        }
    }

    // Pairing PSK provisioning: pairing_psk is the one pairing method every client must
    // implement (spec #113/#122), so a client with no Pairing PSK would advertise a method it
    // cannot complete. Generate one when absent and persist it; the operator transfers it to a
    // server as a pairing token (SendspinClient::pairing_token()). The key is stable across
    // reboots once persisted; if persistence fails it is RAM-only for this boot, so a token
    // printed then will not survive a reboot (a warning is logged when this happens).
    if (!pairing_psk_.has_value()) {
        std::array<uint8_t, NOISE_PSK_SIZE> psk{};
        platform_random_bytes(psk.data(), psk.size());

        SendspinPairingPsk provisioned;
        provisioned.psk_id = psk_id_for(psk);
        provisioned.psk = psk;

        bool psk_persisted = true;
        if (provider_ != nullptr) {
            psk_persisted = provider_->save_pairing_psk(provisioned);
        }
        if (psk_persisted) {
            SS_LOGI(TAG, "Provisioned Sendspin Pairing PSK: %s", provisioned.psk_id.c_str());
        } else {
            SS_LOGW(TAG,
                    "Provisioned Sendspin Pairing PSK %s but failed to persist it; a pairing "
                    "token printed now will not survive a reboot",
                    provisioned.psk_id.c_str());
        }
        pairing_psk_ = std::move(provisioned);
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

    // 2. Accepted Pairing PSK. Excluded from the candidate set when pairing_psk is disabled in
    // the live pairing config (spec #116/#122): a handshake referencing it then fails as a
    // lookup miss, exactly as if no Pairing PSK were configured at all.
    if (pairing_psk_.has_value() && pairing_psk_->psk_id == psk_id && pairing_psk_enabled_) {
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
    return this->store_record_impl(std::move(record), /*supersede_server_id=*/false);
}

bool RecordStore::store_record_superseding(SendspinPairingRecord record) {
    return this->store_record_impl(std::move(record), /*supersede_server_id=*/true);
}

bool RecordStore::store_record_impl(SendspinPairingRecord record, bool supersede_server_id) {
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
        idx = records_.size() - 1;
    }

    // Pairing mints a fresh per-server PSK that REPLACES whatever that server held before, so
    // the new record is already persisted above and any OTHER record still bound to this
    // server_id is now redundant. Drop it, otherwise re-pairing accumulates a second working
    // PSK for the same server and "rotation" never revokes anything. Only the pairing path
    // asks for this: management/add-record stores plainly, because the spec's only stated
    // add-record collision rule is keyed on psk_id (a psk whose psk_id is already known is
    // already_exists) and it defines no outcome for a server_id collision -- silently deleting
    // a record the caller never named would be unattested by any result code. Shared-PSK
    // records (server_id absent) never match here.
    if (supersede_server_id && records_[idx].server_id.has_value()) {
        const std::string superseded_server_id = records_[idx].server_id.value();
        for (size_t i = 0; i < records_.size();) {
            if (i != idx && records_[i].server_id.has_value() &&
                records_[i].server_id.value() == superseded_server_id) {
                SS_LOGI(TAG, "Superseding prior record %s for server_id=%s",
                        records_[i].psk_id.c_str(), superseded_server_id.c_str());
                // The in-memory erase below is unconditional: the operator (or the pairing
                // exchange) asked for this credential to stop working, and keeping it in RAM
                // because the store could not be written would leave it usable right now, which
                // is strictly worse. But a delete that did not reach the store means the record
                // comes back at the next start, so say so loudly instead of reporting a
                // revocation that silently half-happened.
                if (provider_ != nullptr && !provider_->remove_pairing_record(records_[i].psk_id)) {
                    SS_LOGW(TAG,
                            "Superseded record %s but the provider did not delete it; it is gone "
                            "for this boot only and will be valid again after a reboot",
                            records_[i].psk_id.c_str());
                }
                records_.erase(records_.begin() + static_cast<ptrdiff_t>(i));
                if (i < idx) {
                    --idx;
                }
                continue;  // The element that shifted into position i still needs checking.
            }
            ++i;
        }
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
    // Erased from RAM regardless of the store's answer, and warned about when the store did not
    // take it -- see the same reasoning in store_record_impl()'s supersede loop.
    if (provider_ != nullptr && !provider_->remove_pairing_record(psk_id)) {
        SS_LOGW(TAG,
                "Removed record %s but the provider did not delete it; it is gone for this boot "
                "only and will be valid again after a reboot",
                psk_id.c_str());
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
    // Derive psk_id from the secret rather than trusting the caller's: it is the id the server
    // will reference in its handshake, so a supplied mismatch would make the key unresolvable.
    psk.psk_id = psk_id_for(psk.psk);
    pairing_psk_ = std::move(psk);
    if (provider_ != nullptr) {
        provider_->save_pairing_psk(pairing_psk_.value());
    }
}

void RecordStore::clear_pairing_psk() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    pairing_psk_.reset();
    if (provider_ != nullptr && !provider_->clear_pairing_psk()) {
        SS_LOGW(TAG,
                "Cleared the Pairing PSK but the provider did not delete it; it is gone for this "
                "boot only and will authenticate pairing again after a reboot");
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
// Dynamic-PIN failure counter (escalation)
// ============================================================================

void RecordStore::record_dynamic_pin_failure() {
    dynamic_pin_failures_++;
    SS_LOGW(TAG, "Dynamic-PIN failure recorded (count=%d, escalation threshold=%d)",
            dynamic_pin_failures_, DYNAMIC_PIN_ESCALATION_THRESHOLD);
    persist_config();
}

void RecordStore::reset_dynamic_pin_failures() {
    if (dynamic_pin_failures_ == 0) {
        return;  // Nothing to reset; skip the persistence write.
    }
    dynamic_pin_failures_ = 0;
    persist_config();
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
    if (provider_ != nullptr && !provider_->clear_static_pin()) {
        SS_LOGW(TAG,
                "Cleared the static PIN but the provider did not delete it; it is gone for this "
                "boot only and will pair devices again after a reboot");
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
    config.dynamic_pin_failures = dynamic_pin_failures_;
    config.record_mode_psk_id = record_mode_psk_id_;
    if (!provider_->save_pairing_config(config)) {
        SS_LOGW(TAG,
                "Provider rejected pairing config write (record_mode_psk_id=%s); the change is "
                "RAM-only for this boot and will not survive a reboot",
                config.record_mode_psk_id.c_str());
    }
}

}  // namespace sendspin
