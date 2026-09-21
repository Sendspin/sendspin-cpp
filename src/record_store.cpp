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
#include "crypto/pairing_code.h"
#include "platform/crypto.h"
#include "platform/logging.h"
#include "sendspin/persistence_codec.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

static const char* const TAG = "sendspin.record_store";

namespace sendspin {

namespace {

/// @brief The key long-term records shared before they moved to one slot per key. It is not part
/// of persistence_keys: nothing reads it, and the store's only interest in it is emptying it
/// once (see load_records_from_provider()).
constexpr const char* LEGACY_RECORDS_KEY = "records";

/// @brief Shared load -> string_view -> decode -> warn-on-failure -> secure_zero(blob) shape used
/// by the record-slot and PAIRING_PSK loaders below. STATIC_PAIRING_CODE (no decoder, no PSK
/// bytes) and PAIR_CONFIG (no PSK bytes) differ enough to stay direct.
/// @return The decoded value, or nullopt. The raw blob is wiped on both paths.
template <typename T>
std::optional<T> load_decode_wipe(SendspinPersistenceProvider& provider, const char* key,
                                  std::optional<T> (*decode)(std::string_view),
                                  const char* decode_fail_suffix) {
    auto blob = provider.load_blob(key);
    // An empty blob is "nothing stored here": it is how a freed record slot is written.
    if (!blob.has_value() || blob->empty()) {
        return std::nullopt;
    }
    std::string_view text(reinterpret_cast<const char*>(blob->data()), blob->size());
    auto decoded = decode(text);
    if (!decoded.has_value()) {
        SS_LOGW(TAG, "Stored \"%s\" blob failed to decode; %s", key, decode_fail_suffix);
    }
    secure_zero(blob->data(), blob->size());
    return decoded;
}

}  // namespace

// ============================================================================
// Constructor
// ============================================================================

RecordStore::RecordStore(SendspinPersistenceProvider* provider,
                         bool initial_unpaired_access_enabled, size_t max_records)
    : provider_(provider), max_records_(std::clamp(max_records, MIN_MAX_RECORDS, MAX_MAX_RECORDS)) {
    // Every blob here except the static pairing code (raw UTF-8) is codec-encoded: the provider
    // is a pure byte store, so decoding happens entirely on this side of the interface.
    bool loaded_config = false;
    if (this->provider_ != nullptr) {
        this->load_records_from_provider();
        this->load_pairing_psk_from_provider();
        this->load_static_pairing_code_from_provider();
        loaded_config = this->load_pairing_config_from_provider();
    }

    this->seed_first_boot_config(loaded_config, initial_unpaired_access_enabled);
    this->provision_pairing_psk_if_needed();
}

// ============================================================================
// Construction helpers
// ============================================================================

void RecordStore::load_records_from_provider() {
    // One record per slot key, so a slot that fails to decode (corrupt bytes, or a record the
    // codec rejects) costs only that record: the others are separate keys. An absent or empty
    // blob is a free slot. Slots at or above the configured cap are not read, so lowering the cap
    // between boots orphans the records above it rather than loading them.
    //
    // load_decode_wipe() logs the warning and wipes the raw blob on both paths; the raw blob is
    // base64 PSK text (even when it failed to decode), mirroring the save-path wipe in
    // save_slot_write().
    for (size_t slot = 0; slot < this->max_records_; ++slot) {
        const std::string key = persistence_keys::record_slot_key(slot);
        auto decoded = load_decode_wipe<SendspinPairingRecord>(
            *this->provider_, key.c_str(), decode_pairing_record, "ignoring that record");
        if (!decoded.has_value()) {
            continue;
        }
        // Two slots carrying the same psk_id would leave a revoked credential resolving: a
        // removal erases the first match from records_ and empties only that slot, so the
        // duplicate survives both the boot and the flush. Lowering max_pairing_records and
        // raising it again can produce one, so the lower slot wins and the later one is cleared.
        if (this->record_by_psk_id(decoded->psk_id) != nullptr) {
            SS_LOGW(TAG, "Clearing \"%s\": psk_id %s is already stored in a lower slot",
                    key.c_str(), decoded->psk_id.c_str());
            // Owed an empty write, or the duplicate would come back at every boot and outlive a
            // revocation of the record it shadows. Constructor: no other thread holds the store.
            this->mark_slot_dirty_locked(static_cast<uint8_t>(slot));
            continue;
        }
        this->records_.push_back(
            StoredRecord{std::move(decoded.value()), static_cast<uint8_t>(slot)});
    }
    this->load_record_order_from_provider();
    this->note_legacy_records_key();
}

void RecordStore::note_legacy_records_key() {
    // The pre-slot key holds base64url long-term PSKs for every server paired before the move to
    // per-slot keys. Nothing reads it any more and nothing else would ever overwrite it, so the
    // store empties it once: an empty blob rather than erase_blob(), which belongs to the
    // application and which this store's own free-slot marker does not use either. The write is
    // owed to the next persist_records() like any other, so it lands on the main loop.
    auto blob = this->provider_->load_blob(LEGACY_RECORDS_KEY);
    if (!blob.has_value() || blob->empty()) {
        return;
    }
    secure_zero(blob->data(), blob->size());
    SS_LOGW(TAG, "Clearing the pre-slot \"%s\" blob; the records it holds are not migrated",
            LEGACY_RECORDS_KEY);
    this->legacy_records_dirty_ = true;
}

void RecordStore::load_record_order_from_provider() {
    auto blob = this->provider_->load_blob(persistence_keys::RECORD_ORDER);
    if (!blob.has_value()) {
        return;
    }
    // The blob names the occupied slots least recently used first, one byte each, which is the
    // order records_ is kept in and evict_one_locked() reads. A byte naming no loaded record
    // (stale, or a slot that failed to decode) is skipped, and a loaded record the blob does not
    // name sorts after the ones it does, in slot order: a damaged order blob costs recency, not
    // records.
    std::vector<StoredRecord> ordered;
    ordered.reserve(this->records_.size());
    for (uint8_t slot : blob.value()) {
        auto it = std::find_if(this->records_.begin(), this->records_.end(),
                               [slot](const StoredRecord& s) { return s.slot == slot; });
        if (it == this->records_.end()) {
            continue;
        }
        ordered.push_back(std::move(*it));
        this->records_.erase(it);
    }
    for (auto& remaining : this->records_) {
        ordered.push_back(std::move(remaining));
    }
    this->records_ = std::move(ordered);
}

void RecordStore::load_pairing_psk_from_provider() {
    // Base64 PSK text like the record slots above; load_decode_wipe() wipes it on both paths.
    auto decoded = load_decode_wipe<SendspinPairingPsk>(
        *this->provider_, persistence_keys::PAIRING_PSK, decode_pairing_psk, "ignoring");
    if (decoded.has_value()) {
        this->pairing_psk_ = std::move(decoded);
        // psk_id is a pure function of the PSK, and the server derives it the same way to
        // reference the key in its handshake. A stored id that disagrees with the secret
        // (hand-provisioned by an application, or corrupted) would never resolve, so
        // correct it here rather than advertising a method that cannot complete.
        std::string derived = psk_id_for(this->pairing_psk_->psk);
        if (this->pairing_psk_->psk_id != derived) {
            SS_LOGW(TAG, "Stored Pairing PSK id %s does not match the PSK; using %s",
                    this->pairing_psk_->psk_id.c_str(), derived.c_str());
            this->pairing_psk_->psk_id = std::move(derived);
        }
    }
}

void RecordStore::load_static_pairing_code_from_provider() {
    if (auto code_blob = this->provider_->load_blob(persistence_keys::STATIC_PAIRING_CODE)) {
        std::string loaded_code(reinterpret_cast<const char*>(code_blob->data()),
                                code_blob->size());
        // Validate on load, the same way the records and PAIRING_PSK are validated by their
        // decoders: the code is provisioned into the store out of band, so this is the only
        // place the library gets to check it. Accepting a malformed code would advertise
        // static_pairing_code and then fail every pairing with pairing_code_mismatch, with
        // nothing in the logs pointing at storage.
        if (is_valid_static_pairing_code(loaded_code)) {
            this->static_pairing_code_ = std::move(loaded_code);
        } else {
            SS_LOGW(TAG,
                    "Stored \"%s\" blob is not a valid static pairing code (%zu bytes); "
                    "ignoring it, so static_pairing_code pairing stays unavailable until one is "
                    "set again",
                    persistence_keys::STATIC_PAIRING_CODE, loaded_code.size());
        }
    }
}

bool RecordStore::load_pairing_config_from_provider() {
    if (auto config_blob = this->provider_->load_blob(persistence_keys::PAIR_CONFIG)) {
        std::string_view text(reinterpret_cast<const char*>(config_blob->data()),
                              config_blob->size());
        auto config = decode_pairing_config(text);
        if (config.has_value()) {
            this->pairing_psk_enabled_ = config->pairing_psk_enabled;
            this->unpaired_access_enabled_ = config->unpaired_access_enabled;
            this->dynamic_pairing_code_enabled_ = config->dynamic_pairing_code_enabled;
            this->static_pairing_code_enabled_ = config->static_pairing_code_enabled;
            return true;
        }
        SS_LOGW(TAG, "Stored \"%s\" blob failed to decode; ignoring",
                persistence_keys::PAIR_CONFIG);
    }
    return false;
}

void RecordStore::seed_first_boot_config(bool loaded_config, bool initial_unpaired_access_enabled) {
    if (loaded_config) {
        return;
    }

    // First-boot seed: the application's configured default for unpaired access applies only on
    // a genuine first boot; a loaded config always wins.
    //
    // !loaded_config alone is not sufficient evidence of a first boot, and getting that wrong
    // fails open. loaded_config stays false both when the persistence_keys::PAIR_CONFIG blob was
    // never stored and when it was stored but failed to decode: the provider interface gives no
    // way to distinguish "absent" from "present but unreadable" (load_blob() returns nullopt for
    // the former; a decode failure on a non-nullopt blob is treated the same way, see
    // load_pairing_config_from_provider()). Records and config are separate keys, so a provider
    // that loses only the config blob (independent NVS keys, a torn write) would otherwise re-seed
    // unpaired access ON for a device that is still paired and had it deliberately turned off.
    // Any surviving provisioned material therefore vetoes the seed: this is a reboot with a
    // damaged config, not a first boot, and the safe default is the restrictive one.
    //
    // A store that lost everything is indistinguishable from a factory-fresh device by
    // construction, so the seed does apply there, as it does when there is no provider at all.
    const bool previously_provisioned = !this->records_.empty() || this->pairing_psk_.has_value();
    if (previously_provisioned) {
        SS_LOGW(TAG,
                "No pairing config loaded but %zu record(s) survived; ignoring the unpaired-"
                "access seed and leaving unpaired access disabled",
                this->records_.size());
    } else {
        this->unpaired_access_enabled_ = initial_unpaired_access_enabled;
    }
    // Only unpaired_access_enabled_ is protected this way: it defaults to false, so declining to
    // seed it can only withhold a permission. The sibling flags default to true, and forcing them
    // false here would break a provider that seeds records or a Pairing PSK without implementing
    // config persistence at all, which returns nullopt for the same reason a damaged store does.
    //
    // No lock needed here: the constructor runs before this object is reachable by any other
    // thread.
    this->persist_config();
}

void RecordStore::provision_pairing_psk_if_needed() {
    // pairing_psk is the one pairing method every client must implement (messaging.md
    // "client/hello"), so a client with no Pairing PSK would advertise a method it cannot
    // complete. The operator transfers the generated key to a server as a pairing token
    // (SendspinClient::pairing_token()). It is stable across reboots once persisted; if
    // persistence fails it is RAM-only for this boot, so a token printed then will not survive a
    // reboot.
    if (!this->pairing_psk_.has_value()) {
        std::array<uint8_t, NOISE_PSK_SIZE> psk{};
        platform_random_bytes(psk.data(), psk.size());

        SendspinPairingPsk provisioned;
        provisioned.psk_id = psk_id_for(psk);
        provisioned.psk = psk;

        bool psk_persisted = true;
        if (this->provider_ != nullptr) {
            std::string encoded = encode_pairing_psk(provisioned);
            psk_persisted = this->provider_->save_blob(
                persistence_keys::PAIRING_PSK, reinterpret_cast<const uint8_t*>(encoded.data()),
                encoded.size());
            // The encoded blob is base64 PSK text; wipe it now that save_blob() has its own copy
            // (or has failed), rather than leaving it for the string's destructor to free unwiped.
            secure_zero(encoded.data(), encoded.size());
        }
        if (psk_persisted) {
            SS_LOGI(TAG, "Provisioned Sendspin Pairing PSK: %s", provisioned.psk_id.c_str());
        } else {
            SS_LOGW(TAG,
                    "Provisioned Sendspin Pairing PSK %s but failed to persist it; a pairing "
                    "token printed now will not survive a reboot",
                    provisioned.psk_id.c_str());
        }
        this->pairing_psk_ = std::move(provisioned);
    }
}

// ============================================================================
// PSK resolution
// ============================================================================

std::optional<ResolvedPsk> RecordStore::resolve_by_psk_id(const std::string& psk_id,
                                                          PskCategory category) const {
    // Runs on the network thread; lock against main-loop mutations of records_/pairing_psk_.
    std::lock_guard<std::mutex> lock(this->mutex_);
    return this->resolve_by_psk_id_locked(psk_id, category);
}

std::optional<ResolvedPsk> RecordStore::resolve_by_psk_id_locked(const std::string& psk_id,
                                                                 PskCategory category) const {
    // Only the declared category's candidates are searched (connection.md "Pre-Shared Key"): the
    // same psk_id under another category is a lookup miss, which keeps a server from using, say, a
    // long-term PSK as though it were the Pairing PSK and inheriting that category's activities.
    switch (category) {
        case PskCategory::LONG_TERM: {
            const SendspinPairingRecord* rec = this->record_by_psk_id(psk_id);
            if (rec != nullptr) {
                ResolvedPsk r;
                r.psk_id = rec->psk_id;
                r.psk = rec->psk;
                r.category = PskCategory::LONG_TERM;
                r.counterparty_id = rec->server_id;
                return r;
            }
            break;
        }
        case PskCategory::PAIRING: {
            // Excluded from the candidate set when pairing_psk is disabled in the live pairing
            // config (connection.md "Pre-Shared Key"): a handshake referencing it then fails as a
            // lookup miss, exactly as if no Pairing PSK were configured at all.
            if (this->pairing_psk_.has_value() && this->pairing_psk_->psk_id == psk_id &&
                this->pairing_psk_enabled_) {
                ResolvedPsk r;
                r.psk_id = this->pairing_psk_->psk_id;
                r.psk = this->pairing_psk_->psk;
                r.category = PskCategory::PAIRING;
                return r;
            }
            break;
        }
        case PskCategory::SENTINEL: {
            if (psk_id == SENTINEL_PSK_ID) {
                ResolvedPsk r;
                r.psk_id = SENTINEL_PSK_ID;
                r.psk = SENTINEL_PSK;
                r.category = PskCategory::SENTINEL;
                return r;
            }
            break;
        }
    }

    return std::nullopt;
}

// ============================================================================
// Long-term record management
// ============================================================================

size_t RecordStore::find_index(const std::string& psk_id) const {
    for (size_t i = 0; i < this->records_.size(); ++i) {
        if (this->records_[i].record.psk_id == psk_id) {
            return i;
        }
    }
    return NPOS;
}

const RecordStore::StoredRecord* RecordStore::record_in_slot(uint8_t slot) const {
    for (const auto& stored : this->records_) {
        if (stored.slot == slot) {
            return &stored;
        }
    }
    return nullptr;
}

uint8_t RecordStore::first_free_slot_locked() const {
    for (size_t slot = 0; slot < this->max_records_; ++slot) {
        if (this->record_in_slot(static_cast<uint8_t>(slot)) == nullptr) {
            return static_cast<uint8_t>(slot);
        }
    }
    return UNASSIGNED_SLOT;
}

void RecordStore::mark_slot_dirty_locked(uint8_t slot) {
    if (std::find(this->dirty_slots_.begin(), this->dirty_slots_.end(), slot) ==
        this->dirty_slots_.end()) {
        this->dirty_slots_.push_back(slot);
    }
}

const SendspinPairingRecord* RecordStore::record_by_psk_id(const std::string& psk_id) const {
    size_t idx = this->find_index(psk_id);
    if (idx == NPOS) {
        return nullptr;
    }
    return &this->records_[idx].record;
}

const SendspinPairingRecord* RecordStore::record_by_server_id(const std::string& server_id) const {
    for (const auto& stored : this->records_) {
        if (stored.record.server_id == server_id) {
            return &stored.record;
        }
    }
    return nullptr;
}

bool RecordStore::evict_one_locked(const std::vector<std::string>& psk_ids_in_use) {
    // records_ runs least-recently-used first (see note_record_used), so the first record no open
    // connection is resolving against is the victim pairing.md "Pairing Records" leaves to the
    // implementation. Evicting one that backs an open connection would strand a live session on a
    // PSK this store no longer holds.
    for (size_t i = 0; i < this->records_.size(); ++i) {
        const std::string& psk_id = this->records_[i].record.psk_id;
        if (std::find(psk_ids_in_use.begin(), psk_ids_in_use.end(), psk_id) !=
            psk_ids_in_use.end()) {
            continue;
        }
        SS_LOGW(TAG, "Evicting record %s for server_id=%s to make room for a new pairing",
                psk_id.c_str(), this->records_[i].record.server_id.c_str());
        this->mark_slot_dirty_locked(this->records_[i].slot);
        this->order_dirty_ = true;
        this->records_.erase(this->records_.begin() + static_cast<ptrdiff_t>(i));
        return true;
    }
    return false;
}

bool RecordStore::store_record_superseding(SendspinPairingRecord record,
                                           const std::vector<std::string>& psk_ids_in_use) {
    // RAM-only: runs on the network thread (the server/pair-finalize ack handler), where the
    // record must resolve before the handler returns, since the server's follow-up re-handshake
    // is the next message on that thread.
    std::lock_guard<std::mutex> lock(this->mutex_);

    size_t idx = this->find_index(record.psk_id);
    const std::string incoming_psk_id = record.psk_id;
    const bool is_insert = (idx == NPOS);

    // Capacity: a replace by psk_id never grows the store, and neither does an insert that
    // supersedes an existing record for the same server_id, because the retire below drops that
    // record in the same locked section. Anything else is a genuine net-new record, which at
    // capacity evicts one rather than failing the pairing (pairing.md "Pairing Records").
    if (is_insert) {
        const bool will_supersede_existing = this->record_by_server_id(record.server_id) != nullptr;
        if (!will_supersede_existing && !this->has_capacity_locked() &&
            !this->evict_one_locked(psk_ids_in_use)) {
            // Only reachable if every record at capacity backs an open connection, which the
            // connection budget rules out (see MIN_MAX_RECORDS). Fails closed: the connection
            // drops when the server rekeys onto a PSK this store cannot resolve.
            SS_LOGW(TAG, "Storage full (%zu/%zu) and nothing evictable; rejecting record %s",
                    this->records_.size(), this->max_records_, incoming_psk_id.c_str());
            return false;
        }
    }

    if (!is_insert) {
        // A replace keeps the slot it already occupies, so only that one blob is rewritten.
        this->records_[idx].record = std::move(record);
    } else {
        // The slot is assigned after the retire below, which may be what frees one: a re-pair at
        // capacity supersedes rather than evicts.
        this->records_.push_back(StoredRecord{std::move(record), UNASSIGNED_SLOT});
        idx = this->records_.size() - 1;
        this->order_dirty_ = true;
    }

    // Retire any other record still bound to this server_id (see the header).
    const std::string superseded_server_id = this->records_[idx].record.server_id;
    uint8_t retired_slot = UNASSIGNED_SLOT;
    for (size_t i = 0; i < this->records_.size();) {
        if (i != idx && this->records_[i].record.server_id == superseded_server_id) {
            SS_LOGI(TAG, "Superseding prior record %s for server_id=%s",
                    this->records_[i].record.psk_id.c_str(), superseded_server_id.c_str());
            this->mark_slot_dirty_locked(this->records_[i].slot);
            this->order_dirty_ = true;
            retired_slot = this->records_[i].slot;
            this->records_.erase(this->records_.begin() + static_cast<ptrdiff_t>(i));
            if (i < idx) {
                --idx;
            }
            continue;  // The element that shifted into position i still needs checking.
        }
        ++i;
    }

    if (this->records_[idx].slot == UNASSIGNED_SLOT) {
        // A supersede takes the slot its own retire just freed, so re-pairing a server costs one
        // record-sized write rather than a write of the new record plus an empty write of the old
        // slot. Anything else takes the lowest free slot, which at capacity is the one the
        // eviction above freed.
        this->records_[idx].slot =
            (retired_slot != UNASSIGNED_SLOT) ? retired_slot : this->first_free_slot_locked();
    }
    // The capacity check, the eviction and the retire above between them guarantee a free slot
    // below the cap; writing UNASSIGNED_SLOT would name a key the load path never reads.
    assert(this->records_[idx].slot < this->max_records_ && "record assigned no usable slot");
    this->mark_slot_dirty_locked(this->records_[idx].slot);

    return true;
}

bool RecordStore::persist_records() {
    std::vector<SlotWrite> writes;
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        writes = this->take_dirty_writes_locked();
    }
    bool all_accepted = true;
    for (auto& write : writes) {
        if (this->save_slot_write(write)) {
            continue;
        }
        all_accepted = false;
        // Nothing is retried, and RAM stays authoritative for this boot. What a rejection costs
        // depends on the key, so the message does too: only a record slot decides what the next
        // boot holds. The recency order and the pre-slot cleanup are bookkeeping the next boot
        // rebuilds or reattempts, and a rejected order write happens on the first activate of
        // every long-term session against a full or read-only store, so it stays quiet.
        if (write.key == persistence_keys::RECORD_ORDER || write.key == LEGACY_RECORDS_KEY) {
            SS_LOGD(TAG,
                    "Provider rejected the \"%s\" write; the next boot rebuilds or reattempts it, "
                    "and no record is at stake",
                    write.key.c_str());
            continue;
        }
        SS_LOGW(TAG,
                "Provider rejected the \"%s\" write; that change is RAM-only for this boot: "
                "a record stored since the last accepted write will not survive a reboot, and "
                "a record dropped since it will be valid again after one",
                write.key.c_str());
    }
    return all_accepted;
}

bool RecordStore::has_pending_writes() const {
    std::lock_guard<std::mutex> lock(this->mutex_);
    return this->order_dirty_ || this->legacy_records_dirty_ || !this->dirty_slots_.empty();
}

bool RecordStore::note_record_removed(const std::string& psk_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    const size_t idx = this->find_index(psk_id);
    if (idx == NPOS) {
        return false;
    }
    this->mark_slot_dirty_locked(this->records_[idx].slot);
    this->order_dirty_ = true;
    this->records_.erase(this->records_.begin() + static_cast<ptrdiff_t>(idx));
    return true;
}

bool RecordStore::note_record_used(const std::string& psk_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    const size_t idx = this->find_index(psk_id);
    if (idx == NPOS) {
        return false;
    }

    // Keeps records_ least-recently-used first for eviction (see evict_one_locked).
    bool changed = false;
    const size_t last = this->records_.size() - 1;
    if (idx != last) {
        std::rotate(this->records_.begin() + static_cast<ptrdiff_t>(idx),
                    this->records_.begin() + static_cast<ptrdiff_t>(idx) + 1, this->records_.end());
        // Only the order blob: a reorder moves no record between slots, and that blob is one
        // byte per stored record, so persisting recency costs one small write per session rather
        // than a rewrite of the records themselves. A re-activate of the record that is already
        // most recent moves nothing and writes nothing.
        this->order_dirty_ = true;
        changed = true;
    }

    if (!this->records_.back().record.used) {
        this->records_.back().record.used = true;
        this->mark_slot_dirty_locked(this->records_.back().slot);
        changed = true;
    }
    // What THIS call made dirty, not whatever else is owed: a caller that flushes only when this
    // returns true must not be the one to carry away another path's pending write.
    return changed;
}

// ============================================================================
// Pairing outcome
// ============================================================================

RecordStore::PairingOutcome RecordStore::resolve_pairing_outcome(
    const std::string& server_id, const std::optional<std::string>& label) {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());

    SendspinPairingRecord record;
    record.psk_id = psk_id_for(psk);
    record.psk = psk;
    record.server_id = server_id;
    record.label = label;

    PairingOutcome outcome;
    outcome.psk = psk;
    outcome.record = std::move(record);
    return outcome;
}

// ============================================================================
// Private helpers
// ============================================================================

bool RecordStore::persist_config() {
    if (this->provider_ == nullptr) {
        return true;
    }
    SendspinPairingConfig config;
    config.pairing_psk_enabled = this->pairing_psk_enabled_;
    config.unpaired_access_enabled = this->unpaired_access_enabled_;
    config.dynamic_pairing_code_enabled = this->dynamic_pairing_code_enabled_;
    config.static_pairing_code_enabled = this->static_pairing_code_enabled_;
    std::string encoded = encode_pairing_config(config);
    if (!this->provider_->save_blob(persistence_keys::PAIR_CONFIG,
                                    reinterpret_cast<const uint8_t*>(encoded.data()),
                                    encoded.size())) {
        SS_LOGW(TAG, "Provider rejected pairing config write; the change is RAM-only for this "
                     "boot and will not survive a reboot");
        return false;
    }
    return true;
}

// ============================================================================
// Locking discipline for records_ persistence
// ============================================================================
//
// Every path that mutates records_ marks the slots whose stored blob no longer matches it (and
// the order blob, when the recency order moved). The next persist_records() encodes those writes
// under mutex_ (take_dirty_writes_locked()), then drops the lock before handing each blob to the
// provider (save_slot_write()). The provider write is an NVS commit on ESP, tens of milliseconds
// per key, and resolve_by_psk_id() takes the same mutex on the network thread for every
// handshake.
//
// The two halves need not be atomic: persist_records() is main-loop-only, so blobs cannot land
// out of order, and the one writer that can slip into the gap (store_record_superseding, on the
// network thread) is RAM-only and schedules its own flush, which redoes whatever slot it dirtied.
// A resolve in the gap sees the new RAM state, which is the authority for the boot; the blobs
// only decide what survives a reboot.
std::vector<RecordStore::SlotWrite> RecordStore::take_dirty_writes_locked() {
    std::vector<SlotWrite> writes;
    if (this->provider_ == nullptr) {
        this->dirty_slots_.clear();
        this->order_dirty_ = false;
        this->legacy_records_dirty_ = false;
        return writes;
    }
    writes.reserve(this->dirty_slots_.size() + 1);
    for (uint8_t slot : this->dirty_slots_) {
        SlotWrite write;
        write.key = persistence_keys::record_slot_key(slot);
        const StoredRecord* held = this->record_in_slot(slot);
        // A slot nothing occupies is written empty, which is how the store frees it: an evicted,
        // revoked or superseded record must not come back at the next boot.
        if (held != nullptr) {
            write.blob = encode_pairing_record(held->record);
        }
        writes.push_back(std::move(write));
    }
    this->dirty_slots_.clear();

    if (this->order_dirty_) {
        SlotWrite order;
        order.key = persistence_keys::RECORD_ORDER;
        order.blob.reserve(this->records_.size());
        for (const auto& stored : this->records_) {
            order.blob.push_back(static_cast<char>(stored.slot));
        }
        writes.push_back(std::move(order));
        this->order_dirty_ = false;
    }

    if (this->legacy_records_dirty_) {
        SlotWrite legacy;
        legacy.key = LEGACY_RECORDS_KEY;  // Empty blob: see note_legacy_records_key().
        writes.push_back(std::move(legacy));
        this->legacy_records_dirty_ = false;
    }
    return writes;
}

bool RecordStore::save_slot_write(SlotWrite& write) {
    // Only reached for a write take_dirty_writes_locked() produced, which it does only when a
    // provider is set.
    const bool ok = this->provider_->save_blob(
        write.key, reinterpret_cast<const uint8_t*>(write.blob.data()), write.blob.size());
    // An encoded record is base64 PSK text; wipe it now that save_blob() has its own copy (or has
    // rejected it).
    secure_zero(write.blob.data(), write.blob.size());
    return ok;
}

}  // namespace sendspin
