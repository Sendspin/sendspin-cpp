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
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

static const char* const TAG = "sendspin.record_store";

namespace sendspin {

namespace {

/// @brief Shared load -> string_view -> decode -> warn-on-failure -> secure_zero(blob) shape used
/// by the RECORDS and PAIRING_PSK loaders below. STATIC_PAIRING_CODE (no decoder, no PSK bytes)
/// and PAIR_CONFIG (no PSK bytes) differ enough to stay direct.
/// @param decode_fail_suffix Appended to the "Stored "%s" blob failed to decode; " warning, so
///        each caller keeps its own original message verbatim.
/// @return The decoded value, or nullopt if the blob was absent or failed to decode. The raw
///         blob is wiped before returning on BOTH the success and decode-failure paths.
template <typename T>
std::optional<T> load_decode_wipe(SendspinPersistenceProvider& provider, const char* key,
                                  std::optional<T> (*decode)(std::string_view),
                                  const char* decode_fail_suffix) {
    auto blob = provider.load_blob(key);
    if (!blob.has_value()) {
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
    : provider_(provider), max_records_(std::max(max_records, MIN_MAX_RECORDS)) {
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
    // Whole-blob decode failure (corrupt bytes, not JSON at all): the codec already skips
    // individually corrupt entries within an otherwise-valid blob, so this only fires when the
    // blob itself could not be parsed. Continue with an empty store rather than refusing to
    // start. load_decode_wipe() logs the warning and wipes the raw blob on both paths; the raw
    // blob is base64 PSK text (even when it failed to decode), mirroring the save-path wipes in
    // save_encoded_records().
    auto decoded = load_decode_wipe<std::vector<SendspinPairingRecord>>(
        *this->provider_, persistence_keys::RECORDS, decode_pairing_records,
        "starting with an empty store");
    if (decoded.has_value()) {
        this->records_ = std::move(decoded.value());
    }
}

void RecordStore::load_pairing_psk_from_provider() {
    // Base64 PSK text like the RECORDS blob above; load_decode_wipe() wipes it on both paths.
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
        // Validate on load, the same way RECORDS and PAIRING_PSK are validated by their
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
    // !loaded_config alone is NOT sufficient evidence of a first boot, and getting that wrong
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
    // A store that lost EVERYTHING is indistinguishable from a factory-fresh device by
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
    // Scope note: only unpaired_access_enabled_ is protected this way, and deliberately so. It
    // defaults to false, so declining to seed it can only ever withhold a permission. The sibling
    // flags (pairing_psk_enabled_, dynamic_pairing_code_enabled_) default to TRUE, so a config that
    // fails to load does resurrect a pairing method an operator had turned off, and the write below
    // persists that. Forcing those to false here is not a correct fix: a provider that seeds
    // records or a Pairing PSK without implementing config persistence at all returns nullopt for
    // exactly the same reason a damaged one does, and disabling pairing for it would break a
    // legitimate integration. Closing that hole properly needs the provider interface to
    // distinguish "never stored" from "could not be read" (a tri-state load result) rather than
    // more guessing here.
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
    // Calls the unlocked record_by_psk_id() helper, so no recursive acquisition occurs.
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
        if (this->records_[i].psk_id == psk_id) {
            return i;
        }
    }
    return NPOS;
}

const SendspinPairingRecord* RecordStore::record_by_psk_id(const std::string& psk_id) const {
    size_t idx = this->find_index(psk_id);
    if (idx == NPOS) {
        return nullptr;
    }
    return &this->records_[idx];
}

const SendspinPairingRecord* RecordStore::record_by_server_id(const std::string& server_id) const {
    for (const auto& rec : this->records_) {
        if (rec.server_id == server_id) {
            return &rec;
        }
    }
    return nullptr;
}

bool RecordStore::evict_one_locked(const std::vector<std::string>& psk_ids_in_use) {
    // records_ runs least-recently-used first (see mark_record_used), so the first record no open
    // connection is resolving against is the victim pairing.md "Pairing Records" leaves to the
    // implementation. Evicting one that backs an open connection would strand a live session on a
    // PSK this store no longer holds.
    for (size_t i = 0; i < this->records_.size(); ++i) {
        const std::string& psk_id = this->records_[i].psk_id;
        if (std::find(psk_ids_in_use.begin(), psk_ids_in_use.end(), psk_id) !=
            psk_ids_in_use.end()) {
            continue;
        }
        SS_LOGW(TAG, "Evicting record %s for server_id=%s to make room for a new pairing",
                psk_id.c_str(), this->records_[i].server_id.c_str());
        this->records_.erase(this->records_.begin() + static_cast<ptrdiff_t>(i));
        return true;
    }
    return false;
}

bool RecordStore::store_record_superseding(SendspinPairingRecord record,
                                           const std::vector<std::string>& psk_ids_in_use) {
    // RAM-only: this runs on the NETWORK thread (the server/pair-finalize ack handler), where the
    // record must become resolvable before the handler returns: the server's follow-up
    // re-handshake is the next message on that thread. See the header for the rest.
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
            // connection budget rules out (see MIN_MAX_RECORDS). Fails closed: an unresolvable
            // record drops the connection when the server rekeys onto it.
            SS_LOGW(TAG, "Storage full (%zu/%zu) and nothing evictable; rejecting record %s",
                    this->records_.size(), this->max_records_, incoming_psk_id.c_str());
            return false;
        }
    }

    if (!is_insert) {
        this->records_[idx] = std::move(record);
    } else {
        this->records_.push_back(std::move(record));
        idx = this->records_.size() - 1;
    }

    // Retire any OTHER record still bound to this server_id: pairing mints a fresh per-server
    // PSK that REPLACES whatever that server held before, so leaving the prior record in place
    // would let re-pairing accumulate a second working PSK for the same server.
    const std::string superseded_server_id = this->records_[idx].server_id;
    for (size_t i = 0; i < this->records_.size();) {
        if (i != idx && this->records_[i].server_id == superseded_server_id) {
            SS_LOGI(TAG, "Superseding prior record %s for server_id=%s",
                    this->records_[i].psk_id.c_str(), superseded_server_id.c_str());
            this->records_.erase(this->records_.begin() + static_cast<ptrdiff_t>(i));
            if (i < idx) {
                --idx;
            }
            continue;  // The element that shifted into position i still needs checking.
        }
        ++i;
    }

    return true;
}

bool RecordStore::persist_records() {
    std::string encoded;
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        encoded = this->encode_records_locked();
    }
    if (this->save_encoded_records(encoded)) {
        return true;
    }
    // One warning covers every RAM-only change the rejected blob leaves behind: a freshly paired
    // record dies at the next reboot, and a record this write would have dropped (retired by a
    // supersede, revoked by note_record_removed()) is valid again after one. Nothing is retried:
    // a provider that cannot write will not start writing because it is asked again, and the RAM
    // state stays authoritative for this boot either way.
    SS_LOGW(TAG,
            "Provider rejected the pairing-record write; the store's contents are RAM-only for "
            "this boot: a just-paired record will not survive a reboot, and a record this write "
            "would have dropped will be valid again after a reboot");
    return false;
}

bool RecordStore::note_record_removed(const std::string& psk_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    const size_t idx = this->find_index(psk_id);
    if (idx == NPOS) {
        return false;
    }
    this->records_.erase(this->records_.begin() + static_cast<ptrdiff_t>(idx));
    return true;
}

void RecordStore::remove_record(const std::string& psk_id) {
    if (!this->note_record_removed(psk_id)) {
        return;
    }
    std::string encoded;
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        encoded = this->encode_records_locked();
    }
    // Erased from RAM regardless of the store's answer: the operator (or the pairing exchange)
    // asked for this credential to stop working, and keeping it in RAM because the store could
    // not be written would leave it usable right now, which is strictly worse. But a write that
    // did not reach the store means the record comes back at the next start, so say so loudly
    // instead of reporting a revocation that silently half-happened.
    if (!this->save_encoded_records(encoded)) {
        SS_LOGW(TAG,
                "Removed record %s but the provider did not persist the updated store; it is "
                "gone for this boot only and will be valid again after a reboot",
                psk_id.c_str());
    }
}

bool RecordStore::note_record_used(const std::string& psk_id) {
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        const size_t idx = this->find_index(psk_id);
        if (idx == NPOS) {
            return false;
        }

        // Keeps records_ least-recently-used first for eviction (see evict_one_locked).
        const size_t last = this->records_.size() - 1;
        if (idx != last) {
            std::rotate(this->records_.begin() + static_cast<ptrdiff_t>(idx),
                        this->records_.begin() + static_cast<ptrdiff_t>(idx) + 1,
                        this->records_.end());
        }

        // The recency order stays in RAM. This runs on the first activate of EVERY long-term
        // session, so persisting the reorder would rewrite the whole records blob per connection
        // in steady state: on ESP, an NVS erase cycle per connection for advisory bookkeeping.
        // The order is rebuilt from use, so a reboot only loses the ordering among records
        // nothing has connected on since.
        //
        // The `used` flag is durable, so its first flip is written.
        if (this->records_.back().used) {
            return false;
        }
        this->records_.back().used = true;
    }
    return true;
}

void RecordStore::mark_record_used(const std::string& psk_id) {
    if (!this->note_record_used(psk_id)) {
        return;
    }
    std::string encoded;
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        encoded = this->encode_records_locked();
    }
    // Best-effort: the flag is advisory bookkeeping, so a rejected write is not reported.
    this->save_encoded_records(encoded);
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
// records_ is guarded by mutex_ (see the class comment in record_store.h). Every mutation that
// touches records_ AND needs to persist it follows one uniform discipline: mutate records_ and
// encode the WHOLE array under mutex_ (encode_records_locked()), then DROP the lock and hand the
// encoded blob to the provider (save_encoded_records()). The provider write is an NVS commit on
// ESP, tens of milliseconds long, and resolve_by_psk_id() takes this same mutex on the network
// thread for every handshake, so holding it across the write would block a handshake for the
// length of a flash commit.
//
// Encode and save do not need to be atomic with respect to each other. All three persisting
// paths (persist_records, remove_record, mark_record_used) are main-loop-only, so their
// encode/save pairs are serialized by thread confinement and two blobs cannot land out of order.
// The only writer that can slip into the gap is a network-thread store_record_superseding(),
// which is RAM-only: the saved blob then predates that insert, which was already true (it was
// not in records_ when the encode ran) and is repaired by the persist_records() flush the insert
// schedules onto the main loop.
//
// A resolve landing in the gap sees the new RAM state while flash still holds the old blob. That
// is the answer it wants: RAM is the authority for the current boot, since a provider may reject
// the write outright and leave the same divergence permanently, and the blob only decides what
// comes back after a reboot.
//
// store_record_superseding() is the exception: it mutates records_
// WITHOUT persisting at all, because it runs on the network thread where the provider may not be
// called. Its deferred flush is persist_records() (the public wrapper below), scheduled onto the
// main loop by the client via INBOX_TOPIC_RECORDS; one flush write covers the insert and the
// retire together.
//
// Preconditions: encode_records_locked() with mutex_ held, save_encoded_records() with it
// dropped.
std::string RecordStore::encode_records_locked() const {
    if (this->provider_ == nullptr) {
        return {};
    }
    return encode_pairing_records(this->records_);
}

bool RecordStore::save_encoded_records(std::string& encoded) {
    if (this->provider_ == nullptr) {
        return true;
    }
    const bool ok = this->provider_->save_blob(persistence_keys::RECORDS,
                                               reinterpret_cast<const uint8_t*>(encoded.data()),
                                               encoded.size());
    // The encoded blob is base64 PSK text for every stored record; wipe it now that save_blob()
    // has its own copy (or has rejected it), rather than leaving it for the caller's string to
    // be freed unwiped. This is the one blob write on every records_ mutation path (see the
    // locking-discipline comment above), so it covers store/remove/mark-used/supersede alike.
    secure_zero(encoded.data(), encoded.size());
    return ok;
}

}  // namespace sendspin
