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
#include "crypto/pin.h"
#include "platform/crypto.h"
#include "platform/logging.h"
#include "protocol_messages.h"
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
/// by the RECORDS and PAIRING_PSK loaders below. STATIC_PIN (no decoder, no PSK bytes) and
/// PAIR_CONFIG (no PSK bytes) differ enough to stay direct.
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
    : provider_(provider), max_records_(max_records) {
    // Try loading persisted records and config first. Every blob here (except static_pin, which
    // is raw UTF-8 bytes) is a codec-encoded blob; the provider itself is a pure byte store, so
    // decoding happens entirely on this side of the interface.
    bool loaded_config = false;
    if (this->provider_ != nullptr) {
        this->load_records_from_provider();
        this->load_pairing_psk_from_provider();
        this->load_static_pin_from_provider();
        loaded_config = this->load_pairing_config_from_provider();
    }

    this->provision_shared_record_if_needed(loaded_config, initial_unpaired_access_enabled);
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
    // persist_records_locked() and set_pairing_psk().
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

void RecordStore::load_static_pin_from_provider() {
    if (auto pin_blob = this->provider_->load_blob(persistence_keys::STATIC_PIN)) {
        std::string loaded_pin(reinterpret_cast<const char*>(pin_blob->data()), pin_blob->size());
        // Validate on load, the same way RECORDS and PAIRING_PSK are validated by their
        // decoders. The write path (management/set-pairing-config) already checks this, so a
        // value that fails here came from provider corruption or out-of-band provisioning.
        // Accepting it would leave the device advertising static_pin while feeding malformed
        // PRS bytes to the PAKE, which can only ever produce pin_mismatch, a pairing that
        // deterministically fails with nothing in the logs pointing at storage.
        if (is_valid_static_pin(loaded_pin)) {
            this->static_pin_ = std::move(loaded_pin);
        } else {
            SS_LOGW(TAG,
                    "Stored \"%s\" blob is not a valid static PIN (%zu bytes); ignoring it, "
                    "so static_pin pairing stays unavailable until one is set again",
                    persistence_keys::STATIC_PIN, loaded_pin.size());
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
            this->dynamic_pin_enabled_ = config->dynamic_pin_enabled;
            this->static_pin_enabled_ = config->static_pin_enabled;
            this->dynamic_pin_min_length_ = config->dynamic_pin_min_length;
            // Clamp the failure counter into its meaningful range instead of trusting the
            // blob. Only the >= threshold predicate consumes this value, so saturating at
            // the threshold is lossless, and it makes record_dynamic_pin_failure()'s
            // increment unable to overflow (signed overflow is UB) no matter what a corrupt
            // or hand-edited blob supplies, including a negative value, which would
            // otherwise read as "not escalated" and undo the durability guarantee that
            // function documents.
            this->dynamic_pin_failures_ =
                std::clamp(config->dynamic_pin_failures, 0, DYNAMIC_PIN_ESCALATION_THRESHOLD);
            this->pairing_psk_rotated_ = config->pairing_psk_rotated;
            this->static_pin_rotated_ = config->static_pin_rotated;
            this->record_mode_psk_id_ = config->record_mode_psk_id;
            SS_LOGD(TAG, "Loaded pairing config: record_mode_psk_id=%s",
                    this->record_mode_psk_id_.c_str());
            return true;
        }
        SS_LOGW(TAG, "Stored \"%s\" blob failed to decode; ignoring",
                persistence_keys::PAIR_CONFIG);
    }
    return false;
}

void RecordStore::provision_shared_record_if_needed(bool loaded_config,
                                                    bool initial_unpaired_access_enabled) {
    // First-boot seed: the application's configured default for unpaired access applies only on
    // a genuine first boot. A loaded config always wins, so a server that turned unpaired access
    // off through management/set-pairing-config keeps it off across reboots. The value is
    // persisted below by the first-boot provisioning branch, which the !loaded_config condition
    // always enters.
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
    if (!loaded_config && !previously_provisioned) {
        this->unpaired_access_enabled_ = initial_unpaired_access_enabled;
    } else if (!loaded_config) {
        SS_LOGW(TAG,
                "No pairing config loaded but %zu record(s) survived; ignoring the unpaired-"
                "access seed and leaving unpaired access disabled",
                this->records_.size());
    }
    // Scope note: only unpaired_access_enabled_ is protected this way, and deliberately so. It
    // defaults to false, so declining to seed it can only ever withhold a permission; it
    // cannot break a working device. The sibling flags (pairing_psk_enabled_,
    // dynamic_pin_enabled_) default to TRUE, so a config that fails to load does resurrect a
    // pairing method an operator had turned off, and the provisioning branch below persists
    // that. Forcing those to false here is not a correct fix: a provider that seeds records or a
    // Pairing PSK without implementing config persistence at all returns nullopt for exactly the
    // same reason a damaged one does, and disabling pairing for it would break a legitimate
    // integration. Closing that hole properly needs the provider interface to distinguish
    // "never stored" from "could not be read" (a tri-state load result) rather than more
    // guessing here.

    // First-boot provisioning: if no config was loaded (or the referenced shared
    // record is missing), generate a fresh shared-PSK fallback record.
    if (!loaded_config || this->record_mode_psk_id_.empty() ||
        this->record_by_psk_id(this->record_mode_psk_id_) == nullptr) {
        SS_LOGD(TAG, "First-boot provisioning: generating shared-PSK fallback record");

        std::array<uint8_t, NOISE_PSK_SIZE> shared_psk{};
        platform_random_bytes(shared_psk.data(), shared_psk.size());
        std::string shared_psk_id = psk_id_for(shared_psk);

        SendspinPairingRecord shared_record;
        shared_record.psk_id = shared_psk_id;
        shared_record.psk = shared_psk;
        // server_id absent = shared record

        this->records_.push_back(shared_record);
        this->record_mode_psk_id_ = shared_psk_id;

        // Persist the config BEFORE the record, not after. These are two independent provider
        // writes (PAIR_CONFIG and RECORDS) with no atomicity between them (the in-tree
        // reference provider does a full fsync+rename per save_blob()), so a power loss can
        // land between them, and the ORDER decides whether that is self-healing:
        //
        //   config first (this order): the interrupted state is a config naming a record that
        //     RECORDS never received. Next boot takes the third clause of the guard above
        //     (record_by_psk_id(record_mode_psk_id_) == nullptr), regenerates, and overwrites
        //     both keys. Nothing is left behind.
        //   record first (the reverse): the interrupted state is a stored record that no config
        //     references. Next boot sees !loaded_config, re-enters, and APPENDS a second record
        //     while the first stays in records_, still resolvable by resolve_by_psk_id() but
        //     unreferenced. Every repeat of that crash window adds another orphan.
        //
        // Ordering alone only covers a crash. A provider that REJECTS the config write while
        // accepting the record write would reach the same orphaned state by a different route,
        // so skip the record write when the config write was refused: leaving neither key
        // written keeps the next boot a clean first boot instead of a re-provisioning one.
        //
        // A rejected write leaves the record RAM-only for this boot: the device stays usable
        // (pairing_token() etc. still work against the in-memory record), but the record will be
        // regenerated on the next reboot, so any token printed before persistence is fixed would
        // silently stop working. Surface that instead of logging success unconditionally. No lock
        // needed here: the constructor runs before this object is reachable by any other thread.
        const bool config_persisted = this->persist_config();
        const bool record_persisted = config_persisted && this->persist_records_locked();

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
}

void RecordStore::provision_pairing_psk_if_needed() {
    // Pairing PSK provisioning: pairing_psk is the one pairing method every client must
    // implement (spec "client/hello"), so a client with no Pairing PSK would advertise a method it
    // cannot complete. Generate one when absent and persist it; the operator transfers it to a
    // server as a pairing token (SendspinClient::pairing_token()). The key is stable across
    // reboots once persisted; if persistence fails it is RAM-only for this boot, so a token
    // printed then will not survive a reboot (a warning is logged when this happens).
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

std::optional<ResolvedPsk> RecordStore::resolve_by_psk_id(const std::string& psk_id) const {
    // Runs on the network thread; lock against main-loop mutations of records_/pairing_psk_.
    // Calls the unlocked record_by_psk_id() helper, so no recursive acquisition occurs.
    std::lock_guard<std::mutex> lock(this->mutex_);
    return this->resolve_by_psk_id_locked(psk_id);
}

std::optional<ResolvedPsk> RecordStore::resolve_by_psk_id_locked(const std::string& psk_id) const {
    // 1. Long-term records (highest priority).
    const SendspinPairingRecord* rec = this->record_by_psk_id(psk_id);
    if (rec != nullptr) {
        ResolvedPsk r;
        r.psk_id = rec->psk_id;
        r.psk = rec->psk;
        r.category = PskCategory::LONG_TERM;
        r.counterparty_id = rec->server_id;
        return r;
    }

    // 2. Accepted Pairing PSK. Excluded from the candidate set when pairing_psk is disabled in
    // the live pairing config (spec "Pre-Shared Key"): a handshake referencing it then fails as a
    // lookup miss, exactly as if no Pairing PSK were configured at all.
    if (this->pairing_psk_.has_value() && this->pairing_psk_->psk_id == psk_id &&
        this->pairing_psk_enabled_) {
        ResolvedPsk r;
        r.psk_id = this->pairing_psk_->psk_id;
        r.psk = this->pairing_psk_->psk;
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
    for (size_t i = 0; i < this->records_.size(); ++i) {
        if (this->records_[i].psk_id == psk_id) {
            return i;
        }
    }
    return static_cast<size_t>(-1);
}

const SendspinPairingRecord* RecordStore::record_by_psk_id(const std::string& psk_id) const {
    size_t idx = this->find_index(psk_id);
    if (idx == static_cast<size_t>(-1)) {
        return nullptr;
    }
    return &this->records_[idx];
}

const SendspinPairingRecord* RecordStore::record_by_server_id(const std::string& server_id) const {
    for (const auto& rec : this->records_) {
        if (rec.server_id.has_value() && rec.server_id.value() == server_id) {
            return &rec;
        }
    }
    return nullptr;
}

std::vector<RecordSummary> RecordStore::records_summary_snapshot() const {
    std::lock_guard<std::mutex> lock(this->mutex_);
    std::vector<RecordSummary> summaries;
    summaries.reserve(this->records_.size());
    for (const auto& rec : this->records_) {
        RecordSummary summary;
        summary.psk_id = rec.psk_id;
        summary.server_id = rec.server_id;
        summary.used = rec.used;
        summaries.push_back(std::move(summary));
    }
    return summaries;
}

bool RecordStore::store_record(SendspinPairingRecord record) {
    return this->store_record_impl(std::move(record), /*supersede_server_id=*/false);
}

bool RecordStore::store_record_superseding(SendspinPairingRecord record) {
    return this->store_record_impl(std::move(record), /*supersede_server_id=*/true);
}

bool RecordStore::store_record_impl(SendspinPairingRecord record, bool supersede_server_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);

    size_t idx = this->find_index(record.psk_id);
    const std::string incoming_psk_id = record.psk_id;
    const bool is_insert = (idx == static_cast<size_t>(-1));

    // Capacity: a genuine insert grows records_ by one and is subject to max_records_. A
    // replace by psk_id (idx already found, handled below) never grows it, so it is exempt.
    // The pairing-supersede case is also exempt even though it inserts here first: phase 2
    // below retires whatever record already holds this server_id right after this insert
    // commits, so the net occupancy does not change. Without this exemption a device that
    // already holds the store's last free slot could never re-pair once the rest of the store
    // filled up with other servers' records.
    if (is_insert) {
        const bool will_supersede_existing =
            supersede_server_id && record.server_id.has_value() &&
            this->record_by_server_id(record.server_id.value()) != nullptr;
        if (!will_supersede_existing && !this->has_capacity_locked()) {
            SS_LOGW(TAG, "Storage full (%zu/%zu); rejecting new pairing record %s",
                    this->records_.size(), this->max_records_, incoming_psk_id.c_str());
            return false;
        }
    }

    // Phase 1: insert/replace the new record. Fails closed: the record must not survive in
    // records_ when the provider rejects the write (see the class doc). This is safe under
    // mutex_ (held for the whole sequence, so no reader - in particular resolve_by_psk_id() on
    // the network thread - can observe the tentative mutation before it commits or rolls back;
    // see the locking-discipline comment on persist_records_locked() for the general rule this
    // is the one exception to), and each branch below only ever needs to undo the single element
    // it just touched, not the whole vector: a replace snapshots just the record it is about to
    // overwrite, and an insert only needs to pop the one it just pushed.
    if (!is_insert) {
        SendspinPairingRecord replaced = std::move(this->records_[idx]);
        this->records_[idx] = std::move(record);

        if (!this->persist_records_locked()) {
            SS_LOGW(TAG, "Provider rejected pairing record %s; not storing",
                    incoming_psk_id.c_str());
            this->records_[idx] = std::move(replaced);
            return false;
        }
    } else {
        this->records_.push_back(std::move(record));
        idx = this->records_.size() - 1;

        if (!this->persist_records_locked()) {
            SS_LOGW(TAG, "Provider rejected pairing record %s; not storing",
                    incoming_psk_id.c_str());
            this->records_.pop_back();
            return false;
        }
    }

    // Phase 2 (pairing path only, and only a SEPARATE write from phase 1): pairing mints a fresh
    // per-server PSK that REPLACES whatever that server held before, so the new record (already
    // safely persisted above) supersedes any OTHER record still bound to this server_id. Drop
    // it, otherwise re-pairing accumulates a second working PSK for the same server and
    // "rotation" never revokes anything. Only the pairing path asks for this: management/add-
    // record stores plainly, because the spec's only stated add-record collision rule is keyed on
    // psk_id (a psk whose psk_id is already known is already_exists) and it defines no outcome
    // for a server_id collision: silently deleting a record the caller never named would be
    // unattested by any result code. Shared-PSK records (server_id absent) never match here.
    //
    // Deliberately NOT folded into a single write with phase 1: the new record must be safely
    // persisted BEFORE the old one is dropped, so a provider that can add but not delete (a
    // legitimate, independent failure mode on real storage) never turns a successful pairing
    // into a failed one. A rejected phase-2 write behaves like remove_record(): the retired
    // record is erased from RAM unconditionally, and a rejected persist is only logged as a
    // warning rather than treated as a failure.
    if (supersede_server_id && this->records_[idx].server_id.has_value()) {
        const std::string superseded_server_id = this->records_[idx].server_id.value();
        std::vector<std::string> superseded_psk_ids;
        for (size_t i = 0; i < this->records_.size();) {
            if (i != idx && this->records_[i].server_id.has_value() &&
                this->records_[i].server_id.value() == superseded_server_id) {
                superseded_psk_ids.push_back(this->records_[i].psk_id);
                this->records_.erase(this->records_.begin() + static_cast<ptrdiff_t>(i));
                if (i < idx) {
                    --idx;
                }
                continue;  // The element that shifted into position i still needs checking.
            }
            ++i;
        }

        if (!superseded_psk_ids.empty()) {
            if (this->persist_records_locked()) {
                for (const auto& superseded_psk_id : superseded_psk_ids) {
                    SS_LOGI(TAG, "Superseding prior record %s for server_id=%s",
                            superseded_psk_id.c_str(), superseded_server_id.c_str());
                }
            } else {
                for (const auto& superseded_psk_id : superseded_psk_ids) {
                    SS_LOGW(TAG,
                            "Superseded record %s but the provider did not persist the updated "
                            "store; it is gone for this boot only and will be valid again after "
                            "a reboot",
                            superseded_psk_id.c_str());
                }
            }
        }
    }

    return true;
}

void RecordStore::remove_record(const std::string& psk_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    size_t idx = this->find_index(psk_id);
    if (idx == static_cast<size_t>(-1)) {
        return;
    }
    this->records_.erase(this->records_.begin() + static_cast<ptrdiff_t>(idx));
    // Erased from RAM regardless of the store's answer: the operator (or the pairing exchange)
    // asked for this credential to stop working, and keeping it in RAM because the store could
    // not be written would leave it usable right now, which is strictly worse. But a write that
    // did not reach the store means the record comes back at the next start, so say so loudly
    // instead of reporting a revocation that silently half-happened.
    if (!this->persist_records_locked()) {
        SS_LOGW(TAG,
                "Removed record %s but the provider did not persist the updated store; it is "
                "gone for this boot only and will be valid again after a reboot",
                psk_id.c_str());
    }
}

void RecordStore::mark_record_used(const std::string& psk_id) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    size_t idx = this->find_index(psk_id);
    if (idx == static_cast<size_t>(-1) || this->records_[idx].used) {
        return;
    }
    this->records_[idx].used = true;
    // Best-effort: a rejected write here is not reported, since "used" is advisory bookkeeping
    // rather than a revocation whose durability the caller depends on.
    this->persist_records_locked();
}

bool RecordStore::can_remove_record(const std::string& psk_id) const {
    return psk_id != this->record_mode_psk_id_;
}

// ============================================================================
// Pairing PSK
// ============================================================================

void RecordStore::set_pairing_psk(SendspinPairingPsk psk) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    // Derive psk_id from the secret rather than trusting the caller's: it is the id the server
    // will reference in its handshake, so a supplied mismatch would make the key unresolvable.
    psk.psk_id = psk_id_for(psk.psk);
    this->pairing_psk_ = std::move(psk);
    // The secret the device shipped with is now dead, so whatever the application published it
    // in (device label, leaflet) no longer opens this client and the locations hint has to stop
    // pointing there. Persisting under mutex_ is the pattern set_pairing_psk_enabled() documents;
    // skip the write once the flag is already set so a re-rotation costs no extra flash.
    //
    // Ordered before the secret's own write, since the two blobs are separate keys and a provider
    // can take one and reject the other. Losing the secret's write after this one leaves a device
    // whose shipped secret still works pointing an operator at the server that set the
    // replacement, which merely wastes a lookup; the reverse order would leave a rotated device
    // pointing at a label that no longer opens it.
    if (!this->pairing_psk_rotated_) {
        this->pairing_psk_rotated_ = true;
        this->persist_config();
    }
    if (this->provider_ != nullptr) {
        std::string encoded = encode_pairing_psk(this->pairing_psk_.value());
        this->provider_->save_blob(persistence_keys::PAIRING_PSK,
                                   reinterpret_cast<const uint8_t*>(encoded.data()),
                                   encoded.size());
        // See the constructor's provisioning branch for why this is wiped rather than left for
        // the string's destructor to free unwiped: it is base64 PSK text.
        secure_zero(encoded.data(), encoded.size());
    }
}

void RecordStore::clear_pairing_psk() {
    std::lock_guard<std::mutex> lock(this->mutex_);
    this->pairing_psk_.reset();
    if (this->provider_ != nullptr && !this->provider_->erase_blob(persistence_keys::PAIRING_PSK)) {
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
    auto resolved = this->resolve_by_psk_id(psk_id);
    if (!resolved.has_value()) {
        SS_LOGE(TAG, "record_mode psk_id '%s' references no record", psk_id.c_str());
        return false;
    }
    if (!this->is_shared_record(resolved.value())) {
        SS_LOGE(TAG, "record_mode psk_id '%s' must reference a shared-PSK record", psk_id.c_str());
        return false;
    }
    this->record_mode_psk_id_ = psk_id;
    this->persist_config();
    return true;
}

void RecordStore::set_pairing_psk_enabled(bool enabled) {
    // Locked, unlike the other config setters: resolve_by_psk_id() reads this field on the
    // NETWORK thread inside its own mutex_ section (see the thread-safety note on the class).
    // Holding mutex_ across persist_config() is safe on both counts that matter: it does not
    // take mutex_ itself, so there is no recursive acquisition inside this class; and it reaches
    // the consumer's provider, which SendspinPersistenceProvider's documented re-entrancy
    // contract forbids from calling back into the library (that contract cites this exact
    // pattern: set_pairing_psk() has always held mutex_ across its own save_blob()).
    std::lock_guard<std::mutex> lock(this->mutex_);
    this->pairing_psk_enabled_ = enabled;
    this->persist_config();
}

void RecordStore::set_unpaired_access_enabled(bool enabled) {
    this->unpaired_access_enabled_ = enabled;
    this->persist_config();
}

void RecordStore::set_dynamic_pin_enabled(bool enabled) {
    this->dynamic_pin_enabled_ = enabled;
    this->persist_config();
}

void RecordStore::set_dynamic_pin_min_length(int length) {
    this->dynamic_pin_min_length_ = length;
    this->persist_config();
}

// ============================================================================
// Dynamic-PIN failure counter (escalation)
// ============================================================================

void RecordStore::record_dynamic_pin_failure() {
    // Failures arrive network-reachable and unthrottled (every rejected PIN guess calls this),
    // so persisting on every increment would put an attacker-driven write rate directly on
    // flash. Persist only at the two points where losing the in-memory update to an untimely
    // reboot would change observable behavior:
    //  - the first failure after a reset (0 -> 1), so a power-cycle cannot silently erase the
    //    fact that a failed attempt happened at all;
    //  - the failure that crosses DYNAMIC_PIN_ESCALATION_THRESHOLD, so a power-cycle cannot
    //    un-escalate dynamic_pin.
    // Invariant this guarantees: dynamic_pin_escalated() is durable; if it is true before a
    // reboot, it is true after (escalation only clears via reset_dynamic_pin_failures(), which
    // always persists), and it cannot be un-escalated by power-cycling. Non-escalating counts
    // strictly between 1 and DYNAMIC_PIN_ESCALATION_THRESHOLD may be lost to an untimely
    // reboot; that only costs the attacker's own progress toward escalation, not the escalation
    // guarantee itself, in exchange for not touching flash on every guess.
    //
    // This is a considered tradeoff, not just an optimistic one: an attacker who can force a
    // reboot or crash by unrelated means (a bug, a power blip, physical access) gets at most
    // DYNAMIC_PIN_ESCALATION_THRESHOLD - 1 fresh online guesses per forced cycle. Each of those
    // guesses still costs a full CPace PAKE handshake (see crypto/cpace.h); there is no faster
    // offline path, so the reboot-assisted budget only multiplies an already-expensive
    // per-guess cost by a small bounded factor; it does not turn the PIN into a cheap oracle.
    const bool was_escalated = this->dynamic_pin_escalated();
    const bool first_failure_since_reset = (this->dynamic_pin_failures_ == 0);
    // Saturate at the threshold rather than incrementing without bound: nothing reads the count
    // above it (dynamic_pin_escalated() is the only consumer, plus the log line below), and an
    // unbounded ++ on a signed int is UB once it reaches INT_MAX.
    if (this->dynamic_pin_failures_ < DYNAMIC_PIN_ESCALATION_THRESHOLD) {
        this->dynamic_pin_failures_++;
    }
    SS_LOGW(TAG, "Dynamic-PIN failure recorded (count=%d, escalation threshold=%d)",
            this->dynamic_pin_failures_, DYNAMIC_PIN_ESCALATION_THRESHOLD);

    const bool now_escalated = this->dynamic_pin_escalated();
    if (first_failure_since_reset || (now_escalated && !was_escalated)) {
        this->persist_config();
    }
}

void RecordStore::reset_dynamic_pin_failures() {
    if (this->dynamic_pin_failures_ == 0) {
        return;  // Nothing to reset; skip the persistence write.
    }
    this->dynamic_pin_failures_ = 0;
    this->persist_config();
}

// ============================================================================
// Static PIN
// ============================================================================

void RecordStore::set_static_pin(const std::string& pin) {
    this->static_pin_ = pin;
    // Retires the configured locations hint, and ordered ahead of the PIN's own write for the
    // reason set_pairing_psk() spells out.
    if (!this->static_pin_rotated_) {
        this->static_pin_rotated_ = true;
        this->persist_config();
    }
    if (this->provider_ != nullptr) {
        this->provider_->save_blob(persistence_keys::STATIC_PIN,
                                   reinterpret_cast<const uint8_t*>(pin.data()), pin.size());
    }
}

void RecordStore::clear_static_pin() {
    this->static_pin_.reset();
    if (this->provider_ != nullptr && !this->provider_->erase_blob(persistence_keys::STATIC_PIN)) {
        SS_LOGW(TAG,
                "Cleared the static PIN but the provider did not delete it; it is gone for this "
                "boot only and will pair devices again after a reboot");
    }
}

void RecordStore::set_static_pin_enabled(bool enabled) {
    this->static_pin_enabled_ = enabled;
    this->persist_config();
}

// ============================================================================
// Pairing outcome
// ============================================================================

std::optional<RecordStore::PairingOutcome> RecordStore::resolve_pairing_outcome(
    const std::string& server_id, const std::optional<std::string>& label) {
    // Hold mutex_ for the whole body rather than letting each step lock on its own. The
    // capacity probe, the server_id probe, and the shared-PSK fallback lookup must all see one
    // consistent view of records_, and record_by_server_id() iterates records_ directly: without
    // this lock a network-thread store_record_superseding() (client.cpp's server/pair-finalize
    // handler commits synchronously on that thread) can reallocate the vector mid-iteration.
    // Every helper called below is therefore the _locked variant; calling the public
    // can_store_record()/resolve_by_psk_id() here would self-deadlock on this non-recursive mutex.
    std::lock_guard<std::mutex> lock(this->mutex_);

    // A re-pair for a server_id that already holds a long-term record supersedes it in place
    // (store_record_superseding() retires the old record only once the new one is safely
    // persisted; see store_record_impl()), so it does not grow the store and must not be
    // blocked by the capacity check even when the store reports itself full. Without this, a
    // device that already occupies the store's last slot could never re-pair once other
    // servers filled the rest of it.
    const bool replaces_existing = this->record_by_server_id(server_id) != nullptr;
    if (replaces_existing || this->has_capacity_locked()) {
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
    auto resolved = this->resolve_by_psk_id_locked(this->record_mode_psk_id_);
    if (!resolved.has_value() || !this->is_shared_record(resolved.value())) {
        SS_LOGE(TAG, "shared-PSK fallback record '%s' is missing or not shared",
                this->record_mode_psk_id_.c_str());
        return std::nullopt;
    }

    PairingOutcome outcome;
    outcome.psk = resolved->psk;
    // outcome.record is nullopt: caller should not store a new record.
    return outcome;
}

bool RecordStore::can_store_record() const {
    std::lock_guard<std::mutex> lock(this->mutex_);
    return this->has_capacity_locked();
}

// ============================================================================
// Storage accounting
// ============================================================================

RecordStore::StorageReport RecordStore::storage_accounting() const {
    std::lock_guard<std::mutex> lock(this->mutex_);
    StorageReport report;
    report.capacity = static_cast<int>(this->max_records_);
    report.free = static_cast<int>(this->max_records_) - static_cast<int>(this->records_.size());
    if (report.free < 0) {
        report.free = 0;  // Defensive: a shrunk max_records_ must not advertise negative room.
    }
    report.cost_individual = 1;
    report.cost_shared = 1;
    return report;
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
    config.dynamic_pin_enabled = this->dynamic_pin_enabled_;
    config.static_pin_enabled = this->static_pin_enabled_;
    config.dynamic_pin_min_length = this->dynamic_pin_min_length_;
    config.dynamic_pin_failures = this->dynamic_pin_failures_;
    config.pairing_psk_rotated = this->pairing_psk_rotated_;
    config.static_pin_rotated = this->static_pin_rotated_;
    config.record_mode_psk_id = this->record_mode_psk_id_;
    std::string encoded = encode_pairing_config(config);
    if (!this->provider_->save_blob(persistence_keys::PAIR_CONFIG,
                                    reinterpret_cast<const uint8_t*>(encoded.data()),
                                    encoded.size())) {
        SS_LOGW(TAG,
                "Provider rejected pairing config write (record_mode_psk_id=%s); the change is "
                "RAM-only for this boot and will not survive a reboot",
                config.record_mode_psk_id.c_str());
        return false;
    }
    return true;
}

// ============================================================================
// Locking discipline for records_ persistence
// ============================================================================
//
// records_ is guarded by mutex_ (see the class comment in record_store.h). Every mutation that
// touches records_ AND needs to persist it follows one uniform discipline: mutate records_ in
// place, then encode the WHOLE array and save it while STILL HOLDING mutex_
// (persist_records_locked(), below), so the encoded snapshot is always exactly what is in memory
// at the moment of the write. This adds no new deadlock class: providers are already called
// under mutex_ at several call sites in this file (mark_record_used, set_pairing_psk), and no
// provider implementation calls back into RecordStore.
//
// store_record()/store_record_superseding() are the one exception for their own insert/replace
// half, because that half must fail closed: the new record must not survive in records_ when the
// provider rejects the write. store_record_impl() snapshots records_ before mutating, applies
// the insert/replace in place, persists via this same helper, and rolls records_ back to the
// snapshot on failure. That is safe under the same reasoning: the whole sequence runs under
// mutex_, so no reader (in particular resolve_by_psk_id() on the network thread) can observe the
// tentative state before it commits or rolls back.
//
// The superseding form's retire-old-records half is deliberately a SEPARATE, later write (not
// folded into the same persist_records_locked() call as the insert): the new record must be
// safely persisted before the old one is dropped, so a provider that can add but cannot delete
// never turns a successful pairing into a failed one. That second write follows remove_record()'s
// discipline instead: erase from records_ unconditionally, persist, and only warn (not fail) if
// the provider rejects it. See store_record_impl() for the full reasoning.
//
// Precondition: the caller holds mutex_, with one exception: the constructor's first-boot
// provisioning path, which calls this before the object is reachable by any other thread and
// therefore needs (and takes) no lock. Every post-construction caller must hold mutex_.
bool RecordStore::persist_records_locked() {
    if (this->provider_ == nullptr) {
        return true;
    }
    std::string encoded = encode_pairing_records(this->records_);
    const bool ok = this->provider_->save_blob(persistence_keys::RECORDS,
                                               reinterpret_cast<const uint8_t*>(encoded.data()),
                                               encoded.size());
    // The encoded blob is base64 PSK text for every stored record; wipe it now that save_blob()
    // has its own copy (or has rejected it), rather than leaving it for the string's destructor
    // to free unwiped. This is the one blob write on every records_ mutation path (see the
    // locking-discipline comment above), so it covers store/remove/mark-used/supersede alike.
    secure_zero(encoded.data(), encoded.size());
    return ok;
}

}  // namespace sendspin
