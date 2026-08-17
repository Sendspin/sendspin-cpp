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

/// @file record_store.h
/// @brief In-memory client pairing record store.
///
/// Mirrors the client side of `aiosendspin/noise/trust_store.py`
/// (`InMemoryClientPairingStore`). Holds records in memory, calls the
/// `SendspinPersistenceProvider` for durability, and resolves `psk_id` ->
/// PSK for the Noise handshake layer.
///
/// Resolution order: long-term record -> accepted Pairing PSK -> Sentinel PSK.
///
/// Construction pre-provisions a shared-PSK fallback record and points
/// `record_mode_psk_id` at it, mirroring the Python store's `__init__`.
///
/// The record types used here (`SendspinPairingRecord`, `SendspinPairingPsk`,
/// `SendspinPairingConfig`) are the public types from `sendspin/config.h` so
/// that the persistence provider can pass them through without conversion.

#pragma once

#include "crypto/constants.h"
#include "crypto/pin.h"
#include "sendspin/client.h"
#include "sendspin/config.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

/// Forward-declared rather than pulled in via protocol_messages.h: that header drags in every
/// role header (color_role.h, controller_role.h, ...) plus ArduinoJson, and record_store.h is
/// itself included by low-level files (connection.h, admission.h) that have no business seeing
/// any of that. records_summary_snapshot() is declared here and defined in record_store.cpp,
/// which already sits at the leaf of the include graph and can afford the real include.
struct RecordSummary;

// ============================================================================
// PSK category
// ============================================================================

/// @brief Which kind of PSK was matched during a handshake.
/// Mirrors `PskCategory` in `aiosendspin/noise/trust_store.py`.
enum class PskCategory : uint8_t {
    LONG_TERM,  ///< Per-pair long-term PSK from a successful pairing.
    PAIRING,    ///< Pairing PSK distributed out-of-band to admit a new server.
    SENTINEL,   ///< Published Sentinel PSK: authenticates nothing on its own.
};

// ============================================================================
// Resolved PSK (handshake currency)
// ============================================================================

/// @brief A PSK selected during a handshake, with its trust metadata.
/// Mirrors `ResolvedPsk` in `aiosendspin/noise/trust_store.py`.
struct ResolvedPsk {
    std::string psk_id;
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    PskCategory category{PskCategory::SENTINEL};
    /// Peer server_id for stored-pubkey records; empty optional = shared / sentinel / pairing.
    std::optional<std::string> counterparty_id;

    ResolvedPsk() = default;
    ResolvedPsk(const ResolvedPsk&) = default;
    ResolvedPsk(ResolvedPsk&&) = default;
    ResolvedPsk& operator=(const ResolvedPsk&) = default;
    ResolvedPsk& operator=(ResolvedPsk&&) = default;

    /// @brief Wipes `psk` on destruction; same discipline as SendspinPairingRecord (see
    /// config.h): copies of this struct travel through every handshake and must not leave
    /// key bytes behind in freed heap or dead stack frames.
    ~ResolvedPsk() {
        detail::secure_zero_psk(this->psk);
    }
};

// ============================================================================
// RecordStore
// ============================================================================

/// @brief In-memory client pairing record store.
///
/// Thread-safety:
///   - `records_` and `pairing_psk_` are guarded by `mutex_`. ALL cross-thread access
///     must go through `resolve_by_psk_id` or the `*_snapshot` / `*_copy` variants.
///   - The pointer/reference-returning getters (`record_by_psk_id`, `record_by_server_id`,
///     `records`) are for internal-locked or single-threaded (main-loop-only) use ONLY;
///     callers must not retain a returned pointer or reference across any mutation, and must
///     never call them from the network thread.
///   - Most config fields (`unpaired_access_enabled_`, `dynamic_pin_enabled_`,
///     `static_pin_enabled_`, `dynamic_pin_min_length_`, `dynamic_pin_failures_`,
///     `record_mode_psk_id_`) are main-loop-only: written only on the main loop and read only
///     on the main loop, so no lock is needed.
///   - `pairing_psk_enabled_` is the ONE exception and IS guarded by `mutex_`. It is written on
///     the main loop like its neighbours, but it is also READ on the network thread, inside
///     `resolve_by_psk_id`'s locked section, because a disabled Pairing PSK must drop out of the
///     handshake candidate set. Its setter therefore takes `mutex_`, exactly as
///     `set_pairing_psk()` does for the value half of that same condition. Do not "simplify" the
///     lock away to match the other config setters: without it the network-thread read is an
///     unsynchronized race and an operator-disabled Pairing PSK can keep authenticating
///     handshakes for a window after the toggle.
///   - `resolve_by_psk_id` runs on the network thread (Noise handshake and re-handshake)
///     under `mutex_` so a network-thread resolve cannot race a main-loop mutation of
///     `records_` / `pairing_psk_`.
class RecordStore {
public:
    /// @brief Default cap on the number of long-term records retained; see
    /// SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS for the rationale, which this mirrors
    /// so there is one source of truth for the number.
    static constexpr size_t DEFAULT_MAX_RECORDS = SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS;

    /// @brief Construct and pre-provision the shared-PSK fallback record and the Pairing PSK.
    /// If a persistence provider is supplied, attempts to load saved records
    /// and pairing config first; generates fresh material only when absent.
    /// @param provider Persistence provider, or nullptr for an in-memory-only store.
    /// @param initial_unpaired_access_enabled First-boot default for unpaired (Sentinel) access.
    ///        Applied only when no pairing config was loaded; a loaded config always wins.
    /// @param max_records Cap on the number of long-term records retained (see
    ///        can_store_record()). Defaults to DEFAULT_MAX_RECORDS.
    explicit RecordStore(SendspinPersistenceProvider* provider,
                         bool initial_unpaired_access_enabled = false,
                         size_t max_records = DEFAULT_MAX_RECORDS);

    // ========================================
    // PSK resolution (used by the Noise handshake)
    // ========================================

    /// @brief Resolve a psk_id to its PSK for the handshake.
    /// Order: long-term record -> accepted Pairing PSK -> Sentinel PSK.
    /// Returns nullopt only if psk_id is entirely unknown (not even Sentinel).
    [[nodiscard]] std::optional<ResolvedPsk> resolve_by_psk_id(const std::string& psk_id) const;

    // ========================================
    // Long-term record management
    // ========================================

    /// @brief Return the long-term record identified by psk_id, if any.
    [[nodiscard]] const SendspinPairingRecord* record_by_psk_id(const std::string& psk_id) const;

    /// @brief Return the stored-pubkey record bound to server_id, if any.
    /// Shared-PSK records (server_id absent) are never returned here.
    [[nodiscard]] const SendspinPairingRecord* record_by_server_id(
        const std::string& server_id) const;

    /// @brief Return a locked copy of all long-term records (thread-safe).
    /// Safe to call from any thread; iterates under mutex_ so the copy is consistent.
    [[nodiscard]] std::vector<SendspinPairingRecord> records_snapshot() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->records_;
    }

    /// @brief Return a locked snapshot of psk_id/server_id/used for every long-term record
    /// (thread-safe), without materializing any PSK bytes. The only production caller is
    /// management/list-records (see handle_list_records() in management.h), which never needs
    /// the PSK; use records_snapshot() instead when the full record (including the PSK) is
    /// actually required.
    [[nodiscard]] std::vector<RecordSummary> records_summary_snapshot() const;

    /// @brief Return a locked copy of the record identified by psk_id, if any (thread-safe).
    /// Calls the unlocked record_by_psk_id helper while holding mutex_; no recursion since
    /// record_by_psk_id does not lock. Returns nullopt when the psk_id is not found.
    [[nodiscard]] std::optional<SendspinPairingRecord> record_by_psk_id_copy(
        const std::string& psk_id) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        const SendspinPairingRecord* r = record_by_psk_id(psk_id);
        return r ? std::optional<SendspinPairingRecord>(*r) : std::nullopt;
    }

    /// @brief Persist and store a long-term record. Replaces any existing record
    /// with the same psk_id, and leaves records for other psk_ids alone.
    ///
    /// The provider write happens first: when it fails, the in-memory store is left
    /// untouched so the caller can fail the exchange closed instead of completing it on
    /// a key that would be lost at the next reboot.
    ///
    /// This plain form does NOT supersede other records bound to the same server_id, so a
    /// caller may deliberately hold more than one record for one server (for example an
    /// operator staging a replacement credential via `management/add-record` before
    /// retiring the old one). Use store_record_superseding() for the pairing path.
    /// @return true when the record is stored (and persisted, when a provider is set);
    /// false when the persistence provider rejected the write.
    bool store_record(SendspinPairingRecord record);

    /// @brief Like store_record(), but additionally retires any OTHER record bound to the
    /// same server_id once the new record is safely persisted.
    ///
    /// This is the pairing-completion form: pairing mints a fresh per-server PSK that
    /// REPLACES whatever that server held before, so leaving the prior record in place
    /// would keep the old PSK valid forever and let repeated re-pairs exhaust storage.
    /// Ordering matters: the new record is persisted BEFORE the old one is dropped, so a
    /// rejected write never destroys the working credential. Shared-PSK records (server_id
    /// absent) are never subject to this supersede, which is what keeps the record-mode
    /// fallback record safe.
    /// @return true when the record is stored (and persisted, when a provider is set);
    /// false when the persistence provider rejected the write (nothing is retired then).
    bool store_record_superseding(SendspinPairingRecord record);

    /// @brief Remove the long-term record identified by psk_id.
    /// No-op if absent.
    void remove_record(const std::string& psk_id);

    /// @brief Flag the record at psk_id as used. No-op if absent or already used.
    void mark_record_used(const std::string& psk_id);

    /// @brief Return whether the record may be removed.
    /// The record referenced by record_mode_psk_id is protected.
    [[nodiscard]] bool can_remove_record(const std::string& psk_id) const;

    // ========================================
    // Pairing PSK (the one the client accepts to admit a new server)
    // ========================================

    /// @brief Set the accepted Pairing PSK, replacing any existing one.
    /// psk_id is re-derived from the supplied secret; any id in `psk` is ignored.
    /// Marks the Pairing PSK rotated (see pairing_psk_rotated()): this is the rotation entry
    /// point, distinct from the constructor's first-boot provisioning and provider load, which
    /// install the shipped secret and leave the flag alone.
    void set_pairing_psk(SendspinPairingPsk psk);

    /// @brief Clear the accepted Pairing PSK. No-op if absent.
    void clear_pairing_psk();

    /// @brief Return the accepted Pairing PSK, if any.
    [[nodiscard]] const std::optional<SendspinPairingPsk>& pairing_psk() const {
        return this->pairing_psk_;
    }

    // ========================================
    // Pairing config
    // ========================================

    /// @brief Return whether Pairing-PSK pairing is enabled.
    [[nodiscard]] bool pairing_psk_enabled() const {
        return this->pairing_psk_enabled_;
    }

    /// @brief Return whether unpaired (Sentinel) access is allowed.
    [[nodiscard]] bool unpaired_access_enabled() const {
        return this->unpaired_access_enabled_;
    }

    /// @brief Return whether dynamic-PIN pairing is enabled.
    [[nodiscard]] bool dynamic_pin_enabled() const {
        return this->dynamic_pin_enabled_;
    }

    /// @brief Return the minimum PIN length the client will accept.
    [[nodiscard]] int dynamic_pin_min_length() const {
        return this->dynamic_pin_min_length_;
    }

    /// @brief Return whether the Pairing PSK has been rotated away from the shipped secret.
    /// True retires SendspinClientConfig::pairing_psk_locations, which described where the
    /// shipped secret was published: the current one exists only wherever the operator who
    /// rotated it keeps it, so client/hello advertises `["operator"]` instead. Persisted through
    /// SendspinPairingConfig so it survives reboots alongside the rotated secret.
    [[nodiscard]] bool pairing_psk_rotated() const {
        return this->pairing_psk_rotated_;
    }

    /// @brief Return whether the static PIN has been rotated away from the shipped secret.
    /// Retires SendspinClientConfig::static_pin_locations the same way pairing_psk_rotated()
    /// retires its own hint.
    [[nodiscard]] bool static_pin_rotated() const {
        return this->static_pin_rotated_;
    }

    // ========================================
    // Dynamic-PIN failure counter (escalation, persisted)
    // ========================================

    /// @brief Failure count at which dynamic_pin becomes escalated (gesture-gated).
    static constexpr int DYNAMIC_PIN_ESCALATION_THRESHOLD = 10;

    /// @brief Return true if dynamic_pin is escalated: every attempt is gesture-gated until a
    /// successful server_kc verification de-escalates it. Escalation is not an error state:
    /// the method stays offered.
    [[nodiscard]] bool dynamic_pin_escalated() const {
        return this->dynamic_pin_failures_ >= DYNAMIC_PIN_ESCALATION_THRESHOLD;
    }

    /// @brief Return the current dynamic-PIN failure count.
    [[nodiscard]] int dynamic_pin_failure_count() const {
        return this->dynamic_pin_failures_;
    }

    /// @brief Increment the dynamic-PIN failure counter. Called only when the client's own
    /// verification of server_kc fails; no other event increments it. Persists only at the
    /// first failure since a reset and at the failure that crosses
    /// DYNAMIC_PIN_ESCALATION_THRESHOLD (see the .cpp for the durability invariant this
    /// preserves), not on every call, to bound flash writes on this network-reachable path.
    void record_dynamic_pin_failure();

    /// @brief Reset the dynamic-PIN failure counter to zero and persist it. Called when the
    /// client's own verification of server_kc succeeds, whether or not the attempt finalizes.
    void reset_dynamic_pin_failures();

    // ========================================
    // Static PIN
    // ========================================

    /// @brief Return the configured static PIN, if any.
    [[nodiscard]] const std::optional<std::string>& static_pin() const {
        return this->static_pin_;
    }

    /// @brief Return whether static-PIN pairing is enabled.
    [[nodiscard]] bool static_pin_enabled() const {
        return this->static_pin_enabled_;
    }

    /// @brief Set the configured static PIN (8 decimal digits), replacing any existing one.
    /// Marks the static PIN rotated (see static_pin_rotated()); the provider load that restores
    /// a shipped PIN at construction does not.
    void set_static_pin(const std::string& pin);

    /// @brief Clear the configured static PIN. No-op if absent.
    void clear_static_pin();

    /// @brief Set the static-PIN-enabled flag and persist the config.
    void set_static_pin_enabled(bool enabled);

    /// @brief Set the pairing-PSK-enabled flag and persist the config.
    void set_pairing_psk_enabled(bool enabled);

    /// @brief Set the unpaired-access-enabled flag and persist the config.
    void set_unpaired_access_enabled(bool enabled);

    /// @brief Set the dynamic-PIN-enabled flag and persist the config.
    void set_dynamic_pin_enabled(bool enabled);

    /// @brief Set the minimum PIN length and persist the config.
    void set_dynamic_pin_min_length(int length);

    /// @brief Return the psk_id of the shared-PSK fallback record.
    [[nodiscard]] const std::string& record_mode_psk_id() const {
        return this->record_mode_psk_id_;
    }

    /// @brief Set the shared-PSK fallback record.
    /// @return false if psk_id does not reference an existing shared-PSK record.
    bool set_record_mode_psk_id(const std::string& psk_id);

    // ========================================
    // Pairing outcome
    // ========================================

    /// @brief Result of resolve_pairing_outcome(): either a fresh per-server PSK/record pair,
    /// or the shared-PSK fallback when storage is exhausted.
    struct PairingOutcome {
        std::array<uint8_t, NOISE_PSK_SIZE> psk{};
        /// nullopt = storage exhausted, use the shared-PSK fallback record.
        std::optional<SendspinPairingRecord> record;

        PairingOutcome() = default;
        PairingOutcome(const PairingOutcome&) = default;
        PairingOutcome(PairingOutcome&&) = default;
        PairingOutcome& operator=(const PairingOutcome&) = default;
        PairingOutcome& operator=(PairingOutcome&&) = default;

        /// @brief Wipes `psk` on destruction; same discipline as SendspinPairingRecord (see
        /// config.h). The contained record wipes its own copy independently.
        ~PairingOutcome() {
            detail::secure_zero_psk(this->psk);
        }
    };

    /// @brief Decide a pairing outcome.
    ///
    /// When storage is not exhausted (`can_store_record()` is true), generates a
    /// fresh PSK bound to server_id and returns {psk, record}.
    /// When storage is exhausted, returns the shared fallback PSK and record=nullopt.
    /// Returns nullopt on error (missing shared fallback).
    [[nodiscard]] std::optional<PairingOutcome> resolve_pairing_outcome(
        const std::string& server_id, const std::optional<std::string>& label = std::nullopt);

    /// @brief Return true if a new record can be stored.
    ///
    /// Reports free capacity against max_records_ (see DEFAULT_MAX_RECORDS).
    ///
    /// This is an advisory pre-check consulted by callers (resolve_pairing_outcome(),
    /// management/add-record) before attempting to store a record; it takes mutex_ and releases
    /// it before returning, so the actual insert still goes through store_record_impl(), which
    /// re-checks max_records_ under its own hold of mutex_. An insert that lands in that gap
    /// therefore cannot grow the in-memory array past the cap. A record replacement (matching
    /// psk_id, or a pairing supersede of the record already held for the target server_id) is
    /// exempt from the cap in both places: it does not grow the store.
    [[nodiscard]] bool can_store_record() const;

    // ========================================
    // Storage accounting
    // ========================================

    /// @brief Storage accounting report returned by storage_accounting().
    struct StorageReport {
        int free{0};             ///< Number of free record slots.
        int capacity{0};         ///< Total record slot capacity.
        int cost_individual{1};  ///< Slots consumed by a stored-pubkey record.
        int cost_shared{1};      ///< Slots consumed by a shared-PSK record.
    };

    /// @brief Return storage accounting info for a management result.
    ///
    /// The store is always capacity-bounded, so this always reports real numbers: free =
    /// max_records_ minus the current record count, capacity = max_records_, both costs 1 slot.
    /// A managing server needs to see the actual cap to avoid flooding the store via
    /// management/add-record.
    ///
    /// include_static semantics (attachment point in management.h attach_storage_accounting):
    ///   - list-records and get-pairing-config: include capacity/costs.
    ///   - all other results: free only.
    [[nodiscard]] StorageReport storage_accounting() const;

private:
    // ========================================
    // Construction helpers
    // ========================================
    // Called in this order from the constructor; see the constructor definition in the .cpp for
    // the full first-boot / damaged-config reasoning that ties the load and provisioning steps
    // together.

    /// @brief Load records_ from the provider's RECORDS blob, if present.
    void load_records_from_provider();

    /// @brief Load pairing_psk_ from the provider's PAIRING_PSK blob, if present, correcting its
    /// psk_id if it disagrees with the loaded secret.
    void load_pairing_psk_from_provider();

    /// @brief Load static_pin_ from the provider's STATIC_PIN blob, if present and valid.
    void load_static_pin_from_provider();

    /// @brief Load the pairing config fields from the provider's PAIR_CONFIG blob, if present.
    /// @return True if a valid config was loaded; the provisioning helpers below use this (the
    ///         "loaded_config" signal) to decide first-boot vs. damaged-config behavior.
    bool load_pairing_config_from_provider();

    /// @brief First-boot handling for the unpaired-access default and the shared-PSK fallback
    /// record: seeds unpaired_access_enabled_ only on a genuine first boot, then generates and
    /// persists the fallback record when the loaded config did not already reference one.
    /// @param loaded_config Whether load_pairing_config_from_provider() found a usable config.
    /// @param initial_unpaired_access_enabled First-boot default for unpaired access.
    void provision_shared_record_if_needed(bool loaded_config,
                                           bool initial_unpaired_access_enabled);

    /// @brief Generate and persist the Pairing PSK if the store has none.
    void provision_pairing_psk_if_needed();

    /// @brief Return true if a resolved PSK is a shared-PSK record (long-term, no counterparty).
    static bool is_shared_record(const ResolvedPsk& r);

    /// @brief Return true if there is room for one genuine net-new record under max_records_.
    /// MUST be called with mutex_ already held.
    [[nodiscard]] bool has_capacity_locked() const {
        return this->records_.size() < this->max_records_;
    }

    /// @brief Find the index of a record by psk_id, or npos if absent.
    [[nodiscard]] size_t find_index(const std::string& psk_id) const;

    /// @brief Shared body of store_record() and store_record_superseding().
    /// @param supersede_server_id When true, retire any other record bound to the stored
    ///        record's server_id after the new record is persisted.
    bool store_record_impl(SendspinPairingRecord record, bool supersede_server_id);

    /// @brief Persist the current pairing config via the provider.
    /// @return True if the config was stored (or there is no provider, so there is nothing to
    ///         store); false only when a provider actively rejected the write. Nearly every
    ///         caller ignores this: a rejected config write is warned about and the change
    ///         stays RAM-only for the boot. First-boot provisioning is the exception: it must
    ///         not go on to persist a record the config cannot reference.
    bool persist_config();

    /// @brief Encode records_ (the WHOLE array) and save it under persistence_keys::RECORDS.
    ///
    /// MUST be called with mutex_ already held (the "_locked" suffix), so the encoded snapshot
    /// is always exactly what is in memory at the moment of the write. Every mutation path that
    /// touches records_ and needs to persist it goes through this one helper; see the locking
    /// discipline comment above its definition in the .cpp for why this is safe and how
    /// store_record()'s fail-closed contract is preserved despite it.
    /// @return true on success (or when there is no provider); false on a rejected write.
    bool persist_records_locked();

    // Struct fields
    /// Guards `records_` and `pairing_psk_` against a network-thread `resolve_by_psk_id`
    /// racing a main-loop mutation. Mutable so the const `resolve_by_psk_id` can lock it.
    mutable std::mutex mutex_;

    std::optional<SendspinPairingPsk> pairing_psk_;

    std::string record_mode_psk_id_;

    std::vector<SendspinPairingRecord> records_;

    std::optional<std::string> static_pin_;  ///< Configured static PIN (8 decimal digits).

    // Pointer fields
    SendspinPersistenceProvider* provider_{nullptr};

    // size_t fields
    /// Cap on records_.size() enforced by has_capacity_locked() / can_store_record(), and
    /// reported by storage_accounting(); see DEFAULT_MAX_RECORDS. Set once at construction,
    /// then read-only.
    size_t max_records_{DEFAULT_MAX_RECORDS};

    // 32-bit fields
    /// Dynamic-PIN failure counter (persisted through SendspinPairingConfig so escalation
    /// survives reboots). static_pin has no counter: it is gesture-gated on every attempt.
    int dynamic_pin_failures_{0};
    int dynamic_pin_min_length_{PIN_DEFAULT_MIN_DIGITS};
    // include/sendspin/config.h's SendspinPairingConfig::dynamic_pin_min_length hardcodes this
    // same default as a literal (a public header cannot include this private one); keep the two
    // in sync manually and let this assert catch drift.
    static_assert(PIN_DEFAULT_MIN_DIGITS == 6,
                  "update SendspinPairingConfig::dynamic_pin_min_length's default in "
                  "include/sendspin/config.h to match");

    // 8-bit fields
    bool dynamic_pin_enabled_{true};
    bool pairing_psk_enabled_{true};
    /// Set by set_pairing_psk() and persisted through SendspinPairingConfig; see
    /// pairing_psk_rotated(). Main-loop-only like the other config flags: written from the
    /// management handler and read by build_hello_message().
    bool pairing_psk_rotated_{false};
    bool static_pin_enabled_{false};
    /// Set by set_static_pin(); see static_pin_rotated().
    bool static_pin_rotated_{false};
    bool unpaired_access_enabled_{false};
};

}  // namespace sendspin
