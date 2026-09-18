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
/// The record types used here (`SendspinPairingRecord`, `SendspinPairingPsk`,
/// `SendspinPairingConfig`) are the public types from `sendspin/config.h` so
/// that the persistence provider can pass them through without conversion.

#pragma once

#include "crypto/constants.h"
#include "crypto/pairing_code.h"
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

/// @brief Parses the psk_category code carried in the Noise message 1 payload.
///
/// messaging.md "noise/handshake": 'lt' (long-term), 'pr' (pairing), 'sn' (Sentinel). Anything
/// else is not a category the protocol defines.
/// @param code The wire code.
/// @return The category, or nullopt if the code is not one of the three.
inline std::optional<PskCategory> psk_category_from_string(const std::string& code) {
    if (code == "lt") {
        return PskCategory::LONG_TERM;
    }
    if (code == "pr") {
        return PskCategory::PAIRING;
    }
    if (code == "sn") {
        return PskCategory::SENTINEL;
    }
    return std::nullopt;
}

// ============================================================================
// Resolved PSK (handshake currency)
// ============================================================================

/// @brief A PSK selected during a handshake, with its trust metadata.
/// Mirrors `ResolvedPsk` in `aiosendspin/noise/trust_store.py`.
struct ResolvedPsk {
    std::string psk_id;
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    PskCategory category{PskCategory::SENTINEL};
    /// Peer server_id; set for every long-term record, empty for the Sentinel and Pairing PSKs.
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
///     must go through `resolve_by_psk_id`, the `*_snapshot` / `*_copy` variants, or the one
///     network-thread mutator, `store_record_superseding` (RAM-only there; its deferred
///     provider flush, `persist_records`, is main-loop-only).
///   - The pointer/reference-returning getters (`record_by_psk_id`, `record_by_server_id`,
///     `records`) are for internal-locked or single-threaded (main-loop-only) use ONLY;
///     callers must not retain a returned pointer or reference across any mutation, and must
///     never call them from the network thread.
///   - The pairing config (`pairing_psk_enabled_`, `unpaired_access_enabled_`,
///     `dynamic_pairing_code_enabled_`, `static_pairing_code_enabled_`,
///     `static_pairing_code_`)
///     is construction-time state: seeded from the persisted blob and the client config by the
///     constructor, then read-only for the object's life, so no lock is needed even for the
///     network-thread read of `pairing_psk_enabled_` inside `resolve_by_psk_id`.
///   - `resolve_by_psk_id` runs on the network thread (Noise handshake and re-handshake)
///     under `mutex_` so a network-thread resolve cannot race a main-loop mutation of
///     `records_` / `pairing_psk_`.
class RecordStore {
public:
    /// @brief Default cap on the number of long-term records retained; see
    /// SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS for the rationale, which this mirrors
    /// so there is one source of truth for the number.
    static constexpr size_t DEFAULT_MAX_RECORDS = SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS;

    /// @brief Construct and pre-provision the Pairing PSK.
    /// If a persistence provider is supplied, attempts to load saved records
    /// and pairing config first; generates fresh material only when absent.
    /// @param provider Persistence provider, or nullptr for an in-memory-only store.
    /// @param initial_unpaired_access_enabled First-boot default for unpaired (Sentinel) access.
    ///        Applied only when no pairing config was loaded; a loaded config always wins.
    /// @param max_records Cap on the number of long-term records retained. Defaults to
    ///        DEFAULT_MAX_RECORDS.
    explicit RecordStore(SendspinPersistenceProvider* provider,
                         bool initial_unpaired_access_enabled = false,
                         size_t max_records = DEFAULT_MAX_RECORDS);

    // ========================================
    // PSK resolution (used by the Noise handshake)
    // ========================================

    /// @brief Resolve a psk_id to its PSK for the handshake, within one category.
    ///
    /// connection.md "Pre-Shared Key": the client compares the psk_id to the hash of each
    /// candidate PSK OF THE DECLARED CATEGORY, so a psk_id the client holds only under a
    /// different category is a lookup miss rather than a match.
    /// @param psk_id   The psk_id from the Noise message 1 payload.
    /// @param category The category the server declared it is using that PSK as.
    /// @return The matching PSK, or nullopt if this client holds no such PSK in that category.
    [[nodiscard]] std::optional<ResolvedPsk> resolve_by_psk_id(const std::string& psk_id,
                                                               PskCategory category) const;

    // ========================================
    // Long-term record management
    // ========================================

    /// @brief Return the long-term record identified by psk_id, if any.
    [[nodiscard]] const SendspinPairingRecord* record_by_psk_id(const std::string& psk_id) const;

    /// @brief Return the record bound to server_id, if any.
    [[nodiscard]] const SendspinPairingRecord* record_by_server_id(
        const std::string& server_id) const;

    /// @brief Return a locked copy of all long-term records (thread-safe).
    /// Safe to call from any thread; iterates under mutex_ so the copy is consistent.
    [[nodiscard]] std::vector<SendspinPairingRecord> records_snapshot() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->records_;
    }

    /// @brief Return a locked copy of the record identified by psk_id, if any (thread-safe).
    /// Calls the unlocked record_by_psk_id helper while holding mutex_; no recursion since
    /// record_by_psk_id does not lock. Returns nullopt when the psk_id is not found.
    [[nodiscard]] std::optional<SendspinPairingRecord> record_by_psk_id_copy(
        const std::string& psk_id) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        const SendspinPairingRecord* r = record_by_psk_id(psk_id);
        return r ? std::optional<SendspinPairingRecord>(*r) : std::nullopt;
    }

    /// @brief Store a long-term record in RAM, retiring any OTHER record bound to the same
    /// server_id. Replaces any existing record with the same psk_id, and leaves records for
    /// other psk_ids alone.
    ///
    /// This is the pairing-completion form: pairing mints a fresh per-server PSK that
    /// REPLACES whatever that server held before, so leaving the prior record in place
    /// would keep the old PSK valid forever and let repeated re-pairs exhaust storage.
    ///
    /// This NEVER calls the provider: it runs on the NETWORK thread
    /// (the server/pair-finalize ack handler), where the record must become resolvable before
    /// the handler returns but the provider contract only permits main-loop calls. The caller
    /// must arrange for persist_records() to run on the main loop afterwards (the client does
    /// this via INBOX_TOPIC_RECORDS); until that flush lands, the mutation is RAM-only.
    /// @return true when the record is stored in RAM; false only when the store is at
    /// capacity (nothing is retired then).
    bool store_record_superseding(SendspinPairingRecord record);

    /// @brief Encode records_ and save it under persistence_keys::RECORDS. MAIN LOOP ONLY
    /// (calls the provider). The deferred flush half of store_record_superseding(); logs the
    /// durability warning itself on a rejected write, so callers may ignore the return value.
    /// @return true on success (or when there is no provider); false on a rejected write.
    bool persist_records();

    /// @brief Remove the long-term record identified by psk_id.
    /// No-op if absent.
    void remove_record(const std::string& psk_id);

    /// @brief Flag the record at psk_id as used. No-op if absent or already used.
    void mark_record_used(const std::string& psk_id);

    // ========================================
    // Pairing PSK (the one the client accepts to admit a new server)
    // ========================================

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

    /// @brief Return whether dynamic-pairing-code pairing is enabled.
    [[nodiscard]] bool dynamic_pairing_code_enabled() const {
        return this->dynamic_pairing_code_enabled_;
    }

    // ========================================
    // Static pairing code
    // ========================================

    /// @brief Return the configured static pairing code, if any.
    [[nodiscard]] const std::optional<std::string>& static_pairing_code() const {
        return this->static_pairing_code_;
    }

    /// @brief Return whether static-pairing-code pairing is enabled.
    [[nodiscard]] bool static_pairing_code_enabled() const {
        return this->static_pairing_code_enabled_;
    }

    // ========================================
    // Pairing outcome
    // ========================================

    /// @brief Result of resolve_pairing_outcome(): a fresh per-server PSK and the record that
    /// holds it.
    struct PairingOutcome {
        std::array<uint8_t, NOISE_PSK_SIZE> psk{};
        SendspinPairingRecord record;

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

    /// @brief Mint a pairing outcome: a fresh PSK bound to server_id and the record holding it.
    ///
    /// A re-pair for a server that already holds a record supersedes it in place, so it is not
    /// subject to the capacity cap.
    /// @return nullopt when the store is full and the record would be a net-new one.
    [[nodiscard]] std::optional<PairingOutcome> resolve_pairing_outcome(
        const std::string& server_id, const std::optional<std::string>& label = std::nullopt);

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

    /// @brief Load static_pairing_code_ from the provider's STATIC_PAIRING_CODE blob, if
    /// present and valid.
    void load_static_pairing_code_from_provider();

    /// @brief Load the pairing config fields from the provider's PAIR_CONFIG blob, if present.
    /// @return True if a valid config was loaded; the seeding helper below uses this (the
    ///         "loaded_config" signal) to decide first-boot vs. damaged-config behavior.
    bool load_pairing_config_from_provider();

    /// @brief First-boot handling for the unpaired-access default: seeds
    /// unpaired_access_enabled_ only on a genuine first boot, then persists the config.
    /// @param loaded_config Whether load_pairing_config_from_provider() found a usable config.
    /// @param initial_unpaired_access_enabled First-boot default for unpaired access.
    void seed_first_boot_config(bool loaded_config, bool initial_unpaired_access_enabled);

    /// @brief Generate and persist the Pairing PSK if the store has none.
    void provision_pairing_psk_if_needed();

    /// @brief Return true if there is room for one genuine net-new record under max_records_.
    /// MUST be called with mutex_ already held.
    [[nodiscard]] bool has_capacity_locked() const {
        return this->records_.size() < this->max_records_;
    }
    /// @brief Body of resolve_by_psk_id(). MUST be called with mutex_ already held, so a caller
    /// that holds mutex_ across a wider body can run the same resolution without re-entering
    /// this non-recursive mutex.
    [[nodiscard]] std::optional<ResolvedPsk> resolve_by_psk_id_locked(const std::string& psk_id,
                                                                      PskCategory category) const;

    /// @brief Find the index of a record by psk_id, or npos if absent.
    [[nodiscard]] size_t find_index(const std::string& psk_id) const;

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
    /// discipline comment above its definition in the .cpp for why this is safe.
    /// @return true on success (or when there is no provider); false on a rejected write.
    bool persist_records_locked();

    // Struct fields
    /// Guards `records_` and `pairing_psk_` against a network-thread `resolve_by_psk_id`
    /// racing a main-loop mutation. Mutable so the const `resolve_by_psk_id` can lock it.
    mutable std::mutex mutex_;

    std::optional<SendspinPairingPsk> pairing_psk_;

    std::vector<SendspinPairingRecord> records_;

    /// Configured static pairing code (8 decimal digits).
    std::optional<std::string> static_pairing_code_;

    // Pointer fields
    SendspinPersistenceProvider* provider_{nullptr};

    // size_t fields
    /// Cap on records_.size() enforced by has_capacity_locked(); see DEFAULT_MAX_RECORDS. Set
    /// once at construction, then read-only.
    size_t max_records_{DEFAULT_MAX_RECORDS};

    // 8-bit fields
    bool dynamic_pairing_code_enabled_{true};
    bool pairing_psk_enabled_{true};
    bool static_pairing_code_enabled_{false};
    bool unpaired_access_enabled_{false};
};

}  // namespace sendspin
