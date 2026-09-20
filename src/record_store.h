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
/// @brief In-memory client pairing record store (pairing.md "Pairing Records"): holds the
/// records, calls `SendspinPersistenceProvider` for durability, and resolves `psk_id` -> PSK for
/// the Noise handshake.
///
/// Resolution is scoped to the `psk_category` the server declared: a long-term record, the
/// accepted Pairing PSK (when Pairing PSK access is enabled), or the Sentinel PSK. A psk_id
/// held only under another category is a miss.
///
/// The record types are the public ones from `sendspin/config.h`, so the persistence provider
/// can pass them through without conversion.

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
/// The three categories of connection.md "Pre-Shared Key".
enum class PskCategory : uint8_t {
    LONG_TERM,  ///< Per-pair long-term PSK from a successful pairing.
    PAIRING,    ///< Pairing PSK distributed out-of-band to admit a new server.
    SENTINEL,   ///< Published Sentinel PSK: authenticates nothing on its own.
};

/// @brief Parses the psk_category code carried in the Noise message 1 payload.
///
/// messaging.md "noise/handshake": 'lt' (long-term), 'pr' (pairing), 'sn' (Sentinel).
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
/// Thread-safety: `records_` and `pairing_psk_` are guarded by `mutex_`. Cross-thread access
/// goes through `resolve_by_psk_id` (network thread, Noise handshake and re-handshake) or the
/// one network-thread mutator, `store_record_superseding`, which is RAM-only and defers its
/// provider flush, `persist_records`, to the main loop. The pairing config and `pairing_psk_`
/// are seeded by the constructor and never written again, so `pairing_psk()` and the config
/// getters are the one exception: they read without the lock. No provider call is ever made
/// under `mutex_`.
class RecordStore {
public:
    /// @brief Default cap on retained long-term records; mirrors
    /// SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS.
    static constexpr size_t DEFAULT_MAX_RECORDS = SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS;

    /// @brief Floor under any configured cap. pairing.md "Pairing Records" requires room for at
    /// least 5 records, and requires the client to cap its concurrently open paired connections
    /// below that capacity so an evictable record always exists; connection_manager.h asserts
    /// that this library's connection budget stays under this floor.
    static constexpr size_t MIN_MAX_RECORDS = 5;

    /// @brief Construct and pre-provision the Pairing PSK.
    /// If a persistence provider is supplied, attempts to load saved records
    /// and pairing config first; generates fresh material only when absent.
    /// @param provider Persistence provider, or nullptr for an in-memory-only store.
    /// @param initial_unpaired_access_enabled First-boot default for unpaired (Sentinel) access.
    ///        Applied only when no pairing config was loaded; a loaded config always wins.
    /// @param max_records Cap on the number of long-term records retained. Defaults to
    ///        DEFAULT_MAX_RECORDS and is raised to MIN_MAX_RECORDS when a caller asks for less.
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

    /// @brief Store a long-term record in RAM, replacing any record with the same psk_id and
    /// retiring any other record bound to the same server_id (pairing mints a fresh per-server
    /// PSK, so leaving the prior record would keep the old one valid forever and let repeated
    /// re-pairs exhaust storage).
    ///
    /// Runs on the network thread, so it never calls the provider; the caller must schedule
    /// persist_records() onto the main loop (the client uses INBOX_TOPIC_RECORDS). Until that
    /// flush lands, the mutation is RAM-only.
    ///
    /// A pairing never fails for lack of storage (pairing.md "Pairing Records"): at capacity a
    /// net-new record evicts the least recently used one not in psk_ids_in_use (recency is the
    /// order of `records_`; see note_record_used).
    /// @param record The freshly paired record to store.
    /// @param psk_ids_in_use psk_ids backing a currently-open connection, provisional or
    ///        admitted, none of which may be evicted. The connection budget keeps this list
    ///        shorter than the capacity (see RecordStore::MIN_MAX_RECORDS), so a victim always
    ///        exists.
    /// @return true when stored; false only when every record at capacity is in use.
    bool store_record_superseding(SendspinPairingRecord record,
                                  const std::vector<std::string>& psk_ids_in_use = {});

    /// @brief Encode records_ and save it under persistence_keys::RECORDS. Main loop only: it
    /// calls the provider. The deferred flush half of store_record_superseding(),
    /// note_record_removed() and note_record_used(); logs the durability warning itself on a
    /// rejected write, so callers may ignore the return value.
    /// @param report_rejection Whether a rejected write is worth a warning. False for a write
    ///        that only carries the advisory `used` flag, which is rebuilt from use and whose
    ///        rejection would otherwise be reported on the first activate of every long-term
    ///        session on a device whose store is full or read-only.
    /// @return true on success (or when there is no provider); false on a rejected write.
    bool persist_records(bool report_rejection = true);

    /// @brief Erase the long-term record identified by psk_id from RAM, leaving the durable half
    /// to a later persist_records(). No-op if absent.
    ///
    /// For a revocation that must take effect before the caller's own lock is dropped: this takes
    /// only mutex_, the innermost lock, so a network-thread resolve_by_psk_id() misses the record
    /// from here on even though the blob is written later.
    /// @param psk_id The record to erase.
    /// @return true when a record was erased, and the array therefore needs persisting.
    [[nodiscard]] bool note_record_removed(const std::string& psk_id);

    /// @brief Flag the record at psk_id as used and make it the most recently used one in RAM,
    /// leaving the durable half to a later persist_records(). No-op if absent.
    ///
    /// `records_` is kept least-recently-used first, the order eviction reads (see
    /// store_record_superseding). The reorder stays in RAM; only the first flip of the durable
    /// `used` flag is worth persisting, so recency across a reboot is approximate (see the
    /// definition for why).
    /// @param psk_id The record to flag.
    /// @return true when the durable `used` flag flipped, and the array therefore needs
    ///         persisting; false when only the RAM recency order moved.
    [[nodiscard]] bool note_record_used(const std::string& psk_id);

    // ========================================
    // Pairing PSK (the one the client accepts to admit a new server)
    // ========================================

    [[nodiscard]] const std::optional<SendspinPairingPsk>& pairing_psk() const {
        return this->pairing_psk_;
    }

    // ========================================
    // Pairing config
    // ========================================

    [[nodiscard]] bool pairing_psk_enabled() const {
        return this->pairing_psk_enabled_;
    }

    [[nodiscard]] bool unpaired_access_enabled() const {
        return this->unpaired_access_enabled_;
    }

    [[nodiscard]] bool dynamic_pairing_code_enabled() const {
        return this->dynamic_pairing_code_enabled_;
    }

    // ========================================
    // Static pairing code
    // ========================================

    [[nodiscard]] const std::optional<std::string>& static_pairing_code() const {
        return this->static_pairing_code_;
    }

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
    /// Minting cannot fail on a full store: store_record_superseding() supersedes a re-pair's
    /// existing record and evicts for a net-new one (pairing.md "Pairing Records").
    [[nodiscard]] PairingOutcome resolve_pairing_outcome(
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

    /// @brief Room for one net-new record under max_records_. Call with mutex_ held.
    [[nodiscard]] bool has_capacity_locked() const {
        return this->records_.size() < this->max_records_;
    }
    /// @brief Body of resolve_by_psk_id(); call with mutex_ held.
    [[nodiscard]] std::optional<ResolvedPsk> resolve_by_psk_id_locked(const std::string& psk_id,
                                                                      PskCategory category) const;

    /// @brief The long-term record for psk_id, or nullptr. Call with mutex_ held; the pointer
    /// does not survive a mutation of records_.
    [[nodiscard]] const SendspinPairingRecord* record_by_psk_id(const std::string& psk_id) const;

    /// @brief The record bound to server_id, or nullptr. Same rules.
    [[nodiscard]] const SendspinPairingRecord* record_by_server_id(
        const std::string& server_id) const;

    /// @brief Sentinel find_index() returns for a psk_id the store does not hold.
    static constexpr size_t NPOS = static_cast<size_t>(-1);

    /// @brief Find the index of a record by psk_id, or NPOS if absent.
    [[nodiscard]] size_t find_index(const std::string& psk_id) const;

    /// @brief Drop the least recently used record no open connection is resolving against, to
    /// make room for a net-new one. Call with mutex_ held.
    /// @param psk_ids_in_use psk_ids that must not be evicted (see store_record_superseding).
    /// @return true when a record was evicted.
    bool evict_one_locked(const std::vector<std::string>& psk_ids_in_use);

    /// @brief Persist the current pairing config via the provider.
    /// @return false only when a provider rejected the write; the change then stays RAM-only for
    ///         the boot. The sole caller discards it.
    bool persist_config();

    /// @brief Encode the whole records_ array for persistence_keys::RECORDS. Call with mutex_
    /// held, so the snapshot is exactly what is in memory at that moment.
    /// @return The blob to save, or empty when there is no provider.
    [[nodiscard]] std::string encode_records_locked() const;

    /// @brief Save an encoded blob under persistence_keys::RECORDS and wipe it. Call with mutex_
    /// dropped: the provider write is flash I/O.
    /// @param encoded The encoded blob; wiped in place before returning.
    /// @return true on success (or when there is no provider); false on a rejected write.
    bool save_encoded_records(std::string& encoded);

    // Struct fields
    /// Mutable so the const `resolve_by_psk_id` can lock it.
    mutable std::mutex mutex_;

    std::optional<SendspinPairingPsk> pairing_psk_;

    std::vector<SendspinPairingRecord> records_;

    /// Configured static pairing code (8 decimal digits).
    std::optional<std::string> static_pairing_code_;

    // Pointer fields
    SendspinPersistenceProvider* provider_{nullptr};

    // size_t fields
    size_t max_records_{DEFAULT_MAX_RECORDS};

    // 8-bit fields
    bool dynamic_pairing_code_enabled_{true};
    bool pairing_psk_enabled_{true};
    bool static_pairing_code_enabled_{false};
    bool unpaired_access_enabled_{false};
};

}  // namespace sendspin
