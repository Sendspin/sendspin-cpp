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
#include "protocol_messages.h"
#include "sendspin/client.h"
#include "sendspin/config.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
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
    SENTINEL,   ///< Published Sentinel PSK - authenticates nothing on its own.
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
///   - The config fields (`pairing_psk_enabled_`, `unpaired_access_enabled_`,
///     `record_mode_psk_id_`) are main-loop-only; they are never written from the network
///     thread, so no lock is needed for reads on the main loop.
///   - `resolve_by_psk_id` runs on the network thread (Noise handshake and re-handshake)
///     under `mutex_` so a network-thread resolve cannot race a main-loop mutation of
///     `records_` / `pairing_psk_`.
class RecordStore {
public:
    /// @brief Construct and pre-provision the shared-PSK fallback record.
    /// If a persistence provider is supplied, attempts to load saved records
    /// and pairing config first; generates fresh material only when absent.
    explicit RecordStore(SendspinPersistenceProvider* provider);

    virtual ~RecordStore() = default;

    // ========================================================================
    // PSK resolution (used by the Noise handshake, Phase 2+)
    // ========================================================================

    /// @brief Resolve a psk_id to its PSK for the handshake.
    /// Order: long-term record -> accepted Pairing PSK -> Sentinel PSK.
    /// Returns nullopt only if psk_id is entirely unknown (not even Sentinel).
    [[nodiscard]] std::optional<ResolvedPsk> resolve_by_psk_id(const std::string& psk_id) const;

    // ========================================================================
    // Long-term record management
    // ========================================================================

    /// @brief Return the long-term record identified by psk_id, if any.
    [[nodiscard]] const SendspinPairingRecord* record_by_psk_id(const std::string& psk_id) const;

    /// @brief Return the stored-pubkey record bound to server_id, if any.
    /// Shared-PSK records (server_id absent) are never returned here.
    [[nodiscard]] const SendspinPairingRecord* record_by_server_id(
        const std::string& server_id) const;

    /// @brief Return all long-term records (includes the shared fallback).
    /// Main-loop-only: the reference is invalidated by any concurrent mutation.
    // cppcheck-suppress unusedFunction
    // Public accessor, not currently called by this repo's own sources or tests; kept for
    // consumers that need main-loop-thread, zero-copy record access (records_snapshot() below
    // is the thread-safe copying alternative already used internally).
    [[nodiscard]] const std::vector<SendspinPairingRecord>& records() const {
        return this->records_;
    }

    /// @brief Return a locked copy of all long-term records (thread-safe).
    /// Safe to call from any thread; iterates under mutex_ so the copy is consistent.
    [[nodiscard]] std::vector<SendspinPairingRecord> records_snapshot() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->records_;
    }

    /// @brief Return a locked copy of the record identified by psk_id, if any (thread-safe).
    /// Calls the unlocked record_by_psk_id helper while holding mutex_ -- no recursion since
    /// record_by_psk_id does not lock. Returns nullopt when the psk_id is not found.
    [[nodiscard]] std::optional<SendspinPairingRecord> record_by_psk_id_copy(
        const std::string& psk_id) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        const SendspinPairingRecord* r = record_by_psk_id(psk_id);
        return r ? std::optional<SendspinPairingRecord>(*r) : std::nullopt;
    }

    /// @brief Persist and store a long-term record. Replaces any existing record
    /// with the same psk_id.
    ///
    /// The provider write happens first: when it fails, the in-memory store is left
    /// untouched so the caller can fail the exchange closed instead of completing it on
    /// a key that would be lost at the next reboot.
    /// @return true when the record is stored (and persisted, when a provider is set);
    /// false when the persistence provider rejected the write.
    bool store_record(SendspinPairingRecord record);

    /// @brief Remove the long-term record identified by psk_id.
    /// No-op if absent.
    void remove_record(const std::string& psk_id);

    /// @brief Flag the record at psk_id as used. No-op if absent or already used.
    void mark_record_used(const std::string& psk_id);

    /// @brief Return whether the record may be removed.
    /// The record referenced by record_mode_psk_id is protected.
    [[nodiscard]] bool can_remove_record(const std::string& psk_id) const;

    // ========================================================================
    // Pairing PSK (the one the client accepts to admit a new server)
    // ========================================================================

    /// @brief Set the accepted Pairing PSK, replacing any existing one.
    void set_pairing_psk(SendspinPairingPsk psk);

    /// @brief Clear the accepted Pairing PSK. No-op if absent.
    void clear_pairing_psk();

    /// @brief Return the accepted Pairing PSK, if any.
    [[nodiscard]] const std::optional<SendspinPairingPsk>& pairing_psk() const {
        return this->pairing_psk_;
    }

    // ========================================================================
    // Pairing config
    // ========================================================================

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

    // ========================================================================
    // PIN lockout (Phase 8b/8c, in-memory only)
    // ========================================================================

    /// @brief Number of consecutive PIN failures before lockout.
    static constexpr int PIN_LOCKOUT_THRESHOLD = 10;

    /// @brief Return true if `method`'s PIN pairing is currently locked out.
    /// Lockout is in-memory only (not persisted); cleared on restart.
    [[nodiscard]] bool is_pin_locked_out(SendspinPairMethod method) const {
        auto it = this->pin_failures_.find(method);
        if (it == this->pin_failures_.end()) {
            return false;
        }
        return it->second >= PIN_LOCKOUT_THRESHOLD;
    }

    /// @brief Return the current PIN failure count for `method` (0 if none recorded).
    [[nodiscard]] int pin_failure_count(SendspinPairMethod method) const {
        auto it = this->pin_failures_.find(method);
        return it == this->pin_failures_.end() ? 0 : it->second;
    }

    /// @brief Increment the PIN failure counter for `method`.
    void record_pin_failure(SendspinPairMethod method);

    /// @brief Reset the PIN failure counter for `method` to zero (on success or lockout clear).
    void reset_pin_failures(SendspinPairMethod method);

    // ========================================================================
    // Static PIN (Phase 8c)
    // ========================================================================

    /// @brief Return the configured static PIN, if any.
    [[nodiscard]] const std::optional<std::string>& static_pin() const {
        return this->static_pin_;
    }

    /// @brief Return whether static-PIN pairing is enabled.
    [[nodiscard]] bool static_pin_enabled() const {
        return this->static_pin_enabled_;
    }

    /// @brief Set the configured static PIN (8 decimal digits), replacing any existing one.
    void set_static_pin(const std::string& pin);

    /// @brief Clear the configured static PIN. No-op if absent.
    void clear_static_pin();

    /// @brief Set the static-PIN-enabled flag and persist the config.
    void set_static_pin_enabled(bool enabled);

    /// @brief Return the psk_id of the shared-PSK fallback record.
    [[nodiscard]] const std::string& record_mode_psk_id() const {
        return this->record_mode_psk_id_;
    }

    /// @brief Set the shared-PSK fallback record.
    /// @return false if psk_id does not reference an existing shared-PSK record.
    bool set_record_mode_psk_id(const std::string& psk_id);

    /// @brief Set the pairing-PSK-enabled flag and persist the config.
    void set_pairing_psk_enabled(bool enabled);

    /// @brief Set the unpaired-access-enabled flag and persist the config.
    void set_unpaired_access_enabled(bool enabled);

    /// @brief Set the dynamic-PIN-enabled flag and persist the config.
    void set_dynamic_pin_enabled(bool enabled);

    /// @brief Set the minimum PIN length and persist the config.
    void set_dynamic_pin_min_length(int length);

    // ========================================================================
    // Pairing outcome (Phase 5+, declared now for completeness)
    // ========================================================================

    /// @brief Decide a pairing outcome.
    ///
    /// When storage is not exhausted (`can_store_record()` is true), generates a
    /// fresh PSK bound to server_id and returns {psk, record}.
    /// When storage is exhausted, returns the shared fallback PSK and record=nullopt.
    /// Returns nullopt on error (missing shared fallback).
    struct PairingOutcome {
        std::array<uint8_t, NOISE_PSK_SIZE> psk{};
        /// nullopt = storage exhausted, use the shared-PSK fallback record.
        std::optional<SendspinPairingRecord> record;
    };
    [[nodiscard]] std::optional<PairingOutcome> resolve_pairing_outcome(
        const std::string& server_id, const std::optional<std::string>& label = std::nullopt);

    /// @brief Return true if a new record can be stored (default: always true).
    [[nodiscard]] virtual bool can_store_record() const {
        return true;
    }

    // ========================================================================
    // Storage accounting (Phase 6)
    // ========================================================================

    /// @brief Storage accounting report returned by storage_accounting().
    struct StorageReport {
        int free{0};             ///< Number of free record slots.
        int capacity{0};         ///< Total record slot capacity.
        int cost_individual{1};  ///< Slots consumed by a stored-pubkey record.
        int cost_shared{1};      ///< Slots consumed by a shared-PSK record.
    };

    /// @brief Return storage accounting info, or nullopt for unbounded/unknown storage.
    ///
    /// The default implementation returns nullopt (host-backed provider: unbounded).
    /// A future bounded-storage provider can override this to report capacity to the
    /// managing server. When nullopt, the management/result omits the "storage" key.
    ///
    /// include_static semantics (attachment point in management.h with_storage):
    ///   - list-records and get-pairing-config: include capacity/costs.
    ///   - all other results: free only.
    [[nodiscard]] virtual std::optional<StorageReport> storage_accounting() const {
        return std::nullopt;
    }

private:
    /// @brief Return true if a resolved PSK is a shared-PSK record (long-term, no counterparty).
    static bool is_shared_record(const ResolvedPsk& r);

    /// @brief Find the index of a record by psk_id, or npos if absent.
    [[nodiscard]] size_t find_index(const std::string& psk_id) const;

    /// @brief Persist the current pairing config via the provider.
    void persist_config();

    std::vector<SendspinPairingRecord> records_;
    std::optional<SendspinPairingPsk> pairing_psk_;
    std::optional<std::string> static_pin_;  ///< Configured static PIN (8 decimal digits).

    // Pairing config
    bool pairing_psk_enabled_{true};
    bool unpaired_access_enabled_{false};
    bool dynamic_pin_enabled_{true};
    bool static_pin_enabled_{false};
    int dynamic_pin_min_length_{6};
    std::string record_mode_psk_id_;

    // PIN lockout (in-memory; not persisted; cleared on restart)
    std::map<SendspinPairMethod, int> pin_failures_;

    SendspinPersistenceProvider* provider_{nullptr};

    /// Guards `records_` and `pairing_psk_` against a network-thread `resolve_by_psk_id`
    /// racing a main-loop mutation. Mutable so the const `resolve_by_psk_id` can lock it.
    mutable std::mutex mutex_;
};

}  // namespace sendspin
