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

/// @file management.h
/// @brief Pure handler logic for management/* requests and server/unpair.
///
/// Ports client/management.py from the aiosendspin reference. Each handler takes a
/// RecordStore and parsed request data, returns a ManagementResultPayload and a
/// ManagementEffect. Deliberately transport-free so handlers are unit-testable against
/// a bare RecordStore without any network layer.
///
/// pairing_psk, static_pin, and dynamic_pin are all implemented (Phase 8c added the PIN
/// branches). See handle_get_pairing_config / handle_set_pairing_config below.

#pragma once

#include "crypto/keys.h"
#include "crypto/pin.h"
#include "platform/base64.h"
#include "platform/logging.h"
#include "protocol_messages.h"
#include "record_store.h"

#include <optional>
#include <string>
#include <vector>

namespace sendspin {

inline constexpr const char* MGMT_TAG = "sendspin.management";

// ============================================================================
// ManagementEffect - what the connection does after sending the result
// ============================================================================

/// @brief Action the connection takes after sending management/result.
/// Mirrors ManagementEffect in aiosendspin/client/management.py.
enum class ManagementEffect : uint8_t {
    NONE,                  ///< No connection-level action required.
    GOODBYE_UNAUTHORIZED,  ///< Requester removed its own record; close with goodbye "unauthorized".
};

// ============================================================================
// Handler: server/unpair
// ============================================================================

/// @brief Handle server/unpair: drop the matched long-term record (unless shared) and prepare to
/// close with UNPAIRED.
///
/// Shared-PSK records (server_id absent) are never removed by server/unpair per the reference.
/// This is a fire-and-forget action: the caller (main loop) is responsible for disconnecting
/// after calling this.
///
/// @param store RecordStore to mutate.
/// @param matched_psk_id psk_id of the PSK that was matched for this connection.
inline void handle_unpair(RecordStore& store, const std::string& matched_psk_id) {
    auto record = store.record_by_psk_id_copy(matched_psk_id);
    if (!record.has_value() || !record->server_id.has_value()) {
        // Shared-PSK record or unknown: ignore (do not remove).
        return;
    }
    store.remove_record(matched_psk_id);
}

// ============================================================================
// Handler: management/list-records
// ============================================================================

/// @brief Handle management/list-records.
/// Returns summaries of all stored long-term records.
///
/// @param store RecordStore to query.
/// @param[out] result Populated with result=ok, data.records=[...].
/// @param[out] effect Always NONE.
inline void handle_list_records(RecordStore& store, ManagementResultPayload& result,
                                ManagementEffect& effect) {
    result.result = ManagementResult::OK;
    result.data = ManagementResultData{};
    result.data->records = std::vector<RecordSummary>{};
    for (const auto& r : store.records_snapshot()) {
        RecordSummary summary;
        summary.psk_id = r.psk_id;
        summary.server_id = r.server_id;
        summary.used = r.used;
        result.data->records->push_back(std::move(summary));
    }
    effect = ManagementEffect::NONE;
}

// ============================================================================
// Handler: management/add-record
// ============================================================================

/// @brief Handle management/add-record.
/// Decodes the PSK, validates size, checks for duplicates and capacity, then stores.
///
/// @param store RecordStore to mutate.
/// @param payload Parsed add-record payload.
/// @param[out] result Populated with result code.
/// @param[out] effect Always NONE.
inline void handle_add_record(RecordStore& store, const ManagementAddRecordPayload& payload,
                              ManagementResultPayload& result, ManagementEffect& effect) {
    effect = ManagementEffect::NONE;

    // A present server_id must be a well-formed peer id (43-char base64url of a
    // 32-byte key); anything else (notably "") could never match a handshake
    // server_id and would permanently orphan a storage slot.
    if (payload.server_id.has_value()) {
        auto id_decoded = b64url_decode(payload.server_id.value());
        if (payload.server_id->size() != PEER_ID_SIZE || !id_decoded.has_value() ||
            id_decoded->size() != X25519_KEY_SIZE) {
            SS_LOGW(MGMT_TAG, "add-record: invalid server_id");
            result.result = ManagementResult::INVALID;
            return;
        }
    }

    // Decode the base64url PSK.
    auto psk_decoded = b64url_decode(payload.psk);
    if (!psk_decoded.has_value() || psk_decoded->size() != NOISE_PSK_SIZE) {
        SS_LOGW(MGMT_TAG, "add-record: invalid psk (decode failed or wrong size)");
        result.result = ManagementResult::INVALID;
        return;
    }
    const std::vector<uint8_t>& psk_bytes = psk_decoded.value();

    // Compute psk_id and check for duplicates.
    std::array<uint8_t, NOISE_PSK_SIZE> psk_arr;
    std::copy(psk_bytes.begin(), psk_bytes.end(), psk_arr.begin());
    auto psk_id_opt = psk_id_for(psk_arr.data(), psk_arr.size());
    if (!psk_id_opt.has_value()) {
        result.result = ManagementResult::INVALID;
        return;
    }
    const std::string& psk_id = psk_id_opt.value();

    // Intentional divergence from the Python reference: resolve_by_psk_id also matches the
    // Sentinel PSK, so a submitted PSK whose psk_id equals the Sentinel psk_id returns
    // ALREADY_EXISTS here (cryptographically impossible in practice; the Python reference
    // would store it because it only checks long-term records for duplicates).
    if (store.resolve_by_psk_id(psk_id).has_value()) {
        SS_LOGW(MGMT_TAG, "add-record: record already exists (psk_id=%s)", psk_id.c_str());
        result.result = ManagementResult::ALREADY_EXISTS;
        return;
    }

    if (!store.can_store_record()) {
        SS_LOGW(MGMT_TAG, "add-record: storage exhausted");
        result.result = ManagementResult::STORAGE_EXHAUSTED;
        return;
    }

    SendspinPairingRecord rec;
    rec.psk_id = psk_id;
    rec.psk = psk_arr;
    rec.server_id = payload.server_id;
    store.store_record(std::move(rec));

    result.result = ManagementResult::OK;
}

// ============================================================================
// Handler: management/remove-record
// ============================================================================

/// @brief Handle management/remove-record.
/// Finds the record, checks protections, removes it, and detects own-record removal.
///
/// @param store RecordStore to mutate.
/// @param payload Parsed remove-record payload.
/// @param requester_server_id server_id of the requesting connection (for own-record detection).
/// @param[out] result Populated with result code.
/// @param[out] effect GOODBYE_UNAUTHORIZED if the requester removed its own record; else NONE.
inline void handle_remove_record(RecordStore& store, const ManagementRemoveRecordPayload& payload,
                                 const std::optional<std::string>& requester_server_id,
                                 ManagementResultPayload& result, ManagementEffect& effect) {
    effect = ManagementEffect::NONE;

    auto record = store.record_by_psk_id_copy(payload.psk_id);
    if (!record.has_value()) {
        SS_LOGW(MGMT_TAG, "remove-record: not found (psk_id=%s)", payload.psk_id.c_str());
        result.result = ManagementResult::NOT_FOUND;
        return;
    }

    if (!store.can_remove_record(payload.psk_id)) {
        SS_LOGW(MGMT_TAG, "remove-record: protected record (psk_id=%s)", payload.psk_id.c_str());
        result.result = ManagementResult::INVALID;
        return;
    }

    // Check if the requester is removing its own stored-pubkey record.
    const bool is_self = record->server_id.has_value() && requester_server_id.has_value() &&
                         record->server_id.value() == requester_server_id.value();
    if (is_self) {
        effect = ManagementEffect::GOODBYE_UNAUTHORIZED;
    }

    store.remove_record(payload.psk_id);
    result.result = ManagementResult::OK;
}

// ============================================================================
// Handler: management/get-pairing-config
// ============================================================================

/// @brief Handle management/get-pairing-config.
/// Returns the current pairing configuration. Secrets (raw PSK, raw static PIN) are never
/// included.
///
/// @param store RecordStore to query.
/// @param[out] result Populated with result=ok, data containing pairing_psk, static_pin,
///             dynamic_pin, record_mode, unpaired_access.
/// @param[out] effect Always NONE.
inline void handle_get_pairing_config(RecordStore& store, ManagementResultPayload& result,
                                      ManagementEffect& effect) {
    result.result = ManagementResult::OK;
    result.data = ManagementResultData{};

    // pairing_psk: report enabled flag only (no secrets). Mirrors _method_config(is_pin=False).
    PairingMethodConfig pairing_psk_cfg;
    pairing_psk_cfg.enabled = store.pairing_psk_enabled();
    result.data->pairing_psk = pairing_psk_cfg;

    // static_pin: enabled + locked_out, no min_pin_length (mirrors _method_config(is_pin=True)
    // called without min_pin_length for PairMethod.STATIC_PIN).
    PairingMethodConfig static_pin_cfg;
    static_pin_cfg.enabled = store.static_pin_enabled();
    static_pin_cfg.locked_out = store.is_pin_locked_out(SendspinPairMethod::STATIC_PIN);
    result.data->static_pin = static_pin_cfg;

    // dynamic_pin: enabled + locked_out + min_pin_length (mirrors _method_config(is_pin=True,
    // min_pin_length=config.dynamic_pin_min_length) for PairMethod.DYNAMIC_PIN).
    PairingMethodConfig dynamic_pin_cfg;
    dynamic_pin_cfg.enabled = store.dynamic_pin_enabled();
    dynamic_pin_cfg.locked_out = store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN);
    dynamic_pin_cfg.min_pin_length = store.dynamic_pin_min_length();
    result.data->dynamic_pin = dynamic_pin_cfg;

    // record_mode: psk_id of the shared-PSK fallback record.
    RecordModeConfig record_mode_cfg;
    record_mode_cfg.psk_id = store.record_mode_psk_id();
    result.data->record_mode = record_mode_cfg;

    // unpaired_access: enabled flag.
    UnpairedAccessConfig unpaired_cfg;
    unpaired_cfg.enabled = store.unpaired_access_enabled();
    result.data->unpaired_access = unpaired_cfg;

    effect = ManagementEffect::NONE;
}

// ============================================================================
// Handler: management/set-pairing-config
// ============================================================================

/// @brief Return whether `cfg` sets locked_out to anything but false (only false clears lockout).
/// Mirrors `_rejects_lockout` in aiosendspin/client/management.py.
template <typename PinConfig>
inline bool rejects_lockout(const std::optional<PinConfig>& cfg) {
    return cfg.has_value() && cfg->locked_out.has_value() && cfg->locked_out.value();
}

/// @brief Handle management/set-pairing-config.
/// Validates the entire patch before mutating anything, then applies atomically.
///
/// Validation order (mirrors aiosendspin/client/management.py handle_set_pairing_config):
///   1. pairing_psk.psk present -> decode + must be 32 bytes else INVALID.
///   2. static_pin.pin present -> must be exactly 8 decimal digits else INVALID.
///   3. static_pin.locked_out or dynamic_pin.locked_out present and not false -> INVALID (only
///      false is accepted, to clear lockout).
///   4. dynamic_pin.min_pin_length present -> must be within [PIN_MIN_DIGITS, PIN_MAX_DIGITS]
///      else INVALID.
///   5. record_mode present -> must name a shared-PSK (long-term, no server_id) else INVALID.
///   6. Apply all changes (nothing below fails).
///
/// @param store RecordStore to mutate.
/// @param payload Parsed set-pairing-config payload.
/// @param[out] result Populated with result code.
/// @param[out] effect Always NONE.
inline void handle_set_pairing_config(RecordStore& store,
                                      const ManagementSetPairingConfigPayload& payload,
                                      ManagementResultPayload& result, ManagementEffect& effect) {
    effect = ManagementEffect::NONE;

    // 1. Validate pairing_psk.psk if present.
    std::optional<std::array<uint8_t, NOISE_PSK_SIZE>> new_psk;
    if (payload.pairing_psk.has_value() && payload.pairing_psk->psk.has_value()) {
        auto decoded_opt = b64url_decode(payload.pairing_psk->psk.value());
        if (!decoded_opt.has_value() || decoded_opt->size() != NOISE_PSK_SIZE) {
            SS_LOGW(MGMT_TAG, "set-pairing-config: invalid pairing_psk.psk");
            result.result = ManagementResult::INVALID;
            return;
        }
        std::array<uint8_t, NOISE_PSK_SIZE> arr;
        std::copy(decoded_opt->begin(), decoded_opt->end(), arr.begin());
        new_psk = arr;
    }

    // 2. Validate static_pin.pin if present: exactly 8 decimal digits.
    if (payload.static_pin.has_value() && payload.static_pin->pin.has_value() &&
        !is_valid_static_pin(payload.static_pin->pin.value())) {
        SS_LOGW(MGMT_TAG, "set-pairing-config: invalid static_pin.pin");
        result.result = ManagementResult::INVALID;
        return;
    }

    // 3. locked_out: only false is accepted (clears lockout); true or any other value -> INVALID.
    if (rejects_lockout(payload.static_pin) || rejects_lockout(payload.dynamic_pin)) {
        SS_LOGW(MGMT_TAG, "set-pairing-config: locked_out must be false to clear lockout");
        result.result = ManagementResult::INVALID;
        return;
    }

    // 4. Validate dynamic_pin.min_pin_length if present.
    if (payload.dynamic_pin.has_value() && payload.dynamic_pin->min_pin_length.has_value() &&
        (payload.dynamic_pin->min_pin_length.value() < PIN_MIN_DIGITS ||
         payload.dynamic_pin->min_pin_length.value() > PIN_MAX_DIGITS)) {
        SS_LOGW(MGMT_TAG, "set-pairing-config: dynamic_pin.min_pin_length out of range");
        result.result = ManagementResult::INVALID;
        return;
    }

    // 5. Validate record_mode if present.
    if (payload.record_mode.has_value()) {
        const std::string& candidate_psk_id = payload.record_mode->psk_id;
        auto resolved = store.resolve_by_psk_id(candidate_psk_id);
        // Must be a long-term record with no counterparty (shared-PSK).
        if (!resolved.has_value() || resolved->category != PskCategory::LONG_TERM ||
            resolved->counterparty_id.has_value()) {
            SS_LOGW(MGMT_TAG, "set-pairing-config: record_mode psk_id is not a shared-PSK record");
            result.result = ManagementResult::INVALID;
            return;
        }
    }

    // 6. Apply (all inputs validated; nothing below fails).
    if (payload.record_mode.has_value()) {
        store.set_record_mode_psk_id(payload.record_mode->psk_id);
    }

    if (payload.pairing_psk.has_value() && payload.pairing_psk->enabled.has_value()) {
        store.set_pairing_psk_enabled(payload.pairing_psk->enabled.value());
    }
    if (payload.static_pin.has_value() && payload.static_pin->enabled.has_value()) {
        store.set_static_pin_enabled(payload.static_pin->enabled.value());
    }
    if (payload.dynamic_pin.has_value() && payload.dynamic_pin->enabled.has_value()) {
        store.set_dynamic_pin_enabled(payload.dynamic_pin->enabled.value());
    }
    if (payload.unpaired_access.has_value() && payload.unpaired_access->enabled.has_value()) {
        store.set_unpaired_access_enabled(payload.unpaired_access->enabled.value());
    }

    if (payload.dynamic_pin.has_value() && payload.dynamic_pin->min_pin_length.has_value()) {
        store.set_dynamic_pin_min_length(payload.dynamic_pin->min_pin_length.value());
    }

    if (new_psk.has_value()) {
        auto psk_id_opt = psk_id_for(new_psk->data(), new_psk->size());
        if (psk_id_opt.has_value()) {
            SendspinPairingPsk p;
            p.psk_id = psk_id_opt.value();
            p.psk = new_psk.value();
            store.set_pairing_psk(std::move(p));
        }
    }

    if (payload.static_pin.has_value() && payload.static_pin->pin.has_value()) {
        store.set_static_pin(payload.static_pin->pin.value());
    }

    if (payload.static_pin.has_value() && payload.static_pin->locked_out.has_value() &&
        !payload.static_pin->locked_out.value()) {
        store.reset_pin_failures(SendspinPairMethod::STATIC_PIN);
    }
    if (payload.dynamic_pin.has_value() && payload.dynamic_pin->locked_out.has_value() &&
        !payload.dynamic_pin->locked_out.value()) {
        store.reset_pin_failures(SendspinPairMethod::DYNAMIC_PIN);
    }

    result.result = ManagementResult::OK;
}

// ============================================================================
// Storage accounting attachment
// ============================================================================

/// @brief Attach storage accounting to a result payload if the store provides it.
///
/// Mirrors with_storage from aiosendspin/client/management.py.
/// free is always included; capacity and per-kind costs are added only when include_static=true
/// (list-records and get-pairing-config). If the store reports no accounting (nullopt), the
/// payload is left unchanged.
///
/// @param store The RecordStore whose storage_accounting() to consult.
/// @param[in,out] result The result payload to attach storage to.
/// @param include_static True for list-records and get-pairing-config (add capacity + costs).
inline void attach_storage_accounting(const RecordStore& store, ManagementResultPayload& result,
                                      bool include_static) {
    auto report = store.storage_accounting();
    if (!report.has_value()) {
        return;  // Unbounded/unknown storage: omit entirely.
    }

    StorageAccountingPayload storage;
    storage.free = report->free;
    if (include_static) {
        storage.capacity = report->capacity;
        storage.cost_individual = report->cost_individual;
        storage.cost_shared = report->cost_shared;
    }
    result.storage = std::move(storage);
}

}  // namespace sendspin
