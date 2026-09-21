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

/// @file record_test_helpers.h
/// @brief Shared builders for random PSKs, SendspinPairingRecord fixtures, and the per-slot
/// persistence layout RecordStore loads them from.

#pragma once

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "platform/crypto.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/persistence_codec.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sendspin {

/// Generate a random PSK of NOISE_PSK_SIZE bytes.
inline std::array<uint8_t, NOISE_PSK_SIZE> make_random_psk() {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    return psk;
}

/// Build a stored-pubkey client record bound to server_id.
inline SendspinPairingRecord make_client_record(const std::string& server_id,
                                                 const std::optional<std::string>& label = {}) {
    auto psk = make_random_psk();
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_for(psk);
    rec.psk = psk;
    rec.server_id = server_id;
    rec.label = label;
    return rec;
}

/// True for any key RecordStore persists its long-term records under: a slot key or the
/// record-order key.
inline bool is_record_key(const std::string& key) {
    return key == persistence_keys::RECORD_ORDER ||
           key.rfind(persistence_keys::RECORD_SLOT_PREFIX, 0) == 0;
}

/// Wraps a string's bytes as a blob for load_blob()/seed_blob()/save_blob() calls.
inline std::vector<uint8_t> blob_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

/// Answers a load_blob() for a store seeded with `records` laid out one per slot in index order,
/// least recently used first. Returns nullopt for any other key, and for a slot no record fills.
inline std::optional<std::vector<uint8_t>> seeded_record_blob(
    const std::vector<SendspinPairingRecord>& records, const std::string& key) {
    if (key == persistence_keys::RECORD_ORDER) {
        std::vector<uint8_t> order;
        order.reserve(records.size());
        for (size_t i = 0; i < records.size(); ++i) {
            order.push_back(static_cast<uint8_t>(i));
        }
        return order;
    }
    for (size_t i = 0; i < records.size(); ++i) {
        if (key == persistence_keys::record_slot_key(i)) {
            return blob_bytes(encode_pairing_record(records[i]));
        }
    }
    return std::nullopt;
}

/// The record stored in a slot, or nullopt when the blob is absent, empty (a free slot), or does
/// not decode.
inline std::optional<SendspinPairingRecord> stored_record_in_slot(
    SendspinPersistenceProvider& provider, size_t slot) {
    auto blob = provider.load_blob(persistence_keys::record_slot_key(slot));
    if (!blob.has_value() || blob->empty()) {
        return std::nullopt;
    }
    return decode_pairing_record(
        std::string_view(reinterpret_cast<const char*>(blob->data()), blob->size()));
}

/// The stored record-order blob as slot numbers, least recently used first; empty when absent.
inline std::vector<uint8_t> stored_record_order(SendspinPersistenceProvider& provider) {
    auto blob = provider.load_blob(persistence_keys::RECORD_ORDER);
    return blob.value_or(std::vector<uint8_t>{});
}

/// Lay `records` out in a blob store one per slot in index order, least recently used first,
/// the way RecordStore persists them. TProvider is any fake with seed_blob(key, bytes).
template <typename TProvider>
void seed_records(TProvider& provider, const std::vector<SendspinPairingRecord>& records) {
    for (size_t i = 0; i < records.size(); ++i) {
        provider.seed_blob(persistence_keys::record_slot_key(i),
                           blob_bytes(encode_pairing_record(records[i])));
    }
    provider.seed_blob(persistence_keys::RECORD_ORDER,
                       seeded_record_blob(records, persistence_keys::RECORD_ORDER).value());
}

/// Make every record key a store rejects, so a flush cannot change what the next boot loads.
/// TProvider is any fake with a reject_save_keys set.
template <typename TProvider>
void reject_record_saves(TProvider& provider,
                         size_t max_records = SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS) {
    provider.reject_save_keys.insert(persistence_keys::RECORD_ORDER);
    for (size_t slot = 0; slot < max_records; ++slot) {
        provider.reject_save_keys.insert(persistence_keys::record_slot_key(slot));
    }
}

/// How many writes a store has taken for any record key: the slots plus the recency order.
/// TProvider is any fake with save_attempts(key). Pass the store's cap when it is not the
/// default, or the slots above the default go uncounted.
template <typename TProvider>
size_t record_writes(const TProvider& provider,
                     size_t max_records = SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS) {
    size_t writes = static_cast<size_t>(provider.save_attempts(persistence_keys::RECORD_ORDER));
    for (size_t slot = 0; slot < max_records; ++slot) {
        writes +=
            static_cast<size_t>(provider.save_attempts(persistence_keys::record_slot_key(slot)));
    }
    return writes;
}

/// The records `provider` holds, least recently used first: what the next boot loads. Reads the
/// stored slots and the record-order blob the way the store's load path does, so a test can state
/// what survives a reboot without building a second RecordStore over the same provider. Pass the
/// store's cap when it is not the default, or the slots above the default go unread.
inline std::vector<SendspinPairingRecord> persisted_records(
    SendspinPersistenceProvider& provider,
    size_t max_records = SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS) {
    std::vector<std::pair<uint8_t, SendspinPairingRecord>> by_slot;
    for (size_t slot = 0; slot < max_records; ++slot) {
        if (auto record = stored_record_in_slot(provider, slot)) {
            by_slot.emplace_back(static_cast<uint8_t>(slot), std::move(record.value()));
        }
    }
    std::vector<SendspinPairingRecord> ordered;
    ordered.reserve(by_slot.size());
    for (uint8_t slot : stored_record_order(provider)) {
        auto it = std::find_if(by_slot.begin(), by_slot.end(),
                               [slot](const auto& entry) { return entry.first == slot; });
        if (it == by_slot.end()) {
            continue;
        }
        ordered.push_back(std::move(it->second));
        by_slot.erase(it);
    }
    for (auto& entry : by_slot) {
        ordered.push_back(std::move(entry.second));
    }
    return ordered;
}

/// The psk_ids persisted_records() holds, in the same order.
inline std::vector<std::string> persisted_psk_ids(
    SendspinPersistenceProvider& provider,
    size_t max_records = SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS) {
    std::vector<std::string> ids;
    for (const auto& record : persisted_records(provider, max_records)) {
        ids.push_back(record.psk_id);
    }
    return ids;
}

/// Whether the record the next boot loads for psk_id carries the durable used flag. Pass the
/// store's cap when it is not the default, or the slots above the default go unread.
inline bool persisted_used(SendspinPersistenceProvider& provider, const std::string& psk_id,
                           size_t max_records = SendspinClientConfig::DEFAULT_MAX_PAIRING_RECORDS) {
    for (const auto& record : persisted_records(provider, max_records)) {
        if (record.psk_id == psk_id) {
            return record.used;
        }
    }
    return false;
}

}  // namespace sendspin
