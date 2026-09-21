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

/// @file persistence_codec.h
/// @brief Storage-format codec for the persistence structs in sendspin/config.h
///
/// `SendspinPersistenceProvider` (sendspin/client.h) is a plain blob store. The library is the
/// only caller of this codec: for the record slot keys (`persistence_keys::record_slot_key()`),
/// `PAIRING_PSK` and `PAIR_CONFIG` it turns `SendspinPairingRecord` / `SendspinPairingPsk` /
/// `SendspinPairingConfig` into the JSON blob a provider stores, and back. A provider must not
/// parse these blobs itself. It is public so a custom provider or a test can inspect or seed that
/// content in the same format.
///
/// This is a storage codec, independent of the Sendspin protocol wire format.
///
/// ## Wire format
///
/// Every encoded blob is a JSON object stamped with a "v" (version) field:
///
/// - Record: `{"v":1,"psk_id":"...","psk":"<base64url>","server_id":"...","label":"...",
///   "used":bool}`, with "label" omitted when absent.
/// - Pairing PSK: `{"v":1,"psk_id":"...","psk":"<base64url>","label":"..."}`, with "label"
///   omitted when absent.
/// - Pairing config: `{"v":1,"pairing_psk_enabled":bool,"unpaired_access_enabled":bool,
///   "dynamic_pin_enabled":bool,"static_pin_enabled":bool}`. The last two keys carry
///   `SendspinPairingConfig::dynamic_pairing_code_enabled` and `static_pairing_code_enabled`:
///   the stored names are part of the storage format, which is fixed independently of the
///   protocol's field names. Keys this version does not define are ignored on read.
///
/// `psk` is base64url (RFC 4648 section 5, no `=` padding) and always decodes to exactly 32
/// bytes.
///
/// ## Decode semantics
///
/// - A missing "v" is treated as version 1 (every blob written before "v" existed still
///   decodes). A "v" greater than `RECORD_CODEC_VERSION` still decodes on a best-effort basis
///   rather than being rejected.
/// - Unknown/extra fields are ignored everywhere. Missing optional fields take the struct's
///   default value.
/// - `decode_pairing_record()` / `decode_pairing_psk()` return `std::nullopt` when: the JSON
///   fails to parse, "psk_id" is missing or empty, "psk" is missing, or "psk" does not
///   base64url-decode to exactly 32 bytes. A record additionally needs a non-empty "server_id",
///   without which the PSK could never pass the post-match server check.
/// - `decode_pairing_config()` returns `std::nullopt` only when the JSON fails to parse or the
///   root is not an object. Missing fields take the `SendspinPairingConfig` struct's defaults.
/// - `base64url_decode()` follows RFC 4648 section 5: encode never pads, decode tolerates
///   padding, and any character outside the base64url alphabet makes it return `std::nullopt`.
///
/// ## Keyspace
///
/// Storage keys are the fixed constants in `persistence_keys` (sendspin/client.h), not a
/// provider's choice.
///
/// Long-term records are stored one per key, under the slot keys
/// `persistence_keys::record_slot_key()` names, with `persistence_keys::RECORD_ORDER` holding
/// their eviction order. A slot's blob is one record (`encode_pairing_record()` /
/// `decode_pairing_record()`), or empty when the slot is free, so a pairing or a revocation
/// rewrites one slot instead of every record, and a corrupt slot costs one record instead of the
/// store. A record the library writes encodes to 185 bytes (three 43-character base64url fields
/// plus fixed framing): that is the freshly paired `"used":false` form, which is the first blob
/// every pairing writes and the larger of the two states a record reaches (the flag flipping to
/// `true` costs one byte less). A label, which the library never sets itself, adds 11 bytes plus
/// its JSON-escaped length. Slot numbers keep the keys short: `psk_id` (43 characters) would not
/// fit an NVS key at all.

#pragma once

#include "sendspin/config.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sendspin {

/// Storage-format version stamped into encoded blobs; see "Decode semantics" above.
inline constexpr int RECORD_CODEC_VERSION = 1;

/// @brief Encodes a pairing record to its JSON storage format.
std::string encode_pairing_record(const SendspinPairingRecord& r);

/// @brief Decodes a pairing record from its JSON storage format.
/// @return The decoded record, or std::nullopt on parse failure or an invalid psk_id/psk.
std::optional<SendspinPairingRecord> decode_pairing_record(std::string_view bytes);

/// @brief Encodes the accepted Pairing PSK to its JSON storage format.
std::string encode_pairing_psk(const SendspinPairingPsk& p);

/// @brief Decodes the accepted Pairing PSK from its JSON storage format.
/// @return The decoded Pairing PSK, or std::nullopt on parse failure or an invalid psk_id/psk.
std::optional<SendspinPairingPsk> decode_pairing_psk(std::string_view bytes);

/// @brief Encodes the pairing policy config to its JSON storage format.
std::string encode_pairing_config(const SendspinPairingConfig& c);

/// @brief Decodes the pairing policy config from its JSON storage format. Missing fields take
/// the SendspinPairingConfig struct's defaults.
/// @return The decoded config, or std::nullopt on parse failure or a non-object root.
std::optional<SendspinPairingConfig> decode_pairing_config(std::string_view bytes);

/// @brief Encodes bytes to base64url, no `=` padding (RFC 4648 section 5).
/// @return ASCII string using only `A-Z a-z 0-9 - _`.
std::string base64url_encode(const uint8_t* data, size_t len);

/// @brief Decodes base64url, tolerating missing or present `=` padding (RFC 4648 section 5).
/// @return The decoded bytes, or std::nullopt if s contains a character outside the base64url
///         alphabet.
std::optional<std::vector<uint8_t>> base64url_decode(std::string_view s);

}  // namespace sendspin
