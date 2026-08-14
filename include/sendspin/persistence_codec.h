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
/// A `SendspinPersistenceProvider` implementer needs to turn `SendspinPairingRecord`,
/// `SendspinPairingPsk`, and `SendspinPairingConfig` into bytes it can put in a file, an NVS
/// entry, or any other byte-blob store. This header provides that serialization so providers
/// stop hand-rolling it: encode a struct to a JSON text blob, decode a blob back to a struct.
///
/// This is a STORAGE codec, intentionally independent of the Sendspin protocol wire format
/// (see `src/management.h`, which never carries the PSK secret in list-records responses -- the
/// two formats have different jobs and must not be confused). Providers remain free to use
/// their own format entirely; nothing in `SendspinPersistenceProvider`'s 17-method interface
/// changes. This header is purely an opt-in convenience.
///
/// ## Wire format
///
/// Every encoded blob is a JSON object stamped with a "v" (version) field:
///
/// - Record: `{"v":1,"psk_id":"...","psk":"<base64url>","server_id":"...","label":"...",
///   "used":bool}`, with "server_id"/"label" omitted when absent.
/// - Records array: `{"v":1,"records":[<record objects, without their own "v">]}` -- the array
///   wrapper carries "v" once; each entry has the same fields as a record minus "v".
///   `decode_pairing_record()` still accepts an entry that has its own "v" (it is ignored like
///   any other unknown field), so a single record object round-trips whether it came from
///   `encode_pairing_record()` or was lifted out of a records array.
/// - Pairing PSK: `{"v":1,"psk_id":"...","psk":"<base64url>","label":"..."}`, with "label"
///   omitted when absent.
/// - Pairing config: `{"v":1,"record_mode_psk_id":"...","pairing_psk_enabled":bool,
///   "unpaired_access_enabled":bool,"dynamic_pin_enabled":bool,"static_pin_enabled":bool,
///   "dynamic_pin_min_length":int,"dynamic_pin_failures":int}`.
///
/// `psk` is base64url (RFC 4648 section 5, no `=` padding) and always decodes to exactly 32
/// bytes.
///
/// ## Decode semantics
///
/// - A missing "v" is treated as version 1 (every blob written before "v" existed still
///   decodes). A "v" greater than `RECORD_CODEC_VERSION` still decodes on a best-effort basis --
///   unknown fields are ignored, so a blob written by a newer library version round-trips
///   through an older one instead of being rejected outright.
/// - Unknown/extra fields are ignored everywhere. Missing optional fields take the struct's
///   default value.
/// - `decode_pairing_record()` / `decode_pairing_psk()` return `std::nullopt` when: the JSON
///   fails to parse, "psk_id" is missing or empty, "psk" is missing, or "psk" does not
///   base64url-decode to exactly 32 bytes.
/// - `decode_pairing_records()` returns `std::nullopt` only when the JSON fails to parse or the
///   root has no array "records" field. An individual entry that fails record validation is
///   SKIPPED rather than failing the whole decode -- a provider should not lose its entire store
///   to one corrupt entry.
/// - `decode_pairing_config()` returns `std::nullopt` only when the JSON fails to parse or the
///   root is not an object. Missing fields take the `SendspinPairingConfig` struct's defaults.
/// - `base64url_decode()` follows RFC 4648 section 5: encode never pads, decode tolerates
///   padding, and any character outside the base64url alphabet makes it return `std::nullopt`.
///
/// ## Keyspace guidance for NVS-style stores
///
/// An encoded record is roughly 250 bytes; an 8-record store (`encode_pairing_records()`) comes
/// out around 2 KB -- comfortably under a typical NVS entry's ~4 KB limit. But `psk_id` is 43
/// characters (base64url of a 32-byte key) while NVS keys max out at 15, so do not use `psk_id`
/// as a storage key. Either key blobs by slot index (e.g. "ss_rec_0" .. "ss_rec_N") or store one
/// records-array blob under a single fixed key.

#pragma once

#include "sendspin/config.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sendspin {

/// Storage-format version stamped into encoded blobs. Decoders treat a missing "v" as 1
/// and ignore unknown fields, so blobs round-trip across firmware versions as fields are
/// added.
inline constexpr int RECORD_CODEC_VERSION = 1;

/// @brief Encodes a pairing record to its JSON storage format.
/// @param r The record to encode.
/// @return The encoded JSON text.
std::string encode_pairing_record(const SendspinPairingRecord& r);

/// @brief Decodes a pairing record from its JSON storage format.
/// @param bytes The encoded JSON text.
/// @return The decoded record, or std::nullopt on parse failure or an invalid psk_id/psk (see
///         "Decode semantics" above).
std::optional<SendspinPairingRecord> decode_pairing_record(std::string_view bytes);

/// @brief Encodes a vector of pairing records to their JSON storage format (a single blob
/// holding the whole array, suitable for a provider that stores the record list as one entry).
/// @param v The records to encode.
/// @return The encoded JSON text.
std::string encode_pairing_records(const std::vector<SendspinPairingRecord>& v);

/// @brief Decodes a vector of pairing records from its JSON storage format. Entries that fail
/// record validation are skipped rather than failing the whole decode (see "Decode semantics"
/// above).
/// @param bytes The encoded JSON text.
/// @return The decoded records (possibly fewer than were encoded, if some entries were
///         corrupt), or std::nullopt on parse failure or a missing/non-array "records" field.
std::optional<std::vector<SendspinPairingRecord>> decode_pairing_records(std::string_view bytes);

/// @brief Encodes the accepted Pairing PSK to its JSON storage format.
/// @param p The Pairing PSK to encode.
/// @return The encoded JSON text.
std::string encode_pairing_psk(const SendspinPairingPsk& p);

/// @brief Decodes the accepted Pairing PSK from its JSON storage format.
/// @param bytes The encoded JSON text.
/// @return The decoded Pairing PSK, or std::nullopt on parse failure or an invalid psk_id/psk
///         (see "Decode semantics" above).
std::optional<SendspinPairingPsk> decode_pairing_psk(std::string_view bytes);

/// @brief Encodes the pairing policy config to its JSON storage format.
/// @param c The config to encode.
/// @return The encoded JSON text.
std::string encode_pairing_config(const SendspinPairingConfig& c);

/// @brief Decodes the pairing policy config from its JSON storage format. Missing fields take
/// the SendspinPairingConfig struct's defaults.
/// @param bytes The encoded JSON text.
/// @return The decoded config, or std::nullopt on parse failure or a non-object root.
std::optional<SendspinPairingConfig> decode_pairing_config(std::string_view bytes);

/// @brief Encodes bytes to base64url, no `=` padding (RFC 4648 section 5).
/// @param data Input bytes.
/// @param len Number of bytes.
/// @return ASCII string using only `A-Z a-z 0-9 - _`.
std::string base64url_encode(const uint8_t* data, size_t len);

/// @brief Decodes base64url, tolerating missing or present `=` padding (RFC 4648 section 5).
/// @param s The base64url text.
/// @return The decoded bytes, or std::nullopt if s contains a character outside the base64url
///         alphabet.
std::optional<std::vector<uint8_t>> base64url_decode(std::string_view s);

}  // namespace sendspin
