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

/// @file pairing_token.h
/// @brief Pairing Token encoder (spec's "Pairing Token" section): the single "SP:"-prefixed,
/// versioned, base32 string that distributes a client's static public key and its Sendspin Pairing
/// PSK together for the Pairing PSK flow, so an operator can transfer both by copy/paste or QR
/// scan.
///
/// token   = "SP:" || version || body
/// payload = client_key (32 bytes) || pairing_psk (32 bytes)
/// body    = RFC 4648 base32(payload), '=' padding stripped, then every '2' -> '9'
///
/// This client only ever generates tokens (the server decodes them), so no decoder is provided
/// here; see the spec's "Pairing Token" section for the (server-side) decode algorithm.

#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace sendspin {

/// @brief Pairing-token format version implemented here (the spec's version '0').
static constexpr char PAIRING_TOKEN_VERSION = '0';

/// @brief Length in characters of a version-0 pairing token ("SP:" + version + 103-char body).
static constexpr size_t PAIRING_TOKEN_LENGTH = 107;

/// @brief Build a version-0 pairing token from a client's static public key and its Sendspin
/// Pairing PSK.
/// @param client_key   32-byte raw Curve25519 public key (the same bytes whose base64url form
///                     is the client_id).
/// @param pairing_psk  32-byte raw Sendspin Pairing PSK.
/// @return The 107-character token string (e.g. "SP:0AAAQ...").
std::string format_pairing_token(const std::array<uint8_t, 32>& client_key,
                                 const std::array<uint8_t, 32>& pairing_psk);

}  // namespace sendspin
