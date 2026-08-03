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

/// @file pin.h
/// @brief Dynamic-PIN derivation and commitment.
///
/// Mirrors `aiosendspin/noise/pin.py` exactly.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace sendspin {

// -----------------------------------------------------------------------------
// PIN constants (mirrors pin.py)
// -----------------------------------------------------------------------------

/// @brief Size of a PIN nonce in bytes.
static constexpr size_t PIN_NONCE_SIZE = 32;

/// @brief Size of a PIN commitment (SHA-256 digest) in bytes.
static constexpr size_t PIN_COMMIT_SIZE = 32;

/// @brief Label prepended to the SHA-256 input in derive_pin.
static constexpr char PIN_DERIVE_LABEL[] = "sendspin-pin-derive-v1";

/// @brief Minimum number of PIN digits.
static constexpr int PIN_MIN_DIGITS = 4;

/// @brief Maximum number of PIN digits.
static constexpr int PIN_MAX_DIGITS = 12;

/// @brief Default minimum PIN length (server-chosen default).
static constexpr int PIN_DEFAULT_MIN_DIGITS = 6;

/// @brief Fixed length of a static PIN, in decimal digits.
/// Mirrors `_STATIC_PIN_DIGITS` in aiosendspin/client/management.py.
static constexpr int STATIC_PIN_DIGITS = 8;

// -----------------------------------------------------------------------------
// PIN helpers
// -----------------------------------------------------------------------------

/// @brief Return whether `pin` is exactly STATIC_PIN_DIGITS decimal digits.
/// Mirrors `_valid_static_pin` in aiosendspin/client/management.py.
inline bool is_valid_static_pin(const std::string& pin) {
    if (pin.size() != static_cast<size_t>(STATIC_PIN_DIGITS)) {
        return false;
    }
    for (char c : pin) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

/// @brief Generate a fresh 32-byte CSPRNG nonce (nonce_A or nonce_B).
std::array<uint8_t, PIN_NONCE_SIZE> pin_generate_nonce();

/// @brief Compute the commitment commit_B = SHA-256(nonce).
std::array<uint8_t, PIN_COMMIT_SIZE> pin_commit(const uint8_t* nonce, size_t nonce_len);

/// @brief Return true if SHA-256(nonce) equals commitment (constant-time).
bool pin_verify_commit(const uint8_t* nonce, size_t nonce_len, const uint8_t* commitment,
                       size_t commitment_len);

/// @brief Derive a pin_length-digit PIN from the Noise handshake hash and both nonces.
///
/// digest = SHA-256(PIN_DERIVE_LABEL || handshake_hash || nonce_a || nonce_b)
/// pin_int = int.from_bytes(digest, "big") mod 10^pin_length
/// Returns the zero-padded decimal string, or std::nullopt if pin_length is out of range
/// or any input has the wrong size.
std::optional<std::string> pin_derive(const uint8_t* handshake_hash, size_t hash_len,
                                      const uint8_t* nonce_a, size_t nonce_a_len,
                                      const uint8_t* nonce_b, size_t nonce_b_len, int pin_length);

}  // namespace sendspin
