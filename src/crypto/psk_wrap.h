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

/// @file psk_wrap.h
/// @brief PSK Wrapping (spec "PSK Wrapping"): seals the new Sendspin PSK under a key derived from
/// the CPace output so `client/pair-finalize` in the PIN flows carries `wrapped_psk` instead of the
/// PSK in the clear.
///
/// K_wrap = SHA-256("sendspin-pair-psk-wrap-v1" || sid || ISK)
///
/// where `sid` is the CPace session id (see cpace.h CPace::sid(), spec "PAKE") and `ISK` is the
/// 64-byte CPace intermediate session key (see cpace.h CPace::isk()). The 32-byte PSK is then
/// sealed with the AEAD of the connection's negotiated cipher suite, a 12-byte all-zero nonce,
/// and empty associated data: wrapped_psk is the 48-byte ciphertext-plus-tag.

#pragma once

#include "cpace.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace sendspin {

/// @brief Size in bytes of a wrapped PSK (32-byte PSK + 16-byte AEAD tag).
static constexpr size_t WRAPPED_PSK_SIZE = 32 + 16;

/// @brief Domain-separation label for K_wrap. See PSK Wrapping in the spec's Pairing section.
static constexpr char PSK_WRAP_LABEL[] = "sendspin-pair-psk-wrap-v1";

/// @brief Derive K_wrap = SHA-256(PSK_WRAP_LABEL || sid || isk).
/// Returns std::nullopt if the underlying SHA-256 computation fails (e.g. noise-c allocation
/// failure); callers must not treat this as a recoverable all-zero key.
std::optional<std::array<uint8_t, 32>> derive_psk_wrap_key(
    const std::vector<uint8_t>& sid, const std::array<uint8_t, CPACE_ISK_SIZE>& isk);

/// @brief Seal a 32-byte PSK under K_wrap using the named AEAD cipher ("ChaChaPoly"), a
/// 12-byte all-zero nonce, and empty associated data.
/// @param cipher_name Noise-c cipher name for the connection's negotiated suite.
/// @param sid         CPace session id (see CPace::sid()).
/// @param isk         CPace intermediate session key (see CPace::isk()).
/// @param psk         32-byte PSK to wrap.
/// @return 48-byte wrapped_psk (ciphertext || tag), or nullopt on a cipher failure.
std::optional<std::array<uint8_t, WRAPPED_PSK_SIZE>> wrap_psk(
    const char* cipher_name, const std::vector<uint8_t>& sid,
    const std::array<uint8_t, CPACE_ISK_SIZE>& isk, const std::array<uint8_t, 32>& psk);

/// @brief Open a wrapped_psk sealed by wrap_psk(), recovering the 32-byte PSK.
/// Kept for parity with aiosendspin's reference Python implementation; used by tests.
/// @return The 32-byte PSK, or nullopt if the cipher is unrecognized or AEAD authentication
/// fails (wrong key or corrupted input, which the spec treats as a protocol error).
std::optional<std::array<uint8_t, 32>> unwrap_psk(
    const char* cipher_name, const std::vector<uint8_t>& sid,
    const std::array<uint8_t, CPACE_ISK_SIZE>& isk,
    const std::array<uint8_t, WRAPPED_PSK_SIZE>& wrapped);

}  // namespace sendspin
