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

/// @file wrap_test_helpers.h
/// @brief The server side of pairing.md "Wrapping", for tests that check what the client sealed.
///
/// The client only ever wraps, so opening a wrapped field is the peer's half of the exchange and
/// lives here rather than in the library. The key derivation is the production one
/// (derive_wrap_key()), so a test that opens a field proves the client derived the same K_wrap a
/// server would.

#pragma once

#include "crypto/cpace.h"
#include "crypto/psk_wrap.h"
#include "platform/crypto.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

/// @brief Opens a field sealed by sendspin::wrap_value(), as the server does.
/// @param label       Per-field wrap label (PSK_WRAP_LABEL or NONCE_WRAP_LABEL).
/// @param cipher_name Noise-c cipher name for the connection's negotiated suite.
/// @param sid         CPace session id (see CPace::sid()).
/// @param isk         CPace intermediate session key (see CPace::isk()).
/// @param wrapped     The 48-byte wrapped field (ciphertext || tag).
/// @return The 32-byte value, or nullopt when authentication fails.
inline std::optional<std::array<uint8_t, 32>> unwrap_value_as_server(
    std::string_view label, const char* cipher_name, const std::vector<uint8_t>& sid,
    const std::array<uint8_t, sendspin::CPACE_ISK_SIZE>& isk,
    const std::array<uint8_t, sendspin::WRAPPED_VALUE_SIZE>& wrapped) {
    auto k_wrap = sendspin::derive_wrap_key(label, sid, isk);
    if (!k_wrap.has_value()) {
        return std::nullopt;
    }
    auto pt = sendspin::aead_oneshot_decrypt(cipher_name, k_wrap->data(), k_wrap->size(),
                                             wrapped.data(), wrapped.size());
    sendspin::secure_zero_container(k_wrap.value());
    if (!pt.has_value() || pt->size() != 32) {
        return std::nullopt;
    }
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), pt->data(), out.size());
    sendspin::secure_zero_container(pt.value());
    return out;
}
