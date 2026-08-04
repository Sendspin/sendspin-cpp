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

// Pairing Token (spec #125) tests.
//
// The reference vector below is taken verbatim from the spec's README.md "Pairing Token"
// section (client_key = 0x00..0x1f, pairing_psk = 0xe0..0xff), not independently re-derived by
// us -- it is the spec's own worked example, so reproducing it exactly is the correctness bar.

#include "crypto/pairing_token.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local

namespace {

std::array<uint8_t, 32> make_client_key() {
    std::array<uint8_t, 32> key{};
    for (int i = 0; i < 32; ++i) {
        key[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    }
    return key;
}

std::array<uint8_t, 32> make_pairing_psk() {
    std::array<uint8_t, 32> psk{};
    for (int i = 0; i < 32; ++i) {
        psk[static_cast<size_t>(i)] = static_cast<uint8_t>(0xE0 + i);
    }
    return psk;
}

}  // namespace

// =============================================================================
// Spec reference vector
// =============================================================================

TEST(PairingToken, SpecReferenceVector) {
    const auto client_key = make_client_key();
    const auto pairing_psk = make_pairing_psk();

    const std::string token = format_pairing_token(client_key, pairing_psk);

    // From the spec README.md's "Pairing Token" section, verbatim.
    const std::string expected =
        "SP:0AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYP6BYPC4PSOLZXH5DU6V97M5XXO74HR6LZ7"
        "J5PW674PT6X37T6757Y";
    EXPECT_EQ(token, expected);
}

TEST(PairingToken, IsExactly107Characters) {
    const auto client_key = make_client_key();
    const auto pairing_psk = make_pairing_psk();
    const std::string token = format_pairing_token(client_key, pairing_psk);
    EXPECT_EQ(token.size(), PAIRING_TOKEN_LENGTH);
    EXPECT_EQ(token.size(), 107u);
}

TEST(PairingToken, HasSpPrefixAndVersionZero) {
    const auto client_key = make_client_key();
    const auto pairing_psk = make_pairing_psk();
    const std::string token = format_pairing_token(client_key, pairing_psk);
    ASSERT_GE(token.size(), 4u);
    EXPECT_EQ(token.substr(0, 3), "SP:");
    EXPECT_EQ(token[3], '0');
}

// A version-0 token is drawn only from the QR code alphanumeric set (0-9, A-Z, ':').
TEST(PairingToken, UsesOnlyQrAlphanumericAlphabet) {
    const auto client_key = make_client_key();
    const auto pairing_psk = make_pairing_psk();
    const std::string token = format_pairing_token(client_key, pairing_psk);
    for (char c : token) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == ':';
        EXPECT_TRUE(ok) << "unexpected character '" << c << "' in token";
    }
}

// The body must never contain the digit '2' (transliterated to '9' per spec #125).
TEST(PairingToken, BodyNeverContainsDigitTwo) {
    const auto client_key = make_client_key();
    const auto pairing_psk = make_pairing_psk();
    const std::string token = format_pairing_token(client_key, pairing_psk);
    // Body starts after "SP:0".
    for (size_t i = 4; i < token.size(); ++i) {
        EXPECT_NE(token[i], '2') << "position " << i;
    }
}

// =============================================================================
// Differing inputs produce differing tokens (sanity, not a security proof)
// =============================================================================

TEST(PairingToken, DifferentKeysProduceDifferentTokens) {
    auto client_key_a = make_client_key();
    auto client_key_b = make_client_key();
    client_key_b[0] ^= 0xFF;
    const auto pairing_psk = make_pairing_psk();

    const std::string token_a = format_pairing_token(client_key_a, pairing_psk);
    const std::string token_b = format_pairing_token(client_key_b, pairing_psk);
    EXPECT_NE(token_a, token_b);
}

TEST(PairingToken, AllZeroInputsProduceValidLengthToken) {
    std::array<uint8_t, 32> zero_key{};
    std::array<uint8_t, 32> zero_psk{};
    const std::string token = format_pairing_token(zero_key, zero_psk);
    EXPECT_EQ(token.size(), PAIRING_TOKEN_LENGTH);
    EXPECT_EQ(token.substr(0, 4), "SP:0");
}
