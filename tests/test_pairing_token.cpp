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

// Pairing Token (pairing.md "Pairing Token") tests.
//
// Both reference vectors below are taken verbatim from pairing.md, not independently re-derived
// here: they are the specification's own worked examples, so reproducing them exactly is the
// correctness bar. The version-0 vector is in "Pairing PSK Flow" (client_key = 0x00..0x1f,
// pairing_psk = 0xe0..0xff); the version-1 vector is in "QR-code emission"
// (code = 0xe0..0xf7).

#include "crypto/pairing_code.h"
#include "crypto/pairing_token.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local

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

// ============================================================================
// Spec reference vector
// ============================================================================

TEST(PairingToken, PskSpecReferenceVector) {
    const auto client_key = make_client_key();
    const auto pairing_psk = make_pairing_psk();

    const std::string token = format_pairing_token(client_key, pairing_psk);

    // From pairing.md "Pairing PSK Flow", verbatim.
    const std::string expected =
        "SP:0AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYP6BYPC4PSOLZXH5DU6V97M5XXO74HR6LZ7"
        "J5PW674PT6X37T6757Y";
    EXPECT_EQ(token, expected);
}

// ============================================================================
// Structural invariants, over inputs the reference vector above does not cover
//
// Length / "SP:0" prefix / alphabet / absence of the digit '2' are already pinned byte-for-byte
// by PskSpecReferenceVector for its own input, so asserting them again on that same token proves
// nothing. They are checked here against other inputs, where they are not implied.
// ============================================================================

namespace {

void expect_well_formed_token(const std::string& token) {
    EXPECT_EQ(token.size(), PAIRING_PSK_TOKEN_LENGTH);
    EXPECT_EQ(token.size(), 107u);
    ASSERT_GE(token.size(), 4u);
    EXPECT_EQ(token.substr(0, 4), "SP:0");
    // A version-0 token is drawn only from the QR code alphanumeric set (0-9, A-Z, ':')...
    for (char c : token) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == ':';
        EXPECT_TRUE(ok) << "unexpected character '" << c << "' in token";
    }
    // ...and the body never contains the digit '2' (transliterated to '9' per pairing.md
    // "Pairing Token").
    for (size_t i = 4; i < token.size(); ++i) {
        EXPECT_NE(token[i], '2') << "position " << i;
    }
}

}  // namespace

TEST(PairingToken, WellFormedAcrossVariedInputs) {
    std::array<uint8_t, 32> zero{};
    std::array<uint8_t, 32> ones{};
    ones.fill(0xFF);
    expect_well_formed_token(format_pairing_token(zero, zero));
    expect_well_formed_token(format_pairing_token(ones, ones));
    expect_well_formed_token(format_pairing_token(zero, ones));
    expect_well_formed_token(format_pairing_token(make_client_key(), ones));
}

TEST(PairingToken, DifferentKeysProduceDifferentTokens) {
    auto client_key_a = make_client_key();
    auto client_key_b = make_client_key();
    client_key_b[0] ^= 0xFF;
    const auto pairing_psk = make_pairing_psk();

    const std::string token_a = format_pairing_token(client_key_a, pairing_psk);
    const std::string token_b = format_pairing_token(client_key_b, pairing_psk);
    EXPECT_NE(token_a, token_b);
}

// ============================================================================
// Version-1 tokens (the qr_code emission format)
// ============================================================================

namespace {

std::array<uint8_t, QR_PAIRING_CODE_SIZE> make_qr_code() {
    std::array<uint8_t, QR_PAIRING_CODE_SIZE> code{};
    for (size_t i = 0; i < code.size(); ++i) {
        code[i] = static_cast<uint8_t>(0xE0 + i);
    }
    return code;
}

}  // namespace

TEST(PairingCodeToken, SpecReferenceVector) {
    // From pairing.md "QR-code emission", verbatim, for code = 0xe0 0xe1 ... 0xf7.
    EXPECT_EQ(format_pairing_code_token(make_qr_code()),
              "SP:14DQ6FY7E4XTOP9HJ5LV6Z3PO57YPD4XT6T97N5Y");
}

TEST(PairingCodeToken, WellFormedAcrossVariedInputs) {
    // Length, version character and alphabet, over inputs the reference vector does not cover.
    std::array<uint8_t, QR_PAIRING_CODE_SIZE> zero{};
    std::array<uint8_t, QR_PAIRING_CODE_SIZE> ones{};
    ones.fill(0xFF);
    for (const auto& code : {zero, ones}) {
        const std::string token = format_pairing_code_token(code);
        EXPECT_EQ(token.size(), PAIRING_CODE_TOKEN_LENGTH);
        EXPECT_EQ(token.size(), 43u);
        ASSERT_GE(token.size(), 4u);
        EXPECT_EQ(token.substr(0, 4), "SP:1");
        for (char c : token) {
            const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == ':';
            EXPECT_TRUE(ok) << "unexpected character '" << c << "' in token";
        }
        for (size_t i = 4; i < token.size(); ++i) {
            EXPECT_NE(token[i], '2') << "position " << i;
        }
    }
}

TEST(PairingCodeToken, DifferentCodesProduceDifferentTokens) {
    auto code_a = make_qr_code();
    auto code_b = code_a;
    code_b[0] ^= 0xFF;
    EXPECT_NE(format_pairing_code_token(code_a), format_pairing_code_token(code_b));
}

TEST(PairingCodeToken, CarriesADifferentVersionThanThePskToken) {
    // The two versions must not collide: a server reading operator input decides which payload it
    // holds from this one character (pairing.md "Pairing Token").
    EXPECT_NE(PAIRING_PSK_TOKEN_VERSION, PAIRING_CODE_TOKEN_VERSION);
    std::array<uint8_t, 32> zero{};
    std::array<uint8_t, QR_PAIRING_CODE_SIZE> zero_code{};
    EXPECT_EQ(format_pairing_token(zero, zero).substr(0, 4), "SP:0");
    EXPECT_EQ(format_pairing_code_token(zero_code).substr(0, 4), "SP:1");
}
