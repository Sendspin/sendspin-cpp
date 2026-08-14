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

// PIN helper known-answer tests and round-trip tests.
//
// All expected values were extracted by running the Python reference:
//   aiosendspin/.venv/bin/python3 importing aiosendspin.noise.pin
//   with fixed inputs (see comments per test).

#include "crypto/pin.h"
#include "test_util.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local

// =============================================================================
// pin_commit / pin_verify_commit round-trip
// =============================================================================

TEST(PinCommit, RoundTripSucceeds) {
    // pin_commit(nonce) = SHA-256(nonce)
    // pin_verify_commit(nonce, pin_commit(nonce)) must return true.
    auto nonce = pin_generate_nonce();
    auto commitment = pin_commit(nonce.data(), nonce.size());
    EXPECT_TRUE(pin_verify_commit(nonce.data(), nonce.size(), commitment.data(), commitment.size()));
}

TEST(PinCommit, WrongNonceFailsVerify) {
    auto nonce = pin_generate_nonce();
    auto commitment = pin_commit(nonce.data(), nonce.size());
    // Flip one byte.
    nonce[0] ^= 0xFF;
    EXPECT_FALSE(
        pin_verify_commit(nonce.data(), nonce.size(), commitment.data(), commitment.size()));
}

TEST(PinCommit, WrongCommitmentSizeFailsVerify) {
    auto nonce = pin_generate_nonce();
    std::array<uint8_t, 16> short_commit{};
    EXPECT_FALSE(pin_verify_commit(nonce.data(), nonce.size(), short_commit.data(), 16));
}

// =============================================================================
// pin_commit KAT
// =============================================================================

TEST(PinCommit, Kat) {
    // commit(nonce=bytes(range(32))) = SHA-256("sendspin-pair-commit-v1" || 0x00..0x1f)
    // (spec's "Dynamic PIN Pairing Flow" section: domain separator added to pair commit.)
    // Independently re-derived via: python3 -c "
    //   import hashlib
    //   print(hashlib.sha256(b'sendspin-pair-commit-v1' + bytes(range(32))).hexdigest())"
    // = "ea08c0aee3c421ace702f31591b3d213e8c371a8a8e3b0be3fd405ed841755a3"
    std::array<uint8_t, 32> nonce{};
    for (int i = 0; i < 32; ++i) nonce[i] = static_cast<uint8_t>(i);
    auto commitment = pin_commit(nonce.data(), nonce.size());
    EXPECT_EQ(to_hex(commitment), "ea08c0aee3c421ace702f31591b3d213e8c371a8a8e3b0be3fd405ed841755a3");
}

// =============================================================================
// pin_derive KATs
// =============================================================================

// All expected values extracted from the Python reference:
//   nonce_a = bytes(range(32))
//   nonce_b = bytes(range(32, 64))
//   h = bytes([0xAB] * 32)
//
//   derive_pin(h, nonce_a, nonce_b, 6) = "753798"
//   derive_pin(h, nonce_a, nonce_b, 4) = "3798"
//   derive_pin(h, nonce_a, nonce_b, 12) = "106199753798"
//
// Also for all-zeros inputs:
//   h = bytes(32), nonce_a = bytes(32), nonce_b = bytes(32)
//   derive_pin(h, nonce_a, nonce_b, 6) = "684790"

TEST(PinDerive, Kat6Digits) {
    std::array<uint8_t, 32> h{};
    std::fill(h.begin(), h.end(), 0xABu);
    std::array<uint8_t, 32> nonce_a{};
    for (int i = 0; i < 32; ++i) nonce_a[i] = static_cast<uint8_t>(i);
    std::array<uint8_t, 32> nonce_b{};
    for (int i = 0; i < 32; ++i) nonce_b[i] = static_cast<uint8_t>(i + 32);

    auto pin = pin_derive(h.data(), h.size(), nonce_a.data(), nonce_a.size(),
                          nonce_b.data(), nonce_b.size(), 6);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(*pin, "753798");
    EXPECT_EQ(pin->size(), 6u);
}

TEST(PinDerive, Kat4Digits) {
    std::array<uint8_t, 32> h{};
    std::fill(h.begin(), h.end(), 0xABu);
    std::array<uint8_t, 32> nonce_a{};
    for (int i = 0; i < 32; ++i) nonce_a[i] = static_cast<uint8_t>(i);
    std::array<uint8_t, 32> nonce_b{};
    for (int i = 0; i < 32; ++i) nonce_b[i] = static_cast<uint8_t>(i + 32);

    auto pin = pin_derive(h.data(), h.size(), nonce_a.data(), nonce_a.size(),
                          nonce_b.data(), nonce_b.size(), 4);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(*pin, "3798");
    EXPECT_EQ(pin->size(), 4u);
}

TEST(PinDerive, Kat12Digits) {
    std::array<uint8_t, 32> h{};
    std::fill(h.begin(), h.end(), 0xABu);
    std::array<uint8_t, 32> nonce_a{};
    for (int i = 0; i < 32; ++i) nonce_a[i] = static_cast<uint8_t>(i);
    std::array<uint8_t, 32> nonce_b{};
    for (int i = 0; i < 32; ++i) nonce_b[i] = static_cast<uint8_t>(i + 32);

    auto pin = pin_derive(h.data(), h.size(), nonce_a.data(), nonce_a.size(),
                          nonce_b.data(), nonce_b.size(), 12);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(*pin, "106199753798");
    EXPECT_EQ(pin->size(), 12u);
}

TEST(PinDerive, KatAllZeros6Digits) {
    std::array<uint8_t, 32> h{};
    std::array<uint8_t, 32> nonce_a{};
    std::array<uint8_t, 32> nonce_b{};

    auto pin = pin_derive(h.data(), h.size(), nonce_a.data(), nonce_a.size(),
                          nonce_b.data(), nonce_b.size(), 6);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(*pin, "684790");
}

// =============================================================================
// pin_derive range validation
// =============================================================================

TEST(PinDeriveValidation, BelowMinReturnsNullopt) {
    std::array<uint8_t, 32> h{}, na{}, nb{};
    EXPECT_FALSE(pin_derive(h.data(), 32, na.data(), 32, nb.data(), 32, 3).has_value());
    EXPECT_FALSE(pin_derive(h.data(), 32, na.data(), 32, nb.data(), 32, 0).has_value());
    EXPECT_FALSE(pin_derive(h.data(), 32, na.data(), 32, nb.data(), 32, -1).has_value());
}

TEST(PinDeriveValidation, AboveMaxReturnsNullopt) {
    std::array<uint8_t, 32> h{}, na{}, nb{};
    EXPECT_FALSE(pin_derive(h.data(), 32, na.data(), 32, nb.data(), 32, 13).has_value());
    EXPECT_FALSE(pin_derive(h.data(), 32, na.data(), 32, nb.data(), 32, 100).has_value());
}

TEST(PinDeriveValidation, AtBoundariesSucceeds) {
    std::array<uint8_t, 32> h{}, na{}, nb{};
    EXPECT_TRUE(pin_derive(h.data(), 32, na.data(), 32, nb.data(), 32, 4).has_value());
    EXPECT_TRUE(pin_derive(h.data(), 32, na.data(), 32, nb.data(), 32, 12).has_value());
}

TEST(PinDeriveValidation, WrongHashSizeReturnsNullopt) {
    std::array<uint8_t, 16> short_h{};
    std::array<uint8_t, 32> na{}, nb{};
    EXPECT_FALSE(
        pin_derive(short_h.data(), 16, na.data(), 32, nb.data(), 32, 6).has_value());
}

TEST(PinDeriveValidation, WrongNonceSizeReturnsNullopt) {
    std::array<uint8_t, 32> h{}, nb{};
    std::array<uint8_t, 16> short_na{};
    EXPECT_FALSE(
        pin_derive(h.data(), 32, short_na.data(), 16, nb.data(), 32, 6).has_value());
}

// =============================================================================
// Constants
// =============================================================================

TEST(PinConstants, Values) {
    EXPECT_EQ(PIN_NONCE_SIZE, 32u);
    EXPECT_EQ(PIN_COMMIT_SIZE, 32u);
    EXPECT_EQ(PIN_MIN_DIGITS, 4);
    EXPECT_EQ(PIN_MAX_DIGITS, 12);
    EXPECT_EQ(PIN_DEFAULT_MIN_DIGITS, 6);
}

// =============================================================================
// pin_generate_nonce: basic shape
// =============================================================================

TEST(PinNonce, GenerateProduce32Bytes) {
    auto n1 = pin_generate_nonce();
    auto n2 = pin_generate_nonce();
    EXPECT_EQ(n1.size(), 32u);
    EXPECT_NE(n1, n2);  // two separate calls should produce different nonces
}
