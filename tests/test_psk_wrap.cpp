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

// PSK Wrapping (spec #117) tests: K_wrap derivation and wrap_psk/unwrap_psk round-trips.
//
// The K_wrap KAT below is independently re-derived via a small Python script (see the comment
// on PskWrap.KWrapKat) rather than taken from aiosendspin, since aiosendspin predates this
// construction change; the wrap/unwrap round-trip tests are self-consistency checks against our
// own implementation (there is no independent reference for the AEAD step at KAT granularity
// without re-implementing ChaCha20-Poly1305/AES-GCM by hand).

#include "crypto/psk_wrap.h"
#include "platform/crypto.h"
#include "test_util.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local

namespace {

std::array<uint8_t, CPACE_ISK_SIZE> make_fixed_isk() {
    std::array<uint8_t, CPACE_ISK_SIZE> isk{};
    for (size_t i = 0; i < isk.size(); ++i) {
        isk[i] = static_cast<uint8_t>(i);
    }
    return isk;
}

std::vector<uint8_t> make_fixed_sid() {
    // A representative sid: LABEL || 32-byte handshake hash || 4-byte BE counter (spec #120).
    std::vector<uint8_t> sid;
    const char* label = "sendspin-pair-pake-v1";
    sid.insert(sid.end(), label, label + std::strlen(label));
    for (uint8_t i = 0; i < 32; ++i) {
        sid.push_back(i);
    }
    sid.push_back(0x00);
    sid.push_back(0x00);
    sid.push_back(0x00);
    sid.push_back(0x01);
    return sid;
}

}  // namespace

// =============================================================================
// K_wrap KAT
// =============================================================================

// K_wrap = SHA-256("sendspin-pair-psk-wrap-v1" || sid || isk), independently re-derived via:
//   python3 -c "
//     import hashlib
//     label = b'sendspin-pair-psk-wrap-v1'
//     sid = b'sendspin-pair-pake-v1' + bytes(range(32)) + bytes([0,0,0,1])
//     isk = bytes(range(64))
//     print(hashlib.sha256(label + sid + isk).hexdigest())"
TEST(PskWrap, KWrapKat) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    auto k_wrap = derive_psk_wrap_key(sid, isk);
    EXPECT_EQ(to_hex(k_wrap), "cc733464487dfca4f0dc6af4f355440ccbc5bd25a5b1c0f6475db440463d2ca1");
}

// =============================================================================
// wrap_psk / unwrap_psk round-trip
// =============================================================================

TEST(PskWrap, RoundTripChaChaPoly) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    std::array<uint8_t, 32> psk{};
    for (size_t i = 0; i < psk.size(); ++i) {
        psk[i] = static_cast<uint8_t>(0xA0 + i);
    }

    auto wrapped = wrap_psk("ChaChaPoly", sid, isk, psk);
    ASSERT_TRUE(wrapped.has_value());
    EXPECT_EQ(wrapped->size(), WRAPPED_PSK_SIZE);
    EXPECT_EQ(wrapped->size(), 48u);

    auto unwrapped = unwrap_psk("ChaChaPoly", sid, isk, wrapped.value());
    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(unwrapped.value(), psk);
}

TEST(PskWrap, RoundTripAesGcm) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    std::array<uint8_t, 32> psk{};
    for (size_t i = 0; i < psk.size(); ++i) {
        psk[i] = static_cast<uint8_t>(0x55 + i);
    }

    auto wrapped = wrap_psk("AESGCM", sid, isk, psk);
    ASSERT_TRUE(wrapped.has_value());

    auto unwrapped = unwrap_psk("AESGCM", sid, isk, wrapped.value());
    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(unwrapped.value(), psk);
}

TEST(PskWrap, DifferentSidsProduceDifferentWrappedPsk) {
    const auto isk = make_fixed_isk();
    std::array<uint8_t, 32> psk{};
    for (size_t i = 0; i < psk.size(); ++i) {
        psk[i] = static_cast<uint8_t>(i);
    }

    auto sid_a = make_fixed_sid();
    auto sid_b = make_fixed_sid();
    sid_b.back() = 0x02;  // Different pairing_index counter.

    auto wrapped_a = wrap_psk("ChaChaPoly", sid_a, isk, psk);
    auto wrapped_b = wrap_psk("ChaChaPoly", sid_b, isk, psk);
    ASSERT_TRUE(wrapped_a.has_value());
    ASSERT_TRUE(wrapped_b.has_value());
    EXPECT_NE(wrapped_a.value(), wrapped_b.value());

    // Unwrapping with the wrong sid's key must fail (AEAD authentication failure), matching the
    // spec's "a wrapped_psk that fails to decrypt" protocol-error case.
    auto unwrap_with_wrong_sid = unwrap_psk("ChaChaPoly", sid_b, isk, wrapped_a.value());
    EXPECT_FALSE(unwrap_with_wrong_sid.has_value());
}

TEST(PskWrap, UnwrapFailsOnCorruptedCiphertext) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    std::array<uint8_t, 32> psk{};
    for (size_t i = 0; i < psk.size(); ++i) {
        psk[i] = static_cast<uint8_t>(i);
    }

    auto wrapped = wrap_psk("ChaChaPoly", sid, isk, psk);
    ASSERT_TRUE(wrapped.has_value());
    wrapped.value()[0] ^= 0xFF;  // Flip a bit in the ciphertext.

    auto unwrapped = unwrap_psk("ChaChaPoly", sid, isk, wrapped.value());
    EXPECT_FALSE(unwrapped.has_value());
}

TEST(PskWrap, UnknownCipherNameFails) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    std::array<uint8_t, 32> psk{};

    auto wrapped = wrap_psk("NotACipher", sid, isk, psk);
    EXPECT_FALSE(wrapped.has_value());
}

// =============================================================================
// aead_cipher_name_from_noise_suite (platform/crypto.h)
// =============================================================================

TEST(PskWrap, CipherNameFromNoiseSuite) {
    EXPECT_STREQ(aead_cipher_name_from_noise_suite("Noise_KKpsk2_25519_ChaChaPoly_SHA256"),
                "ChaChaPoly");
    EXPECT_STREQ(aead_cipher_name_from_noise_suite("Noise_KKpsk2_25519_AESGCM_SHA256"), "AESGCM");
    EXPECT_EQ(aead_cipher_name_from_noise_suite(""), nullptr);
    EXPECT_EQ(aead_cipher_name_from_noise_suite("garbage"), nullptr);
}
