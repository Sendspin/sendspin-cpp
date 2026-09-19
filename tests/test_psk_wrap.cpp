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

// Wrapping (pairing.md "Wrapping") tests: K_wrap derivation and wrap_value
// round-trips.
//
// The two K_wrap KATs below were produced twice and compared: once from the spec formula written
// out directly in Python (see the comment on each test) and once by running aiosendspin's
// reference implementation (aiosendspin/noise/pairing.py: _wrap_key over _pake_sid) over the
// same sid and ISK. The wrap/unwrap round-trip tests are self-consistency checks against our own
// implementation (there is no independent reference for the AEAD step at KAT granularity without
// re-implementing ChaCha20-Poly1305/AES-GCM by hand).

#include "crypto/psk_wrap.h"
#include "platform/crypto.h"
#include "test_util.h"
#include "wrap_test_helpers.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local

namespace {

std::array<uint8_t, CPACE_ISK_SIZE> make_fixed_isk() {
    std::array<uint8_t, CPACE_ISK_SIZE> isk{};
    for (size_t i = 0; i < isk.size(); ++i) {
        isk[i] = static_cast<uint8_t>(i);
    }
    return isk;
}

std::vector<uint8_t> make_fixed_sid(uint32_t round = 1) {
    // A representative sid: LABEL || 32-byte handshake hash || 4-byte BE pairing_index ||
    // 4-byte BE round (pairing.md "PAKE"), with pairing_index 1.
    std::vector<uint8_t> sid;
    const char* label = "sendspin-pair-pake-v1";
    sid.insert(sid.end(), label, label + std::strlen(label));
    for (uint8_t i = 0; i < 32; ++i) {
        sid.push_back(i);
    }
    for (uint32_t counter : {uint32_t{1}, round}) {
        sid.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
        sid.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
        sid.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
        sid.push_back(static_cast<uint8_t>(counter & 0xFF));
    }
    return sid;
}

}  // namespace

// ============================================================================
// K_wrap KAT
// ============================================================================

// K_wrap = SHA-256(label || sid || isk), re-derived via:
//   python3 -c "
//     import hashlib
//     sid = (b'sendspin-pair-pake-v1' + bytes(range(32))
//            + (1).to_bytes(4,'big') + (1).to_bytes(4,'big'))
//     isk = bytes(range(64))
//     print(hashlib.sha256(b'sendspin-pair-psk-wrap-v1' + sid + isk).hexdigest())
//     print(hashlib.sha256(b'sendspin-pair-nonce-wrap-v1' + sid + isk).hexdigest())"
// derive_wrap_key() returns std::optional<std::array<uint8_t, 32>>: a failed
// SHA-256 computation must not silently produce an all-zero K_wrap, since wrap_value() would then
// seal the freshly minted PSK under a publicly derivable key. noise-c has no hook to force that
// failure deterministically, so this KAT (and the has_value() check it starts with) is the
// regression coverage available: it pins the success path and the optional-returning contract.
TEST(PskWrap, KWrapKat) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    auto k_wrap = derive_wrap_key(PSK_WRAP_LABEL, sid, isk);
    ASSERT_TRUE(k_wrap.has_value());
    EXPECT_EQ(to_hex(k_wrap.value()),
              "79069f5664638a5263d07188893fb3e38dd1983b603a100e5dccb28ec327967a");
}

TEST(PskWrap, NonceWrapKeyKat) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    auto k_wrap = derive_wrap_key(NONCE_WRAP_LABEL, sid, isk);
    ASSERT_TRUE(k_wrap.has_value());
    EXPECT_EQ(to_hex(k_wrap.value()),
              "7172ccfe4f3d6d71bddb9731344518bbe4b41a2c676a0832f1426056747c31c9");
}

// The two labels are what keeps the PSK and the commitment opening off one key. Both are sealed
// under the same sid and ISK with an all-zero AEAD nonce, so a shared key would be a two-time
// pad: an observer XORing the two ciphertexts would recover nonce_B xor the PSK, and with the
// PSK revealed at the end of a successful pairing, nonce_B itself.
TEST(PskWrap, TheTwoWrapLabelsProduceDifferentKeys) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    auto psk_key = derive_wrap_key(PSK_WRAP_LABEL, sid, isk);
    auto nonce_key = derive_wrap_key(NONCE_WRAP_LABEL, sid, isk);
    ASSERT_TRUE(psk_key.has_value());
    ASSERT_TRUE(nonce_key.has_value());
    EXPECT_NE(psk_key.value(), nonce_key.value());
}

// pairing.md "PAKE" puts the round number in the sid, so each round of an attempt wraps under
// its own key even though the pairing code, the handshake hash and the pairing_index are all
// unchanged across the attempt.
TEST(PskWrap, DifferentRoundsProduceDifferentKeys) {
    const auto isk = make_fixed_isk();
    auto round_1 = derive_wrap_key(PSK_WRAP_LABEL, make_fixed_sid(1), isk);
    auto round_2 = derive_wrap_key(PSK_WRAP_LABEL, make_fixed_sid(2), isk);
    ASSERT_TRUE(round_1.has_value());
    ASSERT_TRUE(round_2.has_value());
    EXPECT_NE(round_1.value(), round_2.value());
}

// ============================================================================
// wrap_value round-trip against the server's unwrap
// ============================================================================

TEST(PskWrap, RoundTripChaChaPoly) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    std::array<uint8_t, 32> psk{};
    for (size_t i = 0; i < psk.size(); ++i) {
        psk[i] = static_cast<uint8_t>(0xA0 + i);
    }

    auto wrapped = wrap_value(PSK_WRAP_LABEL, "ChaChaPoly", sid, isk, psk);
    ASSERT_TRUE(wrapped.has_value());
    EXPECT_EQ(wrapped->size(), WRAPPED_VALUE_SIZE);
    EXPECT_EQ(wrapped->size(), 48u);

    auto unwrapped = unwrap_value_as_server(PSK_WRAP_LABEL, "ChaChaPoly", sid, isk,
                                            wrapped.value());
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
    auto sid_b = make_fixed_sid(/*round=*/2);

    auto wrapped_a = wrap_value(PSK_WRAP_LABEL, "ChaChaPoly", sid_a, isk, psk);
    auto wrapped_b = wrap_value(PSK_WRAP_LABEL, "ChaChaPoly", sid_b, isk, psk);
    ASSERT_TRUE(wrapped_a.has_value());
    ASSERT_TRUE(wrapped_b.has_value());
    EXPECT_NE(wrapped_a.value(), wrapped_b.value());

    // A server holding the other round's sid derives a different K_wrap, so the field it would
    // open is not the one this round sealed: pairing.md "Protocol Errors" makes a wrapped_psk
    // that fails to decrypt a protocol error.
    auto unwrap_with_wrong_sid =
        unwrap_value_as_server(PSK_WRAP_LABEL, "ChaChaPoly", sid_b, isk, wrapped_a.value());
    EXPECT_FALSE(unwrap_with_wrong_sid.has_value());
}

TEST(PskWrap, UnknownCipherNameFails) {
    const auto sid = make_fixed_sid();
    const auto isk = make_fixed_isk();
    std::array<uint8_t, 32> psk{};

    auto wrapped = wrap_value(PSK_WRAP_LABEL, "NotACipher", sid, isk, psk);
    EXPECT_FALSE(wrapped.has_value());
}

// ============================================================================
// aead_cipher_name_from_noise_suite (platform/crypto.h)
// ============================================================================

TEST(PskWrap, CipherNameFromNoiseSuite) {
    EXPECT_STREQ(aead_cipher_name_from_noise_suite("Noise_KKpsk2_25519_ChaChaPoly_SHA256"),
                "ChaChaPoly");
    EXPECT_EQ(aead_cipher_name_from_noise_suite(""), nullptr);
    EXPECT_EQ(aead_cipher_name_from_noise_suite("garbage"), nullptr);
}
