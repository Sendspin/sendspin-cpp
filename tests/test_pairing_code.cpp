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

// Pairing-code derivation and commitment known-answer tests.
//
// Every expected value below was produced twice and compared: once from the spec formula in
// pairing.md "Dynamic Pairing Code Flow" written out directly in Python
//   python3 -c "import hashlib; print(hashlib.sha256(
//       b'sendspin-pairing-code-derive-v1' + h + nonce_a + nonce_b).hexdigest())"
// and once by running aiosendspin's reference implementation over the same inputs
//   aiosendspin/noise/pairing_code.py: derive_digest / derive_digits / derive_qr_code
// so a C++ value that matches these matches both the specification text and the server this
// client pairs with.

#include "crypto/pairing_code.h"
#include "test_util.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local

namespace {

/// @brief The three derivation inputs the known-answer tests below share.
struct DeriveInputs {
    std::array<uint8_t, 32> h{};
    std::array<uint8_t, 32> nonce_a{};
    std::array<uint8_t, 32> nonce_b{};
};

/// @brief h = 0xAB repeated, nonce_a = 0x00..0x1f, nonce_b = 0x20..0x3f.
DeriveInputs kat_inputs() {
    DeriveInputs in;
    std::fill(in.h.begin(), in.h.end(), 0xABu);
    for (int i = 0; i < 32; ++i) {
        in.nonce_a[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
        in.nonce_b[static_cast<size_t>(i)] = static_cast<uint8_t>(i + 32);
    }
    return in;
}

std::optional<std::array<uint8_t, 32>> digest_of(const DeriveInputs& in) {
    return pairing_code_digest(in.h.data(), in.h.size(), in.nonce_a.data(), in.nonce_a.size(),
                               in.nonce_b.data(), in.nonce_b.size());
}

}  // namespace

// =============================================================================
// pairing_code_commit / pairing_code_verify_commit
// =============================================================================

TEST(PairingCodeCommit, RoundTripSucceeds) {
    auto nonce = pairing_generate_nonce();
    auto commitment = pairing_code_commit(nonce.data(), nonce.size());
    EXPECT_TRUE(pairing_code_verify_commit(nonce.data(), nonce.size(), commitment.data(),
                                           commitment.size()));
}

TEST(PairingCodeCommit, WrongNonceFailsVerify) {
    auto nonce = pairing_generate_nonce();
    auto commitment = pairing_code_commit(nonce.data(), nonce.size());
    // Flip one byte.
    nonce[0] ^= 0xFF;
    EXPECT_FALSE(pairing_code_verify_commit(nonce.data(), nonce.size(), commitment.data(),
                                            commitment.size()));
}

TEST(PairingCodeCommit, WrongCommitmentSizeFailsVerify) {
    auto nonce = pairing_generate_nonce();
    std::array<uint8_t, 16> short_commit{};
    EXPECT_FALSE(pairing_code_verify_commit(nonce.data(), nonce.size(), short_commit.data(), 16));
}

TEST(PairingCodeCommit, Kat) {
    // commit_B = SHA-256("sendspin-pair-commit-v1" || 0x00..0x1f)
    // (pairing.md "Binding values"). Re-derived with:
    //   python3 -c "import hashlib; print(hashlib.sha256(
    //       b'sendspin-pair-commit-v1' + bytes(range(32))).hexdigest())"
    std::array<uint8_t, 32> nonce{};
    for (int i = 0; i < 32; ++i) {
        nonce[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    }
    auto commitment = pairing_code_commit(nonce.data(), nonce.size());
    EXPECT_EQ(to_hex(commitment),
              "ea08c0aee3c421ace702f31591b3d213e8c371a8a8e3b0be3fd405ed841755a3");
}

// =============================================================================
// pairing_code_digest
// =============================================================================

TEST(PairingCodeDigest, Kat) {
    auto digest = digest_of(kat_inputs());
    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(to_hex(*digest),
              "ff533978a64a628c9c3bd5de32338fa37cb79825e85f544433136c13e3e7edf7");
}

TEST(PairingCodeDigest, KatAllZeros) {
    DeriveInputs in;  // h, nonce_a and nonce_b all zero.
    auto digest = digest_of(in);
    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(to_hex(*digest),
              "ecdf16f52ca727f063d6d97ba61b5111948f00256a98520891952fba99caf882");
}

TEST(PairingCodeDigest, NonceOrderIsLoadBearing) {
    // The label fixes h, then nonce_A, then nonce_B. Swapping the two nonces must change the
    // digest, or the derivation would not bind each side's contribution to its own position.
    DeriveInputs in = kat_inputs();
    auto forward = digest_of(in);
    std::swap(in.nonce_a, in.nonce_b);
    auto swapped = digest_of(in);
    ASSERT_TRUE(forward.has_value());
    ASSERT_TRUE(swapped.has_value());
    EXPECT_NE(*forward, *swapped);
}

TEST(PairingCodeDigest, WrongHashSizeReturnsNullopt) {
    DeriveInputs in = kat_inputs();
    std::array<uint8_t, 16> short_h{};
    EXPECT_FALSE(pairing_code_digest(short_h.data(), short_h.size(), in.nonce_a.data(),
                                     in.nonce_a.size(), in.nonce_b.data(), in.nonce_b.size())
                     .has_value());
    // Control: the same call with the full-length hash succeeds.
    EXPECT_TRUE(digest_of(in).has_value());
}

TEST(PairingCodeDigest, WrongNonceSizeReturnsNullopt) {
    DeriveInputs in = kat_inputs();
    std::array<uint8_t, 16> short_nonce{};
    EXPECT_FALSE(pairing_code_digest(in.h.data(), in.h.size(), short_nonce.data(),
                                     short_nonce.size(), in.nonce_b.data(), in.nonce_b.size())
                     .has_value());
    EXPECT_FALSE(pairing_code_digest(in.h.data(), in.h.size(), in.nonce_a.data(),
                                     in.nonce_a.size(), short_nonce.data(), short_nonce.size())
                     .has_value());
    // Control: both nonces at their full length succeed.
    EXPECT_TRUE(digest_of(in).has_value());
}

// =============================================================================
// pairing_code_digits
// =============================================================================

TEST(PairingCodeDigits, Kat) {
    auto digest = digest_of(kat_inputs());
    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(pairing_code_digits(*digest), "564919");
}

TEST(PairingCodeDigits, KatAllZeros) {
    DeriveInputs in;
    auto digest = digest_of(in);
    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(pairing_code_digits(*digest), "593986");
}

TEST(PairingCodeDigits, ZeroPadsToSixDigits) {
    // A digest whose value modulo 10^6 is 5 must render as "000005", not "5": the reduction is
    // over the whole 256-bit digest, and the result is left-padded to exactly six ASCII digits.
    std::array<uint8_t, 32> digest{};
    digest[31] = 5;
    EXPECT_EQ(pairing_code_digits(digest), "000005");
}

TEST(PairingCodeDigits, ReducesTheWholeBigEndianDigest) {
    // 2^248 mod 10^6 = 662656, which only a reduction over all 32 bytes, read big-endian,
    // produces: taking the low bytes alone would give "000000".
    std::array<uint8_t, 32> digest{};
    digest[0] = 1;
    EXPECT_EQ(pairing_code_digits(digest), "662656");
}

// =============================================================================
// pairing_code_qr_bytes
// =============================================================================

TEST(PairingCodeQrBytes, KatTakesTheFirst24DigestBytes) {
    auto digest = digest_of(kat_inputs());
    ASSERT_TRUE(digest.has_value());
    auto code = pairing_code_qr_bytes(*digest);
    EXPECT_EQ(code.size(), QR_PAIRING_CODE_SIZE);
    EXPECT_EQ(to_hex(code), "ff533978a64a628c9c3bd5de32338fa37cb79825e85f5444");
}

// =============================================================================
// is_valid_static_pairing_code
// =============================================================================

TEST(StaticPairingCode, AcceptsEightDigits) {
    EXPECT_TRUE(is_valid_static_pairing_code("12345678"));
    EXPECT_TRUE(is_valid_static_pairing_code("00000000"));
}

TEST(StaticPairingCode, RejectsWrongLength) {
    EXPECT_FALSE(is_valid_static_pairing_code("1234567"));
    EXPECT_FALSE(is_valid_static_pairing_code("123456789"));
    EXPECT_FALSE(is_valid_static_pairing_code(""));
}

TEST(StaticPairingCode, RejectsNonDigits) {
    EXPECT_FALSE(is_valid_static_pairing_code("1234567a"));
    EXPECT_FALSE(is_valid_static_pairing_code("1234-567"));
    EXPECT_FALSE(is_valid_static_pairing_code(" 1234567"));
}

// =============================================================================
// pairing_code_digits_prs
// =============================================================================

TEST(PairingCodePrs, DigitsAreTheirOwnAsciiBytes) {
    // pairing.md "PAKE": PRS for a decimal code is the literal digits as UTF-8, e.g. 0x31 0x32
    // for "12". Both the six-digit dynamic code and the eight-digit static one encode this way.
    auto prs = pairing_code_digits_prs("12345678");
    ASSERT_EQ(prs.size(), 8u);
    EXPECT_EQ(prs[0], 0x31u);
    EXPECT_EQ(prs[7], 0x38u);
}

// =============================================================================
// pairing_generate_nonce
// =============================================================================

TEST(PairingNonce, GenerateProduces32Bytes) {
    auto n1 = pairing_generate_nonce();
    auto n2 = pairing_generate_nonce();
    EXPECT_EQ(n1.size(), PAIRING_NONCE_SIZE);
    EXPECT_NE(n1, n2);  // two separate calls should produce different nonces
}
