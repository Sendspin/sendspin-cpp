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

#include "crypto/pairing_code.h"
#include "test_util.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>
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

// ============================================================================
// pairing_code_commit / pairing_code_verify_commit
// ============================================================================

TEST(PairingCodeCommit, RoundTripSucceeds) {
    auto nonce = pairing_generate_nonce();
    auto commitment = pairing_code_commit(nonce.data(), nonce.size());
    ASSERT_TRUE(commitment.has_value());
    EXPECT_TRUE(pairing_code_verify_commit(nonce.data(), nonce.size(), commitment->data(),
                                           commitment->size()));
}

TEST(PairingCodeCommit, WrongNonceFailsVerify) {
    auto nonce = pairing_generate_nonce();
    auto commitment = pairing_code_commit(nonce.data(), nonce.size());
    ASSERT_TRUE(commitment.has_value());
    nonce[0] ^= 0xFF;
    EXPECT_FALSE(pairing_code_verify_commit(nonce.data(), nonce.size(), commitment->data(),
                                            commitment->size()));
}

// The commit/verify length guards. pairing_code_commit() and pairing_code_verify_commit() are
// one family: a commitment is only ever checked against the nonce that produced it, so both
// lengths are guarded on both sides.
TEST(PairingCodeCommit, LengthGuardsRejectWrongSizedArguments) {
    const auto nonce = pairing_generate_nonce();
    const auto commitment = pairing_code_commit(nonce.data(), nonce.size());
    ASSERT_TRUE(commitment.has_value());

    struct CommitRow {
        const char* name;
        size_t nonce_len;
        bool expect_ok;
    };
    const std::array<uint8_t, 33> spare{};
    const CommitRow commit_rows[] = {
        {"commit/nonce-16-bytes", 16, false},
        {"commit/nonce-33-bytes", 33, false},
        {"commit/nonce-0-bytes", 0, false},
        // Control: a nonce of exactly PAIRING_NONCE_SIZE bytes commits.
        {"commit/nonce-PAIRING_NONCE_SIZE", PAIRING_NONCE_SIZE, true},
    };
    for (const CommitRow& row : commit_rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(pairing_code_commit(spare.data(), row.nonce_len).has_value(), row.expect_ok);
    }

    // The verify rows pin the composed contract, not one line: the nonce clause cannot be seen on
    // its own from here, since pairing_code_commit() rejects the same length and the call would
    // return false without it.
    struct VerifyRow {
        const char* name;
        size_t nonce_len;
        size_t commitment_len;
        bool expect_ok;
    };
    const VerifyRow verify_rows[] = {
        {"verify/short-commitment", PAIRING_NONCE_SIZE, 16, false},
        {"verify/short-nonce", 16, PAIRING_COMMIT_SIZE, false},
        {"verify/both-short", 16, 16, false},
        // Control: both arguments at their defined lengths verify.
        {"verify/both-defined-lengths", PAIRING_NONCE_SIZE, PAIRING_COMMIT_SIZE, true},
    };
    for (const VerifyRow& row : verify_rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(pairing_code_verify_commit(nonce.data(), row.nonce_len, commitment->data(),
                                             row.commitment_len),
                  row.expect_ok);
    }
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
    ASSERT_TRUE(commitment.has_value());
    EXPECT_EQ(to_hex(*commitment),
              "ea08c0aee3c421ace702f31591b3d213e8c371a8a8e3b0be3fd405ed841755a3");
}

// ============================================================================
// pairing_code_digest
// ============================================================================

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

// pairing_code_digest()'s length guards: the hash and both nonces are fixed-size inputs to the
// derivation label (pairing.md "Dynamic Pairing Code Flow").
TEST(PairingCodeDigest, LengthGuardsRejectWrongSizedArguments) {
    const DeriveInputs in = kat_inputs();
    const std::array<uint8_t, 32> spare{};

    struct Row {
        const char* name;
        size_t hash_len;
        size_t nonce_a_len;
        size_t nonce_b_len;
        bool expect_ok;
    };
    const Row rows[] = {
        {"short-hash", 16, PAIRING_NONCE_SIZE, PAIRING_NONCE_SIZE, false},
        {"short-nonce_a", in.h.size(), 16, PAIRING_NONCE_SIZE, false},
        {"short-nonce_b", in.h.size(), PAIRING_NONCE_SIZE, 16, false},
        // Control: all three inputs at their defined lengths derive.
        {"all-defined-lengths", in.h.size(), PAIRING_NONCE_SIZE, PAIRING_NONCE_SIZE, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(pairing_code_digest(in.h.data(), row.hash_len, spare.data(), row.nonce_a_len,
                                      spare.data(), row.nonce_b_len)
                      .has_value(),
                  row.expect_ok);
    }
}

// ============================================================================
// pairing_code_digits
// ============================================================================

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

// ============================================================================
// pairing_code_qr_bytes
// ============================================================================

TEST(PairingCodeQrBytes, KatTakesTheFirst24DigestBytes) {
    auto digest = digest_of(kat_inputs());
    ASSERT_TRUE(digest.has_value());
    auto code = pairing_code_qr_bytes(*digest);
    EXPECT_EQ(code.size(), QR_PAIRING_CODE_SIZE);
    EXPECT_EQ(to_hex(code), "ff533978a64a628c9c3bd5de32338fa37cb79825e85f5444");
}

// ============================================================================
// is_valid_static_pairing_code
// ============================================================================

// pairing.md "Static Pairing Code": exactly eight ASCII decimal digits, nothing else.
TEST(StaticPairingCode, AcceptsExactlyEightAsciiDigits) {
    struct Row {
        const char* name;
        const char* code;
        bool expect_ok;
    };
    const Row rows[] = {
        {"seven-digits", "1234567", false},
        {"nine-digits", "123456789", false},
        {"empty", "", false},
        {"trailing-letter", "1234567a", false},
        {"embedded-dash", "1234-567", false},
        {"leading-space", " 1234567", false},
        // Control: eight digits, including the all-zero code.
        {"eight-digits", "12345678", true},
        {"eight-zeros", "00000000", true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(is_valid_static_pairing_code(row.code), row.expect_ok);
    }
}

// ============================================================================
// pairing_code_digits_prs
// ============================================================================

TEST(PairingCodePrs, DigitsAreTheirOwnAsciiBytes) {
    // pairing.md "PAKE": PRS for a decimal code is the literal digits as UTF-8, e.g. 0x31 0x32
    // for "12". Both the six-digit dynamic code and the eight-digit static one encode this way.
    auto prs = pairing_code_digits_prs("12345678");
    ASSERT_EQ(prs.size(), 8u);
    EXPECT_EQ(prs[0], 0x31u);
    EXPECT_EQ(prs[7], 0x38u);
}

// ============================================================================
// pairing_generate_nonce
// ============================================================================

TEST(PairingNonce, GenerateProduces32Bytes) {
    auto n1 = pairing_generate_nonce();
    auto n2 = pairing_generate_nonce();
    EXPECT_EQ(n1.size(), PAIRING_NONCE_SIZE);
    EXPECT_NE(n1, n2);
}
