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

// CPace-X25519-SHA512 known-answer tests and round-trip tests.
//
// All expected bytes were extracted by running the Python reference:
//   aiosendspin/.venv/bin/python3 importing aiosendspin.noise.cpace / pin
//   with fixed inputs (see comments per test).
//
// Official IETF draft-irtf-cfrg-cpace test vectors were not available offline;
// correctness is validated solely against the aiosendspin Python reference.

#include "crypto/cpace.h"
#include "test_util.h"
#include "platform/crypto.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local

// =============================================================================
// Building-block KATs
// =============================================================================

// --- cpace_prepend_len ---
// Reference: _prepend_len in cpace.py
// Expected values extracted from running the Python reference.

TEST(CPacePrimitives, PrependLenEmpty) {
    // _prepend_len(b'') = b'\x00'
    auto result = cpace_prepend_len(nullptr, 0);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], 0x00u);
}

TEST(CPacePrimitives, PrependLenOneByte) {
    // _prepend_len(b'A') = b'\x01A'
    const uint8_t data[] = {0x41};
    auto result = cpace_prepend_len(data, 1);
    EXPECT_EQ(to_hex(result), "0141");
}

TEST(CPacePrimitives, PrependLenDsi) {
    // _prepend_len(b'CPace255') = b'\x08CPace255'
    const uint8_t* dsi = reinterpret_cast<const uint8_t*>("CPace255");
    auto result = cpace_prepend_len(dsi, 8);
    EXPECT_EQ(to_hex(result), "084350616365323535");
}

TEST(CPacePrimitives, PrependLenMultiByteLength) {
    // _prepend_len(b'\x78' * 128): length 128 needs two varint bytes
    // Expected first 3 bytes: 0x80 0x01 0x78
    std::vector<uint8_t> data(128, 0x78);
    auto result = cpace_prepend_len(data.data(), 128);
    ASSERT_GE(result.size(), 3u);
    EXPECT_EQ(result[0], 0x80u);  // (128 & 0x7F) | 0x80
    EXPECT_EQ(result[1], 0x01u);  // 128 >> 7
    EXPECT_EQ(result[2], 0x78u);  // first data byte
    EXPECT_EQ(result.size(), 130u);  // 2 prefix + 128 data
}

// --- cpace_lv_cat ---

TEST(CPacePrimitives, LvCatHelloWorld) {
    // _lv_cat(b'hello', b'world') = b'\x05hello\x05world'
    const uint8_t* hello = reinterpret_cast<const uint8_t*>("hello");
    const uint8_t* world = reinterpret_cast<const uint8_t*>("world");
    auto result = cpace_lv_cat({{hello, 5}, {world, 5}});
    EXPECT_EQ(to_hex(result), "0568656c6c6f05776f726c64");
}

// --- cpace_generator_string ---

TEST(CPacePrimitives, GeneratorStringKat) {
    // _generator_string(b'1234', b'', b'test-session-id-1234567890123456')
    // Expected hex from Python reference.
    const uint8_t* prs = reinterpret_cast<const uint8_t*>("1234");
    const uint8_t* sid = reinterpret_cast<const uint8_t*>("test-session-id-1234567890123456");
    auto gs = cpace_generator_string(prs, 4, nullptr, 0, sid, 32);
    EXPECT_EQ(gs.size(), 162u);
    // Expected: from Python _generator_string(b'1234', b'', b'test-session-id-1234567890123456')
    // Structure: lv(DSI=8B) + lv(prs=4B) + lv(113 zero bytes) + lv(ci='') + lv(sid=32B)
    EXPECT_EQ(to_hex(gs),
        "0843506163653235350431323334710000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0020746573742d73657373696f6e2d69642d3132333435363738393031323334"
        "3536");
}

// --- cpace_decode_u ---

TEST(CPacePrimitives, DecodeUClearsTopBit) {
    // _decode_u(bytes(range(31)) + b'\xff') clears the top bit of byte 31.
    // Expected: same as range(32) with byte 31 having bit 7 cleared.
    // Input: 0x00 .. 0x1e 0xff; expected output: 0x00..0x1e 0x7f
    std::array<uint8_t, 32> src{};
    for (int i = 0; i < 31; ++i) src[i] = static_cast<uint8_t>(i);
    src[31] = 0xff;
    auto result = cpace_decode_u(src.data(), 32);
    EXPECT_EQ(result[31], 0x7fu);
    for (int i = 0; i < 31; ++i) {
        EXPECT_EQ(result[i], static_cast<uint8_t>(i));
    }
}

// --- cpace_elligator2 ---
// Expected values from Python: _elligator2(r_int)

TEST(CPacePrimitives, Elligator2ZeroInput) {
    // _elligator2(0) = b'\x00' * 32  (v = 0 when 1+Z*0=1, so -A/1=-A -> v = p-A)
    // But actually: v = -A * inv(1+0) = -A mod p; eps = legendre(-A^3 + A*A^2 - A + ...) ...
    // Reference says _elligator2(0) = b'\x00' * 32.
    std::array<uint8_t, 32> r{};  // r = 0
    auto result = cpace_elligator2(r);
    EXPECT_EQ(to_hex(result), "0000000000000000000000000000000000000000000000000000000000000000");
}

TEST(CPacePrimitives, Elligator2OneInput) {
    // _elligator2(1): expected from Python reference.
    std::array<uint8_t, 32> r{};
    r[0] = 1;  // r = 1 in little-endian
    auto result = cpace_elligator2(r);
    EXPECT_EQ(to_hex(result), "9cdb525555555555555555555555555555555555555555555555555555555555");
}

TEST(CPacePrimitives, Elligator2FixedInput) {
    // r_val = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    // r_le: efcdab9078563412efcdab9078563412efcdab9078563412efcdab9078563412
    // Expected from Python reference.
    auto r = from_hex_arr<32>("efcdab9078563412efcdab9078563412efcdab9078563412efcdab9078563412");
    auto result = cpace_elligator2(r);
    EXPECT_EQ(to_hex(result), "406682120bd67c0502cb7afed2849918c58c0bc36e1cbdbc2184d407f5a9db19");
}

TEST(CPacePrimitives, Elligator2FieldArithmeticStress) {
    // Extra vectors stressing field reduction/carry across varied bit patterns (all-ones,
    // alternating). The all-ones input exercises modular reduction of a value above p.
    // Expected outputs extracted from the Python reference _elligator2(int.from_bytes(x, 'little')).
    struct V {
        const char* in_le;
        const char* out;
    };
    const V vectors[] = {
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
         "6edfd66733be3f52309983805b9fcdf8fe48c1640e026e7d36e3fb2305933908"},
        {"dededededededededededededededededededededededededededededededede",
         "42d8f3889968f3caa814ca11b2bc880b35c9c0897f193a1aec578043a43e3948"},
        {"0102030405060708010203040506070801020304050607080102030405060708",
         "bde03792c4903abf825e98667c9d4c4945665581b0e2306ad19e10c564e04773"},
        {"aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55",
         "803fcc2dbcf575f784907707db8080a2657230a71c9caa4a87a57beccfdb323f"},
    };
    for (const auto& v : vectors) {
        auto r = from_hex_arr<32>(v.in_le);
        auto result = cpace_elligator2(r);
        EXPECT_EQ(to_hex(result), v.out) << "elligator2 mismatch for input " << v.in_le;
    }
}

// --- cpace_calculate_generator ---

TEST(CPacePrimitives, CalculateGeneratorKat) {
    // _calculate_generator(b'1234', b'', b'test-session-id-1234567890123456')
    // Expected from Python reference.
    const uint8_t* prs = reinterpret_cast<const uint8_t*>("1234");
    const uint8_t* sid = reinterpret_cast<const uint8_t*>("test-session-id-1234567890123456");
    auto gen = cpace_calculate_generator(prs, 4, nullptr, 0, sid, 32);
    EXPECT_EQ(to_hex(gen), "8fb13a51e2f4d62c9d5d6ae2390b41009cd26e6535d28248df9b5984a7a1de70");
}

// --- x25519_scalar_mult clamping KAT ---
// Proves our noise-c dhstate scalar mult matches the Python reference _scalar_mult,
// which uses X25519PrivateKey.from_private_bytes() (RFC 7748 clamped).

TEST(CPacePrimitives, X25519ScalarMultBasepoint) {
    // scalar = bytes(range(32)), point = X25519 basepoint (u=9)
    // Expected: same as Python _scalar_mult(bytes(range(32)), basepoint)
    // = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
    uint8_t scalar[32];
    for (int i = 0; i < 32; ++i) scalar[i] = static_cast<uint8_t>(i);
    uint8_t basepoint[32] = {9};  // u=9, rest zeros
    uint8_t out[32] = {};
    EXPECT_TRUE(x25519_scalar_mult(scalar, basepoint, out));
    EXPECT_EQ(to_hex(out, 32), "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
}

TEST(CPacePrimitives, X25519ScalarMultGenerator) {
    // scalar = 0x10*32, point = generator from prs='1234'/sid=test32
    // Ya = _scalar_mult(SCALAR_A, gen)
    // Expected: "57551a92c995ea9b792f4e89a18c34459491c1484deddbb1498c29b499286c0f"
    uint8_t scalar[32];
    std::memset(scalar, 0x10, 32);
    const uint8_t* prs = reinterpret_cast<const uint8_t*>("1234");
    const uint8_t* sid = reinterpret_cast<const uint8_t*>("test-session-id-1234567890123456");
    auto gen = cpace_calculate_generator(prs, 4, nullptr, 0, sid, 32);
    uint8_t out[32] = {};
    EXPECT_TRUE(x25519_scalar_mult(scalar, gen.data(), out));
    EXPECT_EQ(to_hex(out, 32), "57551a92c995ea9b792f4e89a18c34459491c1484deddbb1498c29b499286c0f");
}

// --- SHA-512 KAT ---

TEST(CPacePrimitives, Sha512OneshotKat) {
    // hashlib.sha512(b'').hexdigest()
    // = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    auto digest = sha512_oneshot(nullptr, 0);
    EXPECT_EQ(to_hex(digest),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

TEST(CPacePrimitives, HmacSha512Kat) {
    // hmac.new(b'\x0b' * 20, b'Hi There', hashlib.sha512).hexdigest()
    // RFC 4231 Test Case 1 adapted for SHA-512.
    // Expected from Python: hmac.new(key, data, hashlib.sha512).digest()
    std::array<uint8_t, 20> key{};
    std::fill(key.begin(), key.end(), 0x0Bu);
    const uint8_t* data = reinterpret_cast<const uint8_t*>("Hi There");
    auto mac = hmac_sha512(key.data(), key.size(), data, 8);
    // RFC 4231 test vector for HMAC-SHA-512, test case 1:
    EXPECT_EQ(to_hex(mac),
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd"
        "edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
}

// =============================================================================
// Full round-trip test - role A and role B with same PRS/sid
// =============================================================================

// Helper: run a complete A-B exchange with FIXED scalars by invoking the
// primitive functions directly (bypassing CPace::start's CSPRNG).
// This gives reproducible KAT values.

struct FixedExchange {
    // Fixed scalars (same as Python KAT).
    static constexpr uint8_t SCALAR_A[32] = {
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    };
    static constexpr uint8_t SCALAR_B[32] = {
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    };

    const uint8_t* prs = reinterpret_cast<const uint8_t*>("1234");
    const size_t prs_len = 4;
    const uint8_t* sid = reinterpret_cast<const uint8_t*>("test-session-id-1234567890123456");
    const size_t sid_len = 32;

    std::array<uint8_t, 32> gen{};
    std::array<uint8_t, 32> Ya{};
    std::array<uint8_t, 32> Yb{};
    std::array<uint8_t, 64> mac_key{};
    std::array<uint8_t, 64> Ta{};
    std::array<uint8_t, 64> Tb{};

    bool run() {
        gen = cpace_calculate_generator(prs, prs_len, nullptr, 0, sid, sid_len);
        if (!x25519_scalar_mult(SCALAR_A, gen.data(), Ya.data())) return false;
        if (!x25519_scalar_mult(SCALAR_B, gen.data(), Yb.data())) return false;

        // Shared secret (both sides compute the same value).
        std::array<uint8_t, 32> shared{};
        if (!x25519_scalar_mult(SCALAR_A, Yb.data(), shared.data())) return false;

        // Transcript: lv_cat(Ya, '') + lv_cat(Yb, '')
        auto t_a = cpace_lv_cat({{Ya.data(), 32}, {nullptr, 0}});
        auto t_b = cpace_lv_cat({{Yb.data(), 32}, {nullptr, 0}});

        // ISK = SHA512(lv_cat(DSI_ISK, sid, shared) + transcript)
        const auto* dsi_isk = reinterpret_cast<const uint8_t*>(CPACE_DSI_ISK);
        size_t dsi_isk_len = sizeof(CPACE_DSI_ISK) - 1;
        auto lv_prefix = cpace_lv_cat({
            {dsi_isk, dsi_isk_len},
            {sid, sid_len},
            {shared.data(), 32},
        });
        Sha512 h_isk;
        h_isk.update(lv_prefix.data(), lv_prefix.size());
        h_isk.update(t_a.data(), t_a.size());
        h_isk.update(t_b.data(), t_b.size());
        auto isk = h_isk.finalize();

        // mac_key = SHA512(MAC_LABEL + sid + ISK)
        const auto* mac_label = reinterpret_cast<const uint8_t*>(CPACE_MAC_LABEL);
        size_t mac_label_len = sizeof(CPACE_MAC_LABEL) - 1;
        Sha512 h_mac;
        h_mac.update(mac_label, mac_label_len);
        h_mac.update(sid, sid_len);
        h_mac.update(isk.data(), isk.size());
        mac_key = h_mac.finalize();

        // Ta = HMAC-SHA512(mac_key, lv_cat(Ya, ''))
        Ta = hmac_sha512(mac_key.data(), 64, t_a.data(), t_a.size());
        // Tb = HMAC-SHA512(mac_key, lv_cat(Yb, ''))
        Tb = hmac_sha512(mac_key.data(), 64, t_b.data(), t_b.size());
        return true;
    }
};

TEST(CPaceRoundTrip, FixedScalarIsKnownAnswers) {
    FixedExchange fx;
    ASSERT_TRUE(fx.run());

    // Ya, Yb (public shares)
    EXPECT_EQ(to_hex(fx.Ya), "57551a92c995ea9b792f4e89a18c34459491c1484deddbb1498c29b499286c0f");
    EXPECT_EQ(to_hex(fx.Yb), "a057a00be47920856f4ae0574971590e9fb0b5d97b89dba12237957dd8ec577f");

    // mac_key
    EXPECT_EQ(to_hex(fx.mac_key),
        "a1fd9e5cc9cbf898a9ebcd2d69b7fb9ed84c3524de3b6047c5dc06fb8cc81aa"
        "e0d0db10ae8d6d231fd2cae0783a60175a875f7cf294a2460278fce192742c8d1");

    // Ta
    EXPECT_EQ(to_hex(fx.Ta),
        "fe47abf1649b3f91ce6e3b38870ac3947a209a1dc1dab2c88db77791e9432426"
        "111e9555562a6f7a41a14079de95617f1396d82c8066f19c8aa486e7f70b8ef0");

    // Tb
    EXPECT_EQ(to_hex(fx.Tb),
        "806b304d1cc3f232ed45afd6d2dc7e08ffd69aeb57ca3c78de75c5d280024a6c"
        "263ec2c6da7414899a91d085b826d63ca320bf50f7b49d985a3db00c8c891e45");
}

// --- Full CPace object round-trip (CSPRNG scalars) ---

TEST(CPaceRoundTrip, MutualTagVerifySucceeds) {
    const std::vector<uint8_t> prs(reinterpret_cast<const uint8_t*>("pinpin"),
                                   reinterpret_cast<const uint8_t*>("pinpin") + 6);
    const std::vector<uint8_t> sid(32, 0xAA);
    const std::vector<uint8_t> ci, ad_a, ad_b;

    CPace side_a, side_b;
    ASSERT_TRUE(side_a.start(CPaceRole::INITIATOR, prs, sid, ci, ad_a, ad_b));
    ASSERT_TRUE(side_b.start(CPaceRole::RESPONDER, prs, sid, ci, ad_b, ad_a));

    // Exchange shares.
    ASSERT_TRUE(side_b.derive(side_a.public_share().data(), CPACE_SHARE_SIZE));
    ASSERT_TRUE(side_a.derive(side_b.public_share().data(), CPACE_SHARE_SIZE));

    auto tag_a = side_a.tag();
    auto tag_b = side_b.tag();
    ASSERT_TRUE(tag_a.has_value());
    ASSERT_TRUE(tag_b.has_value());

    // B verifies A's tag; A verifies B's tag.
    EXPECT_TRUE(side_b.verify(tag_a->data(), CPACE_TAG_SIZE));
    EXPECT_TRUE(side_a.verify(tag_b->data(), CPACE_TAG_SIZE));
}

TEST(CPaceRoundTrip, WrongPrsMakesTagsNotVerify) {
    const std::vector<uint8_t> prs_a(reinterpret_cast<const uint8_t*>("rightpin"),
                                     reinterpret_cast<const uint8_t*>("rightpin") + 8);
    const std::vector<uint8_t> prs_b(reinterpret_cast<const uint8_t*>("wrongpin"),
                                     reinterpret_cast<const uint8_t*>("wrongpin") + 8);
    const std::vector<uint8_t> sid(32, 0xBB);
    const std::vector<uint8_t> ci, ad;

    CPace side_a, side_b;
    ASSERT_TRUE(side_a.start(CPaceRole::INITIATOR, prs_a, sid, ci, ad, ad));
    ASSERT_TRUE(side_b.start(CPaceRole::RESPONDER, prs_b, sid, ci, ad, ad));

    ASSERT_TRUE(side_b.derive(side_a.public_share().data(), CPACE_SHARE_SIZE));
    ASSERT_TRUE(side_a.derive(side_b.public_share().data(), CPACE_SHARE_SIZE));

    auto tag_a = side_a.tag();
    auto tag_b = side_b.tag();
    ASSERT_TRUE(tag_a.has_value());
    ASSERT_TRUE(tag_b.has_value());

    // Tags should NOT verify because the PRS values differ.
    EXPECT_FALSE(side_b.verify(tag_a->data(), CPACE_TAG_SIZE));
    EXPECT_FALSE(side_a.verify(tag_b->data(), CPACE_TAG_SIZE));
}

TEST(CPaceRoundTrip, DeriveIsRejectedTwice) {
    // A second derive() must fail so the state machine cannot silently re-key.
    const std::vector<uint8_t> prs(reinterpret_cast<const uint8_t*>("pinpin"),
                                   reinterpret_cast<const uint8_t*>("pinpin") + 6);
    const std::vector<uint8_t> sid(32, 0xCC);
    const std::vector<uint8_t> ci, ad;

    CPace side_a, side_b;
    ASSERT_TRUE(side_a.start(CPaceRole::INITIATOR, prs, sid, ci, ad, ad));
    ASSERT_TRUE(side_b.start(CPaceRole::RESPONDER, prs, sid, ci, ad, ad));

    ASSERT_TRUE(side_a.derive(side_b.public_share().data(), CPACE_SHARE_SIZE));
    // Second call must be rejected.
    EXPECT_FALSE(side_a.derive(side_b.public_share().data(), CPACE_SHARE_SIZE));
}

// =============================================================================
// Low-order point rejection
// =============================================================================

TEST(CPaceDeriveRejects, AllZeroPeerShare) {
    const std::vector<uint8_t> prs(reinterpret_cast<const uint8_t*>("test"),
                                   reinterpret_cast<const uint8_t*>("test") + 4);
    const std::vector<uint8_t> sid(32, 0x01);
    const std::vector<uint8_t> ci, ad;

    CPace side;
    ASSERT_TRUE(side.start(CPaceRole::RESPONDER, prs, sid, ci, ad, ad));

    // All-zero share -> X25519 output is all-zero (low-order).
    // noise-c may return an error OR return zeros; either way derive() must reject.
    std::array<uint8_t, 32> zero_share{};
    EXPECT_FALSE(side.derive(zero_share.data(), 32));
}

TEST(CPaceDeriveRejects, WrongSizePeerShare) {
    const std::vector<uint8_t> prs(1, 0x01);
    const std::vector<uint8_t> sid(32, 0x01);
    const std::vector<uint8_t> ci, ad;

    CPace side;
    ASSERT_TRUE(side.start(CPaceRole::RESPONDER, prs, sid, ci, ad, ad));

    std::array<uint8_t, 16> short_share{};
    EXPECT_FALSE(side.derive(short_share.data(), 16));
}

TEST(CPaceDeriveRejects, TagBeforeDeriveReturnsNullopt) {
    const std::vector<uint8_t> prs(1, 0x01);
    const std::vector<uint8_t> sid(32, 0x01);
    const std::vector<uint8_t> ci, ad;

    CPace side;
    ASSERT_TRUE(side.start(CPaceRole::RESPONDER, prs, sid, ci, ad, ad));

    // tag() before derive() must return nullopt.
    EXPECT_FALSE(side.tag().has_value());
    // verify() before derive() must return false.
    std::array<uint8_t, CPACE_TAG_SIZE> dummy{};
    EXPECT_FALSE(side.verify(dummy.data(), CPACE_TAG_SIZE));
}

// =============================================================================
// ISK KAT via CPace object (verifies derive() produces the known ISK inputs)
// =============================================================================

// Note: the CPace class does not expose ISK or mac_key directly (internal).
// We verify them indirectly: the Tags produced by the CPace object must match
// the manually-computed Ta/Tb from the FixedExchange helper above.
// Since CPace.start() samples a fresh random scalar, we cannot directly reproduce
// the fixed-scalar KAT through the CPace object.  The FixedExchange test above
// covers the ISK+mac_key derivation path directly.

// =============================================================================
// SHA-512 streaming multi-part test
// =============================================================================

TEST(Sha512Streaming, MultiPartMatchesOneshot) {
    const uint8_t part1[] = {0x01, 0x02, 0x03};
    const uint8_t part2[] = {0x04, 0x05, 0x06};
    const uint8_t all[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    Sha512 h;
    h.update(part1, 3);
    h.update(part2, 3);
    auto streaming = h.finalize();

    auto oneshot = sha512_oneshot(all, 6);
    EXPECT_EQ(streaming, oneshot);
}
