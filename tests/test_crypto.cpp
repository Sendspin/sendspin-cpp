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

// Known-Answer Tests (KATs) for the Sendspin crypto foundation: the hash primitives, the spec
// constants, base64url, and Identity/psk_id derivation.
//
// These tests mirror the vectors from:
//   aiosendspin/tests/noise/test_constants.py
//   aiosendspin/tests/noise/test_keys.py

#include "crypto/constants.h"
#include "test_util.h"
#include "crypto/keys.h"
#include "platform/base64.h"
#include "platform/crypto.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

// =============================================================================
// SHA-512 / HMAC-SHA-512 KATs
//
// Validate the self-contained SHA-512 in platform/crypto.h against FIPS 180-4 and
// RFC 4231 known-answer vectors. These catch any transcription error in the round
// constants or padding, and cover the multi-block and streaming paths.
// =============================================================================

TEST(Sha512, EmptyString) {
    auto d = sha512_oneshot(reinterpret_cast<const uint8_t*>(""), 0);
    EXPECT_EQ(to_hex(d),
              "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
              "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

TEST(Sha512, Abc) {
    const char* m = "abc";
    auto d = sha512_oneshot(reinterpret_cast<const uint8_t*>(m), 3);
    EXPECT_EQ(to_hex(d),
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST(Sha512, TwoBlockNistVector) {
    // 112-byte input -> spans two 128-byte blocks after padding.
    const char* m =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    auto d = sha512_oneshot(reinterpret_cast<const uint8_t*>(m), std::strlen(m));
    EXPECT_EQ(to_hex(d),
              "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
              "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

TEST(Sha512, StreamingByteByByteMatchesOneShot) {
    std::vector<uint8_t> data(1000);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    auto one = sha512_oneshot(data.data(), data.size());
    Sha512 h;
    for (size_t i = 0; i < data.size(); ++i) {
        h.update(&data[i], 1);  // one byte at a time exercises every block boundary
    }
    EXPECT_EQ(to_hex(h.finalize()), to_hex(one));
}

TEST(HmacSha512, Rfc4231Case1) {
    std::vector<uint8_t> key(20, 0x0b);
    const char* data = "Hi There";
    auto mac = hmac_sha512(key.data(), key.size(), reinterpret_cast<const uint8_t*>(data),
                           std::strlen(data));
    EXPECT_EQ(to_hex(mac),
              "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
              "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
}

TEST(HmacSha512, Rfc4231Case2) {
    const char* key = "Jefe";
    const char* data = "what do ya want for nothing?";
    auto mac = hmac_sha512(reinterpret_cast<const uint8_t*>(key), std::strlen(key),
                           reinterpret_cast<const uint8_t*>(data), std::strlen(data));
    EXPECT_EQ(to_hex(mac),
              "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
              "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
}

// =============================================================================
// SHA-256 (Sha256 class / sha256_oneshot) KATs
//
// noise-c's SHA256 backend has no test hook to force an allocation/finalize failure, so the
// failure branch inside Sha256::ok() cannot be exercised here; the callers that must surface it
// (psk_id_for, derive_psk_wrap_key/wrap_psk/unwrap_psk, SENTINEL_PSK) are covered through their
// own std::optional-returning KATs in this file and test_psk_wrap.cpp.
// =============================================================================

TEST(Sha256, KatAbc) {
    // NIST FIPS 180-4 SHA-256("abc"), via both the one-shot helper and the streaming class.
    const char* m = "abc";
    const std::string expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    auto d = sha256_oneshot(reinterpret_cast<const uint8_t*>(m), std::strlen(m));
    EXPECT_EQ(to_hex(d), expected);

    Sha256 h;
    h.update(reinterpret_cast<const uint8_t*>(m), std::strlen(m));
    EXPECT_EQ(to_hex(h.finalize()), expected);
    EXPECT_TRUE(h.ok()) << "ok() must stay true across a normal update()/finalize() cycle";
}

// =============================================================================
// Constants KATs  (mirrors test_constants.py)
// =============================================================================

TEST(CryptoConstants, SentinelPskMatchesSpecHex) {
    // SENTINEL_PSK = SHA-256("sendspin-sentinel-psk-v1")
    // Spec hex: 1b5e24dbc1aed95fc2a5a338a90c05df44bd10f5ec1f4cd66cbf86272767b9d3
    EXPECT_EQ(to_hex(SENTINEL_PSK),
              "1b5e24dbc1aed95fc2a5a338a90c05df44bd10f5ec1f4cd66cbf86272767b9d3");
}

TEST(CryptoConstants, SentinelPskIdMatchesSpecConstant) {
    // psk_id_for(SENTINEL_PSK) must equal the spec's published identifier.
    EXPECT_EQ(SENTINEL_PSK_ID, "GFsV9tLaSQm9HcFWpKsgYQOr7wFTvNUtkmFwuVz3zoo");
}

TEST(CryptoConstants, PskIdLabelIsLiteralUtf8NoNul) {
    // PSK_ID_LABEL is "sendspin-psk-id-v1" with no NUL in the hash input.
    EXPECT_EQ(PSK_ID_LABEL, "sendspin-psk-id-v1");
    EXPECT_EQ(PSK_ID_LABEL.find('\0'), std::string_view::npos);
}

// =============================================================================
// Base64url KATs  (mirrors test_keys.py)
// =============================================================================

TEST(B64Url, RoundTrip) {
    std::array<uint8_t, 32> data{};
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(0xDE + i);
    }
    std::string encoded = b64url_encode(data.data(), data.size());
    auto decoded = b64url_decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->size(), data.size());
    EXPECT_EQ(std::memcmp(decoded->data(), data.data(), data.size()), 0);
}

// Every other test in this section either round-trips through our own decoder (which shares the
// encoder's table, so it agrees with itself under any permutation) or asserts that a character is
// absent. This one pins the encoded bytes: the input packs the 6-bit groups 0..63 in order, so
// the expected string walks the whole alphabet once and a single swapped table entry fails here.
TEST(B64Url, EncodeAlphabetKat) {
    const auto data = from_hex(
        "00108310518720928b30d38f41149351559761969b71d79f"
        "8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf");
    ASSERT_EQ(data.size(), 48u);
    EXPECT_EQ(b64url_encode(data.data(), data.size()),
              "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
}

TEST(B64Url, UsesUrlSafeAlphabet) {
    // bytes 0xFB 0xFF 0xBF encode to characters that exercise - and _ slots.
    std::array<uint8_t, 3> data{0xFB, 0xFF, 0xBF};
    std::string enc = b64url_encode(data.data(), data.size());
    EXPECT_EQ(enc.find('+'), std::string::npos) << "must not contain '+'";
    EXPECT_EQ(enc.find('/'), std::string::npos) << "must not contain '/'";
}

TEST(B64Url, EncodeStripsEqPadding) {
    // 1 byte → needs 2 padding chars in standard base64; b64url must strip them.
    std::array<uint8_t, 1> data{0x00};
    std::string enc = b64url_encode(data.data(), data.size());
    EXPECT_EQ(enc.find('='), std::string::npos) << "must not contain '='";
    EXPECT_EQ(enc.size(), 2u);  // ceil(8/6) = 2 base64 chars
}

TEST(B64Url, DecodeToleratesMissingPadding) {
    // "Zm9vYg" decodes to "foob" (4 bytes, input would need 2 '=' in standard base64)
    auto r1 = b64url_decode("Zm9vYg");
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(std::string(r1->begin(), r1->end()), "foob");

    // "Zm9vYmE" decodes to "fooba" (5 bytes, input needs 1 '=' in standard base64)
    auto r2 = b64url_decode("Zm9vYmE");
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(std::string(r2->begin(), r2->end()), "fooba");
}

TEST(B64Url, DecodeRejectsInvalidCharacter) {
    // '+' and '/' are not part of the URL-safe alphabet.
    EXPECT_FALSE(b64url_decode("Zm9v+g").has_value());
    EXPECT_FALSE(b64url_decode("Zm9v/g").has_value());
}

TEST(B64Url, DecodeRejectsEmbeddedWhitespace) {
    // platform_base64_decode's host implementation silently skips '\n'/'\r'/' ' rather than
    // rejecting them; b64url_decode must reject regardless of that platform-decoder laxity, so
    // accepted input does not silently diverge between host and ESP (mbedTLS rejects these
    // outright).
    EXPECT_FALSE(b64url_decode("Zm9v\nYg").has_value());
    EXPECT_FALSE(b64url_decode("Zm9v\rYg").has_value());
    EXPECT_FALSE(b64url_decode("Zm9v Yg").has_value());
}

// =============================================================================
// PSK-ID derivation KATs  (mirrors test_keys.py)
// =============================================================================

TEST(PskId, Is43CharsNoPadding) {
    std::array<uint8_t, NOISE_PSK_SIZE> all_zero{};
    std::string pid = psk_id_for(all_zero);
    EXPECT_EQ(pid.size(), PEER_ID_SIZE);
    EXPECT_EQ(pid.find('='), std::string::npos) << "must not contain '='";
}

TEST(PskId, RejectsNon32ByteInput) {
    // psk_id_for(ptr, len) overload returns nullopt for wrong sizes.
    std::array<uint8_t, 16> short_psk{};
    EXPECT_FALSE(psk_id_for(short_psk.data(), short_psk.size()).has_value());

    std::array<uint8_t, 64> long_psk{};
    EXPECT_FALSE(psk_id_for(long_psk.data(), long_psk.size()).has_value());
}

// =============================================================================
// Identity KATs  (mirrors test_keys.py)
// =============================================================================

TEST(Identity, GenerateShapes) {
    Identity id = Identity::generate().value();
    EXPECT_EQ(id.private_bytes.size(), 32u);
    EXPECT_EQ(id.public_bytes.size(), 32u);
    EXPECT_EQ(id.peer_id().size(), PEER_ID_SIZE);
    EXPECT_EQ(id.peer_id().find('='), std::string::npos);
}

TEST(Identity, FromPrivateBytesReproducesPubkeyAndPeerId) {
    Identity original = Identity::generate().value();
    Identity rehydrated = Identity::from_private_bytes(original.private_bytes).value();
    EXPECT_EQ(rehydrated.public_bytes, original.public_bytes);
    EXPECT_EQ(rehydrated.peer_id(), original.peer_id());
}

TEST(Identity, FromPrivateBytesRejectsWrongSize) {
    std::array<uint8_t, 16> short_key{};
    EXPECT_FALSE(Identity::from_private_bytes(short_key.data(), short_key.size()).has_value());
}

TEST(Identity, TwoGenerateCallsProduceDifferentKeys) {
    Identity a = Identity::generate().value();
    Identity b = Identity::generate().value();
    EXPECT_NE(a.private_bytes, b.private_bytes);
    EXPECT_NE(a.public_bytes, b.public_bytes);
}

TEST(Identity, PrivateB64uRoundTripsViaDecode) {
    Identity id = Identity::generate().value();
    auto decoded = b64url_decode(id.private_b64u());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->size(), 32u);
    EXPECT_EQ(std::memcmp(decoded->data(), id.private_bytes.data(), 32), 0);
}

// A generated Identity must never be the default-constructed (all-zero) value: generate() returns
// std::optional precisely so a failure surfaces as an empty optional rather than a zero keypair
// that would then be used as a real one. noise-c's DHState has no hook to force that failure, so
// only the success path is reachable from here.
TEST(Identity, GenerateIsNeverAllZero) {
    auto id = Identity::generate();
    ASSERT_TRUE(id.has_value());
    static const std::array<uint8_t, 32> kZero{};
    EXPECT_NE(id->private_bytes, kZero);
    EXPECT_NE(id->public_bytes, kZero);
}

// The full Noise_KKpsk2 handshake is not exercised here. A noise-c-as-both-sides run tests only
// that the vendored library agrees with itself; the handshake as this project drives it (our
// responder against a noise-c initiator, over a real socket) is covered by
// NoiseHandshakeLoopback/NoiseTransport in test_noise_transport.cpp and the fake-server suites in
// test_encrypted_lifecycle.cpp.
