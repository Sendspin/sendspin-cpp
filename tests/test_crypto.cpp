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

// Known-Answer Tests (KATs) for the Sendspin crypto foundation.
//
// These tests mirror the vectors from:
//   aiosendspin/tests/noise/test_constants.py
//   aiosendspin/tests/noise/test_keys.py
//
// and add an in-process KKpsk2 handshake for both cipher suites.

#include "crypto/constants.h"
#include "test_util.h"
#include "crypto/keys.h"
#include "platform/base64.h"
#include "platform/crypto.h"

#include <gtest/gtest.h>

// noise-c is a C library; wrap in extern "C" to avoid name-mangling issues.
extern "C" {
#include <noise/protocol/buffer.h>
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/constants.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/handshakestate.h>
}

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local convenience

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
// SHA-256 (Sha256 class / sha256_oneshot) KATs and failure-propagation contract
//
// noise-c's SHA256 backend has no test hook to force an allocation/finalize failure, so the
// actual "hash primitive fails" branch inside Sha256::ok() (crypto.h) cannot be exercised
// directly from a unit test. What *is* testable, and what these cover, is the contract that
// depends on it: every security-critical caller (psk_id_for, derive_psk_wrap_key/wrap_psk/
// unwrap_psk, SENTINEL_PSK) must surface failure through std::optional (or abort(), for the
// two call sites -- psk_id_for(array) and the SENTINEL_PSK static initializer -- whose
// established non-optional signatures are depended on elsewhere in the tree) rather than ever
// returning a zero-derived value as if it were valid. The tests below pin the normal
// (succeeding) path so a regression that silently drops one of these checks -- e.g. reverting
// to computing a digest without consulting ok() -- would still be caught by a KAT mismatch or
// a has_value()/ok() assertion failing to hold for the property it documents.
// =============================================================================

TEST(Sha256, KatAbc) {
    // NIST FIPS 180-4 SHA-256("abc").
    const char* m = "abc";
    auto d = sha256_oneshot(reinterpret_cast<const uint8_t*>(m), std::strlen(m));
    EXPECT_EQ(to_hex(d), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256, ClassOkAfterConstructionAndFinalize) {
    // Documents the ok() contract: ok() must stay true through a normal update()/finalize()
    // cycle so callers that check it after finalize() (e.g. psk_id_for, derive_psk_wrap_key,
    // the SENTINEL_PSK static initializer) accept the digest.
    Sha256 h;
    ASSERT_TRUE(h.ok());
    const char* m = "abc";
    h.update(reinterpret_cast<const uint8_t*>(m), std::strlen(m));
    auto digest = h.finalize();
    EXPECT_TRUE(h.ok());
    EXPECT_EQ(to_hex(digest), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
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

TEST(CryptoConstants, NoisePskSizeIs32) {
    EXPECT_EQ(NOISE_PSK_SIZE, 32u);
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

// -----------------------------------------------------------------------------
// Failure-propagation contract: generate()/from_private_bytes() must return
// std::optional and must never let a caller observe a default-constructed (all-zero) Identity
// as if it were a real keypair. noise-c's DHState has no test hook to force the underlying
// allocation/keypair-generation failure deterministically, so the actual failure branch cannot
// be exercised here; what these pin is the contract surface -- optional-returning signatures,
// and that a successfully generated/reconstructed Identity is never the zero value a silent
// failure used to produce.
// -----------------------------------------------------------------------------

TEST(Identity, GenerateSucceedsUnderNormalConditionsAndIsNeverAllZero) {
    auto id = Identity::generate();
    ASSERT_TRUE(id.has_value());
    static const std::array<uint8_t, 32> kZero{};
    EXPECT_NE(id->private_bytes, kZero);
    EXPECT_NE(id->public_bytes, kZero);
}

TEST(Identity, FromPrivateBytesArrayOverloadReturnsEngagedOptional) {
    // The array overload used to return a bare Identity (with an internal .value() that could
    // never legitimately fail per its own comment); it now forwards the pointer/length
    // overload's std::optional so a real DH-state failure would propagate instead of being
    // masked. Confirm the normal path still succeeds and reproduces the same keypair.
    auto original = Identity::generate();
    ASSERT_TRUE(original.has_value());
    auto rehydrated = Identity::from_private_bytes(original->private_bytes);
    ASSERT_TRUE(rehydrated.has_value());
    EXPECT_EQ(rehydrated->public_bytes, original->public_bytes);
}

// =============================================================================
// In-process KKpsk2 handshake KATs
//
// Run the full Noise_KKpsk2 handshake with noise-c acting as both initiator
// and responder.  After split(), verify that:
//   - initiator→responder traffic decrypts correctly
//   - responder→initiator traffic decrypts correctly
// Both cipher suites must pass.
// =============================================================================

namespace {

/// Run a complete in-process KKpsk2 handshake for the given suite name.
/// Returns true if the handshake completes and both transport directions work.
bool run_kkpsk2_handshake(const char* suite_name) {
    // Generate static keypairs for initiator and responder.
    Identity init_id = Identity::generate().value();
    Identity resp_id = Identity::generate().value();

    // PSK shared between both sides.
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());

    // -------------------------------------------------------------------------
    // Create handshake states
    // -------------------------------------------------------------------------
    NoiseHandshakeState* initiator = nullptr;
    NoiseHandshakeState* responder = nullptr;

    if (noise_handshakestate_new_by_name(&initiator, suite_name, NOISE_ROLE_INITIATOR) !=
        NOISE_ERROR_NONE) {
        return false;
    }
    if (noise_handshakestate_new_by_name(&responder, suite_name, NOISE_ROLE_RESPONDER) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        return false;
    }

    // -------------------------------------------------------------------------
    // Set local static keypairs
    // -------------------------------------------------------------------------
    NoiseDHState* init_local = noise_handshakestate_get_local_keypair_dh(initiator);
    NoiseDHState* resp_local = noise_handshakestate_get_local_keypair_dh(responder);

    if (noise_dhstate_set_keypair(init_local, init_id.private_bytes.data(), X25519_KEY_SIZE,
                                  init_id.public_bytes.data(), X25519_KEY_SIZE) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    if (noise_dhstate_set_keypair(resp_local, resp_id.private_bytes.data(), X25519_KEY_SIZE,
                                  resp_id.public_bytes.data(), X25519_KEY_SIZE) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }

    // -------------------------------------------------------------------------
    // Set remote static public keys (KK pattern - both sides know each other's key)
    // -------------------------------------------------------------------------
    NoiseDHState* init_remote = noise_handshakestate_get_remote_public_key_dh(initiator);
    NoiseDHState* resp_remote = noise_handshakestate_get_remote_public_key_dh(responder);

    if (noise_dhstate_set_public_key(init_remote, resp_id.public_bytes.data(), X25519_KEY_SIZE) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    if (noise_dhstate_set_public_key(resp_remote, init_id.public_bytes.data(), X25519_KEY_SIZE) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }

    // -------------------------------------------------------------------------
    // Set PSK (psk2 → mixed on msg2)
    // -------------------------------------------------------------------------
    if (noise_handshakestate_set_pre_shared_key(initiator, psk.data(), psk.size()) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    if (noise_handshakestate_set_pre_shared_key(responder, psk.data(), psk.size()) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }

    // -------------------------------------------------------------------------
    // Start
    // -------------------------------------------------------------------------
    if (noise_handshakestate_start(initiator) != NOISE_ERROR_NONE ||
        noise_handshakestate_start(responder) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }

    // -------------------------------------------------------------------------
    // Handshake message exchange
    // KKpsk2 has two messages: initiator→responder (msg1), responder→initiator (msg2).
    // -------------------------------------------------------------------------
    constexpr size_t BUF_SIZE = 4096;
    std::vector<uint8_t> msg_buf(BUF_SIZE);
    NoiseBuffer msg;

    // msg1: initiator writes
    if (noise_handshakestate_get_action(initiator) != NOISE_ACTION_WRITE_MESSAGE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    noise_buffer_set_output(msg, msg_buf.data(), msg_buf.size());
    // Pass nullptr for payload - these handshake messages carry no application payload.
    if (noise_handshakestate_write_message(initiator, &msg, nullptr) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    size_t msg1_size = msg.size;

    // msg1: responder reads
    if (noise_handshakestate_get_action(responder) != NOISE_ACTION_READ_MESSAGE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    noise_buffer_set_input(msg, msg_buf.data(), msg1_size);
    if (noise_handshakestate_read_message(responder, &msg, nullptr) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }

    // msg2: responder writes
    if (noise_handshakestate_get_action(responder) != NOISE_ACTION_WRITE_MESSAGE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    noise_buffer_set_output(msg, msg_buf.data(), msg_buf.size());
    if (noise_handshakestate_write_message(responder, &msg, nullptr) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    size_t msg2_size = msg.size;

    // msg2: initiator reads
    if (noise_handshakestate_get_action(initiator) != NOISE_ACTION_READ_MESSAGE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }
    noise_buffer_set_input(msg, msg_buf.data(), msg2_size);
    if (noise_handshakestate_read_message(initiator, &msg, nullptr) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }

    // Both sides should now report SPLIT.
    if (noise_handshakestate_get_action(initiator) != NOISE_ACTION_SPLIT ||
        noise_handshakestate_get_action(responder) != NOISE_ACTION_SPLIT) {
        noise_handshakestate_free(initiator);
        noise_handshakestate_free(responder);
        return false;
    }

    // -------------------------------------------------------------------------
    // Split into transport cipher states
    // After split():
    //   - initiator_send  encrypts initiator→responder traffic
    //   - initiator_recv  decrypts responder→initiator traffic
    //   - responder_send  encrypts responder→initiator traffic
    //   - responder_recv  decrypts initiator→responder traffic
    // -------------------------------------------------------------------------
    NoiseCipherState* init_send = nullptr;
    NoiseCipherState* init_recv = nullptr;
    NoiseCipherState* resp_send = nullptr;
    NoiseCipherState* resp_recv = nullptr;

    bool ok = (noise_handshakestate_split(initiator, &init_send, &init_recv) == NOISE_ERROR_NONE);
    ok = ok &&
         (noise_handshakestate_split(responder, &resp_send, &resp_recv) == NOISE_ERROR_NONE);

    noise_handshakestate_free(initiator);
    noise_handshakestate_free(responder);

    if (!ok) {
        if (init_send) noise_cipherstate_free(init_send);
        if (init_recv) noise_cipherstate_free(init_recv);
        if (resp_send) noise_cipherstate_free(resp_send);
        if (resp_recv) noise_cipherstate_free(resp_recv);
        return false;
    }

    // -------------------------------------------------------------------------
    // Transport verification: initiator→responder direction
    // -------------------------------------------------------------------------
    std::vector<uint8_t> plaintext_a = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    constexpr size_t MAC_LEN = 16;
    std::vector<uint8_t> ciphertext_buf(plaintext_a.size() + MAC_LEN);
    std::memcpy(ciphertext_buf.data(), plaintext_a.data(), plaintext_a.size());

    NoiseBuffer ct_buf;
    noise_buffer_set_inout(ct_buf, ciphertext_buf.data(), plaintext_a.size(),
                           ciphertext_buf.size());
    ok = (noise_cipherstate_encrypt(init_send, &ct_buf) == NOISE_ERROR_NONE);

    if (ok) {
        noise_buffer_set_inout(ct_buf, ciphertext_buf.data(), ct_buf.size, ct_buf.size);
        ok = (noise_cipherstate_decrypt(resp_recv, &ct_buf) == NOISE_ERROR_NONE);
        if (ok) {
            ok = (ct_buf.size == plaintext_a.size()) &&
                 (std::memcmp(ct_buf.data, plaintext_a.data(), ct_buf.size) == 0);
        }
    }

    // -------------------------------------------------------------------------
    // Transport verification: responder→initiator direction
    // -------------------------------------------------------------------------
    if (ok) {
        std::vector<uint8_t> plaintext_b = {0x57, 0x6F, 0x72, 0x6C, 0x64};  // "World"
        std::vector<uint8_t> ct_buf_b(plaintext_b.size() + MAC_LEN);
        std::memcpy(ct_buf_b.data(), plaintext_b.data(), plaintext_b.size());

        NoiseBuffer ct_b;
        noise_buffer_set_inout(ct_b, ct_buf_b.data(), plaintext_b.size(), ct_buf_b.size());
        ok = (noise_cipherstate_encrypt(resp_send, &ct_b) == NOISE_ERROR_NONE);

        if (ok) {
            noise_buffer_set_inout(ct_b, ct_buf_b.data(), ct_b.size, ct_b.size);
            ok = (noise_cipherstate_decrypt(init_recv, &ct_b) == NOISE_ERROR_NONE);
            if (ok) {
                ok = (ct_b.size == plaintext_b.size()) &&
                     (std::memcmp(ct_b.data, plaintext_b.data(), ct_b.size) == 0);
            }
        }
    }

    noise_cipherstate_free(init_send);
    noise_cipherstate_free(init_recv);
    noise_cipherstate_free(resp_send);
    noise_cipherstate_free(resp_recv);
    return ok;
}

}  // namespace

TEST(NoiseHandshake, KKpsk2ChaChaPoly) {
    EXPECT_TRUE(run_kkpsk2_handshake(std::string(NOISE_SUITE_CHACHAPOLY).c_str()));
}

TEST(NoiseHandshake, KKpsk2AesGcm) {
    EXPECT_TRUE(run_kkpsk2_handshake(std::string(NOISE_SUITE_AESGCM).c_str()));
}
