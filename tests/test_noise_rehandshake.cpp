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

// In-band Noise re-handshake tests.
//
// These tests exercise the server-initiated re-handshake path where:
//   1. An initial KKpsk2 handshake completes (initiator + responder sessions).
//   2. The initiator (server) begins a re-handshake using prior_h as prologue.
//   3. The responder (run_rehandshake_msg1) processes msg1, emits msg2.
//   4. The initiator reads msg2 and splits, producing new sessions.
//   5. Verifies: new sessions work, new h != old h, old session cannot decrypt new traffic.
//
// Also covers the negative path: unknown psk_id in re-handshake msg1 aborts cleanly.
//
// The "server" (initiator) side uses raw noise-c.
// The "client" (responder) side uses run_rehandshake_msg1() from noise_handshake.h.

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "noise_handshake.h"
#include "noise_session.h"
#include "noise_test_helpers.h"
#include "platform/base64.h"
#include "platform/crypto.h"
#include "record_store.h"
#include "sendspin/config.h"

#include <gtest/gtest.h>

// noise-c is a C library
extern "C" {
#include <noise/protocol/buffer.h>
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/constants.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/handshakestate.h>
}

#include <ArduinoJson.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

// =============================================================================
// Helpers
// =============================================================================

// HsGuard, CipherPair, and build_initiator (the raw noise-c KKpsk2 initiator builder playing
// the "server" role) come from noise_test_helpers.h.

/// @brief Run one complete initial KKpsk2 loopback handshake (initiator + responder).
///
/// Returns: initiator cipher pair, responder NoiseSession, and server_id (public key).
struct InitialHandshakeResult {
    CipherPair initiator;
    std::unique_ptr<NoiseSession> responder_session;
    std::array<uint8_t, 32> responder_h{};  // handshake hash from the responder side
    std::array<uint8_t, 32> psk{};
    std::string psk_id;
    Identity client_id;
    Identity server_id;
};

static std::optional<InitialHandshakeResult> run_initial_handshake(const std::string& suite_name) {
    InitialHandshakeResult r;
    r.client_id = Identity::generate().value();
    r.server_id = Identity::generate().value();

    platform_random_bytes(r.psk.data(), r.psk.size());
    r.psk_id = psk_id_for(r.psk);

    RecordStore rs(nullptr);
    SendspinPairingRecord rec;
    rec.psk_id = r.psk_id;
    rec.psk = r.psk;
    rs.store_record(std::move(rec));

    // Run initial handshake via NoiseHandshake state machine
    NoiseHandshake nh(r.client_id, rs, suite_name);
    std::string client_init = nh.build_client_init();
    if (client_init.empty()) { return std::nullopt; }

    // Build server/init and derive prologue
    JsonDocument doc;
    doc["type"] = "server/init";
    doc["payload"]["server_id"] = r.server_id.peer_id();
    doc["payload"]["version"] = 1;
    std::string server_init_text;
    serializeJson(doc, server_init_text);
    std::string prologue_str = client_init + server_init_text;

    std::string captured_msg2;
    auto send_fn = [&captured_msg2](const std::string& text) -> bool {
        captured_msg2 = text;
        return true;
    };
    EXPECT_EQ(nh.on_text_frame(server_init_text, send_fn), HandshakeFrameResult::NEED_MORE);

    // Build initiator msg1
    const uint8_t* prologue = reinterpret_cast<const uint8_t*>(prologue_str.data());
    size_t prologue_len = prologue_str.size();
    NoiseHandshakeState* init_hs_raw =
        build_initiator(suite_name, r.server_id.private_bytes.data(),
                        r.server_id.public_bytes.data(), r.client_id.public_bytes.data(),
                        r.psk.data(), prologue, prologue_len);
    if (!init_hs_raw) { return std::nullopt; }
    HsGuard init_hs_guard(init_hs_raw);

    std::string msg1_text = build_msg1_envelope(init_hs_raw, r.psk_id);
    if (msg1_text.empty()) {
        return std::nullopt;
    }

    EXPECT_EQ(nh.on_text_frame(msg1_text, send_fn), HandshakeFrameResult::COMPLETE);
    if (captured_msg2.empty()) { return std::nullopt; }

    // Initiator reads msg2
    JsonDocument msg2_doc;
    EXPECT_FALSE(deserializeJson(msg2_doc, captured_msg2));
    const char* msg2_b64 = msg2_doc["payload"]["data"] | "";
    auto msg2_bytes_opt = b64url_decode(msg2_b64);
    if (!msg2_bytes_opt.has_value()) { return std::nullopt; }
    auto& msg2_bytes = *msg2_bytes_opt;

    std::vector<uint8_t> msg2_payload_buf(4096);
    NoiseBuffer msg2_in;
    noise_buffer_set_input(msg2_in, msg2_bytes.data(), msg2_bytes.size());
    NoiseBuffer msg2_payload_out;
    noise_buffer_set_output(msg2_payload_out, msg2_payload_buf.data(), msg2_payload_buf.size());
    if (noise_handshakestate_read_message(init_hs_raw, &msg2_in, &msg2_payload_out) !=
        NOISE_ERROR_NONE) {
        return std::nullopt;
    }

    if (noise_handshakestate_split(init_hs_raw, &r.initiator.send_cs, &r.initiator.recv_cs) !=
        NOISE_ERROR_NONE) {
        return std::nullopt;
    }

    auto outcome = nh.take_result();
    if (!outcome.has_value() || !outcome->session) { return std::nullopt; }
    r.responder_h = outcome->session->handshake_hash();
    r.responder_session = std::move(outcome->session);

    return r;
}

// raw_encrypt() / raw_decrypt() (from noise_test_helpers.h) encrypt/decrypt one frame with a raw
// noise-c cipher state.

// =============================================================================
// Re-handshake loopback helper
// =============================================================================

/// @brief Run a re-handshake on top of an already-split initial handshake.
///
/// The initiator (server) starts a new KKpsk2 with prologue = prior_h and a
/// (potentially different) PSK.  The responder calls run_rehandshake_msg1().
///
/// @param suite_name   Noise suite.
/// @param init         Completed initial handshake result (provides server/client keys).
/// @param rs           RecordStore available to the responder.
/// @param rehs_psk     PSK for the re-handshake.
/// @param rehs_psk_id  psk_id for the re-handshake.
/// @return New initiator cipher pair + new responder session on success, or nullopt.
struct RehandshakeResult {
    CipherPair initiator;
    std::unique_ptr<NoiseSession> responder_session;
    std::array<uint8_t, 32> new_h{};  // new handshake hash
};

static std::optional<RehandshakeResult> run_rehandshake(
    const std::string& suite_name, const InitialHandshakeResult& init, const RecordStore& rs,
    const std::array<uint8_t, NOISE_PSK_SIZE>& rehs_psk, const std::string& rehs_psk_id) {
    // Prologue = prior responder handshake hash h (32 bytes)
    const std::array<uint8_t, 32>& prior_h = init.responder_h;

    // Build the re-handshake initiator (server side) with prologue = prior_h
    NoiseHandshakeState* init_hs_raw =
        build_initiator(suite_name, init.server_id.private_bytes.data(),
                        init.server_id.public_bytes.data(), init.client_id.public_bytes.data(),
                        rehs_psk.data(), prior_h.data(), prior_h.size());
    if (!init_hs_raw) {
        ADD_FAILURE() << "build_initiator for re-handshake failed";
        return std::nullopt;
    }
    HsGuard init_hs_guard(init_hs_raw);

    // Initiator writes msg1 with psk_id payload, wrapped in a noise/handshake JSON envelope (as
    // decrypted by the transport layer).
    std::string msg1_json = build_msg1_envelope(init_hs_raw, rehs_psk_id);
    if (msg1_json.empty()) {
        ADD_FAILURE() << "initiator write_message (msg1) failed";
        return std::nullopt;
    }

    auto result = run_rehandshake_msg1(msg1_json, init.server_id.peer_id(), init.client_id, rs,
                                       suite_name, prior_h);
    if (!result.has_value()) {
        ADD_FAILURE() << "run_rehandshake_msg1 returned nullopt";
        return std::nullopt;
    }

    // msg2_text is already in the result: a noise/handshake JSON envelope wrapping msg2.
    // The initiator reads msg2 from it.
    JsonDocument msg2_doc;
    if (deserializeJson(msg2_doc, result->msg2_text)) {
        ADD_FAILURE() << "failed to parse msg2_text JSON";
        return std::nullopt;
    }
    const char* msg2_b64 = msg2_doc["payload"]["data"] | "";
    auto msg2_bytes_opt = b64url_decode(msg2_b64);
    if (!msg2_bytes_opt.has_value() || msg2_bytes_opt->empty()) {
        ADD_FAILURE() << "failed to decode msg2 bytes";
        return std::nullopt;
    }
    auto& msg2_bytes = *msg2_bytes_opt;

    std::vector<uint8_t> msg2_payload_buf(4096);
    NoiseBuffer msg2_in;
    noise_buffer_set_input(msg2_in, msg2_bytes.data(), msg2_bytes.size());
    NoiseBuffer msg2_payload_out;
    noise_buffer_set_output(msg2_payload_out, msg2_payload_buf.data(), msg2_payload_buf.size());
    if (noise_handshakestate_read_message(init_hs_raw, &msg2_in, &msg2_payload_out) !=
        NOISE_ERROR_NONE) {
        ADD_FAILURE() << "initiator read_message (msg2) failed";
        return std::nullopt;
    }

    std::string msg2_payload_str(reinterpret_cast<char*>(msg2_payload_buf.data()),
                                 msg2_payload_out.size);
    EXPECT_EQ(msg2_payload_str, "{}");

    RehandshakeResult rr;
    if (noise_handshakestate_split(init_hs_raw, &rr.initiator.send_cs,
                                   &rr.initiator.recv_cs) != NOISE_ERROR_NONE) {
        ADD_FAILURE() << "initiator split failed in re-handshake";
        return std::nullopt;
    }

    rr.new_h = result->session->handshake_hash();
    rr.responder_session = std::move(result->session);
    return rr;
}

// =============================================================================
// Tests
// =============================================================================

/// @brief Verify a round-trip through a session: initiator->responder and responder->initiator.
static void check_session_roundtrip(CipherPair& init_pair, NoiseSession& responder_session,
                                    const std::vector<uint8_t>& plaintext) {
    // Initiator -> Responder (initiator.send_cs, responder.decrypt)
    {
        auto ct = raw_encrypt(init_pair.send_cs, plaintext);
        ASSERT_FALSE(ct.empty());
        size_t pt_len = responder_session.decrypt(ct.data(), ct.size());
        ASSERT_GT(pt_len, 0u);
        ct.resize(pt_len);
        EXPECT_EQ(ct, plaintext) << "Initiator->Responder round-trip failed";
    }
    // Responder -> Initiator (responder.encrypt, initiator.recv_cs)
    {
        std::vector<uint8_t> buf(plaintext.size() + 16);
        std::copy(plaintext.begin(), plaintext.end(), buf.begin());
        size_t ct_len = responder_session.encrypt(buf.data(), plaintext.size(), buf.size());
        ASSERT_GT(ct_len, 0u);
        auto pt = raw_decrypt(init_pair.recv_cs, std::vector<uint8_t>(buf.begin(), buf.begin() + ct_len));
        ASSERT_FALSE(pt.empty());
        EXPECT_EQ(pt, plaintext) << "Responder->Initiator round-trip failed";
    }
}

// Helper to run both suites with a parameterized test body.
static void run_rehandshake_test(const std::string& suite_name) {
    // Step 1: Run the initial handshake.
    auto init_opt = run_initial_handshake(suite_name);
    ASSERT_TRUE(init_opt.has_value()) << "Initial handshake failed for suite " << suite_name;
    // Non-const: check_session_roundtrip() below encrypts/decrypts through init.initiator's
    // cipher states, which advances their internal nonce counters (a real mutation).
    InitialHandshakeResult& init = *init_opt;

    // Verify a transport message round-trips under the initial session.
    const std::vector<uint8_t> test_plaintext = {0x00, 'h', 'e', 'l', 'l', 'o'};
    check_session_roundtrip(init.initiator, *init.responder_session, test_plaintext);

    std::array<uint8_t, 32> old_h = init.responder_h;

    // Step 2: Prepare a re-handshake PSK (may reuse the same PSK or a new one).
    RecordStore rs(nullptr);
    SendspinPairingRecord rec;
    rec.psk_id = init.psk_id;
    rec.psk = init.psk;
    rs.store_record(std::move(rec));

    // Step 3: Run the re-handshake (same PSK, new session).
    auto rr_opt = run_rehandshake(suite_name, init, rs, init.psk, init.psk_id);
    ASSERT_TRUE(rr_opt.has_value()) << "Re-handshake failed for suite " << suite_name;
    RehandshakeResult& rr = *rr_opt;

    // (a) New sessions encrypt/decrypt correctly.
    check_session_roundtrip(rr.initiator, *rr.responder_session, test_plaintext);

    // (b) New h differs from old h.
    EXPECT_NE(rr.new_h, old_h)
        << "New handshake hash must differ from the prior one after re-handshake";

    // (c) A message encrypted under the OLD initiator send cipher does NOT decrypt under
    //     the NEW responder session.  Keys actually rotated.
    std::vector<uint8_t> old_ct = raw_encrypt(init.initiator.send_cs, test_plaintext);
    ASSERT_FALSE(old_ct.empty());
    size_t old_pt_len = rr.responder_session->decrypt(old_ct.data(), old_ct.size());
    EXPECT_EQ(old_pt_len, 0u)
        << "Old-session ciphertext must NOT decrypt under the new session (keys rotated)";
}

TEST(NoiseRehandshake, BasicRehandshake_ChaChaPoly) {
    run_rehandshake_test(std::string(NOISE_SUITE_CHACHAPOLY));
}

// Test: re-handshake with a DIFFERENT PSK (key rotation to a new long-term key).
TEST(NoiseRehandshake, RehandshakeWithDifferentPsk_ChaChaPoly) {
    const std::string suite = std::string(NOISE_SUITE_CHACHAPOLY);
    auto init_opt = run_initial_handshake(suite);
    ASSERT_TRUE(init_opt.has_value());
    const InitialHandshakeResult& init = *init_opt;

    // Generate a new PSK that differs from the initial one.
    std::array<uint8_t, NOISE_PSK_SIZE> new_psk{};
    platform_random_bytes(new_psk.data(), new_psk.size());
    std::string new_psk_id = psk_id_for(new_psk);

    RecordStore rs(nullptr);
    // Store BOTH the original PSK and the new PSK so the record store can resolve either.
    {
        SendspinPairingRecord rec;
        rec.psk_id = init.psk_id;
        rec.psk = init.psk;
        rs.store_record(std::move(rec));
    }
    {
        SendspinPairingRecord rec2;
        rec2.psk_id = new_psk_id;
        rec2.psk = new_psk;
        rs.store_record(std::move(rec2));
    }

    auto rr_opt = run_rehandshake(suite, init, rs, new_psk, new_psk_id);
    ASSERT_TRUE(rr_opt.has_value()) << "Re-handshake with different PSK failed";

    // New session must work.
    const std::vector<uint8_t> pt = {0x00, 't', 'e', 's', 't'};
    check_session_roundtrip(rr_opt->initiator, *rr_opt->responder_session, pt);

    EXPECT_NE(rr_opt->new_h, init.responder_h);
}

// Negative test: re-handshake msg1 with a psk_id that resolves to no record aborts cleanly.
TEST(NoiseRehandshake, UnknownPskIdAborts) {
    const std::string suite = std::string(NOISE_SUITE_CHACHAPOLY);
    auto init_opt = run_initial_handshake(suite);
    ASSERT_TRUE(init_opt.has_value());
    const InitialHandshakeResult& init = *init_opt;

    // Record store has NO records for the PSK that the initiator will advertise.
    RecordStore empty_rs(nullptr);

    // Generate a PSK not in empty_rs.
    std::array<uint8_t, NOISE_PSK_SIZE> unknown_psk{};
    platform_random_bytes(unknown_psk.data(), unknown_psk.size());
    std::string unknown_psk_id = psk_id_for(unknown_psk);

    const std::array<uint8_t, 32>& prior_h = init.responder_h;

    // Build the re-handshake initiator and write msg1.
    NoiseHandshakeState* init_hs_raw =
        build_initiator(suite, init.server_id.private_bytes.data(),
                        init.server_id.public_bytes.data(), init.client_id.public_bytes.data(),
                        unknown_psk.data(), prior_h.data(), prior_h.size());
    ASSERT_NE(init_hs_raw, nullptr);
    HsGuard guard(init_hs_raw);

    std::string msg1_json = build_msg1_envelope(init_hs_raw, unknown_psk_id);
    ASSERT_FALSE(msg1_json.empty());

    // run_rehandshake_msg1 must return nullopt (unknown psk_id).
    auto result = run_rehandshake_msg1(msg1_json, init.server_id.peer_id(), init.client_id,
                                       empty_rs, suite, prior_h);
    EXPECT_FALSE(result.has_value())
        << "run_rehandshake_msg1 should fail with an unknown psk_id";
}
