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

// Noise transport KATs: in-process loopback tests exercising:
//   - NoiseHandshake state machine (Sendspin client = Noise responder)
//   - NoiseSession (deferred PSK binding: msg1 read before the PSK is known)
//   - SendspinConnection transport helpers (encrypt/fragment/dispatch)
//
// The "server" side uses raw noise-c as the Noise initiator.
// The client proposes only Noise_KKpsk2_25519_ChaChaPoly_SHA256 (see NOISE_SUITE_CHACHAPOLY
// in crypto/constants.h), so that is the only suite exercised here.

#include "connection.h"
#include "crypto/constants.h"
#include "inbound_ring.h"
#include "inbound_test_helpers.h"
#include "crypto/keys.h"
#include "noise_handshake.h"
#include "noise_session.h"
#include "noise_test_helpers.h"
#include "platform/base64.h"
#include "platform/crypto.h"
#include "platform/time.h"
#include "platform/types.h"
#include "protocol_task.h"
#include "record_store.h"
#include "record_test_helpers.h"
#include "sendspin/config.h"
#include "sendspin/types.h"
#include "time_burst.h"
#include "test_util.h"

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
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

// ============================================================================
// Minimal in-process SendspinConnection for testing transport helpers
// ============================================================================

/// @brief Concrete SendspinConnection that captures sent binary frames.
/// Used to verify encrypt_and_send_frame / fragment_and_send output without a real WS socket.
class TestConnection : public SendspinConnection {
public:
    TestConnection() = default;
    ~TestConnection() override = default;

    // --- Interface stubs ---

    void start() override {}
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override {
        disconnect_calls_.push_back(reason);
        if (on_complete) {
            on_complete();
        }
    }
    void close_transport_now() override {
        this->close_transport_now_calls_++;
    }
    bool is_connected() const override { return true; }

    SsErr send_text_message(const std::string& msg, SendCompleteCallback cb) override {
        sent_text_.push_back(msg);
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }

    SsErr send_binary_message(const uint8_t* data, size_t len, SendCompleteCallback cb) override {
        sent_binary_.push_back(std::vector<uint8_t>(data, data + len));
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }

    // The transport side of the receive path, which a concrete transport reaches as a subclass.
    using SendspinConnection::abandon_inbound_message;
    using SendspinConnection::begin_inbound_message;
    using SendspinConnection::begin_inbound_fragment;
    using SendspinConnection::end_inbound_fragment;
    using SendspinConnection::end_inbound_message;
    using SendspinConnection::InboundRoute;
    using SendspinConnection::InboundTarget;

    // --- Test helpers ---

    /// Inject one complete binary WS message into the receive path the protocol task runs,
    /// bypassing the transport. The test thread plays the protocol task: the message lives in a
    /// buffer this connection owns rather than a ring item.
    void inject_binary_payload(const uint8_t* data, size_t len, int64_t receive_time = 0) {
        this->inject(data, len, InboundKind::BINARY, receive_time);
    }

    /// Inject one complete TEXT WS message the same way. Used to drive the pre-transport Noise
    /// handshake (client/init, server/init, noise/handshake) as a real TEXT frame would.
    void inject_text_payload(const std::string& text, int64_t receive_time = 0) {
        this->inject(reinterpret_cast<const uint8_t*>(text.data()), text.size(), InboundKind::TEXT,
                     receive_time);
    }

    void inject(const uint8_t* data, size_t len, InboundKind kind, int64_t receive_time) {
        this->inject_buf_.assign(data, data + len);
        InboundMessage message;
        message.data = this->inject_buf_.data();
        message.len = len;
        message.receive_time_us = static_cast<uint32_t>(receive_time);
        message.kind = kind;
        this->process_inbound_message(message);
    }

    /// Install a noise session directly (bypasses handshake, for transport-only tests).
    void set_noise_session(std::unique_ptr<NoiseSession> session) {
        this->noise_transport_.activate(std::move(session));
        this->noise_handshake_complete_ = true;
    }

    /// Direct access to NoiseTransport::send_binary() for tests exercising the binary send
    /// path (there is no connection-level wrapper; production code has no client-to-server
    /// binary message today).
    SsErr test_send_binary(const uint8_t* data, size_t len) {
        return this->noise_transport_.send_binary(data, len);
    }

    // Accumulated outgoing messages
    std::vector<std::string> sent_text_;
    std::vector<std::vector<uint8_t>> sent_binary_;
    // Backing store for the injected message, which the receive path decrypts in place.
    std::vector<uint8_t> inject_buf_;

    // Reasons passed to disconnect(), in call order.
    std::vector<SendspinGoodbyeReason> disconnect_calls_;

    // Number of times close_transport_now() was invoked (the silent-close path; see
    // close_silently(), which calls this instead of disconnect() so it never blocks on or joins
    // a transport thread from the protocol task it runs on).
    int close_transport_now_calls_{0};
};

// ============================================================================
// Helpers shared by handshake tests
// ============================================================================

/// Build and return `server/init` JSON for the given server_id and version. `type` is a
/// parameter so a test can send the same payload under another envelope type.
static std::string make_server_init(const std::string& server_id, int version = 1,
                                    const char* type = "server/init") {
    JsonDocument doc;
    doc["type"] = type;
    doc["payload"]["server_id"] = server_id;
    doc["payload"]["version"] = version;
    std::string out;
    serializeJson(doc, out);
    return out;
}

/// Build and return a `noise/handshake` JSON envelope wrapping raw Noise bytes.
static std::string make_noise_handshake_envelope(const std::vector<uint8_t>& raw) {
    std::string encoded = b64url_encode(raw.data(), raw.size());
    JsonDocument doc;
    doc["type"] = "noise/handshake";
    doc["payload"]["data"] = encoded;
    std::string out;
    serializeJson(doc, out);
    return out;
}

/// Decode the `payload.data` base64url field from a `noise/handshake` JSON string.
static std::optional<std::vector<uint8_t>> extract_noise_bytes(const std::string& json) {
    JsonDocument doc;
    if (deserializeJson(doc, json)) {
        return std::nullopt;
    }
    const char* data_b64 = doc["payload"]["data"] | "";
    if (data_b64[0] == '\0') {
        return std::nullopt;
    }
    return b64url_decode(data_b64);
}

// HsGuard, CipherPair, and build_initiator (the raw noise-c KKpsk2 initiator builder playing
// the "server" role) come from noise_test_helpers.h.

// ============================================================================
// Full handshake loopback helper
// ============================================================================

/// @brief Run a complete Noise KKpsk2 loopback handshake for one cipher suite.
///
/// The "server" side is noise-c as initiator.
/// The "client" side is our NoiseHandshake/NoiseSession as responder.
///
/// Returns the initiator cipher pair after split (for transport tests), or nullptr on failure.
struct LoopbackResult {
    CipherPair initiator;
    std::unique_ptr<NoiseSession> responder_session;

    LoopbackResult() = default;
    LoopbackResult(LoopbackResult&&) = default;
    LoopbackResult& operator=(LoopbackResult&&) = default;
    LoopbackResult(const LoopbackResult&) = delete;
    LoopbackResult& operator=(const LoopbackResult&) = delete;
};

static std::optional<LoopbackResult> run_loopback_handshake(const std::string& suite_name) {
    Identity client_id = Identity::generate().value();  // Noise responder
    Identity server_id = Identity::generate().value();  // Noise initiator

    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    // Build a RecordStore holding the PSK, bound to the server identity the handshake reaches.
    RecordStore rs(nullptr);
    SendspinPairingRecord rec;
    rec.psk_id = psk_id;
    rec.psk = psk;
    rec.server_id = server_id.peer_id();
    rs.store_record_superseding(std::move(rec), {});

    // -----------------------------------------------------------------
    // Create the NoiseHandshake (our responder driver)
    // -----------------------------------------------------------------
    TestArena arena;
    NoiseHandshake nh(client_id, rs, suite_name, arena);

    // Step 1: client sends client/init
    std::string client_init = nh.build_client_init();
    EXPECT_FALSE(client_init.empty());

    // Verify client/init JSON format
    {
        JsonDocument doc;
        EXPECT_FALSE(deserializeJson(doc, client_init));
        EXPECT_STREQ(doc["type"] | "", "client/init");
        EXPECT_EQ(doc["payload"]["version"] | 0, 1);
        // Wire suite = suffix after "Noise_KKpsk2_"
        static constexpr const char* PREFIX = "Noise_KKpsk2_";
        std::string expected_suite = suite_name;
        if (expected_suite.size() > 13 && expected_suite.substr(0, 13) == PREFIX) {
            expected_suite = expected_suite.substr(13);
        }
        EXPECT_EQ(std::string(doc["payload"]["suite"] | ""), expected_suite);
    }

    // -----------------------------------------------------------------
    // Step 2: server sends server/init
    // Prologue = client_init bytes || server_init bytes (exact bytes, no re-serialization)
    // -----------------------------------------------------------------
    std::string server_init_text = make_server_init(server_id.peer_id());
    std::string prologue_str = client_init + server_init_text;
    const uint8_t* prologue = reinterpret_cast<const uint8_t*>(prologue_str.data());
    size_t prologue_len = prologue_str.size();

    // Our driver processes server/init
    std::string captured_msg2;
    auto send_fn = [&captured_msg2](const std::string& text) -> bool {
        captured_msg2 = text;
        return true;
    };

    HandshakeFrameResult r1 = nh.on_text_frame(server_init_text, send_fn);
    EXPECT_EQ(r1, HandshakeFrameResult::NEED_MORE);
    EXPECT_TRUE(captured_msg2.empty());  // No msg2 yet

    // -----------------------------------------------------------------
    // Step 3: server (noise-c initiator) writes msg1
    // Msg1 plaintext payload: {"psk_id":"..."}
    // -----------------------------------------------------------------
    NoiseHandshakeState* init_hs_raw =
        build_initiator(suite_name, server_id.private_bytes.data(),
                           server_id.public_bytes.data(), client_id.public_bytes.data(), psk.data(),
                           prologue, prologue_len);
    if (init_hs_raw == nullptr) {
        ADD_FAILURE() << "build_initiator failed for suite " << suite_name;
        return std::nullopt;
    }
    HsGuard init_hs_guard(init_hs_raw);

    EXPECT_EQ(noise_handshakestate_get_action(init_hs_raw), NOISE_ACTION_WRITE_MESSAGE);

    // Build msg1 payload: {"psk_id":"..."}
    std::string msg1_text = build_msg1_envelope(init_hs_raw, psk_id);
    EXPECT_FALSE(msg1_text.empty());

    // -----------------------------------------------------------------
    // Step 4: our driver processes msg1
    // on_text_frame should: decrypt msg1, resolve PSK, write msg2, return COMPLETE
    // -----------------------------------------------------------------
    HandshakeFrameResult r2 = nh.on_text_frame(msg1_text, send_fn);
    EXPECT_EQ(r2, HandshakeFrameResult::COMPLETE);
    EXPECT_FALSE(captured_msg2.empty()) << "Expected msg2 to be sent";

    // -----------------------------------------------------------------
    // Step 5: server (noise-c initiator) reads msg2
    // -----------------------------------------------------------------
    auto msg2_bytes = extract_noise_bytes(captured_msg2);
    EXPECT_TRUE(msg2_bytes.has_value()) << "Failed to extract noise bytes from msg2";
    if (!msg2_bytes.has_value()) {
        return std::nullopt;
    }

    EXPECT_EQ(noise_handshakestate_get_action(init_hs_raw), NOISE_ACTION_READ_MESSAGE);

    std::vector<uint8_t> msg2_payload_buf(4096);
    NoiseBuffer msg2_in;
    noise_buffer_set_input(msg2_in, msg2_bytes->data(), msg2_bytes->size());
    NoiseBuffer msg2_payload_out;
    noise_buffer_set_output(msg2_payload_out, msg2_payload_buf.data(), msg2_payload_buf.size());

    EXPECT_EQ(noise_handshakestate_read_message(init_hs_raw, &msg2_in, &msg2_payload_out),
              NOISE_ERROR_NONE);

    // Verify msg2 plaintext payload is `{}`
    std::string msg2_payload_str(reinterpret_cast<char*>(msg2_payload_buf.data()),
                                 msg2_payload_out.size);
    EXPECT_EQ(msg2_payload_str, "{}");

    // Both sides should be ready to split
    EXPECT_EQ(noise_handshakestate_get_action(init_hs_raw), NOISE_ACTION_SPLIT);

    // -----------------------------------------------------------------
    // Step 6: initiator splits
    // -----------------------------------------------------------------
    LoopbackResult result;
    EXPECT_EQ(noise_handshakestate_split(init_hs_raw, &result.initiator.send_cs,
                                         &result.initiator.recv_cs),
              NOISE_ERROR_NONE);
    // noise_handshakestate_split does not free the hs; the guard destructor will free it.

    auto outcome = nh.take_result();
    EXPECT_TRUE(outcome.has_value());
    if (!outcome.has_value()) {
        return std::nullopt;
    }
    EXPECT_TRUE(outcome->session != nullptr);
    EXPECT_FALSE(outcome->server_id.empty());
    EXPECT_EQ(outcome->server_id, server_id.peer_id());

    result.responder_session = std::move(outcome->session);
    return result;
}

// ============================================================================
// Suite-parameterized full handshake tests
// ============================================================================

TEST(NoiseHandshakeLoopback, KKpsk2ChaChaPoly_FullHandshake) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value()) << "ChaChaPoly loopback handshake failed";
    // The split() outcome has no public observable; the transport ciphers it installs are the
    // state production code goes on to use.
    EXPECT_NE(r->responder_session->send_cipher_, nullptr);
    EXPECT_NE(r->responder_session->recv_cipher_, nullptr);
    EXPECT_NE(r->initiator.send_cs, nullptr);
    EXPECT_NE(r->initiator.recv_cs, nullptr);
}

// ============================================================================
// Fragment and reassemble (TestConnection dispatch loop)
// ============================================================================

// raw_decrypt() (from noise_test_helpers.h) decrypts one frame using the initiator recv cipher.

TEST(NoiseTransport, SendEncryptedText_SmallJson_ChaChaPoly) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    // Install session into TestConnection
    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    std::string json = "{\"type\":\"test\",\"value\":123}";
    EXPECT_EQ(conn.send_encrypted_text(json), SsErr::OK);

    ASSERT_EQ(conn.sent_binary_.size(), 1u);
    const auto& ct = conn.sent_binary_[0];

    // Decrypt with initiator recv cipher
    auto pt = raw_decrypt(r->initiator.recv_cs, ct);
    ASSERT_FALSE(pt.empty());
    ASSERT_GE(pt.size(), 1u);
    EXPECT_EQ(pt[0], 0x00u);  // MSG_TYPE_JSON_BODY
    std::string recovered(reinterpret_cast<char*>(pt.data() + 1), pt.size() - 1);
    EXPECT_EQ(recovered, json);
}

// send_app_json routes plaintext before a transport session exists and encrypted afterwards, on
// NoiseTransport::is_active(). The two frames below are the whole contract: the handshake leg
// goes out in the clear, everything after it is a sealed frame.
TEST(NoiseTransport, SendAppJson_RoutesRawBeforeSessionEncryptedAfter) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;

    // Before a session: send_app_json must send a raw TEXT frame.
    const std::string pre = "{\"type\":\"client/init\"}";
    EXPECT_EQ(conn.send_app_json(pre, nullptr), SsErr::OK);
    ASSERT_EQ(conn.sent_text_.size(), 1u);
    EXPECT_EQ(conn.sent_text_[0], pre);
    EXPECT_TRUE(conn.sent_binary_.empty());

    // After installing a session: send_app_json must encrypt (binary frame), no new TEXT frame.
    conn.set_noise_session(std::move(r->responder_session));
    const std::string post = "{\"type\":\"client/state\",\"value\":7}";
    EXPECT_EQ(conn.send_app_json(post, nullptr), SsErr::OK);
    EXPECT_EQ(conn.sent_text_.size(), 1u);  // unchanged
    ASSERT_EQ(conn.sent_binary_.size(), 1u);

    // The encrypted frame decrypts to the JSON body via the initiator's recv cipher.
    auto pt = raw_decrypt(r->initiator.recv_cs, conn.sent_binary_[0]);
    ASSERT_GE(pt.size(), 1u);
    EXPECT_EQ(pt[0], 0x00u);  // MSG_TYPE_JSON_BODY
    std::string recovered(reinterpret_cast<char*>(pt.data() + 1), pt.size() - 1);
    EXPECT_EQ(recovered, post);
}

TEST(NoiseTransport, ReceiveEncryptedBinary_JsonDispatch) {
    // Verify that a binary WS frame encrypted by the initiator is
    // correctly decrypted and dispatched to on_json_message_cb.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    // The responder (client) recv cipher was not exposed in LoopbackResult;
    // we'll use send_encrypted_text to produce a ciphertext and inject it back.

    // Build a JSON frame: [0x00 | utf8(json)]
    std::string json = "{\"type\":\"server/play\"}";
    std::vector<uint8_t> plaintext;
    plaintext.push_back(0x00);
    plaintext.insert(plaintext.end(), json.begin(), json.end());

    // Encrypt with initiator send_cs -> this is what the server sends to us
    std::vector<uint8_t> ct(plaintext.size() + 16);
    std::copy(plaintext.begin(), plaintext.end(), ct.begin());
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, ct.data(), plaintext.size(), ct.size());
    ASSERT_EQ(noise_cipherstate_encrypt(r->initiator.send_cs, &buf), NOISE_ERROR_NONE);
    ct.resize(buf.size);

    // Install responder session into the connection
    conn.set_noise_session(std::move(r->responder_session));

    // Wire up a JSON dispatch callback
    std::string dispatched_json;
    conn.on_json_message_cb = [&dispatched_json](SendspinConnection& /*c*/, const char* data,
                                                  size_t len, int64_t /*ts*/) {
        dispatched_json = std::string(data, len);
    };

    // Inject the ciphertext as if received from the wire
    conn.inject_binary_payload(ct.data(), ct.size());

    EXPECT_EQ(dispatched_json, json);
}

// ============================================================================
// Error cases: driver abort on bad inputs
// ============================================================================

TEST(NoiseHandshakeDriver, CounterpartyMismatchAborts) {
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();
    Identity other_server = Identity::generate().value();  // A different server

    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id_val = psk_id_for(psk);

    RecordStore rs(nullptr);
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_val;
    rec.psk = psk;
    rec.server_id = other_server.peer_id();  // bound to other_server
    rs.store_record_superseding(std::move(rec), {});

    TestArena arena;
    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY), arena);

    std::string client_init = nh.build_client_init();
    std::string server_init_text = make_server_init(server_id.peer_id());
    std::string prologue_str = client_init + server_init_text;
    const uint8_t* prologue = reinterpret_cast<const uint8_t*>(prologue_str.data());
    size_t prologue_len = prologue_str.size();

    // server/init: NEED_MORE
    auto r1 = nh.on_text_frame(server_init_text, [](const std::string&) { return true; });
    EXPECT_EQ(r1, HandshakeFrameResult::NEED_MORE);

    // The initiator uses the stored PSK, so only the counterparty binding differs.
    NoiseHandshakeState* init_hs_raw =
        build_initiator(std::string(NOISE_SUITE_CHACHAPOLY), server_id.private_bytes.data(),
                           server_id.public_bytes.data(), client_id.public_bytes.data(), psk.data(),
                           prologue, prologue_len);
    ASSERT_NE(init_hs_raw, nullptr);
    HsGuard guard(init_hs_raw);

    std::string msg1_text = build_msg1_envelope(init_hs_raw, psk_id_val);
    ASSERT_FALSE(msg1_text.empty());

    auto r2 = nh.on_text_frame(msg1_text, [](const std::string&) { return true; });
    EXPECT_EQ(r2, HandshakeFrameResult::ABORT);
}

// ============================================================================
// psk_category in the Noise message 1 payload
// ============================================================================

/// What the driver made of one Noise message 1.
struct Msg1Outcome {
    HandshakeFrameResult result{HandshakeFrameResult::ABORT};
    /// Category of the PSK the driver bound, when the handshake completed.
    std::optional<PskCategory> category;
    /// Whether the peer that sent message 1 could read the message 2 that came back.
    bool peer_read_msg2{false};
};

// Drives the handshake driver to Noise message 1 against a store holding one long-term record,
// with the message 1 payload the caller supplies, and reports what the driver made of it. The
// initiator always uses the record's PSK, so message 1 authenticates and the payload is the only
// variable.
Msg1Outcome run_msg1_with_payload(
    const std::function<std::string(const std::string& psk_id)>& make_payload,
    bool store_record = true) {
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();

    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    const std::string psk_id = psk_id_for(psk);

    RecordStore rs(nullptr);
    if (store_record) {
        SendspinPairingRecord rec;
        rec.psk_id = psk_id;
        rec.psk = psk;
        rec.server_id = server_id.peer_id();
        rs.store_record_superseding(std::move(rec), {});
    }

    TestArena arena;
    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY), arena);
    const std::string client_init = nh.build_client_init();
    const std::string server_init_text = make_server_init(server_id.peer_id());
    const std::string prologue_str = client_init + server_init_text;

    EXPECT_EQ(nh.on_text_frame(server_init_text, [](const std::string&) { return true; }),
              HandshakeFrameResult::NEED_MORE);

    NoiseHandshakeState* init_hs_raw = build_initiator(
        std::string(NOISE_SUITE_CHACHAPOLY), server_id.private_bytes.data(),
        server_id.public_bytes.data(), client_id.public_bytes.data(), psk.data(),
        reinterpret_cast<const uint8_t*>(prologue_str.data()), prologue_str.size());
    EXPECT_NE(init_hs_raw, nullptr);
    if (init_hs_raw == nullptr) {
        return {};
    }
    HsGuard guard(init_hs_raw);

    const std::string msg1_text =
        build_msg1_envelope_with_payload(init_hs_raw, make_payload(psk_id));
    EXPECT_FALSE(msg1_text.empty());

    Msg1Outcome outcome;
    std::string captured_msg2;
    outcome.result = nh.on_text_frame(msg1_text, [&captured_msg2](const std::string& text) {
        captured_msg2 = text;
        return true;
    });
    if (outcome.result != HandshakeFrameResult::COMPLETE) {
        return outcome;
    }

    auto result = nh.take_result();
    EXPECT_TRUE(result.has_value());
    if (result.has_value()) {
        outcome.category = result->resolved_psk.category;
        EXPECT_NE(result->session, nullptr) << "a completed handshake must carry its session";
    }

    // The peer holds the PSK it referenced, so it can only read message 2 if the client bound the
    // same one. A read failure here is the credential-mismatch signal the Sentinel fallback exists
    // to produce.
    auto msg2_bytes = extract_noise_bytes(captured_msg2);
    EXPECT_TRUE(msg2_bytes.has_value());
    if (msg2_bytes.has_value()) {
        std::vector<uint8_t> payload_buf(4096);
        NoiseBuffer msg2_in;
        noise_buffer_set_input(msg2_in, msg2_bytes->data(), msg2_bytes->size());
        NoiseBuffer payload_out;
        noise_buffer_set_output(payload_out, payload_buf.data(), payload_buf.size());
        outcome.peer_read_msg2 =
            noise_handshakestate_read_message(init_hs_raw, &msg2_in, &payload_out) ==
            NOISE_ERROR_NONE;
    }
    return outcome;
}

// connection.md "Pre-Shared Key": the psk_id is compared only against the candidates of the
// declared category, so a psk_id the client holds as a long-term record is a lookup miss when the
// server declares it as its pairing PSK. Being a miss, it takes the Sentinel Fallback rather than
// resolving to the record: without the scoping the connection would come up on the long-term PSK
// and inherit the trust that category carries.
TEST(NoiseHandshakeDriver, PskCategoryMismatchFallsBackToTheSentinelPsk) {
    Msg1Outcome outcome = run_msg1_with_payload([](const std::string& psk_id) {
        return R"({"psk_id":")" + psk_id + R"(","psk_category":"pr"})";
    });
    EXPECT_EQ(outcome.result, HandshakeFrameResult::COMPLETE);
    EXPECT_EQ(outcome.category, PskCategory::SENTINEL);
    EXPECT_FALSE(outcome.peer_read_msg2)
        << "the peer must see the credential mismatch, not a session on its own PSK";
}

// connection.md "Sentinel Fallback": on a lookup miss in the initial handshake the client
// completes message 2 with the Sentinel PSK instead of failing, whichever category the server
// declared. The connection then proceeds as an ordinary unpaired one, and the server learns its
// credential no longer matches (pairing.md "Pairing Records").
TEST(NoiseHandshakeDriver, UnknownPskIdFallsBackToTheSentinelPsk) {
    for (const char* category : {"lt", "pr", "sn"}) {
        Msg1Outcome outcome = run_msg1_with_payload(
            [category](const std::string& psk_id) {
                return R"({"psk_id":")" + psk_id + R"(","psk_category":")" + category + R"("})";
            },
            /*store_record=*/false);
        EXPECT_EQ(outcome.result, HandshakeFrameResult::COMPLETE) << "category " << category;
        EXPECT_EQ(outcome.category, PskCategory::SENTINEL) << "category " << category;
        EXPECT_FALSE(outcome.peer_read_msg2) << "category " << category;
    }
}

// messaging.md "noise/handshake": the payload declares which category the referenced PSK is used
// as. The code is not optional, and a code outside the three defined ones makes the payload
// malformed, which connection.md "Failure Handling" makes a silent failure: ABORT is how the
// driver reports one, and SendspinConnection then closes the socket without sending anything.
// Guessing a category instead would defeat the lookup scoping above.
TEST(NoiseHandshakeDriver, Msg1PayloadPskCategoryIsValidated) {
    struct Row {
        const char* name;
        const char* category_field;  // inserted after psk_id, empty for a payload without one
        HandshakeFrameResult expected;
    };
    const Row rows[] = {
        {"code outside the defined set", R"(,"psk_category":"xx")", HandshakeFrameResult::ABORT},
        {"no psk_category at all", "", HandshakeFrameResult::ABORT},
        // Control: the category the client actually holds the psk_id in resolves to the record,
        // and the peer that sent message 1 can read the message 2 that comes back.
        {"category matching the stored record", R"(,"psk_category":"lt")",
         HandshakeFrameResult::COMPLETE},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        const std::string category_field = row.category_field;
        Msg1Outcome outcome = run_msg1_with_payload([&category_field](const std::string& psk_id) {
            return R"({"psk_id":")" + psk_id + R"(")" + category_field + "}";
        });
        EXPECT_EQ(outcome.result, row.expected);
        if (row.expected == HandshakeFrameResult::COMPLETE) {
            EXPECT_EQ(outcome.category, PskCategory::LONG_TERM);
            EXPECT_TRUE(outcome.peer_read_msg2);
        }
    }
}

// messaging.md "server/error": the server sends it in place of server/init when it cannot accept
// our client/init, then closes. The handshake aborts, and the reason it carries is logged rather
// than the frame being treated as an unparseable server/init.
TEST(NoiseHandshakeDriver, ServerErrorWhileAwaitingServerInitAborts) {
    Identity client_id = Identity::generate().value();
    RecordStore rs(nullptr);

    TestArena arena;
    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY), arena);
    nh.build_client_init();

    auto r = nh.on_text_frame(R"({"type":"server/error","payload":{"reason":"unsupported_suite"}})",
                              [](const std::string&) { return true; });
    EXPECT_EQ(r, HandshakeFrameResult::ABORT);
    EXPECT_EQ(nh.server_error_reason(), "unsupported_suite");
}

// Control: the same abort from a frame that is not a server/error leaves no reason to report, so
// the connection does not attribute a generic failure to the server.
TEST(NoiseHandshakeDriver, AbortWithoutServerErrorReportsNoReason) {
    Identity client_id = Identity::generate().value();
    RecordStore rs(nullptr);

    TestArena arena;
    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY), arena);
    nh.build_client_init();

    auto r = nh.on_text_frame(R"({"type":"server/init","payload":{"version":99}})",
                              [](const std::string&) { return true; });
    EXPECT_EQ(r, HandshakeFrameResult::ABORT);
    EXPECT_TRUE(nh.server_error_reason().empty());
}

// The same frame after server/init, while the client is waiting for Noise message 1, is refused
// the same way instead of being read as a handshake message.
TEST(NoiseHandshakeDriver, ServerErrorWhileAwaitingMsg1Aborts) {
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();
    RecordStore rs(nullptr);

    TestArena arena;
    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY), arena);
    nh.build_client_init();
    ASSERT_EQ(nh.on_text_frame(make_server_init(server_id.peer_id()),
                               [](const std::string&) { return true; }),
              HandshakeFrameResult::NEED_MORE);

    auto r = nh.on_text_frame(R"({"type":"server/error","payload":{"reason":"malformed"}})",
                              [](const std::string&) { return true; });
    EXPECT_EQ(r, HandshakeFrameResult::ABORT);
    EXPECT_EQ(nh.server_error_reason(), "malformed");
}

// A server/init is accepted only when its type, its server_id and its version are all usable:
// the server_id names the key and goes into the prologue, so both are checked before the
// handshake reads a Noise byte (connection.md "Handshake").
TEST(NoiseHandshakeDriver, ServerInitIsRefusedUnlessWellFormed) {
    enum class ServerId : uint8_t { REAL, TOO_LONG, NON_CANONICAL };
    struct Row {
        const char* name;
        const char* type;
        ServerId server_id;
        int version;
        HandshakeFrameResult expected;
    };
    const Row rows[] = {
        // The payload is the control's, so only the type field can produce the abort: a frame
        // whose payload would pass must still be refused for arriving under another type.
        {"another envelope type", "wrong/type", ServerId::REAL, 1, HandshakeFrameResult::ABORT},
        // A peer id is PEER_ID_SIZE characters of base64url; anything else cannot name a key.
        {"server_id of the wrong length", "server/init", ServerId::TOO_LONG, 1,
         HandshakeFrameResult::ABORT},
        // The right key under a second spelling: stored as the key, it would come back as a
        // different server_id after a reboot.
        {"non-canonical server_id", "server/init", ServerId::NON_CANONICAL, 1,
         HandshakeFrameResult::ABORT},
        {"unsupported version", "server/init", ServerId::REAL, 99, HandshakeFrameResult::ABORT},
        // Control: the driver accepts it and moves on to waiting for Noise message 1.
        {"well formed", "server/init", ServerId::REAL, 1, HandshakeFrameResult::NEED_MORE},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        Identity client_id = Identity::generate().value();
        Identity server_id = Identity::generate().value();
        RecordStore rs(nullptr);

        TestArena arena;
        NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY), arena);
        nh.build_client_init();

        std::string peer_id = server_id.peer_id();
        if (row.server_id == ServerId::TOO_LONG) {
            peer_id = std::string(PEER_ID_SIZE + 2, 'A');
        } else if (row.server_id == ServerId::NON_CANONICAL) {
            peer_id = non_canonical_spelling(peer_id);
        }
        EXPECT_EQ(nh.on_text_frame(make_server_init(peer_id, row.version, row.type),
                                   [](const std::string&) { return true; }),
                  row.expected);
    }
}

// ============================================================================
// accept_plaintext: fragment sequence rules (messaging.md "Fragmentation")
// ============================================================================

/// A receiver connection wired to a loopback handshake, with a helper that encrypts one
/// plaintext frame with the peer's send cipher and feeds it in as if it had arrived off the
/// wire. Tracks how many complete messages of each kind were dispatched.
class FragmentReceiver {
public:
    explicit FragmentReceiver(LoopbackResult& r) : server_send_(r.initiator.send_cs) {
        this->conn_.set_noise_session(std::move(r.responder_session));
        this->conn_.on_json_message_cb = [this](SendspinConnection& /*c*/, const char* d, size_t n,
                                                int64_t /*t*/) {
            ++this->json_dispatched_;
            this->last_message_.assign(d, d + n);
        };
        this->conn_.on_binary_message_cb = [this](SendspinConnection& /*c*/,
                                                  InboundMessage& message) {
            ++this->binary_dispatched_;
            this->last_message_.assign(message.data, message.data + message.len);
        };
    }

    /// Injects one already-shaped plaintext frame.
    void inject(const std::vector<uint8_t>& plaintext) {
        std::vector<uint8_t> ct = raw_encrypt(this->server_send_, plaintext);
        ASSERT_FALSE(ct.empty());
        this->conn_.inject_binary_payload(ct.data(), ct.size());
    }

    /// Injects a type-1 fragment frame: [1][flags][orig_type?][data].
    void inject_fragment(uint8_t flags, const std::vector<uint8_t>& tail) {
        std::vector<uint8_t> pt;
        pt.reserve(2 + tail.size());
        pt.push_back(MSG_TYPE_FRAGMENT);
        pt.push_back(flags);
        pt.insert(pt.end(), tail.begin(), tail.end());
        this->inject(pt);
    }

    bool closed() const {
        return this->conn_.close_transport_now_calls_ > 0;
    }

    /// Gives the connection the admitted slot, which lifts the reassembly cap from
    /// MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES to MAX_REASSEMBLED_MESSAGE_BYTES.
    void admit() {
        this->conn_.set_admitted(true);
    }

    TestConnection conn_;
    NoiseCipherState* server_send_;
    std::vector<uint8_t> last_message_;
    int json_dispatched_{0};
    int binary_dispatched_{0};
};

TEST(FragmentSequence, SingleFragmentCarryingBothFlagsDispatches) {
    // Control: for every malformed case below, one frame with FIRST and LAST set is a complete,
    // well-formed fragmented message and must dispatch its orig_type payload intact.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_FIRST | FRAGMENT_FLAG_LAST,
                       {SENDSPIN_BINARY_PLAYER_AUDIO, 0xAA, 0xBB});

    EXPECT_FALSE(rx.closed());
    EXPECT_EQ(rx.binary_dispatched_, 1);
    EXPECT_EQ(rx.last_message_,
              (std::vector<uint8_t>{SENDSPIN_BINARY_PLAYER_AUDIO, 0xAA, 0xBB}));
}

TEST(FragmentSequence, MultiFragmentMessageDispatchesOnTheLastFragment) {
    // Control: the flags, not a distinct message ID, decide where the message ends. Nothing
    // dispatches until the fragment carrying bit 0 arrives, and then the concatenated data is
    // handed over behind its orig_type.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {SENDSPIN_BINARY_PLAYER_AUDIO, 0x01});
    EXPECT_EQ(rx.binary_dispatched_, 0) << "mid-reassembly: no complete message yet";
    EXPECT_FALSE(rx.closed()) << "a benign mid-reassembly frame must not close the connection";

    rx.inject_fragment(0, {0x02});
    EXPECT_EQ(rx.binary_dispatched_, 0);

    rx.inject_fragment(FRAGMENT_FLAG_LAST, {0x03});
    EXPECT_EQ(rx.binary_dispatched_, 1);
    EXPECT_EQ(rx.last_message_,
              (std::vector<uint8_t>{SENDSPIN_BINARY_PLAYER_AUDIO, 0x01, 0x02, 0x03}));
    EXPECT_FALSE(rx.closed());
}

// messaging.md "Fragmentation" lists the sequences a receiver must treat as malformed. Each row
// is one of them, and every one closes the connection silently: no goodbye, no frame on the wire,
// nothing dispatched. Only the rows' final injection differs; the preamble that puts a sequence
// in flight is part of the row.
TEST(FragmentSequence, MalformedFragmentSequenceCloses) {
    struct Row {
        std::string name;
        bool expect_closed;
        std::function<void(FragmentReceiver&)> feed;
    };

    std::vector<Row> rows;
    rows.push_back({"first fragment while one is in flight", true, [](FragmentReceiver& rx) {
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});
                        ASSERT_FALSE(rx.closed());
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});
                    }});
    rows.push_back({"non-first fragment with none in flight", true, [](FragmentReceiver& rx) {
                        rx.inject_fragment(FRAGMENT_FLAG_LAST, {'A', 'B'});
                    }});
    rows.push_back({"non-fragment message while one is in flight", true, [](FragmentReceiver& rx) {
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});
                        ASSERT_FALSE(rx.closed());
                        rx.inject({MSG_TYPE_JSON_BODY, 'H', 'i'});
                    }});
    // Bits 2-7 are reserved and MUST be zero. Each is a row of its own so the mask cannot be
    // narrowed to a single bit and still pass.
    for (int bit = 2; bit < 8; ++bit) {
        rows.push_back({"reserved flag bit " + std::to_string(bit), true,
                        [bit](FragmentReceiver& rx) {
                            const uint8_t flags = static_cast<uint8_t>(
                                FRAGMENT_FLAG_FIRST | FRAGMENT_FLAG_LAST | (1u << bit));
                            rx.inject_fragment(flags, {MSG_TYPE_JSON_BODY, '{', '}'});
                        }});
    }
    // Fragments do not nest: a first fragment naming the fragment ID as its orig_type is
    // malformed.
    rows.push_back({"orig_type naming the fragment id", true, [](FragmentReceiver& rx) {
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_FRAGMENT, 0xAA});
                    }});
    // A fragment frame that stops before its flags byte cannot be placed in the sequence at all.
    rows.push_back({"fragment frame without its flags byte", true, [](FragmentReceiver& rx) {
                        rx.inject({MSG_TYPE_FRAGMENT});
                    }});
    rows.push_back({"first fragment without an orig_type", true, [](FragmentReceiver& rx) {
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {});
                    }});
    // A message being discarded is still in flight, so the rules apply to it unchanged.
    rows.push_back({"non-fragment message inside a discarded sequence", true,
                    [](FragmentReceiver& rx) {
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_RESERVED_FIRST, 0xAA});
                        ASSERT_FALSE(rx.closed());
                        rx.inject({MSG_TYPE_JSON_BODY, 'H', 'i'});
                    }});
    // Nor does discarding an over-cap message end its sequence. This is the case the
    // discard-instead-of-reset behavior makes reachable: resetting on the over-cap frame would
    // have made the fragment below look like a legitimate fresh message.
    rows.push_back({"first fragment inside a discarded over-cap sequence", true,
                    [](FragmentReceiver& rx) {
                        rx.admit();  // MAX_REASSEMBLED_MESSAGE_BYTES is the admitted cap.
                        const size_t chunk = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT) - 2;
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, 0xAA});
                        size_t data_len = 1;
                        while (data_len + chunk <= MAX_REASSEMBLED_MESSAGE_BYTES) {
                            rx.inject_fragment(0, std::vector<uint8_t>(chunk, 'X'));
                            data_len += chunk;
                        }
                        rx.inject_fragment(0, std::vector<uint8_t>(chunk, 'X'));  // over the cap
                        ASSERT_FALSE(rx.closed());
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});
                    }});
    // Control: the same receiver, fed a well-formed single-frame message, dispatches it and
    // stays open.
    rows.push_back({"well-formed single fragment", false, [](FragmentReceiver& rx) {
                        rx.inject_fragment(FRAGMENT_FLAG_FIRST | FRAGMENT_FLAG_LAST,
                                           {SENDSPIN_BINARY_PLAYER_AUDIO, 0xAA});
                    }});

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
        ASSERT_TRUE(r.has_value());
        FragmentReceiver rx(*r);

        row.feed(rx);

        EXPECT_EQ(rx.closed(), row.expect_closed);
        if (row.expect_closed) {
            EXPECT_EQ(rx.json_dispatched_, 0);
            EXPECT_EQ(rx.binary_dispatched_, 0);
            EXPECT_TRUE(rx.conn_.disconnect_calls_.empty()) << "a malformed sequence is silent";
            EXPECT_TRUE(rx.conn_.sent_text_.empty());
            EXPECT_TRUE(rx.conn_.sent_binary_.empty());
        } else {
            EXPECT_EQ(rx.binary_dispatched_, 1);
        }
    }
}

// A frame already received when the close was decided still reaches the protocol task, so
// close_silently() detaches the inbound gate rather than relying on the transport being gone.
// TestConnection::close_transport_now() only counts, leaving that gate as the one thing that can
// keep this well-formed message from reaching a role.
TEST(FragmentSequence, AFrameLandingAfterTheCloseDoesNotDispatch) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_LAST, {'A', 'B'});  // malformed: none in flight
    ASSERT_TRUE(rx.closed());

    rx.inject_fragment(FRAGMENT_FLAG_FIRST | FRAGMENT_FLAG_LAST,
                       {SENDSPIN_BINARY_PLAYER_AUDIO, 0xAA});
    EXPECT_EQ(rx.binary_dispatched_, 0);
}

TEST(FragmentSequence, ReservedOrigTypeIsDiscardedWithoutReassembly) {
    // The ignore rules let the receiver throw away the data of a message whose orig_type it does
    // not implement. IDs 2-3 are reserved, so nothing can implement them: the message is never
    // dispatched, the connection stays open, and the sequence is still tracked to its last
    // fragment, which is what lets the following message be accepted as a fresh first fragment.
    for (uint8_t orig_type = MSG_TYPE_RESERVED_FIRST; orig_type <= MSG_TYPE_RESERVED_LAST;
         ++orig_type) {
        auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
        ASSERT_TRUE(r.has_value());
        FragmentReceiver rx(*r);

        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {orig_type, 0xAA});
        rx.inject_fragment(0, {0xBB});
        rx.inject_fragment(FRAGMENT_FLAG_LAST, {0xCC});

        EXPECT_FALSE(rx.closed()) << "orig_type " << static_cast<int>(orig_type)
                                  << " is unimplemented, not malformed";
        EXPECT_EQ(rx.binary_dispatched_, 0) << "a discarded message must not be dispatched";
        EXPECT_EQ(rx.json_dispatched_, 0);

        // The sequence ended with that last fragment, so the next message starts cleanly.
        rx.inject_fragment(FRAGMENT_FLAG_FIRST | FRAGMENT_FLAG_LAST,
                           {SENDSPIN_BINARY_PLAYER_AUDIO, 0x11});
        EXPECT_EQ(rx.binary_dispatched_, 1);
        EXPECT_EQ(rx.last_message_,
                  (std::vector<uint8_t>{SENDSPIN_BINARY_PLAYER_AUDIO, 0x11}));
    }
}

TEST(FragmentSequence, OverCapMessageIsDiscardedWithoutClosing) {
    // Outgrowing MAX_REASSEMBLED_MESSAGE_BYTES is not one of the enumerated malformed sequences
    // (a legitimate peer could simply be sending an oversized image), so the rest of the message
    // is discarded, the connection stays open, and the sequence runs to its last fragment.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);
    rx.admit();  // MAX_REASSEMBLED_MESSAGE_BYTES is the admitted connection's cap.

    // Continuation frames at the largest size a single Noise frame allows: its plaintext is
    // MAX_TRANSPORT_PLAINTEXT bytes, two of which are the fragment type and flags.
    const size_t chunk = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT) - 2;
    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, 0xAA});
    size_t data_len = 1;
    while (data_len + chunk <= MAX_REASSEMBLED_MESSAGE_BYTES) {
        rx.inject_fragment(0, std::vector<uint8_t>(chunk, 'X'));
        data_len += chunk;
    }
    ASSERT_FALSE(rx.closed());

    // This one pushes the total past the cap.
    rx.inject_fragment(0, std::vector<uint8_t>(chunk, 'X'));
    EXPECT_FALSE(rx.closed()) << "exceeding the reassembly cap must not close the connection";
    EXPECT_EQ(rx.json_dispatched_, 0);

    rx.inject_fragment(FRAGMENT_FLAG_LAST, {'Z'});
    EXPECT_EQ(rx.json_dispatched_, 0) << "the over-cap message must never be dispatched";
    EXPECT_FALSE(rx.closed());

    // The connection is not wedged: the next message reassembles normally.
    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});
    rx.inject_fragment(FRAGMENT_FLAG_LAST, {'}'});
    EXPECT_EQ(rx.json_dispatched_, 1) << "connection must still be usable after the discard";
    EXPECT_EQ(rx.last_message_, (std::vector<uint8_t>{'{', '}'}));
}

TEST(FragmentSequence, ReassemblyBufferNeverGrowsPastTheCap) {
    // The reassembly buffer grows geometrically and keeps its capacity for the connection's
    // life, so the doubling is what decides the peak, not the message. A peer picks its fragment
    // sizes: the largest message the cap admits arrives one small fragment past a buffer that is
    // already nearly a full MAX_REASSEMBLED_MESSAGE_BYTES, which is where an unclamped double
    // reserves ~2 MiB (~3 MiB in flight while the realloc copies), times MAX_OPEN_CONNECTIONS.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);
    rx.admit();  // MAX_REASSEMBLED_MESSAGE_BYTES is the admitted connection's cap.

    const size_t chunk = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT) - 2;
    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, 0xAA});
    size_t data_len = 1;
    while (data_len + chunk <= MAX_REASSEMBLED_MESSAGE_BYTES) {
        rx.inject_fragment(0, std::vector<uint8_t>(chunk, 'X'));
        data_len += chunk;
    }
    // Everything the cap still has room for, which no full-size fragment could deliver. It
    // reaches past the buffer the full fragments left behind, so the growth step runs on it.
    const size_t tail = MAX_REASSEMBLED_MESSAGE_BYTES - data_len;
    ASSERT_GT(tail, 0u) << "the fragment sizes no longer leave a partial fragment under the cap";
    ASSERT_LT(tail, chunk);
    rx.inject_fragment(FRAGMENT_FLAG_LAST, std::vector<uint8_t>(tail, 'X'));

    EXPECT_FALSE(rx.closed());
    EXPECT_EQ(rx.json_dispatched_, 1)
        << "a message that fits the cap must still reassemble and dispatch";
    EXPECT_LE(rx.conn_.noise_transport_.reasm_buf_.size(), MAX_REASSEMBLED_MESSAGE_BYTES + 1)
        << "the reassembly buffer outgrew the largest message it will ever hold";
}

TEST(FragmentSequence, PreAdmissionMessageOverTheTightCapIsDiscarded) {
    // Every peer on the network holds the Sentinel PSK, so a connection that has not won the
    // admitted slot must not be able to pin MAX_REASSEMBLED_MESSAGE_BYTES in its nursery slot.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    const size_t chunk = 4096;
    const size_t chunks = MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES / chunk + 1;
    ASSERT_LT(chunk * chunks, MAX_REASSEMBLED_MESSAGE_BYTES)
        << "the message must be over the pre-admission cap but under the admitted one";

    auto send_message = [&] {
        rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY});
        for (size_t i = 0; i + 1 < chunks; ++i) {
            rx.inject_fragment(0, std::vector<uint8_t>(chunk, 'X'));
        }
        rx.inject_fragment(FRAGMENT_FLAG_LAST, std::vector<uint8_t>(chunk, 'X'));
    };

    send_message();
    EXPECT_FALSE(rx.closed()) << "exceeding the pre-admission cap must not close the connection";
    EXPECT_EQ(rx.json_dispatched_, 0)
        << "a message over the pre-admission cap was reassembled and dispatched";
    // The pin matters as much as the dispatch: the buffer keeps whatever the growth step
    // reserved for the connection's life, so a clamp left at the admitted cap would let this
    // sequence park a multiple of the tight cap in a nursery slot.
    EXPECT_LE(rx.conn_.noise_transport_.reasm_buf_.size(),
              MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES + 1)
        << "the reassembly buffer outgrew the cap in force before admission";

    // Control: the same message on the same connection, once it holds the admitted slot.
    rx.admit();
    send_message();
    EXPECT_FALSE(rx.closed());
    EXPECT_EQ(rx.json_dispatched_, 1)
        << "the admitted connection must reassemble a message the 1 MiB cap admits";
    EXPECT_EQ(rx.last_message_.size(), chunk * chunks) << "the JSON body is the message minus "
                                                          "its orig_type byte";

    // Losing the slot narrows the cap again. A dropped connection keeps receiving through its
    // deferred-release window, which is the whole point: it must not be able to hold the
    // admitted connection's buffer once it is no longer the admitted connection.
    rx.conn_.set_admitted(false);
    send_message();
    EXPECT_FALSE(rx.closed());
    EXPECT_EQ(rx.json_dispatched_, 1) << "the cap must narrow again when the slot is vacated";
}

TEST(NoiseTransportDispatch, HandshakeAbortClosesConnection) {
    // A fatal initial-handshake error (here: a psk_category outside the three the protocol
    // defines, which messaging.md "noise/handshake" makes a malformed payload) must close the
    // connection. An unresolvable psk_id is not such an error: it takes the Sentinel Fallback.
    // Driven through process_inbound_message() -> handle_noise_handshake_text(), unlike the
    // NoiseHandshakeDriver.*Aborts tests, which only prove the state machine returns ABORT.
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();
    RecordStore rs(nullptr);

    TestArena arena;  // Declared before the connection, which keeps a pointer to it.
    TestConnection conn;
    conn.set_json_arena(arena);
    conn.init_noise_handshake(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
    conn.send_noise_client_init();
    ASSERT_EQ(conn.sent_text_.size(), 1u);
    std::string client_init_text = conn.sent_text_[0];

    std::string server_init_text = make_server_init(server_id.peer_id());
    conn.inject_text_payload(server_init_text);
    EXPECT_TRUE(conn.disconnect_calls_.empty()) << "server/init alone must not close";
    EXPECT_EQ(conn.close_transport_now_calls_, 0) << "server/init alone must not close";

    // Build a msg1 whose payload declares a category the protocol does not define.
    std::string prologue_str = client_init_text + server_init_text;
    const uint8_t* prologue = reinterpret_cast<const uint8_t*>(prologue_str.data());
    size_t prologue_len = prologue_str.size();

    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    NoiseHandshakeState* init_hs_raw =
        build_initiator(std::string(NOISE_SUITE_CHACHAPOLY), server_id.private_bytes.data(),
                           server_id.public_bytes.data(), client_id.public_bytes.data(), psk.data(),
                           prologue, prologue_len);
    ASSERT_NE(init_hs_raw, nullptr);
    HsGuard guard(init_hs_raw);

    std::string msg1_text = build_msg1_envelope(init_hs_raw, psk_id, "xx");
    ASSERT_FALSE(msg1_text.empty());

    conn.inject_text_payload(msg1_text);

    // The handshake must have aborted and the connection must have been closed silently: torn
    // down via close_transport_now() (not disconnect()), with no goodbye (only the earlier
    // client/init is in sent_text_).
    EXPECT_EQ(conn.close_transport_now_calls_, 1)
        << "an aborted initial handshake must close the connection";
    EXPECT_TRUE(conn.disconnect_calls_.empty());
    EXPECT_EQ(conn.sent_text_.size(), 1u) << "only client/init was sent; no goodbye";
    EXPECT_TRUE(conn.sent_binary_.empty());
}

// ============================================================================
// End-to-end fragment + reassembly through the receive (decrypt) path
// ============================================================================

// raw_encrypt() (from noise_test_helpers.h) encrypts one plaintext frame with the "server" send
// cipher (advances its nonce).

/// Split a type-prefixed plaintext into wire fragment frames, per messaging.md
/// "Fragmentation" and matching NoiseTransport::fragment_and_send_locked().
static std::vector<std::vector<uint8_t>> server_fragment_frames(
    const std::vector<uint8_t>& plaintext) {
    std::vector<std::vector<uint8_t>> frames;
    const size_t maxp = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT);
    if (plaintext.size() <= maxp) {
        frames.push_back(plaintext);
        return frames;
    }
    const uint8_t orig_type = plaintext[0];
    const uint8_t* data = plaintext.data() + 1;
    const size_t data_len = plaintext.size() - 1;
    const size_t first_cap = maxp - 3;
    const size_t cont_cap = maxp - 2;

    const size_t first_chunk = std::min(data_len, first_cap);
    std::vector<uint8_t> first;
    first.reserve(3 + first_chunk);
    first.push_back(MSG_TYPE_FRAGMENT);
    first.push_back(static_cast<uint8_t>(
        FRAGMENT_FLAG_FIRST | ((first_chunk == data_len) ? FRAGMENT_FLAG_LAST : 0)));
    first.push_back(orig_type);
    first.insert(first.end(), data, data + first_chunk);
    frames.push_back(std::move(first));

    size_t offset = first_chunk;
    while (offset < data_len) {
        const size_t chunk = std::min(data_len - offset, cont_cap);
        const bool is_last = (offset + chunk >= data_len);
        std::vector<uint8_t> cont;
        cont.reserve(2 + chunk);
        cont.push_back(MSG_TYPE_FRAGMENT);
        cont.push_back(is_last ? FRAGMENT_FLAG_LAST : 0);
        cont.insert(cont.end(), data + offset, data + offset + chunk);
        frames.push_back(std::move(cont));
        offset += chunk;
    }
    return frames;
}

/// Fragment a large JSON body on the "server" side, feed every encrypted frame into a
/// receiver connection, and verify the reassembled JSON is dispatched intact.
static void run_fragment_reassemble_receive(const std::string& suite) {
    auto r = run_loopback_handshake(suite);
    ASSERT_TRUE(r.has_value());
    NoiseCipherState* server_send = r->initiator.send_cs;

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));
    // A message this size is role traffic, which only flows on an admitted connection; before
    // admission the far smaller MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES applies.
    conn.set_admitted(true);

    std::string received;
    int calls = 0;
    conn.on_json_message_cb = [&received, &calls](SendspinConnection& /*c*/, const char* d,
                                                  size_t n, int64_t /*t*/) {
        received.assign(d, n);
        ++calls;
    };

    // plaintext = [0x00] + json; json well over MAX_TRANSPORT_PLAINTEXT to force several frames.
    std::string big_json(200000, 'X');
    std::vector<uint8_t> plaintext;
    plaintext.reserve(1 + big_json.size());
    plaintext.push_back(MSG_TYPE_JSON_BODY);
    plaintext.insert(plaintext.end(), big_json.begin(), big_json.end());

    const auto frames = server_fragment_frames(plaintext);
    ASSERT_GE(frames.size(), 3u);
    for (const auto& f : frames) {
        const auto ct = raw_encrypt(server_send, f);
        EXPECT_FALSE(ct.empty());
        conn.inject_binary_payload(ct.data(), ct.size());
    }

    EXPECT_EQ(calls, 1);
    EXPECT_EQ(received, big_json);
}

TEST(NoiseTransport, FragmentReassembleReceive_ChaChaPoly) {
    run_fragment_reassemble_receive(std::string(NOISE_SUITE_CHACHAPOLY));
}

// ============================================================================
// Transport-mode decrypt failure: a tampered ciphertext is dropped, not dispatched
// ============================================================================

TEST(NoiseTransport, TamperedCiphertextClosesConnection) {
    // An AEAD failure in transport mode must not just drop the frame: the
    // underlying Noise decrypt never advances the receive-direction nonce counter on an auth
    // failure, so leaving the connection open would desync it permanently (every later frame
    // would also fail forever). Spec Failure Handling also mandates closing silently here.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    NoiseCipherState* server_send = r->initiator.send_cs;

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    int calls = 0;
    conn.on_json_message_cb = [&calls](SendspinConnection& /*c*/, const char* /*d*/, size_t /*n*/,
                                       int64_t /*t*/) { ++calls; };
    conn.on_binary_message_cb = [&calls](SendspinConnection& /*c*/,
                                         InboundMessage& /*message*/) { ++calls; };

    std::string json = "{\"x\":1}";
    std::vector<uint8_t> pt;
    pt.push_back(MSG_TYPE_JSON_BODY);
    pt.insert(pt.end(), json.begin(), json.end());
    auto ct = raw_encrypt(server_send, pt);

    // Flip a byte; the AEAD tag check must fail, the frame must be dropped, and the
    // connection must be closed silently, with no application-level message sent.
    ASSERT_GT(ct.size(), 0u);
    ct[ct.size() / 2] ^= 0xFF;
    conn.inject_binary_payload(ct.data(), ct.size());

    EXPECT_EQ(calls, 0) << "tampered ciphertext must not be dispatched";
    EXPECT_EQ(conn.close_transport_now_calls_, 1)
        << "a transport-mode AEAD failure must close the connection";
    EXPECT_TRUE(conn.disconnect_calls_.empty());
    EXPECT_TRUE(conn.sent_text_.empty());
    EXPECT_TRUE(conn.sent_binary_.empty());
}

// connection.md "Failure Handling": a cleartext message after the switch to transport mode is a
// silent failure, even one that would be valid JSON.
TEST(NoiseTransport, CleartextFrameInTransportModeClosesSilently) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));
    int calls = 0;
    conn.on_json_message_cb = [&calls](SendspinConnection& /*c*/, const char* /*d*/, size_t /*n*/,
                                       int64_t /*t*/) { ++calls; };

    conn.inject_text_payload(R"({"type":"server/state","payload":{}})");

    EXPECT_EQ(calls, 0);
    EXPECT_EQ(conn.close_transport_now_calls_, 1);
    EXPECT_TRUE(conn.disconnect_calls_.empty()) << "the close must be silent";
    EXPECT_TRUE(conn.sent_text_.empty());
    EXPECT_TRUE(conn.sent_binary_.empty());
}

// ============================================================================
// Fragmentation threshold: exactly at and one byte over MAX_TRANSPORT_PLAINTEXT
// ============================================================================

TEST(NoiseTransport, FragmentBoundaryExactLimit) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    // plaintext = [0x00] + json, and MAX_TRANSPORT_PLAINTEXT (65519) counts the type byte.
    const size_t maxp = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT);
    constexpr size_t TAG = 16;  // AEAD tag appended to every frame's plaintext

    // json of (maxp - 1) bytes -> plaintext exactly maxp -> a single (unfragmented) frame.
    EXPECT_EQ(conn.send_encrypted_text(std::string(maxp - 1, 'A')), SsErr::OK);
    ASSERT_EQ(conn.sent_binary_.size(), 1u);
    EXPECT_EQ(conn.sent_binary_[0].size(), maxp + TAG);

    conn.sent_binary_.clear();

    // json of maxp bytes -> plaintext (maxp + 1) -> exactly two frames.
    //
    // Assert each frame's exact size, not just the frame count: the split point is wire format
    // (messaging.md "Fragmentation"), so an off-by-one in fragment_and_send_locked's
    // first_cap/cont_cap would still emit two frames that this transport happily reassembles,
    // while a conforming peer would disagree about where the boundary falls.
    //
    // First frame is [1, flags, orig_type, data[:first_cap]], so its plaintext fills the cap
    // exactly at 3 + (maxp - 3) == maxp. That leaves data_len - (maxp - 3) == 3 bytes for the
    // continuation frame, whose plaintext is [1, flags, those 3 bytes] == 5 bytes.
    EXPECT_EQ(conn.send_encrypted_text(std::string(maxp, 'A')), SsErr::OK);
    ASSERT_EQ(conn.sent_binary_.size(), 2u);
    EXPECT_EQ(conn.sent_binary_[0].size(), maxp + TAG)
        << "first fragment must fill MAX_TRANSPORT_PLAINTEXT exactly";
    EXPECT_EQ(conn.sent_binary_[1].size(), 5u + TAG)
        << "continuation must carry exactly the bytes the first frame's cap left over";

    conn.sent_binary_.clear();

    // One byte further: the continuation grows by exactly one, confirming the leftover tracks
    // data_len rather than the frame count staying coincidentally right.
    EXPECT_EQ(conn.send_encrypted_text(std::string(maxp + 1, 'A')), SsErr::OK);
    ASSERT_EQ(conn.sent_binary_.size(), 2u);
    EXPECT_EQ(conn.sent_binary_[0].size(), maxp + TAG);
    EXPECT_EQ(conn.sent_binary_[1].size(), 6u + TAG);
}

// The frame sizes above pin where the split falls, but not what the header bytes are. Decrypt the
// emitted frames and assert the layout messaging.md "Fragmentation" specifies, byte by byte, so a
// transposed flags/orig_type or a wrong flag bit fails a layout test rather than showing up as an
// unrelated failure elsewhere.
TEST(NoiseTransport, FragmentHeaderBytesMatchTheWireFormat) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    const size_t maxp = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT);
    const size_t first_cap = maxp - 3;
    const size_t cont_cap = maxp - 2;

    // One byte past what two frames carry, so there is a first, a middle and a last fragment and
    // every flags combination the send path emits appears exactly once.
    const std::string json(first_cap + cont_cap + 1, 'A');
    ASSERT_EQ(conn.send_encrypted_text(json), SsErr::OK);
    ASSERT_EQ(conn.sent_binary_.size(), 3u);

    std::vector<std::vector<uint8_t>> frames;
    for (const auto& ct : conn.sent_binary_) {
        auto pt = raw_decrypt(r->initiator.recv_cs, ct);
        ASSERT_FALSE(pt.empty());
        frames.push_back(std::move(pt));
    }

    // First fragment: [1][FIRST][orig_type][data...]
    EXPECT_EQ(frames[0][0], MSG_TYPE_FRAGMENT);
    EXPECT_EQ(frames[0][1], FRAGMENT_FLAG_FIRST) << "the first fragment sets bit 1 and not bit 0";
    EXPECT_EQ(frames[0][2], MSG_TYPE_JSON_BODY) << "orig_type is byte 2, after the flags";
    EXPECT_EQ(frames[0][3], 'A') << "the data starts at byte 3";
    EXPECT_EQ(frames[0].size(), 3 + first_cap);

    // Middle fragment: [1][0][data...], no orig_type.
    EXPECT_EQ(frames[1][0], MSG_TYPE_FRAGMENT);
    EXPECT_EQ(frames[1][1], 0u) << "a middle fragment is neither first nor last";
    EXPECT_EQ(frames[1][2], 'A') << "a continuation's data starts at byte 2";
    EXPECT_EQ(frames[1].size(), 2 + cont_cap) << "a middle fragment fills cont_cap";

    // Last fragment: [1][LAST][data...]
    EXPECT_EQ(frames[2][0], MSG_TYPE_FRAGMENT);
    EXPECT_EQ(frames[2][1], FRAGMENT_FLAG_LAST) << "the last fragment sets bit 0 and not bit 1";
    EXPECT_EQ(frames[2][2], 'A');
    EXPECT_EQ(frames[2].size(), 3u);
}

// ============================================================================
// send_buf_ growth: the reused non-fragmented send buffer grows on demand instead of a fixed
// MAX_TRANSPORT_PLAINTEXT + 16 allocation. There is no accessor for its capacity, so these
// exercise growth indirectly: a sequence of increasing sizes (including a shrink back down,
// which must not lose or corrupt data) and the exact MAX_TRANSPORT_PLAINTEXT boundary, all
// round-tripping through encrypt/decrypt correctly on one shared transport instance.
// ============================================================================

TEST(NoiseTransport, SendJson_GrowingSizesRoundTrip) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    const size_t maxp = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT);
    // json length -> plaintext length (1 + json length) stays <= maxp for every size here, so
    // every send takes the single-frame (non-fragmented, send_buf_-backed) path. Includes a
    // shrink (8192 -> 64) to confirm a smaller send after a large one still works correctly.
    const size_t json_lens[] = {0, 1, 64, 200, 2000, 8192, 64, maxp - 1};

    for (size_t json_len : json_lens) {
        std::string json;
        json.reserve(json_len);
        for (size_t i = 0; i < json_len; ++i) {
            json.push_back(static_cast<char>('a' + (i % 26)));
        }

        conn.sent_binary_.clear();
        ASSERT_EQ(conn.send_encrypted_text(json), SsErr::OK) << "json_len=" << json_len;
        ASSERT_EQ(conn.sent_binary_.size(), 1u) << "json_len=" << json_len;

        auto pt = raw_decrypt(r->initiator.recv_cs, conn.sent_binary_[0]);
        ASSERT_FALSE(pt.empty()) << "json_len=" << json_len;
        EXPECT_EQ(pt[0], 0x00u);  // MSG_TYPE_JSON_BODY
        std::string recovered(reinterpret_cast<char*>(pt.data() + 1), pt.size() - 1);
        EXPECT_EQ(recovered, json) << "json_len=" << json_len;
    }
}

TEST(NoiseTransport, SendBinary_GrowingSizesUpToMaxTransportPlaintextRoundTrip) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    const size_t maxp = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT);
    // Total length including the leading type byte; maxp is the largest size the non-fragmented
    // send_binary path ever handles (see send_binary's doc comment).
    const size_t lens[] = {1, 32, 512, 4096, maxp};

    for (size_t len : lens) {
        std::vector<uint8_t> data(len);
        data[0] = SENDSPIN_BINARY_PLAYER_AUDIO;  // arbitrary non-JSON role type byte
        for (size_t i = 1; i < len; ++i) {
            data[i] = static_cast<uint8_t>(i);
        }

        conn.sent_binary_.clear();
        ASSERT_EQ(conn.test_send_binary(data.data(), data.size()), SsErr::OK) << "len=" << len;
        ASSERT_EQ(conn.sent_binary_.size(), 1u) << "len=" << len;

        auto pt = raw_decrypt(r->initiator.recv_cs, conn.sent_binary_[0]);
        ASSERT_EQ(pt.size(), len) << "len=" << len;
        EXPECT_EQ(pt, data) << "len=" << len;
    }
}

TEST(NoiseTransport, SendBinaryRejectsTheFragmentMessageType) {
    // messaging.md "Fragmentation" reserves ID 1 for the transport and forbids it as an
    // orig_type, so a role message may never claim it. Nothing reaches the wire.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    const std::vector<uint8_t> fragment_typed = {MSG_TYPE_FRAGMENT, 0xAA, 0xBB};
    EXPECT_EQ(conn.test_send_binary(fragment_typed.data(), fragment_typed.size()), SsErr::FAIL);
    EXPECT_TRUE(conn.sent_binary_.empty());

    // Control: the same payload behind a role type byte is sent.
    const std::vector<uint8_t> role_typed = {SENDSPIN_BINARY_PLAYER_AUDIO, 0xAA, 0xBB};
    EXPECT_EQ(conn.test_send_binary(role_typed.data(), role_typed.size()), SsErr::OK);
    EXPECT_EQ(conn.sent_binary_.size(), 1u);
}

TEST(NoiseTransport, SendBinaryRejectsAnEmptyPayload) {
    // A zero-length binary message has no type byte, so there is nothing to check ID 1 against
    // and nothing for a receiver to route. It is refused before the type read rather than sealed
    // and put on the wire.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    const std::vector<uint8_t> payload = {SENDSPIN_BINARY_PLAYER_AUDIO};
    EXPECT_EQ(conn.test_send_binary(payload.data(), 0), SsErr::FAIL);
    EXPECT_TRUE(conn.sent_binary_.empty()) << "an empty binary message reached the wire";

    // Control: the same buffer with its one byte counted is sent.
    EXPECT_EQ(conn.test_send_binary(payload.data(), payload.size()), SsErr::OK);
    EXPECT_EQ(conn.sent_binary_.size(), 1u);
}

TEST(NoiseTransport, SendsBeforeTheSessionExistsReportInvalidState) {
    // Both transport sends are guarded on is_active(): with no session installed there is no
    // cipher to seal with, and the caller is told the state is wrong rather than having its
    // message sent in the clear or dropped silently.
    TestConnection conn;

    const std::string json = R"({"type":"client/state"})";
    EXPECT_EQ(conn.send_encrypted_text(json), SsErr::INVALID_STATE);
    const std::vector<uint8_t> payload = {SENDSPIN_BINARY_PLAYER_AUDIO, 0x01};
    EXPECT_EQ(conn.test_send_binary(payload.data(), payload.size()), SsErr::INVALID_STATE);
    EXPECT_TRUE(conn.sent_binary_.empty());

    // Control: with a session installed the same two calls seal and send.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    conn.set_noise_session(std::move(r->responder_session));
    EXPECT_EQ(conn.send_encrypted_text(json), SsErr::OK);
    EXPECT_EQ(conn.test_send_binary(payload.data(), payload.size()), SsErr::OK);
    EXPECT_EQ(conn.sent_binary_.size(), 2u);
}

// ============================================================================
// Malformed Noise message 1 aborts the handshake
// ============================================================================

// Noise message 1 that cannot be read as one aborts the handshake rather than being retried or
// ignored (connection.md "Failure Handling").
TEST(NoiseHandshakeDriver, MalformedMsg1Aborts) {
    struct Row {
        const char* name;
        bool well_formed;                  // build message 1 with a real initiator
        std::vector<uint8_t> noise_bytes;  // the frame's noise bytes when it is not well formed
        HandshakeFrameResult expected;
    };
    const Row rows[] = {
        {"empty noise bytes", false, {}, HandshakeFrameResult::ABORT},
        // Well-formed base64url, but fails Noise authentication as message 1.
        {"garbage of a plausible length", false, std::vector<uint8_t>(64, 0xAB),
         HandshakeFrameResult::ABORT},
        // Control: a message 1 a real initiator wrote over the same prologue completes, so the
        // aborts above are the driver reading the bytes rather than refusing every message 1.
        // The store holds no record, so the driver takes the Sentinel fallback; that is a message
        // 2 concern, since KKpsk2 mixes the PSK after message 1 is read.
        {"a well formed message 1", true, {}, HandshakeFrameResult::COMPLETE},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        Identity client_id = Identity::generate().value();
        Identity server_id = Identity::generate().value();
        RecordStore rs(nullptr);

        TestArena arena;
        NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY), arena);
        const std::string client_init = nh.build_client_init();
        const std::string server_init_text = make_server_init(server_id.peer_id());
        auto send_fn = [](const std::string&) { return true; };
        ASSERT_EQ(nh.on_text_frame(server_init_text, send_fn), HandshakeFrameResult::NEED_MORE);

        if (!row.well_formed) {
            EXPECT_EQ(nh.on_text_frame(make_noise_handshake_envelope(row.noise_bytes), send_fn),
                      row.expected);
            continue;
        }

        const std::string prologue_str = client_init + server_init_text;
        std::array<uint8_t, NOISE_PSK_SIZE> psk{};
        platform_random_bytes(psk.data(), psk.size());
        NoiseHandshakeState* init_hs_raw = build_initiator(
            std::string(NOISE_SUITE_CHACHAPOLY), server_id.private_bytes.data(),
            server_id.public_bytes.data(), client_id.public_bytes.data(), psk.data(),
            reinterpret_cast<const uint8_t*>(prologue_str.data()), prologue_str.size());
        ASSERT_NE(init_hs_raw, nullptr);
        HsGuard guard(init_hs_raw);

        const std::string msg1_text = build_msg1_envelope(init_hs_raw, psk_id_for(psk));
        ASSERT_FALSE(msg1_text.empty());
        EXPECT_EQ(nh.on_text_frame(msg1_text, send_fn), row.expected);
    }
}

// ============================================================================
// Concurrent sends
// ============================================================================

// ============================================================================
// client/time send stamps
// ============================================================================

/// TestConnection that holds each transport frame's write hook instead of running it, so a test
/// can run it later, as a transport that queues its writes does.
class DeferredWriteConnection : public TestConnection {
public:
    SsErr send_transport_frame(const uint8_t* data, size_t len,
                               const NoiseTransport::FrameWriteHook& before_write) override {
        this->sent_binary_.emplace_back(data, data + len);
        this->hooks_.push_back(before_write);
        return SsErr::OK;
    }

    /// Sends through NoiseTransport::send_json() with a write hook, which send_app_json() does
    /// not expose.
    SsErr send_json_with_hook(const std::string& json, const NoiseTransport::FrameWriteHook& hook) {
        return this->noise_transport_.send_json(json.data(), json.size(), hook);
    }

    std::vector<NoiseTransport::FrameWriteHook> hooks_;
};

// The hook marks the moment the message goes to the socket, so only the last frame of a
// fragmented message may carry it.
TEST(NoiseTransport, SendJsonWriteHookRidesTheLastFrame) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    DeferredWriteConnection conn;
    conn.set_noise_session(std::move(r->responder_session));
    const size_t maxp = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT);
    auto hook = []() {};

    ASSERT_EQ(conn.send_json_with_hook("{}", hook), SsErr::OK);
    ASSERT_EQ(conn.hooks_.size(), 1U);
    EXPECT_TRUE(conn.hooks_[0]);

    conn.hooks_.clear();
    ASSERT_EQ(conn.send_json_with_hook(std::string(maxp, 'A'), hook), SsErr::OK);
    ASSERT_EQ(conn.hooks_.size(), 2U);
    EXPECT_FALSE(conn.hooks_[0]);
    EXPECT_TRUE(conn.hooks_[1]);
}

// On a transport that writes synchronously, the default send_transport_frame() runs the hook
// before the write, never after it.
TEST(NoiseTransport, SendTransportFrameRunsTheHookBeforeTheWrite) {
    class OrderRecordingConnection : public TestConnection {
    public:
        SsErr send_binary_message(const uint8_t* data, size_t len,
                                  SendCompleteCallback cb) override {
            this->events_.emplace_back("write");
            return TestConnection::send_binary_message(data, len, std::move(cb));
        }
        std::vector<std::string> events_;
    };
    OrderRecordingConnection conn;
    const uint8_t frame[] = {0x00};

    ASSERT_EQ(conn.send_transport_frame(frame, sizeof(frame),
                                        [&conn]() { conn.events_.emplace_back("hook"); }),
              SsErr::OK);
    EXPECT_EQ(conn.events_, (std::vector<std::string>{"hook", "write"}));
}

/// The client_transmitted carried by a client/time frame the connection sent, read back through
/// the peer's receive cipher (frames must be decrypted in the order they were sent).
static int64_t sent_client_transmitted(NoiseCipherState* recv_cs, const std::vector<uint8_t>& frame) {
    auto pt = raw_decrypt(recv_cs, frame);
    EXPECT_GE(pt.size(), 1U);
    JsonDocument doc;
    EXPECT_FALSE(deserializeJson(doc, reinterpret_cast<const char*>(pt.data() + 1), pt.size() - 1));
    return doc["payload"]["client_transmitted"].as<int64_t>();
}

// A server/time reply is matched by its echo to the one client/time in flight, and only once. A
// connection that never sent client/time (any nursery peer) has nothing in flight, including for
// an echo whose low 32 bits are 0, the tag that means "none". Neither does a frame the burst gave
// up on.
TEST(NoiseTransport, OnlyTheTimeFrameInFlightIsClaimedAndOnlyOnce) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    DeferredWriteConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    EXPECT_FALSE(conn.claim_time_frame(int64_t{1} << 32).has_value());
    EXPECT_FALSE(conn.claim_time_frame(1000).has_value());

    const int64_t embedded = conn.send_time_message();
    ASSERT_NE(embedded, 0);
    ASSERT_EQ(conn.sent_binary_.size(), 1U);
    const int64_t echo = sent_client_transmitted(r->initiator.recv_cs, conn.sent_binary_[0]);
    EXPECT_EQ(echo, embedded) << "send_time_message() returns the time the frame carries";

    EXPECT_FALSE(conn.claim_time_frame(echo - 1).has_value()) << "an echo of another frame";
    const std::optional<int64_t> sent = conn.claim_time_frame(echo);
    ASSERT_TRUE(sent.has_value());
    EXPECT_EQ(*sent, echo) << "until its hook runs, a frame counts as written at the time it carries";
    EXPECT_FALSE(conn.claim_time_frame(echo).has_value()) << "a frame is claimed once";

    ASSERT_NE(conn.send_time_message(), 0);
    ASSERT_EQ(conn.sent_binary_.size(), 2U);
    const int64_t cancelled = sent_client_transmitted(r->initiator.recv_cs, conn.sent_binary_[1]);
    conn.cancel_time_frame();
    EXPECT_FALSE(conn.claim_time_frame(cancelled).has_value());
}

// The claim reports when the write hook ran, and never a time before the one the frame carries,
// even if a leftover hook that sampled the clock before the seed stored an earlier one.
TEST(NoiseTransport, TimeFrameClaimReportsTheSocketWriteTime) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    DeferredWriteConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    ASSERT_NE(conn.send_time_message(), 0);
    const int64_t echo = sent_client_transmitted(r->initiator.recv_cs, conn.sent_binary_[0]);
    // The hook must sample a later microsecond than the time the frame carries.
    while (platform_time_us() <= echo) {
    }
    ASSERT_EQ(conn.hooks_.size(), 1U);
    ASSERT_TRUE(conn.hooks_[0]);
    conn.hooks_[0]();
    const int64_t after_hook = platform_time_us();
    const std::optional<int64_t> sent = conn.claim_time_frame(echo);
    ASSERT_TRUE(sent.has_value());
    EXPECT_GT(*sent, echo);
    EXPECT_LE(*sent, after_hook);

    ASSERT_NE(conn.send_time_message(), 0);
    const int64_t second = sent_client_transmitted(r->initiator.recv_cs, conn.sent_binary_[1]);
    conn.time_frame_sent_us_.store(static_cast<uint32_t>(second) - 5);
    EXPECT_EQ(conn.claim_time_frame(second), std::optional<int64_t>(second));
}

// Both halves of the frame in flight are low 32 bits of the microsecond clock, so a write that
// lands just after they wrap is still a small delay on top of the full 64-bit echo.
TEST(NoiseTransport, TimeFrameWriteDelaySurvivesTheLow32BitWrap) {
    DeferredWriteConnection conn;
    constexpr uint32_t TAG = 0xFFFFFF00U;
    constexpr int64_t ECHO = (int64_t{5} << 32) | TAG;
    conn.time_frame_sent_us_.store(0x100U);
    conn.time_frame_tag_ = TAG;
    EXPECT_EQ(conn.claim_time_frame(ECHO), std::optional<int64_t>(ECHO + 0x200));
}

// A reply counts toward the burst only when its whole echo is that of the message still pending.
// The protocol task matches only the low 32 bits and claims at most one reply per message, but a
// claimed reply can be drained after loop() sent the next message; counted, any of these would
// complete a two-message burst on one real exchange.
TEST(TimeBurst, CountsOnlyTheReplyToItsPendingMessage) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    DeferredWriteConnection conn;
    conn.set_noise_session(std::move(r->responder_session));
    conn.init_time_filter();
    conn.set_client_hello_sent(true);
    conn.set_server_hello_received(true);
    auto reply = [](int64_t echo) {
        TimeResponse response;
        response.offset = 10;
        response.max_error = 50;
        response.timestamp = 1;
        response.client_transmitted = echo;
        return response;
    };
    auto sent_echo = [&](size_t index) {
        return sent_client_transmitted(r->initiator.recv_cs, conn.sent_binary_.at(index));
    };

    SendspinTimeBurst burst;
    // Long enough that loop() never times a message out here.
    burst.configure(/*burst_size=*/2, /*burst_interval_ms=*/0, /*response_timeout_ms=*/60000);
    burst.loop(&conn, platform_time_us() / 1000, true);
    const int64_t first = sent_echo(0);

    EXPECT_FALSE(burst.on_time_response(&conn, reply(first + 1)));
    EXPECT_FALSE(burst.on_time_response(&conn, reply(first)))
        << "the real reply ends the burst only if a reply above was counted";
    EXPECT_FALSE(burst.on_time_response(&conn, reply(first))) << "no message is pending";

    burst.loop(&conn, platform_time_us() / 1000, true);
    const int64_t second = sent_echo(1);
    EXPECT_FALSE(burst.on_time_response(&conn, reply(first)))
        << "a reply to the first message, drained after the second was sent";
    EXPECT_FALSE(burst.on_time_response(&conn, reply(second + (int64_t{1} << 32))))
        << "an echo matching the pending message only in its low 32 bits";
    EXPECT_TRUE(burst.on_time_response(&conn, reply(second)))
        << "the second real reply ends the burst";
}

// A message loop() times out is retired on the connection, so its late reply is not claimed, and
// the burst does not count one claimed just before the timeout either.
TEST(TimeBurst, TimedOutMessageIsRetired) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    DeferredWriteConnection conn;
    conn.set_noise_session(std::move(r->responder_session));
    conn.init_time_filter();
    conn.set_client_hello_sent(true);
    conn.set_server_hello_received(true);

    SendspinTimeBurst burst;
    burst.configure(/*burst_size=*/2, /*burst_interval_ms=*/0, /*response_timeout_ms=*/0);
    burst.loop(&conn, platform_time_us() / 1000, true);
    ASSERT_EQ(conn.sent_binary_.size(), 1U);
    const int64_t echo = sent_client_transmitted(r->initiator.recv_cs, conn.sent_binary_.at(0));
    // A zero timeout expires once the millisecond clock moves past the send.
    const int64_t sent_ms = platform_time_us() / 1000;
    while (platform_time_us() / 1000 <= sent_ms) {
    }
    burst.loop(&conn, platform_time_us() / 1000, true);

    EXPECT_FALSE(conn.claim_time_frame(echo).has_value());
    TimeResponse late;
    late.max_error = 50;
    late.client_transmitted = echo;
    EXPECT_FALSE(burst.on_time_response(&conn, late))
        << "counted, the late reply would complete the burst its timeout already counted toward";
}

// client/time is sent only over the Noise transport, which every operational connection has.
TEST(NoiseTransport, TimeMessageNeedsTheNoiseTransport) {
    DeferredWriteConnection conn;
    EXPECT_EQ(conn.send_time_message(), 0);
    EXPECT_TRUE(conn.sent_text_.empty());
    EXPECT_TRUE(conn.sent_binary_.empty());
}

// ============================================================================
// Inbound receive path: what a transport hands the protocol task
// ============================================================================

namespace {

// A TestConnection wired to its own inbound ring and an unstarted protocol task (whose wake is
// then a no-op), as the connection manager wires a real one.
struct InboundHarness {
    InboundHarness() {
        create_test_ring(this->ring);
        this->conn.attach_inbound(&this->ring, &this->task);
    }

    // Over a ring of `ring_bytes`, which sets the longest message it takes.
    explicit InboundHarness(size_t ring_bytes) {
        EXPECT_TRUE(this->ring.create(ring_bytes, MemoryLocation::PREFER_EXTERNAL));
        this->conn.attach_inbound(&this->ring, &this->task);
    }

    // Receives one complete message as a single-frame transport does.
    TestConnection::InboundRoute receive(const std::vector<uint8_t>& bytes) {
        const TestConnection::InboundTarget target =
            this->conn.begin_inbound_message(bytes.size(), /*is_text=*/false, platform_time_us());
        if (target.route == TestConnection::InboundRoute::RECEIVE) {
            std::memcpy(target.data, bytes.data(), bytes.size());
            this->conn.end_inbound_message(true);
        }
        return target.route;
    }

    InboundRing ring;
    ProtocolTask task{1};
    TestConnection conn;
};

}  // namespace

// The fallback buffer holds one message at a time, and the transport may not overwrite the one in
// flight before the protocol task has consumed it. An unadmitted connection, which never writes
// into the shared ring, waits up to InboundGate::WRITABLE_WAIT_MS for that and is then closed
// rather than parking the transport thread. An admitted connection's message longer than the ring
// takes waits only INBOUND_ACQUIRE_TIMEOUT_MS, as a ring acquire does, and then closes the
// connection too: a frame never received and decrypted would leave the Noise receive nonce
// behind. Either way the message in flight is kept. The Control rows consume the first message in
// time. The two rows that leave the first message pending wait out those bounds (about 600 ms
// together): the bound running out is the behavior under test.
TEST(InboundReceive, TheFallbackBufferHandsOverOneMessageAtATime) {
    struct Row {
        const char* name;
        bool admitted;
        bool consume_first;
        TestConnection::InboundRoute second_route;
    };
    const Row rows[] = {
        {"Control: unadmitted, consumed before the next arrives", false, true,
         TestConnection::InboundRoute::RECEIVE},
        {"unadmitted, the next arrives while the first is pending", false, false,
         TestConnection::InboundRoute::CLOSE},
        {"Control: admitted, consumed before the next arrives", true, true,
         TestConnection::InboundRoute::RECEIVE},
        {"admitted, the next arrives while the first is pending", true, false,
         TestConnection::InboundRoute::CLOSE},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        // A ring sized for JSON, so an admitted connection's longer messages take the buffer.
        InboundHarness h(inbound_ring_min_storage_bytes(INBOUND_JSON_MESSAGE_BYTES));
        h.conn.set_admitted(row.admitted);
        const size_t len = row.admitted ? h.ring.max_message_bytes() + 1 : 3;
        const std::vector<uint8_t> first(len, 0x01);
        const std::vector<uint8_t> second(len, 0x0A);

        ASSERT_EQ(h.receive(first), TestConnection::InboundRoute::RECEIVE);
        size_t taken_len = 0;
        EXPECT_EQ(h.ring.take(&taken_len, 0), nullptr) << "the message was written into the ring";
        EXPECT_FALSE(h.conn.inbound_gate().may_write()) << "the first message is in flight";

        InboundMessage pending;
        ASSERT_TRUE(h.conn.pending_message(pending));
        if (row.consume_first) {
            h.conn.consume_pending_message();
        }

        EXPECT_EQ(h.receive(second), row.second_route);
        ASSERT_TRUE(h.conn.pending_message(pending));
        const std::vector<uint8_t>& expected = row.consume_first ? second : first;
        EXPECT_EQ(std::vector<uint8_t>(pending.data, pending.data + pending.len), expected)
            << "the message in flight was overwritten or lost";
        const bool closed = row.second_route == TestConnection::InboundRoute::CLOSE;
        EXPECT_EQ(h.conn.close_transport_now_calls_, closed ? 1 : 0);
        EXPECT_EQ(h.conn.inbound_gate().is_detached(), closed);
    }
}

// An admitted connection's message that finds no ring item within INBOUND_ACQUIRE_TIMEOUT_MS
// closes the connection rather than being dropped: a frame never received and decrypted would
// leave the Noise receive nonce behind. Messages of the longest size the ring takes arrive with
// nothing taken until one finds no room; the Control row takes and returns each item, as the
// protocol task does, so the ring never fills. The closing row waits out the bound once (about
// 100 ms): the bound running out is the behavior under test.
TEST(InboundReceive, AnAdmittedMessageWithNoRingSpaceClosesTheConnection) {
    struct Row {
        const char* name;
        bool take_each;
        TestConnection::InboundRoute last_route;
    };
    const Row rows[] = {
        {"Control: each item taken before the next arrives", true,
         TestConnection::InboundRoute::RECEIVE},
        {"nothing taken until the ring is full", false, TestConnection::InboundRoute::CLOSE},
    };
    constexpr int MAX_MESSAGES = 8;
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundHarness h(inbound_ring_min_storage_bytes(INBOUND_JSON_MESSAGE_BYTES));
        h.conn.set_admitted(true);
        const std::vector<uint8_t> message(h.ring.max_message_bytes(), 0x5A);
        TestConnection::InboundRoute route = TestConnection::InboundRoute::RECEIVE;
        int received = 0;
        for (; received < MAX_MESSAGES; ++received) {
            route = h.receive(message);
            if (route != TestConnection::InboundRoute::RECEIVE) {
                break;
            }
            if (row.take_each) {
                size_t taken_len = 0;
                void* item = h.ring.take(&taken_len, 0);
                ASSERT_NE(item, nullptr) << "message " << received << " never reached the ring";
                h.conn.inbound_gate().note_item_taken();
                h.ring.return_item(item);
            }
        }
        EXPECT_EQ(route, row.last_route) << "after " << received << " messages";
        const bool closed = row.last_route == TestConnection::InboundRoute::CLOSE;
        EXPECT_EQ(h.conn.close_transport_now_calls_, closed ? 1 : 0);
        EXPECT_EQ(h.conn.inbound_gate().is_detached(), closed);
    }
}

// A message larger than the cap in force closes the connection: before admission that is
// InboundGate::PRE_ADMISSION_MESSAGE_BYTES, after it one Noise frame (INBOUND_MAX_MESSAGE_BYTES).
// No conforming peer sends either, and the transport learns the length before receiving a byte.
TEST(InboundReceive, AMessageOverTheCapInForceClosesTheConnection) {
    struct Row {
        const char* name;
        bool admitted;
        size_t len;
        TestConnection::InboundRoute route;
    };
    const Row rows[] = {
        {"Control: pre-admission, at the cap", false, InboundGate::PRE_ADMISSION_MESSAGE_BYTES,
         TestConnection::InboundRoute::RECEIVE},
        {"pre-admission, one byte over", false, InboundGate::PRE_ADMISSION_MESSAGE_BYTES + 1,
         TestConnection::InboundRoute::CLOSE},
        {"Control: pre-admission, one byte", false, 1, TestConnection::InboundRoute::RECEIVE},
        {"pre-admission, zero length", false, 0, TestConnection::InboundRoute::DROP},
        {"Control: admitted, one Noise frame", true, INBOUND_MAX_MESSAGE_BYTES,
         TestConnection::InboundRoute::RECEIVE},
        {"admitted, one byte over a Noise frame", true, INBOUND_MAX_MESSAGE_BYTES + 1,
         TestConnection::InboundRoute::CLOSE},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundHarness h;
        h.conn.set_admitted(row.admitted);

        EXPECT_EQ(h.receive(std::vector<uint8_t>(row.len, 0x5A)), row.route);
        const bool closed = row.route == TestConnection::InboundRoute::CLOSE;
        EXPECT_EQ(h.conn.close_transport_now_calls_, closed ? 1 : 0);
        EXPECT_EQ(h.conn.inbound_gate().is_detached(), closed)
            << "a closed connection must stop dispatching what it already received";
    }
}

// A message split across WebSocket frames is assembled in the connection's fallback buffer and
// held to the same cap as a single-frame message, applied to its running total, so a peer cannot
// pass the cap with frames that are each under it.
TEST(InboundReceive, AMultiFrameMessageIsCappedOnItsRunningTotal) {
    struct Row {
        const char* name;
        bool admitted;
        size_t cap;
        size_t second_len;
        TestConnection::InboundRoute route;
    };
    const Row rows[] = {
        {"Control: pre-admission, total at the cap", false,
         InboundGate::PRE_ADMISSION_MESSAGE_BYTES, 10, TestConnection::InboundRoute::RECEIVE},
        {"pre-admission, total one byte over", false, InboundGate::PRE_ADMISSION_MESSAGE_BYTES,
         11, TestConnection::InboundRoute::CLOSE},
        {"Control: admitted, total at one Noise frame", true, INBOUND_MAX_MESSAGE_BYTES, 10,
         TestConnection::InboundRoute::RECEIVE},
        {"admitted, total one byte over", true, INBOUND_MAX_MESSAGE_BYTES, 11,
         TestConnection::InboundRoute::CLOSE},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundHarness h;
        h.conn.set_admitted(row.admitted);
        const size_t first_len = row.cap - 10;

        const TestConnection::InboundTarget first = h.conn.begin_inbound_fragment(
            first_len, /*first=*/true, /*is_text=*/false, platform_time_us());
        ASSERT_EQ(first.route, TestConnection::InboundRoute::RECEIVE);
        std::memset(first.data, 0x11, first_len);
        h.conn.end_inbound_fragment(first_len, /*last=*/false);

        const TestConnection::InboundTarget second = h.conn.begin_inbound_fragment(
            row.second_len, /*first=*/false, /*is_text=*/false, platform_time_us());
        EXPECT_EQ(second.route, row.route);
        EXPECT_EQ(h.conn.close_transport_now_calls_,
                  row.route == TestConnection::InboundRoute::CLOSE ? 1 : 0);
        if (second.route != TestConnection::InboundRoute::RECEIVE) {
            continue;
        }
        std::memset(second.data, 0x22, row.second_len);
        h.conn.end_inbound_fragment(row.second_len, /*last=*/true);

        // The whole message reaches the protocol task: in a ring item once admitted (the one
        // copy this path costs), as the pending message before.
        size_t len = 0;
        if (row.admitted) {
            void* item = h.ring.take(&len, 0);
            ASSERT_NE(item, nullptr);
            h.conn.inbound_gate().note_item_taken();
            h.ring.return_item(item);
        } else {
            InboundMessage pending;
            ASSERT_TRUE(h.conn.pending_message(pending));
            len = pending.len;
        }
        EXPECT_EQ(len, row.cap);
    }
}

// An admitted connection's message longer than the ring takes (a ring sized for JSON, as a client
// without the player or artwork role has) is still delivered: through the fallback buffer, and in
// its place between the connection's ring items. The protocol task gets it only once the ring item
// received before it is taken, and the transport writes nothing more until it is consumed. The
// Control rows fit their ring and arrive in a ring item behind the first.
TEST(InboundReceive, AMessageLongerThanTheRingTakesArrivesInOrderThroughTheFallbackBuffer) {
    struct Row {
        const char* name;
        size_t ring_bytes;
        size_t extra_len;  // added to the ring's max_message_bytes()
        bool via_fallback;
    };
    const size_t json_ring = inbound_ring_min_storage_bytes(INBOUND_JSON_MESSAGE_BYTES);
    const Row rows[] = {
        {"Control: the longest message a JSON-sized ring takes", json_ring, 0, false},
        {"one byte longer than a JSON-sized ring takes", json_ring, 1, true},
        {"a maximal frame on a JSON-sized ring", json_ring,
         INBOUND_MAX_MESSAGE_BYTES - INBOUND_JSON_MESSAGE_BYTES, true},
        {"Control: a maximal frame on a ring sized for one", INBOUND_RING_MIN_STORAGE_BYTES, 0,
         false},
    };
    const std::vector<uint8_t> first{0x01, 0x02, 0x03};

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundHarness h(row.ring_bytes);
        h.conn.set_admitted(true);
        const std::vector<uint8_t> second(h.ring.max_message_bytes() + row.extra_len, 0x5A);

        ASSERT_EQ(h.receive(first), TestConnection::InboundRoute::RECEIVE);
        ASSERT_EQ(h.receive(second), TestConnection::InboundRoute::RECEIVE)
            << "the longer message was not delivered";
        EXPECT_EQ(h.conn.close_transport_now_calls_, 0);

        // The ring item received first comes first, whichever way the second arrived.
        InboundMessage pending;
        EXPECT_FALSE(h.conn.pending_message(pending))
            << "the fallback message overtook the ring item received before it";
        size_t len = 0;
        void* item = h.ring.take(&len, 0);
        ASSERT_NE(item, nullptr);
        EXPECT_EQ(std::vector<uint8_t>(inbound_item_bytes(item), inbound_item_bytes(item) + len),
                  first);
        h.conn.inbound_gate().note_item_taken();
        h.ring.return_item(item);

        if (row.via_fallback) {
            EXPECT_EQ(h.ring.take(&len, 0), nullptr) << "the longer message went into the ring";
            EXPECT_FALSE(h.conn.inbound_gate().may_write())
                << "the transport may overwrite the message before it is consumed";
            ASSERT_TRUE(h.conn.pending_message(pending));
            EXPECT_FALSE(pending.data >= h.ring.storage() &&
                         pending.data < h.ring.storage() + row.ring_bytes);
            EXPECT_EQ(std::vector<uint8_t>(pending.data, pending.data + pending.len), second);
            h.conn.consume_pending_message();
        } else {
            item = h.ring.take(&len, 0);
            ASSERT_NE(item, nullptr);
            EXPECT_EQ(len, second.size());
            h.conn.inbound_gate().note_item_taken();
            h.ring.return_item(item);
            EXPECT_FALSE(h.conn.pending_message(pending));
        }
        EXPECT_EQ(h.conn.inbound_gate().in_flight(), 0U);
        EXPECT_TRUE(h.conn.inbound_gate().may_write());
    }
}

// A transport that stops part-way through a message it is receiving into a ring item cannot
// cancel the acquire, so it completes the item as DISCARD: the protocol task must never be handed
// it, and the connection's in-flight count must not keep a close waiting on it.
TEST(InboundReceive, AnAbandonedRingItemIsNeverHandedToTheProtocolTask) {
    struct Row {
        const char* name;
        bool abandon;
    };
    const Row rows[] = {{"Control: received", false}, {"abandoned part-way", true}};
    const std::vector<uint8_t> bytes{0x04, 0x05, 0x06, 0x07};

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundHarness h;
        h.conn.set_admitted(true);

        const TestConnection::InboundTarget target =
            h.conn.begin_inbound_message(bytes.size(), /*is_text=*/false, platform_time_us());
        ASSERT_EQ(target.route, TestConnection::InboundRoute::RECEIVE);
        ASSERT_TRUE(in_ring_storage(h.ring, target.data)) << "an admitted message skipped the ring";
        std::memcpy(target.data, bytes.data(), bytes.size() / 2);
        if (row.abandon) {
            h.conn.abandon_inbound_message();
        } else {
            std::memcpy(target.data + bytes.size() / 2, bytes.data() + bytes.size() / 2,
                        bytes.size() - bytes.size() / 2);
            h.conn.end_inbound_message(true);
        }

        size_t len = 0;
        void* item = h.ring.take(&len, 0);
        EXPECT_EQ(item != nullptr, !row.abandon);
        if (item != nullptr) {
            const uint8_t* received = inbound_item_bytes(item);
            EXPECT_EQ(std::vector<uint8_t>(received, received + len), bytes);
            h.conn.inbound_gate().note_item_taken();
            h.ring.return_item(item);
        }
        EXPECT_EQ(h.conn.inbound_gate().in_flight(), 0U);
    }
}

// RFC 6455 section 5.4: a continuation frame continues an open fragmented message, and the
// fragments of one message are not interleaved with another data message. The ESP transports
// track no fragment state and pass either violation on, so the connection closes over it rather
// than append to a fallback buffer that may hold a message the protocol task is reading.
TEST(InboundReceive, AFrameOutOfFragmentSequenceClosesTheConnection) {
    // What the connection's fallback buffer holds when the second frame arrives: a pending
    // single-frame message, the first fragment of an open message, or a pending message
    // assembled from fragments.
    enum class Before : uint8_t { PENDING_SINGLE, OPEN_ASSEMBLY, PENDING_ASSEMBLED };
    enum class Second : uint8_t { CONTINUATION, SINGLE_FRAME, FIRST_FRAGMENT };
    struct Row {
        const char* name;
        Before before;
        Second second;
        TestConnection::InboundRoute route;
    };
    const Row rows[] = {
        {"Control: continuation after a first fragment", Before::OPEN_ASSEMBLY,
         Second::CONTINUATION, TestConnection::InboundRoute::RECEIVE},
        {"continuation with no fragmented message open", Before::PENDING_SINGLE,
         Second::CONTINUATION, TestConnection::InboundRoute::CLOSE},
        {"continuation after a fragmented message ended", Before::PENDING_ASSEMBLED,
         Second::CONTINUATION, TestConnection::InboundRoute::CLOSE},
        {"single-frame message inside a fragmented message", Before::OPEN_ASSEMBLY,
         Second::SINGLE_FRAME, TestConnection::InboundRoute::CLOSE},
        {"fragmented message started inside another", Before::OPEN_ASSEMBLY,
         Second::FIRST_FRAGMENT, TestConnection::InboundRoute::CLOSE},
    };
    const std::vector<uint8_t> single{0x01, 0x02, 0x03};
    const std::vector<uint8_t> first{0x11, 0x12};
    const std::vector<uint8_t> second{0x21, 0x22, 0x23, 0x24};

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundHarness h;

        // An unadmitted connection's message waits in the fallback buffer for the protocol task.
        if (row.before == Before::PENDING_SINGLE) {
            ASSERT_EQ(h.receive(single), TestConnection::InboundRoute::RECEIVE);
        } else {
            const TestConnection::InboundTarget target = h.conn.begin_inbound_fragment(
                first.size(), /*first=*/true, /*is_text=*/false, platform_time_us());
            ASSERT_EQ(target.route, TestConnection::InboundRoute::RECEIVE);
            std::memcpy(target.data, first.data(), first.size());
            h.conn.end_inbound_fragment(first.size(), row.before == Before::PENDING_ASSEMBLED);
        }
        InboundMessage pending;
        const uint8_t* pending_data = nullptr;
        if (row.before != Before::OPEN_ASSEMBLY) {
            ASSERT_TRUE(h.conn.pending_message(pending));
            pending_data = pending.data;
        }

        TestConnection::InboundRoute route;
        if (row.second != Second::SINGLE_FRAME) {
            const TestConnection::InboundTarget target = h.conn.begin_inbound_fragment(
                second.size(), /*first=*/row.second == Second::FIRST_FRAGMENT,
                /*is_text=*/false, platform_time_us());
            route = target.route;
            if (route == TestConnection::InboundRoute::RECEIVE) {
                std::memcpy(target.data, second.data(), second.size());
                h.conn.end_inbound_fragment(second.size(), /*last=*/true);
            }
        } else {
            route = h.receive(second);
        }
        EXPECT_EQ(route, row.route);
        const bool closed = row.route == TestConnection::InboundRoute::CLOSE;
        EXPECT_EQ(h.conn.close_transport_now_calls_, closed ? 1 : 0);
        EXPECT_EQ(h.conn.inbound_gate().is_detached(), closed);

        if (row.before == Before::OPEN_ASSEMBLY) {
            if (!closed) {
                std::vector<uint8_t> assembled = first;
                assembled.insert(assembled.end(), second.begin(), second.end());
                ASSERT_TRUE(h.conn.pending_message(pending));
                EXPECT_EQ(std::vector<uint8_t>(pending.data, pending.data + pending.len),
                          assembled);
            }
            continue;
        }
        // The message the protocol task holds is neither moved nor overwritten.
        const std::vector<uint8_t>& held = row.before == Before::PENDING_SINGLE ? single : first;
        ASSERT_TRUE(h.conn.pending_message(pending));
        EXPECT_EQ(pending.data, pending_data) << "the pending message's buffer moved";
        EXPECT_EQ(std::vector<uint8_t>(pending.data, pending.data + pending.len), held);
    }
}

// The liveness stamp is taken when a message is complete, not when its first bytes arrive: a
// transport stalled part-way through a message holds a ring item every later item waits behind,
// and the liveness watchdog is what bounds that hold.
TEST(InboundReceive, TheLivenessStampIsTakenWhenAMessageCompletes) {
    enum class Shape : uint8_t { SINGLE_FRAME, MULTI_FRAME };
    struct Row {
        const char* name;
        bool admitted;
        bool detached;  // the transport drops the message rather than receiving it
        Shape shape;
        bool complete;  // the transport delivers the message's last bytes
        bool stamped;
    };
    const Row rows[] = {
        {"Control: admitted single frame, completed", true, false, Shape::SINGLE_FRAME, true,
         true},
        {"admitted single frame, ring item acquired and not completed", true, false,
         Shape::SINGLE_FRAME, false, false},
        {"Control: unadmitted single frame, completed", false, false, Shape::SINGLE_FRAME, true,
         true},
        {"unadmitted single frame, begun and not completed", false, false, Shape::SINGLE_FRAME,
         false, false},
        {"Control: multi-frame message, last fragment in", true, false, Shape::MULTI_FRAME, true,
         true},
        {"multi-frame message, first fragment only", true, false, Shape::MULTI_FRAME, false,
         false},
        // A dropped single frame holds nothing, so its start stands in for its completion.
        {"dropped single frame, stamped at its start", true, true, Shape::SINGLE_FRAME, false,
         true},
        {"Control: dropped multi-frame message, last fragment in", true, true, Shape::MULTI_FRAME,
         true, true},
        {"dropped multi-frame message, first fragment only", true, true, Shape::MULTI_FRAME, false,
         false},
    };
    const std::vector<uint8_t> bytes{0x31, 0x32, 0x33, 0x34};

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundHarness h;
        h.conn.set_admitted(row.admitted);
        if (row.detached) {
            h.conn.inbound_gate().detach();
        }
        const TestConnection::InboundRoute route = row.detached
                                                       ? TestConnection::InboundRoute::DROP
                                                       : TestConnection::InboundRoute::RECEIVE;
        ASSERT_EQ(h.conn.get_last_receive_time_us(), 0U);

        if (row.shape == Shape::SINGLE_FRAME) {
            const TestConnection::InboundTarget target =
                h.conn.begin_inbound_message(bytes.size(), /*is_text=*/false, platform_time_us());
            ASSERT_EQ(target.route, route);
            if (target.route == TestConnection::InboundRoute::RECEIVE) {
                std::memcpy(target.data, bytes.data(), bytes.size());
                EXPECT_EQ(h.conn.get_last_receive_time_us(), 0U) << "stamped before completion";
                if (row.complete) {
                    h.conn.end_inbound_message(true);
                }
            }
        } else {
            const TestConnection::InboundTarget target = h.conn.begin_inbound_fragment(
                bytes.size(), /*first=*/true, /*is_text=*/false, platform_time_us());
            ASSERT_EQ(target.route, route);
            size_t received = 0;
            if (target.route == TestConnection::InboundRoute::RECEIVE) {
                std::memcpy(target.data, bytes.data(), bytes.size());
                received = bytes.size();
            }
            h.conn.end_inbound_fragment(received, /*last=*/false);
            EXPECT_EQ(h.conn.get_last_receive_time_us(), 0U) << "stamped before completion";
            if (row.complete) {
                const TestConnection::InboundTarget last = h.conn.begin_inbound_fragment(
                    0, /*first=*/false, /*is_text=*/false, platform_time_us());
                ASSERT_EQ(last.route, route);
                h.conn.end_inbound_fragment(0, /*last=*/true);
            }
        }
        EXPECT_EQ(h.conn.get_last_receive_time_us() != 0U, row.stamped);

        // Every acquired item is completed (see InboundRing::acquire()).
        h.conn.abandon_inbound_message();
        size_t len = 0;
        while (void* item = h.ring.take(&len, 0)) {
            h.conn.inbound_gate().note_item_taken();
            h.ring.return_item(item);
        }
    }
}
