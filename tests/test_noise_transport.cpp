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
#include "crypto/keys.h"
#include "noise_handshake.h"
#include "noise_session.h"
#include "noise_test_helpers.h"
#include "platform/base64.h"
#include "platform/crypto.h"
#include "platform/types.h"
#include "record_store.h"
#include "sendspin/config.h"
#include "sendspin/types.h"

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
#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

// =============================================================================
// Minimal in-process SendspinConnection for testing transport helpers
// =============================================================================

/// @brief Concrete SendspinConnection that captures sent binary frames.
/// Used to verify encrypt_and_send_frame / fragment_and_send output without a real WS socket.
class TestConnection : public SendspinConnection {
public:
    TestConnection() = default;
    ~TestConnection() override = default;

    // --- Interface stubs ---

    void start() override {}
    void loop() override {}
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

    SsErr send_text_message(const std::string& msg, SendCompleteCallback cb,
                            bool /*allow_before_hello*/) override {
        sent_text_.push_back(msg);
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }

    SsErr send_binary_message(const uint8_t* data, size_t len, SendCompleteCallback cb,
                              bool /*allow_before_hello*/) override {
        sent_binary_.push_back(std::vector<uint8_t>(data, data + len));
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }

    bool send_time_message() override { return true; }

    // --- Test helpers ---

    /// Inject a fully assembled binary frame (plaintext simulation after WS reassembly)
    /// into the dispatch path, bypassing the WS layer.
    void inject_binary_payload(const uint8_t* data, size_t len, int64_t receive_time = 0) {
        uint8_t* dest = this->prepare_receive_buffer(len);
        if (dest != nullptr) {
            std::memcpy(dest, data, len);
            this->commit_receive_buffer(len);
        }
        this->dispatch_completed_message(/*is_text=*/false, receive_time);
    }

    /// Inject a fully assembled TEXT frame into the dispatch path, bypassing the WS layer.
    /// Used to drive the pre-transport Noise handshake (client/init, server/init,
    /// noise/handshake) the same way a real WS TEXT frame would.
    void inject_text_payload(const std::string& text, int64_t receive_time = 0) {
        uint8_t* dest = this->prepare_receive_buffer(text.size());
        if (dest != nullptr) {
            std::memcpy(dest, text.data(), text.size());
            this->commit_receive_buffer(text.size());
        }
        this->dispatch_completed_message(/*is_text=*/true, receive_time);
    }

    /// Install a noise session directly (bypasses handshake, for transport-only tests).
    void set_noise_session(std::unique_ptr<NoiseSession> session) {
        this->noise_transport_.activate(std::move(session));
        this->noise_handshake_complete_.store(true, std::memory_order_release);
    }

    /// Direct access to NoiseTransport::send_binary() for tests exercising the binary send
    /// path (there is no connection-level wrapper; production code has no client-to-server
    /// binary message today).
    SsErr test_send_binary(const uint8_t* data, size_t len) {
        return this->noise_transport_.send_binary(data, len);
    }

    /// Direct access to NoiseTransport::accept_plaintext() for feeding already-decrypted frames
    /// through the reassembly state machine, independent of decrypt_in_place. Lets a test judge
    /// an emitted frame sequence the way a peer would without standing up a second live session.
    NoiseTransport::CompleteMessage test_accept_plaintext(uint8_t* pt, size_t len) {
        return this->noise_transport_.accept_plaintext(pt, len);
    }

    // --- Direct access to the receive-buffer cap, bypassing WS/dispatch ---

    uint8_t* test_prepare_receive_buffer(size_t data_len) {
        return this->prepare_receive_buffer(data_len);
    }
    void test_commit_receive_buffer(size_t data_len) { this->commit_receive_buffer(data_len); }
    size_t test_write_offset() const { return this->websocket_write_offset_; }

    // Accumulated outgoing messages
    std::vector<std::string> sent_text_;
    std::vector<std::vector<uint8_t>> sent_binary_;

    // Reasons passed to disconnect(), in call order.
    std::vector<SendspinGoodbyeReason> disconnect_calls_;

    // Number of times close_transport_now() was invoked (the silent-close path; see
    // close_silently(), which calls this instead of disconnect() so it never blocks/joins the
    // network thread it runs on).
    int close_transport_now_calls_{0};
};

/// TestConnection whose send_binary_message() capture is serialized by its own mutex, so
/// concurrent test threads can push into sent_binary_ without racing the vector itself. This
/// mutex guards only the capture; it deliberately does not serialize the encrypt, which is
/// NoiseTransport::session_mutex_'s job and is what ConcurrentSendsDoNotInterleaveFragments
/// exercises. Frames land in sent_binary_ in the order they reached the sink, which is the
/// order they would reach the wire.
class ConcurrentCaptureConnection : public TestConnection {
public:
    SsErr send_binary_message(const uint8_t* data, size_t len, SendCompleteCallback cb,
                              bool allow_before_hello) override {
        std::lock_guard<std::mutex> lock(this->capture_mutex_);
        return TestConnection::send_binary_message(data, len, cb, allow_before_hello);
    }

private:
    std::mutex capture_mutex_;
};

// =============================================================================
// Helpers shared by handshake tests
// =============================================================================

/// Build and return `server/init` JSON for the given server_id and version.
static std::string make_server_init(const std::string& server_id, int version = 1) {
    JsonDocument doc;
    doc["type"] = "server/init";
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

// =============================================================================
// Full handshake loopback helper
// =============================================================================

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
    rs.store_record_superseding(std::move(rec));

    // -----------------------------------------------------------------
    // Create the NoiseHandshake (our responder driver)
    // -----------------------------------------------------------------
    NoiseHandshake nh(client_id, rs, suite_name);

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

// =============================================================================
// Suite-parameterized full handshake tests
// =============================================================================

TEST(NoiseHandshakeLoopback, KKpsk2ChaChaPoly_FullHandshake) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value()) << "ChaChaPoly loopback handshake failed";
    EXPECT_TRUE(r->responder_session->handshake_complete());
    EXPECT_NE(r->initiator.send_cs, nullptr);
    EXPECT_NE(r->initiator.recv_cs, nullptr);
}

// =============================================================================
// Handshake hash is available and non-zero after split
// =============================================================================

TEST(NoiseHandshakeLoopback, HandshakeHashAvailable) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    const auto& hash = r->responder_session->handshake_hash();
    bool all_zero = std::all_of(hash.begin(), hash.end(), [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zero) << "handshake_hash() should not be all-zero after successful handshake";
}

// =============================================================================
// Transport round-trip (both directions)
// =============================================================================

/// @brief Encrypt with initiator send_cs, decrypt with NoiseSession (responder recv),
/// and vice versa.
static void check_transport_roundtrip(LoopbackResult& r, const std::vector<uint8_t>& plaintext) {
    // Initiator -> Responder direction (initiator.send_cs, responder.recv)
    {
        std::vector<uint8_t> ct(plaintext.size() + 16);
        std::copy(plaintext.begin(), plaintext.end(), ct.begin());

        NoiseBuffer buf;
        noise_buffer_set_inout(buf, ct.data(), plaintext.size(), ct.size());
        ASSERT_EQ(noise_cipherstate_encrypt(r.initiator.send_cs, &buf), NOISE_ERROR_NONE);
        ct.resize(buf.size);

        size_t pt_len = r.responder_session->decrypt(ct.data(), ct.size());
        ASSERT_GT(pt_len, 0u);
        ct.resize(pt_len);
        EXPECT_EQ(ct, plaintext);
    }

    // Responder -> Initiator direction (responder.send, initiator.recv_cs)
    {
        std::vector<uint8_t> buf_v(plaintext.size() + 16);
        std::copy(plaintext.begin(), plaintext.end(), buf_v.begin());

        size_t ct_len = r.responder_session->encrypt(buf_v.data(), plaintext.size(), buf_v.size());
        ASSERT_GT(ct_len, 0u);

        NoiseBuffer buf;
        noise_buffer_set_inout(buf, buf_v.data(), ct_len, ct_len);
        ASSERT_EQ(noise_cipherstate_decrypt(r.initiator.recv_cs, &buf), NOISE_ERROR_NONE);
        ASSERT_EQ(buf.size, plaintext.size());
        std::vector<uint8_t> pt(buf_v.data(), buf_v.data() + buf.size);
        EXPECT_EQ(pt, plaintext);
    }
}

TEST(NoiseTransport, JsonRoundTrip_ChaChaPoly) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    // Type byte 0x00 (JSON body) + JSON string
    std::string json_text = "{\"hello\":\"world\"}";
    std::vector<uint8_t> plaintext;
    plaintext.push_back(0x00);  // MSG_TYPE_JSON_BODY
    plaintext.insert(plaintext.end(), json_text.begin(), json_text.end());
    check_transport_roundtrip(*r, plaintext);
}

TEST(NoiseTransport, BinaryNonZeroTypeRoundTrip) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    // Type byte 0x01 (binary role message) + arbitrary binary data
    std::vector<uint8_t> plaintext = {0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF};
    check_transport_roundtrip(*r, plaintext);
}

// =============================================================================
// Fragment and reassemble (TestConnection dispatch loop)
// =============================================================================

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

// send_app_json routes plaintext before a transport session exists and encrypted afterwards. The
// routing decision reads the atomic noise_active_ flag (set alongside the session), not the
// noise_session_ unique_ptr.
TEST(NoiseTransport, SendAppJson_RoutesRawBeforeSessionEncryptedAfter) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;

    // Before a session: send_app_json must send a raw TEXT frame.
    const std::string pre = "{\"type\":\"client/init\"}";
    EXPECT_EQ(conn.send_app_json(pre, nullptr, /*allow_before_hello=*/true), SsErr::OK);
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
    conn.on_json_message_cb = [&dispatched_json](SendspinConnection* /*c*/, const char* data,
                                                  size_t len, int64_t /*ts*/) {
        dispatched_json = std::string(data, len);
    };

    // Inject the ciphertext as if received from the wire
    conn.inject_binary_payload(ct.data(), ct.size());

    EXPECT_EQ(dispatched_json, json);
}

// =============================================================================
// Fragmentation: payload just over MAX_TRANSPORT_PLAINTEXT
// =============================================================================

TEST(NoiseTransport, FragmentOverMaxTransportPlaintext) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    // Wire up JSON dispatch to collect reassembled messages
    std::string received_json;
    conn.on_json_message_cb = [&received_json](SendspinConnection* /*c*/, const char* data,
                                                size_t len, int64_t /*ts*/) {
        received_json = std::string(data, len);
    };

    // Build a JSON payload larger than MAX_TRANSPORT_PLAINTEXT (65519).
    // plaintext = [0x00] + json, so json must be >= 65519 bytes.
    std::string large_json(65520, 'A');  // 65520 'A' chars
    EXPECT_EQ(conn.send_encrypted_text(large_json), SsErr::OK);

    EXPECT_GE(conn.sent_binary_.size(), 2u);

    // The responder session was moved into conn, so decrypting the captured frames here would
    // need a second handshake to recover matching keys. That full decrypt-and-reassemble path is
    // already covered by ReceiveEncryptedBinary_JsonDispatch; this test only checks the structural
    // shape of the fragmented output: at least two frames, each within the AEAD-tagged size cap.
    EXPECT_GE(conn.sent_binary_.size(), 2u);
    for (const auto& frame : conn.sent_binary_) {
        // Each encrypted frame = plaintext + 16-byte AEAD tag
        EXPECT_LE(frame.size(), static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT) + 16);
    }
}

// =============================================================================
// Error cases: driver abort on bad inputs
// =============================================================================

TEST(NoiseHandshakeDriver, CounterpartyMismatchAborts) {
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();
    Identity other_server = Identity::generate().value();  // A different server

    // PSK bound to other_server, not server_id
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id_val = psk_id_for(psk);

    RecordStore rs(nullptr);
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_val;
    rec.psk = psk;
    rec.server_id = other_server.peer_id();  // bound to other_server
    rs.store_record_superseding(std::move(rec));

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));

    std::string client_init = nh.build_client_init();
    std::string server_init_text = make_server_init(server_id.peer_id());
    std::string prologue_str = client_init + server_init_text;
    const uint8_t* prologue = reinterpret_cast<const uint8_t*>(prologue_str.data());
    size_t prologue_len = prologue_str.size();

    // server/init: NEED_MORE
    auto r1 = nh.on_text_frame(server_init_text, [](const std::string&) { return true; });
    EXPECT_EQ(r1, HandshakeFrameResult::NEED_MORE);

    // Build initiator, using psk (matching the stored PSK)
    NoiseHandshakeState* init_hs_raw =
        build_initiator(std::string(NOISE_SUITE_CHACHAPOLY), server_id.private_bytes.data(),
                           server_id.public_bytes.data(), client_id.public_bytes.data(), psk.data(),
                           prologue, prologue_len);
    ASSERT_NE(init_hs_raw, nullptr);
    HsGuard guard(init_hs_raw);

    std::string msg1_text = build_msg1_envelope(init_hs_raw, psk_id_val);
    ASSERT_FALSE(msg1_text.empty());

    // Should abort because PSK is bound to other_server, not server_id
    auto r2 = nh.on_text_frame(msg1_text, [](const std::string&) { return true; });
    EXPECT_EQ(r2, HandshakeFrameResult::ABORT);
}

// =============================================================================
// psk_category in the Noise message 1 payload
// =============================================================================

// Drives the handshake driver to Noise message 1 against a store holding one long-term record,
// with the message 1 payload the caller supplies, and reports what the driver made of it. The
// initiator always uses the record's PSK, so message 1 authenticates and the payload is the only
// variable.
/// What the driver made of one Noise message 1.
struct Msg1Outcome {
    HandshakeFrameResult result{HandshakeFrameResult::ABORT};
    /// Category of the PSK the driver bound, when the handshake completed.
    std::optional<PskCategory> category;
    /// Whether the peer that sent message 1 could read the message 2 that came back, i.e. whether
    /// both sides mixed in the same PSK.
    bool peer_read_msg2{false};
};

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
        rs.store_record_superseding(std::move(rec));
    }

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
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

// Control: the same psk_id under the category the client actually holds it in resolves to the
// record, and the peer that sent message 1 can read the message 2 that comes back.
TEST(NoiseHandshakeDriver, MatchingPskCategoryCompletes) {
    Msg1Outcome outcome = run_msg1_with_payload([](const std::string& psk_id) {
        return R"({"psk_id":")" + psk_id + R"(","psk_category":"lt"})";
    });
    EXPECT_EQ(outcome.result, HandshakeFrameResult::COMPLETE);
    EXPECT_EQ(outcome.category, PskCategory::LONG_TERM);
    EXPECT_TRUE(outcome.peer_read_msg2);
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

// messaging.md "noise/handshake": a psk_category outside the three defined codes makes the payload
// malformed, and connection.md "Failure Handling" makes that a silent failure. ABORT is how the
// driver reports one: SendspinConnection closes the socket without sending anything.
TEST(NoiseHandshakeDriver, UnknownPskCategoryAborts) {
    EXPECT_EQ(run_msg1_with_payload([](const std::string& psk_id) {
                  return R"({"psk_id":")" + psk_id + R"(","psk_category":"xx"})";
              }).result,
              HandshakeFrameResult::ABORT);
}

// A payload with no psk_category at all is malformed for the same reason: the category is not
// optional, and guessing one would defeat the scoping above.
TEST(NoiseHandshakeDriver, MissingPskCategoryAborts) {
    EXPECT_EQ(run_msg1_with_payload([](const std::string& psk_id) {
                  return R"({"psk_id":")" + psk_id + R"("})";
              }).result,
              HandshakeFrameResult::ABORT);
}

// messaging.md "server/error": the server sends it in place of server/init when it cannot accept
// our client/init, then closes. The handshake aborts, and the reason it carries is logged rather
// than the frame being treated as an unparseable server/init.
TEST(NoiseHandshakeDriver, ServerErrorWhileAwaitingServerInitAborts) {
    Identity client_id = Identity::generate().value();
    RecordStore rs(nullptr);

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
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

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
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

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
    nh.build_client_init();
    ASSERT_EQ(nh.on_text_frame(make_server_init(server_id.peer_id()),
                               [](const std::string&) { return true; }),
              HandshakeFrameResult::NEED_MORE);

    auto r = nh.on_text_frame(R"({"type":"server/error","payload":{"reason":"malformed"}})",
                              [](const std::string&) { return true; });
    EXPECT_EQ(r, HandshakeFrameResult::ABORT);
    EXPECT_EQ(nh.server_error_reason(), "malformed");
}

TEST(NoiseHandshakeDriver, MalformedServerInitAborts) {
    Identity client_id = Identity::generate().value();
    RecordStore rs(nullptr);

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
    nh.build_client_init();

    // Send a malformed server/init (wrong type field)
    auto r = nh.on_text_frame("{\"type\":\"wrong/type\",\"payload\":{\"version\":1,\"server_id\":"
                               "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}",
                               [](const std::string&) { return true; });
    EXPECT_EQ(r, HandshakeFrameResult::ABORT);
}

TEST(NoiseHandshakeDriver, WrongVersionAborts) {
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();
    RecordStore rs(nullptr);

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
    nh.build_client_init();

    // Version 99 should be rejected
    std::string bad_version = make_server_init(server_id.peer_id(), /*version=*/99);
    auto r = nh.on_text_frame(bad_version, [](const std::string&) { return true; });
    EXPECT_EQ(r, HandshakeFrameResult::ABORT);
}

// =============================================================================
// accept_plaintext: fragment sequence rules (messaging.md "Fragmentation")
// =============================================================================

/// A receiver connection wired to a loopback handshake, with a helper that encrypts one
/// plaintext frame with the peer's send cipher and feeds it in as if it had arrived off the
/// wire. Tracks how many complete messages of each kind were dispatched.
class FragmentReceiver {
public:
    explicit FragmentReceiver(LoopbackResult& r) : server_send_(r.initiator.send_cs) {
        this->conn_.set_noise_session(std::move(r.responder_session));
        this->conn_.on_json_message_cb = [this](SendspinConnection* /*c*/, const char* d, size_t n,
                                                int64_t /*t*/) {
            ++this->json_dispatched_;
            this->last_message_.assign(d, d + n);
        };
        this->conn_.on_binary_message_cb = [this](SendspinConnection* /*c*/, uint8_t* d, size_t n) {
            ++this->binary_dispatched_;
            this->last_message_.assign(d, d + n);
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

    TestConnection conn_;
    NoiseCipherState* server_send_;
    std::vector<uint8_t> last_message_;
    int json_dispatched_{0};
    int binary_dispatched_{0};
};

TEST(FragmentSequence, SingleFragmentCarryingBothFlagsDispatches) {
    // Control for every malformed case below: one frame with FIRST and LAST set is a complete,
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

TEST(FragmentSequence, FirstFragmentWhileOneIsInFlightCloses) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});
    ASSERT_FALSE(rx.closed());

    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});

    EXPECT_TRUE(rx.closed()) << "a first fragment while one is in flight is a malformed sequence";
    EXPECT_EQ(rx.json_dispatched_, 0);
    EXPECT_TRUE(rx.conn_.disconnect_calls_.empty());
    EXPECT_TRUE(rx.conn_.sent_text_.empty());
    EXPECT_TRUE(rx.conn_.sent_binary_.empty());
}

TEST(FragmentSequence, NonFirstFragmentWithNoneInFlightCloses) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_LAST, {'A', 'B'});

    EXPECT_TRUE(rx.closed()) << "a non-first fragment with none in flight is a malformed sequence";
    EXPECT_EQ(rx.json_dispatched_, 0);
    EXPECT_EQ(rx.binary_dispatched_, 0);
    EXPECT_TRUE(rx.conn_.disconnect_calls_.empty());
    EXPECT_TRUE(rx.conn_.sent_text_.empty());
    EXPECT_TRUE(rx.conn_.sent_binary_.empty());
}

TEST(FragmentSequence, NonFragmentMessageWhileOneIsInFlightCloses) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});
    ASSERT_FALSE(rx.closed());

    rx.inject({MSG_TYPE_JSON_BODY, 'H', 'i'});

    EXPECT_TRUE(rx.closed())
        << "a non-fragment binary message while one is in flight is a malformed sequence";
    EXPECT_EQ(rx.json_dispatched_, 0) << "the interloping message must not be dispatched either";
}

TEST(FragmentSequence, ReservedFlagBitCloses) {
    // Bits 2-7 are reserved and MUST be zero. Each is checked on its own so the mask cannot be
    // narrowed to a single bit and still pass.
    for (int bit = 2; bit < 8; ++bit) {
        auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
        ASSERT_TRUE(r.has_value());
        FragmentReceiver rx(*r);

        const uint8_t flags =
            static_cast<uint8_t>(FRAGMENT_FLAG_FIRST | FRAGMENT_FLAG_LAST | (1u << bit));
        rx.inject_fragment(flags, {MSG_TYPE_JSON_BODY, '{', '}'});

        EXPECT_TRUE(rx.closed()) << "reserved flag bit " << bit << " must close the connection";
        EXPECT_EQ(rx.json_dispatched_, 0) << "reserved flag bit " << bit;
    }
}

TEST(FragmentSequence, OrigTypeOfOneCloses) {
    // Fragments do not nest: a first fragment naming the fragment ID as its orig_type is a
    // malformed sequence.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_FRAGMENT, 0xAA});

    EXPECT_TRUE(rx.closed());
    EXPECT_EQ(rx.binary_dispatched_, 0);
}

TEST(FragmentSequence, FragmentFrameWithoutFlagsByteCloses) {
    // A fragment frame that stops before its flags byte cannot be placed in the sequence at
    // all, so it is handled like the enumerated malformed sequences.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject({MSG_TYPE_FRAGMENT});

    EXPECT_TRUE(rx.closed());
    EXPECT_EQ(rx.binary_dispatched_, 0);
}

TEST(FragmentSequence, FirstFragmentWithoutOrigTypeCloses) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {});

    EXPECT_TRUE(rx.closed());
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

TEST(FragmentSequence, DiscardedSequenceStillEnforcesTheMalformedRules) {
    // A discarded message is still in flight: a non-fragment message arriving inside it is the
    // same malformed sequence it would be for a buffered one.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_RESERVED_FIRST, 0xAA});
    ASSERT_FALSE(rx.closed());

    rx.inject({MSG_TYPE_JSON_BODY, 'H', 'i'});

    EXPECT_TRUE(rx.closed());
    EXPECT_EQ(rx.json_dispatched_, 0);
}

TEST(FragmentSequence, OverCapMessageIsDiscardedWithoutClosing) {
    // Outgrowing MAX_REASSEMBLED_MESSAGE_BYTES is not one of the enumerated malformed sequences
    // (a legitimate peer could simply be sending an oversized image), so the rest of the message
    // is discarded, the connection stays open, and the sequence runs to its last fragment.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

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

TEST(FragmentSequence, FirstFragmentInsideADiscardedSequenceCloses) {
    // Discarding a message does not end its sequence, so a first fragment arriving inside one is
    // the same malformed sequence it would be for a buffered message. This is the case the
    // discard-instead-of-reset behavior makes reachable: resetting on the over-cap frame would
    // have made this look like a legitimate fresh message.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    FragmentReceiver rx(*r);

    const size_t chunk = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT) - 2;
    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, 0xAA});
    size_t data_len = 1;
    while (data_len + chunk <= MAX_REASSEMBLED_MESSAGE_BYTES) {
        rx.inject_fragment(0, std::vector<uint8_t>(chunk, 'X'));
        data_len += chunk;
    }
    rx.inject_fragment(0, std::vector<uint8_t>(chunk, 'X'));  // over the cap: now discarding
    ASSERT_FALSE(rx.closed());

    rx.inject_fragment(FRAGMENT_FLAG_FIRST, {MSG_TYPE_JSON_BODY, '{'});

    EXPECT_TRUE(rx.closed())
        << "a first fragment inside a discarded sequence is still a malformed sequence";
    EXPECT_EQ(rx.json_dispatched_, 0);
}

// =============================================================================
// Pre-authentication receive-buffer cap (prepare_receive_buffer)
// =============================================================================

TEST(ReceiveBufferCap, SingleFrameOverCapRejected) {
    // A single call declaring more than MAX_TRANSPORT_PLAINTEXT + 16 (the largest legitimate
    // Noise transport frame: plaintext plus the AEAD tag) must be rejected before any allocation,
    // since this call is sized from unauthenticated peer input (a WS frame-length probe or a
    // declared message length) on both the ESP server and ESP client paths.
    constexpr size_t cap = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT) + 16;
    TestConnection conn;
    uint8_t* dest = conn.test_prepare_receive_buffer(cap + 1);
    EXPECT_EQ(dest, nullptr);
    EXPECT_EQ(conn.test_write_offset(), 0u);
}

TEST(ReceiveBufferCap, CumulativeContinuationOverCapRejected) {
    // A WS continuation sequence that stays under the cap on each individual call but whose
    // running total crosses it must also be rejected: the check bounds
    // websocket_write_offset_ + data_len, not just the current call's data_len, so an attacker
    // cannot bypass the cap by splitting a message across many small continuation frames.
    constexpr size_t cap = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT) + 16;
    TestConnection conn;

    uint8_t* first = conn.test_prepare_receive_buffer(cap - 10);
    ASSERT_NE(first, nullptr);
    conn.test_commit_receive_buffer(cap - 10);
    EXPECT_EQ(conn.test_write_offset(), cap - 10);

    // This continuation only adds 20 bytes, but offset + data_len now exceeds the cap.
    uint8_t* second = conn.test_prepare_receive_buffer(20);
    EXPECT_EQ(second, nullptr);
    // Rejection tears the buffer down the same way an allocation failure does, so a stale
    // partial reassembly can never reach dispatch.
    EXPECT_EQ(conn.test_write_offset(), 0u);
}

TEST(ReceiveBufferCap, ExactlyAtCapAccepted) {
    // A frame declaring exactly the cap is the largest legitimate single Noise transport frame
    // and must be accepted, not just rejected past it.
    constexpr size_t cap = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT) + 16;
    TestConnection conn;
    uint8_t* dest = conn.test_prepare_receive_buffer(cap);
    ASSERT_NE(dest, nullptr);
    conn.test_commit_receive_buffer(cap);
    EXPECT_EQ(conn.test_write_offset(), cap);
}

TEST(NoiseTransportDispatch, HandshakeAbortClosesConnection) {
    // A fatal initial-handshake error (here: a psk_category outside the three the protocol
    // defines, which messaging.md "noise/handshake" makes a malformed payload) must close the
    // connection. An unresolvable psk_id is not such an error: it takes the Sentinel Fallback. This drives the full chain through dispatch_completed_message() ->
    // handle_noise_handshake_text(), using the same fake-connection pattern (TestConnection,
    // disconnect_calls_) as the other dispatch tests above. This differs from the
    // NoiseHandshakeDriver.*Aborts tests, which call NoiseHandshake::on_text_frame() directly
    // and only prove the state machine returns ABORT, not that the connection actually closes.
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();
    RecordStore rs(nullptr);

    TestConnection conn;
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

// =============================================================================
// End-to-end fragment + reassembly through the receive (decrypt) path
// =============================================================================

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

    std::string received;
    int calls = 0;
    conn.on_json_message_cb = [&received, &calls](SendspinConnection* /*c*/, const char* d,
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

TEST(NoiseTransport, FragmentReassembleBinaryReceive) {
    // A fragmented binary role message (non-zero type) reassembles and is dispatched with its
    // leading type byte preserved.
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());
    NoiseCipherState* server_send = r->initiator.send_cs;

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    std::vector<uint8_t> got;
    int calls = 0;
    conn.on_binary_message_cb = [&got, &calls](SendspinConnection* /*c*/, uint8_t* d, size_t n) {
        got.assign(d, d + n);
        ++calls;
    };

    std::vector<uint8_t> plaintext;
    plaintext.push_back(0x07);  // arbitrary non-zero binary role type
    for (size_t i = 0; i < 150000; ++i) {
        plaintext.push_back(static_cast<uint8_t>(i & 0xFF));
    }

    const auto frames = server_fragment_frames(plaintext);
    ASSERT_GE(frames.size(), 2u);
    for (const auto& f : frames) {
        const auto ct = raw_encrypt(server_send, f);
        EXPECT_FALSE(ct.empty());
        conn.inject_binary_payload(ct.data(), ct.size());
    }

    EXPECT_EQ(calls, 1);
    ASSERT_EQ(got.size(), plaintext.size());
    EXPECT_EQ(got, plaintext);  // full type-prefixed payload preserved
}

// =============================================================================
// Transport-mode decrypt failure: a tampered ciphertext is dropped, not dispatched
// =============================================================================

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
    conn.on_json_message_cb = [&calls](SendspinConnection* /*c*/, const char* /*d*/, size_t /*n*/,
                                       int64_t /*t*/) { ++calls; };
    conn.on_binary_message_cb = [&calls](SendspinConnection* /*c*/, uint8_t* /*d*/,
                                         size_t /*n*/) { ++calls; };

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

// =============================================================================
// Fragmentation threshold: exactly at and one byte over MAX_TRANSPORT_PLAINTEXT
// =============================================================================

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
    EXPECT_EQ(frames[1].size(), 2 + cont_cap);

    // Last fragment: [1][LAST][data...]
    EXPECT_EQ(frames[2][0], MSG_TYPE_FRAGMENT);
    EXPECT_EQ(frames[2][1], FRAGMENT_FLAG_LAST) << "the last fragment sets bit 0 and not bit 1";
    EXPECT_EQ(frames[2][2], 'A');
    EXPECT_EQ(frames[2].size(), 3u);
}

// The first and continuation frames have different caps: the first spends three plaintext bytes
// on [1, flags, orig_type] while continuations spend two on [1, flags]. A two-frame message never
// fills a continuation, so cont_cap is only observable once a third frame is needed.
TEST(NoiseTransport, FragmentContinuationCapAtThreeFrames) {
    auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
    ASSERT_TRUE(r.has_value());

    TestConnection conn;
    conn.set_noise_session(std::move(r->responder_session));

    const size_t maxp = static_cast<size_t>(MAX_TRANSPORT_PLAINTEXT);
    constexpr size_t TAG = 16;
    const size_t first_cap = maxp - 3;  // first frame: [1, flags, orig_type, data...]
    const size_t cont_cap = maxp - 2;   // continuation: [1, flags, data...]

    // json length == data_len, since plaintext is [0x00] + json. One byte past what two frames
    // can carry, so the run is first_cap + cont_cap + 1 and the tail lands in a third frame.
    const size_t json_len = first_cap + cont_cap + 1;
    EXPECT_EQ(conn.send_encrypted_text(std::string(json_len, 'A')), SsErr::OK);

    ASSERT_EQ(conn.sent_binary_.size(), 3u);
    EXPECT_EQ(conn.sent_binary_[0].size(), maxp + TAG) << "first frame fills first_cap";
    EXPECT_EQ(conn.sent_binary_[1].size(), maxp + TAG) << "middle frame fills cont_cap";
    EXPECT_EQ(conn.sent_binary_[2].size(), 3u + TAG)
        << "tail carries the single leftover byte behind its fragment type and flags";
}

// =============================================================================
// send_buf_ growth: the reused non-fragmented send buffer grows on demand instead of a fixed
// MAX_TRANSPORT_PLAINTEXT + 16 allocation. There is no accessor for its capacity, so these
// exercise growth indirectly: a sequence of increasing sizes (including a shrink back down,
// which must not lose or corrupt data) and the exact MAX_TRANSPORT_PLAINTEXT boundary, all
// round-tripping through encrypt/decrypt correctly on one shared transport instance.
// =============================================================================

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

// =============================================================================
// Malformed Noise message 1 aborts the handshake
// =============================================================================

TEST(NoiseHandshakeDriver, MalformedMsg1EmptyAborts) {
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();
    RecordStore rs(nullptr);

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
    nh.build_client_init();
    auto send_fn = [](const std::string&) { return true; };
    ASSERT_EQ(nh.on_text_frame(make_server_init(server_id.peer_id()), send_fn),
              HandshakeFrameResult::NEED_MORE);

    // Empty Noise bytes cannot be a valid msg1; the read must fail and the handshake abort.
    EXPECT_EQ(nh.on_text_frame(make_noise_handshake_envelope({}), send_fn),
              HandshakeFrameResult::ABORT);
}

TEST(NoiseHandshakeDriver, MalformedMsg1GarbageAborts) {
    Identity client_id = Identity::generate().value();
    Identity server_id = Identity::generate().value();
    RecordStore rs(nullptr);

    NoiseHandshake nh(client_id, rs, std::string(NOISE_SUITE_CHACHAPOLY));
    nh.build_client_init();
    auto send_fn = [](const std::string&) { return true; };
    ASSERT_EQ(nh.on_text_frame(make_server_init(server_id.peer_id()), send_fn),
              HandshakeFrameResult::NEED_MORE);

    // 64 bytes of garbage: well-formed base64url, but fails Noise authentication as msg1.
    std::vector<uint8_t> garbage(64, 0xAB);
    EXPECT_EQ(nh.on_text_frame(make_noise_handshake_envelope(garbage), send_fn),
              HandshakeFrameResult::ABORT);
}

// =============================================================================
// Concurrent sends
// =============================================================================

// The fragments of one logical message must reach the wire consecutively. A peer that sees a
// non-fragment frame while a fragmented message is in flight treats it as a spec
// "Malformed sequences" protocol error and closes the connection (accept_plaintext() sets
// malformed, and connection.cpp turns that into close_silently()).
//
// Sends come from more than one thread in production: on ESP the periodic client/time message
// is built and encrypted on the httpd worker task (async_send_time_text in
// esp/server_connection.cpp), while pairing sends encrypt on the main loop.
// fragment_and_send_locked() therefore has to hold session_mutex_ across every frame, not
// re-acquire it per frame; otherwise a small concurrent send lands a complete frame in the gap.
//
// This test races a fragmenting send against a stream of small sends on one transport, then
// replays the captured frames, in emission order, through an independent reassembly state
// machine and requires it to find no protocol violation. It detects a regression
// probabilistically (the interleave needs the two threads to collide in the gap), so it runs
// several rounds; it never fails spuriously, because correct locking cannot produce a malformed
// sequence at all.
TEST(NoiseTransport, ConcurrentSendsDoNotInterleaveFragments) {
    constexpr int ROUNDS = 4;
    // Fragments into roughly 14 frames at MAX_TRANSPORT_PLAINTEXT, giving many gaps to hit.
    constexpr size_t LARGE_JSON_BYTES = 900000;
    // Overlap margin so the small sender is still running as the large send starts.
    constexpr int MIN_SMALL_SENDS = 50;

    for (int round = 0; round < ROUNDS; ++round) {
        auto r = run_loopback_handshake(std::string(NOISE_SUITE_CHACHAPOLY));
        ASSERT_TRUE(r.has_value());

        ConcurrentCaptureConnection conn;
        conn.set_noise_session(std::move(r->responder_session));

        std::string large_json(LARGE_JSON_BYTES, 'A');
        std::atomic<bool> stop{false};

        std::thread big_sender([&]() {
            EXPECT_EQ(conn.send_encrypted_text(large_json), SsErr::OK);
            stop.store(true, std::memory_order_release);
        });

        std::thread small_sender([&]() {
            int i = 0;
            while (!stop.load(std::memory_order_acquire) || i < MIN_SMALL_SENDS) {
                conn.send_encrypted_text("{\"i\":" + std::to_string(i) + "}");
                ++i;
            }
        });

        big_sender.join();
        small_sender.join();

        ASSERT_GE(conn.sent_binary_.size(), 2u);

        // Decrypt in emission order with the peer's matching cipher. conn encrypted with the
        // responder session, so the initiator's recv cipher is its counterpart; the std::move
        // of responder_session above leaves r->initiator untouched.
        TestConnection receiver;
        size_t frame_index = 0;
        for (auto& frame : conn.sent_binary_) {
            std::vector<uint8_t> pt = raw_decrypt(r->initiator.recv_cs, frame);
            ASSERT_FALSE(pt.empty()) << "round " << round << " frame " << frame_index
                                     << " failed to decrypt";
            NoiseTransport::CompleteMessage msg =
                receiver.test_accept_plaintext(pt.data(), pt.size());
            ASSERT_FALSE(msg.malformed)
                << "round " << round << ": frame " << frame_index << " of "
                << conn.sent_binary_.size()
                << " broke the fragment sequence, so a concurrent send interleaved with a "
                   "fragmented one";
            ++frame_index;
        }
    }
}
