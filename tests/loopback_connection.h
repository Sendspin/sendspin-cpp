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

/// @file loopback_connection.h
/// @brief An in-process SendspinConnection stand-in over a live Noise session: the transport
/// suites and the source role's protocol-task tests play the protocol task against it and decrypt
/// what it sent with the initiator's ciphers.

#pragma once

#include "connection.h"
#include "crypto/constants.h"
#include "crypto/keys.h"
#include "noise_handshake.h"
#include "noise_session.h"
#include "noise_test_helpers.h"
#include "platform/base64.h"
#include "platform/crypto.h"
#include "record_store.h"
#include "record_test_helpers.h"
#include "sendspin/types.h"
#include "test_util.h"

#include <gtest/gtest.h>

// noise-c is a C library
extern "C" {
#include <noise/protocol/buffer.h>
#include <noise/protocol/constants.h>
#include <noise/protocol/handshakestate.h>
}

#include <ArduinoJson.h>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sendspin {

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
    void disconnect(SendspinGoodbyeReason reason) override {
        disconnect_calls_.push_back(reason);
    }
    void close_transport_now() override {
        this->close_transport_now_calls_++;
    }
    bool is_connected() const override { return true; }

    SsErr send_text_message(const std::string& msg) override {
        sent_text_.push_back(msg);
        return SsErr::OK;
    }

    SsErr send_binary_message(const uint8_t* data, size_t len) override {
        sent_binary_.push_back(std::vector<uint8_t>(data, data + len));
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
        InboundMessage complete;
        switch (this->process_inbound_message(message, complete)) {
            case InboundDispatch::NONE:
                break;
            case InboundDispatch::JSON:
                if (this->on_json) {
                    this->on_json(reinterpret_cast<const char*>(complete.data), complete.len);
                }
                break;
            case InboundDispatch::BINARY:
                if (this->on_binary) {
                    this->on_binary(complete);
                }
                break;
        }
    }

    /// Stand-ins for the client's dispatch of the complete message.
    std::function<void(const char* data, size_t len)> on_json;
    std::function<void(InboundMessage& message)> on_binary;

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
inline std::string make_server_init(const std::string& server_id, int version = 1,
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
inline std::string make_noise_handshake_envelope(const std::vector<uint8_t>& raw) {
    std::string encoded = b64url_encode(raw.data(), raw.size());
    JsonDocument doc;
    doc["type"] = "noise/handshake";
    doc["payload"]["data"] = encoded;
    std::string out;
    serializeJson(doc, out);
    return out;
}

/// Decode the `payload.data` base64url field from a `noise/handshake` JSON string.
inline std::optional<std::vector<uint8_t>> extract_noise_bytes(const std::string& json) {
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

inline std::optional<LoopbackResult> run_loopback_handshake(const std::string& suite_name) {
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
    NoiseHandshake nh(client_id, rs, suite_name.c_str(), arena);

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

/// TestConnection whose transport fails every write from a chosen one on. Like the real
/// transports, once closed it refuses every write as not connected, and its disconnect() sends
/// the goodbye and then closes.
class FailingWriteConnection : public TestConnection {
public:
    SsErr send_binary_message(const uint8_t* data, size_t len) override {
        if (!this->connected_) {
            return SsErr::INVALID_STATE;
        }
        if (this->during_write) {
            this->during_write();
        }
        if (this->writes_before_refusal == 0) {
            ++this->refused_writes;
            return SsErr::FAIL;
        }
        if (this->writes_before_refusal > 0) {
            --this->writes_before_refusal;
        }
        return TestConnection::send_binary_message(data, len);
    }

    void disconnect(SendspinGoodbyeReason reason) override {
        TestConnection::disconnect(reason);
        this->send_goodbye_reason(reason);
        this->close_transport_now();
    }

    void close_transport_now() override {
        TestConnection::close_transport_now();
        this->connected_ = false;
    }

    bool is_connected() const override {
        return this->connected_;
    }

    /// The peer closed the transport, which has not reported the close.
    void lose_transport() {
        this->connected_ = false;
    }

    /// Run inside every write the connected transport attempts, before it succeeds or fails.
    std::function<void()> during_write;

    /// Writes that succeed before every later one is refused; negative never refuses.
    int writes_before_refusal{-1};
    int refused_writes{0};

private:
    bool connected_{true};
};

}  // namespace sendspin
