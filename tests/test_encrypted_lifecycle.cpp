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

// Integration tests for the ENCRYPTED connection lifecycle: a real SendspinClient (with
// encryption_required = true, the default) driving admission, the hello/activate cycle, and an
// in-band re-handshake against a fake Sendspin "server" peer that speaks real Noise KKpsk2 over a
// real loopback WebSocket, exactly like test_connection_lifecycle.cpp does for the plaintext
// nursery mechanics. That suite intentionally runs with encryption_required = false and defers all
// Noise coverage to the crypto-primitive-level tests (test_noise_transport.cpp,
// test_noise_rehandshake.cpp, test_admission.cpp); this file closes the remaining gap: nothing
// previously exercised the full encrypted lifecycle end to end through ConnectionManager.
//
// The fake server (FakeEncryptedServer below) plays the Noise INITIATOR role using raw noise-c
// (the project's own NoiseSession class only implements the responder side, matching the
// "client is always the Noise responder" invariant), reusing the exact crypto plumbing pattern
// established in test_noise_rehandshake.cpp (build_initiator / raw_encrypt / raw_decrypt) but
// driven over a real socket instead of in-process function calls.

#include "admission.h"
#include "crypto/constants.h"
#include "crypto/keys.h"
#include "platform/base64.h"
#include "platform/crypto.h"
#include "record_store.h"
#include "sendspin/client.h"
#include "sendspin/config.h"

#include <gtest/gtest.h>
#include <ixwebsocket/IXWebSocket.h>

// noise-c is a C library
extern "C" {
#include <noise/protocol/buffer.h>
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/constants.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/handshakestate.h>
}

#include <ArduinoJson.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

constexpr uint16_t RESUME_TEST_PORT = 18991;
constexpr uint16_t DOWNGRADE_TEST_PORT = 18992;

std::string server_url(uint16_t port) {
    return "ws://127.0.0.1:" + std::to_string(port) + "/sendspin";
}

// ============================================================================
// Test scaffolding shared with test_connection_lifecycle.cpp
// ============================================================================

class TestNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override {
        return true;
    }
};

// Seeds the client's RecordStore with one known LONG_TERM record (server-side pairing is not
// under test here) so a fake server that knows the same psk_id/psk resolves to PskCategory::
// LONG_TERM, matching the trust category the admission tests below need.
class TestPersistenceProvider : public SendspinPersistenceProvider {
public:
    explicit TestPersistenceProvider(SendspinPairingRecord record)
        : record_(std::move(record)) {}

    std::vector<SendspinPairingRecord> load_pairing_records() override {
        return {this->record_};
    }

private:
    SendspinPairingRecord record_;
};

bool pump_until(SendspinClient& client, const std::function<bool()>& pred, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        client.loop();
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return false;
}

void pump_for(SendspinClient& client, int duration_ms) {
    pump_until(
        client, [] { return false; }, duration_ms);
}

// ============================================================================
// Raw noise-c initiator-side crypto helpers (mirrors test_noise_rehandshake.cpp exactly; the
// project's own NoiseSession class only implements the Noise RESPONDER role, so the fake
// server -- playing the Noise INITIATOR -- has to drive noise-c directly).
// ============================================================================

struct HsGuard {
    NoiseHandshakeState* hs{nullptr};
    explicit HsGuard(NoiseHandshakeState* h) : hs(h) {}
    ~HsGuard() {
        if (this->hs) {
            noise_handshakestate_free(this->hs);
        }
    }
    HsGuard(const HsGuard&) = delete;
    HsGuard& operator=(const HsGuard&) = delete;
};

struct CipherPair {
    NoiseCipherState* send_cs{nullptr};
    NoiseCipherState* recv_cs{nullptr};

    CipherPair() = default;
    ~CipherPair() {
        this->reset();
    }
    CipherPair(const CipherPair&) = delete;
    CipherPair& operator=(const CipherPair&) = delete;
    CipherPair(CipherPair&& o) noexcept : send_cs(o.send_cs), recv_cs(o.recv_cs) {
        o.send_cs = nullptr;
        o.recv_cs = nullptr;
    }
    CipherPair& operator=(CipherPair&& o) noexcept {
        if (this != &o) {
            this->reset();
            this->send_cs = o.send_cs;
            this->recv_cs = o.recv_cs;
            o.send_cs = nullptr;
            o.recv_cs = nullptr;
        }
        return *this;
    }
    void reset() {
        if (this->send_cs) {
            noise_cipherstate_free(this->send_cs);
            this->send_cs = nullptr;
        }
        if (this->recv_cs) {
            noise_cipherstate_free(this->recv_cs);
            this->recv_cs = nullptr;
        }
    }
};

NoiseHandshakeState* build_initiator(const std::string& suite_name, const uint8_t* local_priv,
                                     const uint8_t* local_pub, const uint8_t* remote_pub,
                                     const uint8_t* psk, const uint8_t* prologue,
                                     size_t prologue_len) {
    NoiseHandshakeState* hs = nullptr;
    if (noise_handshakestate_new_by_name(&hs, suite_name.c_str(), NOISE_ROLE_INITIATOR) !=
        NOISE_ERROR_NONE) {
        return nullptr;
    }
    NoiseDHState* local_dh = noise_handshakestate_get_local_keypair_dh(hs);
    if (noise_dhstate_set_keypair(local_dh, local_priv, X25519_KEY_SIZE, local_pub,
                                  X25519_KEY_SIZE) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(hs);
        return nullptr;
    }
    NoiseDHState* remote_dh = noise_handshakestate_get_remote_public_key_dh(hs);
    if (noise_dhstate_set_public_key(remote_dh, remote_pub, X25519_KEY_SIZE) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(hs);
        return nullptr;
    }
    if (noise_handshakestate_set_pre_shared_key(hs, psk, NOISE_PSK_SIZE) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(hs);
        return nullptr;
    }
    if (prologue_len > 0) {
        if (noise_handshakestate_set_prologue(hs, prologue, prologue_len) != NOISE_ERROR_NONE) {
            noise_handshakestate_free(hs);
            return nullptr;
        }
    }
    if (noise_handshakestate_start(hs) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(hs);
        return nullptr;
    }
    return hs;
}

std::vector<uint8_t> write_msg1(NoiseHandshakeState* hs, const std::string& psk_id) {
    std::string psk_id_json = "{\"psk_id\":\"" + psk_id + "\"}";
    std::vector<uint8_t> msg1_raw(4096);
    NoiseBuffer msg1_out;
    noise_buffer_set_output(msg1_out, msg1_raw.data(), msg1_raw.size());
    NoiseBuffer payload_in;
    noise_buffer_set_input(
        payload_in, const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(psk_id_json.data())),
        psk_id_json.size());
    if (noise_handshakestate_write_message(hs, &msg1_out, &payload_in) != NOISE_ERROR_NONE) {
        return {};
    }
    msg1_raw.resize(msg1_out.size);
    return msg1_raw;
}

std::vector<uint8_t> raw_encrypt(NoiseCipherState* cs, const std::vector<uint8_t>& pt) {
    std::vector<uint8_t> ct(pt.size() + 16);
    std::copy(pt.begin(), pt.end(), ct.begin());
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, ct.data(), pt.size(), ct.size());
    if (noise_cipherstate_encrypt(cs, &buf) != NOISE_ERROR_NONE) {
        return {};
    }
    ct.resize(buf.size);
    return ct;
}

std::vector<uint8_t> raw_decrypt(NoiseCipherState* cs, std::vector<uint8_t> ct) {
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, ct.data(), ct.size(), ct.size());
    if (noise_cipherstate_decrypt(cs, &buf) != NOISE_ERROR_NONE) {
        return {};
    }
    ct.resize(buf.size);
    return ct;
}

std::string noise_handshake_envelope(const std::vector<uint8_t>& noise_bytes) {
    std::string encoded = b64url_encode(noise_bytes.data(), noise_bytes.size());
    JsonDocument doc;
    doc["type"] = "noise/handshake";
    doc["payload"]["data"] = encoded;
    std::string out;
    serializeJson(doc, out);
    return out;
}

// ============================================================================
// FakeEncryptedServer: a Sendspin "server" peer that speaks real Noise KKpsk2 over a real
// loopback WebSocket, playing both the initial-handshake initiator role and (on request) an
// in-band re-handshake initiator role.
// ============================================================================

struct FakeEncryptedServerOptions {
    // Sent in server/activate after the FIRST client/hello.
    std::string first_activities_json{R"(["playback"])"};
    std::string first_roles_json{R"(["player@v1"])"};
    // Sent in server/activate after the SECOND client/hello (i.e. the one that follows a
    // trigger_rehandshake() call and its resulting fresh hello cycle).
    std::string second_activities_json{R"(["playback"])"};
    std::string second_roles_json{R"(["player@v1"])"};
};

class FakeEncryptedServer {
public:
    FakeEncryptedServer(const std::string& url, std::string suite_name, Identity server_identity,
                        std::string psk_id, std::array<uint8_t, NOISE_PSK_SIZE> psk,
                        FakeEncryptedServerOptions options = {})
        : suite_name_(std::move(suite_name)),
          server_identity_(server_identity),
          init_psk_id_(std::move(psk_id)),
          init_psk_(psk),
          options_(std::move(options)) {
        this->ws_.setUrl(url);
        this->ws_.disableAutomaticReconnection();
        this->ws_.setOnMessageCallback(
            [this](const ix::WebSocketMessagePtr& msg) { this->on_message(msg); });
        this->ws_.start();
    }

    ~FakeEncryptedServer() {
        this->ws_.stop();
        std::lock_guard<std::mutex> lock(this->crypto_mutex_);
        if (this->init_hs_ != nullptr) {
            noise_handshakestate_free(this->init_hs_);
        }
        if (this->rehandshake_hs_ != nullptr) {
            noise_handshakestate_free(this->rehandshake_hs_);
        }
    }

    // Starts an in-band re-handshake to (new_psk_id, new_psk), sent encrypted under the
    // currently active session (mirrors handle_noise_rehandshake's "travels under the current
    // transport keys" contract). No-op (returns false) if the initial handshake never completed.
    bool trigger_rehandshake(const std::string& new_psk_id,
                             const std::array<uint8_t, NOISE_PSK_SIZE>& new_psk) {
        std::lock_guard<std::mutex> lock(this->crypto_mutex_);
        if (this->active_.send_cs == nullptr) {
            return false;
        }
        NoiseHandshakeState* hs =
            build_initiator(this->suite_name_, this->server_identity_.private_bytes.data(),
                            this->server_identity_.public_bytes.data(),
                            this->client_pubkey_.data(), new_psk.data(), this->prior_h_.data(),
                            this->prior_h_.size());
        if (hs == nullptr) {
            return false;
        }
        auto msg1_bytes = write_msg1(hs, new_psk_id);
        if (msg1_bytes.empty()) {
            noise_handshakestate_free(hs);
            return false;
        }
        this->rehandshake_hs_ = hs;
        this->send_encrypted_locked(noise_handshake_envelope(msg1_bytes));
        return true;
    }

    int client_hello_count() const {
        return this->client_hello_count_.load();
    }

    bool closed() const {
        return this->closed_.load();
    }

    std::optional<std::string> goodbye_reason() const {
        std::lock_guard<std::mutex> lock(this->goodbye_mutex_);
        return this->goodbye_reason_;
    }

private:
    void on_message(const ix::WebSocketMessagePtr& msg) {
        if (msg->type == ix::WebSocketMessageType::Close ||
            msg->type == ix::WebSocketMessageType::Error) {
            this->closed_.store(true);
            return;
        }
        if (msg->type != ix::WebSocketMessageType::Message) {
            return;
        }
        if (msg->binary) {
            this->handle_binary(msg->str);
        } else {
            this->handle_text(msg->str);
        }
    }

    // Sends `json` as one Noise transport binary frame: [MSG_TYPE_JSON_BODY | utf8(json)],
    // encrypted under the currently active send cipher. Caller must hold crypto_mutex_.
    void send_encrypted_locked(const std::string& json) {
        std::vector<uint8_t> plaintext(1 + json.size());
        plaintext[0] = MSG_TYPE_JSON_BODY;
        std::memcpy(plaintext.data() + 1, json.data(), json.size());
        auto ct = raw_encrypt(this->active_.send_cs, plaintext);
        if (ct.empty()) {
            return;
        }
        this->ws_.sendBinary(std::string(ct.begin(), ct.end()));
    }

    void handle_text(const std::string& text) {
        JsonDocument doc;
        if (deserializeJson(doc, text)) {
            return;
        }
        const char* type = doc["type"] | "";

        std::lock_guard<std::mutex> lock(this->crypto_mutex_);

        if (std::strcmp(type, "client/init") == 0) {
            const char* client_id_b64 = doc["payload"]["client_id"] | "";
            auto client_pub = b64url_decode(client_id_b64);
            if (!client_pub.has_value() || client_pub->size() != X25519_KEY_SIZE) {
                return;
            }
            std::copy(client_pub->begin(), client_pub->end(), this->client_pubkey_.begin());
            this->client_init_text_ = text;

            JsonDocument sdoc;
            sdoc["type"] = "server/init";
            sdoc["payload"]["server_id"] = this->server_identity_.peer_id();
            sdoc["payload"]["version"] = PROTOCOL_VERSION;
            std::string server_init_text;
            serializeJson(sdoc, server_init_text);
            this->server_init_text_ = server_init_text;
            this->ws_.send(server_init_text);

            std::string prologue_str = this->client_init_text_ + this->server_init_text_;
            this->init_hs_ = build_initiator(
                this->suite_name_, this->server_identity_.private_bytes.data(),
                this->server_identity_.public_bytes.data(), this->client_pubkey_.data(),
                this->init_psk_.data(),
                reinterpret_cast<const uint8_t*>(prologue_str.data()), prologue_str.size());
            if (this->init_hs_ == nullptr) {
                return;
            }
            auto msg1_bytes = write_msg1(this->init_hs_, this->init_psk_id_);
            if (msg1_bytes.empty()) {
                noise_handshakestate_free(this->init_hs_);
                this->init_hs_ = nullptr;
                return;
            }
            this->ws_.send(noise_handshake_envelope(msg1_bytes));
            return;
        }

        if (std::strcmp(type, "noise/handshake") == 0 && this->init_hs_ != nullptr) {
            // The client's msg2 for the INITIAL handshake (still cleartext TEXT per the
            // pre-transport exchange).
            const char* data_b64 = doc["payload"]["data"] | "";
            auto msg2_bytes = b64url_decode(data_b64);
            if (!msg2_bytes.has_value()) {
                return;
            }
            std::vector<uint8_t> payload_buf(512);
            NoiseBuffer msg2_in;
            noise_buffer_set_input(msg2_in, msg2_bytes->data(), msg2_bytes->size());
            NoiseBuffer payload_out;
            noise_buffer_set_output(payload_out, payload_buf.data(), payload_buf.size());
            if (noise_handshakestate_read_message(this->init_hs_, &msg2_in, &payload_out) !=
                NOISE_ERROR_NONE) {
                noise_handshakestate_free(this->init_hs_);
                this->init_hs_ = nullptr;
                return;
            }
            std::array<uint8_t, 32> h{};
            noise_handshakestate_get_handshake_hash(this->init_hs_, h.data(), h.size());
            NoiseCipherState* send_cs = nullptr;
            NoiseCipherState* recv_cs = nullptr;
            if (noise_handshakestate_split(this->init_hs_, &send_cs, &recv_cs) !=
                NOISE_ERROR_NONE) {
                noise_handshakestate_free(this->init_hs_);
                this->init_hs_ = nullptr;
                return;
            }
            noise_handshakestate_free(this->init_hs_);
            this->init_hs_ = nullptr;

            this->active_.reset();
            this->active_.send_cs = send_cs;
            this->active_.recv_cs = recv_cs;
            this->prior_h_ = h;

            // Kick off the post-handshake protocol flow: server/hello, encrypted.
            JsonDocument hdoc;
            hdoc["type"] = "server/hello";
            hdoc["payload"]["name"] = "Fake Encrypted Server";
            std::string hello_text;
            serializeJson(hdoc, hello_text);
            this->send_encrypted_locked(hello_text);
        }
    }

    void handle_binary(const std::string& bytes) {
        std::lock_guard<std::mutex> lock(this->crypto_mutex_);
        if (this->active_.send_cs == nullptr) {
            return;
        }
        std::vector<uint8_t> ct(bytes.begin(), bytes.end());
        auto pt = raw_decrypt(this->active_.recv_cs, std::move(ct));
        if (pt.empty() || pt[0] != MSG_TYPE_JSON_BODY) {
            return;
        }
        std::string json(reinterpret_cast<char*>(pt.data() + 1), pt.size() - 1);
        JsonDocument doc;
        if (deserializeJson(doc, json)) {
            return;
        }
        const char* type = doc["type"] | "";

        if (std::strcmp(type, "client/hello") == 0) {
            int count = this->client_hello_count_.fetch_add(1) + 1;
            const std::string& activities =
                count <= 1 ? this->options_.first_activities_json
                          : this->options_.second_activities_json;
            const std::string& roles =
                count <= 1 ? this->options_.first_roles_json : this->options_.second_roles_json;
            std::string activate = std::string(R"({"type":"server/activate","payload":{)") +
                                   R"("activities":)" + activities + R"(,"active_roles":)" +
                                   roles + "}}";
            this->send_encrypted_locked(activate);
            return;
        }

        if (std::strcmp(type, "client/goodbye") == 0) {
            const char* reason = doc["payload"]["reason"] | "";
            {
                std::lock_guard<std::mutex> glock(this->goodbye_mutex_);
                this->goodbye_reason_ = reason;
            }
            return;
        }

        if (std::strcmp(type, "noise/handshake") == 0 && this->rehandshake_hs_ != nullptr) {
            // The client's msg2 for the in-band re-handshake, still encrypted under the OLD
            // (currently active) session -- decrypted above like any other frame.
            const char* data_b64 = doc["payload"]["data"] | "";
            auto msg2_bytes = b64url_decode(data_b64);
            if (!msg2_bytes.has_value()) {
                return;
            }
            std::vector<uint8_t> payload_buf(512);
            NoiseBuffer msg2_in;
            noise_buffer_set_input(msg2_in, msg2_bytes->data(), msg2_bytes->size());
            NoiseBuffer payload_out;
            noise_buffer_set_output(payload_out, payload_buf.data(), payload_buf.size());
            if (noise_handshakestate_read_message(this->rehandshake_hs_, &msg2_in, &payload_out) !=
                NOISE_ERROR_NONE) {
                noise_handshakestate_free(this->rehandshake_hs_);
                this->rehandshake_hs_ = nullptr;
                return;
            }
            std::array<uint8_t, 32> h{};
            noise_handshakestate_get_handshake_hash(this->rehandshake_hs_, h.data(), h.size());
            NoiseCipherState* send_cs = nullptr;
            NoiseCipherState* recv_cs = nullptr;
            if (noise_handshakestate_split(this->rehandshake_hs_, &send_cs, &recv_cs) !=
                NOISE_ERROR_NONE) {
                noise_handshakestate_free(this->rehandshake_hs_);
                this->rehandshake_hs_ = nullptr;
                return;
            }
            noise_handshakestate_free(this->rehandshake_hs_);
            this->rehandshake_hs_ = nullptr;

            // Swap to the new session for all future traffic, exactly like the responder does
            // in handle_noise_rehandshake()/NoiseTransport::send_msg2_and_swap().
            this->active_.reset();
            this->active_.send_cs = send_cs;
            this->active_.recv_cs = recv_cs;
            this->prior_h_ = h;

            // Resume the post-swap protocol flow: a fresh server/hello.
            JsonDocument hdoc;
            hdoc["type"] = "server/hello";
            hdoc["payload"]["name"] = "Fake Encrypted Server";
            std::string hello_text;
            serializeJson(hdoc, hello_text);
            this->send_encrypted_locked(hello_text);
        }
    }

    ix::WebSocket ws_;
    std::string suite_name_;
    Identity server_identity_;
    std::string init_psk_id_;
    std::array<uint8_t, NOISE_PSK_SIZE> init_psk_;
    FakeEncryptedServerOptions options_;

    // Guards every field below: handle_text/handle_binary run on IXWebSocket's callback thread;
    // trigger_rehandshake() is called from the test thread. Mirrors NoiseTransport::
    // session_mutex_'s role in the production responder.
    mutable std::mutex crypto_mutex_;
    std::array<uint8_t, X25519_KEY_SIZE> client_pubkey_{};
    std::string client_init_text_;
    std::string server_init_text_;
    NoiseHandshakeState* init_hs_{nullptr};        // pending initial handshake
    NoiseHandshakeState* rehandshake_hs_{nullptr};  // pending in-band re-handshake
    CipherPair active_;
    std::array<uint8_t, 32> prior_h_{};

    std::atomic<int> client_hello_count_{0};
    std::atomic<bool> closed_{false};
    mutable std::mutex goodbye_mutex_;
    std::optional<std::string> goodbye_reason_;
};

}  // namespace

// ============================================================================
// Tests
// ============================================================================

// Full encrypted lifecycle: accept -> Noise handshake -> hello -> server/activate -> operational,
// then a server-initiated in-band re-handshake on the ADMITTED connection -> the connection must
// come back operational via a fresh hello/activate cycle under the new session keys, without ever
// being dropped or re-entering nursery arbitration (the MUST-FIX under test: before the fix,
// nothing ever re-armed client/hello for a connection outside the nursery, so the connection
// stayed permanently non-operational after the swap).
TEST(EncryptedLifecycle, InBandRehandshakeResumesOperational) {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    SendspinPairingRecord record;
    record.psk_id = psk_id;
    record.psk = psk;

    TestNetworkProvider network;
    TestPersistenceProvider persistence(record);
    SendspinClientConfig config;
    config.name = "Encrypted Lifecycle Test Client";
    config.server_port = RESUME_TEST_PORT;
    ASSERT_TRUE(config.encryption_required);  // this suite exercises the encrypted path

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    Identity server_identity = Identity::generate();
    FakeEncryptedServer server(server_url(RESUME_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               server_identity, psk_id, psk);

    // Initial handshake + hello + activate must bring the connection operational.
    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Initial encrypted handshake/hello/activate did not complete";
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());
    EXPECT_EQ(server.client_hello_count(), 1);

    // Trigger the in-band re-handshake on the ADMITTED connection (same PSK: this test isolates
    // resumption from trust change, which is covered separately below).
    ASSERT_TRUE(server.trigger_rehandshake(psk_id, psk));

    // Immediately after the swap the connection must go non-operational (first_activate_received_
    // /server_hello_received_/client_hello_sent_ were reset) -- this is the expected transient
    // dip described in connection_manager.h's invariant comment, not a failure.
    EXPECT_TRUE(pump_until(
        client, [&] { return !client.is_connected(); }, 2000))
        << "Connection should go non-operational immediately after the re-handshake swap";

    // The MUST-FIX: without schedule_rehandshake_rearm()/the hello-retry re-arm, the connection
    // would stay non-operational forever. It must instead come back within a few ticks.
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Connection did not resume operational status after the in-band re-handshake";
    EXPECT_EQ(server.client_hello_count(), 2) << "A fresh client/hello must follow the re-handshake";
    // server_id is unchanged (same server, new session keys).
    auto info2 = client.get_server_information();
    ASSERT_TRUE(info2.has_value());
    EXPECT_EQ(info2->server_id, server_identity.peer_id());
    EXPECT_FALSE(server.closed());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Negative path: a post-re-handshake server/activate that the new PSK category cannot admit must
// still go through the existing inadmissible-activate drop path (trust enforcement applies
// identically whether the activate follows the initial handshake or a re-handshake), closing with
// the correct client/goodbye reason.
TEST(EncryptedLifecycle, PostRehandshakeInadmissibleActivateDrops) {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    SendspinPairingRecord record;
    record.psk_id = psk_id;
    record.psk = psk;

    TestNetworkProvider network;
    TestPersistenceProvider persistence(record);
    SendspinClientConfig config;
    config.name = "Encrypted Lifecycle Downgrade Test Client";
    config.server_port = DOWNGRADE_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    Identity server_identity = Identity::generate();
    // After the re-handshake, the fake server switches to declaring ["management"], which the
    // SENTINEL-category PSK it re-handshakes to cannot satisfy (management requires a long-term
    // PSK match) -- see admission.h::activities_allowed.
    FakeEncryptedServerOptions options;
    options.second_activities_json = R"(["management"])";
    options.second_roles_json = R"([])";
    FakeEncryptedServer server(server_url(DOWNGRADE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               server_identity, psk_id, psk, options);

    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Initial encrypted handshake/hello/activate did not complete";

    // Re-handshake down to the Sentinel PSK (unpaired access is disabled by default, so even
    // ["playback"] would be inadmissible for it -- ["management"] is doubly so).
    ASSERT_TRUE(server.trigger_rehandshake(std::string(SENTINEL_PSK_ID), SENTINEL_PSK));

    // The connection must be dropped (never come back operational) once the inadmissible
    // server/activate is processed, and the fake server must observe the WS close.
    EXPECT_TRUE(pump_until(
        client, [&] { return server.closed(); }, 4000))
        << "Connection was not dropped after an inadmissible post-re-handshake server/activate";
    EXPECT_FALSE(client.is_connected());

    auto reason = server.goodbye_reason();
    ASSERT_TRUE(reason.has_value()) << "No client/goodbye observed before close";
    EXPECT_EQ(reason.value(), "unauthorized");

    pump_for(client, 100);
}
