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

/// @file lifecycle_test_fixtures.h
/// @brief Shared scaffolding for the connection-lifecycle integration suites: fake Sendspin
/// "server" peers that speak real Noise KKpsk2 over a real loopback WebSocket, plus the
/// network/persistence providers and the main-loop pump the suites drive them with.
///
/// The fakes play the Noise INITIATOR role using raw noise-c (the project's own NoiseSession
/// class only implements the responder side, matching the "client is always the Noise responder"
/// invariant), reusing the crypto plumbing in noise_test_helpers.h (build_initiator /
/// raw_encrypt / raw_decrypt) but driven over a real socket instead of in-process function calls.

#pragma once

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "noise_test_helpers.h"
#include "platform/base64.h"
#include "sendspin/client.h"
#include "sendspin/persistence_codec.h"
#include "sendspin/types.h"

#include <ixwebsocket/IXConnectionState.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketMessage.h>
#include <ixwebsocket/IXWebSocketMessageType.h>
#include <ixwebsocket/IXWebSocketServer.h>

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
#include <chrono>
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

namespace sendspin {

inline std::string server_url(uint16_t port) {
    return "ws://127.0.0.1:" + std::to_string(port) + "/sendspin";
}

class TestNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override {
        return true;
    }
};

// Seeds the client's RecordStore with known LONG_TERM records (server-side pairing is not under
// test here) so a fake server that knows the same psk_id/psk resolves to PskCategory::LONG_TERM,
// matching the trust category the admission tests need. Optionally also seeds the last-played
// server_id that the rank-0 arbitration tiebreak keys on.
//
// save_blob/erase_blob are left at the base class's rejecting defaults: nothing here is meant to
// observe writes, and a store that accepted them would let a test's own traffic (mark_record_used,
// the keypair save) mutate the seed mid-run. Tests that need to observe or shape a write bring
// their own provider.
class TestPersistenceProvider : public SendspinPersistenceProvider {
public:
    explicit TestPersistenceProvider(SendspinPairingRecord record) : records_{std::move(record)} {}

    explicit TestPersistenceProvider(std::vector<SendspinPairingRecord> records)
        : records_(std::move(records)) {}

    /// Seeds persistence_keys::LAST_PLAYED. Must be called before start_server(), which is where
    /// the client loads it into ConnectionManager::last_played_server_id_.
    void set_last_played_server_id(std::string server_id) {
        this->last_played_server_id_ = std::move(server_id);
    }

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key == persistence_keys::RECORDS) {
            std::string encoded = encode_pairing_records(this->records_);
            return std::vector<uint8_t>(encoded.begin(), encoded.end());
        }
        if (key == persistence_keys::LAST_PLAYED && !this->last_played_server_id_.empty()) {
            return std::vector<uint8_t>(this->last_played_server_id_.begin(),
                                        this->last_played_server_id_.end());
        }
        return std::nullopt;
    }

private:
    std::vector<SendspinPairingRecord> records_;
    std::string last_played_server_id_;
};

inline bool pump_until(SendspinClient& client, const std::function<bool()>& pred, int timeout_ms) {
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

inline void pump_for(SendspinClient& client, int duration_ms) {
    pump_until(
        client, [] { return false; }, duration_ms);
}

inline std::vector<uint8_t> write_msg1(NoiseHandshakeState* hs, const std::string& psk_id) {
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

inline std::vector<uint8_t> raw_encrypt(NoiseCipherState* cs, const std::vector<uint8_t>& pt) {
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

inline std::vector<uint8_t> raw_decrypt(NoiseCipherState* cs, std::vector<uint8_t> ct) {
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, ct.data(), ct.size(), ct.size());
    if (noise_cipherstate_decrypt(cs, &buf) != NOISE_ERROR_NONE) {
        return {};
    }
    ct.resize(buf.size);
    return ct;
}

inline std::string noise_handshake_envelope(const std::vector<uint8_t>& noise_bytes) {
    std::string encoded = b64url_encode(noise_bytes.data(), noise_bytes.size());
    JsonDocument doc;
    doc["type"] = "noise/handshake";
    doc["payload"]["data"] = encoded;
    std::string out;
    serializeJson(doc, out);
    return out;
}

struct FakeEncryptedServerOptions {
    // Sent in server/activate after the FIRST client/hello.
    std::string first_activities_json{R"(["playback"])"};
    std::string first_roles_json{R"(["player@v1"])"};
    // Present only when the first server/activate should select a pairing method (e.g.
    // "pairing_psk"), emitted as the nested payload.pairing object per the current spec;
    // omitted (nullopt) for the normal playback/management admission path.
    std::optional<std::string> first_pairing_method;
    // Sent in server/activate after the SECOND client/hello (i.e. the one that follows a
    // trigger_rehandshake() call and its resulting fresh hello cycle).
    std::string second_activities_json{R"(["playback"])"};
    std::string second_roles_json{R"(["player@v1"])"};
    // When set, this raw JSON message is sent (encrypted) immediately BEFORE the first
    // server/activate: while the connection has finished the Noise handshake but has not
    // yet been admitted. Used to prove role-bound traffic is refused until admission.
    std::optional<std::string> pre_activate_message;
    // When true, no server/activate is ever sent. The connection completes the Noise handshake
    // (so its psk_id/category are resolved) and the hello exchange, but never proves itself, so
    // it stays in the nursery instead of being promoted.
    bool suppress_activate{false};
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

    /// supported_pair_methods from the most recent client/hello, in wire order.
    std::vector<std::string> hello_pair_methods() const {
        std::lock_guard<std::mutex> lock(this->pair_methods_mutex_);
        return this->hello_pair_methods_;
    }

    bool closed() const {
        return this->closed_.load();
    }

    std::optional<std::string> goodbye_reason() const {
        std::lock_guard<std::mutex> lock(this->goodbye_mutex_);
        return this->goodbye_reason_;
    }

    // The PSK (and its derived psk_id) the client generated and sent via client/pair-finalize,
    // captured by the client/pair-finalize handler in handle_binary(). nullopt until pairing has
    // reached that point.
    std::optional<std::array<uint8_t, NOISE_PSK_SIZE>> learned_psk() const {
        std::lock_guard<std::mutex> lock(this->pair_mutex_);
        return this->learned_psk_;
    }

    std::optional<std::string> learned_psk_id() const {
        std::lock_guard<std::mutex> lock(this->pair_mutex_);
        return this->learned_psk_id_;
    }

    // Sends a management/list-records request to the client over the active encrypted session
    // (mirrors the server-initiated management request pattern; the client responds with
    // management/result, captured by the "management/result" branch in handle_binary()).
    bool send_management_list_records() {
        std::lock_guard<std::mutex> lock(this->crypto_mutex_);
        if (this->active_.send_cs == nullptr) {
            return false;
        }
        this->send_encrypted_locked(R"({"type":"management/list-records","payload":{}})");
        return true;
    }

    // Sends an arbitrary application JSON message over the active encrypted session.
    bool send_app_json(const std::string& json) {
        std::lock_guard<std::mutex> lock(this->crypto_mutex_);
        if (this->active_.send_cs == nullptr) {
            return false;
        }
        this->send_encrypted_locked(json);
        return true;
    }

    std::optional<std::string> last_management_result() const {
        std::lock_guard<std::mutex> lock(this->management_mutex_);
        return this->last_management_result_;
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

        if (std::strcmp(type, "client/goodbye") == 0) {
            // A goodbye in CLEARTEXT, before any Noise transport exists: the client rejected the
            // connection at accept (a full nursery), so it never installed a handshake driver and
            // send_app_json() fell back to a plain text frame. The encrypted counterpart of this
            // branch lives in handle_binary().
            std::lock_guard<std::mutex> glock(this->goodbye_mutex_);
            this->goodbye_reason_ = doc["payload"]["reason"] | "";
            return;
        }

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
            {
                std::lock_guard<std::mutex> plock(this->pair_methods_mutex_);
                this->hello_pair_methods_.clear();
                for (JsonVariantConst m :
                     doc["payload"]["supported_pair_methods"].as<JsonArrayConst>()) {
                    this->hello_pair_methods_.emplace_back(m["method"] | "");
                }
            }
            const std::string& activities =
                count <= 1 ? this->options_.first_activities_json
                          : this->options_.second_activities_json;
            const std::string& roles =
                count <= 1 ? this->options_.first_roles_json : this->options_.second_roles_json;
            std::string activate = std::string(R"({"type":"server/activate","payload":{)") +
                                   R"("activities":)" + activities + R"(,"active_roles":)" + roles;
            if (count <= 1 && this->options_.first_pairing_method.has_value()) {
                activate += R"(,"pairing":{"method":")" +
                           this->options_.first_pairing_method.value() + "\"}";
            }
            activate += "}}";
            if (this->options_.suppress_activate) {
                return;
            }
            if (count <= 1 && this->options_.pre_activate_message.has_value()) {
                // Ordered strictly before the activate on the same encrypted stream, so the DUT
                // sees it while the connection is handshake-complete but not yet admitted.
                this->send_encrypted_locked(this->options_.pre_activate_message.value());
            }
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

        if (std::strcmp(type, "client/pair-finalize") == 0) {
            // The client generated a fresh long-term PSK and is handing it to us to store
            // server-side; ack it so the client commits its own pending record. Capture the PSK
            // (and its derived psk_id) so the test can later trigger the post-pairing in-band
            // re-handshake with it, exactly like a real server rekeying onto the new PSK.
            const char* psk_b64 = doc["payload"]["long_term_psk"] | "";
            auto psk_bytes = b64url_decode(psk_b64);
            if (psk_bytes.has_value() && psk_bytes->size() == NOISE_PSK_SIZE) {
                std::array<uint8_t, NOISE_PSK_SIZE> psk{};
                std::copy(psk_bytes->begin(), psk_bytes->end(), psk.begin());
                {
                    std::lock_guard<std::mutex> plock(this->pair_mutex_);
                    this->learned_psk_ = psk;
                    this->learned_psk_id_ = psk_id_for(psk);
                }
                this->send_encrypted_locked(R"({"type":"server/pair-finalize","payload":{}})");
            }
            return;
        }

        if (std::strcmp(type, "management/result") == 0) {
            std::lock_guard<std::mutex> mlock(this->management_mutex_);
            this->last_management_result_ = json;
            return;
        }

        if (std::strcmp(type, "noise/handshake") == 0 && this->rehandshake_hs_ != nullptr) {
            // The client's msg2 for the in-band re-handshake, still encrypted under the OLD
            // (currently active) session, decrypted above like any other frame.
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
    mutable std::mutex pair_methods_mutex_;
    std::vector<std::string> hello_pair_methods_;
    std::atomic<bool> closed_{false};
    mutable std::mutex goodbye_mutex_;
    std::optional<std::string> goodbye_reason_;

    mutable std::mutex pair_mutex_;
    std::optional<std::array<uint8_t, NOISE_PSK_SIZE>> learned_psk_;
    std::optional<std::string> learned_psk_id_;

    mutable std::mutex management_mutex_;
    std::optional<std::string> last_management_result_;
};

// A fake Sendspin "server" that LISTENS for a real Sendspin client's OUTBOUND connection (backed
// by ix::WebSocketServer), speaking the same Noise KKpsk2-initiator protocol as
// FakeEncryptedServer above.
//
// A test that instead drives client.start_server() and connects FakeEncryptedServer to it as a WS
// client exercises SendspinServerConnection (host/server_connection.cpp); that class's
// disconnect() only ever calls the already-async trigger_close(), so it never needs the
// network-thread deadlock/crash guard close_transport_now() (connection.h) provides.
// SendspinClientConnection::disconnect() (host/client_connection.cpp) does need that guard: it is
// reached when the SendspinClient itself calls connect_to() and dispatch_completed_message() runs
// synchronously on IXWebSocket's own outbound worker thread. This class lets the client under
// test be the outbound connector, so a test can reach that code path.
class FakeOutboundEncryptedServer {
public:
    FakeOutboundEncryptedServer(uint16_t port, std::string suite_name, Identity server_identity,
                                std::string psk_id, std::array<uint8_t, NOISE_PSK_SIZE> psk)
        : server_(port, "127.0.0.1"),
          suite_name_(std::move(suite_name)),
          server_identity_(server_identity),
          psk_id_(std::move(psk_id)),
          psk_(psk) {
        this->server_.setOnConnectionCallback(
            [this](const std::weak_ptr<ix::WebSocket>& weak_ws,
                   const std::shared_ptr<ix::ConnectionState>& /*state*/) {
                auto ws = weak_ws.lock();
                if (!ws) {
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(this->crypto_mutex_);
                    this->ws_ = weak_ws;
                }
                ws->setOnMessageCallback(
                    [this](const ix::WebSocketMessagePtr& msg) { this->on_message(msg); });
            });
    }

    ~FakeOutboundEncryptedServer() {
        this->server_.stop();
        std::lock_guard<std::mutex> lock(this->crypto_mutex_);
        if (this->init_hs_ != nullptr) {
            noise_handshakestate_free(this->init_hs_);
        }
    }

    bool listen() {
        return this->server_.listen().first;
    }

    void start() {
        this->server_.start();
    }

    // Sends a single tampered (bit-flipped) frame under the currently active send cipher,
    // simulating a Noise AEAD decrypt failure on an already-operational transport-mode
    // connection. Returns false if no session is active yet or the socket has gone away.
    bool send_tampered_frame() {
        std::lock_guard<std::mutex> lock(this->crypto_mutex_);
        auto ws = this->ws_.lock();
        if (!ws || this->active_.send_cs == nullptr) {
            return false;
        }
        std::vector<uint8_t> plaintext = {MSG_TYPE_JSON_BODY, 'x'};
        auto ct = raw_encrypt(this->active_.send_cs, plaintext);
        if (ct.empty()) {
            return false;
        }
        ct[ct.size() / 2] ^= 0xFF;  // corrupt the ciphertext/AEAD tag
        ws->sendBinary(std::string(ct.begin(), ct.end()));
        return true;
    }

    std::optional<std::string> goodbye_reason() const {
        std::lock_guard<std::mutex> lock(this->goodbye_mutex_);
        return this->goodbye_reason_;
    }

private:
    void on_message(const ix::WebSocketMessagePtr& msg) {
        if (msg->type != ix::WebSocketMessageType::Message) {
            return;
        }
        if (msg->binary) {
            this->handle_binary(msg->str);
        } else {
            this->handle_text(msg->str);
        }
    }

    // Sends `json` as one Noise transport binary frame, encrypted under the active send cipher.
    // Caller must hold crypto_mutex_.
    void send_encrypted_locked(const std::string& json) {
        auto ws = this->ws_.lock();
        if (!ws) {
            return;
        }
        std::vector<uint8_t> plaintext(1 + json.size());
        plaintext[0] = MSG_TYPE_JSON_BODY;
        std::memcpy(plaintext.data() + 1, json.data(), json.size());
        auto ct = raw_encrypt(this->active_.send_cs, plaintext);
        if (ct.empty()) {
            return;
        }
        ws->sendBinary(std::string(ct.begin(), ct.end()));
    }

    void handle_text(const std::string& text) {
        JsonDocument doc;
        if (deserializeJson(doc, text)) {
            return;
        }
        const char* type = doc["type"] | "";

        std::lock_guard<std::mutex> lock(this->crypto_mutex_);
        auto ws = this->ws_.lock();
        if (!ws) {
            return;
        }

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
            ws->send(server_init_text);

            std::string prologue_str = this->client_init_text_ + this->server_init_text_;
            this->init_hs_ = build_initiator(
                this->suite_name_, this->server_identity_.private_bytes.data(),
                this->server_identity_.public_bytes.data(), this->client_pubkey_.data(),
                this->psk_.data(), reinterpret_cast<const uint8_t*>(prologue_str.data()),
                prologue_str.size());
            if (this->init_hs_ == nullptr) {
                return;
            }
            auto msg1_bytes = write_msg1(this->init_hs_, this->psk_id_);
            if (msg1_bytes.empty()) {
                noise_handshakestate_free(this->init_hs_);
                this->init_hs_ = nullptr;
                return;
            }
            ws->send(noise_handshake_envelope(msg1_bytes));
            return;
        }

        if (std::strcmp(type, "noise/handshake") == 0 && this->init_hs_ != nullptr) {
            // The client's msg2, still cleartext TEXT per the pre-transport exchange.
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

            // Kick off the post-handshake protocol flow: server/hello, encrypted.
            JsonDocument hdoc;
            hdoc["type"] = "server/hello";
            hdoc["payload"]["name"] = "Fake Outbound Encrypted Server";
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
            std::string activate =
                R"({"type":"server/activate","payload":{"activities":["playback"],)"
                R"("active_roles":["player@v1"]}})";
            this->send_encrypted_locked(activate);
            return;
        }

        if (std::strcmp(type, "client/goodbye") == 0) {
            const char* reason = doc["payload"]["reason"] | "";
            std::lock_guard<std::mutex> glock(this->goodbye_mutex_);
            this->goodbye_reason_ = reason;
        }
    }

    ix::WebSocketServer server_;
    std::string suite_name_;
    Identity server_identity_;
    std::string psk_id_;
    std::array<uint8_t, NOISE_PSK_SIZE> psk_;

    // Guards every field below: on_message()/handle_text()/handle_binary() run on the WS server's
    // own connection thread; the test thread calls send_tampered_frame().
    mutable std::mutex crypto_mutex_;
    std::weak_ptr<ix::WebSocket> ws_;
    std::array<uint8_t, X25519_KEY_SIZE> client_pubkey_{};
    std::string client_init_text_;
    std::string server_init_text_;
    NoiseHandshakeState* init_hs_{nullptr};
    CipherPair active_;

    mutable std::mutex goodbye_mutex_;
    std::optional<std::string> goodbye_reason_;
};

}  // namespace sendspin
