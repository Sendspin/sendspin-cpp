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
// test_noise_rehandshake.cpp, test_admission.cpp); this file exercises the full encrypted
// lifecycle end to end through ConnectionManager.
//
// The fake server (FakeEncryptedServer below) plays the Noise INITIATOR role using raw noise-c
// (the project's own NoiseSession class only implements the responder side, matching the
// "client is always the Noise responder" invariant), reusing the exact crypto plumbing pattern
// established in test_noise_rehandshake.cpp (build_initiator / raw_encrypt / raw_decrypt) but
// driven over a real socket instead of in-process function calls.

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "noise_test_helpers.h"
#include "platform/base64.h"
#include "platform/crypto.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/metadata_role.h"
#include "sendspin/persistence_codec.h"
#include "sendspin/types.h"

#include <gtest/gtest.h>
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
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

constexpr uint16_t RESUME_TEST_PORT = 18991;
constexpr uint16_t DOWNGRADE_TEST_PORT = 18992;
constexpr uint16_t PAIRING_TEST_PORT = 18993;
constexpr uint16_t MANAGEMENT_TEST_PORT = 18994;
constexpr uint16_t PAIRING_PERSIST_FAILURE_TEST_PORT = 18995;
constexpr uint16_t CIPHER_SUITE_AESGCM_TEST_PORT = 18996;
constexpr uint16_t PAIR_METHODS_TEST_PORT = 18997;
constexpr uint16_t AEAD_FAILURE_TEST_PORT = 18998;
constexpr uint16_t AEAD_FAILURE_OUTBOUND_PORT = 18999;
constexpr uint16_t PREHANDSHAKE_BINARY_TEST_PORT = 19000;
constexpr uint16_t PREADMISSION_ROLE_TEST_PORT = 19001;
constexpr uint16_t REVOCATION_SWEEP_TEST_PORT = 19002;

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

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key != persistence_keys::RECORDS) {
            return std::nullopt;
        }
        std::string encoded = encode_pairing_records({this->record_});
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

private:
    SendspinPairingRecord record_;
};

// Starts with no pairing records (unpaired: only the Sentinel PSK resolves), but captures every
// record store_record() persists via save_blob(persistence_keys::RECORDS, ...), so the
// pairing-flow test below can assert on the psk_id/server_id/psk that pairing generated and
// persisted, and hand the same
// psk/psk_id back to the fake server for the follow-up in-band re-handshake. Thread-safe: the
// server/pair-finalize commit runs on the network thread (see client.cpp's SERVER_PAIR_FINALIZE
// handler), while the test thread reads captured_record().
class PairingCapturePersistenceProvider : public SendspinPersistenceProvider {
public:
    // load_blob(RECORDS) is not overridden beyond the base class's nullopt default: "starts with
    // no pairing records" above, so restating it here would be a no-op override.

    // Optionally pre-seed an accepted Pairing PSK (spec's "server/activate" section: pairing.method
    // MUST be 'pairing_psk' if and only if the matched PSK IS the Pairing PSK; the client
    // enforces this via ConnectionManager::loop()'s pairing-method admissibility check).
    // The Pairing PSK Flow test below needs the fake server to connect using this PSK directly
    // (matching PskCategory::PAIRING immediately), not the Sentinel PSK, so this must be set
    // before start_server() reads it into the RecordStore.
    void set_configured_pairing_psk(SendspinPairingPsk psk) {
        this->configured_pairing_psk_ = std::move(psk);
    }

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key != persistence_keys::PAIRING_PSK || !this->configured_pairing_psk_.has_value()) {
            return std::nullopt;
        }
        std::string encoded = encode_pairing_psk(this->configured_pairing_psk_.value());
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (key != persistence_keys::RECORDS) {
            return true;  // pair_config etc. are not under test here.
        }
        std::string_view text(reinterpret_cast<const char*>(data), len);
        auto decoded = decode_pairing_records(text).value_or(std::vector<SendspinPairingRecord>{});
        // Only capture/reject a write that includes a record WITH a server_id: the RecordStore
        // also persists a shared-PSK fallback record (no server_id) on first boot as part of the
        // very same whole-array write, and that provisioning write must always succeed
        // unconditionally so it is unaffected by reject_pairing_records_.
        const SendspinPairingRecord* with_server_id = nullptr;
        for (const auto& r : decoded) {
            if (r.server_id.has_value()) {
                with_server_id = &r;
                break;
            }
        }
        if (with_server_id == nullptr) {
            return true;
        }
        std::lock_guard<std::mutex> lock(this->mutex_);
        if (this->reject_pairing_records_) {
            return false;
        }
        this->captured_ = *with_server_id;
        return true;
    }

    std::optional<SendspinPairingRecord> captured_record() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->captured_;
    }

    // When set, save_blob(RECORDS, ...) rejects any write that includes a record with a
    // server_id (simulating a persistence-provider failure, e.g. storage full), while still
    // succeeding for the first-boot shared-PSK fallback record. Used to verify the fail-closed
    // contract: a rejected persist must not report pairing success (see client.cpp's
    // SERVER_PAIR_FINALIZE handler, which must check RecordStore::store_record()'s return
    // value).
    void set_reject_pairing_records(bool reject) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->reject_pairing_records_ = reject;
    }

private:
    mutable std::mutex mutex_;
    std::optional<SendspinPairingRecord> captured_;
    bool reject_pairing_records_{false};
    std::optional<SendspinPairingPsk> configured_pairing_psk_;
};

// Records on_trust_changed / on_pairing_succeeded notifications so the pairing-flow test can
// assert both that pairing was reported successful and that trust was later upgraded to USER
// once the post-pairing re-handshake completes. Callbacks fire from SendspinClient::loop() on
// the test thread (see EventState's dispatch block), so no locking is needed here.
class RecordingClientListener : public SendspinClientListener {
public:
    void on_trust_changed(ConnectionTrust trust) override {
        this->trust_history_.push_back(trust);
    }

    void on_pairing_succeeded(const std::string& server_id) override {
        this->pairing_succeeded_server_id_ = server_id;
    }

    void on_pairing_failed(const std::string& server_id, SendspinPairAbortReason reason) override {
        this->pairing_failed_server_id_ = server_id;
        this->pairing_failed_reason_ = reason;
    }

    bool trust_ever_reached(ConnectionTrust trust) const {
        for (const auto& t : this->trust_history_) {
            if (t == trust) {
                return true;
            }
        }
        return false;
    }

    const std::optional<std::string>& pairing_succeeded_server_id() const {
        return this->pairing_succeeded_server_id_;
    }

    const std::optional<std::string>& pairing_failed_server_id() const {
        return this->pairing_failed_server_id_;
    }

    const std::optional<SendspinPairAbortReason>& pairing_failed_reason() const {
        return this->pairing_failed_reason_;
    }

private:
    std::vector<ConnectionTrust> trust_history_;
    std::optional<std::string> pairing_succeeded_server_id_;
    std::optional<std::string> pairing_failed_server_id_;
    std::optional<SendspinPairAbortReason> pairing_failed_reason_;
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
// Raw noise-c initiator-side crypto helpers (HsGuard / CipherPair / build_initiator come from
// noise_test_helpers.h; the project's own NoiseSession class only implements the Noise
// RESPONDER role, so the fake server, playing the Noise INITIATOR, has to drive noise-c
// directly).
// ============================================================================

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
// by ix::WebSocketServer, the same pattern test_connection_lifecycle.cpp's
// SlowOutboundSurvivesUpgradeTier uses for its plaintext backend), speaking the same Noise
// KKpsk2-initiator protocol as FakeEncryptedServer above.
//
// This exists only for the AeadFailureOnOutboundConnectionDoesNotCrash regression test below.
// Every other test in this file drives client.start_server() and connects FakeEncryptedServer to
// it as a WS client, which exercises SendspinServerConnection (host/server_connection.cpp); that
// class's disconnect() only ever calls the already-async trigger_close(), so it never needs the
// network-thread deadlock/crash guard close_transport_now() (connection.h) provides.
// SendspinClientConnection::disconnect() (host/client_connection.cpp) does need that guard: it is
// reached when the SendspinClient itself calls connect_to() and dispatch_completed_message() runs
// synchronously on IXWebSocket's own outbound worker thread. This class lets the DUT be the
// outbound connector so the test exercises that code path.
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

}  // namespace

// ============================================================================
// Tests
// ============================================================================

// Full encrypted lifecycle: accept -> Noise handshake -> hello -> server/activate -> operational,
// then a server-initiated in-band re-handshake on the ADMITTED connection -> the connection must
// come back operational via a fresh hello/activate cycle under the new session keys, without ever
// being dropped or re-entering nursery arbitration. client/hello must be re-armed for a connection
// outside the nursery so it does not stay permanently non-operational after the swap.
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

    Identity server_identity = Identity::generate().value();
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

    // Immediately after the swap the connection must go non-operational: first_activate_received_,
    // server_hello_received_, and client_hello_sent_ are reset. This is the expected transient dip
    // described in connection_manager.h's invariant comment, not a failure.
    EXPECT_TRUE(pump_until(
        client, [&] { return !client.is_connected(); }, 2000))
        << "Connection should go non-operational immediately after the re-handshake swap";

    // schedule_rehandshake_rearm() must re-arm the hello retry so the connection comes back within
    // a few ticks; without it, the connection would stay non-operational forever.
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

// close_silently() (spec Failure Handling: no application-level message on an AEAD
// failure/malformed fragment/handshake abort) must never call disconnect(). On a host OUTBOUND
// connection, disconnect() ends up calling ix::WebSocket::stop() from inside
// dispatch_completed_message(), itself invoked synchronously from IXWebSocket's own worker thread
// callback. Joining the current thread from itself throws std::system_error, which escapes
// WebSocket::run() uncaught and calls std::terminate(), crashing the whole test process.
//
// This must be driven through a real client.connect_to() (SendspinClientConnection): plugging a
// fake peer into client.start_server() instead (as every other test in this file does) exercises
// SendspinServerConnection, whose disconnect() only ever calls the already-async trigger_close()
// and was never vulnerable to this bug. FakeOutboundEncryptedServer above plays the opposite role
// (a real ix::WebSocketServer the DUT connects out to) specifically so this test reaches
// SendspinClientConnection::disconnect().
//
// This test drives a real Noise AEAD decrypt failure on that real outbound host connection (the
// simplest of the three close_silently() triggers to produce from a fake peer): close_silently()
// must use close_transport_now(), which never blocks or joins, so merely completing this test
// without the process aborting is the primary assertion. It also checks that the connection
// is reported lost exactly once and that no client/goodbye is sent (the close is silent, per spec).
TEST(EncryptedLifecycle, AeadFailureOnOutboundConnectionDoesNotCrash) {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    SendspinPairingRecord record;
    record.psk_id = psk_id;
    record.psk = psk;

    TestNetworkProvider network;
    TestPersistenceProvider persistence(record);
    SendspinClientConfig config;
    config.name = "AEAD Failure Outbound Test Client";
    config.server_port = AEAD_FAILURE_TEST_PORT;  // unused: this test never accepts inbound
    ASSERT_TRUE(config.encryption_required);

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeOutboundEncryptedServer server(AEAD_FAILURE_OUTBOUND_PORT,
                                       std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                       psk_id, psk);
    ASSERT_TRUE(server.listen());
    server.start();

    client.connect_to(server_url(AEAD_FAILURE_OUTBOUND_PORT));

    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Initial encrypted handshake/hello/activate did not complete";

    // Send one tampered ciphertext frame. If close_silently() ever regresses back to calling
    // disconnect() on the network thread here, the test process crashes via std::terminate()
    // instead of reaching the assertions below.
    ASSERT_TRUE(server.send_tampered_frame());

    EXPECT_TRUE(pump_until(
        client, [&] { return !client.is_connected(); }, 4000))
        << "An AEAD failure must tear down the connection (reported lost)";

    // Give any duplicate loss-report/close event a chance to arrive and confirm it is tolerated
    // (drop_connection() no-ops on a connection it no longer manages) rather than double-freeing
    // or otherwise misbehaving.
    pump_for(client, 200);
    EXPECT_FALSE(client.is_connected());

    // Spec Failure Handling: no client/goodbye is sent for a silent close.
    EXPECT_FALSE(server.goodbye_reason().has_value());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// SendspinClientConfig::cipher_suite must actually reach the Noise handshake: setting it to
// AESGCM should make init_noise_handshake() (via connection_manager.cpp's suite_name_for())
// build the client's side of the handshake with Noise_KKpsk2_25519_AESGCM_SHA256 rather than
// the ChaChaPoly default. The Noise protocol name is mixed into the handshake hash on both
// sides, so a mismatched suite string would fail the handshake outright; a fake server built
// with the matching AESGCM suite name completing the full handshake/hello/activate cycle is
// therefore proof the preference was threaded through, not just accepted and ignored.
TEST(EncryptedLifecycle, CipherSuitePreferenceAesgcmCompletesHandshake) {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    SendspinPairingRecord record;
    record.psk_id = psk_id;
    record.psk = psk;

    TestNetworkProvider network;
    TestPersistenceProvider persistence(record);
    SendspinClientConfig config;
    config.name = "Cipher Suite AESGCM Test Client";
    config.server_port = CIPHER_SUITE_AESGCM_TEST_PORT;
    config.cipher_suite = NoiseCipherSuitePreference::AESGCM;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServer server(server_url(CIPHER_SUITE_AESGCM_TEST_PORT),
                               std::string(NOISE_SUITE_AESGCM), server_identity, psk_id, psk);

    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "AESGCM-suite handshake/hello/activate did not complete";
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());

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

    Identity server_identity = Identity::generate().value();
    // After the re-handshake, the fake server switches to declaring ["management"], which the
    // SENTINEL-category PSK it re-handshakes to cannot satisfy (management requires a long-term
    // PSK match; see admission.h::activities_allowed).
    FakeEncryptedServerOptions options;
    options.second_activities_json = R"(["management"])";
    options.second_roles_json = R"([])";
    FakeEncryptedServer server(server_url(DOWNGRADE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               server_identity, psk_id, psk, options);

    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Initial encrypted handshake/hello/activate did not complete";

    // Re-handshake down to the Sentinel PSK (unpaired access is disabled by default, so even
    // ["playback"] would be inadmissible for it, and ["management"] is doubly so).
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

// The hello must advertise a pairing method the server can actually start. pairing_psk is the
// client-mandatory method and its PSK is auto-provisioned by the RecordStore on first boot, so it
// is advertised even though nothing was persisted here; dynamic_pin joins it because this client
// declares pin_display_supported. A client that advertises neither leaves a server (and its
// operator) with no way into pairing at all.
TEST(EncryptedLifecycle, HelloAdvertisesPairingMethods) {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    SendspinPairingRecord record;
    record.psk_id = psk_id;
    record.psk = psk;

    TestNetworkProvider network;
    TestPersistenceProvider persistence(record);
    SendspinClientConfig config;
    config.name = "Pair Methods Test Client";
    config.server_port = PAIR_METHODS_TEST_PORT;
    config.pin_display_supported = true;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServer server(server_url(PAIR_METHODS_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity, psk_id, psk);

    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Initial encrypted handshake/hello/activate did not complete";

    std::vector<std::string> methods = server.hello_pair_methods();
    auto advertises = [&methods](const std::string& name) {
        return std::find(methods.begin(), methods.end(), name) != methods.end();
    };
    EXPECT_TRUE(advertises("pairing_psk"))
        << "pairing_psk is client-mandatory and its PSK is auto-provisioned";
    EXPECT_TRUE(advertises("dynamic_pin")) << "pin_display_supported was set on this client";
    EXPECT_FALSE(advertises("static_pin")) << "no static PIN or pairing window on this client";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Full pairing-PSK flow end to end: the operator has already transferred a Pairing PSK to the
// server out of band (a pairing token; see crypto/pairing_token.h), so the server's initial
// handshake resolves it directly to PskCategory::PAIRING (spec: "pairing.method MUST be
// 'pairing_psk' if and only if the matched PSK IS the Pairing PSK". The client enforces this via
// ConnectionManager::loop()'s pairing-method admissibility check, so a fake server that selected
// pairing_psk over a Sentinel-matched connection is correctly rejected as method_not_supported).
// The client generates a fresh long-term PSK client-side (CSPRNG) and sends it via
// client/pair-finalize, the server acks, the client persists the record, and then, exactly like a
// real server immediately rekeying onto the new PSK, the fake server triggers an in-band
// re-handshake with the learned psk_id/psk. The connection must resume operational under the new
// session with trust upgraded from PAIRING to USER (LONG_TERM).
TEST(EncryptedLifecycle, PairingPskFlowPersistsAndUpgradesTrust) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    // The Pairing PSK the operator "typed in" (e.g. via a pairing token): known to both the
    // client (so its RecordStore resolves the fake server's handshake to PskCategory::PAIRING)
    // and the fake server (so it can perform that handshake).
    std::array<uint8_t, 32> pairing_psk_bytes{};
    for (size_t i = 0; i < pairing_psk_bytes.size(); ++i) {
        pairing_psk_bytes[i] = static_cast<uint8_t>(0xD0 + i);
    }
    SendspinPairingPsk configured_pairing_psk;
    configured_pairing_psk.psk_id = psk_id_for(pairing_psk_bytes);
    configured_pairing_psk.psk = pairing_psk_bytes;
    persistence.set_configured_pairing_psk(configured_pairing_psk);

    SendspinClientConfig config;
    config.name = "Pairing Flow Test Client";
    config.server_port = PAIRING_TEST_PORT;

    RecordingClientListener listener;
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    // Initial handshake uses the accepted Pairing PSK directly (matching PskCategory::PAIRING),
    // not the Sentinel PSK: the Pairing PSK Flow's initial handshake IS the Pairing PSK (the
    // Sentinel-then-re-handshake path in the spec is only for upgrading an ALREADY-open Sentinel
    // connection into pairing_psk pairing, a different scenario from this one).
    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.first_activities_json = R"(["pairing"])";
    options.first_roles_json = R"([])";
    options.first_pairing_method = "pairing_psk";
    FakeEncryptedServer server(server_url(PAIRING_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               server_identity, configured_pairing_psk.psk_id, pairing_psk_bytes,
                               options);

    // handle_enter_pairing (PAIRING_PSK branch) fires as soon as the pairing activate is admitted
    // and sends client/pair-finalize; the fake server acks it immediately in handle_binary().
    ASSERT_TRUE(pump_until(
        client, [&] { return server.learned_psk_id().has_value(); }, 4000))
        << "client/pair-finalize (with a freshly generated long_term_psk) was never observed";

    // The server's ack must have made the client persist the record before this returns (see
    // client.cpp's SERVER_PAIR_FINALIZE handler: the commit happens synchronously on the network
    // thread, not deferred to the main loop).
    ASSERT_TRUE(pump_until(
        client, [&] { return persistence.captured_record().has_value(); }, 4000))
        << "Pairing record was never persisted";
    auto captured = persistence.captured_record();
    ASSERT_TRUE(captured.has_value());
    EXPECT_EQ(captured->psk_id, server.learned_psk_id().value());
    EXPECT_EQ(captured->server_id.value_or(""), server_identity.peer_id());

    ASSERT_TRUE(pump_until(
        client, [&] { return listener.pairing_succeeded_server_id().has_value(); }, 4000))
        << "on_pairing_succeeded was never fired";
    EXPECT_EQ(listener.pairing_succeeded_server_id().value(), server_identity.peer_id());

    // Rekey onto the newly paired PSK, exactly like the real server does immediately after
    // acking pair-finalize (see connection.h's note_pairing_finalize_ack()/provisional-timeout
    // re-arm, which exists precisely to bound this step).
    auto learned_psk = server.learned_psk();
    auto learned_psk_id = server.learned_psk_id();
    ASSERT_TRUE(learned_psk.has_value() && learned_psk_id.has_value());
    ASSERT_TRUE(server.trigger_rehandshake(learned_psk_id.value(), learned_psk.value()));

    // The connection must resume operational under the new session, now with LONG_TERM/USER trust
    // instead of the PAIRING/none trust it started with.
    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Connection did not resume operational after the post-pairing re-handshake";
    EXPECT_TRUE(listener.trust_ever_reached(ConnectionTrust::USER))
        << "Trust was never upgraded to USER after pairing completed";
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());
    EXPECT_FALSE(server.closed());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Fail-closed persistence: when the persistence provider rejects the pair-finalize record (e.g.
// storage exhausted, write error), the client must NOT report pairing success, must instead
// report on_pairing_failed with the client-local SendspinPairAbortReason::STORAGE_FAILED reason,
// and must close the connection (schedule_pair_storage_failed -> handle_pair_storage_failed).
// In client.cpp's SERVER_PAIR_FINALIZE handler, RecordStore::store_record()'s return value gates
// on_pairing_succeeded, and a rejection drives an explicit local abort.
TEST(EncryptedLifecycle, PairingPskFlowFailedPersistDoesNotReportSuccess) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    persistence.set_reject_pairing_records(true);
    // As in PairingPskFlowPersistsAndUpgradesTrust: the fake server must connect using an
    // accepted Pairing PSK directly (PskCategory::PAIRING), not Sentinel, now that the client
    // enforces pairing.method=pairing_psk iff the matched PSK IS the Pairing PSK.
    std::array<uint8_t, 32> pairing_psk_bytes{};
    for (size_t i = 0; i < pairing_psk_bytes.size(); ++i) {
        pairing_psk_bytes[i] = static_cast<uint8_t>(0xE0 + i);
    }
    SendspinPairingPsk configured_pairing_psk;
    configured_pairing_psk.psk_id = psk_id_for(pairing_psk_bytes);
    configured_pairing_psk.psk = pairing_psk_bytes;
    persistence.set_configured_pairing_psk(configured_pairing_psk);

    SendspinClientConfig config;
    config.name = "Pairing Flow Persist-Failure Test Client";
    config.server_port = PAIRING_PERSIST_FAILURE_TEST_PORT;

    RecordingClientListener listener;
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.first_activities_json = R"(["pairing"])";
    options.first_roles_json = R"([])";
    options.first_pairing_method = "pairing_psk";
    FakeEncryptedServer server(server_url(PAIRING_PERSIST_FAILURE_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               configured_pairing_psk.psk_id, pairing_psk_bytes, options);

    ASSERT_TRUE(pump_until(
        client, [&] { return server.learned_psk_id().has_value(); }, 4000))
        << "client/pair-finalize was never observed";

    // The rejection must drive an explicit local abort (schedule_pair_storage_failed ->
    // handle_pair_storage_failed), not just a silent no-op left to the watchdog.
    ASSERT_TRUE(pump_until(
        client, [&] { return listener.pairing_failed_server_id().has_value(); }, 4000))
        << "on_pairing_failed was never fired after the persistence provider rejected the record";

    EXPECT_FALSE(persistence.captured_record().has_value())
        << "A rejected record must not be captured (provider returned false)";
    EXPECT_FALSE(listener.pairing_succeeded_server_id().has_value())
        << "on_pairing_succeeded must not fire when the persistence provider rejects the record";
    EXPECT_EQ(listener.pairing_failed_server_id().value(), server_identity.peer_id());
    ASSERT_TRUE(listener.pairing_failed_reason().has_value());
    EXPECT_EQ(listener.pairing_failed_reason().value(), SendspinPairAbortReason::STORAGE_FAILED);

    // The connection must be closed rather than left dangling for the 30 s watchdog.
    EXPECT_TRUE(pump_until(
        client, [&] { return !client.is_connected(); }, 4000))
        << "Connection must be dropped after a storage-failure abort";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Management-suite round trip over an already-encrypted, already-admitted (LONG_TERM/MANAGEMENT)
// transport: the fake server sends management/list-records and the client must reply
// management/result with result=ok and the one seeded record, proving the management dispatch
// path (trust gating -> handle_management_request -> format_management_result_message) works
// end to end over the real Noise transport, not just at the unit level (test_management.cpp).
TEST(EncryptedLifecycle, ManagementListRecordsRoundTripOverEncryptedTransport) {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    SendspinPairingRecord record;
    record.psk_id = psk_id;
    record.psk = psk;

    TestNetworkProvider network;
    TestPersistenceProvider persistence(record);
    SendspinClientConfig config;
    config.name = "Management Round-Trip Test Client";
    config.server_port = MANAGEMENT_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    // A LONG_TERM PSK activated with the MANAGEMENT activity (no roles): admissible per
    // admission.h::activities_allowed (LONG_TERM allows any subset of {PLAYBACK, MANAGEMENT}),
    // and satisfies handle_management_request()'s has_activity(MANAGEMENT) trust gate.
    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.first_activities_json = R"(["management"])";
    options.first_roles_json = R"([])";
    FakeEncryptedServer server(server_url(MANAGEMENT_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               server_identity, psk_id, psk, options);

    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Initial encrypted handshake/hello/activate(management) did not complete";

    ASSERT_TRUE(server.send_management_list_records());

    ASSERT_TRUE(pump_until(
        client, [&] { return server.last_management_result().has_value(); }, 4000))
        << "management/result was never observed";

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, server.last_management_result().value()));
    JsonObject root = doc.as<JsonObject>();
    EXPECT_STREQ(root["type"] | "", "management/result");
    EXPECT_STREQ(root["payload"]["result"] | "", "ok");
    JsonArray records = root["payload"]["data"]["records"].as<JsonArray>();
    ASSERT_FALSE(records.isNull());
    bool found_seeded_record = false;
    for (JsonObject rec : records) {
        if (std::string(rec["psk_id"] | "") == psk_id) {
            found_seeded_record = true;
            break;
        }
    }
    EXPECT_TRUE(found_seeded_record) << "management/result did not list the seeded record";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A binary WebSocket frame that arrives while the Noise handshake is still pending must close the
// connection, not be dispatched.
//
// The binary branch of dispatch_completed_message() must distinguish "handshake installed but not
// finished" from "no handshake at all" (encryption_required == false).
// Collapsing the two into the same fall-through would let a peer skip client/init entirely, send a
// raw binary frame, and have it handed straight to the role binary handlers with the whole
// Noise/PSK/admission chain bypassed. The TEXT branch already routes pre-handshake text into the
// handshake driver, so it does not share this gap.
TEST(EncryptedLifecycle, BinaryFrameBeforeNoiseHandshakeClosesConnection) {
    TestNetworkProvider network;
    SendspinClientConfig config;
    config.name = "Pre-Handshake Binary Test Client";
    config.server_port = PREHANDSHAKE_BINARY_TEST_PORT;
    ASSERT_TRUE(config.encryption_required);

    SendspinClient client(config);
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    // A bare WebSocket peer: it completes the upgrade and then says nothing the protocol expects.
    std::atomic<bool> opened{false};
    std::atomic<bool> closed{false};
    ix::WebSocket ws;
    ws.setUrl(server_url(PREHANDSHAKE_BINARY_TEST_PORT));
    ws.disableAutomaticReconnection();
    ws.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
        if (msg->type == ix::WebSocketMessageType::Open) {
            opened.store(true);
        } else if (msg->type == ix::WebSocketMessageType::Close) {
            closed.store(true);
        }
    });
    ws.start();

    ASSERT_TRUE(pump_until(
        client, [&] { return opened.load(); }, 4000))
        << "Raw peer never completed the WebSocket upgrade";

    // No client/init, no handshake: straight to a player-shaped binary frame (type byte 4 =
    // player role, slot 0, followed by what would be an 8-byte timestamp and a payload).
    const std::string binary_frame(
        "\x04\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef", 13);
    ws.sendBinary(binary_frame);

    EXPECT_TRUE(pump_until(
        client, [&] { return closed.load(); }, 4000))
        << "An unauthenticated binary frame must close the connection, not be dispatched";

    ws.stop();
    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Role-bound traffic from a connection that has finished the Noise handshake but has NOT been
// admitted must be ignored.
//
// Completing the handshake is not authorization: the Sentinel PSK is a spec constant that
// RecordStore::resolve_by_psk_id() accepts unconditionally, so any peer on the network can reach
// handshake-complete and sit in the nursery. Whether its PSK category may drive playback at all is
// decided by admission when server/activate arrives. Before the gate, a peer could simply send
// stream/state traffic ahead of server/activate (or never send one) and drive the roles anyway for
// the whole nursery establish window.
TEST(EncryptedLifecycle, RoleTrafficBeforeAdmissionIsIgnored) {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    std::string psk_id = psk_id_for(psk);

    SendspinPairingRecord record;
    record.psk_id = psk_id;
    record.psk = psk;

    TestNetworkProvider network;
    TestPersistenceProvider persistence(record);
    SendspinClientConfig config;
    config.name = "Pre-Admission Role Traffic Test Client";
    config.server_port = PREADMISSION_ROLE_TEST_PORT;
    ASSERT_TRUE(config.encryption_required);

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);

    struct RecordingMetadataListener : MetadataRoleListener {
        std::atomic<int> updates{0};
        std::string last_title;
        void on_metadata(const ServerMetadataStateObject& m) override {
            this->last_title = m.title.value_or("");
            this->updates.fetch_add(1);
        }
    };
    RecordingMetadataListener metadata_listener;
    client.add_metadata().set_listener(&metadata_listener);

    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    // Sent on the encrypted stream immediately before the first server/activate, so the DUT sees
    // it while the connection is handshake-complete but still unadmitted.
    options.pre_activate_message =
        R"({"type":"server/state","payload":{"metadata":{"timestamp":1,"title":"Pre-Admission Leak"}}})";
    FakeEncryptedServer server(server_url(PREADMISSION_ROLE_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity, psk_id, psk,
                               options);

    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Encrypted handshake/hello/activate did not complete";

    // The pre-activate server/state must have been dropped on the floor.
    EXPECT_EQ(metadata_listener.updates.load(), 0)
        << "Role traffic from an unadmitted connection reached the metadata role (last_title='"
        << metadata_listener.last_title << "')";

    // ...and the same message on the now-admitted connection must go through, so the gate is
    // refusing on admission and not just dropping metadata wholesale.
    server.send_app_json(
        R"({"type":"server/state","payload":{"metadata":{"timestamp":2,"title":"Post-Admission OK"}}})");
    EXPECT_TRUE(pump_until(
        client, [&] { return metadata_listener.updates.load() > 0; }, 4000))
        << "Role traffic from the admitted connection was incorrectly dropped";
    EXPECT_EQ(metadata_listener.last_title, "Post-Admission OK");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Revoking a record via management/remove-record must also end the revoked device's live session.
//
// A connection resolves its psk_id and PSK category once, at Noise-handshake completion, and never
// re-checks them against the RecordStore, so deleting the record alone does not stop the revoked
// peer: handle_remove_record must disconnect both the REQUESTER (the is_self path) and any other
// live connection running on the removed record. Otherwise that connection would keep its
// LONG_TERM trust, and with it management authority and playback, until it happened to disconnect
// on its own, leaving revocation ineffective until the peer's next connection.
TEST(EncryptedLifecycle, RemoveRecordDropsTheRevokedDevicesLiveSession) {
    // Two distinct paired records: the admitted management session (A) and the peer it revokes (B).
    std::array<uint8_t, NOISE_PSK_SIZE> psk_a{};
    std::array<uint8_t, NOISE_PSK_SIZE> psk_b{};
    platform_random_bytes(psk_a.data(), psk_a.size());
    platform_random_bytes(psk_b.data(), psk_b.size());
    const std::string psk_id_a = psk_id_for(psk_a);
    const std::string psk_id_b = psk_id_for(psk_b);

    class TwoRecordProvider : public SendspinPersistenceProvider {
    public:
        TwoRecordProvider(SendspinPairingRecord a, SendspinPairingRecord b)
            : records_{std::move(a), std::move(b)} {}
        std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
            if (key != persistence_keys::RECORDS) {
                return std::nullopt;
            }
            std::string encoded = encode_pairing_records(this->records_);
            return std::vector<uint8_t>(encoded.begin(), encoded.end());
        }

    private:
        std::vector<SendspinPairingRecord> records_;
    };

    SendspinPairingRecord record_a;
    record_a.psk_id = psk_id_a;
    record_a.psk = psk_a;
    SendspinPairingRecord record_b;
    record_b.psk_id = psk_id_b;
    record_b.psk = psk_b;

    TestNetworkProvider network;
    TwoRecordProvider persistence(record_a, record_b);
    SendspinClientConfig config;
    config.name = "Revocation Sweep Test Client";
    config.server_port = REVOCATION_SWEEP_TEST_PORT;
    ASSERT_TRUE(config.encryption_required);

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    // A: admitted, with MANAGEMENT activity so its management/remove-record is honoured.
    Identity identity_a = Identity::generate().value();
    FakeEncryptedServerOptions options_a;
    options_a.first_activities_json = R"(["management"])";
    options_a.first_roles_json = R"([])";
    FakeEncryptedServer server_a(server_url(REVOCATION_SWEEP_TEST_PORT),
                                 std::string(NOISE_SUITE_CHACHAPOLY), identity_a, psk_id_a, psk_a,
                                 options_a);
    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000))
        << "Management session did not reach operational";

    // B: completes the Noise handshake (so its psk_id is resolved and cached on the connection)
    // but never sends server/activate, so it sits in the nursery as a second live session.
    Identity identity_b = Identity::generate().value();
    FakeEncryptedServerOptions options_b;
    options_b.suppress_activate = true;
    FakeEncryptedServer server_b(server_url(REVOCATION_SWEEP_TEST_PORT),
                                 std::string(NOISE_SUITE_CHACHAPOLY), identity_b, psk_id_b, psk_b,
                                 options_b);
    ASSERT_TRUE(pump_until(
        client, [&] { return server_b.client_hello_count() > 0; }, 4000))
        << "Second session never completed its Noise handshake / hello";
    ASSERT_FALSE(server_b.closed()) << "Second session closed before the revocation";

    // A revokes B's record.
    ASSERT_TRUE(server_a.send_app_json(
        R"({"type":"management/remove-record","payload":{"psk_id":")" + psk_id_b + R"("}})"));

    EXPECT_TRUE(pump_until(
        client, [&] { return server_b.closed(); }, 4000))
        << "Revoking a record left the revoked device's live session running";
    // The requester keeps its own session: it removed someone else's record, not its own.
    EXPECT_FALSE(server_a.closed()) << "The requesting management session must not be dropped";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}
