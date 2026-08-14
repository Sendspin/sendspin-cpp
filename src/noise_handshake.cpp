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

#include "noise_handshake.h"

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "noise_session.h"
#include "platform/base64.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include <ArduinoJson.h>

#include <cstring>
#include <string>
#include <vector>

static const char* const TAG = "sendspin.noise_handshake";

namespace sendspin {

// ============================================================================
// JSON serialization helpers
// ============================================================================

/// @brief Serialize client/init to JSON.
/// Format: {"type":"client/init","payload":{"client_id":"...","version":1,"suite":"..."}}
static std::string serialize_client_init(const std::string& client_id,
                                         const std::string& suite_name) {
    // suite_name from NOISE_SUITE_CHACHAPOLY is "Noise_KKpsk2_25519_ChaChaPoly_SHA256";
    // the wire value is the suffix after "Noise_KKpsk2_" (see NoiseCipherSuite in session.py).
    // However, the spec says the full suite name goes on the wire for client/init.
    // Looking at models.py ClientInitPayload.suite, and session.py NoiseCipherSuite.value
    // which is "25519_ChaChaPoly_SHA256" - just the suffix.  But constants.py is the
    // source of truth and says NOISE_SUITE_CHACHAPOLY = "Noise_KKpsk2_25519_ChaChaPoly_SHA256"
    // while NoiseCipherSuite.CHACHAPOLY.value = "25519_ChaChaPoly_SHA256".
    // The wire suite string is NoiseCipherSuite.value = "25519_ChaChaPoly_SHA256".
    // Strip "Noise_KKpsk2_" prefix to produce the wire suite string.
    static constexpr const char* PREFIX = "Noise_KKpsk2_";
    const size_t PREFIX_LEN = 13;
    std::string wire_suite = suite_name;
    if (wire_suite.size() > PREFIX_LEN && wire_suite.substr(0, PREFIX_LEN) == PREFIX) {
        wire_suite = wire_suite.substr(PREFIX_LEN);
    }

    JsonDocument doc = make_json_document();
    doc["type"] = "client/init";
    doc["payload"]["client_id"] = client_id;
    doc["payload"]["version"] = PROTOCOL_VERSION;
    doc["payload"]["suite"] = wire_suite;

    std::string out;
    serializeJson(doc, out);
    return out;
}

/// @brief Serialize a noise/handshake frame containing base64url-encoded noise bytes.
/// Format: {"type":"noise/handshake","payload":{"data":"..."}}
static std::string serialize_noise_handshake(const std::vector<uint8_t>& noise_bytes) {
    std::string encoded = b64url_encode(noise_bytes.data(), noise_bytes.size());

    JsonDocument doc = make_json_document();
    doc["type"] = "noise/handshake";
    doc["payload"]["data"] = encoded;

    std::string out;
    serializeJson(doc, out);
    return out;
}

// ============================================================================
// Shared msg1-processing core (initial handshake + re-handshake)
// ============================================================================

namespace {

/// @brief Outcome of the shared probe/psk-resolve/real-session/write-msg2 core.
/// Carries everything both `NoiseHandshake::handle_msg1` and `run_rehandshake_msg1`
/// need to build their own `NoiseHandshakeResult` and deliver msg2 in their own way.
struct Msg1CoreResult {
    /// The real (post-PSK-resolution) session, split into transport cipher states.
    NoiseSession session;
    /// The PSK record that admitted the connection.
    ResolvedPsk resolved_psk;
    /// Serialized noise/handshake msg2 bytes (not yet wrapped in a JSON envelope).
    std::vector<uint8_t> msg2_bytes;
};

/// @brief Run the shared core of Noise msg1 processing: decode msg1 + server_id,
/// probe for psk_id, resolve the PSK via the record store, verify any stored-pubkey
/// binding, build the real session, and write msg2.
///
/// Used identically by the initial handshake (`NoiseHandshake::handle_msg1`) and the
/// in-band re-handshake (`run_rehandshake_msg1`); the only differences between the two
/// callers are the prologue bytes and how msg2 is delivered to the peer -- both handled
/// by the caller after this returns.
///
/// @param log_prefix    Prefix used for all log lines (mirrors the caller's function name).
/// @param identity      Our static X25519 identity.
/// @param record_store  Record store for psk_id resolution (read-only on network thread).
/// @param suite_name    Noise suite name (NOISE_SUITE_CHACHAPOLY or NOISE_SUITE_AESGCM).
/// @param server_id     Known/claimed server peer_id (43-char base64url).
/// @param prologue      Exact prologue bytes for this handshake (caller-specific).
/// @param prologue_len  Length of `prologue`.
/// @param msg1_json     Raw noise/handshake JSON envelope text containing msg1.
/// @return Populated Msg1CoreResult on success, or nullopt on any failure (caller aborts).
std::optional<Msg1CoreResult> run_msg1_core(const char* log_prefix, const Identity& identity,
                                            const RecordStore& record_store,
                                            const std::string& suite_name,
                                            const std::string& server_id, const uint8_t* prologue,
                                            size_t prologue_len, const std::string& msg1_json) {
    // Parse the JSON envelope
    JsonDocument doc = make_json_document();
    DeserializationError err = deserializeJson(doc, msg1_json);
    if (err || doc.isNull()) {
        SS_LOGE(TAG, "%s: JSON parse failed", log_prefix);
        return std::nullopt;
    }

    const char* type = doc["type"] | "";
    if (std::strcmp(type, "noise/handshake") != 0) {
        SS_LOGE(TAG, "%s: unexpected type '%s'", log_prefix, type);
        return std::nullopt;
    }

    const char* data_b64 = doc["payload"]["data"] | "";
    if (data_b64[0] == '\0') {
        SS_LOGE(TAG, "%s: missing data field", log_prefix);
        return std::nullopt;
    }

    auto msg1_bytes = b64url_decode(data_b64);
    if (!msg1_bytes.has_value() || msg1_bytes->empty()) {
        SS_LOGE(TAG, "%s: failed to base64url-decode noise msg1", log_prefix);
        return std::nullopt;
    }

    // Decode the server static public key from server_id
    auto server_pub = b64url_decode(server_id);
    if (!server_pub.has_value() || server_pub->size() != X25519_KEY_SIZE) {
        SS_LOGE(TAG, "%s: invalid server_id (cannot decode public key)", log_prefix);
        return std::nullopt;
    }

    // Two-handshake trick: Step 1 - probe session with placeholder PSK
    // We need psk_id from msg1's plaintext, but noise-c requires PSK before start.
    // Use a zero placeholder; since psk2 mixes PSK only in msg2, msg1 is
    // authenticated with static keys only.
    static const std::array<uint8_t, NOISE_PSK_SIZE> placeholder_psk{};

    auto probe_session =
        NoiseSession::as_responder(suite_name, identity.private_bytes.data(), server_pub->data(),
                                   prologue, prologue_len, placeholder_psk.data());
    if (!probe_session.has_value()) {
        SS_LOGE(TAG, "%s: failed to build probe session", log_prefix);
        return std::nullopt;
    }

    auto msg1_payload = probe_session->read_msg1(msg1_bytes->data(), msg1_bytes->size());
    if (msg1_payload.empty()) {
        SS_LOGE(TAG, "%s: probe read_msg1 failed (auth error in msg1 static DH)", log_prefix);
        return std::nullopt;
    }

    // Parse psk_id from the decrypted msg1 payload: {"psk_id":"..."}
    JsonDocument payload_doc = make_json_document();
    DeserializationError perr =
        deserializeJson(payload_doc, msg1_payload.data(), msg1_payload.size());
    if (perr || payload_doc.isNull()) {
        SS_LOGE(TAG, "%s: failed to parse msg1 payload JSON", log_prefix);
        return std::nullopt;
    }

    const char* psk_id = payload_doc["psk_id"] | "";
    if (psk_id[0] == '\0') {
        SS_LOGE(TAG, "%s: psk_id missing from msg1 payload", log_prefix);
        return std::nullopt;
    }

    SS_LOGD(TAG, "%s: psk_id='%s'", log_prefix, psk_id);

    // Resolve psk_id via RecordStore
    auto resolved = record_store.resolve_by_psk_id(std::string(psk_id));
    if (!resolved.has_value()) {
        SS_LOGW(TAG, "%s: unknown psk_id='%s', aborting", log_prefix, psk_id);
        return std::nullopt;
    }

    // Stored-pubkey post-match check: if the record is bound to a specific server,
    // verify it matches the server we actually reached.
    if (resolved->counterparty_id.has_value() && resolved->counterparty_id.value() != server_id) {
        SS_LOGW(TAG, "%s: PSK bound to server_id='%s', but connected to '%s'", log_prefix,
                resolved->counterparty_id->c_str(), server_id.c_str());
        return std::nullopt;
    }

    // Two-handshake trick: Step 2 - real session with the resolved PSK
    // Discard the probe; build a fresh handshakestate with the real PSK and
    // re-process the exact same msg1 bytes.
    auto real_session =
        NoiseSession::as_responder(suite_name, identity.private_bytes.data(), server_pub->data(),
                                   prologue, prologue_len, resolved->psk.data());
    if (!real_session.has_value()) {
        SS_LOGE(TAG, "%s: failed to build real session", log_prefix);
        return std::nullopt;
    }

    auto real_msg1_payload = real_session->read_msg1(msg1_bytes->data(), msg1_bytes->size());
    if (real_msg1_payload.empty()) {
        SS_LOGE(TAG, "%s: real read_msg1 failed", log_prefix);
        return std::nullopt;
    }

    // Write msg2 (payload: `{}`) and split to transport mode
    std::vector<uint8_t> msg2_bytes;
    if (!real_session->write_msg2_and_split(msg2_bytes)) {
        SS_LOGE(TAG, "%s: write_msg2_and_split failed", log_prefix);
        return std::nullopt;
    }

    return Msg1CoreResult{std::move(real_session.value()), std::move(resolved.value()),
                          std::move(msg2_bytes)};
}

}  // namespace

// ============================================================================
// Constructor
// ============================================================================

NoiseHandshake::NoiseHandshake(const Identity& identity, const RecordStore& record_store,
                               const std::string& suite_name)
    : identity_(identity), record_store_(record_store), suite_name_(suite_name) {}

// ============================================================================
// Public API
// ============================================================================

std::string NoiseHandshake::build_client_init() {
    if (this->state_ != State::INIT) {
        SS_LOGE(TAG, "build_client_init called in wrong state");
        return {};
    }

    std::string text = serialize_client_init(this->identity_.peer_id(), this->suite_name_);
    this->client_init_text_ = text;
    this->state_ = State::WAIT_SERVER_INIT;
    return text;
}

HandshakeFrameResult NoiseHandshake::on_text_frame(
    const std::string& text, const std::function<bool(const std::string&)>& send_fn) {
    switch (this->state_) {
        case State::WAIT_SERVER_INIT:
            if (!this->handle_server_init(text)) {
                this->state_ = State::ABORTED;
                return HandshakeFrameResult::ABORT;
            }
            this->state_ = State::WAIT_MSG1;
            return HandshakeFrameResult::NEED_MORE;

        case State::WAIT_MSG1:
            if (!this->handle_msg1(text, send_fn)) {
                this->state_ = State::ABORTED;
                return HandshakeFrameResult::ABORT;
            }
            this->state_ = State::COMPLETE;
            return HandshakeFrameResult::COMPLETE;

        case State::INIT:
            SS_LOGE(TAG, "on_text_frame: client/init not sent yet");
            this->state_ = State::ABORTED;
            return HandshakeFrameResult::ABORT;

        case State::COMPLETE:
        case State::ABORTED:
        default:
            SS_LOGE(TAG, "on_text_frame called in terminal state");
            return HandshakeFrameResult::ABORT;
    }
}

// ============================================================================
// Private: handle server/init
// ============================================================================

bool NoiseHandshake::handle_server_init(const std::string& text) {
    JsonDocument doc = make_json_document();
    DeserializationError err = deserializeJson(doc, text);
    if (err || doc.isNull()) {
        SS_LOGE(TAG, "handle_server_init: JSON parse failed");
        return false;
    }

    const char* type = doc["type"] | "";
    if (std::strcmp(type, "server/init") != 0) {
        SS_LOGE(TAG, "handle_server_init: unexpected type '%s'", type);
        return false;
    }

    int version = doc["payload"]["version"] | 0;
    if (version != PROTOCOL_VERSION) {
        SS_LOGE(TAG, "handle_server_init: unsupported version %d (expected %d)", version,
                PROTOCOL_VERSION);
        return false;
    }

    const char* server_id = doc["payload"]["server_id"] | "";
    if (std::strlen(server_id) != PEER_ID_SIZE) {
        SS_LOGE(TAG, "handle_server_init: invalid server_id length %zu", std::strlen(server_id));
        return false;
    }

    this->server_id_ = server_id;
    this->server_init_text_ = text;  // Retain exact bytes for prologue

    SS_LOGD(TAG, "server/init received: server_id=%s", server_id);
    return true;
}

// ============================================================================
// Private: handle noise/handshake msg1
// ============================================================================

bool NoiseHandshake::handle_msg1(const std::string& text,
                                 const std::function<bool(const std::string&)>& send_fn) {
    // Prologue = exact bytes of client/init || server/init
    std::string prologue_str = this->client_init_text_ + this->server_init_text_;
    const uint8_t* prologue = reinterpret_cast<const uint8_t*>(prologue_str.data());
    size_t prologue_len = prologue_str.size();

    auto core = run_msg1_core("handle_msg1", this->identity_, this->record_store_,
                              this->suite_name_, this->server_id_, prologue, prologue_len, text);
    if (!core.has_value()) {
        return false;
    }

    // Send noise/handshake msg2 as a TEXT frame
    std::string msg2_text = serialize_noise_handshake(core->msg2_bytes);
    if (!send_fn(msg2_text)) {
        SS_LOGE(TAG, "handle_msg1: failed to send noise/handshake msg2");
        return false;
    }

    SS_LOGI(TAG, "Noise handshake complete: server_id=%s psk_category=%d", this->server_id_.c_str(),
            static_cast<int>(core->resolved_psk.category));

    // Store result
    NoiseHandshakeResult result;
    result.session = std::make_unique<NoiseSession>(std::move(core->session));
    result.server_id = this->server_id_;
    result.resolved_psk = std::move(core->resolved_psk);
    this->result_ = std::move(result);

    return true;
}

// ============================================================================
// Re-handshake helper
// ============================================================================

std::optional<NoiseHandshakeResult> run_rehandshake_msg1(const std::string& msg1_json,
                                                         const std::string& server_id,
                                                         const Identity& identity,
                                                         const RecordStore& record_store,
                                                         const std::string& suite_name,
                                                         const std::array<uint8_t, 32>& prior_h) {
    // Prologue for re-handshake = prior handshake hash h (32 bytes)
    const uint8_t* prologue = prior_h.data();
    const size_t prologue_len = prior_h.size();

    auto core = run_msg1_core("run_rehandshake_msg1", identity, record_store, suite_name, server_id,
                              prologue, prologue_len, msg1_json);
    if (!core.has_value()) {
        return std::nullopt;
    }

    // Serialize the msg2 noise/handshake envelope (caller sends it encrypted)
    std::string msg2_text = serialize_noise_handshake(core->msg2_bytes);

    SS_LOGI(TAG, "Re-handshake complete: server_id=%s psk_category=%d", server_id.c_str(),
            static_cast<int>(core->resolved_psk.category));

    NoiseHandshakeResult result;
    result.session = std::make_unique<NoiseSession>(std::move(core->session));
    result.server_id = server_id;
    result.resolved_psk = std::move(core->resolved_psk);
    result.msg2_text = std::move(msg2_text);
    return result;
}

}  // namespace sendspin
