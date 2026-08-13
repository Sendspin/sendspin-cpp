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

#include "connection.h"

#include "crypto/constants.h"
#include "platform/compiler.h"
#include "platform/logging.h"
#include "platform/time.h"
#include "sendspin/types.h"
#include "time_filter.h"

#include <cstddef>
#include <memory>
#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.connection";

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinConnection::SendspinConnection() {
    // The transport emits encrypted frames through this connection's binary send path.
    // allow_before_hello=true: Noise frames are transport-level and precede the app hello.
    this->noise_transport_.set_frame_sink([this](const uint8_t* data, size_t len) {
        return this->send_binary_message(data, len, nullptr, /*allow_before_hello=*/true);
    });
}

SendspinConnection::~SendspinConnection() = default;

// ============================================================================
// Time filter
// ============================================================================

void SendspinConnection::init_time_filter() {
    this->time_filter_ = std::make_unique<SendspinTimeFilter>(SendspinTimeFilter::Config{});
}

// ============================================================================
// Message sending
// ============================================================================

SsErr SendspinConnection::send_goodbye_reason(SendspinGoodbyeReason reason,
                                              SendCompleteCallback on_complete) {
    // Goodbye must be sent even when Noise transport is active - route through send_app_json
    // so it is encrypted. allow_before_hello=true because goodbye can precede the hello (e.g.,
    // when rejecting an excess connection before the handshake finishes).
    return this->send_app_json(format_client_goodbye_message(reason), std::move(on_complete),
                               /*allow_before_hello=*/true);
}

SsErr SendspinConnection::send_app_json(const std::string& json, SendCompleteCallback cb,
                                        bool allow_before_hello) {
    // is_active() is an atomic read; NoiseTransport owns its own session mutex, so this
    // main-loop check cannot race the network-thread re-handshake swap: send_encrypted_text
    // re-checks the session under NoiseTransport's own lock.
    if (this->noise_transport_.is_active()) {
        // Post-handshake: all application JSON must be encrypted.
        // The callback is not forwarded through the encrypted path (the transport's send
        // methods call send_binary_message with a null cb). Best-effort: fire it as success
        // if encryption succeeds, fire it as failure otherwise.
        SsErr err = this->send_encrypted_text(json);
        if (cb) {
            cb(err == SsErr::OK);
        }
        return err;
    }
    // Pre-handshake: send as plain text.
    return this->send_text_message(json, std::move(cb), allow_before_hello);
}

SsErr SendspinConnection::send_app_json(const char* json, size_t len, SendCompleteCallback cb,
                                        bool allow_before_hello) {
    // Same routing as the std::string overload, but the encrypted hot path consumes the
    // caller's buffer directly (no std::string materialization).
    if (this->noise_transport_.is_active()) {
        SsErr err = this->send_encrypted_text(json, len);
        if (cb) {
            cb(err == SsErr::OK);
        }
        return err;
    }
    // Pre-handshake cold path: the text-frame API takes a std::string.
    return this->send_text_message(std::string(json, len), std::move(cb), allow_before_hello);
}

// ============================================================================
// Noise transport (Phase 2)
// ============================================================================

void SendspinConnection::init_noise_handshake(const Identity& identity,
                                              const RecordStore& record_store,
                                              const std::string& suite_name) {
    this->noise_handshake_ = std::make_unique<NoiseHandshake>(identity, record_store, suite_name);
    // Retain for re-handshake (Phase 4b): these pointers outlive connections (owned by the
    // SendspinClient that constructed the manager which called this).
    this->noise_identity_ = &identity;
    this->noise_record_store_ = &record_store;
    this->noise_suite_name_ = suite_name;
}

void SendspinConnection::send_noise_client_init() {
    if (!this->noise_handshake_) {
        return;
    }
    std::string client_init = this->noise_handshake_->build_client_init();
    if (!client_init.empty()) {
        this->send_text_message(client_init, nullptr, /*allow_before_hello=*/true);
    }
}

void SendspinConnection::handle_noise_handshake_text(const std::string& text) {
    if (!this->noise_handshake_) {
        return;
    }

    auto send_fn = [this](const std::string& msg) -> bool {
        auto err = this->send_text_message(msg, nullptr, /*allow_before_hello=*/true);
        return err == SsErr::OK;
    };

    HandshakeFrameResult result = this->noise_handshake_->on_text_frame(text, send_fn);

    if (result == HandshakeFrameResult::ABORT) {
        SS_LOGW(TAG, "Noise handshake aborted; closing connection");
        // Discard handshake state, then close per spec Failure Handling: a handshake-phase
        // failure closes the WebSocket without sending any application-level message.
        this->noise_handshake_.reset();
        this->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
        return;
    }

    if (result == HandshakeFrameResult::COMPLETE) {
        auto outcome = this->noise_handshake_->take_result();
        if (!outcome.has_value()) {
            SS_LOGE(TAG, "Noise handshake: COMPLETE but no result");
            this->noise_handshake_.reset();
            return;
        }
        // Record the server's identity (public key) and the PSK category/psk_id that admitted
        // the connection, resolved by the handshake. Trust enforcement (ConnectionManager,
        // reading get_psk_category()/get_psk_id()) happens on the main loop against
        // server/activate, not here. Every write below happens-before the release store of
        // noise_handshake_complete_ just after it, so main-loop readers that observe
        // is_operational() (itself gated behind server_hello_received_/client_hello_sent_,
        // which cannot be true before the Noise transport is active) see these values.
        this->set_noise_handshake_result(outcome->server_id, outcome->resolved_psk.category,
                                         outcome->resolved_psk.psk_id);
        // Reset the pairing server/activate counter (spec #120): a fresh handshake starts a
        // fresh count for the pairing_index / CPace-sid counter.
        this->reset_pairing_index();
        // Install the cipher session; send_app_json() routes encrypted from here on.
        this->noise_transport_.activate(std::move(outcome->session));
        this->noise_handshake_.reset();
        this->noise_handshake_complete_.store(true, std::memory_order_release);
        SS_LOGI(TAG, "Noise transport active (server_id=%s, psk_category=%d)",
                this->server_information_.server_id.c_str(),
                static_cast<int>(this->get_psk_category()));
    }

    // NEED_MORE, or COMPLETE handled above: nothing else to do until the next frame.
}

bool SendspinConnection::handle_noise_rehandshake(const std::string& msg1_json) {
    // Runs on the NETWORK thread (dispatched from the JSON callback for a decrypted
    // "noise/handshake" message, itself only reachable post-COMPLETE, so this always runs on
    // the same network thread as the decrypt path -- sequential with it, never concurrent).
    if (!this->noise_transport_.is_active()) {
        SS_LOGE(TAG, "handle_noise_rehandshake: no active Noise transport");
        return false;
    }
    if (this->noise_identity_ == nullptr || this->noise_record_store_ == nullptr ||
        this->noise_suite_name_.empty()) {
        SS_LOGE(TAG, "handle_noise_rehandshake: missing identity/record_store/suite -- "
                     "init_noise_handshake() was not called");
        return false;
    }

    // Suppress app-level sends (client/state, client/time) for the duration of the
    // re-handshake. The main loop gates on first_activate_received(), so clearing it here
    // cleanly stops publish_client_state()/the time burst until the new server/activate
    // arrives after the session swap.
    this->first_activate_received_.store(false, std::memory_order_release);

    // Clear the pairing-in-progress flag: the re-handshake is the server's signal that
    // pairing finalized and it is rekeying onto the new long-term PSK.  The quiesce gate
    // (pairing_in_progress) must be cleared here (network thread) before the new
    // server/activate arrives, so the main loop can resume time sync and state publishing.
    // Atomic store - written on network thread, read on main loop.
    this->pairing_in_progress_.store(false, std::memory_order_release);

    // Restart the re-proving watchdog: the connection is once again "awaiting its first
    // server/activate" (under the new keys). ConnectionManager::loop()'s re-proving-deadline
    // check reads this timestamp for current_connection_ (gated on !is_operational()) and
    // drops the connection after REPROVE_TIMEOUT_US (see connection_manager.h) if the post-swap
    // server/hello -> client/hello -> server/activate cycle does not complete in time.
    this->set_provisional_time_us(platform_time_us());

    // Run the two-handshake PSK trick with prologue = the prior handshake hash h.
    auto prior_h = this->noise_transport_.handshake_hash();
    if (!prior_h.has_value()) {
        SS_LOGE(TAG, "handle_noise_rehandshake: no handshake hash available");
        return false;
    }
    const std::string current_server_id = this->server_information_.server_id;

    auto result =
        run_rehandshake_msg1(msg1_json, current_server_id, *this->noise_identity_,
                             *this->noise_record_store_, this->noise_suite_name_, prior_h.value());
    if (!result.has_value()) {
        SS_LOGW(TAG, "handle_noise_rehandshake: re-handshake failed; closing connection");
        return false;
    }

    // Commit: encrypt msg2 under the OLD session and send it, then swap to the new session,
    // both under NoiseTransport's session_mutex_ so a concurrent main-loop encrypt cannot
    // interleave between the msg2 send and the swap.
    SsErr err =
        this->noise_transport_.send_msg2_and_swap(result->msg2_text, std::move(result->session));
    if (err != SsErr::OK) {
        SS_LOGE(TAG, "handle_noise_rehandshake: failed to send msg2 / swap session");
        return false;
    }

    // Update PSK metadata from the re-handshake result. server_id is unchanged (same server).
    this->psk_category_.store(result->resolved_psk.category, std::memory_order_release);
    {
        // Same reason as in set_noise_handshake_result(): get_psk_id() may be reading this
        // string from the main loop (the revocation sweep) while this network thread rewrites it.
        std::lock_guard<std::mutex> lock(this->psk_id_mutex_);
        this->psk_id_ = result->resolved_psk.psk_id;
    }

    // Reset the pairing server/activate counter (spec #120): a re-handshake starts a fresh
    // count for the pairing_index / CPace-sid counter, same as an initial handshake.
    this->reset_pairing_index();

    // Reset hello handshake state so the post-swap server/hello -> client/hello ->
    // server/activate flow re-runs under the new session keys. The caller (network thread)
    // arms the actual hello retry via ConnectionManager::schedule_rehandshake_rearm() once
    // this call returns true.
    this->server_hello_received_.store(false, std::memory_order_release);
    this->client_hello_sent_.store(false, std::memory_order_release);

    SS_LOGI(TAG, "Noise re-handshake complete: server_id=%s psk_category=%d; awaiting server/hello",
            current_server_id.c_str(), static_cast<int>(this->get_psk_category()));
    return true;
}

void SendspinConnection::dispatch_complete_noise_message(uint8_t* plaintext, size_t len,
                                                         int64_t receive_time) {
    // A complete (non-fragment, fully reassembled) transport message. plaintext[0] is the
    // message type; fragment types never reach here.
    const uint8_t type_byte = plaintext[0];

    if (type_byte == MSG_TYPE_JSON_BODY) {
        // Type 0: JSON control body, routed without the type byte. A frame carrying only
        // the type byte (no body) is a malformed/empty JSON message; drop it.
        if (len < 2) {
            SS_LOGW(TAG, "empty JSON body after Noise decrypt; dropping");
            return;
        }
        if (!this->message_dispatch_enabled_.load(std::memory_order_acquire)) {
            return;
        }
        if (this->on_json_message_cb) {
            this->on_json_message_cb(this, reinterpret_cast<const char*>(plaintext + 1), len - 1,
                                     receive_time);
        }
        return;
    }

    // All other types: route as binary role message (full type-prefixed plaintext).
    if (!this->message_dispatch_enabled_.load(std::memory_order_acquire)) {
        return;
    }
    if (this->on_binary_message_cb) {
        this->on_binary_message_cb(this, plaintext, len);
    }
}

// ============================================================================
// WebSocket payload buffer management
// ============================================================================

void SendspinConnection::deallocate_websocket_payload() {
    this->websocket_payload_.reset();
    this->websocket_write_offset_ = 0;
}

void SendspinConnection::reset_websocket_payload() {
    this->websocket_write_offset_ = 0;
}

uint8_t* SendspinConnection::prepare_receive_buffer(size_t data_len) {
    if (!this->websocket_payload_) {
        // First fragment - allocate new buffer
        if (!this->websocket_payload_.allocate(data_len, this->websocket_payload_location_)) {
            SS_LOGE(TAG, "Failed to allocate %zu bytes for websocket payload", data_len);
            return nullptr;
        }
        this->websocket_write_offset_ = 0;
    } else if (this->websocket_write_offset_ + data_len > this->websocket_payload_.size()) {
        // Need to expand buffer for additional fragment
        size_t new_len = this->websocket_write_offset_ + data_len;
        if (!this->websocket_payload_.realloc(new_len)) {
            SS_LOGE(TAG, "Failed to expand websocket payload to %zu bytes", new_len);
            this->deallocate_websocket_payload();
            return nullptr;
        }
    }

    return this->websocket_payload_.data() + this->websocket_write_offset_;
}

void SendspinConnection::commit_receive_buffer(size_t data_len) {
    this->websocket_write_offset_ += data_len;
}

SS_HOT void SendspinConnection::dispatch_completed_message(bool is_text, int64_t receive_time) {
    if (!this->websocket_payload_) {
        return;
    }

    const size_t msg_len = this->websocket_write_offset_;

    // -------------------------------------------------------------------------
    // Pre-handshake: TEXT frames feed the Noise handshake state machine (when one is
    // installed - see init_noise_handshake()). Post-handshake: every frame is BINARY
    // (Noise ciphertext); a connection with no handshake driver installed falls through to
    // the legacy direct-dispatch path unchanged.
    // -------------------------------------------------------------------------
    const bool noise_active = this->noise_handshake_complete_.load(std::memory_order_acquire);
    const bool noise_pending = !noise_active && this->noise_handshake_;

    if (is_text) {
        if (noise_pending) {
            // Feed the handshake driver; it handles server/init and noise/handshake frames.
            std::string text(reinterpret_cast<const char*>(this->websocket_payload_.data()),
                             msg_len);
            this->reset_websocket_payload();
            this->handle_noise_handshake_text(text);
            return;
        }

        if (noise_active) {
            // Post-handshake TEXT frames are a protocol error.
            SS_LOGW(TAG, "Unexpected TEXT frame after Noise handshake is complete; ignoring");
            this->reset_websocket_payload();
            return;
        }

        // No Noise handshake installed on this connection: legacy path (direct JSON dispatch).
        // Hand the JSON callback a pointer straight into the reassembly buffer instead of
        // copying it into a std::string. The callback parses synchronously;
        // reset_websocket_payload() below makes the buffer reusable as soon as it returns, so
        // the callback must not retain the pointer. Not null-terminated; the length is
        // authoritative.
        if (!this->message_dispatch_enabled_.load(std::memory_order_acquire)) {
            this->reset_websocket_payload();
            return;
        }
        if (this->on_json_message_cb) {
            this->on_json_message_cb(this,
                                     reinterpret_cast<const char*>(this->websocket_payload_.data()),
                                     msg_len, receive_time);
        }
        this->reset_websocket_payload();
        return;
    }

    // -------------------------------------------------------------------------
    // Binary frame
    // -------------------------------------------------------------------------
    if (noise_active) {
        // Decrypt in-place; buffer has the full ciphertext (plaintext + 16-byte tag).
        size_t pt_len =
            this->noise_transport_.decrypt_in_place(this->websocket_payload_.data(), msg_len);
        if (pt_len == 0) {
            // Spec Failure Handling: an AEAD failure once in transport mode closes the
            // WebSocket silently. It is also unrecoverable if left open: the underlying Noise
            // decrypt never advances the receive-direction nonce counter on an auth failure, so
            // every later frame on this connection would fail authentication forever too.
            SS_LOGW(TAG, "Noise AEAD failure in transport mode; closing connection");
            this->reset_websocket_payload();
            this->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
            return;
        }
        // Route through the fragment state machine; dispatch any completed message.
        NoiseTransport::CompleteMessage msg =
            this->noise_transport_.accept_plaintext(this->websocket_payload_.data(), pt_len);
        if (msg.malformed) {
            // Spec "Malformed sequences": a fragment-end with nothing in flight, a non-fragment
            // frame while one is in flight, or a reassembled orig_type of 2/3 is a protocol
            // error that MUST close the connection.
            SS_LOGW(TAG, "Malformed fragment sequence; closing connection");
            this->reset_websocket_payload();
            this->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
            return;
        }
        if (msg.data != nullptr) {
            this->dispatch_complete_noise_message(msg.data, msg.len, receive_time);
        }
        this->reset_websocket_payload();
        return;
    }

    if (noise_pending) {
        // A handshake driver is installed but the transport is not up yet, so this frame is
        // unauthenticated application data. It must NOT reach the legacy dispatch below: that
        // path hands the bytes straight to the role binary handlers, which would let any peer
        // that merely completed the WebSocket upgrade inject audio/artwork/visualizer data with
        // the whole Noise/PSK/admission chain bypassed. The TEXT branch above already refuses
        // the same trick by routing pre-handshake text into the handshake driver.
        //
        // Treated as a handshake-phase failure per spec "Failure Handling": close the WebSocket
        // without sending any application-level message.
        SS_LOGW(TAG, "Binary frame before the Noise handshake completed; closing connection");
        this->reset_websocket_payload();
        this->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
        return;
    }

    // No Noise handshake installed (encryption_required == false): legacy binary dispatch
    // (connection retains buffer ownership, callback reads in-place).
    if (!this->message_dispatch_enabled_.load(std::memory_order_acquire)) {
        this->reset_websocket_payload();
        return;
    }
    if (this->on_binary_message_cb) {
        this->on_binary_message_cb(this, this->websocket_payload_.data(), msg_len);
    }
    this->reset_websocket_payload();
}

// ============================================================================
// Phase 5: Pairing finalize watchdog
// ============================================================================

void SendspinConnection::note_pairing_finalize_ack() {
    // After the server acks pair-finalize it rekeys via an in-band re-handshake. Resetting
    // first_activate_received_ and re-arming the provisional timer means
    // ConnectionManager::loop()'s re-proving-deadline check (REPROVE_TIMEOUT_US, gated on
    // !current_connection_->is_operational()) will drop the connection if the server acks but
    // never re-handshakes.
    this->first_activate_received_.store(false, std::memory_order_release);
    this->set_provisional_time_us(platform_time_us());
}

}  // namespace sendspin
