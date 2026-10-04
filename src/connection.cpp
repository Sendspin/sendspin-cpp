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
#include "protocol_messages.h"
#include "protocol_task.h"
#include "sendspin/types.h"
#include "time_filter.h"

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sendspin {

static const char* const TAG = "sendspin.connection";

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinConnection::SendspinConnection() {
    this->noise_transport_.set_frame_sink(
        [this](const uint8_t* data, size_t len,
               const NoiseTransport::FrameWriteHook& before_write) {
            return this->send_transport_frame(data, len, before_write);
        });
}

SendspinConnection::~SendspinConnection() {
    // The last reference is gone, so no transport callback can still run on this connection:
    // the drop log is this thread's now, and no delivery will end its run.
    if (const uint32_t dropped = this->acquire_drop_log_.note_delivery(); dropped != 0) {
        SS_LOGW(TAG, "Dropped %" PRIu32 " messages for want of inbound ring space", dropped);
    }
}

// ============================================================================
// Transport frames
// ============================================================================

SsErr SendspinConnection::send_transport_frame(const uint8_t* data, size_t len,
                                               const NoiseTransport::FrameWriteHook& before_write) {
    if (before_write) {
        before_write();
    }
    // allow_before_hello=true: Noise frames are transport-level and precede the app hello.
    return this->send_binary_message(data, len, nullptr, /*allow_before_hello=*/true);
}

// ============================================================================
// Time filter
// ============================================================================

void SendspinConnection::init_time_filter() {
    this->time_filter_ = std::make_shared<SendspinTimeFilter>(SendspinTimeFilter::Config{});
}

// ============================================================================
// Message sending
// ============================================================================

SsErr SendspinConnection::send_goodbye_reason(SendspinGoodbyeReason reason,
                                              SendCompleteCallback on_complete) {
    // Goodbye must be sent even when Noise transport is active; route through send_app_json
    // so it is encrypted. allow_before_hello=true because goodbye can precede the hello (e.g.,
    // when rejecting an excess connection before the handshake finishes).
    return this->send_app_json(format_client_goodbye_message(reason), std::move(on_complete),
                               /*allow_before_hello=*/true);
}

SsErr SendspinConnection::send_app_json(const std::string& json, SendCompleteCallback cb,
                                        bool allow_before_hello) {
    // Delegate to the pointer/length overload: same routing, same is_active() race-freedom
    // reasoning (see that overload).
    return this->send_app_json(json.data(), json.size(), std::move(cb), allow_before_hello);
}

SsErr SendspinConnection::send_app_json(const char* json, size_t len, SendCompleteCallback cb,
                                        bool allow_before_hello) {
    // is_active() is an atomic read; NoiseTransport owns its own session mutex, so this
    // main-loop check cannot race the protocol-task re-handshake swap: send_encrypted_text
    // re-checks the session under NoiseTransport's own lock.
    if (this->noise_transport_.is_active()) {
        // Post-handshake: encrypt straight from the caller's buffer. The transport's send path
        // takes no callback, so fire cb here on the encrypt result (best-effort).
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
// Time messages
// ============================================================================

namespace {

/// The tag a client/time frame is known by (see time_frame_tag_).
uint32_t time_frame_tag(int64_t client_transmitted) {
    return static_cast<uint32_t>(client_transmitted);
}

}  // namespace

int64_t SendspinConnection::send_time_message() {
    if (!this->is_connected()) {
        return 0;
    }

    int64_t now = platform_time_us();
    // Tag 0 is reserved for "no frame in flight" (see time_frame_tag_).
    if (time_frame_tag(now) == 0) {
        ++now;
    }
    char buf[TIME_MESSAGE_BUF_SIZE];
    const size_t len = format_client_time_message(buf, sizeof(buf), now);
    if (len == 0) {
        return 0;
    }
    // Release: a claim that observes this seed also observes the previous frame's retirement.
    this->time_frame_sent_us_.store(time_frame_tag(now), std::memory_order_release);
    this->time_frame_tag_.store(time_frame_tag(now), std::memory_order_release);

    // No tag check: a connection's time frames reach the socket in send order, so a hook left
    // over from an earlier frame stores a time no later than the current frame's write. Capturing
    // only this keeps the closure in std::function's inline storage.
    const NoiseTransport::FrameWriteHook before_write = [this]() {
        this->time_frame_sent_us_.store(time_frame_tag(platform_time_us()),
                                        std::memory_order_release);
    };
    if (this->noise_transport_.send_json(buf, len, before_write) != SsErr::OK) {
        return 0;
    }
    return now;
}

std::optional<int64_t> SendspinConnection::claim_time_frame(int64_t client_transmitted) {
    // Read before the exchange: a later frame's write time is published after this frame was
    // retired, so observing it makes the exchange fail.
    const uint32_t sent = this->time_frame_sent_us_.load(std::memory_order_acquire);
    uint32_t tag = time_frame_tag(client_transmitted);
    if (tag == 0 ||
        !this->time_frame_tag_.compare_exchange_strong(tag, 0, std::memory_order_acq_rel)) {
        return std::nullopt;
    }
    // Wrapping subtraction, read as signed: a leftover hook that sampled the clock before the seed
    // reads as negative, and the frame then counts as written at the time it carries.
    const auto delay = static_cast<int32_t>(sent - tag);
    return client_transmitted + std::max<int32_t>(delay, 0);
}

// ============================================================================
// Noise transport
// ============================================================================

void SendspinConnection::init_noise_handshake(const Identity& identity,
                                              const RecordStore& record_store,
                                              const std::string& suite_name) {
    this->noise_handshake_ = std::make_unique<NoiseHandshake>(identity, record_store, suite_name);
    // Retain for re-handshake: these pointers outlive connections (owned by the
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
        const std::string& server_error = this->noise_handshake_->server_error_reason();
        if (server_error.empty()) {
            SS_LOGW(TAG, "Noise handshake aborted; closing connection");
        } else {
            SS_LOGW(TAG,
                    "Noise handshake aborted by server/error (reason='%s'); closing connection",
                    server_error.c_str());
        }
        // connection.md "Failure Handling": a handshake-phase failure closes the WebSocket
        // without sending any application-level message.
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
        // the connection, resolved by the handshake. Every write below happens-before the store of
        // noise_handshake_complete_ just after it, so main-loop readers that observe
        // is_operational() (itself gated behind server_hello_received_/client_hello_sent_,
        // which cannot be true before the Noise transport is active) see these values.
        this->set_noise_handshake_result(outcome->server_id, outcome->resolved_psk.category,
                                         outcome->resolved_psk.psk_id);
        // pairing.md "Pairing index": a fresh handshake starts a fresh count for the
        // pairing_index / CPace-sid counter.
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

bool SendspinConnection::handle_noise_rehandshake(std::string_view msg1_json) {
    // Runs on the protocol task (dispatched from the JSON callback for a decrypted
    // "noise/handshake" message, itself only reachable post-COMPLETE, so this always runs on
    // the same thread as the decrypt path, sequential with it and never concurrent).
    if (!this->noise_transport_.is_active()) {
        SS_LOGE(TAG, "handle_noise_rehandshake: no active Noise transport");
        return false;
    }
    if (this->noise_identity_ == nullptr || this->noise_record_store_ == nullptr ||
        this->noise_suite_name_.empty()) {
        SS_LOGE(TAG, "handle_noise_rehandshake: missing identity/record_store/suite; "
                     "init_noise_handshake() was not called");
        return false;
    }

    // Restart the re-proving watchdog (ConnectionManager::scan_reprove_watchdog()): the
    // connection is once again awaiting its first server/activate, under the new keys.
    //
    // This must precede the first_activate_received_ store below. The watchdog reads
    // is_operational() and then get_provisional_time_us() while holding nothing that excludes
    // this thread, so clearing the flag first would let it pair "not operational" with this
    // connection's previous stamp, which for a long-admitted connection is far older than
    // REPROVE_TIMEOUT_US, and drop a healthy connection mid-rekey. In this order the relaxed
    // stamp is sequenced before the release store, so any reader whose acquire load observes
    // the cleared flag is guaranteed to see the fresh stamp with it.
    this->set_provisional_time_us(platform_time_us());

    // Suppress app-level sends (client/state, client/time) for the duration of the
    // re-handshake. The main loop gates on first_activate_received(), so clearing it here
    // cleanly stops publish_client_state()/the time burst until the new server/activate
    // arrives after the session swap.
    this->first_activate_received_.store(false, std::memory_order_release);

    // Clear the pairing-in-progress flag: the re-handshake is the server's signal that
    // pairing finalized and it is rekeying onto the new long-term PSK. Clearing it here
    // (protocol task) before the new server/activate arrives is what makes the main loop read
    // that activate as a fresh one rather than a re-entry into the attempt, and discard any
    // pairing message still in flight as stale.
    // Atomic store: written on the protocol task, read on main loop.
    this->pairing_in_progress_.store(false, std::memory_order_release);

    // Run the deferred-PSK-binding msg1 read with prologue = the prior handshake hash h.
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
        // string from the main loop (the revocation sweep) while the protocol task rewrites it.
        std::lock_guard<std::mutex> lock(this->psk_id_mutex_);
        this->psk_id_ = result->resolved_psk.psk_id;
    }

    // pairing.md "Pairing index": a re-handshake starts a fresh count for the pairing_index /
    // CPace-sid counter, same as an initial handshake.
    this->reset_pairing_index();

    // connection.md "Re-handshake": neither hello is re-sent, so the hello state carries over
    // untouched; the server's first message under the new keys is server/activate, which
    // first_activate_received_ (cleared above) now waits on.
    SS_LOGI(TAG,
            "Noise re-handshake complete: server_id=%s psk_category=%d; awaiting server/activate",
            current_server_id.c_str(), static_cast<int>(this->get_psk_category()));
    return true;
}

void SendspinConnection::dispatch_complete_noise_message(InboundMessage& message) {
    // A complete (non-fragment, fully reassembled) transport message. data[0] is the message
    // type; fragment types never reach here.
    const uint8_t type_byte = message.data[0];

    if (type_byte == MSG_TYPE_JSON_BODY) {
        // Type 0: JSON control body, routed without the type byte. A frame carrying only
        // the type byte (no body) is a malformed/empty JSON message; drop it.
        if (message.len < 2) {
            SS_LOGW(TAG, "empty JSON body after Noise decrypt; dropping");
            return;
        }
        if (this->on_json_message_cb) {
            this->on_json_message_cb(
                this, reinterpret_cast<const char*>(message.data + 1), message.len - 1,
                widen_time_stamp_us(message.receive_time_us, platform_time_us()));
        }
        return;
    }

    // All other types: route as binary role message (full type-prefixed plaintext).
    if (this->on_binary_message_cb) {
        this->on_binary_message_cb(this, message);
    }
}

// ============================================================================
// Inbound messages: protocol task side
// ============================================================================

SS_HOT void SendspinConnection::process_inbound_message(InboundMessage& message) {
    // A connection closed or dropped stops dispatching at once, including frames already
    // received before the close was decided.
    if (this->inbound_gate_.is_detached()) {
        return;
    }
    // Every application frame is BINARY ciphertext: decrypt, reassemble, and read the message
    // type from the leading plaintext byte. Cleartext TEXT frames carry only the pre-transport
    // handshake exchange (server/init, noise/handshake), which the handshake driver consumes.
    //
    // A WS-upgraded connection with no driver yet (outbound between connect and
    // init_noise_handshake()) never hears anything legitimate, so its frames are dropped.
    const bool noise_active = this->noise_handshake_complete_.load(std::memory_order_acquire);
    const bool noise_pending = !noise_active && this->noise_handshake_;

    if (message.kind == InboundKind::TEXT) {
        if (noise_pending) {
            // Feed the handshake driver; it handles server/init and noise/handshake frames.
            this->handle_noise_handshake_text(
                std::string(reinterpret_cast<const char*>(message.data), message.len));
            return;
        }
        if (noise_active) {
            // connection.md "Failure Handling": a cleartext message after the switch to transport
            // mode is a silent failure.
            SS_LOGW(TAG, "TEXT frame in transport mode; closing connection");
            this->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
            return;
        }
        SS_LOGW(TAG, "TEXT frame before the Noise handshake started; dropping");
        return;
    }

    if (!noise_active) {
        if (noise_pending) {
            // A handshake driver is installed but the transport is not up, so this frame is
            // unauthenticated application data. It must not reach the role dispatch: that would
            // let any peer that merely completed the WebSocket upgrade inject audio/artwork data
            // with the Noise/PSK/admission chain bypassed. Treated as a handshake-phase failure
            // per connection.md "Failure Handling": close without any application-level message.
            SS_LOGW(TAG, "Binary frame before the Noise handshake completed; closing connection");
            this->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
            return;
        }
        SS_LOGW(TAG, "Binary frame before the Noise handshake started; dropping");
        return;
    }

    // Decrypt in place: the message holds the full ciphertext (plaintext + 16-byte tag), in the
    // ring item it was received into when it has one.
    const size_t pt_len = this->noise_transport_.decrypt_in_place(message.data, message.len);
    if (pt_len == 0) {
        // Spec Failure Handling: an AEAD failure once in transport mode closes the WebSocket
        // silently. It is also unrecoverable if left open: the underlying Noise decrypt never
        // advances the receive-direction nonce counter on an auth failure, so every later frame
        // on this connection would fail authentication forever too.
        SS_LOGW(TAG, "Noise AEAD failure in transport mode; closing connection");
        this->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
        return;
    }
    // Route through the fragment state machine; dispatch any completed message.
    NoiseTransport::CompleteMessage complete = this->noise_transport_.accept_plaintext(
        message.data, pt_len, this->inbound_gate_.is_admitted());
    if (complete.malformed) {
        // messaging.md "Malformed sequences" is a protocol error the receiver MUST close the
        // connection for; NoiseTransport::CompleteMessage::malformed enumerates the sequences
        // that set it.
        SS_LOGW(TAG, "Malformed fragment sequence; closing connection");
        this->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
        return;
    }
    if (complete.data == nullptr) {
        return;
    }
    if (complete.data == message.data) {
        // A single-frame message: it is the plaintext in place, still in its ring item.
        message.len = complete.len;
        this->dispatch_complete_noise_message(message);
        return;
    }
    // A reassembled message lives in the Noise reassembly buffer, not in a ring item; the frame
    // that completed it (message.item) is the caller's to return.
    InboundMessage reassembled;
    reassembled.data = complete.data;
    reassembled.len = complete.len;
    reassembled.receive_time_us = message.receive_time_us;
    reassembled.kind = InboundKind::BINARY;
    this->dispatch_complete_noise_message(reassembled);
}

bool SendspinConnection::pending_message(InboundMessage& out) {
    if (!this->inbound_gate_.has_pending_message()) {
        return false;
    }
    // The acquire load above orders these reads after the transport's writes before its publish.
    out = InboundMessage{};
    out.data = this->fallback_buf_.data();
    out.len = this->fallback_len_;
    out.receive_time_us = this->fallback_receive_time_us_;
    out.kind = this->fallback_kind_;
    return true;
}

// ============================================================================
// Inbound messages: transport side
// ============================================================================

void SendspinConnection::notify_transport_closed() {
    this->inbound_gate_.mark_transport_closed();
    if (this->inbound_task_ != nullptr) {
        this->inbound_task_->wake();
    }
}

void SendspinConnection::fail_inbound() {
    this->detach_inbound();
    this->close_transport_now();
    if (this->inbound_task_ != nullptr) {
        this->inbound_task_->wake();
    }
}

SS_HOT SendspinConnection::InboundTarget SendspinConnection::begin_inbound_message(
    size_t len, bool is_text, int64_t receive_time_us) {
    if (this->fragment_assembly_open_) {
        // RFC 6455 section 5.4: the fragments of one message are not interleaved with another
        // data message. Failing here also keeps the assembly's continuations off a fallback
        // buffer this message would publish.
        SS_LOGW(TAG, "Data frame inside a fragmented message; closing");
        this->fail_inbound();
        return {nullptr, InboundRoute::CLOSE};
    }
    const InboundTarget target =
        this->route_inbound_message(len, is_text ? InboundKind::TEXT : InboundKind::BINARY,
                                    static_cast<uint32_t>(receive_time_us));
    if (target.route == InboundRoute::DROP) {
        // A dropped message is read and discarded without holding anything, so its start
        // stands in for its completion as proof the peer is alive.
        this->note_message_completed();
    }
    // An admitted connection receives into the ring from here on and nothing is pending once a
    // ring write began, so the fallback buffer goes back to the heap.
    if (this->inbound_item_ != nullptr && this->fallback_buf_.data() != nullptr) {
        this->fallback_buf_.reset();
    }
    return target;
}

SendspinConnection::InboundTarget SendspinConnection::route_inbound_message(size_t len,
                                                                            InboundKind kind,
                                                                            uint32_t stamp) {
    if (this->inbound_ring_ == nullptr || this->inbound_gate_.is_detached()) {
        return {nullptr, InboundRoute::DROP};
    }

    if (!this->inbound_gate_.is_admitted()) {
        if (!InboundGate::pre_admission_message_fits(len)) {
            SS_LOGW(TAG, "Pre-admission message of %zu bytes exceeds the %zu-byte cap; closing",
                    len, InboundGate::PRE_ADMISSION_MESSAGE_BYTES);
            this->fail_inbound();
            return {nullptr, InboundRoute::CLOSE};
        }
        const InboundRoute waited = this->wait_until_writable();
        if (waited != InboundRoute::RECEIVE) {
            return {nullptr, waited};
        }
        if (this->fallback_buf_.size() < len &&
            !this->fallback_buf_.allocate(std::max<size_t>(len, 1), this->fallback_location_)) {
            SS_LOGE(TAG, "Failed to allocate %zu bytes for a pre-admission message; closing", len);
            this->fail_inbound();
            return {nullptr, InboundRoute::CLOSE};
        }
        this->fallback_len_ = len;
        this->fallback_kind_ = kind;
        this->fallback_receive_time_us_ = stamp;
        this->inbound_to_fallback_ = true;
        return {this->fallback_buf_.data(), InboundRoute::RECEIVE};
    }

    if (len > INBOUND_MAX_MESSAGE_BYTES) {
        SS_LOGW(TAG, "Message of %zu bytes exceeds one Noise frame (%zu); closing", len,
                INBOUND_MAX_MESSAGE_BYTES);
        this->fail_inbound();
        return {nullptr, InboundRoute::CLOSE};
    }
    // A pre-admission message still pending from before the admission holds every later write
    // back, so the protocol task sees this connection's messages in order.
    while (!this->inbound_gate_.begin_ring_write()) {
        const InboundRoute waited = this->wait_until_writable();
        if (waited != InboundRoute::RECEIVE) {
            return {nullptr, waited};
        }
    }
    void* item = this->inbound_ring_->acquire(len, INBOUND_ACQUIRE_TIMEOUT_MS);
    if (item == nullptr) {
        this->inbound_gate_.abandon_ring_write();
        // Throttled: see InboundDropLog. Reclamation is in ring order, so with the player
        // holding audio the space behind its oldest chunk is what ran out (see
        // derive_inbound_ring_bytes()): said so, to tell that limit from a stalled protocol task.
        if (this->acquire_drop_log_.note_drop()) {
            const size_t held_audio =
                this->inbound_ring_->quota(InboundHolder::PLAYER).outstanding();
            if (held_audio > 0) {
                SS_LOGW(TAG,
                        "No inbound ring space for a %zu-byte message within %u ms: ring pinned "
                        "behind held audio (%zu bytes held); dropping until there is",
                        len, static_cast<unsigned>(INBOUND_ACQUIRE_TIMEOUT_MS), held_audio);
            } else {
                SS_LOGW(TAG,
                        "No inbound ring space for a %zu-byte message within %u ms; dropping "
                        "until there is",
                        len, static_cast<unsigned>(INBOUND_ACQUIRE_TIMEOUT_MS));
            }
        }
        return {nullptr, InboundRoute::DROP};
    }
    if (const uint32_t dropped = this->acquire_drop_log_.note_delivery(); dropped != 0) {
        SS_LOGW(TAG, "Dropped %" PRIu32 " messages for want of inbound ring space", dropped);
    }
    InboundItemHeader* header = inbound_item_header(item);
    header->connection_id = static_cast<uint32_t>(this->instance_id);
    header->receive_time_us = stamp;
    header->kind = kind;
    this->inbound_item_ = item;
    return {inbound_item_bytes(item), InboundRoute::RECEIVE};
}

SendspinConnection::InboundRoute SendspinConnection::wait_until_writable() {
    if (this->inbound_gate_.wait_until_writable(InboundGate::WRITABLE_WAIT_MS)) {
        return InboundRoute::RECEIVE;
    }
    if (this->inbound_gate_.is_detached()) {
        return InboundRoute::DROP;
    }
    SS_LOGW(TAG, "Protocol task took no pending message in %u ms; closing",
            static_cast<unsigned>(InboundGate::WRITABLE_WAIT_MS));
    this->fail_inbound();
    return InboundRoute::CLOSE;
}

void SendspinConnection::note_message_completed() {
    this->last_receive_time_us_.store(static_cast<uint32_t>(platform_time_us()),
                                      std::memory_order_relaxed);
}

void SendspinConnection::end_inbound_message(bool received) {
    if (received) {
        this->note_message_completed();
    }
    if (this->inbound_item_ != nullptr) {
        void* item = std::exchange(this->inbound_item_, nullptr);
        if (received) {
            this->inbound_ring_->complete(item);
        } else {
            // FreeRTOS cannot cancel an acquire: complete it as DISCARD, which take() returns
            // without handing out, and uncount it.
            inbound_item_header(item)->kind = InboundKind::DISCARD;
            this->inbound_ring_->complete(item);
            this->inbound_gate_.abandon_ring_write();
        }
    } else if (this->inbound_to_fallback_) {
        this->inbound_to_fallback_ = false;
        if (!received || !this->inbound_gate_.publish_pending_message()) {
            return;
        }
    } else {
        return;
    }
    this->inbound_task_->wake();
}

void SendspinConnection::abandon_inbound_message() {
    if (this->inbound_item_ != nullptr) {
        this->end_inbound_message(false);
    }
    this->inbound_to_fallback_ = false;
    this->fragment_dropping_ = false;
    this->fragment_assembly_open_ = false;
}

SendspinConnection::InboundTarget SendspinConnection::begin_inbound_fragment(
    size_t len, bool first, bool is_text, int64_t receive_time_us) {
    // The rare path (see the declaration): a multi-frame WebSocket message is assembled in the
    // fallback buffer whatever the admission state, and routed when its last bytes arrive.
    if (first && this->fragment_assembly_open_) {
        // RFC 6455 section 5.4: a fragmented message ends with its final continuation frame
        // before another data message starts.
        SS_LOGW(TAG, "New fragmented message inside an open one; closing");
        this->fail_inbound();
        return {nullptr, InboundRoute::CLOSE};
    }
    if (first) {
        this->fragment_assembly_open_ = true;
        this->fragment_dropping_ = false;
        if (this->inbound_ring_ == nullptr || this->inbound_gate_.is_detached()) {
            this->fragment_dropping_ = true;
        } else {
            const InboundRoute waited = this->wait_until_writable();
            if (waited == InboundRoute::CLOSE) {
                return {nullptr, InboundRoute::CLOSE};
            }
            this->fragment_dropping_ = waited == InboundRoute::DROP;
        }
        if (!this->fragment_dropping_) {
            // The buffer is the transport's from here: nothing is pending. A dropped message
            // leaves the fields alone, since the protocol task may still be reading a detached
            // connection's pending message through them.
            this->fallback_len_ = 0;
            this->fallback_kind_ = is_text ? InboundKind::TEXT : InboundKind::BINARY;
            this->fallback_receive_time_us_ = static_cast<uint32_t>(receive_time_us);
        }
    } else if (!this->fragment_assembly_open_) {
        // RFC 6455 section 5.4: a continuation frame continues a fragmented message, so one with
        // none open is a protocol error. It never reaches the fallback buffer, which may hold a
        // pending message the protocol task is reading.
        SS_LOGW(TAG, "Continuation frame with no fragmented message open; closing");
        this->fail_inbound();
        return {nullptr, InboundRoute::CLOSE};
    }
    if (this->fragment_dropping_ || this->inbound_gate_.is_detached()) {
        this->fragment_dropping_ = true;
        return {nullptr, InboundRoute::DROP};
    }
    const size_t cap = this->inbound_gate_.is_admitted() ? INBOUND_MAX_MESSAGE_BYTES
                                                         : InboundGate::PRE_ADMISSION_MESSAGE_BYTES;
    if (len > cap - this->fallback_len_) {
        SS_LOGW(TAG, "Multi-frame message exceeds %zu bytes; closing", cap);
        this->fail_inbound();
        return {nullptr, InboundRoute::CLOSE};
    }
    const size_t needed = this->fallback_len_ + len;
    if (this->fallback_buf_.size() < needed) {
        const bool grown = this->fallback_buf_.data() == nullptr
                               ? this->fallback_buf_.allocate(needed, this->fallback_location_)
                               : this->fallback_buf_.realloc(needed);
        if (!grown) {
            SS_LOGE(TAG, "Failed to grow the fallback buffer to %zu bytes; closing", needed);
            this->fail_inbound();
            return {nullptr, InboundRoute::CLOSE};
        }
    }
    return {this->fallback_buf_.data() + this->fallback_len_, InboundRoute::RECEIVE};
}

void SendspinConnection::end_inbound_fragment(size_t len, bool last) {
    if (last) {
        this->fragment_assembly_open_ = false;
        this->note_message_completed();
    }
    if (this->fragment_dropping_) {
        if (last) {
            this->fragment_dropping_ = false;
        }
        return;
    }
    this->fallback_len_ += len;
    if (!last) {
        return;
    }
    if (!this->inbound_gate_.is_admitted()) {
        this->inbound_to_fallback_ = true;
        this->end_inbound_message(true);
        return;
    }
    // Admitted: copy the assembled message into a ring item, the one copy this path costs over
    // a single-frame message, and release the buffer.
    const size_t total = this->fallback_len_;
    const InboundTarget target =
        this->route_inbound_message(total, this->fallback_kind_, this->fallback_receive_time_us_);
    if (target.route != InboundRoute::RECEIVE) {
        return;
    }
    if (this->inbound_item_ == nullptr) {
        // The admission flag cleared in between and the message went to the fallback buffer it
        // is already in.
        this->end_inbound_message(true);
        return;
    }
    std::memcpy(target.data, this->fallback_buf_.data(), total);
    this->fallback_buf_.reset();
    this->fallback_len_ = 0;
    this->end_inbound_message(true);
}

// ============================================================================
// Pre-admission message hold
// ============================================================================

bool SendspinConnection::hold_pre_admission_message(const char* data, size_t len,
                                                    int64_t arrival_us) {
    if (this->held_count_ >= MAX_HELD_MESSAGES || this->held_bytes_ + len > MAX_HELD_BYTES) {
        SS_LOGW(TAG,
                "Pre-admission hold budget spent (%zu/%zu messages, %zu+%zu/%zu bytes); dropping",
                this->held_count_, MAX_HELD_MESSAGES, this->held_bytes_, len, MAX_HELD_BYTES);
        return false;
    }
    if (this->held_messages_.data() == nullptr && !this->held_messages_.allocate(MAX_HELD_BYTES)) {
        SS_LOGW(TAG, "Failed to allocate the pre-admission hold buffer");
        return false;
    }
    std::memcpy(this->held_messages_.data() + this->held_bytes_, data, len);
    this->held_extents_[this->held_count_] = {this->held_bytes_, len, arrival_us};
    this->held_bytes_ += len;
    ++this->held_count_;
    return true;
}

void SendspinConnection::replay_pre_admission_messages(const HeldMessageVisitor& visit) {
    const size_t count = this->held_count_;
    // Cleared before the visits so a message the visitor routes back here cannot be replayed
    // twice or read from a buffer this call is already draining.
    this->held_count_ = 0;
    this->held_bytes_ = 0;
    for (size_t i = 0; i < count; ++i) {
        // The admission that started the replay is read once by its caller; a main-loop drop
        // landing between two messages clears the flag and detaches the gate, and the rest of
        // the hold belongs to a connection that no longer drives the roles.
        if (this->inbound_gate_.is_detached() || !this->inbound_gate_.is_admitted()) {
            SS_LOGD(TAG, "Connection dropped during its admission replay; discarding the rest");
            break;
        }
        const HeldMessageExtent& extent = this->held_extents_[i];
        visit(reinterpret_cast<const char*>(this->held_messages_.data()) + extent.offset,
              extent.length, extent.arrival_us);
    }
    // Returned to the heap now rather than staying allocated for the rest of the session.
    this->held_messages_ = PlatformBuffer{};
}

// ============================================================================
// Pairing finalize watchdog
// ============================================================================

void SendspinConnection::note_pairing_finalize_ack() {
    // Stamp the provisional timer before clearing first_activate_received_, for the reason given
    // in handle_noise_rehandshake(): the watchdog reads is_operational() and then
    // get_provisional_time_us() unsynchronized, so the reverse order lets it pair "not
    // operational" with this connection's previous, arbitrarily old stamp and drop it.
    this->set_provisional_time_us(platform_time_us());
    this->first_activate_received_.store(false, std::memory_order_release);
    // Mark the activities snapshot stale: activities_ still reads [PAIRING] until the post-rekey
    // activate lands, and admission must not keep shielding this as an in-flight pairing.
    this->pairing_finalized_.store(true, std::memory_order_release);
}

}  // namespace sendspin
