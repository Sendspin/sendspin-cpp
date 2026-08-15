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

/// @file connection.h
/// @brief Abstract base class for Sendspin WebSocket connections, providing handshake, time sync,
/// and message buffering

#pragma once

#include "crypto/cpace.h"
#include "crypto/keys.h"
#include "noise_handshake.h"
#include "noise_transport.h"
#include "platform/memory.h"
#include "platform/shadow_slot.h"
#include "platform/types.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "sendspin/config.h"
#include "sendspin/types.h"
#include "time_filter.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sendspin {

/// @brief Callback type for message send completion
/// @param success True if the message was sent successfully, false otherwise.
using SendCompleteCallback = std::function<void(bool)>;

/**
 * @brief Abstract base class for Sendspin connections (server-initiated or client-initiated)
 *
 * This class represents a single connection to a Sendspin server. It manages connection state,
 * time synchronization, message buffering, and the hello handshake. Derived classes implement
 * the actual transport mechanism (e.g., incoming WebSocket server connection or outgoing client).
 *
 * The hub owns connection instances and uses callbacks to receive notifications about messages,
 * handshake completion, and disconnection events.
 *
 * Key responsibilities:
 * - Abstract base for platform-specific WebSocket transports (server and client variants)
 * - Owns and drives the time filter (Kalman-based NTP-style synchronization)
 * - Manages the reassembly payload buffer for fragmented WebSocket frames
 * - Tracks hello handshake state (client_hello_sent / server_hello_received)
 *
 * Usage:
 * 1. Construct a concrete subclass (SendspinServerConnection or SendspinClientConnection)
 * 2. Set the on_connected_cb, on_disconnected_cb, on_json_message_cb, and on_binary_message_cb
 *    callbacks
 * 3. Call start() to initialize the transport and begin connecting
 * 4. Call loop() periodically to drive the state machine and process events
 * 5. Call send_text_message() to send JSON messages to the peer
 * 6. Call disconnect() to send a goodbye message and close the connection
 *
 * @code
 * // Concrete subclass provided by the platform layer
 * auto conn = std::make_unique<SendspinClientConnection>(url, config);
 * conn->on_connected_cb = [](SendspinConnection* c) { c->send_text_message(hello_json, {}); };
 * conn->on_json_message_cb = [](SendspinConnection* c, const char* d, size_t n, int64_t t) {...};
 * conn->on_disconnected_cb = [](SendspinConnection* c) { handle_disconnect(); };
 * conn->start();
 * // Call conn->loop() from a periodic task
 * @endcode
 */
class SendspinConnection : public std::enable_shared_from_this<SendspinConnection> {
public:
    /// @brief Wires the NoiseTransport frame sink to this connection's send_binary_message().
    SendspinConnection();

    virtual ~SendspinConnection();

    /// @brief Starts the connection (e.g., initiates client connection or begins message
    /// processing)
    virtual void start() = 0;

    /// @brief Periodic loop processing (e.g., poll for events, handle state machine)
    virtual void loop() = 0;

    /// @brief Disconnects from the server with a goodbye message
    /// @param reason The reason for disconnecting (e.g., shutdown, another server).
    /// @param on_complete Optional callback invoked after goodbye is sent (or send fails/times
    /// out).
    ///                    For server connections, invoked from httpd worker thread (use defer() if
    ///                    needed). For client connections, invoked synchronously in the calling
    ///                    thread.
    virtual void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) = 0;

    /// @brief Closes the underlying transport immediately, without blocking and without ever
    /// joining/stopping the calling thread.
    ///
    /// disconnect() is NOT safe to call from the network thread on every platform: on host
    /// outbound it ends up calling ix::WebSocket::stop(), and on ESP outbound it ends up calling
    /// esp_websocket_client_stop(), and both of those join/block the transport's own worker
    /// thread. Calling either one from a callback already running on that same thread (e.g. from
    /// dispatch_completed_message(), reached synchronously from the transport's own message
    /// callback) deadlocks that thread; on host, joining the current thread additionally throws
    /// std::system_error, which escapes IXWebSocket's thread entry point uncaught and crashes the
    /// process via std::terminate().
    ///
    /// Each platform implements this with whichever non-blocking close primitive it already uses
    /// elsewhere for the same hazard (see the allocation-failure paths in the platform .cpp files
    /// for precedent): host uses ix::WebSocket::close() (async), ESP client reports the loss and
    /// leaves the actual esp_websocket_client_stop() to the owning connection's destructor (run
    /// off the websocket task), and both server transports use their existing trigger_close().
    ///
    /// The connection is still guaranteed to be reported lost exactly once from the manager's
    /// point of view even when a platform's implementation also lets the transport's normal
    /// asynchronous close/disconnect event fire afterwards: ConnectionManager::drop_connection()
    /// treats a repeat disconnect for a connection it no longer manages as a no-op.
    virtual void close_transport_now() = 0;

    /// @brief Checks if the transport connection is established
    /// @return true if connected, false otherwise.
    virtual bool is_connected() const = 0;

    /// @brief Prevents any further message callbacks from firing on the network thread
    ///
    /// Called on the main thread before connection cleanup so that no stale events from a closing
    /// connection can reach role queues after they have been reset. Thread-safe: the flag is
    /// checked atomically in dispatch_completed_message() which runs on the network thread.
    void disable_message_dispatch() {
        this->message_dispatch_enabled_.store(false, std::memory_order_release);
    }

    /// @brief Checks if the hello handshake has completed successfully
    /// @return true if handshake complete (hello exchange done), false otherwise.
    bool is_handshake_complete() const {
        return this->client_hello_sent_ && this->server_hello_received_;
    }

    /// @brief Checks if the connection has fully proven itself: hello handshake complete AND
    /// the first server/activate has been received and applied.
    ///
    /// This is the nursery's PROVE gate (see ConnectionManager): a connection never occupies
    /// the current slot until this is true, so admission/trust/arbitration always run on real
    /// activity data. Note that is_handshake_complete() already implies the Noise handshake is
    /// complete when one is installed, because client/hello and server/hello are themselves
    /// encrypted application traffic that cannot be sent/received before the Noise transport
    /// is active.
    /// @return true once hello + first server/activate are both done.
    bool is_operational() const {
        return this->is_handshake_complete() && this->first_activate_received();
    }

    /// @brief Whether this connection currently occupies the manager's admitted (current) slot.
    ///
    /// Being operational is not the same as being admitted: a nursery member can complete the
    /// Noise handshake and the hello cycle and still lose arbitration, and every peer that knows
    /// the Sentinel PSK (a spec constant, so effectively any peer on the network) can reach that
    /// state. Admission is where the PSK category is actually checked against the requested
    /// activities (see admission.h), so anything that drives shared client state (the roles)
    /// must gate on THIS, not on the handshake having succeeded.
    ///
    /// Set/cleared only by ConnectionManager::set_current_connection() on the main loop; atomic
    /// because the network thread reads it on the message-dispatch path.
    /// @return true while this connection is the admitted one.
    bool is_admitted() const {
        return this->admitted_.load(std::memory_order_acquire);
    }

    /// @brief Mark this connection as occupying (or vacating) the admitted slot.
    /// ConnectionManager::set_current_connection() is the only caller.
    void set_admitted(bool admitted) {
        this->admitted_.store(admitted, std::memory_order_release);
    }

    // ========================================
    // Noise transport
    // ========================================

    /// @brief Initialize the Noise handshake driver for this connection.
    /// Must be called before the WS connection is open. Also retains identity/record_store/
    /// suite_name pointers so a later in-band re-handshake can be driven after this
    /// initial NoiseHandshake object is destroyed.
    /// @param identity     Client static X25519 identity.
    /// @param record_store Record store for psk_id resolution.
    /// @param suite_name   Noise suite name string.
    void init_noise_handshake(const Identity& identity, const RecordStore& record_store,
                              const std::string& suite_name);

    /// @brief Return true once the Noise handshake has completed and transport is encrypted.
    bool is_noise_handshake_complete() const {
        return this->noise_handshake_complete_.load(std::memory_order_acquire);
    }

    /// @brief Return true if a Noise handshake driver has been installed on this connection.
    bool has_noise_handshake() const {
        return this->noise_handshake_ != nullptr;
    }

    /// @brief Return the full Noise suite name supplied at init_noise_handshake() (e.g.
    /// "Noise_KKpsk2_25519_ChaChaPoly_SHA256"), or an empty string if none was set.
    /// Used to select the AEAD cipher for spec "PSK Wrapping" (see
    /// platform/crypto.h aead_cipher_name_from_noise_suite()).
    ///
    /// Virtual so a fake connection can report a canned suite name without an active Noise
    /// session (mirroring get_noise_handshake_hash() below); production connections keep the
    /// same implementation via dynamic dispatch.
    virtual const std::string& get_noise_suite_name() const {
        return this->noise_suite_name_;
    }

    /// @brief Build and send the client/init TEXT frame that starts the Noise handshake.
    /// No-op if no handshake driver is installed.
    /// Must be called after the WebSocket connection is open (from on_connected_cb).
    void send_noise_client_init();  // implemented in connection.cpp

    /// @brief Handle an in-band re-handshake initiated by the server.
    ///
    /// Called on the NETWORK thread when a decrypted noise/handshake JSON message arrives
    /// after transport is already active (routed here from the SERVER_ACTIVATE-adjacent
    /// dispatch for the "noise/handshake" message type). Runs the deferred-PSK-binding msg1
    /// read with prologue = the current NoiseTransport's handshake_hash(), then commits the new
    /// session via NoiseTransport::send_msg2_and_swap() (msg2 sent under the OLD session,
    /// swap happens under the same lock so a concurrent main-loop encrypt cannot interleave).
    ///
    /// Resets first_activate_received_/server_hello_received_/client_hello_sent_ so the
    /// post-swap server/hello -> client/hello -> server/activate flow re-runs under the new
    /// session keys; the manager's nursery is not involved (the connection stays current/
    /// established throughout, with no drop/reconnect).
    ///
    /// @param msg1_json  The decrypted noise/handshake JSON string (msg1 envelope).
    /// @return true on success (session swapped; a post-swap server/hello is expected next).
    ///         false on any failure (caller should close the WebSocket).
    bool handle_noise_rehandshake(const std::string& msg1_json);

    /// @brief Encrypt and send a JSON string as a Noise transport binary frame.
    /// Thin delegate to NoiseTransport::send_json().
    /// @return SsErr::OK on success.
    SsErr send_encrypted_text(const char* json, size_t len) {
        return this->noise_transport_.send_json(json, len);
    }

    /// @brief Encrypt and send a JSON string as a Noise transport binary frame.
    /// Thin delegate to NoiseTransport::send_json().
    /// @return SsErr::OK on success.
    SsErr send_encrypted_text(const std::string& json) {
        return this->noise_transport_.send_json(json);
    }

    /// @brief Send an application-level JSON message.
    ///
    /// This is the single choke point for all post-handshake application JSON.
    /// - If the Noise transport is active, routes through send_encrypted_text() so the
    ///   frame is encrypted.
    /// - If not yet encrypted (pre-handshake), routes through send_text_message().
    ///
    /// All role senders (client/hello, client/state, client/command, client/goodbye) use this
    /// method. client/time is the one exception: its two send_time_message() overrides capture
    /// the transmit timestamp as close to the wire send as possible and avoid std::string
    /// materialization on the hot path, so they encrypt and send directly instead of routing
    /// through here.
    /// @param json    JSON string to send.
    /// @param cb      Optional send-complete callback (best-effort; see send_text_message).
    /// @param allow_before_hello  Passed through to send_text_message on the pre-noise path.
    /// @return SsErr::OK if queued/sent, error code otherwise.
    SsErr send_app_json(const std::string& json, SendCompleteCallback cb = nullptr,
                        bool allow_before_hello = false);

    /// @brief Pointer/length overload of send_app_json for stack-formatted JSON (e.g. the
    /// periodic client/time messages): encrypts straight from the caller's buffer with no
    /// std::string materialization on the hot encrypted path. The pre-handshake text fallback
    /// (cold: only client/hello-era traffic) builds the string it needs.
    SsErr send_app_json(const char* json, size_t len, SendCompleteCallback cb = nullptr,
                        bool allow_before_hello = false);

    /// @brief Encrypt and send pre-typed binary data as a Noise transport binary frame.
    /// Thin delegate to NoiseTransport::send_binary().
    /// @param data  Pointer to type-prefixed binary bytes (first byte is the role type byte).
    /// @param len   Total length including the type byte.
    /// @return SsErr::OK on success.
    // No client-to-server binary message exists yet, so nothing calls this today.
    // cppcheck-suppress unusedFunction
    SsErr send_encrypted_binary(const uint8_t* data, size_t len) {
        return this->noise_transport_.send_binary(data, len);
    }

    /// @brief Gets the socket file descriptor for this connection
    /// @return Socket fd for server connections, -1 for client connections.
    /// @note Used by the hub to identify which connection closed when notified by the server.
    virtual int get_sockfd() const {
        return -1;
    }

    /// @brief Returns this connection's process-unique instance id
    /// @return A monotonic id assigned at construction, never reused for the lifetime of the
    ///         process. Used to identify a connection across a thread-safe queue without a raw
    ///         pointer, which could ABA-collide with a later connection allocated at the same
    ///         address. Ids start at 1, so 0 is a safe "no connection" sentinel.
    uint64_t get_instance_id() const {
        return this->instance_id;
    }

    /// @brief Records the accept/provisional timestamp (microseconds from platform_time_us()).
    /// Called when the connection is admitted into a manager slot (on_new_connection /
    /// connect_to), which may happen on a network thread. The provisional-connection timeout in
    /// ConnectionManager::loop() reads it on the main loop, hence atomic.
    void set_provisional_time_us(int64_t t) {
        this->provisional_time_us_.store(t, std::memory_order_relaxed);
    }

    /// @brief Returns the accept/provisional timestamp, or 0 if not yet set.
    int64_t get_provisional_time_us() const {
        return this->provisional_time_us_.load(std::memory_order_relaxed);
    }

    /// @brief Sends a text message to the server with a completion callback
    /// @param message The message string to send.
    /// @param cb Callback invoked with the send result. On asynchronous transports it is not
    ///        guaranteed to fire: if the connection is torn down before the queued send runs, or
    ///        the message is dropped by the pre-hello gate, the callback is skipped. Treat it as a
    ///        best-effort completion notification, not an unconditional "send finished" signal.
    /// @param allow_before_hello If true, the message may be sent before the client/hello has been
    ///        sent on this connection (used for the hello itself and for goodbye). If false (the
    ///        default), platform transports that send asynchronously drop the message when no
    ///        client/hello has been sent yet, preserving the "hello is always first" protocol
    ///        invariant. Synchronous transports ignore this flag.
    /// @return SsErr::OK if queued successfully, error code otherwise.
    virtual SsErr send_text_message(const std::string& message, SendCompleteCallback cb,
                                    bool allow_before_hello = false) = 0;

    /// @brief Sends a client/time synchronization message
    ///
    /// The transport implementation captures `client_transmitted` as close to the actual wire
    /// send as possible (e.g., inside the httpd worker on ESP server, just before
    /// `httpd_ws_send_frame_async`) and serializes the JSON inline. This eliminates the queue
    /// latency variance that a hub-thread timestamp would introduce.
    ///
    /// @return true if the message was queued/sent successfully, false otherwise.
    virtual bool send_time_message() = 0;

    /// @brief Sends a binary WebSocket frame to the peer.
    /// @param data   Pointer to the binary payload bytes.
    /// @param len    Number of bytes to send.
    /// @param cb     Optional completion callback (best-effort, may be skipped on teardown).
    /// @param allow_before_hello  If true, bypasses the pre-hello send gate (mirrors the
    ///               same flag on send_text_message; binary frames should not precede the
    ///               Noise handshake, so the default is false).
    /// @return SsErr::OK if queued/sent, error code otherwise.
    virtual SsErr send_binary_message(const uint8_t* data, size_t len, SendCompleteCallback cb,
                                      bool allow_before_hello = false) = 0;

    /// @brief Sends a goodbye message with completion callback
    /// @param reason The reason for disconnecting.
    /// @param on_complete Callback invoked after the goodbye message is sent (or fails).
    /// @return SsErr::OK if sent successfully, error code otherwise.
    SsErr send_goodbye_reason(SendspinGoodbyeReason reason, SendCompleteCallback on_complete);

    /// @brief Closes the connection without sending any application-level message.
    ///
    /// Spec "Failure Handling": handshake-phase failures, an AEAD failure once in transport
    /// mode, and malformed fragment sequences all close the WebSocket without sending a
    /// client/goodbye (or any other application-level message). Every call site is reached from
    /// dispatch_completed_message() on the network thread, so this routes to
    /// close_transport_now() (non-blocking on every platform) instead of disconnect() (which is
    /// not network-thread-safe on host/ESP outbound; see close_transport_now()'s doc comment).
    /// Also disables further message dispatch first, matching the existing allocation-failure
    /// precedent in the platform .cpp files, so a stale frame cannot reach role queues while the
    /// close is in flight.
    /// @param reason Kept only for parity with disconnect()'s signature; no goodbye is
    ///        actually transmitted.
    void close_silently(SendspinGoodbyeReason /*reason*/) {
        this->disable_message_dispatch();
        this->close_transport_now();
    }

    // ========================================
    // Server information accessors
    // ========================================

    /// @brief Gets the server ID (from the Noise handshake result, set at COMPLETE; empty
    /// until then when a Noise handshake is installed on this connection).
    /// @return The server ID string.
    const std::string& get_server_id() const {
        return this->server_information_.server_id;
    }

    /// @brief Gets the server information from the server/hello message
    /// @return The ServerInformationObject (fields empty until hello is received).
    const ServerInformationObject& get_server_information() const {
        return this->server_information_;
    }

    // ========================================
    // server/activate state accessors
    // ========================================

    /// @brief Returns the current activity set declared by server/activate.
    /// Main-loop-only: mutated only by apply_server_activate(), which the connection manager
    /// calls while applying a deferred ServerActivateEvent on the main loop.
    const std::vector<SendspinActivity>& get_activities() const {
        return this->activities_;
    }

    /// @brief Returns the sticky active_roles set declared by server/activate.
    const std::vector<std::string>& get_active_roles() const {
        return this->active_roles_;
    }

    /// @brief Returns true once the first server/activate has been received and applied.
    /// Atomic because re-handshake (network thread, see handle_noise_rehandshake) resets it
    /// to false at the start of a key rotation, while the main loop reads it here and via
    /// is_operational().
    bool first_activate_received() const {
        return this->first_activate_received_.load(std::memory_order_acquire);
    }

    /// @brief Returns the PSK category resolved by the Noise handshake (set at COMPLETE, or
    /// re-handshake). Defaults to SENTINEL when no Noise handshake has completed (e.g. when
    /// encryption is not required on this connection).
    PskCategory get_psk_category() const {
        return this->psk_category_.load(std::memory_order_acquire);
    }

    /// @brief Returns the psk_id of the matched PSK (set at COMPLETE; empty for Sentinel or
    /// when no Noise handshake has completed).
    ///
    /// Returns by value under psk_id_mutex_, which both writers also hold, so this is safe from
    /// any thread at any time. It deliberately does NOT return a reference: psk_id_ is rewritten
    /// on the network thread at handshake COMPLETE and at every in-band re-handshake, and a
    /// server may start a re-handshake at any point after admission, so a reader has no way to
    /// exclude a later write by argument, so only the locking form exists: a reference-returning
    /// accessor would let a caller retain a pointer into psk_id_ that a concurrent re-handshake
    /// could rewrite out from under it.
    ///
    /// Every call site is cold (first activate per handshake, remove-record, unpair), so the
    /// copy is not on any hot path. Callers that need the value more than once must read it once
    /// into a local: two calls can straddle a re-handshake and observe different psk_ids.
    /// @return Copy of the psk_id, or an empty string if no handshake has completed.
    std::string get_psk_id() const {
        std::lock_guard<std::mutex> lock(this->psk_id_mutex_);
        return this->psk_id_;
    }

    /// @brief Returns the pairing method the server selected (from the pairing object of the
    /// last pairing server/activate). Used by the pairing flow.
    const std::optional<SendspinPairMethod>& get_pairing_method() const {
        return this->pairing_method_;
    }

    /// @brief Returns the session PIN length from the pairing object of the last pairing
    /// server/activate (present only for dynamic_pin, validated on receipt).
    const std::optional<int>& get_pairing_pin_length() const {
        return this->pairing_pin_length_;
    }

    /// @brief Returns the count of pairing server/activate messages received since the last
    /// Noise handshake (or re-handshake). See pairing_index_ for the cross-thread contract.
    uint32_t get_pairing_index() const {
        return this->pairing_index_.load(std::memory_order_acquire);
    }

    /// @brief Increments the pairing-server/activate counter and returns the new value.
    /// Call on the main loop exactly once per pairing server/activate that starts or re-enters a
    /// pairing attempt (handle_enter_pairing).
    uint32_t bump_pairing_index() {
        return this->pairing_index_.fetch_add(1, std::memory_order_acq_rel) + 1;
    }

    /// @brief Resets the pairing-server/activate counter to zero.
    /// Call on the network thread when a Noise handshake (initial or re-handshake) completes.
    void reset_pairing_index() {
        this->pairing_index_.store(0, std::memory_order_release);
    }

    // ========================================
    // PIN pairing state (dynamic and static)
    // ========================================

    /// @brief Steps in the PIN PAKE state machine (main-loop-only).
    /// Shared by both dynamic-PIN and static-PIN pairing; AWAIT_SERVER_PAIR_INIT is exclusive
    /// to dynamic PIN (see PinSession::method), the remaining steps (AWAIT_SERVER_PAIR_AUTH
    /// onward) are common to both.
    enum class PinStep : uint8_t {
        IDLE,                        ///< No PIN session active.
        AWAIT_PAIRING_WINDOW,        ///< Gesture-gated attempt (static PIN always; dynamic PIN when
                                     ///< escalated or pin_length < 6): client/pair-pending was sent
                                     ///< and client/pair-init waits for a pairing window to open.
        AWAIT_SERVER_PAIR_INIT,      ///< dynamic PIN only: sent client/pair-init (commit_B);
                                     ///< waiting for server/pair-init.
        AWAIT_SERVER_PAIR_AUTH,      ///< CPace RESPONDER started; waiting for server/pair-auth.
        AWAIT_SERVER_PAIR_CONFIRM,   ///< Sent client/pair-auth and derived; waiting for
                                     ///< server/pair-confirm.
        AWAIT_SERVER_PAIR_FINALIZE,  ///< Sent client/pair-finalize; waiting for
                                     ///< server/pair-finalize.
    };

    /// @brief All PIN-pairing session state (main-loop-only; never touched by network thread).
    /// Shared by both dynamic-PIN and static-PIN pairing; `method` selects the gating policy
    /// and pair-confirm wire shape (only dynamic PIN has a failure counter).
    struct PinSession {
        CPace cpace;
        std::array<uint8_t, 32> nonce_b{};
        std::array<uint8_t, 32> handshake_hash{};
        std::string static_pin_value;  ///< static PIN captured at pairing start (static PIN only).
        int64_t attempt_deadline_us{0};  ///< platform_time_us() deadline for the whole attempt.
        int pin_length{0};
        /// pairing_index captured when this attempt entered pairing (see
        /// SendspinConnection::bump_pairing_index()). Sent on client/pair-init and reused
        /// verbatim for the CPace sid counter, so both stay consistent even if the connection's
        /// running counter advances again before the PAKE steps run.
        uint32_t pairing_index{0};
        SendspinPairMethod method{
            SendspinPairMethod::DYNAMIC_PIN};  ///< Which PIN method this session is running.
        PinStep step{PinStep::IDLE};
        bool pin_displayed{false};  ///< True once a PIN was surfaced via on_display_pairing_pin.
        bool window_shown{false};   ///< True once on_open_pairing_window was surfaced, so
                                    ///< abort/teardown knows to fire on_close_pairing_window.
    };

    /// @brief Return the current PIN session state. Main-loop-only.
    PinSession& pin_session() {
        return this->pin_session_;
    }

    /// @brief Return the Noise handshake hash, or nullopt if no active transport session.
    ///
    /// Safe to call from the main loop during a pairing flow because the NoiseTransport session
    /// is only written on the network thread at handshake COMPLETE (before any server/activate
    /// that can trigger pairing) or at re-handshake swap. During a DYNAMIC_PIN pairing activation
    /// the transport session is stable and active.
    ///
    /// Virtual so a fake connection can report a canned hash without an active Noise session;
    /// production connections keep the same implementation via dynamic dispatch.
    virtual std::optional<std::array<uint8_t, 32>> get_noise_handshake_hash() const {
        return this->noise_transport_.handshake_hash();
    }

    // ========================================
    // Pairing state
    // ========================================

    /// @brief Returns true if a pairing exchange is in progress on this connection.
    /// Written on the main loop (set when entering pairing, cleared on abort).
    /// Also cleared on the network thread by handle_noise_rehandshake().
    /// Must be atomic: written main-loop + network thread, read on main loop.
    bool is_pairing_in_progress() const {
        return this->pairing_in_progress_.load(std::memory_order_acquire);
    }

    /// @brief Returns true if the server has acked server/pair-finalize but no fresh
    /// server/activate has arrived yet, i.e. get_activities() still reports the stale
    /// pre-finalize [PAIRING] set for an exchange that is already complete.
    bool is_pairing_finalized() const {
        return this->pairing_finalized_.load(std::memory_order_acquire);
    }

    /// @brief Sets the pairing-in-progress flag.
    /// Call on the main loop when entering the pairing exchange.
    void set_pairing_in_progress(bool value) {
        this->pairing_in_progress_.store(value, std::memory_order_release);
    }

    /// @brief Stores the pending pairing record, committed if/when the server acks with
    /// server/pair-finalize. A nullopt record = storage-exhausted / shared-PSK case: send the
    /// shared PSK but store nothing on ack. Written on the main loop when entering pairing; taken
    /// on the network thread in the server/pair-finalize handler (the commit must happen there,
    /// before the server's re-handshake msg1 (the next message on the same thread) resolves the new
    /// PSK against the RecordStore). Thin wrapper around pending_pairing_slot_ (ShadowSlot);
    /// latest-wins overwrite, matching write()'s semantics.
    void set_pending_pairing_record(std::optional<SendspinPairingRecord> record) {
        this->pending_pairing_slot_.write(std::move(record));
    }

    /// @brief Atomically returns and clears the pending pairing record. A returned value is a
    /// record to store; nullopt means store nothing (shared-PSK case or no pending pairing:
    /// take() leaves the out-param at its default-constructed nullopt when the slot is clean, so
    /// both cases collapse to the same observable result). Called on the network thread when the
    /// server/pair-finalize ack arrives.
    std::optional<SendspinPairingRecord> take_pending_pairing_record() {
        std::optional<SendspinPairingRecord> out;
        this->pending_pairing_slot_.take(out);
        return out;
    }

    /// @brief Clears all pairing state on this connection. Called on abort or leftover-activate.
    void clear_pairing_state() {
        this->pairing_in_progress_.store(false, std::memory_order_release);
        this->pairing_finalized_.store(false, std::memory_order_release);
        this->pending_pairing_slot_.reset();
        // Reset the dynamic-PIN session (main-loop-only fields; no lock needed).
        this->pin_session_ = PinSession{};
    }

    /// @brief Re-arm the provisional timeout after the server acks server/pair-finalize.
    ///
    /// After the server acks pair-finalize it rekeys via an in-band re-handshake. Re-arming the
    /// provisional timer means ConnectionManager::loop()'s re-proving-deadline check
    /// (REPROVE_TIMEOUT_US, gated on this connection being current and !is_operational()) will
    /// drop the connection if the server acks but never re-handshakes (mirrors the reference's
    /// post-pairing timeout). Runs on the network thread; provisional_time_us_ is atomic.
    /// Implemented in connection.cpp to avoid pulling platform/time.h into this header.
    void note_pairing_finalize_ack();

    /// @brief Returns true if any active role is in the given family (e.g., "player" matches
    /// the active role "player@v1").
    /// @param family Role family name without the "@vN" version suffix.
    bool is_role_active(const std::string& family) const {
        for (const auto& role : this->active_roles_) {
            auto at = role.find('@');
            if (at != std::string::npos && role.substr(0, at) == family) {
                return true;
            }
        }
        return false;
    }

    /// @brief Returns true if the given activity is in the current activity set.
    bool has_activity(SendspinActivity activity) const {
        for (const auto& a : this->activities_) {
            if (a == activity) {
                return true;
            }
        }
        return false;
    }

    /// @brief Applies a server/activate update: stores activities and updates active_roles
    /// (sticky: a nullopt active_roles in the message leaves the prior set unchanged). Sets
    /// first_activate_received_ on every call (including after a re-handshake reset it).
    ///
    /// Main-loop-only: called by ConnectionManager::loop() while applying a deferred
    /// ServerActivateEvent, never from the network thread, so activities_/active_roles_ need
    /// no synchronization of their own.
    /// @param activities Activity list from the message.
    /// @param active_roles Optional roles list (nullopt = keep prior set).
    /// @param pairing_method Method from the activation's pairing object (nullopt when absent).
    ///                       Ignored (stored as nullopt) unless `activities` includes PAIRING
    ///                       (spec: "A client ignores this field when activities does not
    ///                       include 'pairing'").
    /// @param pairing_pin_length Session PIN length from the pairing object (dynamic_pin only);
    ///                           stored under the same PAIRING-activity condition.
    void apply_server_activate(const std::vector<SendspinActivity>& activities,
                               const std::optional<std::vector<std::string>>& active_roles,
                               const std::optional<SendspinPairMethod>& pairing_method,
                               const std::optional<int>& pairing_pin_length) {
        this->activities_ = activities;
        if (active_roles.has_value()) {
            this->active_roles_ = active_roles.value();
        }
        bool has_pairing = false;
        for (const auto& a : activities) {
            if (a == SendspinActivity::PAIRING) {
                has_pairing = true;
                break;
            }
        }
        this->pairing_method_ = has_pairing ? pairing_method : std::nullopt;
        this->pairing_pin_length_ = has_pairing ? pairing_pin_length : std::nullopt;
        this->first_activate_received_.store(true, std::memory_order_release);
        // activities_ is fresh again, so the post-finalize staleness window is over.
        this->pairing_finalized_.store(false, std::memory_order_release);
    }

    // ========================================
    // Callbacks set by the hub to receive notifications
    // ========================================

    /// @brief Callback invoked when a JSON message is received
    /// @param conn Pointer to this connection.
    /// @param data Pointer to the message bytes, owned by the connection. Valid only until the
    /// callback returns; it is reused for the next message immediately afterwards, so the callback
    /// must not retain it. Not null-terminated; use @p len.
    /// @param len Length of the message in bytes.
    /// @param timestamp The client timestamp when the message was received.
    std::function<void(SendspinConnection*, const char*, size_t, int64_t)> on_json_message_cb;

    /// @brief Callback invoked when a binary message is received
    /// @param conn Pointer to this connection.
    /// @param payload Pointer to the binary message data (owned by connection, valid until callback
    /// returns).
    /// @param len Length of the binary message data.
    std::function<void(SendspinConnection*, uint8_t*, size_t)> on_binary_message_cb;

    /// @brief Callback invoked when the transport connection is ready for messaging
    /// @param conn Pointer to this connection.
    /// @note Fired by outbound (client) transports only, once the connect and WebSocket upgrade
    ///       complete; the manager uses it to arm the hello. Inbound server connections are
    ///       delivered to the manager already upgraded (their hello is armed at nursery
    ///       admission) and never fire this.
    std::function<void(SendspinConnection*)> on_connected_cb;

    /// @brief Callback invoked when the connection is closed or lost
    /// @param conn Pointer to this connection.
    std::function<void(SendspinConnection*)> on_disconnected_cb;

    /// @brief Converts a server timestamp to the equivalent client timestamp
    /// @param server_time Server timestamp in microseconds.
    /// @return Equivalent client timestamp in microseconds (0 if time filter not initialized).
    int64_t get_client_time(int64_t server_time) const {
        if (this->time_filter_ == nullptr) {
            return 0;
        }
        return this->time_filter_->compute_client_time(server_time);
    }

    /// @brief Gets the time filter for this connection
    /// @return Pointer to the time filter, or nullptr if not initialized.
    SendspinTimeFilter* get_time_filter() {
        return this->time_filter_.get();
    }

    /// @brief Returns true if the time filter has received at least one measurement
    /// @return True if time synchronization has started, false otherwise.
    bool is_time_synced() const {
        if (this->time_filter_ == nullptr) {
            return false;
        }
        return this->time_filter_->has_update();
    }

    /// @brief Initializes the time filter with Kalman parameters
    void init_time_filter();

    /// @brief Returns the EMA (microseconds) of how long format_client_time_message() takes
    ///
    /// Updated by `send_time_message()` on each call. The serialization happens between when
    /// `client_transmitted` is captured and when the bytes hit the wire, so this EMA estimates
    /// the constant bias subtracted from the embedded timestamp. Reported alongside per-burst
    /// stats for diagnostics. Atomic so the httpd worker (ESP server) can update it while the
    /// hub thread reads it.
    // cppcheck-suppress unusedFunction
    // Not currently called by this repo's own sources.
    int64_t get_serialize_ema_us() const {
        return this->serialize_ema_us_.load(std::memory_order_relaxed);
    }

    /// @brief Folds a new serialization-duration sample into the EMA (1/16 weight)
    /// @param sample_us Measured duration in microseconds.
    void update_serialize_ema(int64_t sample_us) {
        int64_t prev = this->serialize_ema_us_.load(std::memory_order_relaxed);
        const int64_t next = (prev == 0) ? sample_us : ((prev * 15 + sample_us) / 16);
        this->serialize_ema_us_.store(next, std::memory_order_relaxed);
    }

    // ========================================
    // Configuration setters (called by hub after receiving server/hello message)
    // ========================================

    /// @brief Sets the client hello sent flag
    /// @param sent True if client hello message has been sent.
    /// @note Called by hub to track handshake state.
    void set_client_hello_sent(bool sent) {
        this->client_hello_sent_ = sent;
    }

    /// @brief Called by dispatch_completed_message() to drive the noise handshake for an
    /// incoming text frame received before transport mode is established. No-op if no
    /// handshake driver is installed on this connection.
    /// @param text The raw text content of the received TEXT frame.
    ///
    /// On HandshakeFrameResult::ABORT (spec Failure Handling: malformed cleartext message,
    /// unsupported version, unknown suite, psk_id lookup miss, or a msg1 auth failure), this
    /// closes the connection itself via close_silently(); the caller has nothing left to do.
    void handle_noise_handshake_text(const std::string& text);

    /// @brief Returns whether this connection has successfully sent its client/hello.
    /// @return true once a client/hello send has completed on this connection.
    bool has_client_hello_sent() const {
        return this->client_hello_sent_;
    }

    /// @brief Marks that the WebSocket upgrade completed
    /// @note Distinct from is_connected(): on ESP the socket is accepted (and is_connected() true)
    ///       before any WebSocket handshake, so this flag signals that the peer spoke the WebSocket
    ///       protocol. Set by the platform ws_server just before it delivers an inbound connection
    ///       to the manager, or by the outbound transport's connected callback, either way on a
    ///       network thread. Read on the main loop (reap diagnostics), hence atomic with
    ///       release/acquire ordering.
    void mark_ws_upgraded() {
        this->ws_upgraded_.store(true, std::memory_order_release);
    }

    /// @brief Returns whether the WebSocket upgrade completed.
    bool is_ws_upgraded() const {
        return this->ws_upgraded_.load(std::memory_order_acquire);
    }

    /// @brief Sets the server_id and PSK metadata from the Noise handshake result.
    /// Called at COMPLETE in connection.cpp.
    void set_noise_handshake_result(const std::string& server_id, PskCategory psk_category,
                                    const std::string& psk_id) {
        this->server_information_.server_id = server_id;
        this->psk_category_.store(psk_category, std::memory_order_release);
        {
            // Held so a concurrent get_psk_id() (the revocation sweep walking the nursery from
            // the main loop) cannot observe this string mid-assignment.
            std::lock_guard<std::mutex> lock(this->psk_id_mutex_);
            this->psk_id_ = psk_id;
        }
    }

    /// @brief Sets the server hello received flag
    /// @param received True if server hello message has been received.
    /// @note Called by hub when SERVER_HELLO is processed.
    void set_server_hello_received(bool received) {
        this->server_hello_received_ = received;
    }

    /// @brief Sets the server information (from server/hello message)
    /// @param info The ServerInformationObject received during the hello handshake.
    /// @note Called by hub after receiving server/hello message.
    void set_server_information(ServerInformationObject info) {
        this->server_information_ = std::move(info);
    }

    // ========================================
    // Time message state accessors
    // ========================================

    /// @brief Checks if a time message is pending (waiting for response)
    /// @return True if a time message has been sent and a response is expected, false otherwise.
    bool is_pending_time_message() const {
        return this->pending_time_message_;
    }

    /// @brief Sets the pending time message flag
    /// @param pending true if a time message is pending, false to clear the flag
    void set_pending_time_message(bool pending) {
        this->pending_time_message_ = pending;
    }

    // ========================================
    // Initialization setters (called by hub before start)
    // ========================================

    /// @brief Sets the memory location preference for the websocket payload reassembly buffer
    /// @param location PREFER_EXTERNAL (SPIRAM-first) or PREFER_INTERNAL (internal-RAM-first).
    /// @note Must be called before the first received frame; takes effect on the next allocation.
    void set_websocket_payload_location(MemoryLocation location) {
        this->websocket_payload_location_ = location;
    }

    /// @brief Sets the memory location preference for the Noise transport's fragment
    /// reassembly and fragmentation buffers.
    /// @param location PREFER_EXTERNAL (SPIRAM-first) or PREFER_INTERNAL (internal-RAM-first).
    /// @note Must be called before the handshake completes; takes effect on the next allocation.
    void set_noise_buffer_location(MemoryLocation location) {
        this->noise_transport_.set_buffer_location(location);
    }

protected:
    // ========================================
    // Noise transport helpers (connection.cpp)
    // ========================================

    /// @brief Dispatch a complete (non-fragment, fully reassembled) transport message:
    /// type 0 as JSON (without the type byte), all other types as binary role messages.
    void dispatch_complete_noise_message(uint8_t* plaintext, size_t len, int64_t receive_time);

    // ========================================
    // WebSocket payload buffer management
    // ========================================

    /// @brief Deallocates the websocket payload buffer if allocated
    void deallocate_websocket_payload();

    /// @brief Resets the write offset without freeing the buffer (reuses it for the next message)
    void reset_websocket_payload();

    /// @brief Allocates or grows the websocket payload buffer and returns a pointer to the write
    /// position
    ///
    /// For the first fragment, allocates a new buffer of the given size.
    /// For continuation fragments, reallocates to grow the buffer if needed.
    ///
    /// The cumulative size (write offset + data_len) is rejected once it would exceed
    /// MAX_TRANSPORT_PLAINTEXT + 16 bytes, the largest legitimate single Noise transport frame.
    /// This bound applies before the Noise handshake completes, since the caller sizes this
    /// call from unauthenticated peer input (a frame-length probe or a declared message length).
    ///
    /// @param data_len Number of bytes that will be written.
    /// @return Pointer to the write position (websocket_payload_ + websocket_write_offset_), or
    /// nullptr on allocation failure or on exceeding the cap above.
    uint8_t* prepare_receive_buffer(size_t data_len);

    /// @brief Advances the write offset after data has been written into the buffer
    /// @param data_len Number of bytes that were written.
    void commit_receive_buffer(size_t data_len);

    /// @brief Dispatches a fully assembled message to the appropriate callback
    ///
    /// For text messages: invokes on_json_message_cb with a pointer into the reassembly buffer
    /// (no intermediate std::string). For binary messages: invokes on_binary_message_cb. Either
    /// way the buffer is retained and only its write offset is reset afterwards. If the buffer is
    /// null, does nothing.
    ///
    /// @param is_text True if this is a text message, false for binary.
    /// @param receive_time Timestamp when the data was received (microseconds).
    void dispatch_completed_message(bool is_text, int64_t receive_time);

    /// @brief Returns the next process-unique connection id (starts at 1, monotonic).
    /// @note The function-local atomic gives thread-safe, ordering-independent uniqueness.
    static uint64_t next_instance_id() {
        static std::atomic<uint64_t> counter{1};
        return counter.fetch_add(1, std::memory_order_relaxed);
    }

    // ========================================
    // Noise transport state
    // ========================================

    // Struct fields

    /// Encrypted transport: owns the cipher session, its mutex, outbound fragmentation,
    /// and inbound reassembly. See noise_transport.h for the threading contract.
    NoiseTransport noise_transport_;

    /// Message buffering (for websocket frame assembly).
    PlatformBuffer websocket_payload_;

    /// Server identity: name from server/hello, server_id from the Noise handshake result
    /// (or re-handshake; unchanged across a re-handshake since it is the same server).
    ServerInformationObject server_information_{};

    // Pointer fields

    /// Time synchronization filter (Kalman-based).
    std::unique_ptr<SendspinTimeFilter> time_filter_;

    /// Noise handshake driver (active from connection open until handshake complete).
    std::unique_ptr<NoiseHandshake> noise_handshake_;

    /// Retained for re-handshake: pointer to the client identity supplied at
    /// init_noise_handshake(). Lifetime is owned by SendspinClient (outlives connections).
    const Identity* noise_identity_{nullptr};

    /// Retained for re-handshake: pointer to the RecordStore supplied at
    /// init_noise_handshake(). Lifetime is owned by SendspinClient (outlives connections).
    const RecordStore* noise_record_store_{nullptr};

    // 64-bit fields

    /// Monotonic timestamp (platform_time_us()) when this connection was admitted into a manager
    /// slot. Atomic because it is written at admission (possibly on a network thread) and read on
    /// the main loop (provisional-connection timeout check). 0 = not yet set.
    std::atomic<int64_t> provisional_time_us_{0};

    /// EMA (microseconds) of format_client_time_message() duration. Atomic because the ESP
    /// server worker thread updates it while the hub thread reads it for logging.
    std::atomic<int64_t> serialize_ema_us_{0};

    /// Process-unique connection identity (see get_instance_id()). Assigned once at construction.
    const uint64_t instance_id{next_instance_id()};

    // size_t fields
    size_t websocket_write_offset_{0};

    // String fields

    /// Retained for re-handshake: Noise suite name supplied at init_noise_handshake().
    std::string noise_suite_name_{};

    /// psk_id of the PSK matched by the Noise handshake (empty for Sentinel, or when no
    /// Noise handshake has completed). Written on the network thread at handshake COMPLETE and
    /// at every in-band re-handshake; read from both the network thread and the main loop.
    /// Never read directly outside this class: go through get_psk_id(), which takes the mutex
    /// below.
    std::string psk_id_{};

    /// Guards psk_id_. Both writers (set_noise_handshake_result(), handle_noise_rehandshake())
    /// and the sole reader (get_psk_id()) hold it. Held only around the assignment and the copy,
    /// never across a send or a callback.
    mutable std::mutex psk_id_mutex_;

    // Vector fields

    /// Activities declared by server/activate (empty until the first activate is applied).
    /// Main-loop-only: see apply_server_activate().
    std::vector<SendspinActivity> activities_{};

    /// Active roles declared by server/activate (sticky: preserved across activates that omit
    /// the field). Empty until the first activate that includes active_roles.
    std::vector<std::string> active_roles_{};

    /// Pairing method from the pairing object of the last pairing server/activate; nullopt
    /// outside a pairing activation. Read by the pairing flow. Written and read on
    /// the main loop (apply_server_activate runs in ConnectionManager::loop()).
    std::optional<SendspinPairMethod> pairing_method_{};

    /// Session PIN length from the same pairing object (dynamic_pin only); nullopt outside a
    /// pairing activation. Same main-loop-only contract as pairing_method_.
    std::optional<int> pairing_pin_length_{};

    // ========================================
    // Pairing state members
    // ========================================

    /// Dynamic-PIN PAKE session (all fields are main-loop-only; no lock needed).
    PinSession pin_session_{};

    /// True while a Pairing-PSK exchange is in progress on this connection.
    /// Written on the main loop (enter/abort) and by the network thread
    /// (handle_noise_rehandshake clears it when the re-handshake begins).
    /// Read on the main loop (time-burst and publish_client_state quiesce gates).
    /// Atomic because of the network-thread write in handle_noise_rehandshake.
    std::atomic<bool> pairing_in_progress_{false};

    /// True from the moment the server acks server/pair-finalize until fresh activities arrive
    /// (or pairing state is cleared). In that window the exchange is protocol-complete (the
    /// record is already stored), but `activities_` still holds the pre-finalize [PAIRING] set,
    /// because only apply_server_activate() ever rewrites it and the post-finalize activate has
    /// not arrived yet. Admission consults this so the "in-flight pairing is not displaced" rule
    /// stops protecting a pairing that has already finished (see should_switch_to_new_server).
    /// Written on the network thread (note_pairing_finalize_ack) and the main loop
    /// (apply_server_activate / clear_pairing_state); read on the main loop. Hence atomic.
    std::atomic<bool> pairing_finalized_{false};

    /// Pending pairing record to be committed when the server/pair-finalize ack arrives (nullopt
    /// = shared-PSK / nothing to store). Written on the main loop (enter pairing), taken on the
    /// network thread (server/pair-finalize handler), cleared on the main loop (abort/leftover).
    /// A ShadowSlot: latest-wins write, take-and-clear read, single mutex internal to the slot.
    ShadowSlot<std::optional<SendspinPairingRecord>> pending_pairing_slot_{};

    /// Count of pairing server/activate messages received since the last Noise handshake (or
    /// re-handshake) (spec "Pairing index"). Feeds both the wire `pairing_index` field on
    /// client/pair-init and the CPace `sid` counter (see PinSession::pairing_index, captured at
    /// handle_enter_pairing() so a later PAKE step reuses the exact value client/pair-init sent).
    /// Written on the main loop (bump_pairing_index(), each pairing server/activate) and on the
    /// network thread (reset_pairing_index(), at handshake/re-handshake completion); atomic for
    /// that cross-thread reset.
    std::atomic<uint32_t> pairing_index_{0};

    // 8-bit fields

    /// Lifecycle-flag axes.
    ///
    /// The six atomic flags in this section are not one linear lifecycle. They form three
    /// independent axes:
    ///
    ///  - Transport axis: ws_upgraded_. Set once by the platform ws_server / outbound connected
    ///    callback (network thread); read for reap diagnostics (see SetupStage in
    ///    connection_manager.cpp).
    ///  - Proving axis: noise_handshake_complete_ is set ONCE on the network thread at handshake
    ///    COMPLETE and never cleared: not even by an in-band re-handshake, because the transport
    ///    stays active across it. Alongside it, the RESETTABLE trio client_hello_sent_ /
    ///    server_hello_received_ / first_activate_received_ tracks the hello + first-activate
    ///    cycle, which does re-run on re-handshake.
    ///  - Admission axis: admitted_ (whether this connection occupies the manager's current
    ///    slot). Written only by ConnectionManager::set_current_connection() / drop_connection() on
    ///    the main loop; read by the network thread's role-dispatch gate. Orthogonal to proving:
    ///    an operational nursery loser is never admitted, and after a re-handshake the current
    ///    connection is admitted but temporarily NOT operational.
    ///
    /// Writer/thread map:
    ///  - client_hello_sent_: set by the hello send-completion callback in
    ///    ConnectionManager::send_hello_message (httpd worker thread on ESP, inline on host);
    ///    cleared by handle_noise_rehandshake (network thread) at the start of a key rotation
    ///    and by the outbound transports' disconnect handlers (esp/host client_connection.cpp,
    ///    transport thread). Inbound connections are never reset on disconnect: a dropped
    ///    server connection is torn down, not reused.
    ///  - server_hello_received_: set by SendspinClient::process_json_message on server/hello
    ///    (network thread); cleared by the same two paths as client_hello_sent_.
    ///  - first_activate_received_: set by apply_server_activate (main loop only); cleared by
    ///    handle_noise_rehandshake and note_pairing_finalize_ack (both network thread).
    ///  - noise_handshake_complete_: set once in handle_noise_handshake_text at COMPLETE (network
    ///    thread); never cleared.
    ///  - admitted_: main loop only (ConnectionManager).
    ///  - ws_upgraded_: network threads (platform ws_server / connect_to connected callback).
    ///
    /// Why not a single phase enum:
    ///  - The order is not total: client_hello_sent_ and server_hello_received_ flip
    ///    independently on different threads and can complete in either order (a nonconforming
    ///    peer's server/hello can race ahead of our client/hello send completion). That is exactly
    ///    why the manager's promotion scan is level-triggered rather than edge-triggered. A single
    ///    enum would force an ordering that does not exist.
    ///  - Transitions are non-monotonic by design: handle_noise_rehandshake rewinds the hello +
    ///    activate flags from the network thread while the main loop reads them;
    ///    note_pairing_finalize_ack rewinds first_activate_received_ alone. Monotonic-transition
    ///    assertions would fire on legitimate operation.
    ///  - The axes are orthogonal (see above), so one scalar cannot represent, e.g., "admitted but
    ///    not operational" during re-proving.
    ///  - The sanctioned way to get a readable single "phase" is to DERIVE it on demand from these
    ///    flags, as SetupStage in connection_manager.cpp does for reap diagnostics: derived,
    ///    never stored, so it cannot go stale.

    /// PSK category resolved by the Noise handshake (set at COMPLETE, or re-handshake).
    /// Atomic because get_psk_category() is read on the main loop (build_hello_message via the
    /// hello-retry path) while the network thread writes it at COMPLETE / re-handshake.
    std::atomic<PskCategory> psk_category_{PskCategory::SENTINEL};

    /// Hello handshake state. Atomic because it is set from the send-completion callback (the httpd
    /// worker thread on ESP) and the disconnect handlers (network thread), while
    /// is_handshake_complete() and the pre-hello send gate read it from other threads.
    std::atomic<bool> client_hello_sent_{false};

    /// True once the Noise transport handshake has completed (set on the network thread,
    /// read from the main loop via is_noise_handshake_complete()).
    std::atomic<bool> noise_handshake_complete_{false};

    /// True while this connection occupies the manager's admitted (current) slot. Written only
    /// by ConnectionManager::set_current_connection() on the main loop; read on the network
    /// thread by the role-dispatch gate. See is_admitted().
    std::atomic<bool> admitted_{false};

    /// true once the transport delivered the connected event (WebSocket upgrade completed).
    /// Written from the transport connected callback (network thread), read by the manager's
    /// setup-stage derivation on the main loop and on other network threads, hence atomic.
    /// See mark_ws_upgraded().
    std::atomic<bool> ws_upgraded_{false};

    /// true if the current message being assembled is text, false if binary
    /// Needed because WebSocket continuation frames do not carry the original frame type
    bool is_text_frame_{false};

    /// When false, dispatch_completed_message() silently drops incoming messages.
    /// Set to false on the main thread before cleanup; checked on the network thread.
    std::atomic<bool> message_dispatch_enabled_{true};

    /// Time message state. Written by the main-loop time burst and cleared by the transport
    /// thread's disconnect handler, hence atomic.
    std::atomic<bool> pending_time_message_{false};

    /// Atomic for the same reason as client_hello_sent_: written on network threads, read from the
    /// main loop via is_handshake_complete().
    std::atomic<bool> server_hello_received_{false};

    /// True after the first server/activate message has been received and applied. Atomic
    /// because re-handshake (network thread, handle_noise_rehandshake) resets it to false at
    /// the start of a key rotation, while the main loop reads it via first_activate_received()
    /// / is_operational() and apply_server_activate() (main-loop-only) sets it back to true.
    std::atomic<bool> first_activate_received_{false};

    /// Memory placement preference for `websocket_payload_` allocations (ESP-IDF only).
    MemoryLocation websocket_payload_location_{MemoryLocation::PREFER_EXTERNAL};
};

}  // namespace sendspin
