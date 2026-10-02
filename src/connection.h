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
#include "platform/crypto.h"
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
#include <string_view>
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
 */
class SendspinConnection : public std::enable_shared_from_this<SendspinConnection> {
public:
    /// @brief Wires the NoiseTransport frame sink to this connection's send_transport_frame().
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
    /// disconnect() is not safe to call from the network thread on every platform: on host
    /// outbound it ends up calling ix::WebSocket::stop(), and on ESP outbound it ends up calling
    /// esp_websocket_client_stop(), and both of those join/block the transport's own worker
    /// thread. Calling either one from a callback already running on that same thread (e.g. from
    /// dispatch_completed_message(), reached synchronously from the transport's own message
    /// callback) deadlocks that thread; on host, joining the current thread additionally throws
    /// std::system_error, which escapes IXWebSocket's thread entry point uncaught and crashes the
    /// process via std::terminate().
    ///
    /// Each platform implements this with whichever non-blocking close primitive it already uses
    /// elsewhere for the same hazard.
    ///
    /// A connection is still reported lost exactly once: ConnectionManager::drop_connection()
    /// no-ops on a repeat disconnect for a connection it no longer manages.
    virtual void close_transport_now() = 0;

    /// @brief Checks if the transport connection is established
    /// @return true if connected, false otherwise.
    virtual bool is_connected() const = 0;

    /// @brief Whether this client opened the connection (connect_to()) rather than accepted it
    virtual bool is_outbound() const {
        return false;
    }

    /// @brief Prevents any further message callbacks from firing on the network thread
    ///
    /// Called before connection cleanup (on either thread) so that no stale events from a closing
    /// connection can reach role queues after they have been reset; the flag is checked atomically
    /// in dispatch_completed_message() on the network thread. Also retires the client/time frame
    /// in flight, so a server/time already past that check cannot claim it and overwrite the next
    /// connection's measurement.
    void disable_message_dispatch() {
        this->message_dispatch_enabled_.store(false, std::memory_order_release);
        this->cancel_time_frame();
    }

    /// @brief Checks if the hello handshake has completed successfully
    /// @return true if handshake complete (hello exchange done), false otherwise.
    bool is_handshake_complete() const {
        return this->client_hello_sent_ && this->server_hello_received_;
    }

    /// @brief True once the connection has proven itself: hello handshake complete and the first
    /// server/activate applied.
    ///
    /// This is the nursery's prove gate (see ConnectionManager). is_handshake_complete() already
    /// implies the Noise handshake, since both hellos are encrypted application traffic.
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
    /// must gate on this, not on the handshake having succeeded.
    ///
    /// Written on the main loop only (see set_admitted()); atomic because the network thread
    /// reads it on the message-dispatch path.
    /// @return true while this connection is the admitted one.
    bool is_admitted() const {
        return this->admitted_.load(std::memory_order_acquire);
    }

    /// @brief Mark this connection as occupying (or vacating) the admitted slot.
    /// Set by SendspinClient::admit_connection(); cleared by ConnectionManager, from
    /// set_current_connection(), drop_connection(), and stop().
    /// @param admitted Whether this connection now occupies the admitted slot.
    void set_admitted(bool admitted) {
        // The transport keeps its own copy: its reassembly cap is tighter until the connection
        // is admitted, and it is read on the network thread. Widen that cap before the dispatch
        // gate opens and narrow it only after the gate closes, so the network thread never sees
        // a gate wider than the cap behind it.
        if (admitted) {
            this->noise_transport_.set_admitted(true);
        }
        this->admitted_.store(admitted, std::memory_order_release);
        if (!admitted) {
            this->noise_transport_.set_admitted(false);
        }
    }

    /// @brief Notes that a server/activate from this connection reached the dispatch path.
    ///
    /// Distinct from first_activate_received(), which the main loop sets once it has APPLIED an
    /// activate. This one is set by the network thread the moment one is handed off, and is what
    /// tells the dispatch gate that role traffic arriving now belongs to an activation the main
    /// loop has not resolved yet (see hold_pre_admission_message()). Never cleared: a connection
    /// that has sent one activate is a peer whose later role traffic is worth holding.
    void note_activate_delivered() {
        this->activate_delivered_.store(true, std::memory_order_release);
    }

    /// @brief Whether a server/activate from this connection has reached the dispatch path.
    bool activate_delivered() const {
        return this->activate_delivered_.load(std::memory_order_acquire);
    }

    /// @brief Receives one held role message: its bytes and the arrival time the live path would
    /// have processed it with.
    using HeldMessageVisitor =
        std::function<void(const char* data, size_t len, int64_t arrival_us)>;

    /// @brief Holds a role message that arrived before admission, for replay at admission.
    ///
    /// A server sends role traffic as soon as it has sent its server/activate, but admission is
    /// decided on the main loop one tick later, so the messages in between would otherwise be
    /// lost (a one-shot server/state carries state that is never repeated). Holding them here
    /// keeps the admission gate: a connection that never wins admission never replays anything,
    /// and its held messages die with it. Only messages that follow an activate are held.
    ///
    /// The storage has no lock of its own: every call, here and in
    /// replay_pre_admission_messages(), runs under SendspinClient's json_processing_mutex_, which
    /// is what orders the network thread's dispatch against the main loop's replay.
    /// @param data Raw JSON text (not null-terminated).
    /// @param len Length of the JSON text in bytes.
    /// @param arrival_us Receive timestamp in microseconds.
    /// @return true if the message was held, false when the budget is full.
    bool hold_pre_admission_message(const char* data, size_t len, int64_t arrival_us);

    /// @brief Passes each held role message to `visit`, in arrival order, then drops them all.
    /// Same locking contract as hold_pre_admission_message().
    /// @param visit Called once per held message, with the message bytes and its arrival time.
    void replay_pre_admission_messages(const HeldMessageVisitor& visit);

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
    /// Used to select the AEAD cipher for pairing.md "Wrapping" (see
    /// platform/crypto.h aead_cipher_name_from_noise_suite()).
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
    /// Resets first_activate_received_ so the connection waits for the post-swap
    /// server/activate that connection.md "Re-handshake" makes the server's first message under
    /// the new keys; neither hello is re-sent, and the manager's nursery is not involved (the
    /// connection stays current/established throughout, with no drop/reconnect).
    ///
    /// @param msg1_json  The decrypted noise/handshake JSON string (msg1 envelope).
    /// @return true on success (session swapped; a post-swap server/activate is expected next).
    ///         false on any failure (caller should close the WebSocket).
    bool handle_noise_rehandshake(std::string_view msg1_json);

    /// @brief Encrypt and send a JSON string as a Noise transport binary frame.
    /// Thin delegate to NoiseTransport::send_json().
    /// @return SsErr::OK on success.
    SsErr send_encrypted_text(const char* json, size_t len) {
        return this->noise_transport_.send_json(json, len);
    }

    /// @brief std::string overload of send_encrypted_text().
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
    /// All role senders use this method. client/time is the one exception: send_time_message()
    /// calls NoiseTransport::send_json() directly to pass its write hook.
    /// @return SsErr::OK if queued/sent, error code otherwise.
    /// @note The encrypted path blocks on the Noise session mutex, which the network thread also
    ///       holds across its own sends. On an ESP outbound connection that send blocks for up to
    ///       the transport's 10 ms send timeout (src/esp/client_connection.cpp), so a call from
    ///       loop() can stall that long, once per frame for a fragmented message since the lock
    ///       spans the whole fragment loop.
    SsErr send_app_json(const std::string& json, SendCompleteCallback cb = nullptr,
                        bool allow_before_hello = false);

    /// @brief Pointer/length form of send_app_json(); encrypts straight from the caller's
    /// buffer, and the pre-handshake text fallback builds the string it needs
    SsErr send_app_json(const char* json, size_t len, SendCompleteCallback cb = nullptr,
                        bool allow_before_hello = false);

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

    /// @brief Returns the low 32 bits of the last complete inbound message's arrival time.
    uint32_t get_last_receive_time_us() const {
        return this->last_receive_time_us_.load(std::memory_order_relaxed);
    }

    /// @brief Sends a text message to the server with a completion callback
    /// @param message The message string to send.
    /// @param cb Callback invoked with the send result. On asynchronous transports it is not
    ///        guaranteed to fire: if the connection is torn down before the queued send runs, or
    ///        the message is dropped by the pre-hello gate, the callback is skipped. Treat it as a
    ///        best-effort completion notification, not an unconditional "send finished" signal.
    /// @param allow_before_hello Lets the message precede this connection's client/hello (used by
    ///        the hello itself and by goodbye). Otherwise asynchronous transports drop it, which
    ///        is what keeps "hello is always first". Synchronous transports ignore the flag.
    /// @return SsErr::OK if queued successfully, error code otherwise.
    virtual SsErr send_text_message(const std::string& message, SendCompleteCallback cb,
                                    bool allow_before_hello = false) = 0;

    /// @brief Sends a client/time message and records it as the frame in flight (see
    /// time_frame_tag_). Needs the Noise transport, which is_operational() implies. Main loop only.
    /// @return The client_transmitted the frame carries, or 0 if the message was not queued/sent.
    int64_t send_time_message();

    /// @brief Claims the client/time frame in flight for a server/time reply echoing
    /// `client_transmitted`, matching on its low 32 bits; the claim retires the frame, so at most
    /// one reply per frame succeeds. Network thread.
    /// @return When the frame was handed to the socket, never earlier than the echo nor later
    ///         than the write, or nullopt if no frame in flight carries that value.
    std::optional<int64_t> claim_time_frame(int64_t client_transmitted);

    /// @brief Retires the client/time frame in flight, so a late reply to it no longer matches
    void cancel_time_frame() {
        this->time_frame_tag_.store(0, std::memory_order_release);
    }

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
    /// connection.md "Failure Handling": handshake-phase failures, an AEAD failure once in
    /// transport mode, and malformed fragment sequences all close the WebSocket without sending a
    /// client/goodbye (or any other application-level message). Every call site is reached from
    /// dispatch_completed_message() on the network thread, so this routes to
    /// close_transport_now() (non-blocking on every platform) instead of disconnect() (which is
    /// not network-thread-safe on host/ESP outbound; see close_transport_now()). Dispatch is
    /// disabled first, so a stale frame cannot reach role queues while the close is in flight.
    void close_silently(SendspinGoodbyeReason /*reason*/) {
        this->disable_message_dispatch();
        this->close_transport_now();
    }

    // ========================================
    // Server information accessors
    // ========================================

    /// @brief Gets the server ID from the Noise handshake result (set at COMPLETE; empty until
    /// then when a Noise handshake is installed on this connection).
    const std::string& get_server_id() const {
        return this->server_information_.server_id;
    }

    /// @brief Gets the server information from the server/hello message (empty until received).
    const ServerInformationObject& get_server_information() const {
        return this->server_information_;
    }

    // ========================================
    // server/activate state accessors
    // ========================================

    /// @brief Returns the current activity set declared by server/activate. Main-loop-only.
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
    /// any thread. psk_id_ is rewritten on the network thread at every in-band re-handshake, and
    /// a server may start one at any point after admission, so a caller that needs the value more
    /// than once must read it into a local: two calls can straddle a re-handshake and observe
    /// different psk_ids. Every call site is cold, so the copy is off any hot path.
    std::string get_psk_id() const {
        std::lock_guard<std::mutex> lock(this->psk_id_mutex_);
        return this->psk_id_;
    }

    /// @brief Returns the pairing method the server selected (from the pairing object of the
    /// last pairing server/activate). Used by the pairing flow.
    const std::optional<SendspinPairMethod>& get_pairing_method() const {
        return this->pairing_method_;
    }

    /// @brief Returns the emission format from the pairing object of the last pairing
    /// server/activate (present only for dynamic_pairing_code, validated on receipt).
    const std::optional<SendspinPairingCodeFormat>& get_pairing_format() const {
        return this->pairing_format_;
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
    // Pairing-code session state (dynamic and static)
    // ========================================

    /// @brief Steps in the pairing-code PAKE state machine (main-loop-only).
    /// Shared by both code-based methods; AWAIT_SERVER_PAIR_INIT is exclusive to the dynamic
    /// pairing code (see PairingSession::method), the remaining steps (AWAIT_SERVER_PAIR_AUTH
    /// onward) are common to both.
    enum class PairingStep : uint8_t {
        IDLE,                        ///< No pairing-code session active.
        AWAIT_PAIRING_WINDOW,        ///< Gesture-gated attempt: client/pair-pending was sent and
                                     ///< client/pair-init waits for a pairing window to open.
        AWAIT_SERVER_PAIR_INIT,      ///< dynamic pairing code only: sent client/pair-init
                                     ///< (commit_B) or client/pair-retry; waiting for the
                                     ///< round's server/pair-init.
        AWAIT_SERVER_PAIR_AUTH,      ///< CPace RESPONDER started; waiting for server/pair-auth.
        AWAIT_SERVER_PAIR_CONFIRM,   ///< Sent client/pair-auth and derived; waiting for
                                     ///< server/pair-confirm.
        AWAIT_SERVER_PAIR_FINALIZE,  ///< Sent client/pair-finalize; waiting for
                                     ///< server/pair-finalize.
    };

    /// @brief All pairing-code session state (main-loop-only; never touched by network thread).
    /// Shared by both code-based methods; `method` selects the gating policy, whether the
    /// attempt runs further rounds, and the pair-confirm wire shape.
    struct PairingSession {
        CPace cpace;
        std::array<uint8_t, 32> nonce_b{};
        /// nonce_A from the attempt's first server/pair-init. pairing.md "Rounds" keeps the
        /// binding values, and so the pairing code, unchanged across an attempt's rounds, and a
        /// later round's server/pair-init carries no nonce.
        std::array<uint8_t, 32> nonce_a{};
        std::array<uint8_t, 32> handshake_hash{};
        /// The pairing code as CPace consumes it (PRS, pairing.md "PAKE"): the six or eight ASCII
        /// digits, or the 24 raw bytes of the qr_code emission format.
        std::vector<uint8_t> prs;
        /// platform_time_us() deadline for the whole attempt; the Pairing PSK Flow arms it too.
        int64_t attempt_deadline_us{0};
        /// pairing_index captured when this attempt entered pairing (see
        /// SendspinConnection::bump_pairing_index()). Sent on client/pair-init and reused
        /// verbatim for the CPace sid, so both stay consistent even if the connection's running
        /// counter advances again before the PAKE steps run.
        uint32_t pairing_index{0};
        /// Number of the round within this attempt, 1 for the first, feeding the CPace sid
        /// (pairing.md "PAKE"). 0 until the attempt's first round begins; always 1 in the Static
        /// Pairing Code Flow, which runs a single round.
        uint32_t round{0};
        SendspinPairMethod method{SendspinPairMethod::DYNAMIC_PAIRING_CODE};
        /// Emission format the server selected; meaningful for DYNAMIC_PAIRING_CODE only.
        SendspinPairingCodeFormat format{SendspinPairingCodeFormat::DIGITS};
        PairingStep step{PairingStep::IDLE};
        bool code_emitted{false};  ///< True once a code was surfaced via on_display_pairing_code.
        bool window_shown{false};  ///< True once on_open_pairing_window was surfaced, so
                                   ///< abort/teardown knows to fire on_close_pairing_window.

        PairingSession() = default;

        /// @brief Wipes the pairing code and both binding nonces on destruction. `prs` lives on
        /// the heap, so releasing it unwiped would leave the code in freed memory.
        ~PairingSession() {
            secure_zero_container(this->nonce_b);
            secure_zero_container(this->nonce_a);
            if (!this->prs.empty()) {
                secure_zero(this->prs.data(), this->prs.size());
            }
        }

        /// Reached only by reference (pairing_session()); a copy would carry the code and the
        /// nonces into a second buffer nothing wipes.
        PairingSession(const PairingSession&) = delete;
        PairingSession& operator=(const PairingSession&) = delete;
    };

    /// @brief Return the current pairing-code session state. Main-loop-only.
    PairingSession& pairing_session() {
        return this->pairing_session_;
    }

    /// @brief Return the Noise handshake hash, or nullopt if no active transport session.
    ///
    /// Safe to call from the main loop during a pairing flow because the NoiseTransport session
    /// is only written on the network thread at handshake COMPLETE (before any server/activate
    /// that can trigger pairing) or at re-handshake swap. During a pairing-code activation
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
    /// server/pair-finalize. Written on the main loop when entering pairing; taken on the
    /// network thread in the server/pair-finalize handler (the commit must happen there, before
    /// the server's re-handshake msg1 (the next message on the same thread) resolves the new PSK
    /// against the RecordStore). Thin wrapper around pending_pairing_slot_ (ShadowSlot);
    /// latest-wins overwrite, matching write()'s semantics.
    void set_pending_pairing_record(SendspinPairingRecord record) {
        this->pending_pairing_slot_.write(std::move(record));
    }

    /// @brief Atomically returns and clears the pending pairing record. A returned value is a
    /// record to store; nullopt means there was no pending pairing (take() leaves the out-param
    /// at its default-constructed nullopt when the slot is clean). Called on the network thread
    /// when the server/pair-finalize ack arrives.
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
        // Reset the pairing-code session (main-loop-only fields; no lock needed). Destroyed and
        // rebuilt in place rather than assigned over: assignment would overwrite the secrets
        // instead of wiping them, and would never run ~PairingSession or ~CPace.
        std::destroy_at(&this->pairing_session_);
        std::construct_at(&this->pairing_session_);
    }

    /// @brief Clears first_activate_received_ and re-arms the provisional timeout after the
    /// server acks server/pair-finalize, so the re-proving watchdog bounds the rekey that
    /// follows. Also sets pairing_finalized_, which stops admission shielding this connection as
    /// an in-flight pairing. Network thread; defined in connection.cpp.
    void note_pairing_finalize_ack();

    /// @brief ORs the roles a just-received server/activate names into the active-role mask.
    ///
    /// Runs on the network thread, where the activate is parsed, so a role the activation adds is
    /// already active for the receive gate when the traffic that legitimately follows it arrives:
    /// messaging.md "server/state" has the server send a re-added role's state promptly, without
    /// waiting for the client's next main-loop tick. Removals are applied in
    /// apply_server_activate() on the main loop, in the same step that tears the removed roles
    /// down, so the gate and the teardown agree on when a role stopped.
    void note_activated_roles(const std::vector<std::string>& active_roles) {
        this->active_role_mask_.fetch_or(active_role_mask(active_roles), std::memory_order_acq_rel);
    }

    /// @brief Takes back the mask bits a refused activation added.
    ///
    /// Main-loop only. An activation the main loop rejects while keeping the connection open
    /// never reaches apply_server_activate(); without this the receive gate would go on admitting
    /// traffic for a role this client never activated.
    void withdraw_activated_roles(const std::vector<std::string>& refused_roles) {
        this->publish_role_mask(active_role_mask(refused_roles));
    }

    /// @brief Returns true if `role` is active on this connection, judged on the exact versioned
    /// name this library implements.
    ///
    /// The one activation test in the library: the receive gate, the send gate, the client/state
    /// role objects and role removal all read the mask active_role_mask() builds with the same
    /// exact-version test (role_in()) role removal applies, so none of them can disagree. The
    /// mask is rebuilt by apply_server_activate() and read atomically, so the receive path may
    /// call it from the network thread while the main loop applies an activation; active_roles_
    /// itself is main-loop-only and must not be walked from there.
    bool is_role_active(SendspinRole role) const {
        return (this->active_role_mask_.load(std::memory_order_acquire) & role_mask_bit(role)) != 0;
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
    /// @param pairing_method Method from the activation's pairing object (nullopt when absent).
    ///                       Ignored (stored as nullopt) unless `activities` includes PAIRING
    ///                       (spec: "A client ignores this field when activities does not
    ///                       include 'pairing'").
    /// @param pairing_format Emission format from the pairing object (dynamic_pairing_code
    ///                       only); stored under the same PAIRING-activity condition.
    void apply_server_activate(const std::vector<SendspinActivity>& activities,
                               const std::optional<std::vector<std::string>>& active_roles,
                               const std::optional<SendspinPairMethod>& pairing_method,
                               const std::optional<SendspinPairingCodeFormat>& pairing_format) {
        this->activities_ = activities;
        const uint16_t previous = active_role_mask(this->active_roles_);
        if (active_roles.has_value()) {
            this->active_roles_ = active_roles.value();
        }
        // Republished on every activation, sticky set included, so the mask cannot drift from
        // active_roles_. Only the roles this activation takes out are withdrawn.
        this->publish_role_mask(
            static_cast<uint16_t>(previous & ~active_role_mask(this->active_roles_)));
        bool has_pairing = false;
        for (const auto& a : activities) {
            if (a == SendspinActivity::PAIRING) {
                has_pairing = true;
                break;
            }
        }
        this->pairing_method_ = has_pairing ? pairing_method : std::nullopt;
        this->pairing_format_ = has_pairing ? pairing_format : std::nullopt;
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
    ///       complete; the manager uses it to start the Noise handshake. Inbound server
    ///       connections are delivered to the manager already upgraded (their handshake starts at
    ///       nursery admission) and never fire this.
    /// @note This and on_disconnected_cb can run during an outbound destructor's transport join
    ///       (see "Event queuing" in connection_manager.h).
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
    /// @note Distinct from is_connected(): on ESP the socket is accepted before any WebSocket
    ///       handshake, so this flag signals that the peer spoke WebSocket.
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

    // ========================================
    // Initialization setters (called by hub before start)
    // ========================================

    /// @brief Sets the memory location preference for the websocket payload reassembly buffer
    /// @param location PREFER_EXTERNAL (SPIRAM-first) or PREFER_INTERNAL (internal-RAM-first).
    /// @note Must be called before the first received frame; takes effect on the next allocation.
    void set_websocket_payload_location(MemoryLocation location) {
        this->websocket_payload_location_ = location;
    }

    /// @brief Sets the memory location preference for the Noise transport's buffers: fragment
    /// reassembly, the fragmentation frame buffer, and the reused send buffer.
    /// @param location PREFER_EXTERNAL (SPIRAM-first) or PREFER_INTERNAL (internal-RAM-first).
    /// @note Must be called before the handshake completes; takes effect on the next allocation.
    void set_noise_buffer_location(MemoryLocation location) {
        this->noise_transport_.set_buffer_location(location);
    }

protected:
    // ========================================
    // Transport frames
    // ========================================

    /// @brief Sends one Noise transport frame, running `before_write` (if set) immediately
    /// before the frame is handed to the socket
    ///
    /// The default runs the hook and then calls send_binary_message(), which suits a transport
    /// that writes synchronously. A transport that queues its writes overrides this to run the
    /// hook where the write happens.
    virtual SsErr send_transport_frame(const uint8_t* data, size_t len,
                                       const NoiseTransport::FrameWriteHook& before_write);

    // ========================================
    // Active-role mask
    // ========================================

    /// @brief Republishes the active-role mask: clears `withdrawn`, then sets what is applied.
    ///
    /// Main-loop only, and the only writer of the mask outside note_activated_roles(). Both steps
    /// are read-modify-writes because the network thread ORs a newly arrived activation's roles
    /// in without waiting for the main loop: a plain store of the applied set would erase the
    /// bits of an activation that is delivered but not yet applied, and the receive gate would
    /// then drop exactly the traffic a server sends immediately behind its activate.
    /// @param withdrawn Bits this step takes back (the roles it removed, or a refusal's roles).
    void publish_role_mask(uint16_t withdrawn) {
        this->active_role_mask_.fetch_and(static_cast<uint16_t>(~withdrawn),
                                          std::memory_order_acq_rel);
        this->active_role_mask_.fetch_or(active_role_mask(this->active_roles_),
                                         std::memory_order_acq_rel);
    }

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

    /// Extent of one held role message within held_messages_.
    struct HeldMessageExtent {
        size_t offset{};
        size_t length{};
        int64_t arrival_us{};
    };

    /// Pre-admission hold budgets, covering the burst a server can send between its
    /// server/activate and the client's next loop() tick: one server/state per role this client
    /// can carry (player, controller, metadata, artwork, visualizer, color), plus the
    /// stream/start and group/update that can follow the same activation. The byte budget is
    /// four steady-state protocol messages' worth (SendspinClientConfig::DEFAULT_JSON_ARENA_SIZE
    /// is one), which those eight fit comfortably: role state objects run to a few hundred bytes
    /// each. Whichever budget runs out first, the message is dropped with a warning rather than
    /// letting an unadmitted peer grow held_messages_ without bound.
    static constexpr size_t MAX_HELD_MESSAGES = 8;
    static constexpr size_t MAX_HELD_BYTES = 4 * SendspinClientConfig::DEFAULT_JSON_ARENA_SIZE;
    static_assert(MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES == 2 * MAX_HELD_BYTES,
                  "the pre-admission reassembly cap is stated as twice the pre-admission hold "
                  "budget; keep the two derivations in step");

    // Struct fields

    /// Extents of the messages held in held_messages_, in arrival order.
    std::array<HeldMessageExtent, MAX_HELD_MESSAGES> held_extents_{};

    /// Role messages received before admission, replayed in order when the connection is
    /// admitted. See hold_pre_admission_message().
    ///
    /// The buffer is allocated on the first hold and freed by the replay (or with the
    /// connection), so it costs nothing on a connection that is admitted before the server says
    /// anything. Worst case is one buffer per live connection, NURSERY_CAPACITY (2) plus the
    /// current slot, i.e. 24 KB of SPIRAM-preferring heap, held only across the admission window.
    PlatformBuffer held_messages_;

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

    /// Bytes of held_messages_ in use, against MAX_HELD_BYTES.
    size_t held_bytes_{0};

    /// Messages held in held_extents_, against MAX_HELD_MESSAGES.
    size_t held_count_{0};

    size_t websocket_write_offset_{0};

    // 32-bit fields

    /// Low 32 bits of platform_time_us() at the last complete inbound message. Atomic because it
    /// is written on the network thread and read by the main-loop liveness check; 32 bits because
    /// it is stored per message and a 64-bit atomic is not lock-free on the ESP32 family.
    std::atomic<uint32_t> last_receive_time_us_{0};

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

    /// active_roles_ as a bitmask of the roles this library implements, so the network thread can
    /// test a role without reading the vector the main loop rewrites. Written by
    /// note_activated_roles() on the network thread and through publish_role_mask() on the main
    /// loop, never with a plain store (see publish_role_mask()).
    std::atomic<uint16_t> active_role_mask_{0};

    /// Pairing method from the pairing object of the last pairing server/activate; nullopt
    /// outside a pairing activation. Read by the pairing flow. Written and read on
    /// the main loop (apply_server_activate runs in ConnectionManager::loop()).
    std::optional<SendspinPairMethod> pairing_method_{};

    /// Emission format from the same pairing object (dynamic_pairing_code only); nullopt outside
    /// a pairing activation. Same main-loop-only contract as pairing_method_.
    std::optional<SendspinPairingCodeFormat> pairing_format_{};

    // ========================================
    // Pairing state members
    // ========================================

    /// Pairing-code PAKE session (all fields are main-loop-only; no lock needed).
    PairingSession pairing_session_{};

    /// True while a Pairing-PSK exchange is in progress on this connection.
    /// Written on the main loop (enter/abort) and by the network thread
    /// (handle_noise_rehandshake clears it when the re-handshake begins).
    /// Read on the main loop by ConnectionManager: the re-entry check in process_activate_event()
    /// and the already-ended checks in handle_pair_abort() / handle_pairing_message().
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
    /// = nothing to store). Written on the main loop (enter pairing), taken on the
    /// network thread (server/pair-finalize handler), cleared on the main loop (abort/leftover).
    /// A ShadowSlot: latest-wins write, take-and-clear read, single mutex internal to the slot.
    ShadowSlot<std::optional<SendspinPairingRecord>> pending_pairing_slot_{};

    /// Count of pairing server/activate messages received since the last Noise handshake (or
    /// re-handshake) (pairing.md "Pairing index"). Feeds both the wire `pairing_index` field on
    /// client/pair-init and the CPace `sid` (see PairingSession::pairing_index, captured at
    /// handle_enter_pairing() so a later PAKE step reuses the exact value client/pair-init sent).
    /// Written on the main loop (bump_pairing_index(), each pairing server/activate) and on the
    /// network thread (reset_pairing_index(), at handshake/re-handshake completion); atomic for
    /// that cross-thread reset.
    std::atomic<uint32_t> pairing_index_{0};

    /// Tag of the client/time frame in flight: the low 32 bits of the client_transmitted it
    /// carries, never 0 for a frame, and 0 once the frame is claimed or cancelled. A failed send
    /// leaves its tag, which no reply can echo. 32 bits because a 64-bit atomic takes a lock on
    /// the ESP32 family.
    std::atomic<uint32_t> time_frame_tag_{0};

    /// Low 32 bits of the client clock when the frame in flight was handed to the socket, seeded
    /// with the tag until the write hook overwrites it on whichever thread performs the write.
    std::atomic<uint32_t> time_frame_sent_us_{0};

    // 8-bit fields

    /// Lifecycle-flag axes.
    ///
    /// The six atomic flags below are three independent axes, not one linear lifecycle:
    ///  - Transport: ws_upgraded_.
    ///  - Proving: noise_handshake_complete_ (set once, never cleared, not even by an in-band
    ///    re-handshake, which keeps the transport active), client_hello_sent_ /
    ///    server_hello_received_ (once per connection; connection.md "Re-handshake" re-sends
    ///    neither hello), and first_activate_received_, which the server owes again after every
    ///    re-handshake.
    ///  - Admission: admitted_, whether this connection occupies the manager's current slot.
    ///    Orthogonal to proving: an operational nursery loser is never admitted, and a
    ///    re-handshaking current connection is admitted but not operational.
    ///
    /// Each flag's own comment below names its writers and threads. Do not fold them into one
    /// phase enum: client_hello_sent_ and server_hello_received_ complete in either order, and
    /// handle_noise_rehandshake() / note_pairing_finalize_ack() rewind first_activate_received_
    /// from the network thread. Derive a phase on demand instead, as SetupStage in
    /// connection_manager.cpp does for reap diagnostics.

    /// PSK category resolved by the Noise handshake (set at COMPLETE, or re-handshake).
    /// Atomic because get_psk_category() is read on the main loop (build_hello_message via the
    /// hello scan) while the network thread writes it at COMPLETE / re-handshake.
    std::atomic<PskCategory> psk_category_{PskCategory::SENTINEL};

    /// Hello handshake state. Atomic because it is set from the send-completion callback (the httpd
    /// worker thread on ESP) and the disconnect handlers (network thread), which only the outbound
    /// transports install: a dropped inbound connection is torn down, not reused. Read by
    /// is_handshake_complete() and the pre-hello send gate from other threads.
    std::atomic<bool> client_hello_sent_{false};

    /// True once the Noise transport handshake has completed (set on the network thread,
    /// read from the main loop via is_noise_handshake_complete()).
    std::atomic<bool> noise_handshake_complete_{false};

    /// True once a server/activate from this connection reached the dispatch path. Written and
    /// read on the network thread only. See note_activate_delivered().
    std::atomic<bool> activate_delivered_{false};

    /// True while this connection occupies the manager's admitted (current) slot. Written on the
    /// main loop only (see set_admitted()); read on the network thread by the role-dispatch gate.
    /// See is_admitted().
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
