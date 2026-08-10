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

/// @file connection_manager.h
/// @brief Manages WebSocket connection lifecycle including server handoff, hello handshake, and
/// graceful disconnection

#pragma once

#include "constants.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "sendspin/client.h"
#include "sendspin/types.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// Forward declaration of the Phase 8d test fixture (defined in tests/test_pin_state_machine.cpp,
// global namespace). Declared here, outside namespace sendspin, so the friend declaration below
// can name it unambiguously with the "::" qualifier.
class PinStateMachineTest;

namespace sendspin {

// Forward declarations
class SendspinClient;
class SendspinConnection;
class SendspinServerConnection;
class SendspinWsServer;

/// @brief Converts a duration in seconds to microseconds at compile time.
constexpr int64_t seconds_to_us(double s) {
    return static_cast<int64_t>(s * US_PER_SECOND);
}

/// @brief Deadline (seconds) for a nursery connection to complete the hello handshake, measured
/// from delivery (inbound, already WS-upgraded) or initiation (outbound, before DNS/TCP resolve)
///
/// Reaps peers that connect and then stall before completing the hello, and outbound sockets whose
/// transport never delivers a close (host IXWebSocket, issue #75). Sockets that never upgrade are
/// closed in the platform layer before the manager sees them (ESP ws_server tick() at
/// WS_UPGRADE_TIMEOUT_US; host IXWebSocket's 3 s handshake timeout).
static constexpr double NURSERY_ESTABLISH_TIMEOUT_S = 30.0;

/// @brief Timeout in microseconds (derived from NURSERY_ESTABLISH_TIMEOUT_S).
static constexpr int64_t NURSERY_ESTABLISH_TIMEOUT_US = seconds_to_us(NURSERY_ESTABLISH_TIMEOUT_S);

/// @brief A connection that has not completed the hello handshake
///
/// Unproven connections never occupy the current-connection slot; they wait in the bounded nursery
/// until they establish, then are promoted (or released after losing the handoff comparison to an
/// established incumbent). Inbound entries arrive WS-upgraded, so their hello is armed at
/// admission; outbound entries arm theirs when the transport's connected event arrives.
struct NurseryEntry {
    std::shared_ptr<SendspinConnection> conn;  ///< Observer; the session slot / transport owns
    bool inbound{false};  ///< true if accepted by the WS server, false for connect_to()
};

/// @brief A connection release deferred until conn_ptr_mutex_ has been dropped
///
/// Sending a goodbye can block on the transport, and even shared_ptr destruction can join the
/// transport thread (the host outbound destructor stops its IXWebSocket). Neither may happen under
/// the manager lock: the join can deadlock against a transport callback waiting on that same lock,
/// and any block stalls every other manager entry point. Locked sections only queue releases;
/// flush_deferred_releases() performs them lock-free.
struct DeferredRelease {
    std::shared_ptr<SendspinConnection> conn;      ///< Sole remaining manager reference
    std::optional<SendspinGoodbyeReason> goodbye;  ///< nullopt: transport gone, just release
};

/// @brief Deferred pair/abort event: the server (or wire) sent pair/abort during pairing.
/// Processed on the main loop in ConnectionManager::loop().
/// (The server/pair-finalize ack is committed synchronously on the network thread, and the
/// leftover-activate case is handled inline in the activate handler, so neither is deferred.)
struct PairAbortEvent {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection on which the abort arrived
    PairAbortReason reason{};                  ///< Parsed abort reason
};

/// @brief Deferred local pairing abort: the persistence provider rejected the long-term
/// record at server/pair-finalize (network thread), so the record was never stored
/// (RecordStore::store_record fails closed) and the pairing must fail closed. Processed on
/// the main loop: sends a best-effort pair/abort, drops the connection, and reports
/// SendspinPairAbortReason::STORAGE_FAILED to the listener. server_id is captured at
/// production time for the same reason as PairingSucceededEvent's server_id (the connection
/// may already be torn down by the time this drains).
struct PairStorageFailedEvent {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection whose pairing failed to persist
    std::string server_id;                     ///< server_id captured when the event was posted
};

// ============================================================================
// Management deferred events
// ============================================================================

/// @brief Type tag for which management/* request arrived.
enum class ManagementRequestKind : uint8_t {
    LIST_RECORDS,
    ADD_RECORD,
    REMOVE_RECORD,
    GET_PAIRING_CONFIG,
    SET_PAIRING_CONFIG,
};

/// @brief Deferred management request event.
///
/// Parsed on the network thread; handler runs on the main loop so it can safely
/// mutate the RecordStore and send the result from the main-loop thread.
/// management is request/response at-most-one-in-flight; FIFO deferred processing
/// preserves the reference's single-concurrent-request property naturally.
struct ManagementRequestEvent {
    std::shared_ptr<SendspinConnection> conn;              ///< Connection that received the request
    ManagementRequestKind kind{};                          ///< Which management/* request type
    ManagementAddRecordPayload add_payload;                ///< Populated for ADD_RECORD
    ManagementRemoveRecordPayload remove_payload;          ///< Populated for REMOVE_RECORD
    ManagementSetPairingConfigPayload set_config_payload;  ///< Populated for SET_PAIRING_CONFIG
};

/// @brief Deferred server/unpair event.
///
/// Parsed on the network thread; the record removal and disconnect run on the main loop.
struct ServerUnpairEvent {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection that received server/unpair
    std::string matched_psk_id;                ///< psk_id matched for this connection
    PskCategory psk_category{};                ///< PSK category (must be LONG_TERM to act)
};

// ============================================================================
// Dynamic-PIN pairing deferred events
// ============================================================================

/// @brief Which server-to-client PIN pairing message arrived.
enum class PinPairingMessageKind : uint8_t {
    PAIR_INIT,     ///< server/pair-init: nonce_A + pin_length
    PAIR_AUTH,     ///< server/pair-auth: pake_msg_1
    PAIR_CONFIRM,  ///< server/pair-confirm: server_kc
    MALFORMED,     ///< a pairing message failed to parse; abort any active PIN session
};

/// @brief Deferred server PIN pairing message event.
///
/// Parsed on the network thread; the PAKE state machine (CPace, nonces, hash) runs
/// on the main loop only, so all PIN message processing is deferred here.
struct ServerPairingMessageEvent {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection that received the message
    PinPairingMessageKind kind{};              ///< Which PIN message arrived

    // server/pair-init fields
    std::array<uint8_t, 32> nonce_a{};  ///< nonce_A decoded from the wire
    int pin_length{0};                  ///< Server-chosen PIN digit count

    // server/pair-auth fields
    std::array<uint8_t, 32> pake_msg_1{};  ///< Server CPace public share

    // server/pair-confirm fields
    std::array<uint8_t, 64> server_kc{};  ///< Server CPace confirmation tag
};

/// @brief Hello retry state for exponential backoff
struct HelloRetryState {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection awaiting hello
    int64_t retry_time_us{0};  ///< Next retry time in microseconds (0 = no pending retry)
    static constexpr uint32_t INITIAL_RETRY_DELAY_MS = 100U;  ///< Initial backoff delay in ms
    uint32_t delay_ms{INITIAL_RETRY_DELAY_MS};                ///< Current backoff delay
    uint8_t attempts{3};                                      ///< Remaining retry attempts
};

/// @brief Deferred server/activate event, processed in ConnectionManager::loop()
///
/// Pushed from SendspinClient::process_json_message() (network thread) so trust enforcement,
/// RecordStore mutations (mark_record_used), and admission arbitration all happen on the main
/// loop, never on the network thread. Carries the parsed payload rather than requiring the main
/// loop to re-read connection state that a concurrent event could have changed.
struct ServerActivateEvent {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection the activate was received on
    std::vector<SendspinActivity> activities;  ///< Activities declared by this activate
    std::optional<std::vector<std::string>> active_roles;    ///< nullopt = sticky/keep prior set
    std::optional<SendspinPairMethod> selected_pair_method;  ///< Server-selected pairing method
};

/**
 * @brief Manages WebSocket connection lifecycle.
 *
 * Accepts and creates connections, handles the hello handshake, orchestrates server handoff
 * decisions, and performs graceful disconnection with deferred cleanup.
 *
 * Connections prove themselves before they are trusted: every new connection enters a bounded
 * nursery and leaves it only by completing the hello handshake AND being admitted by its first
 * server/activate (promotion, or a fair arbitration against the incumbent) or by missing the
 * establish deadline (reaped). When encryption is required (SendspinClientConfig::
 * encryption_required, the default), the prove stage additionally starts with the Noise
 * handshake: accept/connect -> Noise handshake complete -> hello handshake complete -> first
 * server/activate admitted. The platform ws_server delivers inbound connections only after
 * observing their WebSocket upgrade, so the manager never reasons about raw sockets that might
 * not speak WebSocket; those are closed inside the platform layer. Invariant:
 * `current_connection_ != nullptr` implies `current_connection_->is_operational()`, EXCEPT for
 * the transient window while an already-admitted connection re-proves itself after a successful
 * in-band re-handshake (schedule_rehandshake_rearm(): the hello cycle re-arms and re-runs, and
 * the invariant is restored once it completes; if the hello send keeps failing until retries are
 * exhausted, the connection is dropped rather than left wedged -- see the hello-retry-timer scan
 * in loop()).
 *
 * Typical usage:
 *  1. Construct with a `SendspinClient*`.
 *  2. Call `init_server()` once to create and configure the WebSocket server.
 *  3. Call `loop()` periodically to drive connection state, process deferred events, and retry
 *     hellos.
 *  4. Call `connect_to()` to initiate an outgoing client connection when needed.
 *  5. Call `disconnect()` to gracefully close the active connection.
 *
 * @code
 * ConnectionManager manager(client);
 * manager.init_server(client, use_psram, priority);
 *
 * while (running) {
 *     manager.loop();
 * }
 *
 * manager.disconnect(SendspinGoodbyeReason::SHUTDOWN);
 * @endcode
 */
class ConnectionManager {
    // Test-only: lets the Phase 8d PIN state-machine integration harness inject a fake
    // current_connection_ directly and drive on_connection_lost, bypassing the real
    // WebSocket transport and Noise handshake. No production code depends on this;
    // it exists solely so tests/test_pin_state_machine.cpp can reach private state.
    friend class ::PinStateMachineTest;

public:
    explicit ConnectionManager(SendspinClient* client);
    ~ConnectionManager();

    // ========================================
    // Public API
    // ========================================

    /// @brief Initiates a client connection to a Sendspin server.
    /// @param url WebSocket URL of the server to connect to.
    void connect_to(const std::string& url);

    /// @brief Disconnects from the current server.
    ///
    /// Must be called from the main loop thread: conn->disconnect() runs outside conn_ptr_mutex_
    /// (it can block on the transport, and on host outbound it joins the transport thread), so
    /// only the main loop's serialization keeps it from racing loop()'s reap/handoff release of
    /// the same connection into two concurrent transport stops.
    /// @param reason The goodbye reason to send before closing.
    void disconnect(SendspinGoodbyeReason reason);

    // ========================================
    // Server lifecycle
    // ========================================

    /// @brief Creates the WebSocket server and configures callbacks. Call once from start_server().
    /// Server configuration is read from client->config_.
    /// @param client The SendspinClient that owns this manager.
    void init_server(SendspinClient* client);

    /// @brief Drives connection state: starts server when network ready, processes lifecycle
    /// events, retries hello, calls loop() on active connections.
    ///
    /// Tick cost: every section below the ws_server start-retry check is gated on one of the
    /// atomic hints in "Atomic fields" below (has_pending_events_, nursery_size_, has_current_,
    /// deferred_size_), so an idle tick only pays for the atomic loads it needs to decide there
    /// is nothing to do. Steady state: connected and idle (no pending events, empty nursery)
    /// costs exactly one conn_ptr_mutex_ acquisition (the current/nursery copy ahead of the
    /// conn->loop() calls) plus a handful of atomic loads; disconnected and idle costs zero
    /// mutex acquisitions.
    void loop();

    // ========================================
    // Connection queries
    // ========================================

    /// @brief Returns true if there is an active connection with completed handshake.
    /// @return True if connected and handshake is complete, false otherwise.
    bool is_connected() const;

    /// @brief Returns the current active connection. Main-thread only.
    /// @return Pointer to the current connection, or nullptr if none.
    SendspinConnection* current() const {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        return this->current_connection_.get();
    }

    /// @brief Returns a shared_ptr to the current connection. Thread-safe.
    /// Role threads (sync task, artwork/visualizer drains) must use this instead of current():
    /// the shared_ptr keeps the connection alive for the duration of the caller's use even if the
    /// main loop concurrently drops or replaces the current connection.
    /// @return Shared pointer to the current connection, or nullptr if none.
    std::shared_ptr<SendspinConnection> current_shared() const {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        return this->current_connection_;
    }

    /// @brief Schedules a pair/abort event for deferred processing in loop().
    /// @param event The pair-abort event to schedule (moved).
    void schedule_pair_abort(PairAbortEvent event);

    /// @brief Schedules a management request event for deferred processing in loop().
    /// @param event The management request event to schedule (moved).
    void schedule_management_request(ManagementRequestEvent&& event);

    /// @brief Schedules a server/unpair event for deferred processing in loop().
    /// @param event The server/unpair event to schedule (moved).
    void schedule_server_unpair(ServerUnpairEvent&& event);

    /// @brief Schedules a dynamic-PIN pairing message event for deferred processing in loop().
    /// @param event The server pairing message event to schedule (moved).
    void schedule_pin_pairing_message(ServerPairingMessageEvent&& event);

    /// @brief Schedules an on_pairing_succeeded notification for deferred delivery in loop().
    ///
    /// Called from SendspinClient::process_json_message() on the NETWORK thread when the
    /// server/pair-finalize ack handler actually stores a long-term record. This is the one
    /// pairing outcome notification that originates off the main loop, so it rides the same
    /// pending_*_events_ / has_pending_events_ idiom as every other cross-thread mutation in
    /// this class (not a bespoke thread-safe queue): loop() drains it and calls
    /// SendspinClient::note_pairing_succeeded(), which queues the actual listener callback for
    /// SendspinClient::loop() to fire unlocked.
    /// @param server_id The base64url public key of the newly paired server (moved).
    void schedule_pairing_succeeded(std::string server_id);

    /// @brief Schedules a pairing storage-failure abort for deferred processing in loop().
    ///
    /// Called from SendspinClient::process_json_message() on the NETWORK thread when
    /// RecordStore::store_record() reports that the persistence provider rejected the
    /// long-term record at server/pair-finalize. Rides the same pending_*_events_ /
    /// has_pending_events_ idiom as schedule_pairing_succeeded above.
    /// @param event The storage-failed event to schedule (moved).
    void schedule_pair_storage_failed(PairStorageFailedEvent event);

    /// @brief Schedules a static-PIN pairing-window confirmation for deferred processing in
    /// loop(). Thread-safe; called from SendspinClient::confirm_pairing_window().
    void schedule_pairing_window_confirm();

    // ========================================
    // Handoff support
    // ========================================

    /// @brief Sets the last-played server_id for handoff preference decisions.
    /// @param server_id The server_id string of the last-played server.
    void set_last_played_server_id(const std::string& server_id);

    // ========================================
    // Event queuing (thread-safe)
    // ========================================

    /// @brief Schedules a server/activate event for deferred processing in loop().
    /// Called from SendspinClient::process_json_message() on the NETWORK thread; trust
    /// enforcement, RecordStore mutations, and admission arbitration all happen in loop() on
    /// the main loop instead, matching every other cross-thread mutation in this class.
    /// @param event The server/activate event to schedule (moved).
    void schedule_activate(ServerActivateEvent event);

    /// @brief Schedules a hello-cycle re-arm after a successful in-band re-handshake.
    ///
    /// Called from SendspinClient::process_json_message() on the NETWORK thread right after
    /// SendspinConnection::handle_noise_rehandshake() succeeds. That call resets
    /// server_hello_received_/client_hello_sent_/first_activate_received_ on an already-admitted
    /// (current) connection so the post-swap server/hello -> client/hello -> server/activate
    /// cycle re-runs under the new session keys, but nothing else ever re-sends client/hello for
    /// a connection outside the nursery. loop() arms the hello retry for it, matching every
    /// other cross-thread connection-state mutation in this class.
    /// @param conn The connection whose Noise session was just swapped (moved).
    void schedule_rehandshake_rearm(std::shared_ptr<SendspinConnection> conn);

private:
    // ========================================
    // Connection setup
    // ========================================
    /// @brief Attaches message and lifecycle callbacks to a connection.
    /// @param conn The connection to configure.
    void setup_connection_callbacks(SendspinConnection* conn);
    /// @brief Admits an incoming server connection into the nursery and starts its prove stage
    ///
    /// Never enters the current slot directly (the connection has not proven itself yet). If the
    /// inbound slots are full (outbound entries do not count) the newcomer is rejected with a
    /// goodbye, which reaches the peer because its session is already upgraded.
    ///
    /// When encryption is required, this installs the Noise handshake driver and sends
    /// client/init immediately (the connection is already WS-upgraded, so there is no earlier
    /// signal to wait for); the hello is armed later, once the Noise handshake completes (see
    /// the noise-completion scan in loop()). Otherwise the hello is armed right away, as before.
    /// @param conn The newly delivered server connection. The session slot keeps a parallel
    ///             refcount, so this observer can be reset at any time without freeing the conn
    ///             out from under in-flight httpd workers.
    void on_new_connection(std::shared_ptr<SendspinServerConnection> conn);

    /// @brief Finds the nursery entry holding the given connection. Caller must hold
    /// conn_ptr_mutex_.
    /// @param conn The connection to look up.
    /// @return Iterator into nursery_, or nursery_.end() if the connection is not in the nursery.
    std::vector<NurseryEntry>::iterator find_in_nursery(const SendspinConnection* conn);

    /// @brief Appends an entry to the nursery and refreshes nursery_size_ in the same critical
    /// section, so the hint atomic can never drift from nursery_.size(). Caller must hold
    /// conn_ptr_mutex_.
    /// @param entry The nursery entry to add.
    void push_nursery_entry(NurseryEntry entry);

    /// @brief Assigns current_connection_ and refreshes has_current_ in the same critical section,
    /// so the hint atomic can never drift from "current_connection_ != nullptr". Pass nullptr to
    /// clear the slot. Caller must hold conn_ptr_mutex_.
    /// @param conn The connection to install as current, or nullptr to clear; moved from.
    void set_current_connection(std::shared_ptr<SendspinConnection> conn);

    /// @brief Appends a connection to pending_connected_events_ and sets has_pending_events_ in
    /// the same critical section, so loop()'s lock-free gate can never miss a pushed event.
    /// Caller must hold conn_mutex_.
    /// @param conn The freshly connected connection to defer to loop().
    void queue_pending_connected(std::shared_ptr<SendspinConnection> conn);

    /// @brief Appends a connection to pending_disconnect_events_ and sets has_pending_events_ in
    /// the same critical section, so loop()'s lock-free gate can never miss a pushed event.
    /// Caller must hold conn_mutex_.
    /// @param conn The disconnected connection to defer to loop().
    void queue_pending_disconnect(std::shared_ptr<SendspinConnection> conn);

    /// @brief Appends an event to pending_activate_events_ and sets has_pending_events_ in the
    /// same critical section, so loop()'s lock-free gate can never miss a pushed event. Caller
    /// must hold conn_mutex_.
    /// @param event The server/activate event to defer to loop() (moved).
    void queue_pending_activate(ServerActivateEvent event);

    /// @brief Appends a connection to pending_rehandshake_events_ and sets has_pending_events_ in
    /// the same critical section, so loop()'s lock-free gate can never miss a pushed event.
    /// Caller must hold conn_mutex_.
    /// @param conn The re-handshaked connection to defer to loop() (moved).
    void queue_pending_rehandshake(std::shared_ptr<SendspinConnection> conn);

    /// @brief Appends an event to pending_pair_abort_events_ and sets has_pending_events_ in the
    /// same critical section, so loop()'s lock-free gate can never miss a pushed event. Caller
    /// must hold conn_mutex_.
    /// @param event The pair/abort event to defer to loop() (moved).
    void queue_pending_pair_abort(PairAbortEvent event);

    /// @brief Appends an event to pending_management_request_events_ and sets has_pending_events_
    /// in the same critical section, so loop()'s lock-free gate can never miss a pushed event.
    /// Caller must hold conn_mutex_.
    /// @param event The management/* request event to defer to loop() (moved).
    void queue_pending_management_request(ManagementRequestEvent&& event);

    /// @brief Appends an event to pending_server_unpair_events_ and sets has_pending_events_ in
    /// the same critical section, so loop()'s lock-free gate can never miss a pushed event.
    /// Caller must hold conn_mutex_.
    /// @param event The server/unpair event to defer to loop() (moved).
    void queue_pending_server_unpair(ServerUnpairEvent&& event);

    /// @brief Appends an event to pending_pin_pairing_events_ and sets has_pending_events_ in
    /// the same critical section, so loop()'s lock-free gate can never miss a pushed event.
    /// Caller must hold conn_mutex_.
    /// @param event The dynamic-PIN pairing message event to defer to loop() (moved).
    void queue_pending_pin_pairing_message(ServerPairingMessageEvent&& event);

    /// @brief Appends a server_id to pending_pairing_succeeded_events_ and sets
    /// has_pending_events_ in the same critical section, so loop()'s lock-free gate can never
    /// miss a pushed event. Caller must hold conn_mutex_.
    /// @param server_id The newly paired server's base64url public key (moved).
    void queue_pending_pairing_succeeded(std::string server_id);

    /// @brief Appends an event to pending_pair_storage_failed_events_ and sets
    /// has_pending_events_ in the same critical section, so loop()'s lock-free gate can never
    /// miss a pushed event. Caller must hold conn_mutex_.
    /// @param event The storage-failed event to defer to loop() (moved).
    void queue_pending_pair_storage_failed(PairStorageFailedEvent event);

    /// @brief Releases a nursery entry: erases it, prunes its hello retry, and queues the
    /// goodbye+release on deferred_releases_. Caller must hold conn_ptr_mutex_ and call
    /// flush_deferred_releases() after dropping it.
    /// @param it Valid iterator into nursery_.
    /// @param reason The goodbye reason to send before closing, or nullopt when the transport is
    ///        already gone so no goodbye should be attempted.
    /// @return Iterator to the entry after the erased one.
    std::vector<NurseryEntry>::iterator release_nursery_entry(
        std::vector<NurseryEntry>::iterator it, std::optional<SendspinGoodbyeReason> reason);

    /// @brief Appends a release to deferred_releases_ and refreshes deferred_size_ in the same
    /// critical section, so the hint atomic can never drift from deferred_releases_.size().
    /// Caller must hold conn_ptr_mutex_ and call flush_deferred_releases() after dropping it.
    /// @param conn The connection to release; empty on return (moved from).
    /// @param reason The goodbye reason to send before closing, or nullopt when the transport is
    ///        already gone so no goodbye should be attempted.
    void queue_deferred_release(std::shared_ptr<SendspinConnection> conn,
                                std::optional<SendspinGoodbyeReason> reason);

    /// @brief Performs the queued goodbye sends and connection releases from deferred_releases_.
    /// Caller must NOT hold conn_ptr_mutex_ (see DeferredRelease). Safe to call from any thread;
    /// a queued release is performed exactly once. Called after every locked section that can
    /// queue a release; loop() also calls it as a backstop.
    ///
    /// Early-returns without locking when deferred_size_ reads 0 -- see the definition for the
    /// soundness argument.
    void flush_deferred_releases();

    // ========================================
    // Hello handshake
    // ========================================
    /// @brief Arms the hello retry state so loop() will send the hello on its next tick.
    ///
    /// Usually called for a nursery member, but also for the current (already-admitted)
    /// connection to re-arm its hello after a successful in-band re-handshake (see
    /// schedule_rehandshake_rearm()) -- hello_retries_ is not exclusively a nursery-membership
    /// concept, see the field's doc comment.
    /// @param conn The connection to send the hello to.
    void initiate_hello(SendspinConnection* conn);
    /// @brief Sends the hello message to a connection, returning true if no retry is needed.
    /// @param remaining_attempts Number of send attempts remaining before giving up.
    /// @param conn The connection to send the hello to.
    /// @return True if done (sent or connection invalid), false if the send failed and should
    /// retry.
    bool send_hello_message(uint8_t remaining_attempts, SendspinConnection* conn);
    /// @brief Removes any pending hello-retry entry associated with the given connection.
    /// @param conn The connection whose retry state should be dropped.
    void remove_hello_retry(const SendspinConnection* conn);
    /// @brief Returns true if conn already has a pending hello-retry entry. Caller must hold
    /// conn_ptr_mutex_. Used by the noise-completion scan in loop() to arm a connection's hello
    /// exactly once (idempotent re-arming would otherwise reset the backoff every tick).
    /// @param conn The connection to check.
    bool has_hello_retry(const SendspinConnection* conn) const;

    // ========================================
    // Connection lifecycle
    // ========================================
    /// @brief Tears down a lost connection (current or nursery). Caller must hold conn_ptr_mutex_.
    /// @param conn The connection that was lost.
    void on_connection_lost(SendspinConnection* conn);
    /// @brief Decides whether an incoming connection should be admitted over the current one.
    ///
    /// Ports admission.h::should_admit_connection (activity-priority arbitration: management >
    /// playback > pairing > empty, with last-played-server_id as the empty/empty tiebreak and an
    /// in-flight pairing immune to displacement by incoming pairing/playback). Trust enforcement
    /// (admission.h::admissible) is applied separately, before this is ever consulted, in
    /// loop()'s server/activate handling.
    /// @param current The existing active connection, or nullptr if none is admitted yet.
    /// @param new_conn The newly proven candidate connection. Must not be null.
    /// @return True if the new connection should become current, false to keep the existing one
    ///         (or reject the newcomer, when current is null this always returns true).
    bool should_switch_to_new_server(const SendspinConnection* current,
                                     const SendspinConnection* new_conn) const;
    /// @brief Updates last_played_server_id when the ADMITTED (current) connection carries the
    /// PLAYBACK activity. Mirrors note_playback_activity in aiosendspin/client/client.py.
    /// No-op if conn is not the current connection, or does not declare PLAYBACK.
    /// Caller must hold conn_ptr_mutex_.
    /// @param conn The connection to check (typically the connection an activate just applied to).
    void note_playback_activity(const SendspinConnection* conn);

    /// @brief Promotes a proven nursery entry (it->conn->is_operational() must already be true)
    /// into the current slot, or arbitrates it against an existing current connection, or
    /// rejects it with concurrent_attempt if arbitration favors the incumbent.
    ///
    /// Erases the entry from the nursery unconditionally (it never returns to the nursery).
    /// Calls should_switch_to_new_server() when a current connection already exists; both sides
    /// of that comparison are always operational, so arbitration never runs on partial data.
    /// On the winning outcome (promotion, whether or not it displaced an incumbent), notifies the
    /// client, publishes state, and records playback activity. Caller must hold conn_ptr_mutex_.
    /// @param it Valid iterator into nursery_ whose connection satisfies is_operational().
    /// @return Iterator to the entry after the erased one (for use in a scanning loop).
    std::vector<NurseryEntry>::iterator promote_or_arbitrate_nursery_entry(
        std::vector<NurseryEntry>::iterator it);
    /// @brief Sends a goodbye and takes ownership of the caller's shared_ptr so it drops at
    /// function exit.
    /// @param conn The connection to disconnect and release. Caller's shared_ptr is left empty.
    /// @param reason The goodbye reason to send before closing.
    static void disconnect_and_release(std::shared_ptr<SendspinConnection>&& conn,
                                       SendspinGoodbyeReason reason);
    /// @brief Single teardown path: removes a managed connection (the current slot or a nursery
    /// entry), cleans up client state (current slot only), and queues the goodbye+release on
    /// deferred_releases_. The current slot stays empty after a drop; the next nursery
    /// establishment promotes into it.
    ///
    /// No-op if conn is null. If conn is not a managed connection (already released by an
    /// earlier event in the same loop() pass), only its stale hello-retry entry, if any, is
    /// pruned. Caller must hold conn_ptr_mutex_ and call flush_deferred_releases() after
    /// dropping it.
    ///
    /// @param conn The connection to drop; must be current_connection_ or a nursery entry.
    /// @param goodbye Goodbye reason to send before closing, or nullopt when the transport is
    ///        already gone (connection-lost path) so no goodbye should be attempted.
    void drop_connection(SendspinConnection* conn, std::optional<SendspinGoodbyeReason> goodbye);

    /// @brief Maximum number of unproven inbound connections held at once
    ///
    /// The platform ws_server delivers only WS-upgraded sessions, so nursery slots are only ever
    /// occupied by peers that speak WebSocket; raw-TCP junk never reaches the nursery. Outbound
    /// entries do not count against the capacity in either direction: a user-initiated connect_to()
    /// is admitted even against full inbound slots, and an in-flight connect_to() never causes an
    /// inbound peer to be rejected. An outbound entry always replaces any previous one, so the
    /// bound on the whole nursery is NURSERY_CAPACITY + 1.
    ///
    /// Socket-budget invariant: gracefully rejecting a surplus inbound peer requires the transport
    /// to accept NURSERY_CAPACITY + 2 sockets (1 established + the nursery + the surplus peer,
    /// which must be connected to receive its goodbye). The default server_max_connections
    /// satisfies this; init_server warns when a configured value does not.
    static constexpr size_t NURSERY_CAPACITY = 2;

    // ========================================
    // Phase 5: Pairing main-loop handlers
    // ========================================

    /// @brief Enters the pairing exchange for the given connection.
    /// Called on the main loop when a server/activate with activities=["pairing"] and
    /// selected_pair_method=PAIRING_PSK is admitted as the first activate.
    /// @param conn The connection entering pairing.
    void handle_enter_pairing(SendspinConnection* conn);

    /// @brief Handles a pair/abort event on the main loop.
    /// Cleans up pairing state. Per spec #120/#123, only closes the connection for reason
    /// concurrent_attempt; every other reason leaves it open. A pair/abort that arrives after the
    /// attempt has already ended (is_pairing_in_progress() false) is silently ignored (stale).
    /// @param conn The connection on which the abort arrived.
    /// @param reason The abort reason.
    void handle_pair_abort(SendspinConnection* conn, PairAbortReason reason);

    /// @brief Handles a pairing storage-failure event on the main loop.
    /// The persistence provider rejected the long-term record at server/pair-finalize, so the
    /// record was never stored (RecordStore::store_record fails closed) and the pairing cannot
    /// survive a reboot. Sends a best-effort pair/abort, drops the connection, and reports
    /// SendspinPairAbortReason::STORAGE_FAILED to the listener.
    /// @param event The storage-failed event (conn + the server_id captured when it was posted).
    void handle_pair_storage_failed(const PairStorageFailedEvent& event);

    // ========================================
    // Phase 8b: Dynamic-PIN pairing main-loop handlers
    // ========================================

    /// @brief Handle a dynamic-PIN server message on the main loop.
    /// Advances the PinStep state machine for the connection.
    /// @param conn The connection that received the message.
    /// @param event The parsed server PIN pairing message.
    void handle_pin_pairing_message(SendspinConnection* conn,
                                    const ServerPairingMessageEvent& event);

    /// @brief Abort the current PIN-pairing session: send pair/abort, notify, and close the
    /// connection only for reason concurrent_attempt (spec #120/#123; every other reason leaves
    /// the connection open).
    /// @param conn The connection to abort.
    /// @param reason The abort reason to send.
    void local_abort_pin_pairing(SendspinConnection* conn, PairAbortReason reason);

    // ========================================
    // Phase 8c: Static-PIN pairing main-loop handlers
    // ========================================

    /// @brief Handle a confirmed pairing-window gesture on the main loop.
    /// Finds the connection (current or pending) awaiting AWAIT_PAIRING_WINDOW, sends the empty
    /// client/pair-init, and starts CPace RESPONDER with the preconfigured static PIN.
    void handle_pairing_window_confirmed();

    // ========================================
    // Phase 6: Management main-loop handlers
    // ========================================

    /// @brief Handles a management/* request on the main loop.
    /// Enforces trust gating, dispatches to the appropriate handler, formats and sends the result,
    /// and applies the effect (GOODBYE_UNAUTHORIZED -> disconnect).
    /// @param conn The connection that received the request.
    /// @param event The management request event carrying the parsed payload.
    void handle_management_request(SendspinConnection* conn, const ManagementRequestEvent& event);

    /// @brief Handles a server/unpair event on the main loop.
    /// Checks PSK category (LONG_TERM only), removes the matched record (unless shared),
    /// and disconnects with UNPAIRED reason.
    /// @param conn The connection that received server/unpair.
    /// @param event The server/unpair event.
    void handle_server_unpair(SendspinConnection* conn, const ServerUnpairEvent& event);

    // Struct fields
    std::mutex conn_mutex_;                           // Protects deferred lifecycle event queues
    mutable std::mutex conn_ptr_mutex_;               // Protects current_connection_, nursery_, and
                                                      // deferred_releases_
    std::vector<DeferredRelease> deferred_releases_;  // Queued releases; see DeferredRelease
    std::vector<NurseryEntry> nursery_;               // Unproven connections awaiting establishment
    // One entry per connection awaiting its hello. Almost always a nursery member, but also,
    // transiently, the current (already-admitted) connection while it re-runs the hello cycle
    // after a successful in-band re-handshake (see schedule_rehandshake_rearm()); the reap scan
    // and the "left the nursery" cleanup below both account for that case explicitly.
    std::vector<HelloRetryState> hello_retries_;
    std::vector<std::shared_ptr<SendspinConnection>> pending_connected_events_;
    std::vector<std::shared_ptr<SendspinConnection>> pending_disconnect_events_;
    std::vector<ServerActivateEvent> pending_activate_events_;  // Deferred server/activate events
    // Connections whose in-band re-handshake just swapped sessions; loop() re-arms their hello.
    std::vector<std::shared_ptr<SendspinConnection>> pending_rehandshake_events_;
    std::vector<PairAbortEvent> pending_pair_abort_events_;  // Deferred pair/abort events
    std::vector<ManagementRequestEvent> pending_management_request_events_;
    std::vector<ServerUnpairEvent> pending_server_unpair_events_;
    std::vector<ServerPairingMessageEvent> pending_pin_pairing_events_;
    std::vector<std::string> pending_pairing_succeeded_events_;  // server_ids to notify
    // Deferred storage-failure aborts (persist rejected the record at server/pair-finalize)
    std::vector<PairStorageFailedEvent> pending_pair_storage_failed_events_;
    bool pending_pairing_window_confirm_{false};  // Static-PIN pairing-window confirm

    // Pointer fields
    SendspinClient* client_;
    std::shared_ptr<SendspinConnection> current_connection_;
    std::unique_ptr<SendspinWsServer> ws_server_;

    // String fields
    std::string last_played_server_id_;  ///< server_id of the last-played server (empty if unset).

    // 64-bit fields
    /// Earliest time (us) to attempt another WS server start after a failure. Main-loop only.
    int64_t ws_server_start_retry_time_us_{0};

    // 8-bit fields
    bool has_last_played_server_{false};

    // Atomic fields (lock-free hints for loop() tick gating; ground truth remains the
    // mutex-protected containers/pointer above -- see the "Tick cost" note on loop())

    /// True while pending_connected_events_ or pending_disconnect_events_ holds an unswapped
    /// entry. Set under conn_mutex_ at every push into either queue; cleared under conn_mutex_
    /// once loop() has swapped both queues out. Lets loop() skip the conn_mutex_ acquisition
    /// entirely when neither queue has anything pending.
    std::atomic<bool> has_pending_events_{false};

    /// nursery_.size(), refreshed under conn_ptr_mutex_ immediately after every nursery_
    /// mutation (always re-derived from .size(), never incremented/decremented in place, so it
    /// cannot drift). Lets loop() skip the copies/loop() block, the hello-retry scan, and the
    /// nursery reap scan when the nursery is empty, and keeps the lifecycle block running while
    /// any nursery connection exists even with no swapped-out events (its promotion scan is
    /// level-triggered on connection flags, not edge-triggered on events).
    std::atomic<size_t> nursery_size_{0};

    /// True whenever current_connection_ is non-null. Refreshed under conn_ptr_mutex_ at every
    /// assignment (promotion, handoff, drop_connection's exchange, destructor). Lets loop() skip
    /// the copies/loop() block when there is no current connection and the nursery is empty.
    std::atomic<bool> has_current_{false};

    /// hello_retries_.size(), refreshed under conn_ptr_mutex_ immediately after every
    /// hello_retries_ mutation (initiate_hello(), remove_hello_retry(), and the retry-timer scan's
    /// erases in loop()). Lets loop() run the hello-retry-timer scan even when the nursery is
    /// empty, which happens whenever the only pending retry belongs to the current (already-
    /// admitted) connection re-arming its hello after an in-band re-handshake -- that connection
    /// is never a nursery member, so nursery_size_ alone would miss it.
    std::atomic<size_t> hello_retries_size_{0};

    /// deferred_releases_.size(), refreshed under conn_ptr_mutex_ after every push (see
    /// queue_deferred_release()) and after the drain swap in flush_deferred_releases(). Lets
    /// flush_deferred_releases() early-return without locking when nothing is queued.
    std::atomic<size_t> deferred_size_{0};
};

}  // namespace sendspin
