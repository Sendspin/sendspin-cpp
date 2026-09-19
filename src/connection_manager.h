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
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

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

/// @brief Deadline (seconds) for a nursery connection to become operational (hello handshake
/// complete AND first server/activate applied; connection.md "Multiple servers
/// (server-initiated)"), measured from delivery (inbound, already WS-upgraded) or initiation
/// (outbound, before DNS/TCP resolve)
///
/// Reaps peers that connect and then stall before becoming operational, and outbound sockets whose
/// transport never delivers a close (host IXWebSocket). Sockets that never upgrade are
/// closed in the platform layer before the manager sees them (ESP ws_server tick() at
/// WS_UPGRADE_TIMEOUT_US; host IXWebSocket's 3 s handshake timeout).
static constexpr double NURSERY_ESTABLISH_TIMEOUT_S = 30.0;

/// @brief Timeout in microseconds (derived from NURSERY_ESTABLISH_TIMEOUT_S).
static constexpr int64_t NURSERY_ESTABLISH_TIMEOUT_US = seconds_to_us(NURSERY_ESTABLISH_TIMEOUT_S);

/// @brief Deadline (seconds) for the current (already-admitted) connection to re-prove itself
/// after SendspinConnection::handle_noise_rehandshake() or ::note_pairing_finalize_ack() resets
/// its operational state.
///
/// Read by the re-proving watchdog in ConnectionManager::scan_reprove_watchdog() (called every
/// tick from loop()), which is gated on
/// !current_connection_->is_operational(). current_connection_ is never non-operational for any
/// other reason: a nursery entry is only ever promoted once it is already operational (see
/// promote_or_arbitrate_nursery_entry()), and an in-progress pairing-code PAKE exchange keeps
/// is_operational() true throughout (that flow has its own timeouts, PAIRING_ATTEMPT_TIMEOUT_US
/// and pairing_window_open(); see connection_manager.cpp). Shares NURSERY_ESTABLISH_TIMEOUT_S's
/// value by design (same "reach the next protocol milestone within a bounded window" semantics)
/// but is named separately because it applies to the current slot, not the nursery.
static constexpr double REPROVE_TIMEOUT_S = NURSERY_ESTABLISH_TIMEOUT_S;

/// @brief Timeout in microseconds (derived from REPROVE_TIMEOUT_S).
static constexpr int64_t REPROVE_TIMEOUT_US = seconds_to_us(REPROVE_TIMEOUT_S);
/// @brief Consecutive unanswered client/time messages the derived liveness timeout tolerates.
static constexpr int64_t LIVENESS_TOLERATED_MISSES = 2;

/// @brief Returns config.liveness_timeout_ms if set, otherwise a timeout derived from the time
/// burst settings that outlasts LIVENESS_TOLERATED_MISSES consecutive unanswered time messages by
/// at least one response timeout.
/// @param config The client configuration.
/// @return Timeout in milliseconds; 0 or negative disables the check.
int64_t resolve_liveness_timeout_ms(const SendspinClientConfig& config);

/// @brief Bound (milliseconds, per goodbye) on waiting for stop()'s goodbyes to be sent before
/// the transports are torn down
///
/// stop() waits this long times the number of goodbyes it issued: on the ESP server path every
/// goodbye is queued to the single httpd worker and handed to lwIP in turn, so a fixed bound
/// would let the last of several peers lose its goodbye to the close. Per goodbye this is a few
/// scheduler quanta for the worker to dequeue the frame. The host transports send synchronously,
/// so on host the wait resolves before it starts. Send completion is best-effort (see
/// SendspinConnection::send_text_message): a session that closes first never reports, so this is
/// a cap on how long stop() blocks for its peers' sake, never a guarantee the goodbye arrived.
static constexpr uint32_t GOODBYE_FLUSH_TIMEOUT_MS = 50;

/// @brief Counts the goodbye sends stop() is waiting on
///
/// Shared by stop() and each connection's completion callback through a shared_ptr captured by
/// value, so a completion that runs on a transport thread after stop() has given up (an ESP httpd
/// worker draining late) touches only this record, never stop()'s stack or the manager.
struct GoodbyeWait {
    /// @brief Registers one goodbye whose completion is awaited
    void add_pending() {
        std::lock_guard<std::mutex> lock(this->mutex);
        ++this->pending;
    }

    /// @brief Records one completion; wakes wait() when none remain
    void complete_one() {
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            if (this->pending > 0) {
                --this->pending;
            }
        }
        this->cv.notify_all();
    }

    /// @brief Blocks until every registered goodbye has completed or the bound elapses
    /// @param timeout_ms Maximum time to wait.
    /// @return true if every goodbye completed, false if the bound elapsed first.
    bool wait(uint32_t timeout_ms) {
        std::unique_lock<std::mutex> lock(this->mutex);
        return this->cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                 [this] { return this->pending == 0; });
    }

    std::mutex mutex;
    std::condition_variable cv;
    size_t pending{0};
};

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

/// @brief A persistence-provider write decided under conn_ptr_mutex_ and performed after it has
/// been dropped
///
/// The provider write is an NVS commit on ESP: tens of milliseconds during which nothing else
/// may enter the manager, and the sync task takes conn_ptr_mutex_ per audio chunk through
/// current_shared(). Locked sections therefore only decide WHICH record (or server_id) the write
/// covers; flush_pending_record_ops() performs it, in staging order, with no lock held.
struct PendingRecordOp {
    enum class Kind : uint8_t {
        MARK_USED,    ///< RecordStore::mark_record_used(psk_id)
        REMOVE,       ///< RecordStore::remove_record(psk_id)
        LAST_PLAYED,  ///< SendspinClient::write_last_played_server(server_id); the RAM half ran
                      ///< under the lock (see note_playback_activity())
    };
    Kind kind{Kind::MARK_USED};
    std::string value;  ///< psk_id for MARK_USED/REMOVE, server_id for LAST_PLAYED
};

/// @brief Disposition for the connection once abort_pairing_attempt() ends a pairing attempt.
enum class PairingDropAction : uint8_t {
    KEEP_OPEN,           ///< Leave the connection open.
    CLOSE_SILENTLY,      ///< Drop the connection; no client/goodbye is sent.
    CLOSE_WITH_GOODBYE,  ///< Drop the connection, sending client/goodbye first.
};

/// @brief Deferred pair/abort event: the server (or wire) sent pair/abort during pairing.
/// Processed on the main loop in ConnectionManager::loop().
/// (The server/pair-finalize ack is committed synchronously on the network thread, and the
/// leftover-activate case is handled inline in the activate handler, so neither is deferred.)
struct PairAbortEvent {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection on which the abort arrived
    PairAbortReason reason{};                  ///< Parsed abort reason
};

// ============================================================================
// Unpair deferred events
// ============================================================================

/// @brief Deferred server/unpair event.
///
/// Parsed on the network thread; the record removal and disconnect run on the main loop.
struct ServerUnpairEvent {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection that received server/unpair
    std::string matched_psk_id;                ///< psk_id matched for this connection
    PskCategory psk_category{};                ///< PSK category (must be LONG_TERM to act)
};

// ============================================================================
// Pairing-code deferred events
// ============================================================================

/// @brief Which server-to-client pairing-code message arrived.
enum class PairingMessageKind : uint8_t {
    PAIR_INIT,     ///< server/pair-init: begins a round, carrying nonce_A in the first
    PAIR_AUTH,     ///< server/pair-auth: pake_msg_1
    PAIR_CONFIRM,  ///< server/pair-confirm: server_kc
    MALFORMED,     ///< a pairing message failed to parse; a spec Protocol Error when a
                   ///< pairing-code session is active (silent close, no pair/abort), ignored
                   ///< otherwise
};

/// @brief Deferred server pairing-code message event.
///
/// Parsed on the network thread; the PAKE state machine (CPace, nonces, hash) runs
/// on the main loop only, so all pairing-message processing is deferred here.
struct ServerPairingMessageEvent {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection that received the message
    PairingMessageKind kind{};                 ///< Which pairing message arrived

    // server/pair-init fields
    /// nonce_A decoded from the wire; absent after the attempt's first round
    /// (pairing.md "Server -> Client: server/pair-init").
    std::optional<std::array<uint8_t, 32>> nonce_a{};

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
    static constexpr uint8_t MAX_ATTEMPTS = 3;                ///< Hello sends before giving up
    uint32_t delay_ms{INITIAL_RETRY_DELAY_MS};                ///< Current backoff delay
    uint8_t attempts{MAX_ATTEMPTS};                           ///< Remaining retry attempts
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
    std::optional<std::vector<std::string>> active_roles;  ///< nullopt = sticky/keep prior set
    std::optional<SendspinPairMethod> pairing_method;      ///< From the pairing object's method
    /// From the pairing object's format (dynamic_pairing_code only).
    std::optional<SendspinPairingCodeFormat> pairing_format;
};

/// @brief Pairing-UI display flags snapshotted from a connection's PairingSession.
///
/// conn->pairing_session().code_emitted / .window_shown are the sole record of whether a pairing
/// code or pairing-window prompt is still showing, and every path that ends a pairing attempt
/// clears that state (cleanup_connection_state() on the current-slot drop path,
/// clear_pairing_state()) before it gets a chance to dismiss the prompt. Capture the flags
/// BEFORE that cleanup runs, then dismiss afterward (dismiss_pairing_ui(), or the client's
/// note_*() calls on the stop() path) so the dismissal still happens even though the flags it
/// would have read are already gone.
struct PairingUiSnapshot {
    bool code_was_emitted;
    bool window_was_shown;
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
 * establish deadline (reaped). The prove stage starts with the Noise handshake:
 * accept/connect -> Noise handshake complete -> hello handshake complete -> first
 * server/activate admitted. The platform ws_server delivers inbound connections only after
 * observing their WebSocket upgrade, so the manager never reasons about raw sockets that might
 * not speak WebSocket; those are closed inside the platform layer. Invariant:
 * `current_connection_ != nullptr` implies `current_connection_->is_operational()`, EXCEPT for
 * the transient window while an already-admitted connection re-proves itself: after a successful
 * in-band re-handshake (SendspinConnection::handle_noise_rehandshake(), after which the server
 * owes a fresh server/activate under the new keys) or after the server acks
 * client/pair-finalize and is expected to rekey via one
 * (SendspinConnection::note_pairing_finalize_ack()). The invariant is restored once that
 * activation arrives. If it does not, the re-proving-deadline check (REPROVE_TIMEOUT_US) in
 * scan_reprove_watchdog(), called every tick from loop(), drops the connection. For why this
 * state is tracked as independent flags rather than a single phase enum, see the
 * lifecycle-flag axes note above SendspinConnection's atomic flag members in connection.h.
 *
 * Every event-driven path here runs between SendspinClient::start() and ::stop(), so
 * client_->record_store_ and client_->identity_ are non-null and are not null-checked, except
 * where a site says why.
 *
 * Typical usage:
 *  1. Construct with a `SendspinClient*`.
 *  2. Call `start()` to open admission and create the WebSocket server.
 *  3. Call `loop()` periodically to drive connection state, process deferred events, and retry
 *     hellos.
 *  4. Call `connect_to()` to initiate an outgoing client connection when needed.
 *  5. Call `disconnect()` to gracefully close the active connection, or `stop()` to tear
 *     every connection and the server down synchronously.
 *
 * @code
 * ConnectionManager manager(client);
 * manager.start();
 *
 * while (running) {
 *     manager.loop();
 * }
 *
 * manager.stop(SendspinGoodbyeReason::SHUTDOWN);
 * @endcode
 */
class ConnectionManager {
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

    /// @brief Opens admission and creates the WebSocket server on first use
    ///
    /// Server configuration is read from the client's config when the server object is created;
    /// a restart reuses the object. loop() starts the server once the network provider reports
    /// ready. Main-loop thread only.
    void start();

    /// @brief Synchronous teardown: goodbyes every managed connection, waits up to
    /// GOODBYE_FLUSH_TIMEOUT_MS per goodbye for the sends to complete, then stops the WebSocket
    /// server and releases every connection regardless
    ///
    /// Closes admission first, so a peer delivered during the wait is rejected with a goodbye.
    /// Blocks on the transports' own teardown as well as the flush bound: the host server joins
    /// every accepted connection thread, including a raw socket that never completed its
    /// WebSocket upgrade, which can hold the join for the full WS_HANDSHAKE_TIMEOUT_SECS (3 s);
    /// the ESP server waits for the httpd task to exit, and an outbound connection's transport
    /// stop is synchronous (esp_websocket_client_stop() / ix::WebSocket::stop()). Client-state
    /// cleanup is the caller's job: this only detaches connections. Main-loop thread only.
    /// @param reason The goodbye reason sent to every connected peer.
    /// @return The pairing prompts the dropped connections left showing. The caller dismisses
    ///         them (SendspinClient::note_clear_pairing_code() / note_close_pairing_window()) AFTER
    ///         its own cleanup_connection_state(), which would otherwise wipe the queued notes.
    PairingUiSnapshot stop(SendspinGoodbyeReason reason);

    /// @brief Drives connection state: starts server when network ready, processes lifecycle
    /// events, retries hello, calls loop() on active connections.
    ///
    /// Implemented as a short driver over the named private steps in the "loop() decomposition"
    /// section below; each step keeps its own locking.
    ///
    /// Tick cost: most steps are gated on one of the atomic hints in "Atomic fields" below
    /// (has_pending_events_, nursery_size_, has_current_, deferred_size_), so they pay only the
    /// atomic loads needed to decide there is nothing to do. flush_pending_admission(),
    /// scan_pairing_attempt_timeout(), and scan_reprove_watchdog() take conn_ptr_mutex_
    /// unconditionally, so an idle tick costs three acquisitions while disconnected and five
    /// while connected (adding the current/nursery copy ahead of the conn->loop() calls and the
    /// liveness check).
    void loop();

    // ========================================
    // Connection queries
    // ========================================

    /// @brief Returns true if there is an active connection with completed handshake.
    /// @return True if connected and handshake is complete, false otherwise.
    bool is_connected() const;

    /// @brief Returns the current active connection. Main-thread only.
    ///
    /// Takes conn_ptr_mutex_, which sits inside json_processing_mutex_ in the lock order
    /// (docs/conventions.md "Threading and cross-thread state"), so a handler running under the
    /// JSON lock may call it.
    /// @return Pointer to the current connection, or nullptr if none.
    SendspinConnection* current() const {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        return this->current_connection_.get();
    }

    /// @brief Returns a shared_ptr to the current connection. Thread-safe.
    /// Role threads (sync task, artwork/visualizer drains) must use this instead of current():
    /// the shared_ptr keeps the connection alive for the duration of the caller's use even if the
    /// main loop concurrently drops or replaces the current connection. It takes conn_ptr_mutex_
    /// under the same lock order as current().
    /// @return Shared pointer to the current connection, or nullptr if none.
    std::shared_ptr<SendspinConnection> current_shared() const {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        return this->current_connection_;
    }

    /// @brief psk_ids backing a currently-open connection, provisional or admitted. Thread-safe.
    /// These are the records a completed pairing must not evict (pairing.md "Pairing Records").
    /// Takes conn_ptr_mutex_ under the same lock order as current().
    [[nodiscard]] std::vector<std::string> open_connection_psk_ids() const;

    /// @brief Schedules a pair/abort event for deferred processing in loop().
    /// @param event The pair-abort event to schedule (moved).
    void schedule_pair_abort(PairAbortEvent event);

    /// @brief Schedules a server/unpair event for deferred processing in loop().
    /// @param event The server/unpair event to schedule (moved).
    void schedule_server_unpair(ServerUnpairEvent&& event);

    /// @brief Schedules a pairing-code message event for deferred processing in loop().
    /// @param event The server pairing message event to schedule (moved).
    void schedule_pairing_message(ServerPairingMessageEvent&& event);

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

    /// @brief Schedules a pairing-window confirmation for deferred processing in
    /// loop(). Thread-safe; called from SendspinClient::confirm_pairing_window().
    void schedule_pairing_window_confirm();

    /// @brief Schedules a pairing-window cancellation for deferred processing in
    /// loop(). Thread-safe; called from SendspinClient::cancel_pairing_window().
    void schedule_pairing_window_cancel();

    // ========================================
    // Handoff support
    // ========================================

    /// @brief Sets the last-played server_id for handoff preference decisions. Main loop only.
    /// @param server_id The server_id string of the last-played server; empty clears it.
    void set_last_played_server_id(const std::string& server_id);

    /// @brief Returns the current last-played server_id. Main loop only.
    /// @return The server_id of the last-played server, or nullopt if unset.
    const std::optional<std::string>& last_played_server_id() const {
        return this->last_played_server_id_;
    }

    // ========================================
    // Event queuing (thread-safe)
    // ========================================

    /// @brief Schedules a server/activate event for deferred processing in loop().
    /// Called from SendspinClient::process_json_message() on the NETWORK thread; trust
    /// enforcement, RecordStore mutations, and admission arbitration all happen in loop() on
    /// the main loop instead, matching every other cross-thread mutation in this class.
    /// @param event The server/activate event to schedule (moved).
    void schedule_activate(ServerActivateEvent event);

private:
    // ========================================
    // loop() decomposition
    // ========================================
    // loop() is a short driver over the named steps below. Behavior, locking shape, and
    // processing order are exactly as documented on loop() and on ConnectionManager above. Each
    // method's doc comment states its
    // lock contract; see loop()'s definition in connection_manager.cpp for the exact call
    // sequence and the flush_deferred_releases() calls between steps.

    /// @brief Snapshot of every deferred queue, filled by one swap under conn_mutex_ in
    /// swap_out_pending_events(). Lives in drained_events_ so the swap hands the queues back
    /// buffers that keep their capacity. Private to ConnectionManager; never exposed outside it.
    struct DrainedEvents {
        std::vector<std::shared_ptr<SendspinConnection>> connected, disconnected;
        std::vector<ServerActivateEvent> activates;
        std::vector<PairAbortEvent> pair_aborts;
        std::vector<ServerUnpairEvent> server_unpairs;
        std::vector<ServerPairingMessageEvent> pairing_messages;
        std::vector<std::string> pairing_succeeded;
        bool pairing_window_confirm{false};
        bool pairing_window_cancel{false};

        /// @brief True if any queue above has an entry, or a window gesture is set.
        bool any() const;

        /// @brief Empties every queue and clears both gestures, keeping the queues' capacity.
        void clear();
    };

    /// @brief Starts the WS server once the network becomes ready. A persistent failure (e.g. the
    /// server port is already in use) is retried with backoff instead of on every tick, which
    /// would spam the log. Main-loop-only; acquires no manager mutex.
    void maybe_start_ws_server();

    /// @brief Swaps every pending_*_events_ queue and the pairing-window confirm and cancel flags
    /// out into `ev`, which must be empty (the swap hands the queues back its buffers). Acquires
    /// conn_mutex_ internally, and only when the has_pending_events_ acquire-load hint says there
    /// is something to swap; clears has_pending_events_ under that same lock.
    /// @param ev Destination, left empty when the hint was false.
    void swap_out_pending_events(DrainedEvents& ev);

    /// @brief Applies disconnect events, then connected events, then in-band re-handshake
    /// re-arms, then server/activate events (trust enforcement, pairing-method admissibility,
    /// apply), then runs the promotion/arbitration scan over the nursery, in that order. Caller
    /// must hold conn_ptr_mutex_.
    /// @param ev Drained events from swap_out_pending_events(); consumed in place.
    void drain_lifecycle_events(DrainedEvents& ev);

    /// @brief Applies one server/activate event: trust enforcement, pairing_index bump,
    /// pairing-method and emission-format admissibility, then applies the activate's state
    /// and dispatches (arbitration for a nursery entry, or the already-admitted-connection
    /// branches: leftover-pairing cleanup, first-activate handshake completion, or entering
    /// pairing on a subsequent activate). No-op if event.conn is null, or if the connection is
    /// neither in the nursery nor the current connection (already released by an earlier event
    /// in the same loop() pass). Caller must hold conn_ptr_mutex_.
    /// @param event The server/activate event to process.
    void process_activate_event(ServerActivateEvent& event);

    /// @brief Applies pair/abort events, then pairing-code message events, then
    /// pairing-succeeded events, then a pairing-window confirm and then a cancel. Caller must
    /// hold conn_ptr_mutex_.
    /// @param ev Drained events from swap_out_pending_events(); consumed in place.
    void drain_pairing_events(DrainedEvents& ev);

    /// @brief Applies server/unpair events. Caller must hold conn_ptr_mutex_.
    /// @param ev Drained events from swap_out_pending_events(); consumed in place.
    void drain_unpair_events(DrainedEvents& ev);

    /// @brief Copies current_connection_ and every nursery entry under a brief conn_ptr_mutex_
    /// lock, then calls loop() on each copy outside the lock. Acquires conn_ptr_mutex_
    /// internally, and only when the nursery_size_/has_current_ hints say there is something to
    /// copy.
    void loop_managed_connections();

    /// @brief Arms hellos for nursery connections whose Noise handshake just completed (level-
    /// triggered noise-completion scan), checks hello retry timers, and reaps nursery connections
    /// that miss the establish deadline. Acquires conn_ptr_mutex_ internally, and only when the
    /// nursery_size_ hint says there is something to scan.
    void scan_hello_and_nursery();

    /// @brief Aborts a pairing-code exchange on the current connection that has stalled past
    /// PAIRING_ATTEMPT_TIMEOUT_US. Suppressed once the pairing is finalized: the session is
    /// only reset at the post-rekey activate, and the deadline elapsing inside that window
    /// must not abort a completed pairing. Also held while the connection awaits a
    /// server/activate, since connection.md "Re-handshake" lets the client start no application
    /// message there. Acquires conn_ptr_mutex_ internally.
    void scan_pairing_attempt_timeout();

    /// @brief Drops the current connection if it has failed to re-prove itself (after an in-band
    /// re-handshake or a pairing-finalize rekey) within REPROVE_TIMEOUT_US. Closes without a
    /// goodbye: one of those windows starts at Noise message 1, where connection.md
    /// "Re-handshake" allows no application message. Acquires conn_ptr_mutex_ internally.
    void scan_reprove_watchdog();

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
    /// the noise-completion scan in scan_hello_and_nursery()). Otherwise the hello is armed right
    /// away.
    /// @param conn The newly delivered server connection. The session slot keeps a parallel
    ///             refcount, so this observer can be reset at any time without freeing the conn
    ///             out from under in-flight httpd workers.
    void on_new_connection(std::shared_ptr<SendspinServerConnection> conn);

    /// @brief Finds the nursery entry holding the given connection. Caller must hold
    /// conn_ptr_mutex_.
    /// @param conn The connection to look up.
    /// @return Iterator into nursery_, or nursery_.end() if the connection is not in the nursery.
    std::vector<NurseryEntry>::iterator find_in_nursery(const SendspinConnection* conn);

    /// @brief Refreshes nursery_size_ from nursery_.size(). Every nursery_ mutation site calls
    /// this immediately afterward, in the same critical section, so the hint atomic can never
    /// drift from the container. Caller must hold conn_ptr_mutex_.
    void refresh_nursery_size_hint();

    /// @brief Refreshes deferred_size_ from deferred_releases_.size(). Every deferred_releases_
    /// mutation site calls this immediately afterward, in the same critical section, so the hint
    /// atomic can never drift from the container. Caller must hold conn_ptr_mutex_.
    void refresh_deferred_size_hint();

    /// @brief Appends an entry to the nursery and refreshes nursery_size_ (via
    /// refresh_nursery_size_hint()) in the same critical section, so the hint atomic can never
    /// drift from nursery_.size(). Caller must hold conn_ptr_mutex_.
    /// @param entry The nursery entry to add.
    void push_nursery_entry(NurseryEntry entry);

    /// @brief Assigns current_connection_ and refreshes has_current_ in the same critical section,
    /// so the hint atomic can never drift from "current_connection_ != nullptr". Pass nullptr to
    /// clear the slot. Caller must hold conn_ptr_mutex_ and call flush_pending_admission() after
    /// dropping it: installing a connection only stages its admission.
    /// @param conn The connection to install as current, or nullptr to clear; moved from.
    void set_current_connection(std::shared_ptr<SendspinConnection> conn);

    /// @brief Admits the connection staged by the last set_current_connection(), if any.
    /// Caller must NOT hold conn_ptr_mutex_: admission replays the held role messages under
    /// SendspinClient's json_processing_mutex_, which the lock order in docs/conventions.md
    /// ("Threading and cross-thread state") places outside conn_ptr_mutex_. Staging and flushing
    /// are both main-loop-only and happen in the same call, so the staged slot cannot go stale.
    void flush_pending_admission();

    /// @brief Appends a persistence-provider write to pending_record_ops_. Caller must hold
    /// conn_ptr_mutex_ and call flush_pending_record_ops() after dropping it.
    /// @param kind Which write to perform.
    /// @param value The psk_id or server_id it covers.
    void stage_record_op(PendingRecordOp::Kind kind, std::string value);

    /// @brief Performs the writes staged by the locked handlers, in staging order, so a second
    /// op on the same record always lands after the first. Caller must NOT hold conn_ptr_mutex_
    /// (see PendingRecordOp).
    ///
    /// Every staging site sits in loop()'s lifecycle block, which is where the single call to
    /// this function sits too: nothing staged can outlive the tick that staged it, so this needs
    /// no gate atomic and costs nothing on a tick that skips that block.
    void flush_pending_record_ops();

    /// @brief Sets has_pending_events_, the lock-free gate loop() polls before acquiring
    /// conn_mutex_. It is the atomic's only writer outside swap_out_pending_events(), so nothing
    /// can be queued without arming the gate. Caller must hold conn_mutex_.
    void mark_pending() {
        this->has_pending_events_.store(true, std::memory_order_release);
    }

    /// @brief Appends `item` to a pending_*_events_ queue and arms the gate (mark_pending()) in
    /// the same critical section, so loop() can never miss a pushed event. Every
    /// pending_*_events_ push in this class goes through this one template instead of a per-queue
    /// single-use method. Caller must hold conn_mutex_.
    /// @tparam Container Type of a pending_*_events_ member (deduced).
    /// @tparam T Type of the item being pushed (deduced; forwarded into push_back).
    /// @param container The pending_*_events_ queue to append to.
    /// @param item The event to append (forwarded).
    template <typename Container, typename T>
    void queue_pending(Container& container, T&& item) {
        container.push_back(std::forward<T>(item));
        this->mark_pending();
    }

    /// @brief Releases a nursery entry: erases it, prunes its hello retry, and queues the
    /// goodbye+release on deferred_releases_. Caller must hold conn_ptr_mutex_ and call
    /// flush_deferred_releases() after dropping it.
    /// @param it Valid iterator into nursery_.
    /// @param reason The goodbye reason to send before closing, or nullopt when the transport is
    ///        already gone so no goodbye should be attempted.
    /// @return Iterator to the entry after the erased one.
    std::vector<NurseryEntry>::iterator release_nursery_entry(
        std::vector<NurseryEntry>::iterator it, std::optional<SendspinGoodbyeReason> reason);

    /// @brief Appends a release to deferred_releases_ and refreshes deferred_size_ (via
    /// refresh_deferred_size_hint()) in the same critical section, so the hint atomic can never
    /// drift from deferred_releases_.size(). Caller must hold conn_ptr_mutex_ and call
    /// flush_deferred_releases() after dropping it.
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
    /// Early-returns without locking when deferred_size_ reads 0; see the definition for the
    /// soundness argument.
    void flush_deferred_releases();

    // ========================================
    // Hello handshake
    // ========================================
    /// @brief Arms the hello retry state so loop() will send the hello on its next tick.
    /// Only ever called for a nursery member: a connection sends exactly one client/hello, while
    /// it is proving itself.
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
    /// conn_ptr_mutex_. Used by the noise-completion scan in scan_hello_and_nursery() to arm a
    /// connection's hello exactly once (idempotent re-arming would otherwise reset the backoff
    /// every tick).
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
    /// Applies admission.h::should_admit_connection for the activity-priority arbitration. Trust
    /// enforcement (admission.h::admissible) is applied separately, before this is ever consulted,
    /// in loop()'s server/activate handling.
    /// @param current The existing active connection, or nullptr if none is admitted yet.
    /// @param new_conn The newly proven candidate connection. Must not be null.
    /// @return True if the new connection should become current, false to keep the existing one
    ///         (or reject the newcomer, when current is null this always returns true).
    bool should_switch_to_new_server(const SendspinConnection* current,
                                     const SendspinConnection* new_conn) const;
    /// @brief Updates last_played_server_id when the ADMITTED (current) connection carries the
    /// PLAYBACK activity, per the last-playback server of connection.md "Multiple servers
    /// (server-initiated)".
    /// No-op if conn is not the current connection, or does not declare PLAYBACK.
    /// Caller must hold conn_ptr_mutex_: the RAM update runs here, under the lock arbitration
    /// reads it with, and only the durable write is staged for flush_pending_record_ops().
    /// @param conn The connection to check (typically the connection an activate just applied to).
    void note_playback_activity(const SendspinConnection* conn);

    /// @brief Promotes a proven nursery entry (it->conn->is_operational() must already be true)
    /// into the current slot, or arbitrates it against an existing current connection, or
    /// rejects it with concurrent_attempt if arbitration favors the incumbent.
    ///
    /// Erases the entry from the nursery unconditionally (it never returns to the nursery).
    /// Calls should_switch_to_new_server() when a current connection already exists. The incoming
    /// side is always operational. The incumbent normally is too, with one documented exception:
    /// the re-proving window (see the class-level note above), during which it has been rewound
    /// by an in-band re-handshake or a pair-finalize ack. Its activities stay valid across a
    /// routine rekey, so arbitration on them is still correct there; the pair-finalize case is
    /// the one where they go stale, and should_switch_to_new_server() answers it by telling
    /// admission.h that the pairing is no longer in flight (suppressing its not-displaced rule)
    /// while leaving the activities themselves, and therefore every rank comparison, intact.
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

    /// @brief Drop every managed connection that authenticated with `psk_id`.
    ///
    /// Removing a record from the RecordStore does not by itself end a session that is already
    /// running on it: a connection caches its resolved psk_id and PSK category at Noise-handshake
    /// completion (see SendspinConnection::get_psk_category()) and never re-resolves them against
    /// the store. Without this sweep a revoked device would keep its LONG_TERM trust (and with
    /// it playback) until it happened to disconnect, so revocation would not take effect until
    /// the peer's next connection.
    ///
    /// Covers the current slot and the nursery. Caller must hold conn_ptr_mutex_ and call
    /// flush_deferred_releases() after dropping it.
    ///
    /// @param psk_id psk_id whose sessions are no longer trusted.
    /// @param except Connection to leave alone (its caller is already dropping it), or nullptr.
    void drop_connections_using_psk_id(const std::string& psk_id, const SendspinConnection* except);

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
    /// satisfies this; start() warns when a configured value does not.
    static constexpr size_t NURSERY_CAPACITY = 2;

    /// @brief Maximum connections open at once: the admitted one plus the nursery bound, which
    /// is NURSERY_CAPACITY + 1 because an outbound entry does not count against the capacity
    /// (see NURSERY_CAPACITY above).
    static constexpr size_t MAX_OPEN_CONNECTIONS = NURSERY_CAPACITY + 2;

    // pairing.md "Pairing Records" requires the client to cap its concurrently open paired
    // connections below its record capacity, so that a completed pairing at capacity always has
    // a record left to evict. The connection budget is fixed at compile time and the record
    // capacity has a floor, so the cap is an invariant rather than a runtime check.
    static_assert(MAX_OPEN_CONNECTIONS < RecordStore::MIN_MAX_RECORDS,
                  "open connections must stay below the pairing-record capacity floor");

    // ========================================
    // Pairing main-loop handlers
    // ========================================

    /// @brief Enters the pairing exchange for the given connection.
    /// Called on the main loop when an admitted server/activate declares the PAIRING activity
    /// with a pairing.method the client offers. PLAYBACK may ride along, and the activate need
    /// not be the connection's first.
    /// @param conn The connection entering pairing. Must be non-null.
    void handle_enter_pairing(SendspinConnection* conn);

    /// @brief Runs the pairing-code branch of handle_enter_pairing(): populates the
    /// PairingSession, applies gesture gating (pairing.md "Pairing Window"), and either sends
    /// client/pair-pending and waits for a window, or starts the attempt immediately.
    /// @param conn The connection entering pairing.
    /// @param pairing_index Current pairing_index counter, captured by handle_enter_pairing().
    /// @param server_id conn->get_server_id(), captured by handle_enter_pairing().
    /// @param selected_method The selected method; DYNAMIC_PAIRING_CODE or STATIC_PAIRING_CODE.
    void handle_enter_pairing_code(SendspinConnection* conn, uint32_t pairing_index,
                                   const std::string& server_id,
                                   SendspinPairMethod selected_method);

    /// @brief Runs the Pairing-PSK branch of handle_enter_pairing(): resolves the pairing
    /// outcome and sends client/pair-init followed by client/pair-finalize with the long-term
    /// PSK in the clear.
    /// @param conn The connection entering pairing.
    /// @param pairing_index Current pairing_index counter, captured by handle_enter_pairing().
    /// @param server_id conn->get_server_id(), captured by handle_enter_pairing().
    void handle_enter_pairing_psk(SendspinConnection* conn, uint32_t pairing_index,
                                  const std::string& server_id);

    /// @brief Handles a pair/abort event on the main loop.
    /// Cleans up pairing state. Per pairing.md "pair/abort", only closes the connection for reason
    /// concurrent_attempt. A pair/abort that arrives after the attempt has already ended
    /// (is_pairing_in_progress() false) is silently ignored (stale).
    /// @param conn The connection on which the abort arrived. Must be non-null.
    /// @param reason The abort reason.
    void handle_pair_abort(SendspinConnection* conn, PairAbortReason reason);

    /// @brief Fires on_clear_pairing_code and/or on_open_pairing_window's counterpart for a
    /// pairing UI element that was left showing. Caller must hold conn_ptr_mutex_.
    /// @param code_was_emitted Whether a pairing code was being emitted.
    /// @param window_was_shown Whether the pairing-window gesture prompt was open.
    void dismiss_pairing_ui(bool code_was_emitted, bool window_was_shown);

    /// @brief Shared cleanup for every path that locally ends a pairing attempt on `conn`.
    ///
    /// Captures the code-emission / pairing-window flags before clear_pairing_state() resets
    /// them, optionally sends a wire pair/abort, clears the pairing state, optionally drops the
    /// connection, then queues on_pairing_failed and dismisses any pairing UI left showing (via
    /// dismiss_pairing_ui()). When `drop_action` is not KEEP_OPEN, drop_connection() -> the
    /// current-slot cleanup runs before the note_* calls, matching the ordering every call site
    /// needs (the pending-notification vectors it clears must not race the queue pushes below).
    /// Caller must hold conn_ptr_mutex_; `conn` must be non-null.
    ///
    /// @param conn               Connection whose pairing attempt is ending. Must be non-null.
    /// @param wire_abort_reason  If set, sends pair/abort(wire_abort_reason) to the peer first
    ///        (best-effort). Leave nullopt when the abort was received from the peer, or when
    ///        pairing.md "Protocol Errors" forbids sending one.
    /// @param drop_action        Whether/how the connection is closed. KEEP_OPEN leaves it open.
    ///        CLOSE_SILENTLY drops it via drop_connection() without a client/goodbye.
    ///        CLOSE_WITH_GOODBYE drops it via drop_connection() using goodbye_reason.
    /// @param public_reason      Reason delivered to the application via on_pairing_failed.
    /// @param goodbye_reason     Goodbye reason passed to drop_connection() when drop_action is
    ///        CLOSE_WITH_GOODBYE; read only then, so callers for the other actions omit it.
    void abort_pairing_attempt(
        SendspinConnection* conn, std::optional<PairAbortReason> wire_abort_reason,
        PairingDropAction drop_action, SendspinPairAbortReason public_reason,
        SendspinGoodbyeReason goodbye_reason = SendspinGoodbyeReason::UNAUTHORIZED);

    // ========================================
    // Pairing-code main-loop handlers
    // ========================================

    /// @brief Handle a server pairing-code message on the main loop.
    /// Advances the PairingStep state machine for the connection.
    /// @param conn The connection that received the message. Must be non-null.
    /// @param event The parsed server pairing message.
    void handle_pairing_message(SendspinConnection* conn, const ServerPairingMessageEvent& event);

    /// @brief Handles PairingMessageKind::PAIR_INIT: begins a round (pairing.md "Rounds"),
    /// deriving and emitting the pairing code in the attempt's first one, and starts a fresh
    /// CPace run as RESPONDER. Dynamic pairing code only; a PAIR_INIT while
    /// ps.method == STATIC_PAIRING_CODE is a wrong-step protocol violation.
    /// @param conn The connection that received the message.
    /// @param event The parsed server pairing message; nonce_a is used here.
    void handle_pair_init(SendspinConnection* conn, const ServerPairingMessageEvent& event);

    /// @brief Handles PairingMessageKind::PAIR_AUTH: sends client/pair-auth (pake_msg_2), then
    /// derives the MAC key from the server's share (pake_msg_1). A derive failure is a spec
    /// Protocol Errors close (no pair/abort), not a pairing-code mismatch.
    /// @param conn The connection that received the message.
    /// @param event The parsed server pairing message; pake_msg_1 is used here.
    void handle_pair_auth(SendspinConnection* conn, const ServerPairingMessageEvent& event);

    /// @brief Handles PairingMessageKind::PAIR_CONFIRM: verifies server_kc, then either sends
    /// client/pair-confirm plus the CPace-wrapped client/pair-finalize, or asks for another
    /// round with client/pair-retry, or aborts at the round limit (pairing.md "Rounds").
    /// @param conn The connection that received the message.
    /// @param event The parsed server pairing message; server_kc is used here.
    void handle_pair_confirm(SendspinConnection* conn, const ServerPairingMessageEvent& event);

    /// @brief Abort the current pairing-code session: send pair/abort, notify, and close the
    /// connection only for reason concurrent_attempt (pairing.md "pair/abort").
    /// @param conn The connection to abort. Must be non-null.
    /// @param reason The abort reason to send.
    void local_abort_pairing(SendspinConnection* conn, PairAbortReason reason);

    /// @brief End an attempt whose peer sent a pairing message out of sequence: close the
    /// connection without any application-level message and persist nothing
    /// (pairing.md "Sequence violations", "Protocol Errors").
    /// @param conn The connection that sent the out-of-sequence message.
    /// @param message_type The message type as it appears on the wire, for the log.
    void close_on_sequence_violation(SendspinConnection* conn, const char* message_type);

    // ========================================
    // Pairing-window main-loop handlers
    // ========================================

    /// @brief Start the prepared attempt on `conn`: send client/pair-init (with commit_B for a
    /// dynamic pairing code, bare plus CPace start for a static one), advance the PairingStep,
    /// and arm the attempt timeout. The PairingSession must already be populated by
    /// handle_enter_pairing.
    /// @param conn The connection whose session starts.
    void start_pairing_attempt(SendspinConnection* conn);

    /// @brief Start the CPace exchange for the current round: build the sid and start the
    /// RESPONDER run over the session's PRS (pairing.md "PAKE"), advancing the step to
    /// AWAIT_SERVER_PAIR_AUTH. Aborts the attempt and returns false when CPace refuses to start.
    /// @param conn The connection whose session runs the exchange.
    /// @return true when the round started.
    bool start_pake_round(SendspinConnection* conn);

    /// @brief Return true if a pairing window is open (opened by an operator gesture, not yet
    /// closed by one of pairing.md "Pairing Window"'s closing events, and within its 5-minute
    /// lifetime). Main-loop-only.
    [[nodiscard]] bool pairing_window_open() const;

    /// @brief Open the pairing window on the main loop (operator gesture). If an attempt is
    /// already waiting in AWAIT_PAIRING_WINDOW, the window admits it immediately; otherwise it
    /// stands open for WINDOW_LIFETIME_US (5 minutes) awaiting a pairing activate. The gesture is
    /// also the deliberate operator action that clears a standing round limit
    /// (pairing.md "Rounds").
    void open_pairing_window();

    /// @brief Whether the dynamic-pairing-code round limit currently holds attempts back:
    /// PAIRING_ROUND_LIMIT rounds have run since the last verified server_kc
    /// (pairing.md "Rounds"). Main-loop-only.
    [[nodiscard]] bool pairing_round_limit_reached() const;

    /// @brief Handle a confirmed pairing-window gesture on the main loop
    /// (SendspinClient::confirm_pairing_window()). Delegates to open_pairing_window().
    void handle_pairing_window_confirmed();

    /// @brief Handle an operator cancellation on the main loop
    /// (SendspinClient::cancel_pairing_window()): closes the window, and ends an attempt still
    /// waiting on the gesture with pair/abort reason user_cancelled (pairing.md
    /// "Pairing Window").
    void handle_pairing_window_cancelled();

    /// @brief Close the pairing window: clear its deadline, the connection it is bound to, and
    /// its failed-attempt count. Idempotent, and silent when no window is open. Main-loop-only.
    void close_pairing_window();

    /// @brief Whether an open window admits an attempt on `conn`. The window admits attempts
    /// only on the connection that carried its first (pairing.md "Pairing Window"), so a second
    /// server cannot ride a gesture the operator made for another one. Main-loop-only.
    /// @param conn The connection whose attempt is being judged.
    /// @return true when the window admits an attempt on `conn`.
    [[nodiscard]] bool pairing_window_admits(const SendspinConnection* conn) const;

    /// @brief Count one attempt under the current window whose server_kc verification failed,
    /// closing the window on the fifth (pairing.md "Pairing Window"). Main-loop-only.
    void note_pairing_window_attempt_failed();

    // ========================================
    // Unpair main-loop handler
    // ========================================

    /// @brief Handles a server/unpair event on the main loop.
    /// Checks PSK category (LONG_TERM only), removes the matched record, and disconnects with
    /// the UNPAIRED reason.
    /// @param conn The connection that received server/unpair. Must be non-null.
    /// @param event The server/unpair event.
    void handle_server_unpair(SendspinConnection* conn, const ServerUnpairEvent& event);

    // Struct fields
    std::mutex conn_mutex_;                           // Protects deferred lifecycle event queues
    mutable std::mutex conn_ptr_mutex_;               // Protects current_connection_, nursery_, and
                                                      // deferred_releases_
    std::vector<DeferredRelease> deferred_releases_;  // Queued releases; see DeferredRelease
    // Provider writes decided by the locked lifecycle handlers, performed by
    // flush_pending_record_ops() once conn_ptr_mutex_ is dropped; see PendingRecordOp. Written
    // and read only under conn_ptr_mutex_, and emptied within the tick that filled it.
    std::vector<PendingRecordOp> pending_record_ops_;
    std::vector<NurseryEntry> nursery_;  // Unproven connections awaiting establishment
    // One entry per nursery connection awaiting its hello, cleared when the hello is sent or
    // the connection leaves the nursery.
    std::vector<HelloRetryState> hello_retries_;
    std::vector<std::shared_ptr<SendspinConnection>> pending_connected_events_;
    std::vector<std::shared_ptr<SendspinConnection>> pending_disconnect_events_;
    std::vector<ServerActivateEvent> pending_activate_events_;  // Deferred server/activate events
    std::vector<PairAbortEvent> pending_pair_abort_events_;     // Deferred pair/abort events
    std::vector<ServerUnpairEvent> pending_server_unpair_events_;
    std::vector<ServerPairingMessageEvent> pending_pairing_message_events_;
    std::vector<std::string> pending_pairing_succeeded_events_;  // server_ids to notify
    // The queues above, swapped out for the current tick's drain and cleared once it is done.
    // Main-loop-only; see DrainedEvents.
    DrainedEvents drained_events_;

    // Pointer fields
    SendspinClient* client_;
    std::shared_ptr<SendspinConnection> current_connection_;
    // The connection carrying the window's first attempt, or nullptr while the window has
    // admitted none. Compared, never dereferenced, and cleared whenever the window closes, so a
    // released connection's address cannot be mistaken for a live one. Main-loop-only.
    const SendspinConnection* pairing_window_conn_{nullptr};

    /// The connection the last set_current_connection() installed, waiting for
    /// flush_pending_admission() to admit it once conn_ptr_mutex_ is dropped. Null between a
    /// flush and the next assignment, and reset by a clearing assignment. Written and read only
    /// under conn_ptr_mutex_, on the main loop.
    std::shared_ptr<SendspinConnection> pending_admission_;
    std::unique_ptr<SendspinWsServer> ws_server_;

    // String fields
    /// server_id of the last-played server; nullopt if unset.
    std::optional<std::string> last_played_server_id_;

    // 64-bit fields
    /// From resolve_liveness_timeout_ms(), in microseconds; 0 or negative disables the check.
    int64_t liveness_timeout_us_{0};
    // Standing pairing window: platform_time_us() deadline until which the window admits
    // attempts on pairing_window_conn_; 0 = closed. Opened by the operator gesture; cleared by
    // close_pairing_window() on a completed pairing, the fifth failed attempt, the bound
    // connection's drop or operator cancel, and by a client stop/restart. Main-loop-only.
    int64_t pairing_window_open_until_us_{0};
    /// Earliest time (us) to attempt another WS server start after a failure. Main-loop only.
    int64_t ws_server_start_retry_time_us_{0};

    // 32-bit fields
    // Dynamic-pairing-code rounds run since the last verified server_kc (pairing.md "Rounds").
    // Not partitioned by server_id or source address, and not persisted: the limit gates how
    // fast an attacker can guess within one boot, which a reboot does not shorten. Main-loop-only
    // (every round begins and ends in a main-loop pairing handler).
    uint32_t pairing_rounds_since_verified_kc_{0};

    // Attempts under the current window that ended in a failed server_kc verification. Reset
    // when a window opens. Main-loop-only.
    uint32_t pairing_window_failed_attempts_{0};

    // 8-bit fields
    /// True between start() and stop(). Written and read only under conn_ptr_mutex_ (the read is
    /// on_new_connection(), on the network thread), so a peer delivered after stop() closed
    /// admission is rejected rather than admitted into a nursery stop() has already emptied.
    bool accepting_{false};

    /// Pairing-window operator cancel, scheduled from any thread and consumed by loop().
    bool pending_pairing_window_cancel_{false};

    /// Pairing-window gesture confirm, scheduled from any thread and consumed by loop().
    bool pending_pairing_window_confirm_{false};

    // Atomic fields (lock-free hints for loop() tick gating; ground truth remains the
    // mutex-protected containers/pointer above; see the "Tick cost" note on loop())

    /// True while any pending_*_events_ queue holds an unswapped entry or a pairing-window
    /// gesture flag is set. Set under conn_mutex_ by mark_pending(); cleared under conn_mutex_
    /// once swap_out_pending_events() has swapped every queue and flag out. Lets loop() skip the
    /// conn_mutex_ acquisition entirely when nothing is pending.
    std::atomic<bool> has_pending_events_{false};

    /// nursery_.size(), refreshed under conn_ptr_mutex_ immediately after every nursery_
    /// mutation (always re-derived from .size(), never incremented/decremented in place, so it
    /// cannot drift). Lets loop() skip the copies/loop() block, the hello-retry scan, and the
    /// nursery reap scan when the nursery is empty, and keeps the lifecycle block running while
    /// any nursery connection exists even with no swapped-out events (its promotion scan is
    /// level-triggered on connection flags, not edge-triggered on events). Every refresh goes
    /// through refresh_nursery_size_hint().
    std::atomic<size_t> nursery_size_{0};

    /// True whenever current_connection_ is non-null. Refreshed under conn_ptr_mutex_ at every
    /// assignment (promotion, handoff, drop_connection's exchange, destructor). Lets loop() skip
    /// the copies/loop() block when there is no current connection and the nursery is empty.
    std::atomic<bool> has_current_{false};

    /// deferred_releases_.size(), refreshed under conn_ptr_mutex_ after every push (see
    /// queue_deferred_release()) and after the drain swap in flush_deferred_releases(). Lets
    /// flush_deferred_releases() early-return without locking when nothing is queued. Every
    /// refresh goes through refresh_deferred_size_hint().
    std::atomic<size_t> deferred_size_{0};
};

}  // namespace sendspin
