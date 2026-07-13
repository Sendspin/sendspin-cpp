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
#include "sendspin/client.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
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
    bool inbound;  ///< true if accepted by the WS server, false for connect_to()
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

/// @brief Hello retry state for exponential backoff
struct HelloRetryState {
    std::shared_ptr<SendspinConnection> conn;  ///< Connection awaiting hello
    int64_t retry_time_us{0};  ///< Next retry time in microseconds (0 = no pending retry)
    static constexpr uint32_t INITIAL_RETRY_DELAY_MS = 100U;  ///< Initial backoff delay in ms
    uint32_t delay_ms{INITIAL_RETRY_DELAY_MS};                ///< Current backoff delay
    uint8_t attempts{3};                                      ///< Remaining retry attempts
};

/**
 * @brief Manages WebSocket connection lifecycle.
 *
 * Accepts and creates connections, handles the hello handshake, orchestrates server handoff
 * decisions, and performs graceful disconnection with deferred cleanup.
 *
 * Connections prove themselves before they are trusted: every new connection enters a bounded
 * nursery and leaves it only by completing the hello handshake (promotion, or a fair comparison
 * against the incumbent) or by missing the establish deadline (reaped). The platform ws_server
 * delivers inbound connections only after observing their WebSocket upgrade, so the manager never
 * reasons about raw sockets that might not speak WebSocket; those are closed inside the platform
 * layer. Invariant: `current_connection_ != nullptr` implies
 * `current_connection_->is_handshake_complete()`.
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

    // ========================================
    // Handoff support
    // ========================================

    /// @brief Sets the last-played server hash for handoff preference decisions.
    /// @param hash FNV-1 hash of the last-played server ID.
    void set_last_played_server_hash(uint32_t hash);

    /// @brief FNV-1 hash function for strings.
    static uint32_t fnv1_hash(const char* str);

private:
    // ========================================
    // Connection setup
    // ========================================
    /// @brief Attaches message and lifecycle callbacks to a connection.
    /// @param conn The connection to configure.
    void setup_connection_callbacks(SendspinConnection* conn);
    /// @brief Admits an incoming server connection into the nursery and arms its hello
    ///
    /// Never enters the current slot directly (the hello handshake is not complete yet). If the
    /// inbound slots are full (outbound entries do not count) the newcomer is rejected with a
    /// goodbye, which reaches the peer because its session is already upgraded.
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
    /// @brief Arms the hello retry state so loop() will send the hello after a 100ms initial delay.
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
    void remove_hello_retry(SendspinConnection* conn);

    // ========================================
    // Connection lifecycle
    // ========================================
    /// @brief Tears down a lost connection (current or nursery). Caller must hold conn_ptr_mutex_.
    /// @param conn The connection that was lost.
    void on_connection_lost(SendspinConnection* conn);
    /// @brief Decides whether to switch from the current connection to the new one.
    /// @param current The existing active connection. Must not be null.
    /// @param new_conn The newly connected candidate connection. Must not be null.
    /// @return True if the new connection should become current, false to keep the existing one.
    bool should_switch_to_new_server(SendspinConnection* current,
                                     SendspinConnection* new_conn) const;
    /// @brief Sends a goodbye and takes ownership of the caller's shared_ptr so it drops at
    /// function exit.
    /// @param conn The connection to disconnect and release. Caller's shared_ptr is left empty.
    /// @param reason The goodbye reason to send before closing.
    void disconnect_and_release(std::shared_ptr<SendspinConnection>&& conn,
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

    // Struct fields
    std::mutex conn_mutex_;                           // Protects deferred lifecycle event queues
    mutable std::mutex conn_ptr_mutex_;               // Protects current_connection_, nursery_, and
                                                      // deferred_releases_
    std::vector<DeferredRelease> deferred_releases_;  // Queued releases; see DeferredRelease
    std::vector<NurseryEntry> nursery_;               // Unproven connections awaiting establishment
    std::vector<HelloRetryState> hello_retries_;      // One entry per connection awaiting its hello
    std::vector<std::shared_ptr<SendspinConnection>> pending_connected_events_;
    std::vector<std::shared_ptr<SendspinConnection>> pending_disconnect_events_;

    // Pointer fields
    SendspinClient* client_;
    std::shared_ptr<SendspinConnection> current_connection_;
    std::unique_ptr<SendspinWsServer> ws_server_;

    // 32-bit fields
    uint32_t last_played_server_hash_{0};

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

    /// deferred_releases_.size(), refreshed under conn_ptr_mutex_ after every push (see
    /// queue_deferred_release()) and after the drain swap in flush_deferred_releases(). Lets
    /// flush_deferred_releases() early-return without locking when nothing is queued.
    std::atomic<size_t> deferred_size_{0};
};

}  // namespace sendspin
