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

#include "connection_manager.h"

#include "admission.h"
#include "client_connection.h"
#include "connection.h"
#include "constants.h"
#include "crypto/constants.h"
#include "platform/logging.h"
#include "platform/time.h"
#include "server_connection.h"
#include "time_burst.h"
#include "ws_server.h"

#include <array>
#include <string>
#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.conn_mgr";

static constexpr int64_t WS_SERVER_START_RETRY_MS = 5000LL;
static constexpr int64_t WS_SERVER_START_RETRY_US = WS_SERVER_START_RETRY_MS * US_PER_MS;

/// @brief Transport-establishment progress of a nursery connection, used for reap diagnostics
///
/// Derived on demand from the connection's proven flags rather than stored, so it can never go
/// stale. Inbound entries are WS_UP or later by construction (delivered only after their upgrade);
/// only an outbound connect_to() still awaiting DNS/TCP resolve can be TCP_OPEN.
enum class SetupStage : uint8_t {
    TCP_OPEN,
    WS_UP,
    NOISE_PENDING,
    NOISE_DONE,
    HELLO_SENT,
    ACTIVATE_PENDING,
    ESTABLISHED
};

static SetupStage setup_stage(const SendspinConnection& conn) {
    if (conn.is_operational()) {
        return SetupStage::ESTABLISHED;
    }
    if (conn.is_handshake_complete()) {
        return SetupStage::ACTIVATE_PENDING;
    }
    if (conn.has_client_hello_sent()) {
        return SetupStage::HELLO_SENT;
    }
    if (conn.is_noise_handshake_complete()) {
        return SetupStage::NOISE_DONE;
    }
    if (conn.has_noise_handshake()) {
        return SetupStage::NOISE_PENDING;
    }
    if (conn.is_ws_upgraded()) {
        return SetupStage::WS_UP;
    }
    return SetupStage::TCP_OPEN;
}

static const char* to_cstr(SetupStage stage) {
    switch (stage) {
        case SetupStage::TCP_OPEN:
            return "TCP_OPEN";
        case SetupStage::WS_UP:
            return "WS_UP";
        case SetupStage::NOISE_PENDING:
            return "NOISE_PENDING";
        case SetupStage::NOISE_DONE:
            return "NOISE_DONE";
        case SetupStage::HELLO_SENT:
            return "HELLO_SENT";
        case SetupStage::ACTIVATE_PENDING:
            return "ACTIVATE_PENDING";
        case SetupStage::ESTABLISHED:
            return "ESTABLISHED";
    }
    return "UNKNOWN";
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

ConnectionManager::ConnectionManager(SendspinClient* client) : client_(client) {}

ConnectionManager::~ConnectionManager() {
    // Move everything out under the locks, destroy outside them: a connection destructor can join
    // its transport thread (see DeferredRelease), which must not happen while a lock is held.
    // The two mutexes guard disjoint state and are taken in separate scopes, never nested.
    std::vector<std::shared_ptr<SendspinConnection>> pending_connected;
    std::vector<std::shared_ptr<SendspinConnection>> pending_disconnects;
    std::vector<ServerActivateEvent> pending_activates;
    std::vector<std::shared_ptr<SendspinConnection>> pending_rehandshakes;
    {
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        pending_connected = std::move(this->pending_connected_events_);
        pending_disconnects = std::move(this->pending_disconnect_events_);
        pending_activates = std::move(this->pending_activate_events_);
        pending_rehandshakes = std::move(this->pending_rehandshake_events_);
        this->has_pending_events_.store(false, std::memory_order_release);
    }

    std::shared_ptr<SendspinConnection> current;
    std::vector<NurseryEntry> nursery;
    std::vector<HelloRetryState> retries;
    std::vector<DeferredRelease> releases;
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        current = std::move(this->current_connection_);
        nursery = std::move(this->nursery_);
        retries = std::move(this->hello_retries_);
        releases = std::move(this->deferred_releases_);
        // Keep the hint atomics in sync with the now-empty containers (has_pending_events_ was
        // handled above under its own mutex). Nothing reads them again after destruction, but
        // this keeps the "atomic mirrors container" invariant unconditional rather than carving
        // out an exception for teardown.
        this->has_current_.store(false, std::memory_order_release);
        this->nursery_size_.store(0, std::memory_order_release);
        this->deferred_size_.store(0, std::memory_order_release);
        this->hello_retries_size_.store(0, std::memory_order_release);
    }
    // Locals release here. Queued goodbyes are skipped on destruction; shutdown drops slots
    // without a send.
}

// ============================================================================
// Public API
// ============================================================================

void ConnectionManager::connect_to(const std::string& url) {
    SS_LOGI(TAG, "Initiating client connection to: %s", url.c_str());

    auto client_conn = std::make_shared<SendspinClientConnection>(url);
    client_conn->set_auto_reconnect(false);
    client_conn->set_task_config(this->client_->config_.websocket_priority);
    client_conn->set_websocket_payload_location(this->client_->config_.websocket_payload_location);

    this->setup_connection_callbacks(client_conn.get());
    client_conn->on_connected_cb = [this](SendspinConnection* c) {
        // Only outbound transports fire this, so it is wired here rather than in
        // setup_connection_callbacks. The connect succeeded, so the WebSocket upgrade is complete;
        // record it and defer the hello arming to loop() (this runs on the network thread).
        // Inbound connections arrive already upgraded and arm their hello at admission.
        c->mark_ws_upgraded();
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->queue_pending_connected(c->shared_from_this());
    };
    client_conn->on_disconnected_cb = [this](SendspinConnection* conn) {
        // Defer to loop(); this callback runs on IXWebSocket's internal thread
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->queue_pending_disconnect(conn->shared_from_this());
    };

    client_conn->init_time_filter();

    // Start the nursery clock: loop() reaps the connection if it has not completed the hello
    // handshake within NURSERY_ESTABLISH_TIMEOUT_US. The stamp predates DNS/TCP resolve, which is
    // why outbound entries are exempt from the short upgrade deadline.
    client_conn->set_provisional_time_us(platform_time_us());

    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

        // A present-but-disconnected current connection (its close event not yet processed) is
        // being replaced. Tear its state down as on_connection_lost would (the transport is
        // already gone, so no goodbye), instead of leaving it to occupy the slot with orphaned
        // dispatch/time-filter/client state.
        if (this->current_connection_ != nullptr && !this->current_connection_->is_connected()) {
            this->drop_connection(this->current_connection_.get(), std::nullopt);
        }

        // Only one outbound attempt at a time: release any previous outbound entry before pushing
        // the new one. Otherwise it would be dropped with no goodbye and, on ESP, leave its httpd
        // session pinned.
        for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
            if (!it->inbound) {
                it = this->release_nursery_entry(it, SendspinGoodbyeReason::ANOTHER_SERVER);
            } else {
                ++it;
            }
        }

        // A user-initiated connect is admitted even against a full nursery: there is at most one
        // outbound entry (replaced above), so the nursery is still bounded (NURSERY_CAPACITY + 1)
        // and an explicit user request never fails against inbound peers.
        this->push_nursery_entry(NurseryEntry{client_conn, /*inbound=*/false});
        client_conn->start();
    }
    this->flush_deferred_releases();
}

void ConnectionManager::disconnect(SendspinGoodbyeReason reason) {
    // Collect under the lock, send outside it: disconnect() can block on the transport (and on
    // host outbound it joins the transport thread), which must not stall other manager entry
    // points. The connections stay in their slots until their close events arrive (or the
    // manager is destroyed).
    std::vector<std::shared_ptr<SendspinConnection>> to_disconnect;
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
            to_disconnect.push_back(this->current_connection_);
        }
        // Drain the nursery too. A connected entry gets a goodbye and leaves on its close event; an
        // unconnected (pre-upgrade) entry has no transport to goodbye and yields no close, so
        // release it here rather than leave it for the nursery deadline to reap.
        for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
            if (it->conn->is_connected()) {
                to_disconnect.push_back(it->conn);
                ++it;
            } else {
                it = this->release_nursery_entry(it, std::nullopt);
            }
        }
    }
    this->flush_deferred_releases();
    for (auto& conn : to_disconnect) {
        conn->disconnect(reason, nullptr);
    }
}

// ============================================================================
// Server lifecycle
// ============================================================================

void ConnectionManager::init_server(SendspinClient* client) {
    this->client_ = client;

    this->ws_server_ = std::make_unique<SendspinWsServer>();
    this->ws_server_->set_port(this->client_->config_.server_port);
    this->ws_server_->set_max_connections(this->client_->config_.server_max_connections);
    this->ws_server_->set_ctrl_port(this->client_->config_.httpd_ctrl_port);

    // Graceful rejection needs transport headroom: the manager can hold one established inbound
    // connection plus NURSERY_CAPACITY unproven ones, and rejecting a surplus peer with a
    // client/goodbye requires the transport to accept that peer's socket on top. Below this bound
    // the nursery-full goodbye path is unreachable; surplus peers are refused at accept instead
    // (and on ESP they wait unanswered in the TCP backlog, since httpd stops accepting).
    if (this->client_->config_.server_max_connections < NURSERY_CAPACITY + 2) {
        SS_LOGW(TAG,
                "server_max_connections (%u) is below %u (1 established + %u nursery + 1 spare); "
                "surplus peers will be refused at accept instead of receiving a goodbye",
                static_cast<unsigned>(this->client_->config_.server_max_connections),
                static_cast<unsigned>(NURSERY_CAPACITY + 2),
                static_cast<unsigned>(NURSERY_CAPACITY));
    }

    this->ws_server_->set_new_connection_callback(
        [this](std::shared_ptr<SendspinServerConnection> conn) {
            this->on_new_connection(std::move(conn));
        });

    this->ws_server_->set_connection_closed_callback(
        [this](std::shared_ptr<SendspinServerConnection> conn) {
            SS_LOGD(TAG, "Connection closed callback for socket %d", conn->get_sockfd());
            // Defer cleanup to loop() so on_connection_lost runs on the main thread alongside the
            // rest of the connection state mutations. Inbound closes share the outbound disconnect
            // queue: both carry the connection itself, so a stale event can never be mis-routed to
            // a new connection (drop_connection no-ops on connections it does not manage).
            std::lock_guard<std::mutex> lock(this->conn_mutex_);
            this->queue_pending_disconnect(std::move(conn));
        });

    // Connection lookup-by-sockfd. Used by the host build's ws_server to route IXWebSocket
    // messages; the ESP build ignores this and looks the connection up directly via
    // httpd_sess_get_ctx (set in open_callback), so its setter is a no-op stub.
    this->ws_server_->set_find_connection_callback(
        [this](int sockfd) -> std::shared_ptr<SendspinConnection> {
            std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
            if (this->current_connection_ != nullptr &&
                this->current_connection_->get_sockfd() == sockfd) {
                return this->current_connection_;
            }
            for (const auto& entry : this->nursery_) {
                if (entry.conn->get_sockfd() == sockfd) {
                    return entry.conn;
                }
            }
            return nullptr;
        });
}

void ConnectionManager::loop() {
    // Start WS server when network becomes ready. A persistent failure (e.g. the server port is
    // already in use) is retried with backoff instead of on every tick, which would spam the log.
    if (this->ws_server_ != nullptr && !this->ws_server_->is_started()) {
        const int64_t now_us = platform_time_us();
        if (now_us >= this->ws_server_start_retry_time_us_ && this->client_->network_provider_ &&
            this->client_->network_provider_->is_network_ready()) {
            if (!this->ws_server_->start(this->client_, this->client_->config_.httpd_psram_stack,
                                         this->client_->config_.httpd_priority)) {
                this->ws_server_start_retry_time_us_ = now_us + WS_SERVER_START_RETRY_US;
            }
        }
    }

    // Process deferred connection lifecycle events
    {
        std::vector<std::shared_ptr<SendspinConnection>> connected_events;
        std::vector<std::shared_ptr<SendspinConnection>> disconnect_events;
        std::vector<ServerActivateEvent> activate_events;
        std::vector<std::shared_ptr<SendspinConnection>> rehandshake_events;
        // Skip the conn_mutex_ acquisition entirely when the hint says all four queues are
        // empty. Sound because every push site sets has_pending_events_ = true under
        // conn_mutex_ before releasing it (see the field's doc comment in connection_manager.h).
        if (this->has_pending_events_.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(this->conn_mutex_);
            connected_events.swap(this->pending_connected_events_);
            disconnect_events.swap(this->pending_disconnect_events_);
            activate_events.swap(this->pending_activate_events_);
            rehandshake_events.swap(this->pending_rehandshake_events_);
            this->has_pending_events_.store(false, std::memory_order_release);
        }

        // Also runs whenever the nursery is non-empty even with no swapped-out events: the
        // noise-completion scan below (see the nursery_size_ block further down) is
        // level-triggered on handshake flags set by network threads with no corresponding event
        // push, so loop() must keep running every tick a nursery connection exists.
        if (!connected_events.empty() || !disconnect_events.empty() || !activate_events.empty() ||
            !rehandshake_events.empty() ||
            this->nursery_size_.load(std::memory_order_acquire) > 0) {
            std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

            // Connection close/disconnect events (inbound ws_server closes on both platforms,
            // outbound host IXWebSocket disconnects). Keyed on connection identity, never on
            // sockfd: the OS recycles fds, so an fd-keyed event could outlive its connection and
            // mis-route to a newcomer admitted onto the recycled fd. A connection already
            // released by an earlier event is a no-op inside drop_connection.
            for (auto& conn : disconnect_events) {
                this->on_connection_lost(conn.get());
            }

            // Transport connected events: an outbound connection's WebSocket upgrade completed.
            // When encryption is required, this is where the outbound side starts the Noise
            // handshake (client_init is sent proactively; the client is always the Noise
            // responder regardless of who opened the socket, but it still sends client/init
            // first as the Sendspin protocol client). The hello is armed later, once the Noise
            // handshake completes (see the noise-completion scan below). Otherwise, arm the
            // hello right away, as before. (Inbound connections arrive already upgraded and are
            // handled the same way in on_new_connection().) Guarded by nursery membership: a
            // connection promoted or released by an earlier event is skipped.
            for (auto& conn : connected_events) {
                if (this->find_in_nursery(conn.get()) == this->nursery_.end()) {
                    continue;
                }
                if (this->client_->config_.encryption_required) {
                    conn->init_noise_handshake(*this->client_->identity_,
                                               *this->client_->record_store_,
                                               std::string(NOISE_SUITE_CHACHAPOLY));
                    conn->send_noise_client_init();
                } else {
                    this->initiate_hello(conn.get());
                }
            }

            // In-band re-handshake completions: handle_noise_rehandshake() already swapped the
            // Noise session synchronously on the network thread and reset
            // server_hello_received_/client_hello_sent_/first_activate_received_ on the
            // connection; re-arm its hello here so the post-swap server/hello -> client/hello ->
            // server/activate cycle actually runs. Only meaningful for the current (already-
            // admitted) connection -- a re-handshake never targets a nursery member (they have not
            // completed even their first hello yet) -- but is guarded defensively in case a stale
            // event outlives a race with drop_connection.
            for (auto& conn : rehandshake_events) {
                if (!conn || conn.get() != this->current_connection_.get()) {
                    continue;
                }
                SS_LOGI(TAG, "Re-arming hello after in-band re-handshake");
                this->initiate_hello(conn.get());
            }

            // server/activate events: trust enforcement, operational gating, and admission
            // arbitration. ALL decisions (admissibility, arbitration, RecordStore mutations)
            // happen here on the main loop thread, never on the network thread.
            for (auto& event : activate_events) {
                if (!event.conn) {
                    continue;
                }
                const bool in_nursery =
                    this->find_in_nursery(event.conn.get()) != this->nursery_.end();
                const bool is_current = event.conn.get() == this->current_connection_.get();
                if (!in_nursery && !is_current) {
                    // Already released by an earlier event in the same loop() pass.
                    continue;
                }

                // ---- Trust enforcement (admissibility check) ----
                // Compute the effective active_roles (sticky: nullopt keeps the prior set).
                const std::vector<std::string>& effective_roles =
                    event.active_roles.has_value() ? event.active_roles.value()
                                                   : event.conn->get_active_roles();
                const bool has_roles = !effective_roles.empty();
                const bool unpaired_access =
                    this->client_->record_store_ != nullptr &&
                    this->client_->record_store_->unpaired_access_enabled();

                // Trust enforcement only applies when encryption resolved a PSK category for
                // this connection; without it (encryption_required == false) there is no trust
                // model at all, matching pre-encryption behavior.
                const bool trust_ok = !this->client_->config_.encryption_required ||
                                      admissible(event.conn->get_psk_category(), event.activities,
                                                 has_roles, unpaired_access);

                if (!trust_ok) {
                    SendspinGoodbyeReason reject_reason = SendspinGoodbyeReason::UNAUTHORIZED;
                    if (event.conn->get_psk_category() == PskCategory::SENTINEL &&
                        !unpaired_access &&
                        admissible(event.conn->get_psk_category(), event.activities, has_roles,
                                   /*unpaired_access=*/true)) {
                        reject_reason = SendspinGoodbyeReason::PAIRING_REQUIRED;
                    }
                    SS_LOGW(TAG, "server/activate inadmissible (psk_category=%d): closing with %s",
                            static_cast<int>(event.conn->get_psk_category()),
                            reject_reason == SendspinGoodbyeReason::PAIRING_REQUIRED
                                ? "pairing_required"
                                : "unauthorized");
                    this->drop_connection(event.conn.get(), reject_reason);
                    continue;
                }

                // ---- Admissible: apply the activate's state on the main loop ----
                const bool is_first = !event.conn->first_activate_received();
                event.conn->apply_server_activate(event.activities, event.active_roles);

                // First activate on a long-term PSK: mark the record used (reference parity).
                // Safe here because RecordStore mutations stay on the main loop.
                if (is_first && this->client_->config_.encryption_required &&
                    event.conn->get_psk_category() == PskCategory::LONG_TERM &&
                    !event.conn->get_psk_id().empty() && this->client_->record_store_ != nullptr) {
                    this->client_->record_store_->mark_record_used(event.conn->get_psk_id());
                }

                if (event.conn.get() == this->current_connection_.get()) {
                    // Already admitted: no arbitration needed. is_first can still be true here
                    // after an in-band re-handshake reset first_activate_received_ (Phase 4b);
                    // re-publish state in that case, but only once the post-swap hello has also
                    // completed (is_handshake_complete()) -- otherwise this is a stale
                    // pre-completion activate and there is nothing to (re-)publish yet.
                    this->note_playback_activity(event.conn.get());
                    if (is_first && event.conn->is_handshake_complete()) {
                        this->client_->on_handshake_complete(event.conn.get());
                    }
                    continue;
                }

                // A nursery entry's first activate always eventually resolves it (promoted or
                // rejected), so a nursery entry can never see a genuinely "subsequent" activate.
                // is_first is therefore always true here; the promotion itself is handled by the
                // level-triggered scan just below (not here), because this event only proves the
                // activate arrived -- the hello handshake may still be in flight (e.g. a
                // nonconforming peer whose server/hello + server/activate race ahead of our own
                // client/hello). The scan promotes/arbitrates once BOTH are true, in whichever
                // order they complete.
            }

            // Promotion/arbitration scan: handles every nursery entry that has proven itself
            // (is_operational(): hello handshake complete AND first server/activate applied and
            // admissible -- trust was already checked above, for every activate event, including
            // ones that arrived before the hello completed). Level-triggered rather than
            // edge-triggered on the activate events just processed, because hello completion is
            // itself level-triggered (see the establishment invariant note on
            // is_handshake_complete() elsewhere in this file): the two conditions can become true
            // in either order.
            for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
                if (!it->conn->is_operational()) {
                    ++it;
                    continue;
                }
                it = this->promote_or_arbitrate_nursery_entry(it);
            }
        }

        // Send the goodbyes and release the connections dropped above, outside the lock.
        this->flush_deferred_releases();
    }

    // Call loop on active connections using shared_ptr copies to avoid holding the lock. The
    // nursery is bounded (NURSERY_CAPACITY inbound + 1 outbound), so a fixed array avoids a
    // per-tick heap allocation while connections are being set up.
    std::shared_ptr<SendspinConnection> current_copy;
    std::array<std::shared_ptr<SendspinConnection>, NURSERY_CAPACITY + 1> nursery_copies;
    size_t nursery_count = 0;
    // Skip the copy (and thus every conn->loop() call below) when there is nothing to call it
    // on: no current connection and an empty nursery.
    if (this->nursery_size_.load(std::memory_order_acquire) > 0 ||
        this->has_current_.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        current_copy = this->current_connection_;
        for (const auto& entry : this->nursery_) {
            nursery_copies[nursery_count++] = entry.conn;
        }
    }
    if (current_copy) {
        current_copy->loop();
    }
    for (size_t i = 0; i < nursery_count; ++i) {
        nursery_copies[i]->loop();
    }

    // The nursery establish-deadline reap operates purely on nursery membership, so it is skipped
    // whenever the nursery is empty. Hello retry timers used to be exactly as narrow
    // (initiate_hello was only ever called for a nursery member), but schedule_rehandshake_rearm()
    // now also arms one for the current (already-admitted) connection while it re-proves itself
    // after an in-band re-handshake -- that connection is never a nursery member, so
    // hello_retries_size_ is checked alongside nursery_size_ to avoid missing that case. The
    // retry-timer scan's own lazy erase, for a retry whose connection left the nursery AND is not
    // the current connection, covers a connection dropped by an earlier event this same tick.
    if (this->nursery_size_.load(std::memory_order_acquire) > 0 ||
        this->hello_retries_size_.load(std::memory_order_acquire) > 0) {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

        // Noise-completion scan: arm the hello for any nursery connection whose Noise
        // handshake just completed. Level-triggered because noise_handshake_complete_ flips on
        // the network thread (inside dispatch_completed_message/handle_noise_handshake_text)
        // with no corresponding queued event, unlike the connected-events edge above. Skips
        // connections whose hello is already sent or already has a pending retry, so a
        // connection is armed exactly once. When encryption is not required this scan never
        // finds anything to arm (on_new_connection/the connected-events block above already
        // armed the hello immediately in that mode).
        for (const auto& entry : this->nursery_) {
            SendspinConnection* c = entry.conn.get();
            if (c->has_client_hello_sent() || this->has_hello_retry(c)) {
                continue;
            }
            if (this->client_->config_.encryption_required && !c->is_noise_handshake_complete()) {
                continue;
            }
            this->initiate_hello(c);
        }

        // Check hello retry timers (one entry per managed connection, so a second connection
        // arriving mid-handshake cannot clobber the first connection's pending hello).
        {
            const int64_t now_us = platform_time_us();
            for (auto it = this->hello_retries_.begin(); it != this->hello_retries_.end();) {
                HelloRetryState& retry = *it;
                SendspinConnection* rc = retry.conn.get();
                const bool retry_is_current = rc == this->current_connection_.get();

                // Drop retries whose connection is neither a nursery member nor the current
                // connection. A retry entry is normally live only for nursery members; the
                // exception is the current connection transiently re-arming its hello after an
                // in-band re-handshake (schedule_rehandshake_rearm()).
                if (this->find_in_nursery(rc) == this->nursery_.end() && !retry_is_current) {
                    it = this->hello_retries_.erase(it);
                    continue;
                }

                if (retry.retry_time_us == 0 || now_us < retry.retry_time_us) {
                    ++it;
                    continue;
                }

                if (this->send_hello_message(retry.attempts - 1, rc)) {
                    // Sent, or the connection left the nursery; the retry is complete.
                    it = this->hello_retries_.erase(it);
                    continue;
                }

                // Transient failure: retry with exponential backoff until attempts are exhausted.
                if (retry.attempts > 1) {
                    retry.delay_ms *= 2;
                    retry.attempts--;
                    retry.retry_time_us = now_us + static_cast<int64_t>(retry.delay_ms) * US_PER_MS;
                    ++it;
                    continue;
                }

                // Retries exhausted. A nursery member is reaped by the establish-deadline scan
                // just below; the current connection has no such deadline (it is established by
                // construction and normally never awaits a hello), so if its post-re-handshake
                // hello cannot be sent after 3 attempts, drop it directly here instead of leaving
                // it silently wedged in a non-operational state forever.
                it = this->hello_retries_.erase(it);
                if (retry_is_current) {
                    SS_LOGW(TAG, "Post-re-handshake hello send exhausted retries; dropping");
                    this->drop_connection(rc, std::nullopt);
                }
            }
            this->hello_retries_size_.store(this->hello_retries_.size(), std::memory_order_release);
        }

        // Nursery tick: reap connections that miss the establish deadline. This is the only
        // release path for peers that connect and then stall without completing the hello, and
        // for outbound sockets whose transport never delivers a close (host IXWebSocket, issue
        // #75). Hello arming is event-driven (admission for inbound, connected event for
        // outbound), so the tick only ever reaps.
        {
            const int64_t now_us = platform_time_us();
            for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
                NurseryEntry& entry = *it;
                if (now_us - entry.conn->get_provisional_time_us() >=
                    NURSERY_ESTABLISH_TIMEOUT_US) {
                    SS_LOGW(TAG, "Nursery connection stalled at %s (>%d s), dropping",
                            to_cstr(setup_stage(*entry.conn)),
                            static_cast<int>(NURSERY_ESTABLISH_TIMEOUT_US / US_PER_SECOND));
                    it = this->release_nursery_entry(it, SendspinGoodbyeReason::ANOTHER_SERVER);
                    continue;
                }
                ++it;
            }
        }
    }

    // Send the goodbyes and release the connections reaped by the nursery tick, outside the lock.
    this->flush_deferred_releases();

    // Drive the platform ws_server's pending-upgrade reap (ESP: close sessions that never
    // complete their upgrade; host: no-op, IXWebSocket times them out itself). Called with no
    // manager lock held.
    if (this->ws_server_ != nullptr) {
        this->ws_server_->tick();
    }
}

// ============================================================================
// Connection queries
// ============================================================================

bool ConnectionManager::is_connected() const {
    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    return this->current_connection_ != nullptr && this->current_connection_->is_connected() &&
           this->current_connection_->is_operational();
}

// ============================================================================
// Handoff support
// ============================================================================

void ConnectionManager::set_last_played_server_id(const std::string& server_id) {
    this->last_played_server_id_ = server_id;
    this->has_last_played_server_ = !server_id.empty();
}

// ============================================================================
// Event queuing (thread-safe)
// ============================================================================

void ConnectionManager::schedule_activate(ServerActivateEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_activate(std::move(event));
}

void ConnectionManager::schedule_rehandshake_rearm(std::shared_ptr<SendspinConnection> conn) {
    // Called from SendspinClient::process_json_message() on the network thread, right after
    // SendspinConnection::handle_noise_rehandshake() returns success.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_rehandshake(std::move(conn));
}

// ============================================================================
// Connection setup
// ============================================================================

void ConnectionManager::setup_connection_callbacks(SendspinConnection* conn) {
    conn->on_json_message_cb = [this](SendspinConnection* c, const char* data, size_t len,
                                      int64_t timestamp) {
        this->client_->process_json_message(c, data, len, timestamp);
    };
    conn->on_binary_message_cb = [this](SendspinConnection* /*c*/, uint8_t* payload, size_t len) {
        this->client_->process_binary_message(payload, len);
    };
}

void ConnectionManager::on_new_connection(std::shared_ptr<SendspinServerConnection> conn) {
    // Called from the platform ws_server's delivery path (ESP: httpd task, host: IXWebSocket
    // thread) once the connection's WebSocket upgrade has been observed, so the manager never sees
    // a socket that has not proven it speaks WebSocket. The authoritative owner is the platform's
    // session/transport context; this observer shared_ptr can be reset at any time without freeing
    // the conn out from under in-flight workers.
    conn->init_time_filter();
    conn->set_websocket_payload_location(this->client_->config_.websocket_payload_location);

    this->setup_connection_callbacks(conn.get());
    conn->on_disconnected_cb = [](SendspinConnection* /*c*/) {
        // Cleanup happens in on_connection_lost triggered by the server
    };

    // Start the establish clock: loop() reaps the connection if it does not complete the hello
    // handshake within NURSERY_ESTABLISH_TIMEOUT_US.
    conn->set_provisional_time_us(platform_time_us());

    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

        // The newcomer has not completed the hello handshake, so it never touches the current
        // slot; it enters the bounded nursery and is promoted only once it establishes. Only
        // inbound entries count against the capacity (see NURSERY_CAPACITY). If the inbound slots
        // are full, reject the newcomer: every occupant speaks WebSocket, so there is no safe
        // eviction candidate. The goodbye reaches the peer because its session is already upgraded,
        // provided the transport had a socket to accept it on (the NURSERY_CAPACITY + 2 budget).
        size_t inbound_count = 0;
        for (const auto& entry : this->nursery_) {
            if (entry.inbound) {
                ++inbound_count;
            }
        }
        if (inbound_count >= NURSERY_CAPACITY) {
            SS_LOGW(TAG, "Nursery full of live connections, rejecting new connection");
            // Never managed, but its callbacks are already wired: block dispatch so it cannot
            // inject messages during the goodbye window.
            conn->disable_message_dispatch();
            this->queue_deferred_release(std::move(conn), SendspinGoodbyeReason::ANOTHER_SERVER);
        } else {
            SS_LOGD(TAG, "Admitting new connection into the nursery");
            if (this->client_->config_.encryption_required) {
                // The connection arrives WS-upgraded, so client/init can be sent right away
                // (there is no earlier signal to wait for). The hello is armed later, once the
                // Noise handshake completes (see the noise-completion scan in loop()).
                conn->init_noise_handshake(*this->client_->identity_, *this->client_->record_store_,
                                           std::string(NOISE_SUITE_CHACHAPOLY));
                conn->send_noise_client_init();
            } else {
                // Arm the hello right away: the connection arrives WS-upgraded, so there is no
                // earlier signal to wait for. (Outbound connections instead arm theirs when the
                // transport's connected event is processed in loop().)
                this->initiate_hello(conn.get());
            }
            this->push_nursery_entry(NurseryEntry{std::move(conn), /*inbound=*/true});
        }
    }
    this->flush_deferred_releases();
}

// ============================================================================
// Hello handshake
// ============================================================================

void ConnectionManager::initiate_hello(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    // Arm a per-connection hello retry: send on the next tick, 3 attempts. If an entry for this
    // connection already exists (a duplicate connected event for the same connection would land
    // here twice), re-arm it in place instead of pushing a second one, so a connection never gets
    // two timers.
    auto conn_sp = conn->shared_from_this();
    const int64_t retry_time_us = platform_time_us();

    for (auto& retry : this->hello_retries_) {
        if (retry.conn == conn_sp) {
            retry.delay_ms = HelloRetryState::INITIAL_RETRY_DELAY_MS;
            retry.attempts = 3;
            retry.retry_time_us = retry_time_us;
            return;
        }
    }

    HelloRetryState retry;
    retry.conn = std::move(conn_sp);
    retry.delay_ms = HelloRetryState::INITIAL_RETRY_DELAY_MS;
    retry.attempts = 3;
    retry.retry_time_us = retry_time_us;
    this->hello_retries_.push_back(std::move(retry));
    this->hello_retries_size_.store(this->hello_retries_.size(), std::memory_order_release);
}

void ConnectionManager::remove_hello_retry(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    // Safe to call unconditionally: a no-op if conn never had a retry entry (e.g. a connection
    // rejected before initiate_hello, or one whose hello already sent and cleared its entry).
    for (auto it = this->hello_retries_.begin(); it != this->hello_retries_.end();) {
        if (it->conn.get() == conn) {
            it = this->hello_retries_.erase(it);
        } else {
            ++it;
        }
    }
    this->hello_retries_size_.store(this->hello_retries_.size(), std::memory_order_release);
}

bool ConnectionManager::has_hello_retry(const SendspinConnection* conn) const {
    // Note: caller must hold conn_ptr_mutex_
    for (const auto& retry : this->hello_retries_) {
        if (retry.conn.get() == conn) {
            return true;
        }
    }
    return false;
}

bool ConnectionManager::send_hello_message(uint8_t remaining_attempts, SendspinConnection* conn) {
    // Verify the connection is still managed: hellos are normally sent to nursery members, plus
    // the current connection while it re-proves itself after an in-band re-handshake (see
    // schedule_rehandshake_rearm()). Anything else (already released by an earlier event this
    // tick) is stale.
    if (this->find_in_nursery(conn) == this->nursery_.end() &&
        conn != this->current_connection_.get()) {
        SS_LOGW(TAG, "Connection no longer valid for hello message");
        return true;
    }

    if (conn == nullptr || !conn->is_connected()) {
        SS_LOGW(TAG, "Cannot send hello - not connected");
        return true;
    }

    std::string hello_message = this->client_->build_hello_message(conn);

    // send_app_json (not send_text_message): once the Noise transport is active, client/hello
    // must be encrypted like every other post-handshake message; send_app_json routes to the
    // encrypted path automatically and falls back to plain text when there is no active
    // transport (encryption_required == false).
    SsErr err = conn->send_app_json(
        hello_message,
        [conn](bool success) {
            // Runs on the transport's send-completion context (httpd worker on ESP, inline on
            // host); conn is kept alive for the duration by the transport (see AsyncRespArg).
            // Setting the flag is all that is needed: establishment is level-triggered, so
            // loop()'s promotion scan observes is_handshake_complete() on its next tick even
            // when the peer's server/hello raced ahead of this send.
            if (!success) {
                SS_LOGW(TAG, "Hello message send failed");
                return;
            }
            conn->set_client_hello_sent(true);
        },
        /*allow_before_hello=*/true);

    if (err == SsErr::OK) {
        return true;  // Successfully queued
    }

    if (err == SsErr::INVALID_STATE) {
        SS_LOGW(TAG, "No client connected for hello message");
        return true;  // Don't retry
    }

    SS_LOGW(TAG, "Failed to queue hello message (err=%d), %d attempts remaining",
            static_cast<int>(err), remaining_attempts);
    return false;
}

// ============================================================================
// Connection lifecycle
// ============================================================================

std::vector<NurseryEntry>::iterator ConnectionManager::find_in_nursery(
    const SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    for (auto it = this->nursery_.begin(); it != this->nursery_.end(); ++it) {
        if (it->conn.get() == conn) {
            return it;
        }
    }
    return this->nursery_.end();
}

void ConnectionManager::push_nursery_entry(NurseryEntry entry) {
    // Note: caller must hold conn_ptr_mutex_
    this->nursery_.push_back(std::move(entry));
    this->nursery_size_.store(this->nursery_.size(), std::memory_order_release);
}

void ConnectionManager::set_current_connection(std::shared_ptr<SendspinConnection> conn) {
    // Note: caller must hold conn_ptr_mutex_
    this->has_current_.store(conn != nullptr, std::memory_order_release);
    this->current_connection_ = std::move(conn);
}

void ConnectionManager::queue_pending_connected(std::shared_ptr<SendspinConnection> conn) {
    // Note: caller must hold conn_mutex_
    this->pending_connected_events_.push_back(std::move(conn));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_disconnect(std::shared_ptr<SendspinConnection> conn) {
    // Note: caller must hold conn_mutex_
    this->pending_disconnect_events_.push_back(std::move(conn));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_activate(ServerActivateEvent event) {
    // Note: caller must hold conn_mutex_
    this->pending_activate_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_rehandshake(std::shared_ptr<SendspinConnection> conn) {
    // Note: caller must hold conn_mutex_
    this->pending_rehandshake_events_.push_back(std::move(conn));
    this->has_pending_events_.store(true, std::memory_order_release);
}

std::vector<NurseryEntry>::iterator ConnectionManager::release_nursery_entry(
    std::vector<NurseryEntry>::iterator it, std::optional<SendspinGoodbyeReason> reason) {
    // Note: caller must hold conn_ptr_mutex_ and flush_deferred_releases() after dropping it
    auto conn = std::move(it->conn);
    auto next = this->nursery_.erase(it);
    this->nursery_size_.store(this->nursery_.size(), std::memory_order_release);
    // Leaving management: block stale network-thread dispatch into role/state queues during the
    // goodbye window. Outgoing sends, including the goodbye itself, are unaffected.
    conn->disable_message_dispatch();
    this->remove_hello_retry(conn.get());
    this->queue_deferred_release(std::move(conn), reason);
    return next;
}

void ConnectionManager::queue_deferred_release(std::shared_ptr<SendspinConnection> conn,
                                               std::optional<SendspinGoodbyeReason> reason) {
    // Note: caller must hold conn_ptr_mutex_ and call flush_deferred_releases() after dropping it
    this->deferred_releases_.push_back({std::move(conn), reason});
    this->deferred_size_.store(this->deferred_releases_.size(), std::memory_order_release);
}

void ConnectionManager::flush_deferred_releases() {
    // Note: caller must NOT hold conn_ptr_mutex_ (see DeferredRelease)
    //
    // Lock-free early return: deferred_size_ mirrors deferred_releases_.size() and is refreshed
    // only under conn_ptr_mutex_, at every push (queue_deferred_release()) and at the drain swap
    // below, so observing 0 here means the container was empty as of that acquire-load. This is
    // sound because every push site is followed by a call to this function on the SAME thread
    // before the pushing function returns to its caller: loop()'s lifecycle block (Block 2) is
    // followed by the Block-3 call below it in loop() itself; connect_to() and disconnect() each
    // call this function right after their locked section; on_new_connection() calls it right
    // after its locked section too (on the network/httpd thread, not the main loop thread -- the
    // "same thread" guarantee is about the call stack that did the push, not about which thread
    // that happens to be). So a push is normally drained by its own triggering call before that
    // call returns. If a concurrently racing flush call (a different thread, or loop()'s other
    // backstop call within the same tick) wins the lock first and drains it, that is equally
    // fine: a queued release is performed exactly once by whichever call actually swaps it out,
    // and the pushing call's own subsequent gate check then correctly observes 0 and skips a
    // lock it no longer needs. Either way nothing pushed is ever left stranded: loop() also
    // calls this function unconditionally twice per tick (after the lifecycle block and after
    // the nursery reap), so even a hypothetical gap in the reasoning above is bounded to the
    // very next tick.
    if (this->deferred_size_.load(std::memory_order_acquire) == 0) {
        return;
    }
    std::vector<DeferredRelease> releases;
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        releases.swap(this->deferred_releases_);
        this->deferred_size_.store(this->deferred_releases_.size(), std::memory_order_release);
    }
    for (auto& release : releases) {
        if (release.goodbye.has_value()) {
            this->disconnect_and_release(std::move(release.conn), release.goodbye.value());
        }
        // Without a goodbye the shared_ptr simply drops (below, when `releases` goes out of
        // scope): even bare destruction happens outside the lock, because a connection
        // destructor can join its transport thread.
    }
}

void ConnectionManager::on_connection_lost(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_ (reads the slots and calls drop_connection)
    if (conn == nullptr) {
        return;
    }

    if (conn == this->current_connection_.get()) {
        SS_LOGI(TAG, "Current connection lost");
    } else if (this->find_in_nursery(conn) != this->nursery_.end()) {
        SS_LOGD(TAG, "Nursery connection lost");
    }

    // The transport is already gone, so no goodbye is attempted (nullopt).
    this->drop_connection(conn, std::nullopt);
}

void ConnectionManager::drop_connection(SendspinConnection* conn,
                                        std::optional<SendspinGoodbyeReason> goodbye) {
    // Note: caller must hold conn_ptr_mutex_
    if (conn == nullptr) {
        return;
    }

    this->remove_hello_retry(conn);

    if (conn == this->current_connection_.get()) {
        // Dropping the admitted connection: block stale network-thread events and quiesce the
        // client's per-connection state (including the time burst). The slot stays empty; the next
        // nursery establishment promotes into it. The goodbye send and the release itself are
        // deferred (see DeferredRelease).
        conn->disable_message_dispatch();
        this->client_->cleanup_connection_state();
        // set_current_connection(nullptr) reassigns the slot to a clean null (not a moved-from
        // state) after we move the old connection out, so a later event in the same loop() pass
        // that reads current_connection_ never trips the static analyzer.
        auto dropped = std::move(this->current_connection_);
        this->set_current_connection(nullptr);
        this->queue_deferred_release(std::move(dropped), goodbye);
        return;
    }

    if (auto it = this->find_in_nursery(conn); it != this->nursery_.end()) {
        // Dropping an unproven connection: no client-state cleanup (it was never admitted).
        this->release_nursery_entry(it, goodbye);
    }
    // Not a managed connection: nothing to do (already released by an earlier event this tick).
}

bool ConnectionManager::should_switch_to_new_server(SendspinConnection* current,
                                                    SendspinConnection* new_conn) const {
    // Ports admission.h::should_admit_connection (activity-priority arbitration). `current` may
    // be null (nothing admitted yet); the pure function's has_admitted=false path always admits.
    const bool has_current = current != nullptr;
    return should_admit_connection(
        /*incoming_activities=*/new_conn->get_activities(),
        /*incoming_server_id=*/new_conn->get_server_id(),
        /*admitted_activities=*/
        has_current ? current->get_activities() : std::vector<SendspinActivity>{},
        /*admitted_server_id=*/has_current ? current->get_server_id() : std::string{},
        /*has_admitted=*/has_current,
        /*last_playback_server_id=*/this->last_played_server_id_,
        /*has_last_playback=*/this->has_last_played_server_);
}

void ConnectionManager::note_playback_activity(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    // Mirrors note_playback_activity in aiosendspin/client/client.py: only the ADMITTED
    // (current) connection updates last_played_server_id, and only when it carries PLAYBACK.
    if (conn == nullptr || conn != this->current_connection_.get()) {
        return;
    }
    if (!conn->has_activity(SendspinActivity::PLAYBACK)) {
        return;
    }
    const std::string& server_id = conn->get_server_id();
    if (server_id.empty()) {
        return;
    }
    // Delegate to SendspinClient::persist_last_played_server, which also updates this
    // manager's last_played_server_id_ and persists via the provider.
    this->client_->persist_last_played_server(server_id);
    SS_LOGD(TAG, "note_playback_activity: last_played_server_id updated to %s", server_id.c_str());
}

std::vector<NurseryEntry>::iterator ConnectionManager::promote_or_arbitrate_nursery_entry(
    std::vector<NurseryEntry>::iterator it) {
    // Note: caller must hold conn_ptr_mutex_
    auto conn = std::move(it->conn);
    auto next = this->nursery_.erase(it);
    this->nursery_size_.store(this->nursery_.size(), std::memory_order_release);
    this->remove_hello_retry(conn.get());

    if (this->current_connection_ == nullptr) {
        this->set_current_connection(std::move(conn));
    } else if (this->should_switch_to_new_server(this->current_connection_.get(), conn.get())) {
        // Both sides of the comparison are operational (hello + first activate applied), so
        // arbitration always runs on real activity data. No incumbent is ever evicted on timing
        // alone.
        SS_LOGI(TAG, "Admission arbitration: switch to new server");
        this->drop_connection(this->current_connection_.get(),
                              SendspinGoodbyeReason::ANOTHER_SERVER);
        this->set_current_connection(std::move(conn));
    } else {
        SS_LOGI(TAG, "Admission arbitration: reject incoming (keep current)");
        // Leaving management: block stale network-thread dispatch during the goodbye window
        // (outgoing sends, including the goodbye itself, are unaffected).
        conn->disable_message_dispatch();
        this->queue_deferred_release(std::move(conn), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
        return next;
    }

    // Notify the client, publish state, and record playback activity, only for the winner.
    this->note_playback_activity(this->current_connection_.get());
    this->client_->on_handshake_complete(this->current_connection_.get());

    SS_LOGI(TAG, "Connection admitted: server_id=%s",
            this->current_connection_->get_server_id().c_str());
    return next;
}

void ConnectionManager::disconnect_and_release(std::shared_ptr<SendspinConnection>&& conn,
                                               SendspinGoodbyeReason reason) {
    // Take ownership of the caller's shared_ptr into a local, send the goodbye, then let the
    // local go out of scope. On ESP the httpd session slot keeps the conn alive until the
    // goodbye worker runs, calls trigger_close, the session tears down, and the slot's free_fn
    // fires. On host the IXWebSocket send is synchronous, so the goodbye + close have both
    // completed by the time disconnect() returns.
    auto local = std::move(conn);
    local->disconnect(reason, nullptr);
}

}  // namespace sendspin
