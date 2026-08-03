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
#include "crypto/cpace.h"
#include "crypto/pin.h"
#include "management.h"
#include "platform/base64.h"
#include "platform/logging.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "server_connection.h"
#include "time_burst.h"
#include "ws_server.h"

#include <array>
#include <cstring>
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

/// @brief Overall deadline for a dynamic-PIN pairing attempt (mirrors the reference's 120 s
/// asyncio.timeout). If the server stalls mid-exchange the attempt is aborted and the PIN is
/// cleared from the display, rather than hanging until the transport eventually drops.
static constexpr int64_t PIN_ATTEMPT_TIMEOUT_US = 120LL * 1000LL * US_PER_MS;

/// @brief Window during which the operator may perform the static-PIN pairing-window gesture
/// (mirrors the reference's WINDOW_LIFETIME_S = 300.0). Reused as the PinSession
/// attempt_deadline_us while step == AWAIT_PAIRING_WINDOW, so the existing PIN-attempt-timeout
/// check in loop() also enforces this window without a second timer.
static constexpr int64_t WINDOW_LIFETIME_US = 300LL * 1000LL * US_PER_MS;

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
        std::vector<PairAbortEvent> pair_abort_events;
        std::vector<ManagementRequestEvent> management_request_events;
        std::vector<ServerUnpairEvent> server_unpair_events;
        std::vector<ServerPairingMessageEvent> pin_pairing_events;
        std::vector<std::string> pairing_succeeded_events;
        bool pairing_window_confirm_event = false;
        // Skip the conn_mutex_ acquisition entirely when the hint says all queues are
        // empty. Sound because every push site sets has_pending_events_ = true under
        // conn_mutex_ before releasing it (see the field's doc comment in connection_manager.h).
        if (this->has_pending_events_.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(this->conn_mutex_);
            connected_events.swap(this->pending_connected_events_);
            disconnect_events.swap(this->pending_disconnect_events_);
            activate_events.swap(this->pending_activate_events_);
            rehandshake_events.swap(this->pending_rehandshake_events_);
            pair_abort_events.swap(this->pending_pair_abort_events_);
            management_request_events.swap(this->pending_management_request_events_);
            server_unpair_events.swap(this->pending_server_unpair_events_);
            pin_pairing_events.swap(this->pending_pin_pairing_events_);
            pairing_succeeded_events.swap(this->pending_pairing_succeeded_events_);
            pairing_window_confirm_event =
                std::exchange(this->pending_pairing_window_confirm_, false);
            this->has_pending_events_.store(false, std::memory_order_release);
        }

        // Also runs whenever the nursery is non-empty even with no swapped-out events: the
        // noise-completion scan below (see the nursery_size_ block further down) is
        // level-triggered on handshake flags set by network threads with no corresponding event
        // push, so loop() must keep running every tick a nursery connection exists.
        if (!connected_events.empty() || !disconnect_events.empty() || !activate_events.empty() ||
            !rehandshake_events.empty() || !pair_abort_events.empty() ||
            !management_request_events.empty() || !server_unpair_events.empty() ||
            !pin_pairing_events.empty() || !pairing_succeeded_events.empty() ||
            pairing_window_confirm_event ||
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
                event.conn->apply_server_activate(event.activities, event.active_roles,
                                                  event.selected_pair_method);

                // First activate on a long-term PSK: mark the record used (reference parity).
                // Safe here because RecordStore mutations stay on the main loop.
                if (is_first && this->client_->config_.encryption_required &&
                    event.conn->get_psk_category() == PskCategory::LONG_TERM &&
                    !event.conn->get_psk_id().empty() && this->client_->record_store_ != nullptr) {
                    this->client_->record_store_->mark_record_used(event.conn->get_psk_id());
                }

                if (event.conn.get() == this->current_connection_.get()) {
                    // Already admitted: no arbitration needed. is_first can still be true here
                    // after an in-band re-handshake reset first_activate_received_; re-publish
                    // state in that case, but only once the post-swap hello has also completed
                    // (is_handshake_complete()) -- otherwise this is a stale pre-completion
                    // activate and there is nothing to (re-)publish yet.
                    this->note_playback_activity(event.conn.get());
                    if (!is_first && event.conn->is_pairing_in_progress()) {
                        // ---- Pairing leftover activate ----
                        // Pairing was in progress and the server sent another server/activate
                        // instead of server/pair-finalize: it abandoned pairing without
                        // finalizing. Mirrors the reference's leftover branch: the activate was
                        // already applied normally above; going operational discards any pending
                        // record and resets the PIN session structurally (see the comment on
                        // SendspinClient::on_handshake_complete()).
                        SS_LOGI(TAG,
                                "Subsequent activate during pairing (leftover): clearing pairing "
                                "state and going operational for server_id=%s",
                                event.conn->get_server_id().c_str());
                        this->client_->on_handshake_complete(event.conn.get());
                    } else if (is_first && event.conn->is_handshake_complete()) {
                        this->client_->on_handshake_complete(event.conn.get());
                    } else if (!is_first) {
                        // ---- Subsequent activate transitions into pairing ----
                        // The operator can initiate pairing on an already-operational connection,
                        // not only on the very first activate: the server re-activates the
                        // connection with the PAIRING activity and a selected_pair_method.
                        // Mirrors the reference's _handle_server_activate, which runs _pair()
                        // whenever the applied activate is a pairing activate, not only on the
                        // first one. Only reached when pairing is not already in progress (the
                        // leftover-activate branch above handles that case).
                        const auto& activities = event.conn->get_activities();
                        const auto& selected_pair_method = event.conn->get_selected_pair_method();
                        const bool is_pairing_activity_only =
                            activities.size() == 1 && activities[0] == SendspinActivity::PAIRING &&
                            selected_pair_method.has_value();
                        const bool is_supported_pair_method =
                            is_pairing_activity_only &&
                            (selected_pair_method.value() == SendspinPairMethod::PAIRING_PSK ||
                             selected_pair_method.value() == SendspinPairMethod::DYNAMIC_PIN ||
                             selected_pair_method.value() == SendspinPairMethod::STATIC_PIN);
                        if (is_supported_pair_method) {
                            SS_LOGI(TAG,
                                    "Subsequent activate selects pairing (%s): entering pairing "
                                    "for server_id=%s",
                                    to_cstr(selected_pair_method.value()),
                                    event.conn->get_server_id().c_str());
                            this->handle_enter_pairing(event.conn.get());
                        }
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
                // order they complete. A pairing-flavored activate is not special-cased here: the
                // scan promotes the entry into current_connection_ exactly like any other
                // operational candidate (so admission.h's "in-flight pairing is not displaced"
                // arbitration rule applies to it), and only then branches into
                // handle_enter_pairing() instead of on_handshake_complete() -- see
                // promote_or_arbitrate_nursery_entry().
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

            // ---- Pairing deferred events ----
            // pair/abort: clean up pairing state and close the connection. (The
            // server/pair-finalize ack is committed synchronously on the network thread, and the
            // leftover-activate case is handled inline in the subsequent-activate branch above, so
            // neither needs a deferred event here.)
            for (auto& event : pair_abort_events) {
                if (!event.conn || event.conn.get() != this->current_connection_.get()) {
                    continue;
                }
                this->handle_pair_abort(event.conn.get(), event.reason);
            }

            // ---- Dynamic-PIN pairing deferred events ----
            // Only ever targets the current connection: a PIN session only exists on a
            // connection that already won promotion into current_connection_ (see the pairing
            // branch in promote_or_arbitrate_nursery_entry()).
            for (auto& event : pin_pairing_events) {
                if (!event.conn || event.conn.get() != this->current_connection_.get()) {
                    continue;
                }
                this->handle_pin_pairing_message(event.conn.get(), event);
            }

            // ---- on_pairing_succeeded deferred events ----
            // Triggered by the network-thread server/pair-finalize ack handler
            // (SendspinClient::schedule_pairing_succeeded); only ever targets the current
            // connection for the same reason as pin_pairing_events above.
            for (const auto& server_id : pairing_succeeded_events) {
                this->client_->note_pairing_succeeded(server_id);
            }

            // ---- Static-PIN pairing-window confirm deferred event ----
            if (pairing_window_confirm_event) {
                this->handle_pairing_window_confirmed();
            }

            // ---- server/unpair deferred events ----
            // Only ever targets the current connection: server/unpair is only admissible post-
            // promotion (LONG_TERM trust with an active session), never a still-unproven nursery
            // entry.
            for (auto& event : server_unpair_events) {
                if (!event.conn || event.conn.get() != this->current_connection_.get()) {
                    continue;
                }
                this->handle_server_unpair(event.conn.get(), event);
            }

            // ---- Management request deferred events ----
            // At-most-one-in-flight (server waits for result); FIFO processing is correct.
            for (auto& event : management_request_events) {
                if (!event.conn || event.conn.get() != this->current_connection_.get()) {
                    continue;
                }
                this->handle_management_request(event.conn.get(), event);
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

    // ---- Dynamic-PIN attempt timeout ----
    // Abort a dynamic-PIN exchange that has stalled past PIN_ATTEMPT_TIMEOUT_US (mirrors the
    // reference's per-attempt timeout). local_abort_pin_pairing also clears the displayed PIN.
    // Only the current connection can host a PIN session (see the pairing branch in
    // promote_or_arbitrate_nursery_entry()).
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        if (this->current_connection_ != nullptr) {
            const auto& ps = this->current_connection_->pin_session();
            const int64_t now_us = platform_time_us();
            const bool pin_attempt_expired = ps.step != SendspinConnection::PinStep::IDLE &&
                                             ps.attempt_deadline_us != 0 &&
                                             now_us >= ps.attempt_deadline_us;
            if (pin_attempt_expired) {
                SS_LOGW(TAG, "Dynamic-PIN attempt timed out for server_id=%s; aborting",
                        this->current_connection_->get_server_id().c_str());
                this->local_abort_pin_pairing(this->current_connection_.get(),
                                              PairAbortReason::ATTEMPT_TIMEOUT);
            }
        }
    }
    // Send the goodbye and release the connection if the PIN-timeout check above aborted one.
    this->flush_deferred_releases();
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

void ConnectionManager::schedule_pair_abort(PairAbortEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread when a pair/abort
    // message arrives (or a malformed pairing frame forces one).
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_pair_abort(std::move(event));
}

void ConnectionManager::schedule_management_request(ManagementRequestEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread when a
    // management/* request arrives.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_management_request(std::move(event));
}

void ConnectionManager::schedule_server_unpair(ServerUnpairEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread when
    // server/unpair arrives.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_server_unpair(std::move(event));
}

void ConnectionManager::schedule_pin_pairing_message(ServerPairingMessageEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread when a dynamic-PIN
    // pairing message arrives (or a malformed pairing frame forces a MALFORMED event).
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_pin_pairing_message(std::move(event));
}

void ConnectionManager::schedule_pairing_succeeded(std::string server_id) {
    // Called from SendspinClient::process_json_message() on the network thread when the
    // server/pair-finalize ack handler stores a long-term record.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_pairing_succeeded(std::move(server_id));
}

void ConnectionManager::schedule_pairing_window_confirm() {
    // Called from SendspinClient::confirm_pairing_window(), which may run on any thread
    // (typically the application's UI thread relaying an operator gesture).
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->pending_pairing_window_confirm_ = true;
    this->has_pending_events_.store(true, std::memory_order_release);
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

void ConnectionManager::queue_pending_pair_abort(PairAbortEvent event) {
    // Note: caller must hold conn_mutex_
    this->pending_pair_abort_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_management_request(ManagementRequestEvent event) {
    // Note: caller must hold conn_mutex_
    this->pending_management_request_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_server_unpair(ServerUnpairEvent event) {
    // Note: caller must hold conn_mutex_
    this->pending_server_unpair_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_pin_pairing_message(ServerPairingMessageEvent event) {
    // Note: caller must hold conn_mutex_
    this->pending_pin_pairing_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_pairing_succeeded(std::string server_id) {
    // Note: caller must hold conn_mutex_
    this->pending_pairing_succeeded_events_.push_back(std::move(server_id));
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
        //
        // If a PIN pairing was mid-flight, its display / pairing-window prompt must be dismissed.
        // Capture the flags before cleanup_connection_state() clears the pending notification
        // state in EventState, then queue the note_* calls after cleanup so they survive to be
        // dispatched from SendspinClient::loop() (same ordering rule as the abort handlers).
        const bool pin_was_displayed = conn->pin_session().pin_displayed;
        const bool window_was_shown = conn->pin_session().window_shown;
        conn->disable_message_dispatch();
        this->client_->cleanup_connection_state();
        // set_current_connection(nullptr) reassigns the slot to a clean null (not a moved-from
        // state) after we move the old connection out, so a later event in the same loop() pass
        // that reads current_connection_ never trips the static analyzer.
        auto dropped = std::move(this->current_connection_);
        this->set_current_connection(nullptr);
        this->queue_deferred_release(std::move(dropped), goodbye);
        if (pin_was_displayed) {
            this->client_->note_clear_pin();
        }
        if (window_was_shown) {
            this->client_->note_close_pairing_window();
        }
        return;
    }

    if (auto it = this->find_in_nursery(conn); it != this->nursery_.end()) {
        // Dropping an unproven connection: no client-state cleanup (it was never admitted). PIN
        // sessions only ever exist on the current connection (see the pairing-events comment
        // above, in loop()), but dismiss any prompt defensively for symmetry with the other
        // drop paths in case that invariant is ever relaxed.
        const bool pin_was_displayed = conn->pin_session().pin_displayed;
        const bool window_was_shown = conn->pin_session().window_shown;
        this->release_nursery_entry(it, goodbye);
        if (pin_was_displayed) {
            this->client_->note_clear_pin();
        }
        if (window_was_shown) {
            this->client_->note_close_pairing_window();
        }
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
        // Pairing connections receive pair/abort first (the reference dismissal for a displaced
        // pairing attempt); the subsequent goodbye from queue_deferred_release is a benign
        // over-send (no close-without-goodbye path exists in the current transport layer).
        if (conn->has_activity(SendspinActivity::PAIRING)) {
            conn->send_app_json(format_pair_abort_message(PairAbortReason::CONCURRENT_ATTEMPT),
                                nullptr);
        }
        // Leaving management: block stale network-thread dispatch during the goodbye window
        // (outgoing sends, including the goodbye itself, are unaffected).
        conn->disable_message_dispatch();
        this->queue_deferred_release(std::move(conn), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
        return next;
    }

    // Notify the client, publish state, and record playback activity, only for the winner.
    this->note_playback_activity(this->current_connection_.get());

    // ---- Pairing branch ----
    // If the winning activate declares only the PAIRING activity with a supported
    // selected_pair_method (pairing_psk or dynamic_pin), enter the pairing flow instead of the
    // normal operational path. The connection still occupies current_connection_ (so admission.h's
    // "in-flight pairing is not displaced" rule applies), but is not announced to the client
    // as operational until pairing finishes and the post-finalize re-handshake completes.
    const auto& activities = this->current_connection_->get_activities();
    const auto& selected_pair_method = this->current_connection_->get_selected_pair_method();
    const bool is_pairing_activity_only = activities.size() == 1 &&
                                          activities[0] == SendspinActivity::PAIRING &&
                                          selected_pair_method.has_value();

    if (is_pairing_activity_only &&
        selected_pair_method.value() == SendspinPairMethod::PAIRING_PSK) {
        SS_LOGI(TAG, "Pairing activate received (pairing_psk): entering pairing for server_id=%s",
                this->current_connection_->get_server_id().c_str());
        this->handle_enter_pairing(this->current_connection_.get());
    } else if (is_pairing_activity_only &&
               selected_pair_method.value() == SendspinPairMethod::DYNAMIC_PIN) {
        SS_LOGI(TAG,
                "Pairing activate received (dynamic_pin): entering dynamic-PIN pairing for "
                "server_id=%s",
                this->current_connection_->get_server_id().c_str());
        this->handle_enter_pairing(this->current_connection_.get());
    } else if (is_pairing_activity_only &&
               selected_pair_method.value() == SendspinPairMethod::STATIC_PIN) {
        SS_LOGI(TAG,
                "Pairing activate received (static_pin): entering static-PIN pairing for "
                "server_id=%s",
                this->current_connection_->get_server_id().c_str());
        this->handle_enter_pairing(this->current_connection_.get());
    } else {
        this->client_->on_handshake_complete(this->current_connection_.get());
    }

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

// ============================================================================
// Phase 5: Pairing main-loop handlers
// ============================================================================

void ConnectionManager::handle_enter_pairing(SendspinConnection* conn) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). conn is the connection that just won
    // promotion into current_connection_ with a pairing activate (see
    // promote_or_arbitrate_nursery_entry).
    if (conn == nullptr || this->client_->record_store_ == nullptr) {
        SS_LOGE(TAG, "handle_enter_pairing: no connection or record_store");
        return;
    }

    // Quiesce: suppress time sync and client/state while pairing is in progress.
    conn->set_pairing_in_progress(true);

    const std::string& server_id = conn->get_server_id();
    const auto& selected_method = conn->get_selected_pair_method();

    // ---- Phase 8b: Dynamic-PIN branch ----
    if (selected_method.has_value() && selected_method.value() == SendspinPairMethod::DYNAMIC_PIN) {
        RecordStore& store = *this->client_->record_store_;

        // Lockout check: if dynamic_pin is locked out, abort immediately.
        if (store.is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN)) {
            SS_LOGW(TAG, "handle_enter_pairing: dynamic_pin locked out for server_id=%s",
                    server_id.c_str());
            this->local_abort_pin_pairing(conn, PairAbortReason::LOCKED_OUT);
            return;
        }

        // Capture the Noise handshake hash now (main loop, before any further I/O). The
        // NoiseTransport session is network-thread-owned, but we are on the main loop and the
        // session was set before the first server/activate fired; no concurrent write
        // is possible at this point (no re-handshake is in progress). If the hash is
        // unavailable the PAKE SID and PIN derivation cannot be computed, so abort.
        auto hash_opt = conn->get_noise_handshake_hash();
        if (!hash_opt.has_value()) {
            SS_LOGE(TAG, "handle_enter_pairing: no handshake hash for server_id=%s; aborting",
                    server_id.c_str());
            this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            return;
        }

        auto& ps = conn->pin_session();
        ps.method = SendspinPairMethod::DYNAMIC_PIN;
        ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_INIT;
        ps.handshake_hash = hash_opt.value();
        ps.attempt_deadline_us = platform_time_us() + PIN_ATTEMPT_TIMEOUT_US;

        // Generate nonce_B and its commitment.
        ps.nonce_b = pin_generate_nonce();
        auto commit_b = pin_commit(ps.nonce_b.data(), ps.nonce_b.size());

        // Send client/pair-init with commit_B.
        SS_LOGI(TAG, "Sending client/pair-init (dynamic_pin) for server_id=%s", server_id.c_str());
        conn->send_app_json(format_client_pair_init_message(commit_b), nullptr);

        // Notify the listener.
        this->client_->note_pairing_started(server_id);
        return;
    }

    // ---- Phase 8c: Static-PIN branch ----
    // Unlike dynamic PIN, static PIN requires an operator pairing-window gesture before the
    // exchange starts: no client/pair-init is sent here. handle_pairing_window_confirmed() sends
    // it once the operator confirms (see D6c in the Phase 8c brief).
    if (selected_method.has_value() && selected_method.value() == SendspinPairMethod::STATIC_PIN) {
        RecordStore& store = *this->client_->record_store_;

        // Lockout check: if static_pin is locked out, abort immediately.
        if (store.is_pin_locked_out(SendspinPairMethod::STATIC_PIN)) {
            SS_LOGW(TAG, "handle_enter_pairing: static_pin locked out for server_id=%s",
                    server_id.c_str());
            this->local_abort_pin_pairing(conn, PairAbortReason::LOCKED_OUT);
            return;
        }

        // Defensive: the client should not have advertised static_pin without a configured PIN.
        if (!store.static_pin().has_value()) {
            SS_LOGE(TAG, "handle_enter_pairing: no static PIN configured for server_id=%s",
                    server_id.c_str());
            this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            return;
        }

        // Capture the Noise handshake hash now (see the dynamic-PIN branch above for why this is
        // safe on the main loop).
        auto hash_opt = conn->get_noise_handshake_hash();
        if (!hash_opt.has_value()) {
            SS_LOGE(TAG, "handle_enter_pairing: no handshake hash for server_id=%s; aborting",
                    server_id.c_str());
            this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            return;
        }

        auto& ps = conn->pin_session();
        ps.method = SendspinPairMethod::STATIC_PIN;
        ps.handshake_hash = hash_opt.value();
        // Capture the static PIN now, before the operator window wait, so a concurrent management
        // PIN change during the open window cannot swap the CPace secret mid-attempt. Mirrors the
        // reference capturing static_pin before awaiting pairing_window().
        ps.static_pin_value = store.static_pin().value();
        ps.step = SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW;
        // Reused as the pairing-window deadline: the existing PIN-attempt-timeout check in
        // loop() aborts any non-IDLE step whose attempt_deadline_us has passed, so this alone
        // enforces the 300 s window without a second timer.
        ps.attempt_deadline_us = platform_time_us() + WINDOW_LIFETIME_US;

        // Surface the pairing-window prompt to the operator; do not send anything yet.
        this->client_->note_open_pairing_window();
        ps.window_shown = true;

        this->client_->note_pairing_started(server_id);
        return;
    }

    // ---- Phase 5: Pairing-PSK branch (original) ----

    // resolve_pairing_outcome generates the long-term PSK and, if storage is available,
    // a paired record. Three outcomes:
    //   {psk, record=set}     -> normal: send finalize, hold record, store on ack.
    //   {psk, record=nullopt} -> storage exhausted: send finalize with shared PSK, store nothing.
    //   outer nullopt          -> error (no shared fallback): abort.
    auto outcome = this->client_->record_store_->resolve_pairing_outcome(server_id);
    if (!outcome.has_value()) {
        SS_LOGE(TAG,
                "handle_enter_pairing: resolve_pairing_outcome failed for server_id=%s; "
                "aborting pairing",
                server_id.c_str());
        // Send pair/abort(method_not_supported) - closest reason for "cannot proceed".
        // method_not_supported is used as the error path here because there is no distinct
        // "store unavailable" reason in the protocol.
        conn->send_app_json(format_pair_abort_message(PairAbortReason::METHOD_NOT_SUPPORTED),
                            nullptr);
        conn->clear_pairing_state();
        // Close the connection: pairing cannot proceed. drop_connection() handles both the
        // current-slot cleanup (cleanup_connection_state, which also resets the time burst) and
        // the deferred goodbye+release; flush_deferred_releases() runs at the end of the caller's
        // locked block.
        this->drop_connection(conn, SendspinGoodbyeReason::UNAUTHORIZED);
        return;
    }

    // Send client/pair-finalize with the long-term PSK (base64url-encoded, 43 chars).
    SS_LOGI(TAG, "Sending client/pair-finalize for server_id=%s (record=%s)", server_id.c_str(),
            outcome->record.has_value() ? "stored" : "shared-psk-fallback");
    conn->send_app_json(format_client_pair_finalize_message(outcome->psk), nullptr);

    // Hold the pending record: committed to the RecordStore by the network-thread
    // server/pair-finalize handler on ack. nullopt record = storage-exhausted case: store nothing.
    conn->set_pending_pairing_record(std::move(outcome->record));
}

void ConnectionManager::handle_pair_abort(SendspinConnection* conn, PairAbortReason reason) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). pair/abort received from the server
    // during pairing.
    if (conn == nullptr) {
        return;
    }

    SS_LOGW(TAG, "pair/abort received for server_id=%s reason=%s; closing connection",
            conn->get_server_id().c_str(), to_cstr(reason));

    // Capture the deferred-notification inputs BEFORE clear_pairing_state() resets the PIN session
    // and before the connection is released (server_id is copied so it survives the tear-down).
    const std::string server_id = conn->get_server_id();
    const bool pin_was_displayed = conn->pin_session().pin_displayed;
    const bool window_was_shown = conn->pin_session().window_shown;

    // Clean up pairing state and close the connection (see the drop_connection() note in
    // handle_enter_pairing). On the current-slot path drop_connection() ->
    // cleanup_connection_state() clears the pending notification vectors, so the note_* calls below
    // MUST come after this call.
    conn->clear_pairing_state();
    this->drop_connection(conn, SendspinGoodbyeReason::UNAUTHORIZED);

    // Queue listener notifications AFTER drop_connection() so they survive to be dispatched from
    // SendspinClient::loop() after conn_ptr_mutex_ is released. Only the queue push happens while
    // the lock is held.
    this->client_->note_pairing_failed(server_id, to_public_abort_reason(reason));
    if (pin_was_displayed) {
        this->client_->note_clear_pin();
    }
    if (window_was_shown) {
        this->client_->note_close_pairing_window();
    }
}

// ============================================================================
// Dynamic-PIN pairing main-loop handlers
// ============================================================================

void ConnectionManager::local_abort_pin_pairing(SendspinConnection* conn, PairAbortReason reason) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). Aborts the dynamic-PIN session
    // locally:
    //   1. Send pair/abort to the server.
    //   2. Clear PIN display / pairing state on the connection.
    //   3. Close the connection.
    //   4. Queue on_pairing_failed (and on_clear_pairing_pin, if a PIN was shown) for delivery
    //      from loop().
    if (conn == nullptr) {
        return;
    }

    SS_LOGW(TAG, "local_abort_pin_pairing: server_id=%s reason=%s", conn->get_server_id().c_str(),
            to_cstr(reason));

    // Capture the deferred-notification inputs BEFORE clear_pairing_state() resets the PIN session
    // and before the connection is released (server_id is copied so it survives the tear-down).
    const std::string server_id = conn->get_server_id();
    const bool pin_was_displayed = conn->pin_session().pin_displayed;
    const bool window_was_shown = conn->pin_session().window_shown;

    // Best-effort pair/abort to the server (the connection is still live here).
    conn->send_app_json(format_pair_abort_message(reason), nullptr);

    // drop_connection() -> cleanup_connection_state() clears the pending notification vectors on
    // the current-slot path, so the note_* calls below MUST come after this call.
    conn->clear_pairing_state();
    this->drop_connection(conn, SendspinGoodbyeReason::UNAUTHORIZED);

    this->client_->note_pairing_failed(server_id, to_public_abort_reason(reason));
    if (pin_was_displayed) {
        this->client_->note_clear_pin();
    }
    if (window_was_shown) {
        this->client_->note_close_pairing_window();
    }
}

// ============================================================================
// Phase 8c: Static-PIN pairing main-loop handlers
// ============================================================================

void ConnectionManager::handle_pairing_window_confirmed() {
    // Runs on the main loop. A PIN session only ever exists on current_connection_: pairing only
    // starts once a nursery entry has won promotion (see the pairing branch in
    // promote_or_arbitrate_nursery_entry()), so there is no separate "pending" slot to check in
    // this architecture. If nothing is awaiting the window, the confirm is spurious or arrived
    // late (e.g. after the window already timed out) -- log and return.
    if (this->client_->record_store_ == nullptr) {
        return;
    }

    auto awaiting_window = [](SendspinConnection* c) {
        return c != nullptr &&
               c->pin_session().step == SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW;
    };

    SendspinConnection* conn = nullptr;
    if (awaiting_window(this->current_connection_.get())) {
        conn = this->current_connection_.get();
    }

    if (conn == nullptr) {
        SS_LOGW(TAG, "handle_pairing_window_confirmed: no connection awaiting the pairing window; "
                     "ignoring (spurious or late confirm)");
        return;
    }

    const std::string& server_id = conn->get_server_id();

    auto& ps = conn->pin_session();
    // Use the static PIN captured at pairing start (see handle_enter_pairing), not a fresh store
    // read, so a mid-window PIN change cannot swap the CPace secret. Empty means it was never
    // captured (defensive; the enter-pairing path always captures a configured PIN).
    if (ps.static_pin_value.empty()) {
        SS_LOGE(TAG, "handle_pairing_window_confirmed: no static PIN captured for server_id=%s",
                server_id.c_str());
        this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // Send the empty client/pair-init (static PIN carries no commit_B; see D7).
    SS_LOGI(TAG, "Sending client/pair-init (static_pin) for server_id=%s", server_id.c_str());
    conn->send_app_json(format_client_pair_init_message(), nullptr);

    // Build SID = "sendspin-pair-pake-v1" (21 bytes) || 32-byte handshake hash, identical to the
    // dynamic-PIN PAIR_INIT case in handle_pin_pairing_message. PRS = the static PIN's ASCII
    // bytes (mirrors run_static_pin_client in aiosendspin/noise/pairing.py, ~lines 267-309).
    static constexpr char PAKE_SID_LABEL[] = "sendspin-pair-pake-v1";
    std::vector<uint8_t> sid;
    sid.insert(sid.end(), PAKE_SID_LABEL, PAKE_SID_LABEL + sizeof(PAKE_SID_LABEL) - 1);
    sid.insert(sid.end(), ps.handshake_hash.begin(), ps.handshake_hash.end());

    const std::string& pin_str = ps.static_pin_value;
    std::vector<uint8_t> prs(pin_str.begin(), pin_str.end());

    if (!ps.cpace.start(CPaceRole::RESPONDER, prs, sid, {}, {}, {})) {
        SS_LOGE(TAG, "handle_pairing_window_confirmed: CPace::start failed for server_id=%s",
                server_id.c_str());
        this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_AUTH;
    ps.attempt_deadline_us = platform_time_us() + PIN_ATTEMPT_TIMEOUT_US;
}

void ConnectionManager::handle_pin_pairing_message(SendspinConnection* conn,
                                                   const ServerPairingMessageEvent& event) {
    // Runs on the main loop. All CPace / nonce / hash state is main-loop-only.
    if (conn == nullptr || this->client_->record_store_ == nullptr) {
        return;
    }

    auto& ps = conn->pin_session();
    RecordStore& store = *this->client_->record_store_;
    const std::string& server_id = conn->get_server_id();

    switch (event.kind) {
        case PinPairingMessageKind::PAIR_INIT: {
            // Step 1: server/pair-init received. This is a DYNAMIC-PIN-only step; static PIN
            // never expects server/pair-init (see run_static_pin_client in the reference, which
            // goes straight from client/pair-init to server/pair-auth). A PAIR_INIT while
            // ps.method == STATIC_PIN is a protocol violation, handled by the same
            // wrong-step abort as an out-of-order message.
            if (ps.method != SendspinPairMethod::DYNAMIC_PIN ||
                ps.step != SendspinConnection::PinStep::AWAIT_SERVER_PAIR_INIT) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: PAIR_INIT in wrong step=%d method=%s for "
                        "server_id=%s",
                        static_cast<int>(ps.step), to_cstr(ps.method), server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
                return;
            }

            // Validate pin_length. PIN_MIN_DIGITS is the absolute protocol floor, applied even
            // if the configured minimum is somehow lower (mirrors the reference's clamp to 4-12).
            const int min_len = store.dynamic_pin_min_length();
            const int pin_len = event.pin_length;
            if (pin_len < min_len || pin_len < PIN_MIN_DIGITS || pin_len > PIN_MAX_DIGITS) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: pin_length=%d unacceptable (min=%d floor=%d "
                        "max=%d)",
                        pin_len, min_len, PIN_MIN_DIGITS, PIN_MAX_DIGITS);
                this->local_abort_pin_pairing(conn, PairAbortReason::PIN_LENGTH_UNACCEPTABLE);
                return;
            }
            ps.pin_length = pin_len;

            // Derive the PIN.
            auto pin_opt =
                pin_derive(ps.handshake_hash.data(), ps.handshake_hash.size(), event.nonce_a.data(),
                           event.nonce_a.size(), ps.nonce_b.data(), ps.nonce_b.size(), pin_len);
            if (!pin_opt.has_value()) {
                SS_LOGE(TAG, "handle_pin_pairing_message: pin_derive failed for server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            // Display the PIN to the user (deferred to loop() via note_display_pin). Record that
            // a PIN was displayed so the abort/cleanup paths know to clear it.
            this->client_->note_display_pin(pin_opt.value());
            ps.pin_displayed = true;

            // Start CPace RESPONDER.
            // PRS = PIN as UTF-8 bytes.
            // SID = "sendspin-pair-pake-v1" (21 bytes) || 32-byte handshake hash.
            static constexpr char PAKE_SID_LABEL[] = "sendspin-pair-pake-v1";
            std::vector<uint8_t> sid;
            sid.insert(sid.end(), PAKE_SID_LABEL, PAKE_SID_LABEL + sizeof(PAKE_SID_LABEL) - 1);
            sid.insert(sid.end(), ps.handshake_hash.begin(), ps.handshake_hash.end());

            const std::string& pin_str = pin_opt.value();
            std::vector<uint8_t> prs(pin_str.begin(), pin_str.end());

            if (!ps.cpace.start(CPaceRole::RESPONDER, prs, sid, {}, {}, {})) {
                SS_LOGE(TAG, "handle_pin_pairing_message: CPace::start failed for server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_AUTH;
            // No message sent yet: client waits for server/pair-auth.
            break;
        }

        case PinPairingMessageKind::PAIR_AUTH: {
            // Step 2: server/pair-auth received. Expect step AWAIT_SERVER_PAIR_AUTH.
            if (ps.step != SendspinConnection::PinStep::AWAIT_SERVER_PAIR_AUTH) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: PAIR_AUTH in wrong step=%d for server_id=%s",
                        static_cast<int>(ps.step), server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
                return;
            }

            // Send client/pair-auth (pake_msg_2 = client CPace share) BEFORE deriving.
            // This matches the reference: sends pake_msg_2 then calls _derive.
            const auto& client_share = ps.cpace.public_share();
            conn->send_app_json(format_client_pair_auth_message(client_share), nullptr);

            // Derive the MAC key from the server's share (pake_msg_1).
            // A derive failure means the peer share is a low-order point (a malformed or
            // hostile share), NOT a wrong PIN, so it does NOT count toward the lockout
            // counter -- the reference records a failure only on the confirm-tag mismatch below.
            if (!ps.cpace.derive(event.pake_msg_1.data(), event.pake_msg_1.size())) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: CPace::derive failed (low-order point) "
                        "for server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::PIN_MISMATCH);
                return;
            }

            ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_CONFIRM;
            break;
        }

        case PinPairingMessageKind::PAIR_CONFIRM: {
            // Step 3: server/pair-confirm received. Expect step AWAIT_SERVER_PAIR_CONFIRM.
            if (ps.step != SendspinConnection::PinStep::AWAIT_SERVER_PAIR_CONFIRM) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: PAIR_CONFIRM in wrong step=%d for "
                        "server_id=%s",
                        static_cast<int>(ps.step), server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
                return;
            }

            // Verify server_kc (server confirmation tag).
            if (!ps.cpace.verify(event.server_kc.data(), event.server_kc.size())) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: server_kc verification failed "
                        "(PIN mismatch) for server_id=%s",
                        server_id.c_str());
                store.record_pin_failure(ps.method);
                this->local_abort_pin_pairing(conn, PairAbortReason::PIN_MISMATCH);
                return;
            }

            // PIN matched: clear failure counter for this session's method.
            store.reset_pin_failures(ps.method);

            // Compute client_kc (our confirmation tag).
            auto client_kc_opt = ps.cpace.tag();
            if (!client_kc_opt.has_value()) {
                SS_LOGE(TAG, "handle_pin_pairing_message: CPace::tag() failed for server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            // Send client/pair-confirm: dynamic PIN carries client_kc + nonce_B, static PIN
            // carries client_kc only (no nonce opening; see run_static_pin_client vs
            // run_dynamic_pin_client in aiosendspin/noise/pairing.py).
            if (ps.method == SendspinPairMethod::STATIC_PIN) {
                conn->send_app_json(format_client_pair_confirm_message(client_kc_opt.value()),
                                    nullptr);
            } else {
                conn->send_app_json(
                    format_client_pair_confirm_message(client_kc_opt.value(), ps.nonce_b), nullptr);
            }

            // Clear PIN display now that we have confirmed the PIN. Only dynamic PIN displayed
            // one (ps.pin_displayed is never set for a static session), so this is a no-op there.
            if (ps.pin_displayed) {
                this->client_->note_clear_pin();
            }
            // Dismiss the pairing-window prompt now that the exchange succeeded. Only a static
            // session sets window_shown, so this is a no-op for dynamic PIN.
            if (ps.window_shown) {
                this->client_->note_close_pairing_window();
            }

            // Now run the same resolve_pairing_outcome path as pairing_psk, then send
            // client/pair-finalize. The server will respond with server/pair-finalize.
            auto outcome = store.resolve_pairing_outcome(server_id);
            if (!outcome.has_value()) {
                SS_LOGE(TAG,
                        "handle_pin_pairing_message: resolve_pairing_outcome failed for "
                        "server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            SS_LOGI(TAG, "Sending client/pair-finalize (%s) for server_id=%s (record=%s)",
                    to_cstr(ps.method), server_id.c_str(),
                    outcome->record.has_value() ? "stored" : "shared-psk-fallback");
            conn->send_app_json(format_client_pair_finalize_message(outcome->psk), nullptr);
            conn->set_pending_pairing_record(std::move(outcome->record));

            ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_FINALIZE;
            break;
        }

        case PinPairingMessageKind::MALFORMED: {
            // A server pairing message failed to parse. If a PIN session is active, abort it
            // (the reference closes the connection on a malformed pairing frame). If no session
            // is active, the frame is a stray protocol violation on a non-pairing connection;
            // drop it without tearing the connection down.
            if (ps.step == SendspinConnection::PinStep::IDLE) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: malformed pairing frame with no active PIN "
                        "session for server_id=%s; ignoring",
                        server_id.c_str());
                return;
            }
            SS_LOGW(TAG,
                    "handle_pin_pairing_message: malformed pairing frame during PIN pairing for "
                    "server_id=%s; aborting",
                    server_id.c_str());
            this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            break;
        }
    }
}

// ============================================================================
// Management main-loop handlers
// ============================================================================

void ConnectionManager::handle_management_request(SendspinConnection* conn,
                                                  const ManagementRequestEvent& event) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). conn is always current_connection_:
    // management/* is only ever admissible for a MANAGEMENT-activity session, which by
    // definition has already been promoted (see the admissibility check in loop()).
    if (conn == nullptr || this->client_->record_store_ == nullptr) {
        return;
    }

    RecordStore& store = *this->client_->record_store_;

    // Trust gating: MANAGEMENT activity is required.
    if (!conn->has_activity(SendspinActivity::MANAGEMENT)) {
        SS_LOGW(TAG,
                "management request without MANAGEMENT activity; replying permission_denied "
                "(server_id=%s)",
                conn->get_server_id().c_str());
        ManagementResultPayload result;
        result.result = ManagementResult::PERMISSION_DENIED;
        conn->send_app_json(format_management_result_message(result), nullptr);
        return;
    }

    ManagementResultPayload result;
    ManagementEffect effect = ManagementEffect::NONE;
    bool include_static_storage = false;

    switch (event.kind) {
        case ManagementRequestKind::LIST_RECORDS:
            include_static_storage = true;
            handle_list_records(store, result, effect);
            break;
        case ManagementRequestKind::ADD_RECORD:
            handle_add_record(store, event.add_payload, result, effect);
            break;
        case ManagementRequestKind::REMOVE_RECORD: {
            // requester_server_id: used to detect own-record removal.
            std::optional<std::string> requester_server_id;
            if (!conn->get_server_id().empty()) {
                requester_server_id = conn->get_server_id();
            }
            handle_remove_record(store, event.remove_payload, requester_server_id, result, effect);
            break;
        }
        case ManagementRequestKind::GET_PAIRING_CONFIG:
            include_static_storage = true;
            handle_get_pairing_config(store, result, effect);
            break;
        case ManagementRequestKind::SET_PAIRING_CONFIG:
            handle_set_pairing_config(store, event.set_config_payload, result, effect);
            break;
    }

    // Attach storage accounting when the store provides it.
    attach_storage_accounting(store, result, include_static_storage);

    // Send the result.
    conn->send_app_json(format_management_result_message(result), nullptr);

    // Apply the effect.
    if (effect == ManagementEffect::GOODBYE_UNAUTHORIZED) {
        SS_LOGI(TAG,
                "management/remove-record: requester removed its own record; disconnecting "
                "(server_id=%s)",
                conn->get_server_id().c_str());
        this->drop_connection(conn, SendspinGoodbyeReason::UNAUTHORIZED);
    }
}

void ConnectionManager::handle_server_unpair(SendspinConnection* conn,
                                             const ServerUnpairEvent& event) {
    // Runs on the main loop (caller holds conn_ptr_mutex_).
    if (conn == nullptr) {
        return;
    }

    // If the PSK category is not LONG_TERM, ignore (trust_level 'none': pairing /
    // unpaired handshake). Mirrors _handle_unpair in aiosendspin/client/connection.py.
    if (event.psk_category != PskCategory::LONG_TERM) {
        SS_LOGD(TAG, "server/unpair ignored (non-LONG_TERM category, server_id=%s)",
                conn->get_server_id().c_str());
        return;
    }

    SS_LOGI(TAG, "server/unpair: dropping record and disconnecting (server_id=%s, psk_id=%s)",
            conn->get_server_id().c_str(), event.matched_psk_id.c_str());

    // Remove the matched record (unless it is a shared-PSK record).
    if (this->client_->record_store_ != nullptr) {
        handle_unpair(*this->client_->record_store_, event.matched_psk_id);
    }

    // Disconnect with UNPAIRED reason.
    this->drop_connection(conn, SendspinGoodbyeReason::UNPAIRED);
}

}  // namespace sendspin
