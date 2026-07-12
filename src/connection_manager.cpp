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

#include "client_connection.h"
#include "connection.h"
#include "constants.h"
#include "platform/logging.h"
#include "platform/time.h"
#include "server_connection.h"
#include "time_burst.h"
#include "ws_server.h"

#include <array>
#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.conn_mgr";

static constexpr uint32_t FNV_OFFSET_BASIS = 2166136261UL;
static constexpr uint32_t FNV_PRIME = 16777619UL;
static constexpr int64_t HELLO_INITIAL_DELAY_MS = 100LL;
static constexpr int64_t HELLO_INITIAL_DELAY_US = HELLO_INITIAL_DELAY_MS * US_PER_MS;
static constexpr int64_t WS_SERVER_START_RETRY_MS = 5000LL;
static constexpr int64_t WS_SERVER_START_RETRY_US = WS_SERVER_START_RETRY_MS * US_PER_MS;

/// @brief Transport-establishment progress of a nursery connection, used for reap diagnostics
///
/// Derived on demand from the connection's proven flags rather than stored, so it can never go
/// stale. Inbound entries are WS_UP or later by construction (delivered only after their upgrade);
/// only an outbound connect_to() still awaiting DNS/TCP resolve can be TCP_OPEN.
enum class SetupStage : uint8_t { TCP_OPEN, WS_UP, HELLO_SENT, ESTABLISHED };

static SetupStage setup_stage(const SendspinConnection& conn) {
    if (conn.is_handshake_complete()) {
        return SetupStage::ESTABLISHED;
    }
    if (conn.has_client_hello_sent()) {
        return SetupStage::HELLO_SENT;
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
        case SetupStage::HELLO_SENT:
            return "HELLO_SENT";
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
    // Move everything out under the lock, destroy outside it: a connection destructor can join
    // its transport thread (see DeferredRelease), which must not happen while the lock is held.
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
        this->pending_connected_events_.push_back(c->shared_from_this());
    };
    client_conn->on_disconnected_cb = [this](SendspinConnection* conn) {
        // Defer to loop(); this callback runs on IXWebSocket's internal thread
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->pending_disconnect_events_.push_back(conn->shared_from_this());
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
        this->nursery_.push_back(NurseryEntry{client_conn, /*inbound=*/false});
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
            this->pending_disconnect_events_.push_back(std::move(conn));
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
        {
            std::lock_guard<std::mutex> lock(this->conn_mutex_);
            connected_events.swap(this->pending_connected_events_);
            disconnect_events.swap(this->pending_disconnect_events_);
        }

        {
            std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

            // Connection close/disconnect events (inbound ws_server closes on both platforms,
            // outbound host IXWebSocket disconnects). Keyed on connection identity, never on
            // sockfd: the OS recycles fds, so an fd-keyed event could outlive its connection and
            // mis-route to a newcomer admitted onto the recycled fd. A connection already
            // released by an earlier event is a no-op inside drop_connection.
            for (auto& conn : disconnect_events) {
                this->on_connection_lost(conn.get());
            }

            // Transport connected events: an outbound connection's WebSocket upgrade completed,
            // so arm its hello. (Inbound connections arrive already upgraded and armed theirs at
            // admission.) Guarded by nursery membership: a connection promoted or released by an
            // earlier event is skipped, and a duplicate event just re-arms the retry in place.
            for (auto& conn : connected_events) {
                if (this->find_in_nursery(conn.get()) != this->nursery_.end()) {
                    this->initiate_hello(conn.get());
                }
            }

            // Establishment: promote nursery connections whose hello handshake has completed.
            // Level-triggered on the connection's own proven flags (client_hello_sent_ from the
            // send completion, server_hello_received_ from server/hello processing, both set on
            // network threads) rather than edge-triggered on producer events, so the order the two
            // flags are set in is irrelevant: a nonconforming peer whose server/hello races ahead
            // of our client/hello is picked up on the tick after the send completes. A connection
            // leaves the nursery only here (handshake complete) or by being reaped, so the current
            // slot never holds a connection that has not proven itself.
            for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
                if (!it->conn->is_handshake_complete()) {
                    ++it;
                    continue;
                }
                auto conn = std::move(it->conn);
                it = this->nursery_.erase(it);
                this->remove_hello_retry(conn.get());

                if (this->current_connection_ == nullptr) {
                    this->current_connection_ = std::move(conn);
                } else if (this->should_switch_to_new_server(this->current_connection_.get(),
                                                             conn.get())) {
                    // Both sides of the comparison are established, so the PLAYBACK-reason and
                    // last-played-server preferences always ran on real data. No incumbent is
                    // ever evicted on timing alone.
                    SS_LOGI(TAG, "Handoff decision: switch to new server");
                    this->drop_connection(this->current_connection_.get(),
                                          SendspinGoodbyeReason::ANOTHER_SERVER);
                    this->current_connection_ = std::move(conn);
                } else {
                    SS_LOGI(TAG, "Handoff decision: keep current server");
                    // Leaving management: block stale network-thread dispatch during the goodbye
                    // window (outgoing sends, including the goodbye itself, are unaffected).
                    conn->disable_message_dispatch();
                    this->deferred_releases_.push_back(
                        {std::move(conn), SendspinGoodbyeReason::ANOTHER_SERVER});
                    continue;
                }

                // Notify the client and publish state, only for the winner and never for a
                // connection that is about to receive a goodbye.
                this->client_->on_handshake_complete(this->current_connection_.get());

                SS_LOGI(TAG, "Connection handshake complete: server_id=%s, connection_reason=%s",
                        this->current_connection_->get_server_id().c_str(),
                        to_cstr(this->current_connection_->get_connection_reason()));
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
    {
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

    // Check hello retry timers (one entry per managed connection, so a second connection arriving
    // mid-handshake cannot clobber the first connection's pending hello).
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        const int64_t now_us = platform_time_us();
        for (auto it = this->hello_retries_.begin(); it != this->hello_retries_.end();) {
            HelloRetryState& retry = *it;

            // Drop retries whose connection has left the nursery. A retry entry is live only for
            // nursery members: the current connection is established by construction and never
            // awaits a hello.
            if (this->find_in_nursery(retry.conn.get()) == this->nursery_.end()) {
                it = this->hello_retries_.erase(it);
                continue;
            }

            if (retry.retry_time_us == 0 || now_us < retry.retry_time_us) {
                ++it;
                continue;
            }

            if (this->send_hello_message(retry.attempts - 1, retry.conn.get())) {
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
            } else {
                it = this->hello_retries_.erase(it);
            }
        }
    }

    // Nursery tick: reap connections that miss the establish deadline. This is the only release
    // path for peers that connect and then stall without completing the hello, and for outbound
    // sockets whose transport never delivers a close (host IXWebSocket, issue #75). Hello arming
    // is event-driven (admission for inbound, connected event for outbound), so the tick only
    // ever reaps.
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        const int64_t now_us = platform_time_us();
        for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
            NurseryEntry& entry = *it;
            if (now_us - entry.conn->get_provisional_time_us() >= NURSERY_ESTABLISH_TIMEOUT_US) {
                SS_LOGW(TAG, "Nursery connection stalled at %s (>%d s), dropping",
                        to_cstr(setup_stage(*entry.conn)),
                        static_cast<int>(NURSERY_ESTABLISH_TIMEOUT_US / US_PER_SECOND));
                it = this->release_nursery_entry(it, SendspinGoodbyeReason::ANOTHER_SERVER);
                continue;
            }
            ++it;
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
           this->current_connection_->is_handshake_complete();
}

// ============================================================================
// Handoff support
// ============================================================================

void ConnectionManager::set_last_played_server_hash(uint32_t hash) {
    this->last_played_server_hash_ = hash;
    this->has_last_played_server_ = true;
}

uint32_t ConnectionManager::fnv1_hash(const char* str) {
    uint32_t hash = FNV_OFFSET_BASIS;
    while (*str != '\0') {
        hash *= FNV_PRIME;
        hash ^= static_cast<uint8_t>(*str++);
    }
    return hash;
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
            this->deferred_releases_.push_back(
                {std::move(conn), SendspinGoodbyeReason::ANOTHER_SERVER});
        } else {
            SS_LOGD(TAG, "Admitting new connection into the nursery");
            // Arm the hello right away: the connection arrives WS-upgraded, so there is no
            // earlier signal to wait for. (Outbound connections instead arm theirs when the
            // transport's connected event is processed in loop().)
            this->initiate_hello(conn.get());
            this->nursery_.push_back(NurseryEntry{std::move(conn), /*inbound=*/true});
        }
    }
    this->flush_deferred_releases();
}

// ============================================================================
// Hello handshake
// ============================================================================

void ConnectionManager::initiate_hello(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    // Arm a per-connection hello retry: initial delay, 3 attempts. If an entry for this connection
    // already exists (a duplicate connected event for the same connection would land here twice),
    // re-arm it in place instead of pushing a second one, so a connection never gets two timers.
    auto conn_sp = conn->shared_from_this();
    const int64_t retry_time_us = platform_time_us() + HELLO_INITIAL_DELAY_US;

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
}

bool ConnectionManager::send_hello_message(uint8_t remaining_attempts, SendspinConnection* conn) {
    // Verify the connection is still awaiting establishment (hellos are only ever sent to nursery
    // members; the current connection is established by construction).
    if (this->find_in_nursery(conn) == this->nursery_.end()) {
        SS_LOGW(TAG, "Connection no longer valid for hello message");
        return true;
    }

    if (conn == nullptr || !conn->is_connected()) {
        SS_LOGW(TAG, "Cannot send hello - not connected");
        return true;
    }

    std::string hello_message = this->client_->build_hello_message();

    SsErr err = conn->send_text_message(
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

std::vector<NurseryEntry>::iterator ConnectionManager::release_nursery_entry(
    std::vector<NurseryEntry>::iterator it, std::optional<SendspinGoodbyeReason> reason) {
    // Note: caller must hold conn_ptr_mutex_ and flush_deferred_releases() after dropping it
    auto conn = std::move(it->conn);
    auto next = this->nursery_.erase(it);
    // Leaving management: block stale network-thread dispatch into role/state queues during the
    // goodbye window. Outgoing sends, including the goodbye itself, are unaffected.
    conn->disable_message_dispatch();
    this->remove_hello_retry(conn.get());
    this->deferred_releases_.push_back({std::move(conn), reason});
    return next;
}

void ConnectionManager::flush_deferred_releases() {
    // Note: caller must NOT hold conn_ptr_mutex_ (see DeferredRelease)
    std::vector<DeferredRelease> releases;
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        releases.swap(this->deferred_releases_);
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
        // std::exchange (not std::move) so the slot is never left in a moved-from state the
        // static analyzer flags when a later event in the same loop() pass reads it.
        this->deferred_releases_.push_back(
            {std::exchange(this->current_connection_, nullptr), goodbye});
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
    auto new_reason = new_conn->get_connection_reason();
    auto current_reason = current->get_connection_reason();

    // New server wants playback -> switch to new
    if (new_reason == SendspinConnectionReason::PLAYBACK) {
        SS_LOGD(TAG, "New server has playback reason, switching");
        return true;
    }

    // New is discovery, current had playback -> keep current
    if (new_reason == SendspinConnectionReason::DISCOVERY &&
        current_reason == SendspinConnectionReason::PLAYBACK) {
        SS_LOGD(TAG, "New is discovery, current had playback, keeping current");
        return false;
    }

    // Both discovery -> prefer last played server
    if (this->has_last_played_server_) {
        if (fnv1_hash(new_conn->get_server_id().c_str()) == this->last_played_server_hash_) {
            SS_LOGD(TAG, "New server matches last played server, switching");
            return true;
        }
        if (fnv1_hash(current->get_server_id().c_str()) == this->last_played_server_hash_) {
            SS_LOGD(TAG, "Current server matches last played server, keeping");
            return false;
        }
    }

    SS_LOGD(TAG, "Default handoff decision: keep existing");
    return false;
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
