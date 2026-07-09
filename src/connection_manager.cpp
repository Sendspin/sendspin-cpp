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

#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.conn_mgr";

static constexpr uint32_t FNV_OFFSET_BASIS = 2166136261UL;
static constexpr uint32_t FNV_PRIME = 16777619UL;
static constexpr int64_t HELLO_INITIAL_DELAY_MS = 100LL;
static constexpr int64_t HELLO_INITIAL_DELAY_US = HELLO_INITIAL_DELAY_MS * US_PER_MS;
static constexpr int64_t WS_SERVER_START_RETRY_MS = 5000LL;
static constexpr int64_t WS_SERVER_START_RETRY_US = WS_SERVER_START_RETRY_MS * US_PER_MS;

// ============================================================================
// Constructor / Destructor
// ============================================================================

ConnectionManager::ConnectionManager(SendspinClient* client) : client_(client) {}

ConnectionManager::~ConnectionManager() {
    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    this->current_connection_.reset();
    this->pending_connection_.reset();
    // Clear under the same lock that guards every other access to hello_retries_, keeping the
    // locking discipline uniform.
    this->hello_retries_.clear();
}

// ============================================================================
// Public API
// ============================================================================

void ConnectionManager::connect_to(const std::string& url) {
    SS_LOGI(TAG, "Initiating client connection to: %s", url.c_str());

    auto client_conn = std::make_unique<SendspinClientConnection>(url);
    client_conn->set_auto_reconnect(false);
    client_conn->set_task_config(this->client_->config_.websocket_priority);
    client_conn->set_websocket_payload_location(this->client_->config_.websocket_payload_location);

    this->setup_connection_callbacks(client_conn.get());
    client_conn->on_disconnected_cb = [this](SendspinConnection* conn) {
        // Defer to loop(); this callback runs on IXWebSocket's internal thread
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->pending_disconnect_events_.push_back(conn->shared_from_this());
    };

    client_conn->init_time_filter();

    // Start the provisional-timeout window: loop() reaps the connection if the hello handshake
    // has not completed within PROVISIONAL_CONNECTION_TIMEOUT_US.
    client_conn->set_provisional_time_us(platform_time_us());

    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
            SS_LOGD(TAG, "Existing connection active, new connection will go through handoff");
            // Release any existing pending connection (e.g. an inbound handoff candidate) before
            // overwriting the slot, mirroring on_new_connection and complete_handoff; otherwise it
            // is dropped with no goodbye and, on ESP, leaves its httpd session pinned.
            if (this->pending_connection_ != nullptr) {
                this->remove_hello_retry(this->pending_connection_.get());
                this->disconnect_and_release(std::move(this->pending_connection_),
                                             SendspinGoodbyeReason::ANOTHER_SERVER);
            }
            this->pending_connection_ = std::move(client_conn);
            this->pending_connection_->start();
        } else {
            // A present-but-disconnected current connection (its close event not yet processed) is
            // being replaced. Tear its state down as on_connection_lost would, instead of
            // overwriting the slot and orphaning dispatch/time-filter/client state and its retry.
            if (this->current_connection_ != nullptr) {
                this->current_connection_->disable_message_dispatch();
                this->client_->time_burst_->reset();
                this->client_->cleanup_connection_state();
                this->remove_hello_retry(this->current_connection_.get());
                this->current_connection_.reset();
            }
            this->current_connection_ = std::move(client_conn);
            this->current_connection_->start();
        }
    }
}

void ConnectionManager::disconnect(SendspinGoodbyeReason reason) {
    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
        this->current_connection_->disconnect(reason, nullptr);
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

    this->ws_server_->set_new_connection_callback(
        [this](std::shared_ptr<SendspinServerConnection> conn) {
            this->on_new_connection(std::move(conn));
        });

    this->ws_server_->set_connection_closed_callback([this](int sockfd) {
        SS_LOGD(TAG, "Connection closed callback for socket %d", sockfd);
        // Defer the actual cleanup to loop() so on_connection_lost runs on the main thread
        // alongside the rest of the connection state mutations.
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->pending_close_events_.push_back(sockfd);
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
            if (this->pending_connection_ != nullptr &&
                this->pending_connection_->get_sockfd() == sockfd) {
                return this->pending_connection_;
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
        std::vector<int> close_events;
        std::vector<std::shared_ptr<SendspinConnection>> connected_events;
        std::vector<std::shared_ptr<SendspinConnection>> disconnect_events;
        std::vector<ServerHelloEvent> hello_events;
        {
            std::lock_guard<std::mutex> lock(this->conn_mutex_);
            close_events.swap(this->pending_close_events_);
            connected_events.swap(this->pending_connected_events_);
            disconnect_events.swap(this->pending_disconnect_events_);
            hello_events.swap(this->pending_hello_events_);
        }

        {
            std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

            // Server connection close events (ESP httpd)
            for (int sockfd : close_events) {
                if (this->current_connection_ != nullptr &&
                    this->current_connection_->get_sockfd() == sockfd) {
                    SendspinConnection* conn = this->current_connection_.get();
                    this->on_connection_lost(conn);
                } else if (this->pending_connection_ != nullptr &&
                           this->pending_connection_->get_sockfd() == sockfd) {
                    SendspinConnection* conn = this->pending_connection_.get();
                    this->on_connection_lost(conn);
                }
            }

            // Client connection disconnect events (host IXWebSocket)
            for (auto& conn : disconnect_events) {
                this->on_connection_lost(conn.get());
            }

            // Process deferred connected events (initiate hello on main thread)
            for (auto& conn : connected_events) {
                if (conn == this->current_connection_ || conn == this->pending_connection_) {
                    this->initiate_hello(conn.get());
                }
            }

            // Server hello events: handshake completion and handoff
            for (auto& event : hello_events) {
                // Verify the connection is still one we manage (and not null)
                if (!event.conn || (event.conn != this->current_connection_ &&
                                    event.conn != this->pending_connection_)) {
                    continue;
                }

                // Notify client and publish state
                this->client_->on_handshake_complete(event.conn.get());

                SS_LOGI(TAG, "Connection handshake complete: server_id=%s, connection_reason=%s",
                        event.conn->get_server_id().c_str(),
                        to_cstr(event.conn->get_connection_reason()));

                // Handle handoff if pending connection completed its handshake
                if (this->pending_connection_ != nullptr &&
                    this->pending_connection_ == event.conn) {
                    bool should_switch = this->should_switch_to_new_server(
                        this->current_connection_.get(), event.conn.get());
                    SS_LOGI(TAG, "Handoff decision: %s",
                            should_switch ? "switch to new" : "keep current");
                    this->complete_handoff(should_switch);
                }
            }
        }
    }

    // Call loop on active connections using shared_ptr copies to avoid holding the lock
    std::shared_ptr<SendspinConnection> current_copy;
    std::shared_ptr<SendspinConnection> pending_copy;
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        current_copy = this->current_connection_;
        pending_copy = this->pending_connection_;
    }
    if (current_copy) {
        current_copy->loop();
    }
    if (pending_copy) {
        pending_copy->loop();
    }

    // Check hello retry timers (one entry per managed connection, so a second connection arriving
    // mid-handshake cannot clobber the first connection's pending hello).
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        const int64_t now_us = platform_time_us();
        for (auto it = this->hello_retries_.begin(); it != this->hello_retries_.end();) {
            HelloRetryState& retry = *it;

            // Drop retries whose connection is no longer managed.
            if (retry.conn != this->current_connection_ &&
                retry.conn != this->pending_connection_) {
                it = this->hello_retries_.erase(it);
                continue;
            }

            if (retry.retry_time_us == 0 || now_us < retry.retry_time_us) {
                ++it;
                continue;
            }

            if (this->send_hello_message(retry.attempts - 1, retry.conn.get())) {
                // Sent successfully (or connection no longer valid) - retry is complete.
                it = this->hello_retries_.erase(it);
                continue;
            }

            // Transient failure - retry with exponential backoff until attempts are exhausted.
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

    // Provisional-connection timeout: drop any managed connection that has not completed the
    // hello handshake within PROVISIONAL_CONNECTION_TIMEOUT_US. This is the only release path
    // for connections whose socket died before the WebSocket session was established (the host
    // transport never delivers a close for those, issue #75) and for peers that connect and then
    // stall without completing the hello (both platforms).
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        const int64_t now_us = platform_time_us();
        auto handshake_expired = [now_us](const std::shared_ptr<SendspinConnection>& conn) {
            if (conn == nullptr || conn->is_handshake_complete()) {
                return false;
            }
            const int64_t prov_time = conn->get_provisional_time_us();
            return prov_time != 0 && (now_us - prov_time) >= PROVISIONAL_CONNECTION_TIMEOUT_US;
        };
        if (handshake_expired(this->pending_connection_)) {
            SS_LOGW(TAG, "Pending connection timed out (>%d s without completing hello), dropping",
                    static_cast<int>(PROVISIONAL_CONNECTION_TIMEOUT_S));
            this->drop_connection(this->pending_connection_.get(),
                                  SendspinGoodbyeReason::ANOTHER_SERVER);
        }
        if (handshake_expired(this->current_connection_)) {
            SS_LOGW(TAG, "Current connection timed out (>%d s without completing hello), dropping",
                    static_cast<int>(PROVISIONAL_CONNECTION_TIMEOUT_S));
            this->drop_connection(this->current_connection_.get(),
                                  SendspinGoodbyeReason::ANOTHER_SERVER);
        }
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
// Event queuing (thread-safe)
// ============================================================================

void ConnectionManager::schedule_hello(ServerHelloEvent event) {
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->pending_hello_events_.push_back(std::move(event));
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
    conn->on_connected_cb = [this](SendspinConnection* c) {
        // Defer to loop(); this callback runs on the network thread
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->pending_connected_events_.push_back(c->shared_from_this());
    };
    conn->on_json_message_cb = [this](SendspinConnection* c, const char* data, size_t len,
                                      int64_t timestamp) {
        this->client_->process_json_message(c, data, len, timestamp);
    };
    conn->on_binary_message_cb = [this](SendspinConnection* /*c*/, uint8_t* payload, size_t len) {
        this->client_->process_binary_message(payload, len);
    };
    conn->on_handshake_complete_cb = [](SendspinConnection* /*c*/) {
        // Handshake completion is handled via deferred hello events in loop()
    };
}

void ConnectionManager::on_new_connection(std::shared_ptr<SendspinServerConnection> conn) {
    // Called from the platform's new-connection callback (ESP: httpd open_callback). The
    // authoritative owner is the platform's session/transport context; this observer shared_ptr
    // can be reset at any time without freeing the conn out from under in-flight workers.
    conn->init_time_filter();
    conn->set_websocket_payload_location(this->client_->config_.websocket_payload_location);

    this->setup_connection_callbacks(conn.get());
    conn->on_disconnected_cb = [](SendspinConnection* /*c*/) {
        // Cleanup happens in on_connection_lost triggered by the server
    };

    // Start the provisional-timeout window: loop() reaps the connection if the hello handshake
    // has not completed within PROVISIONAL_CONNECTION_TIMEOUT_US. This is the release path for
    // sockets that die before the WebSocket session is established: the host transport delivers
    // no close for those, so without the timeout they would hold a slot forever (issue #75).
    conn->set_provisional_time_us(platform_time_us());

    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    SendspinConnection* accepted_conn = nullptr;
    if (this->current_connection_ == nullptr) {
        SS_LOGD(TAG, "No existing connection, accepting as current");
        this->current_connection_ = std::move(conn);
        accepted_conn = this->current_connection_.get();
    } else {
        SS_LOGD(TAG, "Existing connection present, setting as pending for handoff");
        if (this->pending_connection_ != nullptr) {
            SS_LOGW(TAG, "Already have pending connection, rejecting new connection");
            this->disconnect_and_release(std::move(conn), SendspinGoodbyeReason::ANOTHER_SERVER);
            return;
        }
        this->pending_connection_ = std::move(conn);
        accepted_conn = this->pending_connection_.get();
    }

    // Some ESP-IDF/httpd versions complete the WebSocket upgrade without dispatching the initial
    // HTTP_GET request to websocket_handler(). Arm the hello retry from the accept path as well so
    // server-initiated connections always receive client/hello. If the GET callback arrives later,
    // initiate_hello() only re-arms the existing per-connection retry entry.
    if (accepted_conn != nullptr) {
        this->initiate_hello(accepted_conn);
    }
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
    // Verify the connection is still one of our managed connections
    if (conn != this->current_connection_.get() && conn != this->pending_connection_.get()) {
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
            if (success) {
                conn->set_client_hello_sent(true);
            } else {
                SS_LOGW(TAG, "Hello message send failed");
            }
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

void ConnectionManager::on_connection_lost(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_ (reads the slots and calls drop_connection)
    if (conn == nullptr) {
        return;
    }

    if (conn == this->current_connection_.get()) {
        SS_LOGI(TAG, "Current connection lost");
    } else if (conn == this->pending_connection_.get()) {
        SS_LOGD(TAG, "Pending connection lost");
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
        // Dropping the admitted connection: block stale network-thread events, quiesce the
        // client's per-connection state, and promote the pending connection if one exists.
        conn->disable_message_dispatch();
        this->client_->time_burst_->reset();
        this->client_->cleanup_connection_state();
        // std::exchange (not std::move) so the slots are never left in a moved-from state the
        // static analyzer flags when a later event in the same loop() pass reads them.
        auto conn_to_drop = std::exchange(this->current_connection_, nullptr);
        if (this->pending_connection_ != nullptr) {
            SS_LOGD(TAG, "Promoting pending connection to current");
            this->current_connection_ = std::exchange(this->pending_connection_, nullptr);
        }
        if (goodbye.has_value()) {
            this->disconnect_and_release(std::move(conn_to_drop), goodbye.value());
        }
        // Without a goodbye (connection already lost), conn_to_drop releases here.
    } else if (conn == this->pending_connection_.get()) {
        // Dropping a pending connection: no client-state cleanup (it was never promoted).
        auto conn_to_drop = std::exchange(this->pending_connection_, nullptr);
        if (goodbye.has_value()) {
            this->disconnect_and_release(std::move(conn_to_drop), goodbye.value());
        }
    }
    // Not a managed connection: nothing to do (already released by an earlier event this tick).
}

bool ConnectionManager::should_switch_to_new_server(SendspinConnection* current,
                                                    SendspinConnection* new_conn) const {
    if (current == nullptr || new_conn == nullptr) {
        return new_conn != nullptr;
    }

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

void ConnectionManager::complete_handoff(bool switch_to_new) {
    // Note: caller must hold conn_ptr_mutex_
    if (switch_to_new) {
        SS_LOGD(TAG, "Completing handoff: switching to new server");
        if (this->current_connection_ != nullptr) {
            // drop_connection tears down the displaced current connection (with goodbye) and
            // promotes the pending connection into the current slot.
            this->drop_connection(this->current_connection_.get(),
                                  SendspinGoodbyeReason::ANOTHER_SERVER);
        } else {
            this->current_connection_ = std::exchange(this->pending_connection_, nullptr);
        }
    } else {
        SS_LOGD(TAG, "Completing handoff: keeping current server");
        if (this->pending_connection_ != nullptr) {
            this->drop_connection(this->pending_connection_.get(),
                                  SendspinGoodbyeReason::ANOTHER_SERVER);
        }
    }
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
