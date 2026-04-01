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
#include "platform/logging.h"
#include "platform/time.h"
#include "server_connection.h"
#include "time_burst.h"
#include "ws_server.h"

namespace sendspin {

static const char* const TAG = "sendspin.conn_mgr";

static constexpr uint32_t FNV_OFFSET_BASIS = 2166136261UL;
static constexpr uint32_t FNV_PRIME = 16777619UL;
static constexpr int64_t US_PER_MS = 1000LL;
static constexpr int64_t HELLO_INITIAL_DELAY_MS = 100LL;
static constexpr int64_t HELLO_INITIAL_DELAY_US = HELLO_INITIAL_DELAY_MS * US_PER_MS;

// ============================================================================
// Constructor / Destructor
// ============================================================================

ConnectionManager::ConnectionManager(SendspinClient* client) : client_(client) {}

ConnectionManager::~ConnectionManager() {
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        this->current_connection_.reset();
        this->pending_connection_.reset();
    }
    this->hello_retry_.conn.reset();
    this->dying_connection_.reset();
}

// ============================================================================
// Public API
// ============================================================================

void ConnectionManager::connect_to(const std::string& url) {
    SS_LOGI(TAG, "Initiating client connection to: %s", url.c_str());

    auto client_conn = std::make_unique<SendspinClientConnection>(url);
    client_conn->set_auto_reconnect(false);
    client_conn->set_task_config(this->client_->config_.websocket_priority);

    this->setup_connection_callbacks(client_conn.get());
    client_conn->on_disconnected_cb = [this](SendspinConnection* conn) {
        // Defer to loop(); this callback runs on IXWebSocket's internal thread
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->pending_disconnect_events_.push_back(conn->shared_from_this());
    };

    client_conn->init_time_filter();

    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
            SS_LOGD(TAG, "Existing connection active, new connection will go through handoff");
            this->pending_connection_ = std::move(client_conn);
            this->pending_connection_->start();
        } else {
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
    this->ws_server_->set_max_connections(this->client_->config_.server_max_connections);
    this->ws_server_->set_ctrl_port(this->client_->config_.httpd_ctrl_port);

    this->ws_server_->set_new_connection_callback(
        [this](std::unique_ptr<SendspinServerConnection> conn) {
            this->on_new_connection(std::move(conn));
        });

    this->ws_server_->set_connection_closed_callback([this](int sockfd) {
        SS_LOGD(TAG, "Connection closed callback for socket %d", sockfd);
        // Defer the actual cleanup to loop() to avoid use-after-free.
        // This callback runs in the httpd thread, but there may be pending httpd_queue_work items
        // (e.g., async_send_text) with raw pointers to the connection object. If we destroy the
        // connection here, those pending work items would dereference freed memory when processed.
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->pending_close_events_.push_back(sockfd);
    });

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
            // Deliberately excludes dying_connection_; it has already been through cleanup and its
            // message dispatch is disabled. Returning it here would let httpd route stale messages
            // from the old connection into freshly-reset role queues.
            return nullptr;
        });
}

void ConnectionManager::loop() {
    // Start WS server when network becomes ready
    if (this->ws_server_ != nullptr && !this->ws_server_->is_started()) {
        if (this->client_->network_provider_ &&
            this->client_->network_provider_->is_network_ready()) {
            this->ws_server_->start(this->client_, this->client_->config_.httpd_psram_stack,
                                    this->client_->config_.httpd_priority);
        }
    }

    // Process deferred connection lifecycle events
    {
        std::vector<int> close_events;
        std::vector<std::shared_ptr<SendspinConnection>> connected_events;
        std::vector<std::shared_ptr<SendspinConnection>> disconnect_events;
        std::vector<ServerHelloEvent> hello_events;
        bool release_dying = false;
        {
            std::lock_guard<std::mutex> lock(this->conn_mutex_);
            close_events.swap(this->pending_close_events_);
            connected_events.swap(this->pending_connected_events_);
            disconnect_events.swap(this->pending_disconnect_events_);
            hello_events.swap(this->pending_hello_events_);
            release_dying = this->dying_connection_ready_to_release_;
            this->dying_connection_ready_to_release_ = false;
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

        if (release_dying) {
            this->dying_connection_.reset();
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

    // Check hello retry timer
    if (this->hello_retry_.retry_time_us > 0 &&
        platform_time_us() >= this->hello_retry_.retry_time_us) {
        this->hello_retry_.retry_time_us = 0;

        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        // Verify connection is still valid
        if (this->hello_retry_.conn == this->current_connection_ ||
            this->hello_retry_.conn == this->pending_connection_) {
            if (!this->send_hello_message(this->hello_retry_.attempts - 1,
                                          this->hello_retry_.conn.get())) {
                // Transient failure - retry with exponential backoff
                if (this->hello_retry_.attempts > 1) {
                    this->hello_retry_.delay_ms *= 2;
                    this->hello_retry_.attempts--;
                    this->hello_retry_.retry_time_us =
                        platform_time_us() +
                        static_cast<int64_t>(this->hello_retry_.delay_ms) * US_PER_MS;
                }
            }
        } else {
            this->hello_retry_.conn.reset();
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
    conn->on_json_message_cb = [this](SendspinConnection* c, const std::string& message,
                                      int64_t timestamp) {
        this->client_->process_json_message(c, message, timestamp);
    };
    conn->on_binary_message_cb = [this](SendspinConnection* /*c*/, uint8_t* payload, size_t len) {
        this->client_->process_binary_message(payload, len);
    };
    conn->on_handshake_complete_cb = [](SendspinConnection* /*c*/) {
        // Handshake completion is handled via deferred hello events in loop()
    };
}

void ConnectionManager::on_new_connection(std::unique_ptr<SendspinServerConnection> conn) {
    // Called from httpd open_callback thread. Connection pointer assignment must happen inline
    // because the httpd find_connection_callback needs to locate this connection immediately
    // for subsequent message routing on the same thread.
    conn->init_time_filter();

    this->setup_connection_callbacks(conn.get());
    conn->on_disconnected_cb = [](SendspinConnection* /*c*/) {
        // Cleanup happens in on_connection_lost triggered by the server
    };

    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    if (this->current_connection_ == nullptr) {
        SS_LOGD(TAG, "No existing connection, accepting as current");
        this->current_connection_ = std::move(conn);
    } else {
        SS_LOGD(TAG, "Existing connection present, setting as pending for handoff");
        if (this->pending_connection_ != nullptr) {
            SS_LOGW(TAG, "Already have pending connection, rejecting new connection");
            this->disconnect_and_release(std::shared_ptr<SendspinConnection>(std::move(conn)),
                                         SendspinGoodbyeReason::ANOTHER_SERVER);
            return;
        }
        this->pending_connection_ = std::move(conn);
    }
}

// ============================================================================
// Hello handshake
// ============================================================================

void ConnectionManager::initiate_hello(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    // Set up retry state: initial delay, 3 attempts
    this->hello_retry_.conn = conn->shared_from_this();
    this->hello_retry_.delay_ms = HelloRetryState::INITIAL_RETRY_DELAY_MS;
    this->hello_retry_.attempts = 3;
    this->hello_retry_.retry_time_us = platform_time_us() + HELLO_INITIAL_DELAY_US;
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

    SsErr err =
        conn->send_text_message(hello_message, [conn](bool success, int64_t actual_send_time) {
            if (success) {
                conn->set_client_hello_sent(true);
                conn->set_last_sent_time_message(actual_send_time);
            } else {
                SS_LOGW(TAG, "Hello message send failed");
            }
        });

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
    if (conn == nullptr) {
        return;
    }

    if (this->current_connection_ != nullptr && this->current_connection_.get() == conn) {
        SS_LOGI(TAG, "Current connection lost");
        conn->disable_message_dispatch();
        this->client_->time_burst_->reset();
        this->client_->cleanup_connection_state();
        if (this->hello_retry_.conn.get() == conn) {
            this->hello_retry_.conn.reset();
            this->hello_retry_.retry_time_us = 0;
        }
        this->current_connection_.reset();

        if (this->pending_connection_ != nullptr) {
            SS_LOGD(TAG, "Promoting pending connection to current");
            this->current_connection_ = std::move(this->pending_connection_);
        }
    } else if (this->pending_connection_ != nullptr && this->pending_connection_.get() == conn) {
        SS_LOGD(TAG, "Pending connection lost");
        if (this->hello_retry_.conn.get() == conn) {
            this->hello_retry_.conn.reset();
            this->hello_retry_.retry_time_us = 0;
        }
        this->pending_connection_.reset();
    }
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
            this->current_connection_->disable_message_dispatch();
            this->client_->time_burst_->reset();
            this->client_->cleanup_connection_state();
            auto old_current = std::move(this->current_connection_);
            this->current_connection_ = std::move(this->pending_connection_);
            this->disconnect_and_release(std::move(old_current),
                                         SendspinGoodbyeReason::ANOTHER_SERVER);
        } else {
            this->current_connection_ = std::move(this->pending_connection_);
        }
    } else {
        SS_LOGD(TAG, "Completing handoff: keeping current server");
        if (this->pending_connection_ != nullptr) {
            this->disconnect_and_release(std::move(this->pending_connection_),
                                         SendspinGoodbyeReason::ANOTHER_SERVER);
        }
    }
}

void ConnectionManager::disconnect_and_release(std::shared_ptr<SendspinConnection> conn,
                                               SendspinGoodbyeReason reason) {
    this->dying_connection_ = std::move(conn);
    this->dying_connection_->disconnect(reason, [this]() {
        // Defer the actual destruction to loop() to avoid use-after-free.
        // This callback runs in the httpd worker thread (async_send_text), but the connection
        // must stay alive until all pending httpd_queue_work items have been processed.
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->dying_connection_ready_to_release_ = true;
    });
}

}  // namespace sendspin
