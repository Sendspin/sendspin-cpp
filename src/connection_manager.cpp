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

// --- Constructor / Destructor ---

ConnectionManager::ConnectionManager(SendspinClient* client) : client_(client) {}

ConnectionManager::~ConnectionManager() {
    this->current_connection_.reset();
    this->pending_connection_.reset();
    this->dying_connection_.reset();
}

// --- Public API ---

void ConnectionManager::connect_to(const std::string& url) {
    SS_LOGI(TAG, "Initiating client connection to: %s", url.c_str());

    auto client_conn = std::make_unique<SendspinClientConnection>(url);
    client_conn->set_auto_reconnect(false);

    this->setup_connection_callbacks_(client_conn.get());
    client_conn->on_disconnected = [this](SendspinConnection* conn) {
        // Defer to loop(); this callback runs on IXWebSocket's internal thread
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->pending_disconnect_events_.push_back(conn);
    };

    client_conn->init_time_filter();

    if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
        SS_LOGD(TAG, "Existing connection active, new connection will go through handoff");
        this->pending_connection_ = std::move(client_conn);
        this->pending_connection_->start();
    } else {
        this->current_connection_ = std::move(client_conn);
        this->current_connection_->start();
    }
}

void ConnectionManager::disconnect(SendspinGoodbyeReason reason) {
    if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
        this->current_connection_->disconnect(reason, nullptr);
    }
}

// --- Server lifecycle ---

void ConnectionManager::init_server(SendspinClient* client, bool psram_stack, unsigned priority) {
    this->client_ = client;
    this->psram_stack_ = psram_stack;
    this->task_priority_ = priority;

    this->ws_server_ = std::make_unique<SendspinWsServer>();

    this->ws_server_->set_new_connection_callback(
        [this](std::unique_ptr<SendspinServerConnection> conn) {
            this->on_new_connection_(std::move(conn));
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

    this->ws_server_->set_find_connection_callback([this](int sockfd) -> SendspinServerConnection* {
        if (this->current_connection_ != nullptr &&
            this->current_connection_->get_sockfd() == sockfd) {
            return static_cast<SendspinServerConnection*>(this->current_connection_.get());
        }
        if (this->pending_connection_ != nullptr &&
            this->pending_connection_->get_sockfd() == sockfd) {
            return static_cast<SendspinServerConnection*>(this->pending_connection_.get());
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
            this->ws_server_->start(this->client_, this->psram_stack_, this->task_priority_);
        }
    }

    // Process deferred connection lifecycle events
    {
        std::vector<int> close_events;
        std::vector<SendspinConnection*> disconnect_events;
        std::vector<ServerHelloEvent> hello_events;
        bool release_dying = false;
        {
            std::lock_guard<std::mutex> lock(this->conn_mutex_);
            close_events.swap(this->pending_close_events_);
            disconnect_events.swap(this->pending_disconnect_events_);
            hello_events.swap(this->pending_hello_events_);
            release_dying = this->dying_connection_ready_to_release_;
            this->dying_connection_ready_to_release_ = false;
        }

        // Server connection close events (ESP httpd)
        for (int sockfd : close_events) {
            if (this->current_connection_ != nullptr &&
                this->current_connection_->get_sockfd() == sockfd) {
                this->on_connection_lost_(this->current_connection_.get());
            } else if (this->pending_connection_ != nullptr &&
                       this->pending_connection_->get_sockfd() == sockfd) {
                this->on_connection_lost_(this->pending_connection_.get());
            }
        }

        // Client connection disconnect events (host IXWebSocket)
        for (SendspinConnection* conn : disconnect_events) {
            this->on_connection_lost_(conn);
        }

        if (release_dying) {
            this->dying_connection_.reset();
        }

        // Server hello events — handshake completion and handoff
        for (auto& event : hello_events) {
            // Verify the connection is still one we manage
            if (event.conn != this->current_connection_.get() &&
                event.conn != this->pending_connection_.get()) {
                continue;
            }

            // Notify client (stores server info, publishes state)
            this->client_->on_handshake_complete_(event.conn, std::move(event.server));

            SS_LOGI(TAG, "Connection handshake complete: server_id=%s, connection_reason=%s",
                    event.conn->get_server_id().c_str(),
                    to_cstr(event.conn->get_connection_reason()));

            // Handle handoff if pending connection completed its handshake
            if (this->pending_connection_ != nullptr &&
                this->pending_connection_.get() == event.conn) {
                bool should_switch =
                    this->should_switch_to_new_server_(this->current_connection_.get(), event.conn);
                SS_LOGI(TAG, "Handoff decision: %s",
                        should_switch ? "switch to new" : "keep current");
                this->complete_handoff_(should_switch);
            }
        }
    }

    // Call loop on active connections
    if (this->current_connection_ != nullptr) {
        this->current_connection_->loop();
    }
    if (this->pending_connection_ != nullptr) {
        this->pending_connection_->loop();
    }

    // Check hello retry timer
    if (this->hello_retry_.retry_time_us > 0 &&
        platform_time_us() >= this->hello_retry_.retry_time_us) {
        this->hello_retry_.retry_time_us = 0;
        SendspinConnection* conn = this->hello_retry_.conn;

        // Verify connection is still valid
        if (conn == this->current_connection_.get() || conn == this->pending_connection_.get()) {
            if (!this->send_hello_message_(this->hello_retry_.attempts - 1, conn)) {
                // Transient failure - retry with exponential backoff
                if (this->hello_retry_.attempts > 1) {
                    this->hello_retry_.delay_ms *= 2;
                    this->hello_retry_.attempts--;
                    this->hello_retry_.retry_time_us =
                        platform_time_us() +
                        static_cast<int64_t>(this->hello_retry_.delay_ms) * 1000;
                }
            }
        }
    }
}

// --- Connection queries ---

SendspinConnection* ConnectionManager::current() const {
    return this->current_connection_.get();
}

SendspinConnection* ConnectionManager::pending() const {
    return this->pending_connection_.get();
}

bool ConnectionManager::is_connected() const {
    return this->current_connection_ != nullptr && this->current_connection_->is_connected() &&
           this->current_connection_->is_handshake_complete();
}

// --- Event queuing ---

void ConnectionManager::enqueue_hello(ServerHelloEvent event) {
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->pending_hello_events_.push_back(std::move(event));
}

// --- Handoff support ---

void ConnectionManager::set_last_played_server_hash(uint32_t hash) {
    this->last_played_server_hash_ = hash;
    this->has_last_played_server_ = true;
}

// --- Connection setup ---

void ConnectionManager::setup_connection_callbacks_(SendspinConnection* conn) {
    conn->on_connected = [this](SendspinConnection* c) { this->initiate_hello_(c); };
    conn->on_json_message = [this](SendspinConnection* c, const std::string& message,
                                   int64_t timestamp) {
        this->client_->process_json_message_(c, message, timestamp);
    };
    conn->on_binary_message = [this](SendspinConnection* /*c*/, uint8_t* payload, size_t len) {
        this->client_->process_binary_message_(payload, len);
    };
    conn->on_handshake_complete = [](SendspinConnection* /*c*/) {
        // Handshake completion is handled via deferred hello events in loop()
    };
}

void ConnectionManager::on_new_connection_(std::unique_ptr<SendspinServerConnection> conn) {
    // Called from httpd open_callback thread. Connection pointer assignment must happen inline
    // because the httpd find_connection_callback needs to locate this connection immediately
    // for subsequent message routing on the same thread.
    conn->init_time_filter();

    this->setup_connection_callbacks_(conn.get());
    conn->on_disconnected = [](SendspinConnection* /*c*/) {
        // Cleanup happens in on_connection_closed_ triggered by the server
    };

    if (this->current_connection_ == nullptr) {
        SS_LOGD(TAG, "No existing connection, accepting as current");
        this->current_connection_ = std::move(conn);
    } else {
        SS_LOGD(TAG, "Existing connection present, setting as pending for handoff");
        if (this->pending_connection_ != nullptr) {
            SS_LOGW(TAG, "Already have pending connection, rejecting new connection");
            this->disconnect_and_release_(std::move(conn), SendspinGoodbyeReason::ANOTHER_SERVER);
            return;
        }
        this->pending_connection_ = std::move(conn);
    }
}

// --- Hello handshake ---

void ConnectionManager::initiate_hello_(SendspinConnection* conn) {
    // Set up retry state: 100ms initial delay, 3 attempts
    this->hello_retry_.conn = conn;
    this->hello_retry_.delay_ms = 100;
    this->hello_retry_.attempts = 3;
    this->hello_retry_.retry_time_us = platform_time_us() + 100 * 1000;  // 100ms from now
}

bool ConnectionManager::send_hello_message_(uint8_t remaining_attempts, SendspinConnection* conn) {
    // Verify the connection is still one of our managed connections
    if (conn != this->current_connection_.get() && conn != this->pending_connection_.get()) {
        SS_LOGW(TAG, "Connection no longer valid for hello message");
        return true;
    }

    if (conn == nullptr || !conn->is_connected()) {
        SS_LOGW(TAG, "Cannot send hello - not connected");
        return true;
    }

    std::string hello_message = this->client_->build_hello_message_();

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

// --- Connection lifecycle ---

void ConnectionManager::on_connection_lost_(SendspinConnection* conn) {
    if (conn == nullptr) {
        return;
    }

    if (this->current_connection_ != nullptr && this->current_connection_.get() == conn) {
        SS_LOGI(TAG, "Current connection lost");
        conn->disable_message_dispatch();
        this->client_->time_burst_->reset();
        this->client_->cleanup_connection_state_();
        this->current_connection_.reset();

        if (this->pending_connection_ != nullptr) {
            SS_LOGD(TAG, "Promoting pending connection to current");
            this->current_connection_ = std::move(this->pending_connection_);
        }
    } else if (this->pending_connection_ != nullptr && this->pending_connection_.get() == conn) {
        SS_LOGD(TAG, "Pending connection lost");
        this->pending_connection_.reset();
    }
}

bool ConnectionManager::should_switch_to_new_server_(SendspinConnection* current,
                                                     SendspinConnection* new_conn) {
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

void ConnectionManager::complete_handoff_(bool switch_to_new) {
    if (switch_to_new) {
        SS_LOGD(TAG, "Completing handoff: switching to new server");
        if (this->current_connection_ != nullptr) {
            this->current_connection_->disable_message_dispatch();
            this->client_->time_burst_->reset();
            this->client_->cleanup_connection_state_();
            auto old_current = std::move(this->current_connection_);
            this->current_connection_ = std::move(this->pending_connection_);
            this->disconnect_and_release_(std::move(old_current),
                                          SendspinGoodbyeReason::ANOTHER_SERVER);
        } else {
            this->current_connection_ = std::move(this->pending_connection_);
        }
    } else {
        SS_LOGD(TAG, "Completing handoff: keeping current server");
        if (this->pending_connection_ != nullptr) {
            this->disconnect_and_release_(std::move(this->pending_connection_),
                                          SendspinGoodbyeReason::ANOTHER_SERVER);
        }
    }
}

void ConnectionManager::disconnect_and_release_(std::unique_ptr<SendspinConnection> conn,
                                                SendspinGoodbyeReason reason) {
    this->dying_connection_ = std::shared_ptr<SendspinConnection>(std::move(conn));
    this->dying_connection_->disconnect(reason, [this]() {
        // Defer the actual destruction to loop() to avoid use-after-free.
        // This callback runs in the httpd worker thread (async_send_text), but the connection
        // must stay alive until all pending httpd_queue_work items have been processed.
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->dying_connection_ready_to_release_ = true;
    });
}

// --- Helpers ---

uint32_t ConnectionManager::fnv1_hash(const char* str) {
    uint32_t hash = 2166136261UL;
    while (*str) {
        hash *= 16777619UL;
        hash ^= static_cast<uint8_t>(*str++);
    }
    return hash;
}

}  // namespace sendspin
