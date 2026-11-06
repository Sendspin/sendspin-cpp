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

#include "ws_server.h"

#include "connection_block.h"
#include "constants.h"
#include "lwip/sockets.h"  // for close()
#include "platform/compiler.h"
#include "platform/logging.h"
#include "sendspin/config.h"
#include "server_connection.h"
#include <esp_err.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace sendspin {

// ============================================================================
// SendspinWsServer
// ============================================================================
//
// httpd server accepting incoming WebSocket connections. See the delivery contract in
// ws_server.h.

static const char* const TAG = "sendspin.ws_server";

/// @brief Deadline for an accepted session to complete its WebSocket upgrade
///
/// httpd has no handshake timeout of its own and max_open_sockets is small, so a raw TCP probe
/// held open without ever speaking WebSocket would pin a socket slot indefinitely. Pre-upgrade
/// sockets are a transport concern the manager never sees, so the bound lives here. The host build
/// has no equivalent: IXWebSocket applies its own 3 s server-side handshake timeout.
static constexpr int64_t WS_UPGRADE_TIMEOUT_US = 5LL * 1000 * 1000;

SendspinWsServer::~SendspinWsServer() {
    this->stop();
}

bool SendspinWsServer::start(SendspinClient* client, bool task_stack_in_psram,
                             unsigned task_priority, size_t task_stack_size) {
    if (this->server_ != nullptr) {
        SS_LOGW(TAG, "Server already started");
        return true;
    }

    this->client_ = client;

    // Configure the HTTP server
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    if (task_stack_in_psram) {
        config.task_caps = MALLOC_CAP_SPIRAM;
    }
    config.task_priority = task_priority;
    // Clamp to the documented minimum, the measured stack of this task's deepest call chain (see
    // SendspinClientConfig::DEFAULT_HTTPD_STACK_SIZE).
    if (task_stack_size < SendspinClientConfig::DEFAULT_HTTPD_STACK_SIZE) {
        SS_LOGW(TAG, "httpd_stack_size %u below minimum %u; clamping",
                static_cast<unsigned>(task_stack_size),
                static_cast<unsigned>(SendspinClientConfig::DEFAULT_HTTPD_STACK_SIZE));
        task_stack_size = SendspinClientConfig::DEFAULT_HTTPD_STACK_SIZE;
    }
    config.stack_size = task_stack_size;
    config.server_port = this->server_port_;
    // The session slots and the pending table hold MAX_SESSIONS sessions (see sessions_).
    if (this->max_connections_ > MAX_SESSIONS) {
        SS_LOGW(TAG, "server_max_connections %u above maximum %u; clamping",
                static_cast<unsigned>(this->max_connections_), static_cast<unsigned>(MAX_SESSIONS));
        this->max_connections_ = MAX_SESSIONS;
    }
    config.max_open_sockets = this->max_connections_;
    config.open_fn = SendspinWsServer::open_callback;
    config.close_fn = SendspinWsServer::close_callback;
    // httpd_stop() releases the global user context: with a null free function it calls plain
    // free() on the pointer (esp_http_server httpd_main.c), which would free this object while
    // the ConnectionManager still owns it and stop() still runs on it. A no-op free function
    // keeps ownership here.
    config.global_user_ctx = (void*)this;
    config.global_user_ctx_free_fn = [](void* /*ctx*/) {};
    // Use the configured ctrl_port, or fall back to ESP_HTTPD_DEF_CTRL_PORT + 1 to avoid
    // conflict with the web_server component
    config.ctrl_port = (this->ctrl_port_ != 0) ? this->ctrl_port_
                                               : static_cast<uint16_t>(ESP_HTTPD_DEF_CTRL_PORT + 1);

    // Start the HTTP server
    SS_LOGI(TAG, "Starting server on port: %d (max connections: %d)", config.server_port,
            this->max_connections_);
    esp_err_t err = httpd_start(&this->server_, &config);
    if (err != ESP_OK) {
        SS_LOGE(TAG, "Error starting server: %s", esp_err_to_name(err));
        return false;
    }

    // IDF >= 5.5.5 / 6.0.1 does not dispatch the upgrade GET to
    // the handler; registering the handler itself as the post-handshake callback
    // restores that dispatch, so httpd invokes it with the same GET request at the same lifecycle
    // position and the handler's HTTP_GET branch is the single upgrade signal on every IDF version.
    // There is no fallback path: no version fires both (skip-GET builds return before invoking the
    // handler), and delivery is idempotent regardless. The component's Kconfig selects the option
    // wherever it exists, and the version-gated error below trips if a future IDF breaks that.
    const httpd_uri_t sendspin_ws_uri = {.uri = "/sendspin",
                                         .method = HTTP_GET,
                                         .handler = SendspinWsServer::websocket_handler,
                                         .user_ctx = static_cast<void*>(this),
                                         .is_websocket = true,
                                         .handle_ws_control_frames = false,
                                         .supported_subprotocol = nullptr,
#ifdef CONFIG_HTTPD_WS_POST_HANDSHAKE_CB_SUPPORT
                                         .ws_post_handshake_cb = SendspinWsServer::websocket_handler
#endif
    };

    err = httpd_register_uri_handler(this->server_, &sendspin_ws_uri);
    if (err != ESP_OK) {
        SS_LOGE(TAG, "Error registering URI handler: %s", esp_err_to_name(err));
        httpd_stop(this->server_);
        this->server_ = nullptr;
        return false;
    }

    return true;
}

void SendspinWsServer::stop() {
    if (this->server_ != nullptr) {
        SS_LOGD(TAG, "Stopping server");
        const esp_err_t err = httpd_stop(this->server_);
        this->server_ = nullptr;
        if (err == ESP_OK) {
            // httpd discards work queued after its shutdown without running it, so the send blocks
            // that work held are never released, nor the outbound ring items lent ones hold. Every
            // session is closed and the protocol task joined, so nothing can claim a block now.
            SendspinServerConnection::reclaim_discarded_sends(this->send_pools_);
            // The httpd task is gone, so nothing reads into the discard buffer any more.
            this->discard_buf_.reset();
        }
    }

    // httpd_stop tore down every session, so this is normally already empty; clear defensively
    // so a restart begins from a clean table. One entry at a time, so each connection releases
    // after pending_mutex_ is dropped.
    for (;;) {
        std::shared_ptr<SendspinServerConnection> stale;
        {
            std::lock_guard<std::mutex> lock(this->pending_mutex_);
            if (this->pending_.empty()) {
                return;
            }
            stale = std::move(this->pending_.begin()->conn);
            this->pending_.erase(this->pending_.begin());
        }
    }
}

uint8_t* SendspinWsServer::discard_buffer() {
    if (this->discard_buf_.data() == nullptr &&
        !this->discard_buf_.allocate(this->discard_capacity_, MemoryLocation::PREFER_EXTERNAL)) {
        return nullptr;
    }
    return this->discard_buf_.data();
}

uint32_t SendspinWsServer::tick() {
    if (this->server_ == nullptr) {
        return UINT32_MAX;
    }

    // Pure age-based reap: any session still undelivered past the deadline is closed. Sparing
    // "upgraded but undelivered" sessions would turn a broken post-handshake callback into a
    // silent wedge of httpd's small socket pool instead of a visible close-and-retry loop. Pop
    // one expired session under the lock, close it outside the lock, and scan again; the pop also
    // resolves a delivery racing this reap exactly-once (the loser finds no entry and no-ops). The
    // scan that finds none has seen every remaining deadline.
    const int64_t now_us = esp_timer_get_time();
    for (;;) {
        std::shared_ptr<SendspinServerConnection> expired;
        // The earliest deadline still ahead, for the protocol task's wait.
        int64_t next_due_us = INT64_MAX;
        {
            std::lock_guard<std::mutex> lock(this->pending_mutex_);
            for (auto it = this->pending_.begin(); it != this->pending_.end(); ++it) {
                // A closing session is skipped, not reaped: close_callback pops its entry.
                if (!it->conn->is_connected()) {
                    continue;
                }
                const int64_t due_us = it->accept_time_us + WS_UPGRADE_TIMEOUT_US;
                if (now_us >= due_us) {
                    expired = std::move(it->conn);
                    this->pending_.erase(it);
                    break;
                }
                next_due_us = std::min(next_due_us, due_us);
            }
        }
        if (expired == nullptr) {
            return next_due_us == INT64_MAX ? UINT32_MAX : ms_until(next_due_us, now_us);
        }
        SS_LOGW(TAG, "Session did not complete a WebSocket upgrade within %d s, closing",
                static_cast<int>(WS_UPGRADE_TIMEOUT_US / (1000 * 1000)));
        expired->trigger_close();
    }
}

void SendspinWsServer::deliver_upgraded(int sockfd) {
    auto conn = this->pop_pending(sockfd);
    if (conn == nullptr) {
        return;  // Already closed or reaped (a duplicate delivery cannot happen: the GET branch
                 // fires once per session)
    }

    if (!this->new_connection_callback_) {
        // Normally unreachable (open_callback rejects sessions when no callback is set), but an
        // unset consumer must close the session, not throw bad_function_call on the httpd task.
        SS_LOGW(TAG, "No new connection callback set, closing upgraded session");
        conn->trigger_close();
        return;
    }

    SS_LOGD(TAG, "WebSocket upgrade complete on socket %d, delivering connection", sockfd);
    conn->mark_ws_upgraded();
    if (!this->new_connection_callback_(conn)) {
        // Refused: the session closes, and its slot keeps owning the connection until httpd
        // frees it, so the reference dropped here is never the last.
        conn->trigger_close();
    }
}

std::shared_ptr<SendspinServerConnection> SendspinWsServer::pop_pending(int sockfd) {
    std::lock_guard<std::mutex> lock(this->pending_mutex_);
    for (auto it = this->pending_.begin(); it != this->pending_.end(); ++it) {
        if (it->sockfd == sockfd) {
            auto conn = std::move(it->conn);
            this->pending_.erase(it);
            return conn;
        }
    }
    return nullptr;
}

esp_err_t SendspinWsServer::open_callback(httpd_handle_t handle, int sockfd) {
    SS_LOGD(TAG, "New client connection on socket %d", sockfd);

    SendspinWsServer* server = static_cast<SendspinWsServer*>(httpd_get_global_user_ctx(handle));
    if (server == nullptr) {
        SS_LOGE(TAG, "Server context is null in open_callback");
        return ESP_FAIL;
    }

    // Reject the session before allocating anything if there is nobody to deliver the connection
    // to; otherwise the session would sit pinned with no one driving its handshake until the peer
    // gives up.
    if (!server->new_connection_callback_) {
        SS_LOGW(TAG, "No new connection callback set, rejecting session");
        return ESP_FAIL;
    }

    // A free session slot, found before anything is allocated. One is always free while
    // max_open_sockets <= MAX_SESSIONS (see sessions_), so this refusal guards that invariant
    // rather than turning away a session httpd could hold.
    const auto free_slot = std::find(server->sessions_.begin(), server->sessions_.end(), nullptr);
    if (free_slot == server->sessions_.end()) {
        assert(false && "no free session slot under max_open_sockets <= MAX_SESSIONS");
        return ESP_FAIL;
    }
    auto conn =
        make_connection_in_block<SendspinServerConnection>(handle, sockfd, server->send_pools_);
    if (conn == nullptr) {
        SS_LOGE(TAG, "No memory for a connection; refusing the session");
        return ESP_FAIL;
    }

    // Pin the connection to the httpd session: the slot is set as the session context, with a
    // free_fn that resets it when the session is torn down. httpd invokes the close_fn before the
    // free_fn, so observers (ConnectionManager) get notified first.
    std::shared_ptr<SendspinServerConnection>* slot = &*free_slot;
    *slot = conn;
    httpd_sess_set_ctx(handle, sockfd, slot, SendspinWsServer::release_session_slot);

    // Park it as pending rather than delivering: the rest of the library only ever learns about
    // connections whose WebSocket upgrade has been observed (see the delivery contract in
    // ws_server.h). A session that never upgrades is closed by tick() without the manager ever
    // knowing it existed.
    {
        std::lock_guard<std::mutex> lock(server->pending_mutex_);
        // Never full: this session's slot is in use and it has no entry yet (see pending_).
        server->pending_.push_back(PendingUpgrade{std::move(conn), esp_timer_get_time(), sockfd});
    }
    // The protocol task's next tick() then reports this session's upgrade deadline.
    if (server->wake_callback_) {
        server->wake_callback_();
    }
    return ESP_OK;
}

void SendspinWsServer::release_session_slot(void* slot) {
    // Usually the connection's last reference, so it is destroyed here, on the httpd task.
    static_cast<std::shared_ptr<SendspinServerConnection>*>(slot)->reset();
}

void SendspinWsServer::close_callback(httpd_handle_t handle, int sockfd) {
    SS_LOGD(TAG, "Client closed connection on socket %d", sockfd);

    auto* slot =
        static_cast<std::shared_ptr<SendspinServerConnection>*>(httpd_sess_get_ctx(handle, sockfd));
    if (slot == nullptr) {
        // Only a session open_callback() refused has no context. Its receive side is shut down as
        // below, but httpd_accept_conn() closes its fd once this returns, so closing it here too
        // could close a socket another task opened on the same fd in between.
        shutdown(sockfd, SHUT_RD);
        return;
    }

    // Flip the connection to disconnected immediately: queued async sends check is_connected()
    // and must not resolve this sockfd once httpd may recycle it for a new session.
    if (*slot != nullptr) {
        (*slot)->mark_closed();
    }

    SendspinWsServer* server = static_cast<SendspinWsServer*>(httpd_get_global_user_ctx(handle));

    if (server != nullptr) {
        // Drop a still-pending entry: this session closed before its upgrade was ever observed,
        // so it must not be delivered. Popping here (before the fd can be recycled) also keeps
        // sockfd unique as a pending-table key.
        server->pop_pending(sockfd);
    }

    // Tell the protocol task, which drops the connection from ConnectionManager's slots (its
    // observer shared_ptr) once the messages the session delivered before closing are processed.
    // The event is keyed on the connection's identity, never the recyclable sockfd. The session
    // slot keeps it alive until httpd invokes the free_fn, right after this returns; queued
    // workers hold a weak_ptr, so a worker that runs later finds it gone or closed.
    if (*slot != nullptr) {
        (*slot)->notify_transport_closed();
    }

    // Shut down the receive side before close() to stop lwIP from delivering more packets
    // during teardown. Without this, lwIP can race with netconn_prepare_delete and trigger
    // pbuf_free / recv_tcp assertions or cache faults inside the close path.
    // SHUT_RD (not SHUT_RDWR) lets the FIN still go out cleanly.
    shutdown(sockfd, SHUT_RD);
    close(sockfd);
}

SS_HOT esp_err_t SendspinWsServer::websocket_handler(httpd_req_t* req) {
    // Look up the connection via httpd's per-session ctx. The slot was pinned in open_callback and
    // is freed only after this handler unwinds for a given session, so the shared_ptr copy below
    // is always valid. Copying the shared_ptr keeps the conn alive for the duration of dispatch
    // even if a teardown is racing on another thread.
    int sockfd = httpd_req_to_sockfd(req);
    const auto* slot = static_cast<const std::shared_ptr<SendspinServerConnection>*>(
        httpd_sess_get_ctx(req->handle, sockfd));
    if (slot == nullptr || !*slot) {
        SS_LOGE(TAG, "No connection found for sockfd %d", sockfd);
        return ESP_FAIL;
    }
    std::shared_ptr<SendspinServerConnection> conn_holder = *slot;
    SendspinServerConnection* conn = conn_holder.get();

    SendspinWsServer* server =
        static_cast<SendspinWsServer*>(httpd_get_global_user_ctx(req->handle));

    // Upgrade GET: the sole upgrade signal on every IDF version (see start()). Frames are
    // processed strictly after this request cycle on the same httpd task, so delivery always
    // precedes the first frame.
    if (req->method == HTTP_GET) {
        if (server != nullptr) {
            server->deliver_upgraded(sockfd);
        }
        return ESP_OK;
    }

    // Delegate to connection's handle_data. Stale messages (i.e., after the connection has been
    // dropped from ConnectionManager's slots) are dropped inside the connection by its detached
    // inbound gate, so a still-alive session-pinned conn does not leak messages into freshly-reset
    // role queues. A frame on a never-delivered connection (its session outliving a
    // tick() reap by a moment) has no inbound ring to go to and is dropped the same way.
    return conn->handle_data(req, server);
}

}  // namespace sendspin
