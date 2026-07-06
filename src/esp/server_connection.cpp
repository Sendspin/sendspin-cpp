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

#include "server_connection.h"

#include "lwip/sockets.h"  // for setsockopt, IPPROTO_TCP, NODELAY
#include "platform/compiler.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "protocol_messages.h"
#include <esp_timer.h>

#include <cstring>

namespace sendspin {

static const char* const TAG = "sendspin.server_connection";

// ============================================================================
// Static helpers
// ============================================================================

/// @brief Holds the originating connection and payload data for an async text send
///
/// `conn` is a weak_ptr to the connection that queued the work, not a raw `(server, sockfd)` pair.
/// The worker resolves it with `conn.lock()`: a recycled sockfd can therefore never redirect the
/// frame onto a different connection, and a destroyed connection yields a null lock (a clean
/// no-op) rather than a use-after-free.
struct AsyncRespArg {
    std::weak_ptr<SendspinServerConnection> conn;
    uint8_t* payload{nullptr};
    size_t len{0};
    bool has_callback{false};
    /// When true the frame may be sent before client/hello (the hello itself and goodbye); when
    /// false the worker drops it unless the hello has already been sent on this connection.
    bool allow_before_hello{false};
    SendCompleteCallback on_complete;
};

/// @brief Heap struct used by the time-message worker to identify its originating connection
///
/// Holds a weak_ptr for the same identity-and-lifetime safety as AsyncRespArg.
struct SessionLookup {
    std::weak_ptr<SendspinServerConnection> conn;
};

// ============================================================================
// SendspinConnection interface implementation
// ============================================================================

SendspinServerConnection::SendspinServerConnection(httpd_handle_t server, int sockfd)
    : server_(server), sockfd_(sockfd) {
    // Disabling Nagle's algorithm significantly improves the time syncing accuracy
    int nodelay = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0) {
        SS_LOGW(TAG, "Failed to turn on TCP_NODELAY, syncing may be inaccurate");
    }
}

void SendspinServerConnection::start() {
    // Time filter is initialized by the hub when it sets up the connection.
}

void SendspinServerConnection::loop() {
    // Time message sending is handled by the hub
}

void SendspinServerConnection::disconnect(SendspinGoodbyeReason reason,
                                          std::function<void()> on_complete) {
    if (!this->is_connected()) {
        // Not connected - invoke completion callback immediately if provided
        if (on_complete) {
            on_complete();
        }
        return;
    }

    // Send goodbye, then trigger close, then invoke the user callback. Capture a weak_ptr to
    // self instead of raw `this`: the worker normally finds the conn via the session slot
    // (keeping it alive through the completion), but a weak_ptr makes that invariant explicit
    // and avoids any UAF if the worker ever runs after the slot has been freed (e.g., across
    // ESP-IDF versions whose httpd drain-before-free_fn ordering differs from the version we
    // designed against). Skipping trigger_close() when the conn is already gone is harmless --
    // the session is gone too.
    std::weak_ptr<SendspinServerConnection> weak_self =
        std::static_pointer_cast<SendspinServerConnection>(this->shared_from_this());
    this->send_goodbye_reason(reason, [weak_self, on_complete](bool /*success*/) {
        if (auto self = weak_self.lock()) {
            self->trigger_close();
        }

        // Invoke user-provided completion callback if provided.
        // Already running in httpd worker thread context (async_send_text),
        // so caller should use defer() if they need main loop context
        if (on_complete) {
            on_complete();
        }
    });
}

bool SendspinServerConnection::is_connected() const {
    return this->sockfd_ >= 0 && !this->closed_.load(std::memory_order_acquire);
}

SsErr SendspinServerConnection::send_text_message(const std::string& message,
                                                  SendCompleteCallback on_complete,
                                                  bool allow_before_hello) {
    if (!this->is_connected()) {
        // No client connected - invoke callback with failure if provided
        if (on_complete) {
            on_complete(false);
        }
        return SsErr::INVALID_STATE;
    }

    struct AsyncRespArg* resp_arg =
        static_cast<AsyncRespArg*>(platform_malloc(sizeof(AsyncRespArg)));
    if (resp_arg == nullptr) {
        SS_LOGE(TAG, "Failed to allocate AsyncRespArg for message send");
        if (on_complete) {
            on_complete(false);
        }
        return SsErr::NO_MEM;
    }

    // Use placement new to properly construct the struct with the callback
    new (resp_arg) AsyncRespArg();

    resp_arg->conn = std::static_pointer_cast<SendspinServerConnection>(this->shared_from_this());
    resp_arg->allow_before_hello = allow_before_hello;
    resp_arg->payload = static_cast<uint8_t*>(platform_malloc(message.size()));
    if (resp_arg->payload == nullptr) {
        SS_LOGE(TAG, "Failed to allocate %zu bytes for message payload", message.size());
        resp_arg->~AsyncRespArg();
        platform_free(resp_arg);
        if (on_complete) {
            on_complete(false);
        }
        return SsErr::NO_MEM;
    }
    resp_arg->len = message.size();

    // Move the callback into the struct if provided
    if (on_complete) {
        resp_arg->has_callback = true;
        resp_arg->on_complete = std::move(on_complete);
    }

    std::memcpy((void*)resp_arg->payload, (void*)message.data(), message.size());

    if (httpd_queue_work(this->server_, async_send_text, resp_arg) != ESP_OK) {
        SS_LOGE(TAG, "httpd_queue_work failed!");
        platform_free(resp_arg->payload);
        // Need to invoke callback with failure before destroying it
        if (resp_arg->has_callback) {
            resp_arg->on_complete(false);
        }
        resp_arg->~AsyncRespArg();
        platform_free(resp_arg);
        return SsErr::FAIL;
    }
    return SsErr::OK;
}

void SendspinServerConnection::trigger_close() {
    if (this->sockfd_ >= 0) {
        httpd_sess_trigger_close(this->server_, this->sockfd_);
    }
}

SS_HOT esp_err_t SendspinServerConnection::handle_data(httpd_req_t* req, int64_t receive_time) {
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));

    // First call with max_len = 0 to get the frame length
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        SS_LOGE(TAG, "httpd_ws_recv_frame failed to get frame len with %d", ret);
        return ret;
    }

    // Track frame type: text/binary frames set the type, continuation frames inherit it
    if (ws_pkt.type == HTTPD_WS_TYPE_TEXT || ws_pkt.type == HTTPD_WS_TYPE_BINARY) {
        this->is_text_frame_ = (ws_pkt.type == HTTPD_WS_TYPE_TEXT);
    } else if (ws_pkt.type != HTTPD_WS_TYPE_CONTINUE) {
        // Control frames (ping, pong, close) - not handled here
        return ESP_OK;
    }

    bool is_final = ws_pkt.final;

    if (ws_pkt.len == 0) {
        // No payload data, but still dispatch if final (for empty messages or buffered data)
        if (is_final) {
            this->dispatch_completed_message(this->is_text_frame_, receive_time);
        }
        return ESP_OK;
    }

    // Allocate/grow directly into the websocket payload buffer (zero-copy)
    uint8_t* dest = this->prepare_receive_buffer(ws_pkt.len);
    if (dest == nullptr) {
        return ESP_ERR_NO_MEM;
    }

    // Point httpd directly at our payload buffer so it writes there without an intermediate copy
    ws_pkt.payload = dest;

    // Second call with max_len = ws_pkt.len to receive frame payload directly into our buffer
    ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
    if (ret != ESP_OK) {
        SS_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
        this->reset_websocket_payload();
        return ret;
    }

    this->commit_receive_buffer(ws_pkt.len);

    if (is_final) {
        this->dispatch_completed_message(this->is_text_frame_, receive_time);
    }

    return ESP_OK;
}

bool SendspinServerConnection::send_time_message() {
    if (!this->is_connected()) {
        return false;
    }

    // The worker resolves the originating connection via the weak_ptr below, so a recycled sockfd
    // cannot redirect the frame and a destroyed connection yields a clean no-op. The JSON is built
    // inside the worker so client_transmitted is captured as close to the wire send as possible.
    // SessionLookup now holds a weak_ptr, so it is constructed with placement new and explicitly
    // destroyed before free (matching the AsyncRespArg convention).
    auto* lookup = static_cast<SessionLookup*>(platform_malloc_internal(sizeof(SessionLookup)));
    if (lookup == nullptr) {
        SS_LOGE(TAG, "Failed to allocate SessionLookup for time message");
        return false;
    }
    new (lookup) SessionLookup();
    lookup->conn = std::static_pointer_cast<SendspinServerConnection>(this->shared_from_this());
    if (httpd_queue_work(this->server_, async_send_time_text, lookup) != ESP_OK) {
        SS_LOGE(TAG, "httpd_queue_work failed for time message");
        lookup->~SessionLookup();
        platform_free(lookup);
        return false;
    }
    return true;
}

void SendspinServerConnection::async_send_time_text(void* arg) {
    auto* lookup = static_cast<SessionLookup*>(arg);
    auto conn = lookup->conn.lock();
    lookup->~SessionLookup();
    platform_free(lookup);

    // Drop the time frame unless client/hello has already been sent on this exact connection. The
    // weak_ptr lock guarantees identity (never a recycled-sockfd peer); the hello gate guarantees
    // a stale time frame can never jump ahead of a fresh connection's hello.
    if (!conn || !conn->is_connected() || !conn->client_hello_sent_) {
        return;
    }

    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    // Capture client_transmitted as close as possible to the actual send. The serialization
    // happens between this capture and the wire send; track its duration so the bias is
    // visible in the time_burst log. Stack buffer keeps the path heap-free.
    char buf[TIME_MESSAGE_BUF_SIZE];
    const int64_t client_transmitted = esp_timer_get_time();
    const size_t len = format_client_time_message(buf, sizeof(buf), client_transmitted);

    if (len == 0) {
        return;
    }

    ws_pkt.payload = reinterpret_cast<uint8_t*>(buf);
    ws_pkt.len = len;

    conn->update_serialize_ema(esp_timer_get_time() - client_transmitted);

    httpd_ws_send_frame_async(conn->server_, conn->sockfd_, &ws_pkt);
}

void SendspinServerConnection::async_send_text(void* arg) {
    struct AsyncRespArg* resp_arg = (AsyncRespArg*)arg;
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));

    ws_pkt.payload = resp_arg->payload;
    ws_pkt.len = resp_arg->len;
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    // Resolve the originating connection. weak_ptr.lock() yields the exact conn that queued this
    // work (or null if it has since been destroyed), so a recycled sockfd can never redirect the
    // frame onto a different connection -- the lifetime-safe replacement for the old raw `this`
    // pointer that caused the use-after-free crash. Non-handshake frames are additionally gated on
    // client_hello_sent_ so nothing can precede the client/hello; allow_before_hello opts the hello
    // and goodbye out of that gate. The completion callback fires only when the frame is actually
    // sent: it is skipped both when the gate blocks the frame AND when the connection is already
    // gone (lock() is null) -- allow_before_hello bypasses the gate but not the conn-alive
    // requirement, so callers must not rely on the callback as an unconditional "send finished"
    // signal.
    auto conn = resp_arg->conn.lock();
    if (conn && conn->is_connected() &&
        (resp_arg->allow_before_hello || conn->client_hello_sent_)) {
        esp_err_t err = httpd_ws_send_frame_async(conn->server_, conn->sockfd_, &ws_pkt);
        if (resp_arg->has_callback) {
            resp_arg->on_complete(err == ESP_OK);
        }
    }

    platform_free(ws_pkt.payload);

    // Properly destruct the AsyncRespArg (which includes the std::function)
    resp_arg->~AsyncRespArg();
    platform_free(resp_arg);
}

}  // namespace sendspin
