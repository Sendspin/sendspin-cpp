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
#include "platform/types.h"
#include "protocol_messages.h"
#include "sendspin/types.h"
#include "ws_server.h"
#include <esp_err.h>

#include <cstring>
#include <string>
#include <utility>

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
///
/// Block layout: one block of `sizeof(AsyncRespArg) + len` bytes, the struct placement-new'd at
/// its start and `payload` pointing at the byte immediately following it. The struct is not POD
/// (it holds a weak_ptr and a std::function), so the tail cannot be a flexible array member;
/// `payload` stays a plain pointer into that same block instead. Release it only through
/// release_async_resp_arg(), which also frees the payload.
struct AsyncRespArg {
    std::weak_ptr<SendspinServerConnection> conn;
    /// Pool the block came from, or nullptr for a heap block.
    SendBlockPool* pool{nullptr};
    uint8_t* payload{nullptr};
    size_t len{0};
    /// Frame type (HTTPD_WS_TYPE_TEXT or HTTPD_WS_TYPE_BINARY) the worker sends this as.
    httpd_ws_type_t type{HTTPD_WS_TYPE_TEXT};
    bool has_callback{false};
    /// When true the frame may be sent before client/hello (the hello itself and goodbye); when
    /// false the worker drops it unless the hello has already been sent on this connection.
    bool allow_before_hello{false};
    SendCompleteCallback on_complete;
    /// Run immediately before the write, if set.
    NoiseTransport::FrameWriteHook before_write;
};

static_assert(SEND_BLOCK_SIZE - sizeof(AsyncRespArg) >= 256,
              "SEND_BLOCK_SIZE must leave room for the steady-state sends");

/// @brief Destroys `resp_arg` and returns its block to the pool or heap it came from
static void release_async_resp_arg(AsyncRespArg* resp_arg) {
    SendBlockPool* pool = resp_arg->pool;
    resp_arg->~AsyncRespArg();
    if (pool != nullptr) {
        pool->release(resp_arg);
    } else {
        platform_free(resp_arg);
    }
}

// ============================================================================
// SendspinConnection interface implementation
// ============================================================================

SendspinServerConnection::SendspinServerConnection(httpd_handle_t server, int sockfd,
                                                   SendBlockPool& send_pool)
    : server_(server), send_pool_(&send_pool), sockfd_(sockfd) {
    // Disabling Nagle's algorithm significantly improves the time syncing accuracy
    int nodelay = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0) {
        SS_LOGW(TAG, "Failed to turn on TCP_NODELAY, syncing may be inaccurate");
    }
}

void SendspinServerConnection::start() {
    // Time filter is initialized by the hub when it sets up the connection.
}

void SendspinServerConnection::disconnect(SendspinGoodbyeReason reason,
                                          std::function<void()> on_complete) {
    if (!this->is_connected()) {
        // Not connected: invoke completion callback immediately if provided
        if (on_complete) {
            on_complete();
        }
        return;
    }

    // Send goodbye, then trigger close, then invoke the user callback. Capture a weak_ptr to self
    // instead of raw `this`: the worker normally finds the conn via the session slot (keeping it
    // alive through the completion), but a weak_ptr makes that invariant explicit and avoids a UAF
    // if the worker ever runs after the slot has been freed (e.g. across ESP-IDF versions whose
    // httpd drain-before-free_fn ordering differs). Skipping trigger_close() when the conn is
    // already gone is harmless; the session is gone too.
    std::weak_ptr<SendspinServerConnection> weak_self =
        std::static_pointer_cast<SendspinServerConnection>(this->shared_from_this());
    this->send_goodbye_reason(reason, [weak_self, on_complete](bool /*success*/) {
        if (auto self = weak_self.lock()) {
            self->trigger_close();
        }

        // Invoke the caller's completion callback, if any, on the httpd worker thread
        // (async_send_frame); it must be safe there, as the GoodbyeWait completion is.
        if (on_complete) {
            on_complete();
        }
    });
}

void SendspinServerConnection::close_transport_now() {
    // trigger_close() -> httpd_sess_trigger_close() is already async/non-blocking (the same
    // primitive disconnect() uses in its completion callback), so it is safe from any thread. The
    // resulting close notification (close_callback() in ws_server.cpp) reaches
    // notify_transport_closed().
    this->trigger_close();
}

bool SendspinServerConnection::is_connected() const {
    return this->sockfd_ >= 0 && !this->closed_.load(std::memory_order_acquire);
}

SsErr SendspinServerConnection::send_text_message(const std::string& message,
                                                  SendCompleteCallback on_complete,
                                                  bool allow_before_hello) {
    return this->queue_async_send(reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                                  HTTPD_WS_TYPE_TEXT, std::move(on_complete), allow_before_hello,
                                  nullptr);
}

SsErr SendspinServerConnection::send_binary_message(const uint8_t* data, size_t len,
                                                    SendCompleteCallback on_complete,
                                                    bool allow_before_hello) {
    return this->queue_async_send(data, len, HTTPD_WS_TYPE_BINARY, std::move(on_complete),
                                  allow_before_hello, nullptr);
}

SsErr SendspinServerConnection::send_transport_frame(
    const uint8_t* data, size_t len, const NoiseTransport::FrameWriteHook& before_write) {
    return this->queue_async_send(data, len, HTTPD_WS_TYPE_BINARY, nullptr,
                                  /*allow_before_hello=*/true, before_write);
}

SsErr SendspinServerConnection::queue_async_send(
    const uint8_t* data, size_t len, httpd_ws_type_t type, SendCompleteCallback on_complete,
    bool allow_before_hello, const NoiseTransport::FrameWriteHook& before_write) {
    const bool is_text = (type == HTTPD_WS_TYPE_TEXT);

    if (!this->is_connected()) {
        // No client connected: invoke callback with failure if provided
        if (on_complete) {
            on_complete(false);
        }
        return SsErr::INVALID_STATE;
    }

    const size_t block_size = sizeof(AsyncRespArg) + len;
    SendBlockPool* pool = this->send_pool_;
    void* block = pool->try_acquire(block_size);
    if (block == nullptr) {
        if (block_size <= SendBlockPool::block_size()) {
            SS_LOGD(TAG, "Send pool exhausted, allocating %zu bytes", block_size);
        }
        pool = nullptr;
        block = platform_malloc(block_size);
    }
    if (block == nullptr) {
        if (is_text) {
            SS_LOGE(TAG, "Failed to allocate AsyncRespArg for message send");
        } else {
            SS_LOGE(TAG, "Failed to allocate AsyncRespArg for binary send");
        }
        if (on_complete) {
            on_complete(false);
        }
        return SsErr::NO_MEM;
    }

    // Use placement new to properly construct the struct with the callback
    auto* resp_arg = new (block) AsyncRespArg();

    resp_arg->conn = std::static_pointer_cast<SendspinServerConnection>(this->shared_from_this());
    resp_arg->pool = pool;
    resp_arg->allow_before_hello = allow_before_hello;
    resp_arg->payload = reinterpret_cast<uint8_t*>(block) + sizeof(AsyncRespArg);
    resp_arg->len = len;
    resp_arg->type = type;

    // Move the callback into the struct if provided
    if (on_complete) {
        resp_arg->has_callback = true;
        resp_arg->on_complete = std::move(on_complete);
    }
    resp_arg->before_write = before_write;

    std::memcpy(static_cast<void*>(resp_arg->payload), static_cast<const void*>(data), len);

    if (httpd_queue_work(this->server_, async_send_frame, resp_arg) != ESP_OK) {
        if (is_text) {
            SS_LOGE(TAG, "httpd_queue_work failed!");
        } else {
            SS_LOGE(TAG, "httpd_queue_work failed for binary send!");
        }
        // Need to invoke callback with failure before destroying it
        if (resp_arg->has_callback) {
            resp_arg->on_complete(false);
        }
        release_async_resp_arg(resp_arg);
        return SsErr::FAIL;
    }
    return SsErr::OK;
}

void SendspinServerConnection::trigger_close() {
    // Gate on is_connected(): once close_callback has marked this connection closed, httpd may
    // recycle the fd onto a freshly-accepted session, and closing by the stale fd would kill the
    // wrong peer. A residual instruction-scale TOCTOU remains (the session could close between
    // this check and the call below); eliminating it entirely would need an identity check on
    // the httpd task itself, which is not worth the extra queue hop for a close-time race.
    if (!this->is_connected()) {
        return;
    }
    httpd_sess_trigger_close(this->server_, this->sockfd_);
}

SS_HOT esp_err_t SendspinServerConnection::handle_data(httpd_req_t* req, int64_t receive_time,
                                                       SendspinWsServer* server) {
    // The connection was delivered (and wired to the inbound ring) from the upgrade GET before any
    // frame can arrive; a frame on a never-delivered or released connection is dropped by the
    // inbound routing (begin_inbound_message()).
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));

    // First call with max_len = 0 to get the frame length
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        SS_LOGE(TAG, "httpd_ws_recv_frame failed to get frame len with %d", ret);
        return ret;
    }

    const bool continuation = ws_pkt.type == HTTPD_WS_TYPE_CONTINUE;
    if (!continuation && ws_pkt.type != HTTPD_WS_TYPE_TEXT && ws_pkt.type != HTTPD_WS_TYPE_BINARY) {
        // Control frames (ping, pong, close): not handled here
        return ESP_OK;
    }
    const bool is_text = ws_pkt.type == HTTPD_WS_TYPE_TEXT;

    if (!continuation && ws_pkt.final) {
        // A single-frame message, the only kind a conforming peer sends: received straight into
        // its destination, a ring item once the connection is admitted.
        const InboundTarget target = this->begin_inbound_message(ws_pkt.len, is_text, receive_time);
        if (target.route == InboundRoute::CLOSE) {
            return ESP_FAIL;
        }
        if (target.route == InboundRoute::DROP) {
            return SendspinServerConnection::discard_frame_payload(req, ws_pkt, server);
        }
        ret = SendspinServerConnection::receive_frame_payload(req, ws_pkt, target.data);
        this->end_inbound_message(ret == ESP_OK);
        return ret;
    }

    // A frame of a multi-frame message (the rare path; see begin_inbound_fragment()).
    const InboundTarget target =
        this->begin_inbound_fragment(ws_pkt.len, !continuation, is_text, receive_time);
    if (target.route == InboundRoute::CLOSE) {
        return ESP_FAIL;
    }
    if (target.route == InboundRoute::DROP) {
        ret = SendspinServerConnection::discard_frame_payload(req, ws_pkt, server);
        this->end_inbound_fragment(0, ws_pkt.final);
        return ret;
    }
    ret = SendspinServerConnection::receive_frame_payload(req, ws_pkt, target.data);
    if (ret != ESP_OK) {
        // httpd closes the session over the error; nothing assembled so far is published.
        return ret;
    }
    this->end_inbound_fragment(ws_pkt.len, ws_pkt.final);
    return ESP_OK;
}

esp_err_t SendspinServerConnection::receive_frame_payload(httpd_req_t* req,
                                                          httpd_ws_frame_t& ws_pkt, uint8_t* dest) {
    // A zero-length frame has nothing to read, and a second httpd_ws_recv_frame() on a zero
    // length would parse the next frame's header instead.
    if (ws_pkt.len == 0) {
        return ESP_OK;
    }
    // Point httpd directly at the destination so it writes there without an intermediate copy.
    ws_pkt.payload = dest;
    const esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
    if (ret != ESP_OK) {
        SS_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
    }
    return ret;
}

esp_err_t SendspinServerConnection::discard_frame_payload(httpd_req_t* req,
                                                          httpd_ws_frame_t& ws_pkt,
                                                          SendspinWsServer* server) {
    if (ws_pkt.len == 0) {
        return ESP_OK;
    }
    // httpd hands a frame's payload over only whole (httpd_ws_recv_frame() needs max_len >= the
    // frame length, httpd_ws.c), so a dropped message still needs room for its frame. A frame
    // larger than any message the connection could legitimately carry closes it instead.
    if (ws_pkt.len > INBOUND_MAX_MESSAGE_BYTES) {
        SS_LOGW(TAG, "Dropped frame of %zu bytes exceeds one Noise frame; closing", ws_pkt.len);
        return ESP_FAIL;
    }
    uint8_t* scratch = server != nullptr ? server->discard_buffer() : nullptr;
    if (scratch == nullptr) {
        SS_LOGE(TAG, "No %zu-byte buffer to discard a frame into; closing",
                INBOUND_MAX_MESSAGE_BYTES);
        return ESP_FAIL;
    }
    return SendspinServerConnection::receive_frame_payload(req, ws_pkt, scratch);
}

void SendspinServerConnection::async_send_frame(void* arg) {
    auto* resp_arg = static_cast<AsyncRespArg*>(arg);
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));

    ws_pkt.payload = resp_arg->payload;
    ws_pkt.len = resp_arg->len;
    ws_pkt.type = resp_arg->type;

    // Resolve the originating connection. weak_ptr.lock() yields the exact conn that queued this
    // work (or null if it has been destroyed), so a recycled sockfd can never redirect the frame
    // onto a different connection. Non-handshake frames are gated on client_hello_sent_ so nothing
    // can precede the client/hello; allow_before_hello opts the pre-transport handshake frames, the
    // Noise transport frames, and the client/hello and client/goodbye out of that gate.
    // The completion callback fires only when the frame is sent: it is skipped both when the gate
    // blocks the frame and when the connection is already gone (lock() is null).
    // allow_before_hello bypasses the gate but not the conn-alive requirement, so callers must not
    // rely on the callback as an unconditional "send finished" signal.
    auto conn = resp_arg->conn.lock();
    if (conn && conn->is_connected() &&
        (resp_arg->allow_before_hello || conn->client_hello_sent_)) {
        if (resp_arg->before_write) {
            resp_arg->before_write();
        }
        esp_err_t err = httpd_ws_send_frame_async(conn->server_, conn->sockfd_, &ws_pkt);
        if (resp_arg->has_callback) {
            resp_arg->on_complete(err == ESP_OK);
        }
    }

    // payload lives in resp_arg's own block (see AsyncRespArg), so this releases it too.
    release_async_resp_arg(resp_arg);
}

}  // namespace sendspin
