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

/// @file server_connection.h
/// @brief ESP-IDF WebSocket server-side connection using esp_http_server

#pragma once

#include "connection.h"
#include "fixed_block_pool.h"
#include "platform/types.h"
#include "sendspin/types.h"
#include <esp_err.h>
#include <esp_http_server.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace sendspin {

/// @brief Bytes per outbound-send block: an AsyncRespArg header followed by the frame payload
///
/// Sized for the steady-state sends: an encrypted client/time (at most 93 B of payload), an
/// encrypted player-only client/state (about 235 B), and controller commands. A client/state
/// carrying artwork and visualizer config (about 600 B) takes a heap block; it is sent only on a
/// state change.
static constexpr size_t SEND_BLOCK_SIZE = 320;

/// @brief Outbound-send blocks per server: the one or two sends normally in flight, plus a burst
/// such as a state change during a time burst
static constexpr size_t SEND_BLOCK_COUNT = 4;

/// @brief Pool the ESP server's queued sends take their blocks from
using SendBlockPool = FixedBlockPool<SEND_BLOCK_SIZE, SEND_BLOCK_COUNT>;

/**
 * @brief ESP-IDF httpd WebSocket connection representing a single Sendspin server session
 *
 * Implements SendspinConnection for the server role, where the ESP device hosts the HTTP server
 * and the Sendspin server connects to it as a WebSocket client. Instances are created by
 * SendspinWsServer, never directly; the httpd session owns them (see ws_server.h).
 */
class SendspinWsServer;

class SendspinServerConnection : public SendspinConnection {
public:
    /// @brief Constructs a server connection over an accepted httpd session
    SendspinServerConnection(httpd_handle_t server, int sockfd, SendBlockPool& send_pool);

    ~SendspinServerConnection() override = default;

    // ========================================
    // SendspinConnection interface implementation
    // ========================================

    /// @brief Starts the connection (initializes time filter, prepares for messages)
    void start() override;

    /// @brief Queues a goodbye carrying @p reason to the httpd worker, then calls
    /// trigger_close(), which httpd serves after the queued goodbye.
    void disconnect(SendspinGoodbyeReason reason) override;

    /// @brief Closes the transport immediately without blocking (see base class doc comment).
    /// Delegates to trigger_close(), the same async primitive disconnect() closes with.
    void close_transport_now() override;

    /// @brief Whether the socket connection is valid
    bool is_connected() const override;

    /// @brief Marks the connection closed after the httpd session ends
    ///
    /// Called from the ws server's close notification (httpd thread). Without this,
    /// is_connected() stayed true until the protocol task dropped the connection,
    /// and a queued async send in that window could resolve the stale sockfd against a
    /// recycled httpd session and write the frame to the wrong peer.
    void mark_closed() {
        this->closed_.store(true, std::memory_order_release);
    }

    /// @brief Sends a text message to the connected client (async, via httpd worker)
    SsErr send_text_message(const std::string& message) override;

    /// @brief Sends a binary WebSocket frame to the connected client (async, via httpd worker)
    SsErr send_binary_message(const uint8_t* data, size_t len) override;

    /// @brief Triggers the underlying socket to close
    ///
    /// This is a low-level method that directly triggers the httpd session to close.
    /// It does not send a goodbye message first.
    ///
    /// Relationship with disconnect():
    /// - disconnect() is the high-level API that queues a goodbye message, then calls
    ///   trigger_close(), which httpd serves after the queued goodbye.
    /// - trigger_close() is the low-level mechanism that actually closes the socket.
    ///
    /// Use disconnect() for graceful shutdown. Use trigger_close() only when you
    /// need to force-close without sending goodbye (e.g., after goodbye is already sent).
    ///
    /// Only the first call queues a close; later ones return (see close_triggered_).
    void trigger_close();

    /// @brief Receives one WebSocket frame and hands it to the protocol task: a single-frame
    /// message straight into its ring item (or, before admission, the fallback buffer), a frame of
    /// a multi-frame message into the fallback buffer it is assembled in. On the httpd task.
    /// @param req The httpd request containing the WebSocket frame.
    /// @param receive_time Timestamp when the data was received.
    /// @param server The server whose discard buffer a dropped frame is read into.
    /// @return ESP_OK on success; an error makes httpd close the session.
    esp_err_t handle_data(httpd_req_t* req, int64_t receive_time, SendspinWsServer* server);

protected:
    /// @brief Queues the frame like send_binary_message(), carrying `before_write` to the httpd
    /// worker, which runs it immediately before httpd_ws_send_frame_async()
    SsErr send_transport_frame(const uint8_t* data, size_t len,
                               const NoiseTransport::FrameWriteHook& before_write) override;

    /// @brief Places an AsyncRespArg and a copy of the payload in one block (see AsyncRespArg) and
    /// queues it on the httpd worker to be sent as a text or binary frame by async_send_frame()
    ///
    /// Shared by send_text_message(), send_binary_message() and send_transport_frame(); `type`
    /// selects the WebSocket frame type and which of their (identical apart from wording) log
    /// messages is used.
    /// @param data              Payload bytes to copy and send.
    /// @param len               Number of bytes in `data`.
    /// @param type              HTTPD_WS_TYPE_TEXT or HTTPD_WS_TYPE_BINARY.
    /// @param before_write      Run by the worker immediately before the write, if set.
    SsErr queue_async_send(const uint8_t* data, size_t len, httpd_ws_type_t type,
                           const NoiseTransport::FrameWriteHook& before_write);

    /// @brief Receives the payload of the frame whose header `ws_pkt` holds into `dest`, which has
    /// room for ws_pkt.len bytes. A zero-length frame reads nothing.
    static esp_err_t receive_frame_payload(httpd_req_t* req, httpd_ws_frame_t& ws_pkt,
                                           uint8_t* dest);

    /// @brief Reads and discards the payload of the frame whose header `ws_pkt` holds, into the
    /// server's discard buffer (SendspinWsServer::discard_buffer())
    /// @return ESP_FAIL, closing the session, when the frame is too large to be a message or the
    ///         discard buffer cannot be allocated.
    static esp_err_t discard_frame_payload(httpd_req_t* req, httpd_ws_frame_t& ws_pkt,
                                           SendspinWsServer* server);

    /// @brief httpd_queue_work callback that sends a queued text or binary frame over the
    /// WebSocket
    /// @param arg Pointer to the AsyncRespArg context allocated by queue_async_send().
    static void async_send_frame(void* arg);

    // Pointer fields

    /// @brief The httpd server handle (owned by SendspinWsServer)
    httpd_handle_t server_;

    /// @brief Blocks for queued sends (owned by SendspinWsServer)
    SendBlockPool* send_pool_;

    // 32-bit fields

    /// @brief The socket file descriptor for this connection
    int sockfd_{-1};

    // 8-bit fields

    /// @brief Set once the httpd session has closed (see mark_closed()). Written on the httpd
    /// thread; read by is_connected() on any thread.
    std::atomic<bool> closed_{false};

    /// @brief Set by the first trigger_close() (protocol task, or the httpd worker after a
    /// goodbye). closed_ only flips when httpd runs the close, so without this a second close
    /// queued before then could reach a session httpd has since accepted onto the same slot.
    std::atomic<bool> close_triggered_{false};
};

}  // namespace sendspin
