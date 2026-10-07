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
#include "outbound_ring.h"
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

/// @brief Bytes per lent-send block: an AsyncRespArg alone, the frame staying in its outbound
/// ring item
static constexpr size_t LENT_BLOCK_SIZE = 64;

/// @brief Lent-send blocks per server: one per item the lending ring can have out at once, since
/// each claimed block holds a distinct item. One ring (the source role's) lends to the server,
/// and it reserves every item at its largest size (see OutboundRing, "Item sizes"). A lent block
/// never falls back to the heap, so SendspinServerConnection::reclaim_discarded_sends() can find
/// every one.
static constexpr size_t LENT_BLOCK_COUNT = OUTBOUND_RING_ITEM_COUNT;

/// @brief Pool the ESP server's lent sends take their header blocks from
using LentBlockPool = FixedBlockPool<LENT_BLOCK_SIZE, LENT_BLOCK_COUNT>;

/// @brief The block pools for one server's queued sends, owned by SendspinWsServer
struct SendBlockPools {
    /// Header plus a copy of the frame
    SendBlockPool copied;
    /// Header only, for a frame lent from an outbound ring item (send_lent_frame())
    LentBlockPool lent;
};

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
    SendspinServerConnection(httpd_handle_t server, int sockfd, SendBlockPools& send_pools);

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

    /// @brief Destroys the queued sends httpd discarded at its shutdown, returning each lent
    /// frame's item to its ring, then marks every block free
    ///
    /// httpd drops work queued after its shutdown without running it, so the AsyncRespArg in each
    /// block that work held is never destroyed and a lent item never returned: leaked storage in
    /// a ring that outlives the server, whose owner counts on every item coming back before it
    /// destroys the ring. Call only after httpd_stop() succeeded, with the protocol task joined
    /// and the httpd task stopped (see OutboundRing, "Lifetime").
    /// @param pools The stopped server's pools.
    static void reclaim_discarded_sends(SendBlockPools& pools);

    /// @brief Receives one WebSocket frame and hands it to the protocol task: a single-frame
    /// message straight into its ring item (or, before admission, the fallback buffer), a frame of
    /// a multi-frame message into the fallback buffer it is assembled in. On the httpd task.
    /// @param req The httpd request containing the WebSocket frame.
    /// @param server The server whose discard buffer a dropped frame is read into.
    /// @return ESP_OK on success; an error makes httpd close the session.
    esp_err_t handle_data(httpd_req_t* req, SendspinWsServer* server);

protected:
    /// @brief Queues the frame like send_binary_message(), carrying `before_write` to the httpd
    /// worker, which runs it immediately before httpd_ws_send_frame_async()
    SsErr send_transport_frame(const uint8_t* data, size_t len,
                               const NoiseTransport::FrameWriteHook& before_write) override;

    /// @brief Queues the lent frame on the httpd worker without copying it: the queued work keeps
    /// the item, and async_send_frame() returns it to its ring once the frame is written or
    /// dropped. A block from the lent pool carries it, never the heap.
    SsErr send_lent_frame(OutboundRing& ring, void* item, size_t len) override;

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
    SendBlockPools* send_pools_;

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
