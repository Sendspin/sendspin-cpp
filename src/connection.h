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

/// @file connection.h
/// @brief Abstract base class for Sendspin WebSocket connections, providing handshake, time sync,
/// and message buffering

#pragma once

#include "platform/memory.h"
#include "platform/types.h"
#include "protocol_messages.h"
#include "time_filter.h"

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace sendspin {

/// @brief Callback type for message send completion
/// @param success True if the message was sent successfully, false otherwise.
/// @param timestamp The actual timestamp when the message was sent (in microseconds).
using SendCompleteCallback = std::function<void(bool, int64_t)>;

/**
 * @brief Abstract base class for Sendspin connections (server-initiated or client-initiated)
 *
 * This class represents a single connection to a Sendspin server. It manages connection state,
 * time synchronization, message buffering, and the hello handshake. Derived classes implement
 * the actual transport mechanism (e.g., incoming WebSocket server connection or outgoing client).
 *
 * The hub owns connection instances and uses callbacks to receive notifications about messages,
 * handshake completion, and disconnection events.
 *
 * Key responsibilities:
 * - Abstract base for platform-specific WebSocket transports (server and client variants)
 * - Owns and drives the time filter (Kalman-based NTP-style synchronization)
 * - Manages the reassembly payload buffer for fragmented WebSocket frames
 * - Tracks hello handshake state (client_hello_sent / server_hello_received)
 *
 * Usage:
 * 1. Construct a concrete subclass (SendspinServerConnection or SendspinClientConnection)
 * 2. Set the on_connected_cb, on_handshake_complete_cb, on_disconnected_cb, on_json_message_cb,
 *    and on_binary_message_cb callbacks
 * 3. Call start() to initialize the transport and begin connecting
 * 4. Call loop() periodically to drive the state machine and process events
 * 5. Call send_text_message() to send JSON messages to the peer
 * 6. Call disconnect() to send a goodbye message and close the connection
 *
 * @code
 * // Concrete subclass provided by the platform layer
 * auto conn = std::make_unique<SendspinClientConnection>(url, config);
 * conn->on_connected_cb = [](SendspinConnection* c) { c->send_text_message(hello_json, {}); };
 * conn->on_json_message_cb = [](SendspinConnection* c, const std::string& msg, int64_t t) { ... };
 * conn->on_disconnected_cb = [](SendspinConnection* c) { handle_disconnect(); };
 * conn->start();
 * // Call conn->loop() from a periodic task
 * @endcode
 */
class SendspinConnection : public std::enable_shared_from_this<SendspinConnection> {
public:
    virtual ~SendspinConnection();

    /// @brief Starts the connection (e.g., initiates client connection or begins message
    /// processing)
    virtual void start() = 0;

    /// @brief Periodic loop processing (e.g., poll for events, handle state machine)
    virtual void loop() = 0;

    /// @brief Disconnects from the server with a goodbye message
    /// @param reason The reason for disconnecting (e.g., shutdown, another server).
    /// @param on_complete Optional callback invoked after goodbye is sent (or send fails/times
    /// out).
    ///                    For server connections, invoked from httpd worker thread (use defer() if
    ///                    needed). For client connections, invoked synchronously in the calling
    ///                    thread.
    virtual void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) = 0;

    /// @brief Checks if the transport connection is established
    /// @return true if connected, false otherwise.
    virtual bool is_connected() const = 0;

    /// @brief Prevents any further message callbacks from firing on the network thread
    ///
    /// Called on the main thread before connection cleanup so that no stale events from a dying
    /// connection can sneak into role queues after they've been reset. Thread-safe: the flag is
    /// checked atomically in dispatch_completed_message() which runs on the network thread.
    void disable_message_dispatch() {
        this->message_dispatch_enabled_.store(false, std::memory_order_release);
    }

    /// @brief Checks if the hello handshake has completed successfully
    /// @return true if handshake complete (hello exchange done), false otherwise.
    bool is_handshake_complete() const {
        return this->client_hello_sent_ && this->server_hello_received_;
    }

    /// @brief Gets the socket file descriptor for this connection
    /// @return Socket fd for server connections, -1 for client connections.
    /// @note Used by the hub to identify which connection closed when notified by the server.
    virtual int get_sockfd() const {
        return -1;
    }

    /// @brief Sends a text message to the server with a completion callback
    /// @param msg The message string to send.
    /// @param cb Callback invoked after send completes (success, actual_send_time).
    /// @return SsErr::OK if queued successfully, error code otherwise.
    virtual SsErr send_text_message(const std::string& message, SendCompleteCallback cb) = 0;

    /// @brief Sends a client/time synchronization message
    ///
    /// The transport implementation captures `client_transmitted` as close to the actual wire
    /// send as possible (e.g., inside the httpd worker on ESP server, just before
    /// `httpd_ws_send_frame_async`) and serializes the JSON inline. This eliminates the queue
    /// latency variance that a hub-thread timestamp would introduce.
    ///
    /// @return true if the message was queued/sent successfully, false otherwise.
    virtual bool send_time_message() = 0;

    /// @brief Sends a goodbye message with completion callback
    /// @param reason The reason for disconnecting.
    /// @param on_complete Callback invoked after the goodbye message is sent (or fails).
    /// @return SsErr::OK if sent successfully, error code otherwise.
    SsErr send_goodbye_reason(SendspinGoodbyeReason reason, SendCompleteCallback on_complete);

    // ========================================
    // Server information accessors (populated after server/hello message is received)
    // ========================================

    /// @brief Gets the connection reason from the server/hello message
    /// @return The connection reason (discovery or playback).
    SendspinConnectionReason get_connection_reason() const {
        return this->connection_reason_;
    }

    /// @brief Gets the server ID from the server/hello message
    /// @return The server ID string (empty until hello is received).
    const std::string& get_server_id() const {
        return this->server_information_.server_id;
    }

    /// @brief Gets the server information from the server/hello message
    /// @return The ServerInformationObject (fields empty until hello is received).
    const ServerInformationObject& get_server_information() const {
        return this->server_information_;
    }

    // ========================================
    // Callbacks set by the hub to receive notifications
    // ========================================

    /// @brief Callback invoked when a JSON message is received
    /// @param conn Pointer to this connection.
    /// @param message The JSON message string.
    /// @param timestamp The client timestamp when the message was received.
    std::function<void(SendspinConnection*, const std::string&, int64_t)> on_json_message_cb;

    /// @brief Callback invoked when a binary message is received
    /// @param conn Pointer to this connection.
    /// @param payload Pointer to the binary message data (owned by connection, valid until callback
    /// returns).
    /// @param len Length of the binary message data.
    std::function<void(SendspinConnection*, uint8_t*, size_t)> on_binary_message_cb;

    /// @brief Callback invoked when the transport connection is ready for messaging
    /// @param conn Pointer to this connection.
    /// @note For server connections, this is called when the WebSocket handshake completes.
    ///       For client connections, this is called when the connection to server succeeds.
    ///       The hub uses this to initiate the hello handshake.
    std::function<void(SendspinConnection*)> on_connected_cb;

    /// @brief Callback invoked when the hello handshake completes successfully
    /// @param conn Pointer to this connection.
    std::function<void(SendspinConnection*)> on_handshake_complete_cb;

    /// @brief Callback invoked when the connection is closed or lost
    /// @param conn Pointer to this connection.
    std::function<void(SendspinConnection*)> on_disconnected_cb;

    /// @brief Converts a server timestamp to the equivalent client timestamp
    /// @param server_time Server timestamp in microseconds.
    /// @return Equivalent client timestamp in microseconds (0 if time filter not initialized).
    int64_t get_client_time(int64_t server_time) const {
        if (this->time_filter_ == nullptr) {
            return 0;
        }
        return this->time_filter_->compute_client_time(server_time);
    }

    /// @brief Gets the time filter for this connection
    /// @return Pointer to the time filter, or nullptr if not initialized.
    SendspinTimeFilter* get_time_filter() {
        return this->time_filter_.get();
    }

    /// @brief Returns true if the time filter has received at least one measurement
    /// @return True if time synchronization has started, false otherwise.
    bool is_time_synced() const {
        if (this->time_filter_ == nullptr) {
            return false;
        }
        return this->time_filter_->has_update();
    }

    /// @brief Initializes the time filter with Kalman parameters
    void init_time_filter();

    /// @brief Returns the EMA (microseconds) of how long format_client_time_message() takes
    ///
    /// Updated by `send_time_message()` on each call. The serialization happens between when
    /// `client_transmitted` is captured and when the bytes hit the wire, so this EMA estimates
    /// the constant bias subtracted from the embedded timestamp. Reported alongside per-burst
    /// stats for diagnostics. Atomic so the httpd worker (ESP server) can update it while the
    /// hub thread reads it.
    int64_t get_serialize_ema_us() const {
        return this->serialize_ema_us_.load(std::memory_order_relaxed);
    }

    /// @brief Folds a new serialization-duration sample into the EMA (1/16 weight)
    /// @param sample_us Measured duration in microseconds.
    void update_serialize_ema(int64_t sample_us) {
        int64_t prev = this->serialize_ema_us_.load(std::memory_order_relaxed);
        const int64_t next = (prev == 0) ? sample_us : ((prev * 15 + sample_us) / 16);
        this->serialize_ema_us_.store(next, std::memory_order_relaxed);
    }

    // ========================================
    // Configuration setters (called by hub after receiving server/hello message)
    // ========================================

    /// @brief Sets the client hello sent flag
    /// @param sent True if client hello message has been sent.
    /// @note Called by hub to track handshake state.
    void set_client_hello_sent(bool sent) {
        this->client_hello_sent_ = sent;
    }

    /// @brief Sets the connection reason (from server/hello message)
    /// @param reason The connection reason.
    /// @note Called by hub after receiving server/hello message.
    void set_connection_reason(SendspinConnectionReason reason) {
        this->connection_reason_ = reason;
    }

    /// @brief Sets the server hello received flag
    /// @param received True if server hello message has been received.
    /// @note Called by hub when SERVER_HELLO is processed.
    void set_server_hello_received(bool received) {
        this->server_hello_received_ = received;
    }

    /// @brief Sets the server information (from server/hello message)
    /// @param info The ServerInformationObject received during the hello handshake.
    /// @note Called by hub after receiving server/hello message.
    void set_server_information(ServerInformationObject info) {
        this->server_information_ = std::move(info);
    }

    // ========================================
    // Time message state accessors
    // ========================================

    /// @brief Sets the timestamp of the last sent time message
    /// @param timestamp The timestamp of the last sent time message
    void set_last_sent_time_message(int64_t timestamp) {
        this->last_sent_time_message_ = timestamp;
    }

    /// @brief Checks if a time message is pending (waiting for response)
    /// @return True if a time message has been sent and a response is expected, false otherwise.
    bool is_pending_time_message() const {
        return this->pending_time_message_;
    }

    /// @brief Sets the pending time message flag
    /// @param pending true if a time message is pending, false to clear the flag
    void set_pending_time_message(bool pending) {
        this->pending_time_message_ = pending;
    }

protected:
    /// @brief Deallocates the websocket payload buffer if allocated
    void deallocate_websocket_payload();

    /// @brief Resets the write offset without freeing the buffer (reuses it for the next message)
    void reset_websocket_payload();

    /// @brief Allocates or grows the websocket payload buffer and returns a pointer to the write
    /// position
    ///
    /// For the first fragment, allocates a new buffer of the given size.
    /// For continuation fragments, reallocates to grow the buffer if needed.
    ///
    /// @param data_len Number of bytes that will be written.
    /// @return Pointer to the write position (websocket_payload_ + websocket_write_offset_), or
    /// nullptr on failure.
    uint8_t* prepare_receive_buffer(size_t data_len);

    /// @brief Advances the write offset after data has been written into the buffer
    /// @param data_len Number of bytes that were written.
    void commit_receive_buffer(size_t data_len);

    /// @brief Dispatches a fully assembled message to the appropriate callback
    ///
    /// For text messages: creates a std::string from the buffer, invokes on_json_message_cb,
    /// deallocates buffer. For binary messages: invokes on_binary_message_cb callback. If the
    /// buffer is null, does nothing.
    ///
    /// @param is_text True if this is a text message, false for binary.
    /// @param receive_time Timestamp when the data was received (microseconds).
    void dispatch_completed_message(bool is_text, int64_t receive_time);

    // Struct fields

    /// Message buffering (for websocket frame assembly).
    PlatformBuffer websocket_payload_;

    /// Server identity (from server/hello message).
    ServerInformationObject server_information_{};

    // Pointer fields

    /// Time synchronization filter (Kalman-based).
    std::unique_ptr<SendspinTimeFilter> time_filter_;

    // 64-bit fields

    /// EMA (microseconds) of format_client_time_message() duration. Atomic because the ESP
    /// server worker thread updates it while the hub thread reads it for logging.
    std::atomic<int64_t> serialize_ema_us_{0};

    /// Time message state.
    int64_t last_sent_time_message_{0};

    // size_t fields
    size_t websocket_write_offset_{0};

    // 32-bit fields

    /// Connection reason (discovery or playback, from server/hello).
    SendspinConnectionReason connection_reason_{SendspinConnectionReason::DISCOVERY};

    // 8-bit fields

    /// Hello handshake state.
    bool client_hello_sent_{false};

    /// true if the current message being assembled is text, false if binary
    /// Needed because WebSocket continuation frames do not carry the original frame type
    bool is_text_frame_{false};

    /// When false, dispatch_completed_message() silently drops incoming messages.
    /// Set to false on the main thread before cleanup; checked on the network thread.
    std::atomic<bool> message_dispatch_enabled_{true};

    /// Time message state.
    bool pending_time_message_{false};
    bool server_hello_received_{false};
};

}  // namespace sendspin
