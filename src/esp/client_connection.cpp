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

#include "client_connection.h"

#include "platform/logging.h"
#include "platform/types.h"
#include "protocol_messages.h"
#include "sendspin/types.h"
#include <esp_err.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <cstring>
#include <limits>
#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.client_connection";
// The component's Kconfig selects ESP_WS_CLIENT_SEPARATE_TX_LOCK, so this timeout is spent only
// on other sends, not on the lock the client task holds while handle_data() waits for inbound
// ring space. The exception is a failed write: esp_websocket_client then takes that lock with no
// timeout to abort the connection, so the send waits out the handler's park (bounded by its
// inbound waits, InboundGate::WRITABLE_WAIT_MS and INBOUND_ACQUIRE_TIMEOUT_MS, plus the rest of
// the frame) rather than deadlocking.
static constexpr uint32_t WEBSOCKET_SEND_TIMEOUT_MS = 10U;

// WebSocket frame opcodes (RFC 6455)
static constexpr uint8_t WS_OP_CONTINUATION = 0x00U;
static constexpr uint8_t WS_OP_TEXT = 0x01U;
static constexpr uint8_t WS_OP_BINARY = 0x02U;
static constexpr uint8_t WS_OP_CLOSE = 0x08U;
static constexpr uint8_t WS_OP_PING = 0x09U;
static constexpr uint8_t WS_OP_PONG = 0x0AU;

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinClientConnection::SendspinClientConnection(std::string url) : url_(std::move(url)) {}

SendspinClientConnection::~SendspinClientConnection() {
    if (this->client_ != nullptr) {
        esp_websocket_client_stop(this->client_);
        esp_websocket_client_destroy(this->client_);
        this->client_ = nullptr;
    }
    // The stop can end the websocket task between two chunks of a message; the ring item it was
    // receiving into must still be completed.
    this->abandon_inbound_message();
}

void SendspinClientConnection::start() {
    if (this->client_ != nullptr) {
        SS_LOGW(TAG, "Client already started, stopping first");
        esp_websocket_client_stop(this->client_);
        esp_websocket_client_destroy(this->client_);
        this->client_ = nullptr;
    }

    // Configure the websocket client
    esp_websocket_client_config_t config = {};
    config.uri = this->url_.c_str();
    config.disable_auto_reconnect = true;  // A lost connection is not reopened
    config.task_prio = static_cast<int>(this->task_priority_);
    // Clamp to the documented minimum, the value shipped and verified on hardware (see
    // SendspinClientConfig::DEFAULT_WEBSOCKET_STACK_SIZE), until this task's receive path is
    // measured.
    size_t task_stack_size = this->task_stack_size_;
    if (task_stack_size < SendspinClientConfig::DEFAULT_WEBSOCKET_STACK_SIZE) {
        SS_LOGW(TAG, "websocket_stack_size %u below minimum %u; clamping",
                static_cast<unsigned>(task_stack_size),
                static_cast<unsigned>(SendspinClientConfig::DEFAULT_WEBSOCKET_STACK_SIZE));
        task_stack_size = SendspinClientConfig::DEFAULT_WEBSOCKET_STACK_SIZE;
    }
    // esp_websocket_client's task_stack field is int; bound the size_t config value so an
    // absurd setting cannot wrap negative instead of just failing task creation.
    if (task_stack_size > static_cast<size_t>(std::numeric_limits<int>::max())) {
        task_stack_size = static_cast<size_t>(std::numeric_limits<int>::max());
    }
    config.task_stack = static_cast<int>(task_stack_size);

    // Create the client
    this->client_ = esp_websocket_client_init(&config);
    if (this->client_ == nullptr) {
        SS_LOGE(TAG, "Failed to initialize websocket client");
        return;
    }

    // Register event handler
    esp_websocket_register_events(this->client_, WEBSOCKET_EVENT_ANY, websocket_event_handler,
                                  this);

    // Start the client
    esp_err_t err = esp_websocket_client_start(this->client_);
    if (err != ESP_OK) {
        SS_LOGE(TAG, "Failed to start websocket client: %s", esp_err_to_name(err));
        esp_websocket_client_destroy(this->client_);
        this->client_ = nullptr;
        return;
    }

    SS_LOGD(TAG, "Client connection starting to %s", this->url_.c_str());
}

// ============================================================================
// SendspinConnection interface implementation
// ============================================================================

void SendspinClientConnection::disconnect(SendspinGoodbyeReason reason,
                                          std::function<void()> on_complete) {
    if (!this->is_connected()) {
        // Not connected: invoke completion callback immediately if provided
        if (on_complete) {
            on_complete();
        }
        return;
    }

    // Send goodbye message and then stop client
    // For client connections, send_text_message is synchronous, so callback fires immediately
    this->send_goodbye_reason(reason, [this, on_complete](bool success) {
        // Stop the client regardless of send success
        if (this->client_ != nullptr) {
            esp_websocket_client_stop(this->client_);
        }

        // Invoke user-provided completion callback if provided
        if (on_complete) {
            on_complete();
        }
    });
}

void SendspinClientConnection::close_transport_now() {
    // esp_websocket_client_stop() (used by disconnect() above) cannot be called from the
    // websocket task's own event handler (see esp_websocket_client.h's doc comment on
    // esp_websocket_client_stop()): it blocks until that task exits, which deadlocks when called
    // from within the task itself. Stop taking frames without touching the transport; the
    // protocol task reports the loss (the inbound gate is detached by every caller), and the
    // manager drops this connection, whose destructor calls esp_websocket_client_stop() to
    // actually stop it, off the websocket task.
    this->connected_ = false;
}

bool SendspinClientConnection::is_connected() const {
    return this->connected_;
}

SsErr SendspinClientConnection::send_text_message(const std::string& message,
                                                  SendCompleteCallback cb,
                                                  bool /*allow_before_hello*/) {
    if (!this->is_connected()) {
        if (cb) {
            cb(false);
        }
        return SsErr::INVALID_STATE;
    }

    // esp_websocket_client_send_text is synchronous in the current task
    int sent = esp_websocket_client_send_text(this->client_, message.c_str(), message.length(),
                                              pdMS_TO_TICKS(WEBSOCKET_SEND_TIMEOUT_MS));

    bool success = (sent >= 0);

    if (cb) {
        cb(success);
    }

    if (!success) {
        SS_LOGE(TAG, "Failed to send text message (timeout or error): %d", sent);
        return SsErr::FAIL;
    }

    return SsErr::OK;
}

SsErr SendspinClientConnection::send_binary_message(const uint8_t* data, size_t len,
                                                    SendCompleteCallback cb,
                                                    bool /*allow_before_hello*/) {
    if (!this->is_connected()) {
        if (cb) {
            cb(false);
        }
        return SsErr::INVALID_STATE;
    }

    int sent = esp_websocket_client_send_bin(this->client_, reinterpret_cast<const char*>(data),
                                             static_cast<int>(len),
                                             pdMS_TO_TICKS(WEBSOCKET_SEND_TIMEOUT_MS));

    bool success = (sent >= 0);

    if (cb) {
        cb(success);
    }

    if (!success) {
        SS_LOGE(TAG, "Failed to send binary message (timeout or error): %d", sent);
        return SsErr::FAIL;
    }

    return SsErr::OK;
}

// ============================================================================
// Private helpers / callbacks
// ============================================================================

void SendspinClientConnection::websocket_event_handler(void* handler_args, esp_event_base_t base,
                                                       int32_t event_id, void* event_data) {
    // Capture receive time immediately for accurate time synchronization
    int64_t receive_time = esp_timer_get_time();

    SendspinClientConnection* conn = static_cast<SendspinClientConnection*>(handler_args);

    switch (event_id) {
        case WEBSOCKET_EVENT_CONNECTED:
            conn->handle_connected();
            break;
        case WEBSOCKET_EVENT_DISCONNECTED:
            conn->handle_disconnected();
            break;
        case WEBSOCKET_EVENT_DATA:
            conn->handle_data(static_cast<esp_websocket_event_data_t*>(event_data), receive_time);
            break;
        case WEBSOCKET_EVENT_ERROR:
            conn->handle_error();
            break;
        default:
            break;
    }
}

void SendspinClientConnection::handle_connected() {
    SS_LOGD(TAG, "WebSocket connected to %s", this->url_.c_str());
    this->connected_ = true;

    // Invoke the on_connected_cb callback if set (hub uses this to initiate hello handshake)
    if (this->on_connected_cb) {
        this->on_connected_cb(this);
    }
}

void SendspinClientConnection::handle_disconnected() {
    SS_LOGD(TAG, "WebSocket disconnected from %s", this->url_.c_str());
    this->connected_ = false;
    this->client_hello_sent_ = false;
    this->server_hello_received_ = false;
    this->chunk_dest_ = nullptr;
    this->abandon_inbound_message();
    // The protocol task reports the loss once the messages before it are processed.
    this->notify_transport_closed();
}

void SendspinClientConnection::handle_data(const esp_websocket_event_data_t* data,
                                           int64_t receive_time) {
    // connected_ is cleared by close_transport_now() from another thread too, without stopping
    // the transport, so already-buffered frames keep arriving as further DATA events until the
    // manager drops the connection off this task; drop them here, completing a ring item a
    // message was being received into.
    if (!this->connected_) {
        this->chunk_dest_ = nullptr;
        this->abandon_inbound_message();
        return;
    }

    if (data == nullptr) {
        return;
    }

    // Determine frame type: text (0x01), binary (0x02), or continuation (0x00)
    const bool continuation = data->op_code == WS_OP_CONTINUATION;
    if (!continuation && data->op_code != WS_OP_TEXT && data->op_code != WS_OP_BINARY) {
        // Control frames (ping, pong, close): ignore
        return;
    }
    const bool is_text = data->op_code == WS_OP_TEXT;
    const auto offset = static_cast<size_t>(data->payload_offset);
    const auto chunk_len = static_cast<size_t>(data->data_len);
    const auto frame_len = static_cast<size_t>(data->payload_len);
    // esp_websocket_client delivers one frame's payload across as many events as its buffer
    // needs; the frame is done once its last chunk is in.
    const bool frame_done = offset + chunk_len >= frame_len;

    if (!continuation && data->fin) {
        // A single-frame message, the only kind a conforming peer sends: its chunks are copied
        // from the client's buffer straight into the message's destination, a ring item once the
        // connection is admitted. The destination is chosen on the first chunk, from the frame's
        // full length.
        if (offset == 0) {
            const InboundTarget target =
                this->begin_inbound_message(frame_len, is_text, receive_time);
            this->chunk_dest_ = target.route == InboundRoute::RECEIVE ? target.data : nullptr;
        }
        if (this->chunk_dest_ == nullptr) {
            return;
        }
        if (chunk_len > 0) {
            std::memcpy(this->chunk_dest_ + offset, data->data_ptr, chunk_len);
        }
        if (frame_done) {
            this->chunk_dest_ = nullptr;
            this->end_inbound_message(true);
        }
        return;
    }

    // A chunk of a multi-frame message (the rare path; see begin_inbound_fragment()).
    const bool first = !continuation && offset == 0;
    const bool last = data->fin && frame_done;
    const InboundTarget target =
        this->begin_inbound_fragment(chunk_len, first, is_text, receive_time);
    if (target.route == InboundRoute::RECEIVE) {
        if (chunk_len > 0) {
            std::memcpy(target.data, data->data_ptr, chunk_len);
        }
        this->end_inbound_fragment(chunk_len, last);
    } else if (target.route == InboundRoute::DROP) {
        this->end_inbound_fragment(0, last);
    }
}

void SendspinClientConnection::handle_error() {
    SS_LOGE(TAG, "WebSocket error on connection to %s", this->url_.c_str());
    // Error will typically be followed by a disconnect event
}

}  // namespace sendspin
