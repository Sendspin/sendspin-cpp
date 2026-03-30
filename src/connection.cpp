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

#include "connection.h"

#include "platform/logging.h"
#include "platform/time.h"
#include "time_filter.h"
#include <ArduinoJson.h>

#include <memory>

namespace sendspin {

static const char* const TAG = "sendspin.connection";

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinConnection::~SendspinConnection() = default;

// ============================================================================
// WebSocket payload buffer management
// ============================================================================

void SendspinConnection::deallocate_websocket_payload_() {
    this->websocket_payload_.reset();
    this->websocket_write_offset_ = 0;
}

void SendspinConnection::reset_websocket_payload_() {
    this->websocket_write_offset_ = 0;
}

// ============================================================================
// Time filter
// ============================================================================

void SendspinConnection::init_time_filter() {
    this->time_filter_ = std::make_unique<SendspinTimeFilter>(
        TIME_FILTER_PROCESS_STD_DEV, TIME_FILTER_DRIFT_PROCESS_STD_DEV, TIME_FILTER_FORGET_FACTOR,
        TIME_FILTER_ADAPTIVE_CUTOFF, TIME_FILTER_MIN_SAMPLES,
        TIME_FILTER_DRIFT_SIGNIFICANCE_THRESHOLD);
    if (!this->time_replacement_queue_.is_created()) {
        this->time_replacement_queue_.create(1);
    }
}

TimeTransmittedReplacement SendspinConnection::peek_time_replacement() const {
    TimeTransmittedReplacement replacement{};
    this->time_replacement_queue_.peek(replacement);
    return replacement;
}

// ============================================================================
// Message sending
// ============================================================================

bool SendspinConnection::send_time_message(SendCompleteCallback cb) {
    int64_t now = platform_time_us();

    // Build the time message using ArduinoJson directly
    JsonDocument doc = make_json_document();
    doc["type"] = "client/time";
    doc["payload"]["client_transmitted"] = now;
    std::string serialized_text;
    serializeJson(doc, serialized_text);

    // Wrap the caller's callback to push the time replacement into the queue
    // after the message is actually sent. This is thread-safe: the queue handles
    // synchronization between the send thread and the receive thread.
    auto* queue = &this->time_replacement_queue_;
    auto wrapped_cb = [now, queue, cb = std::move(cb)](bool success, int64_t actual_send_time) {
        if (success && queue->is_created()) {
            TimeTransmittedReplacement replacement{now, actual_send_time};
            queue->overwrite(replacement);
        }
        if (cb) {
            cb(success, actual_send_time);
        }
    };

    return this->send_text_message(serialized_text, std::move(wrapped_cb)) == SsErr::OK;
}

SsErr SendspinConnection::send_goodbye_reason(SendspinGoodbyeReason reason,
                                              SendCompleteCallback on_complete) {
    return this->send_text_message(format_client_goodbye_message(reason), std::move(on_complete));
}

uint8_t* SendspinConnection::prepare_receive_buffer_(size_t data_len) {
    if (!this->websocket_payload_) {
        // First fragment - allocate new buffer
        if (!this->websocket_payload_.allocate(data_len)) {
            SS_LOGE(TAG, "Failed to allocate %zu bytes for websocket payload", data_len);
            return nullptr;
        }
        this->websocket_write_offset_ = 0;
    } else if (this->websocket_write_offset_ + data_len > this->websocket_payload_.size()) {
        // Need to expand buffer for additional fragment
        size_t new_len = this->websocket_write_offset_ + data_len;
        if (!this->websocket_payload_.realloc(new_len)) {
            SS_LOGE(TAG, "Failed to expand websocket payload to %zu bytes", new_len);
            this->deallocate_websocket_payload_();
            return nullptr;
        }
    }

    return this->websocket_payload_.data() + this->websocket_write_offset_;
}

void SendspinConnection::commit_receive_buffer_(size_t data_len) {
    this->websocket_write_offset_ += data_len;
}

void SendspinConnection::dispatch_completed_message_(bool is_text, int64_t receive_time) {
    if (!this->websocket_payload_) {
        return;
    }

    if (!this->message_dispatch_enabled_.load(std::memory_order_acquire)) {
        this->reset_websocket_payload_();
        return;
    }

    if (is_text) {
        // Create string from payload for JSON processing
        const std::string message(this->websocket_payload_.data(),
                                  this->websocket_payload_.data() + this->websocket_write_offset_);

        // Invoke JSON message callback
        if (this->on_json_message) {
            this->on_json_message(this, message, receive_time);
        }
    } else {
        // Binary message - connection retains buffer ownership, callback reads in-place
        if (this->on_binary_message) {
            this->on_binary_message(this, this->websocket_payload_.data(),
                                    this->websocket_write_offset_);
        }
    }

    // Reset write offset for next message; keep buffer allocated for reuse
    this->reset_websocket_payload_();
}

}  // namespace sendspin
