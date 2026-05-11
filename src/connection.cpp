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

#include "platform/compiler.h"
#include "platform/logging.h"
#include "time_filter.h"

#include <memory>

namespace sendspin {

static const char* const TAG = "sendspin.connection";

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinConnection::~SendspinConnection() = default;

// ============================================================================
// Time filter
// ============================================================================

void SendspinConnection::init_time_filter() {
    this->time_filter_ = std::make_unique<SendspinTimeFilter>(SendspinTimeFilter::Config{});
}

// ============================================================================
// Message sending
// ============================================================================

SsErr SendspinConnection::send_goodbye_reason(SendspinGoodbyeReason reason,
                                              SendCompleteCallback on_complete) {
    return this->send_text_message(format_client_goodbye_message(reason), std::move(on_complete));
}

// ============================================================================
// WebSocket payload buffer management
// ============================================================================

void SendspinConnection::deallocate_websocket_payload() {
    this->websocket_payload_.reset();
    this->websocket_write_offset_ = 0;
}

void SendspinConnection::reset_websocket_payload() {
    this->websocket_write_offset_ = 0;
}

uint8_t* SendspinConnection::prepare_receive_buffer(size_t data_len) {
    if (!this->websocket_payload_) {
        // First fragment - allocate new buffer
        if (!this->websocket_payload_.allocate(data_len, this->websocket_payload_location_)) {
            SS_LOGE(TAG, "Failed to allocate %zu bytes for websocket payload", data_len);
            return nullptr;
        }
        this->websocket_write_offset_ = 0;
    } else if (this->websocket_write_offset_ + data_len > this->websocket_payload_.size()) {
        // Need to expand buffer for additional fragment
        size_t new_len = this->websocket_write_offset_ + data_len;
        if (!this->websocket_payload_.realloc(new_len)) {
            SS_LOGE(TAG, "Failed to expand websocket payload to %zu bytes", new_len);
            this->deallocate_websocket_payload();
            return nullptr;
        }
    }

    return this->websocket_payload_.data() + this->websocket_write_offset_;
}

void SendspinConnection::commit_receive_buffer(size_t data_len) {
    this->websocket_write_offset_ += data_len;
}

SS_HOT void SendspinConnection::dispatch_completed_message(bool is_text, int64_t receive_time) {
    if (!this->websocket_payload_) {
        return;
    }

    if (!this->message_dispatch_enabled_.load(std::memory_order_acquire)) {
        this->reset_websocket_payload();
        return;
    }

    if (is_text) {
        // Hand the JSON callback a pointer straight into the reassembly buffer instead of copying
        // it into a std::string. The callback parses synchronously; reset_websocket_payload()
        // below makes the buffer reusable as soon as it returns, so the callback must not retain
        // the pointer. Not null-terminated; the length is authoritative.
        if (this->on_json_message_cb) {
            this->on_json_message_cb(this,
                                     reinterpret_cast<const char*>(this->websocket_payload_.data()),
                                     this->websocket_write_offset_, receive_time);
        }
    } else {
        // Binary message - connection retains buffer ownership, callback reads in-place
        if (this->on_binary_message_cb) {
            this->on_binary_message_cb(this, this->websocket_payload_.data(),
                                       this->websocket_write_offset_);
        }
    }

    // Reset write offset for next message; keep buffer allocated for reuse
    this->reset_websocket_payload();
}

}  // namespace sendspin
