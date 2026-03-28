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

#include "sendspin/artwork_role.h"

#include "client_bridge.h"
#include "platform/logging.h"
#include "protocol_messages.h"

#include <mutex>

static const char* const TAG = "sendspin.artwork";

/// @brief Size of the big-endian 64-bit timestamp at the start of artwork binary messages.
static const size_t BINARY_TIMESTAMP_SIZE = 8;

/// @brief Swaps bytes of a big-endian 64-bit value to host byte order.
static int64_t be64_to_host(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}

namespace sendspin {

void ArtworkRole::attach(ClientBridge* bridge) {
    this->bridge_ = bridge;
}

void ArtworkRole::add_image_preferred_format(const ImageSlotPreference& pref) {
    this->preferred_image_formats_.push_back(pref);
    this->artwork_channels_.push_back({pref.source, pref.format, pref.width, pref.height});
}

void ArtworkRole::contribute_hello(ClientHelloMessage& msg) {
    if (this->artwork_channels_.empty()) {
        return;
    }
    msg.supported_roles.push_back(SendspinRole::ARTWORK);

    ArtworkSupportObject artwork_support = {
        .channels = this->artwork_channels_,
    };
    msg.artwork_v1_support = artwork_support;
}

void ArtworkRole::handle_binary(uint8_t slot, const uint8_t* data, size_t len) {
    if (this->preferred_image_formats_.empty() || !this->on_image) {
        return;
    }
    if (len < BINARY_TIMESTAMP_SIZE) {
        SS_LOGW(TAG, "Binary message too short for timestamp");
        return;
    }
    int64_t timestamp = be64_to_host(data);
    const uint8_t* image_data = data + BINARY_TIMESTAMP_SIZE;
    size_t image_len = len - BINARY_TIMESTAMP_SIZE;

    SendspinImageFormat image_format = SendspinImageFormat::JPEG;
    for (const auto& pref : this->preferred_image_formats_) {
        if (pref.slot == slot) {
            image_format = pref.format;
            break;
        }
    }
    this->on_image(slot, image_data, image_len, image_format, timestamp);
}

void ArtworkRole::handle_stream_end() {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);
    this->pending_stream_end_.push_back(true);
}

void ArtworkRole::drain_events(std::vector<bool>& events) {
    for (size_t i = 0; i < events.size(); ++i) {
        if (this->on_image) {
            for (const auto& pref : this->preferred_image_formats_) {
                this->on_image(pref.slot, nullptr, 0, pref.format, 0);
            }
        }
    }
}

void ArtworkRole::cleanup() {
    std::lock_guard<std::mutex> lock(this->bridge_->event_mutex);

    // Discard stale events from the dead connection
    this->pending_stream_end_.clear();

    // Enqueue a stream end so drain_events() sends null images to clear each slot
    this->pending_stream_end_.push_back(true);
}

}  // namespace sendspin
