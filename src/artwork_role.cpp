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

#include "platform/logging.h"
#include "platform/thread_safe_queue.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

static const char* const TAG = "sendspin.artwork";

/// @brief Size of the big-endian 64-bit timestamp at the start of artwork binary messages
static const size_t BINARY_TIMESTAMP_SIZE = 8;

/// @brief Swaps bytes of a big-endian 64-bit value to host byte order
static int64_t be64_to_host(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}

namespace sendspin {

/// @brief Deferred event state for thread-safe artwork stream lifecycle delivery
struct ArtworkRole::EventState {
    ThreadSafeQueue<uint8_t> stream_end_queue;
};

ArtworkRole::ArtworkRole(SendspinClient* client)
    : client_(client), event_state_(std::make_unique<EventState>()) {
    this->event_state_->stream_end_queue.create(4);
}

ArtworkRole::~ArtworkRole() = default;

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
    if (this->preferred_image_formats_.empty() || !this->listener_) {
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
    this->listener_->on_image(slot, image_data, image_len, image_format, timestamp);
}

void ArtworkRole::handle_stream_end() {
    this->event_state_->stream_end_queue.send(1, 0);
}

void ArtworkRole::drain_events() {
    uint8_t dummy;
    while (this->event_state_->stream_end_queue.receive(dummy, 0)) {
        if (this->listener_) {
            for (const auto& pref : this->preferred_image_formats_) {
                this->listener_->on_image(pref.slot, nullptr, 0, pref.format, 0);
            }
        }
    }
}

void ArtworkRole::cleanup() {
    this->event_state_->stream_end_queue.reset();

    // Enqueue a stream end so drain_events() sends null images to clear each slot
    this->event_state_->stream_end_queue.send(1, 0);
}

}  // namespace sendspin
