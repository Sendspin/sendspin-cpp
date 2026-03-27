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

#include <mutex>

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

void ArtworkRole::handle_binary(uint8_t slot, const uint8_t* data, size_t len, int64_t timestamp) {
    if (!this->preferred_image_formats_.empty() && this->on_image) {
        SendspinImageFormat image_format = SendspinImageFormat::JPEG;
        for (const auto& pref : this->preferred_image_formats_) {
            if (pref.slot == slot) {
                image_format = pref.format;
                break;
            }
        }
        this->on_image(slot, data, len, image_format, timestamp);
    }
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
    // No-op for artwork
}

}  // namespace sendspin
