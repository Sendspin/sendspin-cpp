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

#pragma once

#include "sendspin/protocol.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientBridge;

/// @brief Preference for an image slot's format and resolution.
struct ImageSlotPreference {
    uint8_t slot;
    SendspinImageSource source;
    SendspinImageFormat format;
    uint16_t width;
    uint16_t height;
};

/// @brief Artwork role: receives artwork images from the server.
class ArtworkRole {
    friend class SendspinClient;

public:
    ArtworkRole() = default;

    /// @brief Adds a preferred image format for an artwork slot.
    void add_image_preferred_format(const ImageSlotPreference& pref);

    /// @brief Returns all configured image format preferences.
    const std::vector<ImageSlotPreference>& get_image_preferred_formats() const {
        return this->preferred_image_formats_;
    }

    /// @brief Callback fired when an image is received (or cleared with nullptr data).
    std::function<void(uint8_t, const uint8_t*, size_t, SendspinImageFormat, int64_t)> on_image;

private:
    void attach(ClientBridge* bridge);
    void contribute_hello(ClientHelloMessage& msg);
    void handle_binary(uint8_t slot, const uint8_t* data, size_t len, int64_t timestamp);
    void handle_stream_end();
    void drain_events(std::vector<bool>& pending_stream_end);
    void cleanup();

    ClientBridge* bridge_{nullptr};
    std::vector<ImageSlotPreference> preferred_image_formats_;
    std::vector<ArtworkChannelFormatObject> artwork_channels_;
    std::vector<bool> pending_stream_end_;
};

}  // namespace sendspin
