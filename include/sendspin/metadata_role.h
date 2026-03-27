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

#include <cstdint>
#include <functional>
#include <vector>

namespace sendspin {

class SendspinClient;
struct ClientBridge;

/// @brief Metadata role: provides track metadata and progress information.
class MetadataRole {
    friend class SendspinClient;

public:
    MetadataRole() = default;

    /// @brief Returns the interpolated track progress in milliseconds.
    uint32_t get_track_progress_ms() const;

    /// @brief Returns the track duration in milliseconds. 0 means unknown/live.
    uint32_t get_track_duration_ms() const;

    /// @brief Callback fired when metadata is updated.
    std::function<void(const ServerMetadataStateObject&)> on_metadata;

private:
    void attach(ClientBridge* bridge);
    void contribute_hello(ClientHelloMessage& msg);
    void handle_server_state(ServerMetadataStateObject state);
    void drain_events(std::vector<ServerMetadataStateObject>& events);
    void cleanup();

    ClientBridge* bridge_{nullptr};
    ServerMetadataStateObject metadata_{};
    std::vector<ServerMetadataStateObject> pending_metadata_events_;
};

}  // namespace sendspin
