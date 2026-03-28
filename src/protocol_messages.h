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

#include "sendspin/artwork_role.h"
#include "sendspin/controller_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/protocol.h"
#include "sendspin/visualizer_role.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sendspin {

// ============================================================================
// Message envelope structs
// ============================================================================

struct ClientHelloMessage {
    std::string client_id;
    std::string name;
    std::optional<DeviceInfoObject> device_info;
    uint8_t version;
    std::vector<SendspinRole> supported_roles;
    std::optional<PlayerSupportObject> player_v1_support;
    std::optional<ArtworkSupportObject> artwork_v1_support;
    std::optional<VisualizerSupportObject> visualizer_support;
};

struct ClientStateMessage {
    SendspinClientState state;
    std::optional<ClientPlayerStateObject> player;
};

struct ClientCommandMessage {
    std::optional<ClientCommandControllerObject> controller;
};

struct ClientGoodbyeMessage {
    SendspinGoodbyeReason reason;
};

struct ServerStateMessage {
    std::optional<ServerStateControllerObject> controller;
    std::optional<ServerMetadataStateObject> metadata;
};

struct ServerHelloMessage {
    ServerInformationObject server;
    uint16_t version;
    std::vector<std::string> active_roles;
    SendspinConnectionReason connection_reason;
};

struct GroupUpdateMessage {
    GroupUpdateObject group;
};

struct StreamStartMessage {
    std::optional<ServerPlayerStreamObject> player;
    std::optional<ServerArtworkStreamObject> artwork;
    std::optional<ServerVisualizerStreamObject> visualizer;
};

struct StreamRequestFormatMessage {
    std::optional<ServerPlayerStreamObject> player;
    std::optional<ClientArtworkRequestObject> artwork;
};

struct StreamEndMessage {
    std::optional<std::vector<std::string>> roles;
};

struct StreamClearMessage {
    std::optional<std::vector<std::string>> roles;
};

}  // namespace sendspin
