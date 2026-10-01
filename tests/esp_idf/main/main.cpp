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

// Adds the player role so the decoder and its codec dependencies are linked into the image.

#include "sendspin/client.h"
#include "sendspin/player_role.h"

#include <chrono>
#include <thread>

using namespace sendspin;

struct DiscardPlayer : PlayerRoleListener {
    size_t on_audio_write(uint8_t* /*data*/, size_t length, uint32_t /*timeout_ms*/) override {
        return length;
    }
};

struct AlwaysReady : SendspinNetworkProvider {
    bool is_network_ready() override {
        return true;
    }
};

extern "C" void app_main() {
    SendspinClientConfig config;
    config.client_id = "esp-idf-build";
    config.name = "ESP-IDF Build";

    SendspinClient client(std::move(config));

    PlayerRoleConfig player_config;
    player_config.audio_formats = {{SendspinCodecFormat::FLAC, 2, 44100, 16}};
    auto& player = client.add_player(std::move(player_config));

    DiscardPlayer player_listener;
    AlwaysReady network;
    player.set_listener(&player_listener);
    client.set_network_provider(&network);

    client.start();

    while (true) {
        client.loop();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
