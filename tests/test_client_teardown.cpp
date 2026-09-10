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

/// @file test_client_teardown.cpp
/// @brief Construction and destruction of a client running every threaded role, covering the
/// destruction-order chain that joins the role threads

#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/player_role.h"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <thread>

namespace sendspin {
namespace {

class NullNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override {
        return false;  // Keeps the WebSocket server from starting; no network is involved
    }
};

class NullPlayerListener : public PlayerRoleListener {
public:
    size_t on_audio_write(uint8_t* /*data*/, size_t length, uint32_t /*timeout_ms*/) override {
        return length;
    }
};

// No explicit assertions on the teardown: std::thread's destructor calls std::terminate on a
// still-joinable thread, so a role that fails to join aborts the test, and the sanitizers catch
// a use-after-free against state a role thread still touches as the client unwinds.
//
// Coverage gap: this test does not assert that each role's stop() returns promptly. A role
// whose stop() no longer wakes its thread's blocking receive still passes here, after waiting
// out that receive's fallback timeout. Promptness is a latency property and the suite does not
// make elapsed time a pass/fail condition; the primitive tests pin that wake_receiver() itself
// interrupts a blocked receive, and each role's stop() is one visible call next to its stop
// flag.
TEST(ClientTeardown, JoinsEveryThreadedRoleOnDestruction) {
    NullNetworkProvider network;
    NullPlayerListener player_listener;

    for (int run = 0; run < 3; ++run) {
        SendspinClientConfig config;
        config.client_id = "teardown-test-client";
        config.name = "Teardown Test Client";

        auto client = std::make_unique<SendspinClient>(config);
        client->set_network_provider(&network);

        PlayerRoleConfig player_cfg;
        player_cfg.audio_formats.push_back({SendspinCodecFormat::PCM, 2, 48000, 16});
        player_cfg.audio_buffer_capacity = 64 * 1024;
        auto& player = client->add_player(std::move(player_cfg));
        player.set_listener(&player_listener);

        ArtworkRoleConfig art_cfg;
        art_cfg.preferred_formats.push_back({});
        client->add_artwork(std::move(art_cfg));

        VisualizerRoleConfig vis_cfg;
        vis_cfg.support.types.push_back(VisualizerDataType::LOUDNESS);
        vis_cfg.support.buffer_capacity = 4096;
        vis_cfg.support.rate_max = 30;
        client->add_visualizer(std::move(vis_cfg));

        ASSERT_TRUE(client->start_server());

        if (run > 0) {
            // Run 0 tears down mid-startup; later runs tear down threads parked in receives.
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        client.reset();
    }
}

}  // namespace
}  // namespace sendspin
