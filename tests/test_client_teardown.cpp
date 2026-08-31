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
/// @brief Pins the teardown latency of a client running every threaded role: stopping a
/// role must interrupt its blocking receive, not wait out the receive timeout

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

// Destroying a client whose player sync task, artwork decode thread, and visualizer drain
// thread are all parked in blocking receives must complete promptly: each stop() wakes its
// thread's receive instead of waiting out the receive timeout. Without the wakes this takes
// the sum of the idle receive timeouts (500ms sync + 100ms artwork + 50ms visualizer,
// joined sequentially), so the bound distinguishes cleanly. A regression confined to the
// visualizer alone (50ms) can hide under the bound; the primitive-level wake tests cover
// that mechanism directly. Looping also pins that a fresh client starts and stops cleanly
// after a previous one was torn down (no state leaks across instances).
TEST(ClientTeardown, StopsThreadedRolesWithoutWaitingOutReceiveTimeouts) {
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

        // Let the three role threads spawn and park in their blocking receives, so the
        // teardown below interrupts genuinely parked threads rather than threads that have
        // not reached their first receive yet.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        auto start = std::chrono::steady_clock::now();
        client.reset();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - start)
                              .count();

        EXPECT_LT(elapsed_ms, 150) << "teardown waited out a role receive timeout (run " << run
                                   << ")";
    }
}

}  // namespace
}  // namespace sendspin
