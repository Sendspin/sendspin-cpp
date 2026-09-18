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

/// PlayerRoleConfig as the player reports and enforces it: the timing parameters the player puts
/// in every client/state player object, and the supported-format list the spec constrains.
///
/// The role's Impl is driven directly; the client is never started, so nothing here touches a
/// socket or the sync task thread.

#include "player_role_impl.h"  // build_state_fields(); private access, see tests/CMakeLists.txt
#include "protocol_messages.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/player_role.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <utility>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

PlayerRoleConfig make_player_config() {
    PlayerRoleConfig config;
    config.audio_formats = {{SendspinCodecFormat::FLAC, 2, 44100, 16}};
    return config;
}

SendspinClientConfig make_client_config(const char* name) {
    SendspinClientConfig config;
    config.name = name;
    return config;
}

ClientPlayerStateObject build_player_state(PlayerRole& player) {
    ClientStateMessage msg;
    player.impl_->build_state_fields(msg);
    EXPECT_TRUE(msg.player.has_value());
    return msg.player.value_or(ClientPlayerStateObject{});
}

}  // namespace

// ============================================================================
// Supported-format validation
// ============================================================================

// roles/player/v1.md "client/hello player@v1 support object": supported_formats is non-empty and
// a player MUST list either flac or pcm. A configuration that lists neither cannot be served by
// every server, so start() refuses it rather than advertising it.
TEST(PlayerRoleFormats, StartRejectsListWithoutFlacOrPcm) {
    PlayerRoleConfig player_config;
    player_config.audio_formats = {{SendspinCodecFormat::OPUS, 2, 48000, 16}};

    SendspinClient client(make_client_config("player-formats-opus-only"));
    client.add_player(std::move(player_config));

    EXPECT_FALSE(client.start());
}

TEST(PlayerRoleFormats, StartRejectsEmptyList) {
    SendspinClient client(make_client_config("player-formats-empty"));
    client.add_player(PlayerRoleConfig{});

    EXPECT_FALSE(client.start());
}

// Control: either of the two mandatory codecs is enough on its own, and extra opus entries do
// not spoil an otherwise serveable list.
TEST(PlayerRoleFormats, StartAcceptsFlacOrPcmAmongOthers) {
    SendspinClient flac_client(make_client_config("player-formats-flac"));
    flac_client.add_player(make_player_config());
    EXPECT_TRUE(flac_client.start());
    flac_client.stop();

    PlayerRoleConfig pcm_config;
    pcm_config.audio_formats = {{SendspinCodecFormat::OPUS, 2, 48000, 16},
                                {SendspinCodecFormat::PCM, 2, 44100, 16}};
    SendspinClient pcm_client(make_client_config("player-formats-pcm"));
    pcm_client.add_player(std::move(pcm_config));
    EXPECT_TRUE(pcm_client.start());
    pcm_client.stop();
}

// ============================================================================
// Timing parameters in client/state
// ============================================================================

// roles/player/v1.md "client/state player object": required_lead_time_ms and min_buffer_ms are
// reported in every player state object. They come from PlayerRoleConfig, so a configured value
// must reach the state object unchanged rather than being replaced by the default.
TEST(PlayerRoleTimingParameters, ConfiguredValuesAreReported) {
    PlayerRoleConfig player_config = make_player_config();
    player_config.required_lead_time_ms = 321;
    player_config.min_buffer_ms = 654;

    SendspinClient client(make_client_config("player-timing-configured"));
    auto& player = client.add_player(std::move(player_config));

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.required_lead_time_ms, 321);
    EXPECT_EQ(state.min_buffer_ms, 654);
}

// Control: with nothing configured the player still reports both, at the documented defaults.
// The lead-time default carries the sync task's priming silence and the extra startup silence as
// terms, so it must exceed the startup silence it is derived from.
TEST(PlayerRoleTimingParameters, DefaultsAreReported) {
    SendspinClient client(make_client_config("player-timing-default"));
    auto& player = client.add_player(make_player_config());

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.required_lead_time_ms, PlayerRoleConfig::DEFAULT_REQUIRED_LEAD_TIME_MS);
    EXPECT_EQ(state.min_buffer_ms, PlayerRoleConfig::DEFAULT_MIN_BUFFER_MS);
    EXPECT_GT(PlayerRoleConfig::DEFAULT_REQUIRED_LEAD_TIME_MS,
              PlayerRoleConfig::DEFAULT_EXTRA_STARTUP_SILENCE_MS);
}

// The timing parameters describe the pipeline, not the delay knob: they are reported whether or
// not the output delay is adjustable, and an inadjustable delay reports 0 without touching them.
TEST(PlayerRoleTimingParameters, ReportedWhileOutputDelayIsNotAdjustable) {
    SendspinClient client(make_client_config("player-timing-inadjustable"));
    auto& player = client.add_player(make_player_config());
    player.update_output_delay(250);

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.output_delay_ms, 0);
    EXPECT_EQ(state.required_lead_time_ms, PlayerRoleConfig::DEFAULT_REQUIRED_LEAD_TIME_MS);
    EXPECT_EQ(state.min_buffer_ms, PlayerRoleConfig::DEFAULT_MIN_BUFFER_MS);
}
