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
/// socket or the sync task thread. The binary audio chunk header is parsed directly too.

#include "player_role_impl.h"  // build_state_fields(); private access, see tests/CMakeLists.txt
#include "protocol_messages.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/player_role.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <utility>
#include <vector>

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
// reported in every player state object. A configured lead time above what the pipeline spends
// reaches the state object unchanged.
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
    EXPECT_EQ(state.required_lead_time_ms,
              PlayerRoleConfig::pipeline_lead_time_ms(
                  PlayerRoleConfig::DEFAULT_EXTRA_STARTUP_SILENCE_MS));
    EXPECT_EQ(state.min_buffer_ms, PlayerRoleConfig::DEFAULT_MIN_BUFFER_MS);
    EXPECT_GT(state.required_lead_time_ms, PlayerRoleConfig::DEFAULT_EXTRA_STARTUP_SILENCE_MS);
}

// The reported lead time follows the pipeline it describes: raising the startup silence the sync
// task inserts raises what the server is asked to give, with no second setting to remember.
TEST(PlayerRoleTimingParameters, StartupSilenceRaisesTheReportedLeadTime) {
    PlayerRoleConfig player_config = make_player_config();
    player_config.extra_startup_silence_ms = 400;

    SendspinClient client(make_client_config("player-timing-startup-silence"));
    auto& player = client.add_player(std::move(player_config));

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.required_lead_time_ms, PlayerRoleConfig::pipeline_lead_time_ms(400));
    EXPECT_GT(state.required_lead_time_ms, 400);
}

// A configured value below what the pipeline spends is raised to it: the server extends lead only
// toward the reported number, so reporting less than the truth truncates the stream start.
TEST(PlayerRoleTimingParameters, ConfiguredLeadTimeCannotUndercutThePipeline) {
    PlayerRoleConfig player_config = make_player_config();
    player_config.extra_startup_silence_ms = 400;
    player_config.required_lead_time_ms = 10;

    SendspinClient client(make_client_config("player-timing-undercut"));
    auto& player = client.add_player(std::move(player_config));

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.required_lead_time_ms, PlayerRoleConfig::pipeline_lead_time_ms(400));
}

// The timing parameters describe the pipeline, not the delay knob: they are reported whether or
// not the output delay is adjustable, and an inadjustable delay reports 0 without touching them.
TEST(PlayerRoleTimingParameters, ReportedWhileOutputDelayIsNotAdjustable) {
    SendspinClient client(make_client_config("player-timing-inadjustable"));
    auto& player = client.add_player(make_player_config());
    player.update_output_delay(250);

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.output_delay_ms, 0);
    EXPECT_EQ(state.required_lead_time_ms,
              PlayerRoleConfig::pipeline_lead_time_ms(
                  PlayerRoleConfig::DEFAULT_EXTRA_STARTUP_SILENCE_MS));
    EXPECT_EQ(state.min_buffer_ms, PlayerRoleConfig::DEFAULT_MIN_BUFFER_MS);
}

// ============================================================================
// Supported commands in client/state
// ============================================================================

// roles/player/v1.md "client/state player object": supported_commands lists what the server may
// send. The role applies a volume or mute command on any output, so both are reported whether or
// not the output delay can be changed.
TEST(PlayerRoleSupportedCommands, VolumeAndMuteAreAlwaysReported) {
    SendspinClient client(make_client_config("player-commands-fixed-delay"));
    auto& player = client.add_player(make_player_config());

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.supported_commands, (std::vector<SendspinPlayerCommand>{
                                            SendspinPlayerCommand::VOLUME,
                                            SendspinPlayerCommand::MUTE,
                                        }));
}

// An adjustable output delay adds set_output_delay to the same list rather than replacing it.
TEST(PlayerRoleSupportedCommands, AdjustableOutputDelayAddsItsCommand) {
    SendspinClient client(make_client_config("player-commands-adjustable-delay"));
    auto& player = client.add_player(make_player_config());
    player.set_output_delay_adjustable(true);

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.supported_commands, (std::vector<SendspinPlayerCommand>{
                                            SendspinPlayerCommand::VOLUME,
                                            SendspinPlayerCommand::MUTE,
                                            SendspinPlayerCommand::SET_OUTPUT_DELAY,
                                        }));
}

// ============================================================================
// Audio chunk header
// ============================================================================

// roles/player/v1.md "Audio Chunks (Binary)": bytes 1-8 timestamp, bytes 9-12 send_ahead, the
// encoded audio frame from byte 13. The message type byte is already stripped here, so the
// header is the first 12 bytes.
TEST(PlayerAudioChunk, HeaderSplitsTimestampFromTheEncodedFrame) {
    const std::vector<uint8_t> chunk = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x42, 0x40,  // timestamp = 1000000
        0x00, 0x01, 0x86, 0xA0,                          // send_ahead = 100000
        0xDE, 0xAD, 0xBE, 0xEF,                          // encoded audio
    };

    auto parsed = PlayerRole::Impl::parse_audio_chunk(chunk.data(), chunk.size());
    ASSERT_TRUE(parsed.has_value());
    // A parser reading the timestamp anywhere but bytes 0-7 would pick up send_ahead bytes.
    EXPECT_EQ(parsed->timestamp_us, 1000000);
    ASSERT_EQ(parsed->audio_len, 4u);
    EXPECT_EQ(parsed->audio, chunk.data() + 12) << "the encoded frame starts past send_ahead";
    EXPECT_EQ(std::vector<uint8_t>(parsed->audio, parsed->audio + parsed->audio_len),
              (std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

// A negative timestamp round-trips as a signed value rather than a huge unsigned one.
TEST(PlayerAudioChunk, TimestampIsSigned) {
    const std::vector<uint8_t> chunk = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,  // timestamp = -2
        0xFF, 0xFF, 0xFF, 0xFF,                          // send_ahead saturated
        0x01,
    };

    auto parsed = PlayerRole::Impl::parse_audio_chunk(chunk.data(), chunk.size());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->timestamp_us, -2);
    EXPECT_EQ(parsed->audio_len, 1u);
}

// A chunk with a complete header but no audio after it is still a parsed header: the empty
// frame is what the caller rejects, not the header length.
TEST(PlayerAudioChunk, HeaderWithNoAudioParsesToAnEmptyFrame) {
    const std::vector<uint8_t> chunk(12, 0x00);

    auto parsed = PlayerRole::Impl::parse_audio_chunk(chunk.data(), chunk.size());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->audio_len, 0u);
}

// A chunk too short to hold the 12-byte header is rejected. Eleven bytes is the interesting
// case: it holds a whole timestamp, so a parser that only checked for the timestamp would
// accept it and hand the codec three bytes of send_ahead.
TEST(PlayerAudioChunk, ShortChunkIsRejected) {
    const std::vector<uint8_t> chunk(16, 0x00);
    for (size_t len = 0; len < 12; ++len) {
        EXPECT_FALSE(PlayerRole::Impl::parse_audio_chunk(chunk.data(), len).has_value())
            << "len=" << len;
    }
    // Control: one more byte makes the header complete.
    EXPECT_TRUE(PlayerRole::Impl::parse_audio_chunk(chunk.data(), 12).has_value());
}
