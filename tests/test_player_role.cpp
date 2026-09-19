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
/// The role's Impl is driven directly and no sync-task thread is ever started, so nothing here
/// races a background consumer: the encoded ring and the inbox hold whatever a handler put there.
/// The binary audio chunk header is parsed directly too.

#include "fake_persistence.h"
#include "inbox.h"
#include "player_role_impl.h"  // build_state_fields(); private access, see tests/CMakeLists.txt
#include "protocol_messages.h"
#include "sync_task.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/player_role.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <deque>
#include <memory>
#include <string>
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
// The numbers are spelled out rather than re-derived with pipeline_lead_time_ms(): that is the
// production formula, so re-running it here would report whatever the terms became. 150 is 25 ms
// of sync priming, 50 ms of default extra startup silence and 75 ms of pipeline start allowance.
TEST(PlayerRoleTimingParameters, DefaultsAreReported) {
    SendspinClient client(make_client_config("player-timing-default"));
    auto& player = client.add_player(make_player_config());

    ClientPlayerStateObject state = build_player_state(player);
    EXPECT_EQ(state.required_lead_time_ms, 150);
    EXPECT_EQ(state.min_buffer_ms, 500);
}

// The reported lead time follows the pipeline it describes: raising the startup silence the sync
// task inserts raises what the server is asked to give, with no second setting to remember.
TEST(PlayerRoleTimingParameters, StartupSilenceRaisesTheReportedLeadTime) {
    PlayerRoleConfig player_config = make_player_config();
    player_config.extra_startup_silence_ms = 400;

    SendspinClient client(make_client_config("player-timing-startup-silence"));
    auto& player = client.add_player(std::move(player_config));

    ClientPlayerStateObject state = build_player_state(player);
    // 25 + 400 + 75: only the configured term moved.
    EXPECT_EQ(state.required_lead_time_ms, 500);
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

// The timing parameters describe the pipeline, not the delay knob: an inadjustable delay reports
// 0 without touching them.
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

// ============================================================================
// Teardown generation: every point of effect re-checks the generation the
// receive gate captured
// ============================================================================

namespace {

// A PlayerRole::Impl whose encoded ring and event flags exist but whose sync-task thread was
// never started, bound to its own Inbox. Nothing drains the ring or the inbox, so what a refused
// handler did not do is directly observable; a running task would discard idle-time audio and
// make the ring say nothing either way. Heap-allocated with program lifetime (static deques,
// mirroring make_impl() in test_visualizer_role.cpp): Impl holds atomics, so it is neither
// copyable nor movable, and it keeps a raw SendspinClient* that must outlive it.
std::unique_ptr<PlayerRole::Impl> make_impl() {
    static std::deque<SendspinClient> clients;
    static std::deque<Inbox> inboxes;

    PlayerRoleConfig config;
    config.audio_formats = {{SendspinCodecFormat::PCM, 2, 44100, 16}};
    clients.emplace_back(SendspinClientConfig{});
    auto impl = std::make_unique<PlayerRole::Impl>(std::move(config), &clients.back(), nullptr);
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());
    EXPECT_TRUE(impl->sync_task->init(impl.get(), impl->config.audio_buffer_capacity));
    return impl;
}

// The generation the receive gate hands a handler on a role that has not been torn down.
uint32_t live_generation(const PlayerRole::Impl& impl) {
    return impl.cleanup_generation.load(std::memory_order_acquire);
}

// A stream/start player object the role can serve: PCM sends a synthesized codec header, so the
// blocking header send succeeds and the handler reaches its post-send generation check.
ServerPlayerStreamObject pcm_stream_params() {
    ServerPlayerStreamObject params;
    params.codec = SendspinCodecFormat::PCM;
    params.sample_rate = 44100;
    params.channels = 2;
    params.bit_depth = 16;
    return params;
}

ServerCommandMessage volume_command(uint8_t volume) {
    ServerPlayerCommandObject player_cmd;
    player_cmd.command = SendspinPlayerCommand::VOLUME;
    player_cmd.volume = volume;
    ServerCommandMessage cmd;
    cmd.player = player_cmd;
    return cmd;
}

// One audio chunk: a 12-byte header followed by a frame, as handle_binary receives it.
std::vector<uint8_t> audio_chunk() {
    std::vector<uint8_t> chunk(12, 0x00);
    chunk.insert(chunk.end(), {0xDE, 0xAD, 0xBE, 0xEF});
    return chunk;
}

// Drains the inbox and counts the player stream events it held.
struct StreamEventCounts {
    int starts{0};
    int ends{0};
};

StreamEventCounts drain_stream_events(PlayerRole::Impl& impl) {
    StreamEventCounts counts;
    InboxEvent events[Inbox::EVENT_CAPACITY];
    const size_t n = impl.inbox->take_events(events, Inbox::EVENT_CAPACITY);
    for (size_t i = 0; i < n; ++i) {
        if (events[i].type != InboxEventType::PLAYER_STREAM) {
            continue;
        }
        if (static_cast<PlayerStreamCallbackType>(events[i].code) ==
            PlayerStreamCallbackType::STREAM_START) {
            ++counts.starts;
        } else {
            ++counts.ends;
        }
    }
    return counts;
}

}  // namespace

// The codec-header send inside handle_stream_start blocks for up to HEADER_SEND_TIMEOUT_MS, which
// is the widest window a teardown can land in between the receive gate admitting the message and
// this handler publishing its stream. A teardown that did land has already ended the stream and
// queued its own STREAM_END, so publishing here would re-arm the sync task on the header just
// written with no audio behind it. The header itself is written before the check, which is why
// the check has to exist rather than the send being skipped.
TEST(PlayerTeardownGeneration, StreamStartPublishesNothingAfterATeardown) {
    auto impl = make_impl();
    const uint32_t captured = live_generation(*impl);

    impl->cleanup();
    ASSERT_EQ(drain_stream_events(*impl).ends, 1) << "cleanup() queued no STREAM_END";

    impl->handle_stream_start(pcm_stream_params(), captured);

    ServerPlayerStreamObject published;
    EXPECT_FALSE(impl->event_state->stream_params_slot.take(published))
        << "a stale stream/start published its params to the main loop";
    EXPECT_EQ(drain_stream_events(*impl).starts, 0)
        << "a stale stream/start queued a STREAM_START";

    // Control: the same stream/start with the generation the role now reports is published.
    impl->handle_stream_start(pcm_stream_params(), live_generation(*impl));
    EXPECT_TRUE(impl->event_state->stream_params_slot.take(published));
    EXPECT_EQ(published.sample_rate.value_or(0), 44100u);
    EXPECT_EQ(drain_stream_events(*impl).starts, 1);
}

TEST(PlayerTeardownGeneration, AudioChunkIsNotBufferedAfterATeardown) {
    auto impl = make_impl();
    const uint32_t captured = live_generation(*impl);

    impl->cleanup();
    ASSERT_TRUE(impl->sync_task->encoded_ring_buffer_->is_empty());

    const std::vector<uint8_t> chunk = audio_chunk();
    impl->handle_binary(chunk.data(), chunk.size(), captured);
    EXPECT_TRUE(impl->sync_task->encoded_ring_buffer_->is_empty())
        << "a stale audio chunk was buffered for a stopped stream";

    // Control: the same chunk with the generation the role now reports is buffered.
    impl->handle_binary(chunk.data(), chunk.size(), live_generation(*impl));
    EXPECT_FALSE(impl->sync_task->encoded_ring_buffer_->is_empty());
}

// stream/clear enqueues the marker that tells the sync task where the discarded pre-seek audio
// ends. A stale one would place that boundary in a stream the teardown already ended.
TEST(PlayerTeardownGeneration, StreamClearEnqueuesNoMarkerAfterATeardown) {
    auto impl = make_impl();
    const uint32_t captured = live_generation(*impl);

    impl->cleanup();
    ASSERT_TRUE(impl->sync_task->encoded_ring_buffer_->is_empty());

    impl->handle_stream_clear(captured);
    EXPECT_TRUE(impl->sync_task->encoded_ring_buffer_->is_empty())
        << "a stale stream/clear enqueued its seek marker";

    // Control: the same stream/clear with the generation the role now reports enqueues it.
    impl->handle_stream_clear(live_generation(*impl));
    EXPECT_FALSE(impl->sync_task->encoded_ring_buffer_->is_empty());
}

TEST(PlayerTeardownGeneration, ServerCommandIsNotAppliedAfterATeardown) {
    auto impl = make_impl();
    const uint32_t captured = live_generation(*impl);

    impl->cleanup();

    impl->handle_server_command(volume_command(70), captured);
    ServerCommandMessage merged;
    EXPECT_FALSE(impl->event_state->command_slot.take(merged))
        << "a stale server/command reached the main loop";

    // Control: the same command with the generation the role now reports is applied.
    impl->handle_server_command(volume_command(70), live_generation(*impl));
    ASSERT_TRUE(impl->event_state->command_slot.take(merged));
    ASSERT_TRUE(merged.player.has_value());
    EXPECT_EQ(merged.player->volume.value_or(0), 70);
}

// ============================================================================
// Output delay: spec clamp, write avoidance, and the persisted-value range
// ============================================================================

namespace {

// roles/player/v1.md "Output delay": the delay a player accepts is at most 5000 ms. Spelled out
// rather than read from the production constant, which is what the clamp is being checked against.
constexpr uint16_t MAX_OUTPUT_DELAY_MS = 5000;

std::vector<uint8_t> to_bytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

// A started client whose player persists through `provider`, with the delay knob adjustable so
// get_output_delay_ms() reports the stored value rather than 0.
struct DelayClient {
    explicit DelayClient(InMemoryPersistenceProvider& provider, uint16_t initial_delay_ms = 0)
        : client(make_client_config("player-output-delay")) {
        this->client.set_persistence_provider(&provider);
        PlayerRoleConfig config;
        config.audio_formats = {{SendspinCodecFormat::PCM, 2, 44100, 16}};
        config.initial_output_delay_ms = initial_delay_ms;
        this->player = &this->client.add_player(std::move(config));
        EXPECT_TRUE(this->client.start());
        this->player->set_output_delay_adjustable(true);
    }
    ~DelayClient() {
        this->client.stop();
    }

    SendspinClient client;
    PlayerRole* player{nullptr};
};

std::string persisted_delay(const InMemoryPersistenceProvider& provider) {
    auto blob = provider.blob(persistence_keys::OUTPUT_DELAY);
    return blob.has_value() ? std::string(blob->begin(), blob->end()) : std::string();
}

}  // namespace

// A server (or a consumer control) asking for more than the spec allows is held at the maximum
// rather than accepted, so the player never reports a delay it may not run at.
TEST(PlayerRoleOutputDelay, RequestOverTheSpecMaximumIsClamped) {
    InMemoryPersistenceProvider provider;
    DelayClient fixture(provider);

    fixture.player->update_output_delay(60000);
    EXPECT_EQ(fixture.player->get_output_delay_ms(), MAX_OUTPUT_DELAY_MS);
    EXPECT_EQ(persisted_delay(provider), "5000") << "the clamped value must be what is stored";

    // Control: a value inside the range reaches the player unchanged.
    fixture.player->update_output_delay(MAX_OUTPUT_DELAY_MS - 1);
    EXPECT_EQ(fixture.player->get_output_delay_ms(), MAX_OUTPUT_DELAY_MS - 1);
}

// A server that re-sends the delay it already set must not cost a flash write, which on device is
// the difference between an idle session and one that wears NVS down.
TEST(PlayerRoleOutputDelay, SettingTheValueItAlreadyHasCostsNoWrite) {
    InMemoryPersistenceProvider provider;
    DelayClient fixture(provider);

    fixture.player->update_output_delay(1234);
    const int writes = provider.save_attempts(persistence_keys::OUTPUT_DELAY);
    ASSERT_GE(writes, 1);

    fixture.player->update_output_delay(1234);
    EXPECT_EQ(provider.save_attempts(persistence_keys::OUTPUT_DELAY), writes)
        << "an unchanged output delay was written again";

    // Control: a different value is written.
    fixture.player->update_output_delay(1235);
    EXPECT_EQ(provider.save_attempts(persistence_keys::OUTPUT_DELAY), writes + 1);
}

// A stored blob that parses cleanly but names a delay above the spec maximum is discarded rather
// than loaded and then reported to the server. The configured initial value is not a fallback
// here: it applies only when nothing was stored, so the delay stays at 0.
TEST(PlayerRoleOutputDelay, PersistedValueOverTheSpecMaximumIsDiscarded) {
    InMemoryPersistenceProvider provider;
    provider.seed_blob(persistence_keys::OUTPUT_DELAY, to_bytes("60000"));

    DelayClient fixture(provider, /*initial_delay_ms=*/77);
    EXPECT_EQ(fixture.player->get_output_delay_ms(), 0u);
}

// Control: a stored value at the maximum is in range and is loaded.
TEST(PlayerRoleOutputDelay, PersistedValueAtTheSpecMaximumIsLoaded) {
    InMemoryPersistenceProvider provider;
    provider.seed_blob(persistence_keys::OUTPUT_DELAY, to_bytes("5000"));

    DelayClient fixture(provider, /*initial_delay_ms=*/77);
    EXPECT_EQ(fixture.player->get_output_delay_ms(), MAX_OUTPUT_DELAY_MS);
}
