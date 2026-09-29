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
#include <optional>
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
// a player MUST list either flac or pcm, the codecs every server supports. start() refuses a list
// that breaks the rule rather than advertising it, and refuses an opus entry in a build without the
// Opus decoder (SENDSPIN_ENABLE_OPUS), so the hello never advertises a codec it cannot decode.
TEST(PlayerRoleFormats, StartValidatesTheFormatList) {
#ifdef SENDSPIN_ENABLE_OPUS
    constexpr bool OPUS_DECODES = true;
#else
    constexpr bool OPUS_DECODES = false;
#endif
    const AudioSupportedFormatObject flac{SendspinCodecFormat::FLAC, 2, 44100, 16};
    const AudioSupportedFormatObject pcm{SendspinCodecFormat::PCM, 2, 44100, 16};
    const AudioSupportedFormatObject opus{SendspinCodecFormat::OPUS, 2, 48000, 16};
    struct Row {
        const char* name;
        std::vector<AudioSupportedFormatObject> formats;
        bool starts;
    };
    const Row rows[] = {
        {"empty list", {}, false},
        {"opus only", {opus}, false},
        {"Control: flac alone", {flac}, true},
        {"Control: pcm alone", {pcm}, true},
        {"opus beside pcm", {opus, pcm}, OPUS_DECODES},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        PlayerRoleConfig config;
        config.audio_formats = row.formats;
        SendspinClient client(make_client_config(row.name));
        client.add_player(std::move(config));
        EXPECT_EQ(client.start(), row.starts);
        if (client.is_started()) {
            client.stop();
        }
    }
}

// ============================================================================
// Timing parameters in client/state
// ============================================================================

// roles/player/v1.md "client/state player object": required_lead_time_ms and min_buffer_ms are
// reported in every player state object. The reported lead time follows the pipeline it
// describes, so raising the startup silence the sync task inserts raises what the server is
// asked to give, and a configured value below what the pipeline spends is raised to it: the
// server extends lead only toward the reported number, so reporting less than the truth
// truncates the stream start.
//
// The expected numbers are spelled out rather than re-derived with pipeline_lead_time_ms():
// that is the production formula, so re-running it here would report whatever the terms became.
// 150 is 25 ms of sync priming, 50 ms of default extra startup silence and 75 ms of pipeline
// start allowance.
TEST(PlayerRoleTimingParameters, ReportedLeadTimeIsTheLargerOfTheConfiguredValueAndThePipeline) {
    struct Row {
        const char* name;
        std::optional<uint16_t> configured_lead_ms;
        std::optional<uint16_t> configured_min_buffer_ms;
        std::optional<uint16_t> extra_startup_silence_ms;
        uint16_t expected_lead_ms;
        uint16_t expected_min_buffer_ms;
    };
    const Row rows[] = {
        {"Control: nothing configured reports the defaults", {}, {}, {}, 150, 500},
        {"configured values above the pipeline are reported unchanged", 321, 654, {}, 321, 654},
        {"startup silence raises the lead time", {}, {}, 400, 500, 500},
        {"configured lead below the pipeline is raised to it", 10, {}, 400, 500, 500},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        PlayerRoleConfig player_config = make_player_config();
        player_config.required_lead_time_ms = row.configured_lead_ms;
        if (row.configured_min_buffer_ms.has_value()) {
            player_config.min_buffer_ms = *row.configured_min_buffer_ms;
        }
        if (row.extra_startup_silence_ms.has_value()) {
            player_config.extra_startup_silence_ms = *row.extra_startup_silence_ms;
        }

        SendspinClient client(make_client_config("player-timing"));
        auto& player = client.add_player(std::move(player_config));

        ClientPlayerStateObject state = build_player_state(player);
        EXPECT_EQ(state.required_lead_time_ms, row.expected_lead_ms);
        EXPECT_EQ(state.min_buffer_ms, row.expected_min_buffer_ms);
    }
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

// Every point of effect re-checks the generation the receive gate captured with the message,
// because a teardown can land while the handler is still running: the codec-header send inside
// handle_stream_start blocks for up to HEADER_SEND_TIMEOUT_MS, the widest such window, and the
// header is written before the check, which is why the check has to exist rather than the send
// being skipped. A stale handler that took effect would re-arm the sync task on a header with no
// audio behind it, buffer audio for a stream the teardown already ended, or place a seek marker
// in it.
//
// Each handler's effect is main-loop state that the role publishes rather than a callback, so the
// inbox slots and the encoded ring are read directly: with no main loop running there is nothing
// a caller or peer can observe that distinguishes a refused handler from one that never ran.
TEST(PlayerTeardownGeneration, StaleGenerationIsRefusedAtEveryPointOfEffect) {
    struct Row {
        const char* name;
        void (*drive)(PlayerRole::Impl&, uint32_t);
        bool (*took_effect)(PlayerRole::Impl&);
    };

    const Row rows[] = {
        {"stream/start",
         [](PlayerRole::Impl& impl, uint32_t generation) {
             impl.handle_stream_start(pcm_stream_params(), generation);
         },
         [](PlayerRole::Impl& impl) {
             ServerPlayerStreamObject published;
             const bool published_params = impl.event_state->stream_params_slot.take(published);
             const bool queued_start = drain_stream_events(impl).starts > 0;
             if (published_params) {
                 EXPECT_EQ(published.sample_rate.value_or(0), 44100u);
             }
             return published_params || queued_start;
         }},
        {"audio chunk",
         [](PlayerRole::Impl& impl, uint32_t generation) {
             const std::vector<uint8_t> chunk = audio_chunk();
             impl.handle_binary(chunk.data(), chunk.size(), generation);
         },
         [](PlayerRole::Impl& impl) { return !impl.sync_task->encoded_ring_buffer_->is_empty(); }},
        // stream/clear enqueues the marker that tells the sync task where the discarded pre-seek
        // audio ends, so a stale one would place that boundary in an ended stream.
        {"stream/clear",
         [](PlayerRole::Impl& impl, uint32_t generation) { impl.handle_stream_clear(generation); },
         [](PlayerRole::Impl& impl) { return !impl.sync_task->encoded_ring_buffer_->is_empty(); }},
        {"server/command",
         [](PlayerRole::Impl& impl, uint32_t generation) {
             impl.handle_server_command(volume_command(70), generation);
         },
         [](PlayerRole::Impl& impl) {
             ServerCommandMessage merged;
             if (!impl.event_state->command_slot.take(merged)) {
                 return false;
             }
             EXPECT_TRUE(merged.player.has_value());
             EXPECT_EQ(merged.player->volume.value_or(0), 70);
             return true;
         }},
    };

    for (const auto& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        const uint32_t captured = live_generation(*impl);

        impl->cleanup();
        ASSERT_EQ(drain_stream_events(*impl).ends, 1) << "cleanup() queued no STREAM_END";
        ASSERT_TRUE(impl->sync_task->encoded_ring_buffer_->is_empty());

        row.drive(*impl, captured);
        EXPECT_FALSE(row.took_effect(*impl)) << "a stale message reached the main loop";

        // Control: the same message with the generation the role now reports takes effect.
        row.drive(*impl, live_generation(*impl));
        EXPECT_TRUE(row.took_effect(*impl));
    }
}

// roles/player/v1.md "Audio Chunks (Binary)": while the client is unavailable the player
// discards incoming audio, whether availability changed before or after the role was added.
TEST(PlayerRoleAvailability, AudioIsDiscardedWhileTheClientIsUnavailable) {
    struct Row {
        const char* name;
        bool available_when_added;
        bool available_on_arrival;
        bool queued;
    };
    const Row rows[] = {
        {"available", true, true, true},  // Control:
        {"became unavailable", true, false, false},
        {"unavailable before add", false, false, false},
        {"available again", false, true, true},  // Control:
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinClient client(make_client_config("player-availability"));
        client.set_available(row.available_when_added);
        PlayerRole::Impl& impl = *client.add_player(make_player_config()).impl_;
        ASSERT_TRUE(impl.sync_task->init(&impl, impl.config.audio_buffer_capacity));
        client.set_available(row.available_on_arrival);

        const std::vector<uint8_t> chunk = audio_chunk();
        impl.handle_binary(chunk.data(), chunk.size(), live_generation(impl));
        EXPECT_EQ(!impl.sync_task->encoded_ring_buffer_->is_empty(), row.queued);
    }
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

// roles/player/v1.md "client/state player object": volume is 0-100, so a consumer value above
// that is reported at the maximum.
TEST(PlayerRoleVolume, ValueOverTheSpecMaximumIsClamped) {
    struct Row {
        uint8_t requested;
        uint8_t reported;
    };
    for (const Row& row : {Row{0, 0}, Row{100, 100}, Row{101, 100}, Row{255, 100}}) {
        SCOPED_TRACE(static_cast<int>(row.requested));
        auto impl = make_impl();
        impl->update_volume(row.requested);
        ClientStateMessage state;
        impl->build_state_fields(state);
        ASSERT_TRUE(state.player.has_value());
        EXPECT_EQ(state.player->volume, row.reported);
    }
}

// roles/player/v1.md "server/command player object": set_output_delay is only honored while the
// player advertises it in supported_commands, which the consumer sees as on_output_delay_changed().
TEST(PlayerRoleOutputDelay, SetOutputDelayCommandIsIgnoredUnlessAdvertised) {
    class DelayListener : public PlayerRoleListener {
    public:
        size_t on_audio_write(uint8_t* /*data*/, size_t length, uint32_t /*timeout_ms*/) override {
            return length;
        }
        void on_output_delay_changed(uint16_t delay_ms) override {
            this->changes.push_back(delay_ms);
        }
        std::vector<uint16_t> changes;
    };

    for (const bool adjustable : {false, true}) {
        SCOPED_TRACE(adjustable ? "advertised" : "not advertised");
        DelayListener listener;  // Outlives the role that holds it
        auto impl = make_impl();
        impl->listener = &listener;
        impl->output_delay_adjustable.store(adjustable);

        ServerPlayerCommandObject player_cmd;
        player_cmd.command = SendspinPlayerCommand::SET_OUTPUT_DELAY;
        player_cmd.output_delay_ms = 300;
        ServerCommandMessage cmd;
        cmd.player = player_cmd;
        impl->handle_server_command(cmd, live_generation(*impl));
        impl->drain_events();

        EXPECT_EQ(listener.changes, adjustable ? std::vector<uint16_t>{300} : std::vector<uint16_t>{});
    }
}

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
// here: it applies only when nothing was stored, so a discarded blob leaves the delay at 0.
TEST(PlayerRoleOutputDelay, PersistedValueIsLoadedOnlyWithinTheSpecRange) {
    struct Row {
        const char* name;
        const char* stored;
        uint16_t expected_delay_ms;
    };
    const Row rows[] = {
        {"Control: at the spec maximum", "5000", MAX_OUTPUT_DELAY_MS},
        {"above the spec maximum", "60000", 0},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InMemoryPersistenceProvider provider;
        provider.seed_blob(persistence_keys::OUTPUT_DELAY, to_bytes(row.stored));

        DelayClient fixture(provider, /*initial_delay_ms=*/77);
        EXPECT_EQ(fixture.player->get_output_delay_ms(), row.expected_delay_ms);
    }
}
