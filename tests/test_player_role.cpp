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
#include "inbound_test_helpers.h"
#include "inbox.h"
#include "player_role_impl.h"  // build_state_fields(); private access, see tests/CMakeLists.txt
#include "protocol_messages.h"
#include "sync_task.h"
#include "visualizer_role_impl.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/player_role.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
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
// Teardown generation: handlers stamp what they queue with the generation the
// dispatch loaded, and the drains and the sync task discard a stale stamp
// ============================================================================

namespace {

// Binds the sync task's item list to a created `ring` the way SyncTask::start() does, without
// starting its thread, so what a handler handed over stays on the list to be read.
void bind_items(PlayerRole::Impl& impl, InboundRing& ring) {
    EXPECT_TRUE(impl.sync_task->init(&impl));
    EXPECT_TRUE(impl.sync_task->inbound().bind(&ring, InboundHolder::PLAYER));
}

// A PlayerRole::Impl whose item list is bound to a ring of its own but whose sync-task thread was
// never started, bound to its own Inbox. Nothing drains the list or the inbox, so what a handler
// queued, or did not, is directly observable; a running task would discard idle-time audio and
// make the list say nothing either way. Heap-allocated with program lifetime (static deques,
// mirroring make_impl() in test_visualizer_role.cpp): Impl holds atomics, so it is neither
// copyable nor movable, and it keeps a raw SendspinClient* that must outlive it.
/// @param ring A created ring to bind to, or nullptr for one of its own.
std::unique_ptr<PlayerRole::Impl> make_impl(InboundRing* ring = nullptr) {
    static std::deque<SendspinClient> clients;
    static std::deque<Inbox> inboxes;
    static std::deque<InboundRing> rings;

    PlayerRoleConfig config;
    config.audio_formats = {{SendspinCodecFormat::PCM, 2, 44100, 16}};
    clients.emplace_back(SendspinClientConfig{});
    auto impl = std::make_unique<PlayerRole::Impl>(std::move(config), &clients.back());
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());
    if (ring == nullptr) {
        ring = &rings.emplace_back();
        create_test_ring(*ring);
    }
    bind_items(*impl, *ring);
    return impl;
}

// A stream/start player object the role can serve: PCM sends a synthesized codec header, so the
// blocking header send succeeds and the handler publishes the stream.
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

// One audio chunk message as handle_binary receives it: the type byte, the 12-byte header (the
// server timestamp first) and a frame, the frame's first byte set to `marker`.
std::vector<uint8_t> audio_chunk(uint8_t marker = 0xDE, int64_t server_timestamp = 0) {
    std::vector<uint8_t> chunk{SENDSPIN_BINARY_PLAYER_AUDIO};
    for (int shift = 56; shift >= 0; shift -= 8) {
        chunk.push_back(static_cast<uint8_t>(static_cast<uint64_t>(server_timestamp) >> shift));
    }
    chunk.insert(chunk.end(), 4, 0x00);  // send_ahead
    chunk.insert(chunk.end(), {marker, 0xAD, 0xBE, 0xEF});
    return chunk;
}

// Hands one chunk to the role outside any ring item, as for a reassembled chunk.
void hand_copied_chunk(PlayerRole::Impl& impl, std::vector<uint8_t> chunk) {
    InboundMessage message = message_over(chunk);
    impl.handle_binary(message);
    take_in_ring_order(*impl.sync_task->inbound().ring());
}

}  // namespace

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
        InboundRing ring;  // outlives the client, whose sync task holds a pointer to it
        create_test_ring(ring);
        SendspinClient client(make_client_config("player-availability"));
        client.set_available(row.available_when_added);
        PlayerRole::Impl& impl = *client.add_player(make_player_config()).impl_;
        bind_items(impl, ring);
        client.set_available(row.available_on_arrival);

        hand_copied_chunk(impl, audio_chunk());
        EXPECT_EQ(!impl.sync_task->inbound().items().is_empty(), row.queued);
    }
}

// ============================================================================
// The shared inbound ring: zero-copy hand-off, holder quotas, clear marker, recall
// ============================================================================

namespace {

// A visualizer Impl whose drain list is bound to `ring` without its thread, its stream active
// with every defined wire type negotiated.
std::unique_ptr<VisualizerRole::Impl> make_visualizer(InboundRing& ring) {
    static std::deque<Inbox> inboxes;
    auto impl = std::make_unique<VisualizerRole::Impl>(VisualizerRoleConfig{}, nullptr);
    impl->attach_inbox(inboxes.emplace_back());
    impl->stream_active = true;
    impl->negotiated_types_mask = 0x1F;
    EXPECT_TRUE(impl->drain_task->event_flags.create());
    EXPECT_TRUE(impl->drain_task->inbound.bind(&ring, InboundHolder::VISUALIZER));
    return impl;
}

// One loudness frame as the visualizer's handle_binary receives it.
std::vector<uint8_t> loudness_frame() {
    std::vector<uint8_t> frame{SENDSPIN_BINARY_VISUALIZER_LOUDNESS};
    frame.insert(frame.end(), 8, 0x00);  // server timestamp
    frame.insert(frame.end(), {0x12, 0x34});
    return frame;
}

// Takes every item on the sync task's list, returning each to the ring, and reports the first
// encoded byte of each (the marker audio_chunk() put there; 0 for an item with no encoded bytes).
std::vector<uint8_t> take_all(PlayerRole::Impl& impl) {
    std::vector<uint8_t> markers;
    void* item = nullptr;
    while ((item = impl.sync_task->take_item(0)) != nullptr) {
        markers.push_back(SyncTask::encoded_size(item) > 0 ? SyncTask::encoded_data(item)[0] : 0);
        impl.sync_task->inbound().return_item(item);
    }
    return markers;
}

}  // namespace

// An audio chunk received into a ring item is decoded from that item: the sync task reads the
// frame and the server timestamp where the transport wrote and the protocol task decrypted them.
// A chunk outside any ring item (reassembled from Noise fragments, or received through the
// fallback buffer) is the one case that is copied, into an item of its own.
TEST(PlayerInboundHandOff, AChunkInARingItemIsDecodedInPlace) {
    struct Row {
        const char* name;
        bool in_ring_item;
    };
    const Row rows[] = {{"received into a ring item", true},
                        {"Control: outside a ring item, copied", false}};
    constexpr int64_t SERVER_TS = 0x0102030405060708;

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        InboundRing& ring = *impl->sync_task->inbound().ring();
        std::vector<uint8_t> chunk = audio_chunk(0xC1, SERVER_TS);
        InboundMessage message =
            row.in_ring_item ? receive_into_ring(ring, chunk, 7) : message_over(chunk, 7);
        const uint8_t* frame_in_message = message.data + 13;

        impl->handle_binary(message);
        take_in_ring_order(ring);
        EXPECT_EQ(message.item, nullptr) << "the role must take the item over, or never had one";

        void* item = impl->sync_task->take_item(0);
        ASSERT_NE(item, nullptr);
        const uint8_t* decoded_from = SyncTask::encoded_data(item);
        EXPECT_TRUE(in_ring_storage(ring, decoded_from));
        EXPECT_EQ(decoded_from == frame_in_message, row.in_ring_item)
            << "the frame was copied out of the item it arrived in";
        EXPECT_EQ(SyncTask::encoded_size(item), 4U);
        EXPECT_EQ(decoded_from[0], 0xC1);
        EXPECT_EQ(SyncTask::server_timestamp(item), SERVER_TS);
        impl->sync_task->inbound().return_item(item);
    }
}

// The ring is shared, and each holder's quota bounds what it may keep outstanding. A player past
// its quota drops the chunk with a warning, returning its item, while the visualizer, charged
// against its own quota on the same ring, keeps receiving. The codec header and the clear marker
// the protocol task writes itself are exempt: a server that overran the quota with audio still
// gets its stream started and its seek boundary placed, rather than a header refused into a
// STREAM_END.
TEST(PlayerInboundHandOff, AnOverQuotaPlayerDropsItsChunkWhileTheVisualizerKeepsFlowing) {
    struct Row {
        const char* name;
        size_t player_quota_chunks;
        bool header_and_marker;
        size_t player_items;
    };
    const Row rows[] = {
        {"Control: room for both chunks", 2, false, 2},
        {"room for one chunk", 1, false, 1},
        {"room for one chunk: its codec header and clear marker still pass", 1, true, 3},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundRing ring;
        create_test_ring(ring);
        auto player = make_impl(&ring);
        auto visualizer = make_visualizer(ring);

        InboundMessage first = receive_into_ring(ring, audio_chunk(0x01), 0);
        player->handle_binary(first);
        const size_t one_chunk = ring.quota(InboundHolder::PLAYER).outstanding();
        ASSERT_GT(one_chunk, 0U);
        ring.quota(InboundHolder::PLAYER).set_limit(row.player_quota_chunks * one_chunk);

        InboundMessage second = receive_into_ring(ring, audio_chunk(0x02), 0);
        player->handle_binary(second);
        if (row.header_and_marker) {
            player->handle_stream_start(pcm_stream_params());
            player->handle_stream_clear();
            take_in_ring_order(ring);
        }
        EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(),
                  std::min<size_t>(row.player_items, row.player_quota_chunks) * one_chunk);

        InboundMessage frame = receive_into_ring(ring, loudness_frame(), 0);
        visualizer->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, frame);
        EXPECT_GT(ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U)
            << "the player's quota stopped the visualizer";
        EXPECT_FALSE(visualizer->drain_task->inbound.items().is_empty());

        EXPECT_EQ(take_all(*player).size(), row.player_items);
        visualizer->flush_items();
        EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(), 0U)
            << "a dropped chunk kept its charge";
        EXPECT_EQ(ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U);
    }
}

// messaging.md "stream/clear": the sync task discards the audio buffered before the clear and
// keeps what the server sent after it. The marker the protocol task appends is the boundary.
TEST(PlayerInboundHandOff, StreamClearDiscardsUpToItsMarker) {
    struct Row {
        const char* name;
        bool clear;
        std::vector<uint8_t> survivors;
    };
    const Row rows[] = {
        {"Control: no clear, the discard drains everything", false, {}},
        {"a clear between two chunks", true, {0x02}},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        InboundRing& ring = *impl->sync_task->inbound().ring();
        InboundMessage before = receive_into_ring(ring, audio_chunk(0x01), 0);
        impl->handle_binary(before);
        if (row.clear) {
            impl->handle_stream_clear();
            take_in_ring_order(ring);
        }
        InboundMessage after = receive_into_ring(ring, audio_chunk(0x02), 0);
        impl->handle_binary(after);

        SyncContext context;
        impl->sync_task->discard_to_clear_marker(context);
        EXPECT_EQ(take_all(*impl), row.survivors);
    }
}

// A teardown (a dropped connection, a removed role, stop()) moves the role's generation on, and
// the old stream's audio never plays: cleanup() recalls what the sync task has not taken,
// returning it and its quota charge to the ring, and an item the sync task takes between the
// generation bump and the recall is dropped by its generation stamp and returned the same way.
// That window has no observable trigger, so its row moves the generation on directly, leaving
// the items listed.
TEST(PlayerInboundHandOff, ATeardownRecallsTheItemsTheSyncTaskHasNotTaken) {
    enum class Teardown { NONE, CLEANUP, GENERATION_ONLY };
    struct Row {
        const char* name;
        Teardown teardown;
        size_t listed_before_take;
        size_t delivered;
    };
    const Row rows[] = {
        {"Control: no teardown", Teardown::NONE, 2, 2},
        {"torn down, recalled by cleanup()", Teardown::CLEANUP, 0, 0},
        {"taken by the sync task before the recall", Teardown::GENERATION_ONLY, 2, 0},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        InboundRing& ring = *impl->sync_task->inbound().ring();
        for (uint8_t marker : {0x01, 0x02}) {
            InboundMessage message = receive_into_ring(ring, audio_chunk(marker), 0);
            impl->handle_binary(message);
        }
        if (row.teardown == Teardown::CLEANUP) {
            impl->cleanup();
        } else if (row.teardown == Teardown::GENERATION_ONLY) {
            impl->cleanup_generation.fetch_add(1, std::memory_order_acq_rel);
        }

        EXPECT_EQ(impl->sync_task->inbound().items().is_empty(), row.listed_before_take == 0);
        // Taken under the live generation, as the sync task would: a recalled or stale item is
        // not delivered, and an item left over is.
        EXPECT_EQ(take_all(*impl).size(), row.delivered);
        EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(), 0U)
            << "an item of the torn-down stream kept its charge";
    }
}

// A server command the drain takes is applied only if it was admitted under the role's current
// generation: one stamped before a teardown (taken by a drain on the far side of it) is dropped,
// not applied after the stream it belonged to was torn down. The slot is written with the old
// stamp directly, the payload a drain that took it before the teardown would hold; no observable
// call stages that interleaving on demand.
TEST(PlayerTeardownGeneration, ACommandStampedBeforeATeardownIsNotApplied) {
    struct Row {
        const char* name;
        bool stale;
        uint8_t expected_volume;
    };
    const Row rows[] = {{"Control: stamped with the current generation", false, 70},
                        {"stamped before the teardown", true, 0}};
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        const uint32_t before = impl->cleanup_generation.load();
        impl->cleanup();
        impl->event_state->command_slot.write(volume_command(70),
                                              row.stale ? before : impl->cleanup_generation.load());

        impl->drain_events();

        EXPECT_EQ(impl->volume, row.expected_volume);
    }
}

// roles/player/v1.md "client/hello player@v1 support object": the server fills buffer_capacity
// with encoded frames, and each frame costs the quota its stored size in the inbound ring, so the
// player's advertisement starts from the share that holds frames at the smallest chunk size: two
// thirds of its quota (a 160-byte frame stores in 232 bytes). The server's flow control is sized
// from this number, so the share is spelled out rather than bounded. The hello advertises it
// capped at the ring's largest item, which only a run has; ClientLifecycle's ring-size table
// covers the capped value.
TEST(PlayerHello, TheAdvertisedShareOfTheQuotaHoldsEncodedFrames) {
    struct Row {
        const char* name;
        size_t quota;
        size_t advertised;
    };
    const Row rows[] = {
        {"default quota", 1000000, 666666},
        {"a quota divisible by three", 600000, 400000},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinClient client(make_client_config("player-hello-share"));
        PlayerRoleConfig config = make_player_config();
        config.audio_buffer_capacity = row.quota;
        PlayerRole::Impl& impl = *client.add_player(std::move(config)).impl_;
        EXPECT_EQ(impl.buffer_capacity_share(), row.advertised);
    }
}

// ============================================================================
// Output delay: spec clamp, write avoidance, and the persisted-value range
// ============================================================================

namespace {

// roles/player/v1.md "Output delay": the delay a player accepts is at most 5000 ms. Spelled out
// rather than read from the production constant, which is what the clamp is being checked against.
constexpr uint16_t MAX_OUTPUT_DELAY_MS = 5000;

// The OUTPUT_DELAY blob holding `delay_ms`: a native uint16_t.
std::vector<uint8_t> delay_blob(uint16_t delay_ms) {
    std::vector<uint8_t> blob(sizeof(delay_ms));
    std::memcpy(blob.data(), &delay_ms, sizeof(delay_ms));
    return blob;
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

// The stored delay, or nullopt when no blob of the OUTPUT_DELAY size is stored.
std::optional<uint16_t> persisted_delay(const InMemoryPersistenceProvider& provider) {
    auto blob = provider.blob(persistence_keys::OUTPUT_DELAY);
    if (!blob.has_value() || blob->size() != sizeof(uint16_t)) {
        return std::nullopt;
    }
    uint16_t delay_ms = 0;
    std::memcpy(&delay_ms, blob->data(), sizeof(delay_ms));
    return delay_ms;
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
        impl->handle_server_command(cmd);
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
    EXPECT_EQ(persisted_delay(provider), MAX_OUTPUT_DELAY_MS)
        << "the clamped value must be what is stored";

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

// The player takes the provider the client holds when it starts, so the order of add_player() and
// set_persistence_provider() does not decide whether the stored delay is used.
TEST(PlayerRoleOutputDelay, AProviderSetAfterAddPlayerIsUsed) {
    InMemoryPersistenceProvider provider;
    provider.seed_blob(persistence_keys::OUTPUT_DELAY, delay_blob(120));

    SendspinClient client(make_client_config("player-late-provider"));
    PlayerRoleConfig config;
    config.audio_formats = {{SendspinCodecFormat::PCM, 2, 44100, 16}};
    PlayerRole& player = client.add_player(std::move(config));
    client.set_persistence_provider(&provider);
    ASSERT_TRUE(client.start());
    player.set_output_delay_adjustable(true);

    EXPECT_EQ(player.get_output_delay_ms(), 120) << "the stored delay was not loaded";
    player.update_output_delay(130);
    EXPECT_EQ(persisted_delay(provider), 130) << "the new delay was not written";

    client.stop();
}

// A stored blob of the right size that names a delay above the spec maximum is discarded rather
// than loaded and then reported to the server. The configured initial value is not a fallback
// here: it applies only when nothing was stored, so a discarded blob leaves the delay at 0.
TEST(PlayerRoleOutputDelay, PersistedValueIsLoadedOnlyWithinTheSpecRange) {
    struct Row {
        const char* name;
        uint16_t stored;
        uint16_t expected_delay_ms;
    };
    const Row rows[] = {
        {"Control: at the spec maximum", MAX_OUTPUT_DELAY_MS, MAX_OUTPUT_DELAY_MS},
        {"above the spec maximum", 60000, 0},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InMemoryPersistenceProvider provider;
        provider.seed_blob(persistence_keys::OUTPUT_DELAY, delay_blob(row.stored));

        DelayClient fixture(provider, /*initial_delay_ms=*/77);
        EXPECT_EQ(fixture.player->get_output_delay_ms(), row.expected_delay_ms);
    }
}
