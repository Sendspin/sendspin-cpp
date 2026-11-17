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
/// The role's Impl (PlayerRole's private impl_) is driven directly and no sync-task thread is
/// ever started, so nothing here races a background consumer: the encoded ring and the inbox hold
/// whatever a handler put there, and an item is taken as the sync thread would (SyncTask's
/// take_item()). The binary audio chunk header is parsed directly too.

#include "connection.h"
#include "connection_manager.h"
#include "fake_persistence.h"
#include "inbound_test_helpers.h"
#include "inbox.h"
#include "platform/time.h"
#include "player_role_impl.h"  // build_state_fields()
#include "protocol_messages.h"
#include "protocol_task.h"
#include "sync_task.h"
#include "transfer_buffer.h"
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

// The player object of the client/state the role would send, which only the protocol task builds.
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

// volume and muted are reported only alongside their command. Rows leaving a knob unset check
// its default; the toggled row checks that re-enabling reports the stored value.
TEST(PlayerRoleSupportedCommands, EachAdjustableControlAddsItsCommandAndField) {
    using Cmd = SendspinPlayerCommand;
    struct Row {
        const char* name;
        std::optional<bool> volume;
        std::optional<bool> mute;
        bool delay;
        bool toggled;
        EnumSet<Cmd> commands;
    };
    const Row rows[] = {
        {"Control: defaults", std::nullopt, std::nullopt, false, false, {Cmd::VOLUME, Cmd::MUTE}},
        {"adjustable delay", std::nullopt, std::nullopt, true, false,
         {Cmd::VOLUME, Cmd::MUTE, Cmd::SET_OUTPUT_DELAY}},
        {"fixed volume", false, std::nullopt, false, false, {Cmd::MUTE}},
        {"fixed mute", std::nullopt, false, false, false, {Cmd::VOLUME}},
        {"fixed volume and mute", false, false, true, false, {Cmd::SET_OUTPUT_DELAY}},
        {"volume and mute re-enabled", true, true, false, true, {Cmd::VOLUME, Cmd::MUTE}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinClient client(make_client_config("player-commands"));
        auto& player = client.add_player(make_player_config());
        player.update_volume(40);
        player.update_muted(true);
        if (row.toggled) {
            player.set_volume_adjustable(false);
            player.set_mute_adjustable(false);
        }
        if (row.volume.has_value()) {
            player.set_volume_adjustable(row.volume.value());
        }
        if (row.mute.has_value()) {
            player.set_mute_adjustable(row.mute.value());
        }
        player.set_output_delay_adjustable(row.delay);

        const bool volume_reported = row.volume.value_or(true);
        const bool mute_reported = row.mute.value_or(true);
        ClientPlayerStateObject state = build_player_state(player);
        EXPECT_EQ(state.supported_commands, row.commands);
        EXPECT_EQ(state.volume, volume_reported ? std::optional<uint8_t>(40) : std::nullopt);
        EXPECT_EQ(state.muted, mute_reported ? std::optional<bool>(true) : std::nullopt);
    }
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
PlayerStreamParams pcm_stream_params() {
    PlayerStreamParams params;
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

// An admitted player-owning connection with inert transport calls; dispatch reaches the player
// only from one.
class PlayerOwnerConnection : public SendspinConnection {
public:
    void start() override {}
    void disconnect(SendspinGoodbyeReason) override {}
    void close_transport_now() override {}
    bool is_connected() const override {
        return true;
    }
    SsErr send_binary_message(const uint8_t*, size_t) override {
        return SsErr::OK;
    }
    SsErr send_text_message(const char* /*text*/, size_t /*len*/) override {
        return SsErr::OK;
    }
};

}  // namespace

// roles/player/v1.md "Audio Chunks (Binary)": the player discards incoming audio while the
// adopted client/state snapshot reports the client unavailable; a set_available() takes effect
// only once its snapshot is adopted. A discarded chunk's ring item stays with the dispatcher,
// for process_inbound() to return. The client is never started, so the test publishes and
// adopts each snapshot and dispatches the chunk itself, reaching SendspinClient's
// protocol_task_, build_client_state(), adopt_client_state(), connection_manager_ (its
// install_admitted()) and process_binary_message().
TEST(PlayerRoleAvailability, AudioIsDiscardedWhileTheClientIsUnavailable) {
    struct Row {
        const char* name;
        bool available_when_adopted;
        bool available_on_arrival;
        bool adopted_again;
        bool queued;
    };
    const Row rows[] = {
        {"Control: available", true, true, false, true},
        {"unavailable", false, false, false, false},
        {"unavailable, snapshot not yet adopted", true, false, false, true},
        {"available again, snapshot not yet adopted", false, true, false, false},
        {"Control: available again, snapshot adopted", false, true, true, true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InboundRing ring;  // outlives the client, whose sync task holds a pointer to it
        create_test_ring(ring);
        SendspinClient client(make_client_config("player-availability"));
        PlayerRole::Impl& impl = *client.add_player(make_player_config()).impl_;
        bind_items(impl, ring);
        auto adopt_snapshot = [&client] {
            client.protocol_task_->publish_state(client.build_client_state());
            ClientStateMessage snapshot;
            ASSERT_TRUE(client.protocol_task_->take_state(snapshot));
            client.adopt_client_state(snapshot);
        };

        client.set_available(row.available_when_adopted);
        adopt_snapshot();
        client.set_available(row.available_on_arrival);
        if (row.adopted_again) {
            adopt_snapshot();
        }

        auto conn = std::make_shared<PlayerOwnerConnection>();
        conn->apply_server_activate({SendspinActivity::PLAYBACK}, ActiveRoles{"player@v1"},
                                    std::nullopt, std::nullopt);
        client.connection_manager_->install_admitted(conn, role_mask_bit(SendspinRole::PLAYER));

        InboundMessage message = receive_into_ring(ring, audio_chunk(), 0);
        client.process_binary_message(*conn, message);
        EXPECT_EQ(!impl.sync_task->inbound().items().is_empty(), row.queued);
        EXPECT_EQ(message.item != nullptr, !row.queued);
        if (message.item != nullptr) {
            ring.return_item(message.item);
        }
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
        {"room for one chunk, held by the sync task: its codec header and clear marker still pass",
         1, true, 2},
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
        EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(),
                  std::min<size_t>(2, row.player_quota_chunks) * one_chunk);
        void* held = nullptr;
        if (row.header_and_marker) {
            // A chunk the sync task holds keeps its charge through the clear, so the quota is
            // still full when the marker is handed over.
            held = player->sync_task->take_item(0);
            ASSERT_NE(held, nullptr);
            player->handle_stream_start({pcm_stream_params()});
            player->handle_stream_clear();
            take_in_ring_order(ring);
            EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(), one_chunk);
        }

        InboundMessage frame = receive_into_ring(ring, loudness_frame(), 0);
        visualizer->handle_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, frame);
        EXPECT_GT(ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U)
            << "the player's quota stopped the visualizer";
        EXPECT_FALSE(visualizer->drain_task->inbound.items().is_empty());

        EXPECT_EQ(take_all(*player).size(), row.player_items);
        if (held != nullptr) {
            player->sync_task->inbound().return_item(held);
        }
        visualizer->drain_task->inbound.recall();
        EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(), 0U)
            << "a dropped chunk kept its charge";
        EXPECT_EQ(ring.quota(InboundHolder::VISUALIZER).outstanding(), 0U);
    }
}

// messaging.md "stream/clear": the sync task discards the audio buffered before the clear and
// keeps what the server sent after it. The marker the protocol task appends is the boundary for
// SyncTask's discard_to_clear_marker().
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

// roles/player/v1.md "Player Buffer Accounting": a stream/clear or stream/end resets the server's
// count, so it may refill the whole buffer before the sync task discards the audio queued ahead
// of the boundary. The boundary releases that audio's charge at once, so the refill is kept, and
// the sync task's later return of the old items releases nothing twice.
TEST(PlayerInboundHandOff, AStreamBoundaryFreesTheQuotaForTheRefillBehindIt) {
    enum class Boundary { NONE, CLEAR, END };
    struct Row {
        const char* name;
        Boundary boundary;
        std::vector<uint8_t> listed;
    };
    const Row rows[] = {
        {"Control: no boundary, the full quota drops the refill", Boundary::NONE, {0x01, 0x11}},
        // 0x00 is the clear marker, which carries no encoded bytes.
        {"stream/clear", Boundary::CLEAR, {0x01, 0x11, 0x00, 0x02, 0x12}},
        {"stream/end", Boundary::END, {0x01, 0x11, 0x02, 0x12}},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        InboundRing& ring = *impl->sync_task->inbound().ring();
        for (uint8_t marker : {0x01, 0x11}) {
            InboundMessage old_chunk = receive_into_ring(ring, audio_chunk(marker), 0);
            impl->handle_binary(old_chunk);
        }
        const size_t full = ring.quota(InboundHolder::PLAYER).outstanding();
        ASSERT_GT(full, 0U);
        ring.quota(InboundHolder::PLAYER).set_limit(full);

        if (row.boundary == Boundary::CLEAR) {
            impl->handle_stream_clear();
            take_in_ring_order(ring);
        } else if (row.boundary == Boundary::END) {
            impl->handle_stream_end();
        }
        for (uint8_t marker : {0x02, 0x12}) {
            InboundMessage refill = receive_into_ring(ring, audio_chunk(marker), 0);
            impl->handle_binary(refill);
        }

        EXPECT_EQ(take_all(*impl), row.listed);
        EXPECT_EQ(ring.quota(InboundHolder::PLAYER).outstanding(), 0U)
            << "an item's charge was kept or released twice";
    }
}

// A teardown (a dropped connection, a removed role, stop()) moves the role's generation on, and
// the old stream's audio never plays: cleanup() recalls what the sync task has not taken,
// returning it and its quota charge to the ring, and an item the sync task takes between the
// generation bump and the recall is dropped by its generation stamp and returned the same way.
// That window has no observable trigger, so its row moves the generation on directly
// (cleanup_generation), leaving the items listed.
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
// not applied after the stream it belonged to was torn down. The slot (event_state's
// command_slot) is written with the old stamp directly, the payload a drain that took it before
// the teardown would hold; no observable call stages that interleaving on demand.
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

// roles/player/v1.md "stream/start player object" ignores bit_depth for opus, which decodes to
// 16-bit samples whatever the server sent. The codec header the sync task decodes with and the
// params stream_info() reports both carry the decoded depth.
TEST(PlayerStreamStart, BitDepthIsTheDecodedDepth) {
    struct Row {
        const char* name;
        SendspinCodecFormat codec;
        uint8_t decoded_bit_depth;
    };
    const Row rows[] = {
        {"Control: pcm keeps the server's depth", SendspinCodecFormat::PCM, 24},
#ifdef SENDSPIN_ENABLE_OPUS
        {"opus publishes the decoder's depth", SendspinCodecFormat::OPUS, 16},
#endif
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto impl = make_impl();
        PlayerStreamParams params = pcm_stream_params();
        params.codec = row.codec;
        params.sample_rate = 48000;
        params.bit_depth = 24;
        impl->handle_stream_start({params});

        void* header_item = impl->sync_task->take_item(0);
        ASSERT_NE(header_item, nullptr);
        DummyHeader header{};
        ASSERT_EQ(SyncTask::encoded_size(header_item), sizeof(header));
        std::memcpy(&header, SyncTask::encoded_data(header_item), sizeof(header));
        impl->sync_task->inbound().return_item(header_item);
        EXPECT_EQ(header.bits_per_sample, row.decoded_bit_depth);

        PlayerStreamParams published;
        uint32_t generation = 0;
        ASSERT_TRUE(impl->event_state->stream_params_slot.take(published, generation));
        EXPECT_EQ(published.bit_depth, row.decoded_bit_depth);
    }
}

// roles/player/v1.md "Codec framing": the sync task's FLAC decoder starts from the codec header the
// parse decoded, so the item it takes holds exactly those bytes, typed as a FLAC header.
TEST(PlayerStreamStart, FlacHandsTheParsedHeaderToTheSyncTask) {
    auto impl = make_impl();
    PlayerStreamPayload payload{pcm_stream_params()};
    payload.params.codec = SendspinCodecFormat::FLAC;
    FlacCodecHeader header{'f', 'L', 'a', 'C', 0x80, 0x00, 0x00, 0x22};
    for (size_t i = 8; i < header.size(); ++i) {
        header[i] = static_cast<uint8_t>(i);
    }
    payload.flac_header = header;
    impl->handle_stream_start(payload);

    void* header_item = impl->sync_task->take_item(0);
    ASSERT_NE(header_item, nullptr);
    EXPECT_EQ(inbound_item_header(header_item)->type, CHUNK_TYPE_FLAC_HEADER);
    ASSERT_EQ(SyncTask::encoded_size(header_item), header.size());
    EXPECT_EQ(std::memcmp(SyncTask::encoded_data(header_item), header.data(), header.size()), 0);
    impl->sync_task->inbound().return_item(header_item);
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

// roles/player/v1.md "server/command player object": an unadvertised volume or mute command
// reaches neither the listener nor the stored value.
TEST(PlayerRoleSupportedCommands, VolumeAndMuteCommandsAreIgnoredUnlessAdvertised) {
    class LevelListener : public PlayerRoleListener {
    public:
        size_t on_audio_output(std::span<const uint8_t> pcm, const AudioFormat& /*format*/,
                               uint32_t /*timeout_ms*/) override {
            return pcm.size();
        }
        void on_volume_changed(uint8_t volume) override {
            this->volumes.push_back(volume);
        }
        void on_mute_changed(bool muted) override {
            this->mutes.push_back(muted);
        }
        std::vector<uint8_t> volumes;
        std::vector<bool> mutes;
    };
    struct Row {
        const char* name;
        bool volume;
        bool mute;
    };
    const Row rows[] = {
        {"Control: both advertised", true, true},
        {"volume not advertised", false, true},
        {"mute not advertised", true, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        LevelListener listener;  // Outlives the role that holds it
        SendspinClient client(make_client_config("player-command-gate"));
        auto& player = client.add_player(make_player_config());
        player.set_listener(&listener);
        player.set_volume_adjustable(row.volume);
        player.set_mute_adjustable(row.mute);

        ServerPlayerCommandObject player_cmd;
        player_cmd.command = SendspinPlayerCommand::VOLUME;
        player_cmd.volume = 70;
        player_cmd.mute = true;
        ServerCommandMessage cmd;
        cmd.player = player_cmd;
        player.impl_->handle_server_command(cmd);
        player.impl_->drain_events();

        EXPECT_EQ(listener.volumes, row.volume ? std::vector<uint8_t>{70} : std::vector<uint8_t>{});
        EXPECT_EQ(listener.mutes, row.mute ? std::vector<bool>{true} : std::vector<bool>{});
        EXPECT_EQ(player.get_volume(), row.volume ? 70 : 0);
        EXPECT_EQ(player.get_muted(), row.mute);
    }
}

// roles/player/v1.md "server/command player object": set_output_delay is only honored while the
// player advertises it in supported_commands, which the consumer sees as on_output_delay_changed().
TEST(PlayerRoleOutputDelay, SetOutputDelayCommandIsIgnoredUnlessAdvertised) {
    class DelayListener : public PlayerRoleListener {
    public:
        size_t on_audio_output(std::span<const uint8_t> pcm, const AudioFormat& /*format*/,
                               uint32_t /*timeout_ms*/) override {
            return pcm.size();
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

// ============================================================================
// Hard sync after an underrun: the gap is measured from now
// ============================================================================

// The estimate an underrun leaves behind (the end of the last audio played) is moved up to the
// current time once it trails it by more than the hard-sync threshold
// (SyncTask::starved_playtime_floor()).
TEST(PlayerHardSync, AStarvedEstimateIsFlooredAtNow) {
    constexpr int64_t NOW = 1'000'000'000;
    struct Row {
        const char* name;
        int64_t playtime;
        int64_t expected;
    };
    const Row rows[] = {
        {"Control: ahead of now", NOW + 50'000, NOW + 50'000},
        {"Control: behind by exactly the threshold", NOW - 5'000, NOW - 5'000},
        {"behind by just over the threshold", NOW - 5'001, NOW},
        {"behind by a long underrun", NOW - 20'000'000, NOW},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(SyncTask::starved_playtime_floor(row.playtime, NOW), row.expected);
    }
}

// A chunk is skipped undecoded (SyncTask::chunk_is_unplayably_late()) only when it is later than
// its own length, predicted from the previous chunk or MAX_AUDIO_CHUNK_MS until one has decoded;
// a less late chunk is decoded.
TEST(PlayerHardSync, OnlyAChunkLaterThanItsOwnLengthIsSkipped) {
    constexpr int64_t PLAYTIME = 1'000'000'000;
    constexpr int64_t TYPICAL_CHUNK_US = 25'000;
    constexpr int64_t NO_ESTIMATE = 0;  // No chunk of the stream has decoded yet
    struct Row {
        const char* name;
        int64_t client_timestamp;
        int64_t expected_duration_us;
        bool expected;
    };
    const Row rows[] = {
        {"Control: due after the estimate", PLAYTIME + 50'000, TYPICAL_CHUNK_US, false},
        {"Control: due exactly at the estimate", PLAYTIME, TYPICAL_CHUNK_US, false},
        {"behind by the hard-sync threshold", PLAYTIME - 5'000, TYPICAL_CHUNK_US, false},
        {"behind by just under its own length", PLAYTIME - 24'000, TYPICAL_CHUNK_US, false},
        {"behind by exactly its own length", PLAYTIME - 25'000, TYPICAL_CHUNK_US, false},
        {"behind by just over its own length", PLAYTIME - 26'000, TYPICAL_CHUNK_US, true},
        {"behind by a long underrun", PLAYTIME - 20'000'000, TYPICAL_CHUNK_US, true},
        {"No estimate yet: behind by more than a typical chunk", PLAYTIME - 100'000, NO_ESTIMATE,
         false},
        {"No estimate yet: behind by exactly the longest chunk", PLAYTIME - 150'000, NO_ESTIMATE,
         false},
        {"No estimate yet: behind by just over the longest chunk", PLAYTIME - 150'001, NO_ESTIMATE,
         true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(SyncTask::chunk_is_unplayably_late(row.client_timestamp,
                                                     row.expected_duration_us, PLAYTIME),
                  row.expected);
    }
}

namespace {

// A sink that accepts every write and records the bytes in order, and each write's length, first
// byte and format.
struct RecordingSink : PlayerRoleListener {
    struct Write {
        size_t bytes;
        uint8_t first_byte;
        AudioFormat format;
        bool operator==(const Write&) const = default;
    };

    size_t on_audio_output(std::span<const uint8_t> pcm, const AudioFormat& format,
                           uint32_t /*timeout_ms*/) override {
        written.insert(written.end(), pcm.begin(), pcm.end());
        writes.push_back({pcm.size(), pcm.empty() ? uint8_t{0} : pcm.front(), format});
        return pcm.size();
    }
    std::vector<uint8_t> written;
    std::vector<Write> writes;
};

}  // namespace

// roles/player/v1.md "Large errors and startup": after a long underrun the estimate still ends
// where the last audio did. Measured from there, a chunk due shortly would get the whole underrun
// as silence ahead of it; measured from now it gets at most its own lead. The test thread runs
// the hard-sync steps (SyncTask's handle_synchronize_audio() and handle_transfer_audio()).
TEST(PlayerHardSync, AfterAnUnderrunTheGapIsMeasuredFromNow) {
    constexpr uint8_t CHUNK_SAMPLE = 0x7F;
    constexpr uint32_t LEAD_FRAMES = 44100;  // 1 s at 44.1 kHz
    constexpr uint32_t CHUNK_FRAMES = 441;
    auto impl = make_impl();
    RecordingSink sink;
    impl->listener = &sink;

    // One decoded chunk due 1 s from now, against an estimate left 20 s behind. The lead is long
    // enough that the chunk still needs a hard sync however slowly this runs.
    SyncContext context;
    context.current_stream_info = AudioStreamInfo(16, 2, 44100);
    context.bytes_per_frame = context.current_stream_info.frames_to_bytes(1);
    const size_t chunk_bytes = context.current_stream_info.frames_to_bytes(CHUNK_FRAMES);
    ASSERT_TRUE(context.decode_buffer.allocate(chunk_bytes + context.bytes_per_frame,
                                               MemoryLocation::PREFER_INTERNAL));
    std::memset(context.decode_buffer.get_buffer_end(), CHUNK_SAMPLE, chunk_bytes);
    context.decode_buffer.increase_buffer_length(chunk_bytes);
    const int64_t now = platform_time_us();
    context.new_audio_client_playtime = now - 20'000'000;
    context.decoded_timestamp = now + 1'000'000;
    context.hard_syncing = false;
    context.aligning = false;

    // The SYNCHRONIZE_AUDIO/TRANSFER_AUDIO states, as the sync thread runs them, until the chunk
    // is out.
    SyncTask& task = *impl->sync_task;
    SyncTaskState state = task.handle_synchronize_audio(context);
    while (state != SyncTaskState::LOAD_CHUNK) {
        state = state == SyncTaskState::SYNCHRONIZE_AUDIO ? task.handle_synchronize_audio(context)
                                                          : task.handle_transfer_audio(context);
    }

    const auto first_chunk_byte = std::find(sink.written.begin(), sink.written.end(), CHUNK_SAMPLE);
    const uint32_t silence_frames = context.current_stream_info.bytes_to_frames(
        static_cast<size_t>(first_chunk_byte - sink.written.begin()));
    // Time passing only shortens the lead, so the bound holds however slowly this runs.
    EXPECT_LE(silence_frames, LEAD_FRAMES);
    // Control: the chunk follows the silence whole.
    EXPECT_EQ(sink.written.end() - first_chunk_byte, static_cast<std::ptrdiff_t>(chunk_bytes));
}

// ============================================================================
// Audio output: the callback the library writes through and the format of every write
// ============================================================================

namespace {

// A listener still on the deprecated on_audio_write(), recording the bytes it receives.
struct DeprecatedFormListener : PlayerRoleListener {
    size_t on_audio_write(uint8_t* data, size_t length, uint32_t /*timeout_ms*/) override {
        written.insert(written.end(), data, data + length);
        return length;
    }
    std::vector<uint8_t> written;
};

// An audio chunk message as handle_binary() receives it, due at server time 0, its frame `bytes`
// bytes of `fill`.
std::vector<uint8_t> filled_audio_chunk(uint8_t fill, size_t bytes) {
    std::vector<uint8_t> chunk = audio_chunk();
    chunk.resize(chunk.size() - 4);  // Drop audio_chunk()'s own frame
    chunk.insert(chunk.end(), bytes, fill);
    return chunk;
}

// A PCM stream/start player object of the given format.
PlayerStreamParams pcm_stream(uint32_t sample_rate, uint8_t channels, uint8_t bit_depth) {
    PlayerStreamParams params;
    params.codec = SendspinCodecFormat::PCM;
    params.sample_rate = sample_rate;
    params.channels = channels;
    params.bit_depth = bit_depth;
    return params;
}

// The helpers below play the sync thread's steps on the test thread (SyncTask's reset_context(),
// decode_chunk(), transfer_audio() and send_pending_silence()), since only the thread otherwise
// writes a stream's audio and silence across a format change.

// A SyncContext as IDLE leaves it for a new stream, past its initial-sync priming, so a silence
// write does not wait for the sink to settle.
void start_context(SyncTask& task, SyncContext& context) {
    context.decoder = std::make_unique<SendspinDecoder>();
    task.reset_context(context);
    context.initial_decode = false;
}

// Takes the next item off the sync task's list and decodes it, as LOAD_CHUNK does.
void decode_next_item(SyncTask& task, SyncContext& context) {
    context.encoded_item = task.take_item(0);
    ASSERT_NE(context.encoded_item, nullptr);
    ASSERT_EQ(task.decode_chunk(context), DecodeResult::SUCCESS);
}

// Runs TRANSFER_AUDIO on the decoded chunk until everything pending is out. Bounded, so a
// listener that takes nothing fails the caller's checks rather than hanging.
void transfer_pending(SyncTask& task, SyncContext& context) {
    context.release_chunk = true;
    for (int pass = 0; pass < 8 && !task.transfer_audio(context); ++pass) {
    }
}

}  // namespace

// A listener still on the deprecated on_audio_write() (the ESPHome hub until it moves) gets the
// audio through on_audio_output()'s default.
TEST(PlayerAudioOutput, TheDeprecatedWriteStillReceivesTheAudio) {
    constexpr uint8_t CHUNK_SAMPLE = 0x5A;
    constexpr uint32_t CHUNK_FRAMES = 4;
    constexpr uint32_t SILENCE_FRAMES = 2;
    auto impl = make_impl();
    DeprecatedFormListener listener;
    impl->listener = &listener;
    SyncContext context;
    context.current_stream_info = AudioStreamInfo(16, 2, 44100);
    context.bytes_per_frame = context.current_stream_info.frames_to_bytes(1);
    const size_t chunk_bytes = context.current_stream_info.frames_to_bytes(CHUNK_FRAMES);
    ASSERT_TRUE(context.decode_buffer.allocate(chunk_bytes + context.bytes_per_frame,
                                               MemoryLocation::PREFER_INTERNAL));
    std::memset(context.decode_buffer.get_buffer_end(), CHUNK_SAMPLE, chunk_bytes);
    context.decode_buffer.increase_buffer_length(chunk_bytes);
    context.silence_remaining = context.current_stream_info.frames_to_bytes(SILENCE_FRAMES);

    transfer_pending(*impl->sync_task, context);

    std::vector<uint8_t> expected(context.current_stream_info.frames_to_bytes(SILENCE_FRAMES),
                                  0x00);
    expected.insert(expected.end(), chunk_bytes, CHUNK_SAMPLE);
    EXPECT_EQ(listener.written, expected);
}

// roles/player/v1.md "stream/start": a stream/start that updates the running stream changes the
// format from the chunks after it; those before it are in the old one. Each write carries the
// format of its own bytes, the silence included, though the main loop has already applied the
// update by the time the old audio is written.
TEST(PlayerAudioOutput, EachWriteCarriesTheFormatOfItsOwnBytes) {
    constexpr AudioFormat OLD_FORMAT{.sample_rate = 44100, .channels = 2, .bits_per_sample = 16};
    constexpr AudioFormat NEW_FORMAT{.sample_rate = 48000, .channels = 1, .bits_per_sample = 24};
    constexpr uint8_t OLD_SAMPLE = 0xA1;
    constexpr uint8_t NEW_SAMPLE = 0xB2;
    constexpr size_t OLD_FRAME_BYTES = 4;
    constexpr size_t NEW_FRAME_BYTES = 3;
    auto impl = make_impl();
    RecordingSink sink;
    impl->listener = &sink;
    // Every chunk due a second ahead, so none is skipped as late against the playtime the writes
    // below advance.
    impl->config.fixed_delay_us = -1'000'000;

    impl->handle_stream_start(
        {pcm_stream(OLD_FORMAT.sample_rate, OLD_FORMAT.channels, OLD_FORMAT.bits_per_sample)});
    std::vector<uint8_t> old_chunk = filled_audio_chunk(OLD_SAMPLE, 2 * OLD_FRAME_BYTES);
    InboundMessage old_message = message_over(old_chunk);
    impl->handle_binary(old_message);
    impl->handle_stream_start(
        {pcm_stream(NEW_FORMAT.sample_rate, NEW_FORMAT.channels, NEW_FORMAT.bits_per_sample)});
    std::vector<uint8_t> new_chunk = filled_audio_chunk(NEW_SAMPLE, 2 * NEW_FRAME_BYTES);
    InboundMessage new_message = message_over(new_chunk);
    impl->handle_binary(new_message);
    // The main loop drained both STREAM_STARTs before the sync task wrote the old audio.
    impl->current_stream_params.sample_rate = NEW_FORMAT.sample_rate;
    impl->current_stream_params.channels = NEW_FORMAT.channels;
    impl->current_stream_params.bit_depth = NEW_FORMAT.bits_per_sample;

    SyncTask& task = *impl->sync_task;
    SyncContext context;
    start_context(task, context);
    ASSERT_NO_FATAL_FAILURE(decode_next_item(task, context));  // The old format's header
    ASSERT_NO_FATAL_FAILURE(decode_next_item(task, context));  // Its chunk
    // A hard-sync gap ahead of it
    context.silence_remaining = 2 * OLD_FRAME_BYTES;
    transfer_pending(task, context);
    // Underflow silence still pending when the update's header is taken: counted in the old
    // format's bytes, which are not whole frames of the new one.
    context.silence_remaining = 2 * OLD_FRAME_BYTES;
    ASSERT_NO_FATAL_FAILURE(decode_next_item(task, context));  // The update's header
    ASSERT_NO_FATAL_FAILURE(decode_next_item(task, context));  // Its chunk
    transfer_pending(task, context);
    // A hard-sync gap in the new format
    context.silence_remaining = 2 * NEW_FRAME_BYTES;
    task.send_pending_silence(context);

    using Write = RecordingSink::Write;
    const std::vector<Write> expected = {
        {2 * OLD_FRAME_BYTES, 0x00, OLD_FORMAT},
        {2 * OLD_FRAME_BYTES, OLD_SAMPLE, OLD_FORMAT},
        {2 * NEW_FRAME_BYTES, NEW_SAMPLE, NEW_FORMAT},
        {2 * NEW_FRAME_BYTES, 0x00, NEW_FORMAT},
    };
    ASSERT_EQ(sink.writes.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        SCOPED_TRACE("write " + std::to_string(i));
        EXPECT_EQ(sink.writes[i].bytes, expected[i].bytes);
        EXPECT_EQ(sink.writes[i].first_byte, expected[i].first_byte);
        EXPECT_EQ(sink.writes[i].format, expected[i].format)
            << sink.writes[i].format.sample_rate << " Hz, "
            << int{sink.writes[i].format.channels} << " ch, "
            << int{sink.writes[i].format.bits_per_sample} << "-bit";
    }
}
