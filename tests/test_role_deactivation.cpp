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

/// messaging.md "server/activate", "When applying a server/activate, the client MUST": a later
/// activation that removes a role stops that role's output and clears its buffers, and discards a
/// removed state role's current state and pending scheduled update. Roles the activation leaves
/// active keep streaming untouched, an activation that moves no role changes nothing, and a role
/// that is added back works again.
///
/// The client is driven on loopback ports like test_client_lifecycle.cpp: a FakeEncryptedServer
/// plays the Sendspin server over the real Noise transport, the test thread pumps client.loop(),
/// and each later activation is sent as a plain application message.

#include "artwork_role_impl.h"  // In-flight transfer state after a removal; private, see CMakeLists
#include "color_role_impl.h"     // Held scheduled palette after a removal
#include "controller_role_impl.h"  // Seeded supported-commands mask for the inactive-role send gate
#include "crypto/constants.h"
#include "metadata_role_impl.h"  // Held scheduled metadata state after a removal
#include "lifecycle_test_fixtures.h"
#include "platform/time.h"
#include "player_role_impl.h"  // Sync task state after a removal
#include "protocol_messages.h"  // SENDSPIN_BINARY_VISUALIZER_LOUDNESS
#include "sendspin/artwork_role.h"
#include "sendspin/client.h"
#include "sendspin/color_role.h"
#include "sendspin/config.h"
#include "sendspin/controller_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/visualizer_role.h"
#include "inbox.h"
#include "sync_task.h"
#include "visualizer_role_impl.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// Distinct ports per test, above the ranges the other lifecycle suites use (test_client_lifecycle
// ends at 19020).
constexpr uint16_t PLAYER_REMOVED_TEST_PORT = 19031;
constexpr uint16_t STATE_ROLES_REMOVED_TEST_PORT = 19032;
constexpr uint16_t ARTWORK_REMOVED_TEST_PORT = 19033;
constexpr uint16_t VISUALIZER_REMOVED_TEST_PORT = 19034;
constexpr uint16_t NO_CHANGE_TEST_PORT = 19035;
constexpr uint16_t READD_TEST_PORT = 19036;
constexpr uint16_t STALE_START_TEST_PORT = 19037;
constexpr uint16_t STALE_START_CONTROL_TEST_PORT = 19038;
constexpr uint16_t INACTIVE_TRAFFIC_TEST_PORT = 19039;
constexpr uint16_t VERSION_REPLACED_TEST_PORT = 19040;
constexpr uint16_t INACTIVE_ROLE_SEND_TEST_PORT = 19085;

/// A group/update the protocol task processes after whatever the server sent before it, so its
/// inbox bit marks those messages as applied.
constexpr const char* GROUP_UPDATE_JSON =
    R"({"type":"group/update","payload":{"playback_state":"playing"}})";

/// How long a scenario pumps to give a callback that must NOT fire every chance to fire.
constexpr int SETTLE_MS = 300;

/// Far enough ahead that a state stamped with it can never come due while the suite runs (the
/// hang watchdog fires at 55 s), so "still pending" is a state of the role, not a race.
constexpr int64_t NEVER_DUE_LEAD_US = 10 * 60 * 1000 * 1000LL;

SendspinClientConfig make_config(uint16_t port) {
    SendspinClientConfig config;
    config.name = "Role Deactivation Test Client";
    config.server_port = port;
    config.time_burst_interval_ms = 100;  // Sync promptly after the connect
    return config;
}

std::string activate_json(const std::string& roles_json) {
    return R"({"type":"server/activate","payload":{"activities":["playback"],"active_roles":)" +
           roles_json + "}}";
}

std::string stream_start_artwork_json() {
    return R"({"type":"stream/start","payload":{"artwork":{"channels":[{"source":"album",)"
           R"("format":"jpeg","width":100,"height":100}]}}})";
}

std::string color_state_json(int64_t timestamp) {
    return R"({"type":"server/state","payload":{"color":{"timestamp":)" +
           std::to_string(timestamp) + R"(,"primary":[10,20,30]}}})";
}

std::string controller_state_json(uint8_t volume) {
    return R"({"type":"server/state","payload":{"controller":{"supported_commands":["play"],)"
           R"("volume":)" +
           std::to_string(volume) + R"(,"muted":false,"repeat":"off","shuffle":false}}})";
}

ArtworkRoleConfig make_artwork_config() {
    ArtworkRoleConfig config;
    config.preferred_formats.push_back(
        {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 100, 100, false});
    return config;
}

class RecordingControllerListener : public ControllerRoleListener {
public:
    void on_controller_state(const ServerStateControllerObject& state) override {
        ++this->updates;
        this->last_volume = state.volume;
    }
    void on_controller_state_clear() override {
        ++this->clears;
    }

    int updates{0};
    int clears{0};
    uint8_t last_volume{0};
};

class RecordingArtworkListener : public ArtworkRoleListener {
public:
    void on_image_decode(uint8_t /*slot*/, const uint8_t* /*data*/, size_t length,
                         SendspinImageFormat /*format*/) override {
        this->decodes.fetch_add(1);
        this->last_decode_length.store(length);
    }
    void on_image_clear(uint8_t slot) override {
        ++this->clears;
        this->last_clear_slot = slot;
    }

    std::atomic<size_t> decodes{0};
    std::atomic<size_t> last_decode_length{0};
    int clears{0};
    int last_clear_slot{-1};
};

// Pumps until `done`, feeding loudness frames stamped just ahead of now so the drain thread does
// not drop them as already past.
void send_loudness_until(SendspinClient& client, FakeEncryptedServer& server,
                         const std::function<bool()>& done) {
    constexpr int64_t LEAD_US = 50 * 1000;
    pump_until(client, [&] {
        if (done()) {
            return true;
        }
        server.send_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, platform_time_us() + LEAD_US,
                           std::string("\x00\x10", 2));
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        return false;
    });
}

// roles/artwork/v1.md "Artwork (Binary)": [type][flags][timestamp][total_size], flags bit 1 set.
std::vector<uint8_t> artwork_announce(int64_t timestamp, uint32_t total_size) {
    std::vector<uint8_t> body{SENDSPIN_BINARY_ARTWORK_IMAGE, 0x02};
    put_be64(body, timestamp);
    put_be32(body, total_size);
    return body;
}

// roles/artwork/v1.md "Artwork (Binary)": [type][flags][data], no flag bits set.
std::vector<uint8_t> artwork_part(size_t length) {
    std::vector<uint8_t> body{SENDSPIN_BINARY_ARTWORK_IMAGE, 0x00};
    for (size_t i = 0; i < length; ++i) {
        body.push_back(static_cast<uint8_t>(i));
    }
    return body;
}

}  // namespace

// ============================================================================
// Stream roles
// ============================================================================

// An activation that drops player@v1 stops the player: the sync task leaves the stream (so no
// further PCM is written, buffered or not) and the consumer is told through on_stream_end().
// The roles the same activation keeps are untouched: messaging.md "server/activate", "State for
// roles that remain active at the same version is unchanged".
TEST(RoleDeactivation, RemovedPlayerStopsTheStreamAndLeavesTheOtherRolesAlone) {
    CountingPlayerListener player_listener;
    CountingVisualizerListener visualizer_listener;
    RecordingMetadataListener metadata_listener;

    PairedClientBundle bundle(make_config(PLAYER_REMOVED_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_visualizer(make_visualizer_config()).set_listener(&visualizer_listener);
    client.add_metadata().set_listener(&metadata_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","visualizer@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, PLAYER_REMOVED_TEST_PORT, std::move(options));
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Before Removal")));
    pump_until(client, [&] {
        return player_listener.stream_starts == 1 && visualizer_listener.stream_starts == 1 &&
               metadata_listener.updates == 1;
    });
    stream_audio_until(client, *server, player_listener, 1);
    ASSERT_TRUE(client.player()->impl_->sync_task->is_running());

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["visualizer@v1","metadata@v1"])")));
    pump_until(client, [&] { return player_listener.stream_ends == 1; });
    EXPECT_FALSE(client.player()->impl_->sync_task->is_running())
        << "the sync task kept decoding a stream the activation removed";

    // Nothing more reaches the audio output: the chunks below arrive for a role that is no longer
    // streaming, and the sync task is idle with no codec header to restart it.
    const size_t writes_after_removal = player_listener.audio_writes.load();
    int64_t ts = platform_time_us() + 50 * 1000;
    for (int i = 0; i < 5; ++i) {
        server->send_audio(ts, 48000 / 50 * 2 * 2);
        ts += 20 * 1000;
    }
    pump_for(client, SETTLE_MS);
    EXPECT_EQ(player_listener.audio_writes.load(), writes_after_removal);

    // The roles that stayed active carry on.
    EXPECT_EQ(visualizer_listener.stream_ends, 0) << "a role the activation kept was torn down";
    EXPECT_EQ(metadata_listener.clears, 0) << "a role the activation kept lost its state";
    EXPECT_EQ(metadata_listener.last_title, "Before Removal");
    const size_t loudness_before = visualizer_listener.loudness.load();
    send_loudness_until(client, *server,
                        [&] { return visualizer_listener.loudness.load() > loudness_before; });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// An activation that drops visualizer@v1 ends its stream: the consumer sees
// on_visualizer_stream_end(), the buffered frames are flushed, and later frames for the removed
// role are not delivered. The player, which the same activation keeps, still plays.
TEST(RoleDeactivation, RemovedVisualizerEndsTheStreamAndStopsDelivery) {
    CountingPlayerListener player_listener;
    CountingVisualizerListener visualizer_listener;

    PairedClientBundle bundle(make_config(VISUALIZER_REMOVED_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_visualizer(make_visualizer_config()).set_listener(&visualizer_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","visualizer@v1"])";
    auto server =
        connect_paired_server(bundle.peer, VISUALIZER_REMOVED_TEST_PORT, std::move(options));
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    pump_until(client, [&] {
        return visualizer_listener.stream_starts == 1 && player_listener.stream_starts == 1;
    });
    send_loudness_until(client, *server, [&] { return visualizer_listener.loudness.load() >= 1; });

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1"])")));
    pump_until(client, [&] { return visualizer_listener.stream_ends == 1; });
    // A plain protocol-task field: the stream end pumped through the Inbox mutex orders this read.
    EXPECT_FALSE(client.visualizer()->impl_->stream_active)
        << "the visualizer still accepts frames for a role the activation removed";

    const size_t loudness_after_removal = visualizer_listener.loudness.load();
    for (int i = 0; i < 5; ++i) {
        server->send_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, platform_time_us(),
                            std::string("\x00\x10", 2));
    }
    pump_for(client, SETTLE_MS);
    EXPECT_EQ(visualizer_listener.loudness.load(), loudness_after_removal)
        << "frames were delivered for a role the activation removed";
    EXPECT_TRUE(client.visualizer()->impl_->drain_task->inbound.items().is_empty())
        << "the removed role kept its buffered frames";

    EXPECT_EQ(player_listener.stream_ends, 0) << "a role the activation kept was torn down";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// An activation that drops artwork@v1 clears every channel (roles/artwork/v1.md
// "Artwork (Binary)" has an artwork stream/end clear the current image and discard the pending
// one, and the removal applies the same teardown) and drops the transfer that was in flight.
// Adding the role back gives a working channel again: a whole image announced afterwards decodes,
// with none of the abandoned bytes in it.
TEST(RoleDeactivation, RemovedArtworkDropsTheInFlightTransferAndClearsTheChannel) {
    constexpr uint32_t IMAGE_BYTES = 64;
    RecordingArtworkListener artwork_listener;
    RecordingMetadataListener metadata_listener;

    PairedClientBundle bundle(make_config(ARTWORK_REMOVED_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_artwork(make_artwork_config()).set_listener(&artwork_listener);
    client.add_metadata().set_listener(&metadata_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["artwork@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, ARTWORK_REMOVED_TEST_PORT, std::move(options));
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_artwork_json()));
    ASSERT_TRUE(server->send_binary_body(artwork_announce(platform_time_us(), IMAGE_BYTES)));
    ASSERT_TRUE(server->send_binary_body(artwork_part(IMAGE_BYTES / 2)));

    // The connection's messages are handled in order, so the half-sent transfer is in flight when
    // the activation removes the role. The re-sent stream/start below would end a surviving
    // transfer anyway (cleanup() forgets the streamed channels, so every channel counts as
    // changed), so the direct read of transfer.in_flight after the clear is what guards its reset.
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["metadata@v1"])")));
    pump_until(client, [&] { return artwork_listener.clears == 1; });
    EXPECT_EQ(artwork_listener.last_clear_slot, 0);
    // The transfer belongs to the protocol task, which wrote it before the teardown queued the
    // clear just delivered and does not touch it again here, so it is read after that delivery.
    EXPECT_FALSE(client.artwork()->impl_->transfer.in_flight)
        << "the in-flight transfer survived the removal";
    EXPECT_EQ(artwork_listener.decodes.load(), 0U);
    EXPECT_EQ(metadata_listener.clears, 0) << "a role the activation kept was torn down";

    // Back in: the channel works again, and the image that arrives is whole rather than the
    // abandoned half plus new parts.
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["artwork@v1","metadata@v1"])")));
    ASSERT_TRUE(server->send_app_json(stream_start_artwork_json()));
    ASSERT_TRUE(server->send_binary_body(artwork_announce(platform_time_us(), IMAGE_BYTES)));
    ASSERT_TRUE(server->send_binary_body(artwork_part(IMAGE_BYTES)));
    pump_until(client, [&] { return artwork_listener.decodes.load() == 1; });
    EXPECT_EQ(artwork_listener.last_decode_length.load(), IMAGE_BYTES);

    // The assembly buffers are the run's memory: allocated by start(), one per configured
    // channel at its max_image_bytes, they would otherwise stay allocated for the client's life,
    // half a megabyte at the defaults, on a device that is no longer showing artwork. A stop hands
    // them back. No callback reports a release, so the buffers are read directly: holding memory
    // is not something a caller or peer can observe. Only the buffer objects are read, which the
    // decode thread never reassigns.
    auto* drain = client.artwork()->impl_->drain_task.get();
    ASSERT_NE(drain, nullptr);
    bool holds_a_buffer = false;
    for (const auto& assembly : drain->assemblies) {
        holds_a_buffer = holds_a_buffer || assembly.buffer.data() != nullptr;
    }
    ASSERT_TRUE(holds_a_buffer) << "the running role holds no assembly buffer to release";

    client.stop();

    for (const auto& assembly : drain->assemblies) {
        EXPECT_EQ(assembly.buffer.data(), nullptr)
            << "a stopped artwork role is still holding an image buffer";
    }
}

// ============================================================================
// State roles
// ============================================================================

// An activation that drops metadata@v1, color@v1 and controller@v1 discards each role's current
// state and the scheduled update behind it, and tells the consumer the same way a connection loss
// does. The player, which the same activation keeps, is not touched.
TEST(RoleDeactivation, RemovedStateRolesDiscardCurrentAndScheduledState) {
    CountingPlayerListener player_listener;
    RecordingMetadataListener metadata_listener;
    RecordingColorListener color_listener;
    RecordingControllerListener controller_listener;

    PairedClientBundle bundle(make_config(STATE_ROLES_REMOVED_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_metadata().set_listener(&metadata_listener);
    client.add_color().set_listener(&color_listener);
    client.add_controller().set_listener(&controller_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1","color@v1","controller@v1"])";
    auto server =
        connect_paired_server(bundle.peer, STATE_ROLES_REMOVED_TEST_PORT, std::move(options));
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Now Playing")));
    ASSERT_TRUE(server->send_app_json(color_state_json(1)));
    ASSERT_TRUE(server->send_app_json(controller_state_json(42)));
    pump_until(client, [&] {
        return metadata_listener.updates == 1 && color_listener.updates == 1 &&
               controller_listener.updates == 1 && player_listener.stream_starts == 1;
    });
    // The generation a metadata handler would stamp right now, kept for the stale-stamp check at
    // the end.
    const uint32_t metadata_generation =
        client.metadata()->impl_->cleanup_generation.load(std::memory_order_acquire);

    // The scheduled updates behind the current states: due so far in the future that they are
    // still pending when the removal lands.
    const int64_t scheduled_ts = platform_time_us() + NEVER_DUE_LEAD_US;
    ASSERT_TRUE(server->send_app_json(metadata_state_json(scheduled_ts, "Up Next")));
    ASSERT_TRUE(server->send_app_json(color_state_json(scheduled_ts)));
    pump_until(client, [&] {
        return client.metadata()->impl_->held_state.has_value() &&
               client.color()->impl_->held_state.has_value();
    });
    ASSERT_EQ(metadata_listener.updates, 1) << "a scheduled update was applied early";

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1"])")));
    pump_until(client, [&] {
        return metadata_listener.clears == 1 && color_listener.clears == 1 &&
               controller_listener.clears == 1;
    });

    EXPECT_FALSE(client.metadata()->impl_->held_state.has_value())
        << "the removed metadata role kept its scheduled update";
    EXPECT_FALSE(client.color()->impl_->held_state.has_value())
        << "the removed color role kept its scheduled update";
    EXPECT_EQ(client.metadata()->get_track_duration_ms(), 0U);
    EXPECT_EQ(client.metadata()->get_track_progress_ms(), 0U);
    EXPECT_EQ(client.controller()->get_controller_state().volume, 0)
        << "the removed controller role kept its state";

    // No late application of anything that was discarded, and the role the activation kept plays
    // on.
    pump_for(client, SETTLE_MS);
    EXPECT_EQ(metadata_listener.updates, 1);
    EXPECT_EQ(color_listener.updates, 1);
    EXPECT_EQ(controller_listener.updates, 1);
    EXPECT_EQ(player_listener.stream_ends, 0) << "a role the activation kept was torn down";
    stream_audio_until(client, *server, player_listener, 1);

    // A state stamped with the pre-removal generation, the payload a drain takes on the far side
    // of the removal, is discarded at the drain: writing the role's slot with that stamp forces
    // the interleaving rather than racing for it.
    ServerMetadataStateObject overtaken;
    overtaken.timestamp = 1;
    overtaken.title = "Overtaken By The Removal";
    client.metadata()->impl_->event_state->slot.write(
        PendingMetadataStates{.oldest = std::move(overtaken)}, metadata_generation);
    pump_for(client, SETTLE_MS);
    EXPECT_EQ(metadata_listener.updates, 1)
        << "a payload stamped with the pre-removal generation was applied";

    // Control: the same write carrying the generation the role reports now is applied, so the
    // refusal above came from the stale generation and nothing else.
    ServerMetadataStateObject current;
    current.timestamp = 1;
    current.title = "Current Generation";
    client.metadata()->impl_->event_state->slot.write(
        PendingMetadataStates{.oldest = std::move(current)},
        client.metadata()->impl_->cleanup_generation.load(std::memory_order_acquire));
    pump_until(client, [&] { return metadata_listener.updates == 2; });

    // roles/controller/v1.md "client/command controller object": the removal discarded the offered
    // commands with the rest of the state, so after a re-add nothing goes out until a new
    // server/state offers it.
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1","controller@v1"])")));
    pump_for(client, SETTLE_MS);
    client.controller()->send_command({.command = SendspinControllerCommand::PLAY});
    pump_for(client, SETTLE_MS);
    EXPECT_TRUE(server->controller_commands().empty())
        << "a command the removed role's state offered was sent after the re-add";

    // Control: once a server/state offers it again, the same command goes out.
    ASSERT_TRUE(server->send_app_json(controller_state_json(42)));
    pump_until(client, [&] { return controller_listener.updates == 2; });
    client.controller()->send_command({.command = SendspinControllerCommand::PLAY});
    pump_until(client, [&] { return !server->controller_commands().empty(); });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// ============================================================================
// Controls
// ============================================================================

// The teardown is keyed on a role leaving the set, not on an activation arriving: re-sending the
// same active_roles, and adding a role to them, both leave every active role alone.
TEST(RoleDeactivation, ActivationThatRemovesNoRoleTearsNothingDown) {
    CountingPlayerListener player_listener;
    RecordingMetadataListener metadata_listener;
    RecordingColorListener color_listener;

    PairedClientBundle bundle(make_config(NO_CHANGE_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_metadata().set_listener(&metadata_listener);
    client.add_color().set_listener(&color_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, NO_CHANGE_TEST_PORT, std::move(options));
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Now Playing")));
    pump_until(client, [&] {
        return player_listener.stream_starts == 1 && metadata_listener.updates == 1;
    });

    // Same set again.
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1","metadata@v1"])")));
    pump_for(client, SETTLE_MS);
    EXPECT_EQ(player_listener.stream_ends, 0);
    EXPECT_EQ(metadata_listener.clears, 0);
    EXPECT_EQ(metadata_listener.last_title, "Now Playing");
    EXPECT_TRUE(client.player()->impl_->sync_task->is_running());

    // A wider set: color is added, the two that were active stay active.
    ASSERT_TRUE(
        server->send_app_json(activate_json(R"(["player@v1","metadata@v1","color@v1"])")));
    pump_for(client, SETTLE_MS);
    EXPECT_EQ(player_listener.stream_ends, 0);
    EXPECT_EQ(metadata_listener.clears, 0);
    EXPECT_EQ(color_listener.clears, 0);
    EXPECT_TRUE(client.player()->impl_->sync_task->is_running());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A role removed from a live session comes back on a later activation: the client publishes a
// client/state carrying its object again (messaging.md "client/state", which is what lets the
// server start the stream), and the stream that follows plays.
TEST(RoleDeactivation, ReAddedPlayerPublishesItsStateAndPlaysAgain) {
    CountingPlayerListener player_listener;

    PairedClientBundle bundle(make_config(READD_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_metadata();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, READD_TEST_PORT, std::move(options));
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    pump_until(client, [&] { return player_listener.stream_starts == 1; });
    stream_audio_until(client, *server, player_listener, 1);

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["metadata@v1"])")));
    pump_until(client, [&] { return player_listener.stream_ends == 1; });

    const size_t states_before_readd = server->client_states().size();
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1","metadata@v1"])")));

    // The activate that removed the player published a client/state of its own; that state
    // carries no player object (publish_client_state() gates each role object on the
    // connection's active roles) and may still be in flight here. Waiting for "one more
    // state than before" would therefore be satisfied by it, so wait for a state published after
    // the re-add that carries the object, and assert on that one. A re-add that publishes no such
    // state hangs here and the suite watchdog names it, as everywhere else in this file.
    std::string readd_state;
    pump_until(client, [&] {
        const std::vector<std::string> states = server->client_states();
        for (size_t i = states_before_readd; i < states.size(); ++i) {
            JsonDocument published;
            if (deserializeJson(published, states[i]) != DeserializationError::Ok) {
                continue;
            }
            if (published["payload"]["player"].is<JsonObjectConst>()) {
                readd_state = states[i];
                return true;
            }
        }
        return false;
    });
    {
        JsonDocument doc;
        ASSERT_EQ(deserializeJson(doc, readd_state), DeserializationError::Ok);
        JsonObjectConst player_object = doc["payload"]["player"];
        EXPECT_TRUE(player_object["supported_commands"].is<JsonArrayConst>())
            << "the re-added role's object was published without the commands the server needs";
        EXPECT_TRUE(player_object["required_lead_time_ms"].is<uint16_t>());
    }

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    pump_until(client, [&] { return player_listener.stream_starts == 2; });
    const size_t writes_before = player_listener.audio_writes.load();
    stream_audio_until(client, *server, player_listener, writes_before + 1);
    EXPECT_EQ(player_listener.stream_ends, 1);

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// ============================================================================
// Events already queued when the removal lands
// ============================================================================

// A stream/start that reached the inbox before the activate that removes the role must not act
// after it. The protocol task applies the activation (and the teardown) as soon as it parses it,
// while the START waits in the inbox for the main loop, so the START is drained with the role
// already stopped: acting on it would fire on_stream_start() for a removed role and re-arm the
// sync task, which then writes PCM from the chunks already in its ring.
//
// Nothing is pumped between the sends, so the START is provably still in the ring when the
// activate is applied: a group/update sent behind the activate is processed after it, and the
// test waits for its inbox bit beside the ring bit instead of for a duration.
TEST(RoleDeactivation, StreamStartQueuedBeforeARemovalNeverStarts) {
    CountingPlayerListener player_listener;

    PairedClientBundle bundle(make_config(STALE_START_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_metadata();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, STALE_START_TEST_PORT, std::move(options));
    pump_until_synced(client);

    // From here on the test thread does not pump: everything below queues up client-side.
    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    constexpr size_t PCM_20MS_BYTES = 48000 / 50 * 2 * 2;
    int64_t ts = platform_time_us() + 50 * 1000;
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(server->send_audio(ts, PCM_20MS_BYTES));
        ts += 20 * 1000;
    }
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["metadata@v1"])")));
    ASSERT_TRUE(server->send_app_json(GROUP_UPDATE_JSON));

    // Both halves are in: the START sits in the event ring and the activate has been applied,
    // since the group/update behind it reached the inbox.
    wait_until([&] {
        const uint32_t bits = client.player()->impl_->inbox->poll();
        return (bits & INBOX_TOPIC_EVENTS) != 0 && (bits & INBOX_TOPIC_GROUP) != 0;
    });

    pump_for(client, SETTLE_MS);
    EXPECT_EQ(player_listener.stream_starts, 0)
        << "a stream/start queued before the removal started a stream for the removed role";
    EXPECT_EQ(player_listener.audio_writes.load(), 0U)
        << "PCM was written for a role the activation removed";
    EXPECT_FALSE(client.player()->impl_->sync_task->is_running());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Control for the case above: the same queued stream/start, and an activate that keeps the player,
// starts the stream normally. Without this the teardown could pass its test by dropping every
// queued event.
TEST(RoleDeactivation, StreamStartQueuedBeforeAKeepingActivateStillStarts) {
    CountingPlayerListener player_listener;

    PairedClientBundle bundle(make_config(STALE_START_CONTROL_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_metadata();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1"])";
    auto server =
        connect_paired_server(bundle.peer, STALE_START_CONTROL_TEST_PORT, std::move(options));
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    constexpr size_t PCM_20MS_BYTES = 48000 / 50 * 2 * 2;
    int64_t ts = platform_time_us() + 50 * 1000;
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(server->send_audio(ts, PCM_20MS_BYTES));
        ts += 20 * 1000;
    }
    // Adds metadata, keeps the player: the queued START is for a role that is still active.
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1","metadata@v1"])")));
    ASSERT_TRUE(server->send_app_json(GROUP_UPDATE_JSON));

    wait_until([&] {
        const uint32_t bits = client.player()->impl_->inbox->poll();
        return (bits & INBOX_TOPIC_EVENTS) != 0 && (bits & INBOX_TOPIC_GROUP) != 0;
    });

    pump_until(client, [&] { return player_listener.stream_starts == 1; });
    stream_audio_until(client, *server, player_listener, 1);

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// ============================================================================
// Traffic for a role that is no longer active
// ============================================================================

// messaging.md "Communication" keeps a message the client implements recognized while its role is
// inactive, and messaging.md "server/activate" expects each side to tolerate the other's
// inactive-role traffic rather than close on it, "since the client may not yet have received the
// role removal". So role traffic that arrives after a removal is parsed as usual and then not
// acted on: without that gate the first message after a removal would put the role straight back
// in service and the teardown would be a one-shot with nothing holding it.
//
// Every receive path is driven. The controls are the first half of the test, where the same
// traffic is applied while the roles are active.
TEST(RoleDeactivation, TrafficForARemovedRoleIsIgnoredWithoutClosing) {
    CountingPlayerListener player_listener;
    RecordingMetadataListener metadata_listener;
    RecordingColorListener color_listener;
    RecordingControllerListener controller_listener;
    CountingVisualizerListener visualizer_listener;
    RecordingArtworkListener artwork_listener;

    PairedClientBundle bundle(make_config(INACTIVE_TRAFFIC_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_metadata().set_listener(&metadata_listener);
    client.add_color().set_listener(&color_listener);
    client.add_controller().set_listener(&controller_listener);
    client.add_visualizer(make_visualizer_config()).set_listener(&visualizer_listener);
    client.add_artwork(make_artwork_config()).set_listener(&artwork_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    auto server =
        connect_paired_server(bundle.peer, INACTIVE_TRAFFIC_TEST_PORT, std::move(options));
    pump_until_synced(client);

    // Control: every path works while the roles are active.
    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_artwork_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Active")));
    ASSERT_TRUE(server->send_app_json(color_state_json(1)));
    ASSERT_TRUE(server->send_app_json(controller_state_json(11)));
    pump_until(
        client, [&] {
            return player_listener.stream_starts == 1 && visualizer_listener.stream_starts == 1 &&
                   metadata_listener.updates == 1 && color_listener.updates == 1 &&
                   controller_listener.updates == 1;
        });
    stream_audio_until(client, *server, player_listener, 1);
    send_loudness_until(client, *server, [&] { return visualizer_listener.loudness.load() >= 1; });
    ASSERT_TRUE(server->send_binary_body(artwork_announce(platform_time_us(), 32)));
    ASSERT_TRUE(server->send_binary_body(artwork_part(32)));
    pump_until(client, [&] { return artwork_listener.decodes.load() == 1; });

    // Every role out.
    ASSERT_TRUE(server->send_app_json(activate_json(R"([])")));
    pump_until(
        client, [&] {
            return player_listener.stream_ends == 1 && visualizer_listener.stream_ends == 1 &&
                   metadata_listener.clears == 1 && color_listener.clears == 1 &&
                   controller_listener.clears == 1 && artwork_listener.clears == 1;
        });

    const size_t writes_after_removal = player_listener.audio_writes.load();
    const size_t loudness_after_removal = visualizer_listener.loudness.load();
    // The sync task is idle and its item list drained, so anything the binary path still accepted
    // for the removed player would show up here rather than at the audio output.
    pump_until(client,
               [&] { return client.player()->impl_->sync_task->inbound().items().is_empty(); });

    // The same traffic again, now for roles the server has removed.
    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_artwork_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(2, "Should Not Show")));
    ASSERT_TRUE(server->send_app_json(color_state_json(2)));
    ASSERT_TRUE(server->send_app_json(controller_state_json(99)));
    constexpr size_t PCM_20MS_BYTES = 48000 / 50 * 2 * 2;
    int64_t ts = platform_time_us() + 50 * 1000;
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(server->send_audio(ts, PCM_20MS_BYTES));
        ts += 20 * 1000;
    }
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(server->send_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, platform_time_us(),
                                        std::string("\x00\x10", 2)));
    }
    ASSERT_TRUE(server->send_binary_body(artwork_announce(platform_time_us(), 32)));
    ASSERT_TRUE(server->send_binary_body(artwork_part(32)));
    pump_for(client, SETTLE_MS);

    EXPECT_EQ(player_listener.stream_starts, 1) << "a removed role's stream/start was acted on";
    EXPECT_EQ(visualizer_listener.stream_starts, 1);
    EXPECT_EQ(metadata_listener.updates, 1) << "a removed role's server/state was applied";
    EXPECT_EQ(metadata_listener.last_title, "Active");
    EXPECT_EQ(color_listener.updates, 1);
    EXPECT_EQ(controller_listener.updates, 1);
    EXPECT_EQ(client.controller()->get_controller_state().volume, 0);
    EXPECT_EQ(player_listener.audio_writes.load(), writes_after_removal)
        << "a removed role's audio chunks were played";
    EXPECT_TRUE(client.player()->impl_->sync_task->inbound().items().is_empty())
        << "a removed role's audio chunks were buffered";
    EXPECT_EQ(visualizer_listener.loudness.load(), loudness_after_removal)
        << "a removed role's frames were delivered";
    EXPECT_EQ(artwork_listener.decodes.load(), 1U) << "a removed role's image was decoded";

    // Recognized, not unknown: none of it is a protocol error, so the connection stays up.
    EXPECT_FALSE(server->closed()) << "inactive-role traffic closed the connection";
    EXPECT_TRUE(client.is_connected());

    // Recognized also means the message's own rules still apply (messaging.md "Communication"):
    // an artwork message that is malformed as a message is the protocol error the role closes on
    // whether or not its role is active. Last, because it ends the connection.
    ASSERT_TRUE(server->send_binary_body({SENDSPIN_BINARY_ARTWORK_IMAGE}));
    pump_until(client, [&] { return !client.is_connected(); });

    pump_for(client, 100);
}

// A role that the server has not activated drives no traffic of its own: messaging.md
// "server/activate" has servers tolerate inactive-role objects only because a client that has
// received the removal stops sending them. The client is admitted here with the player role
// alone, so its controller commands must stay off the wire until an activate adds the role.
//
// An inactive controller can hold no server/state, so the offered command is seeded: without it
// the supported_commands check would drop the command before it reached the gate under test.
TEST(RoleDeactivation, ControllerCommandsWaitForTheRoleToBeActive) {
    PairedClientBundle bundle(make_config(INACTIVE_ROLE_SEND_TEST_PORT));
    SendspinClient& client = bundle.client();
    auto& controller = client.add_controller();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["player@v1"])";
    auto server =
        connect_paired_server(bundle.peer, INACTIVE_ROLE_SEND_TEST_PORT, std::move(options));
    pump_until(client, [&] { return client.is_connected(); });

    // Stamped with the role's current generation, as the drain stamps a mask it applies.
    controller.impl_->supported_commands =
        (controller.impl_->cleanup_generation.load() << 16) |
        (1U << static_cast<uint8_t>(SendspinControllerCommand::PLAY));
    controller.send_command({.command = SendspinControllerCommand::PLAY});
    pump_for(client, 100);
    EXPECT_TRUE(server->controller_commands().empty())
        << "a controller command was sent while controller@v1 was not active";

    // Control: the same command goes out once an activate adds the role, so the gate is refusing
    // on activation rather than dropping controller commands outright.
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["player@v1","controller@v1"]}})"));
    pump_until(client, [&] {
        controller.send_command({.command = SendspinControllerCommand::PLAY});
        return !server->controller_commands().empty();
    });
    EXPECT_EQ(server->controller_commands().front(), "play");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// ============================================================================
// Removal by version replacement
// ============================================================================

// messaging.md "server/activate": "Role removal includes ... replacement of an active role
// version". A server that activates a version this client does not implement leaves it with no
// usable player, so the role is torn down exactly as an explicit drop would tear it down, while
// the roles the activation leaves alone keep running.
TEST(RoleDeactivation, ReplacingARoleVersionRemovesTheVersionInUse) {
    CountingPlayerListener player_listener;
    RecordingMetadataListener metadata_listener;

    PairedClientBundle bundle(make_config(VERSION_REPLACED_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    client.add_metadata().set_listener(&metadata_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1"])";
    auto server =
        connect_paired_server(bundle.peer, VERSION_REPLACED_TEST_PORT, std::move(options));
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Before Replacement")));
    pump_until(client, [&] {
        return player_listener.stream_starts == 1 && metadata_listener.updates == 1;
    });
    stream_audio_until(client, *server, player_listener, 1);

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v2","metadata@v1"])")));
    pump_until(client, [&] { return player_listener.stream_ends == 1; });
    EXPECT_FALSE(client.player()->impl_->sync_task->is_running());
    EXPECT_EQ(metadata_listener.clears, 0) << "a role the activation kept was torn down";
    EXPECT_EQ(metadata_listener.last_title, "Before Replacement");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}
