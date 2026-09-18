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
#include "connection_manager.h"  // Pending-activate flag, to queue an event ahead of a removal
#include "color_role_impl.h"     // Held scheduled palette after a removal
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

/// Bound on every pump/wait: generous next to the loopback round trips involved, so the verdict
/// comes from the predicate rather than the clock.
constexpr int PUMP_TIMEOUT_MS = 6000;

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

std::string stream_start_pcm_json() {
    return R"({"type":"stream/start","payload":{"player":{"codec":"pcm","sample_rate":48000,)"
           R"("channels":2,"bit_depth":16}}})";
}

std::string stream_start_visualizer_json() {
    return R"({"type":"stream/start","payload":{"visualizer":{"types":["loudness"],"rate_max":30}}})";
}

std::string stream_start_artwork_json() {
    return R"({"type":"stream/start","payload":{"artwork":{"channels":[{"source":"album",)"
           R"("format":"jpeg","width":100,"height":100}]}}})";
}

std::string metadata_state_json(int64_t timestamp, const std::string& title) {
    return R"({"type":"server/state","payload":{"metadata":{"timestamp":)" +
           std::to_string(timestamp) + R"(,"title":")" + title + R"("}}})";
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

PlayerRoleConfig make_player_config() {
    PlayerRoleConfig player_cfg;
    player_cfg.audio_formats.push_back({SendspinCodecFormat::PCM, 2, 48000, 16});
    player_cfg.audio_buffer_capacity = 64 * 1024;
    return player_cfg;
}

VisualizerRoleConfig make_visualizer_config() {
    VisualizerRoleConfig config;
    config.stream.types = {VisualizerDataType::LOUDNESS};
    config.support.buffer_capacity = 4096;
    config.stream.rate_max = 30;
    return config;
}

ArtworkRoleConfig make_artwork_config() {
    ArtworkRoleConfig config;
    config.preferred_formats.push_back(
        {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 100, 100, false});
    return config;
}

/// Counts the player lifecycle callbacks and audio writes; the write itself is a sink.
class CountingPlayerListener : public PlayerRoleListener {
public:
    size_t on_audio_write(uint8_t* /*data*/, size_t length, uint32_t /*timeout_ms*/) override {
        this->audio_writes.fetch_add(1);
        return length;
    }
    void on_stream_start() override {
        ++this->stream_starts;
    }
    void on_stream_end() override {
        ++this->stream_ends;
    }

    std::atomic<size_t> audio_writes{0};
    int stream_starts{0};
    int stream_ends{0};
};

class RecordingMetadataListener : public MetadataRoleListener {
public:
    void on_metadata(const ServerMetadataStateObject& metadata) override {
        ++this->updates;
        this->last_title = metadata.title.value_or("");
    }
    void on_metadata_clear() override {
        ++this->clears;
    }

    int updates{0};
    int clears{0};
    std::string last_title;
};

class RecordingColorListener : public ColorRoleListener {
public:
    void on_color(const ServerColorStateObject& /*color*/) override {
        ++this->updates;
    }
    void on_color_clear() override {
        ++this->clears;
    }

    int updates{0};
    int clears{0};
};

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

class CountingVisualizerListener : public VisualizerRoleListener {
public:
    void on_loudness(int64_t /*client_timestamp*/, uint16_t /*loudness*/) override {
        this->loudness.fetch_add(1);
    }
    void on_visualizer_stream_start(const ServerVisualizerStreamObject& /*stream*/) override {
        ++this->stream_starts;
    }
    void on_visualizer_stream_end() override {
        ++this->stream_ends;
    }

    std::atomic<size_t> loudness{0};
    int stream_starts{0};
    int stream_ends{0};
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

/// A paired fake server connected to the bundle's client on `port`.
std::unique_ptr<FakeEncryptedServer> connect_paired_server(const PairedPeer& peer, uint16_t port,
                                                           FakeEncryptedServerOptions options) {
    return std::make_unique<FakeEncryptedServer>(server_url(port),
                                                 std::string(NOISE_SUITE_CHACHAPOLY),
                                                 peer.server_identity, peer.record.psk_id, peer.psk,
                                                 std::move(options));
}

bool pump_until_synced(SendspinClient& client) {
    return pump_until(
        client, [&] { return client.is_connected() && client.is_time_synced(); }, PUMP_TIMEOUT_MS);
}

// Pumps until the peer has written at least `target` audio callbacks, feeding 20 ms PCM chunks
// stamped a little ahead of now so the sync task has something to schedule.
bool stream_audio_until(SendspinClient& client, FakeEncryptedServer& server,
                        CountingPlayerListener& listener, size_t target) {
    constexpr size_t PCM_20MS_BYTES = 48000 / 50 * 2 * 2;
    int64_t next_ts = platform_time_us() + 50 * 1000;
    return pump_until(
        client,
        [&] {
            if (listener.audio_writes.load() >= target) {
                return true;
            }
            server.send_audio(next_ts, PCM_20MS_BYTES);
            next_ts += 20 * 1000;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));  // real-time pacing
            return false;
        },
        PUMP_TIMEOUT_MS);
}

// Pumps until `done`, feeding loudness frames stamped for immediate display.
bool send_loudness_until(SendspinClient& client, FakeEncryptedServer& server,
                         const std::function<bool()>& done) {
    return pump_until(
        client,
        [&] {
            if (done()) {
                return true;
            }
            server.send_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, platform_time_us(),
                               std::string("\x00\x10", 2));
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            return false;
        },
        PUMP_TIMEOUT_MS);
}

void put_be64(std::vector<uint8_t>& out, int64_t val) {
    auto u = static_cast<uint64_t>(val);
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xFF));
    }
}

void put_be32(std::vector<uint8_t>& out, uint32_t val) {
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((val >> (8 * i)) & 0xFF));
    }
}

// roles/artwork/v1.md "Artwork (Binary)": [type][flags][timestamp][total_size], flags bit 1 set.
std::vector<uint8_t> artwork_announce(int64_t timestamp, uint32_t total_size) {
    std::vector<uint8_t> body{SENDSPIN_BINARY_ARTWORK_IMAGE, 0x02};
    put_be64(body, timestamp);
    put_be32(body, total_size);
    return body;
}

// [type][flags][data], no flag bits set.
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
// The roles the same activation keeps are untouched, which is what "State for roles that remain
// active at the same version is unchanged" means in practice: the visualizer keeps delivering
// frames and the metadata state stays put.
TEST(RoleDeactivation, RemovedPlayerStopsTheStreamAndLeavesTheOtherRolesAlone) {
    CountingPlayerListener player_listener;
    CountingVisualizerListener visualizer_listener;
    RecordingMetadataListener metadata_listener;

    PairedClientBundle bundle(make_config(PLAYER_REMOVED_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_player_config()).set_listener(&player_listener);
    client.add_visualizer(make_visualizer_config()).set_listener(&visualizer_listener);
    client.add_metadata().set_listener(&metadata_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","visualizer@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, PLAYER_REMOVED_TEST_PORT, std::move(options));
    ASSERT_TRUE(pump_until_synced(client));

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Before Removal")));
    ASSERT_TRUE(pump_until(
        client,
        [&] {
            return player_listener.stream_starts == 1 && visualizer_listener.stream_starts == 1 &&
                   metadata_listener.updates == 1;
        },
        PUMP_TIMEOUT_MS));
    ASSERT_TRUE(stream_audio_until(client, *server, player_listener, 1));
    ASSERT_TRUE(client.player()->impl_->sync_task->is_running());

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["visualizer@v1","metadata@v1"])")));
    ASSERT_TRUE(pump_until(
        client, [&] { return player_listener.stream_ends == 1; }, PUMP_TIMEOUT_MS))
        << "the removed player role never reported its stream ending";
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
    EXPECT_TRUE(send_loudness_until(client, *server, [&] {
        return visualizer_listener.loudness.load() > loudness_before;
    })) << "the visualizer stream stopped delivering when the player was removed";

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
    client.add_player(make_player_config()).set_listener(&player_listener);
    client.add_visualizer(make_visualizer_config()).set_listener(&visualizer_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","visualizer@v1"])";
    auto server =
        connect_paired_server(bundle.peer, VISUALIZER_REMOVED_TEST_PORT, std::move(options));
    ASSERT_TRUE(pump_until_synced(client));

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    ASSERT_TRUE(pump_until(
        client,
        [&] { return visualizer_listener.stream_starts == 1 && player_listener.stream_starts == 1; },
        PUMP_TIMEOUT_MS));
    ASSERT_TRUE(send_loudness_until(
        client, *server, [&] { return visualizer_listener.loudness.load() >= 1; }));

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1"])")));
    ASSERT_TRUE(pump_until(
        client, [&] { return visualizer_listener.stream_ends == 1; }, PUMP_TIMEOUT_MS))
        << "the removed visualizer role never reported its stream ending";
    EXPECT_FALSE(client.visualizer()->impl_->stream_active.load())
        << "the visualizer still accepts frames for a role the activation removed";

    const size_t loudness_after_removal = visualizer_listener.loudness.load();
    for (int i = 0; i < 5; ++i) {
        server->send_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, platform_time_us(),
                            std::string("\x00\x10", 2));
    }
    pump_for(client, SETTLE_MS);
    EXPECT_EQ(visualizer_listener.loudness.load(), loudness_after_removal)
        << "frames were delivered for a role the activation removed";
    EXPECT_TRUE(client.visualizer()->impl_->drain_task->ring_buffer.is_empty())
        << "the removed role kept its buffered frames";

    EXPECT_EQ(player_listener.stream_ends, 0) << "a role the activation kept was torn down";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// An activation that drops artwork@v1 clears every channel (roles/artwork/v1.md has an artwork
// stream/end clear the current image and discard the pending one, and the removal applies the
// same teardown) and drops the transfer that was in flight. Adding the role back gives a working
// channel again: a whole image announced afterwards decodes, with none of the abandoned bytes in
// it.
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
    ASSERT_TRUE(pump_until_synced(client));

    ASSERT_TRUE(server->send_app_json(stream_start_artwork_json()));
    ASSERT_TRUE(server->send_binary_body(artwork_announce(platform_time_us(), IMAGE_BYTES)));
    ASSERT_TRUE(server->send_binary_body(artwork_part(IMAGE_BYTES / 2)));
    ASSERT_TRUE(pump_until(
        client, [&] { return client.artwork()->impl_->transfer.in_flight; }, PUMP_TIMEOUT_MS))
        << "the half-sent image never registered as a transfer in flight";

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["metadata@v1"])")));
    ASSERT_TRUE(pump_until(
        client, [&] { return artwork_listener.clears == 1; }, PUMP_TIMEOUT_MS))
        << "the removed artwork role never cleared its channel";
    EXPECT_EQ(artwork_listener.last_clear_slot, 0);
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
    ASSERT_TRUE(pump_until(
        client, [&] { return artwork_listener.decodes.load() == 1; }, PUMP_TIMEOUT_MS))
        << "the re-added artwork role decoded nothing";
    EXPECT_EQ(artwork_listener.last_decode_length.load(), IMAGE_BYTES);

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
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
    client.add_player(make_player_config()).set_listener(&player_listener);
    client.add_metadata().set_listener(&metadata_listener);
    client.add_color().set_listener(&color_listener);
    client.add_controller().set_listener(&controller_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1","color@v1","controller@v1"])";
    auto server =
        connect_paired_server(bundle.peer, STATE_ROLES_REMOVED_TEST_PORT, std::move(options));
    ASSERT_TRUE(pump_until_synced(client));

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Now Playing")));
    ASSERT_TRUE(server->send_app_json(color_state_json(1)));
    ASSERT_TRUE(server->send_app_json(controller_state_json(42)));
    ASSERT_TRUE(pump_until(
        client,
        [&] {
            return metadata_listener.updates == 1 && color_listener.updates == 1 &&
                   controller_listener.updates == 1 && player_listener.stream_starts == 1;
        },
        PUMP_TIMEOUT_MS));
    // What the receive gate would hand a metadata handler admitted right now, kept for the
    // overtaken-handler check at the end.
    const uint32_t metadata_generation =
        client.metadata()->impl_->cleanup_generation.load(std::memory_order_acquire);

    // The scheduled updates behind the current states: due so far in the future that they are
    // still pending when the removal lands.
    const int64_t scheduled_ts = platform_time_us() + NEVER_DUE_LEAD_US;
    ASSERT_TRUE(server->send_app_json(metadata_state_json(scheduled_ts, "Up Next")));
    ASSERT_TRUE(server->send_app_json(color_state_json(scheduled_ts)));
    ASSERT_TRUE(pump_until(
        client,
        [&] {
            return client.metadata()->impl_->held_state.has_value() &&
                   client.color()->impl_->held_state.has_value();
        },
        PUMP_TIMEOUT_MS))
        << "the scheduled updates never reached the roles";
    ASSERT_EQ(metadata_listener.updates, 1) << "a scheduled update was applied early";

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1"])")));
    ASSERT_TRUE(pump_until(
        client,
        [&] {
            return metadata_listener.clears == 1 && color_listener.clears == 1 &&
                   controller_listener.clears == 1;
        },
        PUMP_TIMEOUT_MS))
        << "a removed state role never told its listener";

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
    EXPECT_TRUE(stream_audio_until(client, *server, player_listener, 1))
        << "the player stopped playing when the state roles were removed";

    // The gate is checked once on the network thread while the handler it admits runs on, so a
    // teardown can land in between. The handler re-checks the generation the gate captured, which
    // a state admitted before this removal no longer carries: driving it directly is the same call
    // the network thread would make, with the interleaving forced rather than raced for.
    ServerMetadataStateObject overtaken;
    overtaken.timestamp = 1;
    overtaken.title = "Overtaken By The Removal";
    client.metadata()->impl_->handle_server_state(std::move(overtaken), metadata_generation);
    pump_for(client, SETTLE_MS);
    EXPECT_EQ(metadata_listener.updates, 1) << "a state a teardown overtook was applied";

    // Control: the same call carrying the generation the role reports now is applied, so the
    // refusal above came from the stale generation and nothing else.
    ServerMetadataStateObject current;
    current.timestamp = 1;
    current.title = "Current Generation";
    client.metadata()->impl_->handle_server_state(
        std::move(current),
        client.metadata()->impl_->cleanup_generation.load(std::memory_order_acquire));
    ASSERT_TRUE(pump_until(
        client, [&] { return metadata_listener.updates == 2; }, PUMP_TIMEOUT_MS));

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
    client.add_player(make_player_config()).set_listener(&player_listener);
    client.add_metadata().set_listener(&metadata_listener);
    client.add_color().set_listener(&color_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, NO_CHANGE_TEST_PORT, std::move(options));
    ASSERT_TRUE(pump_until_synced(client));

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Now Playing")));
    ASSERT_TRUE(pump_until(
        client,
        [&] { return player_listener.stream_starts == 1 && metadata_listener.updates == 1; },
        PUMP_TIMEOUT_MS));

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
    client.add_player(make_player_config()).set_listener(&player_listener);
    client.add_metadata();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, READD_TEST_PORT, std::move(options));
    ASSERT_TRUE(pump_until_synced(client));

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(pump_until(
        client, [&] { return player_listener.stream_starts == 1; }, PUMP_TIMEOUT_MS));
    ASSERT_TRUE(stream_audio_until(client, *server, player_listener, 1));

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["metadata@v1"])")));
    ASSERT_TRUE(pump_until(
        client, [&] { return player_listener.stream_ends == 1; }, PUMP_TIMEOUT_MS));

    const int states_before_readd = server->client_state_count();
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1","metadata@v1"])")));
    ASSERT_TRUE(pump_until(
        client, [&] { return server->client_state_count() > states_before_readd; },
        PUMP_TIMEOUT_MS))
        << "the activation that added the player back published no client/state";
    {
        JsonDocument doc;
        const std::vector<std::string> states = server->client_states();
        ASSERT_FALSE(states.empty());
        ASSERT_EQ(deserializeJson(doc, states.back()), DeserializationError::Ok);
        EXPECT_TRUE(doc["payload"]["player"].is<JsonObjectConst>())
            << "the re-added role's object was missing from the published state";
    }

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(pump_until(
        client, [&] { return player_listener.stream_starts == 2; }, PUMP_TIMEOUT_MS))
        << "the re-added player role never started a stream again";
    const size_t writes_before = player_listener.audio_writes.load();
    EXPECT_TRUE(stream_audio_until(client, *server, player_listener, writes_before + 1))
        << "the re-added player role never played again";
    EXPECT_EQ(player_listener.stream_ends, 1);

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// ============================================================================
// Events already queued when the removal lands
// ============================================================================

// A stream/start that reached the inbox before the activate that removes the role must not act
// after it. The client applies the activation (and the teardown) in connection_manager_->loop(),
// which runs ahead of the event drain in the same tick, so the queued START is drained with the
// role already stopped: acting on it would fire on_stream_start() for a removed role and re-arm
// the sync task, which then writes PCM from the chunks already in its ring.
//
// Nothing is pumped between the three sends, so the START is provably still in the ring when the
// activate is applied: the test waits for the ring bit and the manager's pending-event flag
// instead of for a duration.
TEST(RoleDeactivation, StreamStartQueuedBeforeARemovalNeverStarts) {
    CountingPlayerListener player_listener;

    PairedClientBundle bundle(make_config(STALE_START_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_player_config()).set_listener(&player_listener);
    client.add_metadata();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1"])";
    auto server = connect_paired_server(bundle.peer, STALE_START_TEST_PORT, std::move(options));
    ASSERT_TRUE(pump_until_synced(client));

    // From here on the test thread does not pump: everything below queues up client-side.
    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    constexpr size_t PCM_20MS_BYTES = 48000 / 50 * 2 * 2;
    int64_t ts = platform_time_us() + 50 * 1000;
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(server->send_audio(ts, PCM_20MS_BYTES));
        ts += 20 * 1000;
    }
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["metadata@v1"])")));

    // Both halves are in: the START sits in the event ring, the activate in the manager's pending
    // events. The next loop() tick applies the activate first and drains the ring second.
    ASSERT_TRUE(wait_until(
        [&] {
            return (client.player()->impl_->inbox->poll() & INBOX_TOPIC_EVENTS) != 0 &&
                   client.connection_manager_->has_pending_events_.load();
        },
        PUMP_TIMEOUT_MS))
        << "the stream/start and the activate never both arrived";

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
    client.add_player(make_player_config()).set_listener(&player_listener);
    client.add_metadata();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1"])";
    auto server =
        connect_paired_server(bundle.peer, STALE_START_CONTROL_TEST_PORT, std::move(options));
    ASSERT_TRUE(pump_until_synced(client));

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    constexpr size_t PCM_20MS_BYTES = 48000 / 50 * 2 * 2;
    int64_t ts = platform_time_us() + 50 * 1000;
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(server->send_audio(ts, PCM_20MS_BYTES));
        ts += 20 * 1000;
    }
    // Adds metadata, keeps the player: the queued START is for a role that is still active.
    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v1","metadata@v1"])")));

    ASSERT_TRUE(wait_until(
        [&] {
            return (client.player()->impl_->inbox->poll() & INBOX_TOPIC_EVENTS) != 0 &&
                   client.connection_manager_->has_pending_events_.load();
        },
        PUMP_TIMEOUT_MS))
        << "the stream/start and the activate never both arrived";

    ASSERT_TRUE(pump_until(
        client, [&] { return player_listener.stream_starts == 1; }, PUMP_TIMEOUT_MS))
        << "an activation that removed nothing swallowed the queued stream/start";
    EXPECT_TRUE(stream_audio_until(client, *server, player_listener, 1));

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
// Every receive path is driven: server/state (metadata, color, controller), stream/start (player,
// artwork, visualizer) and the binary IDs (audio, artwork image, visualizer frame). The controls
// are the first half of the test, where the same traffic is applied while the roles are active.
TEST(RoleDeactivation, TrafficForARemovedRoleIsIgnoredWithoutClosing) {
    CountingPlayerListener player_listener;
    RecordingMetadataListener metadata_listener;
    RecordingColorListener color_listener;
    RecordingControllerListener controller_listener;
    CountingVisualizerListener visualizer_listener;
    RecordingArtworkListener artwork_listener;

    PairedClientBundle bundle(make_config(INACTIVE_TRAFFIC_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_player_config()).set_listener(&player_listener);
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
    ASSERT_TRUE(pump_until_synced(client));

    // Control: every path works while the roles are active.
    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    ASSERT_TRUE(server->send_app_json(stream_start_artwork_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Active")));
    ASSERT_TRUE(server->send_app_json(color_state_json(1)));
    ASSERT_TRUE(server->send_app_json(controller_state_json(11)));
    ASSERT_TRUE(pump_until(
        client,
        [&] {
            return player_listener.stream_starts == 1 && visualizer_listener.stream_starts == 1 &&
                   metadata_listener.updates == 1 && color_listener.updates == 1 &&
                   controller_listener.updates == 1;
        },
        PUMP_TIMEOUT_MS));
    ASSERT_TRUE(stream_audio_until(client, *server, player_listener, 1));
    ASSERT_TRUE(send_loudness_until(
        client, *server, [&] { return visualizer_listener.loudness.load() >= 1; }));
    ASSERT_TRUE(server->send_binary_body(artwork_announce(platform_time_us(), 32)));
    ASSERT_TRUE(server->send_binary_body(artwork_part(32)));
    ASSERT_TRUE(pump_until(
        client, [&] { return artwork_listener.decodes.load() == 1; }, PUMP_TIMEOUT_MS));

    // Every role out.
    ASSERT_TRUE(server->send_app_json(activate_json(R"([])")));
    ASSERT_TRUE(pump_until(
        client,
        [&] {
            return player_listener.stream_ends == 1 && visualizer_listener.stream_ends == 1 &&
                   metadata_listener.clears == 1 && color_listener.clears == 1 &&
                   controller_listener.clears == 1 && artwork_listener.clears == 1;
        },
        PUMP_TIMEOUT_MS));

    const size_t writes_after_removal = player_listener.audio_writes.load();
    const size_t loudness_after_removal = visualizer_listener.loudness.load();
    // The sync task is idle and its ring drained, so anything the binary path still accepted for
    // the removed player would show up here rather than at the audio output.
    ASSERT_TRUE(pump_until(
        client,
        [&] { return client.player()->impl_->sync_task->encoded_ring_buffer_->is_empty(); },
        PUMP_TIMEOUT_MS));

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
    EXPECT_TRUE(client.player()->impl_->sync_task->encoded_ring_buffer_->is_empty())
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
    EXPECT_TRUE(pump_until(
        client, [&] { return !client.is_connected(); }, PUMP_TIMEOUT_MS))
        << "a malformed artwork message was excused because its role was inactive";

    pump_for(client, 100);
}

// ============================================================================
// Removal without an explicit shrunken active_roles
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
    client.add_player(make_player_config()).set_listener(&player_listener);
    client.add_metadata().set_listener(&metadata_listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    options.first_roles_json = R"(["player@v1","metadata@v1"])";
    auto server =
        connect_paired_server(bundle.peer, VERSION_REPLACED_TEST_PORT, std::move(options));
    ASSERT_TRUE(pump_until_synced(client));

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(server->send_app_json(metadata_state_json(1, "Before Replacement")));
    ASSERT_TRUE(pump_until(
        client,
        [&] { return player_listener.stream_starts == 1 && metadata_listener.updates == 1; },
        PUMP_TIMEOUT_MS));
    ASSERT_TRUE(stream_audio_until(client, *server, player_listener, 1));

    ASSERT_TRUE(server->send_app_json(activate_json(R"(["player@v2","metadata@v1"])")));
    ASSERT_TRUE(pump_until(
        client, [&] { return player_listener.stream_ends == 1; }, PUMP_TIMEOUT_MS))
        << "replacing player@v1 with a version the client does not implement left it running";
    EXPECT_FALSE(client.player()->impl_->sync_task->is_running());
    EXPECT_EQ(metadata_listener.clears, 0) << "a role the activation kept was torn down";
    EXPECT_EQ(metadata_listener.last_title, "Before Replacement");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}
