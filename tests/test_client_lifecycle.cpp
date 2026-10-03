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

/// SendspinClient start/stop/restart: stop() goodbyes every peer, leaves every role and slot
/// reset and its clear callbacks delivered before stop() returns, a restarted client is live
/// again, and a callback fired from inside stop() cannot recurse into the lifecycle.
///
/// The client is driven on loopback ports like test_connection_lifecycle.cpp: a
/// FakeEncryptedServer plays the Sendspin server over the real Noise transport and the test
/// thread pumps client.loop().

#include "connection.h"  // StubConnection stands in for a real connection
#include "connection_manager.h"  // GoodbyeWait, GOODBYE_FLUSH_TIMEOUT_MS
#include "crypto/constants.h"
#include "crypto/keys.h"
#include "fake_persistence.h"
#include "lifecycle_test_fixtures.h"
#include "platform/time.h"
#include "player_role_impl.h"  // Stream start and the sync task; private access, see tests/CMakeLists.txt
#include "protocol_messages.h"  // SENDSPIN_BINARY_VISUALIZER_LOUDNESS
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/visualizer_role.h"
#include "sync_task.h"
#include "visualizer_role_impl.h"  // Ring state after stop(); private access, see tests/CMakeLists.txt

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// Distinct ports per test so a lingering socket from one scenario cannot bleed into the next,
// and disjoint from every other file's block: test_connection_lifecycle.cpp uses 18941-18985,
// test_encrypted_lifecycle.cpp 18991-19019 and 19041-19046, test_role_deactivation.cpp
// 19031-19051.
constexpr uint16_t RESTART_TEST_PORT = 19061;
constexpr uint16_t NURSERY_GOODBYE_TEST_PORT = 19062;
constexpr uint16_t STREAM_TEST_PORT = 19063;
constexpr uint16_t CALLBACK_TEST_PORT = 19064;
constexpr uint16_t DESTRUCTOR_TEST_PORT = 19065;
constexpr uint16_t ROLLBACK_TEST_PORT = 19066;
constexpr uint16_t HIGH_PERF_TEST_PORT = 19067;
constexpr uint16_t VISUALIZER_TEST_PORT = 19068;
constexpr uint16_t DESTRUCTOR_HIGH_PERF_TEST_PORT = 19069;
constexpr uint16_t PROVIDER_TEST_PORT = 19070;
constexpr uint16_t PUBLISH_STATE_TEST_PORT = 19071;
constexpr uint16_t STREAM_FILTER_LOCK_TEST_PORT = 19072;
constexpr uint16_t STREAM_FILTER_OFFSET_TEST_PORT = 19073;
constexpr uint16_t TIME_FILTER_SLOT_TEST_PORT = 19074;
constexpr uint16_t ADMISSION_CLOSED_TEST_PORT = 19075;
constexpr uint16_t ADMISSION_OPEN_TEST_PORT = 19076;
constexpr uint16_t STREAM_FILTER_MIDSTREAM_TEST_PORT = 19077;
constexpr uint16_t VISUALIZER_SPECTRUM_TEST_PORT = 19078;
constexpr uint16_t VISUALIZER_STALE_TEST_PORT = 19084;
constexpr uint16_t VISUALIZER_SHARED_TS_TEST_PORT = 19086;
constexpr uint16_t VISUALIZER_OFFSET_TEST_PORT = 19088;
constexpr uint16_t HELLO_TEST_PORT = 19090;
#ifndef SENDSPIN_ENABLE_OPUS
constexpr uint16_t OPUS_STREAM_TEST_PORT = 19089;
#endif

SendspinClientConfig make_config(uint16_t port) {
    SendspinClientConfig config;
    config.name = "Client Lifecycle Test Client";
    config.server_port = port;
    return config;
}

/// Reports whether anything is listening on the loopback port.
bool port_accepts(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    const bool connected = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    ::close(fd);
    return connected;
}

/// Records on_metadata_clear() and, from inside it, tries to drive the lifecycle re-entrantly.
class ReentrantMetadataListener : public MetadataRoleListener {
public:
    explicit ReentrantMetadataListener(SendspinClient& client) : client_(client) {}

    void on_metadata_clear() override {
        ++this->clears;
        this->started_during_clear = this->client_.is_started();
        this->group_had_state_during_clear =
            this->client_.get_group_state().playback_state.has_value();
        this->start_result_during_clear = this->client_.start();
        this->client_.stop();                                       // Must be ignored, not recurse
        this->client_.disconnect(SendspinGoodbyeReason::SHUTDOWN);  // Must be ignored
        this->client_.connect_to("ws://127.0.0.1:1/sendspin");      // Must be ignored
    }

    int clears{0};
    bool started_during_clear{true};
    bool group_had_state_during_clear{true};
    bool start_result_during_clear{true};

private:
    SendspinClient& client_;
};

/// A metadata listener that must never be called; every callback aborts the test.
class ForbiddenMetadataListener : public MetadataRoleListener {
public:
    void on_metadata(const ServerMetadataStateObject& /*metadata*/) override {
        ADD_FAILURE() << "on_metadata() fired on a listener the consumer already released";
    }
    void on_metadata_clear() override {
        ADD_FAILURE() << "on_metadata_clear() fired on a listener the consumer already released";
    }
};

std::string group_update_playing_json() {
    return R"({"type":"group/update","payload":{"playback_state":"playing"}})";
}

// ============================================================================
// GoodbyeWait: the bound stop() relies on
// ============================================================================

// A goodbye whose completion never arrives (an ESP session that closes before its worker runs
// reports nothing) must not hold stop() open: wait() returns false once the bound elapses.
// Deleting the bound turns this into a hang the suite watchdog reports.
TEST(GoodbyeWait, BoundElapsesWhenACompletionNeverArrives) {
    GoodbyeWait wait;
    wait.add_pending();
    EXPECT_FALSE(wait.wait(GOODBYE_FLUSH_TIMEOUT_MS));
}

// Control: with every registered goodbye completed (from another thread, as a transport worker
// would) wait() reports success, and with nothing registered it never blocks.
TEST(GoodbyeWait, CompletionsSatisfyTheWait) {
    GoodbyeWait idle;
    EXPECT_TRUE(idle.wait(UINT32_MAX)) << "a wait with nothing registered must not block";

    GoodbyeWait wait;
    wait.add_pending();
    wait.add_pending();
    std::thread worker([&] {
        wait.complete_one();
        wait.complete_one();
    });
    // No bound: a lost completion hangs here and the watchdog reports it, rather than the
    // elapsed time deciding the verdict.
    EXPECT_TRUE(wait.wait(UINT32_MAX));
    worker.join();
}

// ============================================================================
// SendspinClient lifecycle
// ============================================================================

// start -> stop -> start, twice over: every stop goodbyes and closes the established peer, resets
// the group state, and leaves nothing listening; every restart accepts a new peer and completes
// its Noise handshake on the identity and record store the first start created. Also pins
// start() as idempotent while running and stop() as a no-op when stopped.
TEST(ClientLifecycle, RestartYieldsALiveClient) {
    PairedClientBundle bundle(make_config(RESTART_TEST_PORT));
    SendspinClient& client = bundle.client();

    EXPECT_FALSE(client.is_started());
    client.stop();  // No-op when stopped
    EXPECT_FALSE(client.is_started());

    for (int cycle = 0; cycle < 3; ++cycle) {
        ASSERT_TRUE(bundle.start());
        EXPECT_TRUE(client.start());  // Already running: reports true, starts nothing twice
        EXPECT_TRUE(client.is_started());

        auto server = connect_paired_server(bundle.peer, RESTART_TEST_PORT);
        pump_until(client, [&] { return client.is_connected(); });
        auto info = client.get_server_information();
        ASSERT_TRUE(info.has_value());
        EXPECT_EQ(info->server_id, bundle.peer.server_identity.peer_id());

        // Some group state for stop() to reset.
        ASSERT_TRUE(server->send_app_json(group_update_playing_json()));
        pump_until(client, [&] { return client.get_group_state().playback_state.has_value(); });

        client.stop();

        EXPECT_FALSE(client.is_started());
        EXPECT_FALSE(client.is_connected());
        EXPECT_FALSE(client.get_server_information().has_value());
        EXPECT_FALSE(client.get_group_state().playback_state.has_value());
        // The peer received its goodbye and the close, in that order.
        wait_until([&] { return server->closed(); });
        EXPECT_EQ(server->goodbye_reason().value_or(""), "shutdown");

        // Stopped means quiescent: pumping loop() must not bring the server back up.
        pump_for(client, 100);
        EXPECT_FALSE(port_accepts(RESTART_TEST_PORT));
    }
}

// The identity and record store read the persistence provider once, when start() builds them, so
// a provider installed between a stop and the next start must make start() rebuild both: the
// ephemeral keypair the provider-less run generated was never persisted, so the restarted client
// generates and saves a new one. Control: a restart with the same provider keeps the identity.
TEST(ClientLifecycle, ProviderSetBetweenStopAndStartIsHonored) {
    TestNetworkProvider network;
    SendspinClient client(make_config(PROVIDER_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start());
    const std::string ephemeral_id = client.client_id();
    EXPECT_FALSE(ephemeral_id.empty());
    client.stop();

    InMemoryPersistenceProvider store;
    client.set_persistence_provider(&store);
    ASSERT_TRUE(client.start());
    const std::string persisted_id = client.client_id();
    EXPECT_NE(persisted_id, ephemeral_id);
    EXPECT_TRUE(store.load_blob(persistence_keys::KEYPAIR).has_value());
    client.stop();

    ASSERT_TRUE(client.start());
    EXPECT_EQ(client.client_id(), persisted_id);
    EXPECT_EQ(store.save_attempts(persistence_keys::KEYPAIR), 1);
    client.stop();
}

// A peer still in the nursery (it handshook and answered the hello but never activated) gets the
// same goodbye and close as the established one, so no peer is left to discover the shutdown by
// timeout.
TEST(ClientLifecycle, StopGoodbyesNurseryPeersToo) {
    PairedClientBundle bundle(make_config(NURSERY_GOODBYE_TEST_PORT));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    auto established = connect_paired_server(bundle.peer, NURSERY_GOODBYE_TEST_PORT);
    pump_until(client, [&] { return client.is_connected(); });

    // Runs on the Sentinel PSK, which RecordStore resolves unconditionally, so it needs no record
    // of its own; never activating keeps it in the nursery.
    FakeEncryptedServerOptions mute_options;
    mute_options.suppress_activate = true;
    Identity mute_identity = Identity::generate().value();
    FakeEncryptedServer mute(server_url(NURSERY_GOODBYE_TEST_PORT),
                             std::string(NOISE_SUITE_CHACHAPOLY), mute_identity,
                             std::string(SENTINEL_PSK_ID), SENTINEL_PSK, mute_options);
    pump_until(client, [&] { return mute.client_hello_count() > 0; });

    client.stop();

    wait_until([&] { return established->closed() && mute.closed(); });
    EXPECT_EQ(established->goodbye_reason().value_or(""), "shutdown");
    EXPECT_EQ(mute.goodbye_reason().value_or(""), "shutdown");
}

// With a stream playing, stop() ends it (on_stream_end() fires before stop() returns, paired with
// the earlier on_stream_start()) and a restarted client plays a new stream: audio reaches the
// listener again, which needs the sync task thread to have been re-created, not just the server.
TEST(ClientLifecycle, StopEndsTheStreamAndRestartPlaysAgain) {
    CountingPlayerListener listener;
    auto config = make_config(STREAM_TEST_PORT);
    config.time_burst_interval_ms = 100;  // Sync promptly after each (re)connect
    PairedClientBundle bundle(std::move(config));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&listener);

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    for (int cycle = 0; cycle < 2; ++cycle) {
        ASSERT_TRUE(bundle.start());
        auto server = connect_paired_server(bundle.peer, STREAM_TEST_PORT, options);
        pump_until(client, [&] { return client.is_connected(); });

        ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
        pump_until(client, [&] { return listener.stream_starts == cycle + 1; });
        EXPECT_EQ(listener.stream_ends, cycle);

        // Audio flowing proves the sync task thread is alive in this cycle.
        const size_t writes_before = listener.audio_writes.load();
        stream_audio_until(client, *server, listener, writes_before + 1);

        client.stop();

        // The clear callback was delivered inside stop(), not left for a loop() tick.
        EXPECT_EQ(listener.stream_ends, cycle + 1);
        EXPECT_EQ(listener.stream_starts, cycle + 1);
        wait_until([&] { return server->closed(); });
        EXPECT_EQ(server->goodbye_reason().value_or(""), "shutdown");
    }
}

#ifndef SENDSPIN_ENABLE_OPUS
// Without the Opus decoder, a stream/start naming opus (a server ignoring the advertised list)
// takes the unsupported-codec path: no codec header reaches the sync task and no
// on_stream_start() fires. The pcm stream/start sent right behind it starts normally; stream
// events drain in arrival order, so once the pcm params are current an accepted opus start would
// already have been counted.
TEST(ClientLifecycle, OpusStreamStartIsRefusedWithoutTheOpusDecoder) {
    CountingPlayerListener listener;
    PairedClientBundle bundle(make_config(OPUS_STREAM_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    auto server = connect_paired_server(bundle.peer, OPUS_STREAM_TEST_PORT);
    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server->send_app_json(stream_start_json("opus")));
    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    pump_until(client, [&] {
        return client.player()->get_current_stream_params().codec == SendspinCodecFormat::PCM;
    });
    EXPECT_EQ(listener.stream_starts, 1);

    client.stop();
    EXPECT_EQ(listener.stream_ends, 1);
}
#endif

// A listener callback fired from inside stop() cannot re-enter the lifecycle: start() reports
// failure and starts nothing, stop()/disconnect()/connect_to() are ignored rather than recursing,
// and the client (its started flag and its group state) already reads as stopped. Afterwards the
// client restarts normally.
TEST(ClientLifecycle, CallbackDuringStopCannotRecurse) {
    PairedClientBundle bundle(make_config(CALLBACK_TEST_PORT));
    SendspinClient& client = bundle.client();
    ReentrantMetadataListener listener(client);
    client.add_metadata().set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    {
        auto server = connect_paired_server(bundle.peer, CALLBACK_TEST_PORT);
        pump_until(client, [&] { return client.is_connected(); });
        // Group state the callback must already see reset.
        ASSERT_TRUE(server->send_app_json(group_update_playing_json()));
        pump_until(client, [&] { return client.get_group_state().playback_state.has_value(); });

        client.stop();

        EXPECT_EQ(listener.clears, 1);
        EXPECT_FALSE(listener.started_during_clear);
        EXPECT_FALSE(listener.group_had_state_during_clear);
        EXPECT_FALSE(listener.start_result_during_clear);
        EXPECT_FALSE(client.is_started());
        wait_until([&] { return server->closed(); });
    }

    // The refused start() inside the callback left the client stopped; a real start() works.
    ASSERT_TRUE(bundle.start());
    auto server = connect_paired_server(bundle.peer, CALLBACK_TEST_PORT);
    pump_until(client, [&] { return client.is_connected(); });
    client.stop();
    EXPECT_EQ(listener.clears, 2);
}

// Destroying a running client goodbyes its peer like stop() does, but dispatches no clear
// callback: the listener outlives the client, as the role contract requires, and fails the test
// if the destructor calls into it.
TEST(ClientLifecycle, DestructorGoodbyesPeersWithoutCallbacks) {
    std::unique_ptr<FakeEncryptedServer> server;
    ForbiddenMetadataListener listener;
    {
        PairedClientBundle bundle(make_config(DESTRUCTOR_TEST_PORT));
        SendspinClient& client = bundle.client();
        client.add_metadata().set_listener(&listener);
        ASSERT_TRUE(bundle.start());

        server = connect_paired_server(bundle.peer, DESTRUCTOR_TEST_PORT);
        pump_until(client, [&] { return client.is_connected(); });
        // Client destroyed here while established.
    }

    wait_until([&] { return server->closed(); });
    EXPECT_EQ(server->goodbye_reason().value_or(""), "shutdown");
}

// A role that fails to start part-way through start() rolls the roles before it back: here the
// player comes up and the visualizer (a ring too small to create) refuses, so start() reports
// failure and the client stays stopped. Replacing the broken role and starting again succeeds,
// which needs the first attempt to have joined the player's sync task: SyncTask::start() refuses
// a thread that is still running, so a rollback that skipped the join fails the retry too.
TEST(ClientLifecycle, FailedRoleStartRollsBackAndRetryStartsClean) {
    CountingPlayerListener listener;
    PairedClientBundle bundle(make_config(ROLLBACK_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&listener);

    VisualizerRoleConfig broken;
    broken.stream.types = {VisualizerDataType::LOUDNESS};
    broken.support.buffer_capacity = 0;  // Below the ring's minimum: start() fails
    broken.stream.rate_max = 30;
    client.add_visualizer(std::move(broken));

    EXPECT_FALSE(client.start());
    EXPECT_FALSE(client.is_started());
    EXPECT_FALSE(client.start());  // Still broken, still refused, still not stuck half-started

    VisualizerRoleConfig working;
    working.stream.types = {VisualizerDataType::LOUDNESS};
    working.support.buffer_capacity = 4096;
    working.stream.rate_max = 30;
    client.add_visualizer(std::move(working));

    ASSERT_TRUE(bundle.start());
    FakeEncryptedServerOptions options;
    options.answer_time = true;
    auto server = connect_paired_server(bundle.peer, ROLLBACK_TEST_PORT, options);
    pump_until(client, [&] { return client.is_connected(); });
    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    pump_until(client, [&] { return listener.stream_starts == 1; });
    stream_audio_until(client, *server, listener, 1);  // The rolled-back player plays again
    client.stop();
    EXPECT_EQ(listener.stream_ends, 1);
}

/// How far ahead of now a visualizer frame is stamped so it is still in the future when the drain
/// thread takes it, clear of the time filter's error on the same host.
constexpr int64_t VISUALIZER_LEAD_US = 50 * 1000;

// Pumps until pred() holds, sending one loudness frame per iteration stamped `lead_us` ahead of
// the current time (the drain thread drops a frame whose display time has passed). A frame
// can be lost to the ring's documented wake race right after a stream/start (the drain thread
// may take the clear marker as a stray entry and then discard up to a marker that is gone),
// which production shrugs off because the next frame follows; so does this.
void send_loudness_until(SendspinClient& client, FakeEncryptedServer& server, int64_t lead_us,
                         const std::function<bool()>& pred) {
    pump_until(client, [&] {
        if (pred()) {
            return true;
        }
        server.send_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, platform_time_us() + lead_us,
                           std::string("\x00\x10", 2));
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        return false;
    });
}

// stop() joins the visualizer drain thread and flushes the frames it had buffered, and start()
// clears the stop command, so a restart begins with an empty ring and a thread that delivers.
// The old frames are stamped far into the future, so the first session's thread parks on the
// first one with the rest buffered behind it when stop() runs.
//
// The ring is read directly because nothing a caller or peer observes distinguishes a drained
// ring from an abandoned one: the restarted thread drops leftovers before the new peer is time
// synced, and the new session's stream/start would discard them at its clear marker anyway.
TEST(ClientLifecycle, StopFlushesBufferedVisualizerFramesAndRestartDelivers) {
    constexpr int64_t OLD_FRAME_LEAD_US = 5 * 1000 * 1000;

    CountingVisualizerListener listener;
    auto config = make_config(VISUALIZER_TEST_PORT);
    config.time_burst_interval_ms = 100;  // Sync promptly after each (re)connect
    PairedClientBundle bundle(std::move(config));
    SendspinClient& client = bundle.client();
    client.add_visualizer(make_visualizer_config()).set_listener(&listener);

    FakeEncryptedServerOptions options;
    options.answer_time = true;

    ASSERT_TRUE(bundle.start());
    {
        auto server = connect_paired_server(bundle.peer, VISUALIZER_TEST_PORT, options);
        pump_until_synced(client);
        ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
        // The thread holds the first frame while it waits for its display time; the ones behind
        // it are the ring content stop() must discard.
        auto& ring = client.visualizer()->impl_->drain_task->ring_buffer;
        send_loudness_until(client, *server, OLD_FRAME_LEAD_US,
                            [&] { return ring.items_waiting() >= 2; });
        client.stop();
        EXPECT_TRUE(ring.is_empty());
        wait_until([&] { return server->closed(); });
    }
    EXPECT_EQ(listener.loudness.load(), 0U);

    ASSERT_TRUE(bundle.start());
    auto server = connect_paired_server(bundle.peer, VISUALIZER_TEST_PORT, options);
    pump_until_synced(client);
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    send_loudness_until(client, *server, VISUALIZER_LEAD_US,
                        [&] { return listener.loudness.load() >= 1; });
    client.stop();
}

/// Records the bins of the last spectrum frame the drain thread delivered.
class RecordingSpectrumListener : public VisualizerRoleListener {
public:
    void on_spectrum(int64_t client_timestamp, const std::vector<uint16_t>& bins) override {
        {
            std::lock_guard<std::mutex> lock(this->mutex_);
            this->bins_ = bins;
            if (!bins.empty()) {
                this->first_bins_.push_back(bins[0]);
            }
            this->client_timestamp_ = client_timestamp;
            this->delivered_at_ = platform_time_us();
        }
        this->frames.fetch_add(1);
        if (!bins.empty() && bins[0] >= this->hold_from_bin.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(this->hold_ms.load()));
        }
    }

    std::vector<uint16_t> last_bins() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->bins_;
    }

    /// How many delivered frames had `bin` as their first bin.
    size_t delivered(uint16_t bin) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return static_cast<size_t>(
            std::count(this->first_bins_.begin(), this->first_bins_.end(), bin));
    }

    /// How long before its client_timestamp the last frame was delivered (negative: after).
    int64_t last_lead_us() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->client_timestamp_ - this->delivered_at_;
    }

    std::atomic<size_t> frames{0};
    /// Frames whose first bin is at least hold_from_bin hold the drain thread for hold_ms, as a
    /// listener that takes time to render would.
    std::atomic<uint16_t> hold_from_bin{0xFFFF};
    std::atomic<int> hold_ms{0};

private:
    mutable std::mutex mutex_;
    std::vector<uint16_t> bins_;
    std::vector<uint16_t> first_bins_;
    int64_t client_timestamp_{0};
    int64_t delivered_at_{0};
};

/// A visualizer asking for four spectrum bins.
VisualizerRoleConfig make_spectrum_visualizer_config() {
    VisualizerRoleConfig visualizer;
    visualizer.stream.types = {VisualizerDataType::SPECTRUM};
    visualizer.support.buffer_capacity = 4096;
    visualizer.stream.rate_max = 30;
    visualizer.stream.spectrum = VisualizerSpectrumConfig{
        .n_disp_bins = 4, .scale = VisualizerSpectrumScale::MEL, .f_min = 40, .f_max = 16000};
    return visualizer;
}

/// A visualizer stream/start serving `served_bins` spectrum bins.
std::string stream_start_spectrum_json(unsigned served_bins) {
    return R"({"type":"stream/start","payload":{"visualizer":{"types":["spectrum"],)"
           R"("rate_max":30,"spectrum":{"n_disp_bins":)" +
           std::to_string(served_bins) +
           R"(,"scale":"mel","f_min":40,"f_max":16000}}}})";
}

// Pumps until pred() holds, sending one four-bin spectrum frame per iteration stamped
// VISUALIZER_LEAD_US ahead. A frame can be lost to the ring's documented wake race right after a
// stream/start (see send_loudness_until), so frames keep coming until one is delivered.
void send_spectrum_until(SendspinClient& client, FakeEncryptedServer& server,
                         const std::function<bool()>& pred) {
    const std::string four_bins("\x00\x0A\x00\x14\x00\x1E\x00\x28", 8);
    pump_until(client, [&] {
        if (pred()) {
            return true;
        }
        server.send_binary(SENDSPIN_BINARY_VISUALIZER_SPECTRUM,
                           platform_time_us() + VISUALIZER_LEAD_US, four_bins);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        return false;
    });
}

// roles/visualizer/v1.md "Server -> Client: stream/start": the served spectrum object, not the
// requested one, governs how many bins each frame carries. The negotiated count is what the
// drain thread decodes with, so it is pinned where a consumer sees it: a stream that serves two
// bins to a client that asked for four hands on_spectrum the first two of each wire frame.
TEST(ClientLifecycle, TheServedSpectrumBinCountGovernsTheDeliveredFrame) {
    RecordingSpectrumListener listener;
    auto config = make_config(VISUALIZER_SPECTRUM_TEST_PORT);
    config.time_burst_interval_ms = 100;  // Sync promptly: the drain thread needs client time
    PairedClientBundle bundle(std::move(config));
    SendspinClient& client = bundle.client();

    client.add_visualizer(make_spectrum_visualizer_config()).set_listener(&listener);

    FakeEncryptedServerOptions options;
    options.answer_time = true;

    ASSERT_TRUE(bundle.start());
    auto server = connect_paired_server(bundle.peer, VISUALIZER_SPECTRUM_TEST_PORT, options);
    pump_until_synced(client);
    ASSERT_TRUE(server->send_app_json(stream_start_spectrum_json(2)));

    send_spectrum_until(client, *server, [&] { return listener.frames.load() >= 1; });
    EXPECT_EQ(listener.last_bins(), (std::vector<uint16_t>{10, 20}));

    client.stop();
}

// A synced client with a four-bin spectrum stream running and its warm-up frames delivered.
// Frames are told apart by their bin values, and every wait retries or samples rather than
// bounding elapsed time, so a slow host can only make a test take longer.
class VisualizerDelivery : public ::testing::Test {
protected:
    void start(uint16_t port, int32_t display_offset_ms = 0) {
        auto config = make_config(port);
        config.time_burst_interval_ms = 100;  // Sync promptly: the drain thread needs client time
        this->bundle = std::make_unique<PairedClientBundle>(std::move(config));
        VisualizerRoleConfig visualizer = make_spectrum_visualizer_config();
        visualizer.display_offset_ms = display_offset_ms;
        this->client().add_visualizer(std::move(visualizer)).set_listener(&this->listener);

        FakeEncryptedServerOptions options;
        options.answer_time = true;
        ASSERT_TRUE(this->bundle->start());
        this->server = connect_paired_server(this->bundle->peer, port, options);
        pump_until_synced(this->client());
        ASSERT_TRUE(this->server->send_app_json(stream_start_spectrum_json(4)));
        send_spectrum_until(this->client(), *this->server,
                            [&] { return this->listener.frames.load() >= 1; });
        // Let the warm-up frames still queued behind the first one deliver, so a test's frames
        // reach an idle drain thread instead of waiting behind them.
        auto& ring = this->client().visualizer()->impl_->drain_task->ring_buffer;
        pump_until(this->client(), [&] { return ring.is_empty(); });
        pump_for(this->client(), static_cast<int>(2 * VISUALIZER_LEAD_US / 1000));
    }

    void TearDown() override {
        if (this->bundle) {
            this->client().stop();
        }
    }

    SendspinClient& client() {
        return this->bundle->client();
    }

    /// Sends a spectrum frame whose four bins all hold `bin`, stamped `display_us`.
    void send_frame_at(int64_t display_us, uint16_t bin) {
        std::string bins;
        for (int i = 0; i < 4; ++i) {
            bins.push_back(static_cast<char>(bin >> 8));
            bins.push_back(static_cast<char>(bin & 0xFF));
        }
        this->server->send_binary(SENDSPIN_BINARY_VISUALIZER_SPECTRUM, display_us, bins);
    }

    RecordingSpectrumListener listener;
    std::unique_ptr<PairedClientBundle> bundle;
    std::unique_ptr<FakeEncryptedServer> server;
};

// roles/visualizer/v1.md "Visualization Data (Binary)": data already in the past on arrival is
// dropped. The ring is FIFO, so once an in-time frame sent after them is delivered, every late
// frame ahead of it has been judged.
TEST_F(VisualizerDelivery, FramesAlreadyInThePastOnArrivalAreDropped) {
    ASSERT_NO_FATAL_FAILURE(this->start(VISUALIZER_STALE_TEST_PORT));
    for (int i = 0; i < 5; ++i) {
        this->send_frame_at(platform_time_us() - 10 * 1000, 1);
    }
    pump_until(this->client(), [&] {
        if (this->listener.delivered(2) > 0) {
            return true;
        }
        this->send_frame_at(platform_time_us() + VISUALIZER_LEAD_US, 2);  // Control:
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        return false;
    });

    EXPECT_EQ(this->listener.delivered(1), 0U) << "a frame late on arrival was delivered";
}

// A server sends one message per visualization type for each analysis frame, all with the same
// timestamp, and a listener that takes 3 ms per frame leaves the drain thread reaching each
// sibling after that timestamp. Every sibling arrived in time, so a whole group is delivered.
// Groups repeat until one completes, so a stall that pushes a sibling past the lag bound only
// costs another group; judging lateness at dequeue never completes one.
TEST_F(VisualizerDelivery, FramesSharingATimestampAreAllDelivered) {
    ASSERT_NO_FATAL_FAILURE(this->start(VISUALIZER_SHARED_TS_TEST_PORT));
    constexpr uint16_t FIRST_GROUP_BIN = 100;
    constexpr uint16_t SIBLINGS = 4;
    this->listener.hold_from_bin = FIRST_GROUP_BIN;
    this->listener.hold_ms = 3;

    auto group_delivered = [&](uint16_t group) {
        for (uint16_t i = 0; i < SIBLINGS; ++i) {
            if (this->listener.delivered(FIRST_GROUP_BIN + group * SIBLINGS + i) == 0) {
                return false;
            }
        }
        return true;
    };
    uint16_t groups_sent = 0;
    pump_until(this->client(), [&] {
        for (uint16_t group = 0; group < groups_sent; ++group) {
            if (group_delivered(group)) {
                return true;
            }
        }
        const int64_t display_us = platform_time_us() + VISUALIZER_LEAD_US;
        for (uint16_t i = 0; i < SIBLINGS; ++i) {
            this->send_frame_at(display_us, FIRST_GROUP_BIN + groups_sent * SIBLINGS + i);
        }
        ++groups_sent;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        return false;
    });
}

// VisualizerRoleConfig::display_offset_ms shifts delivery from the display time, which the
// callback's client_timestamp still reports. A negative offset is used because a delay is
// checkable without an upper bound: a slow host only delivers later. The wait rounds down to
// whole milliseconds, so delivery can come up to 1 ms before the shifted time.
TEST_F(VisualizerDelivery, DisplayOffsetShiftsDeliveryFromTheDisplayTime) {
    constexpr int32_t OFFSET_MS = -300;
    ASSERT_NO_FATAL_FAILURE(this->start(VISUALIZER_OFFSET_TEST_PORT, OFFSET_MS));

    EXPECT_LE(this->listener.last_lead_us(), (OFFSET_MS + 1) * 1000)
        << "delivered " << this->listener.last_lead_us() << " us before the display time";
}

/// Counts high-performance requests and releases without touching the client, as the listener
/// contract requires.
class CountingClientListener : public SendspinClientListener {
public:
    void on_request_high_performance() override {
        ++this->requests;
    }
    void on_release_high_performance() override {
        ++this->releases;
    }

    int requests{0};
    int releases{0};
};

// The high-performance hold taken for a time burst is released inside the connection-loss path
// and again by stop(); request and release stay paired across a peer loss, a reconnect, and the
// stop.
TEST(ClientLifecycle, HighPerformanceRequestAndReleaseStayPaired) {
    auto config = make_config(HIGH_PERF_TEST_PORT);
    config.time_burst_interval_ms = 50;
    PairedClientBundle bundle(std::move(config));
    SendspinClient& client = bundle.client();
    CountingClientListener listener;
    client.set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    auto server = connect_paired_server(bundle.peer, HIGH_PERF_TEST_PORT);
    pump_until(client, [&] { return client.is_connected(); });
    // The default fake server never answers client/time, so the burst stays open and the hold
    // stays held until the connection is lost.
    pump_until(client, [&] { return listener.requests == 1; });
    EXPECT_EQ(listener.releases, 0);

    server.reset();  // Peer goes away mid-burst: drop_connection releases the hold
    pump_until(client, [&] { return listener.releases == 1; });
    EXPECT_FALSE(client.is_connected());

    auto again = connect_paired_server(bundle.peer, HIGH_PERF_TEST_PORT);
    pump_until(client, [&] { return client.is_connected() && listener.requests == 2; });
    client.stop();
    EXPECT_EQ(listener.releases, 2);
}

// Destroying a running client ends the hold too: the release sites stop() reaches through the
// connection cleanup do not run in the destructor, so it has to release on its own or the
// platform is left in high-performance mode after the client is gone.
TEST(ClientLifecycle, DestructorReleasesHighPerformanceHold) {
    CountingClientListener listener;
    std::unique_ptr<FakeEncryptedServer> server;
    {
        auto config = make_config(DESTRUCTOR_HIGH_PERF_TEST_PORT);
        config.time_burst_interval_ms = 50;
        PairedClientBundle bundle(std::move(config));
        SendspinClient& client = bundle.client();
        client.set_listener(&listener);
        ASSERT_TRUE(bundle.start());

        server = connect_paired_server(bundle.peer, DESTRUCTOR_HIGH_PERF_TEST_PORT);
        pump_until(client, [&] { return client.is_connected() && listener.requests == 1; });
        EXPECT_EQ(listener.releases, 0);
        // Client destroyed here mid-burst, with the hold open.
    }
    EXPECT_EQ(listener.releases, 1);
}

// ============================================================================
// publish_state() connection lifetime
// ============================================================================

/// Rendezvous state for PublishingConnection, owned by the test rather than by the connection so
/// the send path can still reach it after the connection has been destroyed.
struct PublishRendezvous {
    std::promise<void> in_send;      // Signalled once the send is inside the connection
    std::promise<void> slot_dropped;  // Signalled once the manager's slot is gone
    std::vector<std::string> sent;
    bool destroyed{false};
    bool destroyed_during_send{false};
};

/// Connection stand-in with every transport override inert: nothing is sent anywhere, a send
/// completes inline and reports success, and the connection always reads as connected. Tests that
/// install one in the manager's slot derive from it and override only the one call they are about
/// to observe.
class StubConnection : public SendspinConnection {
public:
    void start() override {}
    void loop() override {}
    void disconnect(SendspinGoodbyeReason, std::function<void()> on_complete) override {
        if (on_complete) {
            on_complete();
        }
    }
    void close_transport_now() override {}
    bool is_connected() const override {
        return true;
    }
    SsErr send_binary_message(const uint8_t*, size_t, SendCompleteCallback cb, bool) override {
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }
    SsErr send_text_message(const std::string&, SendCompleteCallback cb, bool) override {
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }
};

/// Parks inside its own send until the test has dropped the connection manager's slot, then
/// records whether it was destroyed while that send was still running.
class PublishingConnection : public StubConnection {
public:
    explicit PublishingConnection(PublishRendezvous* rv) : rv_(rv) {}
    ~PublishingConnection() override {
        this->rv_->destroyed = true;
    }

    // No Noise session, so send_app_json() routes the client/state here as raw text.
    SsErr send_text_message(const std::string& msg, SendCompleteCallback cb, bool) override {
        // Everything this send needs after the drop lives on the stack: under the defect the
        // object is gone by then, and touching a member would be the use-after-free rather than
        // the assertion that names it.
        PublishRendezvous* rv = this->rv_;
        rv->sent.push_back(msg);
        rv->in_send.set_value();
        rv->slot_dropped.get_future().wait();
        rv->destroyed_during_send = rv->destroyed;
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }

private:
    PublishRendezvous* rv_;
};

// publish_state() resolves the current connection as a shared_ptr, so a caller that is not the
// main loop (a role thread, against its documented contract) cannot have the connection freed
// under its send. The main loop drops the manager's slot while the publish is parked inside the
// connection's own send: the shared_ptr publish_state() holds is then the last reference, so the
// connection outlives the call and is destroyed only when it returns.
TEST(ClientLifecycle, PublishStateOutlivesADropDuringTheSend) {
    TestNetworkProvider network;
    SendspinClient client(make_config(PUBLISH_STATE_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start());

    PublishRendezvous rv;
    {
        auto conn = std::make_shared<PublishingConnection>(&rv);
        conn->set_client_hello_sent(true);
        conn->set_server_hello_received(true);
        conn->apply_server_activate({SendspinActivity::PLAYBACK}, std::nullopt, std::nullopt,
                                    std::nullopt);
        // Installed directly, so mark it the way admission would: client/state waits for it.
        conn->set_admitted(true);
        std::lock_guard<std::mutex> lock(client.connection_manager_->conn_ptr_mutex_);
        client.connection_manager_->current_connection_ = std::move(conn);
    }

    std::thread role_thread([&client] { client.publish_state(); });
    rv.in_send.get_future().wait();
    {
        std::lock_guard<std::mutex> lock(client.connection_manager_->conn_ptr_mutex_);
        client.connection_manager_->current_connection_.reset();
    }
    EXPECT_FALSE(rv.destroyed) << "the manager held the only other reference, so the publish's "
                                  "own shared_ptr is what kept the connection alive";
    rv.slot_dropped.set_value();
    role_thread.join();

    EXPECT_FALSE(rv.destroyed_during_send)
        << "the connection was destroyed while its own send was running";
    EXPECT_TRUE(rv.destroyed) << "the publish leaked the connection past its own call";
    EXPECT_EQ(rv.sent.size(), 1u) << "the client/state never reached the connection";

    client.stop();
}

/// Counts client/hello sends; `result` is what each send returns. The completion fires inline with
/// the send's outcome, as the encrypted send_app_json() path reports it.
class HelloCountingConnection : public StubConnection {
public:
    explicit HelloCountingConnection(SsErr result) : result_(result) {}

    // No Noise session, so send_app_json() routes the hello here as raw text.
    SsErr send_text_message(const std::string& msg, SendCompleteCallback cb, bool) override {
        if (msg.find("client/hello") != std::string::npos) {
            ++this->hellos;
        }
        if (cb) {
            cb(this->result_ == SsErr::OK);
        }
        return this->result_;
    }

    int hellos{0};

private:
    SsErr result_;
};

// A nursery connection's client/hello is armed once, when its Noise handshake completes, and never
// again: a hello the transport refuses, or one whose attempts run out, is left for the close event
// or the establish deadline rather than re-armed with a fresh set of attempts. Every tick forces
// the next attempt due, so the backoff delays do not stretch the test (and are not pinned by it).
TEST(ClientLifecycle, NurseryHelloIsArmedOnceAndNeverReArmed) {
    struct Row {
        const char* name;
        SsErr send_result;
        int expected_hellos;
    };
    const Row rows[] = {
        {"Control: queued", SsErr::OK, 1},
        {"refused by the transport", SsErr::INVALID_STATE, 1},
        {"every attempt fails", SsErr::FAIL, NurseryEntry::MAX_HELLO_ATTEMPTS},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        TestNetworkProvider network;
        SendspinClient client(make_config(HELLO_TEST_PORT));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        ConnectionManager& manager = *client.connection_manager_;
        auto conn = std::make_shared<HelloCountingConnection>(row.send_result);
        conn->noise_handshake_complete_.store(true);
        conn->set_provisional_time_us(platform_time_us());
        {
            std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
            manager.push_nursery_entry(NurseryEntry{.conn = conn});
        }

        for (int tick = 0; tick < NurseryEntry::MAX_HELLO_ATTEMPTS + 3; ++tick) {
            manager.scan_hello_and_nursery();
            std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
            for (auto& entry : manager.nursery_) {
                entry.hello_due_us = 0;
            }
        }
        EXPECT_EQ(conn->hellos, row.expected_hellos);

        client.stop();
    }
}

// ============================================================================
// Admission-closed rejection
// ============================================================================

// A peer delivered while admission is closed (stop() tearing down, or before start()) gets a
// client/goodbye with reason shutdown instead of a nursery slot. The goodbye is sent by
// on_new_connection() itself, on the network thread, so the closed row waits on the peer without
// pumping loop(). The open row is the control: the same peer is admitted and owed no goodbye.
// The nursery-full rejection is covered by
// ConnectionLifecycle.FullNurseryOfLivePeersRejectsNewcomer.
TEST(ClientLifecycle, ANewcomerWhileAdmissionIsClosedIsGoodbyedWithShutdown) {
    struct AdmissionRow {
        const char* name;
        bool accepting;
        uint16_t port;
    };
    const AdmissionRow rows[] = {
        {"admission closed", false, ADMISSION_CLOSED_TEST_PORT},
        {"Control: admission open", true, ADMISSION_OPEN_TEST_PORT},
    };

    for (const AdmissionRow& row : rows) {
        SCOPED_TRACE(row.name);
        PairedClientBundle bundle(make_config(row.port));
        SendspinClient& client = bundle.client();
        ASSERT_TRUE(bundle.start());
        {
            std::lock_guard<std::mutex> lock(client.connection_manager_->conn_ptr_mutex_);
            client.connection_manager_->accepting_ = row.accepting;
        }

        auto peer = connect_paired_server(bundle.peer, row.port);
        if (row.accepting) {
            pump_until(client, [&] { return client.is_connected(); });
            EXPECT_FALSE(peer->goodbye_reason().has_value())
                << "an admitted peer was sent a goodbye";
        } else {
            wait_until([&] { return peer->goodbye_reason().has_value(); });
            EXPECT_EQ(peer->goodbye_reason().value_or(""), "shutdown")
                << "a newcomer rejected with admission closed must be told why";
            EXPECT_FALSE(client.is_connected())
                << "a rejected newcomer must not become the current connection";
        }

        client.stop();
    }
}

// ============================================================================
// Time filter slot
// ============================================================================

// 48 kHz stereo 16-bit, the format make_pcm_player_config() advertises.
constexpr uint32_t SINK_SAMPLE_RATE = 48000;
constexpr size_t SINK_FRAME_BYTES = 4;
constexpr size_t SINK_CHUNK_BYTES = SINK_SAMPLE_RATE / 50 * SINK_FRAME_BYTES;  // 20 ms
/// Byte every chunk these tests feed is filled with, so a write the sink takes can be told apart
/// from the silence the sync task emits while priming or filling a hard-sync gap. PCM decoding is
/// a copy, so the pattern survives into the sink.
constexpr uint8_t SINK_AUDIO_MARK = 0x7F;

/// Stands in for an audio sink. Every write is reported back through
/// PlayerRole::notify_audio_played() with the time those frames finish, which is what moves the
/// sync task out of initial-sync priming and into the per-chunk LOAD_CHUNK cycle; a listener that
/// never reports progress leaves it priming forever and no chunk is ever loaded. The write itself
/// is paced so the sink stays slower than a test thread filling the ring.
class VirtualSinkListener : public PlayerRoleListener {
public:
    size_t on_audio_write(uint8_t* data, size_t length, uint32_t /*timeout_ms*/) override {
        const bool marked = std::any_of(data, data + length, [](uint8_t b) { return b != 0; });
        const auto frames = static_cast<uint32_t>(length / SINK_FRAME_BYTES);
        const int64_t now = platform_time_us();
        if (this->playhead_us_ < now) {
            this->playhead_us_ = now;
        }
        this->playhead_us_ +=
            static_cast<int64_t>(frames) * 1000000 / static_cast<int64_t>(SINK_SAMPLE_RATE);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (this->player_ != nullptr && frames > 0) {
            this->player_->notify_audio_played(frames, this->playhead_us_);
        }
        if (marked && !this->decoded_seen_.exchange(true)) {
            this->first_decoded_.set_value();
        }
        return length;
    }
    void on_stream_end() override {
        ++this->stream_ends;
    }

    void attach(PlayerRole& player) {
        this->player_ = &player;
    }
    /// True once a write carried SINK_AUDIO_MARK, i.e. a fed chunk was converted and decoded.
    bool decoded() const {
        return this->decoded_seen_.load();
    }
    /// Parks until the first decoded chunk reaches the sink. No timeout: the point of the caller
    /// is that a regression never gets here.
    void wait_for_decoded() {
        this->first_decoded_.get_future().wait();
    }

    int stream_ends{0};

private:
    PlayerRole* player_{nullptr};
    std::atomic<bool> decoded_seen_{false};
    std::promise<void> first_decoded_;
    int64_t playhead_us_{0};  // Sync-task thread only
};

/// Writes `count` marked 20 ms chunks straight into the sync task's encoded ring, stamped in the
/// server's clock from `first_timestamp` onward. Bypasses the server so a test can feed audio
/// while it holds a lock the client's own loop needs.
void feed_marked_chunks(SyncTask& sync_task, int64_t first_timestamp, int count) {
    const std::vector<uint8_t> chunk(SINK_CHUNK_BYTES, SINK_AUDIO_MARK);
    int64_t timestamp = first_timestamp;
    for (int i = 0; i < count; ++i) {
        sync_task.write_audio_chunk(chunk.data(), chunk.size(), timestamp,
                                    CHUNK_TYPE_ENCODED_AUDIO, 0);
        timestamp += 20 * 1000;
    }
}

/// The lead the fed chunks are stamped with: past the pipeline's own priming and startup silence,
/// so the first chunk is ahead of the sink's playhead rather than late enough to be skipped.
constexpr int64_t SINK_CHUNK_LEAD_US = 250 * 1000;

/// Keeps feeding marked chunks until the sink has decoded one. Each batch is stamped from a fresh
/// read of the clock, so a batch the decoder skipped as late (the gate is
/// HARD_SYNC_THRESHOLD_US behind the sink's playhead) is followed by one that is early again. A
/// fixed number of chunks would instead leave a loaded machine with nothing left to decode, which
/// hangs the waiter exactly the way a parked sync task does. `server_offset_us` is the server
/// clock's offset from this one, which the stream's time filter was synced to.
class ChunkFeeder {
public:
    ChunkFeeder(SyncTask& sync_task, const VirtualSinkListener& listener,
                int64_t server_offset_us = 0)
        : thread_([&sync_task, &listener, server_offset_us] {
              while (!listener.decoded()) {
                  feed_marked_chunks(sync_task,
                                     platform_time_us() + server_offset_us + SINK_CHUNK_LEAD_US, 4);
                  std::this_thread::sleep_for(std::chrono::milliseconds(10));
              }
          }) {}
    ~ChunkFeeder() {
        this->thread_.join();
    }

private:
    std::thread thread_;
};

// The sync task's per-chunk time getters read the manager's time filter slot, not
// conn_ptr_mutex_, so a chunk decodes while this thread holds that lock, as the main loop does in
// ConnectionManager's lifecycle block. A getter that took the lock would park the task and no fed
// chunk would reach the sink. The wait has no timeout of its own, since no bound could tell a
// parked task from a slow machine: the suite watchdog in tests/main.cpp names it instead.
TEST(ClientLifecycle, SyncTaskDecodesAChunkWhileTheManagerLockIsHeld) {
    VirtualSinkListener listener;
    auto config = make_config(STREAM_FILTER_LOCK_TEST_PORT);
    config.time_burst_interval_ms = 100;  // Sync promptly after the connect
    PairedClientBundle bundle(std::move(config));
    SendspinClient& client = bundle.client();
    PlayerRole& player = client.add_player(make_pcm_player_config());
    player.set_listener(&listener);
    listener.attach(player);

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    ASSERT_TRUE(bundle.start());
    auto server = connect_paired_server(bundle.peer, STREAM_FILTER_LOCK_TEST_PORT, options);
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    SyncTask& sync_task = *client.player_->impl_->sync_task;
    pump_until(client, [&] { return sync_task.is_running(); });

    {
        std::lock_guard<std::mutex> lock(client.connection_manager_->conn_ptr_mutex_);
        ChunkFeeder feeder(sync_task, listener);
        listener.wait_for_decoded();
    }

    client.stop();
    EXPECT_EQ(listener.stream_ends, 1);
}

/// What a test learns about a stand-in connection after it is gone; owned by the test, since
/// the connection is what reports its own destruction.
struct ConnectionObservation {
    std::atomic<int> goodbyes{0};
    std::thread::id destroyed_on{};
    std::atomic<bool> destroyed{false};  // Published last: orders the id above for the reader
};

/// Connection stand-in that records where it was destroyed and how many goodbyes it was asked
/// for. The tests drive the stream through the player's own handlers, so no message traffic
/// reaches it: it exists to carry the stream's time filter, and to be goodbyed and freed. Its
/// filter is created with it, as production does before a connection can enter a slot.
class ObservedConnection : public StubConnection {
public:
    explicit ObservedConnection(ConnectionObservation* obs) : obs_(obs) {
        this->init_time_filter();
    }
    ~ObservedConnection() override {
        this->obs_->destroyed_on = std::this_thread::get_id();
        this->obs_->destroyed.store(true);
    }

    // Counts what the wire would carry: one disconnect() is one goodbye frame.
    void disconnect(SendspinGoodbyeReason, std::function<void()> on_complete) override {
        this->obs_->goodbyes.fetch_add(1);
        if (on_complete) {
            on_complete();
        }
    }

private:
    ConnectionObservation* obs_;
};

/// The stream the stand-in connection tests start: the format make_pcm_player_config() advertises.
ServerPlayerStreamObject pcm_stream_params() {
    ServerPlayerStreamObject params;
    params.codec = SendspinCodecFormat::PCM;
    params.sample_rate = SINK_SAMPLE_RATE;
    params.channels = 2;
    params.bit_depth = 16;
    return params;
}

/// Config for a client whose current connection is a stand-in: the stand-in never receives
/// anything, so the liveness check is disabled rather than left to drop it as silent.
SendspinClientConfig make_stand_in_config(uint16_t port) {
    SendspinClientConfig config = make_config(port);
    config.liveness_timeout_ms = 0;
    return config;
}

/// Installs a stand-in connection as current, the way a promotion does, and starts a stream on it,
/// returning once the sync task is running. The stream is driven through PlayerRole::Impl, since
/// nothing is connected to carry a stream/start. The client must use make_stand_in_config().
void start_stream_on(SendspinClient& client, std::shared_ptr<ObservedConnection> conn) {
    {
        std::lock_guard<std::mutex> lock(client.connection_manager_->conn_ptr_mutex_);
        client.connection_manager_->set_current_connection(std::move(conn));
    }
    PlayerRole::Impl& impl = *client.player_->impl_;
    impl.handle_stream_start(pcm_stream_params(), impl.cleanup_generation.load());
    SyncTask& sync_task = *impl.sync_task;
    pump_until(client, [&] { return sync_task.is_running(); });
}

/// Server clock offset the stand-in connections' filters are seeded with: 10 min behind this
/// client, beyond the hang watchdog's budget, so an unconverted chunk cannot age back into a
/// starved sink's window before the watchdog fires.
constexpr int64_t SEEDED_SERVER_OFFSET_US = -10LL * 60 * 1000 * 1000;

/// A stand-in connection whose time filter has taken one measurement of SEEDED_SERVER_OFFSET_US.
std::shared_ptr<ObservedConnection> make_synced_connection(ConnectionObservation* obs) {
    auto conn = std::make_shared<ObservedConnection>(obs);
    conn->get_time_filter()->update(SEEDED_SERVER_OFFSET_US, /*max_error=*/1000, platform_time_us());
    return conn;
}

// set_current_connection() keeps the time filter slot on the current connection's filter: a
// synced connection converts with its offset, a vacated slot reads as unsynced, the slot never
// keeps a connection alive, and an unsynced newcomer installed over a synced one reads its own
// filter.
TEST(ClientLifecycle, TheTimeFilterSlotFollowsTheCurrentConnection) {
    ConnectionObservation dropped_obs;  // All outlive the client
    ConnectionObservation replaced_obs;
    ConnectionObservation newcomer_obs;
    SendspinClient client(make_config(TIME_FILTER_SLOT_TEST_PORT));
    ConnectionManager& manager = *client.connection_manager_;
    constexpr int64_t SERVER_TS_US = 50 * 1000 * 1000;

    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.set_current_connection(make_synced_connection(&dropped_obs));
    }
    EXPECT_TRUE(client.is_time_synced());
    EXPECT_EQ(client.get_client_time(SERVER_TS_US), SERVER_TS_US - SEEDED_SERVER_OFFSET_US);

    std::shared_ptr<SendspinConnection> slot;
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        slot.swap(manager.current_connection_);
        manager.set_current_connection(nullptr);
    }
    EXPECT_FALSE(client.is_time_synced());
    EXPECT_EQ(client.get_client_time(SERVER_TS_US), 0);
    slot.reset();
    EXPECT_TRUE(dropped_obs.destroyed.load())
        << "a reference other than the slot's kept the connection alive";

    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.set_current_connection(make_synced_connection(&replaced_obs));
    }
    ASSERT_TRUE(client.is_time_synced());
    auto newcomer = std::make_shared<ObservedConnection>(&newcomer_obs);
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.set_current_connection(std::move(newcomer));
    }
    EXPECT_FALSE(client.is_time_synced()) << "the newcomer read the replaced connection's filter";
}

// The sync task converts chunks with the current connection's offset. The fed
// chunks are stamped in the server's clock, so a task that never saw the filter (parked unsynced)
// or a conversion that skipped the offset (every chunk late) never reaches the sink. No timeout of
// its own, as in SyncTaskDecodesAChunkWhileTheManagerLockIsHeld.
TEST(ClientLifecycle, TheSyncTaskConvertsEachChunkWithTheCurrentOffset) {
    ConnectionObservation observation;  // Outlives the client
    VirtualSinkListener listener;
    TestNetworkProvider network;
    SendspinClient client(make_stand_in_config(STREAM_FILTER_OFFSET_TEST_PORT));
    client.set_network_provider(&network);
    PlayerRole& player = client.add_player(make_pcm_player_config());
    player.set_listener(&listener);
    listener.attach(player);
    ASSERT_TRUE(client.start());

    start_stream_on(client, make_synced_connection(&observation));
    {
        ChunkFeeder feeder(*client.player_->impl_->sync_task, listener, SEEDED_SERVER_OFFSET_US);
        listener.wait_for_decoded();
    }

    client.stop();
    EXPECT_EQ(listener.stream_ends, 1);
}

// A stream's connection dropped mid-stream carries exactly one client/goodbye on its wire and
// is freed on the thread that pumps loop(), never on the sync task's: the task holds no
// connection reference of its own. A task that did would keep the connection alive past the
// flush and free it on the audio thread when the stream ended.
TEST(ClientLifecycle, ADroppedStreamConnectionIsGoodbyedOnceAndFreedOnTheLoopThread) {
    ConnectionObservation observation;  // Outlives the client
    CountingPlayerListener listener;
    TestNetworkProvider network;
    SendspinClient client(make_stand_in_config(STREAM_FILTER_MIDSTREAM_TEST_PORT));
    client.set_network_provider(&network);
    client.add_player(make_pcm_player_config()).set_listener(&listener);
    ASSERT_TRUE(client.start());

    auto conn = std::make_shared<ObservedConnection>(&observation);
    SendspinConnection* streamed = conn.get();
    start_stream_on(client, std::move(conn));
    ConnectionManager& manager = *client.connection_manager_;

    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.drop_connection(streamed, SendspinGoodbyeReason::ANOTHER_SERVER);
    }
    manager.flush_deferred_releases();
    pump_until(client, [&] { return listener.stream_ends == 1; });
    pump_until(client, [&] { return observation.destroyed.load(); });

    EXPECT_EQ(observation.goodbyes.load(), 1)
        << "expected exactly one client/goodbye on this connection's wire";
    // Private read: nothing a caller or peer observes distinguishes the destructor's thread.
    EXPECT_EQ(observation.destroyed_on, std::this_thread::get_id())
        << "the connection was freed on a thread other than the one that pumps loop()";

    client.stop();
}

}  // namespace
