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

#include "connection_manager.h"  // GoodbyeWait, GOODBYE_FLUSH_TIMEOUT_MS
#include "crypto/constants.h"
#include "crypto/keys.h"
#include "lifecycle_test_fixtures.h"
#include "platform/time.h"
#include "protocol_messages.h"  // SENDSPIN_BINARY_VISUALIZER_LOUDNESS
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/visualizer_role.h"
#include "visualizer_role_impl.h"  // Ring state after stop(); private access, see tests/CMakeLists.txt

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// Distinct ports per test so a lingering socket from one scenario cannot bleed into the next
// (test_connection_lifecycle.cpp uses 18941-18985, test_encrypted_lifecycle.cpp 18991-19003).
constexpr uint16_t RESTART_TEST_PORT = 19011;
constexpr uint16_t NURSERY_GOODBYE_TEST_PORT = 19012;
constexpr uint16_t STREAM_TEST_PORT = 19013;
constexpr uint16_t CALLBACK_TEST_PORT = 19014;
constexpr uint16_t DESTRUCTOR_TEST_PORT = 19015;
constexpr uint16_t ROLLBACK_TEST_PORT = 19016;
constexpr uint16_t HIGH_PERF_TEST_PORT = 19017;
constexpr uint16_t VISUALIZER_TEST_PORT = 19018;
constexpr uint16_t DESTRUCTOR_HIGH_PERF_TEST_PORT = 19019;

/// Bound on every pump/wait: generous next to the loopback round trips involved, so the verdict
/// comes from the predicate rather than the clock.
constexpr int PUMP_TIMEOUT_MS = 6000;

SendspinClientConfig make_config(uint16_t port) {
    SendspinClientConfig config;
    config.name = "Client Lifecycle Test Client";
    config.server_port = port;
    return config;
}

/// A paired fake server connected to the bundle's client on `port`.
std::unique_ptr<FakeEncryptedServer> connect_paired_server(const PairedPeer& peer,
                                                           const Identity& identity, uint16_t port,
                                                           FakeEncryptedServerOptions options = {}) {
    return std::make_unique<FakeEncryptedServer>(server_url(port), std::string(NOISE_SUITE_CHACHAPOLY),
                                                 identity, peer.record.psk_id, peer.psk,
                                                 std::move(options));
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

std::string stream_start_pcm_json() {
    return R"({"type":"stream/start","payload":{"player":{"codec":"pcm","sample_rate":48000,)"
           R"("channels":2,"bit_depth":16}}})";
}

std::string group_update_playing_json() {
    return R"({"type":"group/update","payload":{"playback_state":"playing"}})";
}

PlayerRoleConfig make_player_config() {
    PlayerRoleConfig player_cfg;
    player_cfg.audio_formats.push_back({SendspinCodecFormat::PCM, 2, 48000, 16});
    player_cfg.audio_buffer_capacity = 64 * 1024;
    return player_cfg;
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
    EXPECT_TRUE(idle.wait(GOODBYE_FLUSH_TIMEOUT_MS));

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

        Identity identity = Identity::generate().value();
        auto server = connect_paired_server(bundle.peer, identity, RESTART_TEST_PORT);
        ASSERT_TRUE(pump_until(
            client, [&] { return client.is_connected(); }, PUMP_TIMEOUT_MS));
        auto info = client.get_server_information();
        ASSERT_TRUE(info.has_value());
        EXPECT_EQ(info->server_id, identity.peer_id());

        // Some group state for stop() to reset.
        ASSERT_TRUE(server->send_app_json(group_update_playing_json()));
        ASSERT_TRUE(pump_until(
            client, [&] { return client.get_group_state().playback_state.has_value(); },
            PUMP_TIMEOUT_MS));

        client.stop();

        EXPECT_FALSE(client.is_started());
        EXPECT_FALSE(client.is_connected());
        EXPECT_FALSE(client.get_server_information().has_value());
        EXPECT_FALSE(client.get_group_state().playback_state.has_value());
        // The peer received its goodbye and the close, in that order.
        EXPECT_TRUE(wait_until([&] { return server->closed(); }, PUMP_TIMEOUT_MS));
        EXPECT_EQ(server->goodbye_reason().value_or(""), "shutdown");

        // Stopped means quiescent: pumping loop() must not bring the server back up.
        pump_for(client, 100);
        EXPECT_FALSE(port_accepts(RESTART_TEST_PORT));
    }
}

// A peer still in the nursery (it handshook and answered the hello but never activated) gets the
// same goodbye and close as the established one, so no peer is left to discover the shutdown by
// timeout.
TEST(ClientLifecycle, StopGoodbyesNurseryPeersToo) {
    PairedClientBundle bundle(make_config(NURSERY_GOODBYE_TEST_PORT));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    Identity established_identity = Identity::generate().value();
    auto established =
        connect_paired_server(bundle.peer, established_identity, NURSERY_GOODBYE_TEST_PORT);
    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, PUMP_TIMEOUT_MS));

    // Runs on the Sentinel PSK, which RecordStore resolves unconditionally, so it needs no record
    // of its own; never activating keeps it in the nursery.
    FakeEncryptedServerOptions mute_options;
    mute_options.suppress_activate = true;
    Identity mute_identity = Identity::generate().value();
    FakeEncryptedServer mute(server_url(NURSERY_GOODBYE_TEST_PORT),
                             std::string(NOISE_SUITE_CHACHAPOLY), mute_identity,
                             std::string(SENTINEL_PSK_ID), SENTINEL_PSK, mute_options);
    ASSERT_TRUE(pump_until(
        client, [&] { return mute.client_hello_count() > 0; }, PUMP_TIMEOUT_MS));

    client.stop();

    EXPECT_TRUE(wait_until([&] { return established->closed() && mute.closed(); },
                           PUMP_TIMEOUT_MS));
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
    client.add_player(make_player_config()).set_listener(&listener);

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    for (int cycle = 0; cycle < 2; ++cycle) {
        ASSERT_TRUE(bundle.start());
        Identity identity = Identity::generate().value();
        auto server = connect_paired_server(bundle.peer, identity, STREAM_TEST_PORT, options);
        ASSERT_TRUE(pump_until(
            client, [&] { return client.is_connected(); }, PUMP_TIMEOUT_MS));

        ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
        ASSERT_TRUE(pump_until(
            client, [&] { return listener.stream_starts == cycle + 1; }, PUMP_TIMEOUT_MS));
        EXPECT_EQ(listener.stream_ends, cycle);

        // Audio flowing proves the sync task thread is alive in this cycle.
        const size_t writes_before = listener.audio_writes.load();
        EXPECT_TRUE(stream_audio_until(client, *server, listener, writes_before + 1));

        client.stop();

        // The clear callback was delivered inside stop(), not left for a loop() tick.
        EXPECT_EQ(listener.stream_ends, cycle + 1);
        EXPECT_EQ(listener.stream_starts, cycle + 1);
        EXPECT_TRUE(wait_until([&] { return server->closed(); }, PUMP_TIMEOUT_MS));
        EXPECT_EQ(server->goodbye_reason().value_or(""), "shutdown");
    }
}

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
        Identity identity = Identity::generate().value();
        auto server = connect_paired_server(bundle.peer, identity, CALLBACK_TEST_PORT);
        ASSERT_TRUE(pump_until(
            client, [&] { return client.is_connected(); }, PUMP_TIMEOUT_MS));
        // Group state the callback must already see reset.
        ASSERT_TRUE(server->send_app_json(group_update_playing_json()));
        ASSERT_TRUE(pump_until(
            client, [&] { return client.get_group_state().playback_state.has_value(); },
            PUMP_TIMEOUT_MS));

        client.stop();

        EXPECT_EQ(listener.clears, 1);
        EXPECT_FALSE(listener.started_during_clear);
        EXPECT_FALSE(listener.group_had_state_during_clear);
        EXPECT_FALSE(listener.start_result_during_clear);
        EXPECT_FALSE(client.is_started());
        EXPECT_TRUE(wait_until([&] { return server->closed(); }, PUMP_TIMEOUT_MS));
    }

    // The refused start() inside the callback left the client stopped; a real start() works.
    ASSERT_TRUE(bundle.start());
    Identity identity = Identity::generate().value();
    auto server = connect_paired_server(bundle.peer, identity, CALLBACK_TEST_PORT);
    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, PUMP_TIMEOUT_MS));
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

        Identity identity = Identity::generate().value();
        server = connect_paired_server(bundle.peer, identity, DESTRUCTOR_TEST_PORT);
        ASSERT_TRUE(pump_until(
            client, [&] { return client.is_connected(); }, PUMP_TIMEOUT_MS));
        // Client destroyed here while established.
    }

    EXPECT_TRUE(wait_until([&] { return server->closed(); }, PUMP_TIMEOUT_MS));
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
    client.add_player(make_player_config()).set_listener(&listener);

    VisualizerRoleConfig broken;
    broken.support.types = {VisualizerDataType::LOUDNESS};
    broken.support.buffer_capacity = 0;  // Below the ring's minimum: start() fails
    broken.support.rate_max = 30;
    client.add_visualizer(std::move(broken));

    EXPECT_FALSE(client.start());
    EXPECT_FALSE(client.is_started());
    EXPECT_FALSE(client.start());  // Still broken, still refused, still not stuck half-started

    VisualizerRoleConfig working;
    working.support.types = {VisualizerDataType::LOUDNESS};
    working.support.buffer_capacity = 4096;
    working.support.rate_max = 30;
    client.add_visualizer(std::move(working));

    ASSERT_TRUE(bundle.start());
    FakeEncryptedServerOptions options;
    options.answer_time = true;
    Identity identity = Identity::generate().value();
    auto server = connect_paired_server(bundle.peer, identity, ROLLBACK_TEST_PORT, options);
    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, PUMP_TIMEOUT_MS));
    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    ASSERT_TRUE(pump_until(
        client, [&] { return listener.stream_starts == 1; }, PUMP_TIMEOUT_MS));
    EXPECT_TRUE(stream_audio_until(client, *server, listener, 1));  // The rolled-back player plays again
    client.stop();
    EXPECT_EQ(listener.stream_ends, 1);
}

/// Counts loudness deliveries; they fire on the visualizer drain thread.
class CountingVisualizerListener : public VisualizerRoleListener {
public:
    void on_loudness(int64_t /*client_timestamp*/, uint16_t /*loudness*/) override {
        this->loudness.fetch_add(1);
    }

    std::atomic<size_t> loudness{0};
};

std::string stream_start_visualizer_json() {
    return R"({"type":"stream/start","payload":{"visualizer":{"types":["loudness"],"rate_max":30}}})";
}

VisualizerRoleConfig make_visualizer_config() {
    VisualizerRoleConfig config;
    config.support.types = {VisualizerDataType::LOUDNESS};
    config.support.buffer_capacity = 4096;
    config.support.rate_max = 30;
    return config;
}

// Waits for a fresh peer that answers time messages to be established and synced: the drain
// thread delivers nothing until the client is time synced.
bool pump_until_synced(SendspinClient& client) {
    return pump_until(
        client, [&] { return client.is_connected() && client.is_time_synced(); },
        PUMP_TIMEOUT_MS);
}

// Pumps until pred() holds, sending one loudness frame per iteration stamped `lead_us` ahead of
// the current time (the drain thread drops a frame whose display time is well past). A frame
// can be lost to the ring's documented wake race right after a stream/start (the drain thread
// may take the clear marker as a stray entry and then discard up to a marker that is gone),
// which production shrugs off because the next frame follows; so does this.
bool send_loudness_until(SendspinClient& client, FakeEncryptedServer& server, int64_t lead_us,
                         const std::function<bool()>& pred) {
    return pump_until(
        client,
        [&] {
            if (pred()) {
                return true;
            }
            server.send_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS, platform_time_us() + lead_us,
                               std::string("\x00\x10", 2));
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            return false;
        },
        PUMP_TIMEOUT_MS);
}

// stop() joins the visualizer drain thread and flushes the frames it had buffered, and start()
// clears the stop command, so a restart begins with an empty ring and a thread that delivers.
// The old frames are stamped far into the future, so the first session's thread parks on the
// first one with the rest buffered behind it when stop() runs; the ring is read directly after
// the stop because the restarted thread would silently drop leftovers before the new peer is
// time synced, and the new session's stream/start would discard them at its clear marker.
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
        Identity identity = Identity::generate().value();
        auto server = connect_paired_server(bundle.peer, identity, VISUALIZER_TEST_PORT, options);
        ASSERT_TRUE(pump_until_synced(client));
        ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
        // The thread holds the first frame while it waits for its display time; the ones behind
        // it are the ring content stop() must discard.
        auto& ring = client.visualizer()->impl_->drain_task->ring_buffer;
        ASSERT_TRUE(send_loudness_until(client, *server, OLD_FRAME_LEAD_US,
                                        [&] { return ring.items_waiting() >= 2; }));
        client.stop();
        EXPECT_TRUE(ring.is_empty());
        EXPECT_TRUE(wait_until([&] { return server->closed(); }, PUMP_TIMEOUT_MS));
    }
    EXPECT_EQ(listener.loudness.load(), 0U);

    ASSERT_TRUE(bundle.start());
    Identity identity = Identity::generate().value();
    auto server = connect_paired_server(bundle.peer, identity, VISUALIZER_TEST_PORT, options);
    ASSERT_TRUE(pump_until_synced(client));
    ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
    EXPECT_TRUE(send_loudness_until(client, *server, 0, [&] { return listener.loudness.load() >= 1; }));
    client.stop();
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

    Identity identity_a = Identity::generate().value();
    auto server = connect_paired_server(bundle.peer, identity_a, HIGH_PERF_TEST_PORT);
    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, PUMP_TIMEOUT_MS));
    // The default fake server never answers client/time, so the burst stays open and the hold
    // stays held until the connection is lost.
    ASSERT_TRUE(pump_until(
        client, [&] { return listener.requests == 1; }, PUMP_TIMEOUT_MS));
    EXPECT_EQ(listener.releases, 0);

    server.reset();  // Peer goes away mid-burst: drop_connection releases the hold
    ASSERT_TRUE(pump_until(
        client, [&] { return listener.releases == 1; }, PUMP_TIMEOUT_MS));
    EXPECT_FALSE(client.is_connected());

    Identity identity_b = Identity::generate().value();
    auto again = connect_paired_server(bundle.peer, identity_b, HIGH_PERF_TEST_PORT);
    ASSERT_TRUE(pump_until(
        client, [&] { return client.is_connected() && listener.requests == 2; },
        PUMP_TIMEOUT_MS));
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

        Identity identity = Identity::generate().value();
        server = connect_paired_server(bundle.peer, identity, DESTRUCTOR_HIGH_PERF_TEST_PORT);
        ASSERT_TRUE(pump_until(
            client, [&] { return client.is_connected() && listener.requests == 1; },
            PUMP_TIMEOUT_MS));
        EXPECT_EQ(listener.releases, 0);
        // Client destroyed here mid-burst, with the hold open.
    }
    EXPECT_EQ(listener.releases, 1);
}

}  // namespace
