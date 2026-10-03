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

#include "color_role_impl.h"       // The applied palette and its slot; private, see CMakeLists
#include "connection.h"  // StubConnection stands in for a real connection
#include "connection_manager.h"  // GoodbyeWait, GOODBYE_FLUSH_TIMEOUT_MS
#include "controller_role_impl.h"  // The applied controller state and its slot
#include "crypto/constants.h"
#include "crypto/keys.h"
#include "fake_persistence.h"
#include "inbound_ring.h"
#include "lifecycle_test_fixtures.h"
#include "metadata_role_impl.h"  // The applied metadata state and its slot
#include "platform/time.h"
#include "player_role_impl.h"  // Stream start and the sync task; private access, see tests/CMakeLists.txt
#include "protocol_messages.h"  // SENDSPIN_BINARY_VISUALIZER_LOUDNESS
#include "protocol_task.h"
#include "server_connection.h"  // A delivered connection, handed over without a socket
#include "sendspin/client.h"
#include "sendspin/color_role.h"
#include "sendspin/config.h"
#include "sendspin/controller_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"
#include "sendspin/visualizer_role.h"
#include "sync_task.h"
#include "time_burst.h"  // ms_until_due(), staged directly
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
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
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
constexpr uint16_t STOP_ACCEPT_AFTER_JOIN_TEST_PORT = 19071;
constexpr uint16_t STREAM_FILTER_STOPPED_TASK_TEST_PORT = 19072;
constexpr uint16_t STREAM_FILTER_OFFSET_TEST_PORT = 19073;
constexpr uint16_t TIME_FILTER_SLOT_TEST_PORT = 19074;
constexpr uint16_t ADMISSION_CLOSED_TEST_PORT = 19075;
constexpr uint16_t ADMISSION_OPEN_TEST_PORT = 19076;
constexpr uint16_t STREAM_FILTER_MIDSTREAM_TEST_PORT = 19077;
constexpr uint16_t VISUALIZER_SPECTRUM_TEST_PORT = 19078;
constexpr uint16_t VISUALIZER_STALE_TEST_PORT = 19084;
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

/// A loopback listener that never accepts: a connection to it completes the TCP handshake in the
/// backlog and then hears nothing, so an outbound WebSocket attempt neither upgrades nor closes.
class SilentListener {
public:
    SilentListener() {
        this->fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        socklen_t len = sizeof(addr);
        if (this->fd_ >= 0 &&
            ::bind(this->fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
            ::listen(this->fd_, 4) == 0 &&
            ::getsockname(this->fd_, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
            this->port_ = ntohs(addr.sin_port);
        }
    }
    ~SilentListener() {
        this->close();
    }

    /// Closes the listener, resetting the connections waiting in its backlog. IXWebSocket clears
    /// its cancellation flag when it enters the handshake, so a close() that lands before that
    /// point is forgotten and the connection's destructor (ix::WebSocket::stop()) waits for the
    /// handshake to time out (SendspinClientConnection::HANDSHAKE_TIMEOUT_SECS). The test resets
    /// the attempt first, so stopping the client does not wait out that bound.
    void close() {
        if (this->fd_ >= 0) {
            ::close(this->fd_);
            this->fd_ = -1;
        }
    }
    SilentListener(const SilentListener&) = delete;
    SilentListener& operator=(const SilentListener&) = delete;

    /// The listening port, or 0 when the socket could not be set up.
    uint16_t port() const {
        return this->port_;
    }

private:
    int fd_{-1};
    uint16_t port_{0};
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
// player comes up and the visualizer (a buffer too small to hold one frame) refuses, so start()
// reports failure and the client stays stopped. Replacing the broken role and
// starting again succeeds, which needs the first attempt to have joined the player's sync task:
// SyncTask::start() refuses a thread that is still running, so a rollback that skipped the join
// fails the retry too.
TEST(ClientLifecycle, FailedRoleStartRollsBackAndRetryStartsClean) {
    CountingPlayerListener listener;
    PairedClientBundle bundle(make_config(ROLLBACK_TEST_PORT));
    SendspinClient& client = bundle.client();
    client.add_player(make_pcm_player_config()).set_listener(&listener);

    VisualizerRoleConfig broken;
    broken.stream.types = {VisualizerDataType::LOUDNESS};
    broken.support.buffer_capacity = 0;  // Below one stored frame: start() fails
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

/// Whether at least two items are linked on `list`, read under its lock: the drain thread holds
/// the first frame it took, so these are frames waiting behind it.
bool two_or_more_linked(const InboundItemList& list) {
    std::lock_guard<std::mutex> lock(list.mutex_);
    return list.head_ != INBOUND_LIST_END && list.head_ != list.tail_;
}

// stop() joins the visualizer drain thread and flushes the frames it had buffered, and start()
// clears the stop command, so a restart begins with an empty drain list and a thread that
// delivers. The old frames are stamped far into the future, so the first session's thread parks
// on the first one with the rest buffered behind it when stop() runs.
//
// The list is read directly because nothing a caller or peer observes distinguishes a drained
// list from an abandoned one: the restarted thread drops leftovers before the new peer is time
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
        // it are the list content stop() must return to the ring.
        auto& items = client.visualizer()->impl_->drain_task->items;
        send_loudness_until(client, *server, OLD_FRAME_LEAD_US,
                            [&] { return two_or_more_linked(items); });
        client.stop();
        EXPECT_TRUE(items.is_empty());
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
        auto& items = this->client().visualizer()->impl_->drain_task->items;
        pump_until(this->client(), [&] { return items.is_empty(); });
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
// Stand-in connections
// ============================================================================

/// Connection stand-in with every transport override inert: nothing is sent anywhere, a send
/// completes inline and reports success, and the connection always reads as connected. Tests that
/// install one in the manager's slot derive from it and override only the one call they are about
/// to observe.
class StubConnection : public SendspinConnection {
public:
    void start() override {}
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
        // The test thread plays the protocol task, which owns the nursery.
        client.protocol_task_->stop();
        auto conn = std::make_shared<HelloCountingConnection>(row.send_result);
        conn->noise_handshake_complete_ = true;
        conn->set_provisional_time_us(platform_time_us());
        manager.nursery_.push_back(NurseryEntry{.conn = conn, .client_init_sent = true});

        for (int tick = 0; tick < NurseryEntry::MAX_HELLO_ATTEMPTS + 3; ++tick) {
            (void) manager.scan_nursery(platform_time_us());
            for (auto& entry : manager.nursery_) {
                entry.hello_due_us = 0;
            }
        }
        EXPECT_EQ(conn->hellos, row.expected_hellos);

        client.stop();
    }
}

// ============================================================================
// Accepts queued at stop()
// ============================================================================

/// Commands waiting in the protocol task's queue.
size_t queued_commands(ProtocolTask& task) {
    std::lock_guard<std::mutex> lock(task.command_mutex_);
    return task.command_count_;
}

// A peer the server delivers while stop() is under way waits in the command queue as an accept,
// and stop() refuses it with a client/goodbye of reason shutdown instead of a nursery slot,
// whether the protocol task's final tick takes it or stop() itself takes it once the task is
// joined. The test thread plays the protocol task, so the accept provably sits in the queue when
// admission closes. The open row is the control: the same queued accept is admitted and owed no
// goodbye. The nursery-full rejection is covered by
// ConnectionLifecycle.FullNurseryOfLivePeersRejectsNewcomer.
TEST(ClientLifecycle, StopRefusesAQueuedAcceptWithAShutdownGoodbye) {
    enum class Taker : uint8_t { FINAL_TICK, AFTER_JOIN, OPEN_TICK };
    struct AcceptRow {
        const char* name;
        Taker taker;
        uint16_t port;
    };
    const AcceptRow rows[] = {
        {"the final tick takes it", Taker::FINAL_TICK, ADMISSION_CLOSED_TEST_PORT},
        {"stop() takes it after the join", Taker::AFTER_JOIN, STOP_ACCEPT_AFTER_JOIN_TEST_PORT},
        {"Control: admission open", Taker::OPEN_TICK, ADMISSION_OPEN_TEST_PORT},
    };

    for (const AcceptRow& row : rows) {
        SCOPED_TRACE(row.name);
        PairedClientBundle bundle(make_config(row.port));
        SendspinClient& client = bundle.client();
        ASSERT_TRUE(bundle.start());
        client.protocol_task_->stop();

        auto peer = connect_paired_server(bundle.peer, row.port);
        wait_until([&] { return queued_commands(*client.protocol_task_) == 1; });

        switch (row.taker) {
            case Taker::FINAL_TICK:
                // stop()'s order: admission closes, then the task's final tick runs.
                client.connection_manager_->close_admission();
                (void) client.protocol_tick();
                break;
            case Taker::AFTER_JOIN:
                client.stop();
                break;
            case Taker::OPEN_TICK:
                (void) client.protocol_tick();
                EXPECT_EQ(client.connection_manager_->nursery_.size(), 1U)
                    << "the queued accept never reached the nursery";
                EXPECT_TRUE(never_within([&] { return peer->goodbye_reason().has_value(); }, 200))
                    << "an admitted peer was sent a goodbye";
                break;
        }
        if (row.taker != Taker::OPEN_TICK) {
            wait_until([&] { return peer->goodbye_reason().has_value(); });
            EXPECT_EQ(peer->goodbye_reason().value_or(""), "shutdown")
                << "a newcomer refused at stop() must be told why";
            EXPECT_TRUE(client.connection_manager_->nursery_.empty())
                << "a refused newcomer took a nursery slot";
        }

        client.stop();
    }
}

/// Fills the protocol task's accept slots with accepts that carry no connection, so the next
/// delivery finds them all taken. The test thread plays the protocol task, so none is taken.
void fill_accept_slots(ProtocolTask& task) {
    for (;;) {
        ProtocolCommand command;
        command.type = ProtocolCommandType::ACCEPT_CONNECTION;
        if (!task.push_command(std::move(command))) {
            return;
        }
    }
}

// A refused delivery leaves the connection with the transport that delivered it:
// on_new_connection() reports the refusal and keeps no reference, so the delivering thread's own
// reference is the last one and the transport releases the connection once the delivery returns
// (SendspinWsServer::NewConnectionCallback), never inside it. A delivery is refused when every
// accept slot is taken, and once stop() has joined the protocol task and closed accepts
// (ProtocolTask::close_accepts()), when no refusal pass would take an accept any more. The accepted row is the control: the queued
// accept holds a reference for the protocol task.
TEST(ClientLifecycle, ARefusedDeliveryLeavesTheConnectionWithItsTransport) {
    struct Row {
        const char* name;
        bool fill_queue;
        bool refusing;
        bool expected_accepted;
        long expected_use_count;
    };
    const Row rows[] = {
        {"Control: room in the queue", false, false, true, 2},
        {"every accept slot taken", true, false, false, 1},
        {"stop() has joined the protocol task", false, true, false, 1},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        if (row.fill_queue) {
            fill_accept_slots(*client.protocol_task_);
        }
        if (row.refusing) {
            client.protocol_task_->close_accepts();
        }

        auto conn = std::make_shared<SendspinServerConnection>(nullptr, 1);
        bool accepted = false;
        // The delivering thread stands in for the transport's.
        std::thread transport(
            [&] { accepted = client.connection_manager_->on_new_connection(conn); });
        transport.join();

        EXPECT_EQ(accepted, row.expected_accepted);
        EXPECT_EQ(conn.use_count(), row.expected_use_count)
            << "who holds the delivered connection after the delivery returns";
        EXPECT_EQ(conn->inbound_gate().is_detached(), !row.expected_accepted)
            << "a refused connection must stop routing what the peer sends";

        client.stop();
    }
}

// A command left in the queue after a stop() (a request that raced it on another thread) belongs
// to the run that ended: the next start() begins with an empty queue, so the stale connect_to()
// opens nothing. The command is pushed straight onto the stopped client's queue, the state such a
// race leaves, since the public entry points refuse while stopped. The Control row pushes the same
// command after start() and sees it acted on.
TEST(ClientLifecycle, AStaleCommandIsNotCarriedIntoTheNextRun) {
    for (const bool stale : {true, false}) {
        SCOPED_TRACE(stale ? "pushed while stopped" : "Control: pushed while running");
        SilentListener silent;
        ASSERT_NE(silent.port(), 0);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        client.stop();

        ProtocolCommand command;
        command.type = ProtocolCommandType::CONNECT_TO;
        // The attempt waits in the nursery: the listener never answers or closes.
        command.text = "ws://127.0.0.1:" + std::to_string(silent.port()) + "/sendspin";
        if (stale) {
            ASSERT_TRUE(client.protocol_task_->push_command(std::move(command)));
        }
        ASSERT_TRUE(client.start());
        // The test thread plays the protocol task from here, so the nursery is read where it is
        // written.
        client.protocol_task_->stop();
        if (!stale) {
            ASSERT_TRUE(client.protocol_task_->push_command(std::move(command)));
        }
        (void) client.protocol_tick();
        EXPECT_EQ(client.connection_manager_->nursery_.size(), stale ? 0U : 1U);
        silent.close();
        client.stop();
    }
}

// send_text() reports a request the protocol task will never see: once the consumer burst of the
// command queue is taken, the next request is refused with false rather than dropped silently.
// The test thread plays the protocol task, so nothing drains the queue between the requests.
TEST(ClientLifecycle, SendTextIsRefusedWhenTheCommandQueueIsFull) {
    TestNetworkProvider network;
    SendspinClient client(make_config(0));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start());
    client.protocol_task_->stop();

    const std::string command = R"({"type":"client/command","payload":{}})";
    for (size_t i = 0; i < ProtocolTask::CONSUMER_COMMAND_BURST; ++i) {
        EXPECT_TRUE(client.send_text(command, "controller")) << "Control: request " << i;
    }
    EXPECT_FALSE(client.send_text(command, "controller"))
        << "a request past the consumer burst must be refused";
    // Control: once the task drains the queue, requests are taken again.
    (void) client.protocol_tick();
    EXPECT_TRUE(client.send_text(command, "controller")) << "the drained queue takes requests";
    // A family that names no role is refused on its own, queue or not.
    EXPECT_FALSE(client.send_text(command, "no-such-role"));

    client.stop();
    EXPECT_FALSE(client.send_text(command, "controller")) << "a stopped client refuses";
}

// ============================================================================
// The protocol task's next deadline
// ============================================================================

// SendspinTimeBurst::ms_until_due() is the burst's part of the protocol task's wait: the end of
// the interval between bursts, the timeout of the message in flight, the backoff after a refused
// send, or 0 when loop() has work now. The burst's state is staged directly; loop() moves it
// through these states over real time.
TEST(NextDeadline, TheTimeBurstReportsItsNextStep) {
    struct Row {
        const char* name;
        uint8_t burst_index;
        int64_t last_complete_ms;
        int64_t pending;
        int64_t sent_ms;
        int64_t retry_after_ms;
        bool completed;
        uint32_t expected_ms;
    };
    constexpr int64_t NOW_MS = 1'000'000;
    constexpr uint8_t SIZE = 8;
    constexpr int64_t INTERVAL_MS = 500;
    constexpr int64_t TIMEOUT_MS = 100;
    const Row rows[] = {
        {"between bursts", SIZE, NOW_MS - 200, 0, 0, 0, false, 300},
        {"Control: the interval has elapsed", SIZE, NOW_MS - INTERVAL_MS, 0, 0, 0, false, 0},
        {"a message in flight times out strictly after the timeout", 3, 0, 42, NOW_MS - 50, 0, false,
         51},
        {"a refused send backs off", 3, 0, 0, 0, NOW_MS + 70, false, 70},
        {"Control: ready to send the next message", 3, 0, 0, 0, 0, false, 0},
        {"a completed burst is reported at once", SIZE, NOW_MS, 0, 0, 0, true, 0},
        {"a far interval clamps short of NO_DEADLINE", SIZE, NOW_MS + (1LL << 40), 0, 0, 0, false,
         ProtocolTask::NO_DEADLINE - 1},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinTimeBurst burst;
        burst.configure(SIZE, INTERVAL_MS, TIMEOUT_MS);
        burst.burst_index_ = row.burst_index;
        burst.last_burst_complete_time_ = row.last_complete_ms;
        burst.pending_embedded_ = row.pending;
        burst.current_message_sent_time_ = row.sent_ms;
        burst.send_retry_after_ms_ = row.retry_after_ms;
        burst.pending_burst_completed_ = row.completed;
        EXPECT_EQ(burst.ms_until_due(NOW_MS), row.expected_ms);
    }
}

/// Network provider that never reports ready, so the WebSocket server stays down.
class OfflineNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override {
        return false;
    }
};

// ConnectionManager::tick() returns the milliseconds until the earliest of its timers, one row per
// timer, so the protocol task sleeps exactly until the next one is due; with none armed it
// returns NO_DEADLINE and the task waits for a wake alone. The Control rows hold a connection, or
// a stopped server, whose timer is not armed. The test thread plays the protocol task and stages
// each timer directly against a fixed clock.
TEST(NextDeadline, TheTickReportsTheEarliestTimer) {
    constexpr int64_t NOW_US = 3LL << 32;
    constexpr int64_t LIVENESS_US = 30'000'000;
    enum class Stage : uint8_t {
        NOTHING,
        ADMITTED_UNARMED,
        LIVENESS,
        REPROVE,
        ATTEMPT,
        NURSERY,
        WINDOW,
        WINDOW_AND_LIVENESS,
        NETWORK_POLL,
        SERVER_RETRY,
    };
    struct Row {
        const char* name;
        Stage stage;
        uint32_t expected_ms;
    };
    const Row rows[] = {
        {"Control: nothing armed", Stage::NOTHING, ProtocolTask::NO_DEADLINE},
        {"Control: an admitted connection with no timer armed", Stage::ADMITTED_UNARMED,
         ProtocolTask::NO_DEADLINE},
        {"the liveness timeout, a second of silence in", Stage::LIVENESS,
         static_cast<uint32_t>((LIVENESS_US - 1'000'000) / 1000)},
        {"the re-prove deadline", Stage::REPROVE, static_cast<uint32_t>(REPROVE_TIMEOUT_US / 1000)},
        {"the pairing attempt deadline", Stage::ATTEMPT, 2000},
        {"the nursery establish deadline", Stage::NURSERY,
         static_cast<uint32_t>(NURSERY_ESTABLISH_TIMEOUT_US / 1000)},
        {"the pairing window", Stage::WINDOW, 5000},
        {"the earliest of two", Stage::WINDOW_AND_LIVENESS, 5000},
        {"the network poll while the server is down", Stage::NETWORK_POLL,
         NETWORK_POLL_INTERVAL_MS},
        {"the server start retry", Stage::SERVER_RETRY, 3000},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        TestNetworkProvider online;
        OfflineNetworkProvider offline;
        SendspinClient client(make_config(0));
        const bool server_down = row.stage == Stage::NETWORK_POLL || row.stage == Stage::SERVER_RETRY;
        if (server_down) {
            client.set_network_provider(&offline);
        } else {
            client.set_network_provider(&online);
        }
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        ConnectionManager& manager = *client.connection_manager_;
        manager.liveness_timeout_us_ = 0;

        auto conn = std::make_shared<StubConnection>();
        conn->last_receive_time_us_.store(static_cast<uint32_t>(NOW_US));
        switch (row.stage) {
            case Stage::NOTHING:
            case Stage::NETWORK_POLL:
                break;
            case Stage::ADMITTED_UNARMED:
                manager.install_admitted(conn, 0);
                break;
            case Stage::LIVENESS:
                manager.liveness_timeout_us_ = LIVENESS_US;
                conn->last_receive_time_us_.store(static_cast<uint32_t>(NOW_US - 1'000'000));
                manager.install_admitted(conn, 0);
                break;
            case Stage::REPROVE:
                conn->set_provisional_time_us(NOW_US);
                manager.install_admitted(conn, 0);
                break;
            case Stage::ATTEMPT:
                conn->first_activate_received_ = true;
                conn->pairing_session().attempt_deadline_us = NOW_US + 2'000'000;
                manager.install_admitted(conn, 0);
                break;
            case Stage::NURSERY:
                conn->set_provisional_time_us(NOW_US);
                manager.nursery_.push_back(NurseryEntry{.conn = conn});
                break;
            case Stage::WINDOW:
                manager.pairing_window_open_until_us_ = NOW_US + 5'000'000;
                break;
            case Stage::WINDOW_AND_LIVENESS:
                manager.liveness_timeout_us_ = LIVENESS_US;
                manager.install_admitted(conn, 0);
                manager.pairing_window_open_until_us_ = NOW_US + 5'000'000;
                break;
            case Stage::SERVER_RETRY:
                manager.ws_server_start_retry_time_us_ = NOW_US + 3'000'000;
                break;
        }

        EXPECT_EQ(manager.tick(NOW_US), row.expected_ms);
        EXPECT_FALSE(conn->inbound_gate().is_detached()) << "nothing was due, yet it was dropped";
        manager.pairing_window_open_until_us_ = 0;
        client.stop();
    }
}

// ============================================================================
// The main-loop teardown half
// ============================================================================

/// Records the controller, metadata and color callbacks in the order they fire: "clear", or
/// "state <n>" for a state carrying n (the controller's volume, the metadata year, the color's
/// primary red). Main loop only, as every one of these callbacks is.
class StateRoleLog : public ControllerRoleListener,
                     public MetadataRoleListener,
                     public ColorRoleListener {
public:
    void on_controller_state(const ServerStateControllerObject& state) override {
        this->calls.push_back("state " + std::to_string(state.volume));
    }
    void on_controller_state_clear() override {
        this->calls.push_back("clear");
    }
    void on_metadata(const ServerMetadataStateObject& metadata) override {
        this->calls.push_back("state " + std::to_string(metadata.year.value_or(0)));
    }
    void on_metadata_clear() override {
        this->calls.push_back("clear");
    }
    void on_color(const ServerColorStateObject& color) override {
        this->calls.push_back("state " + std::to_string(color.primary.value_or(RgbColor{})[0]));
    }
    void on_color_clear() override {
        this->calls.push_back("clear");
    }

    std::vector<std::string> calls;
};

/// One state role, reached the way the protocol task and the main loop reach it. `admit` is the
/// handler a server/state reaches on the protocol task, `restore` writes the role's slot with an
/// explicit stamp (the payload a drain holds when it took the slot on the far side of a
/// teardown), `drain` is the role's step of drain_inbox(), and `applied` the state the main loop
/// holds (0 when cleared). Each value is a state's identifying number.
struct StateRoleAccess {
    const char* name;
    void (*admit)(SendspinClient&, uint8_t value, uint32_t generation);
    void (*restore)(SendspinClient&, uint8_t value, uint32_t generation);
    void (*teardown)(SendspinClient&);
    void (*drain)(SendspinClient&);
    uint32_t (*generation)(SendspinClient&);
    uint8_t (*applied)(SendspinClient&);
};

ServerStateControllerObject controller_state_with(uint8_t value) {
    ServerStateControllerObject state;
    state.volume = value;
    return state;
}

ServerMetadataStateObject metadata_state_with(uint8_t value) {
    ServerMetadataStateObject state;  // Timestamp 0: due at once
    state.year = value;
    return state;
}

ServerColorStateObject color_state_with(uint8_t value) {
    ServerColorStateObject state;  // Timestamp 0: due at once
    state.primary = RgbColor{value, 0, 0};
    return state;
}

const StateRoleAccess STATE_ROLES[] = {
    {"controller",
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.controller_->impl_->handle_server_state(controller_state_with(v), g);
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.controller_->impl_->event_state->slot.write(controller_state_with(v), g);
     },
     [](SendspinClient& c) { c.controller_->impl_->cleanup(); },
     [](SendspinClient& c) { c.controller_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.controller_->impl_->cleanup_generation.load(); },
     [](SendspinClient& c) { return c.controller_->impl_->controller_state.volume; }},
    {"metadata",
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.metadata_->impl_->handle_server_state(metadata_state_with(v), g);
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.metadata_->impl_->event_state->slot.write(
             PendingMetadataStates{.oldest = metadata_state_with(v)}, g);
     },
     [](SendspinClient& c) { c.metadata_->impl_->cleanup(); },
     [](SendspinClient& c) { c.metadata_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.metadata_->impl_->cleanup_generation.load(); },
     [](SendspinClient& c) {
         return static_cast<uint8_t>(c.metadata_->impl_->metadata.year.value_or(0));
     }},
    {"color",
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.color_->impl_->handle_server_state(color_state_with(v), g);
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.color_->impl_->event_state->slot.write(
             PendingColorStates{.oldest = color_state_with(v)}, g);
     },
     [](SendspinClient& c) { c.color_->impl_->cleanup(); },
     [](SendspinClient& c) { c.color_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.color_->impl_->cleanup_generation.load(); },
     [](SendspinClient& c) { return c.color_->impl_->color.primary.value_or(RgbColor{})[0]; }},
};

/// A started client with the three state roles, all reporting to `log`, whose protocol task the
/// test thread plays: role handlers and teardowns run on the test thread, between the loop()
/// calls the test makes.
struct StateRoleClient {
    explicit StateRoleClient(StateRoleLog& log) : client(make_config(0)) {
        this->client.set_network_provider(&this->network);
        this->client.add_controller().set_listener(&log);
        this->client.add_metadata().set_listener(&log);
        this->client.add_color().set_listener(&log);
        EXPECT_TRUE(this->client.start());
        this->client.protocol_task_->stop();
    }

    TestNetworkProvider network;
    SendspinClient client;
};

// The teardown reorder guarantee, per state role: the connection that owned a role is dropped (the
// role's cleanup() on the protocol task) and the next one delivers its state before the main loop
// runs. The next drain delivers the role's clear before the new state, and the new state survives:
// it is what the role holds afterwards. Two rows stage the interleavings a drain meets across the
// two threads: the new state taken by a drain whose ring pass ran before the teardown queued its
// CLEARED event (the slot written between the generation bump and the drain), and a payload of the
// torn-down connection that a drain took on the far side of the teardown, which must never be
// applied after the clear. Both are staged by calling the role's drain step, and by writing the
// slot with the old stamp, through the private access the CMakeLists entry describes: no public
// call interleaves the two threads on demand, and the order of the callbacks is the outcome. The
// last row fills the event ring so the teardown's CLEARED is dropped: the clear still fires on the
// next loop(), from the catch-up that heads every drain.
TEST(TeardownReorder, AClearAlwaysPrecedesTheNextConnectionsState) {
    enum class Stage : uint8_t {
        CONTROL,
        ONE_LOOP,
        TAKEN_BEFORE_ITS_CLEARED,
        STALE_ACROSS,
        CLEARED_DROPPED
    };
    struct Row {
        const char* name;
        Stage stage;
        std::vector<std::string> expected_calls;
        uint8_t expected_applied;
    };
    const Row rows[] = {
        {"Control: no teardown, the next state applies", Stage::CONTROL, {"state 22"}, 22},
        {"drop A, admit B, B's state, one loop()", Stage::ONE_LOOP, {"clear", "state 22"}, 22},
        {"B's state taken before its CLEARED is drained", Stage::TAKEN_BEFORE_ITS_CLEARED,
         {"clear", "state 22"},
         22},
        {"A's state taken across the teardown", Stage::STALE_ACROSS, {"clear"}, 0},
        {"the teardown's CLEARED dropped on a full event ring", Stage::CLEARED_DROPPED, {"clear"},
         0},
    };
    for (const StateRoleAccess& role : STATE_ROLES) {
        for (const Row& row : rows) {
            SCOPED_TRACE(std::string(role.name) + ": " + row.name);
            StateRoleLog log;
            StateRoleClient harness(log);
            SendspinClient& client = harness.client;

            // Connection A's state, applied.
            role.admit(client, 11, role.generation(client));
            client.loop();
            ASSERT_EQ(log.calls, std::vector<std::string>{"state 11"});
            log.calls.clear();

            const uint32_t a_generation = role.generation(client);
            switch (row.stage) {
                case Stage::CONTROL:
                    role.admit(client, 22, role.generation(client));
                    break;
                case Stage::ONE_LOOP:
                    role.teardown(client);
                    role.admit(client, 22, role.generation(client));
                    break;
                case Stage::TAKEN_BEFORE_ITS_CLEARED:
                    role.teardown(client);
                    role.admit(client, 22, role.generation(client));
                    role.drain(client);
                    break;
                case Stage::STALE_ACROSS:
                    role.teardown(client);
                    role.restore(client, 33, a_generation);
                    role.drain(client);
                    break;
                case Stage::CLEARED_DROPPED: {
                    // Fill the ring with events no role here acts on (no visualizer is added), so
                    // the push in cleanup() is dropped with its warning.
                    InboxEvent filler{};
                    filler.type = InboxEventType::VISUALIZER_STREAM;
                    // The client's Inbox, reached through the controller it is attached to.
                    while (client.controller_->impl_->inbox->push_event(filler)) {
                    }
                    role.teardown(client);
                    break;
                }
            }
            client.loop();

            EXPECT_EQ(log.calls, row.expected_calls);
            EXPECT_EQ(role.applied(client), row.expected_applied);
            client.stop();
        }
    }
}

/// Calls stop(), and then start() when `restart` is set, from inside the first controller state
/// callback; records every state-role callback in `log`.
class StopFromCallbackListener : public StateRoleLog {
public:
    StopFromCallbackListener(SendspinClient*& client, bool reenter, bool restart)
        : client_(client), reenter_(reenter), restart_(restart) {}

    void on_controller_state(const ServerStateControllerObject& state) override {
        StateRoleLog::on_controller_state(state);
        if (this->reenter_ && !this->reentered_) {
            this->reentered_ = true;
            this->client_->stop();
            if (this->restart_) {
                this->restart_result = this->client_->start();
            }
        }
    }

    bool restart_result{false};

private:
    SendspinClient*& client_;
    bool reenter_;
    bool restart_;
    bool reentered_{false};
};

// A listener may call stop(), and start() after it, from inside a callback a loop() drain fires.
// stop() tears every role down and delivers each clear exactly once from its own drain; the drain
// that fired the callback then abandons the rest of its work, so the metadata state queued beside
// the controller's is never delivered, after its clear or at all. Control: without the re-entry
// both states are delivered.
TEST(ClientLifecycle, StopFromInsideADrainCallbackIsSafe) {
    struct Row {
        const char* name;
        bool reenter;
        bool restart;
        std::vector<std::string> expected_calls;
        bool expected_started;
    };
    const Row rows[] = {
        {"Control: no re-entry", false, false, {"state 11", "state 5"}, true},
        {"stop()", true, false, {"state 11", "clear", "clear"}, false},
        {"stop() then start()", true, true, {"state 11", "clear", "clear"}, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinClient* client_ref = nullptr;
        StopFromCallbackListener log(client_ref, row.reenter, row.restart);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client_ref = &client;
        client.set_network_provider(&network);
        client.add_controller().set_listener(&log);
        client.add_metadata().set_listener(&log);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();

        client.controller_->impl_->handle_server_state(
            controller_state_with(11), client.controller_->impl_->cleanup_generation.load());
        client.metadata_->impl_->handle_server_state(
            metadata_state_with(5), client.metadata_->impl_->cleanup_generation.load());
        client.loop();

        EXPECT_EQ(log.calls, row.expected_calls);
        EXPECT_EQ(client.is_started(), row.expected_started);
        if (row.restart) {
            EXPECT_TRUE(log.restart_result) << "start() from inside the callback was refused";
        }
        client.loop();  // A later loop() delivers nothing the re-entry abandoned.
        EXPECT_EQ(log.calls, row.expected_calls);
        client.stop();
    }
}

/// Counts the pairing prompts and their dismissals. Main loop only.
class PairingPromptLog : public SendspinClientListener {
public:
    void on_display_pairing_code(const std::string& /*code*/,
                                 SendspinPairingCodeFormat /*format*/) override {
        ++this->displays;
    }
    void on_clear_pairing_code() override {
        ++this->clears;
    }
    void on_open_pairing_window() override {
        ++this->opens;
    }
    void on_close_pairing_window() override {
        ++this->closes;
    }

    int displays{0};
    int clears{0};
    int opens{0};
    int closes{0};
};

// A full teardown drops the pairing notes no drain has delivered, but not a dismissal whose prompt
// an earlier drain already showed: one connection's drop queues it, and the next connection's
// drop (or stop()) before the main loop runs must not wipe it, or the code or window stays on the
// operator's screen. A prompt still pending goes with its dismissal, since the operator never saw
// it, and a dismissal the teardown's own path queues again beside a surviving one is delivered
// once. The notes are queued and the teardown run directly, as the protocol task's handlers do,
// because no public call stages two drops inside one main-loop tick.
TEST(ClientLifecycle, AFullTeardownKeepsTheDismissalsOfShownPrompts) {
    enum class Pending : uint8_t { DISMISSALS, PROMPTS_AND_DISMISSALS };
    struct Row {
        const char* name;
        Pending pending;
        bool teardown;
        bool requeue;
        int expected_prompts;
        int expected_dismissals;
    };
    const Row rows[] = {
        {"Control: no teardown", Pending::DISMISSALS, false, false, 0, 1},
        {"dismissals of shown prompts survive the teardown", Pending::DISMISSALS, true, false, 0,
         1},
        {"a dismissal queued again after the teardown is delivered once", Pending::DISMISSALS,
         true, true, 0, 1},
        {"a prompt and its dismissal both pending are dropped together",
         Pending::PROMPTS_AND_DISMISSALS, true, false, 0, 0},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        PairingPromptLog log;
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        client.set_listener(&log);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();

        if (row.pending == Pending::PROMPTS_AND_DISMISSALS) {
            client.note_display_pairing_code("123456", SendspinPairingCodeFormat::DIGITS);
            client.note_open_pairing_window();
        }
        client.note_clear_pairing_code();
        client.note_close_pairing_window();
        if (row.teardown) {
            client.cleanup_connection_state(ALL_ROLES_MASK);
        }
        if (row.requeue) {
            client.note_clear_pairing_code();
            client.note_close_pairing_window();
        }
        client.loop();

        EXPECT_EQ(log.displays, row.expected_prompts);
        EXPECT_EQ(log.opens, row.expected_prompts);
        EXPECT_EQ(log.clears, row.expected_dismissals);
        EXPECT_EQ(log.closes, row.expected_dismissals);
        client.stop();
    }
}

// ============================================================================
// The high-performance grant
// ============================================================================

/// Records the high-performance edges the listener hears, in order. Main loop only.
class HighPerformanceLog : public SendspinClientListener {
public:
    void on_request_high_performance() override {
        this->edges.emplace_back("request");
    }
    void on_release_high_performance() override {
        this->edges.emplace_back("release");
    }

    std::vector<std::string> edges;
};

/// An admitted, operational stand-in for a connection whose time burst runs.
class OperationalStubConnection : public StubConnection {
public:
    OperationalStubConnection() {
        this->set_client_hello_sent(true);
        this->set_server_hello_received(true);
        this->first_activate_received_ = true;
    }
};

/// How many client/time frames the burst has written: send_time_message() tags the frame in
/// flight before handing it to the transport, and nothing in these tests answers or cancels it.
/// The stand-in has no Noise session, so the frame goes no further than that; the tag is the one
/// trace a written frame leaves, and the burst retries a refused frame only after
/// SEND_RETRY_DELAY_MS, past the end of each row.
int time_frames_written(const SendspinConnection& conn) {
    return conn.time_frame_tag_.load() != 0 ? 1 : 0;
}

// A time burst requests the high-performance hold when it comes due and sends its first
// time frame only once the main loop has granted the request (called the listener); its release
// waits for nothing, and an acquire and a release queued inside one stalled main-loop tick still
// reach the listener as a request followed by its release. The test thread plays the protocol
// task (run_time_sync(), on a stand-in connection in the admitted slot) and the main loop
// (loop()), so a frame that must not be sent yet is proven unsent by the tick having returned
// without writing it, not by a wait; the stand-in's frame tag is read for the reason given at
// time_frames_written(). The Control row's burst is not due, so nothing is requested.
TEST(HighPerformanceGrant, TheFirstTimeFrameWaitsForTheMainLoop) {
    enum class Stage : uint8_t { NOT_DUE, WAITS_FOR_GRANT, RELEASE_NOT_GATED, STALLED_TICK };
    struct Row {
        const char* name;
        Stage stage;
        int expected_frames;
        std::vector<std::string> expected_edges;
    };
    const Row rows[] = {
        {"Control: a burst that is not due requests nothing", Stage::NOT_DUE, 0, {}},
        {"the first frame waits for the grant", Stage::WAITS_FOR_GRANT, 1, {"request"}},
        {"the release at the burst's end is not gated", Stage::RELEASE_NOT_GATED, 1,
         {"request", "release"}},
        {"an acquire and a release inside one stalled tick", Stage::STALLED_TICK, 0,
         {"request", "release"}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        HighPerformanceLog log;
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        client.set_listener(&log);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        ConnectionManager& manager = *client.connection_manager_;
        auto conn = std::make_shared<OperationalStubConnection>();
        manager.install_admitted(conn, 0);

        switch (row.stage) {
            case Stage::NOT_DUE:
                conn->time_burst().last_burst_complete_time_ = platform_time_us() / 1000;
                (void) manager.run_time_sync();
                client.loop();
                break;
            case Stage::WAITS_FOR_GRANT:
                (void) manager.run_time_sync();
                (void) manager.run_time_sync();
                EXPECT_EQ(time_frames_written(*conn), 0) << "a frame went out before the grant";
                EXPECT_TRUE(log.edges.empty());
                client.loop();  // The grant
                ASSERT_EQ(log.edges, std::vector<std::string>{"request"});
                (void) manager.run_time_sync();
                break;
            case Stage::RELEASE_NOT_GATED:
                (void) manager.run_time_sync();
                client.loop();
                (void) manager.run_time_sync();
                ASSERT_EQ(time_frames_written(*conn), 1);
                // The burst completes; the tick releases the hold without the main loop.
                conn->time_burst().pending_burst_completed_ = true;
                (void) manager.run_time_sync();
                EXPECT_FALSE(manager.find_admitted(conn.get())->high_performance_held)
                    << "the release waited for the main loop";
                client.loop();
                break;
            case Stage::STALLED_TICK:
                (void) manager.run_time_sync();
                // The connection is lost before the main loop runs: its release joins the
                // acquire the main loop has not applied yet.
                manager.drop_connection(conn.get(), std::nullopt);
                client.loop();
                break;
        }

        EXPECT_EQ(time_frames_written(*conn), row.expected_frames);
        EXPECT_EQ(log.edges, row.expected_edges);
        // stop()'s order with the task played here: admission closes, then the task's final tick
        // runs the shutdown pass, which releases a hold still held.
        manager.close_admission();
        (void) client.protocol_tick();
        client.stop();
        // Every request ends with exactly one release, the stop included.
        const auto requests = std::count(log.edges.begin(), log.edges.end(), "request");
        const auto releases = std::count(log.edges.begin(), log.edges.end(), "release");
        EXPECT_EQ(requests, releases) << "a request was left without its release";
    }
}

// SendspinTimeBurst::loop() is the one chokepoint that opens a burst, and it opens one only with
// the caller's permission: run_time_sync() grants it only once the high-performance hold was
// granted for the burst starts_burst() reported at the same clock reading. A due burst the caller
// does not permit stays closed and writes no time frame. Control: the same due burst, permitted,
// opens and writes its first frame.
TEST(HighPerformanceGrant, LoopOpensNoBurstWithoutTheCallersPermission) {
    for (const bool permitted : {true, false}) {
        SCOPED_TRACE(permitted ? "Control: permitted" : "not permitted");
        OperationalStubConnection conn;
        SendspinTimeBurst& burst = conn.time_burst();
        const int64_t now_ms = platform_time_us() / 1000;
        ASSERT_TRUE(burst.starts_burst(now_ms));

        (void) burst.loop(&conn, now_ms, permitted);

        EXPECT_EQ(time_frames_written(conn), permitted ? 1 : 0);
        EXPECT_EQ(burst.starts_burst(now_ms), !permitted) << "whether the burst was opened";
    }
}

// The grant wakes the protocol task: a burst waiting for it has no deadline of its own, so with the
// real task running and nothing else to wake it, the burst's first time frame goes out after the
// main loop grants and only because of that wake. The stand-in is installed while the test thread
// plays the task, then the task is started again with nothing else armed (liveness off, no
// nursery, the server up). Each wait has no timeout: a missing wake hangs and the suite watchdog
// names this test.
TEST(HighPerformanceGrant, TheGrantWakesTheBurstThatWaitsForIt) {
    HighPerformanceLog log;
    TestNetworkProvider network;
    SendspinClient client(make_config(0));
    client.set_network_provider(&network);
    client.set_listener(&log);
    // Only for its handle on the client's Inbox (impl_->inbox), which the wait below polls.
    client.add_metadata();
    ASSERT_TRUE(client.start());
    client.protocol_task_->stop();
    ConnectionManager& manager = *client.connection_manager_;
    manager.liveness_timeout_us_ = 0;
    Inbox& inbox = *client.metadata_->impl_->inbox;
    auto conn = std::make_shared<OperationalStubConnection>();
    manager.install_admitted(conn, 0);
    ASSERT_TRUE(client.protocol_task_->start([&client] { return client.protocol_tick(); },
                                             SendspinClientConfig::DEFAULT_PROTOCOL_TASK_STACK_SIZE,
                                             1, false));

    // The task requests the hold and parks: nothing grants it until the main loop runs.
    wait_until([&] { return (inbox.poll() & INBOX_TOPIC_HIGH_PERFORMANCE) != 0; });
    EXPECT_EQ(time_frames_written(*conn), 0) << "a frame went out before the grant";

    client.loop();  // The grant, and its wake
    ASSERT_EQ(log.edges, std::vector<std::string>{"request"});
    wait_until([&] { return time_frames_written(*conn) == 1; });

    client.stop();
    EXPECT_EQ(log.edges, (std::vector<std::string>{"request", "release"}));
}

// ============================================================================
// Stream start and end drained in one tick
// ============================================================================

// A stream/start and stream/end that one main-loop drain takes together, after the sync task has
// already taken the start's codec header, met the end and gone back to waiting for a header: the
// drain fires on_stream_start(), signals the start, and holds the STREAM_END behind it until the
// sync task reads idle. The sync task, finding no header for that start, takes it as stale and
// returns to idle, which releases the held end, and the stale start does not carry over: the next
// stream waits for its own. The test thread plays the protocol task, so each step of the
// interleaving is staged in order; every wait has no timeout, and a held end that is never
// released hangs here and the suite watchdog names this test. The sync task's COMMAND_START bit is
// read directly: whether a stale start survives is visible to a caller only as the next stream
// starting before its on_stream_start(), a race no test can stage on demand.
TEST(ClientLifecycle, AStreamStartAndEndDrainedTogetherReleaseTheHeldEnd) {
    CountingPlayerListener listener;
    TestNetworkProvider network;
    SendspinClient client(make_config(0));
    client.set_network_provider(&network);
    client.add_player(make_pcm_player_config()).set_listener(&listener);
    ASSERT_TRUE(client.start());
    client.protocol_task_->stop();
    PlayerRole::Impl& player = *client.player_->impl_;
    SyncTask& sync = *player.sync_task;
    ServerPlayerStreamObject params;
    params.codec = SendspinCodecFormat::PCM;
    params.sample_rate = 48000;
    params.channels = 2;
    params.bit_depth = 16;

    // stream/start: the sync task takes its codec header and waits for the main loop's start.
    player.handle_stream_start(params, player.cleanup_generation.load());
    wait_until([&] { return sync.encoded_items_.is_empty(); });
    // stream/end before the main loop ran: the sync task returns the header and goes idle.
    player.handle_stream_end(player.cleanup_generation.load());
    wait_until([&] { return (player.inbox->poll() & INBOX_TOPIC_PLAYER_SYNC_IDLE) != 0; });

    pump_until(client, [&] { return listener.stream_ends == 1; });
    EXPECT_EQ(listener.stream_starts, 1);
    EXPECT_EQ(sync.event_flags_.get() & EventGroupBits::COMMAND_START, 0U)
        << "the stale start would start the next stream before its own";

    // The next stream starts on its own start.
    player.handle_stream_start(params, player.cleanup_generation.load());
    pump_until(client, [&] { return listener.stream_starts == 2 && sync.is_running(); });
    EXPECT_EQ(listener.stream_ends, 1);
    client.stop();
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

/// Stops the client's protocol task so the calling test can play it: the player's protocol-task
/// handlers and the feeder below then run on one test thread at a time, never beside the task.
void play_protocol_task(SendspinClient& client) {
    client.protocol_task_->stop();
}

/// The connections a test playing the protocol task hands to drain_ring_as_protocol_task().
using ConnectionList = std::vector<std::shared_ptr<SendspinConnection>>;

/// The protocol task's ring drain, for a test playing the task: takes every completed item, which
/// counts the ring-order return of the LOCAL items the feeder hands over, and returns the rest
/// (the time replies a connected server still sends) unprocessed, uncounting each from its
/// connection's in-flight count as the task does (InboundGate::note_item_taken()).
/// @param connections The connections the items can come from, snapshotted beforehand.
void drain_ring_as_protocol_task(InboundRing& ring, const ConnectionList& connections) {
    size_t len = 0;
    void* item = nullptr;
    while ((item = ring.take(&len, 0)) != nullptr) {
        for (const auto& conn : connections) {
            if (static_cast<uint32_t>(conn->get_instance_id()) ==
                inbound_item_header(item)->connection_id) {
                conn->inbound_gate().note_item_taken();
            }
        }
        ring.return_item(item);
    }
}

/// Hands `count` marked 20 ms chunks straight to the sync task, stamped in the server's clock from
/// `first_timestamp` onward, each in an item acquired from the inbound ring the way the protocol
/// task writes a chunk it copies. Bypasses the server so a test can feed audio while it holds a
/// lock the client's own loop needs. Protocol-task work: the caller plays the task
/// (play_protocol_task()). A batch that finds the ring full stops early; the caller's next batch
/// retries.
void feed_marked_chunks(PlayerRole::Impl& impl, int64_t first_timestamp, int count) {
    SyncTask& sync_task = *impl.sync_task;
    InboundRing* ring = sync_task.ring();
    constexpr size_t FRAME_OFFSET = 13;  // type byte, server timestamp, send_ahead
    std::vector<uint8_t> message(FRAME_OFFSET + SINK_CHUNK_BYTES, SINK_AUDIO_MARK);
    message[0] = SENDSPIN_BINARY_PLAYER_AUDIO;
    std::fill(message.begin() + 9, message.begin() + FRAME_OFFSET, 0);
    int64_t timestamp = first_timestamp;
    for (int i = 0; i < count; ++i) {
        for (int byte = 0; byte < 8; ++byte) {
            message[1 + byte] = static_cast<uint8_t>(static_cast<uint64_t>(timestamp) >>
                                                     (56 - 8 * byte));
        }
        void* item = ring->acquire_local(message.size(), 0);
        if (item == nullptr) {
            return;
        }
        std::memcpy(inbound_item_bytes(item), message.data(), message.size());
        InboundItemHeader* header = inbound_item_header(item);
        header->type = CHUNK_TYPE_ENCODED_AUDIO;
        header->data_offset = FRAME_OFFSET;
        header->data_len = static_cast<uint32_t>(SINK_CHUNK_BYTES);
        header->generation = impl.cleanup_generation.load(std::memory_order_acquire);
        ring->complete(item);
        if (!sync_task.hand_item(item, message.size())) {
            ring->return_item(item);
        }
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
    /// @param connections The client's connections (snapshot()).
    ChunkFeeder(SendspinClient& client, ConnectionList connections,
                const VirtualSinkListener& listener, int64_t server_offset_us = 0)
        : thread_([&impl = *client.player_->impl_, &listener, server_offset_us,
                   connections = std::move(connections)] {
              while (!listener.decoded()) {
                  drain_ring_as_protocol_task(*impl.sync_task->ring(), connections);
                  feed_marked_chunks(impl,
                                     platform_time_us() + server_offset_us + SINK_CHUNK_LEAD_US, 4);
                  std::this_thread::sleep_for(std::chrono::milliseconds(10));
              }
          }) {}
    ~ChunkFeeder() {
        this->thread_.join();
    }

    /// The client's connections. Protocol-task work: the caller plays the task.
    static ConnectionList snapshot(SendspinClient& client) {
        ConnectionManager::ConnectionSnapshot snapshot;
        client.connection_manager_->snapshot_connections(snapshot);
        return {snapshot.begin(), snapshot.end()};
    }

private:
    std::thread thread_;
};

// The sync task's per-chunk time getters read the manager's time filter slot, which the protocol
// task publishes, so a chunk decodes while the protocol task is not running at all. A getter that
// waited on the task would park the sync task and no fed chunk would reach the sink. The wait has
// no timeout of its own, since no bound could tell a parked task from a slow machine: the suite
// watchdog in tests/main.cpp names it instead.
TEST(ClientLifecycle, SyncTaskDecodesAChunkWhileTheProtocolTaskIsStopped) {
    VirtualSinkListener listener;
    auto config = make_config(STREAM_FILTER_STOPPED_TASK_TEST_PORT);
    config.time_burst_interval_ms = 100;  // Sync promptly after the connect
    PairedClientBundle bundle(std::move(config));
    SendspinClient& client = bundle.client();
    PlayerRole& player = client.add_player(make_pcm_player_config());
    player.set_listener(&listener);
    listener.attach(player);

    FakeEncryptedServerOptions options;
    options.answer_time = true;
    ASSERT_TRUE(bundle.start());
    auto server = connect_paired_server(bundle.peer, STREAM_FILTER_STOPPED_TASK_TEST_PORT, options);
    pump_until_synced(client);

    ASSERT_TRUE(server->send_app_json(stream_start_pcm_json()));
    SyncTask& sync_task = *client.player_->impl_->sync_task;
    pump_until(client, [&] { return sync_task.is_running(); });
    play_protocol_task(client);

    {
        ChunkFeeder feeder(client, ChunkFeeder::snapshot(client), listener);
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

/// Puts `conn` in the manager's admitted slot, owning every role, the way a promotion does, and
/// returns what the slot held; a null `conn` only vacates it. Protocol-task work: the caller plays
/// the task, or the client is not started.
std::shared_ptr<SendspinConnection> replace_admitted(ConnectionManager& manager,
                                                     std::shared_ptr<SendspinConnection> conn) {
    AdmittedEntry& entry = manager.admitted_[0];
    std::shared_ptr<SendspinConnection> replaced = std::move(entry.conn);
    entry = AdmittedEntry{};
    if (replaced != nullptr) {
        replaced->set_admitted(false);
    }
    if (conn != nullptr) {
        manager.install_admitted(std::move(conn), ALL_ROLES_MASK);
    } else {
        manager.refresh_published_state();
    }
    return replaced;
}

/// Installs a stand-in connection as admitted, the way a promotion does, and starts a stream on it,
/// returning once the sync task is running. The stream is driven through PlayerRole::Impl, since
/// nothing is connected to carry a stream/start, on the test thread, which plays the protocol task
/// from here on. The client must use make_stand_in_config().
void start_stream_on(SendspinClient& client, std::shared_ptr<ObservedConnection> conn) {
    play_protocol_task(client);
    (void) replace_admitted(*client.connection_manager_, std::move(conn));
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

// The time filter slot follows the primary admitted connection's filter: a synced connection
// converts with its offset, a vacated slot reads as unsynced, the slot never keeps a connection
// alive, and an unsynced newcomer installed over a synced one reads its own filter.
TEST(ClientLifecycle, TheTimeFilterSlotFollowsTheAdmittedConnection) {
    ConnectionObservation dropped_obs;  // All outlive the client
    ConnectionObservation replaced_obs;
    ConnectionObservation newcomer_obs;
    SendspinClient client(make_config(TIME_FILTER_SLOT_TEST_PORT));
    ConnectionManager& manager = *client.connection_manager_;
    constexpr int64_t SERVER_TS_US = 50 * 1000 * 1000;

    (void) replace_admitted(manager, make_synced_connection(&dropped_obs));
    EXPECT_TRUE(client.is_time_synced());
    EXPECT_EQ(client.get_client_time(SERVER_TS_US), SERVER_TS_US - SEEDED_SERVER_OFFSET_US);

    std::shared_ptr<SendspinConnection> slot = replace_admitted(manager, nullptr);
    EXPECT_FALSE(client.is_time_synced());
    EXPECT_EQ(client.get_client_time(SERVER_TS_US), 0);
    slot.reset();
    EXPECT_TRUE(dropped_obs.destroyed.load())
        << "a reference other than the slot's kept the connection alive";

    (void) replace_admitted(manager, make_synced_connection(&replaced_obs));
    ASSERT_TRUE(client.is_time_synced());
    (void) replace_admitted(manager, std::make_shared<ObservedConnection>(&newcomer_obs));
    EXPECT_FALSE(client.is_time_synced()) << "the newcomer read the replaced connection's filter";
}

// The sync task converts chunks with the current connection's offset. The fed
// chunks are stamped in the server's clock, so a task that never saw the filter (parked unsynced)
// or a conversion that skipped the offset (every chunk late) never reaches the sink. No timeout of
// its own, as in SyncTaskDecodesAChunkWhileTheProtocolTaskIsStopped.
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
        ChunkFeeder feeder(client, ChunkFeeder::snapshot(client), listener,
                           SEEDED_SERVER_OFFSET_US);
        listener.wait_for_decoded();
    }

    client.stop();
    EXPECT_EQ(listener.stream_ends, 1);
}

// A stream's connection dropped mid-stream carries exactly one client/goodbye on its wire and
// is freed on the protocol task (here the test thread, which plays it), never on the sync task's:
// the sync task holds no connection reference of its own. One that did would keep the connection
// alive past the drop and free it on the audio thread when the stream ended.
TEST(ClientLifecycle, ADroppedStreamConnectionIsGoodbyedOnceAndFreedOnTheProtocolTask) {
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

    manager.drop_connection(streamed, SendspinGoodbyeReason::ANOTHER_SERVER);
    pump_until(client, [&] { return listener.stream_ends == 1; });
    pump_until(client, [&] { return observation.destroyed.load(); });

    EXPECT_EQ(observation.goodbyes.load(), 1)
        << "expected exactly one client/goodbye on this connection's wire";
    // Private read: nothing a caller or peer observes distinguishes the destructor's thread.
    EXPECT_EQ(observation.destroyed_on, std::this_thread::get_id())
        << "the connection was freed on a thread other than the one playing the protocol task";

    client.stop();
}

// Destroying a running client releases the inbound ring only once the role threads are stopped
// and their item lists unbound. A LOCAL item (one the protocol task wrote itself, here a chunk
// copied into the ring) that its holder already returned but the task never took in ring order
// is counted on the ring's reset through its holder's list; with the roles reset first that list
// is freed memory, and the process crashes or is reported by AddressSanitizer. The test thread plays the protocol task, so
// nothing takes the item in ring order before the destructor.
TEST(ClientLifecycle, DestroyingARunningClientWithAReturnedLocalItemIsClean) {
    CountingPlayerListener listener;
    TestNetworkProvider network;
    auto client = std::make_unique<SendspinClient>(make_stand_in_config(0));
    client->set_network_provider(&network);
    client->add_player(make_pcm_player_config()).set_listener(&listener);
    ASSERT_TRUE(client->start());
    play_protocol_task(*client);

    PlayerRole::Impl& impl = *client->player_->impl_;
    InboundRing& ring = *impl.sync_task->ring();
    std::vector<uint8_t> chunk(13 + 4, 0x00);
    chunk[0] = SENDSPIN_BINARY_PLAYER_AUDIO;
    InboundMessage message;
    message.data = chunk.data();
    message.len = chunk.size();
    impl.handle_binary(message, impl.cleanup_generation.load());
    ASSERT_GT(ring.quota(InboundHolder::PLAYER).outstanding(), 0U)
        << "the chunk never reached the sync task's list";

    // The idle sync task discards a chunk with no stream behind it, which is its holder's return.
    wait_until([&] { return ring.quota(InboundHolder::PLAYER).outstanding() == 0; });
    client.reset();
}

// The ring holds the time replies that arrive while the player holds its oldest chunk, so its
// size follows the configured burst cadence: a client syncing ten times as often gets a larger
// ring. Read from the ring the client creates, so the configuration has to reach the derivation.
TEST(ClientLifecycle, TheInboundRingGrowsWithTheTimeBurstRate) {
    const auto ring_bytes = [](int64_t interval_ms) {
        TestNetworkProvider network;
        SendspinClientConfig config = make_config(0);
        config.time_burst_interval_ms = interval_ms;
        SendspinClient client(config);
        client.set_network_provider(&network);
        client.add_player(make_pcm_player_config());
        EXPECT_TRUE(client.start());
        const size_t bytes = client.inbound_ring_->storage_.size();
        client.stop();
        return bytes;
    };
    const size_t default_bytes = ring_bytes(SendspinClientConfig::DEFAULT_BURST_INTERVAL_MS);
    InboundRingBudget budget;
    budget.audio_hold_bytes = make_pcm_player_config().audio_buffer_capacity;
    EXPECT_EQ(default_bytes, derive_inbound_ring_bytes(budget)) << "Control: the defaults";
    EXPECT_GT(ring_bytes(SendspinClientConfig::DEFAULT_BURST_INTERVAL_MS / 10), default_bytes)
        << "the configured burst interval never reached the ring's derivation";
}

}  // namespace
