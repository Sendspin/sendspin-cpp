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

#include "artwork_role_impl.h"  // The display slot and its epochs; private, see CMakeLists
#include "color_role_impl.h"       // The applied palette and its slot; private, see CMakeLists
#include "connection.h"  // StubConnection stands in for a real connection
#include "connection_manager.h"
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
#include "sendspin/artwork_role.h"
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
constexpr uint16_t PROVIDER_TEST_PORT = 19070;
constexpr uint16_t ADMISSION_CLOSED_DELIVERY_TEST_PORT = 19071;
constexpr uint16_t STREAM_FILTER_STOPPED_TASK_TEST_PORT = 19072;
constexpr uint16_t STREAM_FILTER_OFFSET_TEST_PORT = 19073;
constexpr uint16_t TIME_FILTER_SLOT_TEST_PORT = 19074;
constexpr uint16_t ADMISSION_CLOSED_TEST_PORT = 19075;
constexpr uint16_t ADMISSION_OPEN_TEST_PORT = 19076;
constexpr uint16_t STREAM_FILTER_MIDSTREAM_TEST_PORT = 19077;
constexpr uint16_t VISUALIZER_SPECTRUM_TEST_PORT = 19078;
constexpr uint16_t VISUALIZER_STALE_TEST_PORT = 19084;
constexpr uint16_t VISUALIZER_OFFSET_TEST_PORT = 19088;
constexpr uint16_t VISUALIZER_HELD_END_TEST_PORT = 19099;
constexpr uint16_t VISUALIZER_HELD_CLEAR_TEST_PORT = 19100;
constexpr uint16_t VISUALIZER_HELD_TEARDOWN_TEST_PORT = 19104;
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

    /// Takes the next connection off the backlog, blocking with no timeout. The listener still
    /// sends nothing on it.
    /// @return The connection's descriptor, or -1 when the listener is not set up.
    int accept_connection() {
        return this->fd_ >= 0 ? ::accept(this->fd_, nullptr, nullptr) : -1;
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
// the current time (the drain thread drops a frame whose display time has passed).
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
// synced, and they carry the generation stop()'s teardown moved past, so a take would return
// them anyway.
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
        auto& items = client.visualizer()->impl_->drain_task->inbound.items();
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

// stream/end, stream/clear and a teardown each return the frame the drain thread holds for its
// display time, and those listed behind it, undelivered. One frame goes first, and the thread
// holds it once the list is empty with its charge outstanding; stamped an hour ahead, a held
// frame left waiting hangs the pump. stop() joins the thread before the count is read. Control:
// the frames were charged before the boundary.
TEST(ClientLifecycle, AStreamBoundaryReturnsTheVisualizerFrameHeldForItsDisplayTime) {
    constexpr int64_t HELD_FRAME_LEAD_US = 3600LL * 1000 * 1000;
    enum class Boundary : uint8_t { END, CLEAR, TEARDOWN };
    struct Row {
        const char* name;
        uint16_t port;
        Boundary boundary;
    };
    const Row rows[] = {
        {"stream/end", VISUALIZER_HELD_END_TEST_PORT, Boundary::END},
        {"stream/clear", VISUALIZER_HELD_CLEAR_TEST_PORT, Boundary::CLEAR},
        {"a teardown", VISUALIZER_HELD_TEARDOWN_TEST_PORT, Boundary::TEARDOWN},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        CountingVisualizerListener listener;
        auto config = make_config(row.port);
        config.time_burst_interval_ms = 100;  // Sync promptly after the connect
        PairedClientBundle bundle(std::move(config));
        SendspinClient& client = bundle.client();
        client.add_visualizer(make_visualizer_config()).set_listener(&listener);

        FakeEncryptedServerOptions options;
        options.answer_time = true;

        ASSERT_TRUE(bundle.start());
        auto server = connect_paired_server(bundle.peer, row.port, options);
        pump_until_synced(client);
        ASSERT_TRUE(server->send_app_json(stream_start_visualizer_json()));
        InboundConsumer& inbound = client.visualizer()->impl_->drain_task->inbound;
        const InboundQuota& quota = inbound.ring()->quota(InboundHolder::VISUALIZER);
        ASSERT_TRUE(server->send_binary(SENDSPIN_BINARY_VISUALIZER_LOUDNESS,
                                        platform_time_us() + HELD_FRAME_LEAD_US,
                                        std::string("\x00\x10", 2)));
        pump_until(client,
                   [&] { return inbound.items().is_empty() && quota.outstanding() > 0; });
        send_loudness_until(client, *server, HELD_FRAME_LEAD_US,
                            [&] { return !inbound.items().is_empty(); });

        switch (row.boundary) {
            case Boundary::END:
                ASSERT_TRUE(server->send_app_json(R"({"type":"stream/end","payload":{}})"));
                break;
            case Boundary::CLEAR:
                ASSERT_TRUE(server->send_app_json(R"({"type":"stream/clear","payload":{}})"));
                break;
            case Boundary::TEARDOWN:
                server.reset();
                break;
        }
        pump_until(client, [&] { return quota.outstanding() == 0; });
        EXPECT_TRUE(inbound.items().is_empty());
        client.stop();
        EXPECT_EQ(listener.loudness.load(), 0U);
    }
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
// VISUALIZER_LEAD_US ahead, as send_loudness_until() does with loudness frames.
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
        auto& items = this->client().visualizer()->impl_->drain_task->inbound.items();
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
    // The release is queued before the protocol task publishes the loss, so is_connected() can
    // still read true when the release arrives.
    pump_until(client, [&] { return !client.is_connected(); });

    auto again = connect_paired_server(bundle.peer, HIGH_PERF_TEST_PORT);
    pump_until(client, [&] { return client.is_connected() && listener.requests == 2; });
    client.stop();
    EXPECT_EQ(listener.releases, 2);
}

// ============================================================================
// Stand-in connections
// ============================================================================

/// Connection stand-in with every transport override inert: nothing is sent anywhere, a send
/// reports success, and the connection always reads as connected. Tests that install one in the
/// manager's slot derive from it and override only the one call they are about to observe.
class StubConnection : public SendspinConnection {
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
    SsErr send_text_message(const std::string&) override {
        return SsErr::OK;
    }
};

/// Counts client/hello sends, `result` being what each returns, and records the goodbye a drop
/// sends and the transport closes.
class HelloCountingConnection : public StubConnection {
public:
    explicit HelloCountingConnection(SsErr result) : result_(result) {}

    // No Noise session, so send_app_json() routes the hello here as raw text.
    SsErr send_text_message(const std::string& msg) override {
        if (msg.find("client/hello") != std::string::npos) {
            ++this->hellos;
        }
        return this->result_;
    }

    void disconnect(SendspinGoodbyeReason reason) override {
        this->goodbye = reason;
    }

    void close_transport_now() override {
        ++this->closes;
    }

    int hellos{0};
    int closes{0};
    std::optional<SendspinGoodbyeReason> goodbye;

private:
    SsErr result_;
};

// A nursery connection's client/hello is sent once, when its Noise handshake completes, and never
// again. A send that fails on a connected transport is not retried, so the connection is closed
// without a goodbye and dropped; one the transport refuses as no longer connected is left for its
// close event or the establish deadline. The stand-in has no Noise session, so the drop is the
// hello scan's own; the close after the encrypt is covered for other sends by
// NoiseTransport.ASendFailureAfterTheEncryptDropsTheConnectionInItsTick.
TEST(ClientLifecycle, NurseryHelloIsSentOnceAndAFailedSendDropsTheConnection) {
    struct Row {
        const char* name;
        SsErr send_result;
        bool dropped;
    };
    const Row rows[] = {
        {"Control: sent", SsErr::OK, false},
        {"refused by the transport", SsErr::INVALID_STATE, false},
        {"the send fails", SsErr::FAIL, true},
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

        for (int tick = 0; tick < 3; ++tick) {
            (void) manager.scan_nursery(platform_time_us());
        }
        EXPECT_EQ(conn->hellos, 1);
        const bool in_nursery =
            std::any_of(manager.nursery_.begin(), manager.nursery_.end(),
                        [&conn](const NurseryEntry& entry) { return entry.conn == conn; });
        EXPECT_EQ(in_nursery, !row.dropped);
        EXPECT_EQ(conn->closes, row.dropped ? 1 : 0);
        EXPECT_FALSE(conn->goodbye.has_value())
            << "goodbye sent with reason " << static_cast<int>(*conn->goodbye);

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

// A peer the server delivers while stop() is under way is refused, never given a nursery slot.
// One queued as an accept before admission closed is refused by the protocol task's final tick
// with a client/goodbye of reason shutdown; one delivered after admission closed is refused at
// its push (ProtocolTask::close_accepts(), which ConnectionManager::close_admission() calls), so
// its transport closes it without a goodbye and nothing is left queued for stop() to refuse. The
// test thread plays the protocol task, so the accept provably sits in the queue when admission
// closes. The open row is the control: the same queued accept is admitted and owed no goodbye.
// The nursery-full rejection is covered by ConnectionLifecycle.FullNurseryOfLivePeersRejectsNewcomer.
// Each row connects a real peer, and the Control row watches 200 ms for a goodbye that must not
// come, so the table takes most of a second.
TEST(ClientLifecycle, StopRefusesAQueuedAcceptWithAShutdownGoodbye) {
    enum class Taker : uint8_t { FINAL_TICK, AFTER_CLOSE, OPEN_TICK };
    struct AcceptRow {
        const char* name;
        Taker taker;
        uint16_t port;
    };
    const AcceptRow rows[] = {
        {"queued before admission closed: the final tick refuses it", Taker::FINAL_TICK,
         ADMISSION_CLOSED_TEST_PORT},
        {"delivered after admission closed: refused at its push", Taker::AFTER_CLOSE,
         ADMISSION_CLOSED_DELIVERY_TEST_PORT},
        {"Control: admission open", Taker::OPEN_TICK, ADMISSION_OPEN_TEST_PORT},
    };

    for (const AcceptRow& row : rows) {
        SCOPED_TRACE(row.name);
        PairedClientBundle bundle(make_config(row.port));
        SendspinClient& client = bundle.client();
        ASSERT_TRUE(bundle.start());
        client.protocol_task_->stop();
        if (row.taker == Taker::AFTER_CLOSE) {
            client.connection_manager_->close_admission();
        }

        auto peer = connect_paired_server(bundle.peer, row.port);
        if (row.taker != Taker::AFTER_CLOSE) {
            wait_until([&] { return queued_commands(*client.protocol_task_) == 1; });
        }

        switch (row.taker) {
            case Taker::FINAL_TICK:
                // stop()'s order: admission closes, then the task's final tick runs.
                client.connection_manager_->close_admission();
                (void) client.protocol_tick();
                wait_until([&] { return peer->goodbye_reason().has_value(); });
                EXPECT_EQ(peer->goodbye_reason().value_or(""), "shutdown")
                    << "a newcomer refused at stop() must be told why";
                break;
            case Taker::AFTER_CLOSE:
                // No timeout: a delivery the queue took instead would never be closed here, since
                // the test thread runs no tick, and the watchdog names the test.
                wait_until([&] { return peer->closed(); });
                EXPECT_FALSE(peer->goodbye_reason().has_value())
                    << "a delivery refused at its push is closed by its transport, without a goodbye";
                EXPECT_EQ(queued_commands(*client.protocol_task_), 0U)
                    << "a delivery after admission closed reached the queue";
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
            EXPECT_TRUE(client.connection_manager_->nursery_.empty())
                << "a refused newcomer took a nursery slot";
        }

        client.stop();
    }
}

/// Fills the protocol task's accept slots, so the next delivery finds them all taken. Each carries
/// a connection, as every accept does: one with no transport, which stop() refuses at once. The
/// test thread plays the protocol task, so none is taken.
void fill_accept_slots(ProtocolTask& task) {
    for (;;) {
        ProtocolCommand command;
        command.type = ProtocolCommandType::ACCEPT_CONNECTION;
        command.connection = std::make_shared<SendspinServerConnection>(nullptr);
        if (!task.push_command(std::move(command))) {
            return;
        }
    }
}

// A refused delivery leaves the connection with the transport that delivered it:
// on_new_connection() reports the refusal and keeps no reference, so the delivering thread's own
// reference is the last one and the transport releases the connection once the delivery returns
// (SendspinWsServer::NewConnectionCallback), never inside it. A delivery is refused when every
// accept slot is taken, and once admission is closed (ConnectionManager::close_admission() closes
// the protocol task's accepts), when no tick would take an accept any more. The accepted row is
// the control: the queued accept holds a reference for the protocol task.
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
        {"admission is closed", false, true, false, 1},
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
            client.connection_manager_->close_admission();
        }

        auto conn = std::make_shared<SendspinServerConnection>(nullptr);
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

// A lifecycle request left in its slot after a stop() (a call that raced it on another thread)
// belongs to the run that ended: the next start() begins with no request waiting, so a stale
// connect_to() opens nothing and a stale confirm opens no pairing window. Each is posted straight
// to the stopped client's task, the state such a race leaves, since the public entry points refuse
// while stopped. The Control rows post the same after start() and see it acted on.
TEST(ClientLifecycle, AStaleCommandIsNotCarriedIntoTheNextRun) {
    struct Row {
        const char* name;
        bool stale;
        bool request;
    };
    const Row rows[] = {
        {"a connect_to() posted while stopped", true, false},
        {"Control: a connect_to() posted while running", false, false},
        {"a confirm posted while stopped", true, true},
        {"Control: a confirm posted while running", false, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SilentListener silent;
        ASSERT_NE(silent.port(), 0);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        client.stop();

        auto push = [&] {
            if (row.request) {
                client.protocol_task_->post_requests(
                    {.pairing_window = PairingWindowRequest::CONFIRM});
                return;
            }
            // The attempt waits in the nursery: the listener never answers or closes.
            client.protocol_task_->post_requests(
                {.connect_to = "ws://127.0.0.1:" + std::to_string(silent.port()) + "/sendspin"});
        };
        if (row.stale) {
            push();
        }
        ASSERT_TRUE(client.start());
        // The test thread plays the protocol task from here, so the nursery is read where it is
        // written.
        client.protocol_task_->stop();
        if (!row.stale) {
            push();
        }
        (void) client.protocol_tick();
        const bool acted_on = row.request ? client.connection_manager_->pairing_window_open()
                                          : client.connection_manager_->nursery_.size() == 1U;
        EXPECT_EQ(acted_on, !row.stale);
        silent.close();
        client.stop();
    }
}

std::string loopback_url(uint16_t port) {
    return "ws://127.0.0.1:" + std::to_string(port) + "/sendspin";
}

// Releasing an outbound attempt whose upgrade is still in flight never waits for its transport on
// the protocol task: the release closes the transport without blocking and parks the connection
// in ConnectionManager's reaping list, which frees it once the transport reports its close. Each
// row starts an attempt on a listener that never answers and releases it through one path that
// can: disconnect(), a connect_to() that replaces it, and the nursery's establish reap (staged at
// a clock past the deadline). The test thread plays the protocol task for the release, so no tick
// can reap the attempt before it is inspected, and the attempt is watched through a weak_ptr
// only: right after the release it is alive and parked, which a release that stops the transport
// in place cannot produce, since that destroys the connection inside the release (after waiting
// out the handshake timeout when its close landed before the upgrade began). The real task then
// takes a disconnect() and a connect_to() from another thread while every listener is still
// silent, and the probe listener sees the connect (no timeout): the parked attempt holds up no
// later request. That half does not tell a task that never waited from one that waited and then
// went on; the inspection above is what pins the release. Once the listeners close, the attempt's
// transport reports its close (waited for with no timeout) and the very next tick frees it: the
// reap drops a parked connection on its transport's close, not only at its deadline. Control: an
// attempt nothing releases stays in the nursery with nothing parked; it is the one the real
// task's disconnect() then releases. Each row connects loopback sockets only, so the table runs
// in tens of milliseconds.
TEST(ClientLifecycle, AReleasedAttemptStillConnectingIsReapedOffTheProtocolTask) {
    enum class Release : uint8_t { DISCONNECT, REPLACED, ESTABLISH_REAP, NONE };
    struct Row {
        const char* name;
        Release release;
    };
    const Row rows[] = {
        {"disconnect() releases it", Release::DISCONNECT},
        {"a connect_to() replaces it", Release::REPLACED},
        {"the establish reap releases it", Release::ESTABLISH_REAP},
        {"Control: nothing releases it", Release::NONE},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SilentListener silent;
        SilentListener replacement;
        SilentListener probe;
        ASSERT_NE(silent.port(), 0);
        ASSERT_NE(replacement.port(), 0);
        ASSERT_NE(probe.port(), 0);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        ConnectionManager& manager = *client.connection_manager_;

        manager.connect_to(loopback_url(silent.port()));
        ASSERT_EQ(manager.nursery_.size(), 1U);
        const std::weak_ptr<SendspinConnection> attempt = manager.nursery_[0].conn;
        switch (row.release) {
            case Release::DISCONNECT:
                manager.disconnect(SendspinGoodbyeReason::USER_REQUEST);
                break;
            case Release::REPLACED:
                manager.connect_to(loopback_url(replacement.port()));
                break;
            case Release::ESTABLISH_REAP:
                (void) manager.scan_nursery(platform_time_us() + NURSERY_ESTABLISH_TIMEOUT_US);
                break;
            case Release::NONE:
                break;
        }
        if (row.release == Release::NONE) {
            EXPECT_TRUE(manager.reaping_.empty()) << "an attempt nothing released was parked";
            EXPECT_EQ(manager.nursery_.size(), 1U);
        } else {
            ASSERT_FALSE(attempt.expired())
                << "the release destroyed the connection in place, joining its transport";
            ASSERT_EQ(manager.reaping_.size(), 1U);
            EXPECT_EQ(manager.reaping_[0].conn, attempt.lock());
            EXPECT_EQ(manager.nursery_.size(), row.release == Release::REPLACED ? 1U : 0U);
        }

        // The real task takes a disconnect() and then a connect_to() from another thread while
        // every listener is still silent; the probe sees the connect once the task has acted on
        // both.
        ASSERT_TRUE(client.protocol_task_->start([&client] { return client.protocol_tick(); },
                                                 SendspinClientConfig::DEFAULT_PROTOCOL_TASK_STACK_SIZE,
                                                 1, false));
        std::thread consumer([&client, &probe] {
            client.disconnect(SendspinGoodbyeReason::USER_REQUEST);
            client.connect_to(loopback_url(probe.port()));
        });
        consumer.join();
        const int probe_fd = probe.accept_connection();
        EXPECT_GE(probe_fd, 0) << "the probe never saw the connect_to() behind the disconnect()";

        // The attempt fails once its listener is gone; the tick after its transport reports the
        // close frees it, long before its reaping deadline.
        client.protocol_task_->stop();
        ASSERT_FALSE(attempt.expired()) << "the attempt was dropped while its listener was silent";
        if (probe_fd >= 0) {
            ::close(probe_fd);
        }
        silent.close();
        replacement.close();
        probe.close();
        wait_until([&] {
            const std::shared_ptr<SendspinConnection> conn = attempt.lock();
            return conn != nullptr && conn->inbound_gate().is_transport_closed();
        });
        (void) client.protocol_tick();
        EXPECT_TRUE(attempt.expired()) << "the reap kept a parked connection whose transport closed";
        client.stop();
    }
}

// Only an attempt still connecting is parked: a released outbound connection whose WebSocket
// upgrade completed is released in place, since its destructor's stop is the short close of an
// open transport and no platform reports the close of one stopped that way, and a parked attempt
// that opens is dropped by the next tick instead of being held to its deadline. The upgrade is
// staged by marking it (mark_ws_upgraded(), what the transport's Open does) once the listener has
// taken the attempt's TCP connection, so IXWebSocket is inside its handshake and the destructor's
// close cancels it at once. The test thread plays the protocol task, so nothing ticks between the
// steps it inspects. Control: an attempt still connecting is parked.
TEST(ClientLifecycle, AnOpenedOutboundConnectionIsNotHeldForReaping) {
    enum class Step : uint8_t { OPENED_THEN_RELEASED, RELEASED_THEN_OPENED, STILL_CONNECTING };
    struct Row {
        const char* name;
        Step step;
    };
    const Row rows[] = {
        {"released after its upgrade: released in place", Step::OPENED_THEN_RELEASED},
        {"opened after its release: the next tick drops it", Step::RELEASED_THEN_OPENED},
        {"Control: still connecting: parked", Step::STILL_CONNECTING},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SilentListener silent;
        ASSERT_NE(silent.port(), 0);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        ConnectionManager& manager = *client.connection_manager_;

        manager.connect_to(loopback_url(silent.port()));
        ASSERT_EQ(manager.nursery_.size(), 1U);
        const std::weak_ptr<SendspinConnection> attempt = manager.nursery_[0].conn;
        const int fd = silent.accept_connection();
        ASSERT_GE(fd, 0);

        if (row.step == Step::OPENED_THEN_RELEASED) {
            attempt.lock()->mark_ws_upgraded();
        }
        manager.disconnect(SendspinGoodbyeReason::USER_REQUEST);
        switch (row.step) {
            case Step::OPENED_THEN_RELEASED:
                EXPECT_TRUE(attempt.expired()) << "a connection that opened was parked";
                EXPECT_TRUE(manager.reaping_.empty());
                break;
            case Step::RELEASED_THEN_OPENED:
                ASSERT_EQ(manager.reaping_.size(), 1U);
                attempt.lock()->mark_ws_upgraded();
                (void) client.protocol_tick();
                EXPECT_TRUE(attempt.expired())
                    << "a parked attempt that opened was held for its deadline";
                break;
            case Step::STILL_CONNECTING:
                EXPECT_FALSE(attempt.expired());
                EXPECT_EQ(manager.reaping_.size(), 1U);
                break;
        }
        ::close(fd);
        silent.close();
        client.stop();
    }
}

// A full reaping list makes room by dropping the entry parked longest, so the list stays bounded
// (REAPING_CAPACITY) however fast connections are released. Stand-in connections, whose
// destructors join no transport, are parked directly (park_for_reaping()) with the test thread
// playing the protocol task, so no reap pass frees one first. Control: a list filled to capacity
// drops nothing.
TEST(ClientLifecycle, AFullReapingListDropsTheConnectionParkedLongest) {
    TestNetworkProvider network;
    SendspinClient client(make_config(0));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start());
    client.protocol_task_->stop();
    ConnectionManager& manager = *client.connection_manager_;

    std::vector<std::weak_ptr<SendspinConnection>> parked;
    for (size_t i = 0; i < ConnectionManager::REAPING_CAPACITY; ++i) {
        auto conn = std::make_shared<StubConnection>();
        parked.push_back(conn);
        manager.park_for_reaping(std::move(conn));
    }
    ASSERT_EQ(manager.reaping_.size(), ConnectionManager::REAPING_CAPACITY);
    for (size_t i = 0; i < parked.size(); ++i) {
        EXPECT_FALSE(parked[i].expired()) << "Control: a list at capacity dropped entry " << i;
    }

    auto newest = std::make_shared<StubConnection>();
    manager.park_for_reaping(newest);
    EXPECT_EQ(manager.reaping_.size(), ConnectionManager::REAPING_CAPACITY);
    EXPECT_TRUE(parked[0].expired()) << "the entry parked longest was kept";
    for (size_t i = 1; i < parked.size(); ++i) {
        EXPECT_FALSE(parked[i].expired()) << "entry " << i << " was dropped in its place";
    }
    EXPECT_EQ(manager.reaping_[manager.reaping_.size() - 1].conn, newest);
    newest.reset();
    client.stop();
}

/// Records, in order, the client/leave, client/command and client/state messages and the goodbyes
/// sent on it.
class RecordingConnection : public StubConnection {
public:
    void disconnect(SendspinGoodbyeReason reason) override {
        this->events.push_back("goodbye " + std::to_string(static_cast<int>(reason)));
    }
    // No Noise session, so send_app_json() routes a message here as raw text.
    SsErr send_text_message(const std::string& msg) override {
        if (msg.find("client/leave") != std::string::npos) {
            this->events.emplace_back("leave");
        } else if (msg.find("client/command") != std::string::npos) {
            this->events.emplace_back("command");
        } else if (msg.find("client/state") != std::string::npos) {
            this->events.emplace_back("state");
        } else if (msg.find("client/init") != std::string::npos) {
            this->events.emplace_back("init");
        }
        return SsErr::OK;
    }

    std::vector<std::string> events;
};

std::string goodbye_event(SendspinGoodbyeReason reason) {
    return "goodbye " + std::to_string(static_cast<int>(reason));
}

// The command queue's consumer burst bounds the sends, never the lifecycle requests. Once the burst
// is taken, send_controller_command() and ControllerRole::send_command() report the request the
// protocol task will never see by returning false, while connect_to(), disconnect(), leave(), the
// pairing-window gestures and an unpaired-access change still reach the next tick, which applies
// each once (a second tick repeats nothing, nor does a later post of another request). Each is
// latest-wins: a confirm and a cancel resolve to the later, a second disconnect() replaces the
// first's reason, a leave goes out ahead of the goodbye whatever order they were called in, and a
// connect_to() and a disconnect() resolve by call order (a disconnect cancels an earlier connect, a
// later connect opens after the goodbye). The requests go ahead of the sends queued with them, so a
// controller command queued before a disconnect() is dropped rather than sent after the goodbye, as
// is a client/state published before it, though the stand-in still reads as connected, as an ESP
// server connection does until httpd closes it. A controller command validated before a teardown
// moves the controller's generation on (as a switchover that admits a new owner later in the same
// tick would) is dropped at the drain rather than sent to the new owner, which never offered it;
// the row moves the generation on directly, so the stand-in still owns the role and only the
// stamp check stands between the command and the send. Gap: the same detached check in
// ConnectionManager::leave() has no row, since the tick applies a leave ahead of a disconnect. A
// disconnect that only stop()'s final tick sees, once admission is closed, is dropped in favour of
// the shutdown goodbye. The test thread plays the protocol task, so nothing drains the queue
// between the calls; the closed-admission row runs the tick that stop() would. The stand-in is an
// activated Sentinel connection with an active role, so withdrawing unpaired access closes it, and
// the liveness check is off so silence does not. The controller's offered command is seeded,
// stamped with the role's generation as the drain stamps a mask it applies, so a command reaches
// the queue; a row that drops the stand-in tears the controller down, so it is seeded again before
// the drained queue is tried. The outbound attempts dial a listener that never answers, so an
// attempt opened stays in the nursery. Control: a confirm with room in the queue, and a controller
// command and a state change with no disconnect behind them.
TEST(ClientLifecycle, TheCommandQueueRefusesSendsButNeverALifecycleRequest) {
    enum class Call : uint8_t {
        CONFIRM,
        CANCEL,
        LEAVE,
        DISCONNECT,
        DISCONNECT_AGAIN,
        DISCONNECT_ON_TASK,
        UNPAIRED_OFF,
        CONNECT,
        SEND_COMMAND,
        TEAR_DOWN_CONTROLLER,
        TICK,
        CLOSE_ADMISSION,
        SET_UNAVAILABLE,
    };
    struct Row {
        const char* name;
        bool fill_queue;
        std::vector<Call> calls;
        bool window_open;
        std::vector<std::string> events;
        size_t attempts{0};
        bool owns_controller{false};
        /// Whether the stand-in has finished its hello exchange, so a client/state reaches it.
        bool operational{false};
    };
    const std::string user_goodbye = goodbye_event(SendspinGoodbyeReason::USER_REQUEST);
    const Row rows[] = {
        {"Control: a confirm with room in the queue", false, {Call::CONFIRM}, true, {}},
        {"a confirm behind a full queue", true, {Call::CONFIRM}, true, {}},
        {"a confirm then a cancel end cancelled", true, {Call::CONFIRM, Call::CANCEL}, false, {}},
        {"a cancel then a confirm end confirmed", true, {Call::CANCEL, Call::CONFIRM}, true, {}},
        {"a leave behind a full queue", true, {Call::LEAVE}, false, {"leave"}},
        {"a leave, a tick, then a confirm: the leave is not repeated",
         false,
         {Call::LEAVE, Call::TICK, Call::CONFIRM},
         true,
         {"leave"}},
        {"a second disconnect replaces the first's reason",
         true,
         {Call::DISCONNECT, Call::DISCONNECT_AGAIN},
         false,
         {goodbye_event(SendspinGoodbyeReason::ANOTHER_SERVER)}},
        {"a disconnect then a leave: the leave goes out first",
         true,
         {Call::DISCONNECT, Call::LEAVE},
         false,
         {"leave", user_goodbye}},
        {"unpaired access withdrawn behind a full queue",
         true,
         {Call::UNPAIRED_OFF},
         false,
         {goodbye_event(SendspinGoodbyeReason::PAIRING_REQUIRED)}},
        {"a connect_to behind a full queue opens an attempt", true, {Call::CONNECT}, false, {}, 1},
        {"a connect_to then a disconnect: the attempt is cancelled",
         false,
         {Call::CONNECT, Call::DISCONNECT},
         false,
         {user_goodbye},
         0},
        {"a disconnect then a connect_to: the attempt opens after the goodbye",
         false,
         {Call::DISCONNECT, Call::CONNECT},
         false,
         {user_goodbye},
         1},
        {"Control: a controller command is sent",
         false,
         {Call::SEND_COMMAND},
         false,
         {"command"},
         0,
         true},
        {"a controller command queued before a disconnect is not sent",
         false,
         {Call::SEND_COMMAND, Call::DISCONNECT},
         false,
         {user_goodbye},
         0,
         true},
        {"a controller command validated before its owner was torn down is not sent",
         false,
         {Call::SEND_COMMAND, Call::TEAR_DOWN_CONTROLLER},
         false,
         {},
         0,
         true},
        {"Control: a state change is published",
         false,
         {Call::SET_UNAVAILABLE},
         false,
         {"state"},
         0,
         false,
         true},
        {"a state change published before a disconnect is not sent",
         false,
         {Call::SET_UNAVAILABLE, Call::DISCONNECT},
         false,
         {user_goodbye},
         0,
         false,
         true},
        {"a disconnect only the final tick sees: the shutdown goodbye instead",
         false,
         {Call::DISCONNECT, Call::CLOSE_ADMISSION},
         false,
         {goodbye_event(SendspinGoodbyeReason::SHUTDOWN)}},
        {"a disconnect applied before admission closed: no second goodbye at the final tick",
         false,
         {Call::DISCONNECT_ON_TASK, Call::CLOSE_ADMISSION},
         false,
         {user_goodbye}},
    };
    const ClientCommandControllerObject play{.command = SendspinControllerCommand::PLAY};
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SilentListener silent;
        ASSERT_NE(silent.port(), 0);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ControllerRole& controller = client.add_controller();
        client.set_unpaired_access_enabled(true);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        ConnectionManager& manager = *client.connection_manager_;
        manager.liveness_timeout_us_ = 0;
        auto conn = std::make_shared<RecordingConnection>();
        conn->apply_server_activate({}, std::vector<std::string>{"player@v1", "controller@v1"},
                                    std::nullopt, std::nullopt);
        conn->set_client_hello_sent(row.operational);
        conn->set_server_hello_received(row.operational);
        manager.install_admitted(
            conn, row.owns_controller ? role_mask_bit(SendspinRole::CONTROLLER) : 0);
        auto offer_play = [&controller] {
            controller.impl_->supported_commands =
                (controller.impl_->cleanup_generation.load() << 16) |
                (1U << static_cast<uint8_t>(SendspinControllerCommand::PLAY));
        };
        offer_play();
        // The stamp send_command() passes along with a command it validated.
        auto current_stamp = [&controller] {
            return static_cast<uint16_t>(controller.impl_->cleanup_generation.load());
        };

        if (row.fill_queue) {
            for (size_t i = 0; i < ProtocolTask::CONSUMER_COMMAND_BURST; ++i) {
                ASSERT_TRUE(client.send_controller_command(play, current_stamp()))
                    << "request " << i;
            }
            EXPECT_FALSE(client.send_controller_command(play, current_stamp()))
                << "a send past the consumer burst must be refused";
            EXPECT_FALSE(controller.send_command(play))
                << "a controller command past the consumer burst must be refused";
        }
        for (const Call call : row.calls) {
            switch (call) {
                case Call::CONFIRM:
                    client.confirm_pairing_window();
                    break;
                case Call::CANCEL:
                    client.cancel_pairing_window();
                    break;
                case Call::LEAVE:
                    client.leave();
                    break;
                case Call::DISCONNECT:
                    client.disconnect(SendspinGoodbyeReason::USER_REQUEST);
                    break;
                case Call::DISCONNECT_AGAIN:
                    client.disconnect(SendspinGoodbyeReason::ANOTHER_SERVER);
                    break;
                case Call::DISCONNECT_ON_TASK:
                    // The task applying a disconnect before admission closes.
                    manager.disconnect(SendspinGoodbyeReason::USER_REQUEST);
                    break;
                case Call::UNPAIRED_OFF:
                    client.set_unpaired_access_enabled(false);
                    break;
                case Call::CONNECT:
                    client.connect_to(loopback_url(silent.port()));
                    break;
                case Call::SEND_COMMAND:
                    ASSERT_TRUE(controller.send_command(play));
                    break;
                case Call::TEAR_DOWN_CONTROLLER:
                    // The bump a switchover's cleanup() makes before it admits the new owner.
                    controller.impl_->cleanup_generation.fetch_add(1);
                    break;
                case Call::TICK:
                    (void) client.protocol_tick();
                    break;
                case Call::CLOSE_ADMISSION:
                    // What stop() does before the final tick it joins.
                    manager.close_admission();
                    break;
                case Call::SET_UNAVAILABLE:
                    client.set_available(false);
                    break;
            }
        }

        (void) client.protocol_tick();
        EXPECT_EQ(manager.pairing_window_open(), row.window_open);
        EXPECT_EQ(conn->events, row.events);
        EXPECT_EQ(manager.nursery_.size(), row.attempts) << "outbound attempts in the nursery";
        EXPECT_TRUE(manager.reaping_.empty()) << "an attempt was opened and then released";
        (void) client.protocol_tick();
        EXPECT_EQ(conn->events, row.events) << "a second tick applied a request again";

        // The drained queue takes sends again.
        offer_play();
        EXPECT_TRUE(controller.send_command(play));
        EXPECT_TRUE(client.send_controller_command(play, current_stamp()));

        silent.close();
        client.stop();
        EXPECT_FALSE(client.send_controller_command(play, current_stamp()))
            << "a stopped client refuses";
    }
}

// A disconnect frees the nursery slots it goodbyes before the accept queued with it is taken.
// The nursery holds connected inbound stand-ins whose client/init went out, as accept() leaves
// one; one tick takes the posted disconnect and the queued accept, requests first. The test
// thread plays the protocol task. An admitted newcomer is sent client/init, a refused one a
// goodbye. The no-disconnect control keeps the capacity check live.
TEST(ClientLifecycle, AnAcceptBehindADisconnectFindsTheNurserySlotsItFreed) {
    struct Row {
        const char* name;
        size_t occupants;
        bool disconnect;
        bool admitted;
    };
    const Row rows[] = {
        {"a full nursery behind a disconnect: admitted", ConnectionManager::NURSERY_CAPACITY, true,
         true},
        {"Control: a full nursery with no disconnect: refused", ConnectionManager::NURSERY_CAPACITY,
         false, false},
        {"Control: room in the nursery behind a disconnect: admitted",
         ConnectionManager::NURSERY_CAPACITY - 1, true, true},
    };
    const std::string user_goodbye = goodbye_event(SendspinGoodbyeReason::USER_REQUEST);
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        ConnectionManager& manager = *client.connection_manager_;

        std::vector<std::shared_ptr<RecordingConnection>> occupants;
        for (size_t i = 0; i < row.occupants; ++i) {
            auto occupant = std::make_shared<RecordingConnection>();
            // Inside its establish window, as accept() starts it, so the nursery scan keeps it.
            occupant->set_provisional_time_us(platform_time_us());
            manager.nursery_.push_back(NurseryEntry{.conn = occupant, .client_init_sent = true});
            occupants.push_back(occupant);
        }
        if (row.disconnect) {
            client.disconnect(SendspinGoodbyeReason::USER_REQUEST);
        }
        auto newcomer = std::make_shared<RecordingConnection>();
        // What the delivery sets before it queues the accept, for the client/init accept() sends.
        newcomer->set_json_arena(manager.json_arena());
        ProtocolCommand command;
        command.type = ProtocolCommandType::ACCEPT_CONNECTION;
        command.connection = newcomer;
        ASSERT_TRUE(client.protocol_task_->push_command(std::move(command)));

        (void) client.protocol_tick();
        const std::vector<std::string> newcomer_events =
            row.admitted
                ? std::vector<std::string>{"init"}
                : std::vector<std::string>{goodbye_event(SendspinGoodbyeReason::ANOTHER_SERVER)};
        EXPECT_EQ(newcomer->events, newcomer_events);
        for (const auto& occupant : occupants) {
            EXPECT_EQ(occupant->events, row.disconnect ? std::vector<std::string>{user_goodbye}
                                                       : std::vector<std::string>{});
        }

        client.stop();
    }
}

// is_connected() is raised only at the end of a tick, after every handler of that tick has run,
// so a thread that sees it true also sees the tick's whole effect (the published slots and the
// events it queued for the drain): a connection admitted (install_admitted(), which refreshes
// the published slots mid-handler) and made operational (on_handshake_complete(), which queues
// the trust event) reads as not yet connected until the tick ends. A loss lowers the flag at
// once, without a tick: the
// drop row refreshes and reads false. The test thread plays the protocol task. The stand-in is a
// LONG_TERM connection with its hellos and its activation done; the liveness check is off.
TEST(ClientLifecycle, TheConnectedFlagRisesOnlyAtTheEndOfTheTick) {
    for (const bool drop : {false, true}) {
        SCOPED_TRACE(drop ? "a drop lowers the flag without a tick" : "an admission raises it");
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        ConnectionManager& manager = *client.connection_manager_;
        manager.liveness_timeout_us_ = 0;
        auto conn = std::make_shared<StubConnection>();
        conn->set_noise_handshake_result("server", PskCategory::LONG_TERM, "psk");
        conn->set_client_hello_sent(true);
        conn->set_server_hello_received(true);
        conn->apply_server_activate({SendspinActivity::PLAYBACK}, std::vector<std::string>{},
                                    std::nullopt, std::nullopt);

        manager.install_admitted(conn, 0);
        EXPECT_FALSE(client.is_connected()) << "raised by the refresh inside the handler";
        client.on_handshake_complete(conn.get());
        EXPECT_FALSE(client.is_connected()) << "raised before the tick ended";
        (void) client.protocol_tick();
        ASSERT_TRUE(client.is_connected()) << "the end of the tick did not raise it";

        if (drop) {
            manager.drop_connection(conn.get(), std::nullopt);
            EXPECT_FALSE(client.is_connected()) << "a loss waited for the end of a tick";
        }
        client.stop();
    }
}

// ============================================================================
// The protocol task's next deadline
// ============================================================================

// SendspinTimeBurst::ms_until_due() is the burst's part of the protocol task's wait: the end of
// the interval between bursts, the timeout of the message in flight, or 0 when loop() has work
// now. The burst's state is staged directly; loop() moves it through these states over real time.
TEST(NextDeadline, TheTimeBurstReportsItsNextStep) {
    struct Row {
        const char* name;
        uint8_t burst_index;
        int64_t last_complete_ms;
        int64_t pending;
        int64_t sent_ms;
        bool completed;
        uint32_t expected_ms;
    };
    constexpr int64_t NOW_MS = 1'000'000;
    constexpr uint8_t SIZE = 8;
    constexpr int64_t INTERVAL_MS = 500;
    constexpr int64_t TIMEOUT_MS = 100;
    const Row rows[] = {
        {"between bursts", SIZE, NOW_MS - 200, 0, 0, false, 300},
        {"Control: the interval has elapsed", SIZE, NOW_MS - INTERVAL_MS, 0, 0, false, 0},
        {"a message in flight times out strictly after the timeout", 3, 0, 42, NOW_MS - 50, false,
         51},
        {"Control: ready to send the next message", 3, 0, 0, 0, false, 0},
        {"a completed burst is reported at once", SIZE, NOW_MS, 0, 0, true, 0},
        {"a far interval clamps short of NO_DEADLINE", SIZE, NOW_MS + (1LL << 40), 0, 0, false,
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
// a stopped server, whose timer is not armed; the running host server in the first has no
// upgrade reap to report (the ESP server's reap deadline, SendspinWsServer::tick(), only builds
// for ESP). The test thread plays the protocol task and stages each timer directly against a
// fixed clock.
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
        const bool server_down =
            row.stage == Stage::NETWORK_POLL || row.stage == Stage::SERVER_RETRY;
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

// An admitted connection's message longer than the ring takes waits in its fallback buffer until
// the ring item it wrote first has been taken. The tick whose ring pass takes that item finds the
// message due and asks to run again at once (it returns 0), so the next tick processes it without
// waiting for an unrelated wake; left waiting, the transport would drop the connection's next
// messages once its InboundGate::WRITABLE_WAIT_MS ran out. The Control row's second message fits
// the ring: nothing waits and the tick has no deadline. The client runs with no roles, so its ring
// is sized for JSON, and the stand-in has no Noise session, so the receive pass drops both
// messages unread; what is under test is when the pending message is taken.
TEST(NextDeadline, AFallbackMessageHeldBehindARingItemRunsTheNextTickAtOnce) {
    struct Row {
        const char* name;
        size_t extra_len;  // added to the ring's max_message_bytes()
        uint32_t first_tick;
    };
    const Row rows[] = {
        {"Control: the second message fits the ring", 0, ProtocolTask::NO_DEADLINE},
        {"the second message is longer than the ring takes", 1, 0},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        TestNetworkProvider network;
        SendspinClient client(make_config(0));
        client.set_network_provider(&network);
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();
        client.connection_manager_->liveness_timeout_us_ = 0;

        auto conn = std::make_shared<StubConnection>();
        conn->attach_inbound(client.inbound_ring_.get(), client.protocol_task_.get());
        client.connection_manager_->install_admitted(conn, 0);
        InboundGate& gate = conn->inbound_gate();

        // The transport side: a ring item, then the second message.
        const auto receive = [&](size_t len) {
            const auto target = conn->begin_inbound_message(len, false, platform_time_us());
            ASSERT_EQ(target.route, SendspinConnection::InboundRoute::RECEIVE);
            std::memset(target.data, 0x5A, len);
            conn->end_inbound_message(true);
        };
        receive(3);
        receive(client.inbound_ring_->max_message_bytes() + row.extra_len);
        EXPECT_EQ(gate.has_pending_message(), row.extra_len > 0);

        EXPECT_EQ(client.protocol_tick(), row.first_tick);
        EXPECT_EQ(gate.in_flight(), 0U) << "the ring pass left an item untaken";
        EXPECT_EQ(gate.has_pending_message(), row.extra_len > 0)
            << "the fallback message overtook the ring item ahead of it";

        (void)client.protocol_tick();
        EXPECT_FALSE(gate.has_pending_message()) << "the next tick left the message waiting";
        EXPECT_TRUE(gate.may_write());
        client.stop();
    }
}

// ============================================================================
// The main-loop teardown half
// ============================================================================

/// Records the callbacks of the roles that hold main-loop state, in the order they fire: "clear"
/// for a role's clear (the controller, metadata and color clears, the player's and the
/// visualizer's stream end, artwork's clear of channel 0), or "state <n>" for a state carrying n
/// (the controller's volume, the metadata year, the color's primary red, the player's volume or
/// its stream's sample rate in kHz, the visualizer stream's rate_max, the artwork channel
/// displayed). Main loop only, as every one of these callbacks is.
class StateRoleLog : public ControllerRoleListener,
                     public MetadataRoleListener,
                     public ColorRoleListener,
                     public PlayerRoleListener,
                     public VisualizerRoleListener,
                     public ArtworkRoleListener {
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
    size_t on_audio_write(uint8_t* /*data*/, size_t length, uint32_t /*timeout_ms*/) override {
        return length;
    }
    void on_stream_start() override {
        const uint32_t rate = this->player->get_current_stream_params().sample_rate.value_or(0);
        this->calls.push_back("state " + std::to_string(rate / 1000));
    }
    void on_stream_end() override {
        this->calls.push_back("clear");
    }
    void on_volume_changed(uint8_t volume) override {
        this->calls.push_back("state " + std::to_string(volume));
    }
    void on_visualizer_stream_start(const ServerVisualizerStreamObject& stream) override {
        this->visualizer_rate = static_cast<uint8_t>(stream.rate_max);
        this->calls.push_back("state " + std::to_string(stream.rate_max));
    }
    void on_visualizer_stream_end() override {
        this->visualizer_rate = 0;
        this->calls.push_back("clear");
    }
    void on_image_display(uint8_t slot, uint32_t /*lateness_ms*/) override {
        this->artwork_shown = slot;
        this->calls.push_back("state " + std::to_string(slot));
    }
    // A teardown clears every configured channel; one entry stands for the set.
    void on_image_clear(uint8_t slot) override {
        if (slot == 0) {
            this->artwork_shown = 0;
            this->calls.push_back("clear");
        }
    }

    std::vector<std::string> calls;
    PlayerRole* player{nullptr};
    uint8_t visualizer_rate{0};  ///< The started stream's rate_max, 0 once it ended
    uint8_t artwork_shown{0};    ///< The channel last displayed, 0 once cleared
};

/// One role with main-loop state, reached the way the protocol task (or, for artwork, the decode
/// thread) and the main loop reach it. `admit` is what the next connection's message produces
/// (the handler a server/state, server/command or stream/start reaches on the protocol task, or
/// the decode thread's display hand-off), `restore` writes the role's slot with an explicit stamp
/// (the payload a drain holds when it took the slot on the far side of a teardown) and, for a
/// role whose payload rides its STREAM_START, queues that START with the same stamp, `drain` is
/// the role's step of drain_inbox() (the catch-up alone for the visualizer, which has no drain),
/// and `applied` the state the role holds afterwards (0 when cleared). Each value is a state's
/// identifying number. `has_clear` is false for the player's commands, device state a teardown
/// keeps (`keeps_state`), so its rows expect no clear and A's value where a teardown clears.
struct StateRoleAccess {
    const char* name;
    void (*admit)(SendspinClient&, uint8_t value);
    void (*restore)(SendspinClient&, uint8_t value, uint32_t generation);
    void (*teardown)(SendspinClient&);
    void (*drain)(SendspinClient&);
    uint32_t (*generation)(SendspinClient&);
    uint8_t (*applied)(SendspinClient&, const StateRoleLog&);
    bool has_clear;
    bool keeps_state;
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

/// A PCM stream whose sample rate is `value` kHz: the player's state value.
ServerPlayerStreamObject player_stream_with(uint8_t value) {
    ServerPlayerStreamObject params;
    params.codec = SendspinCodecFormat::PCM;
    params.sample_rate = static_cast<uint32_t>(value) * 1000;
    params.channels = 2;
    params.bit_depth = 16;
    return params;
}

ServerCommandMessage player_volume_with(uint8_t value) {
    ServerPlayerCommandObject player_cmd;
    player_cmd.command = SendspinPlayerCommand::VOLUME;
    player_cmd.volume = value;
    ServerCommandMessage cmd;
    cmd.player = player_cmd;
    return cmd;
}

ServerVisualizerStreamObject visualizer_stream_with(uint8_t value) {
    ServerVisualizerStreamObject stream;
    stream.types = {VisualizerDataType::LOUDNESS};
    stream.rate_max = value;
    return stream;
}

/// The decode thread's hand-off of a display on artwork channel `value`, due at once, under the
/// channel's current epoch.
void write_artwork_display(SendspinClient& c, uint8_t value, uint32_t generation) {
    ArtworkRole::Impl& impl = *c.artwork_->impl_;
    ArtworkDisplayUpdate delta{};
    delta.epochs[value] = impl.slot_epochs[value].load();
    delta.valid_mask = static_cast<uint8_t>(1U << value);
    impl.event_state->display_slot.merge(ArtworkRole::Impl::merge_artwork_display_update,
                                         std::move(delta), generation);
}

const StateRoleAccess STATE_ROLES[] = {
    {"controller",
     [](SendspinClient& c, uint8_t v) {
         c.controller_->impl_->handle_server_state(controller_state_with(v));
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.controller_->impl_->event_state->slot.write(controller_state_with(v), g);
     },
     [](SendspinClient& c) { c.controller_->impl_->cleanup(); },
     [](SendspinClient& c) { c.controller_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.controller_->impl_->cleanup_generation.load(); },
     [](SendspinClient& c, const StateRoleLog&) {
         return c.controller_->impl_->controller_state.volume;
     },
     true, false},
    {"metadata",
     [](SendspinClient& c, uint8_t v) {
         c.metadata_->impl_->handle_server_state(metadata_state_with(v));
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.metadata_->impl_->event_state->slot.write(
             PendingMetadataStates{.oldest = metadata_state_with(v)}, g);
     },
     [](SendspinClient& c) { c.metadata_->impl_->cleanup(); },
     [](SendspinClient& c) { c.metadata_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.metadata_->impl_->cleanup_generation.load(); },
     [](SendspinClient& c, const StateRoleLog&) {
         return static_cast<uint8_t>(c.metadata_->impl_->metadata.year.value_or(0));
     },
     true, false},
    {"color",
     [](SendspinClient& c, uint8_t v) {
         c.color_->impl_->handle_server_state(color_state_with(v));
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.color_->impl_->event_state->slot.write(
             PendingColorStates{.oldest = color_state_with(v)}, g);
     },
     [](SendspinClient& c) { c.color_->impl_->cleanup(); },
     [](SendspinClient& c) { c.color_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.color_->impl_->cleanup_generation.load(); },
     [](SendspinClient& c, const StateRoleLog&) {
         return c.color_->impl_->color.primary.value_or(RgbColor{})[0];
     },
     true, false},
    {"player stream params",
     [](SendspinClient& c, uint8_t v) {
         c.player_->impl_->handle_stream_start(player_stream_with(v));
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         PlayerRole::Impl& impl = *c.player_->impl_;
         impl.event_state->stream_params_slot.write(player_stream_with(v), g);
         impl.enqueue_stream_event(PlayerStreamCallbackType::STREAM_START, g, 0);
     },
     [](SendspinClient& c) { c.player_->impl_->cleanup(); },
     [](SendspinClient& c) { c.player_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.player_->impl_->cleanup_generation.load(); },
     [](SendspinClient& c, const StateRoleLog&) {
         const PlayerRole::Impl& impl = *c.player_->impl_;
         if (!impl.stream_active) {
             return uint8_t{0};
         }
         return static_cast<uint8_t>(impl.current_stream_params.sample_rate.value_or(0) / 1000);
     },
     true, false},
    {"player command",
     [](SendspinClient& c, uint8_t v) {
         c.player_->impl_->handle_server_command(player_volume_with(v));
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         c.player_->impl_->event_state->command_slot.write(player_volume_with(v), g);
     },
     [](SendspinClient& c) { c.player_->impl_->cleanup(); },
     [](SendspinClient& c) { c.player_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.player_->impl_->cleanup_generation.load(); },
     [](SendspinClient& c, const StateRoleLog&) { return c.player_->impl_->volume; },
     false, true},
    {"visualizer stream config",
     [](SendspinClient& c, uint8_t v) {
         c.visualizer_->impl_->handle_stream_start(visualizer_stream_with(v));
     },
     [](SendspinClient& c, uint8_t v, uint32_t g) {
         VisualizerRole::Impl& impl = *c.visualizer_->impl_;
         impl.event_state->config_slot.write(visualizer_stream_with(v), g);
         impl.enqueue_stream_event(VisualizerEventType::STREAM_START, g);
     },
     [](SendspinClient& c) { c.visualizer_->impl_->cleanup(); },
     [](SendspinClient& c) {
         VisualizerRole::Impl& impl = *c.visualizer_->impl_;
         catch_up_teardown(impl, impl.cleanup_generation.load());
     },
     [](SendspinClient& c) { return c.visualizer_->impl_->cleanup_generation.load(); },
     [](SendspinClient&, const StateRoleLog& log) { return log.visualizer_rate; },
     true, false},
    {"artwork display",
     [](SendspinClient& c, uint8_t v) {
         write_artwork_display(c, v, c.artwork_->impl_->cleanup_generation.load());
     },
     write_artwork_display,
     [](SendspinClient& c) { c.artwork_->impl_->cleanup(); },
     [](SendspinClient& c) { c.artwork_->impl_->drain_events(); },
     [](SendspinClient& c) { return c.artwork_->impl_->cleanup_generation.load(); },
     [](SendspinClient&, const StateRoleLog& log) { return log.artwork_shown; },
     true, false},
};

/// A started client with every role that holds main-loop state, all reporting to `log`, whose
/// protocol task the test thread plays: role handlers and teardowns run on the test thread,
/// between the loop() calls the test makes. The player's sync task runs no thread: its item list
/// is bound to the ring the way SyncTask::start() binds it, so the player's STREAM_END never
/// waits for a thread to go idle and one loop() delivers it.
struct StateRoleClient {
    explicit StateRoleClient(StateRoleLog& log) : client(make_config(0)) {
        this->client.set_network_provider(&this->network);
        this->client.add_controller().set_listener(&log);
        this->client.add_metadata().set_listener(&log);
        this->client.add_color().set_listener(&log);
        PlayerRole& player = this->client.add_player(make_pcm_player_config());
        player.set_listener(&log);
        log.player = &player;
        this->client.add_visualizer(make_visualizer_config()).set_listener(&log);
        ArtworkRoleConfig artwork;
        for (uint8_t i = 0; i < ARTWORK_MAX_SLOTS; ++i) {
            artwork.preferred_formats.push_back(
                {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 100, 100, false});
        }
        this->client.add_artwork(std::move(artwork)).set_listener(&log);
        EXPECT_TRUE(this->client.start());
        this->client.protocol_task_->stop();
        SyncTask& sync = *this->client.player_->impl_->sync_task;
        InboundRing* ring = sync.inbound().ring();
        sync.stop();
        EXPECT_TRUE(sync.inbound().bind(ring, InboundHolder::PLAYER));
    }
    ~StateRoleClient() {
        // Hands the list back as SyncTask::stop() would, before stop() releases the ring.
        SyncTask& sync = *this->client.player_->impl_->sync_task;
        sync.inbound().unbind();
        this->client.stop();
    }

    TestNetworkProvider network;
    SendspinClient client;
};

// The teardown reorder guarantee, per role with main-loop state: the connection that owned a
// role is dropped (the role's cleanup() on the protocol task) and the next one delivers its state
// before the main loop runs. The next drain delivers the role's clear before the new state, and
// the new state survives: it is what the role holds afterwards. Two rows stage the interleavings
// a drain meets across the threads: the new state taken by a drain whose ring pass ran before the
// teardown queued its CLEARED event (the slot written between the generation bump and the
// drain), and a payload of the torn-down connection that a drain took on the far side of the
// teardown, which must never be applied after the clear. Both are staged by calling the role's
// drain step, and by writing the slot with the old stamp, through the private access the
// CMakeLists entry describes: no public call interleaves the threads on demand, and the order of
// the callbacks is the outcome. The last row fills the event ring so the teardown's CLEARED is
// dropped: the clear still fires on the next loop(), from the catch-up that heads every drain.
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
        {"Control: no teardown, the next state applies", Stage::CONTROL, {"state 2"}, 2},
        {"drop A, admit B, B's state, one loop()", Stage::ONE_LOOP, {"clear", "state 2"}, 2},
        {"B's state taken before its CLEARED is drained", Stage::TAKEN_BEFORE_ITS_CLEARED,
         {"clear", "state 2"},
         2},
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
            role.admit(client, 1);
            client.loop();
            ASSERT_EQ(log.calls, std::vector<std::string>{"state 1"});
            log.calls.clear();

            const uint32_t a_generation = role.generation(client);
            switch (row.stage) {
                case Stage::CONTROL:
                    role.admit(client, 2);
                    break;
                case Stage::ONE_LOOP:
                    role.teardown(client);
                    role.admit(client, 2);
                    break;
                case Stage::TAKEN_BEFORE_ITS_CLEARED:
                    role.teardown(client);
                    role.admit(client, 2);
                    role.drain(client);
                    break;
                case Stage::STALE_ACROSS:
                    role.teardown(client);
                    role.restore(client, 3, a_generation);
                    role.drain(client);
                    break;
                case Stage::CLEARED_DROPPED: {
                    // Fill the ring with an event that acts on nothing (a teardown marker every
                    // role has long caught up with), so the push in cleanup() is dropped with its
                    // warning.
                    InboxEvent filler{};
                    filler.type = InboxEventType::CONTROLLER_CLEARED;
                    // The client's Inbox, reached through the controller it is attached to.
                    while (client.controller_->impl_->inbox->push_event(filler)) {
                    }
                    role.teardown(client);
                    break;
                }
            }
            client.loop();

            std::vector<std::string> expected_calls = row.expected_calls;
            if (!role.has_clear) {
                expected_calls.erase(
                    std::remove(expected_calls.begin(), expected_calls.end(), "clear"),
                    expected_calls.end());
            }
            const uint8_t expected_applied =
                row.expected_applied == 0 && role.keeps_state ? 1 : row.expected_applied;
            EXPECT_EQ(log.calls, expected_calls);
            EXPECT_EQ(role.applied(client, log), expected_applied);
        }
    }
}

/// Calls stop(), and then start() when `restart` is set, from inside the first controller state
/// callback; records every state-role callback in `log`.
class StopFromCallbackListener : public StateRoleLog {
public:
    /// The callback that calls stop(): none, the controller's state or the player's stream end.
    enum class Reenter : uint8_t { NONE, CONTROLLER_STATE, STREAM_END };

    StopFromCallbackListener(SendspinClient*& client, Reenter reenter, bool restart)
        : client_(client), reenter_(reenter), restart_(restart) {}

    void on_controller_state(const ServerStateControllerObject& state) override {
        StateRoleLog::on_controller_state(state);
        this->reenter_from(Reenter::CONTROLLER_STATE);
    }
    void on_stream_end() override {
        StateRoleLog::on_stream_end();
        ++this->stream_ends;
        this->reenter_from(Reenter::STREAM_END);
    }

    bool restart_result{false};
    int stream_ends{0};

private:
    void reenter_from(Reenter callback) {
        if (this->reenter_ == callback && !this->reentered_) {
            this->reentered_ = true;
            this->client_->stop();
            if (this->restart_) {
                this->restart_result = this->client_->start();
            }
        }
    }

    SendspinClient*& client_;
    Reenter reenter_;
    bool restart_;
    bool reentered_{false};
};

// A listener may call stop(), and start() after it, from inside a callback a loop() drain fires.
// stop() tears every role down and delivers each clear exactly once from its own drain; the drain
// that fired the callback then abandons the rest of its work, so the metadata state queued beside
// the controller's is never delivered, after its clear or at all. A stop() from on_stream_end()
// owes no second on_stream_end(): the stream it ends is already closed. Control: without the
// re-entry both states are delivered.
TEST(ClientLifecycle, StopFromInsideADrainCallbackIsSafe) {
    using Reenter = StopFromCallbackListener::Reenter;
    struct Row {
        const char* name;
        Reenter reenter;
        bool restart;
        std::vector<std::string> expected_calls;
        bool expected_started;
        int expected_stream_ends;
    };
    const Row rows[] = {
        {"Control: no re-entry", Reenter::NONE, false, {"state 11", "state 5"}, true, 0},
        {"stop()", Reenter::CONTROLLER_STATE, false, {"state 11", "clear", "clear"}, false, 0},
        {"stop() then start()", Reenter::CONTROLLER_STATE, true, {"state 11", "clear", "clear"},
         true, 0},
        {"stop() from on_stream_end()", Reenter::STREAM_END, false,
         {"state 48", "clear", "clear", "clear"}, false, 1},
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
        PlayerRole& player = client.add_player(make_pcm_player_config());
        player.set_listener(&log);
        log.player = &player;
        ASSERT_TRUE(client.start());
        client.protocol_task_->stop();

        if (row.reenter == Reenter::STREAM_END) {
            PlayerRole::Impl& impl = *player.impl_;
            ServerPlayerStreamObject params;
            params.codec = SendspinCodecFormat::PCM;
            params.sample_rate = 48000;
            params.channels = 2;
            params.bit_depth = 16;
            impl.handle_stream_start(params);
            pump_until(client, [&] { return impl.sync_task->is_running(); });
            impl.handle_stream_end();
            pump_until(client, [&] { return !client.is_started(); });
        } else {
            client.controller_->impl_->handle_server_state(controller_state_with(11));
            client.metadata_->impl_->handle_server_state(metadata_state_with(5));
            client.loop();
        }

        EXPECT_EQ(log.calls, row.expected_calls);
        EXPECT_EQ(log.stream_ends, row.expected_stream_ends);
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

/// Whether the burst has written a client/time frame: send_time_message() seeds the frame's write
/// time (never 0) before handing it to the transport. The stand-in has no Noise session, so the
/// frame goes no further than that; the seed is the one trace a written frame leaves that another
/// thread may read (an atomic, unlike the frame's tag).
int time_frames_written(const SendspinConnection& conn) {
    return conn.time_frame_sent_us_.load() != 0 ? 1 : 0;
}

// A time burst requests the high-performance hold when it comes due and sends its first
// time frame only once the main loop has granted the request (called the listener); its release
// waits for nothing, and an acquire and a release queued inside one stalled main-loop tick still
// reach the listener as a request followed by its release. The test thread plays the protocol
// task (run_time_sync(), on a stand-in connection in the admitted slot) and the main loop
// (loop()), so a frame that must not be sent yet is proven unsent by the tick having returned
// without writing it, not by a wait; the stand-in's frame write time is read for the reason given
// at time_frames_written(). The Control row's burst is not due, so nothing is requested.
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

// Destroying a running client ends every high-performance hold with the client: a hold the main
// loop granted is released exactly once, beside the release the shutdown pass queues for it, and
// a request no drain applied (the main loop never called the listener for it) reaches the
// listener as neither a request nor a release. The test thread plays the protocol task
// (run_time_sync() on a stand-in connection in the admitted slot, then the final tick's shutdown
// pass) and the main loop, so the request is provably queued and, in the second row, provably
// never drained. The granted row is the Control.
TEST(HighPerformanceGrant, DestroyingTheClientReleasesOnlyAGrantedHold) {
    struct Row {
        const char* name;
        bool granted;
        std::vector<std::string> expected_edges;
    };
    const Row rows[] = {
        {"Control: a granted hold is released exactly once", true, {"request", "release"}},
        {"an ungranted request is never heard", false, {}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        HighPerformanceLog log;  // Outlives the client, as the listener contract requires
        {
            TestNetworkProvider network;
            SendspinClient client(make_config(0));
            client.set_network_provider(&network);
            client.set_listener(&log);
            ASSERT_TRUE(client.start());
            client.protocol_task_->stop();
            ConnectionManager& manager = *client.connection_manager_;
            auto conn = std::make_shared<OperationalStubConnection>();
            manager.install_admitted(conn, 0);

            (void) manager.run_time_sync();  // The burst comes due and requests the hold
            ASSERT_TRUE(manager.find_admitted(conn.get())->high_performance_held)
                << "the burst requested no hold";
            if (row.granted) {
                client.loop();
                ASSERT_EQ(log.edges, std::vector<std::string>{"request"});
            }
            // The destructor's order with the task played here: admission closes, then the
            // task's final tick runs the shutdown pass, which queues the hold's release.
            manager.close_admission();
            (void) client.protocol_tick();
            // Destroyed here, the hold granted or the request still queued.
        }
        EXPECT_EQ(log.edges, row.expected_edges);
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
// Stream starts and ends drained in one tick
// ============================================================================

// Each stream/start numbers its codec header and its STREAM_START, and the sync task starts a
// stream only on the main loop's acknowledgement of that stream's number, so stream events the
// main loop drains together, however the sync task interleaved with them, still end each stream
// before the next one starts: every held STREAM_END is released and the last stream plays under
// its own on_stream_start(). The test thread plays the protocol task, so the stream events are
// all queued before the main loop runs. The "start and its end" row stages the interleaving where
// the acknowledgement finds no header left (the sync task took the header, met the end and went
// back to waiting); the other rows leave the sync task free to interleave as it will, since the
// outcome must not depend on it. Every wait has no timeout: a held end that is never released, or
// a stream started under an earlier stream's acknowledgement (which holds the end behind it while
// it plays), hangs here and the suite watchdog names this test.
TEST(ClientLifecycle, StreamEventsDrainedTogetherStartEachStreamOnItsOwnStart) {
    enum class Stage : uint8_t {
        ONE_START,
        START_END,
        START_CLEAR,
        START_END_START,
        PLAYING_END_START_END_START,
    };
    struct Row {
        const char* name;
        Stage stage;
        int expected_starts;
        int expected_ends;
        bool expected_running;
    };
    const Row rows[] = {
        {"Control: a start drained on its own", Stage::ONE_START, 1, 0, true},
        {"a start and its end, the header already returned", Stage::START_END, 1, 1, false},
        {"a start and a clear before its acknowledgement", Stage::START_CLEAR, 1, 0, true},
        {"a start, its end and the next start", Stage::START_END_START, 2, 1, true},
        {"a playing stream's end, a start, its end and the next start",
         Stage::PLAYING_END_START_END_START, 3, 2, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
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
        const auto start = [&] {
            player.handle_stream_start(params);
        };
        const auto end = [&] { player.handle_stream_end(); };

        switch (row.stage) {
            case Stage::ONE_START:
                start();
                break;
            case Stage::START_END:
                // The sync task takes the header and waits; the end makes it return the header
                // and go idle before the main loop acknowledges the start.
                start();
                wait_until([&] { return sync.inbound().items().is_empty(); });
                end();
                wait_until([&] {
                    return (player.inbox->poll() & INBOX_TOPIC_PLAYER_SYNC_IDLE) != 0;
                });
                break;
            case Stage::START_CLEAR:
                // The sync task takes the header and waits; the clear reaches it there, and the
                // stream it holds still plays once acknowledged. The wait is for the clear being
                // applied, not for an empty list: the flag goes up before the marker is handed, so
                // the sync task may apply the clear first and leave the marker for the active
                // stream to take.
                start();
                wait_until([&] { return sync.inbound().items().is_empty(); });
                player.handle_stream_clear();
                wait_until([&] { return (sync.event_flags_.get() & COMMAND_STREAM_CLEAR) == 0; });
                break;
            case Stage::START_END_START:
                start();
                end();
                start();
                break;
            case Stage::PLAYING_END_START_END_START:
                start();
                pump_until(client, [&] { return sync.is_running(); });
                end();
                start();
                end();
                start();
                break;
        }
        pump_until(client, [&] {
            return listener.stream_starts == row.expected_starts &&
                   listener.stream_ends == row.expected_ends &&
                   sync.is_running() == row.expected_running;
        });

        if (row.stage == Stage::START_END) {
            // The next stream starts on its own start, not on the stale one.
            start();
            pump_until(client, [&] { return listener.stream_starts == 2 && sync.is_running(); });
            EXPECT_EQ(listener.stream_ends, 1);
        }
        client.stop();
        EXPECT_EQ(listener.stream_ends, listener.stream_starts)
            << "every on_stream_start() is paired with an on_stream_end() by stop()";
    }
}

// A codec header the sync task takes while the stream before it is still ACTIVE, the end of that
// stream signalled and the next stream/start's header appended before the task's next take,
// starts the next stream from IDLE instead of being decoded into the stream that ended. The test
// thread plays the sync task: its IDLE take of the first header, the ordinal ACTIVE records for
// it, its next ACTIVE load, then its next IDLE wait. Control: a stream/start with no end between
// is the active stream's own format change, loaded to be decoded in place.
TEST(ClientLifecycle, AHeaderTakenAfterTheActiveStreamEndedStartsTheNextStream) {
    struct Row {
        const char* name;
        bool end_first;
        bool expected_loaded_in_place;
    };
    const Row rows[] = {
        {"Control: a format change of the active stream", false, true},
        {"the next stream's header, taken before the end is seen", true, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        StateRoleLog log;
        StateRoleClient harness(log);
        PlayerRole::Impl& player = *harness.client.player_->impl_;
        SyncTask& sync = *player.sync_task;
        sync.event_flags_.clear_all();  // As SyncTask::start() leaves them
        ServerPlayerStreamObject params;
        params.codec = SendspinCodecFormat::PCM;
        params.sample_rate = 48000;
        params.channels = 2;
        params.bit_depth = 16;
        const auto start = [&] {
            player.handle_stream_start(params);
        };

        start();
        SyncContext context;
        ASSERT_TRUE(sync.wait_for_codec_header(context));
        context.active_ordinal = inbound_item_header(context.encoded_item)->serial;
        sync.inbound().return_item(context.encoded_item);  // Decoded: the stream is playing
        context.encoded_item = nullptr;
        if (row.end_first) {
            player.handle_stream_end();
        }
        start();

        EXPECT_EQ(sync.load_next_chunk(context), row.expected_loaded_in_place);
        EXPECT_EQ(context.encoded_item != nullptr, row.expected_loaded_in_place);
        if (!row.expected_loaded_in_place) {
            ASSERT_TRUE(sync.wait_for_codec_header(context)) << "the next stream lost its header";
            EXPECT_EQ(inbound_item_header(context.encoded_item)->serial, player.stream_ordinal);
        }
        for (void* held : {context.encoded_item, context.next_header}) {
            if (held != nullptr) {
                sync.inbound().return_item(held);
            }
        }
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
    InboundRing* ring = sync_task.inbound().ring();
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
        ring->complete(item);
        // Over quota, hand() returns the item itself.
        (void)sync_task.inbound().hand(item, message.size(),
                                       {.data_len = static_cast<uint32_t>(SINK_CHUNK_BYTES),
                                        .serial = 0,
                                        .type = CHUNK_TYPE_ENCODED_AUDIO,
                                        .data_offset = FRAME_OFFSET},
                                       impl.cleanup_generation.load(std::memory_order_acquire),
                                       /*exempt=*/false);
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
                  drain_ring_as_protocol_task(*impl.sync_task->inbound().ring(), connections);
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
    void disconnect(SendspinGoodbyeReason) override {
        this->obs_->goodbyes.fetch_add(1);
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
    impl.handle_stream_start(pcm_stream_params());
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
    conn->get_time_filter()->update(SEEDED_SERVER_OFFSET_US, /*max_error=*/1000,
                                    platform_time_us());
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
// is freed memory, and the process crashes or is reported by AddressSanitizer. The test thread
// plays the protocol task, so nothing takes the item in ring order before the destructor.
TEST(ClientLifecycle, DestroyingARunningClientWithAReturnedLocalItemIsClean) {
    CountingPlayerListener listener;
    TestNetworkProvider network;
    auto client = std::make_unique<SendspinClient>(make_stand_in_config(0));
    client->set_network_provider(&network);
    client->add_player(make_pcm_player_config()).set_listener(&listener);
    ASSERT_TRUE(client->start());
    play_protocol_task(*client);

    PlayerRole::Impl& impl = *client->player_->impl_;
    InboundRing& ring = *impl.sync_task->inbound().ring();
    std::vector<uint8_t> chunk(13 + 4, 0x00);
    chunk[0] = SENDSPIN_BINARY_PLAYER_AUDIO;
    InboundMessage message;
    message.data = chunk.data();
    message.len = chunk.size();
    impl.handle_binary(message);
    // The idle sync task may already have discarded the chunk and emptied the quota, so the
    // hand-over is read from state the sync thread cannot change: the chunk was copied into the
    // ring, where it waits for a ring-order take only this thread (as the protocol task) makes,
    // and was not dropped, which an over-quota hand-over does after the copy.
    size_t waiting = 0;
    {
        std::lock_guard<std::mutex> lock(ring.ring_.mtx_);
        waiting = ring.ring_.items_waiting_;
    }
    ASSERT_EQ(waiting, 1U) << "the chunk was never copied into the ring";
    ASSERT_EQ(impl.sync_task->inbound().drop_log_.dropped_, 0U)
        << "the chunk was copied but dropped instead of handed to the sync task";

    // The idle sync task discards a chunk with no stream behind it, which is its holder's return.
    wait_until([&] { return ring.quota(InboundHolder::PLAYER).outstanding() == 0; });
    client.reset();
}

// The ring's floor and the longest message it takes follow the enabled roles: a 16 KiB JSON
// message every admitted connection can be sent, the longest chunk the player's and the
// visualizer's advertised buffers let the server send, and a maximal Noise frame with the artwork
// role, whatever its image cap: the server sends a refused image's bytes in maximal frames too.
// A client without the player or artwork is floored at two JSON messages (2 x 16,440 =
// 32,880 bytes) instead of two maximal frames (131,152), and a small player's ring follows its
// buffer: 25,000 bytes advertise 16,666, so its chunks are at most 16,682 bytes with the tag and
// the ring is 25,000 + 5,568 held pass-through + 2 x 16,724 = 64,016 bytes; a visualizer
// advertising a seventh of 140,000 bytes is sent messages of up to 20,016, and at 30 loudness
// frames a second (2,040 stored bytes) holds its oldest for 69 s, which pins 69 s of state JSON
// and 7 time bursts behind it (70,656 + 17,472 bytes). Every ring also carries a baseline of two
// of its longest messages that can sit behind a held item (2 x 65,576 bytes with artwork). The
// artwork role adds its quota of one image per channel in flight, sent in parts of at least
// 4,096 bytes (133,024 stored bytes for one default 128 KiB channel: the image plus 61 bytes for
// each of 32 parts; 40,610 for a 40,000-byte one in 10 parts), and behind the player's 87 s hold
// two more returned images (one per 30 s). Controller and metadata hold nothing, so they leave
// the no-role budget unchanged. The time replies follow the configured burst cadence:
// the default player syncing every second instead of every 10 s holds 88 bursts of 8 replies
// (312 stored bytes each) behind its 87 s hold instead of 9. Read from the ring the client
// creates, so every role's figures and the burst configuration have to reach the derivation.
// Each row also reads the buffer_capacity the stream roles' client/hello advertises, which never
// exceeds the ring's largest item, so any one chunk the server may send fits an item: the default
// player's two-thirds share (666,666 bytes) is capped at the default ring's 621,312, while the
// 25,000-byte player's 16,666, the default player's share in the larger rings and the
// visualizer's seventh stay as derived.
TEST(ClientLifecycle, TheInboundRingFollowsTheEnabledRoles) {
    enum : uint8_t {
        PLAYER = 1 << 0,
        SMALL_PLAYER = 1 << 1,
        VISUALIZER = 1 << 2,
        ARTWORK = 1 << 3,
        SMALL_ARTWORK = 1 << 4,
        CONTROLLER_METADATA = 1 << 5,
        LARGE_VISUALIZER = 1 << 6,
    };
    struct Row {
        const char* name;
        uint8_t roles;
        size_t expected_bytes;
        size_t expected_max_message_bytes;
        /// The buffer_capacity each stream role's client/hello advertises; 0 without the role.
        size_t expected_player_advertised;
        size_t expected_visualizer_advertised;
        int64_t burst_interval_ms{SendspinClientConfig::DEFAULT_BURST_INTERVAL_MS};
    };
    const Row rows[] = {
        {"no roles: two JSON messages", 0, 32880, 16400, 0, 0},
        {"controller and metadata: the no-role budget", CONTROLLER_METADATA, 32880, 16400, 0, 0},
        {"visualizer only: its 4,096-byte quota, 3 s of pass-through, the JSON floor", VISUALIZER,
         42544, 21232, 0, 585},
        {"a 140,000-byte visualizer: 69 s of pass-through, two 20,016-byte messages",
         LARGE_VISUALIZER, 268240, INBOUND_MAX_MESSAGE_BYTES, 0, 20000},
        {"a 25,000-byte player: two of its longest chunks, its share advertised uncapped",
         SMALL_PLAYER, 64016, 31968, 16666, 0},
        {"artwork only: one default image in flight and the two-frame baseline", ARTWORK, 264176,
         INBOUND_MAX_MESSAGE_BYTES, 0, 0},
        {"artwork capped at 40,000-byte images: one in flight and the baseline", SMALL_ARTWORK,
         171764, INBOUND_MAX_MESSAGE_BYTES, 0, 0},
        {"Control: the default player, its advertised share capped at the ring's largest item",
         PLAYER, 1242704, INBOUND_MAX_MESSAGE_BYTES, 621312, 0},
        {"the default player, a time burst every second: its share fits the larger ring", PLAYER,
         1439888, INBOUND_MAX_MESSAGE_BYTES, 666666, 0, 1000},
        {"every role", PLAYER | VISUALIZER | ARTWORK | CONTROLLER_METADATA, 1823352,
         INBOUND_MAX_MESSAGE_BYTES, 666666, 585},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        TestNetworkProvider network;
        SendspinClientConfig config = make_config(0);
        config.time_burst_interval_ms = row.burst_interval_ms;
        SendspinClient client(config);
        client.set_network_provider(&network);
        if ((row.roles & (PLAYER | SMALL_PLAYER)) != 0) {
            PlayerRoleConfig player = make_pcm_player_config();
            player.audio_buffer_capacity = (row.roles & PLAYER) != 0
                                               ? PlayerRoleConfig::DEFAULT_AUDIO_BUFFER_CAPACITY
                                               : 25000;
            client.add_player(player);
        }
        if ((row.roles & (VISUALIZER | LARGE_VISUALIZER)) != 0) {
            VisualizerRoleConfig visualizer = make_visualizer_config();
            if ((row.roles & LARGE_VISUALIZER) != 0) {
                visualizer.support.buffer_capacity = 140000;
            }
            client.add_visualizer(std::move(visualizer));
        }
        if ((row.roles & (ARTWORK | SMALL_ARTWORK)) != 0) {
            ArtworkRoleConfig artwork;
            artwork.preferred_formats.push_back(
                {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 100, 100, false});
            if ((row.roles & SMALL_ARTWORK) != 0) {
                artwork.preferred_formats.back().max_image_bytes = 40000;
            }
            client.add_artwork(artwork);
        }
        if ((row.roles & CONTROLLER_METADATA) != 0) {
            client.add_controller();
            client.add_metadata();
        }
        ASSERT_TRUE(client.start());
        EXPECT_EQ(client.inbound_ring_->storage_.size(), row.expected_bytes);
        EXPECT_EQ(client.inbound_ring_->max_message_bytes(), row.expected_max_message_bytes);
        // The local-copy bound is the physical one alone, the Noise-frame cap being a fact about
        // received messages only.
        EXPECT_EQ(client.inbound_ring_->max_item_message_bytes(),
                  SharedRingLayout::max_item_size(row.expected_bytes) - sizeof(InboundItemHeader));
        ClientHelloMessage hello;
        if (client.player_) {
            client.player_->impl_->build_hello_fields(hello);
        }
        if (client.visualizer_) {
            client.visualizer_->impl_->build_hello_fields(hello);
        }
        EXPECT_EQ(hello.player_v1_support ? hello.player_v1_support->buffer_capacity : 0U,
                  row.expected_player_advertised);
        EXPECT_EQ(hello.visualizer_support ? hello.visualizer_support->buffer_capacity : 0U,
                  row.expected_visualizer_advertised);
        client.stop();
    }
}

}  // namespace
