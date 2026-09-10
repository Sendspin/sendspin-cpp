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

/// @file test_client_lifecycle.cpp
/// @brief start() / stop() / restart of a SendspinClient: peers are goodbyed, role state is
/// reset and its clear callbacks delivered before stop() returns, a restarted client is live
/// again, and a callback fired from inside stop() cannot recurse into the lifecycle.
///
/// The client is driven on loopback ports like test_connection_lifecycle.cpp: an IXWebSocket
/// endpoint plays the Sendspin server and the test thread pumps client.loop().

#include "connection_manager.h"  // GoodbyeWait, GOODBYE_FLUSH_TIMEOUT_MS
#include "platform/time.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/metadata_role.h"
#include "sendspin/player_role.h"

#include <gtest/gtest.h>
#include <ixwebsocket/IXWebSocket.h>

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
// (and into test_connection_lifecycle.cpp, which uses 18941-18982).
constexpr uint16_t RESTART_TEST_PORT = 18991;
constexpr uint16_t NURSERY_GOODBYE_TEST_PORT = 18992;
constexpr uint16_t STREAM_TEST_PORT = 18993;
constexpr uint16_t CALLBACK_TEST_PORT = 18994;
constexpr uint16_t DESTRUCTOR_TEST_PORT = 18995;

std::string server_url(uint16_t port) {
    return "ws://127.0.0.1:" + std::to_string(port) + "/sendspin";
}

SendspinClientConfig make_config(uint16_t port) {
    SendspinClientConfig config;
    config.client_id = "lifecycle-test-client";
    config.name = "Lifecycle Test Client";
    config.server_port = port;
    return config;
}

class TestNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override {
        return true;
    }
};

// Pumps client.loop() until pred() is true. No timeout: a regression hangs here and the suite
// watchdog reports it.
void pump_until(SendspinClient& client, const std::function<bool()>& pred) {
    for (;;) {
        client.loop();
        if (pred()) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

// Pumps client.loop() for a fixed window. Only for "must not happen" checks: a window that is
// too short can miss a regression, never fail a correct run.
void pump_for(SendspinClient& client, int duration_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(duration_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        client.loop();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
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

/// Behavior knobs for FakeServer.
struct FakeServerOptions {
    bool answer_hello{true};  ///< Reply to client/hello with server/hello (false: a peer that
                              ///< upgrades and then never establishes, so it stays in the nursery)
};

/// A minimal Sendspin server: an IXWebSocket client that connects to the SendspinClient's WS
/// server, answers client/hello with server/hello, answers client/time with a server/time whose
/// clock is the client's own (both sides read platform_time_us(), so the offset is ~0 and audio
/// timestamps mean what they say), and records the goodbye and close.
class FakeServer {
public:
    FakeServer(const std::string& url, std::string server_id, FakeServerOptions options = {})
        : server_id_(std::move(server_id)) {
        this->ws_.setUrl(url);
        this->ws_.disableAutomaticReconnection();
        this->ws_.setOnMessageCallback([this, options](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message) {
                const std::string& text = msg->str;
                if (text.find("client/hello") != std::string::npos) {
                    this->got_client_hello_.store(true);
                    if (options.answer_hello) {
                        this->ws_.send(
                            std::string(R"({"type":"server/hello","payload":{"server_id":")") +
                            this->server_id_ +
                            R"(","name":"Fake Server","version":1,"active_roles":["player"],)" +
                            R"("connection_reason":"discovery"}})");
                    }
                } else if (text.find("client/time") != std::string::npos) {
                    const auto pos = text.find("\"client_transmitted\":");
                    if (pos != std::string::npos) {
                        const long long client_transmitted =
                            std::strtoll(text.c_str() + pos + 21, nullptr, 10);
                        const int64_t now = platform_time_us();
                        this->ws_.send(std::string(R"({"type":"server/time","payload":{)") +
                                       "\"client_transmitted\":" +
                                       std::to_string(client_transmitted) +
                                       ",\"server_received\":" + std::to_string(now) +
                                       ",\"server_transmitted\":" + std::to_string(now) + "}}");
                    }
                } else if (text.find("client/goodbye") != std::string::npos) {
                    this->got_goodbye_.store(true);
                }
            } else if (msg->type == ix::WebSocketMessageType::Close ||
                       msg->type == ix::WebSocketMessageType::Error) {
                this->closed_.store(true);
            }
        });
        this->ws_.start();
    }

    ~FakeServer() {
        this->ws_.stop();
    }

    void send_text(const std::string& text) {
        this->ws_.send(text);
    }

    /// Sends one player audio chunk: binary type 4, big-endian server timestamp, PCM payload.
    void send_audio(int64_t timestamp_us, size_t payload_bytes) {
        std::string frame;
        frame.push_back(static_cast<char>(4));
        for (int shift = 56; shift >= 0; shift -= 8) {
            frame.push_back(static_cast<char>((timestamp_us >> shift) & 0xFF));
        }
        frame.append(payload_bytes, '\0');
        this->ws_.sendBinary(frame);
    }

    bool closed() const {
        return this->closed_.load();
    }

    bool got_client_hello() const {
        return this->got_client_hello_.load();
    }

    bool got_goodbye() const {
        return this->got_goodbye_.load();
    }

private:
    ix::WebSocket ws_;
    std::string server_id_;
    std::atomic<bool> closed_{false};
    std::atomic<bool> got_client_hello_{false};
    std::atomic<bool> got_goodbye_{false};
};

/// Blocks until pred() is true without pumping the client (for checks on a stopped client).
void wait_until(const std::function<bool()>& pred) {
    while (!pred()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
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
        this->start_result_during_clear = this->client_.start();
        this->client_.stop();  // Must be ignored, not recurse
    }

    int clears{0};
    bool started_during_clear{true};
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

PlayerRoleConfig make_player_config() {
    PlayerRoleConfig player_cfg;
    player_cfg.audio_formats.push_back({SendspinCodecFormat::PCM, 2, 48000, 16});
    player_cfg.audio_buffer_capacity = 64 * 1024;
    return player_cfg;
}

// Pumps until the peer has written at least `target` audio callbacks, feeding 20 ms PCM chunks
// stamped a little ahead of now so the sync task has something to schedule.
void stream_audio_until(SendspinClient& client, FakeServer& server, CountingPlayerListener& listener,
                        size_t target) {
    constexpr size_t PCM_20MS_BYTES = 48000 / 50 * 2 * 2;
    int64_t next_ts = platform_time_us() + 50 * 1000;
    pump_until(client, [&] {
        if (listener.audio_writes.load() >= target) {
            return true;
        }
        server.send_audio(next_ts, PCM_20MS_BYTES);
        next_ts += 20 * 1000;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));  // real-time pacing
        return false;
    });
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
// its handshake. Also pins start() as idempotent while running and stop() as a no-op when
// stopped.
TEST(ClientLifecycle, RestartYieldsALiveClient) {
    TestNetworkProvider network;
    SendspinClient client(make_config(RESTART_TEST_PORT));
    client.set_network_provider(&network);

    EXPECT_FALSE(client.is_started());
    client.stop();  // No-op when stopped
    EXPECT_FALSE(client.is_started());

    for (int cycle = 0; cycle < 3; ++cycle) {
        ASSERT_TRUE(client.start());
        EXPECT_TRUE(client.start());  // Already running: reports true, starts nothing twice
        EXPECT_TRUE(client.is_started());

        const std::string server_id = "server-" + std::to_string(cycle);
        FakeServer server(server_url(RESTART_TEST_PORT), server_id);
        pump_until(client, [&] { return client.is_connected(); });
        auto info = client.get_server_information();
        ASSERT_TRUE(info.has_value());
        EXPECT_EQ(info->server_id, server_id);

        // Some group state for stop() to reset.
        server.send_text(R"({"type":"group/update","payload":{"playback_state":"playing"}})");
        pump_until(client, [&] {
            return client.get_group_state().playback_state.has_value();
        });

        client.stop();

        EXPECT_FALSE(client.is_started());
        EXPECT_FALSE(client.is_connected());
        EXPECT_FALSE(client.get_server_information().has_value());
        EXPECT_FALSE(client.get_group_state().playback_state.has_value());
        // The peer received its goodbye and the close, in that order.
        wait_until([&] { return server.closed(); });
        EXPECT_TRUE(server.got_goodbye());

        // Stopped means quiescent: pumping loop() must not bring the server back up.
        pump_for(client, 100);
        EXPECT_FALSE(port_accepts(RESTART_TEST_PORT));
    }
}

// A peer still in the nursery (it upgraded but never answered the hello) gets the same goodbye and
// close as the established one, so no peer is left to discover the shutdown by timeout.
TEST(ClientLifecycle, StopGoodbyesNurseryPeersToo) {
    TestNetworkProvider network;
    SendspinClient client(make_config(NURSERY_GOODBYE_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start());

    FakeServer established(server_url(NURSERY_GOODBYE_TEST_PORT), "server-established");
    pump_until(client, [&] { return client.is_connected(); });

    FakeServer mute(server_url(NURSERY_GOODBYE_TEST_PORT), "server-mute",
                    FakeServerOptions{.answer_hello = false});
    pump_until(client, [&] { return mute.got_client_hello(); });

    client.stop();

    wait_until([&] { return established.closed() && mute.closed(); });
    EXPECT_TRUE(established.got_goodbye());
    EXPECT_TRUE(mute.got_goodbye());
}

// With a stream playing, stop() ends it (on_stream_end() fires before stop() returns, paired with
// the earlier on_stream_start()) and a restarted client plays a new stream: audio reaches the
// listener again, which needs the sync task thread to have been re-created, not just the server.
TEST(ClientLifecycle, StopEndsTheStreamAndRestartPlaysAgain) {
    TestNetworkProvider network;
    CountingPlayerListener listener;
    auto config = make_config(STREAM_TEST_PORT);
    config.time_burst_interval_ms = 100;  // Sync promptly after each (re)connect
    SendspinClient client(std::move(config));
    client.set_network_provider(&network);
    client.add_player(make_player_config()).set_listener(&listener);

    for (int cycle = 0; cycle < 2; ++cycle) {
        ASSERT_TRUE(client.start());
        FakeServer server(server_url(STREAM_TEST_PORT), "server-" + std::to_string(cycle));
        pump_until(client, [&] { return client.is_connected(); });

        server.send_text(stream_start_pcm_json());
        pump_until(client, [&] { return listener.stream_starts == cycle + 1; });
        EXPECT_EQ(listener.stream_ends, cycle);

        // Audio flowing proves the sync task thread is alive in this cycle.
        const size_t writes_before = listener.audio_writes.load();
        stream_audio_until(client, server, listener, writes_before + 1);

        client.stop();

        // The clear callback was delivered inside stop(), not left for a loop() tick.
        EXPECT_EQ(listener.stream_ends, cycle + 1);
        EXPECT_EQ(listener.stream_starts, cycle + 1);
        wait_until([&] { return server.closed(); });
        EXPECT_TRUE(server.got_goodbye());
    }
}

// A listener callback fired from inside stop() cannot re-enter the lifecycle: start() reports
// failure and starts nothing, stop() is ignored rather than recursing, and the client reads as
// stopped. Afterwards the client restarts normally.
TEST(ClientLifecycle, CallbackDuringStopCannotRecurse) {
    TestNetworkProvider network;
    SendspinClient client(make_config(CALLBACK_TEST_PORT));
    client.set_network_provider(&network);
    ReentrantMetadataListener listener(client);
    client.add_metadata().set_listener(&listener);
    ASSERT_TRUE(client.start());

    {
        FakeServer server(server_url(CALLBACK_TEST_PORT), "server-a");
        pump_until(client, [&] { return client.is_connected(); });

        client.stop();

        EXPECT_EQ(listener.clears, 1);
        EXPECT_FALSE(listener.started_during_clear);
        EXPECT_FALSE(listener.start_result_during_clear);
        EXPECT_FALSE(client.is_started());
        wait_until([&] { return server.closed(); });
    }

    // The refused start() inside the callback left the client stopped; a real start() works.
    ASSERT_TRUE(client.start());
    FakeServer server(server_url(CALLBACK_TEST_PORT), "server-b");
    pump_until(client, [&] { return client.is_connected(); });
    client.stop();
    EXPECT_EQ(listener.clears, 2);
}

// Destroying a running client goodbyes its peer like stop() does, but delivers no listener
// callback: the listener here is released before the client, the natural order for a consumer
// that never called stop(), and the sanitizer turns any callback into a use-after-free.
TEST(ClientLifecycle, DestructorGoodbyesPeersWithoutCallbacks) {
    TestNetworkProvider network;
    FakeServer* server = nullptr;
    auto listener = std::make_unique<ForbiddenMetadataListener>();
    {
        SendspinClient client(make_config(DESTRUCTOR_TEST_PORT));
        client.set_network_provider(&network);
        client.add_metadata().set_listener(listener.get());
        ASSERT_TRUE(client.start());

        server = new FakeServer(server_url(DESTRUCTOR_TEST_PORT), "server-a");
        pump_until(client, [&] { return client.is_connected(); });

        listener.reset();
        // Client destroyed here while established, with its listener already gone.
    }

    wait_until([&] { return server->closed(); });
    EXPECT_TRUE(server->got_goodbye());
    delete server;
}

}  // namespace
