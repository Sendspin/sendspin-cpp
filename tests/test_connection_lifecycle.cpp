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

// Integration tests for the connection nursery (prove-then-admit lifecycle). The manager is only
// reachable through SendspinClient, so these drive a real client on loopback ports: raw TCP
// sockets play the junk probes, IXWebSocket endpoints play the Sendspin servers, and the test
// thread pumps client.loop() like a platform main loop. Each scenario guards one lifecycle
// property or the delivery-at-upgrade contract (connections reach the manager only after their
// WebSocket upgrade; raw-TCP junk is closed inside the transport layer and never occupies a slot).

#include "connection_manager.h"  // fnv1_hash for the last-played preference
#include "sendspin/client.h"
#include "sendspin/config.h"
#include <gtest/gtest.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketServer.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <utility>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// Distinct ports per test so a lingering socket from one scenario cannot bleed into the next.
constexpr uint16_t PROBE_TEST_PORT = 18941;
constexpr uint16_t OUTBOUND_TEST_PORT = 18942;
constexpr uint16_t PROXY_LISTEN_PORT = 18951;
constexpr uint16_t PROXY_BACKEND_PORT = 18952;
constexpr uint16_t RACE_TEST_PORT = 18961;
constexpr uint16_t EARLY_HELLO_TEST_PORT = 18971;
constexpr uint16_t EVICT_TEST_PORT = 18972;
constexpr uint16_t REJECT_TEST_PORT = 18973;
constexpr uint16_t STALL_LISTEN_PORT = 18981;
constexpr uint16_t ADMIT_TEST_PORT = 18982;

std::string server_url(uint16_t port) {
    return "ws://127.0.0.1:" + std::to_string(port) + "/sendspin";
}

std::string server_hello_json(const std::string& server_id, const std::string& reason) {
    return std::string(R"({"type":"server/hello","payload":{"server_id":")") + server_id +
           R"(","name":"Fake Server","version":1,"active_roles":["player"],)" +
           R"("connection_reason":")" + reason + R"("}})";
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

class TestPersistenceProvider : public SendspinPersistenceProvider {
public:
    explicit TestPersistenceProvider(uint32_t hash) : hash_(hash) {}

    std::optional<uint32_t> load_last_server_hash() override {
        return this->hash_;
    }

private:
    uint32_t hash_;
};

/// Pumps client.loop() (like a platform main loop would) until the predicate returns true or the
/// timeout elapses. Returns true if the predicate was satisfied.
bool pump_until(SendspinClient& client, const std::function<bool()>& pred, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        client.loop();
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return false;
}

void pump_for(SendspinClient& client, int duration_ms) {
    pump_until(
        client, [] { return false; }, duration_ms);
}

int connect_loopback(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

/// Non-blocking check for EOF/reset on a raw socket. Drains any pending bytes (a goodbye frame
/// sent to the "probe" is not a close) and reports true only once the peer has closed.
bool socket_closed(int fd) {
    char buf[256];
    while (true) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n == 0) {
            return true;  // orderly EOF
        }
        if (n < 0) {
            return errno != EAGAIN && errno != EWOULDBLOCK;  // reset counts as closed
        }
        // n > 0: bytes to discard; loop and look again
    }
}

/// Behavior knobs for FakeServer.
struct FakeServerOptions {
    bool hello_on_open{false};  ///< Send server/hello immediately on Open, before any
                                ///< client/hello arrives (a nonconforming peer)
    bool answer_hello{true};    ///< Reply to client/hello with server/hello (false: mute peer
                                ///< that upgrades and then never establishes)
};

/// A minimal Sendspin "server": an IXWebSocket client that connects to the SendspinClient's WS
/// server (the server-initiated discovery direction) and answers client/hello with server/hello,
/// per the given options.
class FakeServer {
public:
    FakeServer(const std::string& url, std::string server_id, FakeServerOptions options = {})
        : server_id_(std::move(server_id)) {
        this->ws_.setUrl(url);
        this->ws_.disableAutomaticReconnection();
        this->ws_.setOnMessageCallback([this, options](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Open) {
                if (options.hello_on_open) {
                    this->ws_.send(server_hello_json(this->server_id_, "discovery"));
                }
            } else if (msg->type == ix::WebSocketMessageType::Message &&
                       msg->str.find("client/hello") != std::string::npos) {
                this->got_client_hello_.store(true);
                if (options.answer_hello) {
                    this->ws_.send(server_hello_json(this->server_id_, "discovery"));
                }
            } else if (msg->type == ix::WebSocketMessageType::Message &&
                       msg->str.find("client/goodbye") != std::string::npos) {
                this->got_goodbye_.store(true);
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

/// TCP relay that accepts one connection, sits on it without reading for delay_ms (the peer's
/// WebSocket upgrade request waits in the kernel buffer), then connects to the backend and pumps
/// bytes both ways. Simulates a slow network path in front of a real Sendspin server.
class DelayProxy {
public:
    DelayProxy(uint16_t listen_port, uint16_t backend_port, int delay_ms)
        : backend_port_(backend_port), delay_ms_(delay_ms) {
        this->listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (this->listen_fd_ < 0) {
            return;
        }
        int one = 1;
        ::setsockopt(this->listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(listen_port);
        if (::bind(this->listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(this->listen_fd_, 1) != 0) {
            ::close(this->listen_fd_);
            this->listen_fd_ = -1;
            return;
        }
        this->ok_ = true;
        this->thread_ = std::thread([this] { this->run(); });
    }

    ~DelayProxy() {
        this->stop_.store(true);
        if (this->ok_) {
            // Unblock a still-pending accept() by connecting to ourselves.
            int poke = connect_loopback(this->listen_port());
            if (this->thread_.joinable()) {
                this->thread_.join();
            }
            if (poke >= 0) {
                ::close(poke);
            }
        }
        if (this->listen_fd_ >= 0) {
            ::close(this->listen_fd_);
        }
    }

    /// True once the listening socket is bound and the pump thread is running. Tests must
    /// ASSERT this before using the proxy: a setup failure recorded non-fatally inside a
    /// constructor would not abort the test, which would then hang out its full timeout
    /// budget on a connection that can never be accepted.
    bool ok() const {
        return this->ok_;
    }

private:
    uint16_t listen_port() const {
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        ::getsockname(this->listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        return ntohs(addr.sin_port);
    }

    static bool send_all(int fd, const char* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t n = ::send(fd, data + sent, len - sent, 0);
            if (n <= 0) {
                return false;
            }
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    void run() {
        int client_fd = ::accept(this->listen_fd_, nullptr, nullptr);
        if (client_fd < 0 || this->stop_.load()) {
            if (client_fd >= 0) {
                ::close(client_fd);
            }
            return;
        }

        // The stall: hold the accepted connection without reading until the delay elapses.
        const auto resume =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(this->delay_ms_);
        while (!this->stop_.load() && std::chrono::steady_clock::now() < resume) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        int backend_fd = connect_loopback(this->backend_port_);
        if (backend_fd < 0) {
            ::close(client_fd);
            return;
        }

        while (!this->stop_.load()) {
            pollfd fds[2] = {{client_fd, POLLIN, 0}, {backend_fd, POLLIN, 0}};
            int rc = ::poll(fds, 2, 50);
            if (rc < 0) {
                break;
            }
            if (rc == 0) {
                continue;
            }
            char buf[4096];
            bool alive = true;
            if (fds[0].revents != 0) {
                ssize_t n = ::recv(client_fd, buf, sizeof(buf), 0);
                alive = n > 0 && send_all(backend_fd, buf, static_cast<size_t>(n));
            }
            if (alive && fds[1].revents != 0) {
                ssize_t n = ::recv(backend_fd, buf, sizeof(buf), 0);
                alive = n > 0 && send_all(client_fd, buf, static_cast<size_t>(n));
            }
            if (!alive) {
                break;
            }
        }
        ::close(client_fd);
        ::close(backend_fd);
    }

    std::thread thread_;
    std::atomic<bool> stop_{false};
    int listen_fd_{-1};
    uint16_t backend_port_;
    int delay_ms_;
    bool ok_{false};
};

}  // namespace

// A raw TCP probe (port scan / health check) held open against the client's WS server must not
// keep a real server from connecting and establishing immediately, and the probe socket must be
// closed within roughly the nursery upgrade deadline.
TEST(ConnectionLifecycle, JunkProbeDoesNotBlockRealServer) {
    TestNetworkProvider network;
    SendspinClient client(make_config(PROBE_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start_server());
    // The WS server starts synchronously on the first loop() once the network reports ready.
    pump_for(client, 50);

    // Hold a raw TCP connection open without ever speaking WebSocket.
    int probe_fd = connect_loopback(PROBE_TEST_PORT);
    ASSERT_GE(probe_fd, 0);
    pump_for(client, 200);  // give the transport time to accept it; the probe never reaches the
                            // manager (junk is closed inside the transport layer)
    EXPECT_FALSE(client.is_connected());

    // A real server connects while the probe is held: it must establish promptly, not after the
    // probe's deadline.
    FakeServer real_server(server_url(PROBE_TEST_PORT), "server-a");
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000));
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, "server-a");

    // The probe never completes a WebSocket handshake, so the transport layer closes it without
    // it ever reaching the manager (host: IXWebSocket's 3 s server-side handshake timeout; on
    // ESP the ws_server tick would reap it at 5 s). Budget covers either bound plus margin.
    EXPECT_TRUE(pump_until(
        client, [&] { return socket_closed(probe_fd); }, 6500));
    ::close(probe_fd);

    // The established connection must have been untouched by the probe reap.
    EXPECT_TRUE(client.is_connected());
}

// An outbound connect_to() through a slow network (upgrade stalled ~8 s, past every short
// inbound-side upgrade deadline) must keep its full 30 s establish budget and connect. Short
// upgrade deadlines exist only in the transport layer for inbound accepts (ESP ws_server reap, IX
// handshake timeout); an outbound connect's clock predates DNS/TCP resolve and must never be cut
// short by them.
TEST(ConnectionLifecycle, SlowOutboundSurvivesUpgradeTier) {
    // Real Sendspin-speaking endpoint the proxy forwards to.
    ix::WebSocketServer backend(PROXY_BACKEND_PORT, "127.0.0.1");
    backend.setOnConnectionCallback([](const std::weak_ptr<ix::WebSocket>& weak_ws,
                                       const std::shared_ptr<ix::ConnectionState>& /*state*/) {
        auto ws = weak_ws.lock();
        if (!ws) {
            return;
        }
        ws->setOnMessageCallback([weak_ws](const ix::WebSocketMessagePtr& msg) {
            if (msg->type == ix::WebSocketMessageType::Message &&
                msg->str.find("client/hello") != std::string::npos) {
                if (auto locked = weak_ws.lock()) {
                    locked->send(server_hello_json("server-slow", "discovery"));
                }
            }
        });
    });
    ASSERT_TRUE(backend.listen().first);
    backend.start();

    DelayProxy proxy(PROXY_LISTEN_PORT, PROXY_BACKEND_PORT, 8000);
    ASSERT_TRUE(proxy.ok());

    TestNetworkProvider network;
    SendspinClient client(make_config(OUTBOUND_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    client.connect_to(server_url(PROXY_LISTEN_PORT));

    // Nothing can establish before the proxy forwards the upgrade at ~8 s; the connection must
    // still be alive past the 5 s mark, well beyond any inbound-side upgrade deadline.
    EXPECT_FALSE(pump_until(
        client, [&] { return client.is_connected(); }, 6500));

    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 7500));
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, "server-slow");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
    backend.stop();
}

// An in-flight outbound connect_to() must not count against the inbound nursery capacity: with
// one mute inbound peer holding a slot and an outbound attempt stalled mid-upgrade, a real server
// connecting inbound must still be admitted and establish, not be rejected with ANOTHER_SERVER
// for up to the outbound's 30 s establish budget.
TEST(ConnectionLifecycle, InFlightOutboundDoesNotBlockInboundAdmission) {
    // A listener that accepts TCP (via the backlog) but never reads or replies: connect_to()
    // through it succeeds at the TCP layer and then stalls awaiting the WebSocket upgrade,
    // pinning the outbound nursery entry for the duration of the test.
    int stall_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(stall_fd, 0);
    int one = 1;
    ::setsockopt(stall_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(STALL_LISTEN_PORT);
    ASSERT_EQ(::bind(stall_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(stall_fd, 1), 0);

    TestNetworkProvider network;
    SendspinClient client(make_config(ADMIT_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    client.connect_to(server_url(STALL_LISTEN_PORT));

    // A mute inbound peer occupies one inbound slot past TCP_OPEN.
    FakeServer mute(server_url(ADMIT_TEST_PORT), "mute", {.answer_hello = false});
    ASSERT_TRUE(pump_until(
        client, [&] { return mute.got_client_hello(); }, 3000));

    // The real server takes the second inbound slot; the stalled outbound must not consume it.
    FakeServer real_server(server_url(ADMIT_TEST_PORT), "server-real");
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000));
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, "server-real");
    EXPECT_FALSE(real_server.closed());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
    ::close(stall_fd);
}

// A peer that sends server/hello immediately on connect, before our client/hello has gone out,
// must not be promoted with an incomplete handshake (that would wedge the current slot forever:
// out of the nursery, no deadline, is_connected() false, hello retry cancelled). Establishment
// must instead complete once the client/hello send lands.
TEST(ConnectionLifecycle, EarlyServerHelloDoesNotWedge) {
    TestNetworkProvider network;
    SendspinClient client(make_config(EARLY_HELLO_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    FakeServer eager(server_url(EARLY_HELLO_TEST_PORT), "server-eager", {.hello_on_open = true});
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000));
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, "server-eager");
    EXPECT_FALSE(eager.closed());
}

// Two real servers connecting back to back resolve by the fair comparison, not by handshake
// timing. Sequenced deterministically (not a timed race): server-a is asserted to be current
// before server-b connects, so the second establishment provably exercises the handoff comparison
// rather than the empty-slot promotion.
TEST(ConnectionLifecycle, TwoServerRaceResolvedByPreference) {
    TestNetworkProvider network;
    TestPersistenceProvider persistence(ConnectionManager::fnv1_hash("server-b"));
    SendspinClient client(make_config(RACE_TEST_PORT));
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    // server-a establishes and is promoted into the empty slot first...
    FakeServer server_a(server_url(RACE_TEST_PORT), "server-a");
    ASSERT_TRUE(pump_until(
        client,
        [&] {
            auto info = client.get_server_information();
            return info.has_value() && info->server_id == "server-a";
        },
        3000));

    // ...then server-b establishes against the incumbent. Both sides of the comparison are
    // established; the last-played preference (server-b) must win the handoff, and the later
    // arrival must not be evicted for finishing second.
    FakeServer server_b(server_url(RACE_TEST_PORT), "server-b");
    EXPECT_TRUE(pump_until(
        client,
        [&] {
            auto info = client.get_server_information();
            return info.has_value() && info->server_id == "server-b";
        },
        3000));

    // The displaced incumbent is released with a goodbye, not left dangling.
    EXPECT_TRUE(pump_until(
        client, [&] { return server_a.closed(); }, 3000));
    EXPECT_FALSE(server_b.closed());
    EXPECT_TRUE(client.is_connected());
}

// Delivery-at-upgrade contract: raw TCP probes never reach the manager, so even enough of them to
// fill the nursery capacity cannot occupy a slot or delay a real server.
TEST(ConnectionLifecycle, HeldProbesNeverOccupyNursery) {
    TestNetworkProvider network;
    SendspinClient client(make_config(EVICT_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    // Two held raw probes, enough to fill every nursery slot if they were admitted at accept.
    int probe1 = connect_loopback(EVICT_TEST_PORT);
    ASSERT_GE(probe1, 0);
    pump_for(client, 100);
    int probe2 = connect_loopback(EVICT_TEST_PORT);
    ASSERT_GE(probe2, 0);
    pump_for(client, 100);

    // The real server must establish promptly: the probes hold no nursery slots, so nothing
    // needs evicting and nothing is rejected.
    FakeServer real_server(server_url(EVICT_TEST_PORT), "server-real");
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000));
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, "server-real");

    // The transport layer closes the probes on its own (host: IX 3 s handshake timeout).
    EXPECT_TRUE(pump_until(
        client, [&] { return socket_closed(probe1) && socket_closed(probe2); }, 6500));
    EXPECT_TRUE(client.is_connected());

    ::close(probe1);
    ::close(probe2);
}

// Rejection path: with the nursery full of peers that have proven they speak WebSocket (they
// received client/hello but never establish), a newcomer is rejected. Because rejection happens on
// an already-upgraded session, the goodbye must reach the peer before the close.
TEST(ConnectionLifecycle, FullNurseryOfLivePeersRejectsNewcomer) {
    TestNetworkProvider network;
    SendspinClient client(make_config(REJECT_TEST_PORT));
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    // Two mute peers: they upgrade and receive client/hello but never answer it, occupying both
    // nursery slots past TCP_OPEN until the establish deadline.
    FakeServer mute_a(server_url(REJECT_TEST_PORT), "mute-a", {.answer_hello = false});
    FakeServer mute_b(server_url(REJECT_TEST_PORT), "mute-b", {.answer_hello = false});
    ASSERT_TRUE(pump_until(
        client, [&] { return mute_a.got_client_hello() && mute_b.got_client_hello(); }, 3000));

    FakeServer late(server_url(REJECT_TEST_PORT), "server-late");
    EXPECT_TRUE(pump_until(
        client, [&] { return late.closed(); }, 3000));
    EXPECT_TRUE(late.got_goodbye());
    EXPECT_FALSE(client.is_connected());
    EXPECT_FALSE(mute_a.closed());
    EXPECT_FALSE(mute_b.closed());
}
