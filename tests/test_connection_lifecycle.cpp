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
// sockets play the junk probes, the fake servers from lifecycle_test_fixtures.h play the Sendspin
// peers over real Noise KKpsk2, and the test thread pumps client.loop() like a platform main loop.
// Each scenario guards one lifecycle property or the delivery-at-upgrade contract (connections
// reach the manager only after their WebSocket upgrade; raw-TCP junk is closed inside the
// transport layer and never occupies a slot).
//
// test_encrypted_lifecycle.cpp covers the protocol layer riding on that lifecycle (hello/activate,
// pairing, in-band re-handshake) against the same fixtures.

#include "crypto/constants.h"
#include "connection_manager.h"  // resolve_liveness_timeout_ms, liveness_expired
#include "crypto/keys.h"
#include "lifecycle_test_fixtures.h"
#include "platform/crypto.h"
#include "protocol_task.h"  // ProtocolTask::NO_DEADLINE
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/types.h"

#include <gtest/gtest.h>
#include <ixwebsocket/IXWebSocket.h>

// IWYU pragma: begin_keep
// The include-what-you-use checker misattributes arpa/inet.h's htons/ntohs/htonl/ntohl to
// macOS libc++'s private headers when analyzed on a macOS host toolchain (a known
// include-checker false-positive class for macOS private headers like _abort.h/_endian.h); arpa/inet.h is
// still the correct, portable header on both macOS and Linux CI.
#include <arpa/inet.h>
// IWYU pragma: end_keep
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// Distinct ports per test so a lingering socket from one scenario cannot bleed into the next.
constexpr uint16_t PROBE_TEST_PORT = 18941;
constexpr uint16_t OUTBOUND_TEST_PORT = 18942;
constexpr uint16_t PROXY_LISTEN_PORT = 18951;
constexpr uint16_t PROXY_BACKEND_PORT = 18952;
constexpr uint16_t RACE_TEST_PORT = 18961;
constexpr uint16_t REJECT_TEST_PORT = 18973;
constexpr uint16_t STALL_LISTEN_PORT = 18981;
constexpr uint16_t ADMIT_TEST_PORT = 18982;

SendspinClientConfig make_config(uint16_t port) {
    SendspinClientConfig config;
    config.name = "Lifecycle Test Client";
    config.server_port = port;
    return config;
}

/// Options for a peer that completes the Noise handshake and the hello exchange but never sends
/// server/activate, so it proves it speaks the protocol yet never becomes operational and stays
/// in the nursery for the whole establish window.
FakeEncryptedServerOptions unactivated_peer_options() {
    FakeEncryptedServerOptions options;
    options.suppress_activate = true;
    return options;
}

/// Options for a peer that activates with no activities and no roles: rank 0 for admission
/// arbitration, which is what drives the last-played tiebreak (admission.h rule 5).
FakeEncryptedServerOptions rank_zero_peer_options() {
    FakeEncryptedServerOptions options;
    options.first_activities_json = R"([])";
    options.first_roles_json = R"([])";
    return options;
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

// Raw TCP probes (port scan / health check) held open against the client's WS server must not
// keep a real server from connecting and establishing immediately, and the probe sockets must be
// closed within roughly the nursery upgrade deadline. Enough probes are held to fill every
// nursery slot (ConnectionManager::NURSERY_CAPACITY is 2): if a raw socket took a slot at accept
// the real server would find the nursery full and be rejected, and the transport's socket budget
// (NURSERY_CAPACITY + 2) has to have room for it alongside them.
TEST(ConnectionLifecycle, JunkProbeDoesNotBlockRealServer) {
    PairedClientBundle bundle(make_config(PROBE_TEST_PORT));
    SendspinClient& client = bundle.client();
    // start() creates the WS server and, with the network ready, starts it before returning.
    ASSERT_TRUE(bundle.start());

    // Hold a nursery's worth of raw TCP connections open without ever speaking WebSocket.
    constexpr size_t HELD_PROBES = 2;  // ConnectionManager::NURSERY_CAPACITY (private)
    int probe_fds[HELD_PROBES];
    for (size_t i = 0; i < HELD_PROBES; ++i) {
        probe_fds[i] = connect_loopback(PROBE_TEST_PORT);
        ASSERT_GE(probe_fds[i], 0);
        pump_for(client, 100);  // give the transport time to accept it; the probe never reaches
                                // the manager (junk is closed inside the transport layer)
    }
    EXPECT_FALSE(client.is_connected())
        << "a raw TCP probe must never become the current connection";

    // A real server connects while the probes are held: they hold no nursery slots, so nothing
    // needs evicting and the newcomer reaches the admitted slot. That it establishes before the
    // probes are reaped is not asserted - latency is not a unit-test property.
    const Identity& server_identity = bundle.peer.server_identity;
    FakeEncryptedServer real_server(server_url(PROBE_TEST_PORT),
                                    std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                    bundle.peer.record.psk_id, bundle.peer.psk);
    pump_until(client, [&] { return client.is_connected(); });
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());

    // The probes never complete a WebSocket handshake, so the transport layer closes them without
    // them ever reaching the manager (host: IXWebSocket's 3 s server-side handshake timeout; on
    // ESP the ws_server tick would reap them at 5 s).
    pump_until(client, [&] {
        for (size_t i = 0; i < HELD_PROBES; ++i) {
            if (!socket_closed(probe_fds[i])) {
                return false;
            }
        }
        return true;
    });
    for (size_t i = 0; i < HELD_PROBES; ++i) {
        ::close(probe_fds[i]);
    }

    // The established connection must have been untouched by the probe reap.
    EXPECT_TRUE(client.is_connected())
        << "reaping the held probes must not disturb the established connection";
}

// An outbound connect_to() through a slow network (upgrade stalled ~8 s, past every short
// inbound-side upgrade deadline) must keep its full 30 s establish budget and connect. Short
// upgrade deadlines exist only in the transport layer for inbound accepts (ESP ws_server reap, IX
// handshake timeout); an outbound connect's clock predates DNS/TCP resolve and must never be cut
// short by them.
TEST(ConnectionLifecycle, SlowOutboundSurvivesUpgradeTier) {
    PairedClientBundle bundle(make_config(OUTBOUND_TEST_PORT));
    SendspinClient& client = bundle.client();

    // Real Sendspin-speaking endpoint the proxy forwards to.
    const Identity& server_identity = bundle.peer.server_identity;
    FakeOutboundEncryptedServer backend(PROXY_BACKEND_PORT, std::string(NOISE_SUITE_CHACHAPOLY),
                                        server_identity, bundle.peer.record.psk_id,
                                        bundle.peer.psk);
    ASSERT_TRUE(backend.listen());
    backend.start();

    DelayProxy proxy(PROXY_LISTEN_PORT, PROXY_BACKEND_PORT, 8000);
    ASSERT_TRUE(proxy.ok());

    ASSERT_TRUE(bundle.start());

    client.connect_to(server_url(PROXY_LISTEN_PORT));

    // The proxy holds the upgrade for 8 s, past every inbound-side upgrade deadline; the outbound
    // tier must ride that out and still establish. Completion is the whole verdict, so the wait
    // carries no bound of its own: a cut outbound clock never establishes and hangs here.
    pump_until(client, [&] { return client.is_connected(); });
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// An in-flight outbound connect_to() must not count against the inbound nursery capacity: with
// one inbound peer holding a slot and an outbound attempt stalled mid-upgrade, a real server
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

    PairedClientBundle bundle(make_config(ADMIT_TEST_PORT));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    client.connect_to(server_url(STALL_LISTEN_PORT));

    // A peer that handshakes and answers the hello but never activates occupies one inbound slot.
    // It runs on the Sentinel PSK, which RecordStore resolves unconditionally, so it needs no
    // record of its own.
    Identity mute_identity = Identity::generate().value();
    FakeEncryptedServer mute(server_url(ADMIT_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                             mute_identity, std::string(SENTINEL_PSK_ID), SENTINEL_PSK,
                             unactivated_peer_options());
    pump_until(client, [&] { return mute.client_hello_count() > 0; });

    // The real server takes the second inbound slot; the stalled outbound must not consume it.
    const Identity& server_identity = bundle.peer.server_identity;
    FakeEncryptedServer real_server(server_url(ADMIT_TEST_PORT),
                                    std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                    bundle.peer.record.psk_id, bundle.peer.psk);
    pump_until(client, [&] { return client.is_connected(); });
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());
    EXPECT_FALSE(real_server.closed())
        << "the real server must be admitted, not rejected while an outbound attempt is in flight";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
    ::close(stall_fd);
}

// Two real servers connecting back to back resolve by the fair comparison, not by handshake
// timing. Sequenced deterministically (not a timed race): server A is asserted to be current
// before server B connects, so the second establishment provably exercises the handoff comparison
// rather than the empty-slot promotion. Both activate at rank 0 (no activities, no roles), which
// is what routes the decision to admission.h rule 5's last-played tiebreak.
TEST(ConnectionLifecycle, TwoServerRaceResolvedByPreference) {
    PairedPeer peer_a = make_paired_peer();
    PairedPeer peer_b = make_paired_peer();
    const Identity& identity_a = peer_a.server_identity;
    const Identity& identity_b = peer_b.server_identity;

    TestNetworkProvider network;
    TestPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{peer_a.record, peer_b.record});
    // Seeded before start(), which is where the client loads it into the manager.
    persistence.set_last_played_server_id(identity_b.peer_id());

    SendspinClient client(make_config(RACE_TEST_PORT));
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    // Server A establishes and is promoted into the empty slot first...
    FakeEncryptedServer server_a(server_url(RACE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                                 identity_a, peer_a.record.psk_id, peer_a.psk,
                                 rank_zero_peer_options());
    pump_until(client, [&] {
        auto info = client.get_server_information();
        return info.has_value() && info->server_id == identity_a.peer_id();
    });

    // ...then server B establishes against the incumbent. Both sides of the comparison are
    // established; the last-played preference (server B) must win the handoff, and the later
    // arrival must not be evicted for finishing second.
    FakeEncryptedServer server_b(server_url(RACE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                                 identity_b, peer_b.record.psk_id, peer_b.psk,
                                 rank_zero_peer_options());
    pump_until(client, [&] {
        auto info = client.get_server_information();
        return info.has_value() && info->server_id == identity_b.peer_id();
    });

    // The displaced incumbent is released with a goodbye, not left dangling.
    pump_until(client, [&] { return server_a.closed(); });
    EXPECT_EQ(server_a.goodbye_reason().value_or(""), "another_server")
        << "a displaced incumbent must be told why it was released";
    EXPECT_FALSE(server_b.closed()) << "the preferred server must keep the slot it won";
    // The handoff leaves a current connection behind once the winner's first server/activate
    // makes it count as connected, which can follow its admission by a tick.
    pump_until(client, [&] { return client.is_connected(); });
}

// Rejection path: with the nursery full of peers that have proven they speak the protocol (they
// complete the Noise handshake and the hello exchange but never activate), a newcomer is rejected.
// Rejection happens at accept, before the newcomer gets a Noise handshake driver, so its goodbye
// travels as a cleartext text frame and must reach the peer before the close.
TEST(ConnectionLifecycle, FullNurseryOfLivePeersRejectsNewcomer) {
    PairedClientBundle bundle(make_config(REJECT_TEST_PORT));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    // Two peers on the Sentinel PSK that handshake and answer the hello but never activate,
    // occupying both nursery slots until the establish deadline.
    Identity identity_a = Identity::generate().value();
    Identity identity_b = Identity::generate().value();
    FakeEncryptedServer mute_a(server_url(REJECT_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               identity_a, std::string(SENTINEL_PSK_ID), SENTINEL_PSK,
                               unactivated_peer_options());
    FakeEncryptedServer mute_b(server_url(REJECT_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               identity_b, std::string(SENTINEL_PSK_ID), SENTINEL_PSK,
                               unactivated_peer_options());
    pump_until(client,
               [&] { return mute_a.client_hello_count() > 0 && mute_b.client_hello_count() > 0; });

    const Identity& late_identity = bundle.peer.server_identity;
    FakeEncryptedServer late(server_url(REJECT_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                             late_identity, bundle.peer.record.psk_id, bundle.peer.psk);
    pump_until(client, [&] { return late.closed(); });
    EXPECT_EQ(late.goodbye_reason().value_or(""), "another_server")
        << "a newcomer rejected at accept must still be told why";
    EXPECT_FALSE(client.is_connected())
        << "a rejected newcomer must not become the current connection";
    EXPECT_FALSE(mute_a.closed())
        << "a peer holding a nursery slot must not be evicted for a newcomer";
    EXPECT_FALSE(mute_b.closed())
        << "a peer holding a nursery slot must not be evicted for a newcomer";
}

// ============================================================================
// Liveness timeout
// ============================================================================

// A peer that sends server/hello before the client's own client/hello (main's
// EarlyServerHelloDoesNotWedge scenario) needs no test of its own here: FakeEncryptedServer
// sends its server/hello the moment the Noise handshake completes, before any client/hello
// arrives, so every establishment above already runs that ordering.

namespace {

constexpr uint16_t LIVENESS_TEST_PORT = 18983;
constexpr uint16_t LIVENESS_DISABLED_PORT = 18985;

SendspinClientConfig make_liveness_config(uint16_t port, int64_t liveness_timeout_ms) {
    SendspinClientConfig config = make_config(port);
    config.time_burst_interval_ms = 20;
    config.time_burst_response_timeout_ms = 20;
    config.liveness_timeout_ms = liveness_timeout_ms;
    return config;
}

}  // namespace

// resolve_liveness_timeout_ms() either derives the window from the configured burst settings or
// takes an explicitly configured one, and clamps either to the cap.
TEST(LivenessTimeout, ResolvesFromConfig) {
    struct Row {
        const char* name;
        std::optional<uint32_t> burst_interval_ms;
        std::optional<uint32_t> burst_response_timeout_ms;
        std::optional<int64_t> explicit_timeout_ms;
        int64_t expected_ms;
    };
    const Row rows[] = {
        {"defaults derive", std::nullopt, std::nullopt, std::nullopt, 60000},
        {"longer interval widens the window", 60000, std::nullopt, std::nullopt, 210000},
        {"response timeout widens the window", 10000, 20000, std::nullopt, 90000},
        {"explicit value overrides the derivation", 60000, std::nullopt, 5000, 5000},
        {"explicit zero disables the check", 60000, std::nullopt, 0, 0},
        {"Control: explicit value at the cap is kept", std::nullopt, std::nullopt,
         SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS,
         SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS},
        {"explicit value above the cap is clamped", std::nullopt, std::nullopt,
         SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS + 1,
         SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS},
        {"derived value above the cap is clamped", 900000, std::nullopt, std::nullopt,
         SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinClientConfig config;
        if (row.burst_interval_ms.has_value()) {
            config.time_burst_interval_ms = row.burst_interval_ms.value();
        }
        if (row.burst_response_timeout_ms.has_value()) {
            config.time_burst_response_timeout_ms = row.burst_response_timeout_ms.value();
        }
        config.liveness_timeout_ms = row.explicit_timeout_ms;
        EXPECT_EQ(resolve_liveness_timeout_ms(config), row.expected_ms);
    }
}

// liveness_expired() measures silence from the connection's last arrival, not from time zero, and
// expires once it reaches the timeout; a disabled timeout never expires. Only the low 32 bits
// count: silence stays exact across their wrap, and an arrival just after now never expires.
TEST(LivenessTimeout, ExpiresOnceSilenceReachesTheTimeout) {
    struct Row {
        const char* name;
        int64_t now_us;
        uint32_t last_receive_us;
        int64_t timeout_us;
        bool expected;
    };
    constexpr int64_t TIMEOUT_US = 60'000'000;
    // High bits set, so a row fails if they take part.
    constexpr int64_t EPOCH_US = 5LL << 32;
    constexpr uint32_t LAST = 1'000'000'000U;
    constexpr int64_t LAST_US = EPOCH_US + LAST;
    // Half a timeout before the 32-bit wrap.
    constexpr auto PRE_WRAP = static_cast<uint32_t>((1LL << 32) - TIMEOUT_US / 2);
    constexpr int64_t WRAP_US = EPOCH_US + (1LL << 32);
    const Row rows[] = {
        {"Control: just under the timeout", LAST_US + TIMEOUT_US - 1, LAST, TIMEOUT_US, false},
        {"exactly at the timeout", LAST_US + TIMEOUT_US, LAST, TIMEOUT_US, true},
        {"past the timeout", LAST_US + TIMEOUT_US + 1, LAST, TIMEOUT_US, true},
        {"Control: just under the timeout across the wrap", WRAP_US + TIMEOUT_US / 2 - 1, PRE_WRAP,
         TIMEOUT_US, false},
        {"exactly at the timeout across the wrap", WRAP_US + TIMEOUT_US / 2, PRE_WRAP, TIMEOUT_US,
         true},
        {"Control: last arrival ahead of now", LAST_US - 1, LAST, TIMEOUT_US, false},
        {"Control: last arrival ahead of now across the wrap", WRAP_US - 1, 0, TIMEOUT_US, false},
        {"zero timeout disables the check", LAST_US + 10 * TIMEOUT_US, LAST, 0, false},
        {"negative timeout disables the check", LAST_US + 10 * TIMEOUT_US, LAST, -1, false},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(liveness_expired(row.now_us, row.last_receive_us, row.timeout_us), row.expected);
    }
}

// liveness_remaining_us() is the time the protocol task sleeps before liveness_expired() can next
// change its verdict: the timeout minus the silence so far, never negative, measured on the same
// low 32 bits.
TEST(LivenessTimeout, RemainingTimeIsTheTimeoutLessTheSilence) {
    struct Row {
        const char* name;
        int64_t now_us;
        uint32_t last_receive_us;
        int64_t expected_us;
    };
    constexpr int64_t TIMEOUT_US = 60'000'000;
    constexpr int64_t EPOCH_US = 5LL << 32;  // High bits set, so a row fails if they take part.
    constexpr uint32_t LAST = 1'000'000'000U;
    constexpr int64_t LAST_US = EPOCH_US + LAST;
    constexpr auto PRE_WRAP = static_cast<uint32_t>((1LL << 32) - TIMEOUT_US / 2);
    constexpr int64_t WRAP_US = EPOCH_US + (1LL << 32);
    const Row rows[] = {
        {"Control: an arrival at now leaves the whole timeout", LAST_US, LAST, TIMEOUT_US},
        {"part of the timeout spent", LAST_US + 1'000'000, LAST, TIMEOUT_US - 1'000'000},
        {"exactly at the timeout", LAST_US + TIMEOUT_US, LAST, 0},
        {"past the timeout never goes negative", LAST_US + 2 * TIMEOUT_US, LAST, 0},
        {"across the 32-bit wrap", WRAP_US + 1'000'000, PRE_WRAP, TIMEOUT_US / 2 - 1'000'000},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(liveness_remaining_us(row.now_us, row.last_receive_us, TIMEOUT_US),
                  row.expected_us);
    }
}

// ms_until() turns a deadline into the protocol task's wait: rounded up, so the task never wakes
// before the deadline and finds nothing due, 0 once it has passed, and never NO_DEADLINE, which a
// real deadline must not read as.
TEST(NextDeadline, MillisecondsUntilADeadlineRoundUp) {
    struct Row {
        const char* name;
        int64_t due_us;
        uint32_t expected_ms;
    };
    constexpr int64_t NOW_US = 7LL << 32;
    const Row rows[] = {
        {"Control: a deadline already passed", NOW_US - 1, 0},
        {"Control: a deadline at now", NOW_US, 0},
        {"one microsecond ahead waits a whole millisecond", NOW_US + 1, 1},
        {"an exact millisecond", NOW_US + 1000, 1},
        {"just past a millisecond rounds up", NOW_US + 1001, 2},
        {"a deadline beyond the 32-bit range clamps short of NO_DEADLINE",
         NOW_US + (1LL << 50), ProtocolTask::NO_DEADLINE - 1},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(ms_until(row.due_us, NOW_US), row.expected_ms);
    }
}

// An established peer that stops answering without closing is dropped with a restart goodbye.
// Waiting for client/time proves the peer was admitted, so the drop is not a nursery reap.
//
// Its controls are the "Control:" rows of the table above and of
// LivenessTickDropsOnlyAStaleCurrentConnection (test_encrypted_lifecycle.cpp), which runs the same
// check in the protocol tick against a current connection whose last arrival is fresh, together
// with AnInboundMessageAdvancesTheLivenessStamp there, which shows an answering peer's messages
// keep that arrival fresh. A control here would have to outlast the timeout, so a scheduling stall
// could fail it on a correct client.
TEST(ConnectionLifecycle, SilentEstablishedPeerIsDropped) {
    PairedClientBundle bundle(make_liveness_config(LIVENESS_TEST_PORT, 300));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    const Identity& identity = bundle.peer.server_identity;
    FakeEncryptedServer silent(server_url(LIVENESS_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               identity, bundle.peer.record.psk_id, bundle.peer.psk);
    pump_until(client, [&] { return client.is_connected(); });
    pump_until(client, [&] { return silent.got_client_time(); });

    pump_until(client, [&] { return !client.is_connected(); });
    pump_until(client, [&] { return silent.closed(); });
    EXPECT_EQ(silent.goodbye_reason().value_or(""), "restart")
        << "a peer dropped for liveness must be told to restart";
    EXPECT_FALSE(client.get_server_information().has_value())
        << "a dropped peer must not be left as the current connection";
}

// liveness_timeout_ms = 0 disables the check: a peer that never answers stays current. Guards the
// zero reaching the liveness tick as disabled, without which a zero timeout drops every
// connection at once.
TEST(ConnectionLifecycle, DisabledLivenessKeepsSilentPeer) {
    PairedClientBundle bundle(make_liveness_config(LIVENESS_DISABLED_PORT, 0));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    const Identity& identity = bundle.peer.server_identity;
    FakeEncryptedServer silent(server_url(LIVENESS_DISABLED_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), identity,
                               bundle.peer.record.psk_id, bundle.peer.psk);
    pump_until(client, [&] { return client.is_connected(); });
    pump_until(client, [&] { return silent.got_client_time(); });

    pump_for(client, 300);  // Several time messages go unanswered
    EXPECT_TRUE(client.is_connected())
        << "a disabled liveness check must keep a silent peer current";
    EXPECT_FALSE(silent.closed()) << "a disabled liveness check must not close a silent peer";
    EXPECT_FALSE(silent.goodbye_reason().has_value())
        << "a disabled liveness check must not send a goodbye";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// ============================================================================
// The protocol task works without the main loop
// ============================================================================

namespace {

constexpr uint16_t NO_LOOP_ADMISSION_TEST_PORT = 19101;
constexpr uint16_t CROSS_THREAD_COMMAND_TEST_PORT = 19102;
constexpr uint16_t TWO_PEERS_TEST_PORT = 19103;

}  // namespace

// The protocol task admits a connection on its own: the Noise handshake, the hello exchange, the
// activation, the admission and the first client/state all complete without a single loop()
// call, which only delivers callbacks. The waits are unbounded: a client that needs the main loop
// to admit hangs here, and the suite watchdog names the test.
TEST(ConnectionLifecycle, AdmissionNeedsNoLoopTick) {
    PairedClientBundle bundle(make_config(NO_LOOP_ADMISSION_TEST_PORT));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    auto server = connect_paired_server(bundle.peer, NO_LOOP_ADMISSION_TEST_PORT);
    wait_until([&] { return client.is_connected(); });
    wait_until([&] { return server->client_state_count() > 0; });
    EXPECT_FALSE(server->closed());

    client.stop();
}

// A request made on a thread other than the main loop reaches the protocol task, which acts on it
// with no loop() call in between: the disconnect's goodbye reaches the peer.
TEST(ConnectionLifecycle, ARequestFromAnotherThreadIsActedOnWithoutALoopTick) {
    PairedClientBundle bundle(make_config(CROSS_THREAD_COMMAND_TEST_PORT));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    auto server = connect_paired_server(bundle.peer, CROSS_THREAD_COMMAND_TEST_PORT);
    wait_until([&] { return client.is_connected(); });
    ASSERT_FALSE(server->goodbye_reason().has_value()) << "Control: no goodbye before the request";

    std::thread consumer([&client] { client.disconnect(SendspinGoodbyeReason::USER_REQUEST); });
    consumer.join();
    wait_until([&] { return server->goodbye_reason().has_value(); });
    EXPECT_EQ(server->goodbye_reason().value_or(""), "user_request");

    client.stop();
}

// Two servers connecting at the same moment are both driven by the protocol task at once, and the
// admission settles on the preferred one whichever finishes its handshake first: the last-played
// server holds the slot and the other is released with a goodbye, another_server when it was
// admitted first and then displaced, concurrent_attempt when it arrived second. Nothing calls
// loop().
TEST(ConnectionLifecycle, TwoPeersAtOnceSettleOnThePreferredOne) {
    PairedPeer peer_a = make_paired_peer();
    PairedPeer peer_b = make_paired_peer();
    TestNetworkProvider network;
    TestPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{peer_a.record, peer_b.record});
    persistence.set_last_played_server_id(peer_b.server_identity.peer_id());

    SendspinClient client(make_config(TWO_PEERS_TEST_PORT));
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    FakeEncryptedServer server_a(server_url(TWO_PEERS_TEST_PORT),
                                 std::string(NOISE_SUITE_CHACHAPOLY), peer_a.server_identity,
                                 peer_a.record.psk_id, peer_a.psk, rank_zero_peer_options());
    FakeEncryptedServer server_b(server_url(TWO_PEERS_TEST_PORT),
                                 std::string(NOISE_SUITE_CHACHAPOLY), peer_b.server_identity,
                                 peer_b.record.psk_id, peer_b.psk, rank_zero_peer_options());

    wait_until([&] { return server_a.closed(); });
    const std::string reason = server_a.goodbye_reason().value_or("");
    EXPECT_TRUE(reason == "another_server" || reason == "concurrent_attempt")
        << "the other server must be told why it was released, not '" << reason << "'";
    // Server information is published when a connection is admitted, before its first
    // server/activate makes it count as connected, so both are waited on.
    wait_until([&] {
        auto info = client.get_server_information();
        return client.is_connected() && info.has_value() &&
               info->server_id == peer_b.server_identity.peer_id();
    });
    EXPECT_FALSE(server_b.closed()) << "the preferred server must keep the slot";

    client.stop();
}
