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
// pairing, management, in-band re-handshake) against the same fixtures.

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "lifecycle_test_fixtures.h"
#include "platform/crypto.h"
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
constexpr uint16_t EVICT_TEST_PORT = 18972;
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

// A raw TCP probe (port scan / health check) held open against the client's WS server must not
// keep a real server from connecting and establishing immediately, and the probe socket must be
// closed within roughly the nursery upgrade deadline.
TEST(ConnectionLifecycle, JunkProbeDoesNotBlockRealServer) {
    PairedClientBundle bundle(make_config(PROBE_TEST_PORT));
    SendspinClient& client = bundle.client();
    // The WS server starts synchronously on the first loop() once the network reports ready.
    ASSERT_TRUE(bundle.start());

    // Hold a raw TCP connection open without ever speaking WebSocket.
    int probe_fd = connect_loopback(PROBE_TEST_PORT);
    ASSERT_GE(probe_fd, 0);
    pump_for(client, 200);  // give the transport time to accept it; the probe never reaches the
                            // manager (junk is closed inside the transport layer)
    EXPECT_FALSE(client.is_connected());

    // A real server connects while the probe is held: it must establish promptly, not after the
    // probe's deadline.
    Identity server_identity = Identity::generate().value();
    FakeEncryptedServer real_server(server_url(PROBE_TEST_PORT),
                                    std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                    bundle.peer.record.psk_id, bundle.peer.psk);
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000));
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());

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
    PairedClientBundle bundle(make_config(OUTBOUND_TEST_PORT));
    SendspinClient& client = bundle.client();

    // Real Sendspin-speaking endpoint the proxy forwards to.
    Identity server_identity = Identity::generate().value();
    FakeOutboundEncryptedServer backend(PROXY_BACKEND_PORT, std::string(NOISE_SUITE_CHACHAPOLY),
                                        server_identity, bundle.peer.record.psk_id,
                                        bundle.peer.psk);
    ASSERT_TRUE(backend.listen());
    backend.start();

    DelayProxy proxy(PROXY_LISTEN_PORT, PROXY_BACKEND_PORT, 8000);
    ASSERT_TRUE(proxy.ok());

    ASSERT_TRUE(bundle.start());

    client.connect_to(server_url(PROXY_LISTEN_PORT));

    // Nothing can establish before the proxy forwards the upgrade at ~8 s; the connection must
    // still be alive past the 5 s mark, well beyond any inbound-side upgrade deadline.
    EXPECT_FALSE(pump_until(
        client, [&] { return client.is_connected(); }, 6500));

    // Past the stall the whole remaining sequence (Noise handshake, hello, activate) still has to
    // fit inside the 30 s establish budget that started before the DNS/TCP resolve.
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 7500));
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
    ASSERT_TRUE(pump_until(
        client, [&] { return mute.client_hello_count() > 0; }, 4000));

    // The real server takes the second inbound slot; the stalled outbound must not consume it.
    Identity server_identity = Identity::generate().value();
    FakeEncryptedServer real_server(server_url(ADMIT_TEST_PORT),
                                    std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                    bundle.peer.record.psk_id, bundle.peer.psk);
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000));
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());
    EXPECT_FALSE(real_server.closed());

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
    Identity identity_a = Identity::generate().value();
    Identity identity_b = Identity::generate().value();

    TestNetworkProvider network;
    TestPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{peer_a.record, peer_b.record});
    // Seeded before start_server(), which is where the client loads it into the manager.
    persistence.set_last_played_server_id(identity_b.peer_id());

    SendspinClient client(make_config(RACE_TEST_PORT));
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start_server());
    pump_for(client, 50);

    // Server A establishes and is promoted into the empty slot first...
    FakeEncryptedServer server_a(server_url(RACE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                                 identity_a, peer_a.record.psk_id, peer_a.psk,
                                 rank_zero_peer_options());
    ASSERT_TRUE(pump_until(
        client,
        [&] {
            auto info = client.get_server_information();
            return info.has_value() && info->server_id == identity_a.peer_id();
        },
        4000));

    // ...then server B establishes against the incumbent. Both sides of the comparison are
    // established; the last-played preference (server B) must win the handoff, and the later
    // arrival must not be evicted for finishing second.
    FakeEncryptedServer server_b(server_url(RACE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                                 identity_b, peer_b.record.psk_id, peer_b.psk,
                                 rank_zero_peer_options());
    EXPECT_TRUE(pump_until(
        client,
        [&] {
            auto info = client.get_server_information();
            return info.has_value() && info->server_id == identity_b.peer_id();
        },
        4000));

    // The displaced incumbent is released with a goodbye, not left dangling.
    EXPECT_TRUE(pump_until(
        client, [&] { return server_a.closed(); }, 4000));
    EXPECT_EQ(server_a.goodbye_reason().value_or(""), "another_server");
    EXPECT_FALSE(server_b.closed());
    EXPECT_TRUE(client.is_connected());
}

// Delivery-at-upgrade contract: raw TCP probes never reach the manager, so even enough of them to
// fill the nursery capacity cannot occupy a slot or delay a real server.
TEST(ConnectionLifecycle, HeldProbesNeverOccupyNursery) {
    PairedClientBundle bundle(make_config(EVICT_TEST_PORT));
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    // Two held raw probes, enough to fill every nursery slot if they were admitted at accept.
    int probe1 = connect_loopback(EVICT_TEST_PORT);
    ASSERT_GE(probe1, 0);
    pump_for(client, 100);
    int probe2 = connect_loopback(EVICT_TEST_PORT);
    ASSERT_GE(probe2, 0);
    pump_for(client, 100);

    // The real server must establish promptly: the probes hold no nursery slots, so nothing
    // needs evicting and nothing is rejected.
    Identity server_identity = Identity::generate().value();
    FakeEncryptedServer real_server(server_url(EVICT_TEST_PORT),
                                    std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                    bundle.peer.record.psk_id, bundle.peer.psk);
    EXPECT_TRUE(pump_until(
        client, [&] { return client.is_connected(); }, 4000));
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());

    // The transport layer closes the probes on its own (host: IX 3 s handshake timeout).
    EXPECT_TRUE(pump_until(
        client, [&] { return socket_closed(probe1) && socket_closed(probe2); }, 6500));
    EXPECT_TRUE(client.is_connected());

    ::close(probe1);
    ::close(probe2);
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
    ASSERT_TRUE(pump_until(
        client,
        [&] { return mute_a.client_hello_count() > 0 && mute_b.client_hello_count() > 0; }, 4000));

    Identity late_identity = Identity::generate().value();
    FakeEncryptedServer late(server_url(REJECT_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                             late_identity, bundle.peer.record.psk_id, bundle.peer.psk);
    EXPECT_TRUE(pump_until(
        client, [&] { return late.closed(); }, 4000));
    EXPECT_EQ(late.goodbye_reason().value_or(""), "another_server");
    EXPECT_FALSE(client.is_connected());
    EXPECT_FALSE(mute_a.closed());
    EXPECT_FALSE(mute_b.closed());
}
