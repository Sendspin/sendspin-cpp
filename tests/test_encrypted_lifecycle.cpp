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

// Integration tests for the protocol-level connection lifecycle: a real SendspinClient driving
// admission, the hello/activate cycle, pairing, and an in-band re-handshake against
// fake Sendspin "server" peers that speak real Noise KKpsk2 over a real loopback WebSocket.
// test_connection_lifecycle.cpp covers the connection nursery's structural mechanics (accept,
// prove, admit, reap, arbitration) over the same encrypted transport; the crypto primitives
// themselves have their own coverage in test_noise_transport.cpp / test_noise_rehandshake.cpp /
// test_admission.cpp.
//
// The fake servers (lifecycle_test_fixtures.h) play the Noise INITIATOR role using raw noise-c,
// since the project's own NoiseSession class only implements the responder side, matching the
// "client is always the Noise responder" invariant.

#include "connection.h"
#include "connection_manager.h"
#include "constants.h"
#include "crypto/constants.h"
#include "crypto/keys.h"
#include "lifecycle_test_fixtures.h"
#include "log_capture.h"
#include "platform/crypto.h"
#include "platform/logging.h"
#include "record_store.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/color_role.h"
#include "sendspin/controller_role.h"
#include "sendspin/player_role.h"
#include "sendspin/metadata_role.h"
#include "sendspin/persistence_codec.h"
#include "sendspin/types.h"

#include <gtest/gtest.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketMessage.h>
#include <ixwebsocket/IXWebSocketMessageType.h>

#include <ArduinoJson.h>

#include <algorithm>
#include <array>
#include <functional>
#include <memory>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <future>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

constexpr uint16_t RESUME_TEST_PORT = 18991;
constexpr uint16_t DOWNGRADE_TEST_PORT = 18992;
constexpr uint16_t PAIRING_TEST_PORT = 18993;
constexpr uint16_t PAIRING_PERSIST_FAILURE_TEST_PORT = 18995;
constexpr uint16_t PAIR_METHODS_TEST_PORT = 18997;
constexpr uint16_t AEAD_FAILURE_TEST_PORT = 18998;
constexpr uint16_t AEAD_FAILURE_OUTBOUND_PORT = 18999;
constexpr uint16_t PREHANDSHAKE_BINARY_TEST_PORT = 19000;
constexpr uint16_t PREADMISSION_ROLE_TEST_PORT = 19001;
constexpr uint16_t REVOCATION_SWEEP_TEST_PORT = 19002;
constexpr uint16_t REACTIVATE_PAIRING_TEST_PORT = 19003;
constexpr uint16_t UNPAIR_RECORD_TEST_PORT = 19004;
constexpr uint16_t UNPAIR_SENTINEL_TEST_PORT = 19005;
constexpr uint16_t INACTIVE_ROLE_SEND_TEST_PORT = 19006;
constexpr uint16_t LEAVE_TEST_PORT = 19007;
constexpr uint16_t LEAVE_REPROVE_TEST_PORT = 19008;
constexpr uint16_t LEAVE_PAIRING_TEST_PORT = 19009;
constexpr uint16_t REKEY_ROLE_SEND_TEST_PORT = 19010;
constexpr uint16_t REPROVE_REHANDSHAKE_TEST_PORT = 19011;
constexpr uint16_t COMBINED_FIRST_TEST_PORT = 19012;
constexpr uint16_t COMBINED_REKEY_TEST_PORT = 19013;
constexpr uint16_t COMBINED_METHOD_TEST_PORT = 19014;
constexpr uint16_t RESELECT_PAIRING_TEST_PORT = 19015;
constexpr uint16_t ROLE_STATE_OBJECTS_TEST_PORT = 19016;
constexpr uint16_t ROLE_ADDED_STATE_TEST_PORT = 19017;
constexpr uint16_t METADATA_SCHEDULE_TEST_PORT = 19018;
constexpr uint16_t METADATA_PENDING_TEST_PORT = 19019;
constexpr uint16_t LOSE_CAPABILITY_TEST_PORT = 19041;
constexpr uint16_t REFUSED_ACTIVATE_TEST_PORT = 19042;
constexpr uint16_t COLOR_SCHEDULE_TEST_PORT = 19043;
constexpr uint16_t COLOR_PENDING_TEST_PORT = 19044;
constexpr uint16_t COLOR_BOTH_DUE_TEST_PORT = 19045;
constexpr uint16_t BLOCKING_RECORD_WRITE_TEST_PORT = 19046;

// Starts with no pairing records (unpaired: only the Sentinel PSK resolves), but captures every
// record persisted via save_blob(persistence_keys::RECORDS, ...), so the pairing-flow test below
// can assert on the psk_id/server_id/psk that pairing generated and persisted, and hand the same
// psk/psk_id back to the fake server for the follow-up in-band re-handshake. The
// server/pair-finalize commit is RAM-only on the network thread; the save_blob call this
// captures is the deferred flush from the next loop() tick (RecordStore::persist_records()).
// Locked anyway, per the general rule that a test provider should not assume the library's
// threading beyond its documented contract.
class PairingCapturePersistenceProvider : public SendspinPersistenceProvider {
public:
    // load_blob(RECORDS) is not overridden beyond the base class's nullopt default: "starts with
    // no pairing records" above, so restating it here would be a no-op override.

    // Optionally pre-seed an accepted Pairing PSK, so a fake server can connect on it directly
    // (matching PskCategory::PAIRING immediately) rather than on the Sentinel PSK. Must be set
    // before start() reads it into the RecordStore.
    void set_configured_pairing_psk(SendspinPairingPsk psk) {
        this->configured_pairing_psk_ = std::move(psk);
    }

    // Optionally pre-seed a LONG_TERM record so the fake server can connect to it directly
    // (bypassing pairing) before a test drives an in-band re-handshake onto the pairing PSK
    // above, on an already-admitted connection. Must be set before start() reads it into
    // the RecordStore, like set_configured_pairing_psk() above.
    void set_seeded_long_term_record(SendspinPairingRecord record) {
        this->seeded_long_term_record_ = std::move(record);
    }

    /// Seeds the stored pairing config. A configured Pairing PSK counts as provisioned material,
    /// so SendspinClientConfig's first-boot unpaired-access seed no longer applies and the stored
    /// config is the only way to turn unpaired access on. Must be called before start().
    void set_unpaired_access_enabled(bool enabled) {
        this->unpaired_access_enabled_ = enabled;
    }

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key == persistence_keys::PAIR_CONFIG) {
            SendspinPairingConfig config;
            config.unpaired_access_enabled = this->unpaired_access_enabled_;
            std::string encoded = encode_pairing_config(config);
            return std::vector<uint8_t>(encoded.begin(), encoded.end());
        }
        if (key == persistence_keys::PAIRING_PSK && this->configured_pairing_psk_.has_value()) {
            std::string encoded = encode_pairing_psk(this->configured_pairing_psk_.value());
            return std::vector<uint8_t>(encoded.begin(), encoded.end());
        }
        if (key == persistence_keys::RECORDS && this->seeded_long_term_record_.has_value()) {
            std::string encoded =
                encode_pairing_records({this->seeded_long_term_record_.value()});
            return std::vector<uint8_t>(encoded.begin(), encoded.end());
        }
        return std::nullopt;
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (key != persistence_keys::RECORDS) {
            return true;  // pair_config etc. are not under test here.
        }
        std::string_view text(reinterpret_cast<const char*>(data), len);
        auto decoded = decode_pairing_records(text).value_or(std::vector<SendspinPairingRecord>{});
        if (decoded.empty()) {
            return true;
        }
        std::lock_guard<std::mutex> lock(this->mutex_);
        if (this->reject_pairing_records_) {
            this->rejected_record_saves_++;
            return false;
        }
        this->captured_ = decoded.front();
        return true;
    }

    std::optional<SendspinPairingRecord> captured_record() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->captured_;
    }

    // When set, save_blob(RECORDS, ...) rejects any write that carries a record (simulating a
    // persistence-provider failure, e.g. storage full). Used to verify the deferred fail-open
    // contract: the pairing still completes on the RAM commit, and the rejected flush (counted
    // below) is only a durability warning.
    void set_reject_pairing_records(bool reject) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->reject_pairing_records_ = reject;
    }

    // Proves the deferred flush was attempted: a rejected write captures nothing.
    int rejected_record_saves() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->rejected_record_saves_;
    }

private:
    mutable std::mutex mutex_;
    std::optional<SendspinPairingRecord> captured_;
    int rejected_record_saves_{0};
    bool reject_pairing_records_{false};
    std::optional<SendspinPairingPsk> configured_pairing_psk_;
    std::optional<SendspinPairingRecord> seeded_long_term_record_;
    bool unpaired_access_enabled_{false};
};

// Records on_trust_changed / on_pairing_succeeded notifications so the pairing-flow test can
// assert both that pairing was reported successful and that trust was later upgraded to USER
// once the post-pairing re-handshake completes. Callbacks fire from SendspinClient::loop() on
// the test thread (see EventState's dispatch block), so no locking is needed here.
class RecordingClientListener : public SendspinClientListener {
public:
    void on_trust_changed(ConnectionTrust trust) override {
        this->trust_history_.push_back(trust);
    }

    void on_pairing_started(const std::string& server_id) override {
        this->pairing_started_server_id_ = server_id;
        this->pairing_started_seq_ = this->next_seq_++;
    }

    void on_pairing_succeeded(const std::string& server_id) override {
        this->pairing_succeeded_server_id_ = server_id;
        this->pairing_succeeded_seq_ = this->next_seq_++;
    }

    void on_pairing_failed(const std::string& server_id, SendspinPairAbortReason reason) override {
        this->pairing_failed_server_id_ = server_id;
        this->pairing_failed_reason_ = reason;
    }

    bool trust_ever_reached(ConnectionTrust trust) const {
        for (const auto& t : this->trust_history_) {
            if (t == trust) {
                return true;
            }
        }
        return false;
    }

    const std::optional<std::string>& pairing_started_server_id() const {
        return this->pairing_started_server_id_;
    }

    const std::optional<std::string>& pairing_succeeded_server_id() const {
        return this->pairing_succeeded_server_id_;
    }

    const std::optional<std::string>& pairing_failed_server_id() const {
        return this->pairing_failed_server_id_;
    }

    const std::optional<SendspinPairAbortReason>& pairing_failed_reason() const {
        return this->pairing_failed_reason_;
    }

    /// Dispatch order of the pairing callbacks, for asserting that started precedes its
    /// terminal event. nullopt until the corresponding callback fires.
    const std::optional<size_t>& pairing_started_seq() const {
        return this->pairing_started_seq_;
    }

    const std::optional<size_t>& pairing_succeeded_seq() const {
        return this->pairing_succeeded_seq_;
    }

private:
    std::vector<ConnectionTrust> trust_history_;
    size_t next_seq_{0};
    std::optional<size_t> pairing_started_seq_;
    std::optional<size_t> pairing_succeeded_seq_;
    std::optional<std::string> pairing_started_server_id_;
    std::optional<std::string> pairing_succeeded_server_id_;
    std::optional<std::string> pairing_failed_server_id_;
    std::optional<SendspinPairAbortReason> pairing_failed_reason_;
};





}  // namespace

// ============================================================================
// Tests
// ============================================================================

// Seeds a client whose Pairing PSK is configured and whose unpaired access is on, which is what
// messaging.md "server/activate" requires before a pairing-PSK connection may declare playback.
SendspinPairingPsk seed_pairing_psk(PairingCapturePersistenceProvider& persistence, uint8_t base) {
    std::array<uint8_t, 32> psk_bytes{};
    for (size_t i = 0; i < psk_bytes.size(); ++i) {
        psk_bytes[i] = static_cast<uint8_t>(base + i);
    }
    SendspinPairingPsk psk;
    psk.psk_id = psk_id_for(psk_bytes);
    psk.psk = psk_bytes;
    persistence.set_configured_pairing_psk(psk);
    persistence.set_unpaired_access_enabled(true);
    return psk;
}

// Full encrypted lifecycle: accept -> Noise handshake -> hello -> server/activate -> operational,
// then a server-initiated in-band re-handshake on the ADMITTED connection -> the connection must
// come back operational via a fresh hello/activate cycle under the new session keys, without ever
// being dropped or re-entering nursery arbitration, on the strength of that activation alone:
// connection.md "Re-handshake" makes server/activate the server's first message under the new
// keys and re-sends neither hello.
TEST(EncryptedLifecycle, InBandRehandshakeResumesOperational) {
    SendspinClientConfig config;
    config.name = "Encrypted Lifecycle Test Client";
    config.server_port = RESUME_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    const Identity& server_identity = bundle.peer.server_identity;
    FakeEncryptedServer server(server_url(RESUME_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               server_identity, bundle.peer.record.psk_id, bundle.peer.psk);

    // Initial handshake + hello + activate must bring the connection operational.
    pump_until(client, [&] { return client.is_connected(); });
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());
    EXPECT_EQ(server.client_hello_count(), 1);

    // Trigger the in-band re-handshake on the ADMITTED connection (same PSK: this test isolates
    // resumption from trust change, which is covered separately below).
    ASSERT_TRUE(server.trigger_rehandshake(bundle.peer.record.psk_id, bundle.peer.psk));

    // Immediately after the swap the connection must go non-operational: first_activate_received_
    // is reset. This is the expected transient dip described in connection_manager.h's invariant
    // comment, not a failure.
    pump_until(client, [&] { return !client.is_connected(); });

    // The post-swap server/activate alone brings it back.
    pump_until(client, [&] { return client.is_connected(); });
    EXPECT_EQ(server.client_hello_count(), 1) << "client/hello must not be re-sent";
    EXPECT_EQ(server.activate_count(), 2) << "the server's first message under the new keys";
    // server_id is unchanged (same server, new session keys).
    auto info2 = client.get_server_information();
    ASSERT_TRUE(info2.has_value());
    EXPECT_EQ(info2->server_id, server_identity.peer_id());
    EXPECT_FALSE(server.closed());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// close_silently() (spec Failure Handling: no application-level message on an AEAD
// failure/malformed fragment/handshake abort) must never call disconnect(). On a host OUTBOUND
// connection, disconnect() ends up calling ix::WebSocket::stop() from inside
// dispatch_completed_message(), itself invoked synchronously from IXWebSocket's own worker thread
// callback. Joining the current thread from itself throws std::system_error, which escapes
// WebSocket::run() uncaught and calls std::terminate(), crashing the whole test process.
//
// This must be driven through a real client.connect_to() (SendspinClientConnection): plugging a
// fake peer into client.start() instead (as every other test in this file does) exercises
// SendspinServerConnection, whose disconnect() only ever calls the already-async trigger_close()
// and was never vulnerable to this bug. FakeOutboundEncryptedServer above plays the opposite role
// (a real ix::WebSocketServer the DUT connects out to) specifically so this test reaches
// SendspinClientConnection::disconnect().
//
// This test drives a real Noise AEAD decrypt failure on that real outbound host connection (the
// simplest of the three close_silently() triggers to produce from a fake peer): close_silently()
// must use close_transport_now(), which never blocks or joins, so merely completing this test
// without the process aborting is the primary assertion. It also checks that the connection
// is reported lost exactly once and that no client/goodbye is sent (the close is silent, per spec).
TEST(EncryptedLifecycle, AeadFailureOnOutboundConnectionDoesNotCrash) {
    SendspinClientConfig config;
    config.name = "AEAD Failure Outbound Test Client";
    config.server_port = AEAD_FAILURE_TEST_PORT;  // unused: this test never accepts inbound

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    const Identity& server_identity = bundle.peer.server_identity;
    FakeOutboundEncryptedServer server(AEAD_FAILURE_OUTBOUND_PORT,
                                       std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                       bundle.peer.record.psk_id, bundle.peer.psk);
    ASSERT_TRUE(server.listen());
    server.start();

    client.connect_to(server_url(AEAD_FAILURE_OUTBOUND_PORT));

    pump_until(client, [&] { return client.is_connected(); });

    // Send one tampered ciphertext frame. If close_silently() ever regresses back to calling
    // disconnect() on the network thread here, the test process crashes via std::terminate()
    // instead of reaching the assertions below.
    ASSERT_TRUE(server.send_tampered_frame());

    pump_until(client, [&] { return !client.is_connected(); });

    // Give any duplicate loss-report/close event a chance to arrive and confirm it is tolerated
    // (drop_connection() no-ops on a connection it no longer manages) rather than double-freeing
    // or otherwise misbehaving.
    pump_for(client, 200);
    EXPECT_FALSE(client.is_connected());

    // Spec Failure Handling: no client/goodbye is sent for a silent close.
    EXPECT_FALSE(server.goodbye_reason().has_value());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Negative path: a post-re-handshake server/activate that the new PSK category cannot admit must
// still go through the existing inadmissible-activate drop path (trust enforcement applies
// identically whether the activate follows the initial handshake or a re-handshake), closing with
// the correct client/goodbye reason.
TEST(EncryptedLifecycle, PostRehandshakeInadmissibleActivateDrops) {
    SendspinClientConfig config;
    config.name = "Encrypted Lifecycle Downgrade Test Client";
    config.server_port = DOWNGRADE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    const Identity& server_identity = bundle.peer.server_identity;
    // After the re-handshake, the fake server keeps declaring ["playback"], which the
    // SENTINEL-category PSK it re-handshakes to cannot satisfy while unpaired access is disabled
    // (see admission.h::activities_allowed).
    FakeEncryptedServerOptions options;
    options.second_activities_json = R"(["playback"])";
    options.second_roles_json = R"([])";
    FakeEncryptedServer server(server_url(DOWNGRADE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
                               options);

    pump_until(client, [&] { return client.is_connected(); });

    // Re-handshake down to the Sentinel PSK (unpaired access is disabled by default, so
    // ["playback"] is inadmissible for it).
    ASSERT_TRUE(server.trigger_rehandshake(std::string(SENTINEL_PSK_ID), SENTINEL_PSK));

    // The connection must be dropped (never come back operational) once the inadmissible
    // server/activate is processed, and the fake server must observe the WS close.
    pump_until(client, [&] { return server.closed(); });
    EXPECT_FALSE(client.is_connected());

    auto reason = server.goodbye_reason();
    ASSERT_TRUE(reason.has_value()) << "No client/goodbye observed before close";
    EXPECT_EQ(reason.value(), "pairing_required")
        << "Enabling unpaired access would have admitted this activate, so the server must be "
           "told pairing is what is missing";

    pump_for(client, 100);
}

// The hello must advertise a pairing method the server can actually start. pairing_psk is the
// client-mandatory method and its PSK is auto-provisioned by the RecordStore on first boot, so it
// is advertised even though nothing was persisted here; dynamic_pairing_code joins it because
// this client declares an out-channel and an emission format. A client that advertises neither
// leaves a server (and its operator) with no way into pairing at all.
TEST(EncryptedLifecycle, HelloAdvertisesPairingMethods) {
    SendspinClientConfig config;
    config.name = "Pair Methods Test Client";
    config.server_port = PAIR_METHODS_TEST_PORT;
    config.pairing_code_out_channels = {SendspinPairingCodeChannel::DISPLAY};
    config.pairing_code_formats = {SendspinPairingCodeFormat::DIGITS};

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    const Identity& server_identity = bundle.peer.server_identity;
    FakeEncryptedServer server(server_url(PAIR_METHODS_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               bundle.peer.record.psk_id, bundle.peer.psk);

    pump_until(client, [&] { return client.is_connected(); });

    std::vector<std::string> methods = server.hello_pair_methods();
    auto advertises = [&methods](const std::string& name) {
        return std::find(methods.begin(), methods.end(), name) != methods.end();
    };
    EXPECT_TRUE(advertises("pairing_psk"))
        << "pairing_psk is client-mandatory and its PSK is auto-provisioned";
    EXPECT_TRUE(advertises("dynamic_pairing_code"))
        << "an out-channel and an emission format were configured on this client";
    EXPECT_FALSE(advertises("static_pairing_code"))
        << "no static pairing code or pairing window on this client";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Full pairing-PSK flow end to end: the operator has already transferred a Pairing PSK to the
// server out of band (a pairing token; see crypto/pairing_token.h), so the server's initial
// handshake resolves it directly to PskCategory::PAIRING (spec: "pairing.method MUST be
// 'pairing_psk' if and only if the matched PSK IS the Pairing PSK". The client enforces this via
// ConnectionManager::loop()'s pairing-method admissibility check, so a fake server that selected
// pairing_psk over a Sentinel-matched connection is correctly rejected as method_not_supported).
// The client generates a fresh long-term PSK client-side (CSPRNG) and sends it via
// client/pair-finalize, the server acks, the client persists the record, and then, exactly like a
// real server immediately rekeying onto the new PSK, the fake server triggers an in-band
// re-handshake with the learned psk_id/psk. The connection must resume operational under the new
// session with trust upgraded from PAIRING to USER (LONG_TERM).
TEST(EncryptedLifecycle, PairingPskFlowPersistsAndUpgradesTrust) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    // The Pairing PSK the operator "typed in" (e.g. via a pairing token): known to both the
    // client (so its RecordStore resolves the fake server's handshake to PskCategory::PAIRING)
    // and the fake server (so it can perform that handshake).
    std::array<uint8_t, 32> pairing_psk_bytes{};
    for (size_t i = 0; i < pairing_psk_bytes.size(); ++i) {
        pairing_psk_bytes[i] = static_cast<uint8_t>(0xD0 + i);
    }
    SendspinPairingPsk configured_pairing_psk;
    configured_pairing_psk.psk_id = psk_id_for(pairing_psk_bytes);
    configured_pairing_psk.psk = pairing_psk_bytes;
    persistence.set_configured_pairing_psk(configured_pairing_psk);

    SendspinClientConfig config;
    config.name = "Pairing Flow Test Client";
    config.server_port = PAIRING_TEST_PORT;

    RecordingClientListener listener;
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    // Initial handshake uses the accepted Pairing PSK directly (matching PskCategory::PAIRING),
    // not the Sentinel PSK: the Pairing PSK Flow's initial handshake IS the Pairing PSK (the
    // Sentinel-then-re-handshake path in the spec is only for upgrading an ALREADY-open Sentinel
    // connection into pairing_psk pairing, a different scenario from this one).
    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.first_activities_json = R"(["pairing"])";
    options.first_roles_json = R"([])";
    options.first_pairing_method = "pairing_psk";
    // The initial handshake runs on the Pairing PSK, so message 1 declares that category
    // (messaging.md "noise/handshake").
    options.psk_category = "pr";
    FakeEncryptedServer server(server_url(PAIRING_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
                               server_identity, configured_pairing_psk.psk_id, pairing_psk_bytes,
                               options);

    // handle_enter_pairing (PAIRING_PSK branch) fires as soon as the pairing activate is admitted
    // and sends client/pair-finalize; the fake server acks it immediately in handle_binary().
    pump_until(client, [&] { return server.learned_psk_id().has_value(); });

    // pairing.md "Pairing PSK Flow": the client sends client/pair-init immediately before
    // client/pair-finalize. The init starts the attempt and carries the index of the pairing
    // activate that admitted it; commit_B belongs to the dynamic pairing code flow, so this one
    // must not carry it.
    EXPECT_TRUE(server.pair_init_preceded_finalize())
        << "client/pair-finalize was sent without a preceding client/pair-init";
    auto pair_init = server.pair_init();
    ASSERT_TRUE(pair_init.has_value());
    EXPECT_EQ(pair_init->pairing_index, 1U);
    EXPECT_FALSE(pair_init->has_commit_b);

    // handle_enter_pairing's Pairing-PSK branch must fire on_pairing_started, exactly like the
    // pairing-code branches do, so the started/succeeded/failed callback trio stays
    // method-agnostic.
    ASSERT_TRUE(listener.pairing_started_server_id().has_value())
        << "on_pairing_started was never fired for the pairing-token (Pairing-PSK) flow";
    EXPECT_EQ(listener.pairing_started_server_id().value(), server_identity.peer_id());

    // The server's ack commits the record to RAM synchronously on the network thread (see
    // client.cpp's SERVER_PAIR_FINALIZE handler); the durable save_blob(RECORDS) this waits for
    // is the deferred flush from the next loop() tick (RecordStore::persist_records()).
    pump_until(client, [&] { return persistence.captured_record().has_value(); });
    auto captured = persistence.captured_record();
    ASSERT_TRUE(captured.has_value());
    EXPECT_EQ(captured->psk_id, server.learned_psk_id().value());
    EXPECT_EQ(captured->server_id, server_identity.peer_id());

    pump_until(client, [&] { return listener.pairing_succeeded_server_id().has_value(); });
    EXPECT_EQ(listener.pairing_succeeded_server_id().value(), server_identity.peer_id());

    // The application must see the exchange begin before it sees it end. The ordering is
    // structural (ConnectionManager::loop() swaps pending events out before draining lifecycle
    // events, and SendspinClient::loop() drains the whole note batch each tick), so pin it here
    // to catch a future reordering of either drain.
    ASSERT_TRUE(listener.pairing_started_seq().has_value());
    ASSERT_TRUE(listener.pairing_succeeded_seq().has_value());
    EXPECT_LT(listener.pairing_started_seq().value(), listener.pairing_succeeded_seq().value())
        << "on_pairing_succeeded was delivered before on_pairing_started";

    // Rekey onto the newly paired PSK, exactly like the real server does immediately after
    // acking pair-finalize (see connection.h's note_pairing_finalize_ack()/provisional-timeout
    // re-arm, which exists precisely to bound this step).
    auto learned_psk = server.learned_psk();
    auto learned_psk_id = server.learned_psk_id();
    ASSERT_TRUE(learned_psk.has_value() && learned_psk_id.has_value());
    ASSERT_TRUE(server.trigger_rehandshake(learned_psk_id.value(), learned_psk.value()));

    // The connection must resume operational under the new session, now with LONG_TERM/USER trust
    // instead of the PAIRING/none trust it started with.
    pump_until(client, [&] { return client.is_connected(); });
    EXPECT_TRUE(listener.trust_ever_reached(ConnectionTrust::USER))
        << "Trust was never upgraded to USER after pairing completed";
    EXPECT_EQ(client.get_current_trust(), ConnectionTrust::USER)
        << "get_current_trust() must report the rekeyed connection's trust";
    auto info = client.get_server_information();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->server_id, server_identity.peer_id());
    EXPECT_FALSE(server.closed());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
    EXPECT_EQ(client.get_current_trust(), ConnectionTrust::NONE)
        << "get_current_trust() must reset to NONE once the connection is torn down";
}

// Regression test for the "re-pair an already-connected client" bug: Music Assistant can
// token-pair a client that is already admitted and operational (LONG_TERM trust). The server
// does this by in-band re-handshaking the LIVE connection onto the Pairing PSK, which resets
// first_activate_received_ exactly like any other re-handshake, then sends a fresh
// server/activate declaring ["pairing"] with pairing.method=pairing_psk. That activate looks
// like a FIRST activate (is_first true), so the pairing-selection check must run on every
// activate, first or not, and take priority over the operational branch: routing it into the
// operational branch resumes time sync and sends client/state, which a server awaiting
// client/pair-finalize treats as a protocol error and hard-drops the connection for.
TEST(EncryptedLifecycle, ReactivatePairingOnAlreadyAdmittedConnectionSendsPairFinalize) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;

    // The server identity is generated up front: the LONG_TERM record below is bound to it
    // (record_store.cpp's handle_msg1 rejects a record whose server_id does not match the peer
    // that presents it), and the fake server later needs the same identity for both handshakes.
    Identity server_identity = Identity::generate().value();

    // The LONG_TERM record the client is already connected and admitted with, before pairing is
    // reopened on the same connection.
    PairedPeer long_term_peer = make_paired_peer();
    long_term_peer.record.server_id = server_identity.peer_id();
    persistence.set_seeded_long_term_record(long_term_peer.record);

    // The Pairing PSK the operator hands to the server out of band (e.g. a fresh pairing token),
    // known ahead of time here so the fake server can re-handshake onto it directly.
    std::array<uint8_t, 32> pairing_psk_bytes{};
    for (size_t i = 0; i < pairing_psk_bytes.size(); ++i) {
        pairing_psk_bytes[i] = static_cast<uint8_t>(0xC0 + i);
    }
    SendspinPairingPsk configured_pairing_psk;
    configured_pairing_psk.psk_id = psk_id_for(pairing_psk_bytes);
    configured_pairing_psk.psk = pairing_psk_bytes;
    persistence.set_configured_pairing_psk(configured_pairing_psk);

    SendspinClientConfig config;
    config.name = "Reactivate Pairing Test Client";
    config.server_port = REACTIVATE_PAIRING_TEST_PORT;

    RecordingClientListener listener;
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    // The FIRST server/activate (default options) is a normal playback activate that brings the
    // connection operational exactly like InBandRehandshakeResumesOperational. The SECOND (sent
    // after the re-handshake below and its resulting fresh client/hello) is the pairing activate
    // that reproduces the bug: it declares ["pairing"]/pairing_psk on what looks like a FIRST
    // activate from the connection's point of view.
    FakeEncryptedServerOptions options;
    options.second_activities_json = R"(["pairing"])";
    options.second_roles_json = R"([])";
    options.second_pairing_method = "pairing_psk";

    FakeEncryptedServer server(server_url(REACTIVATE_PAIRING_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               long_term_peer.record.psk_id, long_term_peer.psk, options);

    pump_until(client, [&] { return client.is_connected(); });
    EXPECT_EQ(client.get_current_trust(), ConnectionTrust::USER);

    // Becoming operational the first time legitimately sends one client/state; only traffic
    // AFTER this point is what the regression check below cares about. Pump a little longer to
    // let that legitimate message actually arrive (is_connected() flips as soon as the activate
    // is applied, slightly before the resulting client/state is sent and received).
    pump_until(client, [&] { return server.client_state_count() > 0; });
    const int state_count_before_repair = server.client_state_count();

    // Re-handshake the LIVE, admitted connection onto the pairing PSK, exactly like the server
    // re-pairing an already-connected client (e.g. Music Assistant token-pairing a device that
    // is already streaming).
    ASSERT_TRUE(server.trigger_rehandshake(configured_pairing_psk.psk_id, pairing_psk_bytes, "pr"))
        << "Failed to start the in-band re-handshake onto the pairing PSK";

    // The fixed client must reply with client/pair-finalize instead of hard-stalling; the
    // pre-fix client never sends it (it sends client/state instead, which a real server treats
    // as a protocol violation).
    pump_until(client, [&] { return server.learned_psk_id().has_value(); });

    // The re-pairing activate starts its attempt the same way: pair-init first, then the
    // finalize (pairing.md "Pairing PSK Flow"). Its pairing index counts the pairing activates
    // since the re-handshake that preceded it, which reset the counter.
    EXPECT_TRUE(server.pair_init_preceded_finalize())
        << "client/pair-finalize was sent without a preceding client/pair-init";
    auto repair_init = server.pair_init();
    ASSERT_TRUE(repair_init.has_value());
    EXPECT_EQ(repair_init->pairing_index, 1U);
    EXPECT_FALSE(repair_init->has_commit_b);

    // The primary regression check: no client/state must have reached the server before (or
    // instead of) client/pair-finalize. handle_enter_pairing() never publishes client/state;
    // only the operational branch (on_handshake_complete) does, so any non-zero count here means
    // the activate was misrouted into the operational path.
    EXPECT_EQ(server.client_state_count(), state_count_before_repair)
        << "client/state must not be sent while the server awaits client/pair-finalize";

    // Confirms the fix routed through handle_enter_pairing() (not just that some message with
    // this shape happened to be sent): the started/succeeded pairing callbacks must fire, exactly
    // like a fresh pairing-PSK flow.
    ASSERT_TRUE(listener.pairing_started_server_id().has_value())
        << "on_pairing_started was never fired for the re-pairing activate";
    EXPECT_EQ(listener.pairing_started_server_id().value(), server_identity.peer_id());

    pump_until(client, [&] { return listener.pairing_succeeded_server_id().has_value(); });
    EXPECT_EQ(server.client_state_count(), state_count_before_repair)
        << "client/state must still not have been sent once pairing succeeded (the connection "
           "goes operational only after the follow-up re-handshake completes)";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Fail-open persistence: when the persistence provider rejects the pair-finalize record write
// (e.g. storage full, write error), the pairing still completes for this boot. The RAM commit on
// the network thread is what the server's follow-up re-handshake resolves, so the connection
// rekeys and upgrades trust exactly like the happy path; the rejected write happens later, at
// the deferred flush from loop() (where the provider is main-loop-only), and costs only a logged
// durability warning: the record is lost at the next reboot. This is deliberate: a provider that
// cannot write will not be fixed by aborting the pairing, so the device stays usable until
// reboot instead of dropping the connection. This test drives the rekey explicitly, since the
// fake server only re-handshakes on request.
TEST(EncryptedLifecycle, PairingPskFlowRejectedPersistStillCompletesPairing) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    persistence.set_reject_pairing_records(true);
    // As in PairingPskFlowPersistsAndUpgradesTrust: the fake server must connect using an
    // accepted Pairing PSK directly (PskCategory::PAIRING), not Sentinel, now that the client
    // enforces pairing.method=pairing_psk iff the matched PSK IS the Pairing PSK.
    std::array<uint8_t, 32> pairing_psk_bytes{};
    for (size_t i = 0; i < pairing_psk_bytes.size(); ++i) {
        pairing_psk_bytes[i] = static_cast<uint8_t>(0xE0 + i);
    }
    SendspinPairingPsk configured_pairing_psk;
    configured_pairing_psk.psk_id = psk_id_for(pairing_psk_bytes);
    configured_pairing_psk.psk = pairing_psk_bytes;
    persistence.set_configured_pairing_psk(configured_pairing_psk);

    SendspinClientConfig config;
    config.name = "Pairing Flow Persist-Failure Test Client";
    config.server_port = PAIRING_PERSIST_FAILURE_TEST_PORT;

    RecordingClientListener listener;
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.first_activities_json = R"(["pairing"])";
    options.first_roles_json = R"([])";
    options.first_pairing_method = "pairing_psk";
    // The initial handshake runs on the Pairing PSK, so message 1 declares that category
    // (messaging.md "noise/handshake").
    options.psk_category = "pr";
    FakeEncryptedServer server(server_url(PAIRING_PERSIST_FAILURE_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               configured_pairing_psk.psk_id, pairing_psk_bytes, options);

    pump_until(client, [&] { return server.learned_psk_id().has_value(); });

    // The pairing must be reported successful on the RAM commit alone.
    pump_until(client, [&] { return listener.pairing_succeeded_server_id().has_value(); });
    EXPECT_EQ(listener.pairing_succeeded_server_id().value(), server_identity.peer_id());
    EXPECT_FALSE(persistence.captured_record().has_value())
        << "A rejected record must not be captured (provider returned false)";
    // (Checked after the succeeded callback, so this proves the flush was attempted and
    // rejected, not the flush-before-callback ordering within the tick; that ordering is a
    // structural property of loop(), documented there.)
    EXPECT_GE(persistence.rejected_record_saves(), 1)
        << "The deferred flush must have been attempted (and rejected)";

    // Rekey onto the new PSK, exactly like the real server does immediately after acking
    // pair-finalize. Unlike the retired fail-closed contract, the client CAN resolve the psk_id
    // (the record is in RAM), so the re-handshake succeeds and trust upgrades to USER; only a
    // reboot loses the pairing.
    auto learned_psk = server.learned_psk();
    auto learned_psk_id = server.learned_psk_id();
    ASSERT_TRUE(learned_psk.has_value() && learned_psk_id.has_value());
    ASSERT_TRUE(server.trigger_rehandshake(learned_psk_id.value(), learned_psk.value()));

    pump_until(client, [&] { return client.is_connected(); });
    EXPECT_EQ(client.get_current_trust(), ConnectionTrust::USER)
        << "Trust must upgrade to USER on the RAM-committed record";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A binary WebSocket frame that arrives while the Noise handshake is still pending must close the
// connection, not be dispatched.
//
// The binary branch of dispatch_completed_message() closes rather than dispatching: letting a peer
// skip client/init entirely, send a raw binary frame, and have it handed to the role binary
// handlers would bypass the whole Noise/PSK/admission chain. The TEXT branch routes pre-handshake
// text into the handshake driver instead, so it does not share this gap.
TEST(EncryptedLifecycle, BinaryFrameBeforeNoiseHandshakeClosesConnection) {
    TestNetworkProvider network;
    SendspinClientConfig config;
    config.name = "Pre-Handshake Binary Test Client";
    config.server_port = PREHANDSHAKE_BINARY_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    // A bare WebSocket peer: it completes the upgrade and then says nothing the protocol expects.
    std::atomic<bool> opened{false};
    std::atomic<bool> closed{false};
    ix::WebSocket ws;
    ws.setUrl(server_url(PREHANDSHAKE_BINARY_TEST_PORT));
    ws.disableAutomaticReconnection();
    ws.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
        if (msg->type == ix::WebSocketMessageType::Open) {
            opened.store(true);
        } else if (msg->type == ix::WebSocketMessageType::Close) {
            closed.store(true);
        }
    });
    ws.start();

    pump_until(client, [&] { return opened.load(); });

    // No client/init, no handshake: straight to a player-shaped binary frame (type byte 4 =
    // player role, slot 0, followed by what would be an 8-byte timestamp and a payload).
    const std::string binary_frame(
        "\x04\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef", 13);
    ws.sendBinary(binary_frame);

    pump_until(client, [&] { return closed.load(); });

    ws.stop();
    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// messaging.md "client/leave": a client that no longer wants to take part in its group's playback
// says so, and the server moves it to a solo stopped group. It needs an admitted connection that
// has been activated; before that there is no group to leave and nothing may be sent.
TEST(EncryptedLifecycle, LeaveIsSentOnlyOnAnActivatedConnection) {
    SendspinClientConfig config;
    config.name = "Leave Test Client";
    config.server_port = LEAVE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    // No connection at all: the call is refused rather than queued for the next server.
    client.leave();
    pump_for(client, 20);

    FakeEncryptedServerOptions options;
    options.suppress_activate = true;
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(LEAVE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    // Handshake and hello complete, but the connection is never activated, so it stays in the
    // nursery and has no group.
    pump_until(client, [&] { return server->client_hello_count() > 0; });
    client.leave();
    pump_for(client, 50);
    EXPECT_EQ(server->client_leave_count(), 0)
        << "client/leave was sent on a connection that was never activated";

    // Control: once the activate lands and the connection is admitted, the same call goes out.
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["player@v1"]}})"));
    pump_until(client, [&] { return client.is_connected(); });
    client.leave();
    pump_until(client, [&] { return server->client_leave_count() == 1; });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// An in-band re-handshake rewinds the connection to awaiting its next server/activate while it
// keeps the admitted slot, and connection.md "Re-handshake" allows nothing but that activation
// until it arrives, so client/leave waits for it.
TEST(EncryptedLifecycle, LeaveWaitsForTheActivateThatFollowsAReHandshake) {
    SendspinClientConfig config;
    config.name = "Leave Reprove Test Client";
    config.server_port = LEAVE_REPROVE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.suppress_activate = true;  // Every activate in this test is sent by hand.
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(LEAVE_REPROVE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    const std::string playback_activate =
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["player@v1"]}})";

    pump_until(client, [&] { return server->client_hello_count() > 0; });
    ASSERT_TRUE(server->send_app_json(playback_activate));
    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server->trigger_rehandshake(bundle.peer.record.psk_id, bundle.peer.psk));
    pump_until(client, [&] { return !client.is_connected(); });
    EXPECT_EQ(server->client_hello_count(), 1)
        << "connection.md \"Re-handshake\": client/hello is not re-sent";

    client.leave();
    pump_for(client, 50);
    EXPECT_EQ(server->client_leave_count(), 0)
        << "client/leave was sent while the connection awaited its post-rekey activate";

    // Control: the same call goes out once that activation arrives.
    ASSERT_TRUE(server->send_app_json(playback_activate));
    pump_until(client, [&] { return client.is_connected(); });
    client.leave();
    pump_until(client, [&] { return server->client_leave_count() == 1; });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// pairing.md "Entering and leaving pairing": pairing runs alongside playback, and a
// server/activate that adds 'pairing' does not by itself affect active_roles, streams or group
// membership. messaging.md "server/activate" lists ['playback', 'pairing'] as an allowed set for
// the Pairing PSK when unpaired access is enabled, so such an activation must both enter the
// pairing path and leave the playback side of the connection running.
TEST(EncryptedLifecycle, PlaybackKeepsRunningWhenAnActivateAddsPairing) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xB0);

    SendspinClientConfig config;
    config.name = "Playback With Pairing Test Client";
    config.server_port = LEAVE_PAIRING_TEST_PORT;
    config.time_burst_interval_ms = 100;  // Converge the filter promptly so audio can schedule.

    CountingPlayerListener player_listener;
    SendspinClient client(config);
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    auto& controller = client.add_controller();
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.psk_category = "pr";
    options.suppress_activate = true;  // Every activate in this test is sent by hand.
    options.answer_time = true;        // The player needs a converged filter to schedule audio.
    // Holding the attempt in flight keeps the connection on the activation it was admitted with,
    // instead of rewinding it to await the post-pairing rekey's activate.
    options.withhold_pair_finalize_ack = true;
    FakeEncryptedServer server(server_url(LEAVE_PAIRING_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               pairing_psk.psk_id, pairing_psk.psk, options);

    pump_until(client, [&] { return server.client_hello_count() > 0; });

    // Playback first, on the Pairing PSK: allowed because unpaired access is enabled.
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["player@v1","controller@v1"]}})"));
    pump_until(client, [&] { return client.is_connected(); });

    // A real player stream, so "streams stay open" is observed rather than argued.
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"stream/start","payload":{"player":{"codec":"pcm","sample_rate":48000,)"
        R"("channels":2,"bit_depth":16}}})"));
    pump_until(client, [&] { return player_listener.stream_starts == 1; });
    stream_audio_until(client, server, player_listener, 1);

    controller.send_command({.command = SendspinControllerCommand::PLAY});
    pump_until(client, [&] { return server.controller_commands().size() == 1; });
    client.leave();
    pump_until(client, [&] { return server.client_leave_count() == 1; });

    // The same connection now also declares pairing, keeping its roles.
    const size_t writes_before = player_listener.audio_writes.load();
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback","pairing"],)"
        R"("active_roles":["player@v1","controller@v1"],"pairing":{"method":"pairing_psk"}}})"));
    pump_until(client, [&] { return server.pair_init().has_value(); });

    // pairing.md "Entering and leaving pairing": the stream stays open and keeps playing, and no
    // stream/end or clear was synthesized for the activate.
    EXPECT_EQ(player_listener.stream_starts, 1);
    EXPECT_EQ(player_listener.stream_ends, 0) << "adding pairing must not end the stream";
    stream_audio_until(client, server, player_listener, writes_before + 1);

    EXPECT_TRUE(client.is_connected())
        << "adding pairing must not take the connection out of its operational state";
    controller.send_command({.command = SendspinControllerCommand::PAUSE});
    pump_until(client, [&] { return server.controller_commands().size() == 2; });
    EXPECT_EQ(server.controller_commands().back(), "pause");
    client.leave();
    pump_until(client, [&] { return server.client_leave_count() == 2; });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// pairing.md "Entering and leaving pairing" admits one pairing attempt per pairing
// server/activate. A server that abandons an attempt by sending another activate that itself
// selects pairing has started a new one, and is waiting for the client/pair-init that opens it,
// so the client must end the old attempt and start the new one rather than only going
// operational.
TEST(EncryptedLifecycle, AnActivateThatReselectsPairingStartsTheNewAttempt) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xA0);

    SendspinClientConfig config;
    config.name = "Reselect Pairing Test Client";
    config.server_port = RESELECT_PAIRING_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.psk_category = "pr";
    options.first_activities_json = R"(["pairing"])";
    options.first_roles_json = R"([])";
    options.first_pairing_method = "pairing_psk";
    // The attempt is left in flight so the second activate arrives as a leftover one.
    options.withhold_pair_finalize_ack = true;
    FakeEncryptedServer server(server_url(RESELECT_PAIRING_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               pairing_psk.psk_id, pairing_psk.psk, options);

    pump_until(client, [&] { return server.pair_init().has_value(); });
    ASSERT_EQ(server.pair_init()->pairing_index, 1U);

    // A second pairing activate on the same connection, while the first attempt is still in
    // flight: it admits a new attempt, whose pairing_index is the one it counted.
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/activate","payload":{"activities":["pairing"],)"
        R"("active_roles":[],"pairing":{"method":"pairing_psk"}}})"));

    pump_until(client, [&] { return server.pair_init()->pairing_index == 2U; });
    EXPECT_TRUE(server.pair_abort_reasons().empty()) << "re-selecting pairing is not an abort";
    EXPECT_TRUE(server.pair_init_preceded_finalize())
        << "the new attempt opens with client/pair-init, like any other";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A role that the server has not activated drives no traffic of its own: messaging.md
// "server/activate" has servers tolerate inactive-role objects only because a client that has
// received the removal stops sending them. The client is admitted here with the player role
// alone, so its controller commands must stay off the wire until an activate adds the role.
TEST(EncryptedLifecycle, ControllerCommandsWaitForTheRoleToBeActive) {
    SendspinClientConfig config;
    config.name = "Inactive Role Send Test Client";
    config.server_port = INACTIVE_ROLE_SEND_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    auto& controller = client.add_controller();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["player@v1"])";
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(INACTIVE_ROLE_SEND_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return client.is_connected(); });

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

namespace {

// The roles whose client/state objects these tests read, configured the way a display device
// would: two artwork channels and a spectrum visualizer.
void add_state_object_roles(SendspinClient& client) {
    PlayerRoleConfig player_config;
    player_config.audio_formats = {{SendspinCodecFormat::PCM, 2, 44100, 16}};
    client.add_player(std::move(player_config));

    ArtworkRoleConfig artwork_config;
    artwork_config.preferred_formats = {
        {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 320, 320},
        {SendspinImageSource::ARTIST, SendspinImageFormat::PNG, 64, 64},
    };
    client.add_artwork(std::move(artwork_config));

    VisualizerRoleConfig visualizer_config;
    visualizer_config.support.buffer_capacity = 4096;
    visualizer_config.stream.types = {VisualizerDataType::SPECTRUM};
    visualizer_config.stream.rate_max = 30;
    visualizer_config.stream.spectrum = VisualizerSpectrumConfig{
        .n_disp_bins = 16,
        .scale = VisualizerSpectrumScale::MEL,
        .f_min = 40,
        .f_max = 16000,
    };
    client.add_visualizer(std::move(visualizer_config));
}

// Parses the last client/state the fake server received. Fails the calling test if none arrived.
bool parse_last_client_state(const FakeEncryptedServer& server, JsonDocument& doc) {
    const std::vector<std::string> states = server.client_states();
    if (states.empty()) {
        ADD_FAILURE() << "no client/state was sent";
        return false;
    }
    return deserializeJson(doc, states.back()) == DeserializationError::Ok;
}

}  // namespace

// messaging.md "client/state": a client/state carries an object for each role that is active, and
// nothing for a role that is not, since a server must ignore an inactive role's object rather
// than stream from it. The client configures all three state-object roles here and the server
// activates two of them, so one message shows both halves of that rule.
TEST(EncryptedLifecycle, ClientStateCarriesAnObjectForEachActiveRole) {
    SendspinClientConfig config;
    config.name = "Role State Objects Test Client";
    config.server_port = ROLE_STATE_OBJECTS_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    add_state_object_roles(client);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["player@v1","visualizer@v1"])";
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(ROLE_STATE_OBJECTS_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return server->client_state_count() > 0; });

    JsonDocument doc;
    ASSERT_TRUE(parse_last_client_state(*server, doc));
    JsonObjectConst payload = doc["payload"].as<JsonObjectConst>();

    ASSERT_TRUE(payload["player"].is<JsonObjectConst>()) << "the active player role reported none";
    EXPECT_TRUE(payload["player"]["supported_commands"].is<JsonArrayConst>());

    ASSERT_TRUE(payload["visualizer"].is<JsonObjectConst>())
        << "the active visualizer role reported no state";
    EXPECT_EQ(payload["visualizer"]["rate_max"].as<int>(), 30);
    EXPECT_STREQ(payload["visualizer"]["types"][0], "spectrum");

    // The artwork role is configured on this client but not activated, so its object stays off
    // the wire: a server that received it would have to ignore it.
    EXPECT_TRUE(payload["artwork"].isUnbound())
        << "an inactive role's object was reported in client/state";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// messaging.md "client/state": when a role that defines a state object becomes active in
// active_roles, the client sends an update that includes that role's object, and "stream/start"
// has the server wait for that update before starting the role's stream. A role added by a later
// activation therefore needs its own publication; without one the server never starts its stream.
TEST(EncryptedLifecycle, ActivateThatAddsARoleSendsItsClientState) {
    SendspinClientConfig config;
    config.name = "Role Added State Test Client";
    config.server_port = ROLE_ADDED_STATE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    add_state_object_roles(client);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["player@v1"])";
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(ROLE_ADDED_STATE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return server->client_state_count() > 0; });
    const int states_after_admission = server->client_state_count();
    {
        JsonDocument doc;
        ASSERT_TRUE(parse_last_client_state(*server, doc));
        ASSERT_TRUE(doc["payload"]["artwork"].isUnbound())
            << "artwork@v1 is not active yet, so its object cannot be reported";
    }

    // An activation that leaves the set alone asks for nothing new: the state the server holds is
    // still the state of every active role.
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["player@v1"]}})"));
    pump_for(client, 200);
    EXPECT_EQ(server->client_state_count(), states_after_admission)
        << "an activation that changed no role republished state the server already had";

    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["player@v1","artwork@v1"]}})"));
    pump_until(client, [&] { return server->client_state_count() > states_after_admission; });

    JsonDocument doc;
    ASSERT_TRUE(parse_last_client_state(*server, doc));
    JsonArrayConst channels = doc["payload"]["artwork"]["channels"].as<JsonArrayConst>();
    ASSERT_EQ(channels.size(), 2u) << "the added role's object did not carry its channels";
    EXPECT_STREQ(channels[0]["source"], "album");
    EXPECT_EQ(channels[0]["width"].as<int>(), 320);
    // The roles that were already active are reported in the same message, which is the full
    // state the server keeps for this client.
    EXPECT_TRUE(doc["payload"]["player"].is<JsonObjectConst>());

    // A removal is the mirror image: the next state simply stops carrying the role's object.
    const int states_before_removal = server->client_state_count();
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["player@v1"]}})"));
    pump_until(client, [&] { return server->client_state_count() > states_before_removal; });
    JsonDocument after_removal;
    ASSERT_TRUE(parse_last_client_state(*server, after_removal));
    EXPECT_TRUE(after_removal["payload"]["artwork"].isUnbound())
        << "a removed role's object was still reported";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// connection.md "Re-handshake": once the client has received Noise message 1 it sends nothing but
// the handshake until the new server/activate arrives. Role-originated traffic waits with
// everything else, even though the connection keeps its admitted slot and its active roles
// throughout.
TEST(EncryptedLifecycle, RoleTrafficWaitsForTheActivateThatFollowsAReHandshake) {
    SendspinClientConfig config;
    config.name = "Rekey Role Send Test Client";
    config.server_port = REKEY_ROLE_SEND_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    auto& controller = client.add_controller();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.suppress_activate = true;  // Every activate in this test is sent by hand.
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(REKEY_ROLE_SEND_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    const std::string controller_activate =
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["controller@v1"]}})";

    pump_until(client, [&] { return server->client_hello_count() > 0; });
    ASSERT_TRUE(server->send_app_json(controller_activate));
    pump_until(client, [&] { return client.is_connected(); });
    controller.send_command({.command = SendspinControllerCommand::PLAY});
    pump_until(client, [&] { return !server->controller_commands().empty(); });
    const size_t before_rekey = server->controller_commands().size();

    ASSERT_TRUE(server->trigger_rehandshake(bundle.peer.record.psk_id, bundle.peer.psk));
    pump_until(client, [&] { return !client.is_connected(); });

    controller.send_command({.command = SendspinControllerCommand::PAUSE});
    pump_for(client, 100);
    EXPECT_EQ(server->controller_commands().size(), before_rekey)
        << "a controller command was sent while the connection awaited its post-rekey activate";

    // Control: the same command goes out once that activation arrives, so the gate is the
    // re-handshake window and not the role, which stayed active across it.
    ASSERT_TRUE(server->send_app_json(controller_activate));
    pump_until(client, [&] { return client.is_connected(); });
    controller.send_command({.command = SendspinControllerCommand::PAUSE});
    pump_until(client, [&] { return server->controller_commands().size() > before_rekey; });
    EXPECT_EQ(server->controller_commands().back(), "pause");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A FIRST server/activate of ['playback', 'pairing'] is one of the sets the messaging.md
// "server/activate" table allows. It has to do both things: announce the connection operational
// with its roles (pairing.md "Entering and leaving pairing" leaves active_roles untouched) and
// start the pairing attempt it admits, with the pairing_index that activate counted.
TEST(EncryptedLifecycle, InitialCombinedActivateGoesOperationalAndEntersPairing) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xD0);

    SendspinClientConfig config;
    config.name = "Initial Combined Activate Test Client";
    config.server_port = COMBINED_FIRST_TEST_PORT;

    SendspinClient client(config);
    auto& controller = client.add_controller();
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.psk_category = "pr";
    options.first_activities_json = R"(["playback","pairing"])";
    options.first_roles_json = R"(["controller@v1"])";
    options.first_pairing_method = "pairing_psk";
    // Holding the attempt in flight keeps the connection on the activation it was admitted with,
    // instead of rewinding it to await the post-pairing rekey's activate.
    options.withhold_pair_finalize_ack = true;
    FakeEncryptedServer server(server_url(COMBINED_FIRST_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               pairing_psk.psk_id, pairing_psk.psk, options);

    // The pairing half: the attempt starts, and its pairing_index is the one the activate
    // counted. A client that does not recognize the combined set as a pairing activate never
    // bumps the counter and reports 0 here.
    pump_until(client, [&] { return server.pair_init().has_value(); });
    EXPECT_EQ(server.pair_init()->pairing_index, 1U)
        << "the combined activate must be counted like any other pairing server/activate";

    // The playback half: the connection is operational and publishes client/state, which only
    // the operational path does.
    EXPECT_TRUE(client.is_connected())
        << "a first combined activate must announce the connection operational";
    pump_until(client, [&] { return server.client_state_count() > 0; });

    // ...and its role is active, which is what active_roles surviving the pairing activity means
    // in practice.
    controller.send_command({.command = SendspinControllerCommand::PLAY});
    pump_until(client, [&] { return !server.controller_commands().empty(); });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A refused activation activates nothing, so it must not widen what the client will receive
// either. The receive gate reads a mask the network thread adds an activation's roles to as it
// parses the message, before the main loop judges admissibility; an activation answered with
// pair/abort (pairing.md "Client <-> Server: pair/abort") keeps the connection but never reaches
// the apply step, so those bits have to be taken back with the refusal.
TEST(EncryptedLifecycle, RefusedActivateDoesNotWidenTheReceiveGate) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xC9);

    SendspinClientConfig config;
    config.name = "Refused Activate Gate Test Client";
    config.server_port = REFUSED_ACTIVATE_TEST_PORT;
    // No out-channel, so dynamic_pairing_code is never offered and an activation selecting it is
    // refused while the connection stays open.
    config.pairing_code_out_channels.clear();

    struct CountingControllerListener : ControllerRoleListener {
        std::atomic<int> updates{0};
        void on_controller_state(const ServerStateControllerObject& /*state*/) override {
            this->updates.fetch_add(1);
        }
    };
    CountingControllerListener controller_listener;
    struct CountingMetadataListener : MetadataRoleListener {
        std::atomic<int> updates{0};
        void on_metadata(const ServerMetadataStateObject& /*m*/) override {
            this->updates.fetch_add(1);
        }
    };
    CountingMetadataListener metadata_listener;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    client.add_controller().set_listener(&controller_listener);
    client.add_metadata().set_listener(&metadata_listener);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.psk_category = "pr";
    options.first_activities_json = R"(["playback"])";
    options.first_roles_json = R"(["metadata@v1"])";
    FakeEncryptedServer server(server_url(REFUSED_ACTIVATE_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               pairing_psk.psk_id, pairing_psk.psk, options);

    pump_until(client, [&] { return client.is_connected(); });

    // A later activation that names the controller role and selects a method the client does not
    // offer: refused with pair/abort, connection kept, nothing activated.
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback","pairing"],)"
        R"("active_roles":["metadata@v1","controller@v1"],)"
        R"("pairing":{"method":"dynamic_pairing_code","format":"digits"}}})"));
    pump_until(client, [&] { return !server.pair_abort_reasons().empty(); });
    EXPECT_FALSE(server.closed());

    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/state","payload":{"controller":{"supported_commands":["play"],)"
        R"("volume":42,"muted":false,"repeat":"off","shuffle":false}}})"));
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/state","payload":{"metadata":{"timestamp":1,"title":"Still Active"}}})"));
    pump_until(client, [&] { return metadata_listener.updates == 1; });
    EXPECT_EQ(controller_listener.updates, 0)
        << "a refused activation left the controller role able to receive";

    // Control: an activation the client accepts puts the same role in service, and the same state
    // is applied.
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["metadata@v1","controller@v1"]}})"));
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/state","payload":{"controller":{"supported_commands":["play"],)"
        R"("volume":42,"muted":false,"repeat":"off","shuffle":false}}})"));
    pump_until(client, [&] { return controller_listener.updates == 1; });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// messaging.md "server/activate", "Playback-capable connections": a later activation that changes
// the activities so the connection is no longer playback-capable, without sending active_roles,
// makes the client treat the persisted roles as empty. That is a role removal like any other, so
// the roles it drops are torn down: here a session on a long-term record is re-handshaked onto the
// Pairing PSK and activated for pairing alone, which a client without unpaired access may not
// carry roles on. The activation is admissible, so the connection stays and the pairing it admits
// begins: after the teardown, not instead of it.
TEST(EncryptedLifecycle, ActivateThatLosesPlaybackCapabilityRemovesTheRoles) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;

    Identity server_identity = Identity::generate().value();
    PairedPeer long_term_peer = make_paired_peer();
    long_term_peer.record.server_id = server_identity.peer_id();
    persistence.set_seeded_long_term_record(long_term_peer.record);
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xC5);
    // Without unpaired access, messaging.md "server/activate" allows a pairing-PSK connection no
    // activity set that includes playback, so declaring pairing alone is what takes this
    // connection's playback capability away.
    persistence.set_unpaired_access_enabled(false);

    SendspinClientConfig config;
    config.name = "Lost Capability Test Client";
    config.server_port = LOSE_CAPABILITY_TEST_PORT;

    struct ClearRecordingMetadataListener : MetadataRoleListener {
        std::atomic<int> updates{0};
        std::atomic<int> clears{0};
        void on_metadata(const ServerMetadataStateObject& /*m*/) override {
            this->updates.fetch_add(1);
        }
        void on_metadata_clear() override {
            this->clears.fetch_add(1);
        }
    };
    ClearRecordingMetadataListener metadata_listener;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    client.add_metadata().set_listener(&metadata_listener);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["metadata@v1"])";
    // The post-rekey activate declares pairing alone and omits active_roles: the sticky set is
    // what the client must narrow to empty on its own.
    options.second_activities_json = R"(["pairing"])";
    options.second_roles_json = "";
    options.second_pairing_method = "pairing_psk";
    options.withhold_pair_finalize_ack = true;
    FakeEncryptedServer server(server_url(LOSE_CAPABILITY_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               long_term_peer.record.psk_id, long_term_peer.psk, options);

    pump_until(client, [&] { return client.is_connected(); });
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/state","payload":{"metadata":{"timestamp":1,"title":"Playing"}}})"));
    pump_until(client, [&] { return metadata_listener.updates == 1; });

    ASSERT_TRUE(server.trigger_rehandshake(pairing_psk.psk_id, pairing_psk.psk, "pr"))
        << "failed to start the in-band re-handshake onto the pairing PSK";

    pump_until(client, [&] { return metadata_listener.clears.load() == 1; });
    EXPECT_EQ(client.metadata()->get_track_duration_ms(), 0U);
    pump_until(client, [&] { return server.pair_init().has_value(); });
    EXPECT_TRUE(client.is_connected()) << "an admissible activation closed the connection";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// The same combined activate arriving as the first one under NEW session keys, after the server
// re-handshakes an already-admitted connection onto the Pairing PSK. The connection keeps the
// admitted slot throughout, so this takes the already-admitted branch with is_first true.
TEST(EncryptedLifecycle, CombinedActivateAfterARehandshakeGoesOperationalAndEntersPairing) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;

    Identity server_identity = Identity::generate().value();
    PairedPeer long_term_peer = make_paired_peer();
    long_term_peer.record.server_id = server_identity.peer_id();
    persistence.set_seeded_long_term_record(long_term_peer.record);
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xE0);

    SendspinClientConfig config;
    config.name = "Combined Rekey Activate Test Client";
    config.server_port = COMBINED_REKEY_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    FakeEncryptedServerOptions options;
    options.second_activities_json = R"(["playback","pairing"])";
    options.second_roles_json = R"(["controller@v1"])";
    options.second_pairing_method = "pairing_psk";
    options.withhold_pair_finalize_ack = true;
    FakeEncryptedServer server(server_url(COMBINED_REKEY_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               long_term_peer.record.psk_id, long_term_peer.psk, options);

    pump_until(client, [&] { return client.is_connected(); });
    pump_until(client, [&] { return server.client_state_count() > 0; });
    const int state_count_before_rekey = server.client_state_count();

    ASSERT_TRUE(server.trigger_rehandshake(pairing_psk.psk_id, pairing_psk.psk, "pr"))
        << "failed to start the in-band re-handshake onto the pairing PSK";

    pump_until(client, [&] { return server.pair_init().has_value(); });
    EXPECT_EQ(server.pair_init()->pairing_index, 1U)
        << "a re-handshake resets the counter, so the activate that follows it is the first";

    EXPECT_TRUE(client.is_connected())
        << "the post-rekey combined activate must bring the connection back operational";
    pump_until(client, [&] { return server.client_state_count() > state_count_before_rekey; });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// The pairing-method rules apply to a combined activate exactly as they do to a pairing-only one:
// messaging.md "server/activate" requires pairing.method to be 'pairing_psk' if and only if the
// matched PSK is the Pairing PSK, and answers a method the client does not offer with
// pair/abort reason method_not_supported, leaving the connection open.
TEST(EncryptedLifecycle, CombinedActivateWithAnUnofferedMethodAborts) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xF0);

    SendspinClientConfig config;
    config.name = "Combined Method Test Client";
    config.server_port = COMBINED_METHOD_TEST_PORT;
    // No out-channel, so dynamic_pairing_code is never offered; on the Pairing PSK it is also
    // the wrong category, which is the first half of the same rule.
    config.pairing_code_out_channels.clear();

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    Identity server_identity = Identity::generate().value();
    FakeEncryptedServerOptions options;
    options.psk_category = "pr";
    options.first_activities_json = R"(["playback","pairing"])";
    options.first_roles_json = R"(["controller@v1"])";
    options.first_pairing_method = "dynamic_pairing_code";
    FakeEncryptedServer server(server_url(COMBINED_METHOD_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               pairing_psk.psk_id, pairing_psk.psk, options);

    pump_until(client, [&] { return !server.pair_abort_reasons().empty(); });
    EXPECT_EQ(server.pair_abort_reasons().front(), "method_not_supported");
    EXPECT_FALSE(server.pair_init().has_value()) << "no attempt may start on a refused method";

    // The connection stays open, as the spec's third rejection rule requires.
    pump_for(client, 200);
    EXPECT_FALSE(server.closed());
    EXPECT_FALSE(server.goodbye_reason().has_value());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// scan_reprove_watchdog() is the only guard against a server that rekeys an admitted connection
// and then never activates it: connection.md "Re-handshake" makes server/activate the server's
// first message under the new keys, and nothing else re-proves the connection. The deadline is
// driven by forcing the stamp into the past rather than by waiting REPROVE_TIMEOUT_US (30 s).
TEST(EncryptedLifecycle, RehandshakeWithoutAnActivateIsDroppedByTheReproveWatchdog) {
    SendspinClientConfig config;
    config.name = "Reprove Rehandshake Test Client";
    config.server_port = REPROVE_REHANDSHAKE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.suppress_activate = true;  // The post-rekey activate is the one that never comes.
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(REPROVE_REHANDSHAKE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return server->client_hello_count() > 0; });
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/activate","payload":{"activities":["playback"],)"
        R"("active_roles":["player@v1"]}})"));
    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server->trigger_rehandshake(bundle.peer.record.psk_id, bundle.peer.psk));
    pump_until(client, [&] { return !client.is_connected(); });

    // The state the watchdog keys on, as handle_noise_rehandshake() left it: the hello flags
    // carried over the swap, only the activation rewound, and the stamp was refreshed.
    auto* conn = client.connection_manager_->current();
    ASSERT_NE(conn, nullptr);
    EXPECT_TRUE(conn->is_handshake_complete()) << "neither hello is re-sent, so both flags stand";
    EXPECT_FALSE(conn->is_operational());
    ASSERT_NE(conn->get_provisional_time_us(), 0)
        << "the re-handshake must restamp the re-proving deadline";

    // Control: a connection still inside the deadline is held, not reaped.
    pump_for(client, 100);
    EXPECT_NE(client.connection_manager_->current(), nullptr)
        << "a connection still inside REPROVE_TIMEOUT must be given time to be activated";

    conn->set_provisional_time_us(platform_time_us() - REPROVE_TIMEOUT_US - 1);
    pump_until(client, [&] { return client.connection_manager_->current() == nullptr; });

    // connection.md "Re-handshake" allows no application message between Noise message 1 and the
    // new activation, so the close carries no client/goodbye. Waiting for the socket to close
    // first means a goodbye that was sent has had its chance to arrive.
    wait_until([&] { return server->closed(); });
    EXPECT_FALSE(server->goodbye_reason().has_value())
        << "the re-proving watchdog must close without a goodbye";
}

// ============================================================================
// Pre-admission hold harness
// ============================================================================

// A SendspinConnection that exists only to carry the admission flags and the held-message queue:
// nothing is sent, and no transport is ever attached. It lets a test open the window between a
// server/activate reaching the dispatch path and the main loop admitting the connection, which
// over a real socket is whatever the thread scheduler makes it.
class HoldTestConnection : public SendspinConnection {
public:
    /// Applies the activation a real connection would have received before any role traffic
    /// reaches it: the client acts on a role's messages only while that role is active
    /// (messaging.md "server/activate"), so a connection with no applied activation would silence
    /// every role this fixture drives.
    HoldTestConnection() {
        this->apply_server_activate({SendspinActivity::PLAYBACK},
                                    std::vector<std::string>{"player@v1", "controller@v1",
                                                             "metadata@v1", "color@v1",
                                                             "artwork@v1", "visualizer@v1"},
                                    std::nullopt, std::nullopt);
    }

    void start() override {}
    void loop() override {}
    void disconnect(SendspinGoodbyeReason /*reason*/, std::function<void()> on_complete) override {
        if (on_complete) {
            on_complete();
        }
    }
    void close_transport_now() override {}
    bool is_connected() const override {
        return true;
    }
    SsErr send_text_message(const std::string& /*msg*/, SendCompleteCallback cb,
                            bool /*allow_before_hello*/) override {
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }
    SsErr send_binary_message(const uint8_t* /*data*/, size_t /*len*/, SendCompleteCallback cb,
                              bool /*allow_before_hello*/) override {
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }
    bool send_time_message() override {
        return true;
    }
};

// A started client with a metadata role, and the one entry point the hold tests need: hand a JSON
// message to the dispatch path as the connection's network thread would.
class HoldTestClient {
public:
    explicit HoldTestClient(const char* name) {
        SendspinClientConfig config;
        config.name = name;
        // Port 0: an ephemeral listener nothing connects to; every message is delivered directly.
        config.server_port = 0;
        this->client_storage = std::make_unique<SendspinClient>(std::move(config));
        this->client_storage->set_network_provider(&this->network);
        this->client_storage->add_metadata().set_listener(&this->listener);
        // The other roles a held message can be dispatched to, so the replay runs their real
        // handlers. The player has no listener, so its sync task never starts and its stream
        // handlers take the no-op path through an uninitialized ring.
        PlayerRoleConfig player_config;
        player_config.audio_formats = {{SendspinCodecFormat::PCM, 2, 44100, 16}};
        this->client_storage->add_player(std::move(player_config));
        this->client_storage->add_controller();
        EXPECT_TRUE(this->client_storage->start());
    }

    ~HoldTestClient() {
        this->client_storage->stop();
    }

    void deliver(SendspinConnection& conn, const std::string& json) {
        // A complete message off a transport proves the peer alive (dispatch_completed_message()),
        // and loop()'s liveness tick reaps a current connection whose last arrival is older than
        // the timeout. Handing the JSON straight to the dispatch entry point skips the stamp, so
        // do it here rather than stubbing the tick out.
        conn.last_receive_time_us_.store(platform_time_us(), std::memory_order_relaxed);
        this->client_storage->process_json_message(&conn, json.data(), json.size(),
                                                   platform_time_us());
    }

    void pump() {
        pump_for(*this->client_storage, 20);
    }

    SendspinClient& client_ref() {
        return *this->client_storage;
    }

    TestNetworkProvider network;
    RecordingMetadataListener listener;
    std::unique_ptr<SendspinClient> client_storage;
};

// Role-bound traffic from a connection that has finished the Noise handshake but has NOT been
// admitted must be ignored. The Sentinel PSK is a spec constant that resolves for every peer, so
// any peer on the network can reach handshake-complete and sit in the nursery; whether its PSK
// category may drive playback is decided by admission when server/activate arrives. Without the
// gate, a peer could drive the roles by sending traffic ahead of server/activate, or never
// sending one, for the whole nursery establish window.
TEST(EncryptedLifecycle, RoleTrafficBeforeAdmissionIsIgnored) {
    SendspinClientConfig config;
    config.name = "Pre-Admission Role Traffic Test Client";
    config.server_port = PREADMISSION_ROLE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();

    struct RecordingMetadataListener : MetadataRoleListener {
        std::atomic<int> updates{0};
        std::string last_title;
        void on_metadata(const ServerMetadataStateObject& m) override {
            this->last_title = m.title.value_or("");
            this->updates.fetch_add(1);
        }
    };
    RecordingMetadataListener metadata_listener;
    client.add_metadata().set_listener(&metadata_listener);

    ASSERT_TRUE(bundle.start());

    const Identity& server_identity = bundle.peer.server_identity;
    FakeEncryptedServerOptions options;
    // Sent on the encrypted stream immediately before the first server/activate, so the DUT sees
    // it while the connection is handshake-complete but still unadmitted.
    options.pre_activate_message =
        R"({"type":"server/state","payload":{"metadata":{"timestamp":1,"title":"Pre-Admission Leak"}}})";
    FakeEncryptedServer server(server_url(PREADMISSION_ROLE_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               bundle.peer.record.psk_id, bundle.peer.psk, options);

    pump_until(client, [&] { return client.is_connected(); });

    // The pre-activate server/state must have been dropped on the floor.
    EXPECT_EQ(metadata_listener.updates, 0)
        << "Role traffic from an unadmitted connection reached the metadata role (last_title='"
        << metadata_listener.last_title << "')";

    // ...and the same message on the now-admitted connection must go through, so the gate is
    // refusing on admission and not just dropping metadata wholesale.
    server.send_app_json(
        R"({"type":"server/state","payload":{"metadata":{"timestamp":2,"title":"Post-Admission OK"}}})");
    pump_until(client, [&] { return metadata_listener.updates > 0; });
    EXPECT_EQ(metadata_listener.last_title, "Post-Admission OK");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// messaging.md "server/state": each metadata object carries the role's full state, so what a
// later object leaves out is gone rather than carried forward from the object before it.
TEST(EncryptedLifecycle, MetadataStateReplacesRatherThanMerges) {
    HoldTestClient bundle("Metadata Full State Test Client");

    HoldTestConnection conn;
    bundle.client_ref().admit_connection(&conn);
    bundle.deliver(
        conn,
        R"({"type":"server/state","payload":{"metadata":{"timestamp":1,"title":"First",)"
        R"("artist":"Band","progress":{"track_progress":0,"track_duration":1000,)"
        R"("playback_speed":1000}}}})");
    bundle.pump();
    ASSERT_EQ(bundle.listener.updates, 1);
    EXPECT_EQ(bundle.listener.last_artist, "Band");
    EXPECT_TRUE(bundle.listener.last_had_progress);

    bundle.deliver(conn, metadata_state_json(2, "Second"));
    bundle.pump();
    ASSERT_EQ(bundle.listener.updates, 2);
    EXPECT_EQ(bundle.listener.last_title, "Second");
    EXPECT_EQ(bundle.listener.last_artist, "") << "an omitted artist must not carry forward";
    EXPECT_FALSE(bundle.listener.last_had_progress) << "an omitted progress clears the position";
}

// messaging.md "server/state": the first state a server sends for a role carries a past or
// present timestamp, so the client is brought up to date, and a scheduled update may follow it
// immediately. Both land before the main loop runs, and the state describing what is playing now
// must still be applied rather than skipped in favor of the one timed to the next track.
TEST(EncryptedLifecycle, ImmediateMetadataSurvivesAScheduledStateInTheSameTick) {
    RecordingMetadataListener listener;

    SendspinClientConfig config;
    config.name = "Metadata Immediate Plus Scheduled Test Client";
    config.server_port = METADATA_SCHEDULE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    client.add_metadata().set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["metadata@v1"])";
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(METADATA_SCHEDULE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return client.is_connected(); });

    // Far enough ahead that the scheduled state cannot come due while this test runs.
    const int64_t scheduled_at = platform_time_us() + 30 * static_cast<int64_t>(US_PER_SECOND);
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"metadata":{"timestamp":1,"title":"Now Playing"}}})"));
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"metadata":{"timestamp":)" +
        std::to_string(scheduled_at) + R"(,"title":"Next Track"}}})"));

    // Both cross the network thread while the main loop is parked, so a single drain takes them.
    EXPECT_TRUE(never_within([&] { return listener.updates > 0; }, 300))
        << "a state was applied without a main-loop tick";
    pump_for(client, 50);

    EXPECT_EQ(listener.updates, 1)
        << "the state describing the current track was dropped for the scheduled one";
    EXPECT_EQ(listener.last_title, "Now Playing");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// roles/metadata/v1.md "Scheduled metadata updates": a state whose timestamp is still in the
// future becomes the pending update, replacing any held one, and only the survivor is applied
// when its moment arrives.
TEST(EncryptedLifecycle, ANewerScheduledMetadataStateReplacesThePendingOne) {
    RecordingMetadataListener listener;

    SendspinClientConfig config;
    config.name = "Metadata Pending Replace Test Client";
    config.server_port = METADATA_PENDING_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    client.add_metadata().set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["metadata@v1"])";
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(METADATA_PENDING_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"metadata":{"timestamp":)" +
        std::to_string(platform_time_us() + 30 * static_cast<int64_t>(US_PER_SECOND)) +
        R"(,"title":"First Pending"}}})"));
    pump_for(client, 100);
    ASSERT_EQ(listener.updates, 0) << "a future-dated state was applied early";

    // Comes due shortly, so a client that kept the first pending state instead of replacing it
    // never fires at all.
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"metadata":{"timestamp":)" +
        std::to_string(platform_time_us() + static_cast<int64_t>(US_PER_SECOND) / 4) +
        R"(,"title":"Second Pending"}}})"));
    pump_until(client, [&] { return listener.updates > 0; });

    EXPECT_EQ(listener.last_title, "Second Pending");
    EXPECT_EQ(listener.updates, 1)
        << "the replaced pending state fired as well as the one that replaced it";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// The color role schedules its palettes exactly as the metadata role schedules its states, so it
// is held to the same two rules (roles/color/v1.md "Scheduled color updates"). First: an immediate
// palette and a scheduled one landing in the same tick are both kept, and the immediate one is
// applied.
TEST(EncryptedLifecycle, ImmediateColorSurvivesAScheduledPaletteInTheSameTick) {
    RecordingColorListener listener;

    SendspinClientConfig config;
    config.name = "Color Immediate Plus Scheduled Test Client";
    config.server_port = COLOR_SCHEDULE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    client.add_color().set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["color@v1"])";
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(COLOR_SCHEDULE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return client.is_connected(); });

    // Far enough ahead that the scheduled palette cannot come due while this test runs.
    const int64_t scheduled_at = platform_time_us() + 30 * static_cast<int64_t>(US_PER_SECOND);
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"color":{"timestamp":1,"primary":[10,20,30]}}})"));
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"color":{"timestamp":)" +
        std::to_string(scheduled_at) + R"(,"primary":[40,50,60]}}})"));

    // Both cross the network thread while the main loop is parked, so a single drain takes them.
    EXPECT_TRUE(never_within([&] { return listener.updates > 0; }, 300))
        << "a palette was applied without a main-loop tick";
    pump_for(client, 50);

    EXPECT_EQ(listener.updates, 1)
        << "the palette for the current track was dropped for the scheduled one";
    EXPECT_EQ(listener.last_primary, (std::array<uint8_t, 3>{10, 20, 30}));

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Two palettes that are both already due in the same tick collapse to one: the older would be
// superseded within the tick, so no consumer could observe it, and firing on_color() for it would
// flash a palette the server has already replaced.
TEST(EncryptedLifecycle, TwoDuePalettesInOneTickApplyOnlyTheLatest) {
    RecordingColorListener listener;

    SendspinClientConfig config;
    config.name = "Color Both Due Test Client";
    config.server_port = COLOR_BOTH_DUE_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    client.add_color().set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["color@v1"])";
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(COLOR_BOTH_DUE_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"color":{"timestamp":1,"primary":[10,20,30]}}})"));
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"color":{"timestamp":2,"primary":[40,50,60]}}})"));

    // Both cross the network thread while the main loop is parked, so a single drain takes them.
    EXPECT_TRUE(never_within([&] { return listener.updates > 0; }, 300))
        << "a palette was applied without a main-loop tick";
    pump_for(client, 50);

    EXPECT_EQ(listener.updates, 1)
        << "a palette that was superseded inside the same tick was still handed to the consumer";
    EXPECT_EQ(listener.last_primary, (RgbColor{40, 50, 60}));

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Second: a palette whose timestamp is still in the future becomes the pending update, replacing
// any held one, and only the survivor is applied when its moment arrives.
TEST(EncryptedLifecycle, ANewerScheduledColorPaletteReplacesThePendingOne) {
    RecordingColorListener listener;

    SendspinClientConfig config;
    config.name = "Color Pending Replace Test Client";
    config.server_port = COLOR_PENDING_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    client.add_color().set_listener(&listener);
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["color@v1"])";
    auto server = std::make_unique<FakeEncryptedServer>(
        server_url(COLOR_PENDING_TEST_PORT), std::string(NOISE_SUITE_CHACHAPOLY),
        bundle.peer.server_identity, bundle.peer.record.psk_id, bundle.peer.psk,
        std::move(options));

    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"color":{"timestamp":)" +
        std::to_string(platform_time_us() + 30 * static_cast<int64_t>(US_PER_SECOND)) +
        R"(,"primary":[10,20,30]}}})"));
    pump_for(client, 100);
    ASSERT_EQ(listener.updates, 0) << "a future-dated palette was applied early";

    // Comes due shortly, so a client that kept the first pending palette instead of replacing it
    // never fires at all.
    ASSERT_TRUE(server->send_app_json(
        R"({"type":"server/state","payload":{"color":{"timestamp":)" +
        std::to_string(platform_time_us() + static_cast<int64_t>(US_PER_SECOND) / 4) +
        R"(,"primary":[40,50,60]}}})"));
    pump_until(client, [&] { return listener.updates > 0; });

    EXPECT_EQ(listener.last_primary, (std::array<uint8_t, 3>{40, 50, 60}));
    EXPECT_EQ(listener.updates, 1)
        << "the replaced pending palette fired as well as the one that replaced it";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Control: the harness itself delivers. An admitted connection's role message reaches the
// metadata listener through the same dispatch entry point the hold tests use.
TEST(EncryptedLifecycle, RoleTrafficFromAnAdmittedConnectionIsApplied) {
    HoldTestClient bundle("Admitted Role Traffic Test Client");

    HoldTestConnection conn;
    bundle.client_ref().admit_connection(&conn);
    bundle.deliver(conn, metadata_state_json(1, "Admitted"));
    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 1);
    EXPECT_EQ(bundle.listener.last_title, "Admitted");
}

// A connection that never sends a server/activate is not a peer whose role traffic is worth
// keeping: the message above stays dropped even once that connection reaches the admitted slot.
// This is the boundary of the hold in the test below.
TEST(EncryptedLifecycle, RoleTrafficBeforeAnyActivateIsNotReplayedAtAdmission) {
    HoldTestClient bundle("Pre-Activate Role Traffic Test Client");

    HoldTestConnection conn;
    bundle.deliver(conn, metadata_state_json(1, "Before Any Activate"));
    bundle.pump();
    ASSERT_EQ(bundle.listener.updates, 0);

    bundle.client_ref().admit_connection(&conn);
    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 0)
        << "role traffic that preceded every server/activate must not be replayed (last_title='"
        << bundle.listener.last_title << "')";
}

// A server starts sending role traffic as soon as it has sent its server/activate, while the
// client decides admission on its next loop() tick. The traffic in that window is held and
// replayed at admission: a one-shot server/state (an artwork channel set, a colour palette) is
// never repeated, so dropping it loses that state for the whole session.
//
// Driven through the dispatch entry point rather than over a socket, so the test opens and closes
// the unadmitted window itself instead of racing the scheduler for it.
TEST(EncryptedLifecycle, RoleTrafficBetweenActivateAndAdmissionIsReplayed) {
    HoldTestClient bundle("Post-Activate Role Traffic Test Client");

    HoldTestConnection conn;
    // What the network thread does when it hands a server/activate to the main loop.
    conn.note_activate_delivered();

    bundle.deliver(conn, metadata_state_json(1, "Held Through Admission"));
    bundle.pump();
    ASSERT_EQ(bundle.listener.updates, 0)
        << "an unadmitted connection must not drive the roles, held or not";

    bundle.client_ref().admit_connection(&conn);
    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 1)
        << "the role message held across admission was never applied";
    EXPECT_EQ(bundle.listener.last_title, "Held Through Admission");
}

// Several held messages replay in arrival order, so the last state the server sent in the window
// is the one that stands. They land in the metadata role's collapsing slot, which merges them
// into the single update the listener sees, exactly as it would for live traffic arriving between
// two loop() ticks.
TEST(EncryptedLifecycle, HeldRoleTrafficIsReplayedInArrivalOrder) {
    HoldTestClient bundle("Held Order Test Client");

    HoldTestConnection conn;
    conn.note_activate_delivered();
    bundle.deliver(conn, metadata_state_json(1, "First"));
    bundle.deliver(conn, metadata_state_json(2, "Second"));

    bundle.client_ref().admit_connection(&conn);
    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 1);
    EXPECT_EQ(bundle.listener.last_title, "Second")
        << "the held messages were replayed out of order";
}

// Control: the hold is bounded. A peer that sits unadmitted and keeps sending role traffic gets
// its excess dropped rather than growing the queue without limit, and the messages inside the
// budget still replay.
TEST(EncryptedLifecycle, HeldRoleTrafficIsBounded) {
    HoldTestClient bundle("Held Budget Test Client");

    HoldTestConnection conn;
    conn.note_activate_delivered();
    const size_t over_budget = SendspinConnection::MAX_HELD_MESSAGES + 3;
    for (size_t i = 0; i < over_budget; ++i) {
        bundle.deliver(conn, metadata_state_json(static_cast<int>(i) + 1,
                                                 "Title " + std::to_string(i)));
    }

    bundle.client_ref().admit_connection(&conn);
    bundle.pump();
    // The last title to survive the merge is the last one that fit the budget: everything the
    // peer sent past it was dropped rather than queued.
    EXPECT_EQ(bundle.listener.updates, 1);
    EXPECT_EQ(bundle.listener.last_title,
              "Title " + std::to_string(SendspinConnection::MAX_HELD_MESSAGES - 1));
}

// The role mask has two writers: the network thread ORs in a just-parsed activation's roles, and
// the main loop republishes the applied set a tick later. Applying one activation must not erase
// the bits of another that has already been delivered, or the receive gate drops exactly the
// traffic a server sends immediately behind its activate.
TEST(RoleMask, ApplyingAnActivationKeepsADeliveredOneSRoleBits) {
    HoldTestConnection conn;
    const std::vector<SendspinActivity> playback{SendspinActivity::PLAYBACK};
    const std::vector<std::string> metadata_only{"metadata@v1"};

    conn.apply_server_activate(playback, metadata_only, std::nullopt, std::nullopt);
    ASSERT_FALSE(conn.is_role_active(SendspinRole::PLAYER));

    // A second activation adds the player and is parsed on the network thread...
    conn.note_activated_roles({"metadata@v1", "player@v1"});
    ASSERT_TRUE(conn.is_role_active(SendspinRole::PLAYER));
    // ...while the main loop is still applying one that neither adds nor removes it.
    conn.apply_server_activate(playback, metadata_only, std::nullopt, std::nullopt);

    EXPECT_TRUE(conn.is_role_active(SendspinRole::PLAYER))
        << "the delivered activation's role bit was erased by an application it had nothing to "
           "do with";
    EXPECT_TRUE(conn.is_role_active(SendspinRole::METADATA));
}

// Control: applying an activation that does take a role out clears its bit, so the test above is
// not passing on a mask nothing can ever clear.
TEST(RoleMask, ApplyingAnActivationClearsTheRolesItRemoves) {
    HoldTestConnection conn;
    const std::vector<SendspinActivity> playback{SendspinActivity::PLAYBACK};

    conn.apply_server_activate(playback, std::vector<std::string>{"metadata@v1", "player@v1"},
                               std::nullopt, std::nullopt);
    ASSERT_TRUE(conn.is_role_active(SendspinRole::PLAYER));

    conn.apply_server_activate(playback, std::vector<std::string>{"metadata@v1"}, std::nullopt,
                               std::nullopt);

    EXPECT_FALSE(conn.is_role_active(SendspinRole::PLAYER));
    EXPECT_TRUE(conn.is_role_active(SendspinRole::METADATA));
}

// The other half of the same guard: the hold has two budgets, and the byte one is what keeps the
// memcpy inside the MAX_HELD_BYTES allocation. A peer whose role states are large runs out of
// bytes long before it runs out of slots, so the count cap above cannot stand in for this one.
TEST(EncryptedLifecycle, HeldRoleTrafficIsBoundedByBytesBeforeMessages) {
    HoldTestClient bundle("Held Byte Budget Test Client");

    HoldTestConnection conn;
    conn.note_activate_delivered();
    // Each message is just over a third of the byte budget, so the third one exceeds it while
    // the count is still 3 of MAX_HELD_MESSAGES.
    const size_t title_len = SendspinConnection::MAX_HELD_BYTES / 3;
    for (int i = 0; i < 3; ++i) {
        bundle.deliver(conn,
                       metadata_state_json(i + 1, std::string(title_len,
                                                              static_cast<char>('a' + i))));
    }

    ASSERT_LT(3u, SendspinConnection::MAX_HELD_MESSAGES)
        << "the byte budget must be the one that runs out first for this test to mean anything";
    EXPECT_EQ(conn.held_count_, 2u) << "the message past the byte budget was held anyway";
    EXPECT_LE(conn.held_bytes_, SendspinConnection::MAX_HELD_BYTES)
        << "the hold wrote past the buffer it allocated";

    bundle.client_ref().admit_connection(&conn);
    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 1);
    EXPECT_EQ(bundle.listener.last_title, std::string(title_len, 'b'))
        << "the last state inside the byte budget is the one that must replay";

    // The replay also ends the hold: both budgets read empty again and the MAX_HELD_BYTES
    // allocation goes back to the heap rather than staying held for the rest of the session.
    EXPECT_EQ(conn.held_count_, 0u) << "the replay left messages counted as held";
    EXPECT_EQ(conn.held_bytes_, 0u) << "the replay left the byte budget spent";
    EXPECT_EQ(conn.held_messages_.size(), 0u)
        << "the hold buffer stayed allocated after the replay";
}

// Control: the replay runs every held type's real handler to completion. One message of each
// type, replayed in one admission, so a handler that throws the replay off (or blocks in it)
// takes the metadata message behind it down with it. The group name and the metadata title are
// what say the handlers ran rather than being walked past: a held type whose arm does nothing is
// invisible to the trailing message alone.
TEST(EncryptedLifecycle, EveryHeldMessageTypeReplaysThroughItsHandler) {
    HoldTestClient bundle("Replay Handler Test Client");

    HoldTestConnection conn;
    conn.note_activate_delivered();
    for (const std::string& json :
         {std::string(R"({"type":"server/state","payload":{"controller":{"playback_state":)"
                      R"("playing"}}})"),
          std::string(R"({"type":"server/command","payload":{"player":{"command":"volume",)"
                      R"("volume":42}}})"),
          std::string(R"({"type":"stream/start","payload":{"player":{"codec":"pcm",)"
                      R"("sample_rate":44100,"channels":2,"bit_depth":16}}})"),
          std::string(R"({"type":"stream/clear","payload":{}})"),
          std::string(R"({"type":"stream/end","payload":{}})"),
          std::string(R"({"type":"group/update","payload":{"group_name":"Kitchen"}})"),
          metadata_state_json(1, "Replayed")}) {
        bundle.deliver(conn, json);
    }

    bundle.client_ref().admit_connection(&conn);

    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 1) << "the replay did not run to completion";
    EXPECT_EQ(bundle.listener.last_title, "Replayed");
    ASSERT_TRUE(bundle.client_ref().get_group_state().group_name.has_value())
        << "the replayed group/update never reached its handler";
    EXPECT_EQ(*bundle.client_ref().get_group_state().group_name, "Kitchen");
}

// The two locks the client holds are ordered json_processing_mutex_ then conn_ptr_mutex_
// (docs/conventions.md, "Threading and cross-thread state"). The live receive path fixes that
// order: a server/pair-finalize handler runs under the JSON lock and asks the manager for the
// open connections' psk_ids. Admission is the other half of the pair, and it takes the JSON lock
// to replay, so it must not run under conn_ptr_mutex_, which is why set_current_connection()
// only stages it and flush_pending_admission() performs it after the lock is dropped.
//
// Driving both halves at once pins that. The pairing connection's network thread is parked
// holding the JSON lock and waiting for conn_ptr_mutex_ (this thread holds it), which is the
// state a real pairing ack reaches whenever the main loop is inside its lifecycle block. An
// admission that took the JSON lock from here would close the cycle and hang: the suite watchdog
// in tests/main.cpp names the test, since no timeout of this test's own can distinguish a
// deadlock from a slow machine.
TEST(EncryptedLifecycle, PairFinalizeDoesNotDeadlockAgainstAnAdmission) {
    HoldTestClient bundle("Pair Finalize Admission Test Client");
    SendspinClient& client = bundle.client_ref();
    ConnectionManager& manager = *client.connection_manager_;

    auto admitted = std::make_shared<HoldTestConnection>();
    admitted->note_activate_delivered();
    bundle.deliver(*admitted, metadata_state_json(1, "Held Across A Pair Finalize"));

    // The peer whose pairing the server has just acked, with the record its handler commits.
    auto pairing = std::make_shared<HoldTestConnection>();
    SendspinPairingRecord record;
    record.psk_id = "pair-finalize-deadlock-psk-id";
    record.psk.fill(0x5A);
    record.server_id = "pair-finalize-deadlock-server";
    pairing->set_pending_pairing_record(std::move(record));

    std::unique_lock<std::mutex> conn_lock(manager.conn_ptr_mutex_);

    std::thread network([&] {
        bundle.deliver(*pairing, R"({"type":"server/pair-finalize","payload":{}})");
    });

    // Park until that thread holds the JSON lock. It cannot release it before it takes
    // conn_ptr_mutex_, which this thread holds, so the observation is stable rather than a
    // window: from here on the pairing handler is blocked inside open_connection_psk_ids().
    while (client.json_processing_mutex_.try_lock()) {
        client.json_processing_mutex_.unlock();
        std::this_thread::yield();
    }

    // What the main loop does inside its lifecycle block. Staging only; taking the JSON lock
    // here is the deadlock.
    manager.set_current_connection(admitted);
    conn_lock.unlock();

    network.join();
    manager.flush_pending_admission();

    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 1)
        << "the connection staged under the manager lock was never admitted";
    EXPECT_EQ(bundle.listener.last_title, "Held Across A Pair Finalize");
    EXPECT_TRUE(admitted->is_admitted());
    // The pairing half ran to completion rather than being skipped: its record is resolvable.
    EXPECT_TRUE(client.record_store_
                    ->resolve_by_psk_id("pair-finalize-deadlock-psk-id", PskCategory::LONG_TERM)
                    .has_value())
        << "the server/pair-finalize handler never committed its record";
}

// Seeds a set of LONG_TERM records and keeps the persisted "records" array up to date, so an
// unpair test can assert on what the store would come back with after a reboot as well as on
// what it resolves right now. TestPersistenceProvider rejects writes on purpose (see its
// comment), so it cannot show what a removal persists; this provider accepts them.
class RecordsMirrorPersistenceProvider : public SendspinPersistenceProvider {
public:
    explicit RecordsMirrorPersistenceProvider(std::vector<SendspinPairingRecord> records)
        : records_(std::move(records)) {}

    /// Seeds the stored pairing config. Must be called before start(): a client that already
    /// holds records is not on its first boot, so SendspinClientConfig's unpaired-access seed no
    /// longer applies and the stored config is the only way in.
    void set_unpaired_access_enabled(bool enabled) {
        this->unpaired_access_enabled_ = enabled;
    }

    /// Stands in for a store that cannot take the records blob at all (full or read-only NVS).
    /// A rejected write counts as neither a save nor a change to what the next boot loads.
    void set_reject_records(bool reject) {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->reject_records_ = reject;
    }

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key == persistence_keys::PAIR_CONFIG) {
            SendspinPairingConfig config;
            config.unpaired_access_enabled = this->unpaired_access_enabled_;
            std::string encoded = encode_pairing_config(config);
            return std::vector<uint8_t>(encoded.begin(), encoded.end());
        }
        if (key != persistence_keys::RECORDS) {
            return std::nullopt;
        }
        std::lock_guard<std::mutex> lock(this->mutex_);
        std::string encoded = encode_pairing_records(this->records_);
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (key == persistence_keys::LAST_PLAYED) {
            std::lock_guard<std::mutex> lock(this->mutex_);
            this->last_played_.assign(reinterpret_cast<const char*>(data), len);
            return true;
        }
        if (key != persistence_keys::RECORDS) {
            return true;  // The keypair and pair config are not under test here.
        }
        std::string_view text(reinterpret_cast<const char*>(data), len);
        auto decoded = decode_pairing_records(text);
        if (!decoded.has_value()) {
            return false;
        }
        std::lock_guard<std::mutex> lock(this->mutex_);
        if (this->reject_records_) {
            return false;
        }
        this->records_ = std::move(decoded.value());
        ++this->records_saves_;
        return true;
    }

    /// @brief How many times the records blob has been written.
    [[nodiscard]] size_t records_saves() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->records_saves_;
    }

    /// @brief The last-played server_id the store holds.
    [[nodiscard]] std::string last_played() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->last_played_;
    }

    /// @brief Whether the record the store would load carries the durable used flag.
    [[nodiscard]] bool persisted_used(const std::string& psk_id) const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        for (const auto& record : this->records_) {
            if (record.psk_id == psk_id) {
                return record.used;
            }
        }
        return false;
    }

    /// @brief The psk_ids the store would load on the next boot.
    [[nodiscard]] std::vector<std::string> persisted_psk_ids() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        std::vector<std::string> ids;
        ids.reserve(this->records_.size());
        for (const auto& record : this->records_) {
            ids.push_back(record.psk_id);
        }
        return ids;
    }

private:
    mutable std::mutex mutex_;
    std::vector<SendspinPairingRecord> records_;
    size_t records_saves_{0};
    bool unpaired_access_enabled_{false};
    bool reject_records_{false};
    std::string last_played_{};
};

/// Build a LONG_TERM record for `identity` with a random PSK.
SendspinPairingRecord make_record_for(const Identity& identity) {
    SendspinPairingRecord record;
    platform_random_bytes(record.psk.data(), record.psk.size());
    record.psk_id = psk_id_for(record.psk);
    record.server_id = identity.peer_id();
    return record;
}

// server/unpair revokes the credential itself, not just the session: the matched record must be
// gone from the store AND from the persisted blob, or the server pairs its way back in at the
// next boot (messaging.md "server/unpair").
//
// Only the matched record goes: a client paired with several servers keeps the others, which is
// the difference between honouring an unpair and wiping the device.
TEST(EncryptedLifecycle, UnpairRemovesOnlyTheMatchedRecordFromStoreAndStorage) {
    Identity unpairing_identity = Identity::generate().value();
    Identity bystander_identity = Identity::generate().value();
    SendspinPairingRecord unpairing_record = make_record_for(unpairing_identity);
    SendspinPairingRecord bystander_record = make_record_for(bystander_identity);

    TestNetworkProvider network;
    RecordsMirrorPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{unpairing_record, bystander_record});
    SendspinClientConfig config;
    config.name = "Unpair Record Test Client";
    config.server_port = UNPAIR_RECORD_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    FakeEncryptedServer server(server_url(UNPAIR_RECORD_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), unpairing_identity,
                               unpairing_record.psk_id, unpairing_record.psk);
    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server.send_app_json(R"({"type":"server/unpair","payload":{}})"));
    pump_until(client, [&] { return server.closed(); });
    EXPECT_EQ(server.goodbye_reason().value_or(""), "unpaired");

    // The record is gone for this boot: it no longer resolves a handshake at all.
    EXPECT_FALSE(client.record_store_->resolve_by_psk_id(unpairing_record.psk_id, PskCategory::LONG_TERM).has_value())
        << "server/unpair must revoke the matched record, not just end the session";
    auto bystander_resolved =
        client.record_store_->resolve_by_psk_id(bystander_record.psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(bystander_resolved.has_value())
        << "another server's record must survive an unpair it had no part in";
    EXPECT_EQ(bystander_resolved->category, PskCategory::LONG_TERM);

    // ...and gone for the next one: the removal reached the provider through the main loop.
    EXPECT_EQ(persistence.persisted_psk_ids(),
              std::vector<std::string>{bystander_record.psk_id})
        << "the persisted records blob must hold exactly the surviving record";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Every records op rewrites the whole array, so a tick carrying more than one of them must still
// reach the provider once: on ESP each save is an NVS erase cycle, and flash wear is a budget
// (docs/conventions.md, "Embedded resource discipline"). The two ops here are the pair a real tick
// carries, staged by the activate drain and the unpair drain in the same locked block, on two
// different records so both halves genuinely need the write.
TEST(EncryptedLifecycle, SeveralRecordOpsInOneTickWriteTheBlobOnce) {
    Identity used_identity = Identity::generate().value();
    Identity unpairing_identity = Identity::generate().value();
    SendspinPairingRecord used_record = make_record_for(used_identity);
    SendspinPairingRecord unpairing_record = make_record_for(unpairing_identity);

    TestNetworkProvider network;
    RecordsMirrorPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{used_record, unpairing_record});
    SendspinClientConfig config;
    config.name = "Coalesced Record Write Test Client";
    // Port 0: an ephemeral listener nothing connects to; the manager is driven directly.
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    ConnectionManager& manager = *client.connection_manager_;
    const size_t saves_before = persistence.records_saves();

    HoldTestConnection conn;
    ServerUnpairEvent event;
    event.matched_psk_id = unpairing_record.psk_id;
    event.psk_category = PskCategory::LONG_TERM;
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        // What process_activate_event() stages on the first activate of a long-term session.
        manager.stage_record_op(PendingRecordOp::Kind::MARK_USED, used_record.psk_id);
        manager.handle_server_unpair(&conn, event);
    }

    manager.flush_pending_record_ops();
    manager.flush_deferred_releases();

    EXPECT_EQ(persistence.records_saves() - saves_before, 1u)
        << "the tick's record ops must land as one blob write";
    // Control: the one blob carries both changes, so this is coalescing rather than a lost write.
    EXPECT_EQ(persistence.persisted_psk_ids(), std::vector<std::string>{used_record.psk_id})
        << "the written blob must hold exactly the surviving record";
    const auto* marked = client.record_store_->record_by_psk_id(used_record.psk_id);
    ASSERT_NE(marked, nullptr);
    EXPECT_TRUE(marked->used) << "the mark-used op was dropped instead of coalesced";

    client.stop();
}

// The `used` flag is written once, on its first flip: a MARK_USED op for a record already
// flagged carries no durable change, so the flush must not spend an NVS erase cycle on it. This
// runs on the first activate of every long-term session, so a write here would be one per
// connection in steady state.
TEST(EncryptedLifecycle, AMarkUsedOpThatFlipsNothingWritesNoBlob) {
    Identity used_identity = Identity::generate().value();
    SendspinPairingRecord used_record = make_record_for(used_identity);

    TestNetworkProvider network;
    RecordsMirrorPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{used_record});
    SendspinClientConfig config;
    config.name = "Repeat Mark Used Test Client";
    // Port 0: an ephemeral listener nothing connects to; the manager is driven directly.
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    ConnectionManager& manager = *client.connection_manager_;

    // Control: the first flip is durable, so it does write.
    const size_t saves_before_first = persistence.records_saves();
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.stage_record_op(PendingRecordOp::Kind::MARK_USED, used_record.psk_id);
    }
    manager.flush_pending_record_ops();
    EXPECT_EQ(persistence.records_saves() - saves_before_first, 1u)
        << "the first flip of the durable used flag must reach the provider";

    const size_t saves_before_repeat = persistence.records_saves();
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.stage_record_op(PendingRecordOp::Kind::MARK_USED, used_record.psk_id);
    }
    manager.flush_pending_record_ops();

    EXPECT_EQ(persistence.records_saves(), saves_before_repeat)
        << "a mark-used op that flips nothing must not rewrite the records blob";
    const auto* marked = client.record_store_->record_by_psk_id(used_record.psk_id);
    ASSERT_NE(marked, nullptr);
    EXPECT_TRUE(marked->used) << "the RAM flag must still be set";

    client.stop();
}

// A record op staged after the last tick has no tick left to carry it: stop() flushes once on
// the way down, or the write is lost. The op staged here is the one a real session stages last,
// the MARK_USED of a long-term activate, and what is asserted is the blob the next boot loads
// rather than the RAM flag the same flush also sets.
TEST(EncryptedLifecycle, StopFlushesARecordOpStagedAfterTheLastTick) {
    Identity used_identity = Identity::generate().value();
    SendspinPairingRecord used_record = make_record_for(used_identity);

    TestNetworkProvider network;
    RecordsMirrorPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{used_record});
    SendspinClientConfig config;
    config.name = "Stop Flushes Staged Record Op Test Client";
    // Port 0: an ephemeral listener nothing connects to; the manager is driven directly.
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    ConnectionManager& manager = *client.connection_manager_;

    const size_t saves_before = persistence.records_saves();
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.stage_record_op(PendingRecordOp::Kind::MARK_USED, used_record.psk_id);
    }
    ASSERT_EQ(persistence.records_saves(), saves_before)
        << "staging under the lock must not write on its own";

    client.stop();

    EXPECT_EQ(persistence.records_saves() - saves_before, 1u)
        << "the op staged after the last tick never reached the provider";
    EXPECT_TRUE(persistence.persisted_used(used_record.psk_id))
        << "the blob stop() wrote must carry the staged flip";
}

// The last-played server_id lives under its own key, so a tick that stages only that write must
// leave the records blob alone: the two are coalesced separately, and rewriting the array for a
// handoff would be an NVS erase cycle nothing asked for.
TEST(EncryptedLifecycle, ALastPlayedOnlyFlushWritesNoRecordsBlob) {
    Identity paired_identity = Identity::generate().value();
    SendspinPairingRecord paired_record = make_record_for(paired_identity);

    TestNetworkProvider network;
    RecordsMirrorPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{paired_record});
    SendspinClientConfig config;
    config.name = "Last Played Only Test Client";
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    ConnectionManager& manager = *client.connection_manager_;
    const size_t saves_before = persistence.records_saves();

    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.stage_record_op(PendingRecordOp::Kind::LAST_PLAYED, paired_record.server_id);
    }
    manager.flush_pending_record_ops();

    EXPECT_EQ(persistence.records_saves(), saves_before)
        << "a last-played write must not drag the records blob along";
    // Control: the op was performed rather than dropped.
    EXPECT_EQ(persistence.last_played(), paired_record.server_id)
        << "the staged last-played write never reached the provider";

    client.stop();
}

// A store that cannot take the blob does not undo the RAM decisions the locked handlers already
// made: the revoked credential stays revoked for this boot (leaving it usable because flash is
// full is strictly worse), and the batch is reported once because it carries a revocation.
TEST(EncryptedLifecycle, ACoalescedFlushRejectedByTheProviderKeepsTheRamStateAndWarns) {
    Identity used_identity = Identity::generate().value();
    Identity unpairing_identity = Identity::generate().value();
    SendspinPairingRecord used_record = make_record_for(used_identity);
    SendspinPairingRecord unpairing_record = make_record_for(unpairing_identity);

    TestNetworkProvider network;
    RecordsMirrorPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{used_record, unpairing_record});
    SendspinClientConfig config;
    config.name = "Rejected Coalesced Write Test Client";
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    ConnectionManager& manager = *client.connection_manager_;
    persistence.set_reject_records(true);

    HoldTestConnection conn;
    ServerUnpairEvent event;
    event.matched_psk_id = unpairing_record.psk_id;
    event.psk_category = PskCategory::LONG_TERM;
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.stage_record_op(PendingRecordOp::Kind::MARK_USED, used_record.psk_id);
        manager.handle_server_unpair(&conn, event);
    }

    std::string logs;
    {
        StderrCapture capture;
        manager.flush_pending_record_ops();
        logs = capture.release();
    }
    manager.flush_deferred_releases();

    EXPECT_FALSE(client.record_store_
                     ->resolve_by_psk_id(unpairing_record.psk_id, PskCategory::LONG_TERM)
                     .has_value())
        << "a rejected write must not resurrect the revoked record for this boot";
    const auto* marked = client.record_store_->record_by_psk_id(used_record.psk_id);
    ASSERT_NE(marked, nullptr);
    EXPECT_TRUE(marked->used);
    EXPECT_NE(logs.find("RAM-only"), std::string::npos)
        << "a rejected batch carrying a revocation must be reported; got: " << logs;
    // ...and the provider still holds what it accepted last, which is what a reboot loads.
    EXPECT_EQ(persistence.persisted_psk_ids().size(), 2u)
        << "a rejected write must not be mirrored as if it had landed";

    client.stop();
}

// The other half of the reporting rule: a batch whose only records change is the advisory `used`
// flag stays silent on the same rejection. The flag is rebuilt from use, and this batch is what
// the first activate of every long-term session stages, so a device with a full store would
// otherwise warn once per session forever.
TEST(EncryptedLifecycle, ARejectedMarkUsedOnlyFlushIsSilent) {
    Identity used_identity = Identity::generate().value();
    SendspinPairingRecord used_record = make_record_for(used_identity);

    TestNetworkProvider network;
    RecordsMirrorPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{used_record});
    SendspinClientConfig config;
    config.name = "Rejected Mark Used Test Client";
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    ConnectionManager& manager = *client.connection_manager_;
    persistence.set_reject_records(true);

    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.stage_record_op(PendingRecordOp::Kind::MARK_USED, used_record.psk_id);
    }

    std::string logs;
    {
        StderrCapture capture;
        manager.flush_pending_record_ops();
        logs = capture.release();
    }

    EXPECT_EQ(logs.find("RAM-only"), std::string::npos)
        << "advisory bookkeeping must not report a rejected write; got: " << logs;

    client.stop();
}

// The revocation itself is not deferred, only its blob write. handle_server_unpair() erases the
// record under conn_ptr_mutex_, so a Noise re-handshake on the revoked psk_id, which resolves
// against the store on the network thread, misses it from that instant rather than for as long as
// the writes staged ahead of it take to commit (an NVS commit each, tens of milliseconds, on ESP).
//
// Driving the handler directly is what pins that: the resolve below runs inside the locked
// section itself, which is where an erase deferred to flush_pending_record_ops() would still be
// resolvable.
TEST(EncryptedLifecycle, UnpairRevokesTheRecordBeforeTheWriteIsFlushed) {
    HoldTestClient bundle("Unpair Revocation Window Test Client");
    SendspinClient& client = bundle.client_ref();
    ConnectionManager& manager = *client.connection_manager_;

    SendspinPairingRecord record;
    record.psk_id = "unpair-window-psk-id";
    record.psk.fill(0x3C);
    record.server_id = "unpair-window-server";
    ASSERT_TRUE(client.record_store_->store_record_superseding(record, {}));

    HoldTestConnection conn;
    ServerUnpairEvent event;
    event.matched_psk_id = record.psk_id;
    event.psk_category = PskCategory::LONG_TERM;
    std::optional<ResolvedPsk> resolved;
    {
        std::lock_guard<std::mutex> lock(manager.conn_ptr_mutex_);
        manager.handle_server_unpair(&conn, event);
        // The handshake thread's lookup, issued while the manager lock is still held: it takes
        // only RecordStore::mutex_, so it neither waits on nor deadlocks against this scope.
        std::thread network([&] {
            resolved =
                client.record_store_->resolve_by_psk_id(record.psk_id, PskCategory::LONG_TERM);
        });
        network.join();
    }
    EXPECT_FALSE(resolved.has_value())
        << "the revoked record still resolved a handshake while the unpair handler held the lock";

    // Control: only the RAM half ran under the lock. The durable half is still owed, so this is
    // a split rather than a provider write smuggled into the locked section.
    EXPECT_EQ(manager.pending_record_ops_.size(), 1u)
        << "the records-blob write must still be staged at this point";

    manager.flush_pending_record_ops();
    manager.flush_deferred_releases();
}

// An unpaired session has no record to revoke, so server/unpair on one is ignored outright: it
// must not drop the session and must not touch stored records (messaging.md "server/unpair": if the
// session is unpaired, ignore the message).
TEST(EncryptedLifecycle, UnpairOnAnUnpairedSessionChangesNothing) {
    Identity sentinel_identity = Identity::generate().value();
    Identity paired_identity = Identity::generate().value();
    SendspinPairingRecord paired_record = make_record_for(paired_identity);

    TestNetworkProvider network;
    RecordsMirrorPersistenceProvider persistence(
        std::vector<SendspinPairingRecord>{paired_record});
    SendspinClientConfig config;
    config.name = "Unpair Sentinel Test Client";
    config.server_port = UNPAIR_SENTINEL_TEST_PORT;
    persistence.set_unpaired_access_enabled(true);

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    // The Sentinel PSK admits an unpaired server (ConnectionTrust::NONE).
    FakeEncryptedServer server(server_url(UNPAIR_SENTINEL_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), sentinel_identity,
                               std::string(SENTINEL_PSK_ID), SENTINEL_PSK);
    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server.send_app_json(R"({"type":"server/unpair","payload":{}})"));
    // Must-not-happen window: the drop an acted-on unpair would perform runs on the main loop a
    // tick or two after the message, so the session is pumped well past that before it is read.
    pump_for(client, 500);

    EXPECT_FALSE(server.closed())
        << "server/unpair on an unpaired session must be ignored, not acted on";
    EXPECT_FALSE(server.goodbye_reason().has_value());
    EXPECT_TRUE(client.is_connected());

    // The paired server's record is untouched: it was never what this session ran on.
    EXPECT_TRUE(client.record_store_->resolve_by_psk_id(paired_record.psk_id, PskCategory::LONG_TERM).has_value());
    EXPECT_EQ(persistence.persisted_psk_ids(), std::vector<std::string>{paired_record.psk_id});

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// server/unpair must drop the record AND end every live session running on it, not just the
// session that asked (messaging.md "server/unpair").
//
// A connection resolves its psk_id and PSK category once, at Noise-handshake completion, and never
// re-checks them against the RecordStore, so deleting the record alone does not stop a second
// session holding the same credential: it would keep its LONG_TERM trust, and with it playback,
// until it happened to disconnect on its own.
TEST(EncryptedLifecycle, UnpairDropsEverySessionOnTheRecord) {
    // One paired record, two sessions on it: the admitted one (A) and a nursery entry (B).
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    const std::string psk_id = psk_id_for(psk);

    // One server identity, two transports: the record's stored server_id must match the peer on
    // both, since every long-term PSK is bound to its server (connection.md "Pre-Shared Key").
    Identity identity = Identity::generate().value();

    SendspinPairingRecord record;
    record.psk_id = psk_id;
    record.psk = psk;
    record.server_id =
        base64url_encode(identity.public_bytes.data(), identity.public_bytes.size());

    TestNetworkProvider network;
    TestPersistenceProvider persistence(std::vector<SendspinPairingRecord>{record});
    SendspinClientConfig config;
    config.name = "Unpair Sweep Test Client";
    config.server_port = REVOCATION_SWEEP_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    // A: admitted, so its server/unpair is honoured.
    FakeEncryptedServerOptions options_a;
    options_a.first_activities_json = R"([])";
    options_a.first_roles_json = R"([])";
    FakeEncryptedServer server_a(server_url(REVOCATION_SWEEP_TEST_PORT),
                                 std::string(NOISE_SUITE_CHACHAPOLY), identity, psk_id, psk,
                                 options_a);
    pump_until(client, [&] { return client.is_connected(); });

    // B: completes the Noise handshake (so its psk_id is resolved and cached on the connection)
    // but never sends server/activate, so it sits in the nursery as a second live session.
    FakeEncryptedServerOptions options_b;
    options_b.suppress_activate = true;
    FakeEncryptedServer server_b(server_url(REVOCATION_SWEEP_TEST_PORT),
                                 std::string(NOISE_SUITE_CHACHAPOLY), identity, psk_id, psk,
                                 options_b);
    pump_until(client, [&] { return server_b.client_hello_count() > 0; });
    ASSERT_FALSE(server_b.closed()) << "Second session closed before the unpair";

    ASSERT_TRUE(server_a.send_app_json(R"({"type":"server/unpair","payload":{}})"));

    pump_until(client, [&] { return server_b.closed(); });
    pump_until(client, [&] { return server_a.closed(); });
    EXPECT_EQ(server_a.goodbye_reason().value_or(""), "unpaired");

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

namespace {

// A persistence provider whose records write parks until the test releases it, standing in for an
// NVS commit of tens of milliseconds. It serves the one seeded long-term record, so the peer
// below resolves to PskCategory::LONG_TERM and its first activate reaches the flush's
// persist_records().
class BlockingRecordWriteProvider : public SendspinPersistenceProvider {
public:
    explicit BlockingRecordWriteProvider(SendspinPairingRecord record)
        : records_{std::move(record)} {}

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key != persistence_keys::RECORDS) {
            return std::nullopt;
        }
        std::string encoded = encode_pairing_records(this->records_);
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

    bool save_blob(const std::string& key, const uint8_t* /*data*/, size_t /*len*/) override {
        if (key != persistence_keys::RECORDS) {
            return true;  // The keypair and pairing config must not park the tick.
        }
        std::unique_lock<std::mutex> lock(this->mutex_);
        this->entered_ = true;
        this->cv_.notify_all();
        this->cv_.wait(lock, [&] { return this->released_; });
        return true;
    }

    /// No bound: the write either reaches the provider or the test hangs and the watchdog in
    /// tests/main.cpp names it.
    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(this->mutex_);
        this->cv_.wait(lock, [&] { return this->entered_; });
    }

    void release() {
        {
            std::lock_guard<std::mutex> lock(this->mutex_);
            this->released_ = true;
        }
        this->cv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<SendspinPairingRecord> records_;
    bool entered_{false};
    bool released_{false};
};

}  // namespace

// The lifecycle handlers decide which record a write covers under conn_ptr_mutex_ and perform the
// write after dropping it (PendingRecordOp / flush_pending_record_ops()). What that buys is here:
// the sync task takes the same mutex for every decoded audio chunk through current_shared(), and
// on ESP the write is an NVS commit that stalls code running from flash for tens of milliseconds,
// so a write held under the lock is a stall of the audio path.
//
// The provider above holds that whole window open inside the persist_records() the first
// activate's flush_pending_record_ops() performs.
// A current_shared() caller issued in the window must still return: is_time_synced() is exactly
// the call the sync task makes (SendspinClient::is_time_synced() -> current_shared()). It is
// waited on with no timeout, so a regression hangs rather than turning a loaded runner into a
// failure, and the watchdog in tests/main.cpp names the test.
TEST(EncryptedLifecycle, ARecordWriteDoesNotHoldTheManagerLock) {
    PairedPeer peer = make_paired_peer();
    TestNetworkProvider network;
    BlockingRecordWriteProvider persistence(peer.record);
    SendspinClientConfig config;
    config.name = "Blocking Record Write Test Client";
    config.server_port = BLOCKING_RECORD_WRITE_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    pump_for(client, 50);

    // The main loop runs on its own thread from here: it is the thread that parks in the write,
    // so the probe below has to be a different one.
    std::atomic<bool> pumping{true};
    std::thread main_loop([&] {
        while (pumping.load(std::memory_order_acquire)) {
            client.loop();
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    });

    FakeEncryptedServer server(server_url(BLOCKING_RECORD_WRITE_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), peer.server_identity,
                               peer.record.psk_id, peer.psk);
    persistence.wait_until_entered();

    std::promise<void> probed;
    std::future<void> probed_future = probed.get_future();
    std::thread probe([&] {
        client.is_time_synced();
        probed.set_value();
    });

    // The provider is still parked here, so a current_shared() that waits on the manager lock
    // hangs on this get().
    probed_future.get();
    probe.join();

    persistence.release();
    pumping.store(false, std::memory_order_release);
    main_loop.join();

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}
