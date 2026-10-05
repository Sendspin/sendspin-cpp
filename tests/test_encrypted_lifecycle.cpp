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
#include "fake_persistence.h"
#include "inbound_ring.h"
#include "inbox.h"
#include "lifecycle_test_fixtures.h"
#include "platform/crypto.h"
#include "platform/logging.h"
#include "protocol_task.h"
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
constexpr uint16_t CONTROLLER_VALIDATION_TEST_PORT = 19006;
constexpr uint16_t LEAVE_TEST_PORT = 19007;
constexpr uint16_t LEAVE_PAIRING_TEST_PORT = 19009;
constexpr uint16_t REKEY_ROLE_SEND_TEST_PORT = 19010;
constexpr uint16_t REPROVE_REHANDSHAKE_TEST_PORT = 19011;
constexpr uint16_t COMBINED_FIRST_TEST_PORT = 19012;
constexpr uint16_t COMBINED_REKEY_TEST_PORT = 19013;
constexpr uint16_t PAIRING_REKEY_ROLE_TEST_PORT = 19014;
constexpr uint16_t RECENCY_IDLE_TEST_PORT = 19021;
constexpr uint16_t RECENCY_PLAYBACK_TEST_PORT = 19022;
constexpr uint16_t RECENCY_LATER_PLAYBACK_TEST_PORT = 19023;
constexpr uint16_t LIVENESS_STAMP_TEST_PORT = 19024;
constexpr uint16_t AVAILABILITY_TEST_PORT = 19079;
constexpr uint16_t CLOCK_GATE_SYNCED_TEST_PORT = 19080;
constexpr uint16_t CLOCK_GATE_UNSYNCED_TEST_PORT = 19081;
constexpr uint16_t CLOCK_GATE_NO_PLAYER_TEST_PORT = 19082;
constexpr uint16_t CLOCK_GATE_UNAVAILABLE_TEST_PORT = 19083;
constexpr uint16_t RESELECT_PAIRING_TEST_PORT = 19015;
constexpr uint16_t ROLE_STATE_OBJECTS_TEST_PORT = 19016;
constexpr uint16_t ROLE_ADDED_STATE_TEST_PORT = 19017;
constexpr uint16_t METADATA_SCHEDULE_TEST_PORT = 19018;
constexpr uint16_t METADATA_PENDING_TEST_PORT = 19019;
constexpr uint16_t LOSE_CAPABILITY_TEST_PORT = 19041;
constexpr uint16_t COLOR_SCHEDULE_TEST_PORT = 19043;
constexpr uint16_t COLOR_PENDING_TEST_PORT = 19044;
constexpr uint16_t COLOR_BOTH_DUE_TEST_PORT = 19045;
constexpr uint16_t BLOCKING_RECORD_WRITE_TEST_PORT = 19046;
constexpr uint16_t UNPAIRED_TOGGLE_TEST_PORT = 19091;
constexpr uint16_t UNPAIRED_TOGGLE_CONTROL_TEST_PORT = 19092;
constexpr uint16_t UNPAIRED_TOGGLE_NURSERY_TEST_PORT = 19093;
constexpr uint16_t UNPAIRED_TOGGLE_OUTBOUND_PORT = 19094;
constexpr uint16_t UNPAIRED_TOGGLE_OUTBOUND_TEST_PORT = 19095;
constexpr uint16_t UNPAIRED_TOGGLE_REKEY_TEST_PORT = 19096;
constexpr uint16_t UNPAIRED_TOGGLE_STOPPED_TEST_PORT = 19097;
constexpr uint16_t UNPAIRED_TOGGLE_NURSERY_PAIRING_TEST_PORT = 19098;

// Starts with no pairing records (unpaired: only the Sentinel PSK resolves), but captures every
// record persisted via save_blob() to a record slot key, so the pairing-flow test below
// can assert on the psk_id/server_id/psk that pairing generated and persisted, and hand the same
// psk/psk_id back to the fake server for the follow-up in-band re-handshake. The
// server/pair-finalize commit is RAM-only on the protocol task; the save_blob call this
// captures is the deferred flush from the next loop() tick (RecordStore::persist_records()).
// Locked anyway, per the general rule that a test provider should not assume the library's
// threading beyond its documented contract.
class PairingCapturePersistenceProvider : public SendspinPersistenceProvider {
public:
    // The record slots are not served beyond the base class's nullopt default: "starts with
    // no pairing records" above, so restating it here would be a no-op override.

    // Optionally pre-seed a stored Pairing PSK, so a fake server can connect on it directly
    // (matching PskCategory::PAIRING immediately) rather than on the Sentinel PSK. Must be set
    // before start() reads it into the RecordStore.
    void set_stored_pairing_psk(SendspinPairingPsk psk) {
        this->stored_pairing_psk_ = std::move(psk);
    }

    // Optionally pre-seed a LONG_TERM record so the fake server can connect to it directly
    // (bypassing pairing) before a test drives an in-band re-handshake onto the pairing PSK
    // above, on an already-admitted connection. Must be set before start() reads it into
    // the RecordStore, like set_stored_pairing_psk() above.
    void set_seeded_long_term_record(SendspinPairingRecord record) {
        this->seeded_long_term_record_ = std::move(record);
    }

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key == persistence_keys::PAIRING_PSK && this->stored_pairing_psk_.has_value()) {
            return blob_bytes(encode_pairing_psk(this->stored_pairing_psk_.value()));
        }
        if (is_record_key(key) && this->seeded_long_term_record_.has_value()) {
            return seeded_record_blob({this->seeded_long_term_record_.value()}, key);
        }
        return std::nullopt;
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (!is_record_key(key) || key == persistence_keys::RECORD_ORDER) {
            return true;  // Keys other than the record slots are not under test here.
        }
        // A zeroed slot write frees that slot and carries no record to capture.
        auto decoded = decode_pairing_record(data, len);
        if (!decoded.has_value()) {
            return true;
        }
        std::lock_guard<std::mutex> lock(this->mutex_);
        if (this->reject_pairing_records_) {
            this->rejected_record_saves_++;
            return false;
        }
        this->captured_ = std::move(decoded.value());
        return true;
    }

    bool commit() override {
        std::lock_guard<std::mutex> lock(this->mutex_);
        this->committed_ = this->captured_;
        return true;
    }

    std::optional<SendspinPairingRecord> captured_record() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->captured_;
    }

    // The captured record as of the last commit(): what a provider that queues its writes would
    // have on flash.
    std::optional<SendspinPairingRecord> committed_record() const {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return this->committed_;
    }

    // When set, a slot write that carries a record is rejected (simulating a
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
    std::optional<SendspinPairingRecord> committed_;
    int rejected_record_saves_{0};
    bool reject_pairing_records_{false};
    std::optional<SendspinPairingPsk> stored_pairing_psk_;
    std::optional<SendspinPairingRecord> seeded_long_term_record_;
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
        if (this->on_pairing_succeeded_hook) {
            this->on_pairing_succeeded_hook();
        }
    }

    /// Runs inside on_pairing_succeeded(), for a test that reads state as of the callback.
    std::function<void()> on_pairing_succeeded_hook;

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

// Seeds a stored Pairing PSK a fake server can connect on directly. A test whose pairing-PSK
// connection declares playback also calls set_unpaired_access_enabled(true), which
// messaging.md "server/activate" requires for that.
SendspinPairingPsk seed_pairing_psk(PairingCapturePersistenceProvider& persistence, uint8_t base) {
    std::array<uint8_t, 32> psk_bytes{};
    for (size_t i = 0; i < psk_bytes.size(); ++i) {
        psk_bytes[i] = static_cast<uint8_t>(base + i);
    }
    SendspinPairingPsk psk;
    psk.psk_id = psk_id_for(psk_bytes);
    psk.psk = psk_bytes;
    persistence.set_stored_pairing_psk(psk);
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

    // The post-swap server/activate alone brings it back. The evidence is monotonic: the client
    // sends client/state only while operational, and a client/state the server counted after it
    // sent that activate was sent in answer to it (every pre-swap one reached the server before
    // the msg2 the activate follows). The non-operational dip between the swap and that
    // activation is not waited for: the protocol task can apply both within one receive pass, so
    // is_connected() may never read false.
    pump_until(client, [&] {
        return server.activate_count() == 2 &&
               server.client_state_count() > server.client_states_at_last_activate() &&
               client.is_connected();
    });
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
// connection, disconnect() ends up calling ix::WebSocket::stop(), which joins IXWebSocket's own
// worker thread; close_silently() runs on the protocol task, and that worker can be waiting on
// the protocol task for ring space, so a join there would stall both. close_transport_now()
// only requests the close.
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
    // disconnect() here, the close blocks on the transport thread instead of reaching the
    // assertions below.
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
    // and the fake server (so it can perform that handshake). Supplied through
    // SendspinClientConfig::pairing_psk, the provisioning path that bypasses the provider.
    std::array<uint8_t, 32> pairing_psk_bytes{};
    for (size_t i = 0; i < pairing_psk_bytes.size(); ++i) {
        pairing_psk_bytes[i] = static_cast<uint8_t>(0xD0 + i);
    }
    const std::string pairing_psk_id = psk_id_for(pairing_psk_bytes);

    SendspinClientConfig config;
    config.name = "Pairing Flow Test Client";
    config.server_port = PAIRING_TEST_PORT;
    config.pairing_psk = SendspinPsk(pairing_psk_bytes);

    RecordingClientListener listener;
    std::optional<SendspinPairingRecord> committed_at_success;
    listener.on_pairing_succeeded_hook = [&] {
        committed_at_success = persistence.committed_record();
    };
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

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
                               server_identity, pairing_psk_id, pairing_psk_bytes, options);

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

    // The server's ack commits the record to RAM synchronously on the protocol task (see
    // client.cpp's SERVER_PAIR_FINALIZE handler); the durable save_blob(RECORDS) this waits for
    // is the deferred flush from the next loop() tick (RecordStore::persist_records()).
    pump_until(client, [&] { return persistence.captured_record().has_value(); });
    auto captured = persistence.captured_record();
    ASSERT_TRUE(captured.has_value());
    EXPECT_EQ(captured->psk_id, server.learned_psk_id().value());
    EXPECT_EQ(captured->server_id, server_identity.peer_id());

    pump_until(client, [&] { return listener.pairing_succeeded_server_id().has_value(); });
    EXPECT_EQ(listener.pairing_succeeded_server_id().value(), server_identity.peer_id());

    // An application that acts on the callback (a reboot, say) must find the record durable.
    ASSERT_TRUE(committed_at_success.has_value())
        << "on_pairing_succeeded fired before the record was committed to the provider";
    EXPECT_EQ(committed_at_success->psk_id, server.learned_psk_id().value());

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
    // instead of the PAIRING/none trust it started with. Waited for with no timeout: is_connected()
    // still reads true from before the re-handshake until a tick refreshes it, so only the trust
    // the re-activation reports tells the new session apart, and a trust that is never upgraded
    // hangs here for the suite watchdog to name.
    pump_until(client, [&] {
        return listener.trust_ever_reached(ConnectionTrust::USER) && client.is_connected();
    });
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
    SendspinPairingPsk stored_pairing_psk;
    stored_pairing_psk.psk_id = psk_id_for(pairing_psk_bytes);
    stored_pairing_psk.psk = pairing_psk_bytes;
    persistence.set_stored_pairing_psk(stored_pairing_psk);

    SendspinClientConfig config;
    config.name = "Reactivate Pairing Test Client";
    config.server_port = REACTIVATE_PAIRING_TEST_PORT;

    RecordingClientListener listener;
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

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

    // Admission publishes is_connected() before the trust level is stored, so the wait also
    // covers the trust callback, which is queued only after the getter's value is set.
    pump_until(client, [&] {
        return listener.trust_ever_reached(ConnectionTrust::USER) && client.is_connected();
    });
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
    ASSERT_TRUE(server.trigger_rehandshake(stored_pairing_psk.psk_id, pairing_psk_bytes, "pr"))
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
    // instead of) client/pair-finalize. This pairing activate adds no role, so the pairing branch
    // owes no client/state and only the operational branch (on_handshake_complete) would send
    // one: any non-zero count here means the activate was misrouted into the operational path.
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
// the protocol task is what the server's follow-up re-handshake resolves, so the connection
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
    SendspinPairingPsk stored_pairing_psk;
    stored_pairing_psk.psk_id = psk_id_for(pairing_psk_bytes);
    stored_pairing_psk.psk = pairing_psk_bytes;
    persistence.set_stored_pairing_psk(stored_pairing_psk);

    SendspinClientConfig config;
    config.name = "Pairing Flow Persist-Failure Test Client";
    config.server_port = PAIRING_PERSIST_FAILURE_TEST_PORT;

    RecordingClientListener listener;
    SendspinClient client(config);
    client.set_listener(&listener);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

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
                               stored_pairing_psk.psk_id, pairing_psk_bytes, options);

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

    // The protocol task can publish is_connected() before it stores the trust level, so the wait
    // also covers the trust callback, which is queued only after the getter's value is set.
    pump_until(client, [&] {
        return listener.trust_ever_reached(ConnectionTrust::USER) && client.is_connected();
    });
    EXPECT_EQ(client.get_current_trust(), ConnectionTrust::USER)
        << "Trust must upgrade to USER on the RAM-committed record";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A binary WebSocket frame that arrives while the Noise handshake is still pending must close the
// connection, not be dispatched.
//
// The binary branch of process_inbound_message() closes rather than dispatching: letting a peer
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

// messaging.md "External Source Handling": availability is device state. Set before a connection,
// and kept across stop()/start(), it reaches the first client/state; each change publishes once,
// and restating the current value sends nothing.
TEST(EncryptedLifecycle, AvailabilityIsDeviceStateAndPublishesOnChange) {
    SendspinClientConfig config;
    config.name = "Availability Test Client";
    config.server_port = AVAILABILITY_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());
    client.set_available(false);
    client.stop();
    ASSERT_TRUE(bundle.start());
    EXPECT_FALSE(client.is_available());

    auto available_in = [](const std::string& state) {
        JsonDocument doc;
        EXPECT_EQ(deserializeJson(doc, state), DeserializationError::Ok);
        return doc["payload"]["available"].as<bool>();
    };

    auto server = connect_paired_server(bundle.peer, AVAILABILITY_TEST_PORT);
    pump_until(client, [&] { return !server->client_states().empty(); });
    EXPECT_FALSE(available_in(server->client_states().front()))
        << "the first client/state lost the availability set before the restart";

    const size_t states_before_change = server->client_states().size();
    client.set_available(true);
    pump_until(client,
               [&] { return server->client_states().size() > states_before_change; });
    EXPECT_TRUE(available_in(server->client_states().back()));

    const size_t states_before_repeat = server->client_states().size();
    client.set_available(true);
    pump_for(client, 50);
    EXPECT_EQ(server->client_states().size(), states_before_repeat)
        << "restating the current availability published a client/state";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// messaging.md "client/state": an available player reports its state only after clock
// synchronization; a client with no active player, or an unavailable one, does not wait. The first
// row is the control: every later row differs from it in one input.
TEST(EncryptedLifecycle, ClientStateWaitsForClockSyncOnlyForAnAvailablePlayer) {
    struct Row {
        const char* name;
        uint16_t port;
        bool with_player;
        bool answer_time;
        bool available;
        bool expect_state;
    };
    const Row rows[] = {
        {"Control: available player, clock synced", CLOCK_GATE_SYNCED_TEST_PORT, true, true, true,
         true},
        {"available player, clock never synced", CLOCK_GATE_UNSYNCED_TEST_PORT, true, false, true,
         false},
        {"no player role, clock never synced", CLOCK_GATE_NO_PLAYER_TEST_PORT, false, false, true,
         true},
        {"unavailable player, clock never synced", CLOCK_GATE_UNAVAILABLE_TEST_PORT, true, false,
         false, true},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinClientConfig config;
        config.name = "Clock Gate Test Client";
        config.server_port = row.port;
        config.time_burst_interval_ms = 100;

        PairedClientBundle bundle(config);
        SendspinClient& client = bundle.client();
        CountingPlayerListener player_listener;
        if (row.with_player) {
            client.add_player(make_pcm_player_config()).set_listener(&player_listener);
        } else {
            client.add_metadata();
        }
        ASSERT_TRUE(bundle.start());
        client.set_available(row.available);

        FakeEncryptedServerOptions options;
        options.answer_time = row.answer_time;
        options.first_roles_json = row.with_player ? R"(["player@v1"])" : R"(["metadata@v1"])";
        auto server = connect_paired_server(bundle.peer, row.port, std::move(options));

        // The first client/time shows the connection is operational.
        pump_until(client, [&] { return server->got_client_time(); });
        if (row.expect_state) {
            pump_until(client, [&] { return server->client_state_count() > 0; });
            JsonDocument doc;
            ASSERT_EQ(deserializeJson(doc, server->client_states().front()),
                      DeserializationError::Ok);
            EXPECT_EQ(doc["payload"]["available"].as<bool>(), row.available);
        } else {
            pump_for(client, 300);
            EXPECT_EQ(server->client_state_count(), 0)
                << "an available player reported its state before its clock synchronized";
        }

        client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
        pump_for(client, 100);
    }
}

namespace {

/// Sends a controller server/state offering `commands_json` and pumps until the client holds it:
/// roles/controller/v1.md "client/command controller object" lets a command name only an offered
/// command.
void offer_controller_commands(SendspinClient& client, FakeEncryptedServer& server,
                               const ControllerRole& controller,
                               const std::string& commands_json = R"(["play","pause"])") {
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/state","payload":{"controller":{"supported_commands":)" +
        commands_json + R"(,"volume":50,"muted":false,"repeat":"off","shuffle":false}}})"));
    pump_until(client,
               [&] { return !controller.get_controller_state().supported_commands.empty(); });
}

}  // namespace

// roles/controller/v1.md "client/command controller object": a command must be among the
// latest supported_commands, and "Command behaviour" requires volume, mute, position_ms and
// offset_ms for the commands that take them. Anything else is dropped rather than sent.
TEST(EncryptedLifecycle, ControllerCommandsNeedAnOfferedCommandAndItsParameter) {
    SendspinClientConfig config;
    config.name = "Controller Validation Test Client";
    config.server_port = CONTROLLER_VALIDATION_TEST_PORT;

    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    auto& controller = client.add_controller();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServerOptions options;
    options.first_roles_json = R"(["controller@v1"])";
    auto server =
        connect_paired_server(bundle.peer, CONTROLLER_VALIDATION_TEST_PORT, std::move(options));
    pump_until(client, [&] { return client.is_connected(); });
    offer_controller_commands(client, *server, controller,
                              R"(["play","volume","mute","seek","seek_relative"])");

    // `sent_as` is the command's wire name when it goes out, null when it must be dropped.
    using Cmd = SendspinControllerCommand;
    struct Row {
        ClientCommandControllerObject cmd;
        const char* sent_as;
    };
    const Row rows[] = {
        {{.command = Cmd::PLAY}, "play"},  // Control:
        {{.command = Cmd::NEXT}, nullptr},  // not offered
        {{.command = Cmd::VOLUME}, nullptr},
        {{.command = Cmd::VOLUME, .volume = 101}, nullptr},
        {{.command = Cmd::VOLUME, .volume = 100}, "volume"},  // Control:
        {{.command = Cmd::MUTE}, nullptr},
        {{.command = Cmd::MUTE, .muted = true}, "mute"},  // Control:
        {{.command = Cmd::SEEK}, nullptr},
        {{.command = Cmd::SEEK, .position_ms = 1000}, "seek"},  // Control:
        {{.command = Cmd::SEEK_RELATIVE}, nullptr},
        {{.command = Cmd::SEEK_RELATIVE, .offset_ms = -5000}, "seek_relative"},  // Control:
    };

    std::vector<std::string> expected;
    for (const Row& row : rows) {
        controller.send_command(row.cmd);
        if (row.sent_as != nullptr) {
            expected.emplace_back(row.sent_as);
        }
    }
    // Commands go out in order, so once the last one sent has arrived every dropped one would have.
    pump_until(client, [&] { return server->controller_commands().size() >= expected.size(); });
    pump_for(client, 100);
    EXPECT_EQ(server->controller_commands(), expected);

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
    client.set_unpaired_access_enabled(true);
    client.add_player(make_pcm_player_config()).set_listener(&player_listener);
    auto& controller = client.add_controller();
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

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

    offer_controller_commands(client, server, controller);
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
    options.answer_time = true;  // An active player's state waits for clock sync.
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
    options.answer_time = true;  // An active player's state waits for clock sync.
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
    offer_controller_commands(client, *server, controller);
    controller.send_command({.command = SendspinControllerCommand::PLAY});
    pump_until(client, [&] { return !server->controller_commands().empty(); });
    const size_t before_rekey = server->controller_commands().size();

    ASSERT_TRUE(server->trigger_rehandshake(bundle.peer.record.psk_id, bundle.peer.psk));
    pump_until(client, [&] { return !client.is_connected(); });
    EXPECT_EQ(server->client_hello_count(), 1)
        << "connection.md \"Re-handshake\": client/hello is not re-sent";

    controller.send_command({.command = SendspinControllerCommand::PAUSE});
    client.leave();
    pump_for(client, 100);
    EXPECT_EQ(server->controller_commands().size(), before_rekey)
        << "a controller command was sent while the connection awaited its post-rekey activate";
    EXPECT_EQ(server->client_leave_count(), 0)
        << "client/leave was sent while the connection awaited its post-rekey activate";

    // Control: the same command goes out once that activation arrives, so the gate is the
    // re-handshake window and not the role, which stayed active across it.
    ASSERT_TRUE(server->send_app_json(controller_activate));
    pump_until(client, [&] { return client.is_connected(); });
    controller.send_command({.command = SendspinControllerCommand::PAUSE});
    pump_until(client, [&] { return server->controller_commands().size() > before_rekey; });
    EXPECT_EQ(server->controller_commands().back(), "pause");
    client.leave();
    pump_until(client, [&] { return server->client_leave_count() == 1; });

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
    client.set_unpaired_access_enabled(true);
    auto& controller = client.add_controller();
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

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
    offer_controller_commands(client, server, controller);
    controller.send_command({.command = SendspinControllerCommand::PLAY});
    pump_until(client, [&] { return !server.controller_commands().empty(); });

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
    // With unpaired access off (its default), messaging.md "server/activate" allows a
    // pairing-PSK connection no activity set that includes playback, so declaring pairing alone
    // is what takes this connection's playback capability away.
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xC5);

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
    client.set_unpaired_access_enabled(true);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

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

// A pairing-only activate after the same re-handshake that adds a role with a state object.
// connection.md "Re-handshake" makes it a subsequent activation, so messaging.md "client/state"
// owes the added role's object even though the connection is entering pairing rather than going
// operational. ReactivatePairingOnAlreadyAdmittedConnectionSendsPairFinalize is the control: its
// pairing-only activate adds no role and sends no state.
TEST(EncryptedLifecycle, PairingActivateAfterARehandshakeThatAddsARoleSendsItsClientState) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;

    Identity server_identity = Identity::generate().value();
    PairedPeer long_term_peer = make_paired_peer();
    long_term_peer.record.server_id = server_identity.peer_id();
    persistence.set_seeded_long_term_record(long_term_peer.record);
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xD0);

    SendspinClientConfig config;
    config.name = "Pairing Rekey Role Test Client";
    config.server_port = PAIRING_REKEY_ROLE_TEST_PORT;

    SendspinClient client(config);
    add_state_object_roles(client);
    // Makes roles on a Pairing PSK session with pairing alone admissible (messaging.md
    // "Playback-capable connections").
    client.set_unpaired_access_enabled(true);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    FakeEncryptedServerOptions options;
    // No player: an active player's state also waits for clock sync.
    options.first_roles_json = R"(["controller@v1"])";
    options.second_activities_json = R"(["pairing"])";
    options.second_roles_json = R"(["controller@v1","artwork@v1"])";
    options.second_pairing_method = "pairing_psk";
    options.withhold_pair_finalize_ack = true;
    FakeEncryptedServer server(server_url(PAIRING_REKEY_ROLE_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                               long_term_peer.record.psk_id, long_term_peer.psk, options);

    pump_until(client, [&] { return server.client_state_count() > 0; });
    const int state_count_before_rekey = server.client_state_count();

    ASSERT_TRUE(server.trigger_rehandshake(pairing_psk.psk_id, pairing_psk.psk, "pr"))
        << "failed to start the in-band re-handshake onto the pairing PSK";

    pump_until(client, [&] { return server.client_state_count() > state_count_before_rekey; });
    EXPECT_TRUE(server.pair_init().has_value()) << "the activate did not enter pairing";

    JsonDocument doc;
    ASSERT_TRUE(parse_last_client_state(server, doc));
    EXPECT_TRUE(doc["payload"]["artwork"].is<JsonObjectConst>())
        << "the state did not carry the object of the role the activation added";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

/// Frees the manager's admitted slot, the way a drop does, without the teardown. Protocol-task
/// work: the caller plays the task, or the client is not started.
void release_admitted(ConnectionManager& manager) {
    for (auto& entry : manager.admitted_) {
        if (entry.conn != nullptr) {
            entry.conn->set_admitted(false);
        }
        entry = AdmittedEntry{};
    }
    manager.refresh_published_state();
}

/// The primary admitted connection, or nullptr. Protocol-task work, like release_admitted().
SendspinConnection* admitted_connection(SendspinClient& client) {
    AdmittedEntry* primary = client.connection_manager_->primary();
    return primary != nullptr ? primary->conn.get() : nullptr;
}

/// One protocol tick on the test thread, then the main loop's drain, for a test that plays the
/// protocol task.
void tick(SendspinClient& client) {
    (void) client.protocol_tick();
    client.loop();
}

/// Ticks until pred() holds. Unbounded, like pump_until().
void tick_until(SendspinClient& client, const std::function<bool()>& pred) {
    while (!pred()) {
        tick(client);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
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

    // The test thread plays the protocol task from here: the stamp is the task's state.
    client.protocol_task_->stop();
    // The state the watchdog keys on, as handle_noise_rehandshake() left it: the hello flags
    // carried over the swap, only the activation rewound, and the stamp was refreshed.
    auto* conn = admitted_connection(client);
    ASSERT_NE(conn, nullptr);
    EXPECT_TRUE(conn->is_handshake_complete()) << "neither hello is re-sent, so both flags stand";
    EXPECT_FALSE(conn->is_operational());
    ASSERT_NE(conn->get_provisional_time_us(), 0)
        << "the re-handshake must restamp the re-proving deadline";

    // Control: a connection still inside the deadline is held, not reaped.
    tick(client);
    EXPECT_NE(admitted_connection(client), nullptr)
        << "a connection still inside REPROVE_TIMEOUT must be given time to be activated";

    conn->set_provisional_time_us(platform_time_us() - REPROVE_TIMEOUT_US - 1);
    tick_until(client, [&] { return admitted_connection(client) == nullptr; });

    // connection.md "Re-handshake" allows no application message between Noise message 1 and the
    // new activation, so the close carries no client/goodbye. Waiting for the socket to close
    // first means a goodbye that was sent has had its chance to arrive.
    wait_until([&] { return server->closed(); });
    EXPECT_FALSE(server->goodbye_reason().has_value())
        << "the re-proving watchdog must close without a goodbye";
}

// ============================================================================
// Direct-dispatch harness
// ============================================================================

// A SendspinConnection that exists only to carry the connection's protocol state: nothing is sent,
// and no transport is ever attached. It lets a test hand messages straight to the dispatch path
// on the test thread, which plays the protocol task.
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
};

// A started client with a metadata role, and the one entry point the hold tests need: hand a JSON
// message to the dispatch path as the protocol task would.
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
        // The test thread plays the protocol task: deliver() calls its entry point directly, and
        // a second thread running the same code on the same connections would race it.
        this->client_storage->protocol_task_->stop();
    }

    ~HoldTestClient() {
        this->client_storage->stop();
    }

    void deliver(SendspinConnection& conn, const std::string& json) {
        // A complete message off a transport proves the peer alive (end_inbound_message()),
        // and the protocol tick's liveness scan reaps an admitted connection whose last arrival
        // is older than the timeout. Handing the JSON straight to the dispatch entry point skips the stamp, so
        // do it here rather than stubbing the tick out.
        conn.last_receive_time_us_.store(static_cast<uint32_t>(platform_time_us()),
                                         std::memory_order_relaxed);
        this->client_storage->process_json_message(&conn, json.data(), json.size(),
                                                   platform_time_us());
    }

    /// A stand-in connection owned by the bundle, so it outlives every reference the client's
    /// connection manager takes to it.
    HoldTestConnection& connection() {
        this->connections.push_back(std::make_shared<HoldTestConnection>());
        return *this->connections.back();
    }

    /// Admits `conn` the way a promotion does, owning the roles its activation made active.
    void admit(HoldTestConnection& conn) {
        this->admit_owning(conn, conn.get_active_role_mask());
    }

    /// Admits `conn` owning `owned_roles` (role_mask_bit() bits), as arbitration leaves a
    /// connection that shares the admitted array with another owner.
    void admit_owning(HoldTestConnection& conn, uint16_t owned_roles) {
        std::shared_ptr<HoldTestConnection> owned;
        for (const auto& candidate : this->connections) {
            if (candidate.get() == &conn) {
                owned = candidate;
            }
        }
        ASSERT_NE(owned, nullptr) << "admit() takes a connection from connection()";
        ConnectionManager& manager = *this->client_storage->connection_manager_;
        manager.install_admitted(owned, owned_roles);
    }

    /// One protocol tick on the test thread, then the main loop.
    void pump() {
        this->client_storage->protocol_tick();
        pump_for(*this->client_storage, 20);
    }

    SendspinClient& client_ref() {
        return *this->client_storage;
    }

    TestNetworkProvider network;
    RecordingMetadataListener listener;
    // Declared before the client, so the client (stopped first) is destroyed before them.
    std::vector<std::shared_ptr<HoldTestConnection>> connections;
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

// messaging.md "server/time" answers the client's own client/time, yet any peer that knows the
// Sentinel PSK can sit in the nursery and send it unasked. Twice the event ring's capacity of such
// replies between two loop() ticks must not crowd the admitted server's next stream/start off the
// ring: server/time traffic stays on the protocol task, in each connection's own burst, and off
// the lifecycle ring (docs/conventions.md "Threading and cross-thread state").
//
// Control: the same handler takes the reply to a frame in flight, seeded the way
// send_time_message() records one, since the stand-in has no transport to send it over.
TEST(EncryptedLifecycle, ServerTimeIsTakenOnlyAsTheReplyToTheFrameInFlight) {
    SendspinClientConfig config;
    config.name = "Unsolicited Time Test Client";
    // Port 0: an ephemeral listener nothing connects to; every message is delivered directly.
    config.server_port = 0;
    SendspinClient client(config);
    TestNetworkProvider network;
    client.set_network_provider(&network);
    CountingPlayerListener listener;
    client.add_player(make_pcm_player_config()).set_listener(&listener);
    ASSERT_TRUE(client.start());
    // The test thread plays the protocol task, as in HoldTestClient.
    client.protocol_task_->stop();

    auto admitted_owner = std::make_shared<HoldTestConnection>();
    HoldTestConnection& admitted = *admitted_owner;
    client.connection_manager_->install_admitted(admitted_owner,
                                                 admitted_owner->get_active_role_mask());
    HoldTestConnection unsolicited;

    auto deliver = [&client](SendspinConnection& conn, const std::string& json) {
        client.process_json_message(&conn, json.data(), json.size(), platform_time_us());
    };
    auto time_reply = [](int64_t echo) {
        return R"({"type":"server/time","payload":{"client_transmitted":)" +
               std::to_string(echo) + R"(,"server_received":2000,"server_transmitted":2001}})";
    };
    for (size_t i = 0; i < 2 * Inbox::EVENT_CAPACITY; ++i) {
        deliver(unsolicited, time_reply(0));
    }
    deliver(admitted, stream_start_pcm_json());
    pump_until(client, [&] { return listener.stream_starts == 1; });

    constexpr uint32_t TAG = 5000;
    admitted.time_frame_sent_us_.store(TAG);
    admitted.time_frame_tag_.store(TAG);
    deliver(admitted, time_reply(TAG + 1));
    EXPECT_EQ(admitted.time_frame_tag_.load(), TAG) << "a reply to another frame must not take it";
    deliver(admitted, time_reply(TAG));
    EXPECT_EQ(admitted.time_frame_tag_.load(), 0U) << "the reply to the frame in flight takes it";

    client.stop();
}

// messaging.md "server/state": each metadata object carries the role's full state, so what a
// later object leaves out is gone rather than carried forward from the object before it.
TEST(EncryptedLifecycle, MetadataStateReplacesRatherThanMerges) {
    HoldTestClient bundle("Metadata Full State Test Client");

    HoldTestConnection& conn = bundle.connection();
    bundle.admit(conn);
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

    // Both cross the protocol task while the main loop is parked, so a single drain takes them.
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

    // Both cross the protocol task while the main loop is parked, so a single drain takes them.
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

    // Both cross the protocol task while the main loop is parked, so a single drain takes them.
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

    HoldTestConnection& conn = bundle.connection();
    bundle.admit(conn);
    bundle.deliver(conn, metadata_state_json(1, "Admitted"));
    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 1);
    EXPECT_EQ(bundle.listener.last_title, "Admitted");
}

// Role traffic from a connection that is not admitted is dropped, not kept: it stays dropped even
// once that connection reaches the admitted slot.
TEST(EncryptedLifecycle, RoleTrafficBeforeAdmissionIsNotAppliedAtAdmission) {
    HoldTestClient bundle("Pre-Activate Role Traffic Test Client");

    HoldTestConnection& conn = bundle.connection();
    bundle.deliver(conn, metadata_state_json(1, "Before Any Activate"));
    bundle.pump();
    ASSERT_EQ(bundle.listener.updates, 0);

    bundle.admit(conn);
    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 0)
        << "role traffic that preceded the admission must not be applied (last_title='"
        << bundle.listener.last_title << "')";
}

// Control: every role message type runs its real handler to completion on an admitted
// connection. One message of each type, back to back, so a handler that throws the dispatch off
// (or blocks in it) takes the metadata message behind it down with it. The group name and the
// metadata title are what say the handlers ran rather than being walked past: a type whose arm
// does nothing is invisible to the trailing message alone.
TEST(EncryptedLifecycle, EveryRoleMessageTypeRunsThroughItsHandler) {
    HoldTestClient bundle("Role Handler Test Client");

    HoldTestConnection& conn = bundle.connection();
    bundle.admit(conn);
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

    bundle.pump();
    EXPECT_EQ(bundle.listener.updates, 1) << "the dispatch did not run to completion";
    EXPECT_EQ(bundle.listener.last_title, "Replayed");
    ASSERT_TRUE(bundle.client_ref().get_group_state().group_name.has_value())
        << "the group/update never reached its handler";
    EXPECT_EQ(*bundle.client_ref().get_group_state().group_name, "Kitchen");
}

// Role traffic reaches a role only from the admitted connection that owns it, not from any
// connection that merely has the role active: with more than one admitted connection, each role
// has one owner, and the others' traffic for it is ignored. Every row's connection has the
// metadata role active.
TEST(EncryptedLifecycle, RoleDispatchFollowsOwnership) {
    const uint16_t without_metadata =
        static_cast<uint16_t>(ALL_ROLES_MASK & ~role_mask_bit(SendspinRole::METADATA));
    struct Row {
        const char* name;
        bool admitted;
        uint16_t owned_roles;
        int expected_updates;
    };
    const Row rows[] = {
        {"Control: the admitted connection owns the role", true, ALL_ROLES_MASK, 1},
        {"admitted, but another connection owns the role", true, without_metadata, 0},
        {"not admitted", false, 0, 0},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        HoldTestClient bundle("Role Ownership Dispatch Test Client");
        HoldTestConnection& conn = bundle.connection();
        ASSERT_TRUE(conn.is_role_active(SendspinRole::METADATA));
        if (row.admitted) {
            bundle.admit_owning(conn, row.owned_roles);
        }
        bundle.deliver(conn, metadata_state_json(1, "Owned"));
        bundle.pump();
        EXPECT_EQ(bundle.listener.updates, row.expected_updates);
    }
}

/// A stand-in that keeps every client/state it is asked to send.
class StateCapturingConnection : public HoldTestConnection {
public:
    SsErr send_text_message(const std::string& msg, SendCompleteCallback cb,
                            bool allow_before_hello) override {
        if (msg.find("client/state") != std::string::npos) {
            this->states.push_back(msg);
        }
        return HoldTestConnection::send_text_message(msg, std::move(cb), allow_before_hello);
    }

    std::vector<std::string> states;
};

// messaging.md "client/state": a connection is sent the role objects of the roles it owns, and no
// other: a role another admitted connection owns is that connection's to report. The player is
// the role with a state object here, active on every row.
TEST(EncryptedLifecycle, ClientStateCarriesOnlyTheOwnedRoles) {
    struct Row {
        const char* name;
        uint16_t owned_roles;
        bool expect_player;
    };
    const Row rows[] = {
        {"Control: the connection owns the player", ALL_ROLES_MASK, true},
        {"another connection owns the player",
         static_cast<uint16_t>(ALL_ROLES_MASK & ~role_mask_bit(SendspinRole::PLAYER)), false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        HoldTestClient bundle("Owned Client State Test Client");
        auto conn = std::make_shared<StateCapturingConnection>();
        conn->set_client_hello_sent(true);
        conn->set_server_hello_received(true);
        conn->last_receive_time_us_.store(static_cast<uint32_t>(platform_time_us()),
                                          std::memory_order_relaxed);
        bundle.client_ref().connection_manager_->install_admitted(conn, row.owned_roles);
        // Unavailable, so a player's state does not wait for the clock.
        bundle.client_ref().set_available(false);
        bundle.pump();

        ASSERT_FALSE(conn->states.empty()) << "the snapshot never reached the admitted connection";
        JsonDocument doc;
        ASSERT_FALSE(deserializeJson(doc, conn->states.back()));
        EXPECT_FALSE(doc["payload"]["available"].as<bool>());
        EXPECT_EQ(!doc["payload"]["player"].isNull(), row.expect_player);
    }
}

// A stand-in that records, for each client/state it is asked to send, whether it held the
// admitted slot at that moment.
class StateRecordingConnection : public HoldTestConnection {
public:
    SsErr send_text_message(const std::string& msg, SendCompleteCallback cb,
                            bool allow_before_hello) override {
        if (msg.find("client/state") != std::string::npos) {
            this->state_sent_while_admitted.push_back(this->is_admitted());
        }
        return HoldTestConnection::send_text_message(msg, std::move(cb), allow_before_hello);
    }

    std::vector<bool> state_sent_while_admitted;
};

// messaging.md "client/state": the first client/state is what lets the server start a role's
// stream and send its binary data, and the client drops binary from a connection that is not
// admitted yet. A state sent before the connection is installed in the admitted slot would invite
// an artwork announce into that gap; the announce is dropped and the part behind it is a malformed
// sequence the role closes the connection on. A first activate that selects pairing alone still carries active roles on a
// playback-capable connection (messaging.md "server/activate"), and those are owed the initial
// state as well.
//
// Driven through the protocol task's own tick from the nursery, so the order under test is the
// one a real promotion runs. The stand-in sends inline, which makes "was it admitted when the state
// left" a plain read instead of a race against a socket. Every row runs with unpaired access, the
// setting that makes its activation admissible on a Sentinel or Pairing PSK session. The pairing
// row matches the Pairing PSK and selects pairing_psk, whose entry sends client/pair-init and
// client/pair-finalize at once; those are not client/state, so the count below ignores them.
TEST(EncryptedLifecycle, TheFirstClientStateLeavesOnlyOnceTheConnectionIsAdmitted) {
    struct Row {
        const char* label;
        std::vector<SendspinActivity> activities;
        std::optional<SendspinPairMethod> pairing_method;
    };
    const Row rows[] = {
        {"Control: playback", {SendspinActivity::PLAYBACK}, std::nullopt},
        {"pairing alone", {SendspinActivity::PAIRING}, SendspinPairMethod::PAIRING_PSK},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.label);
        HoldTestClient bundle("State After Admission Test Client");
        bundle.client_ref().set_unpaired_access_enabled(true);
        ConnectionManager& manager = *bundle.client_ref().connection_manager_;

        auto conn = std::make_shared<StateRecordingConnection>();
        if (row.pairing_method.has_value()) {
            const auto& pairing_psk = bundle.client_ref().record_store_->pairing_psk();
            ASSERT_TRUE(pairing_psk.has_value());
            conn->set_noise_handshake_result(test_peer_id("state-after-admission-server"),
                                             PskCategory::PAIRING, pairing_psk->psk_id);
            // The count the activate-event drain takes for every pairing server/activate.
            conn->bump_pairing_index();
        }
        // No player in the active set: an active player's state also waits for clock sync, which
        // lands after admission by itself and would hide the gate under test.
        conn->apply_server_activate(row.activities, std::vector<std::string>{"metadata@v1"},
                                    row.pairing_method, std::nullopt);
        conn->set_client_hello_sent(true);
        conn->set_server_hello_received(true);
        conn->set_provisional_time_us(platform_time_us());
        conn->last_receive_time_us_.store(static_cast<uint32_t>(platform_time_us()),
                                          std::memory_order_relaxed);
        {
            manager.nursery_.push_back(NurseryEntry{.conn = conn, .client_init_sent = true});
        }

        tick(bundle.client_ref());

        ASSERT_TRUE(conn->is_admitted()) << "the tick did not promote and admit the connection";
        ASSERT_EQ(conn->state_sent_while_admitted.size(), 1u)
            << "the promotion tick owes exactly one client/state";
        EXPECT_TRUE(conn->state_sent_while_admitted.front())
            << "client/state left before the connection could receive the binary data it opens";
        if (row.pairing_method.has_value()) {
            EXPECT_TRUE(conn->is_pairing_in_progress())
                << "publishing the state ended the pairing attempt the activation started";
        }
    }
}

// A stand-in that records the goodbye a drop sends it.
class GoodbyeRecordingConnection : public HoldTestConnection {
public:
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override {
        this->goodbye = reason;
        HoldTestConnection::disconnect(reason, std::move(on_complete));
    }

    std::optional<SendspinGoodbyeReason> goodbye;
};

// The protocol tick's liveness scan reads the admitted connection's last-arrival stamp: a connection whose
// last arrival is older than the timeout is dropped with a restart goodbye (messaging.md
// "client/goodbye"), and one heard from just now stays current. The stamp is set directly rather
// than aged by waiting, and the timeout is the manager's own, default-derived and tens of seconds,
// so no scheduling stall can age the control row past it. The stand-in is promoted from the
// nursery by a real tick, so it holds the slot the way an established connection does; as a
// Sentinel-category playback connection it is admissible only with unpaired access on.
TEST(EncryptedLifecycle, LivenessTickDropsOnlyAStaleCurrentConnection) {
    struct Row {
        const char* label;
        bool stale;
    };
    const Row rows[] = {
        {"Control: last arrival at now", false},
        {"last arrival older than the timeout", true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.label);
        HoldTestClient bundle("Liveness Tick Test Client");
        bundle.client_ref().set_unpaired_access_enabled(true);
        SendspinClient& client = bundle.client_ref();
        ConnectionManager& manager = *client.connection_manager_;
        // What the tick itself compares against.
        const int64_t timeout_us = manager.liveness_timeout_us_;
        ASSERT_GT(timeout_us, 0) << "the liveness check is disabled, so no row can be dropped";

        auto conn = std::make_shared<GoodbyeRecordingConnection>();
        conn->set_client_hello_sent(true);
        conn->set_server_hello_received(true);
        conn->set_provisional_time_us(platform_time_us());
        conn->last_receive_time_us_.store(static_cast<uint32_t>(platform_time_us()),
                                          std::memory_order_relaxed);
        {
            manager.nursery_.push_back(NurseryEntry{.conn = conn, .client_init_sent = true});
        }
        tick(client);
        ASSERT_TRUE(client.is_connected()) << "the tick did not promote the connection";
        ASSERT_TRUE(conn->is_admitted()) << "the tick did not admit the connection";

        const int64_t now_us = platform_time_us();
        conn->last_receive_time_us_.store(
            static_cast<uint32_t>(row.stale ? now_us - 2 * timeout_us : now_us),
            std::memory_order_relaxed);
        tick(client);

        if (row.stale) {
            EXPECT_FALSE(client.is_connected()) << "a stale connection was left current";
            EXPECT_FALSE(conn->is_admitted()) << "a dropped connection still claims admission";
            EXPECT_EQ(conn->goodbye, SendspinGoodbyeReason::RESTART)
                << "a connection dropped for liveness must be told to restart";
        } else {
            EXPECT_TRUE(client.is_connected()) << "a connection heard from just now was dropped";
            EXPECT_FALSE(conn->goodbye.has_value()) << "a live connection was sent a goodbye";
        }
    }
}

// A complete message from the peer advances the connection's last-arrival stamp, which is what
// keeps an answering peer clear of the liveness tick above. The stamp is private and has no
// observable of its own short of the drop; reading it is what lets the test wait for the advance
// instead of for a timeout to pass.
TEST(EncryptedLifecycle, AnInboundMessageAdvancesTheLivenessStamp) {
    SendspinClientConfig config;
    config.name = "Liveness Stamp Test Client";
    config.server_port = LIVENESS_STAMP_TEST_PORT;
    PairedClientBundle bundle(config);
    SendspinClient& client = bundle.client();
    ASSERT_TRUE(bundle.start());

    FakeEncryptedServer server(server_url(LIVENESS_STAMP_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), bundle.peer.server_identity,
                               bundle.peer.record.psk_id, bundle.peer.psk);
    pump_until(client, [&] { return client.is_connected(); });
    // The test thread plays the protocol task from here, so it can read the admitted slot.
    client.protocol_task_->stop();
    SendspinConnection* conn = admitted_connection(client);
    ASSERT_NE(conn, nullptr);

    const uint32_t before_us = conn->get_last_receive_time_us();
    ASSERT_TRUE(server.send_app_json(metadata_state_json(1, "Liveness Stamp")));
    // Unbounded: completion is the proof, and the suite watchdog catches a stamp that never moves.
    // Inequality, since the 32-bit stamp can wrap.
    tick_until(client, [&] { return conn->get_last_receive_time_us() != before_us; });

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Seeds a set of LONG_TERM records into the slot layout RecordStore loads them from, so an
// unpair test can assert on what the store would come back with after a reboot as well as on
// what it resolves right now. TestPersistenceProvider rejects writes on purpose (see its
// comment), so it cannot show what a removal persists; InMemoryPersistenceProvider accepts them
// and counts the writes per key, which is what the coalescing tests below read.
/// @param records The records to seed, least recently used first.
std::unique_ptr<InMemoryPersistenceProvider> make_record_store_provider(
    const std::vector<SendspinPairingRecord>& records) {
    auto provider = std::make_unique<InMemoryPersistenceProvider>();
    seed_records(*provider, records);
    return provider;
}

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
    auto provider = make_record_store_provider({unpairing_record, bystander_record});
    InMemoryPersistenceProvider& persistence = *provider;
    SendspinClientConfig config;
    config.name = "Unpair Record Test Client";
    config.server_port = UNPAIR_RECORD_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

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
    EXPECT_EQ(persisted_psk_ids(persistence), std::vector<std::string>{bystander_record.psk_id})
        << "the persisted slots must hold exactly the surviving record";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A tick carrying more than one record change must write each key those changes touched exactly
// once, and no other: on ESP each save is an NVS erase cycle, and flash wear is a budget
// (docs/conventions.md, "Embedded resource discipline"). Once per key holds because the store's
// dirty set holds each key once, whatever number of changes dirtied it. The two here are the pair
// a real tick can carry, made by a playback activate and the unpair drain in the same locked
// block, and both move the recency order. A third record keeps the played one from being the
// most recent once the unpair has removed the other, so the playback move is a real one.
TEST(EncryptedLifecycle, SeveralRecordChangesInOneTickWriteEachTouchedKeyOnce) {
    Identity played_identity = Identity::generate().value();
    Identity other_identity = Identity::generate().value();
    Identity unpairing_identity = Identity::generate().value();
    SendspinPairingRecord played_record = make_record_for(played_identity);
    SendspinPairingRecord other_record = make_record_for(other_identity);
    SendspinPairingRecord unpairing_record = make_record_for(unpairing_identity);

    TestNetworkProvider network;
    // Slots 0-2 in order, least recently used first (seed_records() lays them out that way).
    auto provider = make_record_store_provider({played_record, other_record, unpairing_record});
    InMemoryPersistenceProvider& persistence = *provider;
    SendspinClientConfig config;
    config.name = "Coalesced Record Write Test Client";
    // Port 0: an ephemeral listener nothing connects to; the manager is driven directly.
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    // The test thread plays the protocol task, which owns the manager's slots.
    client.protocol_task_->stop();
    ConnectionManager& manager = *client.connection_manager_;
    const size_t writes_before = record_writes(persistence);

    HoldTestConnection conn;
    conn.set_noise_handshake_result(unpairing_record.server_id, PskCategory::LONG_TERM,
                                    unpairing_record.psk_id);
    {
        // What note_playback_activity() does when a long-term connection takes playback.
        EXPECT_TRUE(client.record_store_->note_record_played(played_record.psk_id));
        client.request_persist();
        manager.handle_server_unpair(&conn);
    }

    client.flush_pending_persistence();

    // Slot 2 is zeroed and the order, which both ops moved, is written once.
    EXPECT_EQ(record_writes(persistence) - writes_before, 2u)
        << "the tick's record changes must write each touched key once";
    EXPECT_EQ(persistence.save_attempts(persistence_keys::RECORD_ORDER), 1)
        << "two changes that both move the order must write it once";
    EXPECT_EQ(persistence.save_attempts(persistence_keys::record_slot_key(2)), 1)
        << "the unpair must write its own slot once";
    EXPECT_EQ(persistence.save_attempts(persistence_keys::record_slot_key(0)), 0)
        << "a recency move must not rewrite the played record's slot";
    // Control: the writes carry both changes, so this is coalescing rather than a lost write.
    // Least recently used first, so the played record comes last.
    EXPECT_EQ(persisted_psk_ids(persistence),
              (std::vector<std::string>{other_record.psk_id, played_record.psk_id}))
        << "the next boot must load exactly the surviving records, the played one most recent";

    client.stop();
}

// A playback activate on the record that is already the most recent moves nothing, so it must
// not spend an NVS erase cycle: every activate of the server already playing takes this path.
TEST(EncryptedLifecycle, APlaybackThatMovesNothingWritesNothing) {
    Identity older_identity = Identity::generate().value();
    Identity newer_identity = Identity::generate().value();
    SendspinPairingRecord older = make_record_for(older_identity);
    SendspinPairingRecord newer = make_record_for(newer_identity);

    TestNetworkProvider network;
    auto provider = make_record_store_provider({older, newer});
    InMemoryPersistenceProvider& persistence = *provider;
    SendspinClientConfig config;
    config.name = "Repeat Playback Test Client";
    // Port 0: an ephemeral listener nothing connects to; the manager is driven directly.
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    // The test thread plays the protocol task, which owns the manager's slots.
    client.protocol_task_->stop();
    ConnectionManager& manager = *client.connection_manager_;

    auto conn = std::make_shared<HoldTestConnection>();
    conn->set_noise_handshake_result(older.server_id, PskCategory::LONG_TERM, older.psk_id);
    conn->apply_server_activate({SendspinActivity::PLAYBACK}, std::nullopt, std::nullopt,
                                std::nullopt);

    // Control: playback on the least recently used record does write the order.
    const size_t writes_before_first = record_writes(persistence);
    {
        manager.install_admitted(conn, conn->get_active_role_mask());
        manager.note_playback_activity(conn.get());
    }
    client.flush_pending_persistence();
    EXPECT_EQ(record_writes(persistence) - writes_before_first, 1u)
        << "a recency move must reach the provider";

    const size_t writes_before_repeat = record_writes(persistence);
    {
        manager.note_playback_activity(conn.get());
    }
    client.flush_pending_persistence();

    EXPECT_EQ(record_writes(persistence), writes_before_repeat)
        << "a playback that moves nothing must not write a record key";

    {
        release_admitted(manager);
    }
    client.stop();
}

// The recency move takes effect inside the locked block that applies the playback activate, not
// at the flush after it. Eviction spares only the records of open connections, and a pairing at
// capacity evicts on the protocol task whenever its pair-finalize lands; a connection that
// declares playback and closes in the same block must not leave its record looking least recently
// used in the gap before the flush.
TEST(EncryptedLifecycle, AnEvictionBeforeTheFlushSparesTheRecordJustPlayed) {
    std::vector<SendspinPairingRecord> records;
    for (size_t i = 0; i < RecordStore::MIN_MAX_RECORDS; ++i) {
        records.push_back(make_record_for(Identity::generate().value()));
    }
    const SendspinPairingRecord& played = records[0];
    const SendspinPairingRecord& next_oldest = records[1];

    TestNetworkProvider network;
    auto provider = make_record_store_provider(records);
    InMemoryPersistenceProvider& persistence = *provider;
    SendspinClientConfig config;
    config.name = "Eviction Before Flush Test Client";
    config.max_pairing_records = RecordStore::MIN_MAX_RECORDS;
    // Port 0: an ephemeral listener nothing connects to; the manager is driven directly.
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    // The test thread plays the protocol task, which owns the manager's slots.
    client.protocol_task_->stop();
    ConnectionManager& manager = *client.connection_manager_;

    auto conn = std::make_shared<HoldTestConnection>();
    conn->set_noise_handshake_result(played.server_id, PskCategory::LONG_TERM, played.psk_id);
    conn->apply_server_activate({SendspinActivity::PLAYBACK}, std::nullopt, std::nullopt,
                                std::nullopt);
    {
        manager.install_admitted(conn, conn->get_active_role_mask());
        manager.note_playback_activity(conn.get());
        // The connection closes in the same block, so its record is no longer in use. Resetting
        // the slot alone models the close: it is all open_connection_psk_ids() reads.
        release_admitted(manager);
    }

    // What a protocol-task pair-finalize at capacity does, landing before the flush.
    SendspinPairingRecord incoming = make_record_for(Identity::generate().value());
    ASSERT_TRUE(client.record_store_->store_record_superseding(incoming,
                                                               manager.open_connection_psk_ids()));

    EXPECT_TRUE(
        client.record_store_->resolve_by_psk_id(played.psk_id, PskCategory::LONG_TERM).has_value())
        << "the record that just declared playback must not be the eviction victim";
    // Control: the store was full, so something was evicted, and it was the next least recent.
    EXPECT_FALSE(client.record_store_->resolve_by_psk_id(next_oldest.psk_id, PskCategory::LONG_TERM)
                     .has_value())
        << "the pairing at capacity must evict the least recently used record";

    client.flush_pending_persistence();
    client.stop();
}

// A record change made after the last tick has no tick left to carry it: stop() flushes once on
// the way down, or the write is lost. What is asserted is the blob the next boot loads.
TEST(EncryptedLifecycle, StopFlushesARecordChangeMadeAfterTheLastTick) {
    Identity older_identity = Identity::generate().value();
    Identity newer_identity = Identity::generate().value();
    SendspinPairingRecord older = make_record_for(older_identity);
    SendspinPairingRecord newer = make_record_for(newer_identity);

    TestNetworkProvider network;
    auto provider = make_record_store_provider({older, newer});
    InMemoryPersistenceProvider& persistence = *provider;
    SendspinClientConfig config;
    config.name = "Stop Flushes Record Change Test Client";
    // Port 0: an ephemeral listener nothing connects to; the manager is driven directly.
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    const size_t writes_before = record_writes(persistence);
    // What note_playback_activity() does when a long-term connection takes playback.
    EXPECT_TRUE(client.record_store_->note_record_played(older.psk_id));
    client.request_persist();
    ASSERT_EQ(record_writes(persistence), writes_before)
        << "a change made in RAM must not write on its own";

    client.stop();

    EXPECT_EQ(record_writes(persistence) - writes_before, 1u)
        << "the change made after the last tick never reached the provider";
    EXPECT_EQ(stored_record_order(persistence), (std::vector<uint8_t>{1, 0}))
        << "the order stop() wrote must carry the move";
}

// The last-played server_id lives under its own key, so a flush that owes only that write must
// leave every record key alone: rewriting a record slot for a handoff would be an NVS erase cycle
// nothing asked for.
TEST(EncryptedLifecycle, ALastPlayedOnlyFlushWritesNoRecordKey) {
    Identity paired_identity = Identity::generate().value();
    SendspinPairingRecord paired_record = make_record_for(paired_identity);

    TestNetworkProvider network;
    auto provider = make_record_store_provider({paired_record});
    InMemoryPersistenceProvider& persistence = *provider;
    SendspinClientConfig config;
    config.name = "Last Played Only Test Client";
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    // The test thread plays the protocol task, which owns the last-played server_id.
    client.protocol_task_->stop();
    const size_t writes_before = record_writes(persistence);

    client.note_last_played_server(paired_record.server_id);
    client.flush_pending_persistence();

    EXPECT_EQ(record_writes(persistence), writes_before)
        << "a last-played write must not drag a record key along";
    // Control: the write was performed rather than dropped.
    auto last_played = persistence.blob(persistence_keys::LAST_PLAYED);
    ASSERT_TRUE(last_played.has_value());
    EXPECT_EQ(*last_played, blob_bytes(paired_identity.public_bytes))
        << "the last-played write never reached the provider";

    client.stop();
}

// connection.md "Multiple servers": the last-playback server is the one that held the admitted
// connection while 'playback' was among its activities. A group that is playing says nothing
// about the connection's activities, and every connection is sent group/update.
TEST(EncryptedLifecycle, APlayingGroupDoesNotMakeAnIdleServerTheLastPlaybackOne) {
    Identity server_identity = Identity::generate().value();

    TestNetworkProvider network;
    InMemoryPersistenceProvider persistence;
    SendspinClientConfig config;
    config.name = "Idle Group Playing Test Client";
    // Port 0: an ephemeral listener nothing connects to; the manager is driven directly.
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    // The test thread plays the protocol task, as in HoldTestClient.
    client.protocol_task_->stop();
    ConnectionManager& manager = *client.connection_manager_;

    auto conn = std::make_shared<HoldTestConnection>();
    conn->set_noise_handshake_result(server_identity.peer_id(), PskCategory::SENTINEL,
                                     /*psk_id=*/"");
    conn->apply_server_activate({}, std::nullopt, std::nullopt, std::nullopt);
    {
        manager.install_admitted(conn, conn->get_active_role_mask());
        manager.note_playback_activity(conn.get());
    }

    const std::string playing = R"({"type":"group/update","payload":{"playback_state":"playing"}})";
    conn->last_receive_time_us_.store(static_cast<uint32_t>(platform_time_us()),
                                      std::memory_order_relaxed);
    client.process_json_message(conn.get(), playing.data(), playing.size(), platform_time_us());
    // Two ticks: a write requested by the group drain would land on the tick after it.
    tick(client);
    tick(client);

    ASSERT_EQ(client.get_group_state().playback_state, SendspinPlaybackState::PLAYING)
        << "the group/update never reached the client";
    EXPECT_FALSE(persistence.blob(persistence_keys::LAST_PLAYED).has_value())
        << "a server that never declared 'playback' became the last-playback server";

    // Control: the same connection declaring 'playback' does.
    conn->apply_server_activate({SendspinActivity::PLAYBACK}, std::nullopt, std::nullopt,
                                std::nullopt);
    {
        manager.note_playback_activity(conn.get());
    }
    tick(client);
    auto last_played = persistence.blob(persistence_keys::LAST_PLAYED);
    ASSERT_TRUE(last_played.has_value());
    EXPECT_EQ(*last_played, blob_bytes(server_identity.public_bytes));

    {
        release_admitted(manager);
    }
    client.stop();
}

// A record's recency moves when the admitted connection on it declares 'playback', the same event
// that makes a server the last-playback one (connection.md "Multiple servers"), and not on an
// idle activate: a server that only holds a connection must not outlive one the device is played
// from. Driven through note_playback_activity(), which process_activate_event() and the promotion
// scan both call.
TEST(EncryptedLifecycle, OnlyPlaybackOnTheAdmittedConnectionMovesRecency) {
    struct Row {
        const char* name;
        std::vector<SendspinActivity> activities;
        bool admitted;
        std::vector<uint8_t> expected_order;
    };
    const Row rows[] = {
        {"idle admitted connection", {}, true, {0, 1}},
        {"playback on a connection that is not the admitted one", {SendspinActivity::PLAYBACK},
         false, {0, 1}},
        // Control: the least recently used record moves behind the other.
        {"playback on the admitted connection", {SendspinActivity::PLAYBACK}, true, {1, 0}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        Identity older_identity = Identity::generate().value();
        Identity newer_identity = Identity::generate().value();
        SendspinPairingRecord older = make_record_for(older_identity);
        SendspinPairingRecord newer = make_record_for(newer_identity);

        TestNetworkProvider network;
        auto provider = make_record_store_provider({older, newer});
        InMemoryPersistenceProvider& persistence = *provider;
        SendspinClientConfig config;
        config.name = "Playback Recency Test Client";
        config.server_port = 0;

        SendspinClient client(config);
        client.set_network_provider(&network);
        client.set_persistence_provider(&persistence);
        ASSERT_TRUE(client.start());
        // The test thread plays the protocol task, which owns the manager's slots.
        client.protocol_task_->stop();
        ConnectionManager& manager = *client.connection_manager_;

        auto conn = std::make_shared<HoldTestConnection>();
        conn->set_noise_handshake_result(older.server_id, PskCategory::LONG_TERM, older.psk_id);
        conn->apply_server_activate(row.activities, std::nullopt, std::nullopt, std::nullopt);
        {
            if (row.admitted) {
                manager.install_admitted(conn, conn->get_active_role_mask());
            }
            manager.note_playback_activity(conn.get());
        }
        client.flush_pending_persistence();

        EXPECT_EQ(stored_record_order(persistence), row.expected_order);
        {
            release_admitted(manager);
        }
        client.stop();
    }
}

// A record's recency moves when the admitted connection's server/activate declares 'playback',
// either in the first activate that wins promotion or in a later one on that connection.
// Admission with an idle activate moves nothing. The connecting server's record starts as the
// least recent of three, so a move shows in the persisted order. Three loopback admissions make
// this take about half a second.
TEST(EncryptedLifecycle, PersistedRecencyFollowsPlaybackActivates) {
    struct Row {
        const char* name;
        uint16_t port;
        const char* first_activities;
        bool later_playback;  // A second activate on the admitted connection declares 'playback'.
        std::vector<uint8_t> expected_order;
    };
    const Row rows[] = {
        {"idle first activate", RECENCY_IDLE_TEST_PORT, "[]", false, {0, 1, 2}},
        {"Control: playback first activate", RECENCY_PLAYBACK_TEST_PORT, R"(["playback"])", false,
         {1, 2, 0}},
        {"idle first activate, later playback activate", RECENCY_LATER_PLAYBACK_TEST_PORT, "[]",
         true, {1, 2, 0}},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        Identity server_identity = Identity::generate().value();
        SendspinPairingRecord connecting = make_record_for(server_identity);
        SendspinPairingRecord middle = make_record_for(Identity::generate().value());
        SendspinPairingRecord newest = make_record_for(Identity::generate().value());

        TestNetworkProvider network;
        auto provider = make_record_store_provider({connecting, middle, newest});
        InMemoryPersistenceProvider& persistence = *provider;
        SendspinClientConfig config;
        config.name = "Playback Recency Activate Test Client";
        config.server_port = row.port;

        SendspinClient client(config);
        // The later activate adds this role, so the client/state it triggers marks it processed.
        client.add_metadata();
        client.set_network_provider(&network);
        client.set_persistence_provider(&persistence);
        ASSERT_TRUE(client.start());

        FakeEncryptedServerOptions options;
        options.first_activities_json = row.first_activities;
        options.first_roles_json = "[]";
        FakeEncryptedServer server(server_url(row.port), std::string(NOISE_SUITE_CHACHAPOLY),
                                   server_identity, connecting.psk_id, connecting.psk, options);
        // Promotion and the record flush run in the same loop() pass.
        pump_until(client, [&] { return client.is_connected(); });

        if (row.later_playback) {
            // The admission's client/state reaches the fake on its own thread; waiting for it
            // leaves the count below to move only for the later activate.
            pump_until(client, [&] { return server.client_state_count() > 0; });
            const int states_before = server.client_state_count();
            ASSERT_TRUE(server.send_app_json(
                R"({"type":"server/activate","payload":{"activities":["playback"],)"
                R"("active_roles":["metadata@v1"]}})"));
            pump_until(client, [&] { return server.client_state_count() > states_before; });
        }

        EXPECT_EQ(stored_record_order(persistence), row.expected_order)
            << "slot 0 is the connecting server's record, least recently used first";

        client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
        pump_for(client, 100);
    }
}

// A store that cannot take the writes does not undo the RAM decisions the locked handlers already
// made: the revoked credential stays revoked for this boot (leaving it usable because flash is
// full is strictly worse).
TEST(EncryptedLifecycle, ACoalescedFlushRejectedByTheProviderKeepsTheRamState) {
    Identity played_identity = Identity::generate().value();
    Identity other_identity = Identity::generate().value();
    Identity unpairing_identity = Identity::generate().value();
    SendspinPairingRecord played_record = make_record_for(played_identity);
    SendspinPairingRecord other_record = make_record_for(other_identity);
    SendspinPairingRecord unpairing_record = make_record_for(unpairing_identity);

    TestNetworkProvider network;
    // A third record keeps the playback move real once the unpair has removed a record.
    auto provider = make_record_store_provider({played_record, other_record, unpairing_record});
    InMemoryPersistenceProvider& persistence = *provider;
    SendspinClientConfig config;
    config.name = "Rejected Coalesced Write Test Client";
    config.server_port = 0;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());
    // The test thread plays the protocol task, which owns the manager's slots.
    client.protocol_task_->stop();
    ConnectionManager& manager = *client.connection_manager_;
    reject_record_saves(persistence);

    HoldTestConnection conn;
    conn.set_noise_handshake_result(unpairing_record.server_id, PskCategory::LONG_TERM,
                                    unpairing_record.psk_id);
    {
        // What note_playback_activity() does when a long-term connection takes playback.
        EXPECT_TRUE(client.record_store_->note_record_played(played_record.psk_id));
        client.request_persist();
        manager.handle_server_unpair(&conn);
    }

    client.flush_pending_persistence();

    EXPECT_FALSE(client.record_store_
                     ->resolve_by_psk_id(unpairing_record.psk_id, PskCategory::LONG_TERM)
                     .has_value())
        << "a rejected write must not resurrect the revoked record for this boot";
    EXPECT_EQ(client.record_store_->records_.back().record.psk_id, played_record.psk_id)
        << "a rejected write must not undo the recency move for this boot";
    // ...and the provider still holds what it accepted last, which is what a reboot loads.
    EXPECT_EQ(persisted_psk_ids(persistence).size(), 3u)
        << "a rejected write must not change what the next boot loads";
    EXPECT_EQ(stored_record_order(persistence), (std::vector<uint8_t>{0, 1, 2}));

    client.stop();
}

// The revocation itself is not deferred, only its blob write. handle_server_unpair() erases the
// record in RAM, so a Noise re-handshake on the revoked psk_id, which resolves against the store
// on the protocol task right behind the unpair, misses it from that instant rather than for as
// long as the main loop takes to flush the writes (an NVS commit each, tens of milliseconds, on
// ESP).
//
// Driving the handler directly is what pins that: the resolve below runs before any flush, which
// is where an erase deferred to the flush would still be resolvable.
TEST(EncryptedLifecycle, UnpairRevokesTheRecordBeforeTheWriteIsFlushed) {
    HoldTestClient bundle("Unpair Revocation Window Test Client");
    SendspinClient& client = bundle.client_ref();
    ConnectionManager& manager = *client.connection_manager_;

    SendspinPairingRecord record;
    record.psk.fill(0x3C);
    record.psk_id = psk_id_for(record.psk);
    record.server_id = test_peer_id("unpair-window-server");
    ASSERT_TRUE(client.record_store_->store_record_superseding(record, {}));

    HoldTestConnection conn;
    conn.set_noise_handshake_result(record.server_id, PskCategory::LONG_TERM, record.psk_id);
    manager.handle_server_unpair(&conn);
    // The re-handshake's lookup, on the protocol task (this thread) right behind the handler.
    const std::optional<ResolvedPsk> resolved =
        client.record_store_->resolve_by_psk_id(record.psk_id, PskCategory::LONG_TERM);
    EXPECT_FALSE(resolved.has_value())
        << "the revoked record still resolved a handshake before the write was flushed";

    client.flush_pending_persistence();
}

// An unpaired session has no record to revoke, so server/unpair on one is ignored outright: it
// must not drop the session and must not touch stored records (messaging.md "server/unpair": if the
// session is unpaired, ignore the message).
TEST(EncryptedLifecycle, UnpairOnAnUnpairedSessionChangesNothing) {
    Identity sentinel_identity = Identity::generate().value();
    Identity paired_identity = Identity::generate().value();
    SendspinPairingRecord paired_record = make_record_for(paired_identity);

    TestNetworkProvider network;
    auto provider = make_record_store_provider({paired_record});
    InMemoryPersistenceProvider& persistence = *provider;
    SendspinClientConfig config;
    config.name = "Unpair Sentinel Test Client";
    config.server_port = UNPAIR_SENTINEL_TEST_PORT;

    SendspinClient client(config);
    client.set_unpaired_access_enabled(true);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

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
    EXPECT_EQ(persisted_psk_ids(persistence), std::vector<std::string>{paired_record.psk_id});

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

// A persistence provider whose record writes park until the test releases it, standing in for an
// NVS commit of tens of milliseconds. It serves the peer's long-term record behind a more recent
// one, so the peer resolves to PskCategory::LONG_TERM and its playback activate moves the recency
// order, which reaches the flush's persist_records().
class BlockingRecordWriteProvider : public SendspinPersistenceProvider {
public:
    explicit BlockingRecordWriteProvider(SendspinPairingRecord record)
        : records_{std::move(record), make_client_record("server-more-recent")} {}

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (!is_record_key(key)) {
            return std::nullopt;
        }
        return seeded_record_blob(this->records_, key);
    }

    bool save_blob(const std::string& key, const uint8_t* /*data*/, size_t /*len*/) override {
        if (!is_record_key(key)) {
            return true;  // Keys other than the record slots must not park the tick.
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

// The lifecycle handlers change RAM under conn_ptr_mutex_ and leave the provider write to
// SendspinClient::flush_pending_persistence(), which holds no lock. Consumer threads reading the
// connection and the protocol task's server/pair-finalize handler take the same mutex, and on ESP
// the write is an NVS commit that stalls code running from flash for tens of milliseconds.
//
// The provider above holds that whole window open inside the persist_records() the flush after
// the first activate performs.
// A get_server_information() issued in the window must still return. It is waited on with no timeout, so a regression hangs rather than turning a
// loaded runner into a failure, and the watchdog in tests/main.cpp names the test.
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
        (void)client.get_server_information();
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

// pairing.md "Unpaired Access" on one live client. Turning the setting on restarts an idle
// unpaired session so its server reconnects and reads the new value in the hello; turning it off
// closes the session that came back with playback, since only the setting was admitting it.
TEST(EncryptedLifecycle, TogglingUnpairedAccessBringsTheUnpairedSessionInLine) {
    TestNetworkProvider network;
    InMemoryPersistenceProvider persistence;
    SendspinClientConfig config;
    config.name = "Unpaired Toggle Test Client";
    config.server_port = UNPAIRED_TOGGLE_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    Identity identity = Identity::generate().value();
    FakeEncryptedServerOptions idle;
    idle.first_activities_json = R"([])";
    idle.first_roles_json = R"([])";
    FakeEncryptedServer held(server_url(UNPAIRED_TOGGLE_TEST_PORT),
                             std::string(NOISE_SUITE_CHACHAPOLY), identity,
                             std::string(SENTINEL_PSK_ID), SENTINEL_PSK, idle);
    pump_until(client, [&] { return client.is_connected(); });
    ASSERT_EQ(held.hello_unpaired_access(), std::optional<bool>(false));

    client.set_unpaired_access_enabled(true);
    EXPECT_TRUE(client.is_unpaired_access_enabled());
    pump_until(client, [&] { return held.closed(); });
    EXPECT_EQ(held.goodbye_reason(), std::optional<std::string>("restart"));

    FakeEncryptedServer playing(server_url(UNPAIRED_TOGGLE_TEST_PORT),
                                std::string(NOISE_SUITE_CHACHAPOLY), identity,
                                std::string(SENTINEL_PSK_ID), SENTINEL_PSK);
    pump_until(client, [&] { return client.is_connected(); });
    EXPECT_EQ(playing.hello_unpaired_access(), std::optional<bool>(true));

    // Setting the current value is not a change. Must-not-happen window: a restart would close
    // the session within a tick of the call.
    client.set_unpaired_access_enabled(true);
    pump_for(client, 300);
    EXPECT_FALSE(playing.closed()) << "re-setting the current value restarted the session";

    client.set_unpaired_access_enabled(false);
    EXPECT_FALSE(client.is_unpaired_access_enabled());
    pump_until(client, [&] { return playing.closed(); });
    EXPECT_EQ(playing.goodbye_reason(), std::optional<std::string>("pairing_required"));
    EXPECT_FALSE(client.is_connected());

    pump_for(client, 100);
}

// Control for the test above: a paired session never depends on the setting, and a session in a
// pairing attempt is left to finish it rather than restarted.
TEST(EncryptedLifecycle, UnpairedAccessChangesLeavePairedAndPairingSessionsAlone) {
    TestNetworkProvider network;
    PairingCapturePersistenceProvider persistence;
    Identity server_identity = Identity::generate().value();
    PairedPeer long_term_peer = make_paired_peer();
    long_term_peer.record.server_id = server_identity.peer_id();
    persistence.set_seeded_long_term_record(long_term_peer.record);
    const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xD1);

    SendspinClientConfig config;
    config.name = "Unpaired Toggle Control Test Client";
    config.server_port = UNPAIRED_TOGGLE_CONTROL_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    {
        FakeEncryptedServer paired(server_url(UNPAIRED_TOGGLE_CONTROL_TEST_PORT),
                                   std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                   long_term_peer.record.psk_id, long_term_peer.psk);
        pump_until(client, [&] { return client.is_connected(); });

        client.set_unpaired_access_enabled(true);
        client.set_unpaired_access_enabled(false);
        // Must-not-happen window: a close would follow within a tick of either call.
        pump_for(client, 300);
        EXPECT_FALSE(paired.closed()) << "a paired session was closed by an unpaired-access change";
    }
    pump_until(client, [&] { return !client.is_connected(); });

    FakeEncryptedServerOptions pairing_options;
    pairing_options.first_activities_json = R"(["pairing"])";
    pairing_options.first_roles_json = R"([])";
    pairing_options.first_pairing_method = "pairing_psk";
    pairing_options.psk_category = "pr";
    pairing_options.withhold_pair_finalize_ack = true;
    FakeEncryptedServer pairing(server_url(UNPAIRED_TOGGLE_CONTROL_TEST_PORT),
                                std::string(NOISE_SUITE_CHACHAPOLY), server_identity,
                                pairing_psk.psk_id, pairing_psk.psk, pairing_options);
    pump_until(client, [&] { return pairing.pair_init().has_value(); });

    client.set_unpaired_access_enabled(true);
    pump_for(client, 300);
    EXPECT_FALSE(pairing.closed()) << "enabling unpaired access restarted a pairing attempt";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// A session still proving itself has already sent the hello that carries the old value, so
// enabling unpaired access restarts it as it does an admitted one, unless it connected on the
// Pairing PSK: such a session is most likely about to declare pairing, and a restart would cost
// that attempt. This pins the not-yet-activated half;
// the activated case is the current-slot tests'.
TEST(EncryptedLifecycle, EnablingUnpairedAccessRestartsAnUnpairedSessionStillInTheNursery) {
    struct Row {
        const char* name;
        uint16_t port;
        bool pairing_psk;  // Connect on the Pairing PSK rather than the Sentinel PSK.
        bool expect_restart;
    };
    const Row rows[] = {
        // Control: the setting's own target, a server that read the old value and has not
        // activated yet.
        {"Control: Sentinel PSK", UNPAIRED_TOGGLE_NURSERY_TEST_PORT, false, true},
        {"Pairing PSK", UNPAIRED_TOGGLE_NURSERY_PAIRING_TEST_PORT, true, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        TestNetworkProvider network;
        PairingCapturePersistenceProvider persistence;
        const SendspinPairingPsk pairing_psk = seed_pairing_psk(persistence, 0xD2);
        SendspinClientConfig config;
        config.name = "Unpaired Toggle Nursery Test Client";
        config.server_port = row.port;

        SendspinClient client(config);
        client.set_network_provider(&network);
        client.set_persistence_provider(&persistence);
        ASSERT_TRUE(client.start());

        FakeEncryptedServerOptions options;
        options.suppress_activate = true;
        if (row.pairing_psk) {
            options.psk_category = "pr";
        }
        FakeEncryptedServer server(
            server_url(row.port), std::string(NOISE_SUITE_CHACHAPOLY), Identity::generate().value(),
            row.pairing_psk ? pairing_psk.psk_id : std::string(SENTINEL_PSK_ID),
            row.pairing_psk ? pairing_psk.psk : SENTINEL_PSK, options);
        pump_until(client, [&] { return server.client_hello_count() == 1; });

        client.set_unpaired_access_enabled(true);
        if (row.expect_restart) {
            pump_until(client, [&] { return server.closed(); });
            EXPECT_EQ(server.goodbye_reason(), std::optional<std::string>("restart"));
        } else {
            // Must-not-happen window: a restart would close the session within a tick of the
            // call.
            pump_for(client, 300);
            EXPECT_FALSE(server.closed())
                << "enabling unpaired access restarted a pairing-PSK session awaiting activation";
            client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
        }

        pump_for(client, 100);
    }
}

// Enabling unpaired access keeps a connect_to() session open.
TEST(EncryptedLifecycle, EnablingUnpairedAccessKeepsAnOutboundUnpairedSession) {
    TestNetworkProvider network;
    InMemoryPersistenceProvider persistence;
    SendspinClientConfig config;
    config.name = "Unpaired Toggle Outbound Test Client";
    config.server_port = UNPAIRED_TOGGLE_OUTBOUND_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    FakeOutboundEncryptedServer server(UNPAIRED_TOGGLE_OUTBOUND_PORT,
                                       std::string(NOISE_SUITE_CHACHAPOLY),
                                       Identity::generate().value(), std::string(SENTINEL_PSK_ID),
                                       SENTINEL_PSK, R"({"activities":[],"active_roles":[]})");
    ASSERT_TRUE(server.listen());
    server.start();
    client.connect_to(server_url(UNPAIRED_TOGGLE_OUTBOUND_PORT));
    pump_until(client, [&] { return client.is_connected(); });

    client.set_unpaired_access_enabled(true);
    // Must-not-happen window: a restart would close the session within a tick of the call.
    pump_for(client, 300);
    EXPECT_TRUE(client.is_connected());
    EXPECT_FALSE(server.goodbye_reason().has_value());

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// Enabling unpaired access does not restart a connection between a re-handshake and the
// activation that follows it.
TEST(EncryptedLifecycle, UnpairedAccessChangesWaitOutARehandshake) {
    TestNetworkProvider network;
    InMemoryPersistenceProvider persistence;
    SendspinClientConfig config;
    config.name = "Unpaired Toggle Rekey Test Client";
    config.server_port = UNPAIRED_TOGGLE_REKEY_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    ASSERT_TRUE(client.start());

    FakeEncryptedServerOptions options;
    options.suppress_activate = true;  // The post-rekey activate is the one that never comes.
    FakeEncryptedServer server(server_url(UNPAIRED_TOGGLE_REKEY_TEST_PORT),
                               std::string(NOISE_SUITE_CHACHAPOLY), Identity::generate().value(),
                               std::string(SENTINEL_PSK_ID), SENTINEL_PSK, options);
    pump_until(client, [&] { return server.client_hello_count() > 0; });
    ASSERT_TRUE(server.send_app_json(
        R"({"type":"server/activate","payload":{"activities":[],"active_roles":[]}})"));
    pump_until(client, [&] { return client.is_connected(); });

    ASSERT_TRUE(server.trigger_rehandshake(std::string(SENTINEL_PSK_ID), SENTINEL_PSK));
    pump_until(client, [&] { return !client.is_connected(); });

    client.set_unpaired_access_enabled(true);
    // Must-not-happen window: a restart would close the session within a tick of the call.
    pump_for(client, 300);
    EXPECT_FALSE(server.closed()) << "a connection awaiting its post-rekey activation was closed";

    client.disconnect(SendspinGoodbyeReason::SHUTDOWN);
    pump_for(client, 100);
}

// pairing.md "Unpaired Access": the device decides the setting. It is off until
// set_unpaired_access_enabled() turns it on, which works at any time, before the first start() and
// while stopped included; the next start() advertises and admits against the current value. The
// library persists none of it.
TEST(EncryptedLifecycle, UnpairedAccessIsOffUntilSetAndIsNeverPersisted) {
    TestNetworkProvider network;
    InMemoryPersistenceProvider persistence;
    const Identity identity = Identity::generate().value();

    // An unpaired server declaring playback: admitted only while unpaired access is on.
    // Every call follows a start().
    auto expect_unpaired_playback = [&](SendspinClient& client, bool admitted) {
        FakeEncryptedServer server(server_url(UNPAIRED_TOGGLE_STOPPED_TEST_PORT),
                                   std::string(NOISE_SUITE_CHACHAPOLY), identity,
                                   std::string(SENTINEL_PSK_ID), SENTINEL_PSK);
        pump_until(client, [&] { return client.is_connected() || server.closed(); });
        EXPECT_EQ(client.is_connected(), admitted);
        if (!admitted) {
            EXPECT_EQ(server.goodbye_reason(), std::optional<std::string>("pairing_required"));
        }
        EXPECT_EQ(server.hello_unpaired_access(), std::optional<bool>(admitted));
        client.stop();
    };

    SendspinClientConfig config;
    config.name = "Unpaired Access Setter Test Client";
    config.server_port = UNPAIRED_TOGGLE_STOPPED_TEST_PORT;

    SendspinClient client(config);
    client.set_network_provider(&network);
    client.set_persistence_provider(&persistence);
    EXPECT_FALSE(client.is_unpaired_access_enabled());
    ASSERT_TRUE(client.start());
    {
        SCOPED_TRACE("off with no call");
        expect_unpaired_playback(client, false);
    }
    // Control: the provider does record the library's own writes.
    EXPECT_GT(persistence.save_attempts(persistence_keys::KEYPAIR), 0);

    size_t saves = persistence.saved_keys().size();
    client.set_unpaired_access_enabled(true);
    EXPECT_EQ(persistence.saved_keys().size(), saves) << "the setter persisted something";
    ASSERT_TRUE(client.start());
    {
        SCOPED_TRACE("the setter while stopped");
        expect_unpaired_playback(client, true);
    }

    SendspinClient fresh(config);
    fresh.set_network_provider(&network);
    fresh.set_persistence_provider(&persistence);
    saves = persistence.saved_keys().size();
    fresh.set_unpaired_access_enabled(true);
    EXPECT_EQ(persistence.saved_keys().size(), saves) << "the setter persisted something";
    EXPECT_TRUE(fresh.is_unpaired_access_enabled());
    ASSERT_TRUE(fresh.start());
    {
        SCOPED_TRACE("the setter before the first start()");
        expect_unpaired_playback(fresh, true);
    }

    // Only state the library generates or learns reaches the provider.
    for (const std::string& key : persistence.saved_keys()) {
        EXPECT_TRUE(key == persistence_keys::KEYPAIR || key == persistence_keys::PAIRING_PSK ||
                    key == persistence_keys::LAST_PLAYED || is_record_key(key))
            << "unexpected persisted key " << key;
    }
}
