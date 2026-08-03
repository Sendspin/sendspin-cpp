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

// Phase 8d integration harness: drives ConnectionManager's PIN pairing state machine
// end-to-end for both dynamic PIN and static PIN, including the abort / cleanup /
// connection-loss paths that the Phase 8b/8c unit tests could not reach (they only covered
// wire parse/format, the lockout counter, CPace round-trips, and the client/hello descriptor).
//
// The device under test is the CPace RESPONDER; the "server" side is simulated in-test with
// a CPace INITIATOR (see cpace.h). A FakeConnection (adapted from TestConnection in
// tests/test_noise_transport.cpp) stands in for the transport: it reports a canned Noise
// handshake hash while leaving the Noise session unset, so SendspinConnection::send_app_json
// emits raw JSON via send_text_message, which this file parses directly with ArduinoJson.
//
// Server-to-client pairing messages are injected via ConnectionManager's public
// schedule_pin_pairing_message() / schedule_pair_abort() / schedule_pairing_window_confirm()
// APIs followed by SendspinClient::loop() -- the same entry points process_json_message() uses
// on the network thread -- so these tests exercise the real deferred-event + main-loop path.
// Listener callbacks are NOT fired directly by ConnectionManager; they are queued into
// SendspinClient::EventState and drained by SendspinClient::loop() after
// connection_manager_->loop() returns, so every scenario below calls client.loop() and asserts
// on the RecordingListener rather than on ConnectionManager state directly.

#include "connection.h"
#include "connection_manager.h"
#include "crypto/cpace.h"
#include "crypto/pin.h"
#include "platform/base64.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/types.h"

#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local convenience

namespace {

// =============================================================================
// FakeConnection: minimal SendspinConnection stand-in (D2)
// =============================================================================

/// @brief Concrete SendspinConnection that captures outbound frames and reports a canned
/// Noise handshake hash without ever installing a real Noise session. Adapted from
/// TestConnection in tests/test_noise_transport.cpp; kept as a separate copy per the brief
/// (that file's copy is not to be disturbed).
class FakeConnection : public SendspinConnection {
public:
    FakeConnection() = default;
    ~FakeConnection() override = default;

    // -- Interface stubs --

    void start() override {}
    void loop() override {}
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override {
        this->last_disconnect_reason_ = reason;
        this->disconnect_count_++;
        if (on_complete) {
            on_complete();
        }
    }
    bool is_connected() const override { return this->connected_; }

    SsErr send_text_message(const std::string& msg, SendCompleteCallback cb,
                            bool /*allow_before_hello*/) override {
        sent_text_.push_back(msg);
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }

    SsErr send_binary_message(const uint8_t* data, size_t len, SendCompleteCallback cb,
                              bool /*allow_before_hello*/) override {
        sent_binary_.push_back(std::vector<uint8_t>(data, data + len));
        if (cb) {
            cb(true);
        }
        return SsErr::OK;
    }

    bool send_time_message() override { return true; }

    // -- Test-only seam: canned handshake hash without a Noise session (D1, seam #1) --

    /// Report a fixed 32-byte handshake hash while leaving noise_session_ (and therefore
    /// noise_active_) unset, so send_app_json() routes through send_text_message() as raw
    /// JSON. Overrides the now-virtual base implementation (see connection.h).
    std::optional<std::array<uint8_t, 32>> get_noise_handshake_hash() const override {
        return this->canned_hash_;
    }

    void set_canned_hash(const std::array<uint8_t, 32>& hash) { this->canned_hash_ = hash; }

    void set_connected(bool connected) { this->connected_ = connected; }

    // -- Accumulated outgoing messages / disconnect bookkeeping --

    std::vector<std::string> sent_text_;
    std::vector<std::vector<uint8_t>> sent_binary_;
    int disconnect_count_{0};
    std::optional<SendspinGoodbyeReason> last_disconnect_reason_;

private:
    std::optional<std::array<uint8_t, 32>> canned_hash_{std::array<uint8_t, 32>{}};
    bool connected_{true};
};

// =============================================================================
// RecordingListener: captures every pairing-related callback, in order (D2)
// =============================================================================

enum class PairingEventKind {
    STARTED,
    SUCCEEDED,
    FAILED,
    DISPLAY_PIN,
    CLEAR_PIN,
    OPEN_WINDOW,
    CLOSE_WINDOW,
};

struct PairingEvent {
    PairingEventKind kind;
    std::string server_id;                            // STARTED / SUCCEEDED / FAILED
    SendspinPairAbortReason reason{};                  // FAILED
    std::string pin;                                   // DISPLAY_PIN
};

class RecordingListener : public SendspinClientListener {
public:
    void on_pairing_started(const std::string& server_id) override {
        this->events_.push_back({PairingEventKind::STARTED, server_id, {}, {}});
    }
    void on_pairing_succeeded(const std::string& server_id) override {
        this->events_.push_back({PairingEventKind::SUCCEEDED, server_id, {}, {}});
    }
    void on_pairing_failed(const std::string& server_id, SendspinPairAbortReason reason) override {
        this->events_.push_back({PairingEventKind::FAILED, server_id, reason, {}});
    }
    void on_display_pairing_pin(const std::string& pin) override {
        this->events_.push_back({PairingEventKind::DISPLAY_PIN, {}, {}, pin});
    }
    void on_clear_pairing_pin() override {
        this->events_.push_back({PairingEventKind::CLEAR_PIN, {}, {}, {}});
    }
    void on_open_pairing_window() override {
        this->events_.push_back({PairingEventKind::OPEN_WINDOW, {}, {}, {}});
    }
    void on_close_pairing_window() override {
        this->events_.push_back({PairingEventKind::CLOSE_WINDOW, {}, {}, {}});
    }

    [[nodiscard]] int count(PairingEventKind kind) const {
        int n = 0;
        for (const auto& e : this->events_) {
            if (e.kind == kind) {
                ++n;
            }
        }
        return n;
    }

    [[nodiscard]] bool fired(PairingEventKind kind) const { return this->count(kind) > 0; }

    /// Returns the index of the first event of `kind`, or -1 if never fired. Used to assert
    /// ordering between two callbacks (e.g. display-pin must precede clear-pin).
    [[nodiscard]] int first_index_of(PairingEventKind kind) const {
        for (size_t i = 0; i < this->events_.size(); ++i) {
            if (this->events_[i].kind == kind) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    [[nodiscard]] std::optional<std::string> last_displayed_pin() const {
        for (auto it = this->events_.rbegin(); it != this->events_.rend(); ++it) {
            if (it->kind == PairingEventKind::DISPLAY_PIN) {
                return it->pin;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SendspinPairAbortReason> last_failed_reason() const {
        for (auto it = this->events_.rbegin(); it != this->events_.rend(); ++it) {
            if (it->kind == PairingEventKind::FAILED) {
                return it->reason;
            }
        }
        return std::nullopt;
    }

    std::vector<PairingEvent> events_;
};

// =============================================================================
// Minimal fake providers (D2)
// =============================================================================

/// Network provider that always reports "not ready", so ConnectionManager::loop() never
/// starts the real WebSocket server -- these tests inject connections directly and never
/// exercise the transport or accept path.
class FakeNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override { return false; }
};

/// Persistence provider that does nothing (in-memory RecordStore defaults are sufficient for
/// these tests: shared-PSK fallback record is generated fresh, no config restrictions).
class FakePersistenceProvider : public SendspinPersistenceProvider {};

// =============================================================================
// JSON helpers for asserting on captured outbound frames
// =============================================================================

/// Parse a captured outbound JSON string. Fails the calling test via ASSERT semantics through
/// the returned bool so callers can `ASSERT_TRUE(parse_json(...))`.
bool parse_json(const std::string& json, JsonDocument& doc, JsonObject& root) {
    if (deserializeJson(doc, json)) {
        return false;
    }
    root = doc.as<JsonObject>();
    return true;
}

/// Return the last captured frame's "type" field, or "" if sent_text_ is empty.
std::string last_frame_type(const std::vector<std::string>& sent_text) {
    if (sent_text.empty()) {
        return "";
    }
    JsonDocument doc;
    JsonObject root;
    if (!parse_json(sent_text.back(), doc, root)) {
        return "";
    }
    return std::string(root["type"] | "");
}

/// Return true if any captured frame has the given type.
bool any_frame_of_type(const std::vector<std::string>& sent_text, const std::string& type) {
    for (const auto& s : sent_text) {
        JsonDocument doc;
        JsonObject root;
        if (parse_json(s, doc, root) && std::string(root["type"] | "") == type) {
            return true;
        }
    }
    return false;
}

/// Return the payload.reason field of the last pair/abort frame, or "" if none was sent.
std::string last_pair_abort_reason(const std::vector<std::string>& sent_text) {
    for (auto it = sent_text.rbegin(); it != sent_text.rend(); ++it) {
        JsonDocument doc;
        JsonObject root;
        if (parse_json(*it, doc, root) && std::string(root["type"] | "") == "pair/abort") {
            return std::string(root["payload"]["reason"] | "");
        }
    }
    return "";
}

// =============================================================================
// Server-side ("stand-in initiator") frame builders, mirroring test_dynamic_pin.cpp
// =============================================================================

/// Build the SID CPace expects: "sendspin-pair-pake-v1" (21 bytes, no NUL) || 32-byte hash.
std::vector<uint8_t> make_sid(const std::array<uint8_t, 32>& handshake_hash) {
    static constexpr char PAKE_SID_LABEL[] = "sendspin-pair-pake-v1";
    std::vector<uint8_t> sid;
    sid.insert(sid.end(), PAKE_SID_LABEL, PAKE_SID_LABEL + sizeof(PAKE_SID_LABEL) - 1);
    sid.insert(sid.end(), handshake_hash.begin(), handshake_hash.end());
    return sid;
}

std::vector<uint8_t> ascii_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

/// One side of a simulated server: a CPace INITIATOR plus the nonce/hash bookkeeping needed to
/// answer either the dynamic-PIN or static-PIN device flow.
struct ServerStandIn {
    CPace initiator;
    std::array<uint8_t, 32> nonce_a{};
    std::string prs_pin;

    /// Start the initiator for a given PRS (PIN ASCII bytes) and SID (label || handshake hash).
    bool start(const std::string& pin, const std::array<uint8_t, 32>& handshake_hash) {
        this->prs_pin = pin;
        const std::vector<uint8_t> empty;
        return this->initiator.start(CPaceRole::INITIATOR, ascii_bytes(pin), make_sid(handshake_hash),
                                     empty, empty, empty);
    }
};

}  // namespace

// =============================================================================
// Test fixture (D2): builds a SendspinClient, injects a FakeConnection as
// current_connection_, and provides helpers to drive the PIN state machine.
// =============================================================================

class PinStateMachineTest : public ::testing::Test {
protected:
    void SetUp() override {
        SendspinClientConfig config;
        config.name = "PinStateMachineTestDevice";
        this->client_ = std::make_unique<SendspinClient>(config);
        this->client_->set_listener(&this->listener_);
        this->client_->set_network_provider(&this->network_provider_);
        this->client_->set_persistence_provider(&this->persistence_provider_);
        ASSERT_TRUE(this->client_->start_server());
    }

    /// Inject a fresh FakeConnection as current_connection_, with the given server_id and
    /// selected pair method already applied (as if a server/activate had been admitted), and
    /// pairing_in_progress cleared. Returns a raw pointer valid for the test's lifetime.
    ///
    /// The test fixture also keeps its own shared_ptr (injected_conn_) alive independently of
    /// ConnectionManager::current_connection_: abort/cleanup paths (local_abort_pin_pairing,
    /// handle_pair_abort, on_connection_lost) move-and-drop ConnectionManager's slot as part of
    /// tearing the connection down, which would otherwise destroy the FakeConnection out from
    /// under the test (its sent_text_ / disconnect_count_ are asserted AFTER those paths run).
    FakeConnection* inject_current_connection(const std::string& server_id,
                                              SendspinPairMethod method) {
        auto conn = std::make_shared<FakeConnection>();
        conn->set_noise_handshake_result(server_id, PskCategory::SENTINEL, /*psk_id=*/"");
        conn->apply_server_activate({SendspinActivity::PAIRING}, std::nullopt, method);
        conn->set_pairing_in_progress(false);
        FakeConnection* raw = conn.get();
        this->injected_conn_ = conn;
        {
            std::lock_guard<std::mutex> lock(this->client_->connection_manager_->conn_ptr_mutex_);
            this->client_->connection_manager_->current_connection_ = conn;
        }
        return raw;
    }

    /// Inject a fresh FakeConnection as current_connection_ WITHOUT applying any activate (no
    /// activities, no selected pair method, first_activate_received() still false). Unlike
    /// inject_current_connection, this lets a test drive the real ServerActivateEvent
    /// arbitration path via post_activate() + loop(), so the first-vs-subsequent activate
    /// handling in ConnectionManager::loop() is exercised end to end (not bypassed through the
    /// handle_enter_pairing() friend seam).
    FakeConnection* inject_provisional_current_connection(const std::string& server_id) {
        auto conn = std::make_shared<FakeConnection>();
        conn->set_noise_handshake_result(server_id, PskCategory::SENTINEL, /*psk_id=*/"");
        FakeConnection* raw = conn.get();
        this->injected_conn_ = conn;
        {
            std::lock_guard<std::mutex> lock(this->client_->connection_manager_->conn_ptr_mutex_);
            this->client_->connection_manager_->current_connection_ = conn;
        }
        return raw;
    }

    /// Drive handle_enter_pairing() for the injected current connection via the same call
    /// ConnectionManager::loop() makes for a first pairing activate. Called directly (through
    /// the friend seam) rather than replaying the full activate-arbitration path, per the
    /// brief's "if intractable" fallback -- arbitration itself is exercised by test_admission.cpp
    /// and is not the subject of this harness.
    void enter_pairing(SendspinConnection* conn) {
        this->client_->connection_manager_->handle_enter_pairing(conn);
    }

    /// Simulate the connection being lost (network thread reporting a close/disconnect),
    /// exercising ConnectionManager::on_connection_lost() -- the Phase 8c regression path.
    void simulate_connection_lost(SendspinConnection* conn) {
        this->client_->connection_manager_->on_connection_lost(conn);
    }

    /// Returns the shared_ptr backing the injected current connection, for building
    /// ServerPairingMessageEvent / PairAbortEvent conn fields (which require a shared_ptr).
    /// Backed by the fixture's own owning reference (see inject_current_connection), not
    /// ConnectionManager::current_connection_, so it stays valid even after an abort/cleanup
    /// path has released ConnectionManager's slot.
    std::shared_ptr<SendspinConnection> current_connection_sp() { return this->injected_conn_; }

    /// Schedule a server-to-client PIN pairing message for deferred processing (the same public
    /// entry point process_json_message() uses on the network thread), without pumping loop().
    void schedule_pin_message(ServerPairingMessageEvent event) {
        this->client_->connection_manager_->schedule_pin_pairing_message(std::move(event));
    }

    /// Schedule a pair/abort event for deferred processing, without pumping loop().
    void schedule_abort(PairAbortEvent event) {
        this->client_->connection_manager_->schedule_pair_abort(std::move(event));
    }

    /// Schedule a server/activate event on the injected current connection for deferred
    /// processing, without pumping loop(). Drives the real activate-arbitration path in
    /// ConnectionManager::loop() (trust check, apply_server_activate, then either the
    /// already-admitted branch's leftover-activate handling or on_handshake_complete()) --
    /// the same entry point process_json_message() uses on the network thread.
    void post_activate(std::vector<SendspinActivity> activities,
                       std::optional<std::vector<std::string>> active_roles,
                       std::optional<SendspinPairMethod> selected_pair_method) {
        ServerActivateEvent event;
        event.conn = this->current_connection_sp();
        event.activities = std::move(activities);
        event.active_roles = std::move(active_roles);
        event.selected_pair_method = selected_pair_method;
        this->client_->connection_manager_->schedule_activate(std::move(event));
    }

    RecordStore& record_store() { return *this->client_->record_store_; }

    std::unique_ptr<SendspinClient> client_;
    RecordingListener listener_;
    FakeNetworkProvider network_provider_;
    FakePersistenceProvider persistence_provider_;
    /// Keeps the last-injected FakeConnection alive independently of ConnectionManager's slot
    /// (see inject_current_connection). Only one connection is injected per test.
    std::shared_ptr<SendspinConnection> injected_conn_;
};

// =============================================================================
// Dynamic PIN: happy path
// =============================================================================

TEST_F(PinStateMachineTest, DynamicPinHappyPath) {
    FakeConnection* conn = this->inject_current_connection("server-dyn-1", SendspinPairMethod::DYNAMIC_PIN);

    this->enter_pairing(conn);
    this->client_->loop();

    // client/pair-init(commit_B) was emitted, and on_pairing_started + on_display_pairing_pin
    // have NOT fired yet (display only happens after server/pair-init supplies pin_length).
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(this->listener_.events_.front().server_id, "server-dyn-1");
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));

    // Capture nonce_B via the test seam (pin_session() is public on SendspinConnection).
    const std::array<uint8_t, 32> nonce_b = conn->pin_session().nonce_b;
    const std::array<uint8_t, 32> handshake_hash = conn->pin_session().handshake_hash;

    // ---- server/pair-init: nonce_A + pin_length ----
    std::array<uint8_t, 32> nonce_a{};
    for (size_t i = 0; i < nonce_a.size(); ++i) {
        nonce_a[i] = static_cast<uint8_t>(i + 1);
    }
    const int pin_length = 6;
    auto pin_opt = pin_derive(handshake_hash.data(), handshake_hash.size(), nonce_a.data(),
                              nonce_a.size(), nonce_b.data(), nonce_b.size(), pin_length);
    ASSERT_TRUE(pin_opt.has_value());

    auto conn_sp = this->current_connection_sp();

    ServerPairingMessageEvent pair_init_event;
    pair_init_event.conn = conn_sp;
    pair_init_event.kind = PinPairingMessageKind::PAIR_INIT;
    pair_init_event.nonce_a = nonce_a;
    pair_init_event.pin_length = pin_length;
    this->schedule_pin_message(std::move(pair_init_event));
    this->client_->loop();

    // The derived PIN must now be displayed.
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));
    EXPECT_EQ(this->listener_.last_displayed_pin(), pin_opt.value());

    // ---- Simulated server (INITIATOR) starts CPace with the same derived PIN ----
    ServerStandIn server;
    ASSERT_TRUE(server.start(pin_opt.value(), handshake_hash));

    // ---- server/pair-auth: server's public share (pake_msg_1) ----
    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = conn_sp;
    pair_auth_event.kind = PinPairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1 = server.initiator.public_share();
    this->schedule_pin_message(std::move(pair_auth_event));
    this->client_->loop();

    // Device must have emitted client/pair-auth (pake_msg_2).
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");
    JsonDocument auth_doc;
    JsonObject auth_root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), auth_doc, auth_root));
    auto pake_msg_2_b64 = std::string(auth_root["payload"]["pake_msg_2"] | "");
    auto pake_msg_2 = b64url_decode(pake_msg_2_b64);
    ASSERT_TRUE(pake_msg_2.has_value());
    ASSERT_EQ(pake_msg_2->size(), 32u);

    // Server derives against the device's share, then computes server_kc.
    ASSERT_TRUE(server.initiator.derive(pake_msg_2->data(), pake_msg_2->size()));
    auto server_kc = server.initiator.tag();
    ASSERT_TRUE(server_kc.has_value());

    // ---- server/pair-confirm: server_kc ----
    ServerPairingMessageEvent pair_confirm_event;
    pair_confirm_event.conn = conn_sp;
    pair_confirm_event.kind = PinPairingMessageKind::PAIR_CONFIRM;
    pair_confirm_event.server_kc = server_kc.value();
    this->schedule_pin_message(std::move(pair_confirm_event));
    this->client_->loop();

    // Device must emit client/pair-confirm (with client_kc + nonce_B) then client/pair-finalize.
    ASSERT_GE(conn->sent_text_.size(), 4u);
    JsonDocument confirm_doc;
    JsonObject confirm_root;
    const std::string& confirm_frame = conn->sent_text_[conn->sent_text_.size() - 2];
    ASSERT_TRUE(parse_json(confirm_frame, confirm_doc, confirm_root));
    EXPECT_STREQ(confirm_root["type"], "client/pair-confirm");
    EXPECT_TRUE(confirm_root["payload"]["client_kc"].is<const char*>());
    EXPECT_TRUE(confirm_root["payload"]["nonce_B"].is<const char*>())
        << "dynamic PIN pair-confirm must open nonce_B";
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-finalize");

    // Success callbacks: on_clear_pairing_pin fires (display -> clear ordering), and the
    // DYNAMIC_PIN failure counter is reset (was already 0, but exercise the call path by
    // checking it stays at 0 and is not locked out).
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_PIN));
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::DISPLAY_PIN),
             this->listener_.first_index_of(PairingEventKind::CLEAR_PIN));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_FALSE(this->record_store().is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));
    EXPECT_EQ(this->record_store().pin_failure_count(SendspinPairMethod::DYNAMIC_PIN), 0);
}

// =============================================================================
// Dynamic PIN: PIN mismatch (bad server_kc)
// =============================================================================

TEST_F(PinStateMachineTest, DynamicPinMismatchRecordsFailureAndAborts) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-2", SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    const std::array<uint8_t, 32> nonce_b = conn->pin_session().nonce_b;
    const std::array<uint8_t, 32> handshake_hash = conn->pin_session().handshake_hash;

    std::array<uint8_t, 32> nonce_a{};
    for (size_t i = 0; i < nonce_a.size(); ++i) {
        nonce_a[i] = static_cast<uint8_t>(i + 2);
    }
    const int pin_length = 6;
    auto pin_opt = pin_derive(handshake_hash.data(), handshake_hash.size(), nonce_a.data(),
                              nonce_a.size(), nonce_b.data(), nonce_b.size(), pin_length);
    ASSERT_TRUE(pin_opt.has_value());

    auto current_conn_sp = this->current_connection_sp();

    ServerPairingMessageEvent pair_init_event;
    pair_init_event.conn = current_conn_sp;
    pair_init_event.kind = PinPairingMessageKind::PAIR_INIT;
    pair_init_event.nonce_a = nonce_a;
    pair_init_event.pin_length = pin_length;
    this->schedule_pin_message(std::move(pair_init_event));
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));

    // Simulated server uses the CORRECT pin to complete the CPace handshake (so derive()
    // succeeds), but then sends a bogus server_kc so verify() fails (a genuine PIN mismatch,
    // as opposed to a low-order-point derive() failure).
    ServerStandIn server;
    ASSERT_TRUE(server.start(pin_opt.value(), handshake_hash));

    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = current_conn_sp;
    pair_auth_event.kind = PinPairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1 = server.initiator.public_share();
    this->schedule_pin_message(std::move(pair_auth_event));
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");

    std::array<uint8_t, 64> bogus_server_kc{};
    bogus_server_kc.fill(0xAB);

    ServerPairingMessageEvent pair_confirm_event;
    pair_confirm_event.conn = current_conn_sp;
    pair_confirm_event.kind = PinPairingMessageKind::PAIR_CONFIRM;
    pair_confirm_event.server_kc = bogus_server_kc;
    this->schedule_pin_message(std::move(pair_confirm_event));
    this->client_->loop();

    // Device must abort with pin_mismatch, record a DYNAMIC_PIN failure, and fire the failure
    // callbacks (abort-ordering regression: on_pairing_failed AND on_clear_pairing_pin both
    // survive cleanup_connection_state()).
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "pin_mismatch");
    EXPECT_EQ(this->record_store().pin_failure_count(SendspinPairMethod::DYNAMIC_PIN), 1);
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::PIN_MISMATCH);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_PIN));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::SUCCEEDED));
}

// =============================================================================
// Dynamic PIN: attempt timeout
// =============================================================================

TEST_F(PinStateMachineTest, DynamicPinAttemptTimeout) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-3", SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");

    // Force the attempt deadline into the past; the next loop() tick must detect and abort it.
    conn->pin_session().attempt_deadline_us = platform_time_us() - 1;
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "attempt_timeout");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::ATTEMPT_TIMEOUT);
    // No PIN was ever displayed for this session (timed out before server/pair-init), so
    // on_clear_pairing_pin must NOT fire (pin_displayed was never set).
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::CLEAR_PIN));
}

// =============================================================================
// Dynamic PIN: malformed server frame
// =============================================================================

TEST_F(PinStateMachineTest, DynamicPinMalformedFrameDuringSessionAborts) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-4", SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent malformed_event;
    malformed_event.conn = current_conn_sp;
    malformed_event.kind = PinPairingMessageKind::MALFORMED;
    this->schedule_pin_message(std::move(malformed_event));
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "method_not_supported");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(conn->disconnect_count_, 1);
}

TEST_F(PinStateMachineTest, DynamicPinMalformedFrameWithNoActiveSessionIsIgnored) {
    // A connection with no active PIN session (pin_session().step == IDLE) at all: a stray
    // malformed pairing frame must not tear anything down.
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-5", SendspinPairMethod::DYNAMIC_PIN);
    ASSERT_EQ(conn->pin_session().step, SendspinConnection::PinStep::IDLE);

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent malformed_event;
    malformed_event.conn = current_conn_sp;
    malformed_event.kind = PinPairingMessageKind::MALFORMED;
    this->schedule_pin_message(std::move(malformed_event));
    this->client_->loop();

    EXPECT_TRUE(conn->sent_text_.empty());
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::CLEAR_PIN));
}

// =============================================================================
// Dynamic PIN: lockout
// =============================================================================

TEST_F(PinStateMachineTest, DynamicPinLockoutBlocksNewAttempt) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-6", SendspinPairMethod::DYNAMIC_PIN);

    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD; ++i) {
        this->record_store().record_pin_failure(SendspinPairMethod::DYNAMIC_PIN);
    }
    ASSERT_TRUE(this->record_store().is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));

    this->enter_pairing(conn);
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "locked_out");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::LOCKED_OUT);
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));
    EXPECT_FALSE(any_frame_of_type(conn->sent_text_, "client/pair-init"));
}

// =============================================================================
// Static PIN: happy path
// =============================================================================

TEST_F(PinStateMachineTest, StaticPinHappyPath) {
    this->record_store().set_static_pin("13572468");

    FakeConnection* conn =
        this->inject_current_connection("server-static-1", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    // Entering static-PIN pairing surfaces the pairing-window prompt and sends NOTHING yet.
    EXPECT_TRUE(conn->sent_text_.empty());
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::DISPLAY_PIN))
        << "static PIN never displays a PIN on the device";

    const std::array<uint8_t, 32> handshake_hash = conn->pin_session().handshake_hash;

    // Operator confirms the pairing-window gesture: this must send the empty client/pair-init.
    this->client_->confirm_pairing_window();
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    JsonDocument init_doc;
    JsonObject init_root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), init_doc, init_root));
    EXPECT_STREQ(init_root["type"], "client/pair-init");
    ASSERT_TRUE(init_root["payload"].is<JsonObjectConst>());
    EXPECT_EQ(init_root["payload"].as<JsonObjectConst>().size(), 0u)
        << "static-PIN client/pair-init payload must be empty (no commit_B)";

    ServerStandIn server;
    ASSERT_TRUE(server.start("13572468", handshake_hash));

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = current_conn_sp;
    pair_auth_event.kind = PinPairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1 = server.initiator.public_share();
    this->schedule_pin_message(std::move(pair_auth_event));
    this->client_->loop();

    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");
    JsonDocument auth_doc;
    JsonObject auth_root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), auth_doc, auth_root));
    auto pake_msg_2 = b64url_decode(std::string(auth_root["payload"]["pake_msg_2"] | ""));
    ASSERT_TRUE(pake_msg_2.has_value());

    ASSERT_TRUE(server.initiator.derive(pake_msg_2->data(), pake_msg_2->size()));
    auto server_kc = server.initiator.tag();
    ASSERT_TRUE(server_kc.has_value());

    ServerPairingMessageEvent pair_confirm_event;
    pair_confirm_event.conn = current_conn_sp;
    pair_confirm_event.kind = PinPairingMessageKind::PAIR_CONFIRM;
    pair_confirm_event.server_kc = server_kc.value();
    this->schedule_pin_message(std::move(pair_confirm_event));
    this->client_->loop();

    // client/pair-confirm must carry client_kc and NO nonce_B (static PIN never opens a nonce).
    ASSERT_GE(conn->sent_text_.size(), 2u);
    JsonDocument confirm_doc;
    JsonObject confirm_root;
    const std::string& confirm_frame = conn->sent_text_[conn->sent_text_.size() - 2];
    ASSERT_TRUE(parse_json(confirm_frame, confirm_doc, confirm_root));
    EXPECT_STREQ(confirm_root["type"], "client/pair-confirm");
    EXPECT_TRUE(confirm_root["payload"]["client_kc"].is<const char*>());
    EXPECT_TRUE(confirm_root["payload"]["nonce_B"].isUnbound())
        << "static PIN pair-confirm must NOT carry nonce_B";
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-finalize");

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::OPEN_WINDOW),
             this->listener_.first_index_of(PairingEventKind::CLOSE_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_FALSE(this->record_store().is_pin_locked_out(SendspinPairMethod::STATIC_PIN));
    EXPECT_EQ(this->record_store().pin_failure_count(SendspinPairMethod::STATIC_PIN), 0);
}

// =============================================================================
// Entered from a SUBSEQUENT activate (regression)
// =============================================================================

// A device that first goes operational on an empty server/activate must still enter static-PIN
// pairing when the operator later triggers a SUBSEQUENT activate declaring [pairing]. Before the
// fix, ConnectionManager::loop() only entered pairing on the FIRST activate on an already-admitted
// connection and silently dropped a later one as an ordinary "subsequent activate", so the pairing
// window never opened. Mirrors the reference's _handle_server_activate, which runs pairing on any
// pairing activate, not only the first.
TEST_F(PinStateMachineTest, SubsequentActivateEntersStaticPinPairing) {
    this->record_store().set_static_pin("13572468");

    FakeConnection* conn = this->inject_provisional_current_connection("server-static-sub");

    // First activate: empty activities -> connection goes operational, no pairing.
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    EXPECT_TRUE(conn->sent_text_.empty());

    // Subsequent activate: [pairing] + static_pin -> must enter pairing and open the window.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::STATIC_PIN);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW))
        << "a subsequent pairing activate must open the operator pairing window";
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    EXPECT_TRUE(conn->sent_text_.empty()) << "nothing is sent until the operator confirms";

    // Confirming the window sends the empty client/pair-init, proving the flow is live.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// Same regression, dynamic-PIN flavor: a subsequent activate declaring [pairing] + dynamic_pin on
// an already-operational connection must enter pairing and send client/pair-init (commit_B)
// immediately (dynamic PIN has no operator pairing-window gesture, unlike static PIN above).
TEST_F(PinStateMachineTest, SubsequentActivateEntersDynamicPinPairing) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-dyn-sub");

    // First activate: empty activities -> connection goes operational, no pairing.
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_TRUE(conn->sent_text_.empty());

    // Subsequent activate: [pairing] + dynamic_pin -> must enter pairing.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PIN);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED))
        << "a subsequent pairing activate must start the dynamic-PIN pairing flow";
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_SERVER_PAIR_INIT);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// =============================================================================
// Static PIN: mismatch
// =============================================================================

TEST_F(PinStateMachineTest, StaticPinMismatchRecordsFailureAndAborts) {
    this->record_store().set_static_pin("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-2", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    const std::array<uint8_t, 32> handshake_hash = conn->pin_session().handshake_hash;
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");

    // Server uses the CORRECT static PIN so derive() succeeds, then lies about server_kc.
    ServerStandIn server;
    ASSERT_TRUE(server.start("13572468", handshake_hash));

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = current_conn_sp;
    pair_auth_event.kind = PinPairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1 = server.initiator.public_share();
    this->schedule_pin_message(std::move(pair_auth_event));
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");

    std::array<uint8_t, 64> bogus_server_kc{};
    bogus_server_kc.fill(0xCD);
    ServerPairingMessageEvent pair_confirm_event;
    pair_confirm_event.conn = current_conn_sp;
    pair_confirm_event.kind = PinPairingMessageKind::PAIR_CONFIRM;
    pair_confirm_event.server_kc = bogus_server_kc;
    this->schedule_pin_message(std::move(pair_confirm_event));
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "pin_mismatch");
    EXPECT_EQ(this->record_store().pin_failure_count(SendspinPairMethod::STATIC_PIN), 1);
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::PIN_MISMATCH);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::SUCCEEDED));
    // DYNAMIC_PIN's counter must be untouched (independent lockout counters).
    EXPECT_EQ(this->record_store().pin_failure_count(SendspinPairMethod::DYNAMIC_PIN), 0);
}

// =============================================================================
// Static PIN: pairing-window timeout
// =============================================================================

TEST_F(PinStateMachineTest, StaticPinWindowTimeout) {
    this->record_store().set_static_pin("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-3", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    ASSERT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    EXPECT_TRUE(conn->sent_text_.empty());

    // Force the pairing-window deadline into the past (reused as attempt_deadline_us).
    conn->pin_session().attempt_deadline_us = platform_time_us() - 1;
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "attempt_timeout");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::ATTEMPT_TIMEOUT);
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::OPEN_WINDOW),
             this->listener_.first_index_of(PairingEventKind::CLOSE_WINDOW));
}

// =============================================================================
// Static PIN: lockout independent of dynamic PIN
// =============================================================================

TEST_F(PinStateMachineTest, StaticPinLockoutIsIndependentOfDynamicPin) {
    this->record_store().set_static_pin("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-4", SendspinPairMethod::STATIC_PIN);

    for (int i = 0; i < RecordStore::PIN_LOCKOUT_THRESHOLD; ++i) {
        this->record_store().record_pin_failure(SendspinPairMethod::STATIC_PIN);
    }
    ASSERT_TRUE(this->record_store().is_pin_locked_out(SendspinPairMethod::STATIC_PIN));
    ASSERT_FALSE(this->record_store().is_pin_locked_out(SendspinPairMethod::DYNAMIC_PIN));

    this->enter_pairing(conn);
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "locked_out");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::LOCKED_OUT);
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
}

// =============================================================================
// Regression: connection loss mid-pairing (Phase 8c MAJOR)
// =============================================================================

TEST_F(PinStateMachineTest, ConnectionLossDuringStaticPairingWindowClosesWindow) {
    this->record_store().set_static_pin("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-5", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    ASSERT_FALSE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    ASSERT_TRUE(conn->pin_session().window_shown);

    // Simulate the transport dying mid-window (before the operator ever confirms).
    this->simulate_connection_lost(conn);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW))
        << "on_connection_lost must dismiss a stranded pairing-window prompt (Phase 8c MAJOR)";
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::OPEN_WINDOW),
             this->listener_.first_index_of(PairingEventKind::CLOSE_WINDOW));
}

TEST_F(PinStateMachineTest, ConnectionLossWithPinDisplayedClearsPin) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-7", SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    const std::array<uint8_t, 32> nonce_b = conn->pin_session().nonce_b;
    const std::array<uint8_t, 32> handshake_hash = conn->pin_session().handshake_hash;
    std::array<uint8_t, 32> nonce_a{};
    for (size_t i = 0; i < nonce_a.size(); ++i) {
        nonce_a[i] = static_cast<uint8_t>(i + 3);
    }
    auto pin_opt = pin_derive(handshake_hash.data(), handshake_hash.size(), nonce_a.data(),
                              nonce_a.size(), nonce_b.data(), nonce_b.size(), 6);
    ASSERT_TRUE(pin_opt.has_value());

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent pair_init_event;
    pair_init_event.conn = current_conn_sp;
    pair_init_event.kind = PinPairingMessageKind::PAIR_INIT;
    pair_init_event.nonce_a = nonce_a;
    pair_init_event.pin_length = 6;
    this->schedule_pin_message(std::move(pair_init_event));
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));
    ASSERT_FALSE(this->listener_.fired(PairingEventKind::CLEAR_PIN));
    ASSERT_TRUE(conn->pin_session().pin_displayed);

    // Connection dies while the PIN is still on screen.
    this->simulate_connection_lost(conn);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_PIN))
        << "on_connection_lost must dismiss a stranded displayed PIN";
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::DISPLAY_PIN),
             this->listener_.first_index_of(PairingEventKind::CLEAR_PIN));
}

// =============================================================================
// Regression: abort ordering survives cleanup_connection_state() (Phase 8b BLOCKER)
// =============================================================================

TEST_F(PinStateMachineTest, CurrentConnectionAbortOrderingSurvivesCleanup) {
    // A current-connection abort (pair/abort from the server) must still deliver
    // on_pairing_failed AND on_clear_pairing_pin even though cleanup_connection_state() wipes
    // the EventState pending-notification vectors -- the note_* calls in
    // ConnectionManager::handle_pair_abort() must run strictly AFTER that wipe.
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-8", SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    const std::array<uint8_t, 32> nonce_b = conn->pin_session().nonce_b;
    const std::array<uint8_t, 32> handshake_hash = conn->pin_session().handshake_hash;
    std::array<uint8_t, 32> nonce_a{};
    for (size_t i = 0; i < nonce_a.size(); ++i) {
        nonce_a[i] = static_cast<uint8_t>(i + 4);
    }
    auto pin_opt = pin_derive(handshake_hash.data(), handshake_hash.size(), nonce_a.data(),
                              nonce_a.size(), nonce_b.data(), nonce_b.size(), 6);
    ASSERT_TRUE(pin_opt.has_value());

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent pair_init_event;
    pair_init_event.conn = current_conn_sp;
    pair_init_event.kind = PinPairingMessageKind::PAIR_INIT;
    pair_init_event.nonce_a = nonce_a;
    pair_init_event.pin_length = 6;
    this->schedule_pin_message(std::move(pair_init_event));
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));
    ASSERT_TRUE(conn->pin_session().pin_displayed);

    // The server aborts the exchange directly (pair/abort), which drives
    // ConnectionManager::handle_pair_abort() -> cleanup_connection_state() -> deferred note_*.
    PairAbortEvent abort_event;
    abort_event.conn = current_conn_sp;
    abort_event.reason = PairAbortReason::USER_CANCELLED;
    this->schedule_abort(std::move(abort_event));
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED))
        << "on_pairing_failed must survive cleanup_connection_state() (Phase 8b BLOCKER)";
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::USER_CANCELLED);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_PIN))
        << "on_clear_pairing_pin must survive cleanup_connection_state() (Phase 8b BLOCKER)";
    EXPECT_EQ(conn->disconnect_count_, 1);
}

TEST_F(PinStateMachineTest, CurrentConnectionAbortOrderingSurvivesCleanupStaticWindow) {
    // Same regression, static-PIN flavor: abort while AWAIT_PAIRING_WINDOW (before any PIN
    // exchange even starts) must still fire on_pairing_failed + on_close_pairing_window.
    this->record_store().set_static_pin("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-6", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    auto current_conn_sp = this->current_connection_sp();
    PairAbortEvent abort_event;
    abort_event.conn = current_conn_sp;
    abort_event.reason = PairAbortReason::USER_CANCELLED;
    this->schedule_abort(std::move(abort_event));
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::USER_CANCELLED);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_EQ(conn->disconnect_count_, 1);
}

// =============================================================================
// Leftover activate: entering the operational state structurally clears pairing state
// =============================================================================

// A server/activate in place of server/pair-finalize ends the pairing attempt without
// finalizing; the spec requires persisting nothing and discarding any pending long_term_psk.
// The clear is folded into SendspinClient::on_handshake_complete() -- the one place every
// "connection is now operational" path converges -- so no operational-entry path can leave a
// stale PIN session or pending record behind.
TEST_F(PinStateMachineTest, LeftoverActivateDiscardsPendingRecordAndPinSession) {
    this->record_store().set_static_pin("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-leftover", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    // Simulate the state after client/pair-finalize: a pending pairing record awaiting the ack.
    SendspinPairingRecord pending;
    pending.psk_id = "test-psk-id";
    conn->set_pending_pairing_record(pending);
    conn->pin_session().attempt_deadline_us = platform_time_us() + 120LL * 1000LL * 1000LL;

    // The server leaves pairing without finalizing: activate instead of pair-finalize.
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();

    // Going operational must have discarded the pending record and reset the PIN session.
    // (is_operational() also requires is_handshake_complete(), which FakeConnection never sets --
    // no real hello handshake runs in this harness -- so it is not asserted here.)
    EXPECT_FALSE(conn->take_pending_pairing_record().has_value())
        << "leftover activate must discard the received long_term_psk";
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::IDLE);
    EXPECT_EQ(conn->pin_session().attempt_deadline_us, 0);
}
