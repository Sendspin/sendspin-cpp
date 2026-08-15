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

// Integration harness: drives ConnectionManager's PIN pairing state machine end-to-end for
// both dynamic PIN and static PIN, including the abort / cleanup / connection-loss paths that
// the dynamic/static PIN unit tests (test_dynamic_pin.cpp) do not reach. Those cover wire
// parse/format, the lockout counter, CPace round-trips, and the client/hello descriptor.
//
// The device under test is the CPace RESPONDER; the "server" side is simulated in-test with
// a CPace INITIATOR (see cpace.h). A FakeConnection (adapted from TestConnection in
// tests/test_noise_transport.cpp) stands in for the transport: it reports a canned Noise
// handshake hash while leaving the Noise session unset, so SendspinConnection::send_app_json
// emits raw JSON via send_text_message, which this file parses directly with ArduinoJson.
//
// Server-to-client pairing messages are injected via ConnectionManager's public
// schedule_pin_pairing_message() / schedule_pair_abort() / schedule_pairing_window_confirm()
// APIs followed by SendspinClient::loop() (the same entry points process_json_message() uses
// on the network thread), so these tests exercise the real deferred-event + main-loop path.
// Listener callbacks are NOT fired directly by ConnectionManager; they are queued into
// SendspinClient::EventState and drained by SendspinClient::loop() after
// connection_manager_->loop() returns, so every scenario below calls client.loop() and asserts
// on the RecordingListener rather than on ConnectionManager state directly.

#include "connection.h"
#include "connection_manager.h"
#include "crypto/cpace.h"
#include "crypto/pin.h"
#include "crypto/psk_wrap.h"
#include "platform/base64.h"
#include "platform/time.h"
#include "platform/types.h"
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
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// =============================================================================
// FakeConnection: minimal SendspinConnection stand-in
// =============================================================================

/// @brief Concrete SendspinConnection that captures outbound frames and reports a canned
/// Noise handshake hash without ever installing a real Noise session. Adapted from
/// TestConnection in tests/test_noise_transport.cpp; kept as a deliberately separate copy
/// so this harness's needs can diverge without disturbing that file's fixture.
class FakeConnection : public SendspinConnection {
public:
    FakeConnection() = default;
    ~FakeConnection() override = default;

    // Interface stubs

    void start() override {}
    void loop() override {}
    void disconnect(SendspinGoodbyeReason reason, std::function<void()> on_complete) override {
        this->last_disconnect_reason_ = reason;
        this->disconnect_count_++;
        if (on_complete) {
            on_complete();
        }
    }
    void close_transport_now() override {
        this->close_transport_now_count_++;
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

    // Test-only seam: canned handshake hash without a Noise session

    /// Report a fixed 32-byte handshake hash while leaving noise_session_ (and therefore
    /// noise_active_) unset, so send_app_json() routes through send_text_message() as raw
    /// JSON. Overrides the virtual base implementation (see connection.h).
    std::optional<std::array<uint8_t, 32>> get_noise_handshake_hash() const override {
        return this->canned_hash_;
    }

    /// Report a canned Noise suite name without an active Noise session, so PSK Wrapping
    /// (spec "PSK Wrapping") can resolve an AEAD cipher during the PAIR_CONFIRM step. Overrides the
    /// virtual base implementation (see connection.h).
    const std::string& get_noise_suite_name() const override {
        return this->canned_suite_name_;
    }

    // Accumulated outgoing messages / disconnect bookkeeping

    std::vector<std::string> sent_text_;
    std::vector<std::vector<uint8_t>> sent_binary_;
    int disconnect_count_{0};
    int close_transport_now_count_{0};
    std::optional<SendspinGoodbyeReason> last_disconnect_reason_;

private:
    std::optional<std::array<uint8_t, 32>> canned_hash_{std::array<uint8_t, 32>{}};
    std::string canned_suite_name_{"Noise_KKpsk2_25519_ChaChaPoly_SHA256"};
    bool connected_{true};
};

// =============================================================================
// RecordingListener: captures every pairing-related callback, in order
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
    PairingEventKind kind{};
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

    [[nodiscard]] std::optional<std::string> last_failed_server_id() const {
        for (auto it = this->events_.rbegin(); it != this->events_.rend(); ++it) {
            if (it->kind == PairingEventKind::FAILED) {
                return it->server_id;
            }
        }
        return std::nullopt;
    }

    std::vector<PairingEvent> events_;
};

// =============================================================================
// Minimal fake providers
// =============================================================================

/// Network provider that always reports "not ready", so ConnectionManager::loop() never
/// starts the real WebSocket server: these tests inject connections directly and never
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

/// Build the SID CPace expects: "sendspin-pair-pake-v1" (21 bytes, no NUL) || 32-byte hash ||
/// 4-byte big-endian pairing_index counter (spec "PAKE"). `counter` must equal the pairing_index
/// the client captured for this attempt (SendspinConnection::bump_pairing_index(), which returns
/// 1 for the first pairing server/activate on a fresh connection, the value every single-
/// enter_pairing() test in this file uses).
std::vector<uint8_t> make_sid(const std::array<uint8_t, 32>& handshake_hash, uint32_t counter = 1) {
    static constexpr char PAKE_SID_LABEL[] = "sendspin-pair-pake-v1";
    std::vector<uint8_t> sid;
    sid.insert(sid.end(), PAKE_SID_LABEL, PAKE_SID_LABEL + sizeof(PAKE_SID_LABEL) - 1);
    sid.insert(sid.end(), handshake_hash.begin(), handshake_hash.end());
    sid.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
    sid.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
    sid.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
    sid.push_back(static_cast<uint8_t>(counter & 0xFF));
    return sid;
}

std::vector<uint8_t> ascii_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

/// ADa = "server" (the (stand-in) server's own AD), ADb = "client" (the device's own AD);
/// spec "PAKE".
std::vector<uint8_t> ad_server() {
    return ascii_bytes("server");
}
std::vector<uint8_t> ad_client() {
    return ascii_bytes("client");
}

/// One side of a simulated server: a CPace INITIATOR plus the nonce/hash bookkeeping needed to
/// answer either the dynamic-PIN or static-PIN device flow.
struct ServerStandIn {
    CPace initiator;
    std::string prs_pin;

    /// Start the initiator for a given PRS (PIN ASCII bytes) and SID (label || handshake hash ||
    /// pairing_index counter). `counter` defaults to 1, matching the pairing_index every
    /// single-enter_pairing() test in this file captures.
    bool start(const std::string& pin, const std::array<uint8_t, 32>& handshake_hash,
              uint32_t counter = 1) {
        this->prs_pin = pin;
        const std::vector<uint8_t> empty;
        return this->initiator.start(CPaceRole::INITIATOR, ascii_bytes(pin),
                                     make_sid(handshake_hash, counter), empty, ad_server(),
                                     ad_client());
    }
};

}  // namespace

// =============================================================================
// Test fixture: builds a SendspinClient, injects a FakeConnection as
// current_connection_, and provides helpers to drive the PIN state machine.
//
// This file reaches ConnectionManager's and SendspinClient's private state
// directly: tests/CMakeLists.txt compiles this one translation unit with
// -fno-access-control so the production headers need no test friend
// declarations. Route every such access through a fixture helper below (each
// documents why the seam exists) rather than touching privates inline in
// tests, so the private surface this harness depends on stays auditable in
// one place.
// =============================================================================

class PinStateMachineTest : public ::testing::Test {
protected:
    void SetUp() override {
        // This harness exercises both dynamic-PIN and static-PIN device flows, so the platform
        // capability flags gating their advertisement/admissibility default to both set (spec
        // "PAKE"'s pairing-method admissibility check in ConnectionManager::loop() mirrors
        // build_hello_message()'s gating exactly, including these). Tests that need a different
        // capability shape call init_client() again with other flags.
        this->init_client(/*pin_display_supported=*/true, /*pairing_window_supported=*/true);
    }

    /// (Re)build the SendspinClient under test with the given platform capability flags.
    void init_client(bool pin_display_supported, bool pairing_window_supported) {
        SendspinClientConfig config;
        config.name = "PinStateMachineTestDevice";
        config.pin_display_supported = pin_display_supported;
        config.pairing_window_supported = pairing_window_supported;
        this->client_ = std::make_unique<SendspinClient>(config);
        this->client_->set_listener(&this->listener_);
        this->client_->set_network_provider(&this->network_provider_);
        this->client_->set_persistence_provider(&this->persistence_provider_);
        ASSERT_TRUE(this->client_->start_server());
        // A device that implements static_pin enables it in its live pairing config (the flag a
        // real client would flip once, independent of whether a PIN is currently configured).
        // Needed since spec "server/activate"'s pairing-method admissibility check (see
        // ConnectionManager::loop()) gates entry on RecordStore::static_pin_enabled().
        this->record_store().set_static_pin_enabled(true);
    }

    /// Inject a fresh FakeConnection as current_connection_, with the given server_id and
    /// pairing method already applied (as if a server/activate had been admitted; dynamic_pin
    /// activations carry the session pin_length, default 6 = ungated), and pairing_in_progress
    /// cleared. Returns a raw pointer valid for the test's lifetime.
    ///
    /// The test fixture also keeps its own shared_ptr (injected_conn_) alive independently of
    /// ConnectionManager::current_connection_: abort/cleanup paths (local_abort_pin_pairing,
    /// handle_pair_abort, on_connection_lost) move-and-drop ConnectionManager's slot as part of
    /// tearing the connection down, which would otherwise destroy the FakeConnection out from
    /// under the test (its sent_text_ / disconnect_count_ are asserted AFTER those paths run).
    FakeConnection* inject_current_connection(const std::string& server_id,
                                              SendspinPairMethod method, int pin_length = 6) {
        auto conn = std::make_shared<FakeConnection>();
        conn->set_noise_handshake_result(server_id, PskCategory::SENTINEL, /*psk_id=*/"");
        conn->apply_server_activate({SendspinActivity::PAIRING}, std::nullopt, method,
                                    method == SendspinPairMethod::DYNAMIC_PIN
                                        ? std::optional<int>(pin_length)
                                        : std::nullopt);
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
    /// handle_enter_pairing() seam).
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
    /// the private-access seam) rather than replaying the full activate-arbitration path, since
    /// arbitration itself is exercised by test_admission.cpp and is not the subject of this
    /// harness.
    ///
    /// Production bumps pairing_index at the point a pairing server/activate is RECEIVED (the
    /// activate_events loop in ConnectionManager::loop(), before the admissibility gate), not
    /// inside handle_enter_pairing() itself: pairing_index must reflect every received activate,
    /// not only ones that reach this seam. This seam skips that loop entirely, so it must bump
    /// here to stand in for "a pairing server/activate was just received for this connection",
    /// matching what every real caller of handle_enter_pairing() already observes.
    void enter_pairing(SendspinConnection* conn) {
        conn->bump_pairing_index();
        this->client_->connection_manager_->handle_enter_pairing(conn);
    }

    /// Simulate the connection being lost (network thread reporting a close/disconnect),
    /// exercising ConnectionManager::on_connection_lost() with a pairing attempt in flight.
    void simulate_connection_lost(SendspinConnection* conn) {
        this->client_->connection_manager_->on_connection_lost(conn);
    }

    /// Seam for arbitration checks: should_switch_to_new_server() and the last-playback fields
    /// are private to ConnectionManager; per this file's access policy (see the fixture header
    /// comment) the call routes through here.
    /// @param last_playback_server_id Sets last_played_server_id_; empty clears the has-value
    ///        flag, so rule 5's tiebreak is only armed when a non-empty id is passed.
    bool would_switch_to(SendspinConnection* current, SendspinConnection* incoming,
                         const std::string& last_playback_server_id) {
        auto& mgr = *this->client_->connection_manager_;
        mgr.last_played_server_id_ = last_playback_server_id;
        mgr.has_last_played_server_ = !last_playback_server_id.empty();
        return mgr.should_switch_to_new_server(current, incoming);
    }

    /// Returns the shared_ptr backing the injected current connection, for building
    /// ServerPairingMessageEvent / PairAbortEvent conn fields (which require a shared_ptr).
    /// Backed by the fixture's own owning reference (see inject_current_connection), not
    /// ConnectionManager::current_connection_, so it stays valid even after an abort/cleanup
    /// path has released ConnectionManager's slot.
    std::shared_ptr<SendspinConnection> current_connection_sp() { return this->injected_conn_; }

    /// Returns ConnectionManager::current_connection_ (nullptr once dropped), through the
    /// private-access seam. Unlike current_connection_sp() above, this reflects whether the
    /// connection is still actually managed, not just whether the fixture's own reference is
    /// still alive.
    SendspinConnection* current_connection() {
        return this->client_->connection_manager_->current();
    }

    /// Drive ConnectionManager's real teardown path for `conn`, through the private-access seam, taking
    /// the same lock and running the same deferred-release flush loop() would.
    void drop_connection(SendspinConnection* conn, SendspinGoodbyeReason goodbye) {
        {
            std::lock_guard<std::mutex> lock(this->client_->connection_manager_->conn_ptr_mutex_);
            this->client_->connection_manager_->drop_connection(conn, goodbye);
        }
        this->client_->connection_manager_->flush_deferred_releases();
    }

    /// Schedule a server-to-client PIN pairing message for deferred processing (the same public
    /// entry point process_json_message() uses on the network thread), without pumping loop().
    void schedule_pin_message(ServerPairingMessageEvent event) {
        this->client_->connection_manager_->schedule_pin_pairing_message(std::move(event));
    }

    /// Schedule a pair/abort event for deferred processing, without pumping loop().
    void schedule_abort(PairAbortEvent event) {
        this->client_->connection_manager_->schedule_pair_abort(std::move(event));
    }

    /// Schedule a pairing storage-failure event for deferred processing, without pumping
    /// loop(). Mirrors what SendspinClient::process_json_message() does on the network thread
    /// when RecordStore::store_record() rejects the long-term record at server/pair-finalize.
    void schedule_storage_failed(PairStorageFailedEvent event) {
        this->client_->connection_manager_->schedule_pair_storage_failed(std::move(event));
    }

    /// Schedule a management/* request event for deferred processing, without pumping loop().
    void schedule_management(ManagementRequestEvent event) {
        this->client_->connection_manager_->schedule_management_request(std::move(event));
    }

    /// Schedule a server/activate event on the injected current connection for deferred
    /// processing, without pumping loop(). Drives the real activate-arbitration path in
    /// ConnectionManager::loop() (trust check, apply_server_activate, then either the
    /// already-admitted branch's leftover-activate handling or on_handshake_complete()):
    /// the same entry point process_json_message() uses on the network thread.
    void post_activate(std::vector<SendspinActivity> activities,
                       std::optional<std::vector<std::string>> active_roles,
                       std::optional<SendspinPairMethod> pairing_method,
                       std::optional<int> pairing_pin_length = std::nullopt) {
        ServerActivateEvent event;
        event.conn = this->current_connection_sp();
        event.activities = std::move(activities);
        event.active_roles = std::move(active_roles);
        event.pairing_method = pairing_method;
        event.pairing_pin_length = pairing_pin_length;
        this->client_->connection_manager_->schedule_activate(std::move(event));
    }

    /// Read the standing pairing-window deadline (0 = closed) through the private-access seam.
    int64_t window_deadline() {
        return this->client_->connection_manager_->pairing_window_open_until_us_;
    }

    /// Force the standing pairing window's deadline (e.g. into the past to simulate expiry).
    void set_window_deadline(int64_t deadline_us) {
        this->client_->connection_manager_->pairing_window_open_until_us_ = deadline_us;
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

    // server/pair-init: nonce_A only; pin_length (6) came from the activation.
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
    this->schedule_pin_message(std::move(pair_init_event));
    this->client_->loop();

    // The derived PIN must now be displayed.
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));
    EXPECT_EQ(this->listener_.last_displayed_pin(), pin_opt.value());

    // Simulated server (INITIATOR) starts CPace with the same derived PIN.
    ServerStandIn server;
    ASSERT_TRUE(server.start(pin_opt.value(), handshake_hash));

    // server/pair-auth: server's public share (pake_msg_1).
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

    // server/pair-confirm: server_kc.
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

    // PSK Wrapping round-trip (spec "PSK Wrapping"): client/pair-finalize must carry
    // wrapped_psk (NOT long_term_psk) in a PIN flow, and the server-side ServerStandIn (using its
    // own
    // independently-derived ISK/sid, exactly as a real server would) must be able to unwrap it.
    // A successful AEAD decrypt here proves the client used the same K_wrap the server derives.
    JsonDocument finalize_doc;
    JsonObject finalize_root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), finalize_doc, finalize_root));
    EXPECT_TRUE(finalize_root["payload"]["long_term_psk"].isUnbound())
        << "PIN flows must not send long_term_psk in the clear";
    ASSERT_TRUE(finalize_root["payload"]["wrapped_psk"].is<const char*>());
    auto wrapped_bytes =
        b64url_decode(std::string(finalize_root["payload"]["wrapped_psk"] | ""));
    ASSERT_TRUE(wrapped_bytes.has_value());
    ASSERT_EQ(wrapped_bytes->size(), WRAPPED_PSK_SIZE);
    std::array<uint8_t, WRAPPED_PSK_SIZE> wrapped_psk{};
    std::memcpy(wrapped_psk.data(), wrapped_bytes->data(), WRAPPED_PSK_SIZE);

    ASSERT_TRUE(server.initiator.isk().has_value());
    auto unwrapped =
        unwrap_psk("ChaChaPoly", server.initiator.sid(), server.initiator.isk().value(), wrapped_psk);
    ASSERT_TRUE(unwrapped.has_value()) << "server-side unwrap_psk failed";
    EXPECT_EQ(unwrapped->size(), 32u);

    // Success callbacks: on_clear_pairing_pin fires (display -> clear ordering), and the
    // dynamic-PIN failure counter is reset (was already 0, but exercise the call path by
    // checking it stays at 0 and the method is not escalated).
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_PIN));
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::DISPLAY_PIN),
             this->listener_.first_index_of(PairingEventKind::CLEAR_PIN));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_FALSE(this->record_store().dynamic_pin_escalated());
    EXPECT_EQ(this->record_store().dynamic_pin_failure_count(), 0);
}

// A PIN attempt that reaches PAIR_CONFIRM success already dismisses the displayed PIN there (see
// the PAIR_CONFIRM handler in connection_manager.cpp). If the server then acks
// server/pair-finalize but the persistence provider rejects the record, handle_pair_storage_
// failed() ends the same attempt a second time via abort_pairing_attempt(); on_clear_pairing_pin
// must NOT fire again for the PIN this attempt already stopped showing.
TEST_F(PinStateMachineTest, StorageFailureAfterConfirmDoesNotReclearAlreadyDismissedPin) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-storage-fail", SendspinPairMethod::DYNAMIC_PIN);

    this->enter_pairing(conn);
    this->client_->loop();

    const std::array<uint8_t, 32> nonce_b = conn->pin_session().nonce_b;
    const std::array<uint8_t, 32> handshake_hash = conn->pin_session().handshake_hash;

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
    this->schedule_pin_message(std::move(pair_init_event));
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));

    ServerStandIn server;
    ASSERT_TRUE(server.start(pin_opt.value(), handshake_hash));

    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = conn_sp;
    pair_auth_event.kind = PinPairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1 = server.initiator.public_share();
    this->schedule_pin_message(std::move(pair_auth_event));
    this->client_->loop();

    JsonDocument auth_doc;
    JsonObject auth_root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), auth_doc, auth_root));
    auto pake_msg_2_b64 = std::string(auth_root["payload"]["pake_msg_2"] | "");
    auto pake_msg_2 = b64url_decode(pake_msg_2_b64);
    ASSERT_TRUE(pake_msg_2.has_value());
    ASSERT_TRUE(server.initiator.derive(pake_msg_2->data(), pake_msg_2->size()));
    auto server_kc = server.initiator.tag();
    ASSERT_TRUE(server_kc.has_value());

    ServerPairingMessageEvent pair_confirm_event;
    pair_confirm_event.conn = conn_sp;
    pair_confirm_event.kind = PinPairingMessageKind::PAIR_CONFIRM;
    pair_confirm_event.server_kc = server_kc.value();
    this->schedule_pin_message(std::move(pair_confirm_event));
    this->client_->loop();

    // PAIR_CONFIRM succeeded: client/pair-finalize was sent, and the PIN was already dismissed
    // exactly once.
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-finalize");
    ASSERT_EQ(this->listener_.count(PairingEventKind::CLEAR_PIN), 1);
    ASSERT_FALSE(this->listener_.fired(PairingEventKind::FAILED));

    // The persistence provider now rejects the record at server/pair-finalize ack (network
    // thread, in production); simulate the resulting deferred event directly.
    PairStorageFailedEvent storage_failed_event;
    storage_failed_event.conn = conn_sp;
    storage_failed_event.server_id = "server-dyn-storage-fail";
    this->schedule_storage_failed(std::move(storage_failed_event));
    this->client_->loop();

    // The attempt now fails and the connection is dropped, but on_clear_pairing_pin must NOT
    // fire a second time: pin_displayed was already reset to false at PAIR_CONFIRM.
    EXPECT_EQ(this->listener_.count(PairingEventKind::CLEAR_PIN), 1)
        << "on_clear_pairing_pin must not fire twice for one pairing attempt";
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::STORAGE_FAILED);
    EXPECT_EQ(this->listener_.last_failed_server_id(), "server-dyn-storage-fail");
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
    // callbacks: on_pairing_failed AND on_clear_pairing_pin both survive
    // cleanup_connection_state().
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "pin_mismatch");
    EXPECT_EQ(this->record_store().dynamic_pin_failure_count(), 1);
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

// Spec "Protocol Errors": "a malformed or missing field ... is a protocol error: the detecting
// side closes the WebSocket without sending any application-level error message, and persists
// nothing." This pins that behavior for the MALFORMED case in
// ConnectionManager::handle_pin_pairing_message: no pair/abort, and the connection closes.
TEST_F(PinStateMachineTest, DynamicPinMalformedFrameDuringSessionClosesSilently) {
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

    // No pair/abort (or any other application-level message) is sent: sent_text_ still holds
    // only the earlier client/pair-init.
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    // The close goes through drop_connection() with goodbye=std::nullopt (no client/goodbye
    // either), so disconnect_count_ stays 0, unlike
    // PairAbortConcurrentAttemptStillClosesConnection, which does send a goodbye.
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_EQ(this->current_connection(), nullptr)
        << "a malformed pairing frame during an active PIN session must close the connection";
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::IDLE)
        << "clear_pairing_state() must have reset the PIN session (persists nothing)";
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
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
// Dynamic PIN: CPace derive() failure on server/pair-auth (low-order/malformed share)
// =============================================================================

// Spec "Protocol Errors": "a CPace share with the wrong length or encoding a low-order point" is
// a protocol error, not a pin_mismatch: the detecting side closes the WebSocket without sending
// any application-level error message, and persists nothing. A derive() failure happens on the
// peer's raw share BEFORE the PIN-derived generator can even be compared, so it can never be
// produced by an operator simply mistyping the PIN (that produces a well-formed shared secret
// that only fails the confirm-tag check exercised by DynamicPinMismatchRecordsFailureAndAborts
// above); it must not count toward the dynamic-PIN failure counter or escalate the method, which
// is the security-relevant half of this test.
TEST_F(PinStateMachineTest, DynamicPinDeriveFailureOnPairAuthClosesSilentlyWithoutFailureCount) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-7", SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");

    std::array<uint8_t, 32> nonce_a{};
    for (size_t i = 0; i < nonce_a.size(); ++i) {
        nonce_a[i] = static_cast<uint8_t>(i + 3);
    }

    auto current_conn_sp = this->current_connection_sp();

    ServerPairingMessageEvent pair_init_event;
    pair_init_event.conn = current_conn_sp;
    pair_init_event.kind = PinPairingMessageKind::PAIR_INIT;
    pair_init_event.nonce_a = nonce_a;
    this->schedule_pin_message(std::move(pair_init_event));
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_PIN));
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_SERVER_PAIR_AUTH);

    // server/pair-auth with an all-zero pake_msg_1: a well-formed-length but low-order X25519
    // point, so CPace::derive() fails on the peer share itself (see
    // CPaceDeriveRejects.AllZeroPeerShare in test_cpace.cpp), independent of any PIN value.
    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = current_conn_sp;
    pair_auth_event.kind = PinPairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1.fill(0);
    this->schedule_pin_message(std::move(pair_auth_event));
    this->client_->loop();

    // No pair/abort (or any other application-level message) beyond the earlier
    // client/pair-init and the client/pair-auth this handler itself sends before deriving.
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");
    EXPECT_FALSE(any_frame_of_type(conn->sent_text_, "pair/abort"));

    // The close goes through drop_connection() with goodbye=std::nullopt (no client/goodbye
    // either), matching the sibling MALFORMED close.
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_EQ(this->current_connection(), nullptr)
        << "a CPace derive() failure on the peer's share must close the connection";
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::IDLE)
        << "clear_pairing_state() must have reset the PIN session (persists nothing)";
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_PIN))
        << "PIN was displayed for this session, so the close must clear it";

    // Security-relevant assertion: a peer that never knew the PIN, and only sent a malformed
    // share, must NOT be able to drive the dynamic-PIN failure counter or escalate the method.
    EXPECT_EQ(this->record_store().dynamic_pin_failure_count(), 0);
    EXPECT_FALSE(this->record_store().dynamic_pin_escalated());
}

// =============================================================================
// Dynamic PIN: escalation (gesture gating, not a lockout)
// =============================================================================

// At the failure threshold the method is escalated, NOT locked out: the attempt is not
// refused, it is gesture-gated. The client reports the pending gesture with
// client/pair-pending and proceeds normally once the operator opens the window.
TEST_F(PinStateMachineTest, EscalatedDynamicPinIsGestureGatedNotRefused) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-6", SendspinPairMethod::DYNAMIC_PIN);

    for (int i = 0; i < RecordStore::DYNAMIC_PIN_ESCALATION_THRESHOLD; ++i) {
        this->record_store().record_dynamic_pin_failure();
    }
    ASSERT_TRUE(this->record_store().dynamic_pin_escalated());

    this->enter_pairing(conn);
    this->client_->loop();

    // No abort, no refusal: client/pair-pending goes out and the operator is prompted.
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_FALSE(any_frame_of_type(conn->sent_text_, "client/pair-init"));

    // pair-pending does not start the attempt or its timeout.
    EXPECT_EQ(conn->pin_session().attempt_deadline_us, 0);

    // The operator gesture opens the window: the attempt starts (client/pair-init with
    // commit_B) and the attempt timeout is armed.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_SERVER_PAIR_INIT);
    EXPECT_GT(conn->pin_session().attempt_deadline_us, 0);
}

// A session pin_length below 6 gesture-gates the attempt even when the method is not
// escalated: short PINs are bought with a gesture (spec: Pairing Window).
TEST_F(PinStateMachineTest, ShortDynamicPinIsGestureGated) {
    // Allow short PINs so the activation passes pin_length validation.
    this->record_store().set_dynamic_pin_min_length(4);
    ASSERT_FALSE(this->record_store().dynamic_pin_escalated());

    FakeConnection* conn = this->inject_current_connection(
        "server-dyn-short", SendspinPairMethod::DYNAMIC_PIN, /*pin_length=*/4);

    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    // client/pair-pending must carry the pairing_index.
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), doc, root));
    EXPECT_EQ(root["payload"]["pairing_index"] | 0u, 1u);

    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// A pairing window opened by the operator BEFORE the pairing activate arrives is standing
// state: a gated attempt arriving within its lifetime proceeds without a further gesture
// (and without a client/pair-pending).
TEST_F(PinStateMachineTest, StandingWindowAdmitsLaterGatedAttempt) {
    this->record_store().set_static_pin("13572468");

    // Gesture first: no attempt is waiting, so the window stands open.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    EXPECT_GT(this->window_deadline(), 0);

    // The gated (static PIN) pairing activate arrives: pair-init goes out immediately.
    FakeConnection* conn =
        this->inject_current_connection("server-standing", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    EXPECT_FALSE(any_frame_of_type(conn->sent_text_, "client/pair-pending"));
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_SERVER_PAIR_AUTH);
    // Sending client/pair-init consumed the window (its lifetime runs until pair-init).
    EXPECT_EQ(this->window_deadline(), 0);
}

// An expired standing window admits nothing: the gated attempt falls back to
// client/pair-pending and a fresh gesture.
TEST_F(PinStateMachineTest, ExpiredStandingWindowDoesNotAdmit) {
    this->record_store().set_static_pin("13572468");

    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_GT(this->window_deadline(), 0);
    // Simulate the 5-minute lifetime passing.
    this->set_window_deadline(platform_time_us() - 1);

    FakeConnection* conn =
        this->inject_current_connection("server-expired", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
}

// A device that offers dynamic_pin but has no pairing-window gesture UI
// (pairing_window_supported=false) can still hit the gesture gate through escalation. The
// on_open_pairing_window prompt must NOT fire (its contract requires the flag), but the
// spec-mandated client/pair-pending still goes out, and the attempt remains recoverable by a
// window opened without the local gesture (management/open-pairing-window remotely; modeled
// here via confirm_pairing_window(), which drives the same open_pairing_window() path).
TEST_F(PinStateMachineTest, GatedAttemptWithoutWindowSupportSkipsPrompt) {
    this->init_client(/*pin_display_supported=*/true, /*pairing_window_supported=*/false);

    for (int i = 0; i < RecordStore::DYNAMIC_PIN_ESCALATION_THRESHOLD; ++i) {
        this->record_store().record_dynamic_pin_failure();
    }
    ASSERT_TRUE(this->record_store().dynamic_pin_escalated());

    FakeConnection* conn =
        this->inject_current_connection("server-dyn-nowindow", SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::OPEN_WINDOW))
        << "on_open_pairing_window must not fire when pairing_window_supported is false";
    EXPECT_FALSE(conn->pin_session().window_shown);

    // A window opened without the local gesture still starts the waiting attempt.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// =============================================================================
// management/open-pairing-window
// =============================================================================

// Fixture-level helpers for driving a management/open-pairing-window request through the real
// deferred-event path (schedule_management_request + loop), on a connection whose activate
// declared the MANAGEMENT activity.

TEST_F(PinStateMachineTest, ManagementOpenPairingWindowOpensWindow) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-mgmt-1");
    conn->apply_server_activate({SendspinActivity::MANAGEMENT}, std::vector<std::string>{},
                                std::nullopt, std::nullopt);
    ASSERT_EQ(this->window_deadline(), 0);

    ManagementRequestEvent event;
    event.conn = this->current_connection_sp();
    event.kind = ManagementRequestKind::OPEN_PAIRING_WINDOW;
    this->schedule_management(std::move(event));
    this->client_->loop();

    // The result is ok and a standing window is now open.
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), doc, root));
    EXPECT_STREQ(root["type"], "management/result");
    EXPECT_STREQ(root["payload"]["result"], "ok");
    EXPECT_GT(this->window_deadline(), 0);

    // A second request while the window is open is a no-op ok: the deadline is not extended.
    const int64_t deadline_before = this->window_deadline();
    ManagementRequestEvent again;
    again.conn = this->current_connection_sp();
    again.kind = ManagementRequestKind::OPEN_PAIRING_WINDOW;
    this->schedule_management(std::move(again));
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 2u);
    JsonDocument doc2;
    JsonObject root2;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), doc2, root2));
    EXPECT_STREQ(root2["payload"]["result"], "ok");
    EXPECT_EQ(this->window_deadline(), deadline_before)
        << "a no-op ok must not extend the open window's lifetime";
}

TEST_F(PinStateMachineTest, ManagementOpenPairingWindowInvalidWhenNoPinMethodEnabled) {
    // Disable dynamic_pin; static_pin is enabled in the fixture but has no PIN configured, so
    // neither PIN method is offered.
    this->record_store().set_dynamic_pin_enabled(false);
    ASSERT_FALSE(this->record_store().static_pin().has_value());

    FakeConnection* conn = this->inject_provisional_current_connection("server-mgmt-2");
    conn->apply_server_activate({SendspinActivity::MANAGEMENT}, std::vector<std::string>{},
                                std::nullopt, std::nullopt);

    ManagementRequestEvent event;
    event.conn = this->current_connection_sp();
    event.kind = ManagementRequestKind::OPEN_PAIRING_WINDOW;
    this->schedule_management(std::move(event));
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), doc, root));
    EXPECT_STREQ(root["type"], "management/result");
    EXPECT_STREQ(root["payload"]["result"], "invalid");
    EXPECT_EQ(this->window_deadline(), 0) << "a rejected request must not open a window";
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

    // Entering static-PIN pairing (gesture-gated, no window open) sends client/pair-pending
    // and surfaces the pairing-window prompt; nothing else is sent yet.
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::DISPLAY_PIN))
        << "static PIN never displays a PIN on the device";

    const std::array<uint8_t, 32> handshake_hash = conn->pin_session().handshake_hash;

    // Operator confirms the pairing-window gesture: this must send client/pair-init with no
    // commit_B, but WITH the required pairing_index (spec "Pairing index").
    this->client_->confirm_pairing_window();
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 2u);
    JsonDocument init_doc;
    JsonObject init_root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), init_doc, init_root));
    EXPECT_STREQ(init_root["type"], "client/pair-init");
    ASSERT_TRUE(init_root["payload"].is<JsonObjectConst>());
    EXPECT_TRUE(init_root["payload"]["commit_B"].isUnbound())
        << "static-PIN client/pair-init must not carry commit_B";
    ASSERT_TRUE(init_root["payload"]["pairing_index"].is<uint32_t>());
    EXPECT_EQ(init_root["payload"]["pairing_index"].as<uint32_t>(), 1u);

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

    // PSK Wrapping round-trip (spec "PSK Wrapping"), static-PIN flavor: see the identical block in
    // DynamicPinHappyPath above for the full rationale.
    JsonDocument finalize_doc;
    JsonObject finalize_root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), finalize_doc, finalize_root));
    EXPECT_TRUE(finalize_root["payload"]["long_term_psk"].isUnbound())
        << "PIN flows must not send long_term_psk in the clear";
    ASSERT_TRUE(finalize_root["payload"]["wrapped_psk"].is<const char*>());
    auto wrapped_bytes =
        b64url_decode(std::string(finalize_root["payload"]["wrapped_psk"] | ""));
    ASSERT_TRUE(wrapped_bytes.has_value());
    ASSERT_EQ(wrapped_bytes->size(), WRAPPED_PSK_SIZE);
    std::array<uint8_t, WRAPPED_PSK_SIZE> wrapped_psk{};
    std::memcpy(wrapped_psk.data(), wrapped_bytes->data(), WRAPPED_PSK_SIZE);

    ASSERT_TRUE(server.initiator.isk().has_value());
    auto unwrapped =
        unwrap_psk("ChaChaPoly", server.initiator.sid(), server.initiator.isk().value(), wrapped_psk);
    ASSERT_TRUE(unwrapped.has_value()) << "server-side unwrap_psk failed";

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::OPEN_WINDOW),
             this->listener_.first_index_of(PairingEventKind::CLOSE_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->record_store().dynamic_pin_failure_count(), 0)
        << "a static-PIN attempt must never touch the dynamic-PIN failure counter";
}

// =============================================================================
// Entered from a SUBSEQUENT activate
// =============================================================================

// A device that first goes operational on an empty server/activate must still enter static-PIN
// pairing when the operator later triggers a SUBSEQUENT activate declaring [pairing].
// ConnectionManager::loop() must enter pairing on ANY pairing activate on an already-admitted
// connection, not only the first, or a later one is silently dropped as an ordinary "subsequent
// activate" and the pairing window never opens. Mirrors the reference's _handle_server_activate,
// which runs pairing on any pairing activate, not only the first.
TEST_F(PinStateMachineTest, SubsequentActivateEntersStaticPinPairing) {
    this->record_store().set_static_pin("13572468");

    FakeConnection* conn = this->inject_provisional_current_connection("server-static-sub");

    // First activate: empty activities -> connection goes operational, no pairing.
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    EXPECT_TRUE(conn->sent_text_.empty());

    // Subsequent activate: [pairing] + static_pin -> must enter pairing, send
    // client/pair-pending, and prompt for the window gesture.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::STATIC_PIN);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW))
        << "a subsequent pairing activate must open the operator pairing window";
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending")
        << "only client/pair-pending is sent until the operator confirms";

    // Confirming the window sends the empty client/pair-init, proving the flow is live.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// Dynamic-PIN flavor: a subsequent activate declaring [pairing] + dynamic_pin on an
// already-operational connection must enter pairing and send client/pair-init (commit_B)
// immediately (dynamic PIN has no operator pairing-window gesture, unlike static PIN above).
TEST_F(PinStateMachineTest, SubsequentActivateEntersDynamicPinPairing) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-dyn-sub");

    // First activate: empty activities -> connection goes operational, no pairing.
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_TRUE(conn->sent_text_.empty());

    // Subsequent activate: [pairing] + dynamic_pin (pin_length 6 from the pairing object) ->
    // must enter pairing.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PIN, /*pairing_pin_length=*/6);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED))
        << "a subsequent pairing activate must start the dynamic-PIN pairing flow";
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_SERVER_PAIR_INIT);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// The client validates pin_length on receipt of the ACTIVATION (not at server/pair-init,
// which carries only nonce_A): a value below min_pin_length or outside 4-12 is rejected
// with pair/abort(pin_length_unacceptable), leaving the connection open.
TEST_F(PinStateMachineTest, OutOfRangePinLengthOnActivationIsRejected) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-badlen");

    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    ASSERT_TRUE(conn->sent_text_.empty());

    // Above the protocol maximum of 12.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PIN, /*pairing_pin_length=*/13);
    this->client_->loop();

    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::IDLE);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "pin_length_unacceptable");
    EXPECT_EQ(conn->disconnect_count_, 0) << "the connection must stay open after the abort";

    // Below the client's min_pin_length (default 6) but inside 4-12: also rejected.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PIN, /*pairing_pin_length=*/4);
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "pin_length_unacceptable");

    // Missing entirely on a dynamic_pin activation (required field): also rejected.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PIN, std::nullopt);
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 3u);
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "pin_length_unacceptable");
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));
}

// A pairing activate that names no method (absent, or a method string the parser did not
// recognize) starts nothing, so the client must say so instead of ignoring the message: an
// unanswered pairing activate leaves the server waiting on the device indefinitely.
TEST_F(PinStateMachineTest, PairingActivateWithoutMethodIsAborted) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-no-method");

    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    ASSERT_TRUE(conn->sent_text_.empty());

    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();

    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::IDLE);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "pair/abort");
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "method_not_supported");
    EXPECT_EQ(conn->disconnect_count_, 0) << "the connection must stay open after the abort";
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
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::PIN_MISMATCH);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::SUCCEEDED));
    // The failure counter is dynamic-PIN only (spec: Failure counter); a static-PIN mismatch
    // must not touch it.
    EXPECT_EQ(this->record_store().dynamic_pin_failure_count(), 0);
}

// =============================================================================
// Static PIN: the gesture wait is unbounded client-side
// =============================================================================

// client/pair-pending does not start the attempt or its timeout (spec: the server applies its
// own timeout and cancels via server/activate), so the wait for the gesture must not be
// aborted by the client's attempt-timeout check.
TEST_F(PinStateMachineTest, GestureWaitHasNoClientTimeout) {
    this->record_store().set_static_pin("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-3", SendspinPairMethod::STATIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    ASSERT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    EXPECT_EQ(conn->pin_session().attempt_deadline_us, 0)
        << "client/pair-pending must not arm the attempt timeout";

    // Further loop() ticks must not abort the waiting session.
    this->client_->loop();
    this->client_->loop();
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));

    // Once the gesture starts the attempt, the timeout IS armed and enforceable.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_GT(conn->pin_session().attempt_deadline_us, 0);
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
// Connection loss mid-pairing
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
        << "on_connection_lost must dismiss a stranded pairing-window prompt";
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
// Abort ordering survives cleanup_connection_state()
// =============================================================================

TEST_F(PinStateMachineTest, CurrentConnectionAbortOrderingSurvivesCleanup) {
    // A current-connection abort (pair/abort from the server) must still deliver
    // on_pairing_failed AND on_clear_pairing_pin even though cleanup_connection_state() wipes
    // the EventState pending-notification vectors: the note_* calls in
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
        << "on_pairing_failed must survive cleanup_connection_state()";
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::USER_CANCELLED);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_PIN))
        << "on_clear_pairing_pin must survive cleanup_connection_state()";
    // Spec "pair/abort": only reason concurrent_attempt closes the connection; user_cancelled
    // leaves it open (pairing state is still cleared above).
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_FALSE(conn->is_pairing_in_progress());
}

TEST_F(PinStateMachineTest, CurrentConnectionAbortOrderingSurvivesCleanupStaticWindow) {
    // Static-PIN flavor: abort while AWAIT_PAIRING_WINDOW (before any PIN exchange even starts)
    // must still fire on_pairing_failed + on_close_pairing_window.
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
    // Spec "pair/abort": only reason concurrent_attempt closes the connection.
    EXPECT_EQ(conn->disconnect_count_, 0);
}

// =============================================================================
// Leftover activate: entering the operational state structurally clears pairing state
// =============================================================================

// A server/activate in place of server/pair-finalize ends the pairing attempt without
// finalizing; the spec requires persisting nothing and discarding any pending long_term_psk.
// The clear is folded into SendspinClient::on_handshake_complete(), the one place every
// "connection is now operational" path converges, so no operational-entry path can leave a
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
    // (is_operational() also requires is_handshake_complete(), which FakeConnection never sets,
    // since no real hello handshake runs in this harness, so it is not asserted here.)
    EXPECT_FALSE(conn->take_pending_pairing_record().has_value())
        << "leftover activate must discard the received long_term_psk";
    EXPECT_EQ(conn->pin_session().step, SendspinConnection::PinStep::IDLE);
    EXPECT_EQ(conn->pin_session().attempt_deadline_us, 0);
}

// =============================================================================
// pairing_index counter (spec "Pairing index")
// =============================================================================

// The pairing_index counter (sent on every client/pair-init and folded into the CPace sid)
// must keep incrementing across repeated pairing server/activate messages on the SAME
// connection (e.g. the operator retries after a stalled attempt), not reset with each attempt.
// It only resets on a fresh Noise handshake (initial or re-handshake).
TEST_F(PinStateMachineTest, PairingIndexIncrementsAcrossRepeatedPairingActivates) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-idx", SendspinPairMethod::DYNAMIC_PIN);
    EXPECT_EQ(conn->get_pairing_index(), 0u);

    auto sent_pairing_index = [&]() -> uint32_t {
        JsonDocument doc;
        JsonObject root;
        if (!parse_json(conn->sent_text_.back(), doc, root)) {
            return 0;
        }
        return root["payload"]["pairing_index"] | 0u;
    };

    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_FALSE(conn->sent_text_.empty());
    EXPECT_EQ(sent_pairing_index(), 1u);
    EXPECT_EQ(conn->get_pairing_index(), 1u);
    EXPECT_EQ(conn->pin_session().pairing_index, 1u);

    // A second pairing activate on the same connection (no intervening handshake): the counter
    // advances to 2, not back to 1.
    conn->clear_pairing_state();
    conn->set_pairing_in_progress(false);
    this->enter_pairing(conn);
    this->client_->loop();
    EXPECT_EQ(sent_pairing_index(), 2u);
    EXPECT_EQ(conn->get_pairing_index(), 2u);

    // A third.
    conn->clear_pairing_state();
    conn->set_pairing_in_progress(false);
    this->enter_pairing(conn);
    this->client_->loop();
    EXPECT_EQ(sent_pairing_index(), 3u);
    EXPECT_EQ(conn->get_pairing_index(), 3u);

    // A fresh Noise handshake resets the counter to zero (reset_pairing_index() is called from
    // connection.cpp at handshake/re-handshake completion; exercised directly here since
    // FakeConnection never runs a real Noise handshake).
    conn->reset_pairing_index();
    EXPECT_EQ(conn->get_pairing_index(), 0u);
}

// pairing_index counts RECEIVED pairing server/activate messages, not accepted attempts: a
// pairing activate the pairing-method admissibility gate rejects (method_not_supported) must
// still count. Unlike PairingIndexIncrementsAcrossRepeatedPairingActivates above (which drives
// handle_enter_pairing() directly via the enter_pairing() test seam, bypassing the gate
// entirely), this test goes through the REAL ConnectionManager::loop() admissibility gate via
// post_activate()/schedule_activate(), the same code path a stray or drifted server activate
// takes in production, to prove the bump in the activate_events loop (connection_manager.cpp,
// before the pairing-method admissibility check) fires for a rejected activate too, so a second,
// admissible activate on the same connection is not left one behind the server's own count.
TEST_F(PinStateMachineTest, RejectedActivateStillCountsTowardPairingIndex) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-rejected-idx");

    // First activate: empty activities -> connection goes operational (first_activate_received()
    // becomes true), no pairing. Needed so the next two activates are genuinely "subsequent" and
    // take the same real arbitration path SubsequentActivateEntersStaticPinPairing exercises,
    // rather than the nursery-promotion path (which this lightweight harness does not model).
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    EXPECT_TRUE(conn->sent_text_.empty());

    // Second activate: [pairing] + pairing_psk, but this connection resolved via the Sentinel PSK
    // (PskCategory::SENTINEL, not PAIRING), so category_ok fails and the admissibility gate rejects
    // it with pair/abort(method_not_supported) and leaves the connection open, WITHOUT ever
    // reaching handle_enter_pairing(). The counter must still have advanced to 1.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::PAIRING_PSK);
    this->client_->loop();
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "method_not_supported");
    EXPECT_EQ(conn->disconnect_count_, 0) << "method_not_supported must not close the connection";
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED))
        << "a rejected activate must not start a pairing attempt";
    EXPECT_EQ(conn->get_pairing_index(), 1u)
        << "a rejected pairing server/activate must still count toward pairing_index";

    // Third activate: [pairing] + dynamic_pin, admissible this time (category_ok: dynamic_pin
    // does not require a Pairing-category PSK; offered: pin_display_supported=true and
    // dynamic_pin_enabled_ defaults true). Must proceed into pairing and its client/pair-init
    // must carry pairing_index == 2: BOTH the rejected and the accepted activate counted.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PIN, /*pairing_pin_length=*/6);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED))
        << "the second, admissible pairing activate must proceed";
    // sent_text_ accumulates across the whole test: [0] is the pair/abort from the rejected
    // activate, [1] (the most recent) must be the client/pair-init from the accepted one.
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    EXPECT_EQ(conn->get_pairing_index(), 2u);
    EXPECT_EQ(conn->pin_session().pairing_index, 2u);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), doc, root));
    EXPECT_EQ(root["payload"]["pairing_index"] | 0u, 2u)
        << "the surviving attempt's client/pair-init must carry pairing_index == 2, proving the "
           "rejected activate was not silently dropped from the count";
}

// =============================================================================
// pair/abort close-vs-stay-open semantics (spec "pair/abort")
// =============================================================================

// Reason concurrent_attempt is the ONE pair/abort reason whose sender (and, symmetrically, this
// client on receipt) still closes the connection.
TEST_F(PinStateMachineTest, PairAbortConcurrentAttemptStillClosesConnection) {
    FakeConnection* conn = this->inject_current_connection("server-dyn-concurrent",
                                                            SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    auto current_conn_sp = this->current_connection_sp();
    PairAbortEvent abort_event;
    abort_event.conn = current_conn_sp;
    abort_event.reason = PairAbortReason::CONCURRENT_ATTEMPT;
    this->schedule_abort(std::move(abort_event));
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::CONCURRENT_ATTEMPT);
    EXPECT_EQ(conn->disconnect_count_, 1);
}

// A pair/abort that arrives after the receiver has already ended the attempt (here: a local
// attempt-timeout abort) has no effect: it must not fire a second on_pairing_failed, and must
// not touch the connection.
TEST_F(PinStateMachineTest, StalePairAbortAfterLocalAbortHasNoEffect) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-stale", SendspinPairMethod::DYNAMIC_PIN);
    this->enter_pairing(conn);
    this->client_->loop();

    // The client locally aborts first (attempt timeout).
    conn->pin_session().attempt_deadline_us = platform_time_us() - 1;
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::ATTEMPT_TIMEOUT);
    EXPECT_FALSE(conn->is_pairing_in_progress());
    const size_t events_before = this->listener_.events_.size();
    const int disconnects_before = conn->disconnect_count_;

    // A pair/abort from the server races in AFTER the local abort already ended the attempt.
    auto current_conn_sp = this->current_connection_sp();
    PairAbortEvent stale_event;
    stale_event.conn = current_conn_sp;
    stale_event.reason = PairAbortReason::PIN_MISMATCH;
    this->schedule_abort(std::move(stale_event));
    this->client_->loop();

    EXPECT_EQ(this->listener_.events_.size(), events_before)
        << "a stale pair/abort must not fire any new listener event";
    EXPECT_EQ(conn->disconnect_count_, disconnects_before);
}

// =============================================================================
// Re-proving watchdog (current_connection_ non-operational after a re-handshake or a
// pair-finalize ack; see REPROVE_TIMEOUT_US in connection_manager.h)
// =============================================================================

// SendspinConnection::note_pairing_finalize_ack() resets first_activate_received_ (so
// is_operational() goes false) and re-arms provisional_time_us_, anticipating the server's
// follow-up in-band re-handshake. If the server goes silent instead, ConnectionManager::loop()
// must eventually drop the connection rather than leave it wedged non-operational forever. The
// nursery reaper cannot cover this: the connection is current_connection_, never a nursery member.
// Forces the deadline into the past instead of sleeping REPROVE_TIMEOUT_US (30 s) in a unit test,
// matching the attempt_deadline_us pattern (e.g. DynamicPinAttemptTimeout above).
TEST_F(PinStateMachineTest, ReproveWatchdogDropsConnectionAfterFinalizeAckGoesSilent) {
    FakeConnection* conn =
        this->inject_current_connection("server-reprove-silent", SendspinPairMethod::DYNAMIC_PIN);

    // Simulate: the server acked client/pair-finalize (the SERVER_PAIR_FINALIZE handler in
    // client.cpp calls this on success) and is expected to rekey via an in-band re-handshake.
    conn->note_pairing_finalize_ack();
    ASSERT_FALSE(conn->is_operational());
    ASSERT_NE(conn->get_provisional_time_us(), 0);

    // The server then goes silent forever instead of re-handshaking.
    conn->set_provisional_time_us(platform_time_us() - REPROVE_TIMEOUT_US - 1);
    this->client_->loop();

    EXPECT_EQ(this->current_connection(), nullptr)
        << "a connection that never re-proves itself after a pair-finalize ack must eventually "
           "be dropped instead of left wedged non-operational forever";
}

// Companion to the test above, proving the watchdog does NOT over-reap: a connection that is
// operational (is_operational() == true, as a real promoted current_connection_ always is
// outside the two re-proving windows; see promote_or_arbitrate_nursery_entry()) and legitimately
// mid-PIN-pairing, awaiting a human to press a physical gesture with no fixed deadline of its
// own, must survive even though its provisional_time_us_ is stale by far more than
// REPROVE_TIMEOUT_US.
TEST_F(PinStateMachineTest, ReproveWatchdogDoesNotDropConnectionAwaitingHumanPinGesture) {
    this->record_store().set_static_pin("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-reprove-pin-wait", SendspinPairMethod::STATIC_PIN);

    // inject_current_connection() does not run a real hello handshake (see the comment on
    // LeftoverActivateDiscardsPendingRecordAndPinSession above), so is_handshake_complete(),
    // and therefore is_operational(), would otherwise stay false regardless of pairing state.
    // Set it explicitly so this test exercises the same !is_operational() gate a real connection
    // would, and so a false pass (the watchdog skipping this connection only because
    // is_operational() can never be true in this harness) cannot hide a real over-reap bug.
    conn->set_client_hello_sent(true);
    conn->set_server_hello_received(true);
    ASSERT_TRUE(conn->is_operational());

    // static_pin is always gesture-gated (spec: Pairing Window), so with no window open this
    // attempt waits for a human to press a button. AWAIT_PAIRING_WINDOW leaves attempt_deadline_us
    // at 0 (see handle_enter_pairing): the wait has no fixed deadline of its own.
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_EQ(conn->pin_session().step, SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW);
    ASSERT_TRUE(conn->is_operational())
        << "entering pairing must not itself clear first_activate_received_";

    // A long time passes, far beyond REPROVE_TIMEOUT_US, while the human has not yet acted.
    conn->set_provisional_time_us(platform_time_us() - REPROVE_TIMEOUT_US - 1);
    this->client_->loop();

    EXPECT_EQ(this->current_connection(), conn)
        << "a connection legitimately awaiting a human PIN gesture must not be reaped by the "
           "re-proving watchdog";
    EXPECT_TRUE(conn->is_operational());
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
}

// The admitted flag must be cleared when the admitted connection is dropped.
//
// SendspinConnection::is_admitted() is what the network-thread dispatch gate reads to decide
// whether a connection may drive the roles (see requires_admitted_connection() in client.cpp).
// drop_connection() moves the connection out of current_connection_ BEFORE calling
// set_current_connection(nullptr), so the setter sees an already-null slot and cannot clear the
// outgoing occupant; drop_connection() has to do it itself. The dropped connection outlives the
// call (queue_deferred_release keeps it alive through the goodbye window), so a missed clear
// leaves an object that still claims admission.
//
// Asserted on the flag directly rather than end to end: disable_message_dispatch(), called a few
// lines earlier in the same function, independently blocks dispatch from a dropped connection, so
// an end-to-end test cannot tell a cleared flag from a stale one. That masking is why this is
// defence in depth rather than the only barrier, and it is exactly why the invariant needs its
// own test.
TEST_F(PinStateMachineTest, DropClearsTheAdmittedFlag) {
    FakeConnection* conn = this->inject_current_connection("server-drop-admitted",
                                                           SendspinPairMethod::PAIRING_PSK);
    // inject_current_connection() assigns current_connection_ directly (bypassing
    // set_current_connection), so set the flag the way promotion would.
    conn->set_admitted(true);
    ASSERT_TRUE(conn->is_admitted());

    this->drop_connection(conn, SendspinGoodbyeReason::SHUTDOWN);

    EXPECT_EQ(this->current_connection(), nullptr) << "the slot must be empty after the drop";
    EXPECT_FALSE(conn->is_admitted())
        << "a dropped connection must not keep claiming the admitted slot";
}

// ============================================================================
// Arbitration against a finalized-but-not-yet-re-proven incumbent
// ============================================================================

// Companion to test_admission.cpp's pure-function tests: those pin what
// should_admit_connection() does with a given admitted_pairing_in_flight, while this pins that
// should_switch_to_new_server() WIRES it correctly: passing the incumbent's real activities and
// signalling the finished pairing through the flag, rather than substituting an empty activity
// set (which would silently drop the incumbent to rank 0 and let rule 5's last_playback tiebreak
// evict a connection that had just finished pairing).
TEST_F(PinStateMachineTest, FinalizedPairingIsNotEvictedByRankZeroLastPlaybackPeer) {
    FakeConnection* current =
        this->inject_current_connection("paired-server", SendspinPairMethod::DYNAMIC_PIN);
    // The server has acked pair-finalize: pairing is complete, but no post-rekey activate has
    // landed, so get_activities() still reports [PAIRING].
    current->note_pairing_finalize_ack();
    ASSERT_TRUE(current->is_pairing_finalized());
    ASSERT_EQ(current->get_activities().size(), 1u);

    // A rank-0 peer (no activities) whose server_id is the last playback server: exactly the
    // inputs admission rule 5 keys on.
    auto newcomer = std::make_shared<FakeConnection>();
    newcomer->set_noise_handshake_result("old-playback-server", PskCategory::SENTINEL,
                                         /*psk_id=*/"");
    newcomer->apply_server_activate({}, std::nullopt, std::nullopt, std::nullopt);

    EXPECT_FALSE(this->would_switch_to(current, newcomer.get(), "old-playback-server"))
        << "a rank-0 peer must not displace a just-paired rank-1 connection; suppressing the "
           "in-flight-pairing shield must not also drop the incumbent's rank";

    // The shield really is suppressed though: a rank-2 playback peer wins.
    auto playback = std::make_shared<FakeConnection>();
    playback->set_noise_handshake_result("playback-server", PskCategory::SENTINEL, /*psk_id=*/"");
    playback->apply_server_activate({SendspinActivity::PLAYBACK}, std::nullopt, std::nullopt,
                                    std::nullopt);
    EXPECT_TRUE(this->would_switch_to(current, playback.get(), "old-playback-server"))
        << "a finalized pairing must stop blocking a higher-ranked incoming connection";
}
