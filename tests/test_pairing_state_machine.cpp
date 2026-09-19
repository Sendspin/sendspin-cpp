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

// Integration harness: drives ConnectionManager's code pairing state machine end-to-end for
// both the dynamic and static pairing code, including the abort / cleanup / connection-loss paths
// that
// the dynamic/static pairing code unit tests (test_dynamic_pairing_code.cpp) do not reach. Those
// cover wire
// parse/format, the lockout counter, CPace round-trips, and the client/hello descriptor.
//
// The device under test is the CPace RESPONDER; the "server" side is simulated in-test with
// a CPace INITIATOR (see cpace.h). A FakeConnection (adapted from TestConnection in
// tests/test_noise_transport.cpp) stands in for the transport: it reports a canned Noise
// handshake hash while leaving the Noise session unset, so SendspinConnection::send_app_json
// emits raw JSON via send_text_message, which this file parses directly with ArduinoJson.
//
// Server-to-client pairing messages are injected via ConnectionManager's public
// schedule_pairing_message() / schedule_pair_abort() / schedule_pairing_window_confirm()
// APIs followed by SendspinClient::loop() (the same entry points process_json_message() uses
// on the network thread), so these tests exercise the real deferred-event + main-loop path.
// Listener callbacks are NOT fired directly by ConnectionManager; they are queued into
// SendspinClient::EventState and drained by SendspinClient::loop() after
// connection_manager_->loop() returns, so every scenario below calls client.loop() and asserts
// on the RecordingListener rather than on ConnectionManager state directly.

#include "connection.h"
#include "connection_manager.h"
#include "crypto/cpace.h"
#include "crypto/pairing_code.h"
#include "crypto/pairing_token.h"
#include "crypto/psk_wrap.h"
#include "platform/base64.h"
#include "platform/time.h"
#include "platform/types.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/persistence_codec.h"
#include "sendspin/types.h"
#include "wrap_test_helpers.h"

#include <ArduinoJson.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// ============================================================================
// FakeConnection: minimal SendspinConnection stand-in
// ============================================================================

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

    // Records every call instead of just reporting success, so a test can assert that the
    // time-burst gate in SendspinClient::loop() (see client.cpp) never reached this connection
    // at all, not merely that no client/time frame text happens to appear in sent_text_.
    bool send_time_message() override {
        this->time_message_send_count_++;
        return true;
    }

    // Test-only seam: canned handshake hash without a Noise session

    /// Report a fixed 32-byte handshake hash while leaving noise_session_ (and therefore
    /// noise_active_) unset, so send_app_json() routes through send_text_message() as raw JSON.
    std::optional<std::array<uint8_t, 32>> get_noise_handshake_hash() const override {
        return this->canned_hash_;
    }

    /// Report a canned Noise suite name without an active Noise session, so the wrapping
    /// (pairing.md "Wrapping") can resolve an AEAD cipher during the PAIR_CONFIRM step.
    const std::string& get_noise_suite_name() const override {
        return this->canned_suite_name_;
    }

    // Accumulated outgoing messages / disconnect bookkeeping

    std::vector<std::string> sent_text_;
    std::vector<std::vector<uint8_t>> sent_binary_;
    int disconnect_count_{0};
    int close_transport_now_count_{0};
    int time_message_send_count_{0};
    std::optional<SendspinGoodbyeReason> last_disconnect_reason_;

private:
    std::optional<std::array<uint8_t, 32>> canned_hash_{std::array<uint8_t, 32>{}};
    std::string canned_suite_name_{"Noise_KKpsk2_25519_ChaChaPoly_SHA256"};
    bool connected_{true};
};

// ============================================================================
// RecordingListener: captures every pairing-related callback, in order
// ============================================================================

enum class PairingEventKind {
    STARTED,
    SUCCEEDED,
    FAILED,
    DISPLAY_CODE,
    CLEAR_CODE,
    OPEN_WINDOW,
    CLOSE_WINDOW,
};

struct PairingEvent {
    PairingEventKind kind{};
    std::string server_id;              // STARTED / SUCCEEDED / FAILED
    SendspinPairAbortReason reason{};   // FAILED
    std::string code;                   // DISPLAY_CODE
    SendspinPairingCodeFormat format{};  // DISPLAY_CODE
};

class RecordingListener : public SendspinClientListener {
public:
    void on_pairing_started(const std::string& server_id) override {
        this->events_.push_back({PairingEventKind::STARTED, server_id, {}, {}, {}});
    }
    void on_pairing_succeeded(const std::string& server_id) override {
        this->events_.push_back({PairingEventKind::SUCCEEDED, server_id, {}, {}, {}});
    }
    void on_pairing_failed(const std::string& server_id, SendspinPairAbortReason reason) override {
        this->events_.push_back({PairingEventKind::FAILED, server_id, reason, {}, {}});
    }
    void on_display_pairing_code(const std::string& code,
                                 SendspinPairingCodeFormat format) override {
        this->events_.push_back({PairingEventKind::DISPLAY_CODE, {}, {}, code, format});
    }
    void on_clear_pairing_code() override {
        this->events_.push_back({PairingEventKind::CLEAR_CODE, {}, {}, {}, {}});
    }
    void on_open_pairing_window() override {
        this->events_.push_back({PairingEventKind::OPEN_WINDOW, {}, {}, {}, {}});
    }
    void on_close_pairing_window() override {
        this->events_.push_back({PairingEventKind::CLOSE_WINDOW, {}, {}, {}, {}});
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
    /// ordering between two callbacks (e.g. code emission must precede its withdrawal).
    [[nodiscard]] int first_index_of(PairingEventKind kind) const {
        for (size_t i = 0; i < this->events_.size(); ++i) {
            if (this->events_[i].kind == kind) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    [[nodiscard]] std::optional<std::string> last_emitted_code() const {
        for (auto it = this->events_.rbegin(); it != this->events_.rend(); ++it) {
            if (it->kind == PairingEventKind::DISPLAY_CODE) {
                return it->code;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<SendspinPairingCodeFormat> last_emitted_format() const {
        for (auto it = this->events_.rbegin(); it != this->events_.rend(); ++it) {
            if (it->kind == PairingEventKind::DISPLAY_CODE) {
                return it->format;
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

// ============================================================================
// Minimal fake providers
// ============================================================================

/// Network provider that always reports "not ready", so ConnectionManager::loop() never
/// starts the real WebSocket server: these tests inject connections directly and never
/// exercise the transport or accept path.
class FakeNetworkProvider : public SendspinNetworkProvider {
public:
    bool is_network_ready() override { return false; }
};

/// Persistence provider that serves only what a test seeded into it, which is how the pairing
/// configuration reaches RecordStore at all (its constructor reads these blobs; there are no
/// runtime setters). Counts save_blob() calls per key, still returning false like the base class
/// default, so tests can assert on write counts (e.g. the persist_last_played_server() dedup
/// guard) without disturbing the always-fails behavior the RECORDS-storage-failure tests rely on.
class FakePersistenceProvider : public SendspinPersistenceProvider {
public:
    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        auto it = this->seeded_.find(key);
        if (it == this->seeded_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool save_blob(const std::string& key, const uint8_t* /*data*/, size_t /*len*/) override {
        this->save_attempts_[key]++;
        return false;
    }

    /// @brief Place a blob in the store directly, as out-of-band provisioning would.
    void seed_blob(const std::string& key, const std::string& bytes) {
        this->seeded_[key] = std::vector<uint8_t>(bytes.begin(), bytes.end());
    }

    [[nodiscard]] int save_attempts(const std::string& key) const {
        auto it = this->save_attempts_.find(key);
        return it == this->save_attempts_.end() ? 0 : it->second;
    }

private:
    std::map<std::string, int> save_attempts_;
    std::map<std::string, std::vector<uint8_t>> seeded_;
};

// ============================================================================
// JSON helpers for asserting on captured outbound frames
// ============================================================================

/// Parse a captured outbound JSON string. Returns false on malformed JSON, for ASSERT_TRUE at
/// the call site.
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

// ============================================================================
// Server-side ("stand-in initiator") frame builders, mirroring test_dynamic_pairing_code.cpp
// ============================================================================

/// Build the sid CPace expects: "sendspin-pair-pake-v1" (21 bytes, no NUL) || 32-byte hash ||
/// 4-byte big-endian pairing_index || 4-byte big-endian round (pairing.md "PAKE").
/// `pairing_index` must equal the one the client captured for this attempt
/// (SendspinConnection::bump_pairing_index(), which returns 1 for the first pairing
/// server/activate on a fresh connection, the value every single-enter_pairing() test in this
/// file uses); `round` is 1 for an attempt's first round.
std::vector<uint8_t> make_sid(const std::array<uint8_t, 32>& handshake_hash,
                              uint32_t pairing_index = 1, uint32_t round = 1) {
    static constexpr char PAKE_SID_LABEL[] = "sendspin-pair-pake-v1";
    std::vector<uint8_t> sid;
    sid.insert(sid.end(), PAKE_SID_LABEL, PAKE_SID_LABEL + sizeof(PAKE_SID_LABEL) - 1);
    sid.insert(sid.end(), handshake_hash.begin(), handshake_hash.end());
    for (uint32_t counter : {pairing_index, round}) {
        sid.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
        sid.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
        sid.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
        sid.push_back(static_cast<uint8_t>(counter & 0xFF));
    }
    return sid;
}

std::vector<uint8_t> ascii_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

/// ADa = "server" (the (stand-in) server's own AD), ADb = "client" (the device's own AD);
/// pairing.md "PAKE".
std::vector<uint8_t> ad_server() {
    return ascii_bytes("server");
}
std::vector<uint8_t> ad_client() {
    return ascii_bytes("client");
}

/// One side of a simulated server: a CPace INITIATOR plus the nonce/hash bookkeeping needed to
/// answer either the dynamic or static pairing-code device flow.
struct ServerStandIn {
    CPace initiator;
    std::vector<uint8_t> prs;

    /// Start the initiator over the PRS the operator entered and the sid for one round; the
    /// defaults are make_sid()'s (see its doc comment).
    bool start(const std::vector<uint8_t>& prs, const std::array<uint8_t, 32>& handshake_hash,
               uint32_t pairing_index = 1, uint32_t round = 1) {
        this->prs = prs;
        const std::vector<uint8_t> empty;
        return this->initiator.start(CPaceRole::INITIATOR, prs,
                                     make_sid(handshake_hash, pairing_index, round), empty,
                                     ad_server(), ad_client());
    }
};

/// Result of PairingStateMachineTest::drive_to_code_emitted(): the emitted code (matches
/// on_display_pairing_code's argument) and the PRS bytes behind it, plus the handshake hash and
/// nonce_A a later ServerStandIn needs to start CPace over the same PRS and sid.
struct CodeEmissionResult {
    std::string emitted;
    std::vector<uint8_t> prs;
    std::array<uint8_t, 32> handshake_hash{};
    std::array<uint8_t, 32> nonce_a{};
};

}  // namespace

// ============================================================================
// Test fixture: builds a SendspinClient, injects a FakeConnection as
// current_connection_, and provides helpers to drive the pairing state machine.
//
// This file reaches ConnectionManager's and SendspinClient's private state
// directly: tests/CMakeLists.txt compiles this one translation unit with
// -fno-access-control so the production headers need no test friend
// declarations. Route every such access through a fixture helper below (each
// documents why the seam exists) rather than touching privates inline in
// tests, so the private surface this harness depends on stays auditable in
// one place.
// ============================================================================

class PairingStateMachineTest : public ::testing::Test {
protected:
    void SetUp() override {
        // This harness exercises both dynamic and static pairing-code device flows, so the platform
        // capability flags gating their advertisement/admissibility default to both set (spec
        // "PAKE"'s pairing-method admissibility check in ConnectionManager::loop() mirrors
        // build_hello_message()'s gating exactly, including these). Tests that need a different
        // capability shape call init_client() again with other flags.
        this->init_client(/*pairing_code_emission_supported=*/true,
                          /*pairing_window_supported=*/true);
    }

    /// (Re)build the SendspinClient under test with the given platform capability flags, and
    /// optionally the factory locations hints the client/hello descriptors advertise.
    /// `pairing_code_emission_supported` stands for the pair of config fields that make a device
    /// able to emit a dynamic pairing code at all: an out-channel and an emission format.
    void init_client(bool pairing_code_emission_supported, bool pairing_window_supported,
                     std::vector<std::string> pairing_psk_locations = {},
                     std::vector<std::string> static_pairing_code_locations = {}) {
        this->pairing_code_emission_supported_ = pairing_code_emission_supported;
        this->pairing_window_supported_ = pairing_window_supported;
        this->pairing_psk_locations_ = std::move(pairing_psk_locations);
        this->static_pairing_code_locations_ = std::move(static_pairing_code_locations);
        this->build_client();
    }

    /// Shape the device as a static-pairing-code device: the code it was provisioned with, and
    /// no out-channel, since messaging.md "client/hello" permits at most one pairing-code method
    /// in supported_pair_methods and pairing.md "Methods" prefers the dynamic code wherever an
    /// out-channel exists. Rebuilds the client: the pairing configuration is construction-time
    /// state (RecordStore reads it from the persistence provider and never writes it again), so
    /// it is seeded and the client rebuilt rather than set on a live store.
    void configure_static_pairing_code(const std::string& code) {
        this->pairing_code_emission_supported_ = false;
        this->static_pairing_code_ = code;
        this->build_client();
    }

    /// Build the SendspinClient under test from the fixture's current configuration, seeding
    /// the pairing blobs its RecordStore reads at construction.
    void build_client() {
        SendspinPairingConfig pairing_config;
        // A device that implements static_pairing_code enables it in its pairing config,
        // independent of whether a code is currently configured. Needed since the
        // pairing-method admissibility check (see ConnectionManager::process_activate_event())
        // gates entry on RecordStore::static_pairing_code_enabled().
        pairing_config.static_pairing_code_enabled = true;
        this->persistence_provider_.seed_blob(persistence_keys::PAIR_CONFIG,
                                              encode_pairing_config(pairing_config));
        if (this->static_pairing_code_.has_value()) {
            this->persistence_provider_.seed_blob(persistence_keys::STATIC_PAIRING_CODE,
                                                  this->static_pairing_code_.value());
        }

        SendspinClientConfig config;
        config.name = "PairingStateMachineTestDevice";
        if (this->pairing_code_emission_supported_) {
            config.pairing_code_out_channels = {SendspinPairingCodeChannel::DISPLAY};
            config.pairing_code_formats = {SendspinPairingCodeFormat::DIGITS,
                                           SendspinPairingCodeFormat::QR_CODE};
        }
        config.pairing_window_supported = this->pairing_window_supported_;
        config.pairing_psk_locations = this->pairing_psk_locations_;
        config.static_pairing_code_locations = this->static_pairing_code_locations_;
        this->client_ = std::make_unique<SendspinClient>(config);
        this->client_->set_listener(&this->listener_);
        this->client_->set_network_provider(&this->network_provider_);
        this->client_->set_persistence_provider(&this->persistence_provider_);
        ASSERT_TRUE(this->client_->start());
    }

    /// Inject a fresh FakeConnection as current_connection_, with the given server_id and
    /// pairing method already applied (as if a server/activate had been admitted;
    /// dynamic_pairing_code activations carry the emission format), and pairing_in_progress
    /// cleared. Returns a raw pointer valid for the test's lifetime.
    ///
    /// The test fixture also keeps its own shared_ptr (injected_conn_) alive independently of
    /// ConnectionManager::current_connection_: abort/cleanup paths (local_abort_pairing,
    /// handle_pair_abort, on_connection_lost) move-and-drop ConnectionManager's slot as part of
    /// tearing the connection down, which would otherwise destroy the FakeConnection out from
    /// under the test (its sent_text_ / disconnect_count_ are asserted AFTER those paths run).
    FakeConnection* inject_current_connection(
        const std::string& server_id, SendspinPairMethod method,
        SendspinPairingCodeFormat format = SendspinPairingCodeFormat::DIGITS) {
        auto conn = std::make_shared<FakeConnection>();
        conn->set_noise_handshake_result(server_id, PskCategory::SENTINEL, /*psk_id=*/"");
        conn->apply_server_activate({SendspinActivity::PAIRING}, std::nullopt, method,
                                    method == SendspinPairMethod::DYNAMIC_PAIRING_CODE
                                        ? std::optional<SendspinPairingCodeFormat>(format)
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

    /// Seam for arbitration checks: should_switch_to_new_server() and the last-playback field
    /// are private to ConnectionManager.
    /// @param last_playback_server_id Sets last_played_server_id_; empty leaves it unset, so
    ///        rule 5's tiebreak is only armed when a non-empty id is passed.
    bool would_switch_to(SendspinConnection* current, SendspinConnection* incoming,
                         const std::string& last_playback_server_id) {
        auto& mgr = *this->client_->connection_manager_;
        mgr.set_last_played_server_id(last_playback_server_id);
        return mgr.should_switch_to_new_server(current, incoming);
    }

    /// Drives SendspinClient::persist_last_played_server(), private to SendspinClient.
    void persist_last_played_server(const std::string& server_id) {
        this->client_->persist_last_played_server(server_id);
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

    /// Drive ConnectionManager's real teardown path for `conn`, through the private-access seam,
    /// taking
    /// the same lock and running the same deferred-release flush loop() would.
    void drop_connection(SendspinConnection* conn, SendspinGoodbyeReason goodbye) {
        {
            std::lock_guard<std::mutex> lock(this->client_->connection_manager_->conn_ptr_mutex_);
            this->client_->connection_manager_->drop_connection(conn, goodbye);
        }
        this->client_->connection_manager_->flush_deferred_releases();
    }

    /// Schedule a server-to-client code pairing message for deferred processing (the same public
    /// entry point process_json_message() uses on the network thread), without pumping loop().
    void schedule_pairing_message_event(ServerPairingMessageEvent event) {
        this->client_->connection_manager_->schedule_pairing_message(std::move(event));
    }

    /// Schedule a pair/abort event for deferred processing, without pumping loop().
    void schedule_abort(PairAbortEvent event) {
        this->client_->connection_manager_->schedule_pair_abort(std::move(event));
    }

    /// Schedule a server/activate event on the injected current connection for deferred
    /// processing, without pumping loop(). Drives the real activate-arbitration path in
    /// ConnectionManager::loop() (trust check, apply_server_activate, then either the
    /// already-admitted branch's leftover-activate handling or on_handshake_complete()):
    /// the same entry point process_json_message() uses on the network thread.
    void post_activate(std::vector<SendspinActivity> activities,
                       std::optional<std::vector<std::string>> active_roles,
                       std::optional<SendspinPairMethod> pairing_method,
                       std::optional<SendspinPairingCodeFormat> pairing_format = std::nullopt) {
        ServerActivateEvent event;
        event.conn = this->current_connection_sp();
        event.activities = std::move(activities);
        event.active_roles = std::move(active_roles);
        event.pairing_method = pairing_method;
        event.pairing_format = pairing_format;
        this->client_->connection_manager_->schedule_activate(std::move(event));
    }

    /// Put the injected connection into, or out of, the state
    /// SendspinConnection::handle_noise_rehandshake() leaves it in after a session swap: awaiting
    /// its next server/activate, with the re-proving stamp refreshed. The real call needs a live
    /// Noise transport this harness has none of, and the flags are what the loop() scans under
    /// test actually read. first_activate_received_ is private to SendspinConnection.
    void set_awaiting_activate(FakeConnection* conn, bool awaiting) {
        if (awaiting) {
            conn->set_provisional_time_us(platform_time_us());
        }
        conn->first_activate_received_.store(!awaiting, std::memory_order_release);
    }

    /// Read the standing pairing-window deadline (0 = closed) through the private-access seam.
    int64_t window_deadline() {
        return this->client_->connection_manager_->pairing_window_open_until_us_;
    }

    /// Force the standing pairing window's deadline (e.g. into the past to simulate expiry).
    void set_window_deadline(int64_t deadline_us) {
        this->client_->connection_manager_->pairing_window_open_until_us_ = deadline_us;
    }

    /// Deliver the server's server/pair-finalize ack for `conn`, the way
    /// SendspinClient::process_json_message()'s SERVER_PAIR_FINALIZE handler does on the network
    /// thread: commit the pending record and schedule the pairing-succeeded note. Routed through
    /// the private-access seam rather than a fake transport, since this harness never installs a
    /// real Noise session to decrypt a frame through.
    void deliver_pair_finalize_ack(FakeConnection* conn) {
        auto record = conn->take_pending_pairing_record();
        ASSERT_TRUE(record.has_value()) << "no record was staged for the ack to commit";
        ASSERT_TRUE(this->client_->record_store_->store_record_superseding(
            std::move(record.value()),
            this->client_->connection_manager_->open_connection_psk_ids()));
        this->client_->connection_manager_->schedule_pairing_succeeded(conn->get_server_id());
        conn->note_pairing_finalize_ack();
        this->client_->loop();
    }

    /// Read the connection the open window is bound to (nullptr until it admits its first
    /// attempt), through the private-access seam.
    const SendspinConnection* window_connection() {
        return this->client_->connection_manager_->pairing_window_conn_;
    }

    /// Read the window's failed-attempt count, through the private-access seam.
    uint32_t window_failed_attempts() {
        return this->client_->connection_manager_->pairing_window_failed_attempts_;
    }

    RecordStore& record_store() { return *this->client_->record_store_; }

    /// Return the `locations` array on the client/hello descriptor for `method`, or nullopt when
    /// the descriptor omits the hint. Fails the calling test if the method is not advertised at
    /// all. build_hello_message() is private; this is the -fno-access-control seam for it.
    std::optional<std::vector<std::string>> hello_locations(const char* method) {
        JsonDocument doc;
        JsonObject root;
        EXPECT_TRUE(parse_json(this->client_->build_hello_message(), doc, root));
        JsonVariantConst desc = root["payload"]["supported_pair_methods"][method];
        if (!desc.isUnbound()) {
            if (desc["locations"].isUnbound()) {
                return std::nullopt;
            }
            std::vector<std::string> out;
            for (JsonVariantConst loc : desc["locations"].as<JsonArrayConst>()) {
                out.emplace_back(loc.as<const char*>());
            }
            return out;
        }
        ADD_FAILURE() << "client/hello does not advertise " << method;
        return std::nullopt;
    }

    // =========================================================================
    // CPace pair-init/auth/confirm drive helpers
    //
    // These stage the choreography shared by the dynamic and static pairing-code happy paths (and
    // the connection-loss / abort-ordering tests that ride the front half of it): inject +
    // enter pairing, drive server/pair-init to a emitted code, drive server/pair-auth to a
    // genuine server_kc, then send server/pair-confirm. Each stage asserts its own
    // preconditions internally (ASSERT_TRUE/ASSERT_EQ), so callers wrap the call in
    // ASSERT_NO_FATAL_FAILURE to propagate a failure out of the TEST_F body the way an inline
    // ASSERT_* would (gtest's fatal-assertion `return` only unwinds the helper itself).
    // =========================================================================

    /// Inject a fresh dynamic-pairing-code FakeConnection for `server_id` and drive
    /// handle_enter_pairing(): emits client/pair-init(commit_B), but no code is emitted yet
    /// (server/pair-init has not arrived from the "server", so nonce_A is unknown). Returns the
    /// injected connection.
    FakeConnection* enter_dynamic_code_pairing(
        const std::string& server_id,
        SendspinPairingCodeFormat format = SendspinPairingCodeFormat::DIGITS) {
        FakeConnection* conn = this->inject_current_connection(
            server_id, SendspinPairMethod::DYNAMIC_PAIRING_CODE, format);
        this->enter_pairing(conn);
        this->client_->loop();
        return conn;
    }

    /// Complete the server/pair-init leg of a dynamic attempt already at handle_enter_pairing():
    /// captures nonce_B from the session, builds nonce_A (each byte i + nonce_a_seed, matching
    /// this file's per-test constants that keep derived codes distinct across tests), derives
    /// the code the way the device does, then schedules+pumps server/pair-init and asserts the
    /// code was emitted (pairing.md "Dynamic Pairing Code Flow": emission only happens once
    /// server/pair-init supplies nonce_A).
    void drive_to_code_emitted(FakeConnection* conn, uint8_t nonce_a_seed,
                               CodeEmissionResult& out) {
        const std::array<uint8_t, 32> nonce_b = conn->pairing_session().nonce_b;
        out.handshake_hash = conn->pairing_session().handshake_hash;
        out.nonce_a = std::array<uint8_t, 32>{};
        for (size_t i = 0; i < out.nonce_a.size(); ++i) {
            out.nonce_a[i] = static_cast<uint8_t>(i + nonce_a_seed);
        }

        auto digest = pairing_code_digest(out.handshake_hash.data(), out.handshake_hash.size(),
                                          out.nonce_a.data(), out.nonce_a.size(), nonce_b.data(),
                                          nonce_b.size());
        ASSERT_TRUE(digest.has_value());
        if (conn->pairing_session().format == SendspinPairingCodeFormat::QR_CODE) {
            auto code = pairing_code_qr_bytes(digest.value());
            out.prs.assign(code.begin(), code.end());
            out.emitted = format_pairing_code_token(code);
        } else {
            out.emitted = pairing_code_digits(digest.value());
            out.prs = pairing_code_digits_prs(out.emitted);
        }

        ServerPairingMessageEvent pair_init_event;
        pair_init_event.conn = this->current_connection_sp();
        pair_init_event.kind = PairingMessageKind::PAIR_INIT;
        pair_init_event.nonce_a = out.nonce_a;
        this->schedule_pairing_message_event(std::move(pair_init_event));
        this->client_->loop();

        ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_CODE));
    }

    /// Complete the server/pair-auth leg of a pairing attempt already at PAIR_INIT: schedules+pumps
    /// server/pair-auth carrying `server`'s public share, asserts the device answered with
    /// client/pair-auth(pake_msg_2), then feeds that share into `server`'s CPace and returns the
    /// resulting server_kc via `server_kc_out` (pairing.md "PAKE"). Callers that need a genuine
    /// server_kc for a successful PAIR_CONFIRM use this; the code-mismatch test fabricates its
    /// own bogus server_kc instead and drives PAIR_AUTH inline (it never calls derive()/tag()).
    void drive_pair_auth(FakeConnection* conn, ServerStandIn& server,
                         std::array<uint8_t, CPACE_TAG_SIZE>& server_kc_out) {
        ServerPairingMessageEvent pair_auth_event;
        pair_auth_event.conn = this->current_connection_sp();
        pair_auth_event.kind = PairingMessageKind::PAIR_AUTH;
        pair_auth_event.pake_msg_1 = server.initiator.public_share();
        this->schedule_pairing_message_event(std::move(pair_auth_event));
        this->client_->loop();

        ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");
        JsonDocument auth_doc;
        JsonObject auth_root;
        ASSERT_TRUE(parse_json(conn->sent_text_.back(), auth_doc, auth_root));
        auto pake_msg_2_b64 = std::string(auth_root["payload"]["pake_msg_2"] | "");
        auto pake_msg_2 = b64url_decode(pake_msg_2_b64);
        ASSERT_TRUE(pake_msg_2.has_value());
        ASSERT_EQ(pake_msg_2->size(), 32u);

        ASSERT_TRUE(server.initiator.derive(pake_msg_2->data(), pake_msg_2->size()));
        auto server_kc = server.initiator.tag();
        ASSERT_TRUE(server_kc.has_value());
        server_kc_out = server_kc.value();
    }

    /// Schedule a server/pair-confirm(server_kc) event for the injected connection and pump
    /// loop(). Shared by every PAIR_CONFIRM step: the dispatch is identical whether server_kc
    /// is genuine or a code-mismatch test's fabricated tag.
    void schedule_pair_confirm(const std::array<uint8_t, CPACE_TAG_SIZE>& server_kc) {
        ServerPairingMessageEvent pair_confirm_event;
        pair_confirm_event.conn = this->current_connection_sp();
        pair_confirm_event.kind = PairingMessageKind::PAIR_CONFIRM;
        pair_confirm_event.server_kc = server_kc;
        this->schedule_pairing_message_event(std::move(pair_confirm_event));
        this->client_->loop();
    }

    /// Read ConnectionManager::pairing_rounds_since_verified_kc_, the count the dynamic-code
    /// round limit is measured against (pairing.md "Rounds"), through the private-access seam.
    uint32_t rounds_since_verified_kc() {
        return this->client_->connection_manager_->pairing_rounds_since_verified_kc_;
    }

    /// Force that same count, so a test can stand one round short of the limit without driving
    /// every round before it. Tests whose subject IS the limit drive the rounds for real.
    void set_rounds_since_verified_kc(uint32_t rounds) {
        this->client_->connection_manager_->pairing_rounds_since_verified_kc_ = rounds;
    }

    /// Begin the next round of a dynamic attempt sitting in AWAIT_SERVER_PAIR_INIT after a
    /// client/pair-retry. A retry round's server/pair-init carries no nonce_A: the binding
    /// values, and so the pairing code the operator is looking at, do not move between rounds
    /// (pairing.md "Rounds").
    void schedule_retry_round_pair_init() {
        ServerPairingMessageEvent event;
        event.conn = this->current_connection_sp();
        event.kind = PairingMessageKind::PAIR_INIT;
        this->schedule_pairing_message_event(std::move(event));
        this->client_->loop();
    }

    /// Run one whole round that the "server" fails deliberately: it starts CPace over the code
    /// the device actually emitted, under `round`'s sid, so derive() succeeds and only the
    /// confirmation tag is wrong, then answers with a fabricated server_kc. This is the shape a
    /// mistyped code produces at this point in the exchange, as opposed to a low-order-point
    /// derive() failure. Leaves the client wherever its round accounting put it: another
    /// client/pair-retry, or the pair/abort that ends the attempt.
    void drive_failed_round(FakeConnection* conn, const CodeEmissionResult& display,
                            uint32_t round) {
        ServerStandIn server;
        ASSERT_TRUE(server.start(display.prs, display.handshake_hash, /*pairing_index=*/1, round));

        ServerPairingMessageEvent pair_auth_event;
        pair_auth_event.conn = this->current_connection_sp();
        pair_auth_event.kind = PairingMessageKind::PAIR_AUTH;
        pair_auth_event.pake_msg_1 = server.initiator.public_share();
        this->schedule_pairing_message_event(std::move(pair_auth_event));
        this->client_->loop();
        ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");

        std::array<uint8_t, CPACE_TAG_SIZE> bogus_server_kc{};
        bogus_server_kc.fill(0xAB);
        this->schedule_pair_confirm(bogus_server_kc);
    }

    /// Run one whole static-pairing-code attempt on `conn` that the "server" fails deliberately.
    /// `pairing_index` is the index this attempt's activate carries, which the sid binds and so
    /// the stand-in must run under. Enters pairing, expects the attempt to start without a
    /// further gesture (the window is open), drives the CPace exchange under the correct code,
    /// and answers with a fabricated server_kc.
    void drive_failed_static_attempt(FakeConnection* conn, const std::string& code,
                                     uint32_t pairing_index) {
        this->enter_pairing(conn);
        this->client_->loop();
        ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");

        ServerStandIn server;
        ASSERT_TRUE(server.start(pairing_code_digits_prs(code),
                                 conn->pairing_session().handshake_hash, pairing_index,
                                 /*round=*/1));

        ServerPairingMessageEvent pair_auth_event;
        pair_auth_event.conn = this->current_connection_sp();
        pair_auth_event.kind = PairingMessageKind::PAIR_AUTH;
        pair_auth_event.pake_msg_1 = server.initiator.public_share();
        this->schedule_pairing_message_event(std::move(pair_auth_event));
        this->client_->loop();
        ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");

        std::array<uint8_t, CPACE_TAG_SIZE> bogus_server_kc{};
        bogus_server_kc.fill(0xCD);
        this->schedule_pair_confirm(bogus_server_kc);
        ASSERT_EQ(last_pair_abort_reason(conn->sent_text_), "pairing_code_mismatch");
    }

    /// Verify the second-to-last frame, client/pair-confirm, carries client_kc and, only in the
    /// dynamic flow, wrapped_nonce_B; then verify the last frame is client/pair-finalize.
    /// `expect_wrapped_nonce` distinguishes the dynamic flow (which opens its commitment
    /// alongside the confirm) from the static one (which sends no commit_B and so has nothing to
    /// open). Callers assert the frame count first, since the required minimum differs by flow.
    void verify_pair_confirm_frame(const std::vector<std::string>& sent_text,
                                   bool expect_wrapped_nonce) {
        JsonDocument confirm_doc;
        JsonObject confirm_root;
        const std::string& confirm_frame = sent_text[sent_text.size() - 2];
        ASSERT_TRUE(parse_json(confirm_frame, confirm_doc, confirm_root));
        EXPECT_STREQ(confirm_root["type"], "client/pair-confirm");
        EXPECT_TRUE(confirm_root["payload"]["client_kc"].is<const char*>());
        // The opening never crosses the wire in the clear under any name (pairing.md "Wrapping").
        EXPECT_TRUE(confirm_root["payload"]["nonce_B"].isUnbound())
            << "nonce_B must never be sent unwrapped";
        if (expect_wrapped_nonce) {
            EXPECT_TRUE(confirm_root["payload"]["wrapped_nonce_B"].is<const char*>())
                << "the dynamic flow's pair-confirm must carry wrapped_nonce_B";
        } else {
            EXPECT_TRUE(confirm_root["payload"]["wrapped_nonce_B"].isUnbound())
                << "the static flow's pair-confirm must NOT carry wrapped_nonce_B";
        }
        EXPECT_EQ(last_frame_type(sent_text), "client/pair-finalize");
    }

    /// Verify the sealed commitment opening (pairing.md "Wrapping"): the client/pair-confirm
    /// frame's wrapped_nonce_B must unwrap, under the key `server` derives independently from
    /// its own sid and ISK, to the preimage of the commit_B the attempt opened with. A
    /// successful decrypt proves the client used the nonce-wrap label and this round's key; the
    /// commitment check proves it sealed the nonce it actually committed to, which is the
    /// binding the server re-derives the pairing code from.
    void verify_wrapped_nonce_opens_commit(const std::vector<std::string>& sent_text,
                                           const ServerStandIn& server) {
        // Frame 0 is the client/pair-init that carried commit_B; the confirm is second to last.
        ASSERT_GE(sent_text.size(), 2u);
        JsonDocument init_doc;
        JsonObject init_root;
        ASSERT_TRUE(parse_json(sent_text.front(), init_doc, init_root));
        ASSERT_STREQ(init_root["type"], "client/pair-init");
        auto commit_b = b64url_decode(std::string(init_root["payload"]["commit_B"] | ""));
        ASSERT_TRUE(commit_b.has_value());

        JsonDocument confirm_doc;
        JsonObject confirm_root;
        ASSERT_TRUE(parse_json(sent_text[sent_text.size() - 2], confirm_doc, confirm_root));
        auto wrapped_bytes =
            b64url_decode(std::string(confirm_root["payload"]["wrapped_nonce_B"] | ""));
        ASSERT_TRUE(wrapped_bytes.has_value());
        ASSERT_EQ(wrapped_bytes->size(), WRAPPED_VALUE_SIZE);
        std::array<uint8_t, WRAPPED_VALUE_SIZE> wrapped{};
        std::memcpy(wrapped.data(), wrapped_bytes->data(), WRAPPED_VALUE_SIZE);

        ASSERT_TRUE(server.initiator.isk().has_value());
        auto nonce_b = unwrap_value_as_server(NONCE_WRAP_LABEL, "ChaChaPoly", server.initiator.sid(),
                                    server.initiator.isk().value(), wrapped);
        ASSERT_TRUE(nonce_b.has_value()) << "server-side unwrap of wrapped_nonce_B failed";
        EXPECT_TRUE(pairing_code_verify_commit(nonce_b->data(), nonce_b->size(), commit_b->data(),
                                               commit_b->size()))
            << "the revealed nonce does not open the commitment sent in client/pair-init";
    }

    /// Verify the sealed PSK (pairing.md "Wrapping"): the last captured frame must be
    /// client/pair-finalize carrying wrapped_psk (never long_term_psk in a code flow), and
    /// `server` (using its own independently-derived ISK/sid, exactly as a real server would)
    /// must be able to unwrap it. A successful AEAD decrypt here proves the client used the
    /// same K_wrap the server derives.
    void verify_wrapped_psk_finalize(const std::vector<std::string>& sent_text,
                                     const ServerStandIn& server) {
        JsonDocument finalize_doc;
        JsonObject finalize_root;
        ASSERT_TRUE(parse_json(sent_text.back(), finalize_doc, finalize_root));
        EXPECT_TRUE(finalize_root["payload"]["long_term_psk"].isUnbound())
            << "code flows must not send long_term_psk in the clear";
        ASSERT_TRUE(finalize_root["payload"]["wrapped_psk"].is<const char*>());
        auto wrapped_bytes =
            b64url_decode(std::string(finalize_root["payload"]["wrapped_psk"] | ""));
        ASSERT_TRUE(wrapped_bytes.has_value());
        ASSERT_EQ(wrapped_bytes->size(), WRAPPED_VALUE_SIZE);
        std::array<uint8_t, WRAPPED_VALUE_SIZE> wrapped_psk{};
        std::memcpy(wrapped_psk.data(), wrapped_bytes->data(), WRAPPED_VALUE_SIZE);

        ASSERT_TRUE(server.initiator.isk().has_value());
        auto unwrapped = unwrap_value_as_server(PSK_WRAP_LABEL, "ChaChaPoly", server.initiator.sid(),
                                    server.initiator.isk().value(), wrapped_psk);
        ASSERT_TRUE(unwrapped.has_value()) << "server-side unwrap_psk failed";
        EXPECT_EQ(unwrapped->size(), 32u);
    }

    std::unique_ptr<SendspinClient> client_;
    RecordingListener listener_;
    FakeNetworkProvider network_provider_;
    FakePersistenceProvider persistence_provider_;

    // Construction-time inputs replayed by build_client() on every rebuild.
    bool pairing_code_emission_supported_{true};
    bool pairing_window_supported_{true};
    std::vector<std::string> pairing_psk_locations_;
    std::vector<std::string> static_pairing_code_locations_;
    std::optional<std::string> static_pairing_code_;
    /// Keeps the last-injected FakeConnection alive independently of ConnectionManager's slot
    /// (see inject_current_connection). Only one connection is injected per test.
    std::shared_ptr<SendspinConnection> injected_conn_;
};

// ============================================================================
// Dynamic pairing code: happy path
// ============================================================================

TEST_F(PairingStateMachineTest, DynamicCodeHappyPath) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-1");

    // client/pair-init(commit_B) was emitted, and on_pairing_started + on_display_pairing_code
    // have NOT fired yet (the code is only derived once server/pair-init supplies nonce_A).
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(this->listener_.events_.front().server_id, "server-dyn-1");
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::DISPLAY_CODE));

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/1, display));
    EXPECT_EQ(this->listener_.last_emitted_code(), display.emitted);

    // Simulated server (INITIATOR) starts CPace with the same derived code.
    ServerStandIn server;
    ASSERT_TRUE(server.start(display.prs, display.handshake_hash));

    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    ASSERT_NO_FATAL_FAILURE(this->drive_pair_auth(conn, server, server_kc));

    this->schedule_pair_confirm(server_kc);

    ASSERT_GE(conn->sent_text_.size(), 4u);
    ASSERT_NO_FATAL_FAILURE(
        this->verify_pair_confirm_frame(conn->sent_text_, /*expect_wrapped_nonce=*/true));

    ASSERT_NO_FATAL_FAILURE(this->verify_wrapped_nonce_opens_commit(conn->sent_text_, server));
    ASSERT_NO_FATAL_FAILURE(this->verify_wrapped_psk_finalize(conn->sent_text_, server));

    // Success callbacks: on_clear_pairing_code fires (display -> clear ordering).
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_CODE));
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::DISPLAY_CODE),
             this->listener_.first_index_of(PairingEventKind::CLEAR_CODE));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
}

// The qr_code emission format, driven the whole way: the code the operator carries is a
// version-1 pairing token over the digest's first bytes, and CPace consumes those raw bytes as
// PRS rather than the token's text (pairing.md "Pairing code derivation", "PAKE").
TEST_F(PairingStateMachineTest, DynamicCodeQrFormatHappyPath) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-qr",
                                                            SendspinPairingCodeFormat::QR_CODE);

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/7, display));

    // What the application is handed is the token, tagged as the format the server asked for.
    EXPECT_EQ(this->listener_.last_emitted_format(), SendspinPairingCodeFormat::QR_CODE);
    ASSERT_TRUE(this->listener_.last_emitted_code().has_value());
    const std::string emitted = this->listener_.last_emitted_code().value();
    EXPECT_EQ(emitted.rfind("SP:1", 0), 0u) << "a qr_code pairing code is a version-1 token";
    EXPECT_EQ(emitted.size(), 43u);
    EXPECT_EQ(emitted.find('='), std::string::npos) << "the token carries no base32 padding";

    // The server derives the same 24 bytes and runs CPace over them, not over the token text.
    EXPECT_EQ(display.prs.size(), QR_PAIRING_CODE_SIZE);
    EXPECT_NE(display.prs, pairing_code_digits_prs(emitted))
        << "the token's characters are not the PRS";
    ServerStandIn server;
    ASSERT_TRUE(server.start(display.prs, display.handshake_hash));

    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    ASSERT_NO_FATAL_FAILURE(this->drive_pair_auth(conn, server, server_kc));
    this->schedule_pair_confirm(server_kc);

    ASSERT_NO_FATAL_FAILURE(
        this->verify_pair_confirm_frame(conn->sent_text_, /*expect_wrapped_nonce=*/true));
    ASSERT_NO_FATAL_FAILURE(this->verify_wrapped_nonce_opens_commit(conn->sent_text_, server));
    ASSERT_NO_FATAL_FAILURE(this->verify_wrapped_psk_finalize(conn->sent_text_, server));
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_CODE));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
}

// A pairing attempt that reaches PAIR_CONFIRM success already dismisses the emitted code there (see
// the PAIR_CONFIRM handler in connection_manager.cpp). If a pair/abort then ends the same attempt
// a second time via abort_pairing_attempt(), on_clear_pairing_code must NOT fire again for the code
// this attempt already stopped emitting.
TEST_F(PairingStateMachineTest, AbortAfterConfirmDoesNotReclearAlreadyWithdrawnCode) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-abort-after-confirm");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/1, display));

    ServerStandIn server;
    ASSERT_TRUE(server.start(display.prs, display.handshake_hash));

    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    ASSERT_NO_FATAL_FAILURE(this->drive_pair_auth(conn, server, server_kc));

    this->schedule_pair_confirm(server_kc);

    // PAIR_CONFIRM succeeded: client/pair-finalize was sent, and the code was already dismissed
    // exactly once.
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-finalize");
    ASSERT_EQ(this->listener_.count(PairingEventKind::CLEAR_CODE), 1);
    ASSERT_FALSE(this->listener_.fired(PairingEventKind::FAILED));

    // The server now aborts the exchange after the code was already dismissed (it can do this
    // any time before the attempt concludes, e.g. the operator cancelled on its side).
    PairAbortEvent abort_event;
    abort_event.conn = this->current_connection_sp();
    abort_event.reason = PairAbortReason::USER_CANCELLED;
    this->schedule_abort(std::move(abort_event));
    this->client_->loop();

    // The attempt now fails, but on_clear_pairing_code must NOT fire a second time:
    // code_emitted was already reset to false at PAIR_CONFIRM.
    EXPECT_EQ(this->listener_.count(PairingEventKind::CLEAR_CODE), 1)
        << "on_clear_pairing_code must not fire twice for one pairing attempt";
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::USER_CANCELLED);
}

// ============================================================================
// pairing.md "Rounds": a server_kc that does not verify means the operator entered a code this
// device did not emit. The dynamic flow answers with another round rather than ending the
// attempt, each round runs its own CPace under its own sid, and the attempt only fails once the
// round limit is reached.
// ============================================================================

TEST_F(PairingStateMachineTest, DynamicCodeMismatchAsksForAnotherRound) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-2");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/2, display));
    const int emissions_before_retry = this->listener_.count(PairingEventKind::DISPLAY_CODE);

    ASSERT_NO_FATAL_FAILURE(this->drive_failed_round(conn, display, /*round=*/1));

    // The attempt continues: client/pair-retry, no pair/abort, and nothing that would end the
    // attempt locally.
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-retry");
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "")
        << "a retryable mismatch must not send pair/abort";
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::SUCCEEDED));
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_TRUE(conn->is_pairing_in_progress())
        << "the attempt survives a failed round, so its in-progress flag must stand";

    // The operator keeps looking at the same code, so it is neither withdrawn nor re-emitted
    // (pairing.md "Client verification").
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::CLEAR_CODE));
    EXPECT_EQ(this->listener_.count(PairingEventKind::DISPLAY_CODE), emissions_before_retry);

    EXPECT_EQ(this->rounds_since_verified_kc(), 1u);
}

TEST_F(PairingStateMachineTest, RetryRoundRunsTheNextRoundsSid) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-retry-sid");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/3, display));
    ASSERT_NO_FATAL_FAILURE(this->drive_failed_round(conn, display, /*round=*/1));
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-retry");

    // Round 2: the server sends server/pair-init again, without nonce_A, and runs CPace under
    // the sid whose round counter now reads 2.
    this->schedule_retry_round_pair_init();
    ServerStandIn server;
    ASSERT_TRUE(server.start(display.prs, display.handshake_hash, /*pairing_index=*/1,
                             /*round=*/2));

    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    ASSERT_NO_FATAL_FAILURE(this->drive_pair_auth(conn, server, server_kc));
    this->schedule_pair_confirm(server_kc);

    // Only a second round derived over the round-2 sid produces a server_kc this client
    // verifies, so reaching pair-confirm at all is the assertion: the sid moved with the round.
    ASSERT_NO_FATAL_FAILURE(
        this->verify_pair_confirm_frame(conn->sent_text_, /*expect_wrapped_nonce=*/true));
    ASSERT_NO_FATAL_FAILURE(this->verify_wrapped_nonce_opens_commit(conn->sent_text_, server));
    ASSERT_NO_FATAL_FAILURE(this->verify_wrapped_psk_finalize(conn->sent_text_, server));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));

    // The verified server_kc is what the round limit counts back from.
    EXPECT_EQ(this->rounds_since_verified_kc(), 0u);
}

TEST_F(PairingStateMachineTest, RetryRoundRejectsAReplayOfTheFirstRoundsSid) {
    // Control for RetryRoundRunsTheNextRoundsSid: the same second round, with the same correct
    // pairing code, fails when the server reuses round 1's sid. Without the round in the sid the
    // two runs would agree and this would confirm.
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-replay-sid");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/4, display));
    ASSERT_NO_FATAL_FAILURE(this->drive_failed_round(conn, display, /*round=*/1));
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-retry");

    this->schedule_retry_round_pair_init();
    ServerStandIn server;
    ASSERT_TRUE(server.start(display.prs, display.handshake_hash, /*pairing_index=*/1,
                             /*round=*/1));

    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    ASSERT_NO_FATAL_FAILURE(this->drive_pair_auth(conn, server, server_kc));
    this->schedule_pair_confirm(server_kc);

    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-retry");
    EXPECT_FALSE(any_frame_of_type(conn->sent_text_, "client/pair-confirm"));
    EXPECT_EQ(this->rounds_since_verified_kc(), 2u);
}

TEST_F(PairingStateMachineTest, RoundLimitEndsTheAttemptWithPairingCodeMismatch) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-round-limit");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/5, display));

    // Round 1 already ran to its server/pair-init above; every later round opens with the
    // retry-round server/pair-init the client's client/pair-retry asks for.
    uint32_t round = 1;
    for (;; ++round) {
        ASSERT_NO_FATAL_FAILURE(this->drive_failed_round(conn, display, round));
        if (last_frame_type(conn->sent_text_) != "client/pair-retry") {
            break;
        }
        ASSERT_LT(round, 64u) << "the client must stop retrying at some point";
        this->schedule_retry_round_pair_init();
    }

    // pairing.md "Rounds" caps a dynamic pairing code at 20 rounds since the last verified
    // server_kc, so the twentieth failure is the one that ends the attempt.
    EXPECT_EQ(round, 20u);
    EXPECT_EQ(this->rounds_since_verified_kc(), 20u);
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "pairing_code_mismatch");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::PAIRING_CODE_MISMATCH);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_CODE));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::SUCCEEDED));
    EXPECT_EQ(conn->disconnect_count_, 0)
        << "pairing_code_mismatch leaves the connection open (pairing.md 'pair/abort')";
}

TEST_F(PairingStateMachineTest, StandingRoundLimitHoldsTheNextAttemptForAGesture) {
    // A dynamic attempt is normally ungated. Once the round limit stands, pairing.md "Rounds"
    // requires a deliberate operator action before another attempt may run, which is the same
    // gesture the pairing window is opened by.
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-gate-control");
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init")
        << "control: without a standing limit the attempt starts unprompted";
    ASSERT_FALSE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    this->set_rounds_since_verified_kc(20);
    conn->sent_text_.clear();
    this->enter_pairing(conn);
    this->client_->loop();

    // pairing.md "Rounds": while the limit holds an attempt back the client says so with
    // client/pair-pending, and starts nothing until the gesture admits it.
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_FALSE(any_frame_of_type(conn->sent_text_, "client/pair-init"));
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    this->client_->confirm_pairing_window();
    this->client_->loop();

    EXPECT_EQ(this->rounds_since_verified_kc(), 0u)
        << "the gesture clears the standing limit before what it admits can run";
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// ============================================================================
// pairing.md "Entering and leaving pairing": pairing runs alongside playback, so a declared
// 'pairing' activity suppresses nothing. Traffic keeps flowing across an attempt and across the
// retry window between a local abort and the server's next server/activate.
// ============================================================================

TEST_F(PairingStateMachineTest, TrafficContinuesWhileActivitiesDeclarePairing) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-suppress");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/9, display));

    // Stand at the round limit so the wrong server_kc below ends the attempt instead of asking
    // for another round: the abort, not the retry, is what this test needs to keep traffic
    // flowing across.
    this->set_rounds_since_verified_kc(20);

    // Wrong server_kc: a genuine code mismatch (not concurrent_attempt), so
    // local_abort_pairing keeps the connection open (PairingDropAction::KEEP_OPEN) instead
    // of closing it.
    ASSERT_NO_FATAL_FAILURE(this->drive_failed_round(conn, display, /*round=*/1));

    ASSERT_EQ(last_pair_abort_reason(conn->sent_text_), "pairing_code_mismatch");
    ASSERT_EQ(conn->disconnect_count_, 0) << "pairing_code_mismatch must leave the connection open";
    ASSERT_FALSE(conn->is_pairing_in_progress())
        << "clear_pairing_state() must clear the local attempt flag on abort";
    ASSERT_TRUE(conn->has_activity(SendspinActivity::PAIRING))
        << "activities_ is untouched by a local abort: only the next server/activate updates it";

    // Complete the hello preconditions is_operational() also requires. A real connection would
    // already have these true long before any server/activate (this one included); the fixture's
    // inject/enter-pairing helpers never touch them, so they are set explicitly here purely to
    // exercise SendspinClient::loop()'s time-burst gate, which is otherwise unreachable through
    // this harness.
    conn->set_client_hello_sent(true);
    conn->set_server_hello_received(true);
    ASSERT_TRUE(conn->is_operational());

    // A fresh SendspinTimeBurst starts its first burst immediately (last_burst_complete_time_
    // defaults to 0, so the inter-burst wait is trivially satisfied), so any tick that reaches
    // time_burst_->loop() sends. The connection still declares 'pairing', which must not stop it:
    // a player keeps its timeline across an attempt and can only do that with a converging filter.
    for (int i = 0; i < 5; ++i) {
        this->client_->loop();
    }
    EXPECT_GT(conn->time_message_send_count_, 0)
        << "client/time must keep flowing while activities declare pairing";

    this->client_->update_state(SendspinClientState::SYNCHRONIZED);
    EXPECT_TRUE(any_frame_of_type(conn->sent_text_, "client/state"))
        << "client/state must keep flowing while activities declare pairing";

    // The activate that leaves pairing changes nothing about any of this.
    const int before_leave = conn->time_message_send_count_;
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    ASSERT_FALSE(conn->has_activity(SendspinActivity::PAIRING));
    EXPECT_GE(conn->time_message_send_count_, before_leave)
        << "time sync must not stall when the connection leaves pairing either";
}

// ============================================================================
// The attempt timeout inside the re-handshake window
// ============================================================================

// connection.md "Re-handshake": between Noise message 1 and the new server/activate the client
// starts no application message but the handshake, and a pair/abort would be one. pairing.md
// "Entering and leaving pairing" has an expired attempt send pair/abort; the narrower MUST NOT
// wins for the length of the window, and the abort waits for the activation instead.
TEST_F(PairingStateMachineTest, AttemptTimeoutAbortWaitsForThePostRekeyActivate) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-rekey-timeout");
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    const size_t frames_before = conn->sent_text_.size();

    // The attempt's deadline expires while the connection awaits an activation, exactly as it
    // would between a server's Noise message 1 and the activate that follows the swap.
    this->set_awaiting_activate(conn, true);
    conn->pairing_session().attempt_deadline_us = platform_time_us() - 1;

    for (int i = 0; i < 5; ++i) {
        this->client_->loop();
    }
    EXPECT_EQ(conn->sent_text_.size(), frames_before)
        << "pair/abort must not be sent while the connection awaits a server/activate";
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT)
        << "the attempt is held, not abandoned";
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));

    // Control: the same expired deadline aborts on the next tick once the activation has landed,
    // so the hold is the window and not something that swallowed the timeout outright.
    this->set_awaiting_activate(conn, false);
    this->client_->loop();
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "attempt_timeout");
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
}

// ============================================================================
// Dynamic pairing code: attempt timeout
// ============================================================================

TEST_F(PairingStateMachineTest, DynamicCodeAttemptTimeout) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-3", SendspinPairMethod::DYNAMIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");

    // Force the attempt deadline into the past; the next loop() tick must detect and abort it.
    conn->pairing_session().attempt_deadline_us = platform_time_us() - 1;
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "attempt_timeout");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::ATTEMPT_TIMEOUT);
    // No code was ever emitted for this session (timed out before server/pair-init), so
    // on_clear_pairing_code must NOT fire (code_emitted was never set).
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::CLEAR_CODE));
}

// ============================================================================
// Sequence violations
// ============================================================================

// pairing.md "Sequence violations": a pairing message out of sequence for the selected method
// and the current state is a protocol error, and "Protocol Errors" closes the connection
// without any application-level message. No pair/abort names a reason for it.

TEST_F(PairingStateMachineTest, StaticCodeAttemptClosesOnServerPairInit) {
    // server/pair-init belongs to the dynamic flow alone: the static flow runs from
    // client/pair-init straight to server/pair-auth.
    this->configure_static_pairing_code("13572468");
    FakeConnection* conn = this->inject_current_connection("server-static-seq",
                                                           SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    const size_t frames_before = conn->sent_text_.size();

    ServerPairingMessageEvent pair_init_event;
    pair_init_event.conn = this->current_connection_sp();
    pair_init_event.kind = PairingMessageKind::PAIR_INIT;
    pair_init_event.nonce_a = std::array<uint8_t, 32>{};
    this->schedule_pairing_message_event(std::move(pair_init_event));
    this->client_->loop();

    EXPECT_EQ(conn->sent_text_.size(), frames_before)
        << "a sequence violation sends no application-level message, pair/abort included";
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "");
    EXPECT_EQ(conn->disconnect_count_, 0) << "the close carries no client/goodbye either";
    EXPECT_EQ(this->current_connection(), nullptr);
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
}

TEST_F(PairingStateMachineTest, OutOfSequenceServerPairAuthClosesSilently) {
    // server/pair-auth while the attempt is still waiting for server/pair-init.
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-seq-auth");
    ASSERT_EQ(conn->pairing_session().step,
              SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT);
    const size_t frames_before = conn->sent_text_.size();

    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = this->current_connection_sp();
    pair_auth_event.kind = PairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1 = std::array<uint8_t, 32>{};
    this->schedule_pairing_message_event(std::move(pair_auth_event));
    this->client_->loop();

    EXPECT_EQ(conn->sent_text_.size(), frames_before)
        << "a sequence violation sends no application-level message, pair/abort included";
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "");
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_EQ(this->current_connection(), nullptr);
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
}

TEST_F(PairingStateMachineTest, OutOfSequenceServerPairConfirmClosesSilently) {
    // server/pair-confirm before the exchange has produced anything to confirm.
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-seq-confirm");
    ASSERT_EQ(conn->pairing_session().step,
              SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT);
    const size_t frames_before = conn->sent_text_.size();

    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    this->schedule_pair_confirm(server_kc);

    EXPECT_EQ(conn->sent_text_.size(), frames_before)
        << "a sequence violation sends no application-level message, pair/abort included";
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "")
        << "in particular not pairing_code_mismatch: nothing was verified";
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_EQ(this->current_connection(), nullptr);
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
}

// ============================================================================
// Dynamic pairing code: malformed server frame
// ============================================================================

// pairing.md "Protocol Errors": "a malformed or missing field ... is a protocol error: the
// detecting side closes the WebSocket without sending any application-level error message, and
// persists nothing." This pins that behavior for the MALFORMED case in
// ConnectionManager::handle_pairing_message: no pair/abort, and the connection closes.

TEST_F(PairingStateMachineTest, DynamicCodeMalformedFrameDuringSessionClosesSilently) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-4", SendspinPairMethod::DYNAMIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent malformed_event;
    malformed_event.conn = current_conn_sp;
    malformed_event.kind = PairingMessageKind::MALFORMED;
    this->schedule_pairing_message_event(std::move(malformed_event));
    this->client_->loop();

    // No pair/abort, or any other application-level message, is sent.
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    // The close goes through drop_connection() with goodbye=std::nullopt (no client/goodbye
    // either), so disconnect_count_ stays 0, unlike
    // PairAbortConcurrentAttemptStillClosesConnection, which does send a goodbye.
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_EQ(this->current_connection(), nullptr)
        << "a malformed pairing frame during an active pairing-code session must close the connection";
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE)
        << "clear_pairing_state() must have reset the pairing session (persists nothing)";
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
}

TEST_F(PairingStateMachineTest, DynamicCodeMalformedFrameWithNoActiveSessionIsIgnored) {
    // A connection with no active pairing-code session (pairing_session().step == IDLE) at all: a
    // stray
    // malformed pairing frame must not tear anything down.
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-5", SendspinPairMethod::DYNAMIC_PAIRING_CODE);
    ASSERT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE);

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent malformed_event;
    malformed_event.conn = current_conn_sp;
    malformed_event.kind = PairingMessageKind::MALFORMED;
    this->schedule_pairing_message_event(std::move(malformed_event));
    this->client_->loop();

    EXPECT_TRUE(conn->sent_text_.empty());
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::CLEAR_CODE));
}

// ============================================================================
// Dynamic pairing code: CPace derive() failure on server/pair-auth (low-order/malformed share)
// ============================================================================

// pairing.md "Protocol Errors": "a CPace share with the wrong length or encoding a low-order point"
// is
// a protocol error, not a pairing_code_mismatch: the detecting side closes the WebSocket without
// sending
// any application-level error message, and persists nothing. A derive() failure happens on the
// peer's raw share BEFORE the code-derived generator can even be compared, so it can never be
// produced by an operator simply mistyping the code (that produces a well-formed shared secret
// that only fails the confirm-tag check exercised by DynamicCodeMismatchAsksForAnotherRound above).
TEST_F(PairingStateMachineTest, DynamicCodeDeriveFailureOnPairAuthClosesSilently) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-7", SendspinPairMethod::DYNAMIC_PAIRING_CODE);
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
    pair_init_event.kind = PairingMessageKind::PAIR_INIT;
    pair_init_event.nonce_a = nonce_a;
    this->schedule_pairing_message_event(std::move(pair_init_event));
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::DISPLAY_CODE));
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_AUTH);

    // server/pair-auth with an all-zero pake_msg_1: a well-formed-length but low-order X25519
    // point, so CPace::derive() fails on the peer share itself (see
    // CPaceDeriveRejects.AllZeroPeerShare in test_cpace.cpp), independent of any code value.
    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = current_conn_sp;
    pair_auth_event.kind = PairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1.fill(0);
    this->schedule_pairing_message_event(std::move(pair_auth_event));
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
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE)
        << "clear_pairing_state() must have reset the pairing session (persists nothing)";
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_CODE))
        << "A code was emitted for this session, so the close must clear it";
}

// pairing.md "Static Pairing Code Flow" gesture-gates every static attempt on a pairing window;
// the dynamic flow runs ungated. Without a window the client withholds client/pair-init and
// reports the wait with client/pair-pending instead.
TEST_F(PairingStateMachineTest, StaticPairingCodeAttemptIsGestureGated) {
    this->configure_static_pairing_code("24681357");

    FakeConnection* conn = this->inject_current_connection(
        "server-static-gated", SendspinPairMethod::STATIC_PAIRING_CODE);

    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
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
TEST_F(PairingStateMachineTest, StandingWindowAdmitsLaterGatedAttempt) {
    this->configure_static_pairing_code("13572468");

    // Gesture first: no attempt is waiting, so the window stands open.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    EXPECT_GT(this->window_deadline(), 0);

    // The gated (static pairing code) pairing activate arrives: pair-init goes out immediately.
    FakeConnection* conn =
        this->inject_current_connection("server-standing", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    EXPECT_FALSE(any_frame_of_type(conn->sent_text_, "client/pair-pending"));
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_AUTH);
    // Starting an attempt does not spend the window: it runs for its own lifetime, and binds to
    // the connection carrying this first attempt (pairing.md "Pairing Window").
    EXPECT_GT(this->window_deadline(), 0);
    EXPECT_EQ(this->window_connection(), conn);
}

// An expired standing window admits nothing: the gated attempt falls back to
// client/pair-pending and a fresh gesture.
TEST_F(PairingStateMachineTest, ExpiredStandingWindowDoesNotAdmit) {
    this->configure_static_pairing_code("13572468");

    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_GT(this->window_deadline(), 0);
    // Simulate the 5-minute lifetime passing.
    this->set_window_deadline(platform_time_us() - 1);

    FakeConnection* conn =
        this->inject_current_connection("server-expired", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
}

// ============================================================================
// pairing.md "Pairing Window": what closes an open window. Starting an attempt does not; a
// completed pairing, the fifth failed attempt, the drop of the connection the window is bound
// to, an operator cancellation and the lifetime expiry all do.
// ============================================================================

TEST_F(PairingStateMachineTest, WindowSurvivesFailedAttemptsUntilTheFifth) {
    const std::string code = "13572468";
    this->configure_static_pairing_code(code);

    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_GT(this->window_deadline(), 0);

    FakeConnection* conn =
        this->inject_current_connection("server-window-fail", SendspinPairMethod::STATIC_PAIRING_CODE);

    // The first four failures spend the window's budget without closing it: each following
    // attempt starts straight away, with no second gesture.
    for (uint32_t attempt = 1; attempt <= 4; ++attempt) {
        ASSERT_NO_FATAL_FAILURE(this->drive_failed_static_attempt(conn, code, attempt));
        EXPECT_GT(this->window_deadline(), 0) << "failure " << attempt << " must not close it";
        EXPECT_EQ(this->window_failed_attempts(), attempt);
    }

    ASSERT_NO_FATAL_FAILURE(this->drive_failed_static_attempt(conn, code, 5));
    EXPECT_EQ(this->window_deadline(), 0) << "the fifth failed attempt closes the window";

    // With the window closed, the next attempt is withheld for a fresh gesture again.
    conn->sent_text_.clear();
    this->enter_pairing(conn);
    this->client_->loop();
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
}

TEST_F(PairingStateMachineTest, CompletedPairingClosesTheWindow) {
    const std::string code = "13572468";
    this->configure_static_pairing_code(code);

    FakeConnection* conn =
        this->inject_current_connection("server-window-done", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    ASSERT_GT(this->window_deadline(), 0);

    ServerStandIn server;
    ASSERT_TRUE(server.start(pairing_code_digits_prs(code), conn->pairing_session().handshake_hash));
    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    ASSERT_NO_FATAL_FAILURE(this->drive_pair_auth(conn, server, server_kc));
    this->schedule_pair_confirm(server_kc);

    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-finalize");
    EXPECT_GT(this->window_deadline(), 0)
        << "the attempt is not a pairing until the server acks it: a server/activate arriving "
           "here instead would persist nothing";

    ASSERT_NO_FATAL_FAILURE(this->deliver_pair_finalize_ack(conn));
    EXPECT_EQ(this->window_deadline(), 0)
        << "the gesture was consent to pair, and the completed pairing spent it";
}

TEST_F(PairingStateMachineTest, WindowClosesWhenItsConnectionDrops) {
    this->configure_static_pairing_code("13572468");

    FakeConnection* conn = this->inject_current_connection("server-window-drop",
                                                           SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(this->window_connection(), conn);

    this->drop_connection(conn, SendspinGoodbyeReason::RESTART);

    EXPECT_EQ(this->window_deadline(), 0);
    EXPECT_EQ(this->window_connection(), nullptr);
}

TEST_F(PairingStateMachineTest, WindowAdmitsOnlyTheConnectionItIsBoundTo) {
    this->configure_static_pairing_code("13572468");

    this->client_->confirm_pairing_window();
    this->client_->loop();
    FakeConnection* bound = this->inject_current_connection("server-window-bound",
                                                            SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(bound);
    this->client_->loop();
    ASSERT_EQ(last_frame_type(bound->sent_text_), "client/pair-init");
    ASSERT_EQ(this->window_connection(), bound);

    // Hold the first connection alive so the second cannot reuse its address and pass the
    // binding check by accident.
    auto keep_alive = this->current_connection_sp();
    FakeConnection* other = this->inject_current_connection("server-window-other",
                                                            SendspinPairMethod::STATIC_PAIRING_CODE);
    ASSERT_NE(other, bound);
    this->enter_pairing(other);
    this->client_->loop();

    EXPECT_EQ(last_frame_type(other->sent_text_), "client/pair-pending")
        << "a second server must not ride a gesture the operator made for another one";
    EXPECT_EQ(other->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
    EXPECT_GT(this->window_deadline(), 0) << "the window still belongs to the bound connection";
}

TEST_F(PairingStateMachineTest, OperatorCancellationClosesTheWindowAndEndsTheWaitingAttempt) {
    this->configure_static_pairing_code("13572468");

    FakeConnection* conn = this->inject_current_connection("server-window-cancel",
                                                           SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    this->client_->cancel_pairing_window();
    this->client_->loop();

    EXPECT_EQ(this->window_deadline(), 0);
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "user_cancelled");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::USER_CANCELLED);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
}

TEST_F(PairingStateMachineTest, OperatorCancellationClosesAStandingWindow) {
    // Control for the test above: with no attempt waiting there is nothing to abort, but the
    // standing window is still closed, so the next attempt waits for a fresh gesture.
    this->configure_static_pairing_code("13572468");

    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_GT(this->window_deadline(), 0);

    this->client_->cancel_pairing_window();
    this->client_->loop();
    EXPECT_EQ(this->window_deadline(), 0);
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));

    FakeConnection* conn = this->inject_current_connection("server-window-recancel",
                                                           SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
}

// A gesture-gated attempt on a device with no pairing-window gesture UI
// (pairing_window_supported=false) must not fire the on_open_pairing_window prompt, whose
// contract requires the flag. The client/pair-pending the spec requires still goes out, and the
// attempt remains recoverable by a window opened through confirm_pairing_window(), which drives
// the same open_pairing_window() path.
TEST_F(PairingStateMachineTest, GatedAttemptWithoutWindowSupportSkipsPrompt) {
    this->init_client(/*pairing_code_emission_supported=*/true,
                      /*pairing_window_supported=*/false);
    this->configure_static_pairing_code("24681357");

    FakeConnection* conn = this->inject_current_connection(
        "server-static-nowindow", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::OPEN_WINDOW))
        << "on_open_pairing_window must not fire when pairing_window_supported is false";
    EXPECT_FALSE(conn->pairing_session().window_shown);

    // A window opened later still starts the waiting attempt.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// ============================================================================
// Static pairing code: happy path
// ============================================================================

TEST_F(PairingStateMachineTest, StaticCodeHappyPath) {
    this->configure_static_pairing_code("13572468");

    FakeConnection* conn =
        this->inject_current_connection("server-static-1", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();

    // Entering static pairing-code pairing (gesture-gated, no window open) sends
    // client/pair-pending
    // and surfaces the pairing-window prompt; nothing else is sent yet.
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending");
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::DISPLAY_CODE))
        << "static pairing code never emits a code from the device";

    const std::array<uint8_t, 32> handshake_hash = conn->pairing_session().handshake_hash;

    // Operator confirms the pairing-window gesture: this must send client/pair-init with no
    // commit_B, but WITH the required pairing_index (pairing.md "Pairing index").
    this->client_->confirm_pairing_window();
    this->client_->loop();

    ASSERT_EQ(conn->sent_text_.size(), 2u);
    JsonDocument init_doc;
    JsonObject init_root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), init_doc, init_root));
    EXPECT_STREQ(init_root["type"], "client/pair-init");
    ASSERT_TRUE(init_root["payload"].is<JsonObjectConst>());
    EXPECT_TRUE(init_root["payload"]["commit_B"].isUnbound())
        << "static pairing-code client/pair-init must not carry commit_B";
    ASSERT_TRUE(init_root["payload"]["pairing_index"].is<uint32_t>());
    EXPECT_EQ(init_root["payload"]["pairing_index"].as<uint32_t>(), 1u);

    ServerStandIn server;
    ASSERT_TRUE(server.start(pairing_code_digits_prs("13572468"), handshake_hash));

    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    ASSERT_NO_FATAL_FAILURE(this->drive_pair_auth(conn, server, server_kc));

    this->schedule_pair_confirm(server_kc);

    // client/pair-confirm must carry client_kc and no opening: the static flow sends no
    // commit_B, so there is nothing to open.
    ASSERT_GE(conn->sent_text_.size(), 2u);
    ASSERT_NO_FATAL_FAILURE(
        this->verify_pair_confirm_frame(conn->sent_text_, /*expect_wrapped_nonce=*/false));

    // PSK wrapping round-trip (pairing.md "Wrapping"), static flavor: see
    // verify_wrapped_psk_finalize()'s doc comment for the rationale.
    ASSERT_NO_FATAL_FAILURE(this->verify_wrapped_psk_finalize(conn->sent_text_, server));

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::OPEN_WINDOW),
             this->listener_.first_index_of(PairingEventKind::CLOSE_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
}

// ============================================================================
// Entered from a SUBSEQUENT activate
// ============================================================================

// A device that first goes operational on an empty server/activate must still enter static
// pairing-code
// pairing when the operator later triggers a SUBSEQUENT activate declaring [pairing].
// ConnectionManager::loop() must enter pairing on ANY pairing activate on an already-admitted
// connection, not only the first, or a later one is silently dropped as an ordinary "subsequent
// activate" and the pairing window never opens (messaging.md "server/activate": an activate may
// be re-sent to change the pairing parameters).
TEST_F(PairingStateMachineTest, SubsequentActivateEntersStaticCodePairing) {
    this->configure_static_pairing_code("13572468");

    FakeConnection* conn = this->inject_provisional_current_connection("server-static-sub");

    // First activate: empty activities -> connection goes operational, no pairing.
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    EXPECT_TRUE(conn->sent_text_.empty());

    // Subsequent activate: [pairing] + static_pairing_code -> must enter pairing, send
    // client/pair-pending, and prompt for the window gesture.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::STATIC_PAIRING_CODE);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW))
        << "a subsequent pairing activate must open the operator pairing window";
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-pending")
        << "only client/pair-pending is sent until the operator confirms";

    // Confirming the window sends the empty client/pair-init, proving the flow is live.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// Dynamic flavor: a subsequent activate declaring [pairing] + dynamic_pairing_code on an
// already-operational connection must enter pairing and send client/pair-init (commit_B)
// immediately (the dynamic flow is not gesture-gated, unlike the static one above).
TEST_F(PairingStateMachineTest, SubsequentActivateEntersDynamicCodePairing) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-dyn-sub");

    // First activate: empty activities -> connection goes operational, no pairing.
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_TRUE(conn->sent_text_.empty());

    // Subsequent activate: [pairing] + dynamic_pairing_code (with the emission format from the
    // pairing object) -> must enter pairing.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PAIRING_CODE,
                        SendspinPairingCodeFormat::DIGITS);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED))
        << "a subsequent pairing activate must start the dynamic pairing-code flow";
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// The client checks the emission format on receipt of the ACTIVATION (server/pair-init carries
// only nonce_A): a format the client does not offer, or none at all on a dynamic_pairing_code
// activation, is answered with pair/abort(method_not_supported), leaving the connection open
// (messaging.md "server/activate").
TEST_F(PairingStateMachineTest, UnofferedFormatOnActivationIsRejected) {
    // A device that offers only `digits`, so `qr_code` is a format it does not currently offer.
    this->init_client(/*pairing_code_emission_supported=*/false,
                      /*pairing_window_supported=*/true);
    {
        SendspinClientConfig& cfg = this->client_->config_;
        cfg.pairing_code_out_channels = {SendspinPairingCodeChannel::DISPLAY};
        cfg.pairing_code_formats = {SendspinPairingCodeFormat::DIGITS};
    }
    FakeConnection* conn = this->inject_provisional_current_connection("server-badformat");

    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    ASSERT_TRUE(conn->sent_text_.empty());

    // A format this device does not advertise.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PAIRING_CODE,
                        SendspinPairingCodeFormat::QR_CODE);
    this->client_->loop();

    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "method_not_supported");
    EXPECT_EQ(conn->disconnect_count_, 0) << "the connection must stay open after the abort";

    // Missing entirely on a dynamic_pairing_code activation (a required field): also rejected.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PAIRING_CODE, std::nullopt);
    this->client_->loop();
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "method_not_supported");
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));

    // Control: the format this device does advertise starts the attempt.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PAIRING_CODE,
                        SendspinPairingCodeFormat::DIGITS);
    this->client_->loop();
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED));
    ASSERT_EQ(conn->sent_text_.size(), 3u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
}

// A pairing activate that names no method (absent, or a method string the parser did not
// recognize) starts nothing, so the client must say so instead of ignoring the message: an
// unanswered pairing activate leaves the server waiting on the device indefinitely.
TEST_F(PairingStateMachineTest, PairingActivateWithoutMethodIsAborted) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-no-method");

    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();
    ASSERT_TRUE(conn->sent_text_.empty());

    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();

    EXPECT_FALSE(this->listener_.fired(PairingEventKind::STARTED));
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE);
    ASSERT_EQ(conn->sent_text_.size(), 1u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "pair/abort");
    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "method_not_supported");
    EXPECT_EQ(conn->disconnect_count_, 0) << "the connection must stay open after the abort";
}

// ============================================================================
// Static pairing code: mismatch
// ============================================================================

TEST_F(PairingStateMachineTest, StaticCodeMismatchRecordsFailureAndAborts) {
    this->configure_static_pairing_code("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-2", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    const std::array<uint8_t, 32> handshake_hash = conn->pairing_session().handshake_hash;
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");

    // Server uses the CORRECT static pairing code so derive() succeeds, then lies about server_kc.
    ServerStandIn server;
    ASSERT_TRUE(server.start(pairing_code_digits_prs("13572468"), handshake_hash));

    auto current_conn_sp = this->current_connection_sp();
    ServerPairingMessageEvent pair_auth_event;
    pair_auth_event.conn = current_conn_sp;
    pair_auth_event.kind = PairingMessageKind::PAIR_AUTH;
    pair_auth_event.pake_msg_1 = server.initiator.public_share();
    this->schedule_pairing_message_event(std::move(pair_auth_event));
    this->client_->loop();
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-auth");

    std::array<uint8_t, 64> bogus_server_kc{};
    bogus_server_kc.fill(0xCD);
    ServerPairingMessageEvent pair_confirm_event;
    pair_confirm_event.conn = current_conn_sp;
    pair_confirm_event.kind = PairingMessageKind::PAIR_CONFIRM;
    pair_confirm_event.server_kc = bogus_server_kc;
    this->schedule_pairing_message_event(std::move(pair_confirm_event));
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "pairing_code_mismatch");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::PAIRING_CODE_MISMATCH);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::SUCCEEDED));

    // Rounds belong to the dynamic pairing code alone (pairing.md "Rounds"): a static code the
    // operator mistyped is the same code on the next round, so the first failure is the last.
    EXPECT_FALSE(any_frame_of_type(conn->sent_text_, "client/pair-retry"));
    EXPECT_EQ(this->rounds_since_verified_kc(), 0u)
        << "the static flow runs no rounds to count";
}

// ============================================================================
// Static pairing code: the gesture wait is unbounded client-side
// ============================================================================

// client/pair-pending does not start the attempt or its timeout (spec: the server applies its
// own timeout and cancels via server/activate), so the wait for the gesture must not be
// aborted by the client's attempt-timeout check.
TEST_F(PairingStateMachineTest, GestureWaitHasNoClientTimeout) {
    this->configure_static_pairing_code("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-3", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    ASSERT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
    EXPECT_EQ(conn->pairing_session().attempt_deadline_us, 0)
        << "client/pair-pending must not arm the attempt timeout";

    // Further loop() ticks must not abort the waiting session.
    this->client_->loop();
    this->client_->loop();
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));

    // Once the gesture starts the attempt, the timeout IS armed and enforceable.
    this->client_->confirm_pairing_window();
    this->client_->loop();
    ASSERT_GT(conn->pairing_session().attempt_deadline_us, 0);
    conn->pairing_session().attempt_deadline_us = platform_time_us() - 1;
    this->client_->loop();

    EXPECT_EQ(last_pair_abort_reason(conn->sent_text_), "attempt_timeout");
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED));
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::ATTEMPT_TIMEOUT);
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::OPEN_WINDOW),
             this->listener_.first_index_of(PairingEventKind::CLOSE_WINDOW));
}

// ============================================================================
// Connection loss mid-pairing
// ============================================================================

TEST_F(PairingStateMachineTest, ConnectionLossDuringStaticPairingWindowClosesWindow) {
    this->configure_static_pairing_code("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-5", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));
    ASSERT_FALSE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW));
    ASSERT_TRUE(conn->pairing_session().window_shown);

    // Simulate the transport dying mid-window (before the operator ever confirms).
    this->simulate_connection_lost(conn);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLOSE_WINDOW))
        << "on_connection_lost must dismiss a stranded pairing-window prompt";
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::OPEN_WINDOW),
             this->listener_.first_index_of(PairingEventKind::CLOSE_WINDOW));
}

TEST_F(PairingStateMachineTest, ConnectionLossWhileEmittingCodeWithdrawsIt) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-7");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/3, display));

    ASSERT_FALSE(this->listener_.fired(PairingEventKind::CLEAR_CODE));
    ASSERT_TRUE(conn->pairing_session().code_emitted);

    // Connection dies while the code is still being emitted.
    this->simulate_connection_lost(conn);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_CODE))
        << "on_connection_lost must dismiss a stranded emitted code";
    EXPECT_LT(this->listener_.first_index_of(PairingEventKind::DISPLAY_CODE),
             this->listener_.first_index_of(PairingEventKind::CLEAR_CODE));
}

// ============================================================================
// Abort ordering survives cleanup_connection_state()
// ============================================================================

TEST_F(PairingStateMachineTest, CurrentConnectionAbortOrderingSurvivesCleanup) {
    // A current-connection abort (pair/abort from the server) must still deliver
    // on_pairing_failed AND on_clear_pairing_code even though cleanup_connection_state() wipes
    // the EventState pending-notification vectors: the note_* calls in
    // ConnectionManager::handle_pair_abort() must run strictly AFTER that wipe.
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-8");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/4, display));
    ASSERT_TRUE(conn->pairing_session().code_emitted);

    // The server aborts the exchange directly (pair/abort), which drives
    // ConnectionManager::handle_pair_abort() -> cleanup_connection_state() -> deferred note_*.
    PairAbortEvent abort_event;
    abort_event.conn = this->current_connection_sp();
    abort_event.reason = PairAbortReason::USER_CANCELLED;
    this->schedule_abort(std::move(abort_event));
    this->client_->loop();

    ASSERT_TRUE(this->listener_.fired(PairingEventKind::FAILED))
        << "on_pairing_failed must survive cleanup_connection_state()";
    EXPECT_EQ(this->listener_.last_failed_reason(), SendspinPairAbortReason::USER_CANCELLED);
    EXPECT_TRUE(this->listener_.fired(PairingEventKind::CLEAR_CODE))
        << "on_clear_pairing_code must survive cleanup_connection_state()";
    // pairing.md "pair/abort": only reason concurrent_attempt closes the connection; user_cancelled
    // leaves it open (pairing state is still cleared above).
    EXPECT_EQ(conn->disconnect_count_, 0);
    EXPECT_FALSE(conn->is_pairing_in_progress());
}

TEST_F(PairingStateMachineTest, CurrentConnectionAbortOrderingSurvivesCleanupStaticWindow) {
    // Static flavor: abort while AWAIT_PAIRING_WINDOW (before any PAKE exchange even starts)
    // must still fire on_pairing_failed + on_close_pairing_window.
    this->configure_static_pairing_code("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-static-6", SendspinPairMethod::STATIC_PAIRING_CODE);
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
    // pairing.md "pair/abort": only reason concurrent_attempt closes the connection.
    EXPECT_EQ(conn->disconnect_count_, 0);
}

// ============================================================================
// Leftover activate: entering the operational state structurally clears pairing state
// ============================================================================

// A server/activate in place of server/pair-finalize ends the pairing attempt without
// finalizing; the spec requires persisting nothing and discarding any pending long_term_psk.
// The clear is folded into SendspinClient::on_handshake_complete(), the one place every
// "connection is now operational" path converges, so no operational-entry path can leave a
// stale pairing session or pending record behind.
TEST_F(PairingStateMachineTest, LeftoverActivateDiscardsPendingRecordAndPairingSession) {
    this->configure_static_pairing_code("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-leftover", SendspinPairMethod::STATIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_TRUE(this->listener_.fired(PairingEventKind::OPEN_WINDOW));

    // Simulate the state after client/pair-finalize: a pending pairing record awaiting the ack.
    SendspinPairingRecord pending;
    pending.psk_id = "test-psk-id";
    conn->set_pending_pairing_record(pending);
    conn->pairing_session().attempt_deadline_us = platform_time_us() + 120LL * 1000LL * 1000LL;

    // The server leaves pairing without finalizing: activate instead of pair-finalize.
    this->post_activate({}, std::vector<std::string>{}, std::nullopt);
    this->client_->loop();

    // Going operational must have discarded the pending record and reset the pairing session.
    // (is_operational() also requires is_handshake_complete(), which FakeConnection never sets,
    // since no real hello handshake runs in this harness, so it is not asserted here.)
    EXPECT_FALSE(conn->take_pending_pairing_record().has_value())
        << "leftover activate must discard the received long_term_psk";
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::IDLE);
    EXPECT_EQ(conn->pairing_session().attempt_deadline_us, 0);
}

// ============================================================================
// pairing_index counter (pairing.md "Pairing index")
// ============================================================================

// The pairing_index counter (sent on every client/pair-init and folded into the CPace sid)
// must keep incrementing across repeated pairing server/activate messages on the SAME
// connection (e.g. the operator retries after a stalled attempt), not reset with each attempt.
// It only resets on a fresh Noise handshake (initial or re-handshake).
TEST_F(PairingStateMachineTest, PairingIndexIncrementsAcrossRepeatedPairingActivates) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-idx", SendspinPairMethod::DYNAMIC_PAIRING_CODE);
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
    EXPECT_EQ(conn->pairing_session().pairing_index, 1u);

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
TEST_F(PairingStateMachineTest, RejectedActivateStillCountsTowardPairingIndex) {
    FakeConnection* conn = this->inject_provisional_current_connection("server-rejected-idx");

    // First activate: empty activities -> connection goes operational (first_activate_received()
    // becomes true), no pairing. Needed so the next two activates are genuinely "subsequent" and
    // take the same real arbitration path SubsequentActivateEntersStaticCodePairing exercises,
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

    // Third activate: [pairing] + dynamic_pairing_code, admissible this time (category_ok: the
    // dynamic method does not require a Pairing-category PSK; offered: an out-channel and a
    // format are configured and dynamic_pairing_code_enabled_ defaults true). Must proceed into
    // pairing and its client/pair-init must carry pairing_index == 2: BOTH the rejected and the
    // accepted activate counted.
    this->post_activate({SendspinActivity::PAIRING}, std::vector<std::string>{},
                        SendspinPairMethod::DYNAMIC_PAIRING_CODE,
                        SendspinPairingCodeFormat::DIGITS);
    this->client_->loop();

    EXPECT_TRUE(this->listener_.fired(PairingEventKind::STARTED))
        << "the second, admissible pairing activate must proceed";
    // sent_text_ accumulates across the whole test: [0] is the pair/abort from the rejected
    // activate, [1] (the most recent) must be the client/pair-init from the accepted one.
    ASSERT_EQ(conn->sent_text_.size(), 2u);
    EXPECT_EQ(last_frame_type(conn->sent_text_), "client/pair-init");
    EXPECT_EQ(conn->get_pairing_index(), 2u);
    EXPECT_EQ(conn->pairing_session().pairing_index, 2u);

    JsonDocument doc;
    JsonObject root;
    ASSERT_TRUE(parse_json(conn->sent_text_.back(), doc, root));
    EXPECT_EQ(root["payload"]["pairing_index"] | 0u, 2u)
        << "the surviving attempt's client/pair-init must carry pairing_index == 2, proving the "
           "rejected activate was not silently dropped from the count";
}

// ============================================================================
// pair/abort close-vs-stay-open semantics (pairing.md "pair/abort")
// ============================================================================

// Reason concurrent_attempt is the ONE pair/abort reason whose sender (and, symmetrically, this
// client on receipt) still closes the connection.
TEST_F(PairingStateMachineTest, PairAbortConcurrentAttemptStillClosesConnection) {
    FakeConnection* conn = this->inject_current_connection("server-dyn-concurrent",
                                                            SendspinPairMethod::DYNAMIC_PAIRING_CODE);
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
TEST_F(PairingStateMachineTest, StalePairAbortAfterLocalAbortHasNoEffect) {
    FakeConnection* conn =
        this->inject_current_connection("server-dyn-stale", SendspinPairMethod::DYNAMIC_PAIRING_CODE);
    this->enter_pairing(conn);
    this->client_->loop();

    // The client locally aborts first (attempt timeout).
    conn->pairing_session().attempt_deadline_us = platform_time_us() - 1;
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
    stale_event.reason = PairAbortReason::PAIRING_CODE_MISMATCH;
    this->schedule_abort(std::move(stale_event));
    this->client_->loop();

    EXPECT_EQ(this->listener_.events_.size(), events_before)
        << "a stale pair/abort must not fire any new listener event";
    EXPECT_EQ(conn->disconnect_count_, disconnects_before);
}

// ============================================================================
// Re-proving watchdog (current_connection_ non-operational after a re-handshake or a
// pair-finalize ack; see REPROVE_TIMEOUT_US in connection_manager.h)
// ============================================================================

// SendspinConnection::note_pairing_finalize_ack() resets first_activate_received_ (so
// is_operational() goes false) and re-arms provisional_time_us_, anticipating the server's
// follow-up in-band re-handshake. If the server goes silent instead, ConnectionManager::loop()
// must eventually drop the connection rather than leave it wedged non-operational forever. The
// nursery reaper cannot cover this: the connection is current_connection_, never a nursery member.
// Forces the deadline into the past instead of sleeping REPROVE_TIMEOUT_US (30 s) in a unit test,
// matching the attempt_deadline_us pattern (e.g. DynamicCodeAttemptTimeout above).
TEST_F(PairingStateMachineTest, ReproveWatchdogDropsConnectionAfterFinalizeAckGoesSilent) {
    FakeConnection* conn =
        this->inject_current_connection("server-reprove-silent", SendspinPairMethod::DYNAMIC_PAIRING_CODE);

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
// mid-pairing, awaiting a human to press a physical gesture with no fixed deadline of its
// own, must survive even though its provisional_time_us_ is stale by far more than
// REPROVE_TIMEOUT_US.
TEST_F(PairingStateMachineTest, ReproveWatchdogDoesNotDropConnectionAwaitingOperatorGesture) {
    this->configure_static_pairing_code("13572468");
    FakeConnection* conn =
        this->inject_current_connection("server-reprove-gesture-wait", SendspinPairMethod::STATIC_PAIRING_CODE);

    // inject_current_connection() does not run a real hello handshake (see the comment on
    // LeftoverActivateDiscardsPendingRecordAndPairingSession above), so is_handshake_complete(),
    // and therefore is_operational(), would otherwise stay false regardless of pairing state.
    // Set it explicitly so this test exercises the same !is_operational() gate a real connection
    // would, and so a false pass (the watchdog skipping this connection only because
    // is_operational() can never be true in this harness) cannot hide a real over-reap bug.
    conn->set_client_hello_sent(true);
    conn->set_server_hello_received(true);
    ASSERT_TRUE(conn->is_operational());

    // The static pairing code is always gesture-gated (pairing.md "Pairing Window"), so with
    // no window open this
    // attempt waits for a human to press a button. AWAIT_PAIRING_WINDOW leaves attempt_deadline_us
    // at 0 (see handle_enter_pairing): the wait has no fixed deadline of its own.
    this->enter_pairing(conn);
    this->client_->loop();
    ASSERT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW);
    ASSERT_TRUE(conn->is_operational())
        << "entering pairing must not itself clear first_activate_received_";

    // A long time passes, far beyond REPROVE_TIMEOUT_US, while the human has not yet acted.
    conn->set_provisional_time_us(platform_time_us() - REPROVE_TIMEOUT_US - 1);
    this->client_->loop();

    EXPECT_EQ(this->current_connection(), conn)
        << "a connection legitimately awaiting a human pairing gesture must not be reaped by the "
           "re-proving watchdog";
    EXPECT_TRUE(conn->is_operational());
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED));
}

// The finalize-ack window above also has to defuse scan_pairing_attempt_timeout(): the pairing
// session is
// only reset by clear_pairing_state(), which runs once the post-rekey server/activate lands, not
// by note_pairing_finalize_ack() itself. So its step and attempt_deadline_us are
// still exactly what PAIR_CONFIRM left them while the rekey is in flight, and a slow rekey can
// let that deadline elapse for an exchange that already succeeded.
TEST_F(PairingStateMachineTest, PairingAttemptTimeoutScanSuppressedDuringFinalizeAckWindow) {
    FakeConnection* conn = this->enter_dynamic_code_pairing("server-dyn-finalize-window");

    CodeEmissionResult display;
    ASSERT_NO_FATAL_FAILURE(this->drive_to_code_emitted(conn, /*nonce_a_seed=*/3, display));

    ServerStandIn server;
    ASSERT_TRUE(server.start(display.prs, display.handshake_hash));

    std::array<uint8_t, CPACE_TAG_SIZE> server_kc{};
    ASSERT_NO_FATAL_FAILURE(this->drive_pair_auth(conn, server, server_kc));

    this->schedule_pair_confirm(server_kc);
    ASSERT_EQ(last_frame_type(conn->sent_text_), "client/pair-finalize");
    ASSERT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_FINALIZE);

    // Simulate: the server acked client/pair-finalize (the SERVER_PAIR_FINALIZE handler in
    // client.cpp calls this on success) and is now expected to rekey via an in-band
    // re-handshake. The pairing session is untouched by this call.
    conn->note_pairing_finalize_ack();
    ASSERT_TRUE(conn->is_pairing_finalized());
    ASSERT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_FINALIZE);

    // The rekey takes long enough that the original attempt deadline elapses.
    conn->pairing_session().attempt_deadline_us = platform_time_us() - 1;
    this->client_->loop();

    EXPECT_EQ(this->current_connection(), conn)
        << "a pairing that already finalized must not be dropped by the pairing attempt-timeout scan";
    EXPECT_FALSE(this->listener_.fired(PairingEventKind::FAILED))
        << "the attempt-timeout scan must not abort a pairing that already finalized";
    EXPECT_EQ(conn->pairing_session().step, SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_FINALIZE)
        << "the pairing session must survive untouched until the post-rekey activate clears it";
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
// an end-to-end test cannot tell a cleared flag from a stale one.
TEST_F(PairingStateMachineTest, DropClearsTheAdmittedFlag) {
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
TEST_F(PairingStateMachineTest, FinalizedPairingIsNotEvictedByRankZeroLastPlaybackPeer) {
    FakeConnection* current =
        this->inject_current_connection("paired-server", SendspinPairMethod::DYNAMIC_PAIRING_CODE);
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

// ============================================================================
// persist_last_played_server() same-value dedup guard
// ============================================================================

// A single-server deployment repeats the same server_id on every PLAYING transition, so the
// guard must skip the write (not just rely on the storage backend to dedup) once the id already
// matches ConnectionManager's last-played state; a genuine handoff to a different server_id must
// still go through.
TEST_F(PairingStateMachineTest, PersistLastPlayedServerSkipsDuplicateWrite) {
    EXPECT_EQ(this->persistence_provider_.save_attempts(persistence_keys::LAST_PLAYED), 0);

    this->persist_last_played_server("server-a");
    EXPECT_EQ(this->persistence_provider_.save_attempts(persistence_keys::LAST_PLAYED), 1);
    EXPECT_EQ(this->client_->connection_manager_->last_played_server_id(), "server-a");

    // Same server_id again (also covers the post-reboot case, where load_last_played_server()
    // already seeded this value via the same setter): no second write.
    this->persist_last_played_server("server-a");
    EXPECT_EQ(this->persistence_provider_.save_attempts(persistence_keys::LAST_PLAYED), 1);

    // A different server_id must still go through.
    this->persist_last_played_server("server-b");
    EXPECT_EQ(this->persistence_provider_.save_attempts(persistence_keys::LAST_PLAYED), 2);
    EXPECT_EQ(this->client_->connection_manager_->last_played_server_id(), "server-b");
}

// ============================================================================
// client/hello locations hint
// ============================================================================

// The configured hints describe where the shipped secrets were published, and ride every
// client/hello (pairing.md "client/hello pair-method descriptor").
TEST_F(PairingStateMachineTest, HelloAdvertisesConfiguredLocationsForShippedSecrets) {
    this->init_client(/*pairing_code_emission_supported=*/false,
                      /*pairing_window_supported=*/true, /*pairing_psk_locations=*/{"device"},
                      /*static_pairing_code_locations=*/{"leaflet", "operator"});
    this->configure_static_pairing_code("13572468");

    EXPECT_EQ(this->hello_locations("pairing_psk"), (std::vector<std::string>{"device"}));
    EXPECT_EQ(this->hello_locations("static_pairing_code"),
              (std::vector<std::string>{"leaflet", "operator"}));
}

// With nothing configured the hint is omitted rather than guessed at: only the application knows
// where its secrets were published.
TEST_F(PairingStateMachineTest, HelloOmitsLocationsWhenNoneAreConfigured) {
    this->configure_static_pairing_code("13572468");

    EXPECT_FALSE(this->hello_locations("pairing_psk").has_value());
    EXPECT_FALSE(this->hello_locations("static_pairing_code").has_value());
}
