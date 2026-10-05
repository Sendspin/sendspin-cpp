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

#include "connection_manager.h"

#include "admission.h"
#include "client_connection.h"
#include "connection.h"
#include "constants.h"
#include "crypto/constants.h"
#include "crypto/cpace.h"
#include "crypto/pairing_code.h"
#include "crypto/pairing_token.h"
#include "crypto/psk_wrap.h"
#include "pairing_offers.h"
#include "platform/crypto.h"
#include "platform/logging.h"
#include "platform/time.h"
#include "platform/types.h"
#include "protocol_messages.h"
#include "protocol_task.h"
#include "record_store.h"
#include "sendspin/config.h"
#include "sendspin/types.h"
#include "server_connection.h"
#include "time_burst.h"
#include "time_filter.h"
#include "ws_server.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cinttypes>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.conn_mgr";

static constexpr int64_t WS_SERVER_START_RETRY_MS = 5000LL;
static constexpr int64_t WS_SERVER_START_RETRY_US = WS_SERVER_START_RETRY_MS * US_PER_MS;

/// @brief Stands in for an active_roles set the server left out or the client refuses to keep.
static const std::vector<std::string> EMPTY_ROLES{};

/// @brief Refuses an activation the client cannot act on
///
/// pairing.md "Client <-> Server: pair/abort" answers a method or format the client does not offer
/// with pair/abort rather than a close, so the activation is never applied: the connection keeps
/// the activities and roles it had.
///
/// Answering here rather than ignoring the activate matters: a server that never hears back sits
/// waiting for the device forever, with nothing on either side to explain the stall.
/// @param conn The connection the activation arrived on.
/// @param why What the activation asked for that the client cannot act on.
/// @param method The pairing method the activation named, for the diagnostic.
static void refuse_activate(SendspinConnection* conn, const char* why, const char* method) {
    SS_LOGW(TAG,
            "server/activate %s (pairing.method=%s) for server_id=%s; replying "
            "pair/abort(method_not_supported), connection stays open",
            why, method, conn->get_server_id().c_str());
    conn->send_app_json(format_pair_abort_message(PairAbortReason::METHOD_NOT_SUPPORTED), nullptr);
}

/// @brief Transport-establishment progress of a nursery connection, used for reap diagnostics
///
/// Derived on demand from the connection's proven flags rather than stored, so it can never go
/// stale. Inbound entries are WS_UP or later by construction (delivered only after their upgrade);
/// only an outbound connect_to() still awaiting DNS/TCP resolve can be TCP_OPEN. See the
/// lifecycle-flag axes note above SendspinConnection's atomic flag members in connection.h.
enum class SetupStage : uint8_t {
    TCP_OPEN,
    WS_UP,
    NOISE_PENDING,
    NOISE_DONE,
    HELLO_SENT,
    ACTIVATE_PENDING,
    ESTABLISHED
};

static SetupStage setup_stage(const SendspinConnection& conn) {
    if (conn.is_operational()) {
        return SetupStage::ESTABLISHED;
    }
    if (conn.is_handshake_complete()) {
        return SetupStage::ACTIVATE_PENDING;
    }
    if (conn.has_client_hello_sent()) {
        return SetupStage::HELLO_SENT;
    }
    if (conn.is_noise_handshake_complete()) {
        return SetupStage::NOISE_DONE;
    }
    if (conn.has_noise_handshake()) {
        return SetupStage::NOISE_PENDING;
    }
    if (conn.is_ws_upgraded()) {
        return SetupStage::WS_UP;
    }
    return SetupStage::TCP_OPEN;
}

static const char* to_cstr(SetupStage stage) {
    switch (stage) {
        case SetupStage::TCP_OPEN:
            return "TCP_OPEN";
        case SetupStage::WS_UP:
            return "WS_UP";
        case SetupStage::NOISE_PENDING:
            return "NOISE_PENDING";
        case SetupStage::NOISE_DONE:
            return "NOISE_DONE";
        case SetupStage::HELLO_SENT:
            return "HELLO_SENT";
        case SetupStage::ACTIVATE_PENDING:
            return "ACTIVATE_PENDING";
        case SetupStage::ESTABLISHED:
            return "ESTABLISHED";
    }
    return "UNKNOWN";
}

/// @brief Captures conn's pairing-UI display flags. See PairingUiSnapshot for
/// why the capture must happen before any pairing-state cleanup.
/// @param conn Connection to snapshot. Must be non-null.
/// @return The captured flags.
static PairingUiSnapshot snapshot_pairing_ui(SendspinConnection* conn) {
    return {conn->pairing_session().code_emitted, conn->pairing_session().window_shown};
}

/// @brief Overall deadline for a pairing attempt in any flow, bounding it from its first message
/// (pairing.md "Entering and leaving pairing" recommends 2 minutes). In the pairing-code flows it
/// spans every round: a retry keeps the running deadline rather than re-arming it. On expiry the
/// attempt is aborted with reason attempt_timeout and any emitted code is withdrawn.
static constexpr double PAIRING_ATTEMPT_TIMEOUT_S = 120.0;

/// @brief Attempt deadline in microseconds (derived from PAIRING_ATTEMPT_TIMEOUT_S).
static constexpr int64_t PAIRING_ATTEMPT_TIMEOUT_US = seconds_to_us(PAIRING_ATTEMPT_TIMEOUT_S);

/// @brief Lifetime of an open pairing window, measured from opening and not paused during an
/// attempt (pairing.md "Pairing Window" recommends 5 minutes). On expiry the window closes
/// silently.
static constexpr double WINDOW_LIFETIME_S = 300.0;

/// @brief Window lifetime in microseconds (derived from WINDOW_LIFETIME_S).
static constexpr int64_t WINDOW_LIFETIME_US = seconds_to_us(WINDOW_LIFETIME_S);

/// @brief Attempts under one pairing window whose server_kc verification may fail before the
/// window closes (pairing.md "Pairing Window"): the window is the operator's consent to a bounded
/// run of guesses.
static constexpr uint32_t WINDOW_FAILED_ATTEMPT_LIMIT = 5;

/// @brief Rounds a dynamic pairing code may run since the last verified server_kc before the
/// client stops retrying (pairing.md "Rounds"). Reaching it aborts the attempt with
/// pairing_code_mismatch and holds further attempts behind a deliberate operator gesture, which
/// bounds an online guessing attacker to this many tries per gesture.
static constexpr uint32_t PAIRING_ROUND_LIMIT = 20;

/// @brief CPace sid label (pairing.md "PAKE"):
/// sid = LABEL || h || pairing_index || round, each counter a big-endian uint32.
static constexpr char PAKE_SID_LABEL[] = "sendspin-pair-pake-v1";

/// @brief CPace ADa/ADb (pairing.md "PAKE"): distinct associated data per side fixes a
/// reflected-MAC issue. The server is CPace role A, the client is role B.
static constexpr char PAKE_AD_SERVER[] = "server";  // ADa
static constexpr char PAKE_AD_CLIENT[] = "client";  // ADb

namespace {

/// @brief A CPace ISK held for the length of one handler and wiped when it goes out of scope.
///
/// CPace::isk() answers by value, so the caller owns a copy of the 64-byte secret that
/// CPace::~CPace never sees. K_wrap is SHA-256(label || sid || ISK) and the sid is not secret,
/// so a copy left in a dead stack frame is worth both wrap keys. The scope guard covers the
/// early returns between the two wraps, as the surrounding code already does for K_wrap itself
/// and for every PSK-bearing struct.
class ScopedIsk {
public:
    /// @brief Takes ownership of an ISK and wipes the caller's copy
    /// @param isk Taken by value, so the caller's temporary does not outlive this copy.
    explicit ScopedIsk(std::optional<std::array<uint8_t, CPACE_ISK_SIZE>> isk) : value_(isk) {
        if (isk.has_value()) {
            // The bytes were copied, so the argument still holds them.
            secure_zero_container(*isk);
        }
    }

    ScopedIsk(const ScopedIsk&) = delete;
    ScopedIsk& operator=(const ScopedIsk&) = delete;

    ~ScopedIsk() {
        if (this->value_.has_value()) {
            secure_zero_container(*this->value_);
        }
    }

    /// @brief Whether an ISK was handed over
    /// @return true when a value is held.
    [[nodiscard]] bool has_value() const {
        return this->value_.has_value();
    }

    /// @brief The held ISK; only valid when has_value()
    /// @return Reference to the held bytes, valid until this object goes out of scope.
    [[nodiscard]] const std::array<uint8_t, CPACE_ISK_SIZE>& value() const {
        assert(this->value_.has_value());
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): callers check has_value() first
        return *this->value_;
    }

private:
    std::optional<std::array<uint8_t, CPACE_ISK_SIZE>> value_;
};

}  // namespace

/// @brief Append `value` to `out` as a big-endian uint32, the encoding pairing.md "PAKE" gives
/// both of the sid's counters.
static void append_be32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

/// @brief Build the CPace sid for one round of a pairing attempt (pairing.md "PAKE"):
/// LABEL || h (32 bytes) || pairing_index || round, the counters big-endian uint32.
/// Binding the round in means every round of an attempt runs its own CPace transcript, so a
/// retry cannot replay the previous round's shares or reuse its wrap keys.
/// @param handshake_hash The Noise handshake hash the attempt is bound to.
/// @param pairing_index The pairing_index captured for this attempt
///        (SendspinConnection::PairingSession::pairing_index).
/// @param round The round number within the attempt, 1 for the first.
static std::vector<uint8_t> build_pake_sid(const std::array<uint8_t, 32>& handshake_hash,
                                           uint32_t pairing_index, uint32_t round) {
    std::vector<uint8_t> sid;
    sid.reserve(sizeof(PAKE_SID_LABEL) - 1 + 32 + 4 + 4);
    sid.insert(sid.end(), PAKE_SID_LABEL, PAKE_SID_LABEL + sizeof(PAKE_SID_LABEL) - 1);
    sid.insert(sid.end(), handshake_hash.begin(), handshake_hash.end());
    append_be32(sid, pairing_index);
    append_be32(sid, round);
    return sid;
}

/// @brief The client's own CPace associated data (ADb = "client"), as raw bytes.
static std::vector<uint8_t> pake_ad_client() {
    return std::vector<uint8_t>(PAKE_AD_CLIENT, PAKE_AD_CLIENT + sizeof(PAKE_AD_CLIENT) - 1);
}

/// @brief The peer's (server's) CPace associated data (ADa = "server"), as raw bytes.
static std::vector<uint8_t> pake_ad_server() {
    return std::vector<uint8_t>(PAKE_AD_SERVER, PAKE_AD_SERVER + sizeof(PAKE_AD_SERVER) - 1);
}

/// @brief The pairing method an applied server/activate selects, if it selects the pairing flow:
/// the PAIRING activity together with a pairing.method the client recognizes. Shared by every
/// site that must route such an activate into ConnectionManager::handle_enter_pairing().
/// PLAYBACK may ride along (messaging.md "server/activate" allows ['playback', 'pairing']), and
/// the connection then also takes the operational path (SendspinClient::on_handshake_complete()).
/// @return The selected method, or nullopt when the activate does not select pairing.
static std::optional<SendspinPairMethod> selected_pairing_method(
    const std::vector<SendspinActivity>& activities,
    const std::optional<SendspinPairMethod>& pairing_method) {
    if (!contains_activity(activities, SendspinActivity::PAIRING) || !pairing_method.has_value()) {
        return std::nullopt;
    }
    const SendspinPairMethod method = pairing_method.value();
    if (method == SendspinPairMethod::PAIRING_PSK ||
        method == SendspinPairMethod::DYNAMIC_PAIRING_CODE ||
        method == SendspinPairMethod::STATIC_PAIRING_CODE) {
        return method;
    }
    return std::nullopt;
}

// A cap under liveness_expired()'s 2^31 us range leaves minutes in which to see an expiry.
static_assert(SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS * US_PER_MS < INT32_MAX,
              "liveness cap exceeds the 32-bit arrival stamp's range");

int64_t resolve_liveness_timeout_ms(const SendspinClientConfig& config) {
    // The next message goes out after at most one inter-burst interval, and an unanswered one
    // times out after one response timeout. Not value_or(): it would evaluate the derivation,
    // which can overflow, even when unused.
    const int64_t timeout_ms =
        config.liveness_timeout_ms.has_value()
            ? config.liveness_timeout_ms.value()
            : (LIVENESS_TOLERATED_MISSES + 1) *
                  (config.time_burst_interval_ms + config.time_burst_response_timeout_ms);
    if (timeout_ms > SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS) {
        SS_LOGW(TAG, "Liveness timeout of %" PRId64 " ms exceeds the maximum, using %" PRId64 " ms",
                timeout_ms, SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS);
        return SendspinClientConfig::MAX_LIVENESS_TIMEOUT_MS;
    }
    return timeout_ms;
}

bool liveness_expired(int64_t now_us, uint32_t last_receive_us, int64_t timeout_us) {
    // Signed: an arrival stamped after now_us was read is a negative silence, not ~2^32 us.
    const auto silence_us = static_cast<int32_t>(static_cast<uint32_t>(now_us) - last_receive_us);
    return timeout_us > 0 && silence_us >= timeout_us;
}

int64_t liveness_remaining_us(int64_t now_us, uint32_t last_receive_us, int64_t timeout_us) {
    // The same signed 32-bit silence liveness_expired() measures.
    const auto silence_us = static_cast<int32_t>(static_cast<uint32_t>(now_us) - last_receive_us);
    return silence_us >= timeout_us ? 0 : timeout_us - silence_us;
}

uint32_t ms_until(int64_t due_us, int64_t now_us) {
    if (due_us <= now_us) {
        return 0;
    }
    const int64_t wait_ms = (due_us - now_us + US_PER_MS - 1) / US_PER_MS;
    // UINT32_MAX is ProtocolTask::NO_DEADLINE, which a real deadline must never read as.
    return wait_ms >= static_cast<int64_t>(UINT32_MAX) ? UINT32_MAX - 1
                                                       : static_cast<uint32_t>(wait_ms);
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

// Reading config_ here is safe: SendspinClient declares it before connection_manager_.
ConnectionManager::ConnectionManager(SendspinClient* client)
    : client_(client),
      liveness_timeout_us_(resolve_liveness_timeout_ms(client->config_) * US_PER_MS) {}

ConnectionManager::~ConnectionManager() {
    // The protocol task is joined (or never ran) and finish_stop() released what the shutdown pass
    // kept, so anything left here is released on the thread destroying the client. Detach first:
    // a destructor below can join its transport thread, which must not be parked on its gate.
    for (auto& entry : this->admitted_) {
        if (entry.conn != nullptr) {
            entry.conn->detach_inbound();
            entry.conn->set_admitted(false);
        }
    }
    for (auto& entry : this->nursery_) {
        entry.conn->detach_inbound();
    }
    for (auto& conn : this->closing_) {
        conn->detach_inbound();
    }
}

// ============================================================================
// Main loop
// ============================================================================

void ConnectionManager::start() {
    // A restart begins with no shutdown pass behind it and retries the server at once rather than
    // honoring a backoff from before the stop. The protocol task is not running, so these writes
    // reach it through its start.
    this->shutdown_done_ = false;
    this->shutdown_goodbyes_pending_ = 0;
    this->shutdown_wait_.reset();
    this->shutdown_ui_ = {false, false};
    this->ws_server_start_retry_time_us_ = 0;

    if (this->ws_server_ == nullptr) {
        // First start: create the server object and configure it once. The config is immutable
        // for the client's lifetime, so a restart reuses these values along with the object.
        this->ws_server_ = std::make_unique<SendspinWsServer>();
        this->ws_server_->set_port(this->client_->config_.server_port);
        this->ws_server_->set_max_connections(this->client_->config_.server_max_connections);
        this->ws_server_->set_ctrl_port(this->client_->config_.httpd_ctrl_port);

        // Graceful rejection needs transport headroom: the manager can hold MAX_ADMITTED admitted
        // connections plus NURSERY_CAPACITY unproven ones, and rejecting a surplus peer with a
        // client/goodbye requires the transport to accept that peer's socket on top. Below this
        // bound the nursery-full goodbye path is unreachable; surplus peers are refused at accept
        // instead (and on ESP they wait unanswered in the TCP backlog, since httpd stops
        // accepting).
        constexpr size_t GRACEFUL_SOCKETS = MAX_ADMITTED + NURSERY_CAPACITY + 1;
        if (this->client_->config_.server_max_connections < GRACEFUL_SOCKETS) {
            SS_LOGW(TAG,
                    "server_max_connections (%u) is below %u (%u admitted + %u nursery + 1 spare); "
                    "surplus peers will be refused at accept instead of receiving a goodbye",
                    static_cast<unsigned>(this->client_->config_.server_max_connections),
                    static_cast<unsigned>(GRACEFUL_SOCKETS), static_cast<unsigned>(MAX_ADMITTED),
                    static_cast<unsigned>(NURSERY_CAPACITY));
        }

        this->ws_server_->set_new_connection_callback(
            [this](const std::shared_ptr<SendspinServerConnection>& conn) {
                return this->on_new_connection(conn);
            });
        // The server's own deadline (a pending upgrade) is reported by tick(); a new pending
        // session wakes the task so the deadline it reports covers it.
        ProtocolTask* task = this->client_->protocol_task_.get();
        this->ws_server_->set_wake_callback([task]() { task->wake(); });
    }

    this->accepting_.store(true, std::memory_order_release);
    // Started here when the network is already up, so the server is listening once start()
    // returns; otherwise the protocol task starts it once the provider reports ready.
    (void)this->maybe_start_ws_server(platform_time_us());
}

void ConnectionManager::close_admission() {
    this->accepting_.store(false, std::memory_order_release);
    this->client_->protocol_task_->wake();
}

PairingUiSnapshot ConnectionManager::finish_stop() {
    // The protocol task is joined. A shutdown pass that never ran (the task never started) leaves
    // the slots to fold in here; they hold nothing on a client whose start() failed before the
    // task ran, since only the task fills them.
    if (!this->shutdown_done_) {
        for (auto& entry : this->admitted_) {
            if (entry.conn != nullptr) {
                entry.conn->detach_inbound();
                entry.conn->set_admitted(false);
                this->closing_.push_back(std::move(entry.conn));
                entry = AdmittedEntry{};
            }
        }
        for (auto& entry : this->nursery_) {
            entry.conn->detach_inbound();
            this->closing_.push_back(std::move(entry.conn));
        }
        this->nursery_.clear();
        this->shutdown_done_ = true;
        this->refresh_published_state();
    }

    // Close every transport the shutdown pass kept before the server stops, so its join does not
    // wait out a peer that never closes. Every gate is detached, so no transport thread the stop
    // joins is parked on one, and one in a ring acquire gives up within
    // INBOUND_ACQUIRE_TIMEOUT_MS.
    for (auto& conn : this->closing_) {
        conn->close_transport_now();
    }
    if (this->ws_server_ != nullptr) {
        this->ws_server_->stop();
    }
    // Released here, after the server stop: an outbound connection's destructor stops its
    // transport synchronously.
    std::vector<std::shared_ptr<SendspinConnection>> releasing;
    releasing.swap(this->closing_);
    releasing.clear();

    const PairingUiSnapshot ui = this->shutdown_ui_;
    this->shutdown_ui_ = {false, false};
    return ui;
}

// ============================================================================
// Any thread
// ============================================================================

std::shared_ptr<SendspinTimeFilter> ConnectionManager::time_filter() const {
    std::lock_guard<std::mutex> lock(this->time_filter_mutex_);
    return this->time_filter_;
}

std::optional<ServerInformationObject> ConnectionManager::server_information() const {
    std::lock_guard<std::mutex> lock(this->server_info_mutex_);
    return this->server_information_;
}

// ============================================================================
// Transport threads
// ============================================================================

bool ConnectionManager::on_new_connection(const std::shared_ptr<SendspinServerConnection>& conn) {
    // On the transport's delivery thread, ahead of the connection's first frame and before the
    // protocol task can reach the connection: the push below publishes these writes to the task.
    conn->init_time_filter();
    conn->time_burst().configure(this->client_->config_.time_burst_size,
                                 this->client_->config_.time_burst_interval_ms,
                                 this->client_->config_.time_burst_response_timeout_ms);
    conn->set_inbound_buffer_location(this->client_->config_.inbound_ring_location);
    conn->set_noise_buffer_location(this->client_->config_.noise_buffer_location);
    this->setup_connection_callbacks(conn.get());

    ProtocolCommand command;
    command.type = ProtocolCommandType::ACCEPT_CONNECTION;
    command.connection = conn;
    if (this->client_->protocol_task_->push_command(std::move(command))) {
        return true;
    }
    // Refused (push_command() logged it: the slots are full, or stop() closed accepts once the
    // task was joined): the transport drops what the peer sends from here, and the caller closes
    // the socket and releases the connection on its own close path. The delivery runs ahead of
    // the connection's first frame on the delivering thread, so nothing reached the ring before
    // the detach.
    conn->detach_inbound();
    return false;
}

// ============================================================================
// Protocol task: commands
// ============================================================================

void ConnectionManager::accept(std::shared_ptr<SendspinConnection> conn) {
    if (!this->accepting_.load(std::memory_order_acquire)) {
        this->refuse_accept(std::move(conn));
        return;
    }

    // Start the establish clock: the nursery scan reaps the connection if it does not complete
    // the hello handshake within NURSERY_ESTABLISH_TIMEOUT_US.
    conn->set_provisional_time_us(platform_time_us());

    // The newcomer has not completed the hello handshake, so it never touches an admitted slot;
    // it enters the bounded nursery and is admitted only once it establishes. Only inbound
    // entries count against the capacity (see NURSERY_CAPACITY). If the inbound slots are full,
    // reject the newcomer: every occupant speaks WebSocket, so there is no safe eviction
    // candidate. The goodbye reaches the peer because its session is already upgraded, provided
    // the transport had a socket to accept it on (the socket budget in NURSERY_CAPACITY).
    size_t inbound_count = 0;
    for (const auto& entry : this->nursery_) {
        if (!entry.conn->is_outbound()) {
            ++inbound_count;
        }
    }
    if (inbound_count >= NURSERY_CAPACITY) {
        SS_LOGW(TAG, "Nursery full of live connections, rejecting new connection");
        release_connection(std::move(conn), SendspinGoodbyeReason::ANOTHER_SERVER);
        return;
    }

    SS_LOGD(TAG, "Admitting new connection into the nursery");
    this->nursery_.push_back(NurseryEntry{.conn = std::move(conn)});
    // The connection arrives WS-upgraded, so client/init goes out at once.
    this->start_noise_handshake(this->nursery_[this->nursery_.size() - 1]);
}

void ConnectionManager::refuse_accept(std::shared_ptr<SendspinConnection> conn) {
    // Delivered while admission is closed (a stop() under way): the slots are being emptied, so
    // the newcomer gets a goodbye and a close instead of one, and is kept for finish_stop().
    SS_LOGD(TAG, "Not accepting connections, rejecting new connection");
    conn->detach_inbound();
    if (this->shutdown_wait_ == nullptr) {
        this->shutdown_wait_ = std::make_shared<GoodbyeWait>();
    }
    std::shared_ptr<GoodbyeWait> wait = this->shutdown_wait_;
    wait->add_pending();
    ++this->shutdown_goodbyes_pending_;
    conn->disconnect(SendspinGoodbyeReason::SHUTDOWN, [wait] { wait->complete_one(); });
    this->closing_.push_back(std::move(conn));
}

void ConnectionManager::connect_to(const std::string& url) {
    SS_LOGI(TAG, "Initiating client connection to: %s", url.c_str());

    auto client_conn = std::make_shared<SendspinClientConnection>(url);
    client_conn->set_task_config(this->client_->config_.websocket_priority,
                                 this->client_->config_.websocket_stack_size);
    client_conn->set_inbound_buffer_location(this->client_->config_.inbound_ring_location);
    client_conn->set_noise_buffer_location(this->client_->config_.noise_buffer_location);

    // Wired before start(): the transport may deliver from its own thread as soon as it runs.
    this->setup_connection_callbacks(client_conn.get());
    // Only outbound transports fire this, on the transport thread, once the WebSocket upgrade is
    // complete; the protocol task starts the Noise handshake on its next tick
    // (start_upgraded_handshakes()). It can run during the destructor's transport join, so it
    // touches only the connection it is handed.
    client_conn->on_connected_cb = [](SendspinConnection* c) {
        c->mark_ws_upgraded();
        c->wake_protocol_task();
    };

    client_conn->init_time_filter();
    client_conn->time_burst().configure(this->client_->config_.time_burst_size,
                                        this->client_->config_.time_burst_interval_ms,
                                        this->client_->config_.time_burst_response_timeout_ms);

    // Start the nursery clock: the nursery scan reaps the connection if it has not completed the
    // hello handshake within NURSERY_ESTABLISH_TIMEOUT_US. The stamp predates DNS/TCP resolve,
    // which is why outbound entries are exempt from the short upgrade deadline.
    client_conn->set_provisional_time_us(platform_time_us());

    // An admitted connection whose transport is already gone (its close not processed yet) is
    // being replaced. Tear its state down as a loss would (no goodbye), instead of leaving it to
    // occupy the slot with orphaned role state.
    for (auto& entry : this->admitted_) {
        if (entry.conn != nullptr && !entry.conn->is_connected()) {
            this->drop_connection(entry.conn.get(), std::nullopt);
        }
    }

    // Only one outbound attempt at a time: release any previous outbound entry before pushing
    // the new one. Otherwise it would be dropped with no goodbye and, on ESP, leave its httpd
    // session pinned.
    for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
        if (it->conn->is_outbound()) {
            it = this->release_nursery_entry(it, SendspinGoodbyeReason::ANOTHER_SERVER);
        } else {
            ++it;
        }
    }

    // A user-initiated connect is admitted even against a full nursery: there is at most one
    // outbound entry (replaced above), so the nursery is still bounded (MAX_NURSERY_ENTRIES)
    // and an explicit user request never fails against inbound peers.
    this->nursery_.push_back(NurseryEntry{.conn = client_conn});
    client_conn->start();
}

void ConnectionManager::disconnect(SendspinGoodbyeReason reason) {
    // The connected connections stay in their slots until the loss pass sees their detached gates
    // (or the manager is stopped). An unconnected (pre-upgrade) nursery entry has no transport to
    // goodbye and yields no close, so it is released here rather than left for the establish
    // deadline.
    InlineVector<std::shared_ptr<SendspinConnection>, MAX_OPEN_CONNECTIONS> to_disconnect;
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr && entry.conn->is_connected()) {
            to_disconnect.push_back(entry.conn);
        }
    }
    for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
        if (it->conn->is_connected()) {
            to_disconnect.push_back(it->conn);
            ++it;
        } else {
            it = this->release_nursery_entry(it, std::nullopt);
        }
    }
    // Detached before the goodbye, as release_connection() does: an outbound connection's
    // disconnect() joins its transport thread, which must not be parked waiting on this task
    // (InboundGate::wait_until_writable() or a ring acquire) while the join waits for it.
    for (auto& conn : to_disconnect) {
        conn->detach_inbound();
        conn->disconnect(reason, nullptr);
    }
}

void ConnectionManager::leave() {
    // messaging.md "client/leave". Not a role message, so it does not route through
    // send_role_text(). It still shares the activation gate every outbound message has: nothing
    // may be sent before the connection is admitted and its server/activate has arrived.
    // Admission does not imply the latter: an in-band re-handshake rewinds the connection to
    // awaiting its next activation while it keeps the admitted slot.
    AdmittedEntry* entry = this->primary();
    SendspinConnection* conn = entry != nullptr ? entry->conn.get() : nullptr;
    if (conn == nullptr || !conn->is_connected() || !conn->first_activate_received()) {
        SS_LOGW(TAG, "client/leave ignored: no activated connection with a group to leave");
        return;
    }
    SS_LOGI(TAG, "Leaving the group (client/leave)");
    conn->send_app_json(format_client_leave_message(), nullptr);
}

void ConnectionManager::send_role_text(SendspinRole role, const std::string& text) const {
    // Routed to the connection that owns the role, whose activation of it is the role's own gate
    // (see owns_role()): the same gate the receive path and the client/state role objects apply.
    // A declared PAIRING activity is not a gate: pairing.md "Entering and leaving pairing" says an
    // activate that adds it does not by itself affect active_roles, so an active role keeps
    // driving its own traffic across the attempt.
    SendspinConnection* conn = this->role_owner(role);
    if (conn == nullptr || !conn->is_connected()) {
        SS_LOGD(TAG, "Dropping a %s message: no admitted connection owns the role", to_cstr(role));
        return;
    }
    // connection.md "Re-handshake": once the client has received Noise message 1 it sends nothing
    // but the handshake until the new server/activate arrives. Same gate client/leave and
    // client/state apply.
    if (!conn->first_activate_received()) {
        SS_LOGD(TAG, "Dropping a %s message: the connection awaits its server/activate",
                to_cstr(role));
        return;
    }
    conn->send_app_json(text, nullptr);
}

void ConnectionManager::confirm_pairing_window() {
    // Without a record store there is nothing to pair with, so the gesture is ignored.
    if (this->client_->record_store_ == nullptr) {
        return;
    }
    this->open_pairing_window();
}

void ConnectionManager::cancel_pairing_window() {
    // Operator cancellation is one of the window's closing events (pairing.md "Pairing Window"). An
    // attempt still withheld for the gesture has just lost the only thing that could admit it, so
    // it ends here with the reason that says why; an attempt already under way runs to its own end,
    // as it does on expiry.
    this->close_pairing_window();

    InlineVector<SendspinConnection*, MAX_ADMITTED> waiting;
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr && entry.conn->pairing_session().step ==
                                         SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW) {
            waiting.push_back(entry.conn.get());
        }
    }
    for (SendspinConnection* conn : waiting) {
        SS_LOGI(TAG, "Pairing window cancelled: ending the waiting attempt for server_id=%s",
                conn->get_server_id().c_str());
        this->local_abort_pairing(conn, PairAbortReason::USER_CANCELLED);
    }
}

void ConnectionManager::apply_unpaired_access_change(bool enabled) {
    // pairing.md "Unpaired Access": disabling closes the connections relying on it with
    // pairing_required; enabling restarts unpaired connections so their servers read the new value
    // in the next client/hello.

    // Collect first: drop_connection() edits the slots being walked.
    InlineVector<std::shared_ptr<SendspinConnection>, MAX_OPEN_CONNECTIONS> doomed;
    auto consider = [&](const std::shared_ptr<SendspinConnection>& conn, bool hello_sent) {
        if (!enabled) {
            // A connection still awaiting its activation is judged against the new setting
            // when that activation is applied.
            if (conn->first_activate_received() &&
                relies_on_unpaired_access(conn->get_psk_category(), conn->get_activities(),
                                          !conn->get_active_roles().empty())) {
                doomed.push_back(conn);
            }
            return;
        }
        // messaging.md "client/goodbye": restart on a connection the client opened promises
        // that the client reopens it, and nothing reopens a connect_to() connection. A
        // connection declaring pairing is left to finish. A Pairing-PSK one that has not
        // activated yet is most likely about to declare pairing, and a restart would cost that
        // attempt, so it is left alone too; if it activates idle instead, it keeps the hello
        // it already read until it reconnects. A Sentinel one awaiting its activation is
        // restarted, since its server may be deciding that activation on the value its hello
        // carried.
        if (hello_sent && !conn->is_outbound() &&
            conn->get_psk_category() != PskCategory::LONG_TERM &&
            !conn->has_activity(SendspinActivity::PAIRING) &&
            (conn->first_activate_received() || conn->get_psk_category() != PskCategory::PAIRING)) {
            doomed.push_back(conn);
        }
    };

    // An admitted connection sent its hello to be admitted. One between a re-handshake and the
    // activation that follows it is left alone: its server may be moving it into pairing.
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr && entry.conn->first_activate_received()) {
            consider(entry.conn, /*hello_sent=*/true);
        }
    }
    for (const auto& entry : this->nursery_) {
        consider(entry.conn, entry.hello_step == HelloStep::DONE);
    }

    const SendspinGoodbyeReason reason =
        enabled ? SendspinGoodbyeReason::RESTART : SendspinGoodbyeReason::PAIRING_REQUIRED;
    for (const auto& conn : doomed) {
        SS_LOGI(TAG, "Unpaired access %s: closing the session with server_id=%s",
                enabled ? "enabled" : "disabled", conn->get_server_id().c_str());
        this->drop_connection(conn.get(), reason);
    }
}

// ============================================================================
// Protocol task: message handlers
// ============================================================================

void ConnectionManager::on_server_activate(SendspinConnection* conn, ServerActivateMessage&& msg) {
    NurseryEntry* nursery_entry = this->find_in_nursery(conn);
    AdmittedEntry* admitted_entry = this->find_admitted(conn);
    if (nursery_entry == this->nursery_.end() && admitted_entry == nullptr) {
        // Released while its messages were still queued (a rejection, a reap).
        SS_LOGD(TAG, "Ignoring server/activate from a connection the manager released");
        return;
    }

    const bool unpaired_access =
        this->client_->unpaired_access_enabled_.load(std::memory_order_relaxed);

    // Compute the effective active_roles (sticky: nullopt keeps the prior set), except
    // when this activate omits active_roles and its activities are no longer
    // playback-capable: messaging.md "Playback-capable connections" says the client treats the
    // persisted roles as empty in that case rather than rejecting the message (a later
    // activate can legally narrow activities without re-sending an empty active_roles).
    const bool playback_capable =
        is_playback_capable(conn->get_psk_category(), msg.activities, unpaired_access);
    const std::vector<std::string>& effective_roles =
        msg.active_roles.has_value() ? msg.active_roles.value()
                                     : (playback_capable ? conn->get_active_roles() : EMPTY_ROLES);
    const bool has_roles = !effective_roles.empty();

    // Trust enforcement against the PSK category the Noise handshake resolved for this
    // connection. Every connection has one: no server/activate can arrive before the
    // handshake completes.
    const bool trust_ok =
        admissible(conn->get_psk_category(), msg.activities, has_roles, unpaired_access);

    if (!trust_ok) {
        const SendspinGoodbyeReason reject_reason = inadmissible_reject_reason(
            conn->get_psk_category(), msg.activities, has_roles, unpaired_access);
        SS_LOGW(TAG, "server/activate inadmissible (psk_category=%d): closing with %s",
                static_cast<int>(conn->get_psk_category()),
                reject_reason == SendspinGoodbyeReason::PAIRING_REQUIRED ? "pairing_required"
                                                                         : "unauthorized");
        this->drop_connection(conn, reject_reason);
        return;
    }

    // pairing.md "Pairing index": the count is of pairing server/activate messages received,
    // not of accepted attempts, so the server counts every pairing activate it sends, including
    // ones the client goes on to reject (e.g. method_not_supported below). Bump here, at the
    // single point every pairing server/activate is received, so a rejected activate does not
    // leave the client permanently behind the server's count. handle_enter_pairing() reads this
    // value; it must not bump again.
    const bool is_pairing_activate = contains_activity(msg.activities, SendspinActivity::PAIRING);
    if (is_pairing_activate) {
        conn->bump_pairing_index();
    }

    // Structurally admissible already (the activity set passed the table above),
    // but a pairing activate additionally carries a pairing object whose method must
    // (a) match the matched PSK's category (pairing_psk iff the matched PSK IS the
    // Pairing PSK) and (b) be one the client/hello advertised in supported_pair_methods.
    // When it is not, reply pair/abort(method_not_supported) and leave the connection open
    // (unlike the reasons above, this does not close the connection).
    // A pairing activate that names no usable method (pairing object absent, or a
    // method string this client does not recognize; process_server_activate_message
    // logs the raw value) cannot start any flow.
    if (is_pairing_activate && !msg.pairing_method.has_value()) {
        refuse_activate(conn, "declares pairing with no usable pairing.method",
                        "absent or unrecognized");
        return;
    }

    if (is_pairing_activate && msg.pairing_method.has_value()) {
        const SendspinPairMethod method = msg.pairing_method.value();
        const bool category_ok = (method == SendspinPairMethod::PAIRING_PSK) ==
                                 (conn->get_psk_category() == PskCategory::PAIRING);
        // The same predicates build_hello_message() advertises from (pairing_offers.h).
        const auto& cfg = this->client_->config_;
        bool offered = true;
        switch (method) {
            case SendspinPairMethod::PAIRING_PSK:
                offered = true;  // Always advertised; see pairing_offers.h.
                break;
            case SendspinPairMethod::DYNAMIC_PAIRING_CODE:
                offered = offers_dynamic_pairing_code(cfg);
                break;
            case SendspinPairMethod::STATIC_PAIRING_CODE:
                offered = offers_static_pairing_code(cfg);
                break;
        }
        if (!category_ok || !offered) {
            refuse_activate(conn, "selects an unsupported pairing method", to_cstr(method));
            return;
        }

        // messaging.md "server/activate" requires `format` on a dynamic_pairing_code
        // activation, drawn from the client's own `formats`; a missing, unrecognized,
        // or unoffered one is pair/abort(method_not_supported) with the connection left
        // open (pairing.md "Client <-> Server: pair/abort").
        if (method == SendspinPairMethod::DYNAMIC_PAIRING_CODE &&
            !offers_pairing_code_format(this->client_->config_, msg.pairing_format)) {
            refuse_activate(conn, "names no usable pairing.format", to_cstr(method));
            return;
        }
    }

    const bool is_first = !conn->first_activate_received();
    // Pass the same active_roles the admissibility check above used: when the message
    // omitted active_roles but the connection is no longer playback-capable, that is
    // effective_roles == EMPTY_ROLES, and it must be applied (not left sticky) so the
    // persisted active_roles_ is actually cleared (messaging.md "Playback-capable connections").
    const std::optional<std::vector<std::string>> active_roles_to_apply =
        msg.active_roles.has_value()
            ? msg.active_roles
            : (!playback_capable ? std::make_optional(EMPTY_ROLES) : std::nullopt);
    // Copied before the activate is applied: messaging.md "client/state" ties the next state
    // update to the active-role set changing, so the comparison needs the set this activation
    // replaces.
    const uint16_t roles_before = conn->get_active_role_mask();
    conn->apply_server_activate(msg.activities, active_roles_to_apply, msg.pairing_method,
                                msg.pairing_format);
    const bool roles_changed = roles_before != conn->get_active_role_mask();

    if (admitted_entry != nullptr) {
        // messaging.md "server/activate": a role this activation took out of active_roles stops
        // its output and drops its state as part of applying the activation, so the teardown runs
        // before the branches below act on the new activation. The connection keeps owning what
        // it still activates and claims what it newly activates unless another admitted
        // connection owns it; only the roles it owned and no longer does are torn down. A nursery
        // entry sees one activate and owns nothing yet.
        const uint16_t owned_before = admitted_entry->owned_roles;
        admitted_entry->owned_roles = claimable_roles(conn->get_active_role_mask(),
                                                      this->roles_owned_by_others(admitted_entry));
        const auto removed = static_cast<uint16_t>(owned_before & ~admitted_entry->owned_roles);
        if (removed != 0) {
            this->client_->apply_role_removals(removed);
        }
        if (admitted_entry->owned_roles != owned_before) {
            this->refresh_published_state();
        }

        // Already admitted: no arbitration needed. is_first can still be true here after an
        // in-band re-handshake reset first_activate_received_, so the branches below that act on
        // an is_first activate also require is_handshake_complete().
        this->note_playback_activity(conn);

        const auto& activities = conn->get_activities();
        const std::optional<SendspinPairMethod> pairing_method =
            selected_pairing_method(activities, conn->get_pairing_method());
        const bool selects_pairing = pairing_method.has_value();

        // The pairing-selection check runs on every activate and takes priority over the plain
        // operational branch: a server rehandshaking an admitted connection onto the pairing PSK
        // resets first_activate_received_, so its pairing activate looks like a first activate,
        // and the operational branch would publish client/state while the server waits for
        // client/pair-finalize.
        if (conn->is_pairing_in_progress()) {
            // Pairing was in progress and the server sent another server/activate instead of
            // server/pair-finalize: it abandoned pairing without finalizing. Going operational
            // discards any pending record and resets the pairing session structurally.
            // pairing.md "Entering and leaving pairing" admits one pairing attempt per pairing
            // server/activate, so an activate that selects pairing again also starts the attempt
            // it admits: its pairing_index was already counted, and the server that sent it is
            // waiting for the client/pair-init that opens the new attempt.
            SS_LOGI(TAG,
                    "Subsequent activate during pairing (leftover): clearing pairing "
                    "state and going operational for server_id=%s",
                    conn->get_server_id().c_str());
            this->client_->on_handshake_complete(conn);
            if (selects_pairing) {
                SS_LOGI(TAG,
                        "Leftover activate selects pairing again (%s): starting the "
                        "attempt it admits for server_id=%s",
                        to_cstr(pairing_method.value()), conn->get_server_id().c_str());
                this->handle_enter_pairing(conn);
            }
        } else if (selects_pairing) {
            // Reached both when the operator initiates pairing on an already-operational
            // connection (is_first false) and when the server first rehandshakes the connection
            // onto the pairing PSK (is_first true).
            if (!is_first || conn->is_handshake_complete()) {
                // pairing.md "Entering and leaving pairing": adding 'pairing' does not by
                // itself affect active_roles, streams or group membership. An activate that
                // declares both purposes therefore runs the operational path as well as the
                // pairing one, and first: going operational clears stale pairing state the
                // new attempt must not inherit.
                if (is_first && contains_activity(activities, SendspinActivity::PLAYBACK)) {
                    this->client_->on_handshake_complete(conn);
                }
                SS_LOGI(TAG,
                        "Activate selects pairing (%s): entering pairing for "
                        "server_id=%s",
                        to_cstr(pairing_method.value()), conn->get_server_id().c_str());
                this->handle_enter_pairing(conn);
                // connection.md "Re-handshake" makes a post-re-handshake activation a subsequent
                // one, so messaging.md "client/state" owes an update for a role it activates.
                const bool adds_role = (conn->get_active_role_mask() & ~roles_before) != 0;
                if (is_first && adds_role &&
                    !contains_activity(activities, SendspinActivity::PLAYBACK)) {
                    this->client_->publish_client_state(conn);
                }
            }
        } else if (is_first && conn->is_handshake_complete()) {
            this->client_->on_handshake_complete(conn);
        }

        // messaging.md "client/state": a role that becomes active in active_roles must be told
        // about in an update that includes that role's object, before the server may send its
        // binary data. A first activate publishes through on_handshake_complete(), or above when
        // it selects pairing alone and adds a role; this covers every later one that moves the set.
        if (roles_changed && !is_first && conn->is_operational()) {
            this->client_->publish_client_state(conn);
        }
        return;
    }

    // A nursery entry is admitted here when the hello handshake has already completed, so the
    // messages the server sends behind its activate are dispatched with the connection admitted.
    // A nonconforming peer's server/activate can race ahead of the hello exchange; the
    // level-triggered admission in scan_nursery() then admits it once both are true, in whichever
    // order they complete. A pairing-flavored activate goes through admission like any other
    // operational candidate; see promote_or_arbitrate_nursery_entry().
    if (conn->is_operational()) {
        this->promote_or_arbitrate_nursery_entry(nursery_entry);
    }
}

void ConnectionManager::on_pair_abort(SendspinConnection* conn, PairAbortReason reason) {
    // A pairing attempt only ever runs on an admitted connection (see the pairing branch in
    // promote_or_arbitrate_nursery_entry()).
    if (this->find_admitted(conn) == nullptr) {
        SS_LOGD(TAG, "Discarding pair/abort (reason=%s) for server_id=%s: not admitted",
                to_cstr(reason), conn->get_server_id().c_str());
        return;
    }
    this->handle_pair_abort(conn, reason);
}

void ConnectionManager::on_server_unpair(SendspinConnection* conn) {
    // Only an admitted connection is acted on. A nursery peer that has proven itself can send
    // server/unpair too (the spec calls it valid regardless of the current activities), so this
    // drops one from a peer the client is not actually running a session with. Rare, and it
    // costs that peer nothing but a repeat once it is admitted.
    if (this->find_admitted(conn) == nullptr) {
        SS_LOGD(TAG, "Discarding server/unpair for server_id=%s: not admitted",
                conn->get_server_id().c_str());
        return;
    }
    this->handle_server_unpair(conn);
}

void ConnectionManager::on_pairing_message(SendspinConnection* conn,
                                           const ServerPairingMessage& message) {
    // Only ever targets an admitted connection: a pairing-code session only exists on a
    // connection that already won admission.
    if (this->find_admitted(conn) == nullptr) {
        SS_LOGD(TAG, "Discarding pairing message (kind=%d) for server_id=%s: not admitted",
                static_cast<int>(message.kind), conn->get_server_id().c_str());
        return;
    }
    this->handle_pairing_message(conn, message);
}

void ConnectionManager::on_pairing_succeeded(SendspinConnection* conn) {
    // A completed pairing closes the pairing window (pairing.md "Pairing Window"). The pairing is
    // complete here and not a message earlier: pairing.md "Entering and leaving pairing" has a
    // client that sent client/pair-finalize and then received server/activate in place of
    // server/pair-finalize persist nothing, so the attempt only becomes a pairing when that ack
    // arrives and the record is stored, which is what calls this. The window is closed only when
    // it is the one this connection's attempt ran under: an attempt it never admitted has not
    // spent the operator's gesture.
    if (this->pairing_window_conn_ != nullptr && this->pairing_window_conn_ == conn) {
        this->close_pairing_window();
    }
    this->client_->note_pairing_succeeded(conn->get_server_id());
}

void ConnectionManager::on_connection_lost(SendspinConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    if (this->find_admitted(conn) != nullptr) {
        SS_LOGI(TAG, "Admitted connection lost");
    } else if (this->find_in_nursery(conn) != this->nursery_.end()) {
        SS_LOGD(TAG, "Nursery connection lost");
    }
    // The transport is already gone, so no goodbye is attempted (nullopt). A connection the
    // manager no longer manages is a no-op.
    this->drop_connection(conn, std::nullopt);
}

std::vector<std::string> ConnectionManager::open_connection_psk_ids() const {
    std::vector<std::string> psk_ids;
    psk_ids.reserve(MAX_OPEN_CONNECTIONS);
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr && !entry.conn->get_psk_id().empty()) {
            psk_ids.push_back(entry.conn->get_psk_id());
        }
    }
    for (const auto& entry : this->nursery_) {
        if (!entry.conn->get_psk_id().empty()) {
            psk_ids.push_back(entry.conn->get_psk_id());
        }
    }
    return psk_ids;
}

// ============================================================================
// Protocol task: tick
// ============================================================================

void ConnectionManager::snapshot_connections(ConnectionSnapshot& out) const {
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr) {
            out.push_back(entry.conn);
        }
    }
    for (const auto& entry : this->nursery_) {
        out.push_back(entry.conn);
    }
}

void ConnectionManager::start_upgraded_handshakes() {
    // Level-triggered on the upgrade flag the transport sets (on_connected_cb), so a wake that
    // carried several upgrades, or one that raced the previous tick, is never missed. An inbound
    // entry sent its client/init at accept().
    for (auto& entry : this->nursery_) {
        if (!entry.client_init_sent && entry.conn->is_ws_upgraded()) {
            this->start_noise_handshake(entry);
        }
    }
}

uint32_t ConnectionManager::tick(int64_t now_us) {
    uint32_t next = this->scan_nursery(now_us);
    next = std::min(next, this->scan_admitted(now_us));

    // The pairing window's lifetime (pairing.md "Pairing Window"): closed silently at expiry,
    // whether or not it admitted an attempt.
    if (this->pairing_window_open_until_us_ != 0) {
        if (now_us >= this->pairing_window_open_until_us_) {
            this->close_pairing_window();
        } else {
            next = std::min(next, ms_until(this->pairing_window_open_until_us_, now_us));
        }
    }

    // The platform server's pending-upgrade reap (ESP: close sessions that never complete their
    // upgrade; host: none, IXWebSocket times them out itself).
    if (this->ws_server_ != nullptr) {
        next = std::min(next, this->ws_server_->tick());
    }
    next = std::min(next, this->maybe_start_ws_server(now_us));
    return next;
}

uint32_t ConnectionManager::run_time_sync() {
    uint32_t next = ProtocolTask::NO_DEADLINE;
    AdmittedEntry* primary = this->primary();
    for (auto& entry : this->admitted_) {
        SendspinConnection* conn = entry.conn.get();
        // Gate on is_operational() (hello + first server/activate), not just admission: an
        // in-band re-handshake resets first_activate_received_ on an admitted connection, and a
        // stale pre-re-handshake time exchange must not resume mid-rotation. A declared PAIRING
        // activity is not a gate: pairing.md "Entering and leaving pairing" runs pairing
        // alongside playback, leaving streams open and their timeline unaffected, which a player
        // can only deliver with its time filter still converging. A connection whose transport
        // is gone waits for its close to be processed.
        if (conn == nullptr || !conn->is_operational() || !conn->is_connected()) {
            continue;
        }
        SendspinTimeBurst& burst = conn->time_burst();

        // A burst holds the platform's high-performance networking for the round trips it
        // measures, so it requests the hold when it comes due and sends its first time frame only
        // once the main loop has granted it: called the listener and counted the grant
        // (SendspinClient::high_performance_granted()). The grant wakes the task, so a burst
        // waiting for it adds no deadline. The release at the burst's end waits for nothing.
        // One clock read for both, so the burst loop() may open is the one the request was made
        // for; loop() opens none without the grant (may_open_burst).
        const int64_t now_ms = platform_time_us() / US_PER_MS;
        if (!entry.high_performance_held && burst.starts_burst(now_ms)) {
            entry.high_performance_ticket = this->client_->request_high_performance(true);
            entry.high_performance_held = true;
        }
        const bool granted = entry.high_performance_held &&
                             this->client_->high_performance_granted(entry.high_performance_ticket);
        if (granted || !entry.high_performance_held) {
            const TimeBurstResult result = burst.loop(conn, now_ms, granted);
            if (result.burst_completed) {
                if (entry.high_performance_held) {
                    this->client_->request_high_performance(false);
                    entry.high_performance_held = false;
                }
                if (&entry == primary && conn->get_time_filter() != nullptr) {
                    this->client_->post_time_sync_error(conn->get_time_filter()->get_error());
                }
            }
            next = std::min(next, burst.ms_until_due(now_ms));
        }
        // A client/state held for this connection's clock goes out with its first measurement.
        if (entry.state_held && conn->is_time_synced()) {
            this->client_->publish_client_state(conn);
        }
    }
    return next;
}

void ConnectionManager::refresh_published_state() {
    AdmittedEntry* primary = this->primary();
    SendspinConnection* primary_conn = primary != nullptr ? primary->conn.get() : nullptr;
    const uint64_t primary_id = primary_conn != nullptr ? primary_conn->get_instance_id() : 0;
    if (primary_id != this->published_primary_id_) {
        // The slots change only with the primary connection: its filter is fixed at creation and
        // its server information is complete before admission (server/hello precedes it).
        this->published_primary_id_ = primary_id;
        std::shared_ptr<SendspinTimeFilter> filter =
            primary_conn != nullptr ? primary_conn->get_shared_time_filter() : nullptr;
        std::optional<ServerInformationObject> info =
            primary_conn != nullptr ? std::make_optional(primary_conn->get_server_information())
                                    : std::nullopt;
        {
            // Swapped under the leaf lock; what they replace is destroyed outside it.
            std::lock_guard<std::mutex> lock(this->time_filter_mutex_);
            this->time_filter_.swap(filter);
        }
        {
            std::lock_guard<std::mutex> lock(this->server_info_mutex_);
            this->server_information_.swap(info);
        }
    }

    bool connected = false;
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr && entry.conn->is_connected() && entry.conn->is_operational()) {
            connected = true;
            break;
        }
    }
    this->connected_.store(connected, std::memory_order_release);
}

void ConnectionManager::shutdown() {
    this->shutdown_done_ = true;

    // A code or pairing-window prompt still showing must be dismissed once the client has reset
    // its state; the flags live on the connections, so capture them before they go (see
    // PairingUiSnapshot). stop() queues the dismissal after its own cleanup.
    PairingUiSnapshot ui{false, false};
    InlineVector<std::shared_ptr<SendspinConnection>, MAX_OPEN_CONNECTIONS> to_goodbye;
    for (auto& entry : this->admitted_) {
        if (entry.conn == nullptr) {
            continue;
        }
        const PairingUiSnapshot entry_ui = snapshot_pairing_ui(entry.conn.get());
        ui.code_was_emitted |= entry_ui.code_was_emitted;
        ui.window_was_shown |= entry_ui.window_was_shown;
        entry.conn->detach_inbound();
        entry.conn->set_admitted(false);
        entry.conn->time_burst().reset();
        if (entry.high_performance_held) {
            this->client_->request_high_performance(false);
        }
        to_goodbye.push_back(std::move(entry.conn));
        entry = AdmittedEntry{};
    }
    for (auto& entry : this->nursery_) {
        const PairingUiSnapshot entry_ui = snapshot_pairing_ui(entry.conn.get());
        ui.code_was_emitted |= entry_ui.code_was_emitted;
        ui.window_was_shown |= entry_ui.window_was_shown;
        entry.conn->detach_inbound();
        to_goodbye.push_back(std::move(entry.conn));
    }
    this->nursery_.clear();
    // A standing pairing window belongs to this run; a restart begins with it closed.
    this->close_pairing_window();
    // Empties the time filter slot before stop() stops the role threads: a role thread that reads
    // it from here converts to 0, which reads as late.
    this->refresh_published_state();
    this->shutdown_ui_.code_was_emitted |= ui.code_was_emitted;
    this->shutdown_ui_.window_was_shown |= ui.window_was_shown;

    // Goodbye every connection, registering each count before any wait starts, so a completion
    // that runs inline (host, and any not-connected transport) cannot satisfy the wait early. A
    // disconnected connection completes immediately (see SendspinConnection::disconnect).
    if (this->shutdown_wait_ == nullptr) {
        this->shutdown_wait_ = std::make_shared<GoodbyeWait>();
    }
    std::shared_ptr<GoodbyeWait> wait = this->shutdown_wait_;
    for (auto& conn : to_goodbye) {
        wait->add_pending();
        ++this->shutdown_goodbyes_pending_;
        conn->disconnect(SendspinGoodbyeReason::SHUTDOWN, [wait] { wait->complete_one(); });
        this->closing_.push_back(std::move(conn));
    }
    this->flush_shutdown_goodbyes();
}

void ConnectionManager::flush_shutdown_goodbyes() {
    if (this->shutdown_goodbyes_pending_ == 0 || this->shutdown_wait_ == nullptr) {
        return;
    }
    // The bound scales with the goodbyes issued: on ESP they are handed to lwIP one at a time by
    // the single httpd worker, so several peers need several quanta.
    const uint32_t count = this->shutdown_goodbyes_pending_;
    const uint32_t flush_bound_ms = GOODBYE_FLUSH_TIMEOUT_MS * count;
    if (!this->shutdown_wait_->wait(flush_bound_ms)) {
        SS_LOGD(TAG, "Goodbye flush bound (%u ms for %u goodbyes) elapsed; closing regardless",
                static_cast<unsigned>(flush_bound_ms), static_cast<unsigned>(count));
    }
    this->shutdown_goodbyes_pending_ = 0;
}

// ============================================================================
// Protocol task: role ownership
// ============================================================================

AdmittedEntry* ConnectionManager::find_admitted(const SendspinConnection* conn) {
    if (conn == nullptr) {
        return nullptr;
    }
    for (auto& entry : this->admitted_) {
        if (entry.conn.get() == conn) {
            return &entry;
        }
    }
    return nullptr;
}

bool ConnectionManager::owns_role(const SendspinConnection* conn, SendspinRole role) const {
    for (const auto& entry : this->admitted_) {
        if (entry.conn.get() == conn && conn != nullptr) {
            return (entry.owned_roles & role_mask_bit(role)) != 0 && conn->is_role_active(role);
        }
    }
    return false;
}

SendspinConnection* ConnectionManager::role_owner(SendspinRole role) const {
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr && (entry.owned_roles & role_mask_bit(role)) != 0 &&
            entry.conn->is_role_active(role)) {
            return entry.conn.get();
        }
    }
    return nullptr;
}

AdmittedEntry* ConnectionManager::primary() {
    AdmittedEntry* first = nullptr;
    for (auto& entry : this->admitted_) {
        if (entry.conn == nullptr) {
            continue;
        }
        if ((entry.owned_roles & role_mask_bit(SendspinRole::PLAYER)) != 0) {
            return &entry;
        }
        if (first == nullptr) {
            first = &entry;
        }
    }
    return first;
}

uint16_t ConnectionManager::roles_owned_by_others(const AdmittedEntry* except) const {
    uint16_t owned = 0;
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr && &entry != except) {
            owned |= entry.owned_roles;
        }
    }
    return owned;
}

// ============================================================================
// Handoff support
// ============================================================================

void ConnectionManager::set_last_played_server_id(const std::string& server_id) {
    if (server_id.empty()) {
        this->last_played_server_id_.reset();
    } else {
        this->last_played_server_id_ = server_id;
    }
}

// ============================================================================
// Tick steps
// ============================================================================

uint32_t ConnectionManager::maybe_start_ws_server(int64_t now_us) {
    if (this->ws_server_ == nullptr || this->ws_server_->is_started() ||
        !this->accepting_.load(std::memory_order_acquire)) {
        return ProtocolTask::NO_DEADLINE;
    }
    if (now_us < this->ws_server_start_retry_time_us_) {
        return ms_until(this->ws_server_start_retry_time_us_, now_us);
    }
    // is_network_ready() is called here, on the protocol task, and from start() on the main loop
    // (see SendspinNetworkProvider).
    if (this->client_->network_provider_ == nullptr) {
        return ProtocolTask::NO_DEADLINE;
    }
    if (!this->client_->network_provider_->is_network_ready()) {
        return NETWORK_POLL_INTERVAL_MS;
    }
    if (!this->ws_server_->start(this->client_, this->client_->config_.httpd_psram_stack,
                                 this->client_->config_.httpd_priority,
                                 this->client_->config_.httpd_stack_size)) {
        // A persistent failure (e.g. the server port is already in use) is retried with backoff
        // instead of on every tick, which would spam the log.
        this->ws_server_start_retry_time_us_ = now_us + WS_SERVER_START_RETRY_US;
        return ms_until(this->ws_server_start_retry_time_us_, now_us);
    }
    return ProtocolTask::NO_DEADLINE;
}

uint32_t ConnectionManager::scan_nursery(int64_t now_us) {
    uint32_t next = ProtocolTask::NO_DEADLINE;

    // Hello scan. Arming is level-triggered on noise_handshake_complete_, which the receive path
    // sets with no event of its own. Each entry arms once (AWAIT_NOISE -> SENDING) and, once its
    // hello is queued, refused, or out of attempts, stays DONE (see HelloStep); the state lives
    // on the entry, so a second connection arriving mid-handshake cannot clobber the first's.
    for (auto& entry : this->nursery_) {
        SendspinConnection* c = entry.conn.get();
        if (entry.hello_step == HelloStep::AWAIT_NOISE) {
            if (!c->is_noise_handshake_complete()) {
                continue;
            }
            entry.hello_step = HelloStep::SENDING;
            entry.hello_due_us = now_us;
        }
        if (entry.hello_step != HelloStep::SENDING) {
            continue;
        }
        if (now_us < entry.hello_due_us) {
            next = std::min(next, ms_until(entry.hello_due_us, now_us));
            continue;
        }

        if (this->send_hello_message(entry.hello_attempts_left - 1, c)) {
            entry.hello_step = HelloStep::DONE;
            continue;
        }

        if (entry.hello_attempts_left > 1) {
            entry.hello_retry_delay_ms *= 2;
            entry.hello_attempts_left--;
            entry.hello_due_us =
                now_us + static_cast<int64_t>(entry.hello_retry_delay_ms) * US_PER_MS;
            next = std::min(next, ms_until(entry.hello_due_us, now_us));
            continue;
        }

        // Attempts exhausted: the establish-deadline reap below releases the entry.
        entry.hello_step = HelloStep::DONE;
    }

    // Admission: every nursery entry that has proven itself (is_operational(): hello handshake
    // complete and first server/activate applied and admissible; trust was already checked when
    // that activate was processed). The activate handler admits at once when the hello completed
    // first; this level-triggered pass covers the other order.
    for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
        if (!it->conn->is_operational()) {
            ++it;
            continue;
        }
        it = this->promote_or_arbitrate_nursery_entry(it);
    }

    // Establish reap: the only release path for peers that connect and then stall without
    // completing the hello, for outbound sockets whose transport never delivers a close (host
    // IXWebSocket), and so also for a connection whose hello never completed.
    for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
        const int64_t deadline_us =
            it->conn->get_provisional_time_us() + NURSERY_ESTABLISH_TIMEOUT_US;
        if (now_us >= deadline_us) {
            SS_LOGW(TAG, "Nursery connection stalled at %s (>%d s), dropping",
                    to_cstr(setup_stage(*it->conn)),
                    static_cast<int>(NURSERY_ESTABLISH_TIMEOUT_US / US_PER_SECOND));
            it = this->release_nursery_entry(it, SendspinGoodbyeReason::ANOTHER_SERVER);
            continue;
        }
        next = std::min(next, ms_until(deadline_us, now_us));
        ++it;
    }
    return next;
}

uint32_t ConnectionManager::scan_admitted(int64_t now_us) {
    uint32_t next = ProtocolTask::NO_DEADLINE;
    // The array is never compacted, so a drop below frees its slot without moving the others.
    for (auto& entry : this->admitted_) {
        SendspinConnection* conn = entry.conn.get();
        if (conn == nullptr) {
            continue;
        }

        // Liveness: a blackholed socket (no FIN, RST, or close frame) never produces a transport
        // close, so drop an admitted connection once its inbound silence reaches the timeout.
        if (this->liveness_timeout_us_ > 0) {
            if (liveness_expired(now_us, conn->get_last_receive_time_us(),
                                 this->liveness_timeout_us_)) {
                SS_LOGW(TAG, "Admitted connection silent for >%" PRId64 " ms, dropping as lost",
                        this->liveness_timeout_us_ / US_PER_MS);
                // The goodbye actively closes the transport, which the silent peer never will; an
                // inbound session would otherwise hold its server slot. Per the spec's
                // `client/goodbye` section, restart asks a server that was only slow to reconnect.
                this->drop_connection(conn, SendspinGoodbyeReason::RESTART);
                continue;
            }
            next = std::min(next, ms_until(now_us + liveness_remaining_us(
                                                        now_us, conn->get_last_receive_time_us(),
                                                        this->liveness_timeout_us_),
                                           now_us));
        }

        // Re-prove: an admitted connection is briefly non-operational while it re-proves itself,
        // after a successful in-band re-handshake (SendspinConnection::handle_noise_rehandshake(),
        // which leaves it awaiting the post-swap server/activate) or after the server acks
        // client/pair-finalize and is expected to rekey via one
        // (SendspinConnection::note_pairing_finalize_ack()). Both stamp provisional_time_us_ when
        // they enter this window. An admitted connection is never non-operational for any other
        // reason: a nursery entry is only admitted once it is operational, and an in-progress
        // pairing-code exchange keeps is_operational() true throughout (that flow has its own
        // timeouts: the attempt deadline below, and the pairing window while a gesture is
        // awaited). The stamp != 0 guard keeps the check inert for a connection never stamped.
        if (!conn->is_operational() && conn->get_provisional_time_us() != 0) {
            const int64_t deadline_us = conn->get_provisional_time_us() + REPROVE_TIMEOUT_US;
            if (now_us >= deadline_us) {
                SS_LOGW(TAG,
                        "Admitted connection failed to re-prove itself within %d s "
                        "(server_id=%s); dropping",
                        static_cast<int>(REPROVE_TIMEOUT_US / US_PER_SECOND),
                        conn->get_server_id().c_str());
                // Closed without a goodbye. One of the two windows this reaps starts at Noise
                // message 1, and connection.md "Re-handshake" lets the client start no application
                // message there but the handshake; the other ends at a rekey the peer has already
                // failed to perform. No goodbye reason describes either, and the peer learns the
                // same thing from the close, which the nullopt release below performs.
                this->drop_connection(conn, std::nullopt);
                continue;
            }
            next = std::min(next, ms_until(deadline_us, now_us));
        }

        // Pairing attempt timeout (pairing.md "Entering and leaving pairing"); local_abort_pairing
        // also withdraws an emitted code. Between the server's pair-finalize ack and the
        // post-rekey activate that reaches clear_pairing_state(), pairing_session_ still reports
        // its last pre-ack step and attempt_deadline_us keeps counting down against an exchange
        // that has already succeeded, so the check is skipped for that window: a slow rekey must
        // not abort a completed pairing. connection.md "Re-handshake": between Noise message 1 and
        // the new server/activate the client starts no application message but the handshake,
        // which a pair/abort would be. first_activate_received() is false for exactly that window,
        // so the abort waits for the activation; if it never comes, the re-prove check above
        // closes the connection instead and the attempt ends with it. pairing.md "Entering and
        // leaving pairing" bounds an attempt with a timeout "on expiry it sends pair/abort"; the
        // re-handshake rule is the narrower MUST NOT, and the wait it imposes is bounded by
        // REPROVE_TIMEOUT_US.
        const int64_t attempt_deadline_us = conn->pairing_session().attempt_deadline_us;
        if (attempt_deadline_us != 0 && !conn->is_pairing_finalized() &&
            conn->first_activate_received()) {
            if (now_us >= attempt_deadline_us) {
                SS_LOGW(TAG, "Pairing attempt timed out for server_id=%s; aborting",
                        conn->get_server_id().c_str());
                this->local_abort_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
                continue;
            }
            next = std::min(next, ms_until(attempt_deadline_us, now_us));
        }
    }
    return next;
}

// ============================================================================
// Connection setup
// ============================================================================

void ConnectionManager::setup_connection_callbacks(SendspinConnection* conn) {
    // Both run on the protocol task (SendspinConnection::process_inbound_message()).
    conn->on_json_message_cb = [this](SendspinConnection* c, const char* data, size_t len,
                                      int64_t timestamp) {
        this->client_->process_json_message(c, data, len, timestamp);
    };
    conn->on_binary_message_cb = [this](SendspinConnection* c, InboundMessage& message) {
        this->client_->process_binary_message(c, message);
    };
    conn->attach_inbound(this->client_->inbound_ring_.get(), this->client_->protocol_task_.get());
}

void ConnectionManager::start_noise_handshake(NurseryEntry& entry) {
    // client/init is sent proactively: the client is always the Noise responder regardless of
    // who opened the socket, but it still sends client/init first as the Sendspin protocol
    // client. The hello is armed later, once the Noise handshake completes (the hello scan in
    // scan_nursery()).
    entry.conn->init_noise_handshake(*this->client_->identity_, *this->client_->record_store_,
                                     std::string(NOISE_SUITE_CHACHAPOLY));
    entry.conn->send_noise_client_init();
    entry.client_init_sent = true;
}

NurseryEntry* ConnectionManager::find_in_nursery(const SendspinConnection* conn) {
    for (auto it = this->nursery_.begin(); it != this->nursery_.end(); ++it) {
        if (it->conn.get() == conn) {
            return it;
        }
    }
    return this->nursery_.end();
}

void ConnectionManager::install_admitted(std::shared_ptr<SendspinConnection> conn,
                                         uint16_t owned_roles) {
    for (auto& entry : this->admitted_) {
        if (entry.conn != nullptr) {
            continue;
        }
        entry = AdmittedEntry{};
        entry.owned_roles = owned_roles;
        // The admitted flag is what the transport routes on (admitted connections receive into
        // the ring) and what the dispatch gate reads; it tracks the slot exactly.
        conn->set_admitted(true);
        entry.conn = std::move(conn);
        this->refresh_published_state();
        return;
    }
    // promote_or_arbitrate_nursery_entry() frees a slot before it installs.
    assert(false && "install_admitted() with every admitted slot taken");
}

NurseryEntry* ConnectionManager::release_nursery_entry(
    NurseryEntry* it, std::optional<SendspinGoodbyeReason> reason) {
    auto conn = std::move(it->conn);
    auto next = this->nursery_.erase(it);
    release_connection(std::move(conn), reason);
    return next;
}

void ConnectionManager::release_connection(std::shared_ptr<SendspinConnection> conn,
                                           std::optional<SendspinGoodbyeReason> goodbye) {
    // Leaving the manager: stop its inbound traffic first, so nothing it sends during the goodbye
    // reaches the roles and its transport never waits on the protocol task. Outgoing sends,
    // including the goodbye itself, are unaffected. On ESP the httpd session slot keeps the
    // connection alive until the goodbye worker runs and the session closes; the host transports
    // send synchronously, so the goodbye and the close have both completed when disconnect()
    // returns.
    conn->detach_inbound();
    if (goodbye.has_value()) {
        conn->disconnect(goodbye.value(), nullptr);
    } else if (conn->is_connected()) {
        // No goodbye still closes the WebSocket (connection.md "Failure Handling", pairing.md
        // "Protocol Errors"): an inbound transport is held open by its server until the peer
        // closes otherwise. close_transport_now() is non-blocking on every platform.
        conn->close_transport_now();
    }
    // The caller's reference drops here.
    conn.reset();
}

// ============================================================================
// Hello handshake
// ============================================================================

bool ConnectionManager::send_hello_message(uint8_t remaining_attempts, SendspinConnection* conn) {
    if (!conn->is_connected()) {
        SS_LOGW(TAG, "Cannot send hello - not connected");
        return true;
    }

    std::string hello_message = this->client_->build_hello_message();

    // send_app_json (not send_text_message): client/hello is encrypted like every other
    // post-handshake message. The hello is only ever armed once the Noise handshake completes,
    // so the transport send_app_json routes to is always active here, and that path runs the
    // completion inline, on this task.
    SsErr err = conn->send_app_json(
        hello_message,
        [conn](bool success) {
            // Setting the flag is all that is needed: admission is level-triggered, so the
            // nursery scan observes is_handshake_complete() even when the peer's server/hello
            // raced ahead of this send.
            if (!success) {
                SS_LOGW(TAG, "Hello message send failed");
                return;
            }
            conn->set_client_hello_sent(true);
        },
        /*allow_before_hello=*/true);

    if (err == SsErr::OK) {
        return true;  // Successfully queued
    }

    if (err == SsErr::INVALID_STATE) {
        SS_LOGW(TAG, "No client connected for hello message");
        return true;  // Don't retry
    }

    SS_LOGW(TAG, "Failed to queue hello message (err=%d), %d attempts remaining",
            static_cast<int>(err), remaining_attempts);
    return false;
}

// ============================================================================
// Connection lifecycle
// ============================================================================

void ConnectionManager::drop_connections_using_psk_id(const std::string& psk_id,
                                                      const SendspinConnection* except) {
    if (psk_id.empty()) {
        return;
    }

    // Collect first, then drop: drop_connection() mutates the admitted slots and nursery_, so
    // dropping while walking the nursery would invalidate the iterator underneath us.
    InlineVector<std::shared_ptr<SendspinConnection>, MAX_OPEN_CONNECTIONS> doomed;
    for (const auto& entry : this->admitted_) {
        if (entry.conn != nullptr && entry.conn.get() != except &&
            entry.conn->get_psk_id() == psk_id) {
            doomed.push_back(entry.conn);
        }
    }
    for (const auto& entry : this->nursery_) {
        if (entry.conn.get() != except && entry.conn->get_psk_id() == psk_id) {
            doomed.push_back(entry.conn);
        }
    }

    for (const auto& conn : doomed) {
        SS_LOGI(TAG, "Record %s revoked; dropping its live session (server_id=%s)", psk_id.c_str(),
                conn->get_server_id().c_str());
        this->drop_connection(conn.get(), SendspinGoodbyeReason::UNAUTHORIZED);
    }
}

void ConnectionManager::drop_connection(SendspinConnection* conn,
                                        std::optional<SendspinGoodbyeReason> goodbye) {
    if (conn == nullptr) {
        return;
    }

    // A pairing window admits attempts only on the connection carrying its first, so losing that
    // connection closes it (pairing.md "Pairing Window"). Done before the branches below, which
    // release the connection this address identifies.
    if (conn == this->pairing_window_conn_) {
        this->close_pairing_window();
    }

    if (AdmittedEntry* entry = this->find_admitted(conn); entry != nullptr) {
        // Dropping an admitted connection: vacate its slot, then quiesce the client state no
        // remaining admitted connection owns. The slot stays empty; the next nursery
        // establishment is admitted into it.
        //
        // Snapshot before cleanup_connection_state() clears the queued pairing notes (see
        // PairingUiSnapshot), then queue the note_* calls after it.
        const PairingUiSnapshot ui = snapshot_pairing_ui(conn);
        conn->detach_inbound();
        conn->set_admitted(false);
        conn->time_burst().reset();
        if (entry->high_performance_held) {
            this->client_->request_high_performance(false);
        }
        std::shared_ptr<SendspinConnection> dropped = std::move(entry->conn);
        *entry = AdmittedEntry{};
        // Ahead of the slot refresh below: the teardown commands the stream to end before the
        // time filter slot stops naming this connection's filter (see docs/internals.md "Time
        // Filter Slot").
        this->client_->cleanup_connection_state(
            static_cast<uint16_t>(ALL_ROLES_MASK & ~this->roles_owned_by_others(nullptr)));
        this->refresh_published_state();
        release_connection(std::move(dropped), goodbye);
        this->dismiss_pairing_ui(ui.code_was_emitted, ui.window_was_shown);
        return;
    }

    if (auto it = this->find_in_nursery(conn); it != this->nursery_.end()) {
        // Dropping an unproven connection: no client-state cleanup (it was never admitted). A
        // code session only ever exists on an admitted connection, so no prompt can be showing
        // here; the dismissal is kept for symmetry with the other drop paths and costs two bool
        // reads. Snapshot before release for the same reason as the admitted path above.
        const PairingUiSnapshot ui = snapshot_pairing_ui(conn);
        this->release_nursery_entry(it, goodbye);
        this->dismiss_pairing_ui(ui.code_was_emitted, ui.window_was_shown);
    }
    // Not a managed connection: nothing to do (already released).
}

bool ConnectionManager::should_switch_to_new_server(const SendspinConnection* admitted,
                                                    const SendspinConnection* new_conn) const {
    // Applies admission.h::should_admit_connection (activity-priority arbitration). `admitted`
    // may be null (nothing to displace); the pure function's has_admitted=false path always
    // admits.
    const bool has_admitted = admitted != nullptr;
    // An incumbent whose pair-finalize was acked still reports the pre-finalize [PAIRING] set,
    // so tell rule 2 the pairing is no longer in flight rather than rewriting the activities
    // (see admission.h).
    const bool pairing_in_flight = !has_admitted || !admitted->is_pairing_finalized();
    return should_admit_connection(
        /*incoming_activities=*/new_conn->get_activities(),
        /*incoming_server_id=*/new_conn->get_server_id(),
        /*admitted_activities=*/
        has_admitted ? admitted->get_activities() : std::vector<SendspinActivity>{},
        /*admitted_server_id=*/has_admitted ? admitted->get_server_id() : std::string{},
        /*has_admitted=*/has_admitted,
        /*last_playback_server_id=*/this->last_played_server_id_,
        /*admitted_pairing_in_flight=*/pairing_in_flight);
}

void ConnectionManager::note_playback_activity(const SendspinConnection* conn) {
    // connection.md "Multiple servers (server-initiated)": only an ADMITTED connection updates
    // last_played_server_id, and only when it carries PLAYBACK.
    if (conn == nullptr || this->find_admitted(conn) == nullptr) {
        return;
    }
    if (!conn->has_activity(SendspinActivity::PLAYBACK)) {
        return;
    }
    const std::string& server_id = conn->get_server_id();
    if (server_id.empty()) {
        return;
    }
    // The RAM half updates here, because a later arbitration reads last_played_server_id_; the
    // provider writes for this and for the recency move below wait for
    // SendspinClient::flush_pending_persistence() on the main loop.
    this->client_->note_last_played_server(server_id);
    // A pair-finalize at capacity evicts against the recency order and spares only the records
    // of open connections, so a connection that closes later must not leave its record looking
    // least recent until a deferred move lands. RecordStore::mutex_ is a leaf (docs/conventions.md,
    // "Threading and cross-thread state"), and this holds no other lock.
    if (conn->get_psk_category() == PskCategory::LONG_TERM) {
        const std::string& psk_id = conn->get_psk_id();
        if (!psk_id.empty() && this->client_->record_store_->note_record_played(psk_id)) {
            this->client_->request_persist();
        }
    }
}

NurseryEntry* ConnectionManager::promote_or_arbitrate_nursery_entry(NurseryEntry* it) {
    auto conn = std::move(it->conn);
    auto next = this->nursery_.erase(it);

    // Role ownership decides whom the incoming connection competes with: the admitted
    // connections owning one of its roles, or, with no slot free, every admitted one.
    std::array<AdmittedRoles, MAX_ADMITTED> slots{};
    for (size_t i = 0; i < MAX_ADMITTED; ++i) {
        slots[i].occupied = this->admitted_[i].conn != nullptr;
        slots[i].owned_roles = this->admitted_[i].owned_roles;
    }
    const uint16_t incoming_roles = conn->get_active_role_mask();
    const uint32_t conflicts = admission_conflicts(incoming_roles, slots);

    if (conflicts != 0) {
        // The incoming side is always operational (hello + first activate applied), so
        // arbitration always runs on real activity data. No incumbent is ever evicted on timing
        // alone, and the incoming connection must win against every one it conflicts with.
        for (size_t i = 0; i < MAX_ADMITTED; ++i) {
            if ((conflicts & (1U << i)) == 0 ||
                this->should_switch_to_new_server(this->admitted_[i].conn.get(), conn.get())) {
                continue;
            }
            SS_LOGI(TAG, "Admission arbitration: reject incoming (keep admitted)");
            // Pairing connections receive pair/abort first (the reference dismissal for a
            // displaced pairing attempt); the goodbye after it is a benign over-send, since the
            // transport layer has no close-without-goodbye path to use instead.
            if (conn->has_activity(SendspinActivity::PAIRING)) {
                conn->send_app_json(format_pair_abort_message(PairAbortReason::CONCURRENT_ATTEMPT),
                                    nullptr);
            }
            release_connection(std::move(conn), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
            return next;
        }
        SS_LOGI(TAG, "Admission arbitration: switch to new server");
        for (size_t i = 0; i < MAX_ADMITTED; ++i) {
            if ((conflicts & (1U << i)) != 0) {
                this->drop_connection(this->admitted_[i].conn.get(),
                                      SendspinGoodbyeReason::ANOTHER_SERVER);
            }
        }
    }

    SendspinConnection* admitted = conn.get();
    this->install_admitted(std::move(conn),
                           claimable_roles(incoming_roles, this->roles_owned_by_others(nullptr)));

    // Notify the client and record playback activity, only for the winner.
    this->note_playback_activity(admitted);

    // An activate declaring pairing alone is not announced to the client as operational until
    // pairing finishes and the post-finalize re-handshake completes; one that also declares
    // playback is announced first, because pairing.md "Entering and leaving pairing" leaves
    // active_roles and streams untouched and going operational is what clears any stale pairing
    // state before the new attempt. A playback-capable connection may carry active roles with
    // pairing alone (messaging.md "server/activate"), and those still owe the initial
    // client/state (messaging.md "client/state"), published without going operational.
    const auto& activities = admitted->get_activities();
    const std::optional<SendspinPairMethod> pairing_method =
        selected_pairing_method(activities, admitted->get_pairing_method());
    const bool selects_pairing = pairing_method.has_value();

    if (!selects_pairing || contains_activity(activities, SendspinActivity::PLAYBACK)) {
        this->client_->on_handshake_complete(admitted);
    }
    if (selects_pairing) {
        SS_LOGI(TAG, "Pairing activate received (%s): entering pairing for server_id=%s",
                to_cstr(pairing_method.value()), admitted->get_server_id().c_str());
        this->handle_enter_pairing(admitted);
        if (!contains_activity(activities, SendspinActivity::PLAYBACK) &&
            !admitted->get_active_roles().empty() && this->find_admitted(admitted) != nullptr) {
            this->client_->publish_client_state(admitted);
        }
    }

    if (this->find_admitted(admitted) != nullptr) {
        SS_LOGI(TAG, "Connection admitted: server_id=%s", admitted->get_server_id().c_str());
    }
    return next;
}

// ============================================================================
// Pairing handlers
// ============================================================================

void ConnectionManager::handle_enter_pairing(SendspinConnection* conn) {
    // conn is an admitted connection whose activate selects pairing: one that just won admission
    // (see promote_or_arbitrate_nursery_entry()) or one already admitted (on_server_activate()).

    // An attempt is in flight from here until it finalizes or aborts: pairing messages are only
    // routed while it is (pairing.md "Entering and leaving pairing"). Playback is untouched.
    conn->set_pairing_in_progress(true);

    // The pairing server/activate counter (pairing.md "Pairing index") was already bumped at the
    // point this activate was received (on_server_activate()). Do not bump again here: this
    // handler can also be reached after the activate was applied (the "subsequent activate
    // transitions into pairing" branch applies the activate first, then calls this), so bumping
    // here would double-count or use a stale value.
    // The current value is captured into the pairing session below for the code-based branches
    // (sent as pairing_index and reused for the CPace sid).
    const uint32_t pairing_index = conn->get_pairing_index();

    const std::string& server_id = conn->get_server_id();
    const auto& selected_method = conn->get_pairing_method();

    if (selected_method.has_value() &&
        (selected_method.value() == SendspinPairMethod::DYNAMIC_PAIRING_CODE ||
         selected_method.value() == SendspinPairMethod::STATIC_PAIRING_CODE)) {
        this->handle_enter_pairing_code(conn, pairing_index, server_id, selected_method.value());
        return;
    }

    this->handle_enter_pairing_psk(conn, pairing_index, server_id);
}

void ConnectionManager::handle_enter_pairing_code(SendspinConnection* conn, uint32_t pairing_index,
                                                  const std::string& server_id,
                                                  SendspinPairMethod selected_method) {
    const bool is_dynamic = selected_method == SendspinPairMethod::DYNAMIC_PAIRING_CODE;
    const auto& static_code = this->client_->config_.static_pairing_code;
    const auto& pairing_format = conn->get_pairing_format();

    // Defensive: the client should not have advertised static_pairing_code without a configured
    // code, nor dynamic_pairing_code without an emission format the activation could name.
    if (!is_dynamic && !static_code.has_value()) {
        SS_LOGE(TAG, "handle_enter_pairing: no static pairing code configured for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }
    if (is_dynamic && !pairing_format.has_value()) {
        SS_LOGE(TAG, "handle_enter_pairing: no emission format selected for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // Capture the Noise handshake hash now, before any further I/O: a re-handshake would replace
    // it. If the hash is unavailable the PAKE sid and the code derivation cannot be computed, so
    // abort.
    auto hash_opt = conn->get_noise_handshake_hash();
    if (!hash_opt.has_value()) {
        SS_LOGE(TAG, "handle_enter_pairing: no handshake hash for server_id=%s; aborting",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    auto& ps = conn->pairing_session();
    ps.method = selected_method;
    ps.handshake_hash = hash_opt.value();
    ps.pairing_index = pairing_index;
    if (is_dynamic) {
        // Checked against the advertised formats when the activation was admitted.
        ps.format = pairing_format.value();
    } else {
        // CPace consumes the static code as PRS directly, so it is known here; a dynamic code
        // is only known once nonce_A arrives.
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access): checked above for the static method
        ps.prs = pairing_code_digits_prs(static_code.value());
    }

    // Gesture gating: the static pairing code gates every attempt on an operator gesture
    // (pairing.md "Pairing Window"); the dynamic one runs ungated until the round limit stands,
    // which holds attempts back until the same deliberate operator action clears it
    // (pairing.md "Rounds"). Both wait the same way, sending client/pair-pending, which is what
    // the limit asks a held-back attempt to send.
    const bool gesture_gated = !is_dynamic || this->pairing_round_limit_reached();

    if (gesture_gated && !this->pairing_window_admits(conn)) {
        // No window open: report the pending gesture with client/pair-pending and wait.
        // pair-pending does not start the attempt or its timeout (the server applies its
        // own timeout and cancels via server/activate), so no attempt deadline is armed
        // here (attempt_deadline_us == 0 disables the timeout check in scan_admitted()).
        ps.step = SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW;
        ps.attempt_deadline_us = 0;
        SS_LOGI(TAG,
                "Sending client/pair-pending (%s, gesture-gated, no window open) for "
                "server_id=%s",
                to_cstr(ps.method), server_id.c_str());
        conn->send_app_json(format_client_pair_pending_message(ps.pairing_index), nullptr);

        // Surface the pairing-window prompt to the operator, but only when the platform
        // implements the gesture UI (on_open_pairing_window's contract is that it fires only
        // when pairing_window_supported is true). A static_pairing_code attempt never gets here
        // without that flag (see offers_static_pairing_code()); a dynamic attempt held back by
        // the round limit does, and then has no way to proceed and waits for the server's own
        // timeout to cancel it.
        if (this->client_->config_.pairing_window_supported) {
            this->client_->note_open_pairing_window();
            ps.window_shown = true;
        } else {
            SS_LOGW(TAG,
                    "Gesture-gated %s attempt for server_id=%s but "
                    "pairing_window_supported=false: no operator prompt can be shown; "
                    "waiting for the server to cancel the attempt",
                    to_cstr(ps.method), server_id.c_str());
        }

        this->client_->note_pairing_started(server_id);
        return;
    }

    // Not gated, or a standing window is already open: start the attempt immediately
    // (start_pairing_attempt binds an open window to this connection; it does not spend it).
    this->start_pairing_attempt(conn);
    this->client_->note_pairing_started(server_id);
}

void ConnectionManager::handle_enter_pairing_psk(SendspinConnection* conn, uint32_t pairing_index,
                                                 const std::string& server_id) {
    // resolve_pairing_outcome mints the long-term PSK and the record that holds it. It cannot
    // fail: a pairing never fails for lack of record storage (pairing.md "Pairing Records"),
    // and room for the record is made where it is stored.
    auto outcome = this->client_->record_store_->resolve_pairing_outcome(server_id);

    // pairing.md "Pairing PSK Flow": after the pairing server/activate the client sends
    // client/pair-init followed immediately by client/pair-finalize, without waiting for a
    // server response. pair-init starts the attempt and carries the pairing index alone; the
    // PSK flow has no PAKE round and so no commit_B.
    SS_LOGI(TAG, "Sending client/pair-init (pairing_psk) for server_id=%s", server_id.c_str());
    conn->send_app_json(format_client_pair_init_message(pairing_index), nullptr);
    conn->pairing_session().attempt_deadline_us = platform_time_us() + PAIRING_ATTEMPT_TIMEOUT_US;

    // Send client/pair-finalize with the long-term PSK (base64url-encoded, 43 chars).
    SS_LOGI(TAG, "Sending client/pair-finalize for server_id=%s", server_id.c_str());
    // Named local rather than a temporary so the serialized message, which carries the raw
    // base64 long-term PSK, can be wiped once it has been handed to the transport.
    std::string finalize_msg = format_client_pair_finalize_message(outcome.psk);
    conn->send_app_json(finalize_msg, nullptr);
    secure_zero(finalize_msg.data(), finalize_msg.size());

    // Hold the pending record: committed to the RecordStore by the server/pair-finalize handler
    // on ack.
    conn->set_pending_pairing_record(std::move(outcome.record));

    this->client_->note_pairing_started(server_id);
}

void ConnectionManager::handle_pair_abort(SendspinConnection* conn, PairAbortReason reason) {
    // pair/abort received from the server during pairing.

    // A pair/abort that arrives after the receiver (us) has already ended the attempt (locally
    // aborted, or the server itself left pairing via a leftover server/activate) has no effect
    // (pairing.md "pair/abort"). is_pairing_in_progress() is cleared by clear_pairing_state() on
    // every path that ends an attempt, so it is the right proxy for "already ended" here.
    if (!conn->is_pairing_in_progress()) {
        SS_LOGI(TAG,
                "pair/abort (reason=%s) received for server_id=%s after the attempt already "
                "ended; ignoring (stale)",
                to_cstr(reason), conn->get_server_id().c_str());
        return;
    }

    SS_LOGW(TAG, "pair/abort received for server_id=%s reason=%s", conn->get_server_id().c_str(),
            to_cstr(reason));

    // Clean up pairing state. pairing.md "pair/abort": the sender closes the connection only for
    // reason concurrent_attempt, leaving it open on every other reason so the server can
    // re-activate pairing (or resume normal operation) on it. Mirrored here (the server, as
    // sender, is closing its side regardless; closing here just avoids waiting on the TCP
    // teardown). No wire pair/abort is sent: this one already arrived from the server.
    this->abort_pairing_attempt(
        conn, /*wire_abort_reason=*/std::nullopt,
        reason == PairAbortReason::CONCURRENT_ATTEMPT ? PairingDropAction::CLOSE_WITH_GOODBYE
                                                      : PairingDropAction::KEEP_OPEN,
        to_public_abort_reason(reason), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
}

void ConnectionManager::dismiss_pairing_ui(bool code_was_emitted, bool window_was_shown) {
    if (code_was_emitted) {
        this->client_->note_clear_pairing_code();
    }
    if (window_was_shown) {
        this->client_->note_close_pairing_window();
    }
}

void ConnectionManager::abort_pairing_attempt(SendspinConnection* conn,
                                              std::optional<PairAbortReason> wire_abort_reason,
                                              PairingDropAction drop_action,
                                              SendspinPairAbortReason public_reason,
                                              SendspinGoodbyeReason goodbye_reason) {
    // server_id is copied so it survives any tear-down below.
    const std::string server_id = conn->get_server_id();
    // Snapshot before clear_pairing_state()/drop_connection() clear it (see PairingUiSnapshot).
    const PairingUiSnapshot ui = snapshot_pairing_ui(conn);

    if (wire_abort_reason.has_value()) {
        conn->send_app_json(format_pair_abort_message(wire_abort_reason.value()), nullptr);
    }

    // On the admitted path drop_connection() -> cleanup_connection_state() clears the queued
    // pairing notes, so the note_* calls below must come after it.
    conn->clear_pairing_state();
    if (drop_action != PairingDropAction::KEEP_OPEN) {
        const std::optional<SendspinGoodbyeReason> drop_goodbye_reason =
            drop_action == PairingDropAction::CLOSE_WITH_GOODBYE
                ? std::optional<SendspinGoodbyeReason>(goodbye_reason)
                : std::nullopt;
        this->drop_connection(conn, drop_goodbye_reason);
    }

    // Queued after any drop_connection() so they survive to be dispatched on the main loop.
    this->client_->note_pairing_failed(server_id, public_reason);
    this->dismiss_pairing_ui(ui.code_was_emitted, ui.window_was_shown);
}

// ============================================================================
// Pairing-code handlers
// ============================================================================

void ConnectionManager::handle_pairing_message(SendspinConnection* conn,
                                               const ServerPairingMessage& message) {
    // All CPace / nonce / hash state is protocol-task-only, like this handler.

    // pairing.md "Entering and leaving pairing": a client that has aborted an attempt silently
    // discards pairing messages received before the next server/activate. is_pairing_in_progress()
    // is cleared by clear_pairing_state() on every path that ends an attempt (local abort, received
    // pair/abort, leftover activate), so a pairing message that races the abort and lands here
    // after the fact is discarded without re-aborting (which would otherwise fire on every stray,
    // now-stale message since ps.step is back to IDLE).
    if (!conn->is_pairing_in_progress()) {
        SS_LOGI(TAG,
                "handle_pairing_message: discarding pairing message (kind=%d) for "
                "server_id=%s; no attempt in progress",
                static_cast<int>(message.kind), conn->get_server_id().c_str());
        return;
    }

    switch (message.kind) {
        case PairingMessageKind::PAIR_INIT:
            this->handle_pair_init(conn, message);
            break;

        case PairingMessageKind::PAIR_AUTH:
            this->handle_pair_auth(conn, message);
            break;

        case PairingMessageKind::PAIR_CONFIRM:
            this->handle_pair_confirm(conn, message);
            break;

        case PairingMessageKind::MALFORMED: {
            auto& ps = conn->pairing_session();
            const std::string& server_id = conn->get_server_id();

            // A server pairing message (server/pair-init, server/pair-auth, or
            // server/pair-confirm) failed to parse. If no pairing-code session is active on this
            // connection, the frame is a stray protocol violation: e.g. a code-flow message
            // arriving during a pairing_psk exchange, which leaves ps.step IDLE. So drop it
            // without tearing the connection down.
            if (ps.step == SendspinConnection::PairingStep::IDLE) {
                SS_LOGW(TAG,
                        "handle_pairing_message: malformed pairing frame with no active "
                        "pairing-code session for server_id=%s; ignoring",
                        server_id.c_str());
                return;
            }

            // pairing.md "Protocol Errors": "a malformed or missing field ... is a protocol error:
            // the detecting side closes the WebSocket without sending any application-level error
            // message, and persists nothing." This is the one pairing-abort path that must NOT
            // send pair/abort and must close unconditionally, so it cannot route through
            // local_abort_pairing() (which always sends pair/abort and only closes for
            // concurrent_attempt).
            SS_LOGW(TAG,
                    "handle_pairing_message: malformed pairing frame during code pairing for "
                    "server_id=%s; closing per pairing.md Protocol Errors (no pair/abort sent)",
                    server_id.c_str());
            // clear_pairing_state() drops any pending pairing record, so nothing is persisted;
            // drop_connection() with goodbye=std::nullopt closes the transport without sending a
            // client/goodbye (or any other application-level message).
            // SendspinPairAbortReason has no dedicated "protocol error" value and none of the
            // wire-facing reasons fit (no pair/abort was received or sent); UNKNOWN is the
            // closest available local-only fit.
            this->abort_pairing_attempt(conn, /*wire_abort_reason=*/std::nullopt,
                                        PairingDropAction::CLOSE_SILENTLY,
                                        SendspinPairAbortReason::UNKNOWN);
            break;
        }
    }
}

void ConnectionManager::handle_pair_init(SendspinConnection* conn,
                                         const ServerPairingMessage& message) {
    auto& ps = conn->pairing_session();
    const std::string& server_id = conn->get_server_id();

    // Step 1: server/pair-init received. This step belongs to the dynamic pairing code alone;
    // the static flow goes straight from client/pair-init to server/pair-auth (pairing.md
    // "Static Pairing Code Flow"), so a PAIR_INIT while ps.method == STATIC_PAIRING_CODE is out
    // of sequence exactly as an out-of-order message is.
    if (ps.method != SendspinPairMethod::DYNAMIC_PAIRING_CODE ||
        ps.step != SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT) {
        this->close_on_sequence_violation(conn, "server/pair-init");
        return;
    }

    // pairing.md "Server -> Client: server/pair-init" carries nonce_A in the attempt's first
    // round only: the binding values, and so the pairing code, are unchanged across the rounds
    // that follow. A first round without it cannot derive a code, and a later round that carries
    // one is a message no conformant server sends, so both are protocol errors
    // (pairing.md "Protocol Errors"): close without a pair/abort and persist nothing. Ignoring a
    // late nonce would be no safer, since it must not move the code the operator already holds.
    const bool first_round = ps.round == 0;
    if (first_round != message.nonce_a.has_value()) {
        SS_LOGW(TAG,
                "handle_pairing_message: server/pair-init %s nonce_A in round %u for "
                "server_id=%s; closing per pairing.md Protocol Errors (no pair/abort sent)",
                message.nonce_a.has_value() ? "carries an unexpected" : "is missing its",
                static_cast<unsigned>(ps.round + 1), server_id.c_str());
        this->abort_pairing_attempt(conn, /*wire_abort_reason=*/std::nullopt,
                                    PairingDropAction::CLOSE_SILENTLY,
                                    SendspinPairAbortReason::UNKNOWN);
        return;
    }

    if (first_round) {
        ps.nonce_a = message.nonce_a.value();

        // Derive the code both formats share: the digest over the handshake hash and the two
        // binding nonces (pairing.md "Pairing code derivation").
        auto digest = pairing_code_digest(ps.handshake_hash.data(), ps.handshake_hash.size(),
                                          ps.nonce_a.data(), ps.nonce_a.size(), ps.nonce_b.data(),
                                          ps.nonce_b.size());
        if (!digest.has_value()) {
            SS_LOGE(TAG, "handle_pairing_message: pairing-code derivation failed for server_id=%s",
                    server_id.c_str());
            this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            return;
        }

        // The emission format decides both what the operator receives and what CPace consumes as
        // PRS: the six ASCII digits, or the 24 raw digest bytes the version-1 pairing token
        // carries (pairing.md "Pairing code derivation", "QR-code emission").
        std::string emitted;
        if (ps.format == SendspinPairingCodeFormat::QR_CODE) {
            auto code = pairing_code_qr_bytes(digest.value());
            ps.prs.assign(code.begin(), code.end());
            emitted = format_pairing_code_token(code);
        } else {
            std::string digits = pairing_code_digits(digest.value());
            ps.prs = pairing_code_digits_prs(digits);
            emitted = std::move(digits);
        }

        // Emit the code to the operator (queued for the main loop by note_display_pairing_code).
        // Record that one is being emitted so the abort/cleanup paths know to withdraw it. A
        // later round re-emits nothing: the code has not changed, so an emission that persists
        // (a display) is already showing the right one (pairing.md "Client verification").
        this->client_->note_display_pairing_code(emitted, ps.format);
        ps.code_emitted = true;
    }

    // The round counts from the moment its code is being emitted, whatever becomes of it
    // (pairing.md "Rounds").
    ++ps.round;
    ++this->pairing_rounds_since_verified_kc_;

    if (!this->start_pake_round(conn)) {
        return;
    }
    // No message sent yet: the client waits for server/pair-auth.
}

void ConnectionManager::handle_pair_auth(SendspinConnection* conn,
                                         const ServerPairingMessage& message) {
    auto& ps = conn->pairing_session();
    const std::string& server_id = conn->get_server_id();

    // Step 2: server/pair-auth received. Expect step AWAIT_SERVER_PAIR_AUTH.
    if (ps.step != SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_AUTH) {
        this->close_on_sequence_violation(conn, "server/pair-auth");
        return;
    }

    // Send client/pair-auth (pake_msg_2 = client CPace share) before deriving.
    const auto& client_share = ps.cpace.public_share();
    conn->send_app_json(format_client_pair_auth_message(client_share), nullptr);

    // Derive the MAC key from the server's share (pake_msg_1).
    // A derive failure means the peer share has the wrong length or encodes a
    // low-order point (a malformed or hostile share), not a wrong code: a wrong code
    // still produces a well-formed, non-low-order shared secret that only fails the
    // confirm-tag check in handle_pair_confirm().
    //
    // pairing.md "Protocol Errors": "a CPace share with the wrong length or encoding a
    // low-order point" is a protocol error: the detecting side closes the WebSocket
    // without sending any application-level error message, and persists nothing. This
    // is the same class as the MALFORMED case in handle_pairing_message(), so it follows
    // the same shape: no pair/abort, unconditional close.
    if (!ps.cpace.derive(message.pake_msg_1.data(), message.pake_msg_1.size())) {
        SS_LOGW(TAG,
                "handle_pairing_message: CPace::derive failed (malformed/low-order "
                "peer share) for server_id=%s; closing per pairing.md Protocol Errors "
                "(no pair/abort sent)",
                server_id.c_str());
        this->abort_pairing_attempt(conn, /*wire_abort_reason=*/std::nullopt,
                                    PairingDropAction::CLOSE_SILENTLY,
                                    SendspinPairAbortReason::UNKNOWN);
        return;
    }

    ps.step = SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_CONFIRM;
}

void ConnectionManager::handle_pair_confirm(SendspinConnection* conn,
                                            const ServerPairingMessage& message) {
    auto& ps = conn->pairing_session();
    RecordStore& store = *this->client_->record_store_;
    const std::string& server_id = conn->get_server_id();

    // Step 3: server/pair-confirm received. Expect step AWAIT_SERVER_PAIR_CONFIRM.
    if (ps.step != SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_CONFIRM) {
        this->close_on_sequence_violation(conn, "server/pair-confirm");
        return;
    }

    // Verify server_kc (server confirmation tag). A failure means the operator entered a
    // different code than the one this client emitted, which the Dynamic Pairing Code Flow
    // answers with another round rather than ending the attempt (pairing.md "Rounds").
    if (!ps.cpace.verify(message.server_kc.data(), message.server_kc.size())) {
        const bool can_retry = ps.method == SendspinPairMethod::DYNAMIC_PAIRING_CODE &&
                               !this->pairing_round_limit_reached();
        if (!can_retry) {
            SS_LOGW(TAG,
                    "handle_pairing_message: server_kc verification failed (pairing-code "
                    "mismatch) for server_id=%s; aborting (%s)",
                    server_id.c_str(),
                    ps.method == SendspinPairMethod::DYNAMIC_PAIRING_CODE
                        ? "round limit reached"
                        : "the static flow runs one round");
            // The attempt ends on a failed verification, which is what a pairing window counts
            // (pairing.md "Pairing Window").
            this->note_pairing_window_attempt_failed();
            this->local_abort_pairing(conn, PairAbortReason::PAIRING_CODE_MISMATCH);
            return;
        }

        // A retry keeps the attempt, its pairing code and its running attempt timeout in place;
        // the server answers with a fresh server/pair-init that begins the next round, which
        // carries no nonce because the binding values do not move.
        SS_LOGW(TAG,
                "handle_pairing_message: server_kc verification failed (pairing-code mismatch) "
                "for server_id=%s after round %u; sending client/pair-retry",
                server_id.c_str(), static_cast<unsigned>(ps.round));
        conn->send_app_json(format_client_pair_retry_message(), nullptr);
        ps.step = SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT;
        return;
    }

    // A verified server_kc is what the round limit counts back from (pairing.md "Rounds").
    this->pairing_rounds_since_verified_kc_ = 0;

    // Compute client_kc (our confirmation tag).
    auto client_kc_opt = ps.cpace.tag();
    if (!client_kc_opt.has_value()) {
        SS_LOGE(TAG, "handle_pairing_message: CPace::tag() failed for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // Both wrapped fields are sealed under the same CPace run (pairing.md "Wrapping"), so the
    // AEAD and the ISK are resolved once here, before the first of them is sent.
    const char* cipher_name = aead_cipher_name_from_noise_suite(conn->get_noise_suite_name());
    ScopedIsk isk(ps.cpace.isk());
    if (cipher_name == nullptr || !isk.has_value()) {
        SS_LOGE(TAG, "handle_pairing_message: cannot wrap (cipher=%s, isk=%s) for server_id=%s",
                cipher_name != nullptr ? cipher_name : "unknown",
                isk.has_value() ? "present" : "missing", server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // Send client/pair-confirm: the dynamic flow carries client_kc plus the sealed opening of
    // commit_B, the static flow client_kc alone (pairing.md "Client -> Server:
    // client/pair-confirm").
    if (ps.method == SendspinPairMethod::STATIC_PAIRING_CODE) {
        conn->send_app_json(format_client_pair_confirm_message(client_kc_opt.value()), nullptr);
    } else {
        auto wrapped_nonce =
            wrap_value(NONCE_WRAP_LABEL, cipher_name, ps.cpace.sid(), isk.value(), ps.nonce_b);
        if (!wrapped_nonce.has_value()) {
            SS_LOGE(TAG, "handle_pairing_message: wrapping nonce_B failed for server_id=%s",
                    server_id.c_str());
            this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            return;
        }
        conn->send_app_json(
            format_client_pair_confirm_message(client_kc_opt.value(), wrapped_nonce.value()),
            nullptr);
    }

    // Reset both flags immediately after dismissing: clear_pairing_state() does not run on this
    // success path, so a later inspection must not dismiss the same attempt's UI twice.
    this->dismiss_pairing_ui(ps.code_emitted, ps.window_shown);
    ps.code_emitted = false;
    ps.window_shown = false;

    // Now run the same resolve_pairing_outcome path as pairing_psk, then send
    // client/pair-finalize. The server will respond with server/pair-finalize.
    auto outcome = store.resolve_pairing_outcome(server_id);

    // The code-based flows carry the new PSK wrapped under the CPace output, not in the clear
    // (pairing.md "Wrapping"). K_wrap = SHA-256(PSK_WRAP_LABEL || sid || ISK); the PSK is
    // sealed with the connection's negotiated AEAD, a 12-byte all-zero nonce, and empty AD. The
    // label differs from the one nonce_B was sealed under, so the two fields never share a key.
    auto wrapped =
        wrap_value(PSK_WRAP_LABEL, cipher_name, ps.cpace.sid(), isk.value(), outcome.psk);
    if (!wrapped.has_value()) {
        SS_LOGE(TAG, "handle_pairing_message: wrapping the long-term PSK failed for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    SS_LOGI(TAG, "Sending client/pair-finalize (%s) for server_id=%s", to_cstr(ps.method),
            server_id.c_str());
    // Wiped after the send for the same reason as the unwrapped form above. The payload here is
    // the AEAD-wrapped PSK rather than raw key bytes, so this is the weaker of the two cases,
    // but the two finalize paths are kept identical so neither drifts.
    std::string finalize_msg = format_client_pair_finalize_wrapped_message(wrapped.value());
    conn->send_app_json(finalize_msg, nullptr);
    secure_zero(finalize_msg.data(), finalize_msg.size());
    conn->set_pending_pairing_record(std::move(outcome.record));

    ps.step = SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_FINALIZE;
}

void ConnectionManager::local_abort_pairing(SendspinConnection* conn, PairAbortReason reason) {
    // Ends the pairing-code session with a pair/abort on the wire; per pairing.md "pair/abort" only
    // concurrent_attempt also closes the connection.

    SS_LOGW(TAG, "local_abort_pairing: server_id=%s reason=%s", conn->get_server_id().c_str(),
            to_cstr(reason));

    // Best-effort pair/abort to the server (the connection is still live here).
    this->abort_pairing_attempt(
        conn, reason,
        reason == PairAbortReason::CONCURRENT_ATTEMPT ? PairingDropAction::CLOSE_WITH_GOODBYE
                                                      : PairingDropAction::KEEP_OPEN,
        to_public_abort_reason(reason), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
}

void ConnectionManager::close_on_sequence_violation(SendspinConnection* conn,
                                                    const char* message_type) {
    // pairing.md "Sequence violations": a pairing message out of sequence for the selected
    // method and the current state is a protocol error, and "Protocol Errors" has the detecting
    // side close the WebSocket without sending any application-level message. No pair/abort
    // goes out, and clear_pairing_state() inside abort_pairing_attempt() drops the pending
    // record, so nothing is persisted. SendspinPairAbortReason has no protocol-error value, so
    // the listener hears the local-only UNKNOWN.
    const auto& ps = conn->pairing_session();
    SS_LOGW(TAG,
            "handle_pairing_message: %s out of sequence (step=%d method=%s) for server_id=%s; "
            "closing per pairing.md Protocol Errors (no pair/abort sent)",
            message_type, static_cast<int>(ps.step), to_cstr(ps.method),
            conn->get_server_id().c_str());
    this->abort_pairing_attempt(conn, /*wire_abort_reason=*/std::nullopt,
                                PairingDropAction::CLOSE_SILENTLY,
                                SendspinPairAbortReason::UNKNOWN);
}

// ============================================================================
// Pairing window
// ============================================================================

void ConnectionManager::start_pairing_attempt(SendspinConnection* conn) {
    // The PairingSession was populated by handle_enter_pairing; this sends the client/pair-init
    // that starts the attempt and arms the attempt timeout that bounds it (pairing.md "Entering and
    // leaving pairing").
    //
    // An open window is not spent by starting an attempt: it runs for its own lifetime and
    // admits further attempts, but only on the connection carrying its first
    // (pairing.md "Pairing Window"), which is bound here.
    if (this->pairing_window_open() && this->pairing_window_conn_ == nullptr) {
        this->pairing_window_conn_ = conn;
    }

    auto& ps = conn->pairing_session();
    const std::string& server_id = conn->get_server_id();

    if (ps.method == SendspinPairMethod::DYNAMIC_PAIRING_CODE) {
        // Generate nonce_B and its commitment, then send client/pair-init with commit_B and
        // the required pairing_index (pairing.md "Client -> Server: client/pair-init"). The code
        // itself cannot be derived until the server's nonce_A arrives, so CPace starts in
        // handle_pair_init() rather than here.
        ps.nonce_b = pairing_generate_nonce();
        auto commit_b = pairing_code_commit(ps.nonce_b.data(), ps.nonce_b.size());
        if (!commit_b.has_value()) {
            SS_LOGE(TAG, "start_pairing_attempt: commitment derivation failed for server_id=%s",
                    server_id.c_str());
            this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            return;
        }

        SS_LOGI(TAG, "Sending client/pair-init (dynamic_pairing_code) for server_id=%s",
                server_id.c_str());
        conn->send_app_json(format_client_pair_init_message(commit_b.value(), ps.pairing_index),
                            nullptr);

        ps.step = SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT;
        ps.attempt_deadline_us = platform_time_us() + PAIRING_ATTEMPT_TIMEOUT_US;
        return;
    }

    // Static pairing code: the PRS handle_enter_pairing_code() set. Empty means it was never set
    // (defensive; that path always sets it for a static attempt).
    if (ps.prs.empty()) {
        SS_LOGE(TAG, "start_pairing_attempt: no static pairing code captured for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // pairing_index is required on every client/pair-init (pairing.md "Pairing index"); the
    // static flow carries no commit_B.
    SS_LOGI(TAG, "Sending client/pair-init (static_pairing_code) for server_id=%s",
            server_id.c_str());
    conn->send_app_json(format_client_pair_init_message(ps.pairing_index), nullptr);

    // The static flow has no rounds: its single CPace run is round 1 (pairing.md "PAKE").
    ps.round = 1;
    if (!this->start_pake_round(conn)) {
        return;
    }
    ps.attempt_deadline_us = platform_time_us() + PAIRING_ATTEMPT_TIMEOUT_US;
}

bool ConnectionManager::start_pake_round(SendspinConnection* conn) {
    // Both code-based flows run the same CPace exchange over the attempt's PRS and sid (pairing.md
    // "PAKE"); only the point at which the PRS becomes known differs, so the start lives here
    // rather than in each caller. The caller has already set ps.round to the number of the round
    // this run belongs to.
    auto& ps = conn->pairing_session();
    std::vector<uint8_t> sid = build_pake_sid(ps.handshake_hash, ps.pairing_index, ps.round);

    // ADb = "client" (our own AD), ADa = "server" (peer's AD): pairing.md "PAKE".
    if (!ps.cpace.start(CPaceRole::RESPONDER, ps.prs, sid, {}, pake_ad_client(),
                        pake_ad_server())) {
        SS_LOGE(TAG, "start_pake_round: CPace::start failed for server_id=%s",
                conn->get_server_id().c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return false;
    }
    ps.step = SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_AUTH;
    return true;
}

bool ConnectionManager::pairing_window_open() const {
    return this->pairing_window_open_until_us_ != 0 &&
           platform_time_us() < this->pairing_window_open_until_us_;
}

void ConnectionManager::open_pairing_window() {
    // A pairing session only ever exists on an admitted connection: pairing only starts once a
    // nursery entry has won admission (see the pairing branch in
    // promote_or_arbitrate_nursery_entry()).
    //
    // The window's lifetime runs from here and is not paused by the attempts it admits
    // (pairing.md "Pairing Window"), so it is armed whether or not an attempt is waiting: with
    // none waiting it stands open for a pairing activate arriving within its lifetime.
    //
    // The gesture is also the deliberate, manufacturer-defined operator action pairing.md
    // "Rounds" requires to clear a standing round limit, so it resets the count before anything
    // it admits can run.
    this->pairing_rounds_since_verified_kc_ = 0;
    this->pairing_window_conn_ = nullptr;
    this->pairing_window_failed_attempts_ = 0;
    this->pairing_window_open_until_us_ = platform_time_us() + WINDOW_LIFETIME_US;

    // The window admits attempts on one connection only (pairing.md "Pairing Window"), so the
    // gesture starts the first attempt it finds waiting and binds itself to that connection.
    for (const auto& entry : this->admitted_) {
        SendspinConnection* conn = entry.conn.get();
        if (conn != nullptr &&
            conn->pairing_session().step == SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW) {
            SS_LOGI(TAG, "Pairing window opened: starting the waiting %s attempt for server_id=%s",
                    to_cstr(conn->pairing_session().method), conn->get_server_id().c_str());
            this->start_pairing_attempt(conn);
            return;
        }
    }

    SS_LOGI(TAG, "Pairing window opened: standing open for %lld s awaiting a pairing attempt",
            static_cast<long long>(WINDOW_LIFETIME_S));
}

bool ConnectionManager::pairing_round_limit_reached() const {
    return this->pairing_rounds_since_verified_kc_ >= PAIRING_ROUND_LIMIT;
}

void ConnectionManager::close_pairing_window() {
    if (this->pairing_window_open_until_us_ == 0) {
        return;
    }
    this->pairing_window_open_until_us_ = 0;
    this->pairing_window_conn_ = nullptr;
    this->pairing_window_failed_attempts_ = 0;
    SS_LOGI(TAG, "Pairing window closed");
}

bool ConnectionManager::pairing_window_admits(const SendspinConnection* conn) const {
    return this->pairing_window_open() &&
           (this->pairing_window_conn_ == nullptr || this->pairing_window_conn_ == conn);
}

void ConnectionManager::note_pairing_window_attempt_failed() {
    if (!this->pairing_window_open()) {
        return;
    }
    ++this->pairing_window_failed_attempts_;
    if (this->pairing_window_failed_attempts_ < WINDOW_FAILED_ATTEMPT_LIMIT) {
        SS_LOGW(TAG, "Pairing window: %u of %u attempts failed verification",
                static_cast<unsigned>(this->pairing_window_failed_attempts_),
                static_cast<unsigned>(WINDOW_FAILED_ATTEMPT_LIMIT));
        return;
    }
    SS_LOGW(TAG, "Pairing window: %u failed attempts; closing the window",
            static_cast<unsigned>(WINDOW_FAILED_ATTEMPT_LIMIT));
    this->close_pairing_window();
}

// ============================================================================
// Unpair handler
// ============================================================================

void ConnectionManager::handle_server_unpair(SendspinConnection* conn) {
    // Only a session running on a long-term record is paired at all (messaging.md "server/unpair":
    // if the session is unpaired, ignore the message), so a pairing or Sentinel handshake has
    // nothing to drop.
    if (conn->get_psk_category() != PskCategory::LONG_TERM) {
        SS_LOGD(TAG, "server/unpair ignored (non-LONG_TERM category, server_id=%s)",
                conn->get_server_id().c_str());
        return;
    }

    // Copied: the drops below release the connection that owns the string.
    const std::string psk_id = conn->get_psk_id();
    SS_LOGI(TAG, "server/unpair: dropping record and disconnecting (server_id=%s, psk_id=%s)",
            conn->get_server_id().c_str(), psk_id.c_str());

    // Drop the matched pairing record (messaging.md "server/unpair"). The RAM erase runs here,
    // because a re-handshake on the revoked psk_id resolves against the store and must miss it
    // from this instant: deferring it would leave the credential usable until the flush. The slot
    // write is left to SendspinClient::flush_pending_persistence() on the main loop.
    if (this->client_->record_store_->note_record_removed(psk_id)) {
        this->client_->request_persist();
    }

    // Any OTHER session running on the same record is no longer trusted either; see
    // drop_connections_using_psk_id(). `conn` itself is excluded and dropped below with the
    // spec's UNPAIRED reason rather than UNAUTHORIZED.
    this->drop_connections_using_psk_id(psk_id, conn);

    this->drop_connection(conn, SendspinGoodbyeReason::UNPAIRED);
}

}  // namespace sendspin
