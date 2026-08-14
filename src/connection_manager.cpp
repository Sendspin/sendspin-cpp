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
#include "crypto/pin.h"
#include "crypto/psk_wrap.h"
#include "management.h"
#include "platform/crypto.h"
#include "platform/logging.h"
#include "platform/time.h"
#include "platform/types.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "sendspin/config.h"
#include "sendspin/types.h"
#include "server_connection.h"
#include "time_burst.h"
#include "ws_server.h"

#include <array>
#include <cstring>
#include <string>
#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.conn_mgr";

static constexpr int64_t WS_SERVER_START_RETRY_MS = 5000LL;
static constexpr int64_t WS_SERVER_START_RETRY_US = WS_SERVER_START_RETRY_MS * US_PER_MS;

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

/// @brief Overall deadline for a dynamic-PIN pairing attempt (mirrors the reference's 120 s
/// asyncio.timeout). If the server stalls mid-exchange the attempt is aborted and the PIN is
/// cleared from the display, rather than hanging until the transport eventually drops.
static constexpr int64_t PIN_ATTEMPT_TIMEOUT_US = 120LL * 1000LL * US_PER_MS;

/// @brief Lifetime of an open pairing window, from opening until client/pair-init is sent
/// (spec-recommended 5 minutes). On expiry the window closes silently.
static constexpr int64_t WINDOW_LIFETIME_US = 300LL * 1000LL * US_PER_MS;

/// @brief Dynamic-PIN gesture-gating floor (spec: Pairing Window): a session PIN shorter than
/// this many digits is gesture-gated even when the method is not escalated: short PINs are
/// bought with a gesture. static_pin is gesture-gated on every attempt.
static constexpr int PIN_GESTURE_GATE_MIN_LENGTH = 6;

/// @brief CPace sid label (spec "PAKE"): sid = LABEL || h || counter (big-endian uint32).
static constexpr char PAKE_SID_LABEL[] = "sendspin-pair-pake-v1";

/// @brief CPace ADa/ADb (spec "PAKE"): distinct associated data per side fixes a reflected-MAC
/// issue. The server is CPace role A, the client is role B.
static constexpr char PAKE_AD_SERVER[] = "server";  // ADa
static constexpr char PAKE_AD_CLIENT[] = "client";  // ADb

/// @brief Build the CPace sid for a PIN-pairing attempt: LABEL || h (32 bytes) || counter
/// (4-byte big-endian uint32), per spec "PAKE". `counter` is the pairing_index captured for this
/// attempt (SendspinConnection::PinSession::pairing_index).
static std::vector<uint8_t> build_pake_sid(const std::array<uint8_t, 32>& handshake_hash,
                                           uint32_t counter) {
    std::vector<uint8_t> sid;
    sid.reserve(sizeof(PAKE_SID_LABEL) - 1 + 32 + 4);
    sid.insert(sid.end(), PAKE_SID_LABEL, PAKE_SID_LABEL + sizeof(PAKE_SID_LABEL) - 1);
    sid.insert(sid.end(), handshake_hash.begin(), handshake_hash.end());
    sid.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
    sid.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
    sid.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
    sid.push_back(static_cast<uint8_t>(counter & 0xFF));
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

/// @brief Map NoiseCipherSuitePreference to the full Noise protocol suite name string.
/// On ESP-IDF, AESGCM is unusable: the esphome__noise-c ESP-IDF component builds with
/// NOISE_USE_AES=0 by default, so the "AESGCM" cipher name is never registered and
/// session creation by that suite name fails outright. Fall back to ChaChaPoly and warn.
static std::string suite_name_for(NoiseCipherSuitePreference pref) {
    if (pref == NoiseCipherSuitePreference::AESGCM) {
#ifdef ESP_PLATFORM
        SS_LOGW(TAG, "AESGCM cipher suite is not supported on ESP-IDF (not compiled into the "
                     "noise-c component); falling back to ChaChaPoly");
        return std::string(NOISE_SUITE_CHACHAPOLY);
#else
        return std::string(NOISE_SUITE_AESGCM);
#endif
    }
    return std::string(NOISE_SUITE_CHACHAPOLY);
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

ConnectionManager::ConnectionManager(SendspinClient* client) : client_(client) {}

ConnectionManager::~ConnectionManager() {
    // Move everything out under the locks, destroy outside them: a connection destructor can join
    // its transport thread (see DeferredRelease), which must not happen while a lock is held.
    // The two mutexes guard disjoint state and are taken in separate scopes, never nested.
    //
    // cppcheck (variableScope/unreadVariable) wants these vectors narrowed into the lock_guard
    // block below; that would destroy them (and join transport threads) while still locked.
    // cppcheck-suppress variableScope
    std::vector<std::shared_ptr<SendspinConnection>> pending_connected;
    // cppcheck-suppress variableScope
    std::vector<std::shared_ptr<SendspinConnection>> pending_disconnects;
    // cppcheck-suppress variableScope
    std::vector<ServerActivateEvent> pending_activates;
    // cppcheck-suppress variableScope
    std::vector<std::shared_ptr<SendspinConnection>> pending_rehandshakes;
    {
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        // cppcheck-suppress unreadVariable
        pending_connected = std::move(this->pending_connected_events_);
        // cppcheck-suppress unreadVariable
        pending_disconnects = std::move(this->pending_disconnect_events_);
        // cppcheck-suppress unreadVariable
        pending_activates = std::move(this->pending_activate_events_);
        // cppcheck-suppress unreadVariable
        pending_rehandshakes = std::move(this->pending_rehandshake_events_);
        this->has_pending_events_.store(false, std::memory_order_release);
    }

    std::shared_ptr<SendspinConnection> current;
    // cppcheck-suppress variableScope
    std::vector<NurseryEntry> nursery;
    // cppcheck-suppress variableScope
    std::vector<HelloRetryState> retries;
    // cppcheck-suppress variableScope
    std::vector<DeferredRelease> releases;
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        current = std::move(this->current_connection_);
        // cppcheck-suppress unreadVariable
        nursery = std::move(this->nursery_);
        // cppcheck-suppress unreadVariable
        retries = std::move(this->hello_retries_);
        // cppcheck-suppress unreadVariable
        releases = std::move(this->deferred_releases_);
        // Keep the hint atomics in sync with the now-empty containers (has_pending_events_ was
        // handled above under its own mutex). Nothing reads them again after destruction, but
        // this keeps the "atomic mirrors container" invariant unconditional rather than carving
        // out an exception for teardown.
        this->has_current_.store(false, std::memory_order_release);
        this->nursery_size_.store(0, std::memory_order_release);
        this->deferred_size_.store(0, std::memory_order_release);
        this->hello_retries_size_.store(0, std::memory_order_release);
    }
    // Locals release here. Queued goodbyes are skipped on destruction; shutdown drops slots
    // without a send.
}

// ============================================================================
// Public API
// ============================================================================

void ConnectionManager::connect_to(const std::string& url) {
    SS_LOGI(TAG, "Initiating client connection to: %s", url.c_str());

    auto client_conn = std::make_shared<SendspinClientConnection>(url);
    client_conn->set_auto_reconnect(false);
    client_conn->set_task_config(this->client_->config_.websocket_priority,
                                 this->client_->config_.websocket_stack_size);
    client_conn->set_websocket_payload_location(this->client_->config_.websocket_payload_location);
    client_conn->set_noise_buffer_location(this->client_->config_.noise_buffer_location);

    this->setup_connection_callbacks(client_conn.get());
    client_conn->on_connected_cb = [this](SendspinConnection* c) {
        // Only outbound transports fire this, so it is wired here rather than in
        // setup_connection_callbacks. The connect succeeded, so the WebSocket upgrade is complete;
        // record it and defer the hello arming to loop() (this runs on the network thread).
        // Inbound connections arrive already upgraded and arm their hello at admission.
        c->mark_ws_upgraded();
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->queue_pending_connected(c->shared_from_this());
    };
    client_conn->on_disconnected_cb = [this](SendspinConnection* conn) {
        // Defer to loop(); this callback runs on IXWebSocket's internal thread
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->queue_pending_disconnect(conn->shared_from_this());
    };

    client_conn->init_time_filter();

    // Start the nursery clock: loop() reaps the connection if it has not completed the hello
    // handshake within NURSERY_ESTABLISH_TIMEOUT_US. The stamp predates DNS/TCP resolve, which is
    // why outbound entries are exempt from the short upgrade deadline.
    client_conn->set_provisional_time_us(platform_time_us());

    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

        // A present-but-disconnected current connection (its close event not yet processed) is
        // being replaced. Tear its state down as on_connection_lost would (the transport is
        // already gone, so no goodbye), instead of leaving it to occupy the slot with orphaned
        // dispatch/time-filter/client state.
        if (this->current_connection_ != nullptr && !this->current_connection_->is_connected()) {
            this->drop_connection(this->current_connection_.get(), std::nullopt);
        }

        // Only one outbound attempt at a time: release any previous outbound entry before pushing
        // the new one. Otherwise it would be dropped with no goodbye and, on ESP, leave its httpd
        // session pinned.
        for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
            if (!it->inbound) {
                it = this->release_nursery_entry(it, SendspinGoodbyeReason::ANOTHER_SERVER);
            } else {
                ++it;
            }
        }

        // A user-initiated connect is admitted even against a full nursery: there is at most one
        // outbound entry (replaced above), so the nursery is still bounded (NURSERY_CAPACITY + 1)
        // and an explicit user request never fails against inbound peers.
        this->push_nursery_entry(NurseryEntry{client_conn, /*inbound=*/false});
        client_conn->start();
    }
    this->flush_deferred_releases();
}

void ConnectionManager::disconnect(SendspinGoodbyeReason reason) {
    // Collect under the lock, send outside it: disconnect() can block on the transport (and on
    // host outbound it joins the transport thread), which must not stall other manager entry
    // points. The connections stay in their slots until their close events arrive (or the
    // manager is destroyed).
    std::vector<std::shared_ptr<SendspinConnection>> to_disconnect;
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        if (this->current_connection_ != nullptr && this->current_connection_->is_connected()) {
            to_disconnect.push_back(this->current_connection_);
        }
        // Drain the nursery too. A connected entry gets a goodbye and leaves on its close event; an
        // unconnected (pre-upgrade) entry has no transport to goodbye and yields no close, so
        // release it here rather than leave it for the nursery deadline to reap.
        for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
            if (it->conn->is_connected()) {
                to_disconnect.push_back(it->conn);
                ++it;
            } else {
                it = this->release_nursery_entry(it, std::nullopt);
            }
        }
    }
    this->flush_deferred_releases();
    for (auto& conn : to_disconnect) {
        conn->disconnect(reason, nullptr);
    }
}

// ============================================================================
// Server lifecycle
// ============================================================================

void ConnectionManager::init_server(SendspinClient* client) {
    this->client_ = client;

    this->ws_server_ = std::make_unique<SendspinWsServer>();
    this->ws_server_->set_port(this->client_->config_.server_port);
    this->ws_server_->set_max_connections(this->client_->config_.server_max_connections);
    this->ws_server_->set_ctrl_port(this->client_->config_.httpd_ctrl_port);

    // Graceful rejection needs transport headroom: the manager can hold one established inbound
    // connection plus NURSERY_CAPACITY unproven ones, and rejecting a surplus peer with a
    // client/goodbye requires the transport to accept that peer's socket on top. Below this bound
    // the nursery-full goodbye path is unreachable; surplus peers are refused at accept instead
    // (and on ESP they wait unanswered in the TCP backlog, since httpd stops accepting).
    if (this->client_->config_.server_max_connections < NURSERY_CAPACITY + 2) {
        SS_LOGW(TAG,
                "server_max_connections (%u) is below %u (1 established + %u nursery + 1 spare); "
                "surplus peers will be refused at accept instead of receiving a goodbye",
                static_cast<unsigned>(this->client_->config_.server_max_connections),
                static_cast<unsigned>(NURSERY_CAPACITY + 2),
                static_cast<unsigned>(NURSERY_CAPACITY));
    }

    this->ws_server_->set_new_connection_callback(
        [this](std::shared_ptr<SendspinServerConnection> conn) {
            this->on_new_connection(std::move(conn));
        });

    this->ws_server_->set_connection_closed_callback(
        [this](std::shared_ptr<SendspinServerConnection> conn) {
            SS_LOGD(TAG, "Connection closed callback for socket %d", conn->get_sockfd());
            // Defer cleanup to loop() so on_connection_lost runs on the main thread alongside the
            // rest of the connection state mutations. Inbound closes share the outbound disconnect
            // queue: both carry the connection itself, so a stale event can never be mis-routed to
            // a new connection (drop_connection no-ops on connections it does not manage).
            std::lock_guard<std::mutex> lock(this->conn_mutex_);
            this->queue_pending_disconnect(std::move(conn));
        });

    // Connection lookup-by-sockfd. Used by the host build's ws_server to route IXWebSocket
    // messages; the ESP build ignores this and looks the connection up directly via
    // httpd_sess_get_ctx (set in open_callback), so its setter is a no-op stub.
    this->ws_server_->set_find_connection_callback(
        [this](int sockfd) -> std::shared_ptr<SendspinConnection> {
            std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
            if (this->current_connection_ != nullptr &&
                this->current_connection_->get_sockfd() == sockfd) {
                return this->current_connection_;
            }
            for (const auto& entry : this->nursery_) {
                if (entry.conn->get_sockfd() == sockfd) {
                    return entry.conn;
                }
            }
            return nullptr;
        });
}

bool ConnectionManager::DrainedEvents::any() const {
    return !this->connected.empty() || !this->disconnected.empty() || !this->activates.empty() ||
           !this->rehandshake.empty() || !this->pair_aborts.empty() ||
           !this->management_requests.empty() || !this->server_unpairs.empty() ||
           !this->pin_messages.empty() || !this->pairing_succeeded.empty() ||
           !this->pair_storage_failed.empty() || this->pairing_window_confirm;
}

void ConnectionManager::maybe_start_ws_server() {
    // Start WS server when network becomes ready. A persistent failure (e.g. the server port is
    // already in use) is retried with backoff instead of on every tick, which would spam the log.
    if (this->ws_server_ != nullptr && !this->ws_server_->is_started()) {
        const int64_t now_us = platform_time_us();
        if (now_us >= this->ws_server_start_retry_time_us_ && this->client_->network_provider_ &&
            this->client_->network_provider_->is_network_ready()) {
            if (!this->ws_server_->start(this->client_, this->client_->config_.httpd_psram_stack,
                                         this->client_->config_.httpd_priority,
                                         this->client_->config_.httpd_stack_size)) {
                this->ws_server_start_retry_time_us_ = now_us + WS_SERVER_START_RETRY_US;
            }
        }
    }
}

ConnectionManager::DrainedEvents ConnectionManager::swap_out_pending_events() {
    DrainedEvents ev;
    // Skip the conn_mutex_ acquisition entirely when the hint says all queues are
    // empty. Sound because every push site sets has_pending_events_ = true under
    // conn_mutex_ before releasing it (see the field's doc comment in connection_manager.h).
    if (this->has_pending_events_.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        ev.connected.swap(this->pending_connected_events_);
        ev.disconnected.swap(this->pending_disconnect_events_);
        ev.activates.swap(this->pending_activate_events_);
        ev.rehandshake.swap(this->pending_rehandshake_events_);
        ev.pair_aborts.swap(this->pending_pair_abort_events_);
        ev.management_requests.swap(this->pending_management_request_events_);
        ev.server_unpairs.swap(this->pending_server_unpair_events_);
        ev.pin_messages.swap(this->pending_pin_pairing_events_);
        ev.pairing_succeeded.swap(this->pending_pairing_succeeded_events_);
        ev.pair_storage_failed.swap(this->pending_pair_storage_failed_events_);
        ev.pairing_window_confirm = std::exchange(this->pending_pairing_window_confirm_, false);
        this->has_pending_events_.store(false, std::memory_order_release);
    }
    return ev;
}

void ConnectionManager::drain_lifecycle_events(DrainedEvents& ev) {
    // Connection close/disconnect events (inbound ws_server closes on both platforms,
    // outbound host IXWebSocket disconnects). Keyed on connection identity, never on
    // sockfd: the OS recycles fds, so an fd-keyed event could outlive its connection and
    // mis-route to a newcomer admitted onto the recycled fd. A connection already
    // released by an earlier event is a no-op inside drop_connection.
    for (auto& conn : ev.disconnected) {
        this->on_connection_lost(conn.get());
    }

    // Transport connected events: an outbound connection's WebSocket upgrade completed.
    // This is where the outbound side starts the Noise handshake (client_init is sent
    // proactively; the client is always the Noise responder regardless of who opened the
    // socket, but it still sends client/init first as the Sendspin protocol client). The
    // hello is armed later, once the Noise handshake completes (see the noise-completion
    // scan in scan_hello_and_nursery()). (Inbound connections arrive already upgraded and
    // are handled the same way in on_new_connection().) Guarded by nursery membership: a
    // connection promoted or released by an earlier event is skipped.
    for (auto& conn : ev.connected) {
        if (this->find_in_nursery(conn.get()) == this->nursery_.end()) {
            continue;
        }
        conn->init_noise_handshake(*this->client_->identity_, *this->client_->record_store_,
                                   suite_name_for(this->client_->config_.cipher_suite));
        conn->send_noise_client_init();
    }

    // In-band re-handshake completions: handle_noise_rehandshake() already swapped the
    // Noise session synchronously on the network thread and reset
    // server_hello_received_/client_hello_sent_/first_activate_received_ on the
    // connection; re-arm its hello here so the post-swap server/hello -> client/hello ->
    // server/activate cycle actually runs. Only meaningful for the current (already-
    // admitted) connection: a re-handshake never targets a nursery member (they have not
    // completed even their first hello yet), but this is guarded defensively in case a stale
    // event outlives a race with drop_connection.
    for (auto& conn : ev.rehandshake) {
        if (!conn || conn.get() != this->current_connection_.get()) {
            continue;
        }
        SS_LOGI(TAG, "Re-arming hello after in-band re-handshake");
        this->initiate_hello(conn.get());
    }

    // server/activate events: trust enforcement, operational gating, and admission
    // arbitration. ALL decisions (admissibility, arbitration, RecordStore mutations)
    // happen here on the main loop thread, never on the network thread.
    for (auto& event : ev.activates) {
        if (!event.conn) {
            continue;
        }
        const bool in_nursery = this->find_in_nursery(event.conn.get()) != this->nursery_.end();
        const bool is_current = event.conn.get() == this->current_connection_.get();
        if (!in_nursery && !is_current) {
            // Already released by an earlier event in the same loop() pass.
            continue;
        }

        // ==== Trust enforcement (admissibility check) ====
        const bool unpaired_access = this->client_->record_store_ != nullptr &&
                                     this->client_->record_store_->unpaired_access_enabled();

        // Compute the effective active_roles (sticky: nullopt keeps the prior set), except
        // when this activate omits active_roles and its activities are no longer
        // playback-capable: spec "Playback-capable connections" says the client treats the
        // persisted roles as empty in that case rather than rejecting the message (a later
        // activate can legally narrow activities without re-sending an empty active_roles).
        const bool playback_capable =
            is_playback_capable(event.conn->get_psk_category(), event.activities, unpaired_access);
        static const std::vector<std::string> EMPTY_ROLES{};
        const std::vector<std::string>& effective_roles =
            event.active_roles.has_value()
                ? event.active_roles.value()
                : (playback_capable ? event.conn->get_active_roles() : EMPTY_ROLES);
        const bool has_roles = !effective_roles.empty();

        // Trust enforcement against the PSK category the Noise handshake resolved for this
        // connection. Every connection has one: no server/activate can arrive before the
        // handshake completes.
        const bool trust_ok = admissible(event.conn->get_psk_category(), event.activities,
                                         has_roles, unpaired_access);

        if (!trust_ok) {
            SendspinGoodbyeReason reject_reason = SendspinGoodbyeReason::UNAUTHORIZED;
            if (event.conn->get_psk_category() == PskCategory::SENTINEL && !unpaired_access &&
                admissible(event.conn->get_psk_category(), event.activities, has_roles,
                           /*unpaired_access=*/true)) {
                reject_reason = SendspinGoodbyeReason::PAIRING_REQUIRED;
            }
            SS_LOGW(TAG, "server/activate inadmissible (psk_category=%d): closing with %s",
                    static_cast<int>(event.conn->get_psk_category()),
                    reject_reason == SendspinGoodbyeReason::PAIRING_REQUIRED ? "pairing_required"
                                                                             : "unauthorized");
            this->drop_connection(event.conn.get(), reject_reason);
            continue;
        }

        // ==== pairing_index counter (spec "Pairing index") ====
        // "the number of pairing server/activate messages received since the last Noise
        // handshake" is a RAW MESSAGE COUNT, not an accepted-attempt count: the server
        // counts every pairing activate it sends, including ones the client goes on to
        // reject (e.g. method_not_supported below). Bump here, at the single point every
        // pairing server/activate is received (structurally admissible activates only:
        // one rejected by the trust-enforcement block above is about to close the
        // connection and a fresh handshake will reset the counter anyway), so that a
        // rejected activate does not leave the client permanently behind the server's own
        // count. handle_enter_pairing() reads this value; it must not bump again.
        const bool is_pairing_activate =
            event.activities.size() == 1 && event.activities[0] == SendspinActivity::PAIRING;
        if (is_pairing_activate) {
            event.conn->bump_pairing_index();
        }

        // ==== Pairing-method admissibility (spec "pair/abort") ====
        // Structurally admissible ('pairing' alone is always an allowed activity set),
        // but a pairing activate additionally carries a pairing object whose method must
        // (a) match the matched PSK's category (pairing_psk iff the matched PSK IS the
        // Pairing PSK) and (b) currently be offered per the LIVE pairing config, which
        // may have drifted from the supported_pair_methods advertised at hello time. When
        // it is not, reply pair/abort(method_not_supported) and leave the connection open
        // (unlike the reasons above, this does not close the connection).
        // A pairing activate that names NO usable method (pairing object absent, or a
        // method string this client does not recognize; process_server_activate_message
        // logs the raw value) cannot start any flow.
        // Answering pair/abort here rather than ignoring the activate matters: a server
        // that never hears back sits waiting for the device forever, with nothing on
        // either side to explain the stall.
        if (is_pairing_activate && !event.pairing_method.has_value()) {
            SS_LOGW(TAG,
                    "server/activate declares pairing with no usable pairing.method "
                    "for server_id=%s; replying pair/abort(method_not_supported), "
                    "connection stays open",
                    event.conn->get_server_id().c_str());
            event.conn->send_app_json(
                format_pair_abort_message(PairAbortReason::METHOD_NOT_SUPPORTED), nullptr);
            continue;
        }

        if (is_pairing_activate && event.pairing_method.has_value()) {
            const SendspinPairMethod method = event.pairing_method.value();
            const bool category_ok = (method == SendspinPairMethod::PAIRING_PSK) ==
                                     (event.conn->get_psk_category() == PskCategory::PAIRING);
            // "Currently offered" mirrors exactly what build_hello_message() advertises
            // in supported_pair_methods (client.cpp): the RecordStore's live enabled
            // flags AND the platform-capability flags (a device with no PIN display
            // never offers dynamic_pin, regardless of the enabled flag).
            bool offered = true;
            if (this->client_->record_store_ != nullptr) {
                const RecordStore& rs = *this->client_->record_store_;
                const auto& cfg = this->client_->config_;
                switch (method) {
                    case SendspinPairMethod::PAIRING_PSK:
                        offered = rs.pairing_psk_enabled() && rs.pairing_psk().has_value();
                        break;
                    case SendspinPairMethod::DYNAMIC_PIN:
                        offered = cfg.pin_display_supported && rs.dynamic_pin_enabled();
                        break;
                    case SendspinPairMethod::STATIC_PIN:
                        offered = cfg.pairing_window_supported && rs.static_pin_enabled() &&
                                  rs.static_pin().has_value();
                        break;
                }
            }
            if (!category_ok || !offered) {
                SS_LOGW(TAG,
                        "server/activate selects unsupported pairing method (%s) for "
                        "server_id=%s; replying pair/abort(method_not_supported), "
                        "connection stays open",
                        to_cstr(method), event.conn->get_server_id().c_str());
                event.conn->send_app_json(
                    format_pair_abort_message(PairAbortReason::METHOD_NOT_SUPPORTED), nullptr);
                continue;
            }

            // ==== pin_length validation (dynamic_pin only) ====
            // The server computes L = max(client_min, server_min) clamped to 4-12 and
            // sends it in the activation's pairing object; the client validates it HERE,
            // on receipt of the activation (server/pair-init carries only nonce_A).
            // Absent, below the configured minimum, or outside the protocol's 4-12
            // range -> pair/abort(pin_length_unacceptable), connection stays open.
            if (method == SendspinPairMethod::DYNAMIC_PIN) {
                const int min_len = this->client_->record_store_ != nullptr
                                        ? this->client_->record_store_->dynamic_pin_min_length()
                                        : PIN_MIN_DIGITS;
                const int pin_len = event.pairing_pin_length.value_or(0);
                if (pin_len < min_len || pin_len < PIN_MIN_DIGITS || pin_len > PIN_MAX_DIGITS) {
                    SS_LOGW(TAG,
                            "server/activate pairing.pin_length=%d unacceptable (min=%d "
                            "floor=%d max=%d) for server_id=%s; replying "
                            "pair/abort(pin_length_unacceptable), connection stays open",
                            pin_len, min_len, PIN_MIN_DIGITS, PIN_MAX_DIGITS,
                            event.conn->get_server_id().c_str());
                    event.conn->send_app_json(
                        format_pair_abort_message(PairAbortReason::PIN_LENGTH_UNACCEPTABLE),
                        nullptr);
                    continue;
                }
            }
        }

        // ==== Admissible: apply the activate's state on the main loop ====
        const bool is_first = !event.conn->first_activate_received();
        // Pass the same active_roles the admissibility check above used: when the message
        // omitted active_roles but the connection is no longer playback-capable, that is
        // effective_roles == EMPTY_ROLES, and it must be applied (not left sticky) so the
        // persisted active_roles_ is actually cleared (spec "Playback-capable connections").
        const std::optional<std::vector<std::string>> active_roles_to_apply =
            event.active_roles.has_value()
                ? event.active_roles
                : (!playback_capable ? std::make_optional(EMPTY_ROLES) : std::nullopt);
        event.conn->apply_server_activate(event.activities, active_roles_to_apply,
                                          event.pairing_method, event.pairing_pin_length);

        // First activate on a long-term PSK: mark the record used (reference parity).
        // Safe here because RecordStore mutations stay on the main loop.
        //
        // Read the psk_id ONCE into a local. is_first is true again after every in-band
        // re-handshake (see the comment below), and a server may start the next
        // re-handshake while this activate is still queued, so a second read here could
        // straddle a network-thread rewrite and disagree with the first.
        if (is_first && event.conn->get_psk_category() == PskCategory::LONG_TERM &&
            this->client_->record_store_ != nullptr) {
            const std::string psk_id = event.conn->get_psk_id();
            if (!psk_id.empty()) {
                this->client_->record_store_->mark_record_used(psk_id);
            }
        }

        if (event.conn.get() == this->current_connection_.get()) {
            // Already admitted: no arbitration needed. is_first can still be true here
            // after an in-band re-handshake reset first_activate_received_; re-publish
            // state in that case, but only once the post-swap hello has also completed
            // (is_handshake_complete()); otherwise this is a stale pre-completion
            // activate and there is nothing to (re-)publish yet.
            this->note_playback_activity(event.conn.get());
            if (!is_first && event.conn->is_pairing_in_progress()) {
                // ==== Pairing leftover activate ====
                // Pairing was in progress and the server sent another server/activate
                // instead of server/pair-finalize: it abandoned pairing without
                // finalizing. Mirrors the reference's leftover branch: the activate was
                // already applied normally above; going operational discards any pending
                // record and resets the PIN session structurally (see the comment on
                // SendspinClient::on_handshake_complete()).
                SS_LOGI(TAG,
                        "Subsequent activate during pairing (leftover): clearing pairing "
                        "state and going operational for server_id=%s",
                        event.conn->get_server_id().c_str());
                this->client_->on_handshake_complete(event.conn.get());
            } else if (is_first && event.conn->is_handshake_complete()) {
                this->client_->on_handshake_complete(event.conn.get());
            } else if (!is_first) {
                // ==== Subsequent activate transitions into pairing ====
                // The operator can initiate pairing on an already-operational connection,
                // not only on the very first activate: the server re-activates the
                // connection with the PAIRING activity and a pairing object.
                // Mirrors the reference's _handle_server_activate, which runs _pair()
                // whenever the applied activate is a pairing activate, not only on the
                // first one. Only reached when pairing is not already in progress (the
                // leftover-activate branch above handles that case).
                const auto& activities = event.conn->get_activities();
                const auto& pairing_method = event.conn->get_pairing_method();
                const bool is_pairing_activity_only = activities.size() == 1 &&
                                                      activities[0] == SendspinActivity::PAIRING &&
                                                      pairing_method.has_value();
                const bool is_supported_pair_method =
                    is_pairing_activity_only &&
                    (pairing_method.value() == SendspinPairMethod::PAIRING_PSK ||
                     pairing_method.value() == SendspinPairMethod::DYNAMIC_PIN ||
                     pairing_method.value() == SendspinPairMethod::STATIC_PIN);
                if (is_supported_pair_method) {
                    SS_LOGI(TAG,
                            "Subsequent activate selects pairing (%s): entering pairing "
                            "for server_id=%s",
                            to_cstr(pairing_method.value()), event.conn->get_server_id().c_str());
                    this->handle_enter_pairing(event.conn.get());
                }
            }
            continue;
        }

        // A nursery entry's first activate always eventually resolves it (promoted or
        // rejected), so a nursery entry can never see a genuinely "subsequent" activate.
        // is_first is therefore always true here; the promotion itself is handled by the
        // level-triggered scan just below (not here), because this event only proves the
        // activate arrived. The hello handshake may still be in flight (e.g. a
        // nonconforming peer whose server/hello + server/activate race ahead of our own
        // client/hello). The scan promotes/arbitrates once BOTH are true, in whichever
        // order they complete. A pairing-flavored activate is not special-cased here: the
        // scan promotes the entry into current_connection_ exactly like any other
        // operational candidate (so admission.h's "in-flight pairing is not displaced"
        // arbitration rule applies to it), and only then branches into
        // handle_enter_pairing() instead of on_handshake_complete(); see
        // promote_or_arbitrate_nursery_entry().
    }

    // Promotion/arbitration scan: handles every nursery entry that has proven itself
    // (is_operational(): hello handshake complete AND first server/activate applied and
    // admissible; trust was already checked above, for every activate event, including
    // ones that arrived before the hello completed). Level-triggered rather than
    // edge-triggered on the activate events just processed, because hello completion is
    // itself level-triggered (see the establishment invariant note on
    // is_handshake_complete() elsewhere in this file): the two conditions can become true
    // in either order.
    for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
        if (!it->conn->is_operational()) {
            ++it;
            continue;
        }
        it = this->promote_or_arbitrate_nursery_entry(it);
    }
}

void ConnectionManager::drain_pairing_events(DrainedEvents& ev) {
    // ==== Pairing deferred events ====
    // pair/abort: clean up pairing state and close the connection. (The
    // server/pair-finalize ack is committed synchronously on the network thread, and the
    // leftover-activate case is handled inline in the subsequent-activate branch of
    // drain_lifecycle_events(), so neither needs a deferred event here.)
    for (auto& event : ev.pair_aborts) {
        if (!event.conn || event.conn.get() != this->current_connection_.get()) {
            continue;
        }
        this->handle_pair_abort(event.conn.get(), event.reason);
    }

    // ==== Dynamic-PIN pairing deferred events ====
    // Only ever targets the current connection: a PIN session only exists on a
    // connection that already won promotion into current_connection_ (see the pairing
    // branch in promote_or_arbitrate_nursery_entry()).
    for (auto& event : ev.pin_messages) {
        if (!event.conn || event.conn.get() != this->current_connection_.get()) {
            continue;
        }
        this->handle_pin_pairing_message(event.conn.get(), event);
    }

    // ==== on_pairing_succeeded deferred events ====
    // Triggered by the network-thread server/pair-finalize ack handler
    // (SendspinClient::schedule_pairing_succeeded); only ever targets the current
    // connection for the same reason as ev.pin_messages above.
    for (const auto& server_id : ev.pairing_succeeded) {
        this->client_->note_pairing_succeeded(server_id);
    }

    // ==== Pairing storage-failure deferred events ====
    // Only ever targets the current connection, for the same reason as
    // ev.pairing_succeeded above: pairing only exists on a connection that already
    // won promotion. A connection that already left current_connection_ (e.g. raced by a
    // disconnect event earlier in this same pass) still gets the listener notification
    // (handle_pair_storage_failed() reports it unconditionally) but skips the redundant
    // drop_connection()/pair-abort send.
    for (const auto& event : ev.pair_storage_failed) {
        this->handle_pair_storage_failed(event);
    }

    // ==== Static-PIN pairing-window confirm deferred event ====
    if (ev.pairing_window_confirm) {
        this->handle_pairing_window_confirmed();
    }
}

void ConnectionManager::drain_management_events(DrainedEvents& ev) {
    // ==== server/unpair deferred events ====
    // Only ever targets the current connection: server/unpair is only admissible post-
    // promotion (LONG_TERM trust with an active session), never a still-unproven nursery
    // entry.
    for (auto& event : ev.server_unpairs) {
        if (!event.conn || event.conn.get() != this->current_connection_.get()) {
            continue;
        }
        this->handle_server_unpair(event.conn.get(), event);
    }

    // ==== Management request deferred events ====
    // At-most-one-in-flight (server waits for result); FIFO processing is correct.
    for (auto& event : ev.management_requests) {
        if (!event.conn || event.conn.get() != this->current_connection_.get()) {
            continue;
        }
        this->handle_management_request(event.conn.get(), event);
    }
}

void ConnectionManager::loop_managed_connections() {
    // Call loop on active connections using shared_ptr copies to avoid holding the lock. The
    // nursery is bounded (NURSERY_CAPACITY inbound + 1 outbound), so a fixed array avoids a
    // per-tick heap allocation while connections are being set up.
    std::shared_ptr<SendspinConnection> current_copy;
    std::array<std::shared_ptr<SendspinConnection>, NURSERY_CAPACITY + 1> nursery_copies;
    size_t nursery_count = 0;
    // Skip the copy (and thus every conn->loop() call below) when there is nothing to call it
    // on: no current connection and an empty nursery.
    if (this->nursery_size_.load(std::memory_order_acquire) > 0 ||
        this->has_current_.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        current_copy = this->current_connection_;
        for (const auto& entry : this->nursery_) {
            nursery_copies[nursery_count++] = entry.conn;
        }
    }
    if (current_copy) {
        current_copy->loop();
    }
    for (size_t i = 0; i < nursery_count; ++i) {
        nursery_copies[i]->loop();
    }
}

void ConnectionManager::scan_hello_and_nursery() {
    // The nursery establish-deadline reap operates purely on nursery membership, so it is skipped
    // whenever the nursery is empty. Hello retry timers are not confined to nursery membership,
    // though: schedule_rehandshake_rearm() also arms one for the current (already-admitted)
    // connection while it re-proves itself after an in-band re-handshake; that connection is
    // never a nursery member, so hello_retries_size_ is checked alongside nursery_size_ to avoid
    // missing that case. The retry-timer scan's own lazy erase, for a retry whose connection left
    // the nursery AND is not the current connection, covers a connection dropped by an earlier
    // event this same tick.
    if (this->nursery_size_.load(std::memory_order_acquire) > 0 ||
        this->hello_retries_size_.load(std::memory_order_acquire) > 0) {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

        // Noise-completion scan: arm the hello for any nursery connection whose Noise
        // handshake just completed. Level-triggered because noise_handshake_complete_ flips on
        // the network thread (inside dispatch_completed_message/handle_noise_handshake_text)
        // with no corresponding queued event, unlike the connected-events edge above. Skips
        // connections whose hello is already sent or already has a pending retry, so a
        // connection is armed exactly once.
        for (const auto& entry : this->nursery_) {
            SendspinConnection* c = entry.conn.get();
            if (c->has_client_hello_sent() || this->has_hello_retry(c)) {
                continue;
            }
            if (!c->is_noise_handshake_complete()) {
                continue;
            }
            this->initiate_hello(c);
        }

        // Check hello retry timers (one entry per managed connection, so a second connection
        // arriving mid-handshake cannot clobber the first connection's pending hello).
        {
            const int64_t now_us = platform_time_us();
            for (auto it = this->hello_retries_.begin(); it != this->hello_retries_.end();) {
                HelloRetryState& retry = *it;
                SendspinConnection* rc = retry.conn.get();
                const bool retry_is_current = rc == this->current_connection_.get();

                // Drop retries whose connection is neither a nursery member nor the current
                // connection. A retry entry is normally live only for nursery members; the
                // exception is the current connection transiently re-arming its hello after an
                // in-band re-handshake (schedule_rehandshake_rearm()).
                if (this->find_in_nursery(rc) == this->nursery_.end() && !retry_is_current) {
                    it = this->hello_retries_.erase(it);
                    continue;
                }

                if (retry.retry_time_us == 0 || now_us < retry.retry_time_us) {
                    ++it;
                    continue;
                }

                if (this->send_hello_message(retry.attempts - 1, rc)) {
                    // Sent, or the connection left the nursery; the retry is complete.
                    it = this->hello_retries_.erase(it);
                    continue;
                }

                // Transient failure: retry with exponential backoff until attempts are exhausted.
                if (retry.attempts > 1) {
                    retry.delay_ms *= 2;
                    retry.attempts--;
                    retry.retry_time_us = now_us + static_cast<int64_t>(retry.delay_ms) * US_PER_MS;
                    ++it;
                    continue;
                }

                // Retries exhausted. A nursery member is reaped by the establish-deadline scan
                // just below; the current connection has no such deadline (it is established by
                // construction and normally never awaits a hello), so if its post-re-handshake
                // hello cannot be sent after 3 attempts, drop it directly here instead of leaving
                // it silently wedged in a non-operational state forever.
                it = this->hello_retries_.erase(it);
                if (retry_is_current) {
                    SS_LOGW(TAG, "Post-re-handshake hello send exhausted retries; dropping");
                    this->drop_connection(rc, std::nullopt);
                }
            }
            this->hello_retries_size_.store(this->hello_retries_.size(), std::memory_order_release);
        }

        // Nursery tick: reap connections that miss the establish deadline. This is the only
        // release path for peers that connect and then stall without completing the hello, and
        // for outbound sockets whose transport never delivers a close (host IXWebSocket, issue
        // #75). Hello arming is event-driven (admission for inbound, connected event for
        // outbound), so the tick only ever reaps.
        {
            const int64_t now_us = platform_time_us();
            for (auto it = this->nursery_.begin(); it != this->nursery_.end();) {
                const NurseryEntry& entry = *it;
                if (now_us - entry.conn->get_provisional_time_us() >=
                    NURSERY_ESTABLISH_TIMEOUT_US) {
                    SS_LOGW(TAG, "Nursery connection stalled at %s (>%d s), dropping",
                            to_cstr(setup_stage(*entry.conn)),
                            static_cast<int>(NURSERY_ESTABLISH_TIMEOUT_US / US_PER_SECOND));
                    it = this->release_nursery_entry(it, SendspinGoodbyeReason::ANOTHER_SERVER);
                    continue;
                }
                ++it;
            }
        }
    }
}

void ConnectionManager::scan_pin_attempt_timeout() {
    // ==== Dynamic-PIN attempt timeout ====
    // Abort a dynamic-PIN exchange that has stalled past PIN_ATTEMPT_TIMEOUT_US (mirrors the
    // reference's per-attempt timeout). local_abort_pin_pairing also clears the displayed PIN.
    // Only the current connection can host a PIN session (see the pairing branch in
    // promote_or_arbitrate_nursery_entry()).
    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    if (this->current_connection_ != nullptr) {
        const auto& ps = this->current_connection_->pin_session();
        const int64_t now_us = platform_time_us();
        const bool pin_attempt_expired = ps.step != SendspinConnection::PinStep::IDLE &&
                                         ps.attempt_deadline_us != 0 &&
                                         now_us >= ps.attempt_deadline_us;
        if (pin_attempt_expired) {
            SS_LOGW(TAG, "Dynamic-PIN attempt timed out for server_id=%s; aborting",
                    this->current_connection_->get_server_id().c_str());
            this->local_abort_pin_pairing(this->current_connection_.get(),
                                          PairAbortReason::ATTEMPT_TIMEOUT);
        }
    }
}

void ConnectionManager::scan_reprove_watchdog() {
    // ==== Re-proving watchdog ====
    // current_connection_ is briefly non-operational while it re-proves itself: after a
    // successful in-band re-handshake (SendspinConnection::handle_noise_rehandshake(), re-armed
    // via schedule_rehandshake_rearm()) or after the server acks client/pair-finalize and is
    // expected to rekey via one (SendspinConnection::note_pairing_finalize_ack()). Both call
    // sites reset provisional_time_us_ to a fresh (non-zero) timestamp when they enter this
    // window. current_connection_ is never non-operational for any other reason: a nursery
    // entry is only ever promoted once it is already operational (see
    // promote_or_arbitrate_nursery_entry()), and an in-progress PIN-pairing PAKE exchange keeps
    // is_operational() true throughout (that flow has its own timeouts: the PIN_ATTEMPT_TIMEOUT_US
    // check above, and pairing_window_open() while a gesture is awaited). Gating on
    // !is_operational() here therefore reaps exactly the re-proving window and never a
    // legitimate pairing wait. The provisional_time_us_ != 0 guard additionally excludes a
    // connection that was never stamped, keeping the check inert for anything that reaches
    // current_connection_ by a route that skips both admission paths.
    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    if (this->current_connection_ != nullptr && !this->current_connection_->is_operational()) {
        const int64_t provisional_us = this->current_connection_->get_provisional_time_us();
        const int64_t now_us = platform_time_us();
        if (provisional_us != 0 && now_us - provisional_us >= REPROVE_TIMEOUT_US) {
            SS_LOGW(TAG,
                    "Current connection failed to re-prove itself within %d s "
                    "(server_id=%s); dropping",
                    static_cast<int>(REPROVE_TIMEOUT_US / US_PER_SECOND),
                    this->current_connection_->get_server_id().c_str());
            this->drop_connection(this->current_connection_.get(),
                                  SendspinGoodbyeReason::ANOTHER_SERVER);
        }
    }
}

void ConnectionManager::loop() {
    this->maybe_start_ws_server();

    // Process deferred connection lifecycle events: one conn_mutex_ swap, then (when there is
    // something to do) one conn_ptr_mutex_ section applying lifecycle, pairing, and management
    // events in order.
    DrainedEvents ev = this->swap_out_pending_events();

    // Also runs whenever the nursery is non-empty even with no swapped-out events: the
    // noise-completion scan in scan_hello_and_nursery() (called further down) is
    // level-triggered on handshake flags set by network threads with no corresponding event
    // push, so loop() must keep running every tick a nursery connection exists.
    if (ev.any() || this->nursery_size_.load(std::memory_order_acquire) > 0) {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        this->drain_lifecycle_events(ev);
        this->drain_pairing_events(ev);
        this->drain_management_events(ev);
    }

    // Send the goodbyes and release the connections dropped above, outside the lock.
    this->flush_deferred_releases();

    // Call loop() on active connections using shared_ptr copies to avoid holding the lock.
    this->loop_managed_connections();

    // Noise-completion scan, hello retry timers, and the nursery establish-deadline reap.
    this->scan_hello_and_nursery();

    // Send the goodbyes and release the connections reaped by the nursery tick, outside the lock.
    this->flush_deferred_releases();

    // Drive the platform ws_server's pending-upgrade reap (ESP: close sessions that never
    // complete their upgrade; host: no-op, IXWebSocket times them out itself). Called with no
    // manager lock held.
    if (this->ws_server_ != nullptr) {
        this->ws_server_->tick();
    }

    // Abort a dynamic-PIN exchange that has stalled past its attempt timeout.
    this->scan_pin_attempt_timeout();
    // Send the goodbye and release the connection if the PIN-timeout check above aborted one.
    this->flush_deferred_releases();

    // Drop the current connection if it failed to re-prove itself after an in-band re-handshake
    // or a pairing-finalize rekey.
    this->scan_reprove_watchdog();
    // Send the goodbye and release the connection if the re-proving watchdog above dropped one.
    this->flush_deferred_releases();
}

// ============================================================================
// Connection queries
// ============================================================================

bool ConnectionManager::is_connected() const {
    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    return this->current_connection_ != nullptr && this->current_connection_->is_connected() &&
           this->current_connection_->is_operational();
}

// ============================================================================
// Handoff support
// ============================================================================

void ConnectionManager::set_last_played_server_id(const std::string& server_id) {
    this->last_played_server_id_ = server_id;
    this->has_last_played_server_ = !server_id.empty();
}

// ============================================================================
// Event queuing (thread-safe)
// ============================================================================

void ConnectionManager::schedule_activate(ServerActivateEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_activate(std::move(event));
}

void ConnectionManager::schedule_rehandshake_rearm(std::shared_ptr<SendspinConnection> conn) {
    // Called from SendspinClient::process_json_message() on the network thread, right after
    // SendspinConnection::handle_noise_rehandshake() returns success.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_rehandshake(std::move(conn));
}

void ConnectionManager::schedule_pair_abort(PairAbortEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread when a pair/abort
    // message arrives (or a malformed pairing frame forces one).
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_pair_abort(std::move(event));
}

void ConnectionManager::schedule_management_request(ManagementRequestEvent&& event) {
    // Called from SendspinClient::process_json_message() on the network thread when a
    // management/* request arrives.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_management_request(std::move(event));
}

void ConnectionManager::schedule_server_unpair(ServerUnpairEvent&& event) {
    // Called from SendspinClient::process_json_message() on the network thread when
    // server/unpair arrives.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_server_unpair(std::move(event));
}

void ConnectionManager::schedule_pin_pairing_message(ServerPairingMessageEvent&& event) {
    // Called from SendspinClient::process_json_message() on the network thread when a dynamic-PIN
    // pairing message arrives (or a malformed pairing frame forces a MALFORMED event).
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_pin_pairing_message(std::move(event));
}

void ConnectionManager::schedule_pairing_succeeded(std::string server_id) {
    // Called from SendspinClient::process_json_message() on the network thread when the
    // server/pair-finalize ack handler stores a long-term record.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_pairing_succeeded(std::move(server_id));
}

void ConnectionManager::schedule_pair_storage_failed(PairStorageFailedEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread when
    // RecordStore::store_record() reports that the persistence provider rejected the record.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending_pair_storage_failed(std::move(event));
}

void ConnectionManager::schedule_pairing_window_confirm() {
    // Called from SendspinClient::confirm_pairing_window(), which may run on any thread
    // (typically the application's UI thread relaying an operator gesture).
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->pending_pairing_window_confirm_ = true;
    this->has_pending_events_.store(true, std::memory_order_release);
}

// ============================================================================
// Connection setup
// ============================================================================

void ConnectionManager::setup_connection_callbacks(SendspinConnection* conn) {
    conn->on_json_message_cb = [this](SendspinConnection* c, const char* data, size_t len,
                                      int64_t timestamp) {
        this->client_->process_json_message(c, data, len, timestamp);
    };
    conn->on_binary_message_cb = [this](SendspinConnection* c, uint8_t* payload, size_t len) {
        this->client_->process_binary_message(c, payload, len);
    };
}

void ConnectionManager::on_new_connection(std::shared_ptr<SendspinServerConnection> conn) {
    // Called from the platform ws_server's delivery path (ESP: httpd task, host: IXWebSocket
    // thread) once the connection's WebSocket upgrade has been observed, so the manager never sees
    // a socket that has not proven it speaks WebSocket. The authoritative owner is the platform's
    // session/transport context; this observer shared_ptr can be reset at any time without freeing
    // the conn out from under in-flight workers.
    conn->init_time_filter();
    conn->set_websocket_payload_location(this->client_->config_.websocket_payload_location);
    conn->set_noise_buffer_location(this->client_->config_.noise_buffer_location);

    this->setup_connection_callbacks(conn.get());
    conn->on_disconnected_cb = [](SendspinConnection* /*c*/) {
        // Cleanup happens in on_connection_lost triggered by the server
    };

    // Start the establish clock: loop() reaps the connection if it does not complete the hello
    // handshake within NURSERY_ESTABLISH_TIMEOUT_US.
    conn->set_provisional_time_us(platform_time_us());

    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);

        // The newcomer has not completed the hello handshake, so it never touches the current
        // slot; it enters the bounded nursery and is promoted only once it establishes. Only
        // inbound entries count against the capacity (see NURSERY_CAPACITY). If the inbound slots
        // are full, reject the newcomer: every occupant speaks WebSocket, so there is no safe
        // eviction candidate. The goodbye reaches the peer because its session is already upgraded,
        // provided the transport had a socket to accept it on (the NURSERY_CAPACITY + 2 budget).
        size_t inbound_count = 0;
        for (const auto& entry : this->nursery_) {
            if (entry.inbound) {
                ++inbound_count;
            }
        }
        if (inbound_count >= NURSERY_CAPACITY) {
            SS_LOGW(TAG, "Nursery full of live connections, rejecting new connection");
            // Never managed, but its callbacks are already wired: block dispatch so it cannot
            // inject messages during the goodbye window.
            conn->disable_message_dispatch();
            this->queue_deferred_release(std::move(conn), SendspinGoodbyeReason::ANOTHER_SERVER);
        } else {
            SS_LOGD(TAG, "Admitting new connection into the nursery");
            // The connection arrives WS-upgraded, so client/init can be sent right away (there
            // is no earlier signal to wait for). The hello is armed later, once the Noise
            // handshake completes (see the noise-completion scan in scan_hello_and_nursery()).
            conn->init_noise_handshake(*this->client_->identity_, *this->client_->record_store_,
                                       suite_name_for(this->client_->config_.cipher_suite));
            conn->send_noise_client_init();
            this->push_nursery_entry(NurseryEntry{std::move(conn), /*inbound=*/true});
        }
    }
    this->flush_deferred_releases();
}

// ============================================================================
// Hello handshake
// ============================================================================

void ConnectionManager::initiate_hello(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    // Arm a per-connection hello retry: send on the next tick, 3 attempts. If an entry for this
    // connection already exists (a duplicate connected event for the same connection would land
    // here twice), re-arm it in place instead of pushing a second one, so a connection never gets
    // two timers.
    auto conn_sp = conn->shared_from_this();
    const int64_t retry_time_us = platform_time_us();

    for (auto& retry : this->hello_retries_) {
        if (retry.conn == conn_sp) {
            retry.delay_ms = HelloRetryState::INITIAL_RETRY_DELAY_MS;
            retry.attempts = 3;
            retry.retry_time_us = retry_time_us;
            return;
        }
    }

    HelloRetryState retry;
    retry.conn = std::move(conn_sp);
    retry.delay_ms = HelloRetryState::INITIAL_RETRY_DELAY_MS;
    retry.attempts = 3;
    retry.retry_time_us = retry_time_us;
    this->hello_retries_.push_back(std::move(retry));
    this->hello_retries_size_.store(this->hello_retries_.size(), std::memory_order_release);
}

void ConnectionManager::remove_hello_retry(const SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    // Safe to call unconditionally: a no-op if conn never had a retry entry (e.g. a connection
    // rejected before initiate_hello, or one whose hello already sent and cleared its entry).
    for (auto it = this->hello_retries_.begin(); it != this->hello_retries_.end();) {
        if (it->conn.get() == conn) {
            it = this->hello_retries_.erase(it);
        } else {
            ++it;
        }
    }
    this->hello_retries_size_.store(this->hello_retries_.size(), std::memory_order_release);
}

bool ConnectionManager::has_hello_retry(const SendspinConnection* conn) const {
    // Note: caller must hold conn_ptr_mutex_
    for (const auto& retry : this->hello_retries_) {
        if (retry.conn.get() == conn) {
            return true;
        }
    }
    return false;
}

bool ConnectionManager::send_hello_message(uint8_t remaining_attempts, SendspinConnection* conn) {
    // Verify the connection is still managed: hellos are normally sent to nursery members, plus
    // the current connection while it re-proves itself after an in-band re-handshake (see
    // schedule_rehandshake_rearm()). Anything else (already released by an earlier event this
    // tick) is stale.
    if (this->find_in_nursery(conn) == this->nursery_.end() &&
        conn != this->current_connection_.get()) {
        SS_LOGW(TAG, "Connection no longer valid for hello message");
        return true;
    }

    if (conn == nullptr || !conn->is_connected()) {
        SS_LOGW(TAG, "Cannot send hello - not connected");
        return true;
    }

    std::string hello_message = this->client_->build_hello_message(conn);

    // send_app_json (not send_text_message): client/hello is encrypted like every other
    // post-handshake message. The hello is only ever armed once the Noise handshake completes,
    // so the transport send_app_json routes to is always active here.
    SsErr err = conn->send_app_json(
        hello_message,
        [conn](bool success) {
            // Runs on the transport's send-completion context (httpd worker on ESP, inline on
            // host); conn is kept alive for the duration by the transport (see AsyncRespArg).
            // Setting the flag is all that is needed: establishment is level-triggered, so
            // drain_lifecycle_events()'s promotion scan observes is_handshake_complete() on its
            // next tick even when the peer's server/hello raced ahead of this send.
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

std::vector<NurseryEntry>::iterator ConnectionManager::find_in_nursery(
    const SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    for (auto it = this->nursery_.begin(); it != this->nursery_.end(); ++it) {
        if (it->conn.get() == conn) {
            return it;
        }
    }
    return this->nursery_.end();
}

void ConnectionManager::push_nursery_entry(NurseryEntry entry) {
    // Note: caller must hold conn_ptr_mutex_
    this->nursery_.push_back(std::move(entry));
    this->nursery_size_.store(this->nursery_.size(), std::memory_order_release);
}

void ConnectionManager::set_current_connection(std::shared_ptr<SendspinConnection> conn) {
    // Note: caller must hold conn_ptr_mutex_
    // The admitted flag tracks this slot exactly: it is what the network-thread dispatch gate
    // reads to decide whether a connection may drive the roles (see SendspinConnection::
    // is_admitted()). Clear the outgoing occupant before marking the incoming one so a handoff
    // never leaves two connections flagged as admitted, and skip the clear when the same
    // connection is being re-set.
    //
    // This only covers an occupant still sitting in the slot. drop_connection() moves the
    // outgoing connection out BEFORE calling here, so it clears the flag itself; keep the two
    // in step if either changes.
    if (this->current_connection_ != nullptr && this->current_connection_ != conn) {
        this->current_connection_->set_admitted(false);
    }
    if (conn != nullptr) {
        conn->set_admitted(true);
    }
    this->has_current_.store(conn != nullptr, std::memory_order_release);
    this->current_connection_ = std::move(conn);
}

void ConnectionManager::queue_pending_connected(std::shared_ptr<SendspinConnection> conn) {
    // Note: caller must hold conn_mutex_
    this->pending_connected_events_.push_back(std::move(conn));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_disconnect(std::shared_ptr<SendspinConnection> conn) {
    // Note: caller must hold conn_mutex_
    this->pending_disconnect_events_.push_back(std::move(conn));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_activate(ServerActivateEvent event) {
    // Note: caller must hold conn_mutex_
    this->pending_activate_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_rehandshake(std::shared_ptr<SendspinConnection> conn) {
    // Note: caller must hold conn_mutex_
    this->pending_rehandshake_events_.push_back(std::move(conn));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_pair_abort(PairAbortEvent event) {
    // Note: caller must hold conn_mutex_
    this->pending_pair_abort_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_management_request(ManagementRequestEvent&& event) {
    // Note: caller must hold conn_mutex_
    this->pending_management_request_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_server_unpair(ServerUnpairEvent&& event) {
    // Note: caller must hold conn_mutex_
    this->pending_server_unpair_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_pin_pairing_message(ServerPairingMessageEvent&& event) {
    // Note: caller must hold conn_mutex_
    this->pending_pin_pairing_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_pairing_succeeded(std::string server_id) {
    // Note: caller must hold conn_mutex_
    this->pending_pairing_succeeded_events_.push_back(std::move(server_id));
    this->has_pending_events_.store(true, std::memory_order_release);
}

void ConnectionManager::queue_pending_pair_storage_failed(PairStorageFailedEvent event) {
    // Note: caller must hold conn_mutex_
    this->pending_pair_storage_failed_events_.push_back(std::move(event));
    this->has_pending_events_.store(true, std::memory_order_release);
}

std::vector<NurseryEntry>::iterator ConnectionManager::release_nursery_entry(
    std::vector<NurseryEntry>::iterator it, std::optional<SendspinGoodbyeReason> reason) {
    // Note: caller must hold conn_ptr_mutex_ and flush_deferred_releases() after dropping it
    auto conn = std::move(it->conn);
    auto next = this->nursery_.erase(it);
    this->nursery_size_.store(this->nursery_.size(), std::memory_order_release);
    // Leaving management: block stale network-thread dispatch into role/state queues during the
    // goodbye window. Outgoing sends, including the goodbye itself, are unaffected.
    conn->disable_message_dispatch();
    this->remove_hello_retry(conn.get());
    this->queue_deferred_release(std::move(conn), reason);
    return next;
}

void ConnectionManager::drop_connections_using_psk_id(const std::string& psk_id,
                                                      const SendspinConnection* except) {
    // Note: caller must hold conn_ptr_mutex_ and flush_deferred_releases() after dropping it
    if (psk_id.empty()) {
        return;
    }

    // Collect first, then drop: drop_connection() mutates both the current slot and nursery_,
    // so dropping while walking the nursery would invalidate the iterator underneath us.
    //
    // get_psk_id() locks: a nursery member can be completing its Noise handshake on its own
    // network thread right now, and that write rewrites the very string being compared here.
    std::vector<std::shared_ptr<SendspinConnection>> doomed;
    if (this->current_connection_ != nullptr && this->current_connection_.get() != except &&
        this->current_connection_->get_psk_id() == psk_id) {
        doomed.push_back(this->current_connection_);
    }
    for (const auto& entry : this->nursery_) {
        if (entry.conn != nullptr && entry.conn.get() != except &&
            entry.conn->get_psk_id() == psk_id) {
            doomed.push_back(entry.conn);
        }
    }

    for (const auto& conn : doomed) {
        SS_LOGI(TAG, "Record %s revoked; dropping its live session (server_id=%s)", psk_id.c_str(),
                conn->get_server_id().c_str());
        this->drop_connection(conn.get(), SendspinGoodbyeReason::UNAUTHORIZED);
    }
}

void ConnectionManager::queue_deferred_release(std::shared_ptr<SendspinConnection> conn,
                                               std::optional<SendspinGoodbyeReason> reason) {
    // Note: caller must hold conn_ptr_mutex_ and call flush_deferred_releases() after dropping it
    this->deferred_releases_.push_back({std::move(conn), reason});
    this->deferred_size_.store(this->deferred_releases_.size(), std::memory_order_release);
}

void ConnectionManager::flush_deferred_releases() {
    // Note: caller must NOT hold conn_ptr_mutex_ (see DeferredRelease)
    //
    // Lock-free early return: deferred_size_ mirrors deferred_releases_.size() and is refreshed
    // only under conn_ptr_mutex_, at every push (queue_deferred_release()) and at the drain swap
    // below, so observing 0 here means the container was empty as of that acquire-load. This is
    // sound because every push site is followed by a call to this function on the SAME thread
    // before the pushing function returns to its caller: loop()'s lifecycle block (Block 2) is
    // followed by the Block-3 call below it in loop() itself; connect_to() and disconnect() each
    // call this function right after their locked section; on_new_connection() calls it right
    // after its locked section too (on the network/httpd thread, not the main loop thread; the
    // "same thread" guarantee is about the call stack that did the push, not about which thread
    // that happens to be). So a push is normally drained by its own triggering call before that
    // call returns. If a concurrently racing flush call (a different thread, or loop()'s other
    // backstop call within the same tick) wins the lock first and drains it, that is equally
    // fine: a queued release is performed exactly once by whichever call actually swaps it out,
    // and the pushing call's own subsequent gate check then correctly observes 0 and skips a
    // lock it no longer needs. loop() also calls this function unconditionally twice per tick
    // (after the lifecycle block and after the nursery reap), so nothing pushed stays queued
    // past the next tick.
    if (this->deferred_size_.load(std::memory_order_acquire) == 0) {
        return;
    }
    std::vector<DeferredRelease> releases;
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        releases.swap(this->deferred_releases_);
        this->deferred_size_.store(this->deferred_releases_.size(), std::memory_order_release);
    }
    for (auto& release : releases) {
        if (release.goodbye.has_value()) {
            this->disconnect_and_release(std::move(release.conn), release.goodbye.value());
        }
        // Without a goodbye the shared_ptr simply drops (below, when `releases` goes out of
        // scope): even bare destruction happens outside the lock, because a connection
        // destructor can join its transport thread.
    }
}

void ConnectionManager::on_connection_lost(SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_ (reads the slots and calls drop_connection)
    if (conn == nullptr) {
        return;
    }

    if (conn == this->current_connection_.get()) {
        SS_LOGI(TAG, "Current connection lost");
    } else if (this->find_in_nursery(conn) != this->nursery_.end()) {
        SS_LOGD(TAG, "Nursery connection lost");
    }

    // The transport is already gone, so no goodbye is attempted (nullopt).
    this->drop_connection(conn, std::nullopt);
}

void ConnectionManager::drop_connection(SendspinConnection* conn,
                                        std::optional<SendspinGoodbyeReason> goodbye) {
    // Note: caller must hold conn_ptr_mutex_
    if (conn == nullptr) {
        return;
    }

    this->remove_hello_retry(conn);

    if (conn == this->current_connection_.get()) {
        // Dropping the admitted connection: block stale network-thread events and quiesce the
        // client's per-connection state (including the time burst). The slot stays empty; the next
        // nursery establishment promotes into it. The goodbye send and the release itself are
        // deferred (see DeferredRelease).
        //
        // If a PIN pairing was mid-flight, its display / pairing-window prompt must be dismissed.
        // Capture the flags before cleanup_connection_state() clears the pending notification
        // state in EventState, then queue the note_* calls after cleanup so they survive to be
        // dispatched from SendspinClient::loop() (same ordering rule as the abort handlers).
        const bool pin_was_displayed = conn->pin_session().pin_displayed;
        const bool window_was_shown = conn->pin_session().window_shown;
        conn->disable_message_dispatch();
        // Vacate the admitted slot explicitly. set_current_connection(nullptr) below cannot do
        // it: the outgoing connection is moved out of current_connection_ first, so the setter
        // sees an already-null slot and has nothing to clear. The connection outlives this call
        // (queue_deferred_release keeps it alive through the goodbye window), so leaving the flag
        // set would leave a dropped connection claiming admission.
        conn->set_admitted(false);
        this->client_->cleanup_connection_state();
        // set_current_connection(nullptr) reassigns the slot to a clean null (not a moved-from
        // state) after we move the old connection out, so a later event in the same loop() pass
        // that reads current_connection_ never trips the static analyzer.
        auto dropped = std::move(this->current_connection_);
        this->set_current_connection(nullptr);
        this->queue_deferred_release(std::move(dropped), goodbye);
        this->dismiss_pairing_ui(pin_was_displayed, window_was_shown);
        return;
    }

    if (auto it = this->find_in_nursery(conn); it != this->nursery_.end()) {
        // Dropping an unproven connection: no client-state cleanup (it was never admitted). PIN
        // sessions only ever exist on the current connection (see the pairing-events comment
        // above, in loop()), but dismiss any prompt defensively for symmetry with the other
        // drop paths in case that invariant is ever relaxed.
        const bool pin_was_displayed = conn->pin_session().pin_displayed;
        const bool window_was_shown = conn->pin_session().window_shown;
        this->release_nursery_entry(it, goodbye);
        this->dismiss_pairing_ui(pin_was_displayed, window_was_shown);
    }
    // Not a managed connection: nothing to do (already released by an earlier event this tick).
}

bool ConnectionManager::should_switch_to_new_server(const SendspinConnection* current,
                                                    const SendspinConnection* new_conn) const {
    // Ports admission.h::should_admit_connection (activity-priority arbitration). `current` may
    // be null (nothing admitted yet); the pure function's has_admitted=false path always admits.
    const bool has_current = current != nullptr;
    // An incumbent whose pair-finalize has already been acked still reports the pre-finalize
    // [PAIRING] activities (only apply_server_activate rewrites them, and the post-rekey activate
    // has not arrived), so admission.h rule 2 ("an in-flight pairing is NOT displaced") would
    // keep shielding a pairing that already completed. Tell the rule the pairing is no longer in
    // flight instead of rewriting the activities: the rank comparisons must keep seeing rank 1,
    // because dropping the incumbent to rank 0 would expose it to rule 5's last_playback
    // tiebreak. A rank-0 newcomer must never be able to evict a just-paired connection
    // mid-rekey.
    const bool pairing_in_flight = !has_current || !current->is_pairing_finalized();
    return should_admit_connection(
        /*incoming_activities=*/new_conn->get_activities(),
        /*incoming_server_id=*/new_conn->get_server_id(),
        /*admitted_activities=*/
        has_current ? current->get_activities() : std::vector<SendspinActivity>{},
        /*admitted_server_id=*/has_current ? current->get_server_id() : std::string{},
        /*has_admitted=*/has_current,
        /*last_playback_server_id=*/this->last_played_server_id_,
        /*has_last_playback=*/this->has_last_played_server_,
        /*admitted_pairing_in_flight=*/pairing_in_flight);
}

void ConnectionManager::note_playback_activity(const SendspinConnection* conn) {
    // Note: caller must hold conn_ptr_mutex_
    // Mirrors note_playback_activity in aiosendspin/client/client.py: only the ADMITTED
    // (current) connection updates last_played_server_id, and only when it carries PLAYBACK.
    if (conn == nullptr || conn != this->current_connection_.get()) {
        return;
    }
    if (!conn->has_activity(SendspinActivity::PLAYBACK)) {
        return;
    }
    const std::string& server_id = conn->get_server_id();
    if (server_id.empty()) {
        return;
    }
    // Delegate to SendspinClient::persist_last_played_server, which also updates this
    // manager's last_played_server_id_ and persists via the provider.
    this->client_->persist_last_played_server(server_id);
    SS_LOGD(TAG, "note_playback_activity: last_played_server_id updated to %s", server_id.c_str());
}

std::vector<NurseryEntry>::iterator ConnectionManager::promote_or_arbitrate_nursery_entry(
    std::vector<NurseryEntry>::iterator it) {
    // Note: caller must hold conn_ptr_mutex_
    auto conn = std::move(it->conn);
    auto next = this->nursery_.erase(it);
    this->nursery_size_.store(this->nursery_.size(), std::memory_order_release);
    this->remove_hello_retry(conn.get());

    if (this->current_connection_ == nullptr) {
        this->set_current_connection(std::move(conn));
    } else if (this->should_switch_to_new_server(this->current_connection_.get(), conn.get())) {
        // Both sides of the comparison are operational (hello + first activate applied), so
        // arbitration always runs on real activity data. No incumbent is ever evicted on timing
        // alone.
        SS_LOGI(TAG, "Admission arbitration: switch to new server");
        this->drop_connection(this->current_connection_.get(),
                              SendspinGoodbyeReason::ANOTHER_SERVER);
        this->set_current_connection(std::move(conn));
    } else {
        SS_LOGI(TAG, "Admission arbitration: reject incoming (keep current)");
        // Pairing connections receive pair/abort first (the reference dismissal for a displaced
        // pairing attempt); the subsequent goodbye from queue_deferred_release is a benign
        // over-send (no close-without-goodbye path exists in the current transport layer).
        if (conn->has_activity(SendspinActivity::PAIRING)) {
            conn->send_app_json(format_pair_abort_message(PairAbortReason::CONCURRENT_ATTEMPT),
                                nullptr);
        }
        // Leaving management: block stale network-thread dispatch during the goodbye window
        // (outgoing sends, including the goodbye itself, are unaffected).
        conn->disable_message_dispatch();
        this->queue_deferred_release(std::move(conn), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
        return next;
    }

    // Notify the client, publish state, and record playback activity, only for the winner.
    this->note_playback_activity(this->current_connection_.get());

    // ==== Pairing branch ====
    // If the winning activate declares only the PAIRING activity with a supported
    // pairing.method, enter the pairing flow instead of the normal operational path. The
    // connection still occupies current_connection_ (so admission.h's "in-flight pairing is not
    // displaced" rule applies), but is not announced to the client as operational until pairing
    // finishes and the post-finalize re-handshake completes.
    const auto& activities = this->current_connection_->get_activities();
    const auto& pairing_method = this->current_connection_->get_pairing_method();
    const bool is_pairing_activity_only = activities.size() == 1 &&
                                          activities[0] == SendspinActivity::PAIRING &&
                                          pairing_method.has_value();

    if (is_pairing_activity_only) {
        SS_LOGI(TAG, "Pairing activate received (%s): entering pairing for server_id=%s",
                to_cstr(pairing_method.value()),
                this->current_connection_->get_server_id().c_str());
        this->handle_enter_pairing(this->current_connection_.get());
    } else {
        this->client_->on_handshake_complete(this->current_connection_.get());
    }

    SS_LOGI(TAG, "Connection admitted: server_id=%s",
            this->current_connection_->get_server_id().c_str());
    return next;
}

void ConnectionManager::disconnect_and_release(std::shared_ptr<SendspinConnection>&& conn,
                                               SendspinGoodbyeReason reason) {
    // Take ownership of the caller's shared_ptr into a local, send the goodbye, then let the
    // local go out of scope. On ESP the httpd session slot keeps the conn alive until the
    // goodbye worker runs, calls trigger_close, the session tears down, and the slot's free_fn
    // fires. On host the IXWebSocket send is synchronous, so the goodbye + close have both
    // completed by the time disconnect() returns.
    auto local = std::move(conn);
    local->disconnect(reason, nullptr);
}

// ============================================================================
// Pairing main-loop handlers
// ============================================================================

void ConnectionManager::handle_enter_pairing(SendspinConnection* conn) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). conn is the connection that just won
    // promotion into current_connection_ with a pairing activate (see
    // promote_or_arbitrate_nursery_entry).
    if (conn == nullptr || this->client_->record_store_ == nullptr) {
        SS_LOGE(TAG, "handle_enter_pairing: no connection or record_store");
        return;
    }

    // Quiesce: suppress time sync and client/state while pairing is in progress.
    conn->set_pairing_in_progress(true);

    // The pairing server/activate counter (spec "Pairing index") was already bumped by the caller
    // at the point this activate was received (see the activate-events loop in
    // drain_lifecycle_events(): every pairing server/activate counts there, whether or not it turns
    // out to be admissible, so a method_not_supported rejection does not desync the count from the
    // server's). Do NOT bump
    // again here: this handler can also be reached well after reception (the "subsequent activate
    // transitions into pairing" branch applies the activate first, then calls this), so bumping
    // here would double-count or use a stale value. The current value is captured into the PIN
    // session below for the PIN-method branches (sent as pairing_index and reused for the CPace
    // sid).
    const uint32_t pairing_index = conn->get_pairing_index();

    const std::string& server_id = conn->get_server_id();
    const auto& selected_method = conn->get_pairing_method();

    // ==== PIN branches (dynamic and static) ====
    if (selected_method.has_value() &&
        (selected_method.value() == SendspinPairMethod::DYNAMIC_PIN ||
         selected_method.value() == SendspinPairMethod::STATIC_PIN)) {
        const bool is_dynamic = selected_method.value() == SendspinPairMethod::DYNAMIC_PIN;
        const RecordStore& store = *this->client_->record_store_;

        // Defensive: the client should not have advertised static_pin without a configured PIN.
        if (!is_dynamic && !store.static_pin().has_value()) {
            SS_LOGE(TAG, "handle_enter_pairing: no static PIN configured for server_id=%s",
                    server_id.c_str());
            this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            return;
        }

        // Capture the Noise handshake hash now (main loop, before any further I/O). The
        // NoiseTransport session is network-thread-owned, but we are on the main loop and the
        // session was set before the first server/activate fired; no concurrent write
        // is possible at this point (no re-handshake is in progress). If the hash is
        // unavailable the PAKE SID and PIN derivation cannot be computed, so abort.
        auto hash_opt = conn->get_noise_handshake_hash();
        if (!hash_opt.has_value()) {
            SS_LOGE(TAG, "handle_enter_pairing: no handshake hash for server_id=%s; aborting",
                    server_id.c_str());
            this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
            return;
        }

        auto& ps = conn->pin_session();
        ps.method = selected_method.value();
        ps.handshake_hash = hash_opt.value();
        ps.pairing_index = pairing_index;
        if (is_dynamic) {
            // Validated against [min_pin_length, 12] when the activation was admitted.
            ps.pin_length = conn->get_pairing_pin_length().value_or(0);
        } else {
            // Capture the static PIN now, before any operator window wait, so a concurrent
            // management PIN change during the open window cannot swap the CPace secret
            // mid-attempt. Mirrors the reference capturing static_pin before awaiting
            // pairing_window().
            ps.static_pin_value = store.static_pin().value();
        }

        // Gesture gating (spec: Pairing Window). static_pin: every attempt. dynamic_pin: only
        // when the method is escalated by its failure counter, or the session PIN is short.
        const bool gesture_gated = !is_dynamic || store.dynamic_pin_escalated() ||
                                   ps.pin_length < PIN_GESTURE_GATE_MIN_LENGTH;

        if (gesture_gated && !this->pairing_window_open()) {
            // No window open: report the pending gesture with client/pair-pending and wait.
            // pair-pending does not start the attempt or its timeout (the server applies its
            // own timeout and cancels via server/activate), so no attempt deadline is armed
            // here (attempt_deadline_us == 0 disables the loop() timeout check).
            ps.step = SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW;
            ps.attempt_deadline_us = 0;
            SS_LOGI(TAG,
                    "Sending client/pair-pending (%s, gesture-gated, no window open) for "
                    "server_id=%s",
                    to_cstr(ps.method), server_id.c_str());
            conn->send_app_json(format_client_pair_pending_message(ps.pairing_index), nullptr);

            // Surface the pairing-window prompt to the operator, but only when the platform
            // actually implements the gesture UI (on_open_pairing_window's contract is that it
            // fires only when pairing_window_supported is true). A gated dynamic_pin attempt can
            // still reach this branch on a device without that UI (escalation and the short-PIN
            // gate apply to dynamic_pin regardless of the flag); the attempt then waits for a
            // window opened remotely via management/open-pairing-window, or for the server's own
            // timeout to cancel it. Log loudly so the stall is diagnosable.
            if (this->client_->config_.pairing_window_supported) {
                this->client_->note_open_pairing_window();
                ps.window_shown = true;
            } else {
                SS_LOGW(TAG,
                        "Gesture-gated %s attempt for server_id=%s but "
                        "pairing_window_supported=false: no operator prompt can be shown; "
                        "waiting for management/open-pairing-window or server cancel",
                        to_cstr(ps.method), server_id.c_str());
            }

            this->client_->note_pairing_started(server_id);
            return;
        }

        // Not gated, or a standing window is already open: start the attempt immediately
        // (start_pin_attempt consumes the window; its lifetime runs until pair-init is sent).
        this->start_pin_attempt(conn);
        this->client_->note_pairing_started(server_id);
        return;
    }

    // ==== Pairing-PSK branch ====

    // resolve_pairing_outcome generates the long-term PSK and, if storage is available,
    // a paired record. Three outcomes:
    //   {psk, record=set}     -> normal: send finalize, hold record, store on ack.
    //   {psk, record=nullopt} -> storage exhausted: send finalize with shared PSK, store nothing.
    //   outer nullopt          -> error (no shared fallback): abort.
    auto outcome = this->client_->record_store_->resolve_pairing_outcome(server_id);
    if (!outcome.has_value()) {
        SS_LOGE(TAG,
                "handle_enter_pairing: resolve_pairing_outcome failed for server_id=%s; "
                "aborting pairing",
                server_id.c_str());
        // Send pair/abort(method_not_supported): closest reason for "cannot proceed".
        // method_not_supported is used as the error path here because there is no distinct
        // "store unavailable" reason in the protocol.
        conn->send_app_json(format_pair_abort_message(PairAbortReason::METHOD_NOT_SUPPORTED),
                            nullptr);
        conn->clear_pairing_state();
        // Close the connection: pairing cannot proceed. drop_connection() handles both the
        // current-slot cleanup (cleanup_connection_state, which also resets the time burst) and
        // the deferred goodbye+release; flush_deferred_releases() runs at the end of the caller's
        // locked block.
        this->drop_connection(conn, SendspinGoodbyeReason::UNAUTHORIZED);
        return;
    }

    // Send client/pair-finalize with the long-term PSK (base64url-encoded, 43 chars).
    SS_LOGI(TAG, "Sending client/pair-finalize for server_id=%s (record=%s)", server_id.c_str(),
            outcome->record.has_value() ? "stored" : "shared-psk-fallback");
    conn->send_app_json(format_client_pair_finalize_message(outcome->psk), nullptr);

    // Hold the pending record: committed to the RecordStore by the network-thread
    // server/pair-finalize handler on ack. nullopt record = storage-exhausted case: store nothing.
    conn->set_pending_pairing_record(std::move(outcome->record));
}

void ConnectionManager::handle_pair_abort(SendspinConnection* conn, PairAbortReason reason) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). pair/abort received from the server
    // during pairing.
    if (conn == nullptr) {
        return;
    }

    // A pair/abort that arrives after the receiver (us) has already ended the attempt (locally
    // aborted, or the server itself left pairing via a leftover server/activate) has no effect
    // (spec "pair/abort": "A pair/abort received after the receiver has itself ended the attempt
    // has no effect"). is_pairing_in_progress() is cleared by clear_pairing_state() on every path
    // that ends an attempt, so it is the right proxy for "already ended" here.
    if (!conn->is_pairing_in_progress()) {
        SS_LOGI(TAG,
                "pair/abort (reason=%s) received for server_id=%s after the attempt already "
                "ended; ignoring (stale)",
                to_cstr(reason), conn->get_server_id().c_str());
        return;
    }

    SS_LOGW(TAG, "pair/abort received for server_id=%s reason=%s", conn->get_server_id().c_str(),
            to_cstr(reason));

    // Clean up pairing state. Per spec "pair/abort", the sender of pair/abort closes the connection
    // only for reason concurrent_attempt; every other reason leaves the connection open so the
    // server can re-activate pairing (or resume normal operation) on the same connection. We
    // mirror that here: only concurrent_attempt drops the connection on our side too (the server,
    // as sender, is closing its side regardless; closing here just avoids waiting on the TCP
    // teardown). No wire pair/abort is sent: this one already arrived from the server.
    this->abort_pairing_attempt(conn, /*wire_abort_reason=*/std::nullopt,
                                /*should_drop=*/reason == PairAbortReason::CONCURRENT_ATTEMPT,
                                SendspinGoodbyeReason::CONCURRENT_ATTEMPT,
                                to_public_abort_reason(reason));
}

void ConnectionManager::handle_pair_storage_failed(const PairStorageFailedEvent& event) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). The persistence provider rejected
    // the long-term record when server/pair-finalize was acked on the network thread
    // (RecordStore::store_record fails closed, see SendspinClient::process_json_message), so the
    // record was never stored and this pairing cannot survive a reboot. The server has already
    // persisted its side (server/pair-finalize acks its own store), so it is left holding a
    // record this client never had; aborting loudly here makes that visible immediately rather
    // than at the next reconnect. Note: the server's follow-up re-handshake msg1 may race this
    // event and fail on the unresolvable psk_id first. Both paths drop the connection, and the
    // listener notification below does not depend on the connection still being managed.
    if (event.conn && event.conn.get() == this->current_connection_.get()) {
        SS_LOGE(TAG, "Pairing record persist failed for server_id=%s; aborting pairing",
                event.server_id.c_str());
        // Best-effort pair/abort. The wire enum has no storage-failure value (candidate spec
        // addition); user_cancelled is the closest fit: the application cancelled the exchange.
        // Per spec "pair/abort", a pair/abort sender only closes the connection for reason
        // concurrent_attempt, but this is not an ordinary protocol-level pairing abort: the
        // server has already persisted its side (it acked server/pair-finalize) and is about to
        // re-handshake to a PSK this client never stored, which is guaranteed to fail anyway. We
        // close proactively here (an independent local decision, not the wire pair/abort
        // semantics) so the client gets a clean reconnect instead of a doomed re-handshake.
        //
        // server_id_override=event.server_id (not conn->get_server_id()): matches the
        // production-time server_id used below on the no-match path, so the listener sees the
        // same value regardless of which branch handled the event.
        this->abort_pairing_attempt(event.conn.get(), PairAbortReason::USER_CANCELLED,
                                    /*should_drop=*/true, SendspinGoodbyeReason::UNAUTHORIZED,
                                    SendspinPairAbortReason::STORAGE_FAILED, event.server_id);
        return;
    }

    // conn is no longer managed (e.g. already dropped by a race with the re-handshake failure
    // path noted above): nothing to clean up on it, but the listener still needs to hear about
    // the failure. Uses the production-time server_id, since there is no connection to read it
    // from here.
    this->client_->note_pairing_failed(event.server_id, SendspinPairAbortReason::STORAGE_FAILED);
}

/// @brief Fires on_clear_pairing_pin and/or on_open_pairing_window's counterpart for a pairing UI
/// element that was left showing. Caller must hold conn_ptr_mutex_.
void ConnectionManager::dismiss_pairing_ui(bool pin_was_displayed, bool window_was_shown) {
    if (pin_was_displayed) {
        this->client_->note_clear_pin();
    }
    if (window_was_shown) {
        this->client_->note_close_pairing_window();
    }
}

void ConnectionManager::abort_pairing_attempt(
    SendspinConnection* conn, std::optional<PairAbortReason> wire_abort_reason, bool should_drop,
    std::optional<SendspinGoodbyeReason> drop_goodbye_reason, SendspinPairAbortReason public_reason,
    std::optional<std::string> server_id_override) {
    // Runs on the main loop (caller holds conn_ptr_mutex_).
    //
    // Capture the deferred-notification inputs BEFORE clear_pairing_state() resets the PIN
    // session and before the connection is possibly released (server_id is copied so it survives
    // any tear-down). server_id_override lets a caller substitute a value captured earlier
    // (see handle_pair_storage_failed()) instead of reading the connection's current state.
    const std::string server_id =
        server_id_override.has_value() ? server_id_override.value() : conn->get_server_id();
    const bool pin_was_displayed = conn->pin_session().pin_displayed;
    const bool window_was_shown = conn->pin_session().window_shown;

    if (wire_abort_reason.has_value()) {
        conn->send_app_json(format_pair_abort_message(wire_abort_reason.value()), nullptr);
    }

    // On the current-slot path drop_connection() -> cleanup_connection_state() clears the
    // pending notification vectors, so the note_* calls below MUST come after it.
    conn->clear_pairing_state();
    if (should_drop) {
        this->drop_connection(conn, drop_goodbye_reason);
    }

    // Queue listener notifications AFTER any drop_connection() so they survive to be dispatched
    // from SendspinClient::loop() after conn_ptr_mutex_ is released. Only the queue push happens
    // while the lock is held.
    this->client_->note_pairing_failed(server_id, public_reason);
    this->dismiss_pairing_ui(pin_was_displayed, window_was_shown);
}

// ============================================================================
// Dynamic-PIN pairing main-loop handlers
// ============================================================================

void ConnectionManager::local_abort_pin_pairing(SendspinConnection* conn, PairAbortReason reason) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). Aborts the PIN-pairing session
    // locally:
    //   1. Send pair/abort to the server.
    //   2. Clear PIN display / pairing state on the connection.
    //   3. Close the connection, but ONLY for reason concurrent_attempt (spec "pair/abort": every
    //      other reason (attempt_timeout, method_not_supported, pin_length_unacceptable,
    //      pin_mismatch, user_cancelled) leaves the connection open).
    //   4. Queue on_pairing_failed (and on_clear_pairing_pin, if a PIN was shown) for delivery
    //      from loop().
    if (conn == nullptr) {
        return;
    }

    SS_LOGW(TAG, "local_abort_pin_pairing: server_id=%s reason=%s", conn->get_server_id().c_str(),
            to_cstr(reason));

    // Best-effort pair/abort to the server (the connection is still live here).
    this->abort_pairing_attempt(conn, reason,
                                /*should_drop=*/reason == PairAbortReason::CONCURRENT_ATTEMPT,
                                SendspinGoodbyeReason::CONCURRENT_ATTEMPT,
                                to_public_abort_reason(reason));
}

// ============================================================================
// Pairing-window main-loop handlers
// ============================================================================

void ConnectionManager::start_pin_attempt(SendspinConnection* conn) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). The PinSession was populated by
    // handle_enter_pairing; this sends the client/pair-init that starts the attempt. Sending
    // pair-init ends the pairing window's lifetime (spec: Pairing Window), so any standing
    // window is consumed here whether the attempt was gated or not.
    this->pairing_window_open_until_us_ = 0;

    auto& ps = conn->pin_session();
    const std::string& server_id = conn->get_server_id();

    if (ps.method == SendspinPairMethod::DYNAMIC_PIN) {
        // Generate nonce_B and its commitment, then send client/pair-init with commit_B and
        // the required pairing_index (spec "PAKE").
        ps.nonce_b = pin_generate_nonce();
        auto commit_b = pin_commit(ps.nonce_b.data(), ps.nonce_b.size());

        SS_LOGI(TAG, "Sending client/pair-init (dynamic_pin) for server_id=%s", server_id.c_str());
        conn->send_app_json(format_client_pair_init_message(commit_b, ps.pairing_index), nullptr);

        ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_INIT;
        ps.attempt_deadline_us = platform_time_us() + PIN_ATTEMPT_TIMEOUT_US;
        return;
    }

    // Static PIN. Use the PIN captured at pairing start (see handle_enter_pairing), not a fresh
    // store read, so a mid-window PIN change cannot swap the CPace secret. Empty means it was
    // never captured (defensive; the enter-pairing path always captures a configured PIN).
    if (ps.static_pin_value.empty()) {
        SS_LOGE(TAG, "start_pin_attempt: no static PIN captured for server_id=%s",
                server_id.c_str());
        this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // Send client/pair-init with just pairing_index (static PIN carries no commit_B).
    // pairing_index is required on every client/pair-init per spec "Pairing index".
    SS_LOGI(TAG, "Sending client/pair-init (static_pin) for server_id=%s", server_id.c_str());
    conn->send_app_json(format_client_pair_init_message(ps.pairing_index), nullptr);

    // Build SID = LABEL || 32-byte handshake hash || 4-byte BE pairing_index counter (spec "PAKE"),
    // identical to the dynamic-PIN PAIR_INIT case in handle_pin_pairing_message. PRS = the
    // static PIN's ASCII bytes (mirrors run_static_pin_client in aiosendspin/noise/pairing.py).
    std::vector<uint8_t> sid = build_pake_sid(ps.handshake_hash, ps.pairing_index);

    const std::string& pin_str = ps.static_pin_value;
    std::vector<uint8_t> prs(pin_str.begin(), pin_str.end());

    // ADb = "client" (our own AD), ADa = "server" (peer's AD): spec "PAKE".
    if (!ps.cpace.start(CPaceRole::RESPONDER, prs, sid, {}, pake_ad_client(), pake_ad_server())) {
        SS_LOGE(TAG, "start_pin_attempt: CPace::start failed for server_id=%s", server_id.c_str());
        this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_AUTH;
    ps.attempt_deadline_us = platform_time_us() + PIN_ATTEMPT_TIMEOUT_US;
}

bool ConnectionManager::pairing_window_open() const {
    return this->pairing_window_open_until_us_ != 0 &&
           platform_time_us() < this->pairing_window_open_until_us_;
}

void ConnectionManager::open_pairing_window() {
    // Runs on the main loop (caller holds conn_ptr_mutex_). A PIN session only ever exists on
    // current_connection_: pairing only starts once a nursery entry has won promotion (see the
    // pairing branch in promote_or_arbitrate_nursery_entry()). If an attempt is already waiting
    // for the gesture, the freshly opened window is consumed by it immediately; otherwise the
    // window stands open (spec: Pairing Window) so a pairing activate arriving within its
    // lifetime can proceed without a further gesture.
    SendspinConnection* conn = this->current_connection_.get();
    const bool awaiting = conn != nullptr && conn->pin_session().step ==
                                                 SendspinConnection::PinStep::AWAIT_PAIRING_WINDOW;

    if (awaiting) {
        SS_LOGI(TAG, "Pairing window opened: starting the waiting %s attempt for server_id=%s",
                to_cstr(conn->pin_session().method), conn->get_server_id().c_str());
        this->start_pin_attempt(conn);
        return;
    }

    this->pairing_window_open_until_us_ = platform_time_us() + WINDOW_LIFETIME_US;
    SS_LOGI(TAG, "Pairing window opened: standing open for %lld s awaiting a pairing attempt",
            static_cast<long long>(WINDOW_LIFETIME_US / (1000LL * US_PER_MS)));
}

void ConnectionManager::handle_pairing_window_confirmed() {
    if (this->client_->record_store_ == nullptr) {
        return;
    }
    this->open_pairing_window();
}

void ConnectionManager::handle_pin_pairing_message(SendspinConnection* conn,
                                                   const ServerPairingMessageEvent& event) {
    // Runs on the main loop. All CPace / nonce / hash state is main-loop-only.
    if (conn == nullptr || this->client_->record_store_ == nullptr) {
        return;
    }

    // Spec "Entering and leaving pairing": "After the client has aborted an attempt, silently
    // discard pairing messages received before the next server/activate." is_pairing_in_progress()
    // is cleared by clear_pairing_state() on every path that ends an attempt (local abort, received
    // pair/abort, leftover activate), so a pairing message that races the abort and lands here
    // after the fact is discarded without re-aborting (which would otherwise fire on every stray,
    // now-stale message since ps.step is back to IDLE).
    if (!conn->is_pairing_in_progress()) {
        SS_LOGI(TAG,
                "handle_pin_pairing_message: discarding pairing message (kind=%d) for "
                "server_id=%s; no attempt in progress",
                static_cast<int>(event.kind), conn->get_server_id().c_str());
        return;
    }

    auto& ps = conn->pin_session();
    RecordStore& store = *this->client_->record_store_;
    const std::string& server_id = conn->get_server_id();

    switch (event.kind) {
        case PinPairingMessageKind::PAIR_INIT: {
            // Step 1: server/pair-init received. This is a DYNAMIC-PIN-only step; static PIN
            // never expects server/pair-init (see run_static_pin_client in the reference, which
            // goes straight from client/pair-init to server/pair-auth). A PAIR_INIT while
            // ps.method == STATIC_PIN is a protocol violation, handled by the same
            // wrong-step abort as an out-of-order message.
            if (ps.method != SendspinPairMethod::DYNAMIC_PIN ||
                ps.step != SendspinConnection::PinStep::AWAIT_SERVER_PAIR_INIT) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: PAIR_INIT in wrong step=%d method=%s for "
                        "server_id=%s",
                        static_cast<int>(ps.step), to_cstr(ps.method), server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
                return;
            }

            // Derive the PIN. The session pin_length arrived in the activation's pairing
            // object and was validated against [min_pin_length, 12] when the activation was
            // admitted (server/pair-init carries only nonce_A).
            auto pin_opt = pin_derive(ps.handshake_hash.data(), ps.handshake_hash.size(),
                                      event.nonce_a.data(), event.nonce_a.size(), ps.nonce_b.data(),
                                      ps.nonce_b.size(), ps.pin_length);
            if (!pin_opt.has_value()) {
                SS_LOGE(TAG, "handle_pin_pairing_message: pin_derive failed for server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            // Display the PIN to the user (deferred to loop() via note_display_pin). Record that
            // a PIN was displayed so the abort/cleanup paths know to clear it.
            this->client_->note_display_pin(pin_opt.value());
            ps.pin_displayed = true;

            // Start CPace RESPONDER.
            // PRS = PIN as UTF-8 bytes.
            // SID = LABEL || 32-byte handshake hash || 4-byte BE pairing_index counter (spec
            // "PAKE").
            std::vector<uint8_t> sid = build_pake_sid(ps.handshake_hash, ps.pairing_index);

            const std::string& pin_str = pin_opt.value();
            std::vector<uint8_t> prs(pin_str.begin(), pin_str.end());

            // ADb = "client" (our own AD), ADa = "server" (peer's AD): spec "PAKE".
            if (!ps.cpace.start(CPaceRole::RESPONDER, prs, sid, {}, pake_ad_client(),
                                pake_ad_server())) {
                SS_LOGE(TAG, "handle_pin_pairing_message: CPace::start failed for server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_AUTH;
            // No message sent yet: client waits for server/pair-auth.
            break;
        }

        case PinPairingMessageKind::PAIR_AUTH: {
            // Step 2: server/pair-auth received. Expect step AWAIT_SERVER_PAIR_AUTH.
            if (ps.step != SendspinConnection::PinStep::AWAIT_SERVER_PAIR_AUTH) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: PAIR_AUTH in wrong step=%d for server_id=%s",
                        static_cast<int>(ps.step), server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
                return;
            }

            // Send client/pair-auth (pake_msg_2 = client CPace share) BEFORE deriving.
            // This matches the reference: sends pake_msg_2 then calls _derive.
            const auto& client_share = ps.cpace.public_share();
            conn->send_app_json(format_client_pair_auth_message(client_share), nullptr);

            // Derive the MAC key from the server's share (pake_msg_1).
            // A derive failure means the peer share has the wrong length or encodes a
            // low-order point (a malformed or hostile share), NOT a wrong PIN: a wrong PIN
            // still produces a well-formed, non-low-order shared secret that only fails the
            // confirm-tag check below, so it does NOT count toward the lockout counter: the
            // reference records a failure only on the confirm-tag mismatch below.
            //
            // Spec Protocol Errors: "a CPace share with the wrong length or encoding a
            // low-order point" is a protocol error: the detecting side closes the WebSocket
            // without sending any application-level error message, and persists nothing. This
            // is the same class as the MALFORMED case below, so it follows the same shape: no
            // pair/abort, unconditional close, no failure-counter increment.
            if (!ps.cpace.derive(event.pake_msg_1.data(), event.pake_msg_1.size())) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: CPace::derive failed (malformed/low-order "
                        "peer share) for server_id=%s; closing per spec Protocol Errors (no "
                        "pair/abort sent)",
                        server_id.c_str());
                // clear_pairing_state() drops any pending pairing record, so nothing is
                // persisted; drop_connection() with goodbye=std::nullopt closes the transport
                // without sending a client/goodbye (or any other application-level message).
                // SendspinPairAbortReason has no dedicated "protocol error" value and none of
                // the wire-facing reasons fit (no pair/abort was received or sent); UNKNOWN is
                // reused here as the closest available local-only fit, matching the MALFORMED
                // case below.
                this->abort_pairing_attempt(conn, /*wire_abort_reason=*/std::nullopt,
                                            /*should_drop=*/true,
                                            /*drop_goodbye_reason=*/std::nullopt,
                                            SendspinPairAbortReason::UNKNOWN);
                return;
            }

            ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_CONFIRM;
            break;
        }

        case PinPairingMessageKind::PAIR_CONFIRM: {
            // Step 3: server/pair-confirm received. Expect step AWAIT_SERVER_PAIR_CONFIRM.
            if (ps.step != SendspinConnection::PinStep::AWAIT_SERVER_PAIR_CONFIRM) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: PAIR_CONFIRM in wrong step=%d for "
                        "server_id=%s",
                        static_cast<int>(ps.step), server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
                return;
            }

            // Verify server_kc (server confirmation tag). Only dynamic_pin carries a failure
            // counter (spec: Failure counter): the client's own verification of server_kc
            // failing is the ONE event that increments it, and it escalates the method to
            // gesture-gating at the threshold rather than locking it out.
            if (!ps.cpace.verify(event.server_kc.data(), event.server_kc.size())) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: server_kc verification failed "
                        "(PIN mismatch) for server_id=%s",
                        server_id.c_str());
                if (ps.method == SendspinPairMethod::DYNAMIC_PIN) {
                    store.record_dynamic_pin_failure();
                }
                this->local_abort_pin_pairing(conn, PairAbortReason::PIN_MISMATCH);
                return;
            }

            // server_kc verified: the dynamic-PIN failure counter resets (whether or not the
            // attempt goes on to finalize), de-escalating the method.
            if (ps.method == SendspinPairMethod::DYNAMIC_PIN) {
                store.reset_dynamic_pin_failures();
            }

            // Compute client_kc (our confirmation tag).
            auto client_kc_opt = ps.cpace.tag();
            if (!client_kc_opt.has_value()) {
                SS_LOGE(TAG, "handle_pin_pairing_message: CPace::tag() failed for server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            // Send client/pair-confirm: dynamic PIN carries client_kc + nonce_B, static PIN
            // carries client_kc only (no nonce opening; see run_static_pin_client vs
            // run_dynamic_pin_client in aiosendspin/noise/pairing.py).
            if (ps.method == SendspinPairMethod::STATIC_PIN) {
                conn->send_app_json(format_client_pair_confirm_message(client_kc_opt.value()),
                                    nullptr);
            } else {
                conn->send_app_json(
                    format_client_pair_confirm_message(client_kc_opt.value(), ps.nonce_b), nullptr);
            }

            // Clear PIN display and/or dismiss the pairing-window prompt now that the exchange
            // succeeded; each is a no-op unless this attempt actually showed it (see
            // pin_displayed / window_shown above). Reset both flags immediately after: they are
            // the sole record of "does a prompt still need dismissing", and clear_pairing_state()
            // does NOT run on this success path (only on abort), so anything that inspects them
            // later (e.g. handle_pair_storage_failed()/abort_pairing_attempt() if server/pair-
            // finalize is acked but persistence then fails) must see that the UI was already
            // dismissed here, not fire on_clear_pairing_pin/on_close_pairing_window a second time
            // for the same attempt.
            this->dismiss_pairing_ui(ps.pin_displayed, ps.window_shown);
            ps.pin_displayed = false;
            ps.window_shown = false;

            // Now run the same resolve_pairing_outcome path as pairing_psk, then send
            // client/pair-finalize. The server will respond with server/pair-finalize.
            auto outcome = store.resolve_pairing_outcome(server_id);
            if (!outcome.has_value()) {
                SS_LOGE(TAG,
                        "handle_pin_pairing_message: resolve_pairing_outcome failed for "
                        "server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            // PIN flows carry the new PSK wrapped under the CPace output, not in the clear
            // (spec "PSK Wrapping"). K_wrap = SHA-256(LABEL || sid || ISK); the PSK is
            // sealed with the connection's negotiated AEAD, a 12-byte all-zero nonce, and
            // empty AD.
            const char* cipher_name =
                aead_cipher_name_from_noise_suite(conn->get_noise_suite_name());
            auto isk_opt = ps.cpace.isk();
            if (cipher_name == nullptr || !isk_opt.has_value()) {
                SS_LOGE(TAG,
                        "handle_pin_pairing_message: cannot wrap PSK (cipher=%s, isk=%s) for "
                        "server_id=%s",
                        cipher_name != nullptr ? cipher_name : "unknown",
                        isk_opt.has_value() ? "present" : "missing", server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }
            auto wrapped = wrap_psk(cipher_name, ps.cpace.sid(), isk_opt.value(), outcome->psk);
            if (!wrapped.has_value()) {
                SS_LOGE(TAG, "handle_pin_pairing_message: wrap_psk failed for server_id=%s",
                        server_id.c_str());
                this->local_abort_pin_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
                return;
            }

            SS_LOGI(TAG, "Sending client/pair-finalize (%s) for server_id=%s (record=%s)",
                    to_cstr(ps.method), server_id.c_str(),
                    outcome->record.has_value() ? "stored" : "shared-psk-fallback");
            conn->send_app_json(format_client_pair_finalize_wrapped_message(wrapped.value()),
                                nullptr);
            conn->set_pending_pairing_record(std::move(outcome->record));

            ps.step = SendspinConnection::PinStep::AWAIT_SERVER_PAIR_FINALIZE;
            break;
        }

        case PinPairingMessageKind::MALFORMED: {
            // A server pairing message (server/pair-init, server/pair-auth, or
            // server/pair-confirm) failed to parse. If no PIN session is active on this
            // connection, the frame is a stray protocol violation: e.g. a dynamic/static-PIN
            // message arriving during a pairing_psk exchange, which never touches pin_session_
            // (ps.step stays IDLE). So drop it without tearing the connection down.
            if (ps.step == SendspinConnection::PinStep::IDLE) {
                SS_LOGW(TAG,
                        "handle_pin_pairing_message: malformed pairing frame with no active PIN "
                        "session for server_id=%s; ignoring",
                        server_id.c_str());
                return;
            }

            // Spec Protocol Errors: "a malformed or missing field ... is a protocol error: the
            // detecting side closes the WebSocket without sending any application-level error
            // message, and persists nothing." This is the one pairing-abort path that must NOT
            // send pair/abort and must close unconditionally, so it cannot route through
            // local_abort_pin_pairing() (which always sends pair/abort and only closes for
            // concurrent_attempt); it calls abort_pairing_attempt() directly instead, with no
            // wire_abort_reason and should_drop forced true.
            SS_LOGW(TAG,
                    "handle_pin_pairing_message: malformed pairing frame during PIN pairing for "
                    "server_id=%s; closing per spec Protocol Errors (no pair/abort sent)",
                    server_id.c_str());
            // clear_pairing_state() drops any pending pairing record, so nothing is persisted;
            // drop_connection() with goodbye=std::nullopt closes the transport without sending a
            // client/goodbye (or any other application-level message).
            // SendspinPairAbortReason has no dedicated "protocol error" value and none of the
            // wire-facing reasons fit (no pair/abort was received or sent); UNKNOWN is reused
            // here as the closest available local-only fit, mirroring how STORAGE_FAILED is
            // reused for the other client-local abort (see handle_pair_storage_failed()).
            this->abort_pairing_attempt(conn, /*wire_abort_reason=*/std::nullopt,
                                        /*should_drop=*/true, /*drop_goodbye_reason=*/std::nullopt,
                                        SendspinPairAbortReason::UNKNOWN);
            break;
        }
    }
}

// ============================================================================
// Management main-loop handlers
// ============================================================================

void ConnectionManager::handle_management_request(SendspinConnection* conn,
                                                  const ManagementRequestEvent& event) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). conn is always current_connection_:
    // management/* is only ever admissible for a MANAGEMENT-activity session, which by
    // definition has already been promoted (see the admissibility check in loop()).
    if (conn == nullptr || this->client_->record_store_ == nullptr) {
        return;
    }

    RecordStore& store = *this->client_->record_store_;

    // Trust gating: MANAGEMENT activity is required.
    if (!conn->has_activity(SendspinActivity::MANAGEMENT)) {
        SS_LOGW(TAG,
                "management request without MANAGEMENT activity; replying permission_denied "
                "(server_id=%s)",
                conn->get_server_id().c_str());
        ManagementResultPayload result;
        result.result = ManagementResult::PERMISSION_DENIED;
        conn->send_app_json(format_management_result_message(result), nullptr);
        return;
    }

    ManagementResultPayload result;
    ManagementEffect effect = ManagementEffect::NONE;
    bool include_static_storage = false;

    switch (event.kind) {
        case ManagementRequestKind::LIST_RECORDS:
            include_static_storage = true;
            handle_list_records(store, result, effect);
            break;
        case ManagementRequestKind::ADD_RECORD:
            handle_add_record(store, event.add_payload, result, effect);
            break;
        case ManagementRequestKind::REMOVE_RECORD: {
            // requester_psk_id: the psk_id that authenticated this connection, used to detect
            // own-record removal (see handle_remove_record's doc comment for why psk_id, not
            // server_id, is the right key here).
            //
            // Read once into a local: this runs on the main loop, and the server can start an
            // in-band re-handshake (which rewrites psk_id_ on the network thread) at any point
            // between queueing this request and this drain.
            std::optional<std::string> requester_psk_id;
            if (std::string psk_id = conn->get_psk_id(); !psk_id.empty()) {
                requester_psk_id = std::move(psk_id);
            }
            handle_remove_record(store, event.remove_payload, requester_psk_id, result, effect);
            // Revocation must end the revoked device's live sessions, not just delete the
            // record: a connection resolves its psk_id/category once at handshake time and never
            // re-checks the store. The requester's own connection is excluded here because the
            // GOODBYE_UNAUTHORIZED effect below already drops it (and only after its
            // management/result has been sent).
            if (result.result == ManagementResult::OK) {
                this->drop_connections_using_psk_id(event.remove_payload.psk_id, conn);
            }
            break;
        }
        case ManagementRequestKind::GET_PAIRING_CONFIG:
            include_static_storage = true;
            handle_get_pairing_config(store, this->client_->config_.pin_display_supported,
                                      this->client_->config_.pairing_window_supported, result,
                                      effect);
            break;
        case ManagementRequestKind::SET_PAIRING_CONFIG:
            handle_set_pairing_config(
                store, event.set_config_payload, this->client_->config_.pin_display_supported,
                this->client_->config_.pairing_window_supported, result, effect);
            break;
        case ManagementRequestKind::OPEN_PAIRING_WINDOW: {
            // Opens a pairing window in place of the operator gesture. Handled here rather than
            // in management.h because the window state lives on the ConnectionManager, not the
            // RecordStore. Rejected as invalid when no PIN method is enabled (the same offered
            // logic as build_hello_message); a no-op ok when a window is already open.
            const auto& cfg = this->client_->config_;
            const bool dynamic_offered = cfg.pin_display_supported && store.dynamic_pin_enabled();
            const bool static_offered = cfg.pairing_window_supported &&
                                        store.static_pin_enabled() &&
                                        store.static_pin().has_value();
            if (!dynamic_offered && !static_offered) {
                SS_LOGW(TAG, "management/open-pairing-window: no PIN method enabled; invalid");
                result.result = ManagementResult::INVALID;
            } else {
                if (!this->pairing_window_open()) {
                    this->open_pairing_window();
                }
                result.result = ManagementResult::OK;
            }
            effect = ManagementEffect::NONE;
            break;
        }
    }

    // Attach storage accounting when the store provides it.
    attach_storage_accounting(store, result, include_static_storage);

    conn->send_app_json(format_management_result_message(result), nullptr);

    if (effect == ManagementEffect::GOODBYE_UNAUTHORIZED) {
        SS_LOGI(TAG,
                "management/remove-record: requester removed its own record; disconnecting "
                "(server_id=%s)",
                conn->get_server_id().c_str());
        this->drop_connection(conn, SendspinGoodbyeReason::UNAUTHORIZED);
    }
}

void ConnectionManager::handle_server_unpair(SendspinConnection* conn,
                                             const ServerUnpairEvent& event) {
    // Runs on the main loop (caller holds conn_ptr_mutex_).
    if (conn == nullptr) {
        return;
    }

    // If the PSK category is not LONG_TERM, ignore (trust_level 'none': pairing /
    // unpaired handshake). Mirrors _handle_unpair in aiosendspin/client/connection.py.
    if (event.psk_category != PskCategory::LONG_TERM) {
        SS_LOGD(TAG, "server/unpair ignored (non-LONG_TERM category, server_id=%s)",
                conn->get_server_id().c_str());
        return;
    }

    SS_LOGI(TAG, "server/unpair: dropping record and disconnecting (server_id=%s, psk_id=%s)",
            conn->get_server_id().c_str(), event.matched_psk_id.c_str());

    // Remove the matched record (unless it is a shared-PSK record).
    if (this->client_->record_store_ != nullptr) {
        handle_unpair(*this->client_->record_store_, event.matched_psk_id);
    }

    // Any OTHER session running on the same record is no longer trusted either; see
    // drop_connections_using_psk_id(). `conn` itself is excluded and dropped below with the
    // spec's UNPAIRED reason rather than UNAUTHORIZED.
    this->drop_connections_using_psk_id(event.matched_psk_id, conn);

    this->drop_connection(conn, SendspinGoodbyeReason::UNPAIRED);
}

}  // namespace sendspin
