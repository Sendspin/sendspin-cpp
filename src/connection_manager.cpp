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

/// @brief Captures conn's pairing-UI display flags. See PairingUiSnapshot for
/// why the capture must happen before any pairing-state cleanup.
/// @param conn Connection to snapshot. Must be non-null.
/// @return The captured flags.
static PairingUiSnapshot snapshot_pairing_ui(SendspinConnection* conn) {
    return {conn->pairing_session().code_emitted, conn->pairing_session().window_shown};
}

/// @brief Overall deadline for a pairing-code attempt, bounding it from its first message
/// (pairing.md "Entering and leaving pairing" recommends 2 minutes). It spans every round of the
/// attempt: a retry keeps the running deadline rather than re-arming it. On expiry the attempt is
/// aborted with reason attempt_timeout and the emitted code is withdrawn, rather than hanging
/// until the transport eventually drops.
static constexpr int64_t PAIRING_ATTEMPT_TIMEOUT_US = 120LL * 1000LL * US_PER_MS;

/// @brief Lifetime of an open pairing window, measured from opening and not paused during an
/// attempt (pairing.md "Pairing Window" recommends 5 minutes). On expiry the window closes
/// silently.
static constexpr int64_t WINDOW_LIFETIME_US = 300LL * 1000LL * US_PER_MS;

/// @brief CPace sid label (pairing.md "PAKE"):
/// sid = LABEL || h || pairing_index, the counter a big-endian uint32.
static constexpr char PAKE_SID_LABEL[] = "sendspin-pair-pake-v1";

/// @brief CPace ADa/ADb (spec "PAKE"): distinct associated data per side fixes a reflected-MAC
/// issue. The server is CPace role A, the client is role B.
static constexpr char PAKE_AD_SERVER[] = "server";  // ADa
static constexpr char PAKE_AD_CLIENT[] = "client";  // ADb

/// @brief Append `value` to `out` as a big-endian uint32, the encoding pairing.md "PAKE" gives
/// both of the sid's counters.
static void append_be32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

/// @brief Build the CPace sid for a pairing attempt (pairing.md "PAKE"):
/// LABEL || h (32 bytes) || pairing_index, the counter a big-endian uint32.
/// @param handshake_hash The Noise handshake hash the attempt is bound to.
/// @param pairing_index The pairing_index captured for this attempt
///        (SendspinConnection::PairingSession::pairing_index).
static std::vector<uint8_t> build_pake_sid(const std::array<uint8_t, 32>& handshake_hash,
                                           uint32_t pairing_index) {
    std::vector<uint8_t> sid;
    sid.reserve(sizeof(PAKE_SID_LABEL) - 1 + 32 + 4);
    sid.insert(sid.end(), PAKE_SID_LABEL, PAKE_SID_LABEL + sizeof(PAKE_SID_LABEL) - 1);
    sid.insert(sid.end(), handshake_hash.begin(), handshake_hash.end());
    append_be32(sid, pairing_index);
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

/// @brief Whether an applied server/activate selects the pairing flow: the PAIRING activity
/// together with a pairing.method the client recognizes. Shared by every site that must route
/// such an activate into ConnectionManager::handle_enter_pairing(). PLAYBACK may ride along
/// (messaging.md "server/activate" allows ['playback', 'pairing']); when it does, the connection
/// also takes the operational path (SendspinClient::on_handshake_complete()) rather than
/// instead of it.
static bool is_pairing_selection_activate(const std::vector<SendspinActivity>& activities,
                                          const std::optional<SendspinPairMethod>& pairing_method) {
    if (!contains_activity(activities, SendspinActivity::PAIRING) || !pairing_method.has_value()) {
        return false;
    }
    return pairing_method.value() == SendspinPairMethod::PAIRING_PSK ||
           pairing_method.value() == SendspinPairMethod::DYNAMIC_PAIRING_CODE ||
           pairing_method.value() == SendspinPairMethod::STATIC_PAIRING_CODE;
}

int64_t resolve_liveness_timeout_ms(const SendspinClientConfig& config) {
    if (config.liveness_timeout_ms.has_value()) {
        return config.liveness_timeout_ms.value();
    }
    // The next message goes out after at most one inter-burst interval, and an unanswered one
    // times out after one response timeout.
    return (LIVENESS_TOLERATED_MISSES + 1) *
           (config.time_burst_interval_ms + config.time_burst_response_timeout_ms);
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

// Reading config_ here is safe: SendspinClient declares it before connection_manager_.
ConnectionManager::ConnectionManager(SendspinClient* client)
    : client_(client),
      liveness_timeout_us_(resolve_liveness_timeout_ms(client->config_) * US_PER_MS) {}

ConnectionManager::~ConnectionManager() {
    // Move everything out under the locks, destroy outside them: a connection destructor can join
    // its transport thread (see DeferredRelease), which must not happen while a lock is held.
    // The two mutexes guard disjoint state and are taken in separate scopes, never nested.
    DrainedEvents pending = this->swap_out_pending_events();

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
        // out an exception for teardown. The containers were just moved-from (empty), so the
        // refresh helpers store 0.
        this->has_current_.store(false, std::memory_order_release);
        this->refresh_nursery_size_hint();
        this->refresh_deferred_size_hint();
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
        this->queue_pending(this->pending_connected_events_, c->shared_from_this());
    };
    client_conn->on_disconnected_cb = [this](SendspinConnection* conn) {
        // Defer to loop(); this callback runs on IXWebSocket's internal thread
        std::lock_guard<std::mutex> lock(this->conn_mutex_);
        this->queue_pending(this->pending_disconnect_events_, conn->shared_from_this());
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

void ConnectionManager::start() {
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        this->accepting_ = true;
    }
    // A restart reuses the server object: stop() only stopped it, and loop() starts it again
    // once the network is ready. Retry immediately rather than honoring a backoff from before
    // the stop.
    this->ws_server_start_retry_time_us_ = 0;
    if (this->ws_server_ != nullptr) {
        return;
    }

    // First start: create the server object and configure it once. The config is immutable for
    // the client's lifetime, so a restart reuses these values along with the object.
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
            this->queue_pending(this->pending_disconnect_events_, std::move(conn));
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
           !this->pair_aborts.empty() || !this->server_unpairs.empty() ||
           !this->pairing_messages.empty() || !this->pairing_succeeded.empty() ||
           this->pairing_window_confirm;
}

PairingUiSnapshot ConnectionManager::stop(SendspinGoodbyeReason reason) {
    // Close admission and detach every managed connection under the lock. Nothing is sent or
    // released here (see DeferredRelease): the goodbyes below run outside the lock, and a
    // rejection for a peer delivered during the wait can take the lock meanwhile.
    std::vector<std::shared_ptr<SendspinConnection>> to_goodbye;
    PairingUiSnapshot ui{false, false};
    {
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        this->accepting_ = false;
        if (this->current_connection_ != nullptr) {
            // A code or pairing-window prompt still showing must be dismissed once the client has
            // reset its state; the flags live on the connection, so capture them before it goes
            // (see PairingUiSnapshot). The caller queues the dismissal after its own cleanup.
            const PairingUiSnapshot current_ui =
                snapshot_pairing_ui(this->current_connection_.get());
            ui.code_was_emitted |= current_ui.code_was_emitted;
            ui.window_was_shown |= current_ui.window_was_shown;
            this->current_connection_->disable_message_dispatch();
            // Vacate the admitted slot explicitly, as drop_connection() does: the connection is
            // moved out below, so set_current_connection(nullptr) finds an empty slot and clears
            // nothing, and the goodbye keeps the connection alive past this call.
            this->current_connection_->set_admitted(false);
            to_goodbye.push_back(std::move(this->current_connection_));
            this->set_current_connection(nullptr);
        }
        for (auto& entry : this->nursery_) {
            const PairingUiSnapshot entry_ui = snapshot_pairing_ui(entry.conn.get());
            ui.code_was_emitted |= entry_ui.code_was_emitted;
            ui.window_was_shown |= entry_ui.window_was_shown;
            entry.conn->disable_message_dispatch();
            to_goodbye.push_back(std::move(entry.conn));
        }
        this->nursery_.clear();
        this->nursery_size_.store(0, std::memory_order_release);
        this->hello_retries_.clear();
        this->has_current_.store(false, std::memory_order_release);
        // A standing pairing window belongs to this run; a restart begins with it closed.
        this->pairing_window_open_until_us_ = 0;
        // Releases already queued (a handoff loser, a reaped entry) had their dispatch disabled
        // when they were queued; the shutdown goodbye replaces whatever reason they carried. One
        // queued without a reason has a transport that is already gone, and every transport's
        // disconnect() completes immediately on a disconnected connection, so it needs no
        // separate path.
        for (auto& release : this->deferred_releases_) {
            to_goodbye.push_back(std::move(release.conn));
        }
        this->deferred_releases_.clear();
        this->deferred_size_.store(0, std::memory_order_release);
    }

    // Goodbye every connection and wait, bounded, for the sends to complete. Every count is
    // registered before the wait starts, so a completion that runs inline (host, and any
    // not-connected transport) cannot satisfy the wait early. A disconnected connection completes
    // immediately (see SendspinConnection::disconnect), so none needs a pre-check.
    auto wait = std::make_shared<GoodbyeWait>();
    for (auto& conn : to_goodbye) {
        wait->add_pending();
        conn->disconnect(reason, [wait] { wait->complete_one(); });
    }
    // The bound scales with the goodbyes issued: on ESP they are handed to lwIP one at a time by
    // the single httpd worker, so several peers need several quanta.
    const uint32_t flush_bound_ms =
        GOODBYE_FLUSH_TIMEOUT_MS * static_cast<uint32_t>(to_goodbye.size());
    if (!wait->wait(flush_bound_ms)) {
        SS_LOGD(TAG, "Goodbye flush bound (%u ms for %u goodbyes) elapsed; closing regardless",
                static_cast<unsigned>(flush_bound_ms), static_cast<unsigned>(to_goodbye.size()));
    }

    // Tear the server down regardless. This joins every network thread on host and waits for
    // the httpd task on ESP, so no callback of any kind arrives after it returns. Close
    // callbacks fired during it queue disconnect events under conn_mutex_, which is not held.
    if (this->ws_server_ != nullptr) {
        this->ws_server_->stop();
    }

    // Drop every deferred event those closes (or the last ticks) queued: the connections they
    // name are gone, and a pairing event has no session to act on.
    DrainedEvents dropped = this->swap_out_pending_events();
    // Locals release here, outside every lock. An outbound connection's destructor stops its
    // transport synchronously; deferring that is not an option (see DeferredRelease).
    return ui;
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
        ev.pair_aborts.swap(this->pending_pair_abort_events_);
        ev.server_unpairs.swap(this->pending_server_unpair_events_);
        ev.pairing_messages.swap(this->pending_pairing_message_events_);
        ev.pairing_succeeded.swap(this->pending_pairing_succeeded_events_);
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
                                   std::string(NOISE_SUITE_CHACHAPOLY));
        conn->send_noise_client_init();
    }

    // server/activate events: trust enforcement, operational gating, and admission
    // arbitration. ALL decisions (admissibility, arbitration, RecordStore mutations)
    // happen here on the main loop thread, never on the network thread.
    for (auto& event : ev.activates) {
        this->process_activate_event(event);
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

void ConnectionManager::process_activate_event(ServerActivateEvent& event) {
    if (!event.conn) {
        return;
    }
    const bool in_nursery = this->find_in_nursery(event.conn.get()) != this->nursery_.end();
    const bool is_current = event.conn.get() == this->current_connection_.get();
    if (!in_nursery && !is_current) {
        // Already released by an earlier event in the same loop() pass.
        return;
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
    const bool trust_ok =
        admissible(event.conn->get_psk_category(), event.activities, has_roles, unpaired_access);

    if (!trust_ok) {
        const SendspinGoodbyeReason reject_reason = inadmissible_reject_reason(
            event.conn->get_psk_category(), event.activities, has_roles, unpaired_access);
        SS_LOGW(TAG, "server/activate inadmissible (psk_category=%d): closing with %s",
                static_cast<int>(event.conn->get_psk_category()),
                reject_reason == SendspinGoodbyeReason::PAIRING_REQUIRED ? "pairing_required"
                                                                         : "unauthorized");
        this->drop_connection(event.conn.get(), reject_reason);
        return;
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
    const bool is_pairing_activate = contains_activity(event.activities, SendspinActivity::PAIRING);
    if (is_pairing_activate) {
        event.conn->bump_pairing_index();
    }

    // ==== Pairing-method admissibility (spec "pair/abort") ====
    // Structurally admissible already (the activity set passed the table above),
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
        event.conn->send_app_json(format_pair_abort_message(PairAbortReason::METHOD_NOT_SUPPORTED),
                                  nullptr);
        return;
    }

    if (is_pairing_activate && event.pairing_method.has_value()) {
        const SendspinPairMethod method = event.pairing_method.value();
        const bool category_ok = (method == SendspinPairMethod::PAIRING_PSK) ==
                                 (event.conn->get_psk_category() == PskCategory::PAIRING);
        // "Currently offered" mirrors exactly what build_hello_message() advertises
        // in supported_pair_methods (client.cpp): the RecordStore's live enabled
        // flags AND the platform-capability configuration (a device that lists no
        // out-channel or emission format never offers dynamic_pairing_code,
        // regardless of the enabled flag).
        bool offered = true;
        if (this->client_->record_store_ != nullptr) {
            const RecordStore& rs = *this->client_->record_store_;
            const auto& cfg = this->client_->config_;
            switch (method) {
                case SendspinPairMethod::PAIRING_PSK:
                    offered = rs.pairing_psk_enabled() && rs.pairing_psk().has_value();
                    break;
                case SendspinPairMethod::DYNAMIC_PAIRING_CODE:
                    offered = offers_dynamic_pairing_code(cfg, rs);
                    break;
                case SendspinPairMethod::STATIC_PAIRING_CODE:
                    offered = offers_static_pairing_code(cfg, rs);
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
            return;
        }

        // ==== Emission-format admissibility (dynamic_pairing_code only) ====
        // messaging.md "server/activate" requires `format` on a dynamic_pairing_code
        // activation, drawn from the client's own `formats`; a missing, unrecognized,
        // or unoffered one is pair/abort(method_not_supported) with the connection left
        // open (pairing.md "Client <-> Server: pair/abort").
        if (method == SendspinPairMethod::DYNAMIC_PAIRING_CODE &&
            !offers_pairing_code_format(this->client_->config_, event.pairing_format)) {
            SS_LOGW(TAG,
                    "server/activate names no usable pairing.format for "
                    "dynamic_pairing_code on server_id=%s; replying "
                    "pair/abort(method_not_supported), connection stays open",
                    event.conn->get_server_id().c_str());
            event.conn->send_app_json(
                format_pair_abort_message(PairAbortReason::METHOD_NOT_SUPPORTED), nullptr);
            return;
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
    // Copied before the activate is applied: messaging.md "client/state" ties the next state
    // update to the active-role set changing, so the comparison needs the set this activation
    // replaces.
    const std::vector<std::string> roles_before = event.conn->get_active_roles();
    event.conn->apply_server_activate(event.activities, active_roles_to_apply, event.pairing_method,
                                      event.pairing_format);
    const bool roles_changed = roles_before != event.conn->get_active_roles();

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
        // after an in-band re-handshake reset first_activate_received_; both branches
        // below that act on an is_first activate wait for the post-swap hello to have
        // also completed (is_handshake_complete()) before doing so, otherwise this is
        // a stale pre-completion activate and there is nothing to (re-)act on yet.
        this->note_playback_activity(event.conn.get());

        const auto& activities = event.conn->get_activities();
        const auto& pairing_method = event.conn->get_pairing_method();
        const bool selects_pairing = is_pairing_selection_activate(activities, pairing_method);

        // The pairing-selection check runs on every activate, first or not, and takes
        // priority over the plain operational branch. This matters because a
        // server rehandshaking an already-admitted connection onto the pairing PSK
        // resets first_activate_received_, so the resulting pairing activate arrives
        // looking like a first activate; routing it into the operational branch would
        // publish client/state while the server is instead waiting for
        // client/pair-finalize. handle_enter_pairing() never publishes client/state
        // (only on_handshake_complete() does), so entering pairing here is always
        // safe on that front regardless of is_first.
        if (event.conn->is_pairing_in_progress()) {
            // ==== Pairing leftover activate ====
            // Pairing was in progress and the server sent another server/activate
            // instead of server/pair-finalize: it abandoned pairing without
            // finalizing. The activate was already applied normally above; going
            // operational discards any pending record and resets the pairing session
            // structurally (see the comment on
            // SendspinClient::on_handshake_complete()).
            // pairing.md "Entering and leaving pairing" admits one pairing attempt per
            // pairing server/activate, so an activate that selects pairing again ends
            // the abandoned attempt and starts the one it admits, rather than only
            // going operational: its pairing_index was already counted, and a server
            // that sent it is waiting for the client/pair-init that opens the new
            // attempt.
            // Two paths reset first_activate_received_ on an already-admitted
            // connection: an in-band re-handshake (handle_noise_rehandshake(), which
            // also clears pairing_in_progress_, so that path always reaches here with
            // is_pairing_in_progress() false) and the pair-finalize ack
            // (note_pairing_finalize_ack(), which leaves pairing_in_progress_ set).
            // An activate arriving in the ack-to-rekey window therefore lands in this
            // branch with is_first true; that is the desired outcome for it too (the
            // server abandoned the finalize choreography, so clear pairing and go
            // operational), and matches the pre-restructure behavior of that window.
            SS_LOGI(TAG,
                    "Subsequent activate during pairing (leftover): clearing pairing "
                    "state and going operational for server_id=%s",
                    event.conn->get_server_id().c_str());
            this->client_->on_handshake_complete(event.conn.get());
            if (selects_pairing) {
                SS_LOGI(TAG,
                        "Leftover activate selects pairing again (%s): starting the "
                        "attempt it admits for server_id=%s",
                        to_cstr(pairing_method.value()), event.conn->get_server_id().c_str());
                this->handle_enter_pairing(event.conn.get());
            }
        } else if (selects_pairing) {
            // ==== Activate selects pairing ====
            // Reached both when the operator initiates pairing on an already-
            // operational connection (is_first false: the server re-activates the
            // connection with the PAIRING activity and a pairing object directly) and
            // when the server first rehandshakes the connection onto the pairing PSK
            // (is_first true: see the priority comment above).
            if (!is_first || event.conn->is_handshake_complete()) {
                // pairing.md "Entering and leaving pairing": adding 'pairing' does not by
                // itself affect active_roles, streams or group membership. An activate that
                // declares both purposes therefore runs the operational path as well as the
                // pairing one, and in that order: going operational clears stale pairing
                // state, so it has to precede the attempt this activate admits.
                if (is_first && contains_activity(activities, SendspinActivity::PLAYBACK)) {
                    this->client_->on_handshake_complete(event.conn.get());
                }
                SS_LOGI(TAG,
                        "Activate selects pairing (%s): entering pairing for "
                        "server_id=%s",
                        to_cstr(pairing_method.value()), event.conn->get_server_id().c_str());
                this->handle_enter_pairing(event.conn.get());
            }
        } else if (is_first && event.conn->is_handshake_complete()) {
            this->client_->on_handshake_complete(event.conn.get());
        }

        // messaging.md "client/state": a role that defines a state object and becomes active in
        // active_roles must be told about in an update that includes that role's object, and
        // "stream/start" has the server wait for that update before starting the role's stream.
        // publish_client_state() builds an object for every role active on the connection, so one
        // publish serves an added role and, equally, drops the object of a removed one. A first
        // activate publishes through on_handshake_complete(); this covers every later one that
        // moves the set.
        if (roles_changed && !is_first && event.conn->is_operational()) {
            this->client_->publish_client_state(event.conn.get());
        }
        return;
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

    // ==== Pairing-code deferred events ====
    // Only ever targets the current connection: a pairing-code session only exists on a
    // connection that already won promotion into current_connection_ (see the pairing
    // branch in promote_or_arbitrate_nursery_entry()).
    for (auto& event : ev.pairing_messages) {
        if (!event.conn || event.conn.get() != this->current_connection_.get()) {
            continue;
        }
        this->handle_pairing_message(event.conn.get(), event);
    }

    // ==== on_pairing_succeeded deferred events ====
    // Triggered by the network-thread server/pair-finalize ack handler
    // (SendspinClient::schedule_pairing_succeeded); only ever targets the current
    // connection for the same reason as ev.pairing_messages above.
    for (const auto& server_id : ev.pairing_succeeded) {
        this->client_->note_pairing_succeeded(server_id);
    }

    // ==== Pairing-window confirm deferred event ====
    if (ev.pairing_window_confirm) {
        this->handle_pairing_window_confirmed();
    }
}

void ConnectionManager::drain_unpair_events(DrainedEvents& ev) {
    // Only the current connection is acted on. A nursery peer that has proven itself can send
    // server/unpair too (the spec calls it valid regardless of the current activities), so this
    // drops one from a peer the client is not actually running a session with. Rare, and it
    // costs that peer nothing but a repeat once it holds the session.
    for (auto& event : ev.server_unpairs) {
        if (!event.conn || event.conn.get() != this->current_connection_.get()) {
            continue;
        }
        this->handle_server_unpair(event.conn.get(), event);
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
    // Both scans operate purely on nursery membership: a hello is only ever sent while its
    // connection is proving itself, and a connection that has left the nursery has no further
    // hello to send. The nursery_size_ hint therefore covers the retry scan too, and the scan's
    // own lazy erase covers a connection dropped by an earlier event this same tick.
    if (this->nursery_size_.load(std::memory_order_acquire) > 0) {
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

                // Drop retries whose connection has left the nursery: it was promoted (its hello
                // completed) or released, and either way there is nothing left to retry.
                if (this->find_in_nursery(rc) == this->nursery_.end()) {
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

                // Retries exhausted: the establish-deadline scan just below reaps the nursery
                // member itself.
                it = this->hello_retries_.erase(it);
            }
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

void ConnectionManager::scan_pairing_attempt_timeout() {
    // ==== Pairing attempt timeout ====
    // Abort a pairing-code exchange that has stalled past PAIRING_ATTEMPT_TIMEOUT_US (pairing.md
    // "Entering and leaving pairing"). local_abort_pairing also withdraws the emitted code.
    // Only the current connection can host a pairing-code session (see the pairing branch in
    // promote_or_arbitrate_nursery_entry()).
    std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
    if (this->current_connection_ != nullptr) {
        // Between the server's pair-finalize ack and the post-rekey activate that reaches
        // clear_pairing_state(), pairing_session_ still reports its last pre-ack step (non-IDLE)
        // and attempt_deadline_us keeps counting down against an exchange that has already
        // succeeded. Skip the scan for that window so a slow rekey cannot abort a completed
        // pairing.
        if (this->current_connection_->is_pairing_finalized()) {
            return;
        }
        // connection.md "Re-handshake": between Noise message 1 and the new server/activate the
        // client starts no application message but the handshake, which a pair/abort would be.
        // first_activate_received() is false for exactly that window, so the abort waits for the
        // activation; if it never comes, scan_reprove_watchdog() closes the connection instead
        // and the attempt ends with it. pairing.md "Entering and leaving pairing" bounds an
        // attempt with a timeout "on expiry it sends pair/abort"; the re-handshake rule is the
        // narrower MUST NOT, and the wait it imposes is bounded by REPROVE_TIMEOUT_US.
        if (!this->current_connection_->first_activate_received()) {
            return;
        }
        const auto& ps = this->current_connection_->pairing_session();
        const int64_t now_us = platform_time_us();
        const bool attempt_expired = ps.step != SendspinConnection::PairingStep::IDLE &&
                                     ps.attempt_deadline_us != 0 &&
                                     now_us >= ps.attempt_deadline_us;
        if (attempt_expired) {
            SS_LOGW(TAG, "Pairing attempt timed out for server_id=%s; aborting",
                    this->current_connection_->get_server_id().c_str());
            this->local_abort_pairing(this->current_connection_.get(),
                                      PairAbortReason::ATTEMPT_TIMEOUT);
        }
    }
}

void ConnectionManager::scan_reprove_watchdog() {
    // ==== Re-proving watchdog ====
    // current_connection_ is briefly non-operational while it re-proves itself: after a
    // successful in-band re-handshake (SendspinConnection::handle_noise_rehandshake(), which
    // leaves it awaiting the post-swap server/activate) or after the server acks
    // client/pair-finalize and is expected to rekey via one
    // (SendspinConnection::note_pairing_finalize_ack()). Both call
    // sites reset provisional_time_us_ to a fresh (non-zero) timestamp when they enter this
    // window. current_connection_ is never non-operational for any other reason: a nursery
    // entry is only ever promoted once it is already operational (see
    // promote_or_arbitrate_nursery_entry()), and an in-progress pairing-code PAKE exchange keeps
    // is_operational() true throughout (that flow has its own timeouts: the
    // PAIRING_ATTEMPT_TIMEOUT_US check above, and pairing_window_open() while a gesture is
    // awaited). Gating on !is_operational() here therefore reaps exactly the re-proving window and
    // never a legitimate pairing wait. The provisional_time_us_ != 0 guard additionally excludes a
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
            // Closed without a goodbye. One of the two windows this reaps starts at Noise
            // message 1, and connection.md "Re-handshake" lets the client start no application
            // message there but the handshake; the other ends at a rekey the peer has already
            // failed to perform. No goodbye reason describes either, and the peer learns the
            // same thing from the close. close_silently() tears the transport down here (it is
            // non-blocking on every platform), so the nullopt release below has nothing left to
            // send and only has to let the connection go.
            this->current_connection_->close_silently(SendspinGoodbyeReason::ANOTHER_SERVER);
            this->drop_connection(this->current_connection_.get(), std::nullopt);
        }
    }
}

void ConnectionManager::loop() {
    this->maybe_start_ws_server();

    // Process deferred connection lifecycle events: one conn_mutex_ swap, then (when there is
    // something to do) one conn_ptr_mutex_ section applying lifecycle, pairing, and unpair
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
        this->drain_unpair_events(ev);
    }

    // Send the goodbyes and release the connections dropped above, outside the lock.
    this->flush_deferred_releases();

    // Call loop() on active connections using shared_ptr copies to avoid holding the lock.
    this->loop_managed_connections();

    // Noise-completion scan, hello retry timers, and the nursery establish-deadline reap.
    this->scan_hello_and_nursery();

    // Liveness tick: a blackholed socket (no FIN, RST, or close frame) never produces a transport
    // close event, so drop the established connection once its inbound silence reaches the timeout.
    if (this->liveness_timeout_us_ > 0 && this->has_current_.load(std::memory_order_acquire)) {
        const int64_t now_us = platform_time_us();
        std::lock_guard<std::mutex> lock(this->conn_ptr_mutex_);
        if (this->current_connection_ != nullptr &&
            now_us - this->current_connection_->get_last_receive_time_us() >=
                this->liveness_timeout_us_) {
            SS_LOGW(TAG, "Current connection silent for >%" PRId64 " ms, dropping as lost",
                    this->liveness_timeout_us_ / US_PER_MS);
            // The goodbye actively closes the transport, which the silent peer never will; an
            // inbound session would otherwise hold its server slot. Per the spec's
            // `client/goodbye` section, restart asks a server that was only slow to reconnect.
            this->drop_connection(this->current_connection_.get(), SendspinGoodbyeReason::RESTART);
        }
    }

    // Send the goodbyes and release the connections reaped by the nursery tick, outside the lock.
    this->flush_deferred_releases();

    // Drive the platform ws_server's pending-upgrade reap (ESP: close sessions that never
    // complete their upgrade; host: no-op, IXWebSocket times them out itself). Called with no
    // manager lock held.
    if (this->ws_server_ != nullptr) {
        this->ws_server_->tick();
    }

    // Abort a pairing-code exchange that has stalled past its attempt timeout.
    this->scan_pairing_attempt_timeout();
    // Send the goodbye and release the connection if the timeout check above aborted one.
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
    this->queue_pending(this->pending_activate_events_, std::move(event));
}

void ConnectionManager::schedule_pair_abort(PairAbortEvent event) {
    // Called from SendspinClient::process_json_message() on the network thread when a pair/abort
    // message arrives (or a malformed pairing frame forces one).
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending(this->pending_pair_abort_events_, std::move(event));
}

void ConnectionManager::schedule_server_unpair(ServerUnpairEvent&& event) {
    // Called from SendspinClient::process_json_message() on the network thread when
    // server/unpair arrives.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending(this->pending_server_unpair_events_, std::move(event));
}

void ConnectionManager::schedule_pairing_message(ServerPairingMessageEvent&& event) {
    // Called from SendspinClient::process_json_message() on the network thread when a
    // pairing message arrives (or a malformed pairing frame forces a MALFORMED event).
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending(this->pending_pairing_message_events_, std::move(event));
}

void ConnectionManager::schedule_pairing_succeeded(std::string server_id) {
    // Called from SendspinClient::process_json_message() on the network thread when the
    // server/pair-finalize ack handler stores a long-term record.
    std::lock_guard<std::mutex> lock(this->conn_mutex_);
    this->queue_pending(this->pending_pairing_succeeded_events_, std::move(server_id));
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
        if (!this->accepting_) {
            // Delivered while stop() is tearing down (or before start()): the nursery is being
            // emptied, so the newcomer gets a goodbye and a close instead of a slot. Same shape
            // as the nursery-full rejection below.
            SS_LOGD(TAG, "Not accepting connections, rejecting new connection");
            conn->disable_message_dispatch();
            this->queue_deferred_release(std::move(conn), SendspinGoodbyeReason::SHUTDOWN);
        } else if (inbound_count >= NURSERY_CAPACITY) {
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
                                       std::string(NOISE_SUITE_CHACHAPOLY));
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
    // Verify the connection is still managed: hellos are only ever sent to nursery members, so
    // anything else (already released or promoted by an earlier event this tick) is stale.
    if (this->find_in_nursery(conn) == this->nursery_.end()) {
        SS_LOGW(TAG, "Connection no longer valid for hello message");
        return true;
    }

    if (conn == nullptr || !conn->is_connected()) {
        SS_LOGW(TAG, "Cannot send hello - not connected");
        return true;
    }

    std::string hello_message = this->client_->build_hello_message();

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

void ConnectionManager::refresh_nursery_size_hint() {
    // Note: caller must hold conn_ptr_mutex_
    this->nursery_size_.store(this->nursery_.size(), std::memory_order_release);
}

void ConnectionManager::refresh_deferred_size_hint() {
    // Note: caller must hold conn_ptr_mutex_
    this->deferred_size_.store(this->deferred_releases_.size(), std::memory_order_release);
}

void ConnectionManager::push_nursery_entry(NurseryEntry entry) {
    // Note: caller must hold conn_ptr_mutex_
    this->nursery_.push_back(std::move(entry));
    this->refresh_nursery_size_hint();
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
        // Admitting also replays the role messages this connection held while it was proving
        // itself, which is why it goes through the client rather than setting the flag here.
        this->client_->admit_connection(conn.get());
    }
    this->has_current_.store(conn != nullptr, std::memory_order_release);
    this->current_connection_ = std::move(conn);
}

std::vector<NurseryEntry>::iterator ConnectionManager::release_nursery_entry(
    std::vector<NurseryEntry>::iterator it, std::optional<SendspinGoodbyeReason> reason) {
    // Note: caller must hold conn_ptr_mutex_ and flush_deferred_releases() after dropping it
    auto conn = std::move(it->conn);
    auto next = this->nursery_.erase(it);
    this->refresh_nursery_size_hint();
    // Leaving the connection manager: block stale network-thread dispatch into role/state queues
    // during the goodbye window. Outgoing sends, including the goodbye itself, are unaffected.
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
    this->refresh_deferred_size_hint();
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
        this->refresh_deferred_size_hint();
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
        // If a code pairing was mid-flight, its code / pairing-window prompt must be dismissed.
        // Snapshot before cleanup_connection_state() clears the pending notification state in
        // EventState (see PairingUiSnapshot), then queue the note_* calls after cleanup so they
        // survive to be dispatched from SendspinClient::loop() (same ordering rule as the abort
        // handlers).
        const PairingUiSnapshot ui = snapshot_pairing_ui(conn);
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
        this->dismiss_pairing_ui(ui.code_was_emitted, ui.window_was_shown);
        return;
    }

    if (auto it = this->find_in_nursery(conn); it != this->nursery_.end()) {
        // Dropping an unproven connection: no client-state cleanup (it was never admitted). Code
        // sessions only ever exist on the current connection (see the pairing-events comment
        // above, in loop()), but dismiss any prompt defensively for symmetry with the other
        // drop paths in case that invariant is ever relaxed. Snapshot before release for the same
        // reason as the current-slot path above (see PairingUiSnapshot).
        const PairingUiSnapshot ui = snapshot_pairing_ui(conn);
        this->release_nursery_entry(it, goodbye);
        this->dismiss_pairing_ui(ui.code_was_emitted, ui.window_was_shown);
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
    this->refresh_nursery_size_hint();
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
        // Leaving the connection manager: block stale network-thread dispatch during the goodbye
        // window (outgoing sends, including the goodbye itself, are unaffected).
        conn->disable_message_dispatch();
        this->queue_deferred_release(std::move(conn), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
        return next;
    }

    // Notify the client, publish state, and record playback activity, only for the winner.
    this->note_playback_activity(this->current_connection_.get());

    // ==== Pairing branch ====
    // If the winning activate declares the PAIRING activity with a supported pairing.method,
    // enter the pairing flow. The connection still occupies current_connection_ (so admission.h's
    // "in-flight pairing is not displaced" rule applies). An activate declaring pairing alone is
    // not announced to the client as operational until pairing finishes and the post-finalize
    // re-handshake completes; one that also declares playback is announced first, because
    // pairing.md "Entering and leaving pairing" leaves active_roles and streams untouched and
    // going operational is what clears any stale pairing state before the new attempt.
    const auto& activities = this->current_connection_->get_activities();
    const auto& pairing_method = this->current_connection_->get_pairing_method();
    const bool selects_pairing = is_pairing_selection_activate(activities, pairing_method);

    if (!selects_pairing || contains_activity(activities, SendspinActivity::PLAYBACK)) {
        this->client_->on_handshake_complete(this->current_connection_.get());
    }
    if (selects_pairing) {
        SS_LOGI(TAG, "Pairing activate received (%s): entering pairing for server_id=%s",
                to_cstr(pairing_method.value()),
                this->current_connection_->get_server_id().c_str());
        this->handle_enter_pairing(this->current_connection_.get());
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

    // An attempt is in flight from here until it finalizes or aborts: pairing messages are only
    // routed while it is (pairing.md "Entering and leaving pairing"). Playback is untouched.
    conn->set_pairing_in_progress(true);

    // The pairing server/activate counter (spec "Pairing index") was already bumped by the caller
    // at the point this activate was received (see the activate-events loop in
    // drain_lifecycle_events(): every pairing server/activate counts there, whether or not it turns
    // out to be admissible, so a method_not_supported rejection does not desync the count from the
    // server's). Do NOT bump
    // again here: this handler can also be reached well after reception (the "subsequent activate
    // transitions into pairing" branch applies the activate first, then calls this), so bumping
    // here would double-count or use a stale value. The current value is captured into the
    // pairing session below for the code-based branches (sent as pairing_index and reused for
    // the CPace sid).
    const uint32_t pairing_index = conn->get_pairing_index();

    const std::string& server_id = conn->get_server_id();
    const auto& selected_method = conn->get_pairing_method();

    // ==== Pairing-code branches (dynamic and static) ====
    if (selected_method.has_value() &&
        (selected_method.value() == SendspinPairMethod::DYNAMIC_PAIRING_CODE ||
         selected_method.value() == SendspinPairMethod::STATIC_PAIRING_CODE)) {
        this->handle_enter_pairing_code(conn, pairing_index, server_id, selected_method.value());
        return;
    }

    // ==== Pairing-PSK branch ====
    this->handle_enter_pairing_psk(conn, pairing_index, server_id);
}

void ConnectionManager::handle_enter_pairing_code(SendspinConnection* conn, uint32_t pairing_index,
                                                  const std::string& server_id,
                                                  SendspinPairMethod selected_method) {
    const bool is_dynamic = selected_method == SendspinPairMethod::DYNAMIC_PAIRING_CODE;
    const RecordStore& store = *this->client_->record_store_;

    // Defensive: the client should not have advertised static_pairing_code without a configured
    // code, nor dynamic_pairing_code without an emission format the activation could name.
    if (!is_dynamic && !store.static_pairing_code().has_value()) {
        SS_LOGE(TAG, "handle_enter_pairing: no static pairing code configured for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }
    if (is_dynamic && !conn->get_pairing_format().has_value()) {
        SS_LOGE(TAG, "handle_enter_pairing: no emission format selected for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // Capture the Noise handshake hash now (main loop, before any further I/O). The
    // NoiseTransport session is network-thread-owned, but we are on the main loop and the
    // session was set before the first server/activate fired; no concurrent write
    // is possible at this point (no re-handshake is in progress). If the hash is
    // unavailable the PAKE sid and the code derivation cannot be computed, so abort.
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
        ps.format = conn->get_pairing_format().value();
    } else {
        // Capture the static code now, before any operator window wait, so a code change during
        // the open window cannot swap the CPace secret mid-attempt. The static code is what CPace
        // consumes as PRS directly; a dynamic one is only known once nonce_A arrives.
        ps.prs = pairing_code_digits_prs(store.static_pairing_code().value());
    }

    // Gesture gating (pairing.md "Pairing Window"): the static pairing code gates every attempt
    // on an operator gesture; the dynamic one runs ungated.
    const bool gesture_gated = !is_dynamic;

    if (gesture_gated && !this->pairing_window_open()) {
        // No window open: report the pending gesture with client/pair-pending and wait.
        // pair-pending does not start the attempt or its timeout (the server applies its
        // own timeout and cancels via server/activate), so no attempt deadline is armed
        // here (attempt_deadline_us == 0 disables the loop() timeout check).
        ps.step = SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW;
        ps.attempt_deadline_us = 0;
        SS_LOGI(TAG,
                "Sending client/pair-pending (%s, gesture-gated, no window open) for "
                "server_id=%s",
                to_cstr(ps.method), server_id.c_str());
        conn->send_app_json(format_client_pair_pending_message(ps.pairing_index), nullptr);

        // Surface the pairing-window prompt to the operator, but only when the platform
        // actually implements the gesture UI (on_open_pairing_window's contract is that it
        // fires only when pairing_window_supported is true). A device that never offers
        // static_pairing_code without that flag (see offers_static_pairing_code()) cannot reach
        // this branch, but a stored config that outlives a capability change could; the attempt
        // then has no way to proceed and waits for the server's own timeout to cancel it. Log
        // loudly so the stall is diagnosable.
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
    // (start_pairing_attempt consumes the window; its lifetime runs until pair-init is sent).
    this->start_pairing_attempt(conn);
    this->client_->note_pairing_started(server_id);
}

void ConnectionManager::handle_enter_pairing_psk(SendspinConnection* conn, uint32_t pairing_index,
                                                 const std::string& server_id) {
    // resolve_pairing_outcome mints the long-term PSK and the record that holds it, or fails
    // when the store has no room for a net-new record.
    auto outcome = this->client_->record_store_->resolve_pairing_outcome(server_id);
    if (!outcome.has_value()) {
        SS_LOGE(TAG,
                "handle_enter_pairing: resolve_pairing_outcome failed for server_id=%s; "
                "aborting pairing",
                server_id.c_str());
        // Send pair/abort(method_not_supported): closest reason for "cannot proceed".
        // method_not_supported is used as the error path here because there is no distinct
        // "store unavailable" reason in the protocol. abort_pairing_attempt() also queues
        // note_pairing_failed() and drops the connection (drop_connection() handles both the
        // current-slot cleanup, which also resets the time burst, and the deferred
        // goodbye+release; flush_deferred_releases() runs at the end of the caller's locked
        // block), matching every other pairing-failure path in this file.
        this->abort_pairing_attempt(
            conn, PairAbortReason::METHOD_NOT_SUPPORTED, PairingDropAction::CLOSE_WITH_GOODBYE,
            SendspinPairAbortReason::METHOD_NOT_SUPPORTED, SendspinGoodbyeReason::UNAUTHORIZED);
        return;
    }

    // pairing.md "Pairing PSK Flow": after the pairing server/activate the client sends
    // client/pair-init followed immediately by client/pair-finalize, without waiting for a
    // server response. pair-init starts the attempt and carries the pairing index alone; the
    // PSK flow has no PAKE round and so no commit_B.
    SS_LOGI(TAG, "Sending client/pair-init (pairing_psk) for server_id=%s", server_id.c_str());
    conn->send_app_json(format_client_pair_init_message(pairing_index), nullptr);

    // Send client/pair-finalize with the long-term PSK (base64url-encoded, 43 chars).
    SS_LOGI(TAG, "Sending client/pair-finalize for server_id=%s", server_id.c_str());
    // Named local rather than a temporary so the serialized message, which carries the raw
    // base64 long-term PSK, can be wiped once it has been handed to the transport.
    std::string finalize_msg = format_client_pair_finalize_message(outcome->psk);
    conn->send_app_json(finalize_msg, nullptr);
    secure_zero(finalize_msg.data(), finalize_msg.size());

    // Hold the pending record: committed to the RecordStore by the network-thread
    // server/pair-finalize handler on ack.
    conn->set_pending_pairing_record(std::move(outcome->record));

    this->client_->note_pairing_started(server_id);
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
    this->abort_pairing_attempt(
        conn, /*wire_abort_reason=*/std::nullopt,
        reason == PairAbortReason::CONCURRENT_ATTEMPT ? PairingDropAction::CLOSE_WITH_GOODBYE
                                                      : PairingDropAction::KEEP_OPEN,
        to_public_abort_reason(reason), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
}

/// @brief Fires on_clear_pairing_code and/or on_open_pairing_window's counterpart for a pairing UI
/// element that was left showing. Caller must hold conn_ptr_mutex_.
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
                                              SendspinGoodbyeReason goodbye_reason,
                                              std::optional<std::string> server_id_override) {
    // Runs on the main loop (caller holds conn_ptr_mutex_).
    //
    // Capture the deferred-notification inputs BEFORE clear_pairing_state() resets the pairing
    // session and before the connection is possibly released (server_id is copied so it survives
    // any tear-down). server_id_override lets a caller substitute a value captured earlier
    // instead of reading the connection's current state.
    const std::string server_id =
        server_id_override.has_value() ? server_id_override.value() : conn->get_server_id();
    // Snapshot before clear_pairing_state()/drop_connection() clear it (see PairingUiSnapshot).
    const PairingUiSnapshot ui = snapshot_pairing_ui(conn);

    if (wire_abort_reason.has_value()) {
        conn->send_app_json(format_pair_abort_message(wire_abort_reason.value()), nullptr);
    }

    // On the current-slot path drop_connection() -> cleanup_connection_state() clears the
    // pending pairing-note queue, so the note_* calls below MUST come after it.
    conn->clear_pairing_state();
    if (drop_action != PairingDropAction::KEEP_OPEN) {
        const std::optional<SendspinGoodbyeReason> drop_goodbye_reason =
            drop_action == PairingDropAction::CLOSE_WITH_GOODBYE
                ? std::optional<SendspinGoodbyeReason>(goodbye_reason)
                : std::nullopt;
        this->drop_connection(conn, drop_goodbye_reason);
    }

    // Queue listener notifications AFTER any drop_connection() so they survive to be dispatched
    // from SendspinClient::loop() after conn_ptr_mutex_ is released. Only the queue push happens
    // while the lock is held.
    this->client_->note_pairing_failed(server_id, public_reason);
    this->dismiss_pairing_ui(ui.code_was_emitted, ui.window_was_shown);
}

// ============================================================================
// Pairing-code main-loop handlers
// ============================================================================

void ConnectionManager::local_abort_pairing(SendspinConnection* conn, PairAbortReason reason) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). Aborts the pairing-code session
    // locally:
    //   1. Send pair/abort to the server.
    //   2. Withdraw the emitted code and clear the pairing state on the connection.
    //   3. Close the connection, but ONLY for reason concurrent_attempt (pairing.md "pair/abort":
    //      every other reason (attempt_timeout, method_not_supported, pairing_code_mismatch,
    //      user_cancelled) leaves the connection open).
    //   4. Queue on_pairing_failed (and on_clear_pairing_code, if a code was emitted) for
    //      delivery from loop().
    if (conn == nullptr) {
        return;
    }

    SS_LOGW(TAG, "local_abort_pairing: server_id=%s reason=%s", conn->get_server_id().c_str(),
            to_cstr(reason));

    // Best-effort pair/abort to the server (the connection is still live here).
    this->abort_pairing_attempt(
        conn, reason,
        reason == PairAbortReason::CONCURRENT_ATTEMPT ? PairingDropAction::CLOSE_WITH_GOODBYE
                                                      : PairingDropAction::KEEP_OPEN,
        to_public_abort_reason(reason), SendspinGoodbyeReason::CONCURRENT_ATTEMPT);
}

// ============================================================================
// Pairing-window main-loop handlers
// ============================================================================

void ConnectionManager::start_pairing_attempt(SendspinConnection* conn) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). The PairingSession was populated by
    // handle_enter_pairing; this sends the client/pair-init that starts the attempt and arms the
    // attempt timeout that bounds it (pairing.md "Entering and leaving pairing"). Sending
    // pair-init ends the pairing window's lifetime, so any standing window is consumed here
    // whether the attempt was gated or not.
    this->pairing_window_open_until_us_ = 0;

    auto& ps = conn->pairing_session();
    const std::string& server_id = conn->get_server_id();

    if (ps.method == SendspinPairMethod::DYNAMIC_PAIRING_CODE) {
        // Generate nonce_B and its commitment, then send client/pair-init with commit_B and
        // the required pairing_index (pairing.md "Client -> Server: client/pair-init"). The code
        // itself cannot be derived until the server's nonce_A arrives, so CPace starts in
        // handle_pair_init() rather than here.
        ps.nonce_b = pairing_generate_nonce();
        auto commit_b = pairing_code_commit(ps.nonce_b.data(), ps.nonce_b.size());

        SS_LOGI(TAG, "Sending client/pair-init (dynamic_pairing_code) for server_id=%s",
                server_id.c_str());
        conn->send_app_json(format_client_pair_init_message(commit_b, ps.pairing_index), nullptr);

        ps.step = SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT;
        ps.attempt_deadline_us = platform_time_us() + PAIRING_ATTEMPT_TIMEOUT_US;
        return;
    }

    // Static pairing code. Use the PRS captured at pairing start (see handle_enter_pairing),
    // not a fresh store read, so a code change during the operator's window cannot swap the
    // CPace secret. Empty means it was never captured (defensive; the enter-pairing path always
    // captures a configured code).
    if (ps.prs.empty()) {
        SS_LOGE(TAG, "start_pairing_attempt: no static pairing code captured for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // Send client/pair-init with just pairing_index (the static flow carries no commit_B).
    // pairing_index is required on every client/pair-init (pairing.md "Pairing index").
    SS_LOGI(TAG, "Sending client/pair-init (static_pairing_code) for server_id=%s",
            server_id.c_str());
    conn->send_app_json(format_client_pair_init_message(ps.pairing_index), nullptr);

    if (!this->start_pake_round(conn)) {
        return;
    }
    ps.attempt_deadline_us = platform_time_us() + PAIRING_ATTEMPT_TIMEOUT_US;
}

bool ConnectionManager::start_pake_round(SendspinConnection* conn) {
    // Runs on the main loop (caller holds conn_ptr_mutex_). Both code-based flows run the same
    // CPace exchange over the attempt's PRS and sid (pairing.md "PAKE"); only the point at which
    // the PRS becomes known differs, so the start lives here rather than in each caller.
    auto& ps = conn->pairing_session();
    std::vector<uint8_t> sid = build_pake_sid(ps.handshake_hash, ps.pairing_index);

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
    // Runs on the main loop (caller holds conn_ptr_mutex_). A pairing session only ever exists on
    // current_connection_: pairing only starts once a nursery entry has won promotion (see the
    // pairing branch in promote_or_arbitrate_nursery_entry()). If an attempt is already waiting
    // for the gesture, the freshly opened window is consumed by it immediately; otherwise the
    // window stands open (spec: Pairing Window) so a pairing activate arriving within its
    // lifetime can proceed without a further gesture.
    SendspinConnection* conn = this->current_connection_.get();
    const bool awaiting =
        conn != nullptr &&
        conn->pairing_session().step == SendspinConnection::PairingStep::AWAIT_PAIRING_WINDOW;

    if (awaiting) {
        SS_LOGI(TAG, "Pairing window opened: starting the waiting %s attempt for server_id=%s",
                to_cstr(conn->pairing_session().method), conn->get_server_id().c_str());
        this->start_pairing_attempt(conn);
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

void ConnectionManager::handle_pairing_message(SendspinConnection* conn,
                                               const ServerPairingMessageEvent& event) {
    // Runs on the main loop. All CPace / nonce / hash state is main-loop-only.
    if (conn == nullptr || this->client_->record_store_ == nullptr) {
        return;
    }

    // pairing.md "Entering and leaving pairing": after the client has aborted an attempt it
    // silently
    // discard pairing messages received before the next server/activate." is_pairing_in_progress()
    // is cleared by clear_pairing_state() on every path that ends an attempt (local abort, received
    // pair/abort, leftover activate), so a pairing message that races the abort and lands here
    // after the fact is discarded without re-aborting (which would otherwise fire on every stray,
    // now-stale message since ps.step is back to IDLE).
    if (!conn->is_pairing_in_progress()) {
        SS_LOGI(TAG,
                "handle_pairing_message: discarding pairing message (kind=%d) for "
                "server_id=%s; no attempt in progress",
                static_cast<int>(event.kind), conn->get_server_id().c_str());
        return;
    }

    switch (event.kind) {
        case PairingMessageKind::PAIR_INIT:
            this->handle_pair_init(conn, event);
            break;

        case PairingMessageKind::PAIR_AUTH:
            this->handle_pair_auth(conn, event);
            break;

        case PairingMessageKind::PAIR_CONFIRM:
            this->handle_pair_confirm(conn, event);
            break;

        case PairingMessageKind::MALFORMED: {
            auto& ps = conn->pairing_session();
            const std::string& server_id = conn->get_server_id();

            // A server pairing message (server/pair-init, server/pair-auth, or
            // server/pair-confirm) failed to parse. If no pairing-code session is active on this
            // connection, the frame is a stray protocol violation: e.g. a code-flow message
            // arriving during a pairing_psk exchange, which never touches pairing_session_
            // (ps.step stays IDLE). So drop it without tearing the connection down.
            if (ps.step == SendspinConnection::PairingStep::IDLE) {
                SS_LOGW(TAG,
                        "handle_pairing_message: malformed pairing frame with no active "
                        "pairing-code session for server_id=%s; ignoring",
                        server_id.c_str());
                return;
            }

            // Spec Protocol Errors: "a malformed or missing field ... is a protocol error: the
            // detecting side closes the WebSocket without sending any application-level error
            // message, and persists nothing." This is the one pairing-abort path that must NOT
            // send pair/abort and must close unconditionally, so it cannot route through
            // local_abort_pairing() (which always sends pair/abort and only closes for
            // concurrent_attempt); it calls abort_pairing_attempt() directly instead, with no
            // wire_abort_reason and drop_action forced CLOSE_SILENTLY.
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
                                         const ServerPairingMessageEvent& event) {
    auto& ps = conn->pairing_session();
    const std::string& server_id = conn->get_server_id();

    // Step 1: server/pair-init received. This step belongs to the dynamic pairing code alone;
    // the static flow goes straight from client/pair-init to server/pair-auth (pairing.md
    // "Static Pairing Code Flow"). A PAIR_INIT while ps.method == STATIC_PAIRING_CODE is a
    // protocol violation, handled by the same wrong-step abort as an out-of-order message.
    if (ps.method != SendspinPairMethod::DYNAMIC_PAIRING_CODE ||
        ps.step != SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_INIT) {
        SS_LOGW(TAG,
                "handle_pairing_message: PAIR_INIT in wrong step=%d method=%s for "
                "server_id=%s",
                static_cast<int>(ps.step), to_cstr(ps.method), server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
        return;
    }

    // Derive the code both formats share: the digest over the handshake hash and the two
    // binding nonces (pairing.md "Pairing code derivation").
    auto digest = pairing_code_digest(ps.handshake_hash.data(), ps.handshake_hash.size(),
                                      event.nonce_a.data(), event.nonce_a.size(), ps.nonce_b.data(),
                                      ps.nonce_b.size());
    if (!digest.has_value()) {
        SS_LOGE(TAG, "handle_pairing_message: pairing-code derivation failed for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // The emission format decides both what the operator receives and what CPace consumes as
    // PRS: the six ASCII digits, or the 24 raw digest bytes the version-1 pairing token carries
    // (pairing.md "Pairing code derivation", "QR-code emission").
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

    // Emit the code to the operator (deferred to loop() via note_display_pairing_code). Record
    // that one is being emitted so the abort/cleanup paths know to withdraw it.
    this->client_->note_display_pairing_code(emitted, ps.format);
    ps.code_emitted = true;

    if (!this->start_pake_round(conn)) {
        return;
    }
    // No message sent yet: the client waits for server/pair-auth.
}

void ConnectionManager::handle_pair_auth(SendspinConnection* conn,
                                         const ServerPairingMessageEvent& event) {
    auto& ps = conn->pairing_session();
    const std::string& server_id = conn->get_server_id();

    // Step 2: server/pair-auth received. Expect step AWAIT_SERVER_PAIR_AUTH.
    if (ps.step != SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_AUTH) {
        SS_LOGW(TAG, "handle_pairing_message: PAIR_AUTH in wrong step=%d for server_id=%s",
                static_cast<int>(ps.step), server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
        return;
    }

    // Send client/pair-auth (pake_msg_2 = client CPace share) BEFORE deriving.
    // This matches the reference: sends pake_msg_2 then calls _derive.
    const auto& client_share = ps.cpace.public_share();
    conn->send_app_json(format_client_pair_auth_message(client_share), nullptr);

    // Derive the MAC key from the server's share (pake_msg_1).
    // A derive failure means the peer share has the wrong length or encodes a
    // low-order point (a malformed or hostile share), NOT a wrong code: a wrong code
    // still produces a well-formed, non-low-order shared secret that only fails the
    // confirm-tag check in handle_pair_confirm().
    //
    // pairing.md "Protocol Errors": "a CPace share with the wrong length or encoding a
    // low-order point" is a protocol error: the detecting side closes the WebSocket
    // without sending any application-level error message, and persists nothing. This
    // is the same class as the MALFORMED case in handle_pairing_message(), so it follows
    // the same shape: no pair/abort, unconditional close.
    if (!ps.cpace.derive(event.pake_msg_1.data(), event.pake_msg_1.size())) {
        SS_LOGW(TAG,
                "handle_pairing_message: CPace::derive failed (malformed/low-order "
                "peer share) for server_id=%s; closing per pairing.md Protocol Errors "
                "(no pair/abort sent)",
                server_id.c_str());
        // clear_pairing_state() drops any pending pairing record, so nothing is
        // persisted; drop_connection() with goodbye=std::nullopt closes the transport
        // without sending a client/goodbye (or any other application-level message).
        // SendspinPairAbortReason has no dedicated "protocol error" value and none of
        // the wire-facing reasons fit (no pair/abort was received or sent); UNKNOWN is
        // reused here as the closest available local-only fit, matching the MALFORMED
        // case in handle_pairing_message().
        this->abort_pairing_attempt(conn, /*wire_abort_reason=*/std::nullopt,
                                    PairingDropAction::CLOSE_SILENTLY,
                                    SendspinPairAbortReason::UNKNOWN);
        return;
    }

    ps.step = SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_CONFIRM;
}

void ConnectionManager::handle_pair_confirm(SendspinConnection* conn,
                                            const ServerPairingMessageEvent& event) {
    auto& ps = conn->pairing_session();
    RecordStore& store = *this->client_->record_store_;
    const std::string& server_id = conn->get_server_id();

    // Step 3: server/pair-confirm received. Expect step AWAIT_SERVER_PAIR_CONFIRM.
    if (ps.step != SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_CONFIRM) {
        SS_LOGW(TAG,
                "handle_pairing_message: PAIR_CONFIRM in wrong step=%d for "
                "server_id=%s",
                static_cast<int>(ps.step), server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::ATTEMPT_TIMEOUT);
        return;
    }

    // Verify server_kc (server confirmation tag).
    if (!ps.cpace.verify(event.server_kc.data(), event.server_kc.size())) {
        SS_LOGW(TAG,
                "handle_pairing_message: server_kc verification failed "
                "(pairing-code mismatch) for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::PAIRING_CODE_MISMATCH);
        return;
    }

    // Compute client_kc (our confirmation tag).
    auto client_kc_opt = ps.cpace.tag();
    if (!client_kc_opt.has_value()) {
        SS_LOGE(TAG, "handle_pairing_message: CPace::tag() failed for server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // Send client/pair-confirm: the dynamic flow carries client_kc plus the sealed opening of
    // commit_B, the static flow client_kc alone (pairing.md "Client -> Server:
    // client/pair-confirm").
    if (ps.method == SendspinPairMethod::STATIC_PAIRING_CODE) {
        conn->send_app_json(format_client_pair_confirm_message(client_kc_opt.value()), nullptr);
    } else {
        conn->send_app_json(format_client_pair_confirm_message(client_kc_opt.value(), ps.nonce_b),
                            nullptr);
    }

    // Withdraw the emitted code and/or dismiss the pairing-window prompt now that the exchange
    // succeeded; each is a no-op unless this attempt actually raised it (see
    // code_emitted / window_shown above). Reset both flags immediately after: they are
    // the sole record of "does a prompt still need dismissing", and clear_pairing_state()
    // does NOT run on this success path (only on abort), so anything that inspects them
    // later (e.g. abort_pairing_attempt()) must see that the UI was already dismissed here,
    // not fire on_clear_pairing_code/on_close_pairing_window a second time for the same
    // attempt.
    this->dismiss_pairing_ui(ps.code_emitted, ps.window_shown);
    ps.code_emitted = false;
    ps.window_shown = false;

    // Now run the same resolve_pairing_outcome path as pairing_psk, then send
    // client/pair-finalize. The server will respond with server/pair-finalize.
    auto outcome = store.resolve_pairing_outcome(server_id);
    if (!outcome.has_value()) {
        SS_LOGE(TAG,
                "handle_pairing_message: resolve_pairing_outcome failed for "
                "server_id=%s",
                server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }

    // The code-based flows carry the new PSK wrapped under the CPace output, not in the clear
    // (pairing.md "Wrapping"). K_wrap = SHA-256(PSK_WRAP_LABEL || sid || ISK); the PSK is
    // sealed with the connection's negotiated AEAD, a 12-byte all-zero nonce, and empty AD.
    const char* cipher_name = aead_cipher_name_from_noise_suite(conn->get_noise_suite_name());
    auto isk_opt = ps.cpace.isk();
    if (cipher_name == nullptr || !isk_opt.has_value()) {
        SS_LOGE(TAG,
                "handle_pairing_message: cannot wrap PSK (cipher=%s, isk=%s) for "
                "server_id=%s",
                cipher_name != nullptr ? cipher_name : "unknown",
                isk_opt.has_value() ? "present" : "missing", server_id.c_str());
        this->local_abort_pairing(conn, PairAbortReason::METHOD_NOT_SUPPORTED);
        return;
    }
    auto wrapped =
        wrap_value(PSK_WRAP_LABEL, cipher_name, ps.cpace.sid(), isk_opt.value(), outcome->psk);
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
    conn->set_pending_pairing_record(std::move(outcome->record));

    ps.step = SendspinConnection::PairingStep::AWAIT_SERVER_PAIR_FINALIZE;
}

// ============================================================================
// Unpair main-loop handler
// ============================================================================

void ConnectionManager::handle_server_unpair(SendspinConnection* conn,
                                             const ServerUnpairEvent& event) {
    // Runs on the main loop (caller holds conn_ptr_mutex_).
    if (conn == nullptr) {
        return;
    }

    // Only a session running on a long-term record is paired at all (spec "server/unpair": if
    // the session is unpaired, ignore the message), so a pairing or Sentinel handshake has
    // nothing to drop.
    if (event.psk_category != PskCategory::LONG_TERM) {
        SS_LOGD(TAG, "server/unpair ignored (non-LONG_TERM category, server_id=%s)",
                conn->get_server_id().c_str());
        return;
    }

    SS_LOGI(TAG, "server/unpair: dropping record and disconnecting (server_id=%s, psk_id=%s)",
            conn->get_server_id().c_str(), event.matched_psk_id.c_str());

    // Drop the matched pairing record (spec "server/unpair").
    if (this->client_->record_store_ != nullptr) {
        this->client_->record_store_->remove_record(event.matched_psk_id);
    }

    // Any OTHER session running on the same record is no longer trusted either; see
    // drop_connections_using_psk_id(). `conn` itself is excluded and dropped below with the
    // spec's UNPAIRED reason rather than UNAUTHORIZED.
    this->drop_connections_using_psk_id(event.matched_psk_id, conn);

    this->drop_connection(conn, SendspinGoodbyeReason::UNPAIRED);
}

}  // namespace sendspin
