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

#include "sendspin/client.h"

#include "connection.h"
#include "connection_manager.h"
#include "crypto/keys.h"
#include "crypto/pairing_code.h"
#include "crypto/pairing_token.h"
#include "inbound_ring.h"
#include "inbox.h"
#include "pairing_offers.h"
#include "platform/base64.h"
#include "platform/compiler.h"
#include "platform/crypto.h"
#include "platform/json_arena.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/network_info.h"
#include "platform/time.h"
#include "record_store.h"
#ifdef SENDSPIN_ENABLE_ARTWORK
#include "artwork_role_impl.h"
#endif
#ifdef SENDSPIN_ENABLE_COLOR
#include "color_role_impl.h"
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
#include "controller_role_impl.h"
#endif
#ifdef SENDSPIN_ENABLE_METADATA
#include "metadata_role_impl.h"
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
#include "player_role_impl.h"
#include "sendspin/player_role.h"
#endif
#include "protocol_messages.h"
#include "protocol_task.h"
#include "time_filter.h"
#ifdef SENDSPIN_ENABLE_VISUALIZER
#include "visualizer_role_impl.h"
#endif
#include <ArduinoJson.h>

#include <algorithm>
#include <utility>

static const char* const TAG = "sendspin.client";

namespace sendspin {

namespace {

/// @brief Discriminates PairingNote entries. Enumerator order is the dispatch precedence: the
/// drain fires all notes of one type before any note of the next, regardless of queue order (e.g.
/// on_pairing_started before the on_open_pairing_window prompt it gated). The dispatch walks this
/// enum by value and switches on it exhaustively with no default, so -Werror forces a new
/// enumerator to be placed in the order and given a case.
enum class PairingNoteType : uint8_t {
    PAIRING_STARTED,
    PAIRING_SUCCEEDED,
    TRUST_CHANGED,
    PAIRING_FAILED,
    DISPLAY_PAIRING_CODE,
    CLEAR_PAIRING_CODE,
    OPEN_PAIRING_WINDOW,
    CLOSE_PAIRING_WINDOW,
    COUNT,  ///< Not a note type; bounds the dispatch walk. Keep last.
};

/// @brief One deferred pairing/trust listener notification, queued by the note_*() methods on
/// the protocol task and dispatched from the main loop's drain
struct PairingNote {
    PairingNoteType type{};
    /// server_id for PAIRING_STARTED/SUCCEEDED/FAILED; the emitted code for
    /// DISPLAY_PAIRING_CODE; empty otherwise.
    std::string text{};
    SendspinPairAbortReason reason{};  ///< Valid only for PAIRING_FAILED.
    ConnectionTrust trust{};           ///< Valid only for TRUST_CHANGED.
    /// Emission format of `text`; valid only for DISPLAY_PAIRING_CODE.
    SendspinPairingCodeFormat format{};
};

/// @brief True for note types that coalesce to at most one callback per tick, keeping the
/// single-flag semantics of the window and code-withdrawal notifications
constexpr bool is_coalesced_note(PairingNoteType type) {
    return type == PairingNoteType::CLEAR_PAIRING_CODE ||
           type == PairingNoteType::OPEN_PAIRING_WINDOW ||
           type == PairingNoteType::CLOSE_PAIRING_WINDOW;
}

/// @brief The provider writes the main loop owes, accumulated by request_persist() and
/// note_last_played_server() and performed by flush_pending_persistence()
struct PersistRequest {
    /// The last-played server_id to write, when it changed since the last flush.
    std::optional<std::string> last_played{};
};

/// @brief High-performance requests the protocol task queued for the main loop, which calls the
/// listener. Counts rather than a net value, so an acquire and a release queued between two
/// drains still reach the listener as a request and a release.
struct HighPerformanceRequests {
    uint8_t acquires{0};
    uint8_t releases{0};
};

/// @brief Adds `delta` to `count`, saturating; a saturated count means the main loop stopped
/// draining, which the caller logs.
bool add_saturating(uint8_t& count, uint8_t delta) {
    if (count > UINT8_MAX - delta) {
        count = UINT8_MAX;
        return false;
    }
    count = static_cast<uint8_t>(count + delta);
    return true;
}

/// @brief Resolve the `locations` hint for a pair-method descriptor in client/hello.
/// @return The hint to advertise, or nullopt to omit the field.
///
/// The hint is informational (pairing.md "client/hello pair-method descriptor"): only the
/// application knows where its secret was published, so an unset value means the client has
/// nothing to say rather than a default worth sending.
std::optional<std::vector<std::string>> locations_hint(const std::vector<std::string>& configured) {
    if (configured.empty()) {
        return std::nullopt;
    }
    return configured;
}

/// @brief Whether inbound traffic for `role` from `conn` may be acted on.
///
/// Every role this client drives has at most one owner among the admitted connections, and only
/// that connection's traffic reaches the role: a connection that is not admitted, or one that
/// does not own the role, is ignored. Ownership implies the role is active on the connection.
///
/// messaging.md "Communication" keeps a message the client implements *recognized* while its role
/// is inactive ("An ID the receiver implements is still recognized when its role is inactive"), so
/// this is not the unknown-message rule: the message is parsed and validated as usual, the
/// connection is never closed for it, and only the role's own handling is skipped. messaging.md
/// "server/activate" requires the mirror of this of servers, so a role removal the peer has not
/// yet seen never costs the connection.
///
/// A true verdict is only half the gate. The caller pairs it with the role's teardown generation,
/// loaded right after this returns and passed into the handler, and each point of effect
/// re-checks the captured value (see Impl::accepts() on each role). Protocol task only.
[[maybe_unused]] bool role_accepts_traffic(const ConnectionManager& manager,
                                           const SendspinConnection* conn, SendspinRole role) {
    if (manager.owns_role(conn, role)) {
        return true;
    }
    SS_LOGD(TAG, "Ignoring %s traffic: the connection does not own the role", to_cstr(role));
    return false;
}

/// @brief Whether `role` is in `mask`, logging the teardown once per role rather than once per
/// call site.
[[maybe_unused]] bool role_removed(uint16_t mask, SendspinRole role) {
    if ((mask & role_mask_bit(role)) == 0) {
        return false;
    }
    SS_LOGI(TAG, "Role %s left its connection: stopping the role", to_cstr(role));
    return true;
}

}  // namespace

/// @brief The main-loop-bound channels the client itself owns, beside the roles' own slots
struct SendspinClient::EventState {
    Inbox inbox;
    InboxSlot<GroupUpdateObject> group_slot{inbox, INBOX_TOPIC_GROUP};
    /// The filter error of the primary connection's latest completed time burst, for
    /// on_time_sync_updated(). Written by the protocol task, latest-wins.
    InboxSlot<double> time_sync_slot{inbox, INBOX_TOPIC_TIME};
    /// Owed provider writes, merged from any thread (request_persist(),
    /// note_last_played_server()) and drained into flush_pending_persistence(). Its own slot
    /// rather than an event: cleanup_connection_state() wipes the event ring, and an owed write
    /// must survive the connection dying before the next drain.
    InboxSlot<PersistRequest> persist_slot{inbox, INBOX_TOPIC_PERSIST};
    /// High-performance requests from the protocol task (time bursts), applied by the drain.
    InboxSlot<HighPerformanceRequests> high_performance_slot{inbox, INBOX_TOPIC_HIGH_PERFORMANCE};
    /// Pairing/trust listener notifications, appended on the protocol task in the order they
    /// happen and dispatched by the drain.
    InboxSlot<std::vector<PairingNote>> pairing_slot{inbox, INBOX_TOPIC_PAIRING};
    /// Bumped by stop() before its teardown so a drain frame already on the stack (a listener
    /// callback that called stop()) abandons the events it copied out before the teardown. Main
    /// loop only.
    uint32_t drain_generation{0};

    /// @brief Appends `note` to the pairing slot. Every SendspinClient::note_*() method funnels
    /// through this so the merge shape lives once. PairingNote is anonymous-namespace-private
    /// to this file, so this lives on EventState (itself private to SendspinClient) rather than as
    /// a SendspinClient member declared in the public header.
    /// @param note The note to append (moved).
    void push_pairing_note(PairingNote&& note) {
        std::vector<PairingNote> delta;
        delta.push_back(std::move(note));
        this->pairing_slot.merge(
            [](std::vector<PairingNote>& current, std::vector<PairingNote>&& added) {
                for (auto& entry : added) {
                    current.push_back(std::move(entry));
                }
            },
            std::move(delta));
    }
};

/// @brief Client-level state the protocol task owns
struct SendspinClient::TaskState {
    /// The newest client/state snapshot the main loop published (publish_state()); each admitted
    /// connection is sent its filtered copy (publish_client_state()). Protocol task only, and
    /// reset by stop() once the task is joined.
    std::optional<ClientStateMessage> client_state;
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinClient::SendspinClient(SendspinClientConfig config)
    : config_(std::move(config)),
      connection_manager_(std::make_unique<ConnectionManager>(this)),
      event_state_(std::make_unique<EventState>()),
      protocol_task_(std::make_unique<ProtocolTask>(this->config_.server_max_connections)),
      task_state_(std::make_unique<TaskState>()) {
    if (this->config_.json_arena_size > 0) {
        this->json_arena_ = std::make_unique<SendspinArenaAllocator>(this->config_.json_arena_size);
    }
}

SendspinClient::~SendspinClient() {
    // Transport-only teardown: goodbye and close every peer in the same order as stop(), but
    // dispatch no teardown or clear callback (nothing reaches the inbox and no drain runs). A
    // role-thread callback can still run until stop_role_threads() below joins its role, so
    // listeners must outlive the client.
    if (this->lifecycle_.load(std::memory_order_relaxed) != LifecycleState::STOPPED) {
        this->close_transports();
        // The role threads next, as stop() does: each returns the items it holds and unbinds its
        // list from the ring, so the ring's reset below never reaches a list the role resets
        // destroy (a LOCAL item its holder returned but the protocol task never took is counted
        // through that list).
        this->stop_role_threads();
        this->release_inbound_ring();
        // Every high-performance hold ends with the client. Requests the protocol task queued are
        // dropped, and the holds the main loop applied are released.
        this->event_state_->high_performance_slot.reset();
        while (this->high_performance_ref_count_.load() > 0) {
            this->release_high_performance();
        }
    }

    // Every thread is joined and the inbound ring released (above, by stop(), or never started).
    // Every role is reset explicitly (not just the threaded ones):
    // role InboxSlots release their topic-bit claims against event_state_'s Inbox on destruction,
    // so all roles must be gone before the alphabetized member order destroys event_state_.
#ifdef SENDSPIN_ENABLE_PLAYER
    this->player_.reset();
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    this->visualizer_.reset();
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    this->artwork_.reset();
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    this->controller_.reset();
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    this->metadata_.reset();
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    this->color_.reset();
#endif
    this->connection_manager_.reset();
    // No new write can be requested once the connection manager is gone; perform one still owed
    // (a pair-finalize that landed after the last loop() tick) before the store goes away.
    this->flush_pending_persistence();
    // Destroyed after the connection manager: every connection holds raw pointers into
    // identity_/record_store_ (see SendspinConnection::init_noise_handshake), so both must
    // outlive every connection the manager could still be tearing down.
    this->record_store_.reset();
    this->identity_.reset();
}

void SendspinClient::set_log_level(LogLevel level) {
    platform_set_log_level(static_cast<int>(level));
}

LogLevel SendspinClient::get_log_level() {
    return static_cast<LogLevel>(platform_get_log_level());
}

// ============================================================================
// Lifecycle
// ============================================================================

bool SendspinClient::start() {
    switch (this->lifecycle_.load(std::memory_order_relaxed)) {
        case LifecycleState::RUNNING:
            return true;
        case LifecycleState::STOPPING:
            SS_LOGW(TAG, "start() ignored: called from a callback while stop() is in progress");
            return false;
        case LifecycleState::STOPPED:
            break;
    }

    // Fail closed, like a failed identity: a Pairing PSK any peer could hold admits every server
    // as a pairing peer, and a malformed static pairing code (pairing.md "Static Pairing Code
    // Flow") fails every attempt with a code mismatch.
    if (this->config_.pairing_psk.has_value() &&
        !RecordStore::is_usable_pairing_psk(this->config_.pairing_psk->bytes)) {
        SS_LOGE(TAG, "Configured Pairing PSK is all zero or the published Sentinel PSK; cannot "
                     "start");
        return false;
    }
    if (this->config_.static_pairing_code.has_value() &&
        !is_valid_static_pairing_code(this->config_.static_pairing_code.value())) {
        SS_LOGE(TAG, "Configured static pairing code is not %d decimal digits; cannot start",
                STATIC_PAIRING_CODE_DIGITS);
        return false;
    }

    // lifecycle_ stays STOPPED until every step below has succeeded. Marking the client running
    // up front would report it started even when this function returns false (e.g. identity
    // generation failed and identity_ is left null), which is precisely the state connect_to()
    // must refuse to build a connection in.
    //
    // Create the record store (needs the persistence provider, so done here rather than at
    // construction) and load or generate the static X25519 identity. Both must exist before the
    // connection manager can hand them out to any connection (connection_manager_->start() below
    // arms the ws_server, and connect_to() may be called any time after start() RETURNS TRUE).
    // A restart keeps both: the store already holds the records the last run persisted, and the
    // identity is fixed for the lifetime of the stored keypair. They are rebuilt only when the
    // persistence provider changed since they were built (each reads the provider once, at
    // construction, so a provider set between a stop and the next start would otherwise never
    // be consulted) or when the previous start failed part-way (a store without an identity).
    if (this->record_store_ == nullptr || this->identity_ == nullptr ||
        this->identity_provider_ != this->persistence_provider_) {
        this->identity_.reset();
        this->record_store_ =
            std::make_unique<RecordStore>(this->persistence_provider_, this->config_);
        if (!this->load_or_generate_identity()) {
            // identity_ is left null: there is no safe key to fall back to (see
            // load_or_generate_identity()'s doc comment), so the client must not start.
            return false;
        }
        this->identity_provider_ = this->persistence_provider_;
    }

    // A store that came up owing a write (a duplicate slot cleared at load) flushes on the first
    // tick, through the same deferred path a pairing uses: the provider is main-loop-only and the
    // store never calls it itself outside that flush.
    if (this->record_store_->has_pending_writes()) {
        this->request_persist();
    }

    // Load persisted state
    this->load_last_played_server();

    // The inbound ring every admitted connection receives into and the role threads consume
    // from; the role starts below bind their item lists to it.
    if (!this->create_inbound_ring()) {
        return false;
    }

    // Start the role threads. A failure part-way stops the roles that did start, so the client
    // is back in the stopped state and a corrected retry begins clean.
    bool roles_started = true;
#ifdef SENDSPIN_ENABLE_PLAYER
    if (roles_started && this->player_) {
        roles_started =
            this->player_->impl_->start(this->persistence_provider_, this->inbound_ring_.get());
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (roles_started && this->visualizer_) {
        roles_started = this->visualizer_->impl_->start(this->inbound_ring_.get());
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (roles_started && this->artwork_) {
        roles_started = this->artwork_->impl_->start();
    }
#endif
    if (!roles_started) {
        this->stop_role_threads();
        this->release_inbound_ring();
        return false;
    }

    // A command queued after the last stop() finished (a request racing it on another thread)
    // belongs to the run that ended; this run begins with an empty queue, taking accepts again.
    this->protocol_task_->drop_commands();
    this->protocol_task_->open_accepts();

    // The first client/state snapshot, taken by the protocol task's first tick: every
    // connection's client/state is built from the newest snapshot the task holds.
    this->protocol_task_->publish_state(this->build_client_state());

    // Open admission and create the WebSocket server, started here when the network is already
    // up. Before the protocol task starts: everything the manager writes here is the task's from
    // then on, and an accept the server delivers meanwhile waits in the command queue for the
    // task's first tick.
    this->connection_manager_->start();

    // The protocol task. Undersized stacks are clamped to the documented minimum, as the
    // transport tasks' are.
    size_t protocol_stack = this->config_.protocol_task_stack_size;
    if (protocol_stack < SendspinClientConfig::DEFAULT_PROTOCOL_TASK_STACK_SIZE) {
        SS_LOGW(TAG, "protocol_task_stack_size %u below minimum %u; clamping",
                static_cast<unsigned>(protocol_stack),
                static_cast<unsigned>(SendspinClientConfig::DEFAULT_PROTOCOL_TASK_STACK_SIZE));
        protocol_stack = SendspinClientConfig::DEFAULT_PROTOCOL_TASK_STACK_SIZE;
    }
    if (!this->protocol_task_->start([this]() { return this->protocol_tick(); }, protocol_stack,
                                     this->config_.protocol_task_priority,
                                     this->config_.protocol_task_psram_stack)) {
        SS_LOGE(TAG, "Failed to start the protocol task");
        // No task ever ran: close admission, stop the server (joining its transport threads),
        // and only then drop the accepts it queued, whose connections no transport reaches any
        // more.
        this->connection_manager_->close_admission();
        (void)this->connection_manager_->finish_stop();
        this->protocol_task_->drop_commands();
        this->stop_role_threads();
        this->release_inbound_ring();
        return false;
    }

    this->lifecycle_.store(LifecycleState::RUNNING, std::memory_order_release);
    return true;
}

void SendspinClient::stop() {
    if (this->lifecycle_.load(std::memory_order_relaxed) != LifecycleState::RUNNING) {
        return;
    }
    // From here the client reads as stopped: is_started() is false, loop() is a no-op, and
    // start()/stop() and every request that queues a command are refused, so a listener callback
    // fired below cannot recurse into the teardown, restart the server, or reach a connection.
    this->lifecycle_.store(LifecycleState::STOPPING, std::memory_order_release);

    // 1-4. Signal the drain roles, close admission, join the protocol task (its final tick
    //      goodbyes every peer within a bound), then close every transport and stop the server
    //      (see close_transports()). Nothing reaches a role or the inbox from a transport or the
    //      protocol task after this.
    const PairingUiSnapshot pairing_ui = this->close_transports();

    // 5. Role threads. Each role returns the inbound ring items it held after its own join, and
    //    with every producer and consumer gone the ring is emptied and released.
    this->stop_role_threads();
    this->release_inbound_ring();

    // 6. Reset per-connection and role state exactly as a lost connection does, here on the main
    //    loop since every other thread is joined. With every producer gone, the state this
    //    leaves behind is the state a restart begins from. The drain generation bump abandons
    //    the events a drain frame further up the stack (a listener that called stop()) copied
    //    out before this teardown. The group slot is reset too, so the drain below cannot
    //    repopulate group_state_ from a delta that arrived before the stop.
    ++this->event_state_->drain_generation;
    this->cleanup_connection_state(ALL_ROLES_MASK);
    this->task_state_->client_state.reset();
    this->group_state_ = GroupUpdateObject{};

    // A pairing attempt cut short by the stop leaves its code or pairing-window prompt showing.
    // Queue the dismissals now, after cleanup_connection_state() wiped the pending notes, so the
    // drain below delivers them (same ordering rule as the ConnectionManager drop paths).
    if (pairing_ui.code_was_emitted) {
        this->note_clear_pairing_code();
    }
    if (pairing_ui.window_was_shown) {
        this->note_close_pairing_window();
    }

    // 7. Deliver the clear callbacks the cleanup queued, now rather than on a loop() tick that is
    //    not coming. Every getter already reports the stopped state, so a callback that reads
    //    the client sees exactly what a caller sees once stop() returns.
    this->drain_inbox();

    this->lifecycle_.store(LifecycleState::STOPPED, std::memory_order_release);
}

PairingUiSnapshot SendspinClient::close_transports() {
    // 1. Ask the artwork and visualizer threads to exit now, so a slow on_image_decode() or a
    //    parked drain overlaps the transport teardown instead of following it. The visualizer's
    //    frames stay on its list until its join; the player keeps running, returning the items
    //    it plays, so a transport waiting for ring space is never parked behind a stopped
    //    consumer.
    this->signal_drain_role_stops();

    // 2. Close admission before the join, so the protocol task's next tick (at the latest its
    //    final one) runs the shutdown pass and refuses every accept with a goodbye.
    this->connection_manager_->close_admission();

    // 3. The protocol task: its final tick acts on the commands queued so far (refusing every
    //    accept with a shutdown goodbye), runs the shutdown pass (detach every connection,
    //    goodbye each with reason shutdown, wait up to the flush bound), then the join.
    this->protocol_task_->stop();

    // An accept the server delivered after the final tick waits in the queue. With the task
    // joined the manager is this thread's: refuse it the same way, then wait out its goodbye.
    // Closing accepts under the queue lock makes the hand-off atomic: an accept is either already
    // queued, and taken below, or refused at its push on the delivering thread, which detaches
    // it; none can slip in behind this pass with an attached gate.
    this->protocol_task_->close_accepts();
    ProtocolCommand command;
    while (this->protocol_task_->take_command(command)) {
        if (command.type == ProtocolCommandType::ACCEPT_CONNECTION &&
            command.connection != nullptr) {
            this->connection_manager_->refuse_accept(std::move(command.connection));
        }
    }
    this->connection_manager_->flush_shutdown_goodbyes();

    // 4. Close every transport the shutdown pass kept and stop the server, joining every
    //    transport thread, then release those connections here.
    const PairingUiSnapshot pairing_ui = this->connection_manager_->finish_stop();

    // Commands a consumer pushed meanwhile are dropped here, outside any run.
    this->protocol_task_->drop_commands();
    return pairing_ui;
}

void SendspinClient::signal_drain_role_stops() {
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->signal_stop();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->signal_stop();
    }
#endif
}

void SendspinClient::stop_role_threads() {
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->stop();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->stop();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->stop();
    }
#endif
}

bool SendspinClient::create_inbound_ring() {
    InboundRingBudget budget;
    budget.time_burst_size = this->config_.time_burst_size;
    budget.time_burst_interval_ms = this->config_.time_burst_interval_ms;
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        budget.audio_hold_bytes = this->player_->impl_->config.audio_buffer_capacity;
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        budget.visualizer_hold_bytes = this->visualizer_->impl_->visualizer_support.buffer_capacity;
        budget.visualizer_stored_bytes_per_second =
            this->visualizer_->impl_->stored_frame_bytes_per_second();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        for (const auto& slot : this->artwork_->impl_->config.preferred_formats) {
            budget.artwork_images_stored_bytes += inbound_frames_stored_bytes(slot.max_image_bytes);
        }
    }
#endif
    const size_t storage_bytes = derive_inbound_ring_bytes(budget);
    auto ring = std::make_unique<InboundRing>();
    if (!ring->create(storage_bytes, this->config_.inbound_ring_location)) {
        return false;
    }
    ring->quota(InboundHolder::PLAYER).set_limit(budget.audio_hold_bytes);
    ring->quota(InboundHolder::VISUALIZER).set_limit(budget.visualizer_hold_bytes);
    SS_LOGD(TAG, "Inbound ring: %zu bytes", storage_bytes);
    this->inbound_ring_ = std::move(ring);
    return true;
}

void SendspinClient::release_inbound_ring() {
    if (this->inbound_ring_ == nullptr) {
        return;
    }
    this->inbound_ring_->reset();
    this->inbound_ring_.reset();
}

void SendspinClient::connect_to(const std::string& url) {
    // Running implies start() succeeded, so identity_ and record_store_ exist for the protocol
    // task to hand to init_noise_handshake() once the WebSocket upgrade completes; a connection
    // built before that would dereference null there.
    if (!this->is_started()) {
        SS_LOGW(TAG, "connect_to() ignored: client is not running");
        return;
    }
    ProtocolCommand command;
    command.type = ProtocolCommandType::CONNECT_TO;
    command.text = url;
    (void)this->protocol_task_->push_command(std::move(command));
}

void SendspinClient::disconnect(SendspinGoodbyeReason reason) {
    // A stopped client has nothing to disconnect, and inside stop() the shutdown pass is already
    // goodbying every peer.
    if (!this->is_started()) {
        SS_LOGD(TAG, "disconnect() ignored: client is not running");
        return;
    }
    ProtocolCommand command;
    command.type = ProtocolCommandType::DISCONNECT;
    command.reason = reason;
    (void)this->protocol_task_->push_command(std::move(command));
}

void SendspinClient::loop() {
    // A stopped client is quiescent: no connections, no threads, nothing to deliver.
    if (!this->is_started()) {
        return;
    }
    this->drain_inbox();
}

void SendspinClient::request_persist() {
    this->event_state_->persist_slot.merge(
        [](PersistRequest& current, PersistRequest&& delta) {
            if (delta.last_played.has_value()) {
                current.last_played = std::move(delta.last_played);
            }
        },
        PersistRequest{});
}

void SendspinClient::flush_pending_persistence() {
    // Lock-free when nothing is owed.
    if ((this->event_state_->inbox.poll() & INBOX_TOPIC_PERSIST) == 0) {
        return;
    }
    PersistRequest owed;
    if (!this->event_state_->persist_slot.take(owed)) {
        return;
    }
    // persist_records() logs the durability warning itself on a rejected write, so the return
    // value is ignored.
    if (this->record_store_ != nullptr) {
        this->record_store_->persist_records();
    }
    if (owed.last_played.has_value()) {
        this->write_last_played_server(owed.last_played.value());
    }
}

void SendspinClient::request_high_performance(bool acquire) {
    HighPerformanceRequests delta;
    if (acquire) {
        delta.acquires = 1;
    } else {
        delta.releases = 1;
    }
    this->event_state_->high_performance_slot.merge(
        [](HighPerformanceRequests& current, HighPerformanceRequests&& added) {
            // A saturated count means the main loop stopped draining: the platform stays pinned
            // in whichever mode it was in, which the drain cannot repair, so the excess is
            // dropped rather than logged under the Inbox mutex.
            (void)add_saturating(current.acquires, added.acquires);
            (void)add_saturating(current.releases, added.releases);
        },
        delta);
}

void SendspinClient::apply_high_performance_requests() {
    HighPerformanceRequests requests;
    if (!this->event_state_->high_performance_slot.take(requests)) {
        return;
    }
    // Acquires first: a burst that both started and finished since the last drain must reach
    // the listener as a request followed by its release, never a release of nothing.
    for (uint8_t i = 0; i < requests.acquires; ++i) {
        this->acquire_high_performance();
    }
    for (uint8_t i = 0; i < requests.releases; ++i) {
        this->release_high_performance();
    }
}

void SendspinClient::post_time_sync_error(double error) {
    this->event_state_->time_sync_slot.write(error);
}

void SendspinClient::complete_role_teardowns() {
    // Each role's cleanup() runs on the protocol task and leaves the state only the main loop
    // touches for this half. The generation is loaded here, ahead of the events and slots the
    // drain takes below, so a teardown that ran before them is always caught up before the state
    // that follows it is applied. A stamped event of a newer teardown catches up again at its
    // dispatch (see the event drain).
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->catch_up_teardown(
            this->player_->impl_->cleanup_generation.load(std::memory_order_acquire));
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_) {
        this->controller_->impl_->catch_up_teardown(
            this->controller_->impl_->cleanup_generation.load(std::memory_order_acquire));
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_) {
        this->metadata_->impl_->catch_up_teardown(
            this->metadata_->impl_->cleanup_generation.load(std::memory_order_acquire));
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_) {
        this->color_->impl_->catch_up_teardown(
            this->color_->impl_->cleanup_generation.load(std::memory_order_acquire));
    }
#endif
}

void SendspinClient::drain_inbox() {
    // The main-loop halves of the teardowns the protocol task ran since the last drain.
    this->complete_role_teardowns();

    // Process deferred events: all state mutations and user callbacks happen here, on the main
    // loop thread, to avoid cross-thread data races. Two poll() snapshots gate the work below:
    // inbox_bits (here) gates the high-performance requests, the provider writes, the time-sync
    // report and the event-ring drain immediately following it; slot_bits (taken after that drain
    // completes, below) gates the pairing notes, the role drains and the group-update drain, since
    // a slot can be written by a producer between this snapshot and that one.
    const uint32_t inbox_bits = this->event_state_->inbox.poll();

    // --- High-performance requests (time bursts) ---
    if (inbox_bits & INBOX_TOPIC_HIGH_PERFORMANCE) {
        this->apply_high_performance_requests();
    }

    // --- Deferred provider writes ---
    // Ahead of the pairing-note dispatch below, so on_pairing_succeeded finds the record
    // committed.
    if (inbox_bits & INBOX_TOPIC_PERSIST) {
        this->flush_pending_persistence();
    }

    // --- Time sync report ---
    if (inbox_bits & INBOX_TOPIC_TIME) {
        double error = 0.0;
        if (this->event_state_->time_sync_slot.take(error) && this->listener_ != nullptr) {
            this->listener_->on_time_sync_updated(static_cast<float>(error));
        }
    }

    // --- Lifecycle events ---
    if (inbox_bits & INBOX_TOPIC_EVENTS) {
        // Drain in small batches to bound the stack cost on the shared main-loop task. A batch that
        // comes back partial means the ring is empty, ending the loop; events pushed mid-drain are
        // still delivered this tick as long as full batches keep arriving. Sized as a fraction of
        // the ring so the batch/ring ratio (and the stack cost above) tracks EVENT_CAPACITY
        // automatically.
        constexpr size_t EVENT_DRAIN_BATCH_SIZE = Inbox::EVENT_CAPACITY / 4;
        InboxEvent events[EVENT_DRAIN_BATCH_SIZE];
        size_t event_count = 0;
        // Snapshot the drain generation: a dispatched event below can run a listener callback
        // that calls stop(), whose teardown bumps the counter and wipes the ring. Events already
        // copied into the local batch are stale at that point and must be dropped, exactly as
        // the ring reset intended.
        const uint32_t drain_generation = this->event_state_->drain_generation;
        bool drain_aborted = false;
        do {
            event_count = this->event_state_->inbox.take_events(events, EVENT_DRAIN_BATCH_SIZE);
            for (size_t i = 0; i < event_count; ++i) {
                if (this->event_state_->drain_generation != drain_generation) {
                    drain_aborted = true;
                    break;
                }
                const InboxEvent& event = events[i];
                // Every event is stamped with its role's teardown generation. A current one may
                // belong to a teardown the protocol task ran after complete_role_teardowns()
                // loaded the generation, so the role catches up on it before acting: the reset
                // lands ahead of what the event starts.
                switch (event.type) {
                    // Stream lifecycle events from the player role, appended to
                    // awaiting_sync_idle_events (the sync-idle gate itself is untouched).
                    // Client-state updates from the sync task travel via the player's
                    // latest-wins state slot, not this ring; see PlayerRole::Impl::EventState.
                    case InboxEventType::PLAYER_STREAM: {
#ifdef SENDSPIN_ENABLE_PLAYER
                        if (this->player_ &&
                            event_is_current(event.epoch,
                                             this->player_->impl_->cleanup_generation.load(
                                                 std::memory_order_acquire),
                                             TAG, "a player stream event")) {
                            this->player_->impl_->catch_up_teardown(event.epoch);
                            this->player_->impl_->on_stream_ring_event(
                                static_cast<PlayerStreamCallbackType>(event.code));
                        }
#endif
                        break;
                    }
                    // CONTROLLER_CLEARED / METADATA_CLEARED / COLOR_CLEARED: pushed by each role's
                    // cleanup(). A role removed, re-added and removed again between two drains
                    // queues two. The callbacks are idempotent by contract (see
                    // on_controller_state_clear() / on_metadata_clear() / on_color_clear()), so an
                    // older one is still delivered; only a current one catches the role up.
                    case InboxEventType::CONTROLLER_CLEARED: {
#ifdef SENDSPIN_ENABLE_CONTROLLER
                        if (this->controller_) {
                            if (event.epoch == this->controller_->impl_->cleanup_generation.load(
                                                   std::memory_order_acquire)) {
                                this->controller_->impl_->catch_up_teardown(event.epoch);
                            }
                            this->controller_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    case InboxEventType::METADATA_CLEARED: {
#ifdef SENDSPIN_ENABLE_METADATA
                        if (this->metadata_) {
                            if (event.epoch == this->metadata_->impl_->cleanup_generation.load(
                                                   std::memory_order_acquire)) {
                                this->metadata_->impl_->catch_up_teardown(event.epoch);
                            }
                            this->metadata_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    case InboxEventType::COLOR_CLEARED: {
#ifdef SENDSPIN_ENABLE_COLOR
                        if (this->color_) {
                            if (event.epoch == this->color_->impl_->cleanup_generation.load(
                                                   std::memory_order_acquire)) {
                                this->color_->impl_->catch_up_teardown(event.epoch);
                            }
                            this->color_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    // ARTWORK_STREAM / VISUALIZER_STREAM: code is the role-local
                    // ArtworkEventType/VisualizerEventType. Neither role keeps main-loop state a
                    // teardown must reset ahead of its events: the artwork STREAM_END is that
                    // reset.
                    case InboxEventType::ARTWORK_STREAM: {
#ifdef SENDSPIN_ENABLE_ARTWORK
                        if (this->artwork_ &&
                            event_is_current(event.epoch,
                                             this->artwork_->impl_->cleanup_generation.load(
                                                 std::memory_order_acquire),
                                             TAG, "an artwork stream event")) {
                            this->artwork_->impl_->handle_stream_ring_event(
                                static_cast<ArtworkEventType>(event.code));
                        }
#endif
                        break;
                    }
                    case InboxEventType::VISUALIZER_STREAM: {
#ifdef SENDSPIN_ENABLE_VISUALIZER
                        if (this->visualizer_ &&
                            event_is_current(event.epoch,
                                             this->visualizer_->impl_->cleanup_generation.load(
                                                 std::memory_order_acquire),
                                             TAG, "a visualizer stream event")) {
                            this->visualizer_->impl_->handle_stream_ring_event(
                                static_cast<VisualizerEventType>(event.code));
                        }
#endif
                        break;
                    }
                    default: {
                        // Guards only against a corrupted enum value.
                        SS_LOGD(TAG, "Unhandled inbox event type: %d",
                                static_cast<int>(event.type));
                        break;
                    }
                }
            }
            // A stop() that re-entered on the final event of a full batch bumps the drain
            // generation but leaves drain_aborted false: the check at the top of the inner loop
            // never runs again because there is no next iteration. Re-check here so the loop stops
            // instead of calling take_events() again and destructively pulling the cleanup's
            // freshly re-pushed CLEARED/STREAM_END events off the live ring (dropping them).
            if (this->event_state_->drain_generation != drain_generation) {
                drain_aborted = true;
            }
        } while (!drain_aborted && event_count == EVENT_DRAIN_BATCH_SIZE);
    }

    // Second snapshot: catches topic bits a producer set while the ring drain above was running.
    // Gates the pairing notes, the role drains and the group drain below; see the inbox_bits
    // comment above for the staleness argument, which applies identically here.
    const uint32_t slot_bits = this->event_state_->inbox.poll();

    // --- Pairing/trust notifications ---
    if (slot_bits & INBOX_TOPIC_PAIRING) {
        auto& es = *this->event_state_;
        std::vector<PairingNote> notes;
        if (es.pairing_slot.take(notes) && this->listener_ != nullptr) {
            // Same staleness rule as the ring drain above.
            const uint32_t note_generation = es.drain_generation;
            // Set when a re-entrant stop() bumps the generation, abandoning the rest of the
            // batch.
            bool notes_aborted = false;
            // Grouped by type in PairingNoteType declaration order, not queue order, firing
            // coalesced types at most once; see the enum and is_coalesced_note(). The listener
            // is set before start() and must outlive the client (see set_listener), so it cannot
            // become null mid-dispatch.
            for (uint8_t i = 0; i < static_cast<uint8_t>(PairingNoteType::COUNT) && !notes_aborted;
                 ++i) {
                const auto type = static_cast<PairingNoteType>(i);
                for (const PairingNote& note : notes) {
                    if (note.type != type) {
                        continue;
                    }
                    switch (type) {
                        case PairingNoteType::PAIRING_STARTED:
                            this->listener_->on_pairing_started(note.text);
                            break;
                        case PairingNoteType::PAIRING_SUCCEEDED:
                            this->listener_->on_pairing_succeeded(note.text);
                            break;
                        case PairingNoteType::TRUST_CHANGED:
                            this->listener_->on_trust_changed(note.trust);
                            break;
                        case PairingNoteType::PAIRING_FAILED:
                            this->listener_->on_pairing_failed(note.text, note.reason);
                            break;
                        case PairingNoteType::DISPLAY_PAIRING_CODE:
                            this->listener_->on_display_pairing_code(note.text, note.format);
                            break;
                        case PairingNoteType::CLEAR_PAIRING_CODE:
                            this->listener_->on_clear_pairing_code();
                            break;
                        case PairingNoteType::OPEN_PAIRING_WINDOW:
                            this->listener_->on_open_pairing_window();
                            break;
                        case PairingNoteType::CLOSE_PAIRING_WINDOW:
                            this->listener_->on_close_pairing_window();
                            break;
                        case PairingNoteType::COUNT:
                            // Unreachable: the walk above stops before COUNT.
                            break;
                    }
                    if (es.drain_generation != note_generation) {
                        notes_aborted = true;
                        break;
                    }
                    if (is_coalesced_note(type)) {
                        break;
                    }
                }
            }
        }
    }

    // --- Role events: bit-gated so an idle tick performs zero inbox mutex acquisitions here ---
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_ && this->player_->impl_->needs_drain(slot_bits)) {
        this->player_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_ && this->controller_->impl_->needs_drain(slot_bits)) {
        this->controller_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_ && this->metadata_->impl_->needs_drain(slot_bits)) {
        this->metadata_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_ && this->color_->impl_->needs_drain(slot_bits)) {
        this->color_->impl_->drain_events();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_ && this->artwork_->impl_->needs_drain(slot_bits)) {
        this->artwork_->impl_->drain_events();
    }
#endif

    // --- Group update events ---
    if (slot_bits & INBOX_TOPIC_GROUP) {
        GroupUpdateObject group_delta;
        if (this->event_state_->group_slot.take(group_delta)) {
            apply_group_update_deltas(&this->group_state_, group_delta);

            if (this->listener_) {
                this->listener_->on_group_update(group_delta);
            }

            SS_LOGD(TAG, "Group update - state: %s, id: %s, name: %s",
                    this->group_state_.playback_state.has_value()
                        ? to_cstr(this->group_state_.playback_state.value())
                        : "unchanged",
                    this->group_state_.group_id.value_or("").c_str(),
                    this->group_state_.group_name.value_or("").c_str());
        }
    }
}

// ============================================================================
// Role registration (call before start())
// ============================================================================

#ifdef SENDSPIN_ENABLE_PLAYER
PlayerRole& SendspinClient::add_player(PlayerRoleConfig config) {
    if (this->lifecycle_.load(std::memory_order_relaxed) != LifecycleState::STOPPED) {
        SS_LOGW(TAG, "add_player() called while started; role may not initialize correctly");
    }
    this->player_ = std::make_unique<PlayerRole>(std::move(config), this);
    // start() refreshes it; set here so a delay the consumer sets before start() is saved.
    this->player_->impl_->persistence = this->persistence_provider_;
    this->player_->impl_->attach_inbox(this->event_state_->inbox);
    this->player_->impl_->discard_audio.store(!this->available_, std::memory_order_relaxed);
    return *this->player_;
}
#endif

#ifdef SENDSPIN_ENABLE_CONTROLLER
ControllerRole& SendspinClient::add_controller() {
    if (this->lifecycle_.load(std::memory_order_relaxed) != LifecycleState::STOPPED) {
        SS_LOGW(TAG, "add_controller() called while started");
    }
    this->controller_ = std::make_unique<ControllerRole>(this);
    this->controller_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->controller_;
}
#endif

#ifdef SENDSPIN_ENABLE_METADATA
MetadataRole& SendspinClient::add_metadata() {
    if (this->lifecycle_.load(std::memory_order_relaxed) != LifecycleState::STOPPED) {
        SS_LOGW(TAG, "add_metadata() called while started");
    }
    this->metadata_ = std::make_unique<MetadataRole>(this);
    this->metadata_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->metadata_;
}
#endif

#ifdef SENDSPIN_ENABLE_COLOR
// cppcheck-suppress unusedFunction
// Public API: a live entry point the bundled examples do not exercise.
ColorRole& SendspinClient::add_color() {
    if (this->lifecycle_.load(std::memory_order_relaxed) != LifecycleState::STOPPED) {
        SS_LOGW(TAG, "add_color() called while started");
    }
    this->color_ = std::make_unique<ColorRole>(this);
    this->color_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->color_;
}
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
// cppcheck-suppress unusedFunction
// Public API: a live entry point the bundled examples do not exercise.
ArtworkRole& SendspinClient::add_artwork(ArtworkRoleConfig config) {
    if (this->lifecycle_.load(std::memory_order_relaxed) != LifecycleState::STOPPED) {
        SS_LOGW(TAG, "add_artwork() called while started");
    }
    this->artwork_ = std::make_unique<ArtworkRole>(std::move(config), this);
    this->artwork_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->artwork_;
}
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
VisualizerRole& SendspinClient::add_visualizer(VisualizerRoleConfig config) {
    if (this->lifecycle_.load(std::memory_order_relaxed) != LifecycleState::STOPPED) {
        SS_LOGW(TAG, "add_visualizer() called while started");
    }
    this->visualizer_ = std::make_unique<VisualizerRole>(std::move(config), this);
    this->visualizer_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->visualizer_;
}
#endif

// ============================================================================
// Queries
// ============================================================================

std::optional<std::string> SendspinClient::format_pairing_token(
    const std::array<uint8_t, 32>& pairing_psk) const {
    if (this->identity_ == nullptr) {
        return std::nullopt;
    }
    return sendspin::format_pairing_token(this->identity_->public_bytes, pairing_psk);
}

std::optional<std::string> SendspinClient::pairing_token() const {
    // Main-loop-only, like the other record-store config reads: the Pairing PSK is set when the
    // store is built, inside start().
    if (this->record_store_ == nullptr) {
        return std::nullopt;
    }
    const auto& pairing_psk = this->record_store_->pairing_psk();
    if (!pairing_psk.has_value()) {
        return std::nullopt;
    }
    return this->format_pairing_token(pairing_psk->psk);
}

bool SendspinClient::is_connected() const {
    return this->connection_manager_->is_connected();
}

bool SendspinClient::is_time_synced() const {
    // See ConnectionManager::time_filter().
    auto filter = this->connection_manager_->time_filter();
    return filter != nullptr && filter->has_update();
}

int64_t SendspinClient::get_client_time(int64_t server_time) const {
    // See ConnectionManager::time_filter().
    auto filter = this->connection_manager_->time_filter();
    return filter != nullptr ? filter->compute_client_time(server_time) : 0;
}

std::optional<ServerInformationObject> SendspinClient::get_server_information() const {
    return this->connection_manager_->server_information();
}

// ============================================================================
// State updates
// ============================================================================

void SendspinClient::set_available(bool available) {
    if (available == this->available_) {
        return;
    }
    this->available_ = available;
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->discard_audio.store(!available, std::memory_order_relaxed);
    }
#endif
    this->publish_state();
}

void SendspinClient::leave() {
    // messaging.md "client/leave". Not a role message, so it does not route through send_text().
    // The protocol task applies the activation gate every outbound message has
    // (ConnectionManager::leave()).
    if (!this->is_started()) {
        SS_LOGW(TAG, "client/leave ignored: client is not running");
        return;
    }
    ProtocolCommand command;
    command.type = ProtocolCommandType::LEAVE;
    (void)this->protocol_task_->push_command(std::move(command));
}

// ============================================================================
// Role services (called by roles via SendspinClient pointer)
// ============================================================================

void SendspinClient::publish_state() {
    // Inside stop() the connections are being goodbyed and a restart publishes its own first
    // snapshot (start()).
    if (!this->is_started()) {
        return;
    }
    this->protocol_task_->publish_state(this->build_client_state());
}

ClientStateMessage SendspinClient::build_client_state() const {
    ClientStateMessage state_msg;
    state_msg.available = this->available_;

    // Every role's object: the protocol task sends each admitted connection the objects of the
    // roles it owns and has active (client_state_for_roles()).
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->build_state_fields(state_msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->build_state_fields(state_msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->build_state_fields(state_msg);
    }
#endif
    return state_msg;
}

bool SendspinClient::send_text(const std::string& text, const std::string& role_family) {
    // Single choke point for every role-originated send (controller commands). Pairing messages
    // are protocol-internal: connection_manager.cpp sends them via
    // SendspinConnection::send_app_json() directly. A declared PAIRING activity is not a gate:
    // pairing.md "Entering and leaving pairing" says an activate that adds it does not by itself
    // affect active_roles, so an active role keeps driving its own traffic across the attempt.
    if (!this->is_started()) {
        SS_LOGD(TAG, "Dropping a %s message: client is not running", role_family.c_str());
        return false;
    }
    // The family names the role this library implements; the protocol task tests ownership and
    // the exact versioned name on the owning connection (ConnectionManager::send_role_text()).
    const std::optional<SendspinRole> role = role_for_family(role_family);
    if (!role.has_value()) {
        SS_LOGD(TAG, "Dropping a %s message: no such role", role_family.c_str());
        return false;
    }
    ProtocolCommand command;
    command.type = ProtocolCommandType::SEND_TEXT;
    command.role = role.value();
    command.text = text;
    return this->protocol_task_->push_command(std::move(command));
}

void SendspinClient::acquire_high_performance() {
    if (this->high_performance_ref_count_.fetch_add(1) == 0 && this->listener_) {
        this->listener_->on_request_high_performance();
    }
}

void SendspinClient::release_high_performance() {
    // Compare-exchange loop so a release at count 0 cannot underflow the counter.
    uint8_t count = this->high_performance_ref_count_.load();
    while (count != 0) {
        if (this->high_performance_ref_count_.compare_exchange_weak(count, count - 1)) {
            if (count == 1 && this->listener_) {
                this->listener_->on_release_high_performance();
            }
            return;
        }
    }
}

// ============================================================================
// Private helpers
// ============================================================================

void SendspinClient::cleanup_connection_state(uint16_t teardown_roles) {
    SS_LOGV(TAG, "Cleaning up connection state (roles 0x%04x)", teardown_roles);

    // Client-wide connection state belongs to the primary connection, so it is reset only when
    // the teardown covers every role, which is when no admitted connection is left to own one.
    // A narrower teardown (a connection that owned a subset while another stays admitted) leaves
    // the survivor's events, group and time-sync report in place.
    if (teardown_roles == ALL_ROLES_MASK) {
        // A second teardown before the main loop drains (a handoff chain can displace two
        // connections in one tick) wipes the first teardown's just-pushed CLEARED/STREAM_END
        // events here before they are ever drained. That is safe only because every role's
        // cleanup() below pushes its full event set unconditionally, re-creating exactly what
        // this wiped. Keep role cleanups unconditional or this reset starts losing clear signals.
        this->event_state_->inbox.reset_events();
        this->event_state_->group_slot.reset();
        this->event_state_->time_sync_slot.reset();

        // Also wipes any not-yet-dispatched pairing listener notifications. Callers that need a
        // notification to survive teardown (e.g. handle_pair_abort's on_pairing_failed /
        // on_clear_pairing_code) must call the corresponding note_*() after
        // cleanup_connection_state() returns; see the ConnectionManager pairing handlers.
        this->event_state_->pairing_slot.reset();

        // The trust level is per-connection state: with no active connection there is nothing to
        // trust, so the getter reports NONE until the next handshake completes.
        this->current_trust_.store(ConnectionTrust::NONE, std::memory_order_release);
    }

#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_ && (teardown_roles & role_mask_bit(SendspinRole::PLAYER)) != 0) {
        this->player_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_ && (teardown_roles & role_mask_bit(SendspinRole::CONTROLLER)) != 0) {
        this->controller_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_ && (teardown_roles & role_mask_bit(SendspinRole::METADATA)) != 0) {
        this->metadata_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_ && (teardown_roles & role_mask_bit(SendspinRole::COLOR)) != 0) {
        this->color_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_ && (teardown_roles & role_mask_bit(SendspinRole::ARTWORK)) != 0) {
        this->artwork_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_ && (teardown_roles & role_mask_bit(SendspinRole::VISUALIZER)) != 0) {
        this->visualizer_->impl_->cleanup();
    }
#endif

    // The protocol task recalls the items the torn-down stream roles' consumers have not taken
    // (on its own next tick when this runs on it).
    this->protocol_task_->wake();
}

std::string SendspinClient::build_hello_message() {
    // Reached only from ConnectionManager::send_hello_message(), so only for a connection, so
    // only after a successful start(): record_store_ exists and is dereferenced unguarded below.
    ClientHelloMessage msg;
    msg.name = this->config_.name;

    // Use the explicitly configured MAC when provided; otherwise fall back to platform detection
    // (reliable on ESP, best-effort on host). Leaves the field absent if neither is available.
    const std::optional<std::string> interface_mac =
        this->config_.mac_address ? this->config_.mac_address : platform_get_interface_mac();

    DeviceInfoObject device_info{};
    device_info.product_name = this->config_.product_name;
    device_info.manufacturer = this->config_.manufacturer;
    device_info.software_version = this->config_.software_version;
    device_info.mac_address = interface_mac;
    msg.device_info = device_info;

    // pairing.md "client/hello pair-method descriptor". offers_*() is the single source both this
    // and the server/activate admissibility check read, so a method advertised here is one an
    // activation can select. pairing_psk is always advertised (see pairing_offers.h).
    {
        PairMethodDescriptor psk_desc;
        psk_desc.method = SendspinPairMethod::PAIRING_PSK;
        psk_desc.locations = locations_hint(this->config_.pairing_psk_locations);
        msg.supported_pair_methods.push_back(std::move(psk_desc));
    }
    // out_channels and formats are both required and non-empty. No `locations`: a per-session code
    // has no resting place for the operator to look it up in.
    if (offers_dynamic_pairing_code(this->config_)) {
        PairMethodDescriptor dynamic_desc;
        dynamic_desc.method = SendspinPairMethod::DYNAMIC_PAIRING_CODE;
        dynamic_desc.out_channels = this->config_.pairing_code_out_channels;
        dynamic_desc.formats = this->config_.pairing_code_formats;
        msg.supported_pair_methods.push_back(std::move(dynamic_desc));
    }
    // Offered only when the dynamic code is not: messaging.md "client/hello" permits at most one
    // pairing-code method.
    if (offers_static_pairing_code(this->config_)) {
        PairMethodDescriptor static_desc;
        static_desc.method = SendspinPairMethod::STATIC_PAIRING_CODE;
        static_desc.locations = locations_hint(this->config_.static_pairing_code_locations);
        msg.supported_pair_methods.push_back(std::move(static_desc));
    }

    msg.unpaired_access_enabled = this->unpaired_access_enabled_.load(std::memory_order_acquire);

    // Let each role add its fields to the hello message
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_) {
        this->controller_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_) {
        this->metadata_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_) {
        this->color_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->build_hello_fields(msg);
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->build_hello_fields(msg);
    }
#endif

    return format_client_hello_message(&msg);
}

// ============================================================================
// Message processing
// ============================================================================
// Protocol task
// ============================================================================

uint32_t SendspinClient::protocol_tick() {
    ConnectionManager& manager = *this->connection_manager_;

    // 1. Commands, in the order they were queued. Each command's resources (a connection, a
    //    lease) are released as the next take replaces it.
    {
        ProtocolCommand command;
        while (this->protocol_task_->take_command(command)) {
            this->handle_command(command);
        }
    }

    // 2. Once admission is closed: the shutdown pass, and the bounded wait for the goodbyes the
    //    commands above refused. Every slot is empty afterwards, so the steps below find no
    //    connection and the ring pass only returns the items still in flight.
    if (manager.shutdown_pending()) {
        manager.shutdown();
    } else {
        manager.flush_shutdown_goodbyes();
    }

    // 3. The newest client/state snapshot, sent to every admitted connection it changes.
    {
        ClientStateMessage snapshot;
        if (this->protocol_task_->take_state(snapshot)) {
            this->task_state_->client_state = std::move(snapshot);
            manager.for_each_admitted(
                [this](AdmittedEntry& entry) { this->publish_client_state(entry.conn.get()); });
        }
    }

    // 4. A role torn down since the last tick hands back what its consumer has not taken
    //    (InboundItemList::recall()); the consumer returns what it holds itself.
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->recall_stale_items(
            this->player_->impl_->cleanup_generation.load(std::memory_order_acquire));
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->recall_stale_items(
            this->visualizer_->impl_->cleanup_generation.load(std::memory_order_acquire));
    }
#endif

    // 5. client/init on the outbound connections whose upgrade completed: the server says
    //    nothing before it, so it goes ahead of the receive pass.
    manager.start_upgraded_handshakes();

    // 6. The receive pass, over a snapshot of the managed connections: a handler below can drop
    //    a connection from its slot, and the snapshot keeps it alive until the tick ends (see
    //    ConnectionManager::snapshot_connections()). Each connection's pending pre-admission
    //    message comes before its ring items: a connection has no ring item queued while a
    //    pending message waits (InboundGate).
    ConnectionManager::ConnectionSnapshot connections;
    manager.snapshot_connections(connections);
    for (auto& conn : connections) {
        InboundMessage message;
        if (!conn->pending_message(message)) {
            continue;
        }
        if (!conn->inbound_gate().is_detached()) {
            this->process_inbound(*conn, message);
        }
        conn->consume_pending_message();
    }

    // The ring, in arrival order across connections. Bounded per tick so the steps around it (a
    // command, a pending pre-admission message, a close report, a timer) come round again while
    // a stream keeps the ring busy: an audio or visualizer item costs microseconds to hand over,
    // so 32 of them delay those steps by well under a millisecond, while 32 still covers 0.6 s
    // of 20 ms audio chunks in one pass. The tick asks to run again at once when it stops here.
    constexpr size_t MAX_ITEMS_PER_TICK = 32;
    bool ring_drained = true;
    for (size_t taken = 0;; ++taken) {
        if (taken == MAX_ITEMS_PER_TICK) {
            ring_drained = false;
            break;
        }
        size_t item_len = 0;
        void* item = this->inbound_ring_->take(&item_len, 0);
        if (item == nullptr) {
            break;
        }
        const InboundItemHeader* header = inbound_item_header(item);
        SendspinConnection* conn = nullptr;
        for (auto& candidate : connections) {
            if (static_cast<uint32_t>(candidate->get_instance_id()) == header->connection_id) {
                conn = candidate.get();
                break;
            }
        }
        if (conn == nullptr) {
            // The connection left the manager since it wrote the item.
            this->inbound_ring_->return_item(item);
            continue;
        }
        conn->inbound_gate().note_item_taken();
        if (conn->inbound_gate().is_detached()) {
            this->inbound_ring_->return_item(item);
            continue;
        }
        InboundMessage message;
        message.item = item;
        message.item_len = item_len;
        message.data = inbound_item_bytes(item);
        message.len = item_len;
        message.receive_time_us = header->receive_time_us;
        message.kind = header->kind;
        this->process_inbound(*conn, message);
    }

    // 7. Losses: a connection the receive path closed, one the manager released, or one whose
    //    transport closed with every message it sent before the close processed, is dropped once
    //    (a connection the manager no longer manages is a no-op there).
    for (auto& conn : connections) {
        InboundGate& gate = conn->inbound_gate();
        if ((gate.is_detached() || gate.close_ready()) && conn->mark_loss_reported()) {
            manager.on_connection_lost(conn.get());
        }
    }

    // 8. The lifecycle scans and timers, 9. the time bursts, 10. what other threads read.
    uint32_t next_deadline = manager.tick(platform_time_us());
    next_deadline = std::min(next_deadline, manager.run_time_sync());
    manager.refresh_published_state();
    if (!ring_drained) {
        next_deadline = 0;
    }
    // The snapshot's references drop here; see ConnectionManager::snapshot_connections().
    return next_deadline;
}

void SendspinClient::handle_command(ProtocolCommand& command) {
    ConnectionManager& manager = *this->connection_manager_;
    switch (command.type) {
        case ProtocolCommandType::ACCEPT_CONNECTION:
            if (command.connection != nullptr) {
                manager.accept(std::move(command.connection));
            }
            return;
        case ProtocolCommandType::CONNECT_TO:
        case ProtocolCommandType::DISCONNECT:
        case ProtocolCommandType::LEAVE:
        case ProtocolCommandType::PAIRING_WINDOW_CANCEL:
        case ProtocolCommandType::PAIRING_WINDOW_CONFIRM:
        case ProtocolCommandType::SEND_TEXT:
        case ProtocolCommandType::SET_UNPAIRED_ACCESS:
            break;
    }
    // A consumer request that reaches the task once admission is closed belongs to a run that
    // is ending: the shutdown pass goodbyes every peer, so acting on it could only open or
    // address a connection that is about to be closed.
    if (!manager.is_accepting()) {
        SS_LOGD(TAG, "Dropping protocol command of type %d: the client is stopping",
                static_cast<int>(command.type));
        return;
    }
    switch (command.type) {
        case ProtocolCommandType::CONNECT_TO:
            manager.connect_to(command.text);
            break;
        case ProtocolCommandType::DISCONNECT:
            manager.disconnect(command.reason);
            break;
        case ProtocolCommandType::LEAVE:
            manager.leave();
            break;
        case ProtocolCommandType::PAIRING_WINDOW_CANCEL:
            manager.cancel_pairing_window();
            break;
        case ProtocolCommandType::PAIRING_WINDOW_CONFIRM:
            manager.confirm_pairing_window();
            break;
        case ProtocolCommandType::SEND_TEXT:
            manager.send_role_text(command.role, command.text);
            break;
        case ProtocolCommandType::SET_UNPAIRED_ACCESS:
            manager.apply_unpaired_access_change(command.enabled);
            break;
        case ProtocolCommandType::ACCEPT_CONNECTION:
            // Handled above.
            break;
    }
}

void SendspinClient::process_inbound(SendspinConnection& conn, InboundMessage& message) {
    conn.process_inbound_message(message);
    if (message.item != nullptr) {
        this->inbound_ring_->return_item(message.item);
        message.item = nullptr;
    }
}

void SendspinClient::report_malformed_pairing_message(SendspinConnection* conn,
                                                      const char* type_name) {
    SS_LOGW(TAG, "Malformed %s; aborting any active code pairing", type_name);
    ServerPairingMessage message;
    message.kind = PairingMessageKind::MALFORMED;
    this->connection_manager_->on_pairing_message(conn, message);
}

void SendspinClient::process_json_message(SendspinConnection* conn, const char* data, size_t len,
                                          int64_t timestamp) {
    // Every connection's messages are processed on the protocol task, one at a time, so the
    // shared arena, the parse and the handlers it dispatches to need no lock. Reusing the arena
    // is safe: the JsonDocument from the previous call was destroyed when that call returned.
    if (this->json_arena_) {
        this->json_arena_->reset();
    }
    JsonDocument doc =
        this->json_arena_ ? make_json_document(*this->json_arena_) : make_json_document();
    DeserializationError error = deserializeJson(doc, data, len);
    if (error || doc.isNull()) {
        SS_LOGW(TAG, "Failed to parse JSON message");
        return;
    }
    JsonObject root = doc.as<JsonObject>();

    SendspinServerToClientMessageType message_type = determine_message_type(root);

    // Role-bound traffic is gated per role on ownership (role_accepts_traffic()): only the
    // admitted connection that owns a role reaches it. The connection is not closed over a
    // message it may not act on: a nursery member that is still racing toward promotion, or one
    // that just lost arbitration, is not misbehaving, and the establish/re-prove watchdogs
    // already reap a connection that never gets admitted. The server/activate that admits a
    // connection is applied before the next message is parsed, so the role traffic behind it is
    // never dropped for lack of admission.
    switch (message_type) {
        case SendspinServerToClientMessageType::STREAM_START: {
            SS_LOGD(TAG, "Stream Started");

            StreamStartMessage stream_msg;
            if (!process_stream_start_message(root, &stream_msg)) {
                SS_LOGE(TAG, "Failed to parse stream/start message");
                break;
            }

#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_ && stream_msg.player.has_value() &&
                role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::PLAYER)) {
                this->player_->impl_->handle_stream_start(
                    stream_msg.player.value(),
                    this->player_->impl_->cleanup_generation.load(std::memory_order_acquire));
            }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
            if (this->artwork_ && stream_msg.artwork.has_value() &&
                role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::ARTWORK)) {
                this->artwork_->impl_->handle_stream_start(
                    stream_msg.artwork.value(),
                    this->artwork_->impl_->cleanup_generation.load(std::memory_order_acquire));
            }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
            if (this->visualizer_ && stream_msg.visualizer.has_value() &&
                role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::VISUALIZER)) {
                this->visualizer_->impl_->handle_stream_start(
                    stream_msg.visualizer.value(),
                    this->visualizer_->impl_->cleanup_generation.load(std::memory_order_acquire));
            }
#endif
            break;
        }
        case SendspinServerToClientMessageType::STREAM_END: {
            StreamEndMessage end_msg;
            if (process_stream_end_message(root, &end_msg)) {
                bool end_player = !end_msg.roles.has_value();
                bool end_artwork = !end_msg.roles.has_value();
                bool end_visualizer = !end_msg.roles.has_value();

                if (end_msg.roles.has_value()) {
                    for (const auto& role : end_msg.roles.value()) {
                        if (role == "player") {
                            end_player = true;
                        } else if (role == "artwork") {
                            end_artwork = true;
                        } else if (role == "visualizer") {
                            end_visualizer = true;
                        }
                    }
                }

                SS_LOGD(TAG, "Stream ended - player:%d artwork:%d visualizer:%d", end_player,
                        end_artwork, end_visualizer);

#ifdef SENDSPIN_ENABLE_PLAYER
                if (this->player_ && end_player &&
                    role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::PLAYER)) {
                    this->player_->impl_->handle_stream_end(
                        this->player_->impl_->cleanup_generation.load(std::memory_order_acquire));
                }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
                if (this->artwork_ && end_artwork &&
                    role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::ARTWORK)) {
                    this->artwork_->impl_->handle_stream_end(
                        this->artwork_->impl_->cleanup_generation.load(std::memory_order_acquire));
                }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
                if (this->visualizer_ && end_visualizer &&
                    role_accepts_traffic(*this->connection_manager_, conn,
                                         SendspinRole::VISUALIZER)) {
                    this->visualizer_->impl_->handle_stream_end(
                        this->visualizer_->impl_->cleanup_generation.load(
                            std::memory_order_acquire));
                }
#endif
            }
            break;
        }
        case SendspinServerToClientMessageType::STREAM_CLEAR: {
            StreamClearMessage clear_msg;
            if (process_stream_clear_message(root, &clear_msg)) {
                // messaging.md "stream/clear": only player and visualizer streams clear, and an
                // omitted roles list clears both.
                bool clear_player = !clear_msg.roles.has_value();
                bool clear_visualizer = !clear_msg.roles.has_value();

                if (clear_msg.roles.has_value()) {
                    for (const auto& role : clear_msg.roles.value()) {
                        if (role == "player") {
                            clear_player = true;
                        } else if (role == "visualizer") {
                            clear_visualizer = true;
                        }
                    }
                }

                SS_LOGD(TAG, "Stream clear - player:%d visualizer:%d", clear_player,
                        clear_visualizer);

#ifdef SENDSPIN_ENABLE_PLAYER
                if (this->player_ && clear_player &&
                    role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::PLAYER)) {
                    this->player_->impl_->handle_stream_clear(
                        this->player_->impl_->cleanup_generation.load(std::memory_order_acquire));
                }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
                if (this->visualizer_ && clear_visualizer &&
                    role_accepts_traffic(*this->connection_manager_, conn,
                                         SendspinRole::VISUALIZER)) {
                    this->visualizer_->impl_->handle_stream_clear(
                        this->visualizer_->impl_->cleanup_generation.load(
                            std::memory_order_acquire));
                }
#endif
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_HELLO: {
            ServerHelloMessage hello_msg;
            if (process_server_hello_message(root, &hello_msg)) {
                // server_id comes from the Noise handshake result (already set on the
                // connection); server/hello only carries the display name.
                if (conn != nullptr) {
                    ServerInformationObject info = conn->get_server_information();
                    info.name = hello_msg.name;
                    conn->set_server_information(std::move(info));
                    // The nursery scan on this task observes is_handshake_complete() and
                    // establishes the connection; nothing needs to be scheduled here.
                    conn->set_server_hello_received(true);

                    SS_LOGD(TAG, "Connected to server '%s' (server_id=%s)", hello_msg.name.c_str(),
                            conn->get_server_id().c_str());
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_ACTIVATE: {
            ServerActivateMessage activate_msg;
            if (process_server_activate_message(root, &activate_msg)) {
                if (conn != nullptr) {
                    SS_LOGD(TAG, "server/activate received (activities_count=%zu)",
                            activate_msg.activities.size());
                    // Applied before the next message is parsed: trust enforcement, role
                    // ownership and, for a nursery connection that is now operational, admission
                    // all land here, so the role traffic the server sends behind this activate
                    // meets the gate this activation set.
                    this->connection_manager_->on_server_activate(conn, std::move(activate_msg));
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::NOISE_HANDSHAKE: {
            // In-band re-handshake initiated by the server. This runs on the protocol task, the
            // thread that decrypts this connection's frames and sends on it, so the session swap
            // is ordered with the decrypt of the next frame and with every send
            // (connection.md "Re-handshake").
            if (conn != nullptr) {
                SS_LOGI(TAG, "noise/handshake received in-band: starting re-handshake");
                if (!conn->handle_noise_rehandshake(std::string_view(data, len))) {
                    SS_LOGW(TAG, "noise/handshake re-handshake failed; closing connection");
                    // Do not leave a half-swapped session. UNAUTHORIZED is the closest available
                    // reason for a crypto failure, though close_silently() never transmits it
                    // (connection.md "Failure Handling": close without any application-level
                    // message). disconnect() can block on a transport join, which close_silently()
                    // avoids; see close_transport_now()'s doc comment in connection.h.
                    conn->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_TIME: {
            if (conn == nullptr) {
                SS_LOGW(TAG, "Received time message but no connection context");
                break;
            }

            ServerTimeMessage time_msg;
            if (!process_server_time_message(root, &time_msg)) {
                break;
            }
            // Only the reply to this connection's frame in flight is taken, so no peer can feed
            // a burst a measurement it did not ask for. Each connection measures its own clock
            // into its own filter.
            const std::optional<int64_t> client_sent =
                conn->claim_time_frame(time_msg.client_transmitted);
            if (!client_sent.has_value()) {
                SS_LOGV(TAG, "server/time answers no client/time in flight; discarding");
                break;
            }
            TimeResponse response;
            compute_time_exchange(time_msg, client_sent.value(), timestamp, &response.offset,
                                  &response.max_error);
            response.timestamp = timestamp;
            response.source_id = conn->get_instance_id();
            response.client_transmitted = time_msg.client_transmitted;
            conn->time_burst().on_time_response(conn, response);
            break;
        }
        case SendspinServerToClientMessageType::SERVER_STATE: {
            // One section at a time, each in its own scope so the compiler reuses the slots.
            // Parsing the whole message into an aggregate would hold every section's storage (a
            // metadata state alone is 200 bytes) in this frame at once, and this runs on the
            // protocol task, whose stack is a fixed budget on ESP-IDF.
#ifdef SENDSPIN_ENABLE_CONTROLLER
            if (this->controller_ &&
                role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::CONTROLLER)) {
                ServerStateControllerObject controller_state;
                if (process_server_state_controller(root, &controller_state)) {
                    this->controller_->impl_->handle_server_state(
                        std::move(controller_state),
                        this->controller_->impl_->cleanup_generation.load(
                            std::memory_order_acquire));
                }
            }
#endif

#ifdef SENDSPIN_ENABLE_METADATA
            if (this->metadata_ &&
                role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::METADATA)) {
                ServerMetadataStateObject metadata_state;
                if (process_server_state_metadata(root, &metadata_state)) {
                    this->metadata_->impl_->handle_server_state(
                        std::move(metadata_state),
                        this->metadata_->impl_->cleanup_generation.load(std::memory_order_acquire));
                }
            }
#endif

#ifdef SENDSPIN_ENABLE_COLOR
            if (this->color_ &&
                role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::COLOR)) {
                ServerColorStateObject color_state;
                if (process_server_state_color(root, &color_state)) {
                    this->color_->impl_->handle_server_state(
                        color_state,
                        this->color_->impl_->cleanup_generation.load(std::memory_order_acquire));
                }
            }
#endif
            break;
        }
        case SendspinServerToClientMessageType::SERVER_COMMAND: {
#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_ &&
                role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::PLAYER)) {
                ServerCommandMessage cmd_msg;
                if (process_server_command_message(root, &cmd_msg)) {
                    this->player_->impl_->handle_server_command(
                        cmd_msg,
                        this->player_->impl_->cleanup_generation.load(std::memory_order_acquire));
                }
            }
#endif
            break;
        }
        case SendspinServerToClientMessageType::GROUP_UPDATE: {
            // group/update describes the group of the connection the client reports from: the
            // primary admitted connection.
            AdmittedEntry* primary = this->connection_manager_->primary();
            if (primary == nullptr || primary->conn.get() != conn) {
                SS_LOGD(TAG, "Ignoring group/update from a connection that is not the primary");
                break;
            }
            GroupUpdateMessage group_msg;
            if (process_group_update_message(root, &group_msg)) {
                this->event_state_->group_slot.merge(
                    [](GroupUpdateObject& current, GroupUpdateObject&& delta) {
                        apply_group_update_deltas(&current, delta);
                    },
                    std::move(group_msg.group));
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_PAIR_FINALIZE: {
            // server/pair-finalize: server acked our client/pair-finalize.
            // Commit the pending pairing record to RAM here: the server rekeys onto the new
            // long-term PSK immediately after this ack, and its re-handshake msg1 (the next
            // message on this same thread) resolves that PSK against the RecordStore. The record
            // must therefore be resolvable before this handler returns, else the re-handshake
            // sees an unknown psk_id and aborts. RecordStore locks its own mutex, since the main
            // loop reads it for the provider write. Only the RAM commit happens here: the provider
            // write is deferred to the main loop via request_persist() below, because the
            // persistence provider is main-loop-only.
            // The payload is spec'd as empty; the message-type dispatch above is the only
            // validation this message needs.
            if (conn != nullptr) {
                auto record = conn->take_pending_pairing_record();
                bool stored_record = false;
                if (record.has_value() && this->record_store_ != nullptr) {
                    // Logged before the store takes ownership of the record; a rejection warns
                    // from inside store_record_superseding().
                    SS_LOGI(TAG, "server/pair-finalize: storing pairing record (psk_id=%s)",
                            record->psk_id.c_str());
                    // store_record_superseding() mutates RAM only. At capacity it evicts the
                    // least recently used record rather than failing, since a pairing never
                    // fails for lack of record storage (pairing.md "Pairing Records"); the
                    // psk_ids of every open connection are handed over so none of them is the
                    // victim. A provider that later rejects the deferred write does not fail the
                    // pairing: the record works for this boot and persist_records() warns that it
                    // will not survive a reboot.
                    //
                    // The superseding form is correct here and only here: this PSK replaces
                    // whatever this server held before, so the prior record for the same
                    // server_id must be retired or the old PSK stays valid forever.
                    if (this->record_store_->store_record_superseding(
                            std::move(record.value()),
                            this->connection_manager_->open_connection_psk_ids())) {
                        stored_record = true;
                    }
                } else {
                    SS_LOGI(TAG, "server/pair-finalize: no pending pairing record to store");
                }
                if (stored_record) {
                    // Before on_pairing_succeeded, so the drain that fires it flushes the write
                    // first. Not fired for the capacity-rejection case.
                    this->request_persist();
                    this->connection_manager_->on_pairing_succeeded(conn);
                }
                // Re-arm the provisional timeout so the 30 s watchdog fires if the server
                // acks but never sends the in-band re-handshake that follows pair-finalize.
                conn->note_pairing_finalize_ack();
            }
            break;
        }
        case SendspinServerToClientMessageType::PAIR_ABORT: {
            // pair/abort: the server aborted the pairing exchange.
            if (conn != nullptr) {
                PairAbortMessage abort_msg;
                if (process_pair_abort_message(root, &abort_msg)) {
                    SS_LOGW(TAG, "pair/abort received: reason=%s", to_cstr(abort_msg.reason));
                    this->connection_manager_->on_pair_abort(conn, abort_msg.reason);
                } else {
                    // pair/abort must trigger cleanup even when the reason is unrecognized.
                    SS_LOGW(TAG, "Malformed pair/abort message; treating as abort with "
                                 "method_not_supported");
                    this->connection_manager_->on_pair_abort(conn,
                                                             PairAbortReason::METHOD_NOT_SUPPORTED);
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_UNPAIR: {
            // server/unpair. Trust gating (LONG_TERM only) happens in handle_server_unpair.
            if (conn != nullptr) {
                SS_LOGI(TAG, "server/unpair received (psk_id=%s)", conn->get_psk_id().c_str());
                this->connection_manager_->on_server_unpair(conn);
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_PAIR_INIT: {
            // server/pair-init: nonce_A from the server (the emission format arrived in the
            // activation's pairing object).
            if (conn != nullptr) {
                ServerPairInitPayload payload;
                if (process_server_pair_init_message(root, &payload)) {
                    ServerPairingMessage message;
                    message.kind = PairingMessageKind::PAIR_INIT;
                    message.nonce_a = payload.nonce_a;
                    this->connection_manager_->on_pairing_message(conn, message);
                } else {
                    this->report_malformed_pairing_message(conn, "server/pair-init");
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_PAIR_AUTH: {
            // server/pair-auth: server CPace share.
            if (conn != nullptr) {
                ServerPairAuthPayload payload;
                if (process_server_pair_auth_message(root, &payload)) {
                    ServerPairingMessage message;
                    message.kind = PairingMessageKind::PAIR_AUTH;
                    message.pake_msg_1 = payload.pake_msg_1;
                    this->connection_manager_->on_pairing_message(conn, message);
                } else {
                    this->report_malformed_pairing_message(conn, "server/pair-auth");
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_PAIR_CONFIRM: {
            // server/pair-confirm: server CPace confirmation tag.
            if (conn != nullptr) {
                ServerPairConfirmPayload payload;
                if (process_server_pair_confirm_message(root, &payload)) {
                    ServerPairingMessage message;
                    message.kind = PairingMessageKind::PAIR_CONFIRM;
                    message.server_kc = payload.server_kc;
                    this->connection_manager_->on_pairing_message(conn, message);
                } else {
                    this->report_malformed_pairing_message(conn, "server/pair-confirm");
                }
            }
            break;
        }
        default:
            SS_LOGW(TAG, "Unhandled server message type: %s",
                    root["type"].is<const char*>() ? root["type"].as<const char*>() : "unknown");
    }
}

SS_HOT void SendspinClient::process_binary_message(SendspinConnection* conn,
                                                   InboundMessage& message) {
    // One byte is enough to name the role that owns the message; how short a body that role
    // tolerates is the role's own rule (roles/artwork/v1.md, for one, closes the connection on a
    // message shorter than 2 bytes).
    if (message.len < 1) {
        return;
    }

    // Every binary message feeds a role, so only an admitted connection's reach one; each role
    // below also gates on the connection owning it (role_accepts_traffic()).
    if (conn == nullptr || this->connection_manager_->find_admitted(conn) == nullptr) {
        SS_LOGW(TAG, "Ignoring binary message from a connection that is not admitted");
        return;
    }

    uint8_t binary_type = message.data[0];
    uint8_t role = get_binary_role(binary_type);

    // The type byte stripped, for the artwork role, which copies the body into its image buffer.
    // The player and the visualizer take the whole message, since they can keep its ring item.
    // Only declared when the artwork role consumes it, so a build without it does not warn/error
    // on an unused variable under -Werror.
#ifdef SENDSPIN_ENABLE_ARTWORK
    const uint8_t* data = message.data + 1;
    size_t data_len = message.len - 1;
#endif

    // The visualizer role has an expanded 8-slot allocation (IDs 16-23), so it is
    // dispatched by ID range before the standard 4-slot role decoding below
    if (binary_type >= SENDSPIN_BINARY_VISUALIZER_FIRST &&
        binary_type <= SENDSPIN_BINARY_VISUALIZER_LAST) {
#ifdef SENDSPIN_ENABLE_VISUALIZER
        if (this->visualizer_ &&
            role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::VISUALIZER)) {
            this->visualizer_->impl_->handle_binary(
                binary_type, message,
                this->visualizer_->impl_->cleanup_generation.load(std::memory_order_acquire));
        }
#endif
        return;
    }

    switch (role) {
        case SENDSPIN_ROLE_PLAYER: {
#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_ &&
                role_accepts_traffic(*this->connection_manager_, conn, SendspinRole::PLAYER)) {
                uint8_t slot = get_binary_slot(binary_type);
                if (slot == 0) {
                    this->player_->impl_->handle_binary(
                        message,
                        this->player_->impl_->cleanup_generation.load(std::memory_order_acquire));
                } else {
                    SS_LOGW(TAG, "Unknown player binary slot %d", slot);
                }
            }
#endif
            break;
        }
        case SENDSPIN_ROLE_ARTWORK: {
#ifdef SENDSPIN_ENABLE_ARTWORK
            // Deliberately not gated on the role being active, unlike every other role dispatch
            // here. messaging.md "Communication" keeps a message the client implements recognized
            // while its role is inactive, and "the validation, direction, and sequencing rules for
            // recognized messages still apply", so an artwork message that is malformed as a
            // message is still the protocol error the role closes on. The role already drops the
            // payload of a message that arrives outside an active stream, below those shape
            // checks, and a removed role has no active stream (cleanup() clears it and a
            // stream/start for an inactive role is refused above). It is gated on ownership
            // conflicts alone: the artwork stream belongs to its owner, so a connection that does
            // not own the role while another one does cannot feed it.
            SendspinConnection* artwork_owner =
                this->connection_manager_->role_owner(SendspinRole::ARTWORK);
            if (this->artwork_ && (artwork_owner == nullptr || artwork_owner == conn)) {
                uint8_t slot = get_binary_slot(binary_type);
                if (!this->artwork_->impl_->handle_binary(slot, data, data_len)) {
                    // roles/artwork/v1.md "Artwork (Binary)": a malformed artwork message, and a
                    // malformed sequence within an active artwork stream, are protocol errors the
                    // client MUST close the connection on. Closed silently, like every other
                    // protocol error the receive path finds (see close_silently()).
                    SS_LOGW(TAG, "Malformed artwork message; closing connection");
                    conn->close_silently(SendspinGoodbyeReason::UNAUTHORIZED);
                }
            }
#endif
            break;
        }
        default: {
            SS_LOGW(TAG, "Unknown binary role %d (type %d)", role, binary_type);
            break;
        }
    }
}

// ============================================================================
// State publishing
// ============================================================================

void SendspinClient::publish_client_state(SendspinConnection* conn) {
    // is_operational() also covers the latest server/activate: before that we do not know which
    // roles this connection owns.
    AdmittedEntry* entry = this->connection_manager_->find_admitted(conn);
    if (entry == nullptr || !conn->is_connected() || !conn->is_operational() ||
        !this->task_state_->client_state.has_value()) {
        return;
    }
    const ClientStateMessage& snapshot = this->task_state_->client_state.value();

    // messaging.md "client/state": a player reports `available: true` only after clock
    // synchronization, and `false` would mean it will not yield, so the state waits for this
    // connection's first measurement when it owns the player; run_time_sync() sends it then.
    bool waits_for_clock = false;
#ifdef SENDSPIN_ENABLE_PLAYER
    waits_for_clock = snapshot.available && this->player_ &&
                      this->connection_manager_->owns_role(conn, SendspinRole::PLAYER) &&
                      !conn->is_time_synced();
#endif
    entry->state_held = waits_for_clock;
    if (waits_for_clock) {
        return;
    }

    // messaging.md "client/state": a role object is included only while that role is active.
    // This client includes every owned, active role's object on every update, so the first state
    // after a server/activate carries them all.
    const ClientStateMessage state_msg =
        client_state_for_roles(snapshot, entry->owned_roles & conn->get_active_role_mask());
    conn->send_app_json(format_client_state_message(&state_msg), nullptr);
}

// ============================================================================
// Persistence & identity
// ============================================================================

bool SendspinClient::load_or_generate_identity() {
    if (this->persistence_provider_ != nullptr) {
        auto saved_priv = this->persistence_provider_->load_blob(persistence_keys::KEYPAIR);
        // No codec involved: the keypair blob is the raw private key, so the only validation
        // needed here is the exact-length check: anything else is corrupt or the wrong key.
        if (saved_priv.has_value() && saved_priv->size() == persistence_keys::KEYPAIR_SIZE) {
            std::array<uint8_t, 32> priv_bytes{};
            std::copy(saved_priv->begin(), saved_priv->end(), priv_bytes.begin());
            auto loaded = Identity::from_private_bytes(priv_bytes);
            // The two plain byte buffers holding the raw private key cannot wipe themselves the
            // way every Identity-shaped copy does via ~Identity().
            secure_zero_container(priv_bytes);
            secure_zero_container(saved_priv.value());
            if (loaded.has_value()) {
                this->identity_ = std::make_unique<Identity>(loaded.value());
                this->client_id_ = this->identity_->peer_id();
                SS_LOGI(TAG, "Loaded static keypair; client_id=%s", this->client_id_.c_str());
                return true;
            }
            // Stored key is corrupt, or the underlying DH computation failed. Do not treat this
            // as an all-zero identity: generate a fresh one (the device will need to re-pair)
            // rather than proceed with a predictable key.
            SS_LOGW(TAG, "Stored static keypair is invalid; generating a new one");
        } else if (saved_priv.has_value()) {
            SS_LOGW(TAG, "Stored static keypair has the wrong size (%zu bytes); regenerating",
                    saved_priv->size());
        }
    }

    // No saved key, or the saved key was invalid: generate a new one.
    auto generated = Identity::generate();
    if (!generated.has_value()) {
        // No safe fallback: identity_ must never be set to a default-constructed (all-zero)
        // Identity, since that would be a fixed, publicly known private key that lets any peer
        // impersonate this device and would be persisted to flash below. Fail closed instead.
        SS_LOGE(TAG, "Failed to generate static identity keypair; cannot start");
        return false;
    }
    this->identity_ = std::make_unique<Identity>(generated.value());
    this->client_id_ = this->identity_->peer_id();

    if (this->persistence_provider_ != nullptr) {
        if (this->persistence_provider_->save_blob(persistence_keys::KEYPAIR,
                                                   this->identity_->private_bytes.data(),
                                                   this->identity_->private_bytes.size()) &&
            this->persistence_provider_->commit()) {
            SS_LOGI(TAG, "Generated and persisted static keypair; client_id=%s",
                    this->client_id_.c_str());
        } else {
            SS_LOGW(TAG, "Generated static keypair but failed to persist it; client_id=%s",
                    this->client_id_.c_str());
        }
    } else {
        SS_LOGI(TAG, "Generated ephemeral static keypair (no provider); client_id=%s",
                this->client_id_.c_str());
    }
    return true;
}

void SendspinClient::load_last_played_server() {
    if (!this->persistence_provider_) {
        return;
    }

    auto key_blob = this->persistence_provider_->load_blob(persistence_keys::LAST_PLAYED);
    if (key_blob.has_value() && key_blob->size() == persistence_keys::LAST_PLAYED_SIZE) {
        std::string server_id = b64url_encode(key_blob->data(), key_blob->size());
        this->connection_manager_->set_last_played_server_id(server_id);
        SS_LOGI(TAG, "Loaded last played server: %s", server_id.c_str());
    }
}
void SendspinClient::note_last_played_server(const std::string& server_id) {
    if (server_id.empty() || server_id == this->connection_manager_->last_played_server_id()) {
        return;
    }
    SS_LOGD(TAG, "Last played server is now %s", server_id.c_str());
    this->connection_manager_->set_last_played_server_id(server_id);
    PersistRequest request;
    request.last_played = server_id;
    this->event_state_->persist_slot.merge(
        [](PersistRequest& current, PersistRequest&& delta) {
            if (delta.last_played.has_value()) {
                current.last_played = std::move(delta.last_played);
            }
        },
        std::move(request));
}

void SendspinClient::write_last_played_server(const std::string& server_id) {
    if (this->persistence_provider_) {
        // The handshake admits only a server_id that is a canonical public key.
        auto key = public_key_from_peer_id(server_id);
        if (!key.has_value()) {
            SS_LOGW(TAG, "Not persisting last played server %s: not a public key",
                    server_id.c_str());
            return;
        }
        if (this->persistence_provider_->save_blob(persistence_keys::LAST_PLAYED, key->data(),
                                                   key->size())) {
            SS_LOGD(TAG, "Persisted last played server: %s", server_id.c_str());
        } else {
            SS_LOGW(TAG, "Failed to persist last played server");
        }
    }
}

// ============================================================================
// Connection event handlers (called by ConnectionManager on the protocol task)
// ============================================================================

void SendspinClient::on_handshake_complete(SendspinConnection* conn) {
    if (conn == nullptr) {
        return;
    }
    // Entering the operational state structurally ends any pairing exchange: discard the pending
    // pairing record and reset the pairing session so a stale attempt timeout can never fire a
    // stray pair/abort on an operational connection. This is the one place every "connection is
    // now operational" path converges (normal activate, leftover activate, and winning promotion).
    // Idempotent no-op for a connection that never paired.
    conn->clear_pairing_state();

    this->publish_client_state(conn);

    // Report the trust level of the newly operational connection; the listener hears it from
    // the main loop's drain.
    ConnectionTrust trust = (conn->get_psk_category() == PskCategory::LONG_TERM)
                                ? ConnectionTrust::USER
                                : ConnectionTrust::NONE;
    this->current_trust_.store(trust, std::memory_order_release);
    this->note_trust_changed(trust);
}

void SendspinClient::apply_role_removals(uint16_t removed_roles) {
    // messaging.md "server/activate", "When applying a server/activate, the client MUST": every
    // removed server-to-client stream role stops its remaining output and clears its buffers, even
    // where an earlier stream/end had let buffered data finish, and every removed role with a
    // server/state object discards its current state and any pending scheduled update.
    //
    // That is exactly what each role's cleanup() does, so deactivation runs the same teardown the
    // disconnect path runs. Only the surroundings differ: the connection survives, so the inbox
    // ring is not reset first (the roles that stay active keep their queued lifecycle events) and
    // the role may be re-added later. Coming back is the role's ordinary start path: a role
    // whose state object the server needs again is carried by the client/state the activation
    // publishes, and a stream role re-arms on the next stream/start.
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_ && role_removed(removed_roles, SendspinRole::PLAYER)) {
        this->player_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_ && role_removed(removed_roles, SendspinRole::CONTROLLER)) {
        this->controller_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_ && role_removed(removed_roles, SendspinRole::METADATA)) {
        this->metadata_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_ && role_removed(removed_roles, SendspinRole::COLOR)) {
        this->color_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    // roles/artwork/v1.md "Server -> Client: Artwork (Binary)" clears the current image and
    // discards the pending one for the whole role, which is what cleanup() carries out per
    // channel.
    if (this->artwork_ && role_removed(removed_roles, SendspinRole::ARTWORK)) {
        this->artwork_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_ && role_removed(removed_roles, SendspinRole::VISUALIZER)) {
        this->visualizer_->impl_->cleanup();
    }
#endif
    // The protocol task recalls the items a removed stream role's consumer has not taken, on
    // its next tick.
    this->protocol_task_->wake();
}

void SendspinClient::note_pairing_started(const std::string& server_id) {
    this->event_state_->push_pairing_note(
        {.type = PairingNoteType::PAIRING_STARTED, .text = server_id});
}

void SendspinClient::note_pairing_succeeded(const std::string& server_id) {
    this->event_state_->push_pairing_note(
        {.type = PairingNoteType::PAIRING_SUCCEEDED, .text = server_id});
}

void SendspinClient::note_pairing_failed(const std::string& server_id,
                                         SendspinPairAbortReason reason) {
    this->event_state_->push_pairing_note(
        {.type = PairingNoteType::PAIRING_FAILED, .text = server_id, .reason = reason});
}

void SendspinClient::note_display_pairing_code(const std::string& code,
                                               SendspinPairingCodeFormat format) {
    this->event_state_->push_pairing_note(
        {.type = PairingNoteType::DISPLAY_PAIRING_CODE, .text = code, .format = format});
}

void SendspinClient::note_clear_pairing_code() {
    this->event_state_->push_pairing_note({.type = PairingNoteType::CLEAR_PAIRING_CODE});
}

void SendspinClient::note_open_pairing_window() {
    this->event_state_->push_pairing_note({.type = PairingNoteType::OPEN_PAIRING_WINDOW});
}

void SendspinClient::note_close_pairing_window() {
    this->event_state_->push_pairing_note({.type = PairingNoteType::CLOSE_PAIRING_WINDOW});
}

void SendspinClient::note_trust_changed(ConnectionTrust trust) {
    this->event_state_->push_pairing_note({.type = PairingNoteType::TRUST_CHANGED, .trust = trust});
}

void SendspinClient::confirm_pairing_window() {
    if (!this->is_started()) {
        SS_LOGD(TAG, "confirm_pairing_window() ignored: client is not running");
        return;
    }
    ProtocolCommand command;
    command.type = ProtocolCommandType::PAIRING_WINDOW_CONFIRM;
    (void)this->protocol_task_->push_command(std::move(command));
}

void SendspinClient::cancel_pairing_window() {
    if (!this->is_started()) {
        SS_LOGD(TAG, "cancel_pairing_window() ignored: client is not running");
        return;
    }
    ProtocolCommand command;
    command.type = ProtocolCommandType::PAIRING_WINDOW_CANCEL;
    (void)this->protocol_task_->push_command(std::move(command));
}

void SendspinClient::set_unpaired_access_enabled(bool enabled) {
    if (this->unpaired_access_enabled_.exchange(enabled, std::memory_order_acq_rel) == enabled) {
        return;
    }
    // The new value reaches the next client/hello through the flag. The connections the change
    // no longer fits are closed by the protocol task; with the client stopped there are none.
    if (!this->is_started()) {
        return;
    }
    ProtocolCommand command;
    command.type = ProtocolCommandType::SET_UNPAIRED_ACCESS;
    command.enabled = enabled;
    (void)this->protocol_task_->push_command(std::move(command));
}

bool SendspinClient::is_unpaired_access_enabled() const {
    return this->unpaired_access_enabled_.load(std::memory_order_acquire);
}

}  // namespace sendspin
