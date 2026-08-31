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
#include "constants.h"
#include "inbox.h"
#include "platform/compiler.h"
#include "platform/json_arena.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/network_info.h"
#include "platform/time.h"
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
#endif
#include "protocol_messages.h"
#ifdef SENDSPIN_ENABLE_VISUALIZER
#include "visualizer_role_impl.h"
#endif
#include "time_burst.h"
#include <ArduinoJson.h>

static const char* const TAG = "sendspin.client";

namespace sendspin {

/// Grace deadline for a request_stop() teardown: covers the sync task's 500 ms idle poll
/// (IDLE_RECEIVE_TIMEOUT_MS in sync_task.cpp; keep the budget above it) plus margin for goodbye
/// sends to flush, close events to arrive, and the artwork/visualizer drain receive timeouts
/// (100 ms / 50 ms). Expiring early is bounded, not a fault: loop() force-finishes the stop, so a
/// peer that ignores its goodbye cannot hold the teardown open.
static constexpr int64_t STOP_GRACE_MS = 750;
static constexpr int64_t STOP_GRACE_US = STOP_GRACE_MS * US_PER_MS;

/// @brief Deferred event state for time responses and group updates on the main thread
struct SendspinClient::EventState {
    Inbox inbox;
    InboxSlot<GroupUpdateObject> group_slot{inbox, INBOX_TOPIC_GROUP};
    /// Bumped by cleanup_connection_state() so an in-progress ring drain abandons the rest of
    /// its already-copied batch. Main-thread only: the ring drain copies events out before
    /// dispatching, so a listener callback that re-enters connection teardown (e.g. connect_to()
    /// replacing a present-but-disconnected connection from inside a clear callback) wipes the
    /// live ring but cannot un-copy the local batch; without this counter the drain would keep
    /// dispatching those stale events (worst case a PLAYER_STREAM start for the dead stream).
    uint32_t drain_generation{0};
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

SendspinClient::SendspinClient(SendspinClientConfig config)
    : config_(std::move(config)),
      connection_manager_(std::make_unique<ConnectionManager>(this)),
      event_state_(std::make_unique<EventState>()),
      time_burst_(std::make_unique<SendspinTimeBurst>()) {
    if (this->config_.json_arena_size > 0) {
        this->json_arena_ = std::make_unique<SendspinArenaAllocator>(this->config_.json_arena_size);
    }
    this->time_burst_->configure(this->config_.time_burst_size,
                                 this->config_.time_burst_interval_ms,
                                 this->config_.time_burst_response_timeout_ms);
}

SendspinClient::~SendspinClient() {
    // Stop background threads before tearing down connections. Every role is reset explicitly
    // (not just the threaded ones): role InboxSlots release their topic-bit claims against
    // event_state_'s Inbox on destruction, so all roles must be gone before the alphabetized
    // member order destroys event_state_.
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
    if (this->run_state_ == SendspinRunState::RUNNING) {
        return true;
    }
    if (this->run_state_ == SendspinRunState::STOPPING) {
        SS_LOGW(TAG, "start() refused; a request_stop() teardown is still in progress");
        return false;
    }

    // Load persisted state
    this->load_last_played_server();

    // Start role background threads. A failure part-way stops the threads that did start, so
    // the client is back in the stopped state and a corrected retry begins clean.
    bool roles_started = true;
#ifdef SENDSPIN_ENABLE_PLAYER
    if (roles_started && this->player_) {
        roles_started = this->player_->impl_->start();
    }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (roles_started && this->visualizer_) {
        roles_started = this->visualizer_->impl_->start();
    }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
    if (roles_started && this->artwork_) {
        roles_started = this->artwork_->impl_->start();
    }
#endif

    if (!roles_started) {
        this->stop_role_threads();
        return false;
    }

    // Create and configure the WebSocket server (started later when network is ready)
    this->connection_manager_->init_server(this);

    this->run_state_ = SendspinRunState::RUNNING;
    return true;
}

void SendspinClient::stop() {
    if (this->run_state_ == SendspinRunState::STOPPED) {
        return;
    }
    // Finishing a pending request_stop() synchronously still announces its completion; a stop
    // straight from RUNNING signals completion by returning instead.
    this->finish_stop(/*notify=*/this->run_state_ == SendspinRunState::STOPPING);
}

void SendspinClient::request_stop() {
    if (this->run_state_ != SendspinRunState::RUNNING) {
        return;
    }
    this->run_state_ = SendspinRunState::STOPPING;
    this->stop_deadline_us_ = platform_time_us() + STOP_GRACE_US;

    // Goodbyes go out now (queued to httpd workers on ESP), with the server left up so they can
    // flush; role threads start winding down concurrently. loop() finishes the teardown once
    // every connection has closed and the sync task has exited, or at the deadline.
    this->connection_manager_->begin_stop(SendspinGoodbyeReason::SHUTDOWN);
    this->request_stop_role_threads();
}

void SendspinClient::connect_to(const std::string& url) {
    // Gated on the run state so a stopped (or stopping) client stays fully quiescent: an
    // outbound connection created here would otherwise re-establish with no server or role
    // threads running.
    if (this->run_state_ != SendspinRunState::RUNNING) {
        SS_LOGW(TAG, "connect_to() ignored; client is not running");
        return;
    }
    this->connection_manager_->connect_to(url);
}

void SendspinClient::disconnect(SendspinGoodbyeReason reason) {
    this->connection_manager_->disconnect(reason);
}

void SendspinClient::loop() {
    // Process connection lifecycle events (close, disconnect, hello, handoff, retry)
    this->connection_manager_->loop();

    // Handle time synchronization for the active connection via burst strategy. Gated on RUNNING
    // so a peer already told SHUTDOWN is sent nothing further: begin_stop() leaves the current
    // connection in its slot until the close event arrives, and on ESP that close is queued to an
    // httpd worker, so is_connected() stays true across at least one more tick. Only the burst is
    // gated; the manager loop above and the teardown completion below must keep running while
    // STOPPING to finish the stop. Nothing leaks if a burst is abandoned mid-flight:
    // cleanup_connection_state() releases the high-performance hold unconditionally.
    auto* conn = this->connection_manager_->current();
    if (conn != nullptr && this->run_state_ == SendspinRunState::RUNNING) {
        auto result = this->time_burst_->loop(conn);

        if (result.sent && !this->high_performance_held_for_time_) {
            this->acquire_high_performance();
            this->high_performance_held_for_time_ = true;
        }
        if (result.burst_completed && this->high_performance_held_for_time_) {
            this->release_high_performance();
            this->high_performance_held_for_time_ = false;
        }
        if (result.burst_completed && this->listener_ && conn->get_time_filter()) {
            this->listener_->on_time_sync_updated(
                static_cast<float>(conn->get_time_filter()->get_error()));
        }
    }

    // Process deferred events: all state mutations and user callbacks happen here, on the main
    // loop thread, to avoid cross-thread data races. See drain_inbox_events() for the two-snapshot
    // gating rationale.
    this->drain_inbox_events();

    // Drive a pending request_stop() to completion. Runs after the manager loop above so this
    // tick's close events are already reflected in has_connections(). Completion waits for every
    // role thread to report exit, so finish_stop()'s joins are instant on this path; the
    // deadline caps the wait when a peer never delivers its close or a thread is stuck in
    // in-flight work, at the cost of a bounded blocking join on that final tick.
    if (this->run_state_ == SendspinRunState::STOPPING) {
        bool roles_done = true;
#ifdef SENDSPIN_ENABLE_PLAYER
        if (this->player_) {
            roles_done = this->player_->impl_->has_stopped();
        }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
        if (roles_done && this->visualizer_) {
            roles_done = this->visualizer_->impl_->has_stopped();
        }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
        if (roles_done && this->artwork_) {
            roles_done = this->artwork_->impl_->has_stopped();
        }
#endif
        if ((roles_done && !this->connection_manager_->has_connections()) ||
            platform_time_us() >= this->stop_deadline_us_) {
            this->finish_stop(/*notify=*/true);
        }
    }
}

void SendspinClient::drain_inbox_events() {
    // Two poll() snapshots gate the work below: inbox_bits (here) gates only the event-ring drain
    // immediately following it; slot_bits (taken after that drain completes, below) gates the role
    // drains and the group-update drain, since a role's InboxSlot can be written by a producer
    // between this snapshot and that one. Both are lock-free atomic loads, so a tick with nothing
    // pending performs zero inbox mutex acquisitions in this section. A bit either snapshot races
    // and misses is picked up by the next tick's poll() -- bounded staleness, already documented on
    // Inbox::poll().
    const uint32_t inbox_bits = this->event_state_->inbox.poll();

    // --- Time sync events ---
    if (inbox_bits & INBOX_TOPIC_EVENTS) {
        // Drain in small batches to bound the stack cost on the shared main-loop task (the ring
        // holds up to EVENT_CAPACITY entries of ~40 bytes each). A batch that comes back partial
        // means the ring is empty, ending the loop; events pushed mid-drain are still delivered
        // this tick as long as full batches keep arriving. Sized as a fraction of the ring so the
        // batch/ring ratio (and the stack cost above) tracks EVENT_CAPACITY automatically.
        constexpr size_t EVENT_DRAIN_BATCH_SIZE = Inbox::EVENT_CAPACITY / 4;
        InboxEvent events[EVENT_DRAIN_BATCH_SIZE];
        size_t event_count = 0;
        // Snapshot the drain generation: a dispatched event below can run a listener callback
        // that re-enters connection teardown (cleanup_connection_state() bumps the counter and
        // wipes the ring). Events already copied into the local batch are stale at that point
        // and must be dropped, exactly as the ring reset intended; events pushed after the
        // reset (e.g. the role cleanups' own STREAM_END) sit in the live ring and are picked up
        // next tick.
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
                switch (event.type) {
                    case InboxEventType::TIME_RESPONSE: {
                        auto* current = this->connection_manager_->current();
                        // Apply only measurements from the connection that is still current; a
                        // response queued by a since-displaced (or pending) server carries that
                        // server's clock and would contaminate this connection's Kalman filter.
                        if (current != nullptr &&
                            current->get_instance_id() == event.time.source_id) {
                            this->time_burst_->on_time_response(current, event.time.offset,
                                                                event.time.max_error,
                                                                event.time.timestamp);
                        }
                        break;
                    }
                    // Stream lifecycle events from the player role. Dispatched to a
                    // main-thread-only Impl method that mirrors the arrival exactly as the old
                    // per-role queue delivered it: PLAYER_STREAM appends to
                    // awaiting_sync_idle_events (the sync-idle gate itself is untouched).
                    // Client-state updates from the sync task travel via the player's
                    // latest-wins state slot, not this ring; see PlayerRole::Impl::EventState.
                    case InboxEventType::PLAYER_STREAM: {
#ifdef SENDSPIN_ENABLE_PLAYER
                        if (this->player_) {
                            this->player_->impl_->on_stream_ring_event(
                                static_cast<PlayerStreamCallbackType>(event.code));
                        }
#endif
                        break;
                    }
                    // CONTROLLER_CLEARED / METADATA_CLEARED / COLOR_CLEARED: pushed by each
                    // role's cleanup() in place of the old boolean coalescing flag. At most one
                    // CLEARED per role is ever pending when this drain runs: cleanup() is called
                    // only from cleanup_connection_state(), which first calls inbox.reset_events()
                    // (wiping the whole ring) before any role re-pushes its CLEARED, and that path
                    // runs only under conn_ptr_mutex_ (ConnectionManager::drop_connection), so it
                    // cannot interleave with itself. So even a back-to-back disconnect/reconnect
                    // coalesces to a single CLEARED -- the reset_events() ordering is what
                    // guarantees it, not clear-callback idempotency. (Callbacks are idempotent by
                    // contract anyway; see on_controller_state_clear() / on_metadata_clear() /
                    // on_color_clear().)
                    case InboxEventType::CONTROLLER_CLEARED: {
#ifdef SENDSPIN_ENABLE_CONTROLLER
                        if (this->controller_) {
                            this->controller_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    case InboxEventType::METADATA_CLEARED: {
#ifdef SENDSPIN_ENABLE_METADATA
                        if (this->metadata_) {
                            this->metadata_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    case InboxEventType::COLOR_CLEARED: {
#ifdef SENDSPIN_ENABLE_COLOR
                        if (this->color_) {
                            this->color_->impl_->handle_cleared_event();
                        }
#endif
                        break;
                    }
                    // ARTWORK_STREAM / VISUALIZER_STREAM: stream lifecycle sub-events (code =
                    // the role-local ArtworkEventType/VisualizerEventType) from the artwork and
                    // visualizer roles, dispatched the same way as PLAYER_STREAM above -- straight
                    // to a main-thread-only Impl method keyed on the role-local enum.
                    case InboxEventType::ARTWORK_STREAM: {
#ifdef SENDSPIN_ENABLE_ARTWORK
                        if (this->artwork_) {
                            this->artwork_->impl_->handle_stream_ring_event(
                                static_cast<ArtworkEventType>(event.code));
                        }
#endif
                        break;
                    }
                    case InboxEventType::VISUALIZER_STREAM: {
#ifdef SENDSPIN_ENABLE_VISUALIZER
                        if (this->visualizer_) {
                            this->visualizer_->impl_->handle_stream_ring_event(
                                static_cast<VisualizerEventType>(event.code));
                        }
#endif
                        break;
                    }
                    default: {
                        // Every InboxEventType is dispatched above; this guards only against a
                        // corrupted enum value.
                        SS_LOGD(TAG, "Unhandled inbox event type: %d",
                                static_cast<int>(event.type));
                        break;
                    }
                }
            }
            // A teardown that re-entered on the final event of a full batch bumps the drain
            // generation but leaves drain_aborted false: the check at the top of the inner loop
            // never runs again because there is no next iteration. Re-check here so the loop stops
            // instead of calling take_events() again and destructively pulling the cleanup's
            // freshly re-pushed CLEARED/STREAM_END events off the live ring (dropping them).
            if (this->event_state_->drain_generation != drain_generation) {
                drain_aborted = true;
            }
        } while (!drain_aborted && event_count == EVENT_DRAIN_BATCH_SIZE);
    }

    // Second snapshot: catches topic bits a producer set while the ring drain above was running
    // (e.g. a role's own ring-event side effects re-entering the inbox, or any other producer
    // thread racing the drain). Gates the role drains and the group drain below; see the
    // inbox_bits comment above for the staleness argument, which applies identically here.
    const uint32_t slot_bits = this->event_state_->inbox.poll();

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

            // Persist last played server when playback starts
            if (group_delta.playback_state.has_value() &&
                group_delta.playback_state.value() == SendspinPlaybackState::PLAYING) {
                auto* current = this->connection_manager_->current();
                if (current != nullptr) {
                    const std::string& server_id = current->get_server_id();
                    if (!server_id.empty()) {
                        this->persist_last_played_server(server_id);
                    }
                }
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
    if (this->run_state_ != SendspinRunState::STOPPED) {
        SS_LOGW(TAG, "add_player() called after start(); role may not initialize correctly");
    }
    this->player_ =
        std::make_unique<PlayerRole>(std::move(config), this, this->persistence_provider_);
    this->player_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->player_;
}
#endif

#ifdef SENDSPIN_ENABLE_CONTROLLER
ControllerRole& SendspinClient::add_controller() {
    if (this->run_state_ != SendspinRunState::STOPPED) {
        SS_LOGW(TAG, "add_controller() called after start()");
    }
    this->controller_ = std::make_unique<ControllerRole>(this);
    this->controller_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->controller_;
}
#endif

#ifdef SENDSPIN_ENABLE_METADATA
MetadataRole& SendspinClient::add_metadata() {
    if (this->run_state_ != SendspinRunState::STOPPED) {
        SS_LOGW(TAG, "add_metadata() called after start()");
    }
    this->metadata_ = std::make_unique<MetadataRole>(this);
    this->metadata_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->metadata_;
}
#endif

#ifdef SENDSPIN_ENABLE_COLOR
ColorRole& SendspinClient::add_color() {
    if (this->run_state_ != SendspinRunState::STOPPED) {
        SS_LOGW(TAG, "add_color() called after start()");
    }
    this->color_ = std::make_unique<ColorRole>(this);
    this->color_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->color_;
}
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
ArtworkRole& SendspinClient::add_artwork(ArtworkRoleConfig config) {
    if (this->run_state_ != SendspinRunState::STOPPED) {
        SS_LOGW(TAG, "add_artwork() called after start()");
    }
    this->artwork_ = std::make_unique<ArtworkRole>(std::move(config), this);
    this->artwork_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->artwork_;
}
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
VisualizerRole& SendspinClient::add_visualizer(VisualizerRoleConfig config) {
    if (this->run_state_ != SendspinRunState::STOPPED) {
        SS_LOGW(TAG, "add_visualizer() called after start()");
    }
    this->visualizer_ = std::make_unique<VisualizerRole>(std::move(config), this);
    this->visualizer_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->visualizer_;
}
#endif

// ============================================================================
// Queries
// ============================================================================

int64_t SendspinClient::get_client_time(int64_t server_time) const {
    // current_shared(): called from role threads; see is_time_synced().
    auto conn = this->connection_manager_->current_shared();
    return conn != nullptr ? conn->get_client_time(server_time) : 0;
}

bool SendspinClient::is_connected() const {
    return this->connection_manager_->is_connected();
}

std::optional<ServerInformationObject> SendspinClient::get_server_information() const {
    // current_shared(): public accessor, callable from any thread.
    auto conn = this->connection_manager_->current_shared();
    if (conn == nullptr || !conn->is_handshake_complete()) {
        return std::nullopt;
    }
    return conn->get_server_information();
}

bool SendspinClient::is_time_synced() const {
    // current_shared(): called from role threads (sync task, drain threads), so the shared_ptr
    // must keep the connection alive while it is dereferenced.
    auto conn = this->connection_manager_->current_shared();
    return conn != nullptr && conn->is_time_synced();
}

// ============================================================================
// State updates
// ============================================================================

void SendspinClient::update_state(SendspinClientState state) {
    this->state_ = state;
    this->publish_client_state(this->connection_manager_->current());
}

// ============================================================================
// Role services (called by roles via SendspinClient pointer)
// ============================================================================

void SendspinClient::publish_state() {
    this->publish_client_state(this->connection_manager_->current());
}

void SendspinClient::send_text(const std::string& text) {
    auto* conn = this->connection_manager_->current();
    if (conn != nullptr && conn->is_connected()) {
        conn->send_text_message(text, nullptr);
    }
}

void SendspinClient::acquire_high_performance() {
    if (this->high_performance_ref_count_.fetch_add(1) == 0 && this->listener_) {
        this->listener_->on_request_high_performance();
    }
}

void SendspinClient::release_high_performance() {
    // Compare-exchange loop so two concurrent releases at count 1 can't both pass a
    // plain zero-check and underflow the counter
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

void SendspinClient::cleanup_connection_state() {
    SS_LOGV(TAG, "Cleaning up connection state");

    // The time burst is per-connection state too; resetting it here keeps it impossible to tear
    // down a connection without also stopping its burst.
    this->time_burst_->reset();

    // Reset client event state. The generation bump makes an in-progress ring drain abandon any
    // events it already copied out of the ring before this reset (see the drain in loop()).
    //
    // A second teardown in the same tick (a handoff chain can displace two current connections
    // in one manager pass) wipes the first teardown's just-pushed CLEARED/STREAM_END events
    // here before they are ever drained. That is safe only because every role's cleanup() below
    // pushes its full event set unconditionally, so this call re-creates exactly what it wiped
    // and the drain still fires each (payload-free, idempotent) callback once -- the same
    // coalescing the old per-role pending_clear booleans provided. Keep role cleanups
    // unconditional or this reset starts losing clear signals.
    this->event_state_->drain_generation++;
    this->event_state_->inbox.reset_events();
    this->event_state_->group_slot.reset();

#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
    if (this->controller_) {
        this->controller_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_METADATA
    if (this->metadata_) {
        this->metadata_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_COLOR
    if (this->color_) {
        this->color_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->cleanup();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->cleanup();
    }
#endif

    // Release high-performance networking for time sync
    if (this->high_performance_held_for_time_) {
        this->release_high_performance();
        this->high_performance_held_for_time_ = false;
    }
}

void SendspinClient::stop_role_threads() {
    // Signal every role before joining any, so their receive timeouts elapse concurrently rather
    // than in series: each role's stop() below both signals and joins, so without this an idle
    // client would wait out the sum of the three timeouts instead of the longest one (the sync
    // task's 500 ms idle poll). Re-signalling inside stop() is harmless, the flags are idempotent.
    // The request_stop() path has already signalled them by the time it reaches here; this makes
    // the direct stop() path behave the same way.
    this->request_stop_role_threads();

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

void SendspinClient::finish_stop(bool notify) {
    // Re-entrancy guard: teardown below runs connection_manager_->stop(), which synchronously
    // invokes listener callbacks (e.g. cleanup_connection_state() -> release_high_performance()
    // -> on_release_high_performance() whenever a time-sync burst is in flight). A listener that
    // calls stop()/request_stop()/start()/connect_to() from inside such a callback must not
    // recurse into a second teardown or observe a state that lets it race the one in progress.
    if (this->tearing_down_) {
        return;
    }
    this->tearing_down_ = true;

    // Force (rather than assert) STOPPING: stop() can reach here directly from RUNNING, not only
    // via a completing request_stop(). Staying in STOPPING (never STOPPED) for the duration means
    // start() explicitly refuses and connect_to()/request_stop() no-op if a listener callback
    // reached during teardown calls back into the client, instead of start() seeing STOPPED and
    // spinning up a second set of role threads and server on top of the teardown still in flight.
    this->run_state_ = SendspinRunState::STOPPING;

    // Goodbye and close every connection, then stop the WebSocket server so no new connections
    // arrive. Dropping the current slot inside runs cleanup_connection_state(), which quiesces
    // per-connection state (time burst, role state, high-performance holds) and queues the
    // roles' clear callbacks for drain_inbox_events() below.
    this->connection_manager_->stop(SendspinGoodbyeReason::SHUTDOWN);

    // Join role threads only after the connection teardown above has signaled their streams
    // closed; a restart via start() re-creates them.
    this->stop_role_threads();

    // Reset session-scoped published state so a restart begins fresh: group_state_ is a delta
    // accumulator that would otherwise keep serving the old session's group, and a stale state_
    // (e.g. ERROR) would be republished verbatim to the next server on handshake. Reset here
    // rather than in cleanup_connection_state(), which also runs on reconnects and handoffs
    // where carrying the state forward is intentional. Runs before drain_inbox_events() below so
    // that drain cannot resurrect a stale group_state_/state_ even in the (already guarded-against
    // by cleanup_connection_state()'s group_slot.reset()) case of a leftover group update.
    this->group_state_ = GroupUpdateObject{};
    this->state_ = SendspinClientState::SYNCHRONIZED;

    // Deliver the roles' clear callbacks (STREAM_END / CONTROLLER_CLEARED / METADATA_CLEARED /
    // COLOR_CLEARED / artwork+visualizer stream events) queued by cleanup_connection_state() above
    // before on_stopped() fires below: the header documents on_stopped() as the signal that it is
    // safe to destroy the client, so those callbacks must already have run by then rather than
    // waiting for a consumer's next loop() call that may never come.
    this->drain_inbox_events();

    this->run_state_ = SendspinRunState::STOPPED;
    // Clear before notifying: on_stopped() is documented to allow calling start() again from
    // inside the callback, which requires run_state_ == STOPPED and tearing_down_ == false to
    // proceed normally.
    this->tearing_down_ = false;

    if (notify && this->listener_ != nullptr) {
        this->listener_->on_stopped();
    }
}

void SendspinClient::request_stop_role_threads() {
#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->request_stop();
    }
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        this->visualizer_->impl_->request_stop();
    }
#endif
#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        this->artwork_->impl_->request_stop();
    }
#endif
}

std::string SendspinClient::build_hello_message() {
    ClientHelloMessage msg;
    msg.name = this->config_.name;

    // Use the explicitly configured MAC when provided; otherwise fall back to platform detection
    // (reliable on ESP, best-effort on host). Leaves the field absent if neither is available.
    const std::optional<std::string> interface_mac =
        this->config_.mac_address ? this->config_.mac_address : platform_get_interface_mac();

    // Some integrations use the network MAC as the Sendspin client_id. If they leave it empty,
    // default to the same active-interface MAC advertised in device_info instead of forcing them
    // to duplicate platform-specific MAC detection.
    msg.client_id = this->config_.client_id;
    if (msg.client_id.empty() && interface_mac.has_value()) {
        msg.client_id = interface_mac.value();
    }

    DeviceInfoObject device_info{};
    device_info.product_name = this->config_.product_name;
    device_info.manufacturer = this->config_.manufacturer;
    device_info.software_version = this->config_.software_version;
    device_info.mac_address = interface_mac;
    msg.device_info = device_info;

    msg.version = 1;

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

void SendspinClient::process_json_message(SendspinConnection* conn, const char* data, size_t len,
                                          int64_t timestamp) {
    // Two connections can deliver JSON concurrently on their own network threads (current +
    // pending during a handoff, or an outbound connect_to() transport alongside the inbound
    // server). Serialize the shared arena and the parse itself; JSON control messages are
    // infrequent, so contention is negligible.
    std::lock_guard<std::mutex> lock(this->json_processing_mutex_);

    // Reuse the internal-RAM scratch arena if configured. Safe to reset here: the JsonDocument
    // from the previous call was already destroyed when that call returned.
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

    switch (message_type) {
        case SendspinServerToClientMessageType::STREAM_START: {
            SS_LOGD(TAG, "Stream Started");

            StreamStartMessage stream_msg;
            if (!process_stream_start_message(root, &stream_msg)) {
                SS_LOGE(TAG, "Failed to parse stream/start message");
                break;
            }

#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_ && stream_msg.player.has_value()) {
                this->player_->impl_->handle_stream_start(stream_msg.player.value());
            }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
            if (this->artwork_ && stream_msg.artwork.has_value()) {
                this->artwork_->impl_->handle_stream_start(stream_msg.artwork.value());
            }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
            if (this->visualizer_ && stream_msg.visualizer.has_value()) {
                this->visualizer_->impl_->handle_stream_start(stream_msg.visualizer.value());
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
                if (this->player_ && end_player) {
                    this->player_->impl_->handle_stream_end();
                }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
                if (this->artwork_ && end_artwork) {
                    this->artwork_->impl_->handle_stream_end();
                }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
                if (this->visualizer_ && end_visualizer) {
                    this->visualizer_->impl_->handle_stream_end();
                }
#endif
            }
            break;
        }
        case SendspinServerToClientMessageType::STREAM_CLEAR: {
            StreamClearMessage clear_msg;
            if (process_stream_clear_message(root, &clear_msg)) {
                bool clear_player = !clear_msg.roles.has_value();
                bool clear_artwork = !clear_msg.roles.has_value();
                bool clear_visualizer = !clear_msg.roles.has_value();

                if (clear_msg.roles.has_value()) {
                    for (const auto& role : clear_msg.roles.value()) {
                        if (role == "player") {
                            clear_player = true;
                        } else if (role == "artwork") {
                            clear_artwork = true;
                        } else if (role == "visualizer") {
                            clear_visualizer = true;
                        }
                    }
                }

                SS_LOGD(TAG, "Stream clear - player:%d artwork:%d visualizer:%d", clear_player,
                        clear_artwork, clear_visualizer);

#ifdef SENDSPIN_ENABLE_PLAYER
                if (this->player_ && clear_player) {
                    this->player_->impl_->handle_stream_clear();
                }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
                if (this->artwork_ && clear_artwork) {
                    this->artwork_->impl_->handle_stream_clear();
                }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
                if (this->visualizer_ && clear_visualizer) {
                    this->visualizer_->impl_->handle_stream_clear();
                }
#endif
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_HELLO: {
            ServerHelloMessage hello_msg;
            if (process_server_hello_message(root, &hello_msg)) {
                SS_LOGD(TAG, "Connected to server %s with id %s (reason: %s)",
                        hello_msg.server.name.c_str(), hello_msg.server.server_id.c_str(),
                        to_cstr(hello_msg.connection_reason));

                if (conn != nullptr) {
                    conn->set_server_information(std::move(hello_msg.server));
                    conn->set_connection_reason(hello_msg.connection_reason);
                    // Set last: this atomic store publishes the fields above to the manager's
                    // promotion scan on the main loop, which observes is_handshake_complete()
                    // and establishes the connection; nothing needs to be scheduled here.
                    conn->set_server_hello_received(true);
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_TIME: {
            if (conn == nullptr) {
                SS_LOGW(TAG, "Received time message but no connection context");
                break;
            }

            int64_t offset{0};
            int64_t max_error{0};
            if (process_server_time_message(root, timestamp, &offset, &max_error)) {
                InboxEvent event{};
                event.type = InboxEventType::TIME_RESPONSE;
                event.time =
                    TimeResponsePayload{offset, max_error, timestamp, conn->get_instance_id()};
                if (!this->event_state_->inbox.push_event(event)) {
                    SS_LOGW(TAG, "Inbox event ring full; dropping time response measurement");
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_STATE: {
            // Parse and hand off one section at a time, each in its own scope. Parsing the whole
            // message into an aggregate would hold every section's storage (a metadata delta alone
            // is 200 bytes) in this frame at once, and this runs on the network task, whose stack
            // is small on ESP-IDF. Scoping the sections lets the compiler reuse the same slots, and
            // a section is only parsed at all when its role is present.
#ifdef SENDSPIN_ENABLE_CONTROLLER
            if (this->controller_ != nullptr) {
                ServerStateControllerObject controller_state;
                if (process_server_state_controller(root, &controller_state)) {
                    this->controller_->impl_->handle_server_state(std::move(controller_state));
                }
            }
#endif

#ifdef SENDSPIN_ENABLE_METADATA
            if (this->metadata_ != nullptr) {
                ServerMetadataStateDelta metadata_delta;
                if (process_server_state_metadata(root, &metadata_delta)) {
                    this->metadata_->impl_->handle_server_state(std::move(metadata_delta));
                }
            }
#endif

#ifdef SENDSPIN_ENABLE_COLOR
            if (this->color_ != nullptr) {
                ServerColorStateDelta color_delta;
                if (process_server_state_color(root, &color_delta)) {
                    this->color_->impl_->handle_server_state(color_delta);
                }
            }
#endif
            break;
        }
        case SendspinServerToClientMessageType::SERVER_COMMAND: {
#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_) {
                ServerCommandMessage cmd_msg;
                if (process_server_command_message(root, &cmd_msg)) {
                    this->player_->impl_->handle_server_command(cmd_msg);
                }
            }
#endif
            break;
        }
        case SendspinServerToClientMessageType::GROUP_UPDATE: {
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
        default:
            SS_LOGW(TAG, "Unhandled server message type: %s",
                    root["type"].is<const char*>() ? root["type"].as<const char*>() : "unknown");
    }
}

SS_HOT void SendspinClient::process_binary_message(const uint8_t* payload, size_t len) {
    if (len < 2) {
        return;
    }

    uint8_t binary_type = payload[0];
    uint8_t role = get_binary_role(binary_type);
    uint8_t slot = get_binary_slot(binary_type);

    // Strip the type byte; each role parses its own binary format from here
    const uint8_t* data = payload + 1;
    size_t data_len = len - 1;

    // The visualizer role has an expanded 8-slot allocation (IDs 16-23), so it is
    // dispatched by ID range before the standard 4-slot role decoding below
    if (binary_type >= SENDSPIN_BINARY_VISUALIZER_FIRST &&
        binary_type <= SENDSPIN_BINARY_VISUALIZER_LAST) {
#ifdef SENDSPIN_ENABLE_VISUALIZER
        if (this->visualizer_) {
            this->visualizer_->impl_->handle_binary(binary_type, data, data_len);
        }
#endif
        return;
    }

    switch (role) {
        case SENDSPIN_ROLE_PLAYER: {
#ifdef SENDSPIN_ENABLE_PLAYER
            if (this->player_) {
                if (slot == 0) {
                    this->player_->impl_->handle_binary(data, data_len);
                } else {
                    SS_LOGW(TAG, "Unknown player binary slot %d", slot);
                }
            }
#endif
            break;
        }
        case SENDSPIN_ROLE_ARTWORK: {
#ifdef SENDSPIN_ENABLE_ARTWORK
            if (this->artwork_) {
                this->artwork_->impl_->handle_binary(slot, data, data_len);
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
    if (conn == nullptr || !conn->is_connected() || !conn->is_handshake_complete()) {
        return;
    }

    ClientStateMessage state_msg;
    state_msg.state = this->state_;

#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        this->player_->impl_->build_state_fields(state_msg);
    }
#endif

    std::string state_message = format_client_state_message(&state_msg);
    conn->send_text_message(state_message, nullptr);
}

// ============================================================================
// Persistence
// ============================================================================

void SendspinClient::load_last_played_server() {
    if (!this->persistence_provider_) {
        return;
    }

    auto hash = this->persistence_provider_->load_last_server_hash();
    if (hash.has_value() && hash.value() != 0) {
        this->connection_manager_->set_last_played_server_hash(hash.value());
        SS_LOGI(TAG, "Loaded last played server hash: 0x%08X", hash.value());
    }
}

void SendspinClient::persist_last_played_server(const std::string& server_id) {
    if (server_id.empty()) {
        return;
    }

    uint32_t hash = ConnectionManager::fnv1_hash(server_id.c_str());
    this->connection_manager_->set_last_played_server_hash(hash);

    if (this->persistence_provider_) {
        if (this->persistence_provider_->save_last_server_hash(hash)) {
            SS_LOGD(TAG, "Persisted last played server: %s (hash: 0x%08X)", server_id.c_str(),
                    hash);
        } else {
            SS_LOGW(TAG, "Failed to persist last played server");
        }
    }
}

// ============================================================================
// Connection event handlers (called by ConnectionManager via friend access)
// ============================================================================

void SendspinClient::on_handshake_complete(SendspinConnection* conn) {
    this->publish_client_state(conn);
}

}  // namespace sendspin
