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
#include "crypto/pairing_token.h"
#include "inbox.h"
#include "platform/compiler.h"
#include "platform/crypto.h"
#include "platform/json_arena.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/network_info.h"
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
#include "time_burst.h"
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
/// loop() dispatch fires all notes of one type before any note of the next, regardless of queue
/// order, preserving the delivery contract of the former per-type pending fields (e.g.
/// on_pairing_started before the on_open_pairing_window prompt it gated). The dispatch walks this
/// enum by value, so adding an enumerator here places it in the order automatically and the
/// exhaustive switch (no default, built with -Werror) forces it to be given a case.
enum class PairingNoteType : uint8_t {
    PAIRING_STARTED,
    PAIRING_SUCCEEDED,
    TRUST_CHANGED,
    PAIRING_FAILED,
    DISPLAY_PIN,
    CLEAR_PIN,
    OPEN_PAIRING_WINDOW,
    CLOSE_PAIRING_WINDOW,
    COUNT,  ///< Not a note type; bounds the dispatch walk. Keep last.
};

/// @brief One deferred pairing/trust listener notification, queued by the note_*() methods and
/// dispatched from loop()
struct PairingNote {
    PairingNoteType type{};
    /// server_id for PAIRING_STARTED/SUCCEEDED/FAILED; PIN text for DISPLAY_PIN; empty otherwise.
    std::string text;
    SendspinPairAbortReason reason{};  ///< Valid only for PAIRING_FAILED.
    ConnectionTrust trust{};           ///< Valid only for TRUST_CHANGED.
};

/// @brief True for note types that coalesce to at most one callback per tick, keeping the
/// single-flag semantics of the window/PIN-clear notifications (two note_clear_pin() calls in one
/// tick still fire on_clear_pairing_pin once)
constexpr bool is_coalesced_note(PairingNoteType type) {
    return type == PairingNoteType::CLEAR_PIN || type == PairingNoteType::OPEN_PAIRING_WINDOW ||
           type == PairingNoteType::CLOSE_PAIRING_WINDOW;
}

/// @brief Resolve the `locations` hint for a pair-method descriptor in client/hello.
/// @param configured Where the application published the secret the device shipped with.
/// @param rotated True once that secret has been replaced (see RecordStore::pairing_psk_rotated()).
/// @return The hint to advertise, or nullopt to omit the field.
///
/// A rotation invalidates every copy of the shipped secret, so the configured answer becomes a
/// lie the moment it happens: the replacement exists only wherever the operator who set it keeps
/// it. The spec has the client update the hint on rotation ("client/hello pair-method
/// descriptor"), and 'operator' is the value that stays true afterwards no matter what the device
/// was labeled with. It is advertised even when the application configured nothing, because the
/// provenance is then known where before it was not.
std::optional<std::vector<std::string>> locations_hint(const std::vector<std::string>& configured,
                                                       bool rotated) {
    if (rotated) {
        return std::vector<std::string>{"operator"};
    }
    if (configured.empty()) {
        return std::nullopt;
    }
    return configured;
}

}  // namespace

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

    // Pairing/trust listener notifications. All of these are produced on the MAIN LOOP only
    // (by ConnectionManager, itself driven from connection_manager_->loop() called from
    // SendspinClient::loop()) while conn_ptr_mutex_ is held, and fired from loop() after that
    // call returns (unlocked, so a listener may safely call back into the client). No lock is
    // needed here: single-writer/single-reader, both on the main loop. Deliberately NOT on the
    // Inbox: the payloads carry strings (the ring is POD-only) and nothing crosses a thread, so
    // the shared mutex and a topic bit would buy nothing.
    //
    // The one genuinely cross-thread notification, on_pairing_succeeded (triggered by the
    // network-thread server/pair-finalize ack handler), does NOT queue here directly; it goes
    // through ConnectionManager's existing pending_*_events_ / has_pending_events_ idiom (see
    // schedule_pairing_succeeded()) and is only turned into a note_pairing_succeeded() call (and
    // thus a PairingNote here) once that idiom's drain has moved it to the main loop.
    std::vector<PairingNote> pairing_notes;

    /// @brief Appends `note` to pairing_notes. Every SendspinClient::note_*() method funnels
    /// through this so the push_back shape lives once. PairingNote is anonymous-namespace-private
    /// to this file, so this lives on EventState (itself private to SendspinClient) rather than as
    /// a SendspinClient member declared in the public header.
    /// @param note The note to append (moved).
    void push_pairing_note(PairingNote&& note) {
        this->pairing_notes.push_back(std::move(note));
    }
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

bool SendspinClient::start_server() {
    // started_ is deliberately NOT set here: it is set only once every step below has succeeded.
    // Setting it up front would mark the client started even when this function returns false
    // (e.g. identity generation failed and identity_ is left null), which is precisely the state
    // connect_to() must refuse to build a connection in.
    //
    // Create the record store (needs the persistence provider, so done here rather than at
    // construction) and load or generate the static X25519 identity. Both must exist before
    // the connection manager can hand them out to any connection (init_server() below starts
    // the ws_server, and connect_to() may be called any time after start_server() RETURNS TRUE;
    // connect_to() enforces that itself rather than trusting the caller's ordering).
    this->record_store_ = std::make_unique<RecordStore>(
        this->persistence_provider_, this->config_.initial_unpaired_access_enabled,
        this->config_.max_pairing_records);
    if (!this->load_or_generate_identity()) {
        // identity_ is left null: there is no safe key to fall back to (see
        // load_or_generate_identity()'s doc comment), so the client must not start.
        return false;
    }

    // Load persisted state
    this->load_last_played_server();

#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_) {
        if (!this->player_->impl_->start()) {
            return false;
        }
    }
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
    if (this->visualizer_) {
        if (!this->visualizer_->impl_->start()) {
            return false;
        }
    }
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
    if (this->artwork_) {
        if (!this->artwork_->impl_->start()) {
            return false;
        }
    }
#endif

    // Create and configure the WebSocket server (started later when network is ready)
    this->connection_manager_->init_server(this);

    this->started_ = true;
    return true;
}

void SendspinClient::connect_to(const std::string& url) {
    // Refuse to build an outbound connection before start_server() has fully succeeded.
    // identity_ and record_store_ are populated only there, and the lifecycle drain hands both
    // to init_noise_handshake() by reference once the WebSocket upgrade completes (see
    // ConnectionManager::drain_lifecycle_events), so a connection started now would dereference
    // null there. Checking the pointers rather than started_ alone also covers a consumer that
    // ignored a false return from start_server().
    if (this->identity_ == nullptr || this->record_store_ == nullptr) {
        SS_LOGE(TAG,
                "connect_to(%s) ignored: start_server() has not completed successfully, so there "
                "is no identity to hand the Noise handshake",
                url.c_str());
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

    // Handle time synchronization for the active connection via burst strategy. Gate on
    // is_operational() (hello + first server/activate), not just non-null: an in-band
    // re-handshake resets first_activate_received_ (and the hello flags) on the still-current
    // connection, and a stale pre-re-handshake time exchange must not resume mid-rotation.
    auto* conn = this->connection_manager_->current();
    // Suppress time sync while a pairing exchange is in progress (mirrors _pause_time_sync in
    // the reference). pairing_in_progress_ is written by the main loop (enter/abort) and by the
    // network thread (handle_noise_rehandshake clears it), so it is atomic.
    if (conn != nullptr && conn->is_operational() && !conn->is_pairing_in_progress()) {
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
    // loop thread, to avoid cross-thread data races. Two poll() snapshots gate the work below:
    // inbox_bits (here) gates only the event-ring drain immediately following it; slot_bits
    // (taken after that drain completes, below) gates the role drains and the group-update drain,
    // since a role's InboxSlot can be written by a producer between this snapshot and that one.
    // Both are lock-free atomic loads, so a tick with nothing pending performs zero inbox mutex
    // acquisitions in this section. A bit either snapshot races and misses is picked up by the
    // next tick's poll(): bounded staleness, already documented on Inbox::poll().
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
                    // coalesces to a single CLEARED; the reset_events() ordering is what
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
                    // visualizer roles, dispatched the same way as PLAYER_STREAM above: straight
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

    // --- Deferred pairing/trust notifications (collected during connection_manager_->loop()
    //     while conn_ptr_mutex_ was held; fired here unlocked so a listener may call back into
    //     the client). Main loop only. ---
    {
        auto& es = *this->event_state_;
        if (!es.pairing_notes.empty()) {
            // Move the queue out before dispatching: a callback below may re-enter the client
            // (e.g. connect_to() from a listener runs cleanup_connection_state(), which clears
            // the live queue), and iterating the member vector across that would invalidate this
            // dispatch's iterators. Notes are consumed (or discarded, when no listener is set)
            // exactly once per tick either way.
            std::vector<PairingNote> notes = std::move(es.pairing_notes);
            es.pairing_notes.clear();
            // Same staleness rule as the ring drain above: a teardown re-entered from a callback
            // bumps drain_generation to wipe undelivered notifications, which must cover the
            // ones already moved into this local batch.
            const uint32_t note_generation = es.drain_generation;
            // Set when a re-entrant teardown bumps the generation, abandoning the rest of the
            // batch.
            bool notes_aborted = false;
            // Checked once for the whole batch: the listener is set before start_server() and must
            // outlive the client (see set_listener), so it cannot become null mid-dispatch.
            if (this->listener_ != nullptr) {
                // Dispatch grouped by type in PairingNoteType declaration order (not queue order),
                // firing coalesced types at most once; see the enum and is_coalesced_note().
                // Walking the enum rather than a hand-written order list leaves nothing to fall out
                // of sync: a new note type joins the order where it is declared.
                for (uint8_t i = 0;
                     i < static_cast<uint8_t>(PairingNoteType::COUNT) && !notes_aborted; ++i) {
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
                            case PairingNoteType::DISPLAY_PIN:
                                this->listener_->on_display_pairing_pin(note.text);
                                break;
                            case PairingNoteType::CLEAR_PIN:
                                this->listener_->on_clear_pairing_pin();
                                break;
                            case PairingNoteType::OPEN_PAIRING_WINDOW:
                                this->listener_->on_open_pairing_window();
                                break;
                            case PairingNoteType::CLOSE_PAIRING_WINDOW:
                                this->listener_->on_close_pairing_window();
                                break;
                            case PairingNoteType::COUNT:
                                // Unreachable: the walk above stops before COUNT. Listed so the
                                // switch stays exhaustive without a default, which is what forces a
                                // new note type to be handled here.
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

            // Persist last played server when playback starts
            if (group_delta.playback_state.has_value() &&
                group_delta.playback_state.value() == SendspinPlaybackState::PLAYING) {
                const auto* current = this->connection_manager_->current();
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
// Role registration (call before start_server)
// ============================================================================

#ifdef SENDSPIN_ENABLE_PLAYER
PlayerRole& SendspinClient::add_player(PlayerRoleConfig config) {
    if (this->started_) {
        SS_LOGW(TAG, "add_player() called after start_server(); role may not initialize correctly");
    }
    this->player_ =
        std::make_unique<PlayerRole>(std::move(config), this, this->persistence_provider_);
    this->player_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->player_;
}
#endif

#ifdef SENDSPIN_ENABLE_CONTROLLER
ControllerRole& SendspinClient::add_controller() {
    if (this->started_) {
        SS_LOGW(TAG, "add_controller() called after start_server()");
    }
    this->controller_ = std::make_unique<ControllerRole>(this);
    this->controller_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->controller_;
}
#endif

#ifdef SENDSPIN_ENABLE_METADATA
MetadataRole& SendspinClient::add_metadata() {
    if (this->started_) {
        SS_LOGW(TAG, "add_metadata() called after start_server()");
    }
    this->metadata_ = std::make_unique<MetadataRole>(this);
    this->metadata_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->metadata_;
}
#endif

#ifdef SENDSPIN_ENABLE_COLOR
// cppcheck-suppress unusedFunction
// Public API: live entry point the reference examples don't happen to exercise, not dead code.
ColorRole& SendspinClient::add_color() {
    if (this->started_) {
        SS_LOGW(TAG, "add_color() called after start_server()");
    }
    this->color_ = std::make_unique<ColorRole>(this);
    this->color_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->color_;
}
#endif

#ifdef SENDSPIN_ENABLE_ARTWORK
// cppcheck-suppress unusedFunction
// Public API: live entry point the reference examples don't happen to exercise, not dead code.
ArtworkRole& SendspinClient::add_artwork(ArtworkRoleConfig config) {
    if (this->started_) {
        SS_LOGW(TAG, "add_artwork() called after start_server()");
    }
    this->artwork_ = std::make_unique<ArtworkRole>(std::move(config), this);
    this->artwork_->impl_->attach_inbox(this->event_state_->inbox);
    return *this->artwork_;
}
#endif

#ifdef SENDSPIN_ENABLE_VISUALIZER
VisualizerRole& SendspinClient::add_visualizer(VisualizerRoleConfig config) {
    if (this->started_) {
        SS_LOGW(TAG, "add_visualizer() called after start_server()");
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
    // Main-loop-only, like the other record-store config reads: the Pairing PSK is mutated only
    // from the main loop (first-boot provisioning and set-pairing-config management).
    if (this->record_store_ == nullptr || !this->record_store_->pairing_psk().has_value()) {
        return std::nullopt;
    }
    return this->format_pairing_token(this->record_store_->pairing_psk()->psk);
}

bool SendspinClient::is_connected() const {
    return this->connection_manager_->is_connected();
}

bool SendspinClient::is_time_synced() const {
    // current_shared(): called from role threads (sync task, drain threads), so the shared_ptr
    // must keep the connection alive while it is dereferenced.
    auto conn = this->connection_manager_->current_shared();
    return conn != nullptr && conn->is_time_synced();
}

int64_t SendspinClient::get_client_time(int64_t server_time) const {
    // current_shared(): called from role threads; see is_time_synced().
    auto conn = this->connection_manager_->current_shared();
    return conn != nullptr ? conn->get_client_time(server_time) : 0;
}

std::optional<ServerInformationObject> SendspinClient::get_server_information() const {
    // current_shared(): public accessor, callable from any thread.
    auto conn = this->connection_manager_->current_shared();
    if (conn == nullptr || !conn->is_handshake_complete()) {
        return std::nullopt;
    }
    return conn->get_server_information();
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
        conn->send_app_json(text, nullptr);
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
    // and the drain still fires each (payload-free, idempotent) callback once, the same
    // coalescing the old per-role pending_clear booleans provided. Keep role cleanups
    // unconditional or this reset starts losing clear signals.
    this->event_state_->drain_generation++;
    this->event_state_->inbox.reset_events();
    this->event_state_->group_slot.reset();

    // Also wipes any not-yet-dispatched pairing/PIN listener notifications. Callers that need a
    // notification to survive teardown (e.g. handle_pair_abort's on_pairing_failed /
    // on_clear_pairing_pin) must call the corresponding note_*() AFTER cleanup_connection_state()
    // returns, never before; see the ConnectionManager pairing/PIN handlers.
    this->event_state_->pairing_notes.clear();

    // The trust level is per-connection state: with no active connection there is nothing to
    // trust, so the getter reports NONE until the next handshake completes.
    this->current_trust_ = ConnectionTrust::NONE;

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

std::string SendspinClient::build_hello_message(const SendspinConnection* conn) {
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

    // trust_level: USER iff the PSK the Noise handshake matched is a long-term (paired)
    // record; NONE for Sentinel/Pairing PSKs or when no Noise handshake ran on this
    // connection at all (encryption not required).
    msg.trust_level = (conn != nullptr && conn->get_psk_category() == PskCategory::LONG_TERM)
                          ? ConnectionTrust::USER
                          : ConnectionTrust::NONE;

    // Advertise supported pair methods from the record store. pairing_psk needs an actual
    // Pairing PSK behind it (normally auto-provisioned on first boot): advertising the method
    // without one offers a server a flow whose handshake could only miss.
    if (this->record_store_ && this->record_store_->pairing_psk_enabled() &&
        this->record_store_->pairing_psk().has_value()) {
        PairMethodDescriptor psk_desc;
        psk_desc.method = SendspinPairMethod::PAIRING_PSK;
        psk_desc.locations = locations_hint(this->config_.pairing_psk_locations,
                                            this->record_store_->pairing_psk_rotated());
        msg.supported_pair_methods.push_back(std::move(psk_desc));
    }
    // Advertise dynamic_pin when enabled and the platform can display a PIN. An escalated
    // failure counter does NOT drop the method from the hello: escalation only gesture-gates
    // attempts (spec: Failure counter), it is not an error state.
    if (this->config_.pin_display_supported && this->record_store_ &&
        this->record_store_->dynamic_pin_enabled()) {
        PairMethodDescriptor dyn_pin;
        dyn_pin.method = SendspinPairMethod::DYNAMIC_PIN;
        dyn_pin.out_channels = std::vector<std::string>{"display"};
        dyn_pin.min_pin_length = this->record_store_->dynamic_pin_min_length();
        msg.supported_pair_methods.push_back(std::move(dyn_pin));
    }
    // Advertise static_pin when enabled, the platform supports the pairing-window gesture, and a
    // static PIN is configured. out_channels and min_pin_length are set only for DYNAMIC_PIN, so
    // static_pin carries neither; locations is its only optional hint.
    if (this->config_.pairing_window_supported && this->record_store_ &&
        this->record_store_->static_pin_enabled() &&
        this->record_store_->static_pin().has_value()) {
        PairMethodDescriptor static_pin_desc;
        static_pin_desc.method = SendspinPairMethod::STATIC_PIN;
        static_pin_desc.locations = locations_hint(this->config_.static_pin_locations,
                                                   this->record_store_->static_pin_rotated());
        msg.supported_pair_methods.push_back(std::move(static_pin_desc));
    }

    msg.unpaired_access_enabled =
        this->record_store_ != nullptr && this->record_store_->unpaired_access_enabled();

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

namespace {

/// @brief Whether a server message may only be acted on when it comes from the admitted
/// (current) connection.
///
/// True for everything that drives the shared, client-global role state. Completing the Noise
/// handshake is NOT authorization to do that: the Sentinel PSK is a spec constant that
/// RecordStore::resolve_by_psk_id() accepts unconditionally, so any peer on the network can
/// finish a handshake and sit in the nursery. Whether its PSK category actually permits the
/// PLAYBACK activity is decided by admission (see admission.h), which runs on the main loop when
/// server/activate arrives, so until this connection holds the admitted slot, none of these
/// messages may touch a role.
///
/// False for the establishment and trust-negotiation traffic a connection must be able to send
/// before it is admitted (hello, activate, in-band re-handshake), and for the pairing and
/// management messages, which carry their own gating on the main loop (management additionally
/// requires the MANAGEMENT activity, which is itself only reachable through admission).
bool requires_admitted_connection(SendspinServerToClientMessageType type) {
    switch (type) {
        case SendspinServerToClientMessageType::SERVER_STATE:
        case SendspinServerToClientMessageType::SERVER_COMMAND:
        case SendspinServerToClientMessageType::STREAM_START:
        case SendspinServerToClientMessageType::STREAM_END:
        case SendspinServerToClientMessageType::STREAM_CLEAR:
        case SendspinServerToClientMessageType::GROUP_UPDATE:
            return true;
        default:
            return false;
    }
}

}  // namespace

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

    // Admission gate for role-bound traffic. Dropped silently rather than closing the
    // connection: a nursery member that is still racing toward promotion, or one that just lost
    // arbitration, is not misbehaving, and the establish/re-prove watchdogs already reap a
    // connection that never gets admitted.
    if (requires_admitted_connection(message_type) && (conn == nullptr || !conn->is_admitted())) {
        SS_LOGW(TAG, "Ignoring role message from a connection that is not admitted (server_id=%s)",
                conn != nullptr ? conn->get_server_id().c_str() : "?");
        return;
    }

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
                // server_id comes from the Noise handshake result (already set on the
                // connection); server/hello only carries the display name.
                if (conn != nullptr) {
                    ServerInformationObject info = conn->get_server_information();
                    info.name = hello_msg.name;
                    conn->set_server_information(std::move(info));
                    // Set last: this atomic store publishes the field above to the manager's
                    // promotion scan on the main loop, which observes is_handshake_complete()
                    // and establishes the connection; nothing needs to be scheduled here.
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
                    // This runs on the network thread. The connection's activity state
                    // (activities_/active_roles_/first_activate_received_) is read on the main
                    // loop, so defer the mutation there: carry the parsed payload in the event
                    // and let ConnectionManager::loop() apply it (and decide is_first, trust
                    // enforcement, and admission arbitration) on the main thread.
                    SS_LOGD(TAG, "server/activate received (activities_count=%zu)",
                            activate_msg.activities.size());
                    this->connection_manager_->schedule_activate(
                        {conn->shared_from_this(), std::move(activate_msg.activities),
                         std::move(activate_msg.active_roles), activate_msg.pairing_method,
                         activate_msg.pairing_pin_length});
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::NOISE_HANDSHAKE: {
            // In-band re-handshake initiated by the server. This runs on the
            // network thread (same thread as decrypt), so no lock is needed on this side; the
            // NoiseTransport session mutex is only acquired inside handle_noise_rehandshake for
            // the encrypt + swap.
            if (conn != nullptr) {
                SS_LOGI(TAG, "noise/handshake received in-band: starting re-handshake");
                std::string msg1_json(data, len);
                if (conn->handle_noise_rehandshake(msg1_json)) {
                    // handle_noise_rehandshake() reset server_hello_received_/
                    // client_hello_sent_/first_activate_received_ so the hello cycle re-runs
                    // under the new session keys, but nothing else ever re-sends client/hello
                    // for a connection outside the nursery. Defer the re-arm to the main loop,
                    // matching every other cross-thread connection-state mutation.
                    this->connection_manager_->schedule_rehandshake_rearm(conn->shared_from_this());
                } else {
                    SS_LOGW(TAG, "noise/handshake re-handshake failed; closing connection");
                    // Close the WebSocket silently (do not leave a half-swapped session).
                    // UNAUTHORIZED is the closest available reason for a crypto failure, though
                    // close_silently() never actually transmits it (spec "Failure Handling":
                    // close without any application-level message). This handler runs on the
                    // network thread, so disconnect() here would be the same
                    // join-the-calling-thread deadlock/std::terminate() hazard close_silently()
                    // was added to avoid; see close_transport_now()'s doc comment in
                    // connection.h.
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
        case SendspinServerToClientMessageType::SERVER_PAIR_FINALIZE: {
            // server/pair-finalize: server acked our client/pair-finalize.
            // Commit the pending pairing record synchronously HERE (network thread), NOT deferred
            // to the main loop: the server rekeys onto the new long-term PSK immediately after
            // this ack, and its re-handshake msg1 (the next message on this same thread) resolves
            // that PSK against the RecordStore. The record must therefore be stored before this
            // handler returns, else the re-handshake sees an unknown psk_id and aborts.
            // RecordStore is thread-safe (its mutators lock).
            // The payload is spec'd as empty; the message-type dispatch above is the only
            // validation this message needs.
            if (conn != nullptr) {
                auto record = conn->take_pending_pairing_record();
                bool stored_record = false;
                if (record.has_value() && this->record_store_ != nullptr) {
                    const std::string psk_id = record->psk_id;
                    // store_record_superseding() persists to the provider before mutating
                    // in-memory state and fails closed, so a provider rejection (full storage,
                    // write error) leaves the record unstored and is never reported as a
                    // successful pairing. Nothing further is needed to unwind the connection:
                    // the server rekeys onto this PSK regardless (it already acked
                    // pair-finalize), and since the client does not hold it, the follow-up
                    // re-handshake fails to resolve the psk_id and drops the connection
                    // (noise_handshake.cpp) -- or, if the server never sends it, the re-prove
                    // watchdog re-armed below does.
                    //
                    // The superseding form is correct here and only here: this PSK replaces
                    // whatever this server held before, so the prior record for the same
                    // server_id must be retired or the old PSK stays valid forever.
                    // management/add-record deliberately uses the plain store_record().
                    if (this->record_store_->store_record_superseding(std::move(record.value()))) {
                        SS_LOGI(TAG, "server/pair-finalize: storing pairing record (psk_id=%s)",
                                psk_id.c_str());
                        stored_record = true;
                    } else {
                        SS_LOGW(TAG,
                                "server/pair-finalize: failed to persist pairing record "
                                "(psk_id=%s); the pairing cannot survive a reboot and the "
                                "server's re-handshake onto it will fail",
                                psk_id.c_str());
                    }
                } else {
                    SS_LOGI(TAG, "server/pair-finalize: no record to store "
                                 "(shared-PSK fallback or no pending pairing)");
                }
                // Defer on_pairing_succeeded to the main loop via the same
                // pending_*_events_ / has_pending_events_ idiom every other cross-thread
                // connection-state mutation in ConnectionManager uses. Only fire when an
                // actual long-term record was stored (not the shared-PSK fallback case, and
                // not when the provider rejected the record).
                if (stored_record) {
                    this->connection_manager_->schedule_pairing_succeeded(conn->get_server_id());
                }
                // Re-arm the provisional timeout so the 30 s watchdog fires if the server
                // acks but never sends the in-band re-handshake that follows pair-finalize.
                conn->note_pairing_finalize_ack();
            }
            break;
        }
        case SendspinServerToClientMessageType::PAIR_ABORT: {
            // pair/abort: the server aborted the pairing exchange.
            // Parse the reason and defer cleanup to the main loop.
            if (conn != nullptr) {
                PairAbortMessage abort_msg;
                if (process_pair_abort_message(root, &abort_msg)) {
                    SS_LOGW(TAG, "pair/abort received: reason=%s", to_cstr(abort_msg.reason));
                    this->connection_manager_->schedule_pair_abort(
                        {conn->shared_from_this(), abort_msg.reason});
                } else {
                    // pair/abort must always trigger cleanup even if the reason is unrecognized,
                    // hence the fallback schedule with METHOD_NOT_SUPPORTED (intentionally
                    // different from the drop-and-ignore used for malformed management messages).
                    SS_LOGW(TAG, "Malformed pair/abort message; treating as abort with "
                                 "method_not_supported");
                    this->connection_manager_->schedule_pair_abort(
                        {conn->shared_from_this(), PairAbortReason::METHOD_NOT_SUPPORTED});
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_UNPAIR: {
            // server/unpair: parse and defer to the main loop.
            // Trust gating (LONG_TERM only) happens in handle_server_unpair on the main loop.
            if (conn != nullptr) {
                ServerUnpairEvent event;
                event.conn = conn->shared_from_this();
                event.matched_psk_id = conn->get_psk_id();
                event.psk_category = conn->get_psk_category();
                SS_LOGI(TAG, "server/unpair received (psk_id=%s)", event.matched_psk_id.c_str());
                this->connection_manager_->schedule_server_unpair(std::move(event));
            }
            break;
        }
        case SendspinServerToClientMessageType::MANAGEMENT_LIST_RECORDS: {
            if (conn != nullptr) {
                ManagementRequestEvent event;
                event.conn = conn->shared_from_this();
                event.kind = ManagementRequestKind::LIST_RECORDS;
                this->connection_manager_->schedule_management_request(std::move(event));
            }
            break;
        }
        case SendspinServerToClientMessageType::MANAGEMENT_ADD_RECORD: {
            if (conn != nullptr) {
                ManagementRequestEvent event;
                if (process_management_add_record_message(root, &event.add_payload)) {
                    event.conn = conn->shared_from_this();
                    event.kind = ManagementRequestKind::ADD_RECORD;
                    this->connection_manager_->schedule_management_request(std::move(event));
                } else {
                    SS_LOGW(TAG, "Malformed management/add-record; ignoring");
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::MANAGEMENT_REMOVE_RECORD: {
            if (conn != nullptr) {
                ManagementRequestEvent event;
                if (process_management_remove_record_message(root, &event.remove_payload)) {
                    event.conn = conn->shared_from_this();
                    event.kind = ManagementRequestKind::REMOVE_RECORD;
                    this->connection_manager_->schedule_management_request(std::move(event));
                } else {
                    SS_LOGW(TAG, "Malformed management/remove-record; ignoring");
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::MANAGEMENT_GET_PAIRING_CONFIG: {
            if (conn != nullptr) {
                ManagementRequestEvent event;
                event.conn = conn->shared_from_this();
                event.kind = ManagementRequestKind::GET_PAIRING_CONFIG;
                this->connection_manager_->schedule_management_request(std::move(event));
            }
            break;
        }
        case SendspinServerToClientMessageType::MANAGEMENT_SET_PAIRING_CONFIG: {
            if (conn != nullptr) {
                ManagementRequestEvent event;
                if (process_management_set_pairing_config_message(root,
                                                                  &event.set_config_payload)) {
                    event.conn = conn->shared_from_this();
                    event.kind = ManagementRequestKind::SET_PAIRING_CONFIG;
                    this->connection_manager_->schedule_management_request(std::move(event));
                } else {
                    SS_LOGW(TAG, "Malformed management/set-pairing-config; ignoring");
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::MANAGEMENT_OPEN_PAIRING_WINDOW: {
            // No payload fields; opens a pairing window in place of the operator gesture.
            if (conn != nullptr) {
                ManagementRequestEvent event;
                event.conn = conn->shared_from_this();
                event.kind = ManagementRequestKind::OPEN_PAIRING_WINDOW;
                this->connection_manager_->schedule_management_request(std::move(event));
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_PAIR_INIT: {
            // server/pair-init: nonce_A from the server (the session pin_length arrived in the
            // activation's pairing object). Parse on the network thread; PIN state machine runs
            // on the main loop.
            if (conn != nullptr) {
                ServerPairInitPayload payload;
                if (process_server_pair_init_message(root, &payload)) {
                    ServerPairingMessageEvent event;
                    event.conn = conn->shared_from_this();
                    event.kind = PinPairingMessageKind::PAIR_INIT;
                    event.nonce_a = payload.nonce_a;
                    this->connection_manager_->schedule_pin_pairing_message(std::move(event));
                } else {
                    SS_LOGW(TAG, "Malformed server/pair-init; aborting any active PIN pairing");
                    ServerPairingMessageEvent event;
                    event.conn = conn->shared_from_this();
                    event.kind = PinPairingMessageKind::MALFORMED;
                    this->connection_manager_->schedule_pin_pairing_message(std::move(event));
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_PAIR_AUTH: {
            // server/pair-auth: server CPace share.
            if (conn != nullptr) {
                ServerPairAuthPayload payload;
                if (process_server_pair_auth_message(root, &payload)) {
                    ServerPairingMessageEvent event;
                    event.conn = conn->shared_from_this();
                    event.kind = PinPairingMessageKind::PAIR_AUTH;
                    event.pake_msg_1 = payload.pake_msg_1;
                    this->connection_manager_->schedule_pin_pairing_message(std::move(event));
                } else {
                    SS_LOGW(TAG, "Malformed server/pair-auth; aborting any active PIN pairing");
                    ServerPairingMessageEvent event;
                    event.conn = conn->shared_from_this();
                    event.kind = PinPairingMessageKind::MALFORMED;
                    this->connection_manager_->schedule_pin_pairing_message(std::move(event));
                }
            }
            break;
        }
        case SendspinServerToClientMessageType::SERVER_PAIR_CONFIRM: {
            // server/pair-confirm: server CPace confirmation tag.
            if (conn != nullptr) {
                ServerPairConfirmPayload payload;
                if (process_server_pair_confirm_message(root, &payload)) {
                    ServerPairingMessageEvent event;
                    event.conn = conn->shared_from_this();
                    event.kind = PinPairingMessageKind::PAIR_CONFIRM;
                    event.server_kc = payload.server_kc;
                    this->connection_manager_->schedule_pin_pairing_message(std::move(event));
                } else {
                    SS_LOGW(TAG, "Malformed server/pair-confirm; aborting any active PIN pairing");
                    ServerPairingMessageEvent event;
                    event.conn = conn->shared_from_this();
                    event.kind = PinPairingMessageKind::MALFORMED;
                    this->connection_manager_->schedule_pin_pairing_message(std::move(event));
                }
            }
            break;
        }
        default:
            SS_LOGW(TAG, "Unhandled server message type: %s",
                    root["type"].is<const char*>() ? root["type"].as<const char*>() : "unknown");
    }
}

SS_HOT void SendspinClient::process_binary_message(const SendspinConnection* conn,
                                                   const uint8_t* payload, size_t len) {
    if (len < 2) {
        return;
    }

    // Every binary message feeds a role, so the same admission gate as the role-bound JSON
    // messages applies; see requires_admitted_connection().
    if (conn == nullptr || !conn->is_admitted()) {
        SS_LOGW(TAG, "Ignoring binary message from a connection that is not admitted");
        return;
    }

    uint8_t binary_type = payload[0];
    uint8_t role = get_binary_role(binary_type);

    // Strip the type byte; each role parses its own binary format from here. Only declared when
    // at least one role below actually consumes it, so an all-roles-disabled (or
    // player+artwork-disabled, with visualizer also off) build does not warn/error on an unused
    // variable under -Werror.
#if defined(SENDSPIN_ENABLE_PLAYER) || defined(SENDSPIN_ENABLE_ARTWORK) || \
    defined(SENDSPIN_ENABLE_VISUALIZER)
    const uint8_t* data = payload + 1;
    size_t data_len = len - 1;
#endif

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
                uint8_t slot = get_binary_slot(binary_type);
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
                uint8_t slot = get_binary_slot(binary_type);
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

    // Gate on receipt of the first server/activate: before that we do not yet know which
    // activities/roles this connection is admitted for.
    if (!conn->first_activate_received()) {
        return;
    }

    // Suppress client/state while a pairing exchange is in progress (mirrors _pause_time_sync).
    if (conn->is_pairing_in_progress()) {
        return;
    }

    ClientStateMessage state_msg;
    state_msg.state = this->state_;

#ifdef SENDSPIN_ENABLE_PLAYER
    if (this->player_ && conn->is_role_active("player")) {
        this->player_->impl_->build_state_fields(state_msg);
    }
#endif

    std::string state_message = format_client_state_message(&state_msg);
    conn->send_app_json(state_message, nullptr);
}

// ============================================================================
// Persistence & identity
// ============================================================================

bool SendspinClient::load_or_generate_identity() {
    if (this->persistence_provider_ != nullptr) {
        auto saved_priv = this->persistence_provider_->load_blob(persistence_keys::KEYPAIR);
        // No codec involved: the keypair blob is exactly 32 raw bytes, so the only validation
        // needed here is the exact-length check: anything else is corrupt or the wrong key.
        if (saved_priv.has_value() && saved_priv->size() == 32) {
            std::array<uint8_t, 32> priv_bytes{};
            std::copy(saved_priv->begin(), saved_priv->end(), priv_bytes.begin());
            auto loaded = Identity::from_private_bytes(priv_bytes);
            // The raw private key has been consumed, so wipe the two transient copies of it now
            // instead of leaving them on the stack/heap until their frames are reused. Every
            // Identity-shaped copy (`loaded`, and the one make_unique takes below) wipes itself
            // via ~Identity(); these two are the plain byte buffers that cannot.
            secure_zero_container(priv_bytes);
            secure_zero_container(saved_priv.value());
            if (loaded.has_value()) {
                this->identity_ = std::make_unique<Identity>(loaded.value());
                this->client_id_ = this->identity_->peer_id();
                SS_LOGI(TAG, "Loaded static keypair; client_id=%s", this->client_id_.c_str());
                return true;
            }
            // Stored key is corrupt, or the underlying DH computation failed; do not use it
            // and do not treat this as an all-zero identity. Fall through and generate a fresh
            // identity (the device will need to re-pair) rather than proceeding with a
            // predictable/zero key.
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
                                                   this->identity_->private_bytes.size())) {
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

    auto server_id_blob = this->persistence_provider_->load_blob(persistence_keys::LAST_PLAYED);
    if (server_id_blob.has_value() && !server_id_blob->empty()) {
        std::string server_id(server_id_blob->begin(), server_id_blob->end());
        this->connection_manager_->set_last_played_server_id(server_id);
        SS_LOGI(TAG, "Loaded last played server: %s", server_id.c_str());
    }
}

void SendspinClient::persist_last_played_server(const std::string& server_id) {
    if (server_id.empty()) {
        return;
    }

    // Skip the setter and the write when the server_id is unchanged (including the boot-time
    // value seeded by load_last_played_server()), bounding flash writes to one per actual
    // handoff instead of one per PLAYING transition.
    if (server_id == this->connection_manager_->last_played_server_id()) {
        return;
    }

    this->connection_manager_->set_last_played_server_id(server_id);

    if (this->persistence_provider_) {
        if (this->persistence_provider_->save_blob(
                persistence_keys::LAST_PLAYED, reinterpret_cast<const uint8_t*>(server_id.data()),
                server_id.size())) {
            SS_LOGD(TAG, "Persisted last played server: %s", server_id.c_str());
        } else {
            SS_LOGW(TAG, "Failed to persist last played server");
        }
    }
}

// ============================================================================
// Connection event handlers (called by ConnectionManager via friend access)
// ============================================================================

void SendspinClient::on_handshake_complete(SendspinConnection* conn) {
    // Entering the operational state structurally ends any pairing exchange: discard the pending
    // pairing record and reset the PIN session so a stale attempt timeout can never fire a stray
    // pair/abort on an operational connection. Folding this in here, the one place every
    // "connection is now operational" path converges (normal activate, leftover activate, and
    // winning promotion), makes it impossible for a future PAIRING/REKEYING transition to leave a
    // stale PIN session behind. Safe because on_handshake_complete() only ever runs on the main
    // loop, where the main-loop-only pin_session_ may be touched. Idempotent no-op for a
    // connection that never paired.
    if (conn != nullptr) {
        conn->clear_pairing_state();
    }

    this->publish_client_state(conn);

    // Queue the trust level for the newly admitted connection. The callback is fired from loop()
    // after connection_manager_->loop() returns, so it runs without conn_ptr_mutex_ held (this
    // method is called with that lock held) and a listener may safely call back into the client.
    if (conn != nullptr) {
        ConnectionTrust trust = (conn->get_psk_category() == PskCategory::LONG_TERM)
                                    ? ConnectionTrust::USER
                                    : ConnectionTrust::NONE;
        this->current_trust_ = trust;
        this->event_state_->pairing_notes.push_back(
            {.type = PairingNoteType::TRUST_CHANGED, .trust = trust});
    }
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

void SendspinClient::note_display_pin(const std::string& pin) {
    this->event_state_->push_pairing_note({.type = PairingNoteType::DISPLAY_PIN, .text = pin});
}

void SendspinClient::note_clear_pin() {
    this->event_state_->push_pairing_note({.type = PairingNoteType::CLEAR_PIN});
}

void SendspinClient::note_open_pairing_window() {
    this->event_state_->push_pairing_note({.type = PairingNoteType::OPEN_PAIRING_WINDOW});
}

void SendspinClient::note_close_pairing_window() {
    this->event_state_->push_pairing_note({.type = PairingNoteType::CLOSE_PAIRING_WINDOW});
}

void SendspinClient::confirm_pairing_window() {
    this->connection_manager_->schedule_pairing_window_confirm();
}

}  // namespace sendspin
