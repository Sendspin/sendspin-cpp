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

/// @file metadata_role_impl.h
/// @brief Private implementation for the metadata role (pimpl)

#pragma once

#include "inbox.h"
#include "protocol_messages.h"
#include "sendspin/metadata_role.h"

#include <atomic>
#include <memory>
#include <optional>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief Metadata states handed to the main loop but not yet drained
///
/// messaging.md "server/state" lets a server bring a client up to date and then schedule the next
/// update straight after it, so two states can land between two main-loop ticks. Both are kept,
/// in arrival order, so the current one is still applied on the tick that also takes the
/// scheduled one. A third state in the same window replaces `newest`, which no observer has seen.
struct PendingMetadataStates {
    std::optional<ServerMetadataStateObject> oldest;
    std::optional<ServerMetadataStateObject> newest;
};

/// @brief Private implementation of the metadata role
struct MetadataRole::Impl {
    explicit Impl(SendspinClient* client);
    ~Impl() = default;

    // ========================================
    // Event state
    // ========================================

    struct EventState {
        InboxSlot<PendingMetadataStates> slot;
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    void build_hello_fields(ClientHelloMessage& msg);
    void handle_server_state(ServerMetadataStateObject&& metadata, uint32_t generation) const;
    // True if a slot state needs taking, or a state already held from a prior tick (see
    // held_state) is still waiting out its server-clock deadline: the deadline itself sets no
    // inbox bit, so held_state must be polled every tick until it fires.
    bool needs_drain(uint32_t pending_bits) const {
        return (pending_bits & INBOX_TOPIC_METADATA) != 0 || this->held_state.has_value();
    }
    void drain_events();
    /// Whether a state's server-clock deadline has passed on the synchronized client clock.
    bool state_is_due(int64_t timestamp) const;
    /// Applies the held state and fires the listener once its server-clock deadline has passed.
    void apply_due_state();
    void handle_cleared_event() const;
    /// @brief Whether an effect the receive gate admitted at `generation` may still be applied
    ///
    /// The gate in SendspinClient's role dispatch is checked once, before the handler it admits
    /// runs, and stop()'s teardown on the main loop can land in between. Re-checking at each point
    /// of effect invalidates the whole handler instead of only the part that ran before it.
    /// @param generation The counter value captured when the message was admitted.
    bool accepts(uint32_t generation) const {
        return generation == this->cleanup_generation.load(std::memory_order_acquire);
    }

    /// @brief Stops the role and discards the state the protocol task can reach. Protocol task,
    /// or the main loop in SendspinClient::stop() once every other thread is joined.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). The listener's clear callback
    /// is queued on the inbox, stamped with the new generation, and the main-loop state is reset
    /// by complete_teardown() at the head of the next drain (catch_up_teardown()).
    void cleanup();

    /// @brief Resets the state only the main loop touches, for a teardown cleanup() ran. Main
    /// loop only, through catch_up_teardown().
    void complete_teardown();

    /// @brief Runs complete_teardown() once for every teardown generation the main loop has not
    /// caught up with. Main loop only: called at the head of each drain with the current
    /// generation, and with a stamped event's generation before that event is acted on, so the
    /// reset always lands ahead of the state the next connection sends.
    void catch_up_teardown(uint32_t generation) {
        if (generation != this->completed_generation) {
            this->completed_generation = generation;
            this->complete_teardown();
        }
    }

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    uint32_t get_track_duration_ms() const;
    uint32_t get_track_progress_ms() const;

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    ServerMetadataStateObject metadata{};
    // State taken from the inbox slot, awaiting its server-clock deadline. Main-thread only:
    // written and read exclusively from drain_events()/complete_teardown() on the loop thread.
    std::optional<ServerMetadataStateObject> held_state;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    MetadataRoleListener* listener{nullptr};

    // 32-bit fields
    /// @brief Teardown generation, bumped by cleanup() and re-checked at every point of effect
    /// (see accepts()). Atomic because the protocol task reads it.
    std::atomic<uint32_t> cleanup_generation{0};
    /// The teardown generation complete_teardown() last ran for. Main loop only.
    uint32_t completed_generation{0};
};

}  // namespace sendspin
