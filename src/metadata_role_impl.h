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
#include "platform/memory.h"
#include "protocol_messages.h"
#include "reserved_text.h"
#include "scheduled_state_slot.h"
#include "sendspin/metadata_role.h"
#include "teardown_tracker.h"
#include <ArduinoJson.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace sendspin {

class SendspinClient;
struct ClientHelloMessage;

/// @brief Text blocks a metadata role keeps, one state's kept text each (MetadataTextLayout): one
/// for each place a state can be, the slot's oldest and newest places and the main loop's current
/// state (ScheduledStateSlot). Each place names its block by index; a delivery swaps the
/// delivered place's block with the current state's, so each block always has one place.
constexpr uint8_t METADATA_TEXT_BLOCKS = 3;

/// @brief A metadata state and the text block it names, an index into the role's text blocks;
/// the block stays with the place when the place holds no state
struct MetadataStateBuffer {
    MetadataStatePayload payload{};
    uint8_t block{0};
};

/// @brief The server-clock timestamp `state` applies at (ScheduledStateSlot)
inline int64_t scheduled_time(const MetadataStateBuffer& state) {
    return state.payload.timestamp;
}

/// @brief Private implementation of the metadata role
struct MetadataRole::Impl : RoleTeardown {
    Impl(MetadataRoleConfig config, SendspinClient* client);
    ~Impl() = default;

    // ========================================
    // Event state
    // ========================================

    /// The block each place names at first: the slot's oldest and newest places, then the
    /// current state
    static constexpr uint8_t OLDEST_FIRST_BLOCK = 0;
    static constexpr uint8_t NEWEST_FIRST_BLOCK = 1;
    static constexpr uint8_t CURRENT_FIRST_BLOCK = 2;
    static_assert(CURRENT_FIRST_BLOCK + 1 == METADATA_TEXT_BLOCKS,
                  "one block for each place a state can be");

    struct EventState {
        ScheduledStateSlot<MetadataStateBuffer> slot{
            MetadataStateBuffer{.block = OLDEST_FIRST_BLOCK},
            MetadataStateBuffer{.block = NEWEST_FIRST_BLOCK}};
    };

    // ========================================
    // Internal integration methods (called by SendspinClient)
    // ========================================

    void attach_inbox(Inbox& inbox);
    /// @brief Allocates the text blocks, once: they are kept across restarts, since the states
    /// that own them hold only their indices. Main loop, from SendspinClient::start().
    /// @return false (logged) when they cannot be allocated, which fails the start.
    bool start();
    void build_hello_fields(ClientHelloMessage& msg);
    /// @brief Parses a server/state metadata object and hands it to the slot, copying its kept
    /// text from the document into the block of the place it takes (fill_place()). Protocol task,
    /// inside ParsedJsonMessage::extract(), the only window the document is alive.
    /// @return What the parse made of it; a REJECTED or IGNORED object reaches no slot.
    MetadataStateOutcome handle_server_state(JsonObject root);
    /// @brief Writes `parsed` into `place`, its text into the block `place` names. Runs under the
    /// Inbox mutex (ScheduledStateSlot::arrive()): a pure data copy of at most a text block, the
    /// largest critical section the Inbox has.
    void fill_place(MetadataStateBuffer& place, const MetadataStateView& parsed);
    /// @brief True if a state arrived, or the pending state the last drain left in the slot has
    /// come due: the deadline sets no inbox bit, so it is checked every tick, against
    /// ScheduledStateSlot::pending_at(), without the Inbox mutex.
    bool needs_drain(uint32_t pending_bits) const {
        const std::optional<int64_t> pending_at = this->event_state->slot.pending_at();
        return (pending_bits & INBOX_TOPIC_METADATA) != 0 ||
               (pending_at.has_value() && this->state_is_due(*pending_at));
    }
    /// @brief Catches the role up on any teardown (complete_teardown()), then applies whichever
    /// state the slot holds is due (drain_scheduled_state()). Main loop.
    void drain_events();
    /// Whether a state's server-clock deadline has passed on the synchronized client clock.
    bool state_is_due(int64_t timestamp) const;
    /// @brief Hands the current state to on_track_metadata(), then to the deprecated
    /// on_metadata() unless the first call re-entered teardown. Main loop, with no lock held.
    void apply_current_state();
    /// @brief The public view of the current state, its text viewing the current block. Main loop.
    TrackMetadata track_metadata() const;
    /// @brief Fills the deprecated public state from the current state, keeping the text storage.
    /// Main loop.
    void fill_deprecated_state();
    /// @brief The text `state` carries for `field`, viewing its block; nullopt when it carries
    /// none
    std::optional<std::string_view> text_of(const MetadataStateBuffer& state,
                                            MetadataField field) const;

    /// @brief Stops the role and discards the state the protocol task can reach. Protocol task,
    /// or the main loop in SendspinClient::stop() once every other thread is joined.
    ///
    /// Shared by the two paths that take the role out of service: a connection being torn down
    /// (SendspinClient::cleanup_connection_state()) and a server/activate that removes the role
    /// from active_roles (SendspinClient::apply_role_removals()). Queues a METADATA_CLEARED event
    /// stamped with the new generation; the main loop runs complete_teardown() for it
    /// (catch_up_teardown()).
    void cleanup();

    /// @brief The main-loop teardown half: empties the current state, keeping its block, and the
    /// deprecated public state, and fires on_metadata_clear(). Main loop only, through
    /// catch_up_teardown().
    void complete_teardown();

    // ========================================
    // Consumer-facing method implementations
    // ========================================

    uint32_t get_track_duration_ms() const;
    uint32_t get_track_progress_ms() const;

    // ========================================
    // Fields
    // ========================================

    // Struct fields
    MetadataRoleConfig config;
    /// The kept fields and where each lies in a text block. Fixed from add_metadata().
    MetadataTextLayout layout;
    /// METADATA_TEXT_BLOCKS blocks of layout.block_bytes, allocated by start(); empty when no
    /// field is kept.
    PlatformBuffer text_blocks;
    /// The state the last delivery handed over, which the listener and the progress getters read.
    /// Main loop only; the slot's commit swaps it, under the Inbox mutex, for the state it
    /// delivers.
    MetadataStateBuffer current{.block = CURRENT_FIRST_BLOCK};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    /// The deprecated public state on_metadata() is handed, filled from the current state. Main
    /// loop only.
    ServerMetadataStateObject metadata{};
#pragma GCC diagnostic pop
    /// Storage for the deprecated public state's text fields, reserved for each kept field's cap.
    /// Main loop only.
    std::array<ReservedText, METADATA_FIELD_COUNT> metadata_text;

    // Pointer fields
    SendspinClient* client;
    std::unique_ptr<EventState> event_state;
    Inbox* inbox{nullptr};
    MetadataRoleListener* listener{nullptr};
};

}  // namespace sendspin
