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

/// @file scheduled_state_slot.h
/// @brief The inbox slot of a role whose server/state object applies at its server-clock
/// timestamp, and the drain shared by those roles

#pragma once

#include "inbox.h"
#include "teardown_tracker.h"

#include <cstdint>
#include <optional>
#include <utility>

namespace sendspin {

/**
 * @brief Generation-stamped inbox slot for a role whose state applies at its server-clock
 * timestamp: the states the protocol task hands the main loop, and the one a drain left waiting
 *
 * roles/metadata/v1.md "Scheduled metadata updates" and roles/color/v1.md "Scheduled color
 * updates": a state whose timestamp is still in the future is the pending update and a newer one
 * replaces it, while a past or present one is applied at once and discards the pending update.
 * messaging.md "server/state" lets a server bring a client up to date and then schedule the next
 * update straight after it, so two states can land between two drains. Both are kept, in arrival
 * order, in the oldest and newest places, so the current one is still applied on the tick that
 * also takes the scheduled one. A third state in the same window replaces the newest, which no
 * observer has seen, and a state that finds the pending one replaces it.
 *
 * The pending state waits here, in the oldest place, rather than with the main loop. A drain
 * (drain_scheduled_state()) peeks at the timestamps under the Inbox mutex, decides with no lock
 * held, since a deadline reads the client clock behind a lock of its own (see Inbox), and commits
 * under the mutex only if nothing arrived or was reset since the peek. So a state is never copied
 * out to be decided on: a commit hands the delivered one over through `deliver`, which for a
 * state whose content lies elsewhere trades storage rather than copying it.
 *
 * Every arrival keeps the newest generation's states, as GenerationSlot does: one stamped with a
 * later generation than the held states discards them, and one stamped with an earlier generation
 * is dropped, so a producer that lost a race with a teardown cannot revive what the teardown
 * discarded.
 *
 * `State` is a place's storage. A discard keeps it and only marks the place empty, so a State that
 * names storage of its own (a metadata state's text block) keeps naming it, and the places and
 * whatever `deliver` trades with always hold distinct storage. `scheduled_time(const State&)`,
 * found by argument-dependent lookup, returns the server-clock timestamp it applies at.
 */
template <typename State>
class ScheduledStateSlot {
public:
    /// @brief A place of the slot
    enum class Place : uint8_t {
        NONE,
        OLDEST,
        NEWEST,
    };

    /// @brief What a drain decides on, copied out under the Inbox mutex: the timestamps and stamp,
    /// never the states
    struct Peek {
        /// The oldest place's timestamp, when it holds a state
        std::optional<int64_t> oldest;
        /// The newest place's timestamp, when it holds a state; only ever beside an oldest
        std::optional<int64_t> newest;
        /// The teardown generation the states were admitted under
        uint32_t generation{0};
        /// Changes with every arrival and reset, so a commit can tell the slot changed
        uint32_t sequence{0};
    };

    /// @brief What a drain does with the states it peeked; every other state is discarded
    struct Decision {
        Place deliver{Place::NONE};  ///< The state applied now
        Place pending{Place::NONE};  ///< The state left waiting for its timestamp
    };

    ScheduledStateSlot() = default;

    /// @brief Constructs with the oldest and newest places holding the storage `oldest` and
    /// `newest` name
    ScheduledStateSlot(State oldest, State newest)
        : slot_(Places{.oldest = {.state = oldest}, .newest = {.state = newest}}) {}

    /// @brief Binds to `inbox` and the topic bit this slot owns exclusively (see InboxSlot::bind())
    void bind(Inbox& inbox, uint32_t topic_bit) {
        this->slot_.bind(inbox, topic_bit);
    }

    /// @brief Hands the main loop a state, which fill(State& place) writes into the place it takes:
    /// the oldest when the slot holds none or only the pending state, which it replaces, and the
    /// newest otherwise, replacing any state there. `fill` writes the content and keeps the
    /// storage the place names. Protocol task. `fill` runs under the Inbox mutex: a pure data
    /// operation only.
    /// @param generation The role's teardown generation the state was admitted under.
    template <typename FillFn>
    void arrive(FillFn&& fill, uint32_t generation) {
        this->slot_.update([&fill, generation](Places& places) {
            if (places.oldest.present && places.generation != generation) {
                if (!count_after(generation, places.generation)) {
                    return;  // Older than what is held: the teardown discarded it.
                }
                discard(places);
            }
            places.generation = generation;
            Entry& place = places.oldest.present && !places.pending ? places.newest : places.oldest;
            fill(place.state);
            place.present = true;
            places.pending = false;
            ++places.sequence;
        });
    }

    /// @brief The timestamps and stamp of the states the slot holds, pending or not. Main loop.
    Peek peek() const {
        return this->slot_.read([](const Places& places) {
            Peek peek;
            if (places.oldest.present) {
                peek.oldest = scheduled_time(places.oldest.state);
            }
            if (places.newest.present) {
                peek.newest = scheduled_time(places.newest.state);
            }
            peek.generation = places.generation;
            peek.sequence = places.sequence;
            return peek;
        });
    }

    /// @brief What to do with the states `peek` saw, by the rules in the class comment;
    /// is_due(timestamp) says whether a timestamp's moment has come, and is asked about the oldest
    /// only when the newest is not due. Runs with no lock held.
    template <typename IsDueFn>
    static Decision decide(const Peek& peek, IsDueFn&& is_due) {
        if (peek.newest.has_value() && is_due(*peek.newest)) {
            // Two states that are both due collapse instead: the older would be superseded within
            // this tick, so no listener could observe it.
            return {.deliver = Place::NEWEST, .pending = Place::NONE};
        }
        if (!peek.oldest.has_value()) {
            return {};
        }
        const Place later = peek.newest.has_value() ? Place::NEWEST : Place::NONE;
        if (is_due(*peek.oldest)) {
            return {.deliver = Place::OLDEST, .pending = later};
        }
        return {.deliver = Place::NONE, .pending = later != Place::NONE ? later : Place::OLDEST};
    }

    /// @brief Carries `decision` out unless the slot changed since `peek`: calls deliver(State&
    /// place) for the delivered state, discards every state but the pending one, which waits in
    /// the oldest place, and cleans the slot, keeping its timestamp as pending_at(). Main loop.
    /// `deliver` runs under the Inbox mutex: a pure data operation only.
    /// @return false, changing nothing, when a state arrived or the slot was reset after `peek`:
    /// decide again on a fresh peek.
    template <typename DeliverFn>
    bool commit(const Peek& peek, Decision decision, DeliverFn&& deliver) {
        bool committed = false;
        std::optional<int64_t> pending_at;
        this->slot_.settle([&](Places& places) {
            if (places.sequence != peek.sequence) {
                return true;  // Still pending: what arrived since the peek
            }
            if (decision.deliver != Place::NONE) {
                deliver(entry(places, decision.deliver).state);
            }
            if (decision.pending == Place::NEWEST) {
                std::swap(places.oldest, places.newest);
            }
            places.oldest.present = decision.pending != Place::NONE;
            places.newest.present = false;
            places.pending = places.oldest.present;
            if (places.pending) {
                pending_at = scheduled_time(places.oldest.state);
            }
            committed = true;
            return false;
        });
        if (committed) {
            this->pending_at_ = pending_at;
        }
        return committed;
    }

    /// @brief Discards every state, the pending one included. Protocol task, or the main loop in
    /// SendspinClient::stop() once every other thread is joined.
    void reset() {
        this->slot_.settle([](Places& places) {
            discard(places);
            ++places.sequence;
            return false;
        });
    }

    /// @brief The pending state's timestamp as the last commit left it, so a drain waiting for it
    /// takes no lock until it is due. Exact while the slot's topic bit is clear and its role has
    /// no teardown to catch up on. Main loop only.
    std::optional<int64_t> pending_at() const {
        return this->pending_at_;
    }

    /// @brief Forgets pending_at() for a teardown, whose cleanup() reset the slot. Main loop only,
    /// from the role's complete_teardown().
    void forget_pending() {
        this->pending_at_.reset();
    }

private:
    struct Entry {
        State state{};
        /// Whether `state` holds a state; false keeps the storage it names
        bool present{false};
    };

    struct Places {
        Entry oldest;
        Entry newest;
        /// Changes with every arrival and reset (Peek::sequence)
        uint32_t sequence{0};
        /// The teardown generation the held states were admitted under
        uint32_t generation{0};
        /// Whether `oldest` holds the state a drain left waiting for its timestamp
        bool pending{false};
    };

    static Entry& entry(Places& places, Place place) {
        return place == Place::NEWEST ? places.newest : places.oldest;
    }

    static void discard(Places& places) {
        places.oldest.present = false;
        places.newest.present = false;
        places.pending = false;
    }

    InboxSlot<Places> slot_;
    /// See pending_at(). Main loop only.
    std::optional<int64_t> pending_at_;
};

/// @brief The drain of a role whose state applies at its server-clock timestamp (see
/// ScheduledStateSlot): peeks at the slot, catches the role up on any teardown and keeps only
/// states stamped with its current generation (keep_current_payload()), decides with no lock held
/// (RoleImpl::state_is_due()), and commits, peeking again when the slot changed meanwhile. A
/// delivered state goes through deliver(State& place) under the Inbox mutex and then apply(), the
/// role's listener callback, outside it. Repeats while the state left pending has come due, so one
/// that falls due during the callback of the state before it is applied in the same tick. Main
/// loop.
template <typename RoleImpl, typename State, typename DeliverFn, typename ApplyFn>
void drain_scheduled_state(RoleImpl& role, ScheduledStateSlot<State>& slot, DeliverFn&& deliver,
                           ApplyFn&& apply, const char* tag, const char* what) {
    using Slot = ScheduledStateSlot<State>;
    const auto is_due = [&role](int64_t timestamp) { return role.state_is_due(timestamp); };
    for (;;) {
        const typename Slot::Peek peek = slot.peek();
        bool current = peek.oldest.has_value();
        const uint32_t generation = keep_current_payload(role, current, peek.generation, tag, what);
        // Also catches a catch-up whose clear callback re-entered teardown (a listener calling
        // stop()): its cleanup() moved the generation on, and its own drain already reset this
        // role.
        if (!role.accepts(generation)) {
            return;
        }
        // States stamped before the teardown are decided away: none delivered, none pending.
        const typename Slot::Decision decision =
            current ? Slot::decide(peek, is_due) : typename Slot::Decision{};
        if (!slot.commit(peek, decision, deliver)) {
            continue;
        }
        if (decision.deliver == Slot::Place::NONE) {
            return;
        }
        apply();
        // A callback that re-entered teardown (a listener calling stop()) reset the slot, and the
        // drain stop() ran forgot pending_at() (the role's complete_teardown()), so this ends the
        // loop too.
        const std::optional<int64_t> pending_at = slot.pending_at();
        if (!pending_at.has_value() || !is_due(*pending_at)) {
            return;
        }
    }
}

}  // namespace sendspin
