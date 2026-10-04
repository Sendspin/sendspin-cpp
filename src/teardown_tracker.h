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

/// @file teardown_tracker.h
/// @brief The main-loop half of a role's two-half teardown, run once per teardown generation

#pragma once

#include "inbox.h"

#include <cstdint>

namespace sendspin {

/**
 * @brief Records which of a role's teardowns the main loop has caught up with
 *
 * A role is torn down in two halves (docs/internals.md "Cleanup"). The protocol-task half,
 * cleanup(), bumps the role's `cleanup_generation`, resets what the protocol task and the role
 * threads reach, and stamps everything it queues from then on with the new generation. The
 * main-loop half, the role's complete_teardown(), resets the state only the main loop touches
 * and delivers the role's clear callback. It must run once per teardown, and before the main loop
 * acts on anything stamped with the new generation, so a clear always lands ahead of the state
 * the next connection sends.
 *
 * Every main-loop path that is about to act on something stamped with a generation calls
 * catch_up_teardown() with it first: the event drain with a stamped event's generation, and a
 * role drain with the role's current generation right after it has taken its GenerationSlot
 * payload (inbox.h). Several teardowns between two catch-ups collapse into one main-loop half.
 *
 * Main loop only: written and read on the main loop, so it needs no lock or atomic.
 */
class TeardownTracker {
public:
    /// @brief Whether `generation` is a teardown the main loop has not caught up with yet
    bool pending(uint32_t generation) const {
        return count_after(generation, this->completed_);
    }

    /// @brief Marks `generation` caught up
    /// @return true when it was pending: the caller runs its main-loop half now. false for a
    ///         generation already caught up, or one older than it (a stamp a later teardown has
    ///         already overtaken).
    [[nodiscard]] bool advance(uint32_t generation) {
        if (!this->pending(generation)) {
            return false;
        }
        this->completed_ = generation;
        return true;
    }

private:
    /// The latest teardown generation whose main-loop half has run.
    uint32_t completed_{0};
};

/// @brief Runs `role`'s main-loop teardown half, complete_teardown(), if `generation` is a
/// teardown `role.teardown` has not caught up with. The one chokepoint every role's catch-up
/// goes through. Main loop only.
template <typename RoleImpl>
void catch_up_teardown(RoleImpl& role, uint32_t generation) {
    if (role.teardown.advance(generation)) {
        role.complete_teardown();
    }
}

}  // namespace sendspin
