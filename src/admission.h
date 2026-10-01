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

/// @file admission.h
/// @brief Pure functions for server/activate trust enforcement and multi-server admission
/// arbitration.
///
/// Implements the allowed-activity-set table and the rejection order in messaging.md
/// "server/activate", and the priority arbitration in connection.md "Multiple servers
/// (server-initiated)".
///
/// All functions are pure, so they unit-test independently of the network layer. The admission
/// handler in ConnectionManager::loop() applies them on the main loop thread; do not call from
/// the network thread.

#pragma once

#include "protocol_messages.h"
#include "record_store.h"

#include <optional>
#include <string>
#include <vector>

namespace sendspin {

// ============================================================================
// Trust enforcement (PSK category -> allowed activities)
// ============================================================================

/// @brief Whether `activities` contains `target`. Activity lists are always tiny, so a linear
/// scan is used everywhere in this file instead of a set.
inline bool contains_activity(const std::vector<SendspinActivity>& activities,
                              SendspinActivity target) {
    for (const auto& a : activities) {
        if (a == target) {
            return true;
        }
    }
    return false;
}

/// @brief Whether an activity set is allowed for the matched PSK category.
///
/// The table in messaging.md "server/activate":
///
///   | PSK matched  | Allowed activity sets                                             |
///   |--------------|-------------------------------------------------------------------|
///   | long-term    | [] or ['playback']                                                |
///   | pairing      | [], ['pairing'], ['playback']*, ['playback', 'pairing']*          |
///   | Sentinel     | [], ['pairing'], ['playback']*, ['playback', 'pairing']*          |
///
///   * only when the client has unpaired access enabled.
///
/// Members are unordered and unique, so the set is characterized by which of the two activities
/// it contains.
///
/// @param category       PSK category matched during the Noise handshake.
/// @param has_playback   Whether the set contains 'playback'.
/// @param has_pairing    Whether the set contains 'pairing'.
/// @param unpaired_access  Whether unpaired (Sentinel) access is enabled.
/// @return true if the activity set is allowed for the given category/config.
inline bool activity_set_allowed(PskCategory category, bool has_playback, bool has_pairing,
                                 bool unpaired_access) {
    if (category == PskCategory::LONG_TERM) {
        return !has_pairing;
    }
    // Pairing PSK and Sentinel share a row: pairing is always theirs to declare, and playback
    // rides along only on unpaired access.
    return !has_playback || unpaired_access;
}

/// @brief activity_set_allowed() for a declared activity list.
inline bool activities_allowed(PskCategory category,
                               const std::vector<SendspinActivity>& activities,
                               bool unpaired_access) {
    return activity_set_allowed(category, contains_activity(activities, SendspinActivity::PLAYBACK),
                                contains_activity(activities, SendspinActivity::PAIRING),
                                unpaired_access);
}

/// @brief Whether a connection declaring `activities` is "playback-capable": `activities`
/// extended with PLAYBACK is an allowed set for the matched PSK category. A connection already
/// declaring PLAYBACK is playback-capable exactly when its own `activities` are allowed.
///
/// @param category    PSK category matched during the Noise handshake.
/// @param activities  Activities declared in the server/activate message.
/// @param unpaired_access Whether unpaired (Sentinel) access is enabled.
/// @return true if the connection is playback-capable under these activities.
inline bool is_playback_capable(PskCategory category,
                                const std::vector<SendspinActivity>& activities,
                                bool unpaired_access) {
    return activity_set_allowed(category, /*has_playback=*/true,
                                contains_activity(activities, SendspinActivity::PAIRING),
                                unpaired_access);
}

/// @brief Whether `activities`/`active_roles` satisfy the matched PSK's structural constraints.
///
/// Per messaging.md "Playback-capable connections", only a playback-capable connection may carry
/// a non-empty active_roles, and it may do so even when PLAYBACK is not currently declared. This
/// catches e.g. a Sentinel connection with has_roles=true and unpaired access disabled.
///
/// @param category        PSK category matched during the Noise handshake.
/// @param activities      Activities declared in the server/activate message.
/// @param has_roles       Whether the effective active_roles set is non-empty.
/// @param unpaired_access Whether unpaired (Sentinel) access is enabled.
/// @return true if the activate is structurally admissible.
inline bool admissible(PskCategory category, const std::vector<SendspinActivity>& activities,
                       bool has_roles, bool unpaired_access) {
    if (!activities_allowed(category, activities, unpaired_access)) {
        return false;
    }
    return !has_roles || is_playback_capable(category, activities, unpaired_access);
}

/// @brief Whether an activation is admissible only while unpaired access is enabled.
///
/// pairing.md "Unpaired Access": the connections a client closes with pairing_required once it
/// stops admitting unpaired access.
///
/// @param category, activities, has_roles  Same as admissible().
inline bool relies_on_unpaired_access(PskCategory category,
                                      const std::vector<SendspinActivity>& activities,
                                      bool has_roles) {
    return admissible(category, activities, has_roles, /*unpaired_access=*/true) &&
           !admissible(category, activities, has_roles, /*unpaired_access=*/false);
}

/// @brief Goodbye reason to close an inadmissible server/activate with.
///
/// Separates "you are not paired yet" from "you may never do this", by the first-rule-wins order
/// in messaging.md "server/activate": an activation that enabling unpaired access would have
/// admitted gets pairing_required, anything else unauthorized. Only an unpaired session reaches
/// pairing_required, since unpaired_access gates nothing in the long-term row.
///
/// Callers must only use this for an activate that admissible() already rejected: for an
/// admissible one the return value is meaningless.
///
/// @param category, activities, has_roles, unpaired_access  Same as admissible().
/// @return PAIRING_REQUIRED if enabling unpaired access would have admitted it, else UNAUTHORIZED.
inline SendspinGoodbyeReason inadmissible_reject_reason(
    PskCategory category, const std::vector<SendspinActivity>& activities, bool has_roles,
    bool unpaired_access) {
    if (!unpaired_access && relies_on_unpaired_access(category, activities, has_roles)) {
        return SendspinGoodbyeReason::PAIRING_REQUIRED;
    }
    return SendspinGoodbyeReason::UNAUTHORIZED;
}

// ============================================================================
// Multi-server admission arbitration
// ============================================================================

/// @brief Rank a connection by its highest activity.
///
/// connection.md "Multiple servers (server-initiated)" ranks playback above pairing and an empty
/// set lowest, so playback=2 > pairing=1 > none=0.
inline int activity_rank(const std::vector<SendspinActivity>& activities) {
    bool has_playback = false;
    bool has_pairing = false;
    for (const auto& a : activities) {
        if (a == SendspinActivity::PLAYBACK) {
            has_playback = true;
        } else if (a == SendspinActivity::PAIRING) {
            has_pairing = true;
        }
    }
    if (has_playback) {
        return 2;
    }
    if (has_pairing) {
        return 1;
    }
    return 0;
}

/// @brief Whether the incoming connection should displace the currently admitted one.
///
/// Rules, from connection.md "Multiple servers (server-initiated)":
///   1. If no currently admitted connection -> admit.
///   2. An admitted connection with an in-flight pairing, alone or alongside playback, is not
///      displaced by incoming rank 1 or 2.
///   3. Higher incoming rank displaces.
///   4. Equal non-zero rank -> admit.
///   5. Both rank-0 (empty activities): admit only if
///      incoming.server_id == last_playback_server_id && admitted.server_id != last_playback.
///
/// @param admitted_pairing_in_flight  Whether the admitted connection's pairing exchange is still
///        in flight. True is the plain reading of rule 2. Pass false only when the admitted side
///        declares PAIRING but has already been acked with server/pair-finalize, so rule 2 stops
///        shielding a pairing that has finished.
/// @return true if the incoming connection should become the admitted one.
inline bool should_admit_connection(const std::vector<SendspinActivity>& incoming_activities,
                                    const std::string& incoming_server_id,
                                    const std::vector<SendspinActivity>& admitted_activities,
                                    const std::string& admitted_server_id, bool has_admitted,
                                    const std::optional<std::string>& last_playback_server_id,
                                    bool admitted_pairing_in_flight) {
    if (!has_admitted) {
        return true;
    }

    const int incoming_rank = activity_rank(incoming_activities);
    const int admitted_rank = activity_rank(admitted_activities);

    // An in-flight pairing is not displaced by incoming rank 1 or 2. The caller passes
    // admitted_pairing_in_flight=false once server/pair-finalize is acked. Substituting an empty
    // activity set instead would drop the admitted side to rank 0 and hand a rank-0 newcomer the
    // last_playback tiebreak below, which it could never have won before.
    if (admitted_pairing_in_flight &&
        contains_activity(admitted_activities, SendspinActivity::PAIRING) && incoming_rank != 0) {
        return false;
    }

    if (incoming_rank != admitted_rank) {
        return incoming_rank > admitted_rank;
    }

    if (incoming_rank == 0) {
        // Both-empty: resolve by last_playback server_id.
        if (!last_playback_server_id.has_value()) {
            return false;
        }
        return (incoming_server_id == *last_playback_server_id &&
                admitted_server_id != *last_playback_server_id);
    }

    return true;
}

}  // namespace sendspin
