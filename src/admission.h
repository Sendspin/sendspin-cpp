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
/// Ports the Python reference:
///   aiosendspin/aiosendspin/client/connection.py:_activities_allowed/_admissible
///   aiosendspin/aiosendspin/client/client.py:_activity_rank/_should_admit_connection
///
/// All functions are pure (no side effects, no connection state mutations) so they can be
/// unit-tested independently of the network layer. The admission handler in
/// ConnectionManager::loop() applies them on the MAIN LOOP thread; do NOT call from the
/// network thread.

#pragma once

#include "protocol_messages.h"
#include "record_store.h"

#include <string>
#include <vector>

namespace sendspin {

// ============================================================================
// Trust enforcement (PSK category -> allowed activities)
// ============================================================================

/// @brief Whether `activities` is an allowed set for the matched PSK category.
///
/// Ports `_activities_allowed` from
/// aiosendspin/aiosendspin/client/connection.py (line ~139).
///
/// Rules (mirroring the reference exactly):
///   - If PAIRING in activities -> only {PAIRING} is valid.
///   - LONG_TERM category -> any subset of {PLAYBACK, MANAGEMENT}.
///   - SENTINEL category -> empty set is ok; {PLAYBACK} is ok IFF unpaired_access.
///   - PAIRING category -> only {PAIRING} (handled by the first check above;
///     anything else falls through to false).
///
/// @param category    PSK category matched during the Noise handshake.
/// @param activities  Activities declared in the server/activate message.
/// @param unpaired_access  Whether unpaired (Sentinel) access is enabled in the record store.
/// @return true if the activity set is allowed for the given category/config.
inline bool activities_allowed(PskCategory category,
                               const std::vector<SendspinActivity>& activities,
                               bool unpaired_access) {
    // Check whether PAIRING is in the set.
    bool has_pairing = false;
    for (const auto& a : activities) {
        if (a == SendspinActivity::PAIRING) {
            has_pairing = true;
            break;
        }
    }

    if (has_pairing) {
        // Only {PAIRING} is valid when PAIRING is present.
        return activities.size() == 1;
    }

    if (category == PskCategory::LONG_TERM) {
        // Any subset of {PLAYBACK, MANAGEMENT} is allowed.
        for (const auto& a : activities) {
            if (a != SendspinActivity::PLAYBACK && a != SendspinActivity::MANAGEMENT) {
                return false;
            }
        }
        return true;
    }

    if (category == PskCategory::SENTINEL) {
        if (activities.empty()) {
            return true;
        }
        // {PLAYBACK} only, and only when unpaired_access is enabled.
        if (activities.size() == 1 && activities[0] == SendspinActivity::PLAYBACK) {
            return unpaired_access;
        }
        return false;
    }

    // PAIRING category: only {PAIRING} is valid, already handled above -> false for anything else.
    return false;
}

/// @brief Whether a connection declaring `activities` is "playback-capable": `activities`
/// extended with PLAYBACK is an allowed set for the matched PSK category. A connection already
/// declaring PLAYBACK is playback-capable exactly when its own `activities` are allowed.
///
/// Used both by admissible() (below) and by the client's re-evaluation of persisted
/// `active_roles` on every server/activate (spec #122: "if a later activation changes activities
/// so the connection is no longer playback-capable without explicitly sending active_roles, the
/// persisted roles are treated as empty rather than the message rejected").
///
/// @param category    PSK category matched during the Noise handshake.
/// @param activities  Activities declared in the server/activate message.
/// @param unpaired_access Whether unpaired (Sentinel) access is enabled.
/// @return true if the connection is playback-capable under these activities.
inline bool is_playback_capable(PskCategory category,
                                const std::vector<SendspinActivity>& activities,
                                bool unpaired_access) {
    bool already_has_playback = false;
    for (const auto& a : activities) {
        if (a == SendspinActivity::PLAYBACK) {
            already_has_playback = true;
            break;
        }
    }
    if (already_has_playback) {
        return activities_allowed(category, activities, unpaired_access);
    }
    std::vector<SendspinActivity> with_playback = activities;
    with_playback.push_back(SendspinActivity::PLAYBACK);
    return activities_allowed(category, with_playback, unpaired_access);
}

/// @brief Whether `activities`/`active_roles` satisfy the matched PSK's structural constraints.
///
/// Ports `_admissible` from
/// aiosendspin/aiosendspin/client/connection.py (line ~154).
///
/// A non-empty active_roles set requires that the connection be "playback-capable" -
/// i.e., activities | {PLAYBACK} must also be allowed. This catches e.g. a Sentinel
/// connection with has_roles=true and activities={} (empty), which would attempt to
/// use role protocol without being allowed playback.
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
    if (!has_roles) {
        return true;
    }
    // Non-empty active_roles requires playback-capable activities.
    // Build activities | {PLAYBACK}.
    bool already_has_playback = false;
    for (const auto& a : activities) {
        if (a == SendspinActivity::PLAYBACK) {
            already_has_playback = true;
            break;
        }
    }
    if (already_has_playback) {
        // activities already includes PLAYBACK -> same check.
        return true;
    }
    std::vector<SendspinActivity> with_playback = activities;
    with_playback.push_back(SendspinActivity::PLAYBACK);
    return activities_allowed(category, with_playback, unpaired_access);
}

// ============================================================================
// Multi-server admission arbitration
// ============================================================================

/// @brief Rank a connection by its highest activity.
///
/// Ports `_activity_rank` from
/// aiosendspin/aiosendspin/client/client.py (line ~504).
///
/// management=3 > playback=2 > pairing=1 > none=0.
///
/// @param activities Activities declared by the connection.
/// @return Integer rank (0-3).
inline int activity_rank(const std::vector<SendspinActivity>& activities) {
    bool has_management = false;
    bool has_playback = false;
    bool has_pairing = false;
    for (const auto& a : activities) {
        if (a == SendspinActivity::MANAGEMENT) {
            has_management = true;
        } else if (a == SendspinActivity::PLAYBACK) {
            has_playback = true;
        } else if (a == SendspinActivity::PAIRING) {
            has_pairing = true;
        }
    }
    if (has_management) {
        return 3;
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
/// Ports `_should_admit_connection` from
/// aiosendspin/aiosendspin/client/client.py (line ~515).
///
/// Rules (from the reference):
///   1. If no currently admitted connection -> admit.
///   2. An in-flight pairing (admitted rank 1) is NOT displaced by incoming rank 1 or 2.
///   3. Higher incoming rank displaces.
///   4. Equal non-zero rank -> admit.
///   5. Both rank-0 (empty activities): admit only if
///      incoming.server_id == last_playback_server_id && admitted.server_id != last_playback.
///
/// @param incoming_activities    Activities of the incoming connection.
/// @param incoming_server_id     server_id of the incoming connection.
/// @param admitted_activities    Activities of the currently admitted connection.
/// @param admitted_server_id     server_id of the currently admitted connection.
/// @param has_admitted           Whether there is an admitted connection at all.
/// @param last_playback_server_id  The last-playback server_id (empty if unset).
/// @param has_last_playback      Whether last_playback_server_id has been set.
/// @return true if the incoming connection should become the admitted one.
inline bool should_admit_connection(const std::vector<SendspinActivity>& incoming_activities,
                                    const std::string& incoming_server_id,
                                    const std::vector<SendspinActivity>& admitted_activities,
                                    const std::string& admitted_server_id, bool has_admitted,
                                    const std::string& last_playback_server_id,
                                    bool has_last_playback) {
    if (!has_admitted) {
        return true;
    }

    const int incoming_rank = activity_rank(incoming_activities);
    const int admitted_rank = activity_rank(admitted_activities);

    // An in-flight pairing is not displaced by incoming rank 1 (pairing) or rank 2 (playback).
    if (admitted_rank == 1 && (incoming_rank == 1 || incoming_rank == 2)) {
        return false;
    }

    if (incoming_rank != admitted_rank) {
        return incoming_rank > admitted_rank;
    }

    // Equal rank.
    if (incoming_rank == 0) {
        // Both-empty: resolve by last_playback server_id.
        if (!has_last_playback) {
            return false;
        }
        return (incoming_server_id == last_playback_server_id &&
                admitted_server_id != last_playback_server_id);
    }

    // Equal non-zero rank -> admit the incoming connection.
    return true;
}

}  // namespace sendspin
