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

// Unit tests for the admission/trust enforcement and arbitration functions:
// the allowed-activity-set table and rejection order in messaging.md "server/activate", and the
// priority rules in connection.md "Multiple servers (server-initiated)".

#include "admission.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "sendspin/types.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

using Acts = std::vector<SendspinActivity>;

static const auto PB = SendspinActivity::PLAYBACK;
static const auto PR = SendspinActivity::PAIRING;

static const auto SENTINEL = PskCategory::SENTINEL;
static const auto PAIRING_CAT = PskCategory::PAIRING;
static const auto LONG_TERM = PskCategory::LONG_TERM;

// ============================================================================
// activities_allowed: the messaging.md "server/activate" table, transcribed
// ============================================================================

// Every cell of the spec table, over PskCategory x activity set x unpaired_access. Accepting rows
// marked Control: are the table's controls - a guard that rejected everything would fail them.
TEST(ActivitiesAllowed, SpecTableRows) {
    struct Row {
        const char* name;
        PskCategory category;
        Acts activities;
        bool unpaired_access;
        bool expected;
    };
    const Row rows[] = {
        // Sentinel row: pairing is what the Sentinel PSK exists for, so unpaired access does not
        // gate it; playback rides along only on unpaired access.
        {"Sentinel/[]/no-unpaired", SENTINEL, Acts{}, false, true},          // Control:
        {"Sentinel/[]/unpaired", SENTINEL, Acts{}, true, true},              // Control:
        {"Sentinel/[pairing]/no-unpaired", SENTINEL, Acts{PR}, false, true}, // Control:
        {"Sentinel/[pairing]/unpaired", SENTINEL, Acts{PR}, true, true},     // Control:
        {"Sentinel/[playback]/no-unpaired", SENTINEL, Acts{PB}, false, false},
        {"Sentinel/[playback]/unpaired", SENTINEL, Acts{PB}, true, true},  // Control:
        {"Sentinel/[pairing,playback]/no-unpaired", SENTINEL, Acts{PR, PB}, false, false},
        {"Sentinel/[pairing,playback]/unpaired", SENTINEL, Acts{PR, PB}, true, true},  // Control:
        // Members are an unordered set.
        {"Sentinel/[playback,pairing]/unpaired", SENTINEL, Acts{PB, PR}, true, true},  // Control:

        // Pairing PSK shares the Sentinel row.
        {"Pairing/[]/no-unpaired", PAIRING_CAT, Acts{}, false, true},           // Control:
        {"Pairing/[]/unpaired", PAIRING_CAT, Acts{}, true, true},               // Control:
        {"Pairing/[pairing]/no-unpaired", PAIRING_CAT, Acts{PR}, false, true},  // Control:
        {"Pairing/[pairing]/unpaired", PAIRING_CAT, Acts{PR}, true, true},      // Control:
        {"Pairing/[playback]/no-unpaired", PAIRING_CAT, Acts{PB}, false, false},
        {"Pairing/[playback]/unpaired", PAIRING_CAT, Acts{PB}, true, true},  // Control:
        {"Pairing/[pairing,playback]/no-unpaired", PAIRING_CAT, Acts{PR, PB}, false, false},
        {"Pairing/[pairing,playback]/unpaired", PAIRING_CAT, Acts{PR, PB}, true, true},  // Control:

        // Long-term row: a paired server has no use for a pairing activity, and unpaired access
        // does not enter into it.
        {"LongTerm/[]/no-unpaired", LONG_TERM, Acts{}, false, true},            // Control:
        {"LongTerm/[]/unpaired", LONG_TERM, Acts{}, true, true},                // Control:
        {"LongTerm/[playback]/no-unpaired", LONG_TERM, Acts{PB}, false, true},  // Control:
        {"LongTerm/[playback]/unpaired", LONG_TERM, Acts{PB}, true, true},      // Control:
        {"LongTerm/[pairing]/no-unpaired", LONG_TERM, Acts{PR}, false, false},
        {"LongTerm/[pairing]/unpaired", LONG_TERM, Acts{PR}, true, false},
        {"LongTerm/[pairing,playback]/no-unpaired", LONG_TERM, Acts{PR, PB}, false, false},
        {"LongTerm/[pairing,playback]/unpaired", LONG_TERM, Acts{PR, PB}, true, false},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(activities_allowed(row.category, row.activities, row.unpaired_access),
                  row.expected);
    }
}

// ============================================================================
// is_playback_capable: activities extended with 'playback' must also be an allowed set
// ============================================================================

TEST(PlaybackCapable, LongTermIsCapableUntilItDeclaresPairing) {
    EXPECT_TRUE(is_playback_capable(LONG_TERM, Acts{}, false));
    EXPECT_TRUE(is_playback_capable(LONG_TERM, Acts{PB}, false));
    // ['pairing'] extended with playback is ['playback', 'pairing'], which the long-term row
    // does not list, so such a connection may carry no roles.
    EXPECT_FALSE(is_playback_capable(LONG_TERM, Acts{PR}, false));
}

TEST(PlaybackCapable, UnpairedCategoriesTrackUnpairedAccess) {
    for (PskCategory cat : {SENTINEL, PAIRING_CAT}) {
        EXPECT_FALSE(is_playback_capable(cat, Acts{}, false));
        EXPECT_FALSE(is_playback_capable(cat, Acts{PR}, false));
        EXPECT_TRUE(is_playback_capable(cat, Acts{}, true));
        EXPECT_TRUE(is_playback_capable(cat, Acts{PR}, true));
        EXPECT_TRUE(is_playback_capable(cat, Acts{PR, PB}, true));
    }
}

// ============================================================================
// admissible: the allowed-set check plus the playback-capable requirement on active_roles
// ============================================================================

// Only a playback-capable connection may carry a non-empty active_roles (messaging.md
// "Playback-capable connections"), so has_roles is a second axis over the same spec table.
TEST(Admissible, RolesRequirePlaybackCapability) {
    struct Row {
        const char* name;
        PskCategory category;
        Acts activities;
        bool has_roles;
        bool unpaired_access;
        bool expected;
    };
    const Row rows[] = {
        {"Sentinel/[]/no-roles", SENTINEL, Acts{}, false, false, true},  // Control:
        // [] is allowed either way, but roles need the connection to be playback-capable, and
        // ['playback'] is a Sentinel set only on unpaired access.
        {"Sentinel/[]/roles/no-unpaired", SENTINEL, Acts{}, true, false, false},
        {"Sentinel/[]/roles/unpaired", SENTINEL, Acts{}, true, true, true},  // Control:
        {"Sentinel/[playback]/no-roles/no-unpaired", SENTINEL, Acts{PB}, false, false, false},
        {"Sentinel/[playback]/no-roles/unpaired", SENTINEL, Acts{PB}, false, true, true},  // Ctrl
        {"Sentinel/[playback]/roles/no-unpaired", SENTINEL, Acts{PB}, true, false, false},
        {"Sentinel/[playback]/roles/unpaired", SENTINEL, Acts{PB}, true, true, true},  // Control:
        // ['pairing'] is allowed with unpaired access off, but roles on it are not.
        {"Sentinel/[pairing]/no-roles/no-unpaired", SENTINEL, Acts{PR}, false, false, true},  // Ctl
        {"Sentinel/[pairing]/roles/no-unpaired", SENTINEL, Acts{PR}, true, false, false},
        {"Sentinel/[pairing]/roles/unpaired", SENTINEL, Acts{PR}, true, true, true},  // Control:

        {"Pairing/[]/no-roles", PAIRING_CAT, Acts{}, false, false, true},                   // Ctrl
        {"Pairing/[pairing]/no-roles", PAIRING_CAT, Acts{PR}, false, false, true},          // Ctrl
        {"Pairing/[pairing]/roles/no-unpaired", PAIRING_CAT, Acts{PR}, true, false, false},
        {"Pairing/[pairing]/roles/unpaired", PAIRING_CAT, Acts{PR}, true, true, true},  // Control:
        // The combined set a server declares when it pairs a client mid-playback.
        {"Pairing/[pairing,playback]/roles/no-unpaired", PAIRING_CAT, Acts{PR, PB}, true, false,
         false},
        {"Pairing/[pairing,playback]/roles/unpaired", PAIRING_CAT, Acts{PR, PB}, true, true,
         true},  // Control:

        {"LongTerm/[playback]/no-roles/no-unpaired", LONG_TERM, Acts{PB}, false, false, true},
        {"LongTerm/[playback]/no-roles/unpaired", LONG_TERM, Acts{PB}, false, true, true},
        {"LongTerm/[playback]/roles", LONG_TERM, Acts{PB}, true, false, true},  // Control:
        // A long-term connection is playback-capable even while idle, so it may hold roles.
        {"LongTerm/[]/roles", LONG_TERM, Acts{}, true, false, true},  // Control:
        {"LongTerm/[pairing]/no-roles", LONG_TERM, Acts{PR}, false, false, false},
        {"LongTerm/[pairing]/roles", LONG_TERM, Acts{PR}, true, false, false},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(admissible(row.category, row.activities, row.has_roles, row.unpaired_access),
                  row.expected);
    }
}

// ============================================================================
// pairing_required vs unauthorized selection (admissibility-based reject reason)
// ============================================================================

// The goodbye reason separates "you are not paired yet" from "you may never do this". A row that
// would have been admitted with unpaired access on gets pairing_required; anything else gets
// unauthorized, which a server reads as a permanent refusal.
TEST(RejectReason, PairingRequiredOnlyWhereUnpairedAccessWouldHaveAdmitted) {
    struct Row {
        const char* name;
        PskCategory category;
        Acts activities;
        bool has_roles;
        bool unpaired_access;
        SendspinGoodbyeReason expected;
    };
    const auto PAIRING_REQUIRED = SendspinGoodbyeReason::PAIRING_REQUIRED;
    const auto UNAUTHORIZED = SendspinGoodbyeReason::UNAUTHORIZED;
    const Row rows[] = {
        {"Sentinel/[playback]/no-roles", SENTINEL, Acts{PB}, false, false, PAIRING_REQUIRED},
        {"Sentinel/[playback]/roles", SENTINEL, Acts{PB}, true, false, PAIRING_REQUIRED},
        {"Sentinel/[]/roles", SENTINEL, Acts{}, true, false, PAIRING_REQUIRED},
        // The Pairing PSK gates playback on unpaired access exactly as the Sentinel PSK does.
        {"Pairing/[playback]/no-roles", PAIRING_CAT, Acts{PB}, false, false, PAIRING_REQUIRED},
        {"Pairing/[pairing,playback]/no-roles", PAIRING_CAT, Acts{PR, PB}, false, false,
         PAIRING_REQUIRED},
        // Pairing is not a long-term activity set under any setting, so enabling unpaired access
        // would not have admitted it.
        {"LongTerm/[pairing]/no-unpaired", LONG_TERM, Acts{PR}, false, false, UNAUTHORIZED},
        {"LongTerm/[pairing,playback]/no-unpaired", LONG_TERM, Acts{PR, PB}, false, false,
         UNAUTHORIZED},
        {"LongTerm/[pairing]/unpaired", LONG_TERM, Acts{PR}, false, true, UNAUTHORIZED},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        // Call the production function the activate handler calls: a local reimplementation of the
        // same condition would keep this test green no matter what the handler does.
        EXPECT_EQ(inadmissible_reject_reason(row.category, row.activities, row.has_roles,
                                             row.unpaired_access),
                  row.expected);
    }
}

// pairing.md "Unpaired Access": turning unpaired access off closes exactly the connections whose
// applied activation it was admitting.
TEST(ReliesOnUnpairedAccess, OnlyUnpairedPlaybackOrRolesRely) {
    struct Row {
        const char* name;
        PskCategory category;
        Acts activities;
        bool has_roles;
        bool relies;
    };
    const Row rows[] = {
        {"Sentinel/[playback]", SENTINEL, Acts{PB}, false, true},
        {"Sentinel/[]/roles", SENTINEL, Acts{}, true, true},
        {"Pairing/[pairing,playback]", PAIRING_CAT, Acts{PR, PB}, false, true},
        // Control: an unpaired connection held idle or pairing stands without unpaired access.
        {"Sentinel/[]", SENTINEL, Acts{}, false, false},
        {"Pairing/[pairing]", PAIRING_CAT, Acts{PR}, false, false},
        // Control: a paired connection never depends on the setting, and one the setting cannot
        // admit either way does not rely on it.
        {"LongTerm/[playback]/roles", LONG_TERM, Acts{PB}, true, false},
        {"LongTerm/[pairing]", LONG_TERM, Acts{PR}, false, false},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(relies_on_unpaired_access(row.category, row.activities, row.has_roles),
                  row.relies);
    }
}

// ============================================================================
// activity_rank
// ============================================================================

TEST(ActivityRank, HighestDeclaredActivityWins) {
    struct Row {
        const char* name;
        Acts activities;
        int expected;
    };
    const Row rows[] = {
        {"[]", Acts{}, 0},
        {"[pairing]", Acts{PR}, 1},
        {"[playback]", Acts{PB}, 2},
        {"[playback,pairing]", Acts{PB, PR}, 2},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(activity_rank(row.activities), row.expected);
    }
    // The ordering itself, independent of the literal values above.
    EXPECT_GT(activity_rank(Acts{PB}), activity_rank(Acts{PR}));
    EXPECT_GT(activity_rank(Acts{PR}), activity_rank(Acts{}));
}

// ============================================================================
// should_admit_connection
// ============================================================================

static bool admit(const Acts& incoming_acts, const std::string& incoming_id,
                  const Acts& admitted_acts, const std::string& admitted_id, bool has_admitted,
                  const std::optional<std::string>& last_playback = std::nullopt,
                  bool admitted_pairing_in_flight = true) {
    return should_admit_connection(incoming_acts, incoming_id, admitted_acts, admitted_id,
                                   has_admitted, last_playback, admitted_pairing_in_flight);
}

// Rules 1-4 of connection.md "Multiple servers (server-initiated)": no incumbent, the in-flight
// pairing shield, rank comparison, and equal non-zero rank.
TEST(ShouldAdmitConnection, RankAndPairingShieldDecideDisplacement) {
    struct Row {
        const char* name;
        Acts incoming;
        Acts admitted;
        bool has_admitted;
        bool admitted_pairing_in_flight;
        bool expected;
    };
    const Row rows[] = {
        // Rule 1: nothing admitted, so anything is admitted.
        {"rule1/no-incumbent/[]", Acts{}, Acts{}, false, true, true},           // Control:
        {"rule1/no-incumbent/[playback]", Acts{PB}, Acts{}, false, true, true}, // Control:
        {"rule1/no-incumbent/[pairing]", Acts{PR}, Acts{}, false, true, true},  // Control:
        // Rule 2: an in-flight pairing is not displaced by rank 1 or rank 2.
        {"rule2/in-flight-pairing/vs-pairing", Acts{PR}, Acts{PR}, true, true, false},
        {"rule2/in-flight-pairing/vs-playback", Acts{PB}, Acts{PR}, true, true, false},
        {"rule2/in-flight-pairing-with-playback/vs-playback", Acts{PB}, Acts{PB, PR}, true, true,
         false},
        {"rule2/in-flight-pairing-with-playback/vs-pairing", Acts{PR}, Acts{PB, PR}, true, true,
         false},
        // Rule 3: rank decides.
        {"rule3/pairing-vs-playback", Acts{PR}, Acts{PB}, true, true, false},
        {"rule3/empty-vs-playback", Acts{}, Acts{PB}, true, true, false},
        {"rule3/playback-vs-empty", Acts{PB}, Acts{}, true, true, true},  // Control:
        // Rule 4: equal non-zero rank admits the incoming connection.
        {"rule4/playback-vs-playback", Acts{PB}, Acts{PB}, true, true, true},  // Control:
        {"rule4/pairing-vs-finished-pairing", Acts{PR}, Acts{PR}, true, false, true},  // Control:
        {"rule4/playback-vs-finished-pairing-with-playback", Acts{PB}, Acts{PB, PR}, true, false,
         true},  // Control:
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(admit(row.incoming, "server-new", row.admitted, "server-old", row.has_admitted,
                        std::nullopt, row.admitted_pairing_in_flight),
                  row.expected);
    }
}

// Rule 5: with both sides rank 0, the last-playback server wins, and only by displacing a peer
// that is not itself the last-playback server.
TEST(ShouldAdmitConnection, BothRankZeroResolveByLastPlaybackServer) {
    struct Row {
        const char* name;
        std::string incoming_id;
        std::string admitted_id;
        std::optional<std::string> last_playback;
        bool expected;
    };
    const Row rows[] = {
        {"incoming-is-last-playback", "server_a", "server_b", "server_a", true},  // Control:
        {"admitted-is-last-playback", "server_b", "server_a", "server_a", false},
        {"neither-is-last-playback", "server_c", "server_b", "server_a", false},
        {"no-last-playback", "server_a", "server_b", std::nullopt, false},
        // Both match: the incumbent is already the last-playback server, so there is nothing to
        // gain by swapping.
        {"both-are-last-playback", "server_a", "server_a", "server_a", false},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        EXPECT_EQ(admit(Acts{}, row.incoming_id, Acts{}, row.admitted_id, true, row.last_playback),
                  row.expected);
    }
}

// ============================================================================
// Post-finalize pairing: rule 2 stops shielding, ranks stay intact
// ============================================================================

// Once server/pair-finalize is acked the pairing is complete, but the admitted connection keeps
// declaring PAIRING until its post-rekey activate lands. Rule 2 must stop protecting it then, or
// a legitimate higher-ranked reconnect is rejected for the whole re-proving window.
TEST(ShouldAdmitConnection, FinalizedPairingNoLongerBlocksHigherRankedIncoming) {
    const Acts incoming{SendspinActivity::PLAYBACK};  // rank 2
    const Acts admitted{SendspinActivity::PAIRING};   // rank 1

    EXPECT_FALSE(should_admit_connection(incoming, "server-new", admitted, "server-pairing", true,
                                         std::nullopt, /*admitted_pairing_in_flight=*/true))
        << "a pairing still in flight must not be displaced";
    EXPECT_TRUE(should_admit_connection(incoming, "server-new", admitted, "server-pairing", true,
                                        std::nullopt, /*admitted_pairing_in_flight=*/false))
        << "a pairing that already finalized must not keep blocking a rank-2 incoming";
}

// Suppressing rule 2 must NOT drop the admitted side to rank 0. Passing an empty activity set
// instead of the incumbent's real [PAIRING] would let rule 5's last_playback tiebreak admit a
// rank-0 newcomer over a just-paired connection, which must never happen: rank still governs, and
// rule 5 applies only when BOTH sides are rank 0.
TEST(ShouldAdmitConnection, FinalizedPairingIsNotEvictedByRankZeroLastPlaybackPeer) {
    const Acts incoming{};                           // rank 0
    const Acts admitted{SendspinActivity::PAIRING};  // rank 1

    // "server-old" is the last playback server, which is exactly the input rule 5 keys on.
    EXPECT_FALSE(should_admit_connection(incoming, "server-old", admitted, "server-paired", true,
                                         "server-old",
                                         /*admitted_pairing_in_flight=*/false))
        << "a rank-0 peer must not displace a rank-1 connection, finalized or not: rank still "
           "decides, and rule 5 applies only when BOTH sides are rank 0";
}
