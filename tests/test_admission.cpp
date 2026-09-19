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

#include <string>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

static std::vector<SendspinActivity> acts() {
    return {};
}
static std::vector<SendspinActivity> acts(SendspinActivity a) {
    return {a};
}
static std::vector<SendspinActivity> acts(SendspinActivity a, SendspinActivity b) {
    return {a, b};
}

static const auto PB = SendspinActivity::PLAYBACK;
static const auto PR = SendspinActivity::PAIRING;

// ============================================================================
// activities_allowed: every row of the messaging.md "server/activate" table, over
// PskCategory x activity set x unpaired_access
// ============================================================================

// SENTINEL row: [], ['pairing'], and (on unpaired access) ['playback'], ['playback', 'pairing'].
TEST(ActivitiesAllowed, SentinelEmpty_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(), false));
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(), true));
}

TEST(ActivitiesAllowed, SentinelPairing_IsAllowed) {
    // Pairing is what the Sentinel PSK exists for, so unpaired access does not gate it.
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(PR), false));
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(PR), true));
}

TEST(ActivitiesAllowed, SentinelPlayback_OnlyWithUnpairedAccess) {
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(PB), false));
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(PB), true));
}

TEST(ActivitiesAllowed, SentinelPlaybackPairing_OnlyWithUnpairedAccess) {
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(PR, PB), false));
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(PR, PB), true));
    // Order is not significant: the members are an unordered set.
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(PB, PR), true));
}

// PAIRING row (the Pairing PSK): identical to the Sentinel row.
TEST(ActivitiesAllowed, PairingCatEmpty_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::PAIRING, acts(), false));
    EXPECT_TRUE(activities_allowed(PskCategory::PAIRING, acts(), true));
}

TEST(ActivitiesAllowed, PairingCatPairing_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::PAIRING, acts(PR), false));
    EXPECT_TRUE(activities_allowed(PskCategory::PAIRING, acts(PR), true));
}

TEST(ActivitiesAllowed, PairingCatPlayback_OnlyWithUnpairedAccess) {
    EXPECT_FALSE(activities_allowed(PskCategory::PAIRING, acts(PB), false));
    EXPECT_TRUE(activities_allowed(PskCategory::PAIRING, acts(PB), true));
}

TEST(ActivitiesAllowed, PairingCatPlaybackPairing_OnlyWithUnpairedAccess) {
    EXPECT_FALSE(activities_allowed(PskCategory::PAIRING, acts(PR, PB), false));
    EXPECT_TRUE(activities_allowed(PskCategory::PAIRING, acts(PR, PB), true));
}

// LONG_TERM row: [] or ['playback'], and nothing that declares pairing. A paired server has no
// use for a pairing activity, and unpaired access does not enter into it.
TEST(ActivitiesAllowed, LongTermEmpty_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(), false));
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(), true));
}

TEST(ActivitiesAllowed, LongTermPlayback_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(PB), false));
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(PB), true));
}

TEST(ActivitiesAllowed, LongTermPairing_NotAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::LONG_TERM, acts(PR), false));
    EXPECT_FALSE(activities_allowed(PskCategory::LONG_TERM, acts(PR), true));
}

TEST(ActivitiesAllowed, LongTermPlaybackPairing_NotAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::LONG_TERM, acts(PR, PB), false));
    EXPECT_FALSE(activities_allowed(PskCategory::LONG_TERM, acts(PR, PB), true));
}

// ============================================================================
// is_playback_capable: activities extended with 'playback' must also be an allowed set
// ============================================================================

TEST(PlaybackCapable, LongTermIsCapableUntilItDeclaresPairing) {
    EXPECT_TRUE(is_playback_capable(PskCategory::LONG_TERM, acts(), false));
    EXPECT_TRUE(is_playback_capable(PskCategory::LONG_TERM, acts(PB), false));
    // ['pairing'] extended with playback is ['playback', 'pairing'], which the long-term row
    // does not list, so such a connection may carry no roles.
    EXPECT_FALSE(is_playback_capable(PskCategory::LONG_TERM, acts(PR), false));
}

TEST(PlaybackCapable, UnpairedCategoriesTrackUnpairedAccess) {
    for (PskCategory cat : {PskCategory::SENTINEL, PskCategory::PAIRING}) {
        EXPECT_FALSE(is_playback_capable(cat, acts(), false));
        EXPECT_FALSE(is_playback_capable(cat, acts(PR), false));
        EXPECT_TRUE(is_playback_capable(cat, acts(), true));
        EXPECT_TRUE(is_playback_capable(cat, acts(PR), true));
        EXPECT_TRUE(is_playback_capable(cat, acts(PR, PB), true));
    }
}

// ============================================================================
// admissible: the allowed-set check plus the playback-capable requirement on active_roles
// ============================================================================

TEST(Admissible, SentinelEmptyNoRoles_Admissible) {
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(), false, false));
}

TEST(Admissible, SentinelEmptyHasRoles_RequiresUnpairedAccess) {
    // [] is allowed either way, but roles need the connection to be playback-capable, and
    // ['playback'] is a Sentinel set only on unpaired access.
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(), true, false));
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(), true, true));
}

TEST(Admissible, SentinelPlaybackNoRoles_RequiresUnpairedAccess) {
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(PB), false, false));
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(PB), false, true));
}

TEST(Admissible, SentinelPlaybackHasRoles_RequiresUnpairedAccess) {
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(PB), true, false));
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(PB), true, true));
}

TEST(Admissible, SentinelPairingHasRoles_RequiresUnpairedAccess) {
    // ['pairing'] is allowed with unpaired access off, but roles on it are not: the connection
    // would not be playback-capable.
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(PR), false, false));
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(PR), true, false));
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(PR), true, true));
}

TEST(Admissible, LongTermPlaybackNoRoles_Admissible) {
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PB), false, false));
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PB), false, true));
}

TEST(Admissible, LongTermPlaybackHasRoles_Admissible) {
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PB), true, false));
}

TEST(Admissible, LongTermEmptyHasRoles_Admissible) {
    // A long-term connection is playback-capable even while idle, so it may hold roles.
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(), true, false));
}

TEST(Admissible, LongTermPairing_NotAdmissible) {
    EXPECT_FALSE(admissible(PskCategory::LONG_TERM, acts(PR), false, false));
    EXPECT_FALSE(admissible(PskCategory::LONG_TERM, acts(PR), true, false));
}

TEST(Admissible, PairingCatEmpty_Admissible) {
    EXPECT_TRUE(admissible(PskCategory::PAIRING, acts(), false, false));
}

TEST(Admissible, PairingCatPairing_AdmissibleAndCarriesRolesOnUnpairedAccess) {
    EXPECT_TRUE(admissible(PskCategory::PAIRING, acts(PR), false, false));
    EXPECT_FALSE(admissible(PskCategory::PAIRING, acts(PR), true, false));
    EXPECT_TRUE(admissible(PskCategory::PAIRING, acts(PR), true, true));
}

TEST(Admissible, PairingCatPlaybackPairing_RequiresUnpairedAccess) {
    // The combined set a server declares when it pairs a client mid-playback.
    EXPECT_FALSE(admissible(PskCategory::PAIRING, acts(PR, PB), true, false));
    EXPECT_TRUE(admissible(PskCategory::PAIRING, acts(PR, PB), true, true));
}

// ============================================================================
// pairing_required vs unauthorized selection (admissibility-based reject reason)
// ============================================================================

// Thin alias for inadmissible_reject_reason(), the same function ConnectionManager's activate
// handler calls to pick the goodbye reason. It must stay a call rather than a local
// reimplementation of the same condition: a copy here would keep these tests green no matter what
// the handler does.
static SendspinGoodbyeReason reject_reason_for(PskCategory cat,
                                               const std::vector<SendspinActivity>& activities,
                                               bool has_roles, bool unpaired_access) {
    return inadmissible_reject_reason(cat, activities, has_roles, unpaired_access);
}

TEST(RejectReason, SentinelPlaybackNoUnpaired_PairingRequired) {
    // Because admissible(SENTINEL, {PB}, false, true) = true.
    EXPECT_EQ(reject_reason_for(PskCategory::SENTINEL, acts(PB), false, false),
              SendspinGoodbyeReason::PAIRING_REQUIRED);
}

TEST(RejectReason, SentinelPlaybackRolesNoUnpaired_PairingRequired) {
    EXPECT_EQ(reject_reason_for(PskCategory::SENTINEL, acts(PB), true, false),
              SendspinGoodbyeReason::PAIRING_REQUIRED);
}

TEST(RejectReason, SentinelEmptyHasRolesNoUnpaired_PairingRequired) {
    // SENTINEL + {} + has_roles + !unpaired_access:
    // admissible(SENTINEL, {}, true, true) = true -> pairing_required
    EXPECT_EQ(reject_reason_for(PskCategory::SENTINEL, acts(), true, false),
              SendspinGoodbyeReason::PAIRING_REQUIRED);
}

TEST(RejectReason, PairingCatPlaybackNoUnpaired_PairingRequired) {
    // The Pairing PSK gates playback on unpaired access exactly as the Sentinel PSK does, so it
    // reaches the same first rule.
    EXPECT_EQ(reject_reason_for(PskCategory::PAIRING, acts(PB), false, false),
              SendspinGoodbyeReason::PAIRING_REQUIRED);
    EXPECT_EQ(reject_reason_for(PskCategory::PAIRING, acts(PR, PB), false, false),
              SendspinGoodbyeReason::PAIRING_REQUIRED);
}

TEST(RejectReason, LongTermPairing_Unauthorized) {
    // Pairing is not a long-term activity set under any setting, so enabling unpaired access
    // would not have admitted it: this is a permanent refusal.
    EXPECT_EQ(reject_reason_for(PskCategory::LONG_TERM, acts(PR), false, false),
              SendspinGoodbyeReason::UNAUTHORIZED);
    EXPECT_EQ(reject_reason_for(PskCategory::LONG_TERM, acts(PR, PB), false, false),
              SendspinGoodbyeReason::UNAUTHORIZED);
    EXPECT_EQ(reject_reason_for(PskCategory::LONG_TERM, acts(PR), false, true),
              SendspinGoodbyeReason::UNAUTHORIZED);
}

// ============================================================================
// activity_rank tests
// ============================================================================

TEST(ActivityRank, Empty_Zero) {
    EXPECT_EQ(activity_rank(acts()), 0);
}

TEST(ActivityRank, Pairing_One) {
    EXPECT_EQ(activity_rank(acts(PR)), 1);
}

TEST(ActivityRank, Playback_Two) {
    EXPECT_EQ(activity_rank(acts(PB)), 2);
}

TEST(ActivityRank, PlaybackPairing_Two) {
    // Both present -> highest is playback
    EXPECT_EQ(activity_rank(acts(PB, PR)), 2);
}

TEST(ActivityRank, Ordering) {
    EXPECT_GT(activity_rank(acts(PB)), activity_rank(acts(PR)));
    EXPECT_GT(activity_rank(acts(PR)), activity_rank(acts()));
}

// ============================================================================
// should_admit_connection tests
// ============================================================================

static bool admit(const std::vector<SendspinActivity>& incoming_acts,
                  const std::string& incoming_id,
                  const std::vector<SendspinActivity>& admitted_acts,
                  const std::string& admitted_id, bool has_admitted,
                  const std::string& last_playback = "", bool has_last = false,
                  bool admitted_pairing_in_flight = true) {
    return should_admit_connection(incoming_acts, incoming_id, admitted_acts, admitted_id,
                                   has_admitted, last_playback, has_last,
                                   admitted_pairing_in_flight);
}

TEST(ShouldAdmit, NoCurrent_AlwaysAdmit) {
    EXPECT_TRUE(admit(acts(), "new", acts(), "", false));
    EXPECT_TRUE(admit(acts(PB), "new", acts(), "", false));
    EXPECT_TRUE(admit(acts(PR), "new", acts(), "", false));
}

TEST(ShouldAdmit, HigherRankDisplaces) {
    // incoming=playback(2), admitted=pairing(1), but pairing is not displaced by rank 2
    // (the in-flight-pairing rule blocks it)
    EXPECT_FALSE(admit(acts(PB), "new", acts(PR), "old", true));

    // Once the pairing is no longer in flight, the rank comparison decides and rank 2 wins.
    EXPECT_TRUE(admit(acts(PB), "new", acts(PR), "old", true, "", false,
                      /*admitted_pairing_in_flight=*/false));

    // incoming=playback(2), admitted=empty(0)
    EXPECT_TRUE(admit(acts(PB), "new", acts(), "old", true));
}

TEST(ShouldAdmit, InFlightPairing_NotDisplacedByPairing) {
    // admitted=pairing(rank 1), incoming=pairing(rank 1) -> not displaced
    EXPECT_FALSE(admit(acts(PR), "new", acts(PR), "old", true));
}

TEST(ShouldAdmit, InFlightPairing_NotDisplacedByPlayback) {
    // admitted=pairing(rank 1), incoming=playback(rank 2) -> not displaced
    EXPECT_FALSE(admit(acts(PB), "new", acts(PR), "old", true));
}

TEST(ShouldAdmit, LowerRankDoesNotDisplace) {
    // incoming=pairing(1), admitted=playback(2) -> no (lower rank)
    EXPECT_FALSE(admit(acts(PR), "new", acts(PB), "old", true));

    // incoming=empty(0), admitted=playback(2) -> no (lower rank)
    EXPECT_FALSE(admit(acts(), "new", acts(PB), "old", true));
}

TEST(ShouldAdmit, EqualNonZeroRank_Admits) {
    // Both playback(2) -> admit incoming
    EXPECT_TRUE(admit(acts(PB), "new", acts(PB), "old", true));

    // Both pairing(1), with the admitted pairing already finished -> admit incoming
    EXPECT_TRUE(admit(acts(PR), "new", acts(PR), "old", true, "", false,
                      /*admitted_pairing_in_flight=*/false));
}

TEST(ShouldAdmit, BothEmpty_ResolvesByLastPlayback_IncomingMatches) {
    // incoming matches last_playback, admitted does not -> admit
    EXPECT_TRUE(admit(acts(), "server_a", acts(), "server_b", true, "server_a", true));
}

TEST(ShouldAdmit, BothEmpty_ResolvesByLastPlayback_AdmittedMatches) {
    // admitted matches last_playback, incoming does not -> keep admitted
    EXPECT_FALSE(admit(acts(), "server_b", acts(), "server_a", true, "server_a", true));
}

TEST(ShouldAdmit, BothEmpty_NeitherMatchesLastPlayback) {
    // Neither matches -> keep admitted
    EXPECT_FALSE(admit(acts(), "server_c", acts(), "server_b", true, "server_a", true));
}

TEST(ShouldAdmit, BothEmpty_NoLastPlayback_KeepAdmitted) {
    // No last_playback -> keep admitted (has_last=false)
    EXPECT_FALSE(admit(acts(), "new", acts(), "old", true, "", false));
}

TEST(ShouldAdmit, BothEmpty_BothMatchLastPlayback) {
    // Both match: admitted already has last_playback; incoming also matches but admitted is not
    // != last_playback, so condition fails -> keep admitted
    EXPECT_FALSE(admit(acts(), "server_a", acts(), "server_a", true, "server_a", true));
}

TEST(ShouldAdmit, PlaybackDisplacesEmpty) {
    // incoming=playback(2), admitted=empty(0) -> admit (higher rank)
    EXPECT_TRUE(admit(acts(PB), "new", acts(), "old", true));
}

// ============================================================================
// Post-finalize pairing: rule 2 stops shielding, ranks stay intact
// ============================================================================

// Once server/pair-finalize is acked the pairing is complete, but the admitted connection keeps
// declaring PAIRING until its post-rekey activate lands. Rule 2 must stop protecting it then, or
// a legitimate higher-ranked reconnect is rejected for the whole re-proving window.
TEST(ShouldAdmitConnection, FinalizedPairingNoLongerBlocksHigherRankedIncoming) {
    const std::vector<SendspinActivity> incoming{SendspinActivity::PLAYBACK};  // rank 2
    const std::vector<SendspinActivity> admitted{SendspinActivity::PAIRING};   // rank 1

    EXPECT_FALSE(should_admit_connection(incoming, "server-new", admitted, "server-pairing", true,
                                         "", false, /*admitted_pairing_in_flight=*/true))
        << "a pairing still in flight must not be displaced";
    EXPECT_TRUE(should_admit_connection(incoming, "server-new", admitted, "server-pairing", true,
                                        "", false, /*admitted_pairing_in_flight=*/false))
        << "a pairing that already finalized must not keep blocking a rank-2 incoming";
}

// Suppressing rule 2 must NOT drop the admitted side to rank 0. Passing an empty activity set
// instead of the incumbent's real [PAIRING] would let rule 5's last_playback tiebreak admit a
// rank-0 newcomer over a just-paired connection, which must never happen: rank still governs, and
// rule 5 applies only when BOTH sides are rank 0.
TEST(ShouldAdmitConnection, FinalizedPairingIsNotEvictedByRankZeroLastPlaybackPeer) {
    const std::vector<SendspinActivity> incoming{};                           // rank 0
    const std::vector<SendspinActivity> admitted{SendspinActivity::PAIRING};  // rank 1

    // "server-old" is the last playback server, which is exactly the input rule 5 keys on.
    EXPECT_FALSE(should_admit_connection(incoming, "server-old", admitted, "server-paired", true,
                                         "server-old", true,
                                         /*admitted_pairing_in_flight=*/false))
        << "a rank-0 peer must not displace a rank-1 connection, finalized or not: rank still "
           "decides, and rule 5 applies only when BOTH sides are rank 0";
}
