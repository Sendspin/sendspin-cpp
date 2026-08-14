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

// Unit tests for the admission/trust enforcement and arbitration functions.
// Mirrors the reference decision logic in:
//   aiosendspin/aiosendspin/client/connection.py:_activities_allowed/_admissible
//   aiosendspin/aiosendspin/client/client.py:_activity_rank/_should_admit_connection

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
static std::vector<SendspinActivity> acts(SendspinActivity a, SendspinActivity b,
                                          SendspinActivity c) {
    return {a, b, c};
}

static const auto PB = SendspinActivity::PLAYBACK;
static const auto MG = SendspinActivity::MANAGEMENT;
static const auto PR = SendspinActivity::PAIRING;

// ============================================================================
// activities_allowed tests: exhaustive over PskCategory x activity_set x unpaired_access
// ============================================================================

// SENTINEL category
TEST(ActivitiesAllowed, SentinelEmpty_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(), false));
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(), true));
}

TEST(ActivitiesAllowed, SentinelPlayback_OnlyWithUnpairedAccess) {
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(PB), false));
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(PB), true));
}

TEST(ActivitiesAllowed, SentinelManagement_NeverAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(MG), false));
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(MG), true));
}

TEST(ActivitiesAllowed, SentinelPlaybackManagement_NeverAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(PB, MG), false));
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(PB, MG), true));
}

TEST(ActivitiesAllowed, SentinelPairing_OnlyExactlyPairing) {
    // {PAIRING} is ok for Sentinel (handled by the "only {PAIRING}" path)
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(PR), false));
    EXPECT_TRUE(activities_allowed(PskCategory::SENTINEL, acts(PR), true));
}

TEST(ActivitiesAllowed, SentinelPairingPlayback_NotAllowed) {
    // {PAIRING, PLAYBACK} is not ok: pairing must be alone
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(PR, PB), false));
    EXPECT_FALSE(activities_allowed(PskCategory::SENTINEL, acts(PR, PB), true));
}

// LONG_TERM category
TEST(ActivitiesAllowed, LongTermEmpty_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(), false));
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(), true));
}

TEST(ActivitiesAllowed, LongTermPlayback_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(PB), false));
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(PB), true));
}

TEST(ActivitiesAllowed, LongTermManagement_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(MG), false));
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(MG), true));
}

TEST(ActivitiesAllowed, LongTermPlaybackManagement_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(PB, MG), false));
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(PB, MG), true));
}

TEST(ActivitiesAllowed, LongTermPairing_OnlyExactlyPairing) {
    // {PAIRING} alone is allowed (by the general "only {PAIRING}" check)
    EXPECT_TRUE(activities_allowed(PskCategory::LONG_TERM, acts(PR), false));
}

TEST(ActivitiesAllowed, LongTermPairingPlayback_NotAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::LONG_TERM, acts(PR, PB), false));
}

TEST(ActivitiesAllowed, LongTermPairingManagement_NotAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::LONG_TERM, acts(PR, MG), false));
}

// PAIRING category (the Pairing PSK)
TEST(ActivitiesAllowed, PairingCatPairing_IsAllowed) {
    EXPECT_TRUE(activities_allowed(PskCategory::PAIRING, acts(PR), false));
    EXPECT_TRUE(activities_allowed(PskCategory::PAIRING, acts(PR), true));
}

TEST(ActivitiesAllowed, PairingCatEmpty_NotAllowed) {
    // PAIRING category admits only {PAIRING}; falls through to "return false"
    EXPECT_FALSE(activities_allowed(PskCategory::PAIRING, acts(), false));
    EXPECT_FALSE(activities_allowed(PskCategory::PAIRING, acts(), true));
}

TEST(ActivitiesAllowed, PairingCatPlayback_NotAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::PAIRING, acts(PB), false));
    EXPECT_FALSE(activities_allowed(PskCategory::PAIRING, acts(PB), true));
}

TEST(ActivitiesAllowed, PairingCatManagement_NotAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::PAIRING, acts(MG), false));
}

TEST(ActivitiesAllowed, PairingCatPairingPlayback_NotAllowed) {
    EXPECT_FALSE(activities_allowed(PskCategory::PAIRING, acts(PR, PB), false));
}

// ============================================================================
// admissible tests: checks the has_roles interaction
// ============================================================================

TEST(Admissible, SentinelEmptyNoRoles_Admissible) {
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(), false, false));
}

TEST(Admissible, SentinelEmptyHasRoles_NotAdmissible) {
    // {} + has_roles requires playback-capable, but SENTINEL+{PLAYBACK} requires unpaired_access
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(), true, false));
    // with unpaired_access=true: {} is allowed, then {} | {PB} = {PB} is also allowed
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(), true, true));
}

TEST(Admissible, SentinelPlaybackNoRoles_RequiresUnpairedAccess) {
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(PB), false, false));
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(PB), false, true));
}

TEST(Admissible, SentinelPlaybackHasRoles_RequiresUnpairedAccess) {
    // {PB} + has_roles: {PB} | {PB} = {PB} still requires unpaired_access
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(PB), true, false));
    EXPECT_TRUE(admissible(PskCategory::SENTINEL, acts(PB), true, true));
}

TEST(Admissible, SentinelManagement_NotAdmissible) {
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(MG), false, false));
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(MG), false, true));
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(MG), true, false));
    EXPECT_FALSE(admissible(PskCategory::SENTINEL, acts(MG), true, true));
}

TEST(Admissible, LongTermPlaybackNoRoles_Admissible) {
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PB), false, false));
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PB), false, true));
}

TEST(Admissible, LongTermPlaybackHasRoles_Admissible) {
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PB), true, false));
}

TEST(Admissible, LongTermManagement_AdmissibleWithoutRoles) {
    // {MG} alone: allowed; then MG | {PB} = {PB, MG} which is also allowed for LONG_TERM
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(MG), false, false));
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(MG), true, false));
}

TEST(Admissible, LongTermPlaybackManagement_Admissible) {
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PB, MG), false, false));
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PB, MG), true, false));
}

TEST(Admissible, LongTermPairing_AdmissibleOnlyWithoutRoles) {
    // {PAIRING} allowed; {PAIRING} | {PB} = {PB, PAIRING} not allowed (pairing must be alone)
    EXPECT_TRUE(admissible(PskCategory::LONG_TERM, acts(PR), false, false));
    EXPECT_FALSE(admissible(PskCategory::LONG_TERM, acts(PR), true, false));
}

TEST(Admissible, PairingCatPairing_AdmissibleOnlyWithoutRoles) {
    // {PAIRING} allowed; + has_roles: {PAIRING}|{PB} = {PB, PAIRING} not allowed
    EXPECT_TRUE(admissible(PskCategory::PAIRING, acts(PR), false, false));
    EXPECT_FALSE(admissible(PskCategory::PAIRING, acts(PR), true, false));
}

TEST(Admissible, PairingCatEmpty_NotAdmissible) {
    EXPECT_FALSE(admissible(PskCategory::PAIRING, acts(), false, false));
}

TEST(Admissible, PairingCatPlayback_NotAdmissible) {
    EXPECT_FALSE(admissible(PskCategory::PAIRING, acts(PB), false, false));
    EXPECT_FALSE(admissible(PskCategory::PAIRING, acts(PB), true, false));
}

// ============================================================================
// pairing_required vs unauthorized selection (admissibility-based reject reason)
// ============================================================================

// Helper: returns the goodbye reason for an inadmissible activate (mirrors the activate handler).
// pairing_required when SENTINEL+!unpaired_access+would-be-admissible-with-unpaired-access=true.
// unauthorized otherwise.
static SendspinGoodbyeReason reject_reason_for(PskCategory cat,
                                               const std::vector<SendspinActivity>& activities,
                                               bool has_roles, bool unpaired_access) {
    if (cat == PskCategory::SENTINEL && !unpaired_access &&
        admissible(cat, activities, has_roles, /*unpaired_access=*/true)) {
        return SendspinGoodbyeReason::PAIRING_REQUIRED;
    }
    return SendspinGoodbyeReason::UNAUTHORIZED;
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

TEST(RejectReason, SentinelManagement_Unauthorized) {
    // Still unauthorized even with unpaired_access=true, unlike the PLAYBACK cases above.
    EXPECT_EQ(reject_reason_for(PskCategory::SENTINEL, acts(MG), false, false),
              SendspinGoodbyeReason::UNAUTHORIZED);
}

TEST(RejectReason, SentinelEmptyHasRolesNoUnpaired_PairingRequired) {
    // SENTINEL + {} + has_roles + !unpaired_access:
    // admissible(SENTINEL, {}, true, true) = true -> pairing_required
    EXPECT_EQ(reject_reason_for(PskCategory::SENTINEL, acts(), true, false),
              SendspinGoodbyeReason::PAIRING_REQUIRED);
}

TEST(RejectReason, LongTermPairingPlayback_Unauthorized) {
    // {PAIRING, PLAYBACK} is not allowed at all for LONG_TERM, not just with unpaired_access.
    EXPECT_EQ(reject_reason_for(PskCategory::LONG_TERM, acts(PR, PB), false, false),
              SendspinGoodbyeReason::UNAUTHORIZED);
}

TEST(RejectReason, PairingCatPlayback_Unauthorized) {
    EXPECT_EQ(reject_reason_for(PskCategory::PAIRING, acts(PB), false, false),
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

TEST(ActivityRank, Management_Three) {
    EXPECT_EQ(activity_rank(acts(MG)), 3);
}

TEST(ActivityRank, ManagementPlayback_Three) {
    EXPECT_EQ(activity_rank(acts(MG, PB)), 3);
}

TEST(ActivityRank, ManagementAll_Three) {
    EXPECT_EQ(activity_rank(acts(MG, PB, PR)), 3);
}

TEST(ActivityRank, Ordering) {
    EXPECT_GT(activity_rank(acts(MG)), activity_rank(acts(PB)));
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
                  const std::string& last_playback = "", bool has_last = false) {
    return should_admit_connection(incoming_acts, incoming_id, admitted_acts, admitted_id,
                                   has_admitted, last_playback, has_last);
}

TEST(ShouldAdmit, NoCurrent_AlwaysAdmit) {
    EXPECT_TRUE(admit(acts(), "new", acts(), "", false));
    EXPECT_TRUE(admit(acts(PB), "new", acts(), "", false));
    EXPECT_TRUE(admit(acts(MG), "new", acts(), "", false));
}

TEST(ShouldAdmit, HigherRankDisplaces) {
    // incoming=playback(2), admitted=pairing(1), but pairing is not displaced by rank 2
    // (the in-flight-pairing rule blocks it)
    EXPECT_FALSE(admit(acts(PB), "new", acts(PR), "old", true));

    // incoming=management(3), admitted=pairing(1)
    // admitted_rank=1; incoming_rank=3 -> 3 > 1, and rank-3 is not in {1,2}, so -> admit
    EXPECT_TRUE(admit(acts(MG), "new", acts(PR), "old", true));

    // incoming=management(3), admitted=playback(2)
    EXPECT_TRUE(admit(acts(MG), "new", acts(PB), "old", true));
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

    // Both management(3) -> admit incoming
    EXPECT_TRUE(admit(acts(MG), "new", acts(MG), "old", true));
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

TEST(ShouldAdmit, ManagementDisplacesPlayback) {
    // incoming=management(3), admitted=playback(2) -> admit
    EXPECT_TRUE(admit(acts(MG), "new", acts(PB), "old", true));
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
