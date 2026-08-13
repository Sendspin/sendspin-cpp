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

// Unit tests for the in-memory pairing record store and keypair persistence.
// Mirrors the CLIENT-relevant cases from:
//   aiosendspin/tests/noise/test_trust_store.py
// and adds C++-specific tests for keypair persistence and first-boot
// provisioning. Most tests exercise RecordStore and FilePersistenceProvider
// standalone; the KeypairPersistsViaClientStartServer test below exercises
// the full SendspinClient::start_server() -> client_id() path.

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "file_persistence_provider.h"
#include "platform/crypto.h"
#include "platform/logging.h"
#include "record_store.h"
#include "sendspin/client.h"
#include "sendspin/config.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>

using namespace sendspin;  // NOLINT(google-build-using-namespace) -- test-local convenience

// =============================================================================
// Test helpers
// =============================================================================

/// Generate a random 32-byte PSK.
static std::array<uint8_t, NOISE_PSK_SIZE> make_random_psk() {
    std::array<uint8_t, NOISE_PSK_SIZE> psk{};
    platform_random_bytes(psk.data(), psk.size());
    return psk;
}

/// Build a stored-pubkey client record bound to server_id.
static SendspinPairingRecord make_client_record(const std::string& server_id,
                                                const std::optional<std::string>& label = {}) {
    auto psk = make_random_psk();
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_for(psk);
    rec.psk = psk;
    rec.server_id = server_id;
    rec.label = label;
    return rec;
}

/// Build a shared-PSK (fallback) record - no server_id.
static SendspinPairingRecord make_shared_record(
    const std::optional<std::string>& label = {}) {
    auto psk = make_random_psk();
    SendspinPairingRecord rec;
    rec.psk_id = psk_id_for(psk);
    rec.psk = psk;
    // server_id absent = shared record
    rec.label = label;
    return rec;
}

/// Build an accepted Pairing PSK.
static SendspinPairingPsk make_pairing_psk(const std::optional<std::string>& label = {}) {
    auto psk = make_random_psk();
    SendspinPairingPsk p;
    p.psk_id = psk_id_for(psk);
    p.psk = psk;
    p.label = label;
    return p;
}

/// A RecordStore subclass that always reports storage exhausted.
class ExhaustedRecordStore : public RecordStore {
public:
    explicit ExhaustedRecordStore(SendspinPersistenceProvider* provider)
        : RecordStore(provider) {}

    bool can_store_record() const override {
        return false;
    }
};

/// A persistence provider whose pairing-record writes can be made to fail
/// (e.g. full or faulty flash).
class RejectingPersistenceProvider : public SendspinPersistenceProvider {
public:
    bool save_pairing_record(const SendspinPairingRecord& /*record*/) override {
        save_attempts++;
        return !reject;
    }

    bool reject{true};
    int save_attempts{0};
};

// =============================================================================
// Basic construction / first-boot provisioning
// =============================================================================

TEST(RecordStore, FirstBootProvisioningCreatesSharedFallback) {
    RecordStore store(nullptr);

    // A non-empty record_mode_psk_id should have been assigned.
    EXPECT_FALSE(store.record_mode_psk_id().empty());

    // The referenced record must exist and have no server_id (shared-PSK record).
    const auto* rec = store.record_by_psk_id(store.record_mode_psk_id());
    ASSERT_NE(rec, nullptr);
    EXPECT_FALSE(rec->server_id.has_value()) << "fallback record must be a shared-PSK record";
}

TEST(RecordStore, FirstBootProvisioningCreatesPairingPsk) {
    RecordStore store(nullptr);

    // pairing_psk is the client-mandatory pairing method, so a Pairing PSK must exist even
    // when nothing was ever persisted, and it must resolve as the PAIRING category.
    ASSERT_TRUE(store.pairing_psk().has_value());
    EXPECT_EQ(store.pairing_psk()->psk_id, psk_id_for(store.pairing_psk()->psk));

    auto resolved = store.resolve_by_psk_id(store.pairing_psk()->psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::PAIRING);
    EXPECT_EQ(resolved->psk, store.pairing_psk()->psk);

    // It must also differ from the shared-PSK fallback record's key.
    const auto* shared = store.record_by_psk_id(store.record_mode_psk_id());
    ASSERT_NE(shared, nullptr);
    EXPECT_NE(store.pairing_psk()->psk, shared->psk);
}

/// A persistence provider whose writes for the shared-PSK record, the Pairing PSK, and the
/// pairing config always fail (e.g. full or read-only NVS), used to verify first-boot
/// provisioning surfaces a rejected write instead of silently discarding it (Finding D).
class AlwaysRejectingProvider : public SendspinPersistenceProvider {
public:
    bool save_pairing_record(const SendspinPairingRecord& /*record*/) override {
        record_save_attempts++;
        return false;
    }
    bool save_pairing_psk(const SendspinPairingPsk& /*psk*/) override {
        psk_save_attempts++;
        return false;
    }
    bool save_pairing_config(const SendspinPairingConfig& /*config*/) override {
        config_save_attempts++;
        return false;
    }

    int record_save_attempts{0};
    int psk_save_attempts{0};
    int config_save_attempts{0};
};

// Finding D: a provider that rejects every write during first-boot provisioning must not be
// silently ignored. The device must still be fully usable for the current boot (RAM-only state),
// and the provider must actually have been asked to persist each piece of material.
TEST(RecordStore, FirstBootProvisioningSurvivesPersistenceFailureForThisBoot) {
    AlwaysRejectingProvider provider;
    RecordStore store(&provider);

    EXPECT_GE(provider.record_save_attempts, 1)
        << "the shared-PSK fallback record write must have been attempted";
    EXPECT_GE(provider.psk_save_attempts, 1) << "the Pairing PSK write must have been attempted";

    // Despite every write being rejected, the device remains usable for this boot: both the
    // shared fallback record and the Pairing PSK are present and resolvable in memory.
    ASSERT_FALSE(store.record_mode_psk_id().empty());
    const auto* shared = store.record_by_psk_id(store.record_mode_psk_id());
    ASSERT_NE(shared, nullptr);
    EXPECT_FALSE(shared->server_id.has_value());

    ASSERT_TRUE(store.pairing_psk().has_value());
    auto resolved = store.resolve_by_psk_id(store.pairing_psk()->psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::PAIRING);
}

TEST(RecordStore, FirstBootPskIdIsSentinelPskIdResolvable) {
    RecordStore store(nullptr);

    // Even on first boot the Sentinel PSK must be resolvable.
    auto resolved = store.resolve_by_psk_id(SENTINEL_PSK_ID);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::SENTINEL);
    EXPECT_EQ(resolved->psk_id, SENTINEL_PSK_ID);
    EXPECT_EQ(resolved->psk, SENTINEL_PSK);
}

// =============================================================================
// Records - reject wrong PSK size
// =============================================================================

TEST(RecordStore, RecordsRejectWrongPskSize) {
    RecordStore store(nullptr);

    // Constructing a record with a wrong-size PSK and then trying to store it
    // in a typed way: the C++ type uses std::array<uint8_t, 32> so a size
    // mismatch is a compile-time error. We verify that psk_id_for() rejects
    // non-32-byte inputs, which is the equivalent runtime guard.
    std::array<uint8_t, 16> short_psk{};
    auto result = psk_id_for(short_psk.data(), short_psk.size());
    EXPECT_FALSE(result.has_value()) << "psk_id_for must reject < 32 bytes";

    std::array<uint8_t, 64> long_psk{};
    auto result2 = psk_id_for(long_psk.data(), long_psk.size());
    EXPECT_FALSE(result2.has_value()) << "psk_id_for must reject > 32 bytes";
}

// =============================================================================
// store_record: provider failure fails closed
// =============================================================================

TEST(RecordStore, StoreRecordFailsClosedWhenProviderRejectsWrite) {
    RejectingPersistenceProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord rec = make_client_record("server-X");
    EXPECT_FALSE(store.store_record(rec)) << "provider rejection must be reported";
    EXPECT_GE(provider.save_attempts, 1);

    // The in-memory store must be untouched: the record is neither resolvable for a
    // handshake nor listed.
    auto resolved = store.resolve_by_psk_id(rec.psk_id);
    EXPECT_TRUE(!resolved.has_value() || resolved->category != PskCategory::LONG_TERM)
        << "a rejected record must not resolve as long-term";
    EXPECT_EQ(store.record_by_psk_id(rec.psk_id), nullptr);
}

TEST(RecordStore, StoreRecordReportsSuccessWithoutProvider) {
    RecordStore store(nullptr);

    SendspinPairingRecord rec = make_client_record("server-X");
    EXPECT_TRUE(store.store_record(rec)) << "in-memory-only store must report success";
    EXPECT_NE(store.record_by_psk_id(rec.psk_id), nullptr);
}

TEST(RecordStore, StoreRecordRejectionDoesNotReplaceExistingRecord) {
    // Store an original record while the provider accepts, then flip the provider to
    // rejecting and try to overwrite it under the same psk_id: the original must survive.
    RejectingPersistenceProvider provider;
    provider.reject = false;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X", "original");
    ASSERT_TRUE(store.store_record(original));

    provider.reject = true;
    SendspinPairingRecord replacement = original;
    replacement.label = "replacement";
    EXPECT_FALSE(store.store_record(replacement));

    const auto* kept = store.record_by_psk_id(original.psk_id);
    ASSERT_NE(kept, nullptr);
    EXPECT_EQ(kept->label, std::optional<std::string>("original"))
        << "a rejected overwrite must leave the existing record untouched";
}

// =============================================================================
// store_record: at most one record per server_id (Finding A supersede invariant)
// =============================================================================

// Re-pairing the same server_id twice (e.g. after the server was factory-reset and re-paired)
// must revoke the prior per-server PSK rather than leaving it valid forever alongside the new
// one. Mirrors the server/pair-finalize ack commit path: resolve_pairing_outcome() mints a
// fresh record, then store_record() commits it.
TEST(RecordStore, StoreRecordSupersedesPriorRecordForSameServerId) {
    RecordStore store(nullptr);
    const std::string server_id = "server-repair";

    auto outcome1 = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(outcome1.has_value());
    ASSERT_TRUE(outcome1->record.has_value());
    ASSERT_TRUE(store.store_record_superseding(outcome1->record.value()));
    const std::string first_psk_id = outcome1->record->psk_id;

    auto outcome2 = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(outcome2.has_value());
    ASSERT_TRUE(outcome2->record.has_value());
    ASSERT_TRUE(store.store_record_superseding(outcome2->record.value()));
    const std::string second_psk_id = outcome2->record->psk_id;

    ASSERT_NE(first_psk_id, second_psk_id);

    // The prior PSK must no longer resolve at all: re-pairing revokes it instead of leaving a
    // second working credential for the same server.
    EXPECT_FALSE(store.resolve_by_psk_id(first_psk_id).has_value());
    EXPECT_EQ(store.record_by_psk_id(first_psk_id), nullptr);

    // The new PSK resolves as the server's long-term record.
    auto resolved = store.resolve_by_psk_id(second_psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
    EXPECT_EQ(resolved->counterparty_id, server_id);

    // Exactly one record remains bound to this server_id.
    const auto* found = store.record_by_server_id(server_id);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, second_psk_id);
    int count = 0;
    for (const auto& r : store.records_snapshot()) {
        if (r.server_id.has_value() && r.server_id.value() == server_id) {
            count++;
        }
    }
    EXPECT_EQ(count, 1);
}

// The supersede must not happen before the new record is safely persisted: a rejected write
// leaves the OLD (still-working) record in place rather than destroying it for nothing.
TEST(RecordStore, StoreRecordSupersedeRejectedWriteKeepsOldRecord) {
    RejectingPersistenceProvider provider;
    provider.reject = false;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X", "original");
    ASSERT_TRUE(store.store_record_superseding(original));

    provider.reject = true;
    SendspinPairingRecord replacement = make_client_record("server-X", "replacement");
    EXPECT_FALSE(store.store_record_superseding(replacement))
        << "a rejected write must not supersede the working credential";

    // The old record must still resolve and be the only one for this server_id.
    auto resolved = store.resolve_by_psk_id(original.psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
    EXPECT_EQ(store.record_by_psk_id(replacement.psk_id), nullptr);

    const auto* found = store.record_by_server_id("server-X");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, original.psk_id);
}

// =============================================================================
// resolve_by_psk_id: long-term first, then Pairing PSK, then Sentinel
// =============================================================================

TEST(RecordStore, ResolveByPskIdLongTermFirst) {
    RecordStore store(nullptr);

    SendspinPairingRecord rec = make_client_record("server-X");
    store.store_record(rec);

    auto resolved = store.resolve_by_psk_id(rec.psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
    EXPECT_EQ(resolved->psk_id, rec.psk_id);
    EXPECT_EQ(resolved->psk, rec.psk);
    EXPECT_EQ(resolved->counterparty_id, rec.server_id);
}

TEST(RecordStore, ResolveByPskIdPairingPskSecond) {
    RecordStore store(nullptr);

    SendspinPairingPsk p = make_pairing_psk();
    store.set_pairing_psk(p);

    auto resolved = store.resolve_by_psk_id(p.psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::PAIRING);
    EXPECT_FALSE(resolved->counterparty_id.has_value());
}

TEST(RecordStore, LongTermRecordWinsOverPairingPskWithSamePskId) {
    RecordStore store(nullptr);

    // Build a record and a pairing PSK that share the same psk_id (and PSK bytes).
    SendspinPairingRecord rec = make_client_record("server-X");
    SendspinPairingPsk p;
    p.psk_id = rec.psk_id;
    p.psk = rec.psk;
    p.label = "dup";

    store.set_pairing_psk(p);
    store.store_record(rec);

    // Long-term record must win.
    auto resolved = store.resolve_by_psk_id(rec.psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
    EXPECT_EQ(resolved->counterparty_id, rec.server_id);
}

TEST(RecordStore, ResolveByPskIdSentinelAlwaysResolvable) {
    RecordStore store(nullptr);

    auto resolved = store.resolve_by_psk_id(SENTINEL_PSK_ID);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::SENTINEL);
    EXPECT_EQ(resolved->psk, SENTINEL_PSK);
    EXPECT_FALSE(resolved->counterparty_id.has_value());
}

TEST(RecordStore, ResolveByPskIdUnknownReturnsNullopt) {
    RecordStore store(nullptr);

    auto resolved = store.resolve_by_psk_id("nope-not-a-real-psk-id");
    EXPECT_FALSE(resolved.has_value());
}

// =============================================================================
// record_by_server_id
// =============================================================================

TEST(RecordStore, RecordByServerIdFindsStoredPubkeyRecord) {
    RecordStore store(nullptr);

    SendspinPairingRecord rec = make_client_record("server-X");
    store.store_record(rec);

    const auto* found = store.record_by_server_id("server-X");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, rec.psk_id);
    EXPECT_EQ(found->server_id, rec.server_id);

    // Unknown server returns null.
    EXPECT_EQ(store.record_by_server_id("server-Y"), nullptr);
}

TEST(RecordStore, RecordByServerIdDoesNotReturnSharedRecord) {
    RecordStore store(nullptr);

    SendspinPairingRecord shared = make_shared_record();
    store.store_record(shared);

    // Shared records have no server_id and must not appear in server_id lookup.
    EXPECT_EQ(store.record_by_server_id("any-server"), nullptr);
}

// =============================================================================
// mark_record_used
// =============================================================================

TEST(RecordStore, MarkRecordUsed) {
    RecordStore store(nullptr);

    SendspinPairingRecord rec = make_client_record("server-X");
    EXPECT_FALSE(rec.used);
    store.store_record(rec);

    store.mark_record_used(rec.psk_id);

    const auto* found = store.record_by_psk_id(rec.psk_id);
    ASSERT_NE(found, nullptr);
    EXPECT_TRUE(found->used);

    // Calling again is a no-op (should not crash).
    store.mark_record_used(rec.psk_id);
    EXPECT_TRUE(store.record_by_psk_id(rec.psk_id)->used);
}

TEST(RecordStore, MarkRecordUsedOnAbsentPskIdIsNoOp) {
    RecordStore store(nullptr);
    // Should not crash.
    store.mark_record_used("does-not-exist");
}

// =============================================================================
// remove_record and list
// =============================================================================

TEST(RecordStore, RemoveRecordAndList) {
    RecordStore store(nullptr);

    SendspinPairingRecord a = make_client_record("server-A");
    SendspinPairingRecord b = make_client_record("server-B");
    store.store_record(a);
    store.store_record(b);

    // Both records are now findable.
    EXPECT_NE(store.record_by_psk_id(a.psk_id), nullptr);
    EXPECT_NE(store.record_by_psk_id(b.psk_id), nullptr);

    store.remove_record(a.psk_id);
    EXPECT_EQ(store.record_by_psk_id(a.psk_id), nullptr);
    EXPECT_NE(store.record_by_psk_id(b.psk_id), nullptr);

    // Removing an absent record is a no-op.
    store.remove_record("absent-psk-id");
}

/// A provider that accepts writes but can refuse deletes, standing in for a store whose delete
/// path fails on its own (full or read-only NVS, a torn write) while saves still work. A refused
/// delete leaves the entry in `saved`, so a later load_pairing_records() hands it back exactly
/// as a real store would after a reboot.
class RejectingDeleteProvider : public SendspinPersistenceProvider {
public:
    bool save_pairing_record(const SendspinPairingRecord& record) override {
        saved.push_back(record);
        return true;
    }
    std::vector<SendspinPairingRecord> load_pairing_records() override {
        return saved;
    }
    bool remove_pairing_record(const std::string& psk_id) override {
        remove_attempts.push_back(psk_id);
        if (refuse_delete) {
            return false;  // The record stays on "disk".
        }
        saved.erase(std::remove_if(saved.begin(), saved.end(),
                                   [&](const SendspinPairingRecord& r) {
                                       return r.psk_id == psk_id;
                                   }),
                    saved.end());
        return true;
    }
    bool save_pairing_psk(const SendspinPairingPsk& /*psk*/) override {
        return true;
    }
    bool clear_pairing_psk() override {
        clear_psk_attempts++;
        return !refuse_delete;
    }
    bool save_static_pin(const std::string& /*pin*/) override {
        return true;
    }
    bool clear_static_pin() override {
        clear_pin_attempts++;
        return !refuse_delete;
    }
    bool save_pairing_config(const SendspinPairingConfig& /*config*/) override {
        return true;
    }

    bool refuse_delete{true};
    std::vector<SendspinPairingRecord> saved{};
    std::vector<std::string> remove_attempts{};
    int clear_psk_attempts{0};
    int clear_pin_attempts{0};
};

/// Captures stderr (where the host SS_LOG* macros write) for the duration of its scope, so a
/// test can assert on the durability warning itself. The warning IS the behavioral delta of the
/// bool return: without asserting on it, a reverted or inverted condition passes unnoticed,
/// because the in-memory erase and the reload-after-reboot were already unconditional before.
class StderrCapture {
public:
    StderrCapture() : prior_level_(platform_get_log_level()) {
        platform_set_log_level(SS_LOG_WARN);
        testing::internal::CaptureStderr();
    }
    ~StderrCapture() {
        if (!released_) {
            static_cast<void>(testing::internal::GetCapturedStderr());
        }
        platform_set_log_level(prior_level_);
    }
    StderrCapture(const StderrCapture&) = delete;
    StderrCapture& operator=(const StderrCapture&) = delete;

    /// Stops capturing and returns everything written so far.
    std::string release() {
        released_ = true;
        return testing::internal::GetCapturedStderr();
    }

private:
    int prior_level_;
    bool released_{false};
};

/// The durability warning always says the credential comes back after a reboot; that phrase is
/// what distinguishes it from the routine "Superseding prior record" info line.
constexpr const char* REBOOT_WARNING = "after a reboot";

// A delete the provider refuses must still revoke the credential for the current boot: leaving
// it in RAM because the store could not be written would keep it usable right now, which is
// strictly worse than a revocation that only fails to outlive a reboot. The provider is asked
// exactly once, and its refusal must be reported rather than swallowed.
TEST(RecordStore, RemoveRecordErasesFromMemoryAndWarnsWhenTheProviderRefusesTheDelete) {
    RejectingDeleteProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord a = make_client_record("server-A");
    store.store_record(a);
    ASSERT_NE(store.record_by_psk_id(a.psk_id), nullptr);

    std::string logs;
    {
        StderrCapture capture;
        store.remove_record(a.psk_id);
        logs = capture.release();
    }

    EXPECT_EQ(store.record_by_psk_id(a.psk_id), nullptr)
        << "a refused delete must not leave the revoked credential resolvable this boot";
    EXPECT_FALSE(store.resolve_by_psk_id(a.psk_id).has_value());
    ASSERT_EQ(provider.remove_attempts.size(), 1u);
    EXPECT_EQ(provider.remove_attempts[0], a.psk_id);
    EXPECT_NE(logs.find(REBOOT_WARNING), std::string::npos)
        << "a refused delete must be reported, not swallowed; got: " << logs;
    EXPECT_NE(logs.find(a.psk_id), std::string::npos)
        << "the warning must name the record that will come back; got: " << logs;
}

// The other half of the contract, and what pins the condition's direction: a delete the provider
// accepted is durable, so it must NOT warn. Without this an inverted test would pass.
TEST(RecordStore, RemoveRecordIsSilentWhenTheProviderAcceptsTheDelete) {
    RejectingDeleteProvider provider;
    provider.refuse_delete = false;
    RecordStore store(&provider);

    SendspinPairingRecord a = make_client_record("server-A");
    store.store_record(a);

    std::string logs;
    {
        StderrCapture capture;
        store.remove_record(a.psk_id);
        logs = capture.release();
    }

    EXPECT_EQ(store.record_by_psk_id(a.psk_id), nullptr);
    ASSERT_EQ(provider.remove_attempts.size(), 1u);
    EXPECT_EQ(logs.find(REBOOT_WARNING), std::string::npos)
        << "a delete the store accepted is durable and must not warn; got: " << logs;
}

// Same contract on the pairing/supersede path: the prior record goes even though the provider
// refused to delete it, and the refusal is reported.
TEST(RecordStore, SupersedeErasesFromMemoryAndWarnsWhenTheProviderRefusesTheDelete) {
    RejectingDeleteProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X", "original");
    ASSERT_TRUE(store.store_record_superseding(original));

    SendspinPairingRecord replacement = make_client_record("server-X", "replacement");
    std::string logs;
    {
        StderrCapture capture;
        ASSERT_TRUE(store.store_record_superseding(replacement));
        logs = capture.release();
    }

    EXPECT_EQ(store.record_by_psk_id(original.psk_id), nullptr);
    EXPECT_FALSE(store.resolve_by_psk_id(original.psk_id).has_value());
    EXPECT_NE(store.record_by_psk_id(replacement.psk_id), nullptr);
    ASSERT_EQ(provider.remove_attempts.size(), 1u);
    EXPECT_EQ(provider.remove_attempts[0], original.psk_id);
    EXPECT_NE(logs.find(REBOOT_WARNING), std::string::npos)
        << "a refused supersede-delete must be reported; got: " << logs;
}

// A supersede whose delete the store accepted is durable: no warning, and the prior record is
// really gone from the provider (so it does not come back on the next start).
TEST(RecordStore, SupersedeIsSilentWhenTheProviderAcceptsTheDelete) {
    RejectingDeleteProvider provider;
    provider.refuse_delete = false;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X", "original");
    ASSERT_TRUE(store.store_record_superseding(original));

    SendspinPairingRecord replacement = make_client_record("server-X", "replacement");
    std::string logs;
    {
        StderrCapture capture;
        ASSERT_TRUE(store.store_record_superseding(replacement));
        logs = capture.release();
    }

    EXPECT_EQ(logs.find(REBOOT_WARNING), std::string::npos)
        << "an accepted supersede-delete must not warn; got: " << logs;

    RecordStore rebooted(&provider);
    EXPECT_FALSE(rebooted.resolve_by_psk_id(original.psk_id).has_value());
    EXPECT_TRUE(rebooted.resolve_by_psk_id(replacement.psk_id).has_value());
}

// The Pairing PSK and the static PIN are revocations too, and carry the same contract: a store
// that keeps them keeps authenticating pairing / pairing devices after a reboot.
TEST(RecordStore, ClearPairingPskAndStaticPinWarnOnlyWhenTheProviderRefuses) {
    RejectingDeleteProvider provider;
    RecordStore store(&provider);

    std::string refused_logs;
    {
        StderrCapture capture;
        store.clear_pairing_psk();
        store.clear_static_pin();
        refused_logs = capture.release();
    }
    EXPECT_EQ(provider.clear_psk_attempts, 1);
    EXPECT_EQ(provider.clear_pin_attempts, 1);
    EXPECT_NE(refused_logs.find(REBOOT_WARNING), std::string::npos)
        << "refused clears must be reported; got: " << refused_logs;

    provider.refuse_delete = false;
    std::string accepted_logs;
    {
        StderrCapture capture;
        store.clear_pairing_psk();
        store.clear_static_pin();
        accepted_logs = capture.release();
    }
    EXPECT_EQ(accepted_logs.find(REBOOT_WARNING), std::string::npos)
        << "accepted clears must not warn; got: " << accepted_logs;
}

// The refused delete is exactly the durability hole the bool return exists to surface: the
// record the store kept comes back on the next start, and resolves as LONG_TERM trust again.
TEST(RecordStore, RefusedDeleteLetsTheRevokedRecordReturnAfterAReboot) {
    RejectingDeleteProvider provider;

    SendspinPairingRecord a = make_client_record("server-A");
    {
        RecordStore store(&provider);
        store.store_record(a);
        store.remove_record(a.psk_id);
        ASSERT_EQ(store.record_by_psk_id(a.psk_id), nullptr);
    }

    // Reboot: a new store over the same provider reloads what the provider still holds.
    RecordStore rebooted(&provider);
    auto resolved = rebooted.resolve_by_psk_id(a.psk_id);
    ASSERT_TRUE(resolved.has_value())
        << "the provider kept the record, so it must come back -- this is what the false return "
           "from remove_pairing_record() warns about";
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
}

// =============================================================================
// set_record_mode_psk_id: must reference a shared-PSK record
// =============================================================================

TEST(RecordStore, SetRecordModePskIdValidation) {
    RecordStore store(nullptr);

    SendspinPairingRecord shared = make_shared_record();
    SendspinPairingRecord pubkey = make_client_record("server-X");
    store.store_record(shared);
    store.store_record(pubkey);

    // Missing psk_id -> fails.
    EXPECT_FALSE(store.set_record_mode_psk_id("missing-psk-id"));

    // Stored-pubkey record -> fails (must be shared).
    EXPECT_FALSE(store.set_record_mode_psk_id(pubkey.psk_id));

    // Valid shared record -> succeeds.
    EXPECT_TRUE(store.set_record_mode_psk_id(shared.psk_id));
    EXPECT_EQ(store.record_mode_psk_id(), shared.psk_id);
}

// =============================================================================
// can_remove_record: record_mode-referenced record is protected
// =============================================================================

TEST(RecordStore, CanRemoveRecordProtectsRecordModeFallback) {
    RecordStore store(nullptr);

    // The auto-provisioned fallback record is the record_mode record.
    const std::string& protected_id = store.record_mode_psk_id();
    EXPECT_FALSE(store.can_remove_record(protected_id))
        << "record_mode-referenced record must not be removable";

    // A different record is removable.
    SendspinPairingRecord other = make_client_record("server-X");
    store.store_record(other);
    EXPECT_TRUE(store.can_remove_record(other.psk_id));
}

// =============================================================================
// resolve_pairing_outcome: normal and fallback paths
// =============================================================================

TEST(RecordStore, ResolveOutcomeMintsFreshRecord) {
    RecordStore store(nullptr);

    auto outcome = store.resolve_pairing_outcome("server-X", "My Hub");
    ASSERT_TRUE(outcome.has_value());
    ASSERT_TRUE(outcome->record.has_value());

    EXPECT_EQ(outcome->record->server_id, "server-X");
    EXPECT_EQ(outcome->record->label, "My Hub");
    EXPECT_EQ(outcome->psk, outcome->record->psk);
    EXPECT_EQ(outcome->record->psk_id, psk_id_for(outcome->psk));
}

TEST(RecordStore, ResolveOutcomeFallsBackToSharedOnExhaustion) {
    ExhaustedRecordStore store(nullptr);

    // Pre-provision and set a shared record (the auto-provisioned one works fine).
    const std::string& shared_psk_id = store.record_mode_psk_id();

    auto outcome = store.resolve_pairing_outcome("server-X");
    ASSERT_TRUE(outcome.has_value()) << "fallback must succeed when shared record exists";
    EXPECT_FALSE(outcome->record.has_value()) << "storage exhausted: no new record";

    // The returned PSK must match the shared record's PSK.
    const auto* shared = store.record_by_psk_id(shared_psk_id);
    ASSERT_NE(shared, nullptr);
    EXPECT_EQ(outcome->psk, shared->psk);
}

// =============================================================================
// Pairing PSK lifecycle
// =============================================================================

TEST(RecordStore, PairingPskLifecycle) {
    RecordStore store(nullptr);

    // First-boot provisioning already installed one; setting replaces it.
    ASSERT_TRUE(store.pairing_psk().has_value());
    const std::string provisioned_psk_id = store.pairing_psk()->psk_id;

    SendspinPairingPsk p = make_pairing_psk();
    store.set_pairing_psk(p);
    EXPECT_TRUE(store.pairing_psk().has_value());
    EXPECT_EQ(store.pairing_psk()->psk_id, p.psk_id);
    EXPECT_FALSE(store.resolve_by_psk_id(provisioned_psk_id).has_value());

    // Setting a new one replaces the old.
    SendspinPairingPsk other = make_pairing_psk();
    store.set_pairing_psk(other);
    EXPECT_EQ(store.pairing_psk()->psk_id, other.psk_id);

    store.clear_pairing_psk();
    EXPECT_FALSE(store.pairing_psk().has_value());
    EXPECT_FALSE(store.resolve_by_psk_id(other.psk_id).has_value());

    // Clearing when absent is a no-op.
    store.clear_pairing_psk();
}

/// A persistence provider that hands back a Pairing PSK whose psk_id does not match its secret.
class MismatchedPairingPskProvider : public SendspinPersistenceProvider {
public:
    explicit MismatchedPairingPskProvider(SendspinPairingPsk psk) : psk_(std::move(psk)) {}

    std::optional<SendspinPairingPsk> load_pairing_psk() override {
        return this->psk_;
    }

    bool save_pairing_psk(const SendspinPairingPsk& psk) override {
        this->saved = psk;
        return true;
    }

    std::optional<SendspinPairingPsk> saved;

private:
    SendspinPairingPsk psk_;
};

TEST(RecordStore, PairingPskIdIsDerivedFromTheSecret) {
    // A caller-supplied psk_id is ignored: the server references the derived id, so anything
    // else would never resolve.
    RecordStore store(nullptr);
    SendspinPairingPsk p = make_pairing_psk();
    const std::string correct_psk_id = p.psk_id;
    p.psk_id = "not-a-derived-psk-id";
    store.set_pairing_psk(p);

    ASSERT_TRUE(store.pairing_psk().has_value());
    EXPECT_EQ(store.pairing_psk()->psk_id, correct_psk_id);
    EXPECT_TRUE(store.resolve_by_psk_id(correct_psk_id).has_value());
    EXPECT_FALSE(store.resolve_by_psk_id("not-a-derived-psk-id").has_value());
}

TEST(RecordStore, LoadedPairingPskIdIsCorrected) {
    SendspinPairingPsk stored = make_pairing_psk();
    const std::string correct_psk_id = stored.psk_id;
    stored.psk_id = "stale-psk-id";
    MismatchedPairingPskProvider provider(stored);

    RecordStore store(&provider);

    ASSERT_TRUE(store.pairing_psk().has_value());
    EXPECT_EQ(store.pairing_psk()->psk_id, correct_psk_id);
    EXPECT_EQ(store.pairing_psk()->psk, stored.psk) << "the secret itself must be preserved";
    EXPECT_TRUE(store.resolve_by_psk_id(correct_psk_id).has_value());
    EXPECT_FALSE(provider.saved.has_value())
        << "a loaded Pairing PSK must not trigger re-provisioning";
}

// =============================================================================
// Keypair persistence across "reboots" via FilePersistenceProvider
// =============================================================================

class TempFile {
public:
    TempFile() {
        std::filesystem::path p =
            std::filesystem::temp_directory_path() /
            ("sendspin_test_" + std::to_string(reinterpret_cast<uintptr_t>(this)) + ".json");
        path_ = p.string();
    }
    ~TempFile() {
        std::filesystem::remove(path_);
        std::filesystem::remove(path_ + ".tmp");
    }
    const std::string& path() const {
        return path_;
    }

private:
    std::string path_;
};

TEST(FilePersistenceProvider, KeypairPersistsAcrossReboots) {
    TempFile tmp;

    std::string client_id_first;
    std::array<uint8_t, X25519_KEY_SIZE> pub_first{};

    // "First boot": generate and persist.
    {
        FilePersistenceProvider provider(tmp.path());
        auto loaded = provider.load_static_keypair();
        EXPECT_FALSE(loaded.has_value()) << "No key yet on first boot";

        Identity id = Identity::generate().value();
        EXPECT_TRUE(provider.save_static_keypair(id.private_bytes));
        client_id_first = id.peer_id();
        pub_first = id.public_bytes;
    }

    // "Reboot": reload and verify same keypair.
    {
        FilePersistenceProvider provider(tmp.path());
        auto loaded = provider.load_static_keypair();
        ASSERT_TRUE(loaded.has_value()) << "Key should be present after first boot";

        Identity rehydrated = Identity::from_private_bytes(loaded.value()).value();
        EXPECT_EQ(rehydrated.public_bytes, pub_first);
        EXPECT_EQ(rehydrated.peer_id(), client_id_first);
    }
}

// Exercises the full public path: SendspinClient::start_server() loads or generates the
// identity via load_or_generate_identity() and exposes it through client_id(). Two separate
// SendspinClient instances sharing the same FilePersistenceProvider file must derive the same
// client_id -- the second instance is the "reboot" case.
TEST(FilePersistenceProvider, KeypairPersistsViaClientStartServer) {
    TempFile tmp;

    std::string client_id_first;
    {
        FilePersistenceProvider provider(tmp.path());
        SendspinClientConfig config;
        config.name = "test-client";
        SendspinClient client(std::move(config));
        client.set_persistence_provider(&provider);
        ASSERT_TRUE(client.start_server());
        client_id_first = client.client_id();
        EXPECT_FALSE(client_id_first.empty());
    }

    // "Reboot": a fresh SendspinClient over the same persistence file must derive the same
    // client_id from the persisted keypair.
    {
        FilePersistenceProvider provider(tmp.path());
        SendspinClientConfig config;
        config.name = "test-client";
        SendspinClient client(std::move(config));
        client.set_persistence_provider(&provider);
        ASSERT_TRUE(client.start_server());
        EXPECT_EQ(client.client_id(), client_id_first);
    }
}

// Finding #4 regression: load_or_generate_identity() must never leave client_id_ as the peer_id
// of an all-zero Identity (the old silent-failure value). This cannot force the underlying
// noise-c DH-state generation to actually fail (no test hook for that), so it instead pins the
// property that would have caught the original bug: a real client_id must differ from what an
// all-zero keypair would have produced.
TEST(FilePersistenceProvider, StartServerNeverProducesAllZeroClientId) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());
    SendspinClientConfig config;
    config.name = "test-client";
    SendspinClient client(std::move(config));
    client.set_persistence_provider(&provider);
    ASSERT_TRUE(client.start_server());

    Identity zero_identity{};  // default-constructed = all-zero private/public bytes
    EXPECT_NE(client.client_id(), zero_identity.peer_id());
}

TEST(FilePersistenceProvider, PairingRecordRoundTrip) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingRecord rec = make_client_record("server-X", "My Label");

    EXPECT_TRUE(provider.save_pairing_record(rec));

    auto loaded = provider.load_pairing_records();
    ASSERT_EQ(loaded.size(), 1u);
    EXPECT_EQ(loaded[0].psk_id, rec.psk_id);
    EXPECT_EQ(loaded[0].psk, rec.psk);
    EXPECT_EQ(loaded[0].server_id, rec.server_id);
    EXPECT_EQ(loaded[0].label, rec.label);
    EXPECT_EQ(loaded[0].used, rec.used);
}

TEST(FilePersistenceProvider, SharedRecordRoundTrip) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingRecord shared = make_shared_record("Fallback");
    EXPECT_TRUE(provider.save_pairing_record(shared));

    auto loaded = provider.load_pairing_records();
    ASSERT_EQ(loaded.size(), 1u);
    EXPECT_FALSE(loaded[0].server_id.has_value()) << "shared record must have no server_id";
}

TEST(FilePersistenceProvider, RemovePairingRecord) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingRecord a = make_client_record("server-A");
    SendspinPairingRecord b = make_client_record("server-B");
    provider.save_pairing_record(a);
    provider.save_pairing_record(b);

    EXPECT_TRUE(provider.remove_pairing_record(a.psk_id));
    auto loaded = provider.load_pairing_records();
    ASSERT_EQ(loaded.size(), 1u);
    EXPECT_EQ(loaded[0].psk_id, b.psk_id);

    // Removing an absent record leaves the file alone and still reports success.
    EXPECT_TRUE(provider.remove_pairing_record("absent-psk-id"));
    EXPECT_EQ(provider.load_pairing_records().size(), 1u);
}

// Nothing stored at all: there is no record to delete, so the delete succeeded by definition.
// A false here would make every removal on a fresh device log a spurious durability warning.
TEST(FilePersistenceProvider, RemovePairingRecordOnEmptyStoreSucceeds) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    EXPECT_TRUE(provider.remove_pairing_record("never-stored"));
}

// The clear_* revocations carry the same contract as remove_pairing_record().
TEST(FilePersistenceProvider, ClearPairingPskAndStaticPinReportSuccess) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingPsk psk;
    psk.psk_id = "pairing-psk-id";
    psk.psk.fill(0x42);
    ASSERT_TRUE(provider.save_pairing_psk(psk));
    ASSERT_TRUE(provider.load_pairing_psk().has_value());
    EXPECT_TRUE(provider.clear_pairing_psk());
    EXPECT_FALSE(provider.load_pairing_psk().has_value());

    ASSERT_TRUE(provider.save_static_pin("12345678"));
    ASSERT_TRUE(provider.load_static_pin().has_value());
    EXPECT_TRUE(provider.clear_static_pin());
    EXPECT_FALSE(provider.load_static_pin().has_value());

    // Clearing what is already absent is still success.
    EXPECT_TRUE(provider.clear_pairing_psk());
    EXPECT_TRUE(provider.clear_static_pin());
}

TEST(FilePersistenceProvider, LastPlayedServerIdRoundTrip) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    EXPECT_FALSE(provider.load_last_played_server_id().has_value());

    EXPECT_TRUE(provider.save_last_played_server_id("server-id-abc"));
    auto loaded = provider.load_last_played_server_id();
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded.value(), "server-id-abc");
}

TEST(FilePersistenceProvider, PairingConfigRoundTrip) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingConfig cfg;
    cfg.pairing_psk_enabled = false;
    cfg.unpaired_access_enabled = true;
    cfg.record_mode_psk_id = "some-psk-id";

    EXPECT_TRUE(provider.save_pairing_config(cfg));

    auto loaded = provider.load_pairing_config();
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->pairing_psk_enabled, false);
    EXPECT_EQ(loaded->unpaired_access_enabled, true);
    EXPECT_EQ(loaded->record_mode_psk_id, "some-psk-id");
}

// The persistence file holds plaintext secrets (static private key, long-term PSKs,
// Pairing PSK, static PIN), so it must never be group/world readable regardless of
// the process umask. This is host-only POSIX, matching how
// examples/common/file_persistence_provider.cpp itself creates the file.
TEST(FilePersistenceProvider, PersistedFileIsOwnerOnly) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    EXPECT_TRUE(provider.save_static_pin("1234"));

    struct stat st{};
    ASSERT_EQ(::stat(tmp.path().c_str(), &st), 0);
    char mode_str[8];
    std::snprintf(mode_str, sizeof(mode_str), "%04o", st.st_mode & 07777);
    EXPECT_EQ(st.st_mode & 07777, static_cast<unsigned int>(0600))
        << "persisted file must be owner-read/write only, got mode " << mode_str;
}

// =============================================================================
// RecordStore with FilePersistenceProvider: first-boot provisioning persists
// =============================================================================

TEST(RecordStoreWithFile, FirstBootProvisioningPersists) {
    TempFile tmp;

    std::string initial_mode_psk_id;
    std::array<uint8_t, NOISE_PSK_SIZE> initial_pairing_psk{};

    // First boot: should create and persist the shared fallback record and the Pairing PSK.
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider);
        initial_mode_psk_id = store.record_mode_psk_id();
        EXPECT_FALSE(initial_mode_psk_id.empty());
        ASSERT_TRUE(store.pairing_psk().has_value());
        initial_pairing_psk = store.pairing_psk()->psk;
    }

    // Second boot: should load the same material, not generate new keys. A rotating Pairing PSK
    // would invalidate any pairing token the operator has already been shown.
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider);
        EXPECT_EQ(store.record_mode_psk_id(), initial_mode_psk_id);
        ASSERT_TRUE(store.pairing_psk().has_value());
        EXPECT_EQ(store.pairing_psk()->psk, initial_pairing_psk);
        EXPECT_EQ(store.pairing_psk()->psk_id, psk_id_for(initial_pairing_psk));
    }
}

// =============================================================================
// Unpaired-access first-boot seed
// =============================================================================

/// A persistence provider that hands back a canned pairing config. Lets a test present a
/// loaded config whose record_mode_psk_id is empty or dangling - states FilePersistenceProvider
/// collapses into "nothing stored", so they are unreachable through it.
class CannedConfigProvider : public SendspinPersistenceProvider {
public:
    explicit CannedConfigProvider(SendspinPairingConfig config) : config_(std::move(config)) {}

    std::optional<SendspinPairingConfig> load_pairing_config() override {
        return this->config_;
    }

    bool save_pairing_config(const SendspinPairingConfig& config) override {
        this->config_ = config;
        return true;
    }

private:
    SendspinPairingConfig config_;
};

TEST(RecordStore, UnpairedAccessDefaultsOffWithoutSeed) {
    RecordStore store(nullptr);
    EXPECT_FALSE(store.unpaired_access_enabled());
}

TEST(RecordStore, UnpairedAccessSeedAppliesWithoutProvider) {
    // No provider means no stored config to load, so the seed applies on every start.
    RecordStore store(nullptr, /*initial_unpaired_access_enabled=*/true);
    EXPECT_TRUE(store.unpaired_access_enabled());
}

TEST(RecordStore, UnpairedAccessSeedYieldsToConfigWithDanglingRecordModeId) {
    // The constructor re-provisions a shared fallback record when record_mode_psk_id names no
    // stored record, but that repair must not be mistaken for a first boot: the config was
    // loaded, so its unpaired-access decision stands.
    SendspinPairingConfig stored;
    stored.unpaired_access_enabled = false;
    stored.record_mode_psk_id = "no-such-record";
    CannedConfigProvider provider(stored);

    RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true);

    EXPECT_FALSE(store.unpaired_access_enabled())
        << "a loaded config outranks the seed even when its fallback record is missing";
    EXPECT_NE(store.record_mode_psk_id(), "no-such-record")
        << "the dangling fallback reference should have been re-provisioned";
}

TEST(RecordStore, UnpairedAccessSeedYieldsToConfigWithEmptyRecordModeId) {
    SendspinPairingConfig stored;
    stored.unpaired_access_enabled = false;
    stored.record_mode_psk_id = "";
    CannedConfigProvider provider(stored);

    RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true);

    EXPECT_FALSE(store.unpaired_access_enabled())
        << "an empty record_mode_psk_id still means a config was loaded";
}

/// A provider whose records survive but whose pairing config does not come back - the shape of
/// a config blob lost or corrupted independently of the records (separate NVS keys, a torn
/// write, or any provider whose parse failure collapses into "nothing stored", which is exactly
/// what the bundled FilePersistenceProvider does).
class RecordsWithoutConfigProvider : public SendspinPersistenceProvider {
public:
    explicit RecordsWithoutConfigProvider(std::vector<SendspinPairingRecord> records)
        : records_(std::move(records)) {}

    std::vector<SendspinPairingRecord> load_pairing_records() override {
        return this->records_;
    }

    std::optional<SendspinPairingConfig> load_pairing_config() override {
        return std::nullopt;
    }

    bool save_pairing_record(const SendspinPairingRecord& record) override {
        this->records_.push_back(record);
        return true;
    }

private:
    std::vector<SendspinPairingRecord> records_;
};

TEST(RecordStore, UnpairedAccessSeedDoesNotApplyWhenOnlyTheConfigIsLost) {
    // load_pairing_config() returning nullopt is not proof of a first boot: the interface cannot
    // distinguish "never stored" from "could not be read back". Surviving records prove the
    // device was provisioned before, so re-seeding unpaired access ON here would silently
    // reopen unauthenticated access on a paired device whose operator had turned it off.
    RecordsWithoutConfigProvider provider({make_client_record("server-1")});

    RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true);

    EXPECT_FALSE(store.unpaired_access_enabled())
        << "a damaged config on a provisioned device must fail closed, not re-seed";
}

TEST(RecordStore, UnpairedAccessSeedStillAppliesWhenNothingSurvived) {
    // A store that lost everything is indistinguishable from a factory-fresh device, so the
    // seed does apply - same as the no-provider case.
    RecordsWithoutConfigProvider provider({});

    RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true);

    EXPECT_TRUE(store.unpaired_access_enabled());
}

TEST(RecordStoreWithFile, UnpairedAccessSeedPersistsOnFirstBoot) {
    TempFile tmp;

    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true);
        EXPECT_TRUE(store.unpaired_access_enabled());
    }

    // The seeded value must have been written through, so a later boot that passes no seed
    // still comes up with unpaired access enabled.
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider);
        EXPECT_TRUE(store.unpaired_access_enabled());
    }
}

TEST(RecordStoreWithFile, UnpairedAccessSeedDoesNotOverrideStoredConfig) {
    TempFile tmp;

    // First boot with the seed on, then the server turns unpaired access off.
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true);
        store.set_unpaired_access_enabled(false);
    }

    // Reboot with the same seed still configured: the stored decision wins.
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true);
        EXPECT_FALSE(store.unpaired_access_enabled())
            << "a persisted config must outrank the first-boot seed";
    }
}

// =============================================================================
// resolve_pairing_outcome: normal and storage-exhausted paths (declared in Phase 2 for
// completeness; exercised for real once pairing lands in a later phase)
// =============================================================================

// Normal case: storage is available -> returns {psk, record=set}.
// The record must be bound to the given server_id and have a valid psk_id.
TEST(RecordStore, ResolvePairingOutcomeNormal) {
    RecordStore store(nullptr);

    const std::string server_id = "server-pair-test";
    auto outcome = store.resolve_pairing_outcome(server_id);

    ASSERT_TRUE(outcome.has_value()) << "resolve_pairing_outcome must succeed when storage available";
    // PSK must be non-zero (randomly generated).
    bool all_zero = true;
    for (auto b : outcome->psk) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "generated PSK should not be all-zero";

    // A record must have been generated (storage not exhausted).
    ASSERT_TRUE(outcome->record.has_value())
        << "storage available: record must be present in outcome";

    // The record's server_id must match what was passed in.
    ASSERT_TRUE(outcome->record->server_id.has_value());
    EXPECT_EQ(outcome->record->server_id.value(), server_id);

    // psk_id must be set and match the PSK.
    EXPECT_FALSE(outcome->record->psk_id.empty());
    // The PSK in the record must match the outcome PSK.
    EXPECT_EQ(outcome->record->psk, outcome->psk);
}

// Storage-exhausted case: ExhaustedRecordStore returns {psk, record=nullopt}.
TEST(RecordStore, ResolvePairingOutcomeExhausted) {
    ExhaustedRecordStore store(nullptr);

    const std::string server_id = "server-exhausted";
    auto outcome = store.resolve_pairing_outcome(server_id);

    ASSERT_TRUE(outcome.has_value())
        << "exhausted store must still succeed (uses shared fallback PSK)";

    // The outer outcome must be present, but the inner record must be nullopt.
    EXPECT_FALSE(outcome->record.has_value())
        << "storage exhausted: record must be nullopt (use shared PSK, store nothing)";

    // PSK must be non-zero (the shared fallback PSK).
    bool all_zero = true;
    for (auto b : outcome->psk) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "shared fallback PSK should not be all-zero";
}

// store_record after resolve_pairing_outcome (simulates the server/pair-finalize ack path).
// After storing, the record must be resolvable by psk_id and bound to the server.
TEST(RecordStore, ResolvePairingOutcomeThenStore) {
    RecordStore store(nullptr);

    const std::string server_id = "server-store-after";
    auto outcome = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(outcome.has_value());
    ASSERT_TRUE(outcome->record.has_value());

    // Simulate the ack path: store the pending record.
    store.store_record(outcome->record.value());

    // The record must now be findable by server_id.
    const auto* stored = store.record_by_server_id(server_id);
    ASSERT_NE(stored, nullptr) << "record must be retrievable by server_id after store";
    EXPECT_EQ(stored->psk_id, outcome->record->psk_id);
    EXPECT_EQ(stored->psk, outcome->psk);

    // And resolvable by psk_id with LONG_TERM category.
    auto resolved = store.resolve_by_psk_id(stored->psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
}

// records_snapshot() returns a thread-safe copy of every long-term record, including the
// auto-provisioned shared fallback and any records added afterward.
TEST(RecordStore, RecordsSnapshotReturnsAllRecords) {
    RecordStore store(nullptr);
    // Auto-provisioned shared fallback is already present (1 record).
    ASSERT_EQ(store.records_snapshot().size(), 1u);

    SendspinPairingRecord a = make_client_record("server-A");
    SendspinPairingRecord b = make_client_record("server-B");
    store.store_record(a);
    store.store_record(b);

    auto snap = store.records_snapshot();
    EXPECT_EQ(snap.size(), 3u);

    // The snapshot must contain both added records.
    bool found_a = false;
    bool found_b = false;
    for (const auto& r : snap) {
        if (r.psk_id == a.psk_id) found_a = true;
        if (r.psk_id == b.psk_id) found_b = true;
    }
    EXPECT_TRUE(found_a);
    EXPECT_TRUE(found_b);
}

TEST(RecordStore, RecordByPskIdCopyReturnsValueForPresent) {
    RecordStore store(nullptr);
    SendspinPairingRecord rec = make_client_record("server-copy-test");
    store.store_record(rec);

    auto copy = store.record_by_psk_id_copy(rec.psk_id);
    ASSERT_TRUE(copy.has_value());
    EXPECT_EQ(copy->psk_id, rec.psk_id);
    ASSERT_TRUE(copy->server_id.has_value());
    EXPECT_EQ(copy->server_id.value(), "server-copy-test");
    EXPECT_EQ(copy->psk, rec.psk);
}

TEST(RecordStore, RecordByPskIdCopyReturnsNulloptForAbsent) {
    RecordStore store(nullptr);
    auto copy = store.record_by_psk_id_copy("nonexistent-psk-id");
    EXPECT_FALSE(copy.has_value());
}

// Exhausted case: resolve_pairing_outcome with nullopt inner record -> store nothing.
// After the "pairing", the server_id must not appear as a long-term record.
TEST(RecordStore, ResolvePairingOutcomeExhaustedNoStore) {
    ExhaustedRecordStore store(nullptr);

    const std::string server_id = "server-no-store";
    auto outcome = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(outcome.has_value());
    ASSERT_FALSE(outcome->record.has_value());

    // No record was stored (nullopt record -> store nothing).
    const auto* stored = store.record_by_server_id(server_id);
    EXPECT_EQ(stored, nullptr) << "no record should exist for the server after exhausted outcome";
}
