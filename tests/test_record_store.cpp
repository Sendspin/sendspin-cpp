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
// the full SendspinClient::start() -> client_id() path.
//
// The persistence provider is a blob store (SendspinPersistenceProvider::load_blob /
// save_blob / erase_blob); RecordStore and FilePersistenceProvider are pure byte stores for the
// "records" / "pairing_psk" / "pair_config" keys, so tests that need to inspect or shape what is
// actually stored go through the codec in sendspin/persistence_codec.h, exactly like production
// code does. Most fakes here share tests/fake_persistence.h's InMemoryPersistenceProvider;
// a handful of tests need bespoke behavior (observing removals specifically, serving
// mismatched/canned codec content) and keep a local fake for that.

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "fake_persistence.h"
#include "file_persistence_provider.h"
#include "platform/crypto.h"
#include "platform/logging.h"
#include "protocol_messages.h"
#include "record_store.h"
#include "record_test_helpers.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/persistence_codec.h"
#include "sendspin/player_role.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

// =============================================================================
// Test helpers
// =============================================================================

/// Build an accepted Pairing PSK.
static SendspinPairingPsk make_pairing_psk(const std::optional<std::string>& label = {}) {
    auto psk = make_random_psk();
    SendspinPairingPsk p;
    p.psk_id = psk_id_for(psk);
    p.psk = psk;
    p.label = label;
    return p;
}

/// Wraps a std::string's bytes as a blob for seed_blob()/save_blob() calls.
static std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

/// Decodes a raw blob as a pairing-records array; ASSERT-fails the calling test on decode
/// failure (helper, not itself a TEST).
static std::optional<std::vector<SendspinPairingRecord>> decode_records_blob(
    const std::optional<std::vector<uint8_t>>& blob) {
    if (!blob.has_value()) {
        return std::nullopt;
    }
    std::string_view text(reinterpret_cast<const char*>(blob->data()), blob->size());
    return decode_pairing_records(text);
}

/// A persistence provider whose "records" blob writes can be made to fail (e.g. full or faulty
/// flash). Pairing PSK / pair config writes always succeed; they are not under test here.
class RejectingPersistenceProvider : public SendspinPersistenceProvider {
public:
    bool save_blob(const std::string& key, const uint8_t* /*data*/, size_t /*len*/) override {
        if (key != persistence_keys::RECORDS) {
            return true;
        }
        save_attempts++;
        return !reject;
    }

    bool reject{true};
    int save_attempts{0};
};

// =============================================================================
// Basic construction / first-boot provisioning
// =============================================================================

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

}

/// A persistence provider whose writes always fail (e.g. full or read-only NVS), used to verify
/// first-boot provisioning surfaces a rejected write instead of silently discarding it.
class AlwaysRejectingProvider : public SendspinPersistenceProvider {
public:
    bool save_blob(const std::string& key, const uint8_t* /*data*/, size_t /*len*/) override {
        if (key == persistence_keys::RECORDS) {
            record_save_attempts++;
        } else if (key == persistence_keys::PAIRING_PSK) {
            psk_save_attempts++;
        } else if (key == persistence_keys::PAIR_CONFIG) {
            config_save_attempts++;
        }
        return false;
    }

    int record_save_attempts{0};
    int psk_save_attempts{0};
    int config_save_attempts{0};
};

// A provider that rejects every write during first-boot provisioning must not be silently
// ignored. The device must still be fully usable for the current boot (RAM-only state), and
// the provider must actually have been asked to persist each piece of material.
TEST(RecordStore, FirstBootProvisioningSurvivesPersistenceFailureForThisBoot) {
    AlwaysRejectingProvider provider;
    RecordStore store(&provider);

    EXPECT_EQ(provider.record_save_attempts, 0) << "a first boot has no record to persist";
    EXPECT_GE(provider.config_save_attempts, 1) << "the pairing config write must be attempted";
    EXPECT_GE(provider.psk_save_attempts, 1) << "the Pairing PSK write must have been attempted";

    // Despite every write being rejected, the device remains usable for this boot: the Pairing
    // PSK is present and resolvable in memory.
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
// Booting from a blob store seeded purely via the public codec
// =============================================================================

// A provider seeded entirely through sendspin/persistence_codec.h (no RecordStore involved)
// must be read back as-is, with no first-boot re-provisioning: the seeded material is complete
// and valid, so RecordStore has nothing to fill in.
TEST(RecordStore, BootsFromBlobStoreSeededViaCodec) {
    InMemoryPersistenceProvider provider;

    SendspinPairingRecord paired = make_client_record("server-seeded", "Seeded Label");
    std::string records_blob = encode_pairing_records({paired});
    provider.seed_blob(persistence_keys::RECORDS, to_bytes(records_blob));

    SendspinPairingPsk psk = make_pairing_psk("Seeded PSK");
    std::string psk_blob = encode_pairing_psk(psk);
    provider.seed_blob(persistence_keys::PAIRING_PSK, to_bytes(psk_blob));

    SendspinPairingConfig cfg;
    cfg.unpaired_access_enabled = true;
    std::string cfg_blob = encode_pairing_config(cfg);
    provider.seed_blob(persistence_keys::PAIR_CONFIG, to_bytes(cfg_blob));

    RecordStore store(&provider);

    EXPECT_TRUE(store.unpaired_access_enabled());
    EXPECT_EQ(provider.save_attempts(persistence_keys::RECORDS), 0)
        << "a fully-seeded store must not trigger first-boot re-provisioning";

    auto resolved_paired = store.resolve_by_psk_id(paired.psk_id);
    ASSERT_TRUE(resolved_paired.has_value());
    EXPECT_EQ(resolved_paired->category, PskCategory::LONG_TERM);
    EXPECT_EQ(resolved_paired->counterparty_id, paired.server_id);

    ASSERT_TRUE(store.pairing_psk().has_value());
    EXPECT_EQ(store.pairing_psk()->psk_id, psk.psk_id);
    EXPECT_EQ(store.pairing_psk()->psk, psk.psk);
}

// A "records" blob that fails to decode at all (corrupt bytes, not valid JSON) must not crash or
// refuse to start: the store falls back to empty and re-provisions from there.
TEST(RecordStore, CorruptRecordsBlobFallsBackToEmptyStore) {
    InMemoryPersistenceProvider provider;
    provider.seed_blob(persistence_keys::RECORDS, to_bytes("not valid json at all {{{"));

    RecordStore store(&provider);

    // First-boot provisioning must have run as if nothing were stored.
    EXPECT_TRUE(store.records_snapshot().empty());
    EXPECT_TRUE(store.pairing_psk().has_value());
}

// =============================================================================
// Records: reject wrong PSK size
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
// store_record_superseding: at most one record per server_id
// =============================================================================

// Re-pairing the same server_id twice (e.g. after the server was factory-reset and re-paired)
// must revoke the prior per-server PSK rather than leaving it valid forever alongside the new
// one. Mirrors the server/pair-finalize ack commit path: resolve_pairing_outcome() mints a
// fresh record, then store_record_superseding() commits it.
TEST(RecordStore, StoreRecordSupersedesPriorRecordForSameServerId) {
    RecordStore store(nullptr);
    const std::string server_id = "server-repair";

    auto outcome1 = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(outcome1.has_value());
    ASSERT_TRUE(store.store_record_superseding(outcome1->record));
    const std::string first_psk_id = outcome1->record.psk_id;

    auto outcome2 = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(outcome2.has_value());
    ASSERT_TRUE(store.store_record_superseding(outcome2->record));
    const std::string second_psk_id = outcome2->record.psk_id;

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
        if (r.server_id == server_id) {
            count++;
        }
    }
    EXPECT_EQ(count, 1);
}

// The supersede itself never calls the provider: in production it runs on the NETWORK thread
// (the server/pair-finalize ack handler), where the provider contract forbids calls, so the
// durable write is deferred to persist_records() on the main loop. The RAM mutation commits
// immediately either way; a provider that then rejects the flush leaves the replacement
// authoritative for this boot while the provider keeps its last accepted blob, so the ORIGINAL
// record comes back at the next boot.
TEST(RecordStore, StoreRecordSupersedingIsRamOnlyUntilPersistRecords) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X", "original");
    ASSERT_TRUE(store.store_record_superseding(original));
    ASSERT_TRUE(store.persist_records());

    provider.reject_save_keys.insert(persistence_keys::RECORDS);
    const int attempts_before = provider.save_attempts(persistence_keys::RECORDS);

    SendspinPairingRecord replacement = make_client_record("server-X", "replacement");
    EXPECT_TRUE(store.store_record_superseding(replacement))
        << "the RAM-only supersede must not fail on a provider that would reject the write";
    EXPECT_EQ(provider.save_attempts(persistence_keys::RECORDS), attempts_before)
        << "store_record_superseding must not call the provider";

    // RAM state is authoritative for this boot: the replacement resolves, the original is gone.
    auto resolved = store.resolve_by_psk_id(replacement.psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
    EXPECT_EQ(store.record_by_psk_id(original.psk_id), nullptr);
    const auto* found = store.record_by_server_id("server-X");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, replacement.psk_id);

    // The deferred flush is where the rejection surfaces.
    EXPECT_FALSE(store.persist_records());
    EXPECT_GT(provider.save_attempts(persistence_keys::RECORDS), attempts_before)
        << "the rejected flush must have been attempted";

    // "Reboot": the provider still holds the last accepted blob, so the original record
    // resurfaces and the replacement is lost.
    RecordStore rebooted(&provider);
    EXPECT_TRUE(rebooted.resolve_by_psk_id(original.psk_id).has_value());
    EXPECT_FALSE(rebooted.resolve_by_psk_id(replacement.psk_id).has_value());
}

// =============================================================================
// Capacity enforcement (max_records_)
// =============================================================================

// Pairing DEFAULT_MAX_RECORDS distinct servers must succeed; the next net-new pairing must be
// refused before a record is minted, and must not change what is stored.
TEST(RecordStore, CapacityRejectsInsertPastDefaultCap) {
    RecordStore store(nullptr);
    for (size_t i = 0; i < RecordStore::DEFAULT_MAX_RECORDS; ++i) {
        auto outcome = store.resolve_pairing_outcome("server-" + std::to_string(i));
        ASSERT_TRUE(outcome.has_value()) << "pairing " << i << " should still fit";
        ASSERT_TRUE(store.store_record_superseding(outcome->record));
    }
    ASSERT_EQ(store.records_snapshot().size(), RecordStore::DEFAULT_MAX_RECORDS);

    EXPECT_FALSE(store.resolve_pairing_outcome("server-overflow").has_value())
        << "a net-new pairing must be refused once the store is at capacity";
    EXPECT_EQ(store.record_by_server_id("server-overflow"), nullptr);
    EXPECT_EQ(store.records_snapshot().size(), RecordStore::DEFAULT_MAX_RECORDS)
        << "a refused pairing must not change the record count";
}

// A supersede that replaces the record already held for a given server_id does not grow the
// store, so it must succeed even when the store is otherwise completely full.
TEST(RecordStore, CapacitySupersedeAtCapacityStillSucceeds) {
    RecordStore store(nullptr);
    const std::string existing_server = "server-existing";

    auto outcome0 = store.resolve_pairing_outcome(existing_server);
    ASSERT_TRUE(outcome0.has_value());
    ASSERT_TRUE(store.store_record_superseding(outcome0->record));
    const std::string first_psk_id = outcome0->record.psk_id;

    // Fill every remaining slot with other servers' records.
    for (size_t i = 1; i < RecordStore::DEFAULT_MAX_RECORDS; ++i) {
        auto outcome = store.resolve_pairing_outcome("server-" + std::to_string(i));
        ASSERT_TRUE(outcome.has_value());
        ASSERT_TRUE(store.store_record_superseding(outcome->record));
    }
    ASSERT_EQ(store.records_snapshot().size(), RecordStore::DEFAULT_MAX_RECORDS);

    // Re-pairing the already-known server must still mint and store a fresh record: it
    // supersedes its own prior record rather than growing the store past capacity.
    auto outcome1 = store.resolve_pairing_outcome(existing_server);
    ASSERT_TRUE(outcome1.has_value())
        << "resolve_pairing_outcome must mint a fresh record for a re-pair even at capacity";
    EXPECT_TRUE(store.store_record_superseding(outcome1->record))
        << "a supersede must not be blocked by the capacity cap";

    EXPECT_EQ(store.records_snapshot().size(), RecordStore::DEFAULT_MAX_RECORDS)
        << "a supersede must not grow the store";
    EXPECT_EQ(store.record_by_psk_id(first_psk_id), nullptr) << "the old record must be retired";
    const auto* found = store.record_by_server_id(existing_server);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, outcome1->record.psk_id);
}

// A caller-supplied cap (the max_records constructor parameter, wired from
// SendspinClientConfig::max_pairing_records) must be respected in place of the default.
TEST(RecordStore, CapacityCustomCapIsRespected) {
    RecordStore store(nullptr, /*initial_unpaired_access_enabled=*/false, /*max_records=*/2);

    for (const std::string& server_id : {std::string("server-A"), std::string("server-B")}) {
        auto outcome = store.resolve_pairing_outcome(server_id);
        ASSERT_TRUE(outcome.has_value());
        ASSERT_TRUE(store.store_record_superseding(outcome->record));
    }

    EXPECT_FALSE(store.resolve_pairing_outcome("server-C").has_value());
    EXPECT_EQ(store.records_snapshot().size(), 2u);
}

// =============================================================================
// resolve_by_psk_id: long-term first, then Pairing PSK, then Sentinel
// =============================================================================

TEST(RecordStore, ResolveByPskIdLongTermFirst) {
    RecordStore store(nullptr);

    SendspinPairingRecord rec = make_client_record("server-X");
    store.store_record_superseding(rec);

    auto resolved = store.resolve_by_psk_id(rec.psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
    EXPECT_EQ(resolved->psk_id, rec.psk_id);
    EXPECT_EQ(resolved->psk, rec.psk);
    EXPECT_EQ(resolved->counterparty_id, rec.server_id);
}

TEST(RecordStore, ResolveByPskIdPairingPskSecond) {
    InMemoryPersistenceProvider provider;
    SendspinPairingPsk p = make_pairing_psk();
    provider.seed_blob(persistence_keys::PAIRING_PSK, to_bytes(encode_pairing_psk(p)));
    RecordStore store(&provider);

    auto resolved = store.resolve_by_psk_id(p.psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::PAIRING);
    EXPECT_FALSE(resolved->counterparty_id.has_value());
}

TEST(RecordStore, LongTermRecordWinsOverPairingPskWithSamePskId) {
    InMemoryPersistenceProvider provider;

    // Build a record and a pairing PSK that share the same psk_id (and PSK bytes).
    SendspinPairingRecord rec = make_client_record("server-X");
    SendspinPairingPsk p;
    p.psk_id = rec.psk_id;
    p.psk = rec.psk;
    p.label = "dup";
    provider.seed_blob(persistence_keys::PAIRING_PSK, to_bytes(encode_pairing_psk(p)));

    RecordStore store(&provider);
    store.store_record_superseding(rec);

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
    store.store_record_superseding(rec);

    const auto* found = store.record_by_server_id("server-X");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, rec.psk_id);
    EXPECT_EQ(found->server_id, rec.server_id);

    // Unknown server returns null.
    EXPECT_EQ(store.record_by_server_id("server-Y"), nullptr);
}

// =============================================================================
// mark_record_used
// =============================================================================

TEST(RecordStore, MarkRecordUsed) {
    RecordStore store(nullptr);

    SendspinPairingRecord rec = make_client_record("server-X");
    EXPECT_FALSE(rec.used);
    store.store_record_superseding(rec);

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
    store.store_record_superseding(a);
    store.store_record_superseding(b);

    // Both records are now findable.
    EXPECT_NE(store.record_by_psk_id(a.psk_id), nullptr);
    EXPECT_NE(store.record_by_psk_id(b.psk_id), nullptr);

    store.remove_record(a.psk_id);
    EXPECT_EQ(store.record_by_psk_id(a.psk_id), nullptr);
    EXPECT_NE(store.record_by_psk_id(b.psk_id), nullptr);

    // Removing an absent record is a no-op.
    store.remove_record("absent-psk-id");
}

/// A persistence provider that accepts every "records" blob save EXCEPT one that drops a
/// psk_id which was present in the previously-accepted blob (i.e. a removal), standing in for a
/// store whose delete path fails on its own (full or read-only NVS, a torn write) while saves
/// that only add/replace still work. Distinguishes an add from a removal by diffing the
/// newly-offered array against the last array it accepted. The store is a pure byte store in
/// production, but a test fake is free to peek at its own content to model this.
class RejectingDeleteProvider : public SendspinPersistenceProvider {
public:
    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key != persistence_keys::RECORDS) {
            return std::nullopt;
        }
        std::string encoded = encode_pairing_records(this->saved_);
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (key != persistence_keys::RECORDS) {
            return true;  // Pairing PSK / pair config writes are not under test here.
        }
        std::string_view text(reinterpret_cast<const char*>(data), len);
        auto decoded = decode_pairing_records(text).value_or(std::vector<SendspinPairingRecord>{});

        for (const auto& old_rec : this->saved_) {
            bool still_present = std::any_of(
                decoded.begin(), decoded.end(),
                [&](const SendspinPairingRecord& r) { return r.psk_id == old_rec.psk_id; });
            if (!still_present) {
                this->remove_attempts.push_back(old_rec.psk_id);
                if (this->refuse_delete) {
                    return false;  // Reject the whole write; saved_ stays as it was.
                }
            }
        }
        this->saved_ = std::move(decoded);
        return true;
    }

    bool refuse_delete{true};
    std::vector<std::string> remove_attempts{};

private:
    std::vector<SendspinPairingRecord> saved_{};
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
    ASSERT_TRUE(store.store_record_superseding(a));
    ASSERT_TRUE(store.persist_records());
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
    ASSERT_TRUE(store.store_record_superseding(a));
    ASSERT_TRUE(store.persist_records());

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

// Same contract on the pairing/supersede path, which persists through the deferred
// persist_records() flush rather than inside the supersede itself: the prior record leaves RAM
// immediately (revoked for this boot no matter what the provider later says), and a flush the
// provider refuses is reported at flush time.
TEST(RecordStore, SupersedeErasesFromMemoryAndFlushWarnsWhenTheProviderRefusesTheDelete) {
    RejectingDeleteProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X", "original");
    ASSERT_TRUE(store.store_record_superseding(original));
    ASSERT_TRUE(store.persist_records());

    SendspinPairingRecord replacement = make_client_record("server-X", "replacement");
    ASSERT_TRUE(store.store_record_superseding(replacement));

    // The RAM effect precedes any provider traffic: the supersede itself asked for nothing.
    EXPECT_EQ(store.record_by_psk_id(original.psk_id), nullptr);
    EXPECT_FALSE(store.resolve_by_psk_id(original.psk_id).has_value());
    EXPECT_NE(store.record_by_psk_id(replacement.psk_id), nullptr);
    EXPECT_TRUE(provider.remove_attempts.empty())
        << "store_record_superseding must not call the provider";

    std::string logs;
    {
        StderrCapture capture;
        EXPECT_FALSE(store.persist_records());
        logs = capture.release();
    }
    ASSERT_EQ(provider.remove_attempts.size(), 1u);
    EXPECT_EQ(provider.remove_attempts[0], original.psk_id);
    EXPECT_NE(logs.find(REBOOT_WARNING), std::string::npos)
        << "a refused supersede flush must be reported; got: " << logs;
}

// A supersede whose flush the store accepted is durable: no warning, and the prior record is
// really gone from the provider (so it does not come back on the next start).
TEST(RecordStore, SupersedeIsSilentWhenTheProviderAcceptsTheFlush) {
    RejectingDeleteProvider provider;
    provider.refuse_delete = false;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X", "original");
    ASSERT_TRUE(store.store_record_superseding(original));
    ASSERT_TRUE(store.persist_records());

    SendspinPairingRecord replacement = make_client_record("server-X", "replacement");
    std::string logs;
    {
        StderrCapture capture;
        ASSERT_TRUE(store.store_record_superseding(replacement));
        ASSERT_TRUE(store.persist_records());
        logs = capture.release();
    }

    EXPECT_EQ(logs.find(REBOOT_WARNING), std::string::npos)
        << "an accepted supersede flush must not warn; got: " << logs;

    RecordStore rebooted(&provider);
    EXPECT_FALSE(rebooted.resolve_by_psk_id(original.psk_id).has_value());
    EXPECT_TRUE(rebooted.resolve_by_psk_id(replacement.psk_id).has_value());
}

// The refused delete is exactly the durability hole the bool return exists to surface: the
// record the store kept comes back on the next start, and resolves as LONG_TERM trust again.
TEST(RecordStore, RefusedDeleteLetsTheRevokedRecordReturnAfterAReboot) {
    RejectingDeleteProvider provider;

    SendspinPairingRecord a = make_client_record("server-A");
    {
        RecordStore store(&provider);
        ASSERT_TRUE(store.store_record_superseding(a));
        ASSERT_TRUE(store.persist_records());
        store.remove_record(a.psk_id);
        ASSERT_EQ(store.record_by_psk_id(a.psk_id), nullptr);
    }

    // Reboot: a new store over the same provider reloads what the provider still holds.
    RecordStore rebooted(&provider);
    auto resolved = rebooted.resolve_by_psk_id(a.psk_id);
    ASSERT_TRUE(resolved.has_value())
        << "the provider kept the record, so it must come back: this is what the false return "
           "from a rejected \"records\" save warns about";
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
}

// =============================================================================
// Pairing PSK lifecycle
// =============================================================================

/// A persistence provider that hands back a Pairing PSK whose psk_id does not match its secret.
class MismatchedPairingPskProvider : public SendspinPersistenceProvider {
public:
    explicit MismatchedPairingPskProvider(SendspinPairingPsk psk) : psk_(std::move(psk)) {}

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key != persistence_keys::PAIRING_PSK) {
            return std::nullopt;
        }
        std::string encoded = encode_pairing_psk(this->psk_);
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (key != persistence_keys::PAIRING_PSK) {
            return false;
        }
        std::string_view text(reinterpret_cast<const char*>(data), len);
        this->saved = decode_pairing_psk(text);
        return this->saved.has_value();
    }

    std::optional<SendspinPairingPsk> saved;

private:
    SendspinPairingPsk psk_;
};

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
        auto loaded = provider.load_blob(persistence_keys::KEYPAIR);
        EXPECT_FALSE(loaded.has_value()) << "No key yet on first boot";

        Identity id = Identity::generate().value();
        EXPECT_TRUE(provider.save_blob(persistence_keys::KEYPAIR, id.private_bytes.data(),
                                       id.private_bytes.size()));
        client_id_first = id.peer_id();
        pub_first = id.public_bytes;
    }

    // "Reboot": reload and verify same keypair.
    {
        FilePersistenceProvider provider(tmp.path());
        auto loaded = provider.load_blob(persistence_keys::KEYPAIR);
        ASSERT_TRUE(loaded.has_value()) << "Key should be present after first boot";
        ASSERT_EQ(loaded->size(), 32u);

        std::array<uint8_t, 32> priv_bytes{};
        std::copy(loaded->begin(), loaded->end(), priv_bytes.begin());
        Identity rehydrated = Identity::from_private_bytes(priv_bytes).value();
        EXPECT_EQ(rehydrated.public_bytes, pub_first);
        EXPECT_EQ(rehydrated.peer_id(), client_id_first);
    }
}

// Exercises the full public path: SendspinClient::start() loads or generates the
// identity via load_or_generate_identity() and exposes it through client_id(). Two separate
// SendspinClient instances sharing the same FilePersistenceProvider file must derive the same
// client_id: the second instance is the "reboot" case.
TEST(FilePersistenceProvider, KeypairPersistsViaClientStartServer) {
    TempFile tmp;

    std::string client_id_first;
    {
        FilePersistenceProvider provider(tmp.path());
        SendspinClientConfig config;
        config.name = "test-client";
        SendspinClient client(std::move(config));
        client.set_persistence_provider(&provider);
        ASSERT_TRUE(client.start());
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
        ASSERT_TRUE(client.start());
        EXPECT_EQ(client.client_id(), client_id_first);
    }
}

// load_or_generate_identity() must never leave client_id_ as the peer_id of an all-zero
// Identity (a silent-failure value). This cannot force the underlying noise-c DH-state
// generation to actually fail (no test hook for that), so instead it pins the invariant:
// a real client_id must differ from what an all-zero keypair would produce.
TEST(FilePersistenceProvider, StartServerNeverProducesAllZeroClientId) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());
    SendspinClientConfig config;
    config.name = "test-client";
    SendspinClient client(std::move(config));
    client.set_persistence_provider(&provider);
    ASSERT_TRUE(client.start());

    Identity zero_identity{};  // default-constructed = all-zero private/public bytes
    EXPECT_NE(client.client_id(), zero_identity.peer_id());
}

// A persisted "keypair" blob of the wrong length must be rejected outright (not
// truncated/reinterpreted) and a fresh keypair generated and persisted in its place.
TEST(SendspinClientIdentity, WrongSizeKeypairBlobIsRejectedAndRegenerated) {
    InMemoryPersistenceProvider provider;
    std::vector<uint8_t> wrong_size(16, 0x42);  // valid X25519 private keys are exactly 32 bytes
    provider.seed_blob(persistence_keys::KEYPAIR, wrong_size);

    SendspinClientConfig config;
    config.name = "wrong-size-keypair-test";
    SendspinClient client(std::move(config));
    client.set_persistence_provider(&provider);
    ASSERT_TRUE(client.start());

    EXPECT_FALSE(client.client_id().empty());

    auto persisted = provider.blob(persistence_keys::KEYPAIR);
    ASSERT_TRUE(persisted.has_value())
        << "a freshly generated keypair must have been persisted over the bad blob";
    EXPECT_EQ(persisted->size(), 32u);
    EXPECT_NE(*persisted, wrong_size);
}

TEST(FilePersistenceProvider, PairingRecordRoundTrip) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingRecord rec = make_client_record("server-X", "My Label");
    std::string encoded = encode_pairing_records({rec});
    EXPECT_TRUE(provider.save_blob(persistence_keys::RECORDS,
                                   reinterpret_cast<const uint8_t*>(encoded.data()),
                                   encoded.size()));

    auto decoded = decode_records_blob(provider.load_blob(persistence_keys::RECORDS));
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 1u);
    EXPECT_EQ((*decoded)[0].psk_id, rec.psk_id);
    EXPECT_EQ((*decoded)[0].psk, rec.psk);
    EXPECT_EQ((*decoded)[0].server_id, rec.server_id);
    EXPECT_EQ((*decoded)[0].label, rec.label);
    EXPECT_EQ((*decoded)[0].used, rec.used);
}

// A stored record with no server_id could never satisfy the post-match server check, so the
// decoder skips it and keeps the rest of the blob (spec "Pre-Shared Key").
TEST(FilePersistenceProvider, RecordWithoutServerIdIsSkipped) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingRecord bound = make_client_record("server-bound");
    std::string encoded = encode_pairing_records({bound});
    // Splice an unbound entry in beside it, the shape an older blob carries.
    const std::string unbound =
        R"({"psk_id":"unbound","psk":")" +
        base64url_encode(make_random_psk().data(), NOISE_PSK_SIZE) + R"(","used":false},)";
    const size_t insert_at = encoded.find("[") + 1;
    encoded.insert(insert_at, unbound);
    EXPECT_TRUE(provider.save_blob(persistence_keys::RECORDS,
                                   reinterpret_cast<const uint8_t*>(encoded.data()),
                                   encoded.size()));

    std::optional<std::vector<SendspinPairingRecord>> decoded;
    std::string logs;
    {
        StderrCapture capture;
        decoded = decode_records_blob(provider.load_blob(persistence_keys::RECORDS));
        logs = capture.release();
    }
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->size(), 1u) << "the unbound entry must be skipped, the bound one kept";
    EXPECT_EQ((*decoded)[0].psk_id, bound.psk_id);

    // A silently dropped pairing makes a server look forgotten for no stated reason, so the skip
    // names the record and why it went.
    EXPECT_NE(logs.find("unbound"), std::string::npos)
        << "the skip must name the record it dropped; got: " << logs;
    EXPECT_NE(logs.find("server_id"), std::string::npos)
        << "the skip must say why the record was dropped; got: " << logs;
    EXPECT_EQ(logs.find(bound.psk_id), std::string::npos)
        << "the accepted record must not be warned about; got: " << logs;
}

// The clear_* revocations (Pairing PSK / static PIN) carry the same contract via erase_blob():
// absent-or-erased both report success, so a fresh device never logs a spurious durability
// warning on first clear.
TEST(FilePersistenceProvider, ClearPairingPskAndStaticPinReportSuccess) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingPsk psk;
    psk.psk_id = "pairing-psk-id";
    psk.psk.fill(0x42);
    std::string psk_encoded = encode_pairing_psk(psk);
    ASSERT_TRUE(provider.save_blob(persistence_keys::PAIRING_PSK,
                                   reinterpret_cast<const uint8_t*>(psk_encoded.data()),
                                   psk_encoded.size()));
    ASSERT_TRUE(provider.load_blob(persistence_keys::PAIRING_PSK).has_value());
    EXPECT_TRUE(provider.erase_blob(persistence_keys::PAIRING_PSK));
    EXPECT_FALSE(provider.load_blob(persistence_keys::PAIRING_PSK).has_value());

    std::string pin = "12345678";
    ASSERT_TRUE(provider.save_blob(persistence_keys::STATIC_PIN,
                                   reinterpret_cast<const uint8_t*>(pin.data()), pin.size()));
    ASSERT_TRUE(provider.load_blob(persistence_keys::STATIC_PIN).has_value());
    EXPECT_TRUE(provider.erase_blob(persistence_keys::STATIC_PIN));
    EXPECT_FALSE(provider.load_blob(persistence_keys::STATIC_PIN).has_value());

    // Clearing what is already absent is still success.
    EXPECT_TRUE(provider.erase_blob(persistence_keys::PAIRING_PSK));
    EXPECT_TRUE(provider.erase_blob(persistence_keys::STATIC_PIN));

    // And a key that was NEVER touched at all is likewise a no-op success.
    EXPECT_TRUE(provider.erase_blob("never-used-key"));
}

TEST(FilePersistenceProvider, LastPlayedServerIdRoundTrip) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    EXPECT_FALSE(provider.load_blob(persistence_keys::LAST_PLAYED).has_value());

    std::string server_id = "server-id-abc";
    EXPECT_TRUE(provider.save_blob(persistence_keys::LAST_PLAYED,
                                   reinterpret_cast<const uint8_t*>(server_id.data()),
                                   server_id.size()));
    auto loaded = provider.load_blob(persistence_keys::LAST_PLAYED);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(std::string(loaded->begin(), loaded->end()), server_id);
}

TEST(FilePersistenceProvider, PairingConfigRoundTrip) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingConfig cfg;
    cfg.pairing_psk_enabled = false;
    cfg.unpaired_access_enabled = true;
    cfg.dynamic_pin_min_length = 8;

    std::string encoded = encode_pairing_config(cfg);
    EXPECT_TRUE(provider.save_blob(persistence_keys::PAIR_CONFIG,
                                   reinterpret_cast<const uint8_t*>(encoded.data()),
                                   encoded.size()));

    auto blob = provider.load_blob(persistence_keys::PAIR_CONFIG);
    ASSERT_TRUE(blob.has_value());
    std::string_view text(reinterpret_cast<const char*>(blob->data()), blob->size());
    auto loaded = decode_pairing_config(text);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->pairing_psk_enabled, false);
    EXPECT_EQ(loaded->unpaired_access_enabled, true);
    EXPECT_EQ(loaded->dynamic_pin_min_length, 8);
}

// The persistence file holds plaintext secrets (static private key, long-term PSKs,
// Pairing PSK, static PIN), so it must never be group/world readable regardless of
// the process umask. This is host-only POSIX, matching how
// examples/common/file_persistence_provider.cpp itself creates the file.
TEST(FilePersistenceProvider, PersistedFileIsOwnerOnly) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    std::string pin = "1234";
    EXPECT_TRUE(provider.save_blob(persistence_keys::STATIC_PIN,
                                   reinterpret_cast<const uint8_t*>(pin.data()), pin.size()));

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

    std::array<uint8_t, NOISE_PSK_SIZE> initial_pairing_psk{};

    // First boot: should create and persist the Pairing PSK.
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider);
        ASSERT_TRUE(store.pairing_psk().has_value());
        initial_pairing_psk = store.pairing_psk()->psk;
    }

    // Second boot: should load the same material, not generate new keys. A rotating Pairing PSK
    // would invalidate any pairing token the operator has already been shown.
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider);
        ASSERT_TRUE(store.pairing_psk().has_value());
        EXPECT_EQ(store.pairing_psk()->psk, initial_pairing_psk);
        EXPECT_EQ(store.pairing_psk()->psk_id, psk_id_for(initial_pairing_psk));
    }
}

// A removed record must not merely vanish from RAM: the persisted "records" blob itself must
// shrink, so a reboot does not resurrect it. Exercised at the RecordStore level, where removal
// is actually implemented, rather than against the provider, which is a pure byte store.
TEST(RecordStoreWithFile, RemoveRecordShrinksThePersistedBlob) {
    TempFile tmp;
    std::string a_psk_id;
    std::string b_psk_id;
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider);
        SendspinPairingRecord a = make_client_record("server-A");
        SendspinPairingRecord b = make_client_record("server-B");
        ASSERT_TRUE(store.store_record_superseding(a));
        ASSERT_TRUE(store.store_record_superseding(b));
        ASSERT_TRUE(store.persist_records());
        a_psk_id = a.psk_id;
        b_psk_id = b.psk_id;
        store.remove_record(a_psk_id);
    }

    FilePersistenceProvider provider(tmp.path());
    auto decoded = decode_records_blob(provider.load_blob(persistence_keys::RECORDS));
    ASSERT_TRUE(decoded.has_value());
    bool found_a = false;
    bool found_b = false;
    for (const auto& r : decoded.value()) {
        if (r.psk_id == a_psk_id) {
            found_a = true;
        }
        if (r.psk_id == b_psk_id) {
            found_b = true;
        }
    }
    EXPECT_FALSE(found_a) << "a removed record must not survive in the persisted blob";
    EXPECT_TRUE(found_b);
}

// =============================================================================
// Unpaired-access first-boot seed
// =============================================================================

/// A persistence provider that hands back a canned pairing config, so a test can present a
/// stored config without a first boot ever having written one. FilePersistenceProvider cannot:
/// it collapses an absent file into "nothing stored", which is the first-boot case itself.
class CannedConfigProvider : public SendspinPersistenceProvider {
public:
    explicit CannedConfigProvider(SendspinPairingConfig config) : config_(std::move(config)) {}

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key != persistence_keys::PAIR_CONFIG) {
            return std::nullopt;
        }
        std::string encoded = encode_pairing_config(this->config_);
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (key != persistence_keys::PAIR_CONFIG) {
            return false;
        }
        std::string_view text(reinterpret_cast<const char*>(data), len);
        auto decoded = decode_pairing_config(text);
        if (decoded.has_value()) {
            this->config_ = decoded.value();
        }
        return decoded.has_value();
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

TEST(RecordStore, UnpairedAccessSeedYieldsToLoadedConfig) {
    SendspinPairingConfig stored;
    stored.unpaired_access_enabled = false;
    CannedConfigProvider provider(stored);

    RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true);

    EXPECT_FALSE(store.unpaired_access_enabled())
        << "a loaded config outranks the first-boot seed";
}

/// A provider whose records survive but whose pairing config does not come back: the shape of
/// a config blob lost or corrupted independently of the records (separate NVS keys, a torn
/// write, or any provider whose parse failure collapses into "nothing stored", which is exactly
/// what the bundled FilePersistenceProvider does).
class RecordsWithoutConfigProvider : public SendspinPersistenceProvider {
public:
    explicit RecordsWithoutConfigProvider(std::vector<SendspinPairingRecord> records)
        : records_(std::move(records)) {}

    std::optional<std::vector<uint8_t>> load_blob(const std::string& key) override {
        if (key != persistence_keys::RECORDS) {
            return std::nullopt;  // In particular, no PAIR_CONFIG: that is the point.
        }
        std::string encoded = encode_pairing_records(this->records_);
        return std::vector<uint8_t>(encoded.begin(), encoded.end());
    }

    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (key != persistence_keys::RECORDS) {
            return false;
        }
        std::string_view text(reinterpret_cast<const char*>(data), len);
        auto decoded = decode_pairing_records(text);
        if (!decoded.has_value()) {
            return false;
        }
        this->records_ = std::move(decoded.value());
        return true;
    }

private:
    std::vector<SendspinPairingRecord> records_;
};

TEST(RecordStore, UnpairedAccessSeedDoesNotApplyWhenOnlyTheConfigIsLost) {
    // A missing/undecodable pair_config blob is not proof of a first boot: the interface cannot
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
    // seed does apply, same as the no-provider case.
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

    // A device provisioned with unpaired access off already has a stored config saying so.
    {
        FilePersistenceProvider provider(tmp.path());
        SendspinPairingConfig stored;
        stored.unpaired_access_enabled = false;
        std::string blob = encode_pairing_config(stored);
        ASSERT_TRUE(provider.save_blob(persistence_keys::PAIR_CONFIG,
                                       reinterpret_cast<const uint8_t*>(blob.data()),
                                       blob.size()));
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
// resolve_pairing_outcome: normal and storage-exhausted paths
// =============================================================================

// Normal case: storage is available -> returns {psk, record=set}.
// The record must be bound to the given server_id/label and carry a psk_id matching the PSK.
TEST(RecordStore, ResolvePairingOutcomeNormal) {
    RecordStore store(nullptr);

    const std::string server_id = "server-pair-test";
    auto outcome = store.resolve_pairing_outcome(server_id, "My Hub");

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

    // The record's server_id and label must match what was passed in.
    EXPECT_EQ(outcome->record.server_id, server_id);
    EXPECT_EQ(outcome->record.label, "My Hub");

    // psk_id must be set and match the PSK.
    EXPECT_EQ(outcome->psk, outcome->record.psk);
    EXPECT_EQ(outcome->record.psk_id, psk_id_for(outcome->psk));
}

// Storage-exhausted case: a net-new record has nowhere to go, so the pairing cannot be minted.
TEST(RecordStore, ResolvePairingOutcomeExhausted) {
    RecordStore store(nullptr, /*initial_unpaired_access_enabled=*/false, /*max_records=*/1);
    ASSERT_TRUE(store.store_record_superseding(make_client_record("server-holding-the-slot")));

    auto outcome = store.resolve_pairing_outcome("server-exhausted");

    EXPECT_FALSE(outcome.has_value()) << "an exhausted store cannot mint a new pairing record";
    EXPECT_EQ(store.record_by_server_id("server-exhausted"), nullptr);
}

// store_record after resolve_pairing_outcome (simulates the server/pair-finalize ack path).
// After storing, the record must be resolvable by psk_id and bound to the server.
TEST(RecordStore, ResolvePairingOutcomeThenStore) {
    RecordStore store(nullptr);

    const std::string server_id = "server-store-after";
    auto outcome = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(outcome.has_value());

    // Simulate the ack path: store the pending record.
    store.store_record_superseding(outcome->record);

    const auto* stored = store.record_by_server_id(server_id);
    ASSERT_NE(stored, nullptr) << "record must be retrievable by server_id after store";
    EXPECT_EQ(stored->psk_id, outcome->record.psk_id);
    EXPECT_EQ(stored->psk, outcome->psk);

    auto resolved = store.resolve_by_psk_id(stored->psk_id);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
}

// records_snapshot() returns a thread-safe copy of every long-term record.
TEST(RecordStore, RecordsSnapshotReturnsAllRecords) {
    RecordStore store(nullptr);
    ASSERT_TRUE(store.records_snapshot().empty());

    SendspinPairingRecord a = make_client_record("server-A");
    SendspinPairingRecord b = make_client_record("server-B");
    store.store_record_superseding(a);
    store.store_record_superseding(b);

    auto snap = store.records_snapshot();
    EXPECT_EQ(snap.size(), 2u);

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
    store.store_record_superseding(rec);

    auto copy = store.record_by_psk_id_copy(rec.psk_id);
    ASSERT_TRUE(copy.has_value());
    EXPECT_EQ(copy->psk_id, rec.psk_id);
    EXPECT_EQ(copy->server_id, "server-copy-test");
    EXPECT_EQ(copy->psk, rec.psk);
}

TEST(RecordStore, RecordByPskIdCopyReturnsNulloptForAbsent) {
    RecordStore store(nullptr);
    auto copy = store.record_by_psk_id_copy("nonexistent-psk-id");
    EXPECT_FALSE(copy.has_value());
}

// =============================================================================
// Player static delay: ASCII-decimal round-trip via persistence_keys::STATIC_DELAY
// =============================================================================

// update_static_delay() must persist an ASCII decimal string (not raw uint16_t bytes):
// debuggable and endian-free, per persistence_keys::STATIC_DELAY's contract.
TEST(PlayerRoleStaticDelay, PersistsAsAsciiDecimal) {
    InMemoryPersistenceProvider provider;
    SendspinClientConfig config;
    config.name = "static-delay-round-trip-test";
    SendspinClient client(std::move(config));
    client.set_persistence_provider(&provider);

    PlayerRoleConfig player_config;
    auto& player = client.add_player(player_config);
    ASSERT_TRUE(client.start());
    player.set_static_delay_adjustable(true);
    player.update_static_delay(1234);

    auto blob = provider.blob(persistence_keys::STATIC_DELAY);
    ASSERT_TRUE(blob.has_value());
    EXPECT_EQ(std::string(blob->begin(), blob->end()), "1234")
        << "static_delay must persist as an ASCII decimal string";

    // And it must load back correctly on a fresh PlayerRole over the same provider.
    SendspinClientConfig config2;
    config2.name = "static-delay-round-trip-test-2";
    SendspinClient client2(std::move(config2));
    client2.set_persistence_provider(&provider);
    PlayerRoleConfig player_config2;
    auto& player2 = client2.add_player(player_config2);
    ASSERT_TRUE(client2.start());
    player2.set_static_delay_adjustable(true);
    EXPECT_EQ(player2.get_static_delay_ms(), 1234u);
}

// An unparseable persisted static_delay blob (corrupt bytes, not decimal digits) must be
// treated as though nothing were saved, falling back to PlayerRoleConfig::initial_static_delay_ms
// rather than crashing or reinterpreting garbage as a number.
TEST(PlayerRoleStaticDelay, InvalidPersistedValueIsTreatedAsAbsent) {
    InMemoryPersistenceProvider provider;
    provider.seed_blob(persistence_keys::STATIC_DELAY, to_bytes("not-a-number"));

    SendspinClientConfig config;
    config.name = "static-delay-invalid-test";
    SendspinClient client(std::move(config));
    client.set_persistence_provider(&provider);

    PlayerRoleConfig player_config;
    player_config.initial_static_delay_ms = 77;
    auto& player = client.add_player(player_config);
    ASSERT_TRUE(client.start());
    player.set_static_delay_adjustable(true);

    EXPECT_EQ(player.get_static_delay_ms(), 77u)
        << "an unparseable static_delay blob must be treated as absent, falling back to "
           "initial_static_delay_ms";
}

// ============================================================================
// Static PIN load-time validation
// ============================================================================

// A STATIC_PIN blob that is not 8 decimal digits is rejected at load, exactly as RECORDS and
// PAIRING_PSK are rejected by their decoders. Accepting it would leave the device advertising
// static_pin while feeding garbage PRS bytes to the PAKE.
TEST(RecordStore, RejectsMalformedStoredStaticPin) {
    for (const std::string& bad : {std::string("abcdefgh"), std::string("1234"),
                                   std::string("123456789"), std::string("1234567x")}) {
        InMemoryPersistenceProvider provider;
        provider.seed_blob(persistence_keys::STATIC_PIN, to_bytes(bad));
        RecordStore store(&provider);
        EXPECT_FALSE(store.static_pin().has_value())
            << "stored static PIN '" << bad << "' should have been rejected at load";
    }
}

TEST(RecordStore, AcceptsValidStoredStaticPin) {
    InMemoryPersistenceProvider provider;
    provider.seed_blob(persistence_keys::STATIC_PIN, to_bytes("12345678"));
    RecordStore store(&provider);
    ASSERT_TRUE(store.static_pin().has_value());
    EXPECT_EQ(store.static_pin().value(), "12345678");
}

TEST(SendspinClientIdentity, ConnectToBeforeStartServerIsRefused) {
    SendspinClientConfig config;
    config.name = "connect-before-start";
    SendspinClient client(std::move(config));

    EXPECT_TRUE(client.client_id().empty()) << "no identity exists before start()";
    client.connect_to("ws://192.0.2.1:8927/sendspin");
    client.loop();  // must not fault on a null identity_

    EXPECT_FALSE(client.is_connected())
        << "connect_to() before start() must not produce a live connection";
}

// Ordering makes a crash between the two provisioning writes self-healing, but a provider that
// rejects PAIR_CONFIG while accepting RECORDS would reach the same orphaned state by another
// route. The record write is skipped when the config write is refused, so the next boot is a
// clean first boot rather than a re-provisioning one that appends alongside an orphan.
// ============================================================================
// PSK zeroization on destruction
// ============================================================================

// The pairing structs promise to wipe their psk array when destroyed (see config.h and
// record_store.h). These tests pin that behavior: each constructs the object in caller-owned
// storage via placement new, fills the psk with a sentinel pattern, destroys the object
// explicitly, and then inspects the storage bytes where the psk lived. The storage itself
// stays alive for the whole test, so reading it after the object's lifetime ends is
// well-defined; only the object is gone.

namespace {

template <typename T> void expect_psk_wiped_on_destruction() {
    alignas(T) unsigned char storage[sizeof(T)];
    T* obj = new (storage) T();
    obj->psk.fill(0xA5u);
    // Take the address before destruction; afterwards only the raw bytes may be read.
    const unsigned char* psk_bytes = reinterpret_cast<const unsigned char*>(obj->psk.data());
    const size_t psk_len = obj->psk.size();
    obj->~T();
    for (size_t i = 0; i < psk_len; ++i) {
        ASSERT_EQ(psk_bytes[i], 0u) << "psk byte " << i << " survived destruction";
    }
}

}  // namespace

TEST(PskZeroization, PairingRecordDestructorWipesPsk) {
    expect_psk_wiped_on_destruction<SendspinPairingRecord>();
}

TEST(PskZeroization, PairingPskDestructorWipesPsk) {
    expect_psk_wiped_on_destruction<SendspinPairingPsk>();
}

TEST(PskZeroization, ResolvedPskDestructorWipesPsk) {
    expect_psk_wiped_on_destruction<ResolvedPsk>();
}

TEST(PskZeroization, PairingOutcomeDestructorWipesPsk) {
    expect_psk_wiped_on_destruction<RecordStore::PairingOutcome>();
}

// Reproduces the two-thread access pattern production actually runs:
//
//   main loop     -> ConnectionManager::handle_enter_pairing_psk()
//                      -> RecordStore::resolve_pairing_outcome()   [reads records_]
//   network thread-> SendspinClient::process_json_message(), server/pair-finalize
//                      -> RecordStore::store_record_superseding()  [push_back/erase records_]
//
// Both threads are real in production: server/pair-finalize commits synchronously on the
// network thread (deliberately, so the server's follow-up re-handshake can resolve the new
// psk_id), while the main loop enters pairing for a different connection. The two sides guard
// different mutexes at the ConnectionManager level, so nothing above RecordStore serializes
// them.
//
// resolve_pairing_outcome() must therefore hold mutex_ across its whole body: probing records_
// through the unlocked record_by_server_id() helper races store_record_superseding()'s
// push_back reallocation. Under ThreadSanitizer (-DENABLE_TSAN=ON) such a race is reported against
// records_ and fails this test. Without TSan the test still carries weight: it would hang if
// the locking ever re-entered the non-recursive mutex_.
TEST(RecordStoreConcurrency, ResolvePairingOutcomeDoesNotRaceRecordStores) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider, /*initial_unpaired_access_enabled=*/true, /*max_records=*/64);

    // Both threads work over an overlapping server_id space so the reader's scan and the
    // writer's supersede-erase touch the same entries.
    constexpr int SERVER_ID_SPACE = 8;
    constexpr int ITERATIONS = 2000;

    std::atomic<bool> writer_ready{false};

    std::thread writer([&] {
        writer_ready.store(true, std::memory_order_release);
        for (int i = 0; i < ITERATIONS; ++i) {
            SendspinPairingRecord record;
            record.psk_id = "psk-" + std::to_string(i);
            record.psk.fill(static_cast<uint8_t>(i));
            record.server_id = "server-" + std::to_string(i % SERVER_ID_SPACE);
            store.store_record_superseding(std::move(record));
        }
    });

    while (!writer_ready.load(std::memory_order_acquire)) {
    }

    for (int i = 0; i < ITERATIONS; ++i) {
        auto outcome = store.resolve_pairing_outcome("server-" + std::to_string(i %
                                                                                SERVER_ID_SPACE));
        // Every resolve must mint a usable outcome, whether this server is new or is re-pairing
        // over its own record. A torn read of records_ would surface here as a miss.
        ASSERT_TRUE(outcome.has_value());
    }

    writer.join();
}
