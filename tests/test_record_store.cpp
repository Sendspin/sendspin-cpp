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
// save_blob); RecordStore and FilePersistenceProvider are pure byte stores for the
// record slot / "pairing_psk" keys, so tests that need to inspect or shape what
// is actually stored go through the codec in sendspin/persistence_codec.h and the slot helpers
// in record_test_helpers.h, exactly like production code does. Most fakes here share
// tests/fake_persistence.h's InMemoryPersistenceProvider; a handful of tests need bespoke
// behavior (observing removals specifically, serving mismatched/canned codec content) and keep a
// local fake for that.

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "fake_persistence.h"
#include "log_capture.h"
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
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <future>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

// ============================================================================
// Test helpers
// ============================================================================

/// Build an accepted Pairing PSK.
static SendspinPairingPsk make_pairing_psk() {
    auto psk = make_random_psk();
    SendspinPairingPsk p;
    p.psk_id = psk_id_for(psk);
    p.psk = psk;
    return p;
}

/// The production playback sequence: ConnectionManager::note_playback_activity() calls
/// note_record_played() and requests a flush only when that call moved the order.
static void play_record(RecordStore& store, const std::string& psk_id) {
    if (store.note_record_played(psk_id)) {
        (void) store.persist_records();
    }
}

/// The production revocation sequence: ConnectionManager::handle_server_unpair() erases under
/// its own lock and the flush empties the slot.
static bool remove_record(RecordStore& store, const std::string& psk_id) {
    if (!store.note_record_removed(psk_id)) {
        return false;
    }
    return store.persist_records();
}

/// A persistence provider whose record writes can be made to fail (e.g. full or faulty flash),
/// counting the slot writes and the recency-order writes separately. Pairing PSK / pair config
/// writes always succeed; they are not under test here.
class RejectingPersistenceProvider : public SendspinPersistenceProvider {
public:
    bool save_blob(const std::string& key, const uint8_t* /*data*/, size_t /*len*/) override {
        if (!is_record_key(key)) {
            return true;
        }
        if (key == persistence_keys::RECORD_ORDER) {
            order_writes++;
        } else {
            slot_writes++;
        }
        return !reject;
    }

    bool reject{true};
    int slot_writes{0};
    int order_writes{0};
};

// ============================================================================
// Basic construction / first-boot provisioning
// ============================================================================

TEST(RecordStore, FirstBootProvisioningCreatesPairingPsk) {
    RecordStore store(nullptr);

    // pairing_psk is the client-mandatory pairing method, so a Pairing PSK must exist even
    // when nothing was ever persisted, and it must resolve as the PAIRING category.
    ASSERT_TRUE(store.pairing_psk().has_value());
    EXPECT_EQ(store.pairing_psk()->psk_id, psk_id_for(store.pairing_psk()->psk));

    auto resolved = store.resolve_by_psk_id(store.pairing_psk()->psk_id, PskCategory::PAIRING);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::PAIRING);
    EXPECT_EQ(resolved->psk, store.pairing_psk()->psk);

}

/// A persistence provider whose writes always fail (e.g. full or read-only NVS), used to verify
/// first-boot provisioning surfaces a rejected write instead of silently discarding it.
class AlwaysRejectingProvider : public SendspinPersistenceProvider {
public:
    bool save_blob(const std::string& key, const uint8_t* /*data*/, size_t /*len*/) override {
        if (is_record_key(key)) {
            record_save_attempts++;
        } else if (key == persistence_keys::PAIRING_PSK) {
            psk_save_attempts++;
        }
        return false;
    }

    int record_save_attempts{0};
    int psk_save_attempts{0};
};

// A provider that rejects every write during first-boot provisioning must not be silently
// ignored. The device must still be fully usable for the current boot (RAM-only state), and
// the provider must actually have been asked to persist each piece of material.
TEST(RecordStore, FirstBootProvisioningSurvivesPersistenceFailureForThisBoot) {
    AlwaysRejectingProvider provider;
    RecordStore store(&provider);

    EXPECT_EQ(provider.record_save_attempts, 0) << "a first boot has no record to persist";
    EXPECT_GE(provider.psk_save_attempts, 1) << "the Pairing PSK write must have been attempted";

    // Despite every write being rejected, the device remains usable for this boot: the Pairing
    // PSK is present and resolvable in memory.
    ASSERT_TRUE(store.pairing_psk().has_value());
    auto resolved = store.resolve_by_psk_id(store.pairing_psk()->psk_id, PskCategory::PAIRING);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::PAIRING);
}

// ============================================================================
// Booting from a blob store seeded purely via the public codec
// ============================================================================

// A provider seeded entirely through sendspin/persistence_codec.h (no RecordStore involved)
// must be read back as-is, with no first-boot re-provisioning: the seeded material is complete
// and valid, so RecordStore has nothing to fill in.
TEST(RecordStore, BootsFromBlobStoreSeededViaCodec) {
    InMemoryPersistenceProvider provider;

    SendspinPairingRecord paired = make_client_record("server-seeded");
    seed_records(provider, {paired});

    SendspinPairingPsk psk = make_pairing_psk();
    provider.seed_blob(persistence_keys::PAIRING_PSK, blob_bytes(encode_pairing_psk(psk)));

    RecordStore store(&provider);

    EXPECT_EQ(provider.save_attempts(persistence_keys::record_slot_key(0)), 0)
        << "a fully-seeded store must not trigger first-boot re-provisioning";
    EXPECT_EQ(provider.save_attempts(persistence_keys::PAIRING_PSK), 0)
        << "a fully-seeded store must not trigger first-boot re-provisioning";

    auto resolved_paired = store.resolve_by_psk_id(paired.psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(resolved_paired.has_value());
    EXPECT_EQ(resolved_paired->category, PskCategory::LONG_TERM);
    EXPECT_EQ(resolved_paired->counterparty_id, paired.server_id);

    ASSERT_TRUE(store.pairing_psk().has_value());
    EXPECT_EQ(store.pairing_psk()->psk_id, psk.psk_id);
    EXPECT_EQ(store.pairing_psk()->psk, psk.psk);
}

// One record per key is what keeps a corrupt blob from costing the whole store: a slot that does
// not decode (corrupt bytes of the wrong size) drops that record and no other, and the store
// still starts.
TEST(RecordStore, ACorruptSlotLosesOnlyThatRecord) {
    InMemoryPersistenceProvider provider;
    SendspinPairingRecord corrupted = make_client_record("server-corrupt");
    SendspinPairingRecord survivor = make_client_record("server-survivor");
    seed_records(provider, {corrupted, survivor});
    provider.seed_blob(persistence_keys::record_slot_key(0),
                       blob_bytes("corrupt bytes"));

    RecordStore store(&provider);

    EXPECT_FALSE(store.resolve_by_psk_id(corrupted.psk_id, PskCategory::LONG_TERM).has_value())
        << "the corrupt slot's record must not resolve";
    EXPECT_TRUE(store.resolve_by_psk_id(survivor.psk_id, PskCategory::LONG_TERM).has_value())
        << "the intact slot must still load";
    EXPECT_TRUE(store.pairing_psk().has_value()) << "the store must still start";
}

// ============================================================================
// store_record_superseding: at most one record per server_id
// ============================================================================

// Re-pairing the same server_id twice (e.g. after the server was factory-reset and re-paired)
// must revoke the prior per-server PSK rather than leaving it valid forever alongside the new
// one. Mirrors the server/pair-finalize ack commit path: resolve_pairing_outcome() mints a
// fresh record, then store_record_superseding() commits it.
TEST(RecordStore, StoreRecordSupersedesPriorRecordForSameServerId) {
    RecordStore store(nullptr);
    const std::string server_id = test_peer_id("server-repair");

    auto outcome1 = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(store.store_record_superseding(outcome1.record, {}));
    const std::string first_psk_id = outcome1.record.psk_id;

    auto outcome2 = store.resolve_pairing_outcome(server_id);
    ASSERT_TRUE(store.store_record_superseding(outcome2.record, {}));
    const std::string second_psk_id = outcome2.record.psk_id;

    ASSERT_NE(first_psk_id, second_psk_id);

    // The prior PSK must no longer resolve at all: re-pairing revokes it instead of leaving a
    // second working credential for the same server.
    EXPECT_FALSE(store.resolve_by_psk_id(first_psk_id, PskCategory::LONG_TERM).has_value());
    EXPECT_EQ(store.record_by_psk_id(first_psk_id), nullptr);

    // The new PSK resolves as the server's long-term record.
    auto resolved = store.resolve_by_psk_id(second_psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
    EXPECT_EQ(resolved->counterparty_id, server_id);

    // Exactly one record remains bound to this server_id.
    const auto* found = store.record_by_server_id(server_id);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, second_psk_id);
    int count = 0;
    for (const auto& stored : store.records_) {
        if (stored.record.server_id == server_id) {
            count++;
        }
    }
    EXPECT_EQ(count, 1);
}

// The supersede itself never calls the provider: in production it runs on the protocol task
// (the server/pair-finalize ack handler), where the provider contract forbids calls, so the
// durable write is deferred to persist_records() on the main loop. The RAM mutation commits
// immediately either way; a provider that then rejects the flush leaves the replacement
// authoritative for this boot while the provider keeps its last accepted blob, so the ORIGINAL
// record comes back at the next boot.
TEST(RecordStore, StoreRecordSupersedingIsRamOnlyUntilPersistRecords) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X");
    ASSERT_TRUE(store.store_record_superseding(original, {}));
    ASSERT_TRUE(store.persist_records());

    reject_record_saves(provider);
    const size_t attempts_before = record_writes(provider);

    SendspinPairingRecord replacement = make_client_record("server-X");
    EXPECT_TRUE(store.store_record_superseding(replacement, {}))
        << "the RAM-only supersede must not fail on a provider that would reject the write";
    EXPECT_EQ(record_writes(provider), attempts_before)
        << "store_record_superseding must not call the provider";

    // RAM state is authoritative for this boot: the replacement resolves, the original is gone.
    auto resolved = store.resolve_by_psk_id(replacement.psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
    EXPECT_EQ(store.record_by_psk_id(original.psk_id), nullptr);
    const auto* found = store.record_by_server_id(test_peer_id("server-X"));
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, replacement.psk_id);

    // The deferred flush is where the rejection surfaces.
    EXPECT_FALSE(store.persist_records());
    EXPECT_GT(record_writes(provider), attempts_before)
        << "the rejected flush must have been attempted";

    // "Reboot": the provider still holds the last accepted slot, so the original record
    // resurfaces and the replacement is lost.
    RecordStore rebooted(&provider);
    EXPECT_TRUE(rebooted.resolve_by_psk_id(original.psk_id, PskCategory::LONG_TERM).has_value());
    EXPECT_FALSE(rebooted.resolve_by_psk_id(replacement.psk_id, PskCategory::LONG_TERM).has_value());
}

// find_index() keys the store on psk_id, so a record whose psk_id is already held replaces that
// record in place instead of adding a second entry for the same credential. Reached here with a
// different server_id, because the supersede-by-server_id retire below would otherwise clean up
// a duplicate and hide the branch. Asserted through the handshake resolve (which server the
// psk_id now authenticates) and the persisted slots (what comes back after a reboot).
TEST(RecordStore, StoreRecordReplacesTheRecordHoldingTheSamePskId) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord first = make_client_record("server-A");
    const std::string psk_id = first.psk_id;
    ASSERT_TRUE(store.store_record_superseding(first, {}));

    SendspinPairingRecord second = first;
    second.server_id = test_peer_id("server-B");
    ASSERT_TRUE(store.store_record_superseding(second, {}));
    ASSERT_TRUE(store.persist_records());

    auto resolved = store.resolve_by_psk_id(psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(resolved.has_value());
    ASSERT_TRUE(resolved->counterparty_id.has_value());
    EXPECT_EQ(resolved->counterparty_id.value(), test_peer_id("server-B"))
        << "the psk_id must authenticate the server that paired with it last, not the one it "
           "replaced";

    auto stored = persisted_records(provider);
    ASSERT_EQ(stored.size(), 1u) << "one record per psk_id";
    EXPECT_EQ(stored[0].server_id, test_peer_id("server-B"));
}

// ============================================================================
// Capacity and eviction (pairing.md "Pairing Records")
// ============================================================================

// Pairing at capacity must not fail: the store evicts a record instead.
TEST(RecordStore, CapacityEvictsRatherThanRefusingANewPairing) {
    RecordStore store(nullptr);
    for (size_t i = 0; i < RecordStore::DEFAULT_MAX_RECORDS; ++i) {
        auto outcome = store.resolve_pairing_outcome(test_peer_id("server-" + std::to_string(i)));
        ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
    }
    ASSERT_EQ(store.records_.size(), RecordStore::DEFAULT_MAX_RECORDS);

    auto overflow = store.resolve_pairing_outcome(test_peer_id("server-overflow"));
    EXPECT_TRUE(store.store_record_superseding(overflow.record, {}))
        << "a pairing never fails for lack of record storage";
    EXPECT_NE(store.record_by_server_id(test_peer_id("server-overflow")), nullptr);
    EXPECT_EQ(store.records_.size(), RecordStore::DEFAULT_MAX_RECORDS)
        << "eviction makes room rather than growing the store";
    EXPECT_EQ(store.record_by_server_id(test_peer_id("server-0")), nullptr)
        << "the least recently used record is the one evicted";
    EXPECT_NE(store.record_by_server_id(test_peer_id("server-1")), nullptr)
        << "only one record is evicted per pairing";
}

// The recency order survives a reboot, but a reorder must cost only the record-order blob: it
// runs on every playback handoff, so rewriting a record slot for it would be an NVS erase cycle
// per handoff for bookkeeping the record itself does not carry.
TEST(RecordStore, RecencyReorderWritesOnlyTheOrderKey) {
    RejectingPersistenceProvider provider;
    provider.reject = false;
    RecordStore store(&provider, {.max_pairing_records = RecordStore::MIN_MAX_RECORDS});
    SendspinPairingRecord record_a = make_client_record("server-A");
    SendspinPairingRecord record_b = make_client_record("server-B");
    const std::string psk_a = record_a.psk_id;
    const std::string psk_b = record_b.psk_id;
    ASSERT_TRUE(store.store_record_superseding(std::move(record_a), {}));
    ASSERT_TRUE(store.store_record_superseding(std::move(record_b), {}));

    // Fill the store, so A and B sit at the front, oldest first.
    std::vector<std::string> filler_psk_ids;
    for (size_t i = 2; i < RecordStore::MIN_MAX_RECORDS; ++i) {
        auto record = make_client_record("filler-" + std::to_string(i));
        filler_psk_ids.push_back(record.psk_id);
        ASSERT_TRUE(store.store_record_superseding(std::move(record), {}));
    }
    ASSERT_TRUE(store.persist_records());
    const int slot_writes_after_pairing = provider.slot_writes;
    const int order_writes_after_pairing = provider.order_writes;

    // Two servers taking turns: each handoff moves the other's record off the back.
    for (int i = 0; i < 10; ++i) {
        play_record(store, psk_a);
        play_record(store, psk_b);
    }
    EXPECT_EQ(provider.slot_writes, slot_writes_after_pairing)
        << "a reorder alone must not rewrite a record slot";
    EXPECT_EQ(provider.order_writes - order_writes_after_pairing, 20)
        << "each reorder must write the record-order blob once";
    play_record(store, psk_b);
    EXPECT_EQ(provider.order_writes - order_writes_after_pairing, 20)
        << "playing the most recent record again moves nothing and must write nothing";

    // Control: the reorder still happened. A and B were the two oldest records when the
    // alternation began, so without the rotate A would be the victim here; with it, the oldest
    // filler is.
    auto outcome = store.resolve_pairing_outcome(test_peer_id("server-new"));
    ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
    EXPECT_FALSE(store.resolve_by_psk_id(filler_psk_ids.front(), PskCategory::LONG_TERM).has_value())
        << "the RAM-only order must still drive eviction";
    EXPECT_TRUE(store.resolve_by_psk_id(psk_a, PskCategory::LONG_TERM).has_value())
        << "a record used since it was stored must not be the victim";
    EXPECT_TRUE(store.resolve_by_psk_id(psk_b, PskCategory::LONG_TERM).has_value());
}

// The persisted recency order is what makes eviction survive a reboot: the store comes up in the
// order persistence_keys::RECORD_ORDER names, not in slot order, so the victim is the record the
// last boot used least recently.
TEST(RecordStore, BootRestoresTheRecencyOrderFromTheOrderKey) {
    struct Row {
        const char* name;
        std::vector<uint8_t> order;
        size_t expected_victim;  ///< Index into the seeded records.
    };
    const Row rows[] = {
        {"stored-order-outranks-slot-order", {4, 0, 1, 2, 3}, 4},
        {"slot-number-naming-no-record-is-ignored", {9, 4, 0, 1, 2, 3}, 4},
        // A blob that names only some slots: the record it names sorts FIRST (least recently
        // used), the ones it does not sort after it in slot order. Appending the unnamed
        // records ahead of the named one instead would make slot 0 the victim.
        {"order-names-only-some-slots", {3}, 3},
        // Control: with no order key at all the store falls back to slot order, so the first
        // slot is the victim. This is what says the rows above read the blob rather than
        // evicting slot 4 for some other reason.
        {"no-order-key-falls-back-to-slot-order", {}, 0},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InMemoryPersistenceProvider provider;
        std::vector<SendspinPairingRecord> seeded;
        for (size_t i = 0; i < RecordStore::MIN_MAX_RECORDS; ++i) {
            seeded.push_back(make_client_record("server-" + std::to_string(i)));
        }
        seed_records(provider, seeded);
        provider.seed_blob(persistence_keys::RECORD_ORDER, row.order);

        RecordStore store(&provider, {.max_pairing_records = RecordStore::MIN_MAX_RECORDS});
        auto overflow = store.resolve_pairing_outcome(test_peer_id("server-new"));
        ASSERT_TRUE(store.store_record_superseding(overflow.record, {}));

        for (size_t i = 0; i < seeded.size(); ++i) {
            const bool evicted =
                !store.resolve_by_psk_id(seeded[i].psk_id, PskCategory::LONG_TERM).has_value();
            EXPECT_EQ(evicted, i == row.expected_victim)
                << "record " << i << " was " << (evicted ? "evicted" : "kept");
        }
    }
}

// The same claim end to end, over the write side: what a session used least recently in one boot
// is what the next boot evicts. Without the persisted order the store would come up in slot
// order and evict the record this test used first.
TEST(RecordStore, EvictionAfterARebootFollowsThePersistedUseOrder) {
    InMemoryPersistenceProvider provider;
    std::vector<std::string> psk_ids;
    {
        RecordStore store(&provider, {.max_pairing_records = RecordStore::MIN_MAX_RECORDS});
        for (size_t i = 0; i < RecordStore::MIN_MAX_RECORDS; ++i) {
            auto record = make_client_record("server-" + std::to_string(i));
            psk_ids.push_back(record.psk_id);
            ASSERT_TRUE(store.store_record_superseding(std::move(record), {}));
        }
        ASSERT_TRUE(store.persist_records());
        // Playback in reverse storage order: the record stored last is now the least recently
        // used one, so slot order and use order disagree.
        for (auto it = psk_ids.rbegin(); it != psk_ids.rend(); ++it) {
            play_record(store, *it);
        }
    }

    RecordStore rebooted(&provider, {.max_pairing_records = RecordStore::MIN_MAX_RECORDS});
    auto overflow = rebooted.resolve_pairing_outcome(test_peer_id("server-new"));
    ASSERT_TRUE(rebooted.store_record_superseding(overflow.record, {}));

    EXPECT_FALSE(rebooted.resolve_by_psk_id(psk_ids.back(), PskCategory::LONG_TERM).has_value())
        << "the record the last boot used least recently must be the victim";
    EXPECT_TRUE(rebooted.resolve_by_psk_id(psk_ids.front(), PskCategory::LONG_TERM).has_value())
        << "the record in the lowest slot must not be evicted for being first in slot order";
}

// One record per key means a change touches one key: a revocation empties the revoked record's
// slot and rewrites the order, and leaves every other record's slot alone. Rewriting them would
// be an NVS erase cycle each on ESP.
TEST(RecordStore, RemovingARecordWritesOnlyItsSlotAndTheOrder) {
    InMemoryPersistenceProvider provider;
    SendspinPairingRecord keeper = make_client_record("server-keeper");
    SendspinPairingRecord revoked = make_client_record("server-revoked");
    seed_records(provider, {keeper, revoked});
    RecordStore store(&provider);

    ASSERT_TRUE(remove_record(store, revoked.psk_id));

    EXPECT_EQ(provider.save_attempts(persistence_keys::record_slot_key(1)), 1)
        << "the revoked record's slot must be written once";
    EXPECT_EQ(provider.save_attempts(persistence_keys::record_slot_key(0)), 0)
        << "a record no op touched must not be rewritten";
    EXPECT_EQ(provider.save_attempts(persistence_keys::RECORD_ORDER), 1)
        << "the order must be rewritten, since the store no longer holds that record";
    EXPECT_FALSE(stored_record_in_slot(provider, 1).has_value())
        << "the revoked record's slot must be emptied, not left holding it";
    EXPECT_EQ(persisted_psk_ids(provider), std::vector<std::string>{keeper.psk_id});
}

// A provider that queues its writes makes them durable at commit(), so the store must commit
// after writing pairing material and must not after the recency order alone: the order moves on
// every playback handoff, and on ESP a commit is the flash write.
TEST(RecordStore, CommitFollowsPairingMaterialButNotTheRecencyOrder) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider, {.max_pairing_records = RecordStore::MIN_MAX_RECORDS});
    EXPECT_EQ(provider.commits(), 1) << "the generated Pairing PSK must be committed";
    EXPECT_TRUE(provider.uncommitted_keys().empty());

    SendspinPairingRecord older = make_client_record("server-older");
    SendspinPairingRecord newer = make_client_record("server-newer");
    const std::string older_psk_id = older.psk_id;
    ASSERT_TRUE(store.store_record_superseding(std::move(older), {}));
    ASSERT_TRUE(store.store_record_superseding(std::move(newer), {}));
    ASSERT_TRUE(store.persist_records());
    EXPECT_EQ(provider.commits(), 2) << "one batch of record slots must commit once";
    EXPECT_TRUE(provider.uncommitted_keys().empty())
        << "the commit must follow every write of the batch";

    play_record(store, older_psk_id);
    EXPECT_EQ(provider.commits(), 2) << "a recency move alone must not commit";
    // Control: the move was written, so the missing commit is a decision and not a missing write.
    EXPECT_EQ(provider.uncommitted_keys(),
              std::vector<std::string>{persistence_keys::RECORD_ORDER});

    provider.fail_commits = true;
    ASSERT_TRUE(store.store_record_superseding(make_client_record("server-uncommitted"), {}));
    EXPECT_FALSE(store.persist_records()) << "a failed commit must be reported like a failed write";
}

// A provider may store each key as a fixed-size value (persistence_keys), so every write the store
// makes has its key's size: a record slot whether it holds a record or is being freed, and the
// recency order however many records the store holds.
TEST(RecordStore, EveryRecordWriteHasItsKeysFixedSize) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider);
    const size_t order_size = RecordStore::DEFAULT_MAX_RECORDS;

    auto outcome = store.resolve_pairing_outcome(test_peer_id("server-sized"));
    ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
    ASSERT_TRUE(store.persist_records());

    auto slot = provider.blob(persistence_keys::record_slot_key(0));
    ASSERT_TRUE(slot.has_value());
    EXPECT_EQ(slot->size(), persistence_keys::RECORD_SLOT_SIZE) << "an occupied slot";
    std::vector<uint8_t> expected_order(order_size, 0xFF);
    expected_order[0] = 0;
    EXPECT_EQ(provider.blob(persistence_keys::RECORD_ORDER), expected_order)
        << "one byte per slot the store may use, unused positions 0xFF";

    ASSERT_TRUE(remove_record(store, outcome.record.psk_id));
    EXPECT_EQ(provider.blob(persistence_keys::record_slot_key(0)),
              std::vector<uint8_t>(persistence_keys::RECORD_SLOT_SIZE, 0))
        << "a freed slot is written as zeros of the same size";
    EXPECT_EQ(provider.blob(persistence_keys::RECORD_ORDER),
              std::vector<uint8_t>(order_size, 0xFF));
}

// A supersede reuses the slot its own retire just freed, which is what makes "a pairing costs
// one record-sized write" true. Taking the lowest free slot instead would put the new record in
// a slot an earlier revocation freed and empty the superseded one as well: two record writes,
// two NVS erase cycles on ESP, per re-pair.
TEST(RecordStore, ASupersedeReusesTheSlotItsRetireFreed) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider);

    auto pair_with = [&store](const std::string& server_id) {
        auto outcome = store.resolve_pairing_outcome(test_peer_id(server_id));
        EXPECT_TRUE(store.store_record_superseding(outcome.record, {}));
        EXPECT_TRUE(store.persist_records());
        return outcome.record.psk_id;
    };

    const std::string psk_a = pair_with("server-a");  // slot 0
    const std::string psk_b = pair_with("server-b");  // slot 1
    ASSERT_TRUE(remove_record(store, psk_a));         // slot 0 is free again, and lower than 1

    const int slot0_before = provider.save_attempts(persistence_keys::record_slot_key(0));
    const int slot1_before = provider.save_attempts(persistence_keys::record_slot_key(1));
    const std::string psk_b2 = pair_with("server-b");

    EXPECT_EQ(provider.save_attempts(persistence_keys::record_slot_key(1)) - slot1_before, 1)
        << "the superseding record must be written into the slot its own retire freed";
    EXPECT_EQ(provider.save_attempts(persistence_keys::record_slot_key(0)) - slot0_before, 0)
        << "a supersede must not take a slot an earlier revocation freed";
    ASSERT_TRUE(stored_record_in_slot(provider, 1).has_value());
    EXPECT_EQ(stored_record_in_slot(provider, 1)->psk_id, psk_b2);
    EXPECT_FALSE(stored_record_in_slot(provider, 0).has_value());

    // Control: a pairing that supersedes nothing still takes the lowest free slot.
    const std::string psk_c = pair_with("server-c");
    ASSERT_TRUE(stored_record_in_slot(provider, 0).has_value());
    EXPECT_EQ(stored_record_in_slot(provider, 0)->psk_id, psk_c);
    EXPECT_FALSE(store.resolve_by_psk_id(psk_b, PskCategory::LONG_TERM).has_value())
        << "the superseded PSK must stop resolving";
}

// note_record_played() reports what THIS call made dirty, not everything the store owes: a call
// that moves nothing reports no change even while a pairing's or a revocation's slot write is
// pending, so ConnectionManager::note_playback_activity() requests no flush for it.
TEST(RecordStore, NoteRecordPlayedThatMovesNothingReportsNoChangeWhileAWriteIsPending) {
    InMemoryPersistenceProvider provider;
    SendspinPairingRecord revoked = make_client_record("server-revoked");
    SendspinPairingRecord other = make_client_record("server-other");
    SendspinPairingRecord active = make_client_record("server-active");
    seed_records(provider, {revoked, other, active});  // active is the most recent
    RecordStore store(&provider);

    ASSERT_TRUE(store.note_record_removed(revoked.psk_id));  // durable, not yet flushed

    EXPECT_FALSE(store.note_record_played(active.psk_id))
        << "a handoff that moves nothing must not report the pending revocation as its own change";

    // Control: a handoff that does move the order reports it, pending write or not.
    EXPECT_TRUE(store.note_record_played(other.psk_id));
}

// A rejected write reports what it actually costs the next boot: a record slot write decides which
// records the next boot holds and warns, while the recency order, which the next boot rebuilds
// from use and which is written on every playback handoff, stays below warn against a full or
// read-only store.
TEST(RecordStore, ARejectedWriteWarnsOnlyWhenTheNextBootCannotRebuildIt) {
    // Seeded least recently used first, so playing the first moves the recency order and nothing
    // else.
    auto seeded = [] {
        return std::vector<SendspinPairingRecord>{make_client_record("server-older"),
                                                  make_client_record("server-newer"),
                                                  make_client_record("server-fresh")};
    };

    using Action = void (*)(RecordStore&, const std::vector<SendspinPairingRecord>&);
    struct Row {
        const char* name;
        Action act;
        /// The key the warning must name, or nullptr when the rejection must stay below warn.
        const char* warns_about;
        /// A phrase of the warning that says what the rejection costs; nullptr with warns_about.
        const char* cost;
    };
    const Row rows[] = {
        {"order-only",
         [](RecordStore& store, const std::vector<SendspinPairingRecord>& records) {
             ASSERT_TRUE(store.note_record_played(records[0].psk_id));
             EXPECT_FALSE(store.persist_records());
         },
         nullptr, nullptr},
        // Control: a write the next boot cannot reconstruct says so.
        {"pairing",
         [](RecordStore& store, const std::vector<SendspinPairingRecord>&) {
             auto outcome = store.resolve_pairing_outcome(test_peer_id("server-paired"));
             ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
             EXPECT_FALSE(store.persist_records());
         },
         "rec_3", "will not survive a reboot"},
        {"revocation",
         [](RecordStore& store, const std::vector<SendspinPairingRecord>& records) {
             EXPECT_FALSE(remove_record(store, records[0].psk_id));
         },
         "rec_0", "valid again"},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InMemoryPersistenceProvider provider;
        const std::vector<SendspinPairingRecord> records = seeded();
        seed_records(provider, records);
        RecordStore store(&provider);
        reject_record_saves(provider);

        std::string output;
        {
            StderrCapture capture;
            row.act(store, records);
            output = capture.release();
        }

        if (row.warns_about == nullptr) {
            EXPECT_TRUE(output.empty())
                << "a rejected write the next boot rebuilds must stay below warn: " << output;
            continue;
        }
        EXPECT_NE(output.find(row.warns_about), std::string::npos)
            << "the warning must name the rejected key: " << output;
        EXPECT_NE(output.find(row.cost), std::string::npos)
            << "the warning must say what the rejection costs: " << output;
    }
}

// Two slots carrying the same psk_id would leave a revoked credential working: a removal erases
// one entry from RAM and empties one slot, so the duplicate resolves again at the next boot.
// Lowering max_pairing_records and raising it back can produce that layout with no provider
// corruption at all, so the load path drops the higher slot and clears it.
TEST(RecordStore, ADuplicatePskIdInASecondSlotDoesNotOutliveARevocation) {
    InMemoryPersistenceProvider provider;
    SendspinPairingRecord keeper = make_client_record("server-keeper");
    SendspinPairingRecord duplicated = make_client_record("server-duplicated");
    seed_records(provider, {keeper, duplicated});
    provider.seed_blob(persistence_keys::record_slot_key(2),
                       record_blob(duplicated));

    {
        RecordStore store(&provider);
        ASSERT_TRUE(
            store.resolve_by_psk_id(duplicated.psk_id, PskCategory::LONG_TERM).has_value());
        ASSERT_TRUE(remove_record(store, duplicated.psk_id));
    }

    RecordStore rebooted(&provider);
    EXPECT_FALSE(rebooted.resolve_by_psk_id(duplicated.psk_id, PskCategory::LONG_TERM).has_value())
        << "a revoked psk_id must not come back from a duplicate slot";
    // Control: the record that was never duplicated is untouched by the dedupe.
    EXPECT_TRUE(rebooted.resolve_by_psk_id(keeper.psk_id, PskCategory::LONG_TERM).has_value());
}

// Recency moves on playback, not on activation: a server that only holds an idle connection must
// not outlive one the device is played from.
TEST(RecordStore, EvictionFollowsPlaybackRecency) {
    struct Row {
        const char* name;
        bool played;
        bool oldest_survives;
    };
    const Row rows[] = {
        {"played", true, true},
        // Control: the same record, not played, is the victim.
        {"not played", false, false},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        RecordStore store(nullptr);
        std::vector<std::string> psk_ids;
        for (size_t i = 0; i < RecordStore::DEFAULT_MAX_RECORDS; ++i) {
            auto outcome =
                store.resolve_pairing_outcome(test_peer_id("server-" + std::to_string(i)));
            psk_ids.push_back(outcome.record.psk_id);
            ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
        }

        // The oldest record, which without a reorder is the next victim.
        if (row.played) {
            (void) store.note_record_played(psk_ids.front());
        }

        auto overflow = store.resolve_pairing_outcome(test_peer_id("server-overflow"));
        ASSERT_TRUE(store.store_record_superseding(overflow.record, {}));

        EXPECT_EQ(store.record_by_server_id(test_peer_id("server-0")) != nullptr,
                  row.oldest_survives);
        EXPECT_EQ(store.record_by_server_id(test_peer_id("server-1")) != nullptr,
                  !row.oldest_survives)
            << "exactly one of the two oldest records is evicted";
    }
}

// A freshly paired record joins as the most recent, so the next pairing cannot evict it before it
// has been played.
TEST(RecordStore, ANewRecordIsNotTheNextVictim) {
    RecordStore store(nullptr, {.max_pairing_records = RecordStore::MIN_MAX_RECORDS});
    for (size_t i = 0; i < RecordStore::MIN_MAX_RECORDS; ++i) {
        auto outcome = store.resolve_pairing_outcome(test_peer_id("server-" + std::to_string(i)));
        ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
    }
    auto first_new = store.resolve_pairing_outcome(test_peer_id("server-new-1"));
    ASSERT_TRUE(store.store_record_superseding(first_new.record, {}));
    auto second_new = store.resolve_pairing_outcome(test_peer_id("server-new-2"));
    ASSERT_TRUE(store.store_record_superseding(second_new.record, {}));

    EXPECT_NE(store.record_by_server_id(test_peer_id("server-new-1")), nullptr)
        << "the record paired just before must survive the next pairing";
    // Control: the pairings evicted the two oldest records instead.
    EXPECT_EQ(store.record_by_server_id(test_peer_id("server-0")), nullptr);
    EXPECT_EQ(store.record_by_server_id(test_peer_id("server-1")), nullptr);
}

// A record backing a currently-open connection must never be evicted, even when it is the
// least recently used one.
TEST(RecordStore, EvictionSkipsRecordsBackingOpenConnections) {
    RecordStore store(nullptr);
    std::vector<std::string> psk_ids;
    for (size_t i = 0; i < RecordStore::DEFAULT_MAX_RECORDS; ++i) {
        auto outcome = store.resolve_pairing_outcome(test_peer_id("server-" + std::to_string(i)));
        psk_ids.push_back(outcome.record.psk_id);
        ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
    }

    auto overflow = store.resolve_pairing_outcome(test_peer_id("server-overflow"));
    ASSERT_TRUE(store.store_record_superseding(overflow.record, {psk_ids.front()}));

    EXPECT_NE(store.record_by_server_id(test_peer_id("server-0")), nullptr)
        << "the record an open connection resolves against must survive";
    EXPECT_EQ(store.record_by_server_id(test_peer_id("server-1")), nullptr)
        << "the next evictable record is taken instead";
}

// Fails closed only when every record at capacity backs an open connection. The
// connection budget makes this unreachable in the library (see ConnectionManager's static
// assertion), so the store is driven here directly.
TEST(RecordStore, NothingEvictableRejectsTheRecord) {
    RecordStore store(nullptr);
    std::vector<std::string> psk_ids;
    for (size_t i = 0; i < RecordStore::DEFAULT_MAX_RECORDS; ++i) {
        auto outcome = store.resolve_pairing_outcome(test_peer_id("server-" + std::to_string(i)));
        psk_ids.push_back(outcome.record.psk_id);
        ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
    }

    auto overflow = store.resolve_pairing_outcome(test_peer_id("server-overflow"));
    EXPECT_FALSE(store.store_record_superseding(overflow.record, psk_ids));
    EXPECT_EQ(store.record_by_server_id(test_peer_id("server-overflow")), nullptr);
    EXPECT_EQ(store.records_.size(), RecordStore::DEFAULT_MAX_RECORDS);
}

// A supersede that replaces the record already held for a given server_id does not grow the
// store, so it must succeed at capacity without evicting anything.
TEST(RecordStore, CapacitySupersedeAtCapacityEvictsNothing) {
    RecordStore store(nullptr);
    const std::string existing_server = test_peer_id("server-existing");

    auto outcome0 = store.resolve_pairing_outcome(existing_server);
    ASSERT_TRUE(store.store_record_superseding(outcome0.record, {}));
    const std::string first_psk_id = outcome0.record.psk_id;

    // Fill every remaining slot with other servers' records.
    std::vector<std::string> other_psk_ids;
    for (size_t i = 1; i < RecordStore::DEFAULT_MAX_RECORDS; ++i) {
        auto outcome = store.resolve_pairing_outcome(test_peer_id("server-" + std::to_string(i)));
        other_psk_ids.push_back(outcome.record.psk_id);
        ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
    }

    // records_ runs least-recently-used first, so without this the re-pairing server's own
    // record is the eviction victim and an eviction is indistinguishable from the supersede.
    (void) store.note_record_played(first_psk_id);

    auto outcome1 = store.resolve_pairing_outcome(existing_server);
    EXPECT_TRUE(store.store_record_superseding(outcome1.record, {}));

    // Every claim below is what a handshake sees: which psk_ids still authenticate, and as whom.
    EXPECT_FALSE(store.resolve_by_psk_id(first_psk_id, PskCategory::LONG_TERM).has_value())
        << "the superseded PSK must stop authenticating";
    auto resolved = store.resolve_by_psk_id(outcome1.record.psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(resolved.has_value());
    ASSERT_TRUE(resolved->counterparty_id.has_value());
    EXPECT_EQ(resolved->counterparty_id.value(), existing_server);
    for (const std::string& psk_id : other_psk_ids) {
        EXPECT_TRUE(store.resolve_by_psk_id(psk_id, PskCategory::LONG_TERM).has_value())
            << "no other server's record may be evicted by a supersede";
    }
}

// The effective cap: a caller-supplied max_records (wired from
// SendspinClientConfig::max_pairing_records) is honoured between the protocol's floor and the
// slot-numbering ceiling, and clamped to whichever it crosses. pairing.md "Pairing Records"
// requires room for at least 5 records.
TEST(RecordStore, ConfiguredCapacityIsHonouredAboveTheProtocolFloor) {
    struct Row {
        const char* name;
        size_t configured;
        size_t effective;
    };
    const Row rows[] = {
        {"above-the-floor", RecordStore::MIN_MAX_RECORDS + 1, RecordStore::MIN_MAX_RECORDS + 1},
        {"below-the-floor", 2, RecordStore::MIN_MAX_RECORDS},
        // The record-order blob names one slot per byte and 255 is the sentinel a record
        // awaiting a slot carries, so the highest usable slot is 254 and the cap is 255. Stated
        // as literals: written in terms of MAX_MAX_RECORDS the row moves with the constant it
        // exists to pin.
        {"above-the-ceiling", 300, 255},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        // A real provider so the ceiling row also exercises the persistence edge it defines:
        // slot 254 and an order blob of 255 bytes.
        InMemoryPersistenceProvider provider;
        RecordStore store(&provider, {.max_pairing_records = row.configured});

        std::vector<std::string> psk_ids;
        for (size_t i = 0; i < row.effective; ++i) {
            auto outcome = store.resolve_pairing_outcome(test_peer_id("server-" + std::to_string(i)));
            psk_ids.push_back(outcome.record.psk_id);
            ASSERT_TRUE(store.store_record_superseding(outcome.record, {}));
        }
        ASSERT_TRUE(store.persist_records());
        EXPECT_TRUE(store.resolve_by_psk_id(psk_ids.front(), PskCategory::LONG_TERM).has_value())
            << "nothing may be evicted before the effective cap is reached";
        EXPECT_EQ(persisted_psk_ids(provider, row.effective).size(), row.effective)
            << "every slot up to the cap must persist";
        ASSERT_TRUE(stored_record_in_slot(provider, row.effective - 1).has_value())
            << "the highest slot the cap allows must be usable and persisted";
        EXPECT_EQ(stored_record_in_slot(provider, row.effective - 1)->psk_id, psk_ids.back())
            << "the last record stored must be the one in the highest slot";

        auto overflow = store.resolve_pairing_outcome(test_peer_id("server-overflow"));
        ASSERT_TRUE(store.store_record_superseding(overflow.record, {}));
        ASSERT_TRUE(store.persist_records());
        EXPECT_FALSE(store.resolve_by_psk_id(psk_ids.front(), PskCategory::LONG_TERM).has_value())
            << "the effective cap still bounds the store, so the oldest record goes";
        EXPECT_TRUE(store.resolve_by_psk_id(psk_ids[1], PskCategory::LONG_TERM).has_value())
            << "exactly one record may be evicted";
        EXPECT_EQ(persisted_psk_ids(provider, row.effective).size(), row.effective)
            << "the evicted record's slot must be reused, not added to";
    }
}

// ============================================================================
// resolve_by_psk_id: the declared category selects the candidate set
// ============================================================================

// Each category resolves its own PSK, and the resolved value carries that category's secret
// and counterparty (connection.md "Pre-Shared Key"): a long-term record answers with the
// server it was paired to, while the Pairing and Sentinel PSKs are bound to no server.
TEST(RecordStore, ResolveByPskIdReturnsTheCategorysPskAndCounterparty) {
    InMemoryPersistenceProvider provider;
    SendspinPairingPsk pairing = make_pairing_psk();
    provider.seed_blob(persistence_keys::PAIRING_PSK, blob_bytes(encode_pairing_psk(pairing)));
    RecordStore store(&provider);

    SendspinPairingRecord rec = make_client_record("server-X");
    ASSERT_TRUE(store.store_record_superseding(rec, {}));

    struct Row {
        const char* name;
        std::string psk_id;
        PskCategory category;
        std::array<uint8_t, NOISE_PSK_SIZE> psk;
        std::optional<std::string> counterparty;
    };
    const Row rows[] = {
        {"long-term-record", rec.psk_id, PskCategory::LONG_TERM, rec.psk, rec.server_id},
        {"pairing-psk", pairing.psk_id, PskCategory::PAIRING, pairing.psk, std::nullopt},
        // The Sentinel PSK is a constant, so it resolves on a store that has never been
        // provisioned as well as on this one.
        {"sentinel-psk", std::string(SENTINEL_PSK_ID), PskCategory::SENTINEL, SENTINEL_PSK,
         std::nullopt},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        auto resolved = store.resolve_by_psk_id(row.psk_id, row.category);
        ASSERT_TRUE(resolved.has_value());
        EXPECT_EQ(resolved->category, row.category);
        EXPECT_EQ(resolved->psk_id, row.psk_id);
        EXPECT_EQ(resolved->psk, row.psk);
        EXPECT_EQ(resolved->counterparty_id, row.counterparty);
    }
}

// One psk_id held under two categories resolves to whichever the server declared: there is no
// precedence between the candidate sets (connection.md "Pre-Shared Key").
TEST(RecordStore, DeclaredCategoryPicksBetweenTwoPsksWithTheSamePskId) {
    InMemoryPersistenceProvider provider;

    // Build a record and a pairing PSK that share the same psk_id (and PSK bytes).
    SendspinPairingRecord rec = make_client_record("server-X");
    SendspinPairingPsk p;
    p.psk_id = rec.psk_id;
    p.psk = rec.psk;
    provider.seed_blob(persistence_keys::PAIRING_PSK, blob_bytes(encode_pairing_psk(p)));

    RecordStore store(&provider);
    store.store_record_superseding(rec, {});

    auto as_long_term = store.resolve_by_psk_id(rec.psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(as_long_term.has_value());
    EXPECT_EQ(as_long_term->category, PskCategory::LONG_TERM);
    EXPECT_EQ(as_long_term->counterparty_id, rec.server_id);

    auto as_pairing = store.resolve_by_psk_id(rec.psk_id, PskCategory::PAIRING);
    ASSERT_TRUE(as_pairing.has_value());
    EXPECT_EQ(as_pairing->category, PskCategory::PAIRING);
    EXPECT_FALSE(as_pairing->counterparty_id.has_value());
}

// A psk_id the client holds only under another category is a lookup miss, not a match
// (connection.md "Pre-Shared Key"). Each case pairs with the resolution that does succeed, so a
// resolver that simply stopped finding anything would not pass.
TEST(RecordStore, ResolveMissesAPskIdHeldUnderAnotherCategory) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord rec = make_client_record("server-X");
    store.store_record_superseding(rec, {});
    ASSERT_TRUE(store.pairing_psk().has_value());
    const std::string pairing_psk_id = store.pairing_psk()->psk_id;

    EXPECT_FALSE(store.resolve_by_psk_id(rec.psk_id, PskCategory::PAIRING).has_value())
        << "a long-term record must not answer a pairing-category lookup";
    EXPECT_FALSE(store.resolve_by_psk_id(rec.psk_id, PskCategory::SENTINEL).has_value());
    EXPECT_TRUE(store.resolve_by_psk_id(rec.psk_id, PskCategory::LONG_TERM).has_value());

    EXPECT_FALSE(store.resolve_by_psk_id(pairing_psk_id, PskCategory::LONG_TERM).has_value())
        << "the Pairing PSK must not answer a long-term lookup";
    EXPECT_TRUE(store.resolve_by_psk_id(pairing_psk_id, PskCategory::PAIRING).has_value());

    EXPECT_FALSE(store.resolve_by_psk_id(SENTINEL_PSK_ID, PskCategory::LONG_TERM).has_value())
        << "the Sentinel PSK must not answer a long-term lookup";
    EXPECT_TRUE(store.resolve_by_psk_id(SENTINEL_PSK_ID, PskCategory::SENTINEL).has_value());
}

// The three wire codes, and nothing else (messaging.md "noise/handshake").
TEST(RecordStore, PskCategoryFromStringAcceptsOnlyTheThreeCodes) {
    EXPECT_EQ(psk_category_from_string("lt"), PskCategory::LONG_TERM);
    EXPECT_EQ(psk_category_from_string("pr"), PskCategory::PAIRING);
    EXPECT_EQ(psk_category_from_string("sn"), PskCategory::SENTINEL);
    EXPECT_FALSE(psk_category_from_string("").has_value());
    EXPECT_FALSE(psk_category_from_string("LT").has_value());
    EXPECT_FALSE(psk_category_from_string("long_term").has_value());
}

TEST(RecordStore, ResolveByPskIdUnknownReturnsNullopt) {
    RecordStore store(nullptr);

    auto resolved = store.resolve_by_psk_id("nope-not-a-real-psk-id", PskCategory::LONG_TERM);
    EXPECT_FALSE(resolved.has_value());
}

// ============================================================================
// record_by_server_id
// ============================================================================

TEST(RecordStore, RecordByServerIdFindsStoredPubkeyRecord) {
    RecordStore store(nullptr);

    SendspinPairingRecord rec = make_client_record("server-X");
    store.store_record_superseding(rec, {});

    const auto* found = store.record_by_server_id(test_peer_id("server-X"));
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->psk_id, rec.psk_id);
    EXPECT_EQ(found->server_id, rec.server_id);

    // Unknown server returns null.
    EXPECT_EQ(store.record_by_server_id(test_peer_id("server-Y")), nullptr);
}

// ============================================================================
// note_record_played
// ============================================================================

// note_record_played()'s return is the persist trigger, so a true for a psk_id the store does not
// hold costs a provider write (an NVS erase cycle on ESP) for nothing.
TEST(RecordStore, NoteRecordPlayedOnAnAbsentPskIdIsNoOp) {
    RecordStore store(nullptr);
    SendspinPairingRecord present = make_client_record("server-A");
    ASSERT_TRUE(store.store_record_superseding(present, {}));
    ASSERT_TRUE(store.store_record_superseding(make_client_record("server-B"), {}));

    EXPECT_FALSE(store.note_record_played("does-not-exist"))
        << "an absent psk_id must not ask for a record write";
    // Control: a psk_id the store does hold, and that is not already the most recent, asks for one.
    EXPECT_TRUE(store.note_record_played(present.psk_id));
}

// ============================================================================
// note_record_removed and list
// ============================================================================

TEST(RecordStore, RemoveRecordAndList) {
    RecordStore store(nullptr);

    SendspinPairingRecord a = make_client_record("server-A");
    SendspinPairingRecord b = make_client_record("server-B");
    store.store_record_superseding(a, {});
    store.store_record_superseding(b, {});

    // Both records are now findable.
    EXPECT_NE(store.record_by_psk_id(a.psk_id), nullptr);
    EXPECT_NE(store.record_by_psk_id(b.psk_id), nullptr);

    remove_record(store, a.psk_id);
    EXPECT_EQ(store.record_by_psk_id(a.psk_id), nullptr);
    EXPECT_NE(store.record_by_psk_id(b.psk_id), nullptr);

    EXPECT_FALSE(store.note_record_removed("absent-psk-id"))
        << "an absent psk_id must not ask for a record write";
    // Control: a psk_id the store holds does.
    EXPECT_TRUE(store.note_record_removed(b.psk_id));
}

/// A persistence provider that accepts every record write EXCEPT one that drops the record a slot
/// currently holds, standing in for a store whose delete path fails on its own (full or
/// read-only NVS, a torn write) while writes that only add or refresh a record still work.
///
/// Dropping a record is either a zeroed blob over an occupied slot (a revocation) or a different
/// psk_id written into it (a supersede reusing the slot it just freed), so the fake reads the
/// slot it is about to overwrite to decide.
class RejectingDeleteProvider : public InMemoryPersistenceProvider {
public:
    bool save_blob(const std::string& key, const uint8_t* data, size_t len) override {
        if (is_record_key(key) && key != persistence_keys::RECORD_ORDER) {
            auto previous = this->blob(key);
            auto held = previous.has_value()
                            ? decode_pairing_record(previous->data(), previous->size())
                            : std::nullopt;
            if (held.has_value()) {
                auto incoming = decode_pairing_record(data, len);
                if (!incoming.has_value() || incoming->psk_id != held->psk_id) {
                    this->remove_attempts.push_back(held->psk_id);
                    if (this->refuse_delete) {
                        return false;  // Reject the write; the slot stays as it was.
                    }
                }
            }
        }
        return InMemoryPersistenceProvider::save_blob(key, data, len);
    }

    bool refuse_delete{true};
    std::vector<std::string> remove_attempts{};
};

// A delete the provider refuses must still revoke the credential for the current boot: leaving
// it in RAM because the store could not be written would keep it usable right now, which is
// strictly worse than a revocation that only fails to outlive a reboot. The provider is asked
// exactly once either way, and the flush's return value is how the caller learns whether the
// revocation is durable.
TEST(RecordStore, RemoveRecordErasesFromMemoryAndReportsWhetherTheDeleteIsDurable) {
    struct Row {
        const char* name;
        bool refuse_delete;
        bool expect_durable;
    };
    const Row rows[] = {
        {"provider-refuses-the-delete", true, false},
        // Control: an accepted delete is durable, which is what pins the direction of the row
        // above.
        {"provider-accepts-the-delete", false, true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        RejectingDeleteProvider provider;
        provider.refuse_delete = row.refuse_delete;
        RecordStore store(&provider);

        SendspinPairingRecord a = make_client_record("server-A");
        ASSERT_TRUE(store.store_record_superseding(a, {}));
        ASSERT_TRUE(store.persist_records());
        ASSERT_NE(store.record_by_psk_id(a.psk_id), nullptr);

        EXPECT_EQ(remove_record(store, a.psk_id), row.expect_durable);
        EXPECT_EQ(store.record_by_psk_id(a.psk_id), nullptr)
            << "a refused delete must not leave the revoked credential resolvable this boot";
        EXPECT_FALSE(store.resolve_by_psk_id(a.psk_id, PskCategory::LONG_TERM).has_value());
        ASSERT_EQ(provider.remove_attempts.size(), 1u);
        EXPECT_EQ(provider.remove_attempts[0], a.psk_id);
    }
}

// Same contract on the pairing/supersede path, which persists through the deferred
// persist_records() flush rather than inside the supersede itself: the prior record leaves RAM
// immediately (revoked for this boot no matter what the provider later says), and a flush the
// provider refuses is reported at flush time.
TEST(RecordStore, SupersedeErasesFromMemoryAndTheFlushFailsWhenTheProviderRefusesTheDelete) {
    RejectingDeleteProvider provider;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X");
    ASSERT_TRUE(store.store_record_superseding(original, {}));
    ASSERT_TRUE(store.persist_records());

    SendspinPairingRecord replacement = make_client_record("server-X");
    ASSERT_TRUE(store.store_record_superseding(replacement, {}));

    // The RAM effect precedes any provider traffic: the supersede itself asked for nothing.
    EXPECT_EQ(store.record_by_psk_id(original.psk_id), nullptr);
    EXPECT_FALSE(store.resolve_by_psk_id(original.psk_id, PskCategory::LONG_TERM).has_value());
    EXPECT_NE(store.record_by_psk_id(replacement.psk_id), nullptr);
    EXPECT_TRUE(provider.remove_attempts.empty())
        << "store_record_superseding must not call the provider";

    EXPECT_FALSE(store.persist_records());
    ASSERT_EQ(provider.remove_attempts.size(), 1u);
    EXPECT_EQ(provider.remove_attempts[0], original.psk_id);
}

// A supersede whose flush the store accepted is durable: the prior record is really gone from
// the provider, so it does not come back on the next start. Control for the refused case above.
TEST(RecordStore, SupersedeIsDurableWhenTheProviderAcceptsTheFlush) {
    RejectingDeleteProvider provider;
    provider.refuse_delete = false;
    RecordStore store(&provider);

    SendspinPairingRecord original = make_client_record("server-X");
    ASSERT_TRUE(store.store_record_superseding(original, {}));
    ASSERT_TRUE(store.persist_records());

    SendspinPairingRecord replacement = make_client_record("server-X");
    ASSERT_TRUE(store.store_record_superseding(replacement, {}));
    ASSERT_TRUE(store.persist_records());

    RecordStore rebooted(&provider);
    EXPECT_FALSE(rebooted.resolve_by_psk_id(original.psk_id, PskCategory::LONG_TERM).has_value());
    EXPECT_TRUE(rebooted.resolve_by_psk_id(replacement.psk_id, PskCategory::LONG_TERM).has_value());
}

// The refused delete is exactly the durability hole the bool return exists to surface: the
// record the store kept comes back on the next start, and resolves as LONG_TERM trust again.
TEST(RecordStore, RefusedDeleteLetsTheRevokedRecordReturnAfterAReboot) {
    RejectingDeleteProvider provider;

    SendspinPairingRecord a = make_client_record("server-A");
    {
        RecordStore store(&provider);
        ASSERT_TRUE(store.store_record_superseding(a, {}));
        ASSERT_TRUE(store.persist_records());
        remove_record(store, a.psk_id);
        ASSERT_EQ(store.record_by_psk_id(a.psk_id), nullptr);
    }

    // Reboot: a new store over the same provider reloads what the provider still holds.
    RecordStore rebooted(&provider);
    auto resolved = rebooted.resolve_by_psk_id(a.psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(resolved.has_value())
        << "the provider kept the record, so it must come back: this is what the false return "
           "from a rejected record save warns about";
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
}

// ============================================================================
// Pairing PSK lifecycle
// ============================================================================

// Where the Pairing PSK comes from: SendspinClientConfig::pairing_psk outranks a stored one, which
// is then neither read nor written; with none configured the stored one is used; with neither, one
// is generated and persisted (pairing.md "Pairing PSK Flow"). A stored key any peer could hold
// (all zero, or the published Sentinel PSK) counts as none stored. Whatever the source, the store
// derives its psk_id and resolves it as the PAIRING category.
TEST(RecordStore, PairingPskSourcePrecedence) {
    enum class Stored : uint8_t { NONE, RANDOM, ALL_ZERO, SENTINEL };
    enum class Source : uint8_t { CONFIGURED, STORED, GENERATED };
    struct Row {
        const char* name;
        Stored stored;
        bool configured;
        Source expect;
    };
    const Row rows[] = {
        {"configured beside a stored one", Stored::RANDOM, true, Source::CONFIGURED},
        {"configured with nothing stored", Stored::NONE, true, Source::CONFIGURED},
        {"Control: stored with nothing configured", Stored::RANDOM, false, Source::STORED},
        {"neither", Stored::NONE, false, Source::GENERATED},
        {"stored all zero", Stored::ALL_ZERO, false, Source::GENERATED},
        {"stored Sentinel PSK", Stored::SENTINEL, false, Source::GENERATED},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinPairingPsk stored = make_pairing_psk();
        if (row.stored == Stored::ALL_ZERO) {
            stored.psk.fill(0);
        } else if (row.stored == Stored::SENTINEL) {
            stored.psk = SENTINEL_PSK;
        }
        stored.psk_id = psk_id_for(stored.psk);
        const SendspinPsk configured(make_random_psk());
        InMemoryPersistenceProvider provider;
        if (row.stored != Stored::NONE) {
            provider.seed_blob(persistence_keys::PAIRING_PSK,
                               blob_bytes(encode_pairing_psk(stored)));
        }
        const auto stored_blob = provider.blob(persistence_keys::PAIRING_PSK);

        SendspinClientConfig config;
        if (row.configured) {
            config.pairing_psk = configured;
        }
        RecordStore store(&provider, config);

        ASSERT_TRUE(store.pairing_psk().has_value());
        const std::array<uint8_t, NOISE_PSK_SIZE> held = store.pairing_psk()->psk;
        EXPECT_EQ(store.pairing_psk()->psk_id, psk_id_for(held));
        auto resolved = store.resolve_by_psk_id(psk_id_for(held), PskCategory::PAIRING);
        ASSERT_TRUE(resolved.has_value());
        EXPECT_EQ(resolved->psk, held);

        switch (row.expect) {
            case Source::CONFIGURED:
                EXPECT_EQ(held, configured.bytes);
                EXPECT_EQ(provider.save_attempts(persistence_keys::PAIRING_PSK), 0)
                    << "a configured Pairing PSK must never reach the provider";
                // Read on the fake: an unread stored blob and a read-then-outranked one leave
                // the same observable store, so only the call itself tells them apart.
                EXPECT_EQ(provider.load_attempts(persistence_keys::PAIRING_PSK), 0)
                    << "a configured Pairing PSK makes the stored one irrelevant";
                EXPECT_EQ(provider.blob(persistence_keys::PAIRING_PSK), stored_blob)
                    << "a stored Pairing PSK the configured one outranks is left as it was";
                EXPECT_FALSE(
                    store.resolve_by_psk_id(stored.psk_id, PskCategory::PAIRING).has_value())
                    << "the outranked stored Pairing PSK must not resolve";
                break;
            case Source::STORED:
                EXPECT_EQ(held, stored.psk);
                EXPECT_EQ(provider.save_attempts(persistence_keys::PAIRING_PSK), 0);
                break;
            case Source::GENERATED: {
                if (row.stored != Stored::NONE) {
                    EXPECT_NE(held, stored.psk) << "an unusable stored Pairing PSK must not load";
                }
                EXPECT_EQ(provider.save_attempts(persistence_keys::PAIRING_PSK), 1);
                auto persisted = provider.blob(persistence_keys::PAIRING_PSK);
                ASSERT_TRUE(persisted.has_value()) << "a generated Pairing PSK must be persisted";
                auto decoded = decode_pairing_psk(persisted->data(), persisted->size());
                ASSERT_TRUE(decoded.has_value());
                EXPECT_EQ(decoded->psk, held);
                break;
            }
        }
    }
}

// ============================================================================
// Keypair persistence across "reboots" via FilePersistenceProvider
// ============================================================================

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

// The keypair is the device's identity: a provider that queues its writes must be told to make
// it durable before start() returns, or a power cut gives the next boot a different client_id.
TEST(SendspinClientIdentity, GeneratedKeypairIsCommitted) {
    InMemoryPersistenceProvider provider;
    SendspinClientConfig config;
    config.name = "keypair-commit-test";
    SendspinClient client(std::move(config));
    client.set_persistence_provider(&provider);
    ASSERT_TRUE(client.start());

    // Control: the keypair was written, so an empty uncommitted list is not an absent write.
    ASSERT_EQ(provider.save_attempts(persistence_keys::KEYPAIR), 1);
    EXPECT_TRUE(provider.uncommitted_keys().empty())
        << "the generated keypair was left queued when start() returned";
}

TEST(FilePersistenceProvider, PairingRecordRoundTrip) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    SendspinPairingRecord rec = make_client_record("server-X");
    const std::vector<uint8_t> encoded = record_blob(rec);
    EXPECT_TRUE(
        provider.save_blob(persistence_keys::record_slot_key(0), encoded.data(), encoded.size()));

    auto decoded = stored_record_in_slot(provider, 0);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->psk_id, rec.psk_id);
    EXPECT_EQ(decoded->psk, rec.psk);
    EXPECT_EQ(decoded->server_id, rec.server_id);
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

// The persistence file holds plaintext secrets (static private key, long-term PSKs, Pairing PSK),
// so it must never be group/world readable regardless of the process umask. This is host-only
// POSIX, matching how examples/common/file_persistence_provider.cpp itself creates the file.
TEST(FilePersistenceProvider, PersistedFileIsOwnerOnly) {
    TempFile tmp;
    FilePersistenceProvider provider(tmp.path());

    std::string server_id = "server-id-abc";
    EXPECT_TRUE(provider.save_blob(persistence_keys::LAST_PLAYED,
                                   reinterpret_cast<const uint8_t*>(server_id.data()),
                                   server_id.size()));

    struct stat st{};
    ASSERT_EQ(::stat(tmp.path().c_str(), &st), 0);
    char mode_str[8];
    std::snprintf(mode_str, sizeof(mode_str), "%04o", st.st_mode & 07777);
    EXPECT_EQ(st.st_mode & 07777, static_cast<unsigned int>(0600))
        << "persisted file must be owner-read/write only, got mode " << mode_str;
}

// ============================================================================
// RecordStore with FilePersistenceProvider: first-boot provisioning persists
// ============================================================================

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

// A removed record must not merely vanish from RAM: its stored slot must be emptied, so a reboot
// does not resurrect it. Exercised at the RecordStore level, where removal is actually
// implemented, rather than against the provider, which is a pure byte store.
TEST(RecordStoreWithFile, RemoveRecordEmptiesThePersistedSlot) {
    TempFile tmp;
    std::string a_psk_id;
    std::string b_psk_id;
    {
        FilePersistenceProvider provider(tmp.path());
        RecordStore store(&provider);
        SendspinPairingRecord a = make_client_record("server-A");
        SendspinPairingRecord b = make_client_record("server-B");
        ASSERT_TRUE(store.store_record_superseding(a, {}));
        ASSERT_TRUE(store.store_record_superseding(b, {}));
        ASSERT_TRUE(store.persist_records());
        a_psk_id = a.psk_id;
        b_psk_id = b.psk_id;
        remove_record(store, a_psk_id);
    }

    FilePersistenceProvider provider(tmp.path());
    auto decoded = persisted_records(provider);
    bool found_a = false;
    bool found_b = false;
    for (const auto& r : decoded) {
        if (r.psk_id == a_psk_id) {
            found_a = true;
        }
        if (r.psk_id == b_psk_id) {
            found_b = true;
        }
    }
    EXPECT_FALSE(found_a) << "a removed record must not survive in its persisted slot";
    EXPECT_TRUE(found_b);
}

// ============================================================================
// resolve_pairing_outcome: normal and storage-exhausted paths
// ============================================================================

// Normal case: storage is available -> returns {psk, record=set}.
// The record must be bound to the given server_id and carry a psk_id matching the PSK.
TEST(RecordStore, ResolvePairingOutcomeNormal) {
    RecordStore store(nullptr);

    const std::string server_id = test_peer_id("server-pair-test");
    auto outcome = store.resolve_pairing_outcome(server_id);

    // PSK must be non-zero (randomly generated).
    bool all_zero = true;
    for (auto b : outcome.psk) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "generated PSK should not be all-zero";

    // The record's server_id must match what was passed in.
    EXPECT_EQ(outcome.record.server_id, server_id);

    // psk_id must be set and match the PSK.
    EXPECT_EQ(outcome.psk, outcome.record.psk);
    EXPECT_EQ(outcome.record.psk_id, psk_id_for(outcome.psk));
}

// A full store still mints: a pairing never fails for lack of record storage
// (pairing.md "Pairing Records"), and room is made where the record is stored.
TEST(RecordStore, ResolvePairingOutcomeMintsOnAFullStore) {
    RecordStore store(nullptr, {.max_pairing_records = RecordStore::MIN_MAX_RECORDS});
    for (size_t i = 0; i < RecordStore::MIN_MAX_RECORDS; ++i) {
        ASSERT_TRUE(
            store.store_record_superseding(make_client_record("server-" + std::to_string(i)), {}));
    }

    auto outcome = store.resolve_pairing_outcome(test_peer_id("server-new"));

    EXPECT_EQ(outcome.record.server_id, test_peer_id("server-new"));
    EXPECT_EQ(outcome.record.psk_id, psk_id_for(outcome.psk));
    EXPECT_EQ(store.record_by_server_id(test_peer_id("server-new")), nullptr)
        << "minting alone stores nothing";
}

// store_record after resolve_pairing_outcome (simulates the server/pair-finalize ack path).
// After storing, the record must be resolvable by psk_id and bound to the server.
TEST(RecordStore, ResolvePairingOutcomeThenStore) {
    RecordStore store(nullptr);

    const std::string server_id = test_peer_id("server-store-after");
    auto outcome = store.resolve_pairing_outcome(server_id);

    // Simulate the ack path: store the pending record.
    store.store_record_superseding(outcome.record, {});

    const auto* stored = store.record_by_server_id(server_id);
    ASSERT_NE(stored, nullptr) << "record must be retrievable by server_id after store";
    EXPECT_EQ(stored->psk_id, outcome.record.psk_id);
    EXPECT_EQ(stored->psk, outcome.psk);

    auto resolved = store.resolve_by_psk_id(stored->psk_id, PskCategory::LONG_TERM);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->category, PskCategory::LONG_TERM);
}

// ============================================================================
// Player output delay: round-trip via persistence_keys::OUTPUT_DELAY
// ============================================================================

// update_output_delay() persists the delay as a native uint16_t, per persistence_keys::OUTPUT_DELAY,
// and a fresh player over the same provider loads it back.
TEST(PlayerRoleOutputDelay, PersistsAsANativeUint16) {
    InMemoryPersistenceProvider provider;
    SendspinClientConfig config;
    config.name = "output-delay-round-trip-test";
    SendspinClient client(std::move(config));
    client.set_persistence_provider(&provider);

    PlayerRoleConfig player_config;
    player_config.audio_formats = {{SendspinCodecFormat::FLAC, 2, 44100, 16}};
    auto& player = client.add_player(player_config);
    ASSERT_TRUE(client.start());
    player.set_output_delay_adjustable(true);
    player.update_output_delay(1234);

    auto blob = provider.blob(persistence_keys::OUTPUT_DELAY);
    ASSERT_TRUE(blob.has_value());
    ASSERT_EQ(blob->size(), persistence_keys::OUTPUT_DELAY_SIZE);
    uint16_t stored = 0;
    std::memcpy(&stored, blob->data(), sizeof(stored));
    EXPECT_EQ(stored, 1234u);

    // And it must load back correctly on a fresh PlayerRole over the same provider.
    SendspinClientConfig config2;
    config2.name = "output-delay-round-trip-test-2";
    SendspinClient client2(std::move(config2));
    client2.set_persistence_provider(&provider);
    PlayerRoleConfig player_config2;
    player_config2.audio_formats = {{SendspinCodecFormat::FLAC, 2, 44100, 16}};
    auto& player2 = client2.add_player(player_config2);
    ASSERT_TRUE(client2.start());
    player2.set_output_delay_adjustable(true);
    EXPECT_EQ(player2.get_output_delay_ms(), 1234u);
}

// A persisted output_delay blob of the wrong size (corrupt bytes) must be treated as though
// nothing were saved, falling back to PlayerRoleConfig::initial_output_delay_ms rather than
// reinterpreting garbage as a number.
TEST(PlayerRoleOutputDelay, InvalidPersistedValueIsTreatedAsAbsent) {
    InMemoryPersistenceProvider provider;
    provider.seed_blob(persistence_keys::OUTPUT_DELAY, blob_bytes("not-a-number"));

    SendspinClientConfig config;
    config.name = "output-delay-invalid-test";
    SendspinClient client(std::move(config));
    client.set_persistence_provider(&provider);

    PlayerRoleConfig player_config;
    player_config.audio_formats = {{SendspinCodecFormat::FLAC, 2, 44100, 16}};
    player_config.initial_output_delay_ms = 77;
    auto& player = client.add_player(player_config);
    ASSERT_TRUE(client.start());
    player.set_output_delay_adjustable(true);

    EXPECT_EQ(player.get_output_delay_ms(), 77u)
        << "a wrong-size output_delay blob must be treated as absent, falling back to "
           "initial_output_delay_ms";
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

// start() fails closed on a configured pairing secret it cannot use: a Pairing PSK any peer could
// hold (all zero, as from a factory partition never written, or the published Sentinel PSK) would
// admit every server as a pairing peer, and a static pairing code that is not 8 decimal digits
// (pairing.md "Static Pairing Code Flow") would fail every attempt.
TEST(SendspinClientStart, RejectsUnusableConfiguredPairingSecrets) {
    struct Row {
        const char* name;
        std::optional<std::array<uint8_t, NOISE_PSK_SIZE>> psk;
        std::optional<std::string> static_code;
        bool expect_started;
    };
    const Row rows[] = {
        {"all-zero Pairing PSK", std::array<uint8_t, NOISE_PSK_SIZE>{}, std::nullopt, false},
        {"Sentinel PSK as the Pairing PSK", SENTINEL_PSK, std::nullopt, false},
        {"Control: a random Pairing PSK", make_random_psk(), std::nullopt, true},
        {"static code one digit short", std::nullopt, "1357246", false},
        {"static code with a non-digit", std::nullopt, "1357246x", false},
        {"Control: a valid static code", std::nullopt, "13572468", true},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        InMemoryPersistenceProvider provider;
        SendspinClientConfig config;
        config.name = "configured-pairing-secret-validation";
        if (row.psk.has_value()) {
            config.pairing_psk = SendspinPsk(row.psk.value());
        }
        config.static_pairing_code = row.static_code;
        SendspinClient client(std::move(config));
        client.set_persistence_provider(&provider);

        EXPECT_EQ(client.start(), row.expect_started);
        EXPECT_EQ(client.is_started(), row.expect_started);
        if (!row.expect_started) {
            // Refused before anything is built, so nothing reached the provider.
            for (const char* key : {persistence_keys::KEYPAIR, persistence_keys::PAIRING_PSK}) {
                EXPECT_EQ(provider.save_attempts(key), 0) << key;
            }
            EXPECT_FALSE(client.start()) << "the config is fixed, so a retry is refused too";
        }
        client.stop();
    }
}

// start() hands SendspinClientConfig::pairing_psk to the store, so the pairing token the operator
// is shown carries the configured key rather than the one the provider holds.
TEST(SendspinClientIdentity, PairingTokenCarriesTheConfiguredPairingPsk) {
    const SendspinPairingPsk stored = make_pairing_psk();
    const std::array<uint8_t, NOISE_PSK_SIZE> configured = make_random_psk();

    for (bool configure : {true, false}) {
        SCOPED_TRACE(configure ? "configured" : "Control: stored only");
        InMemoryPersistenceProvider provider;
        provider.seed_blob(persistence_keys::PAIRING_PSK, blob_bytes(encode_pairing_psk(stored)));

        SendspinClientConfig config;
        config.name = "configured-pairing-psk-token";
        if (configure) {
            config.pairing_psk = SendspinPsk(configured);
        }
        SendspinClient client(std::move(config));
        client.set_persistence_provider(&provider);
        ASSERT_TRUE(client.start());

        const auto expected = client.format_pairing_token(configure ? configured : stored.psk);
        ASSERT_TRUE(expected.has_value());
        EXPECT_EQ(client.pairing_token(), expected);
        client.stop();
    }
}

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

template <typename T, auto Field = &T::psk> void expect_psk_wiped_on_destruction() {
    alignas(T) unsigned char storage[sizeof(T)];
    T* obj = new (storage) T();
    (obj->*Field).fill(0xA5u);
    // Take the address before destruction; afterwards only the raw bytes may be read.
    const unsigned char* psk_bytes = reinterpret_cast<const unsigned char*>((obj->*Field).data());
    const size_t psk_len = (obj->*Field).size();
    obj->~T();
    for (size_t i = 0; i < psk_len; ++i) {
        ASSERT_EQ(psk_bytes[i], 0u) << "psk byte " << i << " survived destruction";
    }
}

}  // namespace

// Every struct that holds a PSK wipes it on destruction. One rule, one row per struct that
// carries one.
TEST(PskZeroization, EveryPskCarryingStructWipesOnDestruction) {
    {
        SCOPED_TRACE("SendspinPairingRecord");
        expect_psk_wiped_on_destruction<SendspinPairingRecord>();
    }
    {
        SCOPED_TRACE("SendspinPairingPsk");
        expect_psk_wiped_on_destruction<SendspinPairingPsk>();
    }
    {
        SCOPED_TRACE("SendspinPsk");
        expect_psk_wiped_on_destruction<SendspinPsk, &SendspinPsk::bytes>();
    }
    {
        SCOPED_TRACE("ResolvedPsk");
        expect_psk_wiped_on_destruction<ResolvedPsk>();
    }
    {
        SCOPED_TRACE("RecordStore::PairingOutcome");
        expect_psk_wiped_on_destruction<RecordStore::PairingOutcome>();
    }
}

// Reproduces the two-thread access pattern production runs over records_:
//
//   protocol task -> Noise handshake
//                       -> RecordStore::resolve_by_psk_id()        [reads records_]
//   main loop     -> an unpair, a playback recency move, a pairing-code commit
//                       -> mutators that push_back/erase/reorder records_
//
// The resolve and the pair-finalize commit (store_record_superseding()) both run on the protocol
// task, so they never overlap; the concurrency left is a protocol-task resolve against a
// main-loop mutator, and nothing above RecordStore serializes the two. The writer thread below
// stands for that mutator, through store_record_superseding()'s push_back/erase. mutex_ is
// therefore the only thing keeping a resolve off the writer's push_back reallocation; under
// ThreadSanitizer (-DENABLE_TSAN=ON) dropping either lock_guard is reported against records_ and
// fails this test.
//
// Without TSan the assertions still bind: two records outside the writer's server_id space are
// stored up front, so every resolve of them must return that record's own psk no matter what
// the writer is doing to the rest of the array.
TEST(RecordStoreConcurrency, ResolveByPskIdDoesNotRaceRecordStores) {
    InMemoryPersistenceProvider provider;
    RecordStore store(&provider, {.max_pairing_records = 64});

    // Both threads work over an overlapping server_id space so the reader's scan and the
    // writer's supersede-erase touch the same entries.
    constexpr int SERVER_ID_SPACE = 8;
    constexpr int ITERATIONS = 2000;

    // Two records the writer never supersedes or evicts, each carrying its own psk pattern.
    SendspinPairingRecord anchor_a;
    anchor_a.psk_id = "psk-anchor-a";
    anchor_a.psk.fill(0xA1u);
    anchor_a.server_id = "server-anchor-a";
    ASSERT_TRUE(store.store_record_superseding(anchor_a, {}));
    SendspinPairingRecord anchor_b;
    anchor_b.psk_id = "psk-anchor-b";
    anchor_b.psk.fill(0xB2u);
    anchor_b.server_id = "server-anchor-b";
    ASSERT_TRUE(store.store_record_superseding(anchor_b, {}));

    std::atomic<bool> writer_ready{false};

    std::thread writer([&] {
        writer_ready.store(true, std::memory_order_release);
        for (int i = 0; i < ITERATIONS; ++i) {
            SendspinPairingRecord record;
            record.psk_id = "psk-" + std::to_string(i);
            record.psk.fill(static_cast<uint8_t>(i));
            record.server_id = "server-" + std::to_string(i % SERVER_ID_SPACE);
            store.store_record_superseding(std::move(record), {});
        }
    });

    while (!writer_ready.load(std::memory_order_acquire)) {
    }

    // Failures are counted rather than asserted in the loop: an ASSERT_* here would return
    // with the writer still joinable, and an EXPECT_* would print 2000 times.
    int anchor_misses = 0;
    int anchor_wrong_record = 0;
    int churned_wrong_record = 0;

    for (int i = 0; i < ITERATIONS; ++i) {
        auto anchored_a = store.resolve_by_psk_id("psk-anchor-a", PskCategory::LONG_TERM);
        auto anchored_b = store.resolve_by_psk_id("psk-anchor-b", PskCategory::LONG_TERM);
        if (!anchored_a.has_value() || !anchored_b.has_value()) {
            ++anchor_misses;
        } else if (anchored_a->psk[0] != 0xA1u || anchored_a->counterparty_id != "server-anchor-a" ||
                   anchored_b->psk[0] != 0xB2u || anchored_b->counterparty_id != "server-anchor-b") {
            ++anchor_wrong_record;
        }

        // The writer may not have reached this psk_id yet, and a later pairing for the same
        // server supersedes it, so a miss is legal; resolving it to another record is not.
        auto churned = store.resolve_by_psk_id("psk-" + std::to_string(i), PskCategory::LONG_TERM);
        if (churned.has_value() && churned->psk[0] != static_cast<uint8_t>(i)) {
            ++churned_wrong_record;
        }
    }

    writer.join();

    EXPECT_EQ(anchor_misses, 0) << "a record the writer never touches must stay resolvable";
    EXPECT_EQ(anchor_wrong_record, 0) << "a resolve must return the record it matched";
    EXPECT_EQ(churned_wrong_record, 0) << "a resolve must return the record it matched";
}

// The persisting paths must not hold mutex_ across the provider's blob write. resolve_by_psk_id()
// takes that same mutex on the protocol task for every Noise handshake, and on ESP the write is
// an NVS commit of tens of milliseconds; holding the lock across it stalls a handshake for the
// length of a flash commit (the post-pairing re-handshake is adjacent to such a write by
// construction, see docs/internals.md "Pairing").
//
// The provider below parks inside save_blob() until this test releases it, which is the whole of
// that commit window held open. A resolve issued in that window must still return: it is waited
// on with no timeout, so a regression hangs rather than turning a loaded runner into a failure,
// and the watchdog in tests/main.cpp names the test.
namespace {

class BlockingRecordsProvider : public SendspinPersistenceProvider {
public:
    bool save_blob(const std::string& key, const uint8_t* /*data*/, size_t /*len*/) override {
        if (!is_record_key(key)) {
            return true;  // Only a record write is under test; provisioning must not park.
        }
        std::unique_lock<std::mutex> lock(this->mutex_);
        this->entered_ = true;
        this->cv_.notify_all();
        this->cv_.wait(lock, [&] { return this->released_; });
        return true;
    }

    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(this->mutex_);
        this->cv_.wait(lock, [&] { return this->entered_; });
    }

    void release() {
        {
            std::lock_guard<std::mutex> lock(this->mutex_);
            this->released_ = true;
        }
        this->cv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    bool entered_{false};
    bool released_{false};
};

}  // namespace

TEST(RecordStoreConcurrency, ResolveRunsWhileARecordsWriteIsInFlight) {
    BlockingRecordsProvider provider;
    RecordStore store(&provider, {.max_pairing_records = 8});

    SendspinPairingRecord record = make_client_record("blocking-write-server");
    const std::string psk_id = record.psk_id;
    ASSERT_TRUE(store.store_record_superseding(std::move(record), {}));

    // The main loop's deferred flush of that RAM-only insert: the one call that reaches the
    // provider here.
    std::thread writer([&] { store.persist_records(); });
    // A flush that never reaches the provider hangs into the watchdog rather than being timed.
    provider.wait_until_entered();

    std::promise<bool> resolved;
    std::future<bool> resolved_future = resolved.get_future();
    std::thread probe([&] {
        resolved.set_value(store.resolve_by_psk_id(psk_id, PskCategory::LONG_TERM).has_value());
    });

    // Nothing is released until the resolve returns, so a resolve that waits out the write
    // hangs here.
    const bool found = resolved_future.get();
    probe.join();
    EXPECT_TRUE(found) << "the resolve returned, but missed the stored record";

    provider.release();
    writer.join();
}
