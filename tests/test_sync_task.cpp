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

// Lifecycle regression tests for SyncTask around the client's stop()/start() restart support.
// This translation unit is compiled with -fno-access-control (see tests/CMakeLists.txt) so the
// tests can stage the exact internal states the regressions arise from (a partially failed
// init(), a stop() landing mid-stream) without adding test seams to the production code.

#include "audio_types.h"
#include "inbox.h"
#include "player_role_impl.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sync_task.h"
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <thread>

using namespace sendspin;

namespace {

constexpr size_t RING_BUFFER_BYTES = 16 * 1024;

// A real, never-started SendspinClient plus a bound PlayerRole::Impl for SyncTask::init() to
// point at. The sync thread only dereferences them once a stream goes active; these tests keep
// the thread idle, so inert instances suffice. Static deques give them program lifetime and
// stable addresses (mirroring make_impl() in test_artwork_role.cpp).
PlayerRole::Impl* make_player_impl() {
    static std::deque<SendspinClient> clients;
    static std::deque<Inbox> inboxes;
    static std::deque<std::unique_ptr<PlayerRole::Impl>> impls;

    clients.emplace_back(SendspinClientConfig{});
    impls.emplace_back(
        std::make_unique<PlayerRole::Impl>(PlayerRoleConfig{}, &clients.back(), nullptr));
    inboxes.emplace_back();
    impls.back()->attach_inbox(inboxes.back());
    return impls.back().get();
}

}  // namespace

// A partially failed init() (event flags created, ring-buffer allocation failed) must not report
// initialized: PlayerRole::Impl::start() gates init() on !is_initialized(), so a stale true
// would make a retried start() skip init() and spawn a thread that dereferences the missing
// ring buffer.
TEST(SyncTaskLifecycle, PartialInitDoesNotReportInitialized) {
    auto* player = make_player_impl();
    SyncTask task;

    // Stage the post-partial-failure state directly: flags exist, ring buffer does not.
    ASSERT_TRUE(task.event_flags_.create());
    EXPECT_FALSE(task.is_initialized());

    // A retried init() succeeds from that state, and the thread starts and stops cleanly.
    ASSERT_TRUE(task.init(player, player->client, RING_BUFFER_BYTES));
    EXPECT_TRUE(task.is_initialized());
    ASSERT_TRUE(task.start(false, 0));
    EXPECT_TRUE(task.is_thread_running());
    task.stop();
    EXPECT_FALSE(task.is_thread_running());
}

// stop() must leave is_running() false even when it interrupts an active stream: the thread's
// COMMAND_STOP exit path skips the idle-state flag clear, so without an exit-path clear a stale
// TASK_RUNNING would wedge the player's sync-idle gate (a queued STREAM_END would never deliver
// its on_stream_end()).
TEST(SyncTaskLifecycle, IsRunningFalseAfterStopDuringActiveStream) {
    auto* player = make_player_impl();
    SyncTask task;
    ASSERT_TRUE(task.init(player, player->client, RING_BUFFER_BYTES));
    ASSERT_TRUE(task.start(false, 0));

    // start() returns only once the thread has passed the idle-state flag clear, so a bit set
    // here stays set until the thread exits -- the state a stop() landing mid-stream sees.
    task.event_flags_.set(EventGroupBits::TASK_RUNNING);
    ASSERT_TRUE(task.is_running());

    task.stop();
    EXPECT_FALSE(task.is_running());
}

// stop() discards whatever an interrupted session left in the ring buffer: the buffer survives
// a stop()/start() cycle (init() runs once), and a stale pre-stop codec header would otherwise
// be picked up by the restarted thread as the new stream's.
TEST(SyncTaskLifecycle, StopDrainsRingBuffer) {
    auto* player = make_player_impl();
    SyncTask task;
    ASSERT_TRUE(task.init(player, player->client, RING_BUFFER_BYTES));

    // Captured before start(), when nothing can be borrowed. chunks_waiting() alone cannot
    // detect a borrowed-but-never-returned entry (items leave that count at receive time, not
    // return time), so the free-byte check below is what catches a leaked borrow.
    const size_t initial_free_bytes = task.encoded_ring_buffer_->ring_buffer_.free_bytes_;

    ASSERT_TRUE(task.start(false, 0));

    // Queue header + audio + header, as a rapid seek interrupted by stop() would. The idle
    // thread may receive (and hold) the first header while waiting for the stream start that
    // never comes; everything behind it stays queued.
    const uint8_t bytes[4] = {1, 2, 3, 4};
    ASSERT_TRUE(task.encoded_ring_buffer_->write_chunk(bytes, sizeof(bytes), 0,
                                                       CHUNK_TYPE_PCM_DUMMY_HEADER, 100));
    ASSERT_TRUE(task.encoded_ring_buffer_->write_chunk(bytes, sizeof(bytes), 0,
                                                       CHUNK_TYPE_ENCODED_AUDIO, 100));
    ASSERT_TRUE(task.encoded_ring_buffer_->write_chunk(bytes, sizeof(bytes), 0,
                                                       CHUNK_TYPE_PCM_DUMMY_HEADER, 100));

    task.stop();
    EXPECT_EQ(task.encoded_ring_buffer_->chunks_waiting(), 0U);
    // Every entry, including one the thread had borrowed at stop time, was returned: the ring's
    // full capacity is available to the next session.
    EXPECT_EQ(task.encoded_ring_buffer_->ring_buffer_.free_bytes_, initial_free_bytes);
}

// request_stop() must signal the thread without joining it: the thread exits on its own within
// its idle poll interval and reports via has_thread_exited(), after which stop() joins without
// blocking. This is the primitive the client's asynchronous request_stop() is built on.
TEST(SyncTaskLifecycle, RequestStopSignalsWithoutJoin) {
    auto* player = make_player_impl();
    SyncTask task;
    ASSERT_TRUE(task.init(player, player->client, RING_BUFFER_BYTES));
    ASSERT_TRUE(task.start(false, 0));
    EXPECT_FALSE(task.has_thread_exited());

    task.request_stop();
    // The thread object is intentionally not joined by request_stop().
    EXPECT_TRUE(task.is_thread_running());

    // The idle poll observes the signal within IDLE_RECEIVE_TIMEOUT_MS (500 ms); allow margin.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!task.has_thread_exited() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(task.has_thread_exited());

    task.stop();
    EXPECT_FALSE(task.is_thread_running());
}
