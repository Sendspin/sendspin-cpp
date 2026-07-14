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

#include "artwork_role_impl.h"
#include "constants.h"
#include "protocol_messages.h"
#include "sendspin/client.h"
#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using namespace sendspin;

namespace {

// Appends val as 8 big-endian bytes (the server timestamp prefix of every artwork binary
// message), mirroring put_be64 in test_visualizer_role.cpp.
void put_be64(std::vector<uint8_t>& out, int64_t val) {
    auto u = static_cast<uint64_t>(val);
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xFF));
    }
}

// Negative-wait window: long enough to be safely past the decode thread's 100ms parked-slot
// sweep fallback (see DRAIN_RECEIVE_TIMEOUT_MS in artwork_role.cpp), short enough to keep the
// suite fast.
constexpr auto NEGATIVE_WINDOW = std::chrono::milliseconds(300);
constexpr auto POSITIVE_TIMEOUT = std::chrono::milliseconds(1500);

// Records every callback fired by an ArtworkRole::Impl under test, guarded by its own mutex so
// the test thread can safely poll state produced on the decode thread and the main thread. If
// frame_done_on_display is set, on_image_display() immediately (and reentrantly) calls
// frame_done() on the Impl this listener was bound to, exercising the reentrant-ack path.
class RecordingListener : public ArtworkRoleListener {
public:
    struct DecodeEvent {
        uint8_t slot;
        std::vector<uint8_t> payload;
    };

    void on_image_decode(uint8_t slot, const uint8_t* data, size_t length,
                         SendspinImageFormat /*format*/) override {
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->decodes.push_back({slot, std::vector<uint8_t>(data, data + length)});
        }
        this->cv.notify_all();
    }

    void on_image_display(uint8_t slot) override {
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->displays.push_back(slot);
        }
        this->cv.notify_all();
        // Deliberately outside the lock above: frame_done() takes the Impl's own slot_mutex, and
        // this call must not be made while holding this listener's mutex (which nothing else
        // needs, but keeping the pattern lock-then-release-then-reenter is the safe shape the
        // production code itself uses -- see drain_events()/handle_stream_ring_event()).
        if (this->frame_done_on_display && this->impl != nullptr) {
            this->impl->frame_done(slot);
        }
    }

    void on_image_clear(uint8_t slot) override {
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->clears.push_back(slot);
        }
        this->cv.notify_all();
    }

    // Waits (up to timeout) for pred() to become true, evaluated under this->mutex so it can
    // safely read decodes/displays/clears.
    template <typename Pred>
    bool wait_for(Pred pred, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(this->mutex);
        return this->cv.wait_for(lock, timeout, pred);
    }

    // Asserts pred() stays false for the whole window; used for "must NOT fire" checks. Returns
    // true if pred() never became true (the expected outcome).
    template <typename Pred>
    bool never_within(Pred pred, std::chrono::milliseconds window) {
        std::unique_lock<std::mutex> lock(this->mutex);
        return !this->cv.wait_for(lock, window, pred);
    }

    size_t decode_count() {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->decodes.size();
    }

    size_t display_count() {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->displays.size();
    }

    size_t clear_count() {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->clears.size();
    }

    // First byte of the payload decoded at `index`, used to identify which frame decoded.
    uint8_t decode_marker_at(size_t index) {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->decodes.at(index).payload.at(0);
    }

    // True if any recorded decode for `slot` carries `marker` as its first payload byte.
    bool has_decoded_marker(uint8_t slot, uint8_t marker) {
        std::lock_guard<std::mutex> lock(this->mutex);
        for (const auto& d : this->decodes) {
            if (d.slot == slot && !d.payload.empty() && d.payload[0] == marker) {
                return true;
            }
        }
        return false;
    }

    size_t decode_count_for_slot(uint8_t slot) {
        std::lock_guard<std::mutex> lock(this->mutex);
        size_t count = 0;
        for (const auto& d : this->decodes) {
            if (d.slot == slot) {
                ++count;
            }
        }
        return count;
    }

    std::mutex mutex;
    std::condition_variable cv;
    std::vector<DecodeEvent> decodes;
    std::vector<uint8_t> displays;
    std::vector<uint8_t> clears;
    bool frame_done_on_display{false};
    ArtworkRole::Impl* impl{nullptr};
};

// Builds a one-slot ArtworkRoleConfig; slot 0 opts into the ack gate iff `gated`.
ArtworkRoleConfig make_single_slot_config(bool gated) {
    ArtworkRoleConfig config;
    config.preferred_formats.push_back(
        {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 100, 100, gated});
    return config;
}

// Builds a two-slot ArtworkRoleConfig: slot 0 gated, slot 1 not.
ArtworkRoleConfig make_two_slot_config() {
    ArtworkRoleConfig config;
    config.preferred_formats.push_back(
        {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 100, 100, true});
    config.preferred_formats.push_back(
        {SendspinImageSource::ARTIST, SendspinImageFormat::JPEG, 100, 100, false});
    return config;
}

// A real, never-started SendspinClient plus a bound ArtworkRole::Impl running a live decode
// thread. Both are heap-allocated with program lifetime (static deques, mirroring make_impl() in
// test_visualizer_role.cpp): Impl holds atomics so it is neither copyable nor movable, and it
// keeps a raw SendspinClient* that drain_events() dereferences (get_client_time()), so the client
// must outlive the Impl. A default-constructed, never-started SendspinClient never opens a
// connection, so get_client_time() always returns 0 -- drain_events() then treats every pending
// display as immediately due instead of honoring a server-clock deadline (see the comment at its
// call site in artwork_role.cpp), which is exactly what these tests want.
std::unique_ptr<ArtworkRole::Impl> make_impl(ArtworkRoleConfig config) {
    static std::deque<SendspinClient> clients;
    static std::deque<Inbox> inboxes;

    clients.emplace_back(SendspinClientConfig{});
    auto impl = std::make_unique<ArtworkRole::Impl>(std::move(config), &clients.back());
    inboxes.emplace_back();
    impl->attach_inbox(inboxes.back());
    return impl;
}

// Sends one fake frame to `slot` whose image payload is [marker, 0xAA] (a distinct first byte
// per frame so tests can tell which frame decoded).
void send_frame(ArtworkRole::Impl& impl, uint8_t slot, uint8_t marker, int64_t timestamp = 1) {
    std::vector<uint8_t> data;
    put_be64(data, timestamp);
    data.push_back(marker);
    data.push_back(0xAA);
    impl.handle_binary(slot, data.data(), data.size());
}

// Polls drain_events() until `pred` is true or the timeout elapses. drain_events() must run on
// the "main loop" thread (here, the test thread), so it cannot be driven from inside the
// listener's condition variable wait -- it has to be called from an ordinary polling loop.
template <typename Pred>
bool poll_drain_until(ArtworkRole::Impl& impl, Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        impl.drain_events();
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::steady_clock::now() < deadline);
    return pred();
}

// Polls until `pred` (evaluated under impl.drain_task->slot_mutex) is true or the timeout
// elapses. SlotBuffer::has_parked/ack_state are decode-thread-owned state with no listener
// callback to hang a condition variable off of, so tests that need to synchronize with "the
// decode thread has parked this notification" (rather than "the decode thread has decoded
// something") poll the (public, per artwork_role_impl.h) SlotBuffer fields directly under the
// same mutex the production code uses.
template <typename Pred>
bool wait_slot_state(ArtworkRole::Impl& impl, Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        {
            std::lock_guard<std::mutex> lock(impl.drain_task->slot_mutex);
            if (pred()) {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    } while (std::chrono::steady_clock::now() < deadline);
    std::lock_guard<std::mutex> lock(impl.drain_task->slot_mutex);
    return pred();
}

}  // namespace

// ============================================================================
// Ungated behavior: require_frame_done = false must reproduce today's behavior exactly
// ============================================================================

TEST(ArtworkFrameDoneGate, DefaultUngatedUnchanged) {
    auto impl = make_impl(make_single_slot_config(false));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(0), 'A');

    send_frame(*impl, 0, 'B');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 2; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

// ============================================================================
// Basic gate: at most one un-acked delivery per gated slot
// ============================================================================

TEST(ArtworkFrameDoneGate, GateHoldsSecondFrame) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(0), 'A');

    send_frame(*impl, 0, 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 2; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

TEST(ArtworkFrameDoneGate, GateHoldsThroughDisplay) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));

    ASSERT_TRUE(
        poll_drain_until(*impl, [&] { return listener.display_count() >= 1; }, POSITIVE_TIMEOUT));

    // The gate must still be held after the display fires -- only frame_done() releases it.
    send_frame(*impl, 0, 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 2; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

TEST(ArtworkFrameDoneGate, SupersedeKeepsNewestParked) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));

    send_frame(*impl, 0, 'B');
    // Wait for B to actually be parked before sending C, so C deterministically observes an
    // already-parked notification to supersede (see the wait_slot_state comment on its first use
    // in ClearIsADeliveryAndDropsParked for why this matters instead of a fixed sleep).
    ASSERT_TRUE(wait_slot_state(
        *impl, [&] { return impl->drain_task->slot_buffers[0].has_parked; }, POSITIVE_TIMEOUT));
    send_frame(*impl, 0, 'C');

    impl->frame_done(0);
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 2; }, POSITIVE_TIMEOUT));

    // Only one more decode fires, and it is the newest (C); B was superseded while parked.
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 3; }, NEGATIVE_WINDOW));
    EXPECT_EQ(listener.decode_marker_at(1), 'C');
    EXPECT_FALSE(listener.has_decoded_marker(0, 'B'));
}

// ============================================================================
// Clear as a delivery: stream/end and stream/clear each owe exactly one ack
// ============================================================================

TEST(ArtworkFrameDoneGate, ClearIsADeliveryAndDropsParked) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));

    send_frame(*impl, 0, 'B');  // parks: A's delivery is still un-acked
    // Wait for the decode thread to actually park B (has_parked observed under slot_mutex)
    // before delivering the clear -- otherwise the clear could race ahead of the still-in-flight
    // notification and land before B is parked, in which case B would park *behind* the clear's
    // own owed ack instead of being dropped by it, which is a different (also-tested, see
    // ClearGateHoldsNextStreamFirstFrame) scenario.
    ASSERT_TRUE(wait_slot_state(
        *impl, [&] { return impl->drain_task->slot_buffers[0].has_parked; }, POSITIVE_TIMEOUT));

    impl->handle_stream_ring_event(ArtworkEventType::STREAM_CLEAR);
    ASSERT_TRUE(listener.wait_for([&] { return listener.clears.size() >= 1; }, POSITIVE_TIMEOUT));

    // The clear itself owes an ack; acking it must NOT resurrect the dropped, parked B.
    impl->frame_done(0);
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    // A fresh stream's frame decodes normally: the gate is IDLE again.
    impl->handle_stream_start(ServerArtworkStreamObject{});
    send_frame(*impl, 0, 'C');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 2; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(1), 'C');
}

TEST(ArtworkFrameDoneGate, ClearGateHoldsNextStreamFirstFrame) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));
    ASSERT_TRUE(
        poll_drain_until(*impl, [&] { return listener.display_count() >= 1; }, POSITIVE_TIMEOUT));

    // stream/end fires the clear callback but the clear's own ack is still outstanding.
    impl->handle_stream_ring_event(ArtworkEventType::STREAM_END);
    ASSERT_TRUE(listener.wait_for([&] { return listener.clears.size() >= 1; }, POSITIVE_TIMEOUT));

    impl->handle_stream_start(ServerArtworkStreamObject{});
    send_frame(*impl, 0, 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 2; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

// ============================================================================
// frame_done() edge cases
// ============================================================================

TEST(ArtworkFrameDoneGate, FrameDoneNoOpWhenIdle) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    // Nothing outstanding: both calls must be safe no-ops (including the out-of-range slot).
    impl->frame_done(0);
    impl->frame_done(99);

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(0), 'A');
}

// ============================================================================
// Stream restart interaction with the gate
// ============================================================================

TEST(ArtworkFrameDoneGate, RestartReleasesUndisplayedDecode) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));
    // Deliberately never call drain_events() here: A's display must never fire.

    impl->handle_stream_start(ServerArtworkStreamObject{});  // restart

    // Give the decode thread's async display hand-off a chance to land, then confirm the restart
    // (epoch bump + display_slot reset) keeps it from ever reaching the listener.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    impl->drain_events();
    impl->drain_events();
    EXPECT_EQ(listener.display_count(), 0U);

    // The DECODE_DELIVERED gate was auto-released by the restart: B decodes without any ack.
    send_frame(*impl, 0, 'B');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 2; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

TEST(ArtworkFrameDoneGate, RestartKeepsPresentedGate) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 1; }, POSITIVE_TIMEOUT));
    ASSERT_TRUE(
        poll_drain_until(*impl, [&] { return listener.display_count() >= 1; }, POSITIVE_TIMEOUT));

    impl->handle_stream_start(ServerArtworkStreamObject{});  // restart; PRESENTED stays armed

    send_frame(*impl, 0, 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    ASSERT_TRUE(listener.wait_for([&] { return listener.decodes.size() >= 2; }, POSITIVE_TIMEOUT));
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

// ============================================================================
// Reentrant frame_done() from inside on_image_display()
// ============================================================================

TEST(ArtworkFrameDoneGate, FrameDoneReentrantFromDisplay) {
    auto impl = make_impl(make_single_slot_config(true));
    RecordingListener listener;
    listener.frame_done_on_display = true;
    listener.impl = impl.get();
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    send_frame(*impl, 0, 'A');
    // B may arrive while A is still un-acked (it will park, then replay once the reentrant ack
    // from A's on_image_display() fires) or after; either way both must eventually decode and
    // display without any external frame_done() call and without deadlock.
    send_frame(*impl, 0, 'B');

    ASSERT_TRUE(poll_drain_until(
        *impl, [&] { return listener.decode_count() >= 2 && listener.display_count() >= 2; },
        POSITIVE_TIMEOUT));

    EXPECT_TRUE(listener.has_decoded_marker(0, 'A'));
    EXPECT_TRUE(listener.has_decoded_marker(0, 'B'));
    EXPECT_EQ(listener.display_count(), 2U);
}

// ============================================================================
// One gated slot must not affect an ungated slot
// ============================================================================

TEST(ArtworkFrameDoneGate, UngatedSlotUnaffectedBesideGatedSlot) {
    auto impl = make_impl(make_two_slot_config());
    RecordingListener listener;
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{});

    // wait_for()'s predicate runs under RecordingListener::mutex (via condition_variable's
    // predicate overload), so it must touch listener.decodes directly rather than going through
    // a helper like decode_count_for_slot() that re-locks the same non-recursive mutex.
    auto count_for_slot = [&](uint8_t slot) {
        size_t n = 0;
        for (const auto& d : listener.decodes) {
            if (d.slot == slot) {
                ++n;
            }
        }
        return n;
    };

    // Gate slot 0 with an un-acked delivery.
    send_frame(*impl, 0, 'A');
    ASSERT_TRUE(listener.wait_for([&] { return count_for_slot(0) >= 1; }, POSITIVE_TIMEOUT));

    // Slot 1 keeps decoding every frame freely, ungated by slot 0's outstanding delivery. Each
    // send waits for its own decode before the next is sent: slot 1 is double-buffered like any
    // other slot (see SlotBuffer::write_generation), so three back-to-back writes with nothing
    // draining them could legitimately overwrite an unclaimed buffer and drop a frame -- a
    // real (and separately-covered) property of the double-buffering scheme, not of the ack
    // gate this test is about, so it must not be exercised here.
    send_frame(*impl, 1, 'X');
    ASSERT_TRUE(listener.wait_for([&] { return count_for_slot(1) >= 1; }, POSITIVE_TIMEOUT));
    send_frame(*impl, 1, 'Y');
    ASSERT_TRUE(listener.wait_for([&] { return count_for_slot(1) >= 2; }, POSITIVE_TIMEOUT));
    send_frame(*impl, 1, 'Z');
    ASSERT_TRUE(listener.wait_for([&] { return count_for_slot(1) >= 3; }, POSITIVE_TIMEOUT));

    EXPECT_EQ(listener.decode_count_for_slot(0), 1U);
}

// ============================================================================
// display_deadline_reached: the drain_events() display-deadline arithmetic, including the
// per-slot display_offset_ms shift. Pure function, so tested directly: the integration tests
// above all run without a connection (client_ts == 0), which bypasses the offset path.
// ============================================================================

TEST(ArtworkDisplayDeadline, NoConnectionSentinelFiresImmediately) {
    // client_ts == 0 means no connection; fires regardless of offset in either direction.
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(0, 0, 5'000'000));
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(0, 1000, 5'000'000));
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(0, -1000, 5'000'000));
}

TEST(ArtworkDisplayDeadline, ZeroOffsetMatchesServerDeadline) {
    const int64_t now = 10'000'000;  // 10 s in us
    EXPECT_FALSE(ArtworkRole::Impl::display_deadline_reached(now + 1, 0, now));
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(now, 0, now));
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(now - 1, 0, now));
}

TEST(ArtworkDisplayDeadline, PositiveOffsetFiresEarly) {
    const int64_t now = 10'000'000;
    // Deadline 900 ms in the future, offset 1000 ms: already due.
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(now + 900 * US_PER_MS, 1000, now));
    // Deadline 1100 ms in the future, offset 1000 ms: still 100 ms out.
    EXPECT_FALSE(ArtworkRole::Impl::display_deadline_reached(now + 1100 * US_PER_MS, 1000, now));
    // Exact boundary: deadline minus offset equals now.
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(now + 1000 * US_PER_MS, 1000, now));
}

TEST(ArtworkDisplayDeadline, NegativeOffsetDelays) {
    const int64_t now = 10'000'000;
    // Deadline 500 ms in the past, but a -1000 ms offset holds it another 500 ms.
    EXPECT_FALSE(ArtworkRole::Impl::display_deadline_reached(now - 500 * US_PER_MS, -1000, now));
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(now - 1000 * US_PER_MS, -1000, now));
}

TEST(ArtworkDisplayDeadline, LargeOffsetDoesNotOverflow) {
    // INT32_MIN/MAX offsets must be widened to 64-bit before the ms-to-us multiply.
    const int64_t now = 10'000'000;
    EXPECT_TRUE(ArtworkRole::Impl::display_deadline_reached(now + US_PER_MS, INT32_MAX, now));
    EXPECT_FALSE(ArtworkRole::Impl::display_deadline_reached(now - US_PER_MS, INT32_MIN, now));
}
