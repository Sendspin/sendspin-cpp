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
#include <ArduinoJson.h>
#include "test_util.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

using namespace sendspin;

namespace {

// Flag bits of roles/artwork/v1.md "Artwork (Binary)": bit 0 cancels, bit 1 announces, a part
// sets neither.
constexpr uint8_t FLAG_CANCEL = 0x01;
constexpr uint8_t FLAG_ANNOUNCE = 0x02;

// Builds an announce body: everything the role sees of `[type][flags][timestamp][total_size]`
// once the caller has stripped the type byte.
std::vector<uint8_t> announce_body(int64_t timestamp, uint32_t total_size) {
    std::vector<uint8_t> data{FLAG_ANNOUNCE};
    put_be64(data, timestamp);
    put_be32(data, total_size);
    return data;
}

// Builds a part body: the flags byte (no bits set) followed by the part's image data.
std::vector<uint8_t> part_body(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> data{0};
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}

// An image of `length` bytes whose first byte is `marker`, so a test can tell which image
// decoded, and whose remaining bytes are a position-dependent pattern, so a reassembly that
// drops, duplicates or reorders a part is visible in the decoded bytes.
std::vector<uint8_t> make_image(uint8_t marker, size_t length) {
    std::vector<uint8_t> image(length);
    for (size_t i = 0; i < length; ++i) {
        image[i] = static_cast<uint8_t>(marker + i);
    }
    return image;
}

// The teardown generation a handler would be handed by the receive gate on a role that has not
// been torn down. The dispatch captures this value with its gate check and every point of effect
// re-checks it, so a unit test driving a handler directly passes the live one.
uint32_t live_generation(const ArtworkRole::Impl& impl) {
    return impl.cleanup_generation.load(std::memory_order_acquire);
}

// Feeds one message to the role. Returns what handle_binary() reported: false means the message
// is a protocol error and the connection must be closed.
bool feed(ArtworkRole::Impl& impl, uint8_t slot, const std::vector<uint8_t>& body) {
    return impl.handle_binary(slot, body.data(), body.size());
}

// Announces `image` on `slot` and sends it as `parts` equal-sized parts (the last one taking the
// remainder). Returns false if any message was rejected.
bool send_image(ArtworkRole::Impl& impl, uint8_t slot, const std::vector<uint8_t>& image,
                size_t parts = 1, int64_t timestamp = 1) {
    if (!feed(impl, slot, announce_body(timestamp, static_cast<uint32_t>(image.size())))) {
        return false;
    }
    const size_t chunk = (image.size() + parts - 1) / parts;
    for (size_t offset = 0; offset < image.size(); offset += chunk) {
        const size_t take = std::min(chunk, image.size() - offset);
        std::vector<uint8_t> slice(image.begin() + static_cast<long>(offset),
                                   image.begin() + static_cast<long>(offset + take));
        if (!feed(impl, slot, part_body(slice))) {
            return false;
        }
    }
    return true;
}

// Window for "must NOT fire" checks. Every path that reopens a slot's gate (frame_done or an
// epoch release) wakes the decode thread, so a spurious replay through that path arrives
// promptly; this is settle time for that wake. The thread also re-runs the parked-slot sweep
// when its receive timeout expires (DRAIN_RECEIVE_TIMEOUT_MS in artwork_role.cpp), so a
// replay reachable only through that fallback sweep lands outside this window and is not
// covered here. Every counter it watches is monotonic, so a window that is too short can only
// miss a regression, never fail a correct run.
constexpr auto NEGATIVE_WINDOW = std::chrono::milliseconds(300);

// Records every callback fired by an ArtworkRole::Impl under test, guarded by its own mutex so
// the test thread can safely poll state produced on the decode thread and the main thread.
// Every test declares it before the Impl so it outlives the drain thread, which ~Impl joins. If
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

    void on_image_display(uint8_t slot, uint32_t /*lateness_ms*/) override {
        {
            std::lock_guard<std::mutex> lock(this->mutex);
            this->displays.push_back(slot);
        }
        this->cv.notify_all();
        // Deliberately outside the lock above: frame_done() takes the Impl's own slot_mutex, and
        // this call must not be made while holding this listener's mutex (which nothing else
        // needs, but keeping the pattern lock-then-release-then-reenter is the safe shape the
        // production code itself uses: see drain_events()/handle_stream_ring_event()).
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

    // Waits for pred() to become true, evaluated under this->mutex so it can safely read
    // decodes/displays/clears. No timeout: a regression hangs here and the CTest TIMEOUT
    // reports it.
    template <typename Pred>
    void wait_until(Pred pred) {
        std::unique_lock<std::mutex> lock(this->mutex);
        this->cv.wait(lock, pred);
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

    // Slot recorded for the clear at `index`, used to tell a per-channel clear (one slot) from a
    // stream-level one (every configured slot).
    uint8_t clear_at(size_t index) {
        std::lock_guard<std::mutex> lock(this->mutex);
        return this->clears.at(index);
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

// A deliberately small per-channel image budget, so a test can cross it without building a
// 128 KiB image.
constexpr size_t SMALL_IMAGE_CAP = 2048;

// Builds a one-slot ArtworkRoleConfig whose channel holds at most `max_image_bytes`.
ArtworkRoleConfig make_capped_slot_config(uint32_t max_image_bytes) {
    ArtworkRoleConfig config;
    config.preferred_formats.push_back({.source = SendspinImageSource::ALBUM,
                                        .format = SendspinImageFormat::JPEG,
                                        .width = 100,
                                        .height = 100,
                                        .max_image_bytes = max_image_bytes});
    return config;
}

// Builds a one-slot ArtworkRoleConfig whose channel budgets enough bytes to hold an image
// spanning several maximum-sized messages.
ArtworkRoleConfig make_large_slot_config() {
    ArtworkRoleConfig config;
    config.preferred_formats.push_back({.source = SendspinImageSource::ALBUM,
                                        .format = SendspinImageFormat::PNG,
                                        .width = 512,
                                        .height = 512,
                                        .max_image_bytes = 256U * 1024U});
    return config;
}

// Two ungated slots, so a frame on each is decoded without an ack.
ArtworkRoleConfig make_two_ungated_slot_config() {
    ArtworkRoleConfig config;
    config.preferred_formats.push_back(
        {SendspinImageSource::ALBUM, SendspinImageFormat::JPEG, 100, 100, false});
    config.preferred_formats.push_back(
        {SendspinImageSource::ARTIST, SendspinImageFormat::JPEG, 100, 100, false});
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
// connection, so get_client_time() always returns 0: drain_events() then treats every pending
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

// Sends one fake frame to `slot` as a complete single-part transfer; `marker` is the image's
// first byte, so tests can tell which frame decoded.
void send_frame(ArtworkRole::Impl& impl, uint8_t slot, uint8_t marker, int64_t timestamp = 1) {
    send_image(impl, slot, make_image(marker, 2), /*parts=*/1, timestamp);
}

// Sends a per-channel clear to `slot`: an announce with total_size 0, the protocol's empty
// image, which is how the server says the artwork on that channel is no longer valid (as opposed
// to simply not resending an image that still is).
void send_clear(ArtworkRole::Impl& impl, uint8_t slot, int64_t timestamp = 1) {
    feed(impl, slot, announce_body(timestamp, 0));
}

// Polls drain_events() until `pred` is true. drain_events() must run on the "main loop" thread
// (here, the test thread), so it cannot be driven from inside the listener's condition variable
// wait: it has to be called from an ordinary polling loop. No timeout: a regression hangs
// here and the CTest TIMEOUT reports it.
template <typename Pred>
void poll_drain_until(ArtworkRole::Impl& impl, Pred pred) {
    for (;;) {
        impl.drain_events();
        if (pred()) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// Asserts pred() stays false for the whole window while the main loop keeps draining: the
// drain-driving counterpart of RecordingListener::never_within(). A negative check on clears or
// displays must use this one rather than never_within(), because on_image_clear()/
// on_image_display() fire only from drain_events() and handle_stream_ring_event(), both on this
// (main loop) thread: a window that parks the test thread instead of driving the loop freezes
// the very counter it is watching, so the assertion could never fail. never_within() stays correct
// for decodes, which the decode thread produces on its own. Returns true if pred() never became
// true (the expected outcome).
template <typename Pred>
bool poll_drain_never(ArtworkRole::Impl& impl, Pred pred, std::chrono::milliseconds window) {
    const auto deadline = std::chrono::steady_clock::now() + window;
    do {
        impl.drain_events();
        if (pred()) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::steady_clock::now() < deadline);
    return !pred();
}

// Polls until `pred` (evaluated under impl.drain_task->slot_mutex) is true. No timeout: a
// regression hangs here and the CTest TIMEOUT reports it. SlotBuffer::has_parked/ack_state are decode-thread-owned state with no listener
// callback to hang a condition variable off of, so tests that need to synchronize with "the
// decode thread has parked this notification" (rather than "the decode thread has decoded
// something") poll the (public, per artwork_role_impl.h) SlotBuffer fields directly under the
// same mutex the production code uses.
template <typename Pred>
void wait_slot_state(ArtworkRole::Impl& impl, Pred pred) {
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(impl.drain_task->slot_mutex);
            if (pred()) {
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

}  // namespace

// ============================================================================
// Transfer format: an announce, its parts, and the cancel that abandons them
// (roles/artwork/v1.md "Server -> Client: Artwork (Binary)")
// ============================================================================

// A teardown that lands after the receive gate admitted a stream/start, while the handler is
// still running, invalidates it: the generation the dispatch captured no longer matches, so the
// stream is not re-armed for a role that has been stopped and the ungated binary path stays shut.
TEST(ArtworkStreamStart, RefusesAGenerationATeardownOvertook) {
    auto impl = make_impl(make_single_slot_config(false));
    const uint32_t captured = live_generation(*impl);

    impl->cleanup();

    impl->handle_stream_start(ServerArtworkStreamObject{}, captured);
    EXPECT_FALSE(impl->stream_active.load()) << "a stopped role was re-armed by a stale handler";

    // Control: the same stream/start with the generation the role now reports is applied.
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));
    EXPECT_TRUE(impl->stream_active.load());
}

TEST(ArtworkTransfer, AnnounceThenPartsCompletesOneImage) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // "The concatenated data of all parts is the encoded image": the decoded bytes must be the
    // image in order, which a part written at the wrong offset or a dropped part would break.
    const std::vector<uint8_t> image = make_image('A', 300);
    EXPECT_TRUE(send_image(*impl, 0, image, /*parts=*/4));

    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decodes[0].payload, image);
    // One image is one delivery, however many messages carried it.
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));
    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });
    EXPECT_EQ(listener.clear_count(), 0U);
}

TEST(ArtworkTransfer, TransferDeliversNothingUntilItCompletes) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    const std::vector<uint8_t> image = make_image('A', 100);
    ASSERT_TRUE(feed(*impl, 0, announce_body(1, 100)));
    ASSERT_TRUE(feed(*impl, 0, part_body({image.begin(), image.begin() + 60})));
    EXPECT_TRUE(listener.never_within([&] { return !listener.decodes.empty(); }, NEGATIVE_WINDOW));

    // Control: the part that takes the accumulated data to total_size completes the transfer.
    ASSERT_TRUE(feed(*impl, 0, part_body({image.begin() + 60, image.end()})));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decodes[0].payload, image);
}

TEST(ArtworkTransfer, EmptyImageCompletesAtItsAnnounce) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // "An announce with total_size 0 completes immediately, with no parts": nothing is left in
    // flight, so the next announce is a legal one rather than the malformed sequence it would be
    // if the empty image were still waiting for parts.
    ASSERT_TRUE(feed(*impl, 0, announce_body(1, 0)));
    poll_drain_until(*impl, [&] { return listener.clear_count() >= 1; });

    EXPECT_TRUE(send_image(*impl, 0, make_image('A', 20)));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
}

TEST(ArtworkTransfer, CancelAbandonsTheTransferInFlight) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    ASSERT_TRUE(feed(*impl, 0, announce_body(1, 100)));
    ASSERT_TRUE(feed(*impl, 0, part_body(make_image('A', 60))));
    ASSERT_TRUE(feed(*impl, 0, {FLAG_CANCEL}));

    // The abandoned image never reaches the listener, and the announce that follows is accepted:
    // the cancel ended the transfer rather than leaving it in flight.
    EXPECT_TRUE(send_image(*impl, 0, make_image('B', 40)));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decode_marker_at(0), 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));
}

TEST(ArtworkTransfer, CancelDiscardsThePendingImage) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // A complete image whose display has not been drained yet is the channel's pending image, and
    // "it discards the channel's pending image", so the display must never fire.
    ASSERT_TRUE(send_image(*impl, 0, make_image('A', 20)));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    ASSERT_TRUE(feed(*impl, 0, {FLAG_CANCEL}));
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.display_count() >= 1; }, NEGATIVE_WINDOW));
    // "the current image is unaffected": a cancel is not itself a delivery, so it clears nothing.
    EXPECT_EQ(listener.clear_count(), 0U);

    // Control: the same image with no cancel is displayed.
    ASSERT_TRUE(send_image(*impl, 0, make_image('B', 20)));
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });
}

TEST(ArtworkTransfer, AnnounceDiscardsThePendingImage) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // "An announce discards that channel's pending image": A is complete but not yet displayed,
    // so B's announce must leave only B to be displayed. The gated slot is what makes the
    // discard observable: no frame_done() is ever called here, so B can only reach the decode
    // callback if discarding A released the delivery A's on_image_decode() armed.
    ASSERT_TRUE(send_image(*impl, 0, make_image('A', 20)));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    ASSERT_TRUE(send_image(*impl, 0, make_image('B', 20)));

    poll_drain_until(*impl, [&] { return listener.decode_count() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
    // One display, B's: A's was discarded before it could fire.
    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.display_count() >= 2; }, NEGATIVE_WINDOW));
}

TEST(ArtworkTransfer, AnnounceTimestampAndSizeAreReadFromTheAnnounce) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // The gated slot holds the first delivery un-acked, so the second image's notification parks
    // where the test can read the timestamp and length that were parsed off its announce. A
    // timestamp read at the wrong offset, or byte-swapped, shows up here.
    constexpr int64_t TIMESTAMP = 0x0102030405060708;
    ASSERT_TRUE(send_image(*impl, 0, make_image('A', 8)));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    ASSERT_TRUE(send_image(*impl, 0, make_image('B', 37), /*parts=*/3, TIMESTAMP));

    wait_slot_state(*impl, [&] { return impl->drain_task->slot_buffers[0].has_parked; });
    std::lock_guard<std::mutex> lock(impl->drain_task->slot_mutex);
    EXPECT_EQ(impl->drain_task->slot_buffers[0].parked.timestamp, TIMESTAMP);
    EXPECT_EQ(impl->drain_task->slot_buffers[0].parked.data_length, 37U);
}

// ============================================================================
// Malformed sequences: the connection closes (roles/artwork/v1.md "Malformed sequences within an
// active artwork stream")
// ============================================================================

TEST(ArtworkMalformedSequence, AnnounceWhileATransferIsInFlightCloses) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    ASSERT_TRUE(feed(*impl, 0, announce_body(1, 100)));
    // "At most one image transfer is in flight at a time across all of the role's channels", so
    // the other channel's announce is a protocol error too.
    EXPECT_FALSE(feed(*impl, 1, announce_body(1, 20)));
    EXPECT_FALSE(feed(*impl, 0, announce_body(1, 20)));
}

TEST(ArtworkMalformedSequence, AnnounceAfterTheTransferCompletesIsAccepted) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // Control for AnnounceWhileATransferIsInFlightCloses: the same two announces, with the first
    // transfer finished in between, are both legal.
    EXPECT_TRUE(send_image(*impl, 0, make_image('A', 100), /*parts=*/2));
    EXPECT_TRUE(send_image(*impl, 1, make_image('B', 20)));
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
}

TEST(ArtworkMalformedSequence, PartWithNoTransferInFlightCloses) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    EXPECT_FALSE(feed(*impl, 0, part_body(make_image('A', 20))));
}

TEST(ArtworkMalformedSequence, PartOnAnotherChannelCloses) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    ASSERT_TRUE(feed(*impl, 0, announce_body(1, 100)));
    EXPECT_FALSE(feed(*impl, 1, part_body(make_image('A', 20))));
}

TEST(ArtworkMalformedSequence, PartPastTotalSizeCloses) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    ASSERT_TRUE(feed(*impl, 0, announce_body(1, 100)));
    ASSERT_TRUE(feed(*impl, 0, part_body(make_image('A', 60))));
    // 41 more bytes would take the image one byte past its announced size.
    EXPECT_FALSE(feed(*impl, 0, part_body(make_image('A', 41))));
}

TEST(ArtworkMalformedSequence, PartThatExactlyFillsTheImageIsAccepted) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // Control for PartPastTotalSizeCloses: one byte fewer is the last part of a complete image.
    ASSERT_TRUE(feed(*impl, 0, announce_body(1, 100)));
    ASSERT_TRUE(feed(*impl, 0, part_body(make_image('A', 60))));
    EXPECT_TRUE(feed(*impl, 0, part_body(make_image('B', 40))));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
}

TEST(ArtworkMalformedSequence, SequenceRulesOnlyApplyWithinAnActiveStream) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());

    // "Servers MUST NOT send artwork messages outside an active artwork stream." A well-formed
    // message that arrives anyway is ignored, not closed on: the sequence rules are scoped to an
    // active stream and there is no sequence for it to break.
    EXPECT_TRUE(feed(*impl, 0, part_body(make_image('A', 20))));
    EXPECT_TRUE(feed(*impl, 0, {FLAG_CANCEL}));
    EXPECT_TRUE(
        listener.never_within([&] { return !listener.decodes.empty(); }, NEGATIVE_WINDOW));
}

// ============================================================================
// Malformed messages: the connection closes (roles/artwork/v1.md "Malformed messages")
// ============================================================================

TEST(ArtworkMalformedMessage, MessageShorterThanTwoBytesCloses) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // A message of just its type byte: nothing is left once the caller strips it.
    const uint8_t* no_body = nullptr;
    EXPECT_FALSE(impl->handle_binary(0, no_body, 0));
    // Control: two bytes is the shortest legal message, a cancel.
    EXPECT_TRUE(feed(*impl, 0, {FLAG_CANCEL}));
}

TEST(ArtworkMalformedMessage, AnnounceThatIsNotFourteenBytesCloses) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    std::vector<uint8_t> short_announce = announce_body(1, 20);
    short_announce.pop_back();
    EXPECT_FALSE(feed(*impl, 0, short_announce));

    std::vector<uint8_t> long_announce = announce_body(1, 20);
    long_announce.push_back(0);
    EXPECT_FALSE(feed(*impl, 0, long_announce));

    // Control: exactly 14 bytes on the wire (13 here, the type byte stripped).
    EXPECT_TRUE(feed(*impl, 0, announce_body(1, 0)));
}

TEST(ArtworkMalformedMessage, CancelWithABodyCloses) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    EXPECT_FALSE(feed(*impl, 0, {FLAG_CANCEL, 0x00}));
    // Control: the same cancel without the trailing byte.
    EXPECT_TRUE(feed(*impl, 0, {FLAG_CANCEL}));
}

TEST(ArtworkMalformedMessage, ReservedFlagBitsClose) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // "Bits 2-7 are reserved and MUST be zero", on every message shape.
    for (int bit = 2; bit < 8; ++bit) {
        const auto flags = static_cast<uint8_t>(1U << bit);
        EXPECT_FALSE(feed(*impl, 0, {flags})) << "part with reserved bit " << bit;
        EXPECT_FALSE(feed(*impl, 0, {static_cast<uint8_t>(FLAG_CANCEL | flags)}))
            << "cancel with reserved bit " << bit;
        std::vector<uint8_t> announce = announce_body(1, 0);
        announce[0] = static_cast<uint8_t>(FLAG_ANNOUNCE | flags);
        EXPECT_FALSE(feed(*impl, 0, announce)) << "announce with reserved bit " << bit;
    }
    // Control: the three defined flag values are all accepted.
    EXPECT_TRUE(feed(*impl, 0, announce_body(1, 20)));
    EXPECT_TRUE(feed(*impl, 0, part_body(make_image('A', 20))));
    EXPECT_TRUE(feed(*impl, 0, {FLAG_CANCEL}));
}

TEST(ArtworkMalformedMessage, CancelAndAnnounceFlagsTogetherClose) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    std::vector<uint8_t> both = announce_body(1, 0);
    both[0] = FLAG_ANNOUNCE | FLAG_CANCEL;
    EXPECT_FALSE(feed(*impl, 0, both));
    // A two-byte message with both bits set is refused for the flags, not for its length.
    EXPECT_FALSE(feed(*impl, 0, {FLAG_ANNOUNCE | FLAG_CANCEL}));
}

TEST(ArtworkMalformedMessage, MessagePastTheSizeCapCloses) {
    RecordingListener listener;
    auto impl = make_impl(make_large_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // "An artwork message MUST NOT exceed 65519 bytes": a part carries at most 65517 data bytes.
    constexpr size_t MAX_PART_DATA = 65519 - 2;
    ASSERT_TRUE(feed(*impl, 0, announce_body(1, MAX_PART_DATA * 2)));
    // Control: a part exactly at the cap is accepted, and is the first half of the image.
    EXPECT_TRUE(feed(*impl, 0, part_body(make_image('A', MAX_PART_DATA))));
    // One byte more is a message of 65520 bytes.
    EXPECT_FALSE(feed(*impl, 0, part_body(make_image('B', MAX_PART_DATA + 1))));
}

TEST(ArtworkMalformedMessage, ShapeRulesApplyWithNoStreamActive) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());

    // Unlike the sequence rules, "Malformed messages are protocol errors" is not scoped to an
    // active stream: the bytes are indefensible whenever they arrive.
    EXPECT_FALSE(feed(*impl, 0, {0x04}));
    EXPECT_FALSE(feed(*impl, 0, {FLAG_CANCEL, 0x00}));
    // Control: a well-formed message outside a stream is ignored, not closed on.
    EXPECT_TRUE(feed(*impl, 0, announce_body(1, 20)));
}

// ============================================================================
// Image cap: an image the role will not hold is discarded, while its sequence is tracked to the
// end (roles/artwork/v1.md "Artwork (Binary)" on unavailable clients)
// ============================================================================

TEST(ArtworkImageCap, IsTheChannelsConfiguredBudget) {
    auto impl = make_impl(make_capped_slot_config(SMALL_IMAGE_CAP));
    EXPECT_EQ(impl->image_cap(0), SMALL_IMAGE_CAP);
    // A channel the role never declared holds nothing, whatever the declared ones budgeted.
    EXPECT_EQ(impl->image_cap(1), 0U);

    // An unset budget is the documented default rather than nothing.
    auto defaulted = make_impl(make_single_slot_config(false));
    EXPECT_EQ(defaulted->image_cap(0), ImageSlotPreference::DEFAULT_MAX_IMAGE_BYTES);
}

TEST(ArtworkImageCap, ImageOverTheCapIsDiscardedAndItsSequenceTracked) {
    RecordingListener listener;
    auto impl = make_impl(make_capped_slot_config(SMALL_IMAGE_CAP));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // "clients discarding image data MUST still process announces and cancels and count each
    // part's data bytes toward total_size": the transfer runs to its end holding nothing, so the
    // announce that follows it is legal rather than a second announce in flight.
    ASSERT_TRUE(send_image(*impl, 0, make_image('A', SMALL_IMAGE_CAP + 1), /*parts=*/3));
    EXPECT_TRUE(listener.never_within([&] { return !listener.decodes.empty(); }, NEGATIVE_WINDOW));

    // Control: an image of exactly the cap on the same channel is delivered.
    EXPECT_TRUE(send_image(*impl, 0, make_image('B', SMALL_IMAGE_CAP), /*parts=*/3));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decodes[0].payload.size(), SMALL_IMAGE_CAP);
    EXPECT_EQ(listener.decode_marker_at(0), 'B');
}

TEST(ArtworkImageCap, RoleWithNoListenerHoldsNothing) {
    auto impl = make_impl(make_single_slot_config(false));
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // Nowhere to deliver an image, so the role takes the discarding path rather than allocating
    // a buffer for it, while still following the transfer to its end.
    EXPECT_TRUE(send_image(*impl, 0, make_image('A', 4096), /*parts=*/2));
    {
        std::lock_guard<std::mutex> lock(impl->drain_task->slot_mutex);
        EXPECT_EQ(impl->drain_task->slot_buffers[0].buffers[0].data(), nullptr);
        EXPECT_EQ(impl->drain_task->slot_buffers[0].buffers[1].data(), nullptr);
    }

    // Control: with a listener the same image is held and delivered.
    RecordingListener listener;
    impl->listener = &listener;
    EXPECT_TRUE(send_image(*impl, 0, make_image('B', 4096), /*parts=*/2));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decodes[0].payload.size(), 4096U);
}

TEST(ArtworkImageCap, ChannelTheRoleDidNotConfigureHoldsNothing) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // Channel 2 was never declared in client/state, so the role holds no image for it and does
    // not close on its arrival either.
    EXPECT_TRUE(send_image(*impl, 2, make_image('A', 20)));
    EXPECT_TRUE(listener.never_within([&] { return !listener.decodes.empty(); }, NEGATIVE_WINDOW));

    // Control: the same image on a declared channel decodes.
    EXPECT_TRUE(send_image(*impl, 1, make_image('B', 20)));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
}

// ============================================================================
// stream/start scopes the pending-image discard to the channels it reconfigured
// (roles/artwork/v1.md "Artwork (Binary)")
// ============================================================================

namespace {

// A stream/start artwork object with two channels; `width` is what the test varies to make a
// channel's configuration differ from the one in force.
ServerArtworkStreamObject two_channel_stream(uint16_t channel0_width, uint16_t channel1_width) {
    ServerArtworkChannelObject channel0;
    channel0.source = SendspinImageSource::ALBUM;
    channel0.format = SendspinImageFormat::JPEG;
    channel0.width = channel0_width;
    channel0.height = 100;
    ServerArtworkChannelObject channel1 = channel0;
    channel1.source = SendspinImageSource::ARTIST;
    channel1.width = channel1_width;

    ServerArtworkStreamObject stream;
    stream.channels = std::vector<ServerArtworkChannelObject>{channel0, channel1};
    return stream;
}

// Decodes an image on `slot` and leaves its display undrained, which is the "pending image" a
// stream/start either keeps or discards.
void leave_pending_image(ArtworkRole::Impl& impl, RecordingListener& listener, uint8_t slot,
                         uint8_t marker, size_t already_decoded) {
    ASSERT_TRUE(send_image(impl, slot, make_image(marker, 20)));
    listener.wait_until([&] { return listener.decodes.size() > already_decoded; });
}

}  // namespace

TEST(ArtworkStreamStart, UnchangedChannelKeepsItsPendingImage) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(two_channel_stream(100, 100), live_generation(*impl));

    leave_pending_image(*impl, listener, 1, 'A', 0);

    // Channel 0's geometry changes, channel 1's entry is identical. The server cancels and
    // re-sends only for the channel it changed, so discarding channel 1's pending image here
    // would lose an image nothing re-sends.
    impl->handle_stream_start(two_channel_stream(200, 100), live_generation(*impl));

    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });
    EXPECT_EQ(listener.clear_count(), 0U);
}

TEST(ArtworkStreamStart, ChangedChannelDropsItsPendingImage) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(two_channel_stream(100, 100), live_generation(*impl));

    leave_pending_image(*impl, listener, 1, 'A', 0);

    // The same stream/start, this time changing channel 1 itself: its pending image is encoded
    // for a configuration that no longer applies, and the server re-sends it.
    impl->handle_stream_start(two_channel_stream(100, 200), live_generation(*impl));

    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.display_count() >= 1; }, NEGATIVE_WINDOW));
}

TEST(ArtworkStreamStart, EveryChannelDropsItsPendingImageWhenAllChange) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(two_channel_stream(100, 100), live_generation(*impl));

    leave_pending_image(*impl, listener, 0, 'A', 0);
    leave_pending_image(*impl, listener, 1, 'B', 1);

    impl->handle_stream_start(two_channel_stream(200, 200), live_generation(*impl));

    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.display_count() >= 1; }, NEGATIVE_WINDOW));
}

TEST(ArtworkStreamStart, ChannelTheNewArrayDropsCountsAsChanged) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(two_channel_stream(100, 100), live_generation(*impl));

    leave_pending_image(*impl, listener, 1, 'A', 0);

    // "A channel the array does not cover ... is not streamed": truncating the array stops
    // streaming channel 1, which is as much a change as reconfiguring it.
    ServerArtworkStreamObject truncated = two_channel_stream(100, 100);
    truncated.channels->pop_back();
    impl->handle_stream_start(truncated, live_generation(*impl));

    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.display_count() >= 1; }, NEGATIVE_WINDOW));
}

TEST(ArtworkStreamStart, StreamWithNoChannelArrayDropsEveryPendingImage) {
    RecordingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(two_channel_stream(100, 100), live_generation(*impl));

    leave_pending_image(*impl, listener, 1, 'A', 0);

    // With no channel array there is nothing to compare, so every channel is treated as
    // reconfigured rather than assumed unchanged.
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.display_count() >= 1; }, NEGATIVE_WINDOW));
}

// ============================================================================
// Stream lifecycle and disconnect drop the transfer in flight
// ============================================================================

namespace {

// Feeds a partial transfer, applies `end_the_stream`, and asserts that the transfer is gone: a
// fresh stream takes a new announce (rather than closing on a second announce in flight) and the
// abandoned image never reaches the listener.
void expect_transfer_dropped_by(const std::function<void(ArtworkRole::Impl&)>& end_the_stream) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    ASSERT_TRUE(feed(*impl, 0, announce_body(1, 100)));
    ASSERT_TRUE(feed(*impl, 0, part_body(make_image('A', 60))));

    end_the_stream(*impl);
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    EXPECT_TRUE(send_image(*impl, 0, make_image('B', 40)));
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decode_marker_at(0), 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));
}

}  // namespace

TEST(ArtworkTransfer, StreamEndDropsTheTransferInFlight) {
    expect_transfer_dropped_by([](ArtworkRole::Impl& impl) { impl.handle_stream_end(live_generation(impl)); });
}

TEST(ArtworkTransfer, StreamClearDropsTheTransferInFlight) {
    expect_transfer_dropped_by([](ArtworkRole::Impl& impl) { impl.handle_stream_clear(live_generation(impl)); });
}

TEST(ArtworkTransfer, StreamStartDropsTheTransferInFlight) {
    expect_transfer_dropped_by(
        [](ArtworkRole::Impl& impl) {
            impl.handle_stream_start(ServerArtworkStreamObject{}, live_generation(impl));
        });
}

TEST(ArtworkTransfer, DisconnectDropsTheTransferInFlight) {
    expect_transfer_dropped_by([](ArtworkRole::Impl& impl) { impl.cleanup(); });
}

// ============================================================================
// Ungated behavior: require_frame_done = false must reproduce today's behavior exactly
// ============================================================================

TEST(ArtworkFrameDoneGate, DefaultUngatedUnchanged) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decode_marker_at(0), 'A');

    send_frame(*impl, 0, 'B');
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

// ============================================================================
// Basic gate: at most one un-acked delivery per gated slot
// ============================================================================

TEST(ArtworkFrameDoneGate, GateHoldsSecondFrame) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decode_marker_at(0), 'A');

    send_frame(*impl, 0, 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

TEST(ArtworkFrameDoneGate, GateHoldsThroughDisplay) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });

    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });

    // The gate must still be held after the display fires: only frame_done() releases it.
    send_frame(*impl, 0, 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

TEST(ArtworkFrameDoneGate, SupersedeKeepsNewestParked) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });

    send_frame(*impl, 0, 'B');
    // Wait for B to actually be parked before sending C, so C deterministically observes an
    // already-parked notification to supersede (see the wait_slot_state comment on its first use
    // in ClearIsADeliveryAndDropsParked for why this matters instead of a fixed sleep).
    wait_slot_state(
        *impl, [&] { return impl->drain_task->slot_buffers[0].has_parked; });
    send_frame(*impl, 0, 'C');

    impl->frame_done(0);
    listener.wait_until([&] { return listener.decodes.size() >= 2; });

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
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });

    send_frame(*impl, 0, 'B');  // parks: A's delivery is still un-acked
    // Wait for the decode thread to actually park B (has_parked observed under slot_mutex)
    // before delivering the clear: otherwise the clear could race ahead of the still-in-flight
    // notification and land before B is parked, in which case B would park *behind* the clear's
    // own owed ack instead of being dropped by it, which is a different (also-tested, see
    // ClearGateHoldsNextStreamFirstFrame) scenario.
    wait_slot_state(
        *impl, [&] { return impl->drain_task->slot_buffers[0].has_parked; });

    impl->handle_stream_ring_event(ArtworkEventType::STREAM_CLEAR);
    listener.wait_until([&] { return listener.clears.size() >= 1; });

    // The clear itself owes an ack; acking it must NOT resurrect the dropped, parked B.
    impl->frame_done(0);
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    // A fresh stream's frame decodes normally: the gate is IDLE again.
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));
    send_frame(*impl, 0, 'C');
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'C');
}

TEST(ArtworkFrameDoneGate, ClearGateHoldsNextStreamFirstFrame) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });

    // stream/end fires the clear callback but the clear's own ack is still outstanding.
    impl->handle_stream_ring_event(ArtworkEventType::STREAM_END);
    listener.wait_until([&] { return listener.clears.size() >= 1; });

    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));
    send_frame(*impl, 0, 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

// ============================================================================
// Per-channel clear: an artwork binary message with no image bytes clears just that channel,
// scheduled to its timestamp like any other delivery
// ============================================================================

TEST(ArtworkChannelClear, EmptyPayloadFiresClearWithoutDecoding) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_clear(*impl, 0);

    poll_drain_until(*impl, [&] { return listener.clear_count() >= 1; });
    EXPECT_EQ(listener.clear_at(0), 0);
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.clear_count() >= 2; }, NEGATIVE_WINDOW));
    // There are no image bytes, so nothing may reach the decode callback, and nothing may be
    // presented as a frame either.
    EXPECT_EQ(listener.decode_count(), 0U);
    EXPECT_EQ(listener.display_count(), 0U);
}

TEST(ArtworkChannelClear, ClearAfterDisplayedFrameFiresAgain) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // The album's first track: artwork arrives and is displayed.
    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });

    // A later track with no artwork of its own: the clear must reach the listener while the
    // stream is still running, so a consumer can tell "no artwork for this item" apart from
    // "artwork unchanged, nothing sent".
    send_clear(*impl, 0);
    poll_drain_until(*impl, [&] { return listener.clear_count() >= 1; });
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.clear_count() >= 2; }, NEGATIVE_WINDOW));
    EXPECT_EQ(listener.display_count(), 1U);
    EXPECT_EQ(listener.decode_count(), 1U);
}

TEST(ArtworkChannelClear, ClearOnlyAffectsItsOwnSlot) {
    RecordingListener listener;
    auto impl = make_impl(make_two_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // Slot 1 (ungated) is cleared; slot 0 (gated) must be left alone entirely: a stream-level
    // clear fires for every configured slot, a per-channel clear for exactly one.
    send_clear(*impl, 1);
    poll_drain_until(*impl, [&] { return listener.clear_count() >= 1; });
    EXPECT_EQ(listener.clear_at(0), 1);
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.clear_count() >= 2; }, NEGATIVE_WINDOW));

    // Slot 0's gate was never armed by slot 1's clear, so its frame decodes without any ack.
    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decode_marker_at(0), 'A');
}

TEST(ArtworkChannelClear, GatedClearParksBehindUnackedFrame) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    // A is displayed and un-acked, so it is the channel's current image rather than its pending
    // one, and the clear that follows cannot discard it.
    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });

    // A's delivery is un-acked, so the clear parks rather than overtaking it: the consumer is
    // mid-presentation of A and its buffers must not be disturbed.
    send_clear(*impl, 0);
    wait_slot_state(
        *impl, [&] { return impl->drain_task->slot_buffers[0].has_parked; });
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.clear_count() >= 1; }, NEGATIVE_WINDOW));

    // Only acking A releases the parked clear.
    impl->frame_done(0);
    poll_drain_until(*impl, [&] { return listener.clear_count() >= 1; });
    EXPECT_EQ(listener.clear_at(0), 0);
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.clear_count() >= 2; }, NEGATIVE_WINDOW));
}

TEST(ArtworkChannelClear, GatedClearOwesExactlyOneAck) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_clear(*impl, 0);
    poll_drain_until(*impl, [&] { return listener.clear_count() >= 1; });
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.clear_count() >= 2; }, NEGATIVE_WINDOW));

    // The clear is a delivery like any frame, so it holds the gate until it is acked.
    send_frame(*impl, 0, 'A');
    EXPECT_TRUE(
        listener.never_within([&] { return !listener.decodes.empty(); }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decode_marker_at(0), 'A');
}

TEST(ArtworkChannelClear, GatedClearSupersedesParkedClear) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    // A is displayed, so it is the current image and neither clear's announce can discard it.
    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });

    // Two clears arrive back to back while A is un-acked. Both park, and the second must overwrite
    // the first (latest-wins) rather than queue behind it, so the consumer is asked to clear once
    // rather than twice. Distinct timestamps make the handoff observable: waiting for the parked
    // notification to carry the second clear's timestamp is what keeps this deterministic, since
    // has_parked is already true from the first.
    send_clear(*impl, 0, /*timestamp=*/1);
    wait_slot_state(
        *impl, [&] { return impl->drain_task->slot_buffers[0].has_parked; });
    send_clear(*impl, 0, /*timestamp=*/2);
    wait_slot_state(
        *impl, [&] { return impl->drain_task->slot_buffers[0].parked.timestamp == 2; });

    impl->frame_done(0);
    poll_drain_until(*impl, [&] { return listener.clear_count() >= 1; });
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.clear_count() >= 2; }, NEGATIVE_WINDOW));
}

TEST(ArtworkChannelClear, StreamEndOnTopOfUnackedChannelClearFiresAgain) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // A per-channel clear is delivered and left un-acked, e.g. the consumer is running a fade-out.
    send_clear(*impl, 0);
    poll_drain_until(*impl, [&] { return listener.clear_count() >= 1; });

    // The queue then ends. stream/end is a distinct lifecycle event, so it fires on_image_clear()
    // again rather than being swallowed because a clear is already outstanding: it supersedes
    // that clear the same way it supersedes an un-acked frame.
    impl->handle_stream_ring_event(ArtworkEventType::STREAM_END);
    listener.wait_until([&] { return listener.clears.size() >= 2; });

    // Superseded, not stacked: exactly one ack is owed for the two clears, so a single frame_done()
    // releases the gate for the next stream's first frame.
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));
    send_frame(*impl, 0, 'A');
    EXPECT_TRUE(listener.never_within([&] { return !listener.decodes.empty(); }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decode_marker_at(0), 'A');
}

TEST(ArtworkChannelClear, ClearIgnoredWithoutActiveStream) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(false));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());

    // No stream/start yet, so handle_binary()'s stream_active guard rejects the message before any
    // clear-specific handling runs. That guard is not new, so unlike the tests above this one does
    // not fail without the per-channel clear path: it pins that the clear path stays behind the
    // guard rather than short-circuiting ahead of it.
    send_clear(*impl, 0);
    EXPECT_TRUE(
        poll_drain_never(*impl, [&] { return listener.clear_count() >= 1; }, NEGATIVE_WINDOW));
    EXPECT_EQ(listener.clear_count(), 0U);
}

// ============================================================================
// frame_done() edge cases
// ============================================================================

TEST(ArtworkFrameDoneGate, FrameDoneNoOpWhenIdle) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // Nothing outstanding: both calls must be safe no-ops (including the out-of-range slot).
    impl->frame_done(0);
    impl->frame_done(99);

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    EXPECT_EQ(listener.decode_marker_at(0), 'A');
}

// ============================================================================
// Stream restart interaction with the gate
// ============================================================================

TEST(ArtworkFrameDoneGate, RestartReleasesUndisplayedDecode) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    // Deliberately never call drain_events() here: A's display must never fire.

    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));  // restart

    // Give the decode thread's async display hand-off a chance to land, then confirm the restart
    // (epoch bump + display_slot reset) keeps it from ever reaching the listener.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    impl->drain_events();
    impl->drain_events();
    EXPECT_EQ(listener.display_count(), 0U);

    // The DECODE_DELIVERED gate was auto-released by the restart: B decodes without any ack.
    send_frame(*impl, 0, 'B');
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

TEST(ArtworkFrameDoneGate, RestartKeepsPresentedGate) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });
    poll_drain_until(*impl, [&] { return listener.display_count() >= 1; });

    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));  // restart; PRESENTED stays armed

    send_frame(*impl, 0, 'B');
    EXPECT_TRUE(
        listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    impl->frame_done(0);
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'B');
}

// ============================================================================
// Impl stop()/start(): the decode thread is joined and restarted between sessions
// ============================================================================

namespace {

// A RecordingListener whose on_image_decode() parks until release(), so a test can hold the
// decode thread inside a callback while it queues more work behind it.
class BlockingListener : public RecordingListener {
public:
    void on_image_decode(uint8_t slot, const uint8_t* data, size_t length,
                         SendspinImageFormat format) override {
        RecordingListener::on_image_decode(slot, data, length, format);
        std::unique_lock<std::mutex> lock(this->gate_mutex_);
        this->gate_cv_.wait(lock, [this] { return this->released_; });
    }

    void release() {
        {
            std::lock_guard<std::mutex> lock(this->gate_mutex_);
            this->released_ = true;
        }
        this->gate_cv_.notify_all();
    }

private:
    std::mutex gate_mutex_;
    std::condition_variable gate_cv_;
    bool released_{false};
};

}  // namespace

// stop() joins the decode thread and discards the notifications it never took, and start()
// clears the stop command, so a restarted role decodes fresh frames without replaying the
// previous session's. The thread is held inside frame A's decode while frame B is queued behind
// it and the stop is signalled; on release it exits at its command check without taking B. The
// stream is deliberately not restarted after start(): a stream restart bumps the epoch that
// would make a replayed B stale on its own, and this test is about the queue reset.
TEST(ArtworkRestart, StopDiscardsQueuedFramesAndStartDecodesNewOnes) {
    BlockingListener listener;
    auto impl = make_impl(make_two_ungated_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    send_frame(*impl, 0, 'A');
    listener.wait_until([&] { return listener.decodes.size() >= 1; });  // Thread parked in A
    send_frame(*impl, 1, 'B');                                          // Queued behind A

    ASSERT_TRUE(impl->signal_stop());
    listener.release();
    impl->stop();
    EXPECT_EQ(listener.decode_count(), 1U);

    ASSERT_TRUE(impl->start());
    // B was discarded with the old session, not replayed by the new thread.
    EXPECT_TRUE(listener.never_within([&] { return listener.decodes.size() >= 2; }, NEGATIVE_WINDOW));

    // The new thread decodes: the stop command did not survive the restart.
    send_frame(*impl, 1, 'C');
    listener.wait_until([&] { return listener.decodes.size() >= 2; });
    EXPECT_EQ(listener.decode_marker_at(1), 'C');
}

// ============================================================================
// Reentrant frame_done() from inside on_image_display()
// ============================================================================

TEST(ArtworkFrameDoneGate, FrameDoneReentrantFromDisplay) {
    RecordingListener listener;
    auto impl = make_impl(make_single_slot_config(true));
    listener.frame_done_on_display = true;
    listener.impl = impl.get();
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // Each image is displayed before the next is announced, so neither is discarded as the
    // other's pending image: both must decode and display on the reentrant ack alone, with no
    // external frame_done() call and no deadlock.
    send_frame(*impl, 0, 'A');
    poll_drain_until(
        *impl, [&] { return listener.decode_count() >= 1 && listener.display_count() >= 1; });
    send_frame(*impl, 0, 'B');
    poll_drain_until(
        *impl, [&] { return listener.decode_count() >= 2 && listener.display_count() >= 2; });

    EXPECT_TRUE(listener.has_decoded_marker(0, 'A'));
    EXPECT_TRUE(listener.has_decoded_marker(0, 'B'));
    EXPECT_EQ(listener.display_count(), 2U);
}

// ============================================================================
// One gated slot must not affect an ungated slot
// ============================================================================

TEST(ArtworkFrameDoneGate, UngatedSlotUnaffectedBesideGatedSlot) {
    RecordingListener listener;
    auto impl = make_impl(make_two_slot_config());
    impl->listener = &listener;
    ASSERT_TRUE(impl->start());
    impl->handle_stream_start(ServerArtworkStreamObject{}, live_generation(*impl));

    // wait_until()'s predicate runs under RecordingListener::mutex (via condition_variable's
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
    listener.wait_until([&] { return count_for_slot(0) >= 1; });

    // Slot 1 keeps decoding every frame freely, ungated by slot 0's outstanding delivery. Each
    // send waits for its own decode before the next is sent: slot 1 is double-buffered like any
    // other slot (see SlotBuffer::write_generation), so three back-to-back writes with nothing
    // draining them could legitimately overwrite an unclaimed buffer and drop a frame: a
    // real (and separately-covered) property of the double-buffering scheme, not of the ack
    // gate this test is about, so it must not be exercised here.
    send_frame(*impl, 1, 'X');
    listener.wait_until([&] { return count_for_slot(1) >= 1; });
    send_frame(*impl, 1, 'Y');
    listener.wait_until([&] { return count_for_slot(1) >= 2; });
    send_frame(*impl, 1, 'Z');
    listener.wait_until([&] { return count_for_slot(1) >= 3; });

    EXPECT_EQ(listener.decode_count_for_slot(0), 1U);
}

// ============================================================================
// merge_artwork_display_update: the cross-thread latest-wins accumulation the decode thread runs
// under the Inbox mutex. Pure function, so tested directly: reaching it end to end needs two
// same-slot deliveries to accumulate before the main loop takes the slot, and the integration
// tests above all run without a connection (client_ts == 0), so every folded-in entry fires in
// the same drain_events() call that folds it in and nothing is ever left pending to replace.
// ============================================================================

namespace {

// A single-slot delta shaped like the one process_notification() publishes.
ArtworkDisplayUpdate make_delta(uint8_t slot, int64_t timestamp, uint32_t epoch, bool is_clear) {
    ArtworkDisplayUpdate delta{};
    const auto bit = static_cast<uint8_t>(1U << slot);
    delta.timestamps[slot] = timestamp;
    delta.epochs[slot] = epoch;
    delta.valid_mask = bit;
    if (is_clear) {
        delta.clear_mask = bit;
    }
    return delta;
}

void merge_into(ArtworkDisplayUpdate& current, ArtworkDisplayUpdate delta) {
    ArtworkRole::Impl::merge_artwork_display_update(current, std::move(delta));
}

}  // namespace

TEST(ArtworkDisplayMerge, FrameAfterUndrainedClearResetsKind) {
    // The case the assigned-not-OR-ed clear_mask exists for: an item with no artwork is cleared
    // and the next item's frame lands before the main loop drains. The pending entry is now a
    // frame, so the bit must be reset: OR-ing it would fire on_image_clear() for a decoded
    // image, blanking the display and dropping the frame.
    ArtworkDisplayUpdate current{};
    merge_into(current, make_delta(0, 100, 7, /*is_clear=*/true));
    ASSERT_EQ(current.clear_mask, 0x01);

    merge_into(current, make_delta(0, 200, 8, /*is_clear=*/false));
    EXPECT_EQ(current.valid_mask, 0x01);
    EXPECT_EQ(current.clear_mask, 0x00);
    EXPECT_EQ(current.timestamps[0], 200);
    EXPECT_EQ(current.epochs[0], 8U);
}

TEST(ArtworkDisplayMerge, ClearAfterUndrainedFrameSetsKind) {
    ArtworkDisplayUpdate current{};
    merge_into(current, make_delta(0, 100, 7, /*is_clear=*/false));
    ASSERT_EQ(current.clear_mask, 0x00);

    merge_into(current, make_delta(0, 200, 7, /*is_clear=*/true));
    EXPECT_EQ(current.valid_mask, 0x01);
    EXPECT_EQ(current.clear_mask, 0x01);
    EXPECT_EQ(current.timestamps[0], 200);
}

TEST(ArtworkDisplayMerge, SameKindReplacementsKeepTheirKind) {
    ArtworkDisplayUpdate clears{};
    merge_into(clears, make_delta(0, 100, 7, /*is_clear=*/true));
    merge_into(clears, make_delta(0, 200, 7, /*is_clear=*/true));
    EXPECT_EQ(clears.clear_mask, 0x01);
    EXPECT_EQ(clears.timestamps[0], 200);

    ArtworkDisplayUpdate frames{};
    merge_into(frames, make_delta(0, 100, 7, /*is_clear=*/false));
    merge_into(frames, make_delta(0, 200, 7, /*is_clear=*/false));
    EXPECT_EQ(frames.clear_mask, 0x00);
    EXPECT_EQ(frames.timestamps[0], 200);
}

TEST(ArtworkDisplayMerge, OtherSlotsAreUntouched) {
    // Latest-wins is per slot: a delta carries exactly one slot's bit and must leave every other
    // slot's accumulated entry (timestamp, epoch, and kind alike) alone.
    ArtworkDisplayUpdate current{};
    merge_into(current, make_delta(1, 100, 7, /*is_clear=*/true));
    merge_into(current, make_delta(0, 200, 8, /*is_clear=*/false));

    EXPECT_EQ(current.valid_mask, 0x03);
    EXPECT_EQ(current.clear_mask, 0x02);
    EXPECT_EQ(current.timestamps[1], 100);
    EXPECT_EQ(current.epochs[1], 7U);
    EXPECT_EQ(current.timestamps[0], 200);
    EXPECT_EQ(current.epochs[0], 8U);

    // And the reverse: slot 0's clear must not disturb slot 1's pending frame.
    ArtworkDisplayUpdate reverse{};
    merge_into(reverse, make_delta(1, 100, 7, /*is_clear=*/false));
    merge_into(reverse, make_delta(0, 200, 7, /*is_clear=*/true));
    EXPECT_EQ(reverse.valid_mask, 0x03);
    EXPECT_EQ(reverse.clear_mask, 0x01);
}

// ============================================================================
// display_overdue_us: the drain_events() display-deadline arithmetic, including the per-slot
// display_offset_ms shift and the lateness (>= 0 overdue) value reported to on_image_display.
// Pure function, so tested directly: the integration tests above all run without a connection
// (client_ts == 0), which bypasses the offset and lateness paths.
// ============================================================================

TEST(ArtworkDisplayDeadline, NoConnectionSentinelFiresImmediately) {
    // client_ts == 0 means no connection: due immediately with lateness 0, regardless of offset
    // in either direction (no deadline exists to be late against).
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(0, 0, 5'000'000), 0);
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(0, 1000, 5'000'000), 0);
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(0, -1000, 5'000'000), 0);
}

TEST(ArtworkDisplayDeadline, ZeroOffsetMatchesServerDeadline) {
    const int64_t now = 10'000'000;  // 10 s in us
    EXPECT_LT(ArtworkRole::Impl::display_overdue_us(now + 1, 0, now), 0);
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now, 0, now), 0);
    // 1 us past the deadline: due, with 1 us of lateness.
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now - 1, 0, now), 1);
}

TEST(ArtworkDisplayDeadline, PositiveOffsetFiresEarly) {
    const int64_t now = 10'000'000;
    // Deadline 900 ms in the future, offset 1000 ms: already due, 100 ms past the shifted
    // deadline.
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now + 900 * US_PER_MS, 1000, now),
              100 * US_PER_MS);
    // Deadline 1100 ms in the future, offset 1000 ms: still 100 ms out.
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now + 1100 * US_PER_MS, 1000, now),
              -100 * US_PER_MS);
    // Exact boundary: deadline minus offset equals now.
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now + 1000 * US_PER_MS, 1000, now), 0);
}

TEST(ArtworkDisplayDeadline, NegativeOffsetDelays) {
    const int64_t now = 10'000'000;
    // Deadline 500 ms in the past, but a -1000 ms offset holds it another 500 ms.
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now - 500 * US_PER_MS, -1000, now),
              -500 * US_PER_MS);
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now - 1000 * US_PER_MS, -1000, now), 0);
}

TEST(ArtworkDisplayDeadline, LatenessReportsPastDeadlineSlip) {
    const int64_t now = 10'000'000;
    // A frame that arrived 600 ms after its shifted deadline reports exactly that slip, letting
    // a consumer shorten its cross-fade (e.g. 2000 ms - 600 ms) so the fade still ends on time.
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now + 400 * US_PER_MS, 1000, now),
              600 * US_PER_MS);
    // A deadline far in the past reports a correspondingly huge lateness, the cue for a consumer
    // to snap instead of fading.
    EXPECT_EQ(ArtworkRole::Impl::display_overdue_us(now - 120'000 * US_PER_MS, 0, now),
              120'000 * US_PER_MS);
}

TEST(ArtworkDisplayDeadline, LargeOffsetDoesNotOverflow) {
    // INT32_MIN/MAX offsets must be widened to 64-bit before the ms-to-us multiply.
    const int64_t now = 10'000'000;
    EXPECT_GE(ArtworkRole::Impl::display_overdue_us(now + US_PER_MS, INT32_MAX, now), 0);
    EXPECT_LT(ArtworkRole::Impl::display_overdue_us(now - US_PER_MS, INT32_MIN, now), 0);
}

// ============================================================================
// display_lateness_ms: maps a due display's overdue microseconds to the lateness_ms passed to
// on_image_display(). Pure function; the integration tests above all run without a connection so
// only its client_ts == 0 branch is otherwise exercised.
// ============================================================================

TEST(ArtworkDisplayLateness, ZeroIsReservedForNoConnection) {
    // The one non-obvious invariant on_image_display() consumers rely on: lateness_ms == 0 means
    // "no connection" and nothing else. With a connection, a display firing under a millisecond
    // late must not truncate to 0 and collide with that sentinel (it is floored to 1 ms) while
    // a normal multi-millisecond slip passes through unchanged.
    EXPECT_EQ(ArtworkRole::Impl::display_lateness_ms(0, 0), 0u);                  // no connection
    EXPECT_EQ(ArtworkRole::Impl::display_lateness_ms(1, US_PER_MS - 1), 1u);      // connected, <1ms
    EXPECT_EQ(ArtworkRole::Impl::display_lateness_ms(1, 600 * US_PER_MS), 600u);  // connected slip
}

// ============================================================================
// client/hello and client/state channel reporting
// ============================================================================

// messaging.md "client/hello" defines no artwork support object, and roles/artwork/v1.md
// "client/state artwork object" carries the channels instead. The hello therefore lists the role
// and says nothing else about artwork.
TEST(ArtworkChannelReporting, HelloListsTheRoleWithoutChannels) {
    auto impl = make_impl(make_two_slot_config());

    ClientHelloMessage hello;
    impl->build_hello_fields(hello);

    ASSERT_EQ(hello.supported_roles.size(), 1u);
    EXPECT_EQ(hello.supported_roles[0], SendspinRole::ARTWORK);

    JsonDocument doc;
    ASSERT_FALSE(deserializeJson(doc, format_client_hello_message(&hello)));
    EXPECT_TRUE(doc["payload"]["artwork@v1_support"].isUnbound());
}

// The configured slots reach the client/state artwork object in configuration order, which is
// what makes the array index the channel number.
TEST(ArtworkChannelReporting, StateCarriesTheConfiguredChannelsInOrder) {
    auto impl = make_impl(make_two_slot_config());

    ClientStateMessage state;
    impl->build_state_fields(state);

    ASSERT_TRUE(state.artwork.has_value());
    ASSERT_EQ(state.artwork->channels.size(), 2u);
    EXPECT_EQ(state.artwork->channels[0].source, SendspinImageSource::ALBUM);
    EXPECT_EQ(state.artwork->channels[1].source, SendspinImageSource::ARTIST);
    EXPECT_EQ(state.artwork->channels[0].width, 100);
    EXPECT_EQ(state.artwork->channels[0].height, 100);
}

// Control: a role configured with no channels has nothing to report, so it neither lists itself
// nor contributes an artwork object a server would have to interpret as an empty channel list.
TEST(ArtworkChannelReporting, NoConfiguredChannelsReportsNothing) {
    auto impl = make_impl(ArtworkRoleConfig{});

    ClientHelloMessage hello;
    impl->build_hello_fields(hello);
    EXPECT_TRUE(hello.supported_roles.empty());

    ClientStateMessage state;
    impl->build_state_fields(state);
    EXPECT_FALSE(state.artwork.has_value());
}

TEST(ArtworkDisplayLateness, HugeLatenessSaturatesAtUint32Max) {
    // A pathological far-past deadline can exceed UINT32_MAX ms (~49 days); the ms value must
    // saturate there rather than wrap when narrowed to uint32_t.
    EXPECT_EQ(ArtworkRole::Impl::display_lateness_ms(1, INT64_MAX), UINT32_MAX);
}
