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
#include "crypto/constants.h"
#include "platform/logging.h"
#include "platform/thread.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

#include <algorithm>
#include <cstring>
#include <iterator>

static const char* const TAG = "sendspin.artwork";

// ============================================================================
// Constants
// ============================================================================

/// @brief Largest artwork message, in bytes: one Noise transport message without fragmentation,
/// per roles/artwork/v1.md "Artwork (Binary)"
static constexpr size_t ARTWORK_MAX_MESSAGE_SIZE = sendspin::MAX_TRANSPORT_PLAINTEXT;

/// @brief Size of an announce message: type, flags, the 8-byte timestamp, the 4-byte total_size
static constexpr size_t ARTWORK_ANNOUNCE_SIZE = 14;

/// @brief Flags byte bits: a part sets neither cancel nor announce, and bits 2-7 must be zero
static constexpr uint8_t ARTWORK_FLAG_CANCEL = 0x01;
static constexpr uint8_t ARTWORK_FLAG_ANNOUNCE = 0x02;
static constexpr uint8_t ARTWORK_FLAGS_RESERVED = 0xFC;

/// @brief Fallback wakeup interval for the decode thread's blocking queue receive. Stop and
/// parked-slot rechecks wake the receive immediately via wake_receiver(), so this is only a
/// safety net against a missed wake: long enough to keep an idle thread asleep, short enough
/// that a wake bug degrades to a slow reaction rather than a hang.
static constexpr uint32_t DRAIN_RECEIVE_TIMEOUT_MS = 5000U;

// Event flag bits for decode thread signaling
static constexpr uint32_t COMMAND_STOP = (1 << 0);

// ============================================================================
// Big-endian helpers
// ============================================================================

/// @brief Swaps bytes of a big-endian 64-bit value to host byte order
static int64_t be64_to_host(const uint8_t* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return static_cast<int64_t>(val);
}

/// @brief Swaps bytes of a big-endian 32-bit value to host byte order
static uint32_t be32_to_host(const uint8_t* bytes) {
    uint32_t val = 0;
    for (int i = 0; i < 4; ++i) {
        val = (val << 8) | bytes[i];
    }
    return val;
}

namespace sendspin {

// ============================================================================
// ArtworkRole::Impl lifecycle
// ============================================================================

ArtworkRole::Impl::Impl(ArtworkRoleConfig config, SendspinClient* client)
    : config(std::move(config)),
      client(client),
      drain_task(std::make_unique<DrainTask>()),
      event_state(std::make_unique<EventState>()) {
    // The array index is authoritative for channel/slot mapping: client/state reports channels
    // in this->artwork_channels order, and handle_binary looks up this->config.preferred_formats
    // by index to match.
    if (this->config.preferred_formats.size() > ARTWORK_MAX_SLOTS) {
        SS_LOGW(TAG, "Artwork configured with %zu channels, truncating to %zu",
                this->config.preferred_formats.size(), ARTWORK_MAX_SLOTS);
        this->config.preferred_formats.resize(ARTWORK_MAX_SLOTS);
    }
    for (size_t i = 0; i < this->config.preferred_formats.size(); ++i) {
        const auto& pref = this->config.preferred_formats[i];
        this->artwork_channels.push_back({pref.source, pref.format, pref.width, pref.height});
        // Said once here rather than once per refused image: a channel budgeted 0 bytes is
        // still announced to the server.
        if (pref.max_image_bytes == 0 && pref.source != SendspinImageSource::NONE) {
            SS_LOGW(TAG, "Artwork channel %zu holds no image: max_image_bytes is 0", i);
        }
    }
    this->drain_task->notify_queue.create(8);
}

ArtworkRole::Impl::~Impl() {
    this->stop();
}

void ArtworkRole::Impl::attach_inbox(Inbox& inbox) {
    this->inbox = &inbox;
    this->event_state->display_slot.bind(inbox, INBOX_TOPIC_ARTWORK_DISPLAY);
}

bool ArtworkRole::Impl::start() {
    if (!this->drain_task || !this->drain_task->notify_queue.is_created()) {
        SS_LOGE(TAG, "Failed to start artwork: decode task not initialized");
        return false;
    }
    if (this->drain_task->drain_thread.joinable()) {
        return true;  // Already running
    }
    if (!this->drain_task->event_flags.is_created() && !this->drain_task->event_flags.create()) {
        SS_LOGE(TAG, "Failed to create artwork event flags");
        return false;
    }

    // The flags survive a stop()/start() cycle, and a command signalled between the join and this
    // start (cleanup() on a stopped role) is still set. Clear the whole group so the new thread's
    // first wait() starts from a clean command state whatever bits the role defines.
    this->drain_task->event_flags.clear_all();

    platform_configure_thread("SsArt", 4096, static_cast<int>(this->config.priority),
                              this->config.psram_stack);
    this->drain_task->drain_thread = std::thread(drain_thread_func, this);
    return true;
}

bool ArtworkRole::Impl::signal_stop() const {
    if (!this->drain_task || !this->drain_task->drain_thread.joinable()) {
        return false;
    }
    // Set the flag before waking: the thread re-checks its command flags at the top of every
    // loop iteration, so this ordering guarantees it observes the stop as soon as the wake
    // pulls it out of its blocking queue receive.
    this->drain_task->event_flags.set(COMMAND_STOP);
    this->drain_task->notify_queue.wake_receiver();
    return true;
}

void ArtworkRole::Impl::stop() const {
    if (!this->signal_stop()) {
        return;
    }
    this->drain_task->drain_thread.join();

    // Joined, so this is the queue's only consumer: discard notifications the old thread never
    // took, so a restart does not decode the previous session's images.
    this->drain_task->notify_queue.reset();

    // ...and the only reader of the image buffers, so every one of them is idle now.
    {
        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        for (auto& sb : this->drain_task->slot_buffers) {
            sb.drain_active = false;
        }
    }
    this->release_idle_slot_buffers();
}

void ArtworkRole::Impl::release_idle_slot_buffers() const {
    // Two buffers per slot, each grown to the largest image that channel ever received and held
    // until the role is destroyed unless they are handed back here: 2 * max_image_bytes per
    // configured channel, 1 MiB at the defaults. A stopped or deactivated role is not showing
    // anything, so it holds nothing; the next stream/start re-announces every channel and
    // begin_transfer() allocates once per channel, off any timing-critical path.
    //
    // The buffer the decode thread is reading is left alone: drain_active/drain_buf_idx name it
    // under this mutex, and it is released by the next call, once that decode has finished.
    std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
    for (auto& sb : this->drain_task->slot_buffers) {
        for (size_t i = 0; i < std::size(sb.buffers); ++i) {
            if (sb.drain_active && sb.drain_buf_idx == i) {
                continue;
            }
            sb.buffers[i] = PlatformBuffer{};
        }
    }
}

void ArtworkRole::Impl::build_hello_fields(ClientHelloMessage& msg) const {
    if (this->artwork_channels.empty()) {
        return;
    }
    // messaging.md "client/hello" defines no artwork support object: the role is listed here and
    // the channels it wants are reported in client/state (see build_state_fields).
    msg.supported_roles.push_back(SendspinRole::ARTWORK);
}

void ArtworkRole::Impl::build_state_fields(ClientStateMessage& msg) const {
    if (this->artwork_channels.empty()) {
        return;
    }

    ClientArtworkStateObject artwork_state{};
    artwork_state.channels = this->artwork_channels;
    msg.artwork = std::move(artwork_state);
}

// ============================================================================
// Display-deadline and ack-gate helpers (used from the protocol task, decode, and main threads)
// ============================================================================

void ArtworkRole::Impl::merge_artwork_display_update(ArtworkDisplayUpdate& current,
                                                     ArtworkDisplayUpdate&& delta) {
    current.valid_mask |= delta.valid_mask;
    for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
        const uint8_t bit = static_cast<uint8_t>(1U << slot);
        if (delta.valid_mask & bit) {
            current.timestamps[slot] = delta.timestamps[slot];
            current.epochs[slot] = delta.epochs[slot];
            // clear_mask is assigned, not OR-ed: it says what kind of delivery this slot's
            // (latest-wins) pending entry is, so a frame arriving after an undrained clear must
            // reset the bit just as a clear after an undrained frame sets it.
            if (delta.clear_mask & bit) {
                current.clear_mask |= bit;
            } else {
                current.clear_mask &= static_cast<uint8_t>(~bit);
            }
        }
    }
}

int64_t ArtworkRole::Impl::display_overdue_us(int64_t client_ts, int32_t display_offset_ms,
                                              int64_t now) {
    // get_client_time returns 0 when there is no current connection. Without a connection we
    // cannot honor the server-clock deadline, so fire immediately rather than starving the
    // listener; the lateness is 0 by definition since no deadline exists. The check must precede
    // the offset shift so the sentinel is never mistaken for a real deadline.
    if (client_ts == 0) {
        return 0;
    }
    // Positive display_offset_ms fires the display early (mirroring
    // PlayerRoleConfig::fixed_delay_us), negative delays it; see ImageSlotPreference.
    return now - (client_ts - static_cast<int64_t>(display_offset_ms) * US_PER_MS);
}

uint32_t ArtworkRole::Impl::display_lateness_ms(int64_t client_ts, int64_t overdue_us) {
    // No connection: no deadline exists, so report the documented 0 sentinel (see
    // display_overdue_us and on_image_display's contract).
    if (client_ts == 0) {
        return 0;
    }
    // Connected: floor at 1 ms. A display firing under a millisecond late truncates to 0 ms,
    // which would collide with the no-connection sentinel above; on-time displays must report a
    // small nonzero value, never exactly 0. Clamp the top so a huge lateness (~49 days) saturates
    // instead of wrapping.
    int64_t ms = std::min<int64_t>(overdue_us / US_PER_MS, UINT32_MAX);
    return static_cast<uint32_t>(std::max<int64_t>(ms, 1));
}

bool ArtworkRole::Impl::ack_enabled(uint8_t slot) const {
    return slot < this->config.preferred_formats.size() &&
           this->config.preferred_formats[slot].require_frame_done;
}

void ArtworkRole::Impl::wake_drain_thread() const {
    this->drain_task->notify_queue.wake_receiver();
}

// ============================================================================
// Binary handling (protocol task)
// ============================================================================

uint32_t ArtworkRole::Impl::image_cap(uint8_t slot) const {
    // A channel the role never declared never asked for an image, so it holds nothing.
    if (slot >= this->config.preferred_formats.size()) {
        return 0;
    }
    return this->config.preferred_formats[slot].max_image_bytes;
}

SendspinImageFormat ArtworkRole::Impl::image_format(uint8_t slot) const {
    if (slot >= this->config.preferred_formats.size()) {
        return SendspinImageFormat::JPEG;
    }
    return this->config.preferred_formats[slot].format;
}

void ArtworkRole::Impl::enqueue_notification(const ArtworkNotification& notif) const {
    ArtworkNotification stamped = notif;
    stamped.teardown_generation = this->cleanup_generation.load(std::memory_order_acquire);
    if (!this->drain_task->notify_queue.send(stamped, 0)) {
        SS_LOGW(TAG, "Artwork notify queue full; dropping %s for slot %u",
                notif.data_length > 0 ? "image" : "clear", notif.slot);
    }
}

void ArtworkRole::Impl::discard_all_pending() {
    std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
    this->streamed_channels.reset();
    this->transfer = ArtworkTransfer{};
    for (auto& epoch : this->slot_epochs) {
        epoch.fetch_add(1, std::memory_order_relaxed);
    }
}

void ArtworkRole::Impl::discard_pending(uint8_t slot) {
    std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
    if (this->transfer.in_flight && this->transfer.slot == slot) {
        this->transfer = ArtworkTransfer{};
    }
    this->slot_epochs[slot].fetch_add(1, std::memory_order_relaxed);
}

ArtworkRole::Impl::TransferOutcome ArtworkRole::Impl::begin_transfer(
    uint8_t slot, const uint8_t* body, ArtworkNotification& complete) {
    const int64_t timestamp = be64_to_host(body + 1);
    const uint32_t total_size = be32_to_host(body + 1 + 8);

    std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
    // roles/artwork/v1.md "Artwork (Binary)": "The server MUST NOT announce an image, on any
    // channel, while a transfer is in flight".
    if (this->transfer.in_flight) {
        SS_LOGW(TAG, "Artwork announce for slot %u while slot %u is mid-transfer", slot,
                this->transfer.slot);
        return TransferOutcome::MALFORMED;
    }

    // "An announce discards that channel's pending image."
    this->slot_epochs[slot].fetch_add(1, std::memory_order_relaxed);
    const uint32_t epoch = this->slot_epochs[slot].load(std::memory_order_relaxed);

    // "An announce with total_size 0 completes immediately, with no parts", and is how the server
    // clears a channel. There are no bytes to stage, so no buffer is claimed and the notification
    // travels with data_length == 0 (see ArtworkNotification).
    if (total_size == 0) {
        complete =
            ArtworkNotification{slot, 0, 0, timestamp, this->image_format(slot), 0, epoch, 0};
        return TransferOutcome::COMPLETED;
    }

    // "During an active stream, unavailable clients SHOULD discard otherwise valid image data and
    // MUST NOT close solely for its arrival": an image the role will not hold is refused here,
    // before a byte of it is allocated, and the transfer runs to its end holding nothing. A role
    // with no listener has nowhere to put an image either, so it takes the same path.
    const uint32_t cap = this->image_cap(slot);
    if (total_size > cap || this->listener == nullptr) {
        if (this->listener != nullptr) {
            SS_LOGW(TAG,
                    "Artwork image of %" PRIu32 " bytes for slot %u exceeds its %" PRIu32
                    " byte cap",
                    total_size, slot, cap);
        }
        this->transfer = ArtworkTransfer{.timestamp = timestamp,
                                         .total_size = total_size,
                                         .in_flight = true,
                                         .slot = slot,
                                         .discarding = true};
        return TransferOutcome::ACCEPTED;
    }

    auto& sb = this->drain_task->slot_buffers[slot];
    uint8_t write_idx = sb.write_idx;
    // Claim the other buffer if the decode thread is reading this one.
    if (sb.drain_active && sb.drain_buf_idx == write_idx) {
        write_idx ^= 1;
    }

    // allocate() rather than realloc(): none of the buffer's contents survive a transfer, so
    // there is nothing to copy forward. The buffer is only ever grown, so a channel settles at
    // its largest image and later transfers reuse it without touching the allocator. Image data
    // prefers SPIRAM, where it is decoded from once and never touched on a timing-critical
    // path.
    auto& buf = sb.buffers[write_idx];
    if (buf.size() < total_size && !buf.allocate(total_size, MemoryLocation::PREFER_EXTERNAL)) {
        SS_LOGE(TAG, "Failed to allocate artwork buffer for slot %u (%" PRIu32 " bytes)", slot,
                total_size);
        this->transfer = ArtworkTransfer{.timestamp = timestamp,
                                         .total_size = total_size,
                                         .in_flight = true,
                                         .slot = slot,
                                         .discarding = true};
        return TransferOutcome::ACCEPTED;
    }

    // Bump this buffer's generation so a notification naming it from an earlier transfer is
    // recognized as stale, then flip write_idx so the next transfer on this slot claims the
    // other buffer and leaves this one to the decode thread.
    sb.write_generation[write_idx]++;
    sb.write_idx = write_idx ^ 1;
    this->transfer = ArtworkTransfer{.timestamp = timestamp,
                                     .total_size = total_size,
                                     .generation = sb.write_generation[write_idx],
                                     .in_flight = true,
                                     .slot = slot,
                                     .buffer_idx = write_idx};
    return TransferOutcome::ACCEPTED;
}

ArtworkRole::Impl::TransferOutcome ArtworkRole::Impl::append_part(uint8_t slot, const uint8_t* part,
                                                                  size_t part_len,
                                                                  ArtworkNotification& complete) {
    // Hold the slot mutex across the whole read-modify-write, the memcpy included, so the decode
    // thread can never observe a buffer mid-write (torn image) and can never have a buffer stolen
    // out from under it while it still owns the notification for that generation.
    std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
    auto& t = this->transfer;
    // roles/artwork/v1.md "Artwork (Binary)": "a part received with no transfer in flight or on
    // a channel other than the in-flight transfer's" is a malformed sequence.
    if (!t.in_flight || t.slot != slot) {
        SS_LOGW(TAG, "Artwork part for slot %u with no transfer in flight on it", slot);
        return TransferOutcome::MALFORMED;
    }
    // "a part whose data would extend past total_size" is a malformed sequence.
    if (part_len > static_cast<size_t>(t.total_size - t.received)) {
        SS_LOGW(TAG, "Artwork part of %zu bytes overruns the %" PRIu32 " byte image on slot %u",
                part_len, t.total_size, slot);
        return TransferOutcome::MALFORMED;
    }

    if (!t.discarding) {
        std::memcpy(this->drain_task->slot_buffers[slot].buffers[t.buffer_idx].data() + t.received,
                    part, part_len);
    }
    t.received += static_cast<uint32_t>(part_len);
    if (t.received < t.total_size) {
        return TransferOutcome::ACCEPTED;
    }

    // "the transfer is complete when the received data reaches total_size".
    const bool discarding = t.discarding;
    complete = ArtworkNotification{slot,
                                   t.buffer_idx,
                                   t.total_size,
                                   t.timestamp,
                                   this->image_format(slot),
                                   t.generation,
                                   this->slot_epochs[slot].load(std::memory_order_relaxed),
                                   0};
    t = ArtworkTransfer{};
    return discarding ? TransferOutcome::ACCEPTED : TransferOutcome::COMPLETED;
}

bool ArtworkRole::Impl::handle_binary(uint8_t slot, const uint8_t* data, size_t len) {
    // roles/artwork/v1.md "Artwork (Binary)" splits its closing rules in two. The
    // malformed-message rules judge the shape of the bytes alone and are not scoped to a stream,
    // so they run first; the malformed-sequence rules are scoped to an active artwork stream and
    // run below the stream gate.
    if (len < 1 || len + 1 > ARTWORK_MAX_MESSAGE_SIZE) {
        SS_LOGW(TAG, "Artwork message of %zu bytes is outside the 2 to %zu byte range", len + 1,
                ARTWORK_MAX_MESSAGE_SIZE);
        return false;
    }

    const uint8_t flags = data[0];
    if ((flags & ARTWORK_FLAGS_RESERVED) != 0) {
        SS_LOGW(TAG, "Artwork message sets reserved flag bits (0x%02X)", flags);
        return false;
    }
    const bool is_cancel = (flags & ARTWORK_FLAG_CANCEL) != 0;
    const bool is_announce = (flags & ARTWORK_FLAG_ANNOUNCE) != 0;
    if (is_cancel && is_announce) {
        SS_LOGW(TAG, "Artwork message sets both the cancel and announce flags");
        return false;
    }
    if (is_announce && len + 1 != ARTWORK_ANNOUNCE_SIZE) {
        SS_LOGW(TAG, "Artwork announce of %zu bytes is not %zu bytes", len + 1,
                ARTWORK_ANNOUNCE_SIZE);
        return false;
    }
    if (is_cancel && len != 1) {
        SS_LOGW(TAG, "Artwork cancel of %zu bytes carries a body", len + 1);
        return false;
    }

    // roles/artwork/v1.md "Artwork (Binary)": "Servers MUST NOT send artwork messages outside an
    // active artwork stream." One that arrives anyway is ignored rather than closed on: the
    // sequence rules below are scoped to an active stream.
    if (!this->stream_active) {
        return true;
    }
    // Unreachable: the caller decodes the slot from binary message IDs 8-11.
    if (slot >= ARTWORK_MAX_SLOTS) {
        return true;
    }

    if (is_cancel) {
        // "Cancel message: ... It discards the channel's pending image, taking effect
        // immediately; the current image is unaffected."
        this->discard_pending(slot);
        return true;
    }

    ArtworkNotification complete{};
    const TransferOutcome outcome = is_announce
                                        ? this->begin_transfer(slot, data, complete)
                                        : this->append_part(slot, data + 1, len - 1, complete);
    if (outcome == TransferOutcome::MALFORMED) {
        return false;
    }
    if (outcome == TransferOutcome::COMPLETED) {
        // Enqueued outside the slot mutex: the decode thread takes that mutex as soon as it
        // dequeues, so handing off under it would make the two threads contend needlessly.
        this->enqueue_notification(complete);
    }
    return true;
}

// ============================================================================
// Stream lifecycle (protocol task)
// ============================================================================

void ArtworkRole::Impl::handle_stream_start(const ServerArtworkStreamObject& stream,
                                            uint32_t generation) {
    if (stream.channels.has_value()) {
        const auto& server_channels = stream.channels.value();
        if (server_channels.size() != this->artwork_channels.size()) {
            SS_LOGW(TAG, "Artwork channel count mismatch: server sent %zu, expected %zu",
                    server_channels.size(), this->artwork_channels.size());
        }
        size_t n = std::min(server_channels.size(), this->artwork_channels.size());
        for (size_t i = 0; i < n; ++i) {
            const auto& srv = server_channels[i];
            const auto& req = this->artwork_channels[i];
            if (srv.source.has_value() && srv.source.value() != req.source) {
                SS_LOGW(TAG, "Artwork channel %zu source mismatch", i);
            }
            if (srv.format.has_value() && srv.format.value() != req.format) {
                SS_LOGW(TAG, "Artwork channel %zu format mismatch", i);
            }
            if (srv.width.has_value() && srv.width.value() != req.width) {
                SS_LOGW(TAG,
                        "Artwork channel %zu width mismatch: server %" PRIu16 ", expected %" PRIu16,
                        i, srv.width.value(), req.width);
            }
            if (srv.height.has_value() && srv.height.value() != req.height) {
                SS_LOGW(TAG,
                        "Artwork channel %zu height mismatch: server %" PRIu16
                        ", expected %" PRIu16,
                        i, srv.height.value(), req.height);
            }
        }
    }

    // No display_slot.reset() here: it would discard the pending display of every channel,
    // including the unchanged ones this stream/start must leave alone. A display published by
    // the decode thread carries the epoch it was decoded under, so drain_events() drops the ones
    // whose channel moved on whether or not they have been folded into the main-thread holds yet.
    {
        // roles/artwork/v1.md "stream/start artwork object": "A stream/start that changes a
        // channel's configuration likewise discards that channel's pending image, and the server
        // re-sends the image if it still applies." A channel the server left alone keeps the
        // image it already scheduled, which the server will neither cancel nor re-send. Bumping
        // the changed channels' epochs is the discard (see slot_epochs), and it also makes any
        // notification still queued for them stale to the decode thread.
        //
        // The comparison and the store of the new array are inside the lock because
        // streamed_channels is also cleared by cleanup(), which stop() runs on the main loop and
        // the decode thread's slot reads share.
        //
        // A transfer in flight ends here only if its channel changed; the server cancels those
        // first (roles/artwork/v1.md "Artwork (Binary)"), and one on an unchanged channel
        // continues.
        //
        // Release a changed channel's DECODE_DELIVERED ack gate: its epoch was just bumped, so
        // that decode's eventual display can no longer fire, and leaving the gate armed would
        // wedge the slot forever. PRESENTED must stay armed: that delivery has already reached
        // the consumer, which may still be mid-fade on it and owes the frame_done() that says so.
        // Protocol messages are serialized on the protocol task, so this runs before any of the
        // new stream's handle_binary() calls.
        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        // The stream is marked active inside this lock: cleanup() bumps the generation before
        // taking the same lock to discard, so a teardown that overtook this handler is seen
        // here, and one that lands afterwards clears what this sets.
        if (!this->accepts(generation)) {
            return;
        }
        this->stream_active = true;
        const uint8_t changed = this->changed_channel_mask(stream);
        this->streamed_channels = stream.channels;
        if ((changed & static_cast<uint8_t>(1U << this->transfer.slot)) != 0) {
            this->transfer = ArtworkTransfer{};
        }
        for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
            if ((changed & static_cast<uint8_t>(1U << slot)) == 0) {
                continue;
            }
            this->slot_epochs[slot].fetch_add(1, std::memory_order_relaxed);
            auto& sb = this->drain_task->slot_buffers[slot];
            sb.has_parked = false;
            if (sb.ack_state == SlotAckState::DECODE_DELIVERED) {
                sb.ack_state = SlotAckState::IDLE;
            }
        }
    }
}

uint8_t ArtworkRole::Impl::changed_channel_mask(const ServerArtworkStreamObject& stream) const {
    // Caller holds slot_mutex; see streamed_channels.
    constexpr uint8_t ALL_CHANNELS = (1U << ARTWORK_MAX_SLOTS) - 1U;
    // Without a channel array on one side or the other there is nothing to compare, so every
    // channel counts as changed. That covers the first stream/start of a connection, where no
    // channel has a pending image to lose anyway.
    if (!this->streamed_channels.has_value() || !stream.channels.has_value()) {
        return ALL_CHANNELS;
    }
    const auto& before = this->streamed_channels.value();
    const auto& now = stream.channels.value();

    uint8_t changed = 0;
    for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
        // roles/artwork/v1.md "stream/start artwork object": "The channels array is positional
        // from channel 0 and never longer than 4. A channel the array does not cover ... is not
        // streamed", so coverage differing between the two arrays is itself a change.
        const bool had = slot < before.size();
        const bool has = slot < now.size();
        if (had != has || (had && !same_channel(before[slot], now[slot]))) {
            changed |= static_cast<uint8_t>(1U << slot);
        }
    }
    return changed;
}

bool ArtworkRole::Impl::same_channel(const ServerArtworkChannelObject& a,
                                     const ServerArtworkChannelObject& b) {
    return a.source == b.source && a.format == b.format && a.width == b.width &&
           a.height == b.height;
}

void ArtworkRole::Impl::handle_stream_end(uint32_t generation) {
    this->stream_active = false;
    this->discard_all_pending();

    this->enqueue_stream_event(ArtworkEventType::STREAM_END, generation);
}

void ArtworkRole::Impl::enqueue_stream_event(ArtworkEventType event, uint32_t generation) const {
    push_event_or_log(this->inbox, InboxEventType::ARTWORK_STREAM, static_cast<uint8_t>(event), TAG,
                      "STREAM_END", generation);
}

// ============================================================================
// Event dispatch (main thread) - lifecycle via the ring, scheduled displays via polling
// ============================================================================

void ArtworkRole::Impl::handle_stream_ring_event(ArtworkEventType event) {
    switch (event) {
        case ArtworkEventType::STREAM_END:
            this->clear_every_channel();
            break;
    }
}

void ArtworkRole::Impl::clear_every_channel() {
    // Called from the ring drain in SendspinClient::drain_inbox() before this role's
    // drain_events() runs each tick, or from the catch-up that heads it, so dropping the holds
    // here cancels every display that predates the end. A display still in display_slot is left to
    // its slot epoch, which the end bumped (discard_all_pending()): one decoded before it is
    // dropped by the deadline check, and one decoded after it belongs to the next stream and fires
    // after these clears.
    this->held_display_mask = 0;
    this->held_display_clear = 0;
    {
        // A clear is itself a delivery that must be acked: it may drive a fade-out, and it
        // supersedes any un-acked frame for the slot, so exactly one frame_done() is owed
        // afterward regardless of what ack_state held before (a decode whose display will never
        // fire included). Drop any notification parked behind an un-acked frame: it is superseded
        // by the clear. Released before firing the callbacks below so a listener calling
        // frame_done() from inside on_image_clear() does not deadlock on this same mutex.
        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        // Sweep the whole fixed-size slot_buffers array (ARTWORK_MAX_SLOTS), matching
        // handle_stream_start(): ack_enabled() already gates the PRESENTED arm to configured ack
        // slots, and clearing has_parked on any others is a harmless reset (they never park).
        for (size_t i = 0; i < ARTWORK_MAX_SLOTS; ++i) {
            auto& sb = this->drain_task->slot_buffers[i];
            sb.has_parked = false;
            if (this->ack_enabled(static_cast<uint8_t>(i))) {
                sb.ack_state = SlotAckState::PRESENTED;
            }
        }
    }
    if (this->listener) {
        // Array index is the authoritative slot number; see the Impl constructor.
        for (size_t i = 0; i < this->config.preferred_formats.size(); ++i) {
            this->listener->on_image_clear(static_cast<uint8_t>(i));
        }
    }
}

void ArtworkRole::Impl::drain_events() {
    // Fold any newly published display update into the main-thread holds. Latest-wins per
    // artwork slot: a bit set in valid_mask means
    // timestamps[i] is a fresher pending display than whatever (if anything) slot i already
    // held. A stream end or teardown drained this tick has already run clear_every_channel()
    // before this call, so it has already cleared held_display_mask before we get here.
    ArtworkDisplayUpdate update{};
    bool have_update = false;
    const uint32_t generation = take_current_payload(*this, this->event_state->display_slot, update,
                                                     have_update, TAG, "artwork displays");
    if (!this->accepts(generation)) {
        return;
    }
    if (have_update) {
        for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
            const uint8_t bit = static_cast<uint8_t>(1U << slot);
            if (update.valid_mask & bit) {
                this->held_display_ts[slot] = update.timestamps[slot];
                this->held_display_epoch[slot] = update.epochs[slot];
                this->held_display_mask |= bit;
                // Assigned rather than OR-ed, for the same latest-wins reason as the cross-thread
                // merge: this slot's held entry has just been replaced wholesale, so the kind of
                // delivery it is must be replaced too. This mirrors
                // merge_artwork_display_update(), which is unit-tested directly
                // (ArtworkDisplayMerge); the two must stay in agreement.
                if (update.clear_mask & bit) {
                    this->held_display_clear |= bit;
                } else {
                    this->held_display_clear &= static_cast<uint8_t>(~bit);
                }
            }
        }
    }

    // No listener guard here: the epoch/deadline sweep below must still consume held bits so a
    // listener-less role does not report needs_drain() forever; only the callback itself is
    // gated on the listener.
    if (this->held_display_mask == 0) {
        return;
    }

    // Single now snapshot per tick, like today. No lock is held here (the slot value was
    // already taken above), unlike the old take_if predicate which ran under the shadow slot's
    // mutex.
    const int64_t now = platform_time_us();
    for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
        const uint8_t bit = static_cast<uint8_t>(1U << slot);
        if (!(this->held_display_mask & bit)) {
            continue;
        }
        // Drop a display whose channel has since moved past it: the epoch bump cannot reach these
        // main-thread holds to cancel the display directly (see held_display_epoch).
        if (this->held_display_epoch[slot] !=
            this->slot_epochs[slot].load(std::memory_order_relaxed)) {
            this->held_display_mask &= static_cast<uint8_t>(~bit);
            this->held_display_clear &= static_cast<uint8_t>(~bit);
            if (this->ack_enabled(slot)) {
                bool should_wake = false;
                {
                    std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
                    auto& sb = this->drain_task->slot_buffers[slot];
                    // The consumer got a decode whose display will never fire now; release the
                    // gate so the slot does not wedge on this stream restart. PRESENTED is left
                    // untouched: a delivery that already reached on_image_display()/
                    // on_image_clear() still owes its frame_done() regardless of epoch.
                    if (sb.ack_state == SlotAckState::DECODE_DELIVERED) {
                        sb.ack_state = SlotAckState::IDLE;
                    }
                    should_wake = sb.has_parked;
                }
                if (should_wake) {
                    this->wake_drain_thread();
                }
            }
            continue;
        }
        int64_t client_ts = this->client->get_client_time(this->held_display_ts[slot]);
        int32_t display_offset_ms = slot < this->config.preferred_formats.size()
                                        ? this->config.preferred_formats[slot].display_offset_ms
                                        : 0;
        int64_t overdue_us = display_overdue_us(client_ts, display_offset_ms, now);
        if (overdue_us < 0) {
            continue;
        }
        this->held_display_mask &= static_cast<uint8_t>(~bit);
        // A per-channel clear is scheduled exactly like a frame, offset shift included, so a
        // consumer can fade out on the same lead it would have faded in on.
        const bool is_clear = (this->held_display_clear & bit) != 0;
        this->held_display_clear &= static_cast<uint8_t>(~bit);
        if (this->ack_enabled(slot)) {
            // Arm the "awaiting frame_done()" state before the callback fires and release the
            // mutex before invoking it: frame_done() may be called synchronously from inside
            // on_image_display()/on_image_clear(), which would deadlock if this mutex were still
            // held.
            std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
            this->drain_task->slot_buffers[slot].ack_state = SlotAckState::PRESENTED;
        }
        if (this->listener) {
            if (is_clear) {
                this->listener->on_image_clear(slot);
            } else {
                this->listener->on_image_display(slot, display_lateness_ms(client_ts, overdue_us));
            }
        }
        // The callback may re-enter teardown (a listener calling stop()), whose own drain already
        // dropped the holds.
        if (!this->accepts(generation)) {
            return;
        }
    }
}

void ArtworkRole::Impl::complete_teardown() {
    // A teardown ends the stream like a stream/end: the held displays are dropped and every
    // channel is cleared, ahead of anything the next connection's stream displays.
    this->clear_every_channel();
}

// ============================================================================
// Cleanup (protocol task, or the main loop in stop() once it is joined)
// ============================================================================

void ArtworkRole::Impl::cleanup() {
    // Stamps every event queued from here on, so an event queued for the stream this teardown
    // ends is discarded at the drain (see event_is_current()).
    const uint32_t generation =
        this->cleanup_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    this->stream_active = false;
    this->discard_all_pending();

    // discard_all_pending() bumped every slot epoch, so no transfer is in flight and nothing
    // that is still decoding can deliver.
    this->release_idle_slot_buffers();

    push_event_or_log(this->inbox, InboxEventType::ARTWORK_CLEARED, 0, TAG, "artwork cleared event",
                      generation);
}

// ============================================================================
// Consumer-facing methods (main thread)
// ============================================================================

void ArtworkRole::Impl::frame_done(uint8_t slot) const {
    if (slot >= ARTWORK_MAX_SLOTS) {
        return;
    }

    bool should_wake = false;
    {
        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        auto& sb = this->drain_task->slot_buffers[slot];
        if (sb.ack_state == SlotAckState::IDLE) {
            // Safe no-op: nothing un-acked for this slot, whether because require_frame_done is
            // disabled, the delivery was already acked, or a clear already acked it for us.
            return;
        }
        sb.ack_state = SlotAckState::IDLE;
        should_wake = sb.has_parked;
    }
    if (should_wake) {
        this->wake_drain_thread();
    }
}

// ============================================================================
// Decode thread
// ============================================================================

void ArtworkRole::Impl::process_notification(const ArtworkNotification& notif) {
    uint8_t slot = notif.slot;
    uint8_t buf_idx = notif.buffer_idx;

    // A per-channel clear (see handle_binary) names no buffer, so it skips the buffer validation
    // and the decode callback below. Everything else is deliberately shared with a frame: the same
    // slot-epoch staleness check, the same ack gate (a clear is a delivery owing exactly one
    // frame_done()), and the same timestamp-scheduled hand-off to the main loop, which fires
    // on_image_clear() rather than on_image_display() when the deadline is reached.
    const bool is_clear = notif.data_length == 0;

    uint8_t* decode_data = nullptr;
    size_t decode_length = 0;
    {
        // Validate the notification is still current before touching the buffer: a newer
        // transfer (epoch changed) or a newer write to the same buffer (write_generation
        // changed) means this notification is stale and the bytes it names may have already
        // been overwritten by the protocol task, or are about to be. A fresher notification
        // for the same slot is already queued or has itself been parked.
        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        auto& sb = this->drain_task->slot_buffers[slot];

        if (notif.epoch != this->slot_epochs[slot].load(std::memory_order_relaxed)) {
            return;
        }
        if (!is_clear) {
            if (notif.generation != sb.write_generation[buf_idx]) {
                return;
            }
            if (sb.buffers[buf_idx].data() == nullptr) {
                return;
            }
        }

        // Ack gate: a slot with require_frame_done set allows only one un-acked delivery in
        // flight. If one is already outstanding, park this (newer) notification instead of
        // decoding it now: overwriting any previously parked notification is latest-wins by
        // design. Otherwise arm the gate (DECODE_DELIVERED) before decoding, so any later
        // notification for this slot parks instead of decoding concurrently with this un-acked
        // delivery. Arming gates on ack_enabled() alone, matching drain_events() and
        // clear_every_channel(); the listener is set before start() (see set_listener) so it
        // is non-null here, and the callback invocation below is the crash-guard for that pointer.
        if (this->ack_enabled(slot) && sb.ack_state != SlotAckState::IDLE) {
            sb.parked = notif;
            sb.has_parked = true;
            return;
        }
        if (this->ack_enabled(slot)) {
            sb.ack_state = SlotAckState::DECODE_DELIVERED;
        }

        if (!is_clear) {
            // Mark this buffer as in-use so the protocol task avoids it while we decode.
            sb.drain_buf_idx = buf_idx;
            sb.drain_active = true;
            decode_data = sb.buffers[buf_idx].data();
            decode_length = notif.data_length;
        }
    }

    if (!is_clear) {
        if (this->listener) {
            this->listener->on_image_decode(slot, decode_data, decode_length, notif.format);
        }

        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        this->drain_task->slot_buffers[slot].drain_active = false;
    }

    // Hand off the timestamp to the main loop. Skip if the stream ended while we were
    // decoding so the main loop doesn't fire a display after on_image_clear. The delta
    // carries just this slot's bit; merge_artwork_display_update ORs it into whatever the
    // main loop hasn't drained out of display_slot yet.
    if (this->stream_active.load(std::memory_order_acquire)) {
        ArtworkDisplayUpdate delta{};
        delta.timestamps[slot] = notif.timestamp;
        // The epoch this decode was validated under: lets the main-loop deadline check drop
        // the display if the stream is replaced after this hand-off (see held_display_epoch).
        delta.epochs[slot] = notif.epoch;
        delta.valid_mask = static_cast<uint8_t>(1U << slot);
        if (is_clear) {
            delta.clear_mask = static_cast<uint8_t>(1U << slot);
        }
        // NOLINTNEXTLINE(performance-move-const-arg): merge() takes the delta as T&&
        this->event_state->display_slot.merge(merge_artwork_display_update, std::move(delta),
                                              notif.teardown_generation);
    }
}

void ArtworkRole::Impl::drain_thread_func(ArtworkRole::Impl* self) {
    SS_LOGD(TAG, "Decode thread started");

    auto& queue = self->drain_task->notify_queue;
    auto& flags = self->drain_task->event_flags;

    while (true) {
        // Non-blocking check for commands
        uint32_t cmd = flags.wait(COMMAND_STOP, false, true, 0);
        if (cmd & COMMAND_STOP) {
            break;
        }

        // Replay any parked notification whose slot's gate has reopened (ack_state back to
        // IDLE via frame_done() or an epoch-mismatch release in drain_events()).
        // process_notification() revalidates the notification itself, so a since-stale
        // generation/epoch is simply skipped: correct, since a fresher notification is either
        // already queued or has itself been freshly parked. Loop until no parked slot is ready
        // so one wakeup can drain several slots without waiting on separate receive timeouts.
        while (true) {
            ArtworkNotification parked_notif{};
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(self->drain_task->slot_mutex);
                for (auto& sb : self->drain_task->slot_buffers) {
                    if (sb.has_parked && sb.ack_state == SlotAckState::IDLE) {
                        parked_notif = sb.parked;
                        sb.has_parked = false;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                break;
            }
            self->process_notification(parked_notif);
        }

        // Blocking receive; returns early (false) when wake_receiver() signals a stop or a
        // parked-slot recheck. The timeout is only a safety net against a missed wake (see
        // DRAIN_RECEIVE_TIMEOUT_MS); a timeout return simply re-runs the sweep above.
        ArtworkNotification notif{};
        if (!queue.receive(notif, DRAIN_RECEIVE_TIMEOUT_MS)) {
            continue;
        }

        if (notif.slot >= ARTWORK_MAX_SLOTS) {
            continue;
        }

        self->process_notification(notif);
    }

    SS_LOGD(TAG, "Decode thread stopped");
}

// ============================================================================
// ArtworkRole public API (thin forwarding)
// ============================================================================

ArtworkRole::ArtworkRole(ArtworkRoleConfig config, SendspinClient* client)
    : impl_(std::make_unique<Impl>(std::move(config), client)) {}

ArtworkRole::~ArtworkRole() = default;

void ArtworkRole::set_listener(ArtworkRoleListener* listener) {
    this->impl_->listener = listener;
}

void ArtworkRole::frame_done(uint8_t slot) {
    this->impl_->frame_done(slot);
}

}  // namespace sendspin
