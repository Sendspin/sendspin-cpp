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
#include "platform/logging.h"
#include "platform/thread.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

#include <algorithm>
#include <cstring>

static const char* const TAG = "sendspin.artwork";

// ============================================================================
// Constants
// ============================================================================

/// @brief Size of the big-endian 64-bit timestamp at the start of artwork binary messages
static constexpr size_t BINARY_TIMESTAMP_SIZE = 8;

/// @brief Timeout for blocking queue receive in decode thread (allows periodic command checks)
static constexpr uint32_t DRAIN_RECEIVE_TIMEOUT_MS = 100U;

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

namespace sendspin {

namespace {

/// @brief Merges a single-slot display delta into the accumulated cross-thread update
///
/// Called under the Inbox mutex via InboxSlot::merge() (see Impl::drain_thread_func), so it must
/// stay a pure data operation with no callbacks into application code. `delta` carries exactly
/// one slot's bit (set by the decode thread after a single image finishes decoding); OR-ing
/// valid_mask and overwriting only the masked timestamps entries preserves latest-wins per slot
/// while leaving any other slot's already-accumulated (not yet drained) timestamp untouched.
void merge_artwork_display_update(ArtworkDisplayUpdate& current, ArtworkDisplayUpdate&& delta) {
    current.valid_mask |= delta.valid_mask;
    for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
        if (delta.valid_mask & (1U << slot)) {
            current.timestamps[slot] = delta.timestamps[slot];
            current.epochs[slot] = delta.epochs[slot];
        }
    }
}

}  // namespace

// ============================================================================
// ArtworkRole::Impl lifecycle
// ============================================================================

ArtworkRole::Impl::Impl(ArtworkRoleConfig config, SendspinClient* client)
    : config(std::move(config)),
      client(client),
      drain_task(std::make_unique<DrainTask>()),
      event_state(std::make_unique<EventState>()) {
    // The array index is authoritative for channel/slot mapping: the hello advertises channels
    // in this->artwork_channels order, and handle_binary looks up this->config.preferred_formats
    // by index to match.
    if (this->config.preferred_formats.size() > ARTWORK_MAX_SLOTS) {
        SS_LOGW(TAG, "Artwork configured with %zu channels, truncating to %zu",
                this->config.preferred_formats.size(), ARTWORK_MAX_SLOTS);
        this->config.preferred_formats.resize(ARTWORK_MAX_SLOTS);
    }
    for (const auto& pref : this->config.preferred_formats) {
        this->artwork_channels.push_back({pref.source, pref.format, pref.width, pref.height});
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
    if (!this->drain_task) {
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

    platform_configure_thread("SsArt", 4096, static_cast<int>(this->config.priority),
                              this->config.psram_stack);
    this->drain_task->drain_thread = std::thread(drain_thread_func, this);
    return true;
}

void ArtworkRole::Impl::stop() const {
    if (!this->drain_task || !this->drain_task->drain_thread.joinable()) {
        return;
    }
    this->drain_task->event_flags.set(COMMAND_STOP);
    this->drain_task->drain_thread.join();
}

void ArtworkRole::Impl::build_hello_fields(ClientHelloMessage& msg) const {
    if (this->artwork_channels.empty()) {
        return;
    }
    msg.supported_roles.push_back(SendspinRole::ARTWORK);

    ArtworkSupportObject artwork_support{};
    artwork_support.channels = this->artwork_channels;
    msg.artwork_v1_support = artwork_support;
}

// ============================================================================
// Display-deadline and ack-gate helpers (used from network, decode, and main threads)
// ============================================================================

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
    // Best-effort wakeup: a dropped send just means the decode thread's own
    // DRAIN_RECEIVE_TIMEOUT_MS receive timeout, plus the parked-slot sweep it runs at the top
    // of every loop iteration, picks up the parked notification a little later instead of
    // immediately.
    ArtworkNotification wake{};
    wake.slot = ARTWORK_RECHECK_SLOT;
    this->drain_task->notify_queue.send(wake, 0);
}

// ============================================================================
// Binary handling (network thread)
// ============================================================================

void ArtworkRole::Impl::handle_binary(uint8_t slot, const uint8_t* data, size_t len) {
    if (!this->stream_active || !this->drain_task || !this->listener) {
        return;
    }
    if (slot >= ARTWORK_MAX_SLOTS) {
        return;
    }
    if (len < BINARY_TIMESTAMP_SIZE) {
        SS_LOGW(TAG, "Binary message too short for timestamp");
        return;
    }

    int64_t timestamp = be64_to_host(data);
    const uint8_t* image_data = data + BINARY_TIMESTAMP_SIZE;
    size_t image_len = len - BINARY_TIMESTAMP_SIZE;

    // Look up format by array index. See the Impl constructor comment for why the index is
    // authoritative for slot mapping.
    SendspinImageFormat image_format = SendspinImageFormat::JPEG;
    if (slot < this->config.preferred_formats.size()) {
        image_format = this->config.preferred_formats[slot].format;
    }

    uint32_t generation = 0;
    uint8_t write_idx = 0;
    {
        // Hold the slot mutex across the read-modify-write of write_idx/drain_active/
        // write_generation and the memcpy itself, so the decode thread can never observe a
        // buffer mid-write (torn image) and can never have a buffer stolen out from under it
        // while it still owns the notification for that generation.
        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        auto& sb = this->drain_task->slot_buffers[slot];
        write_idx = sb.write_idx;

        // If the decode thread is actively using this buffer, skip to the other one.
        // If the decode thread is using the other one, this write_idx is already safe.
        if (sb.drain_active && sb.drain_buf_idx == write_idx) {
            write_idx ^= 1;
        }

        auto& buf = sb.buffers[write_idx];

        if (buf.size() < image_len) {
            if (!buf.realloc(image_len)) {
                SS_LOGE(TAG, "Failed to allocate artwork buffer for slot %d (%zu bytes)", slot,
                        image_len);
                return;
            }
        }

        std::memcpy(buf.data(), image_data, image_len);

        // Bump this buffer's generation so the decode thread can detect if it gets
        // overwritten again before being claimed, then flip write_idx so the next network
        // write goes to the other buffer.
        sb.write_generation[write_idx]++;
        generation = sb.write_generation[write_idx];
        sb.write_idx = write_idx ^ 1;
    }

    // Signal decode thread with all metadata in the notification
    uint32_t epoch = this->stream_epoch.load(std::memory_order_relaxed);
    ArtworkNotification notif{slot,         write_idx,  image_len, timestamp,
                              image_format, generation, epoch};
    if (!this->drain_task->notify_queue.send(notif, 0)) {
        SS_LOGW(TAG, "Artwork notify queue full; dropping image for slot %u", slot);
    }
}

// ============================================================================
// Stream lifecycle (network thread)
// ============================================================================

void ArtworkRole::Impl::handle_stream_start(const ServerArtworkStreamObject& stream) {
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
            if (srv.width.has_value() && srv.width.value() != req.media_width) {
                SS_LOGW(TAG,
                        "Artwork channel %zu width mismatch: server %" PRIu16 ", expected %" PRIu16,
                        i, srv.width.value(), req.media_width);
            }
            if (srv.height.has_value() && srv.height.value() != req.media_height) {
                SS_LOGW(TAG,
                        "Artwork channel %zu height mismatch: server %" PRIu16
                        ", expected %" PRIu16,
                        i, srv.height.value(), req.media_height);
            }
        }
    }

    this->stream_active = true;

    // Bump the stream epoch so any notification still in the queue from a prior stream is
    // recognized as stale by the decode thread and skipped, rather than draining the whole
    // notify queue here (which could wrongly discard this new stream's first image if it was
    // already queued before this handler ran).
    this->stream_epoch.fetch_add(1, std::memory_order_relaxed);

    // Discard any pending display from a prior stream that has not yet been folded into the
    // main thread's held_display_mask (see drain_events()). A display already folded into the
    // holds is not reachable from here, but it carries the epoch it was decoded under
    // (held_display_epoch), so the epoch bump above makes the main-loop deadline check drop it.
    this->event_state->display_slot.reset();

    {
        // Release any DECODE_DELIVERED ack gate: display_slot was just reset and the epoch was
        // just bumped, so that decode's eventual display can no longer fire, and leaving the
        // gate armed would wedge the slot forever. PRESENTED must stay armed here: the consumer
        // may still be mid-fade on the previous stream's last delivery, and its buffers must not
        // be disturbed until frame_done() is called. Protocol messages are serialized on the
        // network thread, so this runs before any of the new stream's handle_binary() calls.
        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        for (auto& sb : this->drain_task->slot_buffers) {
            sb.has_parked = false;
            if (sb.ack_state == SlotAckState::DECODE_DELIVERED) {
                sb.ack_state = SlotAckState::IDLE;
            }
        }
    }
}

void ArtworkRole::Impl::handle_stream_end() {
    this->stream_active = false;
    this->stream_epoch.fetch_add(1, std::memory_order_relaxed);

    this->enqueue_stream_event(ArtworkEventType::STREAM_END);
}

void ArtworkRole::Impl::handle_stream_clear() {
    this->stream_active = false;
    this->stream_epoch.fetch_add(1, std::memory_order_relaxed);

    this->enqueue_stream_event(ArtworkEventType::STREAM_CLEAR);
}

void ArtworkRole::Impl::enqueue_stream_event(ArtworkEventType event) const {
    push_event_or_log(this->inbox, InboxEventType::ARTWORK_STREAM, static_cast<uint8_t>(event), TAG,
                      event == ArtworkEventType::STREAM_END ? "STREAM_END" : "STREAM_CLEAR");
}

// ============================================================================
// Event dispatch (main thread) - lifecycle via the ring, scheduled displays via polling
// ============================================================================

void ArtworkRole::Impl::handle_stream_ring_event(ArtworkEventType event) {
    // Called from the ring drain in SendspinClient::loop() before this role's drain_events()
    // runs each tick (see drain_events()), so clearing the holds and display_slot here cancels
    // any display that would otherwise fire later this same tick -- the same "lifecycle first"
    // ordering the old queue-drain loop at the top of drain_events() used to guarantee by running
    // before the display-deadline loop below it.
    switch (event) {
        case ArtworkEventType::STREAM_END:
        case ArtworkEventType::STREAM_CLEAR:
            this->held_display_mask = 0;
            this->event_state->display_slot.reset();
            {
                // A clear is itself a delivery that must be acked: it may drive a fade-out, and
                // it supersedes any un-acked frame for the slot, so exactly one frame_done() is
                // owed afterward regardless of what ack_state held before. Drop any notification
                // parked behind an un-acked frame -- it is superseded by the clear. Released
                // before firing the callbacks below so a listener calling frame_done() from
                // inside on_image_clear() does not deadlock on this same mutex.
                std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
                // Sweep the whole fixed-size slot_buffers array (ARTWORK_MAX_SLOTS), matching
                // handle_stream_start(): ack_enabled() already gates the PRESENTED arm to
                // configured ack slots, and clearing has_parked on any others is a harmless reset
                // (they never park).
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
            break;
    }
}

void ArtworkRole::Impl::drain_events() {
    // Fold any newly published display update into the main-thread holds. Latest-wins per
    // artwork slot, same as the old per-slot ShadowSlot overwrite: a bit set in valid_mask means
    // timestamps[i] is a fresher pending display than whatever (if anything) slot i already
    // held. Any STREAM_END/STREAM_CLEAR for this tick has already run via
    // handle_stream_ring_event() before this call (see the comment there), so a lifecycle event
    // arriving this tick has already cleared held_display_mask before we get here.
    ArtworkDisplayUpdate update{};
    if (this->event_state->display_slot.take(update)) {
        for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
            if (update.valid_mask & (1U << slot)) {
                this->held_display_ts[slot] = update.timestamps[slot];
                this->held_display_epoch[slot] = update.epochs[slot];
                this->held_display_mask |= static_cast<uint8_t>(1U << slot);
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
    const uint32_t current_epoch = this->stream_epoch.load(std::memory_order_relaxed);
    for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
        if (!(this->held_display_mask & (1U << slot))) {
            continue;
        }
        // Drop a display decoded under a since-replaced stream (restart with no intervening
        // end/clear bumps the epoch but cannot reach these main-thread holds to cancel it).
        if (this->held_display_epoch[slot] != current_epoch) {
            this->held_display_mask &= static_cast<uint8_t>(~(1U << slot));
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
        this->held_display_mask &= static_cast<uint8_t>(~(1U << slot));
        if (this->ack_enabled(slot)) {
            // Arm the "awaiting frame_done()" state before the callback fires and release the
            // mutex before invoking it: frame_done() may be called synchronously from inside
            // on_image_display(), which would deadlock if this mutex were still held.
            std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
            this->drain_task->slot_buffers[slot].ack_state = SlotAckState::PRESENTED;
        }
        if (this->listener) {
            this->listener->on_image_display(slot, display_lateness_ms(client_ts, overdue_us));
        }
    }
}

// ============================================================================
// Cleanup (main thread)
// ============================================================================

void ArtworkRole::Impl::cleanup() {
    this->stream_active = false;
    this->stream_epoch.fetch_add(1, std::memory_order_relaxed);

    // Stale ring-borne events (an in-flight STREAM_END/STREAM_CLEAR queued before this cleanup)
    // are already discarded by SendspinClient::cleanup_connection_state()'s inbox.reset_events()
    // call, which runs before any role's cleanup() -- so there is no per-event ring reset to do
    // here.
    this->held_display_mask = 0;
    this->event_state->display_slot.reset();

    // Enqueue a clean STREAM_END - handle_stream_ring_event() will fire the on_image_clear()
    // callbacks (the ring was just reset above us, so this push should not fail;
    // enqueue_stream_event() logs if it somehow does).
    this->enqueue_stream_event(ArtworkEventType::STREAM_END);
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

    uint8_t* decode_data = nullptr;
    size_t decode_length = 0;
    {
        // Validate the notification is still current before touching the buffer: a newer
        // stream (stream_epoch changed) or a newer write to the same buffer (write_generation
        // changed) means this notification is stale and the bytes it names may have already
        // been overwritten by the network thread, or are about to be. Skip it instead of
        // risking a torn read; a fresher notification for the same slot is already queued or
        // on its way.
        std::lock_guard<std::mutex> lock(this->drain_task->slot_mutex);
        auto& sb = this->drain_task->slot_buffers[slot];

        if (notif.stream_epoch != this->stream_epoch.load(std::memory_order_relaxed)) {
            return;
        }
        if (notif.generation != sb.write_generation[buf_idx]) {
            return;
        }

        auto& buf = sb.buffers[buf_idx];
        if (notif.data_length == 0 || buf.data() == nullptr) {
            return;
        }

        // Ack gate: a slot with require_frame_done set allows only one un-acked delivery in
        // flight. If one is already outstanding, park this (newer) notification instead of
        // decoding it now -- overwriting any previously parked notification is latest-wins by
        // design. Otherwise arm the gate (DECODE_DELIVERED) before decoding, so any later
        // notification for this slot parks instead of decoding concurrently with this un-acked
        // delivery. Arming gates on ack_enabled() alone, matching drain_events() and
        // handle_stream_ring_event(); the listener is set before start() (see set_listener) so it
        // is non-null here, and the callback invocation below is the crash-guard for that pointer.
        if (this->ack_enabled(slot) && sb.ack_state != SlotAckState::IDLE) {
            sb.parked = notif;
            sb.has_parked = true;
            return;
        }
        if (this->ack_enabled(slot)) {
            sb.ack_state = SlotAckState::DECODE_DELIVERED;
        }

        // Mark this buffer as in-use so the network thread avoids it while we decode.
        sb.drain_buf_idx = buf_idx;
        sb.drain_active = true;
        decode_data = buf.data();
        decode_length = notif.data_length;
    }

    if (this->listener) {
        this->listener->on_image_decode(slot, decode_data, decode_length, notif.format);
    }

    {
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
        delta.epochs[slot] = notif.stream_epoch;
        delta.valid_mask = static_cast<uint8_t>(1U << slot);
        this->event_state->display_slot.merge(merge_artwork_display_update, delta);
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
        // generation/epoch is simply skipped -- correct, since a fresher notification is either
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

        // Blocking receive with 100ms timeout (allows periodic command checks and, when nothing
        // ever wakes the queue, an upper bound on how long a parked notification waits before the
        // sweep above rechecks it).
        ArtworkNotification notif{};
        if (!queue.receive(notif, DRAIN_RECEIVE_TIMEOUT_MS)) {
            continue;
        }

        if (notif.slot == ARTWORK_RECHECK_SLOT) {
            // Sentinel used only to unblock receive() so the parked-slot sweep above re-runs
            // promptly; carries no work of its own.
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
