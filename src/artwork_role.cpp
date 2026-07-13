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
    InboxEvent ring_event{};
    ring_event.type = InboxEventType::ARTWORK_STREAM;
    ring_event.code = static_cast<uint8_t>(event);
    if (this->inbox == nullptr || !this->inbox->push_event(ring_event)) {
        SS_LOGW(TAG, "Inbox event ring full; dropping %s",
                event == ArtworkEventType::STREAM_END ? "STREAM_END" : "STREAM_CLEAR");
    }
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

    if (!this->listener || this->held_display_mask == 0) {
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
            continue;
        }
        // get_client_time returns 0 when there is no current connection. Without a connection we
        // cannot honor the server-clock deadline, so fire immediately rather than starving the
        // listener.
        int64_t client_ts = this->client->get_client_time(this->held_display_ts[slot]);
        if (client_ts != 0 && client_ts > now) {
            continue;
        }
        this->held_display_mask &= static_cast<uint8_t>(~(1U << slot));
        this->listener->on_image_display(slot);
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
// Decode thread
// ============================================================================

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

        // Blocking receive with 100ms timeout (allows periodic command checks)
        ArtworkNotification notif{};
        if (!queue.receive(notif, DRAIN_RECEIVE_TIMEOUT_MS)) {
            continue;
        }

        uint8_t slot = notif.slot;
        uint8_t buf_idx = notif.buffer_idx;
        if (slot >= ARTWORK_MAX_SLOTS) {
            continue;
        }

        uint8_t* decode_data = nullptr;
        size_t decode_length = 0;
        {
            // Validate the notification is still current before touching the buffer: a newer
            // stream (stream_epoch changed) or a newer write to the same buffer (write_generation
            // changed) means this notification is stale and the bytes it names may have already
            // been overwritten by the network thread, or are about to be. Skip it instead of
            // risking a torn read; a fresher notification for the same slot is already queued or
            // on its way.
            std::lock_guard<std::mutex> lock(self->drain_task->slot_mutex);
            auto& sb = self->drain_task->slot_buffers[slot];

            if (notif.stream_epoch != self->stream_epoch.load(std::memory_order_relaxed)) {
                continue;
            }
            if (notif.generation != sb.write_generation[buf_idx]) {
                continue;
            }

            auto& buf = sb.buffers[buf_idx];
            if (notif.data_length == 0 || buf.data() == nullptr) {
                continue;
            }

            // Mark this buffer as in-use so the network thread avoids it while we decode.
            sb.drain_buf_idx = buf_idx;
            sb.drain_active = true;
            decode_data = buf.data();
            decode_length = notif.data_length;
        }

        if (self->listener) {
            self->listener->on_image_decode(slot, decode_data, decode_length, notif.format);
        }

        {
            std::lock_guard<std::mutex> lock(self->drain_task->slot_mutex);
            self->drain_task->slot_buffers[slot].drain_active = false;
        }

        // Hand off the timestamp to the main loop. Skip if the stream ended while we were
        // decoding so the main loop doesn't fire a display after on_image_clear. The delta
        // carries just this slot's bit; merge_artwork_display_update ORs it into whatever the
        // main loop hasn't drained out of display_slot yet.
        if (self->stream_active.load(std::memory_order_acquire)) {
            ArtworkDisplayUpdate delta{};
            delta.timestamps[slot] = notif.timestamp;
            // The epoch this decode was validated under: lets the main-loop deadline check drop
            // the display if the stream is replaced after this hand-off (see held_display_epoch).
            delta.epochs[slot] = notif.stream_epoch;
            delta.valid_mask = static_cast<uint8_t>(1U << slot);
            self->event_state->display_slot.merge(merge_artwork_display_update, delta);
        }
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

}  // namespace sendspin
