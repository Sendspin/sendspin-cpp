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
static constexpr uint32_t COMMAND_FLUSH = (1 << 1);

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

// ============================================================================
// ArtworkRole::Impl lifecycle
// ============================================================================

ArtworkRole::Impl::Impl(ArtworkRoleConfig config, SendspinClient* client)
    : config(std::move(config)),
      client(client),
      drain_task(std::make_unique<DrainTask>()),
      event_state(std::make_unique<EventState>()),
      display_scheduler(std::make_unique<DisplayScheduler>()) {
    for (const auto& pref : this->config.preferred_formats) {
        this->artwork_channels.push_back({pref.source, pref.format, pref.width, pref.height});
    }
    this->event_state->queue.create(8);
    this->drain_task->notify_queue.create(8);
}

ArtworkRole::Impl::~Impl() {
    this->stop();
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

    // Look up format for this slot
    SendspinImageFormat image_format = SendspinImageFormat::JPEG;
    for (const auto& pref : this->config.preferred_formats) {
        if (pref.slot == slot) {
            image_format = pref.format;
            break;
        }
    }

    // Copy into the back buffer for this slot (grow-only)
    auto& sb = this->drain_task->slot_buffers[slot];
    uint8_t write_idx = sb.write_idx.load(std::memory_order_acquire);

    // If the decode thread is actively using this buffer, skip to the other one.
    // If the decode thread is using the other one, this write_idx is already safe.
    if (sb.drain_active.load(std::memory_order_acquire) && sb.drain_buf_idx == write_idx) {
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

    // Flip write index so the next network write goes to the other buffer
    sb.write_idx.store(write_idx ^ 1, std::memory_order_release);

    // Signal decode thread with all metadata in the notification
    ArtworkNotification notif{slot, write_idx, image_len, timestamp, image_format};
    this->drain_task->notify_queue.send(notif, 0);
}

// ============================================================================
// Stream lifecycle (network thread)
// ============================================================================

void ArtworkRole::Impl::handle_stream_start() {
    this->stream_active = true;

    // Signal decode thread to flush any stale notifications
    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }
    // Discard any pending displays from a prior stream
    if (this->display_scheduler) {
        for (auto& slot : this->display_scheduler->pending) {
            slot.reset();
        }
    }
}

void ArtworkRole::Impl::handle_stream_end() {
    this->stream_active = false;

    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state->queue.send(ArtworkEventType::STREAM_END, 0);
}

void ArtworkRole::Impl::handle_stream_clear() {
    this->stream_active = false;

    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state->queue.send(ArtworkEventType::STREAM_CLEAR, 0);
}

// ============================================================================
// Event draining (main thread) - lifecycle events and scheduled displays
// ============================================================================

void ArtworkRole::Impl::drain_events() {
    // Process stream lifecycle events first so we don't fire a display that was
    // cancelled by an end/clear in the same tick.
    ArtworkEventType event_type{};
    while (this->event_state->queue.receive(event_type, 0)) {
        switch (event_type) {
            case ArtworkEventType::STREAM_END:
            case ArtworkEventType::STREAM_CLEAR:
                if (this->display_scheduler) {
                    for (auto& pending : this->display_scheduler->pending) {
                        pending.reset();
                    }
                }
                if (this->listener) {
                    for (const auto& pref : this->config.preferred_formats) {
                        this->listener->on_image_clear(pref.slot);
                    }
                }
                break;
        }
    }

    if (!this->display_scheduler || !this->listener) {
        return;
    }

    const int64_t now = platform_time_us();
    for (uint8_t slot = 0; slot < ARTWORK_MAX_SLOTS; ++slot) {
        int64_t server_ts = 0;
        const bool taken = this->display_scheduler->pending[slot].take_if(
            server_ts, [this, now](const int64_t& pending_ts) {
                // Fire immediately if time sync isn't ready: holding forever would starve
                // the listener. Matches the metadata role's behavior.
                int64_t client_ts = this->client->get_client_time(pending_ts);
                if (client_ts == 0) {
                    return true;
                }
                return client_ts <= now;
            });
        if (taken) {
            this->listener->on_image_display(slot);
        }
    }
}

// ============================================================================
// Cleanup (main thread)
// ============================================================================

void ArtworkRole::Impl::cleanup() {
    this->stream_active = false;

    if (this->drain_task) {
        this->drain_task->event_flags.set(COMMAND_FLUSH);
    }

    if (this->display_scheduler) {
        for (auto& pending : this->display_scheduler->pending) {
            pending.reset();
        }
    }

    this->event_state->queue.reset();
    this->event_state->queue.send(ArtworkEventType::STREAM_END, 0);
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
        uint32_t cmd = flags.wait(COMMAND_STOP | COMMAND_FLUSH, false, true, 0);
        if (cmd & COMMAND_STOP) {
            break;
        }
        if (cmd & COMMAND_FLUSH) {
            // Drain all pending notifications without processing
            ArtworkNotification dummy{};
            while (queue.receive(dummy, 0)) {}
            continue;
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

        auto& sb = self->drain_task->slot_buffers[slot];
        auto& buf = sb.buffers[buf_idx];

        if (notif.data_length == 0 || buf.data() == nullptr) {
            continue;
        }

        // Mark this buffer as in-use so the network thread avoids it
        sb.drain_buf_idx = buf_idx;
        sb.drain_active.store(true, std::memory_order_release);

        if (self->listener) {
            self->listener->on_image_decode(slot, buf.data(), notif.data_length, notif.format);
        }

        sb.drain_active.store(false, std::memory_order_release);

        // Hand off the timestamp to the main loop. Skip if the stream ended while we were
        // decoding so the main loop doesn't fire a display after on_image_clear.
        if (self->stream_active.load(std::memory_order_acquire) && self->display_scheduler) {
            self->display_scheduler->pending[slot].write(notif.timestamp);
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
