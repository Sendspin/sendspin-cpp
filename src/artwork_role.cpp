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

#include "sendspin/artwork_role.h"

#include "platform/event_flags.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include "platform/shadow_slot.h"
#include "platform/thread.h"
#include "platform/thread_safe_queue.h"
#include "platform/time.h"
#include "protocol_messages.h"
#include "sendspin/client.h"

#include <cstring>
#include <thread>

static const char* const TAG = "sendspin.artwork";

// ============================================================================
// Constants
// ============================================================================

/// @brief Size of the big-endian 64-bit timestamp at the start of artwork binary messages
static constexpr size_t BINARY_TIMESTAMP_SIZE = 8;

/// @brief Maximum number of artwork slots (2-bit slot field in protocol binary type byte)
static constexpr size_t MAX_SLOTS = 4;

/// @brief Timeout for blocking queue receive in drain thread (allows periodic command checks)
static constexpr uint32_t DRAIN_RECEIVE_TIMEOUT_MS = 100U;

/// @brief Microseconds per millisecond (unit conversion constant)
static constexpr int64_t US_PER_MS = 1000LL;

// Event flag bits for drain thread signaling
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
// Internal types
// ============================================================================

/// @brief Double-buffered image storage for a single artwork slot
struct SlotBuffer {
    PlatformBuffer buffers[2];
    std::atomic<uint8_t> write_idx{0};      ///< Which buffer the network thread writes to next
    std::atomic<bool> drain_active{false};  ///< True while the drain thread is using a buffer
    uint8_t drain_buf_idx{0};               ///< Which buffer the drain thread is currently using
};

/// @brief Notification sent from the network thread to the drain thread when new image data arrives
///
/// All metadata is carried in the notification itself (not in SlotBuffer) so that the
/// ThreadSafeQueue's internal mutex provides the happens-before guarantee between the
/// network thread's writes and the drain thread's reads.
struct ArtworkNotification {
    uint8_t slot;
    uint8_t buffer_idx;
    size_t data_length;
    int64_t timestamp;
    SendspinImageFormat format;
};

// ============================================================================
// Pimpl definitions
// ============================================================================

/// @brief Persistent drain thread context for artwork image decode and display delivery
struct ArtworkRole::DrainTask {
    ThreadSafeQueue<ArtworkNotification> notify_queue;
    EventFlags event_flags;
    std::thread drain_thread;
    SlotBuffer slot_buffers[MAX_SLOTS];
};

/// @brief Deferred event state for thread-safe artwork stream lifecycle delivery
struct ArtworkRole::EventState {
    ThreadSafeQueue<ArtworkRole::EventType> queue;
    ShadowSlot<ServerArtworkStreamObject> shadow_config;
};

// ============================================================================
// Lifecycle
// ============================================================================

ArtworkRole::ArtworkRole(Config config, SendspinClient* client)
    : config_(std::move(config)),
      client_(client),
      drain_task_(std::make_unique<DrainTask>()),
      event_state_(std::make_unique<EventState>()) {
    for (const auto& pref : this->config_.preferred_formats) {
        this->artwork_channels_.push_back({pref.source, pref.format, pref.width, pref.height});
    }
    this->event_state_->queue.create(8);
    this->drain_task_->notify_queue.create(8);
}

ArtworkRole::~ArtworkRole() {
    this->stop();
}

bool ArtworkRole::start() {
    if (!this->drain_task_) {
        return false;
    }
    if (this->drain_task_->drain_thread.joinable()) {
        return true;  // Already running
    }
    if (!this->drain_task_->event_flags.is_created() && !this->drain_task_->event_flags.create()) {
        return false;
    }

    platform_configure_thread("SsArt", 4096, static_cast<int>(this->config_.priority),
                              this->config_.psram_stack);
    this->drain_task_->drain_thread = std::thread(drain_thread_func, this);
    return true;
}

void ArtworkRole::stop() {
    if (!this->drain_task_ || !this->drain_task_->drain_thread.joinable()) {
        return;
    }
    this->drain_task_->event_flags.set(COMMAND_STOP);
    this->drain_task_->drain_thread.join();
}

void ArtworkRole::build_hello_fields(ClientHelloMessage& msg) {
    if (this->artwork_channels_.empty()) {
        return;
    }
    msg.supported_roles.push_back(SendspinRole::ARTWORK);

    ArtworkSupportObject artwork_support{};
    artwork_support.channels = this->artwork_channels_;
    msg.artwork_v1_support = artwork_support;
}

// ============================================================================
// Binary handling (network thread)
// ============================================================================

void ArtworkRole::handle_binary(uint8_t slot, const uint8_t* data, size_t len) {
    if (!this->stream_active_ || !this->drain_task_ || !this->listener_) {
        return;
    }
    if (slot >= MAX_SLOTS) {
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
    for (const auto& pref : this->config_.preferred_formats) {
        if (pref.slot == slot) {
            image_format = pref.format;
            break;
        }
    }

    // Copy into the back buffer for this slot (grow-only)
    auto& sb = this->drain_task_->slot_buffers[slot];
    uint8_t write_idx = sb.write_idx.load(std::memory_order_acquire);

    // If the drain thread is actively using this buffer, skip to the other one.
    // If the drain thread is using the other one, this write_idx is already safe.
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

    // Signal drain thread with all metadata in the notification
    ArtworkNotification notif{slot, write_idx, image_len, timestamp, image_format};
    this->drain_task_->notify_queue.send(notif, 0);
}

// ============================================================================
// Stream lifecycle (network thread)
// ============================================================================

void ArtworkRole::handle_stream_start(const ServerArtworkStreamObject& stream) {
    this->stream_active_ = true;

    // Signal drain thread to flush any stale notifications
    if (this->drain_task_) {
        this->drain_task_->event_flags.set(COMMAND_FLUSH);
    }

    // Shadow the config for main-thread callback
    this->event_state_->shadow_config.write(stream);
    this->event_state_->queue.send(EventType::STREAM_START, 0);
}

void ArtworkRole::handle_stream_end() {
    this->stream_active_ = false;

    if (this->drain_task_) {
        this->drain_task_->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state_->queue.send(EventType::STREAM_END, 0);
}

void ArtworkRole::handle_stream_clear() {
    this->stream_active_ = false;

    if (this->drain_task_) {
        this->drain_task_->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state_->queue.send(EventType::STREAM_CLEAR, 0);
}

// ============================================================================
// Event draining (main thread) - lifecycle events only
// ============================================================================

void ArtworkRole::drain_events() {
    EventType event_type{};
    while (this->event_state_->queue.receive(event_type, 0)) {
        switch (event_type) {
            case EventType::STREAM_START: {
                ServerArtworkStreamObject config{};
                if (this->event_state_->shadow_config.take(config) && this->listener_) {
                    this->listener_->on_artwork_stream_start(config);
                }
                break;
            }
            case EventType::STREAM_END:
                if (this->listener_) {
                    for (const auto& pref : this->config_.preferred_formats) {
                        this->listener_->on_image_clear(pref.slot);
                    }
                    this->listener_->on_artwork_stream_end();
                }
                break;
            case EventType::STREAM_CLEAR:
                if (this->listener_) {
                    for (const auto& pref : this->config_.preferred_formats) {
                        this->listener_->on_image_clear(pref.slot);
                    }
                }
                break;
        }
    }
}

// ============================================================================
// Cleanup (main thread)
// ============================================================================

void ArtworkRole::cleanup() {
    this->stream_active_ = false;

    if (this->drain_task_) {
        this->drain_task_->event_flags.set(COMMAND_FLUSH);
    }

    this->event_state_->queue.reset();
    this->event_state_->shadow_config.reset();
    this->event_state_->queue.send(EventType::STREAM_END, 0);
}

// ============================================================================
// Drain thread
// ============================================================================

void ArtworkRole::drain_thread_func(ArtworkRole* self) {
    SS_LOGD(TAG, "Drain thread started");

    auto& queue = self->drain_task_->notify_queue;
    auto& flags = self->drain_task_->event_flags;

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
        if (slot >= MAX_SLOTS) {
            continue;
        }

        auto& sb = self->drain_task_->slot_buffers[slot];
        auto& buf = sb.buffers[buf_idx];

        if (notif.data_length == 0 || buf.data() == nullptr) {
            continue;
        }

        // Mark this buffer as in-use so the network thread avoids it
        sb.drain_buf_idx = buf_idx;
        sb.drain_active.store(true, std::memory_order_release);

        // Phase 1: Decode callback (immediate)
        if (self->listener_) {
            self->listener_->on_image_decode(slot, buf.data(), notif.data_length, notif.format);
        }

        // Buffer is no longer needed after decode completes
        sb.drain_active.store(false, std::memory_order_release);

        // Wait for time sync before scheduling display
        if (!self->client_->is_time_synced()) {
            continue;
        }

        // Phase 2: Wait until display timestamp
        int64_t client_ts = self->client_->get_client_time(notif.timestamp);

        if (client_ts == 0) {
            continue;
        }

        int64_t now = platform_time_us();
        if (client_ts > now) {
            uint32_t wait_ms = static_cast<uint32_t>((client_ts - now) / US_PER_MS);
            if (wait_ms > 0) {
                cmd = flags.wait(COMMAND_STOP | COMMAND_FLUSH, false, true, wait_ms);
                if (cmd & COMMAND_STOP) {
                    break;
                }
                if (cmd & COMMAND_FLUSH) {
                    ArtworkNotification dummy{};
                    while (queue.receive(dummy, 0)) {}
                    continue;
                }
            }
        }

        // Display/swap callback
        if (self->listener_) {
            self->listener_->on_image_display(slot, client_ts);
        }
    }

    SS_LOGD(TAG, "Drain thread stopped");
}

}  // namespace sendspin
