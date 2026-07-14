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

/// @file artwork_role.h
/// @brief Artwork role that receives artwork images from the server

#pragma once

#include "sendspin/config.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace sendspin {

class SendspinClient;

/// @brief Listener for artwork role events
///
/// THREAD SAFETY: on_image_decode() fires on a dedicated decode thread and must be
/// thread-safe with respect to the other callbacks. on_image_display() and on_image_clear()
/// fire on the main loop thread.
///
/// ACK GATE (opt-in per slot via ImageSlotPreference::require_frame_done): a "delivery" is
/// either a frame (on_image_decode() followed later by on_image_display()) or a clear
/// (on_image_clear()). For an ack-enabled slot, at most one un-acked delivery is ever in flight;
/// the newest payload that arrives while a delivery is un-acked is buffered latest-wins and
/// delivered only after the consumer calls ArtworkRole::frame_done(slot). A clear supersedes any
/// un-acked frame for that slot -- exactly one ack is owed, and it is for the clear. A stream
/// restart automatically releases a frame that was decoded but never displayed (its display can
/// no longer fire), but a delivery that already reached on_image_display()/on_image_clear() stays
/// gated until frame_done() is called; there is no timeout.
class ArtworkRoleListener {
public:
    virtual ~ArtworkRoleListener() = default;

    /// @brief Called on the decode thread when encoded image data arrives
    ///
    /// The implementation should decode the image (e.g., JPEG to bitmap) synchronously.
    /// The data pointer is valid for the duration of this call.
    /// @param slot The artwork slot index.
    /// @param data Pointer to the encoded image data.
    /// @param length Length of the encoded image data in bytes.
    /// @param format Image format (JPEG, PNG, BMP).
    virtual void on_image_decode(uint8_t /*slot*/, const uint8_t* /*data*/, size_t /*length*/,
                                 SendspinImageFormat /*format*/) {}

    /// @brief Called on the main loop thread at the correct timestamp when the decoded image
    /// should be displayed
    ///
    /// Fires after on_image_decode() once the server timestamp is reached. The deadline can be
    /// shifted per slot via ImageSlotPreference::display_offset_ms (positive fires early, e.g.
    /// to start a cross-fade before the track boundary). If a newer frame for the same slot
    /// finishes decoding before the pending display fires, the older pending display is
    /// superseded and only the newer one is delivered.
    /// @param slot The artwork slot index.
    virtual void on_image_display(uint8_t /*slot*/) {}

    /// @brief Called on the main loop thread when artwork should be cleared for a slot
    ///
    /// Fires on stream end or stream clear for each configured slot.
    /// @param slot The artwork slot index to clear.
    virtual void on_image_clear(uint8_t /*slot*/) {}
};

/**
 * @brief Artwork role that receives album art and artist images from the server
 *
 * Receives binary image payloads from the server and delivers them to the platform
 * through ArtworkRoleListener callbacks. A dedicated decode thread fires on_image_decode()
 * immediately when data arrives; on_image_display() and on_image_clear() fire on the main
 * loop thread, with on_image_display() scheduled to the server timestamp. Supports multiple
 * image slots with configurable format and resolution preferences.
 *
 * A slot may opt into a back-pressure gate via ImageSlotPreference::require_frame_done: see
 * the ArtworkRoleListener class comment for the ack contract. Call frame_done() once the
 * consumer has finished presenting a delivery for such a slot.
 *
 * Usage:
 * 1. Implement ArtworkRoleListener with on_image_decode() and on_image_display()
 * 2. Build an ArtworkRoleConfig with the desired slot/format/resolution preferences
 * 3. Add the role to the client via SendspinClient::add_artwork()
 * 4. Call set_listener() with your listener implementation
 *
 * @code
 * struct MyArtworkListener : ArtworkRoleListener {
 *     void on_image_decode(uint8_t slot, const uint8_t* data, size_t length,
 *                          SendspinImageFormat format) override {
 *         decoded_images[slot] = decode(data, length, format);
 *     }
 *     void on_image_display(uint8_t slot) override {
 *         // Slot 0 has require_frame_done set, so this starts a cross-fade; frame_done() is
 *         // called once the fade finishes instead of immediately.
 *         display.start_fade(slot, decoded_images[slot]);
 *     }
 *     void on_image_clear(uint8_t slot) override {
 *         display.clear_slot(slot);
 *         artwork_role->frame_done(slot);
 *     }
 *     void on_fade_complete(uint8_t slot) {
 *         artwork_role->frame_done(slot);
 *     }
 *
 *     ArtworkRole* artwork_role{nullptr};
 * };
 *
 * MyArtworkListener listener;
 * ArtworkRoleConfig config;
 * config.preferred_formats = {{SendspinImageSource::ALBUM,
 *                            SendspinImageFormat::JPEG, 240, 240, true}};
 * auto& artwork = client.add_artwork(config);
 * listener.artwork_role = &artwork;
 * artwork.set_listener(&listener);
 * @endcode
 */
class ArtworkRole {
    friend class SendspinClient;

public:
    struct Impl;

    ArtworkRole(ArtworkRoleConfig config, SendspinClient* client);
    ~ArtworkRole();

    /// @brief Sets the listener for artwork events
    /// @note The listener must outlive this role.
    /// @param listener Pointer to the listener implementation; must outlive this role
    void set_listener(ArtworkRoleListener* listener);

    /// @brief Acknowledges the most recent delivery for an ack-gated slot, releasing the gate
    ///
    /// Call from the main loop thread after finishing presentation of the most recent delivery
    /// (frame or clear) for a slot with ImageSlotPreference::require_frame_done set, e.g. once a
    /// cross-fade animation completes. Safe no-op if the slot has nothing un-acked (including
    /// slots where require_frame_done is false). Also safe to call from inside
    /// on_image_display() or on_image_clear() for instant (non-animated) presentation.
    /// @param slot The artwork slot index to acknowledge.
    void frame_done(uint8_t slot);

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
