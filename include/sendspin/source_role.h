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

/// @file source_role.h
/// @brief Audio capture role that streams audio from the client to the Sendspin server

#pragma once

#include "sendspin/config.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Source types
// ============================================================================

/// @brief Line-input signal state reported by the source role in client/state messages
enum class SourceSignal : uint8_t {
    PRESENT,  // Audio signal detected on the capture input
    ABSENT,   // No audio signal on the capture input
};

/// @brief Listener for source role events. All methods fire on the main loop thread.
class SourceRoleListener {
public:
    virtual ~SourceRoleListener() = default;

    /// @brief Called when the outbound stream to the server has opened (the server commanded
    /// start and client-stream/start was sent); write_audio() accepts audio from this point on
    virtual void on_streaming_started() {}

    /// @brief Called when the outbound stream to the server has closed (server stop command,
    /// connection loss, or disconnect); write_audio() rejects audio again
    virtual void on_streaming_stopped() {}
};

/**
 * @brief Audio capture role that streams audio to the server
 *
 * Streaming is gated by the server (Sendspin spec, Source messages): the client never streams
 * unsolicited, the default after connect is stopped, and permission does not survive
 * reconnection. When the server commands start, the role announces its capture format with
 * client-stream/start and then forwards audio written via write_audio() as timestamped binary
 * chunks until the server commands stop (or the connection is lost), closing with
 * client-stream/end.
 *
 * The capture format is fixed at add_source() time: the SourceRoleConfig passed there is the
 * format contract for every stream this role opens. Changing formats requires tearing down the
 * client and re-adding the role with a new config.
 *
 * Usage:
 * 1. Implement SourceRoleListener to learn when the server starts/stops the stream
 * 2. Add the role to the client via SendspinClient::add_source() with the capture format
 * 3. Call set_listener() with your listener implementation
 * 4. Feed captured audio to write_audio() from your capture thread
 *
 * @code
 * struct MySourceListener : SourceRoleListener {
 *     void on_streaming_started() override { capture.enable(); }
 *     void on_streaming_stopped() override { capture.disable(); }
 * };
 *
 * MySourceListener listener;
 * auto& source = client.add_source(SourceRoleConfig{});
 * source.set_listener(&listener);
 *
 * // Capture thread:
 * source.write_audio(pcm_frames, len, capture_time_us);
 * @endcode
 */
class SourceRole {
    friend class SendspinClient;

public:
    struct Impl;

    SourceRole(SourceRoleConfig config, SendspinClient* client);
    ~SourceRole();

    /// @brief Sets the listener for source events
    /// @note The listener must outlive this role
    /// @param listener Pointer to the listener implementation
    void set_listener(SourceRoleListener* listener);

    /// @brief Writes captured audio into the outbound stream
    ///
    /// Hot path: non-blocking and non-allocating. Exactly one producer thread may call this;
    /// the library does not serialize concurrent writers.
    ///
    /// @param data Interleaved little-endian signed PCM in the configured format (24-bit as 3
    ///        packed bytes per sample). Bytes are forwarded untouched; the config passed to
    ///        add_source() is the format contract.
    /// @param len Length in bytes; must be a whole number of frames (one frame = one sample
    ///        across all channels). A non-whole-frame write is rejected as a whole.
    /// @param capture_time_us Local-clock capture time (same domain as the client's time
    ///        functions) of the FIRST sample in data. Pass 0 to stamp with the current time,
    ///        a best-effort fallback for callers that cannot timestamp their ADC.
    /// @return true if the audio was accepted; false when the stream is not open or the
    ///         capture buffer is full (the write is dropped and counted).
    bool write_audio(const uint8_t* data, size_t len, int64_t capture_time_us);

    /// @brief Reports the capture input's signal state, published to the server via client/state
    ///
    /// Must be called from the main loop thread. Only meaningful when
    /// SourceRoleConfig::line_sense is set; ignored (with a warning) otherwise.
    /// @param signal The new signal state
    void set_signal(SourceSignal signal);

    /// @brief Returns true while the outbound stream is open. Main-loop thread only: reflects
    /// the started/stopped listener callbacks, which fire there.
    bool is_streaming() const;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
