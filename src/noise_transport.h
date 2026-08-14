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

/// @file noise_transport.h
/// @brief Encrypted transport layer for a Sendspin connection: owns the Noise cipher session,
/// its send-side mutex, outbound fragmentation, and inbound fragment reassembly.
///
/// This class isolates every piece of state that the "decrypt runs unlocked on the network
/// thread" invariant applies to. Its threading contract:
///
///   - ENCRYPT / send (send_json, send_binary): any thread; serialized by session_mutex_.
///   - DECRYPT (decrypt_in_place) and reassembly (accept_plaintext): NETWORK THREAD ONLY.
///     The decrypt path is deliberately unlocked: the only writer that can replace the session
///     mid-connection (send_msg2_and_swap, driven by an inbound re-handshake frame) runs on the
///     same network thread, so decrypt and swap are sequential, never concurrent.
///   - Session swap (activate, send_msg2_and_swap): network thread, under session_mutex_ so a
///     concurrent main-loop encrypt cannot interleave with the swap.

#pragma once

#include "noise_session.h"
#include "platform/memory.h"
#include "platform/types.h"
#include "sendspin/types.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace sendspin {

/// @brief Owns the Noise transport session and the wire framing around it.
///
/// A SendspinConnection embeds one NoiseTransport and wires set_frame_sink() to its
/// send_binary_message(). All post-handshake application traffic flows through send_json() /
/// send_binary() outbound and decrypt_in_place() + accept_plaintext() inbound.
class NoiseTransport {
public:
    /// @brief Sink that writes one encrypted frame to the wire as a binary WS frame.
    using FrameSink = std::function<SsErr(const uint8_t* data, size_t len)>;

    /// @brief One complete (non-fragment, fully reassembled) plaintext transport message.
    /// data == nullptr means "no complete message yet" (mid-reassembly, or a dropped frame) --
    /// unless `malformed` is set (see below). The pointed-to bytes are valid until the next
    /// accept_plaintext() call.
    struct CompleteMessage {
        uint8_t* data{nullptr};
        size_t len{0};
        /// True when this (empty) result is a spec "Malformed sequences" protocol error -- a
        /// fragment-end frame with no fragmented message in flight, a non-fragment frame while
        /// one is in flight, or a reassembled orig_type of 2 or 3 -- rather than the benign "no
        /// complete message yet" mid-reassembly state. The caller MUST close the connection
        /// when this is true.
        bool malformed{false};
    };

    /// @brief Sets the sink used to emit encrypted frames. Must be set before activate().
    void set_frame_sink(FrameSink sink) {
        this->frame_sink_ = std::move(sink);
    }

    /// @brief Installs the cipher session produced by the initial Noise handshake and marks
    /// the transport active. Called on the network thread at handshake COMPLETE.
    void activate(std::unique_ptr<NoiseSession> session);

    /// @brief Returns the current session's 32-byte Noise handshake hash, or nullopt if no
    /// session is active. Takes session_mutex_, so it is safe from any thread.
    std::optional<std::array<uint8_t, 32>> handshake_hash() const;

    /// @brief Returns true once a transport session exists (stays true across re-handshake
    /// swaps). Atomic; safe from any thread. This is the check send paths use to decide
    /// encrypted-vs-cleartext without racing a session swap.
    bool is_active() const {
        return this->active_.load(std::memory_order_acquire);
    }

    // ========================================
    // Outbound (encrypt + send); any thread, serialized by session_mutex_
    // ========================================

    /// @brief Encrypt and send a JSON string as a Noise transport frame.
    /// Encodes as [MSG_TYPE_JSON_BODY | utf8(json)] -> encrypt -> frame sink.
    /// Fragments automatically when the plaintext exceeds MAX_TRANSPORT_PLAINTEXT.
    /// @return SsErr::OK on success, INVALID_STATE if the transport is not active.
    SsErr send_json(const char* json, size_t len);

    /// @brief Convenience overload of send_json(const char*, size_t) for std::string callers.
    SsErr send_json(const std::string& json) {
        return this->send_json(json.data(), json.size());
    }

    /// @brief Encrypt and send pre-typed binary data as a Noise transport frame.
    /// @param data  Pointer to type-prefixed binary bytes (first byte is the role type byte).
    /// @param len   Total length including the type byte.
    /// @return SsErr::OK on success, INVALID_STATE if the transport is not active.
    SsErr send_binary(const uint8_t* data, size_t len);

    /// @brief Re-handshake commit: encrypt and send msg2 under the OLD session, then swap to
    /// the new session, all inside one locked region so a concurrent encrypt cannot interleave
    /// between the msg2 send and the swap. Called on the network thread.
    /// @param msg2_text     The noise/handshake msg2 JSON to send under the old keys.
    /// @param next_session  The new cipher session to swap in.
    /// @return SsErr::OK on success (session swapped); on error the old session is kept.
    SsErr send_msg2_and_swap(const std::string& msg2_text,
                             std::unique_ptr<NoiseSession> next_session);

    // ========================================
    // Inbound (decrypt + reassemble); NETWORK THREAD ONLY
    // ========================================

    /// @brief Decrypts one transport frame in-place. Unlocked by design: see the file comment
    /// (decrypt is sequential with the session swap on the same thread).
    /// @param ciphertext  Frame bytes (modified in-place).
    /// @param len         Ciphertext length (plaintext + 16-byte tag).
    /// @return Plaintext length, or 0 on auth failure / no active session.
    size_t decrypt_in_place(uint8_t* ciphertext, size_t len);

    /// @brief Routes one decrypted plaintext frame through the fragment state machine.
    /// Non-fragment frames are returned directly; fragment frames are buffered until the
    /// terminating MSG_TYPE_FRAGMENT_END produces the reassembled message.
    /// @param plaintext  Decrypted frame bytes (type byte first).
    /// @param len        Plaintext length.
    /// @return The complete message (type byte first), or {nullptr, 0} if the frame was
    ///         consumed by reassembly or dropped as malformed.
    CompleteMessage accept_plaintext(uint8_t* plaintext, size_t len);

    /// @brief Sets memory placement for the fragmentation and reassembly buffers (ESP-IDF
    /// only; ignored on host). Call during connection setup, before any transport traffic.
    void set_buffer_location(MemoryLocation location) {
        this->buffer_location_ = location;
    }

private:
    /// @brief Encrypt one frame and emit it via the frame sink. Acquires session_mutex_.
    /// @param buf           Frame buffer holding the plaintext; encrypted in-place.
    /// @param buf_capacity  Total capacity of buf; must be >= plaintext_len + 16 (AEAD tag).
    /// @param plaintext_len Plaintext byte count at the start of buf.
    SsErr encrypt_and_send_frame(uint8_t* buf, size_t buf_capacity, size_t plaintext_len);

    /// @brief Same as encrypt_and_send_frame, but the caller already holds session_mutex_.
    SsErr encrypt_and_send_frame_locked(uint8_t* buf, size_t buf_capacity, size_t plaintext_len);

    /// @brief Fragment a plaintext > MAX_TRANSPORT_PLAINTEXT into multiple frames and
    /// encrypt+send each one. Matches wire.py `_fragment` exactly.
    SsErr fragment_and_send(const uint8_t* plaintext, size_t plaintext_len);

    /// @brief Grows reasm_buf_ to at least `needed` bytes (geometric growth, contents
    /// preserved, capacity retained across messages). Returns false on allocation failure.
    bool reasm_reserve(size_t needed);

    /// @brief Discards any in-flight reassembly state (keeps the allocation).
    void reasm_reset() {
        this->reasm_len_ = 0;
        this->reasm_in_progress_ = false;
    }

    /// Noise cipher session (set at handshake COMPLETE, replaced on re-handshake swap).
    /// Guarded by session_mutex_ for the ENCRYPT (send) path and the swap; the DECRYPT
    /// (receive) path reads it unlocked (same-thread sequential with the swap).
    std::unique_ptr<NoiseSession> session_;

    /// Guards the send-side encrypt path against the re-handshake session swap.
    mutable std::mutex session_mutex_;

    /// True once a transport session exists. See is_active().
    std::atomic<bool> active_{false};

    /// Emits one encrypted frame as a binary WS frame.
    FrameSink frame_sink_;

    // Fragment reassembly state (network thread only).

    /// Accumulates the reassembled message as [orig_type][data...] while a fragmented
    /// message is in flight; on completion accept_plaintext() returns a pointer into this
    /// buffer, valid until the next accept_plaintext() call. Grows with the largest
    /// fragmented message received (e.g. album artwork) and retains its capacity, so it is
    /// placed per buffer_location_ (PSRAM-preferring by default on ESP).
    PlatformBuffer reasm_buf_;

    /// Bytes used in reasm_buf_ (including the leading orig_type byte).
    size_t reasm_len_{0};

    /// True when a fragmented message is being reassembled.
    bool reasm_in_progress_{false};

    /// Memory placement for reasm_buf_ and the fragmentation frame buffer.
    MemoryLocation buffer_location_{MemoryLocation::PREFER_EXTERNAL};
};

}  // namespace sendspin
