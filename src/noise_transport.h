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
/// outbound fragmentation, and inbound fragment reassembly.
///
/// Every use runs on the protocol task: the encrypt and send path (send_json, send_binary), the
/// decrypt path (decrypt_in_place) and reassembly (accept_plaintext), and the session swaps
/// (activate at handshake COMPLETE, send_msg2_and_swap at a re-handshake). One thread owns the
/// session, so this class takes no lock: a swap is sequential with every encrypt and decrypt, and
/// the reused send_buf_ is filled and encrypted by one caller at a time.

#pragma once

#include "noise_session.h"
#include "platform/memory.h"
#include "platform/types.h"
#include "sendspin/types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace sendspin {

/// @brief Owns the Noise transport session and the wire framing around it.
///
/// A SendspinConnection embeds one NoiseTransport and wires set_frame_sink() to its
/// send_transport_frame(). All post-handshake application traffic flows through send_json() /
/// send_binary() outbound and decrypt_in_place() + accept_plaintext() inbound.
class NoiseTransport {
public:
    /// @brief Run by the transport immediately before it writes a frame to the socket
    using FrameWriteHook = std::function<void()>;

    /// @brief Sink that writes one encrypted frame to the wire as a binary WS frame, running
    /// `before_write` (if set) immediately before the write.
    using FrameSink =
        std::function<SsErr(const uint8_t* data, size_t len, const FrameWriteHook& before_write)>;

    /// @brief One complete (non-fragment, fully reassembled) plaintext transport message.
    /// data == nullptr means "no complete message yet" (mid-reassembly, or a dropped frame),
    /// unless `malformed` is set (see below). The pointed-to bytes are valid until the next
    /// accept_plaintext() call.
    struct CompleteMessage {
        uint8_t* data{nullptr};
        size_t len{0};
        /// True when this (empty) result is a messaging.md "Malformed sequences" protocol
        /// error: a first fragment while one is in flight, a non-first fragment with none in
        /// flight, a non-fragment message while one is in flight, a nonzero reserved flag bit,
        /// an orig_type of 1, a fragment frame missing its flags byte, or a first fragment
        /// missing its orig_type, rather than the benign "no complete message yet"
        /// mid-reassembly state. The caller must close the connection when this is true.
        bool malformed{false};
    };

    /// @brief Sets the sink used to emit encrypted frames. Must be set before activate().
    void set_frame_sink(FrameSink sink) {
        this->frame_sink_ = std::move(sink);
    }

    /// @brief Installs the cipher session produced by the initial Noise handshake and marks
    /// the transport active. Called on the protocol task at handshake COMPLETE.
    void activate(std::unique_ptr<NoiseSession> session);

    /// @brief Returns the current session's 32-byte Noise handshake hash, or nullopt if no
    /// session is active. Protocol task only.
    std::optional<std::array<uint8_t, 32>> handshake_hash() const;

    /// @brief Returns true once a transport session exists (stays true across re-handshake
    /// swaps). This is the check send paths use to decide encrypted-vs-cleartext. Protocol task
    /// only.
    bool is_active() const {
        return this->active_;
    }

    // ========================================
    // Outbound (encrypt + send); protocol task only
    // ========================================

    /// @brief Encrypt and send a JSON string as a Noise transport frame.
    /// Encodes as [MSG_TYPE_JSON_BODY | utf8(json)] -> encrypt -> frame sink.
    /// Fragments automatically when the plaintext exceeds MAX_TRANSPORT_PLAINTEXT.
    /// @param before_write Goes to the frame sink with the message's last frame. A synchronous
    ///                     transport runs it inside this call, so it must not block or send.
    /// @return SsErr::OK on success, INVALID_STATE if the transport is not active.
    SsErr send_json(const char* json, size_t len, const FrameWriteHook& before_write = nullptr);

    /// @brief Convenience overload of send_json(const char*, size_t) for std::string callers.
    SsErr send_json(const std::string& json) {
        return this->send_json(json.data(), json.size());
    }

    /// @brief Encrypt and send pre-typed binary data as a Noise transport frame.
    /// @param data  Pointer to type-prefixed binary bytes (first byte is the role type byte).
    SsErr send_binary(const uint8_t* data, size_t len);

    /// @brief Re-handshake commit: encrypt and send msg2 under the OLD session, then swap to
    /// the new session. Protocol task only, like every other send, so no encrypt falls between
    /// the msg2 send and the swap.
    /// @return SsErr::OK on success (session swapped); on error the old session is kept.
    SsErr send_msg2_and_swap(const std::string& msg2_text,
                             std::unique_ptr<NoiseSession> next_session);

    // ========================================
    // Inbound (decrypt + reassemble); protocol task only
    // ========================================

    /// @brief Decrypts one transport frame in-place. Protocol task only, sequential with the
    /// session swap (see the file comment).
    /// @param len  Ciphertext length (plaintext + 16-byte tag).
    /// @return Plaintext length, or 0 on auth failure / no active session.
    size_t decrypt_in_place(uint8_t* ciphertext, size_t len);

    /// @brief Routes one decrypted plaintext frame through the fragment state machine.
    /// Non-fragment frames are returned directly (the same pointer, so the caller can tell the
    /// message is still where it decrypted it); type-1 fragment frames are buffered until one
    /// carrying FRAGMENT_FLAG_LAST produces the reassembled message.
    /// @param admitted Whether the owning connection holds the admitted slot
    ///        (InboundGate::is_admitted()), which selects the reassembly cap:
    ///        MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES until it does.
    /// @return The complete message (type byte first), or {nullptr, 0} if the frame was
    ///         consumed by reassembly, discarded, or dropped as malformed.
    CompleteMessage accept_plaintext(uint8_t* plaintext, size_t len, bool admitted);

    /// @brief Sets memory placement for the fragmentation and reassembly buffers (ESP-IDF
    /// only; ignored on host). Call during connection setup, before any transport traffic.
    void set_buffer_location(MemoryLocation location) {
        this->buffer_location_ = location;
    }

private:
    /// @brief Encrypt one frame and emit it via the frame sink.
    /// @param buf_capacity  Total capacity of buf; must be >= plaintext_len + 16 (AEAD tag).
    SsErr encrypt_and_send_frame(uint8_t* buf, size_t buf_capacity, size_t plaintext_len,
                                 const FrameWriteHook& before_write);

    /// @brief Fragment a plaintext > MAX_TRANSPORT_PLAINTEXT into multiple frames and
    /// encrypt+send each one. Implements messaging.md "Fragmentation": every fragment is a
    /// type-1 message, the first also carrying orig_type.
    ///
    /// The plaintext is passed as its type byte plus the payload rather than as one contiguous
    /// buffer, so no caller has to stage a copy of a message this large.
    ///
    /// The fragments of one logical message reach the wire consecutively, since a peer that sees
    /// a non-fragment frame between them treats it as a messaging.md "Malformed sequences" error
    /// (see accept_plaintext()); every send runs on the protocol task, so none can fall between
    /// them.
    /// @param before_write Passed to the frame sink with the last fragment.
    SsErr fragment_and_send(uint8_t orig_type, const uint8_t* data, size_t data_len,
                            const FrameWriteHook& before_write);

    /// @brief Fills send_buf_ with an optional prefix followed by data, then encrypts and
    /// sends it.
    SsErr fill_and_encrypt(const uint8_t* prefix, size_t prefix_len, const uint8_t* data,
                           size_t data_len, const FrameWriteHook& before_write);

    /// @brief Grows a PlatformBuffer to at least `needed` bytes (geometric growth, contents
    /// preserved, capacity retained across calls), optionally capped.
    /// @param cap     Upper bound on the grown size, or 0 for uncapped.
    /// @param what    Noun describing the buffer, used in the allocation-failure log line.
    bool grow_buffer(PlatformBuffer& buf, size_t needed, size_t cap, const char* what);

    /// @brief The reassembly cap in force: MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES until the
    /// owning connection is admitted, MAX_REASSEMBLED_MESSAGE_BYTES after.
    static size_t reasm_cap(bool admitted);

    /// @brief Grows reasm_buf_ to at least `needed` bytes, capped at the cap in force plus the
    /// orig_type byte. See grow_buffer().
    bool reasm_reserve(size_t needed, bool admitted);

    /// @brief Grows send_buf_ to at least `needed` bytes, capped at MAX_TRANSPORT_PLAINTEXT + 16
    /// (the largest plaintext + AEAD tag room the non-fragmented path ever handles). See
    /// grow_buffer().
    bool ensure_send_buf(size_t needed);

    /// @brief Discards any in-flight reassembly state (keeps the allocation).
    void reasm_reset() {
        this->reasm_len_ = 0;
        this->reasm_in_progress_ = false;
        this->reasm_discarding_ = false;
    }

    // Struct fields

    /// Emits one encrypted frame as a binary WS frame.
    FrameSink frame_sink_;

    /// Accumulates the reassembled message as [orig_type][data...] while a fragmented
    /// message is in flight; on completion accept_plaintext() returns a pointer into this
    /// buffer, valid until the next accept_plaintext() call. Grows with the largest
    /// fragmented message received (a player audio chunk) and retains its capacity, so it is
    /// placed per buffer_location_ (PSRAM-preferring by default on ESP). Protocol task only.
    PlatformBuffer reasm_buf_;

    /// Reused scratch buffer for the non-fragmented send path (send_json, send_binary,
    /// send_msg2_and_swap). Grown on demand by ensure_send_buf() to fit each frame (geometric
    /// growth, same idiom as reasm_buf_/reasm_reserve()), capped at MAX_TRANSPORT_PLAINTEXT + 16
    /// bytes, so typical traffic settles at a working-set size well under that ceiling instead of
    /// paying it on every connection. Protocol task only, like every send. Placed per
    /// buffer_location_ like reasm_buf_.
    PlatformBuffer send_buf_;

    // Pointer fields
    /// Noise cipher session (set at handshake COMPLETE, replaced on re-handshake swap).
    /// Protocol task only.
    std::unique_ptr<NoiseSession> session_;

    // size_t fields
    /// Bytes used in reasm_buf_ (including the leading orig_type byte), 0 while the in-flight
    /// message is being discarded. Protocol task only.
    size_t reasm_len_{0};

    // 8-bit fields
    /// Memory placement for reasm_buf_, send_buf_ and the fragmentation frame buffer.
    MemoryLocation buffer_location_{MemoryLocation::PREFER_EXTERNAL};

    /// True once a transport session exists. See is_active(). Protocol task only.
    bool active_{false};

    /// True when the in-flight message's data is being thrown away rather than buffered: its
    /// orig_type is a reserved ID nothing implements, it outgrew the reassembly cap in force,
    /// or the buffer could not be grown for it. The sequence is still tracked to its last
    /// fragment, but the message is never dispatched. Protocol task only.
    bool reasm_discarding_{false};

    /// True while a fragmented message is in flight, whether it is being reassembled or
    /// discarded. This is the flag the malformed-sequence rules key off. Protocol task only.
    bool reasm_in_progress_{false};
};

}  // namespace sendspin
