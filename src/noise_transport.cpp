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

#include "noise_transport.h"

#include "crypto/constants.h"
#include "platform/logging.h"

#include <cstring>
#include <utility>
#include <vector>

namespace sendspin {

static const char* const TAG = "sendspin.noise_transport";

// ============================================================================
// Session lifecycle
// ============================================================================

void NoiseTransport::activate(std::unique_ptr<NoiseSession> session) {
    {
        std::lock_guard<std::mutex> lock(this->session_mutex_);
        this->session_ = std::move(session);
    }
    this->active_.store(true, std::memory_order_release);
}

std::optional<std::array<uint8_t, 32>> NoiseTransport::handshake_hash() const {
    std::lock_guard<std::mutex> lock(this->session_mutex_);
    if (!this->session_) {
        return std::nullopt;
    }
    return this->session_->handshake_hash();
}

// ============================================================================
// Outbound (encrypt + send)
// ============================================================================

SsErr NoiseTransport::encrypt_and_send_frame_locked(uint8_t* buf, size_t buf_capacity,
                                                    size_t plaintext_len) {
    if (!this->session_) {
        return SsErr::INVALID_STATE;
    }

    // Every caller allocates plaintext_len + 16; this guards against a future caller that
    // forgets the AEAD tag room.
    if (buf_capacity < plaintext_len + 16) {
        SS_LOGE(TAG, "encrypt_and_send_frame: buffer lacks AEAD tag room");
        return SsErr::FAIL;
    }

    size_t ct_len = this->session_->encrypt(buf, plaintext_len, buf_capacity);
    if (ct_len == 0) {
        SS_LOGE(TAG, "Noise encrypt failed");
        return SsErr::FAIL;
    }

    if (!this->frame_sink_) {
        return SsErr::INVALID_STATE;
    }
    return this->frame_sink_(buf, ct_len);
}

SsErr NoiseTransport::fragment_and_send_locked(const uint8_t* plaintext, size_t plaintext_len) {
    // Matches wire.py _fragment() exactly.
    // plaintext[0] = orig_type; plaintext[1..] = data.
    const uint8_t orig_type = plaintext[0];
    const uint8_t* data = plaintext + 1;
    const size_t data_len = plaintext_len - 1;

    const size_t first_cap = MAX_TRANSPORT_PLAINTEXT - 2;  // 65517
    const size_t cont_cap = MAX_TRANSPORT_PLAINTEXT - 1;   // 65518

    // Buffer reused for each frame (plaintext + 16-byte tag room). ~64 KB, so placed per
    // buffer_location_ (PSRAM-preferring by default on ESP) rather than internal RAM.
    PlatformBuffer frame_buf;
    if (!frame_buf.allocate(MAX_TRANSPORT_PLAINTEXT + 16, this->buffer_location_)) {
        SS_LOGE(TAG, "fragment_and_send: frame buffer allocation failed");
        return SsErr::FAIL;
    }

    // First frame: [MSG_TYPE_FRAGMENT_MORE, orig_type, data[:first_cap]]
    size_t first_chunk = (data_len < first_cap) ? data_len : first_cap;
    frame_buf.data()[0] = MSG_TYPE_FRAGMENT_MORE;
    frame_buf.data()[1] = orig_type;
    std::memcpy(frame_buf.data() + 2, data, first_chunk);
    size_t first_frame_len = 2 + first_chunk;

    SsErr err =
        this->encrypt_and_send_frame_locked(frame_buf.data(), frame_buf.size(), first_frame_len);
    if (err != SsErr::OK) {
        return err;
    }

    // Continuation frames
    size_t offset = first_chunk;
    while (offset < data_len) {
        size_t chunk = (data_len - offset < cont_cap) ? (data_len - offset) : cont_cap;
        bool is_last = (offset + chunk >= data_len);

        frame_buf.data()[0] = is_last ? MSG_TYPE_FRAGMENT_END : MSG_TYPE_FRAGMENT_MORE;
        std::memcpy(frame_buf.data() + 1, data + offset, chunk);
        size_t cont_frame_len = 1 + chunk;

        err =
            this->encrypt_and_send_frame_locked(frame_buf.data(), frame_buf.size(), cont_frame_len);
        if (err != SsErr::OK) {
            return err;
        }
        offset += chunk;
    }

    return SsErr::OK;
}

SsErr NoiseTransport::fill_and_encrypt_locked(const uint8_t* prefix, size_t prefix_len,
                                              const uint8_t* data, size_t data_len) {
    const size_t plaintext_len = prefix_len + data_len;
    if (!this->ensure_send_buf(plaintext_len + 16)) {
        return SsErr::FAIL;
    }
    if (prefix_len > 0) {
        std::memcpy(this->send_buf_.data(), prefix, prefix_len);
    }
    std::memcpy(this->send_buf_.data() + prefix_len, data, data_len);
    return this->encrypt_and_send_frame_locked(this->send_buf_.data(), this->send_buf_.size(),
                                               plaintext_len);
}

SsErr NoiseTransport::send_json(const char* json, size_t len) {
    if (!this->is_active()) {
        return SsErr::INVALID_STATE;
    }

    // Plaintext = [MSG_TYPE_JSON_BODY] + utf8(json)
    const size_t plaintext_len = 1 + len;

    if (plaintext_len <= MAX_TRANSPORT_PLAINTEXT) {
        // Locked for fill + encrypt + send, not just encrypt + send: send_buf_ is a shared
        // member, so the whole read/write window over it must stay inside the critical
        // section (see send_buf_'s doc comment).
        std::lock_guard<std::mutex> lock(this->session_mutex_);
        const uint8_t prefix = MSG_TYPE_JSON_BODY;
        return this->fill_and_encrypt_locked(&prefix, 1, reinterpret_cast<const uint8_t*>(json),
                                             len);
    }

    // Need fragmentation. Rare (large messages only) and unbounded in size (up to
    // MAX_REASSEMBLED_MESSAGE_BYTES), so it is not a candidate for the fixed-size reused
    // send_buf_; fragment_and_send_locked() allocates its own frame buffer instead. The
    // plaintext is staged before taking the lock so only the encrypt+send loop is serialized.
    std::vector<uint8_t> plaintext(plaintext_len);
    plaintext[0] = MSG_TYPE_JSON_BODY;
    std::memcpy(plaintext.data() + 1, json, len);
    std::lock_guard<std::mutex> lock(this->session_mutex_);
    return this->fragment_and_send_locked(plaintext.data(), plaintext_len);
}

SsErr NoiseTransport::send_binary(const uint8_t* data, size_t len) {
    if (!this->is_active()) {
        return SsErr::INVALID_STATE;
    }
    if (len == 0) {
        return SsErr::FAIL;
    }

    if (len <= MAX_TRANSPORT_PLAINTEXT) {
        std::lock_guard<std::mutex> lock(this->session_mutex_);
        return this->fill_and_encrypt_locked(nullptr, 0, data, len);
    }

    std::lock_guard<std::mutex> lock(this->session_mutex_);
    return this->fragment_and_send_locked(data, len);
}

SsErr NoiseTransport::send_msg2_and_swap(const std::string& msg2_text,
                                         std::unique_ptr<NoiseSession> next_session) {
    // One locked region for "send msg2 under the OLD session, then swap to the new session"
    // so a concurrent encrypt on another thread cannot interleave between the two. This also
    // covers the send_buf_ fill (see send_buf_'s doc comment).
    std::lock_guard<std::mutex> lock(this->session_mutex_);

    const size_t plaintext_len = 1 + msg2_text.size();
    if (plaintext_len > MAX_TRANSPORT_PLAINTEXT) {
        // The handshake msg2 JSON is never expected to approach this size; reject rather than
        // overflow the fixed-size send_buf_ (mirrors wire.py, which never fragments handshake
        // control messages).
        SS_LOGE(TAG, "send_msg2_and_swap: msg2 plaintext too large (%zu bytes)", plaintext_len);
        return SsErr::FAIL;
    }

    const uint8_t prefix = MSG_TYPE_JSON_BODY;
    SsErr err = this->fill_and_encrypt_locked(
        &prefix, 1, reinterpret_cast<const uint8_t*>(msg2_text.data()), msg2_text.size());
    if (err != SsErr::OK) {
        SS_LOGE(TAG, "send_msg2_and_swap: failed to send encrypted msg2 (err=%d)",
                static_cast<int>(err));
        return err;
    }

    // Swap to the new session. After this line, all subsequent inbound decrypt (network
    // thread, sequential with this call) uses the new session, and all subsequent encrypt
    // (once the lock is released) uses the new session too.
    this->session_ = std::move(next_session);
    return SsErr::OK;
}

// ============================================================================
// Inbound (decrypt + reassemble)
// ============================================================================

size_t NoiseTransport::decrypt_in_place(uint8_t* ciphertext, size_t len) {
    // NETWORK THREAD ONLY; unlocked by design (see the file comment).
    if (!this->session_) {
        return 0;
    }
    return this->session_->decrypt(ciphertext, len);
}

NoiseTransport::CompleteMessage NoiseTransport::accept_plaintext(uint8_t* plaintext, size_t len) {
    // NETWORK THREAD ONLY (reassembly state is unlocked).
    if (len == 0) {
        SS_LOGW(TAG, "accept_plaintext: empty plaintext");
        return {};
    }

    const uint8_t type_byte = plaintext[0];

    if (type_byte == MSG_TYPE_FRAGMENT_MORE) {
        // Fragment frame: begin or continue reassembly. reasm_buf_ accumulates the final
        // message shape directly ([orig_type][data...]), so completion needs no staging copy.
        if (!this->reasm_in_progress_) {
            // Start of a new fragmented message: pt[1] = orig_type, pt[2..] = data
            if (len < 2) {
                SS_LOGW(TAG, "fragment-more start: frame too short (%zu bytes)", len);
                this->reasm_reset();
                return {};
            }
            if (!this->reasm_reserve(len - 1)) {
                return {};
            }
            std::memcpy(this->reasm_buf_.data(), plaintext + 1, len - 1);
            this->reasm_len_ = len - 1;  // [orig_type] + (len - 2) data bytes
            this->reasm_in_progress_ = true;
        } else {
            // Continuation frame: pt[1..] = data
            const size_t new_data = len - 1;
            if (this->reasm_len_ - 1 + new_data > MAX_REASSEMBLED_MESSAGE_BYTES) {
                SS_LOGW(TAG, "fragmented message exceeds %zu bytes; discarding",
                        static_cast<size_t>(MAX_REASSEMBLED_MESSAGE_BYTES));
                this->reasm_reset();
                return {};
            }
            if (!this->reasm_reserve(this->reasm_len_ + new_data)) {
                this->reasm_reset();
                return {};
            }
            std::memcpy(this->reasm_buf_.data() + this->reasm_len_, plaintext + 1, new_data);
            this->reasm_len_ += new_data;
        }
        return {};
    }

    if (type_byte == MSG_TYPE_FRAGMENT_END) {
        if (!this->reasm_in_progress_) {
            // Spec "Malformed sequences": a fragment-end frame with no fragmented message in
            // flight is a protocol error; the caller must close the connection.
            SS_LOGW(TAG, "fragment-end with no fragmented message in flight; malformed sequence");
            return {nullptr, 0, true};
        }
        const size_t new_data = len - 1;
        if (this->reasm_len_ - 1 + new_data > MAX_REASSEMBLED_MESSAGE_BYTES) {
            SS_LOGW(TAG, "fragmented message exceeds %zu bytes on end; discarding",
                    static_cast<size_t>(MAX_REASSEMBLED_MESSAGE_BYTES));
            this->reasm_reset();
            return {};
        }
        if (!this->reasm_reserve(this->reasm_len_ + new_data)) {
            this->reasm_reset();
            return {};
        }
        std::memcpy(this->reasm_buf_.data() + this->reasm_len_, plaintext + 1, new_data);
        this->reasm_len_ += new_data;
        this->reasm_in_progress_ = false;

        // The reassembled message's type byte must be a terminal type, never a fragment
        // type. A peer that nests a fragment type is malformed; drop it rather than
        // re-entering the fragment state machine (matches wire.py, which dispatches the
        // reassembled bytes directly instead of re-decoding them).
        const uint8_t orig_type = this->reasm_buf_.data()[0];
        if (orig_type == MSG_TYPE_FRAGMENT_MORE || orig_type == MSG_TYPE_FRAGMENT_END) {
            // Spec "Malformed sequences": an orig_type of 2 or 3 is a protocol error; the
            // caller must close the connection.
            SS_LOGW(TAG, "reassembled message has fragment orig_type=%d; malformed sequence",
                    static_cast<int>(orig_type));
            this->reasm_reset();
            return {nullptr, 0, true};
        }

        // reasm_buf_ already holds [orig_type][data...]; the returned pointer stays valid
        // until the next accept_plaintext() call (the next fragment start overwrites it).
        return {this->reasm_buf_.data(), this->reasm_len_};
    }

    // Spec "Malformed sequences": a non-fragment frame while a fragmented message is in flight
    // is a protocol error; the caller must close the connection.
    if (this->reasm_in_progress_) {
        SS_LOGW(TAG,
                "non-fragment frame (type=%d) while a fragmented message is in flight; "
                "malformed sequence",
                static_cast<int>(type_byte));
        this->reasm_reset();
        return {nullptr, 0, true};
    }

    return {plaintext, len};
}

bool NoiseTransport::grow_buffer(PlatformBuffer& buf, size_t needed, size_t cap, const char* what) {
    if (buf.size() >= needed) {
        return true;
    }
    // Geometric growth amortizes realloc cost across repeated growth; capacity is retained
    // between calls instead of shrinking back down.
    size_t new_size = buf.size() * 2;
    if (new_size < needed) {
        new_size = needed;
    }
    if (cap != 0 && new_size > cap) {
        new_size = cap;
    }
    const bool ok = (buf.data() == nullptr) ? buf.allocate(new_size, this->buffer_location_)
                                            : buf.realloc(new_size);
    if (!ok) {
        SS_LOGE(TAG, "%s buffer allocation failed (%zu bytes)", what, new_size);
    }
    return ok;
}

bool NoiseTransport::reasm_reserve(size_t needed) {
    // Uncapped: fragmented messages are already size-limited by MAX_REASSEMBLED_MESSAGE_BYTES
    // at the caller (accept_plaintext), before this is reached.
    return this->grow_buffer(this->reasm_buf_, needed, 0, "reassembly");
}

bool NoiseTransport::ensure_send_buf(size_t needed) {
    // Capped at MAX_TRANSPORT_PLAINTEXT + 16 (the largest plaintext + AEAD tag room the
    // non-fragmented path ever handles); callers never request more (the non-fragmented path's
    // own size check enforces this), so the cap never actually clamps.
    return this->grow_buffer(this->send_buf_, needed, MAX_TRANSPORT_PLAINTEXT + 16, "send");
}

}  // namespace sendspin
