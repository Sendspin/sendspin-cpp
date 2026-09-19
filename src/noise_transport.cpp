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
    // messaging.md "Fragmentation": every fragment is a type-1 message, the first also carrying
    // orig_type. plaintext[0] = orig_type; plaintext[1..] = data.
    const uint8_t orig_type = plaintext[0];
    const uint8_t* data = plaintext + 1;
    const size_t data_len = plaintext_len - 1;

    const size_t first_cap = MAX_TRANSPORT_PLAINTEXT - 3;  // 65516
    const size_t cont_cap = MAX_TRANSPORT_PLAINTEXT - 2;   // 65517

    // Buffer reused for each frame (plaintext + 16-byte tag room). ~64 KB, so placed per
    // buffer_location_ (PSRAM-preferring by default on ESP) rather than internal RAM.
    PlatformBuffer frame_buf;
    if (!frame_buf.allocate(MAX_TRANSPORT_PLAINTEXT + 16, this->buffer_location_)) {
        SS_LOGE(TAG, "fragment_and_send: frame buffer allocation failed");
        return SsErr::FAIL;
    }

    size_t first_chunk = (data_len < first_cap) ? data_len : first_cap;
    frame_buf.data()[0] = MSG_TYPE_FRAGMENT;
    frame_buf.data()[1] = static_cast<uint8_t>(
        FRAGMENT_FLAG_FIRST | ((first_chunk == data_len) ? FRAGMENT_FLAG_LAST : 0));
    frame_buf.data()[2] = orig_type;
    std::memcpy(frame_buf.data() + 3, data, first_chunk);
    size_t first_frame_len = 3 + first_chunk;

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

        frame_buf.data()[0] = MSG_TYPE_FRAGMENT;
        frame_buf.data()[1] = is_last ? FRAGMENT_FLAG_LAST : 0;
        std::memcpy(frame_buf.data() + 2, data + offset, chunk);
        size_t cont_frame_len = 2 + chunk;

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
    // messaging.md "Fragmentation": a sender MUST NOT use 1 as orig_type; the transport owns
    // that ID.
    if (data[0] == MSG_TYPE_FRAGMENT) {
        SS_LOGE(TAG, "send_binary: message type 1 belongs to the fragmentation layer");
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

    if (plaintext[0] != MSG_TYPE_FRAGMENT) {
        // messaging.md "Malformed sequences": a non-fragment binary message received while a
        // fragmented message is in flight is a protocol error; the caller must close.
        if (this->reasm_in_progress_) {
            SS_LOGW(TAG,
                    "non-fragment frame (type=%d) while a fragmented message is in flight; "
                    "malformed sequence",
                    static_cast<int>(plaintext[0]));
            this->reasm_reset();
            return {nullptr, 0, true};
        }
        return {plaintext, len};
    }

    // A fragment frame with no flags byte carries no place in the sequence at all, so it cannot
    // be tracked; treat it like the enumerated malformed sequences and close.
    if (len < 2) {
        SS_LOGW(TAG, "fragment frame missing its flags byte; malformed sequence");
        this->reasm_reset();
        return {nullptr, 0, true};
    }

    const uint8_t flags = plaintext[1];
    if ((flags & FRAGMENT_FLAGS_RESERVED) != 0) {
        // messaging.md "Malformed sequences": a nonzero reserved flag bit.
        SS_LOGW(TAG, "fragment flags 0x%02x set a reserved bit; malformed sequence",
                static_cast<unsigned>(flags));
        this->reasm_reset();
        return {nullptr, 0, true};
    }

    // Every path below that reports a malformed sequence clears the reassembly state first, so
    // the connection the caller is about to close cannot be left holding one.
    const uint8_t* data = nullptr;
    size_t data_len = 0;

    if ((flags & FRAGMENT_FLAG_FIRST) != 0) {
        // messaging.md "Malformed sequences": a first fragment received while a fragmented
        // message is in flight.
        if (this->reasm_in_progress_) {
            SS_LOGW(TAG, "first fragment while a fragmented message is in flight; "
                         "malformed sequence");
            this->reasm_reset();
            return {nullptr, 0, true};
        }
        if (len < 3) {
            SS_LOGW(TAG, "first fragment missing its orig_type; malformed sequence");
            this->reasm_reset();
            return {nullptr, 0, true};
        }
        const uint8_t orig_type = plaintext[2];
        // messaging.md "Malformed sequences": an orig_type of 1. Fragments do not nest.
        if (orig_type == MSG_TYPE_FRAGMENT) {
            SS_LOGW(TAG, "first fragment declares orig_type 1; malformed sequence");
            this->reasm_reset();
            return {nullptr, 0, true};
        }
        // The ignore rules let a receiver discard the data of a message whose orig_type it does
        // not implement instead of allocating for it, as long as it keeps tracking the sequence.
        this->reasm_in_progress_ = true;
        this->reasm_discarding_ =
            (orig_type >= MSG_TYPE_RESERVED_FIRST && orig_type <= MSG_TYPE_RESERVED_LAST);
        this->reasm_len_ = 0;
        if (!this->reasm_discarding_) {
            // reasm_buf_ accumulates the final message shape directly ([orig_type][data...]),
            // so completion needs no staging copy.
            if (this->reasm_reserve(1)) {
                this->reasm_buf_.data()[0] = orig_type;
                this->reasm_len_ = 1;
            } else {
                this->reasm_discarding_ = true;
            }
        }
        data = plaintext + 3;
        data_len = len - 3;
    } else {
        // messaging.md "Malformed sequences": a non-first fragment received with none in flight.
        if (!this->reasm_in_progress_) {
            SS_LOGW(TAG, "continuation fragment with no fragmented message in flight; "
                         "malformed sequence");
            this->reasm_reset();
            return {nullptr, 0, true};
        }
        data = plaintext + 2;
        data_len = len - 2;
    }

    if (!this->reasm_discarding_) {
        if (this->reasm_len_ - 1 + data_len > MAX_REASSEMBLED_MESSAGE_BYTES) {
            SS_LOGW(TAG, "fragmented message exceeds %zu bytes; discarding the rest of it",
                    static_cast<size_t>(MAX_REASSEMBLED_MESSAGE_BYTES));
            this->reasm_discarding_ = true;
        } else if (!this->reasm_reserve(this->reasm_len_ + data_len)) {
            this->reasm_discarding_ = true;
        } else {
            std::memcpy(this->reasm_buf_.data() + this->reasm_len_, data, data_len);
            this->reasm_len_ += data_len;
        }
        if (this->reasm_discarding_) {
            // Nothing to dispatch any more, but the sequence is still tracked to its last
            // fragment so the malformed-sequence rules keep applying to the frames that follow.
            this->reasm_len_ = 0;
        }
    }

    if ((flags & FRAGMENT_FLAG_LAST) == 0) {
        return {};
    }

    const bool discarded = this->reasm_discarding_;
    const size_t complete_len = this->reasm_len_;
    this->reasm_reset();
    if (discarded) {
        return {};
    }
    // The returned pointer stays valid until the next accept_plaintext() call (the next first
    // fragment overwrites it).
    return {this->reasm_buf_.data(), complete_len};
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
    // Capped at MAX_REASSEMBLED_MESSAGE_BYTES + 1: the caller's own size check (accept_plaintext)
    // admits a `needed` of exactly that much, one byte of orig_type plus the largest message it
    // will reassemble. Without the cap the doubling step above that admitted size would reserve
    // ~2 MiB per connection, retained for the connection's life, which a peer picks by choosing
    // its fragment sizes.
    return this->grow_buffer(this->reasm_buf_, needed, MAX_REASSEMBLED_MESSAGE_BYTES + 1,
                             "reassembly");
}

bool NoiseTransport::ensure_send_buf(size_t needed) {
    // Capped at MAX_TRANSPORT_PLAINTEXT + 16 (the largest plaintext + AEAD tag room the
    // non-fragmented path ever handles); callers never request more (the non-fragmented path's
    // own size check enforces this), so the cap never actually clamps.
    return this->grow_buffer(this->send_buf_, needed, MAX_TRANSPORT_PLAINTEXT + 16, "send");
}

}  // namespace sendspin
