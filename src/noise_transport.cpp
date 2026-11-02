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
#include "outbound_ring.h"
#include "platform/crypto.h"
#include "platform/logging.h"

#include <cstring>
#include <utility>

namespace sendspin {

static const char* const TAG = "sendspin.noise_transport";

// ============================================================================
// Session lifecycle
// ============================================================================

void NoiseTransport::activate(std::unique_ptr<NoiseSession> session) {
    this->session_ = std::move(session);
    this->active_ = true;
}

std::optional<std::array<uint8_t, 32>> NoiseTransport::handshake_hash() const {
    if (!this->session_) {
        return std::nullopt;
    }
    return this->session_->handshake_hash();
}

// ============================================================================
// Outbound (encrypt + send)
// ============================================================================

size_t NoiseTransport::encrypt_in_place(uint8_t* buf, size_t buf_capacity, size_t plaintext_len) {
    if (buf_capacity < plaintext_len + AEAD_TAG_SIZE) {
        SS_LOGE(TAG, "encrypt_in_place: buffer lacks AEAD tag room");
        return 0;
    }
#ifdef SENDSPIN_ENABLE_MESSAGE_TRACE
    if (this->message_tracer_ != nullptr) {
        this->message_tracer_->trace_outbound(buf, plaintext_len);
    }
#endif

    // noise-c advances the send nonce past a failed encrypt too.
    const size_t ct_len = this->session_->encrypt(buf, plaintext_len, buf_capacity);
    if (ct_len == 0) {
        SS_LOGE(TAG, "Noise encrypt failed");
        this->send_desynced_ = true;
    }
    return ct_len;
}

SsErr NoiseTransport::encrypt_and_send_frame(uint8_t* buf, size_t buf_capacity,
                                             size_t plaintext_len,
                                             const FrameWriteHook& before_write) {
    if (!this->session_ || !this->frame_sink_ || this->send_desynced_) {
        return SsErr::INVALID_STATE;
    }

    const size_t ct_len = this->encrypt_in_place(buf, buf_capacity, plaintext_len);
    if (ct_len == 0) {
        return SsErr::FAIL;
    }

    const SsErr err = this->frame_sink_(buf, ct_len, before_write);
    if (err != SsErr::OK) {
        this->send_desynced_ = true;
    }
    return err;
}

char* NoiseTransport::stage_json(size_t max_len) {
    // Plaintext = [MSG_TYPE_JSON_BODY] + utf8(json). The terminator a caller's writer may add
    // lands in the AEAD tag room.
    if (1 + max_len > MAX_TRANSPORT_PLAINTEXT) {
        SS_LOGE(TAG, "stage_json: a %zu-byte JSON message does not fit one frame", max_len);
        return nullptr;
    }
    if (!this->ensure_send_buf(1 + max_len + AEAD_TAG_SIZE)) {
        return nullptr;
    }
    this->send_buf_.data()[0] = MSG_TYPE_JSON_BODY;
    return reinterpret_cast<char*>(this->send_buf_.data() + 1);
}

SsErr NoiseTransport::send_staged_json(size_t len, const FrameWriteHook& before_write) {
    const SsErr err = this->is_active() ? this->encrypt_and_send_frame(this->send_buf_.data(),
                                                                       this->send_buf_.size(),
                                                                       1 + len, before_write)
                                        : SsErr::INVALID_STATE;
    if (err != SsErr::OK) {
        // A refusal before the encrypt, or a failed encrypt, leaves the plaintext staged; after a
        // failed write the wipe only clears ciphertext.
        secure_zero(this->send_buf_.data(), 1 + len);
    }
    return err;
}

SsErr NoiseTransport::send_binary_lent(OutboundRing& ring, void* item, size_t message_capacity,
                                       size_t plaintext_len) {
    uint8_t* message = outbound_item_message(item);
    SsErr refusal = SsErr::OK;
    if (!this->is_active() || !this->lent_frame_sink_ || this->send_desynced_) {
        refusal = SsErr::INVALID_STATE;
    } else if (plaintext_len == 0 || plaintext_len > MAX_TRANSPORT_PLAINTEXT) {
        SS_LOGE(TAG, "send_binary_lent: a %zu-byte message does not fit one frame", plaintext_len);
        refusal = SsErr::FAIL;
    } else if (plaintext_len + AEAD_TAG_SIZE > message_capacity) {
        SS_LOGE(TAG, "send_binary_lent: item lacks AEAD tag room");
        refusal = SsErr::FAIL;
    } else if (message[0] == MSG_TYPE_FRAGMENT) {
        // messaging.md "Fragmentation": a sender MUST NOT use 1 as orig_type.
        SS_LOGE(TAG, "send_binary_lent: message type 1 belongs to the fragmentation layer");
        refusal = SsErr::FAIL;
    }
    if (refusal != SsErr::OK) {
        ring.return_item(item);
        return refusal;
    }

    const size_t ct_len = this->encrypt_in_place(message, message_capacity, plaintext_len);
    if (ct_len == 0) {
        ring.return_item(item);
        return SsErr::FAIL;
    }

    const SsErr err = this->lent_frame_sink_(ring, item, ct_len);
    if (err != SsErr::OK) {
        this->send_desynced_ = true;
    }
    return err;
}

SsErr NoiseTransport::send_msg2_and_swap(size_t len, std::unique_ptr<NoiseSession> next_session) {
    // msg2 goes out under the OLD session, then the session swaps. Every send runs on the
    // protocol task, as this does, so no encrypt can fall between the two.
    SsErr err = this->send_staged_json(len);
    if (err != SsErr::OK) {
        SS_LOGE(TAG, "send_msg2_and_swap: failed to send encrypted msg2 (err=%d)",
                static_cast<int>(err));
        return err;
    }

    // Swap to the new session. After this line every decrypt and every encrypt, all on the
    // protocol task, uses the new session.
    this->session_ = std::move(next_session);
    return SsErr::OK;
}

// ============================================================================
// Inbound (decrypt + reassemble)
// ============================================================================

size_t NoiseTransport::decrypt_in_place(uint8_t* ciphertext, size_t len) {
    // Protocol task only, like every use of the session (see the file comment).
    if (!this->session_) {
        return 0;
    }
    return this->session_->decrypt(ciphertext, len);
}

NoiseTransport::CompleteMessage NoiseTransport::accept_plaintext(uint8_t* plaintext, size_t len,
                                                                 bool admitted) {
    // Protocol task only.
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
    if (len < FRAGMENT_CONT_HEADER_SIZE) {
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
        if (len < FRAGMENT_FIRST_HEADER_SIZE) {
            SS_LOGW(TAG, "first fragment missing its orig_type; malformed sequence");
            this->reasm_reset();
            return {nullptr, 0, true};
        }
        const uint8_t orig_type = plaintext[FRAGMENT_CONT_HEADER_SIZE];
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
            if (this->reasm_reserve(1, admitted)) {
                this->reasm_buf_.data()[0] = orig_type;
                this->reasm_len_ = 1;
            } else {
                this->reasm_discarding_ = true;
            }
        }
        data = plaintext + FRAGMENT_FIRST_HEADER_SIZE;
        data_len = len - FRAGMENT_FIRST_HEADER_SIZE;
    } else {
        // messaging.md "Malformed sequences": a non-first fragment received with none in flight.
        if (!this->reasm_in_progress_) {
            SS_LOGW(TAG, "continuation fragment with no fragmented message in flight; "
                         "malformed sequence");
            this->reasm_reset();
            return {nullptr, 0, true};
        }
        data = plaintext + FRAGMENT_CONT_HEADER_SIZE;
        data_len = len - FRAGMENT_CONT_HEADER_SIZE;
    }

    if (!this->reasm_discarding_) {
        // Before admission every peer on the network can reach this path with nothing but the
        // Sentinel PSK, and nothing that legitimately arrives then approaches the tighter cap
        // (see MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES), so that cap applies until the
        // connection wins an admitted slot.
        const size_t cap = reasm_cap(admitted);
        if (this->reasm_len_ - 1 + data_len > cap) {
            SS_LOGW(TAG, "fragmented message exceeds %zu bytes; discarding the rest of it", cap);
            this->reasm_discarding_ = true;
        } else if (!this->reasm_reserve(this->reasm_len_ + data_len, admitted)) {
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

size_t NoiseTransport::reasm_cap(bool admitted) {
    return admitted ? MAX_REASSEMBLED_MESSAGE_BYTES : MAX_PRE_ADMISSION_REASSEMBLED_MESSAGE_BYTES;
}

bool NoiseTransport::reasm_reserve(size_t needed, bool admitted) {
    // Capped at the cap in force + 1: the caller's own size check (accept_plaintext) admits a
    // `needed` of exactly that much, one byte of orig_type plus the largest message that cap will
    // reassemble. Both read the cap from reasm_cap() so the clamp cannot be wider than the check.
    // Without the clamp the doubling step above the admitted size would reserve ~2 MiB per
    // connection, retained for the connection's life, which a peer picks by choosing its fragment
    // sizes.
    return this->grow_buffer(this->reasm_buf_, needed, reasm_cap(admitted) + 1, "reassembly");
}

bool NoiseTransport::ensure_send_buf(size_t needed) {
    // Capped at one frame's largest plaintext plus its AEAD tag; stage_json()'s own size check
    // keeps every request within it, so the cap never actually clamps.
    return this->grow_buffer(this->send_buf_, needed, MAX_TRANSPORT_PLAINTEXT + AEAD_TAG_SIZE,
                             "send");
}

}  // namespace sendspin
