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

/// @file noise_test_helpers.h
/// @brief Shared raw noise-c initiator-side scaffolding for tests that play the "server" (Noise
/// INITIATOR) role against the project's own NoiseSession/NoiseHandshake responder code. The
/// project's NoiseSession class only implements the responder side (the client is always the
/// Noise responder), so any test that needs to drive the other side of a handshake has to talk
/// to noise-c directly.

#pragma once

#include "crypto/constants.h"
#include "crypto/keys.h"
#include "platform/base64.h"

// noise-c is a C library; wrap the includes in extern "C" to avoid C++
// name-mangling issues when compiling under -Wpedantic.
extern "C" {
#include <noise/protocol/buffer.h>
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/constants.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/handshakestate.h>
}

#include <ArduinoJson.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/// RAII wrapper for a noise-c handshakestate.
struct HsGuard {
    NoiseHandshakeState* hs{nullptr};
    explicit HsGuard(NoiseHandshakeState* h) : hs(h) {}
    ~HsGuard() {
        if (this->hs) {
            noise_handshakestate_free(this->hs);
        }
    }
    HsGuard(const HsGuard&) = delete;
    HsGuard& operator=(const HsGuard&) = delete;
};

/// RAII wrapper for a pair of noise-c cipher states.
struct CipherPair {
    NoiseCipherState* send_cs{nullptr};
    NoiseCipherState* recv_cs{nullptr};

    CipherPair() = default;
    ~CipherPair() {
        this->reset();
    }
    CipherPair(const CipherPair&) = delete;
    CipherPair& operator=(const CipherPair&) = delete;
    CipherPair(CipherPair&& o) noexcept : send_cs(o.send_cs), recv_cs(o.recv_cs) {
        o.send_cs = nullptr;
        o.recv_cs = nullptr;
    }
    CipherPair& operator=(CipherPair&& o) noexcept {
        if (this != &o) {
            this->reset();
            this->send_cs = o.send_cs;
            this->recv_cs = o.recv_cs;
            o.send_cs = nullptr;
            o.recv_cs = nullptr;
        }
        return *this;
    }
    void reset() {
        if (this->send_cs) {
            noise_cipherstate_free(this->send_cs);
            this->send_cs = nullptr;
        }
        if (this->recv_cs) {
            noise_cipherstate_free(this->recv_cs);
            this->recv_cs = nullptr;
        }
    }
};

/// @brief Build a KKpsk2 initiator handshakestate (the "server" role in Sendspin).
///
/// @param suite_name   Full Noise suite name.
/// @param local_priv   Server static private key (32 bytes).
/// @param local_pub    Server static public key (32 bytes).
/// @param remote_pub   Client static public key (32 bytes).
/// @param psk          PSK (32 bytes), provided to satisfy noise-c before start.
/// @param prologue     Prologue bytes.
/// @param prologue_len Prologue length.
/// @return Raw pointer on success (caller takes ownership via HsGuard), or nullptr.
inline NoiseHandshakeState* build_initiator(const std::string& suite_name,
                                            const uint8_t* local_priv, const uint8_t* local_pub,
                                            const uint8_t* remote_pub, const uint8_t* psk,
                                            const uint8_t* prologue, size_t prologue_len) {
    NoiseHandshakeState* hs = nullptr;
    if (noise_handshakestate_new_by_name(&hs, suite_name.c_str(), NOISE_ROLE_INITIATOR) !=
        NOISE_ERROR_NONE) {
        return nullptr;
    }

    NoiseDHState* local_dh = noise_handshakestate_get_local_keypair_dh(hs);
    if (noise_dhstate_set_keypair(local_dh, local_priv, sendspin::X25519_KEY_SIZE, local_pub,
                                  sendspin::X25519_KEY_SIZE) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(hs);
        return nullptr;
    }

    NoiseDHState* remote_dh = noise_handshakestate_get_remote_public_key_dh(hs);
    if (noise_dhstate_set_public_key(remote_dh, remote_pub, sendspin::X25519_KEY_SIZE) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(hs);
        return nullptr;
    }

    if (noise_handshakestate_set_pre_shared_key(hs, psk, sendspin::NOISE_PSK_SIZE) !=
        NOISE_ERROR_NONE) {
        noise_handshakestate_free(hs);
        return nullptr;
    }

    if (prologue_len > 0) {
        if (noise_handshakestate_set_prologue(hs, prologue, prologue_len) != NOISE_ERROR_NONE) {
            noise_handshakestate_free(hs);
            return nullptr;
        }
    }

    if (noise_handshakestate_start(hs) != NOISE_ERROR_NONE) {
        noise_handshakestate_free(hs);
        return nullptr;
    }
    return hs;
}

/// @brief Write msg1 ({"psk_id":"..."} payload) on an initiator handshakestate and wrap the
/// result in a `noise/handshake` JSON envelope, ready to feed to the responder driver.
///
/// @param hs      Initiator handshakestate positioned to write msg1 (from build_initiator()).
/// @param psk_id  psk_id to advertise in the msg1 payload.
/// @return The envelope JSON text, or an empty string if the Noise write failed.
inline std::string build_msg1_envelope(NoiseHandshakeState* hs, const std::string& psk_id) {
    std::string psk_id_json = "{\"psk_id\":\"" + psk_id + "\"}";
    std::vector<uint8_t> msg1_raw(4096);
    NoiseBuffer msg1_out;
    noise_buffer_set_output(msg1_out, msg1_raw.data(), msg1_raw.size());
    NoiseBuffer payload_in;
    noise_buffer_set_input(
        payload_in, const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(psk_id_json.data())),
        psk_id_json.size());
    if (noise_handshakestate_write_message(hs, &msg1_out, &payload_in) != NOISE_ERROR_NONE) {
        return {};
    }
    msg1_raw.resize(msg1_out.size);

    std::string encoded = sendspin::b64url_encode(msg1_raw.data(), msg1_raw.size());
    JsonDocument doc;
    doc["type"] = "noise/handshake";
    doc["payload"]["data"] = encoded;
    std::string out;
    serializeJson(doc, out);
    return out;
}

/// @brief Encrypt one Noise transport frame with a raw noise-c cipher state (appends the 16-byte
/// AEAD tag). Returns {} on failure; callers check emptiness rather than a Noise error code.
inline std::vector<uint8_t> raw_encrypt(NoiseCipherState* cs, const std::vector<uint8_t>& pt) {
    std::vector<uint8_t> ct(pt.size() + 16);
    std::copy(pt.begin(), pt.end(), ct.begin());
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, ct.data(), pt.size(), ct.size());
    if (noise_cipherstate_encrypt(cs, &buf) != NOISE_ERROR_NONE) {
        return {};
    }
    ct.resize(buf.size);
    return ct;
}

/// @brief Decrypt one Noise transport frame with a raw noise-c cipher state. Returns {} on
/// failure (AEAD tag mismatch, wrong key), for the same reason as raw_encrypt() above.
inline std::vector<uint8_t> raw_decrypt(NoiseCipherState* cs, std::vector<uint8_t> ct) {
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, ct.data(), ct.size(), ct.size());
    if (noise_cipherstate_decrypt(cs, &buf) != NOISE_ERROR_NONE) {
        return {};
    }
    ct.resize(buf.size);
    return ct;
}
