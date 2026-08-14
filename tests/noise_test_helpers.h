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

// noise-c is a C library; wrap the includes in extern "C" to avoid C++
// name-mangling issues when compiling under -Wpedantic.
extern "C" {
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/constants.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/handshakestate.h>
}

#include <cstddef>
#include <cstdint>
#include <string>

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
/// @param psk          PSK (32 bytes) - provided to satisfy noise-c before start.
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
