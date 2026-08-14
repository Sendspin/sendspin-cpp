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

/// @file noise_session.h
/// @brief Noise KKpsk2 session wrapper (handshake + transport cipher states).
///
/// Mirrors `aiosendspin/noise/session.py` (`NoiseSession`).
///
/// Key design choice: the two-handshake trick for PSK-after-start.
/// In KKpsk2 the PSK is mixed only during msg2, so msg1 (which carries
/// the encrypted psk_id) is decryptable with static keys alone.  However,
/// noise-c requires the PSK to be supplied before `noise_handshakestate_start`.
/// We handle this with a throwaway handshake:
///   1. Build a "probe" handshakestate with a zero placeholder PSK.
///   2. Read msg1 through the probe to extract the psk_id.
///   3. Discard the probe.
///   4. Build the real handshakestate with the resolved PSK.
///   5. Read the SAME msg1 bytes through the real handshakestate.
///   6. Write msg2 and call split().
///
/// See `NoiseSession::read_msg1` and `NoiseSession::write_msg2_and_split`.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// noise-c forward declarations: the implementation includes the actual headers.
struct NoiseHandshakeState_s;
typedef struct NoiseHandshakeState_s NoiseHandshakeState;
struct NoiseCipherState_s;
typedef struct NoiseCipherState_s NoiseCipherState;

namespace sendspin {

/// @brief Noise KKpsk2 session: handshake and transport state.
///
/// Construct via the factory `NoiseSession::as_responder()`.
/// Call `read_msg1()` then `write_msg2_and_split()` to complete the handshake.
/// After split(), use `encrypt()` / `decrypt()` for transport traffic.
class NoiseSession {
public:
    ~NoiseSession();

    // Non-copyable; movable.
    NoiseSession(const NoiseSession&) = delete;
    NoiseSession& operator=(const NoiseSession&) = delete;
    NoiseSession(NoiseSession&&) noexcept;
    NoiseSession& operator=(NoiseSession&&) noexcept;

    // ========================================
    // Factory
    // ========================================

    /// @brief Build a KKpsk2 responder session (the Sendspin client role).
    ///
    /// noise-c requires the PSK before `noise_handshakestate_start`, but the real PSK is
    /// only known after `read_msg1` reveals the psk_id. The handshake driver
    /// (noise_handshake.cpp run_msg1_core) therefore uses the two-session trick: a probe
    /// session built with a zero placeholder PSK decrypts msg1 (psk2 mixes the PSK only
    /// into msg2, so msg1 authenticates under static keys alone), then a second session
    /// built with the resolved real PSK re-processes the same msg1 bytes and continues to
    /// `write_msg2_and_split`.
    ///
    /// @param suite_name  Full Noise suite name (e.g. NOISE_SUITE_CHACHAPOLY).
    /// @param local_priv  32-byte X25519 private key.
    /// @param remote_pub  32-byte X25519 public key of the remote (server).
    /// @param prologue    Exact prologue bytes (init messages, or prior hash on re-handshake).
    /// @param psk         32-byte PSK (zero placeholder for a probe session, or the real PSK).
    /// @return Session ready for `read_msg1`, or nullopt on error.
    static std::optional<NoiseSession> as_responder(const std::string& suite_name,
                                                    const uint8_t* local_priv,
                                                    const uint8_t* remote_pub,
                                                    const uint8_t* prologue, size_t prologue_len,
                                                    const uint8_t* psk);

    // ========================================
    // Handshake
    // ========================================

    /// @brief Decrypt Noise message 1 and return its plaintext payload.
    /// @param msg1_bytes   Raw bytes received in the noise/handshake frame.
    /// @param msg1_len     Length of msg1_bytes.
    /// @return Decrypted payload, or empty vector on auth failure.
    std::vector<uint8_t> read_msg1(const uint8_t* msg1_bytes, size_t msg1_len);

    /// @brief Encrypt Noise message 2 (payload = `{}` UTF-8) and split into
    /// transport cipher states.
    /// @param[out] msg2_out  Buffer to receive the Noise ciphertext bytes.
    /// @return true on success; transport mode is now active.
    bool write_msg2_and_split(std::vector<uint8_t>& msg2_out);

    /// @brief Return true once split() has been called successfully.
    bool handshake_complete() const {
        return this->send_cipher_ != nullptr && this->recv_cipher_ != nullptr;
    }

    /// @brief The 32-byte Noise handshake hash `h` (available after split).
    const std::array<uint8_t, 32>& handshake_hash() const {
        return this->handshake_hash_;
    }

    // ========================================
    // Transport
    // ========================================

    /// @brief Encrypt plaintext for transport.
    /// @param plaintext  Input bytes (modified in-place; caller must supply
    ///                   `len + 16` bytes of capacity).
    /// @param len        Number of plaintext bytes.
    /// @param capacity   Total capacity of `plaintext` buffer.
    /// @return Number of ciphertext bytes (len + 16 tag), or 0 on error.
    size_t encrypt(uint8_t* plaintext, size_t len, size_t capacity);

    /// @brief Decrypt ciphertext in-place.
    /// @param ciphertext  Input bytes (modified in-place).
    /// @param len         Number of ciphertext bytes (plaintext + 16-byte tag).
    /// @return Number of plaintext bytes, or 0 on auth failure.
    size_t decrypt(uint8_t* ciphertext, size_t len);

private:
    NoiseSession() = default;

    /// @brief The active handshakestate (null after split).
    NoiseHandshakeState* hs_{nullptr};

    /// @brief Transport cipher: send direction (null until split).
    NoiseCipherState* send_cipher_{nullptr};

    /// @brief Transport cipher: receive direction (null until split).
    NoiseCipherState* recv_cipher_{nullptr};

    /// @brief Noise handshake hash `h` (populated by write_msg2_and_split).
    std::array<uint8_t, 32> handshake_hash_{};
};

}  // namespace sendspin
