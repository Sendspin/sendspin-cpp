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

/// @file noise_handshake.h
/// @brief Noise KKpsk2 cleartext init exchange + handshake state machine.
///
/// Mirrors `aiosendspin/noise/driver.py` `run_handshake_client` /
/// `_exchange_as_responder` for the Sendspin client (always the Noise responder).
///
/// Protocol sequence (all pre-transport frames are WS TEXT):
///   1. Send  `client/init` (TEXT)
///   2. Recv  `server/init` (TEXT): prologue = bytes(client/init) || bytes(server/init)
///   3. Recv  `noise/handshake` msg1 (TEXT): build a KKpsk2 responder with no PSK bound yet,
///      read msg1 through it, extract psk_id from the decrypted payload
///   4. Resolve psk_id via RecordStore; bind the resolved PSK onto the SAME responder
///      (NoiseSession::set_psk) -- valid because KKpsk2 processes the "psk" token in msg2,
///      not msg1
///   5. Send  `noise/handshake` msg2 (TEXT): write msg2, split -> transport
///
/// After step 5 the connection is in encrypted transport mode.
/// Any failure aborts silently (caller closes the WebSocket).
///
/// Re-handshake (in-band key rotation):
///   The server may initiate a new KKpsk2 handshake after transport is active.
///   The re-handshake msg1 arrives as a decrypted noise/handshake JSON envelope.
///   The prologue is the prior handshake hash `h` rather than init-text concatenation.
///   Use run_rehandshake_msg1() which applies the same deferred-PSK-binding sequence.

#pragma once

#include "crypto/keys.h"
#include "noise_session.h"
#include "record_store.h"

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace sendspin {

/// @brief Outcome of a successful Noise handshake (initial or re-handshake).
struct NoiseHandshakeResult {
    /// The cipher session ready for transport-mode encrypt/decrypt.
    std::unique_ptr<NoiseSession> session;
    /// Server's public key peer_id (43-char base64url).
    std::string server_id;
    /// The PSK record that admitted the connection.
    ResolvedPsk resolved_psk;
    /// Serialized noise/handshake msg2 JSON to send to the peer.
    /// Non-empty only for re-handshake results (initial handshake sends msg2 inline).
    std::string msg2_text;
};

/// @brief Result of processing one incoming WS frame during the handshake.
enum class HandshakeFrameResult {
    NEED_MORE,  ///< Frame processed; waiting for the next frame.
    COMPLETE,   ///< Handshake complete; switch to transport mode.
    ABORT,      ///< Fatal error; caller must close the WebSocket silently.
};

// ============================================================================
// Re-handshake helper
// ============================================================================

/// @brief Run the responder side of an in-band Noise KKpsk2 re-handshake.
///
/// Called on the network thread when a decrypted noise/handshake JSON arrives
/// after transport mode is already active.  The prologue for the re-handshake
/// is the 32-byte handshake hash `h` from the PRIOR handshake.
///
/// The same deferred-PSK-binding sequence used by the initial handshake applies here:
///   1. Build a session with no PSK bound.
///   2. Read msg1 through it to extract psk_id.
///   3. Resolve psk_id via record_store.
///   4. Bind the resolved PSK onto the SAME session (NoiseSession::set_psk).
///   5. Write msg2 and split -> new session.
///
/// @param msg1_json      Decrypted noise/handshake JSON string (the re-handshake msg1 envelope).
/// @param server_id      Known server peer_id (43-char base64url) from the prior handshake.
/// @param identity       Our static X25519 identity.
/// @param record_store   Record store for psk_id resolution (read-only on network thread).
/// @param suite_name     Noise suite name (NOISE_SUITE_CHACHAPOLY or NOISE_SUITE_AESGCM).
/// @param prior_h        32-byte handshake hash from the prior session (used as prologue).
/// @return Populated NoiseHandshakeResult (session + msg2_text to send) on success,
///         or nullopt on any failure (caller should close the WebSocket).
std::optional<NoiseHandshakeResult> run_rehandshake_msg1(const std::string& msg1_json,
                                                         const std::string& server_id,
                                                         const Identity& identity,
                                                         const RecordStore& record_store,
                                                         const std::string& suite_name,
                                                         const std::array<uint8_t, 32>& prior_h);

// ============================================================================
// NoiseHandshake class (initial handshake state machine)
// ============================================================================

/// @brief Noise handshake state machine for the Sendspin client (Noise responder).
///
/// Usage:
///   1. Construct with Identity and RecordStore.
///   2. Call send_client_init() to send the first cleartext frame.
///   3. For each incoming WS text frame call on_text_frame().
///   4. When on_text_frame() returns COMPLETE, take the result via take_result().
///
/// Threading: runs entirely on the network thread.  PSK resolution via RecordStore
/// is a read-only in-memory lookup; no mutex needed (see record_store.h comment).
class NoiseHandshake {
public:
    /// @brief Construct the handshake driver.
    /// @param identity     Our static X25519 identity.
    /// @param record_store Record store for psk_id resolution (read-only on network thread).
    /// @param suite_name   Noise suite name (NOISE_SUITE_CHACHAPOLY or NOISE_SUITE_AESGCM).
    NoiseHandshake(const Identity& identity, const RecordStore& record_store,
                   const std::string& suite_name);

    ~NoiseHandshake() = default;

    // Non-copyable, non-movable (contains a reference member).
    NoiseHandshake(const NoiseHandshake&) = delete;
    NoiseHandshake& operator=(const NoiseHandshake&) = delete;
    NoiseHandshake(NoiseHandshake&&) = delete;
    NoiseHandshake& operator=(NoiseHandshake&&) = delete;

    // ========================================
    // Drive the state machine
    // ========================================

    /// @brief Serialize and return the client/init TEXT frame.
    /// Call this immediately after the WS connection is open, before reading frames.
    /// @return Serialized JSON string ready to send, or empty on error.
    std::string build_client_init();

    /// @brief Process one incoming WS text frame.
    /// Must be called in sequence: server/init, then noise/handshake msg1.
    /// @param text     The raw text content of the received WS frame.
    /// @param send_fn  Callable that sends a TEXT frame to the peer.
    ///                 Signature: `bool send_fn(const std::string& text)`.
    /// @return NEED_MORE, COMPLETE, or ABORT.
    HandshakeFrameResult on_text_frame(const std::string& text,
                                       const std::function<bool(const std::string&)>& send_fn);

    /// @brief Take ownership of the handshake result (only valid after COMPLETE).
    std::optional<NoiseHandshakeResult> take_result() {
        return std::move(this->result_);
    }

private:
    enum class State {
        INIT,              ///< client/init not yet sent
        WAIT_SERVER_INIT,  ///< waiting for server/init
        WAIT_MSG1,         ///< waiting for noise/handshake msg1
        COMPLETE,          ///< handshake done
        ABORTED,           ///< terminal error
    };

    /// @brief Parse and validate the server/init text frame.
    bool handle_server_init(const std::string& text);

    /// @brief Parse, authenticate, and respond to the noise/handshake msg1 frame.
    bool handle_msg1(const std::string& text,
                     const std::function<bool(const std::string&)>& send_fn);

    const Identity& identity_;
    const RecordStore& record_store_;
    std::string suite_name_;

    State state_{State::INIT};

    /// Exact bytes of the client/init frame we sent (retained for prologue).
    std::string client_init_text_;

    /// Exact bytes of the server/init frame we received (retained for prologue).
    std::string server_init_text_;

    /// server_id decoded from server/init (43-char base64url).
    std::string server_id_;

    /// Result available after COMPLETE.
    std::optional<NoiseHandshakeResult> result_;
};

}  // namespace sendspin
