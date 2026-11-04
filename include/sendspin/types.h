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

/// @file types.h
/// @brief Shared types used across the Sendspin client and role APIs

#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace sendspin {

// ============================================================================
// Common types
// ============================================================================

/// @brief Reason sent in a client/goodbye message when disconnecting
enum class SendspinGoodbyeReason : uint8_t {
    ANOTHER_SERVER,      // Client is switching to another server
    SHUTDOWN,            // Client is shutting down
    RESTART,             // Client is restarting
    USER_REQUEST,        // User explicitly requested disconnect
    UNAUTHORIZED,        // Session not permitted its activities or roles, or its record revoked
    PAIRING_REQUIRED,    // Server requested playback but client requires pairing first
    CONCURRENT_ATTEMPT,  // Incoming connection rejected because another is already admitted
    UNPAIRED,            // Server unpaired this device via server/unpair
};

/// @brief Server identity fields received in server/hello messages
struct ServerInformationObject {
    std::string server_id{};
    /// At most 64 bytes in UTF-8, cut at a character boundary
    std::string name{};
};

/// @brief Overall group playback state
enum class SendspinPlaybackState : uint8_t {
    PLAYING,  // Group is actively playing
    STOPPED,  // Group playback is stopped
};

/// @brief Group membership and playback state delta received in group/update messages
struct GroupUpdateObject {
    std::optional<SendspinPlaybackState> playback_state{};
    std::optional<std::string> group_id{};
    /// At most 64 bytes in UTF-8, cut at a character boundary
    std::optional<std::string> group_name{};
};

/// @brief Memory placement preference for platform allocations
/// On ESP-IDF, controls whether SPIRAM or internal RAM is tried first; the other is the
/// fallback. Ignored on host platforms (no internal/external distinction).
enum class MemoryLocation : uint8_t {
    PREFER_EXTERNAL,  // Prefer SPIRAM, fall back to internal RAM
    PREFER_INTERNAL,  // Prefer internal RAM, fall back to SPIRAM
};

// ============================================================================
// Pairing types (public API surface)
// ============================================================================

/// @brief Reason a pairing exchange was aborted.
///
/// Mirrors the wire values in the Sendspin pairing protocol.
/// Carried by SendspinClientListener::on_pairing_failed().
enum class SendspinPairAbortReason : uint8_t {
    ATTEMPT_TIMEOUT,        // Server did not complete the exchange in time.
    CONCURRENT_ATTEMPT,     // Another pairing attempt is already in progress.
    METHOD_NOT_SUPPORTED,   // The selected pairing method or emission format is not available.
    PAIRING_CODE_MISMATCH,  // PAKE key confirmation failed.
    USER_CANCELLED,         // User or application cancelled the pairing.
    UNKNOWN,                // Unrecognized reason from the wire, or a client-local abort
                            // with no wire equivalent (e.g. a protocol error).
};

/// @brief Out-channel through which a client conveys a dynamic pairing code to the operator.
///
/// Advertised as `out_channels` on the `dynamic_pairing_code` descriptor in client/hello
/// (pairing.md "client/hello pair-method descriptor").
enum class SendspinPairingCodeChannel : uint8_t {
    DISPLAY,
    SPEAKER,  // The code is spoken, not tone-encoded.
};

/// @brief Emission format of a dynamic pairing code (pairing.md "Dynamic Pairing Code Flow").
///
/// Advertised as `formats` on the `dynamic_pairing_code` descriptor in client/hello; the server
/// picks one of them in the pairing activation's `format` field.
enum class SendspinPairingCodeFormat : uint8_t {
    DIGITS,   // Six decimal digits the operator types into the server.
    QR_CODE,  // A pairing token the operator scans from a rendered QR code.
};

}  // namespace sendspin
