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

/// @brief Client playback state reported to the server
enum class SendspinClientState : uint8_t {
    SYNCHRONIZED,     // Client is synchronized and playing from the server
    ERROR,            // Client encountered a playback error
    EXTERNAL_SOURCE,  // Client is playing from a non-Sendspin source
};

/// @brief Reason sent in a client/goodbye message when disconnecting
enum class SendspinGoodbyeReason : uint8_t {
    ANOTHER_SERVER,      // Client is switching to another server
    SHUTDOWN,            // Client is shutting down
    RESTART,             // Client is restarting
    USER_REQUEST,        // User explicitly requested disconnect
    UNAUTHORIZED,        // Server requested an activity the client's trust level does not permit
    PAIRING_REQUIRED,    // Server requested playback but client requires pairing first
    CONCURRENT_ATTEMPT,  // Incoming connection rejected because another is already admitted
    UNPAIRED,            // Server unpaired this device via management/server-unpair
};

/// @brief Server identity fields received in server/hello messages
struct ServerInformationObject {
    std::string server_id{};
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
// Encryption / trust types (public API surface)
// ============================================================================

/// @brief Trust level of an active connection.
///
/// Derived from which PSK category was matched during the Noise handshake:
///   LONG_TERM PSK -> USER (the server has a stored pairing record)
///   PAIRING or SENTINEL PSK -> NONE (no prior pairing or unpaired access)
enum class ConnectionTrust : uint8_t {
    NONE,  // No long-term pairing record; Sentinel or Pairing PSK was used.
    USER,  // Long-term pairing record matched; connection is from a paired server.
};

/// @brief Reason a pairing exchange was aborted.
///
/// Mirrors the wire values in the Sendspin pairing protocol.
/// Carried by SendspinClientListener::on_pairing_failed().
enum class SendspinPairAbortReason : uint8_t {
    ATTEMPT_TIMEOUT,          // Server did not complete the exchange in time.
    CONCURRENT_ATTEMPT,       // Another pairing attempt is already in progress.
    METHOD_NOT_SUPPORTED,     // The selected pairing method is not available.
    PIN_LENGTH_UNACCEPTABLE,  // Proposed PIN length is outside the accepted range.
    PIN_MISMATCH,             // PIN verification failed.
    USER_CANCELLED,           // User or application cancelled the pairing.
    UNKNOWN,                  // Unrecognized reason from the wire, or a client-local abort
                              // with no wire equivalent (e.g. a protocol error).
};

}  // namespace sendspin
