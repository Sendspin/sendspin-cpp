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

/// @file pairing_offers.h
/// @brief Which pairing methods and emission formats the client currently offers.
///
/// One answer serves two callers that must never disagree: `build_hello_message()` fills
/// `supported_pair_methods` from these predicates (pairing.md "client/hello pair-method
/// descriptor"), and the `server/activate` admissibility check answers
/// `pair/abort(method_not_supported)` for anything they leave out (messaging.md
/// "server/activate"). A method the hello advertises but the activation path rejects would
/// strand a server with nothing left to try.

#pragma once

#include "record_store.h"
#include "sendspin/config.h"
#include "sendspin/types.h"

#include <algorithm>
#include <optional>

namespace sendspin {

// Each predicate below reads the client config and the record store's pairing-config flags, and
// returns true when the method may be advertised and accepted.

/// @brief Whether the client offers the Pairing PSK method.
/// `config` is unused; it is taken for call-site symmetry, since the store alone configures this
/// method.
/// The method needs an actual Pairing PSK behind it (normally auto-provisioned on first boot):
/// advertising it without one offers a server a flow whose handshake could only miss.
inline bool offers_pairing_psk(const SendspinClientConfig& /*config*/, const RecordStore& store) {
    return store.pairing_psk_enabled() && store.pairing_psk().has_value();
}

/// @brief Whether the client offers the dynamic pairing code.
/// pairing.md "client/hello pair-method descriptor" makes `out_channels` and `formats` required,
/// and a descriptor with no recognized channel or format is ignored outright, so a device that
/// lists neither cannot offer the method.
inline bool offers_dynamic_pairing_code(const SendspinClientConfig& config,
                                        const RecordStore& store) {
    return store.dynamic_pairing_code_enabled() && !config.pairing_code_out_channels.empty() &&
           !config.pairing_code_formats.empty();
}

/// @brief Whether the client offers the static pairing code.
/// Needs the configured code and the operator gesture the flow is gated on (pairing.md "Pairing
/// Window"). A client that offers the dynamic pairing code offers that one instead:
/// messaging.md "client/hello" permits at most one pairing-code method in
/// `supported_pair_methods`, and pairing.md "Methods" prefers the dynamic code wherever an
/// out-channel exists.
inline bool offers_static_pairing_code(const SendspinClientConfig& config,
                                       const RecordStore& store) {
    return config.pairing_window_supported && store.static_pairing_code_enabled() &&
           store.static_pairing_code().has_value() && !offers_dynamic_pairing_code(config, store);
}

/// @brief Whether `format` is one the client advertises in its `formats` list.
/// A nullopt format is one the activation omitted or named unrecognizably, which is equally not
/// offered (messaging.md "server/activate" requires the field on a dynamic_pairing_code
/// activation).
inline bool offers_pairing_code_format(const SendspinClientConfig& config,
                                       const std::optional<SendspinPairingCodeFormat>& format) {
    return format.has_value() &&
           std::find(config.pairing_code_formats.begin(), config.pairing_code_formats.end(),
                     format.value()) != config.pairing_code_formats.end();
}

}  // namespace sendspin
