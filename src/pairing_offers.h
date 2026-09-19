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
/// strand a server with nothing left to try, so the two read the same source.

#pragma once

#include "record_store.h"
#include "sendspin/config.h"
#include "sendspin/types.h"

#include <algorithm>
#include <optional>

namespace sendspin {

/// @brief Whether the client offers the Pairing PSK method.
/// The method needs an actual Pairing PSK behind it (normally auto-provisioned on first boot):
/// advertising it without one offers a server a flow whose handshake could only miss.
/// @param config Client configuration, held for call-site symmetry with the siblings below; the
///        method is configured entirely through the store.
/// @param store Record store holding the pairing-config flags and the Pairing PSK.
/// @return true when the method may be advertised and accepted.
inline bool offers_pairing_psk(const SendspinClientConfig& /*config*/, const RecordStore& store) {
    return store.pairing_psk_enabled() && store.pairing_psk().has_value();
}

/// @brief Whether the client offers the dynamic pairing code.
/// pairing.md "client/hello pair-method descriptor" makes `out_channels` and `formats` required,
/// and a descriptor left with no recognized format or no recognized channel is ignored outright,
/// so a device that lists neither cannot offer the method: it has no way to emit the code it
/// would have to derive.
/// @param config Client configuration supplying the out-channels and emission formats.
/// @param store Record store holding the pairing-config flags.
/// @return true when the method may be advertised and accepted.
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
/// @param config Client configuration supplying the pairing-window capability.
/// @param store Record store holding the pairing-config flags and the static code.
/// @return true when the method may be advertised and accepted.
inline bool offers_static_pairing_code(const SendspinClientConfig& config,
                                       const RecordStore& store) {
    return config.pairing_window_supported && store.static_pairing_code_enabled() &&
           store.static_pairing_code().has_value() && !offers_dynamic_pairing_code(config, store);
}

/// @brief Whether `format` is one the client advertises in its `formats` list.
/// A nullopt format is one the activation omitted or named unrecognizably, which is equally not
/// offered (messaging.md "server/activate" requires the field on a dynamic_pairing_code
/// activation).
/// @param config Client configuration supplying the advertised `formats` list.
/// @param format Format the activation selected, or nullopt when it named none.
/// @return true when the client advertises `format`.
inline bool offers_pairing_code_format(const SendspinClientConfig& config,
                                       const std::optional<SendspinPairingCodeFormat>& format) {
    return format.has_value() &&
           std::find(config.pairing_code_formats.begin(), config.pairing_code_formats.end(),
                     format.value()) != config.pairing_code_formats.end();
}

}  // namespace sendspin
