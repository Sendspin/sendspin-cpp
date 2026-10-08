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

// Unit tests for the pairing-method offer predicates: which methods a device advertises in
// client/hello and, by the same answer, accepts on a server/activate (messaging.md
// "client/hello", pairing.md "Methods").

#include "pairing_offers.h"
#include "sendspin/config.h"
#include "sendspin/types.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

// ============================================================================
// Pairing-code offers
// ============================================================================

// The pairing-code offers are a function of SendspinClientConfig alone. The dynamic code needs an
// out-channel and a format, which its descriptor cannot be built without (pairing.md "client/hello
// pair-method descriptor"). The static code needs a configured code and yields to the dynamic code:
// messaging.md "client/hello" permits at most one pairing-code method, and pairing.md "Methods"
// prefers the dynamic one wherever an out-channel exists.
TEST(PairingOffers, PairingCodeOffersFollowTheConfig) {
    struct Row {
        const char* name;
        bool out_channel;
        bool format;
        std::optional<std::string> static_code;
        bool expect_dynamic;
        bool expect_static;
    };
    const Row rows[] = {
        {"Control: an out-channel and a format offer the dynamic code", true, true, std::nullopt,
         true, false},
        {"no out-channel", false, true, std::nullopt, false, false},
        {"no format", true, false, std::nullopt, false, false},
        {"Control: a valid static code", false, false, "13572468", false, true},
        {"no static code", false, false, std::nullopt, false, false},
        {"static and dynamic both configured offer only the dynamic code", true, true, "13572468",
         true, false},
    };

    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SendspinClientConfig config;
        if (row.out_channel) {
            config.pairing_code_out_channels = {SendspinPairingCodeChannel::DISPLAY};
        }
        if (row.format) {
            config.pairing_code_formats = {SendspinPairingCodeFormat::DIGITS};
        }
        config.static_pairing_code = row.static_code;

        EXPECT_EQ(offers_dynamic_pairing_code(config), row.expect_dynamic);
        EXPECT_EQ(offers_static_pairing_code(config), row.expect_static);
    }
}
