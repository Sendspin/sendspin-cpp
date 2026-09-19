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

#include "fake_persistence.h"
#include "pairing_offers.h"
#include "record_store.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/persistence_codec.h"
#include "sendspin/types.h"

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

// A store built the way the client builds one: from provider blobs, since the pairing config and
// the static pairing code are construction-time state the store never rewrites.
class TestStore {
public:
    explicit TestStore(const SendspinPairingConfig& pairing_config,
                       const std::optional<std::string>& static_code = std::nullopt) {
        const std::string encoded = encode_pairing_config(pairing_config);
        this->provider_.seed_blob(
            persistence_keys::PAIR_CONFIG,
            std::vector<uint8_t>(encoded.begin(), encoded.end()));
        if (static_code.has_value()) {
            this->provider_.seed_blob(
                persistence_keys::STATIC_PAIRING_CODE,
                std::vector<uint8_t>(static_code->begin(), static_code->end()));
        }
        this->store_ = std::make_unique<RecordStore>(&this->provider_);
    }

    const RecordStore& get() const { return *this->store_; }

private:
    InMemoryPersistenceProvider provider_;
    std::unique_ptr<RecordStore> store_;
};

// A device able to emit a dynamic pairing code: an out-channel and a format, which the
// descriptor requires (pairing.md "client/hello pair-method descriptor").
SendspinClientConfig emitting_config() {
    SendspinClientConfig config;
    config.pairing_code_out_channels = {SendspinPairingCodeChannel::DISPLAY};
    config.pairing_code_formats = {SendspinPairingCodeFormat::DIGITS};
    return config;
}

constexpr const char* STATIC_CODE = "13572468";

}  // namespace

// ============================================================================
// offers_pairing_psk
// ============================================================================

// The store pre-provisions a Pairing PSK on every boot, so the enabled flag is the whole of the
// decision in practice; the predicate's has_value() conjunct guards a store that was built
// without one, which nothing in the library can currently produce.
TEST(PairingOffers, PairingPskFollowsItsEnabledFlag) {
    SendspinPairingConfig config;
    config.pairing_psk_enabled = true;
    TestStore enabled(config);
    ASSERT_TRUE(enabled.get().pairing_psk().has_value());
    EXPECT_TRUE(offers_pairing_psk(emitting_config(), enabled.get()));

    config.pairing_psk_enabled = false;
    TestStore disabled(config);
    EXPECT_FALSE(offers_pairing_psk(emitting_config(), disabled.get()));
}

// ============================================================================
// offers_dynamic_pairing_code
// ============================================================================

// Enabled, plus the two configured lists the descriptor cannot be built without: a device that
// lists neither channel nor format cannot emit a code, whatever the flag says.
TEST(PairingOffers, DynamicPairingCodeNeedsAnOutChannelAndAFormat) {
    SendspinPairingConfig config;
    config.dynamic_pairing_code_enabled = true;
    TestStore store(config);

    EXPECT_TRUE(offers_dynamic_pairing_code(emitting_config(), store.get()));

    SendspinClientConfig no_channel = emitting_config();
    no_channel.pairing_code_out_channels.clear();
    EXPECT_FALSE(offers_dynamic_pairing_code(no_channel, store.get()));

    SendspinClientConfig no_format = emitting_config();
    no_format.pairing_code_formats.clear();
    EXPECT_FALSE(offers_dynamic_pairing_code(no_format, store.get()));
}

TEST(PairingOffers, DynamicPairingCodeFollowsItsEnabledFlag) {
    SendspinPairingConfig config;
    config.dynamic_pairing_code_enabled = false;
    TestStore store(config);

    EXPECT_FALSE(offers_dynamic_pairing_code(emitting_config(), store.get()));
}

// ============================================================================
// offers_static_pairing_code
// ============================================================================

// The static method needs the provisioned code AND the operator gesture its flow is gated on
// (pairing.md "Pairing Window"), so a device with no pairing-window support offers nothing it
// could then wait on.
TEST(PairingOffers, StaticPairingCodeNeedsTheCodeTheFlagAndTheWindow) {
    SendspinPairingConfig config;
    config.dynamic_pairing_code_enabled = false;
    config.static_pairing_code_enabled = true;

    SendspinClientConfig windowed;
    windowed.pairing_window_supported = true;

    TestStore provisioned(config, STATIC_CODE);
    ASSERT_TRUE(provisioned.get().static_pairing_code().has_value());
    EXPECT_TRUE(offers_static_pairing_code(windowed, provisioned.get()));

    SendspinClientConfig no_window = windowed;
    no_window.pairing_window_supported = false;
    EXPECT_FALSE(offers_static_pairing_code(no_window, provisioned.get()));

    TestStore no_code(config);
    EXPECT_FALSE(offers_static_pairing_code(windowed, no_code.get()));

    SendspinPairingConfig disabled = config;
    disabled.static_pairing_code_enabled = false;
    TestStore flag_off(disabled, STATIC_CODE);
    EXPECT_FALSE(offers_static_pairing_code(windowed, flag_off.get()));
}

// messaging.md "client/hello" permits at most one pairing-code method, and pairing.md "Methods"
// prefers the dynamic one wherever an out-channel exists. A device configured for both must
// therefore offer only the dynamic one, or a server is handed a choice the client/hello may not
// present.
TEST(PairingOffers, StaticPairingCodeYieldsToTheDynamicOne) {
    SendspinPairingConfig both;
    both.dynamic_pairing_code_enabled = true;
    both.static_pairing_code_enabled = true;
    TestStore store(both, STATIC_CODE);

    SendspinClientConfig config = emitting_config();
    config.pairing_window_supported = true;

    ASSERT_TRUE(offers_dynamic_pairing_code(config, store.get()));
    EXPECT_FALSE(offers_static_pairing_code(config, store.get()))
        << "a device offering the dynamic code must not also offer the static one";

    // Control: the same store and the same flags, with the device unable to emit a code, offers
    // the static method instead. Nothing but the dynamic offer suppressed it above.
    SendspinClientConfig no_emission;
    no_emission.pairing_window_supported = true;
    ASSERT_FALSE(offers_dynamic_pairing_code(no_emission, store.get()));
    EXPECT_TRUE(offers_static_pairing_code(no_emission, store.get()));
}
