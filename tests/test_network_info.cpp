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

#include "platform/network_info.h"
#include <gtest/gtest.h>

#include <regex>

using namespace sendspin;

// Host MAC detection is environment-dependent (it may legitimately find no routable interface in a
// sandboxed CI runner), so this asserts the contract rather than a specific value: the result is
// either absent or a well-formed lowercase colon-separated MAC.
TEST(NetworkInfo, InterfaceMacIsWellFormedOrAbsent) {
    const std::optional<std::string> mac = platform_get_interface_mac();
    if (!mac.has_value()) {
        GTEST_SKIP() << "no routable interface detected in this environment";
    }
    const std::regex mac_re("^[0-9a-f]{2}(:[0-9a-f]{2}){5}$");
    EXPECT_TRUE(std::regex_match(*mac, mac_re)) << "malformed MAC: " << *mac;
}
