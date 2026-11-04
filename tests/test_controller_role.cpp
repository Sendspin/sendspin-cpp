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

/// @file test_controller_role.cpp
/// @brief Tests for the controller role's Impl: the public state it fills from a parsed one

#include "controller_role_impl.h"
#include "protocol_messages.h"
#include "sendspin/controller_role.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace sendspin {
namespace {

// roles/controller/v1.md "server/state controller object" makes supported_commands a subset, so
// the public state lists each command once, in enumerator order, beside every other field the
// parsed state carries; a later state's list replaces the one before it.
TEST(ControllerRoleState, AStateFillsEveryFieldOfThePublicState) {
    ControllerRole::Impl role(nullptr);
    ControllerStatePayload first;
    first.supported_commands = {SendspinControllerCommand::MUTE, SendspinControllerCommand::PLAY};
    first.volume = 42;
    first.muted = true;
    first.repeat = SendspinRepeatMode::ALL;
    first.shuffle = true;
    first.seek_max_ms = 215000;
    role.apply_state(first);

    const ServerStateControllerObject& state = role.controller_state;
    EXPECT_EQ(state.supported_commands,
              (std::vector{SendspinControllerCommand::PLAY, SendspinControllerCommand::MUTE}));
    EXPECT_EQ(state.volume, 42);
    EXPECT_TRUE(state.muted);
    EXPECT_EQ(state.repeat, SendspinRepeatMode::ALL);
    EXPECT_TRUE(state.shuffle);
    EXPECT_EQ(state.seek_max_ms, std::optional<uint32_t>{215000});

    ControllerStatePayload second;
    second.supported_commands = {SendspinControllerCommand::SEEK_RELATIVE};
    role.apply_state(second);
    EXPECT_EQ(state.supported_commands, std::vector{SendspinControllerCommand::SEEK_RELATIVE});
    // Every field the later state leaves at its default is reset too, which is also the
    // teardown's reset (complete_teardown() applies a default state).
    EXPECT_EQ(state.volume, 0);
    EXPECT_FALSE(state.muted);
    EXPECT_EQ(state.repeat, SendspinRepeatMode::OFF);
    EXPECT_FALSE(state.shuffle);
    EXPECT_FALSE(state.seek_max_ms.has_value());
}

}  // namespace
}  // namespace sendspin
