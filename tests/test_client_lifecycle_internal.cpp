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

// White-box tests for the two SendspinClient lifecycle paths that no socket-level test can
// reach (compiled with -fno-access-control, see CMakeLists.txt, rather than adding test seams
// to the production code):
//
//   - the session-state reset in finish_stop(). group_state_ is only ever filled from a server
//     group/update and state_ has no public getter, so staging and reading them back needs
//     private access.
//   - start()'s rollback of already-started role threads when a later role fails to start.
//     No role's start() can be made to fail through the public API on host (the failure paths
//     are allocation and pthread-creation failures), so the failure is staged directly.

#include "player_role_impl.h"
#include "sendspin/client.h"
#include "sendspin/config.h"
#include "sendspin/player_role.h"
#include "sendspin/visualizer_role.h"
#include "sync_task.h"
#include "visualizer_role_impl.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <utility>

using namespace sendspin;  // NOLINT(google-build-using-namespace): test-local convenience

namespace {

SendspinClientConfig make_config() {
    SendspinClientConfig config;
    config.client_id = "client-lifecycle-internal-test";
    config.name = "Client Lifecycle Internal Test";
    return config;
}

// Minimal player listener so a real player role (and thus a live sync task thread) can be
// attached without audio hardware: writes are accepted and discarded.
class NullPlayerListener : public PlayerRoleListener {
public:
    size_t on_audio_write(uint8_t* /*data*/, size_t length, uint32_t /*timeout_ms*/) override {
        return length;
    }
};

}  // namespace

// Finding: finish_stop() must clear the session-scoped published state so a restarted client does
// not serve the previous session's group deltas or republish a stale ERROR client state to the
// next server on handshake. cleanup_connection_state() deliberately does not reset these (it also
// runs on reconnects and handoffs, where carrying them forward is intentional), so the stop path
// is the only place that does.
TEST(ClientLifecycleInternal, StopResetsPublishedSessionStateForRestart) {
    SendspinClient client(make_config());
    ASSERT_TRUE(client.start());

    // Stand in for a session that accumulated a group delta and then reported an error.
    client.group_state_.group_id = "old-group";
    client.group_state_.group_name = "Old Group";
    client.update_state(SendspinClientState::ERROR);

    // Control: the state really is dirty going into the stop, so the assertions below cannot
    // pass just because it was never set.
    ASSERT_EQ(client.get_group_state().group_id, "old-group");
    ASSERT_EQ(client.get_group_state().group_name, "Old Group");
    ASSERT_EQ(client.state_, SendspinClientState::ERROR);

    client.stop();

    EXPECT_FALSE(client.get_group_state().group_id.has_value());
    EXPECT_FALSE(client.get_group_state().group_name.has_value());
    EXPECT_FALSE(client.get_group_state().playback_state.has_value());
    EXPECT_EQ(client.state_, SendspinClientState::SYNCHRONIZED);

    // The restart begins from that clean state rather than re-deriving it on connect.
    ASSERT_TRUE(client.start());
    EXPECT_FALSE(client.get_group_state().group_id.has_value());
    EXPECT_EQ(client.state_, SendspinClientState::SYNCHRONIZED);

    client.stop();
}

// Finding: when a role fails to start, start() must stop the role threads that already started
// before returning false, so the client is genuinely back in the stopped state and a corrected
// retry begins clean. Roles start in the order player, visualizer, artwork, so a sabotaged
// visualizer leaves the player's sync task thread as the one that must be rolled back.
TEST(ClientLifecycleInternal, StartRollsBackStartedRoleThreadsWhenALaterRoleFails) {
    SendspinClient client(make_config());
    NullPlayerListener player_listener;

    PlayerRoleConfig player_config;
    player_config.audio_formats = {{SendspinCodecFormat::PCM, 2, 44100, 16}};
    auto& player = client.add_player(std::move(player_config));
    player.set_listener(&player_listener);

    VisualizerRoleConfig visualizer_config;
    visualizer_config.support.buffer_capacity = 4096;
    client.add_visualizer(std::move(visualizer_config));

    // Control: with both roles healthy, start() succeeds and the sync task thread is running.
    // Without this the rollback assertion below would also pass if the thread had simply never
    // started in the first place.
    ASSERT_TRUE(client.start());
    ASSERT_TRUE(client.player_->impl_->sync_task->is_thread_running());
    client.stop();
    ASSERT_FALSE(client.player_->impl_->sync_task->is_thread_running());

    // Sabotage the visualizer so its start() fails at the drain-task check, after the player's
    // start() has already brought the sync task thread back up.
    client.visualizer_->impl_->drain_task.reset();

    EXPECT_FALSE(client.start());
    EXPECT_EQ(client.get_run_state(), SendspinRunState::STOPPED);
    EXPECT_FALSE(client.is_started());

    // The rollback joined the thread the player had already started. Without it the client
    // reports itself stopped while a live sync task thread runs on.
    EXPECT_FALSE(client.player_->impl_->sync_task->is_thread_running());
}
