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

#pragma once

#include <functional>
#include <mutex>
#include <string>

namespace sendspin {

/// @brief Interface from client to roles, providing access to shared client services.
struct ClientBridge {
    std::function<int64_t(int64_t)> get_client_time;
    std::function<bool()> is_time_synced;
    std::function<void()> publish_state;
    std::function<void(const std::string&)> send_text;
    std::function<void()> request_high_performance;
    std::function<void()> release_high_performance;
    std::mutex& event_mutex;
};

}  // namespace sendspin
