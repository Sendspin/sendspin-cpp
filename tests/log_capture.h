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

/// @file log_capture.h
/// @brief Scoped stderr capture for tests that assert on an SS_LOG* line.

#pragma once

#include "platform/logging.h"

#include <gtest/gtest.h>

#include <string>

namespace sendspin {

/// Captures stderr (where the host SS_LOG* macros write) for the duration of its scope, so a
/// test can assert on a warning itself. A durability warning IS the behavioral delta of a
/// rejected provider write: without asserting on it, a reverted or inverted condition passes
/// unnoticed, because the in-memory state is the same either way.
class StderrCapture {
public:
    StderrCapture() : prior_level_(platform_get_log_level()) {
        platform_set_log_level(SS_LOG_WARN);
        testing::internal::CaptureStderr();
    }
    ~StderrCapture() {
        if (!this->released_) {
            static_cast<void>(testing::internal::GetCapturedStderr());
        }
        platform_set_log_level(this->prior_level_);
    }
    StderrCapture(const StderrCapture&) = delete;
    StderrCapture& operator=(const StderrCapture&) = delete;

    /// Stops capturing and returns everything written so far.
    std::string release() {
        this->released_ = true;
        return testing::internal::GetCapturedStderr();
    }

private:
    int prior_level_;
    bool released_{false};
};

}  // namespace sendspin
