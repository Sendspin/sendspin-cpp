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

/// @file cli_util.h
/// @brief Shared command-line parsing helpers for the host examples

#pragma once

#include "sendspin/client.h"

#include <cstdlib>
#include <cstring>

namespace sendspin_examples {

/// @brief Parses a log-level name (none/error/warn/info/debug/verbose) into a LogLevel
/// @return true on a recognized name; false leaves @p level unchanged.
inline bool parse_log_level(const char* str, sendspin::LogLevel& level) {
    if (strcmp(str, "none") == 0) {
        level = sendspin::LogLevel::NONE;
    } else if (strcmp(str, "error") == 0) {
        level = sendspin::LogLevel::ERROR;
    } else if (strcmp(str, "warn") == 0) {
        level = sendspin::LogLevel::WARN;
    } else if (strcmp(str, "info") == 0) {
        level = sendspin::LogLevel::INFO;
    } else if (strcmp(str, "debug") == 0) {
        level = sendspin::LogLevel::DEBUG;
    } else if (strcmp(str, "verbose") == 0) {
        level = sendspin::LogLevel::VERBOSE;
    } else {
        return false;
    }
    return true;
}

}  // namespace sendspin_examples
