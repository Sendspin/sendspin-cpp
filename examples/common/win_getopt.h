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

/// @file win_getopt.h
/// @brief Minimal POSIX getopt() for Windows, which has none: grouped short options, and "x:" for
/// an option taking an argument as -x val or -xval. Parsing stops at the first non-option or "--".
/// Errors return '?' without a message, as the examples print their usage on it.

#pragma once

#include <cstring>

inline char* optarg = nullptr;
inline int optind = 1;

inline int getopt(int argc, char* const argv[], const char* optstring) {
    static int pos = 1;  // next character inside a grouped argument such as -vq
    optarg = nullptr;
    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
        return -1;
    }
    if (std::strcmp(argv[optind], "--") == 0) {
        ++optind;
        return -1;
    }

    char* const arg = argv[optind];
    const char c = arg[pos++];
    const char* spec = c == ':' ? nullptr : std::strchr(optstring, c);
    const bool takes_arg = spec != nullptr && spec[1] == ':';
    if (takes_arg && arg[pos] != '\0') {
        optarg = &arg[pos];
    } else if (takes_arg && optind + 1 < argc) {
        optarg = argv[++optind];
    }
    if (takes_arg || arg[pos] == '\0') {
        ++optind;
        pos = 1;
    }
    return (spec == nullptr || (takes_arg && optarg == nullptr)) ? '?' : c;
}
