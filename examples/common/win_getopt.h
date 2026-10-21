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
/// @brief Minimal POSIX getopt() for Windows, which has none: grouped short options, "x:" for an
/// option that takes an argument, and parsing stops at the first non-option or "--". No argument
/// permutation and no GNU extensions.

#pragma once

#include <cstdio>
#include <cstring>

inline char* optarg = nullptr;
inline int optind = 1;

inline int getopt(int argc, char* const argv[], const char* optstring) {
    static int pos = 1;  // position inside a grouped argument such as -vq
    optarg = nullptr;
    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
        return -1;
    }
    if (std::strcmp(argv[optind], "--") == 0) {
        ++optind;
        return -1;
    }

    const char c = argv[optind][pos];
    const char* spec = std::strchr(optstring, c);
    if (c == ':' || spec == nullptr) {
        std::fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], c);
        if (argv[optind][++pos] == '\0') {
            ++optind;
            pos = 1;
        }
        return '?';
    }

    if (spec[1] == ':') {
        if (argv[optind][pos + 1] != '\0') {
            optarg = &argv[optind][pos + 1];
        } else if (optind + 1 < argc) {
            optarg = argv[++optind];
        } else {
            std::fprintf(stderr, "%s: option requires an argument -- '%c'\n", argv[0], c);
            ++optind;
            pos = 1;
            return '?';
        }
        ++optind;
        pos = 1;
        return c;
    }

    if (argv[optind][++pos] == '\0') {
        ++optind;
        pos = 1;
    }
    return c;
}
