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

// Compile-only check that the public headers survive the macros <windows.h> defines when a
// consumer includes it first: wingdi.h's object-like ERROR and windows.h's function-like min()
// and max(). There is no TEST(): the translation unit failing to build is the failure. Until a
// Windows CI job compiles against the real <windows.h>, this stands in for it on every host.

// Every standard header the public headers include, ahead of the macros: libstdc++ and libc++
// do not guard their own headers against a function-like min()/max() the way the MSVC STL does.
// A public header that adds a standard include needs it added here too, or this file fails
// inside that standard header rather than in a sendspin one.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// As wingdi.h and windows.h (without NOMINMAX) define them.
#define ERROR 0
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

// Every public header. client.h brings in config.h, types.h and persistence_keys.h but only
// forward-declares the roles, so each enabled role's header is included here as well.
#include "sendspin/client.h"
#include "sendspin/persistence_codec.h"
#ifdef SENDSPIN_ENABLE_ARTWORK
#include "sendspin/artwork_role.h"
#endif
#ifdef SENDSPIN_ENABLE_COLOR
#include "sendspin/color_role.h"
#endif
#ifdef SENDSPIN_ENABLE_CONTROLLER
#include "sendspin/controller_role.h"
#endif
#ifdef SENDSPIN_ENABLE_METADATA
#include "sendspin/metadata_role.h"
#endif
#ifdef SENDSPIN_ENABLE_PLAYER
#include "sendspin/player_role.h"
#endif
#ifdef SENDSPIN_ENABLE_SOURCE
#include "sendspin/source_role.h"
#endif
#ifdef SENDSPIN_ENABLE_VISUALIZER
#include "sendspin/visualizer_role.h"
#endif

// client.h set ERROR aside around LogLevel and must hand the consumer's macro back.
static_assert(ERROR == 0, "client.h must restore the consumer's ERROR macro");
