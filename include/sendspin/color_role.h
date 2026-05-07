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

/// @file color_role.h
/// @brief Color role that receives audio-derived colors from the server

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>

namespace sendspin {

class SendspinClient;

// ============================================================================
// Color types
// ============================================================================

/// @brief 8-bit RGB color triple, ordered [R, G, B] with values 0-255
using RgbColor = std::array<uint8_t, 3>;

/// @brief Audio-derived color palette received from the server
///
/// Each color field is `nullopt` when the server has not provided that color,
/// or has explicitly cleared it. The server guarantees WCAG contrast on the
/// background_dark/background_light variants when present.
struct ServerColorStateObject {
    int64_t timestamp{};
    /// @brief Background color suitable for dark mode; safe contrast with white text and on_dark
    std::optional<RgbColor> background_dark;
    /// @brief Background color suitable for light mode; safe contrast with black text and on_light
    std::optional<RgbColor> background_light;
    /// @brief Dominant color, not adjusted for contrast
    std::optional<RgbColor> primary;
    /// @brief Secondary or complementary color, not adjusted for contrast
    std::optional<RgbColor> accent;
    /// @brief Light foreground suitable for use on dark backgrounds
    std::optional<RgbColor> on_dark;
    /// @brief Dark foreground suitable for use on light backgrounds
    std::optional<RgbColor> on_light;
};

/// @brief Listener for color role events. All methods fire on the main loop thread.
class ColorRoleListener {
public:
    virtual ~ColorRoleListener() = default;

    /// @brief Called when the color palette is updated by the server
    virtual void on_color(const ServerColorStateObject& /*color*/) {}

    /// @brief Called when the connection to the server is lost and cached colors are dropped
    ///
    /// Implementations should reset any displayed colors to a neutral or default state since the
    /// previous server's palette is no longer valid.
    virtual void on_color_clear() {}
};

/**
 * @brief Color role that receives audio-derived colors from the server
 *
 * Maintains a local shadow of the server's color palette. Incoming color deltas are merged into
 * the shadow and delivered to the listener on the main loop thread once the synchronized client
 * clock reaches the update's `timestamp` (or immediately if there is no active connection).
 *
 * Usage:
 * 1. Implement ColorRoleListener to receive color updates
 * 2. Add the role to the client via SendspinClient::add_color()
 * 3. Call set_listener() with your listener implementation
 *
 * @code
 * struct MyColorListener : ColorRoleListener {
 *     void on_color(const ServerColorStateObject& c) override {
 *         if (c.primary) led.set_color((*c.primary)[0], (*c.primary)[1], (*c.primary)[2]);
 *     }
 * };
 *
 * MyColorListener listener;
 * auto& color = client.add_color();
 * color.set_listener(&listener);
 * @endcode
 */
class ColorRole {
    friend class SendspinClient;

public:
    struct Impl;

    explicit ColorRole(SendspinClient* client);
    ~ColorRole();

    /// @brief Sets the listener for color events
    /// @note The listener must outlive this role
    /// @param listener Pointer to the listener implementation
    void set_listener(ColorRoleListener* listener);

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace sendspin
