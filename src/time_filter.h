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

/// @file time_filter.h
/// @brief Two-dimensional Kalman filter for NTP-style clock offset and drift estimation between
/// client and server

#pragma once

#include <cstdint>
#include <limits>

namespace sendspin {

/// @brief A time filter's conversion between the client and server clocks, as of its latest
/// measurement: what threads other than the protocol task read of a connection's filter
/// (ConnectionManager::clock()).
struct TimeTransform {
    /// Server minus client time at last_update, in microseconds.
    double offset{0.0};
    /// Drift the conversions apply: the filter's estimate once significant, otherwise 0.
    double drift{0.0};
    /// Client time of the latest measurement, in microseconds.
    int64_t last_update{0};
    /// Whether the filter has taken at least one measurement.
    bool synced{false};

    /// @brief Converts a client timestamp to the equivalent server timestamp.
    int64_t compute_server_time(int64_t client_time) const;

    /// @brief Converts a server timestamp to the equivalent client timestamp.
    int64_t compute_client_time(int64_t server_time) const;

    bool operator==(const TimeTransform&) const = default;
};

/// @brief Two-dimensional Kalman filter for NTP-style time synchronization between client and
/// server.
///
/// This class implements a time synchronization filter that tracks both the timestamp offset and
/// clock drift rate between a client and server. It processes measurements obtained with NTP-style
/// time messages that contain round-trip timing information to optimally estimate the time
/// relationship while accounting for network latency uncertainty.
///
/// The filter maintains a 2D state vector [offset, drift] with associated covariance matrix to
/// track estimation uncertainty. An adaptive forgetting factor helps the filter recover quickly
/// from network disruptions or server clock adjustments.
///
/// All computations use double precision arithmetic to maintain microsecond-level accuracy over
/// extended periods. A filter belongs to one connection and is used on the protocol task only;
/// other threads read its transform().
class SendspinTimeFilter {
public:
    // ========================================
    // Core API
    // ========================================

    /// @brief Processes a new time synchronization measurement through the Kalman filter.
    ///
    /// Updates the filter's offset and drift estimates using a two-stage Kalman filter algorithm:
    /// predict based on the drift model then correct using the new measurement. The measurement
    /// uncertainty is derived from the network round-trip delay.
    ///
    /// @param measurement Computed offset from NTP-style exchange: ((T2-T1)+(T3-T4))/2 in
    /// microseconds.
    /// @param max_error Half the round-trip delay: ((T4-T1)-(T3-T2))/2, representing maximum
    /// measurement uncertainty in
    ///                  microseconds.
    /// @param time_added Client timestamp when this measurement was taken in microseconds.
    void update(int64_t measurement, int64_t max_error, int64_t time_added);

    /// @brief Converts a client timestamp to the equivalent server timestamp.
    ///
    /// Applies the current offset and drift compensation to transform from client time domain to
    /// server time domain. The transformation accounts for both static offset and dynamic drift
    /// accumulated since the last filter update.
    ///
    /// @param client_time Client timestamp in microseconds.
    /// @return Equivalent server timestamp in microseconds.
    int64_t compute_server_time(int64_t client_time) const;

    /// @brief Converts a server timestamp to the equivalent client timestamp.
    ///
    /// Inverts the time transformation to convert from server time domain to client time domain.
    /// Accounts for both offset and drift effects in the inverse transformation.
    ///
    /// @param server_time Server timestamp in microseconds.
    /// @return Equivalent client timestamp in microseconds.
    int64_t compute_client_time(int64_t server_time) const;

    /// @brief Resets the filter to its initial uninitialized state.
    ///
    /// Clears all state estimates and resets covariances to initial values. The filter will require
    /// new measurements to re-establish synchronization.
    void reset();

    // ========================================
    // Accessors
    // ========================================

    /// @brief Returns the estimated standard deviation of the offset in microseconds.
    ///
    /// Provides a measure of the current synchronization accuracy by computing the square root of
    /// the offset covariance. Smaller values indicate higher confidence in the time
    /// synchronization.
    ///
    /// @return Standard deviation of the offset estimate in microseconds.
    int64_t get_error() const;

    /// @brief Returns true if the filter has received at least one measurement.
    /// @return True if the filter has been updated with at least one time measurement.
    bool has_update() const;

    /// @brief Returns the conversion as of the latest measurement.
    TimeTransform transform() const;

protected:
    // ========================================
    // Member variables
    // ========================================

    // 64-bit fields
    double drift_{0.0};
    double drift_covariance_{0.0};
    int64_t last_update_{0};
    double offset_{0.0};
    double offset_covariance_{std::numeric_limits<double>::infinity()};
    double offset_drift_covariance_{0.0};

    // 8-bit fields
    uint8_t count_{0};
    bool use_drift_{false};
};

}  // namespace sendspin
