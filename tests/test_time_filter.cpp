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

// Unit tests for the SendspinTimeFilter Kalman filter. We don't try to prove the filter is
// "optimal" -- instead we pin down the behavioral invariants a refactor could silently break:
// monotonic-timestamp rejection, reset semantics, the offset/inverse round-trip, and convergence
// toward a constant offset.

#include "time_filter.h"

#include <gtest/gtest.h>

#include <cstdint>

using sendspin::SendspinTimeFilter;

TEST(TimeFilter, HasUpdateStartsFalse) {
    SendspinTimeFilter filter;
    EXPECT_FALSE(filter.has_update());

    filter.update(/*measurement=*/1000, /*max_error=*/100, /*time_added=*/5000);
    EXPECT_TRUE(filter.has_update());
}

// The first measurement establishes the offset baseline, so server_time = client_time + offset.
TEST(TimeFilter, FirstSampleEstablishesOffset) {
    SendspinTimeFilter filter;
    filter.update(/*measurement=*/1000, /*max_error=*/100, /*time_added=*/5000);

    EXPECT_EQ(filter.compute_server_time(5000), 6000);          // 5000 + 1000 offset
    EXPECT_EQ(filter.compute_client_time(6000), 5000);          // exact inverse with no drift
}

// time_added <= last_update_ is rejected: it guards against divide-by-zero and out-of-order
// packets. A rejected update must leave the estimate untouched.
TEST(TimeFilter, RejectsNonMonotonicTimestamps) {
    SendspinTimeFilter filter;
    filter.update(/*measurement=*/1000, /*max_error=*/100, /*time_added=*/5000);
    const int64_t before = filter.compute_server_time(5000);

    // Same timestamp -> skipped; a wild measurement must not move the estimate.
    filter.update(/*measurement=*/999999, /*max_error=*/100, /*time_added=*/5000);
    EXPECT_EQ(filter.compute_server_time(5000), before);

    // Earlier timestamp -> also skipped.
    filter.update(/*measurement=*/-999999, /*max_error=*/100, /*time_added=*/4000);
    EXPECT_EQ(filter.compute_server_time(5000), before);
}

TEST(TimeFilter, ResetClearsState) {
    SendspinTimeFilter filter;
    filter.update(1000, 100, 5000);
    filter.update(1000, 100, 6000);
    ASSERT_TRUE(filter.has_update());

    filter.reset();
    EXPECT_FALSE(filter.has_update());
}

// Fed a constant true offset with low measurement noise, the filter should settle on that offset
// and report shrinking uncertainty.
TEST(TimeFilter, ConvergesToConstantOffset) {
    SendspinTimeFilter filter;

    constexpr int64_t kTrueOffset = 5000;
    constexpr int64_t kMaxError = 100;  // measurement std dev = max_error * 0.5 = 50

    for (int i = 1; i <= 100; ++i) {
        const int64_t t = static_cast<int64_t>(i) * 100000;  // 100 ms apart
        filter.update(kTrueOffset, kMaxError, t);
    }

    const int64_t t = 100 * 100000;
    const int64_t estimated_offset = filter.compute_server_time(t) - t;
    EXPECT_NEAR(static_cast<double>(estimated_offset), static_cast<double>(kTrueOffset), 5.0);

    // Uncertainty should have collapsed well below the single-sample measurement std dev.
    const int64_t error = filter.get_error();
    EXPECT_GT(error, 0);
    EXPECT_LT(error, 50);
}
