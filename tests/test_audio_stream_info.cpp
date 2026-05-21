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

// Unit tests for AudioStreamInfo's byte/frame/sample/duration conversions. These are exact
// integer arithmetic, so the assertions are exact: a wrong conversion silently corrupts
// buffering and A/V sync, which is exactly the kind of bug worth pinning down.

#include "audio_stream_info.h"
#include <gtest/gtest.h>

using sendspin::AudioStreamInfo;

// 16-bit stereo at 44.1 kHz: 2 bytes/sample, 4 bytes/frame.
TEST(AudioStreamInfo, CdQualityConversions) {
    const AudioStreamInfo info(16, 2, 44100);

    EXPECT_EQ(info.get_bits_per_sample(), 16);
    EXPECT_EQ(info.get_channels(), 2);
    EXPECT_EQ(info.get_sample_rate(), 44100u);

    EXPECT_EQ(info.frames_to_bytes(100), 400u);
    EXPECT_EQ(info.bytes_to_frames(400), 100u);
    EXPECT_EQ(info.samples_to_bytes(8), 16u);

    // 1 second of audio == sample_rate frames == sample_rate * frame_size bytes.
    EXPECT_EQ(info.ms_to_bytes(1000), 176400u);
    EXPECT_EQ(info.bytes_to_ms(176400), 1000u);

    EXPECT_EQ(info.frames_to_microseconds(441), 10000);   // 10 ms
    EXPECT_EQ(info.frames_to_microseconds(2205), 50000);  // 50 ms
}

// frames_to_microseconds() widens to 64-bit internally, so it stays exact well past the point
// where a 32-bit (frames * 1e6) product overflows (~4295 frames, ~97 ms at 44.1 kHz). These
// counts would have silently wrapped under the old implementation.
TEST(AudioStreamInfo, FramesToMicrosecondsNoOverflowAtLargeCounts) {
    const AudioStreamInfo info(16, 2, 44100);

    EXPECT_EQ(info.frames_to_microseconds(44100), 1000000);      // exactly 1 s
    EXPECT_EQ(info.frames_to_microseconds(88200), 2000000);      // exactly 2 s
    EXPECT_EQ(info.frames_to_microseconds(4410000), 100000000);  // 100 s, far past the old wrap
}

// 16-bit mono at 8 kHz, the library's default-ish low-rate case.
TEST(AudioStreamInfo, MonoLowRateConversions) {
    const AudioStreamInfo info(16, 1, 8000);

    EXPECT_EQ(info.ms_to_bytes(125), 2000u);  // 125 ms * 16000 B/s
    EXPECT_EQ(info.bytes_to_ms(2000), 125u);
    EXPECT_EQ(info.frames_to_microseconds(800), 100000);  // 100 ms
}

// Bit depths that are not multiples of 8 round up to whole bytes per sample.
TEST(AudioStreamInfo, BytesPerSampleRounding) {
    EXPECT_EQ(AudioStreamInfo(8, 1, 48000).frames_to_bytes(10), 10u);   // 1 byte/sample
    EXPECT_EQ(AudioStreamInfo(24, 2, 48000).frames_to_bytes(10), 60u);  // 3 bytes/sample, stereo
}

TEST(AudioStreamInfo, Equality) {
    const AudioStreamInfo a(16, 2, 44100);
    EXPECT_TRUE(a == AudioStreamInfo(16, 2, 44100));
    EXPECT_TRUE(a != AudioStreamInfo(16, 2, 48000));  // sample rate differs
    EXPECT_TRUE(a != AudioStreamInfo(24, 2, 44100));  // bit depth differs
    EXPECT_TRUE(a != AudioStreamInfo(16, 1, 44100));  // channel count differs
}

TEST(AudioStreamInfo, DefaultConstruction) {
    const AudioStreamInfo info;
    EXPECT_EQ(info.get_bits_per_sample(), 16);
    EXPECT_EQ(info.get_channels(), 1);
    EXPECT_EQ(info.get_sample_rate(), sendspin::DEFAULT_SAMPLE_RATE_HZ);
}
