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

// Unit tests for SendspinDecoder's chunk contract (roles/player/v1.md "Codec framing"): a chunk
// may decode to more than the output buffer holds, and the caller resumes with the rest.

#include "audio_stream_info.h"
#include "audio_types.h"
#include "decoder.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

using sendspin::AudioStreamInfo;
using sendspin::SendspinDecoder;

namespace {

// flac --blocksize=16 of kSamples: 16-bit mono at 8 kHz. The header is "fLaC" plus STREAMINFO
// (marked last), which is what stream/start's codec_header carries.
const std::vector<uint8_t> FLAC_HEADER = {
    0x66, 0x4c, 0x61, 0x43, 0x80, 0x00, 0x00, 0x22, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00,
    0x21, 0x00, 0x00, 0x23, 0x01, 0xf4, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x30, 0xe2, 0x6f,
    0x18, 0x66, 0x87, 0x1a, 0x1d, 0xae, 0x60, 0x66, 0x42, 0xbb, 0x98, 0xca, 0x8d, 0x09,
};

// Three 16-sample frames, starting at byte offsets 0, 35 and 68.
const std::vector<uint8_t> FLAC_FRAMES = {
    0xff, 0xf8, 0x64, 0x08, 0x00, 0x0f, 0xce, 0x10, 0x02, 0x47, 0x9f, 0x02, 0x8f, 0x12, 0x11,
    0x1d, 0xc4, 0x3a, 0x3a, 0xc8, 0xa4, 0x74, 0x11, 0xa8, 0xe5, 0x24, 0x11, 0xc4, 0x49, 0xa3,
    0x7c, 0x96, 0x40, 0xf7, 0x7b, 0xff, 0xf8, 0x64, 0x08, 0x01, 0x0f, 0xdb, 0x42, 0x03, 0xb8,
    0xff, 0xcd, 0x63, 0x7f, 0x72, 0x03, 0x08, 0x92, 0x04, 0x28, 0xc2, 0x04, 0x41, 0x02, 0x11,
    0xfa, 0x11, 0xf2, 0x01, 0xea, 0x08, 0xf2, 0xbf, 0xff, 0xf8, 0x64, 0x08, 0x02, 0x0f, 0xe4,
    0x42, 0x03, 0x88, 0xff, 0x9d, 0x63, 0x7e, 0x70, 0x03, 0x0a, 0x15, 0x04, 0xea, 0x42, 0x75,
    0x01, 0x32, 0x70, 0x95, 0x30, 0x48, 0x94, 0x23, 0x4a, 0xd0, 0xc7,
};
constexpr size_t FLAC_FIRST_FRAME_BYTES = 35;
constexpr size_t FLAC_FRAME_PCM_BYTES = 16 * 2;

/// The 48 samples the fixture encodes, as little-endian 16-bit PCM.
std::vector<uint8_t> flac_source_pcm() {
    std::vector<uint8_t> pcm;
    for (int i = 0; i < 48; ++i) {
        const auto sample = static_cast<int16_t>((i * 997 % 2000) - 1000);
        pcm.push_back(static_cast<uint8_t>(sample & 0xff));
        pcm.push_back(static_cast<uint8_t>((sample >> 8) & 0xff));
    }
    return pcm;
}

void start_flac(SendspinDecoder& decoder) {
    AudioStreamInfo info;
    ASSERT_TRUE(decoder.process_header(FLAC_HEADER.data(), FLAC_HEADER.size(),
                                       sendspin::CHUNK_TYPE_FLAC_HEADER, &info));
}

/// Decodes `chunk` the way the sync task does: `room` bytes of output per call, resuming with
/// whatever the previous call left unconsumed. Returns the decoded audio and the call count.
std::vector<uint8_t> decode_resuming(SendspinDecoder& decoder, const std::vector<uint8_t>& chunk,
                                     size_t room, int* calls) {
    std::vector<uint8_t> out;
    size_t offset = 0;
    *calls = 0;
    while (offset < chunk.size() && *calls < 10) {
        std::vector<uint8_t> buffer(room);
        size_t consumed = 0;
        size_t decoded = 0;
        EXPECT_TRUE(decoder.decode_audio_chunk(chunk.data() + offset, chunk.size() - offset,
                                               buffer.data(), buffer.size(), &consumed, &decoded));
        out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(decoded));
        offset += consumed;
        ++*calls;
    }
    return out;
}

}  // namespace

// "flac: one or more complete FLAC frames": every frame in a chunk decodes, whether the output has
// room for all of them in one call or for only one frame at a time.
TEST(Decoder, FlacChunkWithSeveralFramesDecodesEveryFrame) {
    SendspinDecoder decoder;
    start_flac(decoder);
    ASSERT_EQ(decoder.get_decode_buffer_size(), FLAC_FRAME_PCM_BYTES);

    int calls = 0;
    EXPECT_EQ(decode_resuming(decoder, FLAC_FRAMES, 3 * FLAC_FRAME_PCM_BYTES, &calls),
              flac_source_pcm());
    EXPECT_EQ(calls, 1);

    SendspinDecoder resumed;
    start_flac(resumed);
    EXPECT_EQ(decode_resuming(resumed, FLAC_FRAMES, resumed.get_decode_buffer_size(), &calls),
              flac_source_pcm());
    EXPECT_EQ(calls, 3);
}

// Out of room, the decoder stops at a frame boundary and reports how far it got.
TEST(Decoder, FlacStopsAtAFrameBoundaryWhenOutOfRoom) {
    SendspinDecoder decoder;
    start_flac(decoder);
    std::vector<uint8_t> buffer(FLAC_FRAME_PCM_BYTES);
    size_t consumed = 0;
    size_t decoded = 0;
    ASSERT_TRUE(decoder.decode_audio_chunk(FLAC_FRAMES.data(), FLAC_FRAMES.size(), buffer.data(),
                                           buffer.size(), &consumed, &decoded));
    EXPECT_EQ(consumed, FLAC_FIRST_FRAME_BYTES);
    EXPECT_EQ(decoded, FLAC_FRAME_PCM_BYTES);
}

// A chunk that ends mid-frame is malformed: frames never span chunks.
TEST(Decoder, FlacChunkEndingMidFrameIsAnError) {
    SendspinDecoder decoder;
    start_flac(decoder);
    std::vector<uint8_t> buffer(3 * FLAC_FRAME_PCM_BYTES);
    size_t consumed = 0;
    size_t decoded = 0;
    EXPECT_FALSE(decoder.decode_audio_chunk(FLAC_FRAMES.data(), FLAC_FIRST_FRAME_BYTES + 10,
                                            buffer.data(), buffer.size(), &consumed, &decoded));
}

// A PCM chunk as long as roles/player/v1.md "Server Audio Send Constraints" allows (150 ms) fits
// the decode buffer in one call; with less room, whole frames are copied per call and the caller
// resumes. A chunk that is not whole frames is rejected.
TEST(Decoder, PcmChunkAtTheSpecMaximumFitsOneCallAndPartialFramesAreRejected) {
    SendspinDecoder decoder;
    AudioStreamInfo info;
    const sendspin::DummyHeader header{.sample_rate = 48000, .bits_per_sample = 16, .channels = 2};
    ASSERT_TRUE(decoder.process_header(reinterpret_cast<const uint8_t*>(&header), sizeof(header),
                                       sendspin::CHUNK_TYPE_PCM_DUMMY_HEADER, &info));

    std::vector<uint8_t> chunk(info.ms_to_bytes(150));
    for (size_t i = 0; i < chunk.size(); ++i) {
        chunk[i] = static_cast<uint8_t>(i * 7);
    }

    int calls = 0;
    EXPECT_EQ(decode_resuming(decoder, chunk, decoder.get_decode_buffer_size(), &calls), chunk);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(decode_resuming(decoder, chunk, chunk.size() / 2, &calls), chunk);
    EXPECT_EQ(calls, 2);

    std::vector<uint8_t> buffer(chunk.size());
    size_t consumed = 0;
    size_t decoded = 0;
    EXPECT_FALSE(decoder.decode_audio_chunk(chunk.data(), info.frames_to_bytes(1) + 1,
                                            buffer.data(), buffer.size(), &consumed, &decoded));
}
