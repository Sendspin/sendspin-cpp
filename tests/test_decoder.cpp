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
#include "platform/memory.h"
#include "sync_task.h"
#include "transfer_buffer.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#ifdef SENDSPIN_ENABLE_OPUS
#include <opus.h>
#endif

using sendspin::AudioStreamInfo;
using sendspin::SendspinDecoder;
using sendspin::SyncContext;
using sendspin::SyncTask;
using sendspin::TransferBuffer;

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
    // Room for half the chunk plus part of a frame: the first call still stops at a whole frame.
    EXPECT_EQ(decode_resuming(decoder, chunk, chunk.size() / 2 + 1, &calls), chunk);
    EXPECT_EQ(calls, 2);

    std::vector<uint8_t> buffer(chunk.size());
    size_t consumed = 0;
    size_t decoded = 0;
    EXPECT_FALSE(decoder.decode_audio_chunk(chunk.data(), info.frames_to_bytes(1) + 1,
                                            buffer.data(), buffer.size(), &consumed, &decoded));
}

namespace {

#ifdef SENDSPIN_ENABLE_OPUS
constexpr int OPUS_FRAMES_40_MS = 1920;  // 40 ms at 48 kHz

/// One 40 ms Opus packet of 48 kHz stereo silence, twice the 20 ms the decoder first sizes for.
std::vector<uint8_t> opus_packet_40_ms() {
    int error = OPUS_OK;
    OpusEncoder* encoder = opus_encoder_create(48000, 2, OPUS_APPLICATION_AUDIO, &error);
    EXPECT_EQ(error, OPUS_OK);
    if (encoder == nullptr) {
        return {};
    }
    const std::vector<int16_t> pcm(OPUS_FRAMES_40_MS * 2, 0);
    std::vector<uint8_t> packet(4000);
    const int packet_size = opus_encode(encoder, pcm.data(), OPUS_FRAMES_40_MS, packet.data(),
                                        static_cast<opus_int32>(packet.size()));
    opus_encoder_destroy(encoder);
    EXPECT_GT(packet_size, 0);
    packet.resize(packet_size > 0 ? static_cast<size_t>(packet_size) : 0);
    return packet;
}
#endif

/// The 48 kHz stereo header the PCM and Opus rows share.
const sendspin::DummyHeader STEREO_48K_HEADER{
    .sample_rate = 48000, .bits_per_sample = 16, .channels = 2};

}  // namespace

#ifdef SENDSPIN_ENABLE_OPUS
// An Opus packet longer than the 20 ms the decoder first sizes for consumes nothing and raises the
// estimate; with that much room the same packet then decodes whole.
TEST(Decoder, OpusPacketLongerThanTheEstimateRaisesItAndDecodesOnRetry) {
    const std::vector<uint8_t> packet = opus_packet_40_ms();
    ASSERT_FALSE(packet.empty());

    SendspinDecoder decoder;
    AudioStreamInfo info;
    ASSERT_TRUE(decoder.process_header(reinterpret_cast<const uint8_t*>(&STEREO_48K_HEADER),
                                       sizeof(STEREO_48K_HEADER),
                                       sendspin::CHUNK_TYPE_OPUS_DUMMY_HEADER, &info));
    const size_t first_estimate = decoder.get_decode_buffer_size();

    std::vector<uint8_t> buffer(first_estimate);
    size_t consumed = 0;
    size_t decoded = 0;
    ASSERT_TRUE(decoder.decode_audio_chunk(packet.data(), packet.size(), buffer.data(),
                                           buffer.size(), &consumed, &decoded));
    EXPECT_EQ(consumed, 0U);
    EXPECT_EQ(decoded, 0U);
    ASSERT_GT(decoder.get_decode_buffer_size(), first_estimate);

    buffer.resize(decoder.get_decode_buffer_size());
    ASSERT_TRUE(decoder.decode_audio_chunk(packet.data(), packet.size(), buffer.data(),
                                           buffer.size(), &consumed, &decoded));
    EXPECT_EQ(consumed, packet.size());
    EXPECT_EQ(decoded, info.frames_to_bytes(OPUS_FRAMES_40_MS));
}
#endif

namespace {

/// A sync context decoding `header`'s stream, with the decode buffer the sync task allocates at a
/// codec header: one decoder unit plus the soft-sync spare frame.
void start_context(SyncContext& context, const std::vector<uint8_t>& header,
                   sendspin::ChunkType header_type) {
    context.decoder = std::make_unique<SendspinDecoder>();
    ASSERT_TRUE(context.decoder->process_header(header.data(), header.size(), header_type,
                                                &context.current_stream_info));
    context.bytes_per_frame = context.current_stream_info.frames_to_bytes(1);
    context.decode_buffer =
        TransferBuffer::create(context.decoder->get_decode_buffer_size() + context.bytes_per_frame,
                               sendspin::MemoryLocation::PREFER_EXTERNAL);
    ASSERT_NE(context.decode_buffer, nullptr);
}

/// Storage for a ring entry holding `chunk`, laid out as the encoded ring stores it.
std::vector<uint64_t> ring_entry(const std::vector<uint8_t>& chunk) {
    std::vector<uint64_t> storage(
        (sizeof(sendspin::AudioRingBufferEntry) + chunk.size()) / sizeof(uint64_t) + 1);
    auto* entry = reinterpret_cast<sendspin::AudioRingBufferEntry*>(storage.data());
    entry->chunk_type = sendspin::CHUNK_TYPE_ENCODED_AUDIO;
    entry->data_size = chunk.size();
    std::memcpy(entry->data(), chunk.data(), chunk.size());
    return storage;
}

}  // namespace

// The sync task decodes a chunk all or nothing: every frame, growing the buffer as the decoder
// asks, or, when any part fails or the whole decodes past roles/player/v1.md "Server Audio Send
// Constraints" (150 ms), none of it.
TEST(SyncTaskDecodeWholeChunk, DecodesEveryFrameOrLeavesTheBufferEmpty) {
    const std::vector<uint8_t> stereo_48k_header(
        reinterpret_cast<const uint8_t*>(&STEREO_48K_HEADER),
        reinterpret_cast<const uint8_t*>(&STEREO_48K_HEADER) + sizeof(STEREO_48K_HEADER));
#ifdef SENDSPIN_ENABLE_OPUS
    const std::vector<uint8_t> opus_packet = opus_packet_40_ms();
    ASSERT_FALSE(opus_packet.empty());
#endif
    struct Row {
        const char* name;
        const std::vector<uint8_t>* header;
        sendspin::ChunkType header_type;
        std::vector<uint8_t> chunk;
        size_t output_bytes;  // 0 when the chunk must fail
    };
    const Row rows[] = {
        {"Control: three FLAC frames outgrow a one-frame buffer", &FLAC_HEADER,
         sendspin::CHUNK_TYPE_FLAC_HEADER, FLAC_FRAMES, 3 * FLAC_FRAME_PCM_BYTES},
        {"FLAC chunk ending mid-frame", &FLAC_HEADER, sendspin::CHUNK_TYPE_FLAC_HEADER,
         std::vector<uint8_t>(FLAC_FRAMES.begin(), FLAC_FRAMES.end() - 10), 0},
#ifdef SENDSPIN_ENABLE_OPUS
        {"Control: 40 ms Opus packet grows the 20 ms buffer and retries", &stereo_48k_header,
         sendspin::CHUNK_TYPE_OPUS_DUMMY_HEADER, opus_packet, 7680},
#endif
        {"Control: PCM chunk of 150 ms", &stereo_48k_header,
         sendspin::CHUNK_TYPE_PCM_DUMMY_HEADER, std::vector<uint8_t>(28800, 0x11), 28800},
        {"PCM chunk of 151 ms", &stereo_48k_header, sendspin::CHUNK_TYPE_PCM_DUMMY_HEADER,
         std::vector<uint8_t>(28800 + 192, 0x11), 0},
    };
    for (const Row& row : rows) {
        SCOPED_TRACE(row.name);
        SyncContext context;
        ASSERT_NO_FATAL_FAILURE(start_context(context, *row.header, row.header_type));
        std::vector<uint64_t> storage = ring_entry(row.chunk);
        context.encoded_entry = reinterpret_cast<sendspin::AudioRingBufferEntry*>(storage.data());

        EXPECT_EQ(SyncTask::decode_whole_chunk(context), row.output_bytes != 0);
        EXPECT_EQ(context.decode_buffer->available(), row.output_bytes);
        if (row.header_type == sendspin::CHUNK_TYPE_FLAC_HEADER && row.output_bytes != 0) {
            const std::vector<uint8_t> pcm = flac_source_pcm();
            ASSERT_EQ(context.decode_buffer->available(), pcm.size());
            EXPECT_EQ(std::memcmp(context.decode_buffer->get_buffer_start(), pcm.data(), pcm.size()),
                      0);
        }
    }
}
