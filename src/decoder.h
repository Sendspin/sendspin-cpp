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

/// @file decoder.h
/// @brief Audio decoder wrapper supporting FLAC, Opus, and raw PCM codec formats

#pragma once

#include "audio_stream_info.h"
#include "audio_types.h"
#include "platform/memory.h"
#include "sendspin/player_role.h"  // For SendspinCodecFormat
#include <micro_flac/flac_decoder.h>
#include <opus.h>

#include <memory>

namespace sendspin {

/**
 * @brief Audio decoder wrapper supporting FLAC, Opus, and raw PCM codec formats
 *
 * Manages codec state for a single active stream. The caller first passes a header chunk
 * via process_header() to initialize the decoder and populate an AudioStreamInfo, then
 * calls decode_audio_chunk() for each subsequent encoded chunk. FLAC uses micro_flac,
 * Opus uses libopus. PCM and dummy headers bypass decoding and copy data directly.
 *
 * Usage:
 * 1. Call process_header() with the first chunk to initialize the codec and stream info
 * 2. Allocate an output buffer of at least get_decode_buffer_size() bytes
 * 3. Call decode_audio_chunk() for each encoded chunk to fill the output buffer. For Opus this
 *    estimate can grow mid-stream: if decode_audio_chunk() returns false and
 *    get_decode_buffer_size() has increased, enlarge the buffer to the new size and call again.
 * 4. Call reset_decoders() when the stream ends or a new stream starts
 *
 * @code
 * SendspinDecoder decoder;
 * AudioStreamInfo stream_info;
 *
 * decoder.process_header(header_data, header_size, CHUNK_TYPE_FLAC_HEADER, &stream_info);
 *
 * std::vector<uint8_t> output(decoder.get_decode_buffer_size());
 * size_t decoded_size = 0;
 * decoder.decode_audio_chunk(encoded_data, encoded_size,
 *                            output.data(), output.size(), &decoded_size);
 * @endcode
 */
class SendspinDecoder {
public:
    ~SendspinDecoder() {
        this->reset_decoders();
    }

    /// @brief Resets the state of the FLAC and Opus decoders
    void reset_decoders();

    /// @brief Sets up the appropriate decoder and processes the codec header (which may be a dummy
    /// header)
    /// @param data Pointer to the header data.
    /// @param data_size Size of the header data in bytes.
    /// @param chunk_type Type of header chunk.
    /// @param[out] stream_info Pointer to AudioStreamInfo that will be filled out when decoding the
    /// header.
    /// @return True if successful, false otherwise.
    bool process_header(const uint8_t* data, size_t data_size, ChunkType chunk_type,
                        AudioStreamInfo* stream_info);

    /// @brief Decodes an encoded audio chunk into a caller-provided buffer.
    /// @param data Pointer to the encoded audio data.
    /// @param data_size Size of the encoded audio data in bytes.
    /// @param output_buffer Pointer to the buffer where decoded audio will be written.
    /// @param output_buffer_size Size of the output buffer in bytes.
    /// @param[out] decoded_size Pointer to store the number of decoded bytes written.
    /// @return True if successful, false otherwise. For Opus, a false return may simply mean the
    /// chunk decodes to more than output_buffer_size bytes; in that case get_decode_buffer_size()
    /// has increased, so resize output_buffer to it and call again.
    bool decode_audio_chunk(const uint8_t* data, size_t data_size, uint8_t* output_buffer,
                            size_t output_buffer_size, size_t* decoded_size);

    /// @brief Returns the currently active codec format.
    /// @return The codec format in use for decoding.
    SendspinCodecFormat get_current_codec() const {
        return this->current_codec_;
    }

    /// @brief Returns the size to allocate for the decoded-output buffer.
    /// @details For FLAC and PCM this is a fixed upper bound. For Opus it starts at the common 20ms
    /// frame size and grows (up to the 120ms spec maximum) when decode_audio_chunk() meets a larger
    /// packet; that call returns false until the caller resizes its buffer to the new value.
    /// @return Required decoded-output buffer size in bytes.
    size_t get_decode_buffer_size() const {
        return this->decode_buffer_size_;
    }

    // ========================================
    // Internal helpers
    // ========================================
protected:
    /// @brief Parses a dummy (non-FLAC) codec header to extract stream parameters.
    /// @param data Pointer to the header data.
    /// @param data_size Size of the header data in bytes.
    /// @param[out] stream_info Populated with stream parameters on success.
    /// @return True if the header was valid and stream_info was populated, false otherwise.
    bool decode_dummy_header(const uint8_t* data, size_t data_size, AudioStreamInfo* stream_info);

    // Struct fields
    AudioStreamInfo current_stream_info_;
    PlatformBuffer opus_decoder_buf_;

    // Pointer fields
    std::unique_ptr<micro_flac::FLACDecoder> flac_decoder_;

    // size_t fields
    size_t decode_buffer_size_{0};

    // 32-bit fields
    SendspinCodecFormat current_codec_ = SendspinCodecFormat::UNSUPPORTED;
};

}  // namespace sendspin
