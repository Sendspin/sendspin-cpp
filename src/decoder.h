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

#pragma once

#include "audio_stream_info.h"
#include "platform/memory.h"
#include "sendspin/player_role.h"  // For ChunkType, DummyHeader, SendspinCodecFormat
#include <micro_flac/flac_decoder.h>
#include <opus.h>

#include <memory>

namespace sendspin {

class SendspinDecoder {
public:
    ~SendspinDecoder() {
        this->reset_decoders();
    }

    /// @brief Resets the state of the FLAC and Opus decoders
    void reset_decoders();

    /// @brief Sets up the appropriate decoder and processes the codec header (which may be a dummy
    /// header).
    /// @param data Pointer to the header data.
    /// @param data_size Size of the header data in bytes.
    /// @param chunk_type Type of header chunk.
    /// @param stream_info Pointer to AudioStreamInfo that will be filled out when decoding the
    /// header.
    /// @return True if successful, false otherwise.
    bool process_header(const uint8_t* data, size_t data_size, ChunkType chunk_type,
                        AudioStreamInfo* stream_info);

    /// @brief Decodes an encoded audio chunk into a caller-provided buffer.
    /// @param data Pointer to the encoded audio data.
    /// @param data_size Size of the encoded audio data in bytes.
    /// @param output_buffer Pointer to the buffer where decoded audio will be written.
    /// @param output_buffer_size Size of the output buffer in bytes.
    /// @param decoded_size Pointer to store the number of decoded bytes written.
    /// @return True if successful, false otherwise.
    bool decode_audio_chunk(const uint8_t* data, size_t data_size, uint8_t* output_buffer,
                            size_t output_buffer_size, size_t* decoded_size);

    /// @brief Returns the currently active codec format.
    /// @return The codec format in use for decoding.
    SendspinCodecFormat get_current_codec() const {
        return this->current_codec_;
    }

    /// @brief Returns the maximum number of bytes a single decoded frame can produce.
    /// @return Maximum decoded output size in bytes.
    size_t get_maximum_decoded_size() const {
        return this->maximum_decoded_size_;
    }

protected:
    /// @brief Parses a dummy (non-FLAC) codec header to extract stream parameters.
    /// @param data Pointer to the header data.
    /// @param data_size Size of the header data in bytes.
    /// @param stream_info [out] Populated with stream parameters on success.
    /// @return True if the header was valid and stream_info was populated, false otherwise.
    bool decode_dummy_header_(const uint8_t* data, size_t data_size, AudioStreamInfo* stream_info);

    // Struct fields
    AudioStreamInfo current_stream_info_;
    PlatformBuffer opus_decoder_buf_;

    // Pointer fields
    std::unique_ptr<micro_flac::FLACDecoder> flac_decoder_;

    // size_t fields
    size_t maximum_decoded_size_{0};

    // 32-bit fields
    SendspinCodecFormat current_codec_ = SendspinCodecFormat::UNSUPPORTED;
};

}  // namespace sendspin
