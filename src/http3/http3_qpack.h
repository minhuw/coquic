#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "src/http3/http3.h"
#include "src/quic/varint.h"

namespace coquic::http3 {

struct Http3QpackSettings {
    std::uint64_t max_table_capacity = 0;
    std::uint64_t blocked_streams = 0;
};

quic::CodecResult<std::vector<std::byte>>
encode_http3_field_section(std::span<const Http3Field> fields);
Http3Result<Http3Headers> decode_http3_field_section(std::span<const std::byte> bytes);
Http3Result<bool> validate_http3_qpack_encoder_stream(std::span<const std::byte> bytes,
                                                      const Http3QpackSettings &settings);
Http3Result<bool> validate_http3_qpack_decoder_stream(std::span<const std::byte> bytes,
                                                      const Http3QpackSettings &settings);

} // namespace coquic::http3
