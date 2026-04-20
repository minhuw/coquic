#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "src/quic/varint.h"

namespace coquic::http3::test {

quic::CodecResult<std::vector<std::byte>>
serialize_http3_payload_frame_with_synthetic_length_for_tests(std::uint64_t type,
                                                              std::size_t payload_size);

} // namespace coquic::http3::test
