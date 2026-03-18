#pragma once

#include <cstdint>
#include <optional>

#include "src/quic/varint.h"

namespace coquic::quic {

CodecResult<std::uint32_t> truncate_packet_number(std::uint64_t packet_number,
                                                  std::uint8_t packet_number_length);

CodecResult<std::uint64_t>
recover_packet_number(std::optional<std::uint64_t> largest_authenticated_packet_number,
                      std::uint32_t truncated_packet_number, std::uint8_t packet_number_length);

} // namespace coquic::quic
