#pragma once

#include <cstdint>
#include <optional>

#include "src/quic/codec/varint.h"

namespace coquic::quic {

inline constexpr std::uint64_t kMaxPacketNumber = (std::uint64_t{1} << 62) - 1;

CodecResult<std::uint32_t> truncate_packet_number(std::uint64_t packet_number,
                                                  std::uint8_t packet_number_length);

CodecResult<std::uint64_t>
recover_packet_number(std::optional<std::uint64_t> largest_authenticated_packet_number,
                      std::uint32_t truncated_packet_number, std::uint8_t packet_number_length);

} // namespace coquic::quic
