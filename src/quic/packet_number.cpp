#include "src/quic/packet_number.h"

namespace coquic::quic {

namespace {

constexpr std::uint64_t kMaxPacketNumber = (std::uint64_t{1} << 62) - 1;
constexpr std::uint64_t kPacketNumberSpaceSize = std::uint64_t{1} << 62;

bool valid_packet_number_length(std::uint8_t packet_number_length) {
    return packet_number_length >= 1 && packet_number_length <= 4;
}

std::uint64_t packet_number_mask(std::uint8_t packet_number_length) {
    if (packet_number_length == 4) {
        return 0xffffffffULL;
    }

    return (std::uint64_t{1} << (packet_number_length * 8)) - 1;
}

bool valid_truncated_packet_number(std::uint32_t truncated_packet_number,
                                   std::uint8_t packet_number_length) {
    return (static_cast<std::uint64_t>(truncated_packet_number) &
            ~packet_number_mask(packet_number_length)) == 0;
}

} // namespace

CodecResult<std::uint32_t> truncate_packet_number(std::uint64_t packet_number,
                                                  std::uint8_t packet_number_length) {
    if (!valid_packet_number_length(packet_number_length)) {
        return CodecResult<std::uint32_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    return CodecResult<std::uint32_t>::success(
        static_cast<std::uint32_t>(packet_number & packet_number_mask(packet_number_length)));
}

CodecResult<std::uint64_t>
recover_packet_number(std::optional<std::uint64_t> largest_authenticated_packet_number,
                      std::uint32_t truncated_packet_number, std::uint8_t packet_number_length) {
    if (!valid_packet_number_length(packet_number_length)) {
        return CodecResult<std::uint64_t>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (!valid_truncated_packet_number(truncated_packet_number, packet_number_length)) {
        return CodecResult<std::uint64_t>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (largest_authenticated_packet_number.has_value() &&
        largest_authenticated_packet_number.value() > kMaxPacketNumber) {
        return CodecResult<std::uint64_t>::failure(CodecErrorCode::packet_number_recovery_failed,
                                                   0);
    }

    const auto expected_packet_number = largest_authenticated_packet_number.has_value()
                                            ? (largest_authenticated_packet_number.value() + 1)
                                            : 0;
    const auto packet_number_window = std::uint64_t{1} << (packet_number_length * 8);
    const auto packet_number_half_window = packet_number_window / 2;
    const auto packet_number_window_mask = packet_number_window - 1;
    const auto candidate_packet_number =
        (expected_packet_number & ~packet_number_window_mask) | truncated_packet_number;

    if (expected_packet_number >= packet_number_half_window &&
        candidate_packet_number <= expected_packet_number - packet_number_half_window &&
        candidate_packet_number < kPacketNumberSpaceSize - packet_number_window) {
        return CodecResult<std::uint64_t>::success(candidate_packet_number + packet_number_window);
    }
    if (candidate_packet_number > expected_packet_number + packet_number_half_window &&
        candidate_packet_number >= packet_number_window) {
        return CodecResult<std::uint64_t>::success(candidate_packet_number - packet_number_window);
    }

    return CodecResult<std::uint64_t>::success(candidate_packet_number);
}

} // namespace coquic::quic
