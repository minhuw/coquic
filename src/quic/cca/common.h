#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "src/quic/recovery.h"

namespace coquic::quic {

std::size_t congestion_initial_window(std::size_t max_datagram_size);
std::size_t congestion_saturating_add(std::size_t lhs, std::size_t rhs);
std::uint64_t congestion_saturating_add_u64(std::uint64_t lhs, std::size_t rhs);
double congestion_sample_bandwidth_bytes_per_second(
    const SentPacketRecord &packet, std::uint64_t delivered_bytes, QuicCoreTimePoint now,
    const std::optional<std::chrono::milliseconds> &min_rtt);
std::size_t congestion_clamp_to_size_t(double value);
std::size_t congestion_round_to_size_t(double value);

} // namespace coquic::quic
