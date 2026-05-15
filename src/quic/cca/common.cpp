#include "src/quic/cca/common.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>

namespace coquic::quic {

namespace {

constexpr std::size_t kRecommendedInitialWindowUpperBound = 14720;

} // namespace

std::size_t congestion_initial_window(std::size_t max_datagram_size) {
    return std::min<std::size_t>(
        10 * max_datagram_size,
        std::max<std::size_t>(2 * max_datagram_size, kRecommendedInitialWindowUpperBound));
}

std::size_t congestion_saturating_add(std::size_t lhs, std::size_t rhs) {
    if (std::numeric_limits<std::size_t>::max() - lhs < rhs) {
        return std::numeric_limits<std::size_t>::max();
    }
    return lhs + rhs;
}

std::uint64_t congestion_saturating_add_u64(std::uint64_t lhs, std::size_t rhs) {
    if (std::numeric_limits<std::uint64_t>::max() - lhs < rhs) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return lhs + static_cast<std::uint64_t>(rhs);
}

double congestion_sample_bandwidth_bytes_per_second(
    const SentPacketRecord &packet, std::uint64_t delivered_bytes, QuicCoreTimePoint now,
    const std::optional<std::chrono::milliseconds> &min_rtt) {
    static_cast<void>(min_rtt);
    if (delivered_bytes <= packet.delivered) {
        return 0.0;
    }

    const auto send_elapsed = packet.sent_time > packet.first_sent_time
                                  ? packet.sent_time - packet.first_sent_time
                                  : QuicCoreClock::duration::zero();
    const auto ack_elapsed =
        now > packet.delivered_time ? now - packet.delivered_time : QuicCoreClock::duration::zero();
    const auto interval = std::max(send_elapsed, ack_elapsed);
    const auto interval_seconds = std::chrono::duration<double>(interval).count();
    if (interval_seconds <= 0.0) {
        return 0.0;
    }

    return static_cast<double>(delivered_bytes - packet.delivered) / interval_seconds;
}

std::size_t congestion_clamp_to_size_t(double value) {
    if (!(value > 0.0)) {
        return 0;
    }
    const auto maximum = static_cast<double>(std::numeric_limits<std::size_t>::max());
    if (value >= maximum) {
        return std::numeric_limits<std::size_t>::max();
    }
    return static_cast<std::size_t>(value);
}

std::size_t congestion_round_to_size_t(double value) {
    if (!(value > 0.0)) {
        return 0;
    }
    const auto maximum = static_cast<double>(std::numeric_limits<std::size_t>::max());
    if (value >= maximum) {
        return std::numeric_limits<std::size_t>::max();
    }
    return static_cast<std::size_t>(std::llround(value));
}

} // namespace coquic::quic
