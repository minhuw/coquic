#include "src/quic/cca/common.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>

namespace coquic::quic {

namespace {

constexpr std::size_t kRecommendedInitialWindowUpperBound = 14720;
constexpr std::uint8_t kHyStartMinRttSamples = 8;
constexpr std::uint8_t kHyStartCssGrowthDivisor = 4;
constexpr std::uint8_t kHyStartCssRounds = 5;
constexpr std::size_t kHyStartNonPacedAckLimitPackets = 8;
constexpr std::chrono::milliseconds kHyStartMinRttThreshold{4};
constexpr std::chrono::milliseconds kHyStartMaxRttThreshold{16};
constexpr std::uint8_t kHyStartMinRttDivisor = 8;

} // namespace

HyStartPlusPlus::HyStartPlusPlus(std::size_t max_datagram_size)
    : max_datagram_size_(max_datagram_size) {
}

void HyStartPlusPlus::on_packet_sent(SentPacketRecord &packet) {
    if (!packet.ack_eliciting) {
        return;
    }

    packet.congestion_send_sequence = next_send_sequence_++;
    latest_sent_sequence_ = latest_sent_sequence_.has_value()
                                ? std::max(*latest_sent_sequence_, packet.congestion_send_sequence)
                                : packet.congestion_send_sequence;
}

std::size_t HyStartPlusPlus::growth_bytes(std::size_t newly_acked_bytes) const {
    const auto ack_limit = max_datagram_size_ > std::numeric_limits<std::size_t>::max() /
                                                    kHyStartNonPacedAckLimitPackets
                               ? std::numeric_limits<std::size_t>::max()
                               : kHyStartNonPacedAckLimitPackets * max_datagram_size_;
    const auto limited_acked_bytes = std::min(newly_acked_bytes, ack_limit);
    if (!enabled_ || mode_ != Mode::conservative_slow_start) {
        return limited_acked_bytes;
    }
    return limited_acked_bytes / kHyStartCssGrowthDivisor;
}

void HyStartPlusPlus::on_slow_start_ack(std::span<const SentPacketRecord> packets,
                                        const RecoveryRttState &rtt_state) {
    if (!enabled_ || !rtt_state.latest_rtt.has_value()) {
        return;
    }

    std::optional<std::uint64_t> largest_acked_send_sequence;
    for (const auto &packet : packets) {
        if (!packet.ack_eliciting || packet.app_limited || packet.congestion_send_sequence == 0) {
            continue;
        }
        largest_acked_send_sequence =
            largest_acked_send_sequence.has_value()
                ? std::max(*largest_acked_send_sequence, packet.congestion_send_sequence)
                : packet.congestion_send_sequence;
    }
    if (!largest_acked_send_sequence.has_value()) {
        return;
    }

    ensure_round_started(*largest_acked_send_sequence);
    current_round_min_rtt_ = current_round_min_rtt_.has_value()
                                 ? std::min(*current_round_min_rtt_, *rtt_state.latest_rtt)
                                 : *rtt_state.latest_rtt;
    if (rtt_sample_count_ != std::numeric_limits<std::uint8_t>::max()) {
        ++rtt_sample_count_;
    }

    if (mode_ == Mode::standard_slow_start) {
        maybe_enter_conservative_slow_start();
        maybe_finish_round(*largest_acked_send_sequence);
        return;
    }
    if (mode_ == Mode::conservative_slow_start) {
        maybe_resume_standard_slow_start();
        maybe_finish_round(*largest_acked_send_sequence);
        return;
    }
}

void HyStartPlusPlus::disable() {
    enabled_ = false;
    mode_ = Mode::standard_slow_start;
    exit_slow_start_ = false;
    css_entry_round_end_sequence_.reset();
    css_baseline_min_rtt_.reset();
    css_rounds_ = 0;
}

bool HyStartPlusPlus::should_exit_slow_start() const {
    return exit_slow_start_;
}

bool HyStartPlusPlus::in_conservative_slow_start() const {
    return enabled_ && mode_ == Mode::conservative_slow_start;
}

void HyStartPlusPlus::ensure_round_started(std::uint64_t largest_acked_send_sequence) {
    if (window_end_sequence_.has_value()) {
        return;
    }
    window_end_sequence_ = latest_sent_sequence_.has_value()
                               ? std::max(*latest_sent_sequence_, largest_acked_send_sequence)
                               : largest_acked_send_sequence;
}

void HyStartPlusPlus::maybe_enter_conservative_slow_start() {
    if (rtt_sample_count_ < kHyStartMinRttSamples || !current_round_min_rtt_.has_value() ||
        !last_round_min_rtt_.has_value()) {
        return;
    }

    const auto rtt_threshold =
        std::max(kHyStartMinRttThreshold,
                 std::min(*last_round_min_rtt_ / kHyStartMinRttDivisor, kHyStartMaxRttThreshold));
    if (*current_round_min_rtt_ < *last_round_min_rtt_ + rtt_threshold) {
        return;
    }

    mode_ = Mode::conservative_slow_start;
    css_baseline_min_rtt_ = current_round_min_rtt_;
    css_entry_round_end_sequence_ = window_end_sequence_;
    css_rounds_ = 1;
}

void HyStartPlusPlus::maybe_resume_standard_slow_start() {
    if (rtt_sample_count_ < kHyStartMinRttSamples || !current_round_min_rtt_.has_value() ||
        !css_baseline_min_rtt_.has_value()) {
        return;
    }
    if (*current_round_min_rtt_ >= *css_baseline_min_rtt_) {
        return;
    }

    mode_ = Mode::standard_slow_start;
    css_baseline_min_rtt_.reset();
    css_entry_round_end_sequence_.reset();
    css_rounds_ = 0;
}

void HyStartPlusPlus::maybe_finish_round(std::uint64_t largest_acked_send_sequence) {
    if (!window_end_sequence_.has_value() || largest_acked_send_sequence < *window_end_sequence_) {
        return;
    }

    const auto finished_round_end = *window_end_sequence_;
    start_new_round(finished_round_end);

    if (mode_ != Mode::conservative_slow_start) {
        return;
    }

    const bool finished_entry_round = css_entry_round_end_sequence_.has_value() &&
                                      *css_entry_round_end_sequence_ == finished_round_end;
    if (finished_entry_round) {
        css_entry_round_end_sequence_.reset();
        return;
    }

    if (css_rounds_ < std::numeric_limits<std::uint8_t>::max()) {
        ++css_rounds_;
    }
    if (css_rounds_ >= kHyStartCssRounds) {
        mode_ = Mode::congestion_avoidance;
        exit_slow_start_ = true;
    }
}

void HyStartPlusPlus::start_new_round(std::uint64_t finished_round_end) {
    last_round_min_rtt_ = current_round_min_rtt_;
    current_round_min_rtt_.reset();
    rtt_sample_count_ = 0;
    if (latest_sent_sequence_.has_value() && *latest_sent_sequence_ > finished_round_end) {
        window_end_sequence_ = latest_sent_sequence_;
    } else {
        window_end_sequence_.reset();
    }
}

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
