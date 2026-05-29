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
constexpr QuicCoreDuration kHyStartMinRttThreshold{4000};
constexpr QuicCoreDuration kHyStartMaxRttThreshold{16000};
constexpr std::uint8_t kHyStartMinRttDivisor = 8;
constexpr QuicCoreDuration kQuinnPacingBurstInterval{2000};
constexpr std::size_t kQuinnPacingMaximumBurstPackets = 256;

} // namespace

HyStartPlusPlus::HyStartPlusPlus(std::size_t max_datagram_size, bool enabled)
    : max_datagram_size_(max_datagram_size), enabled_(enabled) {
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
    if (!enabled_ || mode_ != Mode::conservative_slow_start) {
        return newly_acked_bytes;
    }
    const auto ack_limit = max_datagram_size_ > std::numeric_limits<std::size_t>::max() /
                                                    kHyStartNonPacedAckLimitPackets
                               ? std::numeric_limits<std::size_t>::max()
                               : kHyStartNonPacedAckLimitPackets * max_datagram_size_;
    const auto limited_acked_bytes = std::min(newly_acked_bytes, ack_limit);
    return limited_acked_bytes / kHyStartCssGrowthDivisor;
}

void HyStartPlusPlus::on_slow_start_ack(std::span<const SentPacketRecord> packets,
                                        const RecoveryRttState &rtt_state) {
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
    on_slow_start_ack_sequence(largest_acked_send_sequence, rtt_state);
}

void HyStartPlusPlus::on_slow_start_ack(std::span<const AckedStreamPacketSample> packets,
                                        const RecoveryRttState &rtt_state) {
    std::optional<std::uint64_t> largest_acked_send_sequence;
    for (const auto &packet : packets) {
        if (packet.congestion_send_sequence == 0) {
            continue;
        }
        largest_acked_send_sequence =
            largest_acked_send_sequence.has_value()
                ? std::max(*largest_acked_send_sequence, packet.congestion_send_sequence)
                : packet.congestion_send_sequence;
    }
    on_slow_start_ack_sequence(largest_acked_send_sequence, rtt_state);
}

void HyStartPlusPlus::on_slow_start_ack_sequence(
    std::optional<std::uint64_t> largest_acked_send_sequence, const RecoveryRttState &rtt_state) {
    if (!enabled_ || !rtt_state.latest_rtt.has_value() ||
        !largest_acked_send_sequence.has_value()) {
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

std::optional<std::uint64_t> HyStartPlusPlus::latest_sent_sequence() const {
    return latest_sent_sequence_;
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

double
congestion_sample_bandwidth_bytes_per_second(const SentPacketRecord &packet,
                                             std::uint64_t delivered_bytes, QuicCoreTimePoint now,
                                             const std::optional<QuicCoreDuration> &min_rtt) {
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

QuicCoreClock::duration congestion_pacing_delay_for_deficit(std::size_t deficit_bytes,
                                                            double rate_bytes_per_second) {
    if (deficit_bytes == 0 || rate_bytes_per_second <= 0.0) {
        return QuicCoreClock::duration::zero();
    }

    constexpr double kClockTicksPerSecond =
        static_cast<double>(QuicCoreClock::duration::period::den) /
        static_cast<double>(QuicCoreClock::duration::period::num);
    const auto delay_ticks = std::ceil(static_cast<double>(deficit_bytes) * kClockTicksPerSecond /
                                       rate_bytes_per_second);
    using TickRep = QuicCoreClock::duration::rep;
    if (delay_ticks >= static_cast<double>(std::numeric_limits<TickRep>::max())) {
        return QuicCoreClock::duration::max();
    }
    return QuicCoreClock::duration{static_cast<TickRep>(delay_ticks)};
}

std::size_t congestion_pacing_replenished_bytes(QuicCoreClock::duration elapsed,
                                                double rate_bytes_per_second) {
    if (elapsed <= QuicCoreClock::duration::zero() || rate_bytes_per_second <= 0.0) {
        return 0;
    }

    constexpr double kClockTicksPerSecond =
        static_cast<double>(QuicCoreClock::duration::period::den) /
        static_cast<double>(QuicCoreClock::duration::period::num);
    const auto replenished =
        (static_cast<double>(elapsed.count()) * rate_bytes_per_second) / kClockTicksPerSecond;
    return congestion_clamp_to_size_t(replenished);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::size_t congestion_quinn_pacing_budget_cap(std::size_t congestion_window,
                                               std::size_t max_datagram_size,
                                               QuicCoreDuration smoothed_rtt,
                                               std::size_t minimum_burst_packets) {
    if (max_datagram_size == 0) {
        return 0;
    }

    const auto minimum =
        minimum_burst_packets > std::numeric_limits<std::size_t>::max() / max_datagram_size
            ? std::numeric_limits<std::size_t>::max()
            : minimum_burst_packets * max_datagram_size;
    const auto maximum = kQuinnPacingMaximumBurstPackets * max_datagram_size;
    if (congestion_window == 0 || smoothed_rtt.count() <= 0) {
        return maximum;
    }

    const auto capacity = static_cast<double>(congestion_window) *
                          std::chrono::duration<double>(kQuinnPacingBurstInterval).count() /
                          std::chrono::duration<double>(smoothed_rtt).count();
    return std::clamp(congestion_clamp_to_size_t(capacity), minimum, maximum);
}

} // namespace coquic::quic
