#include "src/quic/cca/cubic.h"

#include <algorithm>
#include <cmath>

namespace coquic::quic {

namespace {

constexpr double kCubicBeta = 0.7;
constexpr double kCubicC = 0.4;
constexpr double kCubicPacingGain = 1.25;
constexpr double kCubicSlowStartPacingGain = 2.0;
constexpr std::size_t kPacingStartStreamBytes = std::size_t{32} * 1024;

} // namespace

CubicCongestionController::CubicCongestionController(std::size_t max_datagram_size,
                                                     bool enable_hystart_plus_plus)
    : max_datagram_size_(max_datagram_size),
      congestion_window_(congestion_initial_window(max_datagram_size)),
      cwnd_prior_segments_(smss_segments(congestion_window_)),
      w_max_segments_(cwnd_prior_segments_), w_est_segments_(cwnd_prior_segments_),
      hystart_(max_datagram_size, enable_hystart_plus_plus) {
}

bool CubicCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    return bytes_in_flight_ + bytes <= congestion_window_;
}

std::optional<QuicCoreTimePoint>
CubicCongestionController::next_send_time(std::size_t bytes) const {
    if (bytes == 0 || !pacing_budget_timestamp_.has_value()) {
        return std::nullopt;
    }
    const auto pacing_budget_timestamp = *pacing_budget_timestamp_;
    if (!can_send_ack_eliciting(bytes)) {
        return std::nullopt;
    }

    const auto budget = std::min(pacing_budget_bytes_, pacing_budget_cap());
    if (bytes <= budget) {
        return pacing_budget_timestamp;
    }
    if (pacing_rate_bytes_per_second_ <= 0.0) {
        return std::nullopt;
    }

    return pacing_budget_timestamp +
           congestion_pacing_delay_for_deficit(bytes - budget, pacing_rate_bytes_per_second_);
}

void CubicCongestionController::on_packet_sent(std::size_t bytes_sent, bool ack_eliciting) {
    if (!ack_eliciting) {
        return;
    }

    bytes_in_flight_ += bytes_sent;
}

void CubicCongestionController::on_packet_sent(SentPacketRecord &packet) {
    if (!packet.ack_eliciting) {
        return;
    }

    hystart_.on_packet_sent(packet);
    on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
    consume_pacing_budget(packet.bytes_in_flight, packet.sent_time);
}

void CubicCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                 bool app_limited) {
    on_packets_acked(packets, app_limited, QuicCoreTimePoint{},
                     RecoveryRttState{.smoothed_rtt = kInitialRtt});
}

void CubicCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                 bool app_limited, QuicCoreTimePoint now,
                                                 const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    const auto recovery_boundary = recovery_start_time_;
    bool exit_recovery = false;
    std::size_t slow_start_acked_bytes = 0;

    for (const auto &packet : packets) {
        if (packet.in_flight) {
            bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                                   ? 0
                                   : bytes_in_flight_ - packet.bytes_in_flight;
        }

        const bool in_batch_recovery =
            recovery_boundary.has_value() && packet.sent_time <= *recovery_boundary;
        if (packet.ack_eliciting && recovery_boundary.has_value() && !in_batch_recovery) {
            exit_recovery = true;
        }
        if (sent_packet_has_stream_frames(packet)) {
            acked_stream_bytes_for_pacing_ =
                congestion_saturating_add(acked_stream_bytes_for_pacing_, packet.bytes_in_flight);
        }

        if (!packet.ack_eliciting || in_batch_recovery || packet.app_limited) {
            continue;
        }

        if (app_limited_start_time_.has_value()) {
            app_limited_pause_ +=
                std::chrono::duration_cast<QuicCoreDuration>(now - *app_limited_start_time_);
            app_limited_start_time_.reset();
        }

        if (congestion_window_ < slow_start_threshold_) {
            slow_start_acked_bytes =
                congestion_saturating_add(slow_start_acked_bytes, packet.bytes_in_flight);
            continue;
        }

        grow_congestion_avoidance(packet.bytes_in_flight, now, rtt_state);
    }

    if (slow_start_acked_bytes != 0) {
        congestion_window_ = congestion_saturating_add(
            congestion_window_, hystart_.growth_bytes(slow_start_acked_bytes));
        epoch_start_time_.reset();
        cwnd_prior_segments_ = smss_segments(congestion_window_);
        w_est_segments_ = cwnd_prior_segments_;
        hystart_.on_slow_start_ack(packets, rtt_state);
        if (hystart_.should_exit_slow_start()) {
            enter_congestion_avoidance_from_slow_start(now);
        }
    }

    if (!packets.empty() && epoch_start_time_.has_value() && !app_limited_start_time_.has_value()) {
        const auto all_growth_suppressed =
            std::all_of(packets.begin(), packets.end(), [&](const SentPacketRecord &packet) {
                const bool in_batch_recovery =
                    recovery_boundary.has_value() && packet.sent_time <= *recovery_boundary;
                return !packet.ack_eliciting || in_batch_recovery || packet.app_limited;
            });
        if (all_growth_suppressed) {
            app_limited_start_time_ = now;
        }
    }

    if (exit_recovery) {
        recovery_start_time_ = std::nullopt;
    }

    update_pacing_rate(rtt_state);
    if (!pacing_budget_timestamp_.has_value() && should_start_pacing(packets) &&
        now != QuicCoreTimePoint{} && pacing_rate_bytes_per_second_ > 0.0) {
        pacing_budget_timestamp_ = now;
        pacing_budget_bytes_ = pacing_budget_cap();
    }
}

void CubicCongestionController::on_simple_stream_packets_acked(
    std::span<const AckedStreamPacketSample> packets, bool app_limited, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    if (packets.empty()) {
        update_pacing_rate(rtt_state);
        return;
    }

    const auto recovery_boundary = recovery_start_time_;
    bool exit_recovery = false;
    bool all_growth_suppressed = true;
    std::size_t acked_bytes = 0;
    std::size_t slow_start_acked_bytes = 0;

    for (const auto &packet : packets) {
        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
        acked_bytes = congestion_saturating_add(acked_bytes, packet.bytes_in_flight);

        const bool in_batch_recovery =
            recovery_boundary.has_value() && packet.sent_time <= *recovery_boundary;
        if (recovery_boundary.has_value() && !in_batch_recovery) {
            exit_recovery = true;
        }
        if (in_batch_recovery) {
            continue;
        }

        all_growth_suppressed = false;
        if (app_limited_start_time_.has_value()) {
            app_limited_pause_ +=
                std::chrono::duration_cast<QuicCoreDuration>(now - *app_limited_start_time_);
            app_limited_start_time_.reset();
        }

        if (congestion_window_ < slow_start_threshold_) {
            slow_start_acked_bytes =
                congestion_saturating_add(slow_start_acked_bytes, packet.bytes_in_flight);
            continue;
        }

        grow_congestion_avoidance(packet.bytes_in_flight, now, rtt_state);
    }

    acked_stream_bytes_for_pacing_ =
        congestion_saturating_add(acked_stream_bytes_for_pacing_, acked_bytes);
    if (slow_start_acked_bytes != 0) {
        congestion_window_ = congestion_saturating_add(
            congestion_window_, hystart_.growth_bytes(slow_start_acked_bytes));
        epoch_start_time_.reset();
        cwnd_prior_segments_ = smss_segments(congestion_window_);
        w_est_segments_ = cwnd_prior_segments_;
        hystart_.on_slow_start_ack(packets, rtt_state);
        if (hystart_.should_exit_slow_start()) {
            enter_congestion_avoidance_from_slow_start(now);
        }
    }

    if (epoch_start_time_.has_value() && !app_limited_start_time_.has_value() &&
        all_growth_suppressed) {
        app_limited_start_time_ = now;
    }

    if (exit_recovery) {
        recovery_start_time_ = std::nullopt;
    }

    update_pacing_rate(rtt_state);
    if (!pacing_budget_timestamp_.has_value() &&
        acked_stream_bytes_for_pacing_ >= kPacingStartStreamBytes && now != QuicCoreTimePoint{} &&
        pacing_rate_bytes_per_second_ > 0.0) {
        pacing_budget_timestamp_ = now;
        pacing_budget_bytes_ = pacing_budget_cap();
    }
}

void CubicCongestionController::on_packets_discarded(std::span<const SentPacketRecord> packets) {
    for (const auto &packet : packets) {
        if (!packet.in_flight) {
            continue;
        }

        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
    }
}

void CubicCongestionController::on_packets_lost(std::span<const SentPacketRecord> packets) {
    for (const auto &packet : packets) {
        if (!packet.in_flight) {
            continue;
        }

        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
    }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void CubicCongestionController::on_loss_event(QuicCoreTimePoint loss_detection_time,
                                              QuicCoreTimePoint largest_lost_sent_time) {
    if (recovery_start_time_.has_value() && largest_lost_sent_time <= *recovery_start_time_) {
        return;
    }

    const auto current_window_segments = smss_segments(congestion_window_);
    if (current_window_segments < w_max_segments_) {
        w_max_segments_ = current_window_segments * (1.0 + kCubicBeta) / 2.0;
    } else {
        w_max_segments_ = current_window_segments;
    }

    hystart_.disable();
    recovery_start_time_ = loss_detection_time;
    cwnd_prior_segments_ = current_window_segments;
    congestion_avoidance_credit_segments_ *= kCubicBeta;
    const auto reduced_window = bytes_from_segments(current_window_segments * kCubicBeta);
    slow_start_threshold_ = std::max(minimum_window(), reduced_window);
    congestion_window_ = slow_start_threshold_;
    reset_epoch(loss_detection_time);
}

void CubicCongestionController::on_persistent_congestion() {
    hystart_.disable();
    congestion_window_ = minimum_window();
    slow_start_threshold_ = congestion_window_;
    w_max_segments_ = smss_segments(congestion_window_);
    cwnd_prior_segments_ = w_max_segments_;
    congestion_avoidance_credit_segments_ = 0.0;
    reset_epoch(QuicCoreTimePoint{});
}

std::size_t CubicCongestionController::congestion_window() const {
    return congestion_window_;
}

std::size_t CubicCongestionController::bytes_in_flight() const {
    return bytes_in_flight_;
}

std::size_t CubicCongestionController::minimum_window() const {
    return 2 * max_datagram_size_;
}

bool CubicCongestionController::pacing_active() const {
    return pacing_budget_timestamp_.has_value();
}

void CubicCongestionController::update_pacing_rate(const RecoveryRttState &rtt_state) {
    if (rtt_state.smoothed_rtt.count() > 0) {
        pacing_smoothed_rtt_ = rtt_state.smoothed_rtt;
    }

    const auto rtt_seconds = std::chrono::duration<double>(pacing_smoothed_rtt_).count();
    if (rtt_seconds <= 0.0) {
        pacing_rate_bytes_per_second_ = 0.0;
        return;
    }
    const auto gain =
        congestion_window_ < slow_start_threshold_ ? kCubicSlowStartPacingGain : kCubicPacingGain;
    pacing_rate_bytes_per_second_ = gain * static_cast<double>(congestion_window_) / rtt_seconds;
}

bool CubicCongestionController::should_start_pacing(
    std::span<const SentPacketRecord> packets) const {
    if (acked_stream_bytes_for_pacing_ >= kPacingStartStreamBytes) {
        return true;
    }
    return std::ranges::any_of(packets, [](const SentPacketRecord &packet) {
        return packet.bytes_in_flight >= kPacingStartStreamBytes &&
               sent_packet_has_stream_frames(packet);
    });
}

std::size_t CubicCongestionController::pacing_budget_cap() const {
    return congestion_quinn_pacing_budget_cap(congestion_window_, max_datagram_size_,
                                              pacing_smoothed_rtt_);
}

std::size_t CubicCongestionController::pacing_budget_at(QuicCoreTimePoint now) const {
    const auto cap = pacing_budget_cap();
    if (!pacing_budget_timestamp_.has_value()) {
        return cap;
    }

    auto budget = std::min(pacing_budget_bytes_, cap);
    if (now <= *pacing_budget_timestamp_) {
        return budget;
    }
    if (pacing_rate_bytes_per_second_ <= 0.0) {
        return cap;
    }

    const auto missing_budget = cap - budget;
    const auto replenished = congestion_pacing_replenished_bytes(now - *pacing_budget_timestamp_,
                                                                 pacing_rate_bytes_per_second_);
    if (replenished >= missing_budget) {
        return cap;
    }
    return budget + replenished;
}

void CubicCongestionController::consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now) {
    if (!pacing_active()) {
        return;
    }

    const auto budget = pacing_budget_at(now);
    pacing_budget_bytes_ = bytes >= budget ? 0 : budget - bytes;
    pacing_budget_timestamp_ = now;
}

bool CubicCongestionController::in_recovery(const SentPacketRecord &packet) const {
    return recovery_start_time_.has_value() && packet.sent_time <= *recovery_start_time_;
}

void CubicCongestionController::reset_epoch(QuicCoreTimePoint now) {
    epoch_start_time_ = now == QuicCoreTimePoint{} ? std::nullopt : std::optional{now};
    app_limited_pause_ = QuicCoreDuration{0};
    app_limited_start_time_.reset();
    const auto cwnd_epoch = smss_segments(congestion_window_);
    w_est_segments_ = cwnd_epoch;
    if (w_max_segments_ > cwnd_epoch) {
        k_seconds_ = std::cbrt((w_max_segments_ - cwnd_epoch) / kCubicC);
    } else {
        k_seconds_ = 0.0;
    }
}

void CubicCongestionController::enter_congestion_avoidance_from_slow_start(QuicCoreTimePoint now) {
    slow_start_threshold_ = congestion_window_;
    w_max_segments_ = smss_segments(congestion_window_);
    cwnd_prior_segments_ = w_max_segments_;
    w_est_segments_ = w_max_segments_;
    congestion_avoidance_credit_segments_ = 0.0;
    reset_epoch(now);
}

double CubicCongestionController::smss_segments(std::size_t bytes) const {
    return static_cast<double>(bytes) / static_cast<double>(max_datagram_size_);
}

std::size_t CubicCongestionController::bytes_from_segments(double segments) const {
    return congestion_round_to_size_t(segments * static_cast<double>(max_datagram_size_));
}

double CubicCongestionController::reno_alpha() const {
    return w_est_segments_ >= cwnd_prior_segments_ ? 1.0
                                                   : 3.0 * (1.0 - kCubicBeta) / (1.0 + kCubicBeta);
}

double CubicCongestionController::target_window_segments(QuicCoreTimePoint now,
                                                         const RecoveryRttState &rtt_state) const {
    const auto current_window = smss_segments(congestion_window_);
    const auto epoch = epoch_start_time_.value_or(now);
    const auto elapsed = now > epoch ? now - epoch : QuicCoreClock::duration::zero();
    const auto active_elapsed = elapsed > app_limited_pause_ ? elapsed - app_limited_pause_
                                                             : QuicCoreClock::duration::zero();
    const auto rtt = rtt_state.smoothed_rtt.count() > 0 ? rtt_state.smoothed_rtt : kInitialRtt;
    const auto t_seconds = std::chrono::duration<double>(active_elapsed + rtt).count();
    const auto offset = t_seconds - k_seconds_;
    const auto cubic_window = (kCubicC * offset * offset * offset) + w_max_segments_;
    return std::clamp(cubic_window, current_window, current_window * 1.5);
}

double CubicCongestionController::update_reno_estimate(double acked_segments) {
    const auto current_window = std::max(1.0, smss_segments(congestion_window_));
    w_est_segments_ += reno_alpha() * acked_segments / current_window;
    return w_est_segments_;
}

void CubicCongestionController::grow_congestion_avoidance(std::size_t acked_bytes,
                                                          QuicCoreTimePoint now,
                                                          const RecoveryRttState &rtt_state) {
    if (!epoch_start_time_.has_value()) {
        reset_epoch(now);
    }

    const auto current_window = smss_segments(congestion_window_);
    const auto acked_segments = smss_segments(acked_bytes);
    const auto reno_window = update_reno_estimate(acked_segments);
    const auto cubic_target = target_window_segments(now, rtt_state);
    const auto target = std::max(reno_window, cubic_target);
    if (!(target > current_window)) {
        return;
    }

    const auto increment_segments =
        std::max(0.0, (target - current_window) * acked_segments / std::max(1.0, current_window));
    if (!(increment_segments > 0.0)) {
        return;
    }

    congestion_avoidance_credit_segments_ += increment_segments;
    if (congestion_avoidance_credit_segments_ < 1.0) {
        return;
    }

    const auto whole_segments = std::floor(congestion_avoidance_credit_segments_);
    congestion_avoidance_credit_segments_ -= whole_segments;
    const auto increment = bytes_from_segments(whole_segments);
    congestion_window_ =
        congestion_saturating_add(congestion_window_, std::max<std::size_t>(1, increment));
}

} // namespace coquic::quic
