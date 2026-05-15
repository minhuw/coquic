#include "src/quic/cca/copa.h"

#include <algorithm>
#include <chrono>
#include <cmath>

#include "src/quic/cca/common.h"

namespace coquic::quic {

namespace {

constexpr double kCopaLossReductionFactor = 0.7;
constexpr double kCopaPacingGain = 2.0;

std::chrono::milliseconds positive_rtt(std::chrono::milliseconds value) {
    return value.count() > 0 ? value : kGranularity;
}

} // namespace

CopaCongestionController::CopaCongestionController(std::size_t max_datagram_size)
    : max_datagram_size_(max_datagram_size),
      congestion_window_(congestion_initial_window(max_datagram_size)),
      send_quantum_(std::max<std::size_t>(2 * max_datagram_size, max_datagram_size)) {
    latest_rtt_ = kInitialRtt;
    min_rtt_ = kInitialRtt;
    set_pacing_rate();
}

bool CopaCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    return bytes_in_flight_ + bytes <= congestion_window_;
}

std::optional<QuicCoreTimePoint> CopaCongestionController::next_send_time(std::size_t bytes) const {
    if (bytes == 0 || !pacing_budget_timestamp_.has_value()) {
        return std::nullopt;
    }
    if (!can_send_ack_eliciting(bytes)) {
        return std::nullopt;
    }

    const auto budget = std::min(pacing_budget_bytes_, pacing_budget_cap());
    if (bytes <= budget) {
        return pacing_budget_timestamp_;
    }
    if (pacing_rate_bytes_per_second_ <= 0.0) {
        return std::nullopt;
    }

    const auto deficit = static_cast<double>(bytes - budget);
    const auto delay = std::chrono::ceil<QuicCoreClock::duration>(
        std::chrono::duration<double>(deficit / pacing_rate_bytes_per_second_));
    return *pacing_budget_timestamp_ + delay;
}

void CopaCongestionController::on_packet_sent(std::size_t bytes_sent, bool ack_eliciting) {
    if (!ack_eliciting) {
        return;
    }
    bytes_in_flight_ = congestion_saturating_add(bytes_in_flight_, bytes_sent);
}

void CopaCongestionController::on_packet_sent(SentPacketRecord &packet) {
    if (!packet.ack_eliciting) {
        return;
    }
    on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
    consume_pacing_budget(packet.bytes_in_flight, packet.sent_time);
}

void CopaCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                bool app_limited) {
    on_packets_acked(packets, app_limited, QuicCoreTimePoint{}, RecoveryRttState{});
}

void CopaCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                bool app_limited, QuicCoreTimePoint now,
                                                const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    const auto recovery_boundary = recovery_start_time_;
    bool exit_recovery = false;
    std::size_t acked_bytes = 0;

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
        if (!packet.ack_eliciting || in_batch_recovery || packet.app_limited) {
            continue;
        }
        acked_bytes = congestion_saturating_add(acked_bytes, packet.bytes_in_flight);
    }

    update_rtt_model(rtt_state);
    if (acked_bytes == 0 || !latest_rtt_.has_value()) {
        if (exit_recovery) {
            recovery_start_time_.reset();
        }
        return;
    }

    const auto target = target_window();
    if (slow_start_) {
        grow_slow_start(acked_bytes, target);
    } else {
        adjust_congestion_avoidance(acked_bytes, target, now);
    }
    set_pacing_rate();

    if (exit_recovery) {
        recovery_start_time_.reset();
    }
}

void CopaCongestionController::on_packets_discarded(std::span<const SentPacketRecord> packets) {
    subtract_in_flight(packets);
}

void CopaCongestionController::on_packets_lost(std::span<const SentPacketRecord> packets) {
    subtract_in_flight(packets);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void CopaCongestionController::on_loss_event(QuicCoreTimePoint loss_detection_time,
                                             QuicCoreTimePoint largest_lost_sent_time) {
    if (recovery_start_time_.has_value() && largest_lost_sent_time <= *recovery_start_time_) {
        return;
    }

    recovery_start_time_ = loss_detection_time;
    slow_start_ = false;
    const auto reduced = congestion_round_to_size_t(kCopaLossReductionFactor *
                                                    static_cast<double>(congestion_window_));
    congestion_window_ = std::max(minimum_window(), reduced);
    reset_velocity();
    set_pacing_rate();
}

void CopaCongestionController::on_persistent_congestion() {
    slow_start_ = false;
    congestion_window_ = minimum_window();
    reset_velocity();
    set_pacing_rate();
}

std::size_t CopaCongestionController::congestion_window() const {
    return congestion_window_;
}

std::size_t CopaCongestionController::bytes_in_flight() const {
    return bytes_in_flight_;
}

std::size_t CopaCongestionController::minimum_window() const {
    return 2 * max_datagram_size_;
}

std::size_t CopaCongestionController::pacing_budget_cap() const {
    return std::max(send_quantum_, max_datagram_size_);
}

std::size_t CopaCongestionController::pacing_budget_at(QuicCoreTimePoint now) const {
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

    const auto elapsed = std::chrono::duration<double>(now - *pacing_budget_timestamp_).count();
    const auto replenished = elapsed * pacing_rate_bytes_per_second_;
    if (replenished >= static_cast<double>(cap - budget)) {
        return cap;
    }
    return budget + congestion_clamp_to_size_t(replenished);
}

void CopaCongestionController::consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now) {
    const auto budget = pacing_budget_at(now);
    pacing_budget_bytes_ = bytes >= budget ? 0 : budget - bytes;
    pacing_budget_timestamp_ = now;
}

void CopaCongestionController::update_rtt_model(const RecoveryRttState &rtt_state) {
    if (rtt_state.min_rtt.has_value()) {
        min_rtt_ = positive_rtt(*rtt_state.min_rtt);
    }
    if (rtt_state.latest_rtt.has_value()) {
        latest_rtt_ = positive_rtt(*rtt_state.latest_rtt);
    } else if (rtt_state.smoothed_rtt.count() > 0) {
        latest_rtt_ = rtt_state.smoothed_rtt;
    }
    if (latest_rtt_.has_value()) {
        min_rtt_ = min_rtt_.has_value() ? std::min(*min_rtt_, *latest_rtt_) : latest_rtt_;
    }
}

CopaCongestionController::CopaTarget CopaCongestionController::target_window() const {
    if (!latest_rtt_.has_value() || !min_rtt_.has_value() || *latest_rtt_ <= *min_rtt_) {
        return CopaTarget{.finite = false};
    }

    const auto rtt_seconds = std::chrono::duration<double>(*latest_rtt_).count();
    const auto queue_delay_seconds =
        std::chrono::duration<double>(*latest_rtt_ - *min_rtt_).count();
    const auto target_packets = rtt_seconds / (delta_ * queue_delay_seconds);
    const auto target_bytes = target_packets * static_cast<double>(max_datagram_size_);
    return CopaTarget{
        .finite = true,
        .window = std::max(minimum_window(), congestion_round_to_size_t(target_bytes)),
    };
}

void CopaCongestionController::update_velocity(QuicCoreTimePoint now) {
    const auto rtt = positive_rtt(latest_rtt_.value_or(kInitialRtt));
    if (!last_velocity_update_time_.has_value()) {
        last_velocity_update_time_ = now;
        return;
    }
    if (now < *last_velocity_update_time_ + rtt) {
        return;
    }

    if (previous_update_direction_ * update_direction_ > 0) {
        velocity_packets_ = std::min(velocity_packets_ * 2.0,
                                     std::max(1.0, delta_ * smss_segments(congestion_window_)));
    } else {
        velocity_packets_ = 1.0;
    }
    if (update_direction_ != 0) {
        previous_update_direction_ = update_direction_;
    }
    update_direction_ = 0;
    last_velocity_update_time_ = now;
}

void CopaCongestionController::grow_slow_start(std::size_t acked_bytes, const CopaTarget &target) {
    congestion_window_ = congestion_saturating_add(congestion_window_, acked_bytes);
    if (target.finite && congestion_window_ >= target.window) {
        slow_start_ = false;
        congestion_window_ = std::max(minimum_window(), target.window);
        reset_velocity();
    }
}

void CopaCongestionController::adjust_congestion_avoidance(std::size_t acked_bytes,
                                                           const CopaTarget &target,
                                                           QuicCoreTimePoint now) {
    update_velocity(now);

    const bool increase = !target.finite || congestion_window_ < target.window;
    update_direction_ += increase ? 1 : -1;
    const auto acked_packets =
        std::max(1.0, static_cast<double>(acked_bytes) / static_cast<double>(max_datagram_size_));
    const auto cwnd_packets = std::max(1.0, smss_segments(congestion_window_));
    const auto window_delta =
        congestion_round_to_size_t(static_cast<double>(max_datagram_size_) * acked_packets *
                                   velocity_packets_ / (delta_ * cwnd_packets));

    if (increase) {
        congestion_window_ =
            congestion_saturating_add(congestion_window_, std::max<std::size_t>(1, window_delta));
    } else {
        const auto decrement = std::max<std::size_t>(1, window_delta);
        congestion_window_ = congestion_window_ <= minimum_window() + decrement
                                 ? minimum_window()
                                 : congestion_window_ - decrement;
    }
}

void CopaCongestionController::set_pacing_rate() {
    const auto rtt = positive_rtt(latest_rtt_.value_or(kInitialRtt));
    const auto rtt_seconds = std::chrono::duration<double>(rtt).count();
    pacing_rate_bytes_per_second_ =
        kCopaPacingGain * static_cast<double>(congestion_window_) / rtt_seconds;
}

void CopaCongestionController::subtract_in_flight(std::span<const SentPacketRecord> packets) {
    for (const auto &packet : packets) {
        if (!packet.in_flight) {
            continue;
        }
        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
    }
}

void CopaCongestionController::reset_velocity() {
    velocity_packets_ = 1.0;
    update_direction_ = 0;
    previous_update_direction_ = 1;
    last_velocity_update_time_.reset();
}

double CopaCongestionController::smss_segments(std::size_t bytes) const {
    return static_cast<double>(bytes) / static_cast<double>(max_datagram_size_);
}

} // namespace coquic::quic
