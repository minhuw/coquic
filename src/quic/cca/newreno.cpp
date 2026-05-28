#include "src/quic/cca/newreno.h"

#include <algorithm>

namespace coquic::quic {

namespace {

constexpr double kNewRenoPacingGain = 1.25;
constexpr double kNewRenoSlowStartPacingGain = 2.0;
constexpr std::size_t kPacingStartStreamBytes = std::size_t{32} * 1024;

} // namespace

NewRenoCongestionController::NewRenoCongestionController(std::size_t max_datagram_size,
                                                         bool enable_hystart_plus_plus)
    : max_datagram_size_(max_datagram_size),
      congestion_window_(congestion_initial_window(max_datagram_size)),
      hystart_(max_datagram_size, enable_hystart_plus_plus) {
}

bool NewRenoCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    return bytes_in_flight_ + bytes <= congestion_window_;
}

std::optional<QuicCoreTimePoint>
NewRenoCongestionController::next_send_time(std::size_t bytes) const {
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

void NewRenoCongestionController::on_packet_sent(std::size_t bytes_sent, bool ack_eliciting) {
    if (!ack_eliciting) {
        return;
    }

    bytes_in_flight_ += bytes_sent;
}

void NewRenoCongestionController::on_packet_sent(SentPacketRecord &packet) {
    if (!packet.ack_eliciting) {
        return;
    }

    hystart_.on_packet_sent(packet);
    on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
    consume_pacing_budget(packet.bytes_in_flight, packet.sent_time);
}

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                   bool app_limited) {
    on_packets_acked(packets, app_limited, QuicCoreTimePoint{}, RecoveryRttState{});
}

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
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

        if (congestion_window_ < slow_start_threshold_) {
            slow_start_acked_bytes =
                congestion_saturating_add(slow_start_acked_bytes, packet.bytes_in_flight);
            continue;
        }

        congestion_avoidance_credit_ += packet.bytes_in_flight;
        while (congestion_avoidance_credit_ >= congestion_window_) {
            congestion_avoidance_credit_ -= congestion_window_;
            congestion_window_ += max_datagram_size_;
        }
    }

    if (slow_start_acked_bytes != 0) {
        congestion_window_ = congestion_saturating_add(
            congestion_window_, hystart_.growth_bytes(slow_start_acked_bytes));
        hystart_.on_slow_start_ack(packets, rtt_state);
        if (hystart_.should_exit_slow_start()) {
            slow_start_threshold_ = congestion_window_;
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

void NewRenoCongestionController::on_simple_stream_packets_acked(
    std::span<const AckedStreamPacketSample> packets, bool app_limited, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    if (packets.empty()) {
        update_pacing_rate(rtt_state);
        return;
    }

    const auto recovery_boundary = recovery_start_time_;
    bool exit_recovery = false;
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

        if (congestion_window_ < slow_start_threshold_) {
            slow_start_acked_bytes =
                congestion_saturating_add(slow_start_acked_bytes, packet.bytes_in_flight);
            continue;
        }

        congestion_avoidance_credit_ += packet.bytes_in_flight;
        while (congestion_avoidance_credit_ >= congestion_window_) {
            congestion_avoidance_credit_ -= congestion_window_;
            congestion_window_ += max_datagram_size_;
        }
    }

    acked_stream_bytes_for_pacing_ =
        congestion_saturating_add(acked_stream_bytes_for_pacing_, acked_bytes);
    if (slow_start_acked_bytes != 0) {
        congestion_window_ = congestion_saturating_add(
            congestion_window_, hystart_.growth_bytes(slow_start_acked_bytes));
        hystart_.on_slow_start_ack(packets, rtt_state);
        if (hystart_.should_exit_slow_start()) {
            slow_start_threshold_ = congestion_window_;
        }
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

void NewRenoCongestionController::on_packets_discarded(std::span<const SentPacketRecord> packets) {
    for (const auto &packet : packets) {
        if (!packet.in_flight) {
            continue;
        }

        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
    }
}

void NewRenoCongestionController::on_packets_lost(std::span<const SentPacketRecord> packets) {
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
void NewRenoCongestionController::on_loss_event(QuicCoreTimePoint loss_detection_time,
                                                QuicCoreTimePoint largest_lost_sent_time) {
    if (recovery_start_time_.has_value() && largest_lost_sent_time <= *recovery_start_time_) {
        return;
    }

    recovery_start_time_ = loss_detection_time;
    hystart_.disable();
    slow_start_threshold_ = std::max(minimum_window(), congestion_window_ / 2);
    congestion_window_ = slow_start_threshold_;
    congestion_avoidance_credit_ = 0;
}

void NewRenoCongestionController::on_persistent_congestion() {
    hystart_.disable();
    congestion_window_ = minimum_window();
    congestion_avoidance_credit_ = 0;
}

std::size_t NewRenoCongestionController::congestion_window() const {
    return congestion_window_;
}

std::size_t NewRenoCongestionController::bytes_in_flight() const {
    return bytes_in_flight_;
}

std::size_t NewRenoCongestionController::minimum_window() const {
    return 2 * max_datagram_size_;
}

bool NewRenoCongestionController::pacing_active() const {
    return pacing_budget_timestamp_.has_value();
}

void NewRenoCongestionController::update_pacing_rate(const RecoveryRttState &rtt_state) {
    if (rtt_state.smoothed_rtt.count() > 0) {
        pacing_smoothed_rtt_ = rtt_state.smoothed_rtt;
    }

    const auto rtt_seconds = std::chrono::duration<double>(pacing_smoothed_rtt_).count();
    if (rtt_seconds <= 0.0) {
        pacing_rate_bytes_per_second_ = 0.0;
        return;
    }
    const auto gain = congestion_window_ < slow_start_threshold_ ? kNewRenoSlowStartPacingGain
                                                                 : kNewRenoPacingGain;
    pacing_rate_bytes_per_second_ = gain * static_cast<double>(congestion_window_) / rtt_seconds;
}

bool NewRenoCongestionController::should_start_pacing(
    std::span<const SentPacketRecord> packets) const {
    if (acked_stream_bytes_for_pacing_ >= kPacingStartStreamBytes) {
        return true;
    }
    return std::ranges::any_of(packets, [](const SentPacketRecord &packet) {
        return packet.bytes_in_flight >= kPacingStartStreamBytes &&
               sent_packet_has_stream_frames(packet);
    });
}

std::size_t NewRenoCongestionController::pacing_budget_cap() const {
    return congestion_quinn_pacing_budget_cap(congestion_window_, max_datagram_size_,
                                              pacing_smoothed_rtt_);
}

std::size_t NewRenoCongestionController::pacing_budget_at(QuicCoreTimePoint now) const {
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

void NewRenoCongestionController::consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now) {
    if (!pacing_active()) {
        return;
    }

    const auto budget = pacing_budget_at(now);
    pacing_budget_bytes_ = bytes >= budget ? 0 : budget - bytes;
    pacing_budget_timestamp_ = now;
}

bool NewRenoCongestionController::in_recovery(const SentPacketRecord &packet) const {
    return recovery_start_time_.has_value() && packet.sent_time <= *recovery_start_time_;
}

} // namespace coquic::quic
