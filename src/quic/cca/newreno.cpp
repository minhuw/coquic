#include "src/quic/cca/newreno.h"

#include <algorithm>

namespace coquic::quic {

NewRenoCongestionController::NewRenoCongestionController(std::size_t max_datagram_size)
    : max_datagram_size_(max_datagram_size),
      congestion_window_(congestion_initial_window(max_datagram_size)),
      hystart_(max_datagram_size) {
}

bool NewRenoCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    return bytes_in_flight_ + bytes <= congestion_window_;
}

std::optional<QuicCoreTimePoint>
NewRenoCongestionController::next_send_time(std::size_t bytes) const {
    static_cast<void>(bytes);
    return std::nullopt;
}

void NewRenoCongestionController::on_packet_sent(std::size_t bytes_sent, bool ack_eliciting) {
    if (!ack_eliciting) {
        return;
    }

    bytes_in_flight_ += bytes_sent;
}

void NewRenoCongestionController::on_packet_sent(SentPacketRecord &packet) {
    on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
}

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                   bool app_limited) {
    on_packets_acked(packets, app_limited, QuicCoreTimePoint{}, RecoveryRttState{});
}

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                   bool app_limited, QuicCoreTimePoint now,
                                                   const RecoveryRttState &rtt_state) {
    static_cast<void>(now);
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
        congestion_window_ = congestion_saturating_add(congestion_window_, slow_start_acked_bytes);
    }

    if (exit_recovery) {
        recovery_start_time_ = std::nullopt;
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

bool NewRenoCongestionController::in_recovery(const SentPacketRecord &packet) const {
    return recovery_start_time_.has_value() && packet.sent_time <= *recovery_start_time_;
}

} // namespace coquic::quic
