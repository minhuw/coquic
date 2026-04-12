#include "src/quic/congestion.h"

#include <algorithm>

namespace coquic::quic {

namespace {

constexpr std::size_t kRecommendedInitialWindowUpperBound = 14720;

std::size_t initial_window(std::size_t max_datagram_size) {
    return std::min<std::size_t>(
        10 * max_datagram_size,
        std::max<std::size_t>(2 * max_datagram_size, kRecommendedInitialWindowUpperBound));
}

} // namespace

NewRenoCongestionController::NewRenoCongestionController(std::size_t max_datagram_size)
    : max_datagram_size_(max_datagram_size), congestion_window_(initial_window(max_datagram_size)) {
}

bool NewRenoCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    return bytes_in_flight_ + bytes <= congestion_window_;
}

void NewRenoCongestionController::on_packet_sent(std::size_t bytes_sent, bool ack_eliciting) {
    if (!ack_eliciting) {
        return;
    }

    bytes_in_flight_ += bytes_sent;
}

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                   bool app_limited) {
    for (const auto &packet : packets) {
        if (packet.in_flight) {
            bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                                   ? 0
                                   : bytes_in_flight_ - packet.bytes_in_flight;
        }

        if (!packet.ack_eliciting || in_recovery(packet) || app_limited) {
            continue;
        }

        if (recovery_start_time_.has_value()) {
            recovery_start_time_ = std::nullopt;
        }

        if (congestion_window_ < slow_start_threshold_) {
            congestion_window_ += packet.bytes_in_flight;
            continue;
        }

        congestion_avoidance_credit_ += packet.bytes_in_flight;
        while (congestion_avoidance_credit_ >= congestion_window_) {
            congestion_avoidance_credit_ -= congestion_window_;
            congestion_window_ += max_datagram_size_;
        }
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

void NewRenoCongestionController::on_loss_event(QuicCoreTimePoint loss_detection_time,
                                                QuicCoreTimePoint largest_lost_sent_time) {
    if (recovery_start_time_.has_value() && largest_lost_sent_time <= *recovery_start_time_) {
        return;
    }

    recovery_start_time_ = loss_detection_time;
    slow_start_threshold_ = std::max(minimum_window(), congestion_window_ / 2);
    congestion_window_ = slow_start_threshold_;
    congestion_avoidance_credit_ = 0;
}

void NewRenoCongestionController::on_persistent_congestion() {
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
