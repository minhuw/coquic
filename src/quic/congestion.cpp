#include "src/quic/congestion.h"

namespace coquic::quic {

std::string_view congestion_control_algorithm_name(QuicCongestionControlAlgorithm algorithm) {
    if (algorithm == QuicCongestionControlAlgorithm::cubic) {
        return "cubic";
    }
    if (algorithm == QuicCongestionControlAlgorithm::bbr) {
        return "bbr";
    }
    if (algorithm == QuicCongestionControlAlgorithm::copa) {
        return "copa";
    }
    return "newreno";
}

std::optional<QuicCongestionControlAlgorithm>
parse_congestion_control_algorithm(std::string_view value) {
    if (value == "newreno") {
        return QuicCongestionControlAlgorithm::newreno;
    }
    if (value == "cubic") {
        return QuicCongestionControlAlgorithm::cubic;
    }
    if (value == "bbr") {
        return QuicCongestionControlAlgorithm::bbr;
    }
    if (value == "copa") {
        return QuicCongestionControlAlgorithm::copa;
    }
    return std::nullopt;
}

QuicCongestionController::QuicCongestionController(QuicCongestionControlAlgorithm algorithm,
                                                   std::size_t max_datagram_size)
    : storage_(std::in_place_type<NewRenoCongestionController>, max_datagram_size),
      congestion_window_(this, true), bytes_in_flight_(this, false) {
    if (algorithm == QuicCongestionControlAlgorithm::cubic) {
        storage_.emplace<CubicCongestionController>(max_datagram_size);
        return;
    }
    if (algorithm == QuicCongestionControlAlgorithm::bbr) {
        storage_.emplace<BbrCongestionController>(max_datagram_size);
        return;
    }
    if (algorithm == QuicCongestionControlAlgorithm::copa) {
        storage_.emplace<CopaCongestionController>(max_datagram_size);
    }
}

QuicCongestionController::QuicCongestionController(const QuicCongestionController &other)
    : storage_(other.storage_), congestion_window_(this, true), bytes_in_flight_(this, false) {
}

QuicCongestionController &
QuicCongestionController::operator=(const QuicCongestionController &other) {
    if (this != &other) {
        storage_ = other.storage_;
    }
    return *this;
}

QuicCongestionController::QuicCongestionController(QuicCongestionController &&other) noexcept
    : storage_(other.storage_), congestion_window_(this, true), bytes_in_flight_(this, false) {
}

QuicCongestionController &
QuicCongestionController::operator=(QuicCongestionController &&other) noexcept {
    if (this != &other) {
        storage_ = other.storage_;
    }
    return *this;
}

QuicCongestionControlAlgorithm QuicCongestionController::algorithm() const {
    if (std::holds_alternative<CubicCongestionController>(storage_)) {
        return QuicCongestionControlAlgorithm::cubic;
    }
    if (std::holds_alternative<BbrCongestionController>(storage_)) {
        return QuicCongestionControlAlgorithm::bbr;
    }
    if (std::holds_alternative<CopaCongestionController>(storage_)) {
        return QuicCongestionControlAlgorithm::copa;
    }
    return QuicCongestionControlAlgorithm::newreno;
}

std::string_view QuicCongestionController::name() const {
    return congestion_control_algorithm_name(algorithm());
}

bool QuicCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    return std::visit(
        [&](const auto &controller) { return controller.can_send_ack_eliciting(bytes); }, storage_);
}

std::optional<QuicCoreTimePoint> QuicCongestionController::next_send_time(std::size_t bytes) const {
    return std::visit([&](const auto &controller) { return controller.next_send_time(bytes); },
                      storage_);
}

void QuicCongestionController::on_packet_sent(std::size_t bytes_sent, bool ack_eliciting) {
    SentPacketRecord packet{
        .sent_time = QuicCoreTimePoint{},
        .ack_eliciting = ack_eliciting,
        .in_flight = ack_eliciting,
        .bytes_in_flight = bytes_sent,
    };
    on_packet_sent(packet);
}

void QuicCongestionController::on_packet_sent(SentPacketRecord &packet) {
    std::visit([&](auto &controller) { controller.on_packet_sent(packet); }, storage_);
}

void QuicCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                bool app_limited, QuicCoreTimePoint now,
                                                const RecoveryRttState &rtt_state) {
    std::visit(
        [&](auto &controller) {
            controller.on_packets_acked(packets, app_limited, now, rtt_state);
        },
        storage_);
}

void QuicCongestionController::on_packets_discarded(std::span<const SentPacketRecord> packets) {
    std::visit([&](auto &controller) { controller.on_packets_discarded(packets); }, storage_);
}

void QuicCongestionController::on_packets_lost(std::span<const SentPacketRecord> packets) {
    std::visit([&](auto &controller) { controller.on_packets_lost(packets); }, storage_);
}

void QuicCongestionController::on_loss_event(QuicCoreTimePoint loss_detection_time,
                                             QuicCoreTimePoint largest_lost_sent_time) {
    std::visit(
        [&](auto &controller) {
            controller.on_loss_event(loss_detection_time, largest_lost_sent_time);
        },
        storage_);
}

void QuicCongestionController::on_persistent_congestion() {
    std::visit([&](auto &controller) { controller.on_persistent_congestion(); }, storage_);
}

void QuicCongestionController::reset_for_new_path() {
    const auto algorithm_before_reset = algorithm();
    const auto max_datagram_size =
        std::visit([](const auto &controller) { return controller.max_datagram_size_; }, storage_);
    *this = QuicCongestionController(algorithm_before_reset, max_datagram_size);
}

std::size_t QuicCongestionController::congestion_window() const {
    return test_metric(/*congestion_window=*/true);
}

std::size_t QuicCongestionController::bytes_in_flight() const {
    return test_metric(/*congestion_window=*/false);
}

std::size_t QuicCongestionController::minimum_window() const {
    return std::visit([](const auto &controller) { return controller.minimum_window(); }, storage_);
}

bool QuicCongestionController::would_underutilize_congestion_window(std::size_t bytes_sent) const {
    return bytes_in_flight() + bytes_sent < congestion_window();
}

void QuicCongestionController::set_test_metric(bool congestion_window, std::size_t value) {
    std::visit(
        [&](auto &controller) {
            if (congestion_window) {
                controller.congestion_window_ = value;
            } else {
                controller.bytes_in_flight_ = value;
            }
        },
        storage_);
}

std::size_t QuicCongestionController::test_metric(bool congestion_window) const {
    return std::visit(
        [&](const auto &controller) {
            return congestion_window ? controller.congestion_window_ : controller.bytes_in_flight_;
        },
        storage_);
}

} // namespace coquic::quic
