#include "src/quic/congestion.h"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <utility>

namespace coquic::quic {

namespace {

std::uint64_t double_to_u64(double value) {
    if (!(value > 0.0) || !std::isfinite(value)) {
        return 0;
    }
    const auto max = static_cast<double>(std::numeric_limits<std::uint64_t>::max());
    if (value >= max) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t duration_us(const std::optional<QuicCoreDuration> &duration) {
    if (!duration.has_value()) {
        return 0;
    }
    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(*duration).count();
    if (micros <= 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(micros);
}

} // namespace

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
    : storage_(std::move(other.storage_)), congestion_window_(this, true),
      bytes_in_flight_(this, false) {
}

QuicCongestionController &
QuicCongestionController::operator=(QuicCongestionController &&other) noexcept {
    if (this != &other) {
        storage_ = std::move(other.storage_);
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

std::size_t QuicCongestionController::pacing_send_quantum() const {
    return std::visit(
        [](const auto &controller) {
            using Controller = std::decay_t<decltype(controller)>;
            if constexpr (std::is_same_v<Controller, BbrCongestionController> ||
                          std::is_same_v<Controller, CopaCongestionController>) {
                return controller.pacing_budget_cap();
            } else {
                return controller.max_datagram_size_;
            }
        },
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

QuicCongestionDebugMetrics QuicCongestionController::debug_metrics(QuicCoreTimePoint now) const {
    return std::visit(
        [&](const auto &controller) {
            using Controller = std::decay_t<decltype(controller)>;
            QuicCongestionDebugMetrics metrics{
                .send_quantum = controller.max_datagram_size_,
            };

            if constexpr (std::is_same_v<Controller, BbrCongestionController>) {
                metrics.mode = static_cast<std::uint64_t>(controller.mode_);
                metrics.bandwidth_bps = double_to_u64(controller.bandwidth_bytes_per_second_);
                metrics.max_bandwidth_bps =
                    double_to_u64(controller.max_bandwidth_bytes_per_second_);
                metrics.pacing_rate_bps = double_to_u64(controller.pacing_rate_bytes_per_second_);
                metrics.bdp_bytes = double_to_u64(controller.bdp_);
                metrics.max_inflight = controller.max_inflight_;
                metrics.send_quantum = controller.send_quantum_;
                metrics.pacing_budget = controller.pacing_budget_at(now);
                metrics.finite_inflight_longterm =
                    controller.inflight_longterm_ != std::numeric_limits<std::size_t>::max();
                metrics.inflight_longterm =
                    metrics.finite_inflight_longterm ? controller.inflight_longterm_ : 0;
                metrics.finite_inflight_shortterm =
                    controller.inflight_shortterm_ != std::numeric_limits<std::size_t>::max();
                metrics.inflight_shortterm =
                    metrics.finite_inflight_shortterm ? controller.inflight_shortterm_ : 0;
                metrics.extra_acked = controller.extra_acked_;
                metrics.total_delivered = controller.total_delivered_;
                metrics.total_lost = controller.total_lost_;
                metrics.min_rtt_us = duration_us(controller.min_rtt_);
                metrics.round_count = controller.round_count_;
                metrics.app_limited = controller.is_app_limited();
                metrics.full_bw_reached = controller.full_bw_reached_;
            } else if constexpr (std::is_same_v<Controller, CopaCongestionController>) {
                const auto target = controller.target_window();
                metrics.mode = controller.slow_start_ ? 1u : 2u;
                metrics.pacing_rate_bps = double_to_u64(controller.pacing_rate_bytes_per_second_);
                metrics.send_quantum = controller.send_quantum_;
                metrics.pacing_budget = controller.pacing_budget_at(now);
                metrics.latest_rtt_us = duration_us(controller.latest_rtt_);
                metrics.min_rtt_us = duration_us(controller.min_rtt_);
                metrics.unjittered_rtt_us = duration_us(controller.unjittered_rtt_);
                metrics.target_window = target.window;
                metrics.slow_start = controller.slow_start_;
                metrics.startup_probe_complete = controller.startup_probe_complete_;
                metrics.finite_target_window = target.finite;
            }

            return metrics;
        },
        storage_);
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
