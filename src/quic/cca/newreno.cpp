#include "src/quic/cca/newreno.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace coquic::quic {

namespace {

constexpr double kNewRenoPacingGain = 1.25;
constexpr double kNewRenoSlowStartPacingGain = 2.0;
constexpr std::size_t kPacingStartStreamBytes = std::size_t{32} * 1024;
constexpr std::size_t kNewRenoPacingMinimumBurstPackets = 1;

} // namespace

NewRenoCongestionController::NewRenoCongestionController(std::size_t max_datagram_size,
                                                         bool enable_hystart_plus_plus)
    : max_datagram_size_(max_datagram_size),
      congestion_window_(congestion_initial_window(max_datagram_size)),
      hystart_(max_datagram_size, enable_hystart_plus_plus) {
}

bool NewRenoCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    const auto window = send_window();
    return bytes_in_flight_ <= window && bytes <= window - bytes_in_flight_;
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
    if (recovery_start_time_.has_value()) {
        recovery_sent_bytes_ = congestion_saturating_add(recovery_sent_bytes_, bytes_sent);
    }
}

void NewRenoCongestionController::on_packet_sent(SentPacketRecord &packet) {
    if (!packet.ack_eliciting) {
        return;
    }

    hystart_.on_packet_sent(packet);
    bytes_in_flight_ += packet.bytes_in_flight;
    if (sent_after_recovery_boundary(packet, recovery_start_time_, recovery_start_sequence_) ||
        (recovery_start_sequence_ == std::nullopt && recovery_start_time_.has_value() &&
         packet.sent_time >= *recovery_start_time_)) {
        recovery_sent_bytes_ =
            congestion_saturating_add(recovery_sent_bytes_, packet.bytes_in_flight);
    }
    consume_pacing_budget(packet.bytes_in_flight, packet.sent_time);
}

SimpleStreamPacketSentCongestionResult NewRenoCongestionController::on_simple_stream_packet_sent(
    std::size_t bytes_sent, QuicCoreTimePoint sent_time, bool app_limited) {
    const auto congestion_send_sequence = hystart_.on_ack_eliciting_packet_sent();
    bytes_in_flight_ += bytes_sent;
    if (sent_after_recovery_boundary(
            AckedStreamPacketSample{
                .sent_time = sent_time,
                .congestion_send_sequence = congestion_send_sequence,
            },
            recovery_start_time_, recovery_start_sequence_) ||
        (recovery_start_sequence_ == std::nullopt && recovery_start_time_.has_value() &&
         sent_time >= *recovery_start_time_)) {
        recovery_sent_bytes_ = congestion_saturating_add(recovery_sent_bytes_, bytes_sent);
    }
    consume_pacing_budget(bytes_sent, sent_time);
    return SimpleStreamPacketSentCongestionResult{
        .congestion_send_sequence = congestion_send_sequence,
        .app_limited = app_limited,
    };
}

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                   bool app_limited) {
    on_packets_acked(packets, app_limited, QuicCoreTimePoint{}, RecoveryRttState{});
}

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                   bool app_limited, QuicCoreTimePoint now,
                                                   const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    const auto active_recovery_boundary = recovery_start_time_;
    const auto congestion_recovery_boundary = recovery_boundary();
    bool exit_recovery = false;
    std::size_t slow_start_acked_bytes = 0;

    for (const auto &packet : packets) {
        if (packet.declared_lost) {
            maybe_restore_spurious_loss_window();
            exit_recovery = true;
            continue;
        }
        if (packet.in_flight) {
            bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                                   ? 0
                                   : bytes_in_flight_ - packet.bytes_in_flight;
            if (active_recovery_boundary.has_value()) {
                note_recovery_delivered(packet.bytes_in_flight);
            }
        }

        const bool sent_during_or_before_recovery = sent_on_or_before_recovery_boundary(
            packet, congestion_recovery_boundary, last_recovery_start_sequence_);
        const bool sent_after_active_recovery_started = sent_after_recovery_boundary(
            packet, active_recovery_boundary, recovery_start_sequence_);
        if (packet.ack_eliciting && sent_after_active_recovery_started) {
            exit_recovery = true;
        }
        if (sent_packet_has_stream_frames(packet)) {
            acked_stream_bytes_for_pacing_ =
                congestion_saturating_add(acked_stream_bytes_for_pacing_, packet.bytes_in_flight);
        }

        if (!packet.ack_eliciting || sent_during_or_before_recovery) {
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
        clear_spurious_loss_window();
        reset_recovery_send_accounting();
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
    const auto congestion_recovery_boundary = this->recovery_boundary();
    bool exit_recovery = false;
    std::size_t acked_bytes = 0;
    std::size_t slow_start_acked_bytes = 0;

    for (const auto &packet : packets) {
        // The lightweight stream ACK path is only used for newly acked live packets.  Late ACKs
        // of declared-lost packets need the full SentPacketRecord path so NewReno can undo a
        // spurious loss response.
        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
        if (recovery_boundary.has_value()) {
            note_recovery_delivered(packet.bytes_in_flight);
        }
        acked_bytes = congestion_saturating_add(acked_bytes, packet.bytes_in_flight);

        const bool sent_during_or_before_recovery = sent_on_or_before_recovery_boundary(
            packet, congestion_recovery_boundary, last_recovery_start_sequence_);
        if (sent_after_recovery_boundary(packet, recovery_boundary, recovery_start_sequence_)) {
            exit_recovery = true;
        }
        if (sent_during_or_before_recovery) {
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
        clear_spurious_loss_window();
        reset_recovery_send_accounting();
    }

    update_pacing_rate(rtt_state);
    if (!pacing_budget_timestamp_.has_value() &&
        acked_stream_bytes_for_pacing_ >= kPacingStartStreamBytes && now != QuicCoreTimePoint{} &&
        pacing_rate_bytes_per_second_ > 0.0) {
        pacing_budget_timestamp_ = now;
        pacing_budget_bytes_ = pacing_budget_cap();
    }
}

void NewRenoCongestionController::on_simple_stream_packets_acked(
    const AckedStreamPacketAggregate &packets, bool app_limited, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    if (packets.empty()) {
        update_pacing_rate(rtt_state);
        return;
    }

    const auto recovery_boundary = recovery_start_time_;
    const auto congestion_recovery_boundary = this->recovery_boundary();
    const bool sent_during_or_before_recovery =
        (congestion_recovery_boundary.has_value() &&
         packets.latest_sent_time <= *congestion_recovery_boundary) ||
        (last_recovery_start_sequence_.has_value() &&
         packets.largest_congestion_send_sequence != 0 &&
         packets.largest_congestion_send_sequence <= *last_recovery_start_sequence_);

    bytes_in_flight_ =
        packets.bytes_in_flight > bytes_in_flight_ ? 0 : bytes_in_flight_ - packets.bytes_in_flight;
    if (recovery_boundary.has_value()) {
        note_recovery_delivered(packets.bytes_in_flight);
    }
    acked_stream_bytes_for_pacing_ =
        congestion_saturating_add(acked_stream_bytes_for_pacing_, packets.bytes_in_flight);

    if (!sent_during_or_before_recovery) {
        if (congestion_window_ < slow_start_threshold_) {
            congestion_window_ = congestion_saturating_add(
                congestion_window_, hystart_.growth_bytes(packets.bytes_in_flight));
            hystart_.on_slow_start_ack(packets, rtt_state);
            if (hystart_.should_exit_slow_start()) {
                slow_start_threshold_ = congestion_window_;
            }
        } else {
            congestion_avoidance_credit_ =
                congestion_saturating_add(congestion_avoidance_credit_, packets.bytes_in_flight);
            while (congestion_avoidance_credit_ >= congestion_window_) {
                congestion_avoidance_credit_ -= congestion_window_;
                congestion_window_ += max_datagram_size_;
            }
        }
    }

    const bool exits_recovery =
        (recovery_start_sequence_.has_value() && packets.largest_congestion_send_sequence != 0 &&
         packets.largest_congestion_send_sequence > *recovery_start_sequence_) ||
        (recovery_start_sequence_ == std::nullopt && recovery_boundary.has_value() &&
         packets.latest_sent_time > *recovery_boundary);
    if (exits_recovery) {
        recovery_start_time_ = std::nullopt;
        clear_spurious_loss_window();
        reset_recovery_send_accounting();
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

        if (packet.ack_eliciting) {
            pending_recovery_loss_bytes_ =
                congestion_saturating_add(pending_recovery_loss_bytes_, packet.bytes_in_flight);
            if (packet.congestion_send_sequence != 0) {
                pending_largest_lost_send_sequence_ =
                    pending_largest_lost_send_sequence_.has_value()
                        ? std::max(*pending_largest_lost_send_sequence_,
                                   packet.congestion_send_sequence)
                        : packet.congestion_send_sequence;
            }
        }
        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
    }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void NewRenoCongestionController::on_loss_event(QuicCoreTimePoint loss_detection_time,
                                                QuicCoreTimePoint largest_lost_sent_time) {
    const auto lost_bytes = std::exchange(pending_recovery_loss_bytes_, std::size_t{0});
    const auto largest_lost_send_sequence =
        std::exchange(pending_largest_lost_send_sequence_, std::nullopt);
    if (recovery_start_time_.has_value()) {
        return;
    }
    if (loss_on_or_before_last_recovery_boundary(largest_lost_sent_time,
                                                 largest_lost_send_sequence)) {
        return;
    }

    const auto recovery_flight_size = congestion_saturating_add(bytes_in_flight_, lost_bytes);
    prior_congestion_window_ = std::max(prior_congestion_window_.value_or(0), congestion_window_);
    prior_slow_start_threshold_ =
        std::max(prior_slow_start_threshold_.value_or(0), slow_start_threshold_);
    recovery_start_time_ = loss_detection_time;
    last_recovery_start_time_ = loss_detection_time;
    recovery_start_sequence_ = hystart_.latest_sent_sequence();
    last_recovery_start_sequence_ = recovery_start_sequence_;
    recovery_flight_size_ = std::max(recovery_flight_size, max_datagram_size_);
    recovery_delivered_bytes_ = 0;
    recovery_sent_bytes_ = 0;
    hystart_.disable();
    slow_start_threshold_ = std::max(minimum_window(), congestion_window_ / 2);
    congestion_window_ = slow_start_threshold_;
    congestion_avoidance_credit_ = 0;
}

void NewRenoCongestionController::on_persistent_congestion() {
    hystart_.disable();
    congestion_window_ = minimum_window();
    congestion_avoidance_credit_ = 0;
    recovery_start_time_ = std::nullopt;
    last_recovery_start_time_ = std::nullopt;
    recovery_start_sequence_ = std::nullopt;
    last_recovery_start_sequence_ = std::nullopt;
    prior_congestion_window_ = std::nullopt;
    prior_slow_start_threshold_ = std::nullopt;
    reset_recovery_send_accounting();
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

std::size_t NewRenoCongestionController::send_window() const {
    if (!recovery_start_time_.has_value() || recovery_flight_size_ == 0) {
        return congestion_window_;
    }

    const auto prr_delivered = static_cast<long double>(recovery_delivered_bytes_);
    const auto prr_target = static_cast<long double>(slow_start_threshold_);
    const auto recover_flight = static_cast<long double>(recovery_flight_size_);
    const auto proportional_allowed_float =
        std::ceil((prr_delivered * prr_target) / recover_flight);
    const auto proportional_allowed =
        proportional_allowed_float >=
                static_cast<long double>(std::numeric_limits<std::size_t>::max())
            ? std::numeric_limits<std::size_t>::max()
            : static_cast<std::size_t>(proportional_allowed_float);
    const auto delivered_credit = recovery_delivered_bytes_ >= recovery_sent_bytes_
                                      ? recovery_delivered_bytes_ - recovery_sent_bytes_
                                      : std::size_t{0};
    std::size_t send_credit = 0;
    if (bytes_in_flight_ > slow_start_threshold_) {
        send_credit = proportional_allowed > recovery_sent_bytes_
                          ? proportional_allowed - recovery_sent_bytes_
                          : 0;
    } else if (bytes_in_flight_ < slow_start_threshold_) {
        send_credit = std::min(slow_start_threshold_ - bytes_in_flight_,
                               congestion_saturating_add(delivered_credit, max_datagram_size_));
    }
    const auto initial_recovery_credit = recovery_sent_bytes_ < max_datagram_size_
                                             ? max_datagram_size_ - recovery_sent_bytes_
                                             : std::size_t{0};
    send_credit = std::max(send_credit, initial_recovery_credit);

    return congestion_saturating_add(bytes_in_flight_, send_credit);
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
                                              pacing_smoothed_rtt_,
                                              kNewRenoPacingMinimumBurstPackets);
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
    const auto boundary = recovery_boundary();
    return sent_on_or_before_recovery_boundary(packet, boundary, last_recovery_start_sequence_);
}

std::optional<QuicCoreTimePoint> NewRenoCongestionController::recovery_boundary() const {
    return last_recovery_start_time_.has_value() ? last_recovery_start_time_ : recovery_start_time_;
}

bool NewRenoCongestionController::sent_on_or_before_recovery_boundary(
    const SentPacketRecord &packet, const std::optional<QuicCoreTimePoint> &boundary_time,
    const std::optional<std::uint64_t> &boundary_sequence) const {
    if (boundary_sequence.has_value() && packet.congestion_send_sequence != 0) {
        return packet.congestion_send_sequence <= *boundary_sequence;
    }
    return boundary_time.has_value() && packet.sent_time <= *boundary_time;
}

bool NewRenoCongestionController::sent_on_or_before_recovery_boundary(
    const AckedStreamPacketSample &packet, const std::optional<QuicCoreTimePoint> &boundary_time,
    const std::optional<std::uint64_t> &boundary_sequence) const {
    if (boundary_sequence.has_value() && packet.congestion_send_sequence != 0) {
        return packet.congestion_send_sequence <= *boundary_sequence;
    }
    return boundary_time.has_value() && packet.sent_time <= *boundary_time;
}

bool NewRenoCongestionController::sent_after_recovery_boundary(
    const SentPacketRecord &packet, const std::optional<QuicCoreTimePoint> &boundary_time,
    const std::optional<std::uint64_t> &boundary_sequence) const {
    if (boundary_sequence.has_value() && packet.congestion_send_sequence != 0) {
        return packet.congestion_send_sequence > *boundary_sequence;
    }
    return boundary_time.has_value() && packet.sent_time > *boundary_time;
}

bool NewRenoCongestionController::sent_after_recovery_boundary(
    const AckedStreamPacketSample &packet, const std::optional<QuicCoreTimePoint> &boundary_time,
    const std::optional<std::uint64_t> &boundary_sequence) const {
    if (boundary_sequence.has_value() && packet.congestion_send_sequence != 0) {
        return packet.congestion_send_sequence > *boundary_sequence;
    }
    return boundary_time.has_value() && packet.sent_time > *boundary_time;
}

bool NewRenoCongestionController::loss_on_or_before_last_recovery_boundary(
    QuicCoreTimePoint largest_lost_sent_time,
    std::optional<std::uint64_t> largest_lost_send_sequence) const {
    if (last_recovery_start_sequence_.has_value() && largest_lost_send_sequence.has_value()) {
        return *largest_lost_send_sequence <= *last_recovery_start_sequence_;
    }
    return last_recovery_start_time_.has_value() &&
           largest_lost_sent_time <= *last_recovery_start_time_;
}

void NewRenoCongestionController::note_recovery_delivered(std::size_t bytes) {
    recovery_delivered_bytes_ = congestion_saturating_add(recovery_delivered_bytes_, bytes);
}

void NewRenoCongestionController::maybe_restore_spurious_loss_window() {
    if (prior_congestion_window_.has_value()) {
        congestion_window_ = std::max(congestion_window_, *prior_congestion_window_);
    }
    if (prior_slow_start_threshold_.has_value()) {
        slow_start_threshold_ = std::max(slow_start_threshold_, *prior_slow_start_threshold_);
    }
    clear_spurious_loss_window();
}

void NewRenoCongestionController::clear_spurious_loss_window() {
    prior_congestion_window_ = std::nullopt;
    prior_slow_start_threshold_ = std::nullopt;
}

void NewRenoCongestionController::reset_recovery_send_accounting() {
    recovery_start_sequence_ = std::nullopt;
    recovery_flight_size_ = 0;
    recovery_delivered_bytes_ = 0;
    recovery_sent_bytes_ = 0;
    pending_recovery_loss_bytes_ = 0;
    pending_largest_lost_send_sequence_ = std::nullopt;
}

} // namespace coquic::quic
