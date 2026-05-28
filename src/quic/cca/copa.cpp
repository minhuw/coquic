#include "src/quic/cca/copa.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>

#include "src/quic/cca/common.h"

namespace coquic::quic {

namespace {

constexpr double kCopaLossReductionFactor = 0.7;
constexpr double kCopaPacingGain = 2.0;
constexpr double kCopaSrttAlpha = 1.0 / 16.0;
constexpr std::size_t kCopaProbeSegments = 10;
constexpr QuicCoreDuration kCopaSendQuantumWindow{1000};
constexpr std::size_t kCopaMaxSendQuantum = std::size_t{64} * 1024u;

QuicCoreDuration positive_rtt(QuicCoreDuration value) {
    return value.count() > 0 ? value : std::chrono::duration_cast<QuicCoreDuration>(kGranularity);
}

} // namespace

CopaCongestionController::RttWindow::ExtremeWindow::ExtremeWindow(bool find_min)
    : find_min_(find_min) {
}

void CopaCongestionController::RttWindow::ExtremeWindow::clear() {
    samples_.clear();
    extreme_.reset();
    max_duration_ = QuicCoreDuration{10000000};
}

void CopaCongestionController::RttWindow::ExtremeWindow::set_max_duration(
    QuicCoreDuration max_duration) {
    max_duration_ = positive_rtt(max_duration);
}

void CopaCongestionController::RttWindow::ExtremeWindow::add_sample(QuicCoreDuration rtt,
                                                                    QuicCoreTimePoint now) {
    const auto sample = positive_rtt(rtt);
    while (!samples_.empty() && ((find_min_ && samples_.back().second > sample) ||
                                 (!find_min_ && samples_.back().second < sample))) {
        samples_.pop_back();
    }

    samples_.emplace_back(now, sample);
    if (!extreme_.has_value() || (find_min_ && sample < *extreme_) ||
        (!find_min_ && sample > *extreme_)) {
        extreme_ = sample;
    }
    clear_old_history(now);
}

QuicCoreDuration CopaCongestionController::RttWindow::ExtremeWindow::value() const {
    if (extreme_.has_value()) {
        return *extreme_;
    }
    return kInitialRtt;
}

void CopaCongestionController::RttWindow::ExtremeWindow::clear_old_history(QuicCoreTimePoint now) {
    bool recompute = false;
    while (samples_.size() > 1 && samples_.front().first + max_duration_ < now) {
        if (extreme_.has_value() && samples_.front().second == *extreme_) {
            recompute = true;
        }
        samples_.pop_front();
    }
    if (recompute) {
        extreme_.reset();
        for (const auto &[_, sample] : samples_) {
            if (!extreme_.has_value() || (find_min_ && sample < *extreme_) ||
                (!find_min_ && sample > *extreme_)) {
                extreme_ = sample;
            }
        }
    }
}

void CopaCongestionController::RttWindow::clear() {
    smoothed_rtt_.reset();
    latest_rtt_.reset();
    min_rtt_.clear();
    unjittered_rtt_.clear();
}

void CopaCongestionController::RttWindow::add_sample(QuicCoreDuration rtt, QuicCoreTimePoint now) {
    const auto sample = positive_rtt(rtt);
    if (!smoothed_rtt_.has_value()) {
        smoothed_rtt_ = sample;
    } else {
        const auto smoothed = std::chrono::duration<double>(*smoothed_rtt_);
        const auto current = std::chrono::duration<double>(sample);
        smoothed_rtt_ = positive_rtt(std::chrono::duration_cast<QuicCoreDuration>(
            kCopaSrttAlpha * current + (1.0 - kCopaSrttAlpha) * smoothed));
    }
    latest_rtt_ = sample;

    const auto min_sample = min_rtt_.value();
    const auto max_duration = std::max(QuicCoreDuration{10000000}, 20 * positive_rtt(min_sample));
    const auto unjittered_duration = std::min(max_duration, positive_rtt(*smoothed_rtt_) / 2);

    min_rtt_.set_max_duration(max_duration);
    unjittered_rtt_.set_max_duration(unjittered_duration);
    min_rtt_.add_sample(sample, now);
    unjittered_rtt_.add_sample(sample, now);
}

QuicCoreDuration CopaCongestionController::RttWindow::latest_rtt() const {
    return latest_rtt_.value_or(kInitialRtt);
}

QuicCoreDuration CopaCongestionController::RttWindow::min_rtt() const {
    return min_rtt_.value();
}

QuicCoreDuration CopaCongestionController::RttWindow::unjittered_rtt() const {
    return unjittered_rtt_.value();
}

CopaCongestionController::CopaCongestionController(std::size_t max_datagram_size)
    : max_datagram_size_(max_datagram_size),
      congestion_window_(congestion_initial_window(max_datagram_size)),
      congestion_window_segments_(smss_segments(congestion_window_)),
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
    if (!startup_probe_complete_ || slow_start_) {
        return std::nullopt;
    }

    const auto budget = std::min(pacing_budget_bytes_, pacing_budget_cap());
    if (bytes <= budget) {
        return pacing_budget_timestamp_;
    }
    if (pacing_rate_bytes_per_second_ <= 0.0) {
        return std::nullopt;
    }

    return *pacing_budget_timestamp_ +
           congestion_pacing_delay_for_deficit(bytes - budget, pacing_rate_bytes_per_second_);
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

    update_rtt_model(rtt_state, now);
    if (acked_bytes == 0 || !latest_rtt_.has_value()) {
        if (exit_recovery) {
            recovery_start_time_.reset();
        }
        return;
    }

    sync_congestion_window_segments();
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
    sync_congestion_window_segments();
    reset_velocity();
    set_pacing_rate();
}

void CopaCongestionController::on_persistent_congestion() {
    slow_start_ = false;
    congestion_window_ = minimum_window();
    sync_congestion_window_segments();
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

    const auto missing_budget = cap - budget;
    const auto replenished = congestion_pacing_replenished_bytes(now - *pacing_budget_timestamp_,
                                                                 pacing_rate_bytes_per_second_);
    if (replenished >= missing_budget) {
        return cap;
    }
    return budget + replenished;
}

void CopaCongestionController::consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now) {
    const auto budget = pacing_budget_at(now);
    pacing_budget_bytes_ = bytes >= budget ? 0 : budget - bytes;
    pacing_budget_timestamp_ = now;
}

void CopaCongestionController::update_rtt_model(const RecoveryRttState &rtt_state) {
    update_rtt_model(rtt_state, QuicCoreTimePoint{});
}

void CopaCongestionController::update_rtt_model(const RecoveryRttState &rtt_state,
                                                QuicCoreTimePoint now) {
    std::optional<QuicCoreDuration> external_min_rtt;
    bool external_min_matches_sample = true;
    if (rtt_state.latest_ack_delay_compensated_rtt_sample.has_value()) {
        latest_rtt_ = positive_rtt(*rtt_state.latest_ack_delay_compensated_rtt_sample);
        external_min_matches_sample = false;
    } else if (rtt_state.latest_adjusted_rtt_sample.has_value()) {
        latest_rtt_ = positive_rtt(*rtt_state.latest_adjusted_rtt_sample);
    } else if (rtt_state.latest_adjusted_rtt.has_value()) {
        latest_rtt_ = positive_rtt(*rtt_state.latest_adjusted_rtt);
    } else if (rtt_state.latest_rtt_sample.has_value()) {
        latest_rtt_ = positive_rtt(*rtt_state.latest_rtt_sample);
    } else if (rtt_state.latest_rtt.has_value()) {
        latest_rtt_ = positive_rtt(*rtt_state.latest_rtt);
    } else if (rtt_state.smoothed_rtt.count() > 0) {
        latest_rtt_ = positive_rtt(rtt_state.smoothed_rtt);
    }
    if (external_min_matches_sample) {
        if (rtt_state.min_rtt_sample.has_value()) {
            external_min_rtt = positive_rtt(*rtt_state.min_rtt_sample);
        } else if (rtt_state.min_rtt.has_value()) {
            external_min_rtt = positive_rtt(*rtt_state.min_rtt);
        }
    }
    if (external_min_rtt.has_value()) {
        min_rtt_ = *external_min_rtt;
    }
    if (latest_rtt_.has_value()) {
        if (now != QuicCoreTimePoint{}) {
            rtt_window_.add_sample(*latest_rtt_, now);
            latest_rtt_ = rtt_window_.latest_rtt();
            min_rtt_ = external_min_rtt.has_value()
                           ? std::min(*external_min_rtt, rtt_window_.min_rtt())
                           : rtt_window_.min_rtt();
            unjittered_rtt_ = rtt_window_.unjittered_rtt();
        } else {
            min_rtt_ = min_rtt_.has_value() ? std::min(*min_rtt_, *latest_rtt_) : latest_rtt_;
            unjittered_rtt_ = latest_rtt_;
        }
    }
}

CopaCongestionController::CopaTarget CopaCongestionController::target_window() const {
    const auto signal_rtt = unjittered_rtt_.value_or(latest_rtt_.value_or(QuicCoreDuration{0}));
    if (!latest_rtt_.has_value() || !min_rtt_.has_value() || signal_rtt <= *min_rtt_) {
        return CopaTarget{.finite = false};
    }

    const auto queue_delay = signal_rtt - *min_rtt_;
    const auto rtt_seconds = std::chrono::duration<double>(signal_rtt).count();
    const auto queue_delay_seconds = std::chrono::duration<double>(queue_delay).count();
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
    const auto acked_segments = smss_segment_count(acked_bytes);
    const auto probe_segments_before = slow_start_probe_segments_acked_;
    slow_start_probe_segments_acked_ =
        congestion_saturating_add(slow_start_probe_segments_acked_, acked_segments);
    startup_probe_complete_ = slow_start_probe_segments_acked_ >= 2 * kCopaProbeSegments - 1;
    if (probe_segments_before < 2 * kCopaProbeSegments - 1) {
        if (!startup_probe_complete_) {
            return;
        }
        const auto probe_segments_after_completion =
            slow_start_probe_segments_acked_ - (2 * kCopaProbeSegments - 1);
        acked_bytes = probe_segments_after_completion * max_datagram_size_;
        if (acked_bytes == 0) {
            return;
        }
    }

    set_congestion_window_segments(congestion_window_segments_ +
                                   static_cast<double>(acked_bytes) /
                                       static_cast<double>(max_datagram_size_));
    if (startup_probe_complete_ && target.finite && congestion_window_ >= target.window) {
        slow_start_ = false;
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
    const auto cwnd_packets = std::max(1.0, congestion_window_segments_);
    const auto window_delta_packets = acked_packets * velocity_packets_ / (delta_ * cwnd_packets);

    if (increase) {
        set_congestion_window_segments(congestion_window_segments_ + window_delta_packets);
    } else {
        set_congestion_window_segments(congestion_window_segments_ - window_delta_packets);
    }
}

void CopaCongestionController::set_pacing_rate() {
    const auto rtt = positive_rtt(unjittered_rtt_.value_or(latest_rtt_.value_or(kInitialRtt)));
    const auto rtt_seconds = std::chrono::duration<double>(rtt).count();
    pacing_rate_bytes_per_second_ =
        kCopaPacingGain * static_cast<double>(congestion_window_) / rtt_seconds;
    set_send_quantum();
}

void CopaCongestionController::set_send_quantum() {
    const auto quantum =
        congestion_clamp_to_size_t(pacing_rate_bytes_per_second_ *
                                   std::chrono::duration<double>(kCopaSendQuantumWindow).count());
    send_quantum_ = std::clamp(quantum, 2 * max_datagram_size_, kCopaMaxSendQuantum);
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

void CopaCongestionController::sync_congestion_window_segments() {
    congestion_window_segments_ = std::max(2.0, smss_segments(congestion_window_));
}

void CopaCongestionController::set_congestion_window_segments(double segments) {
    congestion_window_segments_ = std::max(2.0, segments);
    congestion_window_ = std::max(
        minimum_window(), congestion_round_to_size_t(congestion_window_segments_ *
                                                     static_cast<double>(max_datagram_size_)));
}

std::size_t CopaCongestionController::smss_segment_count(std::size_t bytes) const {
    return std::max<std::size_t>(1, (bytes + max_datagram_size_ - 1) / max_datagram_size_);
}

double CopaCongestionController::smss_segments(std::size_t bytes) const {
    return static_cast<double>(bytes) / static_cast<double>(max_datagram_size_);
}

} // namespace coquic::quic
