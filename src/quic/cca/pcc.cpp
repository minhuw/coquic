#include "src/quic/cca/pcc.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>

namespace coquic::quic {

namespace {

constexpr double kPccAllegroEpsilonMin = 0.01;
constexpr double kPccAllegroEpsilonMax = 0.05;
constexpr double kPccAllegroSigmoidAlpha = 100.0;
constexpr double kPccLossBarrier = 0.05;
constexpr double kPccVivaceSamplingStep = 0.05;
constexpr double kPccVivaceTheta0 = 1.0;
constexpr double kPccVivaceInitialBoundary = 0.05;
constexpr double kPccVivaceBoundaryIncrement = 0.1;
constexpr double kPccVivaceLatencyFilter = 0.05;
constexpr double kPccVivaceT = 0.9;
constexpr double kPccVivaceLatencyPenalty = 900.0;
constexpr double kPccVivaceLossPenalty = 11.35;
constexpr double kPccPacingGain = 1.0;
constexpr double kPccWindowGain = 2.0;
constexpr std::size_t kPccMinimumWindowPackets = 4;
constexpr std::size_t kPccMinimumMiPackets = 10;
constexpr std::size_t kPccMinimumBurstPackets = 2;
constexpr QuicCoreDuration kPccSendQuantumWindow{1000};
constexpr std::size_t kPccMaxSendQuantum = std::size_t{64} * 1024u;
constexpr double kBytesPerSecondPerMegabit = 125000.0;
constexpr std::size_t kPccMaxPendingMonitorIntervals = 32;

double duration_seconds(QuicCoreDuration duration) {
    const auto seconds = std::chrono::duration<double>(duration).count();
    return seconds > 0.0 ? seconds : std::chrono::duration<double>(kGranularity).count();
}

QuicCoreDuration positive_duration(QuicCoreDuration duration) {
    return duration.count() > 0 ? duration : kGranularity;
}

double sigmoid(double value, double alpha) {
    const auto scaled = std::clamp(alpha * value, -60.0, 60.0);
    return 1.0 / (1.0 + std::exp(scaled));
}

double bytes_per_second_to_megabits_per_second(double bytes_per_second) {
    return bytes_per_second / kBytesPerSecondPerMegabit;
}

double megabits_per_second_to_bytes_per_second(double megabits_per_second) {
    return megabits_per_second * kBytesPerSecondPerMegabit;
}

QuicCoreDuration utility_rtt_sample(const RecoveryRttState &rtt_state, QuicCoreDuration fallback) {
    if (rtt_state.latest_adjusted_rtt_sample.has_value()) {
        return positive_duration(*rtt_state.latest_adjusted_rtt_sample);
    }
    if (rtt_state.latest_adjusted_rtt.has_value()) {
        return positive_duration(*rtt_state.latest_adjusted_rtt);
    }
    if (rtt_state.latest_rtt_sample.has_value()) {
        return positive_duration(*rtt_state.latest_rtt_sample);
    }
    return positive_duration(rtt_state.latest_rtt.value_or(fallback));
}

} // namespace

PccCongestionController::PccCongestionController(std::size_t max_datagram_size, Variant variant)
    : max_datagram_size_(max_datagram_size), variant_(variant) {
    latest_rtt_ = kInitialRtt;
    min_rtt_ = kInitialRtt;
    previous_interval_rtt_ = kInitialRtt;
    if (variant_ == Variant::vivace) {
        epsilon_ = kPccVivaceSamplingStep;
    }
    const auto initial_rate = static_cast<double>(congestion_initial_window(max_datagram_size_)) /
                              duration_seconds(positive_rtt());
    set_sending_rate(initial_rate);
    decision_base_rate_bytes_per_second_ = sending_rate_bytes_per_second_;
    vivace_base_rate_bytes_per_second_ = sending_rate_bytes_per_second_;
}

bool PccCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    return bytes_in_flight_ + bytes <= congestion_window_;
}

std::optional<QuicCoreTimePoint> PccCongestionController::next_send_time(std::size_t bytes) const {
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
    return *pacing_budget_timestamp_ +
           congestion_pacing_delay_for_deficit(bytes - budget, pacing_rate_bytes_per_second_);
}

SimpleStreamPacketSentCongestionResult PccCongestionController::on_simple_stream_packet_sent(
    std::size_t bytes_sent, QuicCoreTimePoint sent_time, bool app_limited) {
    const auto congestion_send_sequence = note_packet_sent(bytes_sent, sent_time, app_limited);
    return SimpleStreamPacketSentCongestionResult{
        .congestion_send_sequence = congestion_send_sequence,
        .app_limited = app_limited,
    };
}

void PccCongestionController::on_packet_sent(std::size_t bytes_sent, bool ack_eliciting) {
    if (!ack_eliciting) {
        return;
    }
    note_packet_sent(bytes_sent, QuicCoreTimePoint{}, /*app_limited=*/false);
}

void PccCongestionController::on_packet_sent(SentPacketRecord &packet) {
    if (!packet.ack_eliciting) {
        return;
    }
    packet.congestion_send_sequence =
        note_packet_sent(packet.bytes_in_flight, packet.sent_time, packet.app_limited);
}

void PccCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                               bool app_limited) {
    on_packets_acked(packets, app_limited, QuicCoreTimePoint{}, RecoveryRttState{});
}

void PccCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                               bool app_limited, QuicCoreTimePoint now,
                                               const RecoveryRttState &rtt_state) {
    apply_acked_bytes(packets, app_limited, now, rtt_state);
}

void PccCongestionController::on_simple_stream_packets_acked(
    std::span<const AckedStreamPacketSample> packets, bool app_limited, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    apply_acked_bytes(packets, app_limited, now, rtt_state);
}

void PccCongestionController::on_simple_stream_packets_acked(
    const AckedStreamPacketAggregate &packets, bool app_limited, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    apply_acked_aggregate(packets, app_limited, now, rtt_state);
}

void PccCongestionController::on_packets_discarded(std::span<const SentPacketRecord> packets) {
    for (const auto &packet : packets) {
        if (packet.in_flight) {
            subtract_in_flight(packet.bytes_in_flight);
        }
    }
}

void PccCongestionController::on_packets_lost(std::span<const SentPacketRecord> packets) {
    for (const auto &packet : packets) {
        if (packet.in_flight) {
            subtract_in_flight(packet.bytes_in_flight);
        }
        record_loss_sample(packet);
    }
    maybe_process_monitor_intervals(recovery_start_time_.value_or(QuicCoreTimePoint{}),
                                    RecoveryRttState{});
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void PccCongestionController::on_loss_event(QuicCoreTimePoint loss_detection_time,
                                            QuicCoreTimePoint largest_lost_sent_time) {
    if (recovery_start_time_.has_value() && largest_lost_sent_time <= *recovery_start_time_) {
        return;
    }
    recovery_start_time_ = loss_detection_time;
}

void PccCongestionController::on_persistent_congestion() {
    reset_pcc_state();
    congestion_window_ = minimum_window();
    persistent_congestion_window_limited_ = true;
    const auto rate = static_cast<double>(congestion_window_) / duration_seconds(positive_rtt());
    set_sending_rate(rate);
    congestion_window_ = minimum_window();
}

std::size_t PccCongestionController::congestion_window() const {
    return congestion_window_;
}

std::size_t PccCongestionController::bytes_in_flight() const {
    return bytes_in_flight_;
}

std::size_t PccCongestionController::minimum_window() const {
    return kPccMinimumWindowPackets * max_datagram_size_;
}

std::size_t PccCongestionController::pacing_budget_cap() const {
    return congestion_quinn_pacing_budget_cap(congestion_window_, max_datagram_size_,
                                              positive_rtt(), kPccMinimumBurstPackets);
}

std::size_t PccCongestionController::pacing_budget_at(QuicCoreTimePoint now) const {
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

void PccCongestionController::consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now) {
    if (!pacing_budget_timestamp_.has_value() || now == QuicCoreTimePoint{}) {
        return;
    }
    const auto budget = pacing_budget_at(now);
    pacing_budget_bytes_ = bytes >= budget ? 0 : budget - bytes;
    pacing_budget_timestamp_ = now;
}

PccCongestionController::MonitorInterval *
PccCongestionController::monitor_interval_for_sample(std::uint64_t sequence,
                                                     QuicCoreTimePoint sent_time) {
    if (sequence != 0) {
        if (current_interval_.active && current_interval_.sequence == sequence) {
            return &current_interval_;
        }
        for (auto &interval : pending_monitor_intervals_) {
            if (interval.sequence == sequence) {
                return &interval;
            }
        }
    }
    if (sent_time == QuicCoreTimePoint{}) {
        return nullptr;
    }
    if (current_interval_.active && sent_time >= current_interval_.start_time &&
        sent_time < current_interval_.end_time) {
        return &current_interval_;
    }
    for (auto &interval : pending_monitor_intervals_) {
        if (sent_time >= interval.start_time && sent_time < interval.end_time) {
            return &interval;
        }
    }
    return nullptr;
}

std::uint64_t PccCongestionController::note_packet_sent(std::size_t bytes_sent,
                                                        QuicCoreTimePoint sent_time,
                                                        bool app_limited) {
    bytes_in_flight_ = congestion_saturating_add(bytes_in_flight_, bytes_sent);
    if (sent_time != QuicCoreTimePoint{} && !current_interval_.active) {
        start_monitor_interval(sent_time);
    }
    maybe_seal_current_monitor_interval(sent_time);
    if (sent_time != QuicCoreTimePoint{} && !current_interval_.active) {
        start_monitor_interval(sent_time);
    }
    auto sequence = std::uint64_t{0};
    if (current_interval_.active) {
        sequence = current_interval_.sequence;
        current_interval_.sent_bytes =
            congestion_saturating_add(current_interval_.sent_bytes, bytes_sent);
        current_interval_.app_limited = current_interval_.app_limited || app_limited;
    }
    consume_pacing_budget(bytes_sent, sent_time);
    return sequence;
}

void PccCongestionController::apply_acked_bytes(std::span<const SentPacketRecord> packets,
                                                bool app_limited, QuicCoreTimePoint now,
                                                const RecoveryRttState &rtt_state) {
    bool exit_recovery = false;
    update_rtt_model(rtt_state, now);
    for (const auto &packet : packets) {
        if (packet.declared_lost) {
            continue;
        }
        if (packet.in_flight) {
            subtract_in_flight(packet.bytes_in_flight);
        }
        if (recovery_start_time_.has_value() && packet.sent_time > *recovery_start_time_) {
            exit_recovery = true;
        }
        if (!packet.ack_eliciting || packet.app_limited) {
            continue;
        }
        record_ack_sample(packet.congestion_send_sequence, packet.sent_time, packet.bytes_in_flight,
                          now, rtt_state, app_limited);
    }
    if (exit_recovery) {
        recovery_start_time_.reset();
    }
    maybe_seal_current_monitor_interval(now);
    maybe_process_monitor_intervals(now, rtt_state);
}

void PccCongestionController::apply_acked_bytes(std::span<const AckedStreamPacketSample> packets,
                                                bool app_limited, QuicCoreTimePoint now,
                                                const RecoveryRttState &rtt_state) {
    bool exit_recovery = false;
    update_rtt_model(rtt_state, now);
    for (const auto &packet : packets) {
        subtract_in_flight(packet.bytes_in_flight);
        if (recovery_start_time_.has_value() && packet.sent_time > *recovery_start_time_) {
            exit_recovery = true;
        }
        if (packet.app_limited) {
            continue;
        }
        record_ack_sample(packet.congestion_send_sequence, packet.sent_time, packet.bytes_in_flight,
                          now, rtt_state, app_limited);
    }
    if (exit_recovery) {
        recovery_start_time_.reset();
    }
    maybe_seal_current_monitor_interval(now);
    maybe_process_monitor_intervals(now, rtt_state);
}

void PccCongestionController::apply_acked_aggregate(const AckedStreamPacketAggregate &packets,
                                                    bool app_limited, QuicCoreTimePoint now,
                                                    const RecoveryRttState &rtt_state) {
    update_rtt_model(rtt_state, now);
    if (packets.empty()) {
        maybe_seal_current_monitor_interval(now);
        maybe_process_monitor_intervals(now, rtt_state);
        return;
    }

    subtract_in_flight(packets.bytes_in_flight);
    if (recovery_start_time_.has_value() && packets.latest_sent_time > *recovery_start_time_) {
        recovery_start_time_.reset();
    }
    record_ack_sample(packets.largest_congestion_send_sequence, packets.latest_sent_time,
                      packets.bytes_in_flight, now, rtt_state, app_limited);
    maybe_seal_current_monitor_interval(now);
    maybe_process_monitor_intervals(now, rtt_state);
}

void PccCongestionController::record_ack_sample(std::uint64_t sequence, QuicCoreTimePoint sent_time,
                                                std::size_t bytes, QuicCoreTimePoint now,
                                                const RecoveryRttState &rtt_state,
                                                bool app_limited) {
    if (now == QuicCoreTimePoint{}) {
        now = current_interval_.active ? current_interval_.end_time : QuicCoreTimePoint{};
    }
    auto *interval = monitor_interval_for_sample(sequence, sent_time);
    if (interval == nullptr) {
        return;
    }

    interval->acked_bytes = congestion_saturating_add(interval->acked_bytes, bytes);
    interval->app_limited = interval->app_limited || app_limited;
    const auto rtt = utility_rtt_sample(rtt_state, positive_rtt());
    if (interval->rtt_sample_count == 0) {
        interval->first_rtt = positive_duration(rtt);
    }
    interval->latest_rtt = positive_duration(rtt);
    if (now != QuicCoreTimePoint{} && interval->start_time != QuicCoreTimePoint{}) {
        const auto x = duration_seconds(
            std::chrono::duration_cast<QuicCoreDuration>(now - interval->start_time));
        const auto y = duration_seconds(positive_duration(rtt));
        interval->rtt_sample_x_sum += x;
        interval->rtt_sample_y_sum += y;
        interval->rtt_sample_x2_sum += x * x;
        interval->rtt_sample_xy_sum += x * y;
    }
    ++interval->rtt_sample_count;
}

void PccCongestionController::record_loss_sample(const SentPacketRecord &packet) {
    if (!packet.ack_eliciting || !packet.in_flight || packet.bytes_in_flight == 0) {
        return;
    }
    if (auto *interval =
            monitor_interval_for_sample(packet.congestion_send_sequence, packet.sent_time);
        interval != nullptr) {
        interval->lost_bytes =
            congestion_saturating_add(interval->lost_bytes, packet.bytes_in_flight);
    }
}

void PccCongestionController::seal_current_monitor_interval() {
    if (!current_interval_.active) {
        return;
    }
    pending_monitor_intervals_.push_back(current_interval_);
    current_interval_ = MonitorInterval{};
    while (pending_monitor_intervals_.size() > kPccMaxPendingMonitorIntervals) {
        pending_monitor_intervals_.pop_front();
    }
}

void PccCongestionController::maybe_seal_current_monitor_interval(QuicCoreTimePoint now) {
    if (now == QuicCoreTimePoint{} || !current_interval_.active) {
        return;
    }
    if (now >= current_interval_.end_time) {
        seal_current_monitor_interval();
    }
}

void PccCongestionController::discard_current_monitor_interval() {
    current_interval_ = MonitorInterval{};
}

void PccCongestionController::maybe_process_monitor_intervals(QuicCoreTimePoint now,
                                                              const RecoveryRttState &rtt_state) {
    update_rtt_model(rtt_state, now);
    while (!pending_monitor_intervals_.empty()) {
        const auto &interval = pending_monitor_intervals_.front();
        if (interval.acked_bytes + interval.lost_bytes < interval.sent_bytes) {
            break;
        }

        const auto sample = build_utility_sample(interval);
        const auto app_limited = interval.app_limited;
        pending_monitor_intervals_.pop_front();
        if (!app_limited) {
            apply_utility_sample(sample);
            discard_current_monitor_interval();
            pending_monitor_intervals_.clear();
            break;
        }
    }
}

void PccCongestionController::finish_monitor_interval(QuicCoreTimePoint now,
                                                      const RecoveryRttState &rtt_state) {
    if (!current_interval_.active) {
        start_monitor_interval(now == QuicCoreTimePoint{} ? QuicCoreTimePoint{} : now);
        return;
    }

    seal_current_monitor_interval();
    maybe_process_monitor_intervals(now, rtt_state);
    start_monitor_interval(now);
}

void PccCongestionController::maybe_finish_monitor_interval(QuicCoreTimePoint now,
                                                            const RecoveryRttState &rtt_state) {
    if (!current_interval_.active) {
        if (now != QuicCoreTimePoint{}) {
            start_monitor_interval(now);
        }
        return;
    }
    if (now == QuicCoreTimePoint{}) {
        return;
    }
    if (now >= current_interval_.end_time) {
        finish_monitor_interval(now, rtt_state);
    }
}

PccCongestionController::UtilitySample
PccCongestionController::build_utility_sample(const MonitorInterval &interval) const {
    const auto sent = static_cast<double>(std::max<std::size_t>(interval.sent_bytes, 1));
    const auto acked = static_cast<double>(interval.acked_bytes);
    const auto lost = static_cast<double>(interval.lost_bytes);
    const auto loss_rate = std::clamp(lost / std::max(sent, acked + lost), 0.0, 1.0);
    const auto interval_duration = positive_duration(
        std::chrono::duration_cast<QuicCoreDuration>(interval.end_time - interval.start_time));
    const auto throughput = acked / duration_seconds(interval_duration);
    double rtt_gradient = 0.0;
    if (interval.rtt_sample_count > 1 && interval.rtt_sample_x2_sum > 0.0) {
        const auto count = static_cast<double>(interval.rtt_sample_count);
        const auto denominator = count * interval.rtt_sample_x2_sum -
                                 interval.rtt_sample_x_sum * interval.rtt_sample_x_sum;
        if (denominator > std::numeric_limits<double>::epsilon()) {
            rtt_gradient = (count * interval.rtt_sample_xy_sum -
                            interval.rtt_sample_x_sum * interval.rtt_sample_y_sum) /
                           denominator;
        } else {
            const auto delta =
                std::chrono::duration<double>(interval.latest_rtt - interval.first_rtt).count();
            rtt_gradient = delta / duration_seconds(interval_duration);
        }
        if (std::abs(rtt_gradient) < kPccVivaceLatencyFilter) {
            rtt_gradient = 0.0;
        }
    } else if (previous_interval_rtt_.has_value()) {
        const auto delta =
            std::chrono::duration<double>(positive_rtt() - *previous_interval_rtt_).count();
        rtt_gradient = delta / duration_seconds(interval_duration);
        if (std::abs(rtt_gradient) < kPccVivaceLatencyFilter) {
            rtt_gradient = 0.0;
        }
    }

    const auto utility =
        variant_ == Variant::vivace
            ? vivace_utility(VivaceUtilityInput{
                  .sending_rate_bytes_per_second = interval.sending_rate_bytes_per_second,
                  .loss_rate = loss_rate,
                  .rtt_gradient = rtt_gradient,
              })
            : allegro_utility(interval.sending_rate_bytes_per_second, throughput, loss_rate);
    return UtilitySample{
        .sending_rate_bytes_per_second = interval.sending_rate_bytes_per_second,
        .utility = utility,
        .loss_rate = loss_rate,
        .throughput_bytes_per_second = throughput,
        .rtt_gradient = rtt_gradient,
    };
}

double PccCongestionController::allegro_utility(double sending_rate_bytes_per_second,
                                                double throughput_bytes_per_second,
                                                double loss_rate) const {
    const auto loss_barrier = sigmoid(loss_rate - kPccLossBarrier, kPccAllegroSigmoidAlpha);
    return throughput_bytes_per_second * loss_barrier - sending_rate_bytes_per_second * loss_rate;
}

double PccCongestionController::vivace_utility(const VivaceUtilityInput &input) const {
    const auto rate_mbps = std::max(
        bytes_per_second_to_megabits_per_second(input.sending_rate_bytes_per_second), 0.001);
    return std::pow(rate_mbps, kPccVivaceT) -
           kPccVivaceLatencyPenalty * rate_mbps * input.rtt_gradient -
           kPccVivaceLossPenalty * rate_mbps * input.loss_rate;
}

void PccCongestionController::apply_utility_sample(const UtilitySample &sample) {
    if (variant_ == Variant::vivace) {
        apply_vivace_sample(sample);
        return;
    }
    apply_allegro_sample(sample);
}

void PccCongestionController::apply_allegro_sample(const UtilitySample &sample) {
    if (mode_ == Mode::startup) {
        if (!previous_startup_sample_.has_value() ||
            sample.utility >= previous_startup_sample_->utility) {
            previous_startup_sample_ = sample;
            set_sending_rate(sending_rate_bytes_per_second_ * 2.0);
            return;
        }

        set_sending_rate(previous_startup_sample_->sending_rate_bytes_per_second);
        enter_decision_mode();
        return;
    }

    if (mode_ == Mode::decision) {
        if (decision_sample_count_ < decision_samples_.size()) {
            decision_samples_[decision_sample_count_++] = sample;
        }
        if (decision_sample_count_ < decision_samples_.size()) {
            set_sending_rate(next_allegro_rate());
            return;
        }

        const auto &first = decision_samples_[0];
        const auto &second = decision_samples_[1];
        const auto &third = decision_samples_[2];
        const auto &fourth = decision_samples_[3];
        const bool first_pair_high_wins =
            first->sending_rate_bytes_per_second > second->sending_rate_bytes_per_second
                ? first->utility > second->utility
                : second->utility > first->utility;
        const bool second_pair_high_wins =
            third->sending_rate_bytes_per_second > fourth->sending_rate_bytes_per_second
                ? third->utility > fourth->utility
                : fourth->utility > third->utility;

        if (first_pair_high_wins == second_pair_high_wins) {
            const auto direction = first_pair_high_wins ? 1 : -1;
            set_sending_rate(decision_base_rate_bytes_per_second_ *
                             (1.0 + static_cast<double>(direction) * epsilon_));
            enter_rate_adjust_mode(direction);
            return;
        }

        epsilon_ = std::min(kPccAllegroEpsilonMax, epsilon_ + kPccAllegroEpsilonMin);
        set_sending_rate(decision_base_rate_bytes_per_second_);
        enter_decision_mode();
        return;
    }

    if (!previous_adjust_sample_.has_value() ||
        sample.utility >= previous_adjust_sample_->utility) {
        previous_adjust_sample_ = sample;
        ++rate_adjust_round_;
        set_sending_rate(next_allegro_rate());
        return;
    }

    set_sending_rate(previous_adjust_sample_->sending_rate_bytes_per_second);
    enter_decision_mode();
}

void PccCongestionController::apply_vivace_sample(const UtilitySample &sample) {
    if (mode_ == Mode::startup) {
        if (!previous_startup_sample_.has_value() ||
            sample.utility >= previous_startup_sample_->utility) {
            previous_startup_sample_ = sample;
            set_sending_rate(sending_rate_bytes_per_second_ * 2.0);
            return;
        }

        set_sending_rate(previous_startup_sample_->sending_rate_bytes_per_second);
        enter_vivace_mode();
        return;
    }

    if (!previous_adjust_sample_.has_value()) {
        previous_adjust_sample_ = sample;
        if (vivace_base_rate_bytes_per_second_ <= 0.0) {
            vivace_base_rate_bytes_per_second_ = sample.sending_rate_bytes_per_second;
        }
        vivace_probe_direction_ = -vivace_probe_direction_;
        set_sending_rate(next_vivace_rate());
        return;
    }

    const auto rate_delta = sample.sending_rate_bytes_per_second -
                            previous_adjust_sample_->sending_rate_bytes_per_second;
    if (std::abs(rate_delta) <= std::numeric_limits<double>::epsilon()) {
        previous_adjust_sample_ = sample;
        vivace_probe_direction_ = -vivace_probe_direction_;
        set_sending_rate(next_vivace_rate());
        return;
    }

    const auto rate_delta_mbps = bytes_per_second_to_megabits_per_second(rate_delta);
    const auto utility_gradient =
        (sample.utility - previous_adjust_sample_->utility) / rate_delta_mbps;

    const int direction = utility_gradient > 0.0 ? 1 : -1;
    if (direction == previous_vivace_direction_) {
        ++vivace_same_direction_count_;
    } else {
        previous_vivace_direction_ = direction;
        vivace_same_direction_count_ = 0;
        vivace_boundary_adjustment_count_ = 0;
    }

    const auto confidence =
        vivace_same_direction_count_ <= 3
            ? static_cast<double>(std::max<std::size_t>(vivace_same_direction_count_, 1))
            : static_cast<double>(2 * vivace_same_direction_count_ - 3);
    const auto raw_rate_change =
        megabits_per_second_to_bytes_per_second(confidence * kPccVivaceTheta0 * utility_gradient);
    const auto boundary = vivace_dynamic_boundary_ * vivace_base_rate_bytes_per_second_;
    const auto rate_change = std::clamp(raw_rate_change, -boundary, boundary);
    vivace_base_rate_bytes_per_second_ =
        clamp_rate(vivace_base_rate_bytes_per_second_ + rate_change, max_datagram_size_);
    previous_adjust_sample_.reset();
    vivace_probe_direction_ = 1;
    if (std::abs(raw_rate_change) > boundary) {
        ++vivace_boundary_adjustment_count_;
        vivace_dynamic_boundary_ =
            kPccVivaceInitialBoundary +
            static_cast<double>(vivace_boundary_adjustment_count_) * kPccVivaceBoundaryIncrement;
    } else {
        const auto normalized_change =
            std::abs(raw_rate_change) / std::max(vivace_base_rate_bytes_per_second_, 1.0);
        auto recalibrated_count = std::size_t{0};
        while (normalized_change >
               kPccVivaceInitialBoundary +
                   static_cast<double>(recalibrated_count) * kPccVivaceBoundaryIncrement) {
            ++recalibrated_count;
        }
        vivace_boundary_adjustment_count_ = recalibrated_count;
        vivace_dynamic_boundary_ =
            kPccVivaceInitialBoundary +
            static_cast<double>(vivace_boundary_adjustment_count_) * kPccVivaceBoundaryIncrement;
    }
    set_sending_rate(next_vivace_rate());
}

void PccCongestionController::enter_decision_mode() {
    mode_ = Mode::decision;
    decision_samples_.fill(std::nullopt);
    decision_sample_count_ = 0;
    decision_base_rate_bytes_per_second_ = sending_rate_bytes_per_second_;
    rate_adjust_round_ = 0;
    rate_adjust_direction_ = 0;
    previous_adjust_sample_.reset();
    set_sending_rate(next_allegro_rate());
}

void PccCongestionController::enter_vivace_mode() {
    mode_ = Mode::vivace;
    previous_adjust_sample_.reset();
    vivace_base_rate_bytes_per_second_ = sending_rate_bytes_per_second_;
    vivace_probe_direction_ = 1;
    previous_vivace_direction_ = 0;
    vivace_same_direction_count_ = 0;
    vivace_boundary_adjustment_count_ = 0;
    vivace_dynamic_boundary_ = kPccVivaceInitialBoundary;
    set_sending_rate(next_vivace_rate());
}

void PccCongestionController::enter_rate_adjust_mode(int direction) {
    mode_ = Mode::rate_adjust;
    rate_adjust_direction_ = direction;
    rate_adjust_round_ = 0;
    previous_adjust_sample_.reset();
    epsilon_ = kPccAllegroEpsilonMin;
    set_sending_rate(next_allegro_rate());
}

void PccCongestionController::start_monitor_interval(QuicCoreTimePoint now) {
    current_interval_ = MonitorInterval{
        .active = true,
        .sending_rate_bytes_per_second = sending_rate_bytes_per_second_,
        .sequence = next_monitor_interval_sequence_++,
        .start_time = now,
        .end_time = now + monitor_interval_duration(),
    };
    if (!pacing_budget_timestamp_.has_value() && now != QuicCoreTimePoint{}) {
        pacing_budget_timestamp_ = now;
        pacing_budget_bytes_ = pacing_budget_cap();
    }
}

double PccCongestionController::next_allegro_rate() const {
    if (mode_ == Mode::decision) {
        return decision_rate(decision_sample_count_);
    }
    if (mode_ == Mode::rate_adjust) {
        const auto factor = 1.0 + static_cast<double>(rate_adjust_round_) * kPccAllegroEpsilonMin *
                                      static_cast<double>(rate_adjust_direction_);
        return sending_rate_bytes_per_second_ * std::max(0.5, factor);
    }
    return sending_rate_bytes_per_second_;
}

double PccCongestionController::decision_rate(std::size_t sample_index) const {
    const bool high = (sample_index % 2) == 0;
    return decision_base_rate_bytes_per_second_ * (1.0 + (high ? epsilon_ : -epsilon_));
}

double PccCongestionController::next_vivace_rate() const {
    return vivace_base_rate_bytes_per_second_ *
           (1.0 + static_cast<double>(vivace_probe_direction_) * kPccVivaceSamplingStep);
}

QuicCoreDuration PccCongestionController::monitor_interval_duration() const {
    const auto rtt = positive_rtt();
    if (variant_ == Variant::vivace) {
        return rtt;
    }

    const auto packets_duration =
        std::chrono::duration_cast<QuicCoreDuration>(std::chrono::duration<double>(
            static_cast<double>(kPccMinimumMiPackets * max_datagram_size_) /
            std::max(sending_rate_bytes_per_second_, 1.0)));
    return std::max(rtt, positive_duration(packets_duration));
}

QuicCoreDuration PccCongestionController::positive_rtt() const {
    return positive_duration(latest_rtt_.value_or(kInitialRtt));
}

QuicCoreDuration PccCongestionController::window_rtt() const {
    return positive_duration(min_rtt_.value_or(positive_rtt()));
}

void PccCongestionController::set_sending_rate(double rate_bytes_per_second) {
    sending_rate_bytes_per_second_ = clamp_rate(rate_bytes_per_second, max_datagram_size_);
    set_pacing_rate();
    refresh_congestion_window();
    set_send_quantum();
}

void PccCongestionController::refresh_congestion_window() {
    if (persistent_congestion_window_limited_) {
        return;
    }
    const auto window = congestion_round_to_size_t(sending_rate_bytes_per_second_ *
                                                   duration_seconds(window_rtt()) * kPccWindowGain);
    congestion_window_ =
        std::max({minimum_window(), congestion_initial_window(max_datagram_size_), window});
}

void PccCongestionController::set_pacing_rate() {
    pacing_rate_bytes_per_second_ = kPccPacingGain * sending_rate_bytes_per_second_;
    if (persistent_congestion_window_limited_ &&
        sending_rate_bytes_per_second_ >
            static_cast<double>(minimum_window()) / duration_seconds(positive_rtt())) {
        persistent_congestion_window_limited_ = false;
        refresh_congestion_window();
    }
}

void PccCongestionController::set_send_quantum() {
    send_quantum_ = std::clamp(
        congestion_round_to_size_t(pacing_rate_bytes_per_second_ *
                                   std::chrono::duration<double>(kPccSendQuantumWindow).count()),
        max_datagram_size_, kPccMaxSendQuantum);
}

void PccCongestionController::update_rtt_model(const RecoveryRttState &rtt_state) {
    update_rtt_model(rtt_state, QuicCoreTimePoint{});
}

void PccCongestionController::update_rtt_model(const RecoveryRttState &rtt_state,
                                               QuicCoreTimePoint now) {
    bool changed = false;
    if (rtt_state.latest_rtt.has_value()) {
        previous_interval_rtt_ = latest_rtt_;
        latest_rtt_ = positive_duration(*rtt_state.latest_rtt);
        changed = true;
    } else if (rtt_state.smoothed_rtt.count() > 0 && !latest_rtt_.has_value()) {
        latest_rtt_ = positive_duration(rtt_state.smoothed_rtt);
        changed = true;
    }
    if (rtt_state.min_rtt.has_value()) {
        min_rtt_ = min_rtt_.has_value() ? std::min(*min_rtt_, positive_duration(*rtt_state.min_rtt))
                                        : positive_duration(*rtt_state.min_rtt);
        changed = true;
    } else if (latest_rtt_.has_value()) {
        min_rtt_ = min_rtt_.has_value() ? std::min(*min_rtt_, *latest_rtt_) : *latest_rtt_;
        changed = true;
    }
    if (changed) {
        refresh_congestion_window();
    }
    if (current_interval_.active && now != QuicCoreTimePoint{} &&
        current_interval_.end_time <= current_interval_.start_time) {
        current_interval_.end_time = current_interval_.start_time + monitor_interval_duration();
    }
}

void PccCongestionController::subtract_in_flight(std::size_t bytes) {
    bytes_in_flight_ = bytes > bytes_in_flight_ ? 0 : bytes_in_flight_ - bytes;
}

void PccCongestionController::reset_pcc_state() {
    const auto max_datagram_size = max_datagram_size_;
    const auto variant = variant_;
    *this = PccCongestionController(max_datagram_size, variant);
}

double PccCongestionController::clamp_rate(double rate_bytes_per_second,
                                           std::size_t max_datagram_size) {
    const auto minimum = static_cast<double>(kPccMinimumWindowPackets * max_datagram_size) /
                         duration_seconds(kInitialRtt);
    const auto maximum = static_cast<double>(std::numeric_limits<std::uint32_t>::max());
    if (!std::isfinite(rate_bytes_per_second)) {
        return minimum;
    }
    return std::clamp(rate_bytes_per_second, minimum, maximum);
}

} // namespace coquic::quic
