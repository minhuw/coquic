#include "src/quic/congestion.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <limits>
#include <type_traits>

namespace coquic::quic {

namespace {

constexpr std::size_t kRecommendedInitialWindowUpperBound = 14720;
constexpr double kBbrStartupPacingGain = 2.77;
constexpr double kBbrDefaultCwndGain = 2.0;
constexpr double kBbrProbeBwDownPacingGain = 0.90;
constexpr double kBbrProbeBwCruisePacingGain = 1.0;
constexpr double kBbrProbeBwRefillPacingGain = 1.0;
constexpr double kBbrProbeBwUpPacingGain = 1.25;
constexpr double kBbrProbeBwUpCwndGain = 2.25;
constexpr double kBbrDrainPacingGain = 0.5;
constexpr double kBbrProbeRttPacingGain = 1.0;
constexpr double kBbrProbeRttCwndGain = 0.5;
constexpr double kBbrFullBandwidthGrowthTarget = 1.25;
constexpr std::uint8_t kBbrFullBandwidthRoundLimit = 3;
constexpr std::chrono::seconds kBbrMinRttWindow{10};
constexpr std::chrono::seconds kBbrProbeRttInterval{5};
constexpr std::chrono::milliseconds kBbrProbeRttDuration{200};
constexpr std::size_t kBbrMinimumWindowPackets = 4;
constexpr std::chrono::milliseconds kBbrSendQuantumWindow{1};
constexpr std::size_t kBbrMaxSendQuantum = std::size_t{64} * 1024u;
constexpr double kBbrLossThresh = 0.02;
constexpr double kBbrBeta = 0.7;
constexpr double kBbrHeadroom = 0.15;
constexpr double kBbrPacingMargin = 0.99;
constexpr std::size_t kBbrExtraAckedFilterLen = 10;
constexpr std::size_t kBbrStartupFullLossCount = 6;
constexpr std::uint64_t kBbrMaxProbeBwRounds = 63;

std::size_t initial_window(std::size_t max_datagram_size) {
    return std::min<std::size_t>(
        10 * max_datagram_size,
        std::max<std::size_t>(2 * max_datagram_size, kRecommendedInitialWindowUpperBound));
}

std::size_t saturating_add(std::size_t lhs, std::size_t rhs) {
    if (std::numeric_limits<std::size_t>::max() - lhs < rhs) {
        return std::numeric_limits<std::size_t>::max();
    }
    return lhs + rhs;
}

std::uint64_t saturating_add_u64(std::uint64_t lhs, std::size_t rhs) {
    if (std::numeric_limits<std::uint64_t>::max() - lhs < rhs) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return lhs + static_cast<std::uint64_t>(rhs);
}

double sample_bandwidth_bytes_per_second(const SentPacketRecord &packet,
                                         std::uint64_t delivered_bytes, QuicCoreTimePoint now,
                                         const std::optional<std::chrono::milliseconds> &min_rtt) {
    if (delivered_bytes <= packet.delivered) {
        return 0.0;
    }

    const auto send_elapsed = packet.sent_time > packet.first_sent_time
                                  ? packet.sent_time - packet.first_sent_time
                                  : QuicCoreClock::duration::zero();
    const auto ack_elapsed =
        now > packet.delivered_time ? now - packet.delivered_time : QuicCoreClock::duration::zero();
    const auto interval = std::max(send_elapsed, ack_elapsed);
    if (min_rtt.has_value() && interval < *min_rtt) {
        return 0.0;
    }

    const auto interval_seconds = std::chrono::duration<double>(interval).count();
    if (interval_seconds <= 0.0) {
        return 0.0;
    }

    return static_cast<double>(delivered_bytes - packet.delivered) / interval_seconds;
}

std::size_t clamp_to_size_t(double value) {
    if (!(value > 0.0)) {
        return 0;
    }
    const auto maximum = static_cast<double>(std::numeric_limits<std::size_t>::max());
    if (value >= maximum) {
        return std::numeric_limits<std::size_t>::max();
    }
    return static_cast<std::size_t>(value);
}

} // namespace

std::string_view congestion_control_algorithm_name(QuicCongestionControlAlgorithm algorithm) {
    switch (algorithm) {
    case QuicCongestionControlAlgorithm::newreno:
        return "newreno";
    case QuicCongestionControlAlgorithm::bbr:
        return "bbr";
    }
    return "newreno";
}

std::optional<QuicCongestionControlAlgorithm>
parse_congestion_control_algorithm(std::string_view value) {
    if (value == "newreno") {
        return QuicCongestionControlAlgorithm::newreno;
    }
    if (value == "bbr") {
        return QuicCongestionControlAlgorithm::bbr;
    }
    return std::nullopt;
}

NewRenoCongestionController::NewRenoCongestionController(std::size_t max_datagram_size)
    : max_datagram_size_(max_datagram_size), congestion_window_(initial_window(max_datagram_size)) {
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

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                   bool app_limited) {
    const auto recovery_boundary = recovery_start_time_;
    bool exit_recovery = false;

    for (const auto &packet : packets) {
        if (packet.in_flight) {
            bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                                   ? 0
                                   : bytes_in_flight_ - packet.bytes_in_flight;
        }

        const bool in_batch_recovery =
            recovery_boundary.has_value() && packet.sent_time <= *recovery_boundary;
        if (!packet.ack_eliciting || in_batch_recovery || app_limited) {
            continue;
        }

        if (recovery_boundary.has_value()) {
            exit_recovery = true;
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

    if (exit_recovery) {
        recovery_start_time_ = std::nullopt;
    }
}

void NewRenoCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                                   bool app_limited, QuicCoreTimePoint now,
                                                   const RecoveryRttState &rtt_state) {
    static_cast<void>(now);
    static_cast<void>(rtt_state);
    on_packets_acked(packets, app_limited);
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

BbrCongestionController::BbrCongestionController(std::size_t max_datagram_size)
    : max_datagram_size_(max_datagram_size), initial_cwnd_(initial_window(max_datagram_size)),
      congestion_window_(initial_cwnd_), max_inflight_(initial_cwnd_),
      offload_budget_(std::max<std::size_t>(2 * max_datagram_size, max_datagram_size)),
      send_quantum_(std::max<std::size_t>(2 * max_datagram_size, max_datagram_size)) {
    bandwidth_filter_cycle_.fill(std::numeric_limits<std::uint64_t>::max());
    extra_acked_round_.fill(std::numeric_limits<std::uint64_t>::max());
    enter_startup();
    const auto initial_rate =
        static_cast<double>(initial_cwnd_) / std::chrono::duration<double>(kInitialRtt).count();
    pacing_rate_bytes_per_second_ = kBbrStartupPacingGain * initial_rate;
}

bool BbrCongestionController::can_send_ack_eliciting(std::size_t bytes) const {
    return bytes_in_flight_ + bytes <= congestion_window_;
}

std::optional<QuicCoreTimePoint> BbrCongestionController::next_send_time(std::size_t bytes) const {
    if (bytes == 0 || !pacing_budget_timestamp_.has_value()) {
        return std::nullopt;
    }

    const auto budget = std::min(pacing_budget_bytes_, pacing_budget_cap());
    if (bytes <= budget) {
        return pacing_budget_timestamp_;
    }

    const auto rate = pacing_rate_bytes_per_second();
    if (rate <= 0.0) {
        return std::nullopt;
    }

    const auto deficit = static_cast<double>(bytes - budget);
    const auto delay =
        std::chrono::ceil<QuicCoreClock::duration>(std::chrono::duration<double>(deficit / rate));
    return *pacing_budget_timestamp_ + delay;
}

void BbrCongestionController::on_packet_sent(SentPacketRecord &packet) {
    if (!packet.ack_eliciting) {
        return;
    }

    maybe_mark_connection_app_limited(packet.app_limited);
    packet.app_limited = is_app_limited();
    handle_restart_from_idle(packet.sent_time);
    if (!first_sent_time_.has_value() || bytes_in_flight_ == 0) {
        first_sent_time_ = packet.sent_time;
        delivered_time_ = packet.sent_time;
    }

    packet.first_sent_time = first_sent_time_.value_or(packet.sent_time);
    packet.delivered_time = delivered_time_.value_or(packet.sent_time);
    packet.delivered = total_delivered_;
    packet.tx_in_flight = bytes_in_flight_ + packet.bytes_in_flight;
    packet.lost = total_lost_;
    bytes_in_flight_ += packet.bytes_in_flight;
    consume_pacing_budget(packet.bytes_in_flight, packet.sent_time);
}

void BbrCongestionController::on_packets_acked(std::span<const SentPacketRecord> packets,
                                               bool app_limited, QuicCoreTimePoint now,
                                               const RecoveryRttState &rtt_state) {
    maybe_mark_connection_app_limited(app_limited);
    auto rs = generate_rate_sample(packets, app_limited, now, rtt_state);
    if (rs.has_spurious_loss) {
        handle_spurious_loss_detection(now);
        rs.exit_loss_recovery = true;
    }

    if (!rs.has_newly_acked) {
        if (rs.exit_loss_recovery) {
            restore_cwnd();
            recovery_start_time_.reset();
        }
        return;
    }

    update_latest_delivery_signals(rs);
    update_congestion_signals(rs);
    update_ack_aggregation(rs, now);
    check_full_bw_reached(rs);
    check_startup_done();
    check_drain_done(now);
    update_probe_bw_cycle_phase(rs, now);
    update_min_rtt(rs, now);
    check_probe_rtt(rs, now);
    advance_latest_delivery_signals(rs);
    bound_bw_for_model();

    if (rs.exit_loss_recovery) {
        restore_cwnd();
        recovery_start_time_.reset();
    }

    set_pacing_rate();
    set_send_quantum();
    set_cwnd(rs);

    if (rs.delivered > 0) {
        idle_restart_ = false;
    }
}

void BbrCongestionController::on_packets_lost(std::span<const SentPacketRecord> packets) {
    for (const auto &packet : packets) {
        if (packet.in_flight) {
            bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                                   ? 0
                                   : bytes_in_flight_ - packet.bytes_in_flight;
        }
        if (packet.bytes_in_flight == 0) {
            continue;
        }

        total_lost_ += packet.bytes_in_flight;
        note_loss(packet);
        if (!bw_probe_samples_) {
            continue;
        }

        RateSample rs;
        rs.tx_in_flight = packet.tx_in_flight;
        rs.lost =
            total_lost_ > packet.lost ? static_cast<std::size_t>(total_lost_ - packet.lost) : 0;
        rs.is_app_limited = packet.app_limited;
        if (is_inflight_too_high(rs)) {
            rs.tx_in_flight = inflight_at_loss(rs, packet);
            handle_inflight_too_high(rs);
        }
    }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void BbrCongestionController::on_loss_event(QuicCoreTimePoint loss_detection_time,
                                            QuicCoreTimePoint largest_lost_sent_time) {
    if (!recovery_start_time_.has_value() || largest_lost_sent_time > *recovery_start_time_) {
        recovery_start_time_ = loss_detection_time;
        recovery_round_start_ = round_count_;
        save_cwnd();
        save_state_upon_loss();
    }

    if (pending_probe_bw_down_ && mode_ == Mode::probe_bw_up) {
        start_probe_bw_down(loss_detection_time);
    }
    pending_probe_bw_down_ = false;
}

void BbrCongestionController::on_persistent_congestion() {
    const auto max_datagram_size = max_datagram_size_;
    *this = BbrCongestionController(max_datagram_size);
    congestion_window_ = minimum_window();
    max_inflight_ = minimum_window();
}

std::size_t BbrCongestionController::congestion_window() const {
    return congestion_window_;
}

std::size_t BbrCongestionController::bytes_in_flight() const {
    return bytes_in_flight_;
}

void BbrCongestionController::handle_restart_from_idle(QuicCoreTimePoint now) {
    if (bytes_in_flight_ != 0 || !is_app_limited()) {
        return;
    }

    idle_restart_ = true;
    extra_acked_interval_start_ = now;
    extra_acked_delivered_ = 0;
    if (is_in_probe_bw_state() && bandwidth_bytes_per_second_ > 0.0) {
        pacing_rate_bytes_per_second_ = bandwidth_bytes_per_second_ * kBbrPacingMargin;
    } else if (mode_ == Mode::probe_rtt) {
        check_probe_rtt_done(now);
    }
}

void BbrCongestionController::mark_connection_app_limited() {
    app_limited_until_delivered_ = std::max(
        app_limited_until_delivered_,
        std::max(saturating_add_u64(total_delivered_, bytes_in_flight_), std::uint64_t{1}));
}

void BbrCongestionController::maybe_mark_connection_app_limited(bool no_pending_data) {
    if (!no_pending_data || bytes_in_flight_ >= congestion_window_) {
        return;
    }
    mark_connection_app_limited();
}

BbrCongestionController::RateSample
BbrCongestionController::generate_rate_sample(std::span<const SentPacketRecord> packets,
                                              bool app_limited, QuicCoreTimePoint now,
                                              const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    RateSample rs;
    const SentPacketRecord *sample_packet = nullptr;

    for (const auto &packet : packets) {
        if (packet.declared_lost) {
            rs.has_spurious_loss = true;
            rs.exit_loss_recovery = true;
            continue;
        }

        if (packet.in_flight) {
            rs.newly_acked += packet.bytes_in_flight;
            bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                                   ? 0
                                   : bytes_in_flight_ - packet.bytes_in_flight;
        }
        if (!packet.ack_eliciting || packet.bytes_in_flight == 0) {
            continue;
        }
        if (sample_packet == nullptr || packet.sent_time > sample_packet->sent_time ||
            (packet.sent_time == sample_packet->sent_time &&
             packet.packet_number > sample_packet->packet_number)) {
            sample_packet = &packet;
        }
        if (recovery_start_time_.has_value() && packet.sent_time > *recovery_start_time_) {
            rs.exit_loss_recovery = true;
        }
    }

    total_delivered_ += rs.newly_acked;
    if (is_app_limited() && total_delivered_ > app_limited_until_delivered_) {
        app_limited_until_delivered_ = 0;
    }
    delivered_time_ = now;
    if (sample_packet != nullptr) {
        first_sent_time_ = sample_packet->sent_time;
    } else if (bytes_in_flight_ == 0) {
        first_sent_time_ = now;
    }

    rs.has_newly_acked = sample_packet != nullptr;
    if (sample_packet == nullptr) {
        return rs;
    }

    rs.prior_delivered = sample_packet->delivered;
    rs.delivered = total_delivered_ - sample_packet->delivered;
    rs.tx_in_flight = sample_packet->tx_in_flight;
    rs.is_app_limited = sample_packet->app_limited || mode_ == Mode::probe_rtt;
    if (rtt_state.latest_rtt.has_value()) {
        rs.rtt = *rtt_state.latest_rtt;
    } else if (rtt_state.min_rtt.has_value()) {
        rs.rtt = *rtt_state.min_rtt;
    }
    rs.delivery_rate_bytes_per_second =
        sample_bandwidth_bytes_per_second(*sample_packet, total_delivered_, now, min_rtt_);
    return rs;
}

void BbrCongestionController::update_round(std::uint64_t prior_delivered) {
    if (prior_delivered >= next_round_delivered_) {
        start_round();
        ++round_count_;
        ++rounds_since_bw_probe_;
        round_start_ = true;
        return;
    }

    round_start_ = false;
}

void BbrCongestionController::start_round() {
    next_round_delivered_ = total_delivered_;
}

void BbrCongestionController::update_max_bw(const RateSample &rs) {
    update_round(rs.prior_delivered);
    if (rs.delivery_rate_bytes_per_second <= 0.0 ||
        (rs.delivery_rate_bytes_per_second < max_bandwidth_bytes_per_second_ &&
         rs.is_app_limited)) {
        return;
    }

    const auto slot = cycle_count_ % bandwidth_filter_.size();
    if (bandwidth_filter_cycle_[slot] != cycle_count_) {
        bandwidth_filter_cycle_[slot] = cycle_count_;
        bandwidth_filter_[slot] = 0.0;
    }
    bandwidth_filter_[slot] = std::max(bandwidth_filter_[slot], rs.delivery_rate_bytes_per_second);

    max_bandwidth_bytes_per_second_ = 0.0;
    for (std::size_t i = 0; i < bandwidth_filter_.size(); ++i) {
        if (bandwidth_filter_cycle_[i] == std::numeric_limits<std::uint64_t>::max()) {
            continue;
        }
        if (cycle_count_ < bandwidth_filter_cycle_[i] ||
            cycle_count_ - bandwidth_filter_cycle_[i] >= bandwidth_filter_.size()) {
            continue;
        }
        max_bandwidth_bytes_per_second_ =
            std::max(max_bandwidth_bytes_per_second_, bandwidth_filter_[i]);
    }
}

void BbrCongestionController::advance_max_bw_filter() {
    ++cycle_count_;
    const auto slot = cycle_count_ % bandwidth_filter_.size();
    bandwidth_filter_cycle_[slot] = cycle_count_;
    bandwidth_filter_[slot] = 0.0;
    max_bandwidth_bytes_per_second_ = 0.0;
    for (std::size_t i = 0; i < bandwidth_filter_.size(); ++i) {
        if (bandwidth_filter_cycle_[i] == std::numeric_limits<std::uint64_t>::max()) {
            continue;
        }
        if (cycle_count_ - bandwidth_filter_cycle_[i] >= bandwidth_filter_.size()) {
            continue;
        }
        max_bandwidth_bytes_per_second_ =
            std::max(max_bandwidth_bytes_per_second_, bandwidth_filter_[i]);
    }
}

void BbrCongestionController::update_latest_delivery_signals(const RateSample &rs) {
    loss_round_start_ = false;
    bw_latest_ = std::max(bw_latest_, rs.delivery_rate_bytes_per_second);
    inflight_latest_ =
        std::max(inflight_latest_, clamp_to_size_t(static_cast<double>(rs.delivered)));
    if (loss_round_delivered_.has_value() && rs.prior_delivered >= *loss_round_delivered_) {
        loss_round_delivered_ = total_delivered_;
        loss_round_start_ = true;
    }
}

void BbrCongestionController::update_congestion_signals(const RateSample &rs) {
    update_max_bw(rs);
    previous_round_had_loss_ = false;
    if (!loss_round_start_) {
        return;
    }

    previous_round_had_loss_ = loss_in_round_;
    previous_round_lost_bytes_ = loss_bytes_in_round_;
    previous_round_loss_events_ = loss_events_in_round_;

    if (!is_probing_bw() && loss_in_round_) {
        if (std::isinf(bw_shortterm_)) {
            bw_shortterm_ = max_bandwidth_bytes_per_second_;
        }
        if (inflight_shortterm_ == std::numeric_limits<std::size_t>::max()) {
            inflight_shortterm_ = congestion_window_;
        }
        bw_shortterm_ = std::max(bw_latest_, kBbrBeta * bw_shortterm_);
        inflight_shortterm_ = std::max(
            inflight_latest_, clamp_to_size_t(kBbrBeta * static_cast<double>(inflight_shortterm_)));
    }

    loss_in_round_ = false;
    loss_bytes_in_round_ = 0;
    loss_events_in_round_ = 0;
    last_lost_packet_number_.reset();
}

void BbrCongestionController::update_ack_aggregation(const RateSample &rs, QuicCoreTimePoint now) {
    if (!extra_acked_interval_start_.has_value()) {
        extra_acked_interval_start_ = now;
    }

    auto expected_delivered =
        bandwidth_bytes_per_second_ *
        std::chrono::duration<double>(now - *extra_acked_interval_start_).count();
    if (static_cast<double>(extra_acked_delivered_) <= expected_delivered) {
        extra_acked_delivered_ = 0;
        extra_acked_interval_start_ = now;
        expected_delivered = 0.0;
    }

    extra_acked_delivered_ = saturating_add(extra_acked_delivered_, rs.newly_acked);
    auto extra = static_cast<double>(extra_acked_delivered_) - expected_delivered;
    extra = std::max(0.0, std::min(extra, static_cast<double>(congestion_window_)));

    const auto slot = round_count_ % extra_acked_filter_.size();
    if (extra_acked_round_[slot] != round_count_) {
        extra_acked_round_[slot] = round_count_;
        extra_acked_filter_[slot] = 0;
    }
    extra_acked_filter_[slot] = std::max(extra_acked_filter_[slot], clamp_to_size_t(extra));

    const std::uint64_t filter_len = full_bw_reached_ ? kBbrExtraAckedFilterLen : 1;
    extra_acked_ = 0;
    for (std::size_t i = 0; i < extra_acked_filter_.size(); ++i) {
        if (extra_acked_round_[i] == std::numeric_limits<std::uint64_t>::max()) {
            continue;
        }
        if (round_count_ < extra_acked_round_[i] ||
            round_count_ - extra_acked_round_[i] >= filter_len) {
            continue;
        }
        extra_acked_ = std::max(extra_acked_, extra_acked_filter_[i]);
    }
}

void BbrCongestionController::check_full_bw_reached(const RateSample &rs) {
    if (full_bw_now_ || !round_start_ || rs.is_app_limited) {
        return;
    }

    if (rs.delivery_rate_bytes_per_second >=
        full_bandwidth_bytes_per_second_ * kBbrFullBandwidthGrowthTarget) {
        reset_full_bw();
        full_bandwidth_bytes_per_second_ = rs.delivery_rate_bytes_per_second;
        return;
    }

    if (full_bandwidth_rounds_without_growth_ < std::numeric_limits<std::uint8_t>::max()) {
        ++full_bandwidth_rounds_without_growth_;
    }
    full_bw_now_ = full_bandwidth_rounds_without_growth_ >= kBbrFullBandwidthRoundLimit;
    if (full_bw_now_) {
        full_bw_reached_ = true;
    }
}

void BbrCongestionController::check_startup_done() {
    check_startup_high_loss();
    if (mode_ == Mode::startup && full_bw_reached_) {
        enter_drain();
    }
}

void BbrCongestionController::check_startup_high_loss() {
    if (mode_ != Mode::startup || !loss_round_start_ || !previous_round_had_loss_ ||
        !recovery_start_time_.has_value() || round_count_ <= recovery_round_start_) {
        return;
    }

    const auto loss_base = std::max(inflight_latest_, target_inflight());
    if (loss_base == 0) {
        return;
    }
    const auto high_loss = static_cast<double>(previous_round_lost_bytes_) >
                           static_cast<double>(loss_base) * kBbrLossThresh;
    if (!high_loss || previous_round_loss_events_ < kBbrStartupFullLossCount) {
        return;
    }

    full_bw_now_ = true;
    full_bw_reached_ = true;
    inflight_longterm_ = std::max(bdp_bytes(1.0), inflight_latest_);
    enter_drain();
}

void BbrCongestionController::check_drain_done(QuicCoreTimePoint now) {
    static_cast<void>(now);
    if (mode_ == Mode::drain &&
        (bytes_in_flight_ <= inflight(1.0) || round_count_ > drain_start_round_ + 3)) {
        enter_probe_bw(now);
    }
}

void BbrCongestionController::update_probe_bw_cycle_phase(const RateSample &rs,
                                                          QuicCoreTimePoint now) {
    if (!full_bw_reached_) {
        return;
    }
    adapt_long_term_model(rs);
    if (!is_in_probe_bw_state()) {
        return;
    }

    switch (mode_) {
    case Mode::probe_bw_down:
        if (is_time_to_probe_bw(now)) {
            return;
        }
        if (is_time_to_cruise()) {
            start_probe_bw_cruise();
        }
        break;
    case Mode::probe_bw_cruise:
        static_cast<void>(is_time_to_probe_bw(now));
        break;
    case Mode::probe_bw_refill:
        if (round_start_) {
            bw_probe_samples_ = true;
            start_probe_bw_up(rs, now);
        }
        break;
    case Mode::probe_bw_up:
        if (is_time_to_go_down(rs)) {
            start_probe_bw_down(now);
        }
        break;
    case Mode::startup:
    case Mode::drain:
    case Mode::probe_rtt:
        break;
    }
}

void BbrCongestionController::adapt_long_term_model(const RateSample &rs) {
    if (ack_phase_ == AckPhase::probe_starting && round_start_) {
        ack_phase_ = AckPhase::probe_feedback;
    }
    if (ack_phase_ == AckPhase::probe_stopping && round_start_) {
        if (is_in_probe_bw_state() && !rs.is_app_limited) {
            advance_max_bw_filter();
        }
    }

    if (is_inflight_too_high(rs)) {
        return;
    }
    if (inflight_longterm_ == std::numeric_limits<std::size_t>::max()) {
        return;
    }
    if (rs.tx_in_flight > inflight_longterm_) {
        inflight_longterm_ = rs.tx_in_flight;
    }
    if (mode_ == Mode::probe_bw_up) {
        probe_inflight_longterm_upward(rs);
    }
}

void BbrCongestionController::raise_inflight_longterm_slope() {
    const auto growth_this_round = std::uint64_t{1} << bw_probe_up_rounds_;
    if (bw_probe_up_rounds_ < 30) {
        ++bw_probe_up_rounds_;
    }
    const auto cwnd_packets = packets_for_bytes(congestion_window_);
    probe_up_cnt_ = std::max<std::uint64_t>(cwnd_packets / growth_this_round, 1);
}

void BbrCongestionController::probe_inflight_longterm_upward(const RateSample &rs) {
    if (!is_cwnd_limited() || congestion_window_ < inflight_longterm_) {
        return;
    }

    bw_probe_up_acks_ += packets_for_bytes(rs.newly_acked);
    if (bw_probe_up_acks_ >= probe_up_cnt_) {
        const auto delta_packets = bw_probe_up_acks_ / probe_up_cnt_;
        bw_probe_up_acks_ -= delta_packets * probe_up_cnt_;
        inflight_longterm_ = saturating_add(inflight_longterm_, delta_packets * max_datagram_size_);
    }
    if (round_start_) {
        raise_inflight_longterm_slope();
    }
}

void BbrCongestionController::update_min_rtt(const RateSample &rs, QuicCoreTimePoint now) {
    probe_rtt_expired_ =
        probe_rtt_min_stamp_.has_value() && now > *probe_rtt_min_stamp_ + kBbrProbeRttInterval;
    if (rs.rtt.has_value() && (!probe_rtt_min_delay_.has_value() ||
                               *rs.rtt < *probe_rtt_min_delay_ || probe_rtt_expired_)) {
        probe_rtt_min_delay_ = *rs.rtt;
        probe_rtt_min_stamp_ = now;
    }

    const auto min_rtt_expired =
        min_rtt_stamp_.has_value() && now > *min_rtt_stamp_ + kBbrMinRttWindow;
    if (probe_rtt_min_delay_.has_value() &&
        (!min_rtt_.has_value() || *probe_rtt_min_delay_ < *min_rtt_ || min_rtt_expired)) {
        min_rtt_ = *probe_rtt_min_delay_;
        min_rtt_stamp_ = probe_rtt_min_stamp_;
    }
}

void BbrCongestionController::check_probe_rtt(const RateSample &rs, QuicCoreTimePoint now) {
    if (mode_ != Mode::probe_rtt && probe_rtt_expired_ && !idle_restart_) {
        enter_probe_rtt();
        save_cwnd();
        probe_rtt_done_stamp_.reset();
        ack_phase_ = AckPhase::probe_stopping;
        start_round();
    }
    if (mode_ == Mode::probe_rtt) {
        handle_probe_rtt(now);
    }
    if (rs.delivered > 0) {
        idle_restart_ = false;
    }
}

void BbrCongestionController::handle_probe_rtt(QuicCoreTimePoint now) {
    mark_connection_app_limited();
    if (!probe_rtt_done_stamp_.has_value() && bytes_in_flight_ <= probe_rtt_cwnd()) {
        probe_rtt_done_stamp_ = now + kBbrProbeRttDuration;
        probe_rtt_round_done_ = false;
        start_round();
        return;
    }
    if (probe_rtt_done_stamp_.has_value()) {
        if (round_start_) {
            probe_rtt_round_done_ = true;
        }
        if (probe_rtt_round_done_) {
            check_probe_rtt_done(now);
        }
    }
}

void BbrCongestionController::check_probe_rtt_done(QuicCoreTimePoint now) {
    if (probe_rtt_done_stamp_.has_value() && now > *probe_rtt_done_stamp_) {
        probe_rtt_min_stamp_ = now;
        restore_cwnd();
        exit_probe_rtt(now);
        probe_rtt_done_stamp_.reset();
        probe_rtt_round_done_ = false;
    }
}

void BbrCongestionController::advance_latest_delivery_signals(const RateSample &rs) {
    if (loss_round_start_) {
        bw_latest_ = rs.delivery_rate_bytes_per_second;
        inflight_latest_ = clamp_to_size_t(static_cast<double>(rs.delivered));
    }
}

void BbrCongestionController::bound_bw_for_model() {
    bandwidth_bytes_per_second_ = std::min(max_bandwidth_bytes_per_second_, bw_shortterm_);
    if (std::isinf(bw_shortterm_)) {
        bandwidth_bytes_per_second_ = max_bandwidth_bytes_per_second_;
    }
}

void BbrCongestionController::set_pacing_rate_with_gain(double gain) {
    if (bandwidth_bytes_per_second_ <= 0.0) {
        return;
    }

    const auto rate = gain * bandwidth_bytes_per_second_ * kBbrPacingMargin;
    if (full_bw_reached_ || rate > pacing_rate_bytes_per_second_) {
        pacing_rate_bytes_per_second_ = rate;
    }
}

void BbrCongestionController::set_pacing_rate() {
    set_pacing_rate_with_gain(pacing_gain_);
}

void BbrCongestionController::set_send_quantum() {
    const auto quantum =
        clamp_to_size_t(pacing_rate_bytes_per_second_ *
                        std::chrono::duration<double>(kBbrSendQuantumWindow).count());
    send_quantum_ = std::clamp(quantum, 2 * max_datagram_size_, kBbrMaxSendQuantum);
}

void BbrCongestionController::update_max_inflight() {
    if (min_rtt_.has_value()) {
        bdp_ = bandwidth_bytes_per_second_ * std::chrono::duration<double>(*min_rtt_).count();
    } else {
        bdp_ = static_cast<double>(initial_cwnd_);
    }
    offload_budget_ = send_quantum_;
    auto inflight_cap = saturating_add(bdp_bytes(cwnd_gain_), extra_acked_);
    max_inflight_ = quantization_budget(inflight_cap);
}

void BbrCongestionController::bound_cwnd_for_probe_rtt() {
    if (mode_ == Mode::probe_rtt) {
        congestion_window_ = std::min(congestion_window_, probe_rtt_cwnd());
    }
}

void BbrCongestionController::bound_cwnd_for_model() {
    auto cap = std::numeric_limits<std::size_t>::max();
    if (is_in_probe_bw_state() && mode_ != Mode::probe_bw_cruise) {
        cap = inflight_longterm_;
    } else if (mode_ == Mode::probe_rtt || mode_ == Mode::probe_bw_cruise) {
        cap = inflight_with_headroom();
    }

    cap = std::min(cap, inflight_shortterm_);
    cap = std::max(cap, minimum_window());
    congestion_window_ = std::min(congestion_window_, cap);
}

void BbrCongestionController::set_cwnd(const RateSample &rs) {
    update_max_inflight();
    if (full_bw_reached_) {
        congestion_window_ =
            std::min(saturating_add(congestion_window_, rs.newly_acked), max_inflight_);
    } else if (congestion_window_ < max_inflight_ || total_delivered_ < initial_cwnd_) {
        congestion_window_ = saturating_add(congestion_window_, rs.newly_acked);
    }
    congestion_window_ = std::max(congestion_window_, minimum_window());
    bound_cwnd_for_probe_rtt();
    bound_cwnd_for_model();
}

void BbrCongestionController::note_loss(const SentPacketRecord &packet) {
    if (!loss_in_round_) {
        loss_round_delivered_ = total_delivered_;
        save_state_upon_loss();
        last_lost_packet_number_.reset();
    }

    loss_in_round_ = true;
    loss_bytes_in_round_ = saturating_add(loss_bytes_in_round_, packet.bytes_in_flight);
    if (!last_lost_packet_number_.has_value() ||
        packet.packet_number != *last_lost_packet_number_ + 1) {
        ++loss_events_in_round_;
    }
    last_lost_packet_number_ = packet.packet_number;
}

void BbrCongestionController::handle_inflight_too_high(const RateSample &rs) {
    bw_probe_samples_ = false;
    if (!rs.is_app_limited) {
        inflight_longterm_ = std::max(
            rs.tx_in_flight, clamp_to_size_t(static_cast<double>(target_inflight()) * kBbrBeta));
    }
    if (mode_ == Mode::probe_bw_up) {
        pending_probe_bw_down_ = true;
    }
}

void BbrCongestionController::enter_startup() {
    mode_ = Mode::startup;
    pacing_gain_ = kBbrStartupPacingGain;
    cwnd_gain_ = kBbrDefaultCwndGain;
}

void BbrCongestionController::enter_drain() {
    mode_ = Mode::drain;
    pacing_gain_ = kBbrDrainPacingGain;
    cwnd_gain_ = kBbrDefaultCwndGain;
    drain_start_round_ = round_count_;
}

void BbrCongestionController::enter_probe_bw(QuicCoreTimePoint now) {
    cwnd_gain_ = kBbrDefaultCwndGain;
    start_probe_bw_down(now);
}

void BbrCongestionController::enter_probe_rtt() {
    mode_ = Mode::probe_rtt;
    pacing_gain_ = kBbrProbeRttPacingGain;
    cwnd_gain_ = kBbrProbeRttCwndGain;
}

void BbrCongestionController::exit_probe_rtt(QuicCoreTimePoint now) {
    reset_short_term_model();
    if (full_bw_reached_) {
        start_probe_bw_down(now);
        start_probe_bw_cruise();
        return;
    }
    enter_startup();
}

void BbrCongestionController::start_probe_bw_down(QuicCoreTimePoint now) {
    reset_congestion_signals();
    probe_up_cnt_ = std::numeric_limits<std::uint64_t>::max();
    pick_probe_wait();
    cycle_stamp_ = now;
    ack_phase_ = AckPhase::probe_stopping;
    start_round();
    mode_ = Mode::probe_bw_down;
    pacing_gain_ = kBbrProbeBwDownPacingGain;
    cwnd_gain_ = kBbrDefaultCwndGain;
    bw_probe_samples_ = false;
}

void BbrCongestionController::start_probe_bw_cruise() {
    mode_ = Mode::probe_bw_cruise;
    pacing_gain_ = kBbrProbeBwCruisePacingGain;
    cwnd_gain_ = kBbrDefaultCwndGain;
}

void BbrCongestionController::start_probe_bw_refill() {
    reset_short_term_model();
    bw_probe_up_rounds_ = 0;
    bw_probe_up_acks_ = 0;
    ack_phase_ = AckPhase::refilling;
    start_round();
    mode_ = Mode::probe_bw_refill;
    pacing_gain_ = kBbrProbeBwRefillPacingGain;
    cwnd_gain_ = kBbrDefaultCwndGain;
    bw_probe_samples_ = false;
}

void BbrCongestionController::start_probe_bw_up(const RateSample &rs, QuicCoreTimePoint now) {
    static_cast<void>(now);
    ack_phase_ = AckPhase::probe_starting;
    start_round();
    reset_full_bw();
    full_bandwidth_bytes_per_second_ = rs.delivery_rate_bytes_per_second;
    mode_ = Mode::probe_bw_up;
    pacing_gain_ = kBbrProbeBwUpPacingGain;
    cwnd_gain_ = kBbrProbeBwUpCwndGain;
    bw_probe_samples_ = true;
    raise_inflight_longterm_slope();
}

void BbrCongestionController::pick_probe_wait() {
    rounds_since_bw_probe_ = next_random() & 1u;
    bw_probe_wait_ = std::chrono::seconds{2} + std::chrono::milliseconds{next_random() % 1000u};
}

void BbrCongestionController::reset_full_bw() {
    full_bandwidth_bytes_per_second_ = 0.0;
    full_bandwidth_rounds_without_growth_ = 0;
    full_bw_now_ = false;
}

void BbrCongestionController::reset_congestion_signals() {
    loss_in_round_ = false;
    loss_round_delivered_.reset();
    loss_round_start_ = false;
    loss_bytes_in_round_ = 0;
    previous_round_lost_bytes_ = 0;
    loss_events_in_round_ = 0;
    previous_round_loss_events_ = 0;
    previous_round_had_loss_ = false;
    last_lost_packet_number_.reset();
    bw_latest_ = 0.0;
    inflight_latest_ = 0;
}

void BbrCongestionController::reset_short_term_model() {
    bw_shortterm_ = std::numeric_limits<double>::infinity();
    inflight_shortterm_ = std::numeric_limits<std::size_t>::max();
}

void BbrCongestionController::save_cwnd() {
    if (!recovery_start_time_.has_value() && mode_ != Mode::probe_rtt) {
        prior_congestion_window_ = congestion_window_;
        return;
    }
    prior_congestion_window_ = std::max(prior_congestion_window_.value_or(0), congestion_window_);
}

void BbrCongestionController::restore_cwnd() {
    congestion_window_ = std::max(congestion_window_, prior_congestion_window_.value_or(0));
}

void BbrCongestionController::save_state_upon_loss() {
    undo_state_ = mode_;
    undo_bw_shortterm_ = bw_shortterm_;
    undo_inflight_shortterm_ = inflight_shortterm_;
    undo_inflight_longterm_ = inflight_longterm_;
}

void BbrCongestionController::handle_spurious_loss_detection(QuicCoreTimePoint now) {
    loss_in_round_ = false;
    loss_bytes_in_round_ = 0;
    loss_events_in_round_ = 0;
    last_lost_packet_number_.reset();
    reset_full_bw();
    bw_shortterm_ = std::max(bw_shortterm_, undo_bw_shortterm_);
    inflight_shortterm_ = std::max(inflight_shortterm_, undo_inflight_shortterm_);
    inflight_longterm_ = std::max(inflight_longterm_, undo_inflight_longterm_);
    if (mode_ != Mode::probe_rtt && undo_state_.has_value() && mode_ != *undo_state_) {
        if (*undo_state_ == Mode::startup) {
            enter_startup();
        } else if (*undo_state_ == Mode::probe_bw_up) {
            RateSample rs;
            rs.delivery_rate_bytes_per_second = max_bandwidth_bytes_per_second_;
            start_probe_bw_up(rs, now);
        }
    }
}

bool BbrCongestionController::is_in_probe_bw_state() const {
    return mode_ == Mode::probe_bw_down || mode_ == Mode::probe_bw_cruise ||
           mode_ == Mode::probe_bw_refill || mode_ == Mode::probe_bw_up;
}

bool BbrCongestionController::is_app_limited() const {
    return app_limited_until_delivered_ != 0;
}

bool BbrCongestionController::is_probing_bw() const {
    return mode_ == Mode::startup || mode_ == Mode::probe_bw_refill || mode_ == Mode::probe_bw_up;
}

bool BbrCongestionController::is_cwnd_limited() const {
    return bytes_in_flight_ + send_quantum_ >= congestion_window_;
}

bool BbrCongestionController::has_elapsed_in_phase(QuicCoreClock::duration interval,
                                                   QuicCoreTimePoint now) const {
    return cycle_stamp_.has_value() && now > *cycle_stamp_ + interval;
}

bool BbrCongestionController::is_reno_coexistence_probe_time() const {
    return rounds_since_bw_probe_ >=
           std::min(packets_for_bytes(target_inflight()), kBbrMaxProbeBwRounds);
}

bool BbrCongestionController::is_time_to_probe_bw(QuicCoreTimePoint now) {
    if (has_elapsed_in_phase(bw_probe_wait_, now) || is_reno_coexistence_probe_time()) {
        start_probe_bw_refill();
        return true;
    }
    return false;
}

bool BbrCongestionController::is_time_to_cruise() const {
    if (bytes_in_flight_ > inflight_with_headroom()) {
        return false;
    }
    if (bytes_in_flight_ > inflight(1.0)) {
        return false;
    }
    return true;
}

bool BbrCongestionController::is_time_to_go_down(const RateSample &rs) {
    if (is_cwnd_limited() && congestion_window_ >= inflight_longterm_) {
        reset_full_bw();
        full_bandwidth_bytes_per_second_ = rs.delivery_rate_bytes_per_second;
    } else if (full_bw_now_) {
        return true;
    }
    return false;
}

bool BbrCongestionController::is_inflight_too_high(const RateSample &rs) const {
    return rs.tx_in_flight != 0 &&
           static_cast<double>(rs.lost) > static_cast<double>(rs.tx_in_flight) * kBbrLossThresh;
}

std::uint32_t BbrCongestionController::next_random() {
    random_state_ = random_state_ * 1664525u + 1013904223u;
    return random_state_;
}

std::uint64_t BbrCongestionController::packets_for_bytes(std::size_t bytes) const {
    if (bytes == 0) {
        return 0;
    }
    return (bytes + max_datagram_size_ - 1) / max_datagram_size_;
}

std::size_t BbrCongestionController::minimum_window() const {
    return kBbrMinimumWindowPackets * max_datagram_size_;
}

std::size_t BbrCongestionController::inflight_at_loss(const RateSample &rs,
                                                      const SentPacketRecord &packet) const {
    const auto size = packet.bytes_in_flight;
    const auto inflight_prev = rs.tx_in_flight > size ? rs.tx_in_flight - size : 0;
    const auto lost_prev = rs.lost > size ? rs.lost - size : 0;
    const auto lost_prefix =
        (kBbrLossThresh * static_cast<double>(inflight_prev) - static_cast<double>(lost_prev)) /
        (1.0 - kBbrLossThresh);
    const auto inflight_at_loss = static_cast<double>(inflight_prev) + std::max(0.0, lost_prefix);
    return std::max(minimum_window(), clamp_to_size_t(inflight_at_loss));
}

std::size_t BbrCongestionController::bdp_bytes(double gain) const {
    if (!min_rtt_.has_value()) {
        return initial_cwnd_;
    }
    return clamp_to_size_t(gain * bandwidth_bytes_per_second_ *
                           std::chrono::duration<double>(*min_rtt_).count());
}

std::size_t BbrCongestionController::quantization_budget(std::size_t inflight_cap) const {
    auto cap = std::max(inflight_cap, offload_budget_);
    cap = std::max(cap, minimum_window());
    if (mode_ == Mode::probe_bw_up) {
        cap = saturating_add(cap, 2 * max_datagram_size_);
    }
    return cap;
}

std::size_t BbrCongestionController::inflight(double gain) const {
    return quantization_budget(bdp_bytes(gain));
}

std::size_t BbrCongestionController::inflight_with_headroom() const {
    if (inflight_longterm_ == std::numeric_limits<std::size_t>::max()) {
        return std::numeric_limits<std::size_t>::max();
    }
    const auto headroom =
        std::max(max_datagram_size_,
                 clamp_to_size_t(kBbrHeadroom * static_cast<double>(inflight_longterm_)));
    if (headroom >= inflight_longterm_) {
        return minimum_window();
    }
    return std::max(inflight_longterm_ - headroom, minimum_window());
}

std::size_t BbrCongestionController::target_inflight() const {
    return std::min(bdp_bytes(1.0), congestion_window_);
}

std::size_t BbrCongestionController::probe_rtt_cwnd() const {
    return std::max(bdp_bytes(kBbrProbeRttCwndGain), minimum_window());
}

double BbrCongestionController::pacing_gain() const {
    return pacing_gain_;
}

double BbrCongestionController::pacing_rate_bytes_per_second() const {
    return pacing_rate_bytes_per_second_;
}

std::size_t BbrCongestionController::send_quantum() const {
    return send_quantum_;
}

std::size_t BbrCongestionController::pacing_budget_cap() const {
    return std::max(send_quantum(), max_datagram_size_);
}

std::size_t BbrCongestionController::pacing_budget_at(QuicCoreTimePoint now) const {
    const auto cap = pacing_budget_cap();
    if (!pacing_budget_timestamp_.has_value()) {
        return cap;
    }

    auto budget = std::min(pacing_budget_bytes_, cap);
    if (now <= *pacing_budget_timestamp_) {
        return budget;
    }

    const auto rate = pacing_rate_bytes_per_second();
    if (rate <= 0.0) {
        return cap;
    }

    const auto elapsed = std::chrono::duration<double>(now - *pacing_budget_timestamp_).count();
    if (elapsed <= 0.0) {
        return budget;
    }

    const auto replenished = elapsed * rate;
    if (replenished >= static_cast<double>(cap - budget)) {
        return cap;
    }
    return budget + clamp_to_size_t(replenished);
}

void BbrCongestionController::consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now) {
    const auto budget = pacing_budget_at(now);
    pacing_budget_bytes_ = bytes >= budget ? 0 : budget - bytes;
    pacing_budget_timestamp_ = now;
}

QuicCongestionController::QuicCongestionController(QuicCongestionControlAlgorithm algorithm,
                                                   std::size_t max_datagram_size)
    : storage_(algorithm == QuicCongestionControlAlgorithm::bbr
                   ? std::variant<NewRenoCongestionController, BbrCongestionController>(
                         std::in_place_type<BbrCongestionController>, max_datagram_size)
                   : std::variant<NewRenoCongestionController, BbrCongestionController>(
                         std::in_place_type<NewRenoCongestionController>, max_datagram_size)),
      congestion_window_(this, true), bytes_in_flight_(this, false) {
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
    return std::holds_alternative<BbrCongestionController>(storage_)
               ? QuicCongestionControlAlgorithm::bbr
               : QuicCongestionControlAlgorithm::newreno;
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
    std::visit(
        [&](auto &controller) {
            using Controller = std::decay_t<decltype(controller)>;
            if constexpr (std::is_same_v<Controller, NewRenoCongestionController>) {
                controller.on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
            } else {
                controller.on_packet_sent(packet);
            }
        },
        storage_);
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

std::size_t QuicCongestionController::congestion_window() const {
    return test_metric(/*congestion_window=*/true);
}

std::size_t QuicCongestionController::bytes_in_flight() const {
    return test_metric(/*congestion_window=*/false);
}

std::size_t QuicCongestionController::minimum_window() const {
    if (std::holds_alternative<NewRenoCongestionController>(storage_)) {
        return std::get<NewRenoCongestionController>(storage_).minimum_window();
    }
    return std::get<BbrCongestionController>(storage_).minimum_window();
}

void QuicCongestionController::set_test_metric(bool congestion_window, std::size_t value) {
    if (std::holds_alternative<NewRenoCongestionController>(storage_)) {
        auto &controller = std::get<NewRenoCongestionController>(storage_);
        if (congestion_window) {
            controller.congestion_window_ = value;
        } else {
            controller.bytes_in_flight_ = value;
        }
        return;
    }

    auto &controller = std::get<BbrCongestionController>(storage_);
    if (congestion_window) {
        controller.congestion_window_ = value;
    } else {
        controller.bytes_in_flight_ = value;
    }
}

std::size_t QuicCongestionController::test_metric(bool congestion_window) const {
    if (std::holds_alternative<NewRenoCongestionController>(storage_)) {
        const auto &controller = std::get<NewRenoCongestionController>(storage_);
        return congestion_window ? controller.congestion_window_ : controller.bytes_in_flight_;
    }

    const auto &controller = std::get<BbrCongestionController>(storage_);
    return congestion_window ? controller.congestion_window_ : controller.bytes_in_flight_;
}

} // namespace coquic::quic
