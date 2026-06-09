#include "src/quic/cca/bbr.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>

#include "src/quic/cca/common.h"

namespace coquic::quic {

namespace {

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
constexpr QuicCoreDuration kBbrMinRttWindow{10000000};
constexpr QuicCoreDuration kBbrProbeRttInterval{30000000};
constexpr QuicCoreDuration kBbrProbeRttDuration{200000};
constexpr std::size_t kBbrMinimumWindowPackets = 4;
constexpr QuicCoreDuration kBbrSendQuantumWindow{1000};
constexpr std::size_t kBbrMaxSendQuantum = std::size_t{64} * 1024u;
constexpr double kBbrLossThresh = 0.02;
constexpr double kBbrBeta = 0.7;
constexpr double kBbrHeadroom = 0.15;
constexpr double kBbrPacingMargin = 1.0;
constexpr std::size_t kBbrExtraAckedFilterLen = 10;
constexpr std::size_t kBbrStartupFullLossCount = 6;
constexpr std::uint64_t kBbrMaxProbeBwRounds = 63;

} // namespace

BbrCongestionController::BbrCongestionController(std::size_t max_datagram_size)
    : max_datagram_size_(max_datagram_size),
      initial_cwnd_(congestion_initial_window(max_datagram_size)),
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
    if (!can_send_ack_eliciting(bytes)) {
        return std::nullopt;
    }
    if (mode_ == Mode::startup) {
        return std::nullopt;
    }

    const auto budget = std::min(pacing_budget_bytes_, pacing_budget_cap());
    if (bytes <= budget) {
        return pacing_budget_timestamp_;
    }

    const auto rate = pacing_rate_bytes_per_second_;
    if (rate <= 0.0) {
        return std::nullopt;
    }

    return *pacing_budget_timestamp_ + congestion_pacing_delay_for_deficit(bytes - budget, rate);
}

SimpleStreamPacketSentCongestionResult BbrCongestionController::on_simple_stream_packet_sent(
    std::size_t bytes_sent, QuicCoreTimePoint sent_time, bool app_limited) {
    maybe_mark_connection_app_limited(app_limited);
    const auto packet_app_limited = is_app_limited();
    handle_restart_from_idle(sent_time);
    if (!first_sent_time_.has_value() || bytes_in_flight_ == 0) {
        first_sent_time_ = sent_time;
        delivered_time_ = sent_time;
    }

    const auto packet_first_sent_time = first_sent_time_.value_or(sent_time);
    const auto packet_delivered_time = delivered_time_.value_or(sent_time);
    const auto packet_delivered = total_delivered_;
    const auto packet_tx_in_flight = bytes_in_flight_ + bytes_sent;
    const auto packet_lost = total_lost_;
    bytes_in_flight_ += bytes_sent;
    consume_pacing_budget(bytes_sent, sent_time);
    return SimpleStreamPacketSentCongestionResult{
        .delivered = packet_delivered,
        .delivered_time = packet_delivered_time,
        .first_sent_time = packet_first_sent_time,
        .tx_in_flight = packet_tx_in_flight,
        .lost = packet_lost,
        .app_limited = packet_app_limited,
    };
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
    static_cast<void>(app_limited);
    auto rs = generate_rate_sample(packets, app_limited, now, rtt_state);
    on_rate_sample_acked(rs, now, rtt_state);
}

void BbrCongestionController::on_simple_stream_packets_acked(
    std::span<const AckedStreamPacketSample> packets, bool app_limited, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    auto rs = generate_rate_sample(packets, app_limited, now, rtt_state);
    on_rate_sample_acked(rs, now, rtt_state);
}

void BbrCongestionController::on_simple_stream_packets_acked(
    const AckedStreamPacketAggregate &packets, bool app_limited, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    static_cast<void>(packets);
    static_cast<void>(app_limited);
    static_cast<void>(now);
    static_cast<void>(rtt_state);
}

void BbrCongestionController::on_rate_sample_acked(RateSample &rs, QuicCoreTimePoint now,
                                                   const RecoveryRttState &rtt_state) {
    static_cast<void>(rtt_state);
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

    idle_restart_ &= rs.delivered == 0;
}

void BbrCongestionController::on_packets_discarded(std::span<const SentPacketRecord> packets) {
    for (const auto &packet : packets) {
        if (!packet.in_flight) {
            continue;
        }

        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
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
    app_limited_until_delivered_ =
        std::max(app_limited_until_delivered_,
                 std::max(congestion_saturating_add_u64(total_delivered_, bytes_in_flight_),
                          std::uint64_t{1}));
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
        const auto sample_sent_time =
            sample_packet != nullptr ? sample_packet->sent_time : QuicCoreTimePoint::min();
        const auto sample_packet_number =
            sample_packet != nullptr ? sample_packet->packet_number : 0;
        const bool newer_sample = (sample_packet == nullptr) ||
                                  (packet.sent_time > sample_sent_time) ||
                                  ((packet.sent_time == sample_sent_time) &&
                                   (packet.packet_number > sample_packet_number));
        if (newer_sample) {
            sample_packet = &packet;
        }
        if (packet.sent_time > recovery_start_time_.value_or(packet.sent_time)) {
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
    rs.delivery_rate_bytes_per_second = congestion_sample_bandwidth_bytes_per_second(
        *sample_packet, total_delivered_, now, min_rtt_);
    return rs;
}

BbrCongestionController::RateSample
BbrCongestionController::generate_rate_sample(std::span<const AckedStreamPacketSample> packets,
                                              bool app_limited, QuicCoreTimePoint now,
                                              const RecoveryRttState &rtt_state) {
    static_cast<void>(app_limited);
    RateSample rs;
    const AckedStreamPacketSample *sample_packet = nullptr;

    for (const auto &packet : packets) {
        rs.newly_acked += packet.bytes_in_flight;
        bytes_in_flight_ = packet.bytes_in_flight > bytes_in_flight_
                               ? 0
                               : bytes_in_flight_ - packet.bytes_in_flight;
        if (packet.bytes_in_flight == 0) {
            continue;
        }
        const auto sample_sent_time =
            sample_packet != nullptr ? sample_packet->sent_time : QuicCoreTimePoint::min();
        const auto sample_packet_number =
            sample_packet != nullptr ? sample_packet->packet_number : 0;
        const bool newer_sample = (sample_packet == nullptr) ||
                                  (packet.sent_time > sample_sent_time) ||
                                  ((packet.sent_time == sample_sent_time) &&
                                   (packet.packet_number > sample_packet_number));
        if (newer_sample) {
            sample_packet = &packet;
        }
        if (packet.sent_time > recovery_start_time_.value_or(packet.sent_time)) {
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

    SentPacketRecord sample{
        .packet_number = sample_packet->packet_number,
        .sent_time = sample_packet->sent_time,
        .ack_eliciting = true,
        .in_flight = true,
        .bytes_in_flight = sample_packet->bytes_in_flight,
        .delivered = sample_packet->delivered,
        .delivered_time = sample_packet->delivered_time,
        .first_sent_time = sample_packet->first_sent_time,
        .tx_in_flight = sample_packet->tx_in_flight,
        .lost = sample_packet->lost,
        .app_limited = sample_packet->app_limited,
    };
    rs.delivery_rate_bytes_per_second =
        congestion_sample_bandwidth_bytes_per_second(sample, total_delivered_, now, min_rtt_);
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
    const bool below_max_bw = rs.delivery_rate_bytes_per_second < max_bandwidth_bytes_per_second_;
    if (rs.delivery_rate_bytes_per_second <= 0.0 || (below_max_bw && rs.is_app_limited)) {
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
        std::max(inflight_latest_, congestion_clamp_to_size_t(static_cast<double>(rs.delivered)));
    if (rs.prior_delivered >=
        loss_round_delivered_.value_or(std::numeric_limits<std::uint64_t>::max())) {
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

    const bool update_shortterm_model = !is_probing_bw() && loss_in_round_;
    const auto shortterm_bw =
        std::isinf(bw_shortterm_) ? max_bandwidth_bytes_per_second_ : bw_shortterm_;
    const auto shortterm_inflight = inflight_shortterm_ == std::numeric_limits<std::size_t>::max()
                                        ? congestion_window_
                                        : inflight_shortterm_;
    if (update_shortterm_model) {
        bw_shortterm_ = std::max(bw_latest_, kBbrBeta * shortterm_bw);
        inflight_shortterm_ = std::max(
            inflight_latest_,
            congestion_clamp_to_size_t(kBbrBeta * static_cast<double>(shortterm_inflight)));
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

    extra_acked_delivered_ = congestion_saturating_add(extra_acked_delivered_, rs.newly_acked);
    auto extra = static_cast<double>(extra_acked_delivered_) - expected_delivered;
    extra = std::max(0.0, std::min(extra, static_cast<double>(congestion_window_)));

    const auto slot = round_count_ % extra_acked_filter_.size();
    if (extra_acked_round_[slot] != round_count_) {
        extra_acked_round_[slot] = round_count_;
        extra_acked_filter_[slot] = 0;
    }
    extra_acked_filter_[slot] =
        std::max(extra_acked_filter_[slot], congestion_clamp_to_size_t(extra));

    const std::uint64_t filter_len = full_bw_reached_ ? kBbrExtraAckedFilterLen : 1;
    extra_acked_ = 0;
    for (std::size_t i = 0; i < extra_acked_filter_.size(); ++i) {
        if (extra_acked_round_[i] == std::numeric_limits<std::uint64_t>::max()) {
            continue;
        }
        const bool outside_filter_window = (round_count_ < extra_acked_round_[i]) ||
                                           (round_count_ - extra_acked_round_[i] >= filter_len);
        if (outside_filter_window) {
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
    full_bw_reached_ |= full_bw_now_;
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
    const bool drain_enough = bytes_in_flight_ <= inflight(1.0);
    const bool drain_round_elapsed = round_count_ > drain_start_round_ + 3;
    if (mode_ == Mode::drain && (drain_enough || drain_round_elapsed)) {
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

    if (mode_ == Mode::probe_bw_down) {
        if (is_time_to_probe_bw(now)) {
            return;
        }
        if (is_time_to_cruise()) {
            start_probe_bw_cruise();
        }
    } else if (mode_ == Mode::probe_bw_cruise) {
        static_cast<void>(is_time_to_probe_bw(now));
    } else if (mode_ == Mode::probe_bw_refill) {
        if (round_start_) {
            bw_probe_samples_ = true;
            start_probe_bw_up(rs, now);
        }
    } else {
        if (is_time_to_go_down(rs)) {
            start_probe_bw_down(now);
        }
    }
}

void BbrCongestionController::adapt_long_term_model(const RateSample &rs) {
    if (ack_phase_ == AckPhase::probe_starting && round_start_) {
        ack_phase_ = AckPhase::probe_feedback;
    }
    if (ack_phase_ == AckPhase::probe_stopping && round_start_) {
        if (is_in_probe_bw_state() && !rs.is_app_limited) {
            advance_max_bw_filter();
            ack_phase_ = AckPhase::refilling;
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
        inflight_longterm_ =
            congestion_saturating_add(inflight_longterm_, delta_packets * max_datagram_size_);
    }
    if (round_start_) {
        raise_inflight_longterm_slope();
    }
}

void BbrCongestionController::update_min_rtt(const RateSample &rs, QuicCoreTimePoint now) {
    probe_rtt_expired_ = now > probe_rtt_min_stamp_.value_or(now) + kBbrProbeRttInterval;
    const auto probe_rtt_min_delay = probe_rtt_min_delay_.value_or(QuicCoreDuration::max());
    const auto sample_rtt = rs.rtt.value_or(probe_rtt_min_delay);
    const bool update_probe_rtt =
        rs.rtt.has_value() && ((sample_rtt < probe_rtt_min_delay) || probe_rtt_expired_ ||
                               !probe_rtt_min_delay_.has_value());
    if (update_probe_rtt) {
        probe_rtt_min_delay_ = sample_rtt;
        probe_rtt_min_stamp_ = now;
    }

    const auto min_rtt_expired = now > min_rtt_stamp_.value_or(now) + kBbrMinRttWindow;
    const auto min_rtt = min_rtt_.value_or(QuicCoreDuration::max());
    const auto sample_min_rtt = probe_rtt_min_delay_.value_or(min_rtt);
    const bool min_rtt_missing = !min_rtt_.has_value();
    const bool update_min_rtt_sample =
        probe_rtt_min_delay_.has_value() &&
        ((sample_min_rtt < min_rtt) || min_rtt_expired || min_rtt_missing);
    if (update_min_rtt_sample) {
        min_rtt_ = sample_min_rtt;
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
    const bool probe_rtt_done_stamp_set = probe_rtt_done_stamp_.has_value();
    probe_rtt_round_done_ = probe_rtt_round_done_ || (probe_rtt_done_stamp_set && round_start_);
    if (probe_rtt_done_stamp_set && probe_rtt_round_done_) {
        check_probe_rtt_done(now);
    }
}

void BbrCongestionController::check_probe_rtt_done(QuicCoreTimePoint now) {
    if (now > probe_rtt_done_stamp_.value_or(now) + QuicCoreClock::duration::zero()) {
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
        inflight_latest_ = congestion_clamp_to_size_t(static_cast<double>(rs.delivered));
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
        congestion_clamp_to_size_t(pacing_rate_bytes_per_second_ *
                                   std::chrono::duration<double>(kBbrSendQuantumWindow).count());
    send_quantum_ = std::clamp(quantum, 2 * max_datagram_size_, kBbrMaxSendQuantum);
}

void BbrCongestionController::update_max_inflight() {
    if (min_rtt_.has_value()) {
        bdp_ = bandwidth_bytes_per_second_ * std::chrono::duration<double>(model_min_rtt()).count();
    } else {
        bdp_ = static_cast<double>(initial_cwnd_);
    }
    offload_budget_ = send_quantum_;
    auto inflight_cap = congestion_saturating_add(bdp_bytes(cwnd_gain_), extra_acked_);
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
            std::min(congestion_saturating_add(congestion_window_, rs.newly_acked), max_inflight_);
    } else if (congestion_window_ < max_inflight_ || total_delivered_ < initial_cwnd_) {
        congestion_window_ = congestion_saturating_add(congestion_window_, rs.newly_acked);
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
    loss_bytes_in_round_ = congestion_saturating_add(loss_bytes_in_round_, packet.bytes_in_flight);
    const auto previous_lost_packet_number =
        last_lost_packet_number_.value_or(packet.packet_number > 0 ? packet.packet_number - 1 : 0);
    loss_events_in_round_ +=
        static_cast<std::size_t>(!last_lost_packet_number_.has_value() ||
                                 packet.packet_number != previous_lost_packet_number + 1);
    last_lost_packet_number_ = packet.packet_number;
}

void BbrCongestionController::handle_inflight_too_high(const RateSample &rs) {
    bw_probe_samples_ = false;
    if (!rs.is_app_limited) {
        inflight_longterm_ =
            std::max(rs.tx_in_flight,
                     congestion_clamp_to_size_t(static_cast<double>(target_inflight()) * kBbrBeta));
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
    bw_probe_wait_ = QuicCoreDuration{2000000} + QuicCoreDuration{(next_random() % 1000u) * 1000u};
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
    const auto undo_state = undo_state_.value_or(mode_);
    if (mode_ != Mode::probe_rtt && undo_state_.has_value() && mode_ != undo_state) {
        if (undo_state == Mode::startup) {
            enter_startup();
        } else if (undo_state == Mode::probe_bw_up) {
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
    return now > cycle_stamp_.value_or(now) + interval;
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
    if (rs.tx_in_flight == 0) {
        return false;
    }

    const auto loss_threshold = std::max(static_cast<double>(max_datagram_size_),
                                         static_cast<double>(rs.tx_in_flight) * kBbrLossThresh);
    return static_cast<double>(rs.lost) > loss_threshold;
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
    const auto lost_prev = rs.lost - std::min(rs.lost, size);
    const auto lost_prefix =
        (kBbrLossThresh * static_cast<double>(inflight_prev) - static_cast<double>(lost_prev)) /
        (1.0 - kBbrLossThresh);
    const auto inflight_at_loss = static_cast<double>(inflight_prev) + std::max(0.0, lost_prefix);
    return std::max(minimum_window(), congestion_clamp_to_size_t(inflight_at_loss));
}

QuicCoreDuration BbrCongestionController::model_min_rtt() const {
    return std::max(min_rtt_.value_or(kInitialRtt), kGranularity);
}

std::size_t BbrCongestionController::bdp_bytes(double gain) const {
    if (!min_rtt_.has_value()) {
        return initial_cwnd_;
    }
    return congestion_clamp_to_size_t(gain * bandwidth_bytes_per_second_ *
                                      std::chrono::duration<double>(model_min_rtt()).count());
}

std::size_t BbrCongestionController::quantization_budget(std::size_t inflight_cap) const {
    auto cap = std::max(inflight_cap, offload_budget_);
    cap = std::max(cap, minimum_window());
    if (mode_ == Mode::probe_bw_up) {
        cap = congestion_saturating_add(cap, 2 * max_datagram_size_);
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
    const auto headroom = std::max(
        max_datagram_size_,
        congestion_clamp_to_size_t(kBbrHeadroom * static_cast<double>(inflight_longterm_)));
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
    return std::max(send_quantum_, max_datagram_size_);
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

    const auto rate = pacing_rate_bytes_per_second_;
    if (rate <= 0.0) {
        return cap;
    }

    const auto missing_budget = cap - budget;
    const auto replenished =
        congestion_pacing_replenished_bytes(now - *pacing_budget_timestamp_, rate);
    if (replenished >= missing_budget) {
        return cap;
    }
    return budget + replenished;
}

void BbrCongestionController::consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now) {
    const auto budget = pacing_budget_at(now);
    pacing_budget_bytes_ = bytes >= budget ? 0 : budget - bytes;
    pacing_budget_timestamp_ = now;
}

} // namespace coquic::quic
