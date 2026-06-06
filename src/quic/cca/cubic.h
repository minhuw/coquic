#pragma once

#include <chrono>
#include <cstddef>
#include <limits>
#include <optional>
#include <span>

#include "src/quic/cca/common.h"
#include "src/quic/transport/recovery.h"

namespace coquic::quic {

class QuicCongestionController;

class CubicCongestionController {
  public:
    explicit CubicCongestionController(std::size_t max_datagram_size,
                                       bool enable_hystart_plus_plus = true);

    bool can_send_ack_eliciting(std::size_t bytes) const;
    std::optional<QuicCoreTimePoint> next_send_time(std::size_t bytes) const;
    void on_packet_sent(std::size_t bytes_sent, bool ack_eliciting);
    void on_packet_sent(SentPacketRecord &packet);
    void on_packets_acked(std::span<const SentPacketRecord> packets, bool app_limited);
    void on_packets_acked(std::span<const SentPacketRecord> packets, bool app_limited,
                          QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    void on_simple_stream_packets_acked(std::span<const AckedStreamPacketSample> packets,
                                        bool app_limited, QuicCoreTimePoint now,
                                        const RecoveryRttState &rtt_state);
    void on_packets_discarded(std::span<const SentPacketRecord> packets);
    void on_packets_lost(std::span<const SentPacketRecord> packets);
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void on_loss_event(QuicCoreTimePoint loss_detection_time,
                       QuicCoreTimePoint largest_lost_sent_time);
    void on_persistent_congestion();

    std::size_t congestion_window() const;
    std::size_t bytes_in_flight() const;

  private:
    friend class QuicCongestionController;

    std::size_t minimum_window() const;
    bool pacing_active() const;
    void update_pacing_rate(const RecoveryRttState &rtt_state);
    bool should_start_pacing(std::span<const SentPacketRecord> packets) const;
    std::size_t pacing_budget_cap() const;
    std::size_t pacing_budget_at(QuicCoreTimePoint now) const;
    void consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now);
    bool in_recovery(const SentPacketRecord &packet) const;
    void reset_epoch(QuicCoreTimePoint now);
    void enter_congestion_avoidance_from_slow_start(QuicCoreTimePoint now);
    double smss_segments(std::size_t bytes) const;
    std::size_t bytes_from_segments(double segments) const;
    double reno_alpha() const;
    double target_window_segments(QuicCoreTimePoint now, const RecoveryRttState &rtt_state) const;
    double update_reno_estimate(double acked_segments);
    void grow_congestion_avoidance(std::size_t acked_bytes, QuicCoreTimePoint now,
                                   const RecoveryRttState &rtt_state);

    std::size_t max_datagram_size_ = 1200;
    std::size_t congestion_window_ = 0;
    std::size_t bytes_in_flight_ = 0;
    std::size_t slow_start_threshold_ = std::numeric_limits<std::size_t>::max();
    std::optional<QuicCoreTimePoint> recovery_start_time_;
    double cwnd_prior_segments_ = 0.0;
    double w_max_segments_ = 0.0;
    double k_seconds_ = 0.0;
    double w_est_segments_ = 0.0;
    double congestion_avoidance_credit_segments_ = 0.0;
    std::optional<QuicCoreTimePoint> epoch_start_time_;
    QuicCoreDuration app_limited_pause_{0};
    std::optional<QuicCoreTimePoint> app_limited_start_time_;
    double pacing_rate_bytes_per_second_ = 0.0;
    std::size_t pacing_budget_bytes_ = 0;
    std::optional<QuicCoreTimePoint> pacing_budget_timestamp_;
    QuicCoreDuration pacing_smoothed_rtt_{kInitialRtt};
    std::size_t acked_stream_bytes_for_pacing_ = 0;
    HyStartPlusPlus hystart_;
};

} // namespace coquic::quic
