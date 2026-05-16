#pragma once

#include <chrono>
#include <cstddef>
#include <limits>
#include <optional>
#include <span>

#include "src/quic/cca/common.h"
#include "src/quic/recovery.h"

namespace coquic::quic {

class QuicCongestionController;

class CubicCongestionController {
  public:
    explicit CubicCongestionController(std::size_t max_datagram_size);

    bool can_send_ack_eliciting(std::size_t bytes) const;
    std::optional<QuicCoreTimePoint> next_send_time(std::size_t bytes) const;
    void on_packet_sent(std::size_t bytes_sent, bool ack_eliciting);
    void on_packet_sent(SentPacketRecord &packet);
    void on_packets_acked(std::span<const SentPacketRecord> packets, bool app_limited);
    void on_packets_acked(std::span<const SentPacketRecord> packets, bool app_limited,
                          QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
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
    bool in_recovery(const SentPacketRecord &packet) const;
    void reset_epoch(QuicCoreTimePoint now);
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
    std::optional<QuicCoreTimePoint> epoch_start_time_;
    QuicCoreDuration app_limited_pause_{0};
    std::optional<QuicCoreTimePoint> app_limited_start_time_;
    HyStartPlusPlus hystart_;
};

} // namespace coquic::quic
