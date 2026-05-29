#pragma once

#include <cstddef>
#include <limits>
#include <optional>
#include <span>

#include "src/quic/cca/common.h"
#include "src/quic/recovery.h"

namespace coquic::quic {

class QuicCongestionController;

class NewRenoCongestionController {
  public:
    explicit NewRenoCongestionController(std::size_t max_datagram_size,
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
    std::size_t send_window() const;
    bool pacing_active() const;
    void update_pacing_rate(const RecoveryRttState &rtt_state);
    bool should_start_pacing(std::span<const SentPacketRecord> packets) const;
    std::size_t pacing_budget_cap() const;
    std::size_t pacing_budget_at(QuicCoreTimePoint now) const;
    void consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now);
    std::optional<QuicCoreTimePoint> recovery_boundary() const;
    bool in_recovery(const SentPacketRecord &packet) const;
    bool sent_on_or_before_recovery_boundary(
        const SentPacketRecord &packet, const std::optional<QuicCoreTimePoint> &boundary_time,
        const std::optional<std::uint64_t> &boundary_sequence) const;
    bool sent_on_or_before_recovery_boundary(
        const AckedStreamPacketSample &packet,
        const std::optional<QuicCoreTimePoint> &boundary_time,
        const std::optional<std::uint64_t> &boundary_sequence) const;
    bool sent_after_recovery_boundary(const SentPacketRecord &packet,
                                      const std::optional<QuicCoreTimePoint> &boundary_time,
                                      const std::optional<std::uint64_t> &boundary_sequence) const;
    bool sent_after_recovery_boundary(const AckedStreamPacketSample &packet,
                                      const std::optional<QuicCoreTimePoint> &boundary_time,
                                      const std::optional<std::uint64_t> &boundary_sequence) const;
    bool loss_on_or_before_last_recovery_boundary(
        QuicCoreTimePoint largest_lost_sent_time,
        std::optional<std::uint64_t> largest_lost_send_sequence) const;
    void note_recovery_delivered(std::size_t bytes);
    void maybe_restore_spurious_loss_window();
    void clear_spurious_loss_window();
    void reset_recovery_send_accounting();

    std::size_t max_datagram_size_ = 1200;
    std::size_t congestion_window_ = 0;
    std::size_t bytes_in_flight_ = 0;
    std::size_t slow_start_threshold_ = std::numeric_limits<std::size_t>::max();
    std::size_t congestion_avoidance_credit_ = 0;
    std::optional<std::size_t> prior_congestion_window_;
    std::optional<std::size_t> prior_slow_start_threshold_;
    std::optional<QuicCoreTimePoint> recovery_start_time_;
    std::optional<QuicCoreTimePoint> last_recovery_start_time_;
    std::optional<std::uint64_t> recovery_start_sequence_;
    std::optional<std::uint64_t> last_recovery_start_sequence_;
    std::size_t recovery_flight_size_ = 0;
    std::size_t recovery_delivered_bytes_ = 0;
    std::size_t recovery_sent_bytes_ = 0;
    std::size_t pending_recovery_loss_bytes_ = 0;
    std::optional<std::uint64_t> pending_largest_lost_send_sequence_;
    double pacing_rate_bytes_per_second_ = 0.0;
    std::size_t pacing_budget_bytes_ = 0;
    std::optional<QuicCoreTimePoint> pacing_budget_timestamp_;
    QuicCoreDuration pacing_smoothed_rtt_{kInitialRtt};
    std::size_t acked_stream_bytes_for_pacing_ = 0;
    HyStartPlusPlus hystart_;
};

} // namespace coquic::quic
