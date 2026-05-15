#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <span>

#include "src/quic/recovery.h"

namespace coquic::quic {

class QuicCongestionController;

class CopaCongestionController {
  public:
    explicit CopaCongestionController(std::size_t max_datagram_size);

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

    struct CopaTarget {
        bool finite = false;
        std::size_t window = 0;
    };

    std::size_t minimum_window() const;
    std::size_t pacing_budget_cap() const;
    std::size_t pacing_budget_at(QuicCoreTimePoint now) const;
    void consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now);
    void update_rtt_model(const RecoveryRttState &rtt_state);
    CopaTarget target_window() const;
    void update_velocity(QuicCoreTimePoint now);
    void grow_slow_start(std::size_t acked_bytes, const CopaTarget &target);
    void adjust_congestion_avoidance(std::size_t acked_bytes, const CopaTarget &target,
                                     QuicCoreTimePoint now);
    void set_pacing_rate();
    void subtract_in_flight(std::span<const SentPacketRecord> packets);
    void reset_velocity();
    double smss_segments(std::size_t bytes) const;

    std::size_t max_datagram_size_ = 1200;
    std::size_t congestion_window_ = 0;
    std::size_t bytes_in_flight_ = 0;
    double delta_ = 0.5;
    bool slow_start_ = true;
    double velocity_packets_ = 1.0;
    int update_direction_ = 0;
    int previous_update_direction_ = 1;
    std::optional<std::chrono::milliseconds> latest_rtt_;
    std::optional<std::chrono::milliseconds> min_rtt_;
    std::optional<QuicCoreTimePoint> last_velocity_update_time_;
    std::optional<QuicCoreTimePoint> recovery_start_time_;
    double pacing_rate_bytes_per_second_ = 0.0;
    std::size_t send_quantum_ = 0;
    std::size_t pacing_budget_bytes_ = 0;
    std::optional<QuicCoreTimePoint> pacing_budget_timestamp_;
};

} // namespace coquic::quic
