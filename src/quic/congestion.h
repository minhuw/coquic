#pragma once

#include <cstddef>
#include <limits>
#include <optional>
#include <span>

#include "src/quic/recovery.h"

namespace coquic::quic {

class NewRenoCongestionController {
  public:
    explicit NewRenoCongestionController(std::size_t max_datagram_size);

    bool can_send_ack_eliciting(std::size_t bytes) const;
    void on_packet_sent(std::size_t bytes_sent, bool ack_eliciting);
    void on_packets_acked(std::span<const SentPacketRecord> packets, bool app_limited);
    void on_packets_lost(std::span<const SentPacketRecord> packets);
    void on_loss_event(QuicCoreTimePoint lost_packet_sent_time);
    void on_persistent_congestion();

    std::size_t congestion_window() const;
    std::size_t bytes_in_flight() const;

  private:
    std::size_t minimum_window() const;
    bool in_recovery(const SentPacketRecord &packet) const;

    std::size_t max_datagram_size_ = 1200;
    std::size_t congestion_window_ = 0;
    std::size_t bytes_in_flight_ = 0;
    std::size_t slow_start_threshold_ = std::numeric_limits<std::size_t>::max();
    std::size_t congestion_avoidance_credit_ = 0;
    std::optional<QuicCoreTimePoint> recovery_start_time_;
};

} // namespace coquic::quic
