#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "src/quic/recovery.h"

namespace coquic::quic {

class HyStartPlusPlus {
  public:
    enum class Mode : std::uint8_t {
        standard_slow_start,
        conservative_slow_start,
        congestion_avoidance,
    };

    explicit HyStartPlusPlus(std::size_t max_datagram_size);

    void on_packet_sent(SentPacketRecord &packet);
    std::size_t growth_bytes(std::size_t newly_acked_bytes) const;
    void on_slow_start_ack(std::span<const SentPacketRecord> packets,
                           const RecoveryRttState &rtt_state);
    void disable();

    bool should_exit_slow_start() const;
    bool in_conservative_slow_start() const;

  private:
    void ensure_round_started(std::uint64_t largest_acked_send_sequence);
    void maybe_enter_conservative_slow_start();
    void maybe_resume_standard_slow_start();
    void maybe_finish_round(std::uint64_t largest_acked_send_sequence);
    void start_new_round(std::uint64_t finished_round_end);

    std::size_t max_datagram_size_ = 1200;
    bool enabled_ = true;
    Mode mode_ = Mode::standard_slow_start;
    bool exit_slow_start_ = false;
    std::uint64_t next_send_sequence_ = 1;
    std::optional<std::uint64_t> latest_sent_sequence_;
    std::optional<std::uint64_t> window_end_sequence_;
    std::optional<std::uint64_t> css_entry_round_end_sequence_;
    std::optional<std::chrono::milliseconds> last_round_min_rtt_;
    std::optional<std::chrono::milliseconds> current_round_min_rtt_;
    std::optional<std::chrono::milliseconds> css_baseline_min_rtt_;
    std::uint8_t rtt_sample_count_ = 0;
    std::uint8_t css_rounds_ = 0;
};

std::size_t congestion_initial_window(std::size_t max_datagram_size);
std::size_t congestion_saturating_add(std::size_t lhs, std::size_t rhs);
std::uint64_t congestion_saturating_add_u64(std::uint64_t lhs, std::size_t rhs);
double congestion_sample_bandwidth_bytes_per_second(
    const SentPacketRecord &packet, std::uint64_t delivered_bytes, QuicCoreTimePoint now,
    const std::optional<std::chrono::milliseconds> &min_rtt);
std::size_t congestion_clamp_to_size_t(double value);
std::size_t congestion_round_to_size_t(double value);

} // namespace coquic::quic
