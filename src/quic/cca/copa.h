#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <optional>
#include <span>
#include <utility>

#include "src/quic/cca/common.h"
#include "src/quic/transport/recovery.h"

namespace coquic::quic {

class QuicCongestionController;

class CopaCongestionController {
  public:
    explicit CopaCongestionController(std::size_t max_datagram_size);

    bool can_send_ack_eliciting(std::size_t bytes) const;
    std::optional<QuicCoreTimePoint> next_send_time(std::size_t bytes) const;
    SimpleStreamPacketSentCongestionResult on_simple_stream_packet_sent(std::size_t bytes_sent,
                                                                        QuicCoreTimePoint sent_time,
                                                                        bool app_limited);
    void on_packet_sent(std::size_t bytes_sent, bool ack_eliciting);
    void on_packet_sent(SentPacketRecord &packet);
    void on_simple_stream_packets_acked(std::span<const AckedStreamPacketSample> packets,
                                        bool app_limited, QuicCoreTimePoint now,
                                        const RecoveryRttState &rtt_state);
    void on_simple_stream_packets_acked(const AckedStreamPacketAggregate &packets, bool app_limited,
                                        QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
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

    class RttWindow {
      public:
        void clear();
        void add_sample(QuicCoreDuration rtt, QuicCoreTimePoint now);
        QuicCoreDuration latest_rtt() const;
        QuicCoreDuration min_rtt() const;
        QuicCoreDuration unjittered_rtt() const;

      private:
        class ExtremeWindow {
          public:
            explicit ExtremeWindow(bool find_min);

            void clear();
            void set_max_duration(QuicCoreDuration max_duration);
            void add_sample(QuicCoreDuration rtt, QuicCoreTimePoint now);
            QuicCoreDuration value() const;

          private:
            void clear_old_history(QuicCoreTimePoint now);

            bool find_min_ = true;
            QuicCoreDuration max_duration_{10000000};
            std::deque<std::pair<QuicCoreTimePoint, QuicCoreDuration>> samples_;
            std::optional<QuicCoreDuration> extreme_;
        };

        std::optional<QuicCoreDuration> smoothed_rtt_;
        std::optional<QuicCoreDuration> latest_rtt_;
        ExtremeWindow min_rtt_{true};
        ExtremeWindow unjittered_rtt_{true};
    };

    struct CopaTarget {
        bool finite = false;
        std::size_t window = 0;
    };

    std::size_t minimum_window() const;
    std::size_t pacing_budget_cap() const;
    std::size_t pacing_budget_at(QuicCoreTimePoint now) const;
    void consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now);
    void update_rtt_model(const RecoveryRttState &rtt_state);
    void update_rtt_model(const RecoveryRttState &rtt_state, QuicCoreTimePoint now);
    void apply_acked_bytes(std::size_t acked_bytes, bool exit_recovery, QuicCoreTimePoint now,
                           const RecoveryRttState &rtt_state);
    CopaTarget target_window() const;
    void update_velocity(QuicCoreTimePoint now);
    void grow_slow_start(std::size_t acked_bytes, const CopaTarget &target);
    void adjust_congestion_avoidance(std::size_t acked_bytes, const CopaTarget &target,
                                     QuicCoreTimePoint now);
    void set_pacing_rate();
    void set_send_quantum();
    void subtract_in_flight(std::span<const SentPacketRecord> packets);
    void reset_velocity();
    void sync_congestion_window_segments();
    void set_congestion_window_segments(double segments);
    std::size_t smss_segment_count(std::size_t bytes) const;
    double smss_segments(std::size_t bytes) const;

    std::size_t max_datagram_size_ = 1200;
    std::size_t congestion_window_ = 0;
    double congestion_window_segments_ = 0.0;
    std::size_t bytes_in_flight_ = 0;
    double delta_ = 0.05;
    bool slow_start_ = true;
    bool startup_probe_complete_ = false;
    std::size_t slow_start_probe_segments_acked_ = 0;
    double velocity_packets_ = 1.0;
    int update_direction_ = 0;
    int previous_update_direction_ = 1;
    std::optional<QuicCoreDuration> latest_rtt_;
    std::optional<QuicCoreDuration> min_rtt_;
    std::optional<QuicCoreDuration> unjittered_rtt_;
    RttWindow rtt_window_;
    std::optional<QuicCoreTimePoint> last_velocity_update_time_;
    std::optional<QuicCoreTimePoint> recovery_start_time_;
    double pacing_rate_bytes_per_second_ = 0.0;
    std::size_t send_quantum_ = 0;
    std::size_t pacing_budget_bytes_ = 0;
    std::optional<QuicCoreTimePoint> pacing_budget_timestamp_;
};

} // namespace coquic::quic
