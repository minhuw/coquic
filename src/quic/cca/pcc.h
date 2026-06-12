#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>

#include "src/quic/cca/common.h"
#include "src/quic/transport/recovery.h"

namespace coquic::quic {

class QuicCongestionController;

class PccCongestionController {
  public:
    enum class Variant : std::uint8_t {
        allegro,
        vivace,
    };

    explicit PccCongestionController(std::size_t max_datagram_size,
                                     Variant variant = Variant::allegro);

    bool can_send_ack_eliciting(std::size_t bytes) const;
    std::optional<QuicCoreTimePoint> next_send_time(std::size_t bytes) const;
    SimpleStreamPacketSentCongestionResult on_simple_stream_packet_sent(std::size_t bytes_sent,
                                                                        QuicCoreTimePoint sent_time,
                                                                        bool app_limited);
    void on_packet_sent(std::size_t bytes_sent, bool ack_eliciting);
    void on_packet_sent(SentPacketRecord &packet);
    void on_packets_acked(std::span<const SentPacketRecord> packets, bool app_limited);
    void on_packets_acked(std::span<const SentPacketRecord> packets, bool app_limited,
                          QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    void on_simple_stream_packets_acked(std::span<const AckedStreamPacketSample> packets,
                                        bool app_limited, QuicCoreTimePoint now,
                                        const RecoveryRttState &rtt_state);
    void on_simple_stream_packets_acked(const AckedStreamPacketAggregate &packets, bool app_limited,
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

    enum class Mode : std::uint8_t {
        startup,
        decision,
        rate_adjust,
        vivace,
    };

    struct MonitorInterval {
        bool active = false;
        double sending_rate_bytes_per_second = 0.0;
        std::size_t sent_bytes = 0;
        std::size_t acked_bytes = 0;
        std::size_t lost_bytes = 0;
        std::size_t rtt_sample_count = 0;
        double rtt_sample_x_sum = 0.0;
        double rtt_sample_y_sum = 0.0;
        double rtt_sample_x2_sum = 0.0;
        double rtt_sample_xy_sum = 0.0;
        std::uint64_t sequence = 0;
        QuicCoreTimePoint start_time{};
        QuicCoreTimePoint end_time{};
        QuicCoreDuration first_rtt{0};
        QuicCoreDuration latest_rtt{0};
        bool app_limited = false;
    };

    struct UtilitySample {
        double sending_rate_bytes_per_second = 0.0;
        double utility = 0.0;
        double loss_rate = 0.0;
        double throughput_bytes_per_second = 0.0;
        double rtt_gradient = 0.0;
    };

    struct VivaceUtilityInput {
        double sending_rate_bytes_per_second = 0.0;
        double loss_rate = 0.0;
        double rtt_gradient = 0.0;
    };

    MonitorInterval *monitor_interval_for_sample(std::uint64_t sequence,
                                                 QuicCoreTimePoint sent_time);
    std::size_t minimum_window() const;
    std::size_t pacing_budget_cap() const;
    std::size_t pacing_budget_at(QuicCoreTimePoint now) const;
    void consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now);
    std::uint64_t note_packet_sent(std::size_t bytes_sent, QuicCoreTimePoint sent_time,
                                   bool app_limited);
    void apply_acked_bytes(std::span<const SentPacketRecord> packets, bool app_limited,
                           QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    void apply_acked_bytes(std::span<const AckedStreamPacketSample> packets, bool app_limited,
                           QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    void apply_acked_aggregate(const AckedStreamPacketAggregate &packets, bool app_limited,
                               QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    void record_ack_sample(std::uint64_t sequence, QuicCoreTimePoint sent_time, std::size_t bytes,
                           QuicCoreTimePoint now, const RecoveryRttState &rtt_state,
                           bool app_limited);
    void record_loss_sample(const SentPacketRecord &packet);
    void seal_current_monitor_interval();
    void maybe_seal_current_monitor_interval(QuicCoreTimePoint now);
    void discard_current_monitor_interval();
    void maybe_process_monitor_intervals(QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    void finish_monitor_interval(QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    void maybe_finish_monitor_interval(QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    UtilitySample build_utility_sample(const MonitorInterval &interval) const;
    double allegro_utility(double sending_rate_bytes_per_second, double throughput_bytes_per_second,
                           double loss_rate) const;
    double vivace_utility(const VivaceUtilityInput &input) const;
    void apply_utility_sample(const UtilitySample &sample);
    void apply_allegro_sample(const UtilitySample &sample);
    void apply_vivace_sample(const UtilitySample &sample);
    void enter_decision_mode();
    void enter_vivace_mode();
    void enter_rate_adjust_mode(int direction);
    void start_monitor_interval(QuicCoreTimePoint now);
    double next_allegro_rate() const;
    double decision_rate(std::size_t sample_index) const;
    double next_vivace_rate() const;
    QuicCoreDuration monitor_interval_duration() const;
    QuicCoreDuration positive_rtt() const;
    QuicCoreDuration window_rtt() const;
    void set_sending_rate(double rate_bytes_per_second);
    void refresh_congestion_window();
    void set_pacing_rate();
    void set_send_quantum();
    void update_rtt_model(const RecoveryRttState &rtt_state);
    void update_rtt_model(const RecoveryRttState &rtt_state, QuicCoreTimePoint now);
    void subtract_in_flight(std::size_t bytes);
    void reset_pcc_state();
    static double clamp_rate(double rate_bytes_per_second, std::size_t max_datagram_size);

    std::size_t max_datagram_size_ = 1200;
    Variant variant_ = Variant::allegro;
    Mode mode_ = Mode::startup;
    std::size_t congestion_window_ = 0;
    std::size_t bytes_in_flight_ = 0;
    double sending_rate_bytes_per_second_ = 0.0;
    double pacing_rate_bytes_per_second_ = 0.0;
    std::size_t send_quantum_ = 0;
    std::size_t pacing_budget_bytes_ = 0;
    std::optional<QuicCoreTimePoint> pacing_budget_timestamp_;
    std::optional<QuicCoreTimePoint> recovery_start_time_;
    std::optional<QuicCoreDuration> latest_rtt_;
    std::optional<QuicCoreDuration> min_rtt_;
    std::optional<QuicCoreDuration> previous_interval_rtt_;
    MonitorInterval current_interval_;
    std::deque<MonitorInterval> pending_monitor_intervals_;
    std::uint64_t next_monitor_interval_sequence_ = 1;
    std::optional<UtilitySample> previous_startup_sample_;
    std::optional<UtilitySample> previous_adjust_sample_;
    std::array<std::optional<UtilitySample>, 4> decision_samples_;
    std::size_t decision_sample_count_ = 0;
    double decision_base_rate_bytes_per_second_ = 0.0;
    double epsilon_ = 0.01;
    std::size_t rate_adjust_round_ = 0;
    int rate_adjust_direction_ = 0;
    double vivace_base_rate_bytes_per_second_ = 0.0;
    int vivace_probe_direction_ = 1;
    int previous_vivace_direction_ = 0;
    std::size_t vivace_same_direction_count_ = 0;
    std::size_t vivace_boundary_adjustment_count_ = 0;
    double vivace_dynamic_boundary_ = 0.05;
    bool persistent_congestion_window_limited_ = false;
};

} // namespace coquic::quic
