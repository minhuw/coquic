#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

#include "src/quic/recovery.h"

namespace coquic::quic {

class NewRenoCongestionController {
  public:
    explicit NewRenoCongestionController(std::size_t max_datagram_size);

    bool can_send_ack_eliciting(std::size_t bytes) const;
    std::optional<QuicCoreTimePoint> next_send_time(std::size_t bytes) const;
    void on_packet_sent(std::size_t bytes_sent, bool ack_eliciting);
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

    std::size_t max_datagram_size_ = 1200;
    std::size_t congestion_window_ = 0;
    std::size_t bytes_in_flight_ = 0;
    std::size_t slow_start_threshold_ = std::numeric_limits<std::size_t>::max();
    std::size_t congestion_avoidance_credit_ = 0;
    std::optional<QuicCoreTimePoint> recovery_start_time_;
};

class BbrCongestionController { // NOLINT(clang-analyzer-optin.performance.Padding)
  public:
    explicit BbrCongestionController(std::size_t max_datagram_size);

    bool can_send_ack_eliciting(std::size_t bytes) const;
    std::optional<QuicCoreTimePoint> next_send_time(std::size_t bytes) const;
    void on_packet_sent(SentPacketRecord &packet);
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

    struct RateSample {
        double delivery_rate_bytes_per_second = 0.0;
        std::size_t newly_acked = 0;
        std::size_t lost = 0;
        std::size_t tx_in_flight = 0;
        std::uint64_t prior_delivered = 0;
        std::uint64_t delivered = 0;
        std::optional<std::chrono::milliseconds> rtt;
        bool is_app_limited = false;
        bool has_newly_acked = false;
        bool has_spurious_loss = false;
        bool exit_loss_recovery = false;
    };

    enum class Mode : std::uint8_t {
        startup,
        drain,
        probe_bw_down,
        probe_bw_cruise,
        probe_bw_refill,
        probe_bw_up,
        probe_rtt,
    };

    enum class AckPhase : std::uint8_t {
        probe_starting,
        probe_feedback,
        probe_stopping,
        refilling,
    };

    void handle_restart_from_idle(QuicCoreTimePoint now);
    RateSample generate_rate_sample(std::span<const SentPacketRecord> packets, bool app_limited,
                                    QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    void mark_connection_app_limited();
    void maybe_mark_connection_app_limited(bool no_pending_data);
    void update_round(std::uint64_t prior_delivered);
    void start_round();
    void update_max_bw(const RateSample &rs);
    void advance_max_bw_filter();
    void update_latest_delivery_signals(const RateSample &rs);
    void update_congestion_signals(const RateSample &rs);
    void update_ack_aggregation(const RateSample &rs, QuicCoreTimePoint now);
    void check_full_bw_reached(const RateSample &rs);
    void check_startup_done();
    void check_startup_high_loss();
    void check_drain_done(QuicCoreTimePoint now);
    void update_probe_bw_cycle_phase(const RateSample &rs, QuicCoreTimePoint now);
    void adapt_long_term_model(const RateSample &rs);
    void raise_inflight_longterm_slope();
    void probe_inflight_longterm_upward(const RateSample &rs);
    void update_min_rtt(const RateSample &rs, QuicCoreTimePoint now);
    void check_probe_rtt(const RateSample &rs, QuicCoreTimePoint now);
    void handle_probe_rtt(QuicCoreTimePoint now);
    void check_probe_rtt_done(QuicCoreTimePoint now);
    void advance_latest_delivery_signals(const RateSample &rs);
    void bound_bw_for_model();
    void set_pacing_rate_with_gain(double gain);
    void set_pacing_rate();
    void set_send_quantum();
    void update_max_inflight();
    void bound_cwnd_for_probe_rtt();
    void bound_cwnd_for_model();
    void set_cwnd(const RateSample &rs);
    void note_loss(const SentPacketRecord &packet);
    void handle_inflight_too_high(const RateSample &rs);
    void enter_startup();
    void enter_drain();
    void enter_probe_bw(QuicCoreTimePoint now);
    void enter_probe_rtt();
    void exit_probe_rtt(QuicCoreTimePoint now);
    void start_probe_bw_down(QuicCoreTimePoint now);
    void start_probe_bw_cruise();
    void start_probe_bw_refill();
    void start_probe_bw_up(const RateSample &rs, QuicCoreTimePoint now);
    void pick_probe_wait();
    void reset_full_bw();
    void reset_congestion_signals();
    void reset_short_term_model();
    void save_cwnd();
    void restore_cwnd();
    void save_state_upon_loss();
    void handle_spurious_loss_detection(QuicCoreTimePoint now);

    bool is_in_probe_bw_state() const;
    bool is_app_limited() const;
    bool is_probing_bw() const;
    bool is_cwnd_limited() const;
    bool has_elapsed_in_phase(QuicCoreClock::duration interval, QuicCoreTimePoint now) const;
    bool is_reno_coexistence_probe_time() const;
    bool is_time_to_probe_bw(QuicCoreTimePoint now);
    bool is_time_to_cruise() const;
    bool is_time_to_go_down(const RateSample &rs);
    bool is_inflight_too_high(const RateSample &rs) const;

    std::uint32_t next_random();
    std::uint64_t packets_for_bytes(std::size_t bytes) const;
    std::size_t minimum_window() const;
    std::size_t inflight_at_loss(const RateSample &rs, const SentPacketRecord &packet) const;
    std::size_t bdp_bytes(double gain) const;
    std::size_t quantization_budget(std::size_t inflight_cap) const;
    std::size_t inflight(double gain) const;
    std::size_t inflight_with_headroom() const;
    std::size_t target_inflight() const;
    std::size_t probe_rtt_cwnd() const;
    double pacing_gain() const;
    double pacing_rate_bytes_per_second() const;
    std::size_t send_quantum() const;
    std::size_t pacing_budget_cap() const;
    std::size_t pacing_budget_at(QuicCoreTimePoint now) const;
    void consume_pacing_budget(std::size_t bytes, QuicCoreTimePoint now);

    std::size_t max_datagram_size_ = 1200;
    std::size_t initial_cwnd_ = 0;
    std::size_t congestion_window_ = 0;
    std::size_t bytes_in_flight_ = 0;
    Mode mode_ = Mode::startup;
    AckPhase ack_phase_ = AckPhase::probe_stopping;
    double max_bandwidth_bytes_per_second_ = 0.0;
    std::array<double, 2> bandwidth_filter_{};
    std::array<std::uint64_t, 2> bandwidth_filter_cycle_{};
    double bandwidth_bytes_per_second_ = 0.0;
    double full_bandwidth_bytes_per_second_ = 0.0;
    std::uint8_t full_bandwidth_rounds_without_growth_ = 0;
    bool full_bw_now_ = false;
    bool full_bw_reached_ = false;
    std::optional<std::chrono::milliseconds> min_rtt_;
    std::optional<QuicCoreTimePoint> min_rtt_stamp_;
    std::optional<std::chrono::milliseconds> probe_rtt_min_delay_;
    std::optional<QuicCoreTimePoint> probe_rtt_min_stamp_;
    bool probe_rtt_expired_ = false;
    std::optional<QuicCoreTimePoint> probe_rtt_done_stamp_;
    bool probe_rtt_round_done_ = false;
    std::optional<std::size_t> prior_congestion_window_;
    bool idle_restart_ = false;
    std::uint64_t app_limited_until_delivered_ = 0;
    std::uint64_t total_delivered_ = 0;
    std::optional<QuicCoreTimePoint> delivered_time_;
    std::optional<QuicCoreTimePoint> first_sent_time_;
    std::uint64_t total_lost_ = 0;
    std::uint64_t next_round_delivered_ = 0;
    std::uint64_t round_count_ = 0;
    std::uint64_t rounds_since_bw_probe_ = 0;
    std::uint64_t cycle_count_ = 0;
    std::optional<QuicCoreTimePoint> cycle_stamp_;
    bool round_start_ = false;
    std::uint64_t drain_start_round_ = 0;
    std::optional<QuicCoreTimePoint> recovery_start_time_;
    std::uint64_t recovery_round_start_ = 0;
    std::optional<Mode> undo_state_;
    double bw_shortterm_ = std::numeric_limits<double>::infinity();
    double undo_bw_shortterm_ = std::numeric_limits<double>::infinity();
    std::size_t inflight_shortterm_ = std::numeric_limits<std::size_t>::max();
    std::size_t undo_inflight_shortterm_ = std::numeric_limits<std::size_t>::max();
    std::size_t inflight_longterm_ = std::numeric_limits<std::size_t>::max();
    std::size_t undo_inflight_longterm_ = std::numeric_limits<std::size_t>::max();
    double bw_latest_ = 0.0;
    std::size_t inflight_latest_ = 0;
    bool loss_in_round_ = false;
    std::optional<std::uint64_t> loss_round_delivered_;
    bool loss_round_start_ = false;
    std::size_t loss_bytes_in_round_ = 0;
    std::size_t previous_round_lost_bytes_ = 0;
    std::size_t loss_events_in_round_ = 0;
    std::size_t previous_round_loss_events_ = 0;
    bool previous_round_had_loss_ = false;
    std::optional<std::uint64_t> last_lost_packet_number_;
    bool bw_probe_samples_ = false;
    std::uint8_t bw_probe_up_rounds_ = 0;
    std::uint64_t bw_probe_up_acks_ = 0;
    std::uint64_t probe_up_cnt_ = std::numeric_limits<std::uint64_t>::max();
    std::chrono::milliseconds bw_probe_wait_{2000};
    std::size_t extra_acked_ = 0;
    std::array<std::size_t, 10> extra_acked_filter_{};
    std::array<std::uint64_t, 10> extra_acked_round_{};
    std::optional<QuicCoreTimePoint> extra_acked_interval_start_;
    std::size_t extra_acked_delivered_ = 0;
    std::size_t max_inflight_ = 0;
    std::size_t offload_budget_ = 0;
    double bdp_ = 0.0;
    double pacing_rate_bytes_per_second_ = 0.0;
    double pacing_gain_ = 1.0;
    double cwnd_gain_ = 2.0;
    std::size_t send_quantum_ = 0;
    bool pending_probe_bw_down_ = false;
    std::uint32_t random_state_ = 1;
    std::size_t pacing_budget_bytes_ = 0;
    std::optional<QuicCoreTimePoint> pacing_budget_timestamp_;
};

class QuicCongestionController {
  public:
    class TestMetricHandle {
      public:
        TestMetricHandle() = default;
        TestMetricHandle(QuicCongestionController *owner, bool congestion_window)
            : owner_(owner), congestion_window_(congestion_window) {
        }

        TestMetricHandle &operator=(const TestMetricHandle &other) {
            if (this != &other) {
                *this = static_cast<std::size_t>(other);
            }
            return *this;
        }

        TestMetricHandle &operator=(TestMetricHandle &&other) noexcept {
            if (this != &other) {
                *this = static_cast<std::size_t>(other);
            }
            return *this;
        }

        TestMetricHandle &operator=(std::size_t value) {
            if (owner_ != nullptr) {
                owner_->set_test_metric(congestion_window_, value);
            }
            return *this;
        }

        operator std::size_t() const {
            return owner_ == nullptr ? 0 : owner_->test_metric(congestion_window_);
        }

      private:
        QuicCongestionController *owner_ = nullptr;
        bool congestion_window_ = true;
    };

    QuicCongestionController(QuicCongestionControlAlgorithm algorithm,
                             std::size_t max_datagram_size);
    QuicCongestionController(const QuicCongestionController &other);
    QuicCongestionController &operator=(const QuicCongestionController &other);
    QuicCongestionController(QuicCongestionController &&other) noexcept;
    QuicCongestionController &operator=(QuicCongestionController &&other) noexcept;

    QuicCongestionControlAlgorithm algorithm() const;
    std::string_view name() const;
    bool can_send_ack_eliciting(std::size_t bytes) const;
    std::optional<QuicCoreTimePoint> next_send_time(std::size_t bytes) const;
    void on_packet_sent(std::size_t bytes_sent, bool ack_eliciting);
    void on_packet_sent(SentPacketRecord &packet);
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
    std::size_t minimum_window() const;

  private:
    void set_test_metric(bool congestion_window, std::size_t value);
    std::size_t test_metric(bool congestion_window) const;

    std::variant<NewRenoCongestionController, BbrCongestionController> storage_;
    TestMetricHandle congestion_window_{this, true};
    TestMetricHandle bytes_in_flight_{this, false};
};

} // namespace coquic::quic
