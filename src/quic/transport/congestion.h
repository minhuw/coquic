#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

#include "src/quic/cca/bbr.h"
#include "src/quic/cca/copa.h"
#include "src/quic/cca/cubic.h"
#include "src/quic/cca/newreno.h"
#include "src/quic/core.h"

namespace coquic::quic {

struct QuicCongestionDebugMetrics {
    std::uint64_t mode = 0;
    std::uint64_t bandwidth_bps = 0;
    std::uint64_t max_bandwidth_bps = 0;
    std::uint64_t pacing_rate_bps = 0;
    std::uint64_t bdp_bytes = 0;
    std::uint64_t max_inflight = 0;
    std::uint64_t send_quantum = 0;
    std::uint64_t pacing_budget = 0;
    std::uint64_t inflight_longterm = 0;
    std::uint64_t inflight_shortterm = 0;
    std::uint64_t extra_acked = 0;
    std::uint64_t total_delivered = 0;
    std::uint64_t total_lost = 0;
    std::uint64_t latest_rtt_us = 0;
    std::uint64_t min_rtt_us = 0;
    std::uint64_t unjittered_rtt_us = 0;
    std::uint64_t target_window = 0;
    std::uint64_t round_count = 0;
    bool app_limited = false;
    bool full_bw_reached = false;
    bool finite_inflight_longterm = false;
    bool finite_inflight_shortterm = false;
    bool slow_start = false;
    bool startup_probe_complete = false;
    bool finite_target_window = false;
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
                             std::size_t max_datagram_size, bool enable_hystart_plus_plus = true);
    QuicCongestionController(const QuicCongestionController &other);
    QuicCongestionController &operator=(const QuicCongestionController &other);
    QuicCongestionController(QuicCongestionController &&other) noexcept;
    QuicCongestionController &operator=(QuicCongestionController &&other) noexcept;

    QuicCongestionControlAlgorithm algorithm() const;
    std::string_view name() const;
    bool can_send_ack_eliciting(std::size_t bytes) const;
    std::optional<QuicCoreTimePoint> next_send_time(std::size_t bytes) const;
    std::size_t pacing_send_quantum() const;
    void on_packet_sent(std::size_t bytes_sent, bool ack_eliciting);
    void on_packet_sent(SentPacketRecord &packet);
    std::optional<SimpleStreamPacketSentCongestionResult>
    on_simple_stream_packet_sent(std::size_t bytes_sent, QuicCoreTimePoint sent_time,
                                 bool app_limited);
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
    void reset_for_new_path();

    std::size_t congestion_window() const;
    std::size_t send_window() const;
    std::size_t bytes_in_flight() const;
    std::size_t minimum_window() const;
    bool would_underutilize_congestion_window(std::size_t bytes_sent) const;
    QuicCongestionDebugMetrics debug_metrics(QuicCoreTimePoint now) const;

  private:
    void set_test_metric(bool congestion_window, std::size_t value);
    std::size_t test_metric(bool congestion_window) const;

    std::variant<NewRenoCongestionController, CubicCongestionController, BbrCongestionController,
                 CopaCongestionController>
        storage_;
    bool enable_hystart_plus_plus_ = true;
    TestMetricHandle congestion_window_{this, true};
    TestMetricHandle bytes_in_flight_{this, false};
};

} // namespace coquic::quic
