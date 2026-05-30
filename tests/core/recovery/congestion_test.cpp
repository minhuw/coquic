#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <limits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#define private public
#include "src/quic/congestion.h"
#undef private
#include "tests/support/quic_test_utils.h"

namespace {

using coquic::quic::BbrCongestionController;
using coquic::quic::CopaCongestionController;
using coquic::quic::CubicCongestionController;
using coquic::quic::NewRenoCongestionController;
using coquic::quic::SentPacketRecord;

constexpr std::size_t kTestDatagramSize = 1200;

template <typename T> const T &optional_ref_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return *value;
}

SentPacketRecord make_sent_packet(std::uint64_t packet_number, bool ack_eliciting, bool in_flight,
                                  std::size_t bytes_in_flight,
                                  coquic::quic::QuicCoreTimePoint sent_time) {
    return SentPacketRecord{
        .packet_number = packet_number,
        .sent_time = sent_time,
        .ack_eliciting = ack_eliciting,
        .in_flight = in_flight,
        .bytes_in_flight = bytes_in_flight,
    };
}

template <typename Controller>
std::array<SentPacketRecord, 8> send_hystart_round(Controller &controller,
                                                   std::uint64_t first_packet_number) {
    std::array<SentPacketRecord, 8> packets{};
    for (std::size_t offset = 0; offset < packets.size(); ++offset) {
        const auto packet_number = first_packet_number + offset;
        packets[offset] = make_sent_packet(
            packet_number, /*ack_eliciting=*/true, /*in_flight=*/true,
            /*bytes_in_flight=*/kTestDatagramSize,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
        controller.on_packet_sent(packets[offset]);
    }
    return packets;
}

template <typename Controller>
void ack_hystart_round(Controller &controller, std::span<const SentPacketRecord> sent_packets,
                       std::chrono::milliseconds latest_rtt) {
    for (const auto &sent_packet : sent_packets) {
        std::array<SentPacketRecord, 1> packet{sent_packet};
        controller.on_packets_acked(packet, /*app_limited=*/false,
                                    coquic::quic::test::test_time(
                                        static_cast<std::int64_t>(sent_packet.packet_number + 200)),
                                    coquic::quic::RecoveryRttState{
                                        .latest_rtt = latest_rtt,
                                        .min_rtt = std::chrono::milliseconds{100},
                                        .smoothed_rtt = latest_rtt,
                                    });
    }
}

struct CopaProbePackets {
    std::size_t count = 0;
    std::uint64_t first_packet_number = 0;
    std::int64_t sent_time_ms = 0;
};

std::vector<SentPacketRecord> send_copa_probe_packets(CopaCongestionController &controller,
                                                      CopaProbePackets probe) {
    std::vector<SentPacketRecord> packets;
    packets.reserve(probe.count);
    for (std::size_t offset = 0; offset < probe.count; ++offset) {
        auto packet = make_sent_packet(probe.first_packet_number + offset, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(probe.sent_time_ms));
        controller.on_packet_sent(packet);
        packets.push_back(packet);
    }
    return packets;
}

void ack_copa_packets(CopaCongestionController &controller,
                      std::span<const SentPacketRecord> packets,
                      coquic::quic::QuicCoreTimePoint ack_time,
                      std::chrono::microseconds latest_rtt, std::chrono::microseconds min_rtt) {
    controller.on_packets_acked(
        packets, /*app_limited=*/false, ack_time,
        coquic::quic::RecoveryRttState{
            .latest_rtt_sample = latest_rtt,
            .latest_adjusted_rtt_sample = latest_rtt,
            .min_rtt_sample = min_rtt,
            .smoothed_rtt = std::chrono::duration_cast<std::chrono::milliseconds>(latest_rtt),
        });
}

BbrCongestionController::RateSample
make_rate_sample(double delivery_rate_bytes_per_second = 0.0, std::size_t newly_acked = 0,
                 std::size_t lost = 0, std::size_t tx_in_flight = 0,
                 std::uint64_t prior_delivered = 0, std::uint64_t delivered = 0,
                 std::optional<std::chrono::milliseconds> rtt = std::nullopt,
                 bool is_app_limited = false, bool has_newly_acked = true) {
    return BbrCongestionController::RateSample{
        .delivery_rate_bytes_per_second = delivery_rate_bytes_per_second,
        .newly_acked = newly_acked,
        .lost = lost,
        .tx_in_flight = tx_in_flight,
        .prior_delivered = prior_delivered,
        .delivered = delivered,
        .rtt = rtt,
        .is_app_limited = is_app_limited,
        .has_newly_acked = has_newly_acked,
    };
}

TEST(QuicCongestionTest, CopaExtremeWindowRecomputesAfterExpiringCurrentExtreme) {
    using ExtremeWindow = CopaCongestionController::RttWindow::ExtremeWindow;

    ExtremeWindow min_window(/*find_min=*/true);
    min_window.max_duration_ = std::chrono::milliseconds{10};
    min_window.samples_ = {
        {coquic::quic::test::test_time(0), std::chrono::milliseconds{20}},
        {coquic::quic::test::test_time(1), std::chrono::milliseconds{30}},
        {coquic::quic::test::test_time(2), std::chrono::milliseconds{25}},
    };
    min_window.extreme_ = std::chrono::milliseconds{20};
    min_window.clear_old_history(coquic::quic::test::test_time(11));
    EXPECT_EQ(min_window.value(), std::chrono::milliseconds{25});

    ExtremeWindow max_window(/*find_min=*/false);
    max_window.max_duration_ = std::chrono::milliseconds{10};
    max_window.samples_ = {
        {coquic::quic::test::test_time(0), std::chrono::milliseconds{30}},
        {coquic::quic::test::test_time(1), std::chrono::milliseconds{20}},
        {coquic::quic::test::test_time(2), std::chrono::milliseconds{25}},
    };
    max_window.extreme_ = std::chrono::milliseconds{30};
    max_window.clear_old_history(coquic::quic::test::test_time(11));
    EXPECT_EQ(max_window.value(), std::chrono::milliseconds{25});

    ExtremeWindow min_window_keeps_first_recomputed_sample(/*find_min=*/true);
    min_window_keeps_first_recomputed_sample.max_duration_ = std::chrono::milliseconds{10};
    min_window_keeps_first_recomputed_sample.samples_ = {
        {coquic::quic::test::test_time(0), std::chrono::milliseconds{10}},
        {coquic::quic::test::test_time(1), std::chrono::milliseconds{20}},
        {coquic::quic::test::test_time(2), std::chrono::milliseconds{25}},
    };
    min_window_keeps_first_recomputed_sample.extreme_ = std::chrono::milliseconds{10};
    min_window_keeps_first_recomputed_sample.clear_old_history(coquic::quic::test::test_time(11));
    EXPECT_EQ(min_window_keeps_first_recomputed_sample.value(), std::chrono::milliseconds{20});

    ExtremeWindow max_window_keeps_first_recomputed_sample(/*find_min=*/false);
    max_window_keeps_first_recomputed_sample.max_duration_ = std::chrono::milliseconds{10};
    max_window_keeps_first_recomputed_sample.samples_ = {
        {coquic::quic::test::test_time(0), std::chrono::milliseconds{30}},
        {coquic::quic::test::test_time(1), std::chrono::milliseconds{25}},
        {coquic::quic::test::test_time(2), std::chrono::milliseconds{20}},
    };
    max_window_keeps_first_recomputed_sample.extreme_ = std::chrono::milliseconds{30};
    max_window_keeps_first_recomputed_sample.clear_old_history(coquic::quic::test::test_time(11));
    EXPECT_EQ(max_window_keeps_first_recomputed_sample.value(), std::chrono::milliseconds{25});
}

TEST(QuicCongestionTest, UsesRfcInitialWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/kTestDatagramSize);
    EXPECT_EQ(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, ParsesCongestionControlAlgorithms) {
    const auto newreno = coquic::quic::parse_congestion_control_algorithm("newreno");
    ASSERT_TRUE(newreno.has_value());
    EXPECT_EQ(optional_ref_or_terminate(newreno),
              coquic::quic::QuicCongestionControlAlgorithm::newreno);
    EXPECT_EQ(coquic::quic::congestion_control_algorithm_name(optional_ref_or_terminate(newreno)),
              "newreno");

    const auto cubic = coquic::quic::parse_congestion_control_algorithm("cubic");
    ASSERT_TRUE(cubic.has_value());
    EXPECT_EQ(optional_ref_or_terminate(cubic),
              coquic::quic::QuicCongestionControlAlgorithm::cubic);
    EXPECT_EQ(coquic::quic::congestion_control_algorithm_name(optional_ref_or_terminate(cubic)),
              "cubic");

    const auto bbr = coquic::quic::parse_congestion_control_algorithm("bbr");
    ASSERT_TRUE(bbr.has_value());
    EXPECT_EQ(optional_ref_or_terminate(bbr), coquic::quic::QuicCongestionControlAlgorithm::bbr);
    EXPECT_EQ(coquic::quic::congestion_control_algorithm_name(optional_ref_or_terminate(bbr)),
              "bbr");

    const auto copa = coquic::quic::parse_congestion_control_algorithm("copa");
    ASSERT_TRUE(copa.has_value());
    EXPECT_EQ(optional_ref_or_terminate(copa), coquic::quic::QuicCongestionControlAlgorithm::copa);
    EXPECT_EQ(coquic::quic::congestion_control_algorithm_name(optional_ref_or_terminate(copa)),
              "copa");

    EXPECT_FALSE(coquic::quic::parse_congestion_control_algorithm("vegas").has_value());
}

TEST(QuicCongestionTest, CommonPacingMathCoversGuardAndOverflowBranches) {
    coquic::quic::HyStartPlusPlus hystart(std::numeric_limits<std::size_t>::max());
    hystart.mode_ = coquic::quic::HyStartPlusPlus::Mode::conservative_slow_start;
    EXPECT_EQ(hystart.growth_bytes(std::numeric_limits<std::size_t>::max()),
              std::numeric_limits<std::size_t>::max() / 4u);

    EXPECT_EQ(coquic::quic::congestion_pacing_delay_for_deficit(/*deficit_bytes=*/0, 1.0),
              coquic::quic::QuicCoreClock::duration::zero());
    EXPECT_EQ(coquic::quic::congestion_pacing_delay_for_deficit(/*deficit_bytes=*/1200, 0.0),
              coquic::quic::QuicCoreClock::duration::zero());
    EXPECT_EQ(coquic::quic::congestion_pacing_delay_for_deficit(
                  std::numeric_limits<std::size_t>::max(), 1.0),
              coquic::quic::QuicCoreClock::duration::max());
    EXPECT_EQ(coquic::quic::congestion_pacing_replenished_bytes(
                  coquic::quic::QuicCoreClock::duration::zero(), 1.0),
              0u);
    EXPECT_EQ(coquic::quic::congestion_pacing_replenished_bytes(std::chrono::milliseconds{1}, 0.0),
              0u);
    EXPECT_EQ(
        coquic::quic::congestion_quinn_pacing_budget_cap(
            /*congestion_window=*/12000, /*max_datagram_size=*/0, std::chrono::milliseconds{100}),
        0u);
    EXPECT_EQ(
        coquic::quic::congestion_quinn_pacing_budget_cap(
            /*congestion_window=*/0, /*max_datagram_size=*/1200, std::chrono::milliseconds{100}),
        256u * 1200u);
    EXPECT_EQ(coquic::quic::congestion_quinn_pacing_budget_cap(
                  /*congestion_window=*/12000, /*max_datagram_size=*/1200,
                  coquic::quic::QuicCoreDuration::zero()),
              256u * 1200u);
    EXPECT_EQ(coquic::quic::congestion_quinn_pacing_budget_cap(
                  /*congestion_window=*/0, /*max_datagram_size=*/2, std::chrono::milliseconds{100},
                  std::numeric_limits<std::size_t>::max()),
              256u * 2u);
}

TEST(QuicCongestionTest, WrapperDebugMetricsAndDispatchCoverColdBranches) {
    using Algorithm = coquic::quic::QuicCongestionControlAlgorithm;
    const auto empty_stream_samples = std::span<const coquic::quic::AckedStreamPacketSample>{};

    coquic::quic::QuicCongestionController copa(Algorithm::copa, /*max_datagram_size=*/1200);
    auto &copa_impl = std::get<CopaCongestionController>(copa.storage_);
    copa_impl.slow_start_ = false;
    copa_impl.startup_probe_complete_ = true;
    copa_impl.congestion_window_ = 24000;
    copa_impl.latest_rtt_ = std::chrono::milliseconds{200};
    copa_impl.min_rtt_ = std::chrono::milliseconds{100};
    copa_impl.unjittered_rtt_ = std::chrono::milliseconds{200};
    copa_impl.pacing_budget_timestamp_ = coquic::quic::test::test_time(1);
    copa_impl.pacing_budget_bytes_ = 0;
    copa_impl.pacing_rate_bytes_per_second_ = 1200000.0;
    copa_impl.send_quantum_ = 2400;

    EXPECT_EQ(copa.send_window(), 24000u);
    EXPECT_TRUE(copa.next_send_time(/*bytes=*/2400).has_value());
    copa.on_simple_stream_packets_acked(empty_stream_samples, /*app_limited=*/false,
                                        coquic::quic::test::test_time(2),
                                        coquic::quic::RecoveryRttState{});
    auto copa_packet =
        make_sent_packet(/*packet_number=*/40, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(3));
    copa.on_packets_discarded(std::array<SentPacketRecord, 1>{copa_packet});
    copa_impl.bytes_in_flight_ = 1200;
    copa.on_packets_lost(std::array<SentPacketRecord, 1>{copa_packet});
    copa.on_loss_event(coquic::quic::test::test_time(4), copa_packet.sent_time);

    const auto copa_metrics = copa.debug_metrics(coquic::quic::test::test_time(5));
    EXPECT_EQ(copa_metrics.mode, 2u);
    EXPECT_TRUE(copa_metrics.finite_target_window);
    EXPECT_EQ(copa_metrics.latest_rtt_us, 200000u);
    EXPECT_EQ(copa_metrics.min_rtt_us, 100000u);
    EXPECT_EQ(copa_metrics.unjittered_rtt_us, 200000u);

    copa_impl.latest_rtt_.reset();
    copa_impl.min_rtt_ = std::chrono::microseconds{0};
    copa_impl.unjittered_rtt_.reset();
    const auto sparse_copa_metrics = copa.debug_metrics(coquic::quic::test::test_time(6));
    EXPECT_EQ(sparse_copa_metrics.latest_rtt_us, 0u);
    EXPECT_EQ(sparse_copa_metrics.min_rtt_us, 0u);

    coquic::quic::QuicCongestionController bbr(Algorithm::bbr, /*max_datagram_size=*/1200);
    auto &bbr_impl = std::get<BbrCongestionController>(bbr.storage_);
    bbr_impl.bandwidth_bytes_per_second_ = std::numeric_limits<double>::max();
    bbr_impl.max_bandwidth_bytes_per_second_ = std::numeric_limits<double>::max();
    bbr_impl.pacing_rate_bytes_per_second_ = std::numeric_limits<double>::max();
    bbr_impl.bdp_ = std::numeric_limits<double>::max();
    bbr_impl.inflight_longterm_ = 111;
    bbr_impl.inflight_shortterm_ = 222;
    bbr_impl.min_rtt_ = std::chrono::microseconds{0};
    bbr_impl.send_quantum_ = 4800;
    bbr_impl.pacing_budget_timestamp_ = coquic::quic::test::test_time(1);
    bbr_impl.pacing_budget_bytes_ = 1200;

    EXPECT_EQ(bbr_impl.pacing_rate_bytes_per_second(), std::numeric_limits<double>::max());

    bbr.on_simple_stream_packets_acked(empty_stream_samples, /*app_limited=*/false,
                                       coquic::quic::test::test_time(2),
                                       coquic::quic::RecoveryRttState{});
    const auto bbr_metrics = bbr.debug_metrics(coquic::quic::test::test_time(2));
    EXPECT_EQ(bbr_metrics.bandwidth_bps, std::numeric_limits<std::uint64_t>::max());
    EXPECT_TRUE(bbr_metrics.finite_inflight_longterm);
    EXPECT_TRUE(bbr_metrics.finite_inflight_shortterm);
    EXPECT_EQ(bbr_metrics.inflight_longterm, 111u);
    EXPECT_EQ(bbr_metrics.inflight_shortterm, 222u);
    EXPECT_EQ(bbr_metrics.min_rtt_us, 0u);

    bbr_impl.min_rtt_.reset();
    EXPECT_EQ(bbr.debug_metrics(coquic::quic::test::test_time(3)).min_rtt_us, 0u);

    bbr_impl.bandwidth_bytes_per_second_ = std::numeric_limits<double>::infinity();
    bbr_impl.inflight_longterm_ = std::numeric_limits<std::size_t>::max();
    bbr_impl.inflight_shortterm_ = std::numeric_limits<std::size_t>::max();
    const auto sparse_bbr_metrics = bbr.debug_metrics(coquic::quic::test::test_time(4));
    EXPECT_EQ(sparse_bbr_metrics.bandwidth_bps, 0u);
    EXPECT_FALSE(sparse_bbr_metrics.finite_inflight_longterm);
    EXPECT_FALSE(sparse_bbr_metrics.finite_inflight_shortterm);
    EXPECT_EQ(sparse_bbr_metrics.inflight_longterm, 0u);
    EXPECT_EQ(sparse_bbr_metrics.inflight_shortterm, 0u);

    CopaCongestionController::RttWindow::ExtremeWindow extreme_window(/*find_min=*/true);
    extreme_window.add_sample(std::chrono::milliseconds{20}, coquic::quic::test::test_time(1));
    EXPECT_EQ(extreme_window.value(), std::chrono::milliseconds{20});
    extreme_window.clear();
    EXPECT_EQ(extreme_window.value(), coquic::quic::kInitialRtt);

    CopaCongestionController::RttWindow rtt_window;
    rtt_window.add_sample(std::chrono::milliseconds{30}, coquic::quic::test::test_time(1));
    EXPECT_EQ(rtt_window.latest_rtt(), std::chrono::milliseconds{30});
    rtt_window.clear();
    EXPECT_EQ(rtt_window.latest_rtt(), coquic::quic::kInitialRtt);

    CopaCongestionController direct_copa(/*max_datagram_size=*/1200);
    direct_copa.update_rtt_model(
        coquic::quic::RecoveryRttState{
            .latest_adjusted_rtt = std::chrono::milliseconds{77},
            .min_rtt = std::chrono::milliseconds{55},
        },
        coquic::quic::test::test_time(7));
    EXPECT_EQ(direct_copa.latest_rtt_, std::chrono::milliseconds{77});
    EXPECT_EQ(direct_copa.min_rtt_, std::chrono::milliseconds{55});

    coquic::quic::QuicCongestionController cubic(Algorithm::cubic, /*max_datagram_size=*/1200);
    auto &cubic_impl = std::get<CubicCongestionController>(cubic.storage_);
    cubic_impl.bytes_in_flight_ = 1200;
    const std::array<coquic::quic::AckedStreamPacketSample, 1> cubic_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 41,
            .sent_time = coquic::quic::test::test_time(4),
            .congestion_send_sequence = 41,
            .bytes_in_flight = 1200,
        },
    };
    cubic.on_simple_stream_packets_acked(cubic_sample, /*app_limited=*/false,
                                         coquic::quic::test::test_time(5),
                                         coquic::quic::RecoveryRttState{
                                             .smoothed_rtt = std::chrono::milliseconds{100},
                                         });
    EXPECT_EQ(cubic.send_window(), cubic.congestion_window());
}

TEST(QuicCongestionTest, CopaExtremeWindowCoversMinMaxAndExpiryBranches) {
    {
        CopaCongestionController::RttWindow::ExtremeWindow min_window(/*find_min=*/true);
        min_window.set_max_duration(std::chrono::milliseconds{2});
        min_window.add_sample(std::chrono::milliseconds{30}, coquic::quic::test::test_time(1));
        min_window.add_sample(std::chrono::milliseconds{20}, coquic::quic::test::test_time(2));
        EXPECT_EQ(min_window.value(), std::chrono::milliseconds{20});
        min_window.add_sample(std::chrono::milliseconds{25}, coquic::quic::test::test_time(6));
        EXPECT_EQ(min_window.value(), std::chrono::milliseconds{25});
    }

    {
        CopaCongestionController::RttWindow::ExtremeWindow min_window(/*find_min=*/true);
        min_window.set_max_duration(std::chrono::milliseconds{10});
        min_window.add_sample(std::chrono::milliseconds{30}, coquic::quic::test::test_time(1));
        min_window.add_sample(std::chrono::milliseconds{20}, coquic::quic::test::test_time(2));
        min_window.add_sample(std::chrono::milliseconds{25}, coquic::quic::test::test_time(12));
        EXPECT_EQ(min_window.value(), std::chrono::milliseconds{20});
    }

    {
        CopaCongestionController::RttWindow::ExtremeWindow max_window(/*find_min=*/false);
        max_window.set_max_duration(std::chrono::milliseconds{2});
        max_window.add_sample(std::chrono::milliseconds{20}, coquic::quic::test::test_time(1));
        max_window.add_sample(std::chrono::milliseconds{30}, coquic::quic::test::test_time(2));
        EXPECT_EQ(max_window.value(), std::chrono::milliseconds{30});
        max_window.add_sample(std::chrono::milliseconds{25}, coquic::quic::test::test_time(6));
        EXPECT_EQ(max_window.value(), std::chrono::milliseconds{25});
    }

    {
        CopaCongestionController::RttWindow::ExtremeWindow max_window(/*find_min=*/false);
        max_window.set_max_duration(std::chrono::milliseconds{10});
        max_window.add_sample(std::chrono::milliseconds{20}, coquic::quic::test::test_time(1));
        max_window.add_sample(std::chrono::milliseconds{30}, coquic::quic::test::test_time(2));
        max_window.add_sample(std::chrono::milliseconds{25}, coquic::quic::test::test_time(12));
        EXPECT_EQ(max_window.value(), std::chrono::milliseconds{30});
    }
}

TEST(QuicCongestionTest, CopaSlowStartCompletionBoundariesCoverNoGrowthAndExit) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);
    controller.slow_start_probe_segments_acked_ = 18;
    controller.grow_slow_start(/*acked_bytes=*/1200, CopaCongestionController::CopaTarget{
                                                         .finite = true,
                                                         .window = 12000,
                                                     });
    EXPECT_TRUE(controller.slow_start_);
    EXPECT_EQ(controller.congestion_window(), 12000u);

    controller.slow_start_probe_segments_acked_ = 18;
    controller.grow_slow_start(/*acked_bytes=*/2400, CopaCongestionController::CopaTarget{
                                                         .finite = true,
                                                         .window = 12000,
                                                     });
    EXPECT_FALSE(controller.slow_start_);
}

TEST(QuicCongestionTest, CubicColdPacingAndSuppressedGrowthBranches) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/0).has_value());

    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(10);
    controller.pacing_budget_bytes_ = 0;
    controller.pacing_rate_bytes_per_second_ = 0.0;
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    controller.bytes_in_flight_ = controller.congestion_window();
    controller.pacing_rate_bytes_per_second_ = 1000.0;
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    auto non_ack = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/false,
                                    /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                    coquic::quic::test::test_time(10));
    controller.on_packet_sent(non_ack);
    EXPECT_EQ(controller.bytes_in_flight(), controller.congestion_window());

    controller.pacing_smoothed_rtt_ = coquic::quic::QuicCoreDuration::zero();
    controller.update_pacing_rate(coquic::quic::RecoveryRttState{
        .smoothed_rtt = coquic::quic::QuicCoreDuration::zero(),
    });
    EXPECT_EQ(controller.pacing_rate_bytes_per_second_, 0.0);

    controller.pacing_budget_timestamp_.reset();
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(11)),
              controller.pacing_budget_cap());

    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(10);
    controller.pacing_budget_bytes_ = 100;
    controller.pacing_rate_bytes_per_second_ = 1000.0;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(11)), 101u);

    controller.epoch_start_time_ = coquic::quic::test::test_time(1);
    controller.app_limited_start_time_.reset();
    controller.recovery_start_time_ = coquic::quic::test::test_time(20);
    controller.bytes_in_flight_ = 1200;
    const std::array<coquic::quic::AckedStreamPacketSample, 1> old_recovery_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 2,
            .sent_time = coquic::quic::test::test_time(10),
            .congestion_send_sequence = 2,
            .bytes_in_flight = 1200,
        },
    };
    controller.on_simple_stream_packets_acked(
        old_recovery_sample, /*app_limited=*/false, coquic::quic::test::test_time(30),
        coquic::quic::RecoveryRttState{.smoothed_rtt = std::chrono::milliseconds{100}});
    EXPECT_EQ(controller.app_limited_start_time_, std::optional{coquic::quic::test::test_time(30)});

    const std::array large_stream_packet{
        [&] {
            auto packet = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                           /*in_flight=*/true, /*bytes_in_flight=*/32u * 1024u,
                                           coquic::quic::test::test_time(31));
            packet.stream_fragments.push_back(coquic::quic::StreamFrameSendFragment{
                .stream_id = 0,
                .bytes = coquic::quic::SharedBytes(std::vector<std::byte>(1)),
            });
            return packet;
        }(),
    };
    EXPECT_TRUE(controller.should_start_pacing(large_stream_packet));
}

TEST(QuicCongestionTest, NewRenoColdBranchEdgesUseDirectState) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_EQ(controller.send_window(), controller.congestion_window());

    controller.recovery_start_time_ = coquic::quic::test::test_time(1);
    controller.recovery_flight_size_ = 0;
    EXPECT_EQ(controller.send_window(), controller.congestion_window());

    controller.bytes_in_flight_ = controller.congestion_window() + 1;
    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/1));
    controller.bytes_in_flight_ = controller.congestion_window() - 1;
    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/2));

    auto packet = make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true, /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(10));
    packet.congestion_send_sequence = 5;
    controller.recovery_start_time_ = coquic::quic::test::test_time(20);
    controller.recovery_start_sequence_ = 5;
    controller.on_packet_sent(packet);
    EXPECT_EQ(controller.recovery_sent_bytes_, 0u);

    controller.recovery_start_sequence_.reset();
    packet.sent_time = coquic::quic::test::test_time(19);
    controller.on_packet_sent(packet);
    EXPECT_EQ(controller.recovery_sent_bytes_, 0u);

    const auto boundary = std::optional{coquic::quic::test::test_time(20)};
    const auto sequence = std::optional<std::uint64_t>{5};
    SentPacketRecord zero_sequence = packet;
    zero_sequence.congestion_send_sequence = 0;
    zero_sequence.sent_time = coquic::quic::test::test_time(19);
    EXPECT_TRUE(controller.sent_on_or_before_recovery_boundary(zero_sequence, boundary, sequence));
    EXPECT_FALSE(controller.sent_after_recovery_boundary(zero_sequence, boundary, sequence));

    const coquic::quic::AckedStreamPacketSample zero_sequence_sample{
        .packet_number = 11,
        .sent_time = coquic::quic::test::test_time(19),
        .congestion_send_sequence = 0,
        .bytes_in_flight = 1200,
    };
    EXPECT_TRUE(
        controller.sent_on_or_before_recovery_boundary(zero_sequence_sample, boundary, sequence));
    EXPECT_FALSE(controller.sent_after_recovery_boundary(zero_sequence_sample, boundary, sequence));

    controller.last_recovery_start_sequence_ = 5;
    controller.last_recovery_start_time_ = coquic::quic::test::test_time(20);
    EXPECT_TRUE(controller.loss_on_or_before_last_recovery_boundary(
        coquic::quic::test::test_time(19), std::nullopt));

    const std::array large_non_stream_packet{
        make_sent_packet(/*packet_number=*/12, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/32u * 1024u, coquic::quic::test::test_time(12)),
    };
    controller.acked_stream_bytes_for_pacing_ = 0;
    EXPECT_FALSE(controller.should_start_pacing(large_non_stream_packet));
}

TEST(QuicCongestionTest, NewRenoPacingStartGuardFalseBranches) {
    NewRenoCongestionController default_now(/*max_datagram_size=*/1200);
    default_now.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));
    default_now.on_packet_sent(packet);
    default_now.on_packets_acked(std::array<SentPacketRecord, 1>{packet},
                                 /*app_limited=*/false, coquic::quic::QuicCoreTimePoint{},
                                 coquic::quic::RecoveryRttState{
                                     .smoothed_rtt = std::chrono::milliseconds{100},
                                 });
    EXPECT_FALSE(default_now.pacing_budget_timestamp_.has_value());

    NewRenoCongestionController zero_rate(/*max_datagram_size=*/1200);
    zero_rate.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    zero_rate.pacing_smoothed_rtt_ = coquic::quic::QuicCoreDuration::zero();
    auto zero_rate_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(2));
    zero_rate.on_packet_sent(zero_rate_packet);
    zero_rate.on_packets_acked(std::array<SentPacketRecord, 1>{zero_rate_packet},
                               /*app_limited=*/false, coquic::quic::test::test_time(3),
                               coquic::quic::RecoveryRttState{
                                   .smoothed_rtt = coquic::quic::QuicCoreDuration::zero(),
                               });
    EXPECT_FALSE(zero_rate.pacing_budget_timestamp_.has_value());

    NewRenoCongestionController simple_default_now(/*max_datagram_size=*/1200);
    simple_default_now.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    const std::array<coquic::quic::AckedStreamPacketSample, 1> stream_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 3,
            .sent_time = coquic::quic::test::test_time(3),
            .congestion_send_sequence = 3,
            .bytes_in_flight = 1200,
        },
    };
    simple_default_now.bytes_in_flight_ = 1200;
    simple_default_now.on_simple_stream_packets_acked(
        stream_sample, /*app_limited=*/false, coquic::quic::QuicCoreTimePoint{},
        coquic::quic::RecoveryRttState{.smoothed_rtt = std::chrono::milliseconds{100}});
    EXPECT_FALSE(simple_default_now.pacing_budget_timestamp_.has_value());

    NewRenoCongestionController simple_zero_rate(/*max_datagram_size=*/1200);
    simple_zero_rate.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    simple_zero_rate.pacing_smoothed_rtt_ = coquic::quic::QuicCoreDuration::zero();
    simple_zero_rate.bytes_in_flight_ = 1200;
    simple_zero_rate.on_simple_stream_packets_acked(
        stream_sample, /*app_limited=*/false, coquic::quic::test::test_time(4),
        coquic::quic::RecoveryRttState{.smoothed_rtt = coquic::quic::QuicCoreDuration::zero()});
    EXPECT_FALSE(simple_zero_rate.pacing_budget_timestamp_.has_value());
}

TEST(QuicCongestionTest, CubicPacingStartGuardFalseBranches) {
    CubicCongestionController default_now(/*max_datagram_size=*/1200);
    default_now.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));
    default_now.on_packet_sent(packet);
    default_now.on_packets_acked(std::array<SentPacketRecord, 1>{packet},
                                 /*app_limited=*/false, coquic::quic::QuicCoreTimePoint{},
                                 coquic::quic::RecoveryRttState{
                                     .smoothed_rtt = std::chrono::milliseconds{100},
                                 });
    EXPECT_FALSE(default_now.pacing_budget_timestamp_.has_value());

    CubicCongestionController zero_rate(/*max_datagram_size=*/1200);
    zero_rate.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    zero_rate.pacing_smoothed_rtt_ = coquic::quic::QuicCoreDuration::zero();
    auto zero_rate_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(2));
    zero_rate.on_packet_sent(zero_rate_packet);
    zero_rate.on_packets_acked(std::array<SentPacketRecord, 1>{zero_rate_packet},
                               /*app_limited=*/false, coquic::quic::test::test_time(3),
                               coquic::quic::RecoveryRttState{
                                   .smoothed_rtt = coquic::quic::QuicCoreDuration::zero(),
                               });
    EXPECT_FALSE(zero_rate.pacing_budget_timestamp_.has_value());

    CubicCongestionController simple_default_now(/*max_datagram_size=*/1200);
    simple_default_now.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    const std::array<coquic::quic::AckedStreamPacketSample, 1> stream_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 3,
            .sent_time = coquic::quic::test::test_time(3),
            .congestion_send_sequence = 3,
            .bytes_in_flight = 1200,
        },
    };
    simple_default_now.bytes_in_flight_ = 1200;
    simple_default_now.on_simple_stream_packets_acked(
        stream_sample, /*app_limited=*/false, coquic::quic::QuicCoreTimePoint{},
        coquic::quic::RecoveryRttState{.smoothed_rtt = std::chrono::milliseconds{100}});
    EXPECT_FALSE(simple_default_now.pacing_budget_timestamp_.has_value());

    CubicCongestionController simple_zero_rate(/*max_datagram_size=*/1200);
    simple_zero_rate.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    simple_zero_rate.pacing_smoothed_rtt_ = coquic::quic::QuicCoreDuration::zero();
    simple_zero_rate.bytes_in_flight_ = 1200;
    simple_zero_rate.on_simple_stream_packets_acked(
        stream_sample, /*app_limited=*/false, coquic::quic::test::test_time(4),
        coquic::quic::RecoveryRttState{.smoothed_rtt = coquic::quic::QuicCoreDuration::zero()});
    EXPECT_FALSE(simple_zero_rate.pacing_budget_timestamp_.has_value());

    const std::array large_non_stream_packet{
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/32u * 1024u, coquic::quic::test::test_time(4)),
    };
    CubicCongestionController pacing_probe(/*max_datagram_size=*/1200);
    EXPECT_FALSE(pacing_probe.should_start_pacing(large_non_stream_packet));

    CubicCongestionController already_pacing(/*max_datagram_size=*/1200);
    already_pacing.pacing_budget_timestamp_ = coquic::quic::test::test_time(1);
    already_pacing.acked_stream_bytes_for_pacing_ = 32u * 1024u;
    already_pacing.on_packets_acked(std::array<SentPacketRecord, 1>{packet},
                                    /*app_limited=*/false, coquic::quic::test::test_time(5),
                                    coquic::quic::RecoveryRttState{
                                        .smoothed_rtt = std::chrono::milliseconds{100},
                                    });
    EXPECT_EQ(already_pacing.pacing_budget_timestamp_,
              std::optional{coquic::quic::test::test_time(1)});

    CubicCongestionController already_app_limited_started(/*max_datagram_size=*/1200);
    already_app_limited_started.epoch_start_time_ = coquic::quic::test::test_time(1);
    already_app_limited_started.app_limited_start_time_ = coquic::quic::test::test_time(2);
    already_app_limited_started.recovery_start_time_ = coquic::quic::test::test_time(20);
    already_app_limited_started.bytes_in_flight_ = 1200;
    const std::array<coquic::quic::AckedStreamPacketSample, 1> old_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 5,
            .sent_time = coquic::quic::test::test_time(10),
            .congestion_send_sequence = 5,
            .bytes_in_flight = 1200,
        },
    };
    already_app_limited_started.on_simple_stream_packets_acked(
        old_sample, /*app_limited=*/false, coquic::quic::test::test_time(30),
        coquic::quic::RecoveryRttState{.smoothed_rtt = std::chrono::milliseconds{100}});
    EXPECT_EQ(already_app_limited_started.app_limited_start_time_,
              std::optional{coquic::quic::test::test_time(2)});
}

TEST(QuicCongestionTest, CopaColdBranchEdgesUseDirectState) {
    using ExtremeWindow = CopaCongestionController::RttWindow::ExtremeWindow;

    ExtremeWindow no_extreme(/*find_min=*/true);
    no_extreme.max_duration_ = std::chrono::milliseconds{2};
    no_extreme.samples_ = {
        {coquic::quic::test::test_time(1), std::chrono::milliseconds{20}},
        {coquic::quic::test::test_time(2), std::chrono::milliseconds{30}},
    };
    no_extreme.extreme_.reset();
    no_extreme.clear_old_history(coquic::quic::test::test_time(6));
    EXPECT_EQ(no_extreme.value(), coquic::quic::kInitialRtt);

    ExtremeWindow front_not_extreme(/*find_min=*/true);
    front_not_extreme.max_duration_ = std::chrono::milliseconds{2};
    front_not_extreme.samples_ = {
        {coquic::quic::test::test_time(1), std::chrono::milliseconds{30}},
        {coquic::quic::test::test_time(2), std::chrono::milliseconds{20}},
        {coquic::quic::test::test_time(3), std::chrono::milliseconds{25}},
    };
    front_not_extreme.extreme_ = std::chrono::milliseconds{20};
    front_not_extreme.clear_old_history(coquic::quic::test::test_time(6));
    EXPECT_EQ(front_not_extreme.value(), std::chrono::milliseconds{25});

    ExtremeWindow recompute_false_min(/*find_min=*/true);
    recompute_false_min.max_duration_ = std::chrono::milliseconds{2};
    recompute_false_min.samples_ = {
        {coquic::quic::test::test_time(1), std::chrono::milliseconds{20}},
        {coquic::quic::test::test_time(2), std::chrono::milliseconds{30}},
        {coquic::quic::test::test_time(3), std::chrono::milliseconds{25}},
    };
    recompute_false_min.extreme_ = std::chrono::milliseconds{20};
    recompute_false_min.clear_old_history(coquic::quic::test::test_time(6));
    EXPECT_EQ(recompute_false_min.value(), std::chrono::milliseconds{25});

    ExtremeWindow recompute_false_max(/*find_min=*/false);
    recompute_false_max.max_duration_ = std::chrono::milliseconds{2};
    recompute_false_max.samples_ = {
        {coquic::quic::test::test_time(1), std::chrono::milliseconds{30}},
        {coquic::quic::test::test_time(2), std::chrono::milliseconds{20}},
        {coquic::quic::test::test_time(3), std::chrono::milliseconds{25}},
    };
    recompute_false_max.extreme_ = std::chrono::milliseconds{30};
    recompute_false_max.clear_old_history(coquic::quic::test::test_time(6));
    EXPECT_EQ(recompute_false_max.value(), std::chrono::milliseconds{25});

    CopaCongestionController no_exit(/*max_datagram_size=*/1200);
    no_exit.startup_probe_complete_ = true;
    no_exit.slow_start_probe_segments_acked_ = 2 * 10;
    no_exit.congestion_window_ = 12000;
    no_exit.congestion_window_segments_ = 10.0;
    no_exit.grow_slow_start(/*acked_bytes=*/1200,
                            CopaCongestionController::CopaTarget{.finite = false});
    EXPECT_TRUE(no_exit.slow_start_);

    CopaCongestionController below_target(/*max_datagram_size=*/1200);
    below_target.startup_probe_complete_ = true;
    below_target.slow_start_probe_segments_acked_ = 2 * 10;
    below_target.congestion_window_ = 12000;
    below_target.congestion_window_segments_ = 10.0;
    below_target.grow_slow_start(/*acked_bytes=*/1200, CopaCongestionController::CopaTarget{
                                                           .finite = true,
                                                           .window = 50000,
                                                       });
    EXPECT_TRUE(below_target.slow_start_);

    CopaCongestionController in_flight_saturates(/*max_datagram_size=*/1200);
    in_flight_saturates.bytes_in_flight_ = 100;
    const std::array oversized_flight_packet{
        make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(5)),
    };
    in_flight_saturates.on_packets_discarded(oversized_flight_packet);
    EXPECT_EQ(in_flight_saturates.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, CubicUsesRfcInitialWindowAndSlowStartGrowth) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_EQ(controller.congestion_window(), 12000u);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/false);
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);
    ASSERT_EQ(controller.bytes_in_flight(), 1200u);
    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false);

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_EQ(controller.congestion_window(), 13200u);
    EXPECT_FALSE(controller.pacing_active());
}

TEST(QuicCongestionTest, HyStartPlusPlusIgnoresPacketsWithoutUsableRttSignal) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);

    auto non_ack_eliciting =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/false,
                         /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));
    controller.on_packet_sent(non_ack_eliciting);
    EXPECT_EQ(non_ack_eliciting.congestion_send_sequence, 0u);

    auto app_limited = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                        /*in_flight=*/true,
                                        /*bytes_in_flight=*/1200, coquic::quic::test::test_time(2));
    controller.on_packet_sent(app_limited);
    app_limited.app_limited = true;

    auto unsent = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                   /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(3));
    auto missing_rtt = make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                        /*in_flight=*/true,
                                        /*bytes_in_flight=*/1200, coquic::quic::test::test_time(4));
    controller.on_packet_sent(missing_rtt);
    const auto cwnd = controller.congestion_window();
    controller.hystart_.on_slow_start_ack(
        std::array<SentPacketRecord, 4>{non_ack_eliciting, app_limited, unsent, missing_rtt},
        coquic::quic::RecoveryRttState{});

    EXPECT_FALSE(controller.hystart_.in_conservative_slow_start());
    EXPECT_EQ(controller.congestion_window(), cwnd);
}

TEST(QuicCongestionTest, HyStartPlusPlusCoversDisabledAndUnusableAckPaths) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);

    auto non_ack_eliciting =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/false,
                         /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));
    controller.hystart_.on_packet_sent(non_ack_eliciting);
    auto app_limited = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                        /*in_flight=*/true,
                                        /*bytes_in_flight=*/1200, coquic::quic::test::test_time(2));
    controller.on_packet_sent(app_limited);
    app_limited.app_limited = true;
    auto unsent = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                   /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(3));
    const std::array<SentPacketRecord, 3> unusable_packets{
        non_ack_eliciting,
        app_limited,
        unsent,
    };

    controller.hystart_.on_slow_start_ack(unusable_packets,
                                          coquic::quic::RecoveryRttState{
                                              .latest_rtt = std::chrono::milliseconds{100},
                                              .smoothed_rtt = std::chrono::milliseconds{100},
                                          });
    EXPECT_FALSE(controller.hystart_.window_end_sequence_.has_value());

    controller.hystart_.disable();
    controller.hystart_.on_slow_start_ack(std::span<const SentPacketRecord>{},
                                          coquic::quic::RecoveryRttState{
                                              .latest_rtt = std::chrono::milliseconds{100},
                                              .smoothed_rtt = std::chrono::milliseconds{100},
                                          });
    controller.hystart_.on_slow_start_ack(
        std::array<coquic::quic::AckedStreamPacketSample, 1>{
            coquic::quic::AckedStreamPacketSample{},
        },
        coquic::quic::RecoveryRttState{
            .latest_rtt = std::chrono::milliseconds{100},
            .smoothed_rtt = std::chrono::milliseconds{100},
        });
    EXPECT_FALSE(controller.hystart_.should_exit_slow_start());

    controller.hystart_.enabled_ = true;
    controller.hystart_.mode_ = coquic::quic::HyStartPlusPlus::Mode::congestion_avoidance;
    auto congestion_avoidance_packet =
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(4));
    controller.on_packet_sent(congestion_avoidance_packet);
    controller.hystart_.on_slow_start_ack(
        std::array<SentPacketRecord, 1>{
            congestion_avoidance_packet,
        },
        coquic::quic::RecoveryRttState{
            .latest_rtt = std::chrono::milliseconds{100},
            .smoothed_rtt = std::chrono::milliseconds{100},
        });
    EXPECT_FALSE(controller.hystart_.in_conservative_slow_start());
}

TEST(QuicCongestionTest, NewRenoHyStartPlusPlusExitsSlowStartAfterCssRounds) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    auto first_round = send_hystart_round(controller, /*first_packet_number=*/1);
    ack_hystart_round(controller, first_round, std::chrono::milliseconds{100});
    auto second_round = send_hystart_round(controller, /*first_packet_number=*/9);
    ack_hystart_round(controller, second_round, std::chrono::milliseconds{120});
    ASSERT_TRUE(controller.hystart_.in_conservative_slow_start());

    for (std::uint64_t first_packet_number : {17u, 25u, 33u, 41u}) {
        auto round = send_hystart_round(controller, first_packet_number);
        ack_hystart_round(controller, round, std::chrono::milliseconds{121});
    }

    EXPECT_FALSE(controller.hystart_.in_conservative_slow_start());
    EXPECT_EQ(controller.slow_start_threshold_, controller.congestion_window());
}

TEST(QuicCongestionTest, NewRenoGrowsOnAppLimitedAcks) {
    {
        NewRenoCongestionController controller(/*max_datagram_size=*/kTestDatagramSize);
        auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/kTestDatagramSize,
                                       coquic::quic::test::test_time(1));
        packet.app_limited = true;
        controller.on_packet_sent(packet);

        controller.on_packets_acked(std::array<SentPacketRecord, 1>{packet},
                                    /*app_limited=*/true, coquic::quic::test::test_time(2),
                                    coquic::quic::RecoveryRttState{
                                        .latest_rtt = std::chrono::milliseconds{1},
                                        .min_rtt = std::chrono::milliseconds{1},
                                        .smoothed_rtt = std::chrono::milliseconds{1},
                                    });

        EXPECT_EQ(controller.bytes_in_flight(), 0u);
        EXPECT_EQ(controller.congestion_window(), 11u * kTestDatagramSize);
    }

    {
        NewRenoCongestionController controller(/*max_datagram_size=*/kTestDatagramSize);
        controller.slow_start_threshold_ = controller.congestion_window();
        std::array<SentPacketRecord, 10> packets{};
        for (std::size_t index = 0; index < packets.size(); ++index) {
            auto packet = make_sent_packet(
                static_cast<std::uint64_t>(index + 1), /*ack_eliciting=*/true,
                /*in_flight=*/true, /*bytes_in_flight=*/kTestDatagramSize,
                coquic::quic::test::test_time(static_cast<std::int64_t>(index + 1)));
            packet.app_limited = true;
            controller.on_packet_sent(packet);
            packets[index] = packet;
        }

        controller.on_packets_acked(packets, /*app_limited=*/true,
                                    coquic::quic::test::test_time(20),
                                    coquic::quic::RecoveryRttState{
                                        .smoothed_rtt = std::chrono::milliseconds{1},
                                    });

        EXPECT_EQ(controller.bytes_in_flight(), 0u);
        EXPECT_EQ(controller.congestion_window(), 11u * kTestDatagramSize);
    }
}

TEST(QuicCongestionTest, CubicHyStartPlusPlusExitsSlowStartAfterCssRounds) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);

    auto first_round = send_hystart_round(controller, /*first_packet_number=*/1);
    ack_hystart_round(controller, first_round, std::chrono::milliseconds{100});
    auto second_round = send_hystart_round(controller, /*first_packet_number=*/9);
    ack_hystart_round(controller, second_round, std::chrono::milliseconds{120});
    ASSERT_TRUE(controller.hystart_.in_conservative_slow_start());

    for (std::uint64_t first_packet_number : {17u, 25u, 33u, 41u}) {
        auto round = send_hystart_round(controller, first_packet_number);
        ack_hystart_round(controller, round, std::chrono::milliseconds{121});
    }

    EXPECT_FALSE(controller.hystart_.in_conservative_slow_start());
    EXPECT_EQ(controller.slow_start_threshold_, controller.congestion_window());
    EXPECT_DOUBLE_EQ(controller.w_max_segments_,
                     static_cast<double>(controller.congestion_window()) /
                         static_cast<double>(kTestDatagramSize));
    EXPECT_DOUBLE_EQ(controller.cwnd_prior_segments_, controller.w_max_segments_);
    EXPECT_DOUBLE_EQ(controller.w_est_segments_, controller.w_max_segments_);
    EXPECT_TRUE(controller.epoch_start_time_.has_value());
    EXPECT_DOUBLE_EQ(controller.k_seconds_, 0.0);
}

TEST(QuicCongestionTest, HyStartPlusPlusResumesStandardSlowStartWhenDelayFalls) {
    CubicCongestionController controller(/*max_datagram_size=*/kTestDatagramSize);

    auto first_round = send_hystart_round(controller, /*first_packet_number=*/1);
    ack_hystart_round(controller, first_round, std::chrono::milliseconds{100});
    auto second_round = send_hystart_round(controller, /*first_packet_number=*/9);
    ack_hystart_round(controller, second_round, std::chrono::milliseconds{120});
    ASSERT_TRUE(controller.hystart_.in_conservative_slow_start());

    const auto after_css_entry = controller.congestion_window();
    auto third_round = send_hystart_round(controller, /*first_packet_number=*/17);
    ack_hystart_round(controller, third_round, std::chrono::milliseconds{90});
    EXPECT_FALSE(controller.hystart_.in_conservative_slow_start());
    EXPECT_EQ(controller.congestion_window(), after_css_entry + 2u * kTestDatagramSize);

    const auto after_resume_round = controller.congestion_window();
    auto fourth_round = send_hystart_round(controller, /*first_packet_number=*/25);
    ack_hystart_round(controller, fourth_round, std::chrono::milliseconds{91});
    EXPECT_EQ(controller.congestion_window(), after_resume_round + 8u * kTestDatagramSize);
}

TEST(QuicCongestionTest, HyStartPlusPlusRoundsUseSendSequenceAcrossPacketNumberSpaces) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);

    auto initial_space_round = send_hystart_round(controller, /*first_packet_number=*/100);
    ack_hystart_round(controller, initial_space_round, std::chrono::milliseconds{100});

    auto handshake_space_round = send_hystart_round(controller, /*first_packet_number=*/0);
    ack_hystart_round(controller, handshake_space_round, std::chrono::milliseconds{120});

    EXPECT_TRUE(controller.hystart_.in_conservative_slow_start());
}

TEST(QuicCongestionTest, HyStartPlusPlusHandlesAckLimitsAndDisabledMode) {
    NewRenoCongestionController huge_datagram(
        /*max_datagram_size=*/std::numeric_limits<std::size_t>::max());
    EXPECT_EQ(huge_datagram.hystart_.growth_bytes(std::numeric_limits<std::size_t>::max()),
              std::numeric_limits<std::size_t>::max());

    CubicCongestionController controller(/*max_datagram_size=*/1200);
    auto first_round = send_hystart_round(controller, /*first_packet_number=*/1);
    ack_hystart_round(controller, first_round, std::chrono::milliseconds{100});
    auto second_round = send_hystart_round(controller, /*first_packet_number=*/9);
    ack_hystart_round(controller, second_round, std::chrono::milliseconds{120});
    ASSERT_TRUE(controller.hystart_.in_conservative_slow_start());

    EXPECT_EQ(controller.hystart_.growth_bytes(24u * kTestDatagramSize), 2u * kTestDatagramSize);
    controller.hystart_.disable();
    EXPECT_FALSE(controller.hystart_.in_conservative_slow_start());
    EXPECT_EQ(controller.hystart_.growth_bytes(24u * kTestDatagramSize), 24u * kTestDatagramSize);
}

TEST(QuicCongestionTest, DisabledHyStartPlusPlusDoesNotCapBatchedSlowStartGrowth) {
    NewRenoCongestionController newreno(/*max_datagram_size=*/kTestDatagramSize,
                                        /*enable_hystart_plus_plus=*/false);
    CubicCongestionController cubic(/*max_datagram_size=*/kTestDatagramSize,
                                    /*enable_hystart_plus_plus=*/false);
    std::vector<SentPacketRecord> newreno_packets;
    std::vector<SentPacketRecord> cubic_packets;

    for (std::uint64_t packet_number = 1; packet_number <= 24; ++packet_number) {
        auto newreno_packet = make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            /*in_flight=*/true,
            /*bytes_in_flight=*/kTestDatagramSize,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
        auto cubic_packet = newreno_packet;
        newreno.on_packet_sent(newreno_packet);
        cubic.on_packet_sent(cubic_packet);
        newreno_packets.push_back(newreno_packet);
        cubic_packets.push_back(cubic_packet);
    }

    const auto initial_newreno_cwnd = newreno.congestion_window();
    const auto initial_cubic_cwnd = cubic.congestion_window();
    const auto ack_time = coquic::quic::test::test_time(200);
    const auto rtt_state = coquic::quic::RecoveryRttState{
        .latest_rtt = std::chrono::milliseconds{100},
        .min_rtt = std::chrono::milliseconds{100},
        .smoothed_rtt = std::chrono::milliseconds{100},
    };

    newreno.on_packets_acked(newreno_packets, /*app_limited=*/false, ack_time, rtt_state);
    cubic.on_packets_acked(cubic_packets, /*app_limited=*/false, ack_time, rtt_state);

    EXPECT_EQ(newreno.congestion_window(), initial_newreno_cwnd + 24u * kTestDatagramSize);
    EXPECT_EQ(cubic.congestion_window(), initial_cubic_cwnd + 24u * kTestDatagramSize);
}

TEST(QuicCongestionTest, HyStartPlusPlusCoversRoundAndRttStateEdges) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.hystart_.rtt_sample_count_ = std::numeric_limits<std::uint8_t>::max();
    controller.hystart_.window_end_sequence_ = 10;

    auto first = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                  /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                  coquic::quic::test::test_time(1));
    first.congestion_send_sequence = 1;
    controller.hystart_.on_slow_start_ack(std::array<SentPacketRecord, 1>{first},
                                          coquic::quic::RecoveryRttState{
                                              .latest_rtt = std::chrono::milliseconds{80},
                                              .smoothed_rtt = std::chrono::milliseconds{80},
                                          });
    EXPECT_EQ(controller.hystart_.rtt_sample_count_, std::numeric_limits<std::uint8_t>::max());
    EXPECT_EQ(controller.hystart_.window_end_sequence_, std::optional<std::uint64_t>{10});

    controller.hystart_.latest_sent_sequence_.reset();
    controller.hystart_.start_new_round(/*finished_round_end=*/1);
    EXPECT_FALSE(controller.hystart_.window_end_sequence_.has_value());
    controller.hystart_.ensure_round_started(/*largest_acked_send_sequence=*/7);
    EXPECT_EQ(controller.hystart_.window_end_sequence_, std::optional<std::uint64_t>{7});
    controller.hystart_.window_end_sequence_.reset();
    controller.hystart_.maybe_finish_round(/*largest_acked_send_sequence=*/7);
    EXPECT_FALSE(controller.hystart_.window_end_sequence_.has_value());

    controller.hystart_.mode_ = coquic::quic::HyStartPlusPlus::Mode::conservative_slow_start;
    controller.hystart_.css_entry_round_end_sequence_.reset();
    controller.hystart_.css_baseline_min_rtt_ = std::chrono::milliseconds{100};
    controller.hystart_.current_round_min_rtt_.reset();
    controller.hystart_.rtt_sample_count_ = 8;
    controller.hystart_.maybe_resume_standard_slow_start();
    EXPECT_TRUE(controller.hystart_.in_conservative_slow_start());

    controller.hystart_.current_round_min_rtt_ = std::chrono::milliseconds{110};
    controller.hystart_.maybe_resume_standard_slow_start();
    EXPECT_TRUE(controller.hystart_.in_conservative_slow_start());

    controller.hystart_.css_rounds_ = std::numeric_limits<std::uint8_t>::max();
    controller.hystart_.window_end_sequence_ = 10;
    controller.hystart_.latest_sent_sequence_ = 10;
    controller.hystart_.maybe_finish_round(/*largest_acked_send_sequence=*/10);
    EXPECT_TRUE(controller.hystart_.should_exit_slow_start());

    NewRenoCongestionController thresholds(/*max_datagram_size=*/1200);
    thresholds.hystart_.rtt_sample_count_ = 8;
    thresholds.hystart_.current_round_min_rtt_ = std::chrono::milliseconds{100};
    thresholds.hystart_.maybe_enter_conservative_slow_start();
    EXPECT_FALSE(thresholds.hystart_.in_conservative_slow_start());
    thresholds.hystart_.last_round_min_rtt_ = std::chrono::milliseconds{100};
    thresholds.hystart_.maybe_enter_conservative_slow_start();
    EXPECT_FALSE(thresholds.hystart_.in_conservative_slow_start());
    thresholds.hystart_.current_round_min_rtt_.reset();
    thresholds.hystart_.maybe_enter_conservative_slow_start();
    EXPECT_FALSE(thresholds.hystart_.in_conservative_slow_start());

    NewRenoCongestionController resume_without_baseline(/*max_datagram_size=*/1200);
    resume_without_baseline.hystart_.mode_ =
        coquic::quic::HyStartPlusPlus::Mode::conservative_slow_start;
    resume_without_baseline.hystart_.rtt_sample_count_ = 8;
    resume_without_baseline.hystart_.current_round_min_rtt_ = std::chrono::milliseconds{90};
    resume_without_baseline.hystart_.css_baseline_min_rtt_.reset();
    resume_without_baseline.hystart_.maybe_resume_standard_slow_start();
    EXPECT_TRUE(resume_without_baseline.hystart_.in_conservative_slow_start());

    NewRenoCongestionController css_mismatch(/*max_datagram_size=*/1200);
    css_mismatch.hystart_.mode_ = coquic::quic::HyStartPlusPlus::Mode::conservative_slow_start;
    css_mismatch.hystart_.css_entry_round_end_sequence_ = 9;
    css_mismatch.hystart_.css_rounds_ = 1;
    css_mismatch.hystart_.window_end_sequence_ = 10;
    css_mismatch.hystart_.latest_sent_sequence_ = 10;
    css_mismatch.hystart_.maybe_finish_round(/*largest_acked_send_sequence=*/10);
    EXPECT_EQ(css_mismatch.hystart_.css_rounds_, 2u);

    EXPECT_EQ(coquic::quic::congestion_round_to_size_t(-1.0), 0u);
    EXPECT_EQ(coquic::quic::congestion_round_to_size_t(
                  static_cast<double>(std::numeric_limits<std::size_t>::max())),
              std::numeric_limits<std::size_t>::max());
}

TEST(QuicCongestionTest, CubicLossUsesBetaReductionAndFastConvergence) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 24000;
    controller.bytes_in_flight_ = 24000;

    controller.on_loss_event(coquic::quic::test::test_time(10), coquic::quic::test::test_time(9));

    EXPECT_EQ(controller.congestion_window(), 16800u);
    EXPECT_EQ(controller.slow_start_threshold_, 16800u);
    EXPECT_DOUBLE_EQ(controller.cwnd_prior_segments_, 20.0);
    EXPECT_DOUBLE_EQ(controller.w_max_segments_, 20.0);
    EXPECT_TRUE(controller.epoch_start_time_.has_value());
    EXPECT_GT(controller.k_seconds_, 0.0);

    controller.recovery_start_time_.reset();
    controller.congestion_window_ = 14400;
    controller.on_loss_event(coquic::quic::test::test_time(20), coquic::quic::test::test_time(19));

    EXPECT_EQ(controller.congestion_window(), 10080u);
    EXPECT_DOUBLE_EQ(controller.w_max_segments_, 10.2);
}

TEST(QuicCongestionTest, CubicAvoidanceUsesRenoFriendlyAndCubicRegions) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 16800;
    controller.slow_start_threshold_ = 16800;
    controller.w_max_segments_ = 20.0;
    controller.cwnd_prior_segments_ = 20.0;

    auto first_ack =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11));
    controller.bytes_in_flight_ = 1200;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{first_ack},
                                /*app_limited=*/false, coquic::quic::test::test_time(110),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });

    EXPECT_EQ(controller.congestion_window(), 16800u);
    EXPECT_TRUE(controller.epoch_start_time_.has_value());
    EXPECT_GT(controller.w_est_segments_, 14.0);
    EXPECT_GT(controller.congestion_avoidance_credit_segments_, 0.0);
    const auto reno_friendly_credit = controller.congestion_avoidance_credit_segments_;

    for (std::uint64_t packet_number = 3; controller.congestion_window() == 16800u;
         ++packet_number) {
        auto packet = make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            /*in_flight=*/true, /*bytes_in_flight=*/1200,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number + 10)));
        controller.bytes_in_flight_ = 1200;
        controller.on_packets_acked(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number + 110)),
            coquic::quic::RecoveryRttState{
                .smoothed_rtt = std::chrono::milliseconds{100},
            });
    }
    EXPECT_GT(controller.congestion_window(), 16800u);

    controller.w_est_segments_ = 10.0;
    controller.congestion_window_ = 16800;
    controller.congestion_avoidance_credit_segments_ = 0.0;
    controller.bytes_in_flight_ = 1200;
    controller.epoch_start_time_ = coquic::quic::test::test_time(0);
    auto later_ack =
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(111));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{later_ack},
                                /*app_limited=*/false, coquic::quic::test::test_time(5000),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });

    EXPECT_EQ(controller.congestion_window(), 16800u);
    EXPECT_GT(controller.congestion_avoidance_credit_segments_, reno_friendly_credit);

    auto next_later_ack =
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(112));
    controller.bytes_in_flight_ = 1200;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{next_later_ack},
                                /*app_limited=*/false, coquic::quic::test::test_time(5001),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_GT(controller.congestion_window(), 16800u);
}

TEST(QuicCongestionTest, CubicAvoidanceAccumulatesSubDatagramGrowthCredit) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 120000;
    controller.slow_start_threshold_ = 120000;
    controller.w_max_segments_ = 120.0;
    controller.cwnd_prior_segments_ = 120.0;
    controller.w_est_segments_ = 100.0;
    controller.epoch_start_time_ = coquic::quic::test::test_time(0);

    for (std::uint64_t packet_number = 1; packet_number <= 100; ++packet_number) {
        auto packet = make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            /*in_flight=*/true, /*bytes_in_flight=*/1200,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
        controller.bytes_in_flight_ = 1200;
        controller.on_packets_acked(
            std::array<SentPacketRecord, 1>{packet},
            /*app_limited=*/false,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number + 1000)),
            coquic::quic::RecoveryRttState{
                .smoothed_rtt = std::chrono::milliseconds{100},
            });
    }

    EXPECT_GT(controller.congestion_window(), 120000u);
    EXPECT_LT(controller.congestion_avoidance_credit_segments_, 1.0);
}

TEST(QuicCongestionTest, CubicSuppressesAppLimitedGrowthAndPausesEpochClock) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 16800;
    controller.slow_start_threshold_ = 16800;
    controller.w_max_segments_ = 20.0;
    controller.cwnd_prior_segments_ = 20.0;
    controller.epoch_start_time_ = coquic::quic::test::test_time(100);

    auto app_limited_packet =
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(110));
    app_limited_packet.app_limited = true;
    controller.bytes_in_flight_ = 1200;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{app_limited_packet},
                                /*app_limited=*/true, coquic::quic::test::test_time(200),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });

    EXPECT_EQ(controller.congestion_window(), 16800u);
    ASSERT_TRUE(controller.app_limited_start_time_.has_value());

    auto non_app_limited_packet =
        make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(201));
    controller.bytes_in_flight_ = 1200;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{non_app_limited_packet},
                                /*app_limited=*/false, coquic::quic::test::test_time(500),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });

    EXPECT_FALSE(controller.app_limited_start_time_.has_value());
    EXPECT_EQ(controller.app_limited_pause_, std::chrono::milliseconds{300});
    EXPECT_EQ(controller.congestion_window(), 16800u);
    EXPECT_GT(controller.congestion_avoidance_credit_segments_, 0.0);

    for (std::uint64_t packet_number = 6; controller.congestion_window() == 16800u;
         ++packet_number) {
        auto packet = make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            /*in_flight=*/true, /*bytes_in_flight=*/1200,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number + 200)));
        controller.bytes_in_flight_ = 1200;
        controller.on_packets_acked(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number + 500)),
            coquic::quic::RecoveryRttState{
                .smoothed_rtt = std::chrono::milliseconds{100},
            });
    }
    EXPECT_GT(controller.congestion_window(), 16800u);
}

TEST(QuicCongestionTest, CubicRecoveryExitAndPersistentCongestion) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 24000;
    controller.bytes_in_flight_ = 24000;
    controller.on_loss_event(coquic::quic::test::test_time(10), coquic::quic::test::test_time(9));
    ASSERT_TRUE(controller.recovery_start_time_.has_value());

    controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{
            make_sent_packet(/*packet_number=*/6, /*ack_eliciting=*/true, /*in_flight=*/true,
                             /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11)),
        },
        /*app_limited=*/false, coquic::quic::test::test_time(111),
        coquic::quic::RecoveryRttState{.smoothed_rtt = std::chrono::milliseconds{100}});

    EXPECT_FALSE(controller.recovery_start_time_.has_value());
    controller.on_persistent_congestion();
    EXPECT_EQ(controller.congestion_window(), 2400u);
    EXPECT_EQ(controller.slow_start_threshold_, 2400u);
    EXPECT_FALSE(controller.epoch_start_time_.has_value());
}

TEST(QuicCongestionTest, CubicCoversRecoveryPredicateAndSuppressedGrowthEdges) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    auto no_recovery_packet =
        make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));
    EXPECT_FALSE(controller.in_recovery(no_recovery_packet));

    controller.epoch_start_time_ = coquic::quic::test::test_time(1);
    controller.app_limited_start_time_.reset();
    controller.on_packets_acked(std::span<const SentPacketRecord>{},
                                /*app_limited=*/false, coquic::quic::test::test_time(2),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_FALSE(controller.app_limited_start_time_.has_value());

    controller.app_limited_start_time_ = coquic::quic::test::test_time(2);
    auto paused_epoch_packet =
        make_sent_packet(/*packet_number=*/12, /*ack_eliciting=*/false, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(3));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{paused_epoch_packet},
                                /*app_limited=*/false, coquic::quic::test::test_time(4),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_EQ(controller.app_limited_start_time_, std::optional{coquic::quic::test::test_time(2)});
    controller.app_limited_start_time_.reset();

    controller.recovery_start_time_ = coquic::quic::test::test_time(10);
    auto recovery_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(9));
    auto fresh_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11));
    EXPECT_TRUE(controller.in_recovery(recovery_packet));
    EXPECT_FALSE(controller.in_recovery(fresh_packet));

    controller.bytes_in_flight_ = 0;
    auto non_in_flight_packet =
        make_sent_packet(/*packet_number=*/8, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(13));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{non_in_flight_packet},
                                /*app_limited=*/false, coquic::quic::test::test_time(14),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    controller.recovery_start_time_ = coquic::quic::test::test_time(10);

    controller.epoch_start_time_ = coquic::quic::test::test_time(10);
    controller.app_limited_start_time_.reset();
    auto non_ack_recovery_packet =
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/false, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(9));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{non_ack_recovery_packet},
                                /*app_limited=*/false, coquic::quic::test::test_time(14),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_TRUE(controller.recovery_start_time_.has_value());
    ASSERT_TRUE(controller.app_limited_start_time_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(controller.app_limited_start_time_),
              coquic::quic::test::test_time(14));

    controller.app_limited_start_time_.reset();
    auto app_limited_recovery_packet =
        make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(9));
    app_limited_recovery_packet.app_limited = true;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{app_limited_recovery_packet},
                                /*app_limited=*/true, coquic::quic::test::test_time(15),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    ASSERT_TRUE(controller.app_limited_start_time_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(controller.app_limited_start_time_),
              coquic::quic::test::test_time(15));

    controller.bytes_in_flight_ = 0;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{fresh_packet},
                                /*app_limited=*/false, coquic::quic::test::test_time(12),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_FALSE(controller.recovery_start_time_.has_value());

    controller.congestion_window_ = 16800;
    controller.slow_start_threshold_ = 16800;
    controller.w_max_segments_ = 20.0;
    controller.cwnd_prior_segments_ = 20.0;
    controller.w_est_segments_ = 20.0;
    controller.epoch_start_time_ = coquic::quic::test::test_time(100);
    const auto cwnd_before_zero_ack = controller.congestion_window();
    controller.grow_congestion_avoidance(/*acked_bytes=*/0, coquic::quic::test::test_time(100),
                                         coquic::quic::RecoveryRttState{
                                             .smoothed_rtt = std::chrono::milliseconds{100},
                                         });
    EXPECT_EQ(controller.congestion_window(), cwnd_before_zero_ack);

    controller.w_est_segments_ = 1.0;
    controller.w_max_segments_ = 1.0;
    controller.k_seconds_ = 10.0;
    const auto cwnd_before_clamped_target = controller.congestion_window();
    controller.grow_congestion_avoidance(/*acked_bytes=*/1200, coquic::quic::test::test_time(100),
                                         coquic::quic::RecoveryRttState{
                                             .smoothed_rtt = std::chrono::milliseconds{0},
                                         });
    EXPECT_EQ(controller.congestion_window(), cwnd_before_clamped_target);

    controller.on_loss_event(coquic::quic::test::test_time(200),
                             coquic::quic::test::test_time(150));
    const auto reduced_window = controller.congestion_window();
    controller.on_loss_event(coquic::quic::test::test_time(201),
                             coquic::quic::test::test_time(150));
    EXPECT_EQ(controller.congestion_window(), reduced_window);

    controller.recovery_start_time_ = coquic::quic::test::test_time(200);
    controller.on_loss_event(coquic::quic::test::test_time(220),
                             coquic::quic::test::test_time(210));
    EXPECT_EQ(controller.recovery_start_time_, std::optional{coquic::quic::test::test_time(220)});
}

TEST(QuicCongestionTest, CubicDiscardAndLossAccountingIgnoreNonInflightPackets) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    controller.bytes_in_flight_ = 1200;

    controller.on_packets_discarded(std::array<SentPacketRecord, 2>{
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1)),
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/2400, coquic::quic::test::test_time(2)),
    });
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.bytes_in_flight_ = 1200;
    controller.on_packets_lost(std::array<SentPacketRecord, 2>{
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(3)),
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/2400, coquic::quic::test::test_time(4)),
    });
    EXPECT_EQ(controller.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, CubicAckBatchOrderDoesNotChangeRecoveryExit) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 16800;
    controller.slow_start_threshold_ = 16800;
    controller.recovery_start_time_ = coquic::quic::test::test_time(10);
    controller.bytes_in_flight_ = 2400;

    const auto newer_packet =
        make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11));
    const auto recovery_packet =
        make_sent_packet(/*packet_number=*/6, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(9));

    controller.on_packets_acked(std::array<SentPacketRecord, 2>{newer_packet, recovery_packet},
                                /*app_limited=*/false, coquic::quic::test::test_time(111),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });

    EXPECT_FALSE(controller.recovery_start_time_.has_value());
    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_LT(controller.congestion_window(), 18000u);
}

TEST(QuicCongestionTest, CopaUsesDelayTargetToExitSlowStartAndPacesSends) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_EQ(controller.congestion_window(), 12000u);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    auto initial_probe =
        send_copa_probe_packets(controller, {.count = 18, .first_packet_number = 1});
    ack_copa_packets(controller, initial_probe, coquic::quic::test::test_time(100),
                     std::chrono::microseconds{150000}, std::chrono::microseconds{100000});

    EXPECT_TRUE(controller.slow_start_);
    EXPECT_FALSE(controller.startup_probe_complete_);
    EXPECT_EQ(controller.congestion_window(), 12000u);
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    auto last_probe = send_copa_probe_packets(
        controller, {.count = 1, .first_packet_number = 19, .sent_time_ms = 100});
    const auto ack_time = coquic::quic::test::test_time(150);
    ack_copa_packets(controller, last_probe, ack_time, std::chrono::microseconds{150000},
                     std::chrono::microseconds{100000});

    EXPECT_TRUE(controller.startup_probe_complete_);
    EXPECT_TRUE(controller.slow_start_);
    EXPECT_EQ(controller.congestion_window(), 12000u);
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    auto second = make_sent_packet(/*packet_number=*/20, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200, ack_time);
    controller.on_packet_sent(second);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/2400).has_value());

    controller.on_packets_acked(std::array<SentPacketRecord, 1>{second}, /*app_limited=*/false,
                                coquic::quic::test::test_time(250),
                                coquic::quic::RecoveryRttState{
                                    .latest_rtt = std::chrono::milliseconds{150},
                                    .min_rtt = std::chrono::milliseconds{100},
                                    .smoothed_rtt = std::chrono::milliseconds{150},
                                });
    EXPECT_TRUE(controller.slow_start_);
    EXPECT_EQ(controller.congestion_window(), 13200u);

    std::array<SentPacketRecord, 11> exit_packets{};
    for (std::size_t index = 0; index < exit_packets.size(); ++index) {
        exit_packets[index] = make_sent_packet(/*packet_number=*/21 + index, /*ack_eliciting=*/true,
                                               /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                               coquic::quic::test::test_time(1000));
        controller.on_packet_sent(exit_packets[index]);
    }
    controller.on_packets_acked(exit_packets, /*app_limited=*/false,
                                coquic::quic::test::test_time(2000),
                                coquic::quic::RecoveryRttState{
                                    .latest_rtt = std::chrono::milliseconds{2000},
                                    .min_rtt = std::chrono::milliseconds{100},
                                    .smoothed_rtt = std::chrono::milliseconds{2000},
                                });
    EXPECT_FALSE(controller.slow_start_);
    EXPECT_EQ(controller.congestion_window(), 26400u);

    const auto before_decrease = controller.congestion_window();
    auto third = make_sent_packet(/*packet_number=*/32, /*ack_eliciting=*/true,
                                  /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                  coquic::quic::test::test_time(2000));
    controller.on_packet_sent(third);
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{third}, /*app_limited=*/false,
                                coquic::quic::test::test_time(2100),
                                coquic::quic::RecoveryRttState{
                                    .latest_rtt = std::chrono::milliseconds{2000},
                                    .min_rtt = std::chrono::milliseconds{100},
                                    .smoothed_rtt = std::chrono::milliseconds{2000},
                                });
    EXPECT_EQ(controller.update_direction_, -1);
    EXPECT_LT(controller.congestion_window(), before_decrease);
    EXPECT_GE(controller.congestion_window(), controller.minimum_window());
}

TEST(QuicCongestionTest, CopaDoesNotPaceSlowStartBurst) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);

    auto first = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                                  /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    controller.on_packet_sent(first);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    controller = CopaCongestionController(/*max_datagram_size=*/1200);
    for (std::uint64_t packet_number = 1; packet_number <= 9; ++packet_number) {
        ASSERT_TRUE(controller.can_send_ack_eliciting(/*bytes=*/1200));
        auto packet = make_sent_packet(packet_number, /*ack_eliciting=*/true, /*in_flight=*/true,
                                       /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
        controller.on_packet_sent(packet);
        EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());
    }

    EXPECT_TRUE(controller.can_send_ack_eliciting(/*bytes=*/1200));
    auto tenth = make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true, /*in_flight=*/true,
                                  /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    controller.on_packet_sent(tenth);
    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/1200));
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());
}

TEST(QuicCongestionTest, CopaPacingStartsAfterDelayTargetExitsSlowStart) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);

    auto initial_probe =
        send_copa_probe_packets(controller, {.count = 18, .first_packet_number = 1});
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/2400).has_value());
    ack_copa_packets(controller, initial_probe, coquic::quic::test::test_time(100),
                     std::chrono::microseconds{150000}, std::chrono::microseconds{100000});
    EXPECT_TRUE(controller.slow_start_);
    EXPECT_FALSE(controller.startup_probe_complete_);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/2400).has_value());

    auto last_probe = send_copa_probe_packets(
        controller, {.count = 1, .first_packet_number = 19, .sent_time_ms = 100});
    ack_copa_packets(controller, last_probe, coquic::quic::test::test_time(150),
                     std::chrono::microseconds{150000}, std::chrono::microseconds{100000});

    EXPECT_TRUE(controller.startup_probe_complete_);
    EXPECT_TRUE(controller.slow_start_);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/2400).has_value());
    std::array<SentPacketRecord, 12> paced_packets{};
    for (std::size_t index = 0; index < paced_packets.size(); ++index) {
        paced_packets[index] = make_sent_packet(
            /*packet_number=*/20 + index, /*ack_eliciting=*/true,
            /*in_flight=*/true, /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1000));
        controller.on_packet_sent(paced_packets[index]);
    }
    ack_copa_packets(controller, paced_packets, coquic::quic::test::test_time(2000),
                     std::chrono::microseconds{2000000}, std::chrono::microseconds{100000});
    ASSERT_FALSE(controller.slow_start_);

    controller.pacing_budget_bytes_ = controller.pacing_budget_cap();
    EXPECT_EQ(controller.next_send_time(/*bytes=*/1200),
              std::optional{coquic::quic::test::test_time(1000)});
    controller.pacing_budget_bytes_ = 0;
    const auto future_pacing_deadline = controller.next_send_time(/*bytes=*/2400);
    ASSERT_TRUE(future_pacing_deadline.has_value());
    EXPECT_GT(optional_ref_or_terminate(future_pacing_deadline),
              coquic::quic::test::test_time(1000));
}

TEST(QuicCongestionTest, CopaUsesAdjustedRttForDelayTarget) {
    CopaCongestionController raw_controller(/*max_datagram_size=*/1200);
    CopaCongestionController adjusted_controller(/*max_datagram_size=*/1200);

    raw_controller.slow_start_ = false;
    adjusted_controller.slow_start_ = false;
    raw_controller.congestion_window_ = 48000;
    adjusted_controller.congestion_window_ = 48000;
    raw_controller.sync_congestion_window_segments();
    adjusted_controller.sync_congestion_window_segments();
    raw_controller.latest_rtt_ = std::chrono::microseconds{100000};
    raw_controller.min_rtt_ = std::chrono::microseconds{100000};
    adjusted_controller.latest_rtt_ = std::chrono::microseconds{100000};
    adjusted_controller.min_rtt_ = std::chrono::microseconds{100000};

    auto raw_packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(100));
    auto adjusted_packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                            /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                            coquic::quic::test::test_time(100));
    raw_controller.on_packet_sent(raw_packet);
    adjusted_controller.on_packet_sent(adjusted_packet);

    raw_controller.on_packets_acked(std::array<SentPacketRecord, 1>{raw_packet},
                                    /*app_limited=*/false, coquic::quic::QuicCoreTimePoint{},
                                    coquic::quic::RecoveryRttState{
                                        .latest_rtt_sample = std::chrono::microseconds{3000000},
                                        .min_rtt_sample = std::chrono::microseconds{100000},
                                        .smoothed_rtt = std::chrono::milliseconds{3000},
                                    });
    adjusted_controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{adjusted_packet}, /*app_limited=*/false,
        coquic::quic::test::test_time(200),
        coquic::quic::RecoveryRttState{
            .latest_rtt_sample = std::chrono::microseconds{125000},
            .latest_adjusted_rtt_sample = std::chrono::microseconds{100000},
            .min_rtt_sample = std::chrono::microseconds{100000},
            .smoothed_rtt = std::chrono::milliseconds{125},
        });

    EXPECT_LT(raw_controller.congestion_window(), 48000u);
    EXPECT_GT(adjusted_controller.congestion_window(), 48000u);
    EXPECT_EQ(raw_controller.update_direction_, -1);
    EXPECT_EQ(adjusted_controller.update_direction_, 1);
}

TEST(QuicCongestionTest, CopaUsesAckDelayCompensatedRttForQueueDelay) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);
    controller.slow_start_ = false;
    controller.congestion_window_ = 48000;
    controller.latest_rtt_ = std::chrono::microseconds{100000};
    controller.min_rtt_ = std::chrono::microseconds{100000};
    controller.set_pacing_rate();

    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(0));
    controller.on_packet_sent(packet);
    controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
        coquic::quic::test::test_time(100),
        coquic::quic::RecoveryRttState{
            .latest_rtt_sample = std::chrono::microseconds{125000},
            .latest_adjusted_rtt_sample = std::chrono::microseconds{125000},
            .latest_ack_delay_compensated_rtt_sample = std::chrono::microseconds{100000},
            .min_rtt_sample = std::chrono::microseconds{100000},
        });

    EXPECT_GT(controller.congestion_window(), 48000u);
    EXPECT_EQ(controller.latest_rtt_, std::chrono::microseconds{100000});
}

TEST(QuicCongestionTest, CopaKeepsCompensatedRttMinimumOnSameSampleBasis) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);
    controller.slow_start_ = false;
    controller.congestion_window_ = 48000;
    controller.latest_rtt_ = std::chrono::microseconds{100000};
    controller.min_rtt_ = std::chrono::microseconds{100000};
    controller.set_pacing_rate();

    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(0));
    controller.on_packet_sent(packet);
    controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
        coquic::quic::test::test_time(100),
        coquic::quic::RecoveryRttState{
            .latest_rtt_sample = std::chrono::microseconds{25000},
            .latest_adjusted_rtt_sample = std::chrono::microseconds{25000},
            .latest_ack_delay_compensated_rtt_sample = std::chrono::microseconds{1000},
            .min_rtt_sample = std::chrono::microseconds{24000},
            .smoothed_rtt = std::chrono::milliseconds{25},
        });

    EXPECT_EQ(controller.latest_rtt_, std::chrono::microseconds{1000});
    EXPECT_EQ(controller.min_rtt_, std::chrono::microseconds{1000});
    EXPECT_GT(controller.congestion_window(), 48000u);
}

TEST(QuicCongestionTest, CopaUsesMicrosecondRttSamplesForDelayTarget) {
    CopaCongestionController coarse_controller(/*max_datagram_size=*/1200);
    CopaCongestionController precise_controller(/*max_datagram_size=*/1200);

    coarse_controller.slow_start_ = false;
    precise_controller.slow_start_ = false;
    coarse_controller.congestion_window_ = 300000;
    precise_controller.congestion_window_ = 300000;
    coarse_controller.latest_rtt_ = std::chrono::microseconds{100500};
    coarse_controller.min_rtt_ = std::chrono::microseconds{100000};
    precise_controller.latest_rtt_ = std::chrono::microseconds{100500};
    precise_controller.min_rtt_ = std::chrono::microseconds{100000};
    coarse_controller.set_pacing_rate();
    precise_controller.set_pacing_rate();

    auto coarse_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    auto precise_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    coarse_controller.on_packet_sent(coarse_packet);
    precise_controller.on_packet_sent(precise_packet);

    coarse_controller.on_packets_acked(std::array<SentPacketRecord, 1>{coarse_packet},
                                       /*app_limited=*/false, coquic::quic::test::test_time(100),
                                       coquic::quic::RecoveryRttState{
                                           .latest_rtt = std::chrono::milliseconds{110},
                                           .min_rtt = std::chrono::milliseconds{100},
                                           .smoothed_rtt = std::chrono::milliseconds{110},
                                       });
    precise_controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{precise_packet}, /*app_limited=*/false,
        coquic::quic::test::test_time(100),
        coquic::quic::RecoveryRttState{
            .latest_rtt = std::chrono::milliseconds{102},
            .min_rtt = std::chrono::milliseconds{100},
            .latest_rtt_sample = std::chrono::microseconds{100500},
            .latest_adjusted_rtt_sample = std::chrono::microseconds{100500},
            .min_rtt_sample = std::chrono::microseconds{100000},
            .smoothed_rtt = std::chrono::milliseconds{102},
        });

    EXPECT_LT(coarse_controller.congestion_window(), precise_controller.congestion_window());
    EXPECT_GT(precise_controller.congestion_window(), 300000u);
    EXPECT_EQ(precise_controller.latest_rtt_, std::chrono::microseconds{100500});
    EXPECT_EQ(precise_controller.min_rtt_, std::chrono::microseconds{100000});
}

TEST(QuicCongestionTest, CopaSlowStartUsesSubMillisecondQueueDelay) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 300000;
    controller.latest_rtt_ = std::chrono::microseconds{100000};
    controller.min_rtt_ = std::chrono::microseconds{100000};
    controller.set_pacing_rate();

    std::array<SentPacketRecord, 19> packets{};
    for (std::size_t index = 0; index < packets.size(); ++index) {
        packets[index] = make_sent_packet(
            static_cast<std::uint64_t>(index + 1), /*ack_eliciting=*/true, /*in_flight=*/true,
            /*bytes_in_flight=*/1200, coquic::quic::test::test_time(static_cast<int>(index)));
        controller.on_packet_sent(packets[index]);
    }

    controller.on_packets_acked(packets, /*app_limited=*/false, coquic::quic::test::test_time(120),
                                coquic::quic::RecoveryRttState{
                                    .latest_rtt_sample = std::chrono::microseconds{120000},
                                    .latest_adjusted_rtt_sample = std::chrono::microseconds{120000},
                                    .min_rtt_sample = std::chrono::microseconds{100000},
                                    .smoothed_rtt = std::chrono::milliseconds{120},
                                });

    EXPECT_TRUE(controller.slow_start_);
    EXPECT_EQ(controller.congestion_window(), 300000u);

    auto packet = make_sent_packet(/*packet_number=*/20, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(120));
    controller.on_packet_sent(packet);
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
                                coquic::quic::test::test_time(220),
                                coquic::quic::RecoveryRttState{
                                    .latest_rtt_sample = std::chrono::microseconds{120000},
                                    .latest_adjusted_rtt_sample = std::chrono::microseconds{120000},
                                    .min_rtt_sample = std::chrono::microseconds{100000},
                                    .smoothed_rtt = std::chrono::milliseconds{120},
                                });

    EXPECT_FALSE(controller.slow_start_);
    EXPECT_GT(controller.congestion_window(), 300000u);
    EXPECT_LT(controller.congestion_window(), 330000u);
}

TEST(QuicCongestionTest, CopaRttWindowUsesUnjitteredMinimum) {
    CopaCongestionController windowed_controller(/*max_datagram_size=*/1200);

    windowed_controller.slow_start_ = false;
    windowed_controller.congestion_window_ = 24000;

    for (std::int64_t sample = 1; sample <= 3; ++sample) {
        windowed_controller.update_rtt_model(
            coquic::quic::RecoveryRttState{
                .latest_rtt_sample = std::chrono::microseconds{100000},
                .min_rtt_sample = std::chrono::microseconds{100000},
            },
            coquic::quic::test::test_time(sample));
    }

    auto windowed_packet =
        make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));
    windowed_controller.on_packet_sent(windowed_packet);

    const auto spike_rtt = coquic::quic::RecoveryRttState{
        .latest_rtt_sample = std::chrono::microseconds{30000000},
        .min_rtt_sample = std::chrono::microseconds{100000},
    };
    windowed_controller.on_packets_acked(std::array<SentPacketRecord, 1>{windowed_packet},
                                         /*app_limited=*/false, coquic::quic::test::test_time(50),
                                         spike_rtt);

    EXPECT_GT(windowed_controller.congestion_window(), 24000u);
    EXPECT_EQ(windowed_controller.unjittered_rtt_, std::chrono::microseconds{100000});
}

TEST(QuicCongestionTest, CopaReducesWindowWhenQueueDelayExceedsTarget) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);
    controller.slow_start_ = false;
    controller.congestion_window_ = 48000;
    controller.latest_rtt_ = std::chrono::microseconds{300000};
    controller.min_rtt_ = std::chrono::microseconds{100000};
    controller.set_pacing_rate();

    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(0));
    controller.on_packet_sent(packet);
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
                                coquic::quic::test::test_time(150),
                                coquic::quic::RecoveryRttState{
                                    .latest_rtt = std::chrono::milliseconds{300},
                                    .min_rtt = std::chrono::milliseconds{100},
                                    .smoothed_rtt = std::chrono::milliseconds{300},
                                });

    EXPECT_LT(controller.congestion_window(), 48000u);
    EXPECT_EQ(controller.update_direction_, -1);
}

TEST(QuicCongestionTest, CopaLossDiscardAndPersistentCongestionPaths) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 24000;
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/false);
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(1));
    controller.on_packet_sent(packet);
    EXPECT_EQ(controller.bytes_in_flight(), 1200u);

    controller.on_packets_lost(std::array<SentPacketRecord, 1>{packet});
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.bytes_in_flight_ = 600;
    controller.on_packets_discarded(std::array<SentPacketRecord, 2>{
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(2)),
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(3)),
    });
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.congestion_window_ = 24000;
    controller.on_loss_event(coquic::quic::test::test_time(10), packet.sent_time);
    EXPECT_EQ(controller.congestion_window(), 16800u);
    controller.on_loss_event(coquic::quic::test::test_time(11), packet.sent_time);
    EXPECT_EQ(controller.congestion_window(), 16800u);

    controller.on_persistent_congestion();
    EXPECT_EQ(controller.congestion_window(), controller.minimum_window());
    EXPECT_FALSE(controller.slow_start_);
}

TEST(QuicCongestionTest, CopaWrapperDispatchCoversAccessorsAndCopyMove) {
    coquic::quic::QuicCongestionController wrapper(
        coquic::quic::QuicCongestionControlAlgorithm::copa, /*max_datagram_size=*/1200);

    EXPECT_EQ(wrapper.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::copa);
    EXPECT_EQ(wrapper.name(), "copa");
    EXPECT_EQ(wrapper.minimum_window(), 2400u);
    EXPECT_TRUE(std::holds_alternative<CopaCongestionController>(wrapper.storage_));

    auto packet = make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(5));
    wrapper.on_packet_sent(packet);
    EXPECT_EQ(wrapper.bytes_in_flight(), 1200u);
    EXPECT_TRUE(wrapper.can_send_ack_eliciting(1200));
    EXPECT_EQ(wrapper.pacing_send_quantum(), 2400u);

    wrapper.on_packets_acked(std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
                             coquic::quic::test::test_time(155),
                             coquic::quic::RecoveryRttState{
                                 .latest_rtt = std::chrono::milliseconds{150},
                                 .min_rtt = std::chrono::milliseconds{100},
                                 .smoothed_rtt = std::chrono::milliseconds{150},
                             });
    EXPECT_EQ(wrapper.bytes_in_flight(), 0u);
    EXPECT_EQ(wrapper.congestion_window(), 12000u);

    auto copied = wrapper;
    EXPECT_EQ(copied.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::copa);

    auto assigned = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::newreno, /*max_datagram_size=*/1200);
    assigned = wrapper;
    EXPECT_EQ(assigned.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::copa);

    auto moved = std::move(copied);
    EXPECT_EQ(moved.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::copa);

    auto move_assigned = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr, /*max_datagram_size=*/1200);
    move_assigned = std::move(assigned);
    EXPECT_EQ(move_assigned.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::copa);

    move_assigned.congestion_window_ = 48000;
    move_assigned.bytes_in_flight_ = 1200;
    EXPECT_EQ(move_assigned.congestion_window(), 48000u);
    EXPECT_EQ(move_assigned.bytes_in_flight(), 1200u);

    move_assigned.on_persistent_congestion();
    EXPECT_EQ(move_assigned.congestion_window(), move_assigned.minimum_window());

    move_assigned.reset_for_new_path();
    EXPECT_EQ(move_assigned.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::copa);
    EXPECT_EQ(move_assigned.congestion_window(), 12000u);
    EXPECT_EQ(move_assigned.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, CopaPacingBudgetAndAckGuardsCoverColdPaths) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);

    auto non_ack_eliciting = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/false,
                                              /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                              coquic::quic::test::test_time(1));
    controller.on_packet_sent(non_ack_eliciting);
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(10);
    controller.pacing_budget_bytes_ = 2400;
    controller.slow_start_ = false;
    controller.startup_probe_complete_ = true;
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/0).has_value());
    EXPECT_EQ(controller.next_send_time(/*bytes=*/1200), controller.pacing_budget_timestamp_);

    controller.bytes_in_flight_ = controller.congestion_window();
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    controller.bytes_in_flight_ = 0;
    controller.pacing_budget_bytes_ = 0;
    controller.pacing_rate_bytes_per_second_ = 0.0;
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(11)),
              controller.pacing_budget_cap());

    controller.pacing_rate_bytes_per_second_ = 1200000.0;
    controller.pacing_budget_bytes_ = 3000;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(9)),
              controller.pacing_budget_cap());
    controller.pacing_budget_bytes_ = 0;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(11)), 1200u);

    controller.bytes_in_flight_ = 1200;
    auto old_recovery = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                         /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                         coquic::quic::test::test_time(2));
    auto non_in_flight = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                          /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                          coquic::quic::test::test_time(12));
    auto app_limited = make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                        /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                        coquic::quic::test::test_time(13));
    auto non_ack = make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/false,
                                    /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                    coquic::quic::test::test_time(14));
    app_limited.app_limited = true;
    controller.recovery_start_time_ = coquic::quic::test::test_time(10);
    controller.on_packets_acked(
        std::array<SentPacketRecord, 4>{
            old_recovery,
            non_in_flight,
            app_limited,
            non_ack,
        },
        /*app_limited=*/true, coquic::quic::test::test_time(20),
        coquic::quic::RecoveryRttState{
            .latest_rtt = std::chrono::milliseconds{0},
            .min_rtt = std::chrono::milliseconds{0},
            .smoothed_rtt = std::chrono::milliseconds{0},
        });
    EXPECT_FALSE(controller.recovery_start_time_.has_value());
    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_EQ(controller.latest_rtt_, std::chrono::microseconds{1000});
    EXPECT_EQ(controller.min_rtt_, std::chrono::microseconds{1000});

    controller.latest_rtt_.reset();
    controller.min_rtt_.reset();
    auto cold_ack = make_sent_packet(/*packet_number=*/6, /*ack_eliciting=*/true,
                                     /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                     coquic::quic::test::test_time(21));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{cold_ack},
                                /*app_limited=*/false, coquic::quic::test::test_time(22),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{0},
                                });
    EXPECT_FALSE(controller.latest_rtt_.has_value());
    EXPECT_FALSE(controller.min_rtt_.has_value());
}

TEST(QuicCongestionTest, CopaTargetRttAndVelocityBranchesAreCovered) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);

    controller.latest_rtt_ = std::chrono::microseconds{100000};
    controller.min_rtt_ = std::chrono::microseconds{100000};
    EXPECT_FALSE(controller.target_window().finite);
    controller.latest_rtt_.reset();
    EXPECT_FALSE(controller.target_window().finite);
    controller.latest_rtt_ = std::chrono::microseconds{100000};
    controller.min_rtt_.reset();
    EXPECT_FALSE(controller.target_window().finite);

    controller.update_rtt_model(coquic::quic::RecoveryRttState{
        .smoothed_rtt = std::chrono::milliseconds{80},
    });
    EXPECT_EQ(controller.latest_rtt_, std::chrono::microseconds{80000});
    EXPECT_EQ(controller.min_rtt_, std::chrono::microseconds{80000});

    controller.latest_rtt_ = std::chrono::microseconds{0};
    controller.min_rtt_ = std::chrono::microseconds{0};
    controller.congestion_window_ = 12000;
    controller.set_pacing_rate();
    EXPECT_GT(controller.pacing_rate_bytes_per_second_, 0.0);

    controller.slow_start_ = true;
    controller.congestion_window_ = 12000;
    controller.grow_slow_start(/*acked_bytes=*/1200, CopaCongestionController::CopaTarget{
                                                         .finite = true,
                                                         .window = 24000,
                                                     });
    EXPECT_TRUE(controller.slow_start_);
    EXPECT_EQ(controller.congestion_window(), 12000u);

    controller.slow_start_ = false;
    controller.latest_rtt_ = std::chrono::microseconds{100000};
    controller.min_rtt_ = std::chrono::microseconds{100000};
    controller.congestion_window_ = 12000;
    controller.last_velocity_update_time_ = coquic::quic::test::test_time(100);
    controller.update_direction_ = 1;
    controller.previous_update_direction_ = 1;
    controller.velocity_packets_ = 1.0;
    controller.adjust_congestion_avoidance(/*acked_bytes=*/1200,
                                           CopaCongestionController::CopaTarget{
                                               .finite = false,
                                           },
                                           coquic::quic::test::test_time(150));
    EXPECT_EQ(controller.velocity_packets_, 1.0);
    EXPECT_EQ(controller.update_direction_, 2);

    controller.adjust_congestion_avoidance(/*acked_bytes=*/1200,
                                           CopaCongestionController::CopaTarget{
                                               .finite = false,
                                           },
                                           coquic::quic::test::test_time(220));
    EXPECT_EQ(controller.velocity_packets_, 1.0);
    EXPECT_EQ(controller.previous_update_direction_, 2);
    EXPECT_EQ(controller.update_direction_, 1);

    controller.update_direction_ = -1;
    controller.previous_update_direction_ = 1;
    controller.last_velocity_update_time_ = coquic::quic::test::test_time(220);
    controller.adjust_congestion_avoidance(/*acked_bytes=*/1200,
                                           CopaCongestionController::CopaTarget{
                                               .finite = true,
                                               .window = 2400,
                                           },
                                           coquic::quic::test::test_time(320));
    EXPECT_EQ(controller.velocity_packets_, 1.0);
    EXPECT_EQ(controller.previous_update_direction_, -1);

    controller.congestion_window_ = 2401;
    controller.sync_congestion_window_segments();
    controller.adjust_congestion_avoidance(/*acked_bytes=*/1,
                                           CopaCongestionController::CopaTarget{
                                               .finite = true,
                                               .window = 2400,
                                           },
                                           coquic::quic::test::test_time(321));
    EXPECT_EQ(controller.congestion_window(), controller.minimum_window());

    controller.congestion_window_ = 2400;
    controller.on_loss_event(coquic::quic::test::test_time(400),
                             coquic::quic::test::test_time(401));
    EXPECT_EQ(controller.congestion_window(), controller.minimum_window());
}

TEST(QuicCongestionTest, CopaResidualCoverageBranches) {
    CopaCongestionController controller(/*max_datagram_size=*/1200);

    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(1));
    controller.on_packet_sent(packet);
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false);
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.latest_rtt_.reset();
    controller.min_rtt_ = std::chrono::microseconds{100000};
    controller.bytes_in_flight_ = 1200;
    auto no_latest_rtt = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                          /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                          coquic::quic::test::test_time(2));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{no_latest_rtt},
                                /*app_limited=*/false, coquic::quic::test::test_time(3),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{0},
                                });
    EXPECT_FALSE(controller.latest_rtt_.has_value());
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.latest_rtt_ = std::chrono::microseconds{100000};
    controller.min_rtt_.reset();
    controller.bytes_in_flight_ = 1200;
    auto no_min_rtt = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(3));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{no_min_rtt},
                                /*app_limited=*/false, coquic::quic::test::test_time(4),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{0},
                                });
    EXPECT_EQ(controller.min_rtt_, std::chrono::microseconds{100000});
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.recovery_start_time_ = coquic::quic::test::test_time(10);
    controller.on_loss_event(coquic::quic::test::test_time(20), coquic::quic::test::test_time(11));
    EXPECT_EQ(controller.recovery_start_time_, coquic::quic::test::test_time(20));

    auto app_limited_recovery_exit =
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(21));
    app_limited_recovery_exit.app_limited = true;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{app_limited_recovery_exit},
                                /*app_limited=*/true, coquic::quic::test::test_time(22),
                                coquic::quic::RecoveryRttState{});
    EXPECT_FALSE(controller.recovery_start_time_.has_value());

    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(30);
    controller.pacing_budget_bytes_ = 1000;
    controller.consume_pacing_budget(/*bytes=*/1000, coquic::quic::test::test_time(30));
    EXPECT_EQ(controller.pacing_budget_bytes_, 0u);

    controller.latest_rtt_ = std::chrono::microseconds{100000};
    controller.min_rtt_ = std::chrono::microseconds{100000};
    controller.last_velocity_update_time_ = coquic::quic::test::test_time(40);
    controller.previous_update_direction_ = 1;
    controller.update_direction_ = 0;
    controller.update_velocity(coquic::quic::test::test_time(140));
    EXPECT_EQ(controller.previous_update_direction_, 1);
}

TEST(QuicCongestionTest, BbrSamplesBandwidthAndTracksMinimumRttFromAckedPackets) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(10));

    controller.on_packet_sent(packet);

    EXPECT_EQ(packet.delivered, 0u);
    EXPECT_EQ(packet.delivered_time, packet.sent_time);
    EXPECT_EQ(packet.first_sent_time, packet.sent_time);
    EXPECT_EQ(packet.tx_in_flight, 1200u);
    EXPECT_EQ(packet.lost, 0u);
    EXPECT_EQ(controller.bytes_in_flight(), 1200u);

    const std::array<SentPacketRecord, 1> acked_packets{packet};
    const auto rtt_state = coquic::quic::RecoveryRttState{
        .latest_rtt = std::chrono::milliseconds{100},
        .min_rtt = std::chrono::milliseconds{100},
    };
    controller.on_packets_acked(acked_packets, /*app_limited=*/false,
                                coquic::quic::test::test_time(110), rtt_state);

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    ASSERT_TRUE(controller.min_rtt_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(controller.min_rtt_), std::chrono::milliseconds{100});
    EXPECT_GT(controller.max_bandwidth_bytes_per_second_, 0.0);
    EXPECT_GE(controller.congestion_window(), controller.minimum_window());
}

TEST(QuicCongestionTest, BbrPacingBudgetProducesFutureSendDeadlineAfterBurst) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.pacing_rate_bytes_per_second_ = 120000.0;
    controller.max_bandwidth_bytes_per_second_ = 120000.0;
    controller.min_rtt_ = std::chrono::milliseconds{100};

    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    auto first_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    controller.on_packet_sent(first_packet);
    EXPECT_EQ(controller.pacing_budget_bytes_, 1200u);
    EXPECT_EQ(controller.next_send_time(/*bytes=*/1200),
              std::optional{coquic::quic::test::test_time(0)});
    EXPECT_EQ(controller.next_send_time(/*bytes=*/2400),
              std::optional{coquic::quic::test::test_time(10)});

    auto second_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    controller.on_packet_sent(second_packet);
    EXPECT_EQ(controller.pacing_budget_bytes_, 0u);
    EXPECT_EQ(controller.next_send_time(/*bytes=*/1200),
              std::optional{coquic::quic::test::test_time(10)});

    controller.congestion_window_ = controller.bytes_in_flight_;
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());
}

TEST(QuicCongestionTest, BbrStartupModeDoesNotExposePacingDeadline) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(7);
    controller.pacing_budget_bytes_ = 1200;

    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());
}

TEST(QuicCongestionTest, BbrPersistentCongestionClearsPacingDeadline) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.pacing_rate_bytes_per_second_ = 120000.0;
    controller.max_bandwidth_bytes_per_second_ = 120000.0;

    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    controller.on_packet_sent(packet);
    ASSERT_TRUE(controller.next_send_time(/*bytes=*/2400).has_value());

    controller.on_persistent_congestion();

    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());
}

TEST(QuicCongestionTest, BbrIdleRestartPinsPacingRateToBandwidthInProbeBw) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
    controller.full_bw_reached_ = true;
    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.pacing_rate_bytes_per_second_ = 200000.0;
    controller.app_limited_until_delivered_ = 1;

    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                                   /*bytes_in_flight=*/1200, coquic::quic::test::test_time(5));
    controller.on_packet_sent(packet);

    EXPECT_TRUE(controller.idle_restart_);
    EXPECT_LT(controller.pacing_rate_bytes_per_second_, 200000.0);
    EXPECT_GT(controller.pacing_rate_bytes_per_second_, 0.0);
}

TEST(QuicCongestionTest, BbrAppLimitedBubbleMarksPacketsUntilDeliveredThreshold) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);

    auto first_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    first_packet.app_limited = true;
    controller.on_packet_sent(first_packet);

    ASSERT_NE(controller.app_limited_until_delivered_, 0u);
    EXPECT_TRUE(first_packet.app_limited);

    auto second_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));
    second_packet.app_limited = false;
    controller.on_packet_sent(second_packet);

    EXPECT_TRUE(second_packet.app_limited);

    const auto rtt_state = coquic::quic::RecoveryRttState{
        .latest_rtt = std::chrono::milliseconds{100},
        .min_rtt = std::chrono::milliseconds{100},
    };
    controller.on_packets_acked(std::array<SentPacketRecord, 2>{first_packet, second_packet},
                                /*app_limited=*/false, coquic::quic::test::test_time(100),
                                rtt_state);

    EXPECT_EQ(controller.app_limited_until_delivered_, 0u);
}

TEST(QuicCongestionTest, BbrUsesAckedPacketAppLimitedStateForBandwidthSample) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.total_delivered_ = 2400;
    controller.bytes_in_flight_ = 2400;
    controller.min_rtt_ = std::chrono::milliseconds{100};

    auto first_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(10));
    first_packet.app_limited = true;
    first_packet.delivered = 0;
    first_packet.delivered_time = coquic::quic::test::test_time(0);
    first_packet.first_sent_time = coquic::quic::test::test_time(0);
    first_packet.tx_in_flight = 1200;

    auto second_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11));
    second_packet.app_limited = false;
    second_packet.delivered = 1200;
    second_packet.delivered_time = coquic::quic::test::test_time(1);
    second_packet.first_sent_time = coquic::quic::test::test_time(1);
    second_packet.tx_in_flight = 2400;

    const auto rs = controller.generate_rate_sample(
        std::array<SentPacketRecord, 2>{first_packet, second_packet},
        /*app_limited=*/true, coquic::quic::test::test_time(111), coquic::quic::RecoveryRttState{});

    EXPECT_TRUE(rs.has_newly_acked);
    EXPECT_FALSE(rs.is_app_limited);
    EXPECT_EQ(rs.prior_delivered, second_packet.delivered);
}

TEST(QuicCongestionTest, BbrRateSampleUsesNewestPacketNumberForEqualSendTime) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.total_delivered_ = 2400;
    controller.bytes_in_flight_ = 2400;
    controller.min_rtt_ = std::chrono::milliseconds{100};

    auto first_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(10));
    first_packet.delivered = 1200;
    first_packet.delivered_time = coquic::quic::test::test_time(5);
    first_packet.first_sent_time = coquic::quic::test::test_time(4);
    first_packet.tx_in_flight = 3600;

    auto second_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(10));
    second_packet.delivered = 2400;
    second_packet.delivered_time = coquic::quic::test::test_time(6);
    second_packet.first_sent_time = coquic::quic::test::test_time(8);
    second_packet.tx_in_flight = 2400;

    const auto rs = controller.generate_rate_sample(
        std::array<SentPacketRecord, 2>{first_packet, second_packet},
        /*app_limited=*/false, coquic::quic::test::test_time(120),
        coquic::quic::RecoveryRttState{});

    EXPECT_TRUE(rs.has_newly_acked);
    EXPECT_EQ(rs.prior_delivered, second_packet.delivered);
    EXPECT_EQ(rs.delivered, 2400u);
    EXPECT_EQ(rs.tx_in_flight, second_packet.tx_in_flight);
}

TEST(QuicCongestionTest, BbrSamplesBandwidthWhenAckIntervalIsBelowMinRtt) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.total_delivered_ = 1200;
    controller.bytes_in_flight_ = 1200;
    controller.min_rtt_ = std::chrono::milliseconds{10};

    auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(2));
    packet.delivered = 0;
    packet.delivered_time = coquic::quic::test::test_time(0);
    packet.first_sent_time = coquic::quic::test::test_time(1);
    packet.tx_in_flight = 1200;

    const auto rs = controller.generate_rate_sample(
        std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
        coquic::quic::test::test_time(3), coquic::quic::RecoveryRttState{});

    EXPECT_TRUE(rs.has_newly_acked);
    EXPECT_EQ(rs.delivered, 2400u);
    EXPECT_DOUBLE_EQ(rs.delivery_rate_bytes_per_second, 800000.0);
}

TEST(QuicCongestionTest, BbrUsesTimerGranularityForZeroRttModel) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.full_bw_reached_ = true;
    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.bandwidth_bytes_per_second_ = 50'000'000.0;
    controller.max_bandwidth_bytes_per_second_ = controller.bandwidth_bytes_per_second_;
    controller.min_rtt_ = std::chrono::milliseconds{0};
    controller.congestion_window_ = 84'000;
    controller.send_quantum_ = 2'400;

    controller.set_cwnd(make_rate_sample(/*delivery_rate_bytes_per_second=*/50'000'000.0,
                                         /*newly_acked=*/2'400, /*lost=*/0, /*tx_in_flight=*/84'000,
                                         /*prior_delivered=*/0, /*delivered=*/2'400));

    EXPECT_EQ(controller.model_min_rtt(), coquic::quic::kGranularity);
    EXPECT_GE(controller.max_inflight_, 50'000u);
    EXPECT_GT(controller.congestion_window_, 25'000u);
}

TEST(QuicCongestionTest, BbrLateAckRestoresProbeUpStateAfterSpuriousLoss) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_down;
    controller.undo_state_ = BbrCongestionController::Mode::probe_bw_up;
    controller.undo_bw_shortterm_ = std::numeric_limits<double>::infinity();
    controller.undo_inflight_shortterm_ = std::numeric_limits<std::size_t>::max();
    controller.undo_inflight_longterm_ = 24000u;
    controller.inflight_longterm_ = 12000u;
    controller.bw_shortterm_ = 1000.0;
    controller.inflight_shortterm_ = 6000u;

    SentPacketRecord late_acked{
        .packet_number = 7,
        .sent_time = coquic::quic::test::test_time(5),
        .ack_eliciting = true,
        .in_flight = false,
        .declared_lost = true,
        .bytes_in_flight = 0,
    };

    controller.on_packets_acked(std::array<SentPacketRecord, 1>{late_acked},
                                /*app_limited=*/false, coquic::quic::test::test_time(15),
                                coquic::quic::RecoveryRttState{});

    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_up);
    EXPECT_EQ(controller.inflight_longterm_, 24000u);
    EXPECT_TRUE(std::isinf(controller.bw_shortterm_));
    EXPECT_EQ(controller.inflight_shortterm_, std::numeric_limits<std::size_t>::max());
}

TEST(QuicCongestionTest, BbrStartupHighLossLeavesStartupAndDrainsIntoProbeBw) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::startup;
    controller.max_bandwidth_bytes_per_second_ = 120000.0;
    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.min_rtt_ = std::chrono::milliseconds{100};
    controller.loss_round_start_ = true;
    controller.previous_round_had_loss_ = true;
    controller.previous_round_lost_bytes_ = 1800;
    controller.previous_round_loss_events_ = 6;
    controller.recovery_start_time_ = coquic::quic::test::test_time(1);
    controller.round_count_ = 3;
    controller.recovery_round_start_ = 1;
    controller.inflight_latest_ = 24000;

    controller.check_startup_done();

    EXPECT_TRUE(controller.full_bw_now_);
    EXPECT_TRUE(controller.full_bw_reached_);
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::drain);
    EXPECT_DOUBLE_EQ(controller.pacing_gain_, 0.5);
    EXPECT_DOUBLE_EQ(controller.cwnd_gain_, 2.0);
    EXPECT_GE(controller.inflight_longterm_, 24000u);

    controller.bytes_in_flight_ = controller.inflight(1.0);
    controller.check_drain_done(coquic::quic::test::test_time(5));

    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_down);
    EXPECT_EQ(controller.ack_phase_, BbrCongestionController::AckPhase::probe_stopping);
    ASSERT_TRUE(controller.cycle_stamp_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(controller.cycle_stamp_), coquic::quic::test::test_time(5));
}

TEST(QuicCongestionTest, BbrUpdatesLossSignalsAndLongTermBandwidthModel) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.bandwidth_filter_[0] = 80000.0;
    controller.bandwidth_filter_[1] = 60000.0;
    controller.bandwidth_filter_cycle_[0] = 0;
    controller.bandwidth_filter_cycle_[1] = 0;
    controller.max_bandwidth_bytes_per_second_ = 80000.0;
    controller.congestion_window_ = 20000;
    controller.loss_round_start_ = true;
    controller.loss_in_round_ = true;
    controller.loss_bytes_in_round_ = 2400;
    controller.loss_events_in_round_ = 2;
    controller.bw_latest_ = 90000.0;
    controller.inflight_latest_ = 15000;

    controller.update_congestion_signals(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/120000.0,
                         /*newly_acked=*/2400, /*lost=*/0, /*tx_in_flight=*/15000,
                         /*prior_delivered=*/0, /*delivered=*/2400));

    EXPECT_TRUE(controller.previous_round_had_loss_);
    EXPECT_EQ(controller.previous_round_lost_bytes_, 2400u);
    EXPECT_EQ(controller.previous_round_loss_events_, 2u);
    EXPECT_DOUBLE_EQ(controller.bw_shortterm_, 90000.0);
    EXPECT_EQ(controller.inflight_shortterm_, 15000u);
    EXPECT_FALSE(controller.loss_in_round_);
    EXPECT_EQ(controller.loss_bytes_in_round_, 0u);
    EXPECT_EQ(controller.loss_events_in_round_, 0u);
    EXPECT_FALSE(controller.last_lost_packet_number_.has_value());

    controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
    controller.ack_phase_ = BbrCongestionController::AckPhase::probe_starting;
    controller.round_start_ = true;
    controller.congestion_window_ = 12000;
    controller.bytes_in_flight_ = 10800;
    controller.send_quantum_ = 1200;
    controller.inflight_longterm_ = 12000;
    controller.probe_up_cnt_ = 1;

    controller.adapt_long_term_model(make_rate_sample(/*delivery_rate_bytes_per_second=*/125000.0,
                                                      /*newly_acked=*/2400, /*lost=*/0,
                                                      /*tx_in_flight=*/12000,
                                                      /*prior_delivered=*/0, /*delivered=*/2400));

    EXPECT_EQ(controller.ack_phase_, BbrCongestionController::AckPhase::probe_feedback);
    EXPECT_EQ(controller.inflight_longterm_, 14400u);
    EXPECT_EQ(controller.bw_probe_up_rounds_, 1u);
    EXPECT_EQ(controller.probe_up_cnt_, 10u);

    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.ack_phase_ = BbrCongestionController::AckPhase::probe_stopping;
    controller.round_start_ = true;
    controller.cycle_count_ = 0;
    controller.bandwidth_filter_[0] = 50000.0;
    controller.bandwidth_filter_[1] = 70000.0;
    controller.bandwidth_filter_cycle_[0] = 0;
    controller.bandwidth_filter_cycle_[1] = 0;
    controller.max_bandwidth_bytes_per_second_ = 70000.0;
    controller.inflight_longterm_ = 14000;

    controller.adapt_long_term_model(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/0, /*lost=*/0,
                         /*tx_in_flight=*/18000, /*prior_delivered=*/0, /*delivered=*/0,
                         std::nullopt, /*is_app_limited=*/false,
                         /*has_newly_acked=*/false));

    EXPECT_EQ(controller.cycle_count_, 1u);
    EXPECT_DOUBLE_EQ(controller.max_bandwidth_bytes_per_second_, 50000.0);
    EXPECT_EQ(controller.inflight_longterm_, 18000u);
    EXPECT_EQ(controller.ack_phase_, BbrCongestionController::AckPhase::refilling);

    controller.round_start_ = true;
    controller.adapt_long_term_model(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/0, /*lost=*/0,
                         /*tx_in_flight=*/18000, /*prior_delivered=*/0, /*delivered=*/0,
                         std::nullopt, /*is_app_limited=*/false,
                         /*has_newly_acked=*/false));

    EXPECT_EQ(controller.cycle_count_, 1u);
    EXPECT_DOUBLE_EQ(controller.max_bandwidth_bytes_per_second_, 50000.0);
}

TEST(QuicCongestionTest, BbrProbeBwCycleTransitionsAcrossAllPhases) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.full_bw_reached_ = true;
    controller.max_bandwidth_bytes_per_second_ = 120000.0;
    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.min_rtt_ = std::chrono::milliseconds{100};
    controller.inflight_longterm_ = 24000;
    controller.congestion_window_ = 24000;
    controller.mode_ = BbrCongestionController::Mode::probe_bw_down;
    controller.bytes_in_flight_ = 10000;
    controller.cycle_stamp_ = coquic::quic::test::test_time(0);
    controller.bw_probe_wait_ = std::chrono::seconds{5};
    const auto rs = make_rate_sample(/*delivery_rate_bytes_per_second=*/120000.0,
                                     /*newly_acked=*/1200, /*lost=*/0, /*tx_in_flight=*/12000,
                                     /*prior_delivered=*/0, /*delivered=*/1200);

    controller.update_probe_bw_cycle_phase(rs, coquic::quic::test::test_time(1));
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_cruise);

    controller.cycle_stamp_ = coquic::quic::test::test_time(0);
    controller.bw_probe_wait_ = std::chrono::milliseconds{1};
    controller.update_probe_bw_cycle_phase(rs, coquic::quic::test::test_time(2));
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_refill);
    EXPECT_EQ(controller.ack_phase_, BbrCongestionController::AckPhase::refilling);
    EXPECT_EQ(controller.bw_probe_up_rounds_, 0u);
    EXPECT_EQ(controller.bw_probe_up_acks_, 0u);

    controller.round_start_ = true;
    controller.update_probe_bw_cycle_phase(rs, coquic::quic::test::test_time(3));
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_up);
    EXPECT_EQ(controller.ack_phase_, BbrCongestionController::AckPhase::probe_starting);
    EXPECT_TRUE(controller.bw_probe_samples_);

    controller.full_bw_now_ = true;
    controller.bytes_in_flight_ = 0;
    controller.send_quantum_ = 0;
    controller.update_probe_bw_cycle_phase(rs, coquic::quic::test::test_time(4));
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_down);
}

TEST(QuicCongestionTest, BbrLossRecoveryTransitionsOutOfProbeUpWhenInflightIsTooHigh) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
    controller.full_bw_reached_ = true;
    controller.bw_probe_samples_ = true;
    controller.congestion_window_ = 24000;
    controller.bytes_in_flight_ = 24000;
    controller.inflight_longterm_ = 24000;
    controller.max_bandwidth_bytes_per_second_ = 120000.0;
    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.min_rtt_ = std::chrono::milliseconds{100};

    auto first_lost =
        make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(5));
    first_lost.tx_in_flight = 24000;
    first_lost.lost = 0;

    auto second_lost =
        make_sent_packet(/*packet_number=*/11, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(5));
    second_lost.tx_in_flight = 22800;
    second_lost.lost = 1200;

    controller.on_packets_lost(std::array<SentPacketRecord, 2>{first_lost, second_lost});

    EXPECT_EQ(controller.bytes_in_flight_, 21600u);
    EXPECT_TRUE(controller.loss_in_round_);
    EXPECT_EQ(controller.loss_events_in_round_, 1u);
    EXPECT_TRUE(controller.bw_probe_samples_);
    EXPECT_FALSE(controller.pending_probe_bw_down_);
    EXPECT_EQ(controller.inflight_longterm_, 24000u);

    auto third_lost =
        make_sent_packet(/*packet_number=*/12, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(5));
    third_lost.tx_in_flight = 21600;
    third_lost.lost = 1200;

    controller.on_packets_lost(std::array<SentPacketRecord, 1>{third_lost});

    EXPECT_EQ(controller.bytes_in_flight_, 20400u);
    EXPECT_EQ(controller.loss_events_in_round_, 1u);
    EXPECT_FALSE(controller.bw_probe_samples_);
    EXPECT_TRUE(controller.pending_probe_bw_down_);
    EXPECT_LT(controller.inflight_longterm_, 24000u);

    const auto previous_random_state = controller.random_state_;
    controller.on_loss_event(coquic::quic::test::test_time(7), second_lost.sent_time);

    ASSERT_TRUE(controller.recovery_start_time_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(controller.recovery_start_time_),
              coquic::quic::test::test_time(7));
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_down);
    EXPECT_EQ(controller.undo_state_, BbrCongestionController::Mode::probe_bw_up);
    EXPECT_TRUE(controller.prior_congestion_window_.has_value());
    EXPECT_FALSE(controller.pending_probe_bw_down_);
    EXPECT_NE(controller.random_state_, previous_random_state);
}

TEST(QuicCongestionTest, BbrProbeRttLifecycleRestoresProbeBwCruiseAndStartupModes) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.full_bw_reached_ = true;
    controller.congestion_window_ = 24000;
    controller.max_bandwidth_bytes_per_second_ = 120000.0;
    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.min_rtt_ = std::chrono::milliseconds{100};
    controller.probe_rtt_expired_ = true;
    controller.bytes_in_flight_ = controller.probe_rtt_cwnd();

    controller.check_probe_rtt(make_rate_sample(/*delivery_rate_bytes_per_second=*/120000.0,
                                                /*newly_acked=*/0, /*lost=*/0, /*tx_in_flight=*/0,
                                                /*prior_delivered=*/0, /*delivered=*/0),
                               coquic::quic::test::test_time(10));

    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_rtt);
    ASSERT_TRUE(controller.probe_rtt_done_stamp_.has_value());
    EXPECT_DOUBLE_EQ(controller.pacing_gain_, 1.0);
    EXPECT_DOUBLE_EQ(controller.cwnd_gain_, 0.5);
    EXPECT_TRUE(controller.app_limited_until_delivered_ != 0);

    controller.round_start_ = true;
    controller.handle_probe_rtt(optional_ref_or_terminate(controller.probe_rtt_done_stamp_) +
                                std::chrono::milliseconds{1});

    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_cruise);
    EXPECT_EQ(controller.congestion_window_, 24000u);
    EXPECT_FALSE(controller.probe_rtt_done_stamp_.has_value());
    EXPECT_FALSE(controller.probe_rtt_round_done_);

    BbrCongestionController startup_controller(/*max_datagram_size=*/1200);
    startup_controller.enter_probe_rtt();
    startup_controller.bw_shortterm_ = 1.0;
    startup_controller.inflight_shortterm_ = 1;
    startup_controller.exit_probe_rtt(coquic::quic::test::test_time(20));

    EXPECT_EQ(startup_controller.mode_, BbrCongestionController::Mode::startup);
    EXPECT_TRUE(std::isinf(startup_controller.bw_shortterm_));
    EXPECT_EQ(startup_controller.inflight_shortterm_, std::numeric_limits<std::size_t>::max());
}

TEST(QuicCongestionTest, BbrProbeRttRefreshUsesMinRttWindow) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.full_bw_reached_ = true;
    controller.min_rtt_ = std::chrono::milliseconds{100};
    controller.min_rtt_stamp_ = coquic::quic::test::test_time(0);
    controller.probe_rtt_min_delay_ = std::chrono::milliseconds{100};
    controller.probe_rtt_min_stamp_ = coquic::quic::test::test_time(0);

    controller.update_min_rtt(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/120000.0,
                         /*newly_acked=*/1200, /*lost=*/0, /*tx_in_flight=*/1200,
                         /*prior_delivered=*/0, /*delivered=*/1200, std::chrono::milliseconds{100}),
        coquic::quic::test::test_time(9999));

    EXPECT_FALSE(controller.probe_rtt_expired_);

    controller.update_min_rtt(make_rate_sample(/*delivery_rate_bytes_per_second=*/120000.0,
                                               /*newly_acked=*/1200, /*lost=*/0,
                                               /*tx_in_flight=*/1200,
                                               /*prior_delivered=*/1200, /*delivered=*/1200,
                                               std::chrono::milliseconds{100}),
                              coquic::quic::test::test_time(10001));

    EXPECT_FALSE(controller.probe_rtt_expired_);

    controller.update_min_rtt(make_rate_sample(/*delivery_rate_bytes_per_second=*/120000.0,
                                               /*newly_acked=*/1200, /*lost=*/0,
                                               /*tx_in_flight=*/1200,
                                               /*prior_delivered=*/2400, /*delivered=*/1200,
                                               std::chrono::milliseconds{100}),
                              coquic::quic::test::test_time(30001));

    EXPECT_TRUE(controller.probe_rtt_expired_);
}

TEST(QuicCongestionTest, BbrHelperPredicatesMathAndWrapperDispatchCoverAccessors) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.mode_ = BbrCongestionController::Mode::startup;
    EXPECT_TRUE(controller.is_probing_bw());

    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    EXPECT_FALSE(controller.is_probing_bw());
    controller.congestion_window_ = 12000;
    controller.bytes_in_flight_ = 10800;
    controller.send_quantum_ = 1200;
    EXPECT_TRUE(controller.is_cwnd_limited());
    controller.bytes_in_flight_ = 9600;
    EXPECT_FALSE(controller.is_cwnd_limited());

    controller.cycle_stamp_ = coquic::quic::test::test_time(5);
    EXPECT_FALSE(controller.has_elapsed_in_phase(std::chrono::milliseconds{10},
                                                 coquic::quic::test::test_time(15)));
    EXPECT_TRUE(controller.has_elapsed_in_phase(std::chrono::milliseconds{10},
                                                coquic::quic::test::test_time(16)));

    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.min_rtt_ = std::chrono::milliseconds{100};
    controller.congestion_window_ = 24000;
    controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
    EXPECT_EQ(controller.target_inflight(), 12000u);
    EXPECT_EQ(controller.probe_rtt_cwnd(), 6000u);
    EXPECT_EQ(controller.inflight(1.0), 14400u);
    controller.inflight_longterm_ = 24000;
    EXPECT_EQ(controller.inflight_with_headroom(), 20400u);
    EXPECT_DOUBLE_EQ(controller.pacing_gain(), controller.pacing_gain_);

    controller.rounds_since_bw_probe_ = controller.packets_for_bytes(controller.target_inflight());
    EXPECT_TRUE(controller.is_reno_coexistence_probe_time());
    controller.mode_ = BbrCongestionController::Mode::probe_bw_down;
    EXPECT_TRUE(controller.is_time_to_probe_bw(coquic::quic::test::test_time(20)));
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_refill);

    controller.mode_ = BbrCongestionController::Mode::probe_bw_down;
    controller.bytes_in_flight_ = 13000;
    EXPECT_FALSE(controller.is_time_to_cruise());
    controller.bytes_in_flight_ = 10000;
    EXPECT_TRUE(controller.is_time_to_cruise());

    auto rate_sample = make_rate_sample(/*delivery_rate_bytes_per_second=*/130000.0,
                                        /*newly_acked=*/0, /*lost=*/0, /*tx_in_flight=*/12000,
                                        /*prior_delivered=*/0, /*delivered=*/0);
    controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
    controller.inflight_longterm_ = 12000;
    controller.congestion_window_ = 12000;
    controller.bytes_in_flight_ = 10800;
    controller.send_quantum_ = 1200;
    controller.full_bandwidth_bytes_per_second_ = 1.0;
    controller.full_bw_now_ = false;
    EXPECT_FALSE(controller.is_time_to_go_down(rate_sample));
    EXPECT_DOUBLE_EQ(controller.full_bandwidth_bytes_per_second_, 130000.0);

    controller.bytes_in_flight_ = 0;
    controller.send_quantum_ = 0;
    controller.full_bw_now_ = true;
    EXPECT_TRUE(controller.is_time_to_go_down(rate_sample));

    const auto tolerated_single_packet_loss =
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/0,
                         /*lost=*/1200,
                         /*tx_in_flight=*/24000, /*prior_delivered=*/0, /*delivered=*/0);
    EXPECT_FALSE(controller.is_inflight_too_high(tolerated_single_packet_loss));

    const auto loss_rs = make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                          /*newly_acked=*/0, /*lost=*/1300,
                                          /*tx_in_flight=*/10000, /*prior_delivered=*/0,
                                          /*delivered=*/0);
    EXPECT_TRUE(controller.is_inflight_too_high(loss_rs));
    EXPECT_FALSE(controller.is_inflight_too_high(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/0,
                         /*lost=*/10, /*tx_in_flight=*/0, /*prior_delivered=*/0,
                         /*delivered=*/0)));
    controller.adapt_long_term_model(loss_rs);
    EXPECT_FALSE(controller.bw_probe_samples_);
    EXPECT_EQ(controller.next_random(), 1015568748u);
    EXPECT_EQ(controller.next_random(), 1586005467u);

    const auto loss_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    EXPECT_EQ(
        controller.inflight_at_loss(make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                                     /*newly_acked=*/0, /*lost=*/1200,
                                                     /*tx_in_flight=*/24000, /*prior_delivered=*/0,
                                                     /*delivered=*/0),
                                    loss_packet),
        23265u);

    coquic::quic::QuicCongestionController wrapper(
        coquic::quic::QuicCongestionControlAlgorithm::bbr, /*max_datagram_size=*/1200);
    EXPECT_EQ(wrapper.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::bbr);
    EXPECT_EQ(wrapper.name(), "bbr");
    EXPECT_EQ(wrapper.minimum_window(), 4800u);
    wrapper.reset_for_new_path();
    EXPECT_EQ(wrapper.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::bbr);
    EXPECT_EQ(wrapper.minimum_window(), 4800u);

    auto &bbr = std::get<BbrCongestionController>(wrapper.storage_);
    bbr.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};
    bbr.send_quantum_ = 4800;

    auto wrapper_packet =
        make_sent_packet(/*packet_number=*/9, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    wrapper.on_packet_sent(wrapper_packet);
    ASSERT_TRUE(wrapper.can_send_ack_eliciting(1200));
    ASSERT_TRUE(wrapper.next_send_time(2400).has_value());
    EXPECT_EQ(wrapper.pacing_send_quantum(), 4800u);

    wrapper.on_packets_acked(std::array<SentPacketRecord, 1>{wrapper_packet}, /*app_limited=*/false,
                             coquic::quic::test::test_time(100),
                             coquic::quic::RecoveryRttState{
                                 .latest_rtt = std::chrono::milliseconds{100},
                                 .min_rtt = std::chrono::milliseconds{100},
                             });

    auto copied = wrapper;
    EXPECT_EQ(copied.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::bbr);
    EXPECT_EQ(copied.name(), "bbr");

    auto assigned = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::newreno, /*max_datagram_size=*/1200);
    assigned = wrapper;
    EXPECT_EQ(assigned.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::bbr);

    auto moved = std::move(copied);
    EXPECT_EQ(moved.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::bbr);

    auto move_assigned = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::newreno, /*max_datagram_size=*/1200);
    move_assigned = std::move(assigned);
    EXPECT_EQ(move_assigned.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::bbr);

    auto null_handle = coquic::quic::QuicCongestionController::TestMetricHandle{};
    EXPECT_EQ(static_cast<std::size_t>(null_handle), 0u);
    auto cwnd_handle = coquic::quic::QuicCongestionController::TestMetricHandle(
        &moved, /*congestion_window=*/true);
    auto copied_cwnd_handle = coquic::quic::QuicCongestionController::TestMetricHandle(
        &moved, /*congestion_window=*/true);
    auto bif_handle = coquic::quic::QuicCongestionController::TestMetricHandle(
        &moved, /*congestion_window=*/false);
    copied_cwnd_handle = cwnd_handle;
    EXPECT_EQ(static_cast<std::size_t>(copied_cwnd_handle), moved.congestion_window());
    bif_handle = std::move(cwnd_handle);
    EXPECT_EQ(static_cast<std::size_t>(bif_handle), moved.congestion_window());

    move_assigned.on_packets_lost(std::array<SentPacketRecord, 1>{wrapper_packet});
    move_assigned.on_loss_event(coquic::quic::test::test_time(101), wrapper_packet.sent_time);
    move_assigned.on_persistent_congestion();
    EXPECT_EQ(move_assigned.congestion_window(), move_assigned.minimum_window());
}

TEST(QuicCongestionTest, CubicWrapperDispatchCoversAccessorsAndCopyMove) {
    coquic::quic::QuicCongestionController wrapper(
        coquic::quic::QuicCongestionControlAlgorithm::cubic, /*max_datagram_size=*/1200);

    EXPECT_EQ(wrapper.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::cubic);
    EXPECT_EQ(wrapper.name(), "cubic");
    EXPECT_EQ(wrapper.minimum_window(), 2400u);
    EXPECT_TRUE(std::holds_alternative<CubicCongestionController>(wrapper.storage_));

    auto packet = make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                   /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                   coquic::quic::test::test_time(1));
    wrapper.on_packet_sent(packet);
    EXPECT_EQ(wrapper.bytes_in_flight(), 1200u);
    EXPECT_TRUE(wrapper.can_send_ack_eliciting(1200));
    EXPECT_FALSE(wrapper.next_send_time(1200).has_value());
    EXPECT_EQ(wrapper.pacing_send_quantum(), 12000u);

    wrapper.on_packets_acked(std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
                             coquic::quic::test::test_time(101),
                             coquic::quic::RecoveryRttState{
                                 .smoothed_rtt = std::chrono::milliseconds{100},
                             });
    EXPECT_EQ(wrapper.bytes_in_flight(), 0u);
    EXPECT_GT(wrapper.congestion_window(), 12000u);
    EXPECT_FALSE(wrapper.next_send_time(1200).has_value());

    auto copied = wrapper;
    EXPECT_EQ(copied.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::cubic);

    auto assigned = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::newreno, /*max_datagram_size=*/1200);
    assigned = wrapper;
    EXPECT_EQ(assigned.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::cubic);

    auto moved = std::move(copied);
    EXPECT_EQ(moved.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::cubic);

    auto move_assigned = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr, /*max_datagram_size=*/1200);
    move_assigned = std::move(assigned);
    EXPECT_EQ(move_assigned.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::cubic);

    move_assigned.congestion_window_ = 48000;
    move_assigned.bytes_in_flight_ = 1200;
    EXPECT_EQ(move_assigned.congestion_window(), 48000u);
    EXPECT_EQ(move_assigned.bytes_in_flight(), 1200u);

    auto discarded = make_sent_packet(/*packet_number=*/8, /*ack_eliciting=*/true,
                                      /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                      coquic::quic::test::test_time(2));
    move_assigned.on_packets_discarded(std::array<SentPacketRecord, 1>{discarded});
    EXPECT_EQ(move_assigned.bytes_in_flight(), 0u);

    move_assigned.bytes_in_flight_ = 1200;
    auto lost = make_sent_packet(/*packet_number=*/9, /*ack_eliciting=*/true,
                                 /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                 coquic::quic::test::test_time(3));
    move_assigned.on_packets_lost(std::array<SentPacketRecord, 1>{lost});
    EXPECT_EQ(move_assigned.bytes_in_flight(), 0u);

    move_assigned.congestion_window_ = 24000;
    move_assigned.on_loss_event(coquic::quic::test::test_time(4), coquic::quic::test::test_time(4));
    EXPECT_LT(move_assigned.congestion_window(), 24000u);
    move_assigned.on_persistent_congestion();
    EXPECT_EQ(move_assigned.congestion_window(), move_assigned.minimum_window());

    move_assigned.reset_for_new_path();
    EXPECT_EQ(move_assigned.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::cubic);
    EXPECT_EQ(move_assigned.congestion_window(), 12000u);
    EXPECT_EQ(move_assigned.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, CubicPacingBudgetProducesFutureSendDeadlineAfterBurst) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    std::vector<SentPacketRecord> acked_packets;
    acked_packets.reserve(28);
    for (std::uint64_t packet_number = 1; packet_number <= 28; ++packet_number) {
        auto packet = make_sent_packet(packet_number, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(0));
        packet.stream_fragments.push_back(coquic::quic::StreamFrameSendFragment{
            .stream_id = 0,
            .bytes = coquic::quic::SharedBytes(std::vector<std::byte>(1)),
        });
        controller.on_packet_sent(packet);
        acked_packets.push_back(std::move(packet));
    }
    controller.on_packets_acked(acked_packets, /*app_limited=*/false,
                                coquic::quic::test::test_time(100),
                                coquic::quic::RecoveryRttState{
                                    .latest_rtt = std::chrono::milliseconds{100},
                                    .min_rtt = std::chrono::milliseconds{100},
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    ASSERT_TRUE(controller.pacing_active());
    EXPECT_EQ(controller.pacing_budget_cap(), 12000u);
    EXPECT_EQ(static_cast<std::uint64_t>(controller.pacing_rate_bytes_per_second_), 912000u);
    EXPECT_EQ(controller.next_send_time(/*bytes=*/1200),
              std::optional{coquic::quic::test::test_time(100)});

    for (std::uint64_t packet_number = 2; packet_number <= 11; ++packet_number) {
        auto packet = make_sent_packet(packet_number, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(100));
        controller.on_packet_sent(packet);
    }

    const auto deadline = controller.next_send_time(/*bytes=*/1200);
    ASSERT_TRUE(deadline.has_value());
    EXPECT_GT(optional_ref_or_terminate(deadline), coquic::quic::test::test_time(100));
}

TEST(QuicCongestionTest, CubicSimpleStreamAckPathCoversSlowStartRecoveryAndPacing) {
    CubicCongestionController controller(/*max_datagram_size=*/1200);

    controller.on_simple_stream_packets_acked(
        std::span<const coquic::quic::AckedStreamPacketSample>{},
        /*app_limited=*/false, coquic::quic::test::test_time(1),
        coquic::quic::RecoveryRttState{
            .smoothed_rtt = std::chrono::milliseconds{100},
        });
    EXPECT_GT(controller.pacing_rate_bytes_per_second_, 0.0);

    controller.bytes_in_flight_ = 0;
    const std::array<coquic::quic::AckedStreamPacketSample, 1> saturated_subtract_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 59,
            .sent_time = coquic::quic::test::test_time(59),
            .congestion_send_sequence = 59,
            .bytes_in_flight = 1200,
        },
    };
    controller.on_simple_stream_packets_acked(saturated_subtract_sample, /*app_limited=*/false,
                                              coquic::quic::test::test_time(60),
                                              coquic::quic::RecoveryRttState{
                                                  .latest_rtt = std::chrono::milliseconds{100},
                                                  .min_rtt = std::chrono::milliseconds{100},
                                                  .smoothed_rtt = std::chrono::milliseconds{100},
                                              });
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.bytes_in_flight_ = 36000;
    std::array<coquic::quic::AckedStreamPacketSample, 28> slow_start_samples{};
    for (std::size_t index = 0; index < slow_start_samples.size(); ++index) {
        slow_start_samples[index] = coquic::quic::AckedStreamPacketSample{
            .packet_number = static_cast<std::uint64_t>(index + 1),
            .sent_time = coquic::quic::test::test_time(static_cast<std::int64_t>(index + 1)),
            .congestion_send_sequence = static_cast<std::uint64_t>(index + 1),
            .bytes_in_flight = 1200,
        };
    }
    controller.on_simple_stream_packets_acked(slow_start_samples, /*app_limited=*/false,
                                              coquic::quic::test::test_time(100),
                                              coquic::quic::RecoveryRttState{
                                                  .latest_rtt = std::chrono::milliseconds{100},
                                                  .min_rtt = std::chrono::milliseconds{100},
                                                  .smoothed_rtt = std::chrono::milliseconds{100},
                                              });
    EXPECT_EQ(controller.bytes_in_flight(), 2400u);
    EXPECT_GT(controller.congestion_window(), 12000u);
    EXPECT_TRUE(controller.pacing_active());

    CubicCongestionController hystart_exit_controller(/*max_datagram_size=*/1200);
    hystart_exit_controller.hystart_.exit_slow_start_ = true;
    hystart_exit_controller.bytes_in_flight_ = 1200;
    const std::array<coquic::quic::AckedStreamPacketSample, 1> hystart_exit_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 60,
            .sent_time = coquic::quic::test::test_time(60),
            .congestion_send_sequence = 60,
            .bytes_in_flight = 1200,
        },
    };
    hystart_exit_controller.on_simple_stream_packets_acked(
        hystart_exit_sample, /*app_limited=*/false, coquic::quic::test::test_time(120),
        coquic::quic::RecoveryRttState{
            .latest_rtt = std::chrono::milliseconds{100},
            .min_rtt = std::chrono::milliseconds{100},
            .smoothed_rtt = std::chrono::milliseconds{100},
        });
    EXPECT_TRUE(hystart_exit_controller.epoch_start_time_.has_value());
    EXPECT_EQ(hystart_exit_controller.slow_start_threshold_,
              hystart_exit_controller.congestion_window());

    controller.congestion_window_ = 24000;
    controller.slow_start_threshold_ = 24000;
    controller.w_max_segments_ = 24.0;
    controller.cwnd_prior_segments_ = 24.0;
    controller.w_est_segments_ = 20.0;
    controller.epoch_start_time_ = coquic::quic::test::test_time(100);
    controller.app_limited_start_time_ = coquic::quic::test::test_time(120);
    controller.bytes_in_flight_ = 1200;
    const std::array<coquic::quic::AckedStreamPacketSample, 1> congestion_avoidance_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 29,
            .sent_time = coquic::quic::test::test_time(140),
            .congestion_send_sequence = 29,
            .bytes_in_flight = 1200,
        },
    };
    controller.on_simple_stream_packets_acked(congestion_avoidance_sample, /*app_limited=*/false,
                                              coquic::quic::test::test_time(2000),
                                              coquic::quic::RecoveryRttState{
                                                  .smoothed_rtt = std::chrono::milliseconds{100},
                                              });
    EXPECT_FALSE(controller.app_limited_start_time_.has_value());
    EXPECT_GT(controller.app_limited_pause_, coquic::quic::QuicCoreDuration{0});

    controller.recovery_start_time_ = coquic::quic::test::test_time(3000);
    controller.epoch_start_time_ = coquic::quic::test::test_time(3000);
    controller.app_limited_start_time_.reset();
    const std::array<coquic::quic::AckedStreamPacketSample, 1> suppressed_recovery_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 30,
            .sent_time = coquic::quic::test::test_time(2999),
            .congestion_send_sequence = 30,
            .bytes_in_flight = 1200,
        },
    };
    controller.bytes_in_flight_ = 1200;
    controller.on_simple_stream_packets_acked(suppressed_recovery_sample, /*app_limited=*/false,
                                              coquic::quic::test::test_time(3010),
                                              coquic::quic::RecoveryRttState{
                                                  .smoothed_rtt = std::chrono::milliseconds{100},
                                              });
    EXPECT_TRUE(controller.app_limited_start_time_.has_value());
    EXPECT_TRUE(controller.recovery_start_time_.has_value());

    const std::array<coquic::quic::AckedStreamPacketSample, 1> exits_recovery_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 31,
            .sent_time = coquic::quic::test::test_time(3001),
            .congestion_send_sequence = 31,
            .bytes_in_flight = 1200,
        },
    };
    controller.bytes_in_flight_ = 1200;
    controller.on_simple_stream_packets_acked(exits_recovery_sample, /*app_limited=*/false,
                                              coquic::quic::test::test_time(3020),
                                              coquic::quic::RecoveryRttState{
                                                  .smoothed_rtt = std::chrono::milliseconds{100},
                                              });
    EXPECT_FALSE(controller.recovery_start_time_.has_value());

    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(10);
    controller.pacing_budget_bytes_ = 0;
    controller.pacing_rate_bytes_per_second_ = 0.0;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(20)),
              controller.pacing_budget_cap());

    controller.pacing_rate_bytes_per_second_ = 1000.0;
    controller.pacing_budget_bytes_ = 100;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(10)), 100u);
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(20000)),
              controller.pacing_budget_cap());
}

TEST(QuicCongestionTest, InRecoveryReflectsRecoveryStartBoundary) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    const auto boundary = coquic::quic::test::test_time(5);
    const auto older_packet =
        make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(4));
    const auto newer_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(6));

    EXPECT_FALSE(controller.in_recovery(older_packet));
    EXPECT_FALSE(controller.in_recovery(newer_packet));

    controller.on_loss_event(boundary, older_packet.sent_time);

    EXPECT_TRUE(controller.in_recovery(older_packet));
    EXPECT_FALSE(controller.in_recovery(newer_packet));
}

TEST(QuicCongestionTest, SlowStartGrowthMatchesAcknowledgedBytes) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);
    controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{
            make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true, /*in_flight=*/true,
                             /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0)),
        },
        /*app_limited=*/false);

    EXPECT_GT(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, PersistentCongestionCollapsesToMinimumWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_persistent_congestion();
    EXPECT_EQ(controller.congestion_window(), 2400u);
}

TEST(QuicCongestionTest, AppLimitedAckSaturatesBytesInFlightAndGrowsNewRenoWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);

    auto ack_only_packet =
        make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/0, coquic::quic::test::test_time(0));
    ack_only_packet.app_limited = true;
    auto app_limited_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/2400, coquic::quic::test::test_time(1));
    app_limited_packet.app_limited = true;

    controller.on_packets_acked(
        std::array<SentPacketRecord, 2>{ack_only_packet, app_limited_packet},
        /*app_limited=*/true);

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_EQ(controller.congestion_window(), 14400u);
}

TEST(QuicCongestionTest, NewRenoCountsMixedAppLimitedAckedPacketsForWindowGrowth) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/2400, /*ack_eliciting=*/true);

    auto app_limited_packet =
        make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    app_limited_packet.app_limited = true;
    auto non_app_limited_packet =
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1));

    controller.on_packets_acked(
        std::array<SentPacketRecord, 2>{app_limited_packet, non_app_limited_packet},
        /*app_limited=*/true);

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_EQ(controller.congestion_window(), 14400u);
}

TEST(QuicCongestionTest, AppLimitedAckSentDuringRecoveryStillExitsNewRenoRecovery) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/12000, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(5), coquic::quic::test::test_time(1));
    ASSERT_EQ(controller.congestion_window(), 6000u);

    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);
    auto recovery_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(6));
    recovery_packet.app_limited = true;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{recovery_packet},
                                /*app_limited=*/true);

    EXPECT_EQ(controller.congestion_window(), 6000u);
    EXPECT_EQ(controller.bytes_in_flight(), 12000u);
    controller.on_loss_event(coquic::quic::test::test_time(20), coquic::quic::test::test_time(19));
    EXPECT_EQ(controller.congestion_window(), 3000u);
}

TEST(QuicCongestionTest, NewRenoLateAckRestoresWindowAfterSpuriousLoss) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 24000;
    controller.slow_start_threshold_ = 48000;
    controller.bytes_in_flight_ = 24000;

    auto lost = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                 /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                 coquic::quic::test::test_time(1));
    controller.on_packets_lost(std::array<SentPacketRecord, 1>{lost});
    controller.on_loss_event(coquic::quic::test::test_time(10), lost.sent_time);
    ASSERT_EQ(controller.congestion_window(), 12000u);
    ASSERT_EQ(controller.slow_start_threshold_, 12000u);
    ASSERT_TRUE(controller.recovery_start_time_.has_value());

    auto late_acked = lost;
    late_acked.in_flight = false;
    late_acked.declared_lost = true;
    late_acked.bytes_in_flight = 0;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{late_acked},
                                /*app_limited=*/false, coquic::quic::test::test_time(20),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });

    EXPECT_FALSE(controller.recovery_start_time_.has_value());
    EXPECT_EQ(controller.congestion_window(), 24000u);
    EXPECT_EQ(controller.slow_start_threshold_, 48000u);
    EXPECT_FALSE(controller.prior_congestion_window_.has_value());
    EXPECT_FALSE(controller.prior_slow_start_threshold_.has_value());
}

TEST(QuicCongestionTest, NewRenoNormalRecoveryExitClearsSpuriousLossUndoState) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 24000;
    controller.slow_start_threshold_ = 48000;
    controller.bytes_in_flight_ = 24000;

    auto lost = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                 /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                 coquic::quic::test::test_time(1));
    controller.on_packets_lost(std::array<SentPacketRecord, 1>{lost});
    controller.on_loss_event(coquic::quic::test::test_time(10), lost.sent_time);
    ASSERT_EQ(controller.congestion_window(), 12000u);
    ASSERT_TRUE(controller.prior_congestion_window_.has_value());

    auto recovery_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{recovery_packet},
                                /*app_limited=*/false, coquic::quic::test::test_time(20),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    ASSERT_FALSE(controller.recovery_start_time_.has_value());
    EXPECT_FALSE(controller.prior_congestion_window_.has_value());
    EXPECT_FALSE(controller.prior_slow_start_threshold_.has_value());

    auto late_acked = lost;
    late_acked.in_flight = false;
    late_acked.declared_lost = true;
    late_acked.bytes_in_flight = 0;
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{late_acked},
                                /*app_limited=*/false, coquic::quic::test::test_time(30),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });

    EXPECT_EQ(controller.congestion_window(), 12000u);
    EXPECT_EQ(controller.slow_start_threshold_, 12000u);
}

TEST(QuicCongestionTest, CongestionWrapperDetectsWindowUnderutilizationAfterSend) {
    coquic::quic::QuicCongestionController wrapper(
        coquic::quic::QuicCongestionControlAlgorithm::newreno, /*max_datagram_size=*/1200);
    EXPECT_EQ(wrapper.pacing_send_quantum(), 1200u);
    wrapper.congestion_window_ = 12000;
    wrapper.bytes_in_flight_ = 10800;

    EXPECT_FALSE(wrapper.would_underutilize_congestion_window(/*bytes_sent=*/1200));
    EXPECT_TRUE(wrapper.would_underutilize_congestion_window(/*bytes_sent=*/1199));

    wrapper.bytes_in_flight_ = 12000;
    EXPECT_FALSE(wrapper.would_underutilize_congestion_window(/*bytes_sent=*/0));
}

TEST(QuicCongestionTest, DiscardedPacketsOnlyReduceNewRenoBytesInFlight) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.congestion_window_ = 18000;
    controller.bytes_in_flight_ = 1200;
    controller.recovery_start_time_ = coquic::quic::test::test_time(20);

    const auto cwnd = controller.congestion_window();
    const auto recovery_start_time = controller.recovery_start_time_;
    const std::array<SentPacketRecord, 2> packets{
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(10)),
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11)),
    };

    controller.on_packets_discarded(packets);

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_EQ(controller.congestion_window(), cwnd);
    EXPECT_EQ(controller.recovery_start_time_, recovery_start_time);

    controller.bytes_in_flight_ = 600;
    controller.on_packets_discarded(std::array<SentPacketRecord, 1>{
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(12)),
    });
    EXPECT_EQ(controller.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, RecoveryAckTransitionsToCongestionAvoidance) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/6000, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(1), coquic::quic::test::test_time(1));
    ASSERT_EQ(controller.congestion_window(), 6000u);

    controller.on_packet_sent(/*bytes_sent=*/6000, /*ack_eliciting=*/true);
    controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{
            make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                             /*bytes_in_flight=*/6000, coquic::quic::test::test_time(2)),
        },
        /*app_limited=*/false);

    EXPECT_EQ(controller.congestion_window(), 7200u);
    EXPECT_EQ(controller.bytes_in_flight(), 6000u);
}

TEST(QuicCongestionTest, NewRenoRecoveryUsesAckClockedSendWindowWhileCwndIsReduced) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.bytes_in_flight_ = 24000;
    controller.congestion_window_ = 24000;

    auto lost = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                 /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                 coquic::quic::test::test_time(1));
    controller.on_packets_lost(std::array<SentPacketRecord, 1>{lost});
    controller.on_loss_event(coquic::quic::test::test_time(10), lost.sent_time);

    EXPECT_EQ(controller.congestion_window(), 12000u);
    EXPECT_EQ(controller.slow_start_threshold_, 12000u);
    EXPECT_EQ(controller.bytes_in_flight(), 22800u);
    EXPECT_TRUE(controller.can_send_ack_eliciting(/*bytes=*/1200));
    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/1201));

    auto initial_recovery_send =
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(10));
    controller.on_packet_sent(initial_recovery_send);
    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/1));

    auto first_recovery_ack =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(2));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{first_recovery_ack},
                                /*app_limited=*/false, coquic::quic::test::test_time(20),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_EQ(controller.congestion_window(), 12000u);
    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/1200));
    EXPECT_TRUE(controller.recovery_start_time_.has_value());

    auto second_recovery_ack =
        make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/13200, coquic::quic::test::test_time(3));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{second_recovery_ack},
                                /*app_limited=*/false, coquic::quic::test::test_time(30),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_EQ(controller.bytes_in_flight(), 9600u);
    EXPECT_TRUE(controller.can_send_ack_eliciting(/*bytes=*/1200));
    EXPECT_TRUE(controller.can_send_ack_eliciting(/*bytes=*/2400));
    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/2401));
    EXPECT_TRUE(controller.recovery_start_time_.has_value());

    auto recovery_send =
        make_sent_packet(/*packet_number=*/6, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11));
    controller.on_packet_sent(recovery_send);

    auto exit_ack =
        make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(12));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{exit_ack},
                                /*app_limited=*/false, coquic::quic::test::test_time(40),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    EXPECT_FALSE(controller.recovery_start_time_.has_value());
    EXPECT_EQ(controller.recovery_flight_size_, 0u);
    EXPECT_EQ(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, NewRenoConsumesSameTickRecoveryCredit) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.bytes_in_flight_ = 24000;
    controller.congestion_window_ = 24000;

    auto lost = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                 /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                 coquic::quic::test::test_time(1));
    controller.on_packets_lost(std::array<SentPacketRecord, 1>{lost});
    const auto recovery_start = coquic::quic::test::test_time(10);
    controller.on_loss_event(recovery_start, lost.sent_time);

    auto recovery_ack =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/12000, coquic::quic::test::test_time(2));
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{recovery_ack},
                                /*app_limited=*/false, coquic::quic::test::test_time(20),
                                coquic::quic::RecoveryRttState{
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    ASSERT_TRUE(controller.can_send_ack_eliciting(/*bytes=*/1200));

    auto first_recovery_send =
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, recovery_start);
    controller.on_packet_sent(first_recovery_send);

    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/1200));
    EXPECT_TRUE(controller.recovery_start_time_.has_value());
}

TEST(QuicCongestionTest, AckBatchOrderDoesNotChangeRecoveryExit) {
    NewRenoCongestionController ascending(/*max_datagram_size=*/1200);
    NewRenoCongestionController descending(/*max_datagram_size=*/1200);

    for (auto *controller : {&ascending, &descending}) {
        controller->on_packet_sent(/*bytes_sent=*/18000, /*ack_eliciting=*/true);
        controller->on_loss_event(coquic::quic::test::test_time(5),
                                  coquic::quic::test::test_time(1));
        ASSERT_EQ(controller->congestion_window(), 6000u);
        controller->on_packet_sent(/*bytes_sent=*/6000, /*ack_eliciting=*/true);
    }

    const std::array<SentPacketRecord, 3> ascending_packets{
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(1)),
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(2)),
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(6)),
    };
    const std::array<SentPacketRecord, 3> descending_packets{
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(6)),
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(2)),
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/6000, coquic::quic::test::test_time(1)),
    };

    ascending.on_packets_acked(ascending_packets, /*app_limited=*/false);
    descending.on_packets_acked(descending_packets, /*app_limited=*/false);

    EXPECT_EQ(ascending.congestion_window(), descending.congestion_window());
    EXPECT_EQ(ascending.bytes_in_flight(), descending.bytes_in_flight());
    EXPECT_EQ(ascending.congestion_window(), 7200u);
    EXPECT_EQ(ascending.bytes_in_flight(), 6000u);

    const std::array<SentPacketRecord, 1> post_batch_packet{
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/7200, coquic::quic::test::test_time(5)),
    };

    ascending.on_packets_acked(post_batch_packet, /*app_limited=*/false);
    descending.on_packets_acked(post_batch_packet, /*app_limited=*/false);

    EXPECT_EQ(ascending.congestion_window(), descending.congestion_window());
    EXPECT_EQ(ascending.bytes_in_flight(), descending.bytes_in_flight());
    EXPECT_EQ(ascending.congestion_window(), 7200u);
    EXPECT_EQ(ascending.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, LossAccountingIgnoresNonInflightPacketsAndSaturatesToZero) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);

    controller.on_packets_lost(std::array<SentPacketRecord, 2>{
        make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/false, /*in_flight=*/false,
                         /*bytes_in_flight=*/0, coquic::quic::test::test_time(0)),
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/2400, coquic::quic::test::test_time(1)),
    });

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, LossEventDoesNotReduceWindowTwiceWithinRecoveryEpoch) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(5), coquic::quic::test::test_time(1));
    const auto first_reduction = controller.congestion_window();

    controller.on_loss_event(coquic::quic::test::test_time(5), coquic::quic::test::test_time(1));
    controller.on_loss_event(coquic::quic::test::test_time(4), coquic::quic::test::test_time(1));

    EXPECT_EQ(controller.congestion_window(), first_reduction);
}

TEST(QuicCongestionTest, LaterLossEventStartsANewRecoveryEpoch) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/12000, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(5), coquic::quic::test::test_time(1));
    const auto first_reduction = controller.congestion_window();

    auto recovery_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/first_reduction, coquic::quic::test::test_time(6));
    controller.on_packet_sent(recovery_packet);
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{recovery_packet},
                                /*app_limited=*/false);
    ASSERT_FALSE(controller.recovery_start_time_.has_value());
    const auto window_after_recovery_exit = controller.congestion_window();
    EXPECT_GT(window_after_recovery_exit, first_reduction);

    controller.on_loss_event(coquic::quic::test::test_time(7), coquic::quic::test::test_time(6));

    EXPECT_LT(controller.congestion_window(), window_after_recovery_exit);
    EXPECT_EQ(controller.congestion_window(), 3600u);
}

TEST(QuicCongestionTest, StaleLossAfterRecoveryExitDoesNotReduceNewRenoWindowAgain) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/12000, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(5), coquic::quic::test::test_time(1));
    const auto first_reduction = controller.congestion_window();

    auto recovery_packet =
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(6));
    controller.on_packet_sent(recovery_packet);
    controller.on_packets_acked(std::array<SentPacketRecord, 1>{recovery_packet},
                                /*app_limited=*/false);
    ASSERT_FALSE(controller.recovery_start_time_.has_value());

    controller.on_loss_event(coquic::quic::test::test_time(7), coquic::quic::test::test_time(4));

    EXPECT_EQ(controller.congestion_window(), first_reduction);
}

TEST(QuicCongestionTest, AlgorithmFallbackAndNewRenoColdBranches) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/false);
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    controller.on_packets_acked(
        std::array<SentPacketRecord, 1>{
            make_sent_packet(/*packet_number=*/0,
                             /*ack_eliciting=*/false,
                             /*in_flight=*/false,
                             /*bytes_in_flight=*/0, coquic::quic::test::test_time(0)),
        },
        /*app_limited=*/false, coquic::quic::test::test_time(1), coquic::quic::RecoveryRttState{});
    EXPECT_EQ(controller.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, NewRenoColdPacingPrimitivesAndBoundaryHelpers) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_TRUE(controller.can_send_ack_eliciting(/*bytes=*/12000));
    EXPECT_FALSE(controller.can_send_ack_eliciting(/*bytes=*/12001));
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/0).has_value());

    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(10);
    controller.pacing_budget_bytes_ = 0;
    controller.pacing_rate_bytes_per_second_ = 0.0;
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    controller.pacing_rate_bytes_per_second_ = 1000.0;
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/12001).has_value());

    controller.pacing_smoothed_rtt_ = coquic::quic::QuicCoreDuration::zero();
    controller.update_pacing_rate(coquic::quic::RecoveryRttState{
        .smoothed_rtt = coquic::quic::QuicCoreDuration::zero(),
    });
    EXPECT_EQ(controller.pacing_rate_bytes_per_second_, 0.0);

    controller.pacing_budget_timestamp_.reset();
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(11)),
              controller.pacing_budget_cap());

    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(10);
    controller.pacing_budget_bytes_ = 100;
    controller.pacing_rate_bytes_per_second_ = 0.0;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(11)),
              controller.pacing_budget_cap());

    controller.pacing_rate_bytes_per_second_ = 1000.0;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(11)), 101u);

    const std::array<coquic::quic::AckedStreamPacketSample, 1> empty_path_sample{
        coquic::quic::AckedStreamPacketSample{
            .packet_number = 1,
            .sent_time = coquic::quic::test::test_time(21),
            .congestion_send_sequence = 1,
            .bytes_in_flight = 1200,
        },
    };
    controller.on_simple_stream_packets_acked(
        std::span<const coquic::quic::AckedStreamPacketSample>{},
        /*app_limited=*/false, coquic::quic::test::test_time(12),
        coquic::quic::RecoveryRttState{.smoothed_rtt = std::chrono::milliseconds{100}});

    controller.recovery_start_time_ = coquic::quic::test::test_time(20);
    controller.bytes_in_flight_ = 600;
    controller.on_simple_stream_packets_acked(
        empty_path_sample,
        /*app_limited=*/false, coquic::quic::test::test_time(21),
        coquic::quic::RecoveryRttState{.smoothed_rtt = std::chrono::milliseconds{100}});
    EXPECT_FALSE(controller.recovery_start_time_.has_value());

    auto sent = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/true,
                                 /*bytes_in_flight=*/1200, coquic::quic::test::test_time(9));
    sent.congestion_send_sequence = 5;
    EXPECT_TRUE(controller.sent_on_or_before_recovery_boundary(
        sent, coquic::quic::test::test_time(1), std::uint64_t{5}));
    EXPECT_FALSE(controller.sent_after_recovery_boundary(sent, coquic::quic::test::test_time(1),
                                                         std::uint64_t{5}));

    coquic::quic::AckedStreamPacketSample acked{
        .packet_number = 3,
        .sent_time = coquic::quic::test::test_time(9),
        .congestion_send_sequence = 5,
        .bytes_in_flight = 1200,
    };
    EXPECT_TRUE(controller.sent_on_or_before_recovery_boundary(
        acked, coquic::quic::test::test_time(1), std::uint64_t{5}));
    EXPECT_FALSE(controller.sent_after_recovery_boundary(acked, coquic::quic::test::test_time(1),
                                                         std::uint64_t{5}));

    sent.congestion_send_sequence = 0;
    acked.congestion_send_sequence = 0;
    EXPECT_FALSE(controller.sent_on_or_before_recovery_boundary(sent, std::nullopt, std::nullopt));
    EXPECT_FALSE(controller.sent_on_or_before_recovery_boundary(acked, std::nullopt, std::nullopt));
    EXPECT_FALSE(controller.sent_after_recovery_boundary(sent, std::nullopt, std::nullopt));
    EXPECT_FALSE(controller.sent_after_recovery_boundary(acked, std::nullopt, std::nullopt));

    sent.sent_time = coquic::quic::test::test_time(9);
    acked.sent_time = coquic::quic::test::test_time(9);
    EXPECT_TRUE(controller.sent_on_or_before_recovery_boundary(
        sent, coquic::quic::test::test_time(10), std::nullopt));
    EXPECT_TRUE(controller.sent_on_or_before_recovery_boundary(
        acked, coquic::quic::test::test_time(10), std::nullopt));

    const std::array large_stream_packet{
        [&] {
            auto packet = make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                           /*in_flight=*/true, /*bytes_in_flight=*/32u * 1024u,
                                           coquic::quic::test::test_time(30));
            packet.stream_fragments.push_back(coquic::quic::StreamFrameSendFragment{
                .stream_id = 0,
                .bytes = coquic::quic::SharedBytes(std::vector<std::byte>(1)),
            });
            return packet;
        }(),
    };
    EXPECT_TRUE(controller.should_start_pacing(large_stream_packet));

    controller.last_recovery_start_time_ = coquic::quic::test::test_time(50);
    controller.last_recovery_start_sequence_ = 7;
    EXPECT_TRUE(controller.loss_on_or_before_last_recovery_boundary(
        coquic::quic::test::test_time(99), std::uint64_t{7}));
    EXPECT_FALSE(controller.loss_on_or_before_last_recovery_boundary(
        coquic::quic::test::test_time(49), std::uint64_t{8}));
    controller.last_recovery_start_sequence_.reset();
    EXPECT_TRUE(controller.loss_on_or_before_last_recovery_boundary(
        coquic::quic::test::test_time(50), std::nullopt));
}

TEST(QuicCongestionTest, NewRenoRecoverySendWindowCoversPrrCapBranches) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_EQ(controller.send_window(), controller.congestion_window());

    controller.recovery_start_time_ = coquic::quic::test::test_time(10);
    controller.recovery_flight_size_ = 1;
    controller.recovery_delivered_bytes_ = std::numeric_limits<std::size_t>::max();
    controller.slow_start_threshold_ = std::numeric_limits<std::size_t>::max();
    controller.recovery_sent_bytes_ = 1200;
    controller.bytes_in_flight_ = std::numeric_limits<std::size_t>::max();
    EXPECT_EQ(controller.send_window(), std::numeric_limits<std::size_t>::max());

    controller.recovery_delivered_bytes_ = 0;
    controller.slow_start_threshold_ = 12000;
    controller.recovery_sent_bytes_ = 0;
    controller.recovery_flight_size_ = 24000;
    controller.bytes_in_flight_ = 12000;
    EXPECT_EQ(controller.send_window(), 13200u);
}

TEST(QuicCongestionTest, NewRenoPacingBudgetProducesFutureSendDeadlineAfterBurst) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_FALSE(controller.next_send_time(/*bytes=*/1200).has_value());

    std::vector<SentPacketRecord> acked_packets;
    acked_packets.reserve(28);
    for (std::uint64_t packet_number = 1; packet_number <= 28; ++packet_number) {
        auto packet = make_sent_packet(packet_number, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(0));
        packet.stream_fragments.push_back(coquic::quic::StreamFrameSendFragment{
            .stream_id = 0,
            .bytes = coquic::quic::SharedBytes(std::vector<std::byte>(1)),
        });
        controller.on_packet_sent(packet);
        acked_packets.push_back(std::move(packet));
    }
    controller.on_packets_acked(acked_packets, /*app_limited=*/false,
                                coquic::quic::test::test_time(100),
                                coquic::quic::RecoveryRttState{
                                    .latest_rtt = std::chrono::milliseconds{100},
                                    .min_rtt = std::chrono::milliseconds{100},
                                    .smoothed_rtt = std::chrono::milliseconds{100},
                                });
    ASSERT_TRUE(controller.pacing_active());
    EXPECT_EQ(controller.pacing_budget_cap(), 1200u);
    EXPECT_EQ(static_cast<std::uint64_t>(controller.pacing_rate_bytes_per_second_), 912000u);
    EXPECT_EQ(controller.next_send_time(/*bytes=*/1200),
              std::optional{coquic::quic::test::test_time(100)});

    for (std::uint64_t packet_number = 2; packet_number <= 2; ++packet_number) {
        auto packet = make_sent_packet(packet_number, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(100));
        controller.on_packet_sent(packet);
    }

    const auto deadline = controller.next_send_time(/*bytes=*/1200);
    ASSERT_TRUE(deadline.has_value());
    EXPECT_GT(optional_ref_or_terminate(deadline), coquic::quic::test::test_time(100));
}

TEST(QuicCongestionTest, BbrAckLossAndIdleColdBranches) {
    BbrCongestionController pacing(/*max_datagram_size=*/1200);
    pacing.pacing_budget_timestamp_ = coquic::quic::test::test_time(0);
    pacing.pacing_budget_bytes_ = 0;
    pacing.send_quantum_ = 1200;
    pacing.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    pacing.pacing_rate_bytes_per_second_ = 0.0;
    EXPECT_FALSE(pacing.next_send_time(/*bytes=*/2400).has_value());

    auto non_ack = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/false,
                                    /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                    coquic::quic::test::test_time(0));
    pacing.on_packet_sent(non_ack);
    EXPECT_EQ(pacing.bytes_in_flight(), 0u);

    BbrCongestionController probe_rtt_restart(/*max_datagram_size=*/1200);
    probe_rtt_restart.mode_ = BbrCongestionController::Mode::probe_rtt;
    probe_rtt_restart.app_limited_until_delivered_ = 1;
    probe_rtt_restart.prior_congestion_window_ = 6000u;
    probe_rtt_restart.congestion_window_ = 4800u;
    probe_rtt_restart.probe_rtt_done_stamp_ = coquic::quic::test::test_time(5);
    probe_rtt_restart.handle_restart_from_idle(coquic::quic::test::test_time(6));
    EXPECT_EQ(probe_rtt_restart.mode_, BbrCongestionController::Mode::startup);
    EXPECT_FALSE(probe_rtt_restart.probe_rtt_done_stamp_.has_value());

    BbrCongestionController spurious(/*max_datagram_size=*/1200);
    spurious.mode_ = BbrCongestionController::Mode::probe_bw_down;
    spurious.undo_state_ = BbrCongestionController::Mode::startup;
    spurious.recovery_start_time_ = coquic::quic::test::test_time(1);
    spurious.prior_congestion_window_ = 9600u;
    spurious.congestion_window_ = 4800u;
    spurious.bw_shortterm_ = 10.0;
    spurious.undo_bw_shortterm_ = 20.0;
    spurious.inflight_shortterm_ = 1000u;
    spurious.undo_inflight_shortterm_ = 2000u;
    spurious.inflight_longterm_ = 3000u;
    spurious.undo_inflight_longterm_ = 4000u;

    SentPacketRecord late_acked{
        .packet_number = 7,
        .sent_time = coquic::quic::test::test_time(2),
        .ack_eliciting = false,
        .in_flight = false,
        .declared_lost = true,
        .bytes_in_flight = 0,
    };
    spurious.on_packets_acked(std::array<SentPacketRecord, 1>{late_acked},
                              /*app_limited=*/false, coquic::quic::test::test_time(3),
                              coquic::quic::RecoveryRttState{});
    EXPECT_EQ(spurious.mode_, BbrCongestionController::Mode::startup);
    EXPECT_FALSE(spurious.recovery_start_time_.has_value());
    EXPECT_EQ(spurious.congestion_window_, 9600u);
    EXPECT_EQ(spurious.inflight_longterm_, 4000u);

    BbrCongestionController recovery_exit(/*max_datagram_size=*/1200);
    recovery_exit.mode_ = BbrCongestionController::Mode::startup;
    recovery_exit.recovery_start_time_ = coquic::quic::test::test_time(5);
    recovery_exit.prior_congestion_window_ = 12000u;
    recovery_exit.congestion_window_ = 6000u;
    recovery_exit.bytes_in_flight_ = 1200u;
    recovery_exit.min_rtt_ = std::chrono::milliseconds{1};
    recovery_exit.max_bandwidth_bytes_per_second_ = 1000.0;

    auto acked_after_recovery =
        make_sent_packet(/*packet_number=*/9, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(6));
    acked_after_recovery.delivered = 0;
    acked_after_recovery.delivered_time = coquic::quic::test::test_time(5);
    acked_after_recovery.first_sent_time = coquic::quic::test::test_time(5);
    acked_after_recovery.tx_in_flight = 1200;
    recovery_exit.on_packets_acked(std::array<SentPacketRecord, 1>{acked_after_recovery},
                                   /*app_limited=*/false, coquic::quic::test::test_time(7),
                                   coquic::quic::RecoveryRttState{
                                       .latest_rtt = std::chrono::milliseconds{1},
                                       .min_rtt = std::chrono::milliseconds{1},
                                   });
    EXPECT_FALSE(recovery_exit.recovery_start_time_.has_value());
    EXPECT_EQ(recovery_exit.bytes_in_flight(), 0u);

    BbrCongestionController losses(/*max_datagram_size=*/1200);
    losses.bytes_in_flight_ = 1200u;
    losses.on_packets_lost(std::array<SentPacketRecord, 1>{
        make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/false, /*in_flight=*/false,
                         /*bytes_in_flight=*/0, coquic::quic::test::test_time(0)),
    });
    EXPECT_EQ(losses.bytes_in_flight(), 1200u);

    BbrCongestionController app_limited(/*max_datagram_size=*/1200);
    app_limited.total_delivered_ = std::numeric_limits<std::uint64_t>::max() - 1;
    app_limited.bytes_in_flight_ = 8;
    app_limited.congestion_window_ = 8;
    app_limited.mark_connection_app_limited();
    EXPECT_EQ(app_limited.app_limited_until_delivered_, std::numeric_limits<std::uint64_t>::max());

    const auto before = app_limited.app_limited_until_delivered_;
    app_limited.maybe_mark_connection_app_limited(/*no_pending_data=*/true);
    EXPECT_EQ(app_limited.app_limited_until_delivered_, before);
}

TEST(QuicCongestionTest, DiscardedPacketsOnlyReduceBbrBytesInFlight) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);
    controller.bytes_in_flight_ = 1200;
    controller.congestion_window_ = 18000;
    controller.total_delivered_ = 2400;
    controller.total_lost_ = 3600;
    controller.recovery_start_time_ = coquic::quic::test::test_time(20);

    const auto cwnd = controller.congestion_window();
    const auto total_delivered = controller.total_delivered_;
    const auto total_lost = controller.total_lost_;
    const auto recovery_start_time = controller.recovery_start_time_;
    const std::array<SentPacketRecord, 2> packets{
        make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(10)),
        make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true, /*in_flight=*/false,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(11)),
    };

    controller.on_packets_discarded(packets);

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_EQ(controller.congestion_window(), cwnd);
    EXPECT_EQ(controller.total_delivered_, total_delivered);
    EXPECT_EQ(controller.total_lost_, total_lost);
    EXPECT_EQ(controller.recovery_start_time_, recovery_start_time);

    controller.bytes_in_flight_ = 600;
    controller.on_packets_discarded(std::array<SentPacketRecord, 1>{
        make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(12)),
    });
    EXPECT_EQ(controller.bytes_in_flight(), 0u);

    coquic::quic::QuicCongestionController wrapper(
        coquic::quic::QuicCongestionControlAlgorithm::bbr, /*max_datagram_size=*/1200);
    wrapper.bytes_in_flight_ = 600;
    wrapper.on_packets_discarded(std::array<SentPacketRecord, 1>{
        make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(13)),
    });
    EXPECT_EQ(wrapper.bytes_in_flight(), 0u);
}

TEST(QuicCongestionTest, BbrModelAndBudgetColdBranches) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);

    controller.next_round_delivered_ = 2;
    controller.round_count_ = 7;
    controller.rounds_since_bw_probe_ = 9;
    controller.update_round(/*prior_delivered=*/1);
    EXPECT_FALSE(controller.round_start_);
    EXPECT_EQ(controller.round_count_, 7u);
    EXPECT_EQ(controller.rounds_since_bw_probe_, 9u);

    controller.max_bandwidth_bytes_per_second_ = 100.0;
    controller.update_max_bw(make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0));
    EXPECT_EQ(controller.max_bandwidth_bytes_per_second_, 100.0);

    controller.cycle_count_ = 20;
    controller.max_bandwidth_bytes_per_second_ = 123.0;
    controller.bandwidth_filter_[0] = 50.0;
    controller.bandwidth_filter_[1] = 75.0;
    controller.bandwidth_filter_cycle_[0] = 0;
    controller.bandwidth_filter_cycle_[1] = std::numeric_limits<std::uint64_t>::max();
    controller.advance_max_bw_filter();
    EXPECT_EQ(controller.max_bandwidth_bytes_per_second_, 0.0);

    controller.total_delivered_ = 7;
    controller.loss_round_delivered_ = 5;
    controller.bw_latest_ = 0.0;
    controller.inflight_latest_ = 9;
    controller.update_latest_delivery_signals(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/12.0, /*newly_acked=*/0,
                         /*lost=*/0, /*tx_in_flight=*/0, /*prior_delivered=*/5,
                         /*delivered=*/0));
    EXPECT_TRUE(controller.loss_round_start_);
    EXPECT_EQ(optional_ref_or_terminate(controller.loss_round_delivered_), 7);
    EXPECT_EQ(controller.inflight_latest_, 9u);

    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.loss_round_start_ = true;
    controller.loss_in_round_ = true;
    controller.loss_bytes_in_round_ = 1200;
    controller.loss_events_in_round_ = 2;
    controller.bw_shortterm_ = std::numeric_limits<double>::infinity();
    controller.inflight_shortterm_ = std::numeric_limits<std::size_t>::max();
    controller.max_bandwidth_bytes_per_second_ = 200.0;
    controller.bw_latest_ = 300.0;
    controller.inflight_latest_ = 4000;
    controller.congestion_window_ = 5000;
    controller.update_congestion_signals(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/250.0, /*newly_acked=*/1200,
                         /*lost=*/0, /*tx_in_flight=*/4000, /*prior_delivered=*/0,
                         /*delivered=*/1200));
    EXPECT_EQ(controller.bw_shortterm_, 300.0);
    EXPECT_EQ(controller.inflight_shortterm_, 4000u);

    controller.bandwidth_bytes_per_second_ = 0.0;
    controller.extra_acked_interval_start_ = coquic::quic::test::test_time(0);
    controller.extra_acked_delivered_ = std::numeric_limits<std::size_t>::max();
    controller.round_count_ = 20;
    controller.full_bw_reached_ = true;
    controller.extra_acked_round_[0] = 5;
    controller.extra_acked_filter_[0] = 999;
    controller.extra_acked_round_[1] = 25;
    controller.extra_acked_filter_[1] = 777;
    controller.congestion_window_ = 32000;
    controller.update_ack_aggregation(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/1,
                         /*lost=*/0, /*tx_in_flight=*/0, /*prior_delivered=*/0,
                         /*delivered=*/0),
        coquic::quic::test::test_time(1));
    EXPECT_LE(controller.extra_acked_, controller.congestion_window_);

    controller.full_bw_now_ = false;
    controller.round_start_ = true;
    controller.full_bandwidth_bytes_per_second_ = 100.0;
    controller.full_bandwidth_rounds_without_growth_ = 2;
    controller.full_bw_reached_ = false;
    controller.check_full_bw_reached(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/110.0, /*newly_acked=*/0,
                         /*lost=*/0, /*tx_in_flight=*/0, /*prior_delivered=*/0,
                         /*delivered=*/0));
    EXPECT_TRUE(controller.full_bw_now_);
    EXPECT_TRUE(controller.full_bw_reached_);

    controller.mode_ = BbrCongestionController::Mode::startup;
    controller.loss_round_start_ = true;
    controller.previous_round_had_loss_ = true;
    controller.recovery_start_time_ = coquic::quic::test::test_time(1);
    controller.round_count_ = 2;
    controller.recovery_round_start_ = 1;
    controller.inflight_latest_ = 0;
    controller.check_startup_high_loss();
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::startup);

    controller.inflight_latest_ = 2000;
    controller.previous_round_lost_bytes_ = 1;
    controller.previous_round_loss_events_ = 1;
    controller.check_startup_high_loss();
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::startup);

    controller.full_bw_reached_ = true;
    controller.mode_ = BbrCongestionController::Mode::startup;
    controller.update_probe_bw_cycle_phase(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/0,
                         /*lost=*/0, /*tx_in_flight=*/0, /*prior_delivered=*/0,
                         /*delivered=*/0),
        coquic::quic::test::test_time(5));
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::startup);

    controller.ack_phase_ = BbrCongestionController::AckPhase::probe_stopping;
    controller.round_start_ = true;
    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.inflight_longterm_ = std::numeric_limits<std::size_t>::max();
    controller.adapt_long_term_model(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/0,
                         /*lost=*/0, /*tx_in_flight=*/0, /*prior_delivered=*/0,
                         /*delivered=*/0));
    EXPECT_EQ(controller.ack_phase_, BbrCongestionController::AckPhase::refilling);

    controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
    controller.congestion_window_ = 24000;
    controller.send_quantum_ = 0;
    controller.bytes_in_flight_ = 0;
    controller.inflight_longterm_ = 12000;
    controller.adapt_long_term_model(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/0,
                         /*lost=*/1000, /*tx_in_flight=*/12000, /*prior_delivered=*/0,
                         /*delivered=*/0));
    EXPECT_EQ(controller.inflight_longterm_, 12000u);
}

TEST(QuicCongestionTest, BbrBoundsMathAndWrapperSelfAssignmentBranches) {
    BbrCongestionController controller(/*max_datagram_size=*/1200);

    controller.probe_rtt_min_delay_ = std::chrono::milliseconds{20};
    controller.probe_rtt_min_stamp_ = coquic::quic::test::test_time(0);
    controller.min_rtt_ = std::chrono::milliseconds{10};
    controller.min_rtt_stamp_ = coquic::quic::test::test_time(0);
    controller.update_min_rtt(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0, /*newly_acked=*/0,
                         /*lost=*/0, /*tx_in_flight=*/0, /*prior_delivered=*/0,
                         /*delivered=*/0, std::chrono::milliseconds{5}),
        coquic::quic::test::test_time(11001));
    EXPECT_EQ(optional_ref_or_terminate(controller.min_rtt_), std::chrono::milliseconds{5});

    controller.loss_round_start_ = true;
    controller.advance_latest_delivery_signals(
        make_rate_sample(/*delivery_rate_bytes_per_second=*/42.0, /*newly_acked=*/0,
                         /*lost=*/0, /*tx_in_flight=*/0, /*prior_delivered=*/0,
                         /*delivered=*/2400));
    EXPECT_EQ(controller.bw_latest_, 42.0);
    EXPECT_EQ(controller.inflight_latest_, 2400u);

    controller.max_bandwidth_bytes_per_second_ = 64.0;
    controller.bw_shortterm_ = std::numeric_limits<double>::infinity();
    controller.bound_bw_for_model();
    EXPECT_EQ(controller.bandwidth_bytes_per_second_, 64.0);

    controller.bandwidth_bytes_per_second_ = 0.0;
    controller.pacing_rate_bytes_per_second_ = 77.0;
    controller.set_pacing_rate_with_gain(2.0);
    EXPECT_EQ(controller.pacing_rate_bytes_per_second_, 77.0);

    controller.pacing_rate_bytes_per_second_ = std::numeric_limits<double>::infinity();
    controller.set_send_quantum();
    EXPECT_GE(controller.send_quantum(), 2u * 1200u);

    controller.min_rtt_.reset();
    controller.send_quantum_ = 2400;
    controller.cwnd_gain_ = 2.0;
    controller.extra_acked_ = 0;
    controller.update_max_inflight();
    EXPECT_EQ(controller.bdp_, 12000.0);

    controller.mode_ = BbrCongestionController::Mode::probe_rtt;
    controller.congestion_window_ = 12000;
    controller.bound_cwnd_for_probe_rtt();
    EXPECT_EQ(controller.congestion_window_, controller.probe_rtt_cwnd());

    controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
    controller.inflight_longterm_ = 5000;
    controller.inflight_shortterm_ = 9000;
    controller.congestion_window_ = 12000;
    controller.bound_cwnd_for_model();
    EXPECT_EQ(controller.congestion_window_, 5000u);

    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.inflight_longterm_ = 6000;
    controller.inflight_shortterm_ = std::numeric_limits<std::size_t>::max();
    controller.congestion_window_ = 12000;
    controller.bound_cwnd_for_model();
    EXPECT_EQ(controller.congestion_window_, controller.inflight_with_headroom());

    controller.mode_ = BbrCongestionController::Mode::probe_rtt;
    controller.full_bw_reached_ = true;
    controller.congestion_window_ = 5000;
    controller.max_inflight_ = 8000;
    controller.min_rtt_ = std::chrono::milliseconds{1};
    controller.bandwidth_bytes_per_second_ = 120000.0;
    controller.send_quantum_ = 2400;
    controller.set_cwnd(make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                         /*newly_acked=*/1200, /*lost=*/0,
                                         /*tx_in_flight=*/0, /*prior_delivered=*/0,
                                         /*delivered=*/0));
    EXPECT_GE(controller.congestion_window_, controller.minimum_window());

    controller.loss_in_round_ = true;
    controller.loss_events_in_round_ = 1;
    controller.last_lost_packet_number_ = 10;
    controller.note_loss(make_sent_packet(/*packet_number=*/11, /*ack_eliciting=*/true,
                                          /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                          coquic::quic::test::test_time(0)));
    EXPECT_EQ(controller.loss_events_in_round_, 1u);

    controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    controller.inflight_longterm_ = 7777;
    controller.handle_inflight_too_high(make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                                         /*newly_acked=*/0, /*lost=*/10,
                                                         /*tx_in_flight=*/9999,
                                                         /*prior_delivered=*/0,
                                                         /*delivered=*/0, std::nullopt,
                                                         /*is_app_limited=*/true));
    EXPECT_EQ(controller.inflight_longterm_, 7777u);
    EXPECT_FALSE(controller.pending_probe_bw_down_);

    controller.prior_congestion_window_.reset();
    controller.mode_ = BbrCongestionController::Mode::startup;
    controller.recovery_start_time_.reset();
    controller.congestion_window_ = 9000;
    controller.save_cwnd();
    EXPECT_EQ(optional_ref_or_terminate(controller.prior_congestion_window_), 9000u);

    controller.mode_ = BbrCongestionController::Mode::probe_rtt;
    controller.undo_state_ = BbrCongestionController::Mode::startup;
    controller.handle_spurious_loss_detection(coquic::quic::test::test_time(5));
    EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_rtt);

    controller.cycle_stamp_.reset();
    EXPECT_FALSE(controller.has_elapsed_in_phase(std::chrono::milliseconds{1},
                                                 coquic::quic::test::test_time(10)));
    EXPECT_EQ(controller.packets_for_bytes(0), 0u);

    controller.min_rtt_.reset();
    EXPECT_EQ(controller.bdp_bytes(1.0), controller.initial_cwnd_);

    controller.inflight_longterm_ = 1200;
    EXPECT_EQ(controller.inflight_with_headroom(), controller.minimum_window());

    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(10);
    controller.pacing_budget_bytes_ = 100;
    controller.send_quantum_ = 1200;
    controller.pacing_rate_bytes_per_second_ = 0.0;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(11)),
              controller.pacing_budget_cap());

    controller.pacing_rate_bytes_per_second_ = 1000.0;
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(10)), 100u);

    controller.pacing_budget_bytes_ = 100;
    controller.pacing_budget_timestamp_ = coquic::quic::test::test_time(10);
    EXPECT_EQ(controller.pacing_budget_at(coquic::quic::test::test_time(2000)),
              controller.pacing_budget_cap());

    coquic::quic::QuicCongestionController wrapper(
        coquic::quic::QuicCongestionControlAlgorithm::newreno, /*max_datagram_size=*/1200);
    wrapper = wrapper;
    EXPECT_EQ(wrapper.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::newreno);
    wrapper = std::move(wrapper);
    EXPECT_EQ(wrapper.algorithm(), coquic::quic::QuicCongestionControlAlgorithm::newreno);

    auto metric = coquic::quic::QuicCongestionController::TestMetricHandle(&wrapper, true);
    metric = metric;
    EXPECT_EQ(static_cast<std::size_t>(metric), wrapper.congestion_window());
    auto &metric_alias = metric;
    metric_alias = std::move(metric_alias);
    EXPECT_EQ(static_cast<std::size_t>(metric_alias), wrapper.congestion_window());

    coquic::quic::QuicCongestionController::TestMetricHandle null_metric;
    null_metric = 7;
    EXPECT_EQ(static_cast<std::size_t>(null_metric), 0u);
}

TEST(QuicCongestionTest, BbrAdditionalInternalCoverageBranches) {
    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        EXPECT_FALSE(controller.next_send_time(/*bytes=*/0).has_value());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.bytes_in_flight_ = 100;
        auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                       /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(10));
        packet.delivered = 0;
        packet.delivered_time = coquic::quic::test::test_time(10);
        packet.first_sent_time = coquic::quic::test::test_time(10);
        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(10), coquic::quic::RecoveryRttState{});
        EXPECT_EQ(rs.delivery_rate_bytes_per_second, 0.0);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.total_delivered_ = 10;
        controller.min_rtt_ = std::chrono::milliseconds{1};
        auto packet = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                       /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(20));
        packet.delivered = 0;
        packet.delivered_time = coquic::quic::test::test_time(20);
        packet.first_sent_time = coquic::quic::test::test_time(20);
        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(20), coquic::quic::RecoveryRttState{});
        EXPECT_EQ(rs.delivery_rate_bytes_per_second, 0.0);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.total_delivered_ = 10;
        auto packet = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                       /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(30));
        packet.delivered = 0;
        packet.delivered_time = coquic::quic::test::test_time(30);
        packet.first_sent_time = coquic::quic::test::test_time(30);
        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(30), coquic::quic::RecoveryRttState{});
        EXPECT_EQ(rs.delivery_rate_bytes_per_second, 0.0);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        auto packet = make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/false,
                                       /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(40));
        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(41),
            coquic::quic::RecoveryRttState{.min_rtt = std::chrono::milliseconds{7}});
        EXPECT_FALSE(rs.has_newly_acked);
        EXPECT_EQ(controller.first_sent_time_, std::optional{coquic::quic::test::test_time(41)});
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.bytes_in_flight_ = 1000;
        auto packet = make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(50));
        packet.delivered = 3;
        packet.delivered_time = coquic::quic::test::test_time(49);
        packet.first_sent_time = coquic::quic::test::test_time(48);
        packet.tx_in_flight = 2200;
        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(60),
            coquic::quic::RecoveryRttState{.min_rtt = std::chrono::milliseconds{12}});
        EXPECT_EQ(controller.bytes_in_flight_, 0u);
        EXPECT_EQ(rs.rtt, std::optional{std::chrono::milliseconds{12}});
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.app_limited_until_delivered_ = 5;
        controller.bytes_in_flight_ = 1200;
        auto packet = make_sent_packet(/*packet_number=*/6, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(70));
        packet.delivered = 0;
        packet.delivered_time = coquic::quic::test::test_time(69);
        packet.first_sent_time = coquic::quic::test::test_time(68);
        packet.tx_in_flight = 1200;
        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(80), coquic::quic::RecoveryRttState{});
        EXPECT_EQ(controller.app_limited_until_delivered_, 0u);
        EXPECT_FALSE(rs.is_app_limited);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::probe_rtt;
        auto packet = make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                       /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(90));
        packet.delivered_time = coquic::quic::test::test_time(89);
        packet.first_sent_time = coquic::quic::test::test_time(88);
        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(100), coquic::quic::RecoveryRttState{});
        EXPECT_TRUE(rs.is_app_limited);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.bandwidth_bytes_per_second_ = std::numeric_limits<double>::infinity();
        controller.min_rtt_ = std::chrono::hours{24};
        EXPECT_EQ(controller.bdp_bytes(1.0), std::numeric_limits<std::size_t>::max());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.bandwidth_filter_cycle_.fill(std::numeric_limits<std::uint64_t>::max());
        controller.cycle_count_ = 0;
        controller.advance_max_bw_filter();
        EXPECT_EQ(controller.max_bandwidth_bytes_per_second_, 0.0);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::startup;
        controller.full_bw_reached_ = true;
        controller.check_startup_done();
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::drain);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::startup;
        controller.loss_round_start_ = true;
        controller.previous_round_had_loss_ = true;
        controller.recovery_start_time_ = coquic::quic::test::test_time(1);
        controller.round_count_ = 2;
        controller.recovery_round_start_ = 1;
        controller.inflight_latest_ = 0;
        controller.congestion_window_ = 0;
        controller.bandwidth_bytes_per_second_ = 0.0;
        controller.check_startup_high_loss();
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::startup);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::drain;
        controller.bytes_in_flight_ = 0;
        controller.min_rtt_ = std::chrono::milliseconds{1};
        controller.bandwidth_bytes_per_second_ = 1.0;
        controller.check_drain_done(coquic::quic::test::test_time(5));
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_down);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.full_bw_reached_ = true;
        controller.mode_ = BbrCongestionController::Mode::probe_bw_down;
        controller.cycle_stamp_ = coquic::quic::test::test_time(0);
        controller.bw_probe_wait_ = std::chrono::milliseconds{0};
        controller.rounds_since_bw_probe_ = 0;
        controller.update_probe_bw_cycle_phase(make_rate_sample(),
                                               coquic::quic::test::test_time(1));
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_refill);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.inflight_longterm_ = 10000;
        controller.bytes_in_flight_ = 9000;
        EXPECT_FALSE(controller.is_time_to_cruise());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
        controller.congestion_window_ = 4800;
        controller.inflight_longterm_ = 3600;
        controller.bytes_in_flight_ = 3600;
        controller.send_quantum_ = 1200;
        controller.full_bw_now_ = false;
        EXPECT_FALSE(controller.is_time_to_go_down(
            make_rate_sample(/*delivery_rate_bytes_per_second=*/42.0)));
        EXPECT_EQ(controller.full_bandwidth_bytes_per_second_, 42.0);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
        controller.full_bw_now_ = true;
        EXPECT_TRUE(controller.is_time_to_go_down(make_rate_sample()));
    }
}

TEST(QuicCongestionTest, BbrAdditionalResidualCoverageBranches) {
    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.congestion_window_ = 1200;
        controller.prior_congestion_window_ = 2400;
        controller.recovery_start_time_ = coquic::quic::test::test_time(5);

        auto declared_lost = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/false,
                                              /*in_flight=*/false, /*bytes_in_flight=*/0,
                                              coquic::quic::test::test_time(6));
        declared_lost.declared_lost = true;

        controller.on_packets_acked(std::array<SentPacketRecord, 1>{declared_lost},
                                    /*app_limited=*/false, coquic::quic::test::test_time(7),
                                    coquic::quic::RecoveryRttState{});
        EXPECT_EQ(controller.congestion_window_, 2400u);
        EXPECT_FALSE(controller.recovery_start_time_.has_value());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.idle_restart_ = true;
        controller.total_delivered_ = 5;
        controller.bytes_in_flight_ = 1200;

        auto packet = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(10));
        packet.delivered = 5;
        packet.delivered_time = coquic::quic::test::test_time(9);
        packet.first_sent_time = coquic::quic::test::test_time(8);
        packet.tx_in_flight = 1200;

        controller.on_packets_acked(std::array<SentPacketRecord, 1>{packet},
                                    /*app_limited=*/false, coquic::quic::test::test_time(11),
                                    coquic::quic::RecoveryRttState{});
        EXPECT_FALSE(controller.idle_restart_);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.bw_probe_samples_ = true;
        auto packet = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                       /*in_flight=*/false, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(12));
        packet.tx_in_flight = 1200;
        packet.lost = 5000;
        controller.on_packets_lost(std::array<SentPacketRecord, 1>{packet});
        EXPECT_EQ(controller.loss_events_in_round_, 1u);
        EXPECT_TRUE(controller.bw_probe_samples_);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.recovery_start_time_ = coquic::quic::test::test_time(5);
        controller.pending_probe_bw_down_ = false;
        controller.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
        controller.on_loss_event(coquic::quic::test::test_time(9),
                                 coquic::quic::test::test_time(4));
        EXPECT_EQ(controller.recovery_start_time_, std::optional{coquic::quic::test::test_time(5)});
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::probe_rtt;
        controller.app_limited_until_delivered_ = 1;
        controller.probe_rtt_done_stamp_ = coquic::quic::test::test_time(0);
        controller.handle_restart_from_idle(coquic::quic::test::test_time(1));
        EXPECT_TRUE(controller.idle_restart_);
        EXPECT_TRUE(controller.probe_rtt_min_stamp_.has_value());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.bytes_in_flight_ = 1;
        auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/false,
                                       /*in_flight=*/false, /*bytes_in_flight=*/0,
                                       coquic::quic::test::test_time(20));
        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 1>{packet}, /*app_limited=*/false,
            coquic::quic::test::test_time(21), coquic::quic::RecoveryRttState{});
        EXPECT_FALSE(rs.has_newly_acked);
        EXPECT_FALSE(controller.first_sent_time_.has_value());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.cycle_count_ = 3;
        controller.bandwidth_filter_cycle_[0] = 5;
        controller.bandwidth_filter_[0] = 99.0;
        controller.update_max_bw(make_rate_sample(/*delivery_rate_bytes_per_second=*/10.0,
                                                  /*newly_acked=*/0,
                                                  /*lost=*/0,
                                                  /*tx_in_flight=*/0,
                                                  /*prior_delivered=*/0,
                                                  /*delivered=*/0, std::nullopt,
                                                  /*is_app_limited=*/false));
        EXPECT_EQ(controller.max_bandwidth_bytes_per_second_, 10.0);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::drain;
        controller.loss_round_start_ = true;
        controller.loss_in_round_ = true;
        controller.bw_shortterm_ = std::numeric_limits<double>::infinity();
        controller.inflight_shortterm_ = std::numeric_limits<std::size_t>::max();
        controller.max_bandwidth_bytes_per_second_ = 10.0;
        controller.bw_latest_ = 8.0;
        controller.inflight_latest_ = 4000;
        controller.congestion_window_ = 6000;
        controller.update_congestion_signals(make_rate_sample());
        EXPECT_EQ(controller.bw_shortterm_, 8.0);
        EXPECT_EQ(controller.inflight_shortterm_, 4200u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.round_count_ = 5;
        controller.extra_acked_round_[5 % controller.extra_acked_round_.size()] = 4;
        controller.full_bw_reached_ = true;
        controller.bandwidth_bytes_per_second_ = 1.0;
        controller.congestion_window_ = 1200;
        controller.update_ack_aggregation(make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                                           /*newly_acked=*/1200),
                                          coquic::quic::test::test_time(1));
        EXPECT_GT(controller.extra_acked_, 0u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.round_start_ = true;
        controller.full_bandwidth_rounds_without_growth_ = std::numeric_limits<std::uint8_t>::max();
        controller.full_bandwidth_bytes_per_second_ = 100.0;
        controller.check_full_bw_reached(make_rate_sample(/*delivery_rate_bytes_per_second=*/50.0));
        EXPECT_TRUE(controller.full_bw_now_);
        EXPECT_TRUE(controller.full_bw_reached_);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.round_start_ = true;
        controller.full_bandwidth_rounds_without_growth_ = static_cast<std::uint8_t>(3 - 1);
        controller.full_bandwidth_bytes_per_second_ = 100.0;
        controller.check_full_bw_reached(make_rate_sample(/*delivery_rate_bytes_per_second=*/50.0));
        EXPECT_TRUE(controller.full_bw_now_);
        EXPECT_TRUE(controller.full_bw_reached_);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.full_bw_reached_ = true;
        controller.mode_ = BbrCongestionController::Mode::probe_bw_down;
        controller.cycle_stamp_ = coquic::quic::test::test_time(0);
        controller.bw_probe_wait_ = std::chrono::hours(1);
        controller.inflight_longterm_ = 6000;
        controller.bytes_in_flight_ = controller.inflight_with_headroom() + 1;
        controller.update_probe_bw_cycle_phase(make_rate_sample(),
                                               coquic::quic::test::test_time(1));
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_down);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.full_bw_reached_ = true;
        controller.mode_ = BbrCongestionController::Mode::probe_bw_refill;
        controller.round_start_ = false;
        controller.update_probe_bw_cycle_phase(make_rate_sample(),
                                               coquic::quic::test::test_time(1));
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_refill);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.full_bw_reached_ = true;
        controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
        controller.full_bw_now_ = false;
        controller.congestion_window_ = 4800;
        controller.inflight_longterm_ = 6000;
        controller.bytes_in_flight_ = 0;
        controller.send_quantum_ = 0;
        controller.update_probe_bw_cycle_phase(
            make_rate_sample(/*delivery_rate_bytes_per_second=*/5.0),
            coquic::quic::test::test_time(1));
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::probe_bw_up);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.bw_probe_up_rounds_ = 30;
        controller.congestion_window_ = 12000;
        controller.raise_inflight_longterm_slope();
        EXPECT_EQ(controller.bw_probe_up_rounds_, 30u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.congestion_window_ = 12000;
        controller.inflight_longterm_ = 6000;
        controller.bytes_in_flight_ = 12000;
        controller.send_quantum_ = 0;
        controller.probe_up_cnt_ = 10;
        controller.round_start_ = false;
        controller.probe_inflight_longterm_upward(
            make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                             /*newly_acked=*/1200));
        EXPECT_EQ(controller.bw_probe_up_acks_, 1u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.probe_rtt_expired_ = false;
        controller.update_min_rtt(make_rate_sample(), coquic::quic::test::test_time(1));
        EXPECT_FALSE(controller.probe_rtt_min_delay_.has_value());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::probe_rtt;
        controller.probe_rtt_done_stamp_ = coquic::quic::test::test_time(2);
        controller.round_start_ = false;
        controller.handle_probe_rtt(coquic::quic::test::test_time(1));
        EXPECT_FALSE(controller.probe_rtt_round_done_);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.probe_rtt_done_stamp_ = coquic::quic::test::test_time(2);
        controller.check_probe_rtt_done(coquic::quic::test::test_time(2));
        EXPECT_EQ(controller.probe_rtt_done_stamp_,
                  std::optional{coquic::quic::test::test_time(2)});
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.bandwidth_bytes_per_second_ = 10.0;
        controller.bw_shortterm_ = 5.0;
        controller.max_bandwidth_bytes_per_second_ = 10.0;
        controller.bound_bw_for_model();
        EXPECT_EQ(controller.bandwidth_bytes_per_second_, 5.0);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.full_bw_reached_ = false;
        controller.max_inflight_ = 1200;
        controller.congestion_window_ = 1200;
        controller.total_delivered_ = controller.initial_cwnd_;
        controller.set_cwnd(make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                             /*newly_acked=*/1200));
        EXPECT_EQ(controller.congestion_window_, 4800u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::drain;
        controller.undo_state_ = BbrCongestionController::Mode::startup;
        controller.handle_spurious_loss_detection(coquic::quic::test::test_time(1));
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::startup);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.congestion_window_ = 4800;
        controller.inflight_longterm_ = 6000;
        controller.bytes_in_flight_ = 0;
        controller.send_quantum_ = 0;
        controller.full_bw_now_ = false;
        EXPECT_FALSE(controller.is_time_to_go_down(
            make_rate_sample(/*delivery_rate_bytes_per_second=*/7.0)));
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        const auto inflight = controller.inflight_at_loss(
            make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                             /*newly_acked=*/0,
                             /*lost=*/1200,
                             /*tx_in_flight=*/1200),
            make_sent_packet(/*packet_number=*/9, /*ack_eliciting=*/true, /*in_flight=*/true,
                             /*bytes_in_flight=*/1200, coquic::quic::test::test_time(1)));
        EXPECT_EQ(inflight, controller.minimum_window());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.recovery_start_time_ = coquic::quic::test::test_time(5);

        auto packet = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/false,
                                       /*in_flight=*/false, /*bytes_in_flight=*/0,
                                       coquic::quic::test::test_time(4));

        controller.on_packets_acked(std::array<SentPacketRecord, 1>{packet},
                                    /*app_limited=*/false, coquic::quic::test::test_time(6),
                                    coquic::quic::RecoveryRttState{});
        EXPECT_EQ(controller.recovery_start_time_, std::optional{coquic::quic::test::test_time(5)});
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.recovery_start_time_ = coquic::quic::test::test_time(5);
        controller.on_loss_event(coquic::quic::test::test_time(9),
                                 coquic::quic::test::test_time(6));
        EXPECT_EQ(controller.recovery_start_time_, std::optional{coquic::quic::test::test_time(9)});
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.total_delivered_ = 2400;
        controller.bytes_in_flight_ = 2400;

        auto newest = make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                       /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                       coquic::quic::test::test_time(10));
        newest.delivered = 1200;
        newest.delivered_time = coquic::quic::test::test_time(9);
        newest.first_sent_time = coquic::quic::test::test_time(8);
        newest.tx_in_flight = 1200;

        auto older = make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                      /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                      coquic::quic::test::test_time(10));
        older.delivered = 0;
        older.delivered_time = coquic::quic::test::test_time(7);
        older.first_sent_time = coquic::quic::test::test_time(6);
        older.tx_in_flight = 1200;

        const auto rs = controller.generate_rate_sample(
            std::array<SentPacketRecord, 2>{newest, older},
            /*app_limited=*/false, coquic::quic::test::test_time(11),
            coquic::quic::RecoveryRttState{});
        EXPECT_EQ(rs.prior_delivered, newest.delivered);
        EXPECT_EQ(rs.delivered, 3600u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::drain;
        controller.loss_round_start_ = true;
        controller.loss_in_round_ = true;
        controller.bw_shortterm_ = 7.0;
        controller.inflight_shortterm_ = 5000;
        controller.max_bandwidth_bytes_per_second_ = 10.0;
        controller.bw_latest_ = 8.0;
        controller.inflight_latest_ = 2000;
        controller.update_congestion_signals(make_rate_sample());
        EXPECT_EQ(controller.bw_shortterm_, 8.0);
        EXPECT_EQ(controller.inflight_shortterm_, 3500u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::probe_bw_up;
        controller.loss_round_start_ = true;
        controller.loss_in_round_ = true;
        controller.bw_shortterm_ = 7.0;
        controller.inflight_shortterm_ = 5000;
        controller.max_bandwidth_bytes_per_second_ = 10.0;
        controller.bw_latest_ = 8.0;
        controller.inflight_latest_ = 2000;
        controller.update_congestion_signals(make_rate_sample());
        EXPECT_EQ(controller.bw_shortterm_, 7.0);
        EXPECT_EQ(controller.inflight_shortterm_, 5000u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.round_count_ = 5;
        const auto slot = controller.round_count_ % controller.extra_acked_round_.size();
        controller.extra_acked_round_[slot] = controller.round_count_;
        controller.extra_acked_filter_[slot] = 321;
        controller.full_bw_reached_ = true;
        controller.bandwidth_bytes_per_second_ = 1.0;
        controller.congestion_window_ = 1200;
        controller.update_ack_aggregation(make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                                           /*newly_acked=*/1200),
                                          coquic::quic::test::test_time(1));
        EXPECT_GE(controller.extra_acked_filter_[slot], 321u);
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::drain;
        controller.full_bw_reached_ = false;
        controller.min_rtt_ = std::chrono::milliseconds{1};
        controller.bandwidth_bytes_per_second_ = 0.0;
        controller.send_quantum_ = 0;
        controller.congestion_window_ = controller.minimum_window();
        controller.total_delivered_ = controller.initial_cwnd_;
        controller.set_cwnd(make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                             /*newly_acked=*/1200));
        EXPECT_EQ(controller.congestion_window_, controller.minimum_window());
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.note_loss(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                              /*in_flight=*/true, /*bytes_in_flight=*/1200,
                                              coquic::quic::test::test_time(1)));
        EXPECT_EQ(controller.loss_events_in_round_, 1u);
        EXPECT_EQ(controller.last_lost_packet_number_, std::optional<std::uint64_t>{0});
    }

    {
        BbrCongestionController controller(/*max_datagram_size=*/1200);
        controller.mode_ = BbrCongestionController::Mode::drain;
        controller.undo_state_ = BbrCongestionController::Mode::probe_bw_cruise;
        controller.handle_spurious_loss_detection(coquic::quic::test::test_time(1));
        EXPECT_EQ(controller.mode_, BbrCongestionController::Mode::drain);
    }
}

} // namespace
