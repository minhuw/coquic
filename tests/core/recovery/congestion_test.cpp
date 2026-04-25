#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <limits>
#include <utility>

#include <gtest/gtest.h>

#define private public
#include "src/quic/congestion.h"
#undef private
#include "tests/support/quic_test_utils.h"

namespace {

using coquic::quic::BbrCongestionController;
using coquic::quic::NewRenoCongestionController;
using coquic::quic::SentPacketRecord;

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

TEST(QuicCongestionTest, UsesRfcInitialWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    EXPECT_EQ(controller.congestion_window(), 12000u);
}

TEST(QuicCongestionTest, ParsesCongestionControlAlgorithms) {
    const auto newreno = coquic::quic::parse_congestion_control_algorithm("newreno");
    ASSERT_TRUE(newreno.has_value());
    EXPECT_EQ(optional_ref_or_terminate(newreno),
              coquic::quic::QuicCongestionControlAlgorithm::newreno);
    EXPECT_EQ(coquic::quic::congestion_control_algorithm_name(optional_ref_or_terminate(newreno)),
              "newreno");

    const auto bbr = coquic::quic::parse_congestion_control_algorithm("bbr");
    ASSERT_TRUE(bbr.has_value());
    EXPECT_EQ(optional_ref_or_terminate(bbr), coquic::quic::QuicCongestionControlAlgorithm::bbr);
    EXPECT_EQ(coquic::quic::congestion_control_algorithm_name(optional_ref_or_terminate(bbr)),
              "bbr");

    EXPECT_FALSE(coquic::quic::parse_congestion_control_algorithm("cubic").has_value());
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

    const auto loss_rs = make_rate_sample(/*delivery_rate_bytes_per_second=*/0.0,
                                          /*newly_acked=*/0, /*lost=*/300,
                                          /*tx_in_flight=*/10000, /*prior_delivered=*/0,
                                          /*delivered=*/0);
    EXPECT_TRUE(controller.is_inflight_too_high(loss_rs));
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

    auto &bbr = std::get<BbrCongestionController>(wrapper.storage_);
    bbr.mode_ = BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};

    auto wrapper_packet =
        make_sent_packet(/*packet_number=*/9, /*ack_eliciting=*/true, /*in_flight=*/true,
                         /*bytes_in_flight=*/1200, coquic::quic::test::test_time(0));
    wrapper.on_packet_sent(wrapper_packet);
    ASSERT_TRUE(wrapper.can_send_ack_eliciting(1200));
    ASSERT_TRUE(wrapper.next_send_time(2400).has_value());

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

TEST(QuicCongestionTest, AppLimitedAckSaturatesBytesInFlightWithoutGrowingWindow) {
    NewRenoCongestionController controller(/*max_datagram_size=*/1200);
    controller.on_packet_sent(/*bytes_sent=*/1200, /*ack_eliciting=*/true);

    controller.on_packets_acked(
        std::array<SentPacketRecord, 2>{
            make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true, /*in_flight=*/false,
                             /*bytes_in_flight=*/0, coquic::quic::test::test_time(0)),
            make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true, /*in_flight=*/true,
                             /*bytes_in_flight=*/2400, coquic::quic::test::test_time(1)),
        },
        /*app_limited=*/true);

    EXPECT_EQ(controller.bytes_in_flight(), 0u);
    EXPECT_EQ(controller.congestion_window(), 12000u);
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
    EXPECT_EQ(ascending.congestion_window(), 8400u);
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

    controller.on_packet_sent(/*bytes_sent=*/first_reduction, /*ack_eliciting=*/true);
    controller.on_loss_event(coquic::quic::test::test_time(6), coquic::quic::test::test_time(6));

    EXPECT_LT(controller.congestion_window(), first_reduction);
    EXPECT_EQ(controller.congestion_window(), 3000u);
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

TEST(QuicCongestionTest, BbrAckLossAndIdleColdBranches) {
    BbrCongestionController pacing(/*max_datagram_size=*/1200);
    pacing.pacing_budget_timestamp_ = coquic::quic::test::test_time(0);
    pacing.pacing_budget_bytes_ = 0;
    pacing.send_quantum_ = 1200;
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
    EXPECT_EQ(controller.ack_phase_, BbrCongestionController::AckPhase::probe_stopping);

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
