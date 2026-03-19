#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>

#include "src/quic/recovery.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::AckFrame;
using coquic::quic::PacketSpaceRecovery;
using coquic::quic::ReceivedPacketHistory;
using coquic::quic::RecoveryRttState;
using coquic::quic::SentPacketRecord;

SentPacketRecord make_sent_packet(std::uint64_t packet_number, bool ack_eliciting,
                                  coquic::quic::QuicCoreTimePoint sent_time) {
    return SentPacketRecord{
        .packet_number = packet_number,
        .sent_time = sent_time,
        .ack_eliciting = ack_eliciting,
        .in_flight = ack_eliciting,
    };
}

AckFrame make_ack_frame(std::uint64_t largest, std::uint64_t first_ack_range = 0) {
    return AckFrame{
        .largest_acknowledged = largest,
        .first_ack_range = first_ack_range,
    };
}

TEST(QuicRecoveryTest, AckHistoryBuildsSingleContiguousAckRange) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(5));
    history.record_received(1, true, coquic::quic::test::test_time(6));

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(7));
    ASSERT_TRUE(ack.has_value());
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }
    const auto &ack_frame = *ack;
    EXPECT_EQ(ack_frame.largest_acknowledged, 1u);
    EXPECT_EQ(ack_frame.first_ack_range, 1u);
}

TEST(QuicRecoveryTest, AckHistoryMeasuresAckDelayFromLargestAcknowledgedPacket) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(5));
    history.record_received(/*packet_number=*/2, /*ack_eliciting=*/false,
                            coquic::quic::test::test_time(20));

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(28));
    ASSERT_TRUE(ack.has_value());
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }

    const auto &ack_frame = *ack;
    EXPECT_EQ(ack_frame.largest_acknowledged, 2u);
    EXPECT_EQ(ack_frame.ack_delay, 1000u);
}

TEST(QuicRecoveryTest, PacketThresholdLossMarksOlderPacketLost) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(3, true, coquic::quic::test::test_time(1)));

    const auto loss =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(10));
    EXPECT_TRUE(loss.lost_packet_numbers.contains(0));
}

TEST(QuicRecoveryTest, PtoDeadlineUsesInitialRttBeforeSamples) {
    RecoveryRttState rtt;
    const auto deadline = coquic::quic::compute_pto_deadline(rtt, /*max_ack_delay_ms=*/25,
                                                             coquic::quic::test::test_time(0));
    EXPECT_EQ(deadline, coquic::quic::test::test_time(999));
}

TEST(QuicRecoveryTest, FirstRttSampleResetsEstimator) {
    RecoveryRttState rtt;
    const auto sent = make_sent_packet(/*packet_number=*/8, /*ack_eliciting=*/true,
                                       coquic::quic::test::test_time(10));

    coquic::quic::update_rtt(rtt, coquic::quic::test::test_time(70), sent,
                             /*ack_delay=*/std::chrono::milliseconds(0),
                             /*max_ack_delay=*/std::chrono::milliseconds(25));

    ASSERT_TRUE(rtt.latest_rtt.has_value());
    ASSERT_TRUE(rtt.min_rtt.has_value());
    if (!rtt.latest_rtt.has_value()) {
        GTEST_FAIL() << "expected latest RTT sample";
        return;
    }
    if (!rtt.min_rtt.has_value()) {
        GTEST_FAIL() << "expected min RTT sample";
        return;
    }
    EXPECT_EQ(*rtt.latest_rtt, std::chrono::milliseconds(60));
    EXPECT_EQ(*rtt.min_rtt, std::chrono::milliseconds(60));
    EXPECT_EQ(rtt.smoothed_rtt, std::chrono::milliseconds(60));
    EXPECT_EQ(rtt.rttvar, std::chrono::milliseconds(30));
}

TEST(QuicRecoveryTest, TimeThresholdLossUsesRttWindow) {
    RecoveryRttState rtt;
    rtt.latest_rtt = std::chrono::milliseconds(10);
    rtt.min_rtt = std::chrono::milliseconds(10);
    rtt.smoothed_rtt = std::chrono::milliseconds(10);
    rtt.rttvar = std::chrono::milliseconds(5);

    EXPECT_FALSE(coquic::quic::is_time_threshold_lost(rtt, coquic::quic::test::test_time(0),
                                                      coquic::quic::test::test_time(11)));
    EXPECT_TRUE(coquic::quic::is_time_threshold_lost(rtt, coquic::quic::test::test_time(0),
                                                     coquic::quic::test::test_time(12)));
}

} // namespace
