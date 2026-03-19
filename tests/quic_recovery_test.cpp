#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/recovery.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::AckFrame;
using coquic::quic::ByteRange;
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

std::vector<std::uint64_t> packet_numbers_from(const std::vector<SentPacketRecord> &packets) {
    std::vector<std::uint64_t> packet_numbers;
    packet_numbers.reserve(packets.size());
    for (const auto &packet : packets) {
        packet_numbers.push_back(packet.packet_number);
    }
    return packet_numbers;
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

TEST(QuicRecoveryTest, AckHistoryBuildsMultipleAckRanges) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    history.record_received(/*packet_number=*/4, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(3));

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(4));
    ASSERT_TRUE(ack.has_value());
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }

    const auto &ack_frame = *ack;
    ASSERT_EQ(ack_frame.additional_ranges.size(), 1u);
    EXPECT_EQ(ack_frame.largest_acknowledged, 4u);
    EXPECT_EQ(ack_frame.first_ack_range, 0u);
    EXPECT_EQ(ack_frame.additional_ranges[0].gap, 1u);
    EXPECT_EQ(ack_frame.additional_ranges[0].range_length, 1u);
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

TEST(QuicRecoveryTest, AckProcessingPreservesAckedAndLostPacketMetadata) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(SentPacketRecord{
        .packet_number = 0,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges = {ByteRange{
            .offset = 11,
            .bytes = {std::byte{0xaa}, std::byte{0xbb}},
        }},
        .stream_ranges = {ByteRange{
            .offset = 21,
            .bytes = {std::byte{0xcc}},
        }},
        .has_ping = true,
    });
    recovery.on_packet_sent(SentPacketRecord{
        .packet_number = 3,
        .sent_time = coquic::quic::test::test_time(1),
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges = {ByteRange{
            .offset = 31,
            .bytes = {std::byte{0xdd}},
        }},
        .stream_ranges = {ByteRange{
            .offset = 41,
            .bytes = {std::byte{0xee}, std::byte{0xff}},
        }},
    });

    const auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(10));

    ASSERT_EQ(result.acked_packets.size(), 1u);
    ASSERT_EQ(result.lost_packets.size(), 1u);
    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{3}));
    EXPECT_EQ(packet_numbers_from(result.lost_packets), (std::vector<std::uint64_t>{0}));

    const auto &acked_packet = result.acked_packets.front();
    EXPECT_EQ(acked_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(acked_packet.crypto_ranges[0].offset, 31u);
    EXPECT_EQ(acked_packet.stream_ranges.size(), 1u);
    EXPECT_EQ(acked_packet.stream_ranges[0].offset, 41u);
    EXPECT_FALSE(acked_packet.has_ping);

    const auto &lost_packet = result.lost_packets.front();
    EXPECT_EQ(lost_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(lost_packet.crypto_ranges[0].offset, 11u);
    EXPECT_EQ(lost_packet.stream_ranges.size(), 1u);
    EXPECT_EQ(lost_packet.stream_ranges[0].offset, 21u);
    EXPECT_TRUE(lost_packet.has_ping);
}

TEST(QuicRecoveryTest, PacketThresholdLossKeepsRunningLargestAcknowledgedState) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(3, true, coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(6, true, coquic::quic::test::test_time(2)));

    const auto first_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/6), coquic::quic::test::test_time(10));
    EXPECT_EQ(packet_numbers_from(first_ack.acked_packets), (std::vector<std::uint64_t>{6}));
    const auto first_largest_acked = recovery.largest_acked_packet_number();
    ASSERT_TRUE(first_largest_acked.has_value());
    if (!first_largest_acked.has_value()) {
        GTEST_FAIL() << "expected running largest acknowledged packet number";
        return;
    }
    EXPECT_EQ(*first_largest_acked, 6u);

    const auto stale_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/5), coquic::quic::test::test_time(11));
    EXPECT_TRUE(stale_ack.acked_packets.empty());
    EXPECT_TRUE(stale_ack.lost_packets.empty());
    const auto stale_largest_acked = recovery.largest_acked_packet_number();
    ASSERT_TRUE(stale_largest_acked.has_value());
    if (!stale_largest_acked.has_value()) {
        GTEST_FAIL() << "expected running largest acknowledged packet number";
        return;
    }
    EXPECT_EQ(*stale_largest_acked, 6u);
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
