#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/recovery.h"
#include "tests/quic_test_utils.h"

namespace coquic::quic::test {

struct ReceivedPacketHistoryTestPeer {
    static std::size_t range_count(const ReceivedPacketHistory &history) {
        return history.ranges_.size();
    }
};

} // namespace coquic::quic::test

namespace {

using coquic::quic::AckFrame;
using coquic::quic::AckRange;
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

coquic::quic::QuicEcnCodepoint invalid_ecn_codepoint() {
    constexpr std::uint8_t raw = 0xff;
    coquic::quic::QuicEcnCodepoint value{};
    std::memcpy(&value, &raw, sizeof(value));
    return value;
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

TEST(QuicRecoveryTest, AckHistoryCoalescesContiguousPacketsIntoSingleRange) {
    ReceivedPacketHistory history;
    for (std::uint64_t packet_number = 0; packet_number < 4096; ++packet_number) {
        history.record_received(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }

    EXPECT_EQ(coquic::quic::test::ReceivedPacketHistoryTestPeer::range_count(history), 1u);
}

TEST(QuicRecoveryTest, AckHistoryMergesBridgedRanges) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.record_received(/*packet_number=*/2, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    ASSERT_EQ(coquic::quic::test::ReceivedPacketHistoryTestPeer::range_count(history), 2u);

    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(3));

    EXPECT_EQ(coquic::quic::test::ReceivedPacketHistoryTestPeer::range_count(history), 1u);
}

TEST(QuicRecoveryTest, AckHistoryKeepsSeparatedRangesWhenPacketDoesNotExtendNextRange) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/10, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.record_received(/*packet_number=*/5, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));

    EXPECT_EQ(coquic::quic::test::ReceivedPacketHistoryTestPeer::range_count(history), 2u);
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

TEST(QuicRecoveryTest, AckHistoryClampsAckDelayWhenExponentIsTooLarge) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/2, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(20));

    const auto ack = history.build_ack_frame(std::numeric_limits<std::uint64_t>::digits,
                                             coquic::quic::test::test_time(28));
    ASSERT_TRUE(ack.has_value());
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }

    EXPECT_EQ(ack->ack_delay, 0u);
}

TEST(QuicRecoveryTest, AckHistorySkipsAckDelayWhenNowPredatesLargestPacketReceipt) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/2, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(20));

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(19));
    ASSERT_TRUE(ack.has_value());
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }
    EXPECT_EQ(ack->ack_delay, 0u);
}

TEST(QuicRecoveryTest, AckHistoryBuildsAckFrameWithZeroEcnCountsWhenMetadataIsAccessible) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/2, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(20),
                            coquic::quic::QuicEcnCodepoint::not_ect);

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(28));
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }
    const auto &ack_frame = *ack;
    if (!ack_frame.ecn_counts.has_value()) {
        GTEST_FAIL() << "expected ECN counts";
        return;
    }
    const auto &ecn_counts = *ack_frame.ecn_counts;
    EXPECT_EQ(ecn_counts.ect0, 0u);
    EXPECT_EQ(ecn_counts.ect1, 0u);
    EXPECT_EQ(ecn_counts.ecn_ce, 0u);
}

TEST(QuicRecoveryTest, AckHistoryBuildsAckFrameWithEcnCountsForMarkedPackets) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1), coquic::quic::QuicEcnCodepoint::ect0);
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2), coquic::quic::QuicEcnCodepoint::ect1);
    history.record_received(/*packet_number=*/2, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(3), coquic::quic::QuicEcnCodepoint::ce);

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(4));
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }
    const auto &ack_frame = *ack;
    if (!ack_frame.ecn_counts.has_value()) {
        GTEST_FAIL() << "expected ECN counts";
        return;
    }
    const auto &ecn_counts = *ack_frame.ecn_counts;
    EXPECT_EQ(ecn_counts.ect0, 1u);
    EXPECT_EQ(ecn_counts.ect1, 1u);
    EXPECT_EQ(ecn_counts.ecn_ce, 1u);
}

TEST(QuicRecoveryTest, DuplicatePacketsDoNotIncreaseEcnCountsTwice) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/3, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1), coquic::quic::QuicEcnCodepoint::ce);
    history.record_received(/*packet_number=*/3, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2), coquic::quic::QuicEcnCodepoint::ce);

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(3));
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }
    const auto &ack_frame = *ack;
    if (!ack_frame.ecn_counts.has_value()) {
        GTEST_FAIL() << "expected ECN counts";
        return;
    }
    const auto &ecn_counts = *ack_frame.ecn_counts;
    EXPECT_EQ(ecn_counts.ect0, 0u);
    EXPECT_EQ(ecn_counts.ect1, 0u);
    EXPECT_EQ(ecn_counts.ecn_ce, 1u);
}

TEST(QuicRecoveryTest, UnknownEcnCodepointLeavesAckEcnCountsZeroed) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/5, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1), invalid_ecn_codepoint());

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(2));
    if (!ack.has_value()) {
        GTEST_FAIL() << "expected ACK frame";
        return;
    }
    const auto &ack_frame = *ack;
    if (!ack_frame.ecn_counts.has_value()) {
        GTEST_FAIL() << "expected ECN counts";
        return;
    }
    const auto &ecn_counts = *ack_frame.ecn_counts;
    EXPECT_EQ(ecn_counts.ect0, 0u);
    EXPECT_EQ(ecn_counts.ect1, 0u);
    EXPECT_EQ(ecn_counts.ecn_ce, 0u);
}

TEST(QuicRecoveryTest, HistoryWithoutPendingAckReturnsNulloptEvenWhenPacketsExist) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/false,
                            coquic::quic::test::test_time(5));

    EXPECT_EQ(history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(6)),
              std::nullopt);
}

TEST(QuicRecoveryTest, DuplicateNonAckElicitingPacketKeepsAckPendingClear) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/false,
                            coquic::quic::test::test_time(5));
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/false,
                            coquic::quic::test::test_time(6));

    EXPECT_EQ(history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(7)),
              std::nullopt);
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
        .reset_stream_frames = {coquic::quic::ResetStreamFrame{
            .stream_id = 8,
            .application_protocol_error_code = 9,
            .final_size = 10,
        }},
        .stop_sending_frames = {coquic::quic::StopSendingFrame{
            .stream_id = 12,
            .application_protocol_error_code = 13,
        }},
        .stream_fragments = {coquic::quic::StreamFrameSendFragment{
            .stream_id = 0,
            .offset = 21,
            .bytes = {std::byte{0xcc}},
            .fin = false,
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
        .reset_stream_frames = {coquic::quic::ResetStreamFrame{
            .stream_id = 14,
            .application_protocol_error_code = 15,
            .final_size = 16,
        }},
        .stop_sending_frames = {coquic::quic::StopSendingFrame{
            .stream_id = 18,
            .application_protocol_error_code = 19,
        }},
        .stream_fragments = {coquic::quic::StreamFrameSendFragment{
            .stream_id = 4,
            .offset = 41,
            .bytes = {std::byte{0xee}, std::byte{0xff}},
            .fin = true,
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
    EXPECT_EQ(acked_packet.stream_fragments.size(), 1u);
    EXPECT_EQ(acked_packet.stream_fragments[0].stream_id, 4u);
    EXPECT_EQ(acked_packet.stream_fragments[0].offset, 41u);
    EXPECT_TRUE(acked_packet.stream_fragments[0].fin);
    ASSERT_EQ(acked_packet.reset_stream_frames.size(), 1u);
    EXPECT_EQ(acked_packet.reset_stream_frames[0].stream_id, 14u);
    EXPECT_EQ(acked_packet.reset_stream_frames[0].application_protocol_error_code, 15u);
    EXPECT_EQ(acked_packet.reset_stream_frames[0].final_size, 16u);
    ASSERT_EQ(acked_packet.stop_sending_frames.size(), 1u);
    EXPECT_EQ(acked_packet.stop_sending_frames[0].stream_id, 18u);
    EXPECT_EQ(acked_packet.stop_sending_frames[0].application_protocol_error_code, 19u);
    EXPECT_FALSE(acked_packet.has_ping);

    const auto &lost_packet = result.lost_packets.front();
    EXPECT_EQ(lost_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(lost_packet.crypto_ranges[0].offset, 11u);
    EXPECT_EQ(lost_packet.stream_fragments.size(), 1u);
    EXPECT_EQ(lost_packet.stream_fragments[0].stream_id, 0u);
    EXPECT_EQ(lost_packet.stream_fragments[0].offset, 21u);
    EXPECT_FALSE(lost_packet.stream_fragments[0].fin);
    ASSERT_EQ(lost_packet.reset_stream_frames.size(), 1u);
    EXPECT_EQ(lost_packet.reset_stream_frames[0].stream_id, 8u);
    EXPECT_EQ(lost_packet.reset_stream_frames[0].application_protocol_error_code, 9u);
    EXPECT_EQ(lost_packet.reset_stream_frames[0].final_size, 10u);
    ASSERT_EQ(lost_packet.stop_sending_frames.size(), 1u);
    EXPECT_EQ(lost_packet.stop_sending_frames[0].stream_id, 12u);
    EXPECT_EQ(lost_packet.stop_sending_frames[0].application_protocol_error_code, 13u);
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

TEST(QuicRecoveryTest, AckProcessingRejectsMalformedFirstAckRange) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    const auto result = recovery.on_ack_received(
        make_ack_frame(/*largest=*/0, /*first_ack_range=*/1), coquic::quic::test::test_time(10));

    EXPECT_TRUE(result.acked_packets.empty());
    EXPECT_TRUE(result.lost_packets.empty());
}

TEST(QuicRecoveryTest, AckProcessingRejectsMalformedAdditionalRangeGapUnderflow) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    const auto result = recovery.on_ack_received(
        AckFrame{
            .largest_acknowledged = 1,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 0,
                        .range_length = 0,
                    },
                },
        },
        coquic::quic::test::test_time(10));

    EXPECT_TRUE(result.acked_packets.empty());
    EXPECT_TRUE(result.lost_packets.empty());
}

TEST(QuicRecoveryTest, AckProcessingRejectsMalformedAdditionalRangeLengthUnderflow) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    const auto result = recovery.on_ack_received(
        AckFrame{
            .largest_acknowledged = 3,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 0,
                        .range_length = 2,
                    },
                },
        },
        coquic::quic::test::test_time(10));

    EXPECT_TRUE(result.acked_packets.empty());
    EXPECT_EQ(packet_numbers_from(result.lost_packets), (std::vector<std::uint64_t>{0}));
}

TEST(QuicRecoveryTest, AckProcessingMatchesPacketsInAdditionalAckRanges) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));

    const auto result = recovery.on_ack_received(
        AckFrame{
            .largest_acknowledged = 5,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 1,
                        .range_length = 1,
                    },
                },
        },
        coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{1, 5}));
    EXPECT_TRUE(result.lost_packets.empty());
}

TEST(QuicRecoveryTest, AckProcessingLeavesPacketsUnackedWhenAdditionalRangeStartsAboveThem) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));

    const auto result = recovery.on_ack_received(
        AckFrame{
            .largest_acknowledged = 5,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 1,
                        .range_length = 1,
                    },
                },
        },
        coquic::quic::test::test_time(2));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{5}));
}

TEST(QuicRecoveryTest,
     AckProcessingTracksLargestNewlyAcknowledgedPacketSeparatelyFromAckElicitingStatus) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/false,
                                             coquic::quic::test::test_time(10)));

    const auto result = recovery.on_ack_received(
        make_ack_frame(/*largest=*/2, /*first_ack_range=*/1), coquic::quic::test::test_time(70));

    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    if (!result.largest_newly_acked_packet.has_value()) {
        GTEST_FAIL() << "expected largest newly acknowledged packet";
        return;
    }
    EXPECT_EQ(result.largest_newly_acked_packet.value().packet_number, 2u);
    EXPECT_TRUE(result.has_newly_acked_ack_eliciting);
}

TEST(QuicRecoveryTest, AckProcessingSkipsPacketsAlreadyLostOrNotInFlight) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(SentPacketRecord{
        .packet_number = 0,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = false,
        .declared_lost = true,
    });
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    const auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(20));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{3}));
    EXPECT_TRUE(result.lost_packets.empty());
}

TEST(QuicRecoveryTest, AckProcessingSkipsDeclaredLostAndNotInFlightPacketsIndependently) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(SentPacketRecord{
        .packet_number = 0,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = true,
        .declared_lost = true,
    });
    recovery.on_packet_sent(SentPacketRecord{
        .packet_number = 1,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = false,
        .declared_lost = false,
    });
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    const auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/4), coquic::quic::test::test_time(20));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{4}));
    EXPECT_TRUE(result.lost_packets.empty());
}

TEST(QuicRecoveryTest, AckProcessingCanStillAcknowledgeDeclaredLostPackets) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(SentPacketRecord{
        .packet_number = 2,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = false,
        .declared_lost = true,
        .bytes_in_flight = 0,
    });

    const auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/2), coquic::quic::test::test_time(20));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{2}));
    EXPECT_TRUE(result.lost_packets.empty());
}

TEST(QuicRecoveryTest, PtoDeadlineUsesInitialRttBeforeSamples) {
    RecoveryRttState rtt;
    const auto deadline = coquic::quic::compute_pto_deadline(
        rtt, std::chrono::milliseconds(25), coquic::quic::test::test_time(0), /*pto_count=*/0);
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

TEST(QuicRecoveryTest, SubsequentRttSamplesCanSkipAckDelayAdjustment) {
    RecoveryRttState rtt;
    rtt.latest_rtt = std::chrono::milliseconds(40);
    rtt.smoothed_rtt = std::chrono::milliseconds(40);
    rtt.rttvar = std::chrono::milliseconds(20);
    rtt.min_rtt = std::chrono::milliseconds(30);
    const auto sent = make_sent_packet(/*packet_number=*/9, /*ack_eliciting=*/true,
                                       coquic::quic::test::test_time(10));

    coquic::quic::update_rtt(rtt, coquic::quic::test::test_time(45), sent,
                             /*ack_delay=*/std::chrono::milliseconds(20),
                             /*max_ack_delay=*/std::chrono::milliseconds(25));

    EXPECT_EQ(rtt.latest_rtt, std::optional{std::chrono::milliseconds(35)});
    EXPECT_EQ(rtt.smoothed_rtt, std::chrono::milliseconds(39));
}

TEST(QuicRecoveryTest, SubsequentRttSamplesHandleMissingMinRttDefensively) {
    RecoveryRttState rtt;
    rtt.latest_rtt = std::chrono::milliseconds(40);
    rtt.smoothed_rtt = std::chrono::milliseconds(40);
    rtt.rttvar = std::chrono::milliseconds(20);
    const auto sent = make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true,
                                       coquic::quic::test::test_time(10));

    coquic::quic::update_rtt(rtt, coquic::quic::test::test_time(60), sent,
                             /*ack_delay=*/std::chrono::milliseconds(5),
                             /*max_ack_delay=*/std::chrono::milliseconds(25));

    EXPECT_EQ(rtt.latest_rtt, std::optional{std::chrono::milliseconds(50)});
    EXPECT_EQ(rtt.smoothed_rtt, std::chrono::milliseconds(41));
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

TEST(QuicRecoveryTest, PacketThresholdLossRequiresGapOfAtLeastThreePackets) {
    EXPECT_FALSE(coquic::quic::is_packet_threshold_lost(/*packet_number=*/4, /*largest_acked=*/4));
    EXPECT_FALSE(coquic::quic::is_packet_threshold_lost(/*packet_number=*/1, /*largest_acked=*/2));
    EXPECT_TRUE(coquic::quic::is_packet_threshold_lost(/*packet_number=*/1, /*largest_acked=*/4));
}

TEST(QuicRecoveryTest, PacketThresholdLossReturnsFalseWhenLargestAckedDoesNotAdvance) {
    volatile std::uint64_t packet_number = 7;
    volatile std::uint64_t largest_acked = 7;

    EXPECT_FALSE(coquic::quic::is_packet_threshold_lost(static_cast<std::uint64_t>(packet_number),
                                                        static_cast<std::uint64_t>(largest_acked)));
}

} // namespace
