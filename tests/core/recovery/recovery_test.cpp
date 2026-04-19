#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/frame.h"
#include "src/quic/recovery.h"
#include "tests/support/core/connection_test_fixtures.h"
#include "tests/support/quic_test_utils.h"

namespace coquic::quic::test {

struct ReceivedPacketHistoryTestPeer {
    static std::size_t range_count(const ReceivedPacketHistory &history) {
        return history.ranges_.size();
    }
};

struct PacketSpaceRecoveryTestPeer {
    static bool sent_packets_contains(const PacketSpaceRecovery &recovery,
                                      std::uint64_t packet_number) {
        return recovery.sent_packets_.contains(packet_number);
    }

    static const SentPacketRecord &sent_packets_at(const PacketSpaceRecovery &recovery,
                                                   std::uint64_t packet_number) {
        return recovery.sent_packets_.at(packet_number);
    }

    static std::size_t slot_count(const PacketSpaceRecovery &recovery) {
        return recovery.slots_.size();
    }

    static const SentPacketRecord &slot_packet_at(const PacketSpaceRecovery &recovery,
                                                  std::size_t slot_index) {
        return recovery.slots_.at(slot_index).packet;
    }
};

} // namespace coquic::quic::test

namespace {

using coquic::quic::AckFrame;
using coquic::quic::AckPacketNumberRange;
using coquic::quic::AckRange;
using coquic::quic::ByteRange;
using coquic::quic::PacketSpaceRecovery;
using coquic::quic::ReceivedPacketHistory;
using coquic::quic::RecoveryPacketHandle;
using coquic::quic::RecoveryPacketMetadata;
using coquic::quic::RecoveryRttState;
using coquic::quic::SentPacketRecord;
using coquic::quic::test_support::optional_value_or_terminate;

template <typename Handle>
concept RecoveryHandleHasPacketNumber = requires(Handle handle) { handle.packet_number; };

template <typename Handle>
concept RecoveryHandleHasSlotIndex = requires(Handle handle) { handle.slot_index; };

template <typename Handle>
concept RecoveryHandleHasSentTime = requires(Handle handle) { handle.sent_time; };

template <typename Handle>
concept RecoveryHandleHasAckEliciting = requires(Handle handle) { handle.ack_eliciting; };

template <typename Handle>
concept RecoveryHandleHasInFlight = requires(Handle handle) { handle.in_flight; };

template <typename Handle>
concept RecoveryHandleHasDeclaredLost = requires(Handle handle) { handle.declared_lost; };

static_assert(RecoveryHandleHasPacketNumber<RecoveryPacketHandle>);
static_assert(RecoveryHandleHasSlotIndex<RecoveryPacketHandle>);
static_assert(!RecoveryHandleHasSentTime<RecoveryPacketHandle>);
static_assert(!RecoveryHandleHasAckEliciting<RecoveryPacketHandle>);
static_assert(!RecoveryHandleHasInFlight<RecoveryPacketHandle>);
static_assert(!RecoveryHandleHasDeclaredLost<RecoveryPacketHandle>);

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

template <typename PacketRange>
std::vector<std::uint64_t> packet_numbers_from(const PacketRange &packets) {
    std::vector<std::uint64_t> packet_numbers;
    packet_numbers.reserve(packets.size());
    for (const auto &packet : packets) {
        packet_numbers.push_back(packet.packet_number);
    }
    return packet_numbers;
}

std::vector<std::uint64_t>
packet_numbers_from_handles(const PacketSpaceRecovery &recovery,
                            std::span<const RecoveryPacketHandle> handles) {
    std::vector<std::uint64_t> packet_numbers;
    packet_numbers.reserve(handles.size());
    for (const auto handle : handles) {
        const auto *packet = recovery.packet_for_handle(handle);
        EXPECT_NE(packet, nullptr);
        if (packet != nullptr) {
            packet_numbers.push_back(packet->packet_number);
        }
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

TEST(QuicRecoveryTest, AckHistoryBuildsOutboundAckHeaderWithoutMaterializingAckRanges) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    history.record_received(/*packet_number=*/4, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(3));

    const auto header = history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                                          coquic::quic::test::test_time(4));
    ASSERT_TRUE(header.has_value());
    if (!header.has_value()) {
        GTEST_FAIL() << "expected outbound ACK header";
        return;
    }
    EXPECT_EQ(header->largest_acknowledged, 4u);
    EXPECT_EQ(header->first_ack_range, 0u);
    EXPECT_EQ(header->additional_range_count, 1u);
}

TEST(QuicRecoveryTest, AckHistoryOutboundAckSnapshotWalkerBuildsTwoAdditionalRanges) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    history.record_received(/*packet_number=*/4, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(3));
    history.record_received(/*packet_number=*/7, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(4));

    const auto header = history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                                          coquic::quic::test::test_time(5));
    ASSERT_TRUE(header.has_value());
    if (!header.has_value()) {
        GTEST_FAIL() << "expected outbound ACK header";
        return;
    }

    std::vector<AckRange> additional_ranges;
    history.for_each_additional_ack_range_descending(
        *header, [&](AckRange range) { additional_ranges.push_back(range); });

    EXPECT_EQ(header->largest_acknowledged, 7u);
    EXPECT_EQ(header->first_ack_range, 0u);
    EXPECT_EQ(header->additional_range_count, 2u);
    ASSERT_EQ(additional_ranges.size(), 2u);
    EXPECT_EQ(additional_ranges[0].gap, 1u);
    EXPECT_EQ(additional_ranges[0].range_length, 0u);
    EXPECT_EQ(additional_ranges[1].gap, 1u);
    EXPECT_EQ(additional_ranges[1].range_length, 1u);
}

TEST(QuicRecoveryTest, AckHistoryOutboundSnapshotWalkerIgnoresPostSnapshotHistoryMutations) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    history.record_received(/*packet_number=*/4, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(3));
    history.record_received(/*packet_number=*/7, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(4));

    const auto snapshot_header = history.build_outbound_ack_header(
        /*ack_delay_exponent=*/3, coquic::quic::test::test_time(5));
    ASSERT_TRUE(snapshot_header.has_value());
    if (!snapshot_header.has_value()) {
        GTEST_FAIL() << "expected outbound ACK snapshot";
        return;
    }
    EXPECT_EQ(snapshot_header->largest_acknowledged, 7u);
    EXPECT_EQ(snapshot_header->additional_range_count, 2u);

    history.record_received(/*packet_number=*/10, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(6));
    const auto mutated_header = history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
                                                                  coquic::quic::test::test_time(7));
    ASSERT_TRUE(mutated_header.has_value());
    if (!mutated_header.has_value()) {
        GTEST_FAIL() << "expected outbound ACK header after mutation";
        return;
    }
    EXPECT_EQ(mutated_header->largest_acknowledged, 10u);
    EXPECT_EQ(mutated_header->additional_range_count, 3u);

    std::vector<AckRange> snapshot_ranges;
    history.for_each_additional_ack_range_descending(
        *snapshot_header, [&](AckRange range) { snapshot_ranges.push_back(range); });
    ASSERT_EQ(snapshot_ranges.size(), 2u);
    EXPECT_EQ(snapshot_ranges[0].gap, 1u);
    EXPECT_EQ(snapshot_ranges[0].range_length, 0u);
    EXPECT_EQ(snapshot_ranges[1].gap, 1u);
    EXPECT_EQ(snapshot_ranges[1].range_length, 1u);
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

TEST(QuicRecoveryTest, SecondAckElicitingPacketRequestsImmediateAck) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/4, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    EXPECT_FALSE(history.requests_immediate_ack());

    history.record_received(/*packet_number=*/5, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    EXPECT_TRUE(history.requests_immediate_ack());
}

TEST(QuicRecoveryTest, AckElicitingGapRequestsImmediateAck) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/7, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.on_ack_sent();
    EXPECT_FALSE(history.requests_immediate_ack());

    history.record_received(/*packet_number=*/9, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    EXPECT_TRUE(history.requests_immediate_ack());
}

TEST(QuicRecoveryTest, NonAckElicitingPacketBetweenAckElicitingPacketsDoesNotRequestImmediateAck) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.on_ack_sent();

    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/false,
                            coquic::quic::test::test_time(2));
    history.record_received(/*packet_number=*/2, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(3));
    EXPECT_FALSE(history.requests_immediate_ack());
}

TEST(QuicRecoveryTest, AckProcessingReturnsLightweightAckedAndLostPacketMetadata) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(SentPacketRecord{
        .packet_number = 0,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = true,
    });
    recovery.on_packet_sent(SentPacketRecord{
        .packet_number = 3,
        .sent_time = coquic::quic::test::test_time(1),
        .ack_eliciting = true,
        .in_flight = true,
    });

    const auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(10));

    ASSERT_EQ(result.acked_packets.size(), 1u);
    ASSERT_EQ(result.lost_packets.size(), 1u);
    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{3}));
    EXPECT_EQ(packet_numbers_from(result.lost_packets), (std::vector<std::uint64_t>{0}));

    const auto &acked_packet = result.acked_packets.front();
    EXPECT_EQ(acked_packet.sent_time, coquic::quic::test::test_time(1));
    EXPECT_TRUE(acked_packet.ack_eliciting);
    EXPECT_TRUE(acked_packet.in_flight);
    EXPECT_FALSE(acked_packet.declared_lost);

    const auto &lost_packet = result.lost_packets.front();
    EXPECT_EQ(lost_packet.sent_time, coquic::quic::test::test_time(0));
    EXPECT_TRUE(lost_packet.ack_eliciting);
    EXPECT_FALSE(lost_packet.in_flight);
    EXPECT_TRUE(lost_packet.declared_lost);
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

TEST(QuicRecoveryTest, AckFrameDirectRecoveryMatchesExpandedRangeRecovery) {
    coquic::quic::PacketSpaceRecovery direct_recovery;
    coquic::quic::PacketSpaceRecovery expanded_recovery;

    for (std::uint64_t packet_number = 0; packet_number != 32; ++packet_number) {
        const auto sent = make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
        direct_recovery.on_packet_sent(sent);
        expanded_recovery.on_packet_sent(sent);
    }
    direct_recovery.on_packet_declared_lost(11);
    expanded_recovery.on_packet_declared_lost(11);

    const coquic::quic::AckFrame ack{
        .largest_acknowledged = 15,
        .ack_delay = 0,
        .first_ack_range = 1,
        .additional_ranges =
            {
                coquic::quic::AckRange{
                    .gap = 1,
                    .range_length = 0,
                },
            },
    };

    const auto direct = direct_recovery.on_ack_received(ack, coquic::quic::test::test_time(100));
    const auto ranges = coquic::quic::ack_frame_packet_number_ranges(ack);
    ASSERT_TRUE(ranges.has_value());
    const auto expanded = expanded_recovery.on_ack_received(
        std::span<const coquic::quic::AckPacketNumberRange>(ranges.value()),
        ack.largest_acknowledged, coquic::quic::test::test_time(100));

    EXPECT_EQ(packet_numbers_from_handles(direct_recovery, direct.acked_packets.handles()),
              packet_numbers_from_handles(expanded_recovery, expanded.acked_packets.handles()));
    EXPECT_EQ(
        packet_numbers_from_handles(direct_recovery, direct.late_acked_packets.handles()),
        packet_numbers_from_handles(expanded_recovery, expanded.late_acked_packets.handles()));
    EXPECT_EQ(packet_numbers_from_handles(direct_recovery, direct.lost_packets.handles()),
              packet_numbers_from_handles(expanded_recovery, expanded.lost_packets.handles()));
    EXPECT_EQ(direct.largest_newly_acked_packet.has_value(),
              expanded.largest_newly_acked_packet.has_value());
    if (direct.largest_newly_acked_packet.has_value() &&
        expanded.largest_newly_acked_packet.has_value()) {
        EXPECT_EQ(direct.largest_newly_acked_packet->packet_number,
                  expanded.largest_newly_acked_packet->packet_number);
    }
    EXPECT_EQ(direct.largest_acknowledged_was_newly_acked,
              expanded.largest_acknowledged_was_newly_acked);
    EXPECT_EQ(direct.has_newly_acked_ack_eliciting, expanded.has_newly_acked_ack_eliciting);
}

TEST(QuicRecoveryTest, AckApplyResultMatchesCompatibilityResult) {
    coquic::quic::PacketSpaceRecovery fast_recovery;
    coquic::quic::PacketSpaceRecovery compatibility_recovery;

    for (std::uint64_t packet_number = 0; packet_number != 32; ++packet_number) {
        const auto sent = make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
        fast_recovery.on_packet_sent(sent);
        compatibility_recovery.on_packet_sent(sent);
    }
    fast_recovery.on_packet_declared_lost(11);
    compatibility_recovery.on_packet_declared_lost(11);

    const coquic::quic::AckFrame ack{
        .largest_acknowledged = 15,
        .ack_delay = 0,
        .first_ack_range = 1,
        .additional_ranges =
            {
                coquic::quic::AckRange{
                    .gap = 1,
                    .range_length = 0,
                },
            },
    };

    auto cursor = coquic::quic::make_ack_range_cursor(ack);
    ASSERT_TRUE(cursor.has_value());

    const auto fast = fast_recovery.apply_ack_received(cursor.value(), ack.largest_acknowledged,
                                                       coquic::quic::test::test_time(100));
    const auto compatibility =
        compatibility_recovery.on_ack_received(ack, coquic::quic::test::test_time(100));

    EXPECT_EQ(
        packet_numbers_from_handles(fast_recovery, fast.acked_packets),
        packet_numbers_from_handles(compatibility_recovery, compatibility.acked_packets.handles()));
    EXPECT_EQ(packet_numbers_from_handles(fast_recovery, fast.late_acked_packets),
              packet_numbers_from_handles(compatibility_recovery,
                                          compatibility.late_acked_packets.handles()));
    EXPECT_EQ(
        packet_numbers_from_handles(fast_recovery, fast.lost_packets),
        packet_numbers_from_handles(compatibility_recovery, compatibility.lost_packets.handles()));
    ASSERT_FALSE(fast.lost_packets.empty());
    for (const auto handle : fast.lost_packets) {
        const auto *packet = fast_recovery.packet_for_handle(handle);
        ASSERT_NE(packet, nullptr);
        EXPECT_TRUE(packet->in_flight);
        EXPECT_FALSE(packet->declared_lost);
    }
    for (const auto packet : compatibility.lost_packets) {
        EXPECT_FALSE(packet.in_flight);
        EXPECT_TRUE(packet.declared_lost);
    }
    if (!fast.largest_newly_acked_packet.has_value()) {
        GTEST_FAIL() << "expected fast largest newly ACKed packet";
        return;
    }
    if (!compatibility.largest_newly_acked_packet.has_value()) {
        GTEST_FAIL() << "expected compatibility largest newly ACKed packet";
        return;
    }
    const auto fast_largest = *fast.largest_newly_acked_packet;
    const auto compatibility_largest = compatibility.largest_newly_acked_packet.value();
    EXPECT_EQ(fast_largest.packet_number, compatibility_largest.packet_number);
    EXPECT_EQ(fast_largest.sent_time, compatibility_largest.sent_time);
    EXPECT_EQ(fast.largest_acknowledged_was_newly_acked,
              compatibility.largest_acknowledged_was_newly_acked);
    EXPECT_EQ(fast.has_newly_acked_ack_eliciting, compatibility.has_newly_acked_ack_eliciting);
}

TEST(QuicRecoveryTest, ReceivedAckCursorMatchesOwnedAckApply) {
    PacketSpaceRecovery owned_recovery;
    PacketSpaceRecovery received_recovery;

    for (std::uint64_t packet_number = 0; packet_number != 32; ++packet_number) {
        const auto sent = make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
        owned_recovery.on_packet_sent(sent);
        received_recovery.on_packet_sent(sent);
    }
    owned_recovery.on_packet_declared_lost(11);
    received_recovery.on_packet_declared_lost(11);

    const AckFrame ack{
        .largest_acknowledged = 15,
        .ack_delay = 3,
        .first_ack_range = 1,
        .additional_ranges =
            {
                AckRange{
                    .gap = 1,
                    .range_length = 0,
                },
            },
    };

    const auto encoded = coquic::quic::serialize_frame(coquic::quic::Frame{ack});
    ASSERT_TRUE(encoded.has_value());
    auto storage = std::make_shared<std::vector<std::byte>>(encoded.value());
    const auto decoded = coquic::quic::deserialize_received_frame(
        coquic::quic::SharedBytes(storage, 0, storage->size()));
    ASSERT_TRUE(decoded.has_value());
    const auto *received_ack = std::get_if<coquic::quic::ReceivedAckFrame>(&decoded.value().frame);
    ASSERT_NE(received_ack, nullptr);

    auto owned_cursor = coquic::quic::make_ack_range_cursor(ack);
    ASSERT_TRUE(owned_cursor.has_value());
    auto received_cursor = coquic::quic::make_ack_range_cursor(*received_ack);
    ASSERT_TRUE(received_cursor.has_value());

    const auto owned = owned_recovery.apply_ack_received(
        owned_cursor.value(), ack.largest_acknowledged, coquic::quic::test::test_time(100));
    const auto received = received_recovery.apply_ack_received(received_cursor.value(),
                                                               received_ack->largest_acknowledged,
                                                               coquic::quic::test::test_time(100));

    EXPECT_EQ(packet_numbers_from_handles(owned_recovery, owned.acked_packets),
              packet_numbers_from_handles(received_recovery, received.acked_packets));
    EXPECT_EQ(packet_numbers_from_handles(owned_recovery, owned.late_acked_packets),
              packet_numbers_from_handles(received_recovery, received.late_acked_packets));
    EXPECT_EQ(packet_numbers_from_handles(owned_recovery, owned.lost_packets),
              packet_numbers_from_handles(received_recovery, received.lost_packets));
    EXPECT_EQ(owned.largest_acknowledged_was_newly_acked,
              received.largest_acknowledged_was_newly_acked);
    EXPECT_EQ(owned.has_newly_acked_ack_eliciting, received.has_newly_acked_ack_eliciting);
    ASSERT_EQ(owned.largest_newly_acked_packet.has_value(),
              received.largest_newly_acked_packet.has_value());
    if (owned.largest_newly_acked_packet.has_value() &&
        received.largest_newly_acked_packet.has_value()) {
        EXPECT_EQ(owned.largest_newly_acked_packet->packet_number,
                  received.largest_newly_acked_packet->packet_number);
        EXPECT_EQ(owned.largest_newly_acked_packet->sent_time,
                  received.largest_newly_acked_packet->sent_time);
    }
}

TEST(QuicRecoveryTest, CompatibilityAckResultKeepsAscendingOrderAfterFastApply) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    recovery.on_packet_declared_lost(1);
    recovery.on_packet_declared_lost(5);

    const auto result = recovery.on_ack_received(
        AckFrame{
            .largest_acknowledged = 7,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 0,
                        .range_length = 0,
                    },
                    AckRange{
                        .gap = 2,
                        .range_length = 0,
                    },
                },
        },
        coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{7}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{1, 5}));
}

TEST(QuicRecoveryTest, AckApplyResultKeepsAscendingOrderAcrossSparseRanges) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/9, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(3)));
    recovery.on_packet_declared_lost(3);
    recovery.on_packet_declared_lost(7);

    const AckFrame ack{
        .largest_acknowledged = 9,
        .first_ack_range = 0,
        .additional_ranges =
            {
                AckRange{
                    .gap = 0,
                    .range_length = 0,
                },
                AckRange{
                    .gap = 0,
                    .range_length = 0,
                },
                AckRange{
                    .gap = 0,
                    .range_length = 0,
                },
            },
    };
    auto cursor = make_ack_range_cursor(ack);
    ASSERT_TRUE(cursor.has_value());
    if (!cursor.has_value()) {
        GTEST_FAIL() << "expected ACK range cursor";
        return;
    }

    const auto result = recovery.apply_ack_received(cursor.value(), /*largest_acknowledged=*/9,
                                                    coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets),
              (std::vector<std::uint64_t>{5, 9}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets),
              (std::vector<std::uint64_t>{3, 7}));
    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    if (!result.largest_newly_acked_packet.has_value()) {
        GTEST_FAIL() << "expected largest newly acknowledged packet";
        return;
    }
    EXPECT_EQ(result.largest_newly_acked_packet->packet_number, 9u);
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

TEST(QuicRecoveryTest, AckProcessingPreservesAscendingOrderForLateAckedPackets) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    recovery.on_packet_declared_lost(1);
    recovery.on_packet_declared_lost(5);

    const auto result = recovery.on_ack_received(
        AckFrame{
            .largest_acknowledged = 7,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    AckRange{
                        .gap = 0,
                        .range_length = 0,
                    },
                    AckRange{
                        .gap = 2,
                        .range_length = 0,
                    },
                },
        },
        coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{7}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{1, 5}));
    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    EXPECT_EQ(result.largest_newly_acked_packet->packet_number, 7u);
}

TEST(QuicRecoveryTest, AckProcessingSnapshotsLargestNewlyAckedPacketMetadataBeforeRetirement) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(33)));

    const auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/7), coquic::quic::test::test_time(40));

    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    recovery.retire_packet(result.acked_packets.handles().front());
    EXPECT_EQ(result.largest_newly_acked_packet->packet_number, 7u);
    EXPECT_EQ(result.largest_newly_acked_packet->sent_time, coquic::quic::test::test_time(33));
    EXPECT_TRUE(result.largest_newly_acked_packet->ack_eliciting);
    EXPECT_TRUE(result.largest_newly_acked_packet->in_flight);
    EXPECT_FALSE(result.largest_newly_acked_packet->declared_lost);
}

TEST(QuicRecoveryTest, RetiringEarlierPacketsDoesNotRenumberLaterHandles) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));

    const auto handle_before = recovery.handle_for_packet_number(2);
    ASSERT_TRUE(handle_before.has_value());
    if (!handle_before.has_value()) {
        return;
    }
    const auto checked_handle_before = *handle_before;
    ASSERT_EQ(checked_handle_before.slot_index, 2u);

    recovery.retire_packet(0);
    recovery.retire_packet(1);

    const auto handle_after = recovery.handle_for_packet_number(2);
    ASSERT_TRUE(handle_after.has_value());
    if (!handle_after.has_value()) {
        return;
    }
    const auto checked_handle_after = *handle_after;
    EXPECT_EQ(checked_handle_after.slot_index, 2u);
    EXPECT_EQ(checked_handle_after.slot_index, checked_handle_before.slot_index);
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_count(recovery), 3u);

    const auto *packet = recovery.packet_for_handle(checked_handle_before);
    ASSERT_NE(packet, nullptr);
    if (packet != nullptr) {
        EXPECT_EQ(packet->packet_number, 2u);
    }
}

TEST(QuicRecoveryTest, RetiringPacketClearsPayloadStateButKeepsStableSlotAllocation) {
    PacketSpaceRecovery recovery;
    SentPacketRecord packet = make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                               coquic::quic::test::test_time(0));
    packet.crypto_ranges.push_back(ByteRange{
        .offset = 3,
        .bytes = coquic::quic::SharedBytes({std::byte{0x01}, std::byte{0x02}, std::byte{0x03}}),
    });
    packet.stream_fragments.push_back(coquic::quic::StreamFrameSendFragment{
        .stream_id = 9,
        .offset = 12,
        .bytes = coquic::quic::SharedBytes({std::byte{0x0a}, std::byte{0x0b}}),
        .fin = true,
        .consumes_flow_control = true,
    });
    packet.max_data_frame = coquic::quic::MaxDataFrame{
        .maximum_data = 1024,
    };

    recovery.on_packet_sent(packet);
    recovery.retire_packet(0);

    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_count(recovery), 1u);

    const auto &retired_packet =
        coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_packet_at(recovery, 0);
    EXPECT_EQ(retired_packet.packet_number, 0u);
    EXPECT_TRUE(retired_packet.crypto_ranges.empty());
    EXPECT_TRUE(retired_packet.stream_fragments.empty());
    EXPECT_FALSE(retired_packet.max_data_frame.has_value());
}

TEST(QuicRecoveryTest, PacketHandlesRemainReadableAfterEarlierRetirementCompactsPrefix) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(10)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/11, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(11)));

    const auto handles = recovery.tracked_packets();
    ASSERT_EQ(handles.size(), 2u);

    recovery.retire_packet(handles.front());

    const auto *packet = recovery.packet_for_handle(handles.back());
    ASSERT_NE(packet, nullptr);
    if (packet == nullptr) {
        return;
    }
    EXPECT_EQ(packet->packet_number, 11u);
}

TEST(QuicRecoveryTest, TrackedPacketsPreservePacketNumberOrderAcrossLateLosses) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    recovery.on_packet_declared_lost(4);

    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()),
              (std::vector<std::uint64_t>{2, 4, 7}));
    const auto oldest = recovery.oldest_tracked_packet();
    ASSERT_TRUE(oldest.has_value());
    const auto newest = recovery.newest_tracked_packet();
    ASSERT_TRUE(newest.has_value());
    if (!oldest.has_value() || !newest.has_value()) {
        return;
    }
    EXPECT_EQ(oldest->packet_number, 2u);
    EXPECT_EQ(newest->packet_number, 7u);
}

TEST(QuicRecoveryTest, TimeThresholdLossScansLedgerWithoutSentPacketMap) {
    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));

    const auto ack_ranges = std::array{
        AckPacketNumberRange{
            .smallest = 4,
            .largest = 4,
        },
    };
    static_cast<void>(recovery.on_ack_received(ack_ranges, /*largest_acknowledged=*/4,
                                               coquic::quic::test::test_time(2)));

    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.collect_time_threshold_losses(
                                                        coquic::quic::test::test_time(20))),
              (std::vector<std::uint64_t>{3}));
}

TEST(QuicRecoveryTest, StaleAckStillDeclaresNewTimeThresholdLosses) {
    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(20)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(30)));

    const auto first_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/2), coquic::quic::test::test_time(31));
    EXPECT_EQ(packet_numbers_from(first_ack.acked_packets), (std::vector<std::uint64_t>{2}));
    EXPECT_EQ(packet_numbers_from(first_ack.lost_packets), (std::vector<std::uint64_t>{0}));

    const auto stale_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/2), coquic::quic::test::test_time(40));
    EXPECT_TRUE(stale_ack.acked_packets.empty());
    EXPECT_EQ(packet_numbers_from(stale_ack.lost_packets), (std::vector<std::uint64_t>{1}));
}

TEST(QuicRecoveryTest, RecoveryTracksLatestInflightAckElicitingPacketIncrementally) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(5)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(9)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/false,
                                             coquic::quic::test::test_time(11)));

    const auto latest_in_flight = recovery.latest_in_flight_ack_eliciting_packet();
    ASSERT_TRUE(latest_in_flight.has_value());
    EXPECT_EQ(optional_value_or_terminate(latest_in_flight).packet_number, 2u);

    static_cast<void>(
        recovery.on_ack_received(make_ack_frame(/*largest=*/2), coquic::quic::test::test_time(20)));

    const auto latest_in_flight_after_ack = recovery.latest_in_flight_ack_eliciting_packet();
    ASSERT_TRUE(latest_in_flight_after_ack.has_value());
    EXPECT_EQ(optional_value_or_terminate(latest_in_flight_after_ack).packet_number, 1u);

    recovery.on_packet_declared_lost(1);

    EXPECT_FALSE(recovery.latest_in_flight_ack_eliciting_packet().has_value());
}

TEST(QuicRecoveryTest, RecoveryTracksEarliestLossPacketAcrossLargestAckAdvance) {
    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(5)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(7)));

    EXPECT_FALSE(recovery.earliest_loss_packet().has_value());

    static_cast<void>(
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(9)));

    const auto earliest_loss = recovery.earliest_loss_packet();
    ASSERT_TRUE(earliest_loss.has_value());
    EXPECT_EQ(optional_value_or_terminate(earliest_loss).packet_number, 2u);

    recovery.on_packet_declared_lost(2);

    const auto earliest_loss_after_declaring_packet_2_lost = recovery.earliest_loss_packet();
    ASSERT_TRUE(earliest_loss_after_declaring_packet_2_lost.has_value());
    EXPECT_EQ(
        optional_value_or_terminate(earliest_loss_after_declaring_packet_2_lost).packet_number, 1u);
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

    EXPECT_TRUE(result.acked_packets.empty());
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{2}));
    EXPECT_TRUE(result.lost_packets.empty());
}

TEST(QuicRecoveryTest, AckProcessingRemovesAckedAndLateAckedPacketsFromTrackedPackets) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    recovery.on_packet_declared_lost(1);

    const std::array ack_ranges = {
        AckPacketNumberRange{
            .smallest = 1,
            .largest = 1,
        },
        AckPacketNumberRange{
            .smallest = 2,
            .largest = 2,
        },
    };

    const auto result = recovery.on_ack_received(ack_ranges, /*largest_acknowledged=*/2,
                                                 coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets.handles()),
              (std::vector<std::uint64_t>{2}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{1}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()),
              (std::vector<std::uint64_t>{0}));
    const auto oldest = recovery.oldest_tracked_packet();
    ASSERT_TRUE(oldest.has_value());
    const auto newest = recovery.newest_tracked_packet();
    ASSERT_TRUE(newest.has_value());
    if (!oldest.has_value() || !newest.has_value()) {
        return;
    }
    EXPECT_EQ(oldest->packet_number, 0u);
    EXPECT_EQ(newest->packet_number, 0u);
}

TEST(QuicRecoveryTest, AckProcessingHidesAcknowledgedPacketsFromCompatibilitySentPacketsView) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(4)));

    const auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/4), coquic::quic::test::test_time(8));

    ASSERT_EQ(result.acked_packets.size(), 1u);
    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_contains(recovery, 4));
    EXPECT_THROW(static_cast<void>(
                     coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_at(recovery, 4)),
                 std::out_of_range);
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets.handles()),
              (std::vector<std::uint64_t>{4}));
}

TEST(QuicRecoveryTest, AckProcessingSeparatesActiveAndLateAckedPacketsInLedger) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(3)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/5, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(5)));
    recovery.on_packet_declared_lost(3);

    const std::array ack_ranges = {
        AckPacketNumberRange{
            .smallest = 3,
            .largest = 3,
        },
        AckPacketNumberRange{
            .smallest = 5,
            .largest = 5,
        },
    };

    const auto result = recovery.on_ack_received(ack_ranges, /*largest_acknowledged=*/5,
                                                 coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets.handles()),
              (std::vector<std::uint64_t>{5}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{3}));
    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    EXPECT_EQ(result.largest_newly_acked_packet->packet_number, 5u);
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
