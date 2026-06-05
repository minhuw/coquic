#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <utility>
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

    static bool contains_range_start(const ReceivedPacketHistory &history,
                                     std::uint64_t packet_number) {
        return history.ranges_.contains(packet_number);
    }

    static std::uint64_t least_untracked_packet_number(const ReceivedPacketHistory &history) {
        return history.least_untracked_packet_number_;
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

    static std::size_t sent_packets_size(const PacketSpaceRecovery &recovery) {
        return recovery.sent_packets_.size();
    }

    static bool detached_sent_packets_contains(std::uint64_t packet_number) {
        PacketSpaceRecovery::SentPacketsView view{};
        return view.contains(packet_number);
    }

    static std::size_t detached_sent_packets_size() {
        PacketSpaceRecovery::SentPacketsView view{};
        return view.size();
    }

    static void detached_sent_packets_at(std::uint64_t packet_number) {
        PacketSpaceRecovery::SentPacketsView view{};
        static_cast<void>(view.at(packet_number));
    }

    static bool outstanding_slot_exists(PacketSpaceRecovery &recovery,
                                        std::uint64_t packet_number) {
        return recovery.outstanding_slot_for_packet_number(packet_number) != nullptr;
    }

    static bool slot_exists(const PacketSpaceRecovery &recovery, std::uint64_t packet_number) {
        return recovery.slot_for_packet_number(packet_number) != nullptr;
    }

    static std::size_t slot_count(const PacketSpaceRecovery &recovery) {
        return recovery.slots_.size();
    }

    static bool slot_has_packet_storage(const PacketSpaceRecovery &recovery,
                                        std::size_t slot_index) {
        return recovery.slots_.at(slot_index).packet != nullptr;
    }

    static const SentPacketRecord &slot_packet_at(const PacketSpaceRecovery &recovery,
                                                  std::size_t slot_index) {
        return recovery.slot_packet(recovery.slots_.at(slot_index));
    }

    static std::size_t next_packet_threshold_loss_slot(const PacketSpaceRecovery &recovery) {
        return recovery.next_packet_threshold_loss_slot_;
    }

    static std::uint64_t packet_reordering_threshold(const PacketSpaceRecovery &recovery) {
        return recovery.packet_reordering_threshold_;
    }

    static coquic::quic::QuicCoreDuration
    time_reordering_threshold(const PacketSpaceRecovery &recovery) {
        return recovery.time_reordering_threshold_;
    }

    static AckApplyResult
    apply_ack_received_descending_fast(PacketSpaceRecovery &recovery,
                                       std::span<const AckPacketNumberRange> ack_ranges_descending,
                                       std::uint64_t largest_acknowledged, QuicCoreTimePoint now) {
        return recovery.apply_ack_received_descending(ack_ranges_descending, largest_acknowledged,
                                                      now);
    }

    static void clear_live_slot_bit(PacketSpaceRecovery &recovery, std::size_t slot_index) {
        recovery.clear_live_slot_bit(slot_index);
    }

    static bool
    ack_ranges_include_newly_ackable_ack_eliciting_packet(const PacketSpaceRecovery &recovery,
                                                          AckRangeCursor cursor) {
        return recovery.ack_ranges_include_newly_ackable_ack_eliciting_packet(cursor);
    }

    static AckApplyResult apply_ack_received_descending_reference(
        PacketSpaceRecovery &recovery, std::span<const AckPacketNumberRange> ack_ranges_descending,
        std::uint64_t largest_acknowledged, QuicCoreTimePoint now) {
        auto state = recovery.begin_ack_received_apply(largest_acknowledged);
        state.now = now;
        for (const auto &range : ack_ranges_descending) {
            recovery.apply_ack_range_descending(state, range);
        }

        if (state.result.acked_packets.size() > 1) {
            std::reverse(state.result.acked_packets.begin(), state.result.acked_packets.end());
        }
        if (state.result.late_acked_packets.size() > 1) {
            std::reverse(state.result.late_acked_packets.begin(),
                         state.result.late_acked_packets.end());
        }

        if (recovery.slots_.empty()) {
            return std::move(state.result);
        }

        const auto loss_scan_end = std::min<std::size_t>(
            static_cast<std::size_t>(state.effective_largest_acked), recovery.slots_.size());
        for (auto slot_index = recovery.first_live_slot_;
             slot_index != PacketSpaceRecovery::kInvalidLedgerSlotIndex &&
             slot_index < loss_scan_end;) {
            auto &slot = recovery.slots_[slot_index];
            const auto next_live_slot = recovery.next_live_slot(slot_index);
            auto &packet = recovery.slot_packet(slot);
            const auto packet_number = packet.packet_number;
            if (slot.state != PacketSpaceRecovery::LedgerSlotState::sent || !packet.in_flight) {
                slot_index = next_live_slot;
                continue;
            }

            if (!recovery.is_packet_threshold_lost(packet_number, state.effective_largest_acked) &&
                !recovery.is_time_threshold_lost(packet.sent_time, now)) {
                slot_index = next_live_slot;
                continue;
            }

            recovery.erase_from_tracked_sets(packet);
            if (recovery.is_packet_threshold_lost(packet_number, state.effective_largest_acked)) {
                recovery.note_packet_threshold_loss(packet, state.effective_largest_acked);
            } else {
                recovery.note_time_threshold_loss(packet, now);
            }
            slot.state = PacketSpaceRecovery::LedgerSlotState::declared_lost;
            state.result.lost_packets.push_back(recovery.packet_handle(slot, slot_index));
            state.mutated = true;
            slot_index = next_live_slot;
        }

        if (state.mutated) {
            ++recovery.compatibility_version_;
        }

        return std::move(state.result);
    }

    static bool insert_in_flight_ack_eliciting_tracked(PacketSpaceRecovery &recovery,
                                                       std::uint64_t packet_number) {
        const auto *packet = recovery.find_packet(packet_number);
        if (packet == nullptr) {
            return false;
        }

        recovery.latest_in_flight_ack_eliciting_packet_ = recovery.tracked_packet(*packet);
        return true;
    }

    static bool insert_eligible_loss_tracked(PacketSpaceRecovery &recovery,
                                             std::uint64_t packet_number) {
        const auto *packet = recovery.find_packet(packet_number);
        if (packet == nullptr) {
            return false;
        }

        return recovery.eligible_loss_packets_.insert(recovery.tracked_packet(*packet)).second;
    }

    static std::size_t in_flight_ack_eliciting_tracked_count(const PacketSpaceRecovery &recovery) {
        return recovery.latest_in_flight_ack_eliciting_packet_.has_value() ? 1u : 0u;
    }

    static std::size_t eligible_loss_tracked_count(const PacketSpaceRecovery &recovery) {
        return recovery.eligible_loss_packets_.size();
    }

    static SentPacketRecord &slot_packet_at(PacketSpaceRecovery &recovery, std::size_t slot_index) {
        return recovery.slot_packet(recovery.slots_.at(slot_index));
    }

    struct SlotPacketNumberOverride {
        std::size_t slot_index = 0;
        std::uint64_t packet_number = 0;
    };

    static void set_slot_packet_number(PacketSpaceRecovery &recovery,
                                       SlotPacketNumberOverride override) {
        auto &slot = recovery.slots_.at(override.slot_index);
        slot.packet_number = override.packet_number;
        if (slot.packet != nullptr) {
            slot.packet->packet_number = override.packet_number;
        }
    }

    static void set_slot_acknowledged(PacketSpaceRecovery &recovery, std::size_t slot_index,
                                      bool acknowledged) {
        recovery.slots_.at(slot_index).acknowledged = acknowledged;
    }

    static void set_slot_state_retired(PacketSpaceRecovery &recovery, std::size_t slot_index) {
        recovery.slots_.at(slot_index).state = PacketSpaceRecovery::LedgerSlotState::retired;
    }

    static void set_slot_state_sent(PacketSpaceRecovery &recovery, std::size_t slot_index) {
        recovery.slots_.at(slot_index).state = PacketSpaceRecovery::LedgerSlotState::sent;
    }

    static void set_slot_state_declared_lost(PacketSpaceRecovery &recovery,
                                             std::size_t slot_index) {
        recovery.slots_.at(slot_index).state = PacketSpaceRecovery::LedgerSlotState::declared_lost;
    }

    static AckApplyResult apply_ack_received(PacketSpaceRecovery &recovery, AckRangeCursor cursor,
                                             std::uint64_t largest_acknowledged,
                                             QuicCoreTimePoint now) {
        return recovery.apply_ack_received(cursor, largest_acknowledged, now);
    }

    static void set_largest_acked_packet_number(PacketSpaceRecovery &recovery,
                                                std::optional<std::uint64_t> packet_number) {
        recovery.largest_acked_packet_number_ = packet_number;
    }

    static void set_next_loss_candidate_slot(PacketSpaceRecovery &recovery,
                                             std::size_t slot_index) {
        recovery.next_loss_candidate_slot_ = slot_index;
    }

    static void set_first_live_slot(PacketSpaceRecovery &recovery, std::size_t slot_index) {
        recovery.first_live_slot_ = slot_index;
    }

    static std::size_t next_loss_candidate_slot(const PacketSpaceRecovery &recovery) {
        return recovery.next_loss_candidate_slot_;
    }

    static void maybe_track_as_loss_candidate(PacketSpaceRecovery &recovery,
                                              const SentPacketRecord &packet) {
        recovery.maybe_track_as_loss_candidate(packet);
    }

    static void track_new_loss_candidates(PacketSpaceRecovery &recovery,
                                          std::optional<std::uint64_t> previous_largest_acked,
                                          std::uint64_t largest_acked) {
        recovery.track_new_loss_candidates(previous_largest_acked, largest_acked);
    }

    static void adapt_reordering_thresholds_from_spurious_loss(PacketSpaceRecovery &recovery,
                                                               const SentPacketRecord &packet,
                                                               QuicCoreTimePoint now) {
        recovery.maybe_adapt_reordering_thresholds_from_spurious_loss(packet, now);
    }

    static AckProcessingResult ack_processing_result_from_apply(const PacketSpaceRecovery &recovery,
                                                                const AckApplyResult &apply) {
        return recovery.ack_processing_result_from_apply(apply);
    }

    static bool slot_for_tracked_packet_exists(const PacketSpaceRecovery &recovery,
                                               DeadlineTrackedPacket packet) {
        return recovery.slot_for_tracked_packet(packet) != nullptr;
    }

    static bool is_valid_in_flight_ack_eliciting_tracked(const PacketSpaceRecovery &recovery,
                                                         DeadlineTrackedPacket packet) {
        return recovery.is_valid_in_flight_ack_eliciting_tracked_packet(packet);
    }

    static bool is_valid_eligible_loss_tracked(const PacketSpaceRecovery &recovery,
                                               DeadlineTrackedPacket packet) {
        return recovery.is_valid_eligible_loss_tracked_packet(packet);
    }

    static std::size_t newest_live_slot_at_or_below(const PacketSpaceRecovery &recovery,
                                                    std::uint64_t packet_number) {
        return recovery.newest_live_slot_at_or_below(packet_number);
    }

    static std::size_t invalid_live_slot_index() {
        return PacketSpaceRecovery::kInvalidLedgerSlotIndex;
    }

    static bool link_live_slot_tail_guard_branch_for_tests() {
        PacketSpaceRecovery recovery;
        recovery.slots_.resize(8);
        recovery.first_live_slot_ = 2;
        recovery.last_live_slot_ = 7;
        recovery.live_links_.resize(8);
        recovery.live_links_[2] = PacketSpaceRecovery::LiveSlotLink{
            .prev = PacketSpaceRecovery::kInvalidLedgerSlotIndex,
            .next = PacketSpaceRecovery::kInvalidLedgerSlotIndex,
        };

        recovery.link_live_slot(5);
        return recovery.last_live_slot_ == 5 && recovery.live_links_[5].prev == 7 &&
               recovery.live_links_[7].next == 5;
    }

    static bool newest_live_slot_bitset_guard_branches_for_tests() {
        PacketSpaceRecovery no_words;
        no_words.slots_.resize(64);
        const bool missing_word_ok = no_words.newest_live_slot_at_or_below(63) ==
                                     PacketSpaceRecovery::kInvalidLedgerSlotIndex;

        PacketSpaceRecovery previous_word;
        previous_word.slots_.resize(130);
        previous_word.live_slot_words_.resize(2);
        previous_word.live_slot_words_[0] = std::uint64_t{1} << 7;

        return missing_word_ok && previous_word.newest_live_slot_at_or_below(64) == 7u;
    }
};

} // namespace coquic::quic::test

namespace coquic::quic {
RecoveryPacketMetadata resolved_packet_metadata(const PacketSpaceRecovery *recovery,
                                                RecoveryPacketHandle handle);
}

namespace {

using coquic::quic::AckApplyLargestNewlyAckedPacket;
using coquic::quic::AckApplyResult;
using coquic::quic::AckFrame;
using coquic::quic::AckPacketNumberRange;
using coquic::quic::AckRange;
using coquic::quic::ByteRange;
using coquic::quic::DeadlineTrackedPacket;
using coquic::quic::PacketSpaceRecovery;
using coquic::quic::QuicCoreTimePoint;
using coquic::quic::ReceivedPacketHistory;
using coquic::quic::RecoveryPacketHandle;
using coquic::quic::RecoveryPacketHandleList;
using coquic::quic::RecoveryPacketHandleOptional;
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
packet_numbers_from_handles(const PacketSpaceRecovery &packet_recovery,
                            std::span<const RecoveryPacketHandle> handles) {
    std::vector<std::uint64_t> packet_numbers;
    packet_numbers.reserve(handles.size());
    for (const auto packet_handle : handles) {
        const auto *record = packet_recovery.packet_for_handle(packet_handle);
        EXPECT_NE(record, nullptr);
        if (record != nullptr) {
            packet_numbers.push_back(record->packet_number);
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

std::vector<AckPacketNumberRange>
ack_ranges_descending_from(const std::vector<bool> &acknowledged_by_peer) {
    std::vector<AckPacketNumberRange> ack_ranges;
    std::size_t index = acknowledged_by_peer.size();
    while (index != 0) {
        --index;
        if (!acknowledged_by_peer[index]) {
            continue;
        }

        const auto largest = static_cast<std::uint64_t>(index);
        auto smallest_index = index;
        while (smallest_index != 0 && acknowledged_by_peer[smallest_index - 1]) {
            --smallest_index;
        }
        ack_ranges.push_back(AckPacketNumberRange{
            .smallest = static_cast<std::uint64_t>(smallest_index),
            .largest = largest,
        });
        index = smallest_index;
    }
    return ack_ranges;
}

void consume_ack_apply_result(PacketSpaceRecovery &recovery,
                              const coquic::quic::AckApplyResult &result) {
    for (const auto handle : result.acked_packets) {
        recovery.retire_packet(handle);
    }
    for (const auto handle : result.late_acked_packets) {
        recovery.retire_packet(handle);
    }
    for (const auto handle : result.lost_packets) {
        recovery.on_packet_declared_lost(handle.packet_number);
    }
}

TEST(QuicRecoveryTest, FastAckApplyMatchesReferenceLossScanAcrossSparseAckBatches) {
    PacketSpaceRecovery fast_recovery;
    PacketSpaceRecovery reference_recovery;
    fast_recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    fast_recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    fast_recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    fast_recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    reference_recovery.rtt_state() = fast_recovery.rtt_state();

    constexpr std::uint64_t total_packets = 256;
    for (std::uint64_t packet_number = 0; packet_number != total_packets; ++packet_number) {
        const auto sent = make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
        fast_recovery.on_packet_sent(sent);
        reference_recovery.on_packet_sent(sent);
    }

    std::vector<bool> acknowledged_by_peer(total_packets, false);
    std::uint64_t largest_acknowledged = 0;
    for (std::uint64_t step = 0; step != 96; ++step) {
        largest_acknowledged = std::min<std::uint64_t>(largest_acknowledged + 3, total_packets - 1);
        for (std::uint64_t packet_number = 0; packet_number <= largest_acknowledged;
             ++packet_number) {
            if (acknowledged_by_peer[packet_number]) {
                continue;
            }

            const auto should_ack =
                packet_number == largest_acknowledged ||
                ((packet_number + step) % 11 != 0 && (packet_number + step * 3) % 17 != 0);
            if (should_ack) {
                acknowledged_by_peer[packet_number] = true;
            }
        }

        const auto ack_ranges = ack_ranges_descending_from(acknowledged_by_peer);
        ASSERT_FALSE(ack_ranges.empty());
        const auto now = coquic::quic::test::test_time(1000 + static_cast<std::int64_t>(step));
        auto fast =
            coquic::quic::test::PacketSpaceRecoveryTestPeer::apply_ack_received_descending_fast(
                fast_recovery, std::span<const AckPacketNumberRange>(ack_ranges),
                largest_acknowledged, now);
        auto reference = coquic::quic::test::PacketSpaceRecoveryTestPeer::
            apply_ack_received_descending_reference(
                reference_recovery, std::span<const AckPacketNumberRange>(ack_ranges),
                largest_acknowledged, now);

        EXPECT_EQ(packet_numbers_from_handles(fast_recovery, fast.acked_packets),
                  packet_numbers_from_handles(reference_recovery, reference.acked_packets))
            << "step=" << step;
        EXPECT_EQ(packet_numbers_from_handles(fast_recovery, fast.late_acked_packets),
                  packet_numbers_from_handles(reference_recovery, reference.late_acked_packets))
            << "step=" << step;
        EXPECT_EQ(packet_numbers_from_handles(fast_recovery, fast.lost_packets),
                  packet_numbers_from_handles(reference_recovery, reference.lost_packets))
            << "step=" << step;

        consume_ack_apply_result(fast_recovery, fast);
        consume_ack_apply_result(reference_recovery, reference);
    }
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
    auto mutated_header = history.build_outbound_ack_header(/*ack_delay_exponent=*/3,
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

TEST(QuicRecoveryTest, AckHistoryCapsSparseTrackedRanges) {
    ReceivedPacketHistory history;
    for (std::uint64_t packet_number = 0; packet_number <= coquic::quic::kMaxTrackedAckRanges * 2;
         packet_number += 2) {
        history.record_received(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }

    EXPECT_EQ(coquic::quic::test::ReceivedPacketHistoryTestPeer::range_count(history),
              coquic::quic::kMaxTrackedAckRanges);
    EXPECT_FALSE(
        coquic::quic::test::ReceivedPacketHistoryTestPeer::contains_range_start(history, 0));
    EXPECT_TRUE(coquic::quic::test::ReceivedPacketHistoryTestPeer::contains_range_start(
        history, coquic::quic::kMaxTrackedAckRanges * 2 - 2));
    EXPECT_EQ(
        coquic::quic::test::ReceivedPacketHistoryTestPeer::least_untracked_packet_number(history),
        1u);
    EXPECT_TRUE(history.should_ignore(0));
    EXPECT_TRUE(history.should_ignore(2));
    EXPECT_FALSE(history.should_ignore(1));
    EXPECT_FALSE(history.should_ignore(3));

    const auto built_ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(200));
    if (!built_ack.has_value()) {
        FAIL() << "ACK history cap did not build an ACK frame";
    }
    auto ack_value = optional_value_or_terminate(built_ack);
    EXPECT_EQ(ack_value.additional_ranges.size(), coquic::quic::kMaxTrackedAckRanges - 1);
}

TEST(QuicRecoveryTest, AckHistoryCapStillMergesRetainedBridgedRanges) {
    ReceivedPacketHistory history;
    for (std::uint64_t packet_number = 0; packet_number <= coquic::quic::kMaxTrackedAckRanges * 2;
         packet_number += 2) {
        history.record_received(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }

    history.record_received(coquic::quic::kMaxTrackedAckRanges * 2 - 1,
                            /*ack_eliciting=*/true, coquic::quic::test::test_time(200));

    EXPECT_EQ(coquic::quic::test::ReceivedPacketHistoryTestPeer::range_count(history),
              coquic::quic::kMaxTrackedAckRanges - 1);
    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(201));
    ASSERT_TRUE(ack.has_value());
    auto ack_value = optional_value_or_terminate(ack);
    EXPECT_EQ(ack_value.first_ack_range, 2u);
}

TEST(QuicRecoveryTest, AckHistoryRetiresRangesAcknowledgedByPeerAck) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/0, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    history.record_received(/*packet_number=*/1, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    history.record_received(/*packet_number=*/4, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(3));
    history.record_received(/*packet_number=*/7, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(4));

    history.retire_acknowledged_ranges_up_to(4);

    EXPECT_EQ(coquic::quic::test::ReceivedPacketHistoryTestPeer::range_count(history), 1u);
    EXPECT_EQ(
        coquic::quic::test::ReceivedPacketHistoryTestPeer::least_untracked_packet_number(history),
        5u);
    EXPECT_TRUE(history.should_ignore(4));
    EXPECT_FALSE(history.should_ignore(6));
    EXPECT_TRUE(history.should_ignore(7));

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(8));
    ASSERT_TRUE(ack.has_value());
    auto ack_value = optional_value_or_terminate(ack);
    EXPECT_EQ(ack_value.largest_acknowledged, 7u);
    EXPECT_EQ(ack_value.first_ack_range, 0u);
    EXPECT_TRUE(ack_value.additional_ranges.empty());
}

TEST(QuicRecoveryTest, AckHistoryRetirementShrinksRangeCrossingLargestAcknowledged) {
    ReceivedPacketHistory history;
    for (std::uint64_t packet_number = 0; packet_number <= 7; ++packet_number) {
        history.record_received(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }

    history.retire_acknowledged_ranges_up_to(4);

    EXPECT_EQ(coquic::quic::test::ReceivedPacketHistoryTestPeer::range_count(history), 1u);
    EXPECT_FALSE(
        coquic::quic::test::ReceivedPacketHistoryTestPeer::contains_range_start(history, 0));
    EXPECT_TRUE(
        coquic::quic::test::ReceivedPacketHistoryTestPeer::contains_range_start(history, 5));
    EXPECT_TRUE(history.should_ignore(4));
    EXPECT_TRUE(history.should_ignore(5));
    EXPECT_FALSE(history.should_ignore(8));

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(8));
    ASSERT_TRUE(ack.has_value());
    auto ack_value = optional_value_or_terminate(ack);
    EXPECT_EQ(ack_value.largest_acknowledged, 7u);
    EXPECT_EQ(ack_value.first_ack_range, 2u);
    EXPECT_TRUE(ack_value.additional_ranges.empty());
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

TEST(QuicRecoveryTest, UnavailableEcnLeavesAckEcnCountsAbsent) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/6, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1),
                            coquic::quic::QuicEcnCodepoint::unavailable);

    const auto ack =
        history.build_ack_frame(/*ack_delay_exponent=*/3, coquic::quic::test::test_time(2));
    if (!ack.has_value()) {
        ADD_FAILURE() << "missing ACK frame";
        return;
    }
    const auto &ack_frame = *ack;
    EXPECT_EQ(ack_frame.ecn_counts, std::nullopt);
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

TEST(QuicRecoveryTest, SecondAckElicitingPacketRequestsImmediateAckByDefault) {
    ReceivedPacketHistory history;
    history.record_received(/*packet_number=*/4, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(1));
    EXPECT_FALSE(history.requests_immediate_ack());

    history.record_received(/*packet_number=*/5, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(2));
    EXPECT_TRUE(history.requests_immediate_ack());
}

TEST(QuicRecoveryTest, ConfiguredAckElicitingThresholdRequestsImmediateAck) {
    ReceivedPacketHistory history;
    for (std::uint64_t packet_number = 4; packet_number < 19; ++packet_number) {
        history.record_received(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)),
            coquic::quic::QuicEcnCodepoint::unavailable,
            /*ack_eliciting_threshold=*/16);
        EXPECT_FALSE(history.requests_immediate_ack()) << "packet_number=" << packet_number;
    }

    history.record_received(/*packet_number=*/19, /*ack_eliciting=*/true,
                            coquic::quic::test::test_time(19),
                            coquic::quic::QuicEcnCodepoint::unavailable,
                            /*ack_eliciting_threshold=*/16);
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

    auto result =
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

    auto stale_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/5), coquic::quic::test::test_time(11));
    EXPECT_TRUE(stale_ack.acked_packets.empty());
    EXPECT_TRUE(stale_ack.lost_packets.empty());
    auto stale_largest_acked = recovery.largest_acked_packet_number();
    ASSERT_TRUE(stale_largest_acked.has_value());
    if (!stale_largest_acked.has_value()) {
        GTEST_FAIL() << "expected running largest acknowledged packet number";
        return;
    }
    EXPECT_EQ(*stale_largest_acked, 6u);
}

TEST(QuicRecoveryTest, PacketThresholdLossFrontierAdvancesAcrossAckBatches) {
    PacketSpaceRecovery recovery;
    for (std::uint64_t packet_number = 0; packet_number <= 4; ++packet_number) {
        recovery.on_packet_sent(make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number))));
    }

    const auto first_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(10));
    EXPECT_EQ(packet_numbers_from(first_ack.acked_packets), (std::vector<std::uint64_t>{3}));
    EXPECT_EQ(packet_numbers_from(first_ack.lost_packets), (std::vector<std::uint64_t>{0}));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::next_packet_threshold_loss_slot(recovery),
        1u);

    const auto second_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/4), coquic::quic::test::test_time(11));
    EXPECT_EQ(packet_numbers_from(second_ack.acked_packets), (std::vector<std::uint64_t>{4}));
    EXPECT_EQ(packet_numbers_from(second_ack.lost_packets), (std::vector<std::uint64_t>{1}));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::next_packet_threshold_loss_slot(recovery),
        2u);

    auto stale_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/4), coquic::quic::test::test_time(12));
    EXPECT_TRUE(stale_ack.acked_packets.empty());
    EXPECT_TRUE(stale_ack.lost_packets.empty());
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::next_packet_threshold_loss_slot(recovery),
        2u);
}

TEST(QuicRecoveryTest, PacketThresholdScanSkipsPacketsBelowReorderingGap) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(3)));
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_packet_number(
        recovery, {.slot_index = 0, .packet_number = 2});

    auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(4));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{3}));
    EXPECT_TRUE(result.lost_packets.empty());
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::next_packet_threshold_loss_slot(recovery),
        1u);
}

TEST(QuicRecoveryTest, PacketThresholdLossMarksCauseForAdaptiveReordering) {
    PacketSpaceRecovery recovery;
    for (std::uint64_t packet_number = 0; packet_number <= 3; ++packet_number) {
        recovery.on_packet_sent(make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number))));
    }

    auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(10));

    ASSERT_EQ(result.lost_packets.size(), 1u);
    EXPECT_EQ(result.lost_packets.front().packet_number, 0u);
    const auto *lost = recovery.find_packet(0);
    ASSERT_NE(lost, nullptr);
    EXPECT_TRUE(lost->lost_by_packet_threshold);
    EXPECT_EQ(lost->packet_threshold_largest_acked, 3u);
}

TEST(QuicRecoveryTest, LateAckedPacketThresholdLossRaisesReorderingThreshold) {
    PacketSpaceRecovery recovery;
    for (std::uint64_t packet_number = 0; packet_number <= 7; ++packet_number) {
        recovery.on_packet_sent(make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number))));
    }

    const auto reordered =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(10));
    EXPECT_EQ(packet_numbers_from(reordered.lost_packets), (std::vector<std::uint64_t>{0}));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::packet_reordering_threshold(recovery),
        coquic::quic::kPacketThreshold);

    const auto late =
        recovery.on_ack_received(make_ack_frame(/*largest=*/0), coquic::quic::test::test_time(11));
    EXPECT_EQ(packet_numbers_from(late.late_acked_packets), (std::vector<std::uint64_t>{0}));
    EXPECT_TRUE(late.lost_packets.empty());
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::packet_reordering_threshold(recovery), 4u);

    const auto same_distance =
        recovery.on_ack_received(make_ack_frame(/*largest=*/4), coquic::quic::test::test_time(12));
    EXPECT_EQ(packet_numbers_from(same_distance.acked_packets), (std::vector<std::uint64_t>{4}));
    EXPECT_TRUE(same_distance.lost_packets.empty());

    auto larger_distance =
        recovery.on_ack_received(make_ack_frame(/*largest=*/5), coquic::quic::test::test_time(13));
    EXPECT_EQ(packet_numbers_from(larger_distance.acked_packets), (std::vector<std::uint64_t>{5}));
    EXPECT_EQ(packet_numbers_from(larger_distance.lost_packets), (std::vector<std::uint64_t>{1}));
}

TEST(QuicRecoveryTest, SpuriousLossAdaptationKeepsThresholdsWhenNoNewEvidence) {
    PacketSpaceRecovery recovery;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_largest_acked_packet_number(recovery,
                                                                                     std::nullopt);

    auto no_packet_threshold = make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                                coquic::quic::test::test_time(4));
    coquic::quic::test::PacketSpaceRecoveryTestPeer::adapt_reordering_thresholds_from_spurious_loss(
        recovery, no_packet_threshold, coquic::quic::test::test_time(4));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::packet_reordering_threshold(recovery),
        coquic::quic::kPacketThreshold);

    auto non_reordered_packet_threshold = make_sent_packet(
        /*packet_number=*/5, /*ack_eliciting=*/true, coquic::quic::test::test_time(5));
    non_reordered_packet_threshold.lost_by_packet_threshold = true;
    non_reordered_packet_threshold.packet_threshold_largest_acked = 5;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::adapt_reordering_thresholds_from_spurious_loss(
        recovery, non_reordered_packet_threshold, coquic::quic::test::test_time(5));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::packet_reordering_threshold(recovery),
        coquic::quic::kPacketThreshold);

    auto same_packet_threshold = make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true,
                                                  coquic::quic::test::test_time(10));
    same_packet_threshold.lost_by_packet_threshold = true;
    same_packet_threshold.packet_threshold_largest_acked = 12;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::adapt_reordering_thresholds_from_spurious_loss(
        recovery, same_packet_threshold, coquic::quic::test::test_time(10));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::packet_reordering_threshold(recovery),
        coquic::quic::kPacketThreshold);

    auto larger_packet_threshold_without_largest_ack = make_sent_packet(
        /*packet_number=*/1, /*ack_eliciting=*/true, coquic::quic::test::test_time(1));
    larger_packet_threshold_without_largest_ack.lost_by_packet_threshold = true;
    larger_packet_threshold_without_largest_ack.packet_threshold_largest_acked = 5;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::adapt_reordering_thresholds_from_spurious_loss(
        recovery, larger_packet_threshold_without_largest_ack, coquic::quic::test::test_time(10));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::packet_reordering_threshold(recovery), 5u);

    auto time_threshold_without_delay = make_sent_packet(
        /*packet_number=*/6, /*ack_eliciting=*/true, coquic::quic::test::test_time(20));
    time_threshold_without_delay.lost_by_time_threshold = true;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::adapt_reordering_thresholds_from_spurious_loss(
        recovery, time_threshold_without_delay, coquic::quic::test::test_time(20));
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::time_reordering_threshold(recovery),
              std::chrono::milliseconds(0));
}

TEST(QuicRecoveryTest, TimeThresholdLossMarksCauseForAdaptiveReordering) {
    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);

    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));

    auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/1), coquic::quic::test::test_time(12));

    ASSERT_EQ(result.lost_packets.size(), 1u);
    EXPECT_EQ(result.lost_packets.front().packet_number, 0u);
    const auto *lost = recovery.find_packet(0);
    ASSERT_NE(lost, nullptr);
    EXPECT_FALSE(lost->lost_by_packet_threshold);
    EXPECT_TRUE(lost->lost_by_time_threshold);
    EXPECT_EQ(lost->time_threshold_loss_time, coquic::quic::test::test_time(12));
}

TEST(QuicRecoveryTest, LateAckedTimeThresholdLossRaisesReorderingThreshold) {
    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);

    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));

    const auto loss =
        recovery.on_ack_received(make_ack_frame(/*largest=*/1), coquic::quic::test::test_time(12));
    EXPECT_EQ(packet_numbers_from(loss.lost_packets), (std::vector<std::uint64_t>{0}));
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::time_reordering_threshold(recovery),
              std::chrono::milliseconds(0));

    const auto late =
        recovery.on_ack_received(make_ack_frame(/*largest=*/0), coquic::quic::test::test_time(20));

    EXPECT_EQ(packet_numbers_from(late.late_acked_packets), (std::vector<std::uint64_t>{0}));
    EXPECT_TRUE(late.lost_packets.empty());
    EXPECT_GE(coquic::quic::test::PacketSpaceRecoveryTestPeer::time_reordering_threshold(recovery),
              std::chrono::milliseconds(21));
    EXPECT_EQ(recovery.time_threshold_deadline(coquic::quic::test::test_time(2)),
              coquic::quic::test::test_time(23));
}

TEST(QuicRecoveryTest, AckProcessingRejectsMalformedFirstAckRange) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    auto result = recovery.on_ack_received(make_ack_frame(/*largest=*/0, /*first_ack_range=*/1),
                                           coquic::quic::test::test_time(10));

    EXPECT_TRUE(result.acked_packets.empty());
    EXPECT_TRUE(result.lost_packets.empty());
}

TEST(QuicRecoveryTest, AckProcessingRejectsMalformedAdditionalRangeGapUnderflow) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    auto result = recovery.on_ack_received(
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

    auto result = recovery.on_ack_received(
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

    auto result = recovery.on_ack_received(
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

    auto result = recovery.on_ack_received(
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

    auto direct = direct_recovery.on_ack_received(ack, coquic::quic::test::test_time(100));
    auto ranges = coquic::quic::ack_frame_packet_number_ranges(ack);
    ASSERT_TRUE(ranges.has_value());
    auto expanded = expanded_recovery.on_ack_received(
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

    auto fast = fast_recovery.apply_ack_received(cursor.value(), ack.largest_acknowledged,
                                                 coquic::quic::test::test_time(100));
    auto compatibility =
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
    auto compatibility_largest = compatibility.largest_newly_acked_packet.value();
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

    auto owned = owned_recovery.apply_ack_received(owned_cursor.value(), ack.largest_acknowledged,
                                                   coquic::quic::test::test_time(100));
    auto received = received_recovery.apply_ack_received(received_cursor.value(),
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

    auto result = recovery.on_ack_received(
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

    auto result = recovery.apply_ack_received(cursor.value(), /*largest_acknowledged=*/9,
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

    auto result = recovery.on_ack_received(make_ack_frame(/*largest=*/2, /*first_ack_range=*/1),
                                           coquic::quic::test::test_time(70));

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

    auto result = recovery.on_ack_received(
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

    auto result =
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

TEST(QuicRecoveryTest, RetiringPacketReleasesPayloadStateButKeepsStableSlotAllocation) {
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
    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_has_packet_storage(recovery, 0));
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
    auto oldest = recovery.oldest_tracked_packet();
    ASSERT_TRUE(oldest.has_value());
    auto newest = recovery.newest_tracked_packet();
    ASSERT_TRUE(newest.has_value());
    if (!oldest.has_value() || !newest.has_value()) {
        return;
    }
    EXPECT_EQ(oldest.value().packet_number, 2u);
    EXPECT_EQ(newest.value().packet_number, 7u);
}

TEST(QuicRecoveryTest, RecoveryLiveSlotHelpersCoverTailAndBitsetFallbacks) {
    EXPECT_TRUE(coquic::quic::test::PacketSpaceRecoveryTestPeer::
                    link_live_slot_tail_guard_branch_for_tests());
    EXPECT_TRUE(coquic::quic::test::PacketSpaceRecoveryTestPeer::
                    newest_live_slot_bitset_guard_branches_for_tests());

    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/130, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));

    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::newest_live_slot_at_or_below(
                  recovery, 129),
              coquic::quic::test::PacketSpaceRecoveryTestPeer::invalid_live_slot_index());
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::newest_live_slot_at_or_below(
                  recovery, 130),
              130u);
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::newest_live_slot_at_or_below(
                  recovery, 140),
              130u);
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

TEST(QuicRecoveryTest, UnsortedAckRangesAreSortedBeforeApply) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(3)));

    std::array ranges = {
        AckPacketNumberRange{.smallest = 1, .largest = 1},
        AckPacketNumberRange{.smallest = 3, .largest = 3},
    };
    auto result = recovery.on_ack_received(ranges, /*largest_acknowledged=*/3,
                                           coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{1, 3}));
}

TEST(QuicRecoveryTest, AckRangeSortBreaksTiesBySmallestDescending) {
    PacketSpaceRecovery recovery;
    for (std::uint64_t packet_number = 2; packet_number <= 3; ++packet_number) {
        recovery.on_packet_sent(make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number))));
    }

    std::array ranges = {
        AckPacketNumberRange{.smallest = 2, .largest = 3},
        AckPacketNumberRange{.smallest = 3, .largest = 3},
    };

    auto result = recovery.on_ack_received(ranges, /*largest_acknowledged=*/3,
                                           coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{2, 3}));
}

TEST(QuicRecoveryTest, PmtuProbeDeadlineHelpersSelectEarliestProbeAndCollectExpiredProbes) {
    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));

    auto later_probe = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                        coquic::quic::test::test_time(5));
    later_probe.is_pmtu_probe = true;
    later_probe.pmtu_probe_size = 1400;
    recovery.on_packet_sent(later_probe);

    auto earlier_probe = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                          coquic::quic::test::test_time(3));
    earlier_probe.is_pmtu_probe = true;
    earlier_probe.pmtu_probe_size = 1300;
    recovery.on_packet_sent(earlier_probe);

    const auto earliest = recovery.earliest_pmtu_probe_packet();
    ASSERT_TRUE(earliest.has_value());
    auto earliest_probe = optional_value_or_terminate(earliest);
    EXPECT_EQ(earliest_probe.packet_number, 3u);
    EXPECT_EQ(earliest_probe.sent_time, coquic::quic::test::test_time(3));

    EXPECT_TRUE(recovery.collect_pmtu_probe_timeouts(coquic::quic::test::test_time(10)).empty());

    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.collect_pmtu_probe_timeouts(
                                                        coquic::quic::test::test_time(100))),
              (std::vector<std::uint64_t>{2, 3}));
}

TEST(QuicRecoveryTest, PmtuProbeDeadlineHelpersSkipDeclaredLostProbeSlots) {
    PacketSpaceRecovery recovery;

    auto declared_lost_probe = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                                coquic::quic::test::test_time(1));
    declared_lost_probe.is_pmtu_probe = true;
    recovery.on_packet_sent(declared_lost_probe);
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_state_declared_lost(recovery, 1);

    EXPECT_FALSE(recovery.earliest_pmtu_probe_packet().has_value());
}

TEST(QuicRecoveryTest, PmtuProbeDeadlineHelpersIgnoreCorruptLiveSlotHead) {
    PacketSpaceRecovery recovery;
    auto probe = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                  coquic::quic::test::test_time(1));
    probe.is_pmtu_probe = true;
    recovery.on_packet_sent(probe);
    ASSERT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_count(recovery), 2u);

    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_first_live_slot(recovery, 2);

    EXPECT_TRUE(recovery.collect_pmtu_probe_timeouts(coquic::quic::test::test_time(100)).empty());
    EXPECT_FALSE(recovery.earliest_pmtu_probe_packet().has_value());
}

TEST(QuicRecoveryTest, PmtuProbeDeadlineHelpersKeepExistingEarliestAgainstLaterCandidate) {
    PacketSpaceRecovery recovery;

    auto earlier_probe = make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                          coquic::quic::test::test_time(4));
    earlier_probe.is_pmtu_probe = true;
    recovery.on_packet_sent(earlier_probe);

    auto later_probe = make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                        coquic::quic::test::test_time(8));
    later_probe.is_pmtu_probe = true;
    recovery.on_packet_sent(later_probe);

    const auto earliest = recovery.earliest_pmtu_probe_packet();
    ASSERT_TRUE(earliest.has_value());
    EXPECT_EQ(optional_value_or_terminate(earliest).packet_number, 2u);
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

    auto stale_ack =
        recovery.on_ack_received(make_ack_frame(/*largest=*/2), coquic::quic::test::test_time(40));
    EXPECT_TRUE(stale_ack.acked_packets.empty());
    EXPECT_EQ(packet_numbers_from(stale_ack.lost_packets), (std::vector<std::uint64_t>{1}));
}

TEST(QuicRecoveryTest, TimeThresholdLossesSortMultipleExpiredCandidates) {
    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    for (std::uint64_t packet_number = 0; packet_number <= 3; ++packet_number) {
        recovery.on_packet_sent(make_sent_packet(packet_number, /*ack_eliciting=*/true,
                                                 coquic::quic::test::test_time(0)));
    }

    auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(40));

    EXPECT_EQ(packet_numbers_from(result.acked_packets), (std::vector<std::uint64_t>{3}));
    EXPECT_EQ(packet_numbers_from(result.lost_packets), (std::vector<std::uint64_t>{0, 1, 2}));
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

TEST(QuicRecoveryTest, LatestInflightAckElicitingPacketRefreshesStaleCache) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(5)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(9)));

    static_cast<void>(
        recovery.on_ack_received(make_ack_frame(/*largest=*/2), coquic::quic::test::test_time(20)));

    static_cast<void>(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::insert_in_flight_ack_eliciting_tracked(
            recovery, 2));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::in_flight_ack_eliciting_tracked_count(
            recovery),
        1u);

    const auto latest_in_flight = recovery.latest_in_flight_ack_eliciting_packet();
    ASSERT_TRUE(latest_in_flight.has_value());
    EXPECT_EQ(optional_value_or_terminate(latest_in_flight).packet_number, 1u);
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::in_flight_ack_eliciting_tracked_count(
            recovery),
        1u);
}

TEST(QuicRecoveryTest, RetiringLatestInflightAckElicitingPacketPromotesPreviousLivePacket) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(5)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(9)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/false,
                                             coquic::quic::test::test_time(11)));

    EXPECT_EQ(
        optional_value_or_terminate(recovery.latest_in_flight_ack_eliciting_packet()).packet_number,
        2u);

    const auto handle = recovery.handle_for_packet_number(2);
    ASSERT_TRUE(handle.has_value());
    auto retired = recovery.take_retired_packet_if_present(optional_value_or_terminate(handle));
    ASSERT_TRUE(retired.has_value());

    EXPECT_EQ(
        optional_value_or_terminate(recovery.latest_in_flight_ack_eliciting_packet()).packet_number,
        1u);
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::in_flight_ack_eliciting_tracked_count(
            recovery),
        1u);
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

    auto earliest_loss_after_declaring_packet_2_lost = recovery.earliest_loss_packet();
    ASSERT_TRUE(earliest_loss_after_declaring_packet_2_lost.has_value());
    EXPECT_EQ(
        optional_value_or_terminate(earliest_loss_after_declaring_packet_2_lost).packet_number, 1u);
}

TEST(QuicRecoveryTest, EarliestLossPacketPrunesStaleTrackedEntries) {
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

    static_cast<void>(
        recovery.on_ack_received(make_ack_frame(/*largest=*/3), coquic::quic::test::test_time(9)));
    recovery.on_packet_declared_lost(2);

    static_cast<void>(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::insert_eligible_loss_tracked(recovery, 2));
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::eligible_loss_tracked_count(recovery), 2u);

    const auto earliest_loss = recovery.earliest_loss_packet();
    ASSERT_TRUE(earliest_loss.has_value());
    EXPECT_EQ(optional_value_or_terminate(earliest_loss).packet_number, 1u);
    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::eligible_loss_tracked_count(recovery), 1u);
}

TEST(QuicRecoveryTest, AckProcessingResultSynthesizesMetadataForMissingHandles) {
    PacketSpaceRecovery recovery;
    AckApplyResult apply;
    apply.acked_packets.push_back(RecoveryPacketHandle{
        .packet_number = 7,
        .slot_index = 7,
    });
    apply.late_acked_packets.push_back(RecoveryPacketHandle{
        .packet_number = 8,
        .slot_index = 8,
    });
    apply.lost_packets.push_back(RecoveryPacketHandle{
        .packet_number = 9,
        .slot_index = 9,
    });
    apply.largest_newly_acked_packet = AckApplyLargestNewlyAckedPacket{
        .handle =
            {
                .packet_number = 10,
                .slot_index = 10,
            },
        .packet_number = 10,
        .sent_time = coquic::quic::test::test_time(33),
    };

    auto result = coquic::quic::test::PacketSpaceRecoveryTestPeer::ack_processing_result_from_apply(
        recovery, apply);

    ASSERT_EQ(result.acked_packets.size(), 1u);
    EXPECT_EQ(result.acked_packets.front().packet_number, 7u);
    ASSERT_EQ(result.late_acked_packets.size(), 1u);
    EXPECT_EQ(result.late_acked_packets.front().packet_number, 8u);
    ASSERT_EQ(result.lost_packets.size(), 1u);
    EXPECT_EQ(result.lost_packets.front().packet_number, 9u);
    EXPECT_FALSE(result.lost_packets.front().in_flight);
    EXPECT_TRUE(result.lost_packets.front().declared_lost);
    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    EXPECT_EQ(result.largest_newly_acked_packet->packet_number, 10u);
    EXPECT_EQ(result.largest_newly_acked_packet->sent_time, coquic::quic::test::test_time(33));
    EXPECT_FALSE(result.largest_newly_acked_packet->ack_eliciting);
    EXPECT_FALSE(result.largest_newly_acked_packet->in_flight);
    EXPECT_FALSE(result.largest_newly_acked_packet->declared_lost);
}

TEST(QuicRecoveryTest, TrackedPacketValidationHelpersRejectAcknowledgedAndNonEligiblePackets) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(5)));

    const auto tracked = DeadlineTrackedPacket{
        .packet_number = 0,
        .sent_time = coquic::quic::test::test_time(5),
    };
    EXPECT_TRUE(coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_for_tracked_packet_exists(
        recovery, tracked));
    EXPECT_TRUE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_in_flight_ack_eliciting_tracked(
            recovery, tracked));
    EXPECT_TRUE(coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_eligible_loss_tracked(
        recovery, tracked));

    EXPECT_FALSE(coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_for_tracked_packet_exists(
        recovery, DeadlineTrackedPacket{
                      .packet_number = 0,
                      .sent_time = coquic::quic::test::test_time(6),
                  }));

    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_acknowledged(recovery, 0, true);
    EXPECT_FALSE(coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_for_tracked_packet_exists(
        recovery, tracked));

    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_acknowledged(recovery, 0, false);
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_state_declared_lost(recovery, 0);
    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_in_flight_ack_eliciting_tracked(
            recovery, tracked));
    EXPECT_FALSE(coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_eligible_loss_tracked(
        recovery, tracked));

    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_state_sent(recovery, 0);
    coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_packet_at(recovery, 0).ack_eliciting =
        false;
    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_in_flight_ack_eliciting_tracked(
            recovery, tracked));

    coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_packet_at(recovery, 0).ack_eliciting =
        true;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_packet_at(recovery, 0).in_flight = false;
    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_in_flight_ack_eliciting_tracked(
            recovery, tracked));
    EXPECT_FALSE(coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_eligible_loss_tracked(
        recovery, tracked));

    coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_packet_at(recovery, 0).in_flight = true;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_packet_at(recovery, 0).declared_lost =
        true;
    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_in_flight_ack_eliciting_tracked(
            recovery, tracked));
    EXPECT_FALSE(coquic::quic::test::PacketSpaceRecoveryTestPeer::is_valid_eligible_loss_tracked(
        recovery, tracked));
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

    auto result =
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

    auto result =
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

    auto result =
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

    auto result = recovery.on_ack_received(ack_ranges, /*largest_acknowledged=*/2,
                                           coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets.handles()),
              (std::vector<std::uint64_t>{2}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{1}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()),
              (std::vector<std::uint64_t>{0}));
    auto oldest = recovery.oldest_tracked_packet();
    ASSERT_TRUE(oldest.has_value());
    auto newest = recovery.newest_tracked_packet();
    ASSERT_TRUE(newest.has_value());
    if (!oldest.has_value() || !newest.has_value()) {
        return;
    }
    EXPECT_EQ(oldest.value().packet_number, 0u);
    EXPECT_EQ(newest.value().packet_number, 0u);
}

TEST(QuicRecoveryTest, AckProcessingHidesAcknowledgedPacketsFromCompatibilitySentPacketsView) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(4)));

    auto result =
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

    auto result = recovery.on_ack_received(ack_ranges, /*largest_acknowledged=*/5,
                                           coquic::quic::test::test_time(10));

    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets.handles()),
              (std::vector<std::uint64_t>{5}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{3}));
    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    EXPECT_EQ(result.largest_newly_acked_packet->packet_number, 5u);
}

TEST(QuicRecoveryTest, AckProcessingMaintainsTrackedPacketLinksAfterContiguousMixedRangeAck) {
    PacketSpaceRecovery recovery;
    for (std::uint64_t packet_number = 0; packet_number != 7; ++packet_number) {
        recovery.on_packet_sent(make_sent_packet(
            packet_number, /*ack_eliciting=*/true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number))));
    }
    recovery.on_packet_declared_lost(4);

    auto result = recovery.on_ack_received(
        AckFrame{
            .largest_acknowledged = 5,
            .first_ack_range = 2,
        },
        coquic::quic::test::test_time(20));

    EXPECT_EQ(packet_numbers_from_handles(recovery, result.acked_packets.handles()),
              (std::vector<std::uint64_t>{3, 5}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, result.late_acked_packets.handles()),
              (std::vector<std::uint64_t>{4}));
    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()),
              (std::vector<std::uint64_t>{0, 1, 2, 6}));

    auto oldest = recovery.oldest_tracked_packet();
    if (!oldest.has_value()) {
        ADD_FAILURE() << "missing oldest tracked packet";
        return;
    }
    EXPECT_EQ(oldest->packet_number, 0u);

    auto newest = recovery.newest_tracked_packet();
    if (!newest.has_value()) {
        ADD_FAILURE() << "missing newest tracked packet";
        return;
    }
    EXPECT_EQ(newest->packet_number, 6u);
}

TEST(QuicRecoveryTest, CopyMoveAndMetadataHelpersPreserveRecoveryState) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(10)));

    SentPacketRecord declared_lost = make_sent_packet(/*packet_number=*/4, /*ack_eliciting=*/true,
                                                      coquic::quic::test::test_time(20));
    declared_lost.declared_lost = true;
    declared_lost.in_flight = false;
    recovery.on_packet_sent(declared_lost);

    const auto tracked_before = packet_numbers_from_handles(recovery, recovery.tracked_packets());

    PacketSpaceRecovery copied(recovery);
    EXPECT_EQ(packet_numbers_from_handles(copied, copied.tracked_packets()), tracked_before);

    const auto copied_handle = copied.handle_for_packet_number(1);
    if (!copied_handle.has_value()) {
        FAIL() << "expected copied recovery handle";
        return;
    }
    const auto copied_metadata = coquic::quic::resolved_packet_metadata(&copied, *copied_handle);
    EXPECT_EQ(copied_metadata.packet_number, 1u);
    EXPECT_EQ(copied_metadata.sent_time, coquic::quic::test::test_time(10));
    EXPECT_TRUE(copied_metadata.ack_eliciting);
    EXPECT_TRUE(copied_metadata.in_flight);
    EXPECT_FALSE(copied_metadata.declared_lost);

    auto missing_metadata = coquic::quic::resolved_packet_metadata(
        &copied, RecoveryPacketHandle{.packet_number = 99, .slot_index = 99});
    EXPECT_EQ(missing_metadata.packet_number, 99u);
    EXPECT_EQ(missing_metadata.sent_time, coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(missing_metadata.ack_eliciting);
    EXPECT_FALSE(missing_metadata.in_flight);
    EXPECT_FALSE(missing_metadata.declared_lost);

    auto null_metadata = coquic::quic::resolved_packet_metadata(
        nullptr, RecoveryPacketHandle{.packet_number = 7, .slot_index = 0});
    EXPECT_EQ(null_metadata.packet_number, 7u);
    EXPECT_EQ(null_metadata.sent_time, coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(null_metadata.ack_eliciting);
    EXPECT_FALSE(null_metadata.in_flight);
    EXPECT_FALSE(null_metadata.declared_lost);

    PacketSpaceRecovery moved(std::move(copied));
    EXPECT_EQ(packet_numbers_from_handles(moved, moved.tracked_packets()), tracked_before);

    auto &same_recovery = recovery;
    recovery = same_recovery;
    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()), tracked_before);

    recovery = std::move(recovery);
    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()), tracked_before);
}

TEST(QuicRecoveryTest, HandleContainersSupportBackPostfixAndOptionalErrors) {
    RecoveryPacketHandleList handles;
    handles.reserve(2);
    handles.push_back(RecoveryPacketHandle{.packet_number = 3, .slot_index = 0},
                      RecoveryPacketMetadata{
                          .packet_number = 3,
                          .sent_time = coquic::quic::test::test_time(3),
                          .ack_eliciting = true,
                          .in_flight = true,
                      });
    handles.push_back(RecoveryPacketHandle{.packet_number = 7, .slot_index = 1},
                      RecoveryPacketMetadata{
                          .packet_number = 7,
                          .sent_time = coquic::quic::test::test_time(7),
                          .declared_lost = true,
                      });

    auto it = handles.begin();
    const auto first = *it++;
    ASSERT_NE(it, handles.end());
    const auto second = *it;
    EXPECT_EQ(first.packet_number, 3u);
    EXPECT_EQ(second.packet_number, 7u);
    EXPECT_EQ(handles.front().packet_number, 3u);
    EXPECT_EQ(handles.back().packet_number, 7u);

    RecoveryPacketHandleOptional maybe_handle;
    EXPECT_FALSE(maybe_handle.has_value());
    EXPECT_THROW(static_cast<void>(maybe_handle.value()), std::bad_optional_access);
    EXPECT_THROW(static_cast<void>(maybe_handle.operator->()), std::bad_optional_access);

    maybe_handle.emplace(RecoveryPacketHandle{.packet_number = 7, .slot_index = 1}, handles.back());
    EXPECT_TRUE(maybe_handle.has_value());
    EXPECT_EQ(maybe_handle.value().packet_number, 7u);
    EXPECT_EQ(maybe_handle->packet_number, 7u);
}

TEST(QuicRecoveryTest, SmallHandleListAccessorsExposeInlineAndHeapStorage) {
    AckApplyResult result;
    for (std::uint64_t packet_number = 0; packet_number != 6; ++packet_number) {
        result.acked_packets.push_back(RecoveryPacketHandle{
            .packet_number = packet_number,
            .slot_index = static_cast<std::size_t>(packet_number),
        });
    }

    ASSERT_FALSE(result.acked_packets.empty());
    EXPECT_EQ(result.acked_packets.front().packet_number, 0u);
    ASSERT_EQ(result.acked_packets.handles().size(), 6u);
    EXPECT_EQ(result.acked_packets.handles()[5].packet_number, 5u);
}

TEST(QuicRecoveryTest, SentPacketsViewHandlesDetachedAndAcknowledgedPackets) {
    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::detached_sent_packets_contains(9));
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::detached_sent_packets_size(), 0u);
    EXPECT_THROW(coquic::quic::test::PacketSpaceRecoveryTestPeer::detached_sent_packets_at(9),
                 std::out_of_range);

    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    SentPacketRecord declared_lost = make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                                      coquic::quic::test::test_time(1));
    declared_lost.declared_lost = true;
    declared_lost.in_flight = false;
    recovery.on_packet_sent(declared_lost);

    EXPECT_TRUE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_contains(recovery, 0));
    EXPECT_TRUE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_contains(recovery, 1));
    EXPECT_TRUE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::outstanding_slot_exists(recovery, 1));
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_size(recovery), 2u);

    static_cast<void>(
        recovery.on_ack_received(make_ack_frame(/*largest=*/0), coquic::quic::test::test_time(10)));

    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_contains(recovery, 0));
    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::outstanding_slot_exists(recovery, 0));
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_size(recovery), 1u);
}

TEST(QuicRecoveryTest, SentPacketsViewReturnsTrackedPacketsAndSkipsRetiredSlots) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));

    EXPECT_EQ(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_at(recovery, 0).packet_number,
        0u);

    recovery.retire_packet(0);

    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_size(recovery), 1u);
    EXPECT_TRUE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_contains(recovery, 1));
}

TEST(QuicRecoveryTest, PacketLookupHelpersHandleUnknownAndMismatchedSlots) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));

    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::outstanding_slot_exists(recovery, 99));

    const auto *resolved =
        recovery.packet_for_handle(RecoveryPacketHandle{.packet_number = 1, .slot_index = 2});
    ASSERT_NE(resolved, nullptr);
    EXPECT_EQ(resolved->packet_number, 1u);

    const PacketSpaceRecovery &const_recovery = recovery;
    const auto *fallback_resolved =
        const_recovery.packet_for_handle(RecoveryPacketHandle{.packet_number = 1, .slot_index = 0});
    ASSERT_NE(fallback_resolved, nullptr);
    EXPECT_EQ(fallback_resolved->packet_number, 1u);
    EXPECT_EQ(const_recovery.packet_for_handle(
                  RecoveryPacketHandle{.packet_number = 99, .slot_index = 0}),
              nullptr);

    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_packet_number(
        recovery, {.slot_index = 1, .packet_number = 9});
    EXPECT_FALSE(coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_exists(recovery, 1));
    EXPECT_FALSE(recovery.handle_for_packet_number(1).has_value());
    EXPECT_EQ(recovery.find_packet(1), nullptr);

    PacketSpaceRecovery mismatched_handle;
    mismatched_handle.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                                      coquic::quic::test::test_time(2)));
    auto mismatched = mismatched_handle.handle_for_packet_number(2);
    ASSERT_TRUE(mismatched.has_value());
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_packet_number(
        mismatched_handle, {.slot_index = 2, .packet_number = 9});
    EXPECT_FALSE(
        mismatched_handle.retire_packet_if_present(optional_value_or_terminate(mismatched)));

    PacketSpaceRecovery lost_handle;
    lost_handle.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                                coquic::quic::test::test_time(2)));
    auto lost = lost_handle.handle_for_packet_number(2);
    ASSERT_TRUE(lost.has_value());
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_state_declared_lost(lost_handle, 2);
    EXPECT_TRUE(lost_handle.retire_packet_if_present(optional_value_or_terminate(lost)));

    PacketSpaceRecovery mismatched_take;
    mismatched_take.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                                    coquic::quic::test::test_time(2)));
    auto mismatched_take_handle = mismatched_take.handle_for_packet_number(2);
    ASSERT_TRUE(mismatched_take_handle.has_value());
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_packet_number(
        mismatched_take, {.slot_index = 2, .packet_number = 9});
    EXPECT_FALSE(
        mismatched_take
            .take_retired_packet_if_present(optional_value_or_terminate(mismatched_take_handle))
            .has_value());
}

TEST(QuicRecoveryTest, RetireAndTakeRetiredPacketHelpersCoverHandleEdges) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(3)));

    const auto handles = recovery.tracked_packets();
    ASSERT_EQ(handles.size(), 2u);

    EXPECT_FALSE(recovery.retire_packet_if_present(RecoveryPacketHandle{
        .packet_number = 99,
        .slot_index = 99,
    }));
    EXPECT_TRUE(recovery.retire_packet_if_present(handles.front()));
    EXPECT_FALSE(recovery.retire_packet_if_present(handles.front()));

    const auto taken = recovery.take_retired_packet(handles.back());
    ASSERT_TRUE(taken.has_value());
    const auto taken_value = optional_value_or_terminate(taken);
    EXPECT_EQ(taken_value.packet_number, 3u);

    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/7, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(7)));
    const auto retired_packet_handle = recovery.handle_for_packet_number(7);
    if (!retired_packet_handle.has_value()) {
        FAIL() << "recovery did not return a handle for packet 7";
    }
    auto handle_value = optional_value_or_terminate(retired_packet_handle);
    const auto moved = recovery.take_retired_packet_if_present(handle_value);
    ASSERT_TRUE(moved.has_value());
    auto moved_value = optional_value_or_terminate(moved);
    EXPECT_EQ(moved_value.packet_number, 7u);
    EXPECT_FALSE(recovery.take_retired_packet_if_present(handle_value).has_value());
    EXPECT_FALSE(recovery
                     .take_retired_packet(RecoveryPacketHandle{
                         .packet_number = 123,
                         .slot_index = 0,
                     })
                     .has_value());

    PacketSpaceRecovery already_acknowledged_take;
    already_acknowledged_take.on_packet_sent(make_sent_packet(/*packet_number=*/0,
                                                              /*ack_eliciting=*/true,
                                                              coquic::quic::test::test_time(0)));
    auto acknowledged_handle = already_acknowledged_take.handle_for_packet_number(0);
    ASSERT_TRUE(acknowledged_handle.has_value());
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_acknowledged(
        already_acknowledged_take, 0, true);
    auto already_acknowledged_packet = already_acknowledged_take.take_retired_packet(
        optional_value_or_terminate(acknowledged_handle));
    ASSERT_TRUE(already_acknowledged_packet.has_value());
    auto already_acknowledged_packet_value =
        optional_value_or_terminate(already_acknowledged_packet);
    EXPECT_EQ(already_acknowledged_packet_value.packet_number, 0u);
}

TEST(QuicRecoveryTest, LossCandidateHelpersSkipDeclaredLostPacketsAndAcknowledgedSlots) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_largest_acked_packet_number(recovery, 5);
    auto &slot_packet =
        coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_packet_at(recovery, 0);
    slot_packet.in_flight = true;
    slot_packet.declared_lost = true;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::maybe_track_as_loss_candidate(recovery,
                                                                                   slot_packet);
    EXPECT_FALSE(recovery.earliest_loss_packet().has_value());

    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_next_loss_candidate_slot(
        recovery, coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_count(recovery));
    coquic::quic::test::PacketSpaceRecoveryTestPeer::track_new_loss_candidates(recovery,
                                                                               std::nullopt, 5);
    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::next_loss_candidate_slot(recovery),
              coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_count(recovery));

    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_next_loss_candidate_slot(recovery, 0);
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_acknowledged(recovery, 0, true);
    coquic::quic::test::PacketSpaceRecoveryTestPeer::track_new_loss_candidates(recovery, 0u, 5);
    EXPECT_FALSE(recovery.earliest_loss_packet().has_value());
}

TEST(QuicRecoveryTest, TrackNewLossCandidatesReturnsWhenNextCandidateSlotIsPastEnd) {
    PacketSpaceRecovery empty_recovery;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::track_new_loss_candidates(empty_recovery,
                                                                               std::nullopt, 5);
    EXPECT_FALSE(empty_recovery.earliest_loss_packet().has_value());

    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    const auto past_end = coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_count(recovery) + 1;
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_next_loss_candidate_slot(recovery,
                                                                                  past_end);
    coquic::quic::test::PacketSpaceRecoveryTestPeer::track_new_loss_candidates(recovery,
                                                                               std::nullopt, 5);

    EXPECT_EQ(coquic::quic::test::PacketSpaceRecoveryTestPeer::next_loss_candidate_slot(recovery),
              past_end);
    EXPECT_FALSE(recovery.earliest_loss_packet().has_value());
}

TEST(QuicRecoveryTest,
     TimeThresholdLossCollectionHandlesEmptyStateNonInflightAndNotYetLostPackets) {
    PacketSpaceRecovery empty_recovery;
    static_cast<void>(empty_recovery.on_ack_received(make_ack_frame(/*largest=*/0),
                                                     coquic::quic::test::test_time(0)));
    EXPECT_TRUE(
        empty_recovery.collect_time_threshold_losses(coquic::quic::test::test_time(1)).empty());

    PacketSpaceRecovery recovery;
    recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/false,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    static_cast<void>(
        recovery.on_ack_received(make_ack_frame(/*largest=*/2), coquic::quic::test::test_time(1)));

    EXPECT_TRUE(recovery.collect_time_threshold_losses(coquic::quic::test::test_time(11)).empty());
}

TEST(QuicRecoveryTest, OnPacketSentReusesAcknowledgedAndDeclaredLostSlots) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    static_cast<void>(
        recovery.on_ack_received(make_ack_frame(/*largest=*/0), coquic::quic::test::test_time(1)));

    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));
    EXPECT_TRUE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::sent_packets_contains(recovery, 0));

    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(3)));
    recovery.on_packet_declared_lost(1);
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(4)));

    const auto *packet = recovery.find_packet(1);
    ASSERT_NE(packet, nullptr);
    EXPECT_FALSE(packet->declared_lost);
    EXPECT_TRUE(packet->in_flight);
}

TEST(QuicRecoveryTest, AckProcessingTracksLargestPacketAcrossOutOfOrderLiveSlotsAndNoOpAcks) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(3)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/2, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(2)));

    EXPECT_EQ(packet_numbers_from_handles(recovery, recovery.tracked_packets()),
              (std::vector<std::uint64_t>{1, 2, 3}));

    auto result = recovery.on_ack_received(make_ack_frame(/*largest=*/3, /*first_ack_range=*/2),
                                           coquic::quic::test::test_time(10));

    ASSERT_TRUE(result.largest_newly_acked_packet.has_value());
    EXPECT_EQ(result.largest_newly_acked_packet->packet_number, 3u);
    EXPECT_EQ(result.acked_packets.size(), 3u);

    PacketSpaceRecovery no_op_recovery;
    no_op_recovery.on_packet_sent(make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true,
                                                   coquic::quic::test::test_time(10)));
    auto version_before = no_op_recovery.compatibility_version();

    auto no_op_result = no_op_recovery.on_ack_received(make_ack_frame(/*largest=*/5),
                                                       coquic::quic::test::test_time(11));

    EXPECT_TRUE(no_op_result.acked_packets.empty());
    EXPECT_TRUE(no_op_result.late_acked_packets.empty());
    EXPECT_TRUE(no_op_result.lost_packets.empty());
    EXPECT_EQ(no_op_recovery.compatibility_version(), version_before);
}

TEST(QuicRecoveryTest, DirectRecoveryColdBranchEdgesUsePeerHooks) {
    using Peer = coquic::quic::test::PacketSpaceRecoveryTestPeer;

    PacketSpaceRecovery empty;
    Peer::clear_live_slot_bit(empty, 64);

    PacketSpaceRecovery ackable;
    ackable.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                            coquic::quic::test::test_time(0)));
    const auto ack = make_ack_frame(/*largest=*/1);
    auto cursor = coquic::quic::make_ack_range_cursor(ack);
    ASSERT_TRUE(cursor.has_value());
    EXPECT_FALSE(
        Peer::ack_ranges_include_newly_ackable_ack_eliciting_packet(ackable, cursor.value()));

    PacketSpaceRecovery packet_number_above_range;
    packet_number_above_range.on_packet_sent(make_sent_packet(/*packet_number=*/0,
                                                              /*ack_eliciting=*/true,
                                                              coquic::quic::test::test_time(0)));
    Peer::set_slot_packet_number(packet_number_above_range, {.slot_index = 0, .packet_number = 2});
    const auto low_ack = make_ack_frame(/*largest=*/0);
    auto low_cursor = coquic::quic::make_ack_range_cursor(low_ack);
    ASSERT_TRUE(low_cursor.has_value());
    EXPECT_FALSE(Peer::ack_ranges_include_newly_ackable_ack_eliciting_packet(
        packet_number_above_range, low_cursor.value()));

    PacketSpaceRecovery state_edges;
    state_edges.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                                coquic::quic::test::test_time(0)));
    Peer::set_slot_state_retired(state_edges, 0);
    auto state_ack = make_ack_frame(/*largest=*/0);
    auto state_cursor = coquic::quic::make_ack_range_cursor(state_ack);
    ASSERT_TRUE(state_cursor.has_value());
    EXPECT_FALSE(Peer::ack_ranges_include_newly_ackable_ack_eliciting_packet(state_edges,
                                                                             state_cursor.value()));

    PacketSpaceRecovery acknowledged_edges;
    acknowledged_edges.on_packet_sent(make_sent_packet(/*packet_number=*/0,
                                                       /*ack_eliciting=*/true,
                                                       coquic::quic::test::test_time(0)));
    Peer::set_slot_acknowledged(acknowledged_edges, 0, true);
    auto acked_ack = make_ack_frame(/*largest=*/0);
    auto acked_cursor = coquic::quic::make_ack_range_cursor(acked_ack);
    ASSERT_TRUE(acked_cursor.has_value());
    EXPECT_FALSE(Peer::ack_ranges_include_newly_ackable_ack_eliciting_packet(acknowledged_edges,
                                                                             acked_cursor.value()));

    PacketSpaceRecovery no_pending_range;
    no_pending_range.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                                     coquic::quic::test::test_time(0)));
    auto no_pending_ack = make_ack_frame(/*largest=*/0);
    auto no_pending_cursor = coquic::quic::make_ack_range_cursor(no_pending_ack);
    ASSERT_TRUE(no_pending_cursor.has_value());
    auto no_pending_cursor_value = no_pending_cursor.value();
    no_pending_cursor_value.first_range_pending = false;
    no_pending_cursor_value.next_additional_index =
        no_pending_cursor_value.additional_ranges.size();
    auto result = Peer::apply_ack_received(no_pending_range, no_pending_cursor_value, 0,
                                           coquic::quic::test::test_time(1));
    EXPECT_TRUE(result.acked_packets.empty());
}

TEST(QuicRecoveryTest,
     RebuildAuxiliaryIndexesSkipsAcknowledgedSlotsAndNonInflightAckElicitingPackets) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    recovery.on_packet_declared_lost(1);
    static_cast<void>(
        recovery.on_ack_received(make_ack_frame(/*largest=*/0), coquic::quic::test::test_time(2)));

    recovery.rebuild_auxiliary_indexes();

    EXPECT_FALSE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::outstanding_slot_exists(recovery, 0));
    EXPECT_TRUE(
        coquic::quic::test::PacketSpaceRecoveryTestPeer::outstanding_slot_exists(recovery, 1));
    EXPECT_FALSE(recovery.latest_in_flight_ack_eliciting_packet().has_value());
}

TEST(QuicRecoveryTest, RebuildAuxiliaryIndexesSkipsSentSlotsMarkedDeclaredLost) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));

    auto &packet = coquic::quic::test::PacketSpaceRecoveryTestPeer::slot_packet_at(recovery, 0);
    packet.declared_lost = true;
    packet.in_flight = true;

    recovery.rebuild_auxiliary_indexes();

    EXPECT_FALSE(recovery.latest_in_flight_ack_eliciting_packet().has_value());
}

TEST(QuicRecoveryTest, AckProcessingSkipsLiveSlotsWithUnexpectedRetiredState) {
    PacketSpaceRecovery recovery;
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/1, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(1)));
    coquic::quic::test::PacketSpaceRecoveryTestPeer::set_slot_state_retired(recovery, 1);

    auto version_before = recovery.compatibility_version();
    auto result =
        recovery.on_ack_received(make_ack_frame(/*largest=*/1), coquic::quic::test::test_time(2));

    EXPECT_TRUE(result.acked_packets.empty());
    EXPECT_TRUE(result.late_acked_packets.empty());
    EXPECT_TRUE(result.lost_packets.empty());
    EXPECT_EQ(recovery.compatibility_version(), version_before);
}

TEST(QuicRecoveryTest, EmptyAndUnknownRecoveryLookupsReturnWithoutStateChanges) {
    PacketSpaceRecovery recovery;

    EXPECT_FALSE(recovery.handle_for_packet_number(42).has_value());
    EXPECT_EQ(
        recovery.packet_for_handle(RecoveryPacketHandle{.packet_number = 42, .slot_index = 0}),
        nullptr);
    EXPECT_EQ(recovery.find_packet(42), nullptr);
    EXPECT_FALSE(recovery.oldest_tracked_packet().has_value());
    EXPECT_FALSE(recovery.newest_tracked_packet().has_value());
    EXPECT_TRUE(recovery.collect_time_threshold_losses(coquic::quic::test::test_time(5)).empty());

    auto version_before = recovery.compatibility_version();
    recovery.on_packet_declared_lost(42);
    recovery.retire_packet(RecoveryPacketHandle{.packet_number = 42, .slot_index = 0});
    recovery.retire_packet(42);
    EXPECT_EQ(recovery.compatibility_version(), version_before);

    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/0, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(0)));
    recovery.on_packet_sent(make_sent_packet(/*packet_number=*/3, /*ack_eliciting=*/true,
                                             coquic::quic::test::test_time(100)));

    static_cast<void>(recovery.on_ack_received(make_ack_frame(/*largest=*/3),
                                               coquic::quic::test::test_time(101)));
    EXPECT_TRUE(recovery.collect_time_threshold_losses(coquic::quic::test::test_time(101)).empty());
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
    EXPECT_FALSE(rtt.latest_adjusted_rtt.has_value());
    EXPECT_EQ(*rtt.min_rtt, std::chrono::milliseconds(60));
    EXPECT_EQ(rtt.latest_rtt_sample, std::optional{std::chrono::microseconds(60000)});
    EXPECT_FALSE(rtt.latest_adjusted_rtt_sample.has_value());
    EXPECT_FALSE(rtt.latest_ack_delay_compensated_rtt_sample.has_value());
    EXPECT_EQ(rtt.min_rtt_sample, std::optional{std::chrono::microseconds(60000)});
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
    EXPECT_EQ(rtt.latest_adjusted_rtt, std::optional{std::chrono::milliseconds(35)});
    EXPECT_EQ(rtt.latest_rtt_sample, std::optional{std::chrono::microseconds(35000)});
    EXPECT_EQ(rtt.latest_adjusted_rtt_sample, std::optional{std::chrono::microseconds(35000)});
    EXPECT_EQ(rtt.latest_ack_delay_compensated_rtt_sample,
              std::optional{std::chrono::microseconds(15000)});
    EXPECT_EQ(rtt.min_rtt_sample, std::optional{std::chrono::microseconds(30000)});
    EXPECT_EQ(rtt.smoothed_rtt, std::chrono::microseconds(39375));
}

TEST(QuicRecoveryTest, SubsequentRttSamplesExposeMicrosecondAdjustedSample) {
    RecoveryRttState rtt;
    rtt.latest_rtt = std::chrono::milliseconds(100);
    rtt.smoothed_rtt = std::chrono::milliseconds(100);
    rtt.rttvar = std::chrono::milliseconds(50);
    rtt.min_rtt = std::chrono::milliseconds(100);
    rtt.min_rtt_sample = std::chrono::microseconds(100200);
    auto sent = make_sent_packet(/*packet_number=*/9, /*ack_eliciting=*/true,
                                 QuicCoreTimePoint{} + std::chrono::microseconds(100));

    coquic::quic::update_rtt(rtt, QuicCoreTimePoint{} + std::chrono::microseconds(105800), sent,
                             /*ack_delay=*/std::chrono::milliseconds(5),
                             /*max_ack_delay=*/std::chrono::milliseconds(25));

    EXPECT_EQ(rtt.latest_rtt, std::optional{std::chrono::microseconds(105700)});
    EXPECT_EQ(rtt.latest_adjusted_rtt, std::optional{std::chrono::microseconds(100700)});
    EXPECT_EQ(rtt.latest_rtt_sample, std::optional{std::chrono::microseconds(105700)});
    EXPECT_EQ(rtt.latest_adjusted_rtt_sample, std::optional{std::chrono::microseconds(100700)});
    EXPECT_EQ(rtt.latest_ack_delay_compensated_rtt_sample,
              std::optional{std::chrono::microseconds(100700)});
    EXPECT_EQ(rtt.min_rtt_sample, std::optional{std::chrono::microseconds(100200)});
    EXPECT_EQ(rtt.smoothed_rtt, std::chrono::microseconds(100087));
}

TEST(QuicRecoveryTest, SubsequentRttSamplesUseSubmillisecondAckDelayForAdjustedSample) {
    RecoveryRttState rtt;
    rtt.latest_rtt = std::chrono::milliseconds(100);
    rtt.smoothed_rtt = std::chrono::milliseconds(100);
    rtt.rttvar = std::chrono::milliseconds(50);
    rtt.min_rtt = std::chrono::milliseconds(100);
    rtt.min_rtt_sample = std::chrono::microseconds(100000);
    auto sent = make_sent_packet(/*packet_number=*/11, /*ack_eliciting=*/true,
                                 QuicCoreTimePoint{} + std::chrono::microseconds(100));

    coquic::quic::update_rtt(rtt, QuicCoreTimePoint{} + std::chrono::microseconds(101300), sent,
                             /*ack_delay=*/std::chrono::microseconds(800),
                             /*max_ack_delay=*/std::chrono::milliseconds(25));

    EXPECT_EQ(rtt.latest_rtt, std::optional{std::chrono::microseconds(101200)});
    EXPECT_EQ(rtt.latest_adjusted_rtt, std::optional{std::chrono::microseconds(100400)});
    EXPECT_EQ(rtt.latest_rtt_sample, std::optional{std::chrono::microseconds(101200)});
    EXPECT_EQ(rtt.latest_adjusted_rtt_sample, std::optional{std::chrono::microseconds(100400)});
    EXPECT_EQ(rtt.latest_ack_delay_compensated_rtt_sample,
              std::optional{std::chrono::microseconds(100400)});
    EXPECT_EQ(rtt.min_rtt_sample, std::optional{std::chrono::microseconds(100000)});
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
    EXPECT_EQ(rtt.latest_adjusted_rtt, std::optional{std::chrono::milliseconds(50)});
    EXPECT_EQ(rtt.latest_rtt_sample, std::optional{std::chrono::microseconds(50000)});
    EXPECT_EQ(rtt.latest_adjusted_rtt_sample, std::optional{std::chrono::microseconds(50000)});
    EXPECT_EQ(rtt.latest_ack_delay_compensated_rtt_sample,
              std::optional{std::chrono::microseconds(45000)});
    EXPECT_EQ(rtt.min_rtt_sample, std::optional{std::chrono::microseconds(50000)});
    EXPECT_EQ(rtt.smoothed_rtt, std::chrono::microseconds(41250));
}

TEST(QuicRecoveryTest, SubsequentRttSampleCanUpdateWithoutMinRttSample) {
    RecoveryRttState rtt;
    rtt.latest_rtt = std::chrono::milliseconds(40);
    rtt.smoothed_rtt = std::chrono::milliseconds(40);
    rtt.rttvar = std::chrono::milliseconds(20);
    rtt.min_rtt = std::chrono::milliseconds(30);
    const auto sent = make_sent_packet(/*packet_number=*/10, /*ack_eliciting=*/true,
                                       coquic::quic::test::test_time(10));

    coquic::quic::update_rtt(rtt, coquic::quic::test::test_time(50), sent,
                             /*ack_delay=*/std::chrono::milliseconds(5),
                             /*max_ack_delay=*/std::chrono::milliseconds(25));

    EXPECT_EQ(rtt.latest_rtt, std::optional{std::chrono::milliseconds(40)});
    EXPECT_EQ(rtt.latest_adjusted_rtt, std::optional{std::chrono::milliseconds(35)});
    EXPECT_EQ(rtt.latest_adjusted_rtt_sample, std::optional{std::chrono::microseconds(35000)});
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
