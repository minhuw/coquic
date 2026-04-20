#include <limits>
#include <memory>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#define private public
#include "src/quic/crypto_stream.h"
#undef private

namespace {

using coquic::quic::CryptoReceiveBuffer;
using coquic::quic::CryptoSendBuffer;
using coquic::quic::ReliableReceiveBuffer;
using coquic::quic::ReliableSendBuffer;
using coquic::quic::SharedBytes;

std::vector<std::byte> bytes_from_string(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const char ch : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return bytes;
}

constexpr std::size_t send_buffer_state_index(ReliableSendBuffer::SegmentState state) {
    return static_cast<std::size_t>(state);
}

TEST(QuicCryptoStreamTest, SendBufferSegmentStateCountsTrackTransitions) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcd"));

    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        0u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)],
        0u);

    const auto initial = buffer.take_ranges(2);
    ASSERT_EQ(initial.size(), 1u);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        1u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)],
        0u);

    buffer.mark_lost(0, 2);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        0u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)],
        1u);

    buffer.mark_sent(0, 2);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        1u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)],
        0u);

    buffer.acknowledge(0, 2);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        0u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)],
        0u);

    buffer.acknowledge(2, 2);
    EXPECT_TRUE(buffer.segments_.empty());
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              0u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        0u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)],
        0u);
}

bool crypto_stream_internal_coverage_for_tests();

bool crypto_stream_internal_coverage_for_tests() {
    ReliableReceiveBuffer receive_buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    receive_buffer.buffered_bytes_.emplace(0, SharedBytes(storage, 0, 2));
    receive_buffer.buffered_bytes_.emplace(2, SharedBytes(storage, 2, 4));

    const auto contiguous = receive_buffer.take_contiguous_buffered_bytes({});
    if (contiguous.owned.size() != 0 || contiguous.shared.storage().get() != storage.get() ||
        contiguous.shared.begin_offset() != 0 || contiguous.shared.end_offset() != 4 ||
        contiguous.to_vector() != bytes_from_string("abcd") ||
        !receive_buffer.buffered_bytes_.empty() || receive_buffer.next_contiguous_offset_ != 4) {
        return false;
    }

    ReliableReceiveBuffer gapped_receive_buffer;
    gapped_receive_buffer.buffered_bytes_.emplace(0, SharedBytes(storage, 0, 2));
    gapped_receive_buffer.buffered_bytes_.emplace(2, SharedBytes(storage, 3, 4));
    const auto gapped = gapped_receive_buffer.take_contiguous_buffered_bytes({});
    if (!gapped.shared.empty() || gapped.owned != bytes_from_string("abd") ||
        !gapped_receive_buffer.buffered_bytes_.empty() ||
        gapped_receive_buffer.next_contiguous_offset_ != 3) {
        return false;
    }

    ReliableSendBuffer send_buffer;
    send_buffer.append(SharedBytes{});
    return send_buffer.segments_.empty() && send_buffer.next_append_offset_ == 0;
}

TEST(QuicCryptoStreamTest, SendBufferProducesIncreasingOffsets) {
    CryptoSendBuffer buffer;
    buffer.append(std::vector<std::byte>{
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
        std::byte{0x04},
    });

    const auto frames = buffer.take_frames(3);
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0].offset, 0u);
    EXPECT_EQ(frames[1].offset, 3u);
}

TEST(QuicCryptoStreamTest, EmptySendBufferProducesNoFrames) {
    CryptoSendBuffer buffer;

    const auto frames = buffer.take_frames(8);

    EXPECT_TRUE(frames.empty());
}

TEST(QuicCryptoStreamTest, ZeroFrameBudgetProducesNoFramesAndKeepsBufferNonEmpty) {
    CryptoSendBuffer buffer;
    buffer.append(std::vector<std::byte>{std::byte{0x01}});

    const auto frames = buffer.take_frames(0);

    EXPECT_TRUE(frames.empty());
    EXPECT_FALSE(buffer.empty());
}

TEST(QuicCryptoStreamTest, EmptyReflectsPendingSendState) {
    CryptoSendBuffer buffer;

    EXPECT_TRUE(buffer.empty());

    buffer.append(std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}});
    EXPECT_FALSE(buffer.empty());

    ASSERT_EQ(buffer.take_frames(16).size(), 1u);
    EXPECT_TRUE(buffer.empty());
}

TEST(QuicCryptoStreamTest, SharedBytesEmptyAndSubviewBehaveLikeSpanViews) {
    SharedBytes empty;

    EXPECT_TRUE(empty.empty());
    EXPECT_EQ(empty.size(), 0u);
    EXPECT_EQ(empty.data(), nullptr);
    EXPECT_TRUE(empty.span().empty());
    EXPECT_EQ(empty.begin(), empty.end());
    EXPECT_TRUE(empty.subspan(1).empty());

    const std::vector<std::byte> empty_bytes;
    EXPECT_TRUE(empty == empty_bytes);
    EXPECT_TRUE(empty_bytes == empty);
    EXPECT_TRUE(std::span<const std::byte>(empty_bytes) == empty);

    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcdef"));
    const SharedBytes view(storage, 2, 4);
    const SharedBytes same_view(storage, 2, 4);
    const SharedBytes empty_view(storage, 2, 2);

    EXPECT_FALSE(view.empty());
    EXPECT_EQ(view.size(), 2u);
    ASSERT_NE(view.data(), nullptr);
    EXPECT_EQ(view.data(), storage->data() + 2);
    EXPECT_EQ(empty_view.data(), nullptr);
    EXPECT_TRUE(empty_view.span().empty());
    const auto view_span = view.span();
    EXPECT_EQ(std::vector<std::byte>(view_span.begin(), view_span.end()), bytes_from_string("cd"));
    EXPECT_EQ(view.to_vector(), bytes_from_string("cd"));
    EXPECT_EQ(view.begin_offset(), 2u);
    EXPECT_EQ(view.end_offset(), 4u);
    EXPECT_EQ(view, same_view);
    EXPECT_TRUE(view == bytes_from_string("cd"));
    EXPECT_TRUE(bytes_from_string("cd") == view);
    EXPECT_TRUE(view == std::span<const std::byte>(storage->data() + 2, 2));
    EXPECT_TRUE(std::span<const std::byte>(storage->data() + 2, 2) == view);
    EXPECT_EQ(view.subspan(1), bytes_from_string("d"));
    EXPECT_TRUE(view.subspan(8).empty());
}

TEST(QuicCryptoStreamTest, SharedBytesEqualityRejectsMismatchedViews) {
    const SharedBytes bytes(bytes_from_string("abcd"));
    const SharedBytes shorter(bytes_from_string("abc"));
    const SharedBytes different(bytes_from_string("abce"));
    const auto short_bytes = bytes_from_string("abc");
    const auto different_bytes = bytes_from_string("abce");

    EXPECT_EQ(bytes.subspan(1, 2), bytes_from_string("bc"));
    EXPECT_FALSE(bytes == different);
    EXPECT_FALSE(bytes == shorter);
    EXPECT_FALSE(bytes == short_bytes);
    EXPECT_FALSE(short_bytes == bytes);
    EXPECT_FALSE(bytes == std::span<const std::byte>(different_bytes));
    EXPECT_FALSE(std::span<const std::byte>(different_bytes) == bytes);
}

TEST(QuicCryptoStreamTest, SendBufferRetainsBytesUntilAcknowledged) {
    ReliableSendBuffer buffer;
    buffer.append(std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}});

    const auto first = buffer.take_ranges(2);
    ASSERT_EQ(first.size(), 1u);
    EXPECT_EQ(first[0].offset, 0u);
    EXPECT_EQ(first[0].bytes.size(), 2u);
    EXPECT_TRUE(buffer.has_outstanding_data());

    buffer.acknowledge(0, 2);
    EXPECT_TRUE(buffer.has_pending_data());
}

TEST(QuicCryptoStreamTest, TakeRangesReusesUnderlyingSegmentStorage) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));

    ASSERT_EQ(buffer.segments_.size(), 1u);
    const auto source_storage = buffer.segments_.begin()->second.storage;
    ASSERT_NE(source_storage, nullptr);
    const auto *source_bytes = source_storage->data();

    const auto ranges = buffer.take_ranges(2);

    ASSERT_EQ(ranges.size(), 1u);
    EXPECT_EQ(ranges[0].offset, 0u);
    EXPECT_EQ(ranges[0].bytes, bytes_from_string("ab"));
    ASSERT_FALSE(ranges[0].bytes.empty());
    EXPECT_EQ(ranges[0].bytes.data(), source_bytes);
}

TEST(QuicCryptoStreamTest, SharedAppendReusesCallerStorageWithoutCloning) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcdef"));
    const SharedBytes shared(storage, 1, 5);

    buffer.append(shared);

    ASSERT_EQ(buffer.segments_.size(), 1u);
    const auto &segment = buffer.segments_.begin()->second;
    EXPECT_EQ(buffer.segments_.begin()->first, 0u);
    EXPECT_EQ(segment.storage, storage);
    EXPECT_EQ(segment.begin, 1u);
    EXPECT_EQ(segment.end, 5u);

    const auto ranges = buffer.take_ranges(4);
    ASSERT_EQ(ranges.size(), 1u);
    EXPECT_EQ(ranges[0].offset, 0u);
    EXPECT_EQ(ranges[0].bytes, bytes_from_string("bcde"));
    EXPECT_EQ(ranges[0].bytes.storage().get(), storage.get());
    EXPECT_EQ(ranges[0].bytes.begin_offset(), 1u);
    EXPECT_EQ(ranges[0].bytes.end_offset(), 5u);
}

TEST(QuicCryptoStreamTest, SharedAppendPreservesAckAndLossBookkeeping) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcdef"));

    buffer.append(SharedBytes(storage, 0, 6));

    const auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].bytes.storage().get(), storage.get());

    buffer.acknowledge(1, 2);
    buffer.mark_lost(0, 4);

    const auto retransmit = buffer.take_ranges(2);
    ASSERT_EQ(retransmit.size(), 2u);
    EXPECT_EQ(retransmit[0].offset, 0u);
    EXPECT_EQ(retransmit[0].bytes, bytes_from_string("a"));
    EXPECT_EQ(retransmit[0].bytes.storage().get(), storage.get());
    EXPECT_EQ(retransmit[1].offset, 3u);
    EXPECT_EQ(retransmit[1].bytes, bytes_from_string("d"));
    EXPECT_EQ(retransmit[1].bytes.storage().get(), storage.get());
}

TEST(QuicCryptoStreamTest, TakeRangesWithZeroBudgetPreservesPendingBytes) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));

    const auto ranges = buffer.take_ranges(0);

    EXPECT_TRUE(ranges.empty());
    EXPECT_TRUE(buffer.has_pending_data());
    EXPECT_FALSE(buffer.has_outstanding_data());
}

TEST(QuicCryptoStreamTest, AdjacentSegmentsFromDifferentStorageDoNotMerge) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));
    buffer.append(bytes_from_string("cd"));

    ASSERT_EQ(buffer.segments_.size(), 2u);
    auto it = buffer.segments_.begin();
    const auto first_storage = it->second.storage;
    EXPECT_EQ(it->first, 0u);
    ++it;
    EXPECT_EQ(it->first, 2u);
    EXPECT_NE(first_storage, it->second.storage);
}

TEST(QuicCryptoStreamTest, AdjacentSegmentsWithStorageGapDoNotMerge) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    buffer.segments_.emplace(0, ReliableSendBuffer::Segment{
                                    .state = ReliableSendBuffer::SegmentState::unsent,
                                    .storage = storage,
                                    .begin = 0,
                                    .end = 1,
                                });
    buffer.segments_.emplace(1, ReliableSendBuffer::Segment{
                                    .state = ReliableSendBuffer::SegmentState::unsent,
                                    .storage = storage,
                                    .begin = 2,
                                    .end = 4,
                                });

    buffer.merge_adjacent_segments();

    EXPECT_EQ(buffer.segments_.size(), 2u);
}

TEST(QuicCryptoStreamTest, LostRangesBecomeSendableBeforeNewRanges) {
    ReliableSendBuffer buffer;
    const auto bytes = bytes_from_string("abcdef");
    buffer.append(bytes);
    const auto first = buffer.take_ranges(2);
    ASSERT_EQ(first.size(), 1u);
    buffer.mark_lost(first[0].offset, first[0].bytes.size());

    const auto retry = buffer.take_ranges(2);
    ASSERT_EQ(retry.size(), 1u);
    EXPECT_EQ(retry[0].offset, first[0].offset);
}

TEST(QuicCryptoStreamTest, PartialAcksRetireOnlyAcknowledgedSubrange) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));

    const auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].offset, 0u);
    EXPECT_EQ(sent[0].bytes, bytes_from_string("abcd"));

    buffer.acknowledge(1, 2);
    buffer.mark_lost(0, 4);

    const auto retransmit = buffer.take_ranges(2);
    ASSERT_EQ(retransmit.size(), 2u);
    EXPECT_EQ(retransmit[0].offset, 0u);
    EXPECT_EQ(retransmit[0].bytes, bytes_from_string("a"));
    EXPECT_EQ(retransmit[1].offset, 3u);
    EXPECT_EQ(retransmit[1].bytes, bytes_from_string("d"));

    const auto unsent = buffer.take_ranges(2);
    ASSERT_EQ(unsent.size(), 1u);
    EXPECT_EQ(unsent[0].offset, 4u);
    EXPECT_EQ(unsent[0].bytes, bytes_from_string("ef"));
}

TEST(QuicCryptoStreamTest, OutstandingRangeRequiresFullCoverageOfRequestedRange) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));

    const auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].offset, 0u);
    EXPECT_EQ(sent[0].bytes, bytes_from_string("abcd"));

    buffer.acknowledge(0, 2);

    EXPECT_FALSE(buffer.has_outstanding_range(0, 4));
    EXPECT_FALSE(buffer.has_outstanding_range(1, 3));
    EXPECT_TRUE(buffer.has_outstanding_range(2, 2));
    EXPECT_FALSE(buffer.has_outstanding_range(3, 3));
}

TEST(QuicCryptoStreamTest, ZeroLengthAcknowledgeLeavesOutstandingBytesUnchanged) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));
    ASSERT_EQ(buffer.take_ranges(2).size(), 1u);

    buffer.acknowledge(0, 0);

    EXPECT_TRUE(buffer.has_outstanding_data());
    EXPECT_TRUE(buffer.take_ranges(2).empty());
}

TEST(QuicCryptoStreamTest, ZeroLengthLostMarkLeavesSentBytesUnchanged) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));
    ASSERT_EQ(buffer.take_ranges(2).size(), 1u);

    buffer.mark_lost(0, 0);

    EXPECT_TRUE(buffer.has_outstanding_data());
    EXPECT_TRUE(buffer.take_ranges(2).empty());
}

TEST(QuicCryptoStreamTest, MarkUnsentAndMarkSentOnlyUpdateEligibleSegments) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcd"));
    ASSERT_EQ(buffer.take_ranges(4).size(), 1u);

    buffer.mark_unsent(1, 2);

    ASSERT_EQ(buffer.segments_.size(), 3u);
    auto it = buffer.segments_.begin();
    EXPECT_EQ(it->first, 0u);
    EXPECT_EQ(it->second.state, ReliableSendBuffer::SegmentState::sent);
    ++it;
    EXPECT_EQ(it->first, 1u);
    EXPECT_EQ(it->second.state, ReliableSendBuffer::SegmentState::unsent);
    ++it;
    EXPECT_EQ(it->first, 3u);
    EXPECT_EQ(it->second.state, ReliableSendBuffer::SegmentState::sent);
    EXPECT_FALSE(buffer.has_outstanding_range(1, 2));

    buffer.mark_lost(0, 4);
    buffer.mark_sent(0, 4);

    ASSERT_EQ(buffer.segments_.size(), 3u);
    it = buffer.segments_.begin();
    EXPECT_EQ(it->second.state, ReliableSendBuffer::SegmentState::sent);
    ++it;
    EXPECT_EQ(it->second.state, ReliableSendBuffer::SegmentState::unsent);
    ++it;
    EXPECT_EQ(it->second.state, ReliableSendBuffer::SegmentState::sent);
    EXPECT_TRUE(buffer.has_outstanding_range(0, 1));
    EXPECT_FALSE(buffer.has_outstanding_range(0, 0));
    EXPECT_FALSE(buffer.has_outstanding_range(1, 2));
    EXPECT_TRUE(buffer.has_outstanding_range(3, 1));
}

TEST(QuicCryptoStreamTest, MarkUnsentEarlierRangeIsTakenBeforeLaterFreshTail) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));
    ASSERT_EQ(buffer.take_ranges(4).size(), 1u);

    buffer.mark_unsent(1, 2);

    const auto unsent = buffer.take_unsent_ranges(4);
    ASSERT_EQ(unsent.size(), 2u);
    EXPECT_EQ(unsent[0].offset, 1u);
    EXPECT_EQ(unsent[0].bytes, bytes_from_string("bc"));
    EXPECT_EQ(unsent[1].offset, 4u);
    EXPECT_EQ(unsent[1].bytes, bytes_from_string("ef"));
}

TEST(QuicCryptoStreamTest, MarkLostEarlierRangeIsTakenBeforeLaterLostTail) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));
    ASSERT_EQ(buffer.take_ranges(6).size(), 1u);

    buffer.mark_lost(4, 2);
    buffer.mark_lost(1, 2);

    const auto lost = buffer.take_lost_ranges(4);
    ASSERT_EQ(lost.size(), 2u);
    EXPECT_EQ(lost[0].offset, 1u);
    EXPECT_EQ(lost[0].bytes, bytes_from_string("bc"));
    EXPECT_EQ(lost[1].offset, 4u);
    EXPECT_EQ(lost[1].bytes, bytes_from_string("ef"));
}

TEST(QuicCryptoStreamTest, ZeroLengthMarkUnsentAndMarkSentLeaveSentStateUnchanged) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));
    ASSERT_EQ(buffer.take_ranges(2).size(), 1u);

    buffer.mark_unsent(0, 0);
    buffer.mark_sent(0, 0);

    ASSERT_EQ(buffer.segments_.size(), 1u);
    EXPECT_EQ(buffer.segments_.begin()->first, 0u);
    EXPECT_EQ(buffer.segments_.begin()->second.state, ReliableSendBuffer::SegmentState::sent);
    EXPECT_TRUE(buffer.has_outstanding_data());
    EXPECT_FALSE(buffer.has_outstanding_range(0, 0));
}

TEST(QuicCryptoStreamTest, MarkLostOnlyRetiresSentSegmentsInsideRange) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcd"));
    ASSERT_EQ(buffer.take_ranges(2).size(), 1u);

    buffer.mark_lost(0, 4);

    const auto retransmit = buffer.take_ranges(4);
    ASSERT_EQ(retransmit.size(), 2u);
    EXPECT_EQ(retransmit[0].offset, 0u);
    EXPECT_EQ(retransmit[0].bytes, bytes_from_string("ab"));
    EXPECT_EQ(retransmit[1].offset, 2u);
    EXPECT_EQ(retransmit[1].bytes, bytes_from_string("cd"));
}

TEST(QuicCryptoStreamTest, AcknowledgeClampsOverflowingRangeEndToUint64Max) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    buffer.segments_.emplace(std::numeric_limits<std::uint64_t>::max() - 2,
                             ReliableSendBuffer::Segment{
                                 .state = ReliableSendBuffer::SegmentState::sent,
                                 .storage = std::move(storage),
                                 .begin = 0,
                                 .end = 4,
                             });

    buffer.acknowledge(std::numeric_limits<std::uint64_t>::max() - 2, 8);

    EXPECT_TRUE(buffer.segments_.empty());
}

TEST(QuicCryptoStreamTest, UnsentSegmentsAreNotOutstandingYet) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));

    EXPECT_FALSE(buffer.has_outstanding_data());
}

TEST(QuicCryptoStreamTest, LostSegmentsRemainOutstanding) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));
    ASSERT_EQ(buffer.take_ranges(2).size(), 1u);
    buffer.mark_lost(0, 2);

    EXPECT_TRUE(buffer.has_outstanding_data());
}

TEST(QuicCryptoStreamTest, MarkUnsentLeavesLostSegmentsOutstanding) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcd"));
    ASSERT_EQ(buffer.take_ranges(4).size(), 1u);
    buffer.mark_lost(0, 4);

    buffer.mark_unsent(0, 4);

    EXPECT_TRUE(buffer.has_lost_data());
    EXPECT_TRUE(buffer.has_outstanding_data());
    EXPECT_TRUE(buffer.has_outstanding_range(0, 4));
}

TEST(QuicCryptoStreamTest, LostOnlySegmentsRemainOutstandingAfterRemovingUnsentTail) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));
    ASSERT_EQ(buffer.take_ranges(1).size(), 1u);
    buffer.acknowledge(1, 1);
    buffer.mark_lost(0, 1);

    EXPECT_TRUE(buffer.has_outstanding_data());
}

TEST(QuicCryptoStreamTest, ReceiveBufferReleasesReorderedApplicationBytesContiguously) {
    ReliableReceiveBuffer buffer;
    ASSERT_TRUE(buffer.push(4, bytes_from_string("ef")).has_value());
    const auto first_release = buffer.push(0, bytes_from_string("abcd"));
    ASSERT_TRUE(first_release.has_value());
    EXPECT_EQ(first_release.value(), bytes_from_string("abcdef"));
    const auto released = buffer.push(6, bytes_from_string("gh"));
    ASSERT_TRUE(released.has_value());
    EXPECT_EQ(released.value(), bytes_from_string("gh"));
}

TEST(QuicCryptoStreamTest, ReceiveBufferReturnsOnlyUndeliveredTailOfOverlappingWrite) {
    ReliableReceiveBuffer buffer;
    const auto first = buffer.push(0, bytes_from_string("abcd"));
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first.value(), bytes_from_string("abcd"));

    const auto second = buffer.push(2, bytes_from_string("cdef"));
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second.value(), bytes_from_string("ef"));
}

TEST(QuicCryptoStreamTest, ReceiveBufferSharedPushReturnsAliasedInOrderStorage) {
    ReliableReceiveBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));

    const auto released = buffer.push_shared(0, SharedBytes(storage, 0, 4));

    ASSERT_TRUE(released.has_value());
    EXPECT_EQ(
        std::vector<std::byte>(released.value().span().begin(), released.value().span().end()),
        bytes_from_string("abcd"));
    EXPECT_EQ(released.value().shared.storage().get(), storage.get());
    EXPECT_TRUE(released.value().owned.empty());
    EXPECT_TRUE(buffer.buffered_bytes_.empty());
}

TEST(QuicCryptoStreamTest, ReceiveBufferSharedPushPreservesBufferedStorageWithoutCloning) {
    ReliableReceiveBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcdef"));

    ASSERT_TRUE(buffer.push_shared(3, SharedBytes(storage, 3, 6)).has_value());

    ASSERT_EQ(buffer.buffered_bytes_.size(), 1u);
    EXPECT_EQ(buffer.buffered_bytes_.begin()->first, 3u);
    EXPECT_EQ(buffer.buffered_bytes_.begin()->second.storage().get(), storage.get());
    EXPECT_EQ(buffer.buffered_bytes_.begin()->second, bytes_from_string("def"));
}

TEST(QuicCryptoStreamTest, ReceiveBufferSharedPushCoalescesSeparateStorageOnlyAtDelivery) {
    ReliableReceiveBuffer buffer;
    auto early = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    auto late = std::make_shared<std::vector<std::byte>>(bytes_from_string("ef"));

    ASSERT_TRUE(buffer.push_shared(4, SharedBytes(late, 0, 2)).has_value());
    const auto released = buffer.push_shared(0, SharedBytes(early, 0, 4));

    ASSERT_TRUE(released.has_value());
    EXPECT_TRUE(released.value().shared.empty());
    EXPECT_EQ(released.value().owned, bytes_from_string("abcdef"));
}

TEST(QuicCryptoStreamTest, InternalCoverageHelperExercisesSharedCoalescingAndEmptySharedAppend) {
    EXPECT_TRUE(crypto_stream_internal_coverage_for_tests());
}

TEST(QuicCryptoStreamTest, ReceiveBufferReleasesOnlyContiguousBytes) {
    CryptoReceiveBuffer buffer;

    const auto first = buffer.push(2, std::vector<std::byte>{std::byte{0xcc}, std::byte{0xdd}});
    ASSERT_TRUE(first.has_value());
    EXPECT_TRUE(first.value().empty());

    const auto second = buffer.push(0, std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}});
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second.value(), (std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb},
                                                      std::byte{0xcc}, std::byte{0xdd}}));
}

TEST(QuicCryptoStreamTest, EmptyReceivePushReturnsNoBytes) {
    CryptoReceiveBuffer buffer;

    const auto pushed = buffer.push(0, {});

    ASSERT_TRUE(pushed.has_value());
    EXPECT_TRUE(pushed.value().empty());
}

TEST(QuicCryptoStreamTest, RejectsReceiveRangePastMaximumOffset) {
    CryptoReceiveBuffer buffer;

    const auto pushed = buffer.push((std::uint64_t{1} << 62) - 1,
                                    std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}});

    ASSERT_FALSE(pushed.has_value());
    EXPECT_EQ(pushed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCryptoStreamTest, RejectsReceiveOffsetAboveMaximumOffset) {
    CryptoReceiveBuffer buffer;

    const auto pushed =
        buffer.push((std::uint64_t{1} << 62), std::vector<std::byte>{std::byte{0xaa}});

    ASSERT_FALSE(pushed.has_value());
    EXPECT_EQ(pushed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCryptoStreamTest, OverlappingReceiveBytesDoNotDuplicateOutput) {
    CryptoReceiveBuffer buffer;

    ASSERT_TRUE(
        buffer.push(0, std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}}).has_value());

    const auto overlapping =
        buffer.push(1, std::vector<std::byte>{std::byte{0xbb}, std::byte{0xcc}});

    ASSERT_TRUE(overlapping.has_value());
    EXPECT_EQ(overlapping.value(), (std::vector<std::byte>{std::byte{0xcc}}));
}

TEST(QuicCryptoStreamTest, ReceiveBufferStoresOutOfOrderBufferedBytesByRangeInsteadOfByByte) {
    ReliableReceiveBuffer buffer;

    ASSERT_TRUE(buffer.push(8, bytes_from_string("ijkl")).has_value());
    ASSERT_TRUE(buffer.push(4, bytes_from_string("efgh")).has_value());

    EXPECT_LE(buffer.buffered_bytes_.size(), 2u);
}

TEST(QuicCryptoStreamTest, ReceiveBufferSkipsEmptyAndOverlappingBufferedRanges) {
    ReliableReceiveBuffer buffer;

    buffer.buffer_range(0, SharedBytes{});
    EXPECT_TRUE(buffer.buffered_bytes_.empty());

    buffer.buffer_range(0, SharedBytes(bytes_from_string("abcd")));
    buffer.buffer_range(2, SharedBytes(bytes_from_string("cde")));

    ASSERT_EQ(buffer.buffered_bytes_.size(), 2u);
    EXPECT_EQ(buffer.buffered_bytes_.at(0), bytes_from_string("abcd"));
    EXPECT_EQ(buffer.buffered_bytes_.at(4), bytes_from_string("e"));
    EXPECT_EQ(buffer.take_contiguous_buffered_bytes(), bytes_from_string("abcde"));
    EXPECT_TRUE(buffer.buffered_bytes_.empty());
}

TEST(QuicCryptoStreamTest, ReceiveBufferSkipsBufferedRangesAlreadyCoveredByCursor) {
    ReliableReceiveBuffer buffer;
    buffer.buffered_bytes_.emplace(0, bytes_from_string("abcdef"));
    buffer.buffered_bytes_.emplace(2, bytes_from_string("cd"));

    buffer.buffer_range(1, SharedBytes(bytes_from_string("bcdefg")));

    EXPECT_EQ(buffer.take_contiguous_buffered_bytes(), bytes_from_string("abcdefg"));
    EXPECT_TRUE(buffer.buffered_bytes_.empty());
}

} // namespace
