#include <cstdlib>
#include <limits>
#include <memory>
#include <optional>
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

template <typename T> const T &optional_ref_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return value.value();
}

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

ReliableSendBuffer::Segment &insert_segment(ReliableSendBuffer &send_buffer, std::uint64_t offset,
                                            ReliableSendBuffer::SegmentState state,
                                            const std::shared_ptr<std::vector<std::byte>> &storage,
                                            std::uint64_t begin, std::uint64_t end) {
    auto insert_result = send_buffer.segments_.emplace(offset, ReliableSendBuffer::Segment{
                                                                   .state = state,
                                                                   .storage = storage,
                                                                   .begin = begin,
                                                                   .end = end,
                                                               });
    if (!insert_result.second) {
        std::abort();
    }
    send_buffer.note_segment_inserted(insert_result.first->second);
    return insert_result.first->second;
}

std::size_t send_buffer_state_count(const ReliableSendBuffer &send_buffer,
                                    ReliableSendBuffer::SegmentState state) {
    return send_buffer.segment_state_counts_[send_buffer_state_index(state)];
}

void expect_send_buffer_state_counts(const ReliableSendBuffer &send_buffer,
                                     std::size_t unsent_count, std::size_t sent_count,
                                     std::size_t lost_count) {
    EXPECT_EQ(send_buffer_state_count(send_buffer, ReliableSendBuffer::SegmentState::unsent),
              unsent_count);
    EXPECT_EQ(send_buffer_state_count(send_buffer, ReliableSendBuffer::SegmentState::sent),
              sent_count);
    EXPECT_EQ(send_buffer_state_count(send_buffer, ReliableSendBuffer::SegmentState::lost),
              lost_count);
}

TEST(QuicCryptoStreamTest, SendBufferSegmentStateCountsTrackTransitions) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcd"));

    expect_send_buffer_state_counts(buffer, 1u, 0u, 0u);

    auto initial = buffer.take_ranges(2);
    ASSERT_EQ(initial.size(), 1u);
    expect_send_buffer_state_counts(buffer, 1u, 1u, 0u);

    buffer.mark_lost(0, 2);
    expect_send_buffer_state_counts(buffer, 1u, 0u, 1u);

    buffer.mark_sent(0, 2);
    expect_send_buffer_state_counts(buffer, 1u, 1u, 0u);

    buffer.acknowledge(0, 2);
    expect_send_buffer_state_counts(buffer, 1u, 0u, 0u);

    buffer.acknowledge(2, 2);
    EXPECT_TRUE(buffer.segments_.empty());
    expect_send_buffer_state_counts(buffer, 0u, 0u, 0u);
}

TEST(QuicCryptoStreamTest, TransitionSegmentStateNoOpKeepsStateCountsStable) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));

    auto before_unsent = buffer.segment_state_counts_[send_buffer_state_index(
        ReliableSendBuffer::SegmentState::unsent)];
    auto before_sent =
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)];
    auto before_lost =
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)];

    auto segment_it = buffer.segments_.begin();
    ASSERT_NE(segment_it, buffer.segments_.end());
    buffer.transition_segment_state(segment_it->second, ReliableSendBuffer::SegmentState::unsent);

    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::unsent);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              before_unsent);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        before_sent);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)],
        before_lost);
}

TEST(QuicCryptoStreamTest, AppendCollisionSkipsDuplicateInsertionAccounting) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("ab"));
    insert_segment(buffer, 0, ReliableSendBuffer::SegmentState::unsent, storage, 0, 1);
    buffer.next_append_offset_ = 0;

    auto before_unsent = buffer.segment_state_counts_[send_buffer_state_index(
        ReliableSendBuffer::SegmentState::unsent)];
    buffer.append(SharedBytes(storage, 1, 2));

    EXPECT_EQ(buffer.segments_.size(), 1u);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              before_unsent);
    EXPECT_EQ(buffer.next_append_offset_, 1u);
}

TEST(QuicCryptoStreamTest, TakeRangesSplitCollisionSkipsDuplicateTailInsertion) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    insert_segment(buffer, 0, ReliableSendBuffer::SegmentState::unsent, storage, 0, 4);
    insert_segment(buffer, 2, ReliableSendBuffer::SegmentState::unsent, storage, 2, 4);

    auto ranges = buffer.take_ranges(2);

    ASSERT_EQ(ranges.size(), 1u);
    EXPECT_EQ(buffer.segments_.size(), 2u);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        1u);
}

TEST(QuicCryptoStreamTest, SplitAtAddsTailSegmentAndAccountsForItsState) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    insert_segment(buffer, 0, ReliableSendBuffer::SegmentState::sent, storage, 0, 4);

    buffer.split_at(2);

    EXPECT_EQ(buffer.segments_.size(), 2u);
    EXPECT_EQ(buffer.segments_.begin()->second.end, 2u);
    auto tail_it = std::next(buffer.segments_.begin());
    EXPECT_EQ(tail_it->first, 2u);
    EXPECT_EQ(tail_it->second.begin, 2u);
    EXPECT_EQ(tail_it->second.end, 4u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        2u);
}

TEST(QuicCryptoStreamTest, FirstOffsetByStateReturnsEmptyWhenStateCountIsStale) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    insert_segment(buffer, 0, ReliableSendBuffer::SegmentState::sent, storage, 0, 4);
    buffer.segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::lost)] =
        1;

    EXPECT_FALSE(buffer.first_lost_offset().has_value());
}

bool crypto_stream_internal_coverage_for_tests();

bool crypto_stream_internal_coverage_for_tests() {
    ReliableReceiveBuffer receive_buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    receive_buffer.buffered_bytes_.emplace(0, SharedBytes(storage, 0, 2));
    receive_buffer.buffered_bytes_.emplace(2, SharedBytes(storage, 2, 4));

    auto contiguous = receive_buffer.take_contiguous_buffered_bytes({});
    if (contiguous.owned.size() != 0 || contiguous.shared.storage().get() != storage.get() ||
        contiguous.shared.begin_offset() != 0 || contiguous.shared.end_offset() != 4 ||
        contiguous.to_vector() != bytes_from_string("abcd") ||
        !receive_buffer.buffered_bytes_.empty() || receive_buffer.next_contiguous_offset_ != 4) {
        return false;
    }

    ReliableReceiveBuffer gapped_receive_buffer;
    gapped_receive_buffer.buffered_bytes_.emplace(0, SharedBytes(storage, 0, 2));
    gapped_receive_buffer.buffered_bytes_.emplace(2, SharedBytes(storage, 3, 4));
    auto gapped = gapped_receive_buffer.take_contiguous_buffered_bytes({});
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

    auto frames = buffer.take_frames(3);
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0].offset, 0u);
    EXPECT_EQ(frames[1].offset, 3u);
}

TEST(QuicCryptoStreamTest, EmptySendBufferProducesNoFrames) {
    CryptoSendBuffer buffer;

    auto frames = buffer.take_frames(8);

    EXPECT_TRUE(frames.empty());
}

TEST(QuicCryptoStreamTest, ZeroFrameBudgetProducesNoFramesAndKeepsBufferNonEmpty) {
    CryptoSendBuffer buffer;
    buffer.append(std::vector<std::byte>{std::byte{0x01}});

    auto frames = buffer.take_frames(0);

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

    std::vector<std::byte> empty_bytes;
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
    auto view_span = view.span();
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
    auto short_bytes = bytes_from_string("abc");
    auto different_bytes = bytes_from_string("abce");

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

    auto first = buffer.take_ranges(2);
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
    auto source_storage = buffer.segments_.begin()->second.storage;
    ASSERT_NE(source_storage, nullptr);
    auto *source_bytes = source_storage->data();

    auto ranges = buffer.take_ranges(2);

    ASSERT_EQ(ranges.size(), 1u);
    EXPECT_EQ(ranges[0].offset, 0u);
    EXPECT_EQ(ranges[0].bytes, bytes_from_string("ab"));
    ASSERT_FALSE(ranges[0].bytes.empty());
    EXPECT_EQ(ranges[0].bytes.data(), source_bytes);
}

TEST(QuicCryptoStreamTest, BytesForRangeCoversSharedOwnedAndMissingRanges) {
    ReliableSendBuffer buffer;
    auto first = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    auto second = std::make_shared<std::vector<std::byte>>(bytes_from_string("efgh"));

    buffer.append(SharedBytes(first, 0, 4));
    ASSERT_EQ(buffer.take_ranges(2).size(), 1u);
    buffer.mark_lost(0, 2);
    ASSERT_EQ(buffer.take_ranges(4).size(), 2u);

    auto first_slice = buffer.bytes_for_range(0, 4);
    ASSERT_TRUE(first_slice.has_value());
    auto &first_slice_value = optional_ref_or_terminate(first_slice);
    EXPECT_EQ(first_slice_value.storage().get(), first.get());
    EXPECT_EQ(first_slice_value.to_vector(), bytes_from_string("abcd"));

    buffer.append(SharedBytes(second, 0, 4));
    EXPECT_FALSE(buffer.bytes_for_range(0, 8).has_value());
    ASSERT_FALSE(buffer.take_ranges(8).empty());

    auto joined = buffer.bytes_for_range(0, 8);
    ASSERT_TRUE(joined.has_value());
    auto &joined_value = optional_ref_or_terminate(joined);
    EXPECT_NE(joined_value.storage().get(), first.get());
    EXPECT_NE(joined_value.storage().get(), second.get());
    EXPECT_EQ(joined_value.to_vector(), bytes_from_string("abcdefgh"));

    auto empty_slice = buffer.bytes_for_range(0, 0);
    ASSERT_TRUE(empty_slice.has_value());
    auto &empty_slice_value = optional_ref_or_terminate(empty_slice);
    EXPECT_TRUE(empty_slice_value.empty());
    EXPECT_FALSE(buffer.bytes_for_range(10, 1).has_value());

    ReliableSendBuffer pending;
    pending.append(bytes_from_string("xy"));
    EXPECT_FALSE(pending.bytes_for_range(0, 1).has_value());
}

TEST(QuicCryptoStreamTest, BytesForRangeCoalescesAdjacentSharedSegmentsAndRejectsGaps) {
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));

    ReliableSendBuffer coalesced_buffer;
    insert_segment(coalesced_buffer, 0, ReliableSendBuffer::SegmentState::sent, storage, 0, 2);
    insert_segment(coalesced_buffer, 2, ReliableSendBuffer::SegmentState::lost, storage, 2, 4);

    auto coalesced = coalesced_buffer.bytes_for_range(0, 4);
    ASSERT_TRUE(coalesced.has_value());
    auto &coalesced_value = optional_ref_or_terminate(coalesced);
    EXPECT_EQ(coalesced_value.storage().get(), storage.get());
    EXPECT_EQ(coalesced_value.begin_offset(), 0u);
    EXPECT_EQ(coalesced_value.end_offset(), 4u);
    EXPECT_EQ(coalesced_value.to_vector(), bytes_from_string("abcd"));

    ReliableSendBuffer gapped_buffer;
    insert_segment(gapped_buffer, 0, ReliableSendBuffer::SegmentState::sent, storage, 0, 2);
    insert_segment(gapped_buffer, 4, ReliableSendBuffer::SegmentState::sent, storage, 2, 4);

    EXPECT_FALSE(gapped_buffer.bytes_for_range(0, 6).has_value());
}

TEST(QuicCryptoStreamTest, SendBufferColdBranchEdgesUseDirectSegments) {
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcdef"));

    ReliableSendBuffer exact_previous_end;
    insert_segment(exact_previous_end, 0, ReliableSendBuffer::SegmentState::sent, storage, 0, 2);
    insert_segment(exact_previous_end, 2, ReliableSendBuffer::SegmentState::sent, storage, 2, 4);
    exact_previous_end.acknowledge(2, 1);
    EXPECT_EQ(exact_previous_end.segments_.begin()->second.end, 2u);

    ReliableSendBuffer exact_previous_end_ack_past_first;
    insert_segment(exact_previous_end_ack_past_first, 0, ReliableSendBuffer::SegmentState::lost,
                   storage, 0, 2);
    insert_segment(exact_previous_end_ack_past_first, 2, ReliableSendBuffer::SegmentState::lost,
                   storage, 2, 4);
    insert_segment(exact_previous_end_ack_past_first, 4, ReliableSendBuffer::SegmentState::lost,
                   storage, 4, 6);
    exact_previous_end_ack_past_first.acknowledge(2, 1);
    EXPECT_EQ(exact_previous_end_ack_past_first.segments_.begin()->second.end, 2u);

    ReliableSendBuffer gap_before_ack;
    insert_segment(gap_before_ack, 0, ReliableSendBuffer::SegmentState::lost, storage, 0, 2);
    insert_segment(gap_before_ack, 4, ReliableSendBuffer::SegmentState::lost, storage, 4, 6);
    gap_before_ack.acknowledge(2, 1);
    EXPECT_EQ(gap_before_ack.segments_.size(), 2u);

    ReliableSendBuffer split_collision;
    insert_segment(split_collision, 0, ReliableSendBuffer::SegmentState::sent, storage, 0, 6);
    insert_segment(split_collision, 4, ReliableSendBuffer::SegmentState::sent, storage, 4, 6);
    split_collision.acknowledge(2, 2);
    EXPECT_EQ(split_collision.segments_.size(), 2u);

    ReliableSendBuffer before_first;
    insert_segment(before_first, 2, ReliableSendBuffer::SegmentState::sent, storage, 2, 4);
    EXPECT_FALSE(before_first.bytes_for_range(0, 1).has_value());

    ReliableSendBuffer exact_first_range;
    insert_segment(exact_first_range, 0, ReliableSendBuffer::SegmentState::sent, storage, 0, 2);
    insert_segment(exact_first_range, 2, ReliableSendBuffer::SegmentState::sent, storage, 2, 4);
    ASSERT_TRUE(exact_first_range.bytes_for_range(0, 2).has_value());

    ReliableSendBuffer non_adjacent_storage_offsets;
    insert_segment(non_adjacent_storage_offsets, 0, ReliableSendBuffer::SegmentState::sent, storage,
                   0, 2);
    insert_segment(non_adjacent_storage_offsets, 2, ReliableSendBuffer::SegmentState::sent, storage,
                   3, 5);
    auto discontiguous = non_adjacent_storage_offsets.bytes_for_range(0, 4);
    ASSERT_TRUE(discontiguous.has_value());
    auto &discontiguous_value = optional_ref_or_terminate(discontiguous);
    EXPECT_EQ(discontiguous_value.to_vector(), bytes_from_string("abde"));

    ReliableSendBuffer owned_already;
    auto other_storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("gh"));
    auto third_storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("ij"));
    insert_segment(owned_already, 0, ReliableSendBuffer::SegmentState::sent, storage, 0, 2);
    insert_segment(owned_already, 2, ReliableSendBuffer::SegmentState::sent, other_storage, 0, 2);
    insert_segment(owned_already, 4, ReliableSendBuffer::SegmentState::sent, third_storage, 0, 2);
    auto owned = owned_already.bytes_for_range(0, 6);
    ASSERT_TRUE(owned.has_value());
    auto &owned_value = optional_ref_or_terminate(owned);
    EXPECT_EQ(owned_value.to_vector(), bytes_from_string("abghij"));
}

TEST(QuicCryptoStreamTest, SharedAppendReusesCallerStorageWithoutCloning) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcdef"));
    const SharedBytes shared(storage, 1, 5);

    buffer.append(shared);

    ASSERT_EQ(buffer.segments_.size(), 1u);
    auto &segment = buffer.segments_.begin()->second;
    EXPECT_EQ(buffer.segments_.begin()->first, 0u);
    EXPECT_EQ(segment.storage, storage);
    EXPECT_EQ(segment.begin, 1u);
    EXPECT_EQ(segment.end, 5u);

    auto ranges = buffer.take_ranges(4);
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

    auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].bytes.storage().get(), storage.get());

    buffer.acknowledge(1, 2);
    buffer.mark_lost(0, 4);

    auto retransmit = buffer.take_ranges(2);
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

    auto ranges = buffer.take_ranges(0);

    EXPECT_TRUE(ranges.empty());
    EXPECT_TRUE(buffer.has_pending_data());
    EXPECT_FALSE(buffer.has_outstanding_data());
}

TEST(QuicCryptoStreamTest, AdjacentSegmentsFromDifferentStorageDoNotMerge) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));
    buffer.append(bytes_from_string("cd"));

    ASSERT_EQ(buffer.segments_.size(), 2u);
    auto segment_it = buffer.segments_.begin();
    auto first_storage = segment_it->second.storage;
    EXPECT_EQ(segment_it->first, 0u);
    ++segment_it;
    EXPECT_EQ(segment_it->first, 2u);
    EXPECT_NE(first_storage, segment_it->second.storage);
}

TEST(QuicCryptoStreamTest, AdjacentSegmentsWithStorageGapDoNotMerge) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    insert_segment(buffer, 0, ReliableSendBuffer::SegmentState::unsent, storage, 0, 1);
    insert_segment(buffer, 1, ReliableSendBuffer::SegmentState::unsent, storage, 2, 4);

    buffer.merge_adjacent_segments();

    EXPECT_EQ(buffer.segments_.size(), 2u);
}

TEST(QuicCryptoStreamTest, LostRangesBecomeSendableBeforeNewRanges) {
    ReliableSendBuffer buffer;
    auto bytes = bytes_from_string("abcdef");
    buffer.append(bytes);
    auto first = buffer.take_ranges(2);
    ASSERT_EQ(first.size(), 1u);
    buffer.mark_lost(first[0].offset, first[0].bytes.size());

    auto retry = buffer.take_ranges(2);
    ASSERT_EQ(retry.size(), 1u);
    EXPECT_EQ(retry[0].offset, first[0].offset);
}

TEST(QuicCryptoStreamTest, PartialAcksRetireOnlyAcknowledgedSubrange) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));

    auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].offset, 0u);
    EXPECT_EQ(sent[0].bytes, bytes_from_string("abcd"));

    buffer.acknowledge(1, 2);
    buffer.mark_lost(0, 4);

    auto retransmit = buffer.take_ranges(2);
    ASSERT_EQ(retransmit.size(), 2u);
    EXPECT_EQ(retransmit[0].offset, 0u);
    EXPECT_EQ(retransmit[0].bytes, bytes_from_string("a"));
    EXPECT_EQ(retransmit[1].offset, 3u);
    EXPECT_EQ(retransmit[1].bytes, bytes_from_string("d"));

    auto unsent = buffer.take_ranges(2);
    ASSERT_EQ(unsent.size(), 1u);
    EXPECT_EQ(unsent[0].offset, 4u);
    EXPECT_EQ(unsent[0].bytes, bytes_from_string("ef"));
}

TEST(QuicCryptoStreamTest, LeadingSentAckUsesDirectEraseFastPath) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));

    auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);

    EXPECT_TRUE(buffer.acknowledge_leading_sent_range(0, 2));

    ASSERT_EQ(buffer.segments_.size(), 2u);
    auto segment_it = buffer.segments_.begin();
    EXPECT_EQ(segment_it->first, 2u);
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::sent);
    EXPECT_EQ(segment_it->second.begin, 2u);
    EXPECT_EQ(segment_it->second.end, 4u);
    ++segment_it;
    EXPECT_EQ(segment_it->first, 4u);
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::unsent);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        1u);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);

    EXPECT_TRUE(buffer.acknowledge_leading_sent_range(2, 4));
    ASSERT_EQ(buffer.segments_.size(), 1u);
    EXPECT_EQ(buffer.segments_.begin()->first, 4u);
    EXPECT_EQ(buffer.segments_.begin()->second.state, ReliableSendBuffer::SegmentState::unsent);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        0u);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);
}

TEST(QuicCryptoStreamTest, LeadingSentAckFastPathRejectsNonLeadingOrOversizedRanges) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));

    auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);

    EXPECT_FALSE(buffer.acknowledge_leading_sent_range(1, 2));
    EXPECT_FALSE(buffer.acknowledge_leading_sent_range(0, 5));

    ASSERT_EQ(buffer.segments_.size(), 2u);
    auto segment_it = buffer.segments_.begin();
    EXPECT_EQ(segment_it->first, 0u);
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::sent);
    EXPECT_EQ(segment_it->second.begin, 0u);
    EXPECT_EQ(segment_it->second.end, 4u);
    ++segment_it;
    EXPECT_EQ(segment_it->first, 4u);
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::unsent);
}

TEST(QuicCryptoStreamTest, OutstandingRangeRequiresFullCoverageOfRequestedRange) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));

    auto sent = buffer.take_ranges(4);
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
    auto segment_it = buffer.segments_.begin();
    EXPECT_EQ(segment_it->first, 0u);
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::sent);
    ++segment_it;
    EXPECT_EQ(segment_it->first, 1u);
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::unsent);
    ++segment_it;
    EXPECT_EQ(segment_it->first, 3u);
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::sent);
    EXPECT_FALSE(buffer.has_outstanding_range(1, 2));

    buffer.mark_lost(0, 4);
    buffer.mark_sent(0, 4);

    ASSERT_EQ(buffer.segments_.size(), 3u);
    segment_it = buffer.segments_.begin();
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::sent);
    ++segment_it;
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::unsent);
    ++segment_it;
    EXPECT_EQ(segment_it->second.state, ReliableSendBuffer::SegmentState::sent);
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

    auto unsent = buffer.take_unsent_ranges(4);
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

    auto lost = buffer.take_lost_ranges(4);
    ASSERT_EQ(lost.size(), 2u);
    EXPECT_EQ(lost[0].offset, 1u);
    EXPECT_EQ(lost[0].bytes, bytes_from_string("bc"));
    EXPECT_EQ(lost[1].offset, 4u);
    EXPECT_EQ(lost[1].bytes, bytes_from_string("ef"));
}

TEST(QuicCryptoStreamTest, TakeRangesHonorsMaxOffsetWhenSplittingLostAndUnsentSegments) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdefgh"));

    auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);
    buffer.mark_lost(0, 4);

    auto lost = buffer.take_lost_ranges(/*max_bytes=*/8, /*max_offset=*/2);
    ASSERT_EQ(lost.size(), 1u);
    EXPECT_EQ(lost[0].offset, 0u);
    EXPECT_EQ(lost[0].bytes, bytes_from_string("ab"));

    auto unsent = buffer.take_unsent_ranges(/*max_bytes=*/8, /*max_offset=*/6);
    ASSERT_EQ(unsent.size(), 1u);
    EXPECT_EQ(unsent[0].offset, 4u);
    EXPECT_EQ(unsent[0].bytes, bytes_from_string("ef"));
}

TEST(QuicCryptoStreamTest, ConsumeRangesHonorsMaxOffsetAndStopsAtSplitBoundary) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdefgh"));

    auto sent = buffer.take_ranges(4);
    ASSERT_EQ(sent.size(), 1u);
    buffer.mark_lost(0, 4);

    std::vector<coquic::quic::ByteRange> lost;
    auto remember_lost = [&](coquic::quic::ByteRange range) { lost.push_back(std::move(range)); };

    std::size_t empty_lost_budget = 0;
    buffer.consume_lost_ranges(empty_lost_budget, std::nullopt, remember_lost);
    EXPECT_TRUE(lost.empty());

    std::size_t lost_budget = 2;
    buffer.consume_lost_ranges(lost_budget, /*max_offset=*/3, remember_lost);
    ASSERT_EQ(lost.size(), 1u);
    EXPECT_EQ(lost[0].offset, 0u);
    EXPECT_EQ(lost[0].bytes, bytes_from_string("ab"));
    EXPECT_EQ(lost_budget, 0u);

    lost.clear();
    lost_budget = 8;
    buffer.consume_lost_ranges(lost_budget, /*max_offset=*/3, remember_lost);
    ASSERT_EQ(lost.size(), 1u);
    EXPECT_EQ(lost[0].offset, 2u);
    EXPECT_EQ(lost[0].bytes, bytes_from_string("c"));
    EXPECT_EQ(lost_budget, 7u);

    std::vector<coquic::quic::ByteRange> unsent;
    auto remember_unsent = [&](coquic::quic::ByteRange range) {
        unsent.push_back(std::move(range));
    };

    std::size_t empty_unsent_budget = 0;
    buffer.consume_unsent_ranges(empty_unsent_budget, std::nullopt, remember_unsent);
    EXPECT_TRUE(unsent.empty());

    std::size_t unsent_budget = 2;
    buffer.consume_unsent_ranges(unsent_budget, /*max_offset=*/7, remember_unsent);
    ASSERT_EQ(unsent.size(), 1u);
    EXPECT_EQ(unsent[0].offset, 4u);
    EXPECT_EQ(unsent[0].bytes, bytes_from_string("ef"));
    EXPECT_EQ(unsent_budget, 0u);

    unsent.clear();
    unsent_budget = 8;
    buffer.consume_unsent_ranges(unsent_budget, /*max_offset=*/7, remember_unsent);
    ASSERT_EQ(unsent.size(), 1u);
    EXPECT_EQ(unsent[0].offset, 6u);
    EXPECT_EQ(unsent[0].bytes, bytes_from_string("g"));
    EXPECT_EQ(unsent_budget, 7u);
}

TEST(QuicCryptoStreamTest, ConsumeRangesCanRunWithoutMaxOffset) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));

    auto sent = buffer.take_ranges(3);
    ASSERT_EQ(sent.size(), 1u);
    buffer.mark_lost(0, 3);

    std::vector<coquic::quic::ByteRange> lost;
    auto remember_lost = [&](coquic::quic::ByteRange range) { lost.push_back(std::move(range)); };
    std::size_t empty_lost_budget = 0;
    buffer.consume_lost_ranges(empty_lost_budget, std::nullopt, remember_lost);
    EXPECT_TRUE(lost.empty());

    std::size_t lost_budget = 8;
    buffer.consume_lost_ranges(lost_budget, std::nullopt, remember_lost);
    ASSERT_EQ(lost.size(), 1u);
    EXPECT_EQ(lost[0].offset, 0u);
    EXPECT_EQ(lost[0].bytes, bytes_from_string("abc"));
    EXPECT_EQ(lost_budget, 5u);

    std::vector<coquic::quic::ByteRange> unsent;
    auto remember_unsent = [&](coquic::quic::ByteRange range) {
        unsent.push_back(std::move(range));
    };
    std::size_t empty_unsent_budget = 0;
    buffer.consume_unsent_ranges(empty_unsent_budget, std::nullopt, remember_unsent);
    EXPECT_TRUE(unsent.empty());

    std::size_t unsent_budget = 8;
    buffer.consume_unsent_ranges(unsent_budget, std::nullopt, remember_unsent);
    ASSERT_EQ(unsent.size(), 1u);
    EXPECT_EQ(unsent[0].offset, 3u);
    EXPECT_EQ(unsent[0].bytes, bytes_from_string("def"));
    EXPECT_EQ(unsent_budget, 5u);
}

TEST(QuicCryptoStreamTest, ConsumeRangesCanSplitWithoutMaxOffset) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));
    ASSERT_EQ(buffer.take_unsent_ranges(6).size(), 1u);
    buffer.mark_lost(0, 6);

    std::size_t remaining = 3;
    std::vector<coquic::quic::ByteRange> lost_ranges;
    buffer.consume_lost_ranges(remaining, std::nullopt, [&](coquic::quic::ByteRange range) {
        lost_ranges.push_back(std::move(range));
    });

    ASSERT_EQ(lost_ranges.size(), 1u);
    EXPECT_EQ(lost_ranges.front().offset, 0u);
    EXPECT_EQ(lost_ranges.front().bytes, bytes_from_string("abc"));
    EXPECT_EQ(remaining, 0u);
    EXPECT_TRUE(buffer.has_lost_data());
    EXPECT_TRUE(buffer.has_outstanding_range(3, 3));
}

TEST(QuicCryptoStreamTest, ConsumeRangesCanSkipDifferentStateWithoutMaxOffset) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));
    ASSERT_EQ(buffer.take_unsent_ranges(3).size(), 1u);
    buffer.mark_lost(0, 3);

    std::size_t remaining = 3;
    std::vector<coquic::quic::ByteRange> unsent_ranges;
    buffer.consume_unsent_ranges(remaining, std::nullopt, [&](coquic::quic::ByteRange range) {
        unsent_ranges.push_back(std::move(range));
    });

    ASSERT_EQ(unsent_ranges.size(), 1u);
    EXPECT_EQ(unsent_ranges.front().offset, 3u);
    EXPECT_EQ(unsent_ranges.front().bytes, bytes_from_string("def"));
    EXPECT_EQ(remaining, 0u);
    EXPECT_TRUE(buffer.has_lost_data());
}

TEST(QuicCryptoStreamTest, ConsumeUnsentRangesExtendsAdjacentSentPrefixWithoutExtraSegment) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));
    ASSERT_EQ(buffer.take_unsent_ranges(3).size(), 1u);

    std::size_t remaining = 2;
    std::vector<coquic::quic::ByteRange> unsent_ranges;
    buffer.consume_unsent_ranges(remaining, std::nullopt, [&](coquic::quic::ByteRange range) {
        unsent_ranges.push_back(std::move(range));
    });

    ASSERT_EQ(unsent_ranges.size(), 1u);
    EXPECT_EQ(unsent_ranges.front().offset, 3u);
    EXPECT_EQ(unsent_ranges.front().bytes, bytes_from_string("de"));
    EXPECT_EQ(remaining, 0u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        1u);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);
    EXPECT_TRUE(buffer.has_outstanding_range(0, 5));
    EXPECT_FALSE(buffer.has_outstanding_range(0, 6));

    remaining = 1;
    unsent_ranges.clear();
    buffer.consume_unsent_ranges(remaining, std::nullopt, [&](coquic::quic::ByteRange range) {
        unsent_ranges.push_back(std::move(range));
    });

    ASSERT_EQ(unsent_ranges.size(), 1u);
    EXPECT_EQ(unsent_ranges.front().offset, 5u);
    EXPECT_EQ(unsent_ranges.front().bytes, bytes_from_string("f"));
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        1u);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              0u);
    EXPECT_TRUE(buffer.has_outstanding_range(0, 6));
}

TEST(QuicCryptoStreamTest, ConsumeUnsentRangesExtendsAdjacentSentPrefixWithMaxOffset) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));
    ASSERT_EQ(buffer.take_unsent_ranges(3).size(), 1u);

    std::size_t remaining = 2;
    std::vector<coquic::quic::ByteRange> unsent_ranges;
    buffer.consume_unsent_ranges(remaining, /*max_offset=*/5, [&](coquic::quic::ByteRange range) {
        unsent_ranges.push_back(std::move(range));
    });

    ASSERT_EQ(unsent_ranges.size(), 1u);
    EXPECT_EQ(unsent_ranges.front().offset, 3u);
    EXPECT_EQ(unsent_ranges.front().bytes, bytes_from_string("de"));
    EXPECT_EQ(remaining, 0u);
    ASSERT_EQ(buffer.segments_.size(), 2u);
    EXPECT_EQ(buffer.segments_.begin()->first, 0u);
    EXPECT_EQ(buffer.segments_.begin()->second.state, ReliableSendBuffer::SegmentState::sent);
    EXPECT_EQ(buffer.segments_.begin()->second.end, 5u);
    auto tail = std::next(buffer.segments_.begin());
    ASSERT_NE(tail, buffer.segments_.end());
    EXPECT_EQ(tail->first, 5u);
    EXPECT_EQ(tail->second.state, ReliableSendBuffer::SegmentState::unsent);
    EXPECT_EQ(tail->second.begin, 5u);
    EXPECT_EQ(tail->second.end, 6u);
    EXPECT_EQ(
        buffer
            .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)],
        1u);
    EXPECT_EQ(buffer.segment_state_counts_[send_buffer_state_index(
                  ReliableSendBuffer::SegmentState::unsent)],
              1u);

    remaining = 8;
    unsent_ranges.clear();
    buffer.consume_unsent_ranges(remaining, /*max_offset=*/5, [&](coquic::quic::ByteRange range) {
        unsent_ranges.push_back(std::move(range));
    });

    EXPECT_TRUE(unsent_ranges.empty());
    EXPECT_EQ(remaining, 8u);
}

TEST(QuicCryptoStreamTest, ConsumeUnsentRangesReturnsWhenMaxOffsetMatchesAdjacentSegmentStart) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("abcdef"));
    ASSERT_EQ(buffer.take_unsent_ranges(3).size(), 1u);

    std::size_t remaining = 8;
    std::vector<coquic::quic::ByteRange> unsent_ranges;
    buffer.consume_unsent_ranges(remaining, /*max_offset=*/3, [&](coquic::quic::ByteRange range) {
        unsent_ranges.push_back(std::move(range));
    });

    EXPECT_TRUE(unsent_ranges.empty());
    EXPECT_EQ(remaining, 8u);
    ASSERT_EQ(buffer.segments_.size(), 2u);
    EXPECT_EQ(buffer.segments_.begin()->first, 0u);
    EXPECT_EQ(std::next(buffer.segments_.begin())->first, 3u);
}

TEST(QuicCryptoStreamTest, ConsumeUnsentRangesReturnsForZeroLengthAdjacentSegment) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abc"));
    buffer.segments_.emplace(0, ReliableSendBuffer::Segment{
                                    .state = ReliableSendBuffer::SegmentState::sent,
                                    .storage = storage,
                                    .begin = 0,
                                    .end = 3,
                                });
    buffer.segments_.emplace(3, ReliableSendBuffer::Segment{
                                    .state = ReliableSendBuffer::SegmentState::unsent,
                                    .storage = storage,
                                    .begin = 3,
                                    .end = 3,
                                });
    buffer.segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::sent)] =
        1;
    buffer
        .segment_state_counts_[send_buffer_state_index(ReliableSendBuffer::SegmentState::unsent)] =
        1;
    buffer.next_append_offset_ = 3;

    std::size_t remaining = 8;
    std::vector<coquic::quic::ByteRange> unsent_ranges;
    buffer.consume_unsent_ranges(remaining, /*max_offset=*/4, [&](coquic::quic::ByteRange range) {
        unsent_ranges.push_back(std::move(range));
    });

    EXPECT_TRUE(unsent_ranges.empty());
    EXPECT_EQ(remaining, 8u);
    ASSERT_EQ(buffer.segments_.size(), 2u);
    const auto unsent = std::next(buffer.segments_.begin());
    ASSERT_NE(unsent, buffer.segments_.end());
    EXPECT_EQ(unsent->first, 3u);
    EXPECT_EQ(unsent->second.begin, 3u);
}

TEST(QuicCryptoStreamTest, EmptyStateSpecificRangeReadsReturnNoOffsetsOrRanges) {
    ReliableSendBuffer empty;
    EXPECT_TRUE(empty.take_ranges(/*max_bytes=*/0).empty());
    EXPECT_TRUE(empty.take_lost_ranges(/*max_bytes=*/8).empty());
    EXPECT_TRUE(empty.take_lost_ranges(/*max_bytes=*/0).empty());
    EXPECT_TRUE(empty.take_unsent_ranges(/*max_bytes=*/8).empty());
    EXPECT_TRUE(empty.take_unsent_ranges(/*max_bytes=*/0).empty());
    EXPECT_FALSE(empty.first_lost_offset().has_value());
    EXPECT_FALSE(empty.first_unsent_offset().has_value());

    ReliableSendBuffer sent_only;
    sent_only.append(bytes_from_string("ab"));
    ASSERT_EQ(sent_only.take_ranges(2).size(), 1u);
    EXPECT_TRUE(sent_only.take_lost_ranges(/*max_bytes=*/8).empty());
    EXPECT_TRUE(sent_only.take_lost_ranges(/*max_bytes=*/0).empty());
    EXPECT_TRUE(sent_only.take_unsent_ranges(/*max_bytes=*/8).empty());
    EXPECT_TRUE(sent_only.take_unsent_ranges(/*max_bytes=*/0).empty());
    EXPECT_FALSE(sent_only.first_lost_offset().has_value());
    EXPECT_FALSE(sent_only.first_unsent_offset().has_value());
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

    auto retransmit = buffer.take_ranges(4);
    ASSERT_EQ(retransmit.size(), 2u);
    EXPECT_EQ(retransmit[0].offset, 0u);
    EXPECT_EQ(retransmit[0].bytes, bytes_from_string("ab"));
    EXPECT_EQ(retransmit[1].offset, 2u);
    EXPECT_EQ(retransmit[1].bytes, bytes_from_string("cd"));
}

TEST(QuicCryptoStreamTest, AcknowledgeClampsOverflowingRangeEndToUint64Max) {
    ReliableSendBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));
    insert_segment(buffer, std::numeric_limits<std::uint64_t>::max() - 2,
                   ReliableSendBuffer::SegmentState::sent, storage, 0, 4);

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
    auto first_release = buffer.push(0, bytes_from_string("abcd"));
    ASSERT_TRUE(first_release.has_value());
    EXPECT_EQ(first_release.value(), bytes_from_string("abcdef"));
    auto released = buffer.push(6, bytes_from_string("gh"));
    ASSERT_TRUE(released.has_value());
    EXPECT_EQ(released.value(), bytes_from_string("gh"));
}

TEST(QuicCryptoStreamTest, ReceiveBufferReturnsOnlyUndeliveredTailOfOverlappingWrite) {
    ReliableReceiveBuffer buffer;
    auto first = buffer.push(0, bytes_from_string("abcd"));
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first.value(), bytes_from_string("abcd"));

    auto second = buffer.push(2, bytes_from_string("cdef"));
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second.value(), bytes_from_string("ef"));
}

TEST(QuicCryptoStreamTest, ReceiveBufferSharedPushReturnsAliasedInOrderStorage) {
    ReliableReceiveBuffer buffer;
    auto storage = std::make_shared<std::vector<std::byte>>(bytes_from_string("abcd"));

    auto released = buffer.push_shared(0, SharedBytes(storage, 0, 4));

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
    auto released = buffer.push_shared(0, SharedBytes(early, 0, 4));

    ASSERT_TRUE(released.has_value());
    EXPECT_TRUE(released.value().shared.empty());
    EXPECT_EQ(released.value().owned, bytes_from_string("abcdef"));
}

TEST(QuicCryptoStreamTest, InternalCoverageHelperExercisesSharedCoalescingAndEmptySharedAppend) {
    EXPECT_TRUE(crypto_stream_internal_coverage_for_tests());
}

TEST(QuicCryptoStreamTest, ReceiveBufferReleasesOnlyContiguousBytes) {
    CryptoReceiveBuffer buffer;

    auto first = buffer.push(2, std::vector<std::byte>{std::byte{0xcc}, std::byte{0xdd}});
    ASSERT_TRUE(first.has_value());
    EXPECT_TRUE(first.value().empty());

    auto second = buffer.push(0, std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}});
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second.value(), (std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb},
                                                      std::byte{0xcc}, std::byte{0xdd}}));
}

TEST(QuicCryptoStreamTest, EmptyReceivePushReturnsNoBytes) {
    CryptoReceiveBuffer buffer;

    auto pushed = buffer.push(0, {});

    ASSERT_TRUE(pushed.has_value());
    EXPECT_TRUE(pushed.value().empty());
}

TEST(QuicCryptoStreamTest, RejectsReceiveRangePastMaximumOffset) {
    CryptoReceiveBuffer buffer;

    auto pushed = buffer.push((std::uint64_t{1} << 62) - 1,
                              std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}});

    ASSERT_FALSE(pushed.has_value());
    EXPECT_EQ(pushed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCryptoStreamTest, RejectsReceiveOffsetAboveMaximumOffset) {
    CryptoReceiveBuffer buffer;

    auto pushed = buffer.push((std::uint64_t{1} << 62), std::vector<std::byte>{std::byte{0xaa}});

    ASSERT_FALSE(pushed.has_value());
    EXPECT_EQ(pushed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCryptoStreamTest, OverlappingReceiveBytesDoNotDuplicateOutput) {
    CryptoReceiveBuffer buffer;

    ASSERT_TRUE(
        buffer.push(0, std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}}).has_value());

    auto overlapping = buffer.push(1, std::vector<std::byte>{std::byte{0xbb}, std::byte{0xcc}});

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
