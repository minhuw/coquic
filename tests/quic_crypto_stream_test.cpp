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

std::vector<std::byte> bytes_from_string(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const char ch : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return bytes;
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

TEST(QuicCryptoStreamTest, TakeRangesWithZeroBudgetPreservesPendingBytes) {
    ReliableSendBuffer buffer;
    buffer.append(bytes_from_string("ab"));

    const auto ranges = buffer.take_ranges(0);

    EXPECT_TRUE(ranges.empty());
    EXPECT_TRUE(buffer.has_pending_data());
    EXPECT_FALSE(buffer.has_outstanding_data());
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

} // namespace
