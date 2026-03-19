#include <limits>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/crypto_stream.h"

namespace {

using coquic::quic::CryptoReceiveBuffer;
using coquic::quic::CryptoSendBuffer;

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
