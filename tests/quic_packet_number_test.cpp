#include <cstdint>
#include <optional>

#include <gtest/gtest.h>

#include "src/quic/packet_number.h"

namespace {

TEST(QuicPacketNumberTest, RecoversPacketNumberFromRfc9000AppendixA3Example) {
    const auto recovered = coquic::quic::recover_packet_number(0xa82f30eaULL, 0x9b32U, 2);
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered.value(), 0xa82f9b32ULL);
}

TEST(QuicPacketNumberTest, RecoversFirstPacketWhenLargestAuthenticatedIsMissing) {
    const auto recovered = coquic::quic::recover_packet_number(std::nullopt, 0U, 1);
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered.value(), 0ULL);
}

TEST(QuicPacketNumberTest, RejectsInvalidPacketNumberLength) {
    const auto recovered = coquic::quic::recover_packet_number(7ULL, 1U, 0);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicPacketNumberTest, RejectsPacketNumberLengthAboveFourBytes) {
    const auto truncated = coquic::quic::truncate_packet_number(1ULL, 5);
    ASSERT_FALSE(truncated.has_value());
    EXPECT_EQ(truncated.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicPacketNumberTest, RejectsTruncatedPacketNumberThatExceedsDeclaredLength) {
    const auto recovered = coquic::quic::recover_packet_number(7ULL, 0x1234U, 1);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicPacketNumberTest, RejectsLargestAuthenticatedPacketNumberAtQuicLimit) {
    const auto recovered = coquic::quic::recover_packet_number((1ULL << 62) - 1, 1U, 1);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error().code, coquic::quic::CodecErrorCode::packet_number_recovery_failed);
}

TEST(QuicPacketNumberTest, RejectsPacketNumbersPastQuicLimitDuringTruncation) {
    const auto truncated = coquic::quic::truncate_packet_number(1ULL << 62, 4);
    ASSERT_FALSE(truncated.has_value());
    EXPECT_EQ(truncated.error().code, coquic::quic::CodecErrorCode::packet_number_recovery_failed);
}

TEST(QuicPacketNumberTest, TruncatesPacketNumberToRequestedLength) {
    const auto truncated = coquic::quic::truncate_packet_number(0x12345678ULL, 2);
    ASSERT_TRUE(truncated.has_value());
    EXPECT_EQ(truncated.value(), 0x5678U);
}

} // namespace
