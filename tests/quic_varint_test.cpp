#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/buffer.h"
#include "src/quic/varint.h"

TEST(QuicVarIntTest, RoundTripsBoundaryValues) {
    for (std::uint64_t value : {
             0ull,
             63ull,
             64ull,
             16383ull,
             16384ull,
             1073741823ull,
             1073741824ull,
             4611686018427387903ull,
         }) {
        auto encoded = coquic::quic::encode_varint(value);
        ASSERT_TRUE(encoded.has_value());

        auto decoded = coquic::quic::decode_varint_bytes(encoded.value());
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded.value().value, value);
        EXPECT_EQ(decoded.value().bytes_consumed, encoded.value().size());
    }
}

TEST(QuicVarIntTest, RejectsTruncatedEncoding) {
    std::array<std::byte, 1> bytes{std::byte{0x40}};
    auto decoded = coquic::quic::decode_varint_bytes(bytes);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicVarIntTest, BufferReaderRejectsTruncatedExactReads) {
    const std::array<std::byte, 1> bytes{std::byte{0x01}};
    coquic::quic::BufferReader reader(bytes);

    const auto result = reader.read_exact(2);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::CodecErrorCode::truncated_input);
    EXPECT_EQ(result.error().offset, 0u);
}

TEST(QuicVarIntTest, EncodeVarintRejectsValuesAboveMaximum) {
    const auto encoded = coquic::quic::encode_varint(4611686018427387904ull);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicVarIntTest, DecodeVarintRejectsEmptyReader) {
    const std::array<std::byte, 0> bytes{};
    coquic::quic::BufferReader reader(bytes);

    const auto decoded = coquic::quic::decode_varint(reader);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::CodecErrorCode::truncated_input);
    EXPECT_EQ(decoded.error().offset, 0u);
}
