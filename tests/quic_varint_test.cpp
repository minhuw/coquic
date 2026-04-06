#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/buffer.h"
#include "src/quic/varint.h"

namespace {

[[gnu::noinline]] std::uint64_t runtime_quic_varint(std::uint64_t value) {
    volatile std::uint64_t runtime_value = value;
    return runtime_value;
}

} // namespace

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

TEST(QuicVarIntTest, ReportsEncodedSizesAcrossAllQuicVarIntWidths) {
    EXPECT_EQ(coquic::quic::encoded_varint_size(63ull), 1u);
    EXPECT_EQ(coquic::quic::encoded_varint_size(16383ull), 2u);
    EXPECT_EQ(coquic::quic::encoded_varint_size(1073741823ull), 4u);
    EXPECT_EQ(coquic::quic::encoded_varint_size(1073741824ull), 8u);
}

TEST(QuicVarIntTest, EncodesEightByteVarintsFromRuntimeValue) {
    const auto runtime_value = runtime_quic_varint(1073741824ull);

    EXPECT_EQ(coquic::quic::encoded_varint_size(runtime_value), 8u);

    const auto encoded = coquic::quic::encode_varint(runtime_value);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(encoded.value().size(), 8u);
}

TEST(QuicVarIntTest, ReportsEightByteWidthForMaximumRuntimeValue) {
    const auto max_value = runtime_quic_varint(4611686018427387903ull);

    EXPECT_EQ(coquic::quic::encoded_varint_size(max_value), 8u);
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
