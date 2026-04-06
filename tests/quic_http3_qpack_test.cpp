#include <array>

#include <gtest/gtest.h>

#include "src/quic/http3_qpack.h"

namespace {

TEST(QuicHttp3QpackTest, EncodesAndDecodesStaticTableRequestHeaders) {
    const coquic::quic::Http3Headers headers = {
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "example.test"},
        {":path", "/index.html"},
    };

    const auto encoded = coquic::quic::encode_http3_field_section(headers);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::decode_http3_field_section(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), headers);
}

TEST(QuicHttp3QpackTest, RejectsDynamicTableInstructionsWhenCapacityIsZero) {
    const std::array encoder_bytes{
        std::byte{0x3f},
        std::byte{0xe1},
        std::byte{0x1f},
    };
    const auto result = coquic::quic::validate_http3_qpack_encoder_stream(
        encoder_bytes,
        coquic::quic::Http3QpackSettings{.max_table_capacity = 0, .blocked_streams = 0});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::Http3ErrorCode::qpack_encoder_stream_error);
}

TEST(QuicHttp3QpackTest, RejectsDecoderInstructionsWhenBlockedStreamsIsZero) {
    const std::array decoder_bytes{
        std::byte{0x80},
    };
    const auto result = coquic::quic::validate_http3_qpack_decoder_stream(
        decoder_bytes,
        coquic::quic::Http3QpackSettings{.max_table_capacity = 0, .blocked_streams = 0});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::Http3ErrorCode::qpack_decoder_stream_error);
}

TEST(QuicHttp3QpackTest, RejectsMalformedLiteralFieldSection) {
    const std::array malformed{std::byte{0xff}, std::byte{0xff}};
    const auto decoded = coquic::quic::decode_http3_field_section(malformed);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::quic::Http3ErrorCode::qpack_decompression_failed);
}

TEST(QuicHttp3QpackTest, RejectsLiteralFieldsLongerThanSingleByteLengthPrefix) {
    const coquic::quic::Http3Headers headers = {{
        .name = std::string(256, 'n'),
        .value = "value",
    }};

    const auto encoded = coquic::quic::encode_http3_field_section(headers);
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::http3_parse_error);
    EXPECT_EQ(encoded.error().offset, 0);
}

} // namespace
