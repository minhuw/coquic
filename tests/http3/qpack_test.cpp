#include <array>
#include <initializer_list>
#include <vector>

#include <gtest/gtest.h>

#include "src/http3/http3_qpack.h"

namespace {

std::vector<std::byte> bytes_from_ints(std::initializer_list<unsigned int> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const unsigned int value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

TEST(QuicHttp3QpackTest, EncodesAndDecodesStaticTableRequestHeaders) {
    const coquic::http3::Http3Headers headers = {
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "example.test"},
        {":path", "/index.html"},
    };

    const auto encoded = coquic::http3::encode_http3_field_section(headers);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::http3::decode_http3_field_section(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), headers);
}

TEST(QuicHttp3QpackTest, RejectsDynamicTableInstructionsWhenCapacityIsZero) {
    const std::array encoder_bytes{
        std::byte{0x3f},
        std::byte{0xe1},
        std::byte{0x1f},
    };
    const auto result = coquic::http3::validate_http3_qpack_encoder_stream(
        encoder_bytes,
        coquic::http3::Http3QpackSettings{.max_table_capacity = 0, .blocked_streams = 0});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
}

TEST(QuicHttp3QpackTest, RejectsDecoderInstructionsWhenBlockedStreamsIsZero) {
    const std::array decoder_bytes{
        std::byte{0x80},
    };
    const auto result = coquic::http3::validate_http3_qpack_decoder_stream(
        decoder_bytes,
        coquic::http3::Http3QpackSettings{.max_table_capacity = 0, .blocked_streams = 0});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decoder_stream_error);
}

TEST(QuicHttp3QpackTest, RejectsMalformedLiteralFieldSection) {
    const std::array malformed{std::byte{0xff}, std::byte{0xff}};
    const auto decoded = coquic::http3::decode_http3_field_section(malformed);
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
}

TEST(QuicHttp3QpackTest, RejectsLiteralFieldsLongerThanSingleByteLengthPrefix) {
    const coquic::http3::Http3Headers long_name_headers = {{
        .name = std::string(256, 'n'),
        .value = "value",
    }};

    const auto encoded_long_name = coquic::http3::encode_http3_field_section(long_name_headers);
    ASSERT_FALSE(encoded_long_name.has_value());
    EXPECT_EQ(encoded_long_name.error().code, coquic::quic::CodecErrorCode::http3_parse_error);
    EXPECT_EQ(encoded_long_name.error().offset, 0);

    const coquic::http3::Http3Headers long_value_headers = {{
        .name = "name",
        .value = std::string(256, 'v'),
    }};

    const auto encoded_long_value = coquic::http3::encode_http3_field_section(long_value_headers);
    ASSERT_FALSE(encoded_long_value.has_value());
    EXPECT_EQ(encoded_long_value.error().code, coquic::quic::CodecErrorCode::http3_parse_error);
    EXPECT_EQ(encoded_long_value.error().offset, 0);
}

TEST(QuicHttp3QpackTest, AcceptsEmptyInstructionsWhenDynamicTableAndBlockedStreamsAreZero) {
    const std::array<std::byte, 0> empty_bytes{};
    const auto settings =
        coquic::http3::Http3QpackSettings{.max_table_capacity = 0, .blocked_streams = 0};

    const auto encoder = coquic::http3::validate_http3_qpack_encoder_stream(empty_bytes, settings);
    ASSERT_TRUE(encoder.has_value());
    EXPECT_TRUE(encoder.value());

    const auto decoder = coquic::http3::validate_http3_qpack_decoder_stream(empty_bytes, settings);
    ASSERT_TRUE(decoder.has_value());
    EXPECT_TRUE(decoder.value());
}

TEST(QuicHttp3QpackTest, RejectsMalformedAndTruncatedLiteralFieldSections) {
    for (const auto &[bytes, detail] : std::array{
             std::pair{bytes_from_ints({0x20, 0x00}), std::string_view{"malformed literal field"}},
             std::pair{bytes_from_ints({0x20, 0x01, 'n'}),
                       std::string_view{"truncated literal field name"}},
             std::pair{bytes_from_ints({0x20, 0x01, 'n', 0x02, 'v'}),
                       std::string_view{"truncated literal field value"}},
         }) {
        const auto decoded = coquic::http3::decode_http3_field_section(bytes);
        ASSERT_FALSE(decoded.has_value());
        EXPECT_EQ(decoded.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
        EXPECT_EQ(decoded.error().detail, detail);
    }
}

TEST(QuicHttp3QpackTest, RejectsWrongLiteralPrefixesAndOutOfRangeStaticIndexes) {
    const auto wrong_prefix = coquic::http3::decode_http3_field_section(bytes_from_ints({
        0x00,
        0x01,
        'n',
        0x01,
        'v',
    }));
    ASSERT_FALSE(wrong_prefix.has_value());
    EXPECT_EQ(wrong_prefix.error().detail, "malformed literal field");

    const auto out_of_range = coquic::http3::decode_http3_field_section(bytes_from_ints({
        0x80,
        0x0a,
    }));
    ASSERT_FALSE(out_of_range.has_value());
    EXPECT_EQ(out_of_range.error().detail, "invalid static table index");
}

TEST(QuicHttp3QpackTest, AcceptsNonEmptyEncoderAndDecoderInstructionsWhenSettingsAllowThem) {
    const auto encoder = coquic::http3::validate_http3_qpack_encoder_stream(
        bytes_from_ints({0x3f, 0xe1, 0x1f}),
        coquic::http3::Http3QpackSettings{.max_table_capacity = 32, .blocked_streams = 0});
    ASSERT_TRUE(encoder.has_value());
    EXPECT_TRUE(encoder.value());

    const auto decoder = coquic::http3::validate_http3_qpack_decoder_stream(
        bytes_from_ints({0x80}),
        coquic::http3::Http3QpackSettings{.max_table_capacity = 0, .blocked_streams = 1});
    ASSERT_TRUE(decoder.has_value());
    EXPECT_TRUE(decoder.value());
}

} // namespace
