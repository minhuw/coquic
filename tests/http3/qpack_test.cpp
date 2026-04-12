#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "src/http3/http3_qpack.h"

namespace {

std::vector<std::byte> bytes_from_ints(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

void append_ascii_bytes(std::vector<std::byte> &bytes, std::string_view text) {
    bytes.insert(bytes.end(), reinterpret_cast<const std::byte *>(text.data()),
                 reinterpret_cast<const std::byte *>(text.data()) + text.size());
}

coquic::http3::Http3QpackEncoderContext make_encoder(std::uint64_t max_table_capacity = 0,
                                                     std::uint64_t blocked_streams = 0) {
    return coquic::http3::Http3QpackEncoderContext{
        .peer_settings =
            {
                .max_table_capacity = max_table_capacity,
                .blocked_streams = blocked_streams,
            },
    };
}

coquic::http3::Http3QpackDecoderContext make_decoder(std::uint64_t max_table_capacity = 0,
                                                     std::uint64_t blocked_streams = 0) {
    return coquic::http3::Http3QpackDecoderContext{
        .local_settings =
            {
                .max_table_capacity = max_table_capacity,
                .blocked_streams = blocked_streams,
            },
    };
}

} // namespace

TEST(QuicHttp3QpackTest, EncodesAndDecodesStaticTableRequestHeaders) {
    auto encoder = make_encoder();
    auto decoder = make_decoder();
    const coquic::http3::Http3Headers headers = {
        {":method", "GET"},
        {":scheme", "https"},
        {":path", "/"},
        {"accept-encoding", "gzip, deflate, br"},
    };

    const auto encoded = coquic::http3::encode_http3_field_section(encoder, 0, headers);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_TRUE(encoded.value().encoder_instructions.empty());
    EXPECT_EQ(encoded.value().prefix, bytes_from_ints({0x00, 0x00}));

    const auto decoded = coquic::http3::decode_http3_field_section(
        decoder, 0, encoded.value().prefix, encoded.value().payload);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().status, coquic::http3::Http3QpackDecodeStatus::complete);
    EXPECT_EQ(decoded.value().headers, headers);
}

TEST(QuicHttp3QpackTest, DecodesHuffmanLiteralWithStaticNameReference) {
    auto decoder = make_decoder();
    const auto decoded =
        coquic::http3::decode_http3_field_section(decoder, 0, bytes_from_ints({0x00, 0x00}),
                                                  bytes_from_ints({
                                                      0x50,
                                                      0x8c,
                                                      0xf1,
                                                      0xe3,
                                                      0xc2,
                                                      0xe5,
                                                      0xf2,
                                                      0x3a,
                                                      0x6b,
                                                      0xa0,
                                                      0xab,
                                                      0x90,
                                                      0xf4,
                                                      0xff,
                                                  }));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().status, coquic::http3::Http3QpackDecodeStatus::complete);
    EXPECT_EQ(decoded.value().headers,
              (coquic::http3::Http3Headers{{":authority", "www.example.com"}}));
}

TEST(QuicHttp3QpackTest, RejectsMalformedFieldSectionPrefix) {
    auto decoder = make_decoder();
    const auto decoded =
        coquic::http3::decode_http3_field_section(decoder, 0, bytes_from_ints({0x00}), {});
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
}

TEST(QuicHttp3QpackTest, RejectsIndexedFieldLineWithInvalidStaticIndex) {
    auto decoder = make_decoder();
    const auto decoded = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0xff, 0x25}));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(decoded.error().detail, "invalid static table index");
}

TEST(QuicHttp3QpackTest, RejectsLiteralNameReferenceWithInvalidStaticIndex) {
    auto decoder = make_decoder();
    const auto decoded = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0x5f, 0x55}));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(decoded.error().detail, "invalid static table name reference");
}

TEST(QuicHttp3QpackTest, RejectsDecoderStreamIncrementBeyondSentInsertCount) {
    auto encoder = make_encoder(220, 8);
    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x01}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decoder_stream_error);
}

TEST(QuicHttp3QpackTest, AcceptsDecoderStreamIncrementForMirroredEncoderState) {
    auto encoder = make_encoder(220, 8);
    auto decoder = make_decoder(220, 8);

    const coquic::http3::Http3Headers headers = {
        {"custom-key", "custom-value"},
    };
    const auto encoded = coquic::http3::encode_http3_field_section(encoder, 0, headers);
    ASSERT_TRUE(encoded.has_value());

    const auto inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, encoded.value().encoder_instructions);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    const auto decoder_feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(decoder_feedback.has_value());
    EXPECT_EQ(decoder_feedback.value(), bytes_from_ints({0x01}));

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, decoder_feedback.value());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(encoder.known_received_count, 1u);
}
