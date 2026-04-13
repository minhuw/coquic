#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
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

std::vector<std::byte> appendix_b2_encoder_instructions() {
    auto bytes = bytes_from_ints({0x3f, 0xbd, 0x01, 0xc0, 0x0f});
    append_ascii_bytes(bytes, "www.example.com");
    bytes.push_back(std::byte{0xc1});
    bytes.push_back(std::byte{0x0c});
    append_ascii_bytes(bytes, "/sample/path");
    return bytes;
}

coquic::http3::Http3Headers appendix_b2_headers() {
    return {
        {":authority", "www.example.com"},
        {":path", "/sample/path"},
    };
}

} // namespace

TEST(QuicHttp3QpackDynamicTest, EncodesAppendixB2DynamicTableExample) {
    auto encoder = make_encoder(220, 8);
    const auto encoded =
        coquic::http3::encode_http3_field_section(encoder, 4, appendix_b2_headers());
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(encoded.value().prefix, bytes_from_ints({0x03, 0x81}));
    EXPECT_EQ(encoded.value().payload, bytes_from_ints({0x10, 0x11}));
    EXPECT_EQ(encoded.value().encoder_instructions, appendix_b2_encoder_instructions());
}

TEST(QuicHttp3QpackDynamicTest, BlocksUntilRequiredInsertCountIsAvailable) {
    auto decoder = make_decoder(220, 1);

    const auto blocked = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x10, 0x11}));
    ASSERT_TRUE(blocked.has_value());
    EXPECT_EQ(blocked.value().status, coquic::http3::Http3QpackDecodeStatus::blocked);
    EXPECT_TRUE(blocked.value().headers.empty());
    EXPECT_EQ(decoder.blocked_streams, 1u);

    const auto unblocked = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, appendix_b2_encoder_instructions());
    ASSERT_TRUE(unblocked.has_value());
    ASSERT_EQ(unblocked.value().size(), 1u);
    EXPECT_EQ(unblocked.value()[0].status, coquic::http3::Http3QpackDecodeStatus::complete);
    EXPECT_EQ(unblocked.value()[0].stream_id, 4u);
    EXPECT_EQ(unblocked.value()[0].headers, appendix_b2_headers());
    EXPECT_EQ(decoder.blocked_streams, 0u);

    const auto decoder_feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(decoder_feedback.has_value());
    EXPECT_EQ(decoder_feedback.value(), bytes_from_ints({0x84}));
}

TEST(QuicHttp3QpackDynamicTest, RejectsAdditionalBlockedFieldSectionOnSameStream) {
    auto decoder = make_decoder(220, 1);

    const auto first = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x10, 0x11}));
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first.value().status, coquic::http3::Http3QpackDecodeStatus::blocked);

    const auto second = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x10, 0x11}));
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
}

TEST(QuicHttp3QpackDynamicTest, RejectsCapacityUpdateThatWouldEvictBlockedReferences) {
    auto decoder = make_decoder(220, 1);

    const auto blocked = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x10, 0x11}));
    ASSERT_TRUE(blocked.has_value());
    EXPECT_EQ(blocked.value().status, coquic::http3::Http3QpackDecodeStatus::blocked);

    auto first_insert = bytes_from_ints({0x3f, 0xbd, 0x01, 0xc0, 0x0f});
    append_ascii_bytes(first_insert, "www.example.com");
    const auto inserted =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, first_insert);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    const auto result = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x3f, 0x01}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
}

TEST(QuicHttp3QpackDynamicTest, RejectsInsertThatWouldEvictBlockedReferences) {
    auto decoder = make_decoder(100, 1);

    const auto blocked = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x10, 0x11}));
    ASSERT_TRUE(blocked.has_value());
    EXPECT_EQ(blocked.value().status, coquic::http3::Http3QpackDecodeStatus::blocked);

    auto first_insert = bytes_from_ints({0x3f, 0x45, 0xc0, 0x0f});
    append_ascii_bytes(first_insert, "www.example.com");
    const auto inserted =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, first_insert);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    auto second_insert = bytes_from_ints({0xc1, 0x0c});
    append_ascii_bytes(second_insert, "/sample/path");
    const auto result =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, second_insert);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
}

TEST(QuicHttp3QpackDynamicTest, CancelsBlockedFieldSectionAndEmitsStreamCancellation) {
    auto decoder = make_decoder(220, 1);

    const auto blocked = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x10, 0x11}));
    ASSERT_TRUE(blocked.has_value());
    EXPECT_EQ(blocked.value().status, coquic::http3::Http3QpackDecodeStatus::blocked);

    const auto cancelled = coquic::http3::cancel_http3_qpack_stream(decoder, 4);
    ASSERT_TRUE(cancelled.has_value());
    EXPECT_EQ(decoder.blocked_streams, 0u);

    const auto decoder_feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(decoder_feedback.has_value());
    EXPECT_EQ(decoder_feedback.value(), bytes_from_ints({0x44}));
}

TEST(QuicHttp3QpackDynamicTest, DecoderFeedbackUpdatesKnownReceivedCountAtEncoder) {
    auto encoder = make_encoder(220, 8);
    auto decoder = make_decoder(220, 8);

    const auto encoded =
        coquic::http3::encode_http3_field_section(encoder, 4, appendix_b2_headers());
    ASSERT_TRUE(encoded.has_value());

    const auto inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, encoded.value().encoder_instructions);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    const auto decoded = coquic::http3::decode_http3_field_section(
        decoder, 4, encoded.value().prefix, encoded.value().payload);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().status, coquic::http3::Http3QpackDecodeStatus::complete);

    const auto decoder_feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(decoder_feedback.has_value());
    EXPECT_EQ(decoder_feedback.value(), bytes_from_ints({0x84}));

    const auto processed =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, decoder_feedback.value());
    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(encoder.known_received_count, 2u);
}

TEST(QuicHttp3QpackDynamicTest, EmitsInsertCountIncrementForSpeculativeInsert) {
    auto decoder = make_decoder(220, 8);
    const auto processed = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder,
        bytes_from_ints({
            0x3f, 0xbd, 0x01, 0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
            0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
        }));
    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(processed.value().empty());

    const auto feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(feedback.has_value());
    EXPECT_EQ(feedback.value(), bytes_from_ints({0x01}));
}

TEST(QuicHttp3QpackDynamicTest, RejectsCapacityUpdateAbovePeerSetting) {
    auto decoder = make_decoder(32, 1);
    const auto result = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x3f, 0x21}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
}
