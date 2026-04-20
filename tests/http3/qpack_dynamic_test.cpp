#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
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

void prime_appendix_b2_decoder(coquic::http3::Http3QpackDecoderContext &decoder) {
    const auto inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, appendix_b2_encoder_instructions());
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());
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

TEST(QuicHttp3QpackDynamicTest, EncodesAcknowledgedDynamicFieldAsRelativeIndexedReference) {
    auto encoder = make_encoder(64, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_TRUE(first.has_value());

    encoder.known_received_count = 1;
    const auto second = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(second.value().encoder_instructions.empty());
    EXPECT_EQ(second.value().prefix, bytes_from_ints({0x02, 0x00}));
    EXPECT_EQ(second.value().payload, bytes_from_ints({0x80}));
}

TEST(QuicHttp3QpackDynamicTest, EncodesLiteralWithDynamicNameReferenceWhenEntryIsTooLargeToInsert) {
    auto encoder = make_encoder(64, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_TRUE(first.has_value());

    const std::string large_value(22, 'x');
    const auto second = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"custom-name", large_value}});
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(second.value().encoder_instructions.empty());
    EXPECT_EQ(second.value().prefix, bytes_from_ints({0x02, 0x00}));

    auto expected_payload = bytes_from_ints({0x40, 0x16});
    append_ascii_bytes(expected_payload, large_value);
    EXPECT_EQ(second.value().payload, expected_payload);
}

TEST(QuicHttp3QpackDynamicTest, FallsBackToLiteralNameWhenDynamicReferencesAreDisallowed) {
    auto encoder = make_encoder(64, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_TRUE(first.has_value());

    encoder.peer_settings.blocked_streams = 0;
    const auto second = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"custom-name", "two"}});
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(second.value().encoder_instructions.empty());
    EXPECT_EQ(second.value().prefix, bytes_from_ints({0x00, 0x00}));

    auto expected_payload = bytes_from_ints({0x27, 0x04});
    append_ascii_bytes(expected_payload, "custom-name");
    expected_payload.push_back(std::byte{0x03});
    append_ascii_bytes(expected_payload, "two");
    EXPECT_EQ(second.value().payload, expected_payload);
}

TEST(QuicHttp3QpackDynamicTest, FallsBackWhenExactDynamicFieldCannotBeReferenced) {
    auto encoder = make_encoder(64, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_TRUE(first.has_value());

    encoder.peer_settings.blocked_streams = 0;
    const auto second = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(second.value().encoder_instructions.empty());
    EXPECT_EQ(second.value().prefix, bytes_from_ints({0x00, 0x00}));

    auto expected_payload = bytes_from_ints({0x27, 0x04});
    append_ascii_bytes(expected_payload, "custom-name");
    expected_payload.push_back(std::byte{0x03});
    append_ascii_bytes(expected_payload, "one");
    EXPECT_EQ(second.value().payload, expected_payload);
}

TEST(QuicHttp3QpackDynamicTest, RejectsEncodingWhenPeerCapacityAllowsNoQpackEntries) {
    auto encoder = make_encoder(64, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_TRUE(first.has_value());

    encoder.peer_settings.max_table_capacity = 16;
    encoder.known_received_count = 1;

    const auto encoded = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, coquic::quic::CodecErrorCode::http3_parse_error);
    EXPECT_EQ(encoded.error().offset, 0u);
}

TEST(QuicHttp3QpackDynamicTest, IgnoresAcknowledgedOutstandingSectionOnSameStream) {
    auto encoder = make_encoder(64, 8);
    encoder.outstanding_field_sections = {
        coquic::http3::Http3QpackOutstandingFieldSection{
            .stream_id = 4,
            .required_insert_count = 1,
        },
    };
    encoder.known_received_count = 1;

    const auto encoded = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{":method", "GET"}});
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(encoded.value().prefix, bytes_from_ints({0x00, 0x00}));
    EXPECT_EQ(encoded.value().payload, bytes_from_ints({0xd1}));
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

TEST(QuicHttp3QpackDynamicTest, BlockedFieldSectionCollectsReferencesAcrossRepresentations) {
    auto decoder = make_decoder(220, 8);

    const auto blocked = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}),
        bytes_from_ints(
            {0xc0, 0x80, 0x10, 0x40, 0x01, 0x78, 0x00, 0x01, 0x79, 0x21, 0x6e, 0x01, 0x76}));
    ASSERT_TRUE(blocked.has_value());
    EXPECT_EQ(blocked.value().status, coquic::http3::Http3QpackDecodeStatus::blocked);
    ASSERT_EQ(decoder.pending_field_sections.size(), 1u);
    EXPECT_EQ(decoder.pending_field_sections[0].referenced_entries,
              (std::vector<std::uint64_t>{0, 1}));
}

TEST(QuicHttp3QpackDynamicTest, RejectsFieldSectionWithInvalidBase) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x82}), bytes_from_ints({0x10}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid field section base");
}

TEST(QuicHttp3QpackDynamicTest, RejectsNonZeroRequiredInsertCountWhenDynamicTableCapacityIsZero) {
    auto decoder = make_decoder(0, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x01, 0x00}), bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsRequiredInsertCountEncodingPastFullRange) {
    auto decoder = make_decoder(64, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x05, 0x00}), bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsRequiredInsertCountThatWrapsToZero) {
    auto decoder = make_decoder(64, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x01, 0x00}), bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsRequiredInsertCountEncodingInInvalidWrappedWindow) {
    auto decoder = make_decoder(64, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x04, 0x00}), bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedFieldSectionWithTruncatedLiteralValue) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x40}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
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

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedFieldSectionWhenBlockedStreamLimitIsExceeded) {
    auto decoder = make_decoder(220, 1);

    const auto first = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x10, 0x11}));
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first.value().status, coquic::http3::Http3QpackDecodeStatus::blocked);

    const auto second = coquic::http3::decode_http3_field_section(
        decoder, 8, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x10, 0x11}));
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(second.error().detail, "too many blocked streams");
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

TEST(QuicHttp3QpackDynamicTest, DecodesDynamicFieldRepresentationsAgainstDynamicTable) {
    auto decoder = make_decoder(220, 8);
    prime_appendix_b2_decoder(decoder);

    const auto decoded = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}),
        bytes_from_ints({0x80, 0x10, 0x40, 0x01, 0x78, 0x00, 0x01, 0x79, 0x21, 0x6e, 0x01, 0x76}));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().status, coquic::http3::Http3QpackDecodeStatus::complete);
    EXPECT_EQ(decoded.value().headers, (coquic::http3::Http3Headers{
                                           {":authority", "www.example.com"},
                                           {":path", "/sample/path"},
                                           {":authority", "x"},
                                           {":path", "y"},
                                           {"n", "v"},
                                       }));
    ASSERT_EQ(decoder.pending_section_acknowledgments.size(), 1u);
    EXPECT_EQ(decoder.pending_section_acknowledgments[0].stream_id, 4u);
    EXPECT_EQ(decoder.pending_section_acknowledgments[0].required_insert_count, 2u);
}

TEST(QuicHttp3QpackDynamicTest, RejectsMalformedDynamicIndexedFieldLine) {
    auto decoder = make_decoder(220, 8);
    prime_appendix_b2_decoder(decoder);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0xbf}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed indexed field line");
}

TEST(QuicHttp3QpackDynamicTest, RejectsDynamicLiteralNameReferenceWithTruncatedValue) {
    auto decoder = make_decoder(220, 8);
    prime_appendix_b2_decoder(decoder);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x40}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
}

TEST(QuicHttp3QpackDynamicTest, CancellingCompletedStreamDropsAckAndDeduplicatesCancellation) {
    auto encoder = make_encoder(220, 8);
    auto decoder = make_decoder(220, 8);

    const auto encoded =
        coquic::http3::encode_http3_field_section(encoder, 4, appendix_b2_headers());
    ASSERT_TRUE(encoded.has_value());

    const auto inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, encoded.value().encoder_instructions);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    const auto first_decode = coquic::http3::decode_http3_field_section(
        decoder, 4, encoded.value().prefix, encoded.value().payload);
    ASSERT_TRUE(first_decode.has_value());
    EXPECT_EQ(first_decode.value().status, coquic::http3::Http3QpackDecodeStatus::complete);

    const auto first_cancel = coquic::http3::cancel_http3_qpack_stream(decoder, 4);
    ASSERT_TRUE(first_cancel.has_value());

    const auto second_decode = coquic::http3::decode_http3_field_section(
        decoder, 4, encoded.value().prefix, encoded.value().payload);
    ASSERT_TRUE(second_decode.has_value());
    EXPECT_EQ(second_decode.value().status, coquic::http3::Http3QpackDecodeStatus::complete);

    const auto second_cancel = coquic::http3::cancel_http3_qpack_stream(decoder, 4);
    ASSERT_TRUE(second_cancel.has_value());

    const auto decoder_feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(decoder_feedback.has_value());
    EXPECT_EQ(decoder_feedback.value(), bytes_from_ints({0x44, 0x02}));
}

TEST(QuicHttp3QpackDynamicTest, CancellingUnknownStreamLeavesFeedbackUnchanged) {
    auto decoder = make_decoder(220, 8);

    const auto cancelled = coquic::http3::cancel_http3_qpack_stream(decoder, 99);
    ASSERT_TRUE(cancelled.has_value());

    const auto decoder_feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(decoder_feedback.has_value());
    EXPECT_TRUE(decoder_feedback.value().empty());
}

TEST(QuicHttp3QpackDynamicTest, CancellingDifferentStreamLeavesPendingVectorsInPlace) {
    auto decoder = make_decoder(220, 8);
    decoder.pending_field_sections = {
        coquic::http3::Http3QpackPendingFieldSection{
            .stream_id = 8,
            .required_insert_count = 2,
            .base = 1,
            .payload = bytes_from_ints({0x80}),
            .referenced_entries = {0},
        },
    };
    decoder.pending_section_acknowledgments = {
        coquic::http3::Http3QpackSectionAcknowledgment{
            .stream_id = 8,
            .required_insert_count = 2,
        },
    };
    decoder.blocked_streams = 1;

    const auto cancelled = coquic::http3::cancel_http3_qpack_stream(decoder, 4);
    ASSERT_TRUE(cancelled.has_value());
    ASSERT_EQ(decoder.pending_field_sections.size(), 1u);
    EXPECT_EQ(decoder.pending_field_sections[0].stream_id, 8u);
    ASSERT_EQ(decoder.pending_section_acknowledgments.size(), 1u);
    EXPECT_EQ(decoder.pending_section_acknowledgments[0].stream_id, 8u);
    EXPECT_EQ(decoder.blocked_streams, 1u);

    const auto decoder_feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(decoder_feedback.has_value());
    EXPECT_EQ(decoder_feedback.value(), bytes_from_ints({0x88}));
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

TEST(QuicHttp3QpackDynamicTest, RejectsMalformedSectionAcknowledgment) {
    auto encoder = make_encoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0xff}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decoder_stream_error);
    EXPECT_EQ(result.error().detail, "malformed section acknowledgment");
}

TEST(QuicHttp3QpackDynamicTest, RejectsUnknownSectionAcknowledgment) {
    auto encoder = make_encoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x84}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decoder_stream_error);
    EXPECT_EQ(result.error().detail, "unknown section acknowledgment");
}

TEST(QuicHttp3QpackDynamicTest, RejectsMalformedStreamCancellation) {
    auto encoder = make_encoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x7f}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decoder_stream_error);
    EXPECT_EQ(result.error().detail, "malformed stream cancellation");
}

TEST(QuicHttp3QpackDynamicTest, CancelsOnlyMatchingOutstandingFieldSections) {
    auto encoder = make_encoder(220, 8);

    const auto first = coquic::http3::encode_http3_field_section(encoder, 4, appendix_b2_headers());
    ASSERT_TRUE(first.has_value());
    const auto second =
        coquic::http3::encode_http3_field_section(encoder, 4, appendix_b2_headers());
    ASSERT_TRUE(second.has_value());
    const auto third = coquic::http3::encode_http3_field_section(encoder, 8, appendix_b2_headers());
    ASSERT_TRUE(third.has_value());

    ASSERT_EQ(encoder.outstanding_field_sections.size(), 3u);
    for (const auto &entry : encoder.dynamic_table) {
        EXPECT_EQ(entry.outstanding_references, 3u);
    }

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x44}));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(encoder.outstanding_field_sections.size(), 1u);
    EXPECT_EQ(encoder.outstanding_field_sections[0].stream_id, 8u);
    for (const auto &entry : encoder.dynamic_table) {
        EXPECT_EQ(entry.outstanding_references, 1u);
    }
}

TEST(QuicHttp3QpackDynamicTest, IgnoresStreamCancellationForUnknownOutstandingFieldSection) {
    auto encoder = make_encoder(220, 8);

    const auto first = coquic::http3::encode_http3_field_section(encoder, 4, appendix_b2_headers());
    ASSERT_TRUE(first.has_value());
    const auto second =
        coquic::http3::encode_http3_field_section(encoder, 8, appendix_b2_headers());
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(encoder.outstanding_field_sections.size(), 2u);

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x41}));
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(encoder.outstanding_field_sections.size(), 2u);
    EXPECT_EQ(encoder.outstanding_field_sections[0].stream_id, 4u);
    EXPECT_EQ(encoder.outstanding_field_sections[1].stream_id, 8u);
}

TEST(QuicHttp3QpackDynamicTest, RejectsMalformedInsertCountIncrement) {
    auto encoder = make_encoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x3f}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decoder_stream_error);
    EXPECT_EQ(result.error().detail, "invalid insert count increment");
}

TEST(QuicHttp3QpackDynamicTest, RejectsZeroInsertCountIncrement) {
    auto encoder = make_encoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decoder_stream_error);
    EXPECT_EQ(result.error().detail, "invalid insert count increment");
}

TEST(QuicHttp3QpackDynamicTest, RejectsOverflowingInsertCountIncrement) {
    auto encoder = make_encoder(220, 8);
    encoder.insert_count = std::numeric_limits<std::uint64_t>::max();
    encoder.known_received_count = std::numeric_limits<std::uint64_t>::max();

    const auto result =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x01}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decoder_stream_error);
    EXPECT_EQ(result.error().detail, "insert count increment exceeds sent state");
}

TEST(QuicHttp3QpackDynamicTest, ProcessesDynamicNameReferenceAndDuplicateInstructions) {
    auto encoder = make_encoder(220, 8);
    auto decoder = make_decoder(220, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"custom-name", "one"}});
    ASSERT_TRUE(first.has_value());
    const auto first_inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, first.value().encoder_instructions);
    ASSERT_TRUE(first_inserted.has_value());
    EXPECT_TRUE(first_inserted.value().empty());

    const auto second = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"custom-name", "two"}});
    ASSERT_TRUE(second.has_value());
    ASSERT_FALSE(second.value().encoder_instructions.empty());
    EXPECT_EQ(std::to_integer<std::uint8_t>(second.value().encoder_instructions.front()) & 0x80u,
              0x80u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(second.value().encoder_instructions.front()) & 0x40u,
              0x00u);

    const auto second_inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, second.value().encoder_instructions);
    ASSERT_TRUE(second_inserted.has_value());
    EXPECT_TRUE(second_inserted.value().empty());
    EXPECT_EQ(decoder.insert_count, 2u);

    const auto duplicated =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({0x00}));
    ASSERT_TRUE(duplicated.has_value());
    EXPECT_TRUE(duplicated.value().empty());
    EXPECT_EQ(decoder.insert_count, 3u);
}

TEST(QuicHttp3QpackDynamicTest, RejectsMalformedCapacityUpdate) {
    auto decoder = make_decoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({0x3f}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "malformed capacity update");
}

TEST(QuicHttp3QpackDynamicTest, RejectsInvalidDynamicNameReferenceInstruction) {
    auto decoder = make_decoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({0x80}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "invalid dynamic table name reference");
}

TEST(QuicHttp3QpackDynamicTest, RejectsDynamicInsertionWithoutCapacityUpdate) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0xc0, 0x01, 0x61}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "dynamic table insertion without capacity");
}

TEST(QuicHttp3QpackDynamicTest, RejectsDynamicEntryLargerThanCapacity) {
    auto decoder = make_decoder(32, 8);

    const auto result = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x3f, 0x01, 0xc0, 0x01, 0x61}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "dynamic table entry exceeds capacity");
}

TEST(QuicHttp3QpackDynamicTest, RejectsInvalidStaticNameReferenceInstruction) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0xff, 0x25}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "invalid static table name reference");
}

TEST(QuicHttp3QpackDynamicTest, RejectsInsertWithNameReferenceMissingValue) {
    auto decoder = make_decoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({0xc0}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "truncated insert value");
}

TEST(QuicHttp3QpackDynamicTest, RejectsMalformedAndTruncatedLiteralNameInsertions) {
    auto decoder = make_decoder(220, 8);

    const auto malformed =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({0x5f}));
    ASSERT_FALSE(malformed.has_value());
    EXPECT_EQ(malformed.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(malformed.error().detail, "malformed insert name length");

    const auto truncated = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x41, 0x6e}));
    ASSERT_FALSE(truncated.has_value());
    EXPECT_EQ(truncated.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(truncated.error().detail, "truncated insert value");
}

TEST(QuicHttp3QpackDynamicTest, RejectsMalformedAndInvalidDuplicateInstructions) {
    auto decoder = make_decoder(220, 8);

    const auto malformed =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({0x1f}));
    ASSERT_FALSE(malformed.has_value());
    EXPECT_EQ(malformed.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(malformed.error().detail, "malformed duplicate instruction");

    const auto invalid =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({0x00}));
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(invalid.error().detail, "invalid duplicate instruction index");
}

TEST(QuicHttp3QpackDynamicTest, LaterPendingSectionOnSameStreamStaysBlockedBehindEarlierOne) {
    auto decoder = make_decoder(220, 8);

    auto first_insert = bytes_from_ints({0x3f, 0xbd, 0x01, 0xc0, 0x0f});
    append_ascii_bytes(first_insert, "www.example.com");
    const auto inserted =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, first_insert);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    decoder.pending_field_sections = {
        coquic::http3::Http3QpackPendingFieldSection{
            .stream_id = 4,
            .required_insert_count = 2,
            .base = 1,
            .payload = bytes_from_ints({0x80}),
            .referenced_entries = {0},
        },
        coquic::http3::Http3QpackPendingFieldSection{
            .stream_id = 4,
            .required_insert_count = 1,
            .base = 1,
            .payload = bytes_from_ints({0x80}),
            .referenced_entries = {0},
        },
    };
    decoder.blocked_streams = 1;

    const auto result =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({}));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value().empty());
    EXPECT_EQ(decoder.pending_field_sections.size(), 2u);
    EXPECT_EQ(decoder.blocked_streams, 1u);
    EXPECT_TRUE(decoder.pending_section_acknowledgments.empty());
}

TEST(QuicHttp3QpackDynamicTest, UnblockedPendingSectionFailureIsSurfaced) {
    auto decoder = make_decoder(220, 8);

    auto first_insert = bytes_from_ints({0x3f, 0xbd, 0x01, 0xc0, 0x0f});
    append_ascii_bytes(first_insert, "www.example.com");
    const auto inserted =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, first_insert);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    decoder.pending_field_sections = {
        coquic::http3::Http3QpackPendingFieldSection{
            .stream_id = 4,
            .required_insert_count = 1,
            .base = 1,
            .payload = bytes_from_ints({0x40}),
            .referenced_entries = {0},
        },
    };

    const auto result =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
    EXPECT_EQ(result.error().stream_id, 4u);
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

TEST(QuicHttp3QpackDynamicTest,
     EncodesLiteralWithPostBaseDynamicNameReferenceWithinSameFieldSection) {
    auto encoder = make_encoder(40, 8);
    auto decoder = make_decoder(40, 8);
    const std::string large_value(20, 'x');

    const auto encoded = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"alpha", "a"}, {"alpha", large_value}});
    ASSERT_TRUE(encoded.has_value());
    EXPECT_EQ(encoded.value().prefix, bytes_from_ints({0x02, 0x80}));
    ASSERT_GE(encoded.value().payload.size(), 3u);
    EXPECT_EQ(encoded.value().payload[0], std::byte{0x10});
    EXPECT_EQ(encoded.value().payload[1], std::byte{0x00});
    EXPECT_EQ(encoded.value().payload[2], std::byte{0x14});
    ASSERT_EQ(encoder.dynamic_table.size(), 1u);
    EXPECT_EQ(encoder.dynamic_table.front().field.name, "alpha");
    EXPECT_EQ(encoder.dynamic_table.front().field.value, "a");

    const auto inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, encoded.value().encoder_instructions);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    const auto decoded = coquic::http3::decode_http3_field_section(
        decoder, 4, encoded.value().prefix, encoded.value().payload);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().status, coquic::http3::Http3QpackDecodeStatus::complete);
    EXPECT_EQ(decoded.value().headers,
              (coquic::http3::Http3Headers{{"alpha", "a"}, {"alpha", large_value}}));
}

TEST(QuicHttp3QpackDynamicTest, EvictsAcknowledgedEncoderEntryToInsertNewField) {
    auto encoder = make_encoder(40, 8);
    auto decoder = make_decoder(40, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"a", "a"}});
    ASSERT_TRUE(first.has_value());
    const auto inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, first.value().encoder_instructions);
    ASSERT_TRUE(inserted.has_value());
    EXPECT_TRUE(inserted.value().empty());

    const auto decoded = coquic::http3::decode_http3_field_section(decoder, 0, first.value().prefix,
                                                                   first.value().payload);
    ASSERT_TRUE(decoded.has_value());

    const auto feedback = coquic::http3::take_http3_qpack_decoder_instructions(decoder);
    ASSERT_TRUE(feedback.has_value());
    const auto acknowledged =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, feedback.value());
    ASSERT_TRUE(acknowledged.has_value());
    EXPECT_EQ(encoder.known_received_count, 1u);

    const auto second = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"b", "1234567"}});
    ASSERT_TRUE(second.has_value());
    EXPECT_FALSE(second.value().encoder_instructions.empty());
    ASSERT_EQ(encoder.dynamic_table.size(), 1u);
    EXPECT_EQ(encoder.dynamic_table.front().field.name, "b");
    EXPECT_EQ(encoder.dynamic_table.front().field.value, "1234567");
    EXPECT_EQ(encoder.dynamic_table.front().absolute_index, 1u);
    EXPECT_EQ(encoder.dynamic_table.front().outstanding_references, 1u);
    EXPECT_EQ(encoder.dynamic_table_size, 40u);
}

TEST(QuicHttp3QpackDynamicTest, FallsBackWhenOutstandingEncoderEntryCannotBeEvicted) {
    auto encoder = make_encoder(40, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"a", "a"}});
    ASSERT_TRUE(first.has_value());
    ASSERT_EQ(encoder.dynamic_table.size(), 1u);

    const auto second = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"b", "1234567"}});
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(second.value().encoder_instructions.empty());
    EXPECT_EQ(second.value().prefix, bytes_from_ints({0x00, 0x00}));

    auto expected_payload = bytes_from_ints({0x21});
    append_ascii_bytes(expected_payload, "b");
    expected_payload.push_back(std::byte{0x07});
    append_ascii_bytes(expected_payload, "1234567");
    EXPECT_EQ(second.value().payload, expected_payload);

    ASSERT_EQ(encoder.dynamic_table.size(), 1u);
    EXPECT_EQ(encoder.dynamic_table.front().field.name, "a");
    EXPECT_EQ(encoder.dynamic_table.front().field.value, "a");
}

TEST(QuicHttp3QpackDynamicTest, FallsBackWhenCancelledEncoderEntryIsNotYetAcknowledged) {
    auto encoder = make_encoder(40, 8);

    const auto first = coquic::http3::encode_http3_field_section(
        encoder, 0, coquic::http3::Http3Headers{{"a", "a"}});
    ASSERT_TRUE(first.has_value());
    ASSERT_EQ(encoder.dynamic_table.size(), 1u);

    const auto cancelled =
        coquic::http3::process_http3_qpack_decoder_instructions(encoder, bytes_from_ints({0x40}));
    ASSERT_TRUE(cancelled.has_value());
    ASSERT_EQ(encoder.dynamic_table.front().outstanding_references, 0u);
    EXPECT_EQ(encoder.known_received_count, 0u);

    const auto second = coquic::http3::encode_http3_field_section(
        encoder, 4, coquic::http3::Http3Headers{{"b", "1234567"}});
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(second.value().encoder_instructions.empty());
    EXPECT_EQ(second.value().prefix, bytes_from_ints({0x00, 0x00}));

    auto expected_payload = bytes_from_ints({0x21});
    append_ascii_bytes(expected_payload, "b");
    expected_payload.push_back(std::byte{0x07});
    append_ascii_bytes(expected_payload, "1234567");
    EXPECT_EQ(second.value().payload, expected_payload);
}

TEST(QuicHttp3QpackDynamicTest, EvictsUnblockedDecoderEntryDuringInsertion) {
    auto decoder = make_decoder(40, 8);

    auto first_insert = bytes_from_ints({0x3f, 0x09, 0x41, 0x61, 0x01, 0x61});
    const auto first =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, first_insert);
    ASSERT_TRUE(first.has_value());
    EXPECT_TRUE(first.value().empty());
    ASSERT_EQ(decoder.dynamic_table.size(), 1u);
    EXPECT_EQ(decoder.dynamic_table.front().field.name, "a");
    EXPECT_EQ(decoder.dynamic_table.front().field.value, "a");

    auto second_insert = bytes_from_ints({0x41, 0x62, 0x07});
    append_ascii_bytes(second_insert, "1234567");
    const auto second =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, second_insert);
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(second.value().empty());
    ASSERT_EQ(decoder.dynamic_table.size(), 1u);
    EXPECT_EQ(decoder.dynamic_table.front().field.name, "b");
    EXPECT_EQ(decoder.dynamic_table.front().field.value, "1234567");
    EXPECT_EQ(decoder.dynamic_table.front().absolute_index, 1u);
    EXPECT_EQ(decoder.dynamic_table_size, 40u);
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithInvalidRelativeDynamicIndex) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x80}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid dynamic table index");
}

TEST(QuicHttp3QpackDynamicTest, CollectsNoReferencesForBlockedSectionWithStaticNameReference) {
    auto decoder = make_decoder(220, 8);

    const auto blocked = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x50, 0x00}));
    ASSERT_TRUE(blocked.has_value());
    EXPECT_EQ(blocked.value().status, coquic::http3::Http3QpackDecodeStatus::blocked);
    ASSERT_EQ(decoder.pending_field_sections.size(), 1u);
    EXPECT_TRUE(decoder.pending_field_sections[0].referenced_entries.empty());
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithOverflowingPostBaseIndex) {
    auto decoder = make_decoder(32, 8);
    decoder.insert_count = std::numeric_limits<std::uint64_t>::max() - 1;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x02, 0x00}), bytes_from_ints({0x11}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid post-base index");
}

TEST(QuicHttp3QpackDynamicTest,
     RejectsBlockedSectionWhenDynamicReferenceExceedsRequiredInsertCount) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x02, 0x01}), bytes_from_ints({0x80}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "dynamic table reference exceeds required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithMalformedPostBaseIndexedFieldLine) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x1f}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed post-base indexed field line");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithMalformedLiteralNameReference) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x4f}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed literal-with-name-reference");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithInvalidDynamicNameReferenceIndex) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x40, 0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid dynamic table index");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithMalformedPostBaseLiteralNameReference) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x07}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed literal-with-post-base-name-reference");
}

TEST(QuicHttp3QpackDynamicTest, RejectsFieldSectionWithTrailingPrefixBytes) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00, 0x00}), bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed field section prefix");
}

TEST(QuicHttp3QpackDynamicTest, RejectsEmptyFieldSectionPrefix) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(decoder, 0, bytes_from_ints({}),
                                                                  bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated field section prefix");
}

TEST(QuicHttp3QpackDynamicTest, RejectsFieldSectionPrefixWhenRequiredInsertCountEncodingOverflows) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0,
        bytes_from_ints({0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}),
        bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed field section prefix");
}

TEST(QuicHttp3QpackDynamicTest, RejectsFieldSectionPrefixWithMalformedDeltaBaseEncoding) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0xff}), bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed field section prefix");
}

TEST(QuicHttp3QpackDynamicTest, RejectsFieldSectionPrefixWhenBaseOverflows) {
    auto decoder = make_decoder(32, 8);
    decoder.insert_count = std::numeric_limits<std::uint64_t>::max() - 1;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x02, 0x01}), bytes_from_ints({}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid field section base");
}

TEST(QuicHttp3QpackDynamicTest, RejectsLiteralFieldValueWithInvalidHuffmanEncoding) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0x50, 0x81, 0xff}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field value huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, RejectsLiteralFieldValueWithEosHuffmanEncoding) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00}),
        bytes_from_ints({0x50, 0x84, 0xff, 0xff, 0xff, 0xfc}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field value huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, RejectsLiteralFieldValueWithNonTerminalHuffmanPaddingBits) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0x50, 0x81, 0xfe}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field value huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, RejectsLiteralFieldValueWithHuffmanPaddingBitsNotAllOnes) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0x50, 0x81, 0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field value huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, RejectsLiteralFieldValueWithTruncatedEncodedBytes) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0x50, 0x02, 0x61}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
}

TEST(QuicHttp3QpackDynamicTest, RejectsLiteralFieldNameWithInvalidHuffmanEncoding) {
    auto decoder = make_decoder();

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 0, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0x29, 0xff, 0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field name huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, CancellingStreamCompactsPendingVectorsAroundOtherStreams) {
    auto decoder = make_decoder(220, 8);
    decoder.pending_field_sections = {
        coquic::http3::Http3QpackPendingFieldSection{
            .stream_id = 4,
            .required_insert_count = 2,
            .base = 0,
            .payload = bytes_from_ints({0x10}),
            .referenced_entries = {0},
        },
        coquic::http3::Http3QpackPendingFieldSection{
            .stream_id = 8,
            .required_insert_count = 1,
            .base = 0,
            .payload = bytes_from_ints({0x10}),
            .referenced_entries = {0},
        },
    };
    decoder.pending_section_acknowledgments = {
        coquic::http3::Http3QpackSectionAcknowledgment{
            .stream_id = 4,
            .required_insert_count = 2,
        },
        coquic::http3::Http3QpackSectionAcknowledgment{
            .stream_id = 8,
            .required_insert_count = 1,
        },
    };
    decoder.blocked_streams = 2;

    const auto cancelled = coquic::http3::cancel_http3_qpack_stream(decoder, 4);
    ASSERT_TRUE(cancelled.has_value());
    ASSERT_EQ(decoder.pending_field_sections.size(), 1u);
    EXPECT_EQ(decoder.pending_field_sections[0].stream_id, 8u);
    ASSERT_EQ(decoder.pending_section_acknowledgments.size(), 1u);
    EXPECT_EQ(decoder.pending_section_acknowledgments[0].stream_id, 8u);
    EXPECT_EQ(decoder.blocked_streams, 1u);
    EXPECT_EQ(decoder.pending_stream_cancellations, (std::vector<std::uint64_t>{4}));
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithMalformedDynamicIndexedFieldLine) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0xbf}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed indexed field line");
}

TEST(QuicHttp3QpackDynamicTest,
     RejectsBlockedSectionWithPostBaseReferenceBeyondRequiredInsertCount) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x02, 0x00}), bytes_from_ints({0x10}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "dynamic table reference exceeds required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithDynamicNameReferenceValueEncodingError) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x40, 0x02, 0x61}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithPostBaseNameReferenceValueEncodingError) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x00, 0x02, 0x61}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
}

TEST(QuicHttp3QpackDynamicTest,
     RejectsBlockedSectionWithPostBaseNameReferenceBeyondRequiredInsertCount) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x02, 0x00}), bytes_from_ints({0x00, 0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "dynamic table reference exceeds required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithPostBaseNameReferenceMissingValue) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithLiteralFieldNameMissingValue) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x21, 0x6e}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithInvalidLiteralFieldNameEncoding) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x29, 0xff}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field name huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, RejectsBlockedSectionWithLiteralFieldValueEncodingError) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x21, 0x6e, 0x81, 0xff}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field value huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithInvalidRelativeDynamicIndex) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x80}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid dynamic table index");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithRelativeDynamicIndexEqualToBase) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 1;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x02, 0x00}), bytes_from_ints({0x81}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid dynamic table index");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithMissingDynamicIndexedEntry) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x80}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid dynamic table index");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithMalformedPostBaseIndexedFieldLine) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x1f}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed post-base indexed field line");
}

TEST(QuicHttp3QpackDynamicTest,
     RejectsCompleteSectionWithPostBaseReferenceBeyondRequiredInsertCount) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 1;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x02, 0x00}), bytes_from_ints({0x10}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "dynamic table reference exceeds required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithMissingPostBaseIndexedEntry) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x10}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid post-base index");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithMalformedDynamicNameReference) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x4f}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed literal-with-name-reference");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithInvalidDynamicNameReferenceIndex) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x81}), bytes_from_ints({0x40, 0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid dynamic table index");
}

TEST(QuicHttp3QpackDynamicTest,
     RejectsCompleteSectionWithDynamicNameReferenceBeyondRequiredInsertCount) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 1;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x02, 0x01}), bytes_from_ints({0x40, 0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "dynamic table reference exceeds required insert count");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithMissingDynamicNameReferenceEntry) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x40, 0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid dynamic table name reference");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithMalformedPostBaseNameReference) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x07}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "malformed literal-with-post-base-name-reference");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithMissingPostBaseNameReferenceEntry) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x00, 0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid post-base name reference");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithPostBaseNameReferenceMissingValue) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;
    decoder.dynamic_table.push_front(coquic::http3::Http3QpackEntry{
        .field =
            {
                .name = "n",
                .value = "v",
            },
        .absolute_index = 1,
    });

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x00}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithPostBaseNameReferenceValueEncodingError) {
    auto decoder = make_decoder(220, 8);
    decoder.insert_count = 2;
    decoder.dynamic_table.push_front(coquic::http3::Http3QpackEntry{
        .field =
            {
                .name = "n",
                .value = "v",
            },
        .absolute_index = 1,
    });

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x03, 0x80}), bytes_from_ints({0x00, 0x81, 0xff}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field value huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, RejectsCompleteSectionWithLiteralFieldNameMissingValue) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0x21, 0x6e}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "truncated literal field value");
}

TEST(QuicHttp3QpackDynamicTest,
     RejectsCompleteSectionWithLiteralFieldValueEncodingErrorAfterLiteralName) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::decode_http3_field_section(
        decoder, 4, bytes_from_ints({0x00, 0x00}), bytes_from_ints({0x21, 0x6e, 0x81, 0xff}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_decompression_failed);
    EXPECT_EQ(result.error().detail, "invalid literal field value huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, ShrinksDecoderCapacityByEvictingUnblockedEntries) {
    auto decoder = make_decoder(64, 8);

    const auto inserted = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x3f, 0x21, 0x41, 0x61, 0x01, 0x61}));
    ASSERT_TRUE(inserted.has_value());
    ASSERT_EQ(decoder.dynamic_table.size(), 1u);

    const auto shrunk = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x3f, 0x01}));
    ASSERT_TRUE(shrunk.has_value());
    EXPECT_TRUE(shrunk.value().empty());
    EXPECT_EQ(decoder.dynamic_table_capacity, 32u);
    EXPECT_TRUE(decoder.dynamic_table.empty());
    EXPECT_EQ(decoder.dynamic_table_size, 0u);
}

TEST(QuicHttp3QpackDynamicTest,
     ShrinksDecoderCapacityByEvictingEntryNotReferencedByBlockedSection) {
    auto decoder = make_decoder(64, 8);
    decoder.dynamic_table_capacity = 64;
    decoder.dynamic_table = {
        coquic::http3::Http3QpackEntry{
            .field = {"b", "b"},
            .size = 34,
            .absolute_index = 1,
        },
        coquic::http3::Http3QpackEntry{
            .field = {"a", "a"},
            .size = 34,
            .absolute_index = 0,
        },
    };
    decoder.dynamic_table_size = 68;
    decoder.insert_count = 2;
    decoder.pending_field_sections = {
        coquic::http3::Http3QpackPendingFieldSection{
            .stream_id = 4,
            .required_insert_count = 3,
            .base = 2,
            .payload = bytes_from_ints({0x80}),
            .referenced_entries = {1},
        },
    };
    decoder.blocked_streams = 1;

    const auto shrunk = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x3f, 0x03}));
    ASSERT_TRUE(shrunk.has_value());
    EXPECT_TRUE(shrunk.value().empty());
    EXPECT_EQ(decoder.dynamic_table_capacity, 34u);
    ASSERT_EQ(decoder.dynamic_table.size(), 1u);
    EXPECT_EQ(decoder.dynamic_table.front().absolute_index, 1u);
    EXPECT_EQ(decoder.dynamic_table_size, 34u);
}

TEST(QuicHttp3QpackDynamicTest, RejectsMalformedInsertWithNameReferenceInstruction) {
    auto decoder = make_decoder(220, 8);

    const auto result =
        coquic::http3::process_http3_qpack_encoder_instructions(decoder, bytes_from_ints({0xbf}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "malformed insert-with-name-reference instruction");
}

TEST(QuicHttp3QpackDynamicTest, RejectsInsertWithNameReferenceInvalidValueEncoding) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x3f, 0xbd, 0x01, 0xc0, 0x81, 0xff}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "invalid insert value huffman encoding");
}

TEST(QuicHttp3QpackDynamicTest, RejectsLiteralNameInsertWithInvalidValueEncoding) {
    auto decoder = make_decoder(220, 8);

    const auto result = coquic::http3::process_http3_qpack_encoder_instructions(
        decoder, bytes_from_ints({0x3f, 0xbd, 0x01, 0x41, 0x6e, 0x81, 0xff}));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::qpack_encoder_stream_error);
    EXPECT_EQ(result.error().detail, "invalid insert value huffman encoding");
}
