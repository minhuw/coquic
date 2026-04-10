#include <array>
#include <initializer_list>
#include <string_view>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "src/http3/http3_protocol.h"

namespace {

std::vector<std::byte> bytes_from_ints(std::initializer_list<unsigned int> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const unsigned int value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

TEST(QuicHttp3ProtocolTest, EncodesAndDecodesSettingsAndGoawayFrames) {
    static_assert(
        std::is_same_v<decltype(coquic::http3::kHttp3ApplicationProtocol), const std::string_view>);

    const auto failed = coquic::http3::Http3Result<bool>::failure(coquic::http3::Http3Error{
        .code = coquic::http3::Http3ErrorCode::missing_settings,
        .detail = "missing settings",
        .stream_id = 7,
    });
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(failed.error().detail, "missing settings");
    EXPECT_EQ(failed.error().stream_id, std::optional<std::uint64_t>(7));

    const coquic::http3::Http3ResponseHead default_response{};
    EXPECT_EQ(default_response.status, 200);

    const coquic::http3::Http3ConnectionState state{
        .local_control_stream_id = 1,
        .local_qpack_encoder_stream_id = 2,
        .local_qpack_decoder_stream_id = 3,
        .remote_control_stream_id = 4,
        .remote_qpack_encoder_stream_id = 5,
        .remote_qpack_decoder_stream_id = 6,
        .local_settings_sent = true,
        .remote_settings_received = true,
        .goaway_id = 7,
    };
    ASSERT_TRUE(state.goaway_id.has_value());
    EXPECT_EQ(*state.goaway_id, 7u);

    using coquic::http3::Http3Frame;
    using coquic::http3::Http3GoawayFrame;
    using coquic::http3::Http3Setting;
    using coquic::http3::Http3SettingsFrame;
    using coquic::http3::Http3UniStreamType;
    using coquic::http3::kHttp3SettingsQpackBlockedStreams;
    using coquic::http3::kHttp3SettingsQpackMaxTableCapacity;

    const std::array settings = {
        Http3Setting{.id = kHttp3SettingsQpackMaxTableCapacity, .value = 0},
        Http3Setting{.id = kHttp3SettingsQpackBlockedStreams, .value = 0},
    };
    const auto control_stream = coquic::http3::serialize_http3_control_stream(settings);
    ASSERT_TRUE(control_stream.has_value());

    const auto control_stream_type =
        coquic::http3::parse_http3_uni_stream_type(control_stream.value());
    ASSERT_TRUE(control_stream_type.has_value());
    EXPECT_EQ(control_stream_type.value().value,
              static_cast<std::uint64_t>(Http3UniStreamType::control));

    const auto settings_bytes = coquic::http3::serialize_http3_frame(Http3Frame{Http3SettingsFrame{
        .settings = std::vector<Http3Setting>(settings.begin(), settings.end()),
    }});
    ASSERT_TRUE(settings_bytes.has_value());

    const auto decoded_settings = coquic::http3::parse_http3_frame(settings_bytes.value());
    ASSERT_TRUE(decoded_settings.has_value());
    const auto *parsed_settings = std::get_if<Http3SettingsFrame>(&decoded_settings.value().frame);
    ASSERT_NE(parsed_settings, nullptr);
    EXPECT_EQ(parsed_settings->settings,
              std::vector<Http3Setting>(settings.begin(), settings.end()));

    const auto goaway_bytes =
        coquic::http3::serialize_http3_frame(Http3Frame{Http3GoawayFrame{.id = 0}});
    ASSERT_TRUE(goaway_bytes.has_value());

    const auto decoded_goaway = coquic::http3::parse_http3_frame(goaway_bytes.value());
    ASSERT_TRUE(decoded_goaway.has_value());
    const auto *parsed_goaway = std::get_if<Http3GoawayFrame>(&decoded_goaway.value().frame);
    ASSERT_NE(parsed_goaway, nullptr);
    EXPECT_EQ(parsed_goaway->id, 0u);
}

TEST(QuicHttp3ProtocolTest, RejectsDuplicateSettingsAndBadPseudoHeaderOrdering) {
    const auto settings_result =
        coquic::http3::validate_http3_settings_frame(coquic::http3::Http3SettingsFrame{
            .settings =
                {
                    {.id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity, .value = 0},
                    {.id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity, .value = 0},
                },
        });
    ASSERT_FALSE(settings_result.has_value());
    EXPECT_EQ(settings_result.error().code, coquic::http3::Http3ErrorCode::settings_error);
    EXPECT_EQ(settings_result.error().detail, "duplicate setting");

    const std::array fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{"x-extra", "1"},
        coquic::http3::Http3Field{":path", "/"},
        coquic::http3::Http3Field{":scheme", "https"},
    };
    const auto request_result = coquic::http3::validate_http3_request_headers(fields);
    ASSERT_FALSE(request_result.has_value());
    EXPECT_EQ(request_result.error().code, coquic::http3::Http3ErrorCode::message_error);

    const std::array uppercase_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":path", "/"},
        coquic::http3::Http3Field{"X-Upper", "1"},
    };
    const auto uppercase_result = coquic::http3::validate_http3_request_headers(uppercase_fields);
    ASSERT_FALSE(uppercase_result.has_value());
    EXPECT_EQ(uppercase_result.error().code, coquic::http3::Http3ErrorCode::message_error);

    const std::array empty_name_fields{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"", "1"},
    };
    const auto empty_name_result =
        coquic::http3::validate_http3_response_headers(empty_name_fields);
    ASSERT_FALSE(empty_name_result.has_value());
    EXPECT_EQ(empty_name_result.error().code, coquic::http3::Http3ErrorCode::message_error);
}

TEST(QuicHttp3ProtocolTest, EncodesAndDecodesDataAndHeadersFrames) {
    using coquic::http3::Http3DataFrame;
    using coquic::http3::Http3Frame;
    using coquic::http3::Http3GoawayFrame;
    using coquic::http3::Http3HeadersFrame;
    using coquic::http3::Http3SettingsFrame;

    const auto data_payload = bytes_from_ints({0xde, 0xad, 0xbe, 0xef});
    const auto encoded_data =
        coquic::http3::serialize_http3_frame(Http3Frame{Http3DataFrame{.payload = data_payload}});
    ASSERT_TRUE(encoded_data.has_value());

    const auto decoded_data = coquic::http3::parse_http3_frame(encoded_data.value());
    ASSERT_TRUE(decoded_data.has_value());
    EXPECT_EQ(decoded_data.value().bytes_consumed, encoded_data.value().size());
    const auto *parsed_data = std::get_if<Http3DataFrame>(&decoded_data.value().frame);
    ASSERT_NE(parsed_data, nullptr);
    EXPECT_EQ(parsed_data->payload, data_payload);

    const auto field_section = bytes_from_ints({0x20, 0x01, 'n', 0x01, 'v'});
    const auto encoded_headers = coquic::http3::serialize_http3_frame(
        Http3Frame{Http3HeadersFrame{.field_section = field_section}});
    ASSERT_TRUE(encoded_headers.has_value());

    const auto decoded_headers = coquic::http3::parse_http3_frame(encoded_headers.value());
    ASSERT_TRUE(decoded_headers.has_value());
    EXPECT_EQ(decoded_headers.value().bytes_consumed, encoded_headers.value().size());
    const auto *parsed_headers = std::get_if<Http3HeadersFrame>(&decoded_headers.value().frame);
    ASSERT_NE(parsed_headers, nullptr);
    EXPECT_EQ(parsed_headers->field_section, field_section);

    EXPECT_TRUE(coquic::http3::http3_frame_allowed_on_request_stream(
        Http3Frame{Http3DataFrame{.payload = {}}}));
    EXPECT_TRUE(coquic::http3::http3_frame_allowed_on_request_stream(
        Http3Frame{Http3HeadersFrame{.field_section = {}}}));
    EXPECT_FALSE(
        coquic::http3::http3_frame_allowed_on_request_stream(Http3Frame{Http3SettingsFrame{}}));

    EXPECT_TRUE(
        coquic::http3::http3_frame_allowed_on_control_stream(Http3Frame{Http3SettingsFrame{}}));
    EXPECT_TRUE(coquic::http3::http3_frame_allowed_on_control_stream(
        Http3Frame{Http3GoawayFrame{.id = 0}}));
    EXPECT_FALSE(coquic::http3::http3_frame_allowed_on_control_stream(
        Http3Frame{Http3HeadersFrame{.field_section = {}}}));
}

TEST(QuicHttp3ProtocolTest, RejectsFramesThatCannotBeSerializedAsVarints) {
    using coquic::http3::Http3Frame;
    using coquic::http3::Http3GoawayFrame;
    using coquic::http3::Http3Setting;
    using coquic::http3::Http3SettingsFrame;
    using coquic::quic::CodecErrorCode;

    constexpr std::uint64_t kTooLargeVarInt = (1ull << 62);

    const auto invalid_setting_id = coquic::http3::serialize_http3_frame(Http3Frame{
        Http3SettingsFrame{.settings = {Http3Setting{.id = kTooLargeVarInt, .value = 0}}}});
    ASSERT_FALSE(invalid_setting_id.has_value());
    EXPECT_EQ(invalid_setting_id.error().code, CodecErrorCode::invalid_varint);

    const auto invalid_setting_value = coquic::http3::serialize_http3_frame(Http3Frame{
        Http3SettingsFrame{.settings = {Http3Setting{.id = 0, .value = kTooLargeVarInt}}},
    });
    ASSERT_FALSE(invalid_setting_value.has_value());
    EXPECT_EQ(invalid_setting_value.error().code, CodecErrorCode::invalid_varint);

    const auto invalid_goaway =
        coquic::http3::serialize_http3_frame(Http3Frame{Http3GoawayFrame{.id = kTooLargeVarInt}});
    ASSERT_FALSE(invalid_goaway.has_value());
    EXPECT_EQ(invalid_goaway.error().code, CodecErrorCode::invalid_varint);

    const auto invalid_control_stream = coquic::http3::serialize_http3_control_stream(
        std::array{Http3Setting{.id = 0, .value = kTooLargeVarInt}});
    ASSERT_FALSE(invalid_control_stream.has_value());
    EXPECT_EQ(invalid_control_stream.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicHttp3ProtocolTest, RejectsMalformedFrameEncodings) {
    using coquic::quic::CodecErrorCode;

    const auto truncated_type = coquic::http3::parse_http3_frame({});
    ASSERT_FALSE(truncated_type.has_value());
    EXPECT_EQ(truncated_type.error().code, CodecErrorCode::truncated_input);
    EXPECT_EQ(truncated_type.error().offset, 0u);

    const auto truncated_length = coquic::http3::parse_http3_frame(bytes_from_ints({0x00}));
    ASSERT_FALSE(truncated_length.has_value());
    EXPECT_EQ(truncated_length.error().code, CodecErrorCode::truncated_input);
    EXPECT_EQ(truncated_length.error().offset, 1u);

    const auto short_payload = coquic::http3::parse_http3_frame(bytes_from_ints({0x00, 0x01}));
    ASSERT_FALSE(short_payload.has_value());
    EXPECT_EQ(short_payload.error().code, CodecErrorCode::http3_parse_error);
    EXPECT_EQ(short_payload.error().offset, 2u);

    const auto unknown_frame = coquic::http3::parse_http3_frame(bytes_from_ints({0x02, 0x00}));
    ASSERT_FALSE(unknown_frame.has_value());
    EXPECT_EQ(unknown_frame.error().code, CodecErrorCode::http3_parse_error);

    const auto truncated_setting_id =
        coquic::http3::parse_http3_frame(bytes_from_ints({0x04, 0x01, 0x40}));
    ASSERT_FALSE(truncated_setting_id.has_value());
    EXPECT_EQ(truncated_setting_id.error().code, CodecErrorCode::truncated_input);

    const auto truncated_setting_value =
        coquic::http3::parse_http3_frame(bytes_from_ints({0x04, 0x02, 0x00, 0x40}));
    ASSERT_FALSE(truncated_setting_value.has_value());
    EXPECT_EQ(truncated_setting_value.error().code, CodecErrorCode::truncated_input);

    const auto truncated_goaway =
        coquic::http3::parse_http3_frame(bytes_from_ints({0x07, 0x01, 0x40}));
    ASSERT_FALSE(truncated_goaway.has_value());
    EXPECT_EQ(truncated_goaway.error().code, CodecErrorCode::truncated_input);

    const auto trailing_goaway =
        coquic::http3::parse_http3_frame(bytes_from_ints({0x07, 0x02, 0x00, 0x00}));
    ASSERT_FALSE(trailing_goaway.has_value());
    EXPECT_EQ(trailing_goaway.error().code, CodecErrorCode::http3_parse_error);
}

TEST(QuicHttp3ProtocolTest, AcceptsValidSettingsRequestsResponsesAndTrailers) {
    const auto settings_result =
        coquic::http3::validate_http3_settings_frame(coquic::http3::Http3SettingsFrame{
            .settings =
                {
                    {.id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity, .value = 0},
                    {.id = coquic::http3::kHttp3SettingsQpackBlockedStreams, .value = 1},
                },
        });
    ASSERT_TRUE(settings_result.has_value());
    EXPECT_TRUE(settings_result.value());

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/"},
        coquic::http3::Http3Field{"accept", "*/*"},
    };
    const auto request = coquic::http3::validate_http3_request_headers(request_fields);
    ASSERT_TRUE(request.has_value());
    EXPECT_EQ(request.value().method, "GET");
    EXPECT_EQ(request.value().scheme, "https");
    EXPECT_EQ(request.value().authority, "example.test");
    EXPECT_EQ(request.value().path, "/");
    ASSERT_EQ(request.value().headers.size(), 1u);
    EXPECT_EQ(request.value().headers.front().name, "accept");

    const std::array response_fields{
        coquic::http3::Http3Field{":status", "204"},
        coquic::http3::Http3Field{"server", "coquic"},
    };
    const auto response = coquic::http3::validate_http3_response_headers(response_fields);
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response.value().status, 204);
    ASSERT_EQ(response.value().headers.size(), 1u);
    EXPECT_EQ(response.value().headers.front().value, "coquic");

    const std::array trailers_fields{
        coquic::http3::Http3Field{"etag", "abc123"},
    };
    const auto trailers = coquic::http3::validate_http3_trailers(trailers_fields);
    ASSERT_TRUE(trailers.has_value());
    ASSERT_EQ(trailers.value().size(), 1u);
    EXPECT_EQ(trailers.value().front().name, "etag");
}

TEST(QuicHttp3ProtocolTest, RejectsInvalidRequestHeaders) {
    struct RequestCase {
        std::vector<coquic::http3::Http3Field> fields;
        std::string_view detail;
    };

    for (const auto &test_case : std::array{
             RequestCase{
                 .fields = {{"", "1"}},
                 .detail = "empty header name",
             },
             RequestCase{
                 .fields =
                     {
                         {":method", "GET"},
                         {":method", "POST"},
                         {":scheme", "https"},
                         {":path", "/"},
                     },
                 .detail = "duplicate request pseudo header",
             },
             RequestCase{
                 .fields =
                     {
                         {":method", "GET"},
                         {":scheme", "https"},
                         {":scheme", "http"},
                         {":path", "/"},
                     },
                 .detail = "duplicate request pseudo header",
             },
             RequestCase{
                 .fields =
                     {
                         {":method", "GET"},
                         {":scheme", "https"},
                         {":authority", "a.test"},
                         {":authority", "b.test"},
                         {":path", "/"},
                     },
                 .detail = "duplicate request pseudo header",
             },
             RequestCase{
                 .fields =
                     {
                         {":method", "GET"},
                         {":scheme", "https"},
                         {":path", "/"},
                         {":path", "/other"},
                     },
                 .detail = "duplicate request pseudo header",
             },
             RequestCase{
                 .fields =
                     {
                         {":method", "GET"},
                         {":scheme", "https"},
                         {":path", "/"},
                         {":status", "200"},
                     },
                 .detail = "unexpected request pseudo header",
             },
             RequestCase{
                 .fields =
                     {
                         {":method", "GET"},
                         {":scheme", "https"},
                         {"accept", "*/*"},
                     },
                 .detail = "missing required request pseudo header",
             },
         }) {
        const auto result = coquic::http3::validate_http3_request_headers(test_case.fields);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
        EXPECT_EQ(result.error().detail, test_case.detail);
    }
}

TEST(QuicHttp3ProtocolTest, RejectsRequestsMissingMethodOrSchemeIndividually) {
    for (const auto &fields : std::array{
             std::vector<coquic::http3::Http3Field>{
                 {":scheme", "https"},
                 {":path", "/"},
             },
             std::vector<coquic::http3::Http3Field>{
                 {":method", "GET"},
                 {":path", "/"},
             },
         }) {
        const auto result = coquic::http3::validate_http3_request_headers(fields);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().detail, "missing required request pseudo header");
    }
}

TEST(QuicHttp3ProtocolTest, RejectsInvalidResponseHeadersAndTrailers) {
    struct HeaderCase {
        std::vector<coquic::http3::Http3Field> fields;
        std::string_view detail;
    };

    for (const auto &test_case : std::array{
             HeaderCase{
                 .fields =
                     {
                         {":status", "200"},
                         {"server", "coquic"},
                         {":status", "204"},
                     },
                 .detail = "pseudo header after regular header",
             },
             HeaderCase{
                 .fields =
                     {
                         {":status", "200"},
                         {"Server", "coquic"},
                     },
                 .detail = "uppercase header name",
             },
             HeaderCase{
                 .fields =
                     {
                         {":path", "/"},
                     },
                 .detail = "unexpected response pseudo header",
             },
             HeaderCase{
                 .fields =
                     {
                         {":status", "200"},
                         {":status", "204"},
                     },
                 .detail = "duplicate response pseudo header",
             },
             HeaderCase{
                 .fields =
                     {
                         {":status", "099"},
                     },
                 .detail = "invalid :status",
             },
             HeaderCase{
                 .fields =
                     {
                         {"server", "coquic"},
                     },
                 .detail = "missing required response pseudo header",
             },
         }) {
        const auto response = coquic::http3::validate_http3_response_headers(test_case.fields);
        ASSERT_FALSE(response.has_value());
        EXPECT_EQ(response.error().code, coquic::http3::Http3ErrorCode::message_error);
        EXPECT_EQ(response.error().detail, test_case.detail);
    }

    const auto trailer_pseudo = coquic::http3::validate_http3_trailers(
        std::array{coquic::http3::Http3Field{":status", "200"}});
    ASSERT_FALSE(trailer_pseudo.has_value());
    EXPECT_EQ(trailer_pseudo.error().detail, "trailers must not contain pseudo headers");

    const auto trailer_uppercase = coquic::http3::validate_http3_trailers(
        std::array{coquic::http3::Http3Field{"X-Test", "1"}});
    ASSERT_FALSE(trailer_uppercase.has_value());
    EXPECT_EQ(trailer_uppercase.error().detail, "uppercase header name");
}

TEST(QuicHttp3ProtocolTest, RejectsResponseStatusParseFailuresAndEmptyTrailerNames) {
    for (const auto &fields : std::array{
             std::vector<coquic::http3::Http3Field>{{":status", "2a0"}},
             std::vector<coquic::http3::Http3Field>{{":status", "abc"}},
             std::vector<coquic::http3::Http3Field>{{":status", "20"}},
             std::vector<coquic::http3::Http3Field>{{":status", "1000"}},
         }) {
        const auto response = coquic::http3::validate_http3_response_headers(fields);
        ASSERT_FALSE(response.has_value());
        EXPECT_EQ(response.error().detail, "invalid :status");
    }

    const auto empty_name_trailer =
        coquic::http3::validate_http3_trailers(std::array{coquic::http3::Http3Field{"", "1"}});
    ASSERT_FALSE(empty_name_trailer.has_value());
    EXPECT_EQ(empty_name_trailer.error().detail, "trailers must not contain pseudo headers");
}

} // namespace
