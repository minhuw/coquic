#include <array>
#include <string_view>
#include <type_traits>

#include <gtest/gtest.h>

#include "src/quic/http3_protocol.h"

namespace {

TEST(QuicHttp3ProtocolTest, EncodesAndDecodesSettingsAndGoawayFrames) {
    static_assert(
        std::is_same_v<decltype(coquic::quic::kHttp3ApplicationProtocol), const std::string_view>);

    const auto failed = coquic::quic::Http3Result<bool>::failure(coquic::quic::Http3Error{
        .code = coquic::quic::Http3ErrorCode::missing_settings,
        .detail = "missing settings",
        .stream_id = 7,
    });
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(failed.error().detail, "missing settings");
    EXPECT_EQ(failed.error().stream_id, std::optional<std::uint64_t>(7));

    const coquic::quic::Http3ResponseHead default_response{};
    EXPECT_EQ(default_response.status, 200);

    const coquic::quic::Http3ConnectionState state{
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

    using coquic::quic::Http3Frame;
    using coquic::quic::Http3GoawayFrame;
    using coquic::quic::Http3Setting;
    using coquic::quic::Http3SettingsFrame;
    using coquic::quic::Http3UniStreamType;
    using coquic::quic::kHttp3SettingsQpackBlockedStreams;
    using coquic::quic::kHttp3SettingsQpackMaxTableCapacity;

    const std::array settings = {
        Http3Setting{.id = kHttp3SettingsQpackMaxTableCapacity, .value = 0},
        Http3Setting{.id = kHttp3SettingsQpackBlockedStreams, .value = 0},
    };
    const auto control_stream = coquic::quic::serialize_http3_control_stream(settings);
    ASSERT_TRUE(control_stream.has_value());

    const auto control_stream_type =
        coquic::quic::parse_http3_uni_stream_type(control_stream.value());
    ASSERT_TRUE(control_stream_type.has_value());
    EXPECT_EQ(control_stream_type.value().value,
              static_cast<std::uint64_t>(Http3UniStreamType::control));

    const auto settings_bytes = coquic::quic::serialize_http3_frame(Http3Frame{Http3SettingsFrame{
        .settings = std::vector<Http3Setting>(settings.begin(), settings.end()),
    }});
    ASSERT_TRUE(settings_bytes.has_value());

    const auto decoded_settings = coquic::quic::parse_http3_frame(settings_bytes.value());
    ASSERT_TRUE(decoded_settings.has_value());
    const auto *parsed_settings = std::get_if<Http3SettingsFrame>(&decoded_settings.value().frame);
    ASSERT_NE(parsed_settings, nullptr);
    EXPECT_EQ(parsed_settings->settings,
              std::vector<Http3Setting>(settings.begin(), settings.end()));

    const auto goaway_bytes =
        coquic::quic::serialize_http3_frame(Http3Frame{Http3GoawayFrame{.id = 0}});
    ASSERT_TRUE(goaway_bytes.has_value());

    const auto decoded_goaway = coquic::quic::parse_http3_frame(goaway_bytes.value());
    ASSERT_TRUE(decoded_goaway.has_value());
    const auto *parsed_goaway = std::get_if<Http3GoawayFrame>(&decoded_goaway.value().frame);
    ASSERT_NE(parsed_goaway, nullptr);
    EXPECT_EQ(parsed_goaway->id, 0u);
}

TEST(QuicHttp3ProtocolTest, RejectsDuplicateSettingsAndBadPseudoHeaderOrdering) {
    const auto settings_result =
        coquic::quic::validate_http3_settings_frame(coquic::quic::Http3SettingsFrame{
            .settings =
                {
                    {.id = coquic::quic::kHttp3SettingsQpackMaxTableCapacity, .value = 0},
                    {.id = coquic::quic::kHttp3SettingsQpackMaxTableCapacity, .value = 0},
                },
        });
    ASSERT_FALSE(settings_result.has_value());
    EXPECT_EQ(settings_result.error().code, coquic::quic::Http3ErrorCode::settings_error);
    EXPECT_EQ(settings_result.error().detail, "duplicate setting");

    const std::array fields{
        coquic::quic::Http3Field{":method", "GET"},
        coquic::quic::Http3Field{"x-extra", "1"},
        coquic::quic::Http3Field{":path", "/"},
        coquic::quic::Http3Field{":scheme", "https"},
    };
    const auto request_result = coquic::quic::validate_http3_request_headers(fields);
    ASSERT_FALSE(request_result.has_value());
    EXPECT_EQ(request_result.error().code, coquic::quic::Http3ErrorCode::message_error);

    const std::array uppercase_fields{
        coquic::quic::Http3Field{":method", "GET"},
        coquic::quic::Http3Field{":scheme", "https"},
        coquic::quic::Http3Field{":path", "/"},
        coquic::quic::Http3Field{"X-Upper", "1"},
    };
    const auto uppercase_result = coquic::quic::validate_http3_request_headers(uppercase_fields);
    ASSERT_FALSE(uppercase_result.has_value());
    EXPECT_EQ(uppercase_result.error().code, coquic::quic::Http3ErrorCode::message_error);

    const std::array empty_name_fields{
        coquic::quic::Http3Field{":status", "200"},
        coquic::quic::Http3Field{"", "1"},
    };
    const auto empty_name_result = coquic::quic::validate_http3_response_headers(empty_name_fields);
    ASSERT_FALSE(empty_name_result.has_value());
    EXPECT_EQ(empty_name_result.error().code, coquic::quic::Http3ErrorCode::message_error);
}

} // namespace
