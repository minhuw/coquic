#include <gtest/gtest.h>

#include "src/quic/http3_protocol.h"

namespace {

TEST(QuicHttp3ProtocolTest, SettingsAndGoawayFramesRoundTrip) {
    const coquic::quic::Http3SettingsFrame settings{
        .settings =
            {
                coquic::quic::Http3Setting{
                    .id = coquic::quic::kHttp3SettingQpackMaxTableCapacity,
                    .value = 1024,
                },
                coquic::quic::Http3Setting{
                    .id = coquic::quic::kHttp3SettingMaxFieldSectionSize,
                    .value = 16384,
                },
            },
    };
    const auto serialized_settings =
        coquic::quic::serialize_http3_frame(coquic::quic::Http3Frame{settings});
    ASSERT_TRUE(serialized_settings.has_value());

    const auto decoded_settings = coquic::quic::parse_http3_frame(serialized_settings.value());
    ASSERT_TRUE(decoded_settings.has_value());
    EXPECT_EQ(decoded_settings.value().bytes_consumed, serialized_settings.value().size());

    const auto *parsed_settings =
        std::get_if<coquic::quic::Http3SettingsFrame>(&decoded_settings.value().frame);
    ASSERT_NE(parsed_settings, nullptr);
    EXPECT_EQ(parsed_settings->settings, settings.settings);

    const coquic::quic::Http3GoawayFrame goaway{
        .id = 0x21,
    };
    const auto serialized_goaway =
        coquic::quic::serialize_http3_frame(coquic::quic::Http3Frame{goaway});
    ASSERT_TRUE(serialized_goaway.has_value());

    const auto decoded_goaway = coquic::quic::parse_http3_frame(serialized_goaway.value());
    ASSERT_TRUE(decoded_goaway.has_value());
    EXPECT_EQ(decoded_goaway.value().bytes_consumed, serialized_goaway.value().size());

    const auto *parsed_goaway =
        std::get_if<coquic::quic::Http3GoawayFrame>(&decoded_goaway.value().frame);
    ASSERT_NE(parsed_goaway, nullptr);
    EXPECT_EQ(parsed_goaway->id, goaway.id);
}

TEST(QuicHttp3ProtocolTest, DuplicateSettingsRejectedWithSettingsError) {
    const coquic::quic::Http3SettingsFrame duplicate_settings{
        .settings =
            {
                coquic::quic::Http3Setting{
                    .id = coquic::quic::kHttp3SettingQpackBlockedStreams,
                    .value = 8,
                },
                coquic::quic::Http3Setting{
                    .id = coquic::quic::kHttp3SettingQpackBlockedStreams,
                    .value = 9,
                },
            },
    };
    const auto settings_validation =
        coquic::quic::validate_http3_settings_frame(duplicate_settings);
    ASSERT_FALSE(settings_validation.has_value());
    EXPECT_EQ(settings_validation.error().code, coquic::quic::Http3ErrorCode::settings_error);
}

TEST(QuicHttp3ProtocolTest, BadPseudoHeaderOrderingRejectedWithMessageError) {
    const coquic::quic::Http3Headers bad_request_headers = {
        coquic::quic::Http3Field{
            .name = "x-user-agent",
            .value = "coquic",
        },
        coquic::quic::Http3Field{
            .name = ":method",
            .value = "GET",
        },
        coquic::quic::Http3Field{
            .name = ":scheme",
            .value = "https",
        },
        coquic::quic::Http3Field{
            .name = ":authority",
            .value = "example.test",
        },
        coquic::quic::Http3Field{
            .name = ":path",
            .value = "/",
        },
    };
    const auto request_validation =
        coquic::quic::validate_http3_request_headers(bad_request_headers);
    ASSERT_FALSE(request_validation.has_value());
    EXPECT_EQ(request_validation.error().code, coquic::quic::Http3ErrorCode::message_error);
}

} // namespace
