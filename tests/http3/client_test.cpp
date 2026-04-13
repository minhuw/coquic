#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "src/http3/http3_client.h"

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

std::vector<std::byte> bytes_from_text(std::string_view text) {
    std::vector<std::byte> bytes;
    append_ascii_bytes(bytes, text);
    return bytes;
}

coquic::quic::QuicCoreResult handshake_ready_result() {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreStateEvent{
            .change = coquic::quic::QuicCoreStateChange::handshake_ready,
        },
    });
    return result;
}

coquic::quic::QuicCoreResult receive_result(std::uint64_t stream_id,
                                            std::span<const std::byte> bytes, bool fin = false) {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreReceiveStreamData{
            .stream_id = stream_id,
            .bytes = std::vector<std::byte>(bytes.begin(), bytes.end()),
            .fin = fin,
        },
    });
    return result;
}

coquic::quic::QuicCoreResult reset_result(std::uint64_t stream_id, std::uint64_t error_code = 0) {
    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCorePeerResetStream{
            .stream_id = stream_id,
            .application_error_code = error_code,
        },
    });
    return result;
}

std::vector<coquic::quic::QuicCoreSendStreamData>
send_stream_inputs_from(const coquic::http3::Http3ClientEndpointUpdate &update) {
    std::vector<coquic::quic::QuicCoreSendStreamData> sends;
    for (const auto &input : update.core_inputs) {
        if (const auto *send = std::get_if<coquic::quic::QuicCoreSendStreamData>(&input)) {
            sends.push_back(*send);
        }
    }
    return sends;
}

std::vector<std::byte> headers_frame_bytes(coquic::http3::Http3QpackEncoderContext &encoder,
                                           std::uint64_t stream_id,
                                           std::span<const coquic::http3::Http3Field> fields) {
    const auto encoded = coquic::http3::encode_http3_field_section(encoder, stream_id, fields);
    EXPECT_TRUE(encoded.has_value());
    if (!encoded.has_value()) {
        return {};
    }

    auto field_section = encoded.value().prefix;
    field_section.insert(field_section.end(), encoded.value().payload.begin(),
                         encoded.value().payload.end());
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3HeadersFrame{
            .field_section = std::move(field_section),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte> headers_frame_bytes(std::uint64_t stream_id,
                                           std::span<const coquic::http3::Http3Field> fields) {
    coquic::http3::Http3QpackEncoderContext encoder;
    return headers_frame_bytes(encoder, stream_id, fields);
}

std::vector<std::byte> data_frame_bytes(std::string_view payload_text) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3DataFrame{
            .payload = bytes_from_text(payload_text),
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

std::vector<std::byte>
settings_stream_bytes(std::initializer_list<coquic::http3::Http3Setting> settings = {}) {
    auto bytes = bytes_from_ints({0x00});
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3SettingsFrame{
            .settings = std::vector<coquic::http3::Http3Setting>(settings),
        },
    });
    EXPECT_TRUE(frame.has_value());
    if (frame.has_value()) {
        bytes.insert(bytes.end(), frame.value().begin(), frame.value().end());
    }
    return bytes;
}

std::vector<std::byte> goaway_frame_bytes(std::uint64_t id) {
    const auto frame = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3GoawayFrame{
            .id = id,
        },
    });
    EXPECT_TRUE(frame.has_value());
    return frame.has_value() ? frame.value() : std::vector<std::byte>{};
}

void prime_client_transport(coquic::http3::Http3ClientEndpoint &endpoint) {
    const auto update =
        endpoint.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_EQ(send_stream_inputs_from(update).size(), 3u);
}

TEST(QuicHttp3ClientTest, SubmitRequestEmitsCompletedResponseAfterFinalFin) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    const auto submitted = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "POST",
                .scheme = "https",
                .authority = "example.test",
                .path = "/_coquic/echo",
                .content_length = 4,
            },
        .body = bytes_from_text("ping"),
        .trailers = {{"etag", "done"}},
    });
    ASSERT_TRUE(submitted.has_value());
    EXPECT_EQ(submitted.value(), 0u);

    const auto request_update = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(send_stream_inputs_from(request_update).empty());

    const std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"content-type", "application/octet-stream"},
    };
    const std::array response_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };
    auto response_bytes = headers_frame_bytes(0, response_headers);
    const auto body_frame = data_frame_bytes("ping");
    response_bytes.insert(response_bytes.end(), body_frame.begin(), body_frame.end());
    const auto trailers_frame = headers_frame_bytes(0, response_trailers);
    response_bytes.insert(response_bytes.end(), trailers_frame.begin(), trailers_frame.end());

    const auto response_update = endpoint.on_core_result(receive_result(0, response_bytes, true),
                                                         coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(response_update.events.size(), 1u);
    EXPECT_EQ(response_update.events[0].stream_id, 0u);
    EXPECT_EQ(response_update.events[0].request.head.path, "/_coquic/echo");
    EXPECT_EQ(response_update.events[0].response.head.status, 200u);
    EXPECT_EQ(response_update.events[0].response.body, bytes_from_text("ping"));
    EXPECT_EQ(response_update.events[0].response.trailers,
              (coquic::http3::Http3Headers{{"etag", "done"}}));
}

TEST(QuicHttp3ClientTest, HeadRequestCollectsHeadersOnlyFinalResponse) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    ASSERT_TRUE(endpoint
                    .submit_request(coquic::http3::Http3Request{
                        .head =
                            {
                                .method = "HEAD",
                                .scheme = "https",
                                .authority = "example.test",
                                .path = "/head",
                            },
                    })
                    .has_value());
    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    const std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"content-type", "text/plain"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, response_headers), true),
                                coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_EQ(update.events[0].stream_id, 0u);
    const auto content_length = update.events[0].response.head.content_length;
    ASSERT_TRUE(content_length.has_value());
    EXPECT_EQ(content_length.value_or(0u), 4u);
    EXPECT_TRUE(update.events[0].response.body.empty());
}

TEST(QuicHttp3ClientTest, RejectsSubmissionAtOrAbovePeerGoawayBoundary) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    EXPECT_TRUE(endpoint
                    .submit_request(coquic::http3::Http3Request{
                        .head =
                            {
                                .method = "GET",
                                .scheme = "https",
                                .authority = "example.test",
                                .path = "/first",
                            },
                    })
                    .has_value());
    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    EXPECT_FALSE(endpoint
                     .on_core_result(receive_result(3, settings_stream_bytes()),
                                     coquic::quic::QuicCoreTimePoint{})
                     .terminal_failure);
    EXPECT_FALSE(endpoint
                     .on_core_result(receive_result(3, goaway_frame_bytes(4)),
                                     coquic::quic::QuicCoreTimePoint{})
                     .terminal_failure);

    const auto rejected = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "GET",
                .scheme = "https",
                .authority = "example.test",
                .path = "/second",
            },
    });
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, coquic::http3::Http3ErrorCode::request_rejected);
    EXPECT_EQ(rejected.error().stream_id, std::optional<std::uint64_t>(4u));
}

TEST(QuicHttp3ClientTest, PeerResetRejectedRequestEmitsRequestErrorEvent) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    const auto submitted = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "GET",
                .scheme = "https",
                .authority = "example.test",
                .path = "/reject",
            },
    });
    ASSERT_TRUE(submitted.has_value());

    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    const auto update = endpoint.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected)),
        coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(update.terminal_failure);
    ASSERT_TRUE(update.events.empty());
    ASSERT_EQ(update.request_error_events.size(), 1u);
    EXPECT_EQ(update.request_error_events[0].stream_id, 0u);
    EXPECT_EQ(update.request_error_events[0].request.head.path, "/reject");
    EXPECT_EQ(update.request_error_events[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected));
}

TEST(QuicHttp3ClientTest, PeerResetAfterCompletedResponseIsIgnored) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    ASSERT_TRUE(endpoint
                    .submit_request(coquic::http3::Http3Request{
                        .head =
                            {
                                .method = "GET",
                                .scheme = "https",
                                .authority = "example.test",
                                .path = "/complete",
                            },
                    })
                    .has_value());
    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    const std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
    };
    const auto response_update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, response_headers), true),
                                coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(response_update.events.size(), 1u);
    ASSERT_TRUE(response_update.request_error_events.empty());

    const auto reset_update = endpoint.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(reset_update.terminal_failure);
    EXPECT_TRUE(reset_update.events.empty());
    EXPECT_TRUE(reset_update.request_error_events.empty());
}

} // namespace
