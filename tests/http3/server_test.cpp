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

#include "src/http3/http3_server.h"

namespace {

std::vector<std::byte> bytes_from_ints(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

std::optional<std::uint8_t> hex_digit_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return static_cast<std::uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<std::uint8_t>(10 + (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<std::uint8_t>(10 + (ch - 'A'));
    }
    return std::nullopt;
}

std::vector<std::byte> bytes_from_hex(std::string_view hex) {
    EXPECT_EQ(hex.size() % 2u, 0u);
    std::vector<std::byte> bytes;
    bytes.reserve(hex.size() / 2u);
    for (std::size_t index = 0; index + 1 < hex.size(); index += 2) {
        const auto high = hex_digit_value(hex[index]);
        const auto low = hex_digit_value(hex[index + 1]);
        EXPECT_TRUE(high.has_value());
        EXPECT_TRUE(low.has_value());
        if (!high.has_value() || !low.has_value()) {
            return {};
        }
        bytes.push_back(static_cast<std::byte>((*high << 4u) | *low));
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

struct ReceivedStreamChunk {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

coquic::quic::QuicCoreResult
multi_receive_result(std::initializer_list<ReceivedStreamChunk> chunks) {
    coquic::quic::QuicCoreResult result;
    for (const auto &chunk : chunks) {
        result.effects.push_back(coquic::quic::QuicCoreEffect{
            coquic::quic::QuicCoreReceiveStreamData{
                .stream_id = chunk.stream_id,
                .bytes = chunk.bytes,
                .fin = chunk.fin,
            },
        });
    }
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
send_stream_inputs_from(const coquic::http3::Http3ServerEndpointUpdate &update) {
    std::vector<coquic::quic::QuicCoreSendStreamData> sends;
    for (const auto &input : update.core_inputs) {
        if (const auto *send = std::get_if<coquic::quic::QuicCoreSendStreamData>(&input)) {
            sends.push_back(*send);
        }
    }
    return sends;
}

std::vector<coquic::quic::QuicCoreStopSending>
stop_sending_inputs_from(const coquic::http3::Http3ServerEndpointUpdate &update) {
    std::vector<coquic::quic::QuicCoreStopSending> stops;
    for (const auto &input : update.core_inputs) {
        if (const auto *stop = std::get_if<coquic::quic::QuicCoreStopSending>(&input)) {
            stops.push_back(*stop);
        }
    }
    return stops;
}

std::vector<coquic::http3::Http3Field>
response_fields(std::uint16_t status, std::span<const coquic::http3::Http3Field> headers,
                std::optional<std::uint64_t> content_length = std::nullopt) {
    std::vector<coquic::http3::Http3Field> fields;
    fields.reserve(headers.size() + 2u);
    fields.push_back(coquic::http3::Http3Field{
        .name = ":status",
        .value = std::to_string(status),
    });
    if (content_length.has_value()) {
        fields.push_back(coquic::http3::Http3Field{
            .name = "content-length",
            .value = std::to_string(*content_length),
        });
    }
    fields.insert(fields.end(), headers.begin(), headers.end());
    return fields;
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

void prime_server_transport(coquic::http3::Http3ServerEndpoint &endpoint) {
    const auto update =
        endpoint.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_EQ(send_stream_inputs_from(update).size(), 3u);
}

TEST(QuicHttp3ServerTest, BuffersRequestUntilCompleteThenDispatchesCustomHandler) {
    std::optional<coquic::http3::Http3Request> captured_request;
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_handler =
            [&](const coquic::http3::Http3Request &request) {
                captured_request = request;
                return coquic::http3::Http3Response{
                    .head =
                        {
                            .status = 200,
                            .headers = {{"content-type", "text/plain"}},
                        },
                    .body = bytes_from_text("ok"),
                    .trailers = {{"x-server-trailer", "done"}},
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "4"},
    };
    const std::array request_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };

    const auto headers_update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(headers_update.terminal_failure);
    EXPECT_FALSE(captured_request.has_value());
    EXPECT_TRUE(send_stream_inputs_from(headers_update).empty());

    auto body_and_trailers = data_frame_bytes("ping");
    const auto trailers = headers_frame_bytes(0, request_trailers);
    body_and_trailers.insert(body_and_trailers.end(), trailers.begin(), trailers.end());

    const auto completion_update = endpoint.on_core_result(
        receive_result(0, body_and_trailers, true), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(completion_update);

    ASSERT_TRUE(captured_request.has_value());
    if (const auto &request = captured_request; request.has_value()) {
        EXPECT_EQ(request->head.method, "POST");
        EXPECT_EQ(request->head.path, "/upload");
        EXPECT_EQ(request->body, bytes_from_text("ping"));
        EXPECT_EQ(request->trailers, (coquic::http3::Http3Headers{{"etag", "done"}}));
    }

    coquic::http3::Http3QpackEncoderContext encoder;
    const auto expected_headers = headers_frame_bytes(
        encoder, 0,
        response_fields(200, std::array{coquic::http3::Http3Field{"content-type", "text/plain"}}));
    const auto expected_body = data_frame_bytes("ok");
    const auto expected_trailers = headers_frame_bytes(
        encoder, 0, std::array{coquic::http3::Http3Field{"x-server-trailer", "done"}});

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_FALSE(sends[1].fin);
    EXPECT_EQ(sends[2].bytes, expected_trailers);
    EXPECT_TRUE(sends[2].fin);
}

TEST(QuicHttp3ServerTest, DefaultEchoRouteReturnsRequestBody) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/echo"},
        coquic::http3::Http3Field{"content-length", "4"},
    };

    auto bytes = headers_frame_bytes(0, request_fields);
    const auto body = data_frame_bytes("ping");
    bytes.insert(bytes.end(), body.begin(), body.end());

    const auto update =
        endpoint.on_core_result(receive_result(0, bytes, true), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"content-type", "application/octet-stream"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(200, response_headers, 4u));
    const auto expected_body = data_frame_bytes("ping");

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ServerTest, DefaultInspectRouteReturnsDeterministicJson) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/inspect"},
        coquic::http3::Http3Field{"content-length", "4"},
    };
    const std::array request_trailers{
        coquic::http3::Http3Field{"etag", "done"},
        coquic::http3::Http3Field{"x-test", "1"},
    };

    auto bytes = headers_frame_bytes(0, request_fields);
    const auto body = data_frame_bytes("pong");
    bytes.insert(bytes.end(), body.begin(), body.end());
    const auto trailers = headers_frame_bytes(0, request_trailers);
    bytes.insert(bytes.end(), trailers.begin(), trailers.end());

    const auto update =
        endpoint.on_core_result(receive_result(0, bytes, true), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    const std::string json =
        "{\"method\":\"POST\",\"content_length\":4,\"body_bytes\":4,\"trailers\":[{\"name\":"
        "\"etag\",\"value\":\"done\"},{\"name\":\"x-test\",\"value\":\"1\"}]}";
    const std::array response_headers{
        coquic::http3::Http3Field{"content-type", "application/json"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(200, response_headers, json.size()));
    const auto expected_body = data_frame_bytes(json);

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ServerTest, UnknownRouteReturns404) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/missing"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto expected_headers = headers_frame_bytes(
        0, response_fields(404, std::array<coquic::http3::Http3Field, 0>{}, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ServerTest,
     AcceptsQuicGoStyleHttp3GetWhenRequestAndSettingsArriveInTheSameCoreResult) {
    std::optional<coquic::http3::Http3Request> captured_request;
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_handler =
            [&](const coquic::http3::Http3Request &request) {
                captured_request = request;
                return coquic::http3::Http3Response{
                    .head =
                        {
                            .status = 200,
                            .content_length = 2,
                            .headers = {{"content-type", "text/plain"}},
                        },
                    .body = bytes_from_text("ok"),
                };
            },
    });

    prime_server_transport(endpoint);

    const auto update = endpoint.on_core_result(
        multi_receive_result({
            {
                .stream_id = 0,
                .bytes = bytes_from_hex(
                    "013500005089416cee5b1ab8d34cffd1519060b6d739ec31161d844988b583aa62d9d75f"
                    "10839bd9ab5f508bed6988b4c7531efdfad867"),
                .fin = true,
            },
            {
                .stream_id = 2,
                .bytes = bytes_from_hex("0004050680a00000"),
                .fin = false,
            },
        }),
        coquic::quic::QuicCoreTimePoint{});

    if (!captured_request.has_value()) {
        FAIL() << "expected server handler to capture the request";
    }
    const auto &request = *captured_request;
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_TRUE(update.request_cancelled_events.empty());
    EXPECT_EQ(request.head.method, "GET");
    EXPECT_EQ(request.head.scheme, "https");
    EXPECT_EQ(request.head.authority, "server4:443");
    EXPECT_EQ(request.head.path, "/euphoric-arctic-ranger");
    EXPECT_EQ(request.head.headers, (coquic::http3::Http3Headers{
                                        {"accept-encoding", "gzip"},
                                        {"user-agent", "quic-go HTTP/3"},
                                    }));

    const auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder;
    const auto expected_headers = headers_frame_bytes(
        encoder, 0,
        response_fields(200, std::array{coquic::http3::Http3Field{"content-type", "text/plain"}},
                        2u));
    const auto expected_body = data_frame_bytes("ok");

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ServerTest, HeadRequestSuppressesResponseBodyButKeepsHeaders) {
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_handler =
            [](const coquic::http3::Http3Request &request) {
                EXPECT_EQ(request.head.method, "HEAD");
                return coquic::http3::Http3Response{
                    .head =
                        {
                            .status = 200,
                            .content_length = 4,
                            .headers = {{"content-type", "text/plain"}},
                        },
                    .body = bytes_from_text("pong"),
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "HEAD"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/head"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const std::array response_headers{
        coquic::http3::Http3Field{"content-type", "text/plain"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(200, response_headers, 4u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ServerTest, EarlyRequestHandlerSendsFinalResponseAndStopsRequestBody) {
    std::optional<coquic::http3::Http3RequestHead> captured_head;
    bool buffered_handler_called = false;
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_head_handler = [&](const coquic::http3::Http3RequestHead &head)
            -> std::optional<coquic::http3::Http3Response> {
            captured_head = head;
            return coquic::http3::Http3Response{
                .head =
                    {
                        .status = 413,
                        .content_length = 0,
                        .headers = {{"x-early", "1"}},
                    },
            };
        },
        .request_handler =
            [&](const coquic::http3::Http3Request &) {
                buffered_handler_called = true;
                return coquic::http3::Http3Response{
                    .head = {.status = 204},
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/too-large"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    const auto early_update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(early_update);
    const auto stops = stop_sending_inputs_from(early_update);

    ASSERT_TRUE(captured_head.has_value());
    if (captured_head.has_value()) {
        EXPECT_EQ(captured_head.value().path, "/too-large");
    }
    EXPECT_FALSE(buffered_handler_called);

    const auto expected_headers = headers_frame_bytes(
        0, response_fields(413, std::array{coquic::http3::Http3Field{"x-early", "1"}}, 0u));
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);

    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));

    const auto late_update = endpoint.on_core_result(
        receive_result(0, data_frame_bytes("ignored"), true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(late_update.terminal_failure);
    EXPECT_FALSE(buffered_handler_called);
    EXPECT_TRUE(send_stream_inputs_from(late_update).empty());
    EXPECT_TRUE(late_update.request_cancelled_events.empty());
}

TEST(QuicHttp3ServerTest, EarlyHeadResponseSuppressesBodyButKeepsContentLength) {
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_head_handler = [](const coquic::http3::Http3RequestHead &head)
            -> std::optional<coquic::http3::Http3Response> {
            EXPECT_EQ(head.method, "HEAD");
            return coquic::http3::Http3Response{
                .head =
                    {
                        .status = 200,
                        .content_length = 4,
                        .headers = {{"content-type", "text/plain"}},
                    },
                .body = bytes_from_text("pong"),
            };
        },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "HEAD"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/head"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto stops = stop_sending_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"content-type", "text/plain"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(200, response_headers, 4u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
    EXPECT_TRUE(stops.empty());
}

TEST(QuicHttp3ServerTest, PeerResetDropsBufferedRequestAndEmitsCancellationEvent) {
    bool handler_called = false;
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .request_handler =
            [&](const coquic::http3::Http3Request &) {
                handler_called = true;
                return coquic::http3::Http3Response{
                    .head = {.status = 204},
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    const auto headers_update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(headers_update.terminal_failure);

    const auto body_update = endpoint.on_core_result(receive_result(0, data_frame_bytes("ping")),
                                                     coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(body_update.terminal_failure);

    const auto cancel_update = endpoint.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(cancel_update.terminal_failure);
    EXPECT_FALSE(handler_called);
    ASSERT_EQ(cancel_update.request_cancelled_events.size(), 1u);
    const auto &cancelled = cancel_update.request_cancelled_events[0];
    EXPECT_EQ(cancelled.stream_id, 0u);
    ASSERT_TRUE(cancelled.head.has_value());
    if (cancelled.head.has_value()) {
        EXPECT_EQ(cancelled.head.value().path, "/upload");
    }
    EXPECT_EQ(cancelled.body, bytes_from_text("ping"));
    EXPECT_EQ(cancelled.application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}

} // namespace
