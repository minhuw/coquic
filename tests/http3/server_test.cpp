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

namespace coquic::http3 {

Http3ServerEndpointUpdate server_make_failure_update_for_test(bool handled_local_error);
std::string server_append_json_escaped_for_test(std::string_view value);
std::string server_inspect_json_body_for_test(const Http3Request &request);
Http3Response server_default_route_response_for_test(const Http3Request &request);
bool server_would_exceed_body_limit_for_test(std::size_t buffered_bytes, std::size_t incoming_bytes,
                                             std::size_t limit);
void server_set_force_abort_request_body_failure_for_test(bool enabled);
void server_set_force_follow_up_poll_terminal_failure_for_test(bool enabled);
bool server_merge_connection_update_for_test(Http3ServerEndpointUpdate &out,
                                             Http3EndpointUpdate &update);
Http3Result<std::vector<coquic::quic::QuicCoreSendStreamData>>
server_submit_response_for_test(bool prepare_request_stream, std::uint64_t stream_id,
                                const Http3RequestHead &request_head,
                                const Http3Response &response);

struct Http3ServerEndpointTestAccess {
    static Http3Connection &connection(Http3ServerEndpoint &endpoint) {
        return endpoint.connection_;
    }

    static auto &pending_request(Http3ServerEndpoint &endpoint, std::uint64_t stream_id) {
        return endpoint.pending_requests_[stream_id];
    }

    static std::size_t pending_request_count(Http3ServerEndpoint &endpoint,
                                             std::uint64_t stream_id) {
        return endpoint.pending_requests_.count(stream_id);
    }

    static bool pending_requests_empty(Http3ServerEndpoint &endpoint) {
        return endpoint.pending_requests_.empty();
    }
};

struct Http3ConnectionTestAccess {
    static void queue_event(Http3Connection &connection, const Http3EndpointEvent &event) {
        connection.pending_events_.push_back(event);
    }

    static void set_closed(Http3Connection &connection, bool closed) {
        connection.closed_ = closed;
    }

    static void set_transport_ready(Http3Connection &connection, bool ready) {
        connection.transport_ready_ = ready;
    }

    static void ensure_local_response_stream(Http3Connection &connection, std::uint64_t stream_id) {
        connection.local_response_streams_[stream_id] = {};
    }

    static void ensure_peer_request_stream(Http3Connection &connection, std::uint64_t stream_id) {
        connection.peer_request_streams_[stream_id] = {};
    }
};

} // namespace coquic::http3

namespace {

namespace http3 = coquic::http3;

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

struct ScopedServerTestHookReset {
    ~ScopedServerTestHookReset() {
        http3::server_set_force_abort_request_body_failure_for_test(false);
        http3::server_set_force_follow_up_poll_terminal_failure_for_test(false);
    }
};

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

coquic::quic::QuicCoreResult local_error_result() {
    coquic::quic::QuicCoreResult result;
    result.local_error = coquic::quic::QuicCoreLocalError{
        .code = coquic::quic::QuicCoreLocalErrorCode::unsupported_operation,
    };
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

TEST(QuicHttp3ServerTest, DefaultSpeedPingRouteReturnsNoContent) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/ping"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"cache-control", "no-store"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(204, response_headers, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ServerTest, DefaultSpeedDownloadRouteReturnsSizedPayload) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/download?bytes=16&ts=1712345678"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"content-type", "application/octet-stream"},
        coquic::http3::Http3Field{"cache-control", "no-store"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(200, response_headers, 16u));
    const auto expected_body = data_frame_bytes("ABCDEFGHIJKLMNOP");

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ServerTest, DefaultSpeedUploadRouteReturnsReceivedByteSummary) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/upload"},
        coquic::http3::Http3Field{"content-length", "4"},
    };

    auto bytes = headers_frame_bytes(0, request_fields);
    const auto body = data_frame_bytes("ping");
    bytes.insert(bytes.end(), body.begin(), body.end());

    const auto update =
        endpoint.on_core_result(receive_result(0, bytes, true), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    const std::string json = "{\"received_bytes\":4}";
    const std::array response_headers{
        coquic::http3::Http3Field{"content-type", "application/json"},
        coquic::http3::Http3Field{"cache-control", "no-store"},
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

TEST(QuicHttp3ServerTest, DefaultSpeedDownloadRouteRejectsMissingBytesQuery) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/download"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"cache-control", "no-store"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(400, response_headers, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ServerTest, DefaultSpeedDownloadRouteRejectsOversizedBytesQuery) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/download?bytes=4194305"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"cache-control", "no-store"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(400, response_headers, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ServerTest, DefaultSpeedDownloadRouteRejectsMalformedBytesQuery) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/download?ts=1712345678&bytes=nope"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"cache-control", "no-store"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(400, response_headers, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ServerTest, DefaultSpeedUploadRouteRejectsNonPostMethod) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/upload"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto expected_headers = headers_frame_bytes(
        0, response_fields(405, std::array{coquic::http3::Http3Field{"allow", "POST"}}, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ServerTest,
     DefaultSpeedUploadRouteRejectsOversizedDeclaredContentLengthBeforeRequestBody) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/upload"},
        coquic::http3::Http3Field{"content-length", "4194305"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto stops = stop_sending_inputs_from(update);

    const std::array response_headers{
        coquic::http3::Http3Field{"cache-control", "no-store"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(400, response_headers, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);

    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));
}

TEST(QuicHttp3ServerTest, FallbackHandlerDoesNotBypassDefaultSpeedUploadDeclaredLengthRejection) {
    bool fallback_handler_called = false;
    coquic::http3::Http3ServerEndpoint endpoint(coquic::http3::Http3ServerConfig{
        .fallback_request_handler =
            [&](const coquic::http3::Http3Request &) {
                fallback_handler_called = true;
                return coquic::http3::Http3Response{
                    .head =
                        {
                            .status = 204,
                            .content_length = 0,
                        },
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/upload"},
        coquic::http3::Http3Field{"content-length", "4194305"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);
    const auto stops = stop_sending_inputs_from(update);

    EXPECT_FALSE(fallback_handler_called);

    const std::array response_headers{
        coquic::http3::Http3Field{"cache-control", "no-store"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(400, response_headers, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);

    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));
}

TEST(QuicHttp3ServerTest, DefaultSpeedUploadRouteRejectsOversizedBodyBeforeRequestComplete) {
    coquic::http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/_coquic/speed/upload"},
    };

    const auto headers_update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(headers_update.terminal_failure);
    EXPECT_TRUE(send_stream_inputs_from(headers_update).empty());

    const std::string max_allowed_body(static_cast<std::size_t>(4) * 1024u * 1024u, 'a');
    const auto max_body_update = endpoint.on_core_result(
        receive_result(0, data_frame_bytes(max_allowed_body)), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(max_body_update.terminal_failure);
    EXPECT_TRUE(send_stream_inputs_from(max_body_update).empty());

    const auto overflow_update = endpoint.on_core_result(receive_result(0, data_frame_bytes("b")),
                                                         coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(overflow_update);
    const auto stops = stop_sending_inputs_from(overflow_update);

    const std::array response_headers{
        coquic::http3::Http3Field{"cache-control", "no-store"},
    };
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(400, response_headers, 0u));

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
    EXPECT_TRUE(send_stream_inputs_from(late_update).empty());
    EXPECT_TRUE(late_update.request_cancelled_events.empty());
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

TEST(QuicHttp3ServerTest, HelperHooksExposeFailureEscapeInspectAndRouteHelpers) {
    const auto failed = http3::server_make_failure_update_for_test(false);
    EXPECT_TRUE(failed.terminal_failure);
    EXPECT_FALSE(failed.handled_local_error);

    const auto handled = http3::server_make_failure_update_for_test(true);
    EXPECT_TRUE(handled.terminal_failure);
    EXPECT_TRUE(handled.handled_local_error);

    std::string escaped_input;
    escaped_input.push_back('"');
    escaped_input.push_back('\\');
    escaped_input.push_back('\b');
    escaped_input.push_back('\f');
    escaped_input.push_back('\n');
    escaped_input.push_back('\r');
    escaped_input.push_back('\t');
    escaped_input.push_back(static_cast<char>(0x01));
    escaped_input.push_back('Z');
    EXPECT_EQ(http3::server_append_json_escaped_for_test(escaped_input),
              "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001Z\"");

    const auto inspect_json = http3::server_inspect_json_body_for_test(http3::Http3Request{
        .head =
            {
                .method = "POST",
                .content_length = std::nullopt,
            },
        .body = bytes_from_text("ok"),
        .trailers = {{"x-one", "alpha"}, {"x-two", "be\"ta"}},
    });
    EXPECT_EQ(
        inspect_json,
        "{\"method\":\"POST\",\"content_length\":null,\"body_bytes\":2,\"trailers\":[{\"name\":"
        "\"x-one\",\"value\":\"alpha\"},{\"name\":\"x-two\",\"value\":\"be\\\"ta\"}]}");

    const auto echo_method_not_allowed =
        http3::server_default_route_response_for_test(http3::Http3Request{
            .head =
                {
                    .method = "GET",
                    .path = "/_coquic/echo",
                },
        });
    EXPECT_EQ(echo_method_not_allowed.head.status, 405);
    EXPECT_EQ(echo_method_not_allowed.head.content_length, std::optional<std::uint64_t>{0});
    EXPECT_EQ(echo_method_not_allowed.head.headers, (http3::Http3Headers{{"allow", "POST"}}));

    const auto inspect_method_not_allowed =
        http3::server_default_route_response_for_test(http3::Http3Request{
            .head =
                {
                    .method = "GET",
                    .path = "/_coquic/inspect",
                },
        });
    EXPECT_EQ(inspect_method_not_allowed.head.status, 405);
    EXPECT_EQ(inspect_method_not_allowed.head.content_length, std::optional<std::uint64_t>{0});
    EXPECT_EQ(inspect_method_not_allowed.head.headers, (http3::Http3Headers{{"allow", "POST"}}));
}

TEST(QuicHttp3ServerTest, HelperHookMergesConnectionUpdatesAndPropagatesTerminalFailure) {
    http3::Http3ServerEndpointUpdate merged;
    http3::Http3EndpointUpdate update;
    update.core_inputs.push_back(coquic::quic::QuicCoreStopSending{
        .stream_id = 9,
        .application_error_code = 7,
    });
    EXPECT_TRUE(http3::server_merge_connection_update_for_test(merged, update));
    ASSERT_EQ(merged.core_inputs.size(), 1u);
    const auto *stop = std::get_if<coquic::quic::QuicCoreStopSending>(&merged.core_inputs[0]);
    ASSERT_NE(stop, nullptr);
    EXPECT_EQ(stop->stream_id, 9u);
    EXPECT_FALSE(merged.terminal_failure);

    http3::Http3EndpointUpdate failed_update;
    failed_update.terminal_failure = true;
    EXPECT_FALSE(http3::server_merge_connection_update_for_test(merged, failed_update));
    EXPECT_TRUE(merged.terminal_failure);
}

TEST(QuicHttp3ServerTest, HelperHookSubmitResponseCoversInterimHeadAndFailures) {
    const http3::Http3RequestHead head_request{
        .method = "HEAD",
        .scheme = "https",
        .authority = "example.test",
        .path = "/head",
        .content_length = 4,
    };
    const http3::Http3Response head_response{
        .interim_heads = {{.status = 103}},
        .head =
            {
                .status = 200,
            },
        .body = bytes_from_text("pong"),
    };

    const auto submitted =
        http3::server_submit_response_for_test(true, 0, head_request, head_response);
    ASSERT_TRUE(submitted.has_value());
    const auto &sends = submitted.value();
    ASSERT_EQ(sends.size(), 2u);

    http3::Http3QpackEncoderContext encoder;
    const auto expected_interim =
        headers_frame_bytes(encoder, 0, response_fields(103, std::array<http3::Http3Field, 0>{}));
    const auto expected_final = headers_frame_bytes(
        encoder, 0, response_fields(200, std::array<http3::Http3Field, 0>{}, 4u));
    EXPECT_EQ(sends[0].bytes, expected_interim);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].bytes, expected_final);
    EXPECT_TRUE(sends[1].fin);

    const auto missing_stream =
        http3::server_submit_response_for_test(false, 0,
                                               {
                                                   .method = "GET",
                                                   .scheme = "https",
                                                   .authority = "example.test",
                                                   .path = "/missing",
                                               },
                                               http3::Http3Response{
                                                   .interim_heads = {{.status = 103}},
                                                   .head = {.status = 200},
                                               });
    ASSERT_FALSE(missing_stream.has_value());
    EXPECT_EQ(missing_stream.error().code, http3::Http3ErrorCode::frame_unexpected);

    const auto missing_stream_without_interim =
        http3::server_submit_response_for_test(false, 0,
                                               {
                                                   .method = "GET",
                                                   .scheme = "https",
                                                   .authority = "example.test",
                                                   .path = "/missing-final",
                                               },
                                               http3::Http3Response{
                                                   .head = {.status = 204},
                                               });
    ASSERT_FALSE(missing_stream_without_interim.has_value());
    EXPECT_EQ(missing_stream_without_interim.error().code, http3::Http3ErrorCode::frame_unexpected);

    const auto body_mismatch =
        http3::server_submit_response_for_test(true, 0,
                                               {
                                                   .method = "GET",
                                                   .scheme = "https",
                                                   .authority = "example.test",
                                                   .path = "/body-mismatch",
                                               },
                                               http3::Http3Response{
                                                   .head =
                                                       {
                                                           .status = 200,
                                                           .content_length = 1,
                                                       },
                                                   .body = bytes_from_text("pong"),
                                               });
    ASSERT_FALSE(body_mismatch.has_value());
    EXPECT_EQ(body_mismatch.error().code, http3::Http3ErrorCode::message_error);
}

TEST(QuicHttp3ServerTest, LocalErrorFailureIsStickyAndPollReportsFailure) {
    http3::Http3ServerEndpoint endpoint;

    const auto failed =
        endpoint.on_core_result(local_error_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(failed.terminal_failure);
    EXPECT_TRUE(failed.handled_local_error);
    EXPECT_TRUE(endpoint.has_failed());

    const auto after_core =
        endpoint.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(after_core.terminal_failure);
    EXPECT_FALSE(after_core.handled_local_error);

    const auto after_poll = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(after_poll.terminal_failure);
    EXPECT_FALSE(after_poll.handled_local_error);
}

TEST(QuicHttp3ServerTest, PollOnHealthyEndpointIsNonFailing) {
    http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const auto update = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_FALSE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, HeadHandlerReturningNulloptFallsBackToBufferedHandler) {
    bool head_handler_called = false;
    bool request_handler_called = false;
    http3::Http3ServerEndpoint endpoint(http3::Http3ServerConfig{
        .request_head_handler =
            [&](const http3::Http3RequestHead &head) -> std::optional<http3::Http3Response> {
            head_handler_called = true;
            EXPECT_EQ(head.path, "/buffered");
            return std::nullopt;
        },
        .request_handler =
            [&](const http3::Http3Request &request) {
                request_handler_called = true;
                EXPECT_EQ(request.head.path, "/buffered");
                EXPECT_EQ(request.body, bytes_from_text("ping"));
                return http3::Http3Response{
                    .head =
                        {
                            .status = 204,
                            .content_length = 0,
                        },
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        http3::Http3Field{":method", "POST"},
        http3::Http3Field{":scheme", "https"},
        http3::Http3Field{":authority", "example.test"},
        http3::Http3Field{":path", "/buffered"},
        http3::Http3Field{"content-length", "4"},
    };

    auto bytes = headers_frame_bytes(0, request_fields);
    const auto body = data_frame_bytes("ping");
    bytes.insert(bytes.end(), body.begin(), body.end());

    const auto update =
        endpoint.on_core_result(receive_result(0, bytes, true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_TRUE(head_handler_called);
    EXPECT_TRUE(request_handler_called);
}

TEST(QuicHttp3ServerTest, EarlyResponseIgnoresCoalescedBodyTrailersAndCompletion) {
    bool request_handler_called = false;
    http3::Http3ServerEndpoint endpoint(http3::Http3ServerConfig{
        .request_head_handler =
            [](const http3::Http3RequestHead &) -> std::optional<http3::Http3Response> {
            return http3::Http3Response{
                .head =
                    {
                        .status = 202,
                        .content_length = 0,
                    },
            };
        },
        .request_handler =
            [&](const http3::Http3Request &) {
                request_handler_called = true;
                return http3::Http3Response{.head = {.status = 500}};
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        http3::Http3Field{":method", "POST"},
        http3::Http3Field{":scheme", "https"},
        http3::Http3Field{":authority", "example.test"},
        http3::Http3Field{":path", "/ignored"},
        http3::Http3Field{"content-length", "4"},
    };
    const std::array request_trailers{
        http3::Http3Field{"x-ignored", "1"},
    };

    auto bytes = headers_frame_bytes(0, request_fields);
    const auto body = data_frame_bytes("ping");
    bytes.insert(bytes.end(), body.begin(), body.end());
    const auto trailers = headers_frame_bytes(0, request_trailers);
    bytes.insert(bytes.end(), trailers.begin(), trailers.end());

    const auto update =
        endpoint.on_core_result(receive_result(0, bytes, true), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_FALSE(request_handler_called);
    EXPECT_TRUE(update.request_cancelled_events.empty());

    const auto sends = send_stream_inputs_from(update);
    const auto expected_headers =
        headers_frame_bytes(0, response_fields(202, std::array<http3::Http3Field, 0>{}, 0u));
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ServerTest, ResetWithoutBufferedRequestIsIgnored) {
    http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const auto update = endpoint.on_core_result(
        reset_result(0, static_cast<std::uint64_t>(http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_TRUE(update.request_cancelled_events.empty());
    EXPECT_FALSE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, ResetAfterPartialBufferedRequestIsIgnored) {
    http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const std::array request_fields{
        http3::Http3Field{":method", "POST"},
        http3::Http3Field{":scheme", "https"},
        http3::Http3Field{":authority", "example.test"},
        http3::Http3Field{":path", "/partial"},
        http3::Http3Field{"content-length", "4"},
    };
    auto partial_headers = headers_frame_bytes(0, request_fields);
    partial_headers.resize(1);

    const auto partial_update = endpoint.on_core_result(receive_result(0, partial_headers),
                                                        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(partial_update.terminal_failure);

    const auto reset_update = endpoint.on_core_result(
        reset_result(0, static_cast<std::uint64_t>(http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(reset_update.terminal_failure);
    EXPECT_TRUE(reset_update.request_cancelled_events.empty());
    EXPECT_FALSE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, CompletionWithoutPendingRequestFailsEndpoint) {
    http3::Http3ServerEndpoint endpoint;

    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerRequestCompleteEvent{.stream_id = 0});

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, CompletionWithoutBufferedHeadFailsEndpoint) {
    http3::Http3ServerEndpoint endpoint;

    http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0).body = bytes_from_text("x");
    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerRequestCompleteEvent{.stream_id = 0});

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, EarlyResponseFollowedByResetInSameCoreResultFailsEndpoint) {
    http3::Http3ServerEndpoint endpoint(http3::Http3ServerConfig{
        .request_head_handler =
            [](const http3::Http3RequestHead &) -> std::optional<http3::Http3Response> {
            return http3::Http3Response{
                .head =
                    {
                        .status = 204,
                        .content_length = 0,
                    },
            };
        },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        http3::Http3Field{":method", "POST"},
        http3::Http3Field{":scheme", "https"},
        http3::Http3Field{":authority", "example.test"},
        http3::Http3Field{":path", "/reset-after-early"},
        http3::Http3Field{"content-length", "4"},
    };

    coquic::quic::QuicCoreResult result;
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreReceiveStreamData{
            .stream_id = 0,
            .bytes = headers_frame_bytes(0, request_fields),
            .fin = false,
        },
    });
    result.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCorePeerResetStream{
            .stream_id = 0,
            .application_error_code =
                static_cast<std::uint64_t>(http3::Http3ErrorCode::request_cancelled),
        },
    });

    const auto update = endpoint.on_core_result(result, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, InvalidRequestFrameCausesTerminalFailureDuringOnCoreResult) {
    http3::Http3ServerEndpoint endpoint;

    prime_server_transport(endpoint);

    const auto update = endpoint.on_core_result(receive_result(0, data_frame_bytes("bad"), true),
                                                coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, BufferedHandlerResponseErrorFailsEndpoint) {
    http3::Http3ServerEndpoint endpoint(http3::Http3ServerConfig{
        .request_handler =
            [](const http3::Http3Request &) {
                return http3::Http3Response{
                    .head =
                        {
                            .status = 200,
                            .content_length = 1,
                        },
                    .body = bytes_from_text("pong"),
                };
            },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        http3::Http3Field{":method", "GET"},
        http3::Http3Field{":scheme", "https"},
        http3::Http3Field{":authority", "example.test"},
        http3::Http3Field{":path", "/broken"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, EarlyHandlerResponseErrorFailsEndpoint) {
    http3::Http3ServerEndpoint endpoint(http3::Http3ServerConfig{
        .request_head_handler =
            [](const http3::Http3RequestHead &) -> std::optional<http3::Http3Response> {
            return http3::Http3Response{
                .head =
                    {
                        .status = 200,
                        .content_length = 1,
                    },
                .body = bytes_from_text("pong"),
            };
        },
    });

    prime_server_transport(endpoint);

    const std::array request_fields{
        http3::Http3Field{":method", "GET"},
        http3::Http3Field{":scheme", "https"},
        http3::Http3Field{":authority", "example.test"},
        http3::Http3Field{":path", "/broken-early"},
    };

    const auto update =
        endpoint.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ServerTest, HelperHooksCoverRemainingDefaultRouteAndDemoRouteErrors) {
    const auto missing = http3::server_default_route_response_for_test(http3::Http3Request{
        .head =
            {
                .method = "GET",
                .path = "/missing-helper",
            },
    });
    EXPECT_EQ(missing.head.status, 404);
    EXPECT_EQ(missing.head.content_length, std::optional<std::uint64_t>{0});

    EXPECT_TRUE(http3::server_would_exceed_body_limit_for_test(/*buffered_bytes=*/5,
                                                               /*incoming_bytes=*/1,
                                                               /*limit=*/4));

    const auto ping_method_not_allowed =
        http3::server_default_route_response_for_test(http3::Http3Request{
            .head =
                {
                    .method = "POST",
                    .path = "/_coquic/speed/ping",
                },
        });
    EXPECT_EQ(ping_method_not_allowed.head.status, 405);
    EXPECT_EQ(ping_method_not_allowed.head.headers, (http3::Http3Headers{{"allow", "GET, HEAD"}}));

    const auto ping_head = http3::server_default_route_response_for_test(http3::Http3Request{
        .head =
            {
                .method = "HEAD",
                .path = "/_coquic/speed/ping",
            },
    });
    EXPECT_EQ(ping_head.head.status, 204);
    EXPECT_EQ(ping_head.head.content_length, std::optional<std::uint64_t>{0});

    const auto download_method_not_allowed =
        http3::server_default_route_response_for_test(http3::Http3Request{
            .head =
                {
                    .method = "POST",
                    .path = "/_coquic/speed/download?bytes=16",
                },
        });
    EXPECT_EQ(download_method_not_allowed.head.status, 405);
    EXPECT_EQ(download_method_not_allowed.head.headers,
              (http3::Http3Headers{{"allow", "GET, HEAD"}}));

    const auto download_head = http3::server_default_route_response_for_test(http3::Http3Request{
        .head =
            {
                .method = "HEAD",
                .path = "/_coquic/speed/download?bytes=16",
            },
    });
    EXPECT_EQ(download_head.head.status, 200);
    EXPECT_EQ(download_head.head.content_length, std::optional<std::uint64_t>{16});

    const auto duplicate_bytes_query =
        http3::server_default_route_response_for_test(http3::Http3Request{
            .head =
                {
                    .method = "GET",
                    .path = "/_coquic/speed/download?bytes=16&bytes=32",
                },
        });
    EXPECT_EQ(duplicate_bytes_query.head.status, 400);
    EXPECT_EQ(duplicate_bytes_query.head.headers,
              (http3::Http3Headers{{"cache-control", "no-store"}}));

    const auto empty_bytes_query =
        http3::server_default_route_response_for_test(http3::Http3Request{
            .head =
                {
                    .method = "GET",
                    .path = "/_coquic/speed/download?",
                },
        });
    EXPECT_EQ(empty_bytes_query.head.status, 400);

    const auto partial_bytes_query =
        http3::server_default_route_response_for_test(http3::Http3Request{
            .head =
                {
                    .method = "GET",
                    .path = "/_coquic/speed/download?bytes=16x",
                },
        });
    EXPECT_EQ(partial_bytes_query.head.status, 400);

    const auto zero_bytes_query = http3::server_default_route_response_for_test(http3::Http3Request{
        .head =
            {
                .method = "GET",
                .path = "/_coquic/speed/download?bytes=0",
            },
    });
    EXPECT_EQ(zero_bytes_query.head.status, 400);

    const auto oversized_upload = http3::server_default_route_response_for_test(http3::Http3Request{
        .head =
            {
                .method = "POST",
                .path = "/_coquic/speed/upload",
            },
        .body = std::vector<std::byte>((static_cast<std::size_t>(4) * 1024u * 1024u) + 1u,
                                       std::byte{0x61}),
    });
    EXPECT_EQ(oversized_upload.head.status, 400);
    EXPECT_EQ(oversized_upload.head.headers, (http3::Http3Headers{{"cache-control", "no-store"}}));
}

TEST(QuicHttp3ServerTest, UploadHeadEarlyResponseTreatsQueryPathAsUploadRoute) {
    http3::Http3ServerEndpoint endpoint;
    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::set_transport_ready(connection, true);
    http3::Http3ConnectionTestAccess::ensure_local_response_stream(connection, 0);
    http3::Http3ConnectionTestAccess::ensure_peer_request_stream(connection, 0);
    http3::Http3ConnectionTestAccess::queue_event(
        connection,
        http3::Http3PeerRequestHeadEvent{
            .stream_id = 0,
            .head =
                http3::Http3RequestHead{
                    .method = "POST",
                    .path = "/_coquic/speed/upload?trace=1",
                    .content_length = (static_cast<std::uint64_t>(4) * 1024u * 1024u) + 1u,
                },
        });

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_FALSE(endpoint.has_failed());
    EXPECT_TRUE(http3::Http3ServerEndpointTestAccess::pending_requests_empty(endpoint));

    ASSERT_FALSE(update.core_inputs.empty());
    const auto *send =
        std::get_if<coquic::quic::QuicCoreSendStreamData>(&update.core_inputs.front());
    ASSERT_NE(send, nullptr);
    EXPECT_FALSE(send->bytes.empty());
}

TEST(QuicHttp3ServerTest, BuffersBodyAndTrailersWithoutCommittedEarlyResponse) {
    http3::Http3ServerEndpoint endpoint;
    http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 2);

    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerRequestBodyEvent{.stream_id = 1, .body = bytes_from_text("x")});
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerRequestBodyEvent{.stream_id = 2, .body = bytes_from_text("y")});
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerRequestTrailersEvent{.stream_id = 3, .trailers = {{"x", "1"}}});

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_FALSE(endpoint.has_failed());
    EXPECT_EQ(http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 1).body,
              bytes_from_text("x"));
    EXPECT_EQ(http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 2).body,
              bytes_from_text("y"));
    EXPECT_EQ(http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 3).trailers,
              (http3::Http3Headers{{"x", "1"}}));
}

TEST(QuicHttp3ServerTest, EarlyCommittedPendingRequestIgnoresQueuedBodyAndTrailers) {
    http3::Http3ServerEndpoint endpoint;
    auto &pending = http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0);
    pending.head = http3::Http3RequestHead{
        .method = "POST",
        .path = "/ignored",
    };
    pending.early_response_committed = true;

    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerRequestBodyEvent{.stream_id = 0, .body = bytes_from_text("x")});
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerRequestTrailersEvent{.stream_id = 0, .trailers = {{"x", "1"}}});

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_TRUE(update.request_cancelled_events.empty());
    EXPECT_TRUE(http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0)
                    .early_response_committed);
    EXPECT_TRUE(http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0).body.empty());
    EXPECT_TRUE(
        http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0).trailers.empty());
}

TEST(QuicHttp3ServerTest, EarlyCommittedPendingRequestResetAndCompletionErasePendingState) {
    {
        http3::Http3ServerEndpoint endpoint;
        auto &pending = http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0);
        pending.head = http3::Http3RequestHead{
            .method = "POST",
            .path = "/ignored-reset",
        };
        pending.early_response_committed = true;

        auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
        http3::Http3ConnectionTestAccess::queue_event(
            connection,
            http3::Http3PeerRequestResetEvent{.stream_id = 0, .application_error_code = 7});

        const auto update = endpoint.on_core_result(coquic::quic::QuicCoreResult{},
                                                    coquic::quic::QuicCoreTimePoint{});
        EXPECT_FALSE(update.terminal_failure);
        EXPECT_TRUE(update.request_cancelled_events.empty());
        EXPECT_FALSE(endpoint.has_failed());
        EXPECT_EQ(http3::Http3ServerEndpointTestAccess::pending_request_count(endpoint, 0), 0u);
    }

    {
        http3::Http3ServerEndpoint endpoint;
        auto &pending = http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0);
        pending.head = http3::Http3RequestHead{
            .method = "POST",
            .path = "/ignored-complete",
        };
        pending.early_response_committed = true;

        auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
        http3::Http3ConnectionTestAccess::queue_event(connection,
                                                      http3::Http3PeerRequestCompleteEvent{
                                                          .stream_id = 0,
                                                      });

        const auto update = endpoint.on_core_result(coquic::quic::QuicCoreResult{},
                                                    coquic::quic::QuicCoreTimePoint{});
        EXPECT_FALSE(update.terminal_failure);
        EXPECT_TRUE(update.request_cancelled_events.empty());
        EXPECT_FALSE(endpoint.has_failed());
        EXPECT_EQ(http3::Http3ServerEndpointTestAccess::pending_request_count(endpoint, 0), 0u);
    }
}

TEST(QuicHttp3ServerTest, IgnoresUnexpectedNonRequestEventInServerEndpointLoop) {
    http3::Http3ServerEndpoint endpoint;
    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerResponseHeadEvent{
                        .stream_id = 0,
                        .head = http3::Http3ResponseHead{.status = 204, .content_length = 0},
                    });

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_TRUE(update.request_cancelled_events.empty());
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp3ServerTest, RequestHeadEarlyResponseAbortFailureMarksEndpointFailed) {
    ScopedServerTestHookReset reset_hooks;
    http3::server_set_force_abort_request_body_failure_for_test(true);

    http3::Http3ServerEndpoint endpoint({
        .request_head_handler =
            [](const http3::Http3RequestHead &) {
                return http3::Http3Response{
                    .head =
                        {
                            .status = 204,
                            .content_length = 0,
                        },
                };
            },
    });
    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::set_transport_ready(connection, true);
    http3::Http3ConnectionTestAccess::ensure_local_response_stream(connection, 0);
    http3::Http3ConnectionTestAccess::queue_event(connection, http3::Http3PeerRequestHeadEvent{
                                                                  .stream_id = 0,
                                                                  .head =
                                                                      http3::Http3RequestHead{
                                                                          .method = "POST",
                                                                          .path = "/forced-abort",
                                                                      },
                                                              });

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(http3::Http3ServerEndpointTestAccess::pending_requests_empty(endpoint));
}

TEST(QuicHttp3ServerTest, BufferedUploadLimitAbortFailureMarksEndpointFailed) {
    ScopedServerTestHookReset reset_hooks;
    http3::server_set_force_abort_request_body_failure_for_test(true);

    http3::Http3ServerEndpoint endpoint;
    auto &pending = http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0);
    pending.head = http3::Http3RequestHead{
        .method = "POST",
        .path = "/_coquic/speed/upload",
    };
    pending.body =
        std::vector<std::byte>((static_cast<std::size_t>(4) * 1024u * 1024u) + 1u, std::byte{0x61});

    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::set_transport_ready(connection, true);
    http3::Http3ConnectionTestAccess::ensure_local_response_stream(connection, 0);
    http3::Http3ConnectionTestAccess::queue_event(
        connection, http3::Http3PeerRequestBodyEvent{.stream_id = 0, .body = bytes_from_text("x")});

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(http3::Http3ServerEndpointTestAccess::pending_requests_empty(endpoint));
}

TEST(QuicHttp3ServerTest, SameBatchResetForIgnoredEarlyResponseErasesPendingState) {
    http3::Http3ServerEndpoint endpoint({
        .request_head_handler =
            [](const http3::Http3RequestHead &) {
                return http3::Http3Response{
                    .head =
                        {
                            .status = 204,
                            .content_length = 0,
                        },
                };
            },
    });
    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::set_transport_ready(connection, true);
    http3::Http3ConnectionTestAccess::ensure_local_response_stream(connection, 0);
    http3::Http3ConnectionTestAccess::ensure_peer_request_stream(connection, 0);
    http3::Http3ConnectionTestAccess::queue_event(connection,
                                                  http3::Http3PeerRequestHeadEvent{
                                                      .stream_id = 0,
                                                      .head =
                                                          http3::Http3RequestHead{
                                                              .method = "POST",
                                                              .path = "/ignored-reset-same-batch",
                                                          },
                                                  });
    http3::Http3ConnectionTestAccess::queue_event(
        connection,
        http3::Http3PeerRequestResetEvent{.stream_id = 0, .application_error_code = 11});

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_FALSE(endpoint.has_failed());
    EXPECT_TRUE(update.request_cancelled_events.empty());
    EXPECT_EQ(http3::Http3ServerEndpointTestAccess::pending_request_count(endpoint, 0), 0u);
}

TEST(QuicHttp3ServerTest, CompleteEventWithMissingHeadFailsEndpoint) {
    http3::Http3ServerEndpoint endpoint;
    http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0).body = bytes_from_text("x");
    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::queue_event(connection, http3::Http3PeerRequestCompleteEvent{
                                                                  .stream_id = 0,
                                                              });

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(http3::Http3ServerEndpointTestAccess::pending_requests_empty(endpoint));
}

TEST(QuicHttp3ServerTest, FollowUpPollFailureAfterDispatchMarksEndpointFailed) {
    ScopedServerTestHookReset reset_hooks;
    http3::server_set_force_follow_up_poll_terminal_failure_for_test(true);

    http3::Http3ServerEndpoint endpoint({
        .request_handler =
            [](const http3::Http3Request &) {
                return http3::Http3Response{
                    .head =
                        {
                            .status = 204,
                            .content_length = 0,
                        },
                };
            },
    });
    http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 0).head =
        http3::Http3RequestHead{
            .method = "GET",
            .path = "/follow-up-failure",
        };
    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::set_transport_ready(connection, true);
    http3::Http3ConnectionTestAccess::ensure_local_response_stream(connection, 0);
    http3::Http3ConnectionTestAccess::queue_event(connection, http3::Http3PeerRequestCompleteEvent{
                                                                  .stream_id = 0,
                                                              });

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(http3::Http3ServerEndpointTestAccess::pending_requests_empty(endpoint));
}

TEST(QuicHttp3ServerTest, PollPropagatesConnectionTerminalFailureAndMarksEndpointFailed) {
    http3::Http3ServerEndpoint endpoint;
    http3::Http3ServerEndpointTestAccess::pending_request(endpoint, 4).head =
        http3::Http3RequestHead{
            .method = "GET",
            .path = "/cleared",
        };
    auto &connection = http3::Http3ServerEndpointTestAccess::connection(endpoint);
    http3::Http3ConnectionTestAccess::set_closed(connection, true);

    const auto update = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
    EXPECT_TRUE(http3::Http3ServerEndpointTestAccess::pending_requests_empty(endpoint));
}

} // namespace
