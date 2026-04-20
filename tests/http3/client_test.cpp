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

coquic::quic::QuicCoreResult local_error_result() {
    coquic::quic::QuicCoreResult result;
    result.local_error = coquic::quic::QuicCoreLocalError{
        .code = coquic::quic::QuicCoreLocalErrorCode::unsupported_operation,
    };
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

} // namespace

namespace coquic::http3 {

struct Http3ClientEndpointTestAccess {
    static Http3Connection &connection(Http3ClientEndpoint &endpoint) {
        return endpoint.connection_;
    }
};

struct Http3ConnectionTestAccess {
    static void set_closed(Http3Connection &connection, bool closed) {
        connection.closed_ = closed;
    }

    static void queue_event(Http3Connection &connection, const Http3EndpointEvent &event) {
        connection.pending_events_.push_back(event);
    }
};

} // namespace coquic::http3

namespace {

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

TEST(QuicHttp3ClientTest, AllowsSubmissionBelowPeerGoawayBoundary) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    ASSERT_TRUE(endpoint
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
                     .on_core_result(receive_result(3, goaway_frame_bytes(8)),
                                     coquic::quic::QuicCoreTimePoint{})
                     .terminal_failure);

    const auto submitted = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "GET",
                .scheme = "https",
                .authority = "example.test",
                .path = "/second",
            },
    });
    ASSERT_TRUE(submitted.has_value());
    EXPECT_EQ(submitted.value(), 4u);
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

TEST(QuicHttp3ClientTest, LocalErrorFailureIsStickyAndRejectsFutureWork) {
    coquic::http3::Http3ClientEndpoint endpoint;

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

    const auto rejected = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "GET",
                .scheme = "https",
                .authority = "example.test",
                .path = "/after-failure",
            },
    });
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ClientTest, ClosedConnectionResultFailsEndpointDuringOnCoreResult) {
    coquic::http3::Http3ClientEndpoint endpoint;

    auto &connection = coquic::http3::Http3ClientEndpointTestAccess::connection(endpoint);
    coquic::http3::Http3ConnectionTestAccess::set_closed(connection, true);

    const auto update =
        endpoint.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ClientTest, ClosedConnectionPollFailsEndpoint) {
    coquic::http3::Http3ClientEndpoint endpoint;

    auto &connection = coquic::http3::Http3ClientEndpointTestAccess::connection(endpoint);
    coquic::http3::Http3ConnectionTestAccess::set_closed(connection, true);

    const auto update = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ClientTest, PendingInvalidRequestFailsWhenPollFlushesQueue) {
    coquic::http3::Http3ClientEndpoint endpoint;

    const auto submitted = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "",
                .scheme = "https",
                .authority = "example.test",
                .path = "/queued-invalid",
            },
    });
    ASSERT_TRUE(submitted.has_value());

    const auto ready =
        endpoint.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(ready.terminal_failure);
    EXPECT_TRUE(ready.has_pending_work);

    const auto update = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ClientTest, ReadyInvalidBodyRequestFailsImmediately) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    const auto submitted = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "POST",
                .scheme = "https",
                .authority = "example.test",
                .path = "/upload",
                .content_length = 1,
            },
        .body = bytes_from_text("xy"),
    });
    ASSERT_FALSE(submitted.has_value());
    EXPECT_EQ(submitted.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(submitted.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ClientTest, EmptyBodyRequestWithTrailersSubmitsImmediately) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    const auto submitted = endpoint.submit_request(coquic::http3::Http3Request{
        .head =
            {
                .method = "POST",
                .scheme = "https",
                .authority = "example.test",
                .path = "/trailers-only",
                .content_length = 0,
            },
        .trailers = {{"etag", "done"}},
    });
    ASSERT_TRUE(submitted.has_value());
    EXPECT_EQ(submitted.value(), 0u);

    const auto update = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_FALSE(send_stream_inputs_from(update).empty());
}

TEST(QuicHttp3ClientTest, QueuedEventsCoverInformationalAndIgnoredClientIncompatibleEvents) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    ASSERT_TRUE(endpoint
                    .submit_request(coquic::http3::Http3Request{
                        .head =
                            {
                                .method = "GET",
                                .scheme = "https",
                                .authority = "example.test",
                                .path = "/queued-events",
                            },
                    })
                    .has_value());
    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto &connection = coquic::http3::Http3ClientEndpointTestAccess::connection(endpoint);
    coquic::http3::Http3ConnectionTestAccess::queue_event(connection,
                                                          coquic::http3::Http3PeerRequestBodyEvent{
                                                              .stream_id = 9,
                                                              .body = bytes_from_text("ignored"),
                                                          });
    coquic::http3::Http3ConnectionTestAccess::queue_event(
        connection, coquic::http3::Http3PeerResponseResetEvent{
                        .stream_id = 4,
                        .application_error_code = 0,
                    });
    coquic::http3::Http3ConnectionTestAccess::queue_event(
        connection, coquic::http3::Http3PeerInformationalResponseEvent{
                        .stream_id = 0,
                        .head =
                            {
                                .status = 103,
                            },
                    });
    coquic::http3::Http3ConnectionTestAccess::queue_event(connection,
                                                          coquic::http3::Http3PeerResponseHeadEvent{
                                                              .stream_id = 0,
                                                              .head =
                                                                  {
                                                                      .status = 200,
                                                                  },
                                                          });
    coquic::http3::Http3ConnectionTestAccess::queue_event(connection,
                                                          coquic::http3::Http3PeerResponseBodyEvent{
                                                              .stream_id = 0,
                                                              .body = bytes_from_text("pong"),
                                                          });
    coquic::http3::Http3ConnectionTestAccess::queue_event(
        connection, coquic::http3::Http3PeerResponseTrailersEvent{
                        .stream_id = 0,
                        .trailers = {{"etag", "done"}},
                    });
    coquic::http3::Http3ConnectionTestAccess::queue_event(
        connection, coquic::http3::Http3PeerResponseCompleteEvent{
                        .stream_id = 0,
                    });

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    ASSERT_TRUE(update.request_error_events.empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_EQ(update.events[0].response.interim_heads.size(), 1u);
    EXPECT_EQ(update.events[0].response.interim_heads[0].status, 103u);
    EXPECT_EQ(update.events[0].response.head.status, 200u);
    EXPECT_EQ(update.events[0].response.body, bytes_from_text("pong"));
    EXPECT_EQ(update.events[0].response.trailers, (coquic::http3::Http3Headers{{"etag", "done"}}));
}

TEST(QuicHttp3ClientTest, QueuedCompleteWithoutActiveRequestFailsOnCoreResult) {
    coquic::http3::Http3ClientEndpoint endpoint;

    auto &connection = coquic::http3::Http3ClientEndpointTestAccess::connection(endpoint);
    coquic::http3::Http3ConnectionTestAccess::queue_event(
        connection, coquic::http3::Http3PeerResponseCompleteEvent{
                        .stream_id = 0,
                    });

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ClientTest, QueuedCompleteWithoutResponseFailsDuringPoll) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    ASSERT_TRUE(endpoint
                    .submit_request(coquic::http3::Http3Request{
                        .head =
                            {
                                .method = "GET",
                                .scheme = "https",
                                .authority = "example.test",
                                .path = "/missing-response",
                            },
                    })
                    .has_value());
    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto &connection = coquic::http3::Http3ClientEndpointTestAccess::connection(endpoint);
    coquic::http3::Http3ConnectionTestAccess::queue_event(
        connection, coquic::http3::Http3PeerResponseCompleteEvent{
                        .stream_id = 0,
                    });

    const auto update = endpoint.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

TEST(QuicHttp3ClientTest, QueuedCompleteWithoutResponseHeadFailsEndpoint) {
    coquic::http3::Http3ClientEndpoint endpoint;

    prime_client_transport(endpoint);

    ASSERT_TRUE(endpoint
                    .submit_request(coquic::http3::Http3Request{
                        .head =
                            {
                                .method = "GET",
                                .scheme = "https",
                                .authority = "example.test",
                                .path = "/missing-head",
                            },
                    })
                    .has_value());
    EXPECT_FALSE(send_stream_inputs_from(endpoint.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto &connection = coquic::http3::Http3ClientEndpointTestAccess::connection(endpoint);
    coquic::http3::Http3ConnectionTestAccess::queue_event(connection,
                                                          coquic::http3::Http3PeerResponseBodyEvent{
                                                              .stream_id = 0,
                                                              .body = bytes_from_text("body"),
                                                          });
    coquic::http3::Http3ConnectionTestAccess::queue_event(
        connection, coquic::http3::Http3PeerResponseCompleteEvent{
                        .stream_id = 0,
                    });

    const auto update =
        endpoint.on_core_result(coquic::quic::QuicCoreResult{}, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.terminal_failure);
    EXPECT_TRUE(endpoint.has_failed());
}

} // namespace
