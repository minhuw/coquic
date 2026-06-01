#include "tests/support/http3/connection_test_support.h"

namespace {

void expect_get_request_head(const coquic::http3::Http3PeerRequestHeadEvent &head) {
    EXPECT_EQ(head.stream_id, 0u);
    EXPECT_EQ(head.head.method, "GET");
    EXPECT_EQ(head.head.scheme, "https");
    EXPECT_EQ(head.head.authority, "example.test");
    EXPECT_EQ(head.head.path, "/hello");
    EXPECT_EQ(head.head.content_length, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRequestHeadersEmitPeerRequestHeadEvent) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/hello"},
        coquic::http3::Http3Field{"content-length", "0"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 1u);
    auto *head = std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&update.events[0]);
    ASSERT_NE(head, nullptr);
    expect_get_request_head(*head);
}

TEST(QuicHttp3ConnectionTest, DataBeforeHeadersClosesConnectionWithFrameUnexpected) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update = connection.on_core_result(receive_result(0, data_frame_bytes("body")),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, RequestTrailersEmitEventsAndCompleteOnFin) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "4"},
    };
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto bytes = headers_frame_bytes(0, request_fields);
    auto data = data_frame_bytes("ping");
    bytes.insert(bytes.end(), data.begin(), data.end());
    auto trailers = headers_frame_bytes(0, trailer_fields);
    bytes.insert(bytes.end(), trailers.begin(), trailers.end());

    auto update = connection.on_core_result(receive_result(0, bytes, true),
                                            coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 4u);

    auto *head = std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&update.events[0]);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(head->head.method, "POST");
    EXPECT_EQ(head->head.path, "/upload");
    EXPECT_EQ(head->head.content_length, std::optional<std::uint64_t>(4u));

    auto *body = std::get_if<coquic::http3::Http3PeerRequestBodyEvent>(&update.events[1]);
    ASSERT_NE(body, nullptr);
    EXPECT_EQ(body->stream_id, 0u);
    EXPECT_EQ(body->body, bytes_from_text("ping"));

    auto *trailers_event =
        std::get_if<coquic::http3::Http3PeerRequestTrailersEvent>(&update.events[2]);
    ASSERT_NE(trailers_event, nullptr);
    EXPECT_EQ(trailers_event->stream_id, 0u);
    EXPECT_EQ(trailers_event->trailers, (coquic::http3::Http3Headers{{"etag", "done"}}));

    auto *complete = std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[3]);
    ASSERT_NE(complete, nullptr);
    EXPECT_EQ(complete->stream_id, 0u);
}

TEST(QuicHttp3ConnectionTest, DataAfterTrailingHeadersClosesConnectionWithFrameUnexpected) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
    };
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto bytes = headers_frame_bytes(0, request_fields);
    auto trailers = headers_frame_bytes(0, trailer_fields);
    bytes.insert(bytes.end(), trailers.begin(), trailers.end());
    auto late_data = data_frame_bytes("late");
    bytes.insert(bytes.end(), late_data.begin(), late_data.end());

    auto update =
        connection.on_core_result(receive_result(0, bytes), coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, MalformedRequestHeadersResetRequestStreamWithMessageError) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "abc"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());

    auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, ContentLengthMismatchResetsRequestStreamWithMessageError) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "4"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(headers_update).has_value());
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    auto body_update = connection.on_core_result(receive_result(0, data_frame_bytes("abc"), true),
                                                 coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(body_update).has_value());
    ASSERT_EQ(body_update.events.size(), 1u);
    auto *body = std::get_if<coquic::http3::Http3PeerRequestBodyEvent>(&body_update.events[0]);
    ASSERT_NE(body, nullptr);
    EXPECT_EQ(body->body, bytes_from_text("abc"));

    auto resets = reset_stream_inputs_from(body_update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    auto stops = stop_sending_inputs_from(body_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, BlockedRequestHeadersEmitEventOnlyAfterQpackUnblocks) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "www.example.com"},
        coquic::http3::Http3Field{":path", "/sample/path"},
    };
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
        .local_settings = local_settings,
    });
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = 220,
                .blocked_streams = 1,
            },
    };

    auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);

    std::vector<std::byte> encoder_instructions;
    auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, request_fields, &encoder_instructions)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    auto unblocked_update = connection.on_core_result(
        receive_result(6, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 1u);
    auto *head = std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&unblocked_update.events[0]);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(head->stream_id, 0u);
    EXPECT_EQ(head->head.authority, "www.example.com");
    EXPECT_EQ(head->head.path, "/sample/path");
}

TEST(QuicHttp3ConnectionTest, CompletedRequestStreamsAreCleanedUp) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields), true),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&update.events[0]), nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[1]),
              nullptr);
    EXPECT_EQ(coquic::http3::Http3ConnectionPeerRequestStreamAccess::size(connection), 0u);
}

TEST(QuicHttp3ConnectionTest, ServerQueuesHeadersOnlyFinalResponseWithFin) {
    std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 204,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    auto finish = connection.finish_response(0);
    ASSERT_TRUE(finish.has_value());
    EXPECT_TRUE(finish.value());

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    auto expected = headers_frame_bytes(0, response_fields(204, response_headers));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, ServerQueuesFinalHeadersThenBodyWithFin) {
    std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
        coquic::http3::Http3Field{"content-type", "text/plain"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    auto body = connection.submit_response_body(0, bytes_from_text("pong"), true);
    ASSERT_TRUE(body.has_value());
    EXPECT_TRUE(body.value());

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    auto expected_headers = headers_frame_bytes(0, response_fields(200, response_headers));
    auto expected_body = data_frame_bytes("pong");

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ServerQueuesTrailersWithFinAfterResponseBody) {
    std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    auto body = connection.submit_response_body(0, bytes_from_text("pong"));
    ASSERT_TRUE(body.has_value());
    EXPECT_TRUE(body.value());

    auto trailers = connection.submit_response_trailers(0, trailer_fields, true);
    ASSERT_TRUE(trailers.has_value());
    EXPECT_TRUE(trailers.value());

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder;
    auto expected_headers = headers_frame_bytes(encoder, 0, response_fields(200, response_headers));
    auto expected_body = data_frame_bytes("pong");
    auto expected_trailers = headers_frame_bytes(encoder, 0, trailer_fields);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_body);
    EXPECT_FALSE(sends[1].fin);
    EXPECT_EQ(sends[2].stream_id, 0u);
    EXPECT_EQ(sends[2].bytes, expected_trailers);
    EXPECT_TRUE(sends[2].fin);
}

TEST(QuicHttp3ConnectionTest, ServerAllowsInterimResponseBeforeFinalResponse) {
    std::array interim_headers{
        coquic::http3::Http3Field{"link", "</style.css>; rel=preload"},
    };
    std::array final_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto interim = connection.submit_response_head(
        0,
        coquic::http3::Http3ResponseHead{
            .status = 103,
            .headers = coquic::http3::Http3Headers(interim_headers.begin(), interim_headers.end()),
        });
    ASSERT_TRUE(interim.has_value());
    EXPECT_TRUE(interim.value());

    auto final = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers = coquic::http3::Http3Headers(final_headers.begin(), final_headers.end()),
           });
    ASSERT_TRUE(final.has_value());
    EXPECT_TRUE(final.value());

    auto finish = connection.finish_response(0);
    ASSERT_TRUE(finish.has_value());
    EXPECT_TRUE(finish.value());

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder;
    auto expected_interim = headers_frame_bytes(encoder, 0, response_fields(103, interim_headers));
    auto expected_final = headers_frame_bytes(encoder, 0, response_fields(200, final_headers));

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, expected_interim);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_final);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, SendingResponseBodyBeforeFinalHeadersFailsLocally) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto body = connection.submit_response_body(0, bytes_from_text("pong"), true);
    ASSERT_FALSE(body.has_value());
    EXPECT_EQ(body.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(body.error().stream_id, std::optional<std::uint64_t>(0u));

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, SendingResponseTrailersBeforeFinalHeadersFailsLocally) {
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto trailers = connection.submit_response_trailers(0, trailer_fields, true);
    ASSERT_FALSE(trailers.has_value());
    EXPECT_EQ(trailers.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(trailers.error().stream_id, std::optional<std::uint64_t>(0u));

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, SendingSecondFinalResponseFailsLocally) {
    std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto first = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(first.has_value());
    EXPECT_TRUE(first.value());
    ASSERT_TRUE(connection.finish_response(0).has_value());

    auto second = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 204,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(second.error().stream_id, std::optional<std::uint64_t>(0u));

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    auto expected_headers = headers_frame_bytes(0, response_fields(200, response_headers));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, SendingResponseBodyPastDeclaredContentLengthFailsLocally) {
    std::array response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .content_length = 0,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    auto body = connection.submit_response_body(0, bytes_from_text("x"));
    ASSERT_FALSE(body.has_value());
    EXPECT_EQ(body.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(body.error().stream_id, std::optional<std::uint64_t>(0u));

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    auto expected_headers = headers_frame_bytes(0, response_fields(200, response_headers, 0u));

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].bytes, expected_headers);
    EXPECT_FALSE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, ServerResponseApiRejectsWrongRoleTransportAndClosedStates) {
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection unready(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    ASSERT_FALSE(unready.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                     .has_value());
    ASSERT_FALSE(unready.submit_response_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(unready.submit_response_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(unready.finish_response(0).has_value());

    coquic::http3::Http3Connection wrong_role(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    ASSERT_FALSE(wrong_role.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                     .has_value());
    ASSERT_FALSE(wrong_role.submit_response_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(wrong_role.submit_response_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(wrong_role.finish_response(0).has_value());

    coquic::http3::Http3Connection closed(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(closed);
    EXPECT_TRUE(close_input_from(closed.on_core_result(stop_sending_result(3),
                                                       coquic::quic::QuicCoreTimePoint{}))
                    .has_value());
    ASSERT_TRUE(closed.is_closed());
    ASSERT_FALSE(closed.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                     .has_value());
    ASSERT_FALSE(closed.submit_response_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(closed.submit_response_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(closed.finish_response(0).has_value());
}

TEST(QuicHttp3ConnectionTest, ServerResponseHeadValidationBranches) {
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(
        unknown_stream.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
            .has_value());

    coquic::http3::Http3Connection duplicate_final(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(duplicate_final);
    receive_completed_get_request(duplicate_final, 0);
    ASSERT_TRUE(
        duplicate_final.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
            .has_value());
    ASSERT_FALSE(
        duplicate_final.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 204})
            .has_value());

    coquic::http3::Http3Connection after_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(after_trailers);
    receive_completed_get_request(after_trailers, 0);
    ASSERT_TRUE(after_trailers
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 0,
                                          })
                    .has_value());
    ASSERT_TRUE(after_trailers.submit_response_trailers(0, trailer_fields, false).has_value());
    ASSERT_FALSE(
        after_trailers.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 204})
            .has_value());
}

TEST(QuicHttp3ConnectionTest, ServerRoleRejectsInvalidResponseHeadFields) {
    std::array invalid_headers{
        coquic::http3::Http3Field{"Connection", "close"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto result =
        connection.submit_response_head(0, coquic::http3::Http3ResponseHead{
                                               .status = 200,
                                               .headers = std::vector<coquic::http3::Http3Field>(
                                                   invalid_headers.begin(), invalid_headers.end()),
                                           });
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(result.error().stream_id, std::nullopt);
}

TEST(QuicHttp3ConnectionTest, ServerResponseBodyValidationBranches) {
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(unknown_stream.submit_response_body(0, bytes_from_text("x")).has_value());

    coquic::http3::Http3Connection finished(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(finished);
    receive_completed_get_request(finished, 0);
    ASSERT_TRUE(finished
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 1,
                                          })
                    .has_value());
    ASSERT_TRUE(finished.submit_response_body(0, bytes_from_text("x"), true).has_value());
    ASSERT_FALSE(finished.submit_response_body(0, bytes_from_text("y")).has_value());

    coquic::http3::Http3Connection after_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(after_trailers);
    receive_completed_get_request(after_trailers, 0);
    ASSERT_TRUE(after_trailers
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 0,
                                          })
                    .has_value());
    ASSERT_TRUE(after_trailers.submit_response_trailers(0, trailer_fields, false).has_value());
    ASSERT_FALSE(after_trailers.submit_response_body(0, bytes_from_text("late")).has_value());

    coquic::http3::Http3Connection fin_mismatch(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(fin_mismatch);
    receive_completed_get_request(fin_mismatch, 0);
    ASSERT_TRUE(fin_mismatch
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 2,
                                          })
                    .has_value());
    ASSERT_FALSE(fin_mismatch.submit_response_body(0, bytes_from_text("x"), true).has_value());
}

TEST(QuicHttp3ConnectionTest, ServerResponseTrailersValidationBranches) {
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    std::array invalid_trailers{
        coquic::http3::Http3Field{":status", "200"},
    };

    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(unknown_stream.submit_response_trailers(0, trailer_fields).has_value());

    coquic::http3::Http3Connection finished(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(finished);
    receive_completed_get_request(finished, 0);
    ASSERT_TRUE(finished.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 204})
                    .has_value());
    ASSERT_TRUE(finished.finish_response(0).has_value());
    ASSERT_FALSE(finished.submit_response_trailers(0, trailer_fields).has_value());

    coquic::http3::Http3Connection duplicate_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(duplicate_trailers);
    receive_completed_get_request(duplicate_trailers, 0);
    ASSERT_TRUE(duplicate_trailers
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 0,
                                          })
                    .has_value());
    ASSERT_TRUE(duplicate_trailers.submit_response_trailers(0, trailer_fields, false).has_value());
    ASSERT_FALSE(duplicate_trailers.submit_response_trailers(0, trailer_fields, false).has_value());

    coquic::http3::Http3Connection body_mismatch(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(body_mismatch);
    receive_completed_get_request(body_mismatch, 0);
    ASSERT_TRUE(body_mismatch
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 1,
                                          })
                    .has_value());
    ASSERT_FALSE(body_mismatch.submit_response_trailers(0, trailer_fields).has_value());

    coquic::http3::Http3Connection invalid_trailer_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(invalid_trailer_connection);
    receive_completed_get_request(invalid_trailer_connection, 0);
    ASSERT_TRUE(invalid_trailer_connection
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 0,
                                          })
                    .has_value());
    ASSERT_FALSE(
        invalid_trailer_connection.submit_response_trailers(0, invalid_trailers).has_value());
}

TEST(QuicHttp3ConnectionTest, ServerFinishResponseValidationBranches) {
    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(unknown_stream.finish_response(0).has_value());

    coquic::http3::Http3Connection missing_final(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(missing_final);
    receive_completed_get_request(missing_final, 0);
    ASSERT_FALSE(missing_final.finish_response(0).has_value());

    coquic::http3::Http3Connection duplicate_finish(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(duplicate_finish);
    receive_completed_get_request(duplicate_finish, 0);
    ASSERT_TRUE(
        duplicate_finish.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 204})
            .has_value());
    ASSERT_TRUE(duplicate_finish.finish_response(0).has_value());
    ASSERT_FALSE(duplicate_finish.finish_response(0).has_value());

    coquic::http3::Http3Connection body_mismatch(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(body_mismatch);
    receive_completed_get_request(body_mismatch, 0);
    ASSERT_TRUE(body_mismatch
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                              .content_length = 1,
                                          })
                    .has_value());
    ASSERT_FALSE(body_mismatch.finish_response(0).has_value());
}

TEST(QuicHttp3ConnectionTest, DynamicTableResponseHeadersQueueEncoderInstructionsBeforeHeaders) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array response_headers{
        coquic::http3::Http3Field{"x-coquic-token", "bravo"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, peer_settings);
    receive_completed_get_request(connection, 0);

    auto head = connection.submit_response_head(
        0, coquic::http3::Http3ResponseHead{
               .status = 200,
               .headers =
                   coquic::http3::Http3Headers(response_headers.begin(), response_headers.end()),
           });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());
    ASSERT_TRUE(connection.finish_response(0).has_value());

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = peer_settings.qpack_max_table_capacity,
                .blocked_streams = peer_settings.qpack_blocked_streams,
            },
    };
    std::vector<std::byte> encoder_instructions;
    auto expected_headers = headers_frame_bytes(encoder, 0, response_fields(200, response_headers),
                                                &encoder_instructions);

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_FALSE(encoder_instructions.empty());
    EXPECT_EQ(sends[0].stream_id, 7u);
    EXPECT_EQ(sends[0].bytes, encoder_instructions);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_headers);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleQueuesRequestHeadersBodyAndTrailersWithFin) {
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array request_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, peer_settings);

    auto head = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                      .method = "POST",
                                                      .scheme = "https",
                                                      .authority = "example.test",
                                                      .path = "/upload",
                                                      .content_length = 4,
                                                  });
    ASSERT_TRUE(head.has_value());
    EXPECT_TRUE(head.value());

    auto body = connection.submit_request_body(0, bytes_from_text("ping"));
    ASSERT_TRUE(body.has_value());
    EXPECT_TRUE(body.value());

    auto trailers = connection.submit_request_trailers(0, request_trailers);
    ASSERT_TRUE(trailers.has_value());
    EXPECT_TRUE(trailers.value());

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_FALSE(sends[0].bytes.empty());
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_FALSE(sends[1].bytes.empty());
    EXPECT_FALSE(sends[1].fin);
    EXPECT_EQ(sends[2].stream_id, 0u);
    EXPECT_FALSE(sends[2].bytes.empty());
    EXPECT_TRUE(sends[2].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsRequestLifecycleAfterInvalidInitialHeaders) {
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    auto invalid_head = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                              .method = "",
                                                              .scheme = "https",
                                                              .authority = "example.test",
                                                              .path = "/resource",
                                                          });
    ASSERT_FALSE(invalid_head.has_value());

    auto body = connection.submit_request_body(0, bytes_from_text("x"));
    ASSERT_FALSE(body.has_value());
    EXPECT_EQ(body.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(body.error().stream_id, std::optional<std::uint64_t>(0u));

    auto trailers = connection.submit_request_trailers(0, trailer_fields);
    ASSERT_FALSE(trailers.has_value());
    EXPECT_EQ(trailers.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(trailers.error().stream_id, std::optional<std::uint64_t>(0u));

    auto finish = connection.finish_request(0);
    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(finish.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsRequestBodyThatExceedsDeclaredContentLength) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 1,
                                         })
                    .has_value());

    auto body = connection.submit_request_body(0, bytes_from_text("xy"));
    ASSERT_FALSE(body.has_value());
    EXPECT_EQ(body.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(body.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsFinishingRequestWithContentLengthMismatch) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 2,
                                         })
                    .has_value());
    ASSERT_TRUE(connection.submit_request_body(0, bytes_from_text("x")).has_value());

    auto finish = connection.finish_request(0);
    ASSERT_FALSE(finish.has_value());
    EXPECT_EQ(finish.error().code, coquic::http3::Http3ErrorCode::message_error);
    EXPECT_EQ(finish.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsDuplicateFinishedRequest) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());

    auto second_finish = connection.finish_request(0);
    ASSERT_FALSE(second_finish.has_value());
    EXPECT_EQ(second_finish.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(second_finish.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRequestApiRejectsWrongRoleTransportAndClosedStates) {
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection unready(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    ASSERT_FALSE(unready
                     .submit_request_head(0,
                                          coquic::http3::Http3RequestHead{
                                              .method = "GET",
                                              .scheme = "https",
                                              .authority = "example.test",
                                              .path = "/resource",
                                          })
                     .has_value());
    ASSERT_FALSE(unready.submit_request_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(unready.submit_request_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(unready.finish_request(0).has_value());

    coquic::http3::Http3Connection wrong_role(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    ASSERT_FALSE(wrong_role
                     .submit_request_head(0,
                                          coquic::http3::Http3RequestHead{
                                              .method = "GET",
                                              .scheme = "https",
                                              .authority = "example.test",
                                              .path = "/resource",
                                          })
                     .has_value());
    ASSERT_FALSE(wrong_role.submit_request_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(wrong_role.submit_request_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(wrong_role.finish_request(0).has_value());

    coquic::http3::Http3Connection closed(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(closed);
    EXPECT_TRUE(close_input_from(closed.on_core_result(stop_sending_result(2),
                                                       coquic::quic::QuicCoreTimePoint{}))
                    .has_value());
    ASSERT_TRUE(closed.is_closed());
    ASSERT_FALSE(closed
                     .submit_request_head(0,
                                          coquic::http3::Http3RequestHead{
                                              .method = "GET",
                                              .scheme = "https",
                                              .authority = "example.test",
                                              .path = "/resource",
                                          })
                     .has_value());
    ASSERT_FALSE(closed.submit_request_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(closed.submit_request_trailers(0, trailer_fields).has_value());
    ASSERT_FALSE(closed.finish_request(0).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRequestHeadRejectsNonRequestStreamAndDuplicateHeaders) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    auto peer_initiated_stream = connection.submit_request_head(1, coquic::http3::Http3RequestHead{
                                                                       .method = "GET",
                                                                       .scheme = "https",
                                                                       .authority = "example.test",
                                                                       .path = "/resource",
                                                                   });
    ASSERT_FALSE(peer_initiated_stream.has_value());
    EXPECT_EQ(peer_initiated_stream.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(peer_initiated_stream.error().stream_id, std::optional<std::uint64_t>(1u));

    auto invalid_stream = connection.submit_request_head(2, coquic::http3::Http3RequestHead{
                                                                .method = "GET",
                                                                .scheme = "https",
                                                                .authority = "example.test",
                                                                .path = "/resource",
                                                            });
    ASSERT_FALSE(invalid_stream.has_value());
    EXPECT_EQ(invalid_stream.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(invalid_stream.error().stream_id, std::optional<std::uint64_t>(2u));

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());

    auto duplicate = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                           .method = "GET",
                                                           .scheme = "https",
                                                           .authority = "example.test",
                                                           .path = "/other",
                                                       });
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
    EXPECT_EQ(duplicate.error().stream_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, ClientRoleAllowsUndeclaredLengthRequestBodyFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                         })
                    .has_value());

    auto body = connection.submit_request_body(0, bytes_from_text("ping"), true);

    ASSERT_TRUE(body.has_value());
    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, data_frame_bytes("ping"));
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleAllowsUndeclaredLengthRequestTrailersAndFinish) {
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.submit_request_body(0, bytes_from_text("ping")).has_value());
    ASSERT_TRUE(connection.submit_request_trailers(0, trailer_fields, false).has_value());

    auto finish = connection.finish_request(0);

    ASSERT_TRUE(finish.has_value());
    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[2].stream_id, 0u);
    EXPECT_FALSE(sends[2].bytes.empty());
    EXPECT_TRUE(sends[2].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRequestBodyAndTrailersValidationBranches) {
    std::array invalid_trailers{
        coquic::http3::Http3Field{":status", "200"},
    };
    std::array valid_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };

    coquic::http3::Http3Connection final_chunk_mismatch(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(final_chunk_mismatch);
    receive_peer_settings(final_chunk_mismatch, {});
    ASSERT_TRUE(final_chunk_mismatch
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 2,
                                         })
                    .has_value());
    ASSERT_FALSE(
        final_chunk_mismatch.submit_request_body(0, bytes_from_text("x"), true).has_value());

    coquic::http3::Http3Connection body_after_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(body_after_trailers);
    receive_peer_settings(body_after_trailers, {});
    ASSERT_TRUE(body_after_trailers
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    ASSERT_TRUE(body_after_trailers.submit_request_trailers(0, valid_trailers, false).has_value());
    ASSERT_FALSE(body_after_trailers.submit_request_body(0, bytes_from_text("late")).has_value());

    coquic::http3::Http3Connection trailers_before_body_complete(
        coquic::http3::Http3ConnectionConfig{
            .role = coquic::http3::Http3ConnectionRole::client,
        });
    prime_client_transport(trailers_before_body_complete);
    receive_peer_settings(trailers_before_body_complete, {});
    ASSERT_TRUE(trailers_before_body_complete
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 1,
                                         })
                    .has_value());
    ASSERT_FALSE(
        trailers_before_body_complete.submit_request_trailers(0, valid_trailers).has_value());

    coquic::http3::Http3Connection invalid_trailer_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(invalid_trailer_connection);
    receive_peer_settings(invalid_trailer_connection, {});
    ASSERT_TRUE(invalid_trailer_connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    ASSERT_FALSE(
        invalid_trailer_connection.submit_request_trailers(0, invalid_trailers).has_value());

    coquic::http3::Http3Connection trailers_after_finished(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(trailers_after_finished);
    receive_peer_settings(trailers_after_finished, {});
    ASSERT_TRUE(trailers_after_finished
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(trailers_after_finished.finish_request(0).has_value());
    ASSERT_FALSE(trailers_after_finished.submit_request_trailers(0, valid_trailers).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsRequestOperationsForMissingAndFinishedStreams) {
    std::array valid_trailers{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection missing_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(missing_stream);
    receive_peer_settings(missing_stream, {});

    ASSERT_FALSE(missing_stream.submit_request_body(0, bytes_from_text("x")).has_value());
    ASSERT_FALSE(missing_stream.submit_request_trailers(0, valid_trailers).has_value());
    ASSERT_FALSE(missing_stream.finish_request(0).has_value());

    coquic::http3::Http3Connection duplicate_trailers(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(duplicate_trailers);
    receive_peer_settings(duplicate_trailers, {});
    ASSERT_TRUE(duplicate_trailers
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    ASSERT_TRUE(duplicate_trailers.submit_request_trailers(0, valid_trailers, false).has_value());
    ASSERT_FALSE(duplicate_trailers.submit_request_trailers(0, valid_trailers).has_value());

    coquic::http3::Http3Connection finished_request(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    prime_client_transport(finished_request);
    receive_peer_settings(finished_request, {});
    ASSERT_TRUE(finished_request
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(finished_request.finish_request(0).has_value());
    ASSERT_FALSE(finished_request.submit_request_body(0, bytes_from_text("late")).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleEmitsInterimFinalBodyTrailersAndCompleteResponseEvents) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    std::array interim_headers{
        coquic::http3::Http3Field{":status", "103"},
        coquic::http3::Http3Field{"link", "</style.css>; rel=preload"},
    };
    std::array final_headers{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "4"},
        coquic::http3::Http3Field{"content-type", "text/plain"},
    };
    std::array trailer_headers{
        coquic::http3::Http3Field{"etag", "done"},
    };

    auto response_bytes = headers_frame_bytes(0, interim_headers);
    auto final_frame = headers_frame_bytes(0, final_headers);
    response_bytes.insert(response_bytes.end(), final_frame.begin(), final_frame.end());
    auto body_frame = data_frame_bytes("pong");
    response_bytes.insert(response_bytes.end(), body_frame.begin(), body_frame.end());
    auto trailers_frame = headers_frame_bytes(0, trailer_headers);
    response_bytes.insert(response_bytes.end(), trailers_frame.begin(), trailers_frame.end());

    auto update = connection.on_core_result(receive_result(0, response_bytes, true),
                                            coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(update.events.size(), 5u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerInformationalResponseEvent>(&update.events[0]),
              nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&update.events[1]), nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseBodyEvent>(&update.events[2]), nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseTrailersEvent>(&update.events[3]),
              nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&update.events[4]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleEmitsResponseBodyWithoutDeclaredContentLength) {
    auto final_headers = response_fields(200, {});
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&headers_update.events[0]),
              nullptr);

    auto body_update = connection.on_core_result(receive_result(0, data_frame_bytes("pong"), true),
                                                 coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(body_update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseBodyEvent>(&body_update.events[0]),
              nullptr);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&body_update.events[1]),
              nullptr);
    EXPECT_FALSE(close_input_from(body_update).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseDataBeforeHeaders) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto update = connection.on_core_result(receive_result(0, data_frame_bytes("oops"), false),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRolePeerResponseFinWithoutFinalHeadersResetsStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto update = connection.on_core_result(receive_result(0, std::span<const std::byte>{}, true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());

    auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseDataForHeadRequest) {
    std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "HEAD",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto response_bytes = headers_frame_bytes(0, response_headers);
    auto body = data_frame_bytes("oops");
    response_bytes.insert(response_bytes.end(), body.begin(), body.end());

    auto update = connection.on_core_result(receive_result(0, response_bytes),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseDataAfterTrailers) {
    std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
    };
    std::array trailer_headers{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto response_bytes = headers_frame_bytes(0, response_headers);
    auto trailers = headers_frame_bytes(0, trailer_headers);
    response_bytes.insert(response_bytes.end(), trailers.begin(), trailers.end());
    auto late_data = data_frame_bytes("late");
    response_bytes.insert(response_bytes.end(), late_data.begin(), late_data.end());

    auto update = connection.on_core_result(receive_result(0, response_bytes),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRoleResponseBodyBeyondDeclaredContentLengthResetsStream) {
    std::array response_headers{
        coquic::http3::Http3Field{":status", "200"},
        coquic::http3::Http3Field{"content-length", "1"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    auto response_bytes = headers_frame_bytes(0, response_headers);
    auto body = data_frame_bytes("xy");
    response_bytes.insert(response_bytes.end(), body.begin(), body.end());

    auto update = connection.on_core_result(receive_result(0, response_bytes),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&update.events[0]), nullptr);

    auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, ClientRoleBlockedFinalResponseHeadersCompleteAfterQpackUnblocks) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array response_headers{
        coquic::http3::Http3Field{":status", "204"},
        coquic::http3::Http3Field{"x-coquic-token", "bravo"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = 220,
                .blocked_streams = 1,
            },
    };

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/resource",
                                         })
                    .has_value());
    ASSERT_TRUE(connection.finish_request(0).has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    std::vector<std::byte> encoder_instructions;
    auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, response_headers, &encoder_instructions),
                       true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    auto unblocked_update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&unblocked_update.events[0]),
              nullptr);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&unblocked_update.events[1]),
        nullptr);
}

} // namespace
