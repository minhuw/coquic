#include "../support/gtest_compat.h"
#include "tests/support/http3/connection_test_support.h"

namespace {

TEST(QuicHttp3ConnectionTest, ClientRolePeerResetEmitsResponseResetEvent) {
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

    auto reset_update = connection.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected)),
        coquic::quic::QuicCoreTimePoint{});

    if (reset_update.events.size() != 1u) {
        FAIL() << "peer reset did not emit one event";
    }
    auto *peer_reset =
        std::get_if<coquic::http3::Http3PeerResponseResetEvent>(&reset_update.events[0]);
    if (peer_reset == nullptr) {
        FAIL() << "peer reset emitted the wrong event";
    }
    EXPECT_EQ(peer_reset->stream_id, 0u);
    EXPECT_EQ(peer_reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_rejected));
}

TEST(QuicHttp3ConnectionTest, ServerRolePeerResetEmitsRequestResetEvent) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto reset_update = connection.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});

    ASSERT_EQ(reset_update.events.size(), 1u);
    auto *reset = std::get_if<coquic::http3::Http3PeerRequestResetEvent>(&reset_update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRejectsSettingsFrameOnRequestStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update = connection.on_core_result(receive_result(0, settings_frame_bytes({})),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ServerRolePeerRequestFinWithoutHeadersResetsStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update = connection.on_core_result(receive_result(0, std::span<const std::byte>{}, true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());

    auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));

    auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));
}

TEST(QuicHttp3ConnectionTest, ServerRolePeerRequestFinWithTruncatedFrameResetsStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update = connection.on_core_result(receive_result(0, bytes_from_ints({0x01}), true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());

    auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));

    auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));
}

TEST(QuicHttp3ConnectionTest, ServerRoleBuffersIncompleteRequestFrameUntilCompletion) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto partial_update = connection.on_core_result(receive_result(0, bytes_from_ints({0x00})),
                                                    coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(partial_update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(partial_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(partial_update).empty());
    EXPECT_TRUE(partial_update.events.empty());

    auto final_update = connection.on_core_result(receive_result(0, bytes_from_ints({0x00}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(final_update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(final_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(final_update).empty());
    ASSERT_EQ(final_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&final_update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ServerRoleMalformedCompleteRequestFrameClosesConnection) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto update = connection.on_core_result(receive_result(0, bytes_from_ints({
                                                                  0x07,
                                                                  0x01,
                                                                  0x40,
                                                              })),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRejectsHeadersAfterRequestTrailers) {
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
    auto late_headers = headers_frame_bytes(0, trailer_fields);
    bytes.insert(bytes.end(), late_headers.begin(), late_headers.end());

    auto update =
        connection.on_core_result(receive_result(0, bytes), coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRequestBodyBeyondDeclaredContentLengthResetsStream) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "1"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto body_update = connection.on_core_result(receive_result(0, data_frame_bytes("xy")),
                                                 coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(body_update).has_value());
    EXPECT_TRUE(body_update.events.empty());

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

TEST(QuicHttp3ConnectionTest, ServerRoleBlockedRequestHeadersCompleteAfterQpackUnblocks) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "www.example.com"},
        coquic::http3::Http3Field{":path", "/sample/path"},
    };
    coquic::http3::Http3SettingsSnapshot local_settings{
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

    prime_server_transport(connection);

    std::vector<std::byte> encoder_instructions;
    auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, request_fields, &encoder_instructions),
                       true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    auto unblocked_update = connection.on_core_result(
        receive_result(6, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 2u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&unblocked_update.events[0]),
              nullptr);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&unblocked_update.events[1]),
        nullptr);
}

TEST(QuicHttp3ConnectionTest, ServerRoleAbortRequestBodyStopsSendingAndIgnoresLaterRequestFrames) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/too-large"},
        coquic::http3::Http3Field{"content-length", "8"},
    };

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    ASSERT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    ASSERT_TRUE(connection
                    .abort_request_body(
                        0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error))
                    .has_value());

    auto abort_update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto stops = stop_sending_inputs_from(abort_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));

    auto late_update = connection.on_core_result(
        receive_result(0, data_frame_bytes("ignored"), true), coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(late_update).has_value());
    EXPECT_TRUE(late_update.events.empty());
    EXPECT_TRUE(reset_stream_inputs_from(late_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(late_update).empty());
}

TEST(QuicHttp3ConnectionTest, ServerRoleAbortRequestValidationBranches) {
    coquic::http3::Http3Connection unready(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    ASSERT_FALSE(unready.abort_request_body(0).has_value());

    coquic::http3::Http3Connection wrong_role(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    ASSERT_FALSE(wrong_role.abort_request_body(0).has_value());

    coquic::http3::Http3Connection closed(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(closed);
    EXPECT_TRUE(close_input_from(closed.on_core_result(stop_sending_result(3),
                                                       coquic::quic::QuicCoreTimePoint{}))
                    .has_value());
    ASSERT_TRUE(closed.is_closed());
    ASSERT_FALSE(closed.abort_request_body(0).has_value());

    coquic::http3::Http3Connection unknown_stream(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(unknown_stream);
    ASSERT_FALSE(unknown_stream.abort_request_body(0).has_value());

    coquic::http3::Http3Connection terminated(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    prime_server_transport(terminated);
    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
    };
    auto request_update =
        terminated.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(request_update.events.size(), 1u);
    ASSERT_TRUE(terminated.abort_request_body(0).has_value());
    ASSERT_TRUE(terminated.abort_request_body(0).has_value());
}

TEST(QuicHttp3ConnectionTest, ServerRoleAbortBlockedRequestBodyFlushesQpackCancellation) {
    coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array request_headers{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
        coquic::http3::Http3Field{"x-coquic-token", "blocked"},
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

    prime_server_transport(connection);

    std::vector<std::byte> encoder_instructions;
    auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, request_headers, &encoder_instructions)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    ASSERT_TRUE(connection
                    .abort_request_body(
                        0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error))
                    .has_value());

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 11u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

    auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error));
}

TEST(QuicHttp3ConnectionTest, ServerRolePeerStopSendingResetsLocalResponseStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});

    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/hello"},
    };

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    ASSERT_TRUE(connection
                    .submit_response_head(0,
                                          coquic::http3::Http3ResponseHead{
                                              .status = 200,
                                          })
                    .has_value());

    auto stop_update = connection.on_core_result(
        stop_sending_result(
            0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    auto resets = reset_stream_inputs_from(stop_update);

    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
    EXPECT_FALSE(
        connection.submit_response_body(0, bytes_from_text("late body"), true).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsServerInitiatedBidirectionalStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    auto update = connection.on_core_result(receive_result(1, std::span<const std::byte>{}),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, ServerRoleIgnoresPeerStopSendingForUnknownResponseStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);

    auto update =
        connection.on_core_result(stop_sending_result(1), coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, ClientRoleBlockedResponseResetFlushesQpackCancellation) {
    coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array response_headers{
        coquic::http3::Http3Field{":status", "204"},
        coquic::http3::Http3Field{"x-coquic-token", "blocked"},
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
    submit_completed_client_get_request(connection, 0);

    std::vector<std::byte> encoder_instructions;
    auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, response_headers, &encoder_instructions)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    auto reset_update = connection.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(reset_update).has_value());

    auto sends = send_stream_inputs_from(reset_update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 10u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

    ASSERT_EQ(reset_update.events.size(), 1u);
    auto *reset = std::get_if<coquic::http3::Http3PeerResponseResetEvent>(&reset_update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}

TEST(QuicHttp3ConnectionTest, ServerRoleBlockedRequestResetFlushesQpackCancellation) {
    coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array request_headers{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
        coquic::http3::Http3Field{"x-coquic-token", "blocked"},
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

    prime_server_transport(connection);

    std::vector<std::byte> encoder_instructions;
    auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, request_headers, &encoder_instructions)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    auto reset_update = connection.on_core_result(
        reset_result(0,
                     static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(reset_update).has_value());

    auto sends = send_stream_inputs_from(reset_update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 11u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

    ASSERT_EQ(reset_update.events.size(), 1u);
    auto *reset = std::get_if<coquic::http3::Http3PeerRequestResetEvent>(&reset_update.events[0]);
    ASSERT_NE(reset, nullptr);
    EXPECT_EQ(reset->stream_id, 0u);
    EXPECT_EQ(reset->application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}

TEST(QuicHttp3ConnectionTest, ServerRoleBlockedRequestUnblockProcessesBufferedForbiddenFrame) {
    coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array request_headers{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
        coquic::http3::Http3Field{"x-coquic-token", "blocked"},
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

    prime_server_transport(connection);

    std::vector<std::byte> encoder_instructions;
    auto bytes = headers_frame_bytes(encoder, 0, request_headers, &encoder_instructions);
    auto settings = settings_frame_bytes({});
    bytes.insert(bytes.end(), settings.begin(), settings.end());

    auto blocked_update =
        connection.on_core_result(receive_result(0, bytes), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    auto unblocked_update = connection.on_core_result(
        receive_result(6, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(unblocked_update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ServerRoleInvalidRequestHeadersFieldSectionPrefixClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update = connection.on_core_result(receive_result(0, raw_headers_frame_bytes({})),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest,
     ServerRoleOverflowingRequestHeadersFieldSectionPrefixClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update = connection.on_core_result(
        receive_result(0, raw_headers_frame_bytes(overflowing_qpack_field_section_prefix_bytes())),
        coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ServerRoleMalformedRequestHeadersFieldSectionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto update =
        connection.on_core_result(receive_result(0, raw_headers_frame_bytes(bytes_from_ints({
                                                        0x00,
                                                        0x00,
                                                        0x01,
                                                    }))),
                                  coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ServerRoleInvalidRequestTrailersResetStream) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    std::array invalid_trailers{
        coquic::http3::Http3Field{":path", "/forbidden"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto trailers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, invalid_trailers), true),
                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(trailers_update).has_value());

    auto resets = reset_stream_inputs_from(trailers_update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    auto stops = stop_sending_inputs_from(trailers_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, ServerRoleBlockedRequestTrailersCompleteAfterQpackUnblocks) {
    coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
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

    prime_server_transport(connection);

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    std::vector<std::byte> encoder_instructions;
    auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, trailer_fields, &encoder_instructions),
                       true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(blocked_update).has_value());
    EXPECT_TRUE(blocked_update.events.empty());
    ASSERT_FALSE(encoder_instructions.empty());

    auto unblocked_update = connection.on_core_result(
        receive_result(6, encoder_stream_bytes(std::span<const std::byte>(encoder_instructions))),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(unblocked_update).has_value());
    ASSERT_EQ(unblocked_update.events.size(), 2u);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerRequestTrailersEvent>(&unblocked_update.events[0]),
        nullptr);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&unblocked_update.events[1]),
        nullptr);
}

TEST(QuicHttp3ConnectionTest, ServerRoleEmptyRequestDataFrameCompletesWithoutBodyEvent) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);

    auto update = connection.on_core_result(receive_result(0, data_frame_bytes(""), true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(update).empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ServerRoleIgnoresUnknownRequestFrameTypeAfterHeaders) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto update = connection.on_core_result(receive_result(0, unknown_frame_bytes(0x21), true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(update).empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerRequestCompleteEvent>(&update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleResponseFinWithTruncatedFrameResetsStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto update = connection.on_core_result(receive_result(0, bytes_from_ints({0x01}), true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

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

TEST(QuicHttp3ConnectionTest, ClientRoleBuffersIncompleteResponseFrameUntilCompletion) {
    auto final_response_headers = response_fields(200, {}, 0);
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto partial_update = connection.on_core_result(receive_result(0, bytes_from_ints({0x00})),
                                                    coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(partial_update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(partial_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(partial_update).empty());
    EXPECT_TRUE(partial_update.events.empty());

    auto final_update = connection.on_core_result(receive_result(0, bytes_from_ints({0x00}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(final_update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(final_update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(final_update).empty());
    ASSERT_EQ(final_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&final_update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleMalformedCompleteResponseFrameClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto update = connection.on_core_result(receive_result(0, bytes_from_ints({
                                                                  0x07,
                                                                  0x01,
                                                                  0x40,
                                                              })),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsForbiddenFrameTypeOnResponseStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto update = connection.on_core_result(receive_result(0, settings_frame_bytes({})),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRoleInvalidResponseHeadersFieldSectionPrefixClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto update = connection.on_core_result(receive_result(0, raw_headers_frame_bytes({})),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest,
     ClientRoleOverflowingResponseHeadersFieldSectionPrefixClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto update = connection.on_core_result(
        receive_result(0, raw_headers_frame_bytes(overflowing_qpack_field_section_prefix_bytes())),
        coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ClientRoleMalformedResponseHeadersFieldSectionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto update =
        connection.on_core_result(receive_result(0, raw_headers_frame_bytes(bytes_from_ints({
                                                        0x00,
                                                        0x00,
                                                        0x01,
                                                    }))),
                                  coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ClientRoleInvalidResponseHeadersResetStream) {
    std::array invalid_response_headers{
        coquic::http3::Http3Field{"server", "coquic"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(0, invalid_response_headers), true),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

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

TEST(QuicHttp3ConnectionTest, ClientRoleInvalidResponseTrailersResetStream) {
    auto final_response_headers = response_fields(200, {});
    std::array invalid_trailers{
        coquic::http3::Http3Field{":status", "204"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&headers_update.events[0]),
              nullptr);

    auto trailers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, invalid_trailers), true),
                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(trailers_update).has_value());

    auto resets = reset_stream_inputs_from(trailers_update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));

    auto stops = stop_sending_inputs_from(trailers_update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::message_error));
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsHeadersAfterResponseTrailers) {
    auto final_response_headers = response_fields(200, {});
    std::array trailer_fields{
        coquic::http3::Http3Field{"etag", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto head_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(head_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&head_update.events[0]),
              nullptr);

    auto trailers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, trailer_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(trailers_update.events.size(), 1u);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerResponseTrailersEvent>(&trailers_update.events[0]),
        nullptr);

    auto late_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, trailer_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(late_update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, ClientRoleBlockedResponseTrailersCompleteAfterQpackUnblocks) {
    coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    auto final_response_headers = response_fields(200, {});
    std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
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
    submit_completed_client_get_request(connection, 0);

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&headers_update.events[0]),
              nullptr);

    std::vector<std::byte> encoder_instructions;
    auto blocked_update = connection.on_core_result(
        receive_result(0, headers_frame_bytes(encoder, 0, trailer_fields, &encoder_instructions),
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
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerResponseTrailersEvent>(&unblocked_update.events[0]),
        nullptr);
    EXPECT_NE(
        std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&unblocked_update.events[1]),
        nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleEmptyResponseDataFrameCompletesWithoutBodyEvent) {
    auto final_response_headers = response_fields(200, {}, 0);
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseHeadEvent>(&headers_update.events[0]),
              nullptr);

    auto update = connection.on_core_result(receive_result(0, data_frame_bytes(""), true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(update).empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleIgnoresUnknownResponseFrameTypeAfterHeaders) {
    auto final_response_headers = response_fields(200, {});
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, final_response_headers)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto update = connection.on_core_result(receive_result(0, unknown_frame_bytes(0x21), true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(reset_stream_inputs_from(update).empty());
    EXPECT_TRUE(stop_sending_inputs_from(update).empty());
    ASSERT_EQ(update.events.size(), 1u);
    EXPECT_NE(std::get_if<coquic::http3::Http3PeerResponseCompleteEvent>(&update.events[0]),
              nullptr);
}

TEST(QuicHttp3ConnectionTest, ClientRoleResponseFinWithContentLengthMismatchResetsStream) {
    auto final_response_headers = response_fields(200, {}, 2);
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto bytes = headers_frame_bytes(0, final_response_headers);
    auto body = data_frame_bytes("x");
    bytes.insert(bytes.end(), body.begin(), body.end());

    auto update = connection.on_core_result(receive_result(0, bytes, true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

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

TEST(QuicHttp3ConnectionTest, ClientRoleFinishedLocalRequestRejectsRequestHead) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});

    coquic::http3::Http3ConnectionTestAccess::local_request_stream(connection, 0).request_finished =
        true;

    auto result = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                        .method = "GET",
                                                        .scheme = "https",
                                                        .authority = "example.test",
                                                        .path = "/resource",
                                                    });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::frame_unexpected);
}

TEST(QuicHttp3ConnectionTest, ClientRoleRequestHeadersRequireLocalQpackEncoderStream) {
    coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, peer_settings);
    coquic::http3::Http3ConnectionTestAccess::clear_local_qpack_encoder_stream(connection);

    auto result = connection.submit_request_head(0, coquic::http3::Http3RequestHead{
                                                        .method = "GET",
                                                        .scheme = "https",
                                                        .authority = "example.test",
                                                        .path = "/resource",
                                                        .headers =
                                                            {
                                                                {
                                                                    .name = "x-coquic-token",
                                                                    .value = "bravo",
                                                                },
                                                            },
                                                    });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ConnectionTest, ClientRoleRequestTrailersRequireLocalQpackEncoderStream) {
    coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, peer_settings);
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    coquic::http3::Http3ConnectionTestAccess::clear_local_qpack_encoder_stream(connection);

    auto result = connection.submit_request_trailers(0, trailer_fields);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ConnectionTest, ClientRoleDynamicRequestTrailersQueueEncoderInstructions) {
    coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
        coquic::http3::Http3Field{"content-length", "0"},
    };
    std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, peer_settings);
    ASSERT_TRUE(connection
                    .submit_request_head(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "POST",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/upload",
                                             .content_length = 0,
                                         })
                    .has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    ASSERT_TRUE(connection.submit_request_trailers(0, trailer_fields).has_value());

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    coquic::http3::Http3QpackEncoderContext encoder{
        .peer_settings =
            {
                .max_table_capacity = peer_settings.qpack_max_table_capacity,
                .blocked_streams = peer_settings.qpack_blocked_streams,
            },
    };
    headers_frame_bytes(encoder, 0, request_fields);
    std::vector<std::byte> encoder_instructions;
    auto expected_trailers = headers_frame_bytes(encoder, 0, trailer_fields, &encoder_instructions);

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_FALSE(encoder_instructions.empty());
    EXPECT_EQ(sends[0].stream_id, 6u);
    EXPECT_EQ(sends[0].bytes, encoder_instructions);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_trailers);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleRequestBodyRejectsCounterOverflow) {
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
    coquic::http3::Http3ConnectionTestAccess::local_request_stream(connection, 0)
        .request_body_bytes_sent = std::numeric_limits<std::uint64_t>::max();

    auto result = connection.submit_request_body(0, bytes_from_text("x"));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
}

TEST(QuicHttp3ConnectionTest, ServerRoleResponseHeadersRequireLocalQpackEncoderStream) {
    coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, peer_settings);
    receive_completed_get_request(connection, 0);
    coquic::http3::Http3ConnectionTestAccess::clear_local_qpack_encoder_stream(connection);

    auto result = connection.submit_response_head(0, coquic::http3::Http3ResponseHead{
                                                         .status = 200,
                                                         .headers =
                                                             {
                                                                 {
                                                                     .name = "x-coquic-token",
                                                                     .value = "bravo",
                                                                 },
                                                             },
                                                     });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ConnectionTest, ServerRoleResponseTrailersRequireLocalQpackEncoderStream) {
    coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, peer_settings);
    receive_completed_get_request(connection, 0);
    ASSERT_TRUE(connection.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                    .has_value());
    coquic::http3::Http3ConnectionTestAccess::clear_local_qpack_encoder_stream(connection);

    auto result = connection.submit_response_trailers(0, trailer_fields);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::general_protocol_error);
}

TEST(QuicHttp3ConnectionTest, ServerRoleDynamicResponseTrailersQueueEncoderInstructions) {
    coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 1,
    };
    std::array trailer_fields{
        coquic::http3::Http3Field{"x-coquic-trailer", "done"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, peer_settings);
    receive_completed_get_request(connection, 0);
    ASSERT_TRUE(connection.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                    .has_value());
    EXPECT_FALSE(
        send_stream_inputs_from(connection.poll(coquic::quic::QuicCoreTimePoint{})).empty());

    ASSERT_TRUE(connection.submit_response_trailers(0, trailer_fields).has_value());

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
    auto expected_trailers = headers_frame_bytes(encoder, 0, trailer_fields, &encoder_instructions);

    ASSERT_EQ(sends.size(), 2u);
    EXPECT_FALSE(encoder_instructions.empty());
    EXPECT_EQ(sends[0].stream_id, 7u);
    EXPECT_EQ(sends[0].bytes, encoder_instructions);
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_EQ(sends[1].bytes, expected_trailers);
    EXPECT_TRUE(sends[1].fin);
}

TEST(QuicHttp3ConnectionTest, ServerRoleResponseBodyRejectsCounterOverflow) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_peer_settings(connection, {});
    receive_completed_get_request(connection, 0);
    ASSERT_TRUE(connection.submit_response_head(0, coquic::http3::Http3ResponseHead{.status = 200})
                    .has_value());
    coquic::http3::Http3ConnectionTestAccess::local_response_stream(connection, 0).body_bytes_sent =
        std::numeric_limits<std::uint64_t>::max();

    auto result = connection.submit_response_body(0, bytes_from_text("x"));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
}

TEST(QuicHttp3ConnectionTest, RequestSidePrivateNoopGuardsDoNotMutateConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    coquic::http3::Http3ConnectionTestAccess::process_request_stream(connection, 0);
    coquic::http3::Http3ConnectionTestAccess::handle_request_headers_frame(
        connection, 0, coquic::http3::Http3HeadersFrame{.field_section = {}});
    coquic::http3::Http3ConnectionTestAccess::handle_request_data_frame(
        connection, 0, coquic::http3::Http3DataFrame{.payload = {}});
    coquic::http3::Http3ConnectionTestAccess::apply_initial_request_headers(connection, 0, {});
    coquic::http3::Http3ConnectionTestAccess::apply_request_trailers(connection, 0, {});
    coquic::http3::Http3ConnectionTestAccess::handle_unblocked_request_field_section(
        connection, coquic::http3::Http3DecodedFieldSection{
                        .stream_id = 0,
                        .status = coquic::http3::Http3QpackDecodeStatus::complete,
                    });
    coquic::http3::Http3ConnectionTestAccess::peer_request_stream(connection, 1);
    coquic::http3::Http3ConnectionTestAccess::handle_unblocked_request_field_section(
        connection, coquic::http3::Http3DecodedFieldSection{
                        .stream_id = 1,
                        .status = coquic::http3::Http3QpackDecodeStatus::complete,
                    });
    coquic::http3::Http3ConnectionTestAccess::finalize_request_stream(connection, 0);

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(connection.is_closed());
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ResponseSidePrivateNoopGuardsDoNotMutateConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    coquic::http3::Http3ConnectionTestAccess::process_response_stream(connection, 0);
    coquic::http3::Http3ConnectionTestAccess::handle_response_headers_frame(
        connection, 0, coquic::http3::Http3HeadersFrame{.field_section = {}});
    coquic::http3::Http3ConnectionTestAccess::handle_response_data_frame(
        connection, 0, coquic::http3::Http3DataFrame{.payload = {}});
    coquic::http3::Http3ConnectionTestAccess::apply_response_headers(connection, 0, {});
    coquic::http3::Http3ConnectionTestAccess::apply_response_trailers(connection, 0, {});
    coquic::http3::Http3ConnectionTestAccess::handle_unblocked_response_field_section(
        connection, coquic::http3::Http3DecodedFieldSection{
                        .stream_id = 0,
                        .status = coquic::http3::Http3QpackDecodeStatus::complete,
                    });
    coquic::http3::Http3ConnectionTestAccess::local_request_stream(connection, 1);
    coquic::http3::Http3ConnectionTestAccess::handle_unblocked_response_field_section(
        connection, coquic::http3::Http3DecodedFieldSection{
                        .stream_id = 1,
                        .status = coquic::http3::Http3QpackDecodeStatus::complete,
                    });
    coquic::http3::Http3ConnectionTestAccess::finalize_response_stream(connection, 0);

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(connection.is_closed());
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ServerRoleRequestDataRejectsCounterOverflow) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto &request = coquic::http3::Http3ConnectionTestAccess::peer_request_stream(connection, 0);
    request.initial_headers_received = true;
    request.body_bytes_received = std::numeric_limits<std::uint64_t>::max();

    coquic::http3::Http3ConnectionTestAccess::handle_request_data_frame(
        connection, 0, coquic::http3::Http3DataFrame{.payload = bytes_from_text("x")});

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
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

TEST(QuicHttp3ConnectionTest, ClientRoleResponseDataRejectsCounterOverflow) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    auto &request = coquic::http3::Http3ConnectionTestAccess::local_request_stream(connection, 0);
    request.final_response_received = true;
    request.response_body_bytes_received = std::numeric_limits<std::uint64_t>::max();

    coquic::http3::Http3ConnectionTestAccess::handle_response_data_frame(
        connection, 0, coquic::http3::Http3DataFrame{.payload = bytes_from_text("x")});

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
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

TEST(QuicHttp3ConnectionTest, ServerRoleMalformedFinishingRequestFrameDoesNotEmitCompleteEvent) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto update = connection.on_core_result(receive_result(0,
                                                           bytes_from_ints({
                                                               0x07,
                                                               0x01,
                                                               0x40,
                                                           }),
                                                           true),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ClientRoleMalformedFinishingResponseFrameDoesNotEmitCompleteEvent) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);

    auto update = connection.on_core_result(receive_result(0,
                                                           bytes_from_ints({
                                                               0x07,
                                                               0x01,
                                                               0x40,
                                                           }),
                                                           true),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ConnectionSettingsGettersExposeLocalAndPeerSnapshots) {
    coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 128,
        .qpack_blocked_streams = 3,
        .max_field_section_size = 1024,
    };
    coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 64,
        .qpack_blocked_streams = 2,
        .max_field_section_size = 4096,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });

    auto actual_local_settings = connection.local_settings();
    EXPECT_EQ(actual_local_settings.qpack_max_table_capacity,
              local_settings.qpack_max_table_capacity);
    EXPECT_EQ(actual_local_settings.qpack_blocked_streams, local_settings.qpack_blocked_streams);
    EXPECT_EQ(actual_local_settings.max_field_section_size, local_settings.max_field_section_size);
    EXPECT_FALSE(connection.peer_settings_received());

    receive_client_peer_settings(connection, peer_settings);

    EXPECT_TRUE(connection.peer_settings_received());
    auto actual_peer_settings = connection.peer_settings();
    EXPECT_EQ(actual_peer_settings.qpack_max_table_capacity,
              peer_settings.qpack_max_table_capacity);
    EXPECT_EQ(actual_peer_settings.qpack_blocked_streams, peer_settings.qpack_blocked_streams);
    EXPECT_EQ(actual_peer_settings.max_field_section_size, peer_settings.max_field_section_size);
}

TEST(QuicHttp3ConnectionTest, StartupFailsWhenLocalSettingsCannotBeSerialized) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings =
            {
                .qpack_max_table_capacity = std::numeric_limits<std::uint64_t>::max(),
            },
    });

    auto update =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::internal_error));
}

TEST(QuicHttp3ConnectionTest, TerminalCoreResultsDrainPendingInputsAndMarkFailure) {
    coquic::http3::Http3Connection closed_connection(coquic::http3::Http3ConnectionConfig{});
    coquic::http3::Http3ConnectionTestAccess::queue_send(closed_connection, 0,
                                                         bytes_from_text("x"));
    coquic::http3::Http3ConnectionTestAccess::set_closed(closed_connection, true);
    auto closed_update = closed_connection.on_core_result(handshake_ready_result(),
                                                          coquic::quic::QuicCoreTimePoint{});
    ASSERT_TRUE(closed_update.terminal_failure);
    ASSERT_EQ(send_stream_inputs_from(closed_update).size(), 1u);

    coquic::http3::Http3Connection local_error_connection(coquic::http3::Http3ConnectionConfig{});
    coquic::http3::Http3ConnectionTestAccess::queue_send(local_error_connection, 0,
                                                         bytes_from_text("x"));
    auto local_error_update = local_error_connection.on_core_result(
        local_error_result(), coquic::quic::QuicCoreTimePoint{});
    ASSERT_TRUE(local_error_update.terminal_failure);
    ASSERT_EQ(send_stream_inputs_from(local_error_update).size(), 1u);
    EXPECT_TRUE(local_error_connection.is_closed());

    coquic::http3::Http3Connection failed_connection(coquic::http3::Http3ConnectionConfig{});
    coquic::http3::Http3ConnectionTestAccess::queue_send(failed_connection, 0,
                                                         bytes_from_text("x"));
    auto failed_update =
        failed_connection.on_core_result(failed_result(), coquic::quic::QuicCoreTimePoint{});
    ASSERT_TRUE(failed_update.terminal_failure);
    ASSERT_EQ(send_stream_inputs_from(failed_update).size(), 1u);
    EXPECT_TRUE(failed_connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, HandshakeReadyOmitsUnsetMaxFieldSectionSizeSetting) {
    coquic::http3::Http3SettingsSnapshot settings{
        .qpack_max_table_capacity = 128,
        .qpack_blocked_streams = 3,
        .max_field_section_size = std::nullopt,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = settings,
    });

    auto update =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 2u);
    EXPECT_EQ(sends[0].bytes, control_stream_bytes(settings));
}

TEST(QuicHttp3ConnectionTest, ClosedInternalGuardsSkipStartupAndPeerUniFinProcessing) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    coquic::http3::Http3ConnectionTestAccess::set_closed(connection, true);
    coquic::http3::Http3ConnectionTestAccess::queue_startup_streams(connection);
    coquic::http3::Http3ConnectionTestAccess::set_peer_uni_stream_kind_control(connection, 3);
    coquic::http3::Http3ConnectionTestAccess::set_peer_uni_stream_kind_encoder(connection, 7);
    coquic::http3::Http3ConnectionTestAccess::set_peer_uni_stream_kind_decoder(connection, 11);
    coquic::http3::Http3ConnectionTestAccess::handle_peer_uni_stream_data(
        connection, 3, std::span<const std::byte>{}, true);
    coquic::http3::Http3ConnectionTestAccess::handle_peer_uni_stream_data(
        connection, 7, bytes_from_ints({0x01}), false);
    coquic::http3::Http3ConnectionTestAccess::handle_peer_uni_stream_data(
        connection, 11, bytes_from_ints({0x01}), false);

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, ClosedQueueHelpersAreNoops) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    coquic::http3::Http3ConnectionTestAccess::set_closed(connection, true);
    coquic::http3::Http3ConnectionTestAccess::queue_connection_close(
        connection, coquic::http3::Http3ErrorCode::internal_error, "ignored");
    coquic::http3::Http3ConnectionTestAccess::queue_stream_error(
        connection, 0, coquic::http3::Http3ErrorCode::message_error);

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, QueueSendSkipsEmptyWritesAndCoalescesTrailingFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{});

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, false);
    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, true);
    update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_TRUE(sends[0].bytes.empty());
    EXPECT_TRUE(sends[0].fin);

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 1, bytes_from_text("x"));
    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, true);
    update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 2u);
    EXPECT_EQ(sends[0].stream_id, 1u);
    EXPECT_EQ(sends[0].bytes, bytes_from_text("x"));
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 0u);
    EXPECT_TRUE(sends[1].bytes.empty());
    EXPECT_TRUE(sends[1].fin);

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0, bytes_from_text("x"));
    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, true);

    update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_EQ(sends[0].bytes, bytes_from_text("x"));
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, ClientRoleIgnoresLocalUnidirectionalReceiveData) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    auto update = connection.on_core_result(receive_result(2, bytes_from_ints({0x00})),
                                            coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.core_inputs.empty());
    EXPECT_TRUE(update.events.empty());
}

TEST(QuicHttp3ConnectionTest, QueueSendDoesNotCoalesceAcrossNonSendPendingInputs) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    std::array request_fields{
        coquic::http3::Http3Field{":method", "POST"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/upload"},
    };

    prime_server_transport(connection);
    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);
    ASSERT_NE(std::get_if<coquic::http3::Http3PeerRequestHeadEvent>(&headers_update.events[0]),
              nullptr);
    ASSERT_TRUE(connection
                    .abort_request_body(
                        0, static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::no_error))
                    .has_value());

    coquic::http3::Http3ConnectionTestAccess::queue_send(connection, 0,
                                                         std::span<const std::byte>{}, true);

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 0u);
    EXPECT_TRUE(sends[0].bytes.empty());
    EXPECT_TRUE(sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderDuplicateInstructionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    auto update = connection.on_core_result(receive_result(7, encoder_stream_bytes({0x01})),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_encoder_stream_error));
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderStreamBuffersTruncatedNameReferenceInstructions) {
    coquic::http3::Http3Connection incomplete_name_reference(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    auto incomplete_name_reference_update = incomplete_name_reference.on_core_result(
        receive_result(7, encoder_stream_bytes({0xff})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(incomplete_name_reference_update).has_value());
    EXPECT_TRUE(incomplete_name_reference_update.core_inputs.empty());

    coquic::http3::Http3Connection missing_value_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    auto missing_value_update = missing_value_connection.on_core_result(
        receive_result(7, encoder_stream_bytes({0xc1})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(missing_value_update).has_value());
    EXPECT_TRUE(missing_value_update.core_inputs.empty());

    coquic::http3::Http3Connection truncated_value_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    auto truncated_value_update = truncated_value_connection.on_core_result(
        receive_result(7, encoder_stream_bytes({0xc1, 0x7f})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(truncated_value_update).has_value());
    EXPECT_TRUE(truncated_value_update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderStreamBuffersTruncatedLiteralNameInstructions) {
    coquic::http3::Http3Connection incomplete_name_length(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    auto incomplete_name_length_update = incomplete_name_length.on_core_result(
        receive_result(7, encoder_stream_bytes({0x5f})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(incomplete_name_length_update).has_value());
    EXPECT_TRUE(incomplete_name_length_update.core_inputs.empty());

    auto missing_value_instruction = bytes_from_ints({0x4a});
    append_ascii_bytes(missing_value_instruction, "custom-key");
    coquic::http3::Http3Connection missing_value_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    auto missing_value_update = missing_value_connection.on_core_result(
        receive_result(7, encoder_stream_bytes(missing_value_instruction)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(missing_value_update).has_value());
    EXPECT_TRUE(missing_value_update.core_inputs.empty());

    auto truncated_value_instruction = missing_value_instruction;
    truncated_value_instruction.push_back(std::byte{0x7f});
    coquic::http3::Http3Connection truncated_value_connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });
    auto truncated_value_update = truncated_value_connection.on_core_result(
        receive_result(7, encoder_stream_bytes(truncated_value_instruction)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(truncated_value_update).has_value());
    EXPECT_TRUE(truncated_value_update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderStreamConsumesMultibyteStringLiteralLengths) {
    auto instruction = bytes_from_ints({0x4a});
    append_ascii_bytes(instruction, "custom-key");
    instruction.push_back(std::byte{0x7f});
    instruction.push_back(std::byte{0x03});
    instruction.insert(instruction.end(), 130u, static_cast<std::byte>('a'));

    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings =
            {
                .qpack_max_table_capacity = 512,
            },
    });

    auto update = connection.on_core_result(receive_result(7, encoder_stream_bytes(instruction)),
                                            coquic::quic::QuicCoreTimePoint{});

    EXPECT_TRUE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());
    EXPECT_TRUE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest,
     PeerQpackDecoderSectionAcknowledgmentWithoutOutstandingSectionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    auto update = connection.on_core_result(receive_result(11, decoder_stream_bytes({0x81})),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decoder_stream_error));
}

TEST(QuicHttp3ConnectionTest, ServerRoleInvalidRequestFieldSectionDeltaBasePrefixClosesConnection) {
    coquic::http3::Http3Connection incomplete(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    auto incomplete_update = incomplete.on_core_result(
        receive_result(0, raw_headers_frame_bytes(bytes_from_ints({0x00}))),
        coquic::quic::QuicCoreTimePoint{});
    auto incomplete_close = close_input_from(incomplete_update);
    ASSERT_TRUE(incomplete_close.has_value());
    EXPECT_EQ(
        close_application_error_code(incomplete_close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));

    auto overflowing_prefix = bytes_from_ints({0x00});
    auto overflow = overflowing_qpack_field_section_prefix_bytes();
    overflowing_prefix.insert(overflowing_prefix.end(), overflow.begin(), overflow.end());
    coquic::http3::Http3Connection overflowing(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });
    auto overflowing_update =
        overflowing.on_core_result(receive_result(0, raw_headers_frame_bytes(overflowing_prefix)),
                                   coquic::quic::QuicCoreTimePoint{});
    auto overflowing_close = close_input_from(overflowing_update);
    ASSERT_TRUE(overflowing_close.has_value());
    EXPECT_EQ(
        close_application_error_code(overflowing_close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decompression_failed));
}

TEST(QuicHttp3ConnectionTest, ServerRoleRejectsTwoDigitResponseStatus) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    receive_completed_get_request(connection, 0);

    auto result = connection.submit_response_head(0, coquic::http3::Http3ResponseHead{
                                                         .status = 99,
                                                     });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::http3::Http3ErrorCode::message_error);
}

TEST(QuicHttp3ConnectionTest, ClientRoleFinishRequestAllowsExactDeclaredContentLength) {
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
    ASSERT_TRUE(connection.submit_request_body(0, bytes_from_text("x")).has_value());

    auto finish = connection.finish_request(0);

    ASSERT_TRUE(finish.has_value());
    EXPECT_TRUE(finish.value());
}

TEST(QuicHttp3ConnectionTest, ServerRoleRequestFinWithTruncatedFrameTypeVarintResetsStream) {
    std::array request_fields{
        coquic::http3::Http3Field{":method", "GET"},
        coquic::http3::Http3Field{":scheme", "https"},
        coquic::http3::Http3Field{":authority", "example.test"},
        coquic::http3::Http3Field{":path", "/resource"},
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    auto headers_update =
        connection.on_core_result(receive_result(0, headers_frame_bytes(0, request_fields)),
                                  coquic::quic::QuicCoreTimePoint{});
    ASSERT_EQ(headers_update.events.size(), 1u);

    auto update = connection.on_core_result(receive_result(0, bytes_from_ints({0x40}), true),
                                            coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());

    auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 0u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));

    auto stops = stop_sending_inputs_from(update);
    ASSERT_EQ(stops.size(), 1u);
    EXPECT_EQ(stops[0].stream_id, 0u);
    EXPECT_EQ(stops[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_incomplete));
}

TEST(QuicHttp3ConnectionTest, QueueStreamErrorCancelsBlockedPeerRequestAndFlushesDecoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(connection);
    coquic::http3::Http3ConnectionTestAccess::set_peer_request_blocked_initial_headers(connection,
                                                                                       0);
    coquic::http3::Http3ConnectionTestAccess::decoder(connection)
        .pending_field_sections.push_back({
            .stream_id = 0,
            .required_insert_count = 1,
        });

    coquic::http3::Http3ConnectionTestAccess::queue_stream_error(
        connection, 0, coquic::http3::Http3ErrorCode::message_error);

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 11u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

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
    EXPECT_EQ(coquic::http3::Http3ConnectionPeerRequestStreamAccess::size(connection), 0u);
}

TEST(QuicHttp3ConnectionTest, QueueStreamErrorCancelsBlockedLocalRequestAndFlushesDecoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_peer_settings(connection, {});
    submit_completed_client_get_request(connection, 0);
    coquic::http3::Http3ConnectionTestAccess::set_local_request_blocked_response_headers(connection,
                                                                                         0);
    coquic::http3::Http3ConnectionTestAccess::decoder(connection)
        .pending_field_sections.push_back({
            .stream_id = 0,
            .required_insert_count = 1,
        });

    coquic::http3::Http3ConnectionTestAccess::queue_stream_error(
        connection, 0, coquic::http3::Http3ErrorCode::message_error);

    auto update = connection.poll(coquic::quic::QuicCoreTimePoint{});
    auto sends = send_stream_inputs_from(update);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 10u);
    EXPECT_EQ(sends[0].bytes, bytes_from_ints({0x40}));

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
    EXPECT_FALSE(connection.finish_request(0).has_value());
}

TEST(QuicHttp3ConnectionTest, ClientRoleRejectsResponseStreamWithoutMatchingLocalRequest) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    auto update = connection.on_core_result(receive_result(0, std::span<const std::byte>{}),
                                            coquic::quic::QuicCoreTimePoint{});
    auto close = close_input_from(update);

    ASSERT_TRUE(close.has_value());
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

} // namespace
