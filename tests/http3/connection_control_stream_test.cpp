#include <gtest/gtest.h>
#include "tests/support/http3/connection_test_support.h"

namespace {

TEST(QuicHttp3ConnectionTest, HandshakeReadyCreatesMandatoryStreamsForClientRole) {
    const coquic::http3::Http3SettingsSnapshot settings{
        .qpack_max_table_capacity = 128,
        .qpack_blocked_streams = 3,
        .max_field_section_size = 1024,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = settings,
    });

    const auto update =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 2u);
    EXPECT_EQ(sends[0].bytes, control_stream_bytes(settings));
    EXPECT_FALSE(sends[0].fin);
    EXPECT_EQ(sends[1].stream_id, 6u);
    EXPECT_EQ(sends[1].bytes, bytes_from_ints({0x02}));
    EXPECT_FALSE(sends[1].fin);
    EXPECT_EQ(sends[2].stream_id, 10u);
    EXPECT_EQ(sends[2].bytes, bytes_from_ints({0x03}));
    EXPECT_FALSE(sends[2].fin);
}

TEST(QuicHttp3ConnectionTest, HandshakeReadyCreatesMandatoryStreamsForServerRole) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 3u);
    EXPECT_EQ(sends[1].stream_id, 7u);
    EXPECT_EQ(sends[2].stream_id, 11u);
}

TEST(QuicHttp3ConnectionTest, HandshakeConfirmedAlsoCreatesMandatoryStreams) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update =
        connection.on_core_result(handshake_confirmed_result(), coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 3u);
    EXPECT_EQ(sends[0].stream_id, 2u);
    EXPECT_EQ(sends[1].stream_id, 6u);
    EXPECT_EQ(sends[2].stream_id, 10u);
}

TEST(QuicHttp3ConnectionTest, IgnoresUnknownStateEventsBeforeTransportReady) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    coquic::quic::QuicCoreResult unknown_state;
    unknown_state.effects.push_back(coquic::quic::QuicCoreEffect{
        coquic::quic::QuicCoreStateEvent{
            .change = invalid_state_change(),
        },
    });

    const auto ignored =
        connection.on_core_result(unknown_state, coquic::quic::QuicCoreTimePoint{});
    EXPECT_TRUE(ignored.core_inputs.empty());
    EXPECT_TRUE(ignored.events.empty());
    EXPECT_FALSE(ignored.has_pending_work);
    EXPECT_FALSE(ignored.terminal_failure);
    EXPECT_FALSE(ignored.terminal_success);

    const auto ready =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    const auto ready_sends = send_stream_inputs_from(ready);

    if (ready_sends.size() != 3u) {
        FAIL() << "handshake ready did not emit control streams";
    }
    EXPECT_EQ(ready_sends[0].stream_id, 2u);
    EXPECT_EQ(ready_sends[1].stream_id, 6u);
    EXPECT_EQ(ready_sends[2].stream_id, 10u);
}

TEST(QuicHttp3ConnectionTest, RejectsPeerControlStreamWithoutInitialSettings) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(3, goaway_stream_bytes(0)),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::missing_settings));
}

TEST(QuicHttp3ConnectionTest, UnknownFirstPeerControlFrameMapsToMissingSettings) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(
        receive_result(3, bytes_from_ints({0x00, 0x21, 0x00})), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::missing_settings));
}

TEST(QuicHttp3ConnectionTest, PeerControlStreamFinBeforeSettingsMapsToMissingSettings) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(3, bytes_from_ints({0x00}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::missing_settings));
}

TEST(QuicHttp3ConnectionTest, RejectsSecondPeerControlStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());

    const auto second = connection.on_core_result(receive_result(15, bytes_from_ints({0x00})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, RejectsClientInitiatedPushStreamsOnServerRole) {
    coquic::http3::Http3Connection server(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    const auto update = server.on_core_result(receive_result(2, bytes_from_ints({0x01})),
                                              coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, RejectsPeerPushStreamAboveAdvertisedMaxPushId) {
    coquic::http3::Http3Connection client(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(client);
    receive_peer_settings(client, {});
    ASSERT_TRUE(client.submit_max_push_id(0).has_value());
    static_cast<void>(client.poll(coquic::quic::QuicCoreTimePoint{}));

    const auto update = client.on_core_result(receive_result(3, push_stream_bytes(1)),
                                              coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::id_error));
}

TEST(QuicHttp3ConnectionTest, ReservedPeerControlFrameMapsToFrameUnexpected) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());

    const auto update = connection.on_core_result(receive_result(3, bytes_from_ints({0x02, 0x00})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, IgnoresUnknownPeerControlFramesAfterSettings) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());

    const auto update = connection.on_core_result(receive_result(3, bytes_from_ints({0x21, 0x00})),
                                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, RejectsSecondPeerQpackEncoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first = connection.on_core_result(receive_result(7, bytes_from_ints({0x02})),
                                                 coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());

    const auto second = connection.on_core_result(receive_result(15, bytes_from_ints({0x02})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);

    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    // # Each endpoint
    // # MUST initiate, at most, one encoder stream and, at most, one decoder
    // # stream.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    // # Receipt of a second instance of either stream type MUST be
    // # treated as a connection error of type H3_STREAM_CREATION_ERROR.
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, RejectsSecondPeerQpackDecoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first = connection.on_core_result(receive_result(11, bytes_from_ints({0x03})),
                                                 coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());

    const auto second = connection.on_core_result(receive_result(15, bytes_from_ints({0x03})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);

    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    // # Each endpoint
    // # MUST initiate, at most, one encoder stream and, at most, one decoder
    // # stream.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    // # Receipt of a second instance of either stream type MUST be
    // # treated as a connection error of type H3_STREAM_CREATION_ERROR.
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::stream_creation_error));
}

TEST(QuicHttp3ConnectionTest, RejectsCriticalStreamClosure) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update =
        connection.on_core_result(reset_result(3), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, RejectsQpackCriticalStreamClosure) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(receive_result(7, bytes_from_ints({0x02})),
                                                      coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update =
        connection.on_core_result(reset_result(7), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerQpackCriticalStreamFinClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(7, bytes_from_ints({0x02}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerControlStreamFinAfterSettingsClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update = connection.on_core_result(
        receive_result(3, std::span<const std::byte>{}, true), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerQpackDecoderCriticalStreamFinClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(11, bytes_from_ints({0x03}), true),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerResetOnRemoteQpackDecoderStreamClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(receive_result(11, bytes_from_ints({0x03})),
                                                      coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update =
        connection.on_core_result(reset_result(11), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerStopSendingOnLocalControlStreamClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);

    const auto update =
        connection.on_core_result(stop_sending_result(2), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerStopSendingOnLocalQpackEncoderStreamClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);

    const auto update =
        connection.on_core_result(stop_sending_result(6), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, PeerStopSendingOnLocalQpackDecoderStreamClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);

    const auto update =
        connection.on_core_result(stop_sending_result(10), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::closed_critical_stream));
}

TEST(QuicHttp3ConnectionTest, IgnoresUnknownPeerUnidirectionalStreamTypes) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update =
        connection.on_core_result(receive_result(15, bytes_from_ints({0x21, 0x01, 0x02}), true),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, CleansUpIgnoredPeerUnidirectionalStreamStateOnFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update =
        connection.on_core_result(receive_result(15, bytes_from_ints({0x21, 0x01, 0x02}), true),
                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_EQ(coquic::http3::Http3ConnectionPeerUniStreamAccess::size(connection), 0u);
}

TEST(QuicHttp3ConnectionTest, CleansUpPartialPeerUnidirectionalStreamTypeStateOnFin) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(15, bytes_from_ints({0x40}), true),
                                                  coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_EQ(coquic::http3::Http3ConnectionPeerUniStreamAccess::size(connection), 0u);
}

TEST(QuicHttp3ConnectionTest, FragmentedPeerUniStreamTypeLaterResolvesToControlStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first_fragment = connection.on_core_result(
        receive_result(15, bytes_from_ints({0x40})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());
    EXPECT_FALSE(connection.peer_settings_received());

    auto second_fragment = bytes_from_ints({0x00});
    const auto control_stream = settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{});
    second_fragment.insert(second_fragment.end(), control_stream.begin() + 1, control_stream.end());

    const auto update = connection.on_core_result(receive_result(15, second_fragment),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(connection.peer_settings_received());
}

TEST(QuicHttp3ConnectionTest, FragmentedPeerUniStreamTypeLaterResolvesToQpackDecoderStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first_fragment = connection.on_core_result(
        receive_result(15, bytes_from_ints({0x40})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());

    const auto update = connection.on_core_result(receive_result(15, bytes_from_ints({0x03})),
                                                  coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(update.events.empty());
    EXPECT_TRUE(update.core_inputs.empty());
}

TEST(QuicHttp3ConnectionTest, RejectsDuplicateSettingsFrameOnPeerControlStream) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto first = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());

    const auto second = connection.on_core_result(
        receive_result(3, settings_frame_bytes({
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
                                  .value = 0,
                              },
                          })),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_unexpected));
}

TEST(QuicHttp3ConnectionTest, InvalidPeerSettingsMapToSettingsError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(3, settings_stream_bytes({
                                                                        coquic::http3::Http3Setting{
                                                                            .id = 0x02,
                                                                            .value = 0,
                                                                        },
                                                                    })),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::settings_error));
}

TEST(QuicHttp3ConnectionTest, IgnoresUnknownPeerSettingsIdentifier) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(
        receive_result(3, settings_stream_bytes({
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
                                  .value = 128,
                              },
                              coquic::http3::Http3Setting{
                                  .id = 0x2a,
                                  .value = 99,
                              },
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackBlockedStreams,
                                  .value = 4,
                              },
                          })),
        coquic::quic::QuicCoreTimePoint{});

    EXPECT_FALSE(close_input_from(update).has_value());
    EXPECT_TRUE(connection.peer_settings_received());
    EXPECT_EQ(connection.peer_settings().qpack_max_table_capacity, 128u);
    EXPECT_EQ(connection.peer_settings().qpack_blocked_streams, 4u);
    EXPECT_EQ(connection.peer_settings().max_field_section_size, std::nullopt);
}

TEST(QuicHttp3ConnectionTest, DuplicateSettingsIdentifiersInSingleFrameMapToSettingsError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(
        receive_result(3, settings_stream_bytes({
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
                                  .value = 16,
                              },
                              coquic::http3::Http3Setting{
                                  .id = coquic::http3::kHttp3SettingsQpackMaxTableCapacity,
                                  .value = 32,
                              },
                          })),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::settings_error));
}

TEST(QuicHttp3ConnectionTest, AppliesPeerSettingsAndEmitsQpackDecoderFeedback) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 4096,
    };
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 512,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });

    const auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(peer_settings)), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());
    EXPECT_TRUE(connection.peer_settings_received());
    EXPECT_EQ(connection.peer_settings().qpack_max_table_capacity,
              peer_settings.qpack_max_table_capacity);
    EXPECT_EQ(connection.peer_settings().qpack_blocked_streams,
              peer_settings.qpack_blocked_streams);
    EXPECT_EQ(connection.peer_settings().max_field_section_size,
              peer_settings.max_field_section_size);

    const auto qpack_encoder_update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes({
                              0x3f, 0xbd, 0x01, 0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f,
                              0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0c, 0x63, 0x75, 0x73,
                              0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
                          })),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(qpack_encoder_update).has_value());

    const auto qpack_feedback_sends = send_stream_inputs_from(qpack_encoder_update);
    if (qpack_feedback_sends.size() != 1u) {
        FAIL() << "QPACK update did not emit decoder feedback";
    }
    EXPECT_EQ(qpack_feedback_sends[0].stream_id, 10u);
    EXPECT_EQ(qpack_feedback_sends[0].bytes, bytes_from_ints({0x01}));
    EXPECT_FALSE(qpack_feedback_sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, RejectsIncreasingPeerGoawayIdentifier) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());

    const auto first_goaway = connection.on_core_result(receive_result(3, goaway_frame_bytes(8)),
                                                        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_goaway).has_value());

    const auto second_goaway = connection.on_core_result(receive_result(3, goaway_frame_bytes(12)),
                                                         coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second_goaway);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::id_error));
}

TEST(QuicHttp3ConnectionTest, AcceptsNonIncreasingPeerGoawayIdentifier) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto first_goaway = connection.on_core_result(receive_result(3, goaway_frame_bytes(12)),
                                                        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_goaway).has_value());

    const auto second_goaway = connection.on_core_result(receive_result(3, goaway_frame_bytes(8)),
                                                         coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(second_goaway).has_value());
    EXPECT_FALSE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, InvalidPeerGoawayIdentifierMapsToIdError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto update = connection.on_core_result(receive_result(3, goaway_frame_bytes(1)),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::id_error));
    EXPECT_TRUE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, CancelPushOnControlStreamMapsToIdErrorWithoutPushSupport) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto cancel_push = coquic::http3::serialize_http3_frame(coquic::http3::Http3Frame{
        coquic::http3::Http3CancelPushFrame{.push_id = 0},
    });
    ASSERT_TRUE(cancel_push.has_value());

    const auto update = connection.on_core_result(receive_result(3, cancel_push.value()),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::id_error));
}

TEST(QuicHttp3ConnectionTest, BuffersIncompletePeerControlFrameUntilCompletion) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto first_fragment = connection.on_core_result(
        receive_result(3, bytes_from_ints({0x07, 0x01})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());
    EXPECT_TRUE(first_fragment.core_inputs.empty());
    EXPECT_FALSE(connection.is_closed());

    const auto second_fragment = connection.on_core_result(
        receive_result(3, bytes_from_ints({0x00})), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(second_fragment).has_value());
    EXPECT_TRUE(second_fragment.core_inputs.empty());
    EXPECT_FALSE(connection.is_closed());
    EXPECT_EQ(connection.state().goaway_id, std::optional<std::uint64_t>(0u));
}

TEST(QuicHttp3ConnectionTest, MalformedGoawayPayloadOnControlStreamMapsToFrameError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update = connection.on_core_result(
        receive_result(
            3, bytes_from_ints(
                   {static_cast<std::uint8_t>(coquic::http3::kHttp3FrameTypeGoaway), 0x01, 0x40})),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
}

TEST(QuicHttp3ConnectionTest, MalformedMaxPushIdPayloadOnControlStreamMapsToFrameError) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto registered = connection.on_core_result(
        receive_result(3, settings_stream_bytes(coquic::http3::Http3SettingsSnapshot{})),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(registered).has_value());

    const auto update = connection.on_core_result(
        receive_result(
            3, bytes_from_ints({static_cast<std::uint8_t>(coquic::http3::kHttp3FrameTypeMaxPushId),
                                0x01, 0x40})),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::frame_error));
}

TEST(QuicHttp3ConnectionTest, ClientSubmitMaxPushIdQueuesControlFrameAndForbidsReduction) {
    coquic::http3::Http3Connection client(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(client);
    receive_peer_settings(client, {});

    ASSERT_TRUE(client.submit_max_push_id(3).has_value());
    auto update = client.poll(coquic::quic::QuicCoreTimePoint{});
    const auto sends = send_stream_inputs_from(update);

    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends[0].stream_id, 2u);
    EXPECT_EQ(sends[0].bytes, max_push_id_frame_bytes(3));
    EXPECT_EQ(client.state().local_max_push_id, std::optional<std::uint64_t>(3u));

    auto reduced = client.submit_max_push_id(2);
    ASSERT_FALSE(reduced.has_value());
    EXPECT_EQ(reduced.error().code, coquic::http3::Http3ErrorCode::id_error);
}

TEST(QuicHttp3ConnectionTest, ServerStoresPeerMaxPushIdAndRejectsReduction) {
    coquic::http3::Http3Connection server(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    receive_peer_settings(server, {});

    auto first = server.on_core_result(receive_result(2, max_push_id_frame_bytes(4)),
                                       coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first).has_value());
    EXPECT_EQ(server.state().peer_max_push_id, std::optional<std::uint64_t>(4u));

    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
    // # A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a
    // # MAX_PUSH_ID frame that contains a smaller value than previously
    // # received MUST be treated as a connection error of type H3_ID_ERROR.
    auto second = server.on_core_result(receive_result(2, max_push_id_frame_bytes(2)),
                                        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(second);
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::id_error));
}

TEST(QuicHttp3ConnectionTest, SubmitGoawayQueuesFrameAndForbidsIncrease) {
    coquic::http3::Http3Connection server(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(server);

    ASSERT_TRUE(server.submit_goaway(8).has_value());
    auto first = server.poll(coquic::quic::QuicCoreTimePoint{});
    const auto first_sends = send_stream_inputs_from(first);

    ASSERT_EQ(first_sends.size(), 1u);
    EXPECT_EQ(first_sends[0].stream_id, 3u);
    EXPECT_EQ(first_sends[0].bytes, goaway_frame_bytes(8));
    EXPECT_EQ(server.state().local_goaway_id, std::optional<std::uint64_t>(8u));

    ASSERT_TRUE(server.submit_goaway(4).has_value());
    auto second = server.poll(coquic::quic::QuicCoreTimePoint{});
    const auto second_sends = send_stream_inputs_from(second);
    ASSERT_EQ(second_sends.size(), 1u);
    EXPECT_EQ(second_sends[0].bytes, goaway_frame_bytes(4));

    auto increased = server.submit_goaway(12);
    ASSERT_FALSE(increased.has_value());
    EXPECT_EQ(increased.error().code, coquic::http3::Http3ErrorCode::id_error);
}

TEST(QuicHttp3ConnectionTest, PeerGoawayPreventsServerFromPromisingNewPushes) {
    coquic::http3::Http3Connection server(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(server);
    receive_peer_settings(server, {});
    static_cast<void>(server.on_core_result(receive_result(2, max_push_id_frame_bytes(4)),
                                            coquic::quic::QuicCoreTimePoint{}));
    static_cast<void>(server.on_core_result(receive_result(2, goaway_frame_bytes(4)),
                                            coquic::quic::QuicCoreTimePoint{}));
    receive_completed_get_request(server, 0);

    auto promised = server.submit_push_promise(0, coquic::http3::Http3RequestHead{
                                                      .method = "GET",
                                                      .scheme = "https",
                                                      .authority = "example.test",
                                                      .path = "/push",
                                                  });
    ASSERT_FALSE(promised.has_value());
    EXPECT_EQ(promised.error().code, coquic::http3::Http3ErrorCode::request_rejected);
}

TEST(QuicHttp3ConnectionTest, ServerHandlesClientCancelPushForLocalPush) {
    coquic::http3::Http3Connection server(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    prime_server_transport(server);
    receive_peer_settings(server, {});
    static_cast<void>(server.on_core_result(receive_result(2, max_push_id_frame_bytes(0)),
                                            coquic::quic::QuicCoreTimePoint{}));
    receive_completed_get_request(server, 0);

    ASSERT_TRUE(server
                    .submit_push_promise(0,
                                         coquic::http3::Http3RequestHead{
                                             .method = "GET",
                                             .scheme = "https",
                                             .authority = "example.test",
                                             .path = "/push",
                                         })
                    .has_value());
    ASSERT_TRUE(server
                    .submit_push_response_head(0,
                                               coquic::http3::Http3ResponseHead{
                                                   .status = 200,
                                               })
                    .has_value());
    static_cast<void>(server.poll(coquic::quic::QuicCoreTimePoint{}));

    const auto update = server.on_core_result(receive_result(2, cancel_push_frame_bytes(0)),
                                              coquic::quic::QuicCoreTimePoint{});
    const auto resets = reset_stream_inputs_from(update);
    ASSERT_EQ(resets.size(), 1u);
    EXPECT_EQ(resets[0].stream_id, 15u);
    EXPECT_EQ(resets[0].application_error_code,
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::request_cancelled));
}

TEST(QuicHttp3ConnectionTest, ServerRejectsCancelPushForUnpromisedPush) {
    coquic::http3::Http3Connection server(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::server,
    });

    receive_peer_settings(server, {});
    static_cast<void>(server.on_core_result(receive_result(2, max_push_id_frame_bytes(2)),
                                            coquic::quic::QuicCoreTimePoint{}));

    const auto update = server.on_core_result(receive_result(2, cancel_push_frame_bytes(1)),
                                              coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);
    EXPECT_EQ(close_application_error_code(close),
              static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::id_error));
}

TEST(QuicHttp3ConnectionTest, BuffersFragmentedPeerQpackEncoderInstructions) {
    const coquic::http3::Http3SettingsSnapshot local_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 4096,
    };
    const coquic::http3::Http3SettingsSnapshot peer_settings{
        .qpack_max_table_capacity = 220,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 512,
    };
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings = local_settings,
    });

    const auto startup =
        connection.on_core_result(handshake_ready_result(), coquic::quic::QuicCoreTimePoint{});
    EXPECT_EQ(send_stream_inputs_from(startup).size(), 3u);

    const auto settings_update = connection.on_core_result(
        receive_result(3, settings_stream_bytes(peer_settings)), coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(settings_update).has_value());

    const auto encoded_qpack_insert = encoder_stream_bytes({
        0x3f, 0xbd, 0x01, 0x4a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
    });
    const auto first_qpack_fragment = connection.on_core_result(
        receive_result(7, std::span<const std::byte>(encoded_qpack_insert).first(8)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_qpack_fragment).has_value());
    EXPECT_TRUE(send_stream_inputs_from(first_qpack_fragment).empty());

    const auto second_qpack_fragment = connection.on_core_result(
        receive_result(7, std::span<const std::byte>(encoded_qpack_insert).subspan(8)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(second_qpack_fragment).has_value());

    const auto decoder_sends = send_stream_inputs_from(second_qpack_fragment);
    if (decoder_sends.size() != 1u) {
        FAIL() << "QPACK encoder insert did not unblock decoder";
    }
    EXPECT_EQ(decoder_sends[0].stream_id, 10u);
    EXPECT_EQ(decoder_sends[0].bytes, bytes_from_ints({0x01}));
    EXPECT_FALSE(decoder_sends[0].fin);
}

TEST(QuicHttp3ConnectionTest, OverflowingPeerQpackEncoderInstructionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes(
                              {0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00})),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_encoder_stream_error));
    EXPECT_TRUE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, PeerQpackEncoderCapacityUpdateAboveSettingClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
        .local_settings =
            coquic::http3::Http3SettingsSnapshot{
                .qpack_max_table_capacity = 32,
            },
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto update = connection.on_core_result(
        receive_result(7, encoder_stream_bytes({0x3f, 0x21})), coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_encoder_stream_error));
    EXPECT_TRUE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, DecoderStreamInstructionsWireIntoEncoderContext) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto update = connection.on_core_result(receive_result(11, decoder_stream_bytes({0x01})),
                                                  coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decoder_stream_error));
}

TEST(QuicHttp3ConnectionTest, OverflowingPeerQpackDecoderInstructionClosesConnection) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    prime_client_transport(connection);
    receive_client_peer_settings(connection, coquic::http3::Http3SettingsSnapshot{});

    const auto update = connection.on_core_result(
        receive_result(11, decoder_stream_bytes(
                               {0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00})),
        coquic::quic::QuicCoreTimePoint{});
    const auto close = close_input_from(update);

    EXPECT_EQ(
        close_application_error_code(close),
        static_cast<std::uint64_t>(coquic::http3::Http3ErrorCode::qpack_decoder_stream_error));
    EXPECT_TRUE(connection.is_closed());
}

TEST(QuicHttp3ConnectionTest, BuffersFragmentedPeerQpackDecoderInstructions) {
    coquic::http3::Http3Connection connection(coquic::http3::Http3ConnectionConfig{
        .role = coquic::http3::Http3ConnectionRole::client,
    });

    const auto decoder_bytes = decoder_stream_bytes({0x7f, 0x01});
    const auto first_fragment = connection.on_core_result(
        receive_result(11, std::span<const std::byte>(decoder_bytes).first(2)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(first_fragment).has_value());
    EXPECT_TRUE(first_fragment.core_inputs.empty());

    const auto second_fragment = connection.on_core_result(
        receive_result(11, std::span<const std::byte>(decoder_bytes).subspan(2)),
        coquic::quic::QuicCoreTimePoint{});
    EXPECT_FALSE(close_input_from(second_fragment).has_value());
    EXPECT_TRUE(second_fragment.core_inputs.empty());
}

} // namespace
