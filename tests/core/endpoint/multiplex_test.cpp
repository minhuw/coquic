#include <gtest/gtest.h>

#include <chrono>
#include <type_traits>
#include <utility>

#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

template <typename T, typename = void> struct has_public_path_id_member : std::false_type {};

template <typename T>
struct has_public_path_id_member<T, std::void_t<decltype(std::declval<T>().path_id)>>
    : std::true_type {};

template <typename T>
using route_handle_member_type = std::remove_cvref_t<decltype(std::declval<T>().route_handle)>;

std::vector<coquic::quic::StreamFrame>
stream_frames_from_sender_datagram(const coquic::quic::QuicConnection &connection,
                                   std::span<const std::byte> datagram) {
    std::vector<coquic::quic::StreamFrame> streams;
    for (const auto &packet : decode_sender_datagram(connection, datagram)) {
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (application == nullptr) {
            continue;
        }
        for (const auto &frame : application->frames) {
            if (const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame)) {
                streams.push_back(*stream);
            }
        }
    }
    return streams;
}

TEST(QuicCoreEndpointTest, ConnectionCommandsOnlyAdvanceTheSelectedHandle) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 22,
        },
        coquic::quic::test::test_time(1)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    *core.connections_.at(2).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);
    core.connections_.at(2).route_handle_by_path_id.emplace(0, 22);
    core.connections_.at(2).path_id_by_route_handle.emplace(22, 0);

    auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 2,
            .input =
                coquic::quic::QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_ints({0x68, 0x69}),
                    .fin = true,
                },
        },
        coquic::quic::test::test_time(2));

    auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    for (const auto &send : sends) {
        EXPECT_EQ(send.connection, 2u);
        ASSERT_TRUE(send.route_handle.has_value());
        EXPECT_EQ(send.route_handle.value_or(0), 22u);
    }
    EXPECT_EQ(core.connection_count(), 2u);
}

TEST(QuicCoreEndpointTest, EndpointConnectionCommandSendsDatagramOnSelectedConnection) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 22,
        },
        coquic::quic::test::test_time(1)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    *core.connections_.at(2).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);
    core.connections_.at(2).route_handle_by_path_id.emplace(0, 22);
    core.connections_.at(2).path_id_by_route_handle.emplace(22, 0);

    auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 2,
            .input =
                coquic::quic::QuicCoreSendDatagramData{
                    .bytes = bytes_from_ints({0x64}),
                },
        },
        coquic::quic::test::test_time(2));

    auto sends = send_effects_from(result);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends.front().connection, 2u);
    ASSERT_TRUE(sends.front().route_handle.has_value());
    EXPECT_EQ(sends.front().route_handle.value_or(0), 22u);

    auto payloads = application_datagram_payloads_from_datagram(*core.connections_.at(2).connection,
                                                                sends.front().bytes.span());
    ASSERT_EQ(payloads.size(), 1u);
    EXPECT_EQ(payloads.front(), bytes_from_ints({0x64}));
}

TEST(QuicCoreEndpointTest, EndpointConnectionCommandReportsDatagramLocalErrors) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);

    auto &peer_transport =
        optional_ref_or_terminate(core.connections_.at(1).connection->peer_transport_parameters_);
    peer_transport.max_datagram_frame_size = 0;
    const auto unsupported = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendDatagramData{
                    .bytes = bytes_from_ints({0x64}),
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(unsupported.local_error.has_value());
    EXPECT_EQ(optional_ref_or_terminate(unsupported.local_error).connection, 1u);
    EXPECT_EQ(optional_ref_or_terminate(unsupported.local_error).code,
              coquic::quic::QuicCoreLocalErrorCode::datagram_not_supported);
    EXPECT_FALSE(optional_ref_or_terminate(unsupported.local_error).stream_id.has_value());
    EXPECT_TRUE(send_effects_from(unsupported).empty());

    auto shared_unsupported = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendSharedDatagramData{
                    .bytes = coquic::quic::SharedBytes(bytes_from_ints({0x65})),
                },
        },
        coquic::quic::test::test_time(2));

    ASSERT_TRUE(shared_unsupported.local_error.has_value());
    EXPECT_EQ(optional_ref_or_terminate(shared_unsupported.local_error).connection, 1u);
    EXPECT_EQ(optional_ref_or_terminate(shared_unsupported.local_error).code,
              coquic::quic::QuicCoreLocalErrorCode::datagram_not_supported);
    EXPECT_FALSE(optional_ref_or_terminate(shared_unsupported.local_error).stream_id.has_value());
    EXPECT_TRUE(send_effects_from(shared_unsupported).empty());

    peer_transport.max_datagram_frame_size = 2;
    auto too_large = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendDatagramData{
                    .bytes = bytes_from_ints({0x64}),
                },
        },
        coquic::quic::test::test_time(3));

    ASSERT_TRUE(too_large.local_error.has_value());
    EXPECT_EQ(optional_ref_or_terminate(too_large.local_error).connection, 1u);
    EXPECT_EQ(optional_ref_or_terminate(too_large.local_error).code,
              coquic::quic::QuicCoreLocalErrorCode::datagram_too_large);
    EXPECT_FALSE(optional_ref_or_terminate(too_large.local_error).stream_id.has_value());
    EXPECT_TRUE(send_effects_from(too_large).empty());
}

TEST(QuicCoreEndpointTest, ConnectionCommandStillDrainsEachStreamSend) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);

    const auto first = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_ints({0x61}),
                    .fin = false,
                },
        },
        coquic::quic::test::test_time(1));
    auto second = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendStreamData{
                    .stream_id = 4,
                    .bytes = bytes_from_ints({0x62}),
                    .fin = false,
                },
        },
        coquic::quic::test::test_time(2));

    EXPECT_EQ(send_effects_from(first).size(), 1u);
    EXPECT_EQ(send_effects_from(second).size(), 1u);
}

TEST(QuicCoreEndpointTest, SharedSendCommandProducesSameDatagramAsOwnedSendCommand) {
    const auto make_ready_core = [] {
        coquic::quic::QuicCore core(make_client_endpoint_config());
        static_cast<void>(core.advance_endpoint(
            coquic::quic::QuicCoreOpenConnection{
                .connection = make_client_open_config(1),
                .initial_route_handle = 11,
            },
            coquic::quic::test::test_time(0)));

        *core.connections_.at(1).connection = make_connected_client_connection();
        core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
        core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);
        return core;
    };

    auto owned_core = make_ready_core();
    auto shared_core = make_ready_core();

    const auto owned = owned_core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_ints({0x68, 0x69, 0x21}),
                    .fin = true,
                },
        },
        coquic::quic::test::test_time(1));
    auto shared = shared_core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendSharedStreamData{
                    .stream_id = 0,
                    .bytes = coquic::quic::SharedBytes(bytes_from_ints({0x68, 0x69, 0x21})),
                    .fin = true,
                },
        },
        coquic::quic::test::test_time(1));

    auto owned_sends = send_effects_from(owned);
    auto shared_sends = send_effects_from(shared);
    ASSERT_EQ(owned_sends.size(), shared_sends.size());
    ASSERT_FALSE(owned_sends.empty());
    EXPECT_EQ(shared_sends.front().route_handle, owned_sends.front().route_handle);
    const auto owned_frames = stream_frames_from_sender_datagram(
        *owned_core.connections_.at(1).connection, owned_sends.front().bytes.span());
    const auto shared_frames = stream_frames_from_sender_datagram(
        *shared_core.connections_.at(1).connection, shared_sends.front().bytes.span());
    ASSERT_EQ(owned_frames.size(), 1u);
    ASSERT_EQ(shared_frames.size(), 1u);
    EXPECT_EQ(shared_frames.front().stream_id, owned_frames.front().stream_id);
    EXPECT_EQ(shared_frames.front().offset, owned_frames.front().offset);
    EXPECT_EQ(shared_frames.front().fin, owned_frames.front().fin);
    EXPECT_EQ(shared_frames.front().stream_data, owned_frames.front().stream_data);
}

TEST(QuicCoreEndpointTest, EndpointConnectionCommandSendsSharedDatagramOnSelectedConnection) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 22,
        },
        coquic::quic::test::test_time(1)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    *core.connections_.at(2).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);
    core.connections_.at(2).route_handle_by_path_id.emplace(0, 22);
    core.connections_.at(2).path_id_by_route_handle.emplace(22, 0);

    auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 2,
            .input =
                coquic::quic::QuicCoreSendSharedDatagramData{
                    .bytes = coquic::quic::SharedBytes(bytes_from_ints({0x73, 0x68})),
                },
        },
        coquic::quic::test::test_time(2));

    EXPECT_FALSE(result.local_error.has_value());
    auto sends = send_effects_from(result);
    ASSERT_EQ(sends.size(), 1u);
    EXPECT_EQ(sends.front().connection, 2u);
    ASSERT_TRUE(sends.front().route_handle.has_value());
    EXPECT_EQ(sends.front().route_handle.value_or(0), 22u);

    auto payloads = application_datagram_payloads_from_datagram(*core.connections_.at(2).connection,
                                                                sends.front().bytes.span());
    ASSERT_EQ(payloads.size(), 1u);
    EXPECT_EQ(payloads.front(), bytes_from_ints({0x73, 0x68}));
}

TEST(QuicCoreEndpointTest, EndpointTimerExpiredWalksAllDueConnections) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 22,
        },
        coquic::quic::test::test_time(0)));

    const auto wakeup = core.next_wakeup();
    ASSERT_TRUE(wakeup.has_value());
    auto result = core.advance_endpoint(coquic::quic::QuicCoreTimerExpired{},
                                        wakeup.value_or(coquic::quic::test::test_time(0)));

    EXPECT_EQ(core.connection_count(), 2u);
    EXPECT_EQ(result.next_wakeup, core.next_wakeup());
}

TEST(QuicCoreEndpointTest, IdleTimeoutRemovesConnectionWithClosedLifecycleEvent) {
    auto config = make_client_endpoint_config();
    config.transport.max_idle_timeout = 5000;
    coquic::quic::QuicCore core(std::move(config));

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    auto &connection = *core.connections_.at(1).connection;
    connection.local_transport_parameters_.max_idle_timeout = 5000;
    optional_ref_or_terminate(connection.peer_transport_parameters_).max_idle_timeout = 5000;
    connection.note_idle_peer_activity(coquic::quic::test::test_time(100));

    const auto deadline = connection.idle_timeout_deadline();
    ASSERT_TRUE(deadline.has_value());

    auto result = core.advance_endpoint(coquic::quic::QuicCoreTimerExpired{},
                                        optional_value_or_terminate(deadline));

    EXPECT_EQ(core.connection_count(), 0u);
    auto lifecycle = lifecycle_events_from(result);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().connection, 1u);
    EXPECT_EQ(lifecycle.front().event, coquic::quic::QuicCoreConnectionLifecycle::closed);
    EXPECT_TRUE(state_changes_from(result).empty());
    EXPECT_TRUE(send_effects_from(result).empty());
}

TEST(QuicCoreEndpointTest, RouteHandleMigrationCommandTargetsSelectedConnection) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    auto &connection = *core.connections_.at(1).connection;
    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0xaa, 0xab}),
    };
    connection.peer_connection_ids_[2] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 2,
        .connection_id = bytes_from_ints({0x10, 0x12}),
    };
    connection.active_peer_connection_id_sequence_ = 0;
    connection.ensure_path_state(0).peer_connection_id_sequence = 0;
    EXPECT_FALSE(
        has_public_path_id_member<coquic::quic::QuicCoreRequestConnectionMigration>::value);
    EXPECT_TRUE(
        (std::is_same_v<route_handle_member_type<coquic::quic::QuicCoreRequestConnectionMigration>,
                        coquic::quic::QuicRouteHandle>));

    auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreRequestConnectionMigration{
                    .route_handle = 29,
                    .reason = coquic::quic::QuicMigrationRequestReason::active,
                },
        },
        coquic::quic::test::test_time(1));

    EXPECT_FALSE(result.local_error.has_value());
}

TEST(QuicCoreEndpointTest, AddressChangePolicyRejectsNewInboundRoutesAndMigrationRequests) {
    auto config = make_client_endpoint_config();
    config.allow_peer_address_change = false;
    coquic::quic::QuicCore core(std::move(config));

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);

    const auto migration = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreRequestConnectionMigration{
                    .route_handle = 29,
                    .reason = coquic::quic::QuicMigrationRequestReason::active,
                },
        },
        coquic::quic::test::test_time(1));
    auto migration_error = optional_value_or_terminate(migration.local_error);
    EXPECT_EQ(migration_error.code, coquic::quic::QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_FALSE(core.connections_.at(1).path_id_by_route_handle.contains(29));

    auto inbound = core.advance_endpoint(
        coquic::quic::QuicCoreInboundDatagram{
            .bytes = bytes_from_ints({0x40, 0xa1, 0xb2, 0x00, 0x00}),
            .route_handle = 29,
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(inbound.effects.empty());
    EXPECT_FALSE(core.connections_.at(1).path_id_by_route_handle.contains(29));
}

TEST(QuicCoreEndpointTest, CloseConnectionCommandRetainsStateUntilCloseDeadline) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);

    auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreCloseConnection{
                    .application_error_code = 0,
                    .reason_phrase = "done",
                },
        },
        coquic::quic::test::test_time(1));

    EXPECT_EQ(core.connection_count(), 1u);
    EXPECT_TRUE(result.next_wakeup.has_value());
    EXPECT_TRUE(lifecycle_events_from(result).empty());
    EXPECT_EQ(coquic::quic::test::count_state_change(coquic::quic::test::state_changes_from(result),
                                                     coquic::quic::QuicCoreStateChange::failed),
              1u);
    EXPECT_FALSE(send_effects_from(result).empty());

    auto next_wakeup = optional_value_or_terminate(result.next_wakeup);
    auto expired = core.advance_endpoint(coquic::quic::QuicCoreTimerExpired{}, next_wakeup);
    auto lifecycle = lifecycle_events_from(expired);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().connection, 1u);
    EXPECT_EQ(lifecycle.front().event, coquic::quic::QuicCoreConnectionLifecycle::closed);
    EXPECT_EQ(core.connection_count(), 0u);
}

TEST(QuicCoreEndpointTest, ServerCloseConnectionCommandRetainsStateUntilCloseDeadline) {
    coquic::quic::QuicCore core(make_server_endpoint_config());

    auto entry = coquic::quic::QuicCore::ConnectionEntry{
        .handle = 1,
        .default_route_handle = 11,
        .connection = std::make_unique<coquic::quic::QuicConnection>(
            coquic::quic::test::make_server_core_config()),
    };
    *entry.connection = make_connected_server_connection();
    entry.route_handle_by_path_id.emplace(0, 11);
    entry.path_id_by_route_handle.emplace(11, 0);
    core.connections_.emplace(entry.handle, std::move(entry));

    auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreCloseConnection{
                    .application_error_code = 0,
                    .reason_phrase = "done",
                },
        },
        coquic::quic::test::test_time(1));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
    // # Servers that retain an open socket for accepting new connections
    // # SHOULD NOT end the closing or draining state early.
    EXPECT_EQ(core.connection_count(), 1u);
    EXPECT_TRUE(result.next_wakeup.has_value());
    EXPECT_TRUE(lifecycle_events_from(result).empty());

    auto next_wakeup = optional_value_or_terminate(result.next_wakeup);
    auto before_deadline = core.advance_endpoint(coquic::quic::QuicCoreTimerExpired{},
                                                 next_wakeup - std::chrono::microseconds(1));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
    // # Servers that retain an open socket for accepting new connections
    // # SHOULD NOT end the closing or draining state early.
    EXPECT_EQ(core.connection_count(), 1u);
    EXPECT_TRUE(lifecycle_events_from(before_deadline).empty());

    auto expired = core.advance_endpoint(coquic::quic::QuicCoreTimerExpired{}, next_wakeup);
    auto lifecycle = lifecycle_events_from(expired);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().connection, 1u);
    EXPECT_EQ(lifecycle.front().event, coquic::quic::QuicCoreConnectionLifecycle::closed);
    EXPECT_EQ(core.connection_count(), 0u);
}
} // namespace
