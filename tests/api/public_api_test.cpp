#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "coquic/coquic.h"
#include "src/quic/core.h"

namespace {

std::vector<std::byte> bytes(std::initializer_list<std::uint8_t> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (const auto value : values) {
        out.push_back(static_cast<std::byte>(value));
    }
    return out;
}

coquic::core::ClientConnectionConfig client_connection_config() {
    return coquic::core::ClientConnectionConfig{
        .source_connection_id = bytes({0xc1, 0x01}),
        .initial_destination_connection_id = bytes({0x83, 0x41}),
        .server_name = "localhost",
    };
}

TEST(CoquicPublicApiTest, CoreEndpointOpensConnectionAndReportsDatagrams) {
    coquic::core::Endpoint endpoint(coquic::core::EndpointConfig{
        .role = coquic::core::Role::client,
        .verify_peer = false,
        .application_protocol = "coquic",
    });

    auto result = endpoint.open_connection(
        coquic::core::OpenConnection{
            .connection = client_connection_config(),
            .initial_route_handle = 7,
        },
        coquic::core::TimePoint{});

    ASSERT_FALSE(result.local_error.has_value());
    const auto lifecycle = coquic::core::lifecycle_events(result);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().connection, 1u);
    EXPECT_EQ(lifecycle.front().event, coquic::core::Lifecycle::created);

    const auto datagrams = coquic::core::send_datagrams(result);
    ASSERT_FALSE(datagrams.empty());
    EXPECT_EQ(datagrams.front().connection, 1u);
    EXPECT_EQ(datagrams.front().route_handle, std::optional<coquic::core::RouteHandle>{7});
    EXPECT_EQ(endpoint.connection_count(), 1u);
}

TEST(CoquicPublicApiTest, QuicEndpointReturnsConnectionFacade) {
    coquic::quic::Endpoint endpoint(coquic::quic::EndpointConfig{
        .core =
            {
                .role = coquic::core::Role::client,
                .verify_peer = false,
                .application_protocol = "coquic",
            },
    });

    auto connected = endpoint.connect(
        coquic::quic::ClientConfig{
            .core = client_connection_config(),
            .initial_route_handle = 11,
        },
        coquic::quic::TimePoint{});

    ASSERT_TRUE(connected.connection);
    EXPECT_EQ(connected.connection.handle(), 1u);
    EXPECT_EQ(endpoint.connection_count(), 1u);

    const auto datagrams = coquic::core::send_datagrams(connected.result);
    ASSERT_FALSE(datagrams.empty());
    EXPECT_EQ(datagrams.front().route_handle, std::optional<coquic::core::RouteHandle>{11});
    EXPECT_TRUE(connected.connection.stream(0));
}

TEST(CoquicPublicApiTest, CoreEndpointCoversServerAndTransportOptions) {
    for (const auto algorithm :
         {coquic::core::CongestionControl::cubic, coquic::core::CongestionControl::bbr,
          coquic::core::CongestionControl::copa}) {
        coquic::core::Endpoint endpoint(coquic::core::EndpointConfig{
            .role = coquic::core::Role::server,
            .supported_versions = {1, 0x6b3343cfu},
            .verify_peer = true,
            .retry_enabled = true,
            .application_protocol = "h3",
            .identity =
                coquic::core::TlsIdentity{
                    .certificate_pem = "not a certificate",
                    .private_key_pem = "not a key",
                },
            .transport =
                {
                    .congestion_control = algorithm,
                    .enable_latency_spin_bit = true,
                    .grease_reserved_versions = true,
                    .grease_quic_bit = true,
                    .enable_optimistic_ack_mitigation = true,
                },
            .zero_rtt =
                {
                    .attempt = true,
                    .allow = true,
                    .application_context = bytes({0x01, 0x02}),
                },
            .qlog = coquic::core::QlogConfig{.directory = "."},
            .tls_keylog_path = ".coquic-test-keylog",
            .emit_shared_receive_stream_data = true,
            .enable_packet_inspection = true,
            .allow_peer_address_change = false,
        });

        EXPECT_EQ(endpoint.connection_count(), 0u);
        EXPECT_FALSE(endpoint.next_wakeup().has_value());
        EXPECT_FALSE(endpoint.has_send_continuation_pending());
        EXPECT_FALSE(endpoint.has_pending_stream_send());
        EXPECT_TRUE(endpoint.connection_diagnostics().empty());
    }
}

TEST(CoquicPublicApiTest, CoreEndpointForwardsEndpointInputs) {
    coquic::core::Endpoint endpoint(coquic::core::EndpointConfig{
        .role = coquic::core::Role::client,
        .verify_peer = false,
        .application_protocol = "coquic",
    });

    auto result = endpoint.advance(
        coquic::core::OpenConnection{
            .connection =
                {
                    .source_connection_id = bytes({0xc1, 0x10}),
                    .initial_destination_connection_id = bytes({0x83, 0x50}),
                    .original_destination_connection_id = bytes({0x83, 0x50}),
                    .retry_source_connection_id = bytes({0x44, 0x55}),
                    .retry_token = bytes({0xaa}),
                    .reacted_to_version_negotiation = true,
                    .server_name = "localhost",
                    .resumption_state = coquic::core::ResumptionState{.serialized = bytes({0x01})},
                    .zero_rtt = {.attempt = true, .application_context = bytes({0x02})},
                },
            .initial_route_handle = 21,
            .address_validation_identity = bytes({0x99}),
        },
        coquic::core::TimePoint{});

    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_EQ(endpoint.connection_count(), 1u);

    for (const auto ecn : {coquic::core::EcnCodepoint::unavailable,
                           coquic::core::EcnCodepoint::not_ect, coquic::core::EcnCodepoint::ect0,
                           coquic::core::EcnCodepoint::ect1, coquic::core::EcnCodepoint::ce}) {
        result = endpoint.input_datagram(
            coquic::core::InboundDatagram{
                .bytes = {},
                .route_handle = std::optional<coquic::core::RouteHandle>{21},
                .address_validation_identity = bytes({0x77}),
                .ecn = ecn,
            },
            coquic::core::TimePoint{});
        EXPECT_FALSE(result.local_error.has_value());
    }

    result = endpoint.update_path_mtu(
        coquic::core::PathMtuUpdate{
            .route_handle = std::optional<coquic::core::RouteHandle>{21},
            .max_udp_payload_size = 1200,
        },
        coquic::core::TimePoint{});
    EXPECT_FALSE(result.local_error.has_value());

    result = endpoint.timer_expired(coquic::core::TimePoint{});
    EXPECT_FALSE(result.local_error.has_value());
}

TEST(CoquicPublicApiTest, CoreEndpointMoveOperationsPreserveUsability) {
    coquic::core::Endpoint source(coquic::core::EndpointConfig{
        .role = coquic::core::Role::client,
        .verify_peer = false,
        .application_protocol = "coquic",
    });

    auto result = source.open_connection(
        coquic::core::OpenConnection{
            .connection = client_connection_config(),
            .initial_route_handle = 25,
        },
        coquic::core::TimePoint{});
    ASSERT_FALSE(result.local_error.has_value());
    ASSERT_EQ(source.connection_count(), 1u);

    coquic::core::Endpoint moved(std::move(source));
    EXPECT_EQ(moved.connection_count(), 1u);

    coquic::core::Endpoint assigned;
    assigned = std::move(moved);
    EXPECT_EQ(assigned.connection_count(), 1u);
    EXPECT_FALSE(assigned.timer_expired(coquic::core::TimePoint{}).local_error.has_value());
}

TEST(CoquicPublicApiTest, QuicFacadeForwardsEndpointAndConnectionMethods) {
    coquic::quic::Endpoint endpoint(coquic::quic::EndpointConfig{
        .core =
            {
                .role = coquic::core::Role::client,
                .verify_peer = false,
                .application_protocol = "coquic",
            },
    });

    auto connected = endpoint.connect(
        coquic::quic::ClientConfig{
            .core = client_connection_config(),
            .initial_route_handle = 31,
            .address_validation_identity = bytes({0x31}),
        },
        coquic::quic::TimePoint{});

    ASSERT_TRUE(connected.connection);
    EXPECT_EQ(endpoint.connection_count(), 1u);
    EXPECT_FALSE(endpoint.connection_diagnostics().empty());
    EXPECT_TRUE(endpoint.next_wakeup().has_value());

    auto result = endpoint.receive_datagram(
        coquic::core::InboundDatagram{
            .bytes = {},
            .route_handle = std::optional<coquic::core::RouteHandle>{31},
            .ecn = coquic::core::EcnCodepoint::ect0,
        },
        coquic::quic::TimePoint{});
    EXPECT_FALSE(result.local_error.has_value());

    result = endpoint.update_path_mtu(
        coquic::core::PathMtuUpdate{
            .route_handle = std::optional<coquic::core::RouteHandle>{31},
            .max_udp_payload_size = 1200,
        },
        coquic::quic::TimePoint{});
    EXPECT_FALSE(result.local_error.has_value());

    result = endpoint.timer_expired(coquic::quic::TimePoint{});
    EXPECT_FALSE(result.local_error.has_value());

    result = endpoint.advance(coquic::core::TimerExpired{}, coquic::quic::TimePoint{});
    EXPECT_FALSE(result.local_error.has_value());

    const auto payload = bytes({0x68, 0x69});
    const auto connection = connected.connection;
    EXPECT_EQ(connection.handle(), 1u);
    EXPECT_TRUE(connection.stream(4));

    (void)connection.send_stream(0, payload, true, coquic::quic::TimePoint{});
    (void)connection.send_datagram(payload, coquic::quic::TimePoint{});
    (void)connection.reset_stream(4, 42, coquic::quic::TimePoint{});
    (void)connection.stop_sending(8, 43, coquic::quic::TimePoint{});
    (void)connection.close(44, "done", coquic::quic::TimePoint{});
    (void)connection.request_key_update(coquic::quic::TimePoint{});

    const auto stream = connection.stream(12);
    EXPECT_EQ(stream.id(), 12u);
    EXPECT_TRUE(stream);
    EXPECT_TRUE(stream.send(payload, true, coquic::quic::TimePoint{}).local_error.has_value());
    EXPECT_TRUE(stream.finish(coquic::quic::TimePoint{}).local_error.has_value());
    EXPECT_TRUE(stream.reset(45, coquic::quic::TimePoint{}).local_error.has_value());
    EXPECT_TRUE(stream.stop_sending(46, coquic::quic::TimePoint{}).local_error.has_value());
}

TEST(CoquicPublicApiTest, QuicEndpointMoveOperationsPreserveUsability) {
    coquic::quic::Endpoint source(coquic::quic::EndpointConfig{
        .core =
            {
                .role = coquic::core::Role::client,
                .verify_peer = false,
                .application_protocol = "coquic",
            },
    });

    auto connected = source.connect(
        coquic::quic::ClientConfig{
            .core = client_connection_config(),
            .initial_route_handle = 33,
        },
        coquic::quic::TimePoint{});
    ASSERT_TRUE(connected.connection);

    coquic::quic::Endpoint moved(std::move(source));
    EXPECT_EQ(moved.connection_count(), 1u);

    coquic::quic::Endpoint assigned;
    assigned = std::move(moved);
    EXPECT_EQ(assigned.connection_count(), 1u);
    EXPECT_FALSE(assigned.timer_expired(coquic::quic::TimePoint{}).local_error.has_value());
}

TEST(CoquicPublicApiTest, QuicDefaultConnectionReportsLocalError) {
    coquic::quic::Connection connection;
    EXPECT_FALSE(connection);
    EXPECT_EQ(connection.handle(), 0u);

    const auto payload = bytes({0x68});
    for (auto result :
         {connection.advance(coquic::core::RequestKeyUpdate{}, coquic::quic::TimePoint{}),
          connection.send_stream(0, payload, false, coquic::quic::TimePoint{}),
          connection.send_datagram(payload, coquic::quic::TimePoint{}),
          connection.reset_stream(0, 1, coquic::quic::TimePoint{}),
          connection.stop_sending(0, 2, coquic::quic::TimePoint{}),
          connection.close(3, "closed", coquic::quic::TimePoint{}),
          connection.request_key_update(coquic::quic::TimePoint{})}) {
        ASSERT_TRUE(result.local_error.has_value());
        EXPECT_FALSE(result.local_error->connection.has_value());
        EXPECT_EQ(result.local_error->code, coquic::core::LocalErrorCode::unsupported_operation);
    }

    coquic::quic::Stream stream;
    EXPECT_FALSE(stream);
    EXPECT_EQ(stream.id(), 0u);
}

TEST(CoquicPublicApiTest, QuicEndpointConnectionWithZeroHandleIsInvalid) {
    coquic::quic::Endpoint endpoint(coquic::quic::EndpointConfig{
        .core =
            {
                .role = coquic::core::Role::client,
                .verify_peer = false,
                .application_protocol = "coquic",
            },
    });

    const auto connection = endpoint.connection(0);
    EXPECT_FALSE(connection);
    EXPECT_EQ(connection.handle(), 0u);
    EXPECT_FALSE(connection.stream(4));
}

TEST(CoquicPublicApiTest, QuicConnectOnServerEndpointReturnsInvalidConnection) {
    coquic::quic::Endpoint endpoint(coquic::quic::EndpointConfig{
        .core =
            {
                .role = coquic::core::Role::server,
                .verify_peer = false,
                .application_protocol = "coquic",
            },
    });

    auto connected = endpoint.connect(
        coquic::quic::ClientConfig{
            .core = client_connection_config(),
        },
        coquic::quic::TimePoint{});

    EXPECT_FALSE(connected.connection);
    EXPECT_EQ(connected.connection.handle(), 0u);
    ASSERT_TRUE(connected.result.local_error.has_value());
    EXPECT_EQ(connected.result.local_error->code,
              coquic::core::LocalErrorCode::unsupported_operation);
    EXPECT_TRUE(coquic::core::lifecycle_events(connected.result).empty());
}

TEST(CoquicPublicApiTest, CoreEffectAllocatorRejectsOverflowingElementCount) {
    coquic::quic::CoreEffectAllocator<coquic::quic::QuicCoreEffect> allocator;
    const auto overflowing_count =
        (std::numeric_limits<std::size_t>::max() / sizeof(coquic::quic::QuicCoreEffect)) + 1u;

#if defined(__cpp_exceptions)
    bool threw_bad_length = false;
    try {
        static_cast<void>(allocator.allocate(overflowing_count));
    } catch (const std::bad_array_new_length &) {
        threw_bad_length = true;
    }
    EXPECT_TRUE(threw_bad_length);
#elif GTEST_HAS_DEATH_TEST
    EXPECT_DEATH(static_cast<void>(allocator.allocate(overflowing_count)), "");
#else
    GTEST_SKIP() << "allocator overflow path aborts without exception support";
#endif
}

TEST(CoquicPublicApiTest, Http3ClientAndServerMoveOperationsPreserveUsability) {
    coquic::http3::Client client;
    coquic::http3::Client moved_client(std::move(client));
    EXPECT_FALSE(moved_client.has_failed());

    coquic::http3::Client assigned_client;
    assigned_client = std::move(moved_client);
    EXPECT_FALSE(assigned_client.has_failed());
    EXPECT_TRUE(assigned_client.poll(coquic::http3::TimePoint{}).quic_inputs.empty());

    coquic::http3::Server server;
    coquic::http3::Server moved_server(std::move(server));
    EXPECT_FALSE(moved_server.has_failed());

    coquic::http3::Server assigned_server;
    assigned_server = std::move(moved_server);
    EXPECT_FALSE(assigned_server.has_failed());
    EXPECT_TRUE(assigned_server.poll(coquic::http3::TimePoint{}).quic_inputs.empty());
}

TEST(CoquicPublicApiTest, Http3ClientQueuesRequestBehindTransportReadiness) {
    coquic::http3::Client client;
    auto submitted = client.submit_request(coquic::http3::Request{
        .head =
            {
                .method = "GET",
                .scheme = "https",
                .authority = "example.test",
                .path = "/",
            },
    });

    ASSERT_TRUE(submitted.has_value());
    EXPECT_EQ(submitted.value(), 0u);

    auto update = client.poll(coquic::http3::TimePoint{});
    EXPECT_TRUE(update.has_pending_work);
    EXPECT_TRUE(update.quic_inputs.empty());

    coquic::core::Result ready;
    ready.effects.push_back(coquic::core::StateEvent{
        .connection = 1,
        .change = coquic::core::StateChange::handshake_ready,
    });
    update = client.on_quic_result(ready, coquic::http3::TimePoint{});
    EXPECT_FALSE(update.terminal_failure);
    EXPECT_GE(update.quic_inputs.size(), 3u);
}

TEST(CoquicPublicApiTest, Http3EndpointConfigSetsAlpnAndRole) {
    const auto client = coquic::http3::client_endpoint_config();
    EXPECT_EQ(client.role, coquic::core::Role::client);
    EXPECT_EQ(client.application_protocol, "h3");

    const auto server = coquic::http3::server_endpoint_config();
    EXPECT_EQ(server.role, coquic::core::Role::server);
    EXPECT_EQ(server.application_protocol, "h3");

    coquic::http3::Server handler_server(coquic::http3::ServerConfig{
        .request_handler =
            [](const coquic::http3::Request &request) {
                EXPECT_EQ(request.head.path, "/");
                return coquic::http3::Response{
                    .head =
                        {
                            .status = 200,
                            .content_length = 2,
                        },
                    .body = bytes({0x6f, 0x6b}),
                };
            },
    });
    EXPECT_FALSE(handler_server.has_failed());
}
} // namespace
