#include <array>
#include <cstddef>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "coquic/coquic.h"

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
