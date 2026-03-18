#include <gtest/gtest.h>

#include "src/quic/transport_parameters.h"

namespace {

using coquic::quic::EndpointRole;
using coquic::quic::TransportParameters;
using coquic::quic::TransportParametersValidationContext;

TEST(QuicTransportParametersTest, RoundTripsMinimalClientParameters) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id =
            coquic::quic::ConnectionId{std::byte{0xc1}, std::byte{0x01}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    const auto &initial_source_connection_id = decoded.value().initial_source_connection_id;
    ASSERT_TRUE(initial_source_connection_id.has_value());
    EXPECT_EQ(initial_source_connection_id.value_or(coquic::quic::ConnectionId{}),
              (coquic::quic::ConnectionId{std::byte{0xc1}, std::byte{0x01}}));
    EXPECT_EQ(decoded.value().active_connection_id_limit, 2u);
}

TEST(QuicTransportParametersTest, RejectsActiveConnectionIdLimitBelowTwo) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 1,
        .initial_source_connection_id = coquic::quic::ConnectionId{std::byte{0xaa}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        coquic::quic::deserialize_transport_parameters(encoded.value()).value(),
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = {std::byte{0xaa}},
        });
    ASSERT_FALSE(validation.has_value());
}

TEST(QuicTransportParametersTest, ValidatesServerConnectionIdsAgainstHandshakeContext) {
    const TransportParameters parameters{
        .original_destination_connection_id =
            coquic::quic::ConnectionId{std::byte{0x83}, std::byte{0x94}},
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id =
            coquic::quic::ConnectionId{std::byte{0x53}, std::byte{0x01}},
    };

    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server, parameters,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = {std::byte{0x53}, std::byte{0x01}},
            .expected_original_destination_connection_id =
                coquic::quic::ConnectionId{std::byte{0x83}, std::byte{0x94}},
        });
    ASSERT_TRUE(validation.has_value());
}

} // namespace
