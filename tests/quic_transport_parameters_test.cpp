#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/transport_parameters.h"

namespace {

using coquic::quic::CodecErrorCode;
using coquic::quic::ConnectionId;
using coquic::quic::EndpointRole;
using coquic::quic::TransportParameters;
using coquic::quic::TransportParametersValidationContext;

std::vector<std::byte> byte_vector(std::initializer_list<unsigned int> values) {
    std::vector<std::byte> bytes;
    bytes.reserve(values.size());
    for (const auto value : values) {
        bytes.push_back(static_cast<std::byte>(value));
    }

    return bytes;
}

TransportParametersValidationContext make_validation_context(
    ConnectionId expected_initial_source_connection_id,
    std::optional<ConnectionId> expected_original_destination_connection_id = std::nullopt,
    std::optional<ConnectionId> expected_retry_source_connection_id = std::nullopt) {
    return TransportParametersValidationContext{
        .expected_initial_source_connection_id = std::move(expected_initial_source_connection_id),
        .expected_original_destination_connection_id =
            std::move(expected_original_destination_connection_id),
        .expected_retry_source_connection_id = std::move(expected_retry_source_connection_id),
    };
}

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

TEST(QuicTransportParametersTest, RoundTripsRetrySourceConnectionId) {
    const TransportParameters parameters{
        .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 4,
        .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
        .retry_source_connection_id = ConnectionId{std::byte{0xaa}, std::byte{0xbb}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().original_destination_connection_id,
              parameters.original_destination_connection_id);
    EXPECT_EQ(decoded.value().max_udp_payload_size, parameters.max_udp_payload_size);
    EXPECT_EQ(decoded.value().active_connection_id_limit, parameters.active_connection_id_limit);
    EXPECT_EQ(decoded.value().initial_source_connection_id,
              parameters.initial_source_connection_id);
    EXPECT_EQ(decoded.value().retry_source_connection_id, parameters.retry_source_connection_id);
}

TEST(QuicTransportParametersTest, RoundTripsAckDelayExponentAndMaxAckDelay) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = ConnectionId{std::byte{0xc1}},
        .ack_delay_exponent = 5,
        .max_ack_delay = 42,
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().ack_delay_exponent, 5u);
    EXPECT_EQ(decoded.value().max_ack_delay, 42u);
}

TEST(QuicTransportParametersTest, MissingAckTimingParametersUseRfcDefaults) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x03,
        0x02,
        0x44,
        0xb0,
        0x0e,
        0x01,
        0x02,
        0x0f,
        0x01,
        0x11,
    }));

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().ack_delay_exponent, 3u);
    EXPECT_EQ(decoded.value().max_ack_delay, 25u);
}

TEST(QuicTransportParametersTest, RejectsInvalidAckTimingValues) {
    const auto bad_exponent = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .ack_delay_exponent = 21,
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));
    ASSERT_FALSE(bad_exponent.has_value());

    const auto bad_max_ack_delay = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .max_ack_delay = (1u << 14),
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));
    ASSERT_FALSE(bad_max_ack_delay.has_value());
}

TEST(QuicTransportParametersTest, RejectsMaxUdpPayloadSizeAboveVarintLimitDuringSerialization) {
    const TransportParameters parameters{
        .max_udp_payload_size = (std::uint64_t{1} << 62),
        .active_connection_id_limit = 2,
        .initial_source_connection_id = ConnectionId{std::byte{0x01}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);

    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest,
     RejectsActiveConnectionIdLimitAboveVarintLimitDuringSerialization) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = (std::uint64_t{1} << 62),
        .initial_source_connection_id = ConnectionId{std::byte{0x01}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);

    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest, RejectsAckDelayExponentAboveVarintLimitDuringSerialization) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = (std::uint64_t{1} << 62),
        .initial_source_connection_id = ConnectionId{std::byte{0x01}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);

    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest, RejectsMaxAckDelayAboveVarintLimitDuringSerialization) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = ConnectionId{std::byte{0x01}},
        .max_ack_delay = (std::uint64_t{1} << 62),
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);

    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest, IgnoresUnknownParameterIdsDuringParse) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x20,
        0x01,
        0xff,
        0x03,
        0x02,
        0x44,
        0xb0,
        0x0e,
        0x01,
        0x02,
        0x0f,
        0x01,
        0x11,
    }));

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().max_udp_payload_size, 1200u);
    EXPECT_EQ(decoded.value().active_connection_id_limit, 2u);
    EXPECT_EQ(decoded.value().initial_source_connection_id,
              std::optional<ConnectionId>{ConnectionId{std::byte{0x11}}});
    EXPECT_FALSE(decoded.value().retry_source_connection_id.has_value());
}

TEST(QuicTransportParametersTest, RejectsMalformedParameterIdEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({0x40}));

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::truncated_input);
}

TEST(QuicTransportParametersTest, RejectsMalformedParameterLengthEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({0x03, 0x40}));

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::truncated_input);
}

TEST(QuicTransportParametersTest, RejectsTruncatedParameterValue) {
    const auto decoded =
        coquic::quic::deserialize_transport_parameters(byte_vector({0x03, 0x02, 0x44}));

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::truncated_input);
}

TEST(QuicTransportParametersTest, RejectsInvalidMaxUdpPayloadSizeEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x03,
        0x02,
        0x01,
        0x00,
    }));

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest, RejectsInvalidActiveConnectionIdLimitEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x0e,
        0x02,
        0x01,
        0x00,
    }));

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest, RejectsInvalidAckDelayExponentEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x0a,
        0x02,
        0x01,
        0x00,
    }));

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest, RejectsInvalidMaxAckDelayEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x0b,
        0x02,
        0x01,
        0x00,
    }));

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest, RejectsTruncatedIntegerParameterEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x03,
        0x01,
        0x40,
    }));

    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::truncated_input);
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
        make_validation_context(ConnectionId{std::byte{0xaa}}));
    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, RejectsMissingInitialSourceConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, RejectsMismatchedInitialSourceConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xbb}},
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, RejectsMaxUdpPayloadSizeBelowMinimum) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1199,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ClientRejectsOriginalDestinationConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ClientRejectsRetrySourceConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .retry_source_connection_id = ConnectionId{std::byte{0xbb}},
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
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
        make_validation_context(ConnectionId{std::byte{0x53}, std::byte{0x01}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}));
    ASSERT_TRUE(validation.has_value());
}

TEST(QuicTransportParametersTest, ServerRejectsMissingOriginalDestinationConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
        },
        make_validation_context(ConnectionId{std::byte{0x53}, std::byte{0x01}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ServerRejectsMissingExpectedOriginalDestinationContext) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
        },
        make_validation_context(ConnectionId{std::byte{0x53}, std::byte{0x01}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ServerRejectsMismatchedOriginalDestinationConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x84}, std::byte{0x95}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
        },
        make_validation_context(ConnectionId{std::byte{0x53}, std::byte{0x01}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ServerRejectsMissingExpectedRetrySourceConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
        },
        make_validation_context(ConnectionId{std::byte{0x53}, std::byte{0x01}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}},
                                ConnectionId{std::byte{0xaa}, std::byte{0xbb}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ServerRejectsMismatchedRetrySourceConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
            .retry_source_connection_id = ConnectionId{std::byte{0xcc}, std::byte{0xdd}},
        },
        make_validation_context(ConnectionId{std::byte{0x53}, std::byte{0x01}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}},
                                ConnectionId{std::byte{0xaa}, std::byte{0xbb}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ServerRejectsUnexpectedRetrySourceConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
            .retry_source_connection_id = ConnectionId{std::byte{0xaa}, std::byte{0xbb}},
        },
        make_validation_context(ConnectionId{std::byte{0x53}, std::byte{0x01}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ServerAcceptsExpectedRetrySourceConnectionId) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
            .retry_source_connection_id = ConnectionId{std::byte{0xaa}, std::byte{0xbb}},
        },
        make_validation_context(ConnectionId{std::byte{0x53}, std::byte{0x01}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}},
                                ConnectionId{std::byte{0xaa}, std::byte{0xbb}}));

    ASSERT_TRUE(validation.has_value());
}

} // namespace
