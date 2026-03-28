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
using coquic::quic::VersionInformation;

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
    std::optional<ConnectionId> expected_retry_source_connection_id = std::nullopt,
    std::optional<VersionInformation> expected_version_information = std::nullopt,
    bool reacted_to_version_negotiation = false) {
    return TransportParametersValidationContext{
        .expected_initial_source_connection_id = std::move(expected_initial_source_connection_id),
        .expected_original_destination_connection_id =
            std::move(expected_original_destination_connection_id),
        .expected_retry_source_connection_id = std::move(expected_retry_source_connection_id),
        .expected_version_information = std::move(expected_version_information),
        .reacted_to_version_negotiation = reacted_to_version_negotiation,
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

TEST(QuicTransportParametersTest, RoundTripsVersionInformation) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = ConnectionId{std::byte{0xc1}, std::byte{0x01}},
        .version_information =
            VersionInformation{
                .chosen_version = 0x6b3343cfu,
                .available_versions = {0x6b3343cfu, 0x00000001u},
            },
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    const auto &decoded_parameters = decoded.value();
    if (!decoded_parameters.version_information.has_value()) {
        FAIL() << "expected version information to round-trip";
        return;
    }
    const auto &version_information = decoded_parameters.version_information.value();
    EXPECT_EQ(version_information.chosen_version, 0x6b3343cfu);
    EXPECT_EQ(version_information.available_versions,
              (std::vector<std::uint32_t>{0x6b3343cfu, 0x00000001u}));
}

TEST(QuicTransportParametersTest, RejectsMalformedVersionInformationEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(
        byte_vector({0x11, 0x05, 0x6b, 0x33, 0x43, 0xcf, 0x00}));
    ASSERT_FALSE(decoded.has_value());
    EXPECT_EQ(decoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest, RoundTripsAckDelayExponentAndMaxAckDelay) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = 5,
        .max_ack_delay = 42,
        .initial_source_connection_id = ConnectionId{std::byte{0xc1}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().ack_delay_exponent, 5u);
    EXPECT_EQ(decoded.value().max_ack_delay, 42u);
}

TEST(QuicTransportParametersTest, RoundTripsMaxIdleTimeout) {
    const TransportParameters parameters{
        .max_idle_timeout = 180000,
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = ConnectionId{std::byte{0xc1}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().max_idle_timeout, 180000u);
}

TEST(QuicTransportParametersTest, RoundTripsFlowControlAndStreamCountParameters) {
    const TransportParameters parameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = 4,
        .max_ack_delay = 17,
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 1024,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_stream_data_uni = 512,
        .initial_max_streams_bidi = 9,
        .initial_max_streams_uni = 5,
        .initial_source_connection_id = ConnectionId{std::byte{0xa1}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = coquic::quic::deserialize_transport_parameters(encoded.value());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value().initial_max_data, 4096u);
    EXPECT_EQ(decoded.value().initial_max_stream_data_bidi_local, 1024u);
    EXPECT_EQ(decoded.value().initial_max_stream_data_bidi_remote, 2048u);
    EXPECT_EQ(decoded.value().initial_max_stream_data_uni, 512u);
    EXPECT_EQ(decoded.value().initial_max_streams_bidi, 9u);
    EXPECT_EQ(decoded.value().initial_max_streams_uni, 5u);
}

TEST(QuicTransportParametersTest, MissingFlowControlParametersDefaultToZero) {
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
    EXPECT_EQ(decoded.value().initial_max_data, 0u);
    EXPECT_EQ(decoded.value().initial_max_stream_data_bidi_local, 0u);
    EXPECT_EQ(decoded.value().initial_max_stream_data_bidi_remote, 0u);
    EXPECT_EQ(decoded.value().initial_max_streams_bidi, 0u);
    EXPECT_EQ(decoded.value().initial_max_streams_uni, 0u);
    EXPECT_EQ(decoded.value().initial_max_stream_data_uni, 0u);
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

TEST(QuicTransportParametersTest, MissingMaxIdleTimeoutDefaultsToZero) {
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
    EXPECT_EQ(decoded.value().max_idle_timeout, 0u);
}

TEST(QuicTransportParametersTest, RejectsInvalidAckTimingValues) {
    const auto bad_exponent = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .ack_delay_exponent = 21,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}));
    ASSERT_FALSE(bad_exponent.has_value());

    const auto bad_max_ack_delay = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .max_ack_delay = (1u << 14),
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
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

TEST(QuicTransportParametersTest, RejectsMaxIdleTimeoutAboveVarintLimitDuringSerialization) {
    const TransportParameters parameters{
        .max_idle_timeout = (std::uint64_t{1} << 62),
        .max_udp_payload_size = 1200,
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
        .max_ack_delay = (std::uint64_t{1} << 62),
        .initial_source_connection_id = ConnectionId{std::byte{0x01}},
    };

    const auto encoded = coquic::quic::serialize_transport_parameters(parameters);

    ASSERT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, CodecErrorCode::invalid_varint);
}

TEST(QuicTransportParametersTest,
     RejectsFlowControlAndStreamCountValuesAboveVarintLimitDuringSerialization) {
    const auto make_parameters = [] {
        return TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0x01}},
        };
    };

    auto bidi_local = make_parameters();
    bidi_local.initial_max_stream_data_bidi_local = (std::uint64_t{1} << 62);
    const auto encoded_bidi_local = coquic::quic::serialize_transport_parameters(bidi_local);
    ASSERT_FALSE(encoded_bidi_local.has_value());
    EXPECT_EQ(encoded_bidi_local.error().code, CodecErrorCode::invalid_varint);

    auto bidi_remote = make_parameters();
    bidi_remote.initial_max_stream_data_bidi_remote = (std::uint64_t{1} << 62);
    const auto encoded_bidi_remote = coquic::quic::serialize_transport_parameters(bidi_remote);
    ASSERT_FALSE(encoded_bidi_remote.has_value());
    EXPECT_EQ(encoded_bidi_remote.error().code, CodecErrorCode::invalid_varint);

    auto streams_bidi = make_parameters();
    streams_bidi.initial_max_streams_bidi = (std::uint64_t{1} << 62);
    const auto encoded_streams_bidi = coquic::quic::serialize_transport_parameters(streams_bidi);
    ASSERT_FALSE(encoded_streams_bidi.has_value());
    EXPECT_EQ(encoded_streams_bidi.error().code, CodecErrorCode::invalid_varint);

    auto streams_uni = make_parameters();
    streams_uni.initial_max_streams_uni = (std::uint64_t{1} << 62);
    const auto encoded_streams_uni = coquic::quic::serialize_transport_parameters(streams_uni);
    ASSERT_FALSE(encoded_streams_uni.has_value());
    EXPECT_EQ(encoded_streams_uni.error().code, CodecErrorCode::invalid_varint);
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

TEST(QuicTransportParametersTest, RejectsInvalidMaxIdleTimeoutEncoding) {
    const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
        0x01,
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

TEST(QuicTransportParametersTest, RejectsInvalidFlowControlAndStreamCountEncodings) {
    for (const auto parameter_id : {0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0x09u}) {
        const auto decoded = coquic::quic::deserialize_transport_parameters(byte_vector({
            parameter_id,
            0x02,
            0x01,
            0x00,
        }));

        ASSERT_FALSE(decoded.has_value());
        EXPECT_EQ(decoded.error().code, CodecErrorCode::invalid_varint);
    }
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

TEST(QuicTransportParametersTest, ServerAcceptsMissingPeerVersionInformation) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::client,
        TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
        },
        make_validation_context(ConnectionId{std::byte{0xaa}}, std::nullopt, std::nullopt,
                                VersionInformation{
                                    .chosen_version = 0x00000001u,
                                    .available_versions = {0x00000001u, 0x6b3343cfu},
                                }));

    ASSERT_TRUE(validation.has_value());
}

TEST(QuicTransportParametersTest, ClientRejectsMissingExpectedVersionInformation) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
        },
        make_validation_context(ConnectionId{std::byte{0xaa}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}, std::nullopt,
                                VersionInformation{
                                    .chosen_version = 0x6b3343cfu,
                                    .available_versions = {0x6b3343cfu, 0x00000001u},
                                }));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ClientRejectsMismatchedExpectedVersionInformation) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .version_information =
                VersionInformation{
                    .chosen_version = 0x00000001u,
                    .available_versions = {0x00000001u},
                },
        },
        make_validation_context(ConnectionId{std::byte{0xaa}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}, std::nullopt,
                                VersionInformation{
                                    .chosen_version = 0x6b3343cfu,
                                    .available_versions = {0x6b3343cfu, 0x00000001u},
                                }));

    ASSERT_FALSE(validation.has_value());
    EXPECT_EQ(validation.error().code, CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTransportParametersTest, ClientAcceptsExpectedVersionInformation) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .version_information =
                VersionInformation{
                    .chosen_version = 0x6b3343cfu,
                    .available_versions = {0x6b3343cfu, 0x00000001u},
                },
        },
        make_validation_context(ConnectionId{std::byte{0xaa}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}, std::nullopt,
                                VersionInformation{
                                    .chosen_version = 0x6b3343cfu,
                                    .available_versions = {0x6b3343cfu, 0x00000001u},
                                }));

    ASSERT_TRUE(validation.has_value());
}

TEST(QuicTransportParametersTest, ClientAcceptsPeerVersionInformationWithAdditionalVersions) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .version_information =
                VersionInformation{
                    .chosen_version = 0x6b3343cfu,
                    .available_versions = {0x00000001u, 0x6b3343cfu, 0x709a50c4u, 0xff000022u},
                },
        },
        make_validation_context(ConnectionId{std::byte{0xaa}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}, std::nullopt,
                                VersionInformation{
                                    .chosen_version = 0x6b3343cfu,
                                    .available_versions = {0x6b3343cfu, 0x00000001u},
                                }));

    ASSERT_TRUE(validation.has_value());
}

TEST(QuicTransportParametersTest,
     ServerRejectsPeerVersionInformationThatWouldSelectDifferentVersionAfterVersionNegotiation) {
    const auto validation = coquic::quic::validate_peer_transport_parameters(
        EndpointRole::server,
        TransportParameters{
            .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x94}},
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 2,
            .initial_source_connection_id = ConnectionId{std::byte{0xaa}},
            .version_information =
                VersionInformation{
                    .chosen_version = 0x00000001u,
                    .available_versions = {0x00000001u, 0x6b3343cfu},
                },
        },
        make_validation_context(ConnectionId{std::byte{0xaa}},
                                ConnectionId{std::byte{0x83}, std::byte{0x94}}, std::nullopt,
                                VersionInformation{
                                    .chosen_version = 0x00000001u,
                                    .available_versions = {0x6b3343cfu, 0x00000001u},
                                },
                                /*reacted_to_version_negotiation=*/true));

    ASSERT_FALSE(validation.has_value());
}

} // namespace
