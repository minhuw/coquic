#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "src/quic/packet.h"
#include "src/quic/protected_codec.h"

namespace coquic::quic {

struct VersionInformation {
    std::uint32_t chosen_version = 0;
    std::vector<std::uint32_t> available_versions;

    bool operator==(const VersionInformation &) const = default;
};

struct PreferredAddress {
    std::array<std::byte, 4> ipv4_address{};
    std::uint16_t ipv4_port = 0;
    std::array<std::byte, 16> ipv6_address{};
    std::uint16_t ipv6_port = 0;
    ConnectionId connection_id;
    std::array<std::byte, 16> stateless_reset_token{};

    bool operator==(const PreferredAddress &) const = default;
};

struct TransportParameters {
    std::optional<ConnectionId> original_destination_connection_id;
    std::uint64_t max_idle_timeout = 0;
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t active_connection_id_limit = 2;
    bool disable_active_migration = false;
    std::uint64_t ack_delay_exponent = 3;
    std::uint64_t max_ack_delay = 25;
    std::uint64_t initial_max_data = 0;
    std::uint64_t initial_max_stream_data_bidi_local = 0;
    std::uint64_t initial_max_stream_data_bidi_remote = 0;
    std::uint64_t initial_max_stream_data_uni = 0;
    std::uint64_t initial_max_streams_bidi = 0;
    std::uint64_t initial_max_streams_uni = 0;
    std::optional<ConnectionId> initial_source_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
    std::optional<PreferredAddress> preferred_address;
    std::optional<VersionInformation> version_information;
};

struct TransportParametersValidationContext {
    ConnectionId expected_initial_source_connection_id;
    std::optional<ConnectionId> expected_original_destination_connection_id;
    std::optional<ConnectionId> expected_retry_source_connection_id;
    std::optional<VersionInformation> expected_version_information;
    bool reacted_to_version_negotiation = false;
};

struct TransportParametersValidationOk {};

CodecResult<std::vector<std::byte>>
serialize_transport_parameters(const TransportParameters &parameters);

CodecResult<TransportParameters> deserialize_transport_parameters(std::span<const std::byte> bytes);

CodecResult<TransportParametersValidationOk>
validate_peer_transport_parameters(EndpointRole peer_role, const TransportParameters &parameters,
                                   const TransportParametersValidationContext &context);

} // namespace coquic::quic
