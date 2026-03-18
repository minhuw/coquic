#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "src/quic/packet.h"
#include "src/quic/protected_codec.h"

namespace coquic::quic {

struct TransportParameters {
    std::optional<ConnectionId> original_destination_connection_id;
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t active_connection_id_limit = 2;
    std::optional<ConnectionId> initial_source_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
};

struct TransportParametersValidationContext {
    ConnectionId expected_initial_source_connection_id;
    std::optional<ConnectionId> expected_original_destination_connection_id;
    std::optional<ConnectionId> expected_retry_source_connection_id;
};

struct TransportParametersValidationOk {};

CodecResult<std::vector<std::byte>>
serialize_transport_parameters(const TransportParameters &parameters);

CodecResult<TransportParameters> deserialize_transport_parameters(std::span<const std::byte> bytes);

CodecResult<TransportParametersValidationOk>
validate_peer_transport_parameters(EndpointRole peer_role, const TransportParameters &parameters,
                                   const TransportParametersValidationContext &context);

} // namespace coquic::quic
