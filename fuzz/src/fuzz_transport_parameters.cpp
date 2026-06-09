#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/transport/transport_parameters.h"

namespace {

coquic::quic::ConnectionId make_connection_id(const std::vector<std::byte> &bytes,
                                              std::size_t offset) {
    coquic::quic::ConnectionId id;
    if (bytes.empty()) {
        id.push_back(std::byte{0xc1});
        return id;
    }
    const auto start = std::min(offset, bytes.size() - 1);
    const auto count = std::min<std::size_t>(8, bytes.size() - start);
    id.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        id.push_back(bytes[start + i]);
    }
    return id;
}

coquic::quic::TransportParametersValidationContext
make_validation_context(const std::vector<std::byte> &bytes) {
    return coquic::quic::TransportParametersValidationContext{
        .expected_initial_source_connection_id = make_connection_id(bytes, 0),
        .expected_original_destination_connection_id = make_connection_id(bytes, 3),
        .expected_retry_source_connection_id = make_connection_id(bytes, 5),
        .expected_version_information =
            coquic::quic::VersionInformation{
                .chosen_version = 0x00000001u,
                .available_versions = {0x00000001u, 0x6b3343cfu},
            },
        .reacted_to_version_negotiation =
            !bytes.empty() && (std::to_integer<unsigned>(bytes.front()) & 1u) != 0,
    };
}

void validate_if_decoded(coquic::quic::EndpointRole role,
                         const coquic::quic::TransportParameters &parameters,
                         const coquic::quic::TransportParametersValidationContext &context) {
    const auto validation =
        coquic::quic::validate_peer_transport_parameters(role, parameters, context);
    if (!validation.has_value()) {
        coquic::fuzz::require(validation.error().offset == 0,
                              "transport parameter validation returned nonzero offset");
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    constexpr std::size_t kMaxTransportParameterInputSize = 4096;
    if (size > kMaxTransportParameterInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    const auto decoded =
        coquic::quic::deserialize_transport_parameters(coquic::fuzz::byte_span(bytes));
    if (!decoded.has_value()) {
        coquic::fuzz::require_error_offset(decoded.error(), bytes.size());
        return 0;
    }

    const auto encoded = coquic::quic::serialize_transport_parameters(decoded.value());
    if (!encoded.has_value()) {
        coquic::fuzz::fail("decoded transport parameters failed to serialize");
        return 0;
    }

    const auto redecode = coquic::quic::deserialize_transport_parameters(encoded.value());
    coquic::fuzz::require(redecode.has_value(),
                          "serialized decoded transport parameters are invalid");

    const auto context = make_validation_context(bytes);
    validate_if_decoded(coquic::quic::EndpointRole::client, decoded.value(), context);
    validate_if_decoded(coquic::quic::EndpointRole::server, decoded.value(), context);

    return 0;
}
