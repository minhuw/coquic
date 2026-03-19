#include "src/quic/transport_parameters.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "src/quic/varint.h"

namespace {

using coquic::quic::CodecErrorCode;
using coquic::quic::CodecResult;
using coquic::quic::ConnectionId;
using coquic::quic::EndpointRole;
using coquic::quic::TransportParameters;
using coquic::quic::TransportParametersValidationContext;
using coquic::quic::TransportParametersValidationOk;

constexpr std::uint64_t original_destination_connection_id_parameter_id = 0x00;
constexpr std::uint64_t max_udp_payload_size_parameter_id = 0x03;
constexpr std::uint64_t active_connection_id_limit_parameter_id = 0x0e;
constexpr std::uint64_t initial_source_connection_id_parameter_id = 0x0f;
constexpr std::uint64_t retry_source_connection_id_parameter_id = 0x10;
constexpr std::uint64_t ack_delay_exponent_parameter_id = 0x0a;
constexpr std::uint64_t max_ack_delay_parameter_id = 0x0b;
constexpr std::uint64_t minimum_max_udp_payload_size = 1200;
constexpr std::uint64_t minimum_active_connection_id_limit = 2;
constexpr std::uint64_t maximum_ack_delay_exponent = 20;
constexpr std::uint64_t maximum_max_ack_delay = (std::uint64_t{1} << 14);

void append_parameter_header(std::vector<std::byte> &output, std::uint64_t id, std::size_t length) {
    const auto encoded_id = coquic::quic::encode_varint(id).value();
    const auto encoded_length = coquic::quic::encode_varint(length).value();

    output.insert(output.end(), encoded_id.begin(), encoded_id.end());
    output.insert(output.end(), encoded_length.begin(), encoded_length.end());
}

void append_raw_parameter(std::vector<std::byte> &output, std::uint64_t parameter_id,
                          std::span<const std::byte> value_bytes) {
    append_parameter_header(output, parameter_id, value_bytes.size());
    output.insert(output.end(), value_bytes.begin(), value_bytes.end());
}

void append_connection_id_parameter(std::vector<std::byte> &output, std::uint64_t id,
                                    const std::optional<ConnectionId> &connection_id) {
    if (!connection_id.has_value()) {
        return;
    }

    append_raw_parameter(output, id, *connection_id);
}

CodecResult<std::uint64_t> decode_integer_parameter(std::span<const std::byte> bytes) {
    const auto decoded = coquic::quic::decode_varint_bytes(bytes);
    if (!decoded.has_value()) {
        return CodecResult<std::uint64_t>::failure(decoded.error().code, decoded.error().offset);
    }
    if (decoded.value().bytes_consumed != bytes.size()) {
        return CodecResult<std::uint64_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

CodecResult<TransportParametersValidationOk> validation_failure() {
    return CodecResult<TransportParametersValidationOk>::failure(
        CodecErrorCode::invalid_packet_protection_state, 0);
}

} // namespace

namespace coquic::quic {

CodecResult<std::vector<std::byte>>
serialize_transport_parameters(const TransportParameters &parameters) {
    std::vector<std::byte> output;

    append_connection_id_parameter(output, original_destination_connection_id_parameter_id,
                                   parameters.original_destination_connection_id);

    auto encoded_max_udp_payload_size = encode_varint(parameters.max_udp_payload_size);
    if (!encoded_max_udp_payload_size.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_max_udp_payload_size.error().code, encoded_max_udp_payload_size.error().offset);
    }

    append_raw_parameter(output, max_udp_payload_size_parameter_id,
                         encoded_max_udp_payload_size.value());

    auto encoded_active_connection_id_limit = encode_varint(parameters.active_connection_id_limit);
    if (!encoded_active_connection_id_limit.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_active_connection_id_limit.error().code,
            encoded_active_connection_id_limit.error().offset);
    }

    append_raw_parameter(output, active_connection_id_limit_parameter_id,
                         encoded_active_connection_id_limit.value());

    auto encoded_ack_delay_exponent = encode_varint(parameters.ack_delay_exponent);
    if (!encoded_ack_delay_exponent.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_ack_delay_exponent.error().code, encoded_ack_delay_exponent.error().offset);
    }

    append_raw_parameter(output, ack_delay_exponent_parameter_id,
                         encoded_ack_delay_exponent.value());

    auto encoded_max_ack_delay = encode_varint(parameters.max_ack_delay);
    if (!encoded_max_ack_delay.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(encoded_max_ack_delay.error().code,
                                                            encoded_max_ack_delay.error().offset);
    }

    append_raw_parameter(output, max_ack_delay_parameter_id, encoded_max_ack_delay.value());

    append_connection_id_parameter(output, initial_source_connection_id_parameter_id,
                                   parameters.initial_source_connection_id);

    append_connection_id_parameter(output, retry_source_connection_id_parameter_id,
                                   parameters.retry_source_connection_id);

    return CodecResult<std::vector<std::byte>>::success(std::move(output));
}

CodecResult<TransportParameters>
deserialize_transport_parameters(std::span<const std::byte> bytes) {
    TransportParameters parameters;
    std::size_t offset = 0;

    while (offset < bytes.size()) {
        const auto id = decode_varint_bytes(bytes.subspan(offset));
        if (!id.has_value()) {
            return CodecResult<TransportParameters>::failure(id.error().code, offset);
        }
        offset += id.value().bytes_consumed;

        const auto length = decode_varint_bytes(bytes.subspan(offset));
        if (!length.has_value()) {
            return CodecResult<TransportParameters>::failure(length.error().code, offset);
        }
        offset += length.value().bytes_consumed;

        if (length.value().value > bytes.size() - offset) {
            return CodecResult<TransportParameters>::failure(CodecErrorCode::truncated_input,
                                                             offset);
        }

        const auto value = bytes.subspan(offset, static_cast<std::size_t>(length.value().value));
        offset += value.size();

        switch (id.value().value) {
        case original_destination_connection_id_parameter_id:
            parameters.original_destination_connection_id =
                ConnectionId(value.begin(), value.end());
            break;
        case max_udp_payload_size_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.max_udp_payload_size = decoded.value();
            break;
        }
        case active_connection_id_limit_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.active_connection_id_limit = decoded.value();
            break;
        }
        case initial_source_connection_id_parameter_id:
            parameters.initial_source_connection_id = ConnectionId(value.begin(), value.end());
            break;
        case retry_source_connection_id_parameter_id:
            parameters.retry_source_connection_id = ConnectionId(value.begin(), value.end());
            break;
        case ack_delay_exponent_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.ack_delay_exponent = decoded.value();
            break;
        }
        case max_ack_delay_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.max_ack_delay = decoded.value();
            break;
        }
        default:
            break;
        }
    }

    return CodecResult<TransportParameters>::success(std::move(parameters));
}

CodecResult<TransportParametersValidationOk>
validate_peer_transport_parameters(EndpointRole peer_role, const TransportParameters &parameters,
                                   const TransportParametersValidationContext &context) {
    if (!parameters.initial_source_connection_id.has_value()) {
        return validation_failure();
    }
    if (parameters.initial_source_connection_id.value() !=
        context.expected_initial_source_connection_id) {
        return validation_failure();
    }
    if (parameters.max_udp_payload_size < minimum_max_udp_payload_size) {
        return validation_failure();
    }
    if (parameters.active_connection_id_limit < minimum_active_connection_id_limit) {
        return validation_failure();
    }
    if (parameters.ack_delay_exponent > maximum_ack_delay_exponent) {
        return validation_failure();
    }
    if (parameters.max_ack_delay >= maximum_max_ack_delay) {
        return validation_failure();
    }

    if (peer_role == EndpointRole::client) {
        if (parameters.original_destination_connection_id.has_value() ||
            parameters.retry_source_connection_id.has_value()) {
            return validation_failure();
        }

        return CodecResult<TransportParametersValidationOk>::success({});
    }

    if (!parameters.original_destination_connection_id.has_value() ||
        !context.expected_original_destination_connection_id.has_value() ||
        parameters.original_destination_connection_id.value() !=
            context.expected_original_destination_connection_id.value()) {
        return validation_failure();
    }

    if (context.expected_retry_source_connection_id.has_value()) {
        if (!parameters.retry_source_connection_id.has_value() ||
            parameters.retry_source_connection_id.value() !=
                context.expected_retry_source_connection_id.value()) {
            return validation_failure();
        }
    } else if (parameters.retry_source_connection_id.has_value()) {
        return validation_failure();
    }

    return CodecResult<TransportParametersValidationOk>::success({});
}

} // namespace coquic::quic
