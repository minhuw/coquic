#include "src/quic/transport_parameters.h"

#include <algorithm>
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
using coquic::quic::VersionInformation;

constexpr std::uint64_t original_destination_connection_id_parameter_id = 0x00;
constexpr std::uint64_t max_idle_timeout_parameter_id = 0x01;
constexpr std::uint64_t max_udp_payload_size_parameter_id = 0x03;
constexpr std::uint64_t initial_max_data_parameter_id = 0x04;
constexpr std::uint64_t initial_max_stream_data_bidi_local_parameter_id = 0x05;
constexpr std::uint64_t initial_max_stream_data_bidi_remote_parameter_id = 0x06;
constexpr std::uint64_t initial_max_stream_data_uni_parameter_id = 0x07;
constexpr std::uint64_t initial_max_streams_bidi_parameter_id = 0x08;
constexpr std::uint64_t initial_max_streams_uni_parameter_id = 0x09;
constexpr std::uint64_t ack_delay_exponent_parameter_id = 0x0a;
constexpr std::uint64_t max_ack_delay_parameter_id = 0x0b;
constexpr std::uint64_t active_connection_id_limit_parameter_id = 0x0e;
constexpr std::uint64_t initial_source_connection_id_parameter_id = 0x0f;
constexpr std::uint64_t retry_source_connection_id_parameter_id = 0x10;
constexpr std::uint64_t version_information_parameter_id = 0x11;
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

void append_u32_be(std::vector<std::byte> &output, std::uint32_t value) {
    output.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    output.push_back(static_cast<std::byte>(value & 0xffu));
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }

    return value;
}

void append_version_information_parameter(std::vector<std::byte> &output,
                                          const std::optional<VersionInformation> &value) {
    if (!value.has_value()) {
        return;
    }

    std::vector<std::byte> encoded;
    encoded.reserve((1 + value->available_versions.size()) * sizeof(std::uint32_t));
    append_u32_be(encoded, value->chosen_version);
    for (const auto version : value->available_versions) {
        append_u32_be(encoded, version);
    }
    append_raw_parameter(output, version_information_parameter_id, encoded);
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

bool contains_version(std::span<const std::uint32_t> versions, std::uint32_t version) {
    return std::find(versions.begin(), versions.end(), version) != versions.end();
}

std::uint32_t select_preferred_version(std::span<const std::uint32_t> preferred_versions,
                                       const VersionInformation &version_information) {
    // The caller has already verified that chosen_version is present in preferred_versions.
    const auto selected = std::find_if(
        preferred_versions.begin(), preferred_versions.end(), [&](std::uint32_t preferred_version) {
            return preferred_version == version_information.chosen_version ||
                   contains_version(version_information.available_versions, preferred_version);
        });
    return *selected;
}

} // namespace

namespace coquic::quic {

CodecResult<std::vector<std::byte>>
serialize_transport_parameters(const TransportParameters &parameters) {
    std::vector<std::byte> output;

    append_connection_id_parameter(output, original_destination_connection_id_parameter_id,
                                   parameters.original_destination_connection_id);

    auto encoded_max_idle_timeout = encode_varint(parameters.max_idle_timeout);
    if (!encoded_max_idle_timeout.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_max_idle_timeout.error().code, encoded_max_idle_timeout.error().offset);
    }

    append_raw_parameter(output, max_idle_timeout_parameter_id, encoded_max_idle_timeout.value());

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

    auto encoded_initial_max_data = encode_varint(parameters.initial_max_data);
    if (!encoded_initial_max_data.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_initial_max_data.error().code, encoded_initial_max_data.error().offset);
    }

    append_raw_parameter(output, initial_max_data_parameter_id, encoded_initial_max_data.value());

    auto encoded_initial_max_stream_data_bidi_local =
        encode_varint(parameters.initial_max_stream_data_bidi_local);
    if (!encoded_initial_max_stream_data_bidi_local.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_initial_max_stream_data_bidi_local.error().code,
            encoded_initial_max_stream_data_bidi_local.error().offset);
    }

    append_raw_parameter(output, initial_max_stream_data_bidi_local_parameter_id,
                         encoded_initial_max_stream_data_bidi_local.value());

    auto encoded_initial_max_stream_data_bidi_remote =
        encode_varint(parameters.initial_max_stream_data_bidi_remote);
    if (!encoded_initial_max_stream_data_bidi_remote.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_initial_max_stream_data_bidi_remote.error().code,
            encoded_initial_max_stream_data_bidi_remote.error().offset);
    }

    append_raw_parameter(output, initial_max_stream_data_bidi_remote_parameter_id,
                         encoded_initial_max_stream_data_bidi_remote.value());

    auto encoded_initial_max_stream_data_uni =
        encode_varint(parameters.initial_max_stream_data_uni);
    if (!encoded_initial_max_stream_data_uni.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_initial_max_stream_data_uni.error().code,
            encoded_initial_max_stream_data_uni.error().offset);
    }

    append_raw_parameter(output, initial_max_stream_data_uni_parameter_id,
                         encoded_initial_max_stream_data_uni.value());

    auto encoded_initial_max_streams_bidi = encode_varint(parameters.initial_max_streams_bidi);
    if (!encoded_initial_max_streams_bidi.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_initial_max_streams_bidi.error().code,
            encoded_initial_max_streams_bidi.error().offset);
    }

    append_raw_parameter(output, initial_max_streams_bidi_parameter_id,
                         encoded_initial_max_streams_bidi.value());

    auto encoded_initial_max_streams_uni = encode_varint(parameters.initial_max_streams_uni);
    if (!encoded_initial_max_streams_uni.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(
            encoded_initial_max_streams_uni.error().code,
            encoded_initial_max_streams_uni.error().offset);
    }

    append_raw_parameter(output, initial_max_streams_uni_parameter_id,
                         encoded_initial_max_streams_uni.value());

    append_connection_id_parameter(output, initial_source_connection_id_parameter_id,
                                   parameters.initial_source_connection_id);

    append_connection_id_parameter(output, retry_source_connection_id_parameter_id,
                                   parameters.retry_source_connection_id);
    append_version_information_parameter(output, parameters.version_information);

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
        case max_idle_timeout_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.max_idle_timeout = decoded.value();
            break;
        }
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
        case initial_max_data_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.initial_max_data = decoded.value();
            break;
        }
        case initial_max_stream_data_bidi_local_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.initial_max_stream_data_bidi_local = decoded.value();
            break;
        }
        case initial_max_stream_data_bidi_remote_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.initial_max_stream_data_bidi_remote = decoded.value();
            break;
        }
        case initial_max_stream_data_uni_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.initial_max_stream_data_uni = decoded.value();
            break;
        }
        case initial_max_streams_bidi_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.initial_max_streams_bidi = decoded.value();
            break;
        }
        case initial_max_streams_uni_parameter_id: {
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.initial_max_streams_uni = decoded.value();
            break;
        }
        case initial_source_connection_id_parameter_id:
            parameters.initial_source_connection_id = ConnectionId(value.begin(), value.end());
            break;
        case retry_source_connection_id_parameter_id:
            parameters.retry_source_connection_id = ConnectionId(value.begin(), value.end());
            break;
        case version_information_parameter_id: {
            if (value.size() < sizeof(std::uint32_t) ||
                (value.size() % sizeof(std::uint32_t)) != 0) {
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }

            VersionInformation version_information{
                .chosen_version = read_u32_be(value.first(sizeof(std::uint32_t))),
            };
            for (std::size_t version_offset = sizeof(std::uint32_t); version_offset < value.size();
                 version_offset += sizeof(std::uint32_t)) {
                version_information.available_versions.push_back(
                    read_u32_be(value.subspan(version_offset, sizeof(std::uint32_t))));
            }
            parameters.version_information = std::move(version_information);
            break;
        }
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

        if (context.expected_version_information.has_value() &&
            parameters.version_information.has_value()) {
            // RFC 9368 allows servers to complete the handshake even if the
            // client's Version Information is missing. If the client does send
            // it, it still needs to be internally consistent and match the
            // negotiated version context we established locally.
            if (parameters.version_information->chosen_version !=
                    context.expected_version_information->chosen_version ||
                !contains_version(parameters.version_information->available_versions,
                                  parameters.version_information->chosen_version)) {
                return validation_failure();
            }
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

    if (context.expected_version_information.has_value()) {
        if (!parameters.version_information.has_value() ||
            parameters.version_information->chosen_version !=
                context.expected_version_information->chosen_version ||
            !contains_version(context.expected_version_information->available_versions,
                              parameters.version_information->chosen_version)) {
            return validation_failure();
        }

        if (context.reacted_to_version_negotiation) {
            if (parameters.version_information->available_versions.empty()) {
                return validation_failure();
            }

            const auto selected_version =
                select_preferred_version(context.expected_version_information->available_versions,
                                         parameters.version_information.value());
            if (selected_version != parameters.version_information->chosen_version) {
                return validation_failure();
            }
        }
    }

    return CodecResult<TransportParametersValidationOk>::success({});
}

} // namespace coquic::quic
