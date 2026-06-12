#include "src/quic/transport/transport_parameters.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <vector>

#include "src/quic/codec/varint.h"

namespace coquic::quic {

bool contains_version(std::span<const std::uint32_t> versions, std::uint32_t version);
std::uint32_t select_preferred_version(std::span<const std::uint32_t> preferred_versions,
                                       const VersionInformation &version_information);

} // namespace coquic::quic

namespace {

using coquic::quic::CodecError;
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
constexpr std::uint64_t stateless_reset_token_parameter_id = 0x02;
constexpr std::uint64_t max_udp_payload_size_parameter_id = 0x03;
constexpr std::uint64_t initial_max_data_parameter_id = 0x04;
constexpr std::uint64_t initial_max_stream_data_bidi_local_parameter_id = 0x05;
constexpr std::uint64_t initial_max_stream_data_bidi_remote_parameter_id = 0x06;
constexpr std::uint64_t initial_max_stream_data_uni_parameter_id = 0x07;
constexpr std::uint64_t initial_max_streams_bidi_parameter_id = 0x08;
constexpr std::uint64_t initial_max_streams_uni_parameter_id = 0x09;
constexpr std::uint64_t ack_delay_exponent_parameter_id = 0x0a;
constexpr std::uint64_t max_ack_delay_parameter_id = 0x0b;
constexpr std::uint64_t disable_active_migration_parameter_id = 0x0c;
constexpr std::uint64_t preferred_address_parameter_id = 0x0d;
constexpr std::uint64_t active_connection_id_limit_parameter_id = 0x0e;
constexpr std::uint64_t initial_source_connection_id_parameter_id = 0x0f;
constexpr std::uint64_t retry_source_connection_id_parameter_id = 0x10;
constexpr std::uint64_t version_information_parameter_id = 0x11;
constexpr std::uint64_t max_datagram_frame_size_parameter_id = 0x20;
constexpr std::uint64_t grease_quic_bit_parameter_id = 0x2ab2;
constexpr std::uint64_t minimum_max_udp_payload_size = 1200;
constexpr std::uint64_t minimum_active_connection_id_limit = 2;
constexpr std::uint64_t maximum_ack_delay_exponent = 20;
constexpr std::uint64_t maximum_max_ack_delay = (std::uint64_t{1} << 14);
constexpr std::uint64_t maximum_stream_limit = std::uint64_t{1} << 60;
constexpr std::size_t maximum_connection_id_length = 20;
constexpr std::size_t stateless_reset_token_length = 16;

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

void append_stateless_reset_token_parameter(
    std::vector<std::byte> &output,
    const std::optional<std::array<std::byte, stateless_reset_token_length>> &token) {
    if (!token.has_value()) {
        return;
    }

    append_raw_parameter(output, stateless_reset_token_parameter_id, *token);
}

void append_u32_be(std::vector<std::byte> &output, std::uint32_t value) {
    output.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    output.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    output.push_back(static_cast<std::byte>(value & 0xffu));
}

void append_u16_be(std::vector<std::byte> &output, std::uint16_t value) {
    output.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    output.push_back(static_cast<std::byte>(value & 0xffu));
}

void append_preferred_address_parameter(
    std::vector<std::byte> &output, const std::optional<coquic::quic::PreferredAddress> &value) {
    if (!value.has_value()) {
        return;
    }

    std::vector<std::byte> encoded;
    encoded.reserve(4 + 2 + 16 + 2 + 1 + value->connection_id.size() + 16);
    encoded.insert(encoded.end(), value->ipv4_address.begin(), value->ipv4_address.end());
    append_u16_be(encoded, value->ipv4_port);
    encoded.insert(encoded.end(), value->ipv6_address.begin(), value->ipv6_address.end());
    append_u16_be(encoded, value->ipv6_port);
    encoded.push_back(static_cast<std::byte>(value->connection_id.size()));
    encoded.insert(encoded.end(), value->connection_id.begin(), value->connection_id.end());
    encoded.insert(encoded.end(), value->stateless_reset_token.begin(),
                   value->stateless_reset_token.end());
    append_raw_parameter(output, preferred_address_parameter_id, encoded);
}

void append_version_information_parameter(std::vector<std::byte> &output,
                                          const std::optional<VersionInformation> &value) {
    if (!value.has_value()) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9368#section-3
    // # Version Information {
    // #   Chosen Version (32),
    // #   Available Versions (32) ...,
    // # }
    std::vector<std::byte> encoded;
    encoded.reserve((1 + value->available_versions.size()) * sizeof(std::uint32_t));
    append_u32_be(encoded, value->chosen_version);
    for (const auto version : value->available_versions) {
        append_u32_be(encoded, version);
    }
    append_raw_parameter(output, version_information_parameter_id, encoded);
}

CodecResult<TransportParametersValidationOk> validation_failure() {
    return CodecResult<TransportParametersValidationOk>::failure(
        CodecErrorCode::invalid_packet_protection_state, 0);
}

CodecResult<TransportParametersValidationOk> version_negotiation_validation_failure() {
    return CodecResult<TransportParametersValidationOk>::failure(CodecError{
        .code = CodecErrorCode::invalid_packet_protection_state,
        .offset = 0,
        //= https://www.rfc-editor.org/rfc/rfc9368#section-4
        // # Every QUIC version that supports version negotiation MUST define a
        // # method for closing the connection with a version negotiation error.
        .transport_error_code = 0x11u,
        .has_transport_error_code = true,
    });
}

bool has_zero_version_information_value(const VersionInformation &version_information) {
    return version_information.chosen_version == 0 ||
           coquic::quic::contains_version(version_information.available_versions, 0);
}

} // namespace

namespace coquic::quic {

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

CodecResult<std::uint64_t> decode_integer_parameter(std::span<const std::byte> bytes) {
    const auto decoded = decode_varint_bytes(bytes);
    if (!decoded.has_value()) {
        return CodecResult<std::uint64_t>::failure(decoded.error().code, decoded.error().offset);
    }
    if (decoded.value().bytes_consumed != bytes.size()) {
        return CodecResult<std::uint64_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

CodecResult<std::vector<std::byte>>
serialize_transport_parameters(const TransportParameters &parameters) {
    std::vector<std::byte> output;

    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4
    // # An endpoint MUST NOT send a parameter more than once in a given
    // # transport parameters extension.
    // Connection identifiers and reset tokens are emitted before scalar transport limits.
    append_connection_id_parameter(output, original_destination_connection_id_parameter_id,
                                   parameters.original_destination_connection_id);
    append_stateless_reset_token_parameter(output, parameters.stateless_reset_token);

    // Core idle, datagram-size, CID-limit, and ACK parameters are encoded as QUIC varints.
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

    // Flow-control windows and stream-count limits are serialized as separate parameters.
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

    if (parameters.disable_active_migration) {
        append_parameter_header(output, disable_active_migration_parameter_id, 0);
    }

    append_connection_id_parameter(output, initial_source_connection_id_parameter_id,
                                   parameters.initial_source_connection_id);

    append_connection_id_parameter(output, retry_source_connection_id_parameter_id,
                                   parameters.retry_source_connection_id);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # Similarly, a server MUST NOT include a zero-
    // # length connection ID in this transport parameter.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # A client MUST
    // # treat a violation of these requirements as a connection error of
    // # type TRANSPORT_PARAMETER_ERROR.
    if (parameters.preferred_address.has_value() &&
        (parameters.preferred_address->connection_id.empty() ||
         parameters.preferred_address->connection_id.size() > maximum_connection_id_length)) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }
    // Migration, preferred-address, version, datagram, and grease extensions are optional tails.
    append_preferred_address_parameter(output, parameters.preferred_address);
    append_version_information_parameter(output, parameters.version_information);
    if (parameters.max_datagram_frame_size > 0) {
        auto encoded_max_datagram_frame_size = encode_varint(parameters.max_datagram_frame_size);
        if (!encoded_max_datagram_frame_size.has_value()) {
            return CodecResult<std::vector<std::byte>>::failure(
                encoded_max_datagram_frame_size.error().code,
                encoded_max_datagram_frame_size.error().offset);
        }
        append_raw_parameter(output, max_datagram_frame_size_parameter_id,
                             encoded_max_datagram_frame_size.value());
    }
    if (parameters.grease_quic_bit) {
        append_parameter_header(output, grease_quic_bit_parameter_id, 0);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(output));
}

CodecResult<TransportParameters>
deserialize_transport_parameters(std::span<const std::byte> bytes) {
    TransportParameters parameters;
    std::set<std::uint64_t> seen_parameter_ids;
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

        //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4
        // # An endpoint SHOULD treat receipt of
        // # duplicate transport parameters as a connection error of type
        // # TRANSPORT_PARAMETER_ERROR.
        if (!seen_parameter_ids.insert(id.value().value).second) {
            return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                             offset);
        }

        switch (id.value().value) {
        case original_destination_connection_id_parameter_id:
            parameters.original_destination_connection_id =
                ConnectionId(value.begin(), value.end());
            break;
        case stateless_reset_token_parameter_id:
            if (value.size() != stateless_reset_token_length) {
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }
            parameters.stateless_reset_token.emplace();
            std::copy_n(value.begin(), parameters.stateless_reset_token->size(),
                        parameters.stateless_reset_token->begin());
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
        case disable_active_migration_parameter_id:
            if (!value.empty()) {
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }
            parameters.disable_active_migration = true;
            break;
        case preferred_address_parameter_id: {
            constexpr std::size_t fixed_prefix_length = 4 + 2 + 16 + 2 + 1;
            constexpr std::size_t token_length = 16;
            if (value.size() < fixed_prefix_length + token_length) {
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }

            const auto connection_id_length = std::to_integer<std::uint8_t>(value[24]);
            //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
            // # Similarly, a server MUST NOT include a zero-
            // # length connection ID in this transport parameter.
            //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
            // # A client MUST
            // # treat a violation of these requirements as a connection error of
            // # type TRANSPORT_PARAMETER_ERROR.
            if (connection_id_length == 0 || connection_id_length > maximum_connection_id_length) {
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }
            if (value.size() != fixed_prefix_length + connection_id_length + token_length) {
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }

            PreferredAddress preferred_address;
            std::copy_n(value.begin(), preferred_address.ipv4_address.size(),
                        preferred_address.ipv4_address.begin());
            preferred_address.ipv4_port =
                static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(value[4]) << 8) |
                                           std::to_integer<std::uint8_t>(value[5]));
            std::copy_n(value.begin() + 6, preferred_address.ipv6_address.size(),
                        preferred_address.ipv6_address.begin());
            preferred_address.ipv6_port =
                static_cast<std::uint16_t>((std::to_integer<std::uint8_t>(value[22]) << 8) |
                                           std::to_integer<std::uint8_t>(value[23]));
            preferred_address.connection_id.assign(value.begin() + 25,
                                                   value.begin() + 25 + connection_id_length);
            std::copy_n(value.begin() + 25 + connection_id_length,
                        preferred_address.stateless_reset_token.size(),
                        preferred_address.stateless_reset_token.begin());
            parameters.preferred_address = std::move(preferred_address);
            break;
        }
        case version_information_parameter_id: {
            //= https://www.rfc-editor.org/rfc/rfc9368#section-4
            // # Both endpoints MUST parse their peer's Version Information during the
            // # handshake.
            //= https://www.rfc-editor.org/rfc/rfc9368#section-3
            // # Version Information {
            // #   Chosen Version (32),
            // #   Available Versions (32) ...,
            // # }
            if (value.size() < sizeof(std::uint32_t) ||
                (value.size() % sizeof(std::uint32_t)) != 0) {
                //= https://www.rfc-editor.org/rfc/rfc9368#section-4
                // # If that leads to a parsing failure (for example, if it is
                // # too short or if its length is not divisible by four), then the
                // # endpoint MUST close the connection; if the connection was using QUIC
                // # version 1, that connection closure MUST use a transport error of type
                // # TRANSPORT_PARAMETER_ERROR.
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }

            VersionInformation version_information{
                .chosen_version =
                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value[0])) << 24) |
                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value[1])) << 16) |
                    (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value[2])) << 8) |
                    static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(value[3])),
            };
            if (version_information.chosen_version == 0) {
                //= https://www.rfc-editor.org/rfc/rfc9368#section-4
                // # If an endpoint receives a Chosen Version
                // # equal to zero, or any Available Version equal to zero, it MUST treat
                // # it as a parsing failure.
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }
            for (std::size_t version_offset = sizeof(std::uint32_t); version_offset < value.size();
                 version_offset += sizeof(std::uint32_t)) {
                const auto available_version =
                    (static_cast<std::uint32_t>(
                         std::to_integer<std::uint8_t>(value[version_offset]))
                     << 24) |
                    (static_cast<std::uint32_t>(
                         std::to_integer<std::uint8_t>(value[version_offset + 1]))
                     << 16) |
                    (static_cast<std::uint32_t>(
                         std::to_integer<std::uint8_t>(value[version_offset + 2]))
                     << 8) |
                    static_cast<std::uint32_t>(
                        std::to_integer<std::uint8_t>(value[version_offset + 3]));
                if (available_version == 0) {
                    //= https://www.rfc-editor.org/rfc/rfc9368#section-4
                    // # If an endpoint receives a Chosen Version
                    // # equal to zero, or any Available Version equal to zero, it MUST treat
                    // # it as a parsing failure.
                    return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                     offset);
                }
                version_information.available_versions.push_back(available_version);
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
        case max_datagram_frame_size_parameter_id: {
            //= https://www.rfc-editor.org/rfc/rfc9221#section-3
            // # The max_datagram_frame_size transport parameter is an
            // # integer value (represented as a variable-length integer) that
            // # represents the maximum size of a DATAGRAM frame (including the
            // # frame type, length, and payload) the endpoint is willing to
            // # receive, in bytes.
            const auto decoded = decode_integer_parameter(value);
            if (!decoded.has_value()) {
                return CodecResult<TransportParameters>::failure(decoded.error().code, offset);
            }
            parameters.max_datagram_frame_size = decoded.value();
            break;
        }
        case grease_quic_bit_parameter_id:
            //= https://www.rfc-editor.org/rfc/rfc9287#section-3
            // # The transport parameter is sent with an empty
            // # value; an endpoint that understands this transport parameter MUST
            // # treat receipt of a non-empty value of the transport parameter as a
            // # connection error of type TRANSPORT_PARAMETER_ERROR.
            if (!value.empty()) {
                return CodecResult<TransportParameters>::failure(CodecErrorCode::invalid_varint,
                                                                 offset);
            }
            parameters.grease_quic_bit = true;
            break;
        default:
            //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4.2
            // # An endpoint MUST ignore transport parameters that it does
            // # not support.
            break;
        }
    }

    return CodecResult<TransportParameters>::success(std::move(parameters));
}

CodecResult<TransportParametersValidationOk>
validate_peer_transport_parameters(EndpointRole peer_role, const TransportParameters &parameters,
                                   const TransportParametersValidationContext &context) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.3
    // # An endpoint MUST treat the absence of the
    // # initial_source_connection_id transport parameter from either endpoint
    // # or the absence of the original_destination_connection_id transport
    // # parameter from the server as a connection error of type
    // # TRANSPORT_PARAMETER_ERROR.
    if (!parameters.initial_source_connection_id.has_value()) {
        return validation_failure();
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.3
    // # The values provided by a peer for these transport parameters MUST
    // # match the values that an endpoint used in the Destination and Source
    // # Connection ID fields of Initial packets that it sent (and received,
    // # for servers).
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.3
    // # Endpoints MUST validate that received transport
    // # parameters match received connection ID values.
    if (parameters.initial_source_connection_id.value() !=
        context.expected_initial_source_connection_id) {
        return validation_failure();
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4
    // # An endpoint MUST treat receipt of a transport parameter with an
    // # invalid value as a connection error of type
    // # TRANSPORT_PARAMETER_ERROR.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # Values below 1200 are invalid.
    if (parameters.max_udp_payload_size < minimum_max_udp_payload_size) {
        return validation_failure();
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # The value of the
    // # active_connection_id_limit parameter MUST be at least 2.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # An
    // # endpoint that receives a value less than 2 MUST close the
    // # connection with an error of type TRANSPORT_PARAMETER_ERROR.
    if (parameters.active_connection_id_limit < minimum_active_connection_id_limit) {
        return validation_failure();
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4
    // # An endpoint MUST treat receipt of a transport parameter with an
    // # invalid value as a connection error of type
    // # TRANSPORT_PARAMETER_ERROR.
    if (parameters.ack_delay_exponent > maximum_ack_delay_exponent) {
        return validation_failure();
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.4
    // # An endpoint MUST treat receipt of a transport parameter with an
    // # invalid value as a connection error of type
    // # TRANSPORT_PARAMETER_ERROR.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # Values of 2^14 or greater are invalid.
    if (parameters.max_ack_delay >= maximum_max_ack_delay) {
        return validation_failure();
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # If either is received, the connection MUST be closed immediately with
    // # a connection error of type TRANSPORT_PARAMETER_ERROR if the offending
    // # value was received in a transport parameter or of type
    // # FRAME_ENCODING_ERROR if it was received in a frame; see Section 10.2.
    if (parameters.initial_max_streams_bidi > maximum_stream_limit ||
        parameters.initial_max_streams_uni > maximum_stream_limit) {
        return validation_failure();
    }

    if (peer_role == EndpointRole::client) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
        // # This transport parameter MUST NOT be sent
        // # by a client but MAY be sent by a server.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
        // # A client MUST NOT include any server-only transport parameter:
        // # original_destination_connection_id, preferred_address,
        // # retry_source_connection_id, or stateless_reset_token.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
        // # A server MUST
        // # treat receipt of any of these transport parameters as a connection
        // # error of type TRANSPORT_PARAMETER_ERROR.
        if (parameters.original_destination_connection_id.has_value() ||
            parameters.retry_source_connection_id.has_value() ||
            parameters.preferred_address.has_value() ||
            parameters.stateless_reset_token.has_value()) {
            return validation_failure();
        }

        if (parameters.version_information.has_value() &&
            has_zero_version_information_value(parameters.version_information.value())) {
            //= https://www.rfc-editor.org/rfc/rfc9368#section-4
            // # Both endpoints MUST parse their peer's Version Information during the
            // # handshake.
            //= https://www.rfc-editor.org/rfc/rfc9368#section-4
            // # If an endpoint receives a Chosen Version
            // # equal to zero, or any Available Version equal to zero, it MUST treat
            // # it as a parsing failure.
            return version_negotiation_validation_failure();
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
                //= https://www.rfc-editor.org/rfc/rfc9368#section-4
                // # If a server receives Version Information
                // # where the Chosen Version is not included in Available Versions, it
                // # MUST treat it as a parsing failure.
                //= https://www.rfc-editor.org/rfc/rfc9368#section-4
                // # Subsequently,
                // # if the server receives the client's Version Information over QUIC
                // # version 1 (as indicated by the Version field of the Long Header
                // # packets that carried the transport parameters) and the client's
                // # Chosen Version is not set to 0x00000001, the server MUST close the
                // # connection with a version negotiation error.
                //= https://www.rfc-editor.org/rfc/rfc9368#section-4
                // # If the two
                // # differ, the server MUST close the connection with a version
                // # negotiation error.
                return version_negotiation_validation_failure();
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9368#section-4
        // # Servers MAY complete the handshake even if the Version Information is
        // # missing.
        return CodecResult<TransportParametersValidationOk>::success({});
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.3
    // # An endpoint MUST treat the absence of the
    // # initial_source_connection_id transport parameter from either endpoint
    // # or the absence of the original_destination_connection_id transport
    // # parameter from the server as a connection error of type
    // # TRANSPORT_PARAMETER_ERROR.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.3
    // # The values provided by a peer for these transport parameters MUST
    // # match the values that an endpoint used in the Destination and Source
    // # Connection ID fields of Initial packets that it sent (and received,
    // # for servers).
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.3
    // # Endpoints MUST validate that received transport
    // # parameters match received connection ID values.
    if (!parameters.original_destination_connection_id.has_value() ||
        !context.expected_original_destination_connection_id.has_value() ||
        parameters.original_destination_connection_id.value() !=
            context.expected_original_destination_connection_id.value()) {
        return validation_failure();
    }

    if (context.expected_retry_source_connection_id.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-7.3
        // # An endpoint MUST treat the following as a connection error of type
        // # TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION:
        if (!parameters.retry_source_connection_id.has_value() ||
            parameters.retry_source_connection_id.value() !=
                context.expected_retry_source_connection_id.value()) {
            return validation_failure();
        }
    } else if (parameters.retry_source_connection_id.has_value()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-7.3
        // # An endpoint MUST treat the following as a connection error of type
        // # TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION:
        return validation_failure();
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # A server
    // # that chooses a zero-length connection ID MUST NOT provide a
    // # preferred address.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # A client MUST
    // # treat a violation of these requirements as a connection error of
    // # type TRANSPORT_PARAMETER_ERROR.
    if (parameters.preferred_address.has_value() &&
        parameters.preferred_address->connection_id.empty()) {
        return validation_failure();
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # A server
    // # that chooses a zero-length connection ID MUST NOT provide a
    // # preferred address.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # A client MUST
    // # treat a violation of these requirements as a connection error of
    // # type TRANSPORT_PARAMETER_ERROR.
    if (parameters.preferred_address.has_value() &&
        parameters.initial_source_connection_id->empty()) {
        return validation_failure();
    }

    if (context.expected_version_information.has_value()) {
        if (parameters.version_information.has_value() &&
            has_zero_version_information_value(parameters.version_information.value())) {
            //= https://www.rfc-editor.org/rfc/rfc9368#section-4
            // # If an endpoint receives a Chosen Version
            // # equal to zero, or any Available Version equal to zero, it MUST treat
            // # it as a parsing failure.
            return version_negotiation_validation_failure();
        }

        if (!parameters.version_information.has_value() ||
            parameters.version_information->chosen_version !=
                context.expected_version_information->chosen_version ||
            !contains_version(context.expected_version_information->available_versions,
                              parameters.version_information->chosen_version)) {
            //= https://www.rfc-editor.org/rfc/rfc9368#section-4
            // # Clients MUST NOT complete the handshake if they are
            // # reacting to a Version Negotiation packet and the Version Information
            // # is missing, but MAY do so otherwise.
            //= https://www.rfc-editor.org/rfc/rfc9368#section-4
            // # If a client receives Version Information where the server's Chosen
            // # Version was not sent by the client as part of its Available Versions,
            // # the client MUST close the connection with a version negotiation
            // # error.
            return version_negotiation_validation_failure();
        }

        if (context.reacted_to_version_negotiation) {
            //= https://www.rfc-editor.org/rfc/rfc9368#section-4
            // # If the client received and acted on a Version Negotiation packet, the
            // # client MUST validate the server's Available Versions field.
            if (parameters.version_information->available_versions.empty()) {
                //= https://www.rfc-editor.org/rfc/rfc9368#section-4
                // # In particular, if the client reacted to a Version
                // # Negotiation packet and the server's Available Versions field is
                // # empty, the client MUST close the connection with a version
                // # negotiation error.
                return version_negotiation_validation_failure();
            }

            const auto selected_version =
                select_preferred_version(context.expected_version_information->available_versions,
                                         parameters.version_information.value());
            if (selected_version != parameters.version_information->chosen_version) {
                //= https://www.rfc-editor.org/rfc/rfc9368#section-4
                // # If the client would have selected a different
                // # version, the client MUST close the connection with a version
                // # negotiation error.
                return version_negotiation_validation_failure();
            }
        }
    }

    return CodecResult<TransportParametersValidationOk>::success({});
}

} // namespace coquic::quic
