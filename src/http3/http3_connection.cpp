#include "src/http3/http3_connection.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

#include "src/quic/streams.h"
#include "src/quic/varint.h"

namespace coquic::http3 {

using quic::classify_stream_id;
using quic::CodecErrorCode;
using quic::decode_varint_bytes;
using quic::StreamDirection;
using quic::StreamInitiator;

namespace {

enum class BufferedInstructionStatus : std::uint8_t {
    complete,
    incomplete,
    invalid,
};

struct BufferedInstructionProgress {
    BufferedInstructionStatus status = BufferedInstructionStatus::incomplete;
    std::size_t bytes_consumed = 0;
};

BufferedInstructionProgress parse_prefixed_integer_progress(std::span<const std::byte> bytes,
                                                            std::uint8_t prefix_bits) {
    if (bytes.empty()) {
        return {};
    }

    const auto first = std::to_integer<std::uint8_t>(bytes.front());
    const auto max_in_prefix = (static_cast<std::uint64_t>(1) << prefix_bits) - 1u;
    std::uint64_t value = first & static_cast<std::uint8_t>(max_in_prefix);
    std::size_t bytes_consumed = 1;
    if (value < max_in_prefix) {
        return {
            .status = BufferedInstructionStatus::complete,
            .bytes_consumed = bytes_consumed,
        };
    }

    std::uint64_t shift = 0;
    while (true) {
        if (bytes_consumed >= bytes.size()) {
            return {};
        }

        const auto byte = std::to_integer<std::uint8_t>(bytes[bytes_consumed++]);
        const auto chunk = static_cast<std::uint64_t>(byte & 0x7fu);
        if (shift >= 63 || chunk > ((std::numeric_limits<std::uint64_t>::max() - value) >> shift)) {
            return {
                .status = BufferedInstructionStatus::invalid,
            };
        }

        value += chunk << shift;
        if ((byte & 0x80u) == 0u) {
            return {
                .status = BufferedInstructionStatus::complete,
                .bytes_consumed = bytes_consumed,
            };
        }

        shift += 7;
    }
}

BufferedInstructionProgress parse_string_literal_progress(std::span<const std::byte> bytes,
                                                          std::uint8_t prefix_bits) {
    const auto length = parse_prefixed_integer_progress(bytes, prefix_bits);
    if (length.status != BufferedInstructionStatus::complete) {
        return length;
    }

    if (bytes.size() < length.bytes_consumed) {
        return {};
    }

    const auto length_bytes = bytes.subspan(0, length.bytes_consumed);
    const auto max_in_prefix = (static_cast<std::uint64_t>(1) << prefix_bits) - 1u;
    std::uint64_t value = std::to_integer<std::uint8_t>(length_bytes.front()) &
                          static_cast<std::uint8_t>(max_in_prefix);
    if (value == max_in_prefix) {
        std::uint64_t shift = 0;
        for (std::size_t index = 1; index < length.bytes_consumed; ++index) {
            const auto byte = std::to_integer<std::uint8_t>(length_bytes[index]);
            value += static_cast<std::uint64_t>(byte & 0x7fu) << shift;
            shift += 7;
        }
    }

    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return {
            .status = BufferedInstructionStatus::invalid,
        };
    }

    const auto payload_size = static_cast<std::size_t>(value);
    if (bytes.size() - length.bytes_consumed < payload_size) {
        return {};
    }

    return {
        .status = BufferedInstructionStatus::complete,
        .bytes_consumed = length.bytes_consumed + payload_size,
    };
}

BufferedInstructionProgress
complete_qpack_encoder_instruction_size(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return {};
    }

    const auto first = std::to_integer<std::uint8_t>(bytes.front());
    if ((first & 0xe0u) == 0x20u) {
        return parse_prefixed_integer_progress(bytes, 5);
    }

    if ((first & 0x80u) == 0x80u) {
        const auto name_reference = parse_prefixed_integer_progress(bytes, 6);
        if (name_reference.status != BufferedInstructionStatus::complete) {
            return name_reference;
        }

        if (bytes.size() <= name_reference.bytes_consumed) {
            return {};
        }

        const auto value =
            parse_string_literal_progress(bytes.subspan(name_reference.bytes_consumed), 7);
        if (value.status != BufferedInstructionStatus::complete) {
            return value;
        }

        return {
            .status = BufferedInstructionStatus::complete,
            .bytes_consumed = name_reference.bytes_consumed + value.bytes_consumed,
        };
    }

    if ((first & 0x40u) == 0x40u) {
        const auto name = parse_string_literal_progress(bytes, 5);
        if (name.status != BufferedInstructionStatus::complete) {
            return name;
        }

        if (bytes.size() <= name.bytes_consumed) {
            return {};
        }

        const auto value = parse_string_literal_progress(bytes.subspan(name.bytes_consumed), 7);
        if (value.status != BufferedInstructionStatus::complete) {
            return value;
        }

        return {
            .status = BufferedInstructionStatus::complete,
            .bytes_consumed = name.bytes_consumed + value.bytes_consumed,
        };
    }

    if ((first & 0xe0u) == 0x00u) {
        return parse_prefixed_integer_progress(bytes, 5);
    }

    return {
        .status = BufferedInstructionStatus::invalid,
    };
}

BufferedInstructionProgress
complete_qpack_decoder_instruction_size(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return {};
    }

    const auto first = std::to_integer<std::uint8_t>(bytes.front());
    if ((first & 0x80u) == 0x80u) {
        return parse_prefixed_integer_progress(bytes, 7);
    }

    return parse_prefixed_integer_progress(bytes, 6);
}

std::optional<std::size_t>
complete_qpack_field_section_prefix_size(std::span<const std::byte> bytes) {
    const auto required_insert_count = parse_prefixed_integer_progress(bytes, 8);
    if (required_insert_count.status == BufferedInstructionStatus::incomplete) {
        return std::nullopt;
    }
    if (required_insert_count.status == BufferedInstructionStatus::invalid) {
        return 0;
    }

    const auto delta_base =
        parse_prefixed_integer_progress(bytes.subspan(required_insert_count.bytes_consumed), 7);
    if (delta_base.status == BufferedInstructionStatus::incomplete) {
        return std::nullopt;
    }
    if (delta_base.status == BufferedInstructionStatus::invalid) {
        return 0;
    }

    return required_insert_count.bytes_consumed + delta_base.bytes_consumed;
}

quic::EndpointRole endpoint_role(Http3ConnectionRole role) {
    return role == Http3ConnectionRole::client ? quic::EndpointRole::client
                                               : quic::EndpointRole::server;
}

Http3QpackSettings qpack_settings_from_snapshot(const Http3SettingsSnapshot &settings) {
    return Http3QpackSettings{
        .max_table_capacity = settings.qpack_max_table_capacity,
        .blocked_streams = settings.qpack_blocked_streams,
    };
}

template <typename T>
Http3Result<T> local_http3_failure(Http3ErrorCode code, std::string detail,
                                   std::optional<std::uint64_t> stream_id = std::nullopt) {
    return Http3Result<T>::failure(Http3Error{
        .code = code,
        .detail = std::move(detail),
        .stream_id = stream_id,
    });
}

bool is_informational_response(std::uint16_t status) {
    return status >= 100u && status < 200u;
}

std::vector<Http3Field> response_fields_from_head(const Http3ResponseHead &head) {
    std::vector<Http3Field> fields;
    fields.reserve(head.headers.size() + 2u);
    fields.push_back(Http3Field{
        .name = ":status",
        .value = std::to_string(head.status),
    });
    if (head.content_length.has_value()) {
        fields.push_back(Http3Field{
            .name = "content-length",
            .value = std::to_string(*head.content_length),
        });
    }
    fields.insert(fields.end(), head.headers.begin(), head.headers.end());
    return fields;
}

std::vector<Http3Field> request_fields_from_head(const Http3RequestHead &head) {
    std::vector<Http3Field> fields;
    fields.reserve(head.headers.size() + 5u);
    fields.push_back(Http3Field{
        .name = ":method",
        .value = head.method,
    });
    fields.push_back(Http3Field{
        .name = ":scheme",
        .value = head.scheme,
    });
    fields.push_back(Http3Field{
        .name = ":authority",
        .value = head.authority,
    });
    fields.push_back(Http3Field{
        .name = ":path",
        .value = head.path,
    });
    if (head.content_length.has_value()) {
        fields.push_back(Http3Field{
            .name = "content-length",
            .value = std::to_string(*head.content_length),
        });
    }
    fields.insert(fields.end(), head.headers.begin(), head.headers.end());
    return fields;
}

std::vector<Http3Setting> settings_from_snapshot(const Http3SettingsSnapshot &settings) {
    std::vector<Http3Setting> values = {
        Http3Setting{
            .id = kHttp3SettingsQpackMaxTableCapacity,
            .value = settings.qpack_max_table_capacity,
        },
    };
    if (settings.max_field_section_size.has_value()) {
        values.push_back(Http3Setting{
            .id = kHttp3SettingsMaxFieldSectionSize,
            .value = *settings.max_field_section_size,
        });
    }
    values.push_back(Http3Setting{
        .id = kHttp3SettingsQpackBlockedStreams,
        .value = settings.qpack_blocked_streams,
    });
    return values;
}

std::optional<std::size_t> complete_http3_frame_size(std::span<const std::byte> bytes) {
    const auto type = decode_varint_bytes(bytes);
    if (!type.has_value()) {
        if (type.error().code == CodecErrorCode::truncated_input) {
            return std::nullopt;
        }
        return 0;
    }

    const auto after_type = bytes.subspan(type.value().bytes_consumed);
    const auto length = decode_varint_bytes(after_type);
    if (!length.has_value()) {
        if (length.error().code == CodecErrorCode::truncated_input) {
            return std::nullopt;
        }
        return 0;
    }

    const auto header_size = type.value().bytes_consumed + length.value().bytes_consumed;
    if (length.value().value > bytes.size() - header_size) {
        return std::nullopt;
    }
    return header_size + static_cast<std::size_t>(length.value().value);
}

} // namespace

Http3Connection::Http3Connection(Http3ConnectionConfig config)
    : config_(config),
      peer_settings_{
          .qpack_max_table_capacity = 0,
          .qpack_blocked_streams = 0,
          .max_field_section_size = std::nullopt,
      },
      encoder_{}, decoder_{} {
    encoder_.peer_settings = qpack_settings_from_snapshot(peer_settings_);
    decoder_.local_settings = qpack_settings_from_snapshot(config_.local_settings);
}

Http3EndpointUpdate Http3Connection::on_core_result(const quic::QuicCoreResult &result,
                                                    quic::QuicCoreTimePoint now) {
    (void)now;

    if (closed_) {
        return drain_pending_inputs(/*terminal_failure=*/true);
    }

    if (result.local_error.has_value()) {
        closed_ = true;
        return drain_pending_inputs(/*terminal_failure=*/true);
    }

    for (const auto &effect : result.effects) {
        if (const auto *state = std::get_if<quic::QuicCoreStateEvent>(&effect)) {
            if (state->change == quic::QuicCoreStateChange::handshake_ready ||
                state->change == quic::QuicCoreStateChange::handshake_confirmed) {
                transport_ready_ = true;
            } else if (state->change == quic::QuicCoreStateChange::failed) {
                closed_ = true;
            }
            continue;
        }

        if (const auto *received = std::get_if<quic::QuicCoreReceiveStreamData>(&effect)) {
            handle_receive_stream_data(*received);
            continue;
        }

        if (const auto *reset = std::get_if<quic::QuicCorePeerResetStream>(&effect)) {
            handle_peer_reset_stream(*reset);
            continue;
        }

        if (const auto *stop = std::get_if<quic::QuicCorePeerStopSending>(&effect)) {
            handle_peer_stop_sending(*stop);
            continue;
        }
    }

    if (transport_ready_) {
        queue_startup_streams();
    }
    flush_qpack_decoder_instructions();
    return drain_pending_inputs(closed_);
}

Http3EndpointUpdate Http3Connection::poll(quic::QuicCoreTimePoint now) {
    (void)now;
    if (transport_ready_) {
        queue_startup_streams();
    }
    flush_qpack_decoder_instructions();
    return drain_pending_inputs(closed_);
}

Http3Result<bool> Http3Connection::submit_request_head(std::uint64_t stream_id,
                                                       const Http3RequestHead &head) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::client) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "request sending requires client role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto info = classify_stream_id(stream_id, endpoint_role(config_.role));
    if (info.initiator != StreamInitiator::local ||
        info.direction != StreamDirection::bidirectional) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream id is not a local bidirectional stream",
                                         stream_id);
    }

    auto &request = local_request_streams_[stream_id];
    if (request.final_request_headers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request headers already sent", stream_id);
    }
    if (request.request_finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream already finished", stream_id);
    }

    auto fields = request_fields_from_head(head);
    const auto validated = validate_http3_request_headers(fields);
    if (!validated.has_value()) {
        return Http3Result<bool>::failure(validated.error());
    }

    const auto encoded = encode_http3_field_section(encoder_, stream_id, fields);
    if (!encoded.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to encode request headers", stream_id);
    }

    if (!encoded.value().encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.value().encoder_instructions);
    }

    auto field_section = encoded.value().prefix;
    field_section.insert(field_section.end(), encoded.value().payload.begin(),
                         encoded.value().payload.end());
    const auto frame = serialize_http3_frame(Http3Frame{
        Http3HeadersFrame{
            .field_section = std::move(field_section),
        },
    });
    if (!frame.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to serialize request headers", stream_id);
    }

    queue_send(stream_id, frame.value());
    request.head_request = head.method == "HEAD";
    request.final_request_headers_sent = true;
    request.expected_request_content_length = head.content_length;
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_request_body(std::uint64_t stream_id,
                                                       std::span<const std::byte> body, bool fin) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::client) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "request sending requires client role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto request_it = local_request_streams_.find(stream_id);
    if (request_it == local_request_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream is not available", stream_id);
    }

    auto &request = request_it->second;
    if (!request.final_request_headers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request body before request headers", stream_id);
    }
    if (request.request_trailers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request trailers already sent", stream_id);
    }
    if (request.request_finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream already finished", stream_id);
    }

    if (body.size() > std::numeric_limits<std::uint64_t>::max() - request.request_body_bytes_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "request body exceeds content-length", stream_id);
    }

    const auto new_total =
        request.request_body_bytes_sent + static_cast<std::uint64_t>(body.size());
    if (request.expected_request_content_length.has_value() &&
        new_total > *request.expected_request_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "request body exceeds content-length", stream_id);
    }
    if (fin && request.expected_request_content_length.has_value() &&
        new_total != *request.expected_request_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "request body does not match content-length", stream_id);
    }

    const auto frame = serialize_http3_frame(Http3Frame{
        Http3DataFrame{
            .payload = std::vector<std::byte>(body.begin(), body.end()),
        },
    });
    if (!frame.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to serialize request body", stream_id);
    }

    queue_send(stream_id, frame.value(), fin);
    request.request_body_bytes_sent = new_total;
    request.request_finished = fin;
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_request_trailers(std::uint64_t stream_id,
                                                           std::span<const Http3Field> trailers,
                                                           bool fin) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::client) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "request sending requires client role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto request_it = local_request_streams_.find(stream_id);
    if (request_it == local_request_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream is not available", stream_id);
    }

    auto &request = request_it->second;
    if (!request.final_request_headers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request trailers before request headers", stream_id);
    }
    if (request.request_trailers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request trailers already sent", stream_id);
    }
    if (request.request_finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream already finished", stream_id);
    }
    if (request.expected_request_content_length.has_value() &&
        request.request_body_bytes_sent != *request.expected_request_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "request body does not match content-length", stream_id);
    }

    const auto validated = validate_http3_trailers(trailers);
    if (!validated.has_value()) {
        return Http3Result<bool>::failure(validated.error());
    }

    const auto encoded = encode_http3_field_section(encoder_, stream_id, validated.value());
    if (!encoded.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to encode request trailers", stream_id);
    }

    if (!encoded.value().encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.value().encoder_instructions);
    }

    auto field_section = encoded.value().prefix;
    field_section.insert(field_section.end(), encoded.value().payload.begin(),
                         encoded.value().payload.end());
    const auto frame = serialize_http3_frame(Http3Frame{
        Http3HeadersFrame{
            .field_section = std::move(field_section),
        },
    });
    if (!frame.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to serialize request trailers", stream_id);
    }

    queue_send(stream_id, frame.value(), fin);
    request.request_trailers_sent = true;
    request.request_finished = fin;
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::finish_request(std::uint64_t stream_id) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::client) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "request sending requires client role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto request_it = local_request_streams_.find(stream_id);
    if (request_it == local_request_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream is not available", stream_id);
    }

    auto &request = request_it->second;
    if (!request.final_request_headers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "final request headers not sent", stream_id);
    }
    if (request.request_finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream already finished", stream_id);
    }
    if (request.expected_request_content_length.has_value() &&
        request.request_body_bytes_sent != *request.expected_request_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "request body does not match content-length", stream_id);
    }

    request.request_finished = true;
    queue_send(stream_id, std::span<const std::byte>{}, true);
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_response_head(std::uint64_t stream_id,
                                                        const Http3ResponseHead &head) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "response sending requires server role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto response_it = local_response_streams_.find(stream_id);
    if (response_it == local_response_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response stream is not available", stream_id);
    }

    auto &response = response_it->second;
    if (response.finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response stream already finished", stream_id);
    }
    if (response.trailers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response trailers already sent", stream_id);
    }

    const bool informational = is_informational_response(head.status);
    if (response.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "final response already sent", stream_id);
    }

    auto fields = response_fields_from_head(head);
    const auto validated = validate_http3_response_headers(fields);
    if (!validated.has_value()) {
        return Http3Result<bool>::failure(validated.error());
    }

    const auto encoded = encode_http3_field_section(encoder_, stream_id, fields);
    if (!encoded.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to encode response headers", stream_id);
    }

    if (!encoded.value().encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.value().encoder_instructions);
    }

    auto field_section = encoded.value().prefix;
    field_section.insert(field_section.end(), encoded.value().payload.begin(),
                         encoded.value().payload.end());
    const auto frame = serialize_http3_frame(Http3Frame{
        Http3HeadersFrame{
            .field_section = std::move(field_section),
        },
    });
    if (!frame.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to serialize response headers", stream_id);
    }

    queue_send(stream_id, frame.value());
    if (!informational) {
        response.final_response_started = true;
        response.expected_content_length = head.content_length;
    }

    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_response_body(std::uint64_t stream_id,
                                                        std::span<const std::byte> body, bool fin) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "response sending requires server role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto response_it = local_response_streams_.find(stream_id);
    if (response_it == local_response_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response stream is not available", stream_id);
    }

    auto &response = response_it->second;
    if (response.finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response stream already finished", stream_id);
    }
    if (!response.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response body before final response headers", stream_id);
    }
    if (response.trailers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response trailers already sent", stream_id);
    }

    if (body.size() > std::numeric_limits<std::uint64_t>::max() - response.body_bytes_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "response body exceeds content-length", stream_id);
    }

    const auto new_total = response.body_bytes_sent + static_cast<std::uint64_t>(body.size());
    if (response.expected_content_length.has_value() &&
        new_total > *response.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "response body exceeds content-length", stream_id);
    }
    if (fin && response.expected_content_length.has_value() &&
        new_total != *response.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "response body does not match content-length", stream_id);
    }

    const auto frame = serialize_http3_frame(Http3Frame{
        Http3DataFrame{
            .payload = std::vector<std::byte>(body.begin(), body.end()),
        },
    });
    if (!frame.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to serialize response body", stream_id);
    }

    queue_send(stream_id, frame.value(), fin);
    response.body_bytes_sent = new_total;
    response.finished = fin;
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_response_trailers(std::uint64_t stream_id,
                                                            std::span<const Http3Field> trailers,
                                                            bool fin) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "response sending requires server role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto response_it = local_response_streams_.find(stream_id);
    if (response_it == local_response_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response stream is not available", stream_id);
    }

    auto &response = response_it->second;
    if (response.finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response stream already finished", stream_id);
    }
    if (!response.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response trailers before final response headers",
                                         stream_id);
    }
    if (response.trailers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response trailers already sent", stream_id);
    }
    if (response.expected_content_length.has_value() &&
        response.body_bytes_sent != *response.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "response body does not match content-length", stream_id);
    }

    const auto validated = validate_http3_trailers(trailers);
    if (!validated.has_value()) {
        return Http3Result<bool>::failure(validated.error());
    }

    const auto encoded = encode_http3_field_section(encoder_, stream_id, validated.value());
    if (!encoded.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to encode response trailers", stream_id);
    }

    if (!encoded.value().encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.value().encoder_instructions);
    }

    auto field_section = encoded.value().prefix;
    field_section.insert(field_section.end(), encoded.value().payload.begin(),
                         encoded.value().payload.end());
    const auto frame = serialize_http3_frame(Http3Frame{
        Http3HeadersFrame{
            .field_section = std::move(field_section),
        },
    });
    if (!frame.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::internal_error,
                                         "unable to serialize response trailers", stream_id);
    }

    queue_send(stream_id, frame.value(), fin);
    response.trailers_sent = true;
    response.finished = fin;
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::finish_response(std::uint64_t stream_id,
                                                   bool enforce_content_length) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "response sending requires server role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    const auto response_it = local_response_streams_.find(stream_id);
    if (response_it == local_response_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response stream is not available", stream_id);
    }

    auto &response = response_it->second;
    if (response.finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response stream already finished", stream_id);
    }
    if (!response.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "final response headers not sent", stream_id);
    }
    if (enforce_content_length && response.expected_content_length.has_value() &&
        response.body_bytes_sent != *response.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "response body does not match content-length", stream_id);
    }

    response.finished = true;
    queue_send(stream_id, std::span<const std::byte>{}, true);
    return Http3Result<bool>::success(true);
}

const Http3ConnectionState &Http3Connection::state() const {
    return state_;
}

const Http3SettingsSnapshot &Http3Connection::local_settings() const {
    return config_.local_settings;
}

const Http3SettingsSnapshot &Http3Connection::peer_settings() const {
    return peer_settings_;
}

bool Http3Connection::peer_settings_received() const {
    return state_.remote_settings_received;
}

bool Http3Connection::is_closed() const {
    return closed_;
}

Http3EndpointUpdate Http3Connection::drain_pending_inputs(bool terminal_failure) {
    Http3EndpointUpdate update{};
    while (!pending_core_inputs_.empty()) {
        update.core_inputs.push_back(std::move(pending_core_inputs_.front()));
        pending_core_inputs_.pop_front();
    }
    while (!pending_events_.empty()) {
        update.events.push_back(std::move(pending_events_.front()));
        pending_events_.pop_front();
    }
    update.has_pending_work = !update.core_inputs.empty() || !update.events.empty();
    update.terminal_failure = terminal_failure;
    return update;
}

void Http3Connection::queue_startup_streams() {
    if (startup_streams_queued_ || closed_) {
        return;
    }

    const auto control_stream_id = next_local_uni_stream_id();
    const auto encoder_stream_id = control_stream_id + 4u;
    const auto decoder_stream_id = encoder_stream_id + 4u;

    const auto control_stream =
        serialize_http3_control_stream(settings_from_snapshot(config_.local_settings));
    if (!control_stream.has_value()) {
        queue_connection_close(Http3ErrorCode::internal_error,
                               "unable to serialize control stream");
        return;
    }

    const auto encoder_prefix =
        serialize_http3_uni_stream_prefix(Http3UniStreamType::qpack_encoder);
    if (!encoder_prefix.has_value()) {
        queue_connection_close(Http3ErrorCode::internal_error,
                               "unable to serialize qpack encoder stream type");
        return;
    }

    const auto decoder_prefix =
        serialize_http3_uni_stream_prefix(Http3UniStreamType::qpack_decoder);
    if (!decoder_prefix.has_value()) {
        queue_connection_close(Http3ErrorCode::internal_error,
                               "unable to serialize qpack decoder stream type");
        return;
    }

    state_.local_control_stream_id = control_stream_id;
    state_.local_qpack_encoder_stream_id = encoder_stream_id;
    state_.local_qpack_decoder_stream_id = decoder_stream_id;
    state_.local_settings_sent = true;

    queue_send(control_stream_id, control_stream.value());
    queue_send(encoder_stream_id, encoder_prefix.value());
    queue_send(decoder_stream_id, decoder_prefix.value());
    startup_streams_queued_ = true;
}

void Http3Connection::flush_qpack_decoder_instructions() {
    if (!state_.local_qpack_decoder_stream_id.has_value() || closed_) {
        return;
    }

    const auto instructions = take_http3_qpack_decoder_instructions(decoder_);
    if (!instructions.has_value()) {
        queue_connection_close(instructions.error().code, instructions.error().detail);
        return;
    }

    if (!instructions.value().empty()) {
        queue_send(*state_.local_qpack_decoder_stream_id, instructions.value());
    }
}

void Http3Connection::queue_connection_close(Http3ErrorCode code, std::string detail) {
    if (closed_) {
        return;
    }

    closed_ = true;
    pending_events_.clear();
    pending_core_inputs_.push_back(quic::QuicCoreCloseConnection{
        .application_error_code = static_cast<std::uint64_t>(code),
        .reason_phrase = std::move(detail),
    });
}

void Http3Connection::queue_stream_error(std::uint64_t stream_id, Http3ErrorCode code) {
    if (closed_) {
        return;
    }

    auto it = peer_request_streams_.find(stream_id);
    if (it != peer_request_streams_.end()) {
        if (it->second.terminal) {
            return;
        }

        if (it->second.blocked_field_section.has_value()) {
            const auto cancelled = cancel_http3_qpack_stream(decoder_, stream_id);
            if (!cancelled.has_value()) {
                queue_connection_close(cancelled.error().code, cancelled.error().detail);
                return;
            }
            it->second.blocked_field_section.reset();
            flush_qpack_decoder_instructions();
            if (closed_) {
                return;
            }
        }

        it->second.buffer.clear();
        peer_request_streams_.erase(it);
    }

    auto local_request = local_request_streams_.find(stream_id);
    if (local_request != local_request_streams_.end()) {
        if (local_request->second.blocked_field_section.has_value()) {
            const auto cancelled = cancel_http3_qpack_stream(decoder_, stream_id);
            if (!cancelled.has_value()) {
                queue_connection_close(cancelled.error().code, cancelled.error().detail);
                return;
            }
            local_request->second.blocked_field_section.reset();
            flush_qpack_decoder_instructions();
            if (closed_) {
                return;
            }
        }

        local_request_streams_.erase(local_request);
    }

    local_response_streams_.erase(stream_id);
    terminated_peer_request_streams_.insert(stream_id);
    pending_core_inputs_.push_back(quic::QuicCoreResetStream{
        .stream_id = stream_id,
        .application_error_code = static_cast<std::uint64_t>(code),
    });
    pending_core_inputs_.push_back(quic::QuicCoreStopSending{
        .stream_id = stream_id,
        .application_error_code = static_cast<std::uint64_t>(code),
    });
}

void Http3Connection::handle_receive_stream_data(const quic::QuicCoreReceiveStreamData &received) {
    const auto info = classify_stream_id(received.stream_id, endpoint_role(config_.role));
    if (info.initiator == StreamInitiator::peer &&
        info.direction == StreamDirection::unidirectional) {
        handle_peer_uni_stream_data(received.stream_id, received.bytes, received.fin);
        return;
    }

    if (config_.role == Http3ConnectionRole::client && info.initiator == StreamInitiator::local &&
        info.direction == StreamDirection::bidirectional) {
        const auto request = local_request_streams_.find(received.stream_id);
        if (request == local_request_streams_.end()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "response stream is not available");
            return;
        }

        request->second.buffer.insert(request->second.buffer.end(), received.bytes.begin(),
                                      received.bytes.end());
        request->second.fin_received = request->second.fin_received || received.fin;
        process_response_stream(received.stream_id);
        return;
    }

    if (info.initiator == StreamInitiator::peer &&
        info.direction == StreamDirection::bidirectional) {
        handle_peer_bidi_stream(received.stream_id, received.bytes, received.fin);
    }
}

void Http3Connection::handle_peer_reset_stream(const quic::QuicCorePeerResetStream &reset) {
    if (is_remote_critical_stream(reset.stream_id)) {
        queue_connection_close(Http3ErrorCode::closed_critical_stream,
                               "peer reset critical stream");
        return;
    }

    peer_uni_streams_.erase(reset.stream_id);
    terminated_peer_request_streams_.erase(reset.stream_id);
    local_response_streams_.erase(reset.stream_id);

    const auto local_request = local_request_streams_.find(reset.stream_id);
    if (local_request != local_request_streams_.end()) {
        if (local_request->second.blocked_field_section.has_value()) {
            const auto cancelled = cancel_http3_qpack_stream(decoder_, reset.stream_id);
            if (!cancelled.has_value()) {
                queue_connection_close(cancelled.error().code, cancelled.error().detail);
                return;
            }
            flush_qpack_decoder_instructions();
            if (closed_) {
                return;
            }
        }
        pending_events_.push_back(Http3PeerResponseResetEvent{
            .stream_id = reset.stream_id,
            .application_error_code = reset.application_error_code,
        });
        local_request_streams_.erase(local_request);
        return;
    }

    const auto request = peer_request_streams_.find(reset.stream_id);
    if (request == peer_request_streams_.end()) {
        return;
    }

    if (request->second.blocked_field_section.has_value()) {
        const auto cancelled = cancel_http3_qpack_stream(decoder_, reset.stream_id);
        if (!cancelled.has_value()) {
            queue_connection_close(cancelled.error().code, cancelled.error().detail);
            return;
        }
        flush_qpack_decoder_instructions();
        if (closed_) {
            return;
        }
    }
    pending_events_.push_back(Http3PeerRequestResetEvent{
        .stream_id = reset.stream_id,
        .application_error_code = reset.application_error_code,
    });
    peer_request_streams_.erase(request);
}

void Http3Connection::handle_peer_stop_sending(const quic::QuicCorePeerStopSending &stop) {
    if (is_local_critical_stream(stop.stream_id)) {
        queue_connection_close(Http3ErrorCode::closed_critical_stream,
                               "peer requested stop sending on critical stream");
        return;
    }

    const auto response = local_response_streams_.find(stop.stream_id);
    if (response == local_response_streams_.end()) {
        return;
    }

    pending_core_inputs_.push_back(quic::QuicCoreResetStream{
        .stream_id = stop.stream_id,
        .application_error_code = stop.application_error_code,
    });
    local_response_streams_.erase(response);
}

void Http3Connection::handle_peer_bidi_stream(std::uint64_t stream_id,
                                              std::span<const std::byte> bytes, bool fin) {
    if (config_.role == Http3ConnectionRole::client) {
        queue_connection_close(Http3ErrorCode::stream_creation_error,
                               "server-initiated bidirectional stream is not permitted");
        return;
    }

    if (terminated_peer_request_streams_.contains(stream_id)) {
        return;
    }

    auto &stream = peer_request_streams_[stream_id];
    if (stream.terminal) {
        return;
    }

    stream.buffer.insert(stream.buffer.end(), bytes.begin(), bytes.end());
    stream.fin_received = stream.fin_received || fin;
    process_request_stream(stream_id);
}

void Http3Connection::handle_peer_uni_stream_data(std::uint64_t stream_id,
                                                  std::span<const std::byte> bytes, bool fin) {
    auto &stream = peer_uni_streams_[stream_id];
    stream.buffer.insert(stream.buffer.end(), bytes.begin(), bytes.end());

    if (!stream.kind.has_value()) {
        const auto decoded = parse_http3_uni_stream_type(stream.buffer);
        if (!decoded.has_value()) {
            if (decoded.error().code == CodecErrorCode::truncated_input) {
                if (fin) {
                    peer_uni_streams_.erase(stream_id);
                }
                return;
            }
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "invalid unidirectional stream type");
            return;
        }

        register_peer_uni_stream(stream_id, decoded.value().value);
        if (closed_) {
            return;
        }

        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(decoded.value().bytes_consumed));
        if (stream.kind == PeerUniStreamKind::ignored) {
            stream.buffer.clear();
        }
    }

    if (stream.kind == PeerUniStreamKind::control) {
        process_control_stream(stream_id, stream);
    } else if (stream.kind == PeerUniStreamKind::qpack_encoder) {
        process_qpack_encoder_stream(stream_id, stream);
    } else if (stream.kind == PeerUniStreamKind::qpack_decoder) {
        process_qpack_decoder_stream(stream_id, stream);
    } else {
        stream.buffer.clear();
    }

    if (!fin || closed_) {
        return;
    }

    if (!stream.kind.has_value() || *stream.kind == PeerUniStreamKind::ignored) {
        peer_uni_streams_.erase(stream_id);
        return;
    }

    if (*stream.kind == PeerUniStreamKind::control && !state_.remote_settings_received) {
        queue_connection_close(Http3ErrorCode::missing_settings,
                               "peer control stream ended before settings");
        return;
    }

    queue_connection_close(Http3ErrorCode::closed_critical_stream, "peer closed critical stream");
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void Http3Connection::register_peer_uni_stream(std::uint64_t stream_id, std::uint64_t stream_type) {
    auto &stream = peer_uni_streams_.at(stream_id);

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::control)) {
        if (state_.remote_control_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "duplicate peer control stream");
            return;
        }
        state_.remote_control_stream_id = stream_id;
        stream.kind = PeerUniStreamKind::control;
        return;
    }

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::qpack_encoder)) {
        if (state_.remote_qpack_encoder_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "duplicate peer qpack encoder stream");
            return;
        }
        state_.remote_qpack_encoder_stream_id = stream_id;
        stream.kind = PeerUniStreamKind::qpack_encoder;
        return;
    }

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::qpack_decoder)) {
        if (state_.remote_qpack_decoder_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "duplicate peer qpack decoder stream");
            return;
        }
        state_.remote_qpack_decoder_stream_id = stream_id;
        stream.kind = PeerUniStreamKind::qpack_decoder;
        return;
    }

    stream.kind = PeerUniStreamKind::ignored;
}

void Http3Connection::process_control_stream(std::uint64_t stream_id, PeerUniStreamState &stream) {
    while (!stream.buffer.empty() && !closed_) {
        const auto frame_size = complete_http3_frame_size(stream.buffer);
        if (!frame_size.has_value()) {
            return;
        }
        if (*frame_size == 0) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame encoding");
            return;
        }

        const auto parsed =
            parse_http3_frame(std::span<const std::byte>(stream.buffer.data(), *frame_size));
        if (!parsed.has_value()) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame");
            return;
        }

        handle_control_frame(stream_id, parsed.value().frame);
        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(parsed.value().bytes_consumed));
    }
}

void Http3Connection::process_qpack_encoder_stream(std::uint64_t stream_id,
                                                   PeerUniStreamState &stream) {
    (void)stream_id;
    while (!stream.buffer.empty() && !closed_) {
        const auto instruction = complete_qpack_encoder_instruction_size(stream.buffer);
        if (instruction.status == BufferedInstructionStatus::incomplete) {
            return;
        }
        if (instruction.status == BufferedInstructionStatus::invalid) {
            queue_connection_close(Http3ErrorCode::qpack_encoder_stream_error,
                                   "invalid qpack encoder instruction");
            return;
        }

        const auto decoded = process_http3_qpack_encoder_instructions(
            decoder_, std::span<const std::byte>(stream.buffer.data(), instruction.bytes_consumed));
        if (!decoded.has_value()) {
            queue_connection_close(decoded.error().code, decoded.error().detail);
            return;
        }

        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(instruction.bytes_consumed));
        for (const auto &field_section : decoded.value()) {
            handle_unblocked_request_field_section(field_section);
            handle_unblocked_response_field_section(field_section);
            if (closed_) {
                return;
            }
        }
        flush_qpack_decoder_instructions();
    }
}

void Http3Connection::process_qpack_decoder_stream(std::uint64_t stream_id,
                                                   PeerUniStreamState &stream) {
    (void)stream_id;
    while (!stream.buffer.empty() && !closed_) {
        const auto instruction = complete_qpack_decoder_instruction_size(stream.buffer);
        if (instruction.status == BufferedInstructionStatus::incomplete) {
            return;
        }
        if (instruction.status == BufferedInstructionStatus::invalid) {
            queue_connection_close(Http3ErrorCode::qpack_decoder_stream_error,
                                   "invalid qpack decoder instruction");
            return;
        }

        const auto processed = process_http3_qpack_decoder_instructions(
            encoder_, std::span<const std::byte>(stream.buffer.data(), instruction.bytes_consumed));
        if (!processed.has_value()) {
            queue_connection_close(processed.error().code, processed.error().detail);
            return;
        }

        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(instruction.bytes_consumed));
    }
}

void Http3Connection::process_request_stream(std::uint64_t stream_id) {
    while (!closed_) {
        const auto request = peer_request_streams_.find(stream_id);
        if (request == peer_request_streams_.end() || request->second.terminal ||
            request->second.blocked_field_section.has_value()) {
            return;
        }

        auto &stream = request->second;
        if (stream.buffer.empty()) {
            break;
        }

        const auto frame_size = complete_http3_frame_size(stream.buffer);
        if (!frame_size.has_value()) {
            if (stream.fin_received) {
                queue_stream_error(stream_id, Http3ErrorCode::request_incomplete);
            }
            return;
        }
        if (*frame_size == 0) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame encoding");
            return;
        }

        const auto parsed =
            parse_http3_frame(std::span<const std::byte>(stream.buffer.data(), *frame_size));
        if (!parsed.has_value()) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame");
            return;
        }
        if (!http3_frame_allowed_on_request_stream(parsed.value().frame)) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "frame is not permitted on the request stream");
            return;
        }

        const auto frame = parsed.value().frame;
        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(parsed.value().bytes_consumed));
        handle_request_frame(stream_id, frame);
    }

    const auto request = peer_request_streams_.find(stream_id);
    if (request == peer_request_streams_.end() || request->second.terminal ||
        request->second.blocked_field_section.has_value()) {
        return;
    }

    if (request->second.fin_received) {
        finalize_request_stream(stream_id);
    }
}

void Http3Connection::process_response_stream(std::uint64_t stream_id) {
    while (!closed_) {
        const auto request = local_request_streams_.find(stream_id);
        if (request == local_request_streams_.end() ||
            request->second.blocked_field_section.has_value()) {
            return;
        }

        auto &stream = request->second;
        if (stream.buffer.empty()) {
            break;
        }

        const auto frame_size = complete_http3_frame_size(stream.buffer);
        if (!frame_size.has_value()) {
            if (stream.fin_received) {
                queue_stream_error(stream_id, Http3ErrorCode::message_error);
            }
            return;
        }
        if (*frame_size == 0) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame encoding");
            return;
        }

        const auto parsed =
            parse_http3_frame(std::span<const std::byte>(stream.buffer.data(), *frame_size));
        if (!parsed.has_value()) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame");
            return;
        }
        if (!http3_frame_allowed_on_request_stream(parsed.value().frame)) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "frame is not permitted on the response stream");
            return;
        }

        const auto frame = parsed.value().frame;
        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(parsed.value().bytes_consumed));
        handle_response_frame(stream_id, frame);
    }

    const auto request = local_request_streams_.find(stream_id);
    if (request == local_request_streams_.end() ||
        request->second.blocked_field_section.has_value()) {
        return;
    }

    if (request->second.fin_received) {
        finalize_response_stream(stream_id);
    }
}

void Http3Connection::handle_request_frame(std::uint64_t stream_id, const Http3Frame &frame) {
    if (const auto *headers = std::get_if<Http3HeadersFrame>(&frame)) {
        handle_request_headers_frame(stream_id, *headers);
        return;
    }

    if (const auto *data = std::get_if<Http3DataFrame>(&frame)) {
        handle_request_data_frame(stream_id, *data);
    }
}

void Http3Connection::handle_response_frame(std::uint64_t stream_id, const Http3Frame &frame) {
    if (const auto *headers = std::get_if<Http3HeadersFrame>(&frame)) {
        handle_response_headers_frame(stream_id, *headers);
        return;
    }

    if (const auto *data = std::get_if<Http3DataFrame>(&frame)) {
        handle_response_data_frame(stream_id, *data);
    }
}

void Http3Connection::handle_request_headers_frame(std::uint64_t stream_id,
                                                   const Http3HeadersFrame &frame) {
    const auto request = peer_request_streams_.find(stream_id);
    if (request == peer_request_streams_.end() || request->second.terminal) {
        return;
    }

    RequestFieldSectionKind kind = RequestFieldSectionKind::initial_headers;
    if (request->second.initial_headers_received) {
        if (request->second.trailing_headers_received) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "headers frame after trailing headers is not permitted");
            return;
        }
        kind = RequestFieldSectionKind::trailers;
    }

    const auto prefix_size = complete_qpack_field_section_prefix_size(frame.field_section);
    if (!prefix_size.has_value() || *prefix_size == 0 ||
        *prefix_size > frame.field_section.size()) {
        queue_connection_close(Http3ErrorCode::qpack_decompression_failed,
                               "invalid qpack field section prefix");
        return;
    }

    const auto decoded = decode_http3_field_section(
        decoder_, stream_id, std::span<const std::byte>(frame.field_section.data(), *prefix_size),
        std::span<const std::byte>(frame.field_section.data() + *prefix_size,
                                   frame.field_section.size() - *prefix_size));
    if (!decoded.has_value()) {
        if (decoded.error().code == Http3ErrorCode::qpack_decompression_failed) {
            queue_connection_close(decoded.error().code, decoded.error().detail);
        } else {
            queue_stream_error(stream_id, decoded.error().code);
        }
        return;
    }

    if (decoded.value().status == Http3QpackDecodeStatus::blocked) {
        request->second.blocked_field_section = kind;
        return;
    }

    apply_request_field_section(stream_id, kind, decoded.value().headers);
}

void Http3Connection::handle_request_data_frame(std::uint64_t stream_id,
                                                const Http3DataFrame &frame) {
    const auto request = peer_request_streams_.find(stream_id);
    if (request == peer_request_streams_.end() || request->second.terminal) {
        return;
    }

    if (!request->second.initial_headers_received) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame before request headers is not permitted");
        return;
    }
    if (request->second.trailing_headers_received) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame after trailing headers is not permitted");
        return;
    }

    if (frame.payload.size() >
        std::numeric_limits<std::uint64_t>::max() - request->second.body_bytes_received) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }

    const auto new_total =
        request->second.body_bytes_received + static_cast<std::uint64_t>(frame.payload.size());
    if (request->second.expected_content_length.has_value() &&
        new_total > *request->second.expected_content_length) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }

    request->second.body_bytes_received = new_total;
    if (!frame.payload.empty()) {
        pending_events_.push_back(Http3PeerRequestBodyEvent{
            .stream_id = stream_id,
            .body = frame.payload,
        });
    }
}

void Http3Connection::handle_response_headers_frame(std::uint64_t stream_id,
                                                    const Http3HeadersFrame &frame) {
    const auto request = local_request_streams_.find(stream_id);
    if (request == local_request_streams_.end()) {
        return;
    }

    ResponseFieldSectionKind kind = ResponseFieldSectionKind::informational_or_final_headers;
    if (request->second.final_response_received) {
        if (request->second.response_trailers_received) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "headers frame after response trailers is not permitted");
            return;
        }
        kind = ResponseFieldSectionKind::trailers;
    }

    const auto prefix_size = complete_qpack_field_section_prefix_size(frame.field_section);
    if (!prefix_size.has_value() || *prefix_size == 0 ||
        *prefix_size > frame.field_section.size()) {
        queue_connection_close(Http3ErrorCode::qpack_decompression_failed,
                               "invalid qpack field section prefix");
        return;
    }

    const auto decoded = decode_http3_field_section(
        decoder_, stream_id, std::span<const std::byte>(frame.field_section.data(), *prefix_size),
        std::span<const std::byte>(frame.field_section.data() + *prefix_size,
                                   frame.field_section.size() - *prefix_size));
    if (!decoded.has_value()) {
        if (decoded.error().code == Http3ErrorCode::qpack_decompression_failed) {
            queue_connection_close(decoded.error().code, decoded.error().detail);
        } else {
            queue_stream_error(stream_id, decoded.error().code);
        }
        return;
    }

    if (decoded.value().status == Http3QpackDecodeStatus::blocked) {
        request->second.blocked_field_section = kind;
        return;
    }

    apply_response_field_section(stream_id, kind, decoded.value().headers);
}

void Http3Connection::handle_response_data_frame(std::uint64_t stream_id,
                                                 const Http3DataFrame &frame) {
    const auto request = local_request_streams_.find(stream_id);
    if (request == local_request_streams_.end()) {
        return;
    }

    if (!request->second.final_response_received) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame before response headers is not permitted");
        return;
    }
    if (request->second.head_request) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame on response to HEAD request is not permitted");
        return;
    }
    if (request->second.response_trailers_received) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame after response trailers is not permitted");
        return;
    }

    if (frame.payload.size() >
        std::numeric_limits<std::uint64_t>::max() - request->second.response_body_bytes_received) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }

    const auto new_total = request->second.response_body_bytes_received +
                           static_cast<std::uint64_t>(frame.payload.size());
    if (request->second.expected_response_content_length.has_value() &&
        new_total > *request->second.expected_response_content_length) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }

    request->second.response_body_bytes_received = new_total;
    if (!frame.payload.empty()) {
        pending_events_.push_back(Http3PeerResponseBodyEvent{
            .stream_id = stream_id,
            .body = frame.payload,
        });
    }
}

void Http3Connection::apply_request_field_section(std::uint64_t stream_id,
                                                  RequestFieldSectionKind kind,
                                                  Http3Headers headers) {
    const auto request = peer_request_streams_.find(stream_id);
    if (request == peer_request_streams_.end() || request->second.terminal) {
        return;
    }

    if (kind == RequestFieldSectionKind::initial_headers) {
        auto head = validate_http3_request_headers(headers);
        if (!head.has_value()) {
            queue_stream_error(stream_id, head.error().code);
            return;
        }

        request->second.initial_headers_received = true;
        request->second.expected_content_length = head.value().content_length;
        local_response_streams_.try_emplace(stream_id);
        pending_events_.push_back(Http3PeerRequestHeadEvent{
            .stream_id = stream_id,
            .head = std::move(head.value()),
        });
        return;
    }

    auto trailers = validate_http3_trailers(headers);
    if (!trailers.has_value()) {
        queue_stream_error(stream_id, trailers.error().code);
        return;
    }

    request->second.trailing_headers_received = true;
    pending_events_.push_back(Http3PeerRequestTrailersEvent{
        .stream_id = stream_id,
        .trailers = std::move(trailers.value()),
    });
}

void Http3Connection::apply_response_field_section(std::uint64_t stream_id,
                                                   ResponseFieldSectionKind kind,
                                                   Http3Headers headers) {
    const auto request = local_request_streams_.find(stream_id);
    if (request == local_request_streams_.end()) {
        return;
    }

    if (kind == ResponseFieldSectionKind::informational_or_final_headers) {
        auto head = validate_http3_response_headers(headers);
        if (!head.has_value()) {
            queue_stream_error(stream_id, head.error().code);
            return;
        }

        if (is_informational_response(head.value().status)) {
            pending_events_.push_back(Http3PeerInformationalResponseEvent{
                .stream_id = stream_id,
                .head = std::move(head.value()),
            });
            return;
        }

        request->second.final_response_received = true;
        request->second.expected_response_content_length = head.value().content_length;
        pending_events_.push_back(Http3PeerResponseHeadEvent{
            .stream_id = stream_id,
            .head = std::move(head.value()),
        });
        return;
    }

    auto trailers = validate_http3_trailers(headers);
    if (!trailers.has_value()) {
        queue_stream_error(stream_id, trailers.error().code);
        return;
    }

    request->second.response_trailers_received = true;
    pending_events_.push_back(Http3PeerResponseTrailersEvent{
        .stream_id = stream_id,
        .trailers = std::move(trailers.value()),
    });
}

void Http3Connection::handle_unblocked_request_field_section(
    const Http3DecodedFieldSection &decoded) {
    const auto request = peer_request_streams_.find(decoded.stream_id);
    if (request == peer_request_streams_.end() || request->second.terminal ||
        !request->second.blocked_field_section.has_value()) {
        return;
    }

    auto kind = RequestFieldSectionKind::initial_headers;
    if (request->second.blocked_field_section == RequestFieldSectionKind::trailers) {
        kind = RequestFieldSectionKind::trailers;
    }
    request->second.blocked_field_section.reset();
    apply_request_field_section(decoded.stream_id, kind, decoded.headers);
    if (!closed_) {
        process_request_stream(decoded.stream_id);
    }
}

void Http3Connection::handle_unblocked_response_field_section(
    const Http3DecodedFieldSection &decoded) {
    const auto request = local_request_streams_.find(decoded.stream_id);
    if (request == local_request_streams_.end() ||
        !request->second.blocked_field_section.has_value()) {
        return;
    }

    auto kind = ResponseFieldSectionKind::informational_or_final_headers;
    if (request->second.blocked_field_section == ResponseFieldSectionKind::trailers) {
        kind = ResponseFieldSectionKind::trailers;
    }
    request->second.blocked_field_section.reset();
    apply_response_field_section(decoded.stream_id, kind, decoded.headers);
    if (!closed_) {
        process_response_stream(decoded.stream_id);
    }
}

void Http3Connection::finalize_request_stream(std::uint64_t stream_id) {
    const auto request = peer_request_streams_.find(stream_id);
    if (request == peer_request_streams_.end() || request->second.terminal) {
        return;
    }

    if (!request->second.initial_headers_received) {
        queue_stream_error(stream_id, Http3ErrorCode::request_incomplete);
        return;
    }
    if (request->second.expected_content_length.has_value() &&
        request->second.body_bytes_received != *request->second.expected_content_length) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }

    pending_events_.push_back(Http3PeerRequestCompleteEvent{
        .stream_id = stream_id,
    });
    peer_request_streams_.erase(request);
}

void Http3Connection::finalize_response_stream(std::uint64_t stream_id) {
    const auto request = local_request_streams_.find(stream_id);
    if (request == local_request_streams_.end()) {
        return;
    }

    if (!request->second.final_response_received) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }
    if (!request->second.head_request &&
        request->second.expected_response_content_length.has_value() &&
        request->second.response_body_bytes_received !=
            *request->second.expected_response_content_length) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }

    pending_events_.push_back(Http3PeerResponseCompleteEvent{
        .stream_id = stream_id,
    });
    local_request_streams_.erase(request);
}

void Http3Connection::handle_control_frame(std::uint64_t stream_id, const Http3Frame &frame) {
    if (!state_.remote_settings_received) {
        const auto *settings = std::get_if<Http3SettingsFrame>(&frame);
        if (settings == nullptr) {
            queue_connection_close(Http3ErrorCode::missing_settings,
                                   "peer control stream did not start with settings");
            return;
        }

        const auto valid = validate_http3_settings_frame(*settings);
        if (!valid.has_value()) {
            queue_connection_close(valid.error().code, valid.error().detail);
            return;
        }

        apply_remote_settings(*settings);
        state_.remote_settings_received = true;
        return;
    }

    if (std::holds_alternative<Http3SettingsFrame>(frame)) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "duplicate settings frame on control stream");
        return;
    }

    if (!http3_frame_allowed_on_control_stream(config_.role, frame)) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "frame is not permitted on the control stream");
        return;
    }

    if (const auto *goaway = std::get_if<Http3GoawayFrame>(&frame)) {
        const auto valid = validate_http3_goaway_id(config_.role, goaway->id);
        if (!valid.has_value()) {
            queue_connection_close(valid.error().code, valid.error().detail);
            return;
        }
        if (state_.goaway_id.has_value() && goaway->id > *state_.goaway_id) {
            queue_connection_close(Http3ErrorCode::id_error, "peer goaway identifier increased");
            return;
        }
        state_.goaway_id = goaway->id;
    }

    (void)stream_id;
}

void Http3Connection::apply_remote_settings(const Http3SettingsFrame &frame) {
    auto updated = peer_settings_;
    for (const auto &setting : frame.settings) {
        if (setting.id == kHttp3SettingsQpackMaxTableCapacity) {
            updated.qpack_max_table_capacity = setting.value;
        } else if (setting.id == kHttp3SettingsQpackBlockedStreams) {
            updated.qpack_blocked_streams = setting.value;
        } else if (setting.id == kHttp3SettingsMaxFieldSectionSize) {
            updated.max_field_section_size = setting.value;
        }
    }

    peer_settings_ = updated;
    encoder_.peer_settings = qpack_settings_from_snapshot(peer_settings_);
}

void Http3Connection::queue_send(std::uint64_t stream_id, std::span<const std::byte> bytes,
                                 bool fin) {
    if (bytes.empty() && !fin) {
        return;
    }

    if (fin && bytes.empty() && !pending_core_inputs_.empty()) {
        if (auto *send = std::get_if<quic::QuicCoreSendStreamData>(&pending_core_inputs_.back())) {
            if (send->stream_id == stream_id) {
                send->fin = true;
                return;
            }
        }
    }

    pending_core_inputs_.push_back(quic::QuicCoreSendStreamData{
        .stream_id = stream_id,
        .bytes = std::vector<std::byte>(bytes.begin(), bytes.end()),
        .fin = fin,
    });
}

std::uint64_t Http3Connection::next_local_uni_stream_id() const {
    return config_.role == Http3ConnectionRole::client ? 2u : 3u;
}

bool Http3Connection::is_remote_critical_stream(std::uint64_t stream_id) const {
    return state_.remote_control_stream_id == stream_id ||
           state_.remote_qpack_encoder_stream_id == stream_id ||
           state_.remote_qpack_decoder_stream_id == stream_id;
}

bool Http3Connection::is_local_critical_stream(std::uint64_t stream_id) const {
    return state_.local_control_stream_id == stream_id ||
           state_.local_qpack_encoder_stream_id == stream_id ||
           state_.local_qpack_decoder_stream_id == stream_id;
}

} // namespace coquic::http3
