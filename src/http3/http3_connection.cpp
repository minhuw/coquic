#include "src/http3/http3_connection.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

#include "src/quic/transport/streams.h"
#include "src/quic/codec/varint.h"

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
    while (bytes_consumed < bytes.size()) {
        const auto byte = std::to_integer<std::uint8_t>(bytes[bytes_consumed++]);
        // The HTTP/3/QPACK prefixes used here are 5-8 bits wide, so the 7-bit continuation
        // chunks cannot overflow std::uint64_t before the shift itself reaches 63.
        if (shift >= 63) {
            return {
                .status = BufferedInstructionStatus::invalid,
            };
        }

        if ((byte & 0x80u) == 0u) {
            return {
                .status = BufferedInstructionStatus::complete,
                .bytes_consumed = bytes_consumed,
            };
        }

        shift += 7;
    }
    return {};
}

BufferedInstructionProgress parse_string_literal_progress(std::span<const std::byte> bytes,
                                                          std::uint8_t prefix_bits) {
    const auto length = parse_prefixed_integer_progress(bytes, prefix_bits);
    if (length.status != BufferedInstructionStatus::complete) {
        return length;
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

    if constexpr (sizeof(std::size_t) < sizeof(std::uint64_t)) {
        if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            return {
                .status = BufferedInstructionStatus::invalid,
            };
        }
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

    return parse_prefixed_integer_progress(bytes, 5);
}

BufferedInstructionProgress
complete_qpack_decoder_instruction_size(std::span<const std::byte> bytes) {
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

bool response_status_forbids_body(std::uint16_t status) {
    return is_informational_response(status) || status == 204u || status == 304u;
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
        .name = ":authority",
        .value = head.authority,
    });
    if (head.protocol.has_value()) {
        fields.push_back(Http3Field{
            .name = ":protocol",
            .value = *head.protocol,
        });
    }
    if (head.method != "CONNECT" || head.protocol.has_value()) {
        fields.push_back(Http3Field{
            .name = ":scheme",
            .value = head.scheme,
        });
        fields.push_back(Http3Field{
            .name = ":path",
            .value = head.path,
        });
    }
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
    if (settings.enable_connect_protocol) {
        values.push_back(Http3Setting{
            .id = kHttp3SettingsEnableConnectProtocol,
            .value = 1,
        });
    }
    if (settings.h3_datagram) {
        values.push_back(Http3Setting{
            .id = kHttp3SettingsH3Datagram,
            .value = 1,
        });
    }
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
    // # Endpoints SHOULD include at least one such setting in their
    // # SETTINGS frame.
    values.push_back(Http3Setting{
        .id = kHttp3SettingsReservedGrease,
        .value = 0,
    });
    return values;
}

bool field_section_exceeds_limit(std::span<const Http3Field> fields, std::uint64_t limit) {
    const auto size = http3_field_section_size(fields);
    return !size.has_value() || *size > limit;
}

std::optional<std::size_t> complete_http3_frame_size(std::span<const std::byte> bytes) {
    const auto type = decode_varint_bytes(bytes);
    if (!type.has_value()) {
        return std::nullopt;
    }

    const auto after_type = bytes.subspan(type.value().bytes_consumed);
    const auto length = decode_varint_bytes(after_type);
    if (!length.has_value()) {
        return std::nullopt;
    }

    const auto header_size = type.value().bytes_consumed + length.value().bytes_consumed;
    if (length.value().value > bytes.size() - header_size) {
        return std::nullopt;
    }
    return header_size + static_cast<std::size_t>(length.value().value);
}

std::optional<std::uint64_t> complete_push_stream_id(std::span<const std::byte> bytes) {
    const auto decoded = decode_varint_bytes(bytes);
    if (!decoded.has_value()) {
        return std::nullopt;
    }
    return decoded.value().value;
}

std::optional<std::size_t> complete_push_stream_id_size(std::span<const std::byte> bytes) {
    const auto decoded = decode_varint_bytes(bytes);
    if (!decoded.has_value()) {
        return std::nullopt;
    }
    return decoded.value().bytes_consumed;
}

bool headers_equal(const Http3Headers &lhs, const Http3Headers &rhs) {
    return lhs == rhs;
}

bool settings_frame_contains_value(const Http3SettingsFrame &frame, std::uint64_t id,
                                   std::uint64_t value) {
    return std::any_of(
        frame.settings.begin(), frame.settings.end(),
        [=](const Http3Setting &setting) { return setting.id == id && setting.value == value; });
}

bool request_stream_id_is_valid(std::uint64_t stream_id) {
    return (stream_id & 0x03u) == 0u;
}

bool priority_field_value_is_connection_safe(std::string_view value) {
    for (const unsigned char ch : value) {
        if (ch < 0x20u || ch > 0x7eu) {
            return false;
        }
    }
    return true;
}

} // namespace

Http3Connection::Http3Connection(Http3ConnectionConfig config)
    : config_(config),
      peer_settings_{config_.remembered_peer_settings.value_or(Http3SettingsSnapshot{
          .qpack_max_table_capacity = 0,
          .qpack_blocked_streams = 0,
          .max_field_section_size = std::nullopt,
      })},
      remembered_peer_settings_{config_.remembered_peer_settings}, encoder_{}, decoder_{},
      next_local_uni_stream_id_{config_.role == Http3ConnectionRole::client ? 2u : 3u} {
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
            switch (state->change) {
            case quic::QuicCoreStateChange::handshake_ready:
            case quic::QuicCoreStateChange::handshake_confirmed:
                transport_ready_ = true;
                break;
            case quic::QuicCoreStateChange::failed:
                closed_ = true;
                break;
            }
            continue;
        }

        if (const auto *received = std::get_if<quic::QuicCoreReceiveStreamData>(&effect)) {
            handle_receive_stream_data(*received);
            continue;
        }

        if (const auto *datagram = std::get_if<quic::QuicCoreReceiveDatagramData>(&effect)) {
            handle_receive_datagram_data(*datagram);
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

        if (const auto *zero_rtt = std::get_if<quic::QuicCoreZeroRttStatusEvent>(&effect)) {
            if (zero_rtt->status == quic::QuicZeroRttStatus::accepted) {
                state_.zero_rtt_accepted = true;
                if (remote_settings_frame_.has_value() && remembered_peer_settings_.has_value() &&
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
                    // # If a
                    // # server accepts 0-RTT but then sends settings that are not compatible
                    // # with the previously specified settings, this MUST be treated as a
                    // # connection error of type H3_SETTINGS_ERROR.
                    //= https://www.rfc-editor.org/rfc/rfc9204#section-3.2.3
                    // # If the remembered value is non-zero, the server MUST
                    // # send the same non-zero value in its SETTINGS frame.
                    !validate_zero_rtt_settings_compatibility(*remote_settings_frame_,
                                                              *remembered_peer_settings_)) {
                    queue_connection_close(Http3ErrorCode::settings_error,
                                           "zero-rtt settings are incompatible");
                }
            } else if (zero_rtt->status == quic::QuicZeroRttStatus::rejected ||
                       zero_rtt->status == quic::QuicZeroRttStatus::unavailable ||
                       zero_rtt->status == quic::QuicZeroRttStatus::not_attempted) {
                state_.zero_rtt_accepted = false;
                if (!state_.remote_settings_received && remembered_peer_settings_.has_value()) {
                    peer_settings_ = Http3SettingsSnapshot{
                        .qpack_max_table_capacity = 0,
                        .qpack_blocked_streams = 0,
                        .max_field_section_size = std::nullopt,
                    };
                    encoder_.peer_settings = qpack_settings_from_snapshot(peer_settings_);
                }
            }
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
    if (head.protocol.has_value() && !peer_settings_.enable_connect_protocol) {
        return local_http3_failure<bool>(Http3ErrorCode::settings_error,
                                         "peer does not enable extended connect", stream_id);
    }

    auto fields = request_fields_from_head(head);
    if (const auto validated = validate_http3_request_headers(fields); !validated.has_value()) {
        return Http3Result<bool>::failure(validated.error());
    }
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
    // # An HTTP implementation MUST NOT send frames or requests that would be
    // # invalid based on its current understanding of the peer's settings.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
    // # An implementation that has received this parameter SHOULD NOT send an
    // # HTTP message header that exceeds the indicated size, as the peer will
    // # likely refuse to process it.
    if (peer_settings_.max_field_section_size.has_value() &&
        field_section_exceeds_limit(fields, *peer_settings_.max_field_section_size)) {
        return local_http3_failure<bool>(
            Http3ErrorCode::message_error,
            "request field section exceeds peer max field section size", stream_id);
    }

    const auto encoded = encode_http3_field_section(encoder_, stream_id, fields).value();
    if (!encoded.encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.encoder_instructions);
    }

    auto field_section = encoded.prefix;
    field_section.insert(field_section.end(), encoded.payload.begin(), encoded.payload.end());
    queue_serialized_frame(stream_id, Http3Frame{
                                          Http3HeadersFrame{
                                              .field_section = std::move(field_section),
                                          },
                                      });
    request.head_request = head.method == "HEAD";
    request.connect_request = head.method == "CONNECT";
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
    // # A client MUST send only a single request on a given stream.
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

    const auto frame =
        serialize_http3_frame(Http3Frame{
                                  Http3DataFrame{
                                      .payload = std::vector<std::byte>(body.begin(), body.end()),
                                  },
                              })
            .value();

    queue_send(stream_id, frame, fin);
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
    if (request.connect_request) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request trailers after connect request", stream_id);
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
    if (peer_settings_.max_field_section_size.has_value() &&
        field_section_exceeds_limit(validated.value(), *peer_settings_.max_field_section_size)) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "request trailers exceed peer max field section size",
                                         stream_id);
    }

    const auto encoded = encode_http3_field_section(encoder_, stream_id, validated.value()).value();
    if (!encoded.encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.encoder_instructions);
    }

    auto field_section = encoded.prefix;
    field_section.insert(field_section.end(), encoded.payload.begin(), encoded.payload.end());
    queue_serialized_frame(stream_id,
                           Http3Frame{
                               Http3HeadersFrame{
                                   .field_section = std::move(field_section),
                               },
                           },
                           fin);
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

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
    // # After sending a request, a client MUST close the stream for sending.
    request.request_finished = true;
    queue_send(stream_id, std::span<const std::byte>{}, true);
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::abort_request_body(std::uint64_t stream_id,
                                                      std::uint64_t application_error_code) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "request abort requires server role", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }
    if (terminated_peer_request_streams_.contains(stream_id)) {
        return Http3Result<bool>::success(true);
    }

    const auto request_it = peer_request_streams_.find(stream_id);
    if (request_it == peer_request_streams_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "request stream is not available", stream_id);
    }

    if (request_it->second.blocked_field_section.has_value()) {
        cancel_http3_qpack_stream(decoder_, stream_id).value();
        flush_qpack_decoder_instructions();
    }

    peer_request_streams_.erase(request_it);
    terminated_peer_request_streams_.insert(stream_id);
    pending_core_inputs_.push_back(quic::QuicCoreStopSending{
        .stream_id = stream_id,
        .application_error_code = application_error_code,
    });
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
    if (const auto validated = validate_http3_response_headers(fields); !validated.has_value()) {
        return Http3Result<bool>::failure(validated.error());
    }
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
    // # An HTTP implementation MUST NOT send frames or requests that would be
    // # invalid based on its current understanding of the peer's settings.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
    // # An implementation that has received this parameter SHOULD NOT send an
    // # HTTP message header that exceeds the indicated size, as the peer will
    // # likely refuse to process it.
    if (peer_settings_.max_field_section_size.has_value() &&
        field_section_exceeds_limit(fields, *peer_settings_.max_field_section_size)) {
        return local_http3_failure<bool>(
            Http3ErrorCode::message_error,
            "response field section exceeds peer max field section size", stream_id);
    }

    const auto encoded = encode_http3_field_section(encoder_, stream_id, fields).value();
    if (!encoded.encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.encoder_instructions);
    }

    auto field_section = encoded.prefix;
    field_section.insert(field_section.end(), encoded.payload.begin(), encoded.payload.end());
    queue_serialized_frame(stream_id, Http3Frame{
                                          Http3HeadersFrame{
                                              .field_section = std::move(field_section),
                                          },
                                      });
    if (!informational) {
        response.final_response_started = true;
        response.expected_content_length = head.content_length;
        response.response_body_forbidden = response_status_forbids_body(head.status);
        if (response.connect_request && head.status >= 200u && head.status < 300u) {
            response.connect_response = true;
            response.expected_content_length.reset();
            response.response_body_forbidden = false;
        }
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
    if (response.connect_request && !response.connect_response) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "connect response data before 2xx response headers",
                                         stream_id);
    }
    if (response.connect_response) {
        const auto frame = serialize_http3_frame(
                               Http3Frame{
                                   Http3DataFrame{
                                       .payload = std::vector<std::byte>(body.begin(), body.end()),
                                   },
                               })
                               .value();

        queue_send(stream_id, frame, fin);
        response.finished = fin;
        return Http3Result<bool>::success(true);
    }
    if (!response.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response body before final response headers", stream_id);
    }
    if (response.response_body_forbidden) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response body is not permitted for this status",
                                         stream_id);
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

    const auto frame =
        serialize_http3_frame(Http3Frame{
                                  Http3DataFrame{
                                      .payload = std::vector<std::byte>(body.begin(), body.end()),
                                  },
                              })
            .value();

    queue_send(stream_id, frame, fin);
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
    if (response.connect_response) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response trailers after connect response", stream_id);
    }
    if (!response.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response trailers before final response headers",
                                         stream_id);
    }
    if (response.response_body_forbidden) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "response trailers are not permitted for this status",
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
    if (peer_settings_.max_field_section_size.has_value() &&
        field_section_exceeds_limit(validated.value(), *peer_settings_.max_field_section_size)) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "response trailers exceed peer max field section size",
                                         stream_id);
    }

    const auto encoded = encode_http3_field_section(encoder_, stream_id, validated.value()).value();
    if (!encoded.encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.encoder_instructions);
    }

    auto field_section = encoded.prefix;
    field_section.insert(field_section.end(), encoded.payload.begin(), encoded.payload.end());
    queue_serialized_frame(stream_id,
                           Http3Frame{
                               Http3HeadersFrame{
                                   .field_section = std::move(field_section),
                               },
                           },
                           fin);
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
    if (enforce_content_length && !response.response_body_forbidden &&
        response.expected_content_length.has_value() &&
        response.body_bytes_sent != *response.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "response body does not match content-length", stream_id);
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
    // # After sending a final response, the server MUST close the stream for
    // # sending.
    response.finished = true;
    queue_send(stream_id, std::span<const std::byte>{}, true);
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_max_push_id(std::uint64_t push_id) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed");
    }
    if (config_.role != Http3ConnectionRole::client) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "max push id sending requires client role");
    }
    if (!transport_ready_ || !state_.local_control_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready");
    }
    if (state_.local_max_push_id.has_value() && push_id < *state_.local_max_push_id) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "max push id cannot be reduced");
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-10.5
    // # A client that accepts server push SHOULD limit the number of push IDs
    // # it issues at a time.
    state_.local_max_push_id = push_id;
    queue_serialized_frame(*state_.local_control_stream_id,
                           Http3Frame{Http3MaxPushIdFrame{.push_id = push_id}});
    return Http3Result<bool>::success(true);
}

Http3Result<std::uint64_t> Http3Connection::submit_push_promise(std::uint64_t request_stream_id,
                                                                const Http3RequestHead &head) {
    if (closed_) {
        return local_http3_failure<std::uint64_t>(Http3ErrorCode::general_protocol_error,
                                                  "connection is closed", request_stream_id);
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<std::uint64_t>(Http3ErrorCode::general_protocol_error,
                                                  "push promise sending requires server role",
                                                  request_stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<std::uint64_t>(Http3ErrorCode::general_protocol_error,
                                                  "transport is not ready", request_stream_id);
    }
    if (!state_.peer_max_push_id.has_value()) {
        return local_http3_failure<std::uint64_t>(
            Http3ErrorCode::id_error, "peer has not enabled server push", request_stream_id);
    }

    const auto response_it = local_response_streams_.find(request_stream_id);
    if (response_it == local_response_streams_.end()) {
        return local_http3_failure<std::uint64_t>(
            Http3ErrorCode::frame_unexpected, "request stream is not available", request_stream_id);
    }
    if (response_it->second.finished || response_it->second.trailers_sent) {
        return local_http3_failure<std::uint64_t>(Http3ErrorCode::frame_unexpected,
                                                  "push promise after response completion",
                                                  request_stream_id);
    }

    const auto push_id = state_.next_local_push_id;
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
    // # A server MUST NOT use a push ID that is larger than the client has
    // # provided in a MAX_PUSH_ID frame (Section 7.2.7).
    if (push_id > *state_.peer_max_push_id) {
        return local_http3_failure<std::uint64_t>(
            Http3ErrorCode::id_error, "peer max push id is exhausted", request_stream_id);
    }
    //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
    // # Endpoints MUST NOT initiate new requests or promise new pushes on the
    // # connection after receipt of a GOAWAY frame from the peer.
    if (state_.goaway_id.has_value()) {
        return local_http3_failure<std::uint64_t>(Http3ErrorCode::request_rejected,
                                                  "peer goaway prevents issuing a new push",
                                                  request_stream_id);
    }

    auto fields = request_fields_from_head(head);
    if (const auto validated = validate_http3_request_headers(fields); !validated.has_value()) {
        return Http3Result<std::uint64_t>::failure(validated.error());
    }
    if (peer_settings_.max_field_section_size.has_value() &&
        field_section_exceeds_limit(fields, *peer_settings_.max_field_section_size)) {
        return local_http3_failure<std::uint64_t>(
            Http3ErrorCode::message_error,
            "push promise field section exceeds peer max field section size", request_stream_id);
    }

    const auto encoded = encode_http3_field_section(encoder_, request_stream_id, fields).value();
    if (!encoded.encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<std::uint64_t>(Http3ErrorCode::general_protocol_error,
                                                      "local qpack encoder stream is unavailable",
                                                      request_stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.encoder_instructions);
    }

    auto field_section = encoded.prefix;
    field_section.insert(field_section.end(), encoded.payload.begin(), encoded.payload.end());
    queue_serialized_frame(request_stream_id, Http3Frame{
                                                  Http3PushPromiseFrame{
                                                      .push_id = push_id,
                                                      .field_section = std::move(field_section),
                                                  },
                                              });

    local_pushes_.insert_or_assign(push_id, LocalPushState{
                                                .push_id = push_id,
                                                .request_stream_id = request_stream_id,
                                                .promised_head = head,
                                            });
    state_.next_local_push_id = push_id + 1u;
    return Http3Result<std::uint64_t>::success(push_id);
}

Http3Result<bool> Http3Connection::submit_push_response_head(std::uint64_t push_id,
                                                             const Http3ResponseHead &head) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed");
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "push response sending requires server role");
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready");
    }

    const auto push_it = local_pushes_.find(push_id);
    if (push_it == local_pushes_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "push id is not available");
    }
    auto &push = push_it->second;
    if (push.cancelled) {
        return local_http3_failure<bool>(Http3ErrorCode::request_cancelled,
                                         "push has been cancelled");
    }
    if (push.finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response already finished");
    }
    if (push.trailers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response trailers already sent");
    }
    const bool informational = is_informational_response(head.status);
    if (push.final_response_started && !informational) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "final push response already sent");
    }

    if (!push.push_stream_id.has_value()) {
        create_local_push_stream(push);
    }
    if (!push.push_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "push stream is not available");
    }
    const auto push_stream_id = push.push_stream_id.value();

    auto fields = response_fields_from_head(head);
    if (const auto validated = validate_http3_response_headers(fields); !validated.has_value()) {
        return Http3Result<bool>::failure(validated.error());
    }
    if (peer_settings_.max_field_section_size.has_value() &&
        field_section_exceeds_limit(fields, *peer_settings_.max_field_section_size)) {
        return local_http3_failure<bool>(
            Http3ErrorCode::message_error,
            "push response field section exceeds peer max field section size", push_stream_id);
    }

    const auto encoded = encode_http3_field_section(encoder_, push_stream_id, fields).value();
    if (!encoded.encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             push_stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.encoder_instructions);
    }

    auto field_section = encoded.prefix;
    field_section.insert(field_section.end(), encoded.payload.begin(), encoded.payload.end());
    queue_serialized_frame(push_stream_id, Http3Frame{
                                               Http3HeadersFrame{
                                                   .field_section = std::move(field_section),
                                               },
                                           });
    if (!informational) {
        push.final_response_started = true;
        push.expected_content_length = head.content_length;
        push.response_body_forbidden = response_status_forbids_body(head.status);
    }

    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_push_response_body(std::uint64_t push_id,
                                                             std::span<const std::byte> body,
                                                             bool fin) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed");
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "push response sending requires server role");
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready");
    }

    const auto push_it = local_pushes_.find(push_id);
    if (push_it == local_pushes_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "push stream is not available");
    }
    const auto maybe_push_stream_id = push_it->second.push_stream_id;
    if (!maybe_push_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "push stream is not available");
    }
    const auto push_stream_id = *maybe_push_stream_id;
    auto &push = push_it->second;
    if (push.cancelled) {
        return local_http3_failure<bool>(Http3ErrorCode::request_cancelled,
                                         "push has been cancelled", push_stream_id);
    }
    if (push.finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response already finished", push_stream_id);
    }
    if (!push.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response body before final response headers",
                                         push_stream_id);
    }
    if (push.response_body_forbidden) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response body is not permitted for this status",
                                         push_stream_id);
    }
    if (push.trailers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response trailers already sent", push_stream_id);
    }

    if (body.size() > std::numeric_limits<std::uint64_t>::max() - push.body_bytes_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "push response body exceeds content-length",
                                         push_stream_id);
    }
    const auto new_total = push.body_bytes_sent + static_cast<std::uint64_t>(body.size());
    if (push.expected_content_length.has_value() && new_total > *push.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "push response body exceeds content-length",
                                         push_stream_id);
    }
    if (fin && push.expected_content_length.has_value() &&
        new_total != *push.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "push response body does not match content-length",
                                         push_stream_id);
    }

    queue_serialized_frame(push_stream_id,
                           Http3Frame{
                               Http3DataFrame{
                                   .payload = std::vector<std::byte>(body.begin(), body.end()),
                               },
                           },
                           fin);
    push.body_bytes_sent = new_total;
    push.finished = fin;
    return Http3Result<bool>::success(true);
}

Http3Result<bool>
Http3Connection::submit_push_response_trailers(std::uint64_t push_id,
                                               std::span<const Http3Field> trailers, bool fin) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed");
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "push response sending requires server role");
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready");
    }

    const auto push_it = local_pushes_.find(push_id);
    if (push_it == local_pushes_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "push stream is not available");
    }
    const auto maybe_push_stream_id = push_it->second.push_stream_id;
    if (!maybe_push_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "push stream is not available");
    }
    const auto push_stream_id = *maybe_push_stream_id;
    auto &push = push_it->second;
    if (push.cancelled) {
        return local_http3_failure<bool>(Http3ErrorCode::request_cancelled,
                                         "push has been cancelled", push_stream_id);
    }
    if (push.finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response already finished", push_stream_id);
    }
    if (!push.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response trailers before final response headers",
                                         push_stream_id);
    }
    if (push.response_body_forbidden) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response trailers are not permitted for this status",
                                         push_stream_id);
    }
    if (push.trailers_sent) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response trailers already sent", push_stream_id);
    }
    if (push.expected_content_length.has_value() &&
        push.body_bytes_sent != *push.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "push response body does not match content-length",
                                         push_stream_id);
    }

    const auto validated = validate_http3_trailers(trailers);
    if (!validated.has_value()) {
        return Http3Result<bool>::failure(validated.error());
    }
    if (peer_settings_.max_field_section_size.has_value() &&
        field_section_exceeds_limit(validated.value(), *peer_settings_.max_field_section_size)) {
        return local_http3_failure<bool>(
            Http3ErrorCode::message_error,
            "push response trailers exceed peer max field section size", push_stream_id);
    }

    const auto encoded =
        encode_http3_field_section(encoder_, push_stream_id, validated.value()).value();
    if (!encoded.encoder_instructions.empty()) {
        if (!state_.local_qpack_encoder_stream_id.has_value()) {
            return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                             "local qpack encoder stream is unavailable",
                                             push_stream_id);
        }
        queue_send(*state_.local_qpack_encoder_stream_id, encoded.encoder_instructions);
    }

    auto field_section = encoded.prefix;
    field_section.insert(field_section.end(), encoded.payload.begin(), encoded.payload.end());
    queue_serialized_frame(push_stream_id,
                           Http3Frame{
                               Http3HeadersFrame{
                                   .field_section = std::move(field_section),
                               },
                           },
                           fin);
    push.trailers_sent = true;
    push.finished = fin;
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::finish_push_response(std::uint64_t push_id,
                                                        bool enforce_content_length) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed");
    }
    if (config_.role != Http3ConnectionRole::server) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "push response sending requires server role");
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready");
    }

    const auto push_it = local_pushes_.find(push_id);
    if (push_it == local_pushes_.end()) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "push stream is not available");
    }
    const auto maybe_push_stream_id = push_it->second.push_stream_id;
    if (!maybe_push_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error, "push stream is not available");
    }
    const auto push_stream_id = *maybe_push_stream_id;
    auto &push = push_it->second;
    if (push.cancelled) {
        return local_http3_failure<bool>(Http3ErrorCode::request_cancelled,
                                         "push has been cancelled", push_stream_id);
    }
    if (push.finished) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "push response already finished", push_stream_id);
    }
    if (!push.final_response_started) {
        return local_http3_failure<bool>(Http3ErrorCode::frame_unexpected,
                                         "final push response headers not sent", push_stream_id);
    }
    if (enforce_content_length && !push.response_body_forbidden &&
        push.expected_content_length.has_value() &&
        push.body_bytes_sent != *push.expected_content_length) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "push response body does not match content-length",
                                         push_stream_id);
    }

    push.finished = true;
    queue_send(push_stream_id, std::span<const std::byte>{}, true);
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::cancel_push(std::uint64_t push_id) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed");
    }
    if (!transport_ready_ || !state_.local_control_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready");
    }
    if (config_.role == Http3ConnectionRole::client) {
        if (!state_.local_max_push_id.has_value() || push_id > *state_.local_max_push_id) {
            return local_http3_failure<bool>(Http3ErrorCode::id_error,
                                             "cancel push references unavailable push id");
        }
        if (auto push_it = peer_pushes_.find(push_id); push_it != peer_pushes_.end()) {
            push_it->second.cancelled = true;
            if (push_it->second.push_stream_id.has_value()) {
                pending_core_inputs_.push_back(quic::QuicCoreStopSending{
                    .stream_id = *push_it->second.push_stream_id,
                    .application_error_code =
                        static_cast<std::uint64_t>(Http3ErrorCode::request_cancelled),
                });
            }
        }
    } else if (!state_.peer_max_push_id.has_value() || push_id > *state_.peer_max_push_id) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error,
                                         "cancel push references unavailable push id");
    }

    queue_serialized_frame(*state_.local_control_stream_id,
                           Http3Frame{Http3CancelPushFrame{.push_id = push_id}});
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_goaway(std::uint64_t id) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed");
    }
    if (!transport_ready_ || !state_.local_control_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready");
    }
    if (config_.role == Http3ConnectionRole::server && ((id & 0x03u) != 0u)) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error,
                                         "invalid server goaway stream id");
    }
    if (state_.local_goaway_id.has_value() && id > *state_.local_goaway_id) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        // # An endpoint MAY send multiple GOAWAY frames indicating different
        // # identifiers, but the identifier in each frame MUST NOT be greater
        // # than the identifier in any previous frame, since clients might
        // # already have retried unprocessed requests on another HTTP
        // # connection.
        return local_http3_failure<bool>(Http3ErrorCode::id_error,
                                         "local goaway identifier cannot increase");
    }

    state_.local_goaway_id = id;
    queue_serialized_frame(*state_.local_control_stream_id, Http3Frame{Http3GoawayFrame{.id = id}});
    return Http3Result<bool>::success(true);
}

Http3Result<bool>
Http3Connection::submit_priority_update_for_request(std::uint64_t stream_id,
                                                    std::string priority_field_value) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (!transport_ready_ || !state_.local_control_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }
    if (!request_stream_id_is_valid(stream_id)) {
        return local_http3_failure<bool>(Http3ErrorCode::id_error,
                                         "priority update references invalid request stream id",
                                         stream_id);
    }
    if (!priority_field_value_is_connection_safe(priority_field_value)) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "invalid priority field value", stream_id);
    }

    queue_serialized_frame(*state_.local_control_stream_id,
                           Http3Frame{Http3PriorityUpdateFrame{
                               .frame_type = kHttp3FrameTypePriorityUpdateRequestStream,
                               .prioritized_element_id = stream_id,
                               .priority_field_value = std::move(priority_field_value),
                           }});
    return Http3Result<bool>::success(true);
}

Http3Result<bool>
Http3Connection::submit_priority_update_for_push(std::uint64_t push_id,
                                                 std::string priority_field_value) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed");
    }
    if (!transport_ready_ || !state_.local_control_stream_id.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready");
    }
    if (!priority_field_value_is_connection_safe(priority_field_value)) {
        return local_http3_failure<bool>(Http3ErrorCode::message_error,
                                         "invalid priority field value");
    }

    queue_serialized_frame(*state_.local_control_stream_id,
                           Http3Frame{Http3PriorityUpdateFrame{
                               .frame_type = kHttp3FrameTypePriorityUpdatePushId,
                               .prioritized_element_id = push_id,
                               .priority_field_value = std::move(priority_field_value),
                           }});
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::submit_datagram(std::uint64_t stream_id,
                                                   std::span<const std::byte> payload) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }
    if (!config_.local_settings.h3_datagram || !peer_settings_.h3_datagram) {
        return local_http3_failure<bool>(Http3ErrorCode::datagram_error,
                                         "h3 datagram is not enabled", stream_id);
    }

    const auto serialized = serialize_http3_datagram(stream_id, payload);
    if (!serialized.has_value()) {
        return local_http3_failure<bool>(Http3ErrorCode::datagram_error,
                                         "invalid h3 datagram stream id", stream_id);
    }

    pending_core_inputs_.push_back(quic::QuicCoreSendDatagramData{
        .bytes = serialized.value(),
    });
    return Http3Result<bool>::success(true);
}

Http3Result<bool> Http3Connection::abort_connect_stream(std::uint64_t stream_id) {
    if (closed_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "connection is closed", stream_id);
    }
    if (!transport_ready_) {
        return local_http3_failure<bool>(Http3ErrorCode::general_protocol_error,
                                         "transport is not ready", stream_id);
    }

    queue_stream_error(stream_id, Http3ErrorCode::connect_error);
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

    const auto control_stream_id = allocate_local_uni_stream_id();
    const auto encoder_stream_id = allocate_local_uni_stream_id();
    const auto decoder_stream_id = allocate_local_uni_stream_id();

    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
    // # After the QUIC connection is established, a SETTINGS frame MUST be
    // # sent by each endpoint as the initial frame of their respective HTTP
    // # control stream.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    // # Each side MUST initiate a single control stream at the beginning of
    // # the connection and send its SETTINGS frame as the first frame on this
    // # stream.
    const auto control_stream =
        serialize_http3_control_stream(settings_from_snapshot(config_.local_settings));
    if (!control_stream.has_value()) {
        queue_connection_close(Http3ErrorCode::internal_error,
                               "unable to serialize control stream");
        return;
    }

    const auto encoder_prefix =
        serialize_http3_uni_stream_prefix(Http3UniStreamType::qpack_encoder).value();
    const auto qpack_decoder_prefix =
        serialize_http3_uni_stream_prefix(Http3UniStreamType::qpack_decoder).value();

    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    // # Each endpoint
    // # MUST initiate, at most, one encoder stream and, at most, one decoder
    // # stream.
    state_.local_control_stream_id = control_stream_id;
    state_.local_qpack_encoder_stream_id = encoder_stream_id;
    state_.local_qpack_decoder_stream_id = decoder_stream_id;
    state_.local_settings_sent = true;

    queue_send(control_stream_id, control_stream.value());
    queue_send(encoder_stream_id, encoder_prefix);
    queue_send(decoder_stream_id, qpack_decoder_prefix);
    startup_streams_queued_ = true;
}

void Http3Connection::flush_qpack_decoder_instructions() {
    if (!state_.local_qpack_decoder_stream_id.has_value() || closed_) {
        return;
    }

    const auto instructions = take_http3_qpack_decoder_instructions(decoder_).value();
    if (!instructions.empty()) {
        queue_send(*state_.local_qpack_decoder_stream_id, instructions);
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
        if (it->second.blocked_field_section.has_value()) {
            cancel_http3_qpack_stream(decoder_, stream_id).value();
            it->second.blocked_field_section.reset();
            flush_qpack_decoder_instructions();
        }

        it->second.buffer.clear();
        peer_request_streams_.erase(it);
    }

    auto local_request = local_request_streams_.find(stream_id);
    if (local_request != local_request_streams_.end()) {
        if (local_request->second.blocked_field_section.has_value()) {
            cancel_http3_qpack_stream(decoder_, stream_id).value();
            local_request->second.blocked_field_section.reset();
            flush_qpack_decoder_instructions();
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

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void Http3Connection::queue_push_stream_error(std::uint64_t stream_id, std::uint64_t push_id,
                                              Http3ErrorCode code) {
    if (closed_) {
        return;
    }

    const auto push = peer_pushes_.find(push_id);
    if (push != peer_pushes_.end()) {
        if (push->second.blocked_field_section.has_value()) {
            cancel_http3_qpack_stream(decoder_, stream_id).value();
            push->second.blocked_field_section.reset();
            flush_qpack_decoder_instructions();
        }
        peer_pushes_.erase(push);
    }
    peer_uni_streams_.erase(stream_id);
    pending_core_inputs_.push_back(quic::QuicCoreStopSending{
        .stream_id = stream_id,
        .application_error_code = static_cast<std::uint64_t>(code),
    });
}

void Http3Connection::handle_receive_stream_data(const quic::QuicCoreReceiveStreamData &received) {
    const auto payload = received.payload();
    const auto info = classify_stream_id(received.stream_id, endpoint_role(config_.role));
    if (info.initiator == StreamInitiator::peer &&
        info.direction == StreamDirection::unidirectional) {
        handle_peer_uni_stream_data(received.stream_id, payload, received.fin);
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

        request->second.buffer.insert(request->second.buffer.end(), payload.begin(), payload.end());
        if (received.fin) {
            request->second.fin_received = true;
        }
        process_response_stream(received.stream_id);
        return;
    }

    if (info.initiator == StreamInitiator::peer) {
        handle_peer_bidi_stream(received.stream_id, payload, received.fin);
    }
}

void Http3Connection::handle_receive_datagram_data(
    const quic::QuicCoreReceiveDatagramData &received) {
    if (!config_.local_settings.h3_datagram || !peer_settings_.h3_datagram) {
        queue_connection_close(Http3ErrorCode::datagram_error,
                               "received h3 datagram without negotiated support");
        return;
    }

    const auto parsed = parse_http3_datagram(received.payload());
    if (!parsed.has_value()) {
        queue_connection_close(Http3ErrorCode::datagram_error, "invalid h3 datagram payload");
        return;
    }

    pending_events_.push_back(Http3DatagramEvent{
        .stream_id = parsed.value().stream_id,
        .payload = parsed.value().payload,
    });
}

void Http3Connection::handle_peer_reset_stream(const quic::QuicCorePeerResetStream &reset) {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    // # If either control
    // # stream is closed at any point, this MUST be treated as a connection
    // # error of type H3_CLOSED_CRITICAL_STREAM.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    // # Closure of either unidirectional stream type MUST be treated as a
    // # connection error of type H3_CLOSED_CRITICAL_STREAM.
    if (is_remote_critical_stream(reset.stream_id)) {
        queue_connection_close(Http3ErrorCode::closed_critical_stream,
                               "peer reset critical stream");
        return;
    }

    peer_uni_streams_.erase(reset.stream_id);
    terminated_peer_request_streams_.erase(reset.stream_id);
    local_response_streams_.erase(reset.stream_id);

    for (auto push_it = peer_pushes_.begin(); push_it != peer_pushes_.end(); ++push_it) {
        if (push_it->second.push_stream_id == reset.stream_id) {
            if (push_it->second.blocked_field_section.has_value()) {
                cancel_http3_qpack_stream(decoder_, reset.stream_id).value();
                flush_qpack_decoder_instructions();
            }
            pending_events_.push_back(Http3PeerPushResetEvent{
                .push_id = push_it->first,
                .application_error_code = reset.application_error_code,
            });
            peer_pushes_.erase(push_it);
            return;
        }
    }

    const auto local_request = local_request_streams_.find(reset.stream_id);
    if (local_request != local_request_streams_.end()) {
        if (local_request->second.blocked_field_section.has_value()) {
            cancel_http3_qpack_stream(decoder_, reset.stream_id).value();
            flush_qpack_decoder_instructions();
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
        cancel_http3_qpack_stream(decoder_, reset.stream_id).value();
        flush_qpack_decoder_instructions();
    }
    pending_events_.push_back(Http3PeerRequestResetEvent{
        .stream_id = reset.stream_id,
        .application_error_code = reset.application_error_code,
    });
    peer_request_streams_.erase(request);
}

void Http3Connection::handle_peer_stop_sending(const quic::QuicCorePeerStopSending &stop) {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    // # The
    // # sender MUST NOT close the control stream, and the receiver MUST NOT
    // # request that the sender close the control stream.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    // # The sender MUST NOT close either of these streams, and the receiver
    // # MUST NOT request that the sender close either of these streams.
    if (is_local_critical_stream(stop.stream_id)) {
        queue_connection_close(Http3ErrorCode::closed_critical_stream,
                               "peer requested stop sending on critical stream");
        return;
    }

    const auto response = local_response_streams_.find(stop.stream_id);
    if (response != local_response_streams_.end()) {
        pending_core_inputs_.push_back(quic::QuicCoreResetStream{
            .stream_id = stop.stream_id,
            .application_error_code = stop.application_error_code,
        });
        local_response_streams_.erase(response);
        return;
    }

    for (auto &push : local_pushes_) {
        if (push.second.push_stream_id == stop.stream_id) {
            pending_core_inputs_.push_back(quic::QuicCoreResetStream{
                .stream_id = stop.stream_id,
                .application_error_code = stop.application_error_code,
            });
            push.second.cancelled = true;
            return;
        }
    }
}

void Http3Connection::handle_peer_bidi_stream(std::uint64_t stream_id,
                                              std::span<const std::byte> bytes, bool fin) {
    if (config_.role == Http3ConnectionRole::client) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
        // # Clients MUST treat receipt of a server-initiated bidirectional
        // # stream as a connection error of type H3_STREAM_CREATION_ERROR
        // # unless such an extension has been negotiated.
        queue_connection_close(Http3ErrorCode::stream_creation_error,
                               "server-initiated bidirectional stream is not permitted");
        return;
    }

    if (terminated_peer_request_streams_.contains(stream_id)) {
        return;
    }

    auto &stream = peer_request_streams_[stream_id];
    stream.buffer.insert(stream.buffer.end(), bytes.begin(), bytes.end());
    if (fin) {
        stream.fin_received = true;
    }
    process_request_stream(stream_id);
}

void Http3Connection::handle_peer_uni_stream_data(std::uint64_t stream_id,
                                                  std::span<const std::byte> bytes, bool fin) {
    auto &stream = peer_uni_streams_[stream_id];
    stream.buffer.insert(stream.buffer.end(), bytes.begin(), bytes.end());

    if (!stream.kind.has_value()) {
        const auto decoded = parse_http3_uni_stream_type(stream.buffer);
        if (!decoded.has_value()) {
            if (fin) {
                peer_uni_streams_.erase(stream_id);
            }
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

    const auto kind = stream.kind.value_or(PeerUniStreamKind::ignored);

    if (kind == PeerUniStreamKind::control) {
        process_control_stream(stream_id, stream);
    } else if (kind == PeerUniStreamKind::push) {
        process_push_stream(stream_id, stream);
    } else if (kind == PeerUniStreamKind::qpack_encoder) {
        process_qpack_encoder_stream(stream_id, stream);
    } else if (kind == PeerUniStreamKind::qpack_decoder) {
        process_qpack_decoder_stream(stream_id, stream);
    } else {
        stream.buffer.clear();
    }

    if (closed_ || !fin) {
        return;
    }

    if (kind == PeerUniStreamKind::ignored) {
        peer_uni_streams_.erase(stream_id);
        return;
    }

    if (kind == PeerUniStreamKind::push) {
        if (stream.push_id.has_value()) {
            finalize_push_stream(stream_id, *stream.push_id);
        } else {
            peer_uni_streams_.erase(stream_id);
        }
        return;
    }

    if (kind == PeerUniStreamKind::control && !state_.remote_settings_received) {
        queue_connection_close(Http3ErrorCode::missing_settings,
                               "peer control stream ended before settings");
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
    // # If either control
    // # stream is closed at any point, this MUST be treated as a connection
    // # error of type H3_CLOSED_CRITICAL_STREAM.
    //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
    // # Closure of either unidirectional stream type MUST be treated as a
    // # connection error of type H3_CLOSED_CRITICAL_STREAM.
    queue_connection_close(Http3ErrorCode::closed_critical_stream, "peer closed critical stream");
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void Http3Connection::register_peer_uni_stream(std::uint64_t stream_id, std::uint64_t stream_type) {
    auto &stream = peer_uni_streams_.at(stream_id);

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::control)) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        // # Only one control stream per peer is permitted;
        // # receipt of a second stream claiming to be a control stream MUST be
        // # treated as a connection error of type H3_STREAM_CREATION_ERROR.
        if (state_.remote_control_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "duplicate peer control stream");
            return;
        }
        state_.remote_control_stream_id = stream_id;
        stream.kind = PeerUniStreamKind::control;
        return;
    }

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::push)) {
        if (config_.role == Http3ConnectionRole::server) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
            // # Only servers can push; if a server receives a client-initiated
            // # push stream, this MUST be treated as a connection error of
            // # type H3_STREAM_CREATION_ERROR.
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "client-initiated push stream is not permitted");
            return;
        }
        stream.kind = PeerUniStreamKind::push;
        return;
    }

    if (stream_type == static_cast<std::uint64_t>(Http3UniStreamType::qpack_encoder)) {
        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
        // # An endpoint MUST allow its peer to create an encoder stream and a
        // # decoder stream even if the connection's settings prevent their use.
        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
        // # Each endpoint
        // # MUST initiate, at most, one encoder stream and, at most, one decoder
        // # stream.
        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
        // # Receipt of a second instance of either stream type MUST be
        // # treated as a connection error of type H3_STREAM_CREATION_ERROR.
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
        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
        // # An endpoint MUST allow its peer to create an encoder stream and a
        // # decoder stream even if the connection's settings prevent their use.
        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
        // # Each endpoint
        // # MUST initiate, at most, one encoder stream and, at most, one decoder
        // # stream.
        //= https://www.rfc-editor.org/rfc/rfc9204#section-4.2
        // # Receipt of a second instance of either stream type MUST be
        // # treated as a connection error of type H3_STREAM_CREATION_ERROR.
        if (state_.remote_qpack_decoder_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::stream_creation_error,
                                   "duplicate peer qpack decoder stream");
            return;
        }
        state_.remote_qpack_decoder_stream_id = stream_id;
        stream.kind = PeerUniStreamKind::qpack_decoder;
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
    // # Recipients of unknown stream types MUST either abort reading of the
    // # stream or discard incoming data without further processing.
    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
    // # The recipient MUST NOT consider unknown stream types to be a
    // # connection error of any kind.
    stream.kind = PeerUniStreamKind::ignored;
}

void Http3Connection::process_control_stream(std::uint64_t stream_id, PeerUniStreamState &stream) {
    if (closed_) {
        return;
    }

    while (!stream.buffer.empty()) {
        const auto frame_size = complete_http3_frame_size(stream.buffer);
        if (!frame_size.has_value()) {
            return;
        }

        const auto parsed =
            parse_http3_frame(std::span<const std::byte>(stream.buffer.data(), *frame_size));
        if (!parsed.has_value()) {
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame");
            return;
        }

        handle_control_frame(stream_id, parsed.value().frame);
        if (closed_) {
            return;
        }
        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(parsed.value().bytes_consumed));
    }
}

void Http3Connection::process_qpack_encoder_stream(std::uint64_t stream_id,
                                                   PeerUniStreamState &stream) {
    (void)stream_id;
    if (closed_) {
        return;
    }

    while (!stream.buffer.empty()) {
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
            //= https://www.rfc-editor.org/rfc/rfc9204#section-7.4
            // # If an implementation encounters a value larger than it is able
            // # to decode, this MUST be treated as a stream error of type
            // # QPACK_DECOMPRESSION_FAILED if on a request stream or a
            // # connection error of the appropriate type if on the encoder or
            // # decoder stream.
            queue_connection_close(decoded.error().code, decoded.error().detail);
            return;
        }

        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(instruction.bytes_consumed));
        for (const auto &field_section : decoded.value()) {
            handle_unblocked_request_field_section(field_section);
            handle_unblocked_response_field_section(field_section);
            handle_unblocked_push_field_section(field_section);
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
    if (closed_) {
        return;
    }

    while (!stream.buffer.empty()) {
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
            //= https://www.rfc-editor.org/rfc/rfc9204#section-7.4
            // # If an implementation encounters a value larger than it is able
            // # to decode, this MUST be treated as a stream error of type
            // # QPACK_DECOMPRESSION_FAILED if on a request stream or a
            // # connection error of the appropriate type if on the encoder or
            // # decoder stream.
            queue_connection_close(processed.error().code, processed.error().detail);
            return;
        }

        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(instruction.bytes_consumed));
    }
}

void Http3Connection::process_push_stream(std::uint64_t stream_id, PeerUniStreamState &stream) {
    if (closed_) {
        return;
    }

    if (!stream.push_id.has_value()) {
        const auto push_id_size = complete_push_stream_id_size(stream.buffer);
        if (!push_id_size.has_value()) {
            return;
        }
        const auto push_id = complete_push_stream_id(stream.buffer);
        if (!push_id.has_value()) {
            queue_connection_close(Http3ErrorCode::id_error, "invalid push stream push id");
            return;
        }
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.6
        // # A client MUST treat receipt of a push stream as a connection error
        // # of type H3_ID_ERROR when no MAX_PUSH_ID frame has been sent or
        // # when the stream references a push ID that is greater than the
        // # maximum push ID.
        if (!state_.local_max_push_id.has_value() || *push_id > *state_.local_max_push_id) {
            queue_connection_close(Http3ErrorCode::id_error,
                                   "push stream references unavailable push id");
            return;
        }

        auto &push = peer_pushes_[*push_id];
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
        // # Each push ID MUST only be used once in a push stream header.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.2
        // # If a client detects that a push stream header includes a push ID
        // # that was used in another push stream header, the client MUST treat
        // # this as a connection error of type H3_ID_ERROR.
        if (push.push_stream_id.has_value()) {
            queue_connection_close(Http3ErrorCode::id_error, "duplicate push stream id");
            return;
        }
        push.push_id = *push_id;
        push.push_stream_id = stream_id;
        stream.push_id = push_id;
        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() + static_cast<std::ptrdiff_t>(*push_id_size));
    }

    const auto push_id = *stream.push_id;
    while (!closed_) {
        const auto push_it = peer_pushes_.find(push_id);
        if (push_it == peer_pushes_.end() || push_it->second.blocked_field_section.has_value()) {
            return;
        }
        if (stream.buffer.empty()) {
            return;
        }

        const auto frame_size = complete_http3_frame_size(stream.buffer);
        if (!frame_size.has_value()) {
            return;
        }

        const auto parsed =
            parse_http3_frame(std::span<const std::byte>(stream.buffer.data(), *frame_size));
        if (!parsed.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
            // # When a stream terminates cleanly, if the last frame on the
            // # stream was truncated, this MUST be treated as a connection
            // # error of type H3_FRAME_ERROR.
            queue_connection_close(Http3ErrorCode::frame_error, "invalid http3 frame");
            return;
        }
        if (!http3_frame_allowed_on_request_stream(parsed.value().frame)) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "frame is not permitted on the push stream");
            return;
        }

        const auto frame = parsed.value().frame;
        stream.buffer.erase(stream.buffer.begin(),
                            stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(parsed.value().bytes_consumed));
        handle_push_stream_frame(stream_id, push_id, frame);
    }
}

void Http3Connection::process_request_stream(std::uint64_t stream_id) {
    PeerRequestStreamState *stream_state = nullptr;
    while (!closed_) {
        const auto request = peer_request_streams_.find(stream_id);
        if (request == peer_request_streams_.end() ||
            request->second.blocked_field_section.has_value()) {
            return;
        }

        auto &stream = request->second;
        stream_state = &stream;
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

        const auto parsed =
            parse_http3_frame(std::span<const std::byte>(stream.buffer.data(), *frame_size));
        if (!parsed.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
            // # When a stream terminates cleanly, if the last frame on the
            // # stream was truncated, this MUST be treated as a connection
            // # error of type H3_FRAME_ERROR.
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

    if (closed_) {
        return;
    }

    if (stream_state->fin_received) {
        finalize_request_stream(stream_id);
    }
}

void Http3Connection::process_response_stream(std::uint64_t stream_id) {
    LocalRequestStreamState *stream_state = nullptr;
    while (!closed_) {
        const auto request = local_request_streams_.find(stream_id);
        if (request == local_request_streams_.end() ||
            request->second.blocked_field_section.has_value() ||
            request->second.blocked_push_promise_id.has_value()) {
            return;
        }

        auto &stream = request->second;
        stream_state = &stream;
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

    if (closed_) {
        return;
    }

    if (stream_state->fin_received) {
        finalize_response_stream(stream_id);
    }
}

void Http3Connection::handle_request_frame(std::uint64_t stream_id, const Http3Frame &frame) {
    if (const auto *headers = std::get_if<Http3HeadersFrame>(&frame)) {
        handle_request_headers_frame(stream_id, *headers);
        return;
    }

    if (const auto *data = std::get_if<Http3DataFrame>(&frame)) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
        // # DATA frames MUST be associated with an HTTP request or response.
        handle_request_data_frame(stream_id, *data);
        return;
    }

    if (std::holds_alternative<Http3PushPromiseFrame>(frame)) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        // # A client MUST NOT send a PUSH_PROMISE frame.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        // # A server MUST treat the
        // # receipt of a PUSH_PROMISE frame as a connection error of type
        // # H3_FRAME_UNEXPECTED.
        queue_connection_close(Http3ErrorCode::frame_unexpected, "client sent push promise frame");
    }
}

void Http3Connection::handle_response_frame(std::uint64_t stream_id, const Http3Frame &frame) {
    if (const auto *headers = std::get_if<Http3HeadersFrame>(&frame)) {
        handle_response_headers_frame(stream_id, *headers);
        return;
    }

    if (const auto *data = std::get_if<Http3DataFrame>(&frame)) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
        // # DATA frames MUST be associated with an HTTP request or response.
        handle_response_data_frame(stream_id, *data);
        return;
    }

    if (const auto *promise = std::get_if<Http3PushPromiseFrame>(&frame)) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        // # A client MUST treat
        // # receipt of a PUSH_PROMISE frame that contains a larger push ID than
        // # the client has advertised as a connection error of H3_ID_ERROR.
        if (!state_.local_max_push_id.has_value() || promise->push_id > *state_.local_max_push_id) {
            queue_connection_close(Http3ErrorCode::id_error,
                                   "push promise references unavailable push id");
            return;
        }

        const auto request = local_request_streams_.find(stream_id);
        if (request == local_request_streams_.end()) {
            return;
        }
        if (request->second.response_trailers_received || request->second.connect_response) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "push promise after response trailers is not permitted");
            return;
        }

        const auto prefix_size = complete_qpack_field_section_prefix_size(promise->field_section);
        if (!prefix_size.has_value() || *prefix_size == 0) {
            queue_connection_close(Http3ErrorCode::qpack_decompression_failed,
                                   "invalid qpack field section prefix");
            return;
        }

        const auto decoded = decode_http3_field_section(
            decoder_, stream_id,
            std::span<const std::byte>(promise->field_section.data(), *prefix_size),
            std::span<const std::byte>(promise->field_section.data() + *prefix_size,
                                       promise->field_section.size() - *prefix_size));
        auto &push = peer_pushes_[promise->push_id];
        push.push_id = promise->push_id;
        push.request_stream_id = stream_id;
        if (!decoded.has_value()) {
            queue_connection_close(decoded.error().code, decoded.error().detail);
            return;
        }
        if (decoded.value().status == Http3QpackDecodeStatus::blocked) {
            push.blocked_field_section = PushFieldSectionKind::promise_headers;
            request->second.blocked_push_promise_id = promise->push_id;
            return;
        }

        apply_push_field_section(stream_id, promise->push_id, PushFieldSectionKind::promise_headers,
                                 decoded.value().headers);
        return;
    }
}

void Http3Connection::handle_push_stream_frame(std::uint64_t stream_id, std::uint64_t push_id,
                                               const Http3Frame &frame) {
    if (const auto *headers = std::get_if<Http3HeadersFrame>(&frame)) {
        handle_push_response_headers_frame(stream_id, push_id, *headers);
        return;
    }

    if (const auto *data = std::get_if<Http3DataFrame>(&frame)) {
        handle_push_response_data_frame(stream_id, push_id, *data);
        return;
    }

    if (std::holds_alternative<Http3PushPromiseFrame>(frame)) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        // # PUSH_PROMISE frames are not permitted on push streams;
        // # a pushed response that includes PUSH_PROMISE frames MUST be treated
        // # as a connection error of type H3_FRAME_UNEXPECTED.
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "push promise is not permitted on push stream");
    }
}

void Http3Connection::handle_request_headers_frame(std::uint64_t stream_id,
                                                   const Http3HeadersFrame &frame) {
    const auto request = peer_request_streams_.find(stream_id);
    if (request == peer_request_streams_.end()) {
        return;
    }

    RequestFieldSectionKind kind = RequestFieldSectionKind::initial_headers;
    if (request->second.initial_headers_received) {
        if (request->second.connect_request) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "headers frame after connect request is not permitted");
            return;
        }
        if (request->second.trailing_headers_received) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "headers frame after trailing headers is not permitted");
            return;
        }
        kind = RequestFieldSectionKind::trailers;
    }

    const auto prefix_size = complete_qpack_field_section_prefix_size(frame.field_section);
    if (!prefix_size.has_value() || *prefix_size == 0) {
        queue_connection_close(Http3ErrorCode::qpack_decompression_failed,
                               "invalid qpack field section prefix");
        return;
    }

    const auto decoded = decode_http3_field_section(
        decoder_, stream_id, std::span<const std::byte>(frame.field_section.data(), *prefix_size),
        std::span<const std::byte>(frame.field_section.data() + *prefix_size,
                                   frame.field_section.size() - *prefix_size));
    if (!decoded.has_value()) {
        queue_connection_close(decoded.error().code, decoded.error().detail);
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
    if (request == peer_request_streams_.end()) {
        return;
    }

    if (!request->second.initial_headers_received) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        // # Receipt of an invalid sequence of frames MUST be treated as a
        // # connection error of type H3_FRAME_UNEXPECTED.
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame before request headers is not permitted");
        return;
    }
    if (request->second.connect_request) {
        if (!frame.payload.empty()) {
            pending_events_.push_back(Http3PeerRequestBodyEvent{
                .stream_id = stream_id,
                .body = frame.payload,
            });
        }
        return;
    }
    if (request->second.trailing_headers_received) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        // # Receipt of an invalid sequence of frames MUST be treated as a
        // # connection error of type H3_FRAME_UNEXPECTED.
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
        if (request->second.connect_response) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "headers frame after connect response is not permitted");
            return;
        }
        if (request->second.response_trailers_received) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "headers frame after response trailers is not permitted");
            return;
        }
        kind = ResponseFieldSectionKind::trailers;
    }

    const auto prefix_size = complete_qpack_field_section_prefix_size(frame.field_section);
    if (!prefix_size.has_value() || *prefix_size == 0) {
        queue_connection_close(Http3ErrorCode::qpack_decompression_failed,
                               "invalid qpack field section prefix");
        return;
    }

    const auto decoded = decode_http3_field_section(
        decoder_, stream_id, std::span<const std::byte>(frame.field_section.data(), *prefix_size),
        std::span<const std::byte>(frame.field_section.data() + *prefix_size,
                                   frame.field_section.size() - *prefix_size));
    if (!decoded.has_value()) {
        queue_connection_close(decoded.error().code, decoded.error().detail);
        return;
    }

    if (decoded.value().status == Http3QpackDecodeStatus::blocked) {
        request->second.blocked_field_section = kind;
        return;
    }

    apply_response_field_section(stream_id, kind, decoded.value().headers);
}

void Http3Connection::handle_push_response_headers_frame(std::uint64_t stream_id,
                                                         std::uint64_t push_id,
                                                         const Http3HeadersFrame &frame) {
    const auto push = peer_pushes_.find(push_id);
    if (push == peer_pushes_.end()) {
        return;
    }
    if (push->second.cancelled) {
        return;
    }

    PushFieldSectionKind kind = PushFieldSectionKind::response_headers;
    if (push->second.final_response_received) {
        if (push->second.response_trailers_received) {
            queue_connection_close(Http3ErrorCode::frame_unexpected,
                                   "headers frame after push response trailers is not permitted");
            return;
        }
        kind = PushFieldSectionKind::response_trailers;
    }

    const auto prefix_size = complete_qpack_field_section_prefix_size(frame.field_section);
    if (!prefix_size.has_value() || *prefix_size == 0) {
        queue_connection_close(Http3ErrorCode::qpack_decompression_failed,
                               "invalid qpack field section prefix");
        return;
    }

    const auto decoded = decode_http3_field_section(
        decoder_, stream_id, std::span<const std::byte>(frame.field_section.data(), *prefix_size),
        std::span<const std::byte>(frame.field_section.data() + *prefix_size,
                                   frame.field_section.size() - *prefix_size));
    if (!decoded.has_value()) {
        queue_connection_close(decoded.error().code, decoded.error().detail);
        return;
    }

    if (decoded.value().status == Http3QpackDecodeStatus::blocked) {
        push->second.blocked_field_section = kind;
        return;
    }

    apply_push_field_section(stream_id, push_id, kind, decoded.value().headers);
}

void Http3Connection::handle_response_data_frame(std::uint64_t stream_id,
                                                 const Http3DataFrame &frame) {
    const auto request = local_request_streams_.find(stream_id);
    if (request == local_request_streams_.end()) {
        return;
    }

    if (!request->second.final_response_received) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        // # Receipt of an invalid sequence of frames MUST be treated as a
        // # connection error of type H3_FRAME_UNEXPECTED.
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame before response headers is not permitted");
        return;
    }
    if (request->second.head_request) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame on response to HEAD request is not permitted");
        return;
    }
    if (request->second.response_body_forbidden) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame on response without a body is not permitted");
        return;
    }
    if (request->second.connect_response) {
        if (!frame.payload.empty()) {
            pending_events_.push_back(Http3PeerResponseBodyEvent{
                .stream_id = stream_id,
                .body = frame.payload,
            });
        }
        return;
    }
    if (request->second.response_trailers_received) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        // # Receipt of an invalid sequence of frames MUST be treated as a
        // # connection error of type H3_FRAME_UNEXPECTED.
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

void Http3Connection::handle_push_response_data_frame(std::uint64_t stream_id,
                                                      std::uint64_t push_id,
                                                      const Http3DataFrame &frame) {
    const auto push = peer_pushes_.find(push_id);
    if (push == peer_pushes_.end()) {
        return;
    }
    if (push->second.cancelled) {
        return;
    }

    if (!push->second.final_response_received) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame before push response headers is not permitted");
        return;
    }
    if (push->second.response_body_forbidden) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame on push response without a body is not permitted");
        return;
    }
    if (push->second.response_trailers_received) {
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "data frame after push response trailers is not permitted");
        return;
    }

    if (frame.payload.size() >
        std::numeric_limits<std::uint64_t>::max() - push->second.response_body_bytes_received) {
        queue_push_stream_error(stream_id, push_id, Http3ErrorCode::message_error);
        return;
    }

    const auto new_total = push->second.response_body_bytes_received +
                           static_cast<std::uint64_t>(frame.payload.size());
    if (push->second.expected_response_content_length.has_value() &&
        new_total > *push->second.expected_response_content_length) {
        queue_push_stream_error(stream_id, push_id, Http3ErrorCode::message_error);
        return;
    }

    push->second.response_body_bytes_received = new_total;
    if (!frame.payload.empty()) {
        pending_events_.push_back(Http3PeerPushResponseBodyEvent{
            .push_id = push_id,
            .body = frame.payload,
        });
    }
}

void Http3Connection::apply_request_field_section(std::uint64_t stream_id,
                                                  RequestFieldSectionKind kind,
                                                  Http3Headers headers) {
    const auto request = peer_request_streams_.find(stream_id);
    if (request == peer_request_streams_.end()) {
        return;
    }

    if (kind == RequestFieldSectionKind::initial_headers) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        // # An HTTP/3 implementation MAY impose a limit on the maximum size
        // # of the message header it will accept on an individual HTTP
        // # message.
        if (config_.local_settings.max_field_section_size.has_value() &&
            field_section_exceeds_limit(headers, *config_.local_settings.max_field_section_size)) {
            queue_stream_error(stream_id, Http3ErrorCode::message_error);
            return;
        }

        auto head = validate_http3_request_headers(headers);
        if (!head.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
            // # Malformed requests or responses that are detected MUST be
            // # treated as a stream error of type H3_MESSAGE_ERROR.
            queue_stream_error(stream_id, head.error().code);
            return;
        }
        if (head.value().protocol.has_value() && !config_.local_settings.enable_connect_protocol) {
            queue_stream_error(stream_id, Http3ErrorCode::settings_error);
            return;
        }

        request->second.initial_headers_received = true;
        request->second.expected_content_length = head.value().content_length;
        request->second.connect_request = head.value().method == "CONNECT";
        auto response = local_response_streams_.try_emplace(stream_id).first;
        response->second.connect_request = request->second.connect_request;
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
    if (config_.local_settings.max_field_section_size.has_value() &&
        field_section_exceeds_limit(trailers.value(),
                                    *config_.local_settings.max_field_section_size)) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
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
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        // # An HTTP/3 implementation MAY impose a limit on the maximum size
        // # of the message header it will accept on an individual HTTP
        // # message.
        if (config_.local_settings.max_field_section_size.has_value() &&
            field_section_exceeds_limit(headers, *config_.local_settings.max_field_section_size)) {
            queue_stream_error(stream_id, Http3ErrorCode::message_error);
            return;
        }

        auto head = validate_http3_response_headers(headers);
        if (!head.has_value()) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
            // # Clients MUST NOT accept a malformed response.
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
            // # Malformed requests or responses that are detected MUST be
            // # treated as a stream error of type H3_MESSAGE_ERROR.
            queue_stream_error(stream_id, head.error().code);
            return;
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        // # A response MAY consist of multiple messages when and only when one
        // # or more interim responses (1xx; see Section 15.2 of [HTTP])
        // # precede a final response to the same request.
        if (is_informational_response(head.value().status)) {
            pending_events_.push_back(Http3PeerInformationalResponseEvent{
                .stream_id = stream_id,
                .head = std::move(head.value()),
            });
            return;
        }

        request->second.final_response_received = true;
        request->second.expected_response_content_length = head.value().content_length;
        request->second.response_body_forbidden = response_status_forbids_body(head.value().status);
        if (request->second.connect_request && head.value().status >= 200u &&
            head.value().status < 300u) {
            request->second.connect_response = true;
            request->second.expected_response_content_length.reset();
            request->second.response_body_forbidden = false;
        }
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
    if (config_.local_settings.max_field_section_size.has_value() &&
        field_section_exceeds_limit(trailers.value(),
                                    *config_.local_settings.max_field_section_size)) {
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }

    request->second.response_trailers_received = true;
    pending_events_.push_back(Http3PeerResponseTrailersEvent{
        .stream_id = stream_id,
        .trailers = std::move(trailers.value()),
    });
}

void Http3Connection::apply_push_field_section(std::uint64_t stream_id, std::uint64_t push_id,
                                               PushFieldSectionKind kind, Http3Headers headers) {
    const auto push = peer_pushes_.find(push_id);
    if (push == peer_pushes_.end()) {
        return;
    }
    if (push->second.cancelled) {
        return;
    }

    if (kind == PushFieldSectionKind::promise_headers) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        // # An HTTP/3 implementation MAY impose a limit on the maximum size
        // # of the message header it will accept on an individual HTTP
        // # message.
        if (config_.local_settings.max_field_section_size.has_value() &&
            field_section_exceeds_limit(headers, *config_.local_settings.max_field_section_size)) {
            queue_stream_error(stream_id, Http3ErrorCode::message_error);
            return;
        }

        auto head = validate_http3_request_headers(headers);
        if (!head.has_value()) {
            queue_stream_error(stream_id, head.error().code);
            return;
        }

        if (push->second.promised_head.has_value()) {
            const auto existing_fields =
                request_fields_from_head(push->second.promised_head.value());
            const auto new_fields = request_fields_from_head(head.value());
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            // # If a client
            // # receives a push ID that has already been promised and detects a
            // # mismatch, it MUST respond with a connection error of type
            // # H3_GENERAL_PROTOCOL_ERROR.
            if (!headers_equal(existing_fields, new_fields)) {
                queue_connection_close(Http3ErrorCode::general_protocol_error,
                                       "duplicate push promise headers differ");
                return;
            }
            return;
        }

        push->second.request_stream_id = stream_id;
        push->second.promised_head = head.value();
        pending_events_.push_back(Http3PeerPushPromiseEvent{
            .request_stream_id = stream_id,
            .push_id = push_id,
            .head = std::move(head.value()),
        });
        return;
    }

    if (kind == PushFieldSectionKind::response_headers) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        // # An HTTP/3 implementation MAY impose a limit on the maximum size
        // # of the message header it will accept on an individual HTTP
        // # message.
        if (config_.local_settings.max_field_section_size.has_value() &&
            field_section_exceeds_limit(headers, *config_.local_settings.max_field_section_size)) {
            queue_push_stream_error(stream_id, push_id, Http3ErrorCode::message_error);
            return;
        }

        auto head = validate_http3_response_headers(headers);
        if (!head.has_value()) {
            queue_push_stream_error(stream_id, push_id, head.error().code);
            return;
        }

        if (is_informational_response(head.value().status)) {
            return;
        }

        push->second.final_response_received = true;
        push->second.expected_response_content_length = head.value().content_length;
        push->second.response_body_forbidden = response_status_forbids_body(head.value().status);
        pending_events_.push_back(Http3PeerPushResponseHeadEvent{
            .push_id = push_id,
            .head = std::move(head.value()),
        });
        return;
    }

    auto trailers = validate_http3_trailers(headers);
    if (!trailers.has_value()) {
        queue_push_stream_error(stream_id, push_id, trailers.error().code);
        return;
    }
    if (config_.local_settings.max_field_section_size.has_value() &&
        field_section_exceeds_limit(trailers.value(),
                                    *config_.local_settings.max_field_section_size)) {
        queue_push_stream_error(stream_id, push_id, Http3ErrorCode::message_error);
        return;
    }

    push->second.response_trailers_received = true;
    pending_events_.push_back(Http3PeerPushResponseTrailersEvent{
        .push_id = push_id,
        .trailers = std::move(trailers.value()),
    });
}

void Http3Connection::handle_unblocked_request_field_section(
    const Http3DecodedFieldSection &decoded) {
    const auto request = peer_request_streams_.find(decoded.stream_id);
    if (request == peer_request_streams_.end() ||
        !request->second.blocked_field_section.has_value()) {
        return;
    }

    auto kind = RequestFieldSectionKind::initial_headers;
    if (request->second.blocked_field_section == RequestFieldSectionKind::trailers) {
        kind = RequestFieldSectionKind::trailers;
    }
    request->second.blocked_field_section.reset();
    apply_request_field_section(decoded.stream_id, kind, decoded.headers);
    process_request_stream(decoded.stream_id);
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
    process_response_stream(decoded.stream_id);
}

void Http3Connection::handle_unblocked_push_field_section(const Http3DecodedFieldSection &decoded) {
    std::optional<std::uint64_t> push_id;
    for (const auto &[candidate_id, push] : peer_pushes_) {
        if (push.blocked_field_section.has_value() && push.push_stream_id == decoded.stream_id) {
            push_id = candidate_id;
            break;
        }
        if (push.blocked_field_section == PushFieldSectionKind::promise_headers &&
            push.request_stream_id == decoded.stream_id) {
            push_id = candidate_id;
            break;
        }
    }
    if (!push_id.has_value()) {
        return;
    }

    auto push_it = peer_pushes_.find(*push_id);
    if (push_it == peer_pushes_.end()) {
        return;
    }
    const auto maybe_kind = push_it->second.blocked_field_section;
    if (!maybe_kind.has_value()) {
        return;
    }
    const auto kind = *maybe_kind;
    push_it->second.blocked_field_section.reset();
    if (kind == PushFieldSectionKind::promise_headers) {
        if (auto request_it = local_request_streams_.find(decoded.stream_id);
            request_it != local_request_streams_.end()) {
            request_it->second.blocked_push_promise_id.reset();
        }
    }
    apply_push_field_section(decoded.stream_id, *push_id, kind, decoded.headers);
    if (kind == PushFieldSectionKind::response_headers ||
        kind == PushFieldSectionKind::response_trailers) {
        auto stream_it = peer_uni_streams_.find(decoded.stream_id);
        if (stream_it != peer_uni_streams_.end()) {
            process_push_stream(decoded.stream_id, stream_it->second);
        }
    } else if (const auto request_stream_id = push_it->second.request_stream_id;
               request_stream_id.has_value()) {
        process_response_stream(*request_stream_id);
    }
}

void Http3Connection::finalize_request_stream(std::uint64_t stream_id) {
    const auto request = peer_request_streams_.find(stream_id);
    if (request == peer_request_streams_.end()) {
        return;
    }

    if (!request->second.initial_headers_received) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        // # If a client-initiated stream terminates without enough of the HTTP
        // # message to provide a complete response, the server SHOULD abort
        // # its response stream with the error code H3_REQUEST_INCOMPLETE.
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
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
        // # Clients MUST NOT accept a malformed response.
        queue_stream_error(stream_id, Http3ErrorCode::message_error);
        return;
    }
    if (!request->second.head_request && !request->second.response_body_forbidden &&
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

void Http3Connection::finalize_push_stream(std::uint64_t stream_id, std::uint64_t push_id) {
    const auto push = peer_pushes_.find(push_id);
    if (push == peer_pushes_.end()) {
        peer_uni_streams_.erase(stream_id);
        return;
    }
    if (push->second.cancelled) {
        peer_pushes_.erase(push);
        peer_uni_streams_.erase(stream_id);
        return;
    }
    if (!push->second.final_response_received) {
        queue_push_stream_error(stream_id, push_id, Http3ErrorCode::message_error);
        return;
    }
    if (!push->second.response_body_forbidden &&
        push->second.expected_response_content_length.has_value() &&
        push->second.response_body_bytes_received !=
            *push->second.expected_response_content_length) {
        queue_push_stream_error(stream_id, push_id, Http3ErrorCode::message_error);
        return;
    }

    pending_events_.push_back(Http3PeerPushResponseCompleteEvent{
        .push_id = push_id,
    });
    peer_pushes_.erase(push);
    peer_uni_streams_.erase(stream_id);
}

void Http3Connection::handle_control_frame(std::uint64_t stream_id, const Http3Frame &frame) {
    if (!state_.remote_settings_received) {
        const auto *settings = std::get_if<Http3SettingsFrame>(&frame);
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        // # If the first frame of the control stream is any other frame
        // # type, this MUST be treated as a connection error of type
        // # H3_MISSING_SETTINGS.
        if (settings == nullptr) {
            queue_connection_close(Http3ErrorCode::missing_settings,
                                   "peer control stream did not start with settings");
            return;
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        // # A SETTINGS frame MUST be sent as the first frame of each control
        // # stream (see Section 6.2.1) by each peer, and it MUST NOT be sent
        // # subsequently.
        const auto valid = validate_http3_settings_frame(*settings);
        if (!valid.has_value()) {
            queue_connection_close(valid.error().code, valid.error().detail);
            return;
        }

        if (state_.zero_rtt_accepted && remembered_peer_settings_.has_value() &&
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
            // # If a
            // # server accepts 0-RTT but then sends settings that are not compatible
            // # with the previously specified settings, this MUST be treated as a
            // # connection error of type H3_SETTINGS_ERROR.
            //= https://www.rfc-editor.org/rfc/rfc9204#section-3.2.3
            // # If the remembered value is non-zero, the server MUST send the
            // # same non-zero value in its SETTINGS frame.
            !validate_zero_rtt_settings_compatibility(*settings, *remembered_peer_settings_)) {
            queue_connection_close(Http3ErrorCode::settings_error,
                                   "zero-rtt settings are incompatible");
            return;
        }

        apply_remote_settings(*settings);
        remote_settings_frame_ = *settings;
        state_.remote_settings_received = true;
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
    // # If an endpoint receives a second SETTINGS frame on the control
    // # stream, the endpoint MUST respond with a connection error of type
    // # H3_FRAME_UNEXPECTED.
    if (std::holds_alternative<Http3SettingsFrame>(frame)) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        // # If an endpoint receives a second SETTINGS
        // # frame on the control stream, the endpoint MUST respond with a
        // # connection error of type H3_FRAME_UNEXPECTED.
        queue_connection_close(Http3ErrorCode::frame_unexpected,
                               "duplicate settings frame on control stream");
        return;
    }

    if (!http3_frame_allowed_on_control_stream(config_.role, frame)) {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
        // # If a DATA frame is received on a control stream, the recipient
        // # MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.2
        // # If a HEADERS frame is received on a control stream, the recipient
        // # MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        // # SETTINGS frames MUST NOT be sent on any stream other than the
        // # control stream.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        // # If a PUSH_PROMISE frame is received on the control stream, the
        // # client MUST respond with a connection error of type
        // # H3_FRAME_UNEXPECTED.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
        // # A client MUST treat a GOAWAY frame on a stream other than the
        // # control stream as a connection error of type H3_FRAME_UNEXPECTED.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
        // # Receipt of a MAX_PUSH_ID frame on any other stream MUST be treated
        // # as a connection error of type H3_FRAME_UNEXPECTED.
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
            //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
            // # Receiving a GOAWAY containing a larger identifier than previously
            // # received MUST be treated as a connection error of type H3_ID_ERROR.
            queue_connection_close(Http3ErrorCode::id_error, "peer goaway identifier increased");
            return;
        }
        state_.goaway_id = goaway->id;
    }

    if (const auto *max_push_id = std::get_if<Http3MaxPushIdFrame>(&frame)) {
        if (state_.peer_max_push_id.has_value() &&
            max_push_id->push_id < *state_.peer_max_push_id) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
            // # A MAX_PUSH_ID frame cannot reduce the maximum push
            // # ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than
            // # previously received MUST be treated as a connection error of type
            // # H3_ID_ERROR.
            queue_connection_close(Http3ErrorCode::id_error, "peer max push id decreased");
            return;
        }
        state_.peer_max_push_id = max_push_id->push_id;
    }

    if (const auto *cancel = std::get_if<Http3CancelPushFrame>(&frame)) {
        if (config_.role == Http3ConnectionRole::client) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
            // # If a CANCEL_PUSH frame is received that
            // # references a push ID greater than currently allowed on the
            // # connection, this MUST be treated as a connection error of type
            // # H3_ID_ERROR.
            if (!state_.local_max_push_id.has_value() ||
                cancel->push_id > *state_.local_max_push_id) {
                queue_connection_close(Http3ErrorCode::id_error,
                                       "cancel push references unavailable push id");
                return;
            }
            if (auto push_it = peer_pushes_.find(cancel->push_id); push_it != peer_pushes_.end()) {
                push_it->second.cancelled = true;
            }
            pending_events_.push_back(Http3PeerPushCancelledEvent{.push_id = cancel->push_id});
            return;
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
        // # If a CANCEL_PUSH frame is received that
        // # references a push ID greater than currently allowed on the
        // # connection, this MUST be treated as a connection error of type
        // # H3_ID_ERROR.
        if (!state_.peer_max_push_id.has_value() || cancel->push_id > *state_.peer_max_push_id) {
            queue_connection_close(Http3ErrorCode::id_error,
                                   "cancel push references unavailable push id");
            return;
        }
        auto push_it = local_pushes_.find(cancel->push_id);
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
        // # If a server receives a CANCEL_PUSH frame for a push
        // # ID that has not yet been mentioned by a PUSH_PROMISE frame, this MUST
        // # be treated as a connection error of type H3_ID_ERROR.
        if (push_it == local_pushes_.end()) {
            queue_connection_close(Http3ErrorCode::id_error,
                                   "cancel push references unpromised push id");
            return;
        }
        push_it->second.cancelled = true;
        if (push_it->second.push_stream_id.has_value()) {
            pending_core_inputs_.push_back(quic::QuicCoreResetStream{
                .stream_id = *push_it->second.push_stream_id,
                .application_error_code =
                    static_cast<std::uint64_t>(Http3ErrorCode::request_cancelled),
            });
        }
    }

    if (const auto *priority = std::get_if<Http3PriorityUpdateFrame>(&frame)) {
        pending_events_.push_back(Http3PriorityUpdateEvent{
            .id = priority->prioritized_element_id,
            .push = priority->frame_type == kHttp3FrameTypePriorityUpdatePushId,
            .priority_field_value = priority->priority_field_value,
        });
    }

    (void)stream_id;
}

bool Http3Connection::validate_zero_rtt_settings_compatibility(
    const Http3SettingsFrame &frame, const Http3SettingsSnapshot &settings) {
    Http3SettingsSnapshot updated{
        .qpack_max_table_capacity = 0,
        .qpack_blocked_streams = 0,
        .max_field_section_size = std::nullopt,
    };
    bool saw_max_field_section_size = false;
    for (const auto &setting : frame.settings) {
        if (setting.id == kHttp3SettingsQpackMaxTableCapacity) {
            updated.qpack_max_table_capacity = setting.value;
        } else if (setting.id == kHttp3SettingsQpackBlockedStreams) {
            updated.qpack_blocked_streams = setting.value;
        } else if (setting.id == kHttp3SettingsMaxFieldSectionSize) {
            updated.max_field_section_size = setting.value;
            saw_max_field_section_size = true;
        } else if (setting.id == kHttp3SettingsEnableConnectProtocol) {
            updated.enable_connect_protocol = setting.value != 0u;
        } else if (setting.id == kHttp3SettingsH3Datagram) {
            updated.h3_datagram = setting.value != 0u;
        }
    }

    if (settings.qpack_max_table_capacity != 0 &&
        //= https://www.rfc-editor.org/rfc/rfc9204#section-3.2.3
        // # If the remembered value is non-zero, the server MUST send the
        // # same non-zero value in its SETTINGS frame.
        updated.qpack_max_table_capacity != settings.qpack_max_table_capacity) {
        return false;
    }
    if (updated.qpack_blocked_streams < settings.qpack_blocked_streams) {
        return false;
    }
    if (settings.max_field_section_size.has_value()) {
        if (!saw_max_field_section_size || !updated.max_field_section_size.has_value() ||
            *updated.max_field_section_size < *settings.max_field_section_size) {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
            // # If 0-RTT data is accepted by the server, its SETTINGS frame
            // # MUST NOT reduce any limits or alter any values that might be
            // # violated by the client with its 0-RTT data.
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
            // # If a server accepts 0-RTT but then sends a SETTINGS frame that
            // # omits a setting value that the client understands (apart from
            // # reserved setting identifiers) that was previously specified to
            // # have a non-default value, this MUST be treated as a connection
            // # error of type H3_SETTINGS_ERROR.
            return false;
        }
    }
    if (settings.enable_connect_protocol &&
        !settings_frame_contains_value(frame, kHttp3SettingsEnableConnectProtocol, 1)) {
        return false;
    }
    if (settings.h3_datagram &&
        !settings_frame_contains_value(frame, kHttp3SettingsH3Datagram, 1)) {
        return false;
    }
    return true;
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
        } else if (setting.id == kHttp3SettingsEnableConnectProtocol) {
            updated.enable_connect_protocol = setting.value != 0u;
        } else if (setting.id == kHttp3SettingsH3Datagram) {
            updated.h3_datagram = setting.value != 0u;
        }
    }

    peer_settings_ = updated;
    encoder_.peer_settings = qpack_settings_from_snapshot(peer_settings_);
}

void Http3Connection::create_local_push_stream(LocalPushState &push) {
    if (push.push_stream_id.has_value()) {
        return;
    }

    const auto stream_id = allocate_local_uni_stream_id();
    push.push_stream_id = stream_id;

    auto prefix = serialize_http3_uni_stream_prefix(Http3UniStreamType::push).value();
    const auto encoded_push_id = quic::encode_varint(push.push_id).value();
    prefix.insert(prefix.end(), encoded_push_id.begin(), encoded_push_id.end());
    queue_send(stream_id, prefix);
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

void Http3Connection::queue_serialized_frame(std::uint64_t stream_id, const Http3Frame &frame,
                                             bool fin) {
    queue_send(stream_id, serialize_http3_frame(frame).value(), fin);
}

std::uint64_t Http3Connection::next_local_uni_stream_id() const {
    return next_local_uni_stream_id_;
}

std::uint64_t Http3Connection::allocate_local_uni_stream_id() {
    const auto stream_id = next_local_uni_stream_id_;
    next_local_uni_stream_id_ += 4u;
    return stream_id;
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
