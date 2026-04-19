#include "src/quic/qlog/json.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace coquic::quic::qlog {
namespace {

std::string hex_bytes(std::span<const std::byte> value) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(value.size() * 2);
    for (const auto byte : value) {
        const auto raw = std::to_integer<std::uint8_t>(byte);
        hex.push_back(kDigits[raw >> 4]);
        hex.push_back(kDigits[raw & 0x0f]);
    }
    return hex;
}

std::string serialize_alpn_identifier(std::span<const std::byte> value) {
    std::string json = "{\"byte_value\":\"";
    json += hex_bytes(value);
    json += "\"";

    const auto as_text = std::string(reinterpret_cast<const char *>(value.data()), value.size());
    const auto printable = std::all_of(as_text.begin(), as_text.end(),
                                       [](unsigned char ch) { return ch >= 0x20 && ch <= 0x7e; });
    if (printable) {
        json += ",\"string_value\":\"" + escape_json_string(as_text) + "\"";
    }
    json += "}";
    return json;
}

std::string serialize_frame_json(const Frame &frame) {
    return std::visit(
        [&](const auto &value) -> std::string {
            using FrameType = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<FrameType, PaddingFrame>) {
                return "{\"frame_type\":\"padding\",\"length\":" + std::to_string(value.length) +
                       "}";
            } else if constexpr (std::is_same_v<FrameType, PingFrame>) {
                return "{\"frame_type\":\"ping\"}";
            } else if constexpr (std::is_same_v<FrameType, AckFrame>) {
                return "{\"frame_type\":\"ack\",\"largest_acknowledged\":" +
                       std::to_string(value.largest_acknowledged) +
                       ",\"ack_delay\":" + std::to_string(value.ack_delay) + "}";
            } else if constexpr (std::is_same_v<FrameType, OutboundAckFrame>) {
                return "{\"frame_type\":\"ack\",\"largest_acknowledged\":" +
                       std::to_string(value.header.largest_acknowledged) +
                       ",\"ack_delay\":" + std::to_string(value.header.ack_delay) + "}";
            } else if constexpr (std::is_same_v<FrameType, ResetStreamFrame>) {
                return "{\"frame_type\":\"reset_stream\",\"stream_id\":" +
                       std::to_string(value.stream_id) +
                       ",\"error_code\":" + std::to_string(value.application_protocol_error_code) +
                       ",\"final_size\":" + std::to_string(value.final_size) + "}";
            } else if constexpr (std::is_same_v<FrameType, StopSendingFrame>) {
                return "{\"frame_type\":\"stop_sending\",\"stream_id\":" +
                       std::to_string(value.stream_id) +
                       ",\"error_code\":" + std::to_string(value.application_protocol_error_code) +
                       "}";
            } else if constexpr (std::is_same_v<FrameType, CryptoFrame>) {
                return "{\"frame_type\":\"crypto\",\"offset\":" + std::to_string(value.offset) +
                       ",\"length\":" + std::to_string(value.crypto_data.size()) + "}";
            } else if constexpr (std::is_same_v<FrameType, NewTokenFrame>) {
                return "{\"frame_type\":\"new_token\",\"token\":\"" + hex_bytes(value.token) +
                       "\"}";
            } else if constexpr (std::is_same_v<FrameType, StreamFrame>) {
                return "{\"frame_type\":\"stream\",\"stream_id\":" +
                       std::to_string(value.stream_id) +
                       ",\"offset\":" + std::to_string(value.offset.value_or(0)) +
                       ",\"length\":" + std::to_string(value.stream_data.size()) +
                       ",\"fin\":" + std::string(value.fin ? "true" : "false") + "}";
            } else if constexpr (std::is_same_v<FrameType, MaxDataFrame>) {
                return "{\"frame_type\":\"max_data\",\"maximum\":" +
                       std::to_string(value.maximum_data) + "}";
            } else if constexpr (std::is_same_v<FrameType, MaxStreamDataFrame>) {
                return "{\"frame_type\":\"max_stream_data\",\"stream_id\":" +
                       std::to_string(value.stream_id) +
                       ",\"maximum\":" + std::to_string(value.maximum_stream_data) + "}";
            } else if constexpr (std::is_same_v<FrameType, MaxStreamsFrame>) {
                return "{\"frame_type\":\"max_streams\",\"stream_type\":\"" +
                       std::string(value.stream_type == StreamLimitType::bidirectional
                                       ? "bidirectional"
                                       : "unidirectional") +
                       "\",\"maximum\":" + std::to_string(value.maximum_streams) + "}";
            } else if constexpr (std::is_same_v<FrameType, DataBlockedFrame>) {
                return "{\"frame_type\":\"data_blocked\",\"maximum\":" +
                       std::to_string(value.maximum_data) + "}";
            } else if constexpr (std::is_same_v<FrameType, StreamDataBlockedFrame>) {
                return "{\"frame_type\":\"stream_data_blocked\",\"stream_id\":" +
                       std::to_string(value.stream_id) +
                       ",\"maximum\":" + std::to_string(value.maximum_stream_data) + "}";
            } else if constexpr (std::is_same_v<FrameType, StreamsBlockedFrame>) {
                return "{\"frame_type\":\"streams_blocked\",\"stream_type\":\"" +
                       std::string(value.stream_type == StreamLimitType::bidirectional
                                       ? "bidirectional"
                                       : "unidirectional") +
                       "\",\"maximum\":" + std::to_string(value.maximum_streams) + "}";
            } else if constexpr (std::is_same_v<FrameType, NewConnectionIdFrame>) {
                return "{\"frame_type\":\"new_connection_id\",\"sequence_number\":" +
                       std::to_string(value.sequence_number) +
                       ",\"retire_prior_to\":" + std::to_string(value.retire_prior_to) +
                       ",\"connection_id\":\"" + hex_bytes(value.connection_id) + "\"}";
            } else if constexpr (std::is_same_v<FrameType, RetireConnectionIdFrame>) {
                return "{\"frame_type\":\"retire_connection_id\",\"sequence_number\":" +
                       std::to_string(value.sequence_number) + "}";
            } else if constexpr (std::is_same_v<FrameType, PathChallengeFrame>) {
                return "{\"frame_type\":\"path_challenge\",\"data\":\"" + hex_bytes(value.data) +
                       "\"}";
            } else if constexpr (std::is_same_v<FrameType, PathResponseFrame>) {
                return "{\"frame_type\":\"path_response\",\"data\":\"" + hex_bytes(value.data) +
                       "\"}";
            } else if constexpr (std::is_same_v<FrameType, TransportConnectionCloseFrame>) {
                return "{\"frame_type\":\"connection_close_transport\",\"error_code\":" +
                       std::to_string(value.error_code) +
                       ",\"frame_type_value\":" + std::to_string(value.frame_type) + "}";
            } else if constexpr (std::is_same_v<FrameType, ApplicationConnectionCloseFrame>) {
                return "{\"frame_type\":\"connection_close_application\",\"error_code\":" +
                       std::to_string(value.error_code) + "}";
            } else {
                return std::string{"{\"frame_type\":\"handshake_done\"}"};
            }
        },
        frame);
}

} // namespace

std::string escape_json_string(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const auto ch : value) {
        switch (ch) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(ch);
            break;
        }
    }
    return out;
}

std::string serialize_file_seq_preamble(const FilePreamble &preamble) {
    return std::string("{") + "\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"," +
           "\"serialization_format\":\"application/qlog+json-seq\"," + "\"title\":\"" +
           escape_json_string(preamble.title) + "\"," + "\"description\":\"" +
           escape_json_string(preamble.description) + "\"," + "\"trace\":{" +
           "\"common_fields\":{" + "\"group_id\":\"" + escape_json_string(preamble.group_id) +
           "\"," + "\"time_format\":\"relative_to_epoch\"," +
           "\"reference_time\":{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}" + "}," +
           "\"vantage_point\":{\"type\":\"" + escape_json_string(preamble.vantage_point_type) +
           "\"}," + "\"event_schemas\":[\"" + escape_json_string(preamble.event_schemas.front()) +
           "\"]" + "}" + "}";
}

std::string make_json_seq_record(std::string_view json_object) {
    std::string out;
    out.reserve(json_object.size() + 2);
    out.push_back('\x1e');
    out.append(json_object);
    out.push_back('\n');
    return out;
}

std::string serialize_version_information(EndpointRole role,
                                          std::span<const std::uint32_t> supported_versions,
                                          std::optional<std::uint32_t> chosen_version) {
    std::string json = "{";
    json += role == EndpointRole::client ? "\"client_versions\":[" : "\"server_versions\":[";
    for (std::size_t index = 0; index < supported_versions.size(); ++index) {
        if (index != 0) {
            json.push_back(',');
        }
        json += std::to_string(supported_versions[index]);
    }
    json += "]";
    if (chosen_version.has_value()) {
        json += ",\"chosen_version\":" + std::to_string(*chosen_version);
    }
    json += "}";
    return json;
}

std::string
serialize_alpn_information(std::optional<std::span<const std::vector<std::byte>>> local_alpns,
                           std::optional<std::span<const std::vector<std::byte>>> peer_alpns,
                           std::optional<std::span<const std::byte>> chosen_alpn,
                           EndpointRole role) {
    std::string json = "{";
    bool needs_comma = false;
    const auto append_list = [&](std::string_view key,
                                 std::span<const std::vector<std::byte>> values) {
        if (needs_comma) {
            json.push_back(',');
        }
        json += "\"";
        json += key;
        json += "\":[";
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (index != 0) {
                json.push_back(',');
            }
            json += serialize_alpn_identifier(values[index]);
        }
        json += "]";
        needs_comma = true;
    };

    if (local_alpns.has_value()) {
        append_list(role == EndpointRole::client ? "client_alpns" : "server_alpns", *local_alpns);
    }
    if (peer_alpns.has_value()) {
        append_list(role == EndpointRole::client ? "server_alpns" : "client_alpns", *peer_alpns);
    }
    if (chosen_alpn.has_value()) {
        if (needs_comma) {
            json.push_back(',');
        }
        json += "\"chosen_alpn\":";
        json += serialize_alpn_identifier(*chosen_alpn);
    }
    json += "}";
    return json;
}

std::string serialize_parameters_set(std::string_view initiator,
                                     const TransportParameters &parameters) {
    std::string json = "{\"initiator\":\"" + escape_json_string(initiator) + "\"";
    const auto append_u64 = [&](std::string_view key, std::uint64_t value) {
        json += ",\"" + std::string(key) + "\":" + std::to_string(value);
    };
    const auto append_connection_id = [&](std::string_view key,
                                          const std::optional<ConnectionId> &value) {
        if (!value.has_value()) {
            return;
        }
        json += ",\"" + std::string(key) + "\":\"" + hex_bytes(*value) + "\"";
    };

    append_connection_id("original_destination_connection_id",
                         parameters.original_destination_connection_id);
    append_connection_id("initial_source_connection_id", parameters.initial_source_connection_id);
    append_connection_id("retry_source_connection_id", parameters.retry_source_connection_id);
    append_u64("max_idle_timeout", parameters.max_idle_timeout);
    append_u64("max_udp_payload_size", parameters.max_udp_payload_size);
    append_u64("ack_delay_exponent", parameters.ack_delay_exponent);
    append_u64("max_ack_delay", parameters.max_ack_delay);
    append_u64("active_connection_id_limit", parameters.active_connection_id_limit);
    append_u64("initial_max_data", parameters.initial_max_data);
    append_u64("initial_max_stream_data_bidi_local", parameters.initial_max_stream_data_bidi_local);
    append_u64("initial_max_stream_data_bidi_remote",
               parameters.initial_max_stream_data_bidi_remote);
    append_u64("initial_max_stream_data_uni", parameters.initial_max_stream_data_uni);
    append_u64("initial_max_streams_bidi", parameters.initial_max_streams_bidi);
    append_u64("initial_max_streams_uni", parameters.initial_max_streams_uni);
    json += "}";
    return json;
}

std::string serialize_packet_snapshot(const PacketSnapshot &snapshot) {
    std::string json = "{\"header\":{";
    json += "\"packet_type\":\"" + escape_json_string(snapshot.header.packet_type) + "\"";
    if (snapshot.header.packet_number_length.has_value()) {
        json +=
            ",\"packet_number_length\":" + std::to_string(*snapshot.header.packet_number_length);
    }
    if (snapshot.header.packet_number.has_value()) {
        json += ",\"packet_number\":" + std::to_string(*snapshot.header.packet_number);
    }
    if (snapshot.header.version.has_value()) {
        json += ",\"version\":" + std::to_string(*snapshot.header.version);
    }
    if (snapshot.header.length.has_value()) {
        json += ",\"length\":" + std::to_string(*snapshot.header.length);
    }
    if (snapshot.header.spin_bit.has_value()) {
        json += ",\"spin_bit\":" + std::string(*snapshot.header.spin_bit ? "true" : "false");
    }
    if (snapshot.header.key_phase.has_value()) {
        json += ",\"key_phase\":" + std::to_string(*snapshot.header.key_phase);
    }
    if (snapshot.header.scid.has_value()) {
        json += ",\"scid\":\"" + hex_bytes(*snapshot.header.scid) + "\"";
    }
    if (snapshot.header.dcid.has_value()) {
        json += ",\"dcid\":\"" + hex_bytes(*snapshot.header.dcid) + "\"";
    }
    if (snapshot.header.token.has_value()) {
        json += ",\"token\":\"" + hex_bytes(*snapshot.header.token) + "\"";
    }
    json += "},\"frames\":[";
    for (std::size_t index = 0; index < snapshot.frames.size(); ++index) {
        if (index != 0) {
            json.push_back(',');
        }
        json += serialize_frame_json(snapshot.frames[index]);
    }
    json += "],\"raw\":{\"length\":" + std::to_string(snapshot.raw_length) + "}";
    if (snapshot.datagram_id.has_value()) {
        json += ",\"datagram_id\":" + std::to_string(*snapshot.datagram_id);
    }
    if (snapshot.trigger.has_value()) {
        json += ",\"trigger\":\"" + escape_json_string(*snapshot.trigger) + "\"";
    }
    json += "}";
    return json;
}

std::string serialize_recovery_metrics(const RecoveryMetricsSnapshot &metrics) {
    std::string json = "{";
    bool needs_comma = false;
    const auto append_number = [&](std::string_view key, auto value) {
        if (needs_comma) {
            json.push_back(',');
        }
        json += "\"";
        json += key;
        json += "\":";
        json += std::to_string(value);
        needs_comma = true;
    };
    if (metrics.min_rtt_ms.has_value()) {
        append_number("min_rtt", *metrics.min_rtt_ms);
    }
    if (metrics.smoothed_rtt_ms.has_value()) {
        append_number("smoothed_rtt", *metrics.smoothed_rtt_ms);
    }
    if (metrics.latest_rtt_ms.has_value()) {
        append_number("latest_rtt", *metrics.latest_rtt_ms);
    }
    if (metrics.rtt_variance_ms.has_value()) {
        append_number("rtt_variance", *metrics.rtt_variance_ms);
    }
    if (metrics.pto_count.has_value()) {
        append_number("pto_count", *metrics.pto_count);
    }
    if (metrics.congestion_window.has_value()) {
        append_number("congestion_window", *metrics.congestion_window);
    }
    if (metrics.bytes_in_flight.has_value()) {
        append_number("bytes_in_flight", *metrics.bytes_in_flight);
    }
    json += "}";
    return json;
}

} // namespace coquic::quic::qlog
