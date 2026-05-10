#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/core.h"
#include "src/quic/protected_codec.h"
#include "src/quic/version.h"

namespace {

using namespace coquic::quic;

constexpr std::int32_t kErrorInvalidArgument = -1;
constexpr std::int32_t kErrorBufferTooSmall = -2;
constexpr std::int32_t kErrorNotFound = -3;
constexpr std::int32_t kErrorUnsupported = -4;
constexpr std::size_t kDatagramHeaderSize = 40;
constexpr std::size_t kEventHeaderSize = 48;
constexpr std::size_t kPacketInspectionHeaderSize = 48;
constexpr QuicRouteHandle kDefaultRouteHandle = 1;
constexpr std::size_t kDemoEthernetMtuBytes = 1500;
constexpr std::size_t kDemoIpv6HeaderBytes = 40;
constexpr std::size_t kDemoUdpHeaderBytes = 8;
constexpr std::size_t kDemoMaxUdpPayloadSize =
    kDemoEthernetMtuBytes - kDemoIpv6HeaderBytes - kDemoUdpHeaderBytes;
constexpr std::uint64_t kDemoInitialMaxData = 512;
constexpr std::uint64_t kDemoInitialMaxStreamData = 512;

enum class WasmEventType : std::uint32_t {
    state = 1,
    lifecycle = 2,
    receive_stream = 3,
    local_error = 4,
    peer_reset_stream = 5,
    peer_stop_sending = 6,
    zero_rtt_status = 7,
    resumption_state_available = 8,
    peer_preferred_address_available = 9,
};

struct PendingDatagram {
    QuicConnectionHandle connection = 0;
    bool has_route_handle = false;
    QuicRouteHandle route_handle = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
    bool is_pmtu_probe = false;
    std::uint64_t packet_inspection_datagram_id = 0;
    std::vector<std::byte> bytes;
};

struct PendingEvent {
    WasmEventType type = WasmEventType::state;
    std::uint32_t code = 0;
    QuicConnectionHandle connection = 0;
    std::uint64_t stream_id = 0;
    bool fin = false;
    std::uint64_t value = 0;
    std::vector<std::byte> payload;
};

struct PendingPacketInspection {
    QuicConnectionHandle connection = 0;
    std::uint32_t direction = 0;
    std::uint32_t packet_type = 0;
    std::uint64_t packet_number = 0;
    std::uint64_t datagram_id = 0;
    std::uint32_t packet_length = 0;
    std::vector<std::byte> payload;
};

struct WasmEndpoint {
    EndpointRole role = EndpointRole::client;
    QuicCore core;
    std::deque<PendingDatagram> datagrams;
    std::deque<PendingEvent> events;
    std::deque<PendingPacketInspection> packet_inspections;

    explicit WasmEndpoint(QuicCoreEndpointConfig config)
        : role(config.role), core(std::move(config)) {
    }
};

bool valid_const(const std::uint8_t *ptr, std::size_t len) {
    return ptr != nullptr || len == 0;
}

bool valid_mut(std::uint8_t *ptr, std::size_t len) {
    return ptr != nullptr || len == 0;
}

std::vector<std::unique_ptr<WasmEndpoint>> &endpoint_registry() {
    static auto *registry = new std::vector<std::unique_ptr<WasmEndpoint>>();
    return *registry;
}

WasmEndpoint *endpoint_from_id(std::uint32_t id) {
    auto &registry = endpoint_registry();
    if (id == 0 || id > registry.size()) {
        return nullptr;
    }
    return registry[id - 1].get();
}

std::uint32_t register_endpoint(std::unique_ptr<WasmEndpoint> endpoint) {
    auto &registry = endpoint_registry();
    for (std::size_t index = 0; index < registry.size(); ++index) {
        if (registry[index] == nullptr) {
            registry[index] = std::move(endpoint);
            return static_cast<std::uint32_t>(index + 1);
        }
    }
    registry.push_back(std::move(endpoint));
    return static_cast<std::uint32_t>(registry.size());
}

QuicCoreTimePoint time_from_ms(std::uint64_t now_ms) {
    return QuicCoreTimePoint{} + std::chrono::milliseconds(now_ms);
}

std::int64_t ms_from_time(QuicCoreTimePoint time) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
}

std::optional<std::span<const std::byte>> input_bytes(const std::uint8_t *input,
                                                      std::size_t input_len) {
    if (!valid_const(input, input_len)) {
        return std::nullopt;
    }
    return std::span<const std::byte>(reinterpret_cast<const std::byte *>(input), input_len);
}

std::optional<std::vector<std::byte>> input_vector(const std::uint8_t *input,
                                                   std::size_t input_len) {
    const auto bytes = input_bytes(input, input_len);
    if (!bytes.has_value()) {
        return std::nullopt;
    }
    return std::vector<std::byte>(bytes->begin(), bytes->end());
}

std::optional<std::string> input_string(const std::uint8_t *input, std::size_t input_len) {
    if (!valid_const(input, input_len)) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char *>(input), input_len);
}

ConnectionId connection_id_from_input(const std::uint8_t *input, std::size_t input_len,
                                      std::initializer_list<std::byte> fallback) {
    if (input_len == 0) {
        return ConnectionId(fallback.begin(), fallback.end());
    }
    auto bytes = input_vector(input, input_len);
    if (!bytes.has_value()) {
        return {};
    }
    return ConnectionId(bytes->begin(), bytes->end());
}

QuicCoreEndpointConfig endpoint_config(EndpointRole role, std::optional<TlsIdentity> identity) {
    QuicCoreEndpointConfig config{
        .role = role,
        .verify_peer = false,
        .application_protocol = "coquic-wasm",
        .identity = std::move(identity),
        .max_outbound_datagram_size = kDemoMaxUdpPayloadSize,
    };
    config.transport.pmtud_enabled = false;
    config.transport.max_udp_payload_size = kDemoMaxUdpPayloadSize;
    config.transport.initial_max_data = kDemoInitialMaxData;
    config.transport.initial_max_stream_data_bidi_local = kDemoInitialMaxStreamData;
    config.transport.initial_max_stream_data_bidi_remote = kDemoInitialMaxStreamData;
    config.transport.initial_max_stream_data_uni = kDemoInitialMaxStreamData;
    config.enable_packet_inspection = true;
    return config;
}

void append_payload(std::vector<std::byte> &out, std::span<const std::byte> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_json_string(std::string &out, std::string_view value) {
    out.push_back('"');
    for (const char ch : value) {
        switch (ch) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
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
            if (static_cast<unsigned char>(ch) < 0x20) {
                out += "\\u00";
                constexpr char kHex[] = "0123456789abcdef";
                out.push_back(kHex[(static_cast<unsigned char>(ch) >> 4) & 0x0f]);
                out.push_back(kHex[static_cast<unsigned char>(ch) & 0x0f]);
            } else {
                out.push_back(ch);
            }
            break;
        }
    }
    out.push_back('"');
}

std::string hex_bytes(std::span<const std::byte> bytes, std::size_t limit = 64) {
    constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    const auto used = std::min(bytes.size(), limit);
    out.reserve(used * 2);
    for (std::size_t i = 0; i < used; ++i) {
        const auto byte = static_cast<std::uint8_t>(bytes[i]);
        out.push_back(kHex[(byte >> 4) & 0x0f]);
        out.push_back(kHex[byte & 0x0f]);
    }
    return out;
}

template <std::size_t Size> std::string hex_array(const std::array<std::byte, Size> &bytes) {
    return hex_bytes(std::span<const std::byte>(bytes.data(), bytes.size()), bytes.size());
}

void append_json_u64_field(std::string &out, std::string_view key, std::uint64_t value) {
    out.push_back(',');
    append_json_string(out, key);
    out.push_back(':');
    out += std::to_string(value);
}

void append_json_first_u64_field(std::string &out, std::string_view key, std::uint64_t value) {
    append_json_string(out, key);
    out.push_back(':');
    out += std::to_string(value);
}

void append_json_bool_field(std::string &out, std::string_view key, bool value) {
    out.push_back(',');
    append_json_string(out, key);
    out.push_back(':');
    out += value ? "true" : "false";
}

void append_json_first_string_field(std::string &out, std::string_view key,
                                    std::string_view value) {
    append_json_string(out, key);
    out.push_back(':');
    append_json_string(out, value);
}

void append_json_string_field(std::string &out, std::string_view key, std::string_view value) {
    out.push_back(',');
    append_json_string(out, key);
    out.push_back(':');
    append_json_string(out, value);
}

void append_json_string_field(std::string &out, std::string_view key, const std::string &value) {
    append_json_string_field(out, key, std::string_view(value.data(), value.size()));
}

void append_json_optional_u64_field(std::string &out, std::string_view key,
                                    std::optional<std::uint64_t> value) {
    out.push_back(',');
    append_json_string(out, key);
    out.push_back(':');
    if (value.has_value()) {
        out += std::to_string(*value);
    } else {
        out += "null";
    }
}

void append_json_hex_field(std::string &out, std::string_view key, std::span<const std::byte> value,
                           std::size_t limit = std::numeric_limits<std::size_t>::max()) {
    const auto used = std::min(value.size(), limit);
    append_json_string_field(out, key, hex_bytes(value, used));
}

std::string_view packet_type_name(QuicCorePacketInspectionPacketType packet_type) {
    switch (packet_type) {
    case QuicCorePacketInspectionPacketType::initial:
        return "Initial";
    case QuicCorePacketInspectionPacketType::zero_rtt:
        return "0-RTT";
    case QuicCorePacketInspectionPacketType::handshake:
        return "Handshake";
    case QuicCorePacketInspectionPacketType::one_rtt:
        return "1-RTT";
    }
    return "Unknown";
}

std::string_view inspection_direction_name(QuicCorePacketInspectionDirection direction) {
    switch (direction) {
    case QuicCorePacketInspectionDirection::outbound:
        return "outbound";
    case QuicCorePacketInspectionDirection::inbound:
        return "inbound";
    }
    return "unknown";
}

std::string_view handshake_status_name(std::uint8_t status) {
    switch (status) {
    case 0:
        return "idle";
    case 1:
        return "in_progress";
    case 2:
        return "connected";
    case 3:
        return "failed";
    }
    return "unknown";
}

std::string_view stream_initiator_name(std::uint8_t initiator) {
    switch (initiator) {
    case 0:
        return "local";
    case 1:
        return "peer";
    }
    return "unknown";
}

std::string_view stream_direction_name(std::uint8_t direction) {
    switch (direction) {
    case 0:
        return "bidi";
    case 1:
        return "uni";
    }
    return "unknown";
}

std::string_view stream_fin_state_name(std::uint8_t state) {
    switch (state) {
    case 0:
        return "none";
    case 1:
        return "pending";
    case 2:
        return "sent";
    case 3:
        return "acknowledged";
    }
    return "unknown";
}

std::string_view control_frame_state_name(std::uint8_t state) {
    switch (state) {
    case 0:
        return "none";
    case 1:
        return "pending";
    case 2:
        return "sent";
    case 3:
        return "acknowledged";
    }
    return "unknown";
}

std::string_view received_frame_name(const ReceivedFrame &frame) {
    switch (frame.index()) {
    case 0:
        return "PADDING";
    case 1:
        return "PING";
    case 2:
        return "ACK";
    case 3:
        return "RESET_STREAM";
    case 4:
        return "STOP_SENDING";
    case 5:
        return "CRYPTO";
    case 6:
        return "NEW_TOKEN";
    case 7:
        return "STREAM";
    case 8:
        return "MAX_DATA";
    case 9:
        return "MAX_STREAM_DATA";
    case 10:
        return "MAX_STREAMS";
    case 11:
        return "DATA_BLOCKED";
    case 12:
        return "STREAM_DATA_BLOCKED";
    case 13:
        return "STREAMS_BLOCKED";
    case 14:
        return "NEW_CONNECTION_ID";
    case 15:
        return "RETIRE_CONNECTION_ID";
    case 16:
        return "PATH_CHALLENGE";
    case 17:
        return "PATH_RESPONSE";
    case 18:
        return "CONNECTION_CLOSE";
    case 19:
        return "APPLICATION_CLOSE";
    case 20:
        return "HANDSHAKE_DONE";
    default:
        return "UNKNOWN";
    }
}

void append_packet_space_json(std::string &out, std::string_view name,
                              const QuicCorePacketSpaceDiagnostics &space) {
    out.push_back('{');
    append_json_first_string_field(out, "name", name);
    append_json_u64_field(out, "next_send_packet_number", space.next_send_packet_number);
    append_json_optional_u64_field(out, "largest_authenticated_packet_number",
                                   space.largest_authenticated_packet_number);
    append_json_bool_field(out, "read_secret_available", space.read_secret_available);
    append_json_bool_field(out, "write_secret_available", space.write_secret_available);
    append_json_bool_field(out, "pending_crypto", space.pending_crypto);
    append_json_u64_field(out, "outstanding_packets", space.outstanding_packets);
    append_json_u64_field(out, "declared_lost_packets", space.declared_lost_packets);
    append_json_bool_field(out, "pending_probe", space.pending_probe);
    append_json_optional_u64_field(out, "pending_ack_deadline_ms",
                                   space.pending_ack_deadline.has_value()
                                       ? std::optional<std::uint64_t>(static_cast<std::uint64_t>(
                                             ms_from_time(*space.pending_ack_deadline)))
                                       : std::nullopt);
    append_json_bool_field(out, "force_ack", space.force_ack);
    out.push_back('}');
}

std::string diagnostics_json(EndpointRole role,
                             std::span<const QuicCoreConnectionDiagnostics> connections) {
    std::string out = "{\"ok\":true";
    append_json_string_field(out, "role",
                             std::string_view(role == EndpointRole::client ? "client" : "server"));
    append_json_u64_field(out, "connection_count", connections.size());
    out += ",\"connections\":[";
    for (std::size_t index = 0; index < connections.size(); ++index) {
        if (index != 0) {
            out.push_back(',');
        }
        const auto &connection = connections[index];
        out.push_back('{');
        append_json_first_u64_field(out, "handle", connection.handle);
        append_json_string_field(out, "handshake_status",
                                 handshake_status_name(connection.handshake_status));
        append_json_bool_field(out, "started", connection.started);
        append_json_bool_field(out, "processed_peer_packet", connection.processed_peer_packet);
        append_json_bool_field(out, "handshake_ready_emitted", connection.handshake_ready_emitted);
        append_json_bool_field(out, "handshake_confirmed", connection.handshake_confirmed);
        append_json_bool_field(out, "handshake_confirmed_emitted",
                               connection.handshake_confirmed_emitted);
        append_json_bool_field(out, "failed_emitted", connection.failed_emitted);
        append_json_bool_field(out, "peer_transport_parameters_validated",
                               connection.peer_transport_parameters_validated);
        append_json_bool_field(out, "peer_address_validated", connection.peer_address_validated);
        append_json_u64_field(out, "current_version", connection.current_version);
        append_json_u64_field(out, "anti_amplification_received_bytes",
                              connection.anti_amplification_received_bytes);
        append_json_u64_field(out, "anti_amplification_sent_bytes",
                              connection.anti_amplification_sent_bytes);
        append_json_u64_field(out, "active_paths", connection.active_paths);
        append_json_optional_u64_field(out, "current_send_path_id",
                                       connection.current_send_path_id);
        append_json_u64_field(out, "active_streams", connection.active_streams);
        append_json_u64_field(out, "retired_streams", connection.retired_streams);

        out += ",\"packet_spaces\":[";
        append_packet_space_json(out, "Initial", connection.initial_space);
        out.push_back(',');
        append_packet_space_json(out, "Handshake", connection.handshake_space);
        out.push_back(',');
        append_packet_space_json(out, "0-RTT", connection.zero_rtt_space);
        out.push_back(',');
        append_packet_space_json(out, "1-RTT", connection.application_space);
        out.push_back(']');

        out += ",\"recovery\":{";
        append_json_first_string_field(
            out, "algorithm", congestion_control_algorithm_name(connection.recovery.algorithm));
        append_json_u64_field(out, "congestion_window", connection.recovery.congestion_window);
        append_json_u64_field(out, "bytes_in_flight", connection.recovery.bytes_in_flight);
        append_json_u64_field(out, "pto_count", connection.recovery.pto_count);
        append_json_optional_u64_field(out, "latest_rtt_ms", connection.recovery.latest_rtt_ms);
        append_json_optional_u64_field(out, "min_rtt_ms", connection.recovery.min_rtt_ms);
        append_json_u64_field(out, "smoothed_rtt_ms", connection.recovery.smoothed_rtt_ms);
        append_json_u64_field(out, "rttvar_ms", connection.recovery.rttvar_ms);
        out.push_back('}');

        out += ",\"flow_control\":{";
        append_json_first_u64_field(out, "peer_max_data", connection.flow_control.peer_max_data);
        append_json_u64_field(out, "highest_sent", connection.flow_control.highest_sent);
        append_json_u64_field(out, "advertised_max_data",
                              connection.flow_control.advertised_max_data);
        append_json_u64_field(out, "delivered_bytes", connection.flow_control.delivered_bytes);
        append_json_u64_field(out, "received_committed",
                              connection.flow_control.received_committed);
        out.push_back('}');

        out += ",\"stream_limits\":{";
        append_json_first_u64_field(out, "peer_max_bidirectional",
                                    connection.stream_limits.peer_max_bidirectional);
        append_json_u64_field(out, "peer_max_unidirectional",
                              connection.stream_limits.peer_max_unidirectional);
        append_json_u64_field(out, "advertised_max_bidirectional",
                              connection.stream_limits.advertised_max_bidirectional);
        append_json_u64_field(out, "advertised_max_unidirectional",
                              connection.stream_limits.advertised_max_unidirectional);
        out.push_back('}');

        out += ",\"streams\":[";
        for (std::size_t stream_index = 0; stream_index < connection.streams.size();
             ++stream_index) {
            if (stream_index != 0) {
                out.push_back(',');
            }
            const auto &stream = connection.streams[stream_index];
            out.push_back('{');
            append_json_first_u64_field(out, "stream_id", stream.stream_id);
            append_json_string_field(out, "initiator", stream_initiator_name(stream.initiator));
            append_json_string_field(out, "direction", stream_direction_name(stream.direction));
            append_json_bool_field(out, "local_can_send", stream.local_can_send);
            append_json_bool_field(out, "local_can_receive", stream.local_can_receive);
            append_json_bool_field(out, "send_closed", stream.send_closed);
            append_json_bool_field(out, "receive_closed", stream.receive_closed);
            append_json_bool_field(out, "peer_send_closed", stream.peer_send_closed);
            append_json_bool_field(out, "peer_fin_delivered", stream.peer_fin_delivered);
            append_json_bool_field(out, "peer_reset_received", stream.peer_reset_received);
            append_json_string_field(out, "send_fin_state",
                                     stream_fin_state_name(stream.send_fin_state));
            append_json_string_field(out, "reset_state",
                                     control_frame_state_name(stream.reset_state));
            append_json_string_field(out, "stop_sending_state",
                                     control_frame_state_name(stream.stop_sending_state));
            append_json_bool_field(out, "pending_send", stream.pending_send);
            append_json_bool_field(out, "outstanding_send", stream.outstanding_send);
            append_json_u64_field(out, "sendable_bytes", stream.sendable_bytes);
            append_json_u64_field(out, "send_flow_control_limit", stream.send_flow_control_limit);
            append_json_u64_field(out, "receive_flow_control_limit",
                                  stream.receive_flow_control_limit);
            append_json_u64_field(out, "highest_received_offset", stream.highest_received_offset);
            append_json_u64_field(out, "receive_flow_control_consumed",
                                  stream.receive_flow_control_consumed);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
    }
    out += "]}";
    return out;
}

void append_received_frame_json(std::string &out, const ReceivedFrame &frame) {
    out += "{\"type\":";
    append_json_string(out, received_frame_name(frame));
    std::visit(
        [&](const auto &typed) {
            using T = std::decay_t<decltype(typed)>;
            if constexpr (std::is_same_v<T, PaddingFrame>) {
                append_json_u64_field(out, "length", typed.length);
            } else if constexpr (std::is_same_v<T, ReceivedAckFrame>) {
                append_json_u64_field(out, "largest_acknowledged", typed.largest_acknowledged);
                append_json_u64_field(out, "ack_delay", typed.ack_delay);
                append_json_u64_field(out, "first_ack_range", typed.first_ack_range);
                append_json_u64_field(out, "additional_range_count", typed.additional_range_count);
                if (typed.ecn_counts.has_value()) {
                    append_json_u64_field(out, "ect0", typed.ecn_counts->ect0);
                    append_json_u64_field(out, "ect1", typed.ecn_counts->ect1);
                    append_json_u64_field(out, "ecn_ce", typed.ecn_counts->ecn_ce);
                }
            } else if constexpr (std::is_same_v<T, ResetStreamFrame>) {
                append_json_u64_field(out, "stream_id", typed.stream_id);
                append_json_u64_field(out, "application_error",
                                      typed.application_protocol_error_code);
                append_json_u64_field(out, "final_size", typed.final_size);
            } else if constexpr (std::is_same_v<T, StopSendingFrame>) {
                append_json_u64_field(out, "stream_id", typed.stream_id);
                append_json_u64_field(out, "application_error",
                                      typed.application_protocol_error_code);
            } else if constexpr (std::is_same_v<T, ReceivedCryptoFrame>) {
                append_json_u64_field(out, "offset", typed.offset);
                append_json_u64_field(out, "length", typed.crypto_data.size());
                append_json_string_field(out, "preview", hex_bytes(typed.crypto_data.span(), 32));
            } else if constexpr (std::is_same_v<T, NewTokenFrame>) {
                append_json_u64_field(out, "length", typed.token.size());
                append_json_string_field(out, "preview",
                                         hex_bytes(std::span<const std::byte>(typed.token), 32));
            } else if constexpr (std::is_same_v<T, ReceivedStreamFrame>) {
                append_json_u64_field(out, "stream_id", typed.stream_id);
                append_json_bool_field(out, "fin", typed.fin);
                append_json_bool_field(out, "has_offset", typed.has_offset);
                append_json_bool_field(out, "has_length", typed.has_length);
                append_json_u64_field(out, "offset", typed.offset.value_or(0));
                append_json_u64_field(out, "length", typed.stream_data.size());
            } else if constexpr (std::is_same_v<T, MaxDataFrame>) {
                append_json_u64_field(out, "maximum_data", typed.maximum_data);
            } else if constexpr (std::is_same_v<T, MaxStreamDataFrame>) {
                append_json_u64_field(out, "stream_id", typed.stream_id);
                append_json_u64_field(out, "maximum_stream_data", typed.maximum_stream_data);
            } else if constexpr (std::is_same_v<T, MaxStreamsFrame>) {
                append_json_string_field(
                    out, "stream_type",
                    std::string_view(typed.stream_type == StreamLimitType::bidirectional
                                         ? "bidirectional"
                                         : "unidirectional"));
                append_json_u64_field(out, "maximum_streams", typed.maximum_streams);
            } else if constexpr (std::is_same_v<T, DataBlockedFrame>) {
                append_json_u64_field(out, "maximum_data", typed.maximum_data);
            } else if constexpr (std::is_same_v<T, StreamDataBlockedFrame>) {
                append_json_u64_field(out, "stream_id", typed.stream_id);
                append_json_u64_field(out, "maximum_stream_data", typed.maximum_stream_data);
            } else if constexpr (std::is_same_v<T, StreamsBlockedFrame>) {
                append_json_string_field(
                    out, "stream_type",
                    std::string_view(typed.stream_type == StreamLimitType::bidirectional
                                         ? "bidirectional"
                                         : "unidirectional"));
                append_json_u64_field(out, "maximum_streams", typed.maximum_streams);
            } else if constexpr (std::is_same_v<T, NewConnectionIdFrame>) {
                append_json_u64_field(out, "sequence_number", typed.sequence_number);
                append_json_u64_field(out, "retire_prior_to", typed.retire_prior_to);
                append_json_u64_field(out, "connection_id_length", typed.connection_id.size());
                append_json_string_field(
                    out, "connection_id",
                    hex_bytes(std::span<const std::byte>(typed.connection_id.data(),
                                                         typed.connection_id.size()),
                              typed.connection_id.size()));
            } else if constexpr (std::is_same_v<T, RetireConnectionIdFrame>) {
                append_json_u64_field(out, "sequence_number", typed.sequence_number);
            } else if constexpr (std::is_same_v<T, PathChallengeFrame>) {
                append_json_string_field(out, "data", hex_array(typed.data));
            } else if constexpr (std::is_same_v<T, PathResponseFrame>) {
                append_json_string_field(out, "data", hex_array(typed.data));
            } else if constexpr (std::is_same_v<T, TransportConnectionCloseFrame>) {
                append_json_u64_field(out, "error_code", typed.error_code);
                append_json_u64_field(out, "frame_type", typed.frame_type);
                append_json_u64_field(out, "reason_length", typed.reason.bytes.size());
            } else if constexpr (std::is_same_v<T, ApplicationConnectionCloseFrame>) {
                append_json_u64_field(out, "error_code", typed.error_code);
                append_json_u64_field(out, "reason_length", typed.reason.bytes.size());
            }
        },
        frame);
    out.push_back('}');
}

std::string initial_packet_json(const ReceivedProtectedInitialPacket &packet) {
    std::string out;
    out += "{\"ok\":true,\"kind\":\"Initial\"";
    append_json_u64_field(out, "version", packet.version);
    append_json_string_field(
        out, "destination_connection_id",
        hex_bytes(std::span<const std::byte>(packet.destination_connection_id.data(),
                                             packet.destination_connection_id.size()),
                  packet.destination_connection_id.size()));
    append_json_string_field(
        out, "source_connection_id",
        hex_bytes(std::span<const std::byte>(packet.source_connection_id.data(),
                                             packet.source_connection_id.size()),
                  packet.source_connection_id.size()));
    append_json_u64_field(out, "token_length", packet.token.size());
    append_json_u64_field(out, "packet_number", packet.packet_number);
    append_json_u64_field(out, "packet_number_length", packet.packet_number_length);
    append_json_u64_field(out, "plaintext_payload_length",
                          packet.plaintext_storage ? packet.plaintext_storage->size() : 0);
    out += ",\"frames\":[";
    for (std::size_t i = 0; i < packet.frames.size(); ++i) {
        if (i != 0) {
            out.push_back(',');
        }
        append_received_frame_json(out, packet.frames[i]);
    }
    out += "]}";
    return out;
}

std::string packet_inspection_json(const QuicCorePacketInspection &inspection) {
    std::string out;
    out += "{\"ok\":true";
    append_json_u64_field(out, "connection", inspection.connection);
    append_json_string_field(out, "direction", inspection_direction_name(inspection.direction));
    append_json_string_field(out, "kind", packet_type_name(inspection.packet_type));
    append_json_u64_field(out, "datagram_id", inspection.datagram_id);
    append_json_u64_field(out, "datagram_length", inspection.datagram_length);
    append_json_u64_field(out, "datagram_offset", inspection.datagram_offset);
    append_json_u64_field(out, "packet_length", inspection.packet_length);
    append_json_u64_field(out, "version", inspection.version);
    append_json_hex_field(out, "destination_connection_id",
                          std::span<const std::byte>(inspection.destination_connection_id.data(),
                                                     inspection.destination_connection_id.size()),
                          inspection.destination_connection_id.size());
    append_json_hex_field(out, "source_connection_id",
                          std::span<const std::byte>(inspection.source_connection_id.data(),
                                                     inspection.source_connection_id.size()),
                          inspection.source_connection_id.size());
    append_json_u64_field(out, "token_length", inspection.token.size());
    append_json_bool_field(out, "spin_bit", inspection.spin_bit);
    append_json_bool_field(out, "key_phase", inspection.key_phase);
    append_json_u64_field(out, "packet_number", inspection.packet_number);
    append_json_u64_field(out, "packet_number_length", inspection.packet_number_length);
    append_json_u64_field(out, "plaintext_payload_length", inspection.plaintext_payload.size());
    append_json_hex_field(out, "plaintext_payload",
                          std::span<const std::byte>(inspection.plaintext_payload.data(),
                                                     inspection.plaintext_payload.size()),
                          256);
    append_json_u64_field(out, "encrypted_packet_length", inspection.encrypted_packet.size());
    append_json_hex_field(out, "encrypted_packet",
                          std::span<const std::byte>(inspection.encrypted_packet.data(),
                                                     inspection.encrypted_packet.size()),
                          256);
    out += ",\"frames\":[";
    for (std::size_t i = 0; i < inspection.frames.size(); ++i) {
        if (i != 0) {
            out.push_back(',');
        }
        append_received_frame_json(out, inspection.frames[i]);
    }
    out += "]}";
    return out;
}

void queue_result(WasmEndpoint &endpoint, QuicCoreResult result) {
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<QuicCoreSendDatagram>(&effect)) {
            PendingDatagram pending{
                .connection = send->connection,
                .has_route_handle = send->route_handle.has_value(),
                .route_handle = send->route_handle.value_or(0),
                .ecn = send->ecn,
                .is_pmtu_probe = send->is_pmtu_probe,
                .packet_inspection_datagram_id = send->packet_inspection_datagram_id,
            };
            append_payload(pending.bytes, send->bytes.span());
            endpoint.datagrams.push_back(std::move(pending));
            continue;
        }

        if (const auto *inspection = std::get_if<QuicCorePacketInspection>(&effect)) {
            const auto json = packet_inspection_json(*inspection);
            endpoint.packet_inspections.push_back(PendingPacketInspection{
                .connection = inspection->connection,
                .direction = static_cast<std::uint32_t>(inspection->direction),
                .packet_type = static_cast<std::uint32_t>(inspection->packet_type),
                .packet_number = inspection->packet_number,
                .datagram_id = inspection->datagram_id,
                .packet_length = static_cast<std::uint32_t>(inspection->packet_length),
                .payload = std::vector<std::byte>(reinterpret_cast<const std::byte *>(json.data()),
                                                  reinterpret_cast<const std::byte *>(json.data()) +
                                                      json.size()),
            });
            continue;
        }

        if (const auto *received = std::get_if<QuicCoreReceiveStreamData>(&effect)) {
            PendingEvent pending{
                .type = WasmEventType::receive_stream,
                .connection = received->connection,
                .stream_id = received->stream_id,
                .fin = received->fin,
            };
            append_payload(pending.payload, received->payload());
            endpoint.events.push_back(std::move(pending));
            continue;
        }

        if (const auto *state = std::get_if<QuicCoreStateEvent>(&effect)) {
            endpoint.events.push_back(PendingEvent{
                .type = WasmEventType::state,
                .code = static_cast<std::uint32_t>(state->change),
                .connection = state->connection,
            });
            continue;
        }

        if (const auto *lifecycle = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect)) {
            endpoint.events.push_back(PendingEvent{
                .type = WasmEventType::lifecycle,
                .code = static_cast<std::uint32_t>(lifecycle->event),
                .connection = lifecycle->connection,
            });
            continue;
        }

        if (const auto *reset = std::get_if<QuicCorePeerResetStream>(&effect)) {
            endpoint.events.push_back(PendingEvent{
                .type = WasmEventType::peer_reset_stream,
                .code = static_cast<std::uint32_t>(reset->application_error_code),
                .connection = reset->connection,
                .stream_id = reset->stream_id,
                .value = reset->final_size,
            });
            continue;
        }

        if (const auto *stop = std::get_if<QuicCorePeerStopSending>(&effect)) {
            endpoint.events.push_back(PendingEvent{
                .type = WasmEventType::peer_stop_sending,
                .code = static_cast<std::uint32_t>(stop->application_error_code),
                .connection = stop->connection,
                .stream_id = stop->stream_id,
            });
            continue;
        }

        if (const auto *zero_rtt = std::get_if<QuicCoreZeroRttStatusEvent>(&effect)) {
            endpoint.events.push_back(PendingEvent{
                .type = WasmEventType::zero_rtt_status,
                .code = static_cast<std::uint32_t>(zero_rtt->status),
                .connection = zero_rtt->connection,
            });
            continue;
        }

        if (const auto *resumption = std::get_if<QuicCoreResumptionStateAvailable>(&effect)) {
            endpoint.events.push_back(PendingEvent{
                .type = WasmEventType::resumption_state_available,
                .connection = resumption->connection,
            });
            continue;
        }

        if (const auto *preferred = std::get_if<QuicCorePeerPreferredAddressAvailable>(&effect)) {
            endpoint.events.push_back(PendingEvent{
                .type = WasmEventType::peer_preferred_address_available,
                .connection = preferred->connection,
            });
            continue;
        }
    }

    if (result.local_error.has_value()) {
        endpoint.events.push_back(PendingEvent{
            .type = WasmEventType::local_error,
            .code = static_cast<std::uint32_t>(result.local_error->code),
            .connection = result.local_error->connection.value_or(0),
            .stream_id = result.local_error->stream_id.value_or(0),
        });
    }
}

std::int32_t copy_bytes(std::span<const std::byte> input, std::uint8_t *output,
                        std::size_t output_len) {
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
        return kErrorBufferTooSmall;
    }
    if (!valid_mut(output, output_len)) {
        return kErrorInvalidArgument;
    }
    if (output_len < input.size()) {
        return kErrorBufferTooSmall;
    }
    if (!input.empty()) {
        std::memcpy(output, input.data(), input.size());
    }
    return static_cast<std::int32_t>(input.size());
}

void write_u32(std::uint8_t *out, std::size_t offset, std::uint32_t value) {
    out[offset + 0] = static_cast<std::uint8_t>(value & 0xffu);
    out[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
    out[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xffu);
    out[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xffu);
}

void write_u64(std::uint8_t *out, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        out[offset + i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xffu);
    }
}

std::int32_t write_datagram_header(const PendingDatagram &datagram, std::uint8_t *output,
                                   std::size_t output_len) {
    if (!valid_mut(output, output_len)) {
        return kErrorInvalidArgument;
    }
    if (output_len < kDatagramHeaderSize ||
        datagram.bytes.size() > std::numeric_limits<std::uint32_t>::max()) {
        return kErrorBufferTooSmall;
    }
    std::memset(output, 0, kDatagramHeaderSize);
    write_u64(output, 0, datagram.connection);
    write_u64(output, 8, datagram.route_handle);
    write_u32(output, 16, datagram.has_route_handle ? 1 : 0);
    write_u32(output, 20, static_cast<std::uint32_t>(datagram.ecn));
    write_u32(output, 24, datagram.is_pmtu_probe ? 1 : 0);
    write_u32(output, 28, static_cast<std::uint32_t>(datagram.bytes.size()));
    write_u64(output, 32, datagram.packet_inspection_datagram_id);
    return 1;
}

std::int32_t write_event_header(const PendingEvent &event, std::uint8_t *output,
                                std::size_t output_len) {
    if (!valid_mut(output, output_len)) {
        return kErrorInvalidArgument;
    }
    if (output_len < kEventHeaderSize ||
        event.payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        return kErrorBufferTooSmall;
    }
    std::memset(output, 0, kEventHeaderSize);
    write_u32(output, 0, static_cast<std::uint32_t>(event.type));
    write_u32(output, 4, event.code);
    write_u64(output, 8, event.connection);
    write_u64(output, 16, event.stream_id);
    write_u32(output, 24, event.fin ? 1 : 0);
    write_u32(output, 28, static_cast<std::uint32_t>(event.payload.size()));
    write_u64(output, 32, event.value);
    return 1;
}

std::int32_t write_packet_inspection_header(const PendingPacketInspection &inspection,
                                            std::uint8_t *output, std::size_t output_len) {
    if (!valid_mut(output, output_len)) {
        return kErrorInvalidArgument;
    }
    if (output_len < kPacketInspectionHeaderSize ||
        inspection.payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        return kErrorBufferTooSmall;
    }
    std::memset(output, 0, kPacketInspectionHeaderSize);
    write_u64(output, 0, inspection.connection);
    write_u32(output, 8, inspection.direction);
    write_u32(output, 12, inspection.packet_type);
    write_u64(output, 16, inspection.packet_number);
    write_u64(output, 24, inspection.datagram_id);
    write_u32(output, 32, inspection.packet_length);
    write_u32(output, 36, static_cast<std::uint32_t>(inspection.payload.size()));
    return 1;
}

} // namespace

extern "C" {

__attribute__((export_name("coquic_wasm_version"))) std::uint32_t coquic_wasm_version() {
    return coquic::quic::kQuicVersion1;
}

__attribute__((export_name("coquic_wasm_alloc"))) std::uint8_t *
coquic_wasm_alloc(std::size_t size) {
    return static_cast<std::uint8_t *>(std::malloc(size));
}

__attribute__((export_name("coquic_wasm_free"))) void coquic_wasm_free(std::uint8_t *pointer) {
    std::free(pointer);
}

__attribute__((export_name("coquic_wasm_endpoint_create"))) std::uint32_t
coquic_wasm_endpoint_create(std::int32_t role_id, const std::uint8_t *certificate_pem,
                            std::size_t certificate_pem_len, const std::uint8_t *private_key_pem,
                            std::size_t private_key_pem_len) {
    std::optional<TlsIdentity> identity;
    EndpointRole role = EndpointRole::client;
    if (role_id == 0) {
        role = EndpointRole::client;
    } else if (role_id == 1) {
        role = EndpointRole::server;
        auto cert = input_string(certificate_pem, certificate_pem_len);
        auto key = input_string(private_key_pem, private_key_pem_len);
        if (!cert.has_value() || !key.has_value() || cert->empty() || key->empty()) {
            return 0;
        }
        identity = TlsIdentity{
            .certificate_pem = std::move(*cert),
            .private_key_pem = std::move(*key),
        };
    } else {
        return 0;
    }

    return register_endpoint(
        std::make_unique<WasmEndpoint>(endpoint_config(role, std::move(identity))));
}

__attribute__((export_name("coquic_wasm_endpoint_destroy"))) void
coquic_wasm_endpoint_destroy(std::uint32_t endpoint_id) {
    auto &registry = endpoint_registry();
    if (endpoint_id == 0 || endpoint_id > registry.size()) {
        return;
    }
    registry[endpoint_id - 1].reset();
}

__attribute__((export_name("coquic_wasm_endpoint_open_connection"))) std::int32_t
coquic_wasm_endpoint_open_connection(std::uint32_t endpoint_id, std::uint64_t now_ms,
                                     const std::uint8_t *initial_dcid, std::size_t initial_dcid_len,
                                     const std::uint8_t *source_cid, std::size_t source_cid_len,
                                     std::uint64_t route_handle) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr || endpoint->role != EndpointRole::client ||
        !valid_const(initial_dcid, initial_dcid_len) || !valid_const(source_cid, source_cid_len)) {
        return kErrorInvalidArgument;
    }

    QuicCoreClientConnectionConfig connection{
        .source_connection_id = connection_id_from_input(source_cid, source_cid_len,
                                                         {std::byte{0xc1}, std::byte{0x01}}),
        .initial_destination_connection_id = connection_id_from_input(
            initial_dcid, initial_dcid_len,
            {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0}, std::byte{0x3e},
             std::byte{0x51}, std::byte{0x57}, std::byte{0x08}}),
        .server_name = "localhost",
    };
    if (connection.source_connection_id.empty() ||
        connection.initial_destination_connection_id.empty()) {
        return kErrorInvalidArgument;
    }

    auto result = endpoint->core.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = std::move(connection),
            .initial_route_handle = route_handle == 0 ? kDefaultRouteHandle : route_handle,
        },
        time_from_ms(now_ms));
    std::uint64_t created_connection = 0;
    for (const auto &effect : result.effects) {
        const auto *lifecycle = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
        if (lifecycle != nullptr && lifecycle->event == QuicCoreConnectionLifecycle::created) {
            created_connection = lifecycle->connection;
            break;
        }
    }
    queue_result(*endpoint, std::move(result));
    if (created_connection > static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())) {
        return kErrorUnsupported;
    }
    return static_cast<std::int32_t>(created_connection);
}

__attribute__((export_name("coquic_wasm_endpoint_input_datagram"))) std::int32_t
coquic_wasm_endpoint_input_datagram(std::uint32_t endpoint_id, std::uint64_t now_ms,
                                    const std::uint8_t *datagram, std::size_t datagram_len,
                                    std::uint64_t route_handle, std::uint32_t ecn) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    auto bytes = input_vector(datagram, datagram_len);
    if (endpoint == nullptr || !bytes.has_value() ||
        ecn > static_cast<std::uint32_t>(QuicEcnCodepoint::ce)) {
        return kErrorInvalidArgument;
    }

    auto result = endpoint->core.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = std::move(*bytes),
            .route_handle = route_handle == 0 ? std::optional<QuicRouteHandle>{}
                                              : std::optional<QuicRouteHandle>{route_handle},
            .ecn = static_cast<QuicEcnCodepoint>(ecn),
        },
        time_from_ms(now_ms));
    queue_result(*endpoint, std::move(result));
    return 0;
}

__attribute__((export_name("coquic_wasm_endpoint_send_stream"))) std::int32_t
coquic_wasm_endpoint_send_stream(std::uint32_t endpoint_id, std::uint64_t now_ms,
                                 std::uint64_t connection_handle, std::uint64_t stream_id,
                                 const std::uint8_t *data, std::size_t data_len, std::int32_t fin) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    auto bytes = input_vector(data, data_len);
    if (endpoint == nullptr || !bytes.has_value() || connection_handle == 0) {
        return kErrorInvalidArgument;
    }

    auto result = endpoint->core.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = connection_handle,
            .input =
                QuicCoreSendStreamData{
                    .stream_id = stream_id,
                    .bytes = std::move(*bytes),
                    .fin = fin != 0,
                },
        },
        time_from_ms(now_ms));
    queue_result(*endpoint, std::move(result));
    return 0;
}

__attribute__((export_name("coquic_wasm_endpoint_timer_expired"))) std::int32_t
coquic_wasm_endpoint_timer_expired(std::uint32_t endpoint_id, std::uint64_t now_ms) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return kErrorInvalidArgument;
    }
    auto result = endpoint->core.advance_endpoint(QuicCoreTimerExpired{}, time_from_ms(now_ms));
    queue_result(*endpoint, std::move(result));
    return 0;
}

__attribute__((export_name("coquic_wasm_endpoint_next_wakeup_ms"))) std::int64_t
coquic_wasm_endpoint_next_wakeup_ms(std::uint32_t endpoint_id) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return -1;
    }
    const auto wakeup = endpoint->core.next_wakeup();
    if (!wakeup.has_value()) {
        return -1;
    }
    return ms_from_time(*wakeup);
}

__attribute__((export_name("coquic_wasm_endpoint_next_datagram_header"))) std::int32_t
coquic_wasm_endpoint_next_datagram_header(std::uint32_t endpoint_id, std::uint8_t *output,
                                          std::size_t output_len) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return kErrorInvalidArgument;
    }
    if (endpoint->datagrams.empty()) {
        return 0;
    }
    return write_datagram_header(endpoint->datagrams.front(), output, output_len);
}

__attribute__((export_name("coquic_wasm_endpoint_pop_datagram"))) std::int32_t
coquic_wasm_endpoint_pop_datagram(std::uint32_t endpoint_id, std::uint8_t *output,
                                  std::size_t output_len) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return kErrorInvalidArgument;
    }
    if (endpoint->datagrams.empty()) {
        return kErrorNotFound;
    }
    const auto copied = copy_bytes(endpoint->datagrams.front().bytes, output, output_len);
    if (copied >= 0) {
        endpoint->datagrams.pop_front();
    }
    return copied;
}

__attribute__((export_name("coquic_wasm_endpoint_next_event_header"))) std::int32_t
coquic_wasm_endpoint_next_event_header(std::uint32_t endpoint_id, std::uint8_t *output,
                                       std::size_t output_len) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return kErrorInvalidArgument;
    }
    if (endpoint->events.empty()) {
        return 0;
    }
    return write_event_header(endpoint->events.front(), output, output_len);
}

__attribute__((export_name("coquic_wasm_endpoint_pop_event"))) std::int32_t
coquic_wasm_endpoint_pop_event(std::uint32_t endpoint_id, std::uint8_t *output,
                               std::size_t output_len) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return kErrorInvalidArgument;
    }
    if (endpoint->events.empty()) {
        return kErrorNotFound;
    }
    const auto copied = copy_bytes(endpoint->events.front().payload, output, output_len);
    if (copied >= 0) {
        endpoint->events.pop_front();
    }
    return copied;
}

__attribute__((export_name("coquic_wasm_endpoint_next_packet_inspection_header"))) std::int32_t
coquic_wasm_endpoint_next_packet_inspection_header(std::uint32_t endpoint_id, std::uint8_t *output,
                                                   std::size_t output_len) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return kErrorInvalidArgument;
    }
    if (endpoint->packet_inspections.empty()) {
        return 0;
    }
    return write_packet_inspection_header(endpoint->packet_inspections.front(), output, output_len);
}

__attribute__((export_name("coquic_wasm_endpoint_pop_packet_inspection"))) std::int32_t
coquic_wasm_endpoint_pop_packet_inspection(std::uint32_t endpoint_id, std::uint8_t *output,
                                           std::size_t output_len) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return kErrorInvalidArgument;
    }
    if (endpoint->packet_inspections.empty()) {
        return kErrorNotFound;
    }
    const auto copied =
        copy_bytes(endpoint->packet_inspections.front().payload, output, output_len);
    if (copied >= 0) {
        endpoint->packet_inspections.pop_front();
    }
    return copied;
}

__attribute__((export_name("coquic_wasm_endpoint_connection_count"))) std::uint64_t
coquic_wasm_endpoint_connection_count(std::uint32_t endpoint_id) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr) {
        return 0;
    }
    return endpoint->core.connection_count();
}

__attribute__((export_name("coquic_wasm_endpoint_diagnostics"))) std::int32_t
coquic_wasm_endpoint_diagnostics(std::uint32_t endpoint_id, std::uint8_t *output,
                                 std::size_t output_len) {
    auto *endpoint = endpoint_from_id(endpoint_id);
    if (endpoint == nullptr || !valid_mut(output, output_len)) {
        return kErrorInvalidArgument;
    }
    const auto diagnostics = endpoint->core.connection_diagnostics();
    const auto json = diagnostics_json(endpoint->role, diagnostics);
    if (json.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
        return kErrorBufferTooSmall;
    }
    if (output_len < json.size()) {
        return kErrorBufferTooSmall;
    }
    if (!json.empty()) {
        std::memcpy(output, json.data(), json.size());
    }
    return static_cast<std::int32_t>(json.size());
}

__attribute__((export_name("coquic_wasm_inspect_initial_packet"))) std::int32_t
coquic_wasm_inspect_initial_packet(std::int32_t peer_role_id, const std::uint8_t *datagram,
                                   std::size_t datagram_len,
                                   const std::uint8_t *client_initial_dcid,
                                   std::size_t client_initial_dcid_len, std::uint8_t *output,
                                   std::size_t output_len) {
    auto datagram_bytes = input_bytes(datagram, datagram_len);
    auto dcid_bytes = input_bytes(client_initial_dcid, client_initial_dcid_len);
    if (!datagram_bytes.has_value() || !dcid_bytes.has_value() || !valid_mut(output, output_len) ||
        (peer_role_id != 0 && peer_role_id != 1) || client_initial_dcid_len == 0) {
        return kErrorInvalidArgument;
    }

    DeserializeProtectionContext context{
        .peer_role = peer_role_id == 0 ? EndpointRole::client : EndpointRole::server,
        .client_initial_destination_connection_id =
            ConnectionId(dcid_bytes->begin(), dcid_bytes->end()),
    };
    auto decoded = deserialize_received_protected_packet(*datagram_bytes, context);
    std::string json;
    if (!decoded.has_value()) {
        json = "{\"ok\":false,\"error\":";
        json += std::to_string(static_cast<std::uint32_t>(decoded.error().code));
        json += ",\"offset\":";
        json += std::to_string(decoded.error().offset);
        json.push_back('}');
    } else if (const auto *initial =
                   std::get_if<ReceivedProtectedInitialPacket>(&decoded.value())) {
        json = initial_packet_json(*initial);
    } else {
        json = "{\"ok\":false,\"error\":\"not_initial\"}";
    }

    if (json.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
        return kErrorBufferTooSmall;
    }
    if (output_len < json.size()) {
        return kErrorBufferTooSmall;
    }
    if (!json.empty()) {
        std::memcpy(output, json.data(), json.size());
    }
    return static_cast<std::int32_t>(json.size());
}

} // extern "C"
