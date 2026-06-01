#include "src/perf/perf_protocol.h"

#include <type_traits>
#include <utility>

namespace coquic::perf {
namespace {

void append_u8(std::vector<std::byte> &out, std::uint8_t value) {
    out.push_back(static_cast<std::byte>(value));
}

void append_u32(std::vector<std::byte> &out, std::uint32_t value) {
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        out.push_back(static_cast<std::byte>((value >> ((sizeof(value) - 1 - i) * 8)) & 0xffU));
    }
}

void append_u64(std::vector<std::byte> &out, std::uint64_t value) {
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        out.push_back(static_cast<std::byte>((value >> ((sizeof(value) - 1 - i) * 8)) & 0xffU));
    }
}

std::optional<std::uint8_t> take_u8(std::span<const std::byte> &in) {
    if (in.size() < 1) {
        return std::nullopt;
    }
    const auto value = static_cast<std::uint8_t>(in[0]);
    in = in.subspan(1);
    return value;
}

std::optional<std::uint32_t> take_u32(std::span<const std::byte> &in) {
    if (in.size() < sizeof(std::uint32_t)) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint32_t); ++i) {
        value = (value << 8) | static_cast<std::uint8_t>(in[i]);
    }
    in = in.subspan(sizeof(std::uint32_t));
    return value;
}

std::optional<std::uint64_t> take_u64(std::span<const std::byte> &in) {
    if (in.size() < sizeof(std::uint64_t)) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
        value = (value << 8) | static_cast<std::uint8_t>(in[i]);
    }
    in = in.subspan(sizeof(std::uint64_t));
    return value;
}

std::optional<std::string> take_string(std::span<const std::byte> &in) {
    const auto size = take_u32(in);
    if (!size.has_value() || in.size() < size.value()) {
        return std::nullopt;
    }

    std::string value;
    value.resize(size.value());
    for (std::size_t i = 0; i < size.value(); ++i) {
        value[i] = static_cast<char>(in[i]);
    }
    in = in.subspan(size.value());
    return value;
}

std::optional<QuicPerfMode> parse_mode(std::uint8_t value) {
    switch (static_cast<QuicPerfMode>(value)) {
    case QuicPerfMode::bulk:
    case QuicPerfMode::rr:
    case QuicPerfMode::crr:
        return static_cast<QuicPerfMode>(value);
    }
    return std::nullopt;
}

std::optional<QuicPerfDirection> parse_direction(std::uint8_t value) {
    switch (static_cast<QuicPerfDirection>(value)) {
    case QuicPerfDirection::upload:
    case QuicPerfDirection::download:
        return static_cast<QuicPerfDirection>(value);
    }
    return std::nullopt;
}

constexpr std::uint8_t kSessionStartOptionalTotalBytesFlag = 0x01;
constexpr std::uint8_t kSessionStartOptionalRequestsFlag = 0x02;

struct RawSessionStartFields {
    std::uint32_t protocol_version = 0;
    QuicPerfMode mode = QuicPerfMode::bulk;
    QuicPerfDirection direction = QuicPerfDirection::download;
    std::uint64_t request_bytes = 0;
    std::uint64_t response_bytes = 0;
    std::uint64_t total_bytes = 0;
    std::uint64_t requests = 0;
    std::uint64_t warmup = 0;
    std::uint64_t duration = 0;
    std::uint64_t streams = 0;
    std::uint64_t connections = 0;
    std::uint64_t requests_in_flight = 0;
    std::uint8_t optional_flags = 0;
};

bool protocol_version_has_session_start_flags(std::uint32_t protocol_version) {
    return protocol_version == kQuicPerfProtocolVersion ||
           protocol_version == kQuicPerfProtocolVersionMilliseconds;
}

bool protocol_version_uses_legacy_duration_units(std::uint32_t protocol_version) {
    return protocol_version == kQuicPerfProtocolVersionLegacy ||
           protocol_version == kQuicPerfProtocolVersionMilliseconds;
}

std::uint64_t duration_to_u64(quic::QuicCoreDuration duration) {
    return static_cast<std::uint64_t>(duration.count());
}

std::uint64_t duration_to_legacy_milliseconds(quic::QuicCoreDuration duration) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count());
}

quic::QuicCoreDuration duration_from_u64(std::uint64_t microseconds) {
    return quic::QuicCoreDuration{static_cast<quic::QuicCoreDuration::rep>(microseconds)};
}

quic::QuicCoreDuration legacy_milliseconds_from_u64(std::uint64_t milliseconds) {
    return std::chrono::duration_cast<quic::QuicCoreDuration>(
        std::chrono::milliseconds{static_cast<std::chrono::milliseconds::rep>(milliseconds)});
}

std::uint8_t session_start_optional_field_flags(const QuicPerfSessionStart &start) {
    std::uint8_t flags = 0;
    if (start.total_bytes.has_value()) {
        flags |= kSessionStartOptionalTotalBytesFlag;
    }
    if (start.requests.has_value()) {
        flags |= kSessionStartOptionalRequestsFlag;
    }
    return flags;
}

bool take_session_start_header(std::span<const std::byte> &in, RawSessionStartFields &fields) {
    std::optional<std::uint32_t> protocol_version = take_u32(in);
    std::optional<std::uint8_t> mode_raw = std::nullopt;
    std::optional<std::uint8_t> direction_raw = std::nullopt;
    if (!protocol_version.has_value()) {
        return false;
    }
    fields.protocol_version = protocol_version.value();

    mode_raw = take_u8(in);
    direction_raw = take_u8(in);
    std::optional<std::uint64_t> request_bytes = take_u64(in);
    std::optional<std::uint64_t> response_bytes = take_u64(in);
    if (!mode_raw.has_value() || !direction_raw.has_value() || !request_bytes.has_value() ||
        !response_bytes.has_value()) {
        return false;
    }
    fields.request_bytes = request_bytes.value();
    fields.response_bytes = response_bytes.value();

    std::optional<QuicPerfMode> mode = parse_mode(mode_raw.value());
    std::optional<QuicPerfDirection> direction = parse_direction(direction_raw.value());
    if (!mode.has_value() || !direction.has_value()) {
        return false;
    }
    fields.mode = mode.value();
    fields.direction = direction.value();
    return true;
}

bool take_session_start_optional_flags(std::span<const std::byte> &in,
                                       RawSessionStartFields &fields) {
    if (protocol_version_has_session_start_flags(fields.protocol_version)) {
        std::optional<std::uint8_t> optional_flags = take_u8(in);
        if (!optional_flags.has_value()) {
            return false;
        }
        fields.optional_flags = optional_flags.value();
        return true;
    }
    return fields.protocol_version == kQuicPerfProtocolVersionLegacy;
}

std::optional<RawSessionStartFields> take_session_start_fields(std::span<const std::byte> &in) {
    RawSessionStartFields fields;
    if (!take_session_start_header(in, fields) || !take_session_start_optional_flags(in, fields)) {
        return std::nullopt;
    }

    std::optional<std::uint64_t> total_bytes = take_u64(in);
    std::optional<std::uint64_t> requests = take_u64(in);
    std::optional<std::uint64_t> warmup = take_u64(in);
    std::optional<std::uint64_t> duration = take_u64(in);
    std::optional<std::uint64_t> streams = take_u64(in);
    std::optional<std::uint64_t> connections = take_u64(in);
    std::optional<std::uint64_t> requests_in_flight = take_u64(in);
    if (!total_bytes.has_value() || !requests.has_value() || !warmup.has_value() ||
        !duration.has_value() || !streams.has_value() || !connections.has_value() ||
        !requests_in_flight.has_value()) {
        return std::nullopt;
    }
    fields.total_bytes = total_bytes.value();
    fields.requests = requests.value();
    fields.warmup = warmup.value();
    fields.duration = duration.value();
    fields.streams = streams.value();
    fields.connections = connections.value();
    fields.requests_in_flight = requests_in_flight.value();
    return fields;
}

void apply_session_start_optional_values(const RawSessionStartFields &fields,
                                         QuicPerfSessionStart &start) {
    if (fields.protocol_version == kQuicPerfProtocolVersionLegacy) {
        if (fields.total_bytes != 0) {
            start.total_bytes = fields.total_bytes;
        }
        if (fields.requests != 0) {
            start.requests = fields.requests;
        }
        return;
    }

    if ((fields.optional_flags & kSessionStartOptionalTotalBytesFlag) != 0) {
        start.total_bytes = fields.total_bytes;
    }
    if ((fields.optional_flags & kSessionStartOptionalRequestsFlag) != 0) {
        start.requests = fields.requests;
    }
}

QuicPerfSessionStart make_session_start(const RawSessionStartFields &fields) {
    QuicPerfSessionStart start;
    start.protocol_version = fields.protocol_version;
    start.mode = fields.mode;
    start.direction = fields.direction;
    start.request_bytes = fields.request_bytes;
    start.response_bytes = fields.response_bytes;
    apply_session_start_optional_values(fields, start);
    if (protocol_version_uses_legacy_duration_units(fields.protocol_version)) {
        start.warmup = legacy_milliseconds_from_u64(fields.warmup);
        start.duration = legacy_milliseconds_from_u64(fields.duration);
    } else {
        start.warmup = duration_from_u64(fields.warmup);
        start.duration = duration_from_u64(fields.duration);
    }
    start.streams = fields.streams;
    start.connections = fields.connections;
    start.requests_in_flight = fields.requests_in_flight;
    return start;
}

} // namespace

std::vector<std::byte> encode_perf_control_message(const QuicPerfControlMessage &message) {
    std::vector<std::byte> payload;
    std::uint8_t type = 0;
    std::visit(
        [&](const auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, QuicPerfSessionStart>) {
                type = static_cast<std::uint8_t>(QuicPerfMessageType::session_start);
                append_u32(payload, value.protocol_version);
                append_u8(payload, static_cast<std::uint8_t>(value.mode));
                append_u8(payload, static_cast<std::uint8_t>(value.direction));
                append_u64(payload, value.request_bytes);
                append_u64(payload, value.response_bytes);
                if (value.protocol_version != kQuicPerfProtocolVersionLegacy) {
                    append_u8(payload, session_start_optional_field_flags(value));
                }
                append_u64(payload, value.total_bytes.value_or(0));
                append_u64(payload, value.requests.value_or(0));
                if (value.protocol_version == kQuicPerfProtocolVersionLegacy ||
                    value.protocol_version == kQuicPerfProtocolVersionMilliseconds) {
                    append_u64(payload, duration_to_legacy_milliseconds(value.warmup));
                    append_u64(payload, duration_to_legacy_milliseconds(value.duration));
                } else {
                    append_u64(payload, duration_to_u64(value.warmup));
                    append_u64(payload, duration_to_u64(value.duration));
                }
                append_u64(payload, value.streams);
                append_u64(payload, value.connections);
                append_u64(payload, value.requests_in_flight);
            } else if constexpr (std::is_same_v<T, QuicPerfSessionReady>) {
                type = static_cast<std::uint8_t>(QuicPerfMessageType::session_ready);
                append_u32(payload, value.protocol_version);
            } else if constexpr (std::is_same_v<T, QuicPerfSessionError>) {
                type = static_cast<std::uint8_t>(QuicPerfMessageType::session_error);
                append_u32(payload, static_cast<std::uint32_t>(value.reason.size()));
                payload.insert(
                    payload.end(), reinterpret_cast<const std::byte *>(value.reason.data()),
                    reinterpret_cast<const std::byte *>(value.reason.data() + value.reason.size()));
            } else {
                type = static_cast<std::uint8_t>(QuicPerfMessageType::session_complete);
                append_u64(payload, value.bytes_sent);
                append_u64(payload, value.bytes_received);
                append_u64(payload, value.requests_completed);
            }
        },
        message);

    std::vector<std::byte> framed;
    append_u8(framed, type);
    append_u32(framed, static_cast<std::uint32_t>(payload.size()));
    framed.insert(framed.end(), payload.begin(), payload.end());
    return framed;
}

std::optional<QuicPerfControlMessage> decode_perf_control_message(std::span<const std::byte> in) {
    const auto type = take_u8(in);
    const auto payload_size = take_u32(in);
    if (!type.has_value() || !payload_size.has_value() || in.size() != payload_size.value()) {
        return std::nullopt;
    }

    const auto message_type = static_cast<QuicPerfMessageType>(type.value());
    switch (message_type) {
    case QuicPerfMessageType::session_start: {
        std::optional<RawSessionStartFields> fields = take_session_start_fields(in);
        if (!fields.has_value() || !in.empty()) {
            return std::nullopt;
        }
        return QuicPerfControlMessage{make_session_start(fields.value())};
    }
    case QuicPerfMessageType::session_ready: {
        const auto protocol_version = take_u32(in);
        if (!protocol_version.has_value() || !in.empty()) {
            return std::nullopt;
        }
        return QuicPerfControlMessage{
            QuicPerfSessionReady{.protocol_version = protocol_version.value()}};
    }
    case QuicPerfMessageType::session_error: {
        const auto reason = take_string(in);
        if (!reason.has_value() || !in.empty()) {
            return std::nullopt;
        }
        return QuicPerfControlMessage{QuicPerfSessionError{.reason = reason.value()}};
    }
    case QuicPerfMessageType::session_complete: {
        const auto bytes_sent = take_u64(in);
        const auto bytes_received = take_u64(in);
        const auto requests_completed = take_u64(in);
        if (!bytes_sent.has_value() || !bytes_received.has_value() ||
            !requests_completed.has_value() || !in.empty()) {
            return std::nullopt;
        }
        return QuicPerfControlMessage{QuicPerfSessionComplete{
            .bytes_sent = bytes_sent.value(),
            .bytes_received = bytes_received.value(),
            .requests_completed = requests_completed.value(),
        }};
    }
    }

    return std::nullopt;
}

std::uint64_t next_client_perf_stream_id(std::uint64_t current_stream_id) {
    return current_stream_id == 0 ? kQuicPerfFirstDataStreamId : current_stream_id + 4;
}

} // namespace coquic::perf
