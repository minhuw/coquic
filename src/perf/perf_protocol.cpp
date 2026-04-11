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
                append_u64(payload, value.total_bytes.value_or(0));
                append_u64(payload, value.requests.value_or(0));
                append_u64(payload, value.warmup_ms);
                append_u64(payload, value.duration_ms);
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
        const auto protocol_version = take_u32(in);
        const auto mode_raw = take_u8(in);
        const auto direction_raw = take_u8(in);
        const auto request_bytes = take_u64(in);
        const auto response_bytes = take_u64(in);
        const auto total_bytes = take_u64(in);
        const auto requests = take_u64(in);
        const auto warmup_ms = take_u64(in);
        const auto duration_ms = take_u64(in);
        const auto streams = take_u64(in);
        const auto connections = take_u64(in);
        const auto requests_in_flight = take_u64(in);
        if (!protocol_version.has_value() || !mode_raw.has_value() || !direction_raw.has_value() ||
            !request_bytes.has_value() || !response_bytes.has_value() || !total_bytes.has_value() ||
            !requests.has_value() || !warmup_ms.has_value() || !duration_ms.has_value() ||
            !streams.has_value() || !connections.has_value() || !requests_in_flight.has_value()) {
            return std::nullopt;
        }

        const auto mode = parse_mode(mode_raw.value());
        const auto direction = parse_direction(direction_raw.value());
        if (!mode.has_value() || !direction.has_value() || !in.empty()) {
            return std::nullopt;
        }

        QuicPerfSessionStart start;
        start.protocol_version = protocol_version.value();
        start.mode = mode.value();
        start.direction = direction.value();
        start.request_bytes = request_bytes.value();
        start.response_bytes = response_bytes.value();
        if (total_bytes.value() != 0) {
            start.total_bytes = total_bytes;
        }
        if (requests.value() != 0) {
            start.requests = requests;
        }
        start.warmup_ms = warmup_ms.value();
        start.duration_ms = duration_ms.value();
        start.streams = streams.value();
        start.connections = connections.value();
        start.requests_in_flight = requests_in_flight.value();
        return QuicPerfControlMessage{start};
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
