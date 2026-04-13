#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "src/perf/perf_runtime.h"

namespace coquic::perf {

constexpr std::uint32_t kQuicPerfProtocolVersionLegacy = 1;
constexpr std::uint32_t kQuicPerfProtocolVersion = 2;
constexpr std::uint64_t kQuicPerfControlStreamId = 0;
constexpr std::uint64_t kQuicPerfFirstDataStreamId = 4;
constexpr std::string_view kQuicPerfApplicationProtocol = "coquic-perf/1";

enum class QuicPerfMessageType : std::uint8_t {
    session_start = 1,
    session_ready = 2,
    session_error = 3,
    session_complete = 4,
};

struct QuicPerfSessionStart {
    std::uint32_t protocol_version = kQuicPerfProtocolVersion;
    QuicPerfMode mode = QuicPerfMode::bulk;
    QuicPerfDirection direction = QuicPerfDirection::download;
    std::uint64_t request_bytes = 0;
    std::uint64_t response_bytes = 0;
    std::optional<std::uint64_t> total_bytes;
    std::optional<std::uint64_t> requests;
    std::uint64_t warmup_ms = 0;
    std::uint64_t duration_ms = 0;
    std::uint64_t streams = 1;
    std::uint64_t connections = 1;
    std::uint64_t requests_in_flight = 1;
};

struct QuicPerfSessionReady {
    std::uint32_t protocol_version = kQuicPerfProtocolVersion;
};

struct QuicPerfSessionError {
    std::string reason;
};

struct QuicPerfSessionComplete {
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_received = 0;
    std::uint64_t requests_completed = 0;
};

using QuicPerfControlMessage = std::variant<QuicPerfSessionStart, QuicPerfSessionReady,
                                            QuicPerfSessionError, QuicPerfSessionComplete>;

std::vector<std::byte> encode_perf_control_message(const QuicPerfControlMessage &message);
std::optional<QuicPerfControlMessage> decode_perf_control_message(std::span<const std::byte>);
std::uint64_t next_client_perf_stream_id(std::uint64_t current_stream_id);

} // namespace coquic::perf
