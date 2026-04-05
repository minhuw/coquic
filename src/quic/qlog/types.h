#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "src/quic/frame.h"
#include "src/quic/packet.h"

namespace coquic::quic::qlog {

struct FilePreamble {
    std::string title;
    std::string description;
    std::string group_id;
    std::string vantage_point_type;
    std::vector<std::string> event_schemas;
};

struct AlpnValue {
    std::vector<std::byte> bytes;
};

struct PacketHeader {
    std::string packet_type;
    std::optional<std::uint8_t> packet_number_length;
    std::optional<std::uint64_t> packet_number;
    std::optional<std::uint32_t> version;
    std::optional<std::uint16_t> length;
    std::optional<bool> spin_bit;
    std::optional<std::uint64_t> key_phase;
    std::optional<ConnectionId> scid;
    std::optional<ConnectionId> dcid;
    std::optional<std::vector<std::byte>> token;
};

struct PacketSnapshot {
    PacketHeader header;
    std::vector<Frame> frames;
    std::uint64_t raw_length = 0;
    std::optional<std::uint32_t> datagram_id;
    std::optional<std::string> trigger;
};

struct PacketSnapshotContext {
    std::uint64_t raw_length = 0;
    std::uint32_t datagram_id = 0;
    std::optional<std::string> trigger;
};

struct RecoveryMetricsSnapshot {
    std::optional<double> min_rtt_ms;
    std::optional<double> smoothed_rtt_ms;
    std::optional<double> latest_rtt_ms;
    std::optional<double> rtt_variance_ms;
    std::optional<std::uint16_t> pto_count;
    std::optional<std::uint64_t> congestion_window;
    std::optional<std::uint64_t> bytes_in_flight;

    bool operator==(const RecoveryMetricsSnapshot &) const = default;
};

} // namespace coquic::quic::qlog
