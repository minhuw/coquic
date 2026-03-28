#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "src/quic/frame.h"

namespace coquic::quic {

using ConnectionId = std::vector<std::byte>;

struct DeserializeOptions {
    std::optional<std::size_t> one_rtt_destination_connection_id_length;
};

struct VersionNegotiationPacket {
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::uint32_t> supported_versions;
};

struct RetryPacket {
    std::uint32_t version = 1;
    std::uint8_t retry_unused_bits = 0;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> retry_token;
    std::array<std::byte, 16> retry_integrity_tag{};
};

struct InitialPacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> token;
    std::uint8_t packet_number_length = 1;
    std::uint32_t truncated_packet_number = 0;
    std::vector<Frame> frames;
};

struct ZeroRttPacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint32_t truncated_packet_number = 0;
    std::vector<Frame> frames;
};

struct HandshakePacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint32_t truncated_packet_number = 0;
    std::vector<Frame> frames;
};

struct OneRttPacket {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint32_t truncated_packet_number = 0;
    std::vector<Frame> frames;
};

using Packet = std::variant<VersionNegotiationPacket, RetryPacket, InitialPacket, ZeroRttPacket,
                            HandshakePacket, OneRttPacket>;

struct PacketDecodeResult {
    Packet packet;
    std::size_t bytes_consumed = 0;
};

CodecResult<std::vector<std::byte>> serialize_packet(const Packet &packet);
CodecResult<PacketDecodeResult> deserialize_packet(std::span<const std::byte> bytes,
                                                   const DeserializeOptions &options);

} // namespace coquic::quic
