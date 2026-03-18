#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "src/quic/packet.h"

namespace coquic::quic {

enum class CipherSuite : std::uint8_t {
    tls_aes_128_gcm_sha256,
    tls_aes_256_gcm_sha384,
    tls_chacha20_poly1305_sha256,
};

enum class EndpointRole : std::uint8_t {
    client,
    server,
};

struct TrafficSecret {
    CipherSuite cipher_suite;
    std::vector<std::byte> secret;
};

struct ProtectedInitialPacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> token;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::vector<Frame> frames;
};

struct ProtectedHandshakePacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::vector<Frame> frames;
};

struct ProtectedOneRttPacket {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::vector<Frame> frames;
};

struct SerializeProtectionContext {
    EndpointRole local_role;
    ConnectionId client_initial_destination_connection_id;
    std::optional<TrafficSecret> handshake_secret;
    std::optional<TrafficSecret> one_rtt_secret;
    bool one_rtt_key_phase = false;
};

struct DeserializeProtectionContext {
    EndpointRole peer_role;
    ConnectionId client_initial_destination_connection_id;
    std::optional<TrafficSecret> handshake_secret;
    std::optional<TrafficSecret> one_rtt_secret;
    bool one_rtt_key_phase = false;
    std::optional<std::uint64_t> largest_authenticated_initial_packet_number;
    std::optional<std::uint64_t> largest_authenticated_handshake_packet_number;
    std::optional<std::uint64_t> largest_authenticated_application_packet_number;
    std::size_t one_rtt_destination_connection_id_length = 0;
};

using ProtectedPacket =
    std::variant<ProtectedInitialPacket, ProtectedHandshakePacket, ProtectedOneRttPacket>;

CodecResult<std::vector<std::byte>>
serialize_protected_datagram(std::span<const ProtectedPacket> packets,
                             const SerializeProtectionContext &context);

CodecResult<std::vector<ProtectedPacket>>
deserialize_protected_datagram(std::span<const std::byte> bytes,
                               const DeserializeProtectionContext &context);

} // namespace coquic::quic
