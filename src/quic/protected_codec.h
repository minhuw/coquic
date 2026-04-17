#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "src/quic/packet.h"
#include "src/quic/varint.h"
#include "src/quic/version.h"

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

struct PacketProtectionKeys {
    std::vector<std::byte> key;
    std::vector<std::byte> iv;
    std::vector<std::byte> hp_key;
};

struct TrafficSecretCacheInputs {
    std::vector<std::byte> secret;
    std::optional<std::vector<std::byte>> header_protection_key;
    std::uint32_t quic_version = kQuicVersion1;
};

struct TrafficSecret {
    CipherSuite cipher_suite;
    std::vector<std::byte> secret;
    std::optional<std::vector<std::byte>> header_protection_key;
    std::uint32_t quic_version = kQuicVersion1;
    mutable std::optional<PacketProtectionKeys> cached_packet_protection_keys;
    mutable std::optional<TrafficSecretCacheInputs> cached_packet_protection_inputs;
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

struct ReceivedProtectedInitialPacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> token;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::shared_ptr<std::vector<std::byte>> plaintext_storage;
    std::vector<ReceivedFrame> frames;
};

struct ProtectedHandshakePacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::vector<Frame> frames;
};

struct ReceivedProtectedHandshakePacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::shared_ptr<std::vector<std::byte>> plaintext_storage;
    std::vector<ReceivedFrame> frames;
};

struct ProtectedZeroRttPacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::vector<Frame> frames;
};

struct ReceivedProtectedZeroRttPacket {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::shared_ptr<std::vector<std::byte>> plaintext_storage;
    std::vector<ReceivedFrame> frames;
};

struct StreamFrameSendFragment;

struct StreamFrameView {
    bool fin = false;
    std::uint64_t stream_id = 0;
    std::uint64_t offset = 0;
    std::shared_ptr<std::vector<std::byte>> storage;
    std::size_t begin = 0;
    std::size_t end = 0;
};

struct ProtectedOneRttPacket {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::vector<Frame> frames;
    std::vector<StreamFrameView> stream_frame_views;
};

struct ReceivedProtectedOneRttPacket {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::shared_ptr<std::vector<std::byte>> plaintext_storage;
    std::vector<ReceivedFrame> frames;
};

struct ProtectedOneRttPacketView {
    bool spin_bit = false;
    bool key_phase = false;
    std::span<const std::byte> destination_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::span<const Frame> frames;
    std::span<const StreamFrameView> stream_frame_views;
};

struct ProtectedOneRttPacketFragmentView {
    bool spin_bit = false;
    bool key_phase = false;
    std::span<const std::byte> destination_connection_id;
    std::uint8_t packet_number_length = 1;
    std::uint64_t packet_number = 0;
    std::span<const Frame> frames;
    std::span<const StreamFrameSendFragment> stream_fragments;
};

struct SerializeProtectionContext {
    EndpointRole local_role;
    ConnectionId client_initial_destination_connection_id;
    std::optional<TrafficSecret> handshake_secret;
    std::optional<TrafficSecret> zero_rtt_secret;
    std::optional<TrafficSecret> one_rtt_secret;
    bool one_rtt_key_phase = false;
};

struct DeserializeProtectionContext {
    EndpointRole peer_role;
    ConnectionId client_initial_destination_connection_id;
    std::optional<TrafficSecret> handshake_secret;
    std::optional<TrafficSecret> zero_rtt_secret;
    std::optional<TrafficSecret> one_rtt_secret;
    bool one_rtt_key_phase = false;
    std::optional<std::uint64_t> largest_authenticated_initial_packet_number;
    std::optional<std::uint64_t> largest_authenticated_handshake_packet_number;
    std::optional<std::uint64_t> largest_authenticated_application_packet_number;
    std::size_t one_rtt_destination_connection_id_length = 0;
};

using ProtectedPacket = std::variant<ProtectedInitialPacket, ProtectedHandshakePacket,
                                     ProtectedZeroRttPacket, ProtectedOneRttPacket>;
using ReceivedProtectedPacket =
    std::variant<ReceivedProtectedInitialPacket, ReceivedProtectedHandshakePacket,
                 ReceivedProtectedZeroRttPacket, ReceivedProtectedOneRttPacket>;

struct SerializedProtectedPacketMetadata {
    std::size_t offset = 0;
    std::size_t length = 0;
};

struct SerializedProtectedDatagram {
    std::vector<std::byte> bytes;
    std::vector<SerializedProtectedPacketMetadata> packet_metadata;
};

CodecResult<SerializedProtectedDatagram>
serialize_protected_datagram_with_metadata(std::span<const ProtectedPacket> packets,
                                           const SerializeProtectionContext &context);
CodecResult<SerializedProtectedDatagram>
serialize_protected_datagram_with_metadata(std::span<const ProtectedPacket> packets,
                                           const ProtectedPacket &appended_packet,
                                           const SerializeProtectionContext &context);

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacketView &packet,
                                            const SerializeProtectionContext &context);

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacketFragmentView &packet,
                                            const SerializeProtectionContext &context);

CodecResult<std::vector<std::byte>>
serialize_protected_datagram(std::span<const ProtectedPacket> packets,
                             const SerializeProtectionContext &context);

CodecResult<std::vector<ProtectedPacket>>
deserialize_protected_datagram(std::span<const std::byte> bytes,
                               const DeserializeProtectionContext &context);
CodecResult<std::vector<ReceivedProtectedPacket>>
deserialize_received_protected_datagram(std::span<const std::byte> bytes,
                                        const DeserializeProtectionContext &context);

} // namespace coquic::quic
