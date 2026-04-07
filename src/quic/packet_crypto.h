#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "src/quic/protected_codec.h"
#include "src/quic/version.h"

namespace coquic::quic {

struct PacketProtectionKeys {
    std::vector<std::byte> key;
    std::vector<std::byte> iv;
    std::vector<std::byte> hp_key;
};

struct PlaintextChunk {
    std::span<const std::byte> bytes;
};

struct HeaderProtectionMaskInput {
    std::span<const std::byte> hp_key;
    std::span<const std::byte> sample;
};

CodecResult<PacketProtectionKeys>
derive_initial_packet_keys(EndpointRole local_role, bool for_local_send,
                           const ConnectionId &client_initial_destination_connection_id,
                           std::uint32_t version = kQuicVersion1);

CodecResult<PacketProtectionKeys> expand_traffic_secret(const TrafficSecret &secret);
CodecResult<TrafficSecret> derive_next_traffic_secret(const TrafficSecret &secret);

CodecResult<std::vector<std::byte>> make_packet_protection_nonce(std::span<const std::byte> iv,
                                                                 std::uint64_t packet_number);

CodecResult<std::array<std::byte, 16>>
compute_retry_integrity_tag(const RetryPacket &packet,
                            const ConnectionId &original_destination_connection_id);
CodecResult<bool>
validate_retry_integrity_tag(const RetryPacket &packet,
                             const ConnectionId &original_destination_connection_id);

CodecResult<std::size_t> seal_payload_into(CipherSuite cipher_suite, std::span<const std::byte> key,
                                           std::span<const std::byte> nonce,
                                           std::span<const std::byte> associated_data,
                                           std::span<const std::byte> plaintext,
                                           std::span<std::byte> ciphertext);

CodecResult<std::size_t> seal_payload_chunks_into(CipherSuite cipher_suite,
                                                  std::span<const std::byte> key,
                                                  std::span<const std::byte> nonce,
                                                  std::span<const std::byte> associated_data,
                                                  std::span<const PlaintextChunk> plaintext_chunks,
                                                  std::span<std::byte> ciphertext);

CodecResult<std::vector<std::byte>> seal_payload(CipherSuite cipher_suite,
                                                 std::span<const std::byte> key,
                                                 std::span<const std::byte> nonce,
                                                 std::span<const std::byte> associated_data,
                                                 std::span<const std::byte> plaintext);

CodecResult<std::vector<std::byte>> open_payload(CipherSuite cipher_suite,
                                                 std::span<const std::byte> key,
                                                 std::span<const std::byte> nonce,
                                                 std::span<const std::byte> associated_data,
                                                 std::span<const std::byte> ciphertext);

CodecResult<std::vector<std::byte>> make_header_protection_mask(CipherSuite cipher_suite,
                                                                HeaderProtectionMaskInput input);

} // namespace coquic::quic
