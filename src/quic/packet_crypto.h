#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "src/quic/protected_codec.h"
#include "src/quic/version.h"

namespace coquic::quic {

struct PlaintextChunk {
    std::span<const std::byte> bytes;
};

struct PacketProtectionNonceInput {
    std::span<const std::byte> iv;
    std::uint64_t packet_number;
};

struct HeaderProtectionMaskInput {
    std::span<const std::byte> hp_key;
    std::span<const std::byte> sample;
};

struct SealPayloadIntoInput {
    CipherSuite cipher_suite;
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const std::byte> plaintext;
    std::span<std::byte> ciphertext;
};

struct SealPayloadChunksIntoInput {
    CipherSuite cipher_suite;
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const PlaintextChunk> plaintext_chunks;
    std::span<std::byte> ciphertext;
};

struct SealPayloadInput {
    CipherSuite cipher_suite;
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const std::byte> plaintext;
};

struct OpenPayloadInput {
    CipherSuite cipher_suite;
    std::span<const std::byte> key;
    std::span<const std::byte> nonce;
    std::span<const std::byte> associated_data;
    std::span<const std::byte> ciphertext;
};

CodecResult<PacketProtectionKeys>
derive_initial_packet_keys(EndpointRole local_role, bool for_local_send,
                           const ConnectionId &client_initial_destination_connection_id,
                           std::uint32_t version = kQuicVersion1);

CodecResult<PacketProtectionKeys> expand_traffic_secret(const TrafficSecret &secret);
CodecResult<TrafficSecret> derive_next_traffic_secret(const TrafficSecret &secret);

CodecResult<std::size_t> make_packet_protection_nonce_into(PacketProtectionNonceInput input,
                                                           std::span<std::byte> nonce);

CodecResult<std::vector<std::byte>> make_packet_protection_nonce(PacketProtectionNonceInput input);

CodecResult<std::array<std::byte, 16>>
compute_retry_integrity_tag(const RetryPacket &packet,
                            const ConnectionId &original_destination_connection_id);
CodecResult<bool>
validate_retry_integrity_tag(const RetryPacket &packet,
                             const ConnectionId &original_destination_connection_id);

CodecResult<std::size_t> seal_payload_into(const SealPayloadIntoInput &input);

CodecResult<std::size_t> seal_payload_chunks_into(const SealPayloadChunksIntoInput &input);

CodecResult<std::vector<std::byte>> seal_payload(const SealPayloadInput &input);

CodecResult<std::vector<std::byte>> open_payload(const OpenPayloadInput &input);

CodecResult<std::size_t> make_header_protection_mask_into(CipherSuite cipher_suite,
                                                          HeaderProtectionMaskInput input,
                                                          std::span<std::byte> mask);

CodecResult<std::vector<std::byte>> make_header_protection_mask(CipherSuite cipher_suite,
                                                                HeaderProtectionMaskInput input);

} // namespace coquic::quic
