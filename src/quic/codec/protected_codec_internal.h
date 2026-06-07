#pragma once

#ifndef COQUIC_PROFILE_HOOKS
#define COQUIC_PROFILE_HOOKS 1
#endif

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "src/quic/codec/protected_codec.h"
#include "src/quic/codec/protected_codec_test_hooks.h"

namespace coquic::quic::detail {

constexpr CipherSuite kInitialCipherSuite = CipherSuite::tls_aes_128_gcm_sha256;
constexpr std::size_t kPacketProtectionTagLength = 16;
constexpr std::size_t kHeaderProtectionSampleOffset = 4;
constexpr std::size_t kMaxInlineSealPlaintextChunks = 32;
constexpr std::uint64_t kMaxVarInt = 4611686018427387903ull;
constexpr bool kCoquicProfileHooksEnabled = COQUIC_PROFILE_HOOKS != 0;

enum class LongHeaderPacketType : std::uint8_t {
    initial = 0x00,
    zero_rtt = 0x01,
    handshake = 0x02,
};

enum class ProtectedPayloadPacketType : std::uint8_t {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
};

struct LongHeaderLayout {
    std::size_t length_offset = 0;
    std::size_t length_size = 0;
    std::uint64_t length_value = 0;
    std::size_t packet_number_offset = 0;
    std::size_t packet_end_offset = 0;
};

struct PatchedLengthField {
    std::size_t packet_number_offset = 0;
};

struct PacketNumberSpan {
    std::size_t packet_number_offset = 0;
    std::uint8_t packet_number_length = 0;
};

struct RemovedLongHeaderProtection {
    std::vector<std::byte> packet_bytes;
    std::uint8_t packet_number_length = 0;
    std::uint32_t truncated_packet_number = 0;
};

struct RemovedShortHeaderProtection {
    std::array<std::byte, 260> plaintext_header;
    std::size_t plaintext_header_size = 0;
    std::uint8_t packet_number_length = 0;
    std::uint32_t truncated_packet_number = 0;

    std::span<const std::byte> plaintext_header_span() const {
        return std::span<const std::byte>(plaintext_header.data(), plaintext_header_size);
    }
};

struct StreamFrameHeaderFields {
    bool fin = false;
    std::uint64_t stream_id = 0;
    std::uint64_t offset = 0;
    std::size_t payload_size = 0;
};

struct ProtectedPacketDecodeResult {
    ProtectedPacket packet;
    std::size_t bytes_consumed = 0;
};

struct ReceivedProtectedPacketDecodeResult {
    using Packet = ReceivedProtectedPacket;

    ReceivedProtectedPacket packet;
    std::size_t bytes_consumed = 0;
};

struct ReceivedProtectedFastPacketDecodeResult {
    using Packet = ReceivedProtectedFastPacket;

    ReceivedProtectedFastPacket packet;
    std::size_t bytes_consumed = 0;
};

struct ProtectedCodecFaultState {
    std::optional<test::ProtectedCodecFaultPoint> fault_point;
    std::size_t occurrence = 0;
};

struct ReceivedLongHeaderPacketFields {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> token;
    std::uint8_t packet_number_length = 1;
    ReceivedFrameList frames;
};

struct ReceivedShortHeaderPacketFields {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    ReceivedFrameList frames;
};

struct ReceivedShortHeaderAckOnlyPacketFields {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    ReceivedAckFrame ack;
};

struct ReceivedShortHeaderAckOnlyFastPacketFields {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    ReceivedAckFrame ack;
};

struct ReceivedShortHeaderStreamFastPacketFields {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    ReceivedStreamFrame stream;
};

ProtectedCodecFaultState &protected_codec_fault_state();
void set_protected_codec_fault_state(std::optional<test::ProtectedCodecFaultPoint> fault_point,
                                     std::size_t occurrence);
bool consume_protected_codec_fault(test::ProtectedCodecFaultPoint fault_point);

std::uint8_t encoded_long_header_type(LongHeaderPacketType packet_type, std::uint32_t version);
std::uint32_t read_u32_be(std::span<const std::byte> bytes);
CodecResult<std::uint8_t> read_u8(BufferReader &reader);
CodecResult<std::uint64_t> read_varint(BufferReader &reader);
std::optional<CodecError> append_varint(BufferWriter &writer, std::uint64_t value);
void append_varint_unchecked(BufferWriter &writer, std::uint64_t value);
void append_bytes(std::vector<std::byte> &bytes, std::span<const std::byte> appended);
std::optional<CodecError> append_varint(std::vector<std::byte> &bytes, std::uint64_t value);
void append_varint_unchecked(std::vector<std::byte> &bytes, std::uint64_t value);
std::uint8_t quic_bit_mask(bool grease_quic_bit, std::uint64_t seed, std::uint64_t packet_number);
std::byte make_short_header_first_byte(bool spin_bit, bool key_phase,
                                       std::uint8_t packet_number_length,
                                       bool grease_quic_bit = false,
                                       std::uint64_t grease_quic_bit_seed = 0,
                                       std::uint64_t packet_number = 0);

struct TruncatedPacketNumberEncoding {
    std::uint8_t packet_number_length;
    std::uint32_t truncated_packet_number;
};

void append_packet_number(BufferWriter &writer, TruncatedPacketNumberEncoding encoding);
void append_packet_number(std::vector<std::byte> &bytes, TruncatedPacketNumberEncoding encoding);
std::optional<CodecError> write_u32_be(SpanBufferWriter &writer, std::uint32_t value);
std::optional<CodecError> append_packet_number(SpanBufferWriter &writer,
                                               TruncatedPacketNumberEncoding encoding);

std::size_t minimum_payload_bytes_for_header_sample(std::uint8_t packet_number_length);
CodecResult<std::size_t> serialized_frame_payload_size(std::span<const Frame> frames);
CodecResult<ConnectionId> read_connection_id(BufferReader &reader, bool enforce_v1_limit);
bool frame_allowed_in_long_header_packet_type(const Frame &frame, LongHeaderPacketType packet_type);
CodecResult<bool> validate_long_header_frames(std::span<const Frame> frames,
                                              LongHeaderPacketType packet_type);
bool frame_allowed_in_protected_payload_packet_type(const ReceivedFrame &frame,
                                                    ProtectedPayloadPacketType packet_type);
CodecResult<ReceivedFrameList> deserialize_received_frame_sequence(
    const SharedBytes &payload, ProtectedPayloadPacketType packet_type, std::size_t base_offset);

std::size_t encoded_stream_frame_payload_size(std::uint64_t stream_id, std::uint64_t offset,
                                              std::size_t payload_size);
CodecResult<std::size_t> serialize_stream_frame_header_into(std::vector<std::byte> &bytes,
                                                            const StreamFrameHeaderFields &header);
CodecResult<std::size_t> serialize_stream_frame_header_into(SpanBufferWriter &writer,
                                                            const StreamFrameHeaderFields &header);
CodecResult<std::size_t> append_stream_frame_payload_into(std::vector<std::byte> &bytes,
                                                          StreamFrameHeaderFields header,
                                                          std::span<const std::byte> payload);
CodecResult<std::size_t> serialize_stream_frame_into(std::span<std::byte> output,
                                                     const StreamFrameHeaderFields &header,
                                                     std::span<const std::byte> payload);
CodecResult<std::size_t> append_stream_frame_view_into_datagram(std::vector<std::byte> &bytes,
                                                                const StreamFrameView &stream_view);
CodecResult<std::size_t>
append_stream_frame_send_fragment_to_datagram(std::vector<std::byte> &bytes,
                                              const StreamFrameSendFragment &fragment);
CodecResult<std::size_t> serialize_stream_frame_view_into_span(std::span<std::byte> output,
                                                               const StreamFrameView &stream_view);
CodecResult<std::span<const std::byte>>
stream_frame_view_payload_span(const StreamFrameView &stream_view);
CodecResult<std::size_t> write_stream_frame_view_header_into_span(std::span<std::byte> output,
                                                                  const StreamFrameView &view);
CodecResult<std::size_t>
serialize_stream_frame_send_fragment_into_span(std::span<std::byte> output,
                                               const StreamFrameSendFragment &fragment);

bool long_header_has_token(LongHeaderPacketType packet_type);
CodecResult<LongHeaderPacketType> read_long_header_type(std::span<const std::byte> bytes,
                                                        bool accept_greased_quic_bit = false);
CodecResult<LongHeaderLayout> locate_long_header(std::span<const std::byte> bytes,
                                                 LongHeaderPacketType expected_type,
                                                 bool accept_greased_quic_bit = false);
CodecResult<PatchedLengthField> patch_long_header_length_field(std::vector<std::byte> &packet_bytes,
                                                               const LongHeaderLayout &layout,
                                                               std::uint64_t new_length_value);
std::uint32_t read_packet_number(std::span<const std::byte> bytes,
                                 std::uint8_t packet_number_length);
EndpointRole opposite_endpoint_role(EndpointRole role);
CodecResult<PacketProtectionKeys>
derive_send_initial_keys(const SerializeProtectionContext &context, std::uint32_t version);
CodecResult<PacketProtectionKeys>
derive_receive_initial_keys(const DeserializeProtectionContext &context, std::uint32_t version);
CodecResult<InitialPacket> to_plaintext_initial(const ProtectedInitialPacket &packet);
CodecResult<HandshakePacket> to_plaintext_handshake(const ProtectedHandshakePacket &packet);
CodecResult<ZeroRttPacket> to_plaintext_zero_rtt(const ProtectedZeroRttPacket &packet);
CodecResult<OneRttPacket> to_plaintext_one_rtt(const ProtectedOneRttPacket &packet);

CodecResult<bool> apply_long_header_protection_in_place(std::span<std::byte> packet_bytes,
                                                        PacketNumberSpan packet_number,
                                                        CipherSuite cipher_suite,
                                                        const PacketProtectionKeys &keys);
CodecResult<RemovedLongHeaderProtection>
remove_long_header_protection(std::span<const std::byte> bytes, const LongHeaderLayout &layout,
                              CipherSuite cipher_suite, const PacketProtectionKeys &keys);
CodecResult<bool> apply_short_header_protection_in_place(std::span<std::byte> packet_bytes,
                                                         PacketNumberSpan packet_number,
                                                         CipherSuite cipher_suite,
                                                         const PacketProtectionKeys &keys);
CodecResult<RemovedShortHeaderProtection>
remove_short_header_protection(std::span<const std::byte> bytes, std::size_t packet_number_offset,
                               CipherSuite cipher_suite, const PacketProtectionKeys &keys);
LongHeaderLayout locate_long_header_or_assert(std::span<const std::byte> bytes,
                                              LongHeaderPacketType expected_type,
                                              bool accept_greased_quic_bit = false);
PatchedLengthField patch_long_header_length_field_or_assert(std::vector<std::byte> &packet_bytes,
                                                            const LongHeaderLayout &layout,
                                                            std::uint64_t new_length_value);
std::span<const std::byte> make_packet_protection_nonce_or_assert(std::span<const std::byte> iv,
                                                                  std::uint64_t packet_number,
                                                                  std::span<std::byte> storage);
std::vector<std::byte> make_packet_protection_nonce_or_assert(std::span<const std::byte> iv,
                                                              std::uint64_t packet_number);
CodecResult<PacketDecodeResult>
deserialize_plaintext_packet_image(std::span<const std::byte> plaintext_image,
                                   const DeserializeOptions &options);

CodecResult<ReceivedStreamFrame>
try_decode_single_received_stream_frame_value_fast(const SharedBytes &plaintext_payload,
                                                   std::size_t base_offset);
CodecResult<ReceivedFrameList>
try_decode_single_received_stream_frame_fast(const SharedBytes &plaintext_payload,
                                             std::size_t base_offset);
CodecResult<std::vector<std::byte>>
build_long_header_plaintext_header(const RemovedLongHeaderProtection &unprotected,
                                   const LongHeaderLayout &layout,
                                   std::size_t plaintext_payload_size);
CodecResult<ReceivedLongHeaderPacketFields> decode_received_long_header_packet_fields(
    std::span<const std::byte> plaintext_header, const SharedBytes &plaintext_payload,
    ProtectedPayloadPacketType packet_type, bool has_token, bool accept_greased_quic_bit = false);
CodecResult<ReceivedShortHeaderPacketFields>
decode_received_short_header_packet_fields(std::span<const std::byte> plaintext_header,
                                           const SharedBytes &plaintext_payload,
                                           bool accept_greased_quic_bit = false);
CodecResult<ReceivedShortHeaderAckOnlyPacketFields>
try_decode_received_short_header_ack_only_packet_fields(std::span<const std::byte> plaintext_header,
                                                        const SharedBytes &plaintext_payload,
                                                        bool accept_greased_quic_bit = false);
CodecResult<ReceivedShortHeaderAckOnlyFastPacketFields>
try_decode_received_short_header_ack_only_fast_packet_fields(
    std::span<const std::byte> plaintext_header, const SharedBytes &plaintext_payload,
    bool accept_greased_quic_bit = false);
CodecResult<ReceivedShortHeaderStreamFastPacketFields>
try_decode_received_short_header_stream_fast_packet_fields(
    std::span<const std::byte> plaintext_header, const SharedBytes &plaintext_payload,
    bool accept_greased_quic_bit = false);

CodecResult<std::size_t> append_protected_long_header_packet_to_datagram(
    std::vector<std::byte> &out_datagram, LongHeaderPacketType packet_type, std::uint32_t version,
    const ConnectionId &destination_connection_id, const ConnectionId &source_connection_id,
    std::span<const std::byte> token, TruncatedPacketNumberEncoding packet_number,
    std::uint64_t full_packet_number, std::span<const Frame> frames, CipherSuite cipher_suite,
    const PacketProtectionKeys &keys, bool grease_quic_bit = false,
    std::uint64_t grease_quic_bit_seed = 0);
CodecResult<std::vector<std::byte>>
serialize_protected_initial_packet(const ProtectedInitialPacket &packet,
                                   const SerializeProtectionContext &context);
CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_initial_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context);
CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_initial_packet(std::span<const std::byte> bytes,
                                              const DeserializeProtectionContext &context);
CodecResult<std::vector<std::byte>>
serialize_protected_handshake_packet(const ProtectedHandshakePacket &packet,
                                     const SerializeProtectionContext &context);
CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_handshake_packet(std::span<const std::byte> bytes,
                                       const DeserializeProtectionContext &context);
CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_handshake_packet(std::span<const std::byte> bytes,
                                                const DeserializeProtectionContext &context);
CodecResult<std::vector<std::byte>>
serialize_protected_zero_rtt_packet(const ProtectedZeroRttPacket &packet,
                                    const SerializeProtectionContext &context);
CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_zero_rtt_packet(std::span<const std::byte> bytes,
                                      const DeserializeProtectionContext &context);
CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_zero_rtt_packet(std::span<const std::byte> bytes,
                                               const DeserializeProtectionContext &context);

void pad_short_header_plaintext_for_header_protection(std::vector<std::byte> &plaintext_image,
                                                      std::size_t packet_number_offset);
const OutboundAckFrame *simple_outbound_ack_frame_or_null(const ProtectedOneRttPacket &packet);
const OutboundAckFrame *simple_outbound_ack_frame_or_null(const ProtectedOneRttPacketView &packet);
const OutboundAckFrame *
simple_outbound_ack_frame_or_null(const ProtectedOneRttPacketFragmentView &packet);
CodecResult<std::size_t> simple_outbound_ack_payload_size(const OutboundAckFrame &ack);
CodecResult<std::size_t> write_simple_outbound_ack_payload(std::span<std::byte> output,
                                                           const OutboundAckFrame &ack);
CodecResult<std::size_t> packet_stream_payload_wire_size(const ProtectedOneRttPacketView &packet,
                                                         std::size_t frame_index_base = 0);
CodecResult<std::size_t>
packet_stream_payload_wire_size(const ProtectedOneRttPacketFragmentView &packet,
                                std::size_t frame_index_base = 0);
CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(DatagramBuffer &out_datagram,
                                                 const ProtectedOneRttPacket &packet,
                                                 const SerializeProtectionContext &context);
CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(DatagramBuffer &out_datagram,
                                                 const ProtectedOneRttPacketView &packet,
                                                 const SerializeProtectionContext &context);
CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(DatagramBuffer &out_datagram,
                                                 const ProtectedOneRttPacketFragmentView &packet,
                                                 const SerializeProtectionContext &context);
CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_one_rtt_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context);
CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_one_rtt_packet(std::span<const std::byte> bytes,
                                              const DeserializeProtectionContext &context);
CodecResult<ReceivedProtectedPacketDecodeResult> deserialize_received_protected_one_rtt_packet(
    const std::shared_ptr<std::vector<std::byte>> &storage, std::size_t begin, std::size_t end,
    const DeserializeProtectionContext &context, bool ack_only_fast = false);
CodecResult<ReceivedProtectedFastPacketDecodeResult>
deserialize_received_protected_one_rtt_packet_fast_compact(
    const std::shared_ptr<std::vector<std::byte>> &storage, std::size_t begin, std::size_t end,
    const DeserializeProtectionContext &context);
CodecResult<bool> append_serialized_protected_packet(SerializedProtectedDatagram &datagram,
                                                     const ProtectedPacket &packet,
                                                     const SerializeProtectionContext &context);

} // namespace coquic::quic::detail
