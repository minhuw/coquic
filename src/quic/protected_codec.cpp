#include "src/quic/protected_codec.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/buffer.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/packet_number.h"
#include "src/quic/protected_codec_test_hooks.h"

namespace coquic::quic {

namespace {

constexpr std::uint32_t kQuicV1 = 1;
constexpr CipherSuite kInitialCipherSuite = CipherSuite::tls_aes_128_gcm_sha256;
constexpr std::size_t kPacketProtectionTagLength = 16;
constexpr std::size_t kHeaderProtectionSampleOffset = 4;
constexpr std::uint64_t kMaxVarInt = 4611686018427387903ull;

enum class LongHeaderPacketType : std::uint8_t {
    initial = 0x00,
    handshake = 0x02,
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
    std::vector<std::byte> packet_bytes;
    std::uint8_t packet_number_length = 0;
    std::uint32_t truncated_packet_number = 0;
};

struct ProtectedPacketDecodeResult {
    ProtectedPacket packet;
    std::size_t bytes_consumed = 0;
};

struct ProtectedCodecFaultState {
    std::optional<test::ProtectedCodecFaultPoint> fault_point;
    std::size_t occurrence = 0;
};

ProtectedCodecFaultState &protected_codec_fault_state() {
    static thread_local ProtectedCodecFaultState state;
    return state;
}

void set_protected_codec_fault_state(std::optional<test::ProtectedCodecFaultPoint> fault_point,
                                     std::size_t occurrence) {
    protected_codec_fault_state() = ProtectedCodecFaultState{
        .fault_point = fault_point,
        .occurrence = occurrence,
    };
}

bool consume_protected_codec_fault(test::ProtectedCodecFaultPoint fault_point) {
    auto &state = protected_codec_fault_state();
    if (!state.fault_point.has_value() || state.fault_point.value() != fault_point)
        return false;
    if (state.occurrence > 1) {
        --state.occurrence;
        return false;
    }

    state.fault_point.reset();
    state.occurrence = 0;
    return true;
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

CodecResult<std::uint8_t> read_u8(BufferReader &reader) {
    const auto byte = reader.read_byte();
    if (!byte.has_value())
        return CodecResult<std::uint8_t>::failure(byte.error().code, byte.error().offset);

    return CodecResult<std::uint8_t>::success(std::to_integer<std::uint8_t>(byte.value()));
}

CodecResult<std::uint64_t> read_varint(BufferReader &reader) {
    const auto decoded = decode_varint(reader);
    if (!decoded.has_value())
        return CodecResult<std::uint64_t>::failure(decoded.error().code, decoded.error().offset);

    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

std::optional<CodecError> append_varint(BufferWriter &writer, std::uint64_t value) {
    const auto encoded = encode_varint(value);
    if (!encoded.has_value()) {
        return encoded.error();
    }

    writer.write_bytes(encoded.value());
    return std::nullopt;
}

void append_varint_unchecked(BufferWriter &writer, std::uint64_t value) {
    writer.write_bytes(encode_varint(value).value());
}

std::byte make_short_header_first_byte(bool spin_bit, bool key_phase,
                                       std::uint8_t packet_number_length) {
    return static_cast<std::byte>(0x40u | (spin_bit ? 0x20u : 0u) | (key_phase ? 0x04u : 0u) |
                                  ((packet_number_length - 1) & 0x03u));
}

struct TruncatedPacketNumberEncoding {
    std::uint8_t packet_number_length;
    std::uint32_t truncated_packet_number;
};

void append_packet_number(BufferWriter &writer, TruncatedPacketNumberEncoding encoding) {
    for (std::size_t index = 0; index < encoding.packet_number_length; ++index) {
        const auto shift = static_cast<unsigned>((encoding.packet_number_length - index - 1) * 8);
        writer.write_byte(
            static_cast<std::byte>((encoding.truncated_packet_number >> shift) & 0xffu));
    }
}

CodecResult<std::vector<std::byte>>
serialize_plaintext_one_rtt_packet_with_stream_views(const ProtectedOneRttPacket &packet) {
    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(truncated_packet_number.error().code,
                                                            truncated_packet_number.error().offset);
    }

    if (packet.frames.empty() && packet.stream_frame_views.empty()) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::empty_packet_payload,
                                                            0);
    }

    BufferWriter writer;
    writer.write_byte(make_short_header_first_byte(packet.spin_bit, packet.key_phase,
                                                   packet.packet_number_length));
    writer.write_bytes(packet.destination_connection_id);
    append_packet_number(writer, TruncatedPacketNumberEncoding{
                                     .packet_number_length = packet.packet_number_length,
                                     .truncated_packet_number = truncated_packet_number.value(),
                                 });

    const auto total_frame_count = packet.frames.size() + packet.stream_frame_views.size();
    std::size_t frame_index = 0;
    for (const auto &frame : packet.frames) {
        if (const auto *stream = std::get_if<StreamFrame>(&frame);
            stream != nullptr && !stream->has_length && frame_index + 1 != total_frame_count) {
            return CodecResult<std::vector<std::byte>>::failure(
                CodecErrorCode::packet_length_mismatch, frame_index);
        }

        const auto encoded = serialize_frame(frame);
        if (!encoded.has_value()) {
            return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                                encoded.error().offset);
        }

        writer.write_bytes(encoded.value());
        ++frame_index;
    }

    for (const auto &stream_view : packet.stream_frame_views) {
        if (stream_view.end < stream_view.begin) {
            return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint,
                                                                frame_index);
        }

        const auto payload_size = stream_view.end - stream_view.begin;
        if (stream_view.offset > kMaxVarInt - payload_size) {
            return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint,
                                                                frame_index);
        }
        if (payload_size != 0 &&
            (!stream_view.storage || stream_view.end > stream_view.storage->size())) {
            return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint,
                                                                frame_index);
        }

        std::byte type = std::byte{0x08};
        type |= std::byte{0x04};
        type |= std::byte{0x02};
        if (stream_view.fin) {
            type |= std::byte{0x01};
        }

        writer.write_byte(type);
        if (const auto error = append_varint(writer, stream_view.stream_id)) {
            return CodecResult<std::vector<std::byte>>::failure(error->code, error->offset);
        }
        append_varint_unchecked(writer, stream_view.offset);
        append_varint_unchecked(writer, payload_size);
        if (payload_size != 0) {
            writer.write_bytes(std::span<const std::byte>(
                stream_view.storage->data() + static_cast<std::ptrdiff_t>(stream_view.begin),
                payload_size));
        }
        ++frame_index;
    }

    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

struct SerializedOneRttPacketChunks {
    std::vector<std::byte> header;
    std::vector<std::vector<std::byte>> owned_payload_chunks;
    std::vector<PlaintextChunk> payload_chunks;
    std::size_t payload_size = 0;
};

void append_owned_payload_chunk(SerializedOneRttPacketChunks &packet_chunks,
                                std::vector<std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }

    packet_chunks.payload_size += bytes.size();
    packet_chunks.owned_payload_chunks.push_back(std::move(bytes));
    const auto &stored = packet_chunks.owned_payload_chunks.back();
    packet_chunks.payload_chunks.push_back(PlaintextChunk{
        .bytes = std::span<const std::byte>(stored),
    });
}

void append_payload_view_chunk(SerializedOneRttPacketChunks &packet_chunks,
                               std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }

    packet_chunks.payload_size += bytes.size();
    packet_chunks.payload_chunks.push_back(PlaintextChunk{
        .bytes = bytes,
    });
}

CodecResult<std::vector<std::byte>>
serialize_stream_frame_view_header(const StreamFrameView &stream_view) {
    if (stream_view.end < stream_view.begin) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload_size = stream_view.end - stream_view.begin;
    if (stream_view.offset > kMaxVarInt - payload_size) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (payload_size != 0 &&
        (!stream_view.storage || stream_view.end > stream_view.storage->size())) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }

    BufferWriter writer;
    std::byte type = std::byte{0x08};
    type |= std::byte{0x04};
    type |= std::byte{0x02};
    if (stream_view.fin) {
        type |= std::byte{0x01};
    }

    writer.write_byte(type);
    if (const auto error = append_varint(writer, stream_view.stream_id)) {
        return CodecResult<std::vector<std::byte>>::failure(error->code, error->offset);
    }
    append_varint_unchecked(writer, stream_view.offset);
    append_varint_unchecked(writer, payload_size);
    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

CodecResult<SerializedOneRttPacketChunks>
serialize_chunked_one_rtt_packet_with_stream_views(const ProtectedOneRttPacket &packet) {
    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<SerializedOneRttPacketChunks>::failure(
            truncated_packet_number.error().code, truncated_packet_number.error().offset);
    }

    if (packet.frames.empty() && packet.stream_frame_views.empty()) {
        return CodecResult<SerializedOneRttPacketChunks>::failure(
            CodecErrorCode::empty_packet_payload, 0);
    }

    SerializedOneRttPacketChunks packet_chunks;
    BufferWriter writer;
    writer.write_byte(make_short_header_first_byte(packet.spin_bit, packet.key_phase,
                                                   packet.packet_number_length));
    writer.write_bytes(packet.destination_connection_id);
    append_packet_number(writer, TruncatedPacketNumberEncoding{
                                     .packet_number_length = packet.packet_number_length,
                                     .truncated_packet_number = truncated_packet_number.value(),
                                 });
    packet_chunks.header = writer.bytes();

    const auto total_frame_count = packet.frames.size() + packet.stream_frame_views.size();
    std::size_t frame_index = 0;
    for (const auto &frame : packet.frames) {
        if (const auto *stream = std::get_if<StreamFrame>(&frame);
            stream != nullptr && !stream->has_length && frame_index + 1 != total_frame_count) {
            return CodecResult<SerializedOneRttPacketChunks>::failure(
                CodecErrorCode::packet_length_mismatch, frame_index);
        }

        const auto encoded = serialize_frame(frame);
        if (!encoded.has_value()) {
            return CodecResult<SerializedOneRttPacketChunks>::failure(encoded.error().code,
                                                                      encoded.error().offset);
        }

        append_owned_payload_chunk(packet_chunks, encoded.value());
        ++frame_index;
    }

    for (const auto &stream_view : packet.stream_frame_views) {
        const auto header = serialize_stream_frame_view_header(stream_view);
        if (!header.has_value()) {
            return CodecResult<SerializedOneRttPacketChunks>::failure(header.error().code,
                                                                      frame_index);
        }

        append_owned_payload_chunk(packet_chunks, header.value());

        if (stream_view.end > stream_view.begin) {
            append_payload_view_chunk(
                packet_chunks,
                std::span<const std::byte>(stream_view.storage->data() +
                                               static_cast<std::ptrdiff_t>(stream_view.begin),
                                           stream_view.end - stream_view.begin));
        }
        ++frame_index;
    }

    const auto minimum_payload_size =
        packet.packet_number_length < kHeaderProtectionSampleOffset
            ? kHeaderProtectionSampleOffset - packet.packet_number_length
            : 0;
    if (packet_chunks.payload_size < minimum_payload_size) {
        append_owned_payload_chunk(
            packet_chunks, std::vector<std::byte>(minimum_payload_size - packet_chunks.payload_size,
                                                  std::byte{0x00}));
    }

    return CodecResult<SerializedOneRttPacketChunks>::success(std::move(packet_chunks));
}

bool long_header_has_token(LongHeaderPacketType packet_type) {
    return packet_type == LongHeaderPacketType::initial;
}

CodecResult<std::uint8_t> read_long_header_type(std::span<const std::byte> bytes) {
    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x40u) == 0)
        return CodecResult<std::uint8_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);

    return CodecResult<std::uint8_t>::success(static_cast<std::uint8_t>((first_byte >> 4) & 0x03u));
}

CodecResult<LongHeaderLayout> locate_long_header(std::span<const std::byte> bytes,
                                                 LongHeaderPacketType expected_type) {
    BufferReader reader(bytes);
    reader.read_byte().value();

    const auto version_bytes = reader.read_exact(4);
    if (!version_bytes.has_value())
        return CodecResult<LongHeaderLayout>::failure(version_bytes.error().code,
                                                      version_bytes.error().offset);
    if (read_u32_be(version_bytes.value()) != kQuicV1)
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::unsupported_packet_type, 0);

    const auto destination_connection_id_length = read_u8(reader);
    if (!destination_connection_id_length.has_value())
        return CodecResult<LongHeaderLayout>::failure(
            destination_connection_id_length.error().code,
            destination_connection_id_length.error().offset);
    if (destination_connection_id_length.value() > 20)
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::invalid_varint,
                                                      reader.offset());
    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length.value());
    if (!destination_connection_id.has_value())
        return CodecResult<LongHeaderLayout>::failure(destination_connection_id.error().code,
                                                      destination_connection_id.error().offset);

    const auto source_connection_id_length = read_u8(reader);
    if (!source_connection_id_length.has_value())
        return CodecResult<LongHeaderLayout>::failure(source_connection_id_length.error().code,
                                                      source_connection_id_length.error().offset);
    if (source_connection_id_length.value() > 20)
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::invalid_varint,
                                                      reader.offset());
    const auto source_connection_id = reader.read_exact(source_connection_id_length.value());
    if (!source_connection_id.has_value())
        return CodecResult<LongHeaderLayout>::failure(source_connection_id.error().code,
                                                      source_connection_id.error().offset);

    if (long_header_has_token(expected_type)) {
        const auto token_length = read_varint(reader);
        if (!token_length.has_value())
            return CodecResult<LongHeaderLayout>::failure(token_length.error().code,
                                                          token_length.error().offset);
        if (token_length.value() > static_cast<std::uint64_t>(reader.remaining()))
            return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::packet_length_mismatch,
                                                          reader.offset());
        reader.read_exact(static_cast<std::size_t>(token_length.value())).value();
    }

    const auto length_offset = reader.offset();
    const auto payload_length = decode_varint(reader);
    if (!payload_length.has_value())
        return CodecResult<LongHeaderLayout>::failure(payload_length.error().code,
                                                      payload_length.error().offset);

    const auto packet_number_offset = reader.offset();
    if (payload_length.value().value > static_cast<std::uint64_t>(reader.remaining()))
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::packet_length_mismatch,
                                                      reader.offset());

    return CodecResult<LongHeaderLayout>::success(LongHeaderLayout{
        .length_offset = length_offset,
        .length_size = payload_length.value().bytes_consumed,
        .length_value = payload_length.value().value,
        .packet_number_offset = packet_number_offset,
        .packet_end_offset =
            packet_number_offset + static_cast<std::size_t>(payload_length.value().value),
    });
}

CodecResult<PatchedLengthField> patch_long_header_length_field(std::vector<std::byte> &packet_bytes,
                                                               const LongHeaderLayout &layout,
                                                               std::uint64_t new_length_value) {
    const auto encoded_length = encode_varint(new_length_value).value();

    packet_bytes.erase(packet_bytes.begin() + static_cast<std::ptrdiff_t>(layout.length_offset),
                       packet_bytes.begin() +
                           static_cast<std::ptrdiff_t>(layout.length_offset + layout.length_size));
    packet_bytes.insert(packet_bytes.begin() + static_cast<std::ptrdiff_t>(layout.length_offset),
                        encoded_length.begin(), encoded_length.end());

    return CodecResult<PatchedLengthField>::success(PatchedLengthField{
        .packet_number_offset = layout.length_offset + encoded_length.size(),
    });
}

std::uint32_t read_packet_number(std::span<const std::byte> bytes,
                                 std::uint8_t packet_number_length) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < packet_number_length; ++index) {
        value = (value << 8) | std::to_integer<std::uint8_t>(bytes[index]);
    }
    return value;
}

EndpointRole opposite_endpoint_role(EndpointRole role) {
    return static_cast<EndpointRole>(1u - static_cast<std::uint8_t>(role));
}

CodecResult<PacketProtectionKeys>
derive_send_initial_keys(const SerializeProtectionContext &context) {
    if (context.client_initial_destination_connection_id.empty()) {
        return CodecResult<PacketProtectionKeys>::failure(CodecErrorCode::missing_crypto_context,
                                                          0);
    }

    return derive_initial_packet_keys(context.local_role, true,
                                      context.client_initial_destination_connection_id);
}

CodecResult<PacketProtectionKeys>
derive_receive_initial_keys(const DeserializeProtectionContext &context) {
    if (context.client_initial_destination_connection_id.empty()) {
        return CodecResult<PacketProtectionKeys>::failure(CodecErrorCode::missing_crypto_context,
                                                          0);
    }

    return derive_initial_packet_keys(opposite_endpoint_role(context.peer_role), false,
                                      context.client_initial_destination_connection_id);
}

CodecResult<InitialPacket> to_plaintext_initial(const ProtectedInitialPacket &packet) {
    if (packet.version != kQuicV1) {
        return CodecResult<InitialPacket>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<InitialPacket>::failure(truncated_packet_number.error().code,
                                                   truncated_packet_number.error().offset);
    }

    return CodecResult<InitialPacket>::success(InitialPacket{
        .version = packet.version,
        .destination_connection_id = packet.destination_connection_id,
        .source_connection_id = packet.source_connection_id,
        .token = packet.token,
        .packet_number_length = packet.packet_number_length,
        .truncated_packet_number = truncated_packet_number.value(),
        .frames = packet.frames,
    });
}

CodecResult<HandshakePacket> to_plaintext_handshake(const ProtectedHandshakePacket &packet) {
    if (packet.version != kQuicV1) {
        return CodecResult<HandshakePacket>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<HandshakePacket>::failure(truncated_packet_number.error().code,
                                                     truncated_packet_number.error().offset);
    }

    return CodecResult<HandshakePacket>::success(HandshakePacket{
        .version = packet.version,
        .destination_connection_id = packet.destination_connection_id,
        .source_connection_id = packet.source_connection_id,
        .packet_number_length = packet.packet_number_length,
        .truncated_packet_number = truncated_packet_number.value(),
        .frames = packet.frames,
    });
}

CodecResult<OneRttPacket> to_plaintext_one_rtt(const ProtectedOneRttPacket &packet) {
    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<OneRttPacket>::failure(truncated_packet_number.error().code,
                                                  truncated_packet_number.error().offset);
    }

    return CodecResult<OneRttPacket>::success(OneRttPacket{
        .spin_bit = packet.spin_bit,
        .key_phase = packet.key_phase,
        .destination_connection_id = packet.destination_connection_id,
        .packet_number_length = packet.packet_number_length,
        .truncated_packet_number = truncated_packet_number.value(),
        .frames = packet.frames,
    });
}

CodecResult<std::vector<std::byte>>
apply_long_header_protection(std::vector<std::byte> packet_bytes, PacketNumberSpan packet_number,
                             CipherSuite cipher_suite, const PacketProtectionKeys &keys) {
    const auto mask = make_header_protection_mask(
        cipher_suite, keys.hp_key,
        std::span<const std::byte>(packet_bytes)
            .subspan(packet_number.packet_number_offset + kHeaderProtectionSampleOffset));
    if (!mask.has_value())
        return CodecResult<std::vector<std::byte>>::failure(mask.error().code, mask.error().offset);

    packet_bytes[0] ^=
        static_cast<std::byte>(std::to_integer<std::uint8_t>(mask.value()[0]) & 0x0fu);
    for (std::size_t index = 0; index < packet_number.packet_number_length; ++index) {
        packet_bytes[packet_number.packet_number_offset + index] ^= mask.value()[index + 1];
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
}

CodecResult<RemovedLongHeaderProtection>
remove_long_header_protection(std::span<const std::byte> bytes, const LongHeaderLayout &layout,
                              CipherSuite cipher_suite, const PacketProtectionKeys &keys) {
    const auto sample_too_short =
        (layout.packet_end_offset > bytes.size()) |
        (layout.packet_number_offset + kHeaderProtectionSampleOffset > layout.packet_end_offset);
    if (sample_too_short)
        return CodecResult<RemovedLongHeaderProtection>::failure(
            CodecErrorCode::header_protection_sample_too_short, 0);

    std::vector<std::byte> packet_bytes(
        bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(layout.packet_end_offset));
    const auto mask = make_header_protection_mask(
        cipher_suite, keys.hp_key,
        std::span<const std::byte>(packet_bytes)
            .subspan(layout.packet_number_offset + kHeaderProtectionSampleOffset));
    if (!mask.has_value())
        return CodecResult<RemovedLongHeaderProtection>::failure(mask.error().code,
                                                                 mask.error().offset);

    packet_bytes[0] ^=
        static_cast<std::byte>(std::to_integer<std::uint8_t>(mask.value()[0]) & 0x0fu);
    const auto packet_number_length =
        static_cast<std::uint8_t>((std::to_integer<std::uint8_t>(packet_bytes[0]) & 0x03u) + 1u);
    const auto packet_number_length_mismatch =
        consume_protected_codec_fault(
            test::ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch) |
        (layout.length_value < packet_number_length) |
        (layout.packet_number_offset + packet_number_length > packet_bytes.size());
    if (packet_number_length_mismatch)
        return CodecResult<RemovedLongHeaderProtection>::failure(
            CodecErrorCode::packet_length_mismatch, layout.packet_number_offset);

    for (std::size_t index = 0; index < packet_number_length; ++index) {
        packet_bytes[layout.packet_number_offset + index] ^= mask.value()[index + 1];
    }

    const auto truncated_packet_number = read_packet_number(
        std::span<const std::byte>(packet_bytes).subspan(layout.packet_number_offset),
        packet_number_length);

    return CodecResult<RemovedLongHeaderProtection>::success(RemovedLongHeaderProtection{
        .packet_bytes = std::move(packet_bytes),
        .packet_number_length = packet_number_length,
        .truncated_packet_number = truncated_packet_number,
    });
}

CodecResult<std::vector<std::byte>>
apply_short_header_protection(std::vector<std::byte> packet_bytes, PacketNumberSpan packet_number,
                              CipherSuite cipher_suite, const PacketProtectionKeys &keys) {
    const auto applied = [&]() -> CodecResult<bool> {
        const auto mask = make_header_protection_mask(
            cipher_suite, keys.hp_key,
            std::span<const std::byte>(packet_bytes)
                .subspan(packet_number.packet_number_offset + kHeaderProtectionSampleOffset));
        if (!mask.has_value())
            return CodecResult<bool>::failure(mask.error().code, mask.error().offset);

        packet_bytes[0] ^=
            static_cast<std::byte>(std::to_integer<std::uint8_t>(mask.value()[0]) & 0x1fu);
        for (std::size_t index = 0; index < packet_number.packet_number_length; ++index) {
            packet_bytes[packet_number.packet_number_offset + index] ^= mask.value()[index + 1];
        }

        return CodecResult<bool>::success(true);
    }();
    if (!applied.has_value())
        return CodecResult<std::vector<std::byte>>::failure(applied.error().code,
                                                            applied.error().offset);

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
}

CodecResult<bool> apply_short_header_protection_in_place(std::span<std::byte> packet_bytes,
                                                         PacketNumberSpan packet_number,
                                                         CipherSuite cipher_suite,
                                                         const PacketProtectionKeys &keys) {
    const auto mask = make_header_protection_mask(
        cipher_suite, keys.hp_key,
        std::span<const std::byte>(packet_bytes)
            .subspan(packet_number.packet_number_offset + kHeaderProtectionSampleOffset));
    if (!mask.has_value())
        return CodecResult<bool>::failure(mask.error().code, mask.error().offset);

    packet_bytes[0] ^=
        static_cast<std::byte>(std::to_integer<std::uint8_t>(mask.value()[0]) & 0x1fu);
    for (std::size_t index = 0; index < packet_number.packet_number_length; ++index) {
        packet_bytes[packet_number.packet_number_offset + index] ^= mask.value()[index + 1];
    }

    return CodecResult<bool>::success(true);
}

CodecResult<RemovedShortHeaderProtection>
remove_short_header_protection(std::span<const std::byte> bytes, std::size_t packet_number_offset,
                               CipherSuite cipher_suite, const PacketProtectionKeys &keys) {
    if (packet_number_offset + kHeaderProtectionSampleOffset > bytes.size())
        return CodecResult<RemovedShortHeaderProtection>::failure(
            CodecErrorCode::header_protection_sample_too_short, 0);

    std::vector<std::byte> packet_bytes(bytes.begin(), bytes.end());
    const auto mask = make_header_protection_mask(
        cipher_suite, keys.hp_key,
        std::span<const std::byte>(packet_bytes)
            .subspan(packet_number_offset + kHeaderProtectionSampleOffset));
    if (!mask.has_value())
        return CodecResult<RemovedShortHeaderProtection>::failure(mask.error().code,
                                                                  mask.error().offset);

    packet_bytes[0] ^=
        static_cast<std::byte>(std::to_integer<std::uint8_t>(mask.value()[0]) & 0x1fu);
    const auto packet_number_length =
        static_cast<std::uint8_t>((std::to_integer<std::uint8_t>(packet_bytes[0]) & 0x03u) + 1u);
    const auto packet_number_length_mismatch =
        consume_protected_codec_fault(
            test::ProtectedCodecFaultPoint::remove_short_header_packet_length_mismatch) |
        (packet_number_offset + packet_number_length > packet_bytes.size());
    if (packet_number_length_mismatch)
        return CodecResult<RemovedShortHeaderProtection>::failure(
            CodecErrorCode::packet_length_mismatch, packet_number_offset);

    for (std::size_t index = 0; index < packet_number_length; ++index) {
        packet_bytes[packet_number_offset + index] ^= mask.value()[index + 1];
    }

    const auto truncated_packet_number =
        read_packet_number(std::span<const std::byte>(packet_bytes).subspan(packet_number_offset),
                           packet_number_length);

    return CodecResult<RemovedShortHeaderProtection>::success(RemovedShortHeaderProtection{
        .packet_bytes = std::move(packet_bytes),
        .packet_number_length = packet_number_length,
        .truncated_packet_number = truncated_packet_number,
    });
}

LongHeaderLayout locate_long_header_or_assert(std::span<const std::byte> bytes,
                                              LongHeaderPacketType expected_type) {
    return locate_long_header(bytes, expected_type).value();
}

PatchedLengthField patch_long_header_length_field_or_assert(std::vector<std::byte> &packet_bytes,
                                                            const LongHeaderLayout &layout,
                                                            std::uint64_t new_length_value) {
    return patch_long_header_length_field(packet_bytes, layout, new_length_value).value();
}

std::vector<std::byte> make_packet_protection_nonce_or_assert(std::span<const std::byte> iv,
                                                              std::uint64_t packet_number) {
    return make_packet_protection_nonce(iv, packet_number).value();
}

void pad_long_header_plaintext_for_header_protection(std::vector<std::byte> &plaintext_image,
                                                     LongHeaderPacketType packet_type) {
    const auto layout = locate_long_header_or_assert(plaintext_image, packet_type);
    const auto minimum_plaintext_size = layout.packet_number_offset + kHeaderProtectionSampleOffset;
    if (plaintext_image.size() < minimum_plaintext_size) {
        // Trailing zero bytes decode as PADDING frames and make the protected sample available.
        plaintext_image.resize(minimum_plaintext_size, std::byte{0x00});
    }
}

CodecResult<PacketDecodeResult>
deserialize_plaintext_packet_image(std::span<const std::byte> plaintext_image,
                                   const DeserializeOptions &options) {
    if (consume_protected_codec_fault(test::ProtectedCodecFaultPoint::deserialize_plaintext_packet))
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::invalid_varint, 0);

    return deserialize_packet(plaintext_image, options);
}

CodecResult<std::vector<std::byte>>
serialize_protected_initial_packet(const ProtectedInitialPacket &packet,
                                   const SerializeProtectionContext &context) {
    const auto keys = derive_send_initial_keys(context);
    if (!keys.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(keys.error().code, keys.error().offset);
    }

    const auto plaintext_packet = to_plaintext_initial(packet);
    if (!plaintext_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);
    }

    const auto plaintext_image = serialize_packet(Packet{plaintext_packet.value()});
    if (!plaintext_image.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(plaintext_image.error().code,
                                                            plaintext_image.error().offset);
    }

    auto sealed_packet = plaintext_image.value();
    pad_long_header_plaintext_for_header_protection(sealed_packet, LongHeaderPacketType::initial);
    const auto layout = locate_long_header_or_assert(sealed_packet, LongHeaderPacketType::initial);

    const auto plaintext_payload_offset = layout.packet_number_offset + packet.packet_number_length;

    const auto patch = patch_long_header_length_field_or_assert(
        sealed_packet, layout,
        packet.packet_number_length + (sealed_packet.size() - plaintext_payload_offset) + 16);

    const auto protected_payload_offset = patch.packet_number_offset + packet.packet_number_length;
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.value().iv, packet.packet_number);

    const auto ciphertext =
        seal_payload(kInitialCipherSuite, keys.value().key, nonce,
                     std::span<const std::byte>(sealed_packet).first(protected_payload_offset),
                     std::span<const std::byte>(sealed_packet).subspan(protected_payload_offset));
    if (!ciphertext.has_value())
        return CodecResult<std::vector<std::byte>>::failure(ciphertext.error().code,
                                                            ciphertext.error().offset);

    sealed_packet.resize(protected_payload_offset);
    sealed_packet.insert(sealed_packet.end(), ciphertext.value().begin(), ciphertext.value().end());

    return apply_long_header_protection(std::move(sealed_packet),
                                        PacketNumberSpan{
                                            .packet_number_offset = patch.packet_number_offset,
                                            .packet_number_length = packet.packet_number_length,
                                        },
                                        kInitialCipherSuite, keys.value());
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_initial_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context) {
    const auto layout = locate_long_header(bytes, LongHeaderPacketType::initial);
    if (!layout.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                 layout.error().offset);

    const auto keys = derive_receive_initial_keys(context);
    if (!keys.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);

    const auto unprotected =
        remove_long_header_protection(bytes, layout.value(), kInitialCipherSuite, keys.value());
    if (!unprotected.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);

    const auto packet_number = recover_packet_number(
        context.largest_authenticated_initial_packet_number,
        unprotected.value().truncated_packet_number, unprotected.value().packet_number_length);
    if (!packet_number.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);

    const auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.value().iv, packet_number.value());

    const auto plaintext =
        open_payload(kInitialCipherSuite, keys.value().key, nonce,
                     std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
                     std::span<const std::byte>(unprotected.value().packet_bytes)
                         .subspan(header_end, layout.value().packet_end_offset - header_end));
    if (!plaintext.has_value()) {
        std::cerr << "quic initial decrypt fail"
                  << " cid_len=" << context.client_initial_destination_connection_id.size()
                  << " layout_len=" << layout.value().length_value
                  << " pn_len=" << static_cast<int>(unprotected.value().packet_number_length)
                  << " truncated_pn=" << unprotected.value().truncated_packet_number
                  << " recovered_pn=" << packet_number.value() << " first_byte="
                  << static_cast<int>(
                         std::to_integer<std::uint8_t>(unprotected.value().packet_bytes.front()))
                  << '\n';
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);
    }

    auto plaintext_image = std::vector<std::byte>(unprotected.value().packet_bytes.begin(),
                                                  unprotected.value().packet_bytes.begin() +
                                                      static_cast<std::ptrdiff_t>(header_end));
    patch_long_header_length_field_or_assert(plaintext_image, layout.value(),
                                             unprotected.value().packet_number_length +
                                                 plaintext.value().size());
    plaintext_image.insert(plaintext_image.end(), plaintext.value().begin(),
                           plaintext.value().end());

    const auto decoded = deserialize_plaintext_packet_image(plaintext_image, {});
    if (!decoded.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);

    const auto &initial = std::get<InitialPacket>(decoded.value().packet);

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedInitialPacket{
                .version = initial.version,
                .destination_connection_id = initial.destination_connection_id,
                .source_connection_id = initial.source_connection_id,
                .token = initial.token,
                .packet_number_length = initial.packet_number_length,
                .packet_number = packet_number.value(),
                .frames = initial.frames,
            },
        .bytes_consumed = layout.value().packet_end_offset,
    });
}

CodecResult<std::vector<std::byte>>
serialize_protected_handshake_packet(const ProtectedHandshakePacket &packet,
                                     const SerializeProtectionContext &context) {
    if (!context.handshake_secret.has_value())
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::missing_crypto_context,
                                                            0);

    const auto keys = expand_traffic_secret(context.handshake_secret.value());
    if (!keys.has_value())
        return CodecResult<std::vector<std::byte>>::failure(keys.error().code, keys.error().offset);

    const auto plaintext_packet = to_plaintext_handshake(packet);
    if (!plaintext_packet.has_value())
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);

    const auto plaintext_image = serialize_packet(Packet{plaintext_packet.value()});
    if (!plaintext_image.has_value())
        return CodecResult<std::vector<std::byte>>::failure(plaintext_image.error().code,
                                                            plaintext_image.error().offset);

    auto sealed_packet = plaintext_image.value();
    pad_long_header_plaintext_for_header_protection(sealed_packet, LongHeaderPacketType::handshake);
    const auto layout =
        locate_long_header_or_assert(sealed_packet, LongHeaderPacketType::handshake);

    const auto plaintext_payload_offset = layout.packet_number_offset + packet.packet_number_length;

    const auto patch = patch_long_header_length_field_or_assert(
        sealed_packet, layout,
        packet.packet_number_length + (sealed_packet.size() - plaintext_payload_offset) + 16);

    const auto cipher_suite = context.handshake_secret->cipher_suite;
    const auto protected_payload_offset = patch.packet_number_offset + packet.packet_number_length;
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.value().iv, packet.packet_number);

    const auto ciphertext =
        seal_payload(cipher_suite, keys.value().key, nonce,
                     std::span<const std::byte>(sealed_packet).first(protected_payload_offset),
                     std::span<const std::byte>(sealed_packet).subspan(protected_payload_offset));
    if (!ciphertext.has_value())
        return CodecResult<std::vector<std::byte>>::failure(ciphertext.error().code,
                                                            ciphertext.error().offset);

    sealed_packet.resize(protected_payload_offset);
    sealed_packet.insert(sealed_packet.end(), ciphertext.value().begin(), ciphertext.value().end());

    return apply_long_header_protection(std::move(sealed_packet),
                                        PacketNumberSpan{
                                            .packet_number_offset = patch.packet_number_offset,
                                            .packet_number_length = packet.packet_number_length,
                                        },
                                        cipher_suite, keys.value());
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_handshake_packet(std::span<const std::byte> bytes,
                                       const DeserializeProtectionContext &context) {
    if (!context.handshake_secret.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);

    const auto layout = locate_long_header(bytes, LongHeaderPacketType::handshake);
    if (!layout.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                 layout.error().offset);

    const auto keys = expand_traffic_secret(context.handshake_secret.value());
    if (!keys.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);

    const auto cipher_suite = context.handshake_secret->cipher_suite;
    const auto unprotected =
        remove_long_header_protection(bytes, layout.value(), cipher_suite, keys.value());
    if (!unprotected.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);

    const auto packet_number = recover_packet_number(
        context.largest_authenticated_handshake_packet_number,
        unprotected.value().truncated_packet_number, unprotected.value().packet_number_length);
    if (!packet_number.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);

    const auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.value().iv, packet_number.value());

    const auto plaintext =
        open_payload(cipher_suite, keys.value().key, nonce,
                     std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
                     std::span<const std::byte>(unprotected.value().packet_bytes)
                         .subspan(header_end, layout.value().packet_end_offset - header_end));
    if (!plaintext.has_value()) {
        std::cerr << "quic handshake decrypt fail"
                  << " secret_present=" << context.handshake_secret.has_value() << " secret_len="
                  << (context.handshake_secret.has_value() ? context.handshake_secret->secret.size()
                                                           : 0u)
                  << " layout_len=" << layout.value().length_value
                  << " pn_len=" << static_cast<int>(unprotected.value().packet_number_length)
                  << " truncated_pn=" << unprotected.value().truncated_packet_number
                  << " recovered_pn=" << packet_number.value() << " first_byte="
                  << static_cast<int>(
                         std::to_integer<std::uint8_t>(unprotected.value().packet_bytes.front()))
                  << '\n';
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);
    }

    auto plaintext_image = std::vector<std::byte>(unprotected.value().packet_bytes.begin(),
                                                  unprotected.value().packet_bytes.begin() +
                                                      static_cast<std::ptrdiff_t>(header_end));
    patch_long_header_length_field_or_assert(plaintext_image, layout.value(),
                                             unprotected.value().packet_number_length +
                                                 plaintext.value().size());
    plaintext_image.insert(plaintext_image.end(), plaintext.value().begin(),
                           plaintext.value().end());

    const auto decoded = deserialize_plaintext_packet_image(plaintext_image, {});
    if (!decoded.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);

    const auto &handshake = std::get<HandshakePacket>(decoded.value().packet);

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedHandshakePacket{
                .version = handshake.version,
                .destination_connection_id = handshake.destination_connection_id,
                .source_connection_id = handshake.source_connection_id,
                .packet_number_length = handshake.packet_number_length,
                .packet_number = packet_number.value(),
                .frames = handshake.frames,
            },
        .bytes_consumed = layout.value().packet_end_offset,
    });
}

void pad_short_header_plaintext_for_header_protection(std::vector<std::byte> &plaintext_image,
                                                      std::size_t packet_number_offset) {
    const auto minimum_plaintext_size = packet_number_offset + kHeaderProtectionSampleOffset;
    if (plaintext_image.size() < minimum_plaintext_size) {
        // Trailing zero bytes decode as PADDING frames and make the protected sample available.
        plaintext_image.resize(minimum_plaintext_size, std::byte{0x00});
    }
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(std::vector<std::byte> &datagram,
                                                 const ProtectedOneRttPacket &packet,
                                                 const SerializeProtectionContext &context) {
    if (!context.one_rtt_secret.has_value())
        return CodecResult<std::size_t>::failure(CodecErrorCode::missing_crypto_context, 0);
    if (packet.key_phase != context.one_rtt_key_phase)
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);

    const auto keys = expand_traffic_secret(context.one_rtt_secret.value());
    if (!keys.has_value())
        return CodecResult<std::size_t>::failure(keys.error().code, keys.error().offset);

    const auto packet_number_offset = 1 + packet.destination_connection_id.size();
    const auto payload_offset = packet_number_offset + packet.packet_number_length;
    const auto cipher_suite = context.one_rtt_secret->cipher_suite;
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.value().iv, packet.packet_number);
    const auto packet_number_span = PacketNumberSpan{
        .packet_number_offset = packet_number_offset,
        .packet_number_length = packet.packet_number_length,
    };
    const auto datagram_begin = datagram.size();
    const auto rollback = [&]() { datagram.resize(datagram_begin); };

    if (packet.stream_frame_views.empty()) {
        CodecResult<std::vector<std::byte>> plaintext_image =
            CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::unsupported_packet_type,
                                                         0);
        const auto plaintext_packet = to_plaintext_one_rtt(packet);
        if (!plaintext_packet.has_value())
            return CodecResult<std::size_t>::failure(plaintext_packet.error().code,
                                                     plaintext_packet.error().offset);

        plaintext_image = serialize_packet(Packet{plaintext_packet.value()});
        if (!plaintext_image.has_value())
            return CodecResult<std::size_t>::failure(plaintext_image.error().code,
                                                     plaintext_image.error().offset);

        auto padded_plaintext_image = std::move(plaintext_image.value());
        pad_short_header_plaintext_for_header_protection(padded_plaintext_image,
                                                         packet_number_offset);
        const auto plaintext_payload =
            std::span<const std::byte>(padded_plaintext_image).subspan(payload_offset);
        const auto packet_size =
            payload_offset + plaintext_payload.size() + kPacketProtectionTagLength;
        datagram.resize(datagram_begin + packet_size);
        auto packet_bytes = std::span<std::byte>(datagram).subspan(datagram_begin, packet_size);
        std::copy_n(padded_plaintext_image.begin(), payload_offset, packet_bytes.begin());

        const auto ciphertext = seal_payload_into(
            cipher_suite, keys.value().key, nonce,
            std::span<const std::byte>(padded_plaintext_image).first(payload_offset),
            plaintext_payload, packet_bytes.subspan(payload_offset));
        if (!ciphertext.has_value()) {
            rollback();
            return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                     ciphertext.error().offset);
        }

        const auto final_packet_size = payload_offset + ciphertext.value();
        datagram.resize(datagram_begin + final_packet_size);
        const auto protected_packet = apply_short_header_protection_in_place(
            std::span<std::byte>(datagram).subspan(datagram_begin, final_packet_size),
            packet_number_span, cipher_suite, keys.value());
        if (!protected_packet.has_value()) {
            rollback();
            return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                     protected_packet.error().offset);
        }

        return CodecResult<std::size_t>::success(final_packet_size);
    }

    const auto packet_chunks = serialize_chunked_one_rtt_packet_with_stream_views(packet);
    if (!packet_chunks.has_value()) {
        return CodecResult<std::size_t>::failure(packet_chunks.error().code,
                                                 packet_chunks.error().offset);
    }
    const auto packet_size = packet_chunks.value().header.size() +
                             packet_chunks.value().payload_size + kPacketProtectionTagLength;
    datagram.resize(datagram_begin + packet_size);
    auto packet_bytes = std::span<std::byte>(datagram).subspan(datagram_begin, packet_size);
    std::copy(packet_chunks.value().header.begin(), packet_chunks.value().header.end(),
              packet_bytes.begin());

    const auto ciphertext = seal_payload_chunks_into(
        cipher_suite, keys.value().key, nonce, packet_chunks.value().header,
        packet_chunks.value().payload_chunks, packet_bytes.subspan(payload_offset));
    if (!ciphertext.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                 ciphertext.error().offset);
    }

    const auto final_packet_size = payload_offset + ciphertext.value();
    datagram.resize(datagram_begin + final_packet_size);
    const auto protected_packet = apply_short_header_protection_in_place(
        std::span<std::byte>(datagram).subspan(datagram_begin, final_packet_size),
        packet_number_span, cipher_suite, keys.value());
    if (!protected_packet.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                 protected_packet.error().offset);
    }

    return CodecResult<std::size_t>::success(final_packet_size);
}

CodecResult<std::vector<std::byte>>
serialize_protected_one_rtt_packet(const ProtectedOneRttPacket &packet,
                                   const SerializeProtectionContext &context) {
    std::vector<std::byte> packet_bytes;
    const auto appended =
        append_protected_one_rtt_packet_to_datagram_impl(packet_bytes, packet, context);
    if (!appended.has_value())
        return CodecResult<std::vector<std::byte>>::failure(appended.error().code,
                                                            appended.error().offset);

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_one_rtt_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context) {
    if (!context.one_rtt_secret.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    if (context.one_rtt_destination_connection_id_length == 0)
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, 0);

    const auto packet_number_offset = 1 + context.one_rtt_destination_connection_id_length;
    if (packet_number_offset > bytes.size())
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, 1);

    const auto keys = expand_traffic_secret(context.one_rtt_secret.value());
    if (!keys.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);

    const auto cipher_suite = context.one_rtt_secret->cipher_suite;
    const auto unprotected =
        remove_short_header_protection(bytes, packet_number_offset, cipher_suite, keys.value());
    if (!unprotected.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);

    const auto key_phase =
        (std::to_integer<std::uint8_t>(unprotected.value().packet_bytes[0]) & 0x04u) != 0;
    if (key_phase != context.one_rtt_key_phase)
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);

    const auto packet_number = recover_packet_number(
        context.largest_authenticated_application_packet_number,
        unprotected.value().truncated_packet_number, unprotected.value().packet_number_length);
    if (!packet_number.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);

    const auto header_end = packet_number_offset + unprotected.value().packet_number_length;
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.value().iv, packet_number.value());

    const auto plaintext = open_payload(
        cipher_suite, keys.value().key, nonce,
        std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        std::span<const std::byte>(unprotected.value().packet_bytes).subspan(header_end));
    if (!plaintext.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);

    auto plaintext_image = std::vector<std::byte>(unprotected.value().packet_bytes.begin(),
                                                  unprotected.value().packet_bytes.begin() +
                                                      static_cast<std::ptrdiff_t>(header_end));
    plaintext_image.insert(plaintext_image.end(), plaintext.value().begin(),
                           plaintext.value().end());

    const auto decoded = deserialize_plaintext_packet_image(
        plaintext_image, DeserializeOptions{
                             .one_rtt_destination_connection_id_length =
                                 context.one_rtt_destination_connection_id_length,
                         });
    if (!decoded.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);

    const auto &one_rtt = std::get<OneRttPacket>(decoded.value().packet);

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedOneRttPacket{
                .spin_bit = one_rtt.spin_bit,
                .key_phase = one_rtt.key_phase,
                .destination_connection_id = one_rtt.destination_connection_id,
                .packet_number_length = one_rtt.packet_number_length,
                .packet_number = packet_number.value(),
                .frames = one_rtt.frames,
            },
        .bytes_consumed = bytes.size(),
    });
}

} // namespace

CodecResult<std::vector<std::byte>>
serialize_protected_datagram(std::span<const ProtectedPacket> packets,
                             const SerializeProtectionContext &context) {
    std::vector<std::byte> datagram;
    for (std::size_t index = 0; index < packets.size(); ++index) {
        const auto encoded = std::visit(
            [&](const auto &packet) -> CodecResult<std::vector<std::byte>> {
                using PacketType = std::decay_t<decltype(packet)>;
                if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                    return serialize_protected_initial_packet(packet, context);
                } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                    return serialize_protected_handshake_packet(packet, context);
                } else {
                    const auto appended =
                        append_protected_one_rtt_packet_to_datagram_impl(datagram, packet, context);
                    if (!appended.has_value()) {
                        return CodecResult<std::vector<std::byte>>::failure(
                            appended.error().code, appended.error().offset);
                    }
                    return CodecResult<std::vector<std::byte>>::success({});
                }
            },
            packets[index]);
        if (!encoded.has_value())
            return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                                encoded.error().offset);

        datagram.insert(datagram.end(), encoded.value().begin(), encoded.value().end());
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(datagram));
}

CodecResult<std::vector<ProtectedPacket>>
deserialize_protected_datagram(std::span<const std::byte> bytes,
                               const DeserializeProtectionContext &context) {
    if (bytes.empty())
        return CodecResult<std::vector<ProtectedPacket>>::failure(CodecErrorCode::truncated_input,
                                                                  0);

    std::vector<ProtectedPacket> packets;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        CodecResult<ProtectedPacketDecodeResult> decoded =
            CodecResult<ProtectedPacketDecodeResult>::failure(
                CodecErrorCode::unsupported_packet_type, 0);
        const auto first_byte = std::to_integer<std::uint8_t>(bytes[offset]);
        if ((first_byte & 0x80u) == 0) {
            decoded = deserialize_protected_one_rtt_packet(bytes.subspan(offset), context);
        } else {
            const auto type = read_long_header_type(bytes.subspan(offset));
            if (!type.has_value())
                return CodecResult<std::vector<ProtectedPacket>>::failure(
                    type.error().code, offset + type.error().offset);

            if (type.value() == static_cast<std::uint8_t>(LongHeaderPacketType::initial)) {
                decoded = deserialize_protected_initial_packet(bytes.subspan(offset), context);
            } else if (type.value() == static_cast<std::uint8_t>(LongHeaderPacketType::handshake)) {
                decoded = deserialize_protected_handshake_packet(bytes.subspan(offset), context);
            }
        }
        if (!decoded.has_value())
            return CodecResult<std::vector<ProtectedPacket>>::failure(
                decoded.error().code, offset + decoded.error().offset);

        packets.push_back(std::move(decoded.value().packet));
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<ProtectedPacket>>::success(std::move(packets));
}

} // namespace coquic::quic

namespace coquic::quic::test {

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacket &packet,
                                            const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl(datagram, packet, context);
}

ScopedProtectedCodecFaultInjector::ScopedProtectedCodecFaultInjector(
    ProtectedCodecFaultPoint fault_point, std::size_t occurrence)
    : previous_fault_point_(protected_codec_fault_state().fault_point),
      previous_occurrence_(protected_codec_fault_state().occurrence) {
    set_protected_codec_fault_state(fault_point, occurrence);
}

ScopedProtectedCodecFaultInjector::~ScopedProtectedCodecFaultInjector() {
    set_protected_codec_fault_state(previous_fault_point_, previous_occurrence_);
}

} // namespace coquic::quic::test
