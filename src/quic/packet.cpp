#include "src/quic/packet.h"

#include <type_traits>
#include "src/quic/buffer.h"

namespace coquic::quic {

namespace {

constexpr std::uint32_t kVersionNegotiationVersion = 0;
constexpr std::uint32_t kQuicV1 = 1;

enum class ProtectedPacketType : std::uint8_t {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
};

void append_varint(BufferWriter &writer, std::uint64_t value) {
    writer.write_bytes(encode_varint(value).value());
}

CodecResult<std::uint64_t> read_varint(BufferReader &reader) {
    const auto decoded = decode_varint(reader);
    if (!decoded.has_value()) {
        return CodecResult<std::uint64_t>::failure(decoded.error().code, decoded.error().offset);
    }

    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

CodecResult<std::uint8_t> read_u8(BufferReader &reader) {
    const auto byte = reader.read_byte();
    if (!byte.has_value()) {
        return CodecResult<std::uint8_t>::failure(byte.error().code, byte.error().offset);
    }

    return CodecResult<std::uint8_t>::success(static_cast<std::uint8_t>(byte.value()));
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | static_cast<std::uint8_t>(byte);
    }
    return value;
}

void write_u32_be(BufferWriter &writer, std::uint32_t value) {
    writer.write_byte(static_cast<std::byte>((value >> 24) & 0xffu));
    writer.write_byte(static_cast<std::byte>((value >> 16) & 0xffu));
    writer.write_byte(static_cast<std::byte>((value >> 8) & 0xffu));
    writer.write_byte(static_cast<std::byte>(value & 0xffu));
}

bool valid_packet_number_length(std::uint8_t packet_number_length) {
    return (packet_number_length >= 1) & (packet_number_length <= 4);
}

struct PacketNumberEncoding {
    std::uint8_t packet_number_length;
    std::uint32_t truncated_packet_number;
};

bool valid_truncated_packet_number(const PacketNumberEncoding &encoding) {
    const auto packet_number_length = encoding.packet_number_length;
    const auto truncated_packet_number = encoding.truncated_packet_number;
    if (!valid_packet_number_length(packet_number_length)) {
        return false;
    }
    if (packet_number_length == 4) {
        return true;
    }

    const auto max_value = (std::uint64_t{1} << (packet_number_length * 8)) - 1;
    return truncated_packet_number <= max_value;
}

std::optional<CodecError> append_packet_number(BufferWriter &writer,
                                               const PacketNumberEncoding &encoding) {
    for (std::size_t i = 0; i < encoding.packet_number_length; ++i) {
        const auto shift = static_cast<unsigned>((encoding.packet_number_length - i - 1) * 8);
        writer.write_byte(
            static_cast<std::byte>((encoding.truncated_packet_number >> shift) & 0xffu));
    }
    return std::nullopt;
}

CodecResult<std::uint32_t> read_packet_number(BufferReader &reader,
                                              std::uint8_t packet_number_length) {
    const auto bytes = reader.read_exact(packet_number_length);
    if (!bytes.has_value()) {
        return CodecResult<std::uint32_t>::failure(bytes.error().code, bytes.error().offset);
    }

    std::uint32_t packet_number = 0;
    for (const auto byte : bytes.value()) {
        packet_number = (packet_number << 8) | static_cast<std::uint8_t>(byte);
    }

    return CodecResult<std::uint32_t>::success(packet_number);
}

void append_connection_id(BufferWriter &writer, const ConnectionId &connection_id,
                          bool enforce_v1_limit) {
    (void)enforce_v1_limit;
    writer.write_byte(static_cast<std::byte>(connection_id.size()));
    writer.write_bytes(connection_id);
}

CodecResult<ConnectionId> read_connection_id(BufferReader &reader, bool enforce_v1_limit) {
    const auto length = read_u8(reader);
    if (!length.has_value()) {
        return CodecResult<ConnectionId>::failure(length.error().code, length.error().offset);
    }
    if (enforce_v1_limit && length.value() > 20) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    const auto bytes = reader.read_exact(length.value());
    if (!bytes.has_value()) {
        return CodecResult<ConnectionId>::failure(bytes.error().code, bytes.error().offset);
    }

    return CodecResult<ConnectionId>::success(ConnectionId{
        bytes.value().begin(),
        bytes.value().end(),
    });
}

bool frame_allowed_in_packet_type(const Frame &frame, ProtectedPacketType packet_type) {
    if (packet_type == ProtectedPacketType::one_rtt) {
        return true;
    }

    const auto frame_index = frame.index();
    const auto packet_type_allows_handshake_space_frames =
        packet_type == ProtectedPacketType::initial ||
        packet_type == ProtectedPacketType::handshake;
    if (packet_type_allows_handshake_space_frames) {
        return (frame_index == 0) | (frame_index == 1) | (frame_index == 2) | (frame_index == 5) |
               (frame_index == 18);
    }

    const auto forbidden_in_zero_rtt = (frame_index == 2) | (frame_index == 5) |
                                       (frame_index == 20) | (frame_index == 6) |
                                       (frame_index == 17) | (frame_index == 15);
    return !forbidden_in_zero_rtt;
}

CodecResult<std::vector<std::byte>> serialize_frame_sequence(const std::vector<Frame> &frames,
                                                             ProtectedPacketType packet_type) {
    if (frames.empty()) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::empty_packet_payload,
                                                            0);
    }

    BufferWriter writer;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (!frame_allowed_in_packet_type(frames[i], packet_type)) {
            return CodecResult<std::vector<std::byte>>::failure(
                CodecErrorCode::frame_not_allowed_in_packet_type, i);
        }

        if (const auto *stream = std::get_if<StreamFrame>(&frames[i]);
            stream != nullptr && !stream->has_length && i + 1 != frames.size()) {
            return CodecResult<std::vector<std::byte>>::failure(
                CodecErrorCode::packet_length_mismatch, i);
        }

        const auto encoded = serialize_frame(frames[i]);
        if (!encoded.has_value()) {
            return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                                encoded.error().offset);
        }
        writer.write_bytes(encoded.value());
    }

    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

CodecResult<std::vector<Frame>> deserialize_frame_sequence(std::span<const std::byte> payload,
                                                           ProtectedPacketType packet_type,
                                                           std::size_t base_offset) {
    if (payload.empty()) {
        return CodecResult<std::vector<Frame>>::failure(CodecErrorCode::empty_packet_payload,
                                                        base_offset);
    }

    std::vector<Frame> frames;
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const auto decoded = deserialize_frame(payload.subspan(offset));
        if (!decoded.has_value()) {
            return CodecResult<std::vector<Frame>>::failure(
                decoded.error().code, base_offset + offset + decoded.error().offset);
        }
        if (!frame_allowed_in_packet_type(decoded.value().frame, packet_type)) {
            return CodecResult<std::vector<Frame>>::failure(
                CodecErrorCode::frame_not_allowed_in_packet_type, base_offset + offset);
        }

        frames.push_back(decoded.value().frame);
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<Frame>>::success(std::move(frames));
}

std::byte make_long_header_first_byte(std::uint8_t type, std::uint8_t packet_number_length) {
    return static_cast<std::byte>(0x80u | 0x40u | ((type & 0x03u) << 4) |
                                  ((packet_number_length - 1) & 0x03u));
}

std::byte make_short_header_first_byte(bool spin_bit, bool key_phase,
                                       std::uint8_t packet_number_length) {
    return static_cast<std::byte>(0x40u | (spin_bit ? 0x20u : 0u) | (key_phase ? 0x04u : 0u) |
                                  ((packet_number_length - 1) & 0x03u));
}

CodecResult<PacketDecodeResult> decode_version_negotiation_packet(std::uint8_t first_byte,
                                                                  BufferReader &reader) {
    (void)first_byte;

    const auto destination_connection_id = read_connection_id(reader, false);
    if (!destination_connection_id.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(destination_connection_id.error().code,
                                                        destination_connection_id.error().offset);
    }

    const auto source_connection_id = read_connection_id(reader, false);
    if (!source_connection_id.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(source_connection_id.error().code,
                                                        source_connection_id.error().offset);
    }

    if (reader.remaining() == 0 || (reader.remaining() % 4) != 0) {
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::packet_length_mismatch,
                                                        reader.offset());
    }

    std::vector<std::uint32_t> versions;
    while (reader.remaining() > 0) {
        versions.push_back(read_u32_be(reader.read_exact(4).value()));
    }

    return CodecResult<PacketDecodeResult>::success(PacketDecodeResult{
        .packet =
            VersionNegotiationPacket{
                .destination_connection_id = destination_connection_id.value(),
                .source_connection_id = source_connection_id.value(),
                .supported_versions = std::move(versions),
            },
        .bytes_consumed = reader.offset(),
    });
}

struct DecodedLongHeaderFields {
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> token;
    std::uint32_t packet_number = 0;
    std::vector<Frame> frames;
    std::size_t bytes_consumed = 0;
};

CodecResult<DecodedLongHeaderFields> decode_long_header_fields(BufferReader &reader,
                                                               std::uint32_t version,
                                                               ProtectedPacketType packet_type,
                                                               std::uint8_t packet_number_length,
                                                               bool has_token) {
    const auto destination_connection_id = read_connection_id(reader, version == kQuicV1);
    if (!destination_connection_id.has_value()) {
        return CodecResult<DecodedLongHeaderFields>::failure(
            destination_connection_id.error().code, destination_connection_id.error().offset);
    }

    const auto source_connection_id = read_connection_id(reader, version == kQuicV1);
    if (!source_connection_id.has_value()) {
        return CodecResult<DecodedLongHeaderFields>::failure(source_connection_id.error().code,
                                                             source_connection_id.error().offset);
    }

    std::vector<std::byte> token;
    if (has_token) {
        const auto token_length = read_varint(reader);
        if (!token_length.has_value()) {
            return CodecResult<DecodedLongHeaderFields>::failure(token_length.error().code,
                                                                 token_length.error().offset);
        }
        if (token_length.value() > static_cast<std::uint64_t>(reader.remaining())) {
            return CodecResult<DecodedLongHeaderFields>::failure(
                CodecErrorCode::packet_length_mismatch, reader.offset());
        }
        const auto token_bytes =
            reader.read_exact(static_cast<std::size_t>(token_length.value())).value();
        token.assign(token_bytes.begin(), token_bytes.end());
    }

    const auto payload_length = read_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<DecodedLongHeaderFields>::failure(payload_length.error().code,
                                                             payload_length.error().offset);
    }
    const auto invalid_payload_length =
        (payload_length.value() < packet_number_length) |
        (payload_length.value() > static_cast<std::uint64_t>(reader.remaining()));
    if (invalid_payload_length) {
        return CodecResult<DecodedLongHeaderFields>::failure(CodecErrorCode::packet_length_mismatch,
                                                             reader.offset());
    }

    const auto packet_payload_bytes = payload_length.value() - packet_number_length;
    const auto packet_number = read_packet_number(reader, packet_number_length).value();
    const auto payload = reader.read_exact(static_cast<std::size_t>(packet_payload_bytes)).value();

    auto frames = deserialize_frame_sequence(payload, packet_type, reader.offset());
    if (!frames.has_value()) {
        return CodecResult<DecodedLongHeaderFields>::failure(frames.error().code,
                                                             frames.error().offset);
    }

    return CodecResult<DecodedLongHeaderFields>::success(DecodedLongHeaderFields{
        .destination_connection_id = destination_connection_id.value(),
        .source_connection_id = source_connection_id.value(),
        .token = std::move(token),
        .packet_number = packet_number,
        .frames = std::move(frames.value()),
        .bytes_consumed = reader.offset(),
    });
}

template <typename PacketType>
CodecResult<PacketDecodeResult>
decode_long_header_packet(BufferReader &reader, std::uint32_t version,
                          std::uint8_t packet_number_length, ProtectedPacketType packet_type,
                          bool has_token) {
    auto decoded =
        decode_long_header_fields(reader, version, packet_type, packet_number_length, has_token);
    if (!decoded.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(decoded.error().code,
                                                        decoded.error().offset);
    }

    if constexpr (std::is_same_v<PacketType, InitialPacket>) {
        return CodecResult<PacketDecodeResult>::success(PacketDecodeResult{
            .packet =
                InitialPacket{
                    .version = version,
                    .destination_connection_id =
                        std::move(decoded.value().destination_connection_id),
                    .source_connection_id = std::move(decoded.value().source_connection_id),
                    .token = std::move(decoded.value().token),
                    .packet_number_length = packet_number_length,
                    .truncated_packet_number = decoded.value().packet_number,
                    .frames = std::move(decoded.value().frames),
                },
            .bytes_consumed = decoded.value().bytes_consumed,
        });
    }

    if constexpr (std::is_same_v<PacketType, ZeroRttPacket>) {
        return CodecResult<PacketDecodeResult>::success(PacketDecodeResult{
            .packet =
                ZeroRttPacket{
                    .version = version,
                    .destination_connection_id =
                        std::move(decoded.value().destination_connection_id),
                    .source_connection_id = std::move(decoded.value().source_connection_id),
                    .packet_number_length = packet_number_length,
                    .truncated_packet_number = decoded.value().packet_number,
                    .frames = std::move(decoded.value().frames),
                },
            .bytes_consumed = decoded.value().bytes_consumed,
        });
    }

    if constexpr (std::is_same_v<PacketType, HandshakePacket>) {
        return CodecResult<PacketDecodeResult>::success(PacketDecodeResult{
            .packet =
                HandshakePacket{
                    .version = version,
                    .destination_connection_id =
                        std::move(decoded.value().destination_connection_id),
                    .source_connection_id = std::move(decoded.value().source_connection_id),
                    .packet_number_length = packet_number_length,
                    .truncated_packet_number = decoded.value().packet_number,
                    .frames = std::move(decoded.value().frames),
                },
            .bytes_consumed = decoded.value().bytes_consumed,
        });
    }
}

CodecResult<PacketDecodeResult> decode_retry_packet(BufferReader &reader, std::uint32_t version) {
    const auto destination_connection_id = read_connection_id(reader, version == kQuicV1);
    if (!destination_connection_id.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(destination_connection_id.error().code,
                                                        destination_connection_id.error().offset);
    }

    const auto source_connection_id = read_connection_id(reader, version == kQuicV1);
    if (!source_connection_id.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(source_connection_id.error().code,
                                                        source_connection_id.error().offset);
    }

    if (reader.remaining() < 16) {
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::packet_length_mismatch,
                                                        reader.offset());
    }

    const auto token_length = reader.remaining() - 16;
    const auto token = reader.read_exact(token_length).value();
    const auto integrity_tag = reader.read_exact(16).value();

    std::array<std::byte, 16> retry_integrity_tag{};
    for (std::size_t i = 0; i < retry_integrity_tag.size(); ++i) {
        retry_integrity_tag[i] = integrity_tag[i];
    }

    return CodecResult<PacketDecodeResult>::success(PacketDecodeResult{
        .packet =
            RetryPacket{
                .version = version,
                .destination_connection_id = destination_connection_id.value(),
                .source_connection_id = source_connection_id.value(),
                .retry_token = std::vector<std::byte>(token.begin(), token.end()),
                .retry_integrity_tag = retry_integrity_tag,
            },
        .bytes_consumed = reader.offset(),
    });
}

CodecResult<PacketDecodeResult> decode_short_header_packet(std::span<const std::byte> bytes,
                                                           BufferReader &reader,
                                                           std::uint8_t first_byte,
                                                           const DeserializeOptions &options) {
    if ((first_byte & 0x40u) == 0) {
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }
    if ((first_byte & 0x18u) != 0) {
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::invalid_reserved_bits, 0);
    }

    if (!options.one_rtt_destination_connection_id_length.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, 0);
    }

    const auto destination_connection_id_length =
        options.one_rtt_destination_connection_id_length.value();
    if (destination_connection_id_length > reader.remaining()) {
        return CodecResult<PacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, reader.offset());
    }

    const auto destination_connection_id_bytes =
        reader.read_exact(destination_connection_id_length).value();

    const auto packet_number_length = static_cast<std::uint8_t>((first_byte & 0x03u) + 1);
    const auto packet_number = read_packet_number(reader, packet_number_length);
    if (!packet_number.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(packet_number.error().code,
                                                        packet_number.error().offset);
    }

    if (reader.remaining() == 0) {
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::empty_packet_payload,
                                                        reader.offset());
    }

    const auto payload = reader.read_exact(reader.remaining()).value();
    auto frames =
        deserialize_frame_sequence(payload, ProtectedPacketType::one_rtt, reader.offset());
    if (!frames.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(frames.error().code, frames.error().offset);
    }

    return CodecResult<PacketDecodeResult>::success(PacketDecodeResult{
        .packet =
            OneRttPacket{
                .spin_bit = (first_byte & 0x20u) != 0,
                .key_phase = (first_byte & 0x04u) != 0,
                .destination_connection_id =
                    ConnectionId{
                        destination_connection_id_bytes.begin(),
                        destination_connection_id_bytes.end(),
                    },
                .packet_number_length = packet_number_length,
                .truncated_packet_number = packet_number.value(),
                .frames = std::move(frames.value()),
            },
        .bytes_consumed = bytes.size(),
    });
}

CodecResult<std::vector<std::byte>> serialize_long_header_fields(
    std::uint32_t version, const ConnectionId &destination_connection_id,
    const ConnectionId &source_connection_id, const std::vector<std::byte> *token,
    std::uint8_t packet_number_length, std::uint32_t truncated_packet_number,
    const std::vector<Frame> &frames, std::uint8_t type, ProtectedPacketType packet_type) {
    if (version == kVersionNegotiationVersion) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::unsupported_packet_type,
                                                            0);
    }
    const auto invalid_v1_connection_id =
        (version == kQuicV1) &
        ((destination_connection_id.size() > 20) | (source_connection_id.size() > 20));
    if (invalid_v1_connection_id) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (!valid_truncated_packet_number(PacketNumberEncoding{
            .packet_number_length = packet_number_length,
            .truncated_packet_number = truncated_packet_number,
        })) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload = serialize_frame_sequence(frames, packet_type);
    if (!payload.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(payload.error().code,
                                                            payload.error().offset);
    }

    BufferWriter writer;
    writer.write_byte(make_long_header_first_byte(type, packet_number_length));
    write_u32_be(writer, version);

    append_connection_id(writer, destination_connection_id, version == kQuicV1);
    append_connection_id(writer, source_connection_id, version == kQuicV1);
    if (token != nullptr) {
        append_varint(writer, token->size());
        writer.write_bytes(*token);
    }

    const auto packet_payload_length =
        static_cast<std::uint64_t>(packet_number_length + payload.value().size());
    append_varint(writer, packet_payload_length);
    append_packet_number(writer, PacketNumberEncoding{
                                     .packet_number_length = packet_number_length,
                                     .truncated_packet_number = truncated_packet_number,
                                 });
    writer.write_bytes(payload.value());

    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

template <typename PacketType, bool IncludeToken>
CodecResult<std::vector<std::byte>> serialize_long_header_packet(const PacketType &packet,
                                                                 std::uint8_t type,
                                                                 ProtectedPacketType packet_type) {
    const std::vector<std::byte> *token = nullptr;
    if constexpr (IncludeToken) {
        token = &packet.token;
    }

    return serialize_long_header_fields(packet.version, packet.destination_connection_id,
                                        packet.source_connection_id, token,
                                        packet.packet_number_length, packet.truncated_packet_number,
                                        packet.frames, type, packet_type);
}

} // namespace

CodecResult<std::vector<std::byte>> serialize_packet(const Packet &packet) {
    if (const auto *version_negotiation = std::get_if<VersionNegotiationPacket>(&packet)) {
        const auto invalid_version_negotiation =
            (version_negotiation->destination_connection_id.size() > 255) |
            (version_negotiation->source_connection_id.size() > 255) |
            version_negotiation->supported_versions.empty();
        if (invalid_version_negotiation) {
            return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
        }

        BufferWriter writer;
        writer.write_byte(std::byte{0xc0});
        write_u32_be(writer, kVersionNegotiationVersion);
        append_connection_id(writer, version_negotiation->destination_connection_id, false);
        append_connection_id(writer, version_negotiation->source_connection_id, false);
        for (const auto version : version_negotiation->supported_versions) {
            write_u32_be(writer, version);
        }
        return CodecResult<std::vector<std::byte>>::success(writer.bytes());
    }

    if (const auto *retry = std::get_if<RetryPacket>(&packet)) {
        const auto invalid_retry_packet = (retry->version == kVersionNegotiationVersion) |
                                          (retry->destination_connection_id.size() > 20) |
                                          (retry->source_connection_id.size() > 20);
        if (invalid_retry_packet) {
            return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
        }

        BufferWriter writer;
        writer.write_byte(std::byte{0xf0});
        write_u32_be(writer, retry->version);
        append_connection_id(writer, retry->destination_connection_id, true);
        append_connection_id(writer, retry->source_connection_id, true);
        writer.write_bytes(retry->retry_token);
        writer.write_bytes(retry->retry_integrity_tag);
        return CodecResult<std::vector<std::byte>>::success(writer.bytes());
    }

    if (const auto *initial = std::get_if<InitialPacket>(&packet)) {
        return serialize_long_header_packet<InitialPacket, true>(*initial, 0x00,
                                                                 ProtectedPacketType::initial);
    }

    if (const auto *zero_rtt = std::get_if<ZeroRttPacket>(&packet)) {
        return serialize_long_header_packet<ZeroRttPacket, false>(*zero_rtt, 0x01,
                                                                  ProtectedPacketType::zero_rtt);
    }

    if (const auto *handshake = std::get_if<HandshakePacket>(&packet)) {
        return serialize_long_header_packet<HandshakePacket, false>(*handshake, 0x02,
                                                                    ProtectedPacketType::handshake);
    }

    const auto &one_rtt = std::get<OneRttPacket>(packet);
    if (!valid_truncated_packet_number(PacketNumberEncoding{
            .packet_number_length = one_rtt.packet_number_length,
            .truncated_packet_number = one_rtt.truncated_packet_number,
        })) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload = serialize_frame_sequence(one_rtt.frames, ProtectedPacketType::one_rtt);
    if (!payload.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(payload.error().code,
                                                            payload.error().offset);
    }

    BufferWriter writer;
    writer.write_byte(make_short_header_first_byte(one_rtt.spin_bit, one_rtt.key_phase,
                                                   one_rtt.packet_number_length));
    writer.write_bytes(one_rtt.destination_connection_id);
    append_packet_number(writer, PacketNumberEncoding{
                                     .packet_number_length = one_rtt.packet_number_length,
                                     .truncated_packet_number = one_rtt.truncated_packet_number,
                                 });
    writer.write_bytes(payload.value());

    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

CodecResult<PacketDecodeResult> deserialize_packet(std::span<const std::byte> bytes,
                                                   const DeserializeOptions &options) {
    if (bytes.empty()) {
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::truncated_input, 0);
    }

    BufferReader reader(bytes);
    const auto first_byte = static_cast<std::uint8_t>(reader.read_byte().value());

    if ((first_byte & 0x80u) == 0) {
        return decode_short_header_packet(bytes, reader, first_byte, options);
    }

    const auto version_bytes = reader.read_exact(4);
    if (!version_bytes.has_value()) {
        return CodecResult<PacketDecodeResult>::failure(version_bytes.error().code,
                                                        version_bytes.error().offset);
    }
    const auto version = read_u32_be(version_bytes.value());

    if (version == kVersionNegotiationVersion) {
        return decode_version_negotiation_packet(first_byte, reader);
    }

    if ((first_byte & 0x40u) == 0) {
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    const auto invalid_reserved_bits = (type != 0x03u) & ((first_byte & 0x0cu) != 0);
    if (invalid_reserved_bits) {
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::invalid_reserved_bits, 0);
    }

    if (type == 0x03u) {
        return decode_retry_packet(reader, version);
    }

    const auto packet_number_length = static_cast<std::uint8_t>((first_byte & 0x03u) + 1);
    if (type == 0x00) {
        return decode_long_header_packet<InitialPacket>(reader, version, packet_number_length,
                                                        ProtectedPacketType::initial, true);
    }
    if (type == 0x01) {
        return decode_long_header_packet<ZeroRttPacket>(reader, version, packet_number_length,
                                                        ProtectedPacketType::zero_rtt, false);
    }

    return decode_long_header_packet<HandshakePacket>(reader, version, packet_number_length,
                                                      ProtectedPacketType::handshake, false);
}

} // namespace coquic::quic
