#include "src/quic/protected_codec.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/buffer.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/packet_number.h"

namespace coquic::quic {

namespace {

constexpr std::uint32_t kQuicV1 = 1;
constexpr CipherSuite kInitialCipherSuite = CipherSuite::tls_aes_128_gcm_sha256;
constexpr std::size_t kHeaderProtectionSampleOffset = 4;

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

struct RemovedLongHeaderProtection {
    std::vector<std::byte> packet_bytes;
    std::uint8_t packet_number_length = 0;
    std::uint32_t truncated_packet_number = 0;
};

struct ProtectedPacketDecodeResult {
    ProtectedPacket packet;
    std::size_t bytes_consumed = 0;
};

std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

CodecResult<std::uint8_t> read_u8(BufferReader &reader) {
    const auto byte = reader.read_byte();
    if (!byte.has_value()) {
        return CodecResult<std::uint8_t>::failure(byte.error().code, byte.error().offset);
    }

    return CodecResult<std::uint8_t>::success(std::to_integer<std::uint8_t>(byte.value()));
}

CodecResult<std::uint64_t> read_varint(BufferReader &reader) {
    const auto decoded = decode_varint(reader);
    if (!decoded.has_value()) {
        return CodecResult<std::uint64_t>::failure(decoded.error().code, decoded.error().offset);
    }

    return CodecResult<std::uint64_t>::success(decoded.value().value);
}

CodecResult<LongHeaderLayout> locate_initial_long_header(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::truncated_input, 0);
    }

    BufferReader reader(bytes);
    const auto first_byte = read_u8(reader);
    if (!first_byte.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(first_byte.error().code,
                                                      first_byte.error().offset);
    }
    if ((first_byte.value() & 0x80u) == 0) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }
    if ((first_byte.value() & 0x40u) == 0) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version_bytes = reader.read_exact(4);
    if (!version_bytes.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(version_bytes.error().code,
                                                      version_bytes.error().offset);
    }
    if (read_u32_be(version_bytes.value()) != kQuicV1) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto type = static_cast<std::uint8_t>((first_byte.value() >> 4) & 0x03u);
    if (type != 0x00u) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto destination_connection_id_length = read_u8(reader);
    if (!destination_connection_id_length.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(
            destination_connection_id_length.error().code,
            destination_connection_id_length.error().offset);
    }
    if (destination_connection_id_length.value() > 20) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::invalid_varint,
                                                      reader.offset());
    }
    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length.value());
    if (!destination_connection_id.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(destination_connection_id.error().code,
                                                      destination_connection_id.error().offset);
    }

    const auto source_connection_id_length = read_u8(reader);
    if (!source_connection_id_length.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(source_connection_id_length.error().code,
                                                      source_connection_id_length.error().offset);
    }
    if (source_connection_id_length.value() > 20) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::invalid_varint,
                                                      reader.offset());
    }
    const auto source_connection_id = reader.read_exact(source_connection_id_length.value());
    if (!source_connection_id.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(source_connection_id.error().code,
                                                      source_connection_id.error().offset);
    }

    const auto token_length = read_varint(reader);
    if (!token_length.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(token_length.error().code,
                                                      token_length.error().offset);
    }
    if (token_length.value() > static_cast<std::uint64_t>(reader.remaining())) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::packet_length_mismatch,
                                                      reader.offset());
    }
    const auto token = reader.read_exact(static_cast<std::size_t>(token_length.value()));
    if (!token.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(token.error().code, token.error().offset);
    }

    const auto length_offset = reader.offset();
    const auto payload_length = decode_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<LongHeaderLayout>::failure(payload_length.error().code,
                                                      payload_length.error().offset);
    }

    const auto packet_number_offset = reader.offset();
    if (payload_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
        return CodecResult<LongHeaderLayout>::failure(CodecErrorCode::packet_length_mismatch,
                                                      reader.offset());
    }

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
    const auto encoded_length = encode_varint(new_length_value);
    if (!encoded_length.has_value()) {
        return CodecResult<PatchedLengthField>::failure(encoded_length.error().code,
                                                        encoded_length.error().offset);
    }

    packet_bytes.erase(packet_bytes.begin() + static_cast<std::ptrdiff_t>(layout.length_offset),
                       packet_bytes.begin() +
                           static_cast<std::ptrdiff_t>(layout.length_offset + layout.length_size));
    packet_bytes.insert(packet_bytes.begin() + static_cast<std::ptrdiff_t>(layout.length_offset),
                        encoded_length.value().begin(), encoded_length.value().end());

    return CodecResult<PatchedLengthField>::success(PatchedLengthField{
        .packet_number_offset = layout.length_offset + encoded_length.value().size(),
    });
}

CodecResult<std::uint32_t> read_packet_number(std::span<const std::byte> bytes,
                                              std::uint8_t packet_number_length) {
    if (packet_number_length < 1 || packet_number_length > 4) {
        return CodecResult<std::uint32_t>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (bytes.size() < packet_number_length) {
        return CodecResult<std::uint32_t>::failure(CodecErrorCode::truncated_input, 0);
    }

    std::uint32_t value = 0;
    for (std::size_t index = 0; index < packet_number_length; ++index) {
        value = (value << 8) | std::to_integer<std::uint8_t>(bytes[index]);
    }

    return CodecResult<std::uint32_t>::success(value);
}

EndpointRole opposite_endpoint_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
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

CodecResult<std::vector<std::byte>>
apply_initial_header_protection(std::vector<std::byte> packet_bytes,
                                std::size_t packet_number_offset, std::uint8_t packet_number_length,
                                const PacketProtectionKeys &keys) {
    if (packet_number_offset + packet_number_length > packet_bytes.size() ||
        packet_number_offset + kHeaderProtectionSampleOffset > packet_bytes.size()) {
        return CodecResult<std::vector<std::byte>>::failure(
            CodecErrorCode::header_protection_sample_too_short, 0);
    }

    const auto mask = make_header_protection_mask(
        kInitialCipherSuite, keys.hp_key,
        std::span<const std::byte>(packet_bytes)
            .subspan(packet_number_offset + kHeaderProtectionSampleOffset));
    if (!mask.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(mask.error().code, mask.error().offset);
    }

    packet_bytes[0] ^=
        static_cast<std::byte>(std::to_integer<std::uint8_t>(mask.value()[0]) & 0x0fu);
    for (std::size_t index = 0; index < packet_number_length; ++index) {
        packet_bytes[packet_number_offset + index] ^= mask.value()[index + 1];
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
}

CodecResult<RemovedLongHeaderProtection>
remove_initial_header_protection(std::span<const std::byte> bytes, const LongHeaderLayout &layout,
                                 const PacketProtectionKeys &keys) {
    if (layout.packet_end_offset > bytes.size() ||
        layout.packet_number_offset + kHeaderProtectionSampleOffset > layout.packet_end_offset) {
        return CodecResult<RemovedLongHeaderProtection>::failure(
            CodecErrorCode::header_protection_sample_too_short, 0);
    }

    std::vector<std::byte> packet_bytes(
        bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(layout.packet_end_offset));
    const auto mask = make_header_protection_mask(
        kInitialCipherSuite, keys.hp_key,
        std::span<const std::byte>(packet_bytes)
            .subspan(layout.packet_number_offset + kHeaderProtectionSampleOffset));
    if (!mask.has_value()) {
        return CodecResult<RemovedLongHeaderProtection>::failure(mask.error().code,
                                                                 mask.error().offset);
    }

    packet_bytes[0] ^=
        static_cast<std::byte>(std::to_integer<std::uint8_t>(mask.value()[0]) & 0x0fu);
    const auto packet_number_length =
        static_cast<std::uint8_t>((std::to_integer<std::uint8_t>(packet_bytes[0]) & 0x03u) + 1u);
    if (layout.length_value < packet_number_length ||
        layout.packet_number_offset + packet_number_length > packet_bytes.size()) {
        return CodecResult<RemovedLongHeaderProtection>::failure(
            CodecErrorCode::packet_length_mismatch, layout.packet_number_offset);
    }

    for (std::size_t index = 0; index < packet_number_length; ++index) {
        packet_bytes[layout.packet_number_offset + index] ^= mask.value()[index + 1];
    }

    const auto truncated_packet_number = read_packet_number(
        std::span<const std::byte>(packet_bytes).subspan(layout.packet_number_offset),
        packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<RemovedLongHeaderProtection>::failure(
            truncated_packet_number.error().code,
            layout.packet_number_offset + truncated_packet_number.error().offset);
    }

    return CodecResult<RemovedLongHeaderProtection>::success(RemovedLongHeaderProtection{
        .packet_bytes = std::move(packet_bytes),
        .packet_number_length = packet_number_length,
        .truncated_packet_number = truncated_packet_number.value(),
    });
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
    const auto layout = locate_initial_long_header(sealed_packet);
    if (!layout.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(layout.error().code,
                                                            layout.error().offset);
    }

    const auto plaintext_payload_offset =
        layout.value().packet_number_offset + packet.packet_number_length;
    if (plaintext_payload_offset > sealed_packet.size()) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::packet_length_mismatch,
                                                            layout.value().packet_number_offset);
    }

    const auto patch = patch_long_header_length_field(
        sealed_packet, layout.value(),
        packet.packet_number_length + (sealed_packet.size() - plaintext_payload_offset) + 16);
    if (!patch.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(patch.error().code,
                                                            patch.error().offset);
    }

    const auto protected_payload_offset =
        patch.value().packet_number_offset + packet.packet_number_length;
    const auto nonce = make_packet_protection_nonce(keys.value().iv, packet.packet_number);
    if (!nonce.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(nonce.error().code,
                                                            nonce.error().offset);
    }

    const auto ciphertext =
        seal_payload(kInitialCipherSuite, keys.value().key, nonce.value(),
                     std::span<const std::byte>(sealed_packet).first(protected_payload_offset),
                     std::span<const std::byte>(sealed_packet).subspan(protected_payload_offset));
    if (!ciphertext.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(ciphertext.error().code,
                                                            ciphertext.error().offset);
    }

    sealed_packet.resize(protected_payload_offset);
    sealed_packet.insert(sealed_packet.end(), ciphertext.value().begin(), ciphertext.value().end());

    return apply_initial_header_protection(std::move(sealed_packet),
                                           patch.value().packet_number_offset,
                                           packet.packet_number_length, keys.value());
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_initial_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context) {
    const auto layout = locate_initial_long_header(bytes);
    if (!layout.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                 layout.error().offset);
    }

    const auto keys = derive_receive_initial_keys(context);
    if (!keys.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);
    }

    const auto unprotected = remove_initial_header_protection(bytes, layout.value(), keys.value());
    if (!unprotected.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);
    }

    const auto packet_number = recover_packet_number(
        context.largest_authenticated_initial_packet_number,
        unprotected.value().truncated_packet_number, unprotected.value().packet_number_length);
    if (!packet_number.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);
    }

    const auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    const auto nonce = make_packet_protection_nonce(keys.value().iv, packet_number.value());
    if (!nonce.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(nonce.error().code,
                                                                 nonce.error().offset);
    }

    const auto plaintext =
        open_payload(kInitialCipherSuite, keys.value().key, nonce.value(),
                     std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
                     std::span<const std::byte>(unprotected.value().packet_bytes)
                         .subspan(header_end, layout.value().packet_end_offset - header_end));
    if (!plaintext.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);
    }

    auto plaintext_image = std::vector<std::byte>(unprotected.value().packet_bytes.begin(),
                                                  unprotected.value().packet_bytes.begin() +
                                                      static_cast<std::ptrdiff_t>(header_end));
    const auto patched_length = patch_long_header_length_field(
        plaintext_image, layout.value(),
        unprotected.value().packet_number_length + plaintext.value().size());
    if (!patched_length.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(patched_length.error().code,
                                                                 patched_length.error().offset);
    }
    plaintext_image.insert(plaintext_image.end(), plaintext.value().begin(),
                           plaintext.value().end());

    const auto decoded = deserialize_packet(plaintext_image, {});
    if (!decoded.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);
    }

    const auto *initial = std::get_if<InitialPacket>(&decoded.value().packet);
    if (initial == nullptr) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::unsupported_packet_type, 0);
    }

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedInitialPacket{
                .version = initial->version,
                .destination_connection_id = initial->destination_connection_id,
                .source_connection_id = initial->source_connection_id,
                .token = initial->token,
                .packet_number_length = initial->packet_number_length,
                .packet_number = packet_number.value(),
                .frames = initial->frames,
            },
        .bytes_consumed = layout.value().packet_end_offset,
    });
}

} // namespace

CodecResult<std::vector<std::byte>>
serialize_protected_datagram(std::span<const ProtectedPacket> packets,
                             const SerializeProtectionContext &context) {
    std::vector<std::byte> datagram;
    for (std::size_t index = 0; index < packets.size(); ++index) {
        if (const auto *initial = std::get_if<ProtectedInitialPacket>(&packets[index])) {
            const auto encoded = serialize_protected_initial_packet(*initial, context);
            if (!encoded.has_value()) {
                return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                                    encoded.error().offset);
            }

            datagram.insert(datagram.end(), encoded.value().begin(), encoded.value().end());
            continue;
        }

        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::unsupported_packet_type,
                                                            index);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(datagram));
}

CodecResult<std::vector<ProtectedPacket>>
deserialize_protected_datagram(std::span<const std::byte> bytes,
                               const DeserializeProtectionContext &context) {
    if (bytes.empty()) {
        return CodecResult<std::vector<ProtectedPacket>>::failure(CodecErrorCode::truncated_input,
                                                                  0);
    }

    std::vector<ProtectedPacket> packets;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        auto decoded = deserialize_protected_initial_packet(bytes.subspan(offset), context);
        if (!decoded.has_value()) {
            return CodecResult<std::vector<ProtectedPacket>>::failure(
                decoded.error().code, offset + decoded.error().offset);
        }

        packets.push_back(std::move(decoded.value().packet));
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<ProtectedPacket>>::success(std::move(packets));
}

} // namespace coquic::quic
