#include "src/quic/protected_codec.h"

#include <cstddef>
#include <cstdint>
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
constexpr std::size_t kHeaderProtectionSampleOffset = 4;

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
    const auto mask = make_header_protection_mask(
        cipher_suite, keys.hp_key,
        std::span<const std::byte>(packet_bytes)
            .subspan(packet_number.packet_number_offset + kHeaderProtectionSampleOffset));
    if (!mask.has_value())
        return CodecResult<std::vector<std::byte>>::failure(mask.error().code, mask.error().offset);

    packet_bytes[0] ^=
        static_cast<std::byte>(std::to_integer<std::uint8_t>(mask.value()[0]) & 0x1fu);
    for (std::size_t index = 0; index < packet_number.packet_number_length; ++index) {
        packet_bytes[packet_number.packet_number_offset + index] ^= mask.value()[index + 1];
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
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
    if (!plaintext.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);

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
    if (!plaintext.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                 plaintext.error().offset);

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

CodecResult<std::vector<std::byte>>
serialize_protected_one_rtt_packet(const ProtectedOneRttPacket &packet,
                                   const SerializeProtectionContext &context) {
    if (!context.one_rtt_secret.has_value())
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::missing_crypto_context,
                                                            0);
    if (packet.key_phase != context.one_rtt_key_phase)
        return CodecResult<std::vector<std::byte>>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);

    const auto keys = expand_traffic_secret(context.one_rtt_secret.value());
    if (!keys.has_value())
        return CodecResult<std::vector<std::byte>>::failure(keys.error().code, keys.error().offset);

    const auto plaintext_packet = to_plaintext_one_rtt(packet);
    if (!plaintext_packet.has_value())
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);

    const auto packet_number_offset = 1 + packet.destination_connection_id.size();
    const auto payload_offset = packet_number_offset + packet.packet_number_length;
    const auto plaintext_image = serialize_packet(Packet{plaintext_packet.value()});
    if (!plaintext_image.has_value())
        return CodecResult<std::vector<std::byte>>::failure(plaintext_image.error().code,
                                                            plaintext_image.error().offset);

    auto padded_plaintext_image = plaintext_image.value();
    pad_short_header_plaintext_for_header_protection(padded_plaintext_image, packet_number_offset);

    const auto cipher_suite = context.one_rtt_secret->cipher_suite;
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.value().iv, packet.packet_number);

    const auto ciphertext =
        seal_payload(cipher_suite, keys.value().key, nonce,
                     std::span<const std::byte>(padded_plaintext_image).first(payload_offset),
                     std::span<const std::byte>(padded_plaintext_image).subspan(payload_offset));
    if (!ciphertext.has_value())
        return CodecResult<std::vector<std::byte>>::failure(ciphertext.error().code,
                                                            ciphertext.error().offset);

    auto sealed_packet = std::vector<std::byte>(padded_plaintext_image.begin(),
                                                padded_plaintext_image.begin() +
                                                    static_cast<std::ptrdiff_t>(payload_offset));
    sealed_packet.insert(sealed_packet.end(), ciphertext.value().begin(), ciphertext.value().end());

    return apply_short_header_protection(std::move(sealed_packet),
                                         PacketNumberSpan{
                                             .packet_number_offset = packet_number_offset,
                                             .packet_number_length = packet.packet_number_length,
                                         },
                                         cipher_suite, keys.value());
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
                    return serialize_protected_one_rtt_packet(packet, context);
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
