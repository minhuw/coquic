#include "src/quic/protected_codec.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/buffer.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/packet_number.h"
#include "src/quic/protected_codec_test_hooks.h"
#include "src/quic/streams.h"
#include "src/quic/version.h"

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::quic {

namespace {

constexpr CipherSuite kInitialCipherSuite = CipherSuite::tls_aes_128_gcm_sha256;
constexpr std::size_t kPacketProtectionTagLength = 16;
constexpr std::size_t kHeaderProtectionSampleOffset = 4;
constexpr std::size_t kMaxInlineSealPlaintextChunks = 32;
constexpr std::uint64_t kMaxVarInt = 4611686018427387903ull;

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

std::uint8_t encoded_long_header_type(LongHeaderPacketType packet_type, std::uint32_t version) {
    const auto encoded_type = static_cast<std::uint8_t>(packet_type);
    return version == kQuicVersion2 ? static_cast<std::uint8_t>(encoded_type + 1u) : encoded_type;
}

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
    ReceivedProtectedPacket packet;
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
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return written.error();
    }

    writer.write_bytes(std::span<const std::byte>(encoded.data(), written.value()));
    return std::nullopt;
}

void append_varint_unchecked(BufferWriter &writer, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value).value();
    writer.write_bytes(std::span<const std::byte>(encoded.data(), written));
}

void append_bytes(std::vector<std::byte> &bytes, std::span<const std::byte> appended) {
    const auto offset = bytes.size();
    bytes.resize(offset + appended.size());
    if (!appended.empty()) {
        std::memcpy(bytes.data() + static_cast<std::ptrdiff_t>(offset), appended.data(),
                    appended.size());
    }
}

std::optional<CodecError> append_varint(std::vector<std::byte> &bytes, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return written.error();
    }

    append_bytes(bytes, std::span<const std::byte>(encoded.data(), written.value()));
    return std::nullopt;
}

void append_varint_unchecked(std::vector<std::byte> &bytes, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value).value();
    append_bytes(bytes, std::span<const std::byte>(encoded.data(), written));
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

void append_packet_number(std::vector<std::byte> &bytes, TruncatedPacketNumberEncoding encoding) {
    for (std::size_t index = 0; index < encoding.packet_number_length; ++index) {
        const auto shift = static_cast<unsigned>((encoding.packet_number_length - index - 1) * 8);
        bytes.push_back(
            static_cast<std::byte>((encoding.truncated_packet_number >> shift) & 0xffu));
    }
}

std::optional<CodecError> write_u32_be(SpanBufferWriter &writer, std::uint32_t value) {
    if (const auto error = writer.write_byte(static_cast<std::byte>((value >> 24) & 0xffu))) {
        return error;
    }
    if (const auto error = writer.write_byte(static_cast<std::byte>((value >> 16) & 0xffu))) {
        return error;
    }
    if (const auto error = writer.write_byte(static_cast<std::byte>((value >> 8) & 0xffu))) {
        return error;
    }
    return writer.write_byte(static_cast<std::byte>(value & 0xffu));
}

std::optional<CodecError> append_packet_number(SpanBufferWriter &writer,
                                               TruncatedPacketNumberEncoding encoding) {
    for (std::size_t index = 0; index < encoding.packet_number_length; ++index) {
        const auto shift = static_cast<unsigned>((encoding.packet_number_length - index - 1) * 8);
        if (const auto error = writer.write_byte(
                static_cast<std::byte>((encoding.truncated_packet_number >> shift) & 0xffu))) {
            return error;
        }
    }
    return std::nullopt;
}

std::size_t minimum_payload_bytes_for_header_sample(std::uint8_t packet_number_length) {
    return packet_number_length >= kHeaderProtectionSampleOffset
               ? 0
               : kHeaderProtectionSampleOffset - packet_number_length;
}

CodecResult<std::size_t> serialized_frame_payload_size(std::span<const Frame> frames) {
    if (frames.empty()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::empty_packet_payload, 0);
    }

    std::size_t total = 0;
    for (const auto &frame : frames) {
        const auto encoded = serialized_frame_size(frame);
        if (!encoded.has_value()) {
            return CodecResult<std::size_t>::failure(encoded.error().code, encoded.error().offset);
        }
        total += encoded.value();
    }

    return CodecResult<std::size_t>::success(total);
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

bool frame_allowed_in_long_header_packet_type(const Frame &frame,
                                              LongHeaderPacketType packet_type) {
    const auto is_ack_like =
        std::holds_alternative<AckFrame>(frame) || std::holds_alternative<OutboundAckFrame>(frame);
    if (packet_type == LongHeaderPacketType::zero_rtt) {
        return !is_ack_like && !std::holds_alternative<CryptoFrame>(frame) &&
               !std::holds_alternative<HandshakeDoneFrame>(frame) &&
               !std::holds_alternative<NewTokenFrame>(frame) &&
               !std::holds_alternative<PathResponseFrame>(frame) &&
               !std::holds_alternative<RetireConnectionIdFrame>(frame);
    }

    return std::holds_alternative<PaddingFrame>(frame) ||
           std::holds_alternative<PingFrame>(frame) || is_ack_like ||
           std::holds_alternative<CryptoFrame>(frame) ||
           std::holds_alternative<TransportConnectionCloseFrame>(frame);
}

CodecResult<bool> validate_long_header_frames(std::span<const Frame> frames,
                                              LongHeaderPacketType packet_type) {
    for (std::size_t index = 0; index < frames.size(); ++index) {
        if (!frame_allowed_in_long_header_packet_type(frames[index], packet_type)) {
            return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type,
                                              index);
        }

        const auto *stream = std::get_if<StreamFrame>(&frames[index]);
        if (stream != nullptr && !stream->has_length && index + 1 != frames.size()) {
            return CodecResult<bool>::failure(CodecErrorCode::packet_length_mismatch, index);
        }
    }

    return CodecResult<bool>::success(true);
}

bool frame_allowed_in_protected_payload_packet_type(const ReceivedFrame &frame,
                                                    ProtectedPayloadPacketType packet_type) {
    if (packet_type == ProtectedPayloadPacketType::one_rtt) {
        return true;
    }

    const auto frame_index = frame.index();
    if (packet_type == ProtectedPayloadPacketType::zero_rtt) {
        const auto forbidden_in_zero_rtt = (frame_index == 2) | (frame_index == 5) |
                                           (frame_index == 20) | (frame_index == 6) |
                                           (frame_index == 17) | (frame_index == 15);
        return !forbidden_in_zero_rtt;
    }

    return (frame_index == 0) | (frame_index == 1) | (frame_index == 2) | (frame_index == 5) |
           (frame_index == 18);
}

CodecResult<std::vector<ReceivedFrame>> deserialize_received_frame_sequence(
    const SharedBytes &payload, ProtectedPayloadPacketType packet_type, std::size_t base_offset) {
    if (payload.empty()) {
        return CodecResult<std::vector<ReceivedFrame>>::failure(
            CodecErrorCode::empty_packet_payload, base_offset);
    }

    std::vector<ReceivedFrame> frames;
    std::size_t offset = 0;
    while (offset < payload.size()) {
        auto decoded = deserialize_received_frame(payload.subspan(offset));
        if (!decoded.has_value()) {
            return CodecResult<std::vector<ReceivedFrame>>::failure(
                decoded.error().code, base_offset + offset + decoded.error().offset);
        }
        if (!frame_allowed_in_protected_payload_packet_type(decoded.value().frame, packet_type)) {
            return CodecResult<std::vector<ReceivedFrame>>::failure(
                CodecErrorCode::frame_not_allowed_in_packet_type, base_offset + offset);
        }

        frames.push_back(std::move(decoded.value().frame));
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<ReceivedFrame>>::success(std::move(frames));
}

std::size_t encoded_stream_frame_payload_size(std::uint64_t stream_id, std::uint64_t offset,
                                              std::size_t payload_size) {
    return 1 + encoded_varint_size(stream_id) + encoded_varint_size(offset) +
           encoded_varint_size(payload_size) + payload_size;
}

CodecResult<std::size_t> serialize_stream_frame_header_into(std::vector<std::byte> &bytes,
                                                            const StreamFrameHeaderFields &header) {
    if (header.offset > kMaxVarInt - header.payload_size) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto begin = bytes.size();
    std::byte type = std::byte{0x08};
    type |= std::byte{0x04};
    type |= std::byte{0x02};
    if (header.fin) {
        type |= std::byte{0x01};
    }

    bytes.push_back(type);
    if (const auto error = append_varint(bytes, header.stream_id)) {
        bytes.resize(begin);
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    append_varint_unchecked(bytes, header.offset);
    append_varint_unchecked(bytes, header.payload_size);
    return CodecResult<std::size_t>::success(bytes.size() - begin);
}

CodecResult<std::size_t> serialize_stream_frame_header_into(SpanBufferWriter &writer,
                                                            const StreamFrameHeaderFields &header) {
    if (header.offset > kMaxVarInt - header.payload_size) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto begin = writer.offset();
    std::byte type = std::byte{0x08};
    type |= std::byte{0x04};
    type |= std::byte{0x02};
    if (header.fin) {
        type |= std::byte{0x01};
    }

    if (const auto error = writer.write_byte(type)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_varint(header.stream_id)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    writer.write_varint_unchecked(header.offset);
    writer.write_varint_unchecked(header.payload_size);
    return CodecResult<std::size_t>::success(writer.offset() - begin);
}

CodecResult<std::size_t> append_stream_frame_payload_into(std::vector<std::byte> &bytes,
                                                          StreamFrameHeaderFields header,
                                                          std::span<const std::byte> payload) {
    const auto begin = bytes.size();
    header.payload_size = payload.size();
    const auto serialized_header = serialize_stream_frame_header_into(bytes, header);
    if (!serialized_header.has_value()) {
        return serialized_header;
    }

    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return CodecResult<std::size_t>::success(bytes.size() - begin);
}

CodecResult<std::size_t> serialize_stream_frame_into(std::span<std::byte> output,
                                                     const StreamFrameHeaderFields &header,
                                                     std::span<const std::byte> payload) {
    SpanBufferWriter writer(output);
    auto adjusted_header = header;
    adjusted_header.payload_size = payload.size();
    const auto serialized_header = serialize_stream_frame_header_into(writer, adjusted_header);
    if (!serialized_header.has_value()) {
        return serialized_header;
    }
    if (const auto error = writer.write_bytes(payload)) {
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    return CodecResult<std::size_t>::success(writer.offset());
}

CodecResult<std::size_t>
append_stream_frame_view_into_datagram(std::vector<std::byte> &bytes,
                                       const StreamFrameView &stream_view) {
    if (stream_view.end < stream_view.begin) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload_size = stream_view.end - stream_view.begin;
    if (payload_size != 0 &&
        (!stream_view.storage || stream_view.end > stream_view.storage->size())) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload =
        payload_size == 0
            ? std::span<const std::byte>{}
            : std::span<const std::byte>(stream_view.storage->data() +
                                             static_cast<std::ptrdiff_t>(stream_view.begin),
                                         payload_size);
    return append_stream_frame_payload_into(bytes,
                                            StreamFrameHeaderFields{
                                                .fin = stream_view.fin,
                                                .stream_id = stream_view.stream_id,
                                                .offset = stream_view.offset,
                                            },
                                            payload);
}

CodecResult<std::size_t>
append_stream_frame_send_fragment_to_datagram(std::vector<std::byte> &bytes,
                                              const StreamFrameSendFragment &fragment) {
    if (fragment.offset > kMaxVarInt - fragment.bytes.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto begin = bytes.size();
    append_bytes(bytes, fragment.stream_frame_header_bytes());
    append_bytes(bytes, fragment.bytes.span());
    return CodecResult<std::size_t>::success(bytes.size() - begin);
}

CodecResult<std::size_t> serialize_stream_frame_view_into_span(std::span<std::byte> output,
                                                               const StreamFrameView &stream_view) {
    if (stream_view.end < stream_view.begin) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload_size = stream_view.end - stream_view.begin;
    if (payload_size != 0 &&
        (!stream_view.storage || stream_view.end > stream_view.storage->size())) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto payload =
        payload_size == 0
            ? std::span<const std::byte>{}
            : std::span<const std::byte>(stream_view.storage->data() +
                                             static_cast<std::ptrdiff_t>(stream_view.begin),
                                         payload_size);
    return serialize_stream_frame_into(output,
                                       StreamFrameHeaderFields{
                                           .fin = stream_view.fin,
                                           .stream_id = stream_view.stream_id,
                                           .offset = stream_view.offset,
                                       },
                                       payload);
}

CodecResult<std::size_t>
serialize_stream_frame_send_fragment_into_span(std::span<std::byte> output,
                                               const StreamFrameSendFragment &fragment) {
    if (fragment.offset > kMaxVarInt - fragment.bytes.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto header_bytes = fragment.stream_frame_header_bytes();
    if (output.size() < header_bytes.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0);
    }
    if (!header_bytes.empty()) {
        std::memcpy(output.data(), header_bytes.data(), header_bytes.size());
    }
    if (output.size() - header_bytes.size() < fragment.bytes.size()) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input,
                                                 header_bytes.size());
    }
    if (!fragment.bytes.empty()) {
        std::memcpy(output.data() + static_cast<std::ptrdiff_t>(header_bytes.size()),
                    fragment.bytes.data(), fragment.bytes.size());
    }

    return CodecResult<std::size_t>::success(header_bytes.size() + fragment.bytes.size());
}

bool long_header_has_token(LongHeaderPacketType packet_type) {
    return packet_type == LongHeaderPacketType::initial;
}

CodecResult<LongHeaderPacketType> read_long_header_type(std::span<const std::byte> bytes) {
    if (bytes.size() < 5) {
        return CodecResult<LongHeaderPacketType>::failure(CodecErrorCode::truncated_input,
                                                          bytes.size());
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x40u) == 0)
        return CodecResult<LongHeaderPacketType>::failure(CodecErrorCode::invalid_fixed_bit, 0);

    const auto version = read_u32_be(bytes.subspan(1, 4));
    const auto encoded_type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    if (encoded_type == encoded_long_header_type(LongHeaderPacketType::initial, version)) {
        return CodecResult<LongHeaderPacketType>::success(LongHeaderPacketType::initial);
    }
    if (encoded_type == encoded_long_header_type(LongHeaderPacketType::zero_rtt, version)) {
        return CodecResult<LongHeaderPacketType>::success(LongHeaderPacketType::zero_rtt);
    }
    if (encoded_type == encoded_long_header_type(LongHeaderPacketType::handshake, version)) {
        return CodecResult<LongHeaderPacketType>::success(LongHeaderPacketType::handshake);
    }

    return CodecResult<LongHeaderPacketType>::failure(CodecErrorCode::unsupported_packet_type, 0);
}

CodecResult<LongHeaderLayout> locate_long_header(std::span<const std::byte> bytes,
                                                 LongHeaderPacketType expected_type) {
    BufferReader reader(bytes);
    reader.read_byte().value();

    const auto version_bytes = reader.read_exact(4).value();
    if (!is_supported_quic_version(read_u32_be(version_bytes)))
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
    std::array<std::byte, 8> encoded_length_bytes{};
    const auto encoded_length = encode_varint_into(encoded_length_bytes, new_length_value);
    if (!encoded_length.has_value()) {
        return CodecResult<PatchedLengthField>::failure(encoded_length.error().code,
                                                        encoded_length.error().offset);
    }
    const auto encoded_length_span =
        std::span<const std::byte>(encoded_length_bytes.data(), encoded_length.value());

    packet_bytes.erase(packet_bytes.begin() + static_cast<std::ptrdiff_t>(layout.length_offset),
                       packet_bytes.begin() +
                           static_cast<std::ptrdiff_t>(layout.length_offset + layout.length_size));
    packet_bytes.insert(packet_bytes.begin() + static_cast<std::ptrdiff_t>(layout.length_offset),
                        encoded_length_span.begin(), encoded_length_span.end());

    return CodecResult<PatchedLengthField>::success(PatchedLengthField{
        .packet_number_offset = layout.length_offset + encoded_length.value(),
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
derive_send_initial_keys(const SerializeProtectionContext &context, std::uint32_t version) {
    if (context.client_initial_destination_connection_id.empty()) {
        return CodecResult<PacketProtectionKeys>::failure(CodecErrorCode::missing_crypto_context,
                                                          0);
    }

    return derive_initial_packet_keys(context.local_role, true,
                                      context.client_initial_destination_connection_id, version);
}

CodecResult<PacketProtectionKeys>
derive_receive_initial_keys(const DeserializeProtectionContext &context, std::uint32_t version) {
    if (context.client_initial_destination_connection_id.empty()) {
        return CodecResult<PacketProtectionKeys>::failure(CodecErrorCode::missing_crypto_context,
                                                          0);
    }

    return derive_initial_packet_keys(opposite_endpoint_role(context.peer_role), false,
                                      context.client_initial_destination_connection_id, version);
}

CodecResult<InitialPacket> to_plaintext_initial(const ProtectedInitialPacket &packet) {
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
    if (!is_supported_quic_version(packet.version)) {
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

CodecResult<ZeroRttPacket> to_plaintext_zero_rtt(const ProtectedZeroRttPacket &packet) {
    if (!is_supported_quic_version(packet.version)) {
        return CodecResult<ZeroRttPacket>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<ZeroRttPacket>::failure(truncated_packet_number.error().code,
                                                   truncated_packet_number.error().offset);
    }

    return CodecResult<ZeroRttPacket>::success(ZeroRttPacket{
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

CodecResult<bool> apply_long_header_protection_in_place(std::span<std::byte> packet_bytes,
                                                        PacketNumberSpan packet_number,
                                                        CipherSuite cipher_suite,
                                                        const PacketProtectionKeys &keys) {
    std::array<std::byte, 5> mask{};
    const auto mask_written = make_header_protection_mask_into(
        cipher_suite,
        HeaderProtectionMaskInput{
            .hp_key = keys.hp_key,
            .sample =
                std::span<const std::byte>(packet_bytes)
                    .subspan(packet_number.packet_number_offset + kHeaderProtectionSampleOffset),
        },
        mask);
    if (!mask_written.has_value()) {
        return CodecResult<bool>::failure(mask_written.error().code, mask_written.error().offset);
    }

    packet_bytes[0] ^= static_cast<std::byte>(std::to_integer<std::uint8_t>(mask[0]) & 0x0fu);
    for (std::size_t index = 0; index < packet_number.packet_number_length; ++index) {
        packet_bytes[packet_number.packet_number_offset + index] ^= mask[index + 1];
    }

    return CodecResult<bool>::success(true);
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
        cipher_suite,
        HeaderProtectionMaskInput{
            .hp_key = keys.hp_key,
            .sample = std::span<const std::byte>(packet_bytes)
                          .subspan(layout.packet_number_offset + kHeaderProtectionSampleOffset),
        });
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

CodecResult<bool> apply_short_header_protection_in_place(std::span<std::byte> packet_bytes,
                                                         PacketNumberSpan packet_number,
                                                         CipherSuite cipher_suite,
                                                         const PacketProtectionKeys &keys) {
    std::array<std::byte, 5> mask{};
    const auto mask_written = make_header_protection_mask_into(
        cipher_suite,
        HeaderProtectionMaskInput{
            .hp_key = keys.hp_key,
            .sample =
                std::span<const std::byte>(packet_bytes)
                    .subspan(packet_number.packet_number_offset + kHeaderProtectionSampleOffset),
        },
        mask);
    if (!mask_written.has_value()) {
        return CodecResult<bool>::failure(mask_written.error().code, mask_written.error().offset);
    }

    packet_bytes[0] ^= static_cast<std::byte>(std::to_integer<std::uint8_t>(mask[0]) & 0x1fu);
    for (std::size_t index = 0; index < packet_number.packet_number_length; ++index) {
        packet_bytes[packet_number.packet_number_offset + index] ^= mask[index + 1];
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
        cipher_suite,
        HeaderProtectionMaskInput{
            .hp_key = keys.hp_key,
            .sample = std::span<const std::byte>(packet_bytes)
                          .subspan(packet_number_offset + kHeaderProtectionSampleOffset),
        });
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

std::span<const std::byte> make_packet_protection_nonce_or_assert(std::span<const std::byte> iv,
                                                                  std::uint64_t packet_number,
                                                                  std::span<std::byte> storage) {
    const auto written = make_packet_protection_nonce_into(
                             PacketProtectionNonceInput{
                                 .iv = iv,
                                 .packet_number = packet_number,
                             },
                             storage)
                             .value();
    return std::span<const std::byte>(storage).first(written);
}

std::vector<std::byte> make_packet_protection_nonce_or_assert(std::span<const std::byte> iv,
                                                              std::uint64_t packet_number) {
    return make_packet_protection_nonce(PacketProtectionNonceInput{
                                            .iv = iv,
                                            .packet_number = packet_number,
                                        })
        .value();
}

CodecResult<PacketDecodeResult>
deserialize_plaintext_packet_image(std::span<const std::byte> plaintext_image,
                                   const DeserializeOptions &options) {
    if (consume_protected_codec_fault(test::ProtectedCodecFaultPoint::deserialize_plaintext_packet))
        return CodecResult<PacketDecodeResult>::failure(CodecErrorCode::invalid_varint, 0);

    return deserialize_packet(plaintext_image, options);
}

struct ReceivedLongHeaderPacketFields {
    std::uint32_t version = 1;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> token;
    std::uint8_t packet_number_length = 1;
    std::vector<ReceivedFrame> frames;
};

struct ReceivedShortHeaderPacketFields {
    bool spin_bit = false;
    bool key_phase = false;
    ConnectionId destination_connection_id;
    std::uint8_t packet_number_length = 1;
    std::vector<ReceivedFrame> frames;
};

CodecResult<std::vector<std::byte>>
build_long_header_plaintext_header(const RemovedLongHeaderProtection &unprotected,
                                   const LongHeaderLayout &layout,
                                   std::size_t plaintext_payload_size) {
    const auto header_end = layout.packet_number_offset + unprotected.packet_number_length;
    std::vector<std::byte> plaintext_header(unprotected.packet_bytes.begin(),
                                            unprotected.packet_bytes.begin() +
                                                static_cast<std::ptrdiff_t>(header_end));
    const auto patched = patch_long_header_length_field(
        plaintext_header, layout, unprotected.packet_number_length + plaintext_payload_size);
    if (!patched.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(patched.error().code,
                                                            patched.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(plaintext_header));
}

CodecResult<ReceivedLongHeaderPacketFields>
decode_received_long_header_packet_fields(std::span<const std::byte> plaintext_header,
                                          const SharedBytes &plaintext_payload,
                                          ProtectedPayloadPacketType packet_type, bool has_token) {
    BufferReader reader(plaintext_header);
    const auto first_byte = read_u8(reader);
    if (!first_byte.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(first_byte.error().code,
                                                                    first_byte.error().offset);
    }
    if ((first_byte.value() & 0x40u) == 0) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            CodecErrorCode::invalid_fixed_bit, 0);
    }
    if ((first_byte.value() & 0x0cu) != 0) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            CodecErrorCode::invalid_reserved_bits, 0);
    }

    const auto version_bytes = reader.read_exact(4);
    if (!version_bytes.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(version_bytes.error().code,
                                                                    version_bytes.error().offset);
    }
    const auto version = read_u32_be(version_bytes.value());

    const auto destination_connection_id = read_connection_id(reader, version == kQuicVersion1);
    if (!destination_connection_id.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            destination_connection_id.error().code, destination_connection_id.error().offset);
    }

    const auto source_connection_id = read_connection_id(reader, version == kQuicVersion1);
    if (!source_connection_id.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            source_connection_id.error().code, source_connection_id.error().offset);
    }

    std::vector<std::byte> token;
    if (has_token) {
        const auto token_length = read_varint(reader);
        if (!token_length.has_value()) {
            return CodecResult<ReceivedLongHeaderPacketFields>::failure(
                token_length.error().code, token_length.error().offset);
        }
        if (token_length.value() > static_cast<std::uint64_t>(reader.remaining())) {
            return CodecResult<ReceivedLongHeaderPacketFields>::failure(
                CodecErrorCode::packet_length_mismatch, reader.offset());
        }

        const auto token_bytes =
            reader.read_exact(static_cast<std::size_t>(token_length.value())).value();
        token.assign(token_bytes.begin(), token_bytes.end());
    }

    const auto payload_length = read_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(payload_length.error().code,
                                                                    payload_length.error().offset);
    }

    const auto packet_number_length = static_cast<std::uint8_t>((first_byte.value() & 0x03u) + 1u);
    const auto expected_payload_length =
        static_cast<std::uint64_t>(packet_number_length + plaintext_payload.size());
    if (payload_length.value() != expected_payload_length) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            CodecErrorCode::packet_length_mismatch, reader.offset());
    }

    const auto packet_number_bytes = reader.read_exact(packet_number_length);
    if (!packet_number_bytes.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(
            packet_number_bytes.error().code, packet_number_bytes.error().offset);
    }

    auto frames =
        deserialize_received_frame_sequence(plaintext_payload, packet_type, reader.offset());
    if (!frames.has_value()) {
        return CodecResult<ReceivedLongHeaderPacketFields>::failure(frames.error().code,
                                                                    frames.error().offset);
    }

    return CodecResult<ReceivedLongHeaderPacketFields>::success(ReceivedLongHeaderPacketFields{
        .version = version,
        .destination_connection_id = destination_connection_id.value(),
        .source_connection_id = source_connection_id.value(),
        .token = std::move(token),
        .packet_number_length = packet_number_length,
        .frames = std::move(frames.value()),
    });
}

CodecResult<ReceivedShortHeaderPacketFields>
decode_received_short_header_packet_fields(std::span<const std::byte> plaintext_header,
                                           const SharedBytes &plaintext_payload) {
    BufferReader reader(plaintext_header);
    const auto first_byte = read_u8(reader);
    if (!first_byte.has_value()) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(first_byte.error().code,
                                                                     first_byte.error().offset);
    }
    if ((first_byte.value() & 0x40u) == 0) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(
            CodecErrorCode::invalid_fixed_bit, 0);
    }
    if ((first_byte.value() & 0x18u) != 0) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(
            CodecErrorCode::invalid_reserved_bits, 0);
    }

    const auto packet_number_length = static_cast<std::uint8_t>((first_byte.value() & 0x03u) + 1u);
    if (reader.remaining() < packet_number_length) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(
            CodecErrorCode::packet_length_mismatch, reader.offset());
    }

    const auto destination_connection_id_length = reader.remaining() - packet_number_length;
    const auto destination_connection_id = reader.read_exact(destination_connection_id_length);
    if (!destination_connection_id.has_value()) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(
            destination_connection_id.error().code, destination_connection_id.error().offset);
    }

    const auto packet_number_bytes = reader.read_exact(packet_number_length);
    if (!packet_number_bytes.has_value()) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(
            packet_number_bytes.error().code, packet_number_bytes.error().offset);
    }

    auto frames = deserialize_received_frame_sequence(
        plaintext_payload, ProtectedPayloadPacketType::one_rtt, plaintext_header.size());
    if (!frames.has_value()) {
        return CodecResult<ReceivedShortHeaderPacketFields>::failure(frames.error().code,
                                                                     frames.error().offset);
    }

    return CodecResult<ReceivedShortHeaderPacketFields>::success(ReceivedShortHeaderPacketFields{
        .spin_bit = (first_byte.value() & 0x20u) != 0,
        .key_phase = (first_byte.value() & 0x04u) != 0,
        .destination_connection_id =
            ConnectionId{
                destination_connection_id.value().begin(),
                destination_connection_id.value().end(),
            },
        .packet_number_length = packet_number_length,
        .frames = std::move(frames.value()),
    });
}

template <typename PacketFactory>
CodecResult<ReceivedProtectedPacketDecodeResult> deserialize_received_long_header_packet(
    std::span<const std::byte> bytes, const DeserializeProtectionContext &context,
    LongHeaderPacketType long_header_type, ProtectedPayloadPacketType packet_type,
    CipherSuite cipher_suite, const PacketProtectionKeys &keys,
    std::optional<std::uint64_t> largest_authenticated_packet_number, bool has_token,
    PacketFactory make_packet) {
    const auto layout = locate_long_header(bytes, long_header_type);
    if (!layout.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                         layout.error().offset);
    }

    const auto unprotected =
        remove_long_header_protection(bytes, layout.value(), cipher_suite, keys);
    if (!unprotected.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            unprotected.error().code, unprotected.error().offset);
    }

    const auto packet_number = recover_packet_number(largest_authenticated_packet_number,
                                                     unprotected.value().truncated_packet_number,
                                                     unprotected.value().packet_number_length);
    if (!packet_number.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            packet_number.error().code, packet_number.error().offset);
    }

    const auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    const auto nonce = make_packet_protection_nonce_or_assert(keys.iv, packet_number.value());
    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext = std::span<const std::byte>(unprotected.value().packet_bytes)
                          .subspan(header_end, layout.value().packet_end_offset - header_end),
    });
    if (!plaintext.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                         plaintext.error().offset);
    }

    auto plaintext_storage = std::make_shared<std::vector<std::byte>>(std::move(plaintext.value()));
    auto plaintext_header = build_long_header_plaintext_header(unprotected.value(), layout.value(),
                                                               plaintext_storage->size());
    if (!plaintext_header.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            plaintext_header.error().code, plaintext_header.error().offset);
    }

    auto decoded_fields = decode_received_long_header_packet_fields(
        plaintext_header.value(), SharedBytes(plaintext_storage, 0, plaintext_storage->size()),
        packet_type, has_token);
    if (!decoded_fields.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            decoded_fields.error().code, decoded_fields.error().offset);
    }

    return CodecResult<ReceivedProtectedPacketDecodeResult>::success(
        ReceivedProtectedPacketDecodeResult{
            .packet = make_packet(decoded_fields.value(), packet_number.value(), plaintext_storage),
            .bytes_consumed = layout.value().packet_end_offset,
        });
}

CodecResult<std::size_t> append_protected_long_header_packet_to_datagram(
    std::vector<std::byte> &datagram, LongHeaderPacketType packet_type, std::uint32_t version,
    const ConnectionId &destination_connection_id, const ConnectionId &source_connection_id,
    std::span<const std::byte> token, TruncatedPacketNumberEncoding packet_number,
    std::uint64_t full_packet_number, std::span<const Frame> frames, CipherSuite cipher_suite,
    const PacketProtectionKeys &keys) {
    const auto datagram_begin = datagram.size();
    const auto rollback = [&]() { datagram.resize(datagram_begin); };

    if (version == kVersionNegotiationVersion) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    if (version == kQuicVersion1 &&
        (destination_connection_id.size() > 20 || source_connection_id.size() > 20)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto valid_frames = validate_long_header_frames(frames, packet_type);
    if (!valid_frames.has_value()) {
        return CodecResult<std::size_t>::failure(valid_frames.error().code,
                                                 valid_frames.error().offset);
    }

    const auto frame_payload_size = serialized_frame_payload_size(frames);
    if (!frame_payload_size.has_value()) {
        return CodecResult<std::size_t>::failure(frame_payload_size.error().code,
                                                 frame_payload_size.error().offset);
    }

    if (frame_payload_size.value() > kMaxVarInt) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto plaintext_payload_size =
        std::max(frame_payload_size.value(),
                 minimum_payload_bytes_for_header_sample(packet_number.packet_number_length));
    const auto payload_length = static_cast<std::uint64_t>(
        packet_number.packet_number_length + plaintext_payload_size + kPacketProtectionTagLength);
    if (payload_length > kMaxVarInt) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto token_size = packet_type == LongHeaderPacketType::initial
                                ? encoded_varint_size(token.size()) + token.size()
                                : 0u;
    const auto length_size = encoded_varint_size(payload_length);
    const auto packet_number_offset = 1 + 4 + 1 + destination_connection_id.size() + 1 +
                                      source_connection_id.size() + token_size + length_size;
    const auto header_end = packet_number_offset + packet_number.packet_number_length;
    const auto packet_size = header_end + plaintext_payload_size + kPacketProtectionTagLength;

    datagram.resize(datagram_begin + packet_size);
    auto packet_bytes = std::span<std::byte>(datagram).subspan(datagram_begin, packet_size);

    SpanBufferWriter writer(packet_bytes.first(header_end));
    if (const auto error = writer.write_byte(static_cast<std::byte>(
            0x80u | 0x40u | ((encoded_long_header_type(packet_type, version) & 0x03u) << 4) |
            ((packet_number.packet_number_length - 1) & 0x03u)))) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = write_u32_be(writer, version)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error =
            writer.write_byte(static_cast<std::byte>(destination_connection_id.size()))) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_bytes(destination_connection_id)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_byte(static_cast<std::byte>(source_connection_id.size()))) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = writer.write_bytes(source_connection_id)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (packet_type == LongHeaderPacketType::initial) {
        if (const auto error = writer.write_varint(token.size())) {
            rollback();
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
        if (const auto error = writer.write_bytes(token)) {
            rollback();
            return CodecResult<std::size_t>::failure(error->code, error->offset);
        }
    }
    writer.write_varint_unchecked(payload_length);
    if (const auto error = append_packet_number(writer, packet_number)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    auto payload_bytes = packet_bytes.subspan(header_end, plaintext_payload_size);
    std::size_t payload_offset = 0;
    for (const auto &frame : frames) {
        const auto written = write_frame_wire_bytes(payload_bytes.subspan(payload_offset), frame);
        if (!written.has_value()) {
            rollback();
            return CodecResult<std::size_t>::failure(written.error().code, written.error().offset);
        }
        payload_offset += written.value();
    }

    std::array<std::byte, 32> nonce_storage{};
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys.iv, full_packet_number, nonce_storage);
    const auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(header_end),
        .plaintext =
            std::span<const std::byte>(packet_bytes).subspan(header_end, plaintext_payload_size),
        .ciphertext = packet_bytes.subspan(header_end),
    });
    if (!ciphertext.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                 ciphertext.error().offset);
    }

    const auto final_packet_size = header_end + ciphertext.value();
    datagram.resize(datagram_begin + final_packet_size);
    const auto protected_packet = apply_long_header_protection_in_place(
        std::span<std::byte>(datagram).subspan(datagram_begin, final_packet_size),
        PacketNumberSpan{
            .packet_number_offset = packet_number_offset,
            .packet_number_length = packet_number.packet_number_length,
        },
        cipher_suite, keys);
    if (!protected_packet.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                 protected_packet.error().offset);
    }

    return CodecResult<std::size_t>::success(final_packet_size);
}

CodecResult<std::vector<std::byte>>
serialize_protected_initial_packet(const ProtectedInitialPacket &packet,
                                   const SerializeProtectionContext &context) {
    const auto keys = derive_send_initial_keys(context, packet.version);
    if (!keys.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(keys.error().code, keys.error().offset);
    }

    const auto plaintext_packet = to_plaintext_initial(packet);
    if (!plaintext_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);
    }
    std::vector<std::byte> datagram;
    const auto appended = append_protected_long_header_packet_to_datagram(
        datagram, LongHeaderPacketType::initial, packet.version, packet.destination_connection_id,
        packet.source_connection_id, packet.token,
        TruncatedPacketNumberEncoding{
            .packet_number_length = packet.packet_number_length,
            .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
        },
        packet.packet_number, packet.frames, kInitialCipherSuite, keys.value());
    if (!appended.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(appended.error().code,
                                                            appended.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(datagram));
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_initial_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context) {
    const auto layout = locate_long_header(bytes, LongHeaderPacketType::initial);
    if (!layout.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                 layout.error().offset);

    const auto version = read_u32_be(bytes.subspan(1, 4));
    const auto keys = derive_receive_initial_keys(context, version);
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

    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = kInitialCipherSuite,
        .key = keys.value().key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext = std::span<const std::byte>(unprotected.value().packet_bytes)
                          .subspan(header_end, layout.value().packet_end_offset - header_end),
    });
    if (!plaintext.has_value()) {
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

CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_initial_packet(std::span<const std::byte> bytes,
                                              const DeserializeProtectionContext &context) {
    const auto version = read_u32_be(bytes.subspan(1, 4));
    const auto keys = derive_receive_initial_keys(context, version);
    if (!keys.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                         keys.error().offset);
    }

    return deserialize_received_long_header_packet(
        bytes, context, LongHeaderPacketType::initial, ProtectedPayloadPacketType::initial,
        kInitialCipherSuite, keys.value(), context.largest_authenticated_initial_packet_number,
        true,
        [](ReceivedLongHeaderPacketFields fields, std::uint64_t packet_number,
           const std::shared_ptr<std::vector<std::byte>> &plaintext_storage)
            -> ReceivedProtectedPacket {
            return ReceivedProtectedInitialPacket{
                .version = fields.version,
                .destination_connection_id = std::move(fields.destination_connection_id),
                .source_connection_id = std::move(fields.source_connection_id),
                .token = std::move(fields.token),
                .packet_number_length = fields.packet_number_length,
                .packet_number = packet_number,
                .plaintext_storage = plaintext_storage,
                .frames = std::move(fields.frames),
            };
        });
}

CodecResult<std::vector<std::byte>>
serialize_protected_handshake_packet(const ProtectedHandshakePacket &packet,
                                     const SerializeProtectionContext &context) {
    if (!context.handshake_secret.has_value())
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::missing_crypto_context,
                                                            0);

    const auto keys = expand_traffic_secret_cached(context.handshake_secret.value());
    if (!keys.has_value())
        return CodecResult<std::vector<std::byte>>::failure(keys.error().code, keys.error().offset);
    const auto &keys_ref = keys.value().get();

    const auto plaintext_packet = to_plaintext_handshake(packet);
    if (!plaintext_packet.has_value())
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);

    const auto cipher_suite = context.handshake_secret->cipher_suite;
    std::vector<std::byte> datagram;
    const auto appended = append_protected_long_header_packet_to_datagram(
        datagram, LongHeaderPacketType::handshake, packet.version, packet.destination_connection_id,
        packet.source_connection_id, {},
        TruncatedPacketNumberEncoding{
            .packet_number_length = packet.packet_number_length,
            .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
        },
        packet.packet_number, packet.frames, cipher_suite, keys_ref);
    if (!appended.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(appended.error().code,
                                                            appended.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(datagram));
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

    const auto keys = expand_traffic_secret_cached(context.handshake_secret.value());
    if (!keys.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);
    const auto &keys_ref = keys.value().get();

    const auto cipher_suite = context.handshake_secret->cipher_suite;
    const auto unprotected =
        remove_long_header_protection(bytes, layout.value(), cipher_suite, keys_ref);
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
    const auto nonce = make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value());

    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext = std::span<const std::byte>(unprotected.value().packet_bytes)
                          .subspan(header_end, layout.value().packet_end_offset - header_end),
    });
    if (!plaintext.has_value()) {
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

CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_handshake_packet(std::span<const std::byte> bytes,
                                                const DeserializeProtectionContext &context) {
    if (!context.handshake_secret.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    const auto keys = expand_traffic_secret_cached(context.handshake_secret.value());
    if (!keys.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                         keys.error().offset);
    }

    return deserialize_received_long_header_packet(
        bytes, context, LongHeaderPacketType::handshake, ProtectedPayloadPacketType::handshake,
        context.handshake_secret->cipher_suite, keys.value().get(),
        context.largest_authenticated_handshake_packet_number, false,
        [](ReceivedLongHeaderPacketFields fields, std::uint64_t packet_number,
           const std::shared_ptr<std::vector<std::byte>> &plaintext_storage)
            -> ReceivedProtectedPacket {
            return ReceivedProtectedHandshakePacket{
                .version = fields.version,
                .destination_connection_id = std::move(fields.destination_connection_id),
                .source_connection_id = std::move(fields.source_connection_id),
                .packet_number_length = fields.packet_number_length,
                .packet_number = packet_number,
                .plaintext_storage = plaintext_storage,
                .frames = std::move(fields.frames),
            };
        });
}

CodecResult<std::vector<std::byte>>
serialize_protected_zero_rtt_packet(const ProtectedZeroRttPacket &packet,
                                    const SerializeProtectionContext &context) {
    if (!context.zero_rtt_secret.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::missing_crypto_context,
                                                            0);
    }

    const auto keys = expand_traffic_secret_cached(context.zero_rtt_secret.value());
    if (!keys.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(keys.error().code, keys.error().offset);
    }
    const auto &keys_ref = keys.value().get();

    const auto plaintext_packet = to_plaintext_zero_rtt(packet);
    if (!plaintext_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(plaintext_packet.error().code,
                                                            plaintext_packet.error().offset);
    }

    const auto cipher_suite = context.zero_rtt_secret->cipher_suite;
    std::vector<std::byte> datagram;
    const auto appended = append_protected_long_header_packet_to_datagram(
        datagram, LongHeaderPacketType::zero_rtt, packet.version, packet.destination_connection_id,
        packet.source_connection_id, {},
        TruncatedPacketNumberEncoding{
            .packet_number_length = packet.packet_number_length,
            .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
        },
        packet.packet_number, packet.frames, cipher_suite, keys_ref);
    if (!appended.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(appended.error().code,
                                                            appended.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(datagram));
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_zero_rtt_packet(std::span<const std::byte> bytes,
                                      const DeserializeProtectionContext &context) {
    if (!context.zero_rtt_secret.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    const auto layout = locate_long_header(bytes, LongHeaderPacketType::zero_rtt);
    if (!layout.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(layout.error().code,
                                                                 layout.error().offset);
    }

    const auto keys = expand_traffic_secret_cached(context.zero_rtt_secret.value());
    if (!keys.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);
    }
    const auto &keys_ref = keys.value().get();

    const auto cipher_suite = context.zero_rtt_secret->cipher_suite;
    const auto unprotected =
        remove_long_header_protection(bytes, layout.value(), cipher_suite, keys_ref);
    if (!unprotected.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(unprotected.error().code,
                                                                 unprotected.error().offset);
    }

    const auto packet_number = recover_packet_number(
        context.largest_authenticated_application_packet_number,
        unprotected.value().truncated_packet_number, unprotected.value().packet_number_length);
    if (!packet_number.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(packet_number.error().code,
                                                                 packet_number.error().offset);
    }

    const auto header_end =
        layout.value().packet_number_offset + unprotected.value().packet_number_length;
    const auto nonce = make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value());
    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext = std::span<const std::byte>(unprotected.value().packet_bytes)
                          .subspan(header_end, layout.value().packet_end_offset - header_end),
    });
    if (!plaintext.has_value()) {
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
    if (!decoded.has_value()) {
        return CodecResult<ProtectedPacketDecodeResult>::failure(decoded.error().code,
                                                                 decoded.error().offset);
    }

    const auto &zero_rtt = std::get<ZeroRttPacket>(decoded.value().packet);

    return CodecResult<ProtectedPacketDecodeResult>::success(ProtectedPacketDecodeResult{
        .packet =
            ProtectedZeroRttPacket{
                .version = zero_rtt.version,
                .destination_connection_id = zero_rtt.destination_connection_id,
                .source_connection_id = zero_rtt.source_connection_id,
                .packet_number_length = zero_rtt.packet_number_length,
                .packet_number = packet_number.value(),
                .frames = zero_rtt.frames,
            },
        .bytes_consumed = layout.value().packet_end_offset,
    });
}

CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_zero_rtt_packet(std::span<const std::byte> bytes,
                                               const DeserializeProtectionContext &context) {
    if (!context.zero_rtt_secret.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    const auto keys = expand_traffic_secret_cached(context.zero_rtt_secret.value());
    if (!keys.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                         keys.error().offset);
    }

    return deserialize_received_long_header_packet(
        bytes, context, LongHeaderPacketType::zero_rtt, ProtectedPayloadPacketType::zero_rtt,
        context.zero_rtt_secret->cipher_suite, keys.value().get(),
        context.largest_authenticated_application_packet_number, false,
        [](ReceivedLongHeaderPacketFields fields, std::uint64_t packet_number,
           const std::shared_ptr<std::vector<std::byte>> &plaintext_storage)
            -> ReceivedProtectedPacket {
            return ReceivedProtectedZeroRttPacket{
                .version = fields.version,
                .destination_connection_id = std::move(fields.destination_connection_id),
                .source_connection_id = std::move(fields.source_connection_id),
                .packet_number_length = fields.packet_number_length,
                .packet_number = packet_number,
                .plaintext_storage = plaintext_storage,
                .frames = std::move(fields.frames),
            };
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

template <typename OneRttPacketLike>
bool packet_has_stream_payloads(const OneRttPacketLike &packet) {
    if constexpr (requires { packet.stream_frame_views; }) {
        return !packet.stream_frame_views.empty();
    } else {
        return !packet.stream_fragments.empty();
    }
}

template <typename OneRttPacketLike>
CodecResult<std::size_t> packet_stream_payload_wire_size(const OneRttPacketLike &packet,
                                                         std::size_t frame_index_base = 0) {
    std::size_t total = 0;
    if constexpr (requires { packet.stream_frame_views; }) {
        for (std::size_t stream_index = 0; stream_index < packet.stream_frame_views.size();
             ++stream_index) {
            const auto &stream_view = packet.stream_frame_views[stream_index];
            if (stream_view.end < stream_view.begin) {
                return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint,
                                                         frame_index_base + stream_index);
            }
            total += encoded_stream_frame_payload_size(stream_view.stream_id, stream_view.offset,
                                                       stream_view.end - stream_view.begin);
        }
    } else {
        for (std::size_t stream_index = 0; stream_index < packet.stream_fragments.size();
             ++stream_index) {
            const auto &fragment = packet.stream_fragments[stream_index];
            if (fragment.offset > kMaxVarInt - fragment.bytes.size()) {
                return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint,
                                                         frame_index_base + stream_index);
            }
            total += fragment.stream_frame_wire_size();
        }
    }
    return CodecResult<std::size_t>::success(total);
}

template <typename OneRttPacketLike>
CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram_impl(DatagramBuffer &datagram,
                                                 const OneRttPacketLike &packet,
                                                 const SerializeProtectionContext &context) {
    if (!context.one_rtt_secret.has_value())
        return CodecResult<std::size_t>::failure(CodecErrorCode::missing_crypto_context, 0);
    if (packet.key_phase != context.one_rtt_key_phase)
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                 0);

    const auto keys = expand_traffic_secret_cached(context.one_rtt_secret.value());
    if (!keys.has_value())
        return CodecResult<std::size_t>::failure(keys.error().code, keys.error().offset);
    const auto &keys_ref = keys.value().get();

    const auto truncated_packet_number =
        truncate_packet_number(packet.packet_number, packet.packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<std::size_t>::failure(truncated_packet_number.error().code,
                                                 truncated_packet_number.error().offset);
    }

    const auto packet_number_offset = 1 + packet.destination_connection_id.size();
    const auto payload_offset = packet_number_offset + packet.packet_number_length;
    const auto cipher_suite = context.one_rtt_secret->cipher_suite;
    std::array<std::byte, 32> nonce_storage{};
    const auto nonce =
        make_packet_protection_nonce_or_assert(keys_ref.iv, packet.packet_number, nonce_storage);
    const auto packet_number_span = PacketNumberSpan{
        .packet_number_offset = packet_number_offset,
        .packet_number_length = packet.packet_number_length,
    };
    const auto datagram_begin = datagram.size();
    const auto rollback = [&]() { datagram.resize(datagram_begin); };

    const auto has_stream_payloads = packet_has_stream_payloads(packet);
    std::size_t frame_payload_size = 0;
    for (std::size_t frame_index = 0; frame_index < packet.frames.size(); ++frame_index) {
        if (const auto *stream = std::get_if<StreamFrame>(&packet.frames[frame_index]);
            stream != nullptr && !stream->has_length &&
            (frame_index + 1 != packet.frames.size() || has_stream_payloads)) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                     frame_index);
        }

        const auto encoded = serialized_frame_size(packet.frames[frame_index]);
        if (!encoded.has_value()) {
            return CodecResult<std::size_t>::failure(encoded.error().code, encoded.error().offset);
        }
        frame_payload_size += encoded.value();
    }

    const auto stream_payload_size = packet_stream_payload_wire_size(packet, packet.frames.size());
    if (!stream_payload_size.has_value()) {
        return CodecResult<std::size_t>::failure(stream_payload_size.error().code,
                                                 stream_payload_size.error().offset);
    }
    const auto payload_size = frame_payload_size + stream_payload_size.value();
    if (payload_size == 0) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::empty_packet_payload, 0);
    }

    const auto plaintext_payload_size = std::max(
        payload_size, minimum_payload_bytes_for_header_sample(packet.packet_number_length));
    const auto maximum_packet_size =
        payload_offset + plaintext_payload_size + kPacketProtectionTagLength;
    datagram.reserve(datagram_begin + maximum_packet_size);
    datagram.resize(datagram_begin + maximum_packet_size);
    auto packet_bytes = std::span<std::byte>(datagram).subspan(datagram_begin, maximum_packet_size);

    SpanBufferWriter header_writer(packet_bytes.first(payload_offset));
    if (const auto error = header_writer.write_byte(make_short_header_first_byte(
            packet.spin_bit, packet.key_phase, packet.packet_number_length))) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = header_writer.write_bytes(packet.destination_connection_id)) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }
    if (const auto error = append_packet_number(
            header_writer, TruncatedPacketNumberEncoding{
                               .packet_number_length = packet.packet_number_length,
                               .truncated_packet_number = truncated_packet_number.value(),
                           })) {
        rollback();
        return CodecResult<std::size_t>::failure(error->code, error->offset);
    }

    auto payload_bytes = packet_bytes.subspan(payload_offset, plaintext_payload_size);
    if constexpr (requires { packet.stream_fragments; }) {
        const auto required_inline_chunks =
            static_cast<std::size_t>(!packet.frames.empty()) + (packet.stream_fragments.size() * 2);
        const bool can_chunk_seal_stream_fragments =
            packet.stream_fragments.size() > 1 && payload_size == plaintext_payload_size &&
            required_inline_chunks <= kMaxInlineSealPlaintextChunks;
        if (can_chunk_seal_stream_fragments) {
            std::array<PlaintextChunk, kMaxInlineSealPlaintextChunks> plaintext_chunks{};
            std::size_t chunk_count = 0;
            std::size_t plaintext_offset = 0;
            std::size_t frame_index = 0;

            for (const auto &frame : packet.frames) {
                const auto written =
                    write_frame_wire_bytes(payload_bytes.subspan(plaintext_offset), frame);
                if (!written.has_value()) {
                    rollback();
                    return CodecResult<std::size_t>::failure(written.error().code,
                                                             written.error().offset);
                }
                plaintext_offset += written.value();
                ++frame_index;
            }
            if (plaintext_offset != 0) {
                plaintext_chunks[chunk_count++] = PlaintextChunk{
                    .bytes = std::span<const std::byte>(payload_bytes).first(plaintext_offset),
                };
            }

            for (const auto &fragment : packet.stream_fragments) {
                const auto header_bytes = fragment.stream_frame_header_bytes();
                plaintext_chunks[chunk_count++] = PlaintextChunk{
                    .bytes = std::span<const std::byte>(payload_bytes)
                                 .subspan(plaintext_offset, header_bytes.size()),
                };
                if (!header_bytes.empty()) {
                    std::memcpy(payload_bytes.data() +
                                    static_cast<std::ptrdiff_t>(plaintext_offset),
                                header_bytes.data(), header_bytes.size());
                }
                plaintext_offset += header_bytes.size();
                plaintext_chunks[chunk_count++] = PlaintextChunk{
                    .bytes = fragment.bytes.span(),
                };
                plaintext_offset += fragment.bytes.size();
                ++frame_index;
            }

            const auto ciphertext = seal_payload_chunks_into(SealPayloadChunksIntoInput{
                .cipher_suite = cipher_suite,
                .key = keys_ref.key,
                .nonce = nonce,
                .associated_data = std::span<const std::byte>(packet_bytes).first(payload_offset),
                .plaintext_chunks =
                    std::span<const PlaintextChunk>(plaintext_chunks.data(), chunk_count),
                .ciphertext = packet_bytes.subspan(payload_offset),
            });
            if (!ciphertext.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                         ciphertext.error().offset);
            }

            const auto final_packet_size = payload_offset + ciphertext.value();
            datagram.resize(datagram_begin + final_packet_size);
            const auto protected_packet = apply_short_header_protection_in_place(
                std::span<std::byte>(datagram).subspan(datagram_begin, final_packet_size),
                packet_number_span, cipher_suite, keys_ref);
            if (!protected_packet.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                         protected_packet.error().offset);
            }

            return CodecResult<std::size_t>::success(final_packet_size);
        }
    }

    std::size_t payload_written = 0;
    std::size_t frame_index = 0;
    for (const auto &frame : packet.frames) {
        const auto written = write_frame_wire_bytes(payload_bytes.subspan(payload_written), frame);
        if (!written.has_value()) {
            rollback();
            return CodecResult<std::size_t>::failure(written.error().code, written.error().offset);
        }
        payload_written += written.value();
        ++frame_index;
    }

    if constexpr (requires { packet.stream_frame_views; }) {
        for (const auto &stream_view : packet.stream_frame_views) {
            const auto written = serialize_stream_frame_view_into_span(
                payload_bytes.subspan(payload_written), stream_view);
            if (!written.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(written.error().code, frame_index);
            }
            payload_written += written.value();
            ++frame_index;
        }
    } else {
        for (const auto &fragment : packet.stream_fragments) {
            const auto written = serialize_stream_frame_send_fragment_into_span(
                payload_bytes.subspan(payload_written), fragment);
            if (!written.has_value()) {
                rollback();
                return CodecResult<std::size_t>::failure(written.error().code, frame_index);
            }
            payload_written += written.value();
            ++frame_index;
        }
    }

    if (payload_written < plaintext_payload_size) {
        // DatagramBuffer growth leaves bytes uninitialized, but short-header padding must
        // serialize as zero-valued PADDING frames before the payload is sealed.
        std::fill(payload_bytes.begin() + static_cast<std::ptrdiff_t>(payload_written),
                  payload_bytes.end(), std::byte{0x00});
    }

    const auto plaintext_payload =
        std::span<const std::byte>(packet_bytes).subspan(payload_offset, plaintext_payload_size);

    const auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(payload_offset),
        .plaintext = plaintext_payload,
        .ciphertext = packet_bytes.subspan(payload_offset),
    });
    if (!ciphertext.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(ciphertext.error().code,
                                                 ciphertext.error().offset);
    }

    const auto final_packet_size = payload_offset + ciphertext.value();
    datagram.resize(datagram_begin + final_packet_size);
    const auto protected_packet = apply_short_header_protection_in_place(
        std::span<std::byte>(datagram).subspan(datagram_begin, final_packet_size),
        packet_number_span, cipher_suite, keys_ref);
    if (!protected_packet.has_value()) {
        rollback();
        return CodecResult<std::size_t>::failure(protected_packet.error().code,
                                                 protected_packet.error().offset);
    }

    return CodecResult<std::size_t>::success(final_packet_size);
}

CodecResult<ProtectedPacketDecodeResult>
deserialize_protected_one_rtt_packet(std::span<const std::byte> bytes,
                                     const DeserializeProtectionContext &context) {
    if (!context.one_rtt_secret.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);

    const auto packet_number_offset = 1 + context.one_rtt_destination_connection_id_length;
    if (packet_number_offset > bytes.size())
        return CodecResult<ProtectedPacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, 1);

    const auto keys = expand_traffic_secret_cached(context.one_rtt_secret.value());
    if (!keys.has_value())
        return CodecResult<ProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                 keys.error().offset);
    const auto &keys_ref = keys.value().get();

    const auto cipher_suite = context.one_rtt_secret->cipher_suite;
    const auto unprotected =
        remove_short_header_protection(bytes, packet_number_offset, cipher_suite, keys_ref);
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
    const auto nonce = make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value());

    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext =
            std::span<const std::byte>(unprotected.value().packet_bytes).subspan(header_end),
    });
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

CodecResult<ReceivedProtectedPacketDecodeResult>
deserialize_received_protected_one_rtt_packet(std::span<const std::byte> bytes,
                                              const DeserializeProtectionContext &context) {
    if (!context.one_rtt_secret.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::missing_crypto_context, 0);
    }

    const auto packet_number_offset = 1 + context.one_rtt_destination_connection_id_length;
    if (packet_number_offset > bytes.size()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::malformed_short_header_context, 1);
    }

    const auto keys = expand_traffic_secret_cached(context.one_rtt_secret.value());
    if (!keys.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(keys.error().code,
                                                                         keys.error().offset);
    }
    const auto &keys_ref = keys.value().get();

    const auto cipher_suite = context.one_rtt_secret->cipher_suite;
    const auto unprotected =
        remove_short_header_protection(bytes, packet_number_offset, cipher_suite, keys_ref);
    if (!unprotected.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            unprotected.error().code, unprotected.error().offset);
    }

    const auto key_phase =
        (std::to_integer<std::uint8_t>(unprotected.value().packet_bytes[0]) & 0x04u) != 0;
    if (key_phase != context.one_rtt_key_phase) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            CodecErrorCode::invalid_packet_protection_state, 0);
    }

    const auto packet_number = recover_packet_number(
        context.largest_authenticated_application_packet_number,
        unprotected.value().truncated_packet_number, unprotected.value().packet_number_length);
    if (!packet_number.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            packet_number.error().code, packet_number.error().offset);
    }

    const auto header_end = packet_number_offset + unprotected.value().packet_number_length;
    const auto nonce = make_packet_protection_nonce_or_assert(keys_ref.iv, packet_number.value());
    auto plaintext = open_payload(OpenPayloadInput{
        .cipher_suite = cipher_suite,
        .key = keys_ref.key,
        .nonce = nonce,
        .associated_data =
            std::span<const std::byte>(unprotected.value().packet_bytes).first(header_end),
        .ciphertext =
            std::span<const std::byte>(unprotected.value().packet_bytes).subspan(header_end),
    });
    if (!plaintext.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(plaintext.error().code,
                                                                         plaintext.error().offset);
    }

    auto plaintext_storage = std::make_shared<std::vector<std::byte>>(std::move(plaintext.value()));
    std::vector<std::byte> plaintext_header(unprotected.value().packet_bytes.begin(),
                                            unprotected.value().packet_bytes.begin() +
                                                static_cast<std::ptrdiff_t>(header_end));
    auto decoded_fields = decode_received_short_header_packet_fields(
        plaintext_header, SharedBytes(plaintext_storage, 0, plaintext_storage->size()));
    if (!decoded_fields.has_value()) {
        return CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
            decoded_fields.error().code, decoded_fields.error().offset);
    }

    return CodecResult<ReceivedProtectedPacketDecodeResult>::success(
        ReceivedProtectedPacketDecodeResult{
            .packet =
                ReceivedProtectedOneRttPacket{
                    .spin_bit = decoded_fields.value().spin_bit,
                    .key_phase = decoded_fields.value().key_phase,
                    .destination_connection_id =
                        std::move(decoded_fields.value().destination_connection_id),
                    .packet_number_length = decoded_fields.value().packet_number_length,
                    .packet_number = packet_number.value(),
                    .plaintext_storage = plaintext_storage,
                    .frames = std::move(decoded_fields.value().frames),
                },
            .bytes_consumed = bytes.size(),
        });
}

CodecResult<bool> append_serialized_protected_packet(SerializedProtectedDatagram &datagram,
                                                     const ProtectedPacket &packet,
                                                     const SerializeProtectionContext &context) {
    const auto offset = datagram.bytes.size();
    const auto appended = std::visit(
        [&](const auto &typed_packet) -> CodecResult<std::size_t> {
            using PacketType = std::decay_t<decltype(typed_packet)>;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                const auto encoded = serialize_protected_initial_packet(typed_packet, context);
                if (!encoded.has_value()) {
                    return CodecResult<std::size_t>::failure(encoded.error().code,
                                                             encoded.error().offset);
                }
                datagram.bytes.append(encoded.value());
                return CodecResult<std::size_t>::success(encoded.value().size());
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                const auto encoded = serialize_protected_handshake_packet(typed_packet, context);
                if (!encoded.has_value()) {
                    return CodecResult<std::size_t>::failure(encoded.error().code,
                                                             encoded.error().offset);
                }
                datagram.bytes.append(encoded.value());
                return CodecResult<std::size_t>::success(encoded.value().size());
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                const auto encoded = serialize_protected_zero_rtt_packet(typed_packet, context);
                if (!encoded.has_value()) {
                    return CodecResult<std::size_t>::failure(encoded.error().code,
                                                             encoded.error().offset);
                }
                datagram.bytes.append(encoded.value());
                return CodecResult<std::size_t>::success(encoded.value().size());
            } else {
                return append_protected_one_rtt_packet_to_datagram_impl(datagram.bytes,
                                                                        typed_packet, context);
            }
        },
        packet);
    if (!appended.has_value()) {
        return CodecResult<bool>::failure(appended.error().code, appended.error().offset);
    }

    datagram.packet_metadata.push_back(SerializedProtectedPacketMetadata{
        .offset = offset,
        .length = appended.value(),
    });

    return CodecResult<bool>::success(true);
}

} // namespace

CodecResult<SerializedProtectedDatagram>
serialize_protected_datagram_with_metadata(std::span<const ProtectedPacket> packets,
                                           const SerializeProtectionContext &context) {
    SerializedProtectedDatagram out;
    out.packet_metadata.reserve(packets.size());
    for (const auto &packet : packets) {
        const auto appended = append_serialized_protected_packet(out, packet, context);
        if (!appended.has_value()) {
            return CodecResult<SerializedProtectedDatagram>::failure(appended.error().code,
                                                                     appended.error().offset);
        }
    }

    return CodecResult<SerializedProtectedDatagram>::success(std::move(out));
}

CodecResult<SerializedProtectedDatagram>
serialize_protected_datagram_with_metadata(std::span<const ProtectedPacket> packets,
                                           const ProtectedPacket &appended_packet,
                                           const SerializeProtectionContext &context) {
    auto encoded = serialize_protected_datagram_with_metadata(packets, context);
    if (!encoded.has_value()) {
        return CodecResult<SerializedProtectedDatagram>::failure(encoded.error().code,
                                                                 encoded.error().offset);
    }

    const auto appended =
        append_serialized_protected_packet(encoded.value(), appended_packet, context);
    if (!appended.has_value()) {
        return CodecResult<SerializedProtectedDatagram>::failure(appended.error().code,
                                                                 appended.error().offset);
    }

    return encoded;
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(DatagramBuffer &datagram,
                                            const ProtectedOneRttPacketView &packet,
                                            const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl(datagram, packet, context);
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacketView &packet,
                                            const SerializeProtectionContext &context) {
    DatagramBuffer encoded(datagram);
    const auto appended =
        append_protected_one_rtt_packet_to_datagram_impl(encoded, packet, context);
    if (!appended.has_value()) {
        return appended;
    }

    datagram = encoded.to_vector();
    return appended;
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(DatagramBuffer &datagram,
                                            const ProtectedOneRttPacketFragmentView &packet,
                                            const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl(datagram, packet, context);
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacketFragmentView &packet,
                                            const SerializeProtectionContext &context) {
    DatagramBuffer encoded(datagram);
    const auto appended =
        append_protected_one_rtt_packet_to_datagram_impl(encoded, packet, context);
    if (!appended.has_value()) {
        return appended;
    }

    datagram = encoded.to_vector();
    return appended;
}

CodecResult<std::vector<std::byte>>
serialize_protected_datagram(std::span<const ProtectedPacket> packets,
                             const SerializeProtectionContext &context) {
    auto encoded = serialize_protected_datagram_with_metadata(packets, context);
    if (!encoded.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                            encoded.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(encoded.value().bytes));
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

            if (type.value() == LongHeaderPacketType::initial) {
                decoded = deserialize_protected_initial_packet(bytes.subspan(offset), context);
            } else if (type.value() == LongHeaderPacketType::zero_rtt) {
                decoded = deserialize_protected_zero_rtt_packet(bytes.subspan(offset), context);
            } else {
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

CodecResult<std::vector<ReceivedProtectedPacket>>
deserialize_received_protected_datagram(std::span<const std::byte> bytes,
                                        const DeserializeProtectionContext &context) {
    if (bytes.empty()) {
        return CodecResult<std::vector<ReceivedProtectedPacket>>::failure(
            CodecErrorCode::truncated_input, 0);
    }

    std::vector<ReceivedProtectedPacket> packets;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        CodecResult<ReceivedProtectedPacketDecodeResult> decoded =
            CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
                CodecErrorCode::unsupported_packet_type, 0);
        const auto first_byte = std::to_integer<std::uint8_t>(bytes[offset]);
        if ((first_byte & 0x80u) == 0) {
            decoded = deserialize_received_protected_one_rtt_packet(bytes.subspan(offset), context);
        } else {
            const auto type = read_long_header_type(bytes.subspan(offset));
            if (!type.has_value()) {
                return CodecResult<std::vector<ReceivedProtectedPacket>>::failure(
                    type.error().code, offset + type.error().offset);
            }

            if (type.value() == LongHeaderPacketType::initial) {
                decoded =
                    deserialize_received_protected_initial_packet(bytes.subspan(offset), context);
            } else if (type.value() == LongHeaderPacketType::zero_rtt) {
                decoded =
                    deserialize_received_protected_zero_rtt_packet(bytes.subspan(offset), context);
            } else {
                decoded =
                    deserialize_received_protected_handshake_packet(bytes.subspan(offset), context);
            }
        }
        if (!decoded.has_value()) {
            return CodecResult<std::vector<ReceivedProtectedPacket>>::failure(
                decoded.error().code, offset + decoded.error().offset);
        }

        packets.push_back(std::move(decoded.value().packet));
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<ReceivedProtectedPacket>>::success(std::move(packets));
}

} // namespace coquic::quic

namespace coquic::quic::test {

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacket &packet,
                                            const SerializeProtectionContext &context) {
    DatagramBuffer encoded(datagram);
    const auto appended =
        append_protected_one_rtt_packet_to_datagram_impl(encoded, packet, context);
    if (!appended.has_value()) {
        return appended;
    }

    datagram = encoded.to_vector();
    return appended;
}

COQUIC_NO_PROFILE bool coverage_check(bool &ok, std::string_view suite_name,
                                      std::string_view label, bool condition) {
    if (!condition) {
        std::cerr << suite_name << " failed: " << label << '\n';
        ok = false;
    }
    return condition;
}

COQUIC_NO_PROFILE void append_u32_be_for_tests(std::vector<std::byte> &bytes,
                                               std::uint32_t value) {
    bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 24)));
    bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 16)));
    bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 8)));
    bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value)));
}

COQUIC_NO_PROFILE CodecResult<std::vector<std::byte>> build_received_long_header_packet_for_tests(
    LongHeaderPacketType packet_type, std::uint32_t version,
    const ConnectionId &destination_connection_id, const ConnectionId &source_connection_id,
    std::span<const std::byte> token, bool has_token, std::uint8_t packet_number_length,
    std::uint64_t packet_number, std::span<const std::byte> plaintext_payload,
    CipherSuite cipher_suite, const PacketProtectionKeys &keys) {
    const auto truncated_packet_number =
        truncate_packet_number(packet_number, packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(truncated_packet_number.error().code,
                                                            truncated_packet_number.error().offset);
    }
    const auto payload_length = static_cast<std::uint64_t>(
        packet_number_length + plaintext_payload.size() + kPacketProtectionTagLength);

    std::vector<std::byte> packet_bytes;
    packet_bytes.push_back(static_cast<std::byte>(
        0x80u | 0x40u | ((encoded_long_header_type(packet_type, version) & 0x03u) << 4u) |
        ((packet_number_length - 1u) & 0x03u)));
    append_u32_be_for_tests(packet_bytes, version);
    packet_bytes.push_back(
        static_cast<std::byte>(static_cast<std::uint8_t>(destination_connection_id.size())));
    append_bytes(packet_bytes, destination_connection_id);
    packet_bytes.push_back(
        static_cast<std::byte>(static_cast<std::uint8_t>(source_connection_id.size())));
    append_bytes(packet_bytes, source_connection_id);
    if (has_token) {
        append_varint_unchecked(packet_bytes, token.size());
        append_bytes(packet_bytes, token);
    }
    append_varint_unchecked(packet_bytes, payload_length);
    append_packet_number(packet_bytes,
                         TruncatedPacketNumberEncoding{
                             .packet_number_length = packet_number_length,
                             .truncated_packet_number = truncated_packet_number.value(),
                         });

    const auto packet_number_offset = packet_bytes.size() - packet_number_length;
    const auto header_end = packet_bytes.size();
    packet_bytes.resize(header_end + plaintext_payload.size() + kPacketProtectionTagLength);

    const auto nonce = make_packet_protection_nonce_or_assert(keys.iv, packet_number);
    const auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(header_end),
        .plaintext = plaintext_payload,
        .ciphertext = std::span<std::byte>(packet_bytes).subspan(header_end),
    });
    if (!ciphertext.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(ciphertext.error().code,
                                                            ciphertext.error().offset);
    }
    packet_bytes.resize(header_end + ciphertext.value());

    const auto protected_packet =
        apply_long_header_protection_in_place(std::span<std::byte>(packet_bytes),
                                              PacketNumberSpan{
                                                  .packet_number_offset = packet_number_offset,
                                                  .packet_number_length = packet_number_length,
                                              },
                                              cipher_suite, keys);
    if (!protected_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(protected_packet.error().code,
                                                            protected_packet.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
}

COQUIC_NO_PROFILE CodecResult<std::vector<std::byte>> build_received_one_rtt_packet_for_tests(
    bool spin_bit, bool key_phase, const ConnectionId &destination_connection_id,
    std::uint8_t packet_number_length, std::uint64_t packet_number,
    std::span<const std::byte> plaintext_payload, CipherSuite cipher_suite,
    const PacketProtectionKeys &keys) {
    const auto truncated_packet_number =
        truncate_packet_number(packet_number, packet_number_length);
    if (!truncated_packet_number.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(truncated_packet_number.error().code,
                                                            truncated_packet_number.error().offset);
    }

    std::vector<std::byte> packet_bytes;
    packet_bytes.push_back(
        make_short_header_first_byte(spin_bit, key_phase, packet_number_length));
    append_bytes(packet_bytes, destination_connection_id);
    append_packet_number(packet_bytes,
                         TruncatedPacketNumberEncoding{
                             .packet_number_length = packet_number_length,
                             .truncated_packet_number = truncated_packet_number.value(),
                         });

    const auto packet_number_offset = 1 + destination_connection_id.size();
    const auto header_end = packet_bytes.size();
    packet_bytes.resize(header_end + plaintext_payload.size() + kPacketProtectionTagLength);

    const auto nonce = make_packet_protection_nonce_or_assert(keys.iv, packet_number);
    const auto ciphertext = seal_payload_into(SealPayloadIntoInput{
        .cipher_suite = cipher_suite,
        .key = keys.key,
        .nonce = nonce,
        .associated_data = std::span<const std::byte>(packet_bytes).first(header_end),
        .plaintext = plaintext_payload,
        .ciphertext = std::span<std::byte>(packet_bytes).subspan(header_end),
    });
    if (!ciphertext.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(ciphertext.error().code,
                                                            ciphertext.error().offset);
    }
    packet_bytes.resize(header_end + ciphertext.value());

    const auto protected_packet =
        apply_short_header_protection_in_place(std::span<std::byte>(packet_bytes),
                                               PacketNumberSpan{
                                                   .packet_number_offset = packet_number_offset,
                                                   .packet_number_length = packet_number_length,
                                               },
                                               cipher_suite, keys);
    if (!protected_packet.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(protected_packet.error().code,
                                                            protected_packet.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(packet_bytes));
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

COQUIC_NO_PROFILE bool protected_codec_internal_coverage_for_tests() {
    bool ok = true;
    const auto check = [&](std::string_view label, bool condition) {
        return coverage_check(ok, "protected_codec_internal_coverage_for_tests", label, condition);
    };
    const auto codec_failure_impl = [](const CodecError *error, CodecErrorCode code) {
        return error != nullptr && error->code == code;
    };
    const auto codec_failure_offset_impl = [](const CodecError *error, CodecErrorCode code,
                                              std::size_t offset) {
        return error != nullptr && error->code == code && error->offset == offset;
    };
    const auto codec_failure = [&](const auto &result, CodecErrorCode code) {
        return codec_failure_impl(std::get_if<CodecError>(&result.storage), code);
    };
    const auto codec_failure_offset = [&](const auto &result, CodecErrorCode code,
                                          std::size_t offset) {
        return codec_failure_offset_impl(std::get_if<CodecError>(&result.storage), code, offset);
    };
    const auto optional_failure = [&](const std::optional<CodecError> &error, CodecErrorCode code,
                                      std::size_t offset) {
        if (!error.has_value()) {
            return false;
        }
        return codec_failure_offset_impl(&*error, code, offset);
    };

    {
        volatile bool keep_missing_error_empty = true;
        std::optional<CodecError> missing_error;
        if (!keep_missing_error_empty) {
            missing_error = CodecError{CodecErrorCode::invalid_varint, 0};
        }
        const std::optional<CodecError> mismatched_code_error =
            CodecError{CodecErrorCode::truncated_input, 0};
        const std::optional<CodecError> mismatched_offset_error =
            CodecError{CodecErrorCode::invalid_varint, 1};
        const std::optional<CodecError> matching_error =
            CodecError{CodecErrorCode::invalid_varint, 0};
        check(
            "codec failure helper matches expected failures and rejects successes",
            !codec_failure(CodecResult<std::size_t>::success(0), CodecErrorCode::invalid_varint) &&
                !codec_failure(
                    CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0),
                    CodecErrorCode::invalid_varint) &&
                codec_failure(CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0),
                              CodecErrorCode::invalid_varint));
        check("codec failure offset helper matches expected failures and rejects mismatches",
              !codec_failure_offset(CodecResult<std::size_t>::success(0),
                                    CodecErrorCode::invalid_varint, 0) &&
                  !codec_failure_offset(
                      CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0),
                      CodecErrorCode::invalid_varint, 0) &&
                  !codec_failure_offset(
                      CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 1),
                      CodecErrorCode::invalid_varint, 0) &&
                  codec_failure_offset(
                      CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0),
                      CodecErrorCode::invalid_varint, 0));
        check("optional failure helper rejects missing and mismatched errors and matches expected "
              "errors",
              !optional_failure(missing_error, CodecErrorCode::invalid_varint, 0) &&
                  !optional_failure(mismatched_code_error, CodecErrorCode::invalid_varint, 0) &&
                  !optional_failure(mismatched_offset_error, CodecErrorCode::invalid_varint, 0) &&
                  optional_failure(matching_error, CodecErrorCode::invalid_varint, 0));
    }

    {
        BufferWriter writer;
        check("append_varint(BufferWriter) rejects out-of-range values",
              optional_failure(append_varint(writer, kMaxVarInt + 1u),
                               CodecErrorCode::invalid_varint, 0) &&
                  writer.bytes().empty());
        static_cast<void>(append_varint(writer, 0x25u));
        append_varint_unchecked(writer, 0x0fu);
        check("append_varint(BufferWriter) and unchecked helper append encoded values",
              writer.bytes() == std::vector<std::byte>{
                                    std::byte{0x25},
                                    std::byte{0x0f},
                                });
    }

    {
        std::vector<std::byte> bytes{std::byte{0xaa}};
        append_bytes(bytes, {});
        append_bytes(bytes, std::array{
                                std::byte{0xbb},
                                std::byte{0xcc},
                            });
        check("append_bytes preserves prefixes and appends non-empty payloads",
              bytes == std::vector<std::byte>{
                           std::byte{0xaa},
                           std::byte{0xbb},
                           std::byte{0xcc},
                       });

        std::vector<std::byte> varints;
        check("append_varint(vector) rejects out-of-range values",
              optional_failure(append_varint(varints, kMaxVarInt + 1u),
                               CodecErrorCode::invalid_varint, 0) &&
                  varints.empty());
        static_cast<void>(append_varint(varints, 0x2au));
        append_varint_unchecked(varints, 0x0cu);
        check("append_varint(vector) and unchecked helper append encoded values",
              varints == std::vector<std::byte>{
                             std::byte{0x2a},
                             std::byte{0x0c},
                         });
    }

    check("make_short_header_first_byte encodes spin, key phase, and packet number length",
          make_short_header_first_byte(/*spin_bit=*/true, /*key_phase=*/true,
                                       /*packet_number_length=*/2) == std::byte{0x65});

    {
        constexpr TruncatedPacketNumberEncoding encoding{
            .packet_number_length = 2,
            .truncated_packet_number = 0x1234u,
        };
        BufferWriter writer;
        append_packet_number(writer, encoding);
        check("append_packet_number(BufferWriter) writes the truncated packet number bytes",
              writer.bytes() == std::vector<std::byte>{
                                    std::byte{0x12},
                                    std::byte{0x34},
                                });

        std::vector<std::byte> bytes;
        append_packet_number(bytes, encoding);
        check("append_packet_number(vector) writes the truncated packet number bytes",
              bytes == std::vector<std::byte>{
                           std::byte{0x12},
                           std::byte{0x34},
                       });

        std::array<std::byte, 1> too_small_packet_number{};
        SpanBufferWriter too_small_writer(too_small_packet_number);
        check("append_packet_number(SpanBufferWriter) reports truncated output",
              optional_failure(append_packet_number(too_small_writer, encoding),
                               CodecErrorCode::truncated_input, 1));

        std::array<std::byte, 2> packet_number_bytes{};
        SpanBufferWriter full_writer(packet_number_bytes);
        check("append_packet_number(SpanBufferWriter) writes the full packet number",
              !append_packet_number(full_writer, encoding).has_value() &&
                  packet_number_bytes == std::array{std::byte{0x12}, std::byte{0x34}});
    }

    {
        std::array<std::byte, 0> no_u32_bytes{};
        SpanBufferWriter no_u32_writer(no_u32_bytes);
        check("write_u32_be fails when no output space is available",
              optional_failure(write_u32_be(no_u32_writer, 0x12345678u),
                               CodecErrorCode::truncated_input, 0));

        std::array<std::byte, 1> one_u32_byte{};
        SpanBufferWriter one_u32_writer(one_u32_byte);
        check("write_u32_be fails on the second byte when only one byte fits",
              optional_failure(write_u32_be(one_u32_writer, 0x12345678u),
                               CodecErrorCode::truncated_input, 1));

        std::array<std::byte, 2> two_u32_bytes{};
        SpanBufferWriter two_u32_writer(two_u32_bytes);
        check("write_u32_be fails on the third byte when only two bytes fit",
              optional_failure(write_u32_be(two_u32_writer, 0x12345678u),
                               CodecErrorCode::truncated_input, 2));

        std::array<std::byte, 3> three_u32_bytes{};
        SpanBufferWriter three_u32_writer(three_u32_bytes);
        check("write_u32_be fails on the final byte when only three bytes fit",
              optional_failure(write_u32_be(three_u32_writer, 0x12345678u),
                               CodecErrorCode::truncated_input, 3));

        std::array<std::byte, 4> u32_bytes{};
        SpanBufferWriter u32_writer(u32_bytes);
        check("write_u32_be writes big-endian u32 values",
              !write_u32_be(u32_writer, 0x12345678u).has_value() &&
                  u32_bytes == std::array{std::byte{0x12}, std::byte{0x34}, std::byte{0x56},
                                          std::byte{0x78}});
    }

    check("minimum_payload_bytes_for_header_sample reports remaining sample padding",
          minimum_payload_bytes_for_header_sample(2) == 2 &&
              minimum_payload_bytes_for_header_sample(4) == 0);
    check("read_u32_be returns zero for empty spans", read_u32_be({}) == 0u);

    {
        const std::array<Frame, 0> empty_frames{};
        check("serialized_frame_payload_size rejects empty payloads",
              codec_failure(serialized_frame_payload_size(empty_frames),
                            CodecErrorCode::empty_packet_payload));

        const std::array<Frame, 2> valid_frames = {
            PingFrame{},
            PaddingFrame{.length = 1},
        };
        const auto valid_size = serialized_frame_payload_size(valid_frames);
        check("serialized_frame_payload_size sums valid frame sizes",
              valid_size.has_value() && valid_size.value() == 2);

        const std::array<Frame, 1> invalid_frames = {
            PaddingFrame{.length = 0},
        };
        check("serialized_frame_payload_size propagates frame serialization failures",
              codec_failure(serialized_frame_payload_size(invalid_frames),
                            CodecErrorCode::invalid_varint));
    }

    {
        BufferReader missing_length_reader({});
        check("read_connection_id propagates missing length failures",
              codec_failure_offset(
                  read_connection_id(missing_length_reader, /*enforce_v1_limit=*/true),
                  CodecErrorCode::truncated_input, 0));

        const std::array<std::byte, 22> oversized_connection_id = {
            std::byte{21},   std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
            std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b}, std::byte{0x0c}, std::byte{0x0d},
            std::byte{0x0e}, std::byte{0x0f}, std::byte{0x10}, std::byte{0x11}, std::byte{0x12},
            std::byte{0x13}, std::byte{0x14},
        };
        BufferReader oversized_reader(oversized_connection_id);
        check("read_connection_id enforces the QUIC v1 connection-id limit",
              codec_failure_offset(read_connection_id(oversized_reader, /*enforce_v1_limit=*/true),
                                   CodecErrorCode::invalid_varint, 1));

        const std::array<std::byte, 2> truncated_connection_id = {
            std::byte{2},
            std::byte{0xaa},
        };
        BufferReader truncated_reader(truncated_connection_id);
        check("read_connection_id propagates truncated connection-id bodies",
              codec_failure_offset(read_connection_id(truncated_reader, /*enforce_v1_limit=*/false),
                                   CodecErrorCode::truncated_input, 1));

        const std::array<std::byte, 3> valid_connection_id = {
            std::byte{2},
            std::byte{0xaa},
            std::byte{0xbb},
        };
        BufferReader valid_reader(valid_connection_id);
        const auto decoded_connection_id =
            read_connection_id(valid_reader, /*enforce_v1_limit=*/true);
        check("read_connection_id returns the decoded connection id",
              decoded_connection_id.has_value() &&
                  decoded_connection_id.value() == ConnectionId{
                                                       std::byte{0xaa},
                                                       std::byte{0xbb},
                                                   });
    }

    {
        const Frame ping = PingFrame{};
        const Frame ack = AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        };
        const Frame stream = StreamFrame{
            .has_length = false,
            .stream_id = 3,
            .stream_data = {std::byte{0x01}},
        };
        check(
            "frame_allowed_in_long_header_packet_type distinguishes zero-rtt and handshake rules",
            frame_allowed_in_long_header_packet_type(ping, LongHeaderPacketType::initial) &&
                !frame_allowed_in_long_header_packet_type(ack, LongHeaderPacketType::zero_rtt) &&
                !frame_allowed_in_long_header_packet_type(stream, LongHeaderPacketType::handshake));

        const std::array<Frame, 1> invalid_initial_frames = {
            Frame(StreamFrame{
                .has_length = true,
                .stream_id = 4,
                .stream_data = {std::byte{0x02}},
            }),
        };
        check("validate_long_header_frames rejects frames not allowed in the packet type",
              codec_failure_offset(validate_long_header_frames(invalid_initial_frames,
                                                               LongHeaderPacketType::initial),
                                   CodecErrorCode::frame_not_allowed_in_packet_type, 0));

        const std::array<Frame, 2> lengthless_stream_frames = {
            Frame(StreamFrame{
                .has_length = false,
                .stream_id = 5,
                .stream_data = {std::byte{0x03}},
            }),
            Frame(PingFrame{}),
        };
        check("validate_long_header_frames rejects non-terminal lengthless stream frames",
              codec_failure_offset(validate_long_header_frames(lengthless_stream_frames,
                                                               LongHeaderPacketType::zero_rtt),
                                   CodecErrorCode::packet_length_mismatch, 0));

        const std::array<Frame, 1> terminal_lengthless_stream_frames = {
            Frame(StreamFrame{
                .has_length = false,
                .stream_id = 5,
                .stream_data = {std::byte{0x04}},
            }),
        };
        check("validate_long_header_frames accepts terminal lengthless stream frames",
              validate_long_header_frames(terminal_lengthless_stream_frames,
                                          LongHeaderPacketType::zero_rtt)
                  .has_value());

        const std::array<Frame, 1> valid_long_header_frames = {
            Frame(PingFrame{}),
        };
        check("validate_long_header_frames accepts valid long-header payloads",
              validate_long_header_frames(valid_long_header_frames, LongHeaderPacketType::initial)
                  .has_value());
    }

    {
        const ReceivedFrame ack = ReceivedAckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        };
        const ReceivedFrame ping = PingFrame{};
        const ReceivedFrame stream = ReceivedStreamFrame{
            .has_length = true,
            .stream_id = 1,
        };
        check("frame_allowed_in_protected_payload_packet_type distinguishes one-rtt and zero-rtt "
              "rules",
              frame_allowed_in_protected_payload_packet_type(ack,
                                                             ProtectedPayloadPacketType::one_rtt) &&
                  !frame_allowed_in_protected_payload_packet_type(
                      ack, ProtectedPayloadPacketType::zero_rtt) &&
                  !frame_allowed_in_protected_payload_packet_type(
                      stream, ProtectedPayloadPacketType::handshake));

        check("deserialize_received_frame_sequence rejects empty payloads",
              codec_failure_offset(deserialize_received_frame_sequence(
                                       SharedBytes{}, ProtectedPayloadPacketType::one_rtt, 7),
                                   CodecErrorCode::empty_packet_payload, 7));

        const auto decode_failure = deserialize_received_frame_sequence(
            SharedBytes{
                std::byte{0x02},
            },
            ProtectedPayloadPacketType::one_rtt, 11);
        check("deserialize_received_frame_sequence propagates frame decode failures",
              !decode_failure.has_value() &&
                  decode_failure.error().code == CodecErrorCode::truncated_input &&
                  decode_failure.error().offset > 11);

        const auto serialized_ack = serialize_frame(AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        });
        check("serialize_frame builds an ack frame fixture for protected payload checks",
              serialized_ack.has_value());
        if (serialized_ack.has_value()) {
            check(
                "deserialize_received_frame_sequence rejects frames forbidden in zero-rtt payloads",
                codec_failure_offset(
                    deserialize_received_frame_sequence(SharedBytes(serialized_ack.value()),
                                                        ProtectedPayloadPacketType::zero_rtt, 19),
                    CodecErrorCode::frame_not_allowed_in_packet_type, 19));
        }

        const auto serialized_ping = serialize_frame(PingFrame{});
        check("serialize_frame builds a ping frame fixture for protected payload checks",
              serialized_ping.has_value());
        if (serialized_ping.has_value()) {
            const auto decoded = deserialize_received_frame_sequence(
                SharedBytes(serialized_ping.value()), ProtectedPayloadPacketType::one_rtt, 23);
            check("deserialize_received_frame_sequence accepts valid payloads",
                  decoded.has_value() && decoded.value().size() == 1 &&
                      std::holds_alternative<PingFrame>(decoded.value().front()));
        }
    }

    check("encoded_stream_frame_payload_size includes type, varints, and payload bytes",
          encoded_stream_frame_payload_size(/*stream_id=*/3, /*offset=*/1, /*payload_size=*/2) ==
              6);

    {
        std::vector<std::byte> overflow_header_prefix{std::byte{0xfe}};
        const auto overflow_header =
            serialize_stream_frame_header_into(overflow_header_prefix, StreamFrameHeaderFields{
                                                                           .stream_id = 1,
                                                                           .offset = kMaxVarInt,
                                                                           .payload_size = 1,
                                                                       });
        check("serialize_stream_frame_header_into(vector) rejects offset overflows",
              codec_failure(overflow_header, CodecErrorCode::invalid_varint) &&
                  overflow_header_prefix == std::vector<std::byte>{std::byte{0xfe}});

        std::vector<std::byte> invalid_stream_id_prefix{std::byte{0xee}};
        const auto invalid_stream_id = serialize_stream_frame_header_into(
            invalid_stream_id_prefix, StreamFrameHeaderFields{
                                          .fin = true,
                                          .stream_id = kMaxVarInt + 1u,
                                          .offset = 0,
                                          .payload_size = 2,
                                      });
        check("serialize_stream_frame_header_into(vector) rolls back when stream id encoding fails",
              codec_failure(invalid_stream_id, CodecErrorCode::invalid_varint) &&
                  invalid_stream_id_prefix == std::vector<std::byte>{std::byte{0xee}});

        std::vector<std::byte> encoded_header;
        const auto valid_header =
            serialize_stream_frame_header_into(encoded_header, StreamFrameHeaderFields{
                                                                   .fin = true,
                                                                   .stream_id = 3,
                                                                   .offset = 1,
                                                                   .payload_size = 2,
                                                               });
        check("serialize_stream_frame_header_into(vector) encodes valid stream headers",
              valid_header.has_value() && valid_header.value() == encoded_header.size() &&
                  !encoded_header.empty() && encoded_header.front() == std::byte{0x0f});
    }

    {
        std::array<std::byte, 0> no_header_space{};
        SpanBufferWriter no_header_writer(no_header_space);
        check("serialize_stream_frame_header_into(span) fails when the type byte does not fit",
              codec_failure(serialize_stream_frame_header_into(no_header_writer,
                                                               StreamFrameHeaderFields{
                                                                   .stream_id = 1,
                                                                   .offset = 0,
                                                                   .payload_size = 0,
                                                               }),
                            CodecErrorCode::truncated_input));

        std::array<std::byte, 1> one_header_byte{};
        SpanBufferWriter one_header_writer(one_header_byte);
        check(
            "serialize_stream_frame_header_into(span) fails when the stream id varint does not fit",
            codec_failure_offset(serialize_stream_frame_header_into(one_header_writer,
                                                                    StreamFrameHeaderFields{
                                                                        .stream_id = 64,
                                                                        .offset = 0,
                                                                        .payload_size = 0,
                                                                    }),
                                 CodecErrorCode::truncated_input, 1));

        std::array<std::byte, 8> overflow_header_space{};
        SpanBufferWriter overflow_header_writer(overflow_header_space);
        check("serialize_stream_frame_header_into(span) rejects offset overflows",
              codec_failure(serialize_stream_frame_header_into(overflow_header_writer,
                                                               StreamFrameHeaderFields{
                                                                   .stream_id = 1,
                                                                   .offset = kMaxVarInt,
                                                                   .payload_size = 1,
                                                               }),
                            CodecErrorCode::invalid_varint));

        std::array<std::byte, 8> header_space{};
        SpanBufferWriter header_writer(header_space);
        const auto valid_header =
            serialize_stream_frame_header_into(header_writer, StreamFrameHeaderFields{
                                                                  .fin = true,
                                                                  .stream_id = 3,
                                                                  .offset = 1,
                                                                  .payload_size = 2,
                                                              });
        check("serialize_stream_frame_header_into(span) encodes valid stream headers",
              valid_header.has_value() && valid_header.value() == header_writer.offset() &&
                  header_space.front() == std::byte{0x0f});
    }

    {
        const std::array payload = {
            std::byte{0x44},
            std::byte{0x55},
        };

        std::vector<std::byte> overflow_payload_prefix{std::byte{0xab}};
        const auto overflow_payload = append_stream_frame_payload_into(overflow_payload_prefix,
                                                                       StreamFrameHeaderFields{
                                                                           .stream_id = 1,
                                                                           .offset = kMaxVarInt,
                                                                       },
                                                                       payload);
        check("append_stream_frame_payload_into propagates header serialization failures",
              codec_failure(overflow_payload, CodecErrorCode::invalid_varint) &&
                  overflow_payload_prefix == std::vector<std::byte>{std::byte{0xab}});

        std::vector<std::byte> stream_frame_bytes;
        const auto appended_payload = append_stream_frame_payload_into(stream_frame_bytes,
                                                                       StreamFrameHeaderFields{
                                                                           .fin = true,
                                                                           .stream_id = 5,
                                                                           .offset = 0,
                                                                       },
                                                                       payload);
        check("append_stream_frame_payload_into appends valid headers and payload bytes",
              appended_payload.has_value() &&
                  appended_payload.value() ==
                      encoded_stream_frame_payload_size(/*stream_id=*/5, /*offset=*/0,
                                                        /*payload_size=*/payload.size()) &&
                  stream_frame_bytes.size() == appended_payload.value());
    }

    {
        const std::array payload = {
            std::byte{0x66},
            std::byte{0x77},
        };
        const StreamFrameHeaderFields header{
            .stream_id = 9,
            .offset = 1,
        };
        std::vector<std::byte> overflow_stream_output(8);

        check("serialize_stream_frame_into propagates header serialization failures",
              codec_failure(serialize_stream_frame_into(overflow_stream_output,
                                                        StreamFrameHeaderFields{
                                                            .stream_id = 1,
                                                            .offset = kMaxVarInt,
                                                        },
                                                        payload),
                            CodecErrorCode::invalid_varint));

        std::vector<std::byte> header_bytes;
        const auto header_size_result =
            serialize_stream_frame_header_into(header_bytes, StreamFrameHeaderFields{
                                                                 .stream_id = header.stream_id,
                                                                 .offset = header.offset,
                                                                 .payload_size = payload.size(),
                                                             });
        check("serialize_stream_frame_into computes a header size fixture",
              header_size_result.has_value());
        if (header_size_result.has_value()) {
            std::vector<std::byte> truncated_output(header_size_result.value());
            check(
                "serialize_stream_frame_into reports truncated payload output",
                codec_failure_offset(serialize_stream_frame_into(truncated_output, header, payload),
                                     CodecErrorCode::truncated_input, header_size_result.value()));

            std::vector<std::byte> output(header_size_result.value() + payload.size());
            const auto serialized = serialize_stream_frame_into(output, header, payload);
            check(
                "serialize_stream_frame_into writes complete frames when the span is large enough",
                serialized.has_value() && serialized.value() == output.size());
        }
    }

    {
        const auto storage = std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{
            std::byte{0x10},
            std::byte{0x11},
            std::byte{0x12},
        });

        std::vector<std::byte> invalid_view_bytes;
        check("append_stream_frame_view_into_datagram rejects inverted byte ranges",
              codec_failure(append_stream_frame_view_into_datagram(invalid_view_bytes,
                                                                   StreamFrameView{
                                                                       .stream_id = 1,
                                                                       .offset = 0,
                                                                       .storage = storage,
                                                                       .begin = 2,
                                                                       .end = 1,
                                                                   }),
                            CodecErrorCode::invalid_varint));

        check("append_stream_frame_view_into_datagram rejects non-empty views without storage",
              codec_failure(append_stream_frame_view_into_datagram(invalid_view_bytes,
                                                                   StreamFrameView{
                                                                       .stream_id = 1,
                                                                       .offset = 0,
                                                                       .begin = 0,
                                                                       .end = 1,
                                                                   }),
                            CodecErrorCode::invalid_varint));
        check("append_stream_frame_view_into_datagram rejects storage-backed views that overrun "
              "storage",
              codec_failure(append_stream_frame_view_into_datagram(invalid_view_bytes,
                                                                   StreamFrameView{
                                                                       .stream_id = 1,
                                                                       .offset = 0,
                                                                       .storage = storage,
                                                                       .begin = 0,
                                                                       .end = 4,
                                                                   }),
                            CodecErrorCode::invalid_varint));

        std::vector<std::byte> zero_payload_bytes;
        const auto zero_payload_view =
            append_stream_frame_view_into_datagram(zero_payload_bytes, StreamFrameView{
                                                                           .fin = true,
                                                                           .stream_id = 7,
                                                                           .offset = 0,
                                                                           .begin = 0,
                                                                           .end = 0,
                                                                       });
        check("append_stream_frame_view_into_datagram accepts empty views without storage",
              zero_payload_view.has_value() &&
                  zero_payload_view.value() ==
                      encoded_stream_frame_payload_size(/*stream_id=*/7, /*offset=*/0,
                                                        /*payload_size=*/0));

        std::vector<std::byte> nonzero_view_bytes;
        const auto nonzero_view =
            append_stream_frame_view_into_datagram(nonzero_view_bytes, StreamFrameView{
                                                                           .stream_id = 7,
                                                                           .offset = 1,
                                                                           .storage = storage,
                                                                           .begin = 1,
                                                                           .end = 3,
                                                                       });
        check("append_stream_frame_view_into_datagram accepts valid non-empty views",
              nonzero_view.has_value() && nonzero_view.value() == encoded_stream_frame_payload_size(
                                                                      /*stream_id=*/7, /*offset=*/1,
                                                                      /*payload_size=*/2));

        std::vector<std::byte> invalid_view_output(8);
        check("serialize_stream_frame_view_into_span rejects inverted byte ranges",
              codec_failure(serialize_stream_frame_view_into_span(invalid_view_output,
                                                                  StreamFrameView{
                                                                      .stream_id = 2,
                                                                      .offset = 0,
                                                                      .storage = storage,
                                                                      .begin = 2,
                                                                      .end = 1,
                                                                  }),
                            CodecErrorCode::invalid_varint));

        std::vector<std::byte> missing_storage_output(8);
        check("serialize_stream_frame_view_into_span rejects non-empty views without storage",
              codec_failure(serialize_stream_frame_view_into_span(missing_storage_output,
                                                                  StreamFrameView{
                                                                      .stream_id = 2,
                                                                      .offset = 0,
                                                                      .begin = 0,
                                                                      .end = 1,
                                                                  }),
                            CodecErrorCode::invalid_varint));
        check("serialize_stream_frame_view_into_span rejects storage-backed views that overrun "
              "storage",
              codec_failure(serialize_stream_frame_view_into_span(missing_storage_output,
                                                                  StreamFrameView{
                                                                      .stream_id = 2,
                                                                      .offset = 0,
                                                                      .storage = storage,
                                                                      .begin = 0,
                                                                      .end = 4,
                                                                  }),
                            CodecErrorCode::invalid_varint));

        std::vector<std::byte> serialized_view_output(
            encoded_stream_frame_payload_size(/*stream_id=*/2, /*offset=*/0, /*payload_size=*/2));
        const auto serialized_view =
            serialize_stream_frame_view_into_span(serialized_view_output, StreamFrameView{
                                                                              .stream_id = 2,
                                                                              .offset = 0,
                                                                              .storage = storage,
                                                                              .begin = 0,
                                                                              .end = 2,
                                                                          });
        check("serialize_stream_frame_view_into_span accepts valid views",
              serialized_view.has_value() &&
                  serialized_view.value() == serialized_view_output.size());
    }

    {
        const StreamFrameSendFragment valid_fragment{
            .stream_id = 11,
            .offset = 3,
            .bytes = SharedBytes(std::vector<std::byte>{
                std::byte{0xde},
                std::byte{0xad},
            }),
            .fin = true,
        };
        const auto fragment_header = valid_fragment.stream_frame_header_bytes();
        const auto fragment_size = fragment_header.size() + valid_fragment.bytes.size();

        std::vector<std::byte> fragment_bytes;
        const auto appended_fragment =
            append_stream_frame_send_fragment_to_datagram(fragment_bytes, valid_fragment);
        check("append_stream_frame_send_fragment_to_datagram appends valid fragments",
              appended_fragment.has_value() && appended_fragment.value() == fragment_size &&
                  fragment_bytes.size() == fragment_size);

        const StreamFrameSendFragment invalid_fragment{
            .stream_id = 11,
            .offset = kMaxVarInt,
            .bytes = SharedBytes(std::vector<std::byte>{
                std::byte{0xde},
            }),
            .fin = false,
        };
        check("append_stream_frame_send_fragment_to_datagram rejects overflowing offsets",
              codec_failure(
                  append_stream_frame_send_fragment_to_datagram(fragment_bytes, invalid_fragment),
                  CodecErrorCode::invalid_varint));

        std::vector<std::byte> invalid_fragment_output(fragment_size);
        check("serialize_stream_frame_send_fragment_into_span rejects overflowing offsets",
              codec_failure(serialize_stream_frame_send_fragment_into_span(invalid_fragment_output,
                                                                           invalid_fragment),
                            CodecErrorCode::invalid_varint));

        std::vector<std::byte> truncated_header_output(fragment_header.size() - 1);
        check("serialize_stream_frame_send_fragment_into_span reports truncated header space",
              codec_failure(serialize_stream_frame_send_fragment_into_span(truncated_header_output,
                                                                           valid_fragment),
                            CodecErrorCode::truncated_input));

        std::vector<std::byte> truncated_payload_output(fragment_size - 1);
        check("serialize_stream_frame_send_fragment_into_span reports truncated payload space",
              codec_failure_offset(serialize_stream_frame_send_fragment_into_span(
                                       truncated_payload_output, valid_fragment),
                                   CodecErrorCode::truncated_input, fragment_header.size()));

        std::vector<std::byte> fragment_output(fragment_size);
        const auto serialized_fragment =
            serialize_stream_frame_send_fragment_into_span(fragment_output, valid_fragment);
        check("serialize_stream_frame_send_fragment_into_span writes complete fragments",
              serialized_fragment.has_value() && serialized_fragment.value() == fragment_size);
    }

    return ok;
}

COQUIC_NO_PROFILE bool protected_codec_packet_path_coverage_for_tests() {
    bool ok = true;
    const auto check = [&](std::string_view label, bool condition) {
        return coverage_check(ok, "protected_codec_packet_path_coverage_for_tests", label,
                              condition);
    };
    const auto codec_failure_impl = [](const CodecError *error, CodecErrorCode code) {
        return error != nullptr && error->code == code;
    };
    const auto codec_failure_offset_impl = [](const CodecError *error, CodecErrorCode code,
                                              std::size_t offset) {
        return error != nullptr && error->code == code && error->offset == offset;
    };
    const auto codec_failure = [&](const auto &result, CodecErrorCode code) {
        return codec_failure_impl(std::get_if<CodecError>(&result.storage), code);
    };
    const auto codec_failure_offset = [&](const auto &result, CodecErrorCode code,
                                          std::size_t offset) {
        return codec_failure_offset_impl(std::get_if<CodecError>(&result.storage), code, offset);
    };
    {
        check(
            "packet-path codec failure helper matches expected failures and rejects successes",
            !codec_failure(CodecResult<std::size_t>::success(0), CodecErrorCode::invalid_varint) &&
                codec_failure(CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0),
                              CodecErrorCode::invalid_varint));
        check("packet-path codec failure offset helper matches expected failures and rejects "
              "mismatches",
              !codec_failure_offset(CodecResult<std::size_t>::success(0),
                                    CodecErrorCode::invalid_varint, 0) &&
                  !codec_failure_offset(
                      CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0),
                      CodecErrorCode::invalid_varint, 0) &&
                  !codec_failure_offset(
                      CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 1),
                      CodecErrorCode::invalid_varint, 0) &&
                  codec_failure_offset(
                      CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0),
                      CodecErrorCode::invalid_varint, 0));
    }
    const auto make_secret_bytes = [](std::size_t size, std::uint8_t seed) {
        std::vector<std::byte> secret(size);
        for (std::size_t index = 0; index < size; ++index) {
            secret[index] = static_cast<std::byte>(seed + static_cast<std::uint8_t>(index));
        }
        return secret;
    };
    const auto invalid_cipher_suite = []() {
        const auto raw = static_cast<std::underlying_type_t<CipherSuite>>(0xff);
        CipherSuite cipher_suite{};
        std::memcpy(&cipher_suite, &raw, sizeof(cipher_suite));
        return cipher_suite;
    };
    const auto append_u32_be = [](std::vector<std::byte> &bytes, std::uint32_t value) {
        bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 24)));
        bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 16)));
        bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value >> 8)));
        bytes.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(value)));
    };
    const auto build_long_header = [&](std::byte first_byte, std::uint32_t version,
                                       std::span<const std::byte> destination_connection_id,
                                       std::span<const std::byte> source_connection_id,
                                       std::span<const std::byte> token, bool has_token,
                                       std::uint64_t payload_length,
                                       std::span<const std::byte> packet_number_bytes) {
        std::vector<std::byte> header{first_byte};
        append_u32_be(header, version);
        header.push_back(
            static_cast<std::byte>(static_cast<std::uint8_t>(destination_connection_id.size())));
        append_bytes(header, destination_connection_id);
        header.push_back(
            static_cast<std::byte>(static_cast<std::uint8_t>(source_connection_id.size())));
        append_bytes(header, source_connection_id);
        if (has_token) {
            static_cast<void>(append_varint(header, token.size()));
            append_bytes(header, token);
        }
        static_cast<void>(append_varint(header, payload_length));
        append_bytes(header, packet_number_bytes);
        return header;
    };

    const auto crypto_payload = serialize_frame(CryptoFrame{
        .offset = 0,
        .crypto_data = {std::byte{0x42}},
    });
    check("serialize_frame builds a crypto payload fixture", crypto_payload.has_value());

    const auto ping_payload = serialize_frame(PingFrame{});
    check("serialize_frame builds a ping payload fixture", ping_payload.has_value());

    const auto ack_payload = serialize_frame(AckFrame{
        .largest_acknowledged = 0,
        .first_ack_range = 0,
    });
    check("serialize_frame builds an ack payload fixture", ack_payload.has_value());

    const auto stream_payload = serialize_frame(StreamFrame{
        .has_length = true,
        .stream_id = 3,
        .stream_data = {std::byte{0x33}},
    });
    check("serialize_frame builds a stream payload fixture", stream_payload.has_value());
    check("codec_failure_offset rejects successful results",
          !codec_failure_offset(CodecResult<std::size_t>::success(7),
                                CodecErrorCode::invalid_varint, 0));
    check(
        "codec_failure_offset rejects mismatched error codes",
        !codec_failure_offset(CodecResult<std::size_t>::failure(CodecErrorCode::truncated_input, 0),
                              CodecErrorCode::invalid_varint, 0));
    check(
        "codec_failure_offset rejects mismatched offsets",
        !codec_failure_offset(CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 1),
                              CodecErrorCode::invalid_varint, 2));
    check("codec_failure rejects successful received decode results",
          !codec_failure(CodecResult<ReceivedProtectedPacketDecodeResult>::success(
                             ReceivedProtectedPacketDecodeResult{
                                 .packet = ReceivedProtectedInitialPacket{},
                                 .bytes_consumed = 0,
                             }),
                         CodecErrorCode::invalid_varint));
    check("codec_failure rejects mismatched received decode error codes",
          !codec_failure(CodecResult<ReceivedProtectedPacketDecodeResult>::failure(
                             CodecErrorCode::truncated_input, 0),
                         CodecErrorCode::invalid_varint));
    check("codec_failure rejects successful serialized datagrams",
          !codec_failure(
              CodecResult<SerializedProtectedDatagram>::success(SerializedProtectedDatagram{}),
              CodecErrorCode::invalid_varint));
    check("codec_failure rejects mismatched serialized datagram error codes",
          !codec_failure(
              CodecResult<SerializedProtectedDatagram>::failure(CodecErrorCode::truncated_input, 0),
              CodecErrorCode::invalid_varint));

    if (crypto_payload.has_value() && ping_payload.has_value() && ack_payload.has_value()) {
        const auto long_header_header = build_long_header(
            std::byte{0xc0}, kQuicVersion1, std::array{std::byte{0xaa}},
            std::array{std::byte{0xbb}}, std::array{std::byte{0xcc}},
            /*has_token=*/true,
            /*payload_length=*/1u + crypto_payload.value().size(), std::array{std::byte{0x01}});
        auto long_header_packet = long_header_header;
        append_bytes(long_header_packet, crypto_payload.value());

        const auto layout =
            locate_long_header_or_assert(long_header_packet, LongHeaderPacketType::initial);
        check("locate_long_header_or_assert finds an initial packet layout",
              layout.length_offset > 0 && layout.packet_end_offset == long_header_packet.size());

        auto patched_packet = long_header_packet;
        const auto patched =
            patch_long_header_length_field_or_assert(patched_packet, layout, layout.length_value);
        check("patch_long_header_length_field_or_assert preserves valid packet layouts",
              patched.packet_number_offset == layout.packet_number_offset &&
                  patched_packet.size() == long_header_packet.size());

        auto unprotected = RemovedLongHeaderProtection{
            .packet_bytes = long_header_packet,
            .packet_number_length = 1,
            .truncated_packet_number = 1,
        };
        const auto rebuilt_header =
            build_long_header_plaintext_header(unprotected, layout, crypto_payload.value().size());
        check("build_long_header_plaintext_header rebuilds plaintext headers",
              rebuilt_header.has_value() && rebuilt_header.value() == long_header_header);

        const auto oversized_rebuilt_header = build_long_header_plaintext_header(
            RemovedLongHeaderProtection{
                .packet_bytes =
                    {
                        std::byte{0xc0},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                    },
                .packet_number_length = 4,
                .truncated_packet_number = 0,
            },
            LongHeaderLayout{
                .length_offset = 0,
                .length_size = 1,
                .packet_number_offset = 0,
            },
            static_cast<std::size_t>(kMaxVarInt));
        check("build_long_header_plaintext_header propagates oversized patched length failures",
              codec_failure_offset(oversized_rebuilt_header, CodecErrorCode::invalid_varint, 0));

        auto invalid_length_packet = long_header_packet;
        const auto oversized_length =
            patch_long_header_length_field(invalid_length_packet, layout, kMaxVarInt + 1u);
        check("patch_long_header_length_field rejects oversized payload lengths",
              codec_failure_offset(oversized_length, CodecErrorCode::invalid_varint, 0));

        const std::array<Frame, 1> minimal_long_header_frames = {
            Frame(CryptoFrame{
                .offset = 0,
                .crypto_data = {std::byte{0x01}},
            }),
        };
        std::vector<std::byte> version_negotiation_datagram;
        check("append_protected_long_header_packet_to_datagram rejects version-negotiation packets",
              codec_failure(append_protected_long_header_packet_to_datagram(
                                version_negotiation_datagram, LongHeaderPacketType::initial,
                                kVersionNegotiationVersion, ConnectionId{std::byte{0xaa}}, {}, {},
                                TruncatedPacketNumberEncoding{
                                    .packet_number_length = 1,
                                    .truncated_packet_number = 0,
                                },
                                0, minimal_long_header_frames, kInitialCipherSuite,
                                PacketProtectionKeys{}),
                            CodecErrorCode::unsupported_packet_type));

        const auto one_rtt_plaintext = to_plaintext_one_rtt(ProtectedOneRttPacket{
            .spin_bit = true,
            .key_phase = false,
            .destination_connection_id = {std::byte{0xde}, std::byte{0xad}},
            .packet_number_length = 2,
            .packet_number = 0x1234,
            .frames = {PingFrame{}},
        });
        check("to_plaintext_one_rtt accepts valid packet number lengths",
              one_rtt_plaintext.has_value() &&
                  one_rtt_plaintext.value().truncated_packet_number == 0x1234u);

        const auto invalid_one_rtt_plaintext = to_plaintext_one_rtt(ProtectedOneRttPacket{
            .destination_connection_id = {std::byte{0xde}},
            .packet_number_length = 0,
            .packet_number = 1,
            .frames = {PingFrame{}},
        });
        check("to_plaintext_one_rtt rejects invalid packet number lengths",
              codec_failure_offset(invalid_one_rtt_plaintext, CodecErrorCode::invalid_varint, 0));

        check("decode_received_long_header_packet_fields rejects empty headers",
              codec_failure_offset(decode_received_long_header_packet_fields(
                                       {}, SharedBytes(crypto_payload.value()),
                                       ProtectedPayloadPacketType::initial, true),
                                   CodecErrorCode::truncated_input, 0));

        const std::array missing_fixed_long_header = {
            std::byte{0x80},
        };
        check("decode_received_long_header_packet_fields rejects missing fixed bits",
              codec_failure(decode_received_long_header_packet_fields(
                                missing_fixed_long_header, SharedBytes(crypto_payload.value()),
                                ProtectedPayloadPacketType::initial, true),
                            CodecErrorCode::invalid_fixed_bit));

        const std::array reserved_long_header = {
            std::byte{0xcc},
        };
        check("decode_received_long_header_packet_fields rejects reserved bits",
              codec_failure(decode_received_long_header_packet_fields(
                                reserved_long_header, SharedBytes(crypto_payload.value()),
                                ProtectedPayloadPacketType::initial, true),
                            CodecErrorCode::invalid_reserved_bits));

        const std::array truncated_version_long_header = {
            std::byte{0xc0},
        };
        check("decode_received_long_header_packet_fields rejects truncated version bytes",
              codec_failure(decode_received_long_header_packet_fields(
                                truncated_version_long_header, SharedBytes(crypto_payload.value()),
                                ProtectedPayloadPacketType::initial, true),
                            CodecErrorCode::truncated_input));

        {
            std::vector<std::byte> header{std::byte{0xc0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x15});
            check("decode_received_long_header_packet_fields rejects oversized destination "
                  "connection ids",
                  codec_failure(decode_received_long_header_packet_fields(
                                    header, SharedBytes(crypto_payload.value()),
                                    ProtectedPayloadPacketType::initial, true),
                                CodecErrorCode::invalid_varint));
        }

        {
            std::vector<std::byte> header{std::byte{0xc0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xaa});
            header.push_back(std::byte{0x15});
            check(
                "decode_received_long_header_packet_fields rejects oversized source connection ids",
                codec_failure(decode_received_long_header_packet_fields(
                                  header, SharedBytes(crypto_payload.value()),
                                  ProtectedPayloadPacketType::initial, true),
                              CodecErrorCode::invalid_varint));
        }

        {
            std::vector<std::byte> header{std::byte{0xc0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xaa});
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xbb});
            header.push_back(std::byte{0x40});
            check("decode_received_long_header_packet_fields propagates malformed token lengths",
                  codec_failure(decode_received_long_header_packet_fields(
                                    header, SharedBytes(crypto_payload.value()),
                                    ProtectedPayloadPacketType::initial, true),
                                CodecErrorCode::truncated_input));
        }

        {
            std::vector<std::byte> header{std::byte{0xc0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xaa});
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xbb});
            static_cast<void>(append_varint(header, 2u));
            check("decode_received_long_header_packet_fields rejects token lengths longer than the "
                  "remaining header",
                  codec_failure(decode_received_long_header_packet_fields(
                                    header, SharedBytes(crypto_payload.value()),
                                    ProtectedPayloadPacketType::initial, true),
                                CodecErrorCode::packet_length_mismatch));
        }

        {
            std::vector<std::byte> header{std::byte{0xd0}};
            append_u32_be(header, kQuicVersion1);
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xaa});
            header.push_back(std::byte{0x01});
            header.push_back(std::byte{0xbb});
            header.push_back(std::byte{0x40});
            check("decode_received_long_header_packet_fields propagates malformed payload lengths",
                  codec_failure(decode_received_long_header_packet_fields(
                                    header, SharedBytes(ping_payload.value()),
                                    ProtectedPayloadPacketType::zero_rtt, false),
                                CodecErrorCode::truncated_input));
        }

        {
            auto header =
                build_long_header(std::byte{0xd1}, kQuicVersion1, std::array{std::byte{0xaa}},
                                  std::array{std::byte{0xbb}}, {},
                                  /*has_token=*/false,
                                  /*payload_length=*/3u, std::array{std::byte{0x01}});
            check("decode_received_long_header_packet_fields rejects truncated packet number bytes",
                  codec_failure(decode_received_long_header_packet_fields(
                                    header, SharedBytes(ping_payload.value()),
                                    ProtectedPayloadPacketType::zero_rtt, false),
                                CodecErrorCode::truncated_input));
        }

        {
            auto header =
                build_long_header(std::byte{0xc0}, kQuicVersion1, std::array{std::byte{0xaa}},
                                  std::array{std::byte{0xbb}}, std::array{std::byte{0xcc}},
                                  /*has_token=*/true,
                                  /*payload_length=*/1u, std::array{std::byte{0x01}});
            check("decode_received_long_header_packet_fields rejects payload length mismatches",
                  codec_failure(decode_received_long_header_packet_fields(
                                    header, SharedBytes(crypto_payload.value()),
                                    ProtectedPayloadPacketType::initial, true),
                                CodecErrorCode::packet_length_mismatch));
        }

        {
            auto header = build_long_header(
                std::byte{0xd0}, kQuicVersion1, std::array{std::byte{0xaa}},
                std::array{std::byte{0xbb}}, {},
                /*has_token=*/false,
                /*payload_length=*/1u + ack_payload.value().size(), std::array{std::byte{0x01}});
            check("decode_received_long_header_packet_fields rejects frames forbidden in zero-rtt "
                  "payloads",
                  codec_failure(decode_received_long_header_packet_fields(
                                    header, SharedBytes(ack_payload.value()),
                                    ProtectedPayloadPacketType::zero_rtt, false),
                                CodecErrorCode::frame_not_allowed_in_packet_type));
        }

        const auto decoded_long_header = decode_received_long_header_packet_fields(
            long_header_header, SharedBytes(crypto_payload.value()),
            ProtectedPayloadPacketType::initial, true);
        bool decoded_long_header_ok =
            decoded_long_header.has_value() &&
            decoded_long_header.value().version == kQuicVersion1 &&
            decoded_long_header.value().destination_connection_id ==
                ConnectionId{std::byte{0xaa}} &&
            decoded_long_header.value().source_connection_id == ConnectionId{std::byte{0xbb}} &&
            decoded_long_header.value().token == std::vector<std::byte>{std::byte{0xcc}} &&
            decoded_long_header.value().packet_number_length == 1 &&
            decoded_long_header.value().frames.size() == 1;
        if (decoded_long_header_ok) {
            const auto *crypto =
                std::get_if<ReceivedCryptoFrame>(&decoded_long_header.value().frames.front());
            decoded_long_header_ok = crypto != nullptr && crypto->offset == 0 &&
                                     crypto->crypto_data == std::vector<std::byte>{std::byte{0x42}};
        }
        check("decode_received_long_header_packet_fields accepts valid initial plaintext headers",
              decoded_long_header_ok);

        check("codec_failure_offset rejects successful short-header decode results",
              !codec_failure_offset(CodecResult<ReceivedShortHeaderPacketFields>::success(
                                        ReceivedShortHeaderPacketFields{
                                            .packet_number_length = 1,
                                        }),
                                    CodecErrorCode::truncated_input, 0));
        check("codec_failure_offset rejects mismatched short-header decode error codes",
              !codec_failure_offset(CodecResult<ReceivedShortHeaderPacketFields>::failure(
                                        CodecErrorCode::invalid_fixed_bit, 0),
                                    CodecErrorCode::truncated_input, 0));
        check("codec_failure_offset rejects mismatched short-header decode offsets",
              !codec_failure_offset(CodecResult<ReceivedShortHeaderPacketFields>::failure(
                                        CodecErrorCode::truncated_input, 1),
                                    CodecErrorCode::truncated_input, 0));
        check("codec_failure rejects successful short-header decode results",
              !codec_failure(CodecResult<ReceivedShortHeaderPacketFields>::success(
                                 ReceivedShortHeaderPacketFields{
                                     .packet_number_length = 1,
                                 }),
                             CodecErrorCode::truncated_input));
        check("codec_failure rejects mismatched short-header decode error codes",
              !codec_failure(CodecResult<ReceivedShortHeaderPacketFields>::failure(
                                 CodecErrorCode::invalid_fixed_bit, 0),
                             CodecErrorCode::truncated_input));
        check("decode_received_short_header_packet_fields rejects empty headers",
              codec_failure_offset(
                  decode_received_short_header_packet_fields({}, SharedBytes(ping_payload.value())),
                  CodecErrorCode::truncated_input, 0));

        const std::array missing_fixed_short_header = {
            std::byte{0x01},
        };
        check("decode_received_short_header_packet_fields rejects missing fixed bits",
              codec_failure(decode_received_short_header_packet_fields(
                                missing_fixed_short_header, SharedBytes(ping_payload.value())),
                            CodecErrorCode::invalid_fixed_bit));

        const std::array reserved_short_header = {
            std::byte{0x59},
        };
        check("decode_received_short_header_packet_fields rejects reserved bits",
              codec_failure(decode_received_short_header_packet_fields(
                                reserved_short_header, SharedBytes(ping_payload.value())),
                            CodecErrorCode::invalid_reserved_bits));

        const std::array truncated_packet_number_short_header = {
            std::byte{0x41},
        };
        check("decode_received_short_header_packet_fields rejects headers shorter than the packet "
              "number",
              codec_failure(
                  decode_received_short_header_packet_fields(truncated_packet_number_short_header,
                                                             SharedBytes(ping_payload.value())),
                  CodecErrorCode::packet_length_mismatch));

        const std::array empty_payload_short_header = {
            std::byte{0x41},
            std::byte{0xaa},
            std::byte{0x01},
            std::byte{0x02},
        };
        check("decode_received_short_header_packet_fields propagates payload decode failures",
              codec_failure(decode_received_short_header_packet_fields(empty_payload_short_header,
                                                                       SharedBytes{}),
                            CodecErrorCode::empty_packet_payload));

        const std::array valid_short_header = {
            std::byte{0x65}, std::byte{0xaa}, std::byte{0xbb}, std::byte{0x01}, std::byte{0x02},
        };
        const auto decoded_short_header = decode_received_short_header_packet_fields(
            valid_short_header, SharedBytes(ping_payload.value()));
        check("decode_received_short_header_packet_fields accepts valid one-rtt plaintext headers",
              decoded_short_header.has_value() && decoded_short_header.value().spin_bit &&
                  decoded_short_header.value().key_phase &&
                  decoded_short_header.value().destination_connection_id ==
                      ConnectionId{
                          std::byte{0xaa},
                          std::byte{0xbb},
                      } &&
                  decoded_short_header.value().packet_number_length == 2 &&
                  decoded_short_header.value().frames.size() == 1 &&
                  std::holds_alternative<PingFrame>(decoded_short_header.value().frames.front()));
    }

    {
        std::vector<std::byte> padded_plaintext{std::byte{0xaa}};
        pad_short_header_plaintext_for_header_protection(padded_plaintext, 2);
        check("pad_short_header_plaintext_for_header_protection extends short payloads with zeros",
              padded_plaintext.size() == 6 && padded_plaintext.back() == std::byte{0x00});

        std::vector<std::byte> unchanged_plaintext(6, std::byte{0xbb});
        pad_short_header_plaintext_for_header_protection(unchanged_plaintext, 2);
        check("pad_short_header_plaintext_for_header_protection leaves already-large payloads "
              "unchanged",
              unchanged_plaintext == std::vector<std::byte>(6, std::byte{0xbb}));
    }

    {
        const auto shared_storage = std::make_shared<std::vector<std::byte>>(std::vector<std::byte>{
            std::byte{0x10},
            std::byte{0x11},
            std::byte{0x12},
        });
        const std::array valid_views = {
            StreamFrameView{
                .stream_id = 7,
                .offset = 1,
                .storage = shared_storage,
                .begin = 0,
                .end = 2,
            },
        };
        const auto view_wire_size = packet_stream_payload_wire_size(
            ProtectedOneRttPacketView{
                .destination_connection_id = {},
                .packet_number_length = 2,
                .packet_number = 0,
                .frames = {},
                .stream_frame_views = valid_views,
            },
            /*frame_index_base=*/5);
        check("packet_stream_payload_wire_size sums valid stream frame view payloads",
              view_wire_size.has_value() &&
                  view_wire_size.value() == encoded_stream_frame_payload_size(/*stream_id=*/7,
                                                                              /*offset=*/1,
                                                                              /*payload_size=*/2));

        const std::array invalid_views = {
            StreamFrameView{
                .stream_id = 7,
                .offset = 1,
                .begin = 2,
                .end = 1,
            },
        };
        check("packet_stream_payload_wire_size rejects inverted stream frame view ranges",
              codec_failure_offset(packet_stream_payload_wire_size(
                                       ProtectedOneRttPacketView{
                                           .destination_connection_id = {},
                                           .packet_number_length = 2,
                                           .packet_number = 0,
                                           .frames = {},
                                           .stream_frame_views = invalid_views,
                                       },
                                       /*frame_index_base=*/5),
                                   CodecErrorCode::invalid_varint, 5));

        const std::array oversized_storage_views = {
            StreamFrameView{
                .stream_id = 7,
                .offset = 1,
                .storage = shared_storage,
                .begin = 0,
                .end = 4,
            },
        };
        const auto oversized_storage_wire_size = packet_stream_payload_wire_size(
            ProtectedOneRttPacketView{
                .destination_connection_id = {},
                .packet_number_length = 2,
                .packet_number = 0,
                .frames = {},
                .stream_frame_views = oversized_storage_views,
            },
            /*frame_index_base=*/5);
        check("packet_stream_payload_wire_size sizes stream frame views from declared ranges",
              oversized_storage_wire_size.has_value() &&
                  oversized_storage_wire_size.value() ==
                      encoded_stream_frame_payload_size(/*stream_id=*/7, /*offset=*/1,
                                                        /*payload_size=*/4));

        const std::array valid_fragments = {
            StreamFrameSendFragment{
                .stream_id = 9,
                .offset = 3,
                .bytes =
                    SharedBytes{
                        std::byte{0xaa},
                        std::byte{0xbb},
                    },
            },
        };
        const auto fragment_wire_size = packet_stream_payload_wire_size(
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = {},
                .packet_number_length = 2,
                .packet_number = 0,
                .frames = {},
                .stream_fragments = valid_fragments,
            },
            /*frame_index_base=*/9);
        check("packet_stream_payload_wire_size sums valid stream fragment payloads",
              fragment_wire_size.has_value() &&
                  fragment_wire_size.value() == valid_fragments.front().stream_frame_wire_size());

        const std::array invalid_fragments = {
            StreamFrameSendFragment{
                .stream_id = 9,
                .offset = kMaxVarInt,
                .bytes =
                    SharedBytes{
                        std::byte{0xaa},
                    },
            },
        };
        check("packet_stream_payload_wire_size rejects overflowing stream fragment offsets",
              codec_failure_offset(packet_stream_payload_wire_size(
                                       ProtectedOneRttPacketFragmentView{
                                           .destination_connection_id = {},
                                           .packet_number_length = 2,
                                           .packet_number = 0,
                                           .frames = {},
                                           .stream_fragments = invalid_fragments,
                                       },
                                       /*frame_index_base=*/9),
                                   CodecErrorCode::invalid_varint, 9));
    }

    {
        const auto initial_packet = ProtectedInitialPacket{
            .version = kQuicVersion1,
            .destination_connection_id =
                {
                    std::byte{0x83},
                    std::byte{0x94},
                },
            .source_connection_id = {std::byte{0xc1}},
            .token = {std::byte{0x55}},
            .packet_number_length = 2,
            .packet_number = 7,
            .frames =
                {
                    CryptoFrame{
                        .offset = 0,
                        .crypto_data = {std::byte{0x01}},
                    },
                },
        };
        const auto initial_bytes = serialize_protected_initial_packet(
            initial_packet, SerializeProtectionContext{
                                .local_role = EndpointRole::client,
                                .client_initial_destination_connection_id =
                                    initial_packet.destination_connection_id,
                            });
        check("serialize_protected_initial_packet builds a received decode fixture",
              initial_bytes.has_value());
        if (initial_bytes.has_value()) {
            check("deserialize_received_protected_initial_packet rejects missing receive context",
                  codec_failure(deserialize_received_protected_initial_packet(
                                    initial_bytes.value(),
                                    DeserializeProtectionContext{
                                        .peer_role = EndpointRole::client,
                                    }),
                                CodecErrorCode::missing_crypto_context));

            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch};
                check("deserialize_received_protected_initial_packet propagates header protection "
                      "failures",
                      codec_failure(deserialize_received_protected_initial_packet(
                                        initial_bytes.value(),
                                        DeserializeProtectionContext{
                                            .peer_role = EndpointRole::client,
                                            .client_initial_destination_connection_id =
                                                initial_packet.destination_connection_id,
                                        }),
                                    CodecErrorCode::packet_length_mismatch));
            }

            const auto initial_keys = derive_initial_packet_keys(
                EndpointRole::client, true, initial_packet.destination_connection_id,
                initial_packet.version);
            check("derive_initial_packet_keys builds a malformed initial payload fixture",
                  initial_keys.has_value());
            if (initial_keys.has_value()) {
                const auto empty_payload_initial = build_received_long_header_packet_for_tests(
                    LongHeaderPacketType::initial, initial_packet.version,
                    initial_packet.destination_connection_id, initial_packet.source_connection_id,
                    initial_packet.token, true, initial_packet.packet_number_length, 21,
                    stream_payload.value(), kInitialCipherSuite, initial_keys.value());
                check("build_received_long_header_packet_for_tests creates a malformed initial "
                      "payload fixture",
                      empty_payload_initial.has_value());
                if (empty_payload_initial.has_value()) {
                    check("deserialize_received_protected_initial_packet rejects forbidden "
                          "decrypted stream frames",
                          codec_failure(deserialize_received_protected_initial_packet(
                                            empty_payload_initial.value(),
                                            DeserializeProtectionContext{
                                                .peer_role = EndpointRole::client,
                                                .client_initial_destination_connection_id =
                                                    initial_packet.destination_connection_id,
                                            }),
                                        CodecErrorCode::frame_not_allowed_in_packet_type));
                }
            }

            const auto decoded = deserialize_received_protected_initial_packet(
                initial_bytes.value(), DeserializeProtectionContext{
                                           .peer_role = EndpointRole::client,
                                           .client_initial_destination_connection_id =
                                               initial_packet.destination_connection_id,
                                       });
            bool decoded_ok = decoded.has_value() && decoded.value().bytes_consumed > 0;
            if (decoded_ok) {
                const auto *packet =
                    std::get_if<ReceivedProtectedInitialPacket>(&decoded.value().packet);
                decoded_ok = packet != nullptr &&
                             packet->packet_number == initial_packet.packet_number &&
                             packet->plaintext_storage != nullptr && packet->frames.size() == 1;
            }
            check("deserialize_received_protected_initial_packet decodes valid packets",
                  decoded_ok);
        }
    }

    {
        const auto handshake_secret = TrafficSecret{
            .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
            .secret = make_secret_bytes(32, 0x20),
        };
        const auto handshake_packet = ProtectedHandshakePacket{
            .version = kQuicVersion1,
            .destination_connection_id =
                {
                    std::byte{0xaa},
                    std::byte{0xbb},
                },
            .source_connection_id = {std::byte{0xcc}},
            .packet_number_length = 2,
            .packet_number = 9,
            .frames =
                {
                    CryptoFrame{
                        .offset = 0,
                        .crypto_data = {std::byte{0x11}, std::byte{0x22}},
                    },
                },
        };
        const auto handshake_bytes = serialize_protected_handshake_packet(
            handshake_packet, SerializeProtectionContext{
                                  .local_role = EndpointRole::client,
                                  .handshake_secret = handshake_secret,
                              });
        check("serialize_protected_handshake_packet builds a received decode fixture",
              handshake_bytes.has_value());
        if (handshake_bytes.has_value()) {
            check(
                "deserialize_received_protected_handshake_packet rejects missing handshake secrets",
                codec_failure(deserialize_received_protected_handshake_packet(
                                  handshake_bytes.value(),
                                  DeserializeProtectionContext{
                                      .peer_role = EndpointRole::client,
                                  }),
                              CodecErrorCode::missing_crypto_context));

            check("deserialize_received_protected_handshake_packet propagates secret expansion "
                  "failures",
                  codec_failure(deserialize_received_protected_handshake_packet(
                                    handshake_bytes.value(),
                                    DeserializeProtectionContext{
                                        .peer_role = EndpointRole::client,
                                        .handshake_secret =
                                            TrafficSecret{
                                                .cipher_suite = invalid_cipher_suite(),
                                                .secret = make_secret_bytes(32, 0x21),
                                            },
                                    }),
                                CodecErrorCode::unsupported_cipher_suite));

            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch};
                check("deserialize_received_protected_handshake_packet propagates header "
                      "protection failures",
                      codec_failure(deserialize_received_protected_handshake_packet(
                                        handshake_bytes.value(),
                                        DeserializeProtectionContext{
                                            .peer_role = EndpointRole::client,
                                            .handshake_secret = handshake_secret,
                                        }),
                                    CodecErrorCode::packet_length_mismatch));
            }

            const auto handshake_keys = expand_traffic_secret_cached(handshake_secret);
            check("expand_traffic_secret_cached builds a malformed handshake payload fixture",
                  handshake_keys.has_value());
            if (handshake_keys.has_value()) {
                const auto empty_payload_handshake = build_received_long_header_packet_for_tests(
                    LongHeaderPacketType::handshake, handshake_packet.version,
                    handshake_packet.destination_connection_id,
                    handshake_packet.source_connection_id, {}, false,
                    handshake_packet.packet_number_length, 23, stream_payload.value(),
                    handshake_secret.cipher_suite, handshake_keys.value().get());
                check("build_received_long_header_packet_for_tests creates a malformed handshake "
                      "payload fixture",
                      empty_payload_handshake.has_value());
                if (empty_payload_handshake.has_value()) {
                    check("deserialize_received_protected_handshake_packet rejects forbidden "
                          "decrypted stream frames",
                          codec_failure(deserialize_received_protected_handshake_packet(
                                            empty_payload_handshake.value(),
                                            DeserializeProtectionContext{
                                                .peer_role = EndpointRole::client,
                                                .handshake_secret = handshake_secret,
                                            }),
                                        CodecErrorCode::frame_not_allowed_in_packet_type));
                }
            }

            const auto decoded = deserialize_received_protected_handshake_packet(
                handshake_bytes.value(), DeserializeProtectionContext{
                                             .peer_role = EndpointRole::client,
                                             .handshake_secret = handshake_secret,
                                         });
            bool decoded_ok = decoded.has_value() && decoded.value().bytes_consumed > 0;
            if (decoded_ok) {
                const auto *packet =
                    std::get_if<ReceivedProtectedHandshakePacket>(&decoded.value().packet);
                decoded_ok = packet != nullptr &&
                             packet->packet_number == handshake_packet.packet_number &&
                             packet->plaintext_storage != nullptr && packet->frames.size() == 1;
            }
            check("deserialize_received_protected_handshake_packet decodes valid packets",
                  decoded_ok);
        }
    }

    {
        const auto zero_rtt_secret = TrafficSecret{
            .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
            .secret = make_secret_bytes(32, 0x40),
        };
        const auto zero_rtt_packet = ProtectedZeroRttPacket{
            .version = kQuicVersion1,
            .destination_connection_id =
                {
                    std::byte{0xaa},
                    std::byte{0xbb},
                },
            .source_connection_id = {std::byte{0xcc}},
            .packet_number_length = 2,
            .packet_number = 11,
            .frames = {PingFrame{}},
        };
        const auto zero_rtt_bytes = serialize_protected_zero_rtt_packet(
            zero_rtt_packet, SerializeProtectionContext{
                                 .local_role = EndpointRole::client,
                                 .zero_rtt_secret = zero_rtt_secret,
                             });
        check("serialize_protected_zero_rtt_packet builds a received decode fixture",
              zero_rtt_bytes.has_value());
        if (zero_rtt_bytes.has_value()) {
            check("deserialize_received_protected_zero_rtt_packet rejects missing zero-rtt secrets",
                  codec_failure(deserialize_received_protected_zero_rtt_packet(
                                    zero_rtt_bytes.value(),
                                    DeserializeProtectionContext{
                                        .peer_role = EndpointRole::client,
                                    }),
                                CodecErrorCode::missing_crypto_context));

            check("deserialize_received_protected_zero_rtt_packet propagates secret expansion "
                  "failures",
                  codec_failure(deserialize_received_protected_zero_rtt_packet(
                                    zero_rtt_bytes.value(),
                                    DeserializeProtectionContext{
                                        .peer_role = EndpointRole::client,
                                        .zero_rtt_secret =
                                            TrafficSecret{
                                                .cipher_suite = invalid_cipher_suite(),
                                                .secret = make_secret_bytes(32, 0x41),
                                            },
                                    }),
                                CodecErrorCode::unsupported_cipher_suite));

            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch};
                check("deserialize_received_protected_zero_rtt_packet propagates header protection "
                      "failures",
                      codec_failure(deserialize_received_protected_zero_rtt_packet(
                                        zero_rtt_bytes.value(),
                                        DeserializeProtectionContext{
                                            .peer_role = EndpointRole::client,
                                            .zero_rtt_secret = zero_rtt_secret,
                                        }),
                                    CodecErrorCode::packet_length_mismatch));
            }

            const auto zero_rtt_keys = expand_traffic_secret_cached(zero_rtt_secret);
            check("expand_traffic_secret_cached builds a malformed zero-rtt payload fixture",
                  zero_rtt_keys.has_value());
            if (zero_rtt_keys.has_value()) {
                const auto empty_payload_zero_rtt = build_received_long_header_packet_for_tests(
                    LongHeaderPacketType::zero_rtt, zero_rtt_packet.version,
                    zero_rtt_packet.destination_connection_id, zero_rtt_packet.source_connection_id,
                    {}, false, zero_rtt_packet.packet_number_length, 25, ack_payload.value(),
                    zero_rtt_secret.cipher_suite, zero_rtt_keys.value().get());
                check("build_received_long_header_packet_for_tests creates a malformed zero-rtt "
                      "payload fixture",
                      empty_payload_zero_rtt.has_value());
                if (empty_payload_zero_rtt.has_value()) {
                    check("deserialize_received_protected_zero_rtt_packet rejects forbidden "
                          "decrypted stream frames",
                          codec_failure(deserialize_received_protected_zero_rtt_packet(
                                            empty_payload_zero_rtt.value(),
                                            DeserializeProtectionContext{
                                                .peer_role = EndpointRole::client,
                                                .zero_rtt_secret = zero_rtt_secret,
                                            }),
                                        CodecErrorCode::frame_not_allowed_in_packet_type));
                }
            }

            const auto decoded = deserialize_received_protected_zero_rtt_packet(
                zero_rtt_bytes.value(), DeserializeProtectionContext{
                                            .peer_role = EndpointRole::client,
                                            .zero_rtt_secret = zero_rtt_secret,
                                        });
            bool decoded_ok = decoded.has_value() && decoded.value().bytes_consumed > 0;
            if (decoded_ok) {
                const auto *packet =
                    std::get_if<ReceivedProtectedZeroRttPacket>(&decoded.value().packet);
                decoded_ok = packet != nullptr && packet->plaintext_storage != nullptr;
            }
            check("deserialize_received_protected_zero_rtt_packet decodes valid packets",
                  decoded_ok);
        }
    }

    {
        const auto one_rtt_secret = TrafficSecret{
            .cipher_suite = CipherSuite::tls_aes_128_gcm_sha256,
            .secret = make_secret_bytes(32, 0x60),
        };
        const ConnectionId destination_connection_id = {
            std::byte{0xde},
            std::byte{0xad},
            std::byte{0xbe},
            std::byte{0xef},
        };
        const auto one_rtt_context = SerializeProtectionContext{
            .local_role = EndpointRole::client,
            .client_initial_destination_connection_id = {std::byte{0x83}},
            .one_rtt_secret = one_rtt_secret,
            .one_rtt_key_phase = false,
        };
        const auto one_rtt_receive_context = DeserializeProtectionContext{
            .peer_role = EndpointRole::client,
            .one_rtt_secret = one_rtt_secret,
            .one_rtt_destination_connection_id_length = destination_connection_id.size(),
        };
        const auto one_rtt_packet_bytes = serialize_protected_datagram(
            std::array<ProtectedPacket, 1>{ProtectedPacket{ProtectedOneRttPacket{
                .spin_bit = false,
                .key_phase = false,
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 12,
                .frames = {PingFrame{}},
            }}},
            one_rtt_context);
        check("serialize_protected_datagram builds a received one-rtt fixture",
              one_rtt_packet_bytes.has_value());
        if (one_rtt_packet_bytes.has_value()) {
            {
                const ScopedProtectedCodecFaultInjector injector{
                    ProtectedCodecFaultPoint::remove_short_header_packet_length_mismatch};
                check("deserialize_received_protected_one_rtt_packet propagates header protection "
                      "failures",
                      codec_failure(deserialize_received_protected_one_rtt_packet(
                                        one_rtt_packet_bytes.value(), one_rtt_receive_context),
                                    CodecErrorCode::packet_length_mismatch));
            }

            auto wrong_one_rtt_secret = one_rtt_secret;
            wrong_one_rtt_secret.secret.back() ^= std::byte{0xff};
            check("deserialize_received_protected_one_rtt_packet rejects packets encrypted with "
                  "different secrets",
                  codec_failure(deserialize_received_protected_one_rtt_packet(
                                    one_rtt_packet_bytes.value(),
                                    DeserializeProtectionContext{
                                        .peer_role = EndpointRole::client,
                                        .one_rtt_secret = wrong_one_rtt_secret,
                                        .one_rtt_destination_connection_id_length =
                                            destination_connection_id.size(),
                                    }),
                                CodecErrorCode::packet_decryption_failed));
        }

        const auto one_rtt_keys = expand_traffic_secret_cached(one_rtt_secret);
        check("expand_traffic_secret_cached builds a malformed one-rtt payload fixture",
              one_rtt_keys.has_value());
        if (one_rtt_keys.has_value()) {
            const std::array malformed_one_rtt_payload = {
                std::byte{0x02},
                std::byte{0x00},
            };
            const auto empty_payload_one_rtt = build_received_one_rtt_packet_for_tests(
                false, false, destination_connection_id, 2, 29, malformed_one_rtt_payload,
                one_rtt_secret.cipher_suite, one_rtt_keys.value().get());
            check("build_received_one_rtt_packet_for_tests creates a malformed one-rtt payload "
                  "fixture",
                  empty_payload_one_rtt.has_value());
            if (empty_payload_one_rtt.has_value()) {
                check("deserialize_received_protected_one_rtt_packet propagates decrypted payload "
                      "decode failures",
                      codec_failure(deserialize_received_protected_one_rtt_packet(
                                        empty_payload_one_rtt.value(), one_rtt_receive_context),
                                    CodecErrorCode::truncated_input));
            }
        }

        std::vector<StreamFrameSendFragment> chunk_fragments{
            StreamFrameSendFragment{
                .stream_id = 1,
                .offset = 0,
                .bytes =
                    SharedBytes{
                        std::byte{0x01},
                    },
            },
            StreamFrameSendFragment{
                .stream_id = 3,
                .offset = 0,
                .bytes =
                    SharedBytes{
                        std::byte{0x02},
                    },
            },
        };
        DatagramBuffer chunk_datagram;
        const auto chunk_appended = append_protected_one_rtt_packet_to_datagram_impl(
            chunk_datagram,
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 13,
                .frames = {},
                .stream_fragments = chunk_fragments,
            },
            one_rtt_context);
        check("append_protected_one_rtt_packet_to_datagram_impl chunk-seals multiple fragments",
              chunk_appended.has_value() && chunk_appended.value() == chunk_datagram.size() &&
                  !chunk_datagram.empty());

        const std::array<Frame, 1> chunk_prefix_frames = {
            Frame(PingFrame{}),
        };
        DatagramBuffer chunk_with_prefix_datagram;
        const auto chunk_with_prefix_appended = append_protected_one_rtt_packet_to_datagram_impl(
            chunk_with_prefix_datagram,
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 17,
                .frames = chunk_prefix_frames,
                .stream_fragments = chunk_fragments,
            },
            one_rtt_context);
        check("append_protected_one_rtt_packet_to_datagram_impl chunk-seals fragments after prefix "
              "frames",
              chunk_with_prefix_appended.has_value() &&
                  chunk_with_prefix_appended.value() == chunk_with_prefix_datagram.size() &&
                  !chunk_with_prefix_datagram.empty());

        std::vector<StreamFrameSendFragment> fallback_fragments;
        fallback_fragments.reserve(17);
        for (std::uint64_t stream_id = 0; stream_id < 17; ++stream_id) {
            fallback_fragments.push_back(StreamFrameSendFragment{
                .stream_id = stream_id,
                .offset = 0,
                .bytes =
                    SharedBytes{
                        std::byte{static_cast<std::uint8_t>(stream_id)},
                    },
            });
        }
        DatagramBuffer fallback_datagram;
        const auto fallback_appended = append_protected_one_rtt_packet_to_datagram_impl(
            fallback_datagram,
            ProtectedOneRttPacketFragmentView{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 14,
                .frames = {},
                .stream_fragments = fallback_fragments,
            },
            one_rtt_context);
        check("append_protected_one_rtt_packet_to_datagram_impl falls back to serializing many "
              "fragments",
              fallback_appended.has_value() &&
                  fallback_appended.value() == fallback_datagram.size() &&
                  !fallback_datagram.empty());

        const std::array invalid_views = {
            StreamFrameView{
                .stream_id = 5,
                .offset = 0,
                .begin = 0,
                .end = 1,
            },
        };
        DatagramBuffer invalid_view_datagram;
        check("append_protected_one_rtt_packet_to_datagram_impl propagates stream view "
              "serialization failures",
              codec_failure_offset(append_protected_one_rtt_packet_to_datagram_impl(
                                       invalid_view_datagram,
                                       ProtectedOneRttPacketView{
                                           .destination_connection_id = destination_connection_id,
                                           .packet_number_length = 2,
                                           .packet_number = 15,
                                           .frames = {},
                                           .stream_frame_views = invalid_views,
                                       },
                                       one_rtt_context),
                                   CodecErrorCode::invalid_varint, 0));

        const auto base_failure = serialize_protected_datagram_with_metadata(
            std::array<ProtectedPacket, 1>{ProtectedInitialPacket{
                .version = kQuicVersion1,
                .destination_connection_id = {std::byte{0x83}},
                .packet_number_length = 1,
                .packet_number = 0,
                .frames = {},
            }},
            ProtectedPacket{ProtectedInitialPacket{
                .version = kQuicVersion1,
                .destination_connection_id = {std::byte{0x83}},
                .packet_number_length = 1,
                .packet_number = 1,
                .frames =
                    {
                        CryptoFrame{
                            .offset = 0,
                            .crypto_data = {std::byte{0x01}},
                        },
                    },
            }},
            one_rtt_context);
        check("serialize_protected_datagram_with_metadata reports prefix serialization failures "
              "before appending",
              codec_failure(base_failure, CodecErrorCode::empty_packet_payload));

        const auto appended_failure = serialize_protected_datagram_with_metadata(
            std::array<ProtectedPacket, 1>{ProtectedInitialPacket{
                .version = kQuicVersion1,
                .destination_connection_id = {std::byte{0x83}},
                .packet_number_length = 1,
                .packet_number = 0,
                .frames =
                    {
                        CryptoFrame{
                            .offset = 0,
                            .crypto_data = {std::byte{0x01}},
                        },
                    },
            }},
            ProtectedPacket{ProtectedOneRttPacket{
                .key_phase = true,
                .destination_connection_id = destination_connection_id,
                .packet_number_length = 2,
                .packet_number = 16,
                .frames = {PingFrame{}},
            }},
            one_rtt_context);
        check("serialize_protected_datagram_with_metadata reports appended packet serialization "
              "failures",
              codec_failure(appended_failure, CodecErrorCode::invalid_packet_protection_state));
    }

    return ok;
}

} // namespace coquic::quic::test
