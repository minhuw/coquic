#include "src/quic/protected_codec.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
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
    const auto frame_index = frame.index();
    if (packet_type == LongHeaderPacketType::zero_rtt) {
        const auto forbidden_in_zero_rtt = (frame_index == 2) | (frame_index == 5) |
                                           (frame_index == 20) | (frame_index == 6) |
                                           (frame_index == 17) | (frame_index == 15);
        return !forbidden_in_zero_rtt;
    }

    return (frame_index == 0) | (frame_index == 1) | (frame_index == 2) | (frame_index == 5) |
           (frame_index == 18);
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

CodecResult<std::vector<ReceivedFrame>>
deserialize_received_frame_sequence(SharedBytes payload, ProtectedPayloadPacketType packet_type,
                                    std::size_t base_offset) {
    if (payload.empty()) {
        return CodecResult<std::vector<ReceivedFrame>>::failure(
            CodecErrorCode::empty_packet_payload, base_offset);
    }

    std::vector<ReceivedFrame> frames;
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const auto decoded = deserialize_received_frame(payload.subspan(offset));
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
                                          SharedBytes plaintext_payload,
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

    const auto frames =
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
                                           SharedBytes plaintext_payload) {
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

    const auto frames = deserialize_received_frame_sequence(
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
    const auto plaintext = open_payload(OpenPayloadInput{
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

    const auto decoded_fields = decode_received_long_header_packet_fields(
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
        const auto written = serialize_frame_into(payload_bytes.subspan(payload_offset), frame);
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

    const auto plaintext = open_payload(OpenPayloadInput{
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

    const auto plaintext = open_payload(OpenPayloadInput{
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
    const auto plaintext = open_payload(OpenPayloadInput{
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
append_protected_one_rtt_packet_to_datagram_impl(std::vector<std::byte> &datagram,
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
                    serialize_frame_into(payload_bytes.subspan(plaintext_offset), frame);
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
        const auto written = serialize_frame_into(payload_bytes.subspan(payload_written), frame);
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

    const auto plaintext = open_payload(OpenPayloadInput{
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
    const auto plaintext = open_payload(OpenPayloadInput{
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
    const auto decoded_fields = decode_received_short_header_packet_fields(
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
                const auto keys = derive_send_initial_keys(context, typed_packet.version);
                if (!keys.has_value()) {
                    return CodecResult<std::size_t>::failure(keys.error().code,
                                                             keys.error().offset);
                }

                const auto plaintext_packet = to_plaintext_initial(typed_packet);
                if (!plaintext_packet.has_value()) {
                    return CodecResult<std::size_t>::failure(plaintext_packet.error().code,
                                                             plaintext_packet.error().offset);
                }

                return append_protected_long_header_packet_to_datagram(
                    datagram.bytes, LongHeaderPacketType::initial, typed_packet.version,
                    typed_packet.destination_connection_id, typed_packet.source_connection_id,
                    typed_packet.token,
                    TruncatedPacketNumberEncoding{
                        .packet_number_length = typed_packet.packet_number_length,
                        .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
                    },
                    typed_packet.packet_number, typed_packet.frames, kInitialCipherSuite,
                    keys.value());
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                if (!context.handshake_secret.has_value()) {
                    return CodecResult<std::size_t>::failure(CodecErrorCode::missing_crypto_context,
                                                             0);
                }

                const auto keys = expand_traffic_secret_cached(context.handshake_secret.value());
                if (!keys.has_value()) {
                    return CodecResult<std::size_t>::failure(keys.error().code,
                                                             keys.error().offset);
                }
                const auto &keys_ref = keys.value().get();

                const auto plaintext_packet = to_plaintext_handshake(typed_packet);
                if (!plaintext_packet.has_value()) {
                    return CodecResult<std::size_t>::failure(plaintext_packet.error().code,
                                                             plaintext_packet.error().offset);
                }

                return append_protected_long_header_packet_to_datagram(
                    datagram.bytes, LongHeaderPacketType::handshake, typed_packet.version,
                    typed_packet.destination_connection_id, typed_packet.source_connection_id, {},
                    TruncatedPacketNumberEncoding{
                        .packet_number_length = typed_packet.packet_number_length,
                        .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
                    },
                    typed_packet.packet_number, typed_packet.frames,
                    context.handshake_secret->cipher_suite, keys_ref);
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                if (!context.zero_rtt_secret.has_value()) {
                    return CodecResult<std::size_t>::failure(CodecErrorCode::missing_crypto_context,
                                                             0);
                }

                const auto keys = expand_traffic_secret_cached(context.zero_rtt_secret.value());
                if (!keys.has_value()) {
                    return CodecResult<std::size_t>::failure(keys.error().code,
                                                             keys.error().offset);
                }
                const auto &keys_ref = keys.value().get();

                const auto plaintext_packet = to_plaintext_zero_rtt(typed_packet);
                if (!plaintext_packet.has_value()) {
                    return CodecResult<std::size_t>::failure(plaintext_packet.error().code,
                                                             plaintext_packet.error().offset);
                }

                return append_protected_long_header_packet_to_datagram(
                    datagram.bytes, LongHeaderPacketType::zero_rtt, typed_packet.version,
                    typed_packet.destination_connection_id, typed_packet.source_connection_id, {},
                    TruncatedPacketNumberEncoding{
                        .packet_number_length = typed_packet.packet_number_length,
                        .truncated_packet_number = plaintext_packet.value().truncated_packet_number,
                    },
                    typed_packet.packet_number, typed_packet.frames,
                    context.zero_rtt_secret->cipher_suite, keys_ref);
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
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacketView &packet,
                                            const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl(datagram, packet, context);
}

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacketFragmentView &packet,
                                            const SerializeProtectionContext &context) {
    return append_protected_one_rtt_packet_to_datagram_impl(datagram, packet, context);
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
