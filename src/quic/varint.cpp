#include "src/quic/varint.h"

#include <bit>

#include "src/quic/buffer.h"

namespace coquic::quic {

namespace {

constexpr std::uint64_t kMaxQuicVarInt = 4611686018427387903ull;

std::byte prefix_mask(std::size_t length) {
    return static_cast<std::byte>(std::countr_zero(length) << 6);
}

} // namespace

std::size_t encoded_varint_size(std::uint64_t value) {
    if (value <= 63) {
        return 1;
    }
    if (value <= 16383) {
        return 2;
    }
    if (value <= 1073741823) {
        return 4;
    }
    return 8;
}

CodecResult<std::vector<std::byte>> encode_varint(std::uint64_t value) {
    if (value > kMaxQuicVarInt) {
        return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto length = encoded_varint_size(value);
    std::vector<std::byte> bytes(length, std::byte{0x00});

    for (std::size_t i = 0; i < length; ++i) {
        const auto shift = static_cast<unsigned>((length - i - 1) * 8);
        bytes[i] = static_cast<std::byte>((value >> shift) & 0xffu);
    }
    bytes[0] |= prefix_mask(length);

    return CodecResult<std::vector<std::byte>>::success(std::move(bytes));
}

CodecResult<VarIntDecoded> decode_varint(BufferReader &reader) {
    const auto first = reader.read_byte();
    if (!first.has_value()) {
        return CodecResult<VarIntDecoded>::failure(first.error().code, first.error().offset);
    }

    const auto first_value = static_cast<std::uint8_t>(first.value());
    const auto prefix = first_value >> 6;
    const auto length = std::size_t{1} << prefix;

    std::uint64_t value = static_cast<std::uint64_t>(first_value & 0x3fu);

    for (std::size_t i = 1; i < length; ++i) {
        const auto byte = reader.read_byte();
        if (!byte.has_value()) {
            return CodecResult<VarIntDecoded>::failure(byte.error().code, byte.error().offset);
        }
        value = (value << 8) | static_cast<std::uint8_t>(byte.value());
    }

    return CodecResult<VarIntDecoded>::success(VarIntDecoded{
        .value = value,
        .bytes_consumed = length,
    });
}

CodecResult<VarIntDecoded> decode_varint_bytes(std::span<const std::byte> bytes) {
    BufferReader reader(bytes);
    return decode_varint(reader);
}

} // namespace coquic::quic
