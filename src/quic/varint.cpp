#include "src/quic/varint.h"

#include <bit>

#include "src/quic/buffer.h"

namespace coquic::quic {

namespace {

constexpr std::uint64_t kMaxQuicVarInt = 4611686018427387903ull;

std::byte prefix_mask(std::size_t length) {
    return static_cast<std::byte>(std::countr_zero(static_cast<unsigned int>(length)) << 6);
}

} // namespace

std::size_t encoded_varint_size(std::uint64_t value) {
    std::size_t length = 8;
    if (value <= 63) {
        length = 1;
    } else if (value <= 16383) {
        length = 2;
    } else if (value <= 1073741823) {
        length = 4;
    }
    return length;
}

CodecResult<std::vector<std::byte>> encode_varint(std::uint64_t value) {
    const auto length = encoded_varint_size(value);
    std::vector<std::byte> bytes(length, std::byte{0x00});

    const auto encoded = encode_varint_into(bytes, value);
    if (!encoded.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                            encoded.error().offset);
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(bytes));
}

CodecResult<std::size_t> encode_varint_into(std::span<std::byte> output, std::uint64_t value) {
    if (value > kMaxQuicVarInt) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    const auto length = encoded_varint_size(value);
    if (output.size() < length) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, 0);
    }

    for (std::size_t i = 0; i < length; ++i) {
        const auto shift = static_cast<unsigned>((length - i - 1) * 8);
        output[i] = static_cast<std::byte>((value >> shift) & 0xffu);
    }
    output[0] |= prefix_mask(length);

    return CodecResult<std::size_t>::success(length);
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
    if (length != 1) {
        const auto tail = reader.read_exact(length - 1);
        if (!tail.has_value()) {
            return CodecResult<VarIntDecoded>::failure(tail.error().code, tail.error().offset);
        }

        for (const auto byte : tail.value()) {
            value = (value << 8) | static_cast<std::uint8_t>(byte);
        }
    }

    return CodecResult<VarIntDecoded>::success(VarIntDecoded{
        .value = value,
        .bytes_consumed = length,
    });
}

CodecResult<VarIntDecoded> decode_varint_bytes(std::span<const std::byte> bytes) {
    return decode_varint_bytes(bytes, 0);
}

CodecResult<VarIntDecoded> decode_varint_bytes(std::span<const std::byte> bytes,
                                               std::size_t offset) {
    if (offset >= bytes.size()) {
        return CodecResult<VarIntDecoded>::failure(CodecErrorCode::truncated_input, offset);
    }

    const auto first_value = static_cast<std::uint8_t>(bytes[offset]);
    const auto prefix = first_value >> 6;
    const auto length = std::size_t{1} << prefix;
    if (bytes.size() - offset < length) {
        return CodecResult<VarIntDecoded>::failure(CodecErrorCode::truncated_input, bytes.size());
    }

    std::uint64_t value = static_cast<std::uint64_t>(first_value & 0x3fu);
    for (std::size_t i = 1; i < length; ++i) {
        value = (value << 8) | static_cast<std::uint8_t>(bytes[offset + i]);
    }

    return CodecResult<VarIntDecoded>::success(VarIntDecoded{
        .value = value,
        .bytes_consumed = length,
    });
}

} // namespace coquic::quic
