#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace coquic::quic {

enum class CodecErrorCode : std::uint8_t {
    truncated_input,
    invalid_varint,
    invalid_fixed_bit,
    invalid_reserved_bits,
    unsupported_packet_type,
    unknown_frame_type,
    non_shortest_frame_type_encoding,
    empty_packet_payload,
    packet_length_mismatch,
    frame_not_allowed_in_packet_type,
    malformed_short_header_context,
};

struct CodecError {
    CodecErrorCode code;
    std::size_t offset;
};

template <typename T> struct CodecResult {
    std::variant<T, CodecError> storage;

    bool has_value() const {
        return std::holds_alternative<T>(storage);
    }

    T &value() {
        return std::get<T>(storage);
    }

    const T &value() const {
        return std::get<T>(storage);
    }

    CodecError &error() {
        return std::get<CodecError>(storage);
    }

    const CodecError &error() const {
        return std::get<CodecError>(storage);
    }

    static CodecResult success(T result) {
        return CodecResult{
            .storage = std::move(result),
        };
    }

    static CodecResult failure(CodecErrorCode code, std::size_t offset) {
        return CodecResult{
            .storage =
                CodecError{
                    .code = code,
                    .offset = offset,
                },
        };
    }
};

class BufferReader;

struct VarIntDecoded {
    std::uint64_t value;
    std::size_t bytes_consumed;
};

std::size_t encoded_varint_size(std::uint64_t value);
CodecResult<std::vector<std::byte>> encode_varint(std::uint64_t value);
CodecResult<VarIntDecoded> decode_varint(BufferReader &reader);
CodecResult<VarIntDecoded> decode_varint_bytes(std::span<const std::byte> bytes);

} // namespace coquic::quic
