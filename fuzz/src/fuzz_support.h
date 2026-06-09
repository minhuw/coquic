#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <vector>

#include "src/quic/codec/varint.h"

namespace coquic::fuzz {

[[noreturn]] inline void fail(const char *message) {
    std::fputs(message, stderr);
    std::fputc('\n', stderr);
    std::abort();
}

inline void require(bool condition, const char *message) {
    if (!condition) {
        fail(message);
    }
}

inline std::vector<std::byte> bytes_from_input(const std::uint8_t *data, std::size_t size) {
    std::vector<std::byte> bytes;
    bytes.reserve(size);
    for (std::size_t i = 0; i < size; ++i) {
        bytes.push_back(static_cast<std::byte>(data[i]));
    }
    return bytes;
}

inline void require_error_offset(const coquic::quic::CodecError &error, std::size_t input_size) {
    require(error.offset <= input_size, "codec error offset exceeds input size");
}

inline std::span<const std::byte> byte_span(const std::vector<std::byte> &bytes) {
    return std::span<const std::byte>(bytes.data(), bytes.size());
}

} // namespace coquic::fuzz
