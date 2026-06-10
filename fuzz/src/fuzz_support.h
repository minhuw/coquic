#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
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

class InputReader {
  public:
    explicit InputReader(std::span<const std::byte> bytes) : bytes_(bytes) {
    }

    bool empty() const {
        return offset_ >= bytes_.size();
    }

    std::size_t remaining() const {
        return offset_ <= bytes_.size() ? bytes_.size() - offset_ : 0;
    }

    std::uint8_t read_u8(std::uint8_t fallback = 0) {
        if (remaining() == 0) {
            return fallback;
        }
        return std::to_integer<std::uint8_t>(bytes_[offset_++]);
    }

    bool read_bool() {
        return (read_u8() & 1u) != 0;
    }

    std::uint64_t read_u64(std::uint64_t fallback = 0) {
        if (remaining() == 0) {
            return fallback;
        }

        std::uint64_t value = 0;
        const auto count = std::min<std::size_t>(remaining(), sizeof(value));
        for (std::size_t i = 0; i < count; ++i) {
            value = (value << 8u) | read_u8();
        }
        return value;
    }

    std::size_t read_size(std::size_t modulo) {
        if (modulo == 0) {
            return 0;
        }
        const auto value = read_u64();
        return static_cast<std::size_t>(value % modulo);
    }

    std::vector<std::byte> read_bytes(std::size_t max_size) {
        const auto count = std::min(max_size, remaining());
        std::vector<std::byte> output;
        output.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            output.push_back(bytes_[offset_++]);
        }
        return output;
    }

    std::vector<std::byte> read_sized_bytes(std::size_t max_size) {
        if (max_size == 0) {
            return {};
        }
        const auto count = read_size(max_size + 1);
        return read_bytes(count);
    }

  private:
    std::span<const std::byte> bytes_;
    std::size_t offset_ = 0;
};

} // namespace coquic::fuzz
