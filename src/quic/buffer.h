#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include "src/quic/varint.h"

namespace coquic::quic {

class BufferReader {
  public:
    explicit BufferReader(std::span<const std::byte> bytes);

    std::size_t offset() const;
    std::size_t remaining() const;
    CodecResult<std::byte> read_byte();
    CodecResult<std::span<const std::byte>> read_exact(std::size_t size);

  private:
    std::span<const std::byte> bytes_;
    std::size_t offset_ = 0;
};

class BufferWriter {
  public:
    void write_byte(std::byte value);
    void write_bytes(std::span<const std::byte> bytes);
    const std::vector<std::byte> &bytes() const;

  private:
    std::vector<std::byte> bytes_;
};

} // namespace coquic::quic
