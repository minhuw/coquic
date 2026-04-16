#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
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
    BufferWriter();
    explicit BufferWriter(std::vector<std::byte> *bytes);

    std::size_t offset() const;
    void write_byte(std::byte value);
    void write_bytes(std::span<const std::byte> bytes);
    std::optional<CodecError> write_varint(std::uint64_t value);
    void write_varint_unchecked(std::uint64_t value);
    const std::vector<std::byte> &bytes() const;

  private:
    std::vector<std::byte> owned_bytes_;
    std::vector<std::byte> *bytes_ = &owned_bytes_;
};

class SpanBufferWriter {
  public:
    explicit SpanBufferWriter(std::span<std::byte> bytes);

    std::size_t offset() const;
    std::size_t remaining() const;
    std::span<const std::byte> written() const;

    std::optional<CodecError> write_byte(std::byte value);
    std::optional<CodecError> write_bytes(std::span<const std::byte> bytes);
    std::optional<CodecError> write_varint(std::uint64_t value);
    void write_varint_unchecked(std::uint64_t value);

  private:
    std::span<std::byte> bytes_;
    std::size_t offset_ = 0;
};

class CountingBufferWriter {
  public:
    std::size_t offset() const;

    std::optional<CodecError> write_byte(std::byte value);
    std::optional<CodecError> write_bytes(std::span<const std::byte> bytes);
    std::optional<CodecError> write_varint(std::uint64_t value);
    void write_varint_unchecked(std::uint64_t value);

  private:
    std::size_t offset_ = 0;
};

} // namespace coquic::quic
