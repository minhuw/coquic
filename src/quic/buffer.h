#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include "src/quic/varint.h"

namespace coquic::quic {

template <typename T> class UninitializedAllocator {
  public:
    using value_type = T;

    UninitializedAllocator() = default;

    template <typename U>
    constexpr UninitializedAllocator(const UninitializedAllocator<U> &) noexcept {
    }

    [[nodiscard]] T *allocate(std::size_t count) {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T *pointer, std::size_t count) noexcept {
        std::allocator<T>{}.deallocate(pointer, count);
    }

    template <typename U, typename... Args> void construct(U *pointer, Args &&...args) {
        if constexpr (sizeof...(Args) == 0 && std::is_trivially_default_constructible_v<U>) {
            ::new (static_cast<void *>(pointer)) U;
        } else {
            std::construct_at(pointer, std::forward<Args>(args)...);
        }
    }

    template <typename U> struct rebind {
        using other = UninitializedAllocator<U>;
    };
};

template <typename T, typename U>
constexpr bool operator==(const UninitializedAllocator<T> &,
                          const UninitializedAllocator<U> &) noexcept {
    return true;
}

class DatagramBuffer {
  public:
    DatagramBuffer() = default;
    DatagramBuffer(std::initializer_list<std::byte> bytes);
    DatagramBuffer(std::span<const std::byte> bytes);
    DatagramBuffer(const std::vector<std::byte> &bytes);
    DatagramBuffer(std::vector<std::byte> &&bytes);

    bool empty() const;
    std::size_t size() const;
    void reserve(std::size_t capacity);
    void resize(std::size_t size);
    void resize(std::size_t size, std::byte value);
    void truncate(std::size_t size);
    void clear();
    void push_back(std::byte value);
    void append(std::span<const std::byte> bytes);
    std::span<std::byte> append_uninitialized(std::size_t size);
    std::span<std::byte> span();
    std::span<const std::byte> span() const;
    std::byte *data();
    const std::byte *data() const;
    std::vector<std::byte> to_vector() const;
    operator std::vector<std::byte>() const;

    auto begin() {
        return bytes_.begin();
    }
    auto begin() const {
        return bytes_.begin();
    }
    auto end() {
        return bytes_.end();
    }
    auto end() const {
        return bytes_.end();
    }

    bool operator==(const DatagramBuffer &) const = default;

  private:
    using Storage = std::vector<std::byte, UninitializedAllocator<std::byte>>;
    Storage bytes_;
};

bool operator==(const DatagramBuffer &lhs, std::span<const std::byte> rhs);
bool operator==(std::span<const std::byte> lhs, const DatagramBuffer &rhs);
bool operator==(const DatagramBuffer &lhs, const std::vector<std::byte> &rhs);
bool operator==(const std::vector<std::byte> &lhs, const DatagramBuffer &rhs);

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
