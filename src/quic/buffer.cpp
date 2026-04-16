#include "src/quic/buffer.h"

#include <algorithm>
#include <array>
#include <cstdlib>

namespace coquic::quic {

namespace {

std::optional<CodecError> write_varint_into_fixed_span(std::span<std::byte> output,
                                                       std::size_t *offset, std::uint64_t value) {
    const auto start_offset = *offset;
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return CodecError{
            .code = written.error().code,
            .offset = start_offset,
        };
    }
    const auto encoded_size = written.value();

    if (output.size() - start_offset < encoded_size) {
        return CodecError{
            .code = CodecErrorCode::truncated_input,
            .offset = start_offset,
        };
    }

    std::copy(encoded.begin(), encoded.begin() + static_cast<std::ptrdiff_t>(encoded_size),
              output.begin() + static_cast<std::ptrdiff_t>(start_offset));
    *offset += encoded_size;
    return std::nullopt;
}

} // namespace

BufferReader::BufferReader(std::span<const std::byte> bytes) : bytes_(bytes) {
}

std::size_t BufferReader::offset() const {
    return offset_;
}

std::size_t BufferReader::remaining() const {
    return bytes_.size() - offset_;
}

CodecResult<std::byte> BufferReader::read_byte() {
    if (offset_ >= bytes_.size()) {
        return CodecResult<std::byte>::failure(CodecErrorCode::truncated_input, offset_);
    }

    return CodecResult<std::byte>::success(bytes_[offset_++]);
}

CodecResult<std::span<const std::byte>> BufferReader::read_exact(std::size_t size) {
    if (remaining() < size) {
        return CodecResult<std::span<const std::byte>>::failure(CodecErrorCode::truncated_input,
                                                                offset_);
    }

    const auto begin = bytes_.subspan(offset_, size);
    offset_ += size;
    return CodecResult<std::span<const std::byte>>::success(begin);
}

BufferWriter::BufferWriter() = default;

BufferWriter::BufferWriter(std::vector<std::byte> *bytes)
    : bytes_(bytes != nullptr ? bytes : &owned_bytes_) {
}

std::size_t BufferWriter::offset() const {
    return bytes_->size();
}

void BufferWriter::write_byte(std::byte value) {
    bytes_->push_back(value);
}

void BufferWriter::write_bytes(std::span<const std::byte> bytes) {
    const auto offset = bytes_->size();
    bytes_->resize(offset + bytes.size());
    std::copy(bytes.begin(), bytes.end(), bytes_->data() + offset);
}

std::optional<CodecError> BufferWriter::write_varint(std::uint64_t value) {
    const auto start_offset = offset();
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return CodecError{
            .code = written.error().code,
            .offset = start_offset,
        };
    }

    write_bytes(std::span<const std::byte>(encoded.data(), written.value()));
    return std::nullopt;
}

void BufferWriter::write_varint_unchecked(std::uint64_t value) {
    if (write_varint(value).has_value()) {
        std::abort();
    }
}

const std::vector<std::byte> &BufferWriter::bytes() const {
    return *bytes_;
}

SpanBufferWriter::SpanBufferWriter(std::span<std::byte> bytes) : bytes_(bytes) {
}

std::size_t SpanBufferWriter::offset() const {
    return offset_;
}

std::size_t SpanBufferWriter::remaining() const {
    return bytes_.size() - offset_;
}

std::span<const std::byte> SpanBufferWriter::written() const {
    return std::span<const std::byte>(bytes_.data(), offset_);
}

std::optional<CodecError> SpanBufferWriter::write_byte(std::byte value) {
    if (remaining() < 1) {
        return CodecError{
            .code = CodecErrorCode::truncated_input,
            .offset = offset_,
        };
    }

    bytes_[offset_++] = value;
    return std::nullopt;
}

std::optional<CodecError> SpanBufferWriter::write_bytes(std::span<const std::byte> bytes) {
    if (remaining() < bytes.size()) {
        return CodecError{
            .code = CodecErrorCode::truncated_input,
            .offset = offset_,
        };
    }

    std::copy(bytes.begin(), bytes.end(), bytes_.begin() + static_cast<std::ptrdiff_t>(offset_));
    offset_ += bytes.size();
    return std::nullopt;
}

std::optional<CodecError> SpanBufferWriter::write_varint(std::uint64_t value) {
    return write_varint_into_fixed_span(bytes_, &offset_, value);
}

void SpanBufferWriter::write_varint_unchecked(std::uint64_t value) {
    if (write_varint(value).has_value()) {
        std::abort();
    }
}

std::size_t CountingBufferWriter::offset() const {
    return offset_;
}

std::optional<CodecError> CountingBufferWriter::write_byte(std::byte /*value*/) {
    ++offset_;
    return std::nullopt;
}

std::optional<CodecError> CountingBufferWriter::write_bytes(std::span<const std::byte> bytes) {
    offset_ += bytes.size();
    return std::nullopt;
}

std::optional<CodecError> CountingBufferWriter::write_varint(std::uint64_t value) {
    const auto start_offset = offset_;
    std::array<std::byte, 8> encoded{};
    const auto written = encode_varint_into(encoded, value);
    if (!written.has_value()) {
        return CodecError{
            .code = written.error().code,
            .offset = start_offset,
        };
    }

    offset_ += written.value();
    return std::nullopt;
}

void CountingBufferWriter::write_varint_unchecked(std::uint64_t value) {
    if (write_varint(value).has_value()) {
        std::abort();
    }
}

} // namespace coquic::quic
