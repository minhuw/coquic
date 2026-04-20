#include "src/quic/buffer.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::quic {

namespace {

std::optional<CodecError> write_varint_into_fixed_span(std::span<std::byte> output,
                                                       std::size_t *offset, std::uint64_t value) {
    constexpr std::uint64_t kMaxQuicVarInt = 4611686018427387903ull;
    const auto start_offset = *offset;
    if (value > kMaxQuicVarInt) {
        return CodecError{
            .code = CodecErrorCode::invalid_varint,
            .offset = start_offset,
        };
    }
    if (start_offset > output.size()) {
        return CodecError{
            .code = CodecErrorCode::truncated_input,
            .offset = start_offset,
        };
    }
    const auto encoded_size = encoded_varint_size(value);
    if (output.size() - start_offset < encoded_size) {
        return CodecError{
            .code = CodecErrorCode::truncated_input,
            .offset = start_offset,
        };
    }

    const auto written = encode_varint_into(output.subspan(start_offset), value).value();
    *offset += written;
    return std::nullopt;
}

COQUIC_NO_PROFILE void abort_if(bool condition) {
    if (condition) {
        std::abort();
    }
}

} // namespace

DatagramBuffer::DatagramBuffer(std::initializer_list<std::byte> bytes) {
    append(std::span<const std::byte>(bytes.begin(), bytes.size()));
}

DatagramBuffer::DatagramBuffer(std::span<const std::byte> bytes) {
    append(bytes);
}

DatagramBuffer::DatagramBuffer(const std::vector<std::byte> &bytes) {
    append(bytes);
}

DatagramBuffer::DatagramBuffer(std::vector<std::byte> &&bytes) {
    append(bytes);
}

bool DatagramBuffer::empty() const {
    return bytes_.empty();
}

std::size_t DatagramBuffer::size() const {
    return bytes_.size();
}

void DatagramBuffer::reserve(std::size_t capacity) {
    bytes_.reserve(capacity);
}

void DatagramBuffer::resize(std::size_t size) {
    bytes_.resize(size);
}

void DatagramBuffer::resize(std::size_t size, std::byte value) {
    bytes_.resize(size, value);
}

void DatagramBuffer::truncate(std::size_t size) {
    bytes_.resize(size);
}

void DatagramBuffer::clear() {
    bytes_.clear();
}

void DatagramBuffer::push_back(std::byte value) {
    bytes_.push_back(value);
}

void DatagramBuffer::append(std::span<const std::byte> bytes) {
    auto tail = append_uninitialized(bytes.size());
    if (!bytes.empty()) {
        std::memcpy(tail.data(), bytes.data(), bytes.size());
    }
}

std::span<std::byte> DatagramBuffer::append_uninitialized(std::size_t size) {
    const auto offset = bytes_.size();
    bytes_.resize(offset + size);
    return std::span<std::byte>(bytes_.data() + static_cast<std::ptrdiff_t>(offset), size);
}

std::span<std::byte> DatagramBuffer::span() {
    return std::span<std::byte>(bytes_.data(), bytes_.size());
}

std::span<const std::byte> DatagramBuffer::span() const {
    return std::span<const std::byte>(bytes_.data(), bytes_.size());
}

std::byte *DatagramBuffer::data() {
    return bytes_.data();
}

const std::byte *DatagramBuffer::data() const {
    return bytes_.data();
}

std::vector<std::byte> DatagramBuffer::to_vector() const {
    return std::vector<std::byte>(bytes_.begin(), bytes_.end());
}

DatagramBuffer::operator std::vector<std::byte>() const {
    return to_vector();
}

bool operator==(const DatagramBuffer &lhs, std::span<const std::byte> rhs) {
    const auto lhs_bytes = lhs.span();
    return lhs_bytes.size() == rhs.size() &&
           std::equal(lhs_bytes.begin(), lhs_bytes.end(), rhs.begin(), rhs.end());
}

bool operator==(std::span<const std::byte> lhs, const DatagramBuffer &rhs) {
    return rhs == lhs;
}

bool operator==(const DatagramBuffer &lhs, const std::vector<std::byte> &rhs) {
    return lhs == std::span<const std::byte>(rhs);
}

bool operator==(const std::vector<std::byte> &lhs, const DatagramBuffer &rhs) {
    return std::span<const std::byte>(lhs) == rhs;
}

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
    abort_if(write_varint(value).has_value());
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
    abort_if(write_varint(value).has_value());
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
    abort_if(write_varint(value).has_value());
}

} // namespace coquic::quic
