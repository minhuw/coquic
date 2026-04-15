#include "src/quic/buffer.h"

#include <algorithm>

namespace coquic::quic {

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

void BufferWriter::write_byte(std::byte value) {
    bytes_->push_back(value);
}

void BufferWriter::write_bytes(std::span<const std::byte> bytes) {
    const auto offset = bytes_->size();
    bytes_->resize(offset + bytes.size());
    std::copy(bytes.begin(), bytes.end(), bytes_->data() + offset);
}

const std::vector<std::byte> &BufferWriter::bytes() const {
    return *bytes_;
}

} // namespace coquic::quic
