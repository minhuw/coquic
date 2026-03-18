#include "src/quic/crypto_stream.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace {

using coquic::quic::CodecErrorCode;
using coquic::quic::CodecResult;
using coquic::quic::CryptoFrame;

constexpr std::uint64_t maximum_crypto_offset = (std::uint64_t{1} << 62) - 1;

CodecResult<std::vector<std::byte>> crypto_stream_failure() {
    return CodecResult<std::vector<std::byte>>::failure(CodecErrorCode::invalid_varint, 0);
}

} // namespace

namespace coquic::quic {

void CryptoSendBuffer::append(std::span<const std::byte> bytes) {
    pending_.insert(pending_.end(), bytes.begin(), bytes.end());
}

std::vector<CryptoFrame> CryptoSendBuffer::take_frames(std::size_t max_frame_payload_size) {
    std::vector<CryptoFrame> frames;
    if (pending_.empty() || max_frame_payload_size == 0) {
        return frames;
    }

    std::size_t offset = 0;
    while (offset < pending_.size()) {
        const auto chunk_size = std::min(max_frame_payload_size, pending_.size() - offset);
        const auto frame_begin = pending_.cbegin() + static_cast<std::ptrdiff_t>(offset);
        const auto frame_end = frame_begin + static_cast<std::ptrdiff_t>(chunk_size);
        frames.push_back(CryptoFrame{
            .offset = next_offset_,
            .crypto_data = std::vector<std::byte>(frame_begin, frame_end),
        });
        offset += chunk_size;
        next_offset_ += chunk_size;
    }

    pending_.clear();
    return frames;
}

bool CryptoSendBuffer::empty() const {
    return pending_.empty();
}

CodecResult<std::vector<std::byte>> CryptoReceiveBuffer::push(std::uint64_t offset,
                                                              std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return CodecResult<std::vector<std::byte>>::success({});
    }
    if (offset > maximum_crypto_offset || bytes.size() - 1 > maximum_crypto_offset - offset) {
        return crypto_stream_failure();
    }

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto position = offset + i;
        if (position < next_contiguous_offset_) {
            continue;
        }

        buffered_bytes_.try_emplace(position, bytes[i]);
    }

    std::vector<std::byte> contiguous;
    while (true) {
        const auto next = buffered_bytes_.find(next_contiguous_offset_);
        if (next == buffered_bytes_.end()) {
            break;
        }

        contiguous.push_back(next->second);
        buffered_bytes_.erase(next);
        ++next_contiguous_offset_;
    }

    return CodecResult<std::vector<std::byte>>::success(std::move(contiguous));
}

} // namespace coquic::quic
