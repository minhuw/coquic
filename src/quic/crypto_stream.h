#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <vector>

#include "src/quic/frame.h"
#include "src/quic/varint.h"

namespace coquic::quic {

class CryptoSendBuffer {
  public:
    void append(std::span<const std::byte> bytes);
    std::vector<CryptoFrame> take_frames(std::size_t max_frame_payload_size);
    bool empty() const;

  private:
    std::vector<std::byte> pending_;
    std::uint64_t next_offset_ = 0;
};

class CryptoReceiveBuffer {
  public:
    CodecResult<std::vector<std::byte>> push(std::uint64_t offset,
                                             std::span<const std::byte> bytes);

  private:
    std::uint64_t next_contiguous_offset_ = 0;
    std::map<std::uint64_t, std::byte> buffered_bytes_;
};

} // namespace coquic::quic
