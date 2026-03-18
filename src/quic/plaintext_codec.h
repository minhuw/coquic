#pragma once

#include <span>
#include <vector>

#include "src/quic/packet.h"

namespace coquic::quic {

CodecResult<std::vector<std::byte>> serialize_datagram(std::span<const Packet> packets);
CodecResult<std::vector<Packet>> deserialize_datagram(std::span<const std::byte> bytes,
                                                      const DeserializeOptions &options = {});

} // namespace coquic::quic
