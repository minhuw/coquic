#include "src/quic/plaintext_codec.h"

#include "src/quic/buffer.h"

namespace coquic::quic {

CodecResult<std::vector<std::byte>> serialize_datagram(std::span<const Packet> packets) {
    BufferWriter writer;

    for (std::size_t i = 0; i < packets.size(); ++i) {
        const auto encoded = serialize_packet(packets[i]);
        if (!encoded.has_value()) {
            return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                                encoded.error().offset);
        }
        writer.write_bytes(encoded.value());
    }

    return CodecResult<std::vector<std::byte>>::success(writer.bytes());
}

CodecResult<std::vector<Packet>> deserialize_datagram(std::span<const std::byte> bytes,
                                                      const DeserializeOptions &options) {
    if (bytes.empty()) {
        return CodecResult<std::vector<Packet>>::failure(CodecErrorCode::truncated_input, 0);
    }

    std::vector<Packet> packets;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto decoded = deserialize_packet(bytes.subspan(offset), options);
        if (!decoded.has_value()) {
            return CodecResult<std::vector<Packet>>::failure(decoded.error().code,
                                                             offset + decoded.error().offset);
        }
        if (decoded.value().bytes_consumed == 0) {
            return CodecResult<std::vector<Packet>>::failure(CodecErrorCode::packet_length_mismatch,
                                                             offset);
        }

        packets.push_back(decoded.value().packet);
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<Packet>>::success(std::move(packets));
}

} // namespace coquic::quic
