#include "src/quic/codec/plaintext_codec.h"

#include "src/quic/codec/buffer.h"
#include "src/quic/fuzz_corpus_capture.h"

namespace coquic::quic {

CodecResult<std::vector<std::byte>> serialize_datagram(std::span<const Packet> packets) {
    BufferWriter writer;

    for (std::size_t i = 0; i < packets.size(); ++i) {
        const auto encoded = serialize_packet(packets[i]);
        if (!encoded.has_value()) {
            return CodecResult<std::vector<std::byte>>::failure(encoded.error().code,
                                                                encoded.error().offset);
        }
        const auto &packet_bytes = encoded.value();
        capture_fuzz_corpus_sample("fuzz_plaintext_packet", packet_bytes);
        if (!packet_bytes.empty()) {
            if ((std::to_integer<std::uint8_t>(packet_bytes.front()) & 0x80u) != 0) {
                capture_fuzz_corpus_sample("fuzz_long_header_packet", packet_bytes);
            } else {
                capture_fuzz_corpus_sample("fuzz_short_header_packet", packet_bytes);
            }
        }
        writer.write_bytes(packet_bytes);
    }

    const auto bytes = writer.bytes();
    capture_fuzz_corpus_sample("fuzz_datagram", bytes);
    return CodecResult<std::vector<std::byte>>::success(bytes);
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

        packets.push_back(decoded.value().packet);
        offset += decoded.value().bytes_consumed;
    }

    return CodecResult<std::vector<Packet>>::success(std::move(packets));
}

} // namespace coquic::quic
