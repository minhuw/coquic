#pragma once

#include <cstddef>
#include <span>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/codec/packet.h"
#include "src/quic/codec/plaintext_codec.h"

namespace coquic::fuzz {

inline void exercise_packet(std::span<const std::byte> bytes,
                            const coquic::quic::DeserializeOptions &options) {
    const auto decoded = coquic::quic::deserialize_packet(bytes, options);
    if (!decoded.has_value()) {
        require_error_offset(decoded.error(), bytes.size());
        return;
    }

    require(decoded.value().bytes_consumed <= bytes.size(), "packet decoder over-consumed input");
    if (decoded.value().bytes_consumed != bytes.size()) {
        return;
    }

    const auto encoded = coquic::quic::serialize_packet(decoded.value().packet);
    if (!encoded.has_value()) {
        fail("decoded packet failed to serialize");
        return;
    }

    const auto redecode = coquic::quic::deserialize_packet(encoded.value(), options);
    require(redecode.has_value(), "serialized decoded packet is invalid");
    require(redecode.value().bytes_consumed == encoded.value().size(),
            "serialized decoded packet was not fully consumed");
    require(decoded.value().packet.index() == redecode.value().packet.index(),
            "packet variant changed after round-trip");
}

inline void exercise_datagram(std::span<const std::byte> bytes,
                              const coquic::quic::DeserializeOptions &options = {}) {
    const auto datagram = coquic::quic::deserialize_datagram(bytes, options);
    if (!datagram.has_value()) {
        require_error_offset(datagram.error(), bytes.size());
        return;
    }

    const auto encoded = coquic::quic::serialize_datagram(datagram.value());
    if (!encoded.has_value()) {
        fail("decoded datagram failed to serialize");
        return;
    }

    const auto redecode = coquic::quic::deserialize_datagram(encoded.value(), options);
    require(redecode.has_value(), "serialized decoded datagram is invalid");
    require(redecode.value().size() == datagram.value().size(),
            "datagram packet count changed after round-trip");
}

} // namespace coquic::fuzz
