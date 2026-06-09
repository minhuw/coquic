#include <cstddef>
#include <cstdint>
#include <span>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/codec/packet.h"
#include "src/quic/codec/plaintext_codec.h"

namespace {

void exercise_packet(std::span<const std::byte> bytes,
                     const coquic::quic::DeserializeOptions &options) {
    const auto decoded = coquic::quic::deserialize_packet(bytes, options);
    if (!decoded.has_value()) {
        coquic::fuzz::require_error_offset(decoded.error(), bytes.size());
        return;
    }

    coquic::fuzz::require(decoded.value().bytes_consumed <= bytes.size(),
                          "packet decoder over-consumed input");
    if (decoded.value().bytes_consumed != bytes.size()) {
        return;
    }

    const auto encoded = coquic::quic::serialize_packet(decoded.value().packet);
    if (!encoded.has_value()) {
        coquic::fuzz::fail("decoded packet failed to serialize");
        return;
    }

    const auto redecode = coquic::quic::deserialize_packet(encoded.value(), options);
    coquic::fuzz::require(redecode.has_value(), "serialized decoded packet is invalid");
    coquic::fuzz::require(redecode.value().bytes_consumed == encoded.value().size(),
                          "serialized decoded packet was not fully consumed");
    coquic::fuzz::require(decoded.value().packet.index() == redecode.value().packet.index(),
                          "packet variant changed after round-trip");
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    constexpr std::size_t kMaxDatagramInputSize = 1500;
    if (size > kMaxDatagramInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    const auto span = std::span<const std::byte>(bytes.data(), bytes.size());

    exercise_packet(span, {});
    exercise_packet(span, {.one_rtt_destination_connection_id_length = 2});
    exercise_packet(span, {
                              .one_rtt_destination_connection_id_length = 2,
                              .accept_greased_quic_bit = true,
                          });

    const auto datagram = coquic::quic::deserialize_datagram(span);
    if (!datagram.has_value()) {
        coquic::fuzz::require_error_offset(datagram.error(), bytes.size());
        return 0;
    }

    const auto encoded = coquic::quic::serialize_datagram(datagram.value());
    if (!encoded.has_value()) {
        coquic::fuzz::fail("decoded datagram failed to serialize");
        return 0;
    }

    const auto redecode = coquic::quic::deserialize_datagram(encoded.value());
    coquic::fuzz::require(redecode.has_value(), "serialized decoded datagram is invalid");
    coquic::fuzz::require(redecode.value().size() == datagram.value().size(),
                          "datagram packet count changed after round-trip");

    return 0;
}
