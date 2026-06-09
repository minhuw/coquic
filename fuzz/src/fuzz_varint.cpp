#include <cstddef>
#include <cstdint>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/codec/varint.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    constexpr std::size_t kMaxVarintInputSize = 16;
    if (size > kMaxVarintInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    const auto decoded = coquic::quic::decode_varint_bytes(coquic::fuzz::byte_span(bytes));
    if (!decoded.has_value()) {
        coquic::fuzz::require_error_offset(decoded.error(), bytes.size());
        return 0;
    }

    coquic::fuzz::require(decoded.value().bytes_consumed <= bytes.size(),
                          "varint decoder over-consumed input");

    const auto encoded = coquic::quic::encode_varint(decoded.value().value);
    coquic::fuzz::require(encoded.has_value(), "decoded varint value failed to encode");
    coquic::fuzz::require(encoded.value().size() ==
                              coquic::quic::encoded_varint_size(decoded.value().value),
                          "encoded varint size mismatch");

    const auto redecode = coquic::quic::decode_varint_bytes(encoded.value());
    coquic::fuzz::require(redecode.has_value(), "encoded varint failed to decode");
    coquic::fuzz::require(redecode.value().value == decoded.value().value,
                          "varint value changed after round-trip");
    coquic::fuzz::require(redecode.value().bytes_consumed == encoded.value().size(),
                          "encoded varint was not fully consumed");

    return 0;
}
