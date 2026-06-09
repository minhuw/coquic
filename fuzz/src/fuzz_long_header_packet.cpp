#include <cstddef>
#include <cstdint>

#include "fuzz/src/fuzz_packet_support.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    constexpr std::size_t kMaxPacketInputSize = 1500;
    if (size > kMaxPacketInputSize || size == 0 || (data[0] & 0x80u) == 0) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    const auto span = coquic::fuzz::byte_span(bytes);

    coquic::fuzz::exercise_packet(span, {});
    coquic::fuzz::exercise_packet(span, {.accept_greased_quic_bit = true});

    return 0;
}
