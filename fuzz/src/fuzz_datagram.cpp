#include <cstddef>
#include <cstdint>

#include "fuzz/src/fuzz_packet_support.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    constexpr std::size_t kMaxDatagramInputSize = 1500;
    if (size > kMaxDatagramInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    const auto span = coquic::fuzz::byte_span(bytes);

    coquic::fuzz::exercise_datagram(span);
    coquic::fuzz::exercise_datagram(span, {.one_rtt_destination_connection_id_length = 8});
    coquic::fuzz::exercise_datagram(span, {.accept_greased_quic_bit = true});
    coquic::fuzz::exercise_datagram(span, {
                                              .one_rtt_destination_connection_id_length = 8,
                                              .accept_greased_quic_bit = true,
                                          });

    return 0;
}
