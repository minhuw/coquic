#include "src/quic/protected_codec.h"
#include "src/quic/protected_codec_internal.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/buffer.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/packet_number.h"
#include "src/quic/protected_codec_test_hooks.h"
#include "src/quic/streams.h"
#include "src/quic/version.h"

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

#ifndef COQUIC_PROFILE_HOOKS
#define COQUIC_PROFILE_HOOKS 1
#endif

namespace coquic::quic::test {

using namespace detail;

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacket &packet,
                                            const SerializeProtectionContext &context) {
    DatagramBuffer encoded(datagram);
    const auto appended =
        append_protected_one_rtt_packet_to_datagram_impl(encoded, packet, context);
    if (!appended.has_value()) {
        return appended;
    }

    datagram = encoded.to_vector();
    return appended;
}

ScopedProtectedCodecFaultInjector::ScopedProtectedCodecFaultInjector(
    ProtectedCodecFaultPoint fault_point, std::size_t occurrence)
    : previous_fault_point_(protected_codec_fault_state().fault_point),
      previous_occurrence_(protected_codec_fault_state().occurrence) {
    set_protected_codec_fault_state(fault_point, occurrence);
}

ScopedProtectedCodecFaultInjector::~ScopedProtectedCodecFaultInjector() {
    set_protected_codec_fault_state(previous_fault_point_, previous_occurrence_);
}

} // namespace coquic::quic::test
