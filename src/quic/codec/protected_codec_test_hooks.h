#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include "src/quic/codec/protected_codec.h"

namespace coquic::quic::test {

enum class ProtectedCodecFaultPoint : std::uint8_t {
    remove_long_header_packet_length_mismatch,
    remove_short_header_packet_length_mismatch,
    remove_short_header_plaintext_header_overflow,
    deserialize_plaintext_packet,
    simple_ack_payload_write_failure,
    simple_ack_payload_size_mismatch,
    simple_ack_force_padding_fill,
};

class ScopedProtectedCodecFaultInjector {
  public:
    explicit ScopedProtectedCodecFaultInjector(ProtectedCodecFaultPoint fault_point,
                                               std::size_t occurrence = 1);
    ~ScopedProtectedCodecFaultInjector();

    ScopedProtectedCodecFaultInjector(const ScopedProtectedCodecFaultInjector &) = delete;
    ScopedProtectedCodecFaultInjector &
    operator=(const ScopedProtectedCodecFaultInjector &) = delete;

  private:
    std::optional<ProtectedCodecFaultPoint> previous_fault_point_;
    std::size_t previous_occurrence_ = 0;
};

} // namespace coquic::quic::test
