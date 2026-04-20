#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "src/quic/protected_codec.h"

namespace coquic::quic::test {

enum class ProtectedCodecFaultPoint : std::uint8_t {
    remove_long_header_packet_length_mismatch,
    remove_short_header_packet_length_mismatch,
    deserialize_plaintext_packet,
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

CodecResult<std::size_t>
append_protected_one_rtt_packet_to_datagram(std::vector<std::byte> &datagram,
                                            const ProtectedOneRttPacket &packet,
                                            const SerializeProtectionContext &context);
bool protected_codec_internal_coverage_for_tests();
bool protected_codec_packet_path_coverage_for_tests();

} // namespace coquic::quic::test
