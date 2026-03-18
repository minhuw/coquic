#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

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

} // namespace coquic::quic::test
