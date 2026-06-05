#include "src/quic/protected_codec_test_hooks.h"
#include "src/quic/protected_codec_internal.h"

namespace coquic::quic::test {

ScopedProtectedCodecFaultInjector::ScopedProtectedCodecFaultInjector(
    ProtectedCodecFaultPoint fault_point, std::size_t occurrence)
    : previous_fault_point_(detail::protected_codec_fault_state().fault_point),
      previous_occurrence_(detail::protected_codec_fault_state().occurrence) {
    detail::set_protected_codec_fault_state(fault_point, occurrence);
}

ScopedProtectedCodecFaultInjector::~ScopedProtectedCodecFaultInjector() {
    detail::set_protected_codec_fault_state(previous_fault_point_, previous_occurrence_);
}

} // namespace coquic::quic::test
