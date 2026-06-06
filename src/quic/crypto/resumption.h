#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace coquic::quic {

struct QuicResumptionState {
    std::vector<std::byte> serialized;
};

struct QuicZeroRttConfig {
    bool attempt = false;
    bool allow = false;
    std::vector<std::byte> application_context;
};

enum class QuicZeroRttStatus : std::uint8_t {
    unavailable,
    not_attempted,
    attempted,
    accepted,
    rejected,
};

} // namespace coquic::quic
