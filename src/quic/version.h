#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace coquic::quic {

constexpr std::uint32_t kVersionNegotiationVersion = 0x00000000u;
constexpr std::uint32_t kQuicVersion1 = 0x00000001u;
constexpr std::uint32_t kQuicVersion2 = 0x6b3343cfu;

constexpr std::array<std::uint32_t, 2> kSupportedQuicVersions{
    kQuicVersion1,
    kQuicVersion2,
};

constexpr bool is_supported_quic_version(std::uint32_t version) {
    return version == kQuicVersion1 || version == kQuicVersion2;
}

constexpr std::span<const std::uint32_t> supported_quic_versions() {
    return std::span<const std::uint32_t>(kSupportedQuicVersions);
}

} // namespace coquic::quic
