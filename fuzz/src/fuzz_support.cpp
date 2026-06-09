#include "src/quic/transport/transport_parameters.h"
#include "src/quic/version.h"

#include <algorithm>
#include <span>

namespace coquic::quic {

bool contains_version(std::span<const std::uint32_t> versions, std::uint32_t version) {
    return std::find(versions.begin(), versions.end(), version) != versions.end();
}

std::uint32_t select_preferred_version(std::span<const std::uint32_t> preferred_versions,
                                       const VersionInformation &version_information) {
    for (const auto preferred_version : preferred_versions) {
        if (contains_version(version_information.available_versions, preferred_version)) {
            return preferred_version;
        }
    }
    return kVersionNegotiationVersion;
}

} // namespace coquic::quic
