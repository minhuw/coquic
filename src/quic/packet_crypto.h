#pragma once

#include <cstddef>
#include <vector>

#include "src/quic/protected_codec.h"

namespace coquic::quic {

struct PacketProtectionKeys {
    std::vector<std::byte> key;
    std::vector<std::byte> iv;
    std::vector<std::byte> hp_key;
};

CodecResult<PacketProtectionKeys>
derive_initial_packet_keys(EndpointRole local_role, bool for_local_send,
                           const ConnectionId &client_initial_destination_connection_id);

CodecResult<PacketProtectionKeys> expand_traffic_secret(const TrafficSecret &secret);

} // namespace coquic::quic
