#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "src/quic/protected_codec.h"

namespace coquic::quic {

enum class EncryptionLevel : std::uint8_t {
    initial,
    handshake,
    application,
};

struct TlsIdentity {
    std::string certificate_pem;
    std::string private_key_pem;
};

struct AvailableTrafficSecret {
    EncryptionLevel level = EncryptionLevel::initial;
    EndpointRole sender = EndpointRole::client;
    TrafficSecret secret;
};

struct TlsAdapterConfig {
    EndpointRole role = EndpointRole::client;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::optional<TlsIdentity> identity;
    std::vector<std::byte> local_transport_parameters;
};

class TlsAdapter {
  public:
    explicit TlsAdapter(TlsAdapterConfig config);

    CodecResult<bool> start();
    CodecResult<bool> provide(EncryptionLevel level, std::span<const std::byte> bytes);
    void poll();
    std::vector<std::byte> take_pending(EncryptionLevel level);
    std::vector<AvailableTrafficSecret> take_available_secrets();
    const std::optional<std::vector<std::byte>> &peer_transport_parameters() const;
    bool handshake_complete() const;
};

} // namespace coquic::quic
