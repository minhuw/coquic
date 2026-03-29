#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "src/quic/protected_codec.h"

namespace coquic::quic::test {
class TlsAdapterTestPeer;
}

namespace coquic::quic {

enum class EncryptionLevel : std::uint8_t {
    initial,
    handshake,
    zero_rtt,
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
    std::string application_protocol = "coquic";
    std::optional<TlsIdentity> identity;
    std::vector<std::byte> local_transport_parameters;
    std::vector<CipherSuite> allowed_tls_cipher_suites;
    std::optional<std::vector<std::byte>> resumption_state;
    bool attempt_zero_rtt = false;
    bool accept_zero_rtt = false;
    std::vector<std::byte> zero_rtt_context;
};

class TlsAdapter {
  public:
    explicit TlsAdapter(TlsAdapterConfig config);
    ~TlsAdapter();

    TlsAdapter(const TlsAdapter &) = delete;
    TlsAdapter &operator=(const TlsAdapter &) = delete;
    TlsAdapter(TlsAdapter &&) noexcept;
    TlsAdapter &operator=(TlsAdapter &&) noexcept;

    CodecResult<bool> start();
    CodecResult<bool> provide(EncryptionLevel level, std::span<const std::byte> bytes);
    void poll();
    std::vector<std::byte> take_pending(EncryptionLevel level);
    std::vector<AvailableTrafficSecret> take_available_secrets();
    std::optional<std::vector<std::byte>> take_resumption_state();
    const std::optional<std::vector<std::byte>> &resumed_resumption_state() const;
    const std::optional<std::vector<std::byte>> &peer_transport_parameters() const;
    bool early_data_attempted() const;
    std::optional<bool> early_data_accepted() const;
    bool handshake_complete() const;

  private:
    friend class test::TlsAdapterTestPeer;
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace coquic::quic
