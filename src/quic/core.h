#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "src/quic/packet.h"
#include "src/quic/tls_adapter.h"

namespace coquic::quic {

struct QuicCoreConfig {
    EndpointRole role = EndpointRole::client;
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::optional<TlsIdentity> identity;
};

class QuicConnection;

class QuicCore {
  public:
    explicit QuicCore(QuicCoreConfig config);
    ~QuicCore();

    QuicCore(const QuicCore &) = delete;
    QuicCore &operator=(const QuicCore &) = delete;
    QuicCore(QuicCore &&) noexcept;
    QuicCore &operator=(QuicCore &&) noexcept;

    std::vector<std::byte> receive(std::vector<std::byte> bytes);
    bool is_handshake_complete() const;

  private:
    std::unique_ptr<QuicConnection> connection_;
};

} // namespace coquic::quic
