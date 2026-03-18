#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "src/quic/core.h"
#include "src/quic/crypto_stream.h"
#include "src/quic/tls_adapter.h"
#include "src/quic/transport_parameters.h"

namespace coquic::quic {

enum class HandshakeStatus : std::uint8_t {
    idle,
    in_progress,
    connected,
    failed,
};

struct PacketSpaceState {
    std::uint64_t next_send_packet_number = 0;
    std::optional<std::uint64_t> largest_authenticated_packet_number;
    std::optional<TrafficSecret> read_secret;
    std::optional<TrafficSecret> write_secret;
    CryptoSendBuffer send_crypto;
    CryptoReceiveBuffer receive_crypto;
};

class QuicConnection {
  public:
    explicit QuicConnection(QuicCoreConfig config);

    std::vector<std::byte> receive(std::span<const std::byte> bytes);
    bool is_handshake_complete() const;

  private:
    void start_client_if_needed();
    std::vector<std::byte> emit_initial_space();

    QuicCoreConfig config_;
    HandshakeStatus status_ = HandshakeStatus::idle;
    bool started_ = false;
    PacketSpaceState initial_space_;
    PacketSpaceState handshake_space_;
    PacketSpaceState application_space_;
    std::optional<TlsAdapter> tls_;
    TransportParameters local_transport_parameters_;
};

} // namespace coquic::quic
