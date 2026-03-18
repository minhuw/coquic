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
    void start_server_if_needed(const ConnectionId &client_initial_destination_connection_id);
    CodecResult<ConnectionId>
    peek_client_initial_destination_connection_id(std::span<const std::byte> bytes) const;
    CodecResult<std::size_t> peek_next_packet_length(std::span<const std::byte> bytes) const;
    CodecResult<bool> process_inbound_packet(const ProtectedPacket &packet);
    CodecResult<bool> process_inbound_crypto(EncryptionLevel level, std::span<const Frame> frames);
    void install_available_secrets();
    void collect_pending_tls_bytes();
    CodecResult<bool> sync_tls_state();
    CodecResult<bool> validate_peer_transport_parameters_if_ready();
    void update_handshake_status();
    std::optional<TransportParametersValidationContext>
    peer_transport_parameters_validation_context() const;
    ConnectionId outbound_destination_connection_id() const;
    ConnectionId client_initial_destination_connection_id() const;
    std::vector<std::byte> flush_outbound_datagram();

    QuicCoreConfig config_;
    HandshakeStatus status_ = HandshakeStatus::idle;
    bool started_ = false;
    PacketSpaceState initial_space_;
    PacketSpaceState handshake_space_;
    PacketSpaceState application_space_;
    std::optional<TlsAdapter> tls_;
    TransportParameters local_transport_parameters_;
    std::optional<ConnectionId> peer_source_connection_id_;
    std::optional<ConnectionId> client_initial_destination_connection_id_;
    std::optional<TransportParameters> peer_transport_parameters_;
    bool peer_transport_parameters_validated_ = false;
};

} // namespace coquic::quic
