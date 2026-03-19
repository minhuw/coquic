#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "src/quic/core.h"
#include "src/quic/crypto_stream.h"
#include "src/quic/recovery.h"
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
    ReliableSendBuffer send_crypto;
    ReliableReceiveBuffer receive_crypto;
    ReceivedPacketHistory received_packets;
    std::map<std::uint64_t, SentPacketRecord> sent_packets;
    PacketSpaceRecovery recovery;
    std::optional<SentPacketRecord> pending_probe_packet;
    std::optional<QuicCoreTimePoint> pending_ack_deadline;
};

class QuicConnection {
  public:
    explicit QuicConnection(QuicCoreConfig config);

    void start();
    void process_inbound_datagram(std::span<const std::byte> bytes, QuicCoreTimePoint now);
    void queue_application_data(std::span<const std::byte> bytes);
    std::vector<std::byte> drain_outbound_datagram(QuicCoreTimePoint now);
    void on_timeout(QuicCoreTimePoint now);
    std::vector<std::byte> take_received_application_data();
    std::optional<QuicCoreStateChange> take_state_change();
    std::optional<QuicCoreTimePoint> next_wakeup() const;
    bool is_handshake_complete() const;
    bool has_failed() const;

  private:
    void start_client_if_needed();
    void start_server_if_needed(const ConnectionId &client_initial_destination_connection_id);
    CodecResult<ConnectionId>
    peek_client_initial_destination_connection_id(std::span<const std::byte> bytes) const;
    CodecResult<std::size_t> peek_next_packet_length(std::span<const std::byte> bytes) const;
    CodecResult<bool> process_inbound_packet(const ProtectedPacket &packet, QuicCoreTimePoint now);
    CodecResult<bool> process_inbound_crypto(EncryptionLevel level, std::span<const Frame> frames,
                                             QuicCoreTimePoint now);
    CodecResult<bool> process_inbound_application(std::span<const Frame> frames,
                                                  QuicCoreTimePoint now);
    CodecResult<bool> process_inbound_ack(PacketSpaceState &packet_space, const AckFrame &ack,
                                          QuicCoreTimePoint now, std::uint64_t ack_delay_exponent,
                                          std::uint64_t max_ack_delay_ms, bool suppress_pto_reset);
    void track_sent_packet(PacketSpaceState &packet_space, const SentPacketRecord &packet);
    void retire_acked_packet(PacketSpaceState &packet_space, const SentPacketRecord &packet);
    void mark_lost_packet(PacketSpaceState &packet_space, const SentPacketRecord &packet);
    void rebuild_recovery(PacketSpaceState &packet_space);
    std::optional<QuicCoreTimePoint> loss_deadline() const;
    std::optional<QuicCoreTimePoint> pto_deadline() const;
    std::optional<QuicCoreTimePoint> ack_deadline() const;
    void detect_lost_packets(QuicCoreTimePoint now);
    void detect_lost_packets(PacketSpaceState &packet_space, QuicCoreTimePoint now);
    void arm_pto_probe(QuicCoreTimePoint now);
    std::optional<SentPacketRecord> select_pto_probe(const PacketSpaceState &packet_space) const;
    void install_available_secrets();
    void collect_pending_tls_bytes();
    CodecResult<bool> sync_tls_state();
    CodecResult<bool> validate_peer_transport_parameters_if_ready();
    void update_handshake_status();
    std::optional<TransportParametersValidationContext>
    peer_transport_parameters_validation_context() const;
    ConnectionId outbound_destination_connection_id() const;
    ConnectionId client_initial_destination_connection_id() const;
    std::vector<std::byte> flush_outbound_datagram(QuicCoreTimePoint now);
    void mark_failed();
    void queue_state_change(QuicCoreStateChange change);

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
    ReliableSendBuffer pending_application_send_;
    ReliableReceiveBuffer pending_application_receive_buffer_;
    std::vector<std::byte> pending_application_receive_;
    std::vector<QuicCoreStateChange> pending_state_changes_;
    std::uint32_t pto_count_ = 0;
    bool handshake_confirmed_ = false;
    bool handshake_ready_emitted_ = false;
    bool failed_emitted_ = false;
};

} // namespace coquic::quic
