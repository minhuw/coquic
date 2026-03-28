#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "src/quic/congestion.h"
#include "src/quic/core.h"
#include "src/quic/crypto_stream.h"
#include "src/quic/recovery.h"
#include "src/quic/streams.h"
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
    std::map<std::uint64_t, SentPacketRecord> declared_lost_packets;
    PacketSpaceRecovery recovery;
    std::optional<SentPacketRecord> pending_probe_packet;
    std::optional<QuicCoreTimePoint> pending_ack_deadline;
    bool force_ack_send = false;
};

struct LocalResetCommand {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct LocalStopSendingCommand {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct ConnectionFlowControlState {
    std::uint64_t peer_max_data = 0;
    std::uint64_t highest_sent = 0;
    std::uint64_t local_receive_window = 0;
    std::uint64_t advertised_max_data = 0;
    std::uint64_t delivered_bytes = 0;
    std::uint64_t received_committed = 0;
    std::optional<MaxDataFrame> pending_max_data_frame;
    StreamControlFrameState max_data_state = StreamControlFrameState::none;
    std::optional<DataBlockedFrame> pending_data_blocked_frame;
    StreamControlFrameState data_blocked_state = StreamControlFrameState::none;

    std::uint64_t sendable_bytes(std::uint64_t queued_bytes) const;
    bool should_send_data_blocked(std::uint64_t queued_bytes) const;
    void note_peer_max_data(std::uint64_t maximum_data);
    void queue_max_data(std::uint64_t maximum_data);
    std::optional<MaxDataFrame> take_max_data_frame();
    void acknowledge_max_data_frame(const MaxDataFrame &frame);
    void mark_max_data_frame_lost(const MaxDataFrame &frame);
    void queue_data_blocked(std::uint64_t maximum_data);
    std::optional<DataBlockedFrame> take_data_blocked_frame();
    void acknowledge_data_blocked_frame(const DataBlockedFrame &frame);
    void mark_data_blocked_frame_lost(const DataBlockedFrame &frame);
};

struct LocalStreamLimitState {
    std::uint64_t advertised_max_streams_bidi = 0;
    std::uint64_t advertised_max_streams_uni = 0;
    std::optional<MaxStreamsFrame> pending_max_streams_bidi_frame;
    StreamControlFrameState max_streams_bidi_state = StreamControlFrameState::none;
    std::optional<MaxStreamsFrame> pending_max_streams_uni_frame;
    StreamControlFrameState max_streams_uni_state = StreamControlFrameState::none;

    void initialize(PeerStreamOpenLimits limits);
    void queue_max_streams(StreamLimitType stream_type, std::uint64_t maximum_streams);
    std::vector<MaxStreamsFrame> take_max_streams_frames();
    void acknowledge_max_streams_frame(const MaxStreamsFrame &frame);
    void mark_max_streams_frame_lost(const MaxStreamsFrame &frame);
};

class QuicConnection {
  public:
    explicit QuicConnection(QuicCoreConfig config);

    void start();
    void process_inbound_datagram(std::span<const std::byte> bytes, QuicCoreTimePoint now);
    StreamStateResult<bool> queue_stream_send(std::uint64_t stream_id,
                                              std::span<const std::byte> bytes, bool fin);
    StreamStateResult<bool> queue_stream_reset(LocalResetCommand command);
    StreamStateResult<bool> queue_stop_sending(LocalStopSendingCommand command);
    std::vector<std::byte> drain_outbound_datagram(QuicCoreTimePoint now);
    void on_timeout(QuicCoreTimePoint now);
    std::optional<QuicCoreReceiveStreamData> take_received_stream_data();
    std::optional<QuicCorePeerResetStream> take_peer_reset_stream();
    std::optional<QuicCorePeerStopSending> take_peer_stop_sending();
    std::optional<QuicCoreStateChange> take_state_change();
    std::optional<QuicCoreTimePoint> next_wakeup() const;
    bool is_handshake_complete() const;
    bool has_processed_peer_packet() const;
    bool has_failed() const;

  private:
    friend class QuicCore;

    void start_client_if_needed();
    void start_server_if_needed(const ConnectionId &client_initial_destination_connection_id,
                                std::uint32_t client_initial_version = kQuicVersion1);
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
    const RecoveryRttState &shared_recovery_rtt_state() const;
    void synchronize_recovery_rtt_state();
    void install_available_secrets();
    void collect_pending_tls_bytes();
    CodecResult<bool> sync_tls_state();
    CodecResult<bool> validate_peer_transport_parameters_if_ready();
    void update_handshake_status();
    void confirm_handshake();
    bool should_reset_client_handshake_peer_state(const ConnectionId &source_connection_id) const;
    void reset_client_handshake_peer_state_for_new_source_connection_id();
    void discard_initial_packet_space();
    void discard_handshake_packet_space();
    std::optional<TransportParametersValidationContext>
    peer_transport_parameters_validation_context() const;
    void initialize_local_flow_control();
    void initialize_peer_flow_control_from_transport_parameters();
    void initialize_stream_flow_control(StreamState &stream) const;
    std::uint64_t initial_stream_send_limit(std::uint64_t stream_id) const;
    std::uint64_t initial_stream_receive_window(std::uint64_t stream_id) const;
    StreamStateResult<StreamState *> get_or_open_local_stream(std::uint64_t stream_id);
    StreamStateResult<StreamState *> get_existing_receive_stream(std::uint64_t stream_id);
    CodecResult<StreamState *> get_or_open_receive_stream(std::uint64_t stream_id);
    CodecResult<StreamState *> get_or_open_send_stream(std::uint64_t stream_id);
    CodecResult<StreamState *> get_or_open_send_stream_for_peer_stop(std::uint64_t stream_id);
    PeerStreamOpenLimits peer_stream_open_limits() const;
    bool has_pending_application_send() const;
    std::uint64_t total_queued_stream_bytes() const;
    void maybe_queue_connection_blocked_frame();
    void maybe_queue_stream_blocked_frame(StreamState &stream);
    void maybe_refresh_connection_receive_credit(bool force);
    void maybe_refresh_stream_receive_credit(StreamState &stream, bool force);
    void maybe_refresh_peer_stream_limit(StreamState &stream);
    ConnectionId outbound_destination_connection_id() const;
    ConnectionId client_initial_destination_connection_id() const;
    std::vector<std::byte> flush_outbound_datagram(QuicCoreTimePoint now);
    void mark_failed();
    void queue_state_change(QuicCoreStateChange change);

    QuicCoreConfig config_;
    std::uint32_t original_version_;
    std::uint32_t current_version_;
    HandshakeStatus status_ = HandshakeStatus::idle;
    bool started_ = false;
    PacketSpaceState initial_space_;
    PacketSpaceState handshake_space_;
    PacketSpaceState zero_rtt_space_;
    PacketSpaceState application_space_;
    std::optional<TlsAdapter> tls_;
    TransportParameters local_transport_parameters_;
    std::optional<ConnectionId> peer_source_connection_id_;
    std::optional<ConnectionId> client_initial_destination_connection_id_;
    std::optional<TransportParameters> peer_transport_parameters_;
    bool peer_transport_parameters_validated_ = false;
    std::map<std::uint64_t, StreamState> streams_;
    ConnectionFlowControlState connection_flow_control_;
    StreamOpenLimits stream_open_limits_;
    LocalStreamLimitState local_stream_limit_state_;
    std::vector<QuicCoreReceiveStreamData> pending_stream_receive_effects_;
    std::vector<QuicCorePeerResetStream> pending_peer_reset_effects_;
    std::vector<QuicCorePeerStopSending> pending_peer_stop_effects_;
    std::vector<QuicCoreStateChange> pending_state_changes_;
    std::optional<std::uint64_t> last_application_send_stream_id_;
    NewRenoCongestionController congestion_controller_;
    RecoveryRttState recovery_rtt_state_;
    std::uint32_t pto_count_ = 0;
    std::uint8_t remaining_pto_probe_datagrams_ = 0;
    bool application_read_key_phase_ = false;
    bool application_write_key_phase_ = false;
    bool initial_packet_space_discarded_ = false;
    bool handshake_confirmed_ = false;
    StreamControlFrameState handshake_done_state_ = StreamControlFrameState::none;
    bool handshake_ready_emitted_ = false;
    bool failed_emitted_ = false;
    bool processed_peer_packet_ = false;
    std::vector<std::vector<std::byte>> deferred_protected_packets_;
    std::optional<QuicCoreTimePoint> last_peer_activity_time_;
    std::optional<QuicCoreTimePoint> last_client_handshake_keepalive_probe_time_;
};

} // namespace coquic::quic
