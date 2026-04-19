#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "src/quic/congestion.h"
#include "src/quic/core.h"
#include "src/quic/crypto_stream.h"
#include "src/quic/qlog/fwd.h"
#include "src/quic/qlog/types.h"
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

enum class QuicConnectionTerminalState : std::uint8_t {
    closed,
    failed,
};

class PacketSpacePacketMapView {
  public:
    using Storage = std::map<std::uint64_t, SentPacketRecord>;
    using const_iterator = Storage::const_iterator;
    using const_reverse_iterator = Storage::const_reverse_iterator;

    enum class Filter : std::uint8_t {
        outstanding,
        declared_lost,
    };

    PacketSpacePacketMapView() = default;
    PacketSpacePacketMapView(PacketSpaceRecovery *recovery, Filter filter)
        : recovery_(recovery), filter_(filter) {
    }

    void bind(PacketSpaceRecovery *recovery, Filter filter) {
        recovery_ = recovery;
        filter_ = filter;
        last_synced_version_.reset();
        cache_.clear();
    }

    bool empty() const {
        sync();
        return cache_.empty();
    }

    std::size_t size() const {
        sync();
        return cache_.size();
    }

    bool contains(std::uint64_t packet_number) const {
        sync();
        return cache_.contains(packet_number);
    }

    const SentPacketRecord &at(std::uint64_t packet_number) const {
        sync();
        return cache_.at(packet_number);
    }

    std::pair<const_iterator, bool> emplace(std::uint64_t packet_number,
                                            const SentPacketRecord &packet) {
        sync();
        const auto existing = cache_.find(packet_number);
        if (existing != cache_.end()) {
            return {existing, false};
        }

        if (recovery_ == nullptr) {
            return {cache_.end(), false};
        }

        auto stored_packet = packet;
        stored_packet.packet_number = packet_number;
        if (filter_ == Filter::declared_lost) {
            stored_packet.declared_lost = true;
            stored_packet.in_flight = false;
            stored_packet.bytes_in_flight = 0;
        }

        recovery_->on_packet_sent(stored_packet);
        if (filter_ == Filter::declared_lost) {
            recovery_->on_packet_declared_lost(packet_number);
        }

        last_synced_version_.reset();
        sync();
        return {cache_.find(packet_number), true};
    }

    std::size_t erase(std::uint64_t packet_number) {
        sync();
        if (!cache_.contains(packet_number) || recovery_ == nullptr) {
            return 0;
        }

        recovery_->retire_packet(packet_number);
        last_synced_version_.reset();
        sync();
        return 1;
    }

    const_iterator begin() const {
        sync();
        return cache_.begin();
    }

    const_iterator end() const {
        sync();
        return cache_.end();
    }

    const_reverse_iterator rbegin() const {
        sync();
        return cache_.rbegin();
    }

    const_reverse_iterator rend() const {
        sync();
        return cache_.rend();
    }

  private:
    void sync() const {
        if (recovery_ == nullptr) {
            cache_.clear();
            last_synced_version_ = 0;
            return;
        }

        const auto version = recovery_->compatibility_version();
        if (last_synced_version_.has_value() && *last_synced_version_ == version) {
            return;
        }

        cache_.clear();
        for (const auto handle : recovery_->tracked_packets()) {
            const auto *packet = recovery_->packet_for_handle(handle);
            if (packet == nullptr) {
                continue;
            }

            const bool matches_filter =
                filter_ == Filter::declared_lost ? packet->declared_lost : !packet->declared_lost;
            if (!matches_filter) {
                continue;
            }

            cache_.emplace(packet->packet_number, *packet);
        }
        last_synced_version_ = version;
    }

    PacketSpaceRecovery *recovery_ = nullptr;
    Filter filter_ = Filter::outstanding;
    mutable std::optional<std::uint64_t> last_synced_version_;
    mutable Storage cache_;
};

struct PacketSpaceState {
    std::uint64_t next_send_packet_number = 0;
    std::optional<std::uint64_t> largest_authenticated_packet_number;
    std::optional<TrafficSecret> read_secret;
    std::optional<TrafficSecret> write_secret;
    ReliableSendBuffer send_crypto;
    ReliableReceiveBuffer receive_crypto;
    ReceivedPacketHistory received_packets;
    PacketSpaceRecovery recovery;
    PacketSpacePacketMapView sent_packets;
    PacketSpacePacketMapView declared_lost_packets;
    std::optional<SentPacketRecord> pending_probe_packet;
    std::optional<QuicCoreTimePoint> pending_ack_deadline;
    bool force_ack_send = false;

    PacketSpaceState()
        : sent_packets(&recovery, PacketSpacePacketMapView::Filter::outstanding),
          declared_lost_packets(&recovery, PacketSpacePacketMapView::Filter::declared_lost) {
    }

    PacketSpaceState(const PacketSpaceState &other) : PacketSpaceState() {
        *this = other;
    }

    PacketSpaceState(PacketSpaceState &&other) noexcept : PacketSpaceState() {
        *this = std::move(other);
    }

    PacketSpaceState &operator=(const PacketSpaceState &other) {
        if (this == &other) {
            return *this;
        }

        next_send_packet_number = other.next_send_packet_number;
        largest_authenticated_packet_number = other.largest_authenticated_packet_number;
        read_secret = other.read_secret;
        write_secret = other.write_secret;
        send_crypto = other.send_crypto;
        receive_crypto = other.receive_crypto;
        received_packets = other.received_packets;
        recovery = other.recovery;
        sent_packets.bind(&recovery, PacketSpacePacketMapView::Filter::outstanding);
        declared_lost_packets.bind(&recovery, PacketSpacePacketMapView::Filter::declared_lost);
        pending_probe_packet = other.pending_probe_packet;
        pending_ack_deadline = other.pending_ack_deadline;
        force_ack_send = other.force_ack_send;
        return *this;
    }

    PacketSpaceState &operator=(PacketSpaceState &&other) noexcept {
        if (this == &other) {
            return *this;
        }

        next_send_packet_number = other.next_send_packet_number;
        largest_authenticated_packet_number = other.largest_authenticated_packet_number;
        read_secret = std::move(other.read_secret);
        write_secret = std::move(other.write_secret);
        send_crypto = std::move(other.send_crypto);
        receive_crypto = std::move(other.receive_crypto);
        received_packets = std::move(other.received_packets);
        recovery = std::move(other.recovery);
        sent_packets.bind(&recovery, PacketSpacePacketMapView::Filter::outstanding);
        declared_lost_packets.bind(&recovery, PacketSpacePacketMapView::Filter::declared_lost);
        pending_probe_packet = std::move(other.pending_probe_packet);
        pending_ack_deadline = other.pending_ack_deadline;
        force_ack_send = other.force_ack_send;
        return *this;
    }
};

struct LocalResetCommand {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct LocalStopSendingCommand {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct LocalApplicationCloseCommand {
    std::uint64_t application_error_code = 0;
    std::string reason_phrase;
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

struct StoredClientResumptionState {
    std::vector<std::byte> tls_state;
    std::uint32_t quic_version = kQuicVersion1;
    std::string application_protocol;
    TransportParameters peer_transport_parameters;
    std::vector<std::byte> application_context;
};

struct DeferredProtectedDatagram {
    DatagramBuffer bytes;
    QuicPathId path_id = 0;
    std::optional<std::uint32_t> datagram_id;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;

    DeferredProtectedDatagram() = default;
    DeferredProtectedDatagram(DatagramBuffer datagram_bytes, QuicPathId id = 0,
                              std::optional<std::uint32_t> qlog_datagram_id = std::nullopt,
                              QuicEcnCodepoint datagram_ecn = QuicEcnCodepoint::unavailable)
        : bytes(std::move(datagram_bytes)), path_id(id), datagram_id(qlog_datagram_id),
          ecn(datagram_ecn) {
    }
    DeferredProtectedDatagram(const std::vector<std::byte> &datagram_bytes, QuicPathId id = 0,
                              std::optional<std::uint32_t> qlog_datagram_id = std::nullopt,
                              QuicEcnCodepoint datagram_ecn = QuicEcnCodepoint::unavailable)
        : DeferredProtectedDatagram(DatagramBuffer(datagram_bytes), id, qlog_datagram_id,
                                    datagram_ecn) {
    }
    DeferredProtectedDatagram(std::vector<std::byte> &&datagram_bytes, QuicPathId id = 0,
                              std::optional<std::uint32_t> qlog_datagram_id = std::nullopt,
                              QuicEcnCodepoint datagram_ecn = QuicEcnCodepoint::unavailable)
        : DeferredProtectedDatagram(DatagramBuffer(std::move(datagram_bytes)), id, qlog_datagram_id,
                                    datagram_ecn) {
    }

    bool operator==(const DeferredProtectedDatagram &) const = default;
};

inline bool operator==(const DeferredProtectedDatagram &lhs, const std::vector<std::byte> &rhs) {
    return lhs.bytes == rhs;
}

inline bool operator==(const std::vector<std::byte> &lhs, const DeferredProtectedDatagram &rhs) {
    return lhs == rhs.bytes;
}

struct DeferredProtectedPacket {
    DatagramBuffer bytes;
    std::uint32_t datagram_id = 0;

    DeferredProtectedPacket() = default;
    DeferredProtectedPacket(DatagramBuffer packet_bytes, std::uint32_t id = 0)
        : bytes(std::move(packet_bytes)), datagram_id(id) {
    }
    DeferredProtectedPacket(const std::vector<std::byte> &packet_bytes, std::uint32_t id = 0)
        : DeferredProtectedPacket(DatagramBuffer(packet_bytes), id) {
    }
    DeferredProtectedPacket(std::vector<std::byte> &&packet_bytes, std::uint32_t id = 0)
        : DeferredProtectedPacket(DatagramBuffer(std::move(packet_bytes)), id) {
    }

    operator DeferredProtectedDatagram() const {
        return DeferredProtectedDatagram{
            bytes,
            /*id=*/0,
            datagram_id == 0 ? std::nullopt : std::optional<std::uint32_t>(datagram_id),
        };
    }

    bool operator==(const DeferredProtectedPacket &) const = default;
    bool operator==(const std::vector<std::byte> &other) const {
        return datagram_id == 0 && bytes == other;
    }
};

inline bool operator==(const std::vector<std::byte> &lhs, const DeferredProtectedPacket &rhs) {
    return rhs == lhs;
}

struct PeerConnectionIdRecord {
    std::uint64_t sequence_number = 0;
    ConnectionId connection_id;
    std::array<std::byte, 16> stateless_reset_token{};
};

struct LocalConnectionIdRecord {
    std::uint64_t sequence_number = 0;
    ConnectionId connection_id;
    std::array<std::byte, 16> stateless_reset_token{};
    bool retired = false;
};

enum class QuicPathEcnState : std::uint8_t {
    probing,
    capable,
    failed,
};

struct PathEcnState {
    QuicPathEcnState state = QuicPathEcnState::probing;
    QuicEcnCodepoint transmit_mark = QuicEcnCodepoint::ect0;
    std::array<AckEcnCounts, 3> last_peer_counts{};
    std::array<bool, 3> has_last_peer_counts{};
    std::uint64_t total_sent_ect0 = 0;
    std::uint64_t total_sent_ect1 = 0;
    std::uint64_t probing_packets_sent = 0;
    std::uint64_t probing_packets_acked = 0;
    std::uint64_t probing_packets_lost = 0;
};

struct PathState {
    QuicPathId id = 0;
    bool validated = false;
    bool is_current_send_path = false;
    bool challenge_pending = false;
    bool validation_initiated_locally = false;
    std::uint64_t anti_amplification_received_bytes = 0;
    std::uint64_t anti_amplification_sent_bytes = 0;
    std::optional<std::array<std::byte, 8>> outstanding_challenge;
    std::optional<std::array<std::byte, 8>> pending_response;
    std::optional<QuicCoreTimePoint> validation_deadline;
    std::uint64_t peer_connection_id_sequence = 0;
    std::optional<ConnectionId> destination_connection_id_override;
    PathEcnState ecn;
};

// NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding)
class QuicConnection {
  public:
    explicit QuicConnection(QuicCoreConfig config);
    ~QuicConnection();
    QuicConnection(const QuicConnection &) = delete;
    QuicConnection &operator=(const QuicConnection &) = delete;
    QuicConnection(QuicConnection &&) noexcept;
    QuicConnection &operator=(QuicConnection &&) noexcept;

    void start();
    void start(QuicCoreTimePoint now);
    void process_inbound_datagram(std::span<const std::byte> bytes, QuicCoreTimePoint now,
                                  QuicPathId path_id = 0,
                                  QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable);
    StreamStateResult<bool> queue_stream_send(std::uint64_t stream_id,
                                              std::span<const std::byte> bytes, bool fin);
    StreamStateResult<bool> queue_stream_send_shared(std::uint64_t stream_id, SharedBytes bytes,
                                                     bool fin);
    StreamStateResult<bool> queue_stream_reset(LocalResetCommand command);
    StreamStateResult<bool> queue_stop_sending(LocalStopSendingCommand command);
    CodecResult<bool> request_connection_migration(QuicPathId path_id,
                                                   QuicMigrationRequestReason reason);
    StreamStateResult<bool> queue_application_close(LocalApplicationCloseCommand command);
    void request_key_update();
    DatagramBuffer drain_outbound_datagram(QuicCoreTimePoint now);
    void on_timeout(QuicCoreTimePoint now);
    std::optional<QuicCoreReceiveStreamData> take_received_stream_data();
    std::optional<QuicCorePeerResetStream> take_peer_reset_stream();
    std::optional<QuicCorePeerStopSending> take_peer_stop_sending();
    std::optional<QuicCoreStateChange> take_state_change();
    std::optional<QuicCorePeerPreferredAddressAvailable> take_peer_preferred_address_available();
    std::optional<QuicCoreResumptionStateAvailable> take_resumption_state_available();
    std::optional<QuicCoreZeroRttStatusEvent> take_zero_rtt_status_event();
    std::optional<QuicConnectionTerminalState> take_terminal_state();
    std::optional<QuicPathId> last_drained_path_id() const;
    QuicEcnCodepoint last_drained_ecn_codepoint() const;
    std::optional<QuicCoreTimePoint> next_wakeup() const;
    std::vector<ConnectionId> active_local_connection_ids() const;
    bool is_handshake_complete() const;
    bool has_processed_peer_packet() const;
    bool has_failed() const;

  private:
    friend class QuicCore;

    void start_client_if_needed();
    void start_client_if_needed(QuicCoreTimePoint now);
    void start_server_if_needed(const ConnectionId &client_initial_destination_connection_id,
                                std::uint32_t client_initial_version = kQuicVersion1);
    void start_server_if_needed(const ConnectionId &client_initial_destination_connection_id,
                                QuicCoreTimePoint now,
                                std::uint32_t client_initial_version = kQuicVersion1);
    void maybe_open_qlog_session(QuicCoreTimePoint now, const ConnectionId &odcid);
    void emit_local_qlog_startup_events(QuicCoreTimePoint now);
    void maybe_emit_remote_qlog_parameters(QuicCoreTimePoint now);
    void maybe_emit_qlog_alpn_information(QuicCoreTimePoint now);
    qlog::PacketSnapshot
    make_qlog_packet_snapshot(const ProtectedPacket &packet,
                              const qlog::PacketSnapshotContext &context) const;
    qlog::RecoveryMetricsSnapshot current_qlog_recovery_metrics() const;
    void maybe_emit_qlog_recovery_metrics(QuicCoreTimePoint now);
    void emit_qlog_packet_lost(const SentPacketRecord &packet, std::string_view trigger,
                               QuicCoreTimePoint now);
    void process_inbound_datagram(std::span<const std::byte> bytes, QuicCoreTimePoint now,
                                  QuicPathId path_id, QuicEcnCodepoint ecn,
                                  std::optional<std::uint32_t> inbound_datagram_id,
                                  bool replay_trigger, bool count_inbound_bytes);
    CodecResult<ConnectionId>
    peek_client_initial_destination_connection_id(std::span<const std::byte> bytes) const;
    CodecResult<std::size_t> peek_next_packet_length(std::span<const std::byte> bytes) const;
    CodecResult<bool> process_inbound_packet(const ProtectedPacket &packet, QuicCoreTimePoint now,
                                             QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable);
    CodecResult<bool>
    process_inbound_received_packet(const ReceivedProtectedPacket &packet, QuicCoreTimePoint now,
                                    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable);
    CodecResult<bool> process_inbound_crypto(EncryptionLevel level, std::span<const Frame> frames,
                                             QuicCoreTimePoint now);
    CodecResult<bool> process_inbound_received_crypto(EncryptionLevel level,
                                                      std::span<const ReceivedFrame> frames,
                                                      QuicCoreTimePoint now);
    CodecResult<bool> process_inbound_application(std::span<const Frame> frames,
                                                  QuicCoreTimePoint now,
                                                  bool allow_preconnected_frames = false,
                                                  QuicPathId path_id = 0);
    CodecResult<bool> process_inbound_received_application(std::span<const ReceivedFrame> frames,
                                                           QuicCoreTimePoint now,
                                                           bool allow_preconnected_frames = false,
                                                           QuicPathId path_id = 0);
    CodecResult<bool> process_inbound_ack(PacketSpaceState &packet_space, const AckFrame &ack,
                                          QuicCoreTimePoint now, std::uint64_t ack_delay_exponent,
                                          std::uint64_t max_ack_delay_ms, bool suppress_pto_reset);
    CodecResult<bool> process_inbound_ack(PacketSpaceState &packet_space,
                                          const ReceivedAckFrame &ack, QuicCoreTimePoint now,
                                          std::uint64_t ack_delay_exponent,
                                          std::uint64_t max_ack_delay_ms, bool suppress_pto_reset);
    CodecResult<bool> process_inbound_ack_cursor(
        PacketSpaceState &packet_space, AckRangeCursor cursor, std::uint64_t largest_acknowledged,
        std::chrono::milliseconds decoded_ack_delay, const std::optional<AckEcnCounts> &ecn_counts,
        std::string ack_ranges, QuicCoreTimePoint now, std::uint64_t max_ack_delay_ms,
        bool suppress_pto_reset);
    void track_sent_packet(PacketSpaceState &packet_space, const SentPacketRecord &packet);
    std::optional<SentPacketRecord> retire_acked_packet(PacketSpaceState &packet_space,
                                                        RecoveryPacketHandle handle);
    std::optional<SentPacketRecord> mark_lost_packet(PacketSpaceState &packet_space,
                                                     RecoveryPacketHandle handle,
                                                     bool already_marked_in_recovery = false);
    void rebuild_recovery(PacketSpaceState &packet_space);
    std::optional<QuicCoreTimePoint> loss_deadline() const;
    std::optional<QuicCoreTimePoint> pto_deadline() const;
    std::optional<QuicCoreTimePoint> ack_deadline() const;
    void detect_lost_packets(QuicCoreTimePoint now);
    void detect_lost_packets(PacketSpaceState &packet_space, QuicCoreTimePoint now);
    void arm_pto_probe(QuicCoreTimePoint now);
    std::optional<SentPacketRecord> select_pto_probe(const PacketSpaceState &packet_space) const;
    void queue_server_handshake_recovery_probes();
    const RecoveryRttState &shared_recovery_rtt_state() const;
    std::optional<QuicCoreTimePoint> zero_rtt_discard_deadline() const;
    void arm_server_zero_rtt_discard_deadline(QuicCoreTimePoint now);
    void maybe_discard_server_zero_rtt_packet_space(QuicCoreTimePoint now);
    void synchronize_recovery_rtt_state();
    void install_available_secrets();
    void collect_pending_tls_bytes();
    CodecResult<bool> sync_tls_state();
    void replay_deferred_protected_packets(QuicCoreTimePoint now);
    CodecResult<bool> validate_peer_transport_parameters_if_ready();
    void update_handshake_status();
    void confirm_handshake();
    PathState &ensure_path_state(QuicPathId path_id);
    void start_path_validation(QuicPathId path_id, bool initiated_locally);
    void queue_path_response(QuicPathId path_id, const std::array<std::byte, 8> &data);
    bool path_validation_timed_out(QuicPathId path_id, QuicCoreTimePoint now) const;
    CodecResult<bool> process_new_connection_id_frame(const NewConnectionIdFrame &frame);
    CodecResult<bool> process_retire_connection_id_frame(const RetireConnectionIdFrame &frame);
    void issue_spare_connection_ids();
    std::array<std::byte, 8> next_path_challenge_data(QuicPathId path_id);
    std::uint64_t select_peer_connection_id_sequence_for_path(QuicPathId path_id) const;
    ConnectionId active_peer_destination_connection_id() const;
    std::optional<NewConnectionIdFrame> take_pending_new_connection_id_frame();
    bool should_reset_client_handshake_peer_state(const ConnectionId &source_connection_id) const;
    void reset_client_handshake_peer_state_for_new_source_connection_id();
    bool packet_targets_discarded_long_header_space(std::span<const std::byte> packet_bytes) const;
    void discard_initial_packet_space();
    void discard_handshake_packet_space();
    std::optional<TransportParametersValidationContext>
    peer_transport_parameters_validation_context() const;
    void initialize_local_flow_control();
    void initialize_peer_flow_control_from_transport_parameters();
    void initialize_stream_flow_control(StreamState &stream) const;
    std::uint64_t initial_stream_send_limit(std::uint64_t stream_id) const;
    std::uint64_t initial_stream_receive_window(std::uint64_t stream_id) const;
    StreamState *find_stream_state(std::uint64_t stream_id);
    const StreamState *find_stream_state(std::uint64_t stream_id) const;
    void maybe_retire_stream(std::uint64_t stream_id);
    StreamStateResult<StreamState *> get_or_open_local_stream(std::uint64_t stream_id);
    StreamStateResult<StreamState *> get_existing_receive_stream(std::uint64_t stream_id);
    CodecResult<StreamState *> get_or_open_receive_stream(std::uint64_t stream_id);
    CodecResult<StreamState *> get_or_open_send_stream(std::uint64_t stream_id);
    CodecResult<StreamState *> get_or_open_send_stream_for_peer_stop(std::uint64_t stream_id);
    StreamStateResult<bool> queue_stream_send_impl(std::uint64_t stream_id,
                                                   std::span<const std::byte> owned_bytes,
                                                   std::optional<SharedBytes> shared_bytes,
                                                   bool fin);
    PeerStreamOpenLimits peer_stream_open_limits() const;
    bool has_pending_application_send() const;
    bool has_pending_fresh_application_stream_send() const;
    std::uint64_t total_queued_stream_bytes() const;
    void maybe_queue_connection_blocked_frame();
    void maybe_queue_stream_blocked_frame(StreamState &stream);
    void maybe_refresh_connection_receive_credit(bool force);
    void maybe_refresh_stream_receive_credit(StreamState &stream, bool force);
    void maybe_refresh_peer_stream_limit(StreamState &stream);
    bool is_probing_only(std::span<const Frame> frames) const;
    void maybe_switch_to_path(QuicPathId path_id, bool initiated_locally);
    bool anti_amplification_applies() const;
    bool anti_amplification_applies(QuicPathId path_id) const;
    std::uint64_t anti_amplification_send_budget() const;
    std::uint64_t anti_amplification_send_budget(QuicPathId path_id) const;
    std::size_t outbound_datagram_size_limit() const;
    void note_inbound_datagram_bytes(std::size_t bytes);
    void note_outbound_datagram_bytes(std::size_t bytes,
                                      std::optional<QuicPathId> path_id = std::nullopt);
    void mark_peer_address_validated();
    void disable_ecn_on_path(QuicPathId path_id);
    QuicEcnCodepoint outbound_ecn_codepoint_for_path(std::optional<QuicPathId> path_id) const;
    ConnectionId
    outbound_destination_connection_id(std::optional<QuicPathId> path_id = std::nullopt) const;
    ConnectionId client_initial_destination_connection_id() const;
    DatagramBuffer flush_outbound_datagram(QuicCoreTimePoint now);
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
    std::map<std::uint64_t, PeerConnectionIdRecord> peer_connection_ids_;
    std::map<std::uint64_t, LocalConnectionIdRecord> local_connection_ids_;
    std::map<QuicPathId, PathState> paths_;
    std::uint64_t active_peer_connection_id_sequence_ = 0;
    std::uint64_t active_local_connection_id_sequence_ = 0;
    std::uint64_t next_local_connection_id_sequence_ = 1;
    std::uint64_t next_path_challenge_sequence_ = 1;
    bool peer_transport_parameters_validated_ = false;
    bool peer_address_validated_ = false;
    std::uint64_t anti_amplification_received_bytes_ = 0;
    std::uint64_t anti_amplification_sent_bytes_ = 0;
    std::map<std::uint64_t, StreamState> streams_;
    std::map<std::uint64_t, StreamState> retired_streams_;
    ConnectionFlowControlState connection_flow_control_;
    StreamOpenLimits stream_open_limits_;
    LocalStreamLimitState local_stream_limit_state_;
    std::vector<QuicCoreReceiveStreamData> pending_stream_receive_effects_;
    std::vector<QuicCorePeerResetStream> pending_peer_reset_effects_;
    std::vector<QuicCorePeerStopSending> pending_peer_stop_effects_;
    std::vector<QuicCoreStateChange> pending_state_changes_;
    std::optional<QuicCorePeerPreferredAddressAvailable> pending_preferred_address_effect_;
    std::optional<QuicCoreResumptionStateAvailable> pending_resumption_state_effect_;
    std::optional<QuicCoreZeroRttStatusEvent> pending_zero_rtt_status_event_;
    std::optional<QuicConnectionTerminalState> pending_terminal_state_;
    std::vector<NewConnectionIdFrame> pending_new_connection_id_frames_;
    std::vector<RetireConnectionIdFrame> pending_retire_connection_id_frames_;
    std::optional<StoredClientResumptionState> decoded_resumption_state_;
    std::optional<std::uint64_t> last_application_send_stream_id_;
    NewRenoCongestionController congestion_controller_;
    RecoveryRttState recovery_rtt_state_;
    std::uint32_t pto_count_ = 0;
    std::uint8_t remaining_pto_probe_datagrams_ = 0;
    bool application_read_key_phase_ = false;
    bool application_write_key_phase_ = false;
    bool local_key_update_requested_ = false;
    bool local_key_update_initiated_ = false;
    std::optional<std::uint64_t> current_write_phase_first_packet_number_;
    std::optional<TrafficSecret> previous_application_read_secret_;
    bool previous_application_read_key_phase_ = false;
    bool initial_packet_space_discarded_ = false;
    bool handshake_packet_space_discarded_ = false;
    bool handshake_confirmed_ = false;
    StreamControlFrameState handshake_done_state_ = StreamControlFrameState::none;
    bool handshake_ready_emitted_ = false;
    bool handshake_confirmed_emitted_ = false;
    bool failed_emitted_ = false;
    bool peer_preferred_address_emitted_ = false;
    bool resumption_state_emitted_ = false;
    bool zero_rtt_attempted_event_emitted_ = false;
    bool processed_peer_packet_ = false;
    bool local_application_close_sent_ = false;
    std::optional<ApplicationConnectionCloseFrame> pending_application_close_;
    std::unique_ptr<qlog::Session> qlog_session_;
    std::vector<DeferredProtectedDatagram> deferred_protected_packets_;
    std::optional<QuicCoreTimePoint> last_peer_activity_time_;
    std::optional<QuicCoreTimePoint> last_client_handshake_keepalive_probe_time_;
    std::optional<QuicCoreTimePoint> send_burst_resume_deadline_;
    std::optional<QuicCoreTimePoint> send_burst_reference_time_;
    std::size_t send_burst_datagrams_sent_ = 0;
    std::optional<QuicCoreTimePoint> server_zero_rtt_discard_deadline_;
    std::optional<QuicPathId> last_validated_path_id_;
    std::optional<QuicPathId> previous_path_id_;
    std::optional<QuicPathId> current_send_path_id_;
    std::optional<QuicPathId> last_drained_path_id_;
    QuicEcnCodepoint last_drained_ecn_codepoint_ = QuicEcnCodepoint::not_ect;
    QuicPathId last_inbound_path_id_ = 0;
};

} // namespace coquic::quic
