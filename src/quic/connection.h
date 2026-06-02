#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
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

namespace test {
struct ConnectionCoverageTestPeer;
bool core_endpoint_internal_coverage_for_tests();
bool connection_helper_edge_cases_for_tests();
bool connection_header_packet_space_coverage_for_tests();
bool connection_key_update_and_probe_coverage_for_tests();
bool connection_pmtud_coverage_for_tests();
} // namespace test

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

enum class QuicConnectionCloseMode : std::uint8_t {
    none,
    closing,
    draining,
};

enum class QuicTransportErrorCode : std::uint64_t { // NOLINT(performance-enum-size)
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
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
        if (!cache_.contains(packet_number)) {
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
    std::uint64_t optimistic_ack_skip_counter = 0;
    std::deque<std::uint64_t> optimistic_ack_skipped_packet_numbers;
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
        optimistic_ack_skip_counter = other.optimistic_ack_skip_counter;
        optimistic_ack_skipped_packet_numbers = other.optimistic_ack_skipped_packet_numbers;
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
        optimistic_ack_skip_counter = other.optimistic_ack_skip_counter;
        optimistic_ack_skipped_packet_numbers =
            std::move(other.optimistic_ack_skipped_packet_numbers);
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

struct StatelessResetTokenRecord {
    ConnectionId connection_id;
    std::array<std::byte, 16> stateless_reset_token{};
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
    explicit DeferredProtectedDatagram(
        DatagramBuffer datagram_bytes, QuicPathId id = 0,
        std::optional<std::uint32_t> qlog_datagram_id = std::nullopt,
        QuicEcnCodepoint datagram_ecn = QuicEcnCodepoint::unavailable)
        : bytes(std::move(datagram_bytes)), path_id(id), datagram_id(qlog_datagram_id),
          ecn(datagram_ecn) {
    }
    explicit DeferredProtectedDatagram(
        const std::vector<std::byte> &datagram_bytes, QuicPathId id = 0,
        std::optional<std::uint32_t> qlog_datagram_id = std::nullopt,
        QuicEcnCodepoint datagram_ecn = QuicEcnCodepoint::unavailable)
        : DeferredProtectedDatagram(DatagramBuffer(datagram_bytes), id, qlog_datagram_id,
                                    datagram_ecn) {
    }
    explicit DeferredProtectedDatagram(
        std::vector<std::byte> &&datagram_bytes, QuicPathId id = 0,
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
    explicit DeferredProtectedPacket(DatagramBuffer packet_bytes, std::uint32_t id = 0)
        : bytes(std::move(packet_bytes)), datagram_id(id) {
    }
    explicit DeferredProtectedPacket(const std::vector<std::byte> &packet_bytes,
                                     std::uint32_t id = 0)
        : DeferredProtectedPacket(DatagramBuffer(packet_bytes), id) {
    }
    explicit DeferredProtectedPacket(std::vector<std::byte> &&packet_bytes, std::uint32_t id = 0)
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
    std::optional<std::array<std::byte, 16>> stateless_reset_token;
    bool locally_retired = false;
    bool retire_frame_in_flight = false;
};

struct LocalConnectionIdRecord {
    std::uint64_t sequence_number = 0;
    ConnectionId connection_id;
    std::array<std::byte, 16> stateless_reset_token{};
    bool retired = false;
    bool retirement_requested = false;
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

struct PathSpinState {
    bool disabled = true;
    bool value = false;
    std::optional<std::uint64_t> largest_peer_packet_number;
};

struct PathMtuState {
    bool enabled = true;
    bool viable = true;
    std::size_t base_datagram_size = 1200;
    std::size_t validated_datagram_size = 1200;
    std::size_t probe_ceiling = 1200;
    std::size_t search_low = 1200;
    std::optional<std::size_t> outstanding_probe_size;
    std::optional<std::uint64_t> outstanding_probe_packet_number;
    std::optional<QuicCoreTimePoint> next_probe_time;
    std::vector<std::size_t> failed_probe_sizes;
};

struct PathState {
    QuicPathId id = 0;
    bool validated = false;
    bool is_current_send_path = false;
    bool preferred_address_path = false;
    bool challenge_pending = false;
    bool validation_initiated_locally = false;
    std::uint64_t anti_amplification_received_bytes = 0;
    std::uint64_t anti_amplification_sent_bytes = 0;
    std::optional<std::array<std::byte, 8>> outstanding_challenge;
    std::optional<std::array<std::byte, 8>> pending_response;
    std::optional<QuicCoreTimePoint> validation_deadline;
    std::uint64_t peer_connection_id_sequence = 0;
    std::optional<ConnectionId> destination_connection_id_override;
    std::optional<std::uint64_t> largest_inbound_application_packet_number;
    PathEcnState ecn;
    PathSpinState spin;
    PathMtuState mtu;
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
    CodecResult<bool> queue_datagram_send(std::span<const std::byte> bytes);
    CodecResult<bool> queue_datagram_send_shared(SharedBytes bytes);
    StreamStateResult<bool> queue_stream_reset(LocalResetCommand command);
    StreamStateResult<bool> queue_stop_sending(LocalStopSendingCommand command);
    CodecResult<bool> request_connection_migration(QuicPathId path_id,
                                                   QuicMigrationRequestReason reason,
                                                   QuicCoreTimePoint now = QuicCoreClock::now());
    void apply_path_mtu_update(QuicPathId path_id, std::size_t max_udp_payload_size);
    StreamStateResult<bool> queue_application_close(LocalApplicationCloseCommand command);
    void queue_new_token(std::vector<std::byte> token);
    void request_key_update();
    DatagramBuffer drain_outbound_datagram(QuicCoreTimePoint now);
    DatagramBuffer drain_outbound_datagram(QuicCoreTimePoint now, bool continue_paced_burst);
    void on_timeout(QuicCoreTimePoint now);
    std::optional<QuicCoreReceiveStreamData> take_received_stream_data();
    std::optional<QuicCoreReceiveDatagramData> take_received_datagram_data();
    std::optional<QuicCorePeerResetStream> take_peer_reset_stream();
    std::optional<QuicCorePeerStopSending> take_peer_stop_sending();
    std::optional<QuicCoreStateChange> take_state_change();
    std::optional<QuicCorePeerPreferredAddressAvailable> take_peer_preferred_address_available();
    std::optional<QuicCoreResumptionStateAvailable> take_resumption_state_available();
    std::optional<QuicCoreZeroRttStatusEvent> take_zero_rtt_status_event();
    std::optional<QuicConnectionTerminalState> take_terminal_state();
    std::optional<QuicCorePacketInspection> take_packet_inspection();
    std::optional<std::vector<std::byte>> take_new_token();
    std::optional<QuicPathId> last_drained_path_id() const;
    QuicEcnCodepoint last_drained_ecn_codepoint() const;
    bool last_drained_is_pmtu_probe() const;
    bool last_drained_allows_send_continuation() const;
    std::uint64_t last_drained_packet_inspection_datagram_id() const;
    bool has_sendable_datagram(QuicCoreTimePoint now) const;
    bool has_sendable_datagram(QuicCoreTimePoint now, bool continue_paced_burst) const;
    std::optional<QuicCoreTimePoint> next_wakeup() const;
    std::vector<ConnectionId> active_local_connection_ids() const;
    std::vector<StatelessResetTokenRecord> active_local_stateless_reset_tokens() const;
    std::vector<StatelessResetTokenRecord> peer_stateless_reset_tokens() const;
    std::uint64_t endpoint_route_generation() const;
    bool is_handshake_complete() const;
    bool has_processed_peer_packet() const;
    bool has_failed() const;
    bool close_state_active() const;
    bool terminal_state_expired(QuicCoreTimePoint now) const;
    void enter_stateless_reset_draining(QuicCoreTimePoint now);
    QuicCoreConnectionDiagnostics diagnostics(QuicConnectionHandle handle) const;

  private:
    struct PendingTrackedPacketScratch {
        PacketSpaceState *packet_space = nullptr;
        SentPacketRecord packet;
        std::size_t packet_index = 0;
        std::size_t fallback_packet_length = 0;
    };

    friend class QuicCore;
    friend struct test::ConnectionCoverageTestPeer;
    friend bool test::core_endpoint_internal_coverage_for_tests();
    friend bool test::connection_helper_edge_cases_for_tests();
    friend bool test::connection_header_packet_space_coverage_for_tests();
    friend bool test::connection_key_update_and_probe_coverage_for_tests();
    friend bool test::connection_pmtud_coverage_for_tests();

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
    void process_inbound_datagram_owned(std::vector<std::byte> bytes, QuicCoreTimePoint now,
                                        QuicPathId path_id, QuicEcnCodepoint ecn);
    void process_inbound_datagram_shared(std::shared_ptr<std::vector<std::byte>> storage,
                                         std::size_t begin, std::size_t end, QuicCoreTimePoint now,
                                         QuicPathId path_id, QuicEcnCodepoint ecn);
    void process_inbound_datagram(std::span<const std::byte> bytes, QuicCoreTimePoint now,
                                  QuicPathId path_id, QuicEcnCodepoint ecn,
                                  std::optional<std::uint32_t> inbound_datagram_id,
                                  bool replay_trigger, bool count_inbound_bytes);
    void process_inbound_datagram(std::shared_ptr<std::vector<std::byte>> storage,
                                  std::size_t begin, std::size_t end, QuicCoreTimePoint now,
                                  QuicPathId path_id, QuicEcnCodepoint ecn,
                                  std::optional<std::uint32_t> inbound_datagram_id,
                                  bool replay_trigger, bool count_inbound_bytes,
                                  bool allow_in_place_receive_decode);
    CodecResult<ConnectionId>
    peek_client_initial_destination_connection_id(std::span<const std::byte> bytes) const;
    CodecResult<std::size_t> peek_next_packet_length(std::span<const std::byte> bytes) const;
    CodecResult<bool> process_inbound_packet(const ProtectedPacket &packet, QuicCoreTimePoint now,
                                             QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable,
                                             bool used_previous_application_read_secret = false);
    CodecResult<bool>
    process_inbound_received_packet(const ReceivedProtectedPacket &packet, QuicCoreTimePoint now,
                                    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable,
                                    bool used_previous_application_read_secret = false);
    CodecResult<bool> process_inbound_crypto(EncryptionLevel level, std::span<const Frame> frames,
                                             QuicCoreTimePoint now);
    CodecResult<bool> process_inbound_received_crypto(EncryptionLevel level,
                                                      std::span<const ReceivedFrame> frames,
                                                      QuicCoreTimePoint now);
    CodecResult<bool>
    process_inbound_application(std::span<const Frame> frames, QuicCoreTimePoint now,
                                bool allow_preconnected_frames = false, QuicPathId path_id = 0,
                                bool used_previous_application_read_secret = false,
                                std::optional<std::uint64_t> packet_number = std::nullopt);
    CodecResult<bool> process_inbound_received_application(
        std::span<const ReceivedFrame> frames, QuicCoreTimePoint now,
        bool allow_preconnected_frames = false, QuicPathId path_id = 0,
        bool used_previous_application_read_secret = false,
        std::optional<std::uint64_t> packet_number = std::nullopt);
    CodecResult<bool>
    process_inbound_received_application_stream(const ReceivedStreamFrame &stream_frame,
                                                bool require_connected);
    CodecResult<bool>
    process_inbound_received_application_stream_packet(std::uint64_t packet_number, bool spin_bit,
                                                       const ReceivedStreamFrame &stream_frame,
                                                       QuicCoreTimePoint now, QuicEcnCodepoint ecn);
    CodecResult<bool> process_inbound_received_application_ack_only(
        std::uint64_t packet_number, bool spin_bit, const ReceivedAckFrame &ack,
        QuicCoreTimePoint now, QuicEcnCodepoint ecn, QuicPathId path_id,
        bool used_previous_application_read_secret = false);
    CodecResult<bool> process_inbound_ack(PacketSpaceState &packet_space, const AckFrame &ack,
                                          QuicCoreTimePoint now, std::uint64_t ack_delay_exponent,
                                          std::uint64_t max_ack_delay_ms, bool suppress_pto_reset,
                                          bool used_previous_application_read_secret = false);
    CodecResult<bool> process_inbound_ack(PacketSpaceState &packet_space,
                                          const ReceivedAckFrame &ack, QuicCoreTimePoint now,
                                          std::uint64_t ack_delay_exponent,
                                          std::uint64_t max_ack_delay_ms, bool suppress_pto_reset,
                                          bool used_previous_application_read_secret = false);
    CodecResult<bool> detect_old_key_ack_of_current_key_phase_packet(PacketSpaceState &packet_space,
                                                                     AckRangeCursor cursor,
                                                                     QuicCoreTimePoint now);
    CodecResult<bool> process_inbound_ack_cursor(
        PacketSpaceState &packet_space, AckRangeCursor cursor, std::uint64_t largest_acknowledged,
        std::chrono::microseconds decoded_ack_delay, const std::optional<AckEcnCounts> &ecn_counts,
        const std::string &ack_ranges, QuicCoreTimePoint now, std::uint64_t max_ack_delay_ms,
        bool suppress_pto_reset);
    void maybe_update_rtt_before_ack_loss_detection(PacketSpaceState &packet_space,
                                                    AckRangeCursor cursor,
                                                    std::uint64_t largest_acknowledged,
                                                    QuicCoreTimePoint now,
                                                    std::chrono::microseconds decoded_ack_delay,
                                                    std::uint64_t max_ack_delay_ms);
    void reset_recovery_for_new_path(QuicPathId path_id);
    void track_sent_packet(PacketSpaceState &packet_space, SentPacketRecord packet);
    bool try_retire_simple_stream_acked_packet(
        PacketSpaceState &packet_space, RecoveryPacketHandle handle,
        std::vector<SentPacketRecord> &acked_packets,
        std::vector<AckedStreamPacketSample> &simple_stream_ack_samples,
        bool use_lightweight_sample);
    bool try_ack_simple_congestion_batch(
        std::span<const AckedStreamPacketSample> simple_stream_ack_samples,
        std::span<const SentPacketRecord> acked_packets, QuicCoreTimePoint now,
        const RecoveryRttState &rtt_state);
    bool can_use_simple_stream_ack_fast_path(std::span<const SentPacketRecord> acked_packets,
                                             bool has_late_acked_packets) const;
    bool try_ack_simple_stream_fast_path(
        PacketSpaceState &packet_space, const AckApplyResult &ack_result,
        std::span<const AckedStreamPacketSample> simple_stream_ack_samples,
        std::span<const SentPacketRecord> acked_packets, QuicCoreTimePoint now,
        const std::optional<AckEcnCounts> &ecn_counts, bool suppress_pto_reset);
    bool process_simple_stream_ack_ecn(
        PacketSpaceState &packet_space,
        std::span<const AckedStreamPacketSample> simple_stream_ack_samples,
        const std::optional<AckEcnCounts> &ecn_counts,
        std::optional<QuicCoreTimePoint> &latest_ecn_ce_sent_time);
    bool process_single_path_simple_stream_ack_ecn(
        PacketSpaceState &packet_space,
        QuicPathId path_id, // NOLINT(bugprone-easily-swappable-parameters)
        std::uint64_t newly_acked_ect0, std::uint64_t newly_acked_ect1,
        QuicCoreTimePoint latest_marked_sent_time, const std::optional<AckEcnCounts> &ecn_counts,
        std::optional<QuicCoreTimePoint> &latest_ecn_ce_sent_time);
    bool try_ack_simple_congestion_batch(std::span<const SentPacketRecord> acked_packets,
                                         QuicCoreTimePoint now, const RecoveryRttState &rtt_state);
    std::optional<SentPacketRecord> retire_acked_packet(PacketSpaceState &packet_space,
                                                        RecoveryPacketHandle handle);
    std::optional<SentPacketRecord>
    mark_lost_packet(PacketSpaceState &packet_space, RecoveryPacketHandle handle,
                     bool already_marked_in_recovery = false,
                     std::optional<QuicCoreTimePoint> now = std::nullopt);
    void rebuild_recovery(PacketSpaceState &packet_space);
    std::optional<QuicCoreTimePoint> loss_deadline() const;
    std::optional<QuicCoreTimePoint> pto_deadline() const;
    std::optional<QuicCoreTimePoint> ack_deadline() const;
    std::optional<QuicCoreTimePoint> pacing_deadline() const;
    std::optional<QuicCoreTimePoint> non_pacing_wakeup_deadline() const;
    bool non_pacing_wakeup_due(QuicCoreTimePoint now) const;
    std::optional<QuicCoreTimePoint> idle_timeout_deadline() const;
    void detect_lost_packets(QuicCoreTimePoint now);
    void detect_lost_packets(PacketSpaceState &packet_space, QuicCoreTimePoint now);
    void arm_pto_probe(QuicCoreTimePoint now);
    bool packet_space_discarded(const PacketSpaceState &packet_space) const;
    SentPacketRecord select_pto_probe(const PacketSpaceState &packet_space) const;
    void queue_client_handshake_recovery_probe();
    void queue_server_handshake_recovery_probes();
    const RecoveryRttState &shared_recovery_rtt_state() const;
    std::optional<QuicCoreTimePoint> zero_rtt_discard_deadline() const;
    void arm_server_zero_rtt_discard_deadline(QuicCoreTimePoint now);
    void maybe_discard_server_zero_rtt_packet_space(QuicCoreTimePoint now);
    void retain_previous_application_read_secret(QuicCoreTimePoint now);
    CodecResult<bool> refresh_next_application_read_secret();
    CodecResult<bool> ensure_next_application_read_secret();
    void promote_next_application_read_secret();
    CodecResult<DeserializeProtectionContext> make_current_short_header_deserialize_context();
    void reset_current_short_header_deserialize_context_cache();
    std::optional<QuicCoreTimePoint> previous_application_read_secret_discard_deadline() const;
    void maybe_discard_previous_application_read_secret(QuicCoreTimePoint now);
    void synchronize_recovery_rtt_state();
    QuicCoreDuration path_validation_timeout_period() const;
    void install_available_secrets();
    void collect_pending_tls_bytes();
    CodecResult<bool> sync_tls_state();
    bool can_skip_outbound_tls_sync() const;
    void replay_deferred_protected_packets(QuicCoreTimePoint now);
    std::size_t queue_outbound_packet_inspections(const SerializedProtectedDatagram &datagram,
                                                  std::uint64_t datagram_id);
    CodecResult<bool> validate_peer_transport_parameters_if_ready();
    void update_handshake_status();
    void confirm_handshake();
    PathState &ensure_path_state(QuicPathId path_id);
    void start_path_validation(QuicPathId path_id, bool initiated_locally,
                               QuicCoreTimePoint now = QuicCoreClock::now());
    void queue_path_response(QuicPathId path_id, const std::array<std::byte, 8> &data);
    void respond_to_path_challenge(QuicPathId path_id, const std::array<std::byte, 8> &data);
    bool path_validation_timed_out(QuicPathId path_id, QuicCoreTimePoint now) const;
    static bool
    should_skip_packet_number_for_optimistic_ack_detection(const PacketSpaceState &packet_space,
                                                           std::uint64_t packet_number);
    std::uint64_t reserve_packet_number(PacketSpaceState &packet_space);
    bool ack_ranges_include_unsent_packet_number(const PacketSpaceState &packet_space,
                                                 AckRangeCursor cursor) const;
    CodecResult<bool> reject_optimistic_ack_if_detected(PacketSpaceState &packet_space,
                                                        AckRangeCursor cursor,
                                                        QuicCoreTimePoint now);
    CodecResult<bool> process_new_connection_id_frame(const NewConnectionIdFrame &frame);
    CodecResult<bool> process_retire_connection_id_frame(const RetireConnectionIdFrame &frame);
    CodecResult<bool> ensure_peer_preferred_address_connection_id();
    void queue_peer_connection_id_retirement(std::uint64_t sequence_number);
    void refresh_peer_connection_id_sequences_after_retirement();
    void issue_spare_connection_ids();
    void issue_path_probe_replacement_connection_id();
    std::array<std::byte, 8> next_path_challenge_data(QuicPathId path_id);
    std::optional<std::uint64_t>
    select_peer_connection_id_sequence_for_path(QuicPathId path_id) const;
    std::optional<std::uint64_t>
    select_unused_peer_connection_id_sequence_for_path(QuicPathId path_id) const;
    bool rotate_peer_connection_id_for_path(QuicPathId path_id);
    ConnectionId active_peer_destination_connection_id() const;
    std::optional<NewConnectionIdFrame> take_pending_new_connection_id_frame();
    bool should_reset_client_handshake_peer_state(const ConnectionId &source_connection_id) const;
    void reset_client_handshake_peer_state_for_new_source_connection_id();
    bool packet_targets_discarded_long_header_space(std::span<const std::byte> packet_bytes) const;
    void discard_packet_space_state(PacketSpaceState &packet_space);
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
    void maybe_emit_zero_rtt_attempted_event();
    PeerStreamOpenLimits peer_stream_open_limits() const;
    bool has_pending_application_send() const;
    bool has_pending_congestion_controlled_send() const;
    bool has_pending_fresh_application_stream_send() const;
    bool has_pending_application_control_send(bool application_ack_due) const;
    bool has_application_space_sendable_data(bool application_ack_due) const;
    std::optional<std::size_t> minimum_pending_application_stream_wire_bytes() const;
    std::optional<std::size_t> minimum_pending_application_stream_datagram_bytes() const;
    std::optional<std::size_t> minimum_pending_application_datagram_wire_bytes() const;
    std::optional<std::size_t> minimum_pending_application_datagram_datagram_bytes() const;
    std::optional<std::size_t> application_stream_pacing_deadline_bytes() const;
    std::optional<std::size_t> application_stream_pacing_deadline_bytes(
        std::optional<std::size_t> minimum_datagram_bytes) const;
    std::uint64_t cached_total_queued_stream_bytes() const;
    std::uint64_t total_queued_stream_bytes() const;
    std::uint64_t fresh_sendable_stream_bytes() const;
    std::uint64_t cached_fresh_sendable_stream_bytes() const;
    std::uint64_t streams_with_lost_send_data() const;
    bool has_lost_application_stream_data() const;
    void refresh_active_queued_stream_bytes();
    void refresh_fresh_sendable_stream_bytes();
    void refresh_stream_lost_send_data_count();
    void refresh_stream_sendable_byte_caches();
    void note_stream_send_bytes_queued(std::size_t bytes);
    void note_stream_fresh_sendable_bytes_delta(std::uint64_t before, std::uint64_t after);
    void note_stream_lost_send_data_changed(bool previous_has_lost_send_data,
                                            const StreamState &stream);
    void note_stream_send_state_changed(std::uint64_t previous_fresh_sendable_bytes,
                                        const StreamState &stream);
    void note_stream_send_state_changed(std::uint64_t previous_fresh_sendable_bytes,
                                        bool previous_has_lost_send_data,
                                        const StreamState &stream);
    void forget_active_stream_queued_bytes(const StreamState &stream);
    void maybe_queue_connection_blocked_frame();
    void maybe_queue_stream_blocked_frame(StreamState &stream);
    void maybe_refresh_connection_receive_credit(bool force);
    void maybe_refresh_stream_receive_credit(StreamState &stream, bool force);
    void maybe_refresh_peer_stream_limit(StreamState &stream);
    bool is_probing_only(std::span<const Frame> frames) const;
    bool can_initiate_path_validation(QuicPathId path_id) const;
    void retire_peer_connection_id_for_inactive_path(QuicPathId old_path_id,
                                                     QuicPathId new_path_id);
    bool should_keep_current_send_path_for_inbound_non_probing(
        QuicPathId inbound_path_id,
        std::optional<std::uint64_t> packet_number = std::nullopt) const;
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void note_inbound_application_packet_for_path(QuicPathId path_id, std::uint64_t packet_number);
    void maybe_switch_to_path(QuicPathId path_id, bool initiated_locally,
                              QuicCoreTimePoint now = QuicCoreClock::now());
    static void set_path_peer_connection_id_sequence(PathState &path,
                                                     std::uint64_t sequence_number);
    void update_spin_bit_on_receive(QuicPathId path_id, bool peer_spin_bit,
                                    std::uint64_t packet_number);
    bool outbound_spin_bit_for_path(std::optional<QuicPathId> path_id) const;
    bool anti_amplification_applies() const;
    bool anti_amplification_applies(QuicPathId path_id) const;
    std::uint64_t anti_amplification_send_budget() const;
    std::uint64_t anti_amplification_send_budget(QuicPathId path_id) const;
    std::uint64_t anti_amplification_remaining_send_budget() const;
    std::size_t outbound_datagram_size_limit(bool allow_pmtu_probe_size = true) const;
    std::size_t outbound_datagram_size_ceiling() const;
    std::size_t outbound_datagram_size_ceiling_for_path(std::optional<QuicPathId> path_id) const;
    std::size_t outbound_datagram_size_limit_for_path(std::optional<QuicPathId> path_id) const;
    std::optional<QuicCoreTimePoint> pmtud_deadline() const;
    void initialize_path_mtu_state(PathState &path);
    void maybe_arm_pmtu_probe(QuicCoreTimePoint now);
    std::optional<std::size_t> next_pmtu_probe_size(PathState &path) const;
    void note_pmtu_probe_sent(QuicPathId path_id, std::uint64_t packet_number,
                              std::size_t datagram_size);
    void maybe_note_pmtu_probe_sent_for_tracking(const std::optional<std::size_t> &pmtu_probe_size,
                                                 const SentPacketRecord &packet);
    void note_pmtu_probe_acked(const SentPacketRecord &packet, QuicCoreTimePoint now);
    void note_pmtu_probe_lost(const SentPacketRecord &packet, QuicCoreTimePoint now);
    void note_inbound_datagram_bytes(std::size_t bytes);
    void note_outbound_datagram_bytes(std::size_t bytes,
                                      std::optional<QuicPathId> path_id = std::nullopt,
                                      std::optional<QuicCoreTimePoint> now = std::nullopt);
    void note_idle_peer_activity(QuicCoreTimePoint now);
    void note_idle_ack_eliciting_send(QuicCoreTimePoint now);
    void mark_peer_address_validated();
    void disable_ecn_on_path(QuicPathId path_id);
    QuicEcnCodepoint outbound_ecn_codepoint_for_path(std::optional<QuicPathId> path_id) const;
    ConnectionId
    outbound_destination_connection_id(std::optional<QuicPathId> path_id = std::nullopt) const;
    ConnectionId client_initial_destination_connection_id() const;
    DatagramBuffer flush_outbound_datagram(QuicCoreTimePoint now,
                                           bool continue_paced_burst = false);
    bool can_send_connection_close_frame() const;
    std::optional<Frame> connection_close_frame_for_send() const;
    void mark_connection_close_frame_sent(const Frame &frame, QuicCoreTimePoint now);
    void enter_closing_state(QuicCoreTimePoint now, QuicConnectionTerminalState terminal_state);
    void enter_draining_state(QuicCoreTimePoint now);
    void queue_transport_close_for_error(QuicCoreTimePoint now, const CodecError &error,
                                         std::uint64_t frame_type = 0);
    bool note_aead_encryption_attempt(std::size_t packet_count, QuicCoreTimePoint now);
    bool note_packet_authentication_failure(const CodecError &error, QuicCoreTimePoint now);
    bool non_paced_burst_allows_send(bool ack_eliciting, bool bypass_congestion_window,
                                     std::optional<bool> pacing_controlled = std::nullopt) const;
    void
    note_burst_limited_ack_eliciting_send(std::size_t packet_count, bool bypass_congestion_window,
                                          std::optional<bool> pacing_controlled = std::nullopt);
    void reset_unpaced_ack_eliciting_burst();
    void clear_connection_failure_effects();
    void mark_silent_close();
    void mark_failed();
    void queue_state_change(QuicCoreStateChange change);
    void note_endpoint_route_state_changed();
    bool accepts_greased_quic_bit() const;
    bool can_skip_receive_tls_sync(std::span<const std::byte> bytes) const;

    QuicCoreConfig config_;
    bool latency_spin_bit_disabled_ = true;
    std::uint32_t original_version_;
    std::uint32_t current_version_;
    std::uint64_t grease_quic_bit_seed_ = 0;
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
    std::set<std::uint64_t> retired_peer_connection_id_sequences_;
    std::map<std::uint64_t, LocalConnectionIdRecord> local_connection_ids_;
    std::map<QuicPathId, PathState> paths_;
    std::uint64_t active_peer_connection_id_sequence_ = 0;
    std::uint64_t largest_peer_retire_prior_to_ = 0;
    std::uint64_t active_local_connection_id_sequence_ = 0;
    std::uint64_t next_local_connection_id_sequence_ = 1;
    std::uint64_t endpoint_route_generation_ = 1;
    std::uint64_t next_path_challenge_sequence_ = 1;
    std::uint64_t current_application_write_key_encrypted_packets_ = 0;
    std::uint64_t current_application_write_key_generation_ = 0;
    std::uint64_t failed_authentication_packets_ = 0;
    std::size_t unpaced_ack_eliciting_burst_packets_ = 0;
    bool peer_transport_parameters_validated_ = false;
    bool peer_address_validated_ = false;
    std::uint64_t anti_amplification_received_bytes_ = 0;
    std::uint64_t anti_amplification_sent_bytes_ = 0;
    std::map<std::uint64_t, StreamState> streams_;
    std::map<std::uint64_t, StreamState> retired_streams_;
    ConnectionFlowControlState connection_flow_control_;
    StreamOpenLimits stream_open_limits_;
    LocalStreamLimitState local_stream_limit_state_;
    std::deque<SharedBytes> pending_datagram_send_queue_;
    std::deque<QuicCoreReceiveStreamData> pending_stream_receive_effects_;
    std::deque<QuicCoreReceiveDatagramData> pending_datagram_receive_effects_;
    std::deque<QuicCorePeerResetStream> pending_peer_reset_effects_;
    std::deque<QuicCorePeerStopSending> pending_peer_stop_effects_;
    std::deque<QuicCoreStateChange> pending_state_changes_;
    std::optional<QuicCorePeerPreferredAddressAvailable> pending_preferred_address_effect_;
    std::optional<QuicCoreResumptionStateAvailable> pending_resumption_state_effect_;
    std::optional<QuicCoreZeroRttStatusEvent> pending_zero_rtt_status_event_;
    std::optional<QuicConnectionTerminalState> pending_terminal_state_;
    std::deque<QuicCorePacketInspection> pending_packet_inspections_;
    std::vector<NewConnectionIdFrame> pending_new_connection_id_frames_;
    std::vector<RetireConnectionIdFrame> pending_retire_connection_id_frames_;
    std::vector<NewTokenFrame> pending_new_token_frames_;
    std::deque<std::vector<std::byte>> pending_received_new_tokens_;
    std::optional<StoredClientResumptionState> decoded_resumption_state_;
    std::optional<std::uint64_t> last_application_send_stream_id_;
    QuicCongestionController congestion_controller_;
    RecoveryRttState recovery_rtt_state_;
    std::uint32_t pto_count_ = 0;
    std::uint8_t remaining_pto_probe_datagrams_ = 0;
    bool application_read_key_phase_ = false;
    bool application_write_key_phase_ = false;
    bool local_key_update_requested_ = false;
    bool local_key_update_initiated_ = false;
    std::optional<std::uint64_t> current_write_phase_first_packet_number_;
    std::optional<TrafficSecret> previous_application_read_secret_;
    std::optional<QuicCoreTimePoint> previous_application_read_secret_discard_deadline_;
    bool previous_application_read_key_phase_ = false;
    std::optional<TrafficSecret> next_application_read_secret_;
    std::uint64_t application_read_secret_generation_ = 0;
    std::optional<std::uint64_t> next_application_read_secret_source_generation_;
    bool next_application_read_key_phase_ = false;
    struct ShortHeaderDeserializeContextCache {
        const TrafficSecret *secret = nullptr;
        std::uint64_t secret_generation = 0;
        bool key_phase = false;
        std::size_t destination_connection_id_length = 0;
        bool accept_greased_quic_bit = false;
        bool secret_cache_primed = false;
    };
    std::optional<ShortHeaderDeserializeContextCache> current_short_header_deserialize_cache_;
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
    std::optional<TransportConnectionCloseFrame> pending_transport_close_;
    std::optional<QuicConnectionTerminalState> pending_connection_close_terminal_state_;
    QuicConnectionCloseMode close_mode_ = QuicConnectionCloseMode::none;
    std::optional<QuicCoreTimePoint> close_started_at_;
    std::optional<QuicCoreTimePoint> close_deadline_;
    std::optional<TransportConnectionCloseFrame> closing_transport_close_;
    std::optional<ApplicationConnectionCloseFrame> closing_application_close_;
    bool closing_close_packet_pending_ = false;
    std::uint64_t closing_packets_since_last_close_ = 0;
    std::uint64_t closing_packet_response_threshold_ = 1;
    std::unique_ptr<qlog::Session> qlog_session_;
    std::vector<DeferredProtectedDatagram> deferred_protected_packets_;
    std::optional<QuicCoreTimePoint> last_peer_activity_time_;
    std::optional<QuicCoreTimePoint> idle_timeout_base_time_;
    bool ack_eliciting_sent_since_idle_reset_ = false;
    std::optional<QuicCoreTimePoint> last_client_handshake_keepalive_probe_time_;
    std::optional<QuicCoreTimePoint> last_client_receive_keepalive_probe_time_;
    std::optional<QuicCoreTimePoint> server_zero_rtt_discard_deadline_;
    std::optional<QuicPathId> last_validated_path_id_;
    std::optional<QuicPathId> previous_path_id_;
    std::optional<QuicPathId> current_send_path_id_;
    std::optional<QuicPathId> last_drained_path_id_;
    QuicEcnCodepoint last_drained_ecn_codepoint_ = QuicEcnCodepoint::not_ect;
    bool last_drained_is_pmtu_probe_ = false;
    bool last_drained_allows_send_continuation_ = false;
    std::optional<QuicCoreTimePoint> last_send_continuation_time_;
    std::uint64_t next_packet_inspection_datagram_id_ = 1;
    std::uint64_t last_drained_packet_inspection_datagram_id_ = 0;
    QuicPathId last_inbound_path_id_ = 0;
    std::uint64_t active_queued_stream_bytes_ = 0;
    std::uint64_t fresh_sendable_stream_bytes_ = 0;
    std::uint64_t streams_with_lost_send_data_ = 0;
    std::vector<PendingTrackedPacketScratch> pending_tracked_packet_scratch_;
    std::vector<StreamFrameSendFragment> application_stream_fragment_scratch_;
    std::vector<std::map<std::uint64_t, StreamState>::iterator> active_stream_iterator_scratch_;
    std::vector<Frame> application_crypto_frame_scratch_;
    std::vector<Frame> application_candidate_frame_scratch_;
    std::vector<Frame> alternate_application_candidate_frame_scratch_;
    std::vector<SentPacketRecord> acked_packet_scratch_;
    std::vector<SentPacketRecord> late_acked_packet_scratch_;
    std::vector<SentPacketRecord> newly_lost_packet_scratch_;
    std::vector<AckedStreamPacketSample> simple_stream_ack_sample_scratch_;
};

} // namespace coquic::quic
