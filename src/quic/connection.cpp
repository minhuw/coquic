#include "src/quic/connection.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <limits>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "src/quic/buffer.h"
#include "src/quic/frame.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/protected_codec.h"

namespace coquic::quic {

namespace {

constexpr std::size_t kMinimumInitialDatagramSize = 1200;
constexpr std::size_t kMaximumDatagramSize = 1200;
constexpr std::size_t kMaximumDeferredProtectedPackets = 32;
constexpr std::uint8_t kDefaultInitialPacketNumberLength = 2;
constexpr std::uint64_t kCompatibilityStreamId = 0;
constexpr std::uint32_t kPersistentCongestionThreshold = 3;

bool supports_version(std::span<const std::uint32_t> supported_versions, std::uint32_t version) {
    return std::find(supported_versions.begin(), supported_versions.end(), version) !=
           supported_versions.end();
}

bool supports_quic_v2(std::span<const std::uint32_t> supported_versions) {
    return supports_version(supported_versions, kQuicVersion2);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_initial_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x01u;
    }
    return packet_type == 0x00u;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_handshake_long_header_type(std::uint32_t version, std::uint8_t packet_type) {
    if (version == kQuicVersion2) {
        return packet_type == 0x03u;
    }
    return packet_type == 0x02u;
}

std::optional<VersionInformation>
make_local_version_information(std::span<const std::uint32_t> supported_versions,
                               std::uint32_t chosen_version) {
    if (!supports_quic_v2(supported_versions)) {
        return std::nullopt;
    }

    return VersionInformation{
        .chosen_version = chosen_version,
        .available_versions =
            std::vector<std::uint32_t>(supported_versions.begin(), supported_versions.end()),
    };
}

std::uint32_t select_server_version(std::span<const std::uint32_t> supported_versions,
                                    std::uint32_t client_initial_version) {
    if (client_initial_version == kQuicVersion1 && supports_quic_v2(supported_versions)) {
        return kQuicVersion2;
    }
    if (supports_version(supported_versions, client_initial_version)) {
        return client_initial_version;
    }

    return client_initial_version;
}

EndpointRole opposite_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
}

void log_codec_failure(std::string_view where, const CodecError &error) {
    std::cerr << "quic connection failure at " << where
              << ": codec=" << static_cast<int>(error.code) << " offset=" << error.offset << '\n';
}

std::size_t datagram_size_or_zero(const CodecResult<std::vector<std::byte>> &datagram) {
    const auto *value = std::get_if<std::vector<std::byte>>(&datagram.storage);
    return value == nullptr ? 0 : value->size();
}

std::uint32_t read_u32_be(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | std::to_integer<std::uint8_t>(byte);
    }

    return value;
}

PacketSpaceState &packet_space_for_level(EncryptionLevel level, PacketSpaceState &initial_space,
                                         PacketSpaceState &handshake_space,
                                         PacketSpaceState &application_space) {
    if (level == EncryptionLevel::initial) {
        return initial_space;
    }
    if (level == EncryptionLevel::handshake) {
        return handshake_space;
    }

    return application_space;
}

bool is_padding_frame(const Frame &frame) {
    return std::holds_alternative<PaddingFrame>(frame);
}

bool is_ack_eliciting_frame(const Frame &frame) {
    constexpr auto kAckElicitingByFrameIndex = std::to_array<bool>({
        false, // PaddingFrame
        true,  // PingFrame
        false, // AckFrame
        true,  // ResetStreamFrame
        true,  // StopSendingFrame
        true,  // CryptoFrame
        false, // NewTokenFrame
        true,  // StreamFrame
        true,  // MaxDataFrame
        true,  // MaxStreamDataFrame
        true,  // MaxStreamsFrame
        true,  // DataBlockedFrame
        true,  // StreamDataBlockedFrame
        true,  // StreamsBlockedFrame
        false, // NewConnectionIdFrame
        false, // RetireConnectionIdFrame
        false, // PathChallengeFrame
        false, // PathResponseFrame
        false, // TransportConnectionCloseFrame
        false, // ApplicationConnectionCloseFrame
        true,  // HandshakeDoneFrame
    });

    return kAckElicitingByFrameIndex[frame.index()];
}

bool has_ack_eliciting_frame(std::span<const Frame> frames) {
    for (const auto &frame : frames) {
        if (is_ack_eliciting_frame(frame)) {
            return true;
        }
    }

    return false;
}

bool has_in_flight_ack_eliciting_packet(const PacketSpaceState &packet_space) {
    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        if (packet.ack_eliciting & packet.in_flight) {
            return true;
        }
    }

    return false;
}

bool is_discardable_short_header_packet_error(CodecErrorCode code) {
    static constexpr std::array kDiscardableErrors = {
        CodecErrorCode::invalid_packet_protection_state,
        CodecErrorCode::packet_decryption_failed,
        CodecErrorCode::header_protection_failed,
        CodecErrorCode::header_protection_sample_too_short,
    };
    return std::ranges::find(kDiscardableErrors, code) != kDiscardableErrors.end();
}

std::optional<QuicCoreTimePoint>
earliest_of(std::initializer_list<std::optional<QuicCoreTimePoint>> deadlines) {
    std::optional<QuicCoreTimePoint> earliest;
    for (const auto &deadline : deadlines) {
        if (!deadline.has_value()) {
            continue;
        }

        if (!earliest.has_value() || *deadline < *earliest) {
            earliest = deadline;
        }
    }

    return earliest;
}

std::chrono::milliseconds decode_ack_delay(const AckFrame &ack, std::uint64_t ack_delay_exponent) {
    if (ack_delay_exponent >= std::numeric_limits<std::uint64_t>::digits) {
        return std::chrono::milliseconds(0);
    }

    const auto max_microseconds =
        static_cast<std::uint64_t>(std::numeric_limits<std::chrono::microseconds::rep>::max()) >>
        ack_delay_exponent;
    const auto bounded_ack_delay = std::min<std::uint64_t>(ack.ack_delay, max_microseconds);
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::microseconds(bounded_ack_delay << ack_delay_exponent));
}

std::size_t stream_fragment_bytes(std::span<const StreamFrameSendFragment> fragments) {
    std::size_t total = 0;
    for (const auto &fragment : fragments) {
        total += fragment.bytes.size();
    }

    return total;
}

std::vector<StreamFrameView>
make_stream_frame_views(std::span<const StreamFrameSendFragment> fragments) {
    std::vector<StreamFrameView> views;
    views.reserve(fragments.size());
    for (const auto &fragment : fragments) {
        views.push_back(StreamFrameView{
            .fin = fragment.fin,
            .stream_id = fragment.stream_id,
            .offset = fragment.offset,
            .storage = fragment.bytes.storage(),
            .begin = fragment.bytes.begin_offset(),
            .end = fragment.bytes.end_offset(),
        });
    }

    return views;
}

CodecResult<std::vector<std::byte>> serialize_locally_validated_transport_parameters(
    EndpointRole local_role, const TransportParameters &parameters,
    const TransportParametersValidationContext &validation_context) {
    const auto validation =
        validate_peer_transport_parameters(local_role, parameters, validation_context);
    if (!validation.has_value()) {
        return CodecResult<std::vector<std::byte>>::failure(validation.error().code,
                                                            validation.error().offset);
    }

    return serialize_transport_parameters(parameters);
}

bool max_data_frame_matches(const std::optional<MaxDataFrame> &candidate,
                            const MaxDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

bool data_blocked_frame_matches(const std::optional<DataBlockedFrame> &candidate,
                                const DataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

bool reset_stream_frame_matches(const std::optional<ResetStreamFrame> &candidate,
                                const ResetStreamFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code,
                    candidate->final_size) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code, frame.final_size);
}

bool stop_sending_frame_matches(const std::optional<StopSendingFrame> &candidate,
                                const StopSendingFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code);
}

bool max_stream_data_frame_matches(const std::optional<MaxStreamDataFrame> &candidate,
                                   const MaxStreamDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

bool max_streams_frame_matches(const std::optional<MaxStreamsFrame> &candidate,
                               const MaxStreamsFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_type, candidate->maximum_streams) ==
           std::tie(frame.stream_type, frame.maximum_streams);
}

bool stream_data_blocked_frame_matches(const std::optional<StreamDataBlockedFrame> &candidate,
                                       const StreamDataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

bool should_refresh_receive_window(std::uint64_t delivered_bytes, std::uint64_t advertised_limit,
                                   std::uint64_t window, bool force) {
    if (window == 0 || advertised_limit < delivered_bytes) {
        return false;
    }

    if (force) {
        return true;
    }

    const auto remaining = advertised_limit - delivered_bytes;
    if (window <= 1) {
        return remaining == 0;
    }

    return remaining < (window / 2);
}

bool packet_space_is_application(const PacketSpaceState &packet_space,
                                 const PacketSpaceState &application_space) {
    return &packet_space == &application_space;
}

bool stream_fin_sendable(const StreamState &stream) {
    if (stream.send_fin_state != StreamSendFinState::pending ||
        !stream.send_final_size.has_value()) {
        return false;
    }

    return *stream.send_final_size <= stream.flow_control.peer_max_stream_data &&
           !stream.send_buffer.has_pending_data();
}

bool stream_receive_terminal(const StreamState &stream) {
    return !stream.id_info.local_can_receive | stream.peer_fin_delivered |
           stream.peer_reset_received;
}

bool stream_send_terminal(const StreamState &stream) {
    return !stream.id_info.local_can_send |
           (stream.send_fin_state == StreamSendFinState::acknowledged) |
           (stream.reset_state == StreamControlFrameState::acknowledged);
}

std::vector<std::uint64_t>
round_robin_stream_order(const std::map<std::uint64_t, StreamState> &streams,
                         std::optional<std::uint64_t> last_stream_id) {
    std::vector<std::uint64_t> order;
    order.reserve(streams.size());
    if (streams.empty()) {
        return order;
    }

    auto append_order = [&](auto begin, auto end) {
        for (auto it = begin; it != end; ++it) {
            order.push_back(it->first);
        }
    };

    if (!last_stream_id.has_value()) {
        append_order(streams.begin(), streams.end());
        return order;
    }

    const auto start = streams.upper_bound(*last_stream_id);
    append_order(start, streams.end());
    append_order(streams.begin(), start);
    return order;
}

std::vector<SentPacketRecord>
ack_eliciting_in_flight_losses(std::span<const SentPacketRecord> packets) {
    std::vector<SentPacketRecord> filtered;
    filtered.reserve(packets.size());
    for (const auto &packet : packets) {
        if (!packet.ack_eliciting || packet.bytes_in_flight == 0) {
            continue;
        }

        filtered.push_back(packet);
    }

    return filtered;
}

std::size_t retransmittable_probe_frame_count(const SentPacketRecord &packet) {
    return packet.crypto_ranges.size() + packet.reset_stream_frames.size() +
           packet.stop_sending_frames.size() + packet.max_stream_data_frames.size() +
           packet.max_streams_frames.size() + packet.stream_data_blocked_frames.size() +
           packet.stream_fragments.size() + static_cast<std::size_t>(packet.has_handshake_done) +
           static_cast<std::size_t>(packet.max_data_frame.has_value()) +
           static_cast<std::size_t>(packet.data_blocked_frame.has_value());
}

bool stream_fragment_is_probe_worthy(const StreamState &stream,
                                     const StreamFrameSendFragment &fragment) {
    if (stream.reset_state != StreamControlFrameState::none) {
        return false;
    }

    if (stream.send_buffer.has_outstanding_range(fragment.offset, fragment.bytes.size())) {
        return true;
    }

    const bool missing_fin = !fragment.fin;
    const bool fin_already_acknowledged = stream.send_fin_state == StreamSendFinState::acknowledged;
    if (missing_fin | fin_already_acknowledged) {
        return false;
    }
    const auto fragment_end = fragment.offset + static_cast<std::uint64_t>(fragment.bytes.size());
    return stream.send_final_size == std::optional<std::uint64_t>{fragment_end};
}

std::size_t application_ack_eliciting_frame_count(
    bool include_handshake_done, const std::optional<MaxDataFrame> &max_data_frame,
    std::span<const MaxStreamDataFrame> max_stream_data_frames,
    std::span<const MaxStreamsFrame> max_streams_frames,
    std::span<const ResetStreamFrame> reset_stream_frames,
    std::span<const StopSendingFrame> stop_sending_frames,
    const std::optional<DataBlockedFrame> &data_blocked_frame,
    std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
    std::span<const StreamFrameSendFragment> stream_fragments) {
    return max_stream_data_frames.size() + max_streams_frames.size() + reset_stream_frames.size() +
           stop_sending_frames.size() + stream_data_blocked_frames.size() +
           stream_fragments.size() + static_cast<std::size_t>(include_handshake_done) +
           static_cast<std::size_t>(max_data_frame.has_value()) +
           static_cast<std::size_t>(data_blocked_frame.has_value());
}

bool establishes_persistent_congestion(std::span<const SentPacketRecord> lost_packets,
                                       const RecoveryRttState &rtt,
                                       std::chrono::milliseconds max_ack_delay) {
    if (!rtt.latest_rtt.has_value()) {
        return false;
    }

    const auto [first_loss, last_loss] =
        std::minmax_element(lost_packets.begin(), lost_packets.end(),
                            [](const SentPacketRecord &lhs, const SentPacketRecord &rhs) {
                                return lhs.sent_time < rhs.sent_time;
                            });
    if (last_loss->sent_time <= first_loss->sent_time) {
        return false;
    }

    const auto persistent_congestion_duration =
        (rtt.smoothed_rtt + std::max(rtt.rttvar * 4, kGranularity) + max_ack_delay) *
        kPersistentCongestionThreshold;
    return last_loss->sent_time - first_loss->sent_time >= persistent_congestion_duration;
}

bool ack_frame_acks_packet(const AckFrame &ack, std::uint64_t packet_number) {
    if (packet_number > ack.largest_acknowledged) {
        return false;
    }
    if (ack.largest_acknowledged < ack.first_ack_range) {
        return false;
    }

    auto range_smallest = ack.largest_acknowledged - ack.first_ack_range;
    if (packet_number >= range_smallest) {
        return true;
    }

    auto previous_smallest = range_smallest;
    for (const auto &range : ack.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return false;
        }

        const auto range_largest = previous_smallest - range.gap - 2;
        if (range_largest < range.range_length) {
            return false;
        }
        range_smallest = range_largest - range.range_length;
        if (packet_number >= range_smallest && packet_number <= range_largest) {
            return true;
        }

        previous_smallest = range_smallest;
    }

    return false;
}

void discard_packet_space_state(PacketSpaceState &packet_space) {
    packet_space.largest_authenticated_packet_number = std::nullopt;
    packet_space.read_secret = std::nullopt;
    packet_space.write_secret = std::nullopt;
    packet_space.send_crypto = ReliableSendBuffer{};
    packet_space.receive_crypto = ReliableReceiveBuffer{};
    packet_space.received_packets = ReceivedPacketHistory{};
    packet_space.sent_packets.clear();
    packet_space.declared_lost_packets.clear();
    packet_space.recovery = PacketSpaceRecovery{};
    packet_space.pending_probe_packet = std::nullopt;
    packet_space.pending_ack_deadline = std::nullopt;
    packet_space.force_ack_send = false;
}

void reset_packet_space_receive_state(PacketSpaceState &packet_space) {
    packet_space.largest_authenticated_packet_number = std::nullopt;
    packet_space.received_packets = ReceivedPacketHistory{};
    packet_space.pending_ack_deadline = std::nullopt;
    packet_space.force_ack_send = false;
}

} // namespace

std::uint64_t ConnectionFlowControlState::sendable_bytes(std::uint64_t queued_bytes) const {
    const auto remaining_credit = peer_max_data > highest_sent ? peer_max_data - highest_sent : 0;
    const auto unsent_bytes = queued_bytes > highest_sent ? queued_bytes - highest_sent : 0;
    return std::min(remaining_credit, unsent_bytes);
}

bool ConnectionFlowControlState::should_send_data_blocked(std::uint64_t queued_bytes) const {
    return queued_bytes > peer_max_data;
}

void ConnectionFlowControlState::note_peer_max_data(std::uint64_t maximum_data) {
    if (maximum_data <= peer_max_data) {
        return;
    }

    peer_max_data = maximum_data;
}

void ConnectionFlowControlState::queue_max_data(std::uint64_t maximum_data) {
    if (maximum_data <= advertised_max_data) {
        return;
    }

    advertised_max_data = maximum_data;
    pending_max_data_frame = MaxDataFrame{
        .maximum_data = maximum_data,
    };
    max_data_state = StreamControlFrameState::pending;
}

std::optional<MaxDataFrame> ConnectionFlowControlState::take_max_data_frame() {
    if (max_data_state != StreamControlFrameState::pending || !pending_max_data_frame.has_value()) {
        return std::nullopt;
    }

    max_data_state = StreamControlFrameState::sent;
    return pending_max_data_frame;
}

void ConnectionFlowControlState::acknowledge_max_data_frame(const MaxDataFrame &frame) {
    if (max_data_frame_matches(pending_max_data_frame, frame)) {
        max_data_state = StreamControlFrameState::acknowledged;
    }
}

void ConnectionFlowControlState::mark_max_data_frame_lost(const MaxDataFrame &frame) {
    if (max_data_state != StreamControlFrameState::acknowledged &&
        max_data_frame_matches(pending_max_data_frame, frame)) {
        max_data_state = StreamControlFrameState::pending;
    }
}

void ConnectionFlowControlState::queue_data_blocked(std::uint64_t maximum_data) {
    if (pending_data_blocked_frame.has_value() &&
        pending_data_blocked_frame->maximum_data == maximum_data &&
        data_blocked_state != StreamControlFrameState::none) {
        return;
    }

    pending_data_blocked_frame = DataBlockedFrame{
        .maximum_data = maximum_data,
    };
    data_blocked_state = StreamControlFrameState::pending;
}

std::optional<DataBlockedFrame> ConnectionFlowControlState::take_data_blocked_frame() {
    if (data_blocked_state != StreamControlFrameState::pending ||
        !pending_data_blocked_frame.has_value()) {
        return std::nullopt;
    }

    data_blocked_state = StreamControlFrameState::sent;
    return pending_data_blocked_frame;
}

void ConnectionFlowControlState::acknowledge_data_blocked_frame(const DataBlockedFrame &frame) {
    if (data_blocked_frame_matches(pending_data_blocked_frame, frame)) {
        data_blocked_state = StreamControlFrameState::acknowledged;
    }
}

void ConnectionFlowControlState::mark_data_blocked_frame_lost(const DataBlockedFrame &frame) {
    if (data_blocked_state != StreamControlFrameState::acknowledged &&
        data_blocked_frame_matches(pending_data_blocked_frame, frame)) {
        data_blocked_state = StreamControlFrameState::pending;
    }
}

void LocalStreamLimitState::initialize(PeerStreamOpenLimits limits) {
    advertised_max_streams_bidi = limits.bidirectional;
    advertised_max_streams_uni = limits.unidirectional;
    pending_max_streams_bidi_frame = std::nullopt;
    max_streams_bidi_state = StreamControlFrameState::none;
    pending_max_streams_uni_frame = std::nullopt;
    max_streams_uni_state = StreamControlFrameState::none;
}

void LocalStreamLimitState::queue_max_streams(StreamLimitType stream_type,
                                              std::uint64_t maximum_streams) {
    auto *advertised_limit = &advertised_max_streams_bidi;
    auto *pending_frame = &pending_max_streams_bidi_frame;
    auto *state = &max_streams_bidi_state;
    if (stream_type == StreamLimitType::unidirectional) {
        advertised_limit = &advertised_max_streams_uni;
        pending_frame = &pending_max_streams_uni_frame;
        state = &max_streams_uni_state;
    }

    if (maximum_streams <= *advertised_limit) {
        return;
    }

    *advertised_limit = maximum_streams;
    *pending_frame = MaxStreamsFrame{
        .stream_type = stream_type,
        .maximum_streams = maximum_streams,
    };
    *state = StreamControlFrameState::pending;
}

std::vector<MaxStreamsFrame> LocalStreamLimitState::take_max_streams_frames() {
    std::vector<MaxStreamsFrame> frames;
    if (max_streams_bidi_state == StreamControlFrameState::pending &&
        pending_max_streams_bidi_frame.has_value()) {
        max_streams_bidi_state = StreamControlFrameState::sent;
        frames.push_back(*pending_max_streams_bidi_frame);
    }
    if (max_streams_uni_state == StreamControlFrameState::pending &&
        pending_max_streams_uni_frame.has_value()) {
        max_streams_uni_state = StreamControlFrameState::sent;
        frames.push_back(*pending_max_streams_uni_frame);
    }

    return frames;
}

StreamControlFrameState *max_streams_state_for(LocalStreamLimitState &state,
                                               StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &state.max_streams_bidi_state
                                                         : &state.max_streams_uni_state;
}

std::optional<MaxStreamsFrame> *pending_max_streams_frame_for(LocalStreamLimitState &state,
                                                              StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &state.pending_max_streams_bidi_frame
                                                         : &state.pending_max_streams_uni_frame;
}

void LocalStreamLimitState::acknowledge_max_streams_frame(const MaxStreamsFrame &frame) {
    auto *state = max_streams_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none) {
        return;
    }
    const auto *pending_frame = pending_max_streams_frame_for(*this, frame.stream_type);
    if (!max_streams_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::acknowledged;
}

void LocalStreamLimitState::mark_max_streams_frame_lost(const MaxStreamsFrame &frame) {
    auto *state = max_streams_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none ||
        *state == StreamControlFrameState::acknowledged) {
        return;
    }
    const auto *pending_frame = pending_max_streams_frame_for(*this, frame.stream_type);
    if (!max_streams_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::pending;
}

QuicConnection::QuicConnection(QuicCoreConfig config)
    : config_(std::move(config)), original_version_(config_.original_version),
      current_version_(config_.initial_version), congestion_controller_(kMaximumDatagramSize) {
    if (config_.supported_versions.empty()) {
        config_.supported_versions.push_back(current_version_);
    }
    local_transport_parameters_ = TransportParameters{
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
    };
    initialize_local_flow_control();
}

void QuicConnection::start() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    start_client_if_needed();
}

void QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes,
                                              QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed || bytes.empty()) {
        return;
    }

    if (!started_) {
        if (config_.role != EndpointRole::server) {
            mark_failed();
            return;
        }

        const auto initial_destination_connection_id =
            peek_client_initial_destination_connection_id(bytes);
        if (!initial_destination_connection_id.has_value()) {
            log_codec_failure("peek_client_initial_destination_connection_id",
                              initial_destination_connection_id.error());
            mark_failed();
            return;
        }

        start_server_if_needed(initial_destination_connection_id.value(),
                               read_u32_be(bytes.subspan(1, 4)));
    }

    auto synced = sync_tls_state();
    if (!synced.has_value()) {
        log_codec_failure("sync_tls_state", synced.error());
        mark_failed();
        return;
    }

    const auto packet_is_bufferable = [](std::span<const std::byte> packet_bytes) {
        const auto first_byte = std::to_integer<std::uint8_t>(packet_bytes.front());
        if ((first_byte & 0x80u) == 0) {
            return true;
        }

        if (packet_bytes.size() < 5) {
            return false;
        }

        const auto version = read_u32_be(packet_bytes.subspan(1, 4));
        return is_handshake_long_header_type(version,
                                             static_cast<std::uint8_t>((first_byte >> 4) & 0x03u));
    };
    const auto packet_requires_connected_state = [](std::span<const std::byte> packet_bytes) {
        return (std::to_integer<std::uint8_t>(packet_bytes.front()) & 0x80u) == 0;
    };
    const auto defer_packet = [&](std::span<const std::byte> packet_bytes) {
        const auto deferred = std::vector<std::byte>(packet_bytes.begin(), packet_bytes.end());
        if (std::find(deferred_protected_packets_.begin(), deferred_protected_packets_.end(),
                      deferred) != deferred_protected_packets_.end()) {
            return;
        }
        if (deferred_protected_packets_.size() >= kMaximumDeferredProtectedPackets) {
            deferred_protected_packets_.erase(deferred_protected_packets_.begin());
        }
        deferred_protected_packets_.push_back(deferred);
    };
    std::size_t offset = 0;
    bool processed_any_packet = false;
    const auto make_deserialize_context =
        [&](const std::optional<TrafficSecret> &application_secret,
            bool application_key_phase) -> DeserializeProtectionContext {
        return DeserializeProtectionContext{
            .peer_role = opposite_role(config_.role),
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
            .handshake_secret = handshake_space_.read_secret,
            .one_rtt_secret = application_secret,
            .one_rtt_key_phase = application_key_phase,
            .largest_authenticated_initial_packet_number =
                initial_space_.largest_authenticated_packet_number,
            .largest_authenticated_handshake_packet_number =
                handshake_space_.largest_authenticated_packet_number,
            .largest_authenticated_application_packet_number =
                application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
        };
    };
    const auto process_packet_bytes = [&](std::span<const std::byte> packet_bytes,
                                          bool allow_defer) -> bool {
        auto packets = deserialize_protected_datagram(
            packet_bytes,
            make_deserialize_context(application_space_.read_secret, application_read_key_phase_));
        const bool short_header_packet =
            (std::to_integer<std::uint8_t>(packet_bytes.front()) & 0x80u) == 0;
        if (!packets.has_value()) {
            const bool retry_with_next_key_phase =
                (packets.error().code == CodecErrorCode::invalid_packet_protection_state) &
                short_header_packet & application_space_.read_secret.has_value() &
                application_space_.write_secret.has_value();
            if (retry_with_next_key_phase) {
                const auto next_read_secret =
                    derive_next_traffic_secret(*application_space_.read_secret).value();
                auto updated_packets = deserialize_protected_datagram(
                    packet_bytes,
                    make_deserialize_context(next_read_secret, !application_read_key_phase_));
                if (updated_packets.has_value()) {
                    const auto next_write_secret =
                        derive_next_traffic_secret(*application_space_.write_secret);
                    if (!next_write_secret.has_value()) {
                        log_codec_failure("derive_next_traffic_secret", next_write_secret.error());
                        mark_failed();
                        return false;
                    }

                    application_space_.read_secret = next_read_secret;
                    application_space_.write_secret = next_write_secret.value();
                    application_read_key_phase_ = !application_read_key_phase_;
                    application_write_key_phase_ = !application_write_key_phase_;
                    packets = std::move(updated_packets);
                }
            }
        }
        if (!packets.has_value()) {
            const bool should_defer_packet =
                allow_defer & (packets.error().code == CodecErrorCode::missing_crypto_context) &
                packet_is_bufferable(packet_bytes);
            if (should_defer_packet) {
                // Later packets in the same datagram can depend on keys unlocked by an earlier
                // packet, so buffer them even after partial progress.
                defer_packet(packet_bytes);
                return true;
            }
            const bool should_discard_short_header_packet =
                short_header_packet &
                is_discardable_short_header_packet_error(packets.error().code);
            if (should_discard_short_header_packet) {
                return true;
            }
            if (processed_any_packet) {
                return true;
            }
            log_codec_failure("deserialize_protected_datagram", packets.error());
            mark_failed();
            return false;
        }

        for (const auto &packet : packets.value()) {
            const bool defer_one_rtt_packet =
                allow_defer & std::holds_alternative<ProtectedOneRttPacket>(packet) &
                (status_ != HandshakeStatus::connected);
            if (defer_one_rtt_packet) {
                defer_packet(packet_bytes);
                return true;
            }

            const auto processed = process_inbound_packet(packet, now);
            if (!processed.has_value()) {
                if (processed_any_packet) {
                    return true;
                }
                log_codec_failure("process_inbound_packet", processed.error());
                mark_failed();
                return false;
            }

            synced = sync_tls_state();
            if (!synced.has_value()) {
                log_codec_failure("sync_tls_state", synced.error());
                mark_failed();
                return false;
            }
        }

        return true;
    };
    const auto replay_deferred_packets = [&]() -> bool {
        if (deferred_protected_packets_.empty()) {
            return true;
        }

        auto deferred_packets = std::move(deferred_protected_packets_);
        deferred_protected_packets_.clear();
        for (const auto &packet_bytes : deferred_packets) {
            if (packet_requires_connected_state(packet_bytes) &&
                status_ != HandshakeStatus::connected) {
                defer_packet(packet_bytes);
                continue;
            }
            if (!process_packet_bytes(packet_bytes, /*allow_defer=*/true)) {
                return false;
            }
        }

        return true;
    };
    if (!replay_deferred_packets()) {
        return;
    }
    while (offset < bytes.size()) {
        const auto packet_length = peek_next_packet_length(bytes.subspan(offset));
        if (!packet_length.has_value()) {
            if (processed_any_packet) {
                return;
            }
            log_codec_failure("peek_next_packet_length", packet_length.error());
            mark_failed();
            return;
        }

        const auto packet_bytes = bytes.subspan(offset, packet_length.value());
        if (!process_packet_bytes(packet_bytes, /*allow_defer=*/true)) {
            return;
        }
        processed_any_packet = true;
        if (!replay_deferred_packets()) {
            return;
        }

        offset += packet_length.value();
    }
}

StreamStateResult<bool> QuicConnection::queue_stream_send(std::uint64_t stream_id,
                                                          std::span<const std::byte> bytes,
                                                          bool fin) {
    if (status_ == HandshakeStatus::failed || (bytes.empty() && !fin)) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_send(fin);
    if (!validated.has_value()) {
        return validated;
    }

    if (!bytes.empty()) {
        stream->send_buffer.append(bytes);
        stream->send_flow_control_committed += static_cast<std::uint64_t>(bytes.size());
    }
    if (fin) {
        stream->send_final_size = stream->send_flow_control_committed;
        stream->send_fin_state = StreamSendFinState::pending;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> QuicConnection::queue_stream_reset(LocalResetCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_or_open_send_stream(command.stream_id);
    if (!stream_state.has_value()) {
        const auto id_info = classify_stream_id(command.stream_id, config_.role);
        return StreamStateResult<bool>::failure(
            id_info.local_can_send ? StreamStateErrorCode::invalid_stream_id
                                   : StreamStateErrorCode::invalid_stream_direction,
            command.stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_reset(command.application_error_code);
    if (!validated.has_value()) {
        return validated;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> QuicConnection::queue_stop_sending(LocalStopSendingCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    auto stream_state = get_existing_receive_stream(command.stream_id);
    if (!stream_state.has_value()) {
        return StreamStateResult<bool>::failure(stream_state.error().code,
                                                stream_state.error().stream_id);
    }

    auto *stream = stream_state.value();
    const auto validated = stream->validate_local_stop_sending(command.application_error_code);
    if (!validated.has_value()) {
        return validated;
    }

    return StreamStateResult<bool>::success(true);
}

std::vector<std::byte> QuicConnection::drain_outbound_datagram(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return {};
    }

    return flush_outbound_datagram(now);
}

void QuicConnection::on_timeout(QuicCoreTimePoint now) {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    if (const auto deadline = loss_deadline(); deadline.has_value() && now >= *deadline) {
        detect_lost_packets(now);
    }

    const auto initial_ack_deadline =
        initial_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (now >= initial_ack_deadline) {
        initial_space_.force_ack_send = true;
    }
    const auto handshake_ack_deadline =
        handshake_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (now >= handshake_ack_deadline) {
        handshake_space_.force_ack_send = true;
    }
    const auto application_ack_deadline =
        application_space_.pending_ack_deadline.value_or(QuicCoreTimePoint::max());
    if (now >= application_ack_deadline) {
        application_space_.force_ack_send = true;
    }

    if (const auto deadline = pto_deadline(); deadline.has_value() && now >= *deadline) {
        arm_pto_probe(now);
    }
}

std::optional<QuicCoreReceiveStreamData> QuicConnection::take_received_stream_data() {
    if (status_ == HandshakeStatus::failed || pending_stream_receive_effects_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_stream_receive_effects_.front());
    pending_stream_receive_effects_.erase(pending_stream_receive_effects_.begin());
    return next;
}

std::optional<QuicCorePeerResetStream> QuicConnection::take_peer_reset_stream() {
    if (status_ == HandshakeStatus::failed || pending_peer_reset_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_reset_effects_.front();
    pending_peer_reset_effects_.erase(pending_peer_reset_effects_.begin());
    return next;
}

std::optional<QuicCorePeerStopSending> QuicConnection::take_peer_stop_sending() {
    if (status_ == HandshakeStatus::failed || pending_peer_stop_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_stop_effects_.front();
    pending_peer_stop_effects_.erase(pending_peer_stop_effects_.begin());
    return next;
}

std::optional<QuicCoreStateChange> QuicConnection::take_state_change() {
    if (pending_state_changes_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_state_changes_.front();
    pending_state_changes_.erase(pending_state_changes_.begin());
    return next;
}

std::optional<QuicCoreTimePoint> QuicConnection::next_wakeup() const {
    if (status_ == HandshakeStatus::failed) {
        return std::nullopt;
    }

    return earliest_of({loss_deadline(), pto_deadline(), ack_deadline()});
}

std::optional<QuicCoreTimePoint> QuicConnection::loss_deadline() const {
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto packet_space_loss_deadline =
        [&](const PacketSpaceState &packet_space) -> std::optional<QuicCoreTimePoint> {
        const auto largest_acked = packet_space.recovery.largest_acked_packet_number();
        if (!largest_acked.has_value()) {
            return std::nullopt;
        }

        std::optional<QuicCoreTimePoint> deadline;
        for (const auto &[packet_number, packet] : packet_space.sent_packets) {
            static_cast<void>(packet_number);
            if (!packet.in_flight || packet.packet_number >= *largest_acked) {
                continue;
            }

            const auto candidate =
                compute_time_threshold_deadline(shared_rtt_state, packet.sent_time);
            if (!deadline.has_value() || candidate < *deadline) {
                deadline = candidate;
            }
        }

        return deadline;
    };

    return earliest_of({packet_space_loss_deadline(initial_space_),
                        packet_space_loss_deadline(handshake_space_),
                        packet_space_loss_deadline(application_space_)});
}

std::optional<QuicCoreTimePoint> QuicConnection::pto_deadline() const {
    const auto application_max_ack_delay = std::chrono::milliseconds(
        peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                               : TransportParameters{}.max_ack_delay);
    const auto allow_application_pto = config_.role == EndpointRole::server || handshake_confirmed_;
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto packet_space_pto_deadline =
        [&](const PacketSpaceState &packet_space,
            std::chrono::milliseconds max_ack_delay) -> std::optional<QuicCoreTimePoint> {
        std::optional<QuicCoreTimePoint> last_ack_eliciting_sent_time;
        for (const auto &[packet_number, packet] : packet_space.sent_packets) {
            static_cast<void>(packet_number);
            if (!packet.ack_eliciting || !packet.in_flight) {
                continue;
            }

            if (!last_ack_eliciting_sent_time.has_value() ||
                packet.sent_time > *last_ack_eliciting_sent_time) {
                last_ack_eliciting_sent_time = packet.sent_time;
            }
        }

        if (!last_ack_eliciting_sent_time.has_value()) {
            return std::nullopt;
        }

        return compute_pto_deadline(shared_rtt_state, max_ack_delay, *last_ack_eliciting_sent_time,
                                    pto_count_);
    };

    const auto regular_deadline =
        earliest_of({packet_space_pto_deadline(initial_space_, std::chrono::milliseconds(0)),
                     packet_space_pto_deadline(handshake_space_, std::chrono::milliseconds(0)),
                     allow_application_pto
                         ? packet_space_pto_deadline(application_space_, application_max_ack_delay)
                         : std::nullopt});
    if (regular_deadline.has_value()) {
        return regular_deadline;
    }

    const auto client_handshake_keepalive_reference_time =
        [this]() -> std::optional<QuicCoreTimePoint> {
        const bool eligible = (config_.role == EndpointRole::client) &
                              (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                              last_peer_activity_time_.has_value() &
                              !has_in_flight_ack_eliciting_packet(initial_space_) &
                              !has_in_flight_ack_eliciting_packet(handshake_space_) &
                              !has_in_flight_ack_eliciting_packet(application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        auto reference_time = last_peer_activity_time_;
        const auto probe_time =
            last_client_handshake_keepalive_probe_time_.value_or(QuicCoreTimePoint::min());
        if (probe_time > *reference_time) {
            reference_time = probe_time;
        }

        return reference_time;
    }();
    const bool client_handshake_keepalive_eligible =
        client_handshake_keepalive_reference_time.has_value();
    const PacketSpaceState *client_handshake_keepalive_space =
        client_handshake_keepalive_eligible && !initial_packet_space_discarded_ ? &initial_space_
                                                                                : nullptr;
    if (client_handshake_keepalive_space == nullptr ||
        !client_handshake_keepalive_reference_time.has_value()) {
        return std::nullopt;
    }

    return compute_pto_deadline(shared_rtt_state, std::chrono::milliseconds(0),
                                *client_handshake_keepalive_reference_time,
                                std::min(pto_count_, 2u));
}

std::optional<QuicCoreTimePoint> QuicConnection::ack_deadline() const {
    return earliest_of({initial_space_.pending_ack_deadline, handshake_space_.pending_ack_deadline,
                        application_space_.pending_ack_deadline});
}

void QuicConnection::detect_lost_packets(QuicCoreTimePoint now) {
    detect_lost_packets(initial_space_, now);
    detect_lost_packets(handshake_space_, now);
    detect_lost_packets(application_space_, now);
}

void QuicConnection::detect_lost_packets(PacketSpaceState &packet_space, QuicCoreTimePoint now) {
    const auto largest_acked = packet_space.recovery.largest_acked_packet_number();
    if (!largest_acked.has_value()) {
        return;
    }

    const auto &shared_rtt_state = shared_recovery_rtt_state();

    std::vector<SentPacketRecord> lost_packets;
    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        if (!packet.in_flight || packet.packet_number >= *largest_acked) {
            continue;
        }
        if (!is_time_threshold_lost(shared_rtt_state, packet.sent_time, now)) {
            continue;
        }

        lost_packets.push_back(packet);
    }

    if (lost_packets.empty()) {
        return;
    }

    for (const auto &packet : lost_packets) {
        mark_lost_packet(packet_space, packet);
    }
    const auto ack_eliciting_lost_packets = ack_eliciting_in_flight_losses(lost_packets);
    if (packet_space_is_application(packet_space, application_space_) &&
        !ack_eliciting_lost_packets.empty()) {
        const auto application_max_ack_delay = std::chrono::milliseconds(
            peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                                   : TransportParameters{}.max_ack_delay);
        congestion_controller_.on_loss_event(now);
        if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                              application_max_ack_delay)) {
            congestion_controller_.on_persistent_congestion();
        }
    }
    rebuild_recovery(packet_space);
}

void QuicConnection::arm_pto_probe(QuicCoreTimePoint now) {
    PacketSpaceState *selected_packet_space = nullptr;
    std::optional<QuicCoreTimePoint> selected_deadline;
    const auto application_max_ack_delay = std::chrono::milliseconds(
        peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                               : TransportParameters{}.max_ack_delay);
    const auto allow_application_pto = config_.role == EndpointRole::server || handshake_confirmed_;
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    const auto effective_pto_count = [&](const PacketSpaceState & /*packet_space*/) {
        if (config_.role != EndpointRole::client || handshake_confirmed_) {
            return pto_count_;
        }
        return std::min(pto_count_, 2u);
    };
    const auto client_handshake_keepalive_reference_time =
        [this]() -> std::optional<QuicCoreTimePoint> {
        const bool eligible = (config_.role == EndpointRole::client) &
                              (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                              last_peer_activity_time_.has_value() &
                              !has_in_flight_ack_eliciting_packet(initial_space_) &
                              !has_in_flight_ack_eliciting_packet(handshake_space_) &
                              !has_in_flight_ack_eliciting_packet(application_space_);
        if (!eligible) {
            return std::nullopt;
        }

        auto reference_time = last_peer_activity_time_;
        const auto probe_time =
            last_client_handshake_keepalive_probe_time_.value_or(QuicCoreTimePoint::min());
        if (probe_time > *reference_time) {
            reference_time = probe_time;
        }

        return reference_time;
    }();
    const bool client_handshake_keepalive_eligible =
        client_handshake_keepalive_reference_time.has_value() && !initial_packet_space_discarded_;
    PacketSpaceState *client_handshake_keepalive_space =
        client_handshake_keepalive_eligible ? &initial_space_ : nullptr;
    auto client_handshake_keepalive_deadline = std::optional<QuicCoreTimePoint>{};
    if (client_handshake_keepalive_space != nullptr &&
        client_handshake_keepalive_reference_time.has_value()) {
        client_handshake_keepalive_deadline = compute_pto_deadline(
            shared_rtt_state, std::chrono::milliseconds(0),
            *client_handshake_keepalive_reference_time, std::min(pto_count_, 2u));
    }
    const bool client_handshake_keepalive_due = client_handshake_keepalive_deadline.has_value() &&
                                                now >= *client_handshake_keepalive_deadline;
    const auto consider_packet_space = [&](PacketSpaceState &packet_space,
                                           std::chrono::milliseconds max_ack_delay) {
        std::optional<QuicCoreTimePoint> packet_space_deadline;
        for (const auto &[packet_number, packet] : packet_space.sent_packets) {
            static_cast<void>(packet_number);
            const bool skip_packet = !packet.ack_eliciting | !packet.in_flight;
            if (skip_packet) {
                continue;
            }

            const auto candidate =
                compute_pto_deadline(shared_rtt_state, max_ack_delay, packet.sent_time,
                                     effective_pto_count(packet_space));
            const auto current_packet_space_deadline = packet_space_deadline.value_or(candidate);
            if (!packet_space_deadline.has_value() | (candidate > current_packet_space_deadline)) {
                packet_space_deadline = candidate;
            }
        }

        const bool deadline_due =
            packet_space_deadline.has_value() && now >= *packet_space_deadline;
        if (!deadline_due) {
            return;
        }

        const auto current_selected_deadline = selected_deadline.value_or(*packet_space_deadline);
        if (!selected_deadline.has_value() | (*packet_space_deadline < current_selected_deadline)) {
            selected_deadline = packet_space_deadline;
            selected_packet_space = &packet_space;
        }
    };

    consider_packet_space(initial_space_, std::chrono::milliseconds(0));
    consider_packet_space(handshake_space_, std::chrono::milliseconds(0));
    if (allow_application_pto) {
        consider_packet_space(application_space_, application_max_ack_delay);
    }

    if (selected_packet_space == nullptr) {
        if (!client_handshake_keepalive_due) {
            return;
        }
        selected_packet_space = client_handshake_keepalive_space;
        selected_deadline = client_handshake_keepalive_deadline;
    }

    ++pto_count_;
    remaining_pto_probe_datagrams_ = 0;
    bool armed_pto_probe = false;
    const auto arm_packet_space_probe = [&](PacketSpaceState &packet_space) {
        const bool allow_client_handshake_keepalive_probe =
            client_handshake_keepalive_due && &packet_space == client_handshake_keepalive_space;
        if (!allow_client_handshake_keepalive_probe &&
            !has_in_flight_ack_eliciting_packet(packet_space)) {
            return;
        }

        if (&packet_space != &application_space_ && packet_space.send_crypto.has_pending_data()) {
            return;
        }

        packet_space.pending_probe_packet = select_pto_probe(packet_space);
        armed_pto_probe |= packet_space.pending_probe_packet.has_value();
    };

    arm_packet_space_probe(*selected_packet_space);

    const auto arm_coalesced_probe = [&](PacketSpaceState &packet_space) {
        if (&packet_space == selected_packet_space) {
            return;
        }

        arm_packet_space_probe(packet_space);
    };

    arm_coalesced_probe(initial_space_);
    arm_coalesced_probe(handshake_space_);
    if (allow_application_pto) {
        arm_coalesced_probe(application_space_);
    }

    if (armed_pto_probe) {
        remaining_pto_probe_datagrams_ = 2;
    }
}

std::optional<SentPacketRecord>
QuicConnection::select_pto_probe(const PacketSpaceState &packet_space) const {
    std::optional<SentPacketRecord> ping_fallback;
    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        if (!packet.ack_eliciting || !packet.in_flight) {
            continue;
        }

        ping_fallback = ping_fallback.value_or(SentPacketRecord{
            .packet_number = packet.packet_number,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        });

        auto probe = packet;
        std::erase_if(probe.crypto_ranges, [&](const ByteRange &range) {
            return !packet_space.send_crypto.has_outstanding_range(range.offset,
                                                                   range.bytes.size());
        });
        std::erase_if(probe.reset_stream_frames, [&](const ResetStreamFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool reset_acknowledged =
                stream->second.reset_state == StreamControlFrameState::acknowledged;
            const bool reset_frame_mismatch =
                !reset_stream_frame_matches(stream->second.pending_reset_frame, frame);
            return static_cast<bool>(reset_acknowledged | reset_frame_mismatch);
        });
        std::erase_if(probe.stop_sending_frames, [&](const StopSendingFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool stop_sending_acknowledged =
                stream->second.stop_sending_state == StreamControlFrameState::acknowledged;
            const bool stop_sending_frame_mismatch =
                !stop_sending_frame_matches(stream->second.pending_stop_sending_frame, frame);
            return static_cast<bool>(stop_sending_acknowledged | stop_sending_frame_mismatch);
        });
        std::erase_if(probe.max_stream_data_frames, [&](const MaxStreamDataFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool max_stream_data_acknowledged =
                stream->second.flow_control.max_stream_data_state ==
                StreamControlFrameState::acknowledged;
            const bool max_stream_data_frame_mismatch = !max_stream_data_frame_matches(
                stream->second.flow_control.pending_max_stream_data_frame, frame);
            return static_cast<bool>(max_stream_data_acknowledged | max_stream_data_frame_mismatch);
        });
        std::erase_if(probe.max_streams_frames, [&](const MaxStreamsFrame &frame) {
            const bool frame_acknowledged =
                frame.stream_type == StreamLimitType::bidirectional
                    ? local_stream_limit_state_.max_streams_bidi_state ==
                          StreamControlFrameState::acknowledged
                    : local_stream_limit_state_.max_streams_uni_state ==
                          StreamControlFrameState::acknowledged;
            const auto &pending_frame =
                frame.stream_type == StreamLimitType::bidirectional
                    ? *local_stream_limit_state_.pending_max_streams_bidi_frame
                    : *local_stream_limit_state_.pending_max_streams_uni_frame;
            const bool frame_mismatch =
                std::tie(pending_frame.stream_type, pending_frame.maximum_streams) !=
                std::tie(frame.stream_type, frame.maximum_streams);
            return static_cast<bool>(frame_acknowledged | frame_mismatch);
        });
        std::erase_if(probe.stream_data_blocked_frames, [&](const StreamDataBlockedFrame &frame) {
            const auto stream = streams_.find(frame.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            const bool stream_data_blocked_acknowledged =
                stream->second.flow_control.stream_data_blocked_state ==
                StreamControlFrameState::acknowledged;
            const bool stream_data_blocked_frame_mismatch = !stream_data_blocked_frame_matches(
                stream->second.flow_control.pending_stream_data_blocked_frame, frame);
            return static_cast<bool>(stream_data_blocked_acknowledged |
                                     stream_data_blocked_frame_mismatch);
        });
        std::erase_if(probe.stream_fragments, [&](const StreamFrameSendFragment &fragment) {
            const auto stream = streams_.find(fragment.stream_id);
            if (stream == streams_.end()) {
                return true;
            }

            return !stream_fragment_is_probe_worthy(stream->second, fragment);
        });

        if (probe.max_data_frame.has_value()) {
            const bool max_data_acknowledged =
                connection_flow_control_.max_data_state == StreamControlFrameState::acknowledged;
            const bool max_data_frame_mismatch = !max_data_frame_matches(
                connection_flow_control_.pending_max_data_frame, *probe.max_data_frame);
            if (max_data_acknowledged | max_data_frame_mismatch) {
                probe.max_data_frame = std::nullopt;
            }
        }
        if (probe.data_blocked_frame.has_value()) {
            const bool data_blocked_acknowledged = connection_flow_control_.data_blocked_state ==
                                                   StreamControlFrameState::acknowledged;
            const bool data_blocked_frame_mismatch = !data_blocked_frame_matches(
                connection_flow_control_.pending_data_blocked_frame, *probe.data_blocked_frame);
            if (data_blocked_acknowledged | data_blocked_frame_mismatch) {
                probe.data_blocked_frame = std::nullopt;
            }
        }
        if (probe.has_handshake_done &&
            handshake_done_state_ == StreamControlFrameState::acknowledged) {
            probe.has_handshake_done = false;
        }

        if (retransmittable_probe_frame_count(probe) != 0 || probe.has_ping) {
            return probe;
        }
    }

    if (ping_fallback.has_value()) {
        return ping_fallback;
    }

    return SentPacketRecord{
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
}

const RecoveryRttState &QuicConnection::shared_recovery_rtt_state() const {
    if (recovery_rtt_state_.latest_rtt.has_value()) {
        return recovery_rtt_state_;
    }
    if (initial_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return initial_space_.recovery.rtt_state();
    }
    if (handshake_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return handshake_space_.recovery.rtt_state();
    }
    if (application_space_.recovery.rtt_state().latest_rtt.has_value()) {
        return application_space_.recovery.rtt_state();
    }

    return recovery_rtt_state_;
}

void QuicConnection::synchronize_recovery_rtt_state() {
    if (!recovery_rtt_state_.latest_rtt.has_value()) {
        recovery_rtt_state_ = shared_recovery_rtt_state();
    }

    const auto shared_rtt_state = shared_recovery_rtt_state();
    initial_space_.recovery.rtt_state() = shared_rtt_state;
    handshake_space_.recovery.rtt_state() = shared_rtt_state;
    application_space_.recovery.rtt_state() = shared_rtt_state;
}

bool QuicConnection::is_handshake_complete() const {
    return status_ == HandshakeStatus::connected;
}

bool QuicConnection::has_failed() const {
    return status_ == HandshakeStatus::failed;
}

void QuicConnection::start_client_if_needed() {
    if (config_.role != EndpointRole::client || started_) {
        return;
    }

    started_ = true;
    status_ = HandshakeStatus::in_progress;
    local_transport_parameters_ = TransportParameters{
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .version_information =
            make_local_version_information(config_.supported_versions, current_version_),
    };
    initialize_local_flow_control();

    const auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id = std::nullopt,
            .expected_retry_source_connection_id = std::nullopt,
        });
    if (!serialized_transport_parameters.has_value()) {
        log_codec_failure("serialize_client_transport_parameters",
                          serialized_transport_parameters.error());
        mark_failed();
        return;
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .application_protocol = config_.application_protocol,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
        .allowed_tls_cipher_suites = config_.allowed_tls_cipher_suites,
    });
    const auto tls_started = tls_->start();
    if (!tls_started.has_value()) {
        log_codec_failure("tls_start", tls_started.error());
        mark_failed();
        return;
    }

    static_cast<void>(sync_tls_state().value());
}

void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id,
    std::uint32_t client_initial_version) {
    if (started_) {
        return;
    }

    started_ = true;
    status_ = HandshakeStatus::in_progress;
    original_version_ = client_initial_version;
    current_version_ = select_server_version(config_.supported_versions, client_initial_version);
    client_initial_destination_connection_id_ = client_initial_destination_connection_id;
    local_transport_parameters_ = TransportParameters{
        .original_destination_connection_id = client_initial_destination_connection_id_,
        .max_idle_timeout = config_.transport.max_idle_timeout,
        .max_udp_payload_size = config_.transport.max_udp_payload_size,
        .active_connection_id_limit = 2,
        .ack_delay_exponent = config_.transport.ack_delay_exponent,
        .max_ack_delay = config_.transport.max_ack_delay,
        .initial_max_data = config_.transport.initial_max_data,
        .initial_max_stream_data_bidi_local = config_.transport.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote =
            config_.transport.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config_.transport.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config_.transport.initial_max_streams_bidi,
        .initial_max_streams_uni = config_.transport.initial_max_streams_uni,
        .initial_source_connection_id = config_.source_connection_id,
        .version_information =
            make_local_version_information(config_.supported_versions, current_version_),
    };
    initialize_local_flow_control();

    const auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id =
                client_initial_destination_connection_id_,
            .expected_retry_source_connection_id = std::nullopt,
        });
    if (!serialized_transport_parameters.has_value()) {
        log_codec_failure("serialize_server_transport_parameters",
                          serialized_transport_parameters.error());
        mark_failed();
        return;
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .application_protocol = config_.application_protocol,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
        .allowed_tls_cipher_suites = config_.allowed_tls_cipher_suites,
    });
    const auto tls_started = tls_->start();
    if (!tls_started.has_value()) {
        log_codec_failure("tls_start", tls_started.error());
        mark_failed();
        return;
    }
    static_cast<void>(sync_tls_state().value());
}

CodecResult<ConnectionId> QuicConnection::peek_client_initial_destination_connection_id(
    std::span<const std::byte> bytes) const {
    BufferReader reader(bytes);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return CodecResult<ConnectionId>::failure(first_byte.error().code,
                                                  first_byte.error().offset);
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }
    if ((header_byte & 0x40u) == 0) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<ConnectionId>::failure(version.error().code, version.error().offset);
    }
    const auto version_value = read_u32_be(version.value());
    if (!is_supported_quic_version(version_value)) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }
    if (!is_initial_long_header_type(version_value,
                                     static_cast<std::uint8_t>((header_byte >> 4) & 0x03u))) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return CodecResult<ConnectionId>::failure(destination_connection_id_length.error().code,
                                                  destination_connection_id_length.error().offset);
    }
    const auto destination_connection_id_length_value =
        std::to_integer<std::uint8_t>(destination_connection_id_length.value());
    if (destination_connection_id_length_value > 20) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }

    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length_value);
    if (!destination_connection_id.has_value()) {
        return CodecResult<ConnectionId>::failure(destination_connection_id.error().code,
                                                  destination_connection_id.error().offset);
    }

    return CodecResult<ConnectionId>::success(ConnectionId(
        destination_connection_id.value().begin(), destination_connection_id.value().end()));
}

CodecResult<std::size_t>
QuicConnection::peek_next_packet_length(std::span<const std::byte> bytes) const {
    BufferReader reader(bytes);
    const auto first_byte = reader.read_byte();
    if (!first_byte.has_value()) {
        return CodecResult<std::size_t>::failure(first_byte.error().code,
                                                 first_byte.error().offset);
    }

    const auto header_byte = std::to_integer<std::uint8_t>(first_byte.value());
    if ((header_byte & 0x80u) == 0) {
        if ((header_byte & 0x40u) == 0) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
        }
        return CodecResult<std::size_t>::success(bytes.size());
    }
    if ((header_byte & 0x40u) == 0) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<std::size_t>::failure(version.error().code, version.error().offset);
    }
    const auto version_value = read_u32_be(version.value());
    if (!is_supported_quic_version(version_value)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto destination_connection_id_length = reader.read_byte();
    if (!destination_connection_id_length.has_value()) {
        return CodecResult<std::size_t>::failure(destination_connection_id_length.error().code,
                                                 destination_connection_id_length.error().offset);
    }
    const auto destination_connection_id_length_value =
        std::to_integer<std::uint8_t>(destination_connection_id_length.value());
    if (destination_connection_id_length_value > 20) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }
    const auto destination_connection_id =
        reader.read_exact(destination_connection_id_length_value);
    if (!destination_connection_id.has_value()) {
        return CodecResult<std::size_t>::failure(destination_connection_id.error().code,
                                                 destination_connection_id.error().offset);
    }

    const auto source_connection_id_length = reader.read_byte();
    if (!source_connection_id_length.has_value()) {
        return CodecResult<std::size_t>::failure(source_connection_id_length.error().code,
                                                 source_connection_id_length.error().offset);
    }
    const auto source_connection_id_length_value =
        std::to_integer<std::uint8_t>(source_connection_id_length.value());
    if (source_connection_id_length_value > 20) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_varint, reader.offset());
    }
    const auto source_connection_id = reader.read_exact(source_connection_id_length_value);
    if (!source_connection_id.has_value()) {
        return CodecResult<std::size_t>::failure(source_connection_id.error().code,
                                                 source_connection_id.error().offset);
    }

    const auto packet_type = static_cast<std::uint8_t>((header_byte >> 4) & 0x03u);
    if (is_initial_long_header_type(version_value, packet_type)) {
        const auto token_length = decode_varint(reader);
        if (!token_length.has_value()) {
            return CodecResult<std::size_t>::failure(token_length.error().code,
                                                     token_length.error().offset);
        }
        if (token_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                     reader.offset());
        }
        static_cast<void>(reader.read_exact(static_cast<std::size_t>(token_length.value().value)));
    } else if (!is_handshake_long_header_type(version_value, packet_type)) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto payload_length = decode_varint(reader);
    if (!payload_length.has_value()) {
        return CodecResult<std::size_t>::failure(payload_length.error().code,
                                                 payload_length.error().offset);
    }
    if (payload_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::packet_length_mismatch,
                                                 reader.offset());
    }

    return CodecResult<std::size_t>::success(
        reader.offset() + static_cast<std::size_t>(payload_length.value().value));
}

CodecResult<bool> QuicConnection::process_inbound_packet(const ProtectedPacket &packet,
                                                         QuicCoreTimePoint now) {
    return std::visit(
        [&](const auto &protected_packet) -> CodecResult<bool> {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                if (config_.role == EndpointRole::client &&
                    is_supported_quic_version(protected_packet.version) &&
                    protected_packet.version != current_version_) {
                    current_version_ = protected_packet.version;
                }
                if (initial_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                peer_source_connection_id_ = protected_packet.source_connection_id;
                initial_space_.largest_authenticated_packet_number = protected_packet.packet_number;
                const auto processed =
                    process_inbound_crypto(EncryptionLevel::initial, protected_packet.frames, now);
                if (!processed.has_value()) {
                    std::cerr << "quic initial packet reject: frame_count="
                              << protected_packet.frames.size() << '\n';
                }
                if (processed.has_value()) {
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    initial_space_.received_packets.record_received(protected_packet.packet_number,
                                                                    ack_eliciting, now);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        last_peer_activity_time_ = now;
                    }
                    if (ack_eliciting) {
                        initial_space_.pending_ack_deadline = now;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                if (config_.role == EndpointRole::client &&
                    is_supported_quic_version(protected_packet.version) &&
                    protected_packet.version != current_version_) {
                    current_version_ = protected_packet.version;
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                peer_source_connection_id_ = protected_packet.source_connection_id;
                handshake_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_crypto(EncryptionLevel::handshake,
                                                              protected_packet.frames, now);
                if (!processed.has_value()) {
                    std::cerr << "quic handshake packet reject: frame_count="
                              << protected_packet.frames.size() << '\n';
                }
                if (processed.has_value()) {
                    if (config_.role == EndpointRole::server) {
                        discard_initial_packet_space();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    handshake_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        last_peer_activity_time_ = now;
                    }
                    if (ack_eliciting) {
                        handshake_space_.pending_ack_deadline = now;
                    }
                }
                return processed;
            } else {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_application(protected_packet.frames, now);
                if (!processed.has_value()) {
                    std::cerr << "quic one-rtt packet reject: status=" << static_cast<int>(status_)
                              << " frame_count=" << protected_packet.frames.size() << '\n';
                }
                if (processed.has_value()) {
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now);
                    last_peer_activity_time_ = now;
                    if (ack_eliciting) {
                        application_space_.pending_ack_deadline = now;
                    }
                }
                return processed;
            }
        },
        packet);
}

CodecResult<bool> QuicConnection::process_inbound_crypto(EncryptionLevel level,
                                                         std::span<const Frame> frames,
                                                         QuicCoreTimePoint now) {
    auto &packet_space =
        packet_space_for_level(level, initial_space_, handshake_space_, application_space_);

    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
            static_cast<void>(process_inbound_ack(
                packet_space, *ack_frame, now, /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
                config_.role == EndpointRole::client && level == EncryptionLevel::initial));
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            continue;
        }

        if (std::holds_alternative<TransportConnectionCloseFrame>(frame)) {
            mark_failed();
            continue;
        }

        const auto *crypto_frame = std::get_if<CryptoFrame>(&frame);
        if (crypto_frame == nullptr) {
            return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type, 0);
        }

        const auto contiguous_bytes =
            packet_space.receive_crypto.push(crypto_frame->offset, crypto_frame->crypto_data);
        if (!contiguous_bytes.has_value()) {
            return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                              contiguous_bytes.error().offset);
        }
        if (contiguous_bytes.value().empty()) {
            continue;
        }

        if (!tls_.has_value()) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        }

        const auto provided = tls_->provide(level, contiguous_bytes.value());
        if (!provided.has_value()) {
            return provided;
        }

        install_available_secrets();
        collect_pending_tls_bytes();
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_ack(PacketSpaceState &packet_space,
                                                      const AckFrame &ack, QuicCoreTimePoint now,
                                                      std::uint64_t ack_delay_exponent,
                                                      std::uint64_t max_ack_delay_ms,
                                                      bool suppress_pto_reset) {
    std::vector<SentPacketRecord> late_acked_packets;
    std::vector<std::uint64_t> late_acked_packet_numbers;
    for (const auto &[packet_number, packet] : packet_space.declared_lost_packets) {
        if (!ack_frame_acks_packet(ack, packet_number)) {
            continue;
        }

        late_acked_packets.push_back(packet);
        late_acked_packet_numbers.push_back(packet_number);
    }
    for (const auto packet_number : late_acked_packet_numbers) {
        packet_space.declared_lost_packets.erase(packet_number);
    }

    packet_space.recovery.rtt_state() = shared_recovery_rtt_state();
    auto ack_result = packet_space.recovery.on_ack_received(ack, now);
    for (const auto &packet : ack_result.acked_packets) {
        retire_acked_packet(packet_space, packet);
    }
    for (const auto &packet : late_acked_packets) {
        retire_acked_packet(packet_space, packet);
    }
    for (const auto &packet : ack_result.lost_packets) {
        mark_lost_packet(packet_space, packet);
    }

    if (ack_result.largest_acknowledged_was_newly_acked &&
        ack_result.has_newly_acked_ack_eliciting) {
        update_rtt(packet_space.recovery.rtt_state(), now, ack_result.acked_packets.back(),
                   decode_ack_delay(ack, ack_delay_exponent),
                   std::chrono::milliseconds(max_ack_delay_ms));
        recovery_rtt_state_ = packet_space.recovery.rtt_state();
        synchronize_recovery_rtt_state();
    }
    if (&packet_space == &application_space_ && !ack_result.acked_packets.empty()) {
        confirm_handshake();
    }
    if (packet_space_is_application(packet_space, application_space_)) {
        const auto &shared_rtt_state = shared_recovery_rtt_state();
        const auto ack_eliciting_lost_packets =
            ack_eliciting_in_flight_losses(ack_result.lost_packets);
        if (!ack_eliciting_lost_packets.empty()) {
            congestion_controller_.on_loss_event(now);
            if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                                  std::chrono::milliseconds(max_ack_delay_ms))) {
                congestion_controller_.on_persistent_congestion();
            }
        }
        congestion_controller_.on_packets_acked(ack_result.acked_packets,
                                                !has_pending_application_send());
    }
    if (!ack_result.acked_packets.empty() && !suppress_pto_reset) {
        const bool keepalive_probe_packet_space =
            (&packet_space == &initial_space_) | (&packet_space == &handshake_space_);
        const bool client_handshake_keepalive_ack_only =
            (config_.role == EndpointRole::client) & (status_ == HandshakeStatus::in_progress) &
            !handshake_confirmed_ & keepalive_probe_packet_space &
            std::ranges::all_of(ack_result.acked_packets, [&](const SentPacketRecord &packet) {
                return packet.has_ping & (retransmittable_probe_frame_count(packet) == 0);
            });
        if (!client_handshake_keepalive_ack_only) {
            pto_count_ = 0;
        }
    }

    return CodecResult<bool>::success(true);
}

void QuicConnection::track_sent_packet(PacketSpaceState &packet_space,
                                       const SentPacketRecord &packet) {
    packet_space.sent_packets[packet.packet_number] = packet;
    packet_space.recovery.on_packet_sent(packet);
    if (packet_space_is_application(packet_space, application_space_)) {
        congestion_controller_.on_packet_sent(packet.bytes_in_flight, packet.ack_eliciting);
    }
}

void QuicConnection::retire_acked_packet(PacketSpaceState &packet_space,
                                         const SentPacketRecord &packet) {
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.acknowledge(range.offset, range.bytes.size());
    }
    if (packet.max_data_frame.has_value()) {
        connection_flow_control_.acknowledge_max_data_frame(*packet.max_data_frame);
    }
    if (packet.data_blocked_frame.has_value()) {
        connection_flow_control_.acknowledge_data_blocked_frame(*packet.data_blocked_frame);
    }
    for (const auto &frame : packet.max_stream_data_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_max_stream_data_frame(frame);
    }
    for (const auto &frame : packet.stream_data_blocked_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stream_data_blocked_frame(frame);
    }
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_send_fragment(fragment);
        maybe_refresh_peer_stream_limit(stream->second);
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_reset_frame(frame);
        maybe_refresh_peer_stream_limit(stream->second);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stop_sending_frame(frame);
    }
    for (const auto &frame : packet.max_streams_frames) {
        local_stream_limit_state_.acknowledge_max_streams_frame(frame);
    }
    if (packet.has_handshake_done) {
        handshake_done_state_ = StreamControlFrameState::acknowledged;
    }

    packet_space.sent_packets.erase(packet.packet_number);
    packet_space.declared_lost_packets.erase(packet.packet_number);
}

void QuicConnection::mark_lost_packet(PacketSpaceState &packet_space,
                                      const SentPacketRecord &packet) {
    if (packet_space_is_application(packet_space, application_space_)) {
        congestion_controller_.on_packets_lost(std::span<const SentPacketRecord>(&packet, 1));
    }
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.mark_lost(range.offset, range.bytes.size());
    }
    if (packet.max_data_frame.has_value()) {
        connection_flow_control_.mark_max_data_frame_lost(*packet.max_data_frame);
    }
    if (packet.data_blocked_frame.has_value()) {
        connection_flow_control_.mark_data_blocked_frame_lost(*packet.data_blocked_frame);
    }
    for (const auto &frame : packet.max_stream_data_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_max_stream_data_frame_lost(frame);
    }
    for (const auto &frame : packet.stream_data_blocked_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_stream_data_blocked_frame_lost(frame);
    }
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_send_fragment_lost(fragment);
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_reset_frame_lost(frame);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.mark_stop_sending_frame_lost(frame);
    }
    for (const auto &frame : packet.max_streams_frames) {
        local_stream_limit_state_.mark_max_streams_frame_lost(frame);
    }
    const bool lost_handshake_done =
        packet.has_handshake_done &
        (handshake_done_state_ != StreamControlFrameState::acknowledged);
    if (lost_handshake_done) {
        handshake_done_state_ = StreamControlFrameState::pending;
    }

    packet_space.sent_packets.erase(packet.packet_number);
    auto declared_lost = packet;
    declared_lost.declared_lost = true;
    declared_lost.in_flight = false;
    declared_lost.bytes_in_flight = 0;
    packet_space.declared_lost_packets[packet.packet_number] = std::move(declared_lost);
}

void QuicConnection::rebuild_recovery(PacketSpaceState &packet_space) {
    const auto largest_acked = packet_space.recovery.largest_acked_packet_number();
    const auto rtt_state = packet_space.recovery.rtt_state();

    packet_space.recovery = PacketSpaceRecovery{};
    packet_space.recovery.rtt_state() = rtt_state;
    if (largest_acked.has_value()) {
        static_cast<void>(packet_space.recovery.on_ack_received(
            AckFrame{
                .largest_acknowledged = *largest_acked,
                .first_ack_range = 0,
            },
            QuicCoreTimePoint{}));
    }

    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        packet_space.recovery.on_packet_sent(packet);
    }
}

CodecResult<bool> QuicConnection::process_inbound_application(std::span<const Frame> frames,
                                                              QuicCoreTimePoint now) {
    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
            const auto ack_delay_exponent = peer_transport_parameters_.has_value()
                                                ? peer_transport_parameters_->ack_delay_exponent
                                                : TransportParameters{}.ack_delay_exponent;
            const auto max_ack_delay_ms = peer_transport_parameters_.has_value()
                                              ? peer_transport_parameters_->max_ack_delay
                                              : TransportParameters{}.max_ack_delay;
            static_cast<void>(process_inbound_ack(application_space_, *ack_frame, now,
                                                  ack_delay_exponent, max_ack_delay_ms,
                                                  /*suppress_pto_reset=*/false));
            continue;
        }

        const auto *stream_frame = std::get_if<StreamFrame>(&frame);
        if (stream_frame != nullptr) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            if (stream_frame->has_offset && !stream_frame->offset.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            const auto stream_offset = stream_frame->offset.value_or(0);

            auto stream = get_or_open_receive_stream(stream_frame->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            auto *stream_state = stream.value();
            if (stream_state->peer_reset_received) {
                continue;
            }

            const auto previous_highest_offset = stream_state->highest_received_offset;
            const auto validated = stream_state->validate_receive_range(
                stream_offset, stream_frame->stream_data.size(), stream_frame->fin);
            if (!validated.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            const auto received_delta =
                stream_state->highest_received_offset - previous_highest_offset;
            if (connection_flow_control_.received_committed >
                    connection_flow_control_.advertised_max_data ||
                received_delta > connection_flow_control_.advertised_max_data -
                                     connection_flow_control_.received_committed) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            connection_flow_control_.received_committed += received_delta;

            const auto contiguous_bytes =
                stream_state->receive_buffer.push(stream_offset, stream_frame->stream_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                                  contiguous_bytes.error().offset);
            }

            stream_state->receive_flow_control_consumed +=
                static_cast<std::uint64_t>(contiguous_bytes.value().size());
            const auto fin_ready =
                stream_state->peer_final_size.has_value() &&
                stream_state->receive_flow_control_consumed == *stream_state->peer_final_size &&
                !stream_state->peer_fin_delivered;
            if (!contiguous_bytes.value().empty() || fin_ready) {
                pending_stream_receive_effects_.push_back(QuicCoreReceiveStreamData{
                    .stream_id = stream_frame->stream_id,
                    .bytes = contiguous_bytes.value(),
                    .fin = fin_ready,
                });
                stream_state->flow_control.delivered_bytes +=
                    static_cast<std::uint64_t>(contiguous_bytes.value().size());
                connection_flow_control_.delivered_bytes +=
                    static_cast<std::uint64_t>(contiguous_bytes.value().size());
                if (fin_ready) {
                    stream_state->peer_fin_delivered = true;
                }
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/false);
                maybe_refresh_connection_receive_credit(/*force=*/false);
                maybe_refresh_peer_stream_limit(*stream_state);
            }
            continue;
        }

        if (const auto *reset_stream = std::get_if<ResetStreamFrame>(&frame)) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto stream = get_or_open_receive_stream(reset_stream->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            auto *stream_state = stream.value();
            const auto noted = stream_state->note_peer_reset(*reset_stream);
            if (!noted.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            pending_peer_reset_effects_.push_back(QuicCorePeerResetStream{
                .stream_id = reset_stream->stream_id,
                .application_error_code = reset_stream->application_protocol_error_code,
                .final_size = reset_stream->final_size,
            });
            maybe_refresh_peer_stream_limit(*stream_state);
            continue;
        }

        if (const auto *stop_sending = std::get_if<StopSendingFrame>(&frame)) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto stream = get_or_open_send_stream_for_peer_stop(stop_sending->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            auto *stream_state = stream.value();
            static_cast<void>(stream_state->note_peer_stop_sending(
                stop_sending->application_protocol_error_code));

            pending_peer_stop_effects_.push_back(QuicCorePeerStopSending{
                .stream_id = stop_sending->stream_id,
                .application_error_code = stop_sending->application_protocol_error_code,
            });
            continue;
        }

        if (const auto *max_data = std::get_if<MaxDataFrame>(&frame)) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            connection_flow_control_.note_peer_max_data(max_data->maximum_data);
            if (total_queued_stream_bytes() <= connection_flow_control_.peer_max_data) {
                connection_flow_control_.pending_data_blocked_frame = std::nullopt;
                connection_flow_control_.data_blocked_state = StreamControlFrameState::none;
            }
            continue;
        }

        if (const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&frame)) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto stream = get_or_open_send_stream(max_stream_data->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            stream.value()->note_peer_max_stream_data(max_stream_data->maximum_stream_data);
            continue;
        }

        if (const auto *max_streams = std::get_if<MaxStreamsFrame>(&frame)) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            stream_open_limits_.note_peer_max_streams(max_streams->stream_type,
                                                      max_streams->maximum_streams);
            continue;
        }

        if (const auto *data_blocked = std::get_if<DataBlockedFrame>(&frame)) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            if (data_blocked->maximum_data >= connection_flow_control_.advertised_max_data) {
                maybe_refresh_connection_receive_credit(/*force=*/true);
            }
            continue;
        }

        if (const auto *stream_data_blocked = std::get_if<StreamDataBlockedFrame>(&frame)) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto stream = get_or_open_receive_stream(stream_data_blocked->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

            auto *stream_state = stream.value();
            if (stream_data_blocked->maximum_stream_data >=
                stream_state->flow_control.advertised_max_stream_data) {
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/true);
            }
            continue;
        }

        if (std::holds_alternative<StreamsBlockedFrame>(frame)) {
            if (status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }
            continue;
        }

        if (std::holds_alternative<NewConnectionIdFrame>(frame)) {
            continue;
        }

        const bool has_transport_close =
            std::holds_alternative<TransportConnectionCloseFrame>(frame);
        const bool has_application_close =
            std::holds_alternative<ApplicationConnectionCloseFrame>(frame);
        if (has_transport_close | has_application_close) {
            mark_failed();
            continue;
        }

        if (std::holds_alternative<HandshakeDoneFrame>(frame)) {
            confirm_handshake();
            continue;
        }

        if (status_ != HandshakeStatus::connected) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
        }
    }

    return CodecResult<bool>::success(true);
}

void QuicConnection::install_available_secrets() {
    if (!tls_.has_value()) {
        return;
    }

    for (auto &available_secret : tls_->take_available_secrets()) {
        available_secret.secret.quic_version = current_version_;
        auto &packet_space = packet_space_for_level(available_secret.level, initial_space_,
                                                    handshake_space_, application_space_);
        if (available_secret.sender == config_.role) {
            packet_space.write_secret = std::move(available_secret.secret);
        } else {
            packet_space.read_secret = std::move(available_secret.secret);
        }
    }
}

void QuicConnection::collect_pending_tls_bytes() {
    if (!tls_.has_value()) {
        return;
    }

    initial_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::initial));
    handshake_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::handshake));
    application_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::application));
}

CodecResult<bool> QuicConnection::sync_tls_state() {
    install_available_secrets();
    collect_pending_tls_bytes();

    const auto validated = validate_peer_transport_parameters_if_ready();
    if (!validated.has_value()) {
        return validated;
    }

    update_handshake_status();
    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::validate_peer_transport_parameters_if_ready() {
    if (peer_transport_parameters_validated_ || !tls_.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto &peer_transport_parameters_bytes = tls_->peer_transport_parameters();
    if (!peer_transport_parameters_bytes.has_value()) {
        return CodecResult<bool>::success(true);
    }

    if (!peer_transport_parameters_.has_value()) {
        const auto parameters =
            deserialize_transport_parameters(peer_transport_parameters_bytes.value());
        if (!parameters.has_value()) {
            log_codec_failure("deserialize_transport_parameters", parameters.error());
            return CodecResult<bool>::failure(parameters.error().code, parameters.error().offset);
        }

        peer_transport_parameters_ = parameters.value();
    }

    const auto validation_context = peer_transport_parameters_validation_context();
    if (!validation_context.has_value()) {
        return CodecResult<bool>::success(true);
    }

    const auto validation = validate_peer_transport_parameters(opposite_role(config_.role),
                                                               peer_transport_parameters_.value(),
                                                               validation_context.value());
    if (!validation.has_value()) {
        log_codec_failure("validate_peer_transport_parameters", validation.error());
        return CodecResult<bool>::failure(validation.error().code, validation.error().offset);
    }

    peer_transport_parameters_validated_ = true;
    initialize_peer_flow_control_from_transport_parameters();
    return CodecResult<bool>::success(true);
}

void QuicConnection::update_handshake_status() {
    if (status_ == HandshakeStatus::failed || !started_) {
        return;
    }
    if (!tls_.has_value()) {
        return;
    }

    const bool handshake_ready = tls_->handshake_complete() & peer_transport_parameters_validated_ &
                                 application_space_.read_secret.has_value() &
                                 application_space_.write_secret.has_value();
    if (handshake_ready) {
        if (status_ != HandshakeStatus::connected) {
            status_ = HandshakeStatus::connected;
            queue_state_change(QuicCoreStateChange::handshake_ready);
        }
        if (config_.role == EndpointRole::server) {
            if (handshake_done_state_ == StreamControlFrameState::none) {
                handshake_done_state_ = StreamControlFrameState::pending;
            }
        }
    } else {
        status_ = HandshakeStatus::in_progress;
    }
}

void QuicConnection::confirm_handshake() {
    if (handshake_confirmed_) {
        return;
    }

    handshake_confirmed_ = true;
    discard_handshake_packet_space();
}

bool QuicConnection::should_reset_client_handshake_peer_state(
    const ConnectionId &source_connection_id) const {
    return config_.role == EndpointRole::client && status_ == HandshakeStatus::in_progress &&
           !handshake_confirmed_ && peer_source_connection_id_.has_value() &&
           peer_source_connection_id_.value() != source_connection_id;
}

void QuicConnection::reset_client_handshake_peer_state_for_new_source_connection_id() {
    reset_packet_space_receive_state(initial_space_);
    reset_packet_space_receive_state(handshake_space_);
    deferred_protected_packets_.clear();
    peer_transport_parameters_.reset();
    peer_transport_parameters_validated_ = false;
}

void QuicConnection::discard_initial_packet_space() {
    recovery_rtt_state_ = shared_recovery_rtt_state();
    initial_packet_space_discarded_ = true;
    discard_packet_space_state(initial_space_);
    pto_count_ = 0;
}

void QuicConnection::discard_handshake_packet_space() {
    recovery_rtt_state_ = shared_recovery_rtt_state();
    discard_packet_space_state(handshake_space_);
    pto_count_ = 0;
}

void QuicConnection::mark_failed() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    status_ = HandshakeStatus::failed;
    streams_.clear();
    deferred_protected_packets_.clear();
    pending_stream_receive_effects_.clear();
    pending_peer_reset_effects_.clear();
    pending_peer_stop_effects_.clear();
    pending_state_changes_.clear();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::queue_state_change(QuicCoreStateChange change) {
    if (change == QuicCoreStateChange::handshake_ready) {
        if (handshake_ready_emitted_) {
            return;
        }
        handshake_ready_emitted_ = true;
    } else {
        if (failed_emitted_) {
            return;
        }
        failed_emitted_ = true;
    }

    pending_state_changes_.push_back(change);
}

std::optional<TransportParametersValidationContext>
QuicConnection::peer_transport_parameters_validation_context() const {
    if (!peer_source_connection_id_.has_value()) {
        return std::nullopt;
    }

    if (config_.role == EndpointRole::client) {
        const auto expected_version_information =
            make_local_version_information(config_.supported_versions, current_version_);
        return TransportParametersValidationContext{
            .expected_initial_source_connection_id = peer_source_connection_id_.value(),
            .expected_original_destination_connection_id =
                client_initial_destination_connection_id(),
            .expected_retry_source_connection_id = std::nullopt,
            .expected_version_information = expected_version_information,
            .reacted_to_version_negotiation = config_.reacted_to_version_negotiation,
        };
    }

    const auto expected_version_information =
        make_local_version_information(config_.supported_versions, original_version_);
    return TransportParametersValidationContext{
        .expected_initial_source_connection_id = peer_source_connection_id_.value(),
        .expected_original_destination_connection_id = std::nullopt,
        .expected_retry_source_connection_id = std::nullopt,
        .expected_version_information = expected_version_information,
    };
}

void QuicConnection::initialize_local_flow_control() {
    connection_flow_control_ = ConnectionFlowControlState{
        .local_receive_window = local_transport_parameters_.initial_max_data,
        .advertised_max_data = local_transport_parameters_.initial_max_data,
    };
    local_stream_limit_state_.initialize(PeerStreamOpenLimits{
        .bidirectional = local_transport_parameters_.initial_max_streams_bidi,
        .unidirectional = local_transport_parameters_.initial_max_streams_uni,
    });
}

void QuicConnection::initialize_peer_flow_control_from_transport_parameters() {
    if (!peer_transport_parameters_.has_value()) {
        return;
    }

    connection_flow_control_.note_peer_max_data(peer_transport_parameters_->initial_max_data);
    stream_open_limits_.note_peer_max_streams(StreamLimitType::bidirectional,
                                              peer_transport_parameters_->initial_max_streams_bidi);
    stream_open_limits_.note_peer_max_streams(StreamLimitType::unidirectional,
                                              peer_transport_parameters_->initial_max_streams_uni);

    for (auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        initialize_stream_flow_control(stream);
    }
}

std::uint64_t QuicConnection::initial_stream_send_limit(std::uint64_t stream_id) const {
    if (!peer_transport_parameters_.has_value()) {
        return 0;
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        return 0;
    }
    if (id_info.direction == StreamDirection::unidirectional) {
        return peer_transport_parameters_->initial_max_stream_data_uni;
    }
    if (id_info.initiator == StreamInitiator::local) {
        return peer_transport_parameters_->initial_max_stream_data_bidi_remote;
    }

    return peer_transport_parameters_->initial_max_stream_data_bidi_local;
}

std::uint64_t QuicConnection::initial_stream_receive_window(std::uint64_t stream_id) const {
    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return 0;
    }
    if (id_info.direction == StreamDirection::unidirectional) {
        return local_transport_parameters_.initial_max_stream_data_uni;
    }
    if (id_info.initiator == StreamInitiator::local) {
        return local_transport_parameters_.initial_max_stream_data_bidi_local;
    }

    return local_transport_parameters_.initial_max_stream_data_bidi_remote;
}

void QuicConnection::initialize_stream_flow_control(StreamState &stream) const {
    stream.flow_control.peer_max_stream_data = initial_stream_send_limit(stream.stream_id);
    stream.flow_control.local_receive_window = initial_stream_receive_window(stream.stream_id);
    stream.flow_control.advertised_max_stream_data = stream.flow_control.local_receive_window;
    stream.send_flow_control_limit = stream.flow_control.peer_max_stream_data;
    stream.receive_flow_control_limit = stream.flow_control.advertised_max_stream_data;
}

StreamStateResult<StreamState *> QuicConnection::get_or_open_local_stream(std::uint64_t stream_id) {
    if (const auto existing = streams_.find(stream_id); existing != streams_.end()) {
        return StreamStateResult<StreamState *>::success(&existing->second);
    }

    if (!is_local_implicit_stream_open_allowed(stream_id, config_.role)) {
        const auto id_info = classify_stream_id(stream_id, config_.role);
        const auto code = !id_info.local_can_send ? StreamStateErrorCode::invalid_stream_direction
                                                  : StreamStateErrorCode::invalid_stream_id;
        return StreamStateResult<StreamState *>::failure(code, stream_id);
    }
    if (!stream_open_limits_.can_open_local_stream(stream_id, config_.role)) {
        return StreamStateResult<StreamState *>::failure(StreamStateErrorCode::invalid_stream_id,
                                                         stream_id);
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return StreamStateResult<StreamState *>::success(&it->second);
}

StreamStateResult<StreamState *>
QuicConnection::get_existing_receive_stream(std::uint64_t stream_id) {
    if (const auto existing = streams_.find(stream_id); existing != streams_.end()) {
        return StreamStateResult<StreamState *>::success(&existing->second);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return StreamStateResult<StreamState *>::failure(
            StreamStateErrorCode::invalid_stream_direction, stream_id);
    }

    return StreamStateResult<StreamState *>::failure(StreamStateErrorCode::invalid_stream_id,
                                                     stream_id);
}

CodecResult<StreamState *> QuicConnection::get_or_open_receive_stream(std::uint64_t stream_id) {
    if (const auto existing = streams_.find(stream_id); existing != streams_.end()) {
        return CodecResult<StreamState *>::success(&existing->second);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_receive) {
        return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
    }
    if (stream_id == kCompatibilityStreamId && id_info.initiator == StreamInitiator::local) {
        auto [it, inserted] =
            streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
        static_cast<void>(inserted);
        initialize_stream_flow_control(it->second);
        return CodecResult<StreamState *>::success(&it->second);
    }
    if (id_info.initiator != StreamInitiator::peer ||
        !is_peer_implicit_stream_open_allowed_by_limits(stream_id, config_.role,
                                                        peer_stream_open_limits())) {
        return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return CodecResult<StreamState *>::success(&it->second);
}

CodecResult<StreamState *> QuicConnection::get_or_open_send_stream(std::uint64_t stream_id) {
    if (const auto existing = streams_.find(stream_id); existing != streams_.end()) {
        return CodecResult<StreamState *>::success(&existing->second);
    }

    const auto id_info = classify_stream_id(stream_id, config_.role);
    if (!id_info.local_can_send) {
        return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
    }

    if (id_info.initiator == StreamInitiator::local) {
        const auto local_stream = get_or_open_local_stream(stream_id);
        if (!local_stream.has_value()) {
            return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
        }
        return CodecResult<StreamState *>::success(local_stream.value());
    }

    if (!is_peer_implicit_stream_open_allowed_by_limits(stream_id, config_.role,
                                                        peer_stream_open_limits())) {
        return CodecResult<StreamState *>::failure(CodecErrorCode::invalid_varint, 0);
    }

    auto [it, inserted] =
        streams_.emplace(stream_id, make_implicit_stream_state(stream_id, config_.role));
    static_cast<void>(inserted);
    initialize_stream_flow_control(it->second);
    return CodecResult<StreamState *>::success(&it->second);
}

CodecResult<StreamState *>
QuicConnection::get_or_open_send_stream_for_peer_stop(std::uint64_t stream_id) {
    return get_or_open_send_stream(stream_id);
}

PeerStreamOpenLimits QuicConnection::peer_stream_open_limits() const {
    return PeerStreamOpenLimits{
        .bidirectional = local_stream_limit_state_.advertised_max_streams_bidi == 0
                             ? (local_transport_parameters_.initial_max_streams_bidi == 0
                                    ? config_.transport.initial_max_streams_bidi
                                    : local_transport_parameters_.initial_max_streams_bidi)
                             : local_stream_limit_state_.advertised_max_streams_bidi,
        .unidirectional = local_stream_limit_state_.advertised_max_streams_uni == 0
                              ? (local_transport_parameters_.initial_max_streams_uni == 0
                                     ? config_.transport.initial_max_streams_uni
                                     : local_transport_parameters_.initial_max_streams_uni)
                              : local_stream_limit_state_.advertised_max_streams_uni,
    };
}

bool QuicConnection::has_pending_application_send() const {
    if (handshake_done_state_ == StreamControlFrameState::pending) {
        return true;
    }

    if (connection_flow_control_.max_data_state == StreamControlFrameState::pending ||
        connection_flow_control_.data_blocked_state == StreamControlFrameState::pending) {
        return true;
    }
    if (local_stream_limit_state_.max_streams_bidi_state == StreamControlFrameState::pending ||
        local_stream_limit_state_.max_streams_uni_state == StreamControlFrameState::pending) {
        return true;
    }

    const auto connection_send_credit =
        connection_flow_control_.peer_max_data > connection_flow_control_.highest_sent
            ? connection_flow_control_.peer_max_data - connection_flow_control_.highest_sent
            : 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        const bool has_pending_control_frame =
            (stream.reset_state == StreamControlFrameState::pending) |
            (stream.stop_sending_state == StreamControlFrameState::pending) |
            (stream.flow_control.max_stream_data_state == StreamControlFrameState::pending) |
            (stream.flow_control.stream_data_blocked_state == StreamControlFrameState::pending);
        if (has_pending_control_frame) {
            return true;
        }
        if (stream.reset_state != StreamControlFrameState::none) {
            continue;
        }

        const auto fin_sendable = stream_fin_sendable(stream);
        if (stream.send_buffer.has_lost_data() || fin_sendable) {
            return true;
        }
        if (connection_send_credit != 0 && stream.sendable_bytes() != 0) {
            return true;
        }
    }

    return false;
}

std::uint64_t QuicConnection::total_queued_stream_bytes() const {
    std::uint64_t total = 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        total += stream.send_flow_control_committed;
    }

    return total;
}

void QuicConnection::maybe_queue_connection_blocked_frame() {
    const auto queued_bytes = total_queued_stream_bytes();
    const bool should_skip_queue =
        !connection_flow_control_.should_send_data_blocked(queued_bytes) |
        (connection_flow_control_.sendable_bytes(queued_bytes) != 0);
    if (should_skip_queue) {
        return;
    }

    connection_flow_control_.queue_data_blocked(connection_flow_control_.peer_max_data);
}

void QuicConnection::maybe_queue_stream_blocked_frame(StreamState &stream) {
    if (stream.sendable_bytes() != 0) {
        return;
    }

    stream.queue_stream_data_blocked();
}

void QuicConnection::maybe_refresh_connection_receive_credit(bool force) {
    if (!should_refresh_receive_window(connection_flow_control_.delivered_bytes,
                                       connection_flow_control_.advertised_max_data,
                                       connection_flow_control_.local_receive_window, force)) {
        return;
    }

    connection_flow_control_.queue_max_data(connection_flow_control_.delivered_bytes +
                                            connection_flow_control_.local_receive_window);
}

void QuicConnection::maybe_refresh_stream_receive_credit(StreamState &stream, bool force) {
    if (!should_refresh_receive_window(stream.flow_control.delivered_bytes,
                                       stream.flow_control.advertised_max_stream_data,
                                       stream.flow_control.local_receive_window, force)) {
        return;
    }

    stream.queue_max_stream_data(stream.flow_control.delivered_bytes +
                                 stream.flow_control.local_receive_window);
}

void QuicConnection::maybe_refresh_peer_stream_limit(StreamState &stream) {
    if (stream.peer_stream_limit_released || stream.id_info.initiator != StreamInitiator::peer ||
        !stream_receive_terminal(stream) || !stream_send_terminal(stream)) {
        return;
    }

    stream.peer_stream_limit_released = true;
    if (stream.id_info.direction == StreamDirection::bidirectional) {
        local_stream_limit_state_.queue_max_streams(StreamLimitType::bidirectional,
                                                    peer_stream_open_limits().bidirectional + 1);
        return;
    }

    local_stream_limit_state_.queue_max_streams(StreamLimitType::unidirectional,
                                                peer_stream_open_limits().unidirectional + 1);
}

ConnectionId QuicConnection::outbound_destination_connection_id() const {
    if (peer_source_connection_id_.has_value()) {
        return peer_source_connection_id_.value();
    }

    return config_.initial_destination_connection_id;
}

ConnectionId QuicConnection::client_initial_destination_connection_id() const {
    if (client_initial_destination_connection_id_.has_value()) {
        return client_initial_destination_connection_id_.value();
    }

    return config_.initial_destination_connection_id;
}

std::vector<std::byte> QuicConnection::flush_outbound_datagram(QuicCoreTimePoint now) {
    auto packets = std::vector<ProtectedPacket>{};
    const auto destination_connection_id = outbound_destination_connection_id();
    const auto initial_destination_connection_id = config_.role == EndpointRole::client
                                                       ? client_initial_destination_connection_id()
                                                       : destination_connection_id;
    const bool duplicate_first_compatible_server_initial_crypto =
        (config_.role == EndpointRole::server) && (original_version_ != current_version_) &&
        (initial_space_.next_send_packet_number == 0) &&
        (handshake_space_.next_send_packet_number == 0);
    const bool initial_probe_pending = initial_space_.pending_probe_packet.has_value();
    const bool handshake_probe_pending = handshake_space_.pending_probe_packet.has_value();
    const bool application_probe_pending = application_space_.pending_probe_packet.has_value();
    const auto pto_probe_burst_active =
        (remaining_pto_probe_datagrams_ > 0) &
        (initial_probe_pending | handshake_probe_pending | application_probe_pending);
    const auto preserve_pto_probe_packets =
        pto_probe_burst_active && remaining_pto_probe_datagrams_ > 1;
    const bool track_client_handshake_keepalive_probes = (config_.role == EndpointRole::client) &
                                                         (status_ == HandshakeStatus::in_progress) &
                                                         !handshake_confirmed_;
    const auto clear_probe_packet_after_send =
        [&](std::optional<SentPacketRecord> &pending_probe_packet) {
            if (pending_probe_packet.has_value() && !preserve_pto_probe_packets) {
                pending_probe_packet = std::nullopt;
            }
        };
    const auto note_client_handshake_keepalive_probe = [&](const SentPacketRecord &sent_packet) {
        if (!sent_packet.has_ping || retransmittable_probe_frame_count(sent_packet) != 0) {
            return;
        }

        last_client_handshake_keepalive_probe_time_ = now;
    };
    const bool defer_server_compatible_negotiation_crypto =
        (config_.role == EndpointRole::server) && (original_version_ != current_version_) &&
        !peer_transport_parameters_validated_;
    const auto initial_packet_version =
        defer_server_compatible_negotiation_crypto ? original_version_ : current_version_;

    std::vector<Frame> initial_frames;
    const auto initial_ack_frame =
        initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now);
    auto initial_crypto_ranges = std::vector<ByteRange>{};
    if (!defer_server_compatible_negotiation_crypto) {
        initial_crypto_ranges =
            initial_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    }
    initial_frames.reserve(initial_crypto_ranges.size() +
                           (initial_ack_frame.has_value() ? 1u : 0u) +
                           (initial_space_.pending_probe_packet.has_value()
                                ? initial_space_.pending_probe_packet->crypto_ranges.size() + 1u
                                : 0u));
    for (const auto &range : initial_crypto_ranges) {
        initial_frames.emplace_back(CryptoFrame{
            .offset = range.offset,
            .crypto_data = range.bytes.to_vector(),
        });
    }
    if (initial_ack_frame.has_value() && initial_crypto_ranges.empty()) {
        initial_frames.emplace_back(*initial_ack_frame);
    }
    if (!defer_server_compatible_negotiation_crypto &&
        initial_space_.pending_probe_packet.has_value() &&
        !has_ack_eliciting_frame(initial_frames)) {
        for (const auto &range : initial_space_.pending_probe_packet->crypto_ranges) {
            initial_frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
        if (!has_ack_eliciting_frame(initial_frames)) {
            initial_frames.emplace_back(PingFrame{});
        }
    }
    if (!initial_frames.empty()) {
        const bool duplicate_compatible_negotiation_initial_crypto =
            duplicate_first_compatible_server_initial_crypto && !initial_crypto_ranges.empty();
        const auto build_initial_frames = [&]() {
            std::vector<Frame> frames;
            frames.reserve(initial_frames.size());
            frames.insert(frames.end(), initial_frames.begin(), initial_frames.end());
            return frames;
        };
        const auto packet_number = initial_space_.next_send_packet_number++;

        packets.emplace_back(ProtectedInitialPacket{
            .version = initial_packet_version,
            .destination_connection_id = initial_destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .token = {},
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = packet_number,
            .frames = build_initial_frames(),
        });

        SentPacketRecord sent_packet{
            .packet_number = packet_number,
            .sent_time = now,
            .ack_eliciting = has_ack_eliciting_frame(initial_frames),
            .in_flight = has_ack_eliciting_frame(initial_frames),
            .declared_lost = false,
            .crypto_ranges = initial_crypto_ranges,
        };
        if (!defer_server_compatible_negotiation_crypto &&
            initial_space_.pending_probe_packet.has_value() && sent_packet.crypto_ranges.empty()) {
            sent_packet.crypto_ranges = initial_space_.pending_probe_packet->crypto_ranges;
            sent_packet.has_ping = initial_space_.pending_probe_packet->has_ping;
        }
        track_sent_packet(initial_space_, sent_packet);
        if (track_client_handshake_keepalive_probes) {
            note_client_handshake_keepalive_probe(sent_packet);
        }
        if (initial_space_.received_packets.has_ack_to_send()) {
            initial_space_.received_packets.on_ack_sent();
            initial_space_.pending_ack_deadline = std::nullopt;
            initial_space_.force_ack_send = false;
        }
        if (!defer_server_compatible_negotiation_crypto) {
            clear_probe_packet_after_send(initial_space_.pending_probe_packet);
        }

        if (duplicate_compatible_negotiation_initial_crypto) {
            const auto duplicate_packet_number = initial_space_.next_send_packet_number++;
            packets.emplace_back(ProtectedInitialPacket{
                .version = initial_packet_version,
                .destination_connection_id = initial_destination_connection_id,
                .source_connection_id = config_.source_connection_id,
                .token = {},
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = duplicate_packet_number,
                .frames = build_initial_frames(),
            });

            track_sent_packet(initial_space_,
                              SentPacketRecord{
                                  .packet_number = duplicate_packet_number,
                                  .sent_time = now,
                                  .ack_eliciting = has_ack_eliciting_frame(initial_frames),
                                  .in_flight = has_ack_eliciting_frame(initial_frames),
                                  .declared_lost = false,
                                  .crypto_ranges = initial_crypto_ranges,
                              });
        }
    }

    std::vector<Frame> handshake_frames;
    auto handshake_crypto_ranges = std::vector<ByteRange>{};
    if (!defer_server_compatible_negotiation_crypto) {
        if (const auto ack_frame =
                handshake_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now)) {
            handshake_frames.emplace_back(*ack_frame);
        }
        handshake_crypto_ranges =
            handshake_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
        for (const auto &range : handshake_crypto_ranges) {
            handshake_frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes.to_vector(),
            });
        }
        if (handshake_space_.pending_probe_packet.has_value() &&
            !has_ack_eliciting_frame(handshake_frames)) {
            for (const auto &range : handshake_space_.pending_probe_packet->crypto_ranges) {
                handshake_frames.emplace_back(CryptoFrame{
                    .offset = range.offset,
                    .crypto_data = range.bytes.to_vector(),
                });
            }
            if (!has_ack_eliciting_frame(handshake_frames)) {
                handshake_frames.emplace_back(PingFrame{});
            }
        }
    }
    if (!handshake_frames.empty()) {
        if (!handshake_space_.write_secret.has_value()) {
            mark_failed();
            return {};
        }

        const auto packet_number = handshake_space_.next_send_packet_number++;
        std::vector<Frame> frames;
        frames.reserve(handshake_frames.size());
        frames.insert(frames.end(), handshake_frames.begin(), handshake_frames.end());

        packets.emplace_back(ProtectedHandshakePacket{
            .version = current_version_,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = packet_number,
            .frames = std::move(frames),
        });

        SentPacketRecord sent_packet{
            .packet_number = packet_number,
            .sent_time = now,
            .ack_eliciting = has_ack_eliciting_frame(handshake_frames),
            .in_flight = has_ack_eliciting_frame(handshake_frames),
            .declared_lost = false,
            .crypto_ranges = handshake_crypto_ranges,
        };
        if (handshake_space_.pending_probe_packet.has_value() &&
            sent_packet.crypto_ranges.empty()) {
            sent_packet.crypto_ranges = handshake_space_.pending_probe_packet->crypto_ranges;
            sent_packet.has_ping = handshake_space_.pending_probe_packet->has_ping;
        }
        track_sent_packet(handshake_space_, sent_packet);
        if (track_client_handshake_keepalive_probes) {
            note_client_handshake_keepalive_probe(sent_packet);
        }
        if (handshake_space_.received_packets.has_ack_to_send()) {
            handshake_space_.received_packets.on_ack_sent();
            handshake_space_.pending_ack_deadline = std::nullopt;
            handshake_space_.force_ack_send = false;
        }
        clear_probe_packet_after_send(handshake_space_.pending_probe_packet);
    }

    if (status_ == HandshakeStatus::connected && application_space_.write_secret.has_value() &&
        (application_space_.received_packets.has_ack_to_send() || has_pending_application_send() ||
         application_space_.pending_probe_packet.has_value())) {
        const auto base_ack_frame = application_space_.received_packets.build_ack_frame(
            local_transport_parameters_.ack_delay_exponent, now);
        for (auto &[stream_id, stream] : streams_) {
            static_cast<void>(stream_id);
            maybe_queue_stream_blocked_frame(stream);
        }
        maybe_queue_connection_blocked_frame();
        const auto take_reset_stream_frames = [](auto &streams) -> std::vector<ResetStreamFrame> {
            std::vector<ResetStreamFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_reset_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_stop_sending_frames = [](auto &streams) -> std::vector<StopSendingFrame> {
            std::vector<StopSendingFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_stop_sending_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_max_stream_data_frames =
            [](auto &streams) -> std::vector<MaxStreamDataFrame> {
            std::vector<MaxStreamDataFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_max_stream_data_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_max_streams_frames =
            [&](bool force_ack_only) -> std::vector<MaxStreamsFrame> {
            if (force_ack_only) {
                return {};
            }

            return local_stream_limit_state_.take_max_streams_frames();
        };
        const auto take_stream_data_blocked_frames =
            [](auto &streams) -> std::vector<StreamDataBlockedFrame> {
            std::vector<StreamDataBlockedFrame> frames;
            for (auto &[stream_id, stream] : streams) {
                static_cast<void>(stream_id);
                if (const auto frame = stream.take_stream_data_blocked_frame()) {
                    frames.push_back(*frame);
                }
            }

            return frames;
        };
        const auto take_stream_fragments =
            [](auto &connection_flow, auto &streams, std::size_t max_bytes,
               auto &last_stream_id) -> std::vector<StreamFrameSendFragment> {
            std::vector<StreamFrameSendFragment> fragments;
            auto remaining_bytes = max_bytes;
            auto remaining_connection_credit =
                connection_flow.peer_max_data > connection_flow.highest_sent
                    ? connection_flow.peer_max_data - connection_flow.highest_sent
                    : 0;
            auto loss_phase = true;
            auto allow_zero_byte_round = true;

            for (;;) {
                const bool should_continue_round = (remaining_bytes > 0) | allow_zero_byte_round;
                if (!should_continue_round) {
                    break;
                }
                const auto zero_byte_round = remaining_bytes == 0;
                allow_zero_byte_round = false;
                const auto order = round_robin_stream_order(streams, last_stream_id);
                std::vector<std::uint64_t> active_stream_ids;
                active_stream_ids.reserve(order.size());
                for (const auto stream_id : order) {
                    auto &stream = streams.at(stream_id);
                    if (stream.reset_state != StreamControlFrameState::none) {
                        continue;
                    }

                    const auto active = loss_phase ? stream.send_buffer.has_lost_data() ||
                                                         stream_fin_sendable(stream)
                                                   : stream.sendable_bytes() != 0;
                    if (active) {
                        active_stream_ids.push_back(stream_id);
                    }
                }

                if (active_stream_ids.empty()) {
                    if (loss_phase) {
                        loss_phase = false;
                        continue;
                    }

                    break;
                }

                std::size_t bytes_sent_this_round = 0;
                bool emitted_fragment = false;
                for (const auto stream_id : active_stream_ids) {
                    auto &stream = streams.at(stream_id);

                    const auto highest_sent_before = stream.flow_control.highest_sent;
                    const auto packet_share =
                        std::max<std::size_t>(static_cast<std::size_t>(!zero_byte_round),
                                              remaining_bytes / active_stream_ids.size());
                    const auto new_byte_share =
                        loss_phase || remaining_connection_credit == 0
                            ? 0
                            : std::max<std::uint64_t>(1, remaining_connection_credit /
                                                             active_stream_ids.size());
                    auto stream_fragments = stream.take_send_fragments(StreamSendBudget{
                        .packet_bytes = std::min(remaining_bytes, packet_share),
                        .new_bytes = new_byte_share,
                    });
                    const auto new_bytes_sent =
                        stream.flow_control.highest_sent - highest_sent_before;
                    connection_flow.highest_sent += new_bytes_sent;
                    remaining_connection_credit -= new_bytes_sent;
                    const auto fragment_bytes = stream_fragment_bytes(stream_fragments);
                    remaining_bytes -= fragment_bytes;
                    if (!stream_fragments.empty()) {
                        emitted_fragment = true;
                        last_stream_id = stream_id;
                    }
                    bytes_sent_this_round += fragment_bytes;
                    fragments.insert(fragments.end(),
                                     std::make_move_iterator(stream_fragments.begin()),
                                     std::make_move_iterator(stream_fragments.end()));
                    const bool finished_round = (remaining_bytes == 0) & !zero_byte_round;
                    if (finished_round) {
                        break;
                    }
                }

                if (!emitted_fragment || bytes_sent_this_round == 0) {
                    break;
                }
            }

            return fragments;
        };
        const auto serialize_application_candidate =
            [&](bool include_handshake_done, const std::optional<AckFrame> &ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool include_ping) -> CodecResult<std::vector<std::byte>> {
            std::vector<Frame> candidate_frames;
            if (ack_frame.has_value()) {
                candidate_frames.emplace_back(*ack_frame);
            }
            if (include_handshake_done) {
                candidate_frames.emplace_back(HandshakeDoneFrame{});
            }
            if (max_data_frame.has_value()) {
                candidate_frames.emplace_back(*max_data_frame);
            }
            for (const auto &frame : max_stream_data_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : max_streams_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : reset_stream_frames) {
                candidate_frames.emplace_back(frame);
            }
            for (const auto &frame : stop_sending_frames) {
                candidate_frames.emplace_back(frame);
            }
            if (data_blocked_frame.has_value()) {
                candidate_frames.emplace_back(*data_blocked_frame);
            }
            for (const auto &frame : stream_data_blocked_frames) {
                candidate_frames.emplace_back(frame);
            }
            if (include_ping) {
                candidate_frames.emplace_back(PingFrame{});
            }

            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedOneRttPacket{
                .key_phase = application_write_key_phase_,
                .destination_connection_id = destination_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = application_space_.next_send_packet_number,
                .frames = std::move(candidate_frames),
                .stream_frame_views = make_stream_frame_views(stream_fragments),
            });

            return serialize_protected_datagram(
                candidate_packets, SerializeProtectionContext{
                                       .local_role = config_.role,
                                       .client_initial_destination_connection_id =
                                           client_initial_destination_connection_id(),
                                       .handshake_secret = handshake_space_.write_secret,
                                       .one_rtt_secret = application_space_.write_secret,
                                       .one_rtt_key_phase = application_write_key_phase_,
                                   });
        };
        const auto restore_application_fragment = [&](const StreamFrameSendFragment &fragment) {
            const bool releases_flow_control =
                fragment.consumes_flow_control & !fragment.bytes.empty();
            if (releases_flow_control) {
                connection_flow_control_.highest_sent -=
                    static_cast<std::uint64_t>(fragment.bytes.size());
            }
            streams_.at(fragment.stream_id).restore_send_fragment(fragment);
        };
        const auto restore_unsent_application_candidate =
            [&](const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments) {
                if (max_data_frame.has_value()) {
                    connection_flow_control_.mark_max_data_frame_lost(*max_data_frame);
                }
                if (data_blocked_frame.has_value()) {
                    connection_flow_control_.mark_data_blocked_frame_lost(*data_blocked_frame);
                }
                for (const auto &frame : max_stream_data_frames) {
                    streams_.at(frame.stream_id).mark_max_stream_data_frame_lost(frame);
                }
                for (const auto &frame : max_streams_frames) {
                    local_stream_limit_state_.mark_max_streams_frame_lost(frame);
                }
                for (const auto &frame : stream_data_blocked_frames) {
                    streams_.at(frame.stream_id).mark_stream_data_blocked_frame_lost(frame);
                }
                for (const auto &frame : reset_stream_frames) {
                    streams_.at(frame.stream_id).mark_reset_frame_lost(frame);
                }
                for (const auto &frame : stop_sending_frames) {
                    streams_.at(frame.stream_id).mark_stop_sending_frame_lost(frame);
                }
                for (const auto &fragment : stream_fragments) {
                    restore_application_fragment(fragment);
                }
            };
        const auto trim_application_ack_frame =
            [&](bool include_handshake_done, const std::optional<AckFrame> &candidate_ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
                std::span<const MaxStreamsFrame> max_streams_frames,
                std::span<const ResetStreamFrame> reset_stream_frames,
                std::span<const StopSendingFrame> stop_sending_frames,
                const std::optional<DataBlockedFrame> &data_blocked_frame,
                std::span<const StreamDataBlockedFrame> stream_data_blocked_frames,
                std::span<const StreamFrameSendFragment> stream_fragments,
                bool include_ping) -> std::optional<AckFrame> {
            if (!candidate_ack_frame.has_value()) {
                return std::nullopt;
            }

            auto candidate_datagram = serialize_application_candidate(
                include_handshake_done, candidate_ack_frame, max_data_frame, max_stream_data_frames,
                max_streams_frames, reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, stream_fragments, include_ping);
            if (!candidate_datagram.has_value()) {
                std::cerr << "quic fail trim_application_ack_frame initial_serialize\n";
                mark_failed();
                return std::nullopt;
            }
            if (candidate_ack_frame->additional_ranges.empty() ||
                candidate_datagram.value().size() <= kMaximumDatagramSize) {
                return candidate_ack_frame;
            }

            std::size_t retained_ranges_low = 0;
            std::size_t retained_ranges_high = candidate_ack_frame->additional_ranges.size();
            std::optional<AckFrame> best_trimmed_ack_frame;

            while (retained_ranges_low <= retained_ranges_high) {
                const auto retained_ranges =
                    retained_ranges_low + (retained_ranges_high - retained_ranges_low) / 2;
                auto trimmed_ack_frame = candidate_ack_frame;
                trimmed_ack_frame->additional_ranges.resize(retained_ranges);

                candidate_datagram = CodecResult<std::vector<std::byte>>::success(
                    serialize_application_candidate(
                        include_handshake_done, trimmed_ack_frame, max_data_frame,
                        max_stream_data_frames, max_streams_frames, reset_stream_frames,
                        stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                        stream_fragments, include_ping)
                        .value());

                if (candidate_datagram.value().size() <= kMaximumDatagramSize) {
                    best_trimmed_ack_frame = std::move(trimmed_ack_frame);
                    retained_ranges_low = retained_ranges + 1;
                    continue;
                }

                if (retained_ranges == 0) {
                    break;
                }
                retained_ranges_high = retained_ranges - 1;
            }

            return best_trimmed_ack_frame;
        };

        const auto *pending_application_probe = application_space_.pending_probe_packet.has_value()
                                                    ? &*application_space_.pending_probe_packet
                                                    : nullptr;
        const auto should_send_application_probe_first = [&]() {
            if (pending_application_probe == nullptr) {
                return false;
            }

            return retransmittable_probe_frame_count(*pending_application_probe) != 0 ||
                   !has_pending_application_send();
        };

        if (should_send_application_probe_first()) {
            const auto &probe_packet = *pending_application_probe;
            const auto include_ping = retransmittable_probe_frame_count(probe_packet) == 0;
            const auto make_probe_stream_fragments = [&]() {
                auto fragments = probe_packet.stream_fragments;
                for (auto &fragment : fragments) {
                    fragment.consumes_flow_control = false;
                }
                return fragments;
            };
            const auto restore_probe_fragment = [&](const StreamFrameSendFragment &fragment) {
                const auto stream = streams_.find(fragment.stream_id);
                if (stream == streams_.end()) {
                    return;
                }

                stream->second.mark_send_fragment_lost(fragment);
            };
            const auto mark_probe_fragments_sent =
                [&](std::span<const StreamFrameSendFragment> fragments) {
                    for (const auto &fragment : fragments) {
                        const auto stream = streams_.find(fragment.stream_id);
                        if (stream == streams_.end()) {
                            continue;
                        }

                        stream->second.mark_send_fragment_sent(fragment);
                    }
                };
            auto probe_stream_fragments = make_probe_stream_fragments();
            mark_probe_fragments_sent(probe_stream_fragments);
            auto ack_frame = trim_application_ack_frame(
                probe_packet.has_handshake_done, base_ack_frame, probe_packet.max_data_frame,
                probe_packet.max_stream_data_frames, probe_packet.max_streams_frames,
                probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                probe_stream_fragments, include_ping);
            if (has_failed()) {
                return {};
            }

            auto datagram = serialize_application_candidate(
                probe_packet.has_handshake_done, ack_frame, probe_packet.max_data_frame,
                probe_packet.max_stream_data_frames, probe_packet.max_streams_frames,
                probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                probe_stream_fragments, include_ping);
            if (!datagram.has_value()) {
                std::cerr << "quic fail probe serialize_application_candidate_or_oversize size="
                          << datagram_size_or_zero(datagram)
                          << " error=" << static_cast<int>(datagram.error().code)
                          << " offset=" << datagram.error().offset << '\n';
                mark_failed();
                return {};
            }
            if (ack_frame.has_value() && datagram.value().size() > kMaximumDatagramSize) {
                auto no_ack_datagram = serialize_application_candidate(
                    probe_packet.has_handshake_done, std::nullopt, probe_packet.max_data_frame,
                    probe_packet.max_stream_data_frames, probe_packet.max_streams_frames,
                    probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                    probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                    probe_stream_fragments, include_ping);
                if (!no_ack_datagram.has_value()) {
                    std::cerr << "quic fail probe serialize_application_candidate_or_oversize "
                                 "size="
                              << 0 << " error=" << static_cast<int>(no_ack_datagram.error().code)
                              << " offset=" << no_ack_datagram.error().offset << '\n';
                    mark_failed();
                    return {};
                }
                if (no_ack_datagram.value().size() <= kMaximumDatagramSize) {
                    ack_frame = std::nullopt;
                    datagram = std::move(no_ack_datagram);
                }
            }
            const auto trim_probe_candidate_to_fit =
                [&](const std::optional<AckFrame> &candidate_ack_frame,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().size() > kMaximumDatagramSize && !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_probe_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot = datagram.value().size() - kMaximumDatagramSize;
                        const auto trim_bytes =
                            std::min<std::size_t>(overshoot, last_fragment.bytes.size());
                        if (trim_bytes == last_fragment.bytes.size()) {
                            restore_probe_fragment(last_fragment);
                            fragments.pop_back();
                        } else {
                            StreamFrameSendFragment tail_fragment{
                                .stream_id = last_fragment.stream_id,
                                .offset = last_fragment.offset +
                                          static_cast<std::uint64_t>(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .bytes = last_fragment.bytes.subspan(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .fin = last_fragment.fin,
                                .consumes_flow_control = false,
                            };
                            last_fragment.bytes.resize(last_fragment.bytes.size() - trim_bytes);
                            last_fragment.fin = false;
                            restore_probe_fragment(tail_fragment);
                        }
                    }

                    datagram = serialize_application_candidate(
                        probe_packet.has_handshake_done, candidate_ack_frame,
                        probe_packet.max_data_frame, probe_packet.max_stream_data_frames,
                        probe_packet.max_streams_frames, probe_packet.reset_stream_frames,
                        probe_packet.stop_sending_frames, probe_packet.data_blocked_frame,
                        probe_packet.stream_data_blocked_frames, fragments, include_ping);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return false;
                    }
                }

                return datagram.value().size() <= kMaximumDatagramSize;
            };
            if (!trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments)) {
                if (has_failed()) {
                    return {};
                }

                if (ack_frame.has_value()) {
                    ack_frame = std::nullopt;
                    probe_stream_fragments = make_probe_stream_fragments();
                    mark_probe_fragments_sent(probe_stream_fragments);
                    datagram = serialize_application_candidate(
                        probe_packet.has_handshake_done, ack_frame, probe_packet.max_data_frame,
                        probe_packet.max_stream_data_frames, probe_packet.max_streams_frames,
                        probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                        probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                        probe_stream_fragments, include_ping);
                    if (!datagram.has_value()) {
                        std::cerr
                            << "quic fail probe serialize_application_candidate_or_oversize\n";
                        mark_failed();
                        return {};
                    }
                    static_cast<void>(
                        trim_probe_candidate_to_fit(ack_frame, probe_stream_fragments));
                }
            }
            const auto probe_datagram_size = datagram_size_or_zero(datagram);
            if (has_failed() | (probe_datagram_size > kMaximumDatagramSize)) {
                std::cerr << "quic fail probe serialize_application_candidate_or_oversize size="
                          << probe_datagram_size << '\n';
                mark_failed();
                return {};
            }

            std::vector<Frame> frames;
            if (ack_frame.has_value()) {
                frames.emplace_back(*ack_frame);
            }
            if (probe_packet.has_handshake_done) {
                frames.emplace_back(HandshakeDoneFrame{});
            }
            if (probe_packet.max_data_frame.has_value()) {
                frames.emplace_back(*probe_packet.max_data_frame);
            }
            for (const auto &frame : probe_packet.max_stream_data_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.max_streams_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.reset_stream_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : probe_packet.stop_sending_frames) {
                frames.emplace_back(frame);
            }
            if (probe_packet.data_blocked_frame.has_value()) {
                frames.emplace_back(*probe_packet.data_blocked_frame);
            }
            for (const auto &frame : probe_packet.stream_data_blocked_frames) {
                frames.emplace_back(frame);
            }
            if (include_ping) {
                frames.emplace_back(PingFrame{});
            }

            const auto packet_number = application_space_.next_send_packet_number++;
            packets.emplace_back(ProtectedOneRttPacket{
                .key_phase = application_write_key_phase_,
                .destination_connection_id = destination_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = packet_number,
                .frames = std::move(frames),
                .stream_frame_views = make_stream_frame_views(probe_stream_fragments),
            });

            track_sent_packet(
                application_space_,
                SentPacketRecord{
                    .packet_number = packet_number,
                    .sent_time = now,
                    .ack_eliciting = true,
                    .in_flight = true,
                    .declared_lost = false,
                    .has_handshake_done = probe_packet.has_handshake_done,
                    .reset_stream_frames = probe_packet.reset_stream_frames,
                    .stop_sending_frames = probe_packet.stop_sending_frames,
                    .max_data_frame = probe_packet.max_data_frame,
                    .max_stream_data_frames = probe_packet.max_stream_data_frames,
                    .max_streams_frames = probe_packet.max_streams_frames,
                    .data_blocked_frame = probe_packet.data_blocked_frame,
                    .stream_data_blocked_frames = probe_packet.stream_data_blocked_frames,
                    .stream_fragments = probe_stream_fragments,
                    .has_ping = include_ping,
                    .bytes_in_flight = datagram.value().size(),
                });
            if (probe_packet.has_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            clear_probe_packet_after_send(application_space_.pending_probe_packet);
        } else {
            const auto include_handshake_done =
                config_.role == EndpointRole::server &&
                handshake_done_state_ == StreamControlFrameState::pending;
            std::vector<Frame> frames;
            const auto force_ack_only =
                application_space_.force_ack_send & base_ack_frame.has_value();
            auto max_data_frame = force_ack_only ? std::optional<MaxDataFrame>{}
                                                 : connection_flow_control_.take_max_data_frame();
            auto data_blocked_frame = force_ack_only
                                          ? std::optional<DataBlockedFrame>{}
                                          : connection_flow_control_.take_data_blocked_frame();
            auto max_stream_data_frames = force_ack_only ? std::vector<MaxStreamDataFrame>{}
                                                         : take_max_stream_data_frames(streams_);
            auto max_streams_frames = take_max_streams_frames(force_ack_only);
            auto reset_stream_frames = force_ack_only ? std::vector<ResetStreamFrame>{}
                                                      : take_reset_stream_frames(streams_);
            auto stop_sending_frames = force_ack_only ? std::vector<StopSendingFrame>{}
                                                      : take_stop_sending_frames(streams_);
            auto stream_data_blocked_frames = force_ack_only
                                                  ? std::vector<StreamDataBlockedFrame>{}
                                                  : take_stream_data_blocked_frames(streams_);
            auto candidate_last_stream_id = last_application_send_stream_id_;
            auto stream_fragments =
                force_ack_only
                    ? std::vector<StreamFrameSendFragment>{}
                    : take_stream_fragments(connection_flow_control_, streams_,
                                            kMaximumDatagramSize, candidate_last_stream_id);
            auto selected_ack_frame = trim_application_ack_frame(
                include_handshake_done, base_ack_frame, max_data_frame, max_stream_data_frames,
                max_streams_frames, reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, stream_fragments, /*include_ping=*/false);
            if (selected_ack_frame.has_value()) {
                const auto retransmitting_stream_data = std::ranges::any_of(
                    stream_fragments, [](const StreamFrameSendFragment &fragment) {
                        return !fragment.consumes_flow_control;
                    });
                if (retransmitting_stream_data) {
                    selected_ack_frame = std::nullopt;
                }
            }
            if (has_failed()) {
                return {};
            }

            auto candidate_datagram = serialize_application_candidate(
                include_handshake_done, selected_ack_frame, max_data_frame, max_stream_data_frames,
                max_streams_frames, reset_stream_frames, stop_sending_frames, data_blocked_frame,
                stream_data_blocked_frames, stream_fragments, /*include_ping=*/false);
            if (!candidate_datagram.has_value()) {
                std::cerr << "quic fail app final serialize_application_candidate initial\n";
                mark_failed();
                return {};
            }
            if (selected_ack_frame.has_value() &&
                candidate_datagram.value().size() > kMaximumDatagramSize) {
                auto no_ack_candidate = serialize_application_candidate(
                    include_handshake_done, std::nullopt, max_data_frame, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments,
                    /*include_ping=*/false);
                if (!no_ack_candidate.has_value()) {
                    std::cerr << "quic fail app final serialize_application_candidate no_ack\n";
                    mark_failed();
                    return {};
                }
                if (no_ack_candidate.value().size() <= kMaximumDatagramSize) {
                    selected_ack_frame = std::nullopt;
                    candidate_datagram = std::move(no_ack_candidate);
                }
            }

            const auto trim_candidate_to_fit =
                [&](const std::optional<AckFrame> &ack_frame,
                    CodecResult<std::vector<std::byte>> &datagram,
                    std::vector<StreamFrameSendFragment> &fragments) -> bool {
                while (datagram.value().size() > kMaximumDatagramSize && !fragments.empty()) {
                    auto &last_fragment = fragments.back();
                    if (last_fragment.bytes.empty()) {
                        restore_application_fragment(last_fragment);
                        fragments.pop_back();
                    } else {
                        const auto overshoot = datagram.value().size() - kMaximumDatagramSize;
                        const auto trim_bytes =
                            std::min<std::size_t>(overshoot, last_fragment.bytes.size());
                        if (trim_bytes == last_fragment.bytes.size()) {
                            restore_application_fragment(last_fragment);
                            fragments.pop_back();
                        } else {
                            StreamFrameSendFragment tail_fragment{
                                .stream_id = last_fragment.stream_id,
                                .offset = last_fragment.offset +
                                          static_cast<std::uint64_t>(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .bytes = last_fragment.bytes.subspan(last_fragment.bytes.size() -
                                                                     trim_bytes),
                                .fin = last_fragment.fin,
                                .consumes_flow_control = last_fragment.consumes_flow_control,
                            };
                            last_fragment.bytes.resize(last_fragment.bytes.size() - trim_bytes);
                            last_fragment.fin = false;
                            restore_application_fragment(tail_fragment);
                        }
                    }

                    datagram = serialize_application_candidate(
                        include_handshake_done, ack_frame, max_data_frame, max_stream_data_frames,
                        max_streams_frames, reset_stream_frames, stop_sending_frames,
                        data_blocked_frame, stream_data_blocked_frames, fragments,
                        /*include_ping=*/false);
                    if (!datagram.has_value()) {
                        mark_failed();
                        return false;
                    }
                }

                return datagram.value().size() <= kMaximumDatagramSize;
            };

            if (!trim_candidate_to_fit(selected_ack_frame, candidate_datagram, stream_fragments)) {
                if (has_failed()) {
                    return {};
                }
                if (selected_ack_frame.has_value()) {
                    restore_unsent_application_candidate(
                        max_data_frame, max_stream_data_frames, max_streams_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, stream_fragments);

                    max_data_frame = connection_flow_control_.take_max_data_frame();
                    data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
                    max_stream_data_frames = take_max_stream_data_frames(streams_);
                    max_streams_frames = take_max_streams_frames(/*force_ack_only=*/false);
                    reset_stream_frames = take_reset_stream_frames(streams_);
                    stop_sending_frames = take_stop_sending_frames(streams_);
                    stream_data_blocked_frames = take_stream_data_blocked_frames(streams_);
                    candidate_last_stream_id = last_application_send_stream_id_;
                    stream_fragments =
                        take_stream_fragments(connection_flow_control_, streams_,
                                              kMaximumDatagramSize, candidate_last_stream_id);
                    selected_ack_frame = std::nullopt;
                    candidate_datagram = serialize_application_candidate(
                        include_handshake_done, selected_ack_frame, max_data_frame,
                        max_stream_data_frames, max_streams_frames, reset_stream_frames,
                        stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                        stream_fragments, /*include_ping=*/false);
                    if (!candidate_datagram.has_value()) {
                        std::cerr << "quic fail app final serialize_application_candidate no_ack\n";
                        mark_failed();
                        return {};
                    }
                    static_cast<void>(trim_candidate_to_fit(selected_ack_frame, candidate_datagram,
                                                            stream_fragments));
                }
            }
            const auto candidate_datagram_size = datagram_size_or_zero(candidate_datagram);
            if (has_failed() | (candidate_datagram_size > kMaximumDatagramSize)) {
                std::cerr << "quic fail app final candidate_datagram oversize size="
                          << candidate_datagram_size << " fragments=" << stream_fragments.size()
                          << '\n';
                mark_failed();
                return {};
            }

            if (selected_ack_frame.has_value()) {
                frames.emplace_back(*selected_ack_frame);
            }
            if (include_handshake_done) {
                frames.emplace_back(HandshakeDoneFrame{});
            }
            const auto ack_eliciting =
                application_ack_eliciting_frame_count(
                    include_handshake_done, max_data_frame, max_stream_data_frames,
                    max_streams_frames, reset_stream_frames, stop_sending_frames,
                    data_blocked_frame, stream_data_blocked_frames, stream_fragments) != 0;
            const auto bypass_congestion_window =
                application_space_.pending_probe_packet.has_value();
            if (ack_eliciting && !bypass_congestion_window &&
                !congestion_controller_.can_send_ack_eliciting(candidate_datagram.value().size())) {
                restore_unsent_application_candidate(max_data_frame, max_stream_data_frames,
                                                     max_streams_frames, reset_stream_frames,
                                                     stop_sending_frames, data_blocked_frame,
                                                     stream_data_blocked_frames, stream_fragments);
                return {};
            }
            last_application_send_stream_id_ = candidate_last_stream_id;

            for (const auto &frame : reset_stream_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : stop_sending_frames) {
                frames.emplace_back(frame);
            }
            if (max_data_frame.has_value()) {
                frames.emplace_back(*max_data_frame);
            }
            for (const auto &frame : max_stream_data_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &frame : max_streams_frames) {
                frames.emplace_back(frame);
            }
            if (data_blocked_frame.has_value()) {
                frames.emplace_back(*data_blocked_frame);
            }
            for (const auto &frame : stream_data_blocked_frames) {
                frames.emplace_back(frame);
            }

            const auto packet_number = application_space_.next_send_packet_number++;
            packets.emplace_back(ProtectedOneRttPacket{
                .key_phase = application_write_key_phase_,
                .destination_connection_id = destination_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = packet_number,
                .frames = std::move(frames),
                .stream_frame_views = make_stream_frame_views(stream_fragments),
            });

            if (ack_eliciting) {
                track_sent_packet(application_space_,
                                  SentPacketRecord{
                                      .packet_number = packet_number,
                                      .sent_time = now,
                                      .ack_eliciting = ack_eliciting,
                                      .in_flight = ack_eliciting,
                                      .declared_lost = false,
                                      .has_handshake_done = include_handshake_done,
                                      .reset_stream_frames = reset_stream_frames,
                                      .stop_sending_frames = stop_sending_frames,
                                      .max_data_frame = max_data_frame,
                                      .max_stream_data_frames = max_stream_data_frames,
                                      .max_streams_frames = max_streams_frames,
                                      .data_blocked_frame = data_blocked_frame,
                                      .stream_data_blocked_frames = stream_data_blocked_frames,
                                      .stream_fragments = stream_fragments,
                                      .bytes_in_flight = candidate_datagram.value().size(),
                                  });
            }
            if (include_handshake_done) {
                handshake_done_state_ = StreamControlFrameState::sent;
            }
            if (selected_ack_frame.has_value()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
                application_space_.force_ack_send = false;
            }
            clear_probe_packet_after_send(application_space_.pending_probe_packet);
        }
    }

    if (packets.empty()) {
        return {};
    }

    auto datagram =
        serialize_protected_datagram(packets, SerializeProtectionContext{
                                                  .local_role = config_.role,
                                                  .client_initial_destination_connection_id =
                                                      client_initial_destination_connection_id(),
                                                  .handshake_secret = handshake_space_.write_secret,
                                                  .one_rtt_secret = application_space_.write_secret,
                                                  .one_rtt_key_phase = application_write_key_phase_,
                                              });
    if (!datagram.has_value()) {
        std::cerr << "quic fail flush serialize_protected_datagram final\n";
        mark_failed();
        return {};
    }

    if (datagram.value().size() < kMinimumInitialDatagramSize) {
        for (auto &packet : packets) {
            auto *initial = std::get_if<ProtectedInitialPacket>(&packet);
            if (initial == nullptr) {
                continue;
            }

            initial->frames.emplace_back(PaddingFrame{
                .length = kMinimumInitialDatagramSize - datagram.value().size(),
            });
            datagram = serialize_protected_datagram(
                packets, SerializeProtectionContext{
                             .local_role = config_.role,
                             .client_initial_destination_connection_id =
                                 client_initial_destination_connection_id(),
                             .handshake_secret = handshake_space_.write_secret,
                             .one_rtt_secret = application_space_.write_secret,
                             .one_rtt_key_phase = application_write_key_phase_,
                         });
            if (!datagram.has_value()) {
                mark_failed();
                return {};
            }
            break;
        }
    }

    if (pto_probe_burst_active) {
        --remaining_pto_probe_datagrams_;
        if (remaining_pto_probe_datagrams_ == 0) {
            initial_space_.pending_probe_packet = std::nullopt;
            handshake_space_.pending_probe_packet = std::nullopt;
            application_space_.pending_probe_packet = std::nullopt;
        }
    }

    if (config_.role == EndpointRole::client) {
        for (const auto &packet : packets) {
            if (std::holds_alternative<ProtectedHandshakePacket>(packet)) {
                discard_initial_packet_space();
                break;
            }
        }
    }

    return datagram.value();
}

} // namespace coquic::quic
