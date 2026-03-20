#include "src/quic/connection.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <limits>
#include <type_traits>
#include <utility>
#include <vector>

#include "src/quic/buffer.h"
#include "src/quic/frame.h"
#include "src/quic/protected_codec.h"

namespace coquic::quic {

namespace {

constexpr std::size_t kMinimumInitialDatagramSize = 1200;
constexpr std::size_t kMaximumDatagramSize = 1200;
constexpr std::uint32_t kQuicVersion1 = 1;
constexpr std::uint8_t kDefaultInitialPacketNumberLength = 2;
constexpr std::uint64_t kCompatibilityStreamId = 0;
constexpr std::uint32_t kPersistentCongestionThreshold = 3;

EndpointRole opposite_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
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
    return std::holds_alternative<CryptoFrame>(frame) ||
           std::holds_alternative<ResetStreamFrame>(frame) ||
           std::holds_alternative<StopSendingFrame>(frame) ||
           std::holds_alternative<StreamFrame>(frame) ||
           std::holds_alternative<MaxDataFrame>(frame) ||
           std::holds_alternative<MaxStreamDataFrame>(frame) ||
           std::holds_alternative<MaxStreamsFrame>(frame) ||
           std::holds_alternative<DataBlockedFrame>(frame) ||
           std::holds_alternative<StreamDataBlockedFrame>(frame) ||
           std::holds_alternative<StreamsBlockedFrame>(frame) ||
           std::holds_alternative<PingFrame>(frame);
}

bool has_ack_eliciting_frame(std::span<const Frame> frames) {
    for (const auto &frame : frames) {
        if (is_ack_eliciting_frame(frame)) {
            return true;
        }
    }

    return false;
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

std::uint64_t saturating_add(std::uint64_t lhs, std::size_t rhs) {
    const auto rhs64 = static_cast<std::uint64_t>(rhs);
    const auto max = std::numeric_limits<std::uint64_t>::max();
    if (rhs64 > max - lhs) {
        return max;
    }

    return lhs + rhs64;
}

std::size_t stream_fragment_bytes(std::span<const StreamFrameSendFragment> fragments) {
    std::size_t total = 0;
    for (const auto &fragment : fragments) {
        total += fragment.bytes.size();
    }

    return total;
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
    return candidate.has_value() && candidate->maximum_data == frame.maximum_data;
}

bool data_blocked_frame_matches(const std::optional<DataBlockedFrame> &candidate,
                                const DataBlockedFrame &frame) {
    return candidate.has_value() && candidate->maximum_data == frame.maximum_data;
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
    return stream.send_fin_state == StreamSendFinState::pending &&
           stream.send_final_size.has_value() &&
           *stream.send_final_size <= stream.flow_control.peer_max_stream_data &&
           !stream.send_buffer.has_pending_data();
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

bool has_ack_eliciting_in_flight_loss(std::span<const SentPacketRecord> packets) {
    return std::any_of(packets.begin(), packets.end(), [](const SentPacketRecord &packet) {
        return packet.ack_eliciting && packet.in_flight && packet.bytes_in_flight != 0;
    });
}

bool establishes_persistent_congestion(std::span<const SentPacketRecord> lost_packets,
                                       const RecoveryRttState &rtt,
                                       std::chrono::milliseconds max_ack_delay) {
    if (!rtt.latest_rtt.has_value()) {
        return false;
    }

    std::optional<QuicCoreTimePoint> first_loss_time;
    std::optional<QuicCoreTimePoint> last_loss_time;
    for (const auto &packet : lost_packets) {
        if (!packet.ack_eliciting || !packet.in_flight || packet.bytes_in_flight == 0) {
            continue;
        }

        if (!first_loss_time.has_value()) {
            first_loss_time = packet.sent_time;
        }
        last_loss_time = packet.sent_time;
    }

    if (!first_loss_time.has_value() || !last_loss_time.has_value() ||
        *last_loss_time <= *first_loss_time) {
        return false;
    }

    const auto persistent_congestion_duration =
        (rtt.smoothed_rtt + std::max(rtt.rttvar * 4, kGranularity) + max_ack_delay) *
        kPersistentCongestionThreshold;
    return *last_loss_time - *first_loss_time >= persistent_congestion_duration;
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

QuicConnection::QuicConnection(QuicCoreConfig config)
    : config_(std::move(config)), congestion_controller_(kMaximumDatagramSize) {
    local_transport_parameters_ = TransportParameters{
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
            mark_failed();
            return;
        }

        start_server_if_needed(initial_destination_connection_id.value());
    }

    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto packet_length = peek_next_packet_length(bytes.subspan(offset));
        if (!packet_length.has_value()) {
            mark_failed();
            return;
        }

        const auto packets = deserialize_protected_datagram(
            bytes.subspan(offset, packet_length.value()),
            DeserializeProtectionContext{
                .peer_role = opposite_role(config_.role),
                .client_initial_destination_connection_id =
                    client_initial_destination_connection_id(),
                .handshake_secret = handshake_space_.read_secret,
                .one_rtt_secret = application_space_.read_secret,
                .largest_authenticated_initial_packet_number =
                    initial_space_.largest_authenticated_packet_number,
                .largest_authenticated_handshake_packet_number =
                    handshake_space_.largest_authenticated_packet_number,
                .largest_authenticated_application_packet_number =
                    application_space_.largest_authenticated_packet_number,
                .one_rtt_destination_connection_id_length = config_.source_connection_id.size(),
            });
        if (!packets.has_value()) {
            mark_failed();
            return;
        }

        for (const auto &packet : packets.value()) {
            if (!process_inbound_packet(packet, now).has_value()) {
                mark_failed();
                return;
            }
        }

        offset += packet_length.value();
    }

    if (!sync_tls_state().has_value()) {
        mark_failed();
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
    const auto packet_space_loss_deadline =
        [](const PacketSpaceState &packet_space) -> std::optional<QuicCoreTimePoint> {
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

            const auto candidate = compute_time_threshold_deadline(
                packet_space.recovery.rtt_state(), packet.sent_time);
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

        return compute_pto_deadline(packet_space.recovery.rtt_state(), max_ack_delay,
                                    *last_ack_eliciting_sent_time, pto_count_);
    };

    return earliest_of({packet_space_pto_deadline(initial_space_, std::chrono::milliseconds(0)),
                        packet_space_pto_deadline(handshake_space_, std::chrono::milliseconds(0)),
                        handshake_confirmed_ ? packet_space_pto_deadline(application_space_,
                                                                         application_max_ack_delay)
                                             : std::nullopt});
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

    std::vector<SentPacketRecord> lost_packets;
    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        if (!packet.in_flight || packet.packet_number >= *largest_acked) {
            continue;
        }
        if (!is_time_threshold_lost(packet_space.recovery.rtt_state(), packet.sent_time, now)) {
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
    if (packet_space_is_application(packet_space, application_space_) &&
        has_ack_eliciting_in_flight_loss(lost_packets)) {
        const auto application_max_ack_delay = std::chrono::milliseconds(
            peer_transport_parameters_.has_value() ? peer_transport_parameters_->max_ack_delay
                                                   : TransportParameters{}.max_ack_delay);
        congestion_controller_.on_loss_event(now);
        if (establishes_persistent_congestion(lost_packets, packet_space.recovery.rtt_state(),
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
    const auto consider_packet_space = [&](PacketSpaceState &packet_space,
                                           std::chrono::milliseconds max_ack_delay) {
        std::optional<QuicCoreTimePoint> packet_space_deadline;
        for (const auto &[packet_number, packet] : packet_space.sent_packets) {
            static_cast<void>(packet_number);
            if (!packet.ack_eliciting || !packet.in_flight) {
                continue;
            }

            const auto candidate = compute_pto_deadline(
                packet_space.recovery.rtt_state(), max_ack_delay, packet.sent_time, pto_count_);
            if (!packet_space_deadline.has_value() || candidate > *packet_space_deadline) {
                packet_space_deadline = candidate;
            }
        }

        if (!packet_space_deadline.has_value() || now < *packet_space_deadline) {
            return;
        }

        if (!selected_deadline.has_value() || *packet_space_deadline < *selected_deadline) {
            selected_deadline = packet_space_deadline;
            selected_packet_space = &packet_space;
        }
    };

    consider_packet_space(initial_space_, std::chrono::milliseconds(0));
    consider_packet_space(handshake_space_, std::chrono::milliseconds(0));
    if (handshake_confirmed_) {
        consider_packet_space(application_space_, application_max_ack_delay);
    }

    if (selected_packet_space == nullptr) {
        return;
    }

    ++pto_count_;
    if (selected_packet_space == &application_space_) {
        if (has_pending_application_send()) {
            return;
        }
    } else if (selected_packet_space->send_crypto.has_pending_data()) {
        return;
    }

    selected_packet_space->pending_probe_packet = select_pto_probe(*selected_packet_space);
}

std::optional<SentPacketRecord>
QuicConnection::select_pto_probe(const PacketSpaceState &packet_space) const {
    for (const auto &[packet_number, packet] : packet_space.sent_packets) {
        static_cast<void>(packet_number);
        if (!packet.ack_eliciting || !packet.in_flight) {
            continue;
        }
        if (!packet.crypto_ranges.empty() || !packet.reset_stream_frames.empty() ||
            !packet.stop_sending_frames.empty() || packet.max_data_frame.has_value() ||
            !packet.max_stream_data_frames.empty() || packet.data_blocked_frame.has_value() ||
            !packet.stream_data_blocked_frames.empty() || !packet.stream_fragments.empty() ||
            packet.has_ping) {
            return packet;
        }
    }

    return SentPacketRecord{
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
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

    const auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id = std::nullopt,
            .expected_retry_source_connection_id = std::nullopt,
        });
    if (!serialized_transport_parameters.has_value()) {
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
    });
    if (!tls_->start().has_value()) {
        mark_failed();
        return;
    }

    static_cast<void>(sync_tls_state().value());
}

void QuicConnection::start_server_if_needed(
    const ConnectionId &client_initial_destination_connection_id) {
    if (started_) {
        return;
    }

    started_ = true;
    status_ = HandshakeStatus::in_progress;
    client_initial_destination_connection_id_ = client_initial_destination_connection_id;
    local_transport_parameters_ = TransportParameters{
        .original_destination_connection_id = client_initial_destination_connection_id_,
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

    const auto serialized_transport_parameters = serialize_locally_validated_transport_parameters(
        config_.role, local_transport_parameters_,
        TransportParametersValidationContext{
            .expected_initial_source_connection_id = config_.source_connection_id,
            .expected_original_destination_connection_id =
                client_initial_destination_connection_id_,
            .expected_retry_source_connection_id = std::nullopt,
        });
    if (!serialized_transport_parameters.has_value()) {
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
    });
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
    if (((header_byte >> 4) & 0x03u) != 0x00u) {
        return CodecResult<ConnectionId>::failure(CodecErrorCode::unsupported_packet_type, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<ConnectionId>::failure(version.error().code, version.error().offset);
    }
    if (read_u32_be(version.value()) != kQuicVersion1) {
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
        return CodecResult<std::size_t>::success(bytes.size());
    }
    if ((header_byte & 0x40u) == 0) {
        return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
    }

    const auto version = reader.read_exact(4);
    if (!version.has_value()) {
        return CodecResult<std::size_t>::failure(version.error().code, version.error().offset);
    }
    if (read_u32_be(version.value()) != kQuicVersion1) {
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
    if (packet_type == 0x00u) {
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
    } else if (packet_type != 0x02u) {
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
                peer_source_connection_id_ = protected_packet.source_connection_id;
                initial_space_.largest_authenticated_packet_number = protected_packet.packet_number;
                const auto processed =
                    process_inbound_crypto(EncryptionLevel::initial, protected_packet.frames, now);
                if (processed.has_value()) {
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    initial_space_.received_packets.record_received(protected_packet.packet_number,
                                                                    ack_eliciting, now);
                    if (ack_eliciting) {
                        initial_space_.pending_ack_deadline = now;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                peer_source_connection_id_ = protected_packet.source_connection_id;
                handshake_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_crypto(EncryptionLevel::handshake,
                                                              protected_packet.frames, now);
                if (processed.has_value()) {
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    handshake_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now);
                    if (ack_eliciting) {
                        handshake_space_.pending_ack_deadline = now;
                    }
                }
                return processed;
            } else {
                application_space_.largest_authenticated_packet_number =
                    protected_packet.packet_number;
                const auto processed = process_inbound_application(protected_packet.frames, now);
                if (processed.has_value()) {
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now);
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
    auto ack_result = packet_space.recovery.on_ack_received(ack, now);
    for (const auto &packet : ack_result.acked_packets) {
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
    }
    if (&packet_space == &application_space_ && !ack_result.acked_packets.empty()) {
        handshake_confirmed_ = true;
    }
    if (packet_space_is_application(packet_space, application_space_)) {
        if (has_ack_eliciting_in_flight_loss(ack_result.lost_packets)) {
            congestion_controller_.on_loss_event(now);
            if (establishes_persistent_congestion(ack_result.lost_packets,
                                                  packet_space.recovery.rtt_state(),
                                                  std::chrono::milliseconds(max_ack_delay_ms))) {
                congestion_controller_.on_persistent_congestion();
            }
        }
        congestion_controller_.on_packets_acked(ack_result.acked_packets,
                                                !has_pending_application_send());
    }
    if (!ack_result.acked_packets.empty() && !suppress_pto_reset) {
        pto_count_ = 0;
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
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_reset_frame(frame);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stop_sending_frame(frame);
    }

    packet_space.sent_packets.erase(packet.packet_number);
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

    packet_space.sent_packets.erase(packet.packet_number);
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
            if (!stream_frame->has_offset || !stream_frame->offset.has_value() ||
                !stream_frame->has_length) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

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
                stream_frame->offset.value(), stream_frame->stream_data.size(), stream_frame->fin);
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

            const auto contiguous_bytes = stream_state->receive_buffer.push(
                stream_frame->offset.value(), stream_frame->stream_data);
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
            const auto noted =
                stream_state->note_peer_stop_sending(stop_sending->application_protocol_error_code);
            if (!noted.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
            }

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

    if (tls_->handshake_complete() && peer_transport_parameters_validated_ &&
        application_space_.read_secret.has_value() && application_space_.write_secret.has_value()) {
        if (status_ != HandshakeStatus::connected) {
            status_ = HandshakeStatus::connected;
            queue_state_change(QuicCoreStateChange::handshake_ready);
        }
        if (config_.role == EndpointRole::server) {
            handshake_confirmed_ = true;
        }
    } else {
        status_ = HandshakeStatus::in_progress;
    }
}

void QuicConnection::mark_failed() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    status_ = HandshakeStatus::failed;
    streams_.clear();
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
        return TransportParametersValidationContext{
            .expected_initial_source_connection_id = peer_source_connection_id_.value(),
            .expected_original_destination_connection_id =
                client_initial_destination_connection_id(),
            .expected_retry_source_connection_id = std::nullopt,
        };
    }

    return TransportParametersValidationContext{
        .expected_initial_source_connection_id = peer_source_connection_id_.value(),
        .expected_original_destination_connection_id = std::nullopt,
        .expected_retry_source_connection_id = std::nullopt,
    };
}

void QuicConnection::initialize_local_flow_control() {
    connection_flow_control_ = ConnectionFlowControlState{
        .local_receive_window = local_transport_parameters_.initial_max_data,
        .advertised_max_data = local_transport_parameters_.initial_max_data,
    };
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
        .bidirectional = local_transport_parameters_.initial_max_streams_bidi == 0
                             ? config_.transport.initial_max_streams_bidi
                             : local_transport_parameters_.initial_max_streams_bidi,
        .unidirectional = local_transport_parameters_.initial_max_streams_uni == 0
                              ? config_.transport.initial_max_streams_uni
                              : local_transport_parameters_.initial_max_streams_uni,
    };
}

bool QuicConnection::has_pending_application_send() const {
    if (connection_flow_control_.max_data_state == StreamControlFrameState::pending ||
        connection_flow_control_.data_blocked_state == StreamControlFrameState::pending) {
        return true;
    }

    const auto connection_send_credit =
        connection_flow_control_.peer_max_data > connection_flow_control_.highest_sent
            ? connection_flow_control_.peer_max_data - connection_flow_control_.highest_sent
            : 0;
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        if (stream.reset_state == StreamControlFrameState::pending ||
            stream.stop_sending_state == StreamControlFrameState::pending ||
            stream.flow_control.max_stream_data_state == StreamControlFrameState::pending ||
            stream.flow_control.stream_data_blocked_state == StreamControlFrameState::pending) {
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
    if (!connection_flow_control_.should_send_data_blocked(queued_bytes) ||
        connection_flow_control_.sendable_bytes(queued_bytes) != 0) {
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

    std::vector<Frame> initial_frames;
    if (const auto ack_frame =
            initial_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now)) {
        initial_frames.emplace_back(*ack_frame);
    }
    const auto initial_crypto_ranges =
        initial_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    for (const auto &range : initial_crypto_ranges) {
        initial_frames.emplace_back(CryptoFrame{
            .offset = range.offset,
            .crypto_data = range.bytes,
        });
    }
    if (initial_space_.pending_probe_packet.has_value() &&
        !has_ack_eliciting_frame(initial_frames)) {
        for (const auto &range : initial_space_.pending_probe_packet->crypto_ranges) {
            initial_frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes,
            });
        }
        if (!has_ack_eliciting_frame(initial_frames)) {
            initial_frames.emplace_back(PingFrame{});
        }
    }
    if (!initial_frames.empty()) {
        const auto packet_number = initial_space_.next_send_packet_number++;
        std::vector<Frame> frames;
        frames.reserve(initial_frames.size());
        frames.insert(frames.end(), initial_frames.begin(), initial_frames.end());

        packets.emplace_back(ProtectedInitialPacket{
            .version = kQuicVersion1,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .token = {},
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = packet_number,
            .frames = std::move(frames),
        });

        SentPacketRecord sent_packet{
            .packet_number = packet_number,
            .sent_time = now,
            .ack_eliciting = has_ack_eliciting_frame(initial_frames),
            .in_flight = has_ack_eliciting_frame(initial_frames),
            .declared_lost = false,
            .crypto_ranges = initial_crypto_ranges,
        };
        if (initial_space_.pending_probe_packet.has_value() && sent_packet.crypto_ranges.empty()) {
            sent_packet.crypto_ranges = initial_space_.pending_probe_packet->crypto_ranges;
            sent_packet.has_ping = initial_space_.pending_probe_packet->has_ping;
        }
        track_sent_packet(initial_space_, sent_packet);
        if (initial_space_.received_packets.has_ack_to_send()) {
            initial_space_.received_packets.on_ack_sent();
            initial_space_.pending_ack_deadline = std::nullopt;
        }
        if (initial_space_.pending_probe_packet.has_value()) {
            initial_space_.pending_probe_packet = std::nullopt;
        }
    }

    std::vector<Frame> handshake_frames;
    if (const auto ack_frame =
            handshake_space_.received_packets.build_ack_frame(/*ack_delay_exponent=*/0, now)) {
        handshake_frames.emplace_back(*ack_frame);
    }
    const auto handshake_crypto_ranges =
        handshake_space_.send_crypto.take_ranges(std::numeric_limits<std::size_t>::max());
    for (const auto &range : handshake_crypto_ranges) {
        handshake_frames.emplace_back(CryptoFrame{
            .offset = range.offset,
            .crypto_data = range.bytes,
        });
    }
    if (handshake_space_.pending_probe_packet.has_value() &&
        !has_ack_eliciting_frame(handshake_frames)) {
        for (const auto &range : handshake_space_.pending_probe_packet->crypto_ranges) {
            handshake_frames.emplace_back(CryptoFrame{
                .offset = range.offset,
                .crypto_data = range.bytes,
            });
        }
        if (!has_ack_eliciting_frame(handshake_frames)) {
            handshake_frames.emplace_back(PingFrame{});
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
            .version = kQuicVersion1,
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
        if (handshake_space_.received_packets.has_ack_to_send()) {
            handshake_space_.received_packets.on_ack_sent();
            handshake_space_.pending_ack_deadline = std::nullopt;
        }
        if (handshake_space_.pending_probe_packet.has_value()) {
            handshake_space_.pending_probe_packet = std::nullopt;
        }
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

            while (remaining_bytes > 0 || allow_zero_byte_round) {
                const auto zero_byte_round = remaining_bytes == 0;
                allow_zero_byte_round = false;
                const auto order = round_robin_stream_order(streams, last_stream_id);
                std::vector<std::uint64_t> active_stream_ids;
                active_stream_ids.reserve(order.size());
                for (const auto stream_id : order) {
                    const auto stream = streams.find(stream_id);
                    if (stream == streams.end() ||
                        stream->second.reset_state != StreamControlFrameState::none) {
                        continue;
                    }

                    const auto active = loss_phase ? stream->second.send_buffer.has_lost_data() ||
                                                         stream_fin_sendable(stream->second)
                                                   : stream->second.sendable_bytes() != 0 ||
                                                         stream_fin_sendable(stream->second);
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
                    auto stream = streams.find(stream_id);
                    if (stream == streams.end()) {
                        continue;
                    }

                    const auto highest_sent_before = stream->second.flow_control.highest_sent;
                    const auto packet_share =
                        zero_byte_round
                            ? 0
                            : std::max<std::size_t>(1, remaining_bytes / active_stream_ids.size());
                    const auto new_byte_share =
                        loss_phase || remaining_connection_credit == 0
                            ? 0
                            : std::max<std::uint64_t>(1, remaining_connection_credit /
                                                             active_stream_ids.size());
                    auto stream_fragments = stream->second.take_send_fragments(StreamSendBudget{
                        .packet_bytes = std::min(remaining_bytes, packet_share),
                        .new_bytes = new_byte_share,
                    });
                    const auto new_bytes_sent =
                        stream->second.flow_control.highest_sent - highest_sent_before;
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
                    if (remaining_bytes == 0 && !zero_byte_round) {
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
            [&](const std::optional<AckFrame> &ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
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
            if (max_data_frame.has_value()) {
                candidate_frames.emplace_back(*max_data_frame);
            }
            for (const auto &frame : max_stream_data_frames) {
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
            for (const auto &fragment : stream_fragments) {
                candidate_frames.emplace_back(StreamFrame{
                    .fin = fragment.fin,
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = fragment.stream_id,
                    .offset = fragment.offset,
                    .stream_data = fragment.bytes,
                });
            }
            if (include_ping) {
                candidate_frames.emplace_back(PingFrame{});
            }

            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedOneRttPacket{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = application_space_.next_send_packet_number,
                .frames = std::move(candidate_frames),
            });

            return serialize_protected_datagram(
                candidate_packets, SerializeProtectionContext{
                                       .local_role = config_.role,
                                       .client_initial_destination_connection_id =
                                           client_initial_destination_connection_id(),
                                       .handshake_secret = handshake_space_.write_secret,
                                       .one_rtt_secret = application_space_.write_secret,
                                   });
        };
        const auto trim_application_ack_frame =
            [&](const std::optional<AckFrame> &candidate_ack_frame,
                const std::optional<MaxDataFrame> &max_data_frame,
                std::span<const MaxStreamDataFrame> max_stream_data_frames,
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
                candidate_ack_frame, max_data_frame, max_stream_data_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                stream_fragments, include_ping);
            if (!candidate_datagram.has_value()) {
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
                        trimmed_ack_frame, max_data_frame, max_stream_data_frames,
                        reset_stream_frames, stop_sending_frames, data_blocked_frame,
                        stream_data_blocked_frames, stream_fragments, include_ping)
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

        if (!has_pending_application_send() &&
            application_space_.pending_probe_packet.has_value()) {
            const auto &probe_packet = *application_space_.pending_probe_packet;
            const auto include_ping = probe_packet.reset_stream_frames.empty() &&
                                      probe_packet.stop_sending_frames.empty() &&
                                      !probe_packet.max_data_frame.has_value() &&
                                      probe_packet.max_stream_data_frames.empty() &&
                                      !probe_packet.data_blocked_frame.has_value() &&
                                      probe_packet.stream_data_blocked_frames.empty() &&
                                      probe_packet.stream_fragments.empty();
            auto ack_frame = trim_application_ack_frame(
                base_ack_frame, probe_packet.max_data_frame, probe_packet.max_stream_data_frames,
                probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                probe_packet.stream_fragments, include_ping);
            if (base_ack_frame.has_value() && !ack_frame.has_value()) {
                mark_failed();
                return {};
            }

            const auto datagram = serialize_application_candidate(
                ack_frame, probe_packet.max_data_frame, probe_packet.max_stream_data_frames,
                probe_packet.reset_stream_frames, probe_packet.stop_sending_frames,
                probe_packet.data_blocked_frame, probe_packet.stream_data_blocked_frames,
                probe_packet.stream_fragments, include_ping);
            if (!datagram.has_value() || datagram.value().size() > kMaximumDatagramSize) {
                mark_failed();
                return {};
            }

            std::vector<Frame> frames;
            if (ack_frame.has_value()) {
                frames.emplace_back(*ack_frame);
            }
            if (probe_packet.max_data_frame.has_value()) {
                frames.emplace_back(*probe_packet.max_data_frame);
            }
            for (const auto &frame : probe_packet.max_stream_data_frames) {
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
            for (const auto &fragment : probe_packet.stream_fragments) {
                frames.emplace_back(StreamFrame{
                    .fin = fragment.fin,
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = fragment.stream_id,
                    .offset = fragment.offset,
                    .stream_data = fragment.bytes,
                });
            }
            if (include_ping) {
                frames.emplace_back(PingFrame{});
            }

            const auto packet_number = application_space_.next_send_packet_number++;
            packets.emplace_back(ProtectedOneRttPacket{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = packet_number,
                .frames = std::move(frames),
            });

            track_sent_packet(
                application_space_,
                SentPacketRecord{
                    .packet_number = packet_number,
                    .sent_time = now,
                    .ack_eliciting = true,
                    .in_flight = true,
                    .declared_lost = false,
                    .reset_stream_frames = probe_packet.reset_stream_frames,
                    .stop_sending_frames = probe_packet.stop_sending_frames,
                    .max_data_frame = probe_packet.max_data_frame,
                    .max_stream_data_frames = probe_packet.max_stream_data_frames,
                    .data_blocked_frame = probe_packet.data_blocked_frame,
                    .stream_data_blocked_frames = probe_packet.stream_data_blocked_frames,
                    .stream_fragments = probe_packet.stream_fragments,
                    .has_ping = include_ping,
                    .bytes_in_flight = datagram.value().size(),
                });
            if (application_space_.received_packets.has_ack_to_send()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
            }
            application_space_.pending_probe_packet = std::nullopt;
        } else {
            std::size_t low = 0;
            std::size_t high = kMaximumDatagramSize;
            std::size_t best_length = 0;
            std::optional<AckFrame> best_ack_frame;

            while (low <= high) {
                const auto candidate_length = low + (high - low) / 2;
                auto candidate_connection_flow = connection_flow_control_;
                auto candidate_streams = streams_;
                auto candidate_max_data_frame = candidate_connection_flow.take_max_data_frame();
                auto candidate_data_blocked_frame =
                    candidate_connection_flow.take_data_blocked_frame();
                auto candidate_max_stream_data_frames =
                    take_max_stream_data_frames(candidate_streams);
                auto candidate_reset_frames = take_reset_stream_frames(candidate_streams);
                auto candidate_stop_frames = take_stop_sending_frames(candidate_streams);
                auto candidate_stream_data_blocked_frames =
                    take_stream_data_blocked_frames(candidate_streams);
                auto candidate_last_stream_id = last_application_send_stream_id_;
                auto candidate_fragments =
                    take_stream_fragments(candidate_connection_flow, candidate_streams,
                                          candidate_length, candidate_last_stream_id);
                auto fitting_ack_frame = trim_application_ack_frame(
                    base_ack_frame, candidate_max_data_frame, candidate_max_stream_data_frames,
                    candidate_reset_frames, candidate_stop_frames, candidate_data_blocked_frame,
                    candidate_stream_data_blocked_frames, candidate_fragments,
                    /*include_ping=*/false);
                if (base_ack_frame.has_value() && !fitting_ack_frame.has_value()) {
                    mark_failed();
                    return {};
                }

                const auto candidate_datagram = serialize_application_candidate(
                    fitting_ack_frame, candidate_max_data_frame, candidate_max_stream_data_frames,
                    candidate_reset_frames, candidate_stop_frames, candidate_data_blocked_frame,
                    candidate_stream_data_blocked_frames, candidate_fragments,
                    /*include_ping=*/false);
                if (!candidate_datagram.has_value()) {
                    mark_failed();
                    return {};
                }

                if (candidate_datagram.value().size() <= kMaximumDatagramSize) {
                    best_length = candidate_length;
                    best_ack_frame = std::move(fitting_ack_frame);
                    low = candidate_length + 1;
                } else {
                    if (candidate_length == 0) {
                        break;
                    }
                    high = candidate_length - 1;
                }
            }

            std::vector<Frame> frames;
            if (best_ack_frame.has_value()) {
                frames.emplace_back(*best_ack_frame);
            }
            auto max_data_frame = connection_flow_control_.take_max_data_frame();
            auto data_blocked_frame = connection_flow_control_.take_data_blocked_frame();
            auto max_stream_data_frames = take_max_stream_data_frames(streams_);
            auto reset_stream_frames = take_reset_stream_frames(streams_);
            auto stop_sending_frames = take_stop_sending_frames(streams_);
            auto stream_data_blocked_frames = take_stream_data_blocked_frames(streams_);
            auto stream_fragments = take_stream_fragments(
                connection_flow_control_, streams_, best_length, last_application_send_stream_id_);
            auto candidate_datagram = serialize_application_candidate(
                best_ack_frame, max_data_frame, max_stream_data_frames, reset_stream_frames,
                stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                stream_fragments, /*include_ping=*/false);
            if (!candidate_datagram.has_value()) {
                mark_failed();
                return {};
            }
            while (candidate_datagram.value().size() > kMaximumDatagramSize &&
                   !stream_fragments.empty()) {
                const auto &last_fragment = stream_fragments.back();
                if (!last_fragment.fin || !last_fragment.bytes.empty()) {
                    mark_failed();
                    return {};
                }

                if (const auto stream = streams_.find(last_fragment.stream_id);
                    stream != streams_.end()) {
                    stream->second.mark_send_fragment_lost(last_fragment);
                }
                stream_fragments.pop_back();
                candidate_datagram = serialize_application_candidate(
                    best_ack_frame, max_data_frame, max_stream_data_frames, reset_stream_frames,
                    stop_sending_frames, data_blocked_frame, stream_data_blocked_frames,
                    stream_fragments, /*include_ping=*/false);
                if (!candidate_datagram.has_value()) {
                    mark_failed();
                    return {};
                }
            }
            if (candidate_datagram.value().size() > kMaximumDatagramSize) {
                mark_failed();
                return {};
            }
            const auto ack_eliciting =
                max_data_frame.has_value() || !max_stream_data_frames.empty() ||
                !reset_stream_frames.empty() || !stop_sending_frames.empty() ||
                data_blocked_frame.has_value() || !stream_data_blocked_frames.empty() ||
                !stream_fragments.empty();
            if (ack_eliciting &&
                !congestion_controller_.can_send_ack_eliciting(candidate_datagram.value().size())) {
                return {};
            }

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
            if (data_blocked_frame.has_value()) {
                frames.emplace_back(*data_blocked_frame);
            }
            for (const auto &frame : stream_data_blocked_frames) {
                frames.emplace_back(frame);
            }
            for (const auto &fragment : stream_fragments) {
                frames.emplace_back(StreamFrame{
                    .fin = fragment.fin,
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = fragment.stream_id,
                    .offset = fragment.offset,
                    .stream_data = fragment.bytes,
                });
            }

            if (frames.empty()) {
                return {};
            }

            const auto packet_number = application_space_.next_send_packet_number++;
            packets.emplace_back(ProtectedOneRttPacket{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = packet_number,
                .frames = std::move(frames),
            });

            track_sent_packet(application_space_,
                              SentPacketRecord{
                                  .packet_number = packet_number,
                                  .sent_time = now,
                                  .ack_eliciting = ack_eliciting,
                                  .in_flight = ack_eliciting,
                                  .declared_lost = false,
                                  .reset_stream_frames = reset_stream_frames,
                                  .stop_sending_frames = stop_sending_frames,
                                  .max_data_frame = max_data_frame,
                                  .max_stream_data_frames = max_stream_data_frames,
                                  .data_blocked_frame = data_blocked_frame,
                                  .stream_data_blocked_frames = stream_data_blocked_frames,
                                  .stream_fragments = stream_fragments,
                                  .bytes_in_flight = candidate_datagram.value().size(),
                              });
            if (application_space_.received_packets.has_ack_to_send()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
            }
            if (application_space_.pending_probe_packet.has_value()) {
                application_space_.pending_probe_packet = std::nullopt;
            }
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
                                              });
    if (!datagram.has_value()) {
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
                         });
            if (!datagram.has_value()) {
                mark_failed();
                return {};
            }
            break;
        }
    }

    return datagram.value();
}

} // namespace coquic::quic
