#include "src/quic/connection.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>

namespace coquic::quic {

namespace {

QuicCorePacketSpaceDiagnostics packet_space_diagnostics(const PacketSpaceState &space) {
    return QuicCorePacketSpaceDiagnostics{
        .next_send_packet_number = space.next_send_packet_number,
        .largest_authenticated_packet_number = space.largest_authenticated_packet_number,
        .read_secret_available = space.read_secret.has_value(),
        .write_secret_available = space.write_secret.has_value(),
        .pending_crypto = space.send_crypto.has_pending_data(),
        .outstanding_packets = space.sent_packets.size(),
        .declared_lost_packets = space.declared_lost_packets.size(),
        .pending_probe = space.pending_probe_packet.has_value(),
        .pending_ack_deadline = space.pending_ack_deadline,
        .force_ack = space.force_ack_send,
    };
}

std::uint64_t nonnegative_milliseconds(QuicCoreDuration value) {
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(value).count();
    return static_cast<std::uint64_t>(std::max<std::int64_t>(0, milliseconds));
}

std::optional<std::uint64_t> optional_ms(std::optional<QuicCoreDuration> value) {
    if (!value.has_value()) {
        return std::nullopt;
    }
    return nonnegative_milliseconds(*value);
}

} // namespace

QuicCoreConnectionDiagnostics QuicConnection::diagnostics(QuicConnectionHandle handle) const {
    const auto &rtt = shared_recovery_rtt_state();
    QuicCoreConnectionDiagnostics out{
        .handle = handle,
        .handshake_status = static_cast<std::uint8_t>(status_),
        .started = started_,
        .processed_peer_packet = processed_peer_packet_,
        .handshake_ready_emitted = handshake_ready_emitted_,
        .handshake_confirmed = handshake_confirmed_,
        .handshake_confirmed_emitted = handshake_confirmed_emitted_,
        .failed_emitted = failed_emitted_,
        .peer_transport_parameters_validated = peer_transport_parameters_validated_,
        .peer_address_validated = peer_address_validated_,
        .current_version = current_version_,
        .anti_amplification_received_bytes = anti_amplification_received_bytes_,
        .anti_amplification_sent_bytes = anti_amplification_sent_bytes_,
        .active_paths = paths_.size(),
        .current_send_path_id = current_send_path_id_,
        .active_streams = streams_.size(),
        .retired_streams = retired_streams_.size() + retired_peer_stream_count(),
        .initial_space = packet_space_diagnostics(initial_space_),
        .handshake_space = packet_space_diagnostics(handshake_space_),
        .zero_rtt_space = packet_space_diagnostics(zero_rtt_space_),
        .application_space = packet_space_diagnostics(application_space_),
        .recovery =
            QuicCoreRecoveryDiagnostics{
                .algorithm = config_.transport.congestion_control,
                .congestion_window =
                    static_cast<std::uint64_t>(congestion_controller_.congestion_window()),
                .bytes_in_flight =
                    static_cast<std::uint64_t>(congestion_controller_.bytes_in_flight()),
                .pto_count = pto_count_,
                .latest_rtt_ms = optional_ms(rtt.latest_rtt),
                .min_rtt_ms = optional_ms(rtt.min_rtt),
                .smoothed_rtt_ms = nonnegative_milliseconds(rtt.smoothed_rtt),
                .rttvar_ms = nonnegative_milliseconds(rtt.rttvar),
            },
        .flow_control =
            QuicCoreFlowControlDiagnostics{
                .peer_max_data = connection_flow_control_.peer_max_data,
                .highest_sent = connection_flow_control_.highest_sent,
                .advertised_max_data = connection_flow_control_.advertised_max_data,
                .delivered_bytes = connection_flow_control_.delivered_bytes,
                .received_committed = connection_flow_control_.received_committed,
            },
        .stream_limits =
            QuicCoreStreamLimitDiagnostics{
                .peer_max_bidirectional = stream_open_limits_.peer_max_bidirectional,
                .peer_max_unidirectional = stream_open_limits_.peer_max_unidirectional,
                .advertised_max_bidirectional =
                    local_stream_limit_state_.advertised_max_streams_bidi,
                .advertised_max_unidirectional =
                    local_stream_limit_state_.advertised_max_streams_uni,
            },
    };

    out.streams.reserve(streams_.size());
    for (const auto &[stream_id, stream] : streams_) {
        static_cast<void>(stream_id);
        out.streams.push_back(QuicCoreStreamDiagnostics{
            .stream_id = stream.stream_id,
            .initiator = static_cast<std::uint8_t>(stream.id_info.initiator),
            .direction = static_cast<std::uint8_t>(stream.id_info.direction),
            .local_can_send = stream.id_info.local_can_send,
            .local_can_receive = stream.id_info.local_can_receive,
            .send_closed = stream.send_closed,
            .receive_closed = stream.receive_closed,
            .peer_send_closed = stream.peer_send_closed,
            .peer_fin_delivered = stream.peer_fin_delivered,
            .peer_reset_received = stream.peer_reset_received,
            .send_fin_state = static_cast<std::uint8_t>(stream.send_fin_state),
            .reset_state = static_cast<std::uint8_t>(stream.reset_state),
            .stop_sending_state = static_cast<std::uint8_t>(stream.stop_sending_state),
            .pending_send = stream.has_pending_send(),
            .outstanding_send = stream.has_outstanding_send(),
            .sendable_bytes = stream.sendable_bytes(),
            .send_flow_control_limit = stream.send_flow_control_limit,
            .receive_flow_control_limit = stream.receive_flow_control_limit,
            .highest_received_offset = stream.highest_received_offset,
            .receive_flow_control_consumed = stream.receive_flow_control_consumed,
        });
    }
    return out;
}

} // namespace coquic::quic
