#include "src/quic/connection/connection.h"

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace coquic::quic {

StreamStateResult<bool> QuicConnection::queue_stream_send(std::uint64_t stream_id,
                                                          std::span<const std::byte> bytes,
                                                          bool fin) {
    return queue_stream_send_impl(stream_id, bytes, std::nullopt, fin);
}

StreamStateResult<bool> QuicConnection::queue_stream_send_shared(std::uint64_t stream_id,
                                                                 SharedBytes bytes, bool fin) {
    return queue_stream_send_impl(stream_id, {}, std::move(bytes), fin);
}

CodecResult<bool> QuicConnection::queue_datagram_send(std::span<const std::byte> bytes) {
    return queue_datagram_send_shared(
        SharedBytes(std::vector<std::byte>(bytes.begin(), bytes.end())));
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
    invalidate_stream_sendability_cache();

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool>
QuicConnection::queue_application_close(LocalApplicationCloseCommand command) {
    if (status_ == HandshakeStatus::failed) {
        return StreamStateResult<bool>::success(true);
    }

    pending_application_close_ = ApplicationConnectionCloseFrame{
        .error_code = command.application_error_code,
        .reason =
            ConnectionCloseReason{
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte *>(command.reason_phrase.data()),
                    reinterpret_cast<const std::byte *>(command.reason_phrase.data()) +
                        command.reason_phrase.size()),
            },
    };
    local_application_close_sent_ = false;
    return StreamStateResult<bool>::success(true);
}

void QuicConnection::queue_new_token(std::vector<std::byte> token) {
    if (status_ == HandshakeStatus::failed || token.empty()) {
        return;
    }

    pending_new_token_frames_.push_back(NewTokenFrame{
        .token = std::move(token),
    });
}

void QuicConnection::request_key_update() {
    local_key_update_requested_ = true;
    if (!local_key_update_initiated_) {
        current_write_phase_first_packet_number_ = application_space_.next_send_packet_number;
    }
}

std::optional<QuicCoreReceiveStreamData> QuicConnection::take_received_stream_data() {
    if (status_ == HandshakeStatus::failed || pending_stream_receive_effects_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_stream_receive_effects_.front());
    pending_stream_receive_effects_.pop_front();
    maybe_retire_stream(next.stream_id);
    return next;
}

std::optional<QuicCoreReceiveDatagramData> QuicConnection::take_received_datagram_data() {
    if (status_ == HandshakeStatus::failed || pending_datagram_receive_effects_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_datagram_receive_effects_.front());
    pending_datagram_receive_effects_.pop_front();
    return next;
}

std::optional<QuicCorePeerResetStream> QuicConnection::take_peer_reset_stream() {
    if (status_ == HandshakeStatus::failed || pending_peer_reset_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_reset_effects_.front();
    pending_peer_reset_effects_.pop_front();
    return next;
}

std::optional<QuicCorePeerStopSending> QuicConnection::take_peer_stop_sending() {
    if (status_ == HandshakeStatus::failed || pending_peer_stop_effects_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_peer_stop_effects_.front();
    pending_peer_stop_effects_.pop_front();
    return next;
}

std::optional<QuicCoreStateChange> QuicConnection::take_state_change() {
    if (pending_state_changes_.empty()) {
        return std::nullopt;
    }

    const auto next = pending_state_changes_.front();
    pending_state_changes_.pop_front();
    return next;
}

std::optional<QuicCorePeerPreferredAddressAvailable>
QuicConnection::take_peer_preferred_address_available() {
    auto next = pending_preferred_address_effect_;
    pending_preferred_address_effect_.reset();
    return next;
}

std::optional<QuicCoreResumptionStateAvailable> QuicConnection::take_resumption_state_available() {
    auto next = std::move(pending_resumption_state_effect_);
    pending_resumption_state_effect_.reset();
    return next;
}

std::optional<QuicCoreZeroRttStatusEvent> QuicConnection::take_zero_rtt_status_event() {
    auto next = pending_zero_rtt_status_event_;
    pending_zero_rtt_status_event_.reset();
    return next;
}

std::optional<QuicConnectionTerminalState> QuicConnection::take_terminal_state() {
    if (!pending_terminal_state_.has_value()) {
        return std::nullopt;
    }

    const auto next = pending_terminal_state_;
    pending_terminal_state_.reset();
    return next;
}

std::optional<QuicCorePacketInspection> QuicConnection::take_packet_inspection() {
    if (pending_packet_inspections_.empty()) {
        return std::nullopt;
    }

    auto next = std::move(pending_packet_inspections_.front());
    pending_packet_inspections_.pop_front();
    return next;
}

std::optional<std::vector<std::byte>> QuicConnection::take_new_token() {
    if (pending_received_new_tokens_.empty()) {
        return std::nullopt;
    }

    auto token = std::move(pending_received_new_tokens_.front());
    pending_received_new_tokens_.pop_front();
    return token;
}

std::optional<QuicPathId> QuicConnection::last_drained_path_id() const {
    return last_drained_path_id_;
}

QuicEcnCodepoint QuicConnection::last_drained_ecn_codepoint() const {
    return last_drained_ecn_codepoint_;
}

bool QuicConnection::last_drained_is_pmtu_probe() const {
    return last_drained_is_pmtu_probe_;
}

bool QuicConnection::last_drained_allows_send_continuation() const {
    return last_drained_allows_send_continuation_;
}

std::uint64_t QuicConnection::last_drained_packet_inspection_datagram_id() const {
    return last_drained_packet_inspection_datagram_id_;
}

std::vector<ConnectionId> QuicConnection::active_local_connection_ids() const {
    std::vector<ConnectionId> connection_ids;
    connection_ids.reserve(local_connection_ids_.size());
    for (const auto &[sequence_number, record] : local_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.retired) {
            continue;
        }
        connection_ids.push_back(record.connection_id);
    }
    return connection_ids;
}

std::vector<StatelessResetTokenRecord> QuicConnection::active_local_stateless_reset_tokens() const {
    std::vector<StatelessResetTokenRecord> tokens;
    tokens.reserve(local_connection_ids_.size());
    for (const auto &[sequence_number, record] : local_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.retired) {
            continue;
        }
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = record.connection_id,
            .stateless_reset_token = record.stateless_reset_token,
        });
    }
    return tokens;
}

std::vector<StatelessResetTokenRecord> QuicConnection::peer_stateless_reset_tokens() const {
    std::vector<StatelessResetTokenRecord> tokens;
    tokens.reserve(
        peer_connection_ids_.size() +
        static_cast<std::size_t>(peer_transport_parameters_.has_value() &&
                                 peer_transport_parameters_->stateless_reset_token.has_value()));
    if (peer_transport_parameters_.has_value() &&
        peer_transport_parameters_->stateless_reset_token.has_value()) {
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = config_.initial_destination_connection_id,
            .stateless_reset_token = *peer_transport_parameters_->stateless_reset_token,
        });
    }
    for (const auto &[sequence_number, record] : peer_connection_ids_) {
        static_cast<void>(sequence_number);
        if (record.locally_retired) {
            continue;
        }
        if (!record.stateless_reset_token.has_value()) {
            continue;
        }
        tokens.push_back(StatelessResetTokenRecord{
            .connection_id = record.connection_id,
            .stateless_reset_token = *record.stateless_reset_token,
        });
    }
    return tokens;
}

std::uint64_t QuicConnection::endpoint_route_generation() const {
    return endpoint_route_generation_;
}

void QuicConnection::note_endpoint_route_state_changed() {
    ++endpoint_route_generation_;
    if (endpoint_route_generation_ == 0) {
        endpoint_route_generation_ = 1;
    }
}

} // namespace coquic::quic
