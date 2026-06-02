#include "src/quic/connection.h"
#include "src/quic/connection_internal.h"

namespace coquic::quic {

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
    if ((header_byte & 0x40u) == 0 && !config_.transport.grease_quic_bit) {
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
        if ((header_byte & 0x40u) == 0 && !config_.transport.grease_quic_bit) {
            return CodecResult<std::size_t>::failure(CodecErrorCode::invalid_fixed_bit, 0);
        }
        return CodecResult<std::size_t>::success(bytes.size());
    }
    if ((header_byte & 0x40u) == 0 && !config_.transport.grease_quic_bit) {
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
    } else if (!is_zero_rtt_long_header_type(version_value, packet_type) &&
               !is_handshake_long_header_type(version_value, packet_type)) {
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

CodecResult<bool>
QuicConnection::process_inbound_packet(const ProtectedPacket &packet, QuicCoreTimePoint now,
                                       QuicEcnCodepoint ecn,
                                       bool used_previous_application_read_secret) {
    return std::visit(
        [&](const auto &protected_packet) -> CodecResult<bool> {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (initial_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                const bool duplicate_initial_packet =
                    should_ignore_received_packet(initial_space_, protected_packet.packet_number);
                note_authenticated_packet_number(initial_space_, protected_packet.packet_number);
                if (duplicate_initial_packet) {
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    note_ignored_ack_eliciting_received_packet(
                        initial_space_, protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    if (ack_eliciting) {
                        queue_server_handshake_recovery_probes();
                    }
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                const bool peer_connection_id_route_changed =
                    peer_connection_ids_.find(0) == peer_connection_ids_.end() ||
                    peer_connection_ids_.at(0).connection_id !=
                        protected_packet.source_connection_id ||
                    peer_connection_ids_.at(0).locally_retired ||
                    active_peer_connection_id_sequence_ != 0;
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                retired_peer_connection_id_sequences_.erase(0);
                active_peer_connection_id_sequence_ = 0;
                if (peer_connection_id_route_changed) {
                    note_endpoint_route_state_changed();
                }
                const auto processed =
                    process_inbound_crypto(EncryptionLevel::initial, protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    initial_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        note_idle_peer_activity(now);
                    }
                    if (ack_eliciting) {
                        initial_space_.pending_ack_deadline = now;
                        initial_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (handshake_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                if (should_ignore_received_packet(handshake_space_,
                                                  protected_packet.packet_number)) {
                    note_authenticated_packet_number(handshake_space_,
                                                     protected_packet.packet_number);
                    note_ignored_ack_eliciting_received_packet(
                        handshake_space_, protected_packet.packet_number,
                        has_ack_eliciting_frame(protected_packet.frames), now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                const bool peer_connection_id_route_changed =
                    peer_connection_ids_.find(0) == peer_connection_ids_.end() ||
                    peer_connection_ids_.at(0).connection_id !=
                        protected_packet.source_connection_id ||
                    peer_connection_ids_.at(0).locally_retired ||
                    active_peer_connection_id_sequence_ != 0;
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                retired_peer_connection_id_sequences_.erase(0);
                active_peer_connection_id_sequence_ = 0;
                if (peer_connection_id_route_changed) {
                    note_endpoint_route_state_changed();
                }
                note_authenticated_packet_number(handshake_space_, protected_packet.packet_number);
                auto processed = process_inbound_crypto(EncryptionLevel::handshake,
                                                        protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server) {
                        mark_peer_address_validated();
                    }
                    if (config_.role == EndpointRole::server) {
                        discard_initial_packet_space();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    handshake_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        note_idle_peer_activity(now);
                    }
                    if (ack_eliciting) {
                        handshake_space_.pending_ack_deadline = now;
                        handshake_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                note_authenticated_packet_number(application_space_,
                                                 protected_packet.packet_number);
                if (should_ignore_received_packet(application_space_,
                                                  protected_packet.packet_number)) {
                    note_ignored_application_received_packet(
                        application_space_, protected_packet.packet_number,
                        has_ack_eliciting_frame(protected_packet.frames), now, ecn,
                        config_.transport.ack_eliciting_threshold,
                        local_transport_parameters_.max_ack_delay);
                    return CodecResult<bool>::success(true);
                }
                const auto processed = process_inbound_application(
                    protected_packet.frames, now, true, last_inbound_path_id_,
                    /*used_previous_application_read_secret=*/false,
                    protected_packet.packet_number);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    note_idle_peer_activity(now);
                    if (ack_eliciting) {
                        application_space_.pending_ack_deadline = now;
                        application_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else {
                note_authenticated_packet_number(application_space_,
                                                 protected_packet.packet_number);
                if (should_ignore_received_packet(application_space_,
                                                  protected_packet.packet_number)) {
                    note_ignored_application_received_packet(
                        application_space_, protected_packet.packet_number,
                        has_ack_eliciting_frame(protected_packet.frames), now, ecn,
                        config_.transport.ack_eliciting_threshold,
                        local_transport_parameters_.max_ack_delay);
                    return CodecResult<bool>::success(true);
                }
                const bool has_crypto_frame =
                    std::ranges::any_of(protected_packet.frames, [](const Frame &frame) {
                        return std::holds_alternative<CryptoFrame>(frame);
                    });
                const auto processed = process_inbound_application(
                    protected_packet.frames, now, has_crypto_frame, last_inbound_path_id_,
                    used_previous_application_read_secret, protected_packet.packet_number);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server &&
                        status_ != HandshakeStatus::connected) {
                        mark_peer_address_validated();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    note_idle_peer_activity(now);
                    if (ack_eliciting) {
                        schedule_application_ack_deadline(application_space_, now,
                                                          local_transport_parameters_.max_ack_delay,
                                                          ecn);
                    }
                    if (zero_rtt_space_.read_secret.has_value() ||
                        zero_rtt_space_.write_secret.has_value()) {
                        if (config_.role == EndpointRole::server &&
                            zero_rtt_space_.read_secret.has_value()) {
                            arm_server_zero_rtt_discard_deadline(now);
                        } else {
                            discard_packet_space_state(zero_rtt_space_);
                        }
                    }
                    update_spin_bit_on_receive(last_inbound_path_id_, protected_packet.spin_bit,
                                               protected_packet.packet_number);
                }
                return processed;
            }
        },
        packet);
}

CodecResult<bool>
QuicConnection::process_inbound_received_packet(const ReceivedProtectedPacket &packet,
                                                QuicCoreTimePoint now, QuicEcnCodepoint ecn,
                                                bool used_previous_application_read_secret) {
    return std::visit(
        [&](const auto &protected_packet) -> CodecResult<bool> {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            if constexpr (std::is_same_v<PacketType, ReceivedProtectedInitialPacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (initial_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                const bool duplicate_initial_packet =
                    should_ignore_received_packet(initial_space_, protected_packet.packet_number);
                note_authenticated_packet_number(initial_space_, protected_packet.packet_number);
                if (duplicate_initial_packet) {
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    note_ignored_ack_eliciting_received_packet(
                        initial_space_, protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    if (ack_eliciting) {
                        queue_server_handshake_recovery_probes();
                    }
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                const bool peer_connection_id_route_changed =
                    peer_connection_ids_.find(0) == peer_connection_ids_.end() ||
                    peer_connection_ids_.at(0).connection_id !=
                        protected_packet.source_connection_id ||
                    peer_connection_ids_.at(0).locally_retired ||
                    active_peer_connection_id_sequence_ != 0;
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                retired_peer_connection_id_sequences_.erase(0);
                active_peer_connection_id_sequence_ = 0;
                if (peer_connection_id_route_changed) {
                    note_endpoint_route_state_changed();
                }
                const auto processed = process_inbound_received_crypto(
                    EncryptionLevel::initial, protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    initial_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        note_idle_peer_activity(now);
                    }
                    if (ack_eliciting) {
                        initial_space_.pending_ack_deadline = now;
                        initial_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedHandshakePacket>) {
                if (should_adopt_supported_client_version(config_.role, protected_packet.version,
                                                          current_version_)) {
                    current_version_ = protected_packet.version;
                }
                if (handshake_packet_space_discarded_) {
                    return CodecResult<bool>::success(true);
                }
                if (should_ignore_received_packet(handshake_space_,
                                                  protected_packet.packet_number)) {
                    note_authenticated_packet_number(handshake_space_,
                                                     protected_packet.packet_number);
                    note_ignored_ack_eliciting_received_packet(
                        handshake_space_, protected_packet.packet_number,
                        has_ack_eliciting_frame(protected_packet.frames), now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    return CodecResult<bool>::success(true);
                }
                if (should_reset_client_handshake_peer_state(
                        protected_packet.source_connection_id)) {
                    reset_client_handshake_peer_state_for_new_source_connection_id();
                }
                const bool peer_connection_id_route_changed =
                    peer_connection_ids_.find(0) == peer_connection_ids_.end() ||
                    peer_connection_ids_.at(0).connection_id !=
                        protected_packet.source_connection_id ||
                    peer_connection_ids_.at(0).locally_retired ||
                    active_peer_connection_id_sequence_ != 0;
                peer_source_connection_id_ = protected_packet.source_connection_id;
                peer_connection_ids_[0] = PeerConnectionIdRecord{
                    .sequence_number = 0,
                    .connection_id = protected_packet.source_connection_id,
                };
                retired_peer_connection_id_sequences_.erase(0);
                active_peer_connection_id_sequence_ = 0;
                if (peer_connection_id_route_changed) {
                    note_endpoint_route_state_changed();
                }
                note_authenticated_packet_number(handshake_space_, protected_packet.packet_number);
                auto processed = process_inbound_received_crypto(EncryptionLevel::handshake,
                                                                 protected_packet.frames, now);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server) {
                        mark_peer_address_validated();
                    }
                    if (config_.role == EndpointRole::server) {
                        discard_initial_packet_space();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    handshake_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    const bool suppress_keepalive_peer_activity =
                        last_client_handshake_keepalive_probe_time_.has_value() &
                        (config_.role == EndpointRole::client) &
                        (status_ == HandshakeStatus::in_progress) & !handshake_confirmed_ &
                        !ack_eliciting;
                    if (!suppress_keepalive_peer_activity) {
                        note_idle_peer_activity(now);
                    }
                    if (ack_eliciting) {
                        handshake_space_.pending_ack_deadline = now;
                        handshake_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedZeroRttPacket>) {
                note_authenticated_packet_number(application_space_,
                                                 protected_packet.packet_number);
                if (should_ignore_received_packet(application_space_,
                                                  protected_packet.packet_number)) {
                    note_ignored_application_received_packet(
                        application_space_, protected_packet.packet_number,
                        has_ack_eliciting_frame(protected_packet.frames), now, ecn,
                        config_.transport.ack_eliciting_threshold,
                        local_transport_parameters_.max_ack_delay);
                    return CodecResult<bool>::success(true);
                }
                const auto processed = process_inbound_received_application(
                    protected_packet.frames, now, true, last_inbound_path_id_,
                    /*used_previous_application_read_secret=*/false,
                    protected_packet.packet_number);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    note_idle_peer_activity(now);
                    if (ack_eliciting) {
                        application_space_.pending_ack_deadline = now;
                        application_space_.force_ack_send |= ecn == QuicEcnCodepoint::ce;
                    }
                }
                return processed;
            } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedOneRttAckOnlyPacket>) {
                note_authenticated_packet_number(application_space_,
                                                 protected_packet.packet_number);
                if (should_ignore_received_packet(application_space_,
                                                  protected_packet.packet_number)) {
                    note_ignored_application_received_packet(
                        application_space_, protected_packet.packet_number, /*ack_eliciting=*/false,
                        now, ecn, config_.transport.ack_eliciting_threshold,
                        local_transport_parameters_.max_ack_delay);
                    return CodecResult<bool>::success(true);
                }
                return process_inbound_received_application_ack_only(
                    protected_packet.packet_number, protected_packet.spin_bit, protected_packet.ack,
                    now, ecn, last_inbound_path_id_, used_previous_application_read_secret);
            } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedOneRttStreamPacket>) {
                note_authenticated_packet_number(application_space_,
                                                 protected_packet.packet_number);
                if (should_ignore_received_packet(application_space_,
                                                  protected_packet.packet_number)) {
                    note_ignored_application_received_packet(
                        application_space_, protected_packet.packet_number, /*ack_eliciting=*/true,
                        now, ecn, config_.transport.ack_eliciting_threshold,
                        local_transport_parameters_.max_ack_delay);
                    return CodecResult<bool>::success(true);
                }
                return process_inbound_received_application_stream_packet(
                    protected_packet.packet_number, protected_packet.spin_bit,
                    protected_packet.stream, now, ecn);
            } else {
                note_authenticated_packet_number(application_space_,
                                                 protected_packet.packet_number);
                if (should_ignore_received_packet(application_space_,
                                                  protected_packet.packet_number)) {
                    note_ignored_application_received_packet(
                        application_space_, protected_packet.packet_number,
                        has_ack_eliciting_frame(protected_packet.frames), now, ecn,
                        config_.transport.ack_eliciting_threshold,
                        local_transport_parameters_.max_ack_delay);
                    return CodecResult<bool>::success(true);
                }
                if (const auto *ack_frame =
                        single_received_ack_frame_or_null(protected_packet.frames);
                    ack_frame != nullptr &&
                    !packet_trace_matches_connection(config_.source_connection_id)) {
                    return process_inbound_received_application_ack_only(
                        protected_packet.packet_number, protected_packet.spin_bit, *ack_frame, now,
                        ecn, last_inbound_path_id_, used_previous_application_read_secret);
                }
                if (const auto *stream_frame =
                        single_received_stream_frame_or_null(protected_packet.frames);
                    stream_frame != nullptr &&
                    !packet_trace_matches_connection(config_.source_connection_id)) {
                    return process_inbound_received_application_stream_packet(
                        protected_packet.packet_number, protected_packet.spin_bit, *stream_frame,
                        now, ecn);
                }
                const bool has_crypto_frame =
                    std::ranges::any_of(protected_packet.frames, [](const ReceivedFrame &frame) {
                        return std::holds_alternative<ReceivedCryptoFrame>(frame);
                    });
                auto processed = process_inbound_received_application(
                    protected_packet.frames, now, has_crypto_frame, last_inbound_path_id_,
                    used_previous_application_read_secret, protected_packet.packet_number);
                if (processed.has_value()) {
                    processed_peer_packet_ = true;
                    if (config_.role == EndpointRole::server &&
                        status_ != HandshakeStatus::connected) {
                        mark_peer_address_validated();
                    }
                    const auto ack_eliciting = has_ack_eliciting_frame(protected_packet.frames);
                    application_space_.received_packets.record_received(
                        protected_packet.packet_number, ack_eliciting, now, ecn,
                        config_.transport.ack_eliciting_threshold);
                    note_idle_peer_activity(now);
                    if (ack_eliciting) {
                        schedule_application_ack_deadline(application_space_, now,
                                                          local_transport_parameters_.max_ack_delay,
                                                          ecn);
                    }
                    if (zero_rtt_space_.read_secret.has_value() ||
                        zero_rtt_space_.write_secret.has_value()) {
                        if (config_.role == EndpointRole::server &&
                            zero_rtt_space_.read_secret.has_value()) {
                            arm_server_zero_rtt_discard_deadline(now);
                        } else {
                            discard_packet_space_state(zero_rtt_space_);
                        }
                    }
                    update_spin_bit_on_receive(last_inbound_path_id_, protected_packet.spin_bit,
                                               protected_packet.packet_number);
                }
                return processed;
            }
        },
        packet);
}

bool QuicConnection::should_skip_packet_number_for_optimistic_ack_detection(
    const PacketSpaceState &packet_space, std::uint64_t packet_number) {
    const bool skip_counter_active = packet_space.optimistic_ack_skip_counter > 0;
    const bool skip_interval_due = (packet_space.optimistic_ack_skip_counter % 8u) == 0;
    const bool packet_number_available = packet_number < kMaxQuicVarInt;
    return skip_counter_active & skip_interval_due & packet_number_available;
}

std::uint64_t QuicConnection::reserve_packet_number(PacketSpaceState &packet_space) {
    const auto packet_number = packet_space.next_send_packet_number++;
    if (!config_.transport.enable_optimistic_ack_mitigation) {
        return packet_number;
    }

    ++packet_space.optimistic_ack_skip_counter;
    if (should_skip_packet_number_for_optimistic_ack_detection(
            packet_space, packet_space.next_send_packet_number)) {
        packet_space.optimistic_ack_skipped_packet_numbers.push_back(
            packet_space.next_send_packet_number);
        ++packet_space.next_send_packet_number;
    }
    return packet_number;
}

bool QuicConnection::ack_ranges_include_unsent_packet_number(const PacketSpaceState &packet_space,
                                                             AckRangeCursor cursor) const {
    if (!config_.transport.enable_optimistic_ack_mitigation) {
        return false;
    }

    while (const auto range = next_ack_range(cursor)) {
        for (const auto skipped_packet_number :
             packet_space.optimistic_ack_skipped_packet_numbers) {
            if (skipped_packet_number < range->smallest) {
                continue;
            }
            if (skipped_packet_number > range->largest) {
                continue;
            }
            if (packet_space.recovery.find_packet(skipped_packet_number) == nullptr) {
                return true;
            }
        }
    }
    return false;
}

CodecResult<bool> QuicConnection::reject_optimistic_ack_if_detected(PacketSpaceState &packet_space,
                                                                    AckRangeCursor cursor,
                                                                    QuicCoreTimePoint now) {
    if (!ack_ranges_include_unsent_packet_number(packet_space, cursor)) {
        return CodecResult<bool>::success(true);
    }

    const auto error = optimistic_ack_protocol_violation_error();
    queue_transport_close_for_error(now, error);
    return CodecResult<bool>::failure(error);
}

CodecResult<bool> QuicConnection::detect_old_key_ack_of_current_key_phase_packet(
    PacketSpaceState &packet_space, AckRangeCursor cursor, QuicCoreTimePoint now) {
    if (!packet_space_is_application(packet_space, application_space_)) {
        return CodecResult<bool>::success(true);
    }

    while (const auto range = next_ack_range(cursor)) {
        for (const auto handle : packet_space.recovery.tracked_packets()) {
            if (handle.packet_number < range->smallest || handle.packet_number > range->largest) {
                continue;
            }
            const auto *packet = packet_space.recovery.packet_for_handle(handle);
            if (packet != nullptr && packet->protection_key_update_generation ==
                                         current_application_write_key_generation_) {
                const auto error = key_update_error();
                queue_transport_close_for_error(now, error);
                return CodecResult<bool>::failure(error);
            }
        }
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_crypto(EncryptionLevel level,
                                                         std::span<const Frame> frames,
                                                         QuicCoreTimePoint now) {
    auto &packet_space = packet_space_for_level(level, initial_space_, handshake_space_,
                                                zero_rtt_space_, application_space_);

    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
            const auto processed_ack = process_inbound_ack(
                packet_space, *ack_frame, now, /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
                config_.role == EndpointRole::client && level == EncryptionLevel::initial);
            if (!processed_ack.has_value()) {
                return processed_ack;
            }
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            continue;
        }

        if (std::holds_alternative<TransportConnectionCloseFrame>(frame)) {
            enter_draining_state(now);
            continue;
        }

        const bool application_handshake_done = (config_.role == EndpointRole::client) &
                                                (level == EncryptionLevel::application) &
                                                std::holds_alternative<HandshakeDoneFrame>(frame);
        if (application_handshake_done) {
            confirm_handshake();
            continue;
        }

        const auto *crypto_frame = std::get_if<CryptoFrame>(&frame);
        if (crypto_frame == nullptr) {
            return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type, 0);
        }
        const auto contiguous_bytes =
            packet_space.receive_crypto.push(crypto_frame->offset, crypto_frame->crypto_data);
        if (!contiguous_bytes.has_value()) {
            return CodecResult<bool>::failure(contiguous_bytes.error());
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

CodecResult<bool> QuicConnection::process_inbound_received_crypto(
    EncryptionLevel level, std::span<const ReceivedFrame> frames, QuicCoreTimePoint now) {
    auto &packet_space = packet_space_for_level(level, initial_space_, handshake_space_,
                                                zero_rtt_space_, application_space_);

    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<ReceivedAckFrame>(&frame)) {
            const auto processed_ack = process_inbound_ack(
                packet_space, *ack_frame, now, /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
                config_.role == EndpointRole::client && level == EncryptionLevel::initial);
            if (!processed_ack.has_value()) {
                return processed_ack;
            }
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            continue;
        }

        if (std::holds_alternative<TransportConnectionCloseFrame>(frame)) {
            enter_draining_state(now);
            continue;
        }

        const bool application_handshake_done = (config_.role == EndpointRole::client) &
                                                (level == EncryptionLevel::application) &
                                                std::holds_alternative<HandshakeDoneFrame>(frame);
        if (application_handshake_done) {
            confirm_handshake();
            continue;
        }

        const auto *crypto_frame = std::get_if<ReceivedCryptoFrame>(&frame);
        if (crypto_frame == nullptr) {
            return CodecResult<bool>::failure(CodecErrorCode::frame_not_allowed_in_packet_type, 0);
        }
        const auto contiguous_bytes = packet_space.receive_crypto.push_shared(
            crypto_frame->offset, crypto_frame->crypto_data);
        if (!contiguous_bytes.has_value()) {
            return CodecResult<bool>::failure(contiguous_bytes.error());
        }
        if (contiguous_bytes.value().empty()) {
            continue;
        }

        if (!tls_.has_value()) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state, 0);
        }

        const auto provided = tls_->provide(level, contiguous_bytes.value().span());
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
                                                      bool suppress_pto_reset,
                                                      bool used_previous_application_read_secret) {
    const auto cursor = make_ack_range_cursor(ack);
    if (!cursor.has_value()) {
        return CodecResult<bool>::success(true);
    }
    const auto optimistic_ack_check =
        reject_optimistic_ack_if_detected(packet_space, cursor.value(), now);
    if (!optimistic_ack_check.has_value()) {
        return optimistic_ack_check;
    }
    if (used_previous_application_read_secret) {
        const auto key_update_check =
            detect_old_key_ack_of_current_key_phase_packet(packet_space, cursor.value(), now);
        if (!key_update_check.has_value()) {
            return key_update_check;
        }
    }

    const bool traces_ack = packet_space_is_application(packet_space, application_space_) &&
                            packet_trace_matches_connection(config_.source_connection_id);
    return process_inbound_ack_cursor(packet_space, cursor.value(), ack.largest_acknowledged,
                                      decode_ack_delay(ack, ack_delay_exponent), ack.ecn_counts,
                                      traces_ack ? format_ack_ranges(ack) : std::string{}, now,
                                      max_ack_delay_ms, suppress_pto_reset);
}

CodecResult<bool>
QuicConnection::process_inbound_ack(PacketSpaceState &packet_space, const ReceivedAckFrame &ack,
                                    QuicCoreTimePoint now, std::uint64_t ack_delay_exponent,
                                    std::uint64_t max_ack_delay_ms, bool suppress_pto_reset,
                                    bool used_previous_application_read_secret) {
    const auto cursor = make_ack_range_cursor(ack);
    if (!cursor.has_value()) {
        return CodecResult<bool>::success(true);
    }
    const auto optimistic_ack_check =
        reject_optimistic_ack_if_detected(packet_space, cursor.value(), now);
    if (!optimistic_ack_check.has_value()) {
        return optimistic_ack_check;
    }
    if (used_previous_application_read_secret) {
        const auto key_update_check =
            detect_old_key_ack_of_current_key_phase_packet(packet_space, cursor.value(), now);
        if (!key_update_check.has_value()) {
            return key_update_check;
        }
    }

    const bool traces_ack = packet_space_is_application(packet_space, application_space_) &&
                            packet_trace_matches_connection(config_.source_connection_id);
    return process_inbound_ack_cursor(packet_space, cursor.value(), ack.largest_acknowledged,
                                      decode_ack_delay(ack, ack_delay_exponent), ack.ecn_counts,
                                      traces_ack ? format_ack_ranges(ack) : std::string{}, now,
                                      max_ack_delay_ms, suppress_pto_reset);
}

CodecResult<bool> QuicConnection::process_inbound_ack_cursor(
    PacketSpaceState &packet_space, AckRangeCursor cursor, std::uint64_t largest_acknowledged,
    std::chrono::microseconds decoded_ack_delay, const std::optional<AckEcnCounts> &ecn_counts,
    const std::string &ack_ranges, QuicCoreTimePoint now, std::uint64_t max_ack_delay_ms,
    bool suppress_pto_reset) {
    packet_space.recovery.rtt_state() = shared_recovery_rtt_state();
    maybe_update_rtt_before_ack_loss_detection(packet_space, cursor, largest_acknowledged, now,
                                               decoded_ack_delay, max_ack_delay_ms);
    auto ack_result = packet_space.recovery.apply_ack_received(cursor, largest_acknowledged, now);
    if (send_profile_enabled()) {
        ++send_profile_counters().ack_frames;
    }
    auto &acked_packets = acked_packet_scratch_;
    auto &late_acked_packets = late_acked_packet_scratch_;
    auto &newly_lost_packets = newly_lost_packet_scratch_;
    auto &simple_stream_ack_samples = simple_stream_ack_sample_scratch_;
    acked_packets.clear();
    late_acked_packets.clear();
    newly_lost_packets.clear();
    simple_stream_ack_samples.clear();
    acked_packets.reserve(ack_result.acked_packets.size());
    simple_stream_ack_samples.reserve(ack_result.acked_packets.size());
    const auto can_collect_lightweight_simple_stream_ack_samples = [&]() {
        if (!ack_result.late_acked_packets.empty() || !ack_result.lost_packets.empty() ||
            config_.role == EndpointRole::client || qlog_session_ != nullptr ||
            packet_trace_matches_connection(config_.source_connection_id)) {
            return false;
        }
        const auto algorithm = congestion_controller_.algorithm();
        if (algorithm != QuicCongestionControlAlgorithm::newreno &&
            algorithm != QuicCongestionControlAlgorithm::cubic) {
            return false;
        }
        return std::ranges::all_of(ack_result.acked_packets, [&](const auto handle) {
            const auto *packet = packet_space.recovery.packet_for_handle(handle);
            return packet != nullptr && packet_has_only_stream_frame_metadata(*packet);
        });
    }();
    for (const auto handle : ack_result.acked_packets) {
        if (try_retire_simple_stream_acked_packet(
                packet_space, handle, acked_packets, simple_stream_ack_samples,
                can_collect_lightweight_simple_stream_ack_samples)) {
            continue;
        }
        append_retired_packet_if_present(acked_packets, retire_acked_packet(packet_space, handle));
    }
    late_acked_packets.reserve(ack_result.late_acked_packets.size());
    for (const auto handle : ack_result.late_acked_packets) {
        append_retired_packet_if_present(late_acked_packets,
                                         retire_acked_packet(packet_space, handle));
    }
    newly_lost_packets.reserve(ack_result.lost_packets.size());
    for (const auto handle : ack_result.lost_packets) {
        append_retired_packet_if_present(
            newly_lost_packets,
            mark_lost_packet(packet_space, handle, /*already_marked_in_recovery=*/true, now));
    }
    if (send_profile_enabled()) {
        auto &profile = send_profile_counters();
        profile.acked_packets += acked_packets.size();
        profile.late_acked_packets += late_acked_packets.size();
        profile.ack_lost_packets += newly_lost_packets.size();
        for (const auto &packet : acked_packets) {
            profile.acked_bytes += packet.bytes_in_flight;
        }
        for (const auto &packet : late_acked_packets) {
            profile.late_acked_bytes += packet.bytes_in_flight;
        }
        for (const auto &packet : newly_lost_packets) {
            profile.ack_lost_bytes += packet.bytes_in_flight;
            if (packet.lost_by_packet_threshold) {
                ++profile.packet_threshold_losses;
            } else {
                ++profile.time_threshold_losses;
            }
        }
    }
    for (const auto &packet : newly_lost_packets) {
        const auto trigger =
            packet.lost_by_packet_threshold ? "reordering_threshold" : "time_threshold";
        emit_qlog_packet_lost(packet, trigger, now);
    }

    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    auto simple_stream_ack_sample_span =
        std::span<const AckedStreamPacketSample>(simple_stream_ack_samples);
    auto acked_packet_span = std::span<const SentPacketRecord>(acked_packets);
    if (ack_result.largest_acknowledged_was_newly_acked) {
        struct PathEcnAckSummary {
            std::uint64_t newly_acked_ect0 = 0;
            std::uint64_t newly_acked_ect1 = 0;
            std::optional<QuicCoreTimePoint> latest_marked_sent_time;
        };

        std::map<QuicPathId, PathEcnAckSummary> acked_ecn_by_path;
        const auto note_acked_ecn_packet = [&](const SentPacketRecord &packet) {
            if (!is_ect_codepoint(packet.ecn)) {
                return;
            }

            auto &summary = acked_ecn_by_path[packet.path_id];
            if (packet.ecn == QuicEcnCodepoint::ect0) {
                ++summary.newly_acked_ect0;
            } else {
                ++summary.newly_acked_ect1;
            }
            summary.latest_marked_sent_time =
                summary.latest_marked_sent_time.has_value()
                    ? std::max(*summary.latest_marked_sent_time, packet.sent_time)
                    : packet.sent_time;
        };
        for (const auto &packet : acked_packets) {
            note_acked_ecn_packet(packet);
        }
        for (const auto &packet : late_acked_packets) {
            note_acked_ecn_packet(packet);
        }

        if (!acked_ecn_by_path.empty()) {
            const std::array packet_spaces = {
                &initial_space_,
                &handshake_space_,
                &application_space_,
            };
            auto packet_space_index = ecn_packet_space_index(packet_space, packet_spaces);
            for (const auto &[path_id, summary] : acked_ecn_by_path) {
                auto &path = ensure_path_state(path_id);
                if (path.ecn.state == QuicPathEcnState::failed) {
                    continue;
                }

                if (!ecn_counts.has_value()) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                const auto previous_counts = path.ecn.has_last_peer_counts[packet_space_index]
                                                 ? path.ecn.last_peer_counts[packet_space_index]
                                                 : AckEcnCounts{};
                const auto &current_counts = *ecn_counts;
                bool counts_decreased = current_counts.ect0 < previous_counts.ect0 ||
                                        current_counts.ect1 < previous_counts.ect1 ||
                                        current_counts.ecn_ce < previous_counts.ecn_ce;
                if (counts_decreased) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                const auto delta_ect0 = current_counts.ect0 - previous_counts.ect0;
                auto delta_ect1 = current_counts.ect1 - previous_counts.ect1;
                auto delta_ce = current_counts.ecn_ce - previous_counts.ecn_ce;
                bool missing_ect0_feedback = delta_ect0 + delta_ce < summary.newly_acked_ect0;
                bool missing_ect1_feedback = delta_ect1 + delta_ce < summary.newly_acked_ect1;
                bool impossible_ect0_count = current_counts.ect0 > path.ecn.total_sent_ect0;
                bool impossible_ect1_count = current_counts.ect1 > path.ecn.total_sent_ect1;
                if (missing_ect0_feedback || missing_ect1_feedback || impossible_ect0_count ||
                    impossible_ect1_count) {
                    disable_ecn_on_path(path_id);
                    continue;
                }

                path.ecn.last_peer_counts[packet_space_index] = current_counts;
                path.ecn.has_last_peer_counts[packet_space_index] = true;
                if (path.ecn.state == QuicPathEcnState::probing) {
                    path.ecn.probing_packets_acked +=
                        summary.newly_acked_ect0 + summary.newly_acked_ect1;
                    path.ecn.state = QuicPathEcnState::capable;
                }

                if (delta_ce != 0) {
                    const auto latest_marked_sent_time = *summary.latest_marked_sent_time;
                    latest_ecn_ce_sent_time =
                        std::max(latest_ecn_ce_sent_time.value_or(latest_marked_sent_time),
                                 latest_marked_sent_time);
                }
            }
        }
    }

    if (try_ack_simple_stream_fast_path(packet_space, ack_result, simple_stream_ack_sample_span,
                                        acked_packet_span, now, ecn_counts, suppress_pto_reset)) {
        return CodecResult<bool>::success(true);
    }

    const bool has_any_acked_packets = !acked_packets.empty() || !late_acked_packets.empty();
    for (const auto &packet : acked_packets) {
        note_pmtu_probe_acked(packet, now);
    }
    for (const auto &packet : late_acked_packets) {
        note_pmtu_probe_acked(packet, now);
    }
    if (config_.role == EndpointRole::client && &packet_space == &application_space_ &&
        has_any_acked_packets) {
        confirm_handshake();
    }
    const auto &shared_rtt_state = shared_recovery_rtt_state();
    auto ack_eliciting_lost_packets = ack_eliciting_in_flight_losses(newly_lost_packets);
    if (!ack_eliciting_lost_packets.empty()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().loss_events;
        }
        congestion_controller_.on_loss_event(now,
                                             latest_packet_sent_time(ack_eliciting_lost_packets));
        if (establishes_persistent_congestion(ack_eliciting_lost_packets, shared_rtt_state,
                                              transport_parameter_milliseconds(max_ack_delay_ms))) {
            if (send_profile_enabled()) {
                ++send_profile_counters().persistent_congestion_events;
            }
            congestion_controller_.on_persistent_congestion();
        }
    }
    if (latest_ecn_ce_sent_time.has_value()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().ecn_loss_events;
        }
        congestion_controller_.on_loss_event(now, *latest_ecn_ce_sent_time);
    }
    // The transport cannot infer application-limited sending from the queue state at ACK time:
    // embedding applications can queue more data only after this ACK is delivered to them.
    // Preserve the per-packet send-time app_limited marker instead.
    constexpr bool app_limited = false;
    if (late_acked_packets.empty() &&
        try_ack_simple_congestion_batch(acked_packet_span, now, shared_rtt_state)) {
    } else if (late_acked_packets.empty()) {
        congestion_controller_.on_packets_acked(acked_packet_span, app_limited, now,
                                                shared_rtt_state);
    } else {
        auto congestion_acked_packets = acked_packets;
        congestion_acked_packets.insert(congestion_acked_packets.end(), late_acked_packets.begin(),
                                        late_acked_packets.end());
        congestion_controller_.on_packets_acked(congestion_acked_packets, app_limited, now,
                                                shared_rtt_state);
    }
    if (send_profile_enabled()) {
        record_congestion_debug_for_profile(congestion_controller_, now, send_profile_counters());
    }
    if (has_any_acked_packets) {
        reset_unpaced_ack_eliciting_burst();
    }
    if (has_any_acked_packets && !suppress_pto_reset) {
        const bool keepalive_probe_packet_space =
            (&packet_space == &initial_space_) | (&packet_space == &handshake_space_);
        const bool client_handshake_keepalive_ack_only =
            (config_.role == EndpointRole::client) & (status_ == HandshakeStatus::in_progress) &
                !handshake_confirmed_ & keepalive_probe_packet_space &
                std::ranges::all_of(acked_packets,
                                    [&](const SentPacketRecord &packet) {
                                        return packet.has_ping &
                                               (retransmittable_probe_frame_count(packet) == 0);
                                    }) &&
            std::ranges::all_of(late_acked_packets, [&](const SentPacketRecord &packet) {
                return packet.has_ping & (retransmittable_probe_frame_count(packet) == 0);
            });
        if (!client_handshake_keepalive_ack_only) {
            pto_count_ = 0;
        }
    }

    if (packet_space_is_application(packet_space, application_space_) &&
        packet_trace_matches_connection(config_.source_connection_id)) {
        std::cerr << "quic-packet-trace ack scid="
                  << format_connection_id_hex(config_.source_connection_id)
                  << " path=" << last_inbound_path_id_ << " ranges=" << ack_ranges << " acked={"
                  << summarize_packets(acked_packets) << "}" << " late={"
                  << summarize_packets(late_acked_packets) << "}" << " lost={"
                  << summarize_packets(newly_lost_packets) << "}"
                  << " pending_send=" << static_cast<int>(has_pending_application_send())
                  << " probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_
                  << " cwnd=" << congestion_controller_.congestion_window()
                  << " bif=" << congestion_controller_.bytes_in_flight()
                  << " current=" << format_optional_path_id(current_send_path_id_)
                  << " previous=" << format_optional_path_id(previous_path_id_)
                  << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                  << " inbound_path={"
                  << format_path_state_summary(find_path_state(paths_, last_inbound_path_id_))
                  << "} current_path={"
                  << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                  << "}\n";
    }
    maybe_emit_qlog_recovery_metrics(now);
    return CodecResult<bool>::success(true);
}

void QuicConnection::maybe_update_rtt_before_ack_loss_detection(
    PacketSpaceState &packet_space, AckRangeCursor cursor, std::uint64_t largest_acknowledged,
    QuicCoreTimePoint now, std::chrono::microseconds decoded_ack_delay,
    std::uint64_t max_ack_delay_ms) {
    const auto *largest_packet =
        packet_space.recovery.find_newly_ackable_packet(largest_acknowledged);
    if (largest_packet == nullptr) {
        return;
    }
    if (!largest_packet->ack_eliciting &&
        !packet_space.recovery.ack_ranges_include_newly_ackable_ack_eliciting_packet(cursor)) {
        return;
    }

    update_rtt(packet_space.recovery.rtt_state(), now, *largest_packet, decoded_ack_delay,
               transport_parameter_milliseconds(max_ack_delay_ms));
    recovery_rtt_state_ = packet_space.recovery.rtt_state();
    synchronize_recovery_rtt_state();
    if (send_profile_enabled()) {
        auto &profile = send_profile_counters();
        const auto &rtt = shared_recovery_rtt_state();
        ++profile.rtt_samples;
        record_latest_rtt_sample_for_profile(rtt, profile);
        profile.smoothed_rtt_us_last = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(rtt.smoothed_rtt).count());
        profile.rttvar_us_last = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(rtt.rttvar).count());
    }
}

void QuicConnection::track_sent_packet(PacketSpaceState &packet_space, SentPacketRecord packet) {
    const auto sent_time = packet.sent_time;
    if (packet.ack_eliciting && !packet.is_pmtu_probe) {
        packet.app_limited =
            congestion_controller_.would_underutilize_congestion_window(packet.bytes_in_flight) &&
            !has_pending_congestion_controlled_send();
        congestion_controller_.on_packet_sent(packet);
    }
    if (is_ect_codepoint(packet.ecn)) {
        auto &path = ensure_path_state(packet.path_id);
        if (packet.ecn == QuicEcnCodepoint::ect0) {
            ++path.ecn.total_sent_ect0;
        } else {
            ++path.ecn.total_sent_ect1;
        }
        if (path.ecn.state == QuicPathEcnState::probing) {
            ++path.ecn.probing_packets_sent;
        }
    }
    packet_space.recovery.on_packet_sent(std::move(packet));
    if (send_profile_enabled()) {
        auto &profile = send_profile_counters();
        profile.congestion_cwnd_last =
            static_cast<std::uint64_t>(congestion_controller_.congestion_window());
        profile.congestion_cwnd_max =
            std::max(profile.congestion_cwnd_max, profile.congestion_cwnd_last);
        profile.congestion_bif_last =
            static_cast<std::uint64_t>(congestion_controller_.bytes_in_flight());
        profile.congestion_bif_max =
            std::max(profile.congestion_bif_max, profile.congestion_bif_last);
        record_congestion_debug_for_profile(congestion_controller_, sent_time, profile);
    }
    maybe_emit_qlog_recovery_metrics(sent_time);
}

bool QuicConnection::try_retire_simple_stream_acked_packet(
    PacketSpaceState &packet_space, RecoveryPacketHandle handle,
    std::vector<SentPacketRecord> &acked_packets,
    std::vector<AckedStreamPacketSample> &simple_stream_ack_samples, bool use_lightweight_sample) {
    const auto *packet = packet_space.recovery.packet_for_handle(handle);
    if (packet == nullptr || !packet_has_only_stream_frame_metadata(*packet)) {
        return false;
    }

    const auto sample = make_acked_stream_packet_sample(*packet);
    auto snapshot =
        use_lightweight_sample ? SentPacketRecord{} : make_congestion_ack_snapshot(*packet);
    std::optional<StreamFrameSendMetadata> first_stream_frame_metadata =
        packet->first_stream_frame_metadata;
    auto stream_frame_metadata = packet->stream_frame_metadata;
    if (!packet_space.recovery.retire_packet_if_present(handle)) {
        return false;
    }

    std::optional<std::uint64_t> single_retirement_candidate;
    std::vector<std::uint64_t> additional_retirement_candidates;
    const auto note_retirement_candidate = [&](std::uint64_t stream_id) {
        note_retirement_candidate_stream_id(single_retirement_candidate,
                                            additional_retirement_candidates, stream_id);
    };
    const auto acknowledge_metadata = [&](const StreamFrameSendMetadata &metadata) {
        const auto stream_it = streams_.find(metadata.stream_id);
        if (stream_it == streams_.end()) {
            return;
        }

        const auto previous_fresh_sendable_bytes =
            fresh_sendable_bytes_for_cache(stream_it->second);
        const auto previous_stream_has_lost_send_data =
            stream_it->second.reset_state == StreamControlFrameState::none &&
            stream_it->second.send_buffer.has_lost_data();
        stream_it->second.acknowledge_send_metadata(metadata);
        note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                       previous_stream_has_lost_send_data, stream_it->second);
        maybe_refresh_peer_stream_limit(stream_it->second);
        note_retirement_candidate(metadata.stream_id);
    };
    if (first_stream_frame_metadata.has_value()) {
        acknowledge_metadata(*first_stream_frame_metadata);
    }
    for (const auto &metadata : stream_frame_metadata) {
        acknowledge_metadata(metadata);
    }
    for_each_retirement_candidate_stream_id(
        single_retirement_candidate, additional_retirement_candidates,
        [&](std::uint64_t stream_id) { maybe_retire_stream(stream_id); });

    if (use_lightweight_sample) {
        simple_stream_ack_samples.push_back(sample);
    } else {
        acked_packets.push_back(std::move(snapshot));
    }
    return true;
}

bool QuicConnection::try_ack_simple_congestion_batch(
    std::span<const AckedStreamPacketSample> simple_stream_ack_samples,
    std::span<const SentPacketRecord> acked_packets, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    if (!acked_packets.empty()) {
        return false;
    }
    if (simple_stream_ack_samples.empty()) {
        return true;
    }
    const auto algorithm = congestion_controller_.algorithm();
    if (algorithm != QuicCongestionControlAlgorithm::newreno &&
        algorithm != QuicCongestionControlAlgorithm::cubic) {
        return false;
    }

    constexpr bool app_limited = false;
    congestion_controller_.on_simple_stream_packets_acked(simple_stream_ack_samples, app_limited,
                                                          now, rtt_state);
    return true;
}

bool QuicConnection::can_use_simple_stream_ack_fast_path(
    std::span<const SentPacketRecord> acked_packets, bool has_late_acked_packets) const {
    if (has_late_acked_packets || !acked_packets.empty()) {
        return false;
    }
    if (config_.role == EndpointRole::client || qlog_session_ != nullptr ||
        packet_trace_matches_connection(config_.source_connection_id)) {
        return false;
    }
    const auto algorithm = congestion_controller_.algorithm();
    return algorithm == QuicCongestionControlAlgorithm::newreno ||
           algorithm == QuicCongestionControlAlgorithm::cubic;
}

bool QuicConnection::process_simple_stream_ack_ecn(
    PacketSpaceState &packet_space,
    std::span<const AckedStreamPacketSample> simple_stream_ack_samples,
    const std::optional<AckEcnCounts> &ecn_counts,
    std::optional<QuicCoreTimePoint> &latest_ecn_ce_sent_time) {
    struct PathEcnAckSummary {
        std::uint64_t newly_acked_ect0 = 0;
        std::uint64_t newly_acked_ect1 = 0;
        std::optional<QuicCoreTimePoint> latest_marked_sent_time;
    };

    std::optional<QuicPathId> single_path_id;
    std::uint64_t single_path_newly_acked_ect0 = 0;
    std::uint64_t single_path_newly_acked_ect1 = 0;
    std::optional<QuicCoreTimePoint> single_path_latest_marked_sent_time;
    bool single_path_summary = true;
    std::map<QuicPathId, PathEcnAckSummary> acked_ecn_by_path;
    for (const auto &packet : simple_stream_ack_samples) {
        if (!is_ect_codepoint(packet.ecn)) {
            continue;
        }

        if (single_path_summary) {
            if (!single_path_id.has_value()) {
                single_path_id = packet.path_id;
            } else if (*single_path_id != packet.path_id) {
                single_path_summary = false;
            }
            if (single_path_summary) {
                if (packet.ecn == QuicEcnCodepoint::ect0) {
                    ++single_path_newly_acked_ect0;
                } else {
                    ++single_path_newly_acked_ect1;
                }
                single_path_latest_marked_sent_time =
                    single_path_latest_marked_sent_time.has_value()
                        ? std::max(*single_path_latest_marked_sent_time, packet.sent_time)
                        : packet.sent_time;
                continue;
            }
        }

        if (single_path_id.has_value()) {
            acked_ecn_by_path[*single_path_id] = PathEcnAckSummary{
                .newly_acked_ect0 = single_path_newly_acked_ect0,
                .newly_acked_ect1 = single_path_newly_acked_ect1,
                .latest_marked_sent_time = single_path_latest_marked_sent_time,
            };
            single_path_id.reset();
        }

        auto &summary = acked_ecn_by_path[packet.path_id];
        if (packet.ecn == QuicEcnCodepoint::ect0) {
            ++summary.newly_acked_ect0;
        } else {
            ++summary.newly_acked_ect1;
        }
        summary.latest_marked_sent_time =
            summary.latest_marked_sent_time.has_value()
                ? std::max(*summary.latest_marked_sent_time, packet.sent_time)
                : packet.sent_time;
    }
    if (single_path_summary && single_path_id.has_value() &&
        single_path_latest_marked_sent_time.has_value()) {
        return process_single_path_simple_stream_ack_ecn(
            packet_space, *single_path_id, single_path_newly_acked_ect0,
            single_path_newly_acked_ect1, *single_path_latest_marked_sent_time, ecn_counts,
            latest_ecn_ce_sent_time);
    }
    if (acked_ecn_by_path.empty()) {
        return true;
    }

    const std::array packet_spaces = {
        &initial_space_,
        &handshake_space_,
        &application_space_,
    };
    auto packet_space_index = ecn_packet_space_index(packet_space, packet_spaces);
    for (const auto &[path_id, summary] : acked_ecn_by_path) {
        auto &path = ensure_path_state(path_id);
        if (path.ecn.state == QuicPathEcnState::failed) {
            continue;
        }

        if (!ecn_counts.has_value()) {
            disable_ecn_on_path(path_id);
            continue;
        }

        const auto previous_counts = path.ecn.has_last_peer_counts[packet_space_index]
                                         ? path.ecn.last_peer_counts[packet_space_index]
                                         : AckEcnCounts{};
        const auto &current_counts = *ecn_counts;
        const bool counts_decreased = current_counts.ect0 < previous_counts.ect0 ||
                                      current_counts.ect1 < previous_counts.ect1 ||
                                      current_counts.ecn_ce < previous_counts.ecn_ce;
        if (counts_decreased) {
            disable_ecn_on_path(path_id);
            continue;
        }

        const auto delta_ect0 = current_counts.ect0 - previous_counts.ect0;
        auto delta_ect1 = current_counts.ect1 - previous_counts.ect1;
        auto delta_ce = current_counts.ecn_ce - previous_counts.ecn_ce;
        bool missing_ect0_feedback = delta_ect0 + delta_ce < summary.newly_acked_ect0;
        bool missing_ect1_feedback = delta_ect1 + delta_ce < summary.newly_acked_ect1;
        bool impossible_ect0_count = current_counts.ect0 > path.ecn.total_sent_ect0;
        bool impossible_ect1_count = current_counts.ect1 > path.ecn.total_sent_ect1;
        if (missing_ect0_feedback || missing_ect1_feedback || impossible_ect0_count ||
            impossible_ect1_count) {
            disable_ecn_on_path(path_id);
            continue;
        }

        path.ecn.last_peer_counts[packet_space_index] = current_counts;
        path.ecn.has_last_peer_counts[packet_space_index] = true;
        if (path.ecn.state == QuicPathEcnState::probing) {
            path.ecn.probing_packets_acked += summary.newly_acked_ect0 + summary.newly_acked_ect1;
            path.ecn.state = QuicPathEcnState::capable;
        }

        if (delta_ce != 0) {
            const auto latest_marked_sent_time = *summary.latest_marked_sent_time;
            latest_ecn_ce_sent_time = std::max(
                latest_ecn_ce_sent_time.value_or(latest_marked_sent_time), latest_marked_sent_time);
        }
    }
    return true;
}

bool QuicConnection::process_single_path_simple_stream_ack_ecn(
    PacketSpaceState &packet_space,
    QuicPathId path_id, // NOLINT(bugprone-easily-swappable-parameters)
    std::uint64_t newly_acked_ect0, std::uint64_t newly_acked_ect1,
    QuicCoreTimePoint latest_marked_sent_time, const std::optional<AckEcnCounts> &ecn_counts,
    std::optional<QuicCoreTimePoint> &latest_ecn_ce_sent_time) {
    const std::array packet_spaces = {
        &initial_space_,
        &handshake_space_,
        &application_space_,
    };
    auto packet_space_index = ecn_packet_space_index(packet_space, packet_spaces);
    auto &path = ensure_path_state(path_id);
    if (path.ecn.state == QuicPathEcnState::failed) {
        return true;
    }

    if (!ecn_counts.has_value()) {
        disable_ecn_on_path(path_id);
        return true;
    }

    const auto previous_counts = path.ecn.has_last_peer_counts[packet_space_index]
                                     ? path.ecn.last_peer_counts[packet_space_index]
                                     : AckEcnCounts{};
    const auto &current_counts = *ecn_counts;
    const bool counts_decreased = current_counts.ect0 < previous_counts.ect0 ||
                                  current_counts.ect1 < previous_counts.ect1 ||
                                  current_counts.ecn_ce < previous_counts.ecn_ce;
    if (counts_decreased) {
        disable_ecn_on_path(path_id);
        return true;
    }

    const auto delta_ect0 = current_counts.ect0 - previous_counts.ect0;
    auto delta_ect1 = current_counts.ect1 - previous_counts.ect1;
    auto delta_ce = current_counts.ecn_ce - previous_counts.ecn_ce;
    bool missing_ect0_feedback = delta_ect0 + delta_ce < newly_acked_ect0;
    bool missing_ect1_feedback = delta_ect1 + delta_ce < newly_acked_ect1;
    bool impossible_ect0_count = current_counts.ect0 > path.ecn.total_sent_ect0;
    bool impossible_ect1_count = current_counts.ect1 > path.ecn.total_sent_ect1;
    if (missing_ect0_feedback || missing_ect1_feedback || impossible_ect0_count ||
        impossible_ect1_count) {
        disable_ecn_on_path(path_id);
        return true;
    }

    path.ecn.last_peer_counts[packet_space_index] = current_counts;
    path.ecn.has_last_peer_counts[packet_space_index] = true;
    if (path.ecn.state == QuicPathEcnState::probing) {
        path.ecn.probing_packets_acked += newly_acked_ect0 + newly_acked_ect1;
        path.ecn.state = QuicPathEcnState::capable;
    }

    if (delta_ce != 0) {
        latest_ecn_ce_sent_time = std::max(
            latest_ecn_ce_sent_time.value_or(latest_marked_sent_time), latest_marked_sent_time);
    }
    return true;
}

bool QuicConnection::try_ack_simple_stream_fast_path(
    PacketSpaceState &packet_space, const AckApplyResult &ack_result,
    std::span<const AckedStreamPacketSample> simple_stream_ack_samples,
    std::span<const SentPacketRecord> acked_packets, QuicCoreTimePoint now,
    const std::optional<AckEcnCounts> &ecn_counts, bool suppress_pto_reset) {
    if (!can_use_simple_stream_ack_fast_path(acked_packets,
                                             !ack_result.late_acked_packets.empty()) ||
        simple_stream_ack_samples.empty() || !ack_result.lost_packets.empty()) {
        return false;
    }

    std::optional<QuicCoreTimePoint> latest_ecn_ce_sent_time;
    if (ack_result.largest_acknowledged_was_newly_acked) {
        static_cast<void>(process_simple_stream_ack_ecn(packet_space, simple_stream_ack_samples,
                                                        ecn_counts, latest_ecn_ce_sent_time));
    }

    const auto &shared_rtt_state = shared_recovery_rtt_state();
    static_cast<void>(try_ack_simple_congestion_batch(simple_stream_ack_samples, acked_packets, now,
                                                      shared_rtt_state));
    if (latest_ecn_ce_sent_time.has_value()) {
        if (send_profile_enabled()) {
            ++send_profile_counters().ecn_loss_events;
        }
        congestion_controller_.on_loss_event(now, *latest_ecn_ce_sent_time);
    }
    if (send_profile_enabled()) {
        record_congestion_debug_for_profile(congestion_controller_, now, send_profile_counters());
    }

    reset_unpaced_ack_eliciting_burst();
    if (!suppress_pto_reset) {
        pto_count_ = 0;
    }
    maybe_emit_qlog_recovery_metrics(now);
    return true;
}

bool QuicConnection::try_ack_simple_congestion_batch(
    std::span<const SentPacketRecord> acked_packets, QuicCoreTimePoint now,
    const RecoveryRttState &rtt_state) {
    if (acked_packets.empty()) {
        return true;
    }
    const auto algorithm = congestion_controller_.algorithm();
    if (algorithm != QuicCongestionControlAlgorithm::newreno &&
        algorithm != QuicCongestionControlAlgorithm::cubic) {
        return false;
    }

    const auto all_simple = std::ranges::all_of(acked_packets, [](const SentPacketRecord &packet) {
        return packet_is_simple_congestion_ack(packet);
    });
    if (!all_simple) {
        return false;
    }

    static_cast<void>(now);
    static_cast<void>(rtt_state);
    return false;
}

std::optional<SentPacketRecord> QuicConnection::retire_acked_packet(PacketSpaceState &packet_space,
                                                                    RecoveryPacketHandle handle) {
    auto retired_packet = packet_space.recovery.take_retired_packet_if_present(handle);
    if (!retired_packet.has_value()) {
        return std::nullopt;
    }

    auto &packet = *retired_packet;
    if (packet.largest_received_packet_number_acked.has_value()) {
        packet_space.received_packets.retire_acknowledged_ranges_up_to(
            *packet.largest_received_packet_number_acked);
    }
    std::optional<std::uint64_t> single_retirement_candidate;
    std::vector<std::uint64_t> additional_retirement_candidates;
    const auto note_retirement_candidate = [&](std::uint64_t stream_id) {
        note_retirement_candidate_stream_id(single_retirement_candidate,
                                            additional_retirement_candidates, stream_id);
    };
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.acknowledge(range.offset, range.bytes.size());
    }
    if (!packet.new_token_frames.empty()) {
        std::erase_if(pending_new_token_frames_, [&](const NewTokenFrame &pending) {
            return std::ranges::any_of(packet.new_token_frames, [&](const NewTokenFrame &acked) {
                return pending.token == acked.token;
            });
        });
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
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.stream_data_blocked_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stream_data_blocked_frame(frame);
        note_retirement_candidate(frame.stream_id);
    }
    for_each_stream_frame_metadata(packet, [&](const StreamFrameSendMetadata &metadata) {
        const auto stream = streams_.find(metadata.stream_id);
        if (stream == streams_.end()) {
            return;
        }

        const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(stream->second);
        auto previous_has_lost_send_data =
            stream->second.reset_state == StreamControlFrameState::none &&
            stream->second.send_buffer.has_lost_data();
        stream->second.acknowledge_send_metadata(metadata);
        note_stream_send_state_changed(previous_fresh_sendable_bytes, previous_has_lost_send_data,
                                       stream->second);
        maybe_refresh_peer_stream_limit(stream->second);
        note_retirement_candidate(metadata.stream_id);
    });
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(stream->second);
        auto previous_has_lost_send_data =
            stream->second.reset_state == StreamControlFrameState::none &&
            stream->second.send_buffer.has_lost_data();
        stream->second.acknowledge_send_fragment(fragment);
        note_stream_send_state_changed(previous_fresh_sendable_bytes, previous_has_lost_send_data,
                                       stream->second);
        maybe_refresh_peer_stream_limit(stream->second);
        note_retirement_candidate(fragment.stream_id);
    }
    for (const auto &frame : packet.reset_stream_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_reset_frame(frame);
        maybe_refresh_peer_stream_limit(stream->second);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.stop_sending_frames) {
        const auto stream = streams_.find(frame.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        stream->second.acknowledge_stop_sending_frame(frame);
        note_retirement_candidate(frame.stream_id);
    }
    for (const auto &frame : packet.max_streams_frames) {
        local_stream_limit_state_.acknowledge_max_streams_frame(frame);
    }
    if (!packet.new_connection_id_frames.empty()) {
        std::erase_if(pending_new_connection_id_frames_, [&](const NewConnectionIdFrame &pending) {
            return std::ranges::any_of(
                packet.new_connection_id_frames, [&](const NewConnectionIdFrame &acked) {
                    return std::tie(pending.sequence_number, pending.retire_prior_to,
                                    pending.connection_id, pending.stateless_reset_token) ==
                           std::tie(acked.sequence_number, acked.retire_prior_to,
                                    acked.connection_id, acked.stateless_reset_token);
                });
        });
    }
    if (!packet.retire_connection_id_frames.empty()) {
        std::erase_if(
            pending_retire_connection_id_frames_, [&](const RetireConnectionIdFrame &pending) {
                return std::ranges::any_of(
                    packet.retire_connection_id_frames, [&](const RetireConnectionIdFrame &acked) {
                        return pending.sequence_number == acked.sequence_number;
                    });
            });
        for (const auto &retired : packet.retire_connection_id_frames) {
            if (const auto peer = peer_connection_ids_.find(retired.sequence_number);
                peer != peer_connection_ids_.end()) {
                if (peer->second.locally_retired) {
                    peer_connection_ids_.erase(peer);
                    retired_peer_connection_id_sequences_.insert(retired.sequence_number);
                }
            }
        }
    }
    if (packet.has_handshake_done) {
        handshake_done_state_ = StreamControlFrameState::acknowledged;
    }
    if (packet.is_pmtu_probe) {
        packet.in_flight = false;
        packet.bytes_in_flight = 0;
        packet.crypto_ranges.clear();
        packet.new_token_frames.clear();
        packet.reset_stream_frames.clear();
        packet.stop_sending_frames.clear();
        packet.new_connection_id_frames.clear();
        packet.retire_connection_id_frames.clear();
        packet.max_data_frame.reset();
        packet.max_stream_data_frames.clear();
        packet.max_streams_frames.clear();
        packet.data_blocked_frame.reset();
        packet.stream_data_blocked_frames.clear();
        packet.first_stream_frame_metadata.reset();
        packet.stream_frame_metadata.clear();
        packet.stream_fragments.clear();
        packet.has_handshake_done = false;
    }

    for_each_retirement_candidate_stream_id(
        single_retirement_candidate, additional_retirement_candidates,
        [&](std::uint64_t stream_id) { maybe_retire_stream(stream_id); });
    return retired_packet;
}

std::optional<SentPacketRecord>
QuicConnection::mark_lost_packet(PacketSpaceState &packet_space, RecoveryPacketHandle handle,
                                 bool already_marked_in_recovery,
                                 std::optional<QuicCoreTimePoint> now) {
    const auto *tracked_packet = packet_space.recovery.packet_for_handle(handle);
    if (tracked_packet == nullptr) {
        return std::nullopt;
    }
    if (connection_drain_test_hooks().force_mark_lost_packet_missing_after_lookup) {
        return std::nullopt;
    }

    auto packet = *tracked_packet;
    if (!packet.new_token_frames.empty()) {
        pending_new_token_frames_.insert(pending_new_token_frames_.begin(),
                                         packet.new_token_frames.begin(),
                                         packet.new_token_frames.end());
    }
    if (!packet.is_pmtu_probe) {
        congestion_controller_.on_packets_lost(std::span<const SentPacketRecord>(&packet, 1));
    }
    note_pmtu_probe_lost(packet, now.value_or(packet.sent_time));
    if (packet_space_is_application(packet_space, application_space_) &&
        current_send_path_id_.has_value()) {
        auto &path = ensure_path_state(*current_send_path_id_);
        if (!path.validated & path.outstanding_challenge.has_value()) {
            path.challenge_pending = true;
        }
    }
    if (is_ect_codepoint(packet.ecn)) {
        auto &path = ensure_path_state(packet.path_id);
        if (path.ecn.state == QuicPathEcnState::probing) {
            ++path.ecn.probing_packets_lost;
            const bool all_probes_lost =
                path.ecn.probing_packets_sent != 0 && path.ecn.probing_packets_acked == 0 &&
                path.ecn.probing_packets_lost >= path.ecn.probing_packets_sent;
            if (all_probes_lost) {
                disable_ecn_on_path(packet.path_id);
            }
        }
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
    for_each_stream_frame_metadata(packet, [&](const StreamFrameSendMetadata &metadata) {
        const auto stream = streams_.find(metadata.stream_id);
        if (stream == streams_.end()) {
            return;
        }

        const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(stream->second);
        auto previous_has_lost_send_data =
            stream->second.reset_state == StreamControlFrameState::none &&
            stream->second.send_buffer.has_lost_data();
        stream->second.mark_send_metadata_lost(metadata);
        note_stream_send_state_changed(previous_fresh_sendable_bytes, previous_has_lost_send_data,
                                       stream->second);
    });
    for (const auto &fragment : packet.stream_fragments) {
        const auto stream = streams_.find(fragment.stream_id);
        if (stream == streams_.end()) {
            continue;
        }

        const auto previous_fresh_sendable_bytes = fresh_sendable_bytes_for_cache(stream->second);
        auto previous_has_lost_send_data =
            stream->second.reset_state == StreamControlFrameState::none &&
            stream->second.send_buffer.has_lost_data();
        stream->second.mark_send_fragment_lost(fragment);
        note_stream_send_state_changed(previous_fresh_sendable_bytes, previous_has_lost_send_data,
                                       stream->second);
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
    if (!packet.new_connection_id_frames.empty()) {
        pending_new_connection_id_frames_.insert(pending_new_connection_id_frames_.begin(),
                                                 packet.new_connection_id_frames.begin(),
                                                 packet.new_connection_id_frames.end());
    }
    if (!packet.retire_connection_id_frames.empty()) {
        pending_retire_connection_id_frames_.insert(pending_retire_connection_id_frames_.begin(),
                                                    packet.retire_connection_id_frames.begin(),
                                                    packet.retire_connection_id_frames.end());
        for (const auto &retired : packet.retire_connection_id_frames) {
            if (auto peer = peer_connection_ids_.find(retired.sequence_number);
                peer != peer_connection_ids_.end()) {
                peer->second.retire_frame_in_flight = false;
            }
        }
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

    static_cast<void>(already_marked_in_recovery);
    packet_space.recovery.on_packet_declared_lost(packet.packet_number);
    return packet;
}

void QuicConnection::rebuild_recovery(PacketSpaceState &packet_space) {
    packet_space.recovery.rebuild_auxiliary_indexes();
}

CodecResult<bool>
QuicConnection::process_inbound_application(std::span<const Frame> frames, QuicCoreTimePoint now,
                                            bool allow_preconnected_frames, QuicPathId path_id,
                                            bool used_previous_application_read_secret,
                                            std::optional<std::uint64_t> packet_number) {
    static_assert(std::variant_size_v<Frame> == 23,
                  "Update process_inbound_application when Frame gains new variants");
    const bool require_connected = !allow_preconnected_frames;
    const bool allow_preconnected_max_data_frame =
        application_space_.read_secret.has_value() && status_ == HandshakeStatus::in_progress;
    const bool traces_this_packet = packet_trace_matches_connection(config_.source_connection_id);
    const bool has_ack_frame = std::ranges::any_of(
        frames, [](const Frame &frame) { return std::holds_alternative<AckFrame>(frame); });
    const bool has_path_challenge_frame = std::ranges::any_of(frames, [](const Frame &frame) {
        return std::holds_alternative<PathChallengeFrame>(frame);
    });
    const bool has_path_response_frame = std::ranges::any_of(frames, [](const Frame &frame) {
        return std::holds_alternative<PathResponseFrame>(frame);
    });
    if (traces_this_packet & (has_ack_frame | has_path_challenge_frame | has_path_response_frame)) {
        std::cerr << "quic-packet-trace recv-app scid="
                  << format_connection_id_hex(config_.source_connection_id) << " path=" << path_id
                  << " frames_ack=" << static_cast<int>(has_ack_frame)
                  << " frames_path_challenge=" << static_cast<int>(has_path_challenge_frame)
                  << " frames_path_response=" << static_cast<int>(has_path_response_frame)
                  << " probing_only=" << static_cast<int>(is_probing_only(frames))
                  << " current=" << format_optional_path_id(current_send_path_id_)
                  << " previous=" << format_optional_path_id(previous_path_id_)
                  << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                  << " inbound_path={"
                  << format_path_state_summary(find_path_state(paths_, path_id))
                  << "} current_path={"
                  << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                  << "} probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_
                  << " cwnd=" << congestion_controller_.congestion_window()
                  << " bif=" << congestion_controller_.bytes_in_flight() << '\n';
    }
    if (path_id != current_send_path_id_.value_or(path_id) && !is_probing_only(frames) &&
        !should_keep_current_send_path_for_inbound_non_probing(path_id, packet_number)) {
        maybe_switch_to_path(path_id, /*initiated_locally=*/false, now);
    }
    if (!paths_.empty() | (path_id != 0) | current_send_path_id_.has_value()) {
        ensure_path_state(path_id);
    }
    if (packet_number.has_value()) {
        note_inbound_application_packet_for_path(path_id, *packet_number);
    }
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
            const auto processed_ack = process_inbound_ack(
                application_space_, *ack_frame, now, ack_delay_exponent, max_ack_delay_ms,
                /*suppress_pto_reset=*/false, used_previous_application_read_secret);
            if (!processed_ack.has_value()) {
                return processed_ack;
            }
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            const bool allow_preconnected_ping_frame = application_space_.read_secret.has_value() &&
                                                       status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_ping_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypePing));
            }
            continue;
        }

        if (const auto *crypto_frame = std::get_if<CryptoFrame>(&frame)) {
            const auto contiguous_bytes = application_space_.receive_crypto.push(
                crypto_frame->offset, crypto_frame->crypto_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error());
            }
            if (contiguous_bytes.value().empty()) {
                continue;
            }
            if (status_ == HandshakeStatus::connected && !tls_.has_value()) {
                continue;
            }

            if (!tls_.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                  0);
            }

            const auto provided =
                tls_->provide(EncryptionLevel::application, contiguous_bytes.value());
            if (!provided.has_value()) {
                return provided;
            }

            install_available_secrets();
            collect_pending_tls_bytes();
            continue;
        }

        const auto *stream_frame = std::get_if<StreamFrame>(&frame);
        if (stream_frame != nullptr) {
            const bool allow_preconnected_stream_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_stream_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(stream_frame_type_for(*stream_frame)));
            }
            if (stream_frame->has_offset && !stream_frame->offset.has_value()) {
                return CodecResult<bool>::failure(frame_encoding_error(kFrameTypeStreamBase));
            }
            const auto stream_offset = stream_frame->offset.value_or(0);

            auto stream = get_or_open_receive_stream(stream_frame->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), stream_frame_type_for(*stream_frame)));
            }
            auto *stream_state = stream.value();
            if (stream_state->peer_reset_received) {
                continue;
            }

            const auto previous_highest_offset = stream_state->highest_received_offset;
            auto validated = stream_state->validate_receive_range(
                stream_offset, stream_frame->stream_data.size(), stream_frame->fin);
            if (!validated.has_value()) {
                return CodecResult<bool>::failure(stream_state_codec_error(
                    validated.error(), stream_frame_type_for(*stream_frame)));
            }
            const auto received_delta =
                stream_state->highest_received_offset - previous_highest_offset;
            if (connection_flow_control_.received_committed >
                    connection_flow_control_.advertised_max_data ||
                received_delta > connection_flow_control_.advertised_max_data -
                                     connection_flow_control_.received_committed) {
                return CodecResult<bool>::failure(
                    flow_control_error(stream_frame_type_for(*stream_frame)));
            }
            connection_flow_control_.received_committed += received_delta;

            auto owned_contiguous_bytes =
                stream_state->receive_buffer.push(stream_offset, stream_frame->stream_data);
            if (!owned_contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(owned_contiguous_bytes.error().code,
                                                  owned_contiguous_bytes.error().offset);
            }
            if (stream_frame->stream_id == 0 &&
                packet_trace_matches_connection(config_.source_connection_id)) {
                std::cerr << "quic-packet-trace stream scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " offset=" << stream_offset
                          << " len=" << stream_frame->stream_data.size()
                          << " fin=" << stream_frame->fin
                          << " contiguous=" << owned_contiguous_bytes.value().size()
                          << " highest=" << stream_state->highest_received_offset << '\n';
            }

            const auto contiguous_size = owned_contiguous_bytes.value().size();
            stream_state->receive_flow_control_consumed +=
                static_cast<std::uint64_t>(contiguous_size);
            auto fin_ready =
                stream_state->peer_final_size.has_value() &&
                stream_state->receive_flow_control_consumed == *stream_state->peer_final_size &&
                !stream_state->peer_fin_delivered;
            if (contiguous_size != 0 || fin_ready) {
                pending_stream_receive_effects_.push_back(QuicCoreReceiveStreamData{
                    .stream_id = stream_frame->stream_id,
                    .bytes = owned_contiguous_bytes.value(),
                    .fin = fin_ready,
                });
                stream_state->flow_control.delivered_bytes +=
                    static_cast<std::uint64_t>(owned_contiguous_bytes.value().size());
                connection_flow_control_.delivered_bytes +=
                    static_cast<std::uint64_t>(owned_contiguous_bytes.value().size());
                if (fin_ready) {
                    stream_state->peer_fin_delivered = true;
                }
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/false);
                maybe_refresh_connection_receive_credit(/*force=*/false);
                maybe_refresh_peer_stream_limit(*stream_state);
                maybe_retire_stream(stream_frame->stream_id);
            }
            continue;
        }

        if (const auto *datagram_frame = std::get_if<DatagramFrame>(&frame)) {
            const bool allow_preconnected_datagram_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected && !allow_preconnected_datagram_frame, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(datagram_frame_type_for(*datagram_frame)));
            }
            if (local_transport_parameters_.max_datagram_frame_size == 0 ||
                datagram_frame_wire_size(datagram_frame->data.size(), datagram_frame->has_length) >
                    local_transport_parameters_.max_datagram_frame_size) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(datagram_frame_type_for(*datagram_frame)));
            }
            pending_datagram_receive_effects_.push_back(QuicCoreReceiveDatagramData{
                .bytes = datagram_frame->data,
            });
            continue;
        }

        if (const auto *reset_stream = std::get_if<ResetStreamFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeResetStream));
            }

            auto stream = get_or_open_receive_stream(reset_stream->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeResetStream));
            }
            auto *stream_state = stream.value();
            const auto noted = stream_state->note_peer_reset(*reset_stream);
            if (!noted.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(noted.error(), kFrameTypeResetStream));
            }

            pending_peer_reset_effects_.push_back(QuicCorePeerResetStream{
                .stream_id = reset_stream->stream_id,
                .application_error_code = reset_stream->application_protocol_error_code,
                .final_size = reset_stream->final_size,
            });
            maybe_refresh_peer_stream_limit(*stream_state);
            maybe_retire_stream(reset_stream->stream_id);
            continue;
        }

        if (const auto *stop_sending = std::get_if<StopSendingFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeStopSending));
            }

            auto stream = get_or_open_send_stream_for_peer_stop(stop_sending->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeStopSending));
            }
            auto *stream_state = stream.value();
            const auto previous_fresh_sendable_bytes =
                fresh_sendable_bytes_for_cache(*stream_state);
            const auto previous_has_lost_send_data =
                stream_state->reset_state == StreamControlFrameState::none &&
                stream_state->send_buffer.has_lost_data();
            static_cast<void>(stream_state->note_peer_stop_sending(
                stop_sending->application_protocol_error_code));
            note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                           previous_has_lost_send_data, *stream_state);

            pending_peer_stop_effects_.push_back(QuicCorePeerStopSending{
                .stream_id = stop_sending->stream_id,
                .application_error_code = stop_sending->application_protocol_error_code,
            });
            continue;
        }

        if (const auto *max_data = std::get_if<MaxDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_max_data_frame, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeMaxData));
            }

            connection_flow_control_.note_peer_max_data(max_data->maximum_data);
            if (cached_total_queued_stream_bytes() <= connection_flow_control_.peer_max_data) {
                connection_flow_control_.pending_data_blocked_frame = std::nullopt;
                connection_flow_control_.data_blocked_state = StreamControlFrameState::none;
            }
            continue;
        }

        if (const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypeMaxStreamData));
            }

            auto stream = get_or_open_send_stream(max_stream_data->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeMaxStreamData));
            }
            auto *stream_state = stream.value();
            const auto previous_fresh_sendable_bytes =
                fresh_sendable_bytes_for_cache(*stream_state);
            const auto previous_has_lost_send_data =
                stream_state->reset_state == StreamControlFrameState::none &&
                stream_state->send_buffer.has_lost_data();
            stream_state->note_peer_max_stream_data(max_stream_data->maximum_stream_data);
            note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                           previous_has_lost_send_data, *stream_state);
            continue;
        }

        if (const auto *max_streams = std::get_if<MaxStreamsFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(frame_type_for_max_streams(max_streams->stream_type)));
            }

            stream_open_limits_.note_peer_max_streams(max_streams->stream_type,
                                                      max_streams->maximum_streams);
            continue;
        }

        if (const auto *data_blocked = std::get_if<DataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeDataBlocked));
            }

            maybe_refresh_connection_credit_for_data_blocked(
                *data_blocked, connection_flow_control_,
                [&] { maybe_refresh_connection_receive_credit(/*force=*/true); });
            continue;
        }

        if (const auto *stream_data_blocked = std::get_if<StreamDataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypeStreamDataBlocked));
            }

            auto stream = get_or_open_receive_stream(stream_data_blocked->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeStreamDataBlocked));
            }

            auto *stream_state = stream.value();
            maybe_refresh_stream_credit_for_data_blocked(*stream_data_blocked, *stream_state, [&] {
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/true);
            });
            continue;
        }

        if (std::holds_alternative<StreamsBlockedFrame>(frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                const auto &streams_blocked = std::get<StreamsBlockedFrame>(frame);
                return CodecResult<bool>::failure(protocol_violation_error(
                    frame_type_for_streams_blocked(streams_blocked.stream_type)));
            }
            continue;
        }

        if (const auto *new_connection_id = std::get_if<NewConnectionIdFrame>(&frame)) {
            const auto stored = process_new_connection_id_frame(*new_connection_id);
            if (!stored.has_value()) {
                return CodecResult<bool>::failure(stored.error());
            }
            continue;
        }

        if (const auto *path_challenge = std::get_if<PathChallengeFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypePathChallenge));
            }

            respond_to_path_challenge(path_id, path_challenge->data);
            continue;
        }

        if (const auto *path_response = std::get_if<PathResponseFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypePathResponse));
            }

            auto matching_path = std::find_if(paths_.begin(), paths_.end(), [&](const auto &entry) {
                return entry.second.outstanding_challenge.has_value() &&
                       entry.second.outstanding_challenge.value() == path_response->data;
            });
            auto *path = matching_path != paths_.end() ? &matching_path->second
                                                       : &ensure_path_state(path_id);
            const auto validated_path_id =
                matching_path != paths_.end() ? matching_path->first : path_id;
            const bool had_outstanding_challenge = path->outstanding_challenge.has_value();
            const bool matched_outstanding_challenge =
                had_outstanding_challenge &&
                path->outstanding_challenge.value() == path_response->data;
            if (matched_outstanding_challenge) {
                path->validated = true;
                path->challenge_pending = false;
                path->validation_initiated_locally = false;
                path->outstanding_challenge.reset();
                path->validation_deadline.reset();
                last_validated_path_id_ = validated_path_id;
                if (current_send_path_id_ != validated_path_id) {
                    maybe_switch_to_path(validated_path_id, /*initiated_locally=*/false, now);
                }
                if (current_send_path_id_ == validated_path_id && previous_path_id_.has_value()) {
                    retire_peer_connection_id_for_inactive_path(*previous_path_id_,
                                                                validated_path_id);
                }
            }
            if (traces_this_packet) {
                std::cerr << "quic-packet-trace path-response scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " path=" << path_id << " validated_path=" << validated_path_id
                          << " had_outstanding=" << static_cast<int>(had_outstanding_challenge)
                          << " matched=" << static_cast<int>(matched_outstanding_challenge)
                          << " current=" << format_optional_path_id(current_send_path_id_)
                          << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                          << " path_state={" << format_path_state_summary(path) << "}\n";
            }
            continue;
        }

        if (const auto *new_token = std::get_if<NewTokenFrame>(&frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(
                    frame_not_allowed_protocol_violation_error(kFrameTypeNewToken));
            }
            pending_received_new_tokens_.push_back(new_token->token);
            continue;
        }

        const bool has_transport_close =
            std::holds_alternative<TransportConnectionCloseFrame>(frame);
        bool has_application_close = std::holds_alternative<ApplicationConnectionCloseFrame>(frame);
        if (has_transport_close | has_application_close) {
            enter_draining_state(now);
            continue;
        }

        if (std::holds_alternative<HandshakeDoneFrame>(frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(
                    frame_not_allowed_protocol_violation_error(kFrameTypeHandshakeDone));
            }
            confirm_handshake();
            continue;
        }

        const auto &retire_connection_id = std::get<RetireConnectionIdFrame>(frame);
        auto retired = process_retire_connection_id_frame(retire_connection_id);
        if (!retired.has_value()) {
            return CodecResult<bool>::failure(retired.error());
        }
        continue;
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_received_application(
    std::span<const ReceivedFrame> frames, QuicCoreTimePoint now, bool allow_preconnected_frames,
    QuicPathId path_id, bool used_previous_application_read_secret,
    std::optional<std::uint64_t> packet_number) {
    static_assert(std::variant_size_v<ReceivedFrame> == 22,
                  "Update process_inbound_received_application when ReceivedFrame changes");
    const bool require_connected = !allow_preconnected_frames;
    const bool allow_preconnected_max_data_frame =
        application_space_.read_secret.has_value() && status_ == HandshakeStatus::in_progress;
    const bool traces_this_packet = packet_trace_matches_connection(config_.source_connection_id);
    const bool has_ack_frame = std::ranges::any_of(frames, [](const ReceivedFrame &frame) {
        return std::holds_alternative<ReceivedAckFrame>(frame);
    });
    const bool has_path_challenge_frame =
        std::ranges::any_of(frames, [](const ReceivedFrame &frame) {
            return std::holds_alternative<PathChallengeFrame>(frame);
        });
    const bool has_path_response_frame =
        std::ranges::any_of(frames, [](const ReceivedFrame &frame) {
            return std::holds_alternative<PathResponseFrame>(frame);
        });
    const bool probing_only = is_probing_only_frames(frames);
    if (traces_this_packet & (has_ack_frame | has_path_challenge_frame | has_path_response_frame)) {
        std::cerr << "quic-packet-trace recv-app scid="
                  << format_connection_id_hex(config_.source_connection_id) << " path=" << path_id
                  << " frames_ack=" << static_cast<int>(has_ack_frame)
                  << " frames_path_challenge=" << static_cast<int>(has_path_challenge_frame)
                  << " frames_path_response=" << static_cast<int>(has_path_response_frame)
                  << " probing_only=" << static_cast<int>(probing_only)
                  << " current=" << format_optional_path_id(current_send_path_id_)
                  << " previous=" << format_optional_path_id(previous_path_id_)
                  << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                  << " inbound_path={"
                  << format_path_state_summary(find_path_state(paths_, path_id))
                  << "} current_path={"
                  << format_path_state_summary(find_path_state(paths_, current_send_path_id_))
                  << "} probe="
                  << static_cast<int>(application_space_.pending_probe_packet.has_value())
                  << " rempto=" << static_cast<unsigned>(remaining_pto_probe_datagrams_)
                  << " pto_count=" << pto_count_
                  << " cwnd=" << congestion_controller_.congestion_window()
                  << " bif=" << congestion_controller_.bytes_in_flight() << '\n';
    }
    if (path_id != current_send_path_id_.value_or(path_id) && !probing_only &&
        !should_keep_current_send_path_for_inbound_non_probing(path_id, packet_number)) {
        maybe_switch_to_path(path_id, /*initiated_locally=*/false, now);
    }
    if (!paths_.empty() | (path_id != 0) | current_send_path_id_.has_value()) {
        ensure_path_state(path_id);
    }
    if (packet_number.has_value()) {
        note_inbound_application_packet_for_path(path_id, *packet_number);
    }
    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<ReceivedAckFrame>(&frame)) {
            const auto ack_delay_exponent = peer_transport_parameters_.has_value()
                                                ? peer_transport_parameters_->ack_delay_exponent
                                                : TransportParameters{}.ack_delay_exponent;
            const auto max_ack_delay_ms = peer_transport_parameters_.has_value()
                                              ? peer_transport_parameters_->max_ack_delay
                                              : TransportParameters{}.max_ack_delay;
            const auto processed_ack = process_inbound_ack(
                application_space_, *ack_frame, now, ack_delay_exponent, max_ack_delay_ms,
                /*suppress_pto_reset=*/false, used_previous_application_read_secret);
            if (!processed_ack.has_value()) {
                return processed_ack;
            }
            continue;
        }

        if (std::holds_alternative<PingFrame>(frame)) {
            const bool allow_preconnected_ping_frame = application_space_.read_secret.has_value() &&
                                                       status_ == HandshakeStatus::in_progress;
            if (require_connected && !allow_preconnected_ping_frame &&
                status_ != HandshakeStatus::connected) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypePing));
            }
            continue;
        }

        if (const auto *crypto_frame = std::get_if<ReceivedCryptoFrame>(&frame)) {
            const auto contiguous_bytes = application_space_.receive_crypto.push_shared(
                crypto_frame->offset, crypto_frame->crypto_data);
            if (!contiguous_bytes.has_value()) {
                return CodecResult<bool>::failure(contiguous_bytes.error());
            }
            if (contiguous_bytes.value().empty()) {
                continue;
            }
            if (status_ == HandshakeStatus::connected && !tls_.has_value()) {
                continue;
            }

            if (!tls_.has_value()) {
                return CodecResult<bool>::failure(CodecErrorCode::invalid_packet_protection_state,
                                                  0);
            }

            const auto provided =
                tls_->provide(EncryptionLevel::application, contiguous_bytes.value().span());
            if (!provided.has_value()) {
                return provided;
            }

            install_available_secrets();
            collect_pending_tls_bytes();
            continue;
        }

        const auto *stream_frame = std::get_if<ReceivedStreamFrame>(&frame);
        if (stream_frame != nullptr) {
            const auto processed =
                process_inbound_received_application_stream(*stream_frame, require_connected);
            if (!processed.has_value()) {
                return processed;
            }
            continue;
        }

        if (const auto *datagram_frame = std::get_if<ReceivedDatagramFrame>(&frame)) {
            const bool allow_preconnected_datagram_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected && !allow_preconnected_datagram_frame, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(datagram_frame_type_for(*datagram_frame)));
            }
            if (local_transport_parameters_.max_datagram_frame_size == 0 ||
                datagram_frame_wire_size(datagram_frame->data.size(), datagram_frame->has_length) >
                    local_transport_parameters_.max_datagram_frame_size) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(datagram_frame_type_for(*datagram_frame)));
            }
            pending_datagram_receive_effects_.push_back(QuicCoreReceiveDatagramData{
                .shared_bytes = datagram_frame->data,
            });
            continue;
        }

        if (const auto *reset_stream = std::get_if<ResetStreamFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeResetStream));
            }

            auto stream = get_or_open_receive_stream(reset_stream->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeResetStream));
            }
            auto *stream_state = stream.value();
            const auto noted = stream_state->note_peer_reset(*reset_stream);
            if (!noted.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(noted.error(), kFrameTypeResetStream));
            }

            pending_peer_reset_effects_.push_back(QuicCorePeerResetStream{
                .stream_id = reset_stream->stream_id,
                .application_error_code = reset_stream->application_protocol_error_code,
                .final_size = reset_stream->final_size,
            });
            maybe_refresh_peer_stream_limit(*stream_state);
            maybe_retire_stream(reset_stream->stream_id);
            continue;
        }

        if (const auto *stop_sending = std::get_if<StopSendingFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeStopSending));
            }

            auto stream = get_or_open_send_stream_for_peer_stop(stop_sending->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeStopSending));
            }
            auto *stream_state = stream.value();
            const auto previous_fresh_sendable_bytes =
                fresh_sendable_bytes_for_cache(*stream_state);
            const auto previous_has_lost_send_data =
                stream_state->reset_state == StreamControlFrameState::none &&
                stream_state->send_buffer.has_lost_data();
            static_cast<void>(stream_state->note_peer_stop_sending(
                stop_sending->application_protocol_error_code));
            note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                           previous_has_lost_send_data, *stream_state);

            pending_peer_stop_effects_.push_back(QuicCorePeerStopSending{
                .stream_id = stop_sending->stream_id,
                .application_error_code = stop_sending->application_protocol_error_code,
            });
            continue;
        }

        if (const auto *max_data = std::get_if<MaxDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_max_data_frame, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeMaxData));
            }

            connection_flow_control_.note_peer_max_data(max_data->maximum_data);
            if (cached_total_queued_stream_bytes() <= connection_flow_control_.peer_max_data) {
                connection_flow_control_.pending_data_blocked_frame = std::nullopt;
                connection_flow_control_.data_blocked_state = StreamControlFrameState::none;
            }
            continue;
        }

        if (const auto *max_stream_data = std::get_if<MaxStreamDataFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypeMaxStreamData));
            }

            auto stream = get_or_open_send_stream(max_stream_data->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeMaxStreamData));
            }
            auto *stream_state = stream.value();
            const auto previous_fresh_sendable_bytes =
                fresh_sendable_bytes_for_cache(*stream_state);
            const auto previous_has_lost_send_data =
                stream_state->reset_state == StreamControlFrameState::none &&
                stream_state->send_buffer.has_lost_data();
            stream_state->note_peer_max_stream_data(max_stream_data->maximum_stream_data);
            note_stream_send_state_changed(previous_fresh_sendable_bytes,
                                           previous_has_lost_send_data, *stream_state);
            continue;
        }

        if (const auto *max_streams = std::get_if<MaxStreamsFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(frame_type_for_max_streams(max_streams->stream_type)));
            }

            stream_open_limits_.note_peer_max_streams(max_streams->stream_type,
                                                      max_streams->maximum_streams);
            continue;
        }

        if (const auto *data_blocked = std::get_if<DataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypeDataBlocked));
            }

            maybe_refresh_connection_credit_for_data_blocked(
                *data_blocked, connection_flow_control_,
                [&] { maybe_refresh_connection_receive_credit(/*force=*/true); });
            continue;
        }

        if (const auto *stream_data_blocked = std::get_if<StreamDataBlockedFrame>(&frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypeStreamDataBlocked));
            }

            auto stream = get_or_open_receive_stream(stream_data_blocked->stream_id);
            if (!stream.has_value()) {
                return CodecResult<bool>::failure(
                    stream_state_codec_error(stream.error(), kFrameTypeStreamDataBlocked));
            }

            auto *stream_state = stream.value();
            maybe_refresh_stream_credit_for_data_blocked(*stream_data_blocked, *stream_state, [&] {
                maybe_refresh_stream_receive_credit(*stream_state, /*force=*/true);
            });
            continue;
        }

        if (std::holds_alternative<StreamsBlockedFrame>(frame)) {
            if (application_frame_requires_connected_state(require_connected, status_)) {
                const auto &streams_blocked = std::get<StreamsBlockedFrame>(frame);
                return CodecResult<bool>::failure(protocol_violation_error(
                    frame_type_for_streams_blocked(streams_blocked.stream_type)));
            }
            continue;
        }

        if (const auto *new_connection_id = std::get_if<NewConnectionIdFrame>(&frame)) {
            const auto stored = process_new_connection_id_frame(*new_connection_id);
            if (!stored.has_value()) {
                return CodecResult<bool>::failure(stored.error());
            }
            continue;
        }

        if (const auto *path_challenge = std::get_if<PathChallengeFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(
                    protocol_violation_error(kFrameTypePathChallenge));
            }

            respond_to_path_challenge(path_id, path_challenge->data);
            continue;
        }

        if (const auto *path_response = std::get_if<PathResponseFrame>(&frame)) {
            const bool allow_preconnected_path_validation_frame =
                application_space_.read_secret.has_value() &&
                status_ == HandshakeStatus::in_progress;
            if (application_frame_requires_connected_state(
                    require_connected & !allow_preconnected_path_validation_frame, status_)) {
                return CodecResult<bool>::failure(protocol_violation_error(kFrameTypePathResponse));
            }

            auto matching_path = std::find_if(paths_.begin(), paths_.end(), [&](const auto &entry) {
                return entry.second.outstanding_challenge.has_value() &&
                       entry.second.outstanding_challenge.value() == path_response->data;
            });
            auto *path = matching_path != paths_.end() ? &matching_path->second
                                                       : &ensure_path_state(path_id);
            const auto validated_path_id =
                matching_path != paths_.end() ? matching_path->first : path_id;
            const bool had_outstanding_challenge = path->outstanding_challenge.has_value();
            const bool matched_outstanding_challenge =
                had_outstanding_challenge &&
                path->outstanding_challenge.value() == path_response->data;
            if (matched_outstanding_challenge) {
                path->validated = true;
                path->challenge_pending = false;
                path->validation_initiated_locally = false;
                path->outstanding_challenge.reset();
                path->validation_deadline.reset();
                last_validated_path_id_ = validated_path_id;
                if (current_send_path_id_ != validated_path_id) {
                    maybe_switch_to_path(validated_path_id, /*initiated_locally=*/false, now);
                } else if (previous_path_id_.has_value()) {
                    retire_peer_connection_id_for_inactive_path(*previous_path_id_,
                                                                validated_path_id);
                }
            }
            if (traces_this_packet) {
                std::cerr << "quic-packet-trace path-response scid="
                          << format_connection_id_hex(config_.source_connection_id)
                          << " path=" << path_id << " validated_path=" << validated_path_id
                          << " had_outstanding=" << static_cast<int>(had_outstanding_challenge)
                          << " matched=" << static_cast<int>(matched_outstanding_challenge)
                          << " current=" << format_optional_path_id(current_send_path_id_)
                          << " last_validated=" << format_optional_path_id(last_validated_path_id_)
                          << " path_state={" << format_path_state_summary(path) << "}\n";
            }
            continue;
        }

        if (const auto *new_token = std::get_if<NewTokenFrame>(&frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(
                    frame_not_allowed_protocol_violation_error(kFrameTypeNewToken));
            }
            pending_received_new_tokens_.push_back(new_token->token);
            continue;
        }

        const bool has_transport_close =
            std::holds_alternative<TransportConnectionCloseFrame>(frame);
        bool has_application_close = std::holds_alternative<ApplicationConnectionCloseFrame>(frame);
        if (has_transport_close | has_application_close) {
            enter_draining_state(now);
            continue;
        }

        if (std::holds_alternative<HandshakeDoneFrame>(frame)) {
            if (config_.role == EndpointRole::server) {
                return CodecResult<bool>::failure(
                    frame_not_allowed_protocol_violation_error(kFrameTypeHandshakeDone));
            }
            confirm_handshake();
            continue;
        }

        const auto &retire_connection_id = std::get<RetireConnectionIdFrame>(frame);
        auto retired = process_retire_connection_id_frame(retire_connection_id);
        if (!retired.has_value()) {
            return CodecResult<bool>::failure(retired.error());
        }
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool>
QuicConnection::process_inbound_received_application_stream(const ReceivedStreamFrame &stream_frame,
                                                            bool require_connected) {
    const bool allow_preconnected_stream_frame =
        application_space_.read_secret.has_value() && status_ == HandshakeStatus::in_progress;
    if (application_frame_requires_connected_state(
            require_connected && !allow_preconnected_stream_frame, status_)) {
        return CodecResult<bool>::failure(
            protocol_violation_error(stream_frame_type_for(stream_frame)));
    }
    if (stream_frame.has_offset && !stream_frame.offset.has_value()) {
        return CodecResult<bool>::failure(frame_encoding_error(kFrameTypeStreamBase));
    }
    const auto stream_offset = stream_frame.offset.value_or(0);

    auto stream = get_or_open_receive_stream(stream_frame.stream_id);
    if (!stream.has_value()) {
        return CodecResult<bool>::failure(
            stream_state_codec_error(stream.error(), stream_frame_type_for(stream_frame)));
    }
    auto *stream_state = stream.value();
    if (stream_state->peer_reset_received) {
        return CodecResult<bool>::success(true);
    }

    const auto previous_highest_offset = stream_state->highest_received_offset;
    auto validated = stream_state->validate_receive_range(
        stream_offset, stream_frame.stream_data.size(), stream_frame.fin);
    if (!validated.has_value()) {
        return CodecResult<bool>::failure(
            stream_state_codec_error(validated.error(), stream_frame_type_for(stream_frame)));
    }
    const auto received_delta = stream_state->highest_received_offset - previous_highest_offset;
    if (connection_flow_control_.received_committed >
            connection_flow_control_.advertised_max_data ||
        received_delta > connection_flow_control_.advertised_max_data -
                             connection_flow_control_.received_committed) {
        return CodecResult<bool>::failure(flow_control_error(stream_frame_type_for(stream_frame)));
    }
    connection_flow_control_.received_committed += received_delta;

    auto shared_contiguous_bytes =
        stream_state->receive_buffer.push_shared(stream_offset, stream_frame.stream_data);
    if (!shared_contiguous_bytes.has_value()) {
        return CodecResult<bool>::failure(shared_contiguous_bytes.error().code,
                                          shared_contiguous_bytes.error().offset);
    }
    const auto contiguous_size = shared_contiguous_bytes.value().span().size();
    if (stream_frame.stream_id == 0 &&
        packet_trace_matches_connection(config_.source_connection_id)) {
        std::cerr << "quic-packet-trace stream scid="
                  << format_connection_id_hex(config_.source_connection_id)
                  << " offset=" << stream_offset << " len=" << stream_frame.stream_data.size()
                  << " fin=" << stream_frame.fin << " contiguous=" << contiguous_size
                  << " highest=" << stream_state->highest_received_offset << '\n';
    }

    stream_state->receive_flow_control_consumed += static_cast<std::uint64_t>(contiguous_size);
    auto fin_ready =
        stream_state->peer_final_size.has_value() &&
        stream_state->receive_flow_control_consumed == *stream_state->peer_final_size &&
        !stream_state->peer_fin_delivered;
    if (contiguous_size != 0 || fin_ready) {
        QuicCoreReceiveStreamData receive{
            .stream_id = stream_frame.stream_id,
            .fin = fin_ready,
        };
        if (config_.emit_shared_receive_stream_data &&
            shared_contiguous_bytes.value().owned.empty()) {
            receive.shared_bytes = std::move(shared_contiguous_bytes.value().shared);
        } else {
            receive.bytes = shared_contiguous_bytes.value().to_vector();
        }
        pending_stream_receive_effects_.push_back(std::move(receive));
        stream_state->flow_control.delivered_bytes += static_cast<std::uint64_t>(contiguous_size);
        connection_flow_control_.delivered_bytes += static_cast<std::uint64_t>(contiguous_size);
        if (fin_ready) {
            stream_state->peer_fin_delivered = true;
        }
        maybe_refresh_stream_receive_credit(*stream_state, /*force=*/false);
        maybe_refresh_connection_receive_credit(/*force=*/false);
        maybe_refresh_peer_stream_limit(*stream_state);
        maybe_retire_stream(stream_frame.stream_id);
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_received_application_stream_packet(
    std::uint64_t packet_number, bool spin_bit, const ReceivedStreamFrame &stream_frame,
    QuicCoreTimePoint now, QuicEcnCodepoint ecn) {
    if (last_inbound_path_id_ != current_send_path_id_.value_or(last_inbound_path_id_) &&
        !should_keep_current_send_path_for_inbound_non_probing(last_inbound_path_id_,
                                                               packet_number)) {
        maybe_switch_to_path(last_inbound_path_id_, /*initiated_locally=*/false, now);
    }
    if (!paths_.empty() | (last_inbound_path_id_ != 0) | current_send_path_id_.has_value()) {
        ensure_path_state(last_inbound_path_id_);
    }
    note_inbound_application_packet_for_path(last_inbound_path_id_, packet_number);

    const auto processed =
        process_inbound_received_application_stream(stream_frame, /*require_connected=*/true);
    if (processed.has_value()) {
        processed_peer_packet_ = true;
        if (config_.role == EndpointRole::server && status_ != HandshakeStatus::connected) {
            mark_peer_address_validated();
        }
        application_space_.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true, now, ecn,
            config_.transport.ack_eliciting_threshold);
        note_idle_peer_activity(now);
        schedule_application_ack_deadline(application_space_, now,
                                          local_transport_parameters_.max_ack_delay, ecn);
        if (zero_rtt_space_.read_secret.has_value() || zero_rtt_space_.write_secret.has_value()) {
            if (config_.role == EndpointRole::server && zero_rtt_space_.read_secret.has_value()) {
                arm_server_zero_rtt_discard_deadline(now);
            } else {
                discard_packet_space_state(zero_rtt_space_);
            }
        }
        update_spin_bit_on_receive(last_inbound_path_id_, spin_bit, packet_number);
    }
    return processed;
}

CodecResult<bool> QuicConnection::process_inbound_received_application_ack_only(
    std::uint64_t packet_number, bool spin_bit, const ReceivedAckFrame &ack, QuicCoreTimePoint now,
    QuicEcnCodepoint ecn, QuicPathId path_id, bool used_previous_application_read_secret) {
    if (path_id != current_send_path_id_.value_or(path_id) &&
        !should_keep_current_send_path_for_inbound_non_probing(path_id, packet_number)) {
        maybe_switch_to_path(path_id, /*initiated_locally=*/false, now);
    }
    if (!paths_.empty() | (path_id != 0) | current_send_path_id_.has_value()) {
        ensure_path_state(path_id);
    }
    note_inbound_application_packet_for_path(path_id, packet_number);

    const auto ack_delay_exponent = peer_transport_parameters_.has_value()
                                        ? peer_transport_parameters_->ack_delay_exponent
                                        : TransportParameters{}.ack_delay_exponent;
    const auto max_ack_delay_ms = peer_transport_parameters_.has_value()
                                      ? peer_transport_parameters_->max_ack_delay
                                      : TransportParameters{}.max_ack_delay;
    const auto processed_ack =
        process_inbound_ack(application_space_, ack, now, ack_delay_exponent, max_ack_delay_ms,
                            /*suppress_pto_reset=*/false, used_previous_application_read_secret);
    if (!processed_ack.has_value()) {
        return processed_ack;
    }

    processed_peer_packet_ = true;
    if (config_.role == EndpointRole::server && status_ != HandshakeStatus::connected) {
        mark_peer_address_validated();
    }
    application_space_.received_packets.record_received(packet_number, /*ack_eliciting=*/false, now,
                                                        ecn,
                                                        config_.transport.ack_eliciting_threshold);
    note_idle_peer_activity(now);
    if (zero_rtt_space_.read_secret.has_value() || zero_rtt_space_.write_secret.has_value()) {
        if (config_.role == EndpointRole::server && zero_rtt_space_.read_secret.has_value()) {
            arm_server_zero_rtt_discard_deadline(now);
        } else {
            discard_packet_space_state(zero_rtt_space_);
        }
    }
    update_spin_bit_on_receive(path_id, spin_bit, packet_number);
    return CodecResult<bool>::success(true);
}

} // namespace coquic::quic
