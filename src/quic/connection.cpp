#include "src/quic/connection.h"

#include <cstddef>
#include <limits>
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
constexpr std::uint64_t kApplicationStreamId = 0;

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
    switch (level) {
    case EncryptionLevel::initial:
        return initial_space;
    case EncryptionLevel::handshake:
        return handshake_space;
    case EncryptionLevel::application:
        return application_space;
    }

    return application_space;
}

bool is_padding_frame(const Frame &frame) {
    return std::holds_alternative<PaddingFrame>(frame);
}

bool is_ack_eliciting_frame(const Frame &frame) {
    return std::holds_alternative<CryptoFrame>(frame) ||
           std::holds_alternative<StreamFrame>(frame) || std::holds_alternative<PingFrame>(frame);
}

bool has_ack_eliciting_frame(std::span<const Frame> frames) {
    for (const auto &frame : frames) {
        if (is_ack_eliciting_frame(frame)) {
            return true;
        }
    }

    return false;
}

bool ack_frame_acks_packet(const AckFrame &ack, std::uint64_t packet_number) {
    if (packet_number > ack.largest_acknowledged ||
        ack.largest_acknowledged < ack.first_ack_range) {
        return false;
    }

    auto range_largest = ack.largest_acknowledged;
    auto range_smallest = ack.largest_acknowledged - ack.first_ack_range;
    if (packet_number >= range_smallest && packet_number <= range_largest) {
        return true;
    }

    auto previous_smallest = range_smallest;
    for (const auto &range : ack.additional_ranges) {
        if (previous_smallest < range.gap + 2) {
            return false;
        }

        range_largest = previous_smallest - range.gap - 2;
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

} // namespace

QuicConnection::QuicConnection(QuicCoreConfig config) : config_(std::move(config)) {
}

void QuicConnection::start() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    start_client_if_needed();
}

void QuicConnection::process_inbound_datagram(std::span<const std::byte> bytes) {
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
        if (status_ == HandshakeStatus::failed) {
            return;
        }
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
            if (!process_inbound_packet(packet).has_value()) {
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

void QuicConnection::queue_application_data(std::span<const std::byte> bytes) {
    if (status_ == HandshakeStatus::failed || bytes.empty()) {
        return;
    }

    pending_application_send_.append(bytes);
}

std::vector<std::byte> QuicConnection::drain_outbound_datagram() {
    if (status_ == HandshakeStatus::failed) {
        return {};
    }

    return flush_outbound_datagram();
}

std::vector<std::byte> QuicConnection::take_received_application_data() {
    if (status_ == HandshakeStatus::failed) {
        return {};
    }

    auto bytes = std::move(pending_application_receive_);
    pending_application_receive_.clear();
    return bytes;
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
    return std::nullopt;
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
        .max_udp_payload_size = kMinimumInitialDatagramSize,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = config_.source_connection_id,
    };

    const auto serialized_transport_parameters =
        serialize_transport_parameters(local_transport_parameters_);
    if (!serialized_transport_parameters.has_value()) {
        mark_failed();
        return;
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
    });
    if (!tls_->start().has_value()) {
        mark_failed();
        return;
    }

    if (!sync_tls_state().has_value()) {
        mark_failed();
    }
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
        .max_udp_payload_size = kMinimumInitialDatagramSize,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = config_.source_connection_id,
    };

    const auto serialized_transport_parameters =
        serialize_transport_parameters(local_transport_parameters_);
    if (!serialized_transport_parameters.has_value()) {
        mark_failed();
        return;
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
    });
    if (!sync_tls_state().has_value()) {
        mark_failed();
    }
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
        const auto token = reader.read_exact(static_cast<std::size_t>(token_length.value().value));
        if (!token.has_value()) {
            return CodecResult<std::size_t>::failure(token.error().code, token.error().offset);
        }
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

CodecResult<bool> QuicConnection::process_inbound_packet(const ProtectedPacket &packet) {
    if (const auto *initial = std::get_if<ProtectedInitialPacket>(&packet)) {
        peer_source_connection_id_ = initial->source_connection_id;
        initial_space_.largest_authenticated_packet_number = initial->packet_number;
        const auto processed = process_inbound_crypto(EncryptionLevel::initial, initial->frames);
        if (processed.has_value()) {
            initial_space_.received_packets.record_received(
                initial->packet_number, has_ack_eliciting_frame(initial->frames),
                QuicCoreTimePoint{});
        }
        return processed;
    }
    if (const auto *handshake = std::get_if<ProtectedHandshakePacket>(&packet)) {
        peer_source_connection_id_ = handshake->source_connection_id;
        handshake_space_.largest_authenticated_packet_number = handshake->packet_number;
        const auto processed =
            process_inbound_crypto(EncryptionLevel::handshake, handshake->frames);
        if (processed.has_value()) {
            handshake_space_.received_packets.record_received(
                handshake->packet_number, has_ack_eliciting_frame(handshake->frames),
                QuicCoreTimePoint{});
        }
        return processed;
    }
    if (const auto *application = std::get_if<ProtectedOneRttPacket>(&packet)) {
        application_space_.largest_authenticated_packet_number = application->packet_number;
        const auto processed = process_inbound_application(application->frames);
        if (processed.has_value()) {
            application_space_.received_packets.record_received(
                application->packet_number, has_ack_eliciting_frame(application->frames),
                QuicCoreTimePoint{});
        }
        return processed;
    }

    return CodecResult<bool>::success(true);
}

CodecResult<bool> QuicConnection::process_inbound_crypto(EncryptionLevel level,
                                                         std::span<const Frame> frames) {
    auto &packet_space =
        packet_space_for_level(level, initial_space_, handshake_space_, application_space_);

    for (const auto &frame : frames) {
        if (is_padding_frame(frame)) {
            continue;
        }

        if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
            std::vector<std::uint64_t> acked_packet_numbers;
            for (const auto &[packet_number, sent_packet] : packet_space.sent_packets) {
                if (!ack_frame_acks_packet(*ack_frame, packet_number)) {
                    continue;
                }

                acked_packet_numbers.push_back(packet_number);
                for (const auto &range : sent_packet.crypto_ranges) {
                    packet_space.send_crypto.acknowledge(range.offset, range.bytes.size());
                }
            }

            for (const auto packet_number : acked_packet_numbers) {
                packet_space.sent_packets.erase(packet_number);
            }
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

CodecResult<bool> QuicConnection::process_inbound_application(std::span<const Frame> frames) {
    for (const auto &frame : frames) {
        if (is_padding_frame(frame) || std::holds_alternative<AckFrame>(frame)) {
            if (const auto *ack_frame = std::get_if<AckFrame>(&frame)) {
                std::vector<std::uint64_t> acked_packet_numbers;
                for (const auto &[packet_number, sent_packet] : application_space_.sent_packets) {
                    if (!ack_frame_acks_packet(*ack_frame, packet_number)) {
                        continue;
                    }

                    acked_packet_numbers.push_back(packet_number);
                    for (const auto &range : sent_packet.stream_ranges) {
                        pending_application_send_.acknowledge(range.offset, range.bytes.size());
                    }
                }

                for (const auto packet_number : acked_packet_numbers) {
                    application_space_.sent_packets.erase(packet_number);
                }
            }
            continue;
        }

        const auto *stream_frame = std::get_if<StreamFrame>(&frame);
        if (stream_frame == nullptr) {
            continue;
        }

        if (status_ != HandshakeStatus::connected) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
        }
        if (!stream_frame->has_offset || !stream_frame->offset.has_value() ||
            !stream_frame->has_length) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
        }
        if (stream_frame->stream_id != kApplicationStreamId || stream_frame->fin) {
            return CodecResult<bool>::failure(CodecErrorCode::invalid_varint, 0);
        }

        const auto contiguous_bytes = pending_application_receive_buffer_.push(
            stream_frame->offset.value(), stream_frame->stream_data);
        if (!contiguous_bytes.has_value()) {
            return CodecResult<bool>::failure(contiguous_bytes.error().code,
                                              contiguous_bytes.error().offset);
        }

        pending_application_receive_.insert(pending_application_receive_.end(),
                                            contiguous_bytes.value().begin(),
                                            contiguous_bytes.value().end());
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
    } else {
        status_ = HandshakeStatus::in_progress;
    }
}

void QuicConnection::mark_failed() {
    if (status_ == HandshakeStatus::failed) {
        return;
    }

    status_ = HandshakeStatus::failed;
    pending_application_send_ = ReliableSendBuffer{};
    pending_application_receive_buffer_ = ReliableReceiveBuffer{};
    pending_application_receive_.clear();
    pending_state_changes_.clear();
    queue_state_change(QuicCoreStateChange::failed);
}

void QuicConnection::queue_state_change(QuicCoreStateChange change) {
    if (change == QuicCoreStateChange::handshake_ready) {
        if (handshake_ready_emitted_) {
            return;
        }
        handshake_ready_emitted_ = true;
    } else if (change == QuicCoreStateChange::failed) {
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

std::vector<std::byte> QuicConnection::flush_outbound_datagram() {
    auto packets = std::vector<ProtectedPacket>{};
    const auto destination_connection_id = outbound_destination_connection_id();

    std::vector<Frame> initial_frames;
    if (const auto ack_frame =
            initial_space_.received_packets.build_ack_frame(0, QuicCoreTimePoint{})) {
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

        initial_space_.sent_packets[packet_number] = SentPacketRecord{
            .packet_number = packet_number,
            .sent_time = QuicCoreTimePoint{},
            .ack_eliciting = !initial_crypto_ranges.empty(),
            .in_flight = !initial_crypto_ranges.empty(),
            .declared_lost = false,
            .crypto_ranges = initial_crypto_ranges,
        };
        if (initial_space_.received_packets.has_ack_to_send()) {
            initial_space_.received_packets.on_ack_sent();
        }
    }

    std::vector<Frame> handshake_frames;
    if (const auto ack_frame =
            handshake_space_.received_packets.build_ack_frame(0, QuicCoreTimePoint{})) {
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

        handshake_space_.sent_packets[packet_number] = SentPacketRecord{
            .packet_number = packet_number,
            .sent_time = QuicCoreTimePoint{},
            .ack_eliciting = !handshake_crypto_ranges.empty(),
            .in_flight = !handshake_crypto_ranges.empty(),
            .declared_lost = false,
            .crypto_ranges = handshake_crypto_ranges,
        };
        if (handshake_space_.received_packets.has_ack_to_send()) {
            handshake_space_.received_packets.on_ack_sent();
        }
    }

    if (status_ == HandshakeStatus::connected && application_space_.write_secret.has_value() &&
        (application_space_.received_packets.has_ack_to_send() ||
         pending_application_send_.has_pending_data())) {
        std::size_t low = 1;
        std::size_t high = kMaximumDatagramSize;
        std::size_t best_length = 0;
        bool found_fitting_candidate = false;
        bool best_ack_only = false;

        while (low <= high) {
            const auto candidate_length = low + (high - low) / 2;
            auto candidate_send_buffer = pending_application_send_;
            const auto candidate_ranges = candidate_send_buffer.take_ranges(candidate_length);

            std::vector<Frame> candidate_frames;
            if (const auto ack_frame =
                    application_space_.received_packets.build_ack_frame(0, QuicCoreTimePoint{})) {
                candidate_frames.emplace_back(*ack_frame);
            }
            for (const auto &range : candidate_ranges) {
                candidate_frames.emplace_back(StreamFrame{
                    .fin = false,
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = kApplicationStreamId,
                    .offset = range.offset,
                    .stream_data = range.bytes,
                });
            }

            auto candidate_packets = packets;
            candidate_packets.emplace_back(ProtectedOneRttPacket{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = application_space_.next_send_packet_number,
                .frames = std::move(candidate_frames),
            });

            const auto candidate_datagram = serialize_protected_datagram(
                candidate_packets, SerializeProtectionContext{
                                       .local_role = config_.role,
                                       .client_initial_destination_connection_id =
                                           client_initial_destination_connection_id(),
                                       .handshake_secret = handshake_space_.write_secret,
                                       .one_rtt_secret = application_space_.write_secret,
                                   });
            if (!candidate_datagram.has_value()) {
                mark_failed();
                return {};
            }

            if (candidate_datagram.value().size() <= kMaximumDatagramSize) {
                found_fitting_candidate = true;
                best_length = candidate_length;
                best_ack_only = candidate_ranges.empty();
                low = candidate_length + 1;
            } else {
                high = candidate_length - 1;
            }
        }

        if (found_fitting_candidate && (best_length > 0 || best_ack_only)) {
            std::vector<Frame> frames;
            if (const auto ack_frame =
                    application_space_.received_packets.build_ack_frame(0, QuicCoreTimePoint{})) {
                frames.emplace_back(*ack_frame);
            }
            const auto stream_ranges = pending_application_send_.take_ranges(best_length);
            for (const auto &range : stream_ranges) {
                frames.emplace_back(StreamFrame{
                    .fin = false,
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = kApplicationStreamId,
                    .offset = range.offset,
                    .stream_data = range.bytes,
                });
            }

            const auto packet_number = application_space_.next_send_packet_number++;
            packets.emplace_back(ProtectedOneRttPacket{
                .destination_connection_id = destination_connection_id,
                .packet_number_length = kDefaultInitialPacketNumberLength,
                .packet_number = packet_number,
                .frames = std::move(frames),
            });

            application_space_.sent_packets[packet_number] = SentPacketRecord{
                .packet_number = packet_number,
                .sent_time = QuicCoreTimePoint{},
                .ack_eliciting = !stream_ranges.empty(),
                .in_flight = !stream_ranges.empty(),
                .declared_lost = false,
                .stream_ranges = stream_ranges,
            };
            if (application_space_.received_packets.has_ack_to_send()) {
                application_space_.received_packets.on_ack_sent();
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
