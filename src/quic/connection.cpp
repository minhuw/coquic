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

} // namespace

QuicConnection::QuicConnection(QuicCoreConfig config) : config_(std::move(config)) {
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

void QuicConnection::queue_application_data(std::span<const std::byte> bytes) {
    if (status_ == HandshakeStatus::failed || bytes.empty()) {
        return;
    }

    pending_application_send_.append(bytes);
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
        if (pending_application_send_.has_pending_data()) {
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
        if (!packet.crypto_ranges.empty() || !packet.stream_ranges.empty() || packet.has_ping) {
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
    if (!ack_result.acked_packets.empty() && !suppress_pto_reset) {
        pto_count_ = 0;
    }

    return CodecResult<bool>::success(true);
}

void QuicConnection::track_sent_packet(PacketSpaceState &packet_space,
                                       const SentPacketRecord &packet) {
    packet_space.sent_packets[packet.packet_number] = packet;
    packet_space.recovery.on_packet_sent(packet);
}

void QuicConnection::retire_acked_packet(PacketSpaceState &packet_space,
                                         const SentPacketRecord &packet) {
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.acknowledge(range.offset, range.bytes.size());
    }
    for (const auto &range : packet.stream_ranges) {
        pending_application_send_.acknowledge(range.offset, range.bytes.size());
    }

    packet_space.sent_packets.erase(packet.packet_number);
}

void QuicConnection::mark_lost_packet(PacketSpaceState &packet_space,
                                      const SentPacketRecord &packet) {
    for (const auto &range : packet.crypto_ranges) {
        packet_space.send_crypto.mark_lost(range.offset, range.bytes.size());
    }
    for (const auto &range : packet.stream_ranges) {
        pending_application_send_.mark_lost(range.offset, range.bytes.size());
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
        (application_space_.received_packets.has_ack_to_send() ||
         pending_application_send_.has_pending_data() ||
         application_space_.pending_probe_packet.has_value())) {
        const auto base_ack_frame = application_space_.received_packets.build_ack_frame(
            local_transport_parameters_.ack_delay_exponent, now);
        const auto serialize_application_candidate =
            [&](const std::optional<AckFrame> &ack_frame, std::span<const ByteRange> stream_ranges,
                bool include_ping) -> CodecResult<std::vector<std::byte>> {
            std::vector<Frame> candidate_frames;
            if (ack_frame.has_value()) {
                candidate_frames.emplace_back(*ack_frame);
            }
            for (const auto &range : stream_ranges) {
                candidate_frames.emplace_back(StreamFrame{
                    .fin = false,
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = kApplicationStreamId,
                    .offset = range.offset,
                    .stream_data = range.bytes,
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
                std::span<const ByteRange> stream_ranges,
                bool include_ping) -> std::optional<AckFrame> {
            if (!candidate_ack_frame.has_value()) {
                return std::nullopt;
            }

            auto candidate_datagram =
                serialize_application_candidate(candidate_ack_frame, stream_ranges, include_ping);
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
                    serialize_application_candidate(trimmed_ack_frame, stream_ranges, include_ping)
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

        if (!pending_application_send_.has_pending_data() &&
            application_space_.pending_probe_packet.has_value()) {
            const auto &probe_packet = *application_space_.pending_probe_packet;
            const auto include_ping = probe_packet.stream_ranges.empty();
            auto ack_frame = trim_application_ack_frame(base_ack_frame, probe_packet.stream_ranges,
                                                        include_ping);
            if (base_ack_frame.has_value() && !ack_frame.has_value()) {
                mark_failed();
                return {};
            }

            const auto datagram = serialize_application_candidate(
                ack_frame, probe_packet.stream_ranges, include_ping);
            if (!datagram.has_value() || datagram.value().size() > kMaximumDatagramSize) {
                mark_failed();
                return {};
            }

            std::vector<Frame> frames;
            if (ack_frame.has_value()) {
                frames.emplace_back(*ack_frame);
            }
            for (const auto &range : probe_packet.stream_ranges) {
                frames.emplace_back(StreamFrame{
                    .fin = false,
                    .has_offset = true,
                    .has_length = true,
                    .stream_id = kApplicationStreamId,
                    .offset = range.offset,
                    .stream_data = range.bytes,
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

            track_sent_packet(application_space_, SentPacketRecord{
                                                      .packet_number = packet_number,
                                                      .sent_time = now,
                                                      .ack_eliciting = true,
                                                      .in_flight = true,
                                                      .declared_lost = false,
                                                      .stream_ranges = probe_packet.stream_ranges,
                                                      .has_ping = include_ping,
                                                  });
            if (application_space_.received_packets.has_ack_to_send()) {
                application_space_.received_packets.on_ack_sent();
                application_space_.pending_ack_deadline = std::nullopt;
            }
            application_space_.pending_probe_packet = std::nullopt;
        } else {
            std::size_t low = 1;
            std::size_t high = kMaximumDatagramSize;
            std::size_t best_length = 0;
            std::optional<AckFrame> best_ack_frame;

            while (low <= high) {
                const auto candidate_length = low + (high - low) / 2;
                auto candidate_send_buffer = pending_application_send_;
                const auto candidate_ranges = candidate_send_buffer.take_ranges(candidate_length);
                auto fitting_ack_frame = trim_application_ack_frame(
                    base_ack_frame, candidate_ranges, /*include_ping=*/false);
                if (base_ack_frame.has_value() && !fitting_ack_frame.has_value()) {
                    mark_failed();
                    return {};
                }

                const auto candidate_datagram = serialize_application_candidate(
                    fitting_ack_frame, candidate_ranges, /*include_ping=*/false);
                if (!candidate_datagram.has_value()) {
                    mark_failed();
                    return {};
                }

                if (candidate_datagram.value().size() <= kMaximumDatagramSize) {
                    best_length = candidate_length;
                    best_ack_frame = std::move(fitting_ack_frame);
                    low = candidate_length + 1;
                } else {
                    high = candidate_length - 1;
                }
            }

            std::vector<Frame> frames;
            if (best_ack_frame.has_value()) {
                frames.emplace_back(*best_ack_frame);
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

            const auto ack_eliciting = !stream_ranges.empty();
            track_sent_packet(application_space_, SentPacketRecord{
                                                      .packet_number = packet_number,
                                                      .sent_time = now,
                                                      .ack_eliciting = ack_eliciting,
                                                      .in_flight = ack_eliciting,
                                                      .declared_lost = false,
                                                      .stream_ranges = stream_ranges,
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
