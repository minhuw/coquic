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
constexpr std::uint32_t kQuicVersion1 = 1;
constexpr std::uint8_t kDefaultInitialPacketNumberLength = 2;

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

} // namespace

QuicConnection::QuicConnection(QuicCoreConfig config) : config_(std::move(config)) {
}

std::vector<std::byte> QuicConnection::receive(std::span<const std::byte> bytes) {
    if (status_ == HandshakeStatus::failed) {
        return {};
    }

    if (bytes.empty()) {
        start_client_if_needed();
        return flush_outbound_datagram();
    }

    if (!started_) {
        if (config_.role != EndpointRole::server) {
            status_ = HandshakeStatus::failed;
            return {};
        }

        const auto initial_destination_connection_id =
            peek_client_initial_destination_connection_id(bytes);
        if (!initial_destination_connection_id.has_value()) {
            status_ = HandshakeStatus::failed;
            return {};
        }

        start_server_if_needed(initial_destination_connection_id.value());
    }

    const auto packets = deserialize_protected_datagram(
        bytes,
        DeserializeProtectionContext{
            .peer_role = opposite_role(config_.role),
            .client_initial_destination_connection_id = client_initial_destination_connection_id(),
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
        status_ = HandshakeStatus::failed;
        return {};
    }

    for (const auto &packet : packets.value()) {
        if (!process_inbound_packet(packet).has_value()) {
            status_ = HandshakeStatus::failed;
            return {};
        }
    }

    if (tls_.has_value()) {
        tls_->poll();
        install_available_secrets();
        collect_pending_tls_bytes();
    }

    return flush_outbound_datagram();
}

bool QuicConnection::is_handshake_complete() const {
    return status_ == HandshakeStatus::connected;
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
        status_ = HandshakeStatus::failed;
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
        status_ = HandshakeStatus::failed;
        return;
    }

    install_available_secrets();
    collect_pending_tls_bytes();
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
        status_ = HandshakeStatus::failed;
        return;
    }

    tls_.emplace(TlsAdapterConfig{
        .role = config_.role,
        .verify_peer = config_.verify_peer,
        .server_name = config_.server_name,
        .identity = config_.identity,
        .local_transport_parameters = serialized_transport_parameters.value(),
    });
    install_available_secrets();
    collect_pending_tls_bytes();
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

CodecResult<bool> QuicConnection::process_inbound_packet(const ProtectedPacket &packet) {
    if (const auto *initial = std::get_if<ProtectedInitialPacket>(&packet)) {
        peer_source_connection_id_ = initial->source_connection_id;
        initial_space_.largest_authenticated_packet_number = initial->packet_number;
        return process_inbound_crypto(EncryptionLevel::initial, initial->frames);
    }
    if (const auto *handshake = std::get_if<ProtectedHandshakePacket>(&packet)) {
        peer_source_connection_id_ = handshake->source_connection_id;
        handshake_space_.largest_authenticated_packet_number = handshake->packet_number;
        return process_inbound_crypto(EncryptionLevel::handshake, handshake->frames);
    }
    if (const auto *application = std::get_if<ProtectedOneRttPacket>(&packet)) {
        application_space_.largest_authenticated_packet_number = application->packet_number;
        return process_inbound_crypto(EncryptionLevel::application, application->frames);
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

    const auto initial_crypto_frames =
        initial_space_.send_crypto.take_frames(std::numeric_limits<std::size_t>::max());
    if (!initial_crypto_frames.empty()) {
        std::vector<Frame> frames;
        frames.reserve(initial_crypto_frames.size());
        for (const auto &crypto_frame : initial_crypto_frames) {
            frames.emplace_back(crypto_frame);
        }

        packets.emplace_back(ProtectedInitialPacket{
            .version = kQuicVersion1,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .token = {},
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = initial_space_.next_send_packet_number++,
            .frames = std::move(frames),
        });
    }

    const auto handshake_crypto_frames =
        handshake_space_.send_crypto.take_frames(std::numeric_limits<std::size_t>::max());
    if (!handshake_crypto_frames.empty()) {
        if (!handshake_space_.write_secret.has_value()) {
            status_ = HandshakeStatus::failed;
            return {};
        }

        std::vector<Frame> frames;
        frames.reserve(handshake_crypto_frames.size());
        for (const auto &crypto_frame : handshake_crypto_frames) {
            frames.emplace_back(crypto_frame);
        }

        packets.emplace_back(ProtectedHandshakePacket{
            .version = kQuicVersion1,
            .destination_connection_id = destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = handshake_space_.next_send_packet_number++,
            .frames = std::move(frames),
        });
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
        status_ = HandshakeStatus::failed;
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
                status_ = HandshakeStatus::failed;
                return {};
            }
            break;
        }
    }

    return datagram.value();
}

} // namespace coquic::quic
