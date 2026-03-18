#include "src/quic/connection.h"

#include <cstddef>
#include <limits>
#include <utility>
#include <vector>

#include "src/quic/frame.h"
#include "src/quic/protected_codec.h"

namespace coquic::quic {

namespace {

constexpr std::size_t kMinimumInitialDatagramSize = 1200;
constexpr std::uint32_t kQuicVersion1 = 1;
constexpr std::uint8_t kDefaultInitialPacketNumberLength = 2;

} // namespace

QuicConnection::QuicConnection(QuicCoreConfig config) : config_(std::move(config)) {
}

std::vector<std::byte> QuicConnection::receive(std::span<const std::byte> bytes) {
    if (status_ == HandshakeStatus::failed) {
        return {};
    }

    if (bytes.empty()) {
        start_client_if_needed();
        return emit_initial_space();
    }

    return {};
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

    initial_space_.send_crypto.append(tls_->take_pending(EncryptionLevel::initial));
}

std::vector<std::byte> QuicConnection::emit_initial_space() {
    const auto crypto_frames =
        initial_space_.send_crypto.take_frames(std::numeric_limits<std::size_t>::max());
    if (crypto_frames.empty()) {
        return {};
    }

    std::vector<Frame> frames;
    frames.reserve(crypto_frames.size() + 1);
    for (const auto &crypto_frame : crypto_frames) {
        frames.emplace_back(crypto_frame);
    }

    auto packets = std::vector<ProtectedPacket>{
        ProtectedInitialPacket{
            .version = kQuicVersion1,
            .destination_connection_id = config_.initial_destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .token = {},
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = initial_space_.next_send_packet_number++,
            .frames = frames,
        },
    };

    const auto context = SerializeProtectionContext{
        .local_role = config_.role,
        .client_initial_destination_connection_id = config_.initial_destination_connection_id,
    };
    auto datagram = serialize_protected_datagram(packets, context);
    if (!datagram.has_value()) {
        status_ = HandshakeStatus::failed;
        return {};
    }

    if (datagram.value().size() < kMinimumInitialDatagramSize) {
        frames.emplace_back(PaddingFrame{
            .length = kMinimumInitialDatagramSize - datagram.value().size(),
        });
        packets[0] = ProtectedInitialPacket{
            .version = kQuicVersion1,
            .destination_connection_id = config_.initial_destination_connection_id,
            .source_connection_id = config_.source_connection_id,
            .token = {},
            .packet_number_length = kDefaultInitialPacketNumberLength,
            .packet_number = initial_space_.next_send_packet_number - 1,
            .frames = std::move(frames),
        };
        datagram = serialize_protected_datagram(packets, context);
        if (!datagram.has_value()) {
            status_ = HandshakeStatus::failed;
            return {};
        }
    }

    return datagram.value();
}

} // namespace coquic::quic
