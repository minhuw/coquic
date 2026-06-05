#include "src/quic/connection.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <type_traits>
#include <variant>
#include <vector>

#include "src/quic/protected_codec.h"

namespace coquic::quic {

namespace {

void maybe_copy_plaintext_payload(auto &inspection, const auto &packet) {
    if constexpr (requires { packet.plaintext_storage; }) {
        if (packet.plaintext_storage != nullptr) {
            inspection.plaintext_payload = *packet.plaintext_storage;
        }
    }
}

template <typename Packet>
void populate_packet_inspection_from_decoded_packet(QuicCorePacketInspection &inspection,
                                                    const Packet &packet) {
    using PacketType = std::decay_t<Packet>;
    inspection.packet_number_length = packet.packet_number_length;
    inspection.packet_number = packet.packet_number;
    if constexpr (requires { packet.frames; }) {
        inspection.frames = packet.frames;
    } else if constexpr (requires { packet.ack; }) {
        inspection.frames = {packet.ack};
    } else if constexpr (requires { packet.stream; }) {
        inspection.frames = {packet.stream};
    }
    maybe_copy_plaintext_payload(inspection, packet);

    if constexpr (std::is_same_v<PacketType, ReceivedProtectedInitialPacket>) {
        inspection.packet_type = QuicCorePacketInspectionPacketType::initial;
        inspection.version = packet.version;
        inspection.destination_connection_id = packet.destination_connection_id;
        inspection.source_connection_id = packet.source_connection_id;
        inspection.token = packet.token;
    } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedHandshakePacket>) {
        inspection.packet_type = QuicCorePacketInspectionPacketType::handshake;
        inspection.version = packet.version;
        inspection.destination_connection_id = packet.destination_connection_id;
        inspection.source_connection_id = packet.source_connection_id;
    } else if constexpr (std::is_same_v<PacketType, ReceivedProtectedZeroRttPacket>) {
        inspection.packet_type = QuicCorePacketInspectionPacketType::zero_rtt;
        inspection.version = packet.version;
        inspection.destination_connection_id = packet.destination_connection_id;
        inspection.source_connection_id = packet.source_connection_id;
    } else if constexpr (requires { packet.spin_bit; }) {
        inspection.packet_type = QuicCorePacketInspectionPacketType::one_rtt;
        inspection.destination_connection_id = packet.destination_connection_id;
        inspection.spin_bit = packet.spin_bit;
        inspection.key_phase = packet.key_phase;
    }
}

} // namespace

std::size_t
QuicConnection::queue_outbound_packet_inspections(const SerializedProtectedDatagram &datagram,
                                                  std::uint64_t datagram_id) {
    if (!config_.enable_packet_inspection) {
        return 0;
    }

    const auto starting_count = pending_packet_inspections_.size();
    DeserializeProtectionContext context{
        .peer_role = config_.role,
        .client_initial_destination_connection_id = client_initial_destination_connection_id(),
        .handshake_secret = handshake_space_.write_secret,
        .zero_rtt_secret = zero_rtt_space_.write_secret,
        .one_rtt_secret = application_space_.write_secret,
        .one_rtt_key_phase = application_write_key_phase_,
        .largest_authenticated_initial_packet_number =
            initial_space_.largest_authenticated_packet_number,
        .largest_authenticated_handshake_packet_number =
            handshake_space_.largest_authenticated_packet_number,
        .largest_authenticated_application_packet_number =
            application_space_.largest_authenticated_packet_number,
        .one_rtt_destination_connection_id_length = outbound_destination_connection_id().size(),
    };

    for (const auto &metadata : datagram.packet_metadata) {
        if (metadata.offset > datagram.bytes.size() ||
            metadata.length > datagram.bytes.size() - metadata.offset) {
            continue;
        }

        const auto packet_bytes = datagram.bytes.span().subspan(metadata.offset, metadata.length);
        auto decoded = deserialize_received_protected_packet(packet_bytes, context);
        if (!decoded.has_value()) {
            continue;
        }

        QuicCorePacketInspection inspection{
            .direction = QuicCorePacketInspectionDirection::outbound,
            .datagram_id = datagram_id,
            .datagram_length = datagram.bytes.size(),
            .datagram_offset = metadata.offset,
            .packet_length = metadata.length,
            .encrypted_packet = std::vector<std::byte>(packet_bytes.begin(), packet_bytes.end()),
        };

        std::visit(
            [&inspection](const auto &packet) {
                populate_packet_inspection_from_decoded_packet(inspection, packet);
            },
            decoded.value());

        pending_packet_inspections_.push_back(std::move(inspection));
    }
    return pending_packet_inspections_.size() - starting_count;
}

} // namespace coquic::quic
