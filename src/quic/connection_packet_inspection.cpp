#include "src/quic/connection.h"

#include <atomic>
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

std::atomic_bool &force_packet_inspection_missing_plaintext_storage_for_tests() {
    static std::atomic_bool enabled{false};
    return enabled;
}

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

struct PacketInspectionPlaintextStorageResetVisitor {
    template <typename Packet> void operator()(Packet &packet) const {
        if constexpr (requires { packet.plaintext_storage; }) {
            packet.plaintext_storage.reset();
        }
    }
};

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
        if (force_packet_inspection_missing_plaintext_storage_for_tests().load(
                std::memory_order_relaxed)) {
            std::visit(PacketInspectionPlaintextStorageResetVisitor{}, decoded.value());
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

namespace test {

void connection_set_force_packet_inspection_missing_plaintext_storage_for_tests(bool enabled) {
    force_packet_inspection_missing_plaintext_storage_for_tests().store(enabled,
                                                                        std::memory_order_relaxed);
}

bool connection_packet_inspection_coverage_for_tests() {
    bool ok = true;
    const auto record = [&ok](bool condition) {
        ok = static_cast<bool>(static_cast<unsigned>(ok) & static_cast<unsigned>(condition));
    };

    const auto plaintext = std::make_shared<std::vector<std::byte>>(
        std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}});
    QuicCorePacketInspection ack_inspection{};
    populate_packet_inspection_from_decoded_packet(
        ack_inspection, ReceivedProtectedOneRttAckOnlyPacket{
                            .spin_bit = true,
                            .key_phase = true,
                            .destination_connection_id = {std::byte{0xaa}},
                            .packet_number_length = 2,
                            .packet_number = 9,
                            .plaintext_storage = plaintext,
                            .ack = ReceivedAckFrame{.largest_acknowledged = 7},
                        });
    record(ack_inspection.packet_type == QuicCorePacketInspectionPacketType::one_rtt);
    record(ack_inspection.spin_bit);
    record(ack_inspection.key_phase);
    record(ack_inspection.packet_number_length == 2);
    record(ack_inspection.packet_number == 9);
    record(ack_inspection.destination_connection_id == ConnectionId{std::byte{0xaa}});
    record(ack_inspection.plaintext_payload == *plaintext);
    record(ack_inspection.frames.size() == 1);
    record(std::holds_alternative<ReceivedAckFrame>(ack_inspection.frames[0]));

    QuicCorePacketInspection stream_inspection{};
    populate_packet_inspection_from_decoded_packet(
        stream_inspection, ReceivedProtectedOneRttStreamPacket{
                               .destination_connection_id = {std::byte{0xbb}},
                               .packet_number_length = 1,
                               .packet_number = 10,
                               .stream = ReceivedStreamFrame{.stream_id = 3},
                           });
    record(stream_inspection.packet_type == QuicCorePacketInspectionPacketType::one_rtt);
    record(stream_inspection.destination_connection_id == ConnectionId{std::byte{0xbb}});
    record(stream_inspection.plaintext_payload.empty());
    record(stream_inspection.frames.size() == 1);
    record(std::holds_alternative<ReceivedStreamFrame>(stream_inspection.frames[0]));

    struct PacketWithoutPlaintextStorage {
        std::uint8_t packet_number_length = 0;
        std::uint64_t packet_number = 0;
    };
    QuicCorePacketInspection no_storage_inspection{};
    populate_packet_inspection_from_decoded_packet(no_storage_inspection,
                                                   PacketWithoutPlaintextStorage{});
    record(no_storage_inspection.packet_number_length == 0);
    record(no_storage_inspection.packet_number == 0);
    record(no_storage_inspection.frames.empty());
    record(no_storage_inspection.plaintext_payload.empty());
    return ok;
}

} // namespace test

} // namespace coquic::quic
