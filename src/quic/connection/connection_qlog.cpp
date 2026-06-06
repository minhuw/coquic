#include "src/quic/connection/connection.h"

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "src/quic/qlog/json.h"
#include "src/quic/qlog/session.h"

namespace coquic::quic {

namespace {

std::vector<std::byte> application_protocol_bytes(std::string_view protocol) {
    std::vector<std::byte> bytes;
    bytes.reserve(protocol.size());
    for (const char value : protocol) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return bytes;
}

} // namespace

void QuicConnection::maybe_open_qlog_session(QuicCoreTimePoint now, const ConnectionId &odcid) {
    if (qlog_session_ != nullptr || !config_.qlog.has_value()) {
        return;
    }

    qlog_session_ = qlog::Session::try_open(*config_.qlog, config_.role, odcid, now);
}

void QuicConnection::emit_local_qlog_startup_events(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr) {
        return;
    }

    if (qlog_session_->mark_local_version_information_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:version_information",
            qlog::serialize_version_information(config_.role, config_.supported_versions,
                                                current_version_)));
    }
    if (qlog_session_->mark_local_alpn_information_emitted()) {
        const std::vector<std::vector<std::byte>> alpns = {
            application_protocol_bytes(config_.application_protocol),
        };
        static_cast<void>(qlog_session_->write_event(
            now, "quic:alpn_information",
            qlog::serialize_alpn_information(std::span<const std::vector<std::byte>>(alpns),
                                             std::nullopt, std::nullopt, config_.role)));
    }
    if (qlog_session_->mark_local_parameters_set_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:parameters_set",
            qlog::serialize_parameters_set("local", local_transport_parameters_)));
    }
}

void QuicConnection::maybe_emit_remote_qlog_parameters(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || !peer_transport_parameters_.has_value()) {
        return;
    }
    if (!qlog_session_->mark_remote_parameters_set_emitted()) {
        return;
    }

    static_cast<void>(qlog_session_->write_event(
        now, "quic:parameters_set",
        qlog::serialize_parameters_set("remote", *peer_transport_parameters_)));
}

void QuicConnection::maybe_emit_qlog_alpn_information(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || !tls_.has_value()) {
        return;
    }

    const auto &selected = tls_->selected_application_protocol();
    if (!selected.has_value()) {
        return;
    }

    if (config_.role == EndpointRole::server) {
        const auto &client_alpns = tls_->peer_offered_application_protocols();
        if (!client_alpns.empty() && qlog_session_->mark_server_alpn_selection_emitted()) {
            const std::vector<std::vector<std::byte>> server_alpns = {
                application_protocol_bytes(config_.application_protocol),
            };
            static_cast<void>(qlog_session_->write_event(
                now, "quic:alpn_information",
                qlog::serialize_alpn_information(
                    std::span<const std::vector<std::byte>>(server_alpns),
                    std::span<const std::vector<std::byte>>(client_alpns),
                    std::span<const std::byte>(*selected), EndpointRole::server)));
        }
        return;
    }

    if (qlog_session_->mark_client_chosen_alpn_emitted()) {
        static_cast<void>(qlog_session_->write_event(
            now, "quic:alpn_information",
            qlog::serialize_alpn_information(std::nullopt, std::nullopt,
                                             std::span<const std::byte>(*selected),
                                             EndpointRole::client)));
    }
}

qlog::PacketSnapshot
QuicConnection::make_qlog_packet_snapshot(const ProtectedPacket &packet,
                                          const qlog::PacketSnapshotContext &context) const {
    return std::visit(
        [&](const auto &protected_packet) -> qlog::PacketSnapshot {
            using PacketType = std::decay_t<decltype(protected_packet)>;
            qlog::PacketSnapshot snapshot;
            snapshot.raw_length = context.raw_length;
            snapshot.datagram_id = context.datagram_id;
            snapshot.trigger = context.trigger;
            snapshot.frames = protected_packet.frames;
            if constexpr (std::is_same_v<PacketType, ProtectedInitialPacket>) {
                snapshot.header.packet_type = "initial";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.token = protected_packet.token;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else if constexpr (std::is_same_v<PacketType, ProtectedHandshakePacket>) {
                snapshot.header.packet_type = "handshake";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else if constexpr (std::is_same_v<PacketType, ProtectedZeroRttPacket>) {
                snapshot.header.packet_type = "0RTT";
                snapshot.header.version = protected_packet.version;
                snapshot.header.scid = protected_packet.source_connection_id;
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            } else {
                snapshot.header.packet_type = "1RTT";
                snapshot.header.dcid = protected_packet.destination_connection_id;
                snapshot.header.spin_bit = protected_packet.spin_bit;
                snapshot.header.key_phase = static_cast<unsigned>(protected_packet.key_phase);
                snapshot.header.packet_number_length = protected_packet.packet_number_length;
                snapshot.header.packet_number = protected_packet.packet_number;
            }
            return snapshot;
        },
        packet);
}

qlog::RecoveryMetricsSnapshot QuicConnection::current_qlog_recovery_metrics() const {
    const auto &rtt = shared_recovery_rtt_state();
    const auto to_milliseconds_double = [](QuicCoreDuration duration) {
        return std::chrono::duration<double, std::milli>(duration).count();
    };
    return qlog::RecoveryMetricsSnapshot{
        .min_rtt_ms = rtt.min_rtt.has_value()
                          ? std::optional<double>(to_milliseconds_double(*rtt.min_rtt))
                          : std::nullopt,
        .smoothed_rtt_ms = to_milliseconds_double(rtt.smoothed_rtt),
        .latest_rtt_ms = rtt.latest_rtt.has_value()
                             ? std::optional<double>(to_milliseconds_double(*rtt.latest_rtt))
                             : std::nullopt,
        .rtt_variance_ms = to_milliseconds_double(rtt.rttvar),
        .pto_count = static_cast<std::uint16_t>(pto_count_),
        .congestion_window = static_cast<std::uint64_t>(congestion_controller_.congestion_window()),
        .bytes_in_flight = static_cast<std::uint64_t>(congestion_controller_.bytes_in_flight()),
    };
}

void QuicConnection::maybe_emit_qlog_recovery_metrics(QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr) {
        return;
    }

    static_cast<void>(
        qlog_session_->maybe_write_recovery_metrics(now, current_qlog_recovery_metrics()));
}

void QuicConnection::emit_qlog_packet_lost(const SentPacketRecord &packet, std::string_view trigger,
                                           QuicCoreTimePoint now) {
    if (qlog_session_ == nullptr || packet.qlog_packet_snapshot == nullptr) {
        return;
    }

    auto snapshot = *packet.qlog_packet_snapshot;
    snapshot.trigger = std::string(trigger);
    static_cast<void>(qlog_session_->write_event(now, "quic:packet_lost",
                                                 qlog::serialize_packet_snapshot(snapshot)));
}

} // namespace coquic::quic
