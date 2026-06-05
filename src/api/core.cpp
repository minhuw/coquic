#include "coquic/core.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <ranges>
#include <span>
#include <type_traits>
#include <utility>

#include "src/quic/core.h"

#if defined(COQUIC_COVERAGE_BUILD)
#define COQUIC_NO_PROFILE
#elif defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::core {

namespace {

quic::EndpointRole to_internal(Role role) {
    switch (role) {
    case Role::client:
        return quic::EndpointRole::client;
    case Role::server:
        return quic::EndpointRole::server;
    }
    return quic::EndpointRole::client;
}

quic::QuicCongestionControlAlgorithm to_internal(CongestionControl algorithm) {
    switch (algorithm) {
    case CongestionControl::newreno:
        return quic::QuicCongestionControlAlgorithm::newreno;
    case CongestionControl::cubic:
        return quic::QuicCongestionControlAlgorithm::cubic;
    case CongestionControl::bbr:
        return quic::QuicCongestionControlAlgorithm::bbr;
    case CongestionControl::copa:
        return quic::QuicCongestionControlAlgorithm::copa;
    }
    return quic::QuicCongestionControlAlgorithm::newreno;
}

CongestionControl from_internal(quic::QuicCongestionControlAlgorithm algorithm) {
    switch (algorithm) {
    case quic::QuicCongestionControlAlgorithm::newreno:
        return CongestionControl::newreno;
    case quic::QuicCongestionControlAlgorithm::cubic:
        return CongestionControl::cubic;
    case quic::QuicCongestionControlAlgorithm::bbr:
        return CongestionControl::bbr;
    case quic::QuicCongestionControlAlgorithm::copa:
        return CongestionControl::copa;
    }
    return CongestionControl::newreno;
}

quic::QuicEcnCodepoint to_internal(EcnCodepoint ecn) {
    switch (ecn) {
    case EcnCodepoint::unavailable:
        return quic::QuicEcnCodepoint::unavailable;
    case EcnCodepoint::not_ect:
        return quic::QuicEcnCodepoint::not_ect;
    case EcnCodepoint::ect0:
        return quic::QuicEcnCodepoint::ect0;
    case EcnCodepoint::ect1:
        return quic::QuicEcnCodepoint::ect1;
    case EcnCodepoint::ce:
        return quic::QuicEcnCodepoint::ce;
    }
    return quic::QuicEcnCodepoint::unavailable;
}

EcnCodepoint from_internal(quic::QuicEcnCodepoint ecn) {
    switch (ecn) {
    case quic::QuicEcnCodepoint::unavailable:
        return EcnCodepoint::unavailable;
    case quic::QuicEcnCodepoint::not_ect:
        return EcnCodepoint::not_ect;
    case quic::QuicEcnCodepoint::ect0:
        return EcnCodepoint::ect0;
    case quic::QuicEcnCodepoint::ect1:
        return EcnCodepoint::ect1;
    case quic::QuicEcnCodepoint::ce:
        return EcnCodepoint::ce;
    }
    return EcnCodepoint::unavailable;
}

quic::QuicMigrationRequestReason to_internal(MigrationReason reason) {
    switch (reason) {
    case MigrationReason::active:
        return quic::QuicMigrationRequestReason::active;
    case MigrationReason::preferred_address:
        return quic::QuicMigrationRequestReason::preferred_address;
    }
    return quic::QuicMigrationRequestReason::active;
}

StateChange from_internal(quic::QuicCoreStateChange change) {
    switch (change) {
    case quic::QuicCoreStateChange::handshake_ready:
        return StateChange::handshake_ready;
    case quic::QuicCoreStateChange::handshake_confirmed:
        return StateChange::handshake_confirmed;
    case quic::QuicCoreStateChange::failed:
        return StateChange::failed;
    }
    return StateChange::failed;
}

LocalErrorCode from_internal(quic::QuicCoreLocalErrorCode code) {
    switch (code) {
    case quic::QuicCoreLocalErrorCode::unsupported_operation:
        return LocalErrorCode::unsupported_operation;
    case quic::QuicCoreLocalErrorCode::invalid_stream_id:
        return LocalErrorCode::invalid_stream_id;
    case quic::QuicCoreLocalErrorCode::invalid_stream_direction:
        return LocalErrorCode::invalid_stream_direction;
    case quic::QuicCoreLocalErrorCode::send_side_closed:
        return LocalErrorCode::send_side_closed;
    case quic::QuicCoreLocalErrorCode::receive_side_closed:
        return LocalErrorCode::receive_side_closed;
    case quic::QuicCoreLocalErrorCode::final_size_conflict:
        return LocalErrorCode::final_size_conflict;
    case quic::QuicCoreLocalErrorCode::datagram_not_supported:
        return LocalErrorCode::datagram_not_supported;
    case quic::QuicCoreLocalErrorCode::datagram_too_large:
        return LocalErrorCode::datagram_too_large;
    }
    return LocalErrorCode::unsupported_operation;
}

Lifecycle from_internal(quic::QuicCoreConnectionLifecycle lifecycle) {
    switch (lifecycle) {
    case quic::QuicCoreConnectionLifecycle::created:
        return Lifecycle::created;
    case quic::QuicCoreConnectionLifecycle::accepted:
        return Lifecycle::accepted;
    case quic::QuicCoreConnectionLifecycle::closed:
        return Lifecycle::closed;
    }
    return Lifecycle::closed;
}

ZeroRttStatus from_internal(quic::QuicZeroRttStatus status) {
    switch (status) {
    case quic::QuicZeroRttStatus::unavailable:
        return ZeroRttStatus::unavailable;
    case quic::QuicZeroRttStatus::not_attempted:
        return ZeroRttStatus::not_attempted;
    case quic::QuicZeroRttStatus::attempted:
        return ZeroRttStatus::attempted;
    case quic::QuicZeroRttStatus::accepted:
        return ZeroRttStatus::accepted;
    case quic::QuicZeroRttStatus::rejected:
        return ZeroRttStatus::rejected;
    }
    return ZeroRttStatus::unavailable;
}

PacketInspectionDirection from_internal(quic::QuicCorePacketInspectionDirection direction) {
    switch (direction) {
    case quic::QuicCorePacketInspectionDirection::outbound:
        return PacketInspectionDirection::outbound;
    case quic::QuicCorePacketInspectionDirection::inbound:
        return PacketInspectionDirection::inbound;
    }
    return PacketInspectionDirection::outbound;
}

PacketInspectionPacketType from_internal(quic::QuicCorePacketInspectionPacketType packet_type) {
    switch (packet_type) {
    case quic::QuicCorePacketInspectionPacketType::initial:
        return PacketInspectionPacketType::initial;
    case quic::QuicCorePacketInspectionPacketType::zero_rtt:
        return PacketInspectionPacketType::zero_rtt;
    case quic::QuicCorePacketInspectionPacketType::handshake:
        return PacketInspectionPacketType::handshake;
    case quic::QuicCorePacketInspectionPacketType::one_rtt:
        return PacketInspectionPacketType::one_rtt;
    }
    return PacketInspectionPacketType::initial;
}

std::optional<quic::TlsIdentity> to_internal(const std::optional<TlsIdentity> &identity) {
    if (!identity.has_value()) {
        return std::nullopt;
    }
    return quic::TlsIdentity{
        .certificate_pem = identity->certificate_pem,
        .private_key_pem = identity->private_key_pem,
    };
}

std::optional<quic::QuicQlogConfig> to_internal(const std::optional<QlogConfig> &config) {
    if (!config.has_value()) {
        return std::nullopt;
    }
    return quic::QuicQlogConfig{
        .directory = config->directory,
    };
}

quic::QuicTransportConfig to_internal(const TransportConfig &config) {
    return quic::QuicTransportConfig{
        .max_idle_timeout = config.max_idle_timeout,
        .max_udp_payload_size = config.max_udp_payload_size,
        .pmtud_enabled = config.pmtud_enabled,
        .pmtud_base_datagram_size = config.pmtud_base_datagram_size,
        .pmtud_max_datagram_size = config.pmtud_max_datagram_size,
        .active_connection_id_limit = config.active_connection_id_limit,
        .disable_active_migration = config.disable_active_migration,
        .preferred_address = std::nullopt,
        .ack_delay_exponent = config.ack_delay_exponent,
        .max_ack_delay = config.max_ack_delay,
        .ack_eliciting_threshold = config.ack_eliciting_threshold,
        .initial_max_data = config.initial_max_data,
        .initial_max_stream_data_bidi_local = config.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = config.initial_max_stream_data_uni,
        .initial_max_streams_bidi = config.initial_max_streams_bidi,
        .initial_max_streams_uni = config.initial_max_streams_uni,
        .max_datagram_frame_size = config.max_datagram_frame_size,
        .congestion_control = to_internal(config.congestion_control),
        .enable_hystart_plus_plus = config.enable_hystart_plus_plus,
        .send_stream_fairness = config.send_stream_fairness,
        .enable_latency_spin_bit = config.enable_latency_spin_bit,
        .grease_reserved_versions = config.grease_reserved_versions,
        .grease_quic_bit = config.grease_quic_bit,
        .enable_optimistic_ack_mitigation = config.enable_optimistic_ack_mitigation,
    };
}

quic::QuicZeroRttConfig to_internal(const ZeroRttConfig &config) {
    return quic::QuicZeroRttConfig{
        .attempt = config.attempt,
        .allow = config.allow,
        .application_context = config.application_context,
    };
}

std::optional<quic::QuicResumptionState> to_internal(const std::optional<ResumptionState> &state) {
    if (!state.has_value()) {
        return std::nullopt;
    }
    return quic::QuicResumptionState{
        .serialized = state->serialized,
    };
}

quic::QuicCoreEndpointConfig to_internal(const EndpointConfig &config) {
    return quic::QuicCoreEndpointConfig{
        .role = to_internal(config.role),
        .supported_versions = config.supported_versions,
        .verify_peer = config.verify_peer,
        .retry_enabled = config.retry_enabled,
        .application_protocol = config.application_protocol,
        .identity = to_internal(config.identity),
        .transport = to_internal(config.transport),
        .max_outbound_datagram_size = config.max_outbound_datagram_size,
        .allowed_tls_cipher_suites = {},
        .zero_rtt = to_internal(config.zero_rtt),
        .qlog = to_internal(config.qlog),
        .tls_keylog_path = config.tls_keylog_path,
        .stateless_reset_secret = std::nullopt,
        .address_validation_token_secret = std::nullopt,
        .previous_address_validation_token_secrets = {},
        .address_validation_replay_store_path = std::nullopt,
        .request_forgery_policy = {},
        .emit_shared_receive_stream_data = config.emit_shared_receive_stream_data,
        .enable_packet_inspection = config.enable_packet_inspection,
        .allow_peer_address_change = config.allow_peer_address_change,
    };
}

quic::QuicCoreClientConnectionConfig to_internal(const ClientConnectionConfig &config) {
    return quic::QuicCoreClientConnectionConfig{
        .source_connection_id = config.source_connection_id,
        .initial_destination_connection_id = config.initial_destination_connection_id,
        .original_destination_connection_id = config.original_destination_connection_id,
        .retry_source_connection_id = config.retry_source_connection_id,
        .retry_token = config.retry_token,
        .original_version = config.original_version,
        .initial_version = config.initial_version,
        .reacted_to_version_negotiation = config.reacted_to_version_negotiation,
        .server_name = config.server_name,
        .resumption_state = to_internal(config.resumption_state),
        .zero_rtt = to_internal(config.zero_rtt),
    };
}

quic::QuicCoreEndpointInput to_internal(EndpointInput input);

quic::QuicCoreConnectionInput to_internal(ConnectionInput input) {
    return std::visit(
        [](auto &&value) -> quic::QuicCoreConnectionInput {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, SendStreamData>) {
                return quic::QuicCoreSendStreamData{
                    .stream_id = value.stream_id,
                    .bytes = std::move(value.bytes),
                    .fin = value.fin,
                };
            } else if constexpr (std::is_same_v<T, SendDatagramData>) {
                return quic::QuicCoreSendDatagramData{
                    .bytes = std::move(value.bytes),
                };
            } else if constexpr (std::is_same_v<T, ResetStream>) {
                return quic::QuicCoreResetStream{
                    .stream_id = value.stream_id,
                    .application_error_code = value.application_error_code,
                };
            } else if constexpr (std::is_same_v<T, StopSending>) {
                return quic::QuicCoreStopSending{
                    .stream_id = value.stream_id,
                    .application_error_code = value.application_error_code,
                };
            } else if constexpr (std::is_same_v<T, CloseConnection>) {
                return quic::QuicCoreCloseConnection{
                    .application_error_code = value.application_error_code,
                    .reason_phrase = std::move(value.reason_phrase),
                };
            } else if constexpr (std::is_same_v<T, RequestKeyUpdate>) {
                return quic::QuicCoreRequestKeyUpdate{};
            } else if constexpr (std::is_same_v<T, RequestConnectionMigration>) {
                return quic::QuicCoreRequestConnectionMigration{
                    .route_handle = value.route_handle,
                    .reason = to_internal(value.reason),
                    .address_validation_identity = std::move(value.address_validation_identity),
                };
            }
        },
        std::move(input));
}

quic::QuicCoreEndpointInput to_internal(EndpointInput input) {
    return std::visit(
        [](auto &&value) -> quic::QuicCoreEndpointInput {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, OpenConnection>) {
                return quic::QuicCoreOpenConnection{
                    .connection = to_internal(value.connection),
                    .initial_route_handle = value.initial_route_handle,
                    .address_validation_identity = std::move(value.address_validation_identity),
                };
            } else if constexpr (std::is_same_v<T, InboundDatagram>) {
                return quic::QuicCoreInboundDatagram{
                    .bytes = std::move(value.bytes),
                    .route_handle = value.route_handle,
                    .address_validation_identity = std::move(value.address_validation_identity),
                    .ecn = to_internal(value.ecn),
                };
            } else if constexpr (std::is_same_v<T, PathMtuUpdate>) {
                return quic::QuicCorePathMtuUpdate{
                    .route_handle = value.route_handle,
                    .max_udp_payload_size = value.max_udp_payload_size,
                };
            } else if constexpr (std::is_same_v<T, ConnectionCommand>) {
                return quic::QuicCoreConnectionCommand{
                    .connection = value.connection,
                    .input = to_internal(std::move(value.input)),
                };
            } else if constexpr (std::is_same_v<T, TimerExpired>) {
                return quic::QuicCoreTimerExpired{};
            }
        },
        std::move(input));
}

std::vector<std::byte> payload_vector(const quic::QuicCoreReceiveStreamData &received) {
    const auto payload = received.payload();
    return {payload.begin(), payload.end()};
}

std::vector<std::byte> payload_vector(const quic::QuicCoreReceiveDatagramData &received) {
    const auto payload = received.payload();
    return {payload.begin(), payload.end()};
}

PreferredAddress from_internal(const quic::PreferredAddress &address) {
    return PreferredAddress{
        .ipv4_address = address.ipv4_address,
        .ipv4_port = address.ipv4_port,
        .ipv6_address = address.ipv6_address,
        .ipv6_port = address.ipv6_port,
        .connection_id = address.connection_id,
        .stateless_reset_token = address.stateless_reset_token,
    };
}

Effect from_internal(quic::QuicCoreEffect effect) {
    return std::visit(
        [](auto &&value) -> Effect {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, quic::QuicCoreSendDatagram>) {
                return SendDatagram{
                    .connection = value.connection,
                    .route_handle = value.route_handle,
                    .bytes = value.bytes.to_vector(),
                    .ecn = from_internal(value.ecn),
                    .is_pmtu_probe = value.is_pmtu_probe,
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCoreReceiveStreamData>) {
                return ReceiveStreamData{
                    .connection = value.connection,
                    .stream_id = value.stream_id,
                    .bytes = payload_vector(value),
                    .fin = value.fin,
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCoreReceiveDatagramData>) {
                return ReceiveDatagramData{
                    .connection = value.connection,
                    .bytes = payload_vector(value),
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCorePeerResetStream>) {
                return PeerResetStream{
                    .connection = value.connection,
                    .stream_id = value.stream_id,
                    .application_error_code = value.application_error_code,
                    .final_size = value.final_size,
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCorePeerStopSending>) {
                return PeerStopSending{
                    .connection = value.connection,
                    .stream_id = value.stream_id,
                    .application_error_code = value.application_error_code,
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCoreStateEvent>) {
                return StateEvent{
                    .connection = value.connection,
                    .change = from_internal(value.change),
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCoreConnectionLifecycleEvent>) {
                return ConnectionLifecycleEvent{
                    .connection = value.connection,
                    .event = from_internal(value.event),
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCorePeerPreferredAddressAvailable>) {
                return PeerPreferredAddressAvailable{
                    .connection = value.connection,
                    .preferred_address = from_internal(value.preferred_address),
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCoreResumptionStateAvailable>) {
                return ResumptionStateAvailable{
                    .connection = value.connection,
                    .state = {.serialized = std::move(value.state.serialized)},
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCoreZeroRttStatusEvent>) {
                return ZeroRttStatusEvent{
                    .connection = value.connection,
                    .status = from_internal(value.status),
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCorePacketInspection>) {
                return PacketInspection{
                    .connection = value.connection,
                    .direction = from_internal(value.direction),
                    .packet_type = from_internal(value.packet_type),
                    .datagram_id = value.datagram_id,
                    .datagram_length = value.datagram_length,
                    .datagram_offset = value.datagram_offset,
                    .packet_length = value.packet_length,
                    .version = value.version,
                    .destination_connection_id = std::move(value.destination_connection_id),
                    .source_connection_id = std::move(value.source_connection_id),
                    .token = std::move(value.token),
                    .spin_bit = value.spin_bit,
                    .key_phase = value.key_phase,
                    .packet_number_length = value.packet_number_length,
                    .packet_number = value.packet_number,
                    .encrypted_packet = std::move(value.encrypted_packet),
                    .plaintext_payload = std::move(value.plaintext_payload),
                };
            } else if constexpr (std::is_same_v<T, quic::QuicCoreNewTokenAvailable>) {
                return NewTokenAvailable{
                    .connection = value.connection,
                    .token = std::move(value.token),
                };
            }
        },
        std::move(effect));
}

LocalError from_internal(const quic::QuicCoreLocalError &error) {
    return LocalError{
        .connection = error.connection,
        .code = from_internal(error.code),
        .stream_id = error.stream_id,
    };
}

Result from_internal(quic::QuicCoreResult result) {
    Result out;
    out.effects.reserve(result.effects.size());
    for (auto &effect : result.effects) {
        out.effects.push_back(from_internal(std::move(effect)));
    }
    out.next_wakeup = result.next_wakeup;
    if (result.local_error.has_value()) {
        out.local_error = from_internal(*result.local_error);
    }
    out.send_continuation_pending = result.send_continuation_pending;
    return out;
}

ConnectionDiagnostics from_internal(const quic::QuicCoreConnectionDiagnostics &diagnostics) {
    return ConnectionDiagnostics{
        .handle = diagnostics.handle,
        .handshake_status = diagnostics.handshake_status,
        .started = diagnostics.started,
        .handshake_confirmed = diagnostics.handshake_confirmed,
        .failed_emitted = diagnostics.failed_emitted,
        .current_version = diagnostics.current_version,
        .active_paths = diagnostics.active_paths,
        .active_streams = diagnostics.active_streams,
        .retired_streams = diagnostics.retired_streams,
    };
}

bool has_pending_stream_send_diagnostics(
    std::span<const quic::QuicCoreConnectionDiagnostics> diagnostics) {
    return std::ranges::any_of(diagnostics, [](const auto &connection) {
        return std::ranges::any_of(connection.streams,
                                   [](const auto &stream) { return stream.pending_send; });
    });
}

template <typename T> std::vector<T> effects_of(const Result &result) {
    std::vector<T> out;
    for (const auto &effect : result.effects) {
        if (const auto *value = std::get_if<T>(&effect)) {
            out.push_back(*value);
        }
    }
    return out;
}

} // namespace

namespace test {

COQUIC_NO_PROFILE bool core_wrapper_conversion_coverage_for_tests() {
    bool ok = true;
    const auto record = [&ok](bool condition) {
        ok = static_cast<bool>(static_cast<unsigned>(ok) & static_cast<unsigned>(condition));
        return condition;
    };

    record(to_internal(Role::client) == quic::EndpointRole::client);
    record(to_internal(Role::server) == quic::EndpointRole::server);
    record(to_internal(static_cast<Role>(0xff)) == quic::EndpointRole::client);
    record(to_internal(CongestionControl::newreno) ==
           quic::QuicCongestionControlAlgorithm::newreno);
    record(to_internal(CongestionControl::cubic) == quic::QuicCongestionControlAlgorithm::cubic);
    record(to_internal(CongestionControl::bbr) == quic::QuicCongestionControlAlgorithm::bbr);
    record(to_internal(CongestionControl::copa) == quic::QuicCongestionControlAlgorithm::copa);
    record(to_internal(static_cast<CongestionControl>(0xff)) ==
           quic::QuicCongestionControlAlgorithm::newreno);
    record(from_internal(quic::QuicCongestionControlAlgorithm::newreno) ==
           CongestionControl::newreno);
    record(from_internal(quic::QuicCongestionControlAlgorithm::cubic) == CongestionControl::cubic);
    record(from_internal(quic::QuicCongestionControlAlgorithm::bbr) == CongestionControl::bbr);
    record(from_internal(quic::QuicCongestionControlAlgorithm::copa) == CongestionControl::copa);
    record(from_internal(static_cast<quic::QuicCongestionControlAlgorithm>(0xff)) ==
           CongestionControl::newreno);
    record(to_internal(EcnCodepoint::unavailable) == quic::QuicEcnCodepoint::unavailable);
    record(to_internal(EcnCodepoint::not_ect) == quic::QuicEcnCodepoint::not_ect);
    record(to_internal(EcnCodepoint::ect0) == quic::QuicEcnCodepoint::ect0);
    record(to_internal(EcnCodepoint::ect1) == quic::QuicEcnCodepoint::ect1);
    record(to_internal(EcnCodepoint::ce) == quic::QuicEcnCodepoint::ce);
    record(to_internal(static_cast<EcnCodepoint>(0xff)) == quic::QuicEcnCodepoint::unavailable);
    record(from_internal(quic::QuicEcnCodepoint::unavailable) == EcnCodepoint::unavailable);
    record(from_internal(quic::QuicEcnCodepoint::not_ect) == EcnCodepoint::not_ect);
    record(from_internal(quic::QuicEcnCodepoint::ect0) == EcnCodepoint::ect0);
    record(from_internal(quic::QuicEcnCodepoint::ect1) == EcnCodepoint::ect1);
    record(from_internal(quic::QuicEcnCodepoint::ce) == EcnCodepoint::ce);
    record(from_internal(static_cast<quic::QuicEcnCodepoint>(0xff)) == EcnCodepoint::unavailable);
    record(to_internal(MigrationReason::active) == quic::QuicMigrationRequestReason::active);
    record(to_internal(MigrationReason::preferred_address) ==
           quic::QuicMigrationRequestReason::preferred_address);
    record(to_internal(static_cast<MigrationReason>(0xff)) ==
           quic::QuicMigrationRequestReason::active);
    record(from_internal(quic::QuicCoreStateChange::failed) == StateChange::failed);
    record(from_internal(static_cast<quic::QuicCoreStateChange>(0xff)) == StateChange::failed);
    record(from_internal(quic::QuicCoreLocalErrorCode::unsupported_operation) ==
           LocalErrorCode::unsupported_operation);
    record(from_internal(quic::QuicCoreLocalErrorCode::invalid_stream_id) ==
           LocalErrorCode::invalid_stream_id);
    record(from_internal(quic::QuicCoreLocalErrorCode::invalid_stream_direction) ==
           LocalErrorCode::invalid_stream_direction);
    record(from_internal(quic::QuicCoreLocalErrorCode::send_side_closed) ==
           LocalErrorCode::send_side_closed);
    record(from_internal(quic::QuicCoreLocalErrorCode::receive_side_closed) ==
           LocalErrorCode::receive_side_closed);
    record(from_internal(quic::QuicCoreLocalErrorCode::final_size_conflict) ==
           LocalErrorCode::final_size_conflict);
    record(from_internal(quic::QuicCoreLocalErrorCode::datagram_not_supported) ==
           LocalErrorCode::datagram_not_supported);
    record(from_internal(static_cast<quic::QuicCoreLocalErrorCode>(0xff)) ==
           LocalErrorCode::unsupported_operation);
    record(from_internal(quic::QuicCoreConnectionLifecycle::created) == Lifecycle::created);
    record(from_internal(static_cast<quic::QuicCoreConnectionLifecycle>(0xff)) ==
           Lifecycle::closed);
    record(from_internal(quic::QuicZeroRttStatus::unavailable) == ZeroRttStatus::unavailable);
    record(from_internal(static_cast<quic::QuicZeroRttStatus>(0xff)) == ZeroRttStatus::unavailable);
    record(from_internal(quic::QuicCorePacketInspectionDirection::outbound) ==
           PacketInspectionDirection::outbound);
    record(from_internal(static_cast<quic::QuicCorePacketInspectionDirection>(0xff)) ==
           PacketInspectionDirection::outbound);
    record(from_internal(quic::QuicCorePacketInspectionPacketType::initial) ==
           PacketInspectionPacketType::initial);
    record(from_internal(quic::QuicCorePacketInspectionPacketType::zero_rtt) ==
           PacketInspectionPacketType::zero_rtt);
    record(from_internal(quic::QuicCorePacketInspectionPacketType::one_rtt) ==
           PacketInspectionPacketType::one_rtt);
    record(from_internal(static_cast<quic::QuicCorePacketInspectionPacketType>(0xff)) ==
           PacketInspectionPacketType::initial);

    quic::QuicCoreResult internal;
    internal.next_wakeup = TimePoint{Duration{42}};
    internal.send_continuation_pending = true;
    internal.effects.push_back(quic::QuicCoreSendDatagram{
        .connection = 1,
        .route_handle = 7,
        .bytes = quic::DatagramBuffer{std::vector<std::byte>{std::byte{0x01}}},
        .ecn = quic::QuicEcnCodepoint::ce,
        .is_pmtu_probe = true,
    });
    internal.effects.push_back(quic::QuicCoreReceiveStreamData{
        .connection = 2,
        .stream_id = 8,
        .shared_bytes = quic::SharedBytes{std::vector<std::byte>{std::byte{0x02}}},
        .fin = true,
    });
    internal.effects.push_back(quic::QuicCoreReceiveDatagramData{
        .connection = 3,
        .shared_bytes = quic::SharedBytes{std::vector<std::byte>{std::byte{0x03}}},
    });
    internal.effects.push_back(quic::QuicCorePeerResetStream{
        .connection = 4,
        .stream_id = 12,
        .application_error_code = 77,
        .final_size = 99,
    });
    internal.effects.push_back(quic::QuicCorePeerStopSending{
        .connection = 5,
        .stream_id = 16,
        .application_error_code = 78,
    });
    internal.effects.push_back(quic::QuicCoreStateEvent{
        .connection = 6,
        .change = quic::QuicCoreStateChange::handshake_ready,
    });
    internal.effects.push_back(quic::QuicCoreStateEvent{
        .connection = 7,
        .change = quic::QuicCoreStateChange::handshake_confirmed,
    });
    internal.effects.push_back(quic::QuicCoreConnectionLifecycleEvent{
        .connection = 8,
        .event = quic::QuicCoreConnectionLifecycle::accepted,
    });
    internal.effects.push_back(quic::QuicCoreConnectionLifecycleEvent{
        .connection = 9,
        .event = quic::QuicCoreConnectionLifecycle::closed,
    });
    internal.effects.push_back(quic::QuicCorePeerPreferredAddressAvailable{
        .connection = 10,
        .preferred_address =
            quic::PreferredAddress{
                .ipv4_address = {std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1}},
                .ipv4_port = 4433,
                .connection_id = {std::byte{0xaa}},
            },
    });
    internal.effects.push_back(quic::QuicCoreResumptionStateAvailable{
        .connection = 11,
        .state = {.serialized = {std::byte{0x04}}},
    });
    internal.effects.push_back(quic::QuicCoreZeroRttStatusEvent{
        .connection = 12,
        .status = quic::QuicZeroRttStatus::not_attempted,
    });
    internal.effects.push_back(quic::QuicCoreZeroRttStatusEvent{
        .connection = 13,
        .status = quic::QuicZeroRttStatus::attempted,
    });
    internal.effects.push_back(quic::QuicCoreZeroRttStatusEvent{
        .connection = 14,
        .status = quic::QuicZeroRttStatus::accepted,
    });
    internal.effects.push_back(quic::QuicCoreZeroRttStatusEvent{
        .connection = 15,
        .status = quic::QuicZeroRttStatus::rejected,
    });
    internal.effects.push_back(quic::QuicCorePacketInspection{
        .connection = 16,
        .direction = quic::QuicCorePacketInspectionDirection::inbound,
        .packet_type = quic::QuicCorePacketInspectionPacketType::handshake,
        .datagram_id = 101,
        .datagram_length = 1200,
        .datagram_offset = 4,
        .packet_length = 1180,
        .version = 1,
        .destination_connection_id = {std::byte{0x05}},
        .source_connection_id = {std::byte{0x06}},
        .token = {std::byte{0x07}},
        .spin_bit = true,
        .key_phase = true,
        .packet_number_length = 4,
        .packet_number = 123,
        .encrypted_packet = {std::byte{0x08}},
        .plaintext_payload = {std::byte{0x09}},
    });
    internal.effects.push_back(quic::QuicCoreNewTokenAvailable{
        .connection = 17,
        .token = {std::byte{0x0a}},
    });
    internal.local_error = quic::QuicCoreLocalError{
        .connection = 18,
        .code = quic::QuicCoreLocalErrorCode::datagram_too_large,
        .stream_id = 20,
    };

    const auto converted = from_internal(std::move(internal));
    record(converted.effects.size() == 17);
    record(converted.next_wakeup.has_value());
    record(converted.send_continuation_pending);
    record(converted.local_error.has_value());

    record(std::holds_alternative<SendDatagram>(converted.effects[0]));
    record(std::holds_alternative<ReceiveStreamData>(converted.effects[1]));
    record(std::holds_alternative<ReceiveDatagramData>(converted.effects[2]));
    record(std::holds_alternative<PeerResetStream>(converted.effects[3]));
    record(std::holds_alternative<PeerStopSending>(converted.effects[4]));
    record(std::holds_alternative<StateEvent>(converted.effects[5]));
    record(std::get<StateEvent>(converted.effects[6]).change == StateChange::handshake_confirmed);
    record(std::holds_alternative<ConnectionLifecycleEvent>(converted.effects[7]));
    record(std::get<ConnectionLifecycleEvent>(converted.effects[8]).event == Lifecycle::closed);
    record(std::holds_alternative<PeerPreferredAddressAvailable>(converted.effects[9]));
    record(std::holds_alternative<ResumptionStateAvailable>(converted.effects[10]));
    record(std::get<ZeroRttStatusEvent>(converted.effects[11]).status ==
           ZeroRttStatus::not_attempted);
    record(std::get<ZeroRttStatusEvent>(converted.effects[12]).status == ZeroRttStatus::attempted);
    record(std::get<ZeroRttStatusEvent>(converted.effects[13]).status == ZeroRttStatus::accepted);
    record(std::get<ZeroRttStatusEvent>(converted.effects[14]).status == ZeroRttStatus::rejected);
    record(std::get<PacketInspection>(converted.effects[15]).direction ==
           PacketInspectionDirection::inbound);
    record(std::holds_alternative<NewTokenAvailable>(converted.effects[16]));
    record(converted.local_error->code == LocalErrorCode::datagram_too_large);
    record(send_datagrams(converted).size() == 1u);
    record(lifecycle_events(converted).size() == 2u);
    record(state_events(converted).size() == 2u);
    record(receive_stream_events(converted).size() == 1u);
    record(receive_datagram_events(converted).size() == 1u);
    record(!has_pending_stream_send_diagnostics({}));
    const std::array no_pending_streams{
        quic::QuicCoreConnectionDiagnostics{
            .handle = 1,
            .streams =
                {
                    quic::QuicCoreStreamDiagnostics{
                        .stream_id = 0,
                        .pending_send = false,
                    },
                },
        },
    };
    record(!has_pending_stream_send_diagnostics(no_pending_streams));
    const std::array pending_streams{
        quic::QuicCoreConnectionDiagnostics{
            .handle = 2,
            .streams =
                {
                    quic::QuicCoreStreamDiagnostics{
                        .stream_id = 4,
                        .pending_send = true,
                    },
                },
        },
    };
    record(has_pending_stream_send_diagnostics(pending_streams));

    return ok;
}

} // namespace test

class Endpoint::Impl {
  public:
    explicit Impl(const EndpointConfig &config) : core(to_internal(config)) {
    }

    quic::QuicCore core;
};

Endpoint::Endpoint(const EndpointConfig &config) : impl_(std::make_unique<Impl>(config)) {
}

Endpoint::~Endpoint() = default;

Endpoint::Endpoint(Endpoint &&) noexcept = default;

Endpoint &Endpoint::operator=(Endpoint &&) noexcept = default;

Result Endpoint::advance(EndpointInput input, TimePoint now) {
    return from_internal(impl_->core.advance_endpoint(to_internal(std::move(input)), now));
}

Result Endpoint::open_connection(OpenConnection input, TimePoint now) {
    return advance(EndpointInput{std::move(input)}, now);
}

Result Endpoint::input_datagram(InboundDatagram input, TimePoint now) {
    return advance(EndpointInput{std::move(input)}, now);
}

Result Endpoint::update_path_mtu(PathMtuUpdate input, TimePoint now) {
    return advance(EndpointInput{input}, now);
}

Result Endpoint::advance_connection(ConnectionCommand input, TimePoint now) {
    return advance(EndpointInput{std::move(input)}, now);
}

Result Endpoint::timer_expired(TimePoint now) {
    return advance(EndpointInput{TimerExpired{}}, now);
}

std::optional<TimePoint> Endpoint::next_wakeup() const {
    return impl_->core.next_wakeup();
}

std::size_t Endpoint::connection_count() const {
    return impl_->core.connection_count();
}

std::vector<ConnectionDiagnostics> Endpoint::connection_diagnostics() const {
    const auto diagnostics = impl_->core.connection_diagnostics();
    std::vector<ConnectionDiagnostics> out;
    out.reserve(diagnostics.size());
    std::ranges::transform(diagnostics, std::back_inserter(out),
                           [](const auto &value) { return from_internal(value); });
    return out;
}

bool Endpoint::has_send_continuation_pending() const {
    return impl_->core.has_send_continuation_pending();
}

bool Endpoint::has_pending_stream_send() const {
    const auto diagnostics = impl_->core.connection_diagnostics();
    return has_pending_stream_send_diagnostics(diagnostics);
}

std::vector<SendDatagram> send_datagrams(const Result &result) {
    return effects_of<SendDatagram>(result);
}

std::vector<ConnectionLifecycleEvent> lifecycle_events(const Result &result) {
    return effects_of<ConnectionLifecycleEvent>(result);
}

std::vector<StateEvent> state_events(const Result &result) {
    return effects_of<StateEvent>(result);
}

std::vector<ReceiveStreamData> receive_stream_events(const Result &result) {
    return effects_of<ReceiveStreamData>(result);
}

std::vector<ReceiveDatagramData> receive_datagram_events(const Result &result) {
    return effects_of<ReceiveDatagramData>(result);
}

} // namespace coquic::core
