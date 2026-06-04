#include "coquic/core.h"

#include <algorithm>
#include <iterator>
#include <ranges>
#include <type_traits>
#include <utility>

#include "src/quic/core.h"

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
    return std::ranges::any_of(diagnostics, [](const auto &connection) {
        return std::ranges::any_of(connection.streams,
                                   [](const auto &stream) { return stream.pending_send; });
    });
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
