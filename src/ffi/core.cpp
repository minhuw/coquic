#include "coquic/ffi/core.h"

#include "coquic/core.h"
#include "src/ffi/core_internal.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#ifndef COQUIC_NO_PROFILE
#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif
#endif

namespace {

using TimePoint = coquic::core::TimePoint;

constexpr std::size_t kEndpointConfigSizeV1 =
    offsetof(coquic_endpoint_config_t, allow_peer_address_change) +
    sizeof(coquic_endpoint_config_t::allow_peer_address_change);
constexpr std::size_t kEndpointConfigSizeV2 =
    offsetof(coquic_endpoint_config_t, max_server_connections) +
    sizeof(coquic_endpoint_config_t::max_server_connections);
constexpr std::size_t kClientConnectionConfigSizeV1 =
    offsetof(coquic_client_connection_config_t, zero_rtt) +
    sizeof(coquic_client_connection_config_t::zero_rtt);
constexpr std::size_t kOpenConnectionSizeV1 =
    offsetof(coquic_open_connection_t, address_validation_identity) +
    sizeof(coquic_open_connection_t::address_validation_identity);
constexpr std::size_t kInboundDatagramSizeV1 =
    offsetof(coquic_inbound_datagram_t, ecn) + sizeof(coquic_inbound_datagram_t::ecn);
constexpr std::size_t kPathMtuUpdateSizeV1 =
    offsetof(coquic_path_mtu_update_t, max_udp_payload_size) +
    sizeof(coquic_path_mtu_update_t::max_udp_payload_size);
constexpr std::size_t kSendStreamDataSizeV1 =
    offsetof(coquic_send_stream_data_t, fin) + sizeof(coquic_send_stream_data_t::fin);
constexpr std::size_t kSendStreamDataSizeV2 =
    offsetof(coquic_send_stream_data_t, priority) + sizeof(coquic_send_stream_data_t::priority);
constexpr std::size_t kSendDatagramDataSizeV1 =
    offsetof(coquic_send_datagram_data_t, bytes) + sizeof(coquic_send_datagram_data_t::bytes);
constexpr std::size_t kSendDatagramDataSizeV2 =
    offsetof(coquic_send_datagram_data_t, priority) + sizeof(coquic_send_datagram_data_t::priority);
constexpr std::size_t kResetStreamSizeV1 = offsetof(coquic_reset_stream_t, application_error_code) +
                                           sizeof(coquic_reset_stream_t::application_error_code);
constexpr std::size_t kStopSendingSizeV1 = offsetof(coquic_stop_sending_t, application_error_code) +
                                           sizeof(coquic_stop_sending_t::application_error_code);
constexpr std::size_t kCloseConnectionSizeV1 =
    offsetof(coquic_close_connection_t, reason_phrase_length) +
    sizeof(coquic_close_connection_t::reason_phrase_length);
constexpr std::size_t kRequestConnectionMigrationSizeV1 =
    offsetof(coquic_request_connection_migration_t, address_validation_identity) +
    sizeof(coquic_request_connection_migration_t::address_validation_identity);

template <typename F> coquic_status_t ffi_guard(F &&function) noexcept {
    try {
        function();
        return COQUIC_STATUS_OK;
    } catch (const std::bad_alloc &) {
        return COQUIC_STATUS_OUT_OF_MEMORY;
    } catch (...) {
        return COQUIC_STATUS_INTERNAL_ERROR;
    }
}

TimePoint to_time_point(coquic_time_us_t now) {
    return TimePoint{std::chrono::microseconds{static_cast<std::int64_t>(now)}};
}

coquic_time_us_t from_time_point(TimePoint time_point) {
    return static_cast<coquic_time_us_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(time_point.time_since_epoch())
            .count());
}

std::string to_string(const char *data, std::size_t length) {
    if (data == nullptr || length == 0) {
        return {};
    }
    return std::string(data, length);
}

std::vector<std::byte> to_vector(coquic_bytes_t bytes) {
    if (bytes.data == nullptr || bytes.length == 0) {
        return {};
    }
    const auto *begin = reinterpret_cast<const std::byte *>(bytes.data);
    return std::vector<std::byte>(begin, begin + bytes.length);
}

coquic_bytes_view_t bytes_view(const std::vector<std::byte> &bytes) {
    return coquic_bytes_view_t{
        .data = reinterpret_cast<const std::uint8_t *>(bytes.data()),
        .length = bytes.size(),
    };
}

template <std::size_t N>
void copy_bytes(const std::array<std::byte, N> &src, std::uint8_t (&dst)[N]) {
    std::memcpy(dst, reinterpret_cast<const std::uint8_t *>(src.data()), N);
}

std::optional<coquic::core::RouteHandle> to_optional(coquic_optional_route_handle_t value) {
    if (value.has_value == 0) {
        return std::nullopt;
    }
    return value.value;
}

coquic_optional_route_handle_t
from_optional_route_handle(std::optional<coquic::core::RouteHandle> value) {
    if (!value.has_value()) {
        return {.has_value = 0, .value = 0};
    }
    return {.has_value = 1, .value = *value};
}

coquic_optional_connection_handle_t
from_optional_connection_handle(std::optional<coquic::core::ConnectionHandle> value) {
    if (!value.has_value()) {
        return {.has_value = 0, .value = 0};
    }
    return {.has_value = 1, .value = *value};
}

coquic_optional_stream_id_t from_optional_stream_id(std::optional<coquic::core::StreamId> value) {
    if (!value.has_value()) {
        return {.has_value = 0, .value = 0};
    }
    return {.has_value = 1, .value = *value};
}

coquic_optional_time_us_t from_optional(std::optional<TimePoint> value) {
    if (!value.has_value()) {
        return {.has_value = 0, .value = 0};
    }
    return {.has_value = 1, .value = from_time_point(*value)};
}

coquic::core::Role role_to_cpp(coquic_role_t role) {
    switch (role) {
    case COQUIC_ROLE_CLIENT:
        return coquic::core::Role::client;
    case COQUIC_ROLE_SERVER:
        return coquic::core::Role::server;
    default:
        return coquic::core::Role::client;
    }
}

coquic::core::CongestionControl congestion_control_to_cpp(coquic_congestion_control_t algorithm) {
    switch (algorithm) {
    case COQUIC_CONGESTION_CONTROL_NEWRENO:
        return coquic::core::CongestionControl::newreno;
    case COQUIC_CONGESTION_CONTROL_CUBIC:
        return coquic::core::CongestionControl::cubic;
    case COQUIC_CONGESTION_CONTROL_BBR:
        return coquic::core::CongestionControl::bbr;
    case COQUIC_CONGESTION_CONTROL_COPA:
        return coquic::core::CongestionControl::copa;
    default:
        return coquic::core::CongestionControl::newreno;
    }
}

coquic_congestion_control_t from_cpp(coquic::core::CongestionControl algorithm) {
    switch (algorithm) {
    case coquic::core::CongestionControl::newreno:
        return COQUIC_CONGESTION_CONTROL_NEWRENO;
    case coquic::core::CongestionControl::cubic:
        return COQUIC_CONGESTION_CONTROL_CUBIC;
    case coquic::core::CongestionControl::bbr:
        return COQUIC_CONGESTION_CONTROL_BBR;
    case coquic::core::CongestionControl::copa:
        return COQUIC_CONGESTION_CONTROL_COPA;
    }
    return COQUIC_CONGESTION_CONTROL_NEWRENO;
}

coquic::core::EcnCodepoint ecn_to_cpp(coquic_ecn_codepoint_t ecn) {
    switch (ecn) {
    case COQUIC_ECN_UNAVAILABLE:
        return coquic::core::EcnCodepoint::unavailable;
    case COQUIC_ECN_NOT_ECT:
        return coquic::core::EcnCodepoint::not_ect;
    case COQUIC_ECN_ECT0:
        return coquic::core::EcnCodepoint::ect0;
    case COQUIC_ECN_ECT1:
        return coquic::core::EcnCodepoint::ect1;
    case COQUIC_ECN_CE:
        return coquic::core::EcnCodepoint::ce;
    default:
        return coquic::core::EcnCodepoint::unavailable;
    }
}

coquic_ecn_codepoint_t from_cpp(coquic::core::EcnCodepoint ecn) {
    switch (ecn) {
    case coquic::core::EcnCodepoint::unavailable:
        return COQUIC_ECN_UNAVAILABLE;
    case coquic::core::EcnCodepoint::not_ect:
        return COQUIC_ECN_NOT_ECT;
    case coquic::core::EcnCodepoint::ect0:
        return COQUIC_ECN_ECT0;
    case coquic::core::EcnCodepoint::ect1:
        return COQUIC_ECN_ECT1;
    case coquic::core::EcnCodepoint::ce:
        return COQUIC_ECN_CE;
    }
    return COQUIC_ECN_UNAVAILABLE;
}

coquic::core::MigrationReason migration_reason_to_cpp(coquic_migration_reason_t reason) {
    switch (reason) {
    case COQUIC_MIGRATION_REASON_ACTIVE:
        return coquic::core::MigrationReason::active;
    case COQUIC_MIGRATION_REASON_PREFERRED_ADDRESS:
        return coquic::core::MigrationReason::preferred_address;
    default:
        return coquic::core::MigrationReason::active;
    }
}

coquic_state_change_t from_cpp(coquic::core::StateChange change) {
    switch (change) {
    case coquic::core::StateChange::handshake_ready:
        return COQUIC_STATE_CHANGE_HANDSHAKE_READY;
    case coquic::core::StateChange::handshake_confirmed:
        return COQUIC_STATE_CHANGE_HANDSHAKE_CONFIRMED;
    case coquic::core::StateChange::failed:
        return COQUIC_STATE_CHANGE_FAILED;
    }
    return COQUIC_STATE_CHANGE_FAILED;
}

coquic_local_error_code_t from_cpp(coquic::core::LocalErrorCode code) {
    switch (code) {
    case coquic::core::LocalErrorCode::unsupported_operation:
        return COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION;
    case coquic::core::LocalErrorCode::invalid_stream_id:
        return COQUIC_LOCAL_ERROR_INVALID_STREAM_ID;
    case coquic::core::LocalErrorCode::invalid_stream_direction:
        return COQUIC_LOCAL_ERROR_INVALID_STREAM_DIRECTION;
    case coquic::core::LocalErrorCode::send_side_closed:
        return COQUIC_LOCAL_ERROR_SEND_SIDE_CLOSED;
    case coquic::core::LocalErrorCode::receive_side_closed:
        return COQUIC_LOCAL_ERROR_RECEIVE_SIDE_CLOSED;
    case coquic::core::LocalErrorCode::final_size_conflict:
        return COQUIC_LOCAL_ERROR_FINAL_SIZE_CONFLICT;
    case coquic::core::LocalErrorCode::flow_control_violation:
        return COQUIC_LOCAL_ERROR_FLOW_CONTROL_VIOLATION;
    case coquic::core::LocalErrorCode::datagram_not_supported:
        return COQUIC_LOCAL_ERROR_DATAGRAM_NOT_SUPPORTED;
    case coquic::core::LocalErrorCode::datagram_too_large:
        return COQUIC_LOCAL_ERROR_DATAGRAM_TOO_LARGE;
    }
    return COQUIC_LOCAL_ERROR_UNSUPPORTED_OPERATION;
}

coquic_lifecycle_t from_cpp(coquic::core::Lifecycle lifecycle) {
    switch (lifecycle) {
    case coquic::core::Lifecycle::created:
        return COQUIC_LIFECYCLE_CREATED;
    case coquic::core::Lifecycle::accepted:
        return COQUIC_LIFECYCLE_ACCEPTED;
    case coquic::core::Lifecycle::closed:
        return COQUIC_LIFECYCLE_CLOSED;
    }
    return COQUIC_LIFECYCLE_CLOSED;
}

coquic_zero_rtt_status_t from_cpp(coquic::core::ZeroRttStatus status) {
    switch (status) {
    case coquic::core::ZeroRttStatus::unavailable:
        return COQUIC_ZERO_RTT_UNAVAILABLE;
    case coquic::core::ZeroRttStatus::not_attempted:
        return COQUIC_ZERO_RTT_NOT_ATTEMPTED;
    case coquic::core::ZeroRttStatus::attempted:
        return COQUIC_ZERO_RTT_ATTEMPTED;
    case coquic::core::ZeroRttStatus::accepted:
        return COQUIC_ZERO_RTT_ACCEPTED;
    case coquic::core::ZeroRttStatus::rejected:
        return COQUIC_ZERO_RTT_REJECTED;
    }
    return COQUIC_ZERO_RTT_UNAVAILABLE;
}

coquic_packet_inspection_direction_t from_cpp(coquic::core::PacketInspectionDirection direction) {
    switch (direction) {
    case coquic::core::PacketInspectionDirection::outbound:
        return COQUIC_PACKET_INSPECTION_OUTBOUND;
    case coquic::core::PacketInspectionDirection::inbound:
        return COQUIC_PACKET_INSPECTION_INBOUND;
    }
    return COQUIC_PACKET_INSPECTION_OUTBOUND;
}

coquic_packet_inspection_packet_type_t
from_cpp(coquic::core::PacketInspectionPacketType packet_type) {
    switch (packet_type) {
    case coquic::core::PacketInspectionPacketType::initial:
        return COQUIC_PACKET_INSPECTION_INITIAL;
    case coquic::core::PacketInspectionPacketType::zero_rtt:
        return COQUIC_PACKET_INSPECTION_ZERO_RTT;
    case coquic::core::PacketInspectionPacketType::handshake:
        return COQUIC_PACKET_INSPECTION_HANDSHAKE;
    case coquic::core::PacketInspectionPacketType::one_rtt:
        return COQUIC_PACKET_INSPECTION_ONE_RTT;
    }
    return COQUIC_PACKET_INSPECTION_INITIAL;
}

coquic::core::ZeroRttConfig to_cpp(coquic_zero_rtt_config_t config) {
    return coquic::core::ZeroRttConfig{
        .attempt = config.attempt != 0,
        .allow = config.allow != 0,
        .application_context = to_vector(config.application_context),
    };
}

coquic::core::TransportConfig to_cpp(const coquic_transport_config_t &config) {
    return coquic::core::TransportConfig{
        .max_idle_timeout = config.max_idle_timeout,
        .max_udp_payload_size = config.max_udp_payload_size,
        .pmtud_enabled = config.pmtud_enabled != 0,
        .pmtud_base_datagram_size = config.pmtud_base_datagram_size,
        .pmtud_max_datagram_size = config.pmtud_max_datagram_size,
        .active_connection_id_limit = config.active_connection_id_limit,
        .disable_active_migration = config.disable_active_migration != 0,
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
        .congestion_control = congestion_control_to_cpp(config.congestion_control),
        .enable_hystart_plus_plus = config.enable_hystart_plus_plus != 0,
        .send_stream_fairness = config.send_stream_fairness != 0,
        .enable_latency_spin_bit = config.enable_latency_spin_bit != 0,
        .grease_reserved_versions = config.grease_reserved_versions != 0,
        .grease_quic_bit = config.grease_quic_bit != 0,
        .enable_optimistic_ack_mitigation = config.enable_optimistic_ack_mitigation != 0,
    };
}

std::optional<coquic::core::TlsIdentity> to_cpp(const coquic_tls_identity_t *identity) {
    if (identity == nullptr) {
        return std::nullopt;
    }
    return coquic::core::TlsIdentity{
        .certificate_pem = to_string(identity->certificate_pem, identity->certificate_pem_length),
        .private_key_pem = to_string(identity->private_key_pem, identity->private_key_pem_length),
    };
}

coquic::core::EndpointConfig to_cpp(const coquic_endpoint_config_t &config) {
    std::vector<std::uint32_t> supported_versions;
    if (config.supported_versions != nullptr && config.supported_versions_count != 0) {
        supported_versions.assign(config.supported_versions,
                                  config.supported_versions + config.supported_versions_count);
    } else {
        supported_versions = {1};
    }

    return coquic::core::EndpointConfig{
        .role = role_to_cpp(config.role),
        .supported_versions = std::move(supported_versions),
        .verify_peer = config.verify_peer != 0,
        .retry_enabled = config.retry_enabled != 0,
        .max_server_connections =
            config.size >= kEndpointConfigSizeV2 ? config.max_server_connections : 0,
        .application_protocol =
            to_string(config.application_protocol, config.application_protocol_length),
        .identity = to_cpp(config.identity),
        .transport = to_cpp(config.transport),
        .max_outbound_datagram_size = config.max_outbound_datagram_size,
        .zero_rtt = to_cpp(config.zero_rtt),
        .qlog = std::nullopt,
        .tls_keylog_path = std::nullopt,
        .emit_shared_receive_stream_data = config.emit_shared_receive_stream_data != 0,
        .enable_packet_inspection = config.enable_packet_inspection != 0,
        .allow_peer_address_change = config.allow_peer_address_change != 0,
    };
}

std::optional<coquic::core::ResumptionState>
to_cpp(const coquic_resumption_state_t *resumption_state) {
    if (resumption_state == nullptr) {
        return std::nullopt;
    }
    return coquic::core::ResumptionState{
        .serialized = to_vector(resumption_state->serialized),
    };
}

coquic::core::ClientConnectionConfig to_cpp(const coquic_client_connection_config_t &config) {
    std::optional<coquic::core::ConnectionId> original_destination_connection_id;
    if (config.has_original_destination_connection_id != 0) {
        original_destination_connection_id = to_vector(config.original_destination_connection_id);
    }

    std::optional<coquic::core::ConnectionId> retry_source_connection_id;
    if (config.has_retry_source_connection_id != 0) {
        retry_source_connection_id = to_vector(config.retry_source_connection_id);
    }

    return coquic::core::ClientConnectionConfig{
        .source_connection_id = to_vector(config.source_connection_id),
        .initial_destination_connection_id = to_vector(config.initial_destination_connection_id),
        .original_destination_connection_id = std::move(original_destination_connection_id),
        .retry_source_connection_id = std::move(retry_source_connection_id),
        .retry_token = to_vector(config.retry_token),
        .original_version = config.original_version,
        .initial_version = config.initial_version,
        .reacted_to_version_negotiation = config.reacted_to_version_negotiation != 0,
        .server_name = to_string(config.server_name, config.server_name_length),
        .resumption_state = to_cpp(config.resumption_state),
        .zero_rtt = to_cpp(config.zero_rtt),
    };
}

coquic_local_error_t from_cpp(const coquic::core::LocalError &error) {
    return coquic_local_error_t{
        .connection = from_optional_connection_handle(error.connection),
        .code = from_cpp(error.code),
        .stream_id = from_optional_stream_id(error.stream_id),
    };
}

coquic_preferred_address_t from_cpp(const coquic::core::PreferredAddress &address) {
    coquic_preferred_address_t out{};
    copy_bytes(address.ipv4_address, out.ipv4_address);
    out.ipv4_port = address.ipv4_port;
    copy_bytes(address.ipv6_address, out.ipv6_address);
    out.ipv6_port = address.ipv6_port;
    out.connection_id = bytes_view(address.connection_id);
    copy_bytes(address.stateless_reset_token, out.stateless_reset_token);
    return out;
}

coquic_effect_t from_cpp(const coquic::core::Effect &effect) {
    return std::visit(
        [](const auto &value) -> coquic_effect_t {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, coquic::core::SendDatagram>) {
                // Network output borrows datagram bytes from the owning result.
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_SEND_DATAGRAM,
                    .as =
                        {
                            .send_datagram =
                                {
                                    .connection = value.connection,
                                    .route_handle = from_optional_route_handle(value.route_handle),
                                    .bytes = bytes_view(value.bytes),
                                    .ecn = from_cpp(value.ecn),
                                    .is_pmtu_probe =
                                        static_cast<std::uint8_t>(value.is_pmtu_probe ? 1 : 0),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::ReceiveStreamData>) {
                // Application data events expose byte views and stream-final state.
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_RECEIVE_STREAM_DATA,
                    .as =
                        {
                            .receive_stream_data =
                                {
                                    .connection = value.connection,
                                    .stream_id = value.stream_id,
                                    .bytes = bytes_view(value.bytes),
                                    .fin = static_cast<std::uint8_t>(value.fin ? 1 : 0),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::ReceiveDatagramData>) {
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_RECEIVE_DATAGRAM_DATA,
                    .as =
                        {
                            .receive_datagram_data =
                                {
                                    .connection = value.connection,
                                    .bytes = bytes_view(value.bytes),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::PeerResetStream>) {
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_PEER_RESET_STREAM,
                    .as =
                        {
                            .peer_reset_stream =
                                {
                                    .connection = value.connection,
                                    .stream_id = value.stream_id,
                                    .application_error_code = value.application_error_code,
                                    .final_size = value.final_size,
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::PeerStopSending>) {
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_PEER_STOP_SENDING,
                    .as =
                        {
                            .peer_stop_sending =
                                {
                                    .connection = value.connection,
                                    .stream_id = value.stream_id,
                                    .application_error_code = value.application_error_code,
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::StateEvent>) {
                // Lifecycle and state events are value-only notifications.
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_STATE_EVENT,
                    .as =
                        {
                            .state_event =
                                {
                                    .connection = value.connection,
                                    .change = from_cpp(value.change),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::ConnectionLifecycleEvent>) {
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_CONNECTION_LIFECYCLE_EVENT,
                    .as =
                        {
                            .connection_lifecycle_event =
                                {
                                    .connection = value.connection,
                                    .event = from_cpp(value.event),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::PeerPreferredAddressAvailable>) {
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_PEER_PREFERRED_ADDRESS_AVAILABLE,
                    .as =
                        {
                            .peer_preferred_address_available =
                                {
                                    .connection = value.connection,
                                    .preferred_address = from_cpp(value.preferred_address),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::ResumptionStateAvailable>) {
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_RESUMPTION_STATE_AVAILABLE,
                    .as =
                        {
                            .resumption_state_available =
                                {
                                    .connection = value.connection,
                                    .serialized = bytes_view(value.state.serialized),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::ZeroRttStatusEvent>) {
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_ZERO_RTT_STATUS_EVENT,
                    .as =
                        {
                            .zero_rtt_status_event =
                                {
                                    .connection = value.connection,
                                    .status = from_cpp(value.status),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::PacketInspection>) {
                // Packet inspection mirrors wire metadata without copying packet buffers.
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_PACKET_INSPECTION,
                    .as =
                        {
                            .packet_inspection =
                                {
                                    .connection = value.connection,
                                    .direction = from_cpp(value.direction),
                                    .packet_type = from_cpp(value.packet_type),
                                    .datagram_id = value.datagram_id,
                                    .datagram_length = value.datagram_length,
                                    .datagram_offset = value.datagram_offset,
                                    .packet_length = value.packet_length,
                                    .version = value.version,
                                    .destination_connection_id =
                                        bytes_view(value.destination_connection_id),
                                    .source_connection_id = bytes_view(value.source_connection_id),
                                    .token = bytes_view(value.token),
                                    .spin_bit = static_cast<std::uint8_t>(value.spin_bit ? 1 : 0),
                                    .key_phase = static_cast<std::uint8_t>(value.key_phase ? 1 : 0),
                                    .packet_number_length = value.packet_number_length,
                                    .packet_number = value.packet_number,
                                    .encrypted_packet = bytes_view(value.encrypted_packet),
                                    .plaintext_payload = bytes_view(value.plaintext_payload),
                                },
                        },
                };
            } else if constexpr (std::is_same_v<T, coquic::core::NewTokenAvailable>) {
                // New-token events publish resumption material as borrowed bytes.
                return coquic_effect_t{
                    .kind = COQUIC_EFFECT_NEW_TOKEN_AVAILABLE,
                    .as =
                        {
                            .new_token_available =
                                {
                                    .connection = value.connection,
                                    .token = bytes_view(value.token),
                                },
                        },
                };
            }
        },
        effect);
}

std::optional<coquic::core::ConnectionHandle>
created_connection_handle(const coquic::core::Result &result) {
    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<coquic::core::ConnectionLifecycleEvent>(&effect);
            event != nullptr && event->event == coquic::core::Lifecycle::created) {
            return event->connection;
        }
    }
    return std::nullopt;
}

coquic_status_t validate_endpoint_call(coquic_endpoint_t *endpoint, coquic_result_t **out_result) {
    if (out_result != nullptr) {
        *out_result = nullptr;
    }
    if (endpoint == nullptr || out_result == nullptr) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return COQUIC_STATUS_OK;
}

coquic_status_t advance_connection(coquic_endpoint_t *endpoint,
                                   coquic_connection_handle_t connection,
                                   coquic::core::ConnectionInput input, coquic_time_us_t now,
                                   coquic_result_t **out_result) {
    const auto valid = validate_endpoint_call(endpoint, out_result);
    if (valid != COQUIC_STATUS_OK) {
        return valid;
    }
    return ffi_guard([&] {
        auto result = endpoint->endpoint.advance_connection(
            coquic::core::ConnectionCommand{
                .connection = connection,
                .input = std::move(input),
            },
            to_time_point(now));
        *out_result = new coquic_result(std::move(result));
    });
}

std::optional<coquic::core::ConnectionInput> to_cpp(const coquic_connection_input_t &input) {
    switch (input.kind) {
    case COQUIC_CONNECTION_INPUT_SEND_STREAM:
        if (input.as.send_stream.size < kSendStreamDataSizeV1) {
            return std::nullopt;
        }
        return coquic::core::SendStreamData{
            .stream_id = input.as.send_stream.stream_id,
            .bytes = to_vector(input.as.send_stream.bytes),
            .fin = input.as.send_stream.fin != 0,
            .priority = input.as.send_stream.size >= kSendStreamDataSizeV2
                            ? input.as.send_stream.priority
                            : 0,
        };
    case COQUIC_CONNECTION_INPUT_SEND_DATAGRAM:
        if (input.as.send_datagram.size < kSendDatagramDataSizeV1) {
            return std::nullopt;
        }
        return coquic::core::SendDatagramData{
            .bytes = to_vector(input.as.send_datagram.bytes),
            .priority = input.as.send_datagram.size >= kSendDatagramDataSizeV2
                            ? input.as.send_datagram.priority
                            : 0,
        };
    case COQUIC_CONNECTION_INPUT_RESET_STREAM:
        if (input.as.reset_stream.size < kResetStreamSizeV1) {
            return std::nullopt;
        }
        return coquic::core::ResetStream{
            .stream_id = input.as.reset_stream.stream_id,
            .application_error_code = input.as.reset_stream.application_error_code,
        };
    case COQUIC_CONNECTION_INPUT_STOP_SENDING:
        if (input.as.stop_sending.size < kStopSendingSizeV1) {
            return std::nullopt;
        }
        return coquic::core::StopSending{
            .stream_id = input.as.stop_sending.stream_id,
            .application_error_code = input.as.stop_sending.application_error_code,
        };
    case COQUIC_CONNECTION_INPUT_CLOSE:
        if (input.as.close.size < kCloseConnectionSizeV1) {
            return std::nullopt;
        }
        return coquic::core::CloseConnection{
            .application_error_code = input.as.close.application_error_code,
            .reason_phrase =
                to_string(input.as.close.reason_phrase, input.as.close.reason_phrase_length),
        };
    case COQUIC_CONNECTION_INPUT_REQUEST_KEY_UPDATE:
        return coquic::core::RequestKeyUpdate{};
    case COQUIC_CONNECTION_INPUT_REQUEST_MIGRATION:
        if (input.as.request_migration.size < kRequestConnectionMigrationSizeV1) {
            return std::nullopt;
        }
        return coquic::core::RequestConnectionMigration{
            .route_handle = input.as.request_migration.route_handle,
            .reason = migration_reason_to_cpp(input.as.request_migration.reason),
            .address_validation_identity =
                to_vector(input.as.request_migration.address_validation_identity),
        };
    default:
        return std::nullopt;
    }
}

} // namespace

extern "C" {

uint32_t coquic_ffi_abi_version(void) {
    return COQUIC_FFI_ABI_VERSION;
}

void coquic_transport_config_init(coquic_transport_config_t *config) {
    if (config == nullptr) {
        return;
    }
    const coquic::core::TransportConfig defaults;
    *config = coquic_transport_config_t{
        .max_idle_timeout = defaults.max_idle_timeout,
        .max_udp_payload_size = defaults.max_udp_payload_size,
        .pmtud_enabled = static_cast<std::uint8_t>(defaults.pmtud_enabled ? 1 : 0),
        .pmtud_base_datagram_size = defaults.pmtud_base_datagram_size,
        .pmtud_max_datagram_size = defaults.pmtud_max_datagram_size,
        .active_connection_id_limit = defaults.active_connection_id_limit,
        .disable_active_migration =
            static_cast<std::uint8_t>(defaults.disable_active_migration ? 1 : 0),
        .ack_delay_exponent = defaults.ack_delay_exponent,
        .max_ack_delay = defaults.max_ack_delay,
        .ack_eliciting_threshold = defaults.ack_eliciting_threshold,
        .initial_max_data = defaults.initial_max_data,
        .initial_max_stream_data_bidi_local = defaults.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote = defaults.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = defaults.initial_max_stream_data_uni,
        .initial_max_streams_bidi = defaults.initial_max_streams_bidi,
        .initial_max_streams_uni = defaults.initial_max_streams_uni,
        .max_datagram_frame_size = defaults.max_datagram_frame_size,
        .congestion_control = from_cpp(defaults.congestion_control),
        .enable_hystart_plus_plus =
            static_cast<std::uint8_t>(defaults.enable_hystart_plus_plus ? 1 : 0),
        .send_stream_fairness = static_cast<std::uint8_t>(defaults.send_stream_fairness ? 1 : 0),
        .enable_latency_spin_bit =
            static_cast<std::uint8_t>(defaults.enable_latency_spin_bit ? 1 : 0),
        .grease_reserved_versions =
            static_cast<std::uint8_t>(defaults.grease_reserved_versions ? 1 : 0),
        .grease_quic_bit = static_cast<std::uint8_t>(defaults.grease_quic_bit ? 1 : 0),
        .enable_optimistic_ack_mitigation =
            static_cast<std::uint8_t>(defaults.enable_optimistic_ack_mitigation ? 1 : 0),
    };
}

void coquic_endpoint_config_init(coquic_endpoint_config_t *config) {
    if (config == nullptr) {
        return;
    }
    coquic_transport_config_t transport{};
    coquic_transport_config_init(&transport);
    *config = coquic_endpoint_config_t{
        .size = sizeof(coquic_endpoint_config_t),
        .role = COQUIC_ROLE_CLIENT,
        .supported_versions = nullptr,
        .supported_versions_count = 0,
        .verify_peer = 1,
        .retry_enabled = 0,
        .application_protocol = "coquic",
        .application_protocol_length = 6,
        .identity = nullptr,
        .transport = transport,
        .max_outbound_datagram_size = 1200,
        .zero_rtt = {},
        .emit_shared_receive_stream_data = 0,
        .enable_packet_inspection = 0,
        .allow_peer_address_change = 1,
        .max_server_connections = 0,
    };
}

void coquic_client_connection_config_init(coquic_client_connection_config_t *config) {
    if (config == nullptr) {
        return;
    }
    *config = coquic_client_connection_config_t{
        .size = sizeof(coquic_client_connection_config_t),
        .source_connection_id = {},
        .initial_destination_connection_id = {},
        .original_destination_connection_id = {},
        .has_original_destination_connection_id = 0,
        .retry_source_connection_id = {},
        .has_retry_source_connection_id = 0,
        .retry_token = {},
        .original_version = 1,
        .initial_version = 1,
        .reacted_to_version_negotiation = 0,
        .server_name = "localhost",
        .server_name_length = 9,
        .resumption_state = nullptr,
        .zero_rtt = {},
    };
}

coquic_status_t coquic_endpoint_create(const coquic_endpoint_config_t *config,
                                       coquic_endpoint_t **out_endpoint) {
    if (out_endpoint != nullptr) {
        *out_endpoint = nullptr;
    }
    if (config == nullptr || out_endpoint == nullptr || config->size < kEndpointConfigSizeV1) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] { *out_endpoint = new coquic_endpoint(to_cpp(*config)); });
}

void coquic_endpoint_destroy(coquic_endpoint_t *endpoint) {
    delete endpoint;
}

coquic_status_t coquic_endpoint_open_connection(coquic_endpoint_t *endpoint,
                                                const coquic_open_connection_t *input,
                                                coquic_time_us_t now,
                                                coquic_result_t **out_result) {
    const auto valid = validate_endpoint_call(endpoint, out_result);
    if (valid != COQUIC_STATUS_OK) {
        return valid;
    }
    if (input == nullptr || input->size < kOpenConnectionSizeV1 ||
        input->connection.size < kClientConnectionConfigSizeV1) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        auto result = endpoint->endpoint.open_connection(
            coquic::core::OpenConnection{
                .connection = to_cpp(input->connection),
                .initial_route_handle = input->initial_route_handle,
                .address_validation_identity = to_vector(input->address_validation_identity),
            },
            to_time_point(now));
        *out_result = new coquic_result(std::move(result));
    });
}

coquic_status_t coquic_endpoint_input_datagram(coquic_endpoint_t *endpoint,
                                               const coquic_inbound_datagram_t *input,
                                               coquic_time_us_t now, coquic_result_t **out_result) {
    const auto valid = validate_endpoint_call(endpoint, out_result);
    if (valid != COQUIC_STATUS_OK) {
        return valid;
    }
    if (input == nullptr || input->size < kInboundDatagramSizeV1) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        auto result = endpoint->endpoint.input_datagram(
            coquic::core::InboundDatagram{
                .bytes = to_vector(input->bytes),
                .route_handle = to_optional(input->route_handle),
                .address_validation_identity = to_vector(input->address_validation_identity),
                .ecn = ecn_to_cpp(input->ecn),
            },
            to_time_point(now));
        *out_result = new coquic_result(std::move(result));
    });
}

coquic_status_t coquic_endpoint_update_path_mtu(coquic_endpoint_t *endpoint,
                                                const coquic_path_mtu_update_t *input,
                                                coquic_time_us_t now,
                                                coquic_result_t **out_result) {
    const auto valid = validate_endpoint_call(endpoint, out_result);
    if (valid != COQUIC_STATUS_OK) {
        return valid;
    }
    if (input == nullptr || input->size < kPathMtuUpdateSizeV1) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        auto result = endpoint->endpoint.update_path_mtu(
            coquic::core::PathMtuUpdate{
                .route_handle = to_optional(input->route_handle),
                .max_udp_payload_size = input->max_udp_payload_size,
            },
            to_time_point(now));
        *out_result = new coquic_result(std::move(result));
    });
}

coquic_status_t coquic_endpoint_timer_expired(coquic_endpoint_t *endpoint, coquic_time_us_t now,
                                              coquic_result_t **out_result) {
    const auto valid = validate_endpoint_call(endpoint, out_result);
    if (valid != COQUIC_STATUS_OK) {
        return valid;
    }
    return ffi_guard([&] {
        auto result = endpoint->endpoint.timer_expired(to_time_point(now));
        *out_result = new coquic_result(std::move(result));
    });
}

coquic_status_t coquic_connection_send_stream(coquic_endpoint_t *endpoint,
                                              coquic_connection_handle_t connection,
                                              const coquic_send_stream_data_t *input,
                                              coquic_time_us_t now, coquic_result_t **out_result) {
    if (input == nullptr || input->size < kSendStreamDataSizeV1) {
        if (out_result != nullptr) {
            *out_result = nullptr;
        }
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return advance_connection(
        endpoint, connection,
        coquic::core::SendStreamData{
            .stream_id = input->stream_id,
            .bytes = to_vector(input->bytes),
            .fin = input->fin != 0,
            .priority = input->size >= kSendStreamDataSizeV2 ? input->priority : 0,
        },
        now, out_result);
}

coquic_status_t coquic_connection_send_datagram(coquic_endpoint_t *endpoint,
                                                coquic_connection_handle_t connection,
                                                const coquic_send_datagram_data_t *input,
                                                coquic_time_us_t now,
                                                coquic_result_t **out_result) {
    if (input == nullptr || input->size < kSendDatagramDataSizeV1) {
        if (out_result != nullptr) {
            *out_result = nullptr;
        }
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return advance_connection(
        endpoint, connection,
        coquic::core::SendDatagramData{
            .bytes = to_vector(input->bytes),
            .priority = input->size >= kSendDatagramDataSizeV2 ? input->priority : 0,
        },
        now, out_result);
}

coquic_status_t coquic_connection_reset_stream(coquic_endpoint_t *endpoint,
                                               coquic_connection_handle_t connection,
                                               const coquic_reset_stream_t *input,
                                               coquic_time_us_t now, coquic_result_t **out_result) {
    if (input == nullptr || input->size < kResetStreamSizeV1) {
        if (out_result != nullptr) {
            *out_result = nullptr;
        }
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return advance_connection(endpoint, connection,
                              coquic::core::ResetStream{
                                  .stream_id = input->stream_id,
                                  .application_error_code = input->application_error_code,
                              },
                              now, out_result);
}

coquic_status_t coquic_connection_stop_sending(coquic_endpoint_t *endpoint,
                                               coquic_connection_handle_t connection,
                                               const coquic_stop_sending_t *input,
                                               coquic_time_us_t now, coquic_result_t **out_result) {
    if (input == nullptr || input->size < kStopSendingSizeV1) {
        if (out_result != nullptr) {
            *out_result = nullptr;
        }
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return advance_connection(endpoint, connection,
                              coquic::core::StopSending{
                                  .stream_id = input->stream_id,
                                  .application_error_code = input->application_error_code,
                              },
                              now, out_result);
}

coquic_status_t coquic_connection_close(coquic_endpoint_t *endpoint,
                                        coquic_connection_handle_t connection,
                                        const coquic_close_connection_t *input,
                                        coquic_time_us_t now, coquic_result_t **out_result) {
    if (input == nullptr || input->size < kCloseConnectionSizeV1) {
        if (out_result != nullptr) {
            *out_result = nullptr;
        }
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return advance_connection(
        endpoint, connection,
        coquic::core::CloseConnection{
            .application_error_code = input->application_error_code,
            .reason_phrase = to_string(input->reason_phrase, input->reason_phrase_length),
        },
        now, out_result);
}

coquic_status_t coquic_connection_request_key_update(coquic_endpoint_t *endpoint,
                                                     coquic_connection_handle_t connection,
                                                     coquic_time_us_t now,
                                                     coquic_result_t **out_result) {
    return advance_connection(endpoint, connection, coquic::core::RequestKeyUpdate{}, now,
                              out_result);
}

coquic_status_t
coquic_connection_request_migration(coquic_endpoint_t *endpoint,
                                    coquic_connection_handle_t connection,
                                    const coquic_request_connection_migration_t *input,
                                    coquic_time_us_t now, coquic_result_t **out_result) {
    if (input == nullptr || input->size < kRequestConnectionMigrationSizeV1) {
        if (out_result != nullptr) {
            *out_result = nullptr;
        }
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return advance_connection(
        endpoint, connection,
        coquic::core::RequestConnectionMigration{
            .route_handle = input->route_handle,
            .reason = migration_reason_to_cpp(input->reason),
            .address_validation_identity = to_vector(input->address_validation_identity),
        },
        now, out_result);
}

coquic_status_t coquic_connection_advance(coquic_endpoint_t *endpoint,
                                          coquic_connection_handle_t connection,
                                          const coquic_connection_input_t *input,
                                          coquic_time_us_t now, coquic_result_t **out_result) {
    if (input == nullptr) {
        if (out_result != nullptr) {
            *out_result = nullptr;
        }
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    auto cpp_input = to_cpp(*input);
    if (!cpp_input.has_value()) {
        if (out_result != nullptr) {
            *out_result = nullptr;
        }
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return advance_connection(endpoint, connection, std::move(*cpp_input), now, out_result);
}

coquic_status_t coquic_quic_connect(coquic_endpoint_t *endpoint,
                                    const coquic_open_connection_t *input, coquic_time_us_t now,
                                    coquic_connection_handle_t *out_connection,
                                    coquic_result_t **out_result) {
    if (out_connection != nullptr) {
        *out_connection = 0;
    }
    const auto valid = validate_endpoint_call(endpoint, out_result);
    if (valid != COQUIC_STATUS_OK) {
        return valid;
    }
    if (out_connection == nullptr || input == nullptr || input->size < kOpenConnectionSizeV1 ||
        input->connection.size < kClientConnectionConfigSizeV1) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] {
        auto result = endpoint->endpoint.open_connection(
            coquic::core::OpenConnection{
                .connection = to_cpp(input->connection),
                .initial_route_handle = input->initial_route_handle,
                .address_validation_identity = to_vector(input->address_validation_identity),
            },
            to_time_point(now));
        if (const auto handle = created_connection_handle(result); handle.has_value()) {
            *out_connection = *handle;
        }
        *out_result = new coquic_result(std::move(result));
    });
}

coquic_status_t coquic_quic_receive_datagram(coquic_endpoint_t *endpoint,
                                             const coquic_inbound_datagram_t *input,
                                             coquic_time_us_t now, coquic_result_t **out_result) {
    return coquic_endpoint_input_datagram(endpoint, input, now, out_result);
}

coquic_status_t coquic_quic_update_path_mtu(coquic_endpoint_t *endpoint,
                                            const coquic_path_mtu_update_t *input,
                                            coquic_time_us_t now, coquic_result_t **out_result) {
    return coquic_endpoint_update_path_mtu(endpoint, input, now, out_result);
}

coquic_status_t coquic_quic_timer_expired(coquic_endpoint_t *endpoint, coquic_time_us_t now,
                                          coquic_result_t **out_result) {
    return coquic_endpoint_timer_expired(endpoint, now, out_result);
}

coquic_status_t coquic_quic_connection_send_stream(coquic_endpoint_t *endpoint,
                                                   coquic_connection_handle_t connection,
                                                   const coquic_send_stream_data_t *input,
                                                   coquic_time_us_t now,
                                                   coquic_result_t **out_result) {
    return coquic_connection_send_stream(endpoint, connection, input, now, out_result);
}

coquic_status_t coquic_quic_connection_send_datagram(coquic_endpoint_t *endpoint,
                                                     coquic_connection_handle_t connection,
                                                     const coquic_send_datagram_data_t *input,
                                                     coquic_time_us_t now,
                                                     coquic_result_t **out_result) {
    return coquic_connection_send_datagram(endpoint, connection, input, now, out_result);
}

coquic_status_t coquic_quic_connection_reset_stream(coquic_endpoint_t *endpoint,
                                                    coquic_connection_handle_t connection,
                                                    const coquic_reset_stream_t *input,
                                                    coquic_time_us_t now,
                                                    coquic_result_t **out_result) {
    return coquic_connection_reset_stream(endpoint, connection, input, now, out_result);
}

coquic_status_t coquic_quic_connection_stop_sending(coquic_endpoint_t *endpoint,
                                                    coquic_connection_handle_t connection,
                                                    const coquic_stop_sending_t *input,
                                                    coquic_time_us_t now,
                                                    coquic_result_t **out_result) {
    return coquic_connection_stop_sending(endpoint, connection, input, now, out_result);
}

coquic_status_t coquic_quic_connection_close(coquic_endpoint_t *endpoint,
                                             coquic_connection_handle_t connection,
                                             const coquic_close_connection_t *input,
                                             coquic_time_us_t now, coquic_result_t **out_result) {
    return coquic_connection_close(endpoint, connection, input, now, out_result);
}

coquic_status_t coquic_quic_connection_request_key_update(coquic_endpoint_t *endpoint,
                                                          coquic_connection_handle_t connection,
                                                          coquic_time_us_t now,
                                                          coquic_result_t **out_result) {
    return coquic_connection_request_key_update(endpoint, connection, now, out_result);
}

coquic_status_t coquic_quic_connection_advance(coquic_endpoint_t *endpoint,
                                               coquic_connection_handle_t connection,
                                               const coquic_connection_input_t *input,
                                               coquic_time_us_t now, coquic_result_t **out_result) {
    return coquic_connection_advance(endpoint, connection, input, now, out_result);
}

// Public C ABI helpers intentionally keep adjacent scalar stream command fields.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
coquic_status_t coquic_quic_stream_send(coquic_endpoint_t *endpoint,
                                        coquic_connection_handle_t connection,
                                        coquic_stream_id_t stream_id, coquic_bytes_t bytes,
                                        uint8_t fin, coquic_time_us_t now,
                                        coquic_result_t **out_result) {
    coquic_send_stream_data_t input{
        .size = sizeof(coquic_send_stream_data_t),
        .stream_id = stream_id,
        .bytes = bytes,
        .fin = fin,
        .priority = 0,
    };
    return coquic_connection_send_stream(endpoint, connection, &input, now, out_result);
}

coquic_status_t coquic_quic_stream_finish(coquic_endpoint_t *endpoint,
                                          coquic_connection_handle_t connection,
                                          coquic_stream_id_t stream_id, coquic_time_us_t now,
                                          coquic_result_t **out_result) {
    return coquic_quic_stream_send(endpoint, connection, stream_id, coquic_bytes_t{}, 1, now,
                                   out_result);
}

coquic_status_t coquic_quic_stream_reset(coquic_endpoint_t *endpoint,
                                         coquic_connection_handle_t connection,
                                         coquic_stream_id_t stream_id,
                                         uint64_t application_error_code, coquic_time_us_t now,
                                         coquic_result_t **out_result) {
    coquic_reset_stream_t input{
        .size = sizeof(coquic_reset_stream_t),
        .stream_id = stream_id,
        .application_error_code = application_error_code,
    };
    return coquic_connection_reset_stream(endpoint, connection, &input, now, out_result);
}

coquic_status_t
coquic_quic_stream_stop_sending(coquic_endpoint_t *endpoint, coquic_connection_handle_t connection,
                                coquic_stream_id_t stream_id, uint64_t application_error_code,
                                coquic_time_us_t now, coquic_result_t **out_result) {
    coquic_stop_sending_t input{
        .size = sizeof(coquic_stop_sending_t),
        .stream_id = stream_id,
        .application_error_code = application_error_code,
    };
    return coquic_connection_stop_sending(endpoint, connection, &input, now, out_result);
}
// NOLINTEND(bugprone-easily-swappable-parameters)

size_t coquic_endpoint_connection_count(const coquic_endpoint_t *endpoint) {
    if (endpoint == nullptr) {
        return 0;
    }
    return endpoint->endpoint.connection_count();
}

uint8_t coquic_endpoint_has_send_continuation_pending(const coquic_endpoint_t *endpoint) {
    if (endpoint == nullptr) {
        return 0;
    }
    return static_cast<std::uint8_t>(endpoint->endpoint.has_send_continuation_pending() ? 1 : 0);
}

uint8_t coquic_endpoint_has_pending_stream_send(const coquic_endpoint_t *endpoint) {
    if (endpoint == nullptr) {
        return 0;
    }
    return static_cast<std::uint8_t>(endpoint->endpoint.has_pending_stream_send() ? 1 : 0);
}

coquic_optional_time_us_t coquic_endpoint_next_wakeup(const coquic_endpoint_t *endpoint) {
    if (endpoint == nullptr) {
        return {.has_value = 0, .value = 0};
    }
    return from_optional(endpoint->endpoint.next_wakeup());
}

void coquic_result_destroy(coquic_result_t *result) {
    delete result;
}

size_t coquic_result_effect_count(const coquic_result_t *result) {
    if (result == nullptr) {
        return 0;
    }
    return result->result.effects.size();
}

coquic_status_t coquic_result_effect_at(const coquic_result_t *result, size_t index,
                                        coquic_effect_t *out_effect) {
    if (result == nullptr || out_effect == nullptr || index >= result->result.effects.size()) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    return ffi_guard([&] { *out_effect = from_cpp(result->result.effects[index]); });
}

coquic_optional_time_us_t coquic_result_next_wakeup(const coquic_result_t *result) {
    if (result == nullptr) {
        return {.has_value = 0, .value = 0};
    }
    return from_optional(result->result.next_wakeup);
}

uint8_t coquic_result_has_local_error(const coquic_result_t *result) {
    if (result == nullptr) {
        return 0;
    }
    return static_cast<std::uint8_t>(result->result.local_error.has_value() ? 1 : 0);
}

coquic_status_t coquic_result_local_error(const coquic_result_t *result,
                                          coquic_local_error_t *out_error) {
    if (result == nullptr || out_error == nullptr || !result->result.local_error.has_value()) {
        return COQUIC_STATUS_INVALID_ARGUMENT;
    }
    *out_error = from_cpp(*result->result.local_error);
    return COQUIC_STATUS_OK;
}

uint8_t coquic_result_send_continuation_pending(const coquic_result_t *result) {
    if (result == nullptr) {
        return 0;
    }
    return static_cast<std::uint8_t>(result->result.send_continuation_pending ? 1 : 0);
}

} // extern "C"
