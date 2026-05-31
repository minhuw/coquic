#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace coquic::core {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration = std::chrono::microseconds;
using ConnectionHandle = std::uint64_t;
using RouteHandle = std::uint64_t;
using StreamId = std::uint64_t;
using ConnectionId = std::vector<std::byte>;

enum class Role : std::uint8_t {
    client,
    server,
};

enum class CongestionControl : std::uint8_t {
    newreno,
    cubic,
    bbr,
    copa,
};

enum class EcnCodepoint : std::uint8_t {
    unavailable,
    not_ect,
    ect0,
    ect1,
    ce,
};

enum class StateChange : std::uint8_t {
    handshake_ready,
    handshake_confirmed,
    failed,
};

enum class LocalErrorCode : std::uint8_t {
    unsupported_operation,
    invalid_stream_id,
    invalid_stream_direction,
    send_side_closed,
    receive_side_closed,
    final_size_conflict,
    datagram_not_supported,
    datagram_too_large,
};

enum class Lifecycle : std::uint8_t {
    created,
    accepted,
    closed,
};

enum class MigrationReason : std::uint8_t {
    active,
    preferred_address,
};

enum class ZeroRttStatus : std::uint8_t {
    unavailable,
    not_attempted,
    attempted,
    accepted,
    rejected,
};

enum class PacketInspectionDirection : std::uint8_t {
    outbound,
    inbound,
};

enum class PacketInspectionPacketType : std::uint8_t {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
};

struct TlsIdentity {
    std::string certificate_pem;
    std::string private_key_pem;
};

struct TransportConfig {
    std::uint64_t max_idle_timeout = 0;
    std::uint64_t max_udp_payload_size = 65527;
    bool pmtud_enabled = true;
    std::size_t pmtud_base_datagram_size = 1200;
    std::size_t pmtud_max_datagram_size = 0;
    std::uint64_t active_connection_id_limit = 2;
    bool disable_active_migration = false;
    std::uint64_t ack_delay_exponent = 3;
    std::uint64_t max_ack_delay = 25;
    std::uint64_t ack_eliciting_threshold = 2;
    std::uint64_t initial_max_data = 1 << 20;
    std::uint64_t initial_max_stream_data_bidi_local = 256 << 10;
    std::uint64_t initial_max_stream_data_bidi_remote = 256 << 10;
    std::uint64_t initial_max_stream_data_uni = 256 << 10;
    std::uint64_t initial_max_streams_bidi = 16;
    std::uint64_t initial_max_streams_uni = 16;
    std::uint64_t max_datagram_frame_size = 65535;
    CongestionControl congestion_control = CongestionControl::newreno;
    bool enable_hystart_plus_plus = true;
    bool send_stream_fairness = true;
    bool enable_latency_spin_bit = false;
    bool grease_reserved_versions = false;
    bool grease_quic_bit = false;
    bool enable_optimistic_ack_mitigation = false;
};

struct QlogConfig {
    std::filesystem::path directory;
};

struct ZeroRttConfig {
    bool attempt = false;
    bool allow = false;
    std::vector<std::byte> application_context;
};

struct ResumptionState {
    std::vector<std::byte> serialized;
};

struct EndpointConfig {
    Role role = Role::client;
    std::vector<std::uint32_t> supported_versions = {1};
    bool verify_peer = false;
    bool retry_enabled = false;
    std::string application_protocol = "coquic";
    std::optional<TlsIdentity> identity;
    TransportConfig transport;
    std::size_t max_outbound_datagram_size = 1200;
    ZeroRttConfig zero_rtt;
    std::optional<QlogConfig> qlog;
    std::optional<std::filesystem::path> tls_keylog_path;
    bool emit_shared_receive_stream_data = false;
    bool enable_packet_inspection = false;
    bool allow_peer_address_change = true;
};

struct ClientConnectionConfig {
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    std::optional<ConnectionId> original_destination_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
    std::vector<std::byte> retry_token;
    std::uint32_t original_version = 1;
    std::uint32_t initial_version = 1;
    bool reacted_to_version_negotiation = false;
    std::string server_name = "localhost";
    std::optional<ResumptionState> resumption_state;
    ZeroRttConfig zero_rtt;
};

struct OpenConnection {
    ClientConnectionConfig connection;
    RouteHandle initial_route_handle = 0;
    std::vector<std::byte> address_validation_identity;
};

struct InboundDatagram {
    std::vector<std::byte> bytes;
    std::optional<RouteHandle> route_handle;
    std::vector<std::byte> address_validation_identity;
    EcnCodepoint ecn = EcnCodepoint::unavailable;
};

struct PathMtuUpdate {
    std::optional<RouteHandle> route_handle;
    std::size_t max_udp_payload_size = 0;
};

struct SendStreamData {
    StreamId stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct SendDatagramData {
    std::vector<std::byte> bytes;
};

struct ResetStream {
    StreamId stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct StopSending {
    StreamId stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct CloseConnection {
    std::uint64_t application_error_code = 0;
    std::string reason_phrase;
};

struct RequestKeyUpdate {};

struct RequestConnectionMigration {
    RouteHandle route_handle = 0;
    MigrationReason reason = MigrationReason::active;
    std::vector<std::byte> address_validation_identity;
};

using ConnectionInput = std::variant<SendStreamData, SendDatagramData, ResetStream, StopSending,
                                     CloseConnection, RequestKeyUpdate, RequestConnectionMigration>;

struct ConnectionCommand {
    ConnectionHandle connection = 0;
    ConnectionInput input;
};

struct TimerExpired {};

using EndpointInput =
    std::variant<OpenConnection, InboundDatagram, PathMtuUpdate, ConnectionCommand, TimerExpired>;

struct SendDatagram {
    ConnectionHandle connection = 0;
    std::optional<RouteHandle> route_handle;
    std::vector<std::byte> bytes;
    EcnCodepoint ecn = EcnCodepoint::not_ect;
    bool is_pmtu_probe = false;
};

struct ReceiveStreamData {
    ConnectionHandle connection = 0;
    StreamId stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct ReceiveDatagramData {
    ConnectionHandle connection = 0;
    std::vector<std::byte> bytes;
};

struct PeerResetStream {
    ConnectionHandle connection = 0;
    StreamId stream_id = 0;
    std::uint64_t application_error_code = 0;
    std::uint64_t final_size = 0;
};

struct PeerStopSending {
    ConnectionHandle connection = 0;
    StreamId stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct StateEvent {
    ConnectionHandle connection = 0;
    StateChange change = StateChange::handshake_ready;
};

struct ConnectionLifecycleEvent {
    ConnectionHandle connection = 0;
    Lifecycle event = Lifecycle::created;
};

struct PreferredAddress {
    std::array<std::byte, 4> ipv4_address{};
    std::uint16_t ipv4_port = 0;
    std::array<std::byte, 16> ipv6_address{};
    std::uint16_t ipv6_port = 0;
    ConnectionId connection_id;
    std::array<std::byte, 16> stateless_reset_token{};
};

struct PeerPreferredAddressAvailable {
    ConnectionHandle connection = 0;
    PreferredAddress preferred_address;
};

struct ResumptionStateAvailable {
    ConnectionHandle connection = 0;
    ResumptionState state;
};

struct ZeroRttStatusEvent {
    ConnectionHandle connection = 0;
    ZeroRttStatus status = ZeroRttStatus::not_attempted;
};

struct NewTokenAvailable {
    ConnectionHandle connection = 0;
    std::vector<std::byte> token;
};

struct PacketInspection {
    ConnectionHandle connection = 0;
    PacketInspectionDirection direction = PacketInspectionDirection::outbound;
    PacketInspectionPacketType packet_type = PacketInspectionPacketType::initial;
    std::uint64_t datagram_id = 0;
    std::size_t datagram_length = 0;
    std::size_t datagram_offset = 0;
    std::size_t packet_length = 0;
    std::uint32_t version = 0;
    ConnectionId destination_connection_id;
    ConnectionId source_connection_id;
    std::vector<std::byte> token;
    bool spin_bit = false;
    bool key_phase = false;
    std::uint8_t packet_number_length = 0;
    std::uint64_t packet_number = 0;
    std::vector<std::byte> encrypted_packet;
    std::vector<std::byte> plaintext_payload;
};

using Effect = std::variant<SendDatagram, ReceiveStreamData, ReceiveDatagramData, PeerResetStream,
                            PeerStopSending, StateEvent, ConnectionLifecycleEvent,
                            PeerPreferredAddressAvailable, ResumptionStateAvailable,
                            ZeroRttStatusEvent, PacketInspection, NewTokenAvailable>;

struct LocalError {
    std::optional<ConnectionHandle> connection;
    LocalErrorCode code = LocalErrorCode::unsupported_operation;
    std::optional<StreamId> stream_id;
};

struct Result {
    std::vector<Effect> effects;
    std::optional<TimePoint> next_wakeup;
    std::optional<LocalError> local_error;
    bool send_continuation_pending = false;
};

struct ConnectionDiagnostics {
    ConnectionHandle handle = 0;
    std::uint8_t handshake_status = 0;
    bool started = false;
    bool handshake_confirmed = false;
    bool failed_emitted = false;
    std::uint32_t current_version = 0;
    std::size_t active_paths = 0;
    std::size_t active_streams = 0;
    std::size_t retired_streams = 0;
};

class Endpoint {
  public:
    explicit Endpoint(const EndpointConfig &config = {});
    ~Endpoint();

    Endpoint(const Endpoint &) = delete;
    Endpoint &operator=(const Endpoint &) = delete;
    Endpoint(Endpoint &&) noexcept;
    Endpoint &operator=(Endpoint &&) noexcept;

    Result advance(EndpointInput input, TimePoint now);
    Result open_connection(OpenConnection input, TimePoint now);
    Result input_datagram(InboundDatagram input, TimePoint now);
    Result update_path_mtu(PathMtuUpdate input, TimePoint now);
    Result advance_connection(ConnectionCommand input, TimePoint now);
    Result timer_expired(TimePoint now);

    std::optional<TimePoint> next_wakeup() const;
    std::size_t connection_count() const;
    std::vector<ConnectionDiagnostics> connection_diagnostics() const;
    bool has_send_continuation_pending() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

std::vector<SendDatagram> send_datagrams(const Result &result);
std::vector<ConnectionLifecycleEvent> lifecycle_events(const Result &result);
std::vector<StateEvent> state_events(const Result &result);
std::vector<ReceiveStreamData> receive_stream_events(const Result &result);
std::vector<ReceiveDatagramData> receive_datagram_events(const Result &result);

} // namespace coquic::core
