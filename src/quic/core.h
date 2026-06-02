#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include "src/quic/buffer.h"
#include "src/quic/crypto_stream.h"
#include "src/quic/packet.h"
#include "src/quic/resumption.h"
#include "src/quic/tls_adapter.h"
#include "src/quic/transport_parameters.h"
#include "src/quic/version.h"

namespace coquic::quic {

enum class QuicCongestionControlAlgorithm : std::uint8_t {
    newreno,
    cubic,
    bbr,
    copa,
};

std::string_view congestion_control_algorithm_name(QuicCongestionControlAlgorithm algorithm);
std::optional<QuicCongestionControlAlgorithm>
parse_congestion_control_algorithm(std::string_view value);

struct QuicTransportConfig {
    std::uint64_t max_idle_timeout = 0;
    std::uint64_t max_udp_payload_size = 65527;
    bool pmtud_enabled = true;
    std::size_t pmtud_base_datagram_size = 1200;
    std::size_t pmtud_max_datagram_size = 0;
    std::uint64_t active_connection_id_limit = 2;
    bool disable_active_migration = false;
    std::optional<PreferredAddress> preferred_address;
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
    QuicCongestionControlAlgorithm congestion_control = QuicCongestionControlAlgorithm::newreno;
    bool enable_hystart_plus_plus = true;
    bool send_stream_fairness = true;
    bool enable_latency_spin_bit = false;
    bool grease_reserved_versions = false;
    bool grease_quic_bit = false;
    bool enable_optimistic_ack_mitigation = false;
};

struct QuicQlogConfig {
    std::filesystem::path directory;
};

using QuicStatelessResetSecret = std::array<std::byte, 32>;
using QuicAddressValidationTokenSecret = std::array<std::byte, 32>;

enum class QuicAddressValidationIdentityClass : std::uint8_t {
    unknown,
    loopback,
    link_local,
    private_use,
    unique_local,
    global,
};

struct QuicRequestForgeryPolicyConfig {
    bool reject_loopback_addresses = false;
    bool reject_link_local_addresses = false;
    bool reject_private_use_addresses = false;
    bool reject_address_space_downgrade = false;
    std::vector<std::uint16_t> blocked_udp_ports;
};

struct QuicCoreConfig {
    EndpointRole role = EndpointRole::client;
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    std::optional<ConnectionId> original_destination_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
    std::vector<std::byte> retry_token;
    std::uint32_t original_version = kQuicVersion1;
    std::uint32_t initial_version = kQuicVersion1;
    std::vector<std::uint32_t> supported_versions = {kQuicVersion1};
    bool reacted_to_version_negotiation = false;
    bool verify_peer = false;
    std::string server_name = "localhost";
    std::string application_protocol = "coquic";
    std::optional<TlsIdentity> identity;
    QuicTransportConfig transport;
    std::size_t max_outbound_datagram_size = 1200;
    std::vector<CipherSuite> allowed_tls_cipher_suites;
    std::optional<QuicResumptionState> resumption_state;
    QuicZeroRttConfig zero_rtt;
    std::optional<QuicQlogConfig> qlog;
    std::optional<std::filesystem::path> tls_keylog_path;
    std::optional<QuicStatelessResetSecret> stateless_reset_secret;
    std::optional<QuicAddressValidationTokenSecret> address_validation_token_secret;
    std::vector<QuicAddressValidationTokenSecret> previous_address_validation_token_secrets;
    std::optional<std::filesystem::path> address_validation_replay_store_path;
    QuicRequestForgeryPolicyConfig request_forgery_policy;
    bool emit_shared_receive_stream_data = false;
    bool enable_packet_inspection = false;
};

using QuicCoreClock = std::chrono::steady_clock;
using QuicCoreTimePoint = QuicCoreClock::time_point;
using QuicCoreDuration = std::chrono::microseconds;
using QuicPathId = std::uint64_t;
using QuicConnectionHandle = std::uint64_t;
using QuicRouteHandle = std::uint64_t;

struct QuicCorePacketSpaceDiagnostics {
    std::uint64_t next_send_packet_number = 0;
    std::optional<std::uint64_t> largest_authenticated_packet_number;
    bool read_secret_available = false;
    bool write_secret_available = false;
    bool pending_crypto = false;
    std::size_t outstanding_packets = 0;
    std::size_t declared_lost_packets = 0;
    bool pending_probe = false;
    std::optional<QuicCoreTimePoint> pending_ack_deadline;
    bool force_ack = false;
};

struct QuicCoreRecoveryDiagnostics {
    QuicCongestionControlAlgorithm algorithm = QuicCongestionControlAlgorithm::newreno;
    std::uint64_t congestion_window = 0;
    std::uint64_t bytes_in_flight = 0;
    std::uint32_t pto_count = 0;
    std::optional<std::uint64_t> latest_rtt_ms;
    std::optional<std::uint64_t> min_rtt_ms;
    std::uint64_t smoothed_rtt_ms = 0;
    std::uint64_t rttvar_ms = 0;
};

struct QuicCoreFlowControlDiagnostics {
    std::uint64_t peer_max_data = 0;
    std::uint64_t highest_sent = 0;
    std::uint64_t advertised_max_data = 0;
    std::uint64_t delivered_bytes = 0;
    std::uint64_t received_committed = 0;
};

struct QuicCoreStreamLimitDiagnostics {
    std::uint64_t peer_max_bidirectional = 0;
    std::uint64_t peer_max_unidirectional = 0;
    std::uint64_t advertised_max_bidirectional = 0;
    std::uint64_t advertised_max_unidirectional = 0;
};

struct QuicCoreStreamDiagnostics {
    std::uint64_t stream_id = 0;
    std::uint8_t initiator = 0;
    std::uint8_t direction = 0;
    bool local_can_send = false;
    bool local_can_receive = false;
    bool send_closed = false;
    bool receive_closed = false;
    bool peer_send_closed = false;
    bool peer_fin_delivered = false;
    bool peer_reset_received = false;
    std::uint8_t send_fin_state = 0;
    std::uint8_t reset_state = 0;
    std::uint8_t stop_sending_state = 0;
    bool pending_send = false;
    bool outstanding_send = false;
    std::uint64_t sendable_bytes = 0;
    std::uint64_t send_flow_control_limit = 0;
    std::uint64_t receive_flow_control_limit = 0;
    std::uint64_t highest_received_offset = 0;
    std::uint64_t receive_flow_control_consumed = 0;
};

struct QuicCoreConnectionDiagnostics {
    QuicConnectionHandle handle = 0;
    std::uint8_t handshake_status = 0;
    bool started = false;
    bool processed_peer_packet = false;
    bool handshake_ready_emitted = false;
    bool handshake_confirmed = false;
    bool handshake_confirmed_emitted = false;
    bool failed_emitted = false;
    bool peer_transport_parameters_validated = false;
    bool peer_address_validated = false;
    std::uint32_t current_version = 0;
    std::uint64_t anti_amplification_received_bytes = 0;
    std::uint64_t anti_amplification_sent_bytes = 0;
    std::size_t active_paths = 0;
    std::optional<QuicPathId> current_send_path_id;
    std::size_t active_streams = 0;
    std::size_t retired_streams = 0;
    QuicCorePacketSpaceDiagnostics initial_space;
    QuicCorePacketSpaceDiagnostics handshake_space;
    QuicCorePacketSpaceDiagnostics zero_rtt_space;
    QuicCorePacketSpaceDiagnostics application_space;
    QuicCoreRecoveryDiagnostics recovery;
    QuicCoreFlowControlDiagnostics flow_control;
    QuicCoreStreamLimitDiagnostics stream_limits;
    std::vector<QuicCoreStreamDiagnostics> streams;
};

enum class QuicCorePacketInspectionDirection : std::uint8_t {
    outbound,
    inbound,
};

enum class QuicCorePacketInspectionPacketType : std::uint8_t {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
};

struct QuicCorePacketInspection {
    QuicConnectionHandle connection = 0;
    QuicCorePacketInspectionDirection direction = QuicCorePacketInspectionDirection::outbound;
    QuicCorePacketInspectionPacketType packet_type = QuicCorePacketInspectionPacketType::initial;
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
    std::vector<ReceivedFrame> frames;
};

struct QuicCoreEndpointConfig {
    EndpointRole role = EndpointRole::client;
    std::vector<std::uint32_t> supported_versions = {kQuicVersion1};
    bool verify_peer = false;
    bool retry_enabled = false;
    std::string application_protocol = "coquic";
    std::optional<TlsIdentity> identity;
    QuicTransportConfig transport;
    std::size_t max_outbound_datagram_size = 1200;
    std::vector<CipherSuite> allowed_tls_cipher_suites;
    QuicZeroRttConfig zero_rtt;
    std::optional<QuicQlogConfig> qlog;
    std::optional<std::filesystem::path> tls_keylog_path;
    std::optional<QuicStatelessResetSecret> stateless_reset_secret;
    std::optional<QuicAddressValidationTokenSecret> address_validation_token_secret;
    std::vector<QuicAddressValidationTokenSecret> previous_address_validation_token_secrets;
    std::optional<std::filesystem::path> address_validation_replay_store_path;
    QuicRequestForgeryPolicyConfig request_forgery_policy;
    bool emit_shared_receive_stream_data = false;
    bool enable_packet_inspection = false;
    bool allow_peer_address_change = true;
    bool retain_stateless_reset_tokens_after_connection_close = true;
    QuicCoreDuration stateless_reset_token_retention{600000000};
};

struct QuicCoreClientConnectionConfig {
    ConnectionId source_connection_id;
    ConnectionId initial_destination_connection_id;
    std::optional<ConnectionId> original_destination_connection_id;
    std::optional<ConnectionId> retry_source_connection_id;
    std::vector<std::byte> retry_token;
    std::uint32_t original_version = kQuicVersion1;
    std::uint32_t initial_version = kQuicVersion1;
    bool reacted_to_version_negotiation = false;
    std::string server_name = "localhost";
    std::optional<QuicResumptionState> resumption_state;
    QuicZeroRttConfig zero_rtt;
};

enum class QuicEcnCodepoint : std::uint8_t {
    unavailable,
    not_ect,
    ect0,
    ect1,
    ce,
};

enum class QuicCoreStateChange : std::uint8_t {
    handshake_ready,
    handshake_confirmed,
    failed,
};

enum class QuicCoreLocalErrorCode : std::uint8_t {
    unsupported_operation,
    invalid_stream_id,
    invalid_stream_direction,
    send_side_closed,
    receive_side_closed,
    final_size_conflict,
    datagram_not_supported,
    datagram_too_large,
};

enum class QuicMigrationRequestReason : std::uint8_t {
    active,
    preferred_address,
};

struct QuicCoreLocalError {
    std::optional<QuicConnectionHandle> connection;
    QuicCoreLocalErrorCode code;
    std::optional<std::uint64_t> stream_id;
};

struct QuicCoreStart {};

struct QuicCoreInboundDatagram {
    std::vector<std::byte> bytes;
    std::optional<QuicRouteHandle> route_handle;
    std::vector<std::byte> address_validation_identity;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
    std::shared_ptr<std::vector<std::byte>> shared_bytes;
    std::size_t begin = 0;
    std::size_t end = 0;

    std::span<const std::byte> payload() const {
        if (shared_bytes != nullptr) {
            const auto clamped_begin = std::min(begin, shared_bytes->size());
            const auto clamped_end = std::min(std::max(end, clamped_begin), shared_bytes->size());
            return std::span<const std::byte>(*shared_bytes)
                .subspan(clamped_begin, clamped_end - clamped_begin);
        }
        return bytes;
    }

    std::vector<std::byte> materialize() const {
        const auto span = payload();
        return {span.begin(), span.end()};
    }
};

struct QuicCorePathMtuUpdate {
    std::optional<QuicRouteHandle> route_handle;
    std::size_t max_udp_payload_size = 0;
};

struct QuicCoreSendStreamData {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct QuicCoreSendSharedStreamData {
    std::uint64_t stream_id = 0;
    SharedBytes bytes;
    bool fin = false;
};

struct QuicCoreSendDatagramData {
    std::vector<std::byte> bytes;
};

struct QuicCoreSendSharedDatagramData {
    SharedBytes bytes;
};

struct QuicCoreResetStream {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreStopSending {
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreCloseConnection {
    std::uint64_t application_error_code = 0;
    std::string reason_phrase;
};

struct QuicCoreTimerExpired {};
struct QuicCoreRequestKeyUpdate {};
struct QuicCoreRequestConnectionMigration {
    QuicRouteHandle route_handle = 0;
    QuicMigrationRequestReason reason = QuicMigrationRequestReason::active;
    std::vector<std::byte> address_validation_identity;
};

struct QuicCoreOpenConnection {
    QuicCoreClientConnectionConfig connection;
    QuicRouteHandle initial_route_handle = 0;
    std::vector<std::byte> address_validation_identity;
};

using QuicCoreConnectionInput =
    std::variant<QuicCoreSendStreamData, QuicCoreSendSharedStreamData, QuicCoreSendDatagramData,
                 QuicCoreSendSharedDatagramData, QuicCoreResetStream, QuicCoreStopSending,
                 QuicCoreCloseConnection, QuicCoreRequestKeyUpdate,
                 QuicCoreRequestConnectionMigration>;

struct QuicCoreConnectionCommand {
    QuicConnectionHandle connection = 0;
    QuicCoreConnectionInput input;
};

using QuicCoreEndpointInput =
    std::variant<QuicCoreOpenConnection, QuicCoreInboundDatagram, QuicCorePathMtuUpdate,
                 QuicCoreConnectionCommand, QuicCoreTimerExpired>;

using QuicCoreInput =
    std::variant<QuicCoreStart, QuicCoreInboundDatagram, QuicCoreSendStreamData,
                 QuicCoreSendSharedStreamData, QuicCoreSendDatagramData,
                 QuicCoreSendSharedDatagramData, QuicCoreResetStream, QuicCoreStopSending,
                 QuicCoreCloseConnection, QuicCoreRequestKeyUpdate,
                 QuicCoreRequestConnectionMigration, QuicCorePathMtuUpdate, QuicCoreTimerExpired>;

struct QuicCoreSendDatagram {
    QuicConnectionHandle connection = 0;
    std::optional<QuicRouteHandle> route_handle;
    DatagramBuffer bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
    bool is_pmtu_probe = false;
    std::uint64_t packet_inspection_datagram_id = 0;
};

struct QuicCoreReceiveStreamData {
    QuicConnectionHandle connection = 0;
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    SharedBytes shared_bytes;
    bool fin = false;

    std::size_t byte_count() const {
        return shared_bytes.empty() ? bytes.size() : shared_bytes.size();
    }

    std::span<const std::byte> payload() const {
        return shared_bytes.empty() ? std::span<const std::byte>(bytes) : shared_bytes.span();
    }
};

struct QuicCoreReceiveDatagramData {
    QuicConnectionHandle connection = 0;
    std::vector<std::byte> bytes;
    SharedBytes shared_bytes;

    std::size_t byte_count() const {
        return shared_bytes.empty() ? bytes.size() : shared_bytes.size();
    }

    std::span<const std::byte> payload() const {
        return shared_bytes.empty() ? std::span<const std::byte>(bytes) : shared_bytes.span();
    }
};

struct QuicCorePeerResetStream {
    QuicConnectionHandle connection = 0;
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
    std::uint64_t final_size = 0;
};

struct QuicCorePeerStopSending {
    QuicConnectionHandle connection = 0;
    std::uint64_t stream_id = 0;
    std::uint64_t application_error_code = 0;
};

struct QuicCoreStateEvent {
    QuicConnectionHandle connection = 0;
    QuicCoreStateChange change;
};

enum class QuicCoreConnectionLifecycle : std::uint8_t {
    created,
    accepted,
    closed,
};

struct QuicCoreConnectionLifecycleEvent {
    QuicConnectionHandle connection = 0;
    QuicCoreConnectionLifecycle event = QuicCoreConnectionLifecycle::created;
};

struct QuicCorePeerPreferredAddressAvailable {
    QuicConnectionHandle connection = 0;
    PreferredAddress preferred_address;
};

struct QuicCoreResumptionStateAvailable {
    QuicConnectionHandle connection = 0;
    QuicResumptionState state;
};

struct QuicCoreZeroRttStatusEvent {
    QuicConnectionHandle connection = 0;
    QuicZeroRttStatus status = QuicZeroRttStatus::not_attempted;
};

struct QuicCoreNewTokenAvailable {
    QuicConnectionHandle connection = 0;
    std::vector<std::byte> token;
};

using QuicCoreEffect =
    std::variant<QuicCoreSendDatagram, QuicCoreReceiveStreamData, QuicCoreReceiveDatagramData,
                 QuicCorePeerResetStream, QuicCorePeerStopSending, QuicCoreStateEvent,
                 QuicCoreConnectionLifecycleEvent, QuicCorePeerPreferredAddressAvailable,
                 QuicCoreResumptionStateAvailable, QuicCoreZeroRttStatusEvent,
                 QuicCorePacketInspection, QuicCoreNewTokenAvailable>;

struct QuicCoreResult {
    std::vector<QuicCoreEffect> effects;
    std::optional<QuicCoreTimePoint> next_wakeup;
    std::optional<QuicCoreLocalError> local_error;
    bool send_continuation_pending = false;
};

class QuicConnection;
class QuicCore;

namespace test {
bool seed_legacy_route_handle_path_for_tests(QuicCore &core, QuicRouteHandle route_handle,
                                             QuicPathId path_id);
bool core_endpoint_internal_coverage_for_tests();
} // namespace test

class QuicCore {
  public:
    explicit QuicCore(QuicCoreEndpointConfig config);
    explicit QuicCore(QuicCoreConfig config);
    ~QuicCore();

    QuicCore(const QuicCore &) = delete;
    QuicCore &operator=(const QuicCore &) = delete;
    QuicCore(QuicCore &&) noexcept;
    QuicCore &operator=(QuicCore &&) noexcept;

    QuicCoreResult advance_endpoint(QuicCoreEndpointInput input, QuicCoreTimePoint now);
    QuicCoreResult advance(QuicCoreInput input, QuicCoreTimePoint now);
    QuicCoreResult advance(std::span<const QuicCoreInput> inputs, QuicCoreTimePoint now);
    std::optional<QuicCoreTimePoint> next_wakeup() const;
    std::size_t connection_count() const;
    std::vector<QuicCoreConnectionDiagnostics> connection_diagnostics() const;
    bool has_send_continuation_pending() const;
    std::vector<ConnectionId> active_local_connection_ids() const;
    bool is_handshake_complete() const;
    bool has_failed() const;

  private:
    struct ConnectionEntry {
        QuicConnectionHandle handle = 0;
        std::optional<QuicRouteHandle> default_route_handle;
        std::unique_ptr<QuicConnection> connection;
        std::unordered_map<QuicRouteHandle, QuicPathId> path_id_by_route_handle;
        std::unordered_map<QuicPathId, QuicRouteHandle> route_handle_by_path_id;
        std::vector<std::string> active_connection_id_keys;
        std::vector<std::string> local_stateless_reset_connection_id_keys;
        std::vector<std::string> peer_stateless_reset_token_keys;
        std::optional<std::string> initial_destination_connection_id_key;
        std::uint64_t endpoint_route_generation = 0;
        std::optional<QuicCoreTimePoint> send_continuation_wakeup;
        bool send_continuation_drain = false;
        std::vector<QuicRouteHandle> new_token_issued_routes;
        std::unordered_map<QuicPathId, std::vector<std::byte>>
            address_validation_identity_by_path_id;
        QuicPathId next_path_id = 1;
    };

    struct ParsedEndpointDatagram {
        enum class Kind : std::uint8_t {
            short_header,
            supported_initial,
            supported_long_header,
            unsupported_version_long_header,
        };

        Kind kind = Kind::short_header;
        ConnectionId destination_connection_id;
        std::optional<ConnectionId> source_connection_id;
        std::uint32_t version = kQuicVersion1;
        std::vector<std::byte> token;
    };

    struct PendingRetryToken {
        ConnectionId original_destination_connection_id;
        ConnectionId retry_source_connection_id;
        std::uint32_t original_version = kQuicVersion1;
        std::vector<std::byte> token;
        std::optional<QuicRouteHandle> route_handle;
        std::vector<std::byte> address_validation_identity;
        QuicCoreTimePoint expires_at{};
    };

    struct StoredEndpointNewToken {
        std::vector<std::byte> token;
        std::optional<QuicRouteHandle> route_handle;
        std::vector<std::byte> address_validation_identity;
        std::uint32_t version = kQuicVersion1;
        QuicCoreTimePoint expires_at{};
        bool used = false;
    };

    struct ClientStoredNewToken {
        std::string server_name;
        std::uint32_t version = kQuicVersion1;
        std::vector<std::byte> token;
        bool used = false;
    };

    struct LocalStatelessResetTokenRoute {
        QuicConnectionHandle owner = 0;
        std::array<std::byte, 16> stateless_reset_token{};
        std::optional<QuicCoreTimePoint> expires_at;
    };

    struct PeerStatelessResetTokenRoute {
        QuicConnectionHandle owner = 0;
    };

    struct LegacyConnectionView {
        QuicCore *owner = nullptr;

        LegacyConnectionView() = default;
        explicit LegacyConnectionView(QuicCore *core) : owner(core) {
        }

        LegacyConnectionView &operator=(std::unique_ptr<QuicConnection> connection);
        QuicConnection *get() const;
        QuicConnection *operator->() const;
        QuicConnection &operator*() const;
        explicit operator bool() const;
        bool operator==(std::nullptr_t) const;
        bool operator!=(std::nullptr_t) const;
    };

    ConnectionEntry *legacy_entry();
    const ConnectionEntry *legacy_entry() const;
    ConnectionEntry *ensure_legacy_entry();
    friend bool test::seed_legacy_route_handle_path_for_tests(QuicCore &core,
                                                              QuicRouteHandle route_handle,
                                                              QuicPathId path_id);
    friend bool test::core_endpoint_internal_coverage_for_tests();
    void set_legacy_connection(std::unique_ptr<QuicConnection> connection);
    static std::string connection_id_key(std::span<const std::byte> connection_id);
    static std::string
    stateless_reset_token_key(const std::array<std::byte, 16> &stateless_reset_token);
    static std::optional<ParsedEndpointDatagram>
    parse_endpoint_datagram(std::span<const std::byte> bytes, bool accept_greased_quic_bit = false);
    std::vector<std::byte> make_endpoint_retry_token(
        std::uint64_t sequence, const ParsedEndpointDatagram *parsed = nullptr,
        const ConnectionId *retry_source_connection_id = nullptr,
        std::optional<QuicRouteHandle> route_handle = std::nullopt,
        std::span<const std::byte> address_validation_identity = std::span<const std::byte>{},
        QuicCoreTimePoint now = QuicCoreTimePoint{});
    std::vector<std::byte> make_endpoint_new_token(
        std::uint64_t sequence, std::uint32_t version = kQuicVersion1,
        std::optional<QuicRouteHandle> route_handle = std::nullopt,
        std::span<const std::byte> address_validation_identity = std::span<const std::byte>{},
        QuicCoreTimePoint now = QuicCoreTimePoint{});
    std::optional<PendingRetryToken>
    take_retry_context(const ParsedEndpointDatagram &parsed,
                       const std::optional<QuicRouteHandle> &route_handle, QuicCoreTimePoint now,
                       std::span<const std::byte> address_validation_identity);
    std::optional<StoredEndpointNewToken> take_new_token_context(
        const ParsedEndpointDatagram &parsed, const std::optional<QuicRouteHandle> &route_handle,
        QuicCoreTimePoint now, std::span<const std::byte> address_validation_identity);
    void maybe_queue_server_new_token(ConnectionEntry &entry, QuicCoreTimePoint now);
    void drain_queued_server_new_token(ConnectionEntry &entry, QuicCoreResult &drained,
                                       QuicCoreTimePoint now);
    void remember_client_new_tokens(ConnectionEntry &entry, const QuicCoreResult &result);
    std::optional<std::vector<std::byte>>
    take_client_new_token_for_open(const QuicCoreClientConnectionConfig &connection);
    std::optional<QuicConnectionHandle>
    detect_stateless_reset(std::span<const std::byte> bytes) const;
    std::optional<QuicCoreSendDatagram> make_stateless_reset_for_unknown_cid(
        const ParsedEndpointDatagram &parsed, std::span<const std::byte> inbound_bytes,
        const std::optional<QuicRouteHandle> &route_handle, QuicCoreTimePoint now);
    void load_consumed_address_validation_tokens();
    void persist_consumed_address_validation_tokens();
    bool address_validation_token_consumed(std::span<const std::byte> token) const;
    void mark_address_validation_token_consumed(std::span<const std::byte> token,
                                                QuicCoreTimePoint expires_at);
    std::span<const std::byte>
    current_address_validation_identity(const ConnectionEntry &entry) const;
    std::vector<std::byte> effective_address_validation_identity_for_route(
        const ConnectionEntry &entry, QuicRouteHandle route_handle,
        std::span<const std::byte> proposed_identity) const;
    bool address_validation_identity_allowed_for_new_route(
        const ConnectionEntry *entry, std::span<const std::byte> address_validation_identity) const;
    static std::vector<std::byte>
    make_version_negotiation_packet_bytes(const ParsedEndpointDatagram &parsed,
                                          std::span<const std::uint32_t> supported_versions,
                                          bool grease_reserved_versions = false);
    static std::vector<std::byte> make_retry_packet_bytes(const ParsedEndpointDatagram &parsed,
                                                          const PendingRetryToken &pending);
    std::optional<QuicConnectionHandle>
    find_endpoint_connection_for_datagram(const ParsedEndpointDatagram &parsed) const;
    void erase_endpoint_connection_routes(const ConnectionEntry &entry);
    void retire_endpoint_connection_routes(const ConnectionEntry &entry, QuicCoreTimePoint now);
    void purge_expired_local_stateless_reset_tokens(QuicCoreTimePoint now);
    void refresh_server_connection_routes(ConnectionEntry &entry);
    static void
    remember_address_validation_identity(ConnectionEntry &entry, QuicPathId path_id,
                                         std::span<const std::byte> address_validation_identity);
    QuicPathId remember_inbound_path(ConnectionEntry &entry, QuicRouteHandle route_handle,
                                     std::span<const std::byte> address_validation_identity);
    std::optional<QuicPathId>
    path_id_for_inbound_route(ConnectionEntry &entry,
                              const std::optional<QuicRouteHandle> &route_handle,
                              std::span<const std::byte> address_validation_identity);
    static std::optional<QuicRouteHandle>
    route_handle_for_path(const ConnectionEntry &entry, const std::optional<QuicPathId> &path_id);
    static bool should_run_connection_timeout(const ConnectionEntry &entry, QuicCoreTimePoint now);
    static void maybe_run_connection_timeout(ConnectionEntry &entry, QuicCoreTimePoint now);
    static void note_send_continuation(ConnectionEntry &entry, const QuicCoreResult &result,
                                       QuicCoreTimePoint now);
    static bool take_send_continuation_drain(ConnectionEntry &entry);
    QuicCoreResult finalize_endpoint_result(QuicCoreResult result, QuicCoreTimePoint now);
    QuicCoreResult finalize_legacy_result(QuicCoreResult result, QuicCoreTimePoint now);

    QuicCoreEndpointConfig endpoint_config_;
    std::optional<QuicCoreConfig> legacy_config_;
    std::unordered_map<QuicConnectionHandle, ConnectionEntry> connections_;
    std::unordered_map<std::string, QuicConnectionHandle> connection_id_routes_;
    std::unordered_map<std::string, QuicConnectionHandle> initial_destination_routes_;
    std::unordered_map<std::string, PendingRetryToken> retry_tokens_;
    std::unordered_map<std::string, StoredEndpointNewToken> new_tokens_;
    std::unordered_map<std::string, QuicCoreTimePoint> consumed_address_validation_tokens_;
    std::vector<ClientStoredNewToken> client_new_tokens_;
    std::unordered_map<std::string, LocalStatelessResetTokenRoute>
        local_stateless_reset_tokens_by_cid_;
    std::unordered_map<std::string, PeerStatelessResetTokenRoute> peer_stateless_reset_tokens_;
    std::optional<QuicConnectionHandle> legacy_connection_handle_;
    QuicConnectionHandle next_connection_handle_ = 1;
    std::uint64_t next_server_connection_id_sequence_ = 1;
    std::mt19937_64 endpoint_random_;
    LegacyConnectionView connection_;
};

} // namespace coquic::quic
