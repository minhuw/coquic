#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "src/quic/packet.h"
#include "src/quic/resumption.h"
#include "src/quic/tls_adapter.h"
#include "src/quic/transport_parameters.h"
#include "src/quic/version.h"

namespace coquic::quic {

struct QuicTransportConfig {
    std::uint64_t max_idle_timeout = 0;
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t active_connection_id_limit = 2;
    bool disable_active_migration = false;
    std::optional<PreferredAddress> preferred_address;
    std::uint64_t ack_delay_exponent = 3;
    std::uint64_t max_ack_delay = 25;
    std::uint64_t initial_max_data = 1 << 20;
    std::uint64_t initial_max_stream_data_bidi_local = 256 << 10;
    std::uint64_t initial_max_stream_data_bidi_remote = 256 << 10;
    std::uint64_t initial_max_stream_data_uni = 256 << 10;
    std::uint64_t initial_max_streams_bidi = 16;
    std::uint64_t initial_max_streams_uni = 16;
};

struct QuicQlogConfig {
    std::filesystem::path directory;
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
    std::vector<CipherSuite> allowed_tls_cipher_suites;
    std::optional<QuicResumptionState> resumption_state;
    QuicZeroRttConfig zero_rtt;
    std::optional<QuicQlogConfig> qlog;
    std::optional<std::filesystem::path> tls_keylog_path;
};

using QuicCoreClock = std::chrono::steady_clock;
using QuicCoreTimePoint = QuicCoreClock::time_point;
using QuicPathId = std::uint64_t;
using QuicConnectionHandle = std::uint64_t;
using QuicRouteHandle = std::uint64_t;

struct QuicCoreEndpointConfig {
    EndpointRole role = EndpointRole::client;
    std::vector<std::uint32_t> supported_versions = {kQuicVersion1};
    bool verify_peer = false;
    bool retry_enabled = false;
    std::string application_protocol = "coquic";
    std::optional<TlsIdentity> identity;
    QuicTransportConfig transport;
    std::vector<CipherSuite> allowed_tls_cipher_suites;
    QuicZeroRttConfig zero_rtt;
    std::optional<QuicQlogConfig> qlog;
    std::optional<std::filesystem::path> tls_keylog_path;
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
    QuicPathId path_id = 0;
    std::optional<QuicRouteHandle> route_handle;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
};

struct QuicCoreSendStreamData {
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
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
    QuicPathId path_id = 0;
    std::optional<QuicRouteHandle> route_handle;
    QuicMigrationRequestReason reason = QuicMigrationRequestReason::active;
};

struct QuicCoreOpenConnection {
    QuicCoreClientConnectionConfig connection;
    QuicRouteHandle initial_route_handle = 0;
};

using QuicCoreConnectionInput =
    std::variant<QuicCoreSendStreamData, QuicCoreResetStream, QuicCoreStopSending,
                 QuicCoreCloseConnection, QuicCoreRequestKeyUpdate,
                 QuicCoreRequestConnectionMigration>;

struct QuicCoreConnectionCommand {
    QuicConnectionHandle connection = 0;
    QuicCoreConnectionInput input;
};

using QuicCoreEndpointInput = std::variant<QuicCoreOpenConnection, QuicCoreInboundDatagram,
                                           QuicCoreConnectionCommand, QuicCoreTimerExpired>;

using QuicCoreInput = std::variant<QuicCoreStart, QuicCoreInboundDatagram, QuicCoreSendStreamData,
                                   QuicCoreResetStream, QuicCoreStopSending,
                                   QuicCoreCloseConnection, QuicCoreRequestKeyUpdate,
                                   QuicCoreRequestConnectionMigration, QuicCoreTimerExpired>;

struct QuicCoreSendDatagram {
    QuicConnectionHandle connection = 0;
    std::optional<QuicPathId> path_id;
    std::optional<QuicRouteHandle> route_handle;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
};

struct QuicCoreReceiveStreamData {
    QuicConnectionHandle connection = 0;
    std::uint64_t stream_id = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
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

using QuicCoreEffect =
    std::variant<QuicCoreSendDatagram, QuicCoreReceiveStreamData, QuicCorePeerResetStream,
                 QuicCorePeerStopSending, QuicCoreStateEvent, QuicCoreConnectionLifecycleEvent,
                 QuicCorePeerPreferredAddressAvailable, QuicCoreResumptionStateAvailable,
                 QuicCoreZeroRttStatusEvent>;

struct QuicCoreResult {
    std::vector<QuicCoreEffect> effects;
    std::optional<QuicCoreTimePoint> next_wakeup;
    std::optional<QuicCoreLocalError> local_error;
};

class QuicConnection;

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
    std::optional<QuicCoreTimePoint> next_wakeup() const;
    std::size_t connection_count() const;
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
        std::optional<std::string> initial_destination_connection_id_key;
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
    void set_legacy_connection(std::unique_ptr<QuicConnection> connection);
    static std::string connection_id_key(std::span<const std::byte> connection_id);
    static std::optional<ParsedEndpointDatagram>
    parse_endpoint_datagram(std::span<const std::byte> bytes);
    static std::vector<std::byte> make_endpoint_retry_token(std::uint64_t sequence);
    std::optional<PendingRetryToken>
    take_retry_context(const ParsedEndpointDatagram &parsed,
                       const std::optional<QuicRouteHandle> &route_handle);
    static std::vector<std::byte>
    make_version_negotiation_packet_bytes(const ParsedEndpointDatagram &parsed,
                                          std::span<const std::uint32_t> supported_versions);
    static std::vector<std::byte> make_retry_packet_bytes(const ParsedEndpointDatagram &parsed,
                                                          const PendingRetryToken &pending);
    std::optional<QuicConnectionHandle>
    find_endpoint_connection_for_datagram(const ParsedEndpointDatagram &parsed) const;
    void erase_endpoint_connection_routes(const ConnectionEntry &entry);
    void refresh_server_connection_routes(ConnectionEntry &entry);
    QuicPathId remember_inbound_path(ConnectionEntry &entry,
                                     const QuicCoreInboundDatagram &inbound);

    QuicCoreEndpointConfig endpoint_config_;
    std::optional<QuicCoreConfig> legacy_config_;
    std::unordered_map<QuicConnectionHandle, ConnectionEntry> connections_;
    std::unordered_map<std::string, QuicConnectionHandle> connection_id_routes_;
    std::unordered_map<std::string, QuicConnectionHandle> initial_destination_routes_;
    std::unordered_map<std::string, PendingRetryToken> retry_tokens_;
    std::optional<QuicConnectionHandle> legacy_connection_handle_;
    QuicConnectionHandle next_connection_handle_ = 1;
    std::uint64_t next_server_connection_id_sequence_ = 1;
    LegacyConnectionView connection_;
};

} // namespace coquic::quic
