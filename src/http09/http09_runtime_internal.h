#pragma once

#ifndef COQUIC_NO_PROFILE
#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif
#endif

#include "src/http09/http09_runtime.h"
#include "src/http09/http09_runtime_test_hooks.h"
#include "src/io/io_backend_factory.h"
#include "src/quic/codec/buffer.h"
#include "src/quic/codec/packet.h"
#include "src/quic/crypto/packet_crypto.h"
#include "src/quic/version.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace coquic::http09 {

using namespace quic;

using io::QuicIoBackend;
using io::QuicIoEvent;
using io::QuicIoPathMtuUpdate;
using io::QuicIoRemote;
using io::QuicIoRxDatagram;
using io::QuicIoTxDatagram;

namespace test {
using Http09RuntimeOpsOverride = io::test::SocketIoBackendOpsOverride;
using io::test::SocketIoBackendReceiveDatagramStatusForTests;
using io::test::SocketIoBackendResolvedUdpAddressForTests;
using ScopedHttp09RuntimeOpsOverride = io::test::ScopedSocketIoBackendOpsOverride;
using io::test::socket_io_backend_address_validation_identity_for_runtime_tests;
using io::test::socket_io_backend_apply_ops_override_for_runtime_tests;
using io::test::socket_io_backend_configure_linux_ecn_socket_options_for_runtime_tests;
using io::test::socket_io_backend_ecn_from_linux_traffic_class_for_runtime_tests;
using io::test::socket_io_backend_has_legacy_recvfrom_override_for_runtime_tests;
using io::test::socket_io_backend_has_legacy_sendto_override_for_runtime_tests;
using io::test::socket_io_backend_is_ipv4_mapped_ipv6_address_for_runtime_tests;
using io::test::socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests;
using io::test::socket_io_backend_open_udp_socket_for_runtime_tests;
using io::test::socket_io_backend_ops_for_runtime_tests;
using io::test::socket_io_backend_preferred_udp_address_family_for_runtime_tests;
using io::test::socket_io_backend_receive_datagram_for_runtime_tests;
using io::test::socket_io_backend_recvmsg_ecn_from_control_for_runtime_tests;
using io::test::socket_io_backend_resolve_udp_address_for_runtime_tests;
using io::test::socket_io_backend_send_datagram_for_runtime_tests;
} // namespace test

constexpr std::size_t kMinimumClientInitialDatagramBytes = 1200;
constexpr std::size_t kRuntimeMaxOutboundDatagramBytes = 1452;
constexpr std::size_t kRuntimeConnectionIdLength = 8;
constexpr int kDefaultClientReceiveTimeoutMs = 30000;
constexpr int kMulticonnectClientReceiveTimeoutMs = 180000;
constexpr int kClientSuccessDrainWindowMs = 500;
constexpr int kServerZeroRttDrainGraceMs = 100;
constexpr int kServerIdleTimeoutMs = 1000;
constexpr std::string_view kProjectName = "coquic";
constexpr std::string_view kInteropApplicationProtocol = "hq-interop";
constexpr std::string_view kUsageLine =
    "usage: coquic [interop-server|interop-client] [--host HOST] [--port PORT] "
    "[--io-backend socket|io_uring] [--congestion-control newreno|cubic|bbr|copa] "
    "[--testcase "
    "handshake|transfer|keyupdate|amplificationlimit|rebind-port|rebind-addr|"
    "connectionmigration|ecn|multiconnect|chacha20|retry|resumption|zerortt|v2] "
    "[--requests URLS] "
    "[--document-root PATH] "
    "[--download-root PATH] [--certificate-chain PATH] [--private-key PATH] "
    "[--server-name NAME] [--verify-peer] [--no-verify-peer] [--retry]";

struct LinuxSocketDescriptor {
    int fd = -1;
};

class ScopedFd {
  public:
    explicit ScopedFd(int fd) : fd_(fd) {
    }

    ~ScopedFd() {
        ::close(fd_);
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

  private:
    int fd_ = -1;
};

struct ResolvedUdpAddress {
    sockaddr_storage address{};
    socklen_t address_len = 0;
    int family = AF_UNSPEC;
};

struct UdpAddressResolutionQuery {
    std::string_view host;
    std::uint16_t port = 0;
    int extra_flags = 0;
    int family = AF_UNSPEC;
};

struct ParsedServerDatagram {
    enum class Kind : std::uint8_t {
        short_header,
        supported_initial,
        supported_long_header,
        unsupported_version_long_header,
    };

    Kind kind;
    std::uint32_t version = 0;
    ConnectionId destination_connection_id;
    std::optional<ConnectionId> source_connection_id;
    std::vector<std::byte> token;
};

struct PendingRetryToken {
    ConnectionId original_destination_connection_id;
    ConnectionId retry_source_connection_id;
    std::uint32_t original_version = kQuicVersion1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

using RetryTokenStore = std::unordered_map<std::string, PendingRetryToken>;

struct SupportedInitialRetryPreparation {
    std::optional<bool> immediate_result;
    std::optional<PendingRetryToken> retry_context;
};

struct RuntimeSendRoute {
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

struct ServerSocketSet {
    int primary_fd = -1;
    std::optional<int> preferred_fd;
};

struct ClientSocketDescriptor {
    int fd = -1;
    int family = AF_UNSPEC;
};

struct ClientSocketSet {
    ClientSocketDescriptor primary;
    std::optional<ClientSocketDescriptor> secondary;
};

class ScopedClientSockets {
  public:
    explicit ScopedClientSockets(ClientSocketSet &sockets) : sockets_(sockets) {
    }

    ~ScopedClientSockets() {
        if (sockets_.secondary.has_value() && sockets_.secondary->fd >= 0 &&
            sockets_.secondary->fd != sockets_.primary.fd) {
            ::close(sockets_.secondary->fd);
        }
        if (sockets_.primary.fd >= 0) {
            ::close(sockets_.primary.fd);
        }
    }

    ScopedClientSockets(const ScopedClientSockets &) = delete;
    ScopedClientSockets &operator=(const ScopedClientSockets &) = delete;

  private:
    ClientSocketSet &sockets_;
};

struct RuntimeWaitStep {
    std::optional<QuicCoreInput> input;
    QuicCoreTimePoint input_time;
    int socket_fd = -1;
    sockaddr_storage source{};
    socklen_t source_len = 0;
    bool has_source = false;
    bool idle_timeout = false;
};

struct RuntimeWaitConfig {
    std::array<int, 2> socket_fds = {-1, -1};
    std::size_t socket_fd_count = 0;
    int idle_timeout_ms = 0;
    std::string_view role_name;
};

enum class ReceiveDatagramStatus : std::uint8_t {
    ok,
    would_block,
    error,
};

struct ReceiveDatagramResult {
    ReceiveDatagramStatus status = ReceiveDatagramStatus::would_block;
    RuntimeWaitStep step;
};

struct ClientLoopIo {
    void *context = nullptr;
    QuicCoreTimePoint (*now_fn)(void *) = nullptr;
    ReceiveDatagramResult (*receive_datagram_fn)(void *, int, int, std::string_view) = nullptr;
    std::optional<RuntimeWaitStep> (*wait_for_socket_or_deadline_fn)(
        void *, const RuntimeWaitConfig &, const std::optional<QuicCoreTimePoint> &) = nullptr;

    QuicCoreTimePoint current_time() const {
        return now_fn(context);
    }

    ReceiveDatagramResult receive_datagram(int socket_fd, int flags,
                                           std::string_view role_name) const {
        return receive_datagram_fn(context, socket_fd, flags, role_name);
    }

    std::optional<RuntimeWaitStep>
    wait_for_socket_or_deadline(const RuntimeWaitConfig &config,
                                const std::optional<QuicCoreTimePoint> &next_wakeup) const {
        return wait_for_socket_or_deadline_fn(context, config, next_wakeup);
    }
};

struct EndpointDriveState {
    std::optional<QuicCoreTimePoint> next_wakeup;
    bool endpoint_has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
    std::optional<QuicResumptionState> last_resumption_state;
    std::unordered_map<std::string, QuicPathId> path_ids_by_peer_tuple;
    std::unordered_map<QuicPathId, RuntimeSendRoute> path_routes;
    std::unordered_map<std::string, QuicRouteHandle> route_handles_by_peer_tuple;
    std::unordered_map<QuicRouteHandle, RuntimeSendRoute> route_routes;
    std::unordered_set<QuicConnectionHandle> handshake_ready_connections;
    QuicRouteHandle next_route_handle = 1;
};

struct ClientRuntimePolicyState {
    bool handshake_ready_seen = false;
    bool handshake_confirmed_seen = false;
    bool preferred_address_request_queued = false;
    std::optional<QuicRouteHandle> preferred_address_route_handle;
    std::vector<std::byte> preferred_address_validation_identity;
};

struct ClientIoContext {
    std::unique_ptr<QuicIoBackend> backend;
    std::optional<QuicRouteHandle> primary_route_handle;
    std::vector<std::byte> primary_address_validation_identity;
    std::optional<QuicRouteHandle> preferred_route_handle;
};

struct ServerIoContext {
    std::unique_ptr<QuicIoBackend> backend;
};

struct ClientConnectionRunResult {
    int exit_code = 0;
    std::optional<QuicResumptionState> resumption_state;
};

struct ServerSession {
    QuicCore core;
    QuicHttp09ServerEndpoint endpoint;
    EndpointDriveState state;
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    std::string local_connection_id_key;
    std::string initial_destination_connection_id_key;
    std::vector<std::string> alternate_connection_id_keys;
};

using ServerSessionMap = std::unordered_map<std::string, std::unique_ptr<ServerSession>>;
using ServerConnectionIdRouteMap = std::unordered_map<std::string, std::string>;
using EraseServerSessionFn = std::function<void(const std::string &)>;

struct EndpointDriver {
    void *context = nullptr;
    QuicHttp09EndpointUpdate (*on_core_result_fn)(void *, const QuicCoreResult &,
                                                  QuicCoreTimePoint) = nullptr;
    QuicHttp09EndpointUpdate (*poll_fn)(void *, QuicCoreTimePoint) = nullptr;

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult &result,
                                            QuicCoreTimePoint current) const {
        return on_core_result_fn(context, result, current);
    }

    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint current) const {
        return poll_fn(context, current);
    }
};

template <typename Endpoint> EndpointDriver make_endpoint_driver(Endpoint &endpoint) {
    return EndpointDriver{
        .context = &endpoint,
        .on_core_result_fn =
            [](void *context, const QuicCoreResult &result, QuicCoreTimePoint current) {
                return static_cast<Endpoint *>(context)->on_core_result(result, current);
            },
        .poll_fn =
            [](void *context, QuicCoreTimePoint current) {
                return static_cast<Endpoint *>(context)->poll(current);
            },
    };
}

struct ServerConnectionEndpointState {
    QuicHttp09ServerEndpoint endpoint;
    bool has_pending_work = false;
};

using ServerConnectionEndpointMap =
    std::unordered_map<QuicConnectionHandle, ServerConnectionEndpointState>;

struct ServerLoopIo {
    std::function<QuicCoreTimePoint()> current_time;
    std::function<ReceiveDatagramResult(int, int, std::string_view)> receive_datagram;
    std::function<std::optional<RuntimeWaitStep>(const RuntimeWaitConfig &,
                                                 const std::optional<QuicCoreTimePoint> &)>
        wait_for_socket_or_deadline;
};

struct ServerLoopDriver {
    std::function<std::optional<QuicCoreTimePoint>()> earliest_wakeup;
    std::function<void(QuicCoreTimePoint, bool &)> process_expired_timers;
    std::function<bool()> pump_endpoint_work;
    std::function<bool()> has_pending_endpoint_work;
    std::function<bool(RuntimeWaitStep)> process_datagram;
    std::function<bool()> has_failed = [] { return false; };
};

struct ServerBackendLoopDriver {
    std::function<QuicCoreTimePoint()> current_time;
    std::function<std::optional<QuicCoreTimePoint>()> next_wakeup;
    std::function<bool(bool &)> pump_endpoint_work;
    std::function<bool()> has_pending_endpoint_work;
    std::function<std::optional<QuicIoEvent>()> initial_buffered_event = [] {
        return std::optional<QuicIoEvent>{};
    };
    std::function<std::optional<QuicIoEvent>(const std::optional<QuicCoreTimePoint> &)> wait;
    std::function<bool(QuicCoreTimePoint)> process_wait_timer;
    std::function<bool(const QuicIoRxDatagram &, QuicCoreTimePoint)> process_datagram;
    std::function<bool(const QuicIoPathMtuUpdate &, QuicCoreTimePoint)> process_path_mtu_update =
        [](const QuicIoPathMtuUpdate &, QuicCoreTimePoint) { return true; };
    std::function<bool()> flush_deferred_output = [] { return true; };
    std::function<std::optional<QuicCoreTimePoint>()> defer_output_until = [] {
        return std::optional<QuicCoreTimePoint>{};
    };
};

bool &runtime_logging_ready_flag();
void init_runtime_logging();
bool runtime_has_openssl();
int client_receive_timeout_ms(const Http09RuntimeConfig &config);
test::Http09RuntimeOpsOverride &runtime_ops();
void apply_runtime_ops_override(const test::Http09RuntimeOpsOverride &override_ops);
bool has_legacy_sendto_override();
bool has_legacy_recvfrom_override();
int linux_traffic_class_for_ecn(QuicEcnCodepoint ecn);
QuicEcnCodepoint ecn_from_linux_traffic_class(int traffic_class);
bool configure_linux_ecn_socket_options(LinuxSocketDescriptor socket, int family);
bool is_ipv4_mapped_ipv6_address(const sockaddr_storage &peer, socklen_t peer_len);
QuicEcnCodepoint recvmsg_ecn_from_control(const msghdr &message);
QuicCoreTimePoint now();
std::optional<std::string> getenv_string(const char *name);
bool env_flag_enabled(const char *name);
bool runtime_trace_enabled();
void with_runtime_trace(const std::function<void(std::ostream &)> &callback);
std::string format_connection_id_hex(std::span<const std::byte> connection_id);
std::string format_connection_id_key_hex(std::string_view connection_id_key);
std::string format_sockaddr_for_trace(const sockaddr_storage &address, socklen_t address_len);
std::string read_text_file(const std::filesystem::path &path);
std::optional<std::string> read_required_text_file(const std::filesystem::path &path,
                                                   std::string_view description);
std::optional<std::uint16_t> parse_port(std::string_view value);
std::optional<QuicHttp09Testcase> parse_testcase(std::string_view value);
std::optional<io::QuicIoBackendKind> parse_io_backend_kind(std::string_view value);
constexpr QuicHttp09Testcase transfer_semantics_testcase(QuicHttp09Testcase testcase) {
    if (testcase == QuicHttp09Testcase::keyupdate || testcase == QuicHttp09Testcase::rebind_port ||
        testcase == QuicHttp09Testcase::rebind_addr || testcase == QuicHttp09Testcase::ecn ||
        testcase == QuicHttp09Testcase::connectionmigration) {
        return QuicHttp09Testcase::transfer;
    }
    return testcase;
}
bool apply_testcase_name(Http09RuntimeConfig &config, std::string_view value);
bool parse_role_into(Http09RuntimeConfig &config, std::string_view role);
int preferred_udp_address_family(std::string_view host);
bool host_is_unspecified(std::string_view host);
std::optional<std::string> preferred_address_host_for_server(std::string_view host);
bool resolve_udp_address(UdpAddressResolutionQuery query, ResolvedUdpAddress &resolved);
PreferredAddress preferred_address_with_connection_id(ConnectionId connection_id);
PreferredAddress preferred_address_from_resolved_udp_address(const ResolvedUdpAddress &resolved,
                                                             ConnectionId connection_id);
void apply_resolved_udp_address_to_preferred_address(PreferredAddress &preferred_address,
                                                     const ResolvedUdpAddress &resolved);
sockaddr_storage sockaddr_from_preferred_address(const PreferredAddress &preferred_address);
socklen_t sockaddr_len_from_preferred_address(const PreferredAddress &preferred_address);
std::optional<ParsedHttp09Authority> parse_http09_authority_impl(std::string_view authority);
std::optional<Http09ClientRemote>
derive_http09_client_remote_impl(const Http09RuntimeConfig &config,
                                 const std::vector<QuicHttp09Request> &requests);
int open_udp_socket(int family);
int open_and_bind_udp_socket(const ResolvedUdpAddress &bind_address, std::string_view role_name);
std::uint32_t runtime_original_quic_version_for_testcase(QuicHttp09Testcase testcase);
std::vector<std::uint32_t>
runtime_supported_quic_versions_for_testcase(QuicHttp09Testcase testcase);
std::optional<PreferredAddress>
runtime_preferred_address_for_server(const Http09RuntimeConfig &config);
void configure_runtime_datagram_profile(QuicTransportConfig &transport);
QuicCoreConfig make_http09_server_core_config_with_identity(const Http09RuntimeConfig &config,
                                                            TlsIdentity identity);
bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name,
                   QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect, bool is_pmtu_probe = false);
ConnectionId make_runtime_connection_id(std::byte prefix, std::uint64_t sequence);
std::string connection_id_key(std::span<const std::byte> connection_id);
std::uint32_t read_u32_be_at(std::span<const std::byte> bytes, std::size_t offset);
bool is_initial_long_header_type(std::uint32_t version, std::uint8_t type);
std::optional<ParsedServerDatagram>
parse_server_datagram_for_routing(std::span<const std::byte> bytes);
std::vector<std::byte> make_runtime_retry_token(std::uint64_t sequence);
bool peer_matches_pending_retry(const PendingRetryToken &pending, const sockaddr_storage &peer,
                                socklen_t peer_len);
std::optional<PendingRetryToken> lookup_retry_context(const ParsedServerDatagram &parsed,
                                                      const sockaddr_storage &peer,
                                                      socklen_t peer_len,
                                                      RetryTokenStore &retry_tokens);
bool send_retry_for_initial(int fd, const ParsedServerDatagram &parsed,
                            const sockaddr_storage &peer, socklen_t peer_len,
                            RetryTokenStore &retry_tokens, std::uint64_t connection_index);
std::optional<bool> maybe_send_retry_for_supported_initial(bool retry_enabled, int socket_fd,
                                                           const ParsedServerDatagram &parsed,
                                                           const sockaddr_storage &peer,
                                                           socklen_t peer_len,
                                                           RetryTokenStore &retry_tokens,
                                                           std::uint64_t &next_connection_index);
bool populate_retry_context_if_required(bool retry_enabled, const ParsedServerDatagram &parsed,
                                        const sockaddr_storage &peer, socklen_t peer_len,
                                        RetryTokenStore &retry_tokens,
                                        std::optional<PendingRetryToken> &retry_context);
SupportedInitialRetryPreparation prepare_supported_initial_retry_handling(
    bool retry_enabled, int socket_fd, const ParsedServerDatagram &parsed,
    const sockaddr_storage &peer, socklen_t peer_len, RetryTokenStore &retry_tokens,
    std::uint64_t &next_connection_index);
bool send_version_negotiation_for_probe(int fd, std::span<const std::byte> datagram,
                                        const ParsedServerDatagram &parsed,
                                        const sockaddr_storage &peer, socklen_t peer_len);
ReceiveDatagramResult receive_datagram(int socket_fd, std::string_view role_name, int flags);
ReceiveDatagramResult receive_runtime_client_datagram(void *, int socket_fd, int flags,
                                                      std::string_view role_name);
std::optional<RuntimeWaitStep>
wait_for_socket_or_deadline(const RuntimeWaitConfig &config,
                            const std::optional<QuicCoreTimePoint> &next_wakeup);
ClientLoopIo make_runtime_client_loop_io();
int client_socket_fd_for_family(const ClientSocketSet &sockets, int family);
std::array<int, 2> active_client_socket_fds(const ClientSocketSet &sockets);
std::size_t active_client_socket_count(const ClientSocketSet &sockets);
std::optional<int> ensure_client_socket_for_family(ClientSocketSet &sockets, int family,
                                                   std::string_view role_name);
bool handle_core_effects(int fallback_socket_fd, const QuicCoreResult &result,
                         const sockaddr_storage *fallback_peer, socklen_t fallback_peer_len,
                         const std::unordered_map<QuicRouteHandle, RuntimeSendRoute> &routes,
                         std::string_view role_name);
void write_advance_core_output_trace(std::ostream &stream, const QuicCoreResult &step);
QuicCoreResult advance_core_with_inputs(QuicCore &core, std::span<const QuicCoreInput> inputs,
                                        QuicCoreTimePoint step_time);
std::string runtime_peer_tuple_key(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len);
QuicPathId remember_runtime_path(EndpointDriveState &state, const sockaddr_storage &peer,
                                 socklen_t peer_len, int socket_fd);
QuicRouteHandle remember_runtime_route_handle(EndpointDriveState &state,
                                              const sockaddr_storage &peer, socklen_t peer_len,
                                              int socket_fd);
std::optional<QuicPathId> assign_runtime_path_for_inbound_step(EndpointDriveState &state,
                                                               RuntimeWaitStep &step);
QuicCoreInboundDatagram make_inbound_datagram_from_io_event(const QuicIoRxDatagram &datagram);
QuicIoTxDatagram make_owning_tx_datagram(const QuicIoTxDatagram &datagram);
bool handle_core_effects_with_backend(const std::optional<QuicRouteHandle> &fallback_route_handle,
                                      QuicIoBackend &backend, const QuicCoreResult &result,
                                      std::string_view role_name,
                                      std::vector<QuicIoTxDatagram> *deferred_output = nullptr);
void record_resumption_state(EndpointDriveState &state, const QuicCoreResult &result);
bool result_observes_new_handshake_ready(EndpointDriveState &state, const QuicCoreResult &result);
bool result_observes_stream_data_before_handshake_ready(const EndpointDriveState &state,
                                                        const QuicCoreResult &result);
void note_server_early_stream_data_deferral(std::optional<QuicCoreTimePoint> &defer_output_until,
                                            QuicCoreTimePoint now);
void maybe_note_server_early_stream_data_deferral(bool ok, bool observed_early_stream_data,
                                                  std::optional<QuicCoreTimePoint> &defer_until,
                                                  QuicCoreTimePoint now);
bool observe_client_runtime_policy_effects(const QuicCoreResult &result, EndpointDriveState &state,
                                           ClientRuntimePolicyState &policy,
                                           ClientSocketSet &client_sockets,
                                           std::string_view role_name);
bool observe_client_runtime_policy_effects_with_backend(const QuicCoreResult &result,
                                                        EndpointDriveState &state,
                                                        ClientRuntimePolicyState &policy,
                                                        ClientIoContext &io_context,
                                                        std::string_view role_name);
bool runtime_client_should_attempt_preferred_address_migration(const Http09RuntimeConfig &config);
void maybe_queue_client_runtime_policy_inputs(const Http09RuntimeConfig &config,
                                              ClientRuntimePolicyState &policy,
                                              std::vector<QuicCoreInput> &core_inputs);
bool zero_rtt_definitely_unavailable(const QuicCoreResult &result);
bool allow_requests_before_handshake_ready(bool attempt_zero_rtt_requests,
                                           const QuicCoreResult &start_result);
void refresh_server_session_connection_id_routes(ServerSession &session,
                                                 ServerConnectionIdRouteMap &connection_id_routes);
void erase_server_session_from_map(ServerSessionMap &sessions,
                                   const std::string &server_session_key);
void erase_server_session_with_routes(
    ServerSessionMap &sessions, ServerConnectionIdRouteMap &connection_id_routes,
    std::unordered_map<std::string, std::string> &initial_destination_routes,
    const std::string &server_session_key);
bool datagram_routes_via_initial_destination(const ParsedServerDatagram &parsed);
ServerSessionMap::iterator find_server_session_for_datagram(
    ServerSessionMap &sessions, const ServerConnectionIdRouteMap &connection_id_routes,
    const std::unordered_map<std::string, std::string> &initial_destination_routes,
    const ParsedServerDatagram &parsed);
void assign_runtime_client_connection_ids(QuicCoreConfig &core_config,
                                          std::uint64_t connection_index);
QuicCoreConfig make_runtime_client_core_config(const Http09RuntimeConfig &config,
                                               std::uint64_t connection_index);
QuicCoreConfig make_runtime_server_core_config(const Http09RuntimeConfig &config,
                                               const TlsIdentity &identity,
                                               std::uint64_t connection_index);
template <typename Range, typename Projection>
std::optional<QuicCoreTimePoint> earliest_wakeup_in_range(const Range &range, Projection project) {
    std::optional<QuicCoreTimePoint> next_wakeup;
    for (const auto &entry : range) {
        const auto candidate = project(entry);
        if (!candidate.has_value()) {
            continue;
        }

        const auto wakeup = candidate.value();
        next_wakeup = std::min(next_wakeup.value_or(wakeup), wakeup);
    }
    return next_wakeup;
}
std::optional<QuicCoreTimePoint> earliest_server_session_wakeup(const ServerSessionMap &sessions);
bool drive_endpoint_until_blocked(const EndpointDriver &endpoint, QuicCore &core, int fd,
                                  const sockaddr_storage *peer, socklen_t peer_len,
                                  const QuicCoreResult &initial_result, EndpointDriveState &state,
                                  std::string_view role_name,
                                  const Http09RuntimeConfig *runtime_config = nullptr,
                                  ClientRuntimePolicyState *client_policy = nullptr,
                                  ClientSocketSet *client_sockets = nullptr,
                                  bool *observed_send_effects = nullptr);
bool drive_endpoint_until_blocked_with_backend(
    const EndpointDriver &endpoint, QuicCore &core,
    const std::optional<QuicRouteHandle> &fallback_route_handle, QuicIoBackend &backend,
    const QuicCoreResult &initial_result, EndpointDriveState &state, std::string_view role_name,
    const Http09RuntimeConfig *runtime_config = nullptr,
    ClientRuntimePolicyState *client_policy = nullptr, ClientIoContext *client_io = nullptr,
    bool *observed_send_effects = nullptr);
int run_http09_client_connection_backend_loop(const Http09RuntimeConfig &config,
                                              const EndpointDriver &endpoint, QuicCore &core,
                                              ClientIoContext &io_context,
                                              EndpointDriveState &state,
                                              ClientRuntimePolicyState &client_policy,
                                              const QuicCoreResult &start_result);
int run_http09_client_connection_loop(const Http09RuntimeConfig &config,
                                      const EndpointDriver &endpoint, QuicCore &core,
                                      ClientSocketSet &client_sockets, int idle_timeout_ms,
                                      const sockaddr_storage &peer, socklen_t peer_len,
                                      EndpointDriveState &state,
                                      ClientRuntimePolicyState &client_policy,
                                      const ClientLoopIo &io, const QuicCoreResult &start_result);
QuicHttp09ClientConfig make_http09_client_endpoint_config(
    const Http09RuntimeConfig &config, const std::vector<QuicHttp09Request> &requests,
    bool attempt_zero_rtt_requests, const QuicCoreResult &start_result);
ClientConnectionRunResult run_http09_client_connection_with_core_config(
    const Http09RuntimeConfig &config, const std::vector<QuicHttp09Request> &requests,
    QuicCoreConfig core_config, std::uint64_t connection_index);
using ClientConnectionRunner = std::function<ClientConnectionRunResult(
    const Http09RuntimeConfig &, const std::vector<QuicHttp09Request> &, QuicCoreConfig,
    std::uint64_t)>;
int run_http09_resumed_client_sequence(const Http09RuntimeConfig &config,
                                       const std::vector<QuicHttp09Request> &requests,
                                       const ClientConnectionRunner &runner);
int run_http09_client_connection(const Http09RuntimeConfig &config,
                                 const std::vector<QuicHttp09Request> &requests,
                                 std::uint64_t connection_index);
int run_http09_client(const Http09RuntimeConfig &config);
bool process_existing_server_session_datagram(ServerSession &session, RuntimeWaitStep &step,
                                              ServerConnectionIdRouteMap &connection_id_routes,
                                              const ParsedServerDatagram &parsed,
                                              const EraseServerSessionFn &erase_session);
void process_expired_server_sessions(ServerSessionMap &sessions, QuicCoreTimePoint current,
                                     ServerConnectionIdRouteMap &connection_id_routes,
                                     const EraseServerSessionFn &erase_session,
                                     bool &processed_any);
bool pump_server_pending_endpoint_work(ServerSessionMap &sessions,
                                       ServerConnectionIdRouteMap &connection_id_routes,
                                       const EraseServerSessionFn &erase_session);
bool has_pending_server_endpoint_work(const ServerSessionMap &sessions);
QuicCoreEndpointConfig make_runtime_server_endpoint_config(const Http09RuntimeConfig &config,
                                                           TlsIdentity identity);
bool result_has_send_effects(const QuicCoreResult &result);
QuicConnectionHandle effect_connection_handle(const QuicCoreEffect &effect);
bool result_has_connection_lifecycle(const QuicCoreResult &result, QuicConnectionHandle connection,
                                     QuicCoreConnectionLifecycle event);
std::vector<QuicConnectionHandle> result_connection_handles(const QuicCoreResult &result);
QuicCoreResult slice_result_for_connection(const QuicCoreResult &result,
                                           QuicConnectionHandle connection);
void ensure_server_connection_endpoints_for_accepts(ServerConnectionEndpointMap &endpoints,
                                                    const QuicCoreResult &result,
                                                    const std::filesystem::path &document_root);
void erase_closed_server_connection_endpoints(ServerConnectionEndpointMap &endpoints,
                                              const QuicCoreResult &result);
std::optional<QuicCoreConnectionInput> to_connection_command_input(const QuicCoreInput &input);
QuicCoreResult advance_endpoint_connection_inputs(QuicCore &core, QuicConnectionHandle connection,
                                                  std::span<const QuicCoreInput> inputs,
                                                  QuicCoreTimePoint step_time);
bool process_server_endpoint_core_result(QuicCore &core, EndpointDriveState &transport_state,
                                         ServerConnectionEndpointMap &endpoints,
                                         const std::filesystem::path &document_root,
                                         QuicCoreResult initial_result, int fallback_socket_fd,
                                         const sockaddr_storage *fallback_peer,
                                         socklen_t fallback_peer_len,
                                         bool *observed_send_effects = nullptr);
bool process_server_endpoint_core_result_with_backend(
    QuicCore &core, EndpointDriveState &transport_state, ServerConnectionEndpointMap &endpoints,
    const std::filesystem::path &document_root, QuicCoreResult initial_result,
    const std::optional<QuicRouteHandle> &fallback_route_handle, QuicIoBackend &backend,
    bool *observed_send_effects = nullptr, std::vector<QuicIoTxDatagram> *deferred_output = nullptr,
    bool *observed_early_stream_data = nullptr);
bool pump_shared_server_endpoint_work(QuicCore &core, EndpointDriveState &transport_state,
                                      ServerConnectionEndpointMap &endpoints,
                                      const std::filesystem::path &document_root,
                                      bool &made_progress);
bool pump_shared_server_endpoint_work_with_backend(
    QuicCore &core, EndpointDriveState &transport_state, ServerConnectionEndpointMap &endpoints,
    const std::filesystem::path &document_root, QuicIoBackend &backend, bool &made_progress,
    std::vector<QuicIoTxDatagram> *deferred_output = nullptr,
    bool *observed_early_stream_data = nullptr);
bool has_pending_shared_server_endpoint_work(const ServerConnectionEndpointMap &endpoints);
bool process_path_mtu_update_event(const ServerBackendLoopDriver &driver,
                                   const QuicIoPathMtuUpdate &update, QuicCoreTimePoint now);
std::optional<QuicCoreTimePoint>
backend_output_wait_deadline(const std::optional<QuicCoreTimePoint> &next_wakeup,
                             const std::optional<QuicCoreTimePoint> &defer_output_until);
bool backend_deferred_output_flush_ready(
    QuicCoreTimePoint current, const std::optional<QuicCoreTimePoint> &defer_output_until);
bool flush_backend_deferred_output_if_ready(const ServerBackendLoopDriver &driver,
                                            QuicCoreTimePoint current, bool &server_failed);
void process_path_mtu_update_event_or_mark_failed(const ServerBackendLoopDriver &driver,
                                                  const QuicIoPathMtuUpdate &update,
                                                  QuicCoreTimePoint now, bool &server_failed);
ServerLoopIo make_runtime_server_loop_io();
int run_http09_server_loop(const ServerSocketSet &sockets, const ServerLoopIo &io,
                           const ServerLoopDriver &driver);
int run_server_backend_loop_with_driver(const ServerBackendLoopDriver &driver);
int run_http09_server_backend_loop(const Http09RuntimeConfig &config, QuicCore &core,
                                   EndpointDriveState &transport_state,
                                   ServerConnectionEndpointMap &endpoints, QuicIoBackend &backend);
int run_http09_server(const Http09RuntimeConfig &config);

} // namespace coquic::http09
