#pragma once

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "src/quic/http09_runtime.h"
#include "src/quic/io_backend_test_hooks.h"
#include "src/quic/packet.h"

namespace coquic::quic::test {

struct RuntimeWaitStepForTests {
    bool has_input = false;
    bool idle_timeout = false;
    bool has_source = false;
    bool input_is_timer_expired = false;
    std::size_t inbound_datagram_bytes = 0;
    socklen_t source_len = 0;
};

enum class DriveEndpointUntilBlockedCaseForTests : std::uint8_t {
    handle_core_effects_fail,
    initial_local_error,
    initial_local_error_handled,
    endpoint_failure,
    endpoint_success,
    endpoint_inputs_then_core_error,
};

struct DriveEndpointUntilBlockedResultForTests {
    bool returned = false;
    bool terminal_success = false;
    bool terminal_failure = false;
    bool endpoint_has_pending_work = false;
};

enum class ClientConnectionLoopCaseForTests : std::uint8_t {
    initial_terminal_success,
    timer_due_then_wait_failure,
    timer_due_then_drive_failure,
    outer_timer_then_wait_failure,
    outer_timer_then_drive_failure,
    pending_work_terminal_failure,
    pending_work_default_poll_then_wait_failure,
    pending_work_no_inputs_then_idle_timeout,
    receive_error_after_nonblocking_drain,
    receive_input_then_drive_failure,
    wait_failure,
    outer_pump_terminal_failure,
    outer_pump_terminal_success,
    wait_input_then_terminal_success,
    wait_input_then_terminal_success_with_followup_input,
    wait_input_then_drive_failure,
    wait_input_missing_failure,
    peer_input_then_outer_pump_terminal_success,
    wait_input_then_terminal_success_exits_after_drain_window,
    nonblocking_drain_repeats_pending_endpoint_progress,
    idle_timeout_with_future_wakeup_trace,
    idle_timeout_with_elapsed_wakeup_trace,
    timer_due_emits_send_trace_with_future_wakeup,
};

enum class ClientConnectionBackendLoopCaseForTests : std::uint8_t {
    initial_terminal_success,
    wait_failure,
    idle_timeout,
    shutdown,
    missing_rx_datagram,
    timer_event_then_wait_failure,
    timer_event_then_drive_failure,
    timer_event_then_terminal_success,
    rx_datagram_then_drive_failure,
    rx_datagram_then_terminal_success_after_elapsed_drain_window,
    rx_datagram_then_terminal_success_with_followup_input,
    pending_work_terminal_failure,
    pending_work_default_poll_then_wait_failure,
    pending_work_no_inputs_then_idle_timeout,
    outer_pump_terminal_failure,
    outer_pump_terminal_success,
    peer_input_then_outer_pump_terminal_success,
};

struct ClientConnectionLoopResultForTests {
    int exit_code = 0;
    bool terminal_success = false;
    bool terminal_failure = false;
    bool endpoint_has_pending_work = false;
    std::size_t receive_calls = 0;
    std::size_t wait_calls = 0;
    std::size_t current_time_calls = 0;
};

enum class ServerLoopCaseForTests : std::uint8_t {
    nonblocking_processed_timers_then_receive_error,
    nonblocking_process_datagram_failure,
    blocking_timer_then_receive_error,
    blocking_processed_timers_then_receive_error,
    blocking_wait_failure,
    blocking_wait_missing_input,
    nonblocking_drain_repeats_pending_endpoint_progress,
    outer_pump_repeats_pending_endpoint_progress,
    ready_datagram_preempts_next_pending_work_pump,
    pending_endpoint_without_transport_progress_waits_instead_of_spinning,
};

enum class ServerBackendLoopCaseForTests : std::uint8_t {
    wait_failure,
    shutdown,
    missing_rx_datagram,
    idle_timeout_then_shutdown,
    timer_event_then_shutdown,
    rx_datagram_then_shutdown,
};

struct ServerLoopResultForTests {
    int exit_code = 0;
    std::size_t current_time_calls = 0;
    std::size_t receive_calls = 0;
    std::size_t wait_calls = 0;
    std::size_t process_expired_calls = 0;
    std::size_t pump_calls = 0;
    std::size_t send_calls = 0;
};

struct ExistingServerSessionDatagramRouteResultForTests {
    bool processed = false;
    bool erased = false;
    bool has_migrated_path_route = false;
    int migrated_path_socket_fd = -1;
    int sendto_calls = 0;
    int sendto_socket_fd = -1;
    std::uint16_t sendto_peer_port = 0;
    std::vector<int> sendto_socket_fds;
    std::vector<std::uint16_t> sendto_peer_ports;
};

struct RuntimePathSeedForTests {
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

bool runtime_trace_enabled_for_tests();
std::string format_connection_id_hex_for_tests(std::span<const std::byte> connection_id);
std::string format_connection_id_key_hex_for_tests(std::string_view connection_id_key);
std::string connection_id_key_for_tests(std::span<const std::byte> connection_id);
int client_receive_timeout_ms_for_tests(const Http09RuntimeConfig &config);
QuicHttp09ClientConfig make_http09_client_endpoint_config_for_tests(
    const Http09RuntimeConfig &config, const std::vector<QuicHttp09Request> &requests,
    bool attempt_zero_rtt_requests, const QuicCoreResult &start_result);
QuicCoreConfig
make_http09_server_core_config_with_identity_for_tests(const Http09RuntimeConfig &config,
                                                       TlsIdentity identity);
int run_http09_client_connection_for_tests(const Http09RuntimeConfig &config,
                                           const std::vector<QuicHttp09Request> &requests,
                                           std::uint64_t connection_index);
std::optional<RuntimeWaitStepForTests>
wait_for_socket_or_deadline_for_tests(int socket_fd, int idle_timeout_ms,
                                      std::string_view role_name,
                                      const std::optional<QuicCoreTimePoint> &next_wakeup);
std::optional<QuicCoreTimePoint>
earliest_runtime_wakeup_for_tests(std::span<const std::optional<QuicCoreTimePoint>> wakeups);
DriveEndpointUntilBlockedResultForTests
drive_endpoint_until_blocked_case_for_tests(DriveEndpointUntilBlockedCaseForTests case_id);
ClientConnectionLoopResultForTests
run_client_connection_loop_case_for_tests(ClientConnectionLoopCaseForTests case_id);
ClientConnectionLoopResultForTests
run_client_connection_backend_loop_case_for_tests(ClientConnectionBackendLoopCaseForTests case_id);
bool existing_server_session_failure_cleans_up_for_tests();
bool existing_server_session_missing_input_fails_for_tests();
bool preferred_address_routes_to_existing_server_session_for_tests();
bool runtime_backend_connectionmigration_request_flow_for_tests();
bool runtime_backend_official_connectionmigration_client_request_flow_for_tests();
bool runtime_backend_cross_family_preferred_address_requests_backend_route_for_tests();
bool runtime_client_loop_requests_preferred_address_route_from_backend_for_tests();
bool runtime_backend_preferred_address_route_failure_stops_migration_request_for_tests();
bool runtime_backend_regular_transfer_does_not_queue_preferred_address_migration_for_tests();
bool expired_server_timer_failure_cleans_up_for_tests();
bool expired_server_timer_success_preserves_session_for_tests();
bool pending_server_work_failure_cleans_up_for_tests();
bool resumed_client_warmup_failure_exits_early_for_tests();
bool zero_rtt_request_allowance_for_tests();
bool version_negotiation_without_source_connection_id_fails_for_tests();
bool runtime_assigns_stable_path_ids_for_tests();
bool drive_endpoint_uses_transport_selected_path_for_tests();
bool core_version_negotiation_restart_preserves_inbound_path_ids_for_tests();
bool core_retry_restart_preserves_inbound_path_ids_for_tests();
bool drive_endpoint_rejects_unknown_transport_selected_path_for_tests();
bool runtime_policy_core_inputs_advance_before_terminal_success_for_tests();
bool server_connectionmigration_preferred_address_config_for_tests();
bool runtime_configures_linux_ecn_socket_options_for_tests();
bool runtime_sendmsg_uses_outbound_ecn_for_tests();
bool runtime_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests();
bool runtime_recvmsg_maps_ecn_to_core_input_for_tests();
bool runtime_registers_all_server_core_connection_ids_for_tests();
bool runtime_server_route_handles_are_stable_per_peer_tuple_for_tests();
bool runtime_server_send_effect_uses_route_handle_for_tests();
bool runtime_misc_internal_coverage_for_tests();
bool runtime_additional_internal_coverage_for_tests();
bool runtime_low_level_socket_and_ecn_coverage_for_tests();
bool runtime_connectionmigration_failure_paths_for_tests();
bool runtime_restart_failure_paths_for_tests();
ExistingServerSessionDatagramRouteResultForTests route_existing_server_session_datagram_for_tests(
    QuicCore &core, std::span<const RuntimePathSeedForTests> seeded_paths,
    std::span<const std::byte> local_connection_id,
    std::span<const std::byte> initial_destination_connection_id, int inbound_socket_fd,
    const sockaddr_storage &inbound_peer, socklen_t inbound_peer_len, std::vector<std::byte> bytes,
    QuicCoreTimePoint input_time);
ExistingServerSessionDatagramRouteResultForTests route_existing_server_session_datagram_for_tests(
    QuicCore &core, int established_socket_fd, const sockaddr_storage &established_peer,
    socklen_t established_peer_len, std::span<const std::byte> local_connection_id,
    std::span<const std::byte> initial_destination_connection_id, int inbound_socket_fd,
    const sockaddr_storage &inbound_peer, socklen_t inbound_peer_len, std::vector<std::byte> bytes,
    QuicCoreTimePoint input_time);
ServerLoopResultForTests run_server_loop_case_for_tests(ServerLoopCaseForTests case_id);
ServerLoopResultForTests
run_server_backend_loop_case_for_tests(ServerBackendLoopCaseForTests case_id);

} // namespace coquic::quic::test
