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

#include "src/io/io_backend_test_hooks.h"
#include "src/http09/http09_runtime.h"
#include "src/quic/codec/packet.h"

namespace coquic::http09::test {

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
    wait_input_then_nonterminal_idle_timeout_failure,
    peer_input_then_outer_pump_terminal_success,
    wait_input_then_terminal_success_exits_after_drain_window,
    nonblocking_drain_repeats_pending_endpoint_progress,
    idle_timeout_with_future_wakeup_trace,
    idle_timeout_with_elapsed_wakeup_trace,
    timer_due_emits_send_trace_with_future_wakeup,
    pending_work_terminal_failure_state_after_pump,
    nonblocking_receive_terminal_failure_state,
    advanced_core_without_pending_work_returns_success,
};

enum class ClientConnectionBackendLoopCaseForTests : std::uint8_t {
    initial_terminal_success,
    wait_failure,
    idle_timeout,
    shutdown,
    missing_rx_datagram,
    timer_event_then_wait_failure,
    timer_due_before_wait_then_wait_failure,
    timer_due_before_wait_then_drive_failure,
    timer_event_then_drive_failure,
    timer_event_then_terminal_success,
    missing_path_mtu_update,
    path_mtu_update_then_wait_failure,
    path_mtu_update_then_drive_failure,
    rx_datagram_then_drive_failure,
    rx_datagram_then_terminal_success_after_elapsed_drain_window,
    rx_datagram_then_terminal_success_with_followup_input,
    pending_work_terminal_failure,
    pending_work_default_poll_then_wait_failure,
    pending_work_no_inputs_then_idle_timeout,
    outer_pump_terminal_failure,
    outer_pump_terminal_success,
    peer_input_then_outer_pump_terminal_success,
    pending_work_core_inputs_are_drained_before_wait,
    pending_work_followup_timer_drive_failure,
    pending_work_followup_timer_continue_then_terminal_success,
};

struct ClientConnectionLoopResultForTests {
    int exit_code = 0;
    bool terminal_success = false;
    bool terminal_failure = false;
    bool endpoint_has_pending_work = false;
    std::size_t receive_calls = 0;
    std::size_t wait_calls = 0;
    std::size_t current_time_calls = 0;
    std::vector<std::optional<quic::QuicCoreTimePoint>> wait_requests;
};

bool runtime_trace_enabled_for_tests();
std::string format_connection_id_hex_for_tests(std::span<const std::byte> connection_id);
std::string format_connection_id_key_hex_for_tests(std::string_view connection_id_key);
std::string connection_id_key_for_tests(std::span<const std::byte> connection_id);
int client_receive_timeout_ms_for_tests(const Http09RuntimeConfig &config);
QuicHttp09ClientConfig make_http09_client_endpoint_config_for_tests(
    const Http09RuntimeConfig &config, const std::vector<QuicHttp09Request> &requests,
    bool attempt_zero_rtt_requests, const quic::QuicCoreResult &start_result);
quic::QuicCoreConfig
make_http09_server_core_config_with_identity_for_tests(const Http09RuntimeConfig &config,
                                                       quic::TlsIdentity identity);
quic::QuicCoreEndpointConfig
make_runtime_server_endpoint_config_for_tests(const Http09RuntimeConfig &config,
                                              quic::TlsIdentity identity);
int run_http09_client_connection_for_tests(const Http09RuntimeConfig &config,
                                           const std::vector<QuicHttp09Request> &requests,
                                           std::uint64_t connection_index);
std::optional<RuntimeWaitStepForTests>
wait_for_socket_or_deadline_for_tests(int socket_fd, int idle_timeout_ms,
                                      std::string_view role_name,
                                      const std::optional<quic::QuicCoreTimePoint> &next_wakeup);
std::optional<quic::QuicCoreTimePoint>
earliest_runtime_wakeup_for_tests(std::span<const std::optional<quic::QuicCoreTimePoint>> wakeups);
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
bool pending_server_work_success_preserves_session_for_tests();
bool resumed_client_warmup_failure_exits_early_for_tests();
bool zero_rtt_request_allowance_for_tests();
bool runtime_assigns_stable_path_ids_for_tests();
bool drive_endpoint_uses_transport_selected_path_for_tests();
bool runtime_policy_core_inputs_advance_before_terminal_success_for_tests();
bool server_connectionmigration_preferred_address_config_for_tests();
bool runtime_configures_linux_ecn_socket_options_for_tests();
bool runtime_sendmsg_uses_outbound_ecn_for_tests();
bool runtime_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests();
bool runtime_recvmsg_maps_ecn_to_core_input_for_tests();
bool runtime_registers_all_server_core_connection_ids_for_tests();
bool runtime_server_route_handles_are_stable_per_peer_tuple_for_tests();
bool runtime_server_send_effect_uses_route_handle_for_tests();
bool runtime_restart_failure_paths_for_tests();

} // namespace coquic::http09::test
