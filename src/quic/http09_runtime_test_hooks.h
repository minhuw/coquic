#pragma once

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "src/quic/http09_runtime.h"
#include "src/quic/packet.h"

namespace coquic::quic::test {

enum class ParsedServerDatagramKind : std::uint8_t {
    short_header,
    supported_initial,
    supported_long_header,
    unsupported_version_long_header,
};

struct ParsedServerDatagramForTests {
    ParsedServerDatagramKind kind;
    ConnectionId destination_connection_id;
    std::optional<ConnectionId> source_connection_id;
};

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
    wait_input_then_drive_failure,
    wait_input_missing_failure,
};

struct ClientConnectionLoopResultForTests {
    int exit_code = 0;
    bool terminal_success = false;
    bool terminal_failure = false;
    bool endpoint_has_pending_work = false;
};

enum class ServerLoopCaseForTests : std::uint8_t {
    nonblocking_processed_timers_then_receive_error,
    nonblocking_process_datagram_failure,
    blocking_timer_then_receive_error,
    blocking_processed_timers_then_receive_error,
    blocking_wait_failure,
    blocking_wait_missing_input,
};

struct ServerLoopResultForTests {
    int exit_code = 0;
    std::size_t current_time_calls = 0;
    std::size_t receive_calls = 0;
    std::size_t wait_calls = 0;
    std::size_t process_expired_calls = 0;
};

struct Http09RuntimeOpsOverride {
    int (*socket_fn)(int, int, int) = nullptr;
    int (*bind_fn)(int, const sockaddr *, socklen_t) = nullptr;
    int (*poll_fn)(pollfd *, nfds_t, int) = nullptr;
    ssize_t (*sendto_fn)(int, const void *, size_t, int, const sockaddr *, socklen_t) = nullptr;
    ssize_t (*recvfrom_fn)(int, void *, size_t, int, sockaddr *, socklen_t *) = nullptr;
    int (*getaddrinfo_fn)(const char *, const char *, const addrinfo *, addrinfo **) = nullptr;
    void (*freeaddrinfo_fn)(addrinfo *) = nullptr;
};

class ScopedHttp09RuntimeOpsOverride {
  public:
    explicit ScopedHttp09RuntimeOpsOverride(Http09RuntimeOpsOverride override_ops);
    ~ScopedHttp09RuntimeOpsOverride();

    ScopedHttp09RuntimeOpsOverride(const ScopedHttp09RuntimeOpsOverride &) = delete;
    ScopedHttp09RuntimeOpsOverride &operator=(const ScopedHttp09RuntimeOpsOverride &) = delete;

  private:
    Http09RuntimeOpsOverride previous_;
};

bool runtime_trace_enabled_for_tests();
std::string format_connection_id_hex_for_tests(std::span<const std::byte> connection_id);
std::string format_connection_id_key_hex_for_tests(std::string_view connection_id_key);
std::string connection_id_key_for_tests(std::span<const std::byte> connection_id);
int client_receive_timeout_ms_for_tests(const Http09RuntimeConfig &config);
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
bool existing_server_session_failure_cleans_up_for_tests();
bool existing_server_session_missing_input_fails_for_tests();
bool expired_server_timer_failure_cleans_up_for_tests();
bool pending_server_work_failure_cleans_up_for_tests();
bool version_negotiation_without_source_connection_id_fails_for_tests();
ServerLoopResultForTests run_server_loop_case_for_tests(ServerLoopCaseForTests case_id);
std::optional<ParsedServerDatagramForTests>
parse_server_datagram_for_routing_for_tests(std::span<const std::byte> bytes);

} // namespace coquic::quic::test
