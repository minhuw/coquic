#ifndef COQUIC_HTTP09_RUNTIME_TEST_SUPPORT_H
#define COQUIC_HTTP09_RUNTIME_TEST_SUPPORT_H

#include "src/http09/http09_runtime_internal.h"

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace coquic::http09 {

namespace test {

namespace {

struct ScriptedEndpointForTests {
    std::vector<QuicHttp09EndpointUpdate> on_core_result_updates;
    std::vector<QuicHttp09EndpointUpdate> poll_updates;
    std::vector<std::optional<QuicCoreTimePoint>> next_wakeup_overrides;
    EndpointDriveState *state = nullptr;
    std::size_t next_on_core_result_index = 0;
    std::size_t next_poll_index = 0;

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult &, QuicCoreTimePoint) {
        const auto update_index = next_on_core_result_index;
        if (next_on_core_result_index >= on_core_result_updates.size()) {
            return {};
        }
        auto update = on_core_result_updates[next_on_core_result_index++];
        if (state != nullptr && update_index < next_wakeup_overrides.size() &&
            next_wakeup_overrides[update_index].has_value()) {
            state->next_wakeup = next_wakeup_overrides[update_index];
        }
        return update;
    }

    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint) {
        if (next_poll_index >= poll_updates.size()) {
            return {};
        }
        return poll_updates[next_poll_index++];
    }
};

QuicCore make_failing_server_core_for_tests() {
    const auto config = Http09RuntimeConfig{
        .mode = Http09RuntimeMode::server,
    };
    return QuicCore(make_http09_server_core_config(config));
}

QuicCore make_local_error_client_core_for_tests() {
    const auto config = Http09RuntimeConfig{
        .mode = Http09RuntimeMode::client,
    };
    return QuicCore(make_http09_client_core_config(config));
}

struct RecordedSendToForTests {
    int calls = 0;
    int socket_fd = -1;
    socklen_t peer_len = 0;
    std::uint16_t peer_port = 0;
    std::vector<int> socket_fds;
    std::vector<std::uint16_t> peer_ports;
};

thread_local RecordedSendToForTests g_recorded_sendto_for_tests;

struct RecordedSetSockOptForTests {
    struct Call {
        int level = 0;
        int name = 0;
        int value = 0;
    };

    std::vector<Call> calls;
};

thread_local RecordedSetSockOptForTests g_recorded_setsockopt_for_tests;

struct RecordedSendMsgForTests {
    int calls = 0;
    int socket_fd = -1;
    int level = 0;
    int type = 0;
    int traffic_class = 0;
};

thread_local RecordedSendMsgForTests g_recorded_sendmsg_for_tests;

struct RecordedRecvMsgForTests {
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
    std::vector<std::byte> bytes;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

thread_local RecordedRecvMsgForTests g_recorded_recvmsg_for_tests;
int &runtime_low_level_getaddrinfo_calls_for_tests() {
    static thread_local int calls = 0;
    return calls;
}

int &runtime_low_level_bind_calls_for_tests() {
    static thread_local int calls = 0;
    return calls;
}

ssize_t record_sendto_for_tests(int socket_fd, const void *, size_t length, int,
                                const sockaddr *destination, socklen_t destination_len) {
    g_recorded_sendto_for_tests.calls += 1;
    g_recorded_sendto_for_tests.socket_fd = socket_fd;
    g_recorded_sendto_for_tests.peer_len = destination_len;
    g_recorded_sendto_for_tests.socket_fds.push_back(socket_fd);
    std::uint16_t peer_port = 0;
    if (destination != nullptr && destination->sa_family == AF_INET &&
        destination_len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(destination);
        peer_port = ntohs(ipv4->sin_port);
    } else if (destination != nullptr && destination->sa_family == AF_INET6 &&
               destination_len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(destination);
        peer_port = ntohs(ipv6->sin6_port);
    }
    g_recorded_sendto_for_tests.peer_port = peer_port;
    g_recorded_sendto_for_tests.peer_ports.push_back(peer_port);
    return static_cast<ssize_t>(length);
}

int record_setsockopt_for_tests(int, int level, int name, const void *value, socklen_t value_len) {
    int option_value = 0;
    if (value != nullptr && value_len >= static_cast<socklen_t>(sizeof(option_value))) {
        std::memcpy(&option_value, value, sizeof(option_value));
    }
    g_recorded_setsockopt_for_tests.calls.push_back(RecordedSetSockOptForTests::Call{
        .level = level,
        .name = name,
        .value = option_value,
    });
    return 0;
}

ssize_t record_sendmsg_for_tests(int socket_fd, const msghdr *message, int) {
    g_recorded_sendmsg_for_tests.calls += 1;
    g_recorded_sendmsg_for_tests.socket_fd = socket_fd;
    g_recorded_sendmsg_for_tests.level = 0;
    g_recorded_sendmsg_for_tests.type = 0;
    g_recorded_sendmsg_for_tests.traffic_class = 0;
    for (auto *control = CMSG_FIRSTHDR(const_cast<msghdr *>(message)); control != nullptr;
         control = CMSG_NXTHDR(const_cast<msghdr *>(message), control)) {
        g_recorded_sendmsg_for_tests.level = control->cmsg_level;
        g_recorded_sendmsg_for_tests.type = control->cmsg_type;
        std::memcpy(&g_recorded_sendmsg_for_tests.traffic_class, CMSG_DATA(control),
                    sizeof(g_recorded_sendmsg_for_tests.traffic_class));
        break;
    }
    return message != nullptr && message->msg_iov != nullptr
               ? static_cast<ssize_t>(message->msg_iov[0].iov_len)
               : 0;
}

ssize_t record_recvmsg_for_tests(int, msghdr *message, int) {
    if (message == nullptr || message->msg_iov == nullptr || message->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    const auto bytes_to_copy = std::min<std::size_t>(g_recorded_recvmsg_for_tests.bytes.size(),
                                                     message->msg_iov[0].iov_len);
    std::memcpy(message->msg_iov[0].iov_base, g_recorded_recvmsg_for_tests.bytes.data(),
                bytes_to_copy);
    if (message->msg_name != nullptr &&
        message->msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        std::memcpy(message->msg_name, &g_recorded_recvmsg_for_tests.peer,
                    sizeof(sockaddr_storage));
        message->msg_namelen = g_recorded_recvmsg_for_tests.peer_len;
    }

    auto *header = CMSG_FIRSTHDR(message);
    if (header != nullptr) {
        const bool ipv6 = g_recorded_recvmsg_for_tests.peer.ss_family == AF_INET6;
        header->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
        header->cmsg_type = ipv6 ? IPV6_TCLASS : IP_TOS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        const int traffic_class = linux_traffic_class_for_ecn(g_recorded_recvmsg_for_tests.ecn);
        std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
        message->msg_controllen = header->cmsg_len;
    }

    return static_cast<ssize_t>(bytes_to_copy);
}

struct ScriptedClientLoopIoForTests {
    std::vector<QuicCoreTimePoint> now_values;
    std::vector<ReceiveDatagramResult> receive_results;
    std::vector<std::optional<RuntimeWaitStep>> wait_steps;
    std::size_t next_now_index = 0;
    std::size_t next_receive_index = 0;
    std::size_t next_wait_index = 0;
};

QuicCoreTimePoint scripted_client_loop_now_for_tests(void *context) {
    auto &script = *static_cast<ScriptedClientLoopIoForTests *>(context);
    if (script.next_now_index >= script.now_values.size()) {
        return now();
    }
    return script.now_values[script.next_now_index++];
}

ReceiveDatagramResult scripted_client_loop_receive_for_tests(void *context, int, int,
                                                             std::string_view) {
    auto &script = *static_cast<ScriptedClientLoopIoForTests *>(context);
    if (script.next_receive_index >= script.receive_results.size()) {
        ReceiveDatagramResult result{};
        result.status = ReceiveDatagramStatus::would_block;
        return result;
    }
    return std::move(script.receive_results[script.next_receive_index++]);
}

std::optional<RuntimeWaitStep>
scripted_client_loop_wait_for_tests(void *context, const RuntimeWaitConfig &,
                                    const std::optional<QuicCoreTimePoint> &) {
    auto &script = *static_cast<ScriptedClientLoopIoForTests *>(context);
    if (script.next_wait_index >= script.wait_steps.size()) {
        return std::nullopt;
    }
    return std::move(script.wait_steps[script.next_wait_index++]);
}

ClientLoopIo make_scripted_client_loop_io_for_tests(ScriptedClientLoopIoForTests &script) {
    return ClientLoopIo{
        .context = &script,
        .now_fn = &scripted_client_loop_now_for_tests,
        .receive_datagram_fn = &scripted_client_loop_receive_for_tests,
        .wait_for_socket_or_deadline_fn = &scripted_client_loop_wait_for_tests,
    };
}

struct FailureInjectingClientLoopIoForTests {
    ScriptedClientLoopIoForTests *script = nullptr;
    EndpointDriveState *state = nullptr;
};

QuicCoreTimePoint failure_injecting_client_loop_now_for_tests(void *context) {
    auto &script = *static_cast<FailureInjectingClientLoopIoForTests *>(context)->script;
    return scripted_client_loop_now_for_tests(&script);
}

ReceiveDatagramResult failure_injecting_client_loop_receive_for_tests(void *context, int socket_fd,
                                                                      int flags,
                                                                      std::string_view role_name) {
    auto &wrapped = *static_cast<FailureInjectingClientLoopIoForTests *>(context);
    wrapped.state->terminal_failure = true;
    return scripted_client_loop_receive_for_tests(wrapped.script, socket_fd, flags, role_name);
}

std::optional<RuntimeWaitStep>
failure_injecting_client_loop_wait_for_tests(void *context, const RuntimeWaitConfig &config,
                                             const std::optional<QuicCoreTimePoint> &next_wakeup) {
    auto &script = *static_cast<FailureInjectingClientLoopIoForTests *>(context)->script;
    return scripted_client_loop_wait_for_tests(&script, config, next_wakeup);
}

QuicIoTxDatagram owning_tx_datagram_for_tests(const QuicIoTxDatagram &datagram) {
    return QuicIoTxDatagram{
        .route_handle = datagram.route_handle,
        .bytes = DatagramBuffer(datagram.payload()),
        .ecn = datagram.ecn,
        .is_pmtu_probe = datagram.is_pmtu_probe,
    };
}

class ScriptedIoBackendForTests final : public QuicIoBackend {
  public:
    std::vector<QuicIoRemote> ensure_route_calls;
    std::vector<std::optional<QuicRouteHandle>> ensure_route_results;
    std::size_t next_ensure_route_result_index = 0;
    std::vector<std::optional<QuicCoreTimePoint>> wait_requests;
    std::vector<std::optional<QuicIoEvent>> wait_results;
    std::size_t next_wait_result_index = 0;
    std::vector<QuicIoTxDatagram> sent_datagrams;

    std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &remote) override {
        ensure_route_calls.push_back(remote);
        if (next_ensure_route_result_index >= ensure_route_results.size()) {
            return std::nullopt;
        }
        return ensure_route_results[next_ensure_route_result_index++];
    }

    std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint> next_wakeup) override {
        wait_requests.push_back(next_wakeup);
        if (next_wait_result_index >= wait_results.size()) {
            return std::nullopt;
        }
        return wait_results[next_wait_result_index++];
    }

    bool send(const QuicIoTxDatagram &datagram) override {
        sent_datagrams.push_back(owning_tx_datagram_for_tests(datagram));
        return true;
    }
};

std::uint16_t peer_port_for_remote_for_tests(const QuicIoRemote &remote) {
    if (remote.family == AF_INET &&
        remote.peer_len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(&remote.peer);
        return ntohs(ipv4->sin_port);
    }
    if (remote.family == AF_INET6 &&
        remote.peer_len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(&remote.peer);
        return ntohs(ipv6->sin6_port);
    }
    return 0;
}

QuicCorePeerPreferredAddressAvailable
make_ipv4_preferred_address_effect_for_tests(std::uint16_t port = 4444) {
    return QuicCorePeerPreferredAddressAvailable{
        .preferred_address =
            PreferredAddress{
                .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
                .ipv4_port = port,
                .connection_id = make_runtime_connection_id(std::byte{0x5a}, 1),
            },
    };
}

QuicCorePeerPreferredAddressAvailable
make_ipv6_preferred_address_effect_for_tests(std::uint16_t port = 4444) {
    return QuicCorePeerPreferredAddressAvailable{
        .preferred_address =
            PreferredAddress{
                .ipv6_address =
                    {
                        std::byte{0x20},
                        std::byte{0x01},
                        std::byte{0x0d},
                        std::byte{0xb8},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x46},
                    },
                .ipv6_port = port,
                .connection_id = make_runtime_connection_id(std::byte{0x5a}, 1),
            },
    };
}

ReceiveDatagramResult make_would_block_receive_for_tests() {
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::would_block,
    };
}

ReceiveDatagramResult make_error_receive_for_tests() {
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::error,
    };
}

ReceiveDatagramResult make_input_receive_for_tests(QuicCoreInput input) {
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::ok,
        .step =
            RuntimeWaitStep{
                .input = std::move(input),
                .input_time = now(),
            },
    };
}

RuntimeWaitStep make_idle_timeout_wait_step_for_tests() {
    return RuntimeWaitStep{
        .input_time = now(),
        .idle_timeout = true,
    };
}

RuntimeWaitStep make_input_wait_step_for_tests(QuicCoreInput input) {
    return RuntimeWaitStep{
        .input = std::move(input),
        .input_time = now(),
    };
}

struct ScriptedServerLoopCaseForTests {
    std::vector<ReceiveDatagramResult> receive_results;
    std::vector<std::optional<RuntimeWaitStep>> wait_steps;
    std::vector<bool> processed_timers_results;
    std::vector<bool> pending_work_after_pump;
    std::vector<bool> pump_made_progress;
    bool process_datagram_result = true;
};

struct ScriptedServerBackendSchedulingCaseForTests {
    std::vector<QuicCoreTimePoint> current_times;
    std::vector<std::optional<QuicCoreTimePoint>> next_wakeup_results;
    std::vector<bool> pending_work_after_pump;
    std::vector<bool> pump_made_progress;
    std::vector<std::optional<QuicIoEvent>> wait_results;
    std::optional<QuicIoEvent> initial_buffered_event;
    std::optional<QuicCoreTimePoint> defer_output_until;
    bool blocking_rx_requires_future_wait = false;
    std::optional<QuicIoEvent> blocking_rx_wait_result;
    std::size_t max_immediate_waits_before_failure = 0;
    bool process_timer_event_result = true;
    bool process_datagram_result = true;
};

ScriptedServerLoopCaseForTests
make_nonblocking_processed_timers_then_receive_error_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_error_receive_for_tests(),
            },
        .processed_timers_results = {true, false},
    };
}

ScriptedServerLoopCaseForTests make_nonblocking_process_datagram_failure_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_input_receive_for_tests(QuicCoreTimerExpired{}),
            },
        .processed_timers_results = {false},
        .process_datagram_result = false,
    };
}

ScriptedServerLoopCaseForTests make_blocking_timer_then_receive_error_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .wait_steps =
            {
                make_input_wait_step_for_tests(QuicCoreTimerExpired{}),
            },
        .processed_timers_results = {false, false, false, false},
    };
}

ScriptedServerLoopCaseForTests make_blocking_processed_timers_then_receive_error_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .processed_timers_results = {false, true, false},
    };
}

ScriptedServerLoopCaseForTests make_blocking_wait_failure_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
            },
        .wait_steps =
            {
                std::nullopt,
            },
        .processed_timers_results = {false, false},
    };
}

ScriptedServerLoopCaseForTests make_blocking_wait_missing_input_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
            },
        .wait_steps =
            {
                RuntimeWaitStep{
                    .input_time = now(),
                },
            },
        .processed_timers_results = {false, false},
    };
}

ScriptedServerLoopCaseForTests
make_nonblocking_drain_repeats_pending_endpoint_progress_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .wait_steps =
            {
                std::nullopt,
            },
        .processed_timers_results = {false, false, false},
        .pending_work_after_pump = {true, true, false},
    };
}

ScriptedServerLoopCaseForTests make_outer_pump_repeats_pending_endpoint_progress_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .processed_timers_results = {false},
        .pending_work_after_pump = {false, true, false},
    };
}

ScriptedServerLoopCaseForTests
make_ready_datagram_preempts_next_pending_work_pump_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_input_receive_for_tests(QuicCoreTimerExpired{}),
            },
        .processed_timers_results = {false, false},
        .pending_work_after_pump = {true},
        .pump_made_progress = {true},
        .process_datagram_result = false,
    };
}

ScriptedServerLoopCaseForTests
make_pending_endpoint_without_transport_progress_waits_instead_of_spinning_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_would_block_receive_for_tests(),
                make_would_block_receive_for_tests(),
            },
        .wait_steps =
            {
                std::nullopt,
            },
        .processed_timers_results = {false, false, false, false},
        .pending_work_after_pump = {true, true, false, false},
        .pump_made_progress = {false, false, false, false},
    };
}

ScriptedServerLoopCaseForTests make_blocking_wait_failure_with_preferred_socket_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_would_block_receive_for_tests(),
            },
        .wait_steps =
            {
                std::nullopt,
            },
        .processed_timers_results = {false, false},
    };
}

ScriptedServerLoopCaseForTests make_blocking_wait_input_then_receive_error_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .wait_steps =
            {
                make_input_wait_step_for_tests(QuicCoreInboundDatagram{
                    .bytes = {std::byte{0x01}},
                }),
            },
        .processed_timers_results = {false, false, false},
        .pending_work_after_pump = {false, false},
        .pump_made_progress = {false, false},
    };
}

ScriptedServerLoopCaseForTests make_server_loop_case_for_tests(ServerLoopCaseForTests case_id) {
    switch (case_id) {
    case ServerLoopCaseForTests::nonblocking_processed_timers_then_receive_error:
        return make_nonblocking_processed_timers_then_receive_error_case_for_tests();
    case ServerLoopCaseForTests::nonblocking_process_datagram_failure:
        return make_nonblocking_process_datagram_failure_case_for_tests();
    case ServerLoopCaseForTests::blocking_timer_then_receive_error:
        return make_blocking_timer_then_receive_error_case_for_tests();
    case ServerLoopCaseForTests::blocking_processed_timers_then_receive_error:
        return make_blocking_processed_timers_then_receive_error_case_for_tests();
    case ServerLoopCaseForTests::blocking_wait_failure:
        return make_blocking_wait_failure_case_for_tests();
    case ServerLoopCaseForTests::blocking_wait_failure_with_preferred_socket:
        return make_blocking_wait_failure_with_preferred_socket_case_for_tests();
    case ServerLoopCaseForTests::blocking_wait_missing_input:
        return make_blocking_wait_missing_input_case_for_tests();
    case ServerLoopCaseForTests::nonblocking_drain_repeats_pending_endpoint_progress:
        return make_nonblocking_drain_repeats_pending_endpoint_progress_case_for_tests();
    case ServerLoopCaseForTests::outer_pump_repeats_pending_endpoint_progress:
        return make_outer_pump_repeats_pending_endpoint_progress_case_for_tests();
    case ServerLoopCaseForTests::ready_datagram_preempts_next_pending_work_pump:
        return make_ready_datagram_preempts_next_pending_work_pump_case_for_tests();
    case ServerLoopCaseForTests::
        pending_endpoint_without_transport_progress_waits_instead_of_spinning:
        return make_pending_endpoint_without_transport_progress_waits_instead_of_spinning_case_for_tests();
    case ServerLoopCaseForTests::blocking_wait_input_then_receive_error:
        return make_blocking_wait_input_then_receive_error_case_for_tests();
    }

    return make_nonblocking_processed_timers_then_receive_error_case_for_tests();
}

ScriptedServerBackendSchedulingCaseForTests
make_ready_datagram_preempts_repeated_due_timers_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time,
                base_time,
                base_time,
            },
        .next_wakeup_results =
            {
                base_time,
                base_time,
                base_time,
            },
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::rx_datagram,
                    .now = base_time,
                    .datagram =
                        QuicIoRxDatagram{
                            .route_handle = QuicRouteHandle{17},
                            .bytes = {std::byte{0x01}},
                        },
                },
            },
        .process_datagram_result = false,
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_ready_datagram_preempts_repeated_pending_work_pumps_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time,
                base_time,
                base_time,
                base_time,
            },
        .pending_work_after_pump = {true, true, true, false},
        .pump_made_progress = {true, true, true, true},
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::rx_datagram,
                    .now = base_time,
                    .datagram =
                        QuicIoRxDatagram{
                            .route_handle = QuicRouteHandle{17},
                            .bytes = {std::byte{0x01}},
                        },
                },
            },
        .process_datagram_result = false,
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_pending_work_yields_to_wait_after_immediate_poll_miss_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time,
                base_time,
                base_time,
            },
        .next_wakeup_results =
            {
                base_time + std::chrono::milliseconds(5),
                base_time + std::chrono::milliseconds(5),
                base_time + std::chrono::milliseconds(5),
            },
        .pending_work_after_pump = {true, false},
        .pump_made_progress = {true, false},
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::timer_expired,
                    .now = base_time,
                },
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::rx_datagram,
                    .now = base_time + std::chrono::milliseconds(1),
                    .datagram =
                        QuicIoRxDatagram{
                            .route_handle = QuicRouteHandle{17},
                            .bytes = {std::byte{0x01}},
                        },
                },
            },
        .process_datagram_result = false,
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_elapsed_wakeup_after_immediate_poll_miss_yields_to_blocking_rx_wait_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time,
                base_time,
                base_time,
                base_time,
            },
        .next_wakeup_results =
            {
                base_time + std::chrono::milliseconds(5),
                base_time,
                base_time + std::chrono::milliseconds(1),
            },
        .pending_work_after_pump = {true},
        .pump_made_progress = {true},
        .blocking_rx_requires_future_wait = true,
        .blocking_rx_wait_result =
            QuicIoEvent{
                .kind = QuicIoEvent::Kind::rx_datagram,
                .now = base_time + std::chrono::milliseconds(1),
                .datagram =
                    QuicIoRxDatagram{
                        .route_handle = QuicRouteHandle{17},
                        .bytes = {std::byte{0x01}},
                    },
            },
        .max_immediate_waits_before_failure = 3,
        .process_datagram_result = false,
    };
}

ScriptedServerBackendSchedulingCaseForTests make_ready_probe_due_timer_failure_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time + std::chrono::milliseconds(5),
            },
        .next_wakeup_results =
            {
                base_time + std::chrono::milliseconds(5),
                base_time + std::chrono::milliseconds(5),
            },
        .pending_work_after_pump = {true},
        .pump_made_progress = {true},
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::timer_expired,
                    .now = base_time + std::chrono::milliseconds(5),
                },
            },
        .process_timer_event_result = false,
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_ready_probe_idle_timeout_then_shutdown_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time,
                base_time,
            },
        .next_wakeup_results =
            {
                base_time + std::chrono::milliseconds(5),
                base_time + std::chrono::milliseconds(5),
                base_time + std::chrono::milliseconds(5),
            },
        .pending_work_after_pump = {true},
        .pump_made_progress = {true},
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::idle_timeout,
                    .now = base_time,
                },
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::shutdown,
                    .now = base_time + std::chrono::milliseconds(1),
                },
            },
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_buffered_top_due_idle_timeout_skips_ready_probe_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time + std::chrono::milliseconds(1),
            },
        .next_wakeup_results =
            {
                std::nullopt,
            },
        .pending_work_after_pump = {true, false},
        .pump_made_progress = {true, false},
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::shutdown,
                    .now = base_time + std::chrono::milliseconds(1),
                },
            },
        .initial_buffered_event =
            QuicIoEvent{
                .kind = QuicIoEvent::Kind::idle_timeout,
                .now = base_time,
            },
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_ready_probe_rx_datagram_success_then_shutdown_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time + std::chrono::milliseconds(1),
            },
        .next_wakeup_results =
            {
                std::nullopt,
            },
        .pending_work_after_pump = {true, false},
        .pump_made_progress = {true, false},
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::rx_datagram,
                    .now = base_time,
                    .datagram =
                        QuicIoRxDatagram{
                            .route_handle = QuicRouteHandle{17},
                            .bytes = {std::byte{0x01}},
                        },
                },
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::shutdown,
                    .now = base_time + std::chrono::milliseconds(1),
                },
            },
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_ready_probe_timer_without_wakeup_falls_back_to_main_wait_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
            },
        .next_wakeup_results =
            {
                std::nullopt,
            },
        .pending_work_after_pump = {true},
        .pump_made_progress = {true},
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::timer_expired,
                    .now = base_time,
                },
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::shutdown,
                    .now = base_time + std::chrono::milliseconds(1),
                },
            },
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_deferred_output_waits_until_grace_deadline_case_for_tests() {
    const auto base_time = now();
    return ScriptedServerBackendSchedulingCaseForTests{
        .current_times =
            {
                base_time,
                base_time,
                base_time,
                base_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs),
                base_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs),
                base_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs),
            },
        .next_wakeup_results =
            {
                std::nullopt,
            },
        .pending_work_after_pump = {false},
        .pump_made_progress = {false},
        .wait_results =
            {
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::timer_expired,
                    .now = base_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs),
                },
                QuicIoEvent{
                    .kind = QuicIoEvent::Kind::shutdown,
                    .now = base_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs),
                },
            },
        .defer_output_until = base_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs),
    };
}

ScriptedServerBackendSchedulingCaseForTests
make_server_backend_scheduling_case_for_tests(ServerBackendSchedulingCaseForTests case_id) {
    switch (case_id) {
    case ServerBackendSchedulingCaseForTests::ready_datagram_preempts_repeated_due_timers:
        return make_ready_datagram_preempts_repeated_due_timers_case_for_tests();
    case ServerBackendSchedulingCaseForTests::ready_datagram_preempts_repeated_pending_work_pumps:
        return make_ready_datagram_preempts_repeated_pending_work_pumps_case_for_tests();
    case ServerBackendSchedulingCaseForTests::pending_work_yields_to_wait_after_immediate_poll_miss:
        return make_pending_work_yields_to_wait_after_immediate_poll_miss_case_for_tests();
    case ServerBackendSchedulingCaseForTests::
        elapsed_wakeup_after_immediate_poll_miss_yields_to_blocking_rx_wait:
        return make_elapsed_wakeup_after_immediate_poll_miss_yields_to_blocking_rx_wait_case_for_tests();
    case ServerBackendSchedulingCaseForTests::ready_probe_due_timer_failure:
        return make_ready_probe_due_timer_failure_case_for_tests();
    case ServerBackendSchedulingCaseForTests::ready_probe_idle_timeout_then_shutdown:
        return make_ready_probe_idle_timeout_then_shutdown_case_for_tests();
    case ServerBackendSchedulingCaseForTests::buffered_top_due_idle_timeout_skips_ready_probe:
        return make_buffered_top_due_idle_timeout_skips_ready_probe_case_for_tests();
    case ServerBackendSchedulingCaseForTests::ready_probe_rx_datagram_success_then_shutdown:
        return make_ready_probe_rx_datagram_success_then_shutdown_case_for_tests();
    case ServerBackendSchedulingCaseForTests::
        ready_probe_timer_without_wakeup_falls_back_to_main_wait:
        return make_ready_probe_timer_without_wakeup_falls_back_to_main_wait_case_for_tests();
    case ServerBackendSchedulingCaseForTests::deferred_output_waits_until_grace_deadline:
        return make_deferred_output_waits_until_grace_deadline_case_for_tests();
    }

    return make_ready_datagram_preempts_repeated_due_timers_case_for_tests();
}

std::vector<std::byte> bytes_from_string_for_runtime_tests(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const char ch : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return bytes;
}

std::vector<std::byte> make_unsupported_version_long_header_datagram_for_tests() {
    std::vector<std::byte> bytes(kMinimumClientInitialDatagramBytes, std::byte{0x00});
    bytes[0] = std::byte{0xc0};
    bytes[1] = std::byte{0xfa};
    bytes[2] = std::byte{0xce};
    bytes[3] = std::byte{0xb0};
    bytes[4] = std::byte{0x0c};
    bytes[5] = std::byte{0x01};
    bytes[6] = std::byte{0x80};
    bytes[7] = std::byte{0x01};
    bytes[8] = std::byte{0x81};
    return bytes;
}

struct ScopedRuntimeTempDirForTests {
    ScopedRuntimeTempDirForTests() {
        path_ = std::filesystem::temp_directory_path() /
                ("coquic-runtime-tests-" + std::to_string(::getpid()) + "-" +
                 std::to_string(counter_++));
        std::filesystem::create_directories(path_);
    }

    ~ScopedRuntimeTempDirForTests() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    void write_file(const std::filesystem::path &relative_path, std::string_view contents) const {
        const auto absolute_path = path_ / relative_path;
        std::filesystem::create_directories(absolute_path.parent_path());
        std::ofstream output(absolute_path, std::ios::binary);
        output << contents;
    }

    const std::filesystem::path &path() const {
        return path_;
    }

  private:
    inline static std::uint64_t counter_ = 0;
    std::filesystem::path path_;
};

QuicCoreResult single_receive_result_for_runtime_tests(std::uint64_t stream_id,
                                                       std::string_view text, bool fin) {
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreReceiveStreamData{
        .stream_id = stream_id,
        .bytes = bytes_from_string_for_runtime_tests(text),
        .fin = fin,
    });
    return result;
}

void append_result_for_runtime_tests(QuicCoreResult &combined, QuicCoreResult step) {
    combined.effects.insert(combined.effects.end(), std::make_move_iterator(step.effects.begin()),
                            std::make_move_iterator(step.effects.end()));
    combined.next_wakeup = step.next_wakeup;
    if (step.local_error.has_value()) {
        combined.local_error = step.local_error;
    }
}

bool result_has_send_datagrams_for_runtime_tests(const QuicCoreResult &result) {
    return std::any_of(result.effects.begin(), result.effects.end(), [](const auto &effect) {
        return std::holds_alternative<QuicCoreSendDatagram>(effect);
    });
}

QuicCoreResult relay_send_datagrams_to_endpoint_core_for_tests(const QuicCoreResult &result,
                                                               QuicCore &server,
                                                               QuicRouteHandle route_handle,
                                                               QuicCoreTimePoint now) {
    QuicCoreResult combined;
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        append_result_for_runtime_tests(combined, server.advance_endpoint(
                                                      QuicCoreInboundDatagram{
                                                          .bytes = send->bytes,
                                                          .route_handle = route_handle,
                                                          .ecn = send->ecn,
                                                      },
                                                      now));
        if (combined.local_error.has_value()) {
            break;
        }
    }
    return combined;
}

QuicCoreResult relay_send_datagrams_to_client_core_for_tests(const QuicCoreResult &result,
                                                             QuicCore &client,
                                                             QuicCoreTimePoint now) {
    QuicCoreResult combined;
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        append_result_for_runtime_tests(combined, client.advance(
                                                      QuicCoreInboundDatagram{
                                                          .bytes = send->bytes,
                                                          .route_handle = std::nullopt,
                                                          .ecn = send->ecn,
                                                      },
                                                      now));
        if (combined.local_error.has_value()) {
            break;
        }
    }
    return combined;
}

QuicCoreResult
relay_backend_sent_datagrams_to_client_core_for_tests(std::span<const QuicIoTxDatagram> datagrams,
                                                      QuicCore &client, QuicCoreTimePoint now) {
    QuicCoreResult combined;
    for (const auto &datagram : datagrams) {
        append_result_for_runtime_tests(combined, client.advance(
                                                      QuicCoreInboundDatagram{
                                                          .bytes = datagram.bytes,
                                                          .route_handle = std::nullopt,
                                                          .ecn = datagram.ecn,
                                                      },
                                                      now));
        if (combined.local_error.has_value()) {
            break;
        }
    }
    return combined;
}

std::optional<QuicConnectionHandle>
accepted_connection_handle_from_result_for_runtime_tests(const QuicCoreResult &result) {
    for (const auto connection : result_connection_handles(result)) {
        if (result_has_connection_lifecycle(result, connection,
                                            QuicCoreConnectionLifecycle::accepted)) {
            return connection;
        }
    }
    return std::nullopt;
}

std::optional<QuicConnectionHandle>
drive_live_server_endpoint_handshake_for_tests(QuicCore &client, QuicRouteHandle route_handle,
                                               QuicCore &server, QuicCoreTimePoint &step_now) {
    auto to_server = client.advance(QuicCoreStart{}, step_now);
    QuicCoreResult to_client;
    std::optional<QuicConnectionHandle> accepted_connection;

    for (int i = 0; i < 32; ++i) {
        if (accepted_connection.has_value() && client.is_handshake_complete() &&
            !result_has_send_datagrams_for_runtime_tests(to_server) &&
            !result_has_send_datagrams_for_runtime_tests(to_client)) {
            return accepted_connection;
        }

        if (result_has_send_datagrams_for_runtime_tests(to_server)) {
            step_now += std::chrono::milliseconds(1);
            to_client = relay_send_datagrams_to_endpoint_core_for_tests(to_server, server,
                                                                        route_handle, step_now);
            if (!accepted_connection.has_value()) {
                accepted_connection =
                    accepted_connection_handle_from_result_for_runtime_tests(to_client);
            }
            to_server.effects.clear();
            continue;
        }

        if (result_has_send_datagrams_for_runtime_tests(to_client)) {
            step_now += std::chrono::milliseconds(1);
            to_server = relay_send_datagrams_to_client_core_for_tests(to_client, client, step_now);
            to_client.effects.clear();
            continue;
        }

        std::optional<QuicCoreTimePoint> next;
        if (to_server.next_wakeup.has_value()) {
            next = to_server.next_wakeup;
        }
        if (to_client.next_wakeup.has_value()) {
            next = std::min(next.value_or(*to_client.next_wakeup), *to_client.next_wakeup);
        }
        if (!next.has_value()) {
            break;
        }

        if (to_server.next_wakeup.has_value() && *to_server.next_wakeup == *next) {
            to_server = client.advance(QuicCoreTimerExpired{}, *next);
            continue;
        }

        if (to_client.next_wakeup.has_value() && *to_client.next_wakeup == *next) {
            to_client = server.advance_endpoint(QuicCoreTimerExpired{}, *next);
            continue;
        }
    }

    if (!client.is_handshake_complete()) {
        return std::nullopt;
    }
    return accepted_connection;
}

QuicCore make_failed_server_core_for_tests() {
    auto core = make_failing_server_core_for_tests();
    static_cast<void>(core.advance(
        QuicCoreInboundDatagram{
            .bytes = {std::byte{0x00}},
        },
        now()));
    return core;
}

} // namespace

bool core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
    bool force_serialization_failure, bool force_path_id_mismatch = false);
bool core_retry_restart_preserves_inbound_path_ids_case_for_tests(
    bool force_integrity_failure, bool force_serialization_failure,
    bool force_path_id_mismatch = false);
bool runtime_backend_connectionmigration_request_flow_case_for_tests(
    bool official_alias, bool include_preferred_address,
    std::optional<QuicRouteHandle> preferred_route_result = QuicRouteHandle{41});
bool runtime_registers_all_server_core_connection_ids_case_for_tests(
    bool include_preferred_address);

} // namespace test

#if defined(__clang__)
#pragma clang attribute pop
#endif

} // namespace coquic::http09

#endif // COQUIC_HTTP09_RUNTIME_TEST_SUPPORT_H
