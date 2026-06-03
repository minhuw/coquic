#include "src/http09/http09_runtime_test_support.h"

#include <algorithm>
#include <cstring>
#include <string_view>

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace coquic::http09 {

namespace test {

bool runtime_trace_enabled_for_tests() {
    return runtime_trace_enabled();
}

std::string format_connection_id_hex_for_tests(std::span<const std::byte> connection_id) {
    return format_connection_id_hex(connection_id);
}

std::string format_connection_id_key_hex_for_tests(std::string_view connection_id_key) {
    return format_connection_id_key_hex(connection_id_key);
}

std::string connection_id_key_for_tests(std::span<const std::byte> connection_id) {
    return connection_id_key(connection_id);
}

sockaddr_storage runtime_test_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return peer;
}

QuicRouteHandle inbound_route_handle_or_zero(const RuntimeWaitStep &step) {
    if (!step.input.has_value()) {
        return 0;
    }
    const auto *inbound = std::get_if<QuicCoreInboundDatagram>(&*step.input);
    return inbound != nullptr ? inbound->route_handle.value_or(0) : 0;
}

int client_receive_timeout_ms_for_tests(const Http09RuntimeConfig &config) {
    return client_receive_timeout_ms(config);
}

QuicHttp09ClientConfig make_http09_client_endpoint_config_for_tests(
    const Http09RuntimeConfig &config, const std::vector<QuicHttp09Request> &requests,
    bool attempt_zero_rtt_requests, const QuicCoreResult &start_result) {
    return make_http09_client_endpoint_config(config, requests, attempt_zero_rtt_requests,
                                              start_result);
}

QuicCoreConfig
make_http09_server_core_config_with_identity_for_tests(const Http09RuntimeConfig &config,
                                                       TlsIdentity identity) {
    return make_http09_server_core_config_with_identity(config, std::move(identity));
}

QuicCoreEndpointConfig
make_runtime_server_endpoint_config_for_tests(const Http09RuntimeConfig &config,
                                              TlsIdentity identity) {
    return make_runtime_server_endpoint_config(config, std::move(identity));
}

int run_http09_client_connection_for_tests(const Http09RuntimeConfig &config,
                                           const std::vector<QuicHttp09Request> &requests,
                                           std::uint64_t connection_index) {
    return run_http09_client_connection(config, requests, connection_index);
}

std::optional<RuntimeWaitStepForTests>
wait_for_socket_or_deadline_for_tests(int socket_fd, int idle_timeout_ms,
                                      std::string_view role_name,
                                      const std::optional<QuicCoreTimePoint> &next_wakeup) {
    const auto step = wait_for_socket_or_deadline(
        RuntimeWaitConfig{
            .socket_fds = {socket_fd, -1},
            .socket_fd_count = 1,
            .idle_timeout_ms = idle_timeout_ms,
            .role_name = role_name,
        },
        next_wakeup);
    if (!step.has_value()) {
        return std::nullopt;
    }

    RuntimeWaitStepForTests result{
        .has_input = step->input.has_value(),
        .idle_timeout = step->idle_timeout,
        .has_source = step->has_source,
        .input_is_timer_expired =
            step->input.has_value() && std::holds_alternative<QuicCoreTimerExpired>(*step->input),
        .source_len = step->source_len,
    };
    if (step->input.has_value()) {
        if (const auto *inbound = std::get_if<QuicCoreInboundDatagram>(&*step->input);
            inbound != nullptr) {
            result.inbound_datagram_bytes = inbound->bytes.size();
        }
    }
    return result;
}

std::optional<QuicCoreTimePoint>
earliest_runtime_wakeup_for_tests(std::span<const std::optional<QuicCoreTimePoint>> wakeups) {
    return earliest_wakeup_in_range(
        wakeups, [](const std::optional<QuicCoreTimePoint> &wakeup) { return wakeup; });
}

DriveEndpointUntilBlockedResultForTests
drive_endpoint_until_blocked_case_for_tests(DriveEndpointUntilBlockedCaseForTests case_id) {
    ScriptedEndpointForTests endpoint;
    QuicCore core = make_failing_server_core_for_tests();
    EndpointDriveState state;
    QuicCoreResult initial_result;
    sockaddr_storage peer{};
    const sockaddr_storage *peer_ptr = &peer;

    using DriveEndpointCaseSetupFn =
        void (*)(ScriptedEndpointForTests &, QuicCore &, QuicCoreResult &);
    static const auto kDriveEndpointCaseSetups = std::to_array<DriveEndpointCaseSetupFn>({
        [](ScriptedEndpointForTests &, QuicCore &, QuicCoreResult &setup_result) {
            setup_result.effects.emplace_back(QuicCoreSendDatagram{
                .bytes = {std::byte{0x01}},
            });
        },
        [](ScriptedEndpointForTests &, QuicCore &, QuicCoreResult &setup_result) {
            setup_result.local_error = QuicCoreLocalError{
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, QuicCore &, QuicCoreResult &setup_result) {
            setup_result.local_error = QuicCoreLocalError{
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .handled_local_error = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, QuicCore &, QuicCoreResult &) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, QuicCore &, QuicCoreResult &) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, QuicCore &setup_core, QuicCoreResult &) {
            setup_core = make_local_error_client_core_for_tests();
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .core_inputs =
                    {
                        QuicCoreStopSending{
                            .stream_id = 2,
                            .application_error_code = 7,
                        },
                    },
            });
        },
    });
    kDriveEndpointCaseSetups[static_cast<std::size_t>(case_id)](endpoint, core, initial_result);

    return DriveEndpointUntilBlockedResultForTests{
        .returned = drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core,
                                                 /*fd=*/-1, peer_ptr,
                                                 /*peer_len=*/0, initial_result, state, "client"),
        .terminal_success = state.terminal_success,
        .terminal_failure = state.terminal_failure,
        .endpoint_has_pending_work = state.endpoint_has_pending_work,
    };
}

ClientConnectionLoopResultForTests
run_client_connection_loop_case_for_tests(ClientConnectionLoopCaseForTests case_id) {
    ScriptedEndpointForTests endpoint;
    ScriptedClientLoopIoForTests io_script;
    QuicCore core = make_local_error_client_core_for_tests();
    EndpointDriveState state;
    QuicCoreResult start_result;
    sockaddr_storage peer{};
    const auto base_time = now();

    using ClientLoopCaseSetupFn =
        void (*)(ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &, QuicCore &,
                 QuicCoreResult &, QuicCoreTimePoint);
    static const auto kClientLoopCaseSetups = std::to_array<ClientLoopCaseSetupFn>({
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time;
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(std::nullopt);
            setup_io.now_values = {setup_base_time, setup_base_time};
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time;
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.now_values = {setup_base_time};
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time + std::chrono::milliseconds(1);
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.now_values = {
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(2),
                setup_base_time + std::chrono::milliseconds(3),
                setup_base_time + std::chrono::milliseconds(4),
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time + std::chrono::milliseconds(1);
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.now_values = {
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(2),
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_io.receive_results.push_back(make_error_receive_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.receive_results.push_back(
                make_input_receive_for_tests(QuicCoreTimerExpired{}));
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &, QuicCore &, QuicCoreResult &,
           QuicCoreTimePoint) {},
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreTimerExpired{}));
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreInboundDatagram{
                .bytes = {std::byte{0x01}},
            }));
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreInboundDatagram{
                .bytes = {std::byte{0x02}},
            }));
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreTimerExpired{}));
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_io.wait_steps.push_back(RuntimeWaitStep{
                .input_time = now(),
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreTimerExpired{}));
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint setup_base_time) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(ReceiveDatagramResult{
                .status = ReceiveDatagramStatus::ok,
                .step =
                    RuntimeWaitStep{
                        .input =
                            QuicCoreInboundDatagram{
                                .bytes = {std::byte{0x01}},
                            },
                        .input_time = setup_base_time + std::chrono::milliseconds(1),
                    },
            });
            setup_io.now_values = {
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(2),
                setup_base_time + std::chrono::milliseconds(3),
                setup_base_time + std::chrono::milliseconds(4),
                setup_base_time + std::chrono::milliseconds(5),
                setup_base_time + std::chrono::milliseconds(6),
            };
            setup_io.wait_steps.push_back(RuntimeWaitStep{
                .input_time = setup_base_time + std::chrono::milliseconds(7),
                .idle_timeout = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint setup_base_time) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(ReceiveDatagramResult{
                .status = ReceiveDatagramStatus::ok,
                .step =
                    RuntimeWaitStep{
                        .input =
                            QuicCoreInboundDatagram{
                                .bytes = {std::byte{0x01}},
                            },
                        .input_time = setup_base_time + std::chrono::milliseconds(1),
                    },
            });
            setup_io.now_values = {
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(kClientSuccessDrainWindowMs + 2),
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .core_inputs =
                    {
                        QuicCoreTimerExpired{},
                    },
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .core_inputs =
                    {
                        QuicCoreTimerExpired{},
                    },
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time + std::chrono::milliseconds(5);
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
            setup_io.now_values = {
                setup_base_time,
                setup_base_time,
                setup_base_time,
            };
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time + std::chrono::milliseconds(1);
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
            setup_io.now_values = {
                setup_base_time,
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(3),
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &setup_core, QuicCoreResult &setup_start_result,
           QuicCoreTimePoint setup_base_time) {
            setup_core = make_local_error_client_core_for_tests();
            setup_start_result = setup_core.advance(QuicCoreStart{}, setup_base_time);
            const auto timer_due = setup_start_result.next_wakeup.value_or(setup_base_time);
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(std::nullopt);
            setup_io.now_values = {
                timer_due,
                timer_due,
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_io.receive_results.push_back(make_input_receive_for_tests(QuicCoreInboundDatagram{
                .bytes = {std::byte{0x01}},
            }));
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .core_inputs =
                    {
                        QuicCoreTimerExpired{},
                    },
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
        },
    });
    kClientLoopCaseSetups[static_cast<std::size_t>(case_id)](endpoint, io_script, core,
                                                             start_result, base_time);
    if (case_id ==
        ClientConnectionLoopCaseForTests::pending_work_terminal_failure_state_after_pump) {
        state.terminal_failure = true;
    }

    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
    };
    ClientRuntimePolicyState client_policy;
    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = 17,
                .family = AF_UNSPEC,
            },
    };
    g_recorded_sendto_for_tests = {};
    return ScopedHttp09RuntimeOpsOverride{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    }
        .while_active([&] {
            auto io = make_scripted_client_loop_io_for_tests(io_script);
            std::unique_ptr<FailureInjectingClientLoopIoForTests> failure_injecting_io;
            if (case_id ==
                ClientConnectionLoopCaseForTests::nonblocking_receive_terminal_failure_state) {
                failure_injecting_io = std::make_unique<FailureInjectingClientLoopIoForTests>(
                    FailureInjectingClientLoopIoForTests{
                        .script = &io_script,
                        .state = &state,
                    });
                io = ClientLoopIo{
                    .context = failure_injecting_io.get(),
                    .now_fn = &failure_injecting_client_loop_now_for_tests,
                    .receive_datagram_fn = &failure_injecting_client_loop_receive_for_tests,
                    .wait_for_socket_or_deadline_fn = &failure_injecting_client_loop_wait_for_tests,
                };
            }
            const int exit_code = run_http09_client_connection_loop(
                config, make_endpoint_driver(endpoint), core, client_sockets,
                /*idle_timeout_ms=*/kDefaultClientReceiveTimeoutMs, peer, /*peer_len=*/0, state,
                client_policy, io, start_result);
            return ClientConnectionLoopResultForTests{
                .exit_code = exit_code,
                .terminal_success = state.terminal_success,
                .terminal_failure = state.terminal_failure,
                .endpoint_has_pending_work = state.endpoint_has_pending_work,
                .receive_calls = io_script.next_receive_index,
                .wait_calls = io_script.next_wait_index,
                .current_time_calls = io_script.next_now_index,
            };
        });
}

ClientConnectionLoopResultForTests
run_client_connection_backend_loop_case_for_tests(ClientConnectionBackendLoopCaseForTests case_id) {
    ScriptedEndpointForTests endpoint;
    auto backend = std::make_unique<ScriptedIoBackendForTests>();
    auto *backend_ptr = backend.get();
    QuicCore core = make_local_error_client_core_for_tests();
    EndpointDriveState state;
    ClientRuntimePolicyState client_policy;
    ClientIoContext io_context{
        .backend = std::move(backend),
        .primary_route_handle = QuicRouteHandle{17},
    };
    QuicCoreResult start_result;
    const auto event_time = now();
    endpoint.state = &state;

    switch (case_id) {
    case ClientConnectionBackendLoopCaseForTests::initial_terminal_success:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::wait_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        break;
    case ClientConnectionBackendLoopCaseForTests::idle_timeout:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::idle_timeout,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::shutdown:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::missing_rx_datagram:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::timer_event_then_wait_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::timer_due_before_wait_then_wait_failure:
        start_result.next_wakeup = event_time;
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        break;
    case ClientConnectionBackendLoopCaseForTests::timer_due_before_wait_then_drive_failure:
        start_result.next_wakeup = event_time;
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_failure = true,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::timer_event_then_drive_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_failure = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::timer_event_then_terminal_success:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::missing_path_mtu_update:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::path_mtu_update,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::path_mtu_update_then_wait_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::path_mtu_update,
            .now = event_time,
            .path_mtu =
                QuicIoPathMtuUpdate{
                    .route_handle = QuicRouteHandle{17},
                    .max_udp_payload_size = 1400,
                },
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::path_mtu_update_then_drive_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_failure = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::path_mtu_update,
            .now = event_time,
            .path_mtu =
                QuicIoPathMtuUpdate{
                    .route_handle = QuicRouteHandle{17},
                    .max_udp_payload_size = 1400,
                },
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::rx_datagram_then_drive_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_failure = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = event_time,
            .datagram =
                QuicIoRxDatagram{
                    .route_handle = QuicRouteHandle{17},
                    .bytes = {std::byte{0x01}},
                },
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::
        rx_datagram_then_terminal_success_after_elapsed_drain_window:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = event_time - std::chrono::milliseconds(kClientSuccessDrainWindowMs + 1),
            .datagram =
                QuicIoRxDatagram{
                    .route_handle = QuicRouteHandle{17},
                    .bytes = {std::byte{0x01}},
                },
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::
        rx_datagram_then_terminal_success_with_followup_input:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = event_time,
            .datagram =
                QuicIoRxDatagram{
                    .route_handle = QuicRouteHandle{17},
                    .bytes = {std::byte{0x01}},
                },
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = event_time + std::chrono::milliseconds(1),
            .datagram =
                QuicIoRxDatagram{
                    .route_handle = QuicRouteHandle{17},
                    .bytes = {std::byte{0x02}},
                },
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::idle_timeout,
            .now = event_time + std::chrono::milliseconds(2),
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::pending_work_terminal_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_failure = true,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::pending_work_default_poll_then_wait_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::pending_work_no_inputs_then_idle_timeout:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::idle_timeout,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::outer_pump_terminal_failure:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_failure = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::outer_pump_terminal_success:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = event_time,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::peer_input_then_outer_pump_terminal_success:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = event_time,
            .datagram =
                QuicIoRxDatagram{
                    .route_handle = QuicRouteHandle{17},
                    .bytes = {std::byte{0x01}},
                },
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::idle_timeout,
            .now = event_time + std::chrono::milliseconds(1),
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::pending_work_core_inputs_are_drained_before_wait:
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .core_inputs =
                {
                    QuicCoreTimerExpired{},
                },
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::pending_work_followup_timer_drive_failure:
        start_result.next_wakeup = event_time + std::chrono::seconds(60);
        endpoint.next_wakeup_overrides = {
            std::nullopt,
            event_time,
        };
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_failure = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .core_inputs =
                {
                    QuicCoreTimerExpired{},
                },
            .has_pending_work = true,
        });
        break;
    case ClientConnectionBackendLoopCaseForTests::
        pending_work_followup_timer_continue_then_terminal_success:
        start_result.next_wakeup = event_time + std::chrono::seconds(60);
        endpoint.next_wakeup_overrides = {
            std::nullopt,
            event_time,
        };
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .core_inputs =
                {
                    QuicCoreTimerExpired{},
                },
            .has_pending_work = true,
        });
        endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
            .terminal_success = true,
        });
        break;
    }

    const int exit_code = run_http09_client_connection_backend_loop(
        Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        },
        make_endpoint_driver(endpoint), core, io_context, state, client_policy, start_result);
    return ClientConnectionLoopResultForTests{
        .exit_code = exit_code,
        .terminal_success = state.terminal_success,
        .terminal_failure = state.terminal_failure,
        .endpoint_has_pending_work = state.endpoint_has_pending_work,
        .wait_calls = backend_ptr->wait_requests.size(),
    };
}

void record_erased_server_session_key_for_tests(std::string *erased_key,
                                                const std::string &local_connection_id_key) {
    *erased_key = local_connection_id_key;
}

bool existing_server_session_failure_cleans_up_for_tests() {
    auto session = std::make_unique<ServerSession>(ServerSession{
        .core = make_failed_server_core_for_tests(),
        .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = std::filesystem::temp_directory_path(),
        }),
        .state = EndpointDriveState{},
        .peer = {},
        .peer_len = 0,
        .local_connection_id_key = "existing-session",
        .initial_destination_connection_id_key = "initial-route",
    });

    std::string erased_key;
    RuntimeWaitStep step{
        .input = QuicCoreTimerExpired{},
        .input_time = now(),
        .has_source = true,
    };
    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .destination_connection_id = {std::byte{0x83}},
    };
    ServerConnectionIdRouteMap connection_id_routes;
    process_existing_server_session_datagram(
        *session, step, connection_id_routes, parsed,
        std::bind_front(&record_erased_server_session_key_for_tests, &erased_key));
    return !erased_key.empty();
}

bool existing_server_session_missing_input_fails_for_tests() {
    auto session = std::make_unique<ServerSession>(ServerSession{
        .core = make_failed_server_core_for_tests(),
        .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = std::filesystem::temp_directory_path(),
        }),
        .state = EndpointDriveState{},
        .peer = {},
        .peer_len = 0,
        .local_connection_id_key = "existing-session",
        .initial_destination_connection_id_key = "initial-route",
    });

    std::string erased_key;
    RuntimeWaitStep step{
        .input_time = now(),
        .has_source = true,
    };
    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .destination_connection_id = {std::byte{0x83}},
    };
    ServerConnectionIdRouteMap connection_id_routes;
    return !process_existing_server_session_datagram(
               *session, step, connection_id_routes, parsed,
               std::bind_front(&record_erased_server_session_key_for_tests, &erased_key)) &&
           erased_key.empty();
}

bool preferred_address_routes_to_existing_server_session_for_tests() {
    const ConnectionId preferred_connection_id = make_runtime_connection_id(std::byte{0x5a}, 1);
    const auto preferred_connection_id_key = connection_id_key(preferred_connection_id);

    ServerSessionMap sessions;
    sessions.emplace("existing-session",
                     std::make_unique<ServerSession>(ServerSession{
                         .core = make_failed_server_core_for_tests(),
                         .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                             .document_root = std::filesystem::temp_directory_path(),
                         }),
                         .state = EndpointDriveState{},
                         .peer = {},
                         .peer_len = 0,
                         .local_connection_id_key = "existing-session",
                         .initial_destination_connection_id_key = "unused-initial",
                     }));

    std::unordered_map<std::string, std::string> initial_destination_routes;
    ServerConnectionIdRouteMap connection_id_routes;
    connection_id_routes.emplace(preferred_connection_id_key, "existing-session");

    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::short_header,
        .destination_connection_id = preferred_connection_id,
    };

    return find_server_session_for_datagram(sessions, connection_id_routes,
                                            initial_destination_routes, parsed) != sessions.end();
}

bool runtime_backend_connectionmigration_request_flow_case_for_tests(
    bool official_alias, bool include_preferred_address,
    std::optional<QuicRouteHandle> preferred_route_result) {
    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
        .testcase =
            official_alias ? QuicHttp09Testcase::transfer : QuicHttp09Testcase::connectionmigration,
        .requests_env = official_alias ? "https://server46:443/file.bin" : "",
    };

    auto backend = std::make_unique<ScriptedIoBackendForTests>();
    auto *backend_ptr = backend.get();
    if (include_preferred_address) {
        backend_ptr->ensure_route_results.push_back(preferred_route_result);
    }

    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    ClientIoContext io_context{
        .backend = std::move(backend),
        .primary_route_handle = QuicRouteHandle{17},
    };
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_ready,
    });
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_confirmed,
    });
    if (include_preferred_address) {
        result.effects.emplace_back(make_ipv4_preferred_address_effect_for_tests());
    }

    if (!observe_client_runtime_policy_effects_with_backend(result, state, policy, io_context,
                                                            "client")) {
        return false;
    }

    std::vector<QuicCoreInput> core_inputs;
    maybe_queue_client_runtime_policy_inputs(config, policy, core_inputs);

    if (backend_ptr->ensure_route_calls.size() != 1 || core_inputs.size() != 1 ||
        !policy.preferred_address_route_handle.has_value() ||
        !io_context.preferred_route_handle.has_value()) {
        return false;
    }

    const auto route_handle = policy.preferred_address_route_handle.value_or(QuicRouteHandle{});
    const auto &request = std::get<QuicCoreRequestConnectionMigration>(core_inputs.front());
    const auto &remote = backend_ptr->ensure_route_calls.front();
    return policy.handshake_ready_seen && policy.handshake_confirmed_seen &&
           policy.preferred_address_request_queued &&
           (route_handle == preferred_route_result.value_or(QuicRouteHandle{})) &&
           (io_context.preferred_route_handle.value_or(0) ==
            preferred_route_result.value_or(QuicRouteHandle{})) &&
           (request.route_handle == preferred_route_result.value_or(QuicRouteHandle{})) &&
           (request.reason == QuicMigrationRequestReason::preferred_address) &&
           (remote.family == AF_INET) && (peer_port_for_remote_for_tests(remote) == 4444);
}

bool runtime_backend_connectionmigration_request_flow_for_tests() {
    return runtime_backend_connectionmigration_request_flow_case_for_tests(
        /*official_alias=*/false, /*include_preferred_address=*/true);
}

bool runtime_backend_official_connectionmigration_client_request_flow_for_tests() {
    return runtime_backend_connectionmigration_request_flow_case_for_tests(
        /*official_alias=*/true, /*include_preferred_address=*/true);
}

bool runtime_backend_cross_family_preferred_address_requests_backend_route_for_tests() {
    auto backend = std::make_unique<ScriptedIoBackendForTests>();
    auto *backend_ptr = backend.get();
    backend_ptr->ensure_route_results.push_back(QuicRouteHandle{23});

    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    ClientIoContext io_context{
        .backend = std::move(backend),
        .primary_route_handle = QuicRouteHandle{17},
    };
    QuicCoreResult result;
    result.effects.emplace_back(make_ipv6_preferred_address_effect_for_tests());

    if (!observe_client_runtime_policy_effects_with_backend(result, state, policy, io_context,
                                                            "client")) {
        return false;
    }
    if (backend_ptr->ensure_route_calls.size() != 1 ||
        !policy.preferred_address_route_handle.has_value() ||
        !io_context.preferred_route_handle.has_value()) {
        return false;
    }

    const auto &remote = backend_ptr->ensure_route_calls.front();
    return (policy.preferred_address_route_handle.value_or(0) == QuicRouteHandle{23}) &&
           (io_context.preferred_route_handle.value_or(0) == QuicRouteHandle{23}) &&
           (remote.family == AF_INET6) && (peer_port_for_remote_for_tests(remote) == 4444);
}

bool runtime_client_loop_requests_preferred_address_route_from_backend_for_tests() {
    ScriptedEndpointForTests endpoint;
    endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});

    auto backend = std::make_unique<ScriptedIoBackendForTests>();
    auto *backend_ptr = backend.get();
    backend_ptr->ensure_route_results.push_back(QuicRouteHandle{59});

    QuicCore core = make_local_error_client_core_for_tests();
    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    ClientIoContext io_context{
        .backend = std::move(backend),
        .primary_route_handle = QuicRouteHandle{17},
    };
    QuicCoreResult start_result;
    start_result.effects.emplace_back(make_ipv6_preferred_address_effect_for_tests());

    const int exit_code = run_http09_client_connection_backend_loop(
        Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::connectionmigration,
        },
        make_endpoint_driver(endpoint), core, io_context, state, policy, start_result);

    return exit_code == 1 && backend_ptr->ensure_route_calls.size() == 1 &&
           backend_ptr->wait_requests.size() == 1 &&
           (peer_port_for_remote_for_tests(backend_ptr->ensure_route_calls.front()) == 4444) &&
           (policy.preferred_address_route_handle.value_or(0) == QuicRouteHandle{59}) &&
           (io_context.preferred_route_handle.value_or(0) == QuicRouteHandle{59});
}

bool runtime_backend_preferred_address_route_failure_stops_migration_request_for_tests() {
    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
        .testcase = QuicHttp09Testcase::connectionmigration,
    };

    auto backend = std::make_unique<ScriptedIoBackendForTests>();
    auto *backend_ptr = backend.get();
    backend_ptr->ensure_route_results.push_back(std::nullopt);

    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    ClientIoContext io_context{
        .backend = std::move(backend),
        .primary_route_handle = QuicRouteHandle{17},
    };
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_ready,
    });
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_confirmed,
    });
    result.effects.emplace_back(make_ipv4_preferred_address_effect_for_tests());

    std::vector<QuicCoreInput> core_inputs;
    const bool preferred_route_rejected = !observe_client_runtime_policy_effects_with_backend(
        result, state, policy, io_context, "client");
    maybe_queue_client_runtime_policy_inputs(config, policy, core_inputs);

    return preferred_route_rejected && backend_ptr->ensure_route_calls.size() == 1 &&
           policy.handshake_ready_seen && policy.handshake_confirmed_seen &&
           !policy.preferred_address_route_handle.has_value() &&
           !io_context.preferred_route_handle.has_value() &&
           !policy.preferred_address_request_queued && core_inputs.empty();
}

bool runtime_backend_regular_transfer_does_not_queue_preferred_address_migration_for_tests() {
    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
        .testcase = QuicHttp09Testcase::transfer,
        .requests_env = "https://localhost:443/file.bin",
    };

    auto backend = std::make_unique<ScriptedIoBackendForTests>();
    auto *backend_ptr = backend.get();
    backend_ptr->ensure_route_results.push_back(QuicRouteHandle{43});

    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    ClientIoContext io_context{
        .backend = std::move(backend),
        .primary_route_handle = QuicRouteHandle{17},
    };
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_ready,
    });
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_confirmed,
    });
    result.effects.emplace_back(make_ipv4_preferred_address_effect_for_tests());

    if (!observe_client_runtime_policy_effects_with_backend(result, state, policy, io_context,
                                                            "client")) {
        return false;
    }

    std::vector<QuicCoreInput> core_inputs;
    maybe_queue_client_runtime_policy_inputs(config, policy, core_inputs);

    return backend_ptr->ensure_route_calls.size() == 1 && policy.handshake_ready_seen &&
           policy.handshake_confirmed_seen &&
           (policy.preferred_address_route_handle.value_or(0) == QuicRouteHandle{43}) &&
           (io_context.preferred_route_handle.value_or(0) == QuicRouteHandle{43}) &&
           !policy.preferred_address_request_queued && core_inputs.empty();
}

bool expired_server_timer_failure_cleans_up_for_tests() {
    const auto run_case = [](std::string_view local_connection_id_key, QuicCore core,
                             QuicHttp09ServerEndpoint endpoint) {
        ServerSessionMap sessions;
        sessions.emplace(std::string(local_connection_id_key),
                         std::make_unique<ServerSession>(ServerSession{
                             .core = std::move(core),
                             .endpoint = std::move(endpoint),
                             .state =
                                 EndpointDriveState{
                                     .next_wakeup = now(),
                                 },
                             .peer = {},
                             .peer_len = 0,
                             .local_connection_id_key = std::string(local_connection_id_key),
                             .initial_destination_connection_id_key = "expired-route",
                         }));
        bool processed_any = false;
        const auto erase_session =
            std::bind_front(erase_server_session_from_map, std::ref(sessions));
        ServerConnectionIdRouteMap connection_id_routes;
        process_expired_server_sessions(sessions, now(), connection_id_routes, erase_session,
                                        processed_any);
        return processed_any && sessions.empty();
    };
    const auto make_endpoint = [] {
        return QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = std::filesystem::temp_directory_path(),
        });
    };

    auto failed_endpoint = make_endpoint();
    return run_case("expired-core-failure", make_failed_server_core_for_tests(), make_endpoint()) &&
           failed_endpoint
               .on_core_result(single_receive_result_for_runtime_tests(0, "", true), now())
               .terminal_failure &&
           run_case("expired-endpoint-failure", make_failing_server_core_for_tests(),
                    std::move(failed_endpoint));
}

bool expired_server_timer_success_preserves_session_for_tests() {
    ServerSessionMap sessions;
    sessions.emplace("expired-session",
                     std::make_unique<ServerSession>(ServerSession{
                         .core = QuicCore(make_http09_server_core_config(Http09RuntimeConfig{
                             .mode = Http09RuntimeMode::server,
                         })),
                         .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                             .document_root = std::filesystem::temp_directory_path(),
                         }),
                         .state =
                             EndpointDriveState{
                                 .next_wakeup = now(),
                             },
                         .peer = {},
                         .peer_len = 0,
                         .local_connection_id_key = "expired-session",
                         .initial_destination_connection_id_key = "expired-route",
                     }));
    bool processed_any = false;
    const auto erase_session = std::bind_front(erase_server_session_from_map, std::ref(sessions));
    ServerConnectionIdRouteMap connection_id_routes;
    process_expired_server_sessions(sessions, now(), connection_id_routes, erase_session,
                                    processed_any);
    return processed_any && (sessions.size() == 1);
}

bool pending_server_work_failure_cleans_up_for_tests() {
    ScopedRuntimeTempDirForTests document_root;
    document_root.write_file("large.bin", std::string(static_cast<std::size_t>(64) * 1024U, 'x'));

    const auto run_case = [&](std::string_view local_connection_id_key, QuicCore core,
                              bool fail_endpoint) {
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        const bool pending_work_available =
            endpoint
                .on_core_result(
                    single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now())
                .has_pending_work;
        if (fail_endpoint &&
            !endpoint.on_core_result(single_receive_result_for_runtime_tests(4, "", true), now())
                 .terminal_failure) {
            return false;
        }
        ServerSessionMap sessions;
        sessions.emplace(std::string(local_connection_id_key),
                         std::make_unique<ServerSession>(ServerSession{
                             .core = std::move(core),
                             .endpoint = std::move(endpoint),
                             .state =
                                 EndpointDriveState{
                                     .endpoint_has_pending_work = pending_work_available,
                                 },
                             .peer = {},
                             .peer_len = 0,
                             .local_connection_id_key = std::string(local_connection_id_key),
                             .initial_destination_connection_id_key = "pending-route",
                         }));
        ServerConnectionIdRouteMap connection_id_routes;
        pump_server_pending_endpoint_work(
            sessions, connection_id_routes,
            [&](const std::string &erased_key) { sessions.erase(erased_key); });
        return pending_work_available && sessions.empty();
    };

    return run_case("pending-core-failure", make_failed_server_core_for_tests(),
                    /*fail_endpoint=*/false) &&
           run_case("pending-endpoint-failure", make_failing_server_core_for_tests(),
                    /*fail_endpoint=*/true);
}

bool pending_server_work_success_preserves_session_for_tests() {
    ScopedRuntimeTempDirForTests document_root;
    document_root.write_file("large.bin", std::string(static_cast<std::size_t>(64) * 1024U, 'x'));

    QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
        .document_root = document_root.path(),
    });
    const auto update = endpoint.on_core_result(
        single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());

    ServerSessionMap sessions;
    sessions.emplace("pending-success",
                     std::make_unique<ServerSession>(ServerSession{
                         .core = make_failing_server_core_for_tests(),
                         .endpoint = std::move(endpoint),
                         .state =
                             EndpointDriveState{
                                 .endpoint_has_pending_work = update.has_pending_work,
                             },
                         .peer = {},
                         .peer_len = 0,
                         .local_connection_id_key = "pending-success",
                         .initial_destination_connection_id_key = "pending-route",
                     }));
    ServerConnectionIdRouteMap connection_id_routes;
    pump_server_pending_endpoint_work(sessions, connection_id_routes,
                                      [&](const std::string &local_connection_id_key) {
                                          sessions.erase(local_connection_id_key);
                                      });
    return update.has_pending_work && !sessions.empty() &&
           !sessions.begin()->second->core.has_failed() &&
           !sessions.begin()->second->state.terminal_failure;
}

bool resumed_client_warmup_failure_exits_early_for_tests() {
    const auto requests = parse_http09_requests_env("https://localhost/warmup.txt").value();
    Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
        .testcase = QuicHttp09Testcase::zerortt,
        .download_root = "downloads",
    };

    int calls = 0;
    const int exit_code = run_http09_resumed_client_sequence(
        config, requests,
        [&](const Http09RuntimeConfig &, const std::vector<QuicHttp09Request> &runner_requests,
            const QuicCoreConfig &core_config, std::uint64_t connection_index) {
            ++calls;
            const bool warmup_matches = (calls == 1) && (connection_index == 1) &&
                                        (runner_requests.size() == 1) &&
                                        (core_config.zero_rtt.application_context ==
                                         http09_zero_rtt_application_context(runner_requests));
            return ClientConnectionRunResult{
                .exit_code = 98 - (static_cast<int>(warmup_matches) * 91),
            };
        });
    return (exit_code == 7) && (calls == 1);
}

bool zero_rtt_request_allowance_for_tests() {
    const auto make_result = [](std::optional<QuicZeroRttStatus> status) {
        QuicCoreResult result;
        if (status.has_value()) {
            result.effects.emplace_back(QuicCoreZeroRttStatusEvent{.status = *status});
        }
        return result;
    };

    const bool unavailable_rejected =
        !allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::unavailable));
    const bool not_attempted_rejected =
        !allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::not_attempted));
    const bool rejected_rejected =
        !allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::rejected));
    const bool attempted_allowed =
        allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::attempted));
    const bool accepted_allowed =
        allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::accepted));
    const bool missing_status_allowed =
        allow_requests_before_handshake_ready(true, make_result(std::nullopt));
    const bool disabled_rejected =
        !allow_requests_before_handshake_ready(false, make_result(QuicZeroRttStatus::accepted));
    return unavailable_rejected && not_attempted_rejected && rejected_rejected &&
           attempted_allowed && accepted_allowed && missing_status_allowed && disabled_rejected;
}

bool runtime_assigns_stable_path_ids_for_tests() {
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    EndpointDriveState state;
    RuntimeWaitStep first{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x01}}},
        .input_time = now(),
        .socket_fd = 4,
        .source = runtime_test_loopback_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };
    RuntimeWaitStep second{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x02}}},
        .input_time = now(),
        .socket_fd = 4,
        .source = runtime_test_loopback_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };
    RuntimeWaitStep third{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x03}}},
        .input_time = now(),
        .socket_fd = 7,
        .source = runtime_test_loopback_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };

    if (!assign_runtime_path_for_inbound_step(state, first).has_value() ||
        !assign_runtime_path_for_inbound_step(state, second).has_value() ||
        !assign_runtime_path_for_inbound_step(state, third).has_value()) {
        return false;
    }
    return state.path_routes.size() == 2 && state.path_routes.contains(1) &&
           state.path_routes.contains(2) && state.path_routes.at(1).socket_fd == 4 &&
           state.path_routes.at(2).socket_fd == 7;
}

bool runtime_server_route_handles_are_stable_per_peer_tuple_for_tests() {
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    EndpointDriveState state;
    RuntimeWaitStep first{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x01}}},
        .input_time = now(),
        .socket_fd = 4,
        .source = runtime_test_loopback_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };
    RuntimeWaitStep second{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x02}}},
        .input_time = now(),
        .socket_fd = 4,
        .source = runtime_test_loopback_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };
    RuntimeWaitStep third{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x03}}},
        .input_time = now(),
        .socket_fd = 7,
        .source = runtime_test_loopback_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };

    if (!assign_runtime_path_for_inbound_step(state, first).has_value() ||
        !assign_runtime_path_for_inbound_step(state, second).has_value() ||
        !assign_runtime_path_for_inbound_step(state, third).has_value()) {
        return false;
    }

    return inbound_route_handle_or_zero(first) != 0 &&
           inbound_route_handle_or_zero(first) == inbound_route_handle_or_zero(second) &&
           inbound_route_handle_or_zero(first) != inbound_route_handle_or_zero(third) &&
           state.route_routes.at(inbound_route_handle_or_zero(first)).socket_fd == 4 &&
           state.route_routes.at(inbound_route_handle_or_zero(third)).socket_fd == 7;
}

bool runtime_configures_linux_ecn_socket_options_for_tests() {
    g_recorded_setsockopt_for_tests = {};
    return ScopedHttp09RuntimeOpsOverride{
        Http09RuntimeOpsOverride{
            .socket_fn = [](int, int, int) { return 41; },
            .setsockopt_fn = &record_setsockopt_for_tests,
        },
    }
        .while_active([&] {
            const int fd = open_udp_socket(AF_INET6);
            const bool opened = fd == 41;
            const auto has_call = [](int level, int name, int value) {
                return std::ranges::any_of(g_recorded_setsockopt_for_tests.calls,
                                           [&](const RecordedSetSockOptForTests::Call &call) {
                                               return call.level == level && call.name == name &&
                                                      call.value == value;
                                           });
            };
            return opened && has_call(IPPROTO_IPV6, IPV6_V6ONLY, 0) &&
                   has_call(IPPROTO_IP, IP_RECVTOS, 1) &&
                   has_call(IPPROTO_IPV6, IPV6_RECVTCLASS, 1);
        });
}

bool runtime_sendmsg_uses_outbound_ecn_for_tests() {
    g_recorded_sendmsg_for_tests = {};
    return ScopedHttp09RuntimeOpsOverride{
        Http09RuntimeOpsOverride{
            .sendmsg_fn = &record_sendmsg_for_tests,
        },
    }
        .while_active([&] {
            const std::array<std::byte, 1> datagram = {
                std::byte{0x01},
            };

            sockaddr_storage peer{};
            auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
            ipv4.sin_family = AF_INET;
            ipv4.sin_port = htons(4433);
            ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

            return send_datagram(/*fd=*/17, datagram, peer,
                                 static_cast<socklen_t>(sizeof(sockaddr_in)), "client",
                                 QuicEcnCodepoint::ect1) &&
                   (g_recorded_sendmsg_for_tests.calls == 1) &&
                   (g_recorded_sendmsg_for_tests.socket_fd == 17) &&
                   (g_recorded_sendmsg_for_tests.level == IPPROTO_IP) &&
                   (g_recorded_sendmsg_for_tests.type == IP_TOS) &&
                   (g_recorded_sendmsg_for_tests.traffic_class == 0x01);
        });
}

bool runtime_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests() {
    g_recorded_sendmsg_for_tests = {};
    return ScopedHttp09RuntimeOpsOverride{
        Http09RuntimeOpsOverride{
            .sendmsg_fn = &record_sendmsg_for_tests,
        },
    }
        .while_active([&] {
            const std::array<std::byte, 1> datagram = {
                std::byte{0x01},
            };

            sockaddr_storage peer{};
            auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
            ipv6.sin6_family = AF_INET6;
            ipv6.sin6_port = htons(4433);
            ipv6.sin6_addr.s6_addr[10] = 0xff;
            ipv6.sin6_addr.s6_addr[11] = 0xff;
            ipv6.sin6_addr.s6_addr[12] = 127;
            ipv6.sin6_addr.s6_addr[15] = 1;

            return send_datagram(/*fd=*/23, datagram, peer,
                                 static_cast<socklen_t>(sizeof(sockaddr_in6)), "server",
                                 QuicEcnCodepoint::ect1) &&
                   (g_recorded_sendmsg_for_tests.calls == 1) &&
                   (g_recorded_sendmsg_for_tests.socket_fd == 23) &&
                   (g_recorded_sendmsg_for_tests.level == IPPROTO_IP) &&
                   (g_recorded_sendmsg_for_tests.type == IP_TOS) &&
                   (g_recorded_sendmsg_for_tests.traffic_class == 0x01);
        });
}

bool runtime_recvmsg_maps_ecn_to_core_input_for_tests() {
    g_recorded_recvmsg_for_tests = {};
    g_recorded_recvmsg_for_tests.ecn = QuicEcnCodepoint::ce;
    g_recorded_recvmsg_for_tests.bytes = {std::byte{0xaa}, std::byte{0xbb}};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&g_recorded_recvmsg_for_tests.peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(6121);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);

    return ScopedHttp09RuntimeOpsOverride{
        Http09RuntimeOpsOverride{
            .recvmsg_fn = &record_recvmsg_for_tests,
        },
    }
        .while_active([&] {
            const auto received = receive_datagram(/*socket_fd=*/29, "client", /*flags=*/0);
            if (received.status != ReceiveDatagramStatus::ok || !received.step.input.has_value()) {
                return false;
            }

            const auto *inbound = std::get_if<QuicCoreInboundDatagram>(&*received.step.input);
            return inbound != nullptr && inbound->bytes == g_recorded_recvmsg_for_tests.bytes &&
                   inbound->ecn == QuicEcnCodepoint::ce;
        });
}

bool drive_endpoint_uses_transport_selected_path_for_tests() {
    g_recorded_sendto_for_tests = {};
    return ScopedHttp09RuntimeOpsOverride{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    }
        .while_active([&] {
            const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
            const auto selected_route_handle = static_cast<QuicRouteHandle>(9);
            const int fallback_socket_fd = 31;
            const int selected_socket_fd = 77;
            const auto fallback_peer = runtime_test_loopback_peer(8443);

            EndpointDriveState state;
            state.route_routes[selected_route_handle] = RuntimeSendRoute{
                .socket_fd = selected_socket_fd,
                .peer = runtime_test_loopback_peer(9443),
                .peer_len = peer_len,
            };

            QuicCoreResult result;
            result.effects.emplace_back(QuicCoreSendDatagram{
                .route_handle = selected_route_handle,
                .bytes = {std::byte{0xaa}},
            });

            ScriptedEndpointForTests endpoint;
            QuicCore core = make_local_error_client_core_for_tests();
            return drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core,
                                                fallback_socket_fd, &fallback_peer, peer_len,
                                                result, state, "client") &&
                   (g_recorded_sendto_for_tests.calls == 1) &&
                   (g_recorded_sendto_for_tests.socket_fd == selected_socket_fd) &&
                   (g_recorded_sendto_for_tests.peer_port == 9443);
        });
}

bool runtime_server_send_effect_uses_route_handle_for_tests() {
    g_recorded_sendto_for_tests = {};
    return ScopedHttp09RuntimeOpsOverride{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    }
        .while_active([&] {
            const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
            const int fallback_socket_fd = 31;
            const int route_socket_fd = 77;
            const auto fallback_peer = runtime_test_loopback_peer(8443);

            QuicCoreResult result;
            result.effects.emplace_back(QuicCoreSendDatagram{
                .route_handle = 5,
                .bytes = {std::byte{0xaa}},
            });

            EndpointDriveState state;
            state.route_routes.emplace(5, RuntimeSendRoute{
                                              .socket_fd = route_socket_fd,
                                              .peer = runtime_test_loopback_peer(10443),
                                              .peer_len = peer_len,
                                          });

            return handle_core_effects(fallback_socket_fd, result, &fallback_peer, peer_len,
                                       state.route_routes, "server") &&
                   (g_recorded_sendto_for_tests.calls == 1) &&
                   (g_recorded_sendto_for_tests.socket_fd == route_socket_fd) &&
                   (g_recorded_sendto_for_tests.peer_port == 10443);
        });
}

bool runtime_policy_core_inputs_advance_before_terminal_success_for_tests() {
    ScriptedEndpointForTests endpoint;
    endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
        .terminal_success = true,
    });
    endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});

    QuicCore core = make_local_error_client_core_for_tests();
    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    QuicCoreResult initial_result;
    initial_result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_ready,
    });
    initial_result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_confirmed,
    });
    initial_result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
        .preferred_address =
            PreferredAddress{
                .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
                .ipv4_port = 4444,
                .connection_id = make_runtime_connection_id(std::byte{0x5a}, 1),
            },
    });

    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = 17,
                .family = AF_INET,
            },
    };
    sockaddr_storage peer{};
    return [&] {
        const Http09RuntimeConfig config{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::connectionmigration,
        };
        return drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core, /*fd=*/17, &peer,
                                            /*peer_len=*/0, initial_result, state, "client",
                                            &config, &policy, &client_sockets);
    }() && state.terminal_success &&
           policy.preferred_address_request_queued && (endpoint.next_on_core_result_index == 2);
}

bool server_connectionmigration_preferred_address_config_for_tests() {
    const auto inspect_preferred_address = [](const Http09RuntimeConfig &config) {
        const auto core = make_http09_server_core_config(config);
        const bool has_preferred_address = core.transport.preferred_address.has_value();
        const auto preferred_port =
            has_preferred_address ? core.transport.preferred_address->ipv4_port : 0;
        const auto preferred_connection_id = has_preferred_address
                                                 ? core.transport.preferred_address->connection_id
                                                 : ConnectionId{};
        return std::tuple{has_preferred_address, preferred_port, preferred_connection_id};
    };

    const auto [has_preferred_address, preferred_port, preferred_connection_id] =
        inspect_preferred_address(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
        });
    const auto [transfer_has_preferred_address, transfer_preferred_port,
                transfer_preferred_connection_id] = inspect_preferred_address(Http09RuntimeConfig{
        .mode = Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .testcase = QuicHttp09Testcase::transfer,
    });
    return has_preferred_address && (preferred_port == 444) &&
           (preferred_connection_id == make_runtime_connection_id(std::byte{0x5a}, 1)) &&
           !transfer_has_preferred_address && (transfer_preferred_port == 0) &&
           transfer_preferred_connection_id.empty();
}

bool runtime_registers_all_server_core_connection_ids_case_for_tests(
    bool include_preferred_address) {
    auto core_config = make_http09_server_core_config(Http09RuntimeConfig{
        .mode = Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .testcase = include_preferred_address ? QuicHttp09Testcase::connectionmigration
                                              : QuicHttp09Testcase::transfer,
    });
    if (!core_config.transport.preferred_address.has_value()) {
        return false;
    }

    const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
    const auto preferred_connection_id_key =
        connection_id_key(core_config.transport.preferred_address->connection_id);

    ServerConnectionIdRouteMap connection_id_routes;
    ServerSession session{
        .core = QuicCore(std::move(core_config)),
        .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = std::filesystem::temp_directory_path(),
        }),
        .state = EndpointDriveState{},
        .socket_fd = -1,
        .peer = {},
        .peer_len = 0,
        .local_connection_id_key = local_connection_id_key,
        .initial_destination_connection_id_key = "unused-initial",
    };

    refresh_server_session_connection_id_routes(session, connection_id_routes);

    if (preferred_connection_id_key.empty() ||
        !connection_id_routes.contains(preferred_connection_id_key)) {
        return false;
    }
    return (connection_id_routes.at(preferred_connection_id_key) == local_connection_id_key) &&
           (session.alternate_connection_id_keys.size() == 1) &&
           (session.alternate_connection_id_keys.front() == preferred_connection_id_key);
}

bool runtime_registers_all_server_core_connection_ids_for_tests() {
    return runtime_registers_all_server_core_connection_ids_case_for_tests(
        /*include_preferred_address=*/true);
}

bool runtime_misc_internal_coverage_check(bool &ok, std::string_view label, bool condition) {
    if (!condition) {
        std::cerr << "runtime_misc_internal_coverage_for_tests failed: " << label << '\n';
        ok = false;
    }
    return condition;
}

bool runtime_misc_internal_coverage_for_tests() {
    struct ScopedEnvVar {
        std::string name;
        std::optional<std::string> previous;

        ScopedEnvVar(std::string variable, std::optional<std::string> value)
            : name(std::move(variable)) {
            if (const char *existing = std::getenv(name.c_str()); existing != nullptr) {
                previous = std::string(existing);
            }
            if (value.has_value()) {
                ::setenv(name.c_str(), value->c_str(), 1);
            } else {
                ::unsetenv(name.c_str());
            }
        }

        ~ScopedEnvVar() {
            if (previous.has_value()) {
                ::setenv(name.c_str(), previous->c_str(), 1);
            } else {
                ::unsetenv(name.c_str());
            }
        }
    };

    bool runtime_misc_coverage_ok = true;

    {
        static_cast<void>(::setenv("COQUIC_RUNTIME_MISC_RESTORE", "seed", 1));
        {
            ScopedEnvVar unset_existing("COQUIC_RUNTIME_MISC_RESTORE", std::nullopt);
            runtime_misc_internal_coverage_check(
                runtime_misc_coverage_ok, "scoped env clears existing variable",
                std::getenv("COQUIC_RUNTIME_MISC_RESTORE") == nullptr);
        }
        runtime_misc_internal_coverage_check(
            runtime_misc_coverage_ok, "scoped env restores previous variable",
            getenv_string("COQUIC_RUNTIME_MISC_RESTORE").value_or("") == "seed");
        static_cast<void>(::unsetenv("COQUIC_RUNTIME_MISC_RESTORE"));
    }

    static_cast<void>(runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                                           "expected diagnostic path", false));
    runtime_misc_coverage_ok = true;

    sockaddr_storage invalid_address{};
    invalid_address.ss_family = AF_UNSPEC;
    runtime_misc_internal_coverage_check(runtime_misc_coverage_ok, "format trace empty length",
                                         format_sockaddr_for_trace(invalid_address, 0) == "-");
    runtime_misc_internal_coverage_check(
        runtime_misc_coverage_ok, "format trace invalid family",
        format_sockaddr_for_trace(invalid_address, sizeof(invalid_address)) == "-");

    runtime_misc_internal_coverage_check(runtime_misc_coverage_ok, "empty host unspecified",
                                         host_is_unspecified(""));
    runtime_misc_internal_coverage_check(runtime_misc_coverage_ok, "named host not unspecified",
                                         !host_is_unspecified("interop-server-host"));

    {
        ScopedEnvVar empty_hostname("HOSTNAME", std::string{});
        const auto gethostname_fn = [](char *buffer, size_t length) -> int {
            if (length == 0) {
                errno = EINVAL;
                return -1;
            }
            constexpr std::string_view runtime_host = "runtime-host";
            const auto copy_length = std::min(length - 1, runtime_host.size());
            std::memcpy(buffer, runtime_host.data(), copy_length);
            buffer[copy_length] = '\0';
            return 0;
        };
        char dummy = '\0';
        runtime_misc_internal_coverage_check(
            runtime_misc_coverage_ok, "zero-length gethostname fails",
            (gethostname_fn(&dummy, 0) == -1) && (errno == EINVAL));
        ScopedHttp09RuntimeOpsOverride{
            Http09RuntimeOpsOverride{
                .gethostname_fn = gethostname_fn,
            },
        }
            .while_active([&] {
                runtime_misc_internal_coverage_check(
                    runtime_misc_coverage_ok, "hostname fallback succeeds",
                    preferred_address_host_for_server("").value_or("") == "runtime-host");
            });
    }

    {
        ScopedEnvVar unset_hostname("HOSTNAME", std::nullopt);
        const auto gethostname_fn = [](char *buffer, size_t length) -> int {
            if (length == 0) {
                errno = EINVAL;
                return -1;
            }
            buffer[0] = '\0';
            return 0;
        };
        char dummy = '\0';
        runtime_misc_internal_coverage_check(
            runtime_misc_coverage_ok, "empty hostname zero-length gethostname fails",
            (gethostname_fn(&dummy, 0) == -1) && (errno == EINVAL));
        ScopedHttp09RuntimeOpsOverride{
            Http09RuntimeOpsOverride{
                .gethostname_fn = gethostname_fn,
            },
        }
            .while_active([&] {
                runtime_misc_internal_coverage_check(
                    runtime_misc_coverage_ok, "hostname fallback empty string returns nullopt",
                    !preferred_address_host_for_server("").has_value());
            });
    }

    {
        ScopedEnvVar empty_hostname("HOSTNAME", std::string{});
        ScopedHttp09RuntimeOpsOverride{
            Http09RuntimeOpsOverride{
                .gethostname_fn = [](char *, size_t) -> int {
                    errno = EIO;
                    return -1;
                },
            },
        }
            .while_active([&] {
                runtime_misc_internal_coverage_check(
                    runtime_misc_coverage_ok, "hostname fallback failure returns nullopt",
                    !preferred_address_host_for_server("").has_value());
                runtime_misc_internal_coverage_check(
                    runtime_misc_coverage_ok, "preferred address lookup failure returns nullopt",
                    !runtime_preferred_address_for_server(
                         Http09RuntimeConfig{
                             .mode = Http09RuntimeMode::server,
                             .host = "",
                             .port = 443,
                             .testcase = QuicHttp09Testcase::connectionmigration,
                         })
                         .has_value());
            });
    }

    runtime_misc_internal_coverage_check(
        runtime_misc_coverage_ok, "invalid host preferred address fails",
        !runtime_preferred_address_for_server(
             Http09RuntimeConfig{
                 .mode = Http09RuntimeMode::server,
                 .host = "invalid host",
                 .port = 443,
                 .testcase = QuicHttp09Testcase::connectionmigration,
             })
             .has_value());

    PreferredAddress ipv6_preferred_address{
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
                std::byte{0x09},
            },
        .ipv6_port = 4444,
        .connection_id = make_runtime_connection_id(std::byte{0x5a}, 7),
    };
    auto preferred_ipv6_sockaddr = sockaddr_from_preferred_address(ipv6_preferred_address);
    const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(&preferred_ipv6_sockaddr);
    runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                         "preferred address sockaddr family",
                                         ipv6->sin6_family == AF_INET6);
    runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                         "preferred address sockaddr port",
                                         ntohs(ipv6->sin6_port) == 4444);

    ResolvedUdpAddress ipv4_resolved{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&ipv4_resolved.address);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4443);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ipv4_resolved.address_len = sizeof(sockaddr_in);
    ipv4_resolved.family = AF_INET;
    auto resolved_ipv4_preferred_address =
        preferred_address_from_resolved_udp_address(ipv4_resolved, {});
    runtime_misc_internal_coverage_check(runtime_misc_coverage_ok, "preferred address ipv4 port",
                                         resolved_ipv4_preferred_address.ipv4_port == 4443);
    runtime_misc_internal_coverage_check(
        runtime_misc_coverage_ok, "preferred address empty cid still mints reset token",
        std::ranges::any_of(resolved_ipv4_preferred_address.stateless_reset_token,
                            [](std::byte value) { return value != std::byte{0x00}; }));
    ResolvedUdpAddress unknown_family_resolved{};
    unknown_family_resolved.family = AF_UNSPEC;
    auto resolved_unknown_family_preferred_address =
        preferred_address_from_resolved_udp_address(unknown_family_resolved, {});
    runtime_misc_internal_coverage_check(
        runtime_misc_coverage_ok, "preferred address unknown family leaves ports empty",
        (resolved_unknown_family_preferred_address.ipv4_port == 0) &&
            (resolved_unknown_family_preferred_address.ipv6_port == 0));

    runtime_misc_internal_coverage_check(runtime_misc_coverage_ok, "wait without sockets fails",
                                         !wait_for_socket_or_deadline(
                                              RuntimeWaitConfig{
                                                  .socket_fds = {-1, -1},
                                                  .socket_fd_count = 0,
                                                  .idle_timeout_ms = 1,
                                                  .role_name = "client",
                                              },
                                              std::nullopt)
                                              .has_value());

    {
        ScopedHttp09RuntimeOpsOverride{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *, nfds_t, int) -> int { return 1; },
            },
        }
            .while_active([&] {
                runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                                     "wait unreadable socket fails",
                                                     !wait_for_socket_or_deadline(
                                                          RuntimeWaitConfig{
                                                              .socket_fds = {-1, -1},
                                                              .socket_fd_count = 1,
                                                              .idle_timeout_ms = 1,
                                                              .role_name = "client",
                                                          },
                                                          std::nullopt)
                                                          .has_value());
            });
    }

    {
        EndpointDriveState state;
        RuntimeWaitStep step{
            .input = QuicCoreTimerExpired{},
            .input_time = now(),
            .socket_fd = 7,
            .source = preferred_ipv6_sockaddr,
            .source_len = sizeof(sockaddr_in6),
            .has_source = true,
        };
        runtime_misc_internal_coverage_check(
            runtime_misc_coverage_ok, "timer step does not assign path",
            !assign_runtime_path_for_inbound_step(state, step).has_value());
    }

    runtime_misc_internal_coverage_check(
        runtime_misc_coverage_ok, "invalid requests env does not trigger migration",
        !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::transfer,
            .requests_env = "not-a-valid-request",
        }));
    runtime_misc_internal_coverage_check(
        runtime_misc_coverage_ok, "server transfer request never triggers migration",
        !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .testcase = QuicHttp09Testcase::transfer,
            .requests_env = "https://server46:443/file.bin",
        }));
    runtime_misc_internal_coverage_check(
        runtime_misc_coverage_ok, "non-server46 transfer request does not trigger migration",
        !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::transfer,
            .requests_env = "https://example.com:443/file.bin",
        }));

    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        const auto run_traced_input = [&](QuicCoreInput input) {
            QuicCore trace_core = make_local_error_client_core_for_tests();
            const std::array<QuicCoreInput, 1> inputs = {
                std::move(input),
            };
            static_cast<void>(advance_core_with_inputs(trace_core, inputs, now()));
        };
        run_traced_input(QuicCoreStart{});
        run_traced_input(QuicCoreInboundDatagram{
            .bytes = bytes_from_string_for_runtime_tests("input"),
            .route_handle = 4,
        });
        run_traced_input(QuicCoreResetStream{.stream_id = 0, .application_error_code = 1});
        run_traced_input(QuicCoreStopSending{.stream_id = 0, .application_error_code = 2});
        run_traced_input(QuicCoreRequestKeyUpdate{});
        run_traced_input(QuicCoreRequestConnectionMigration{
            .route_handle = 9,
            .reason = QuicMigrationRequestReason::preferred_address,
        });
        run_traced_input(QuicCoreRequestConnectionMigration{
            .route_handle = 10,
            .reason = QuicMigrationRequestReason::active,
        });
        run_traced_input(QuicCoreTimerExpired{});

        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientSocketSet client_sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 17,
                    .family = AF_INET,
                },
        };
        QuicCoreResult result;
        result.effects.emplace_back(QuicCoreStateEvent{
            .change = QuicCoreStateChange::handshake_ready,
        });
        result.effects.emplace_back(QuicCoreStateEvent{
            .change = QuicCoreStateChange::handshake_confirmed,
        });
        result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
            .preferred_address = ipv6_preferred_address,
        });
        ScopedHttp09RuntimeOpsOverride{
            Http09RuntimeOpsOverride{
                .socket_fn = [](int family, int, int) -> int {
                    if (family != AF_INET6) {
                        errno = EAFNOSUPPORT;
                        return -1;
                    }
                    return 23;
                },
                .setsockopt_fn = [](int, int, int, const void *, socklen_t) -> int { return 0; },
            },
        }
            .while_active([&] {
                runtime_misc_internal_coverage_check(
                    runtime_misc_coverage_ok, "policy observes cross-family preferred address",
                    observe_client_runtime_policy_effects(result, state, policy, client_sockets,
                                                          "client"));
                std::vector<QuicCoreInput> core_inputs;
                maybe_queue_client_runtime_policy_inputs(
                    Http09RuntimeConfig{
                        .mode = Http09RuntimeMode::client,
                        .testcase = QuicHttp09Testcase::connectionmigration,
                    },
                    policy, core_inputs);
                runtime_misc_internal_coverage_check(
                    runtime_misc_coverage_ok, "policy records preferred address route",
                    policy.preferred_address_route_handle.has_value());
                runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                                     "policy queues one migration input",
                                                     core_inputs.size() == 1);

                runtime_misc_internal_coverage_check(
                    runtime_misc_coverage_ok, "client timer trace samples time",
                    run_client_connection_loop_case_for_tests(
                        ClientConnectionLoopCaseForTests::outer_timer_then_wait_failure)
                            .current_time_calls > 0);
                runtime_misc_internal_coverage_check(
                    runtime_misc_coverage_ok, "client timer trace records send-count path",
                    run_client_connection_loop_case_for_tests(
                        ClientConnectionLoopCaseForTests::
                            timer_due_emits_send_trace_with_future_wakeup)
                            .current_time_calls > 0);
            });
    }

    {
        g_recorded_sendto_for_tests = {};
        sockaddr_in short_ipv4{};
        short_ipv4.sin_family = AF_INET;
        short_ipv4.sin_port = htons(4445);
        static_cast<void>(record_sendto_for_tests(
            /*socket_fd=*/31, nullptr, /*length=*/5, /*flags=*/0,
            reinterpret_cast<const sockaddr *>(&short_ipv4),
            static_cast<socklen_t>(sizeof(sockaddr_in) - 1)));
        sockaddr_in6 short_ipv6{};
        short_ipv6.sin6_family = AF_INET6;
        short_ipv6.sin6_port = htons(4446);
        static_cast<void>(record_sendto_for_tests(
            /*socket_fd=*/32, nullptr, /*length=*/7, /*flags=*/0,
            reinterpret_cast<const sockaddr *>(&short_ipv6),
            static_cast<socklen_t>(sizeof(sockaddr_in6) - 1)));
        runtime_misc_internal_coverage_check(
            runtime_misc_coverage_ok, "short sendto destinations keep peer port zero",
            g_recorded_sendto_for_tests.peer_ports == std::vector<std::uint16_t>{0, 0});
    }

    {
        auto core_config = make_http09_server_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
        });
        const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
        ServerConnectionIdRouteMap connection_id_routes{
            {"stale-route", local_connection_id_key},
        };
        ServerSession session{
            .core = QuicCore(std::move(core_config)),
            .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                .document_root = std::filesystem::temp_directory_path(),
            }),
            .state = EndpointDriveState{},
            .socket_fd = -1,
            .peer = {},
            .peer_len = 0,
            .local_connection_id_key = local_connection_id_key,
            .initial_destination_connection_id_key = "initial-route",
            .alternate_connection_id_keys = {"stale-route"},
        };
        refresh_server_session_connection_id_routes(session, connection_id_routes);
        runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                             "refresh removes stale route",
                                             !connection_id_routes.contains("stale-route"));
    }

    {
        auto core_config = make_http09_server_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
        });
        const auto preferred_address =
            core_config.transport.preferred_address.value_or(PreferredAddress{});
        runtime_misc_internal_coverage_check(
            runtime_misc_coverage_ok, "connectionmigration config provides a preferred address",
            core_config.transport.preferred_address.has_value());
        const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
        const auto preferred_connection_id_key = connection_id_key(preferred_address.connection_id);
        ServerConnectionIdRouteMap connection_id_routes{
            {preferred_connection_id_key, local_connection_id_key},
        };
        ServerSession session{
            .core = QuicCore(std::move(core_config)),
            .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                .document_root = std::filesystem::temp_directory_path(),
            }),
            .state = EndpointDriveState{},
            .socket_fd = -1,
            .peer = {},
            .peer_len = 0,
            .local_connection_id_key = local_connection_id_key,
            .initial_destination_connection_id_key = "initial-route",
            .alternate_connection_id_keys = {preferred_connection_id_key},
        };
        refresh_server_session_connection_id_routes(session, connection_id_routes);
        runtime_misc_internal_coverage_check(
            runtime_misc_coverage_ok, "refresh preserves live alternate routes",
            connection_id_routes.contains(preferred_connection_id_key) &&
                (session.alternate_connection_id_keys.size() == 1) &&
                (session.alternate_connection_id_keys.front() == preferred_connection_id_key));
    }

    {
        auto core_config = make_http09_server_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
        });
        const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
        ServerSessionMap sessions;
        ServerConnectionIdRouteMap connection_id_routes{
            {"alternate-route", local_connection_id_key},
        };
        std::unordered_map<std::string, std::string> initial_destination_routes{
            {"initial-route", local_connection_id_key},
        };
        sessions.emplace(local_connection_id_key,
                         std::make_unique<ServerSession>(ServerSession{
                             .core = QuicCore(std::move(core_config)),
                             .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                 .document_root = std::filesystem::temp_directory_path(),
                             }),
                             .state = EndpointDriveState{},
                             .socket_fd = -1,
                             .peer = {},
                             .peer_len = 0,
                             .local_connection_id_key = local_connection_id_key,
                             .initial_destination_connection_id_key = "initial-route",
                             .alternate_connection_id_keys = {"alternate-route"},
                         }));
        erase_server_session_with_routes(sessions, connection_id_routes, initial_destination_routes,
                                         local_connection_id_key);
        runtime_misc_internal_coverage_check(runtime_misc_coverage_ok, "erase removes session",
                                             !sessions.contains(local_connection_id_key));
        runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                             "erase removes alternate route",
                                             !connection_id_routes.contains("alternate-route"));
        runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                             "erase removes initial route",
                                             !initial_destination_routes.contains("initial-route"));
    }

    {
        const auto server_config = Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "invalid host",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        };
        runtime_misc_internal_coverage_check(runtime_misc_coverage_ok, "invalid host server fails",
                                             run_http09_server(server_config) == 1);
    }

    {
        ScopedHttp09RuntimeOpsOverride{
            Http09RuntimeOpsOverride{
                .socket_fn = [](int, int, int) -> int {
                    static thread_local int next_fd = 760;
                    return next_fd++;
                },
                .bind_fn = [](int, const sockaddr *, socklen_t) -> int { return 0; },
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .getaddrinfo_fn = [](const char *node, const char *service, const addrinfo *hints,
                                     addrinfo **results) -> int {
                    static thread_local int call_count = 0;
                    ++call_count;
                    if (call_count == 2) {
                        return EAI_FAIL;
                    }
                    return ::getaddrinfo(node, service, hints, results);
                },
                .freeaddrinfo_fn = ::freeaddrinfo,
            },
        }
            .while_active([&] {
                const auto server_config = Http09RuntimeConfig{
                    .mode = Http09RuntimeMode::server,
                    .host = "127.0.0.1",
                    .port = 443,
                    .testcase = QuicHttp09Testcase::connectionmigration,
                    .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
                    .private_key_path = "tests/fixtures/quic-server-key.pem",
                };
                runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                                     "preferred bind resolve failure aborts server",
                                                     run_http09_server(server_config) == 1);
            });
    }

    {
        ScopedHttp09RuntimeOpsOverride{
            Http09RuntimeOpsOverride{
                .socket_fn = [](int, int, int) -> int {
                    static thread_local int next_fd = 700;
                    return next_fd++;
                },
                .bind_fn = [](int, const sockaddr *, socklen_t) -> int {
                    static thread_local int bind_calls = 0;
                    ++bind_calls;
                    if (bind_calls == 2) {
                        errno = EADDRINUSE;
                        return -1;
                    }
                    return 0;
                },
            },
        }
            .while_active([&] {
                const auto server_config = Http09RuntimeConfig{
                    .mode = Http09RuntimeMode::server,
                    .host = "127.0.0.1",
                    .port = 443,
                    .testcase = QuicHttp09Testcase::connectionmigration,
                    .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
                    .private_key_path = "tests/fixtures/quic-server-key.pem",
                };
                runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                                     "second bind failure aborts server",
                                                     run_http09_server(server_config) == 1);
            });
    }

    {
        auto duplicate_seed_peer = preferred_ipv6_sockaddr;
        QuicCore core = make_failed_server_core_for_tests();
        const std::array seeded_paths{
            RuntimePathSeedForTests{
                .socket_fd = 11,
                .peer = duplicate_seed_peer,
                .peer_len = sizeof(sockaddr_in6),
            },
            RuntimePathSeedForTests{
                .socket_fd = 11,
                .peer = duplicate_seed_peer,
                .peer_len = sizeof(sockaddr_in6),
            },
        };
        const auto duplicate_result = route_existing_server_session_datagram_for_tests(
            core, seeded_paths, bytes_from_string_for_runtime_tests("local"),
            bytes_from_string_for_runtime_tests("odcid"),
            /*inbound_socket_fd=*/11, duplicate_seed_peer, sizeof(sockaddr_in6),
            bytes_from_string_for_runtime_tests("payload"), now());
        runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                             "duplicate seeded route is rejected",
                                             !duplicate_result.processed);
    }

    {
        QuicCore core = make_failed_server_core_for_tests();
        const auto unparsable_result = route_existing_server_session_datagram_for_tests(
            core, std::span<const RuntimePathSeedForTests>{},
            bytes_from_string_for_runtime_tests("local"),
            bytes_from_string_for_runtime_tests("odcid"), /*inbound_socket_fd=*/11,
            preferred_ipv6_sockaddr, sizeof(sockaddr_in6), std::vector<std::byte>{std::byte{0x00}},
            now());
        runtime_misc_internal_coverage_check(runtime_misc_coverage_ok,
                                             "unparsable datagram is rejected",
                                             !unparsable_result.processed);
    }

    return runtime_misc_coverage_ok;
}

bool runtime_additional_internal_coverage_for_tests() {
    bool ok = true;

    runtime_misc_internal_coverage_check(
        ok, "empty transfer requests do not trigger migration",
        !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::transfer,
            .requests_env = "",
        }));
    runtime_misc_internal_coverage_check(
        ok, "non-server46 transfer request still does not trigger migration",
        !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::transfer,
            .requests_env = "https://example.com:443/file.bin",
        }));

    g_recorded_sendto_for_tests = {};
    static_cast<void>(record_sendto_for_tests(
        /*socket_fd=*/33, nullptr, /*length=*/0, /*flags=*/0, /*destination=*/nullptr,
        /*destination_len=*/0));
    runtime_misc_internal_coverage_check(ok, "null sendto destination keeps peer port zero",
                                         g_recorded_sendto_for_tests.peer_ports ==
                                             std::vector<std::uint16_t>{0});

    return ok;
}

} // namespace test

#if defined(__clang__)
#pragma clang attribute pop
#endif

} // namespace coquic::http09
