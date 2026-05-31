#include "src/http09/http09_runtime_test_support.h"

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace coquic::http09 {

namespace test {

void reset_runtime_logging_state_for_tests() {
    runtime_logging_ready_flag() = false;
}

bool runtime_logging_ready_for_tests() {
    return runtime_logging_ready_flag();
}

bool runtime_openssl_available_for_tests() {
    return runtime_has_openssl();
}

bool runtime_server_loop_and_trace_coverage_for_tests() {
    bool ok = true;
    struct RuntimeServerLoopCheck {
        bool &ok;
        bool operator()(std::string_view, bool condition) const {
            ok &= condition;
            return condition;
        }
    } check{ok};
    const auto make_loopback_peer = [](std::uint16_t port) {
        sockaddr_storage loopback_peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&loopback_peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return loopback_peer;
    };
    const auto make_identity = [] {
        return TlsIdentity{
            .certificate_pem = read_text_file("tests/fixtures/quic-server-cert.pem"),
            .private_key_pem = read_text_file("tests/fixtures/quic-server-key.pem"),
        };
    };
    struct BackendLoopScriptForTests {
        std::vector<QuicCoreTimePoint> current_times;
        std::vector<std::optional<QuicCoreTimePoint>> next_wakeup_results;
        std::vector<std::optional<QuicIoEvent>> wait_results;
        std::vector<bool> pump_return_results;
        std::vector<bool> pending_work_after_pump;
        std::vector<bool> pump_made_progress;
        std::vector<bool> process_wait_timer_results;
        bool process_datagram_result = true;
        bool process_path_mtu_result = true;
    };

    const auto peer = make_loopback_peer(4443);
    const ParsedServerDatagram supported_initial{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = make_runtime_connection_id(std::byte{0x51}, 1),
        .source_connection_id = make_runtime_connection_id(std::byte{0x61}, 2),
        .token = {},
    };

    ::setenv("COQUIC_RUNTIME_TRACE", "1", 1);

    {
        g_recorded_sendto_for_tests = {};
        RetryTokenStore retry_tokens;
        std::uint64_t next_connection_index = 9;
        const ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
            },
        };
        const auto retry_result = maybe_send_retry_for_supported_initial(
            /*retry_enabled=*/true, /*socket_fd=*/17, supported_initial, peer, sizeof(sockaddr_in),
            retry_tokens, next_connection_index);
        check("retry helper traces and sends tokenless initials",
              retry_result.has_value() & retry_result.value_or(false) &
                  g_recorded_sendto_for_tests.calls == 1 & next_connection_index == 10);
    }

    {
        std::optional<PendingRetryToken> retry_context;
        RetryTokenStore retry_tokens;
        ParsedServerDatagram invalid_retry = supported_initial;
        invalid_retry.token = make_runtime_retry_token(0x0102030405060708ull);
        invalid_retry.destination_connection_id = make_runtime_connection_id(std::byte{0x72}, 4);
        check("invalid retry tokens hit the traced rejection path",
              !populate_retry_context_if_required(/*retry_enabled=*/true, invalid_retry, peer,
                                                  sizeof(sockaddr_in), retry_tokens,
                                                  retry_context) &
                  !retry_context.has_value());
    }

    {
        RetryTokenStore retry_tokens;
        ParsedServerDatagram invalid_retry_version = supported_initial;
        invalid_retry_version.version = kVersionNegotiationVersion;
        check("retry send covers retry integrity-tag failures",
              !send_retry_for_initial(/*fd=*/18, invalid_retry_version, peer, sizeof(sockaddr_in),
                                      retry_tokens,
                                      /*connection_index=*/1));
    }

    {
        const auto run_traced_input = [&](QuicCoreInput input) {
            QuicCore core = make_local_error_client_core_for_tests();
            const std::array<QuicCoreInput, 1> inputs = {
                std::move(input),
            };
            static_cast<void>(advance_core_with_inputs(core, inputs, now()));
        };
        run_traced_input(QuicCoreStart{});
        run_traced_input(QuicCoreInboundDatagram{
            .bytes = bytes_from_string_for_runtime_tests("trace"),
        });
        run_traced_input(QuicCoreResetStream{.stream_id = 1, .application_error_code = 7});
        run_traced_input(QuicCoreStopSending{.stream_id = 2, .application_error_code = 8});
        run_traced_input(
            QuicCoreCloseConnection{.application_error_code = 12, .reason_phrase = "trace"});
        run_traced_input(QuicCoreSendSharedStreamData{
            .stream_id = 3,
            .bytes = quic::SharedBytes{std::byte{0x04}},
            .fin = true,
        });
        run_traced_input(QuicCoreRequestKeyUpdate{});
        run_traced_input(QuicCorePathMtuUpdate{
            .route_handle = 11,
            .max_udp_payload_size = 1400,
        });

        QuicCore sending_core(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        const std::array<QuicCoreInput, 1> sending_inputs = {
            QuicCoreStart{},
        };
        static_cast<void>(advance_core_with_inputs(sending_core, sending_inputs, now()));

        auto server_initial = serialize_packet(InitialPacket{
            .version = kQuicVersion1,
            .destination_connection_id = make_runtime_connection_id(std::byte{0x83}, 7),
            .source_connection_id = make_runtime_connection_id(std::byte{0xc1}, 8),
            .packet_number_length = 1,
            .truncated_packet_number = 1,
            .frames = {PaddingFrame{}},
        });
        check("trace coverage can serialize a public server Initial", server_initial.has_value());
        auto initial_bytes = server_initial.value();
        initial_bytes.resize(1200, std::byte{0x00});
        QuicCore accepting_core(make_http09_server_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
        }));
        const std::array<QuicCoreInput, 1> accepting_inputs = {
            QuicCoreInboundDatagram{
                .bytes = std::move(initial_bytes),
                .route_handle = QuicRouteHandle{42},
            },
        };
        static_cast<void>(advance_core_with_inputs(accepting_core, accepting_inputs, now()));
    }

    {
        check("connection command translation covers remaining supported commands",
              to_connection_command_input(QuicCoreSendStreamData{
                                              .stream_id = 3,
                                              .bytes = bytes_from_string_for_runtime_tests("body"),
                                              .fin = true,
                                          })
                      .has_value() &
                  to_connection_command_input(QuicCoreResetStream{
                                                  .stream_id = 4,
                                                  .application_error_code = 9,
                                              })
                      .has_value() &
                  to_connection_command_input(QuicCoreStopSending{
                                                  .stream_id = 5,
                                                  .application_error_code = 10,
                                              })
                      .has_value() &
                  to_connection_command_input(QuicCoreRequestKeyUpdate{}).has_value() &
                  !to_connection_command_input(QuicCoreSendSharedStreamData{
                                                   .stream_id = 6,
                                                   .bytes = quic::SharedBytes{std::byte{0x01}},
                                                   .fin = true,
                                               })
                       .has_value());
    }

    {
        QuicCoreResult result;
        result.local_error = QuicCoreLocalError{
            .connection = 1,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        result.effects.emplace_back(QuicCoreReceiveStreamData{
            .connection = 2,
            .stream_id = 7,
            .bytes = bytes_from_string_for_runtime_tests("rx"),
            .fin = true,
        });
        result.effects.emplace_back(QuicCorePeerResetStream{
            .connection = 3,
            .stream_id = 8,
            .application_error_code = 11,
            .final_size = 12,
        });
        result.effects.emplace_back(QuicCorePeerStopSending{
            .connection = 4,
            .stream_id = 9,
            .application_error_code = 13,
        });
        result.effects.emplace_back(QuicCoreStateEvent{
            .connection = 5,
            .change = QuicCoreStateChange::handshake_ready,
        });
        result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
            .connection = 6,
            .event = QuicCoreConnectionLifecycle::accepted,
        });
        auto preferred_address = make_ipv4_preferred_address_effect_for_tests(9555);
        preferred_address.connection = 7;
        result.effects.emplace_back(preferred_address);
        result.effects.emplace_back(QuicCoreResumptionStateAvailable{
            .connection = 8,
            .state =
                QuicResumptionState{
                    .serialized = {std::byte{0xaa}},
                },
        });
        result.effects.emplace_back(QuicCoreZeroRttStatusEvent{
            .connection = 9,
            .status = QuicZeroRttStatus::accepted,
        });
        result.effects.emplace_back(QuicCorePacketInspection{
            .connection = 10,
            .direction = QuicCorePacketInspectionDirection::outbound,
            .datagram_id = 1,
        });
        result.effects.emplace_back(QuicCoreNewTokenAvailable{
            .connection = 12,
            .token = bytes_from_string_for_runtime_tests("token"),
        });
        const auto handles = result_connection_handles(result);
        const auto contains = [&](QuicConnectionHandle handle) {
            return std::find(handles.begin(), handles.end(), handle) != handles.end();
        };
        const auto sliced = slice_result_for_connection(result, 4);
        QuicCoreResult transport_error_result;
        transport_error_result.local_error = QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        transport_error_result.effects.emplace_back(QuicCoreStateEvent{
            .connection = 11,
            .change = QuicCoreStateChange::handshake_ready,
        });
        const auto transport_handles = result_connection_handles(transport_error_result);
        check(
            "result connection helpers cover the remaining effect variants",
            contains(1) & contains(2) & contains(3) & contains(4) & contains(5) & contains(6) &
                contains(7) & contains(8) & contains(9) & contains(10) & contains(12) &
                sliced.effects.size() == 1 &
                std::holds_alternative<QuicCorePeerStopSending>(sliced.effects.at(0)) &
                !result_has_connection_lifecycle(result, 4, QuicCoreConnectionLifecycle::accepted));
        check("result connection helpers ignore transport-wide local errors without connections",
              transport_handles == std::vector<QuicConnectionHandle>{11});
    }

    {
        EndpointDriveState state;
        QuicCoreResult duplicate_ready;
        duplicate_ready.effects.emplace_back(QuicCoreStateEvent{
            .connection = 13,
            .change = QuicCoreStateChange::handshake_ready,
        });
        duplicate_ready.effects.emplace_back(QuicCoreStateEvent{
            .connection = 13,
            .change = QuicCoreStateChange::handshake_ready,
        });
        check("handshake-ready observation treats repeated ready events as already observed",
              result_observes_new_handshake_ready(state, duplicate_ready) &
                  !result_observes_new_handshake_ready(state, duplicate_ready));

        std::optional<QuicCoreTimePoint> defer_output_until;
        const auto defer_base_time = now();
        note_server_early_stream_data_deferral(defer_output_until, defer_base_time);
        check("server early-data deferral records a grace deadline",
              defer_output_until ==
                  std::optional<QuicCoreTimePoint>{
                      defer_base_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs)});
    }

    {
        ServerConnectionEndpointMap endpoints;
        endpoints.emplace(17, ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = std::filesystem::path("."),
                                  }),
                              });
        QuicCoreResult accept_result;
        accept_result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
            .connection = 17,
            .event = QuicCoreConnectionLifecycle::accepted,
        });
        ensure_server_connection_endpoints_for_accepts(endpoints, accept_result,
                                                       std::filesystem::path("."));
        check("accept handling keeps pre-existing endpoint entries stable", endpoints.size() == 1);
    }

    {
        QuicCore core = make_failing_server_core_for_tests();
        EndpointDriveState transport_state;
        ServerConnectionEndpointMap endpoints;
        QuicCoreResult transport_error_result;
        transport_error_result.local_error = QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        check("server endpoint processing rejects transport-wide local errors",
              !process_server_endpoint_core_result(
                  core, transport_state, endpoints, std::filesystem::path("."),
                  transport_error_result,
                  /*fallback_socket_fd=*/77, &peer, sizeof(sockaddr_in)));

        QuicCoreResult send_failure_result;
        send_failure_result.effects.emplace_back(QuicCoreSendDatagram{
            .bytes = {std::byte{0x01}},
        });
        check("server endpoint processing rejects missing fallback routes",
              !process_server_endpoint_core_result(core, transport_state, endpoints,
                                                   std::filesystem::path("."), send_failure_result,
                                                   /*fallback_socket_fd=*/-1,
                                                   /*fallback_peer=*/nullptr,
                                                   /*fallback_peer_len=*/0));

        QuicCoreResult missing_endpoint_result;
        missing_endpoint_result.effects.emplace_back(QuicCoreStateEvent{
            .connection = 19,
            .change = QuicCoreStateChange::handshake_ready,
        });
        check("server endpoint processing tolerates missing connection endpoints",
              process_server_endpoint_core_result(
                  core, transport_state, endpoints, std::filesystem::path("."),
                  missing_endpoint_result,
                  /*fallback_socket_fd=*/77, &peer, sizeof(sockaddr_in)));
    }

    {
        const auto run_server_loop_script = [&](ScriptedServerLoopCaseForTests script,
                                                bool include_preferred_socket,
                                                std::vector<bool> has_failed_results) {
            std::size_t current_time_calls = 0;
            std::size_t receive_calls = 0;
            std::size_t wait_calls = 0;
            std::size_t process_expired_calls = 0;
            std::size_t process_datagram_calls = 0;
            std::size_t pump_calls = 0;
            std::size_t has_failed_calls = 0;
            bool endpoint_has_pending_work = false;

            const auto io = ServerLoopIo{
                .current_time =
                    [&] {
                        current_time_calls += 1;
                        return now();
                    },
                .receive_datagram =
                    [&](int, int, std::string_view) {
                        const auto index =
                            std::min(receive_calls, script.receive_results.size() - 1);
                        receive_calls += 1;
                        return script.receive_results.at(index);
                    },
                .wait_for_socket_or_deadline = [&](const RuntimeWaitConfig &,
                                                   const std::optional<QuicCoreTimePoint> &)
                    -> std::optional<RuntimeWaitStep> {
                    const auto index = std::min(wait_calls, script.wait_steps.size() - 1);
                    wait_calls += 1;
                    return script.wait_steps.at(index);
                },
            };
            const auto driver = ServerLoopDriver{
                .earliest_wakeup = [] { return std::optional<QuicCoreTimePoint>{}; },
                .process_expired_timers =
                    [&](QuicCoreTimePoint, bool &processed_any) {
                        const auto index = std::min(process_expired_calls,
                                                    script.processed_timers_results.size() - 1);
                        process_expired_calls += 1;
                        processed_any = script.processed_timers_results.at(index);
                    },
                .pump_endpoint_work =
                    [&] {
                        const auto work_index =
                            std::min(pump_calls, script.pending_work_after_pump.size() - 1);
                        endpoint_has_pending_work = script.pending_work_after_pump.at(work_index);
                        const auto progress_index =
                            std::min(pump_calls, script.pump_made_progress.size() - 1);
                        const bool made_progress = script.pump_made_progress.at(progress_index);
                        pump_calls += 1;
                        return made_progress;
                    },
                .has_pending_endpoint_work = [&] { return endpoint_has_pending_work; },
                .process_datagram =
                    [&](const RuntimeWaitStep &) {
                        process_datagram_calls += 1;
                        return script.process_datagram_result;
                    },
                .has_failed = [&]() -> bool {
                    const auto index = std::min(has_failed_calls, has_failed_results.size() - 1);
                    has_failed_calls += 1;
                    return static_cast<bool>(has_failed_results.at(index));
                },
            };
            return ServerLoopResultForTests{
                .exit_code = run_http09_server_loop(
                    ServerSocketSet{
                        .primary_fd = -1,
                        .preferred_fd =
                            include_preferred_socket ? std::optional<int>{-2} : std::nullopt,
                    },
                    io, driver),
                .current_time_calls = current_time_calls,
                .receive_calls = receive_calls,
                .wait_calls = wait_calls,
                .process_expired_calls = process_expired_calls,
                .process_datagram_calls = process_datagram_calls,
                .pump_calls = pump_calls,
            };
        };

        const auto top_level_failed =
            run_server_loop_script({}, /*include_preferred_socket=*/false, {true});
        check("server loop exits immediately when the driver has already failed",
              top_level_failed.exit_code == 1 & top_level_failed.receive_calls == 0 &
                  top_level_failed.wait_calls == 0);

        ScriptedServerLoopCaseForTests inner_timer_failure_case;
        inner_timer_failure_case.processed_timers_results = {false};
        const auto inner_timer_failed = run_server_loop_script(
            inner_timer_failure_case, /*include_preferred_socket=*/false, {false, true});
        check("server loop exits when timer processing marks the driver failed",
              inner_timer_failed.exit_code == 1 & inner_timer_failed.process_expired_calls == 1 &
                  inner_timer_failed.receive_calls == 0);

        ScriptedServerLoopCaseForTests preferred_socket_case;
        preferred_socket_case.receive_results = {
            make_input_receive_for_tests(QuicCoreInboundDatagram{
                .bytes = {std::byte{0x22}},
            }),
            make_error_receive_for_tests(),
        };
        preferred_socket_case.processed_timers_results = {false, false};
        const auto preferred_socket_result = run_server_loop_script(
            preferred_socket_case, /*include_preferred_socket=*/true, {false});
        check("server loop covers preferred-socket short-circuiting after a ready datagram",
              preferred_socket_result.exit_code == 1 &
                  preferred_socket_result.process_datagram_calls == 1 &
                  preferred_socket_result.receive_calls == 2);

        ScriptedServerLoopCaseForTests inner_pump_failure_case;
        inner_pump_failure_case.receive_results = {
            make_would_block_receive_for_tests(),
        };
        inner_pump_failure_case.processed_timers_results = {false};
        inner_pump_failure_case.pending_work_after_pump = {false};
        inner_pump_failure_case.pump_made_progress = {false};
        const auto inner_pump_failed = run_server_loop_script(
            inner_pump_failure_case, /*include_preferred_socket=*/false, {false, false, true});
        check("server loop exits when pumping pending work marks the driver failed",
              inner_pump_failed.exit_code == 1 & inner_pump_failed.pump_calls == 1 &
                  inner_pump_failed.wait_calls == 0);

        ScriptedServerLoopCaseForTests outer_failure_case;
        outer_failure_case.receive_results = {
            make_would_block_receive_for_tests(),
        };
        outer_failure_case.processed_timers_results = {false, false};
        outer_failure_case.pending_work_after_pump = {false, false};
        outer_failure_case.pump_made_progress = {false, false};
        const auto outer_timer_failed = run_server_loop_script(
            outer_failure_case, /*include_preferred_socket=*/false, {false, false, false, true});
        check("server loop exits when the outer timer pass marks the driver failed",
              outer_timer_failed.exit_code == 1 & outer_timer_failed.process_expired_calls == 2 &
                  outer_timer_failed.pump_calls == 1);
        const auto outer_pump_failed =
            run_server_loop_script(outer_failure_case, /*include_preferred_socket=*/false,
                                   {false, false, false, false, true});
        check("server loop exits when the outer pump marks the driver failed",
              outer_pump_failed.exit_code == 1 & outer_pump_failed.process_expired_calls == 2 &
                  outer_pump_failed.pump_calls == 2);

        ScriptedServerLoopCaseForTests idle_timeout_case;
        idle_timeout_case.receive_results = {
            make_would_block_receive_for_tests(),
            make_error_receive_for_tests(),
        };
        idle_timeout_case.wait_steps = {
            make_idle_timeout_wait_step_for_tests(),
        };
        idle_timeout_case.processed_timers_results = {false, false, false};
        idle_timeout_case.pending_work_after_pump = {false};
        idle_timeout_case.pump_made_progress = {false};
        const auto idle_timeout_result =
            run_server_loop_script(idle_timeout_case, /*include_preferred_socket=*/false, {false});
        check("server loop continues after idle timeout steps",
              idle_timeout_result.exit_code == 1 & idle_timeout_result.wait_calls == 1 &
                  idle_timeout_result.receive_calls == 2);

        ScriptedServerLoopCaseForTests wait_datagram_failure_case;
        wait_datagram_failure_case.receive_results = {
            make_would_block_receive_for_tests(),
        };
        wait_datagram_failure_case.wait_steps = {
            make_input_wait_step_for_tests(QuicCoreInboundDatagram{
                .bytes = {std::byte{0x33}},
            }),
        };
        wait_datagram_failure_case.processed_timers_results = {false, false};
        wait_datagram_failure_case.pending_work_after_pump = {false};
        wait_datagram_failure_case.pump_made_progress = {false};
        wait_datagram_failure_case.process_datagram_result = false;
        const auto wait_datagram_failure = run_server_loop_script(
            wait_datagram_failure_case, /*include_preferred_socket=*/false, {false});
        check("server loop propagates failures from datagrams returned by blocking waits",
              wait_datagram_failure.exit_code == 1 & wait_datagram_failure.wait_calls == 1 &
                  wait_datagram_failure.process_datagram_calls == 1);
    }

    {
        const auto run_backend_loop_script = [&](BackendLoopScriptForTests script) {
            std::size_t current_time_calls = 0;
            std::size_t next_wakeup_calls = 0;
            std::size_t wait_calls = 0;
            std::size_t process_wait_timer_calls = 0;
            std::size_t process_datagram_calls = 0;
            std::size_t process_path_mtu_calls = 0;
            std::size_t pump_calls = 0;
            bool endpoint_has_pending_work = false;
            QuicCoreTimePoint last_current_time = script.current_times.front();

            const auto driver = ServerBackendLoopDriver{
                .current_time =
                    [&] {
                        const auto index =
                            std::min(current_time_calls, script.current_times.size() - 1);
                        last_current_time = script.current_times.at(index);
                        current_time_calls += 1;
                        return last_current_time;
                    },
                .next_wakeup =
                    [&] {
                        const auto index =
                            std::min(next_wakeup_calls, script.next_wakeup_results.size() - 1);
                        next_wakeup_calls += 1;
                        return script.next_wakeup_results.at(index);
                    },
                .pump_endpoint_work =
                    [&](bool &made_progress) {
                        const auto work_index =
                            std::min(pump_calls, script.pending_work_after_pump.size() - 1);
                        endpoint_has_pending_work = script.pending_work_after_pump.at(work_index);
                        const auto progress_index =
                            std::min(pump_calls, script.pump_made_progress.size() - 1);
                        made_progress = script.pump_made_progress.at(progress_index);
                        const auto result_index =
                            std::min(pump_calls, script.pump_return_results.size() - 1);
                        const bool result = script.pump_return_results.at(result_index);
                        pump_calls += 1;
                        return result;
                    },
                .has_pending_endpoint_work = [&] { return endpoint_has_pending_work; },
                .wait =
                    [&](const std::optional<QuicCoreTimePoint> &) {
                        const auto index = std::min(wait_calls, script.wait_results.size() - 1);
                        wait_calls += 1;
                        return script.wait_results.at(index);
                    },
                .process_wait_timer = [&](QuicCoreTimePoint) -> bool {
                    const auto index = std::min(process_wait_timer_calls,
                                                script.process_wait_timer_results.size() - 1);
                    process_wait_timer_calls += 1;
                    return static_cast<bool>(script.process_wait_timer_results.at(index));
                },
                .process_datagram =
                    [&](const QuicIoRxDatagram &, QuicCoreTimePoint) {
                        process_datagram_calls += 1;
                        return script.process_datagram_result;
                    },
                .process_path_mtu_update =
                    [&](const QuicIoPathMtuUpdate &, QuicCoreTimePoint) {
                        process_path_mtu_calls += 1;
                        return script.process_path_mtu_result;
                    },
            };
            return ServerLoopResultForTests{
                .exit_code = run_server_backend_loop_with_driver(driver),
                .current_time_calls = current_time_calls,
                .wait_calls = wait_calls,
                .process_expired_calls = process_wait_timer_calls,
                .process_datagram_calls = process_datagram_calls,
                .process_path_mtu_calls = process_path_mtu_calls,
                .pump_calls = pump_calls,
            };
        };

        const auto base_time = now();
        const auto wait_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time},
            .next_wakeup_results = {base_time},
            .wait_results = {std::nullopt},
        });
        check("backend loop covers top-due wait failures and null event tracing",
              wait_failure.exit_code == 1 & wait_failure.wait_calls == 1);

        const auto top_due_missing_datagram = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time},
            .next_wakeup_results = {base_time},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::rx_datagram,
                        .now = base_time,
                    },
                },
        });
        check("backend loop covers top-due datagrams that arrive without payloads",
              top_due_missing_datagram.exit_code == 1 &
                  top_due_missing_datagram.process_datagram_calls == 0 &
                  top_due_missing_datagram.wait_calls == 1);

        const auto top_due_successful_datagram = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results = {base_time, std::nullopt},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::rx_datagram,
                        .now = base_time,
                        .datagram =
                            QuicIoRxDatagram{
                                .route_handle = QuicRouteHandle{17},
                                .bytes = {std::byte{0x34}},
                            },
                    },
                    std::nullopt,
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
        });
        check("backend loop covers successful top-due datagrams",
              top_due_successful_datagram.exit_code == 1 &
                  top_due_successful_datagram.process_datagram_calls == 1 &
                  top_due_successful_datagram.wait_calls == 2);

        const auto top_due_missing_path_mtu = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time},
            .next_wakeup_results = {base_time},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::path_mtu_update,
                        .now = base_time,
                    },
                },
        });
        check("backend loop covers top-due path MTU events without payloads",
              top_due_missing_path_mtu.exit_code == 1 &
                  top_due_missing_path_mtu.process_path_mtu_calls == 0 &
                  top_due_missing_path_mtu.wait_calls == 1);

        const auto top_due_path_mtu_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time},
            .next_wakeup_results = {base_time},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::path_mtu_update,
                        .now = base_time,
                        .path_mtu =
                            QuicIoPathMtuUpdate{
                                .route_handle = QuicRouteHandle{17},
                                .max_udp_payload_size = 1400,
                            },
                    },
                },
            .process_path_mtu_result = false,
        });
        check("backend loop propagates top-due path MTU update failures",
              top_due_path_mtu_failure.exit_code == 1 &
                  top_due_path_mtu_failure.process_path_mtu_calls == 1 &
                  top_due_path_mtu_failure.wait_calls == 1);

        const auto top_due_timer_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results = {base_time},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::timer_expired,
                        .now = base_time,
                    },
                },
            .process_wait_timer_results = {false},
        });
        check("backend loop covers due timer events that fail while tracing",
              top_due_timer_failure.exit_code == 1 &
                  top_due_timer_failure.process_expired_calls == 1);

        const auto top_due_timer_success = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results = {base_time, std::nullopt},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::timer_expired,
                        .now = base_time,
                    },
                    std::nullopt,
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
            .process_wait_timer_results = {true},
        });
        check("backend loop covers successful top-due timer handling",
              top_due_timer_success.exit_code == 1 &
                  top_due_timer_success.process_expired_calls == 1 &
                  top_due_timer_success.wait_calls == 2);

        const auto buffered_shutdown = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results = {base_time},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::shutdown,
                        .now = base_time,
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
        });
        check("backend loop buffers top-due shutdown events before consuming them",
              buffered_shutdown.exit_code == 1 & buffered_shutdown.wait_calls == 1 &
                  buffered_shutdown.pump_calls == 1);

        const auto buffered_idle_timeout = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time, base_time},
            .next_wakeup_results = {base_time, std::nullopt},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::idle_timeout,
                        .now = base_time,
                    },
                    std::nullopt,
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
        });
        check("backend loop buffers top-due idle timeouts before consuming them",
              buffered_idle_timeout.exit_code == 1 & buffered_idle_timeout.wait_calls == 2 &
                  buffered_idle_timeout.pump_calls == 2);

        const auto pump_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results = {std::nullopt},
            .pump_return_results = {false},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
        });
        check("backend loop exits after pending-work pump failures",
              pump_failure.exit_code == 1 & pump_failure.pump_calls == 1);

        const auto ready_probe_wait_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results =
                {
                    base_time + std::chrono::milliseconds(5),
                    base_time + std::chrono::milliseconds(5),
                },
            .wait_results = {std::nullopt},
            .pump_return_results = {true},
            .pending_work_after_pump = {true},
            .pump_made_progress = {true},
        });
        check("backend loop covers ready-probe wait failures",
              ready_probe_wait_failure.exit_code == 1 & ready_probe_wait_failure.wait_calls == 1 &
                  ready_probe_wait_failure.pump_calls == 1);

        const auto ready_probe_missing_datagram = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results =
                {
                    base_time + std::chrono::milliseconds(5),
                    base_time + std::chrono::milliseconds(5),
                },
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::rx_datagram,
                        .now = base_time,
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {true},
            .pump_made_progress = {true},
        });
        check("backend loop covers ready-probe datagrams that arrive without payloads",
              ready_probe_missing_datagram.exit_code == 1 &
                  ready_probe_missing_datagram.process_datagram_calls == 0 &
                  ready_probe_missing_datagram.wait_calls == 1);

        const auto ready_probe_missing_path_mtu = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results =
                {
                    base_time + std::chrono::milliseconds(5),
                    base_time + std::chrono::milliseconds(5),
                },
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::path_mtu_update,
                        .now = base_time,
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {true},
            .pump_made_progress = {true},
        });
        check("backend loop covers ready-probe path MTU events without payloads",
              ready_probe_missing_path_mtu.exit_code == 1 &
                  ready_probe_missing_path_mtu.process_path_mtu_calls == 0 &
                  ready_probe_missing_path_mtu.wait_calls == 1);

        const auto ready_probe_path_mtu_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results =
                {
                    base_time + std::chrono::milliseconds(5),
                    base_time + std::chrono::milliseconds(5),
                },
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::path_mtu_update,
                        .now = base_time,
                        .path_mtu =
                            QuicIoPathMtuUpdate{
                                .route_handle = QuicRouteHandle{17},
                                .max_udp_payload_size = 1400,
                            },
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {true},
            .pump_made_progress = {true},
            .process_path_mtu_result = false,
        });
        check("backend loop propagates ready-probe path MTU update failures",
              ready_probe_path_mtu_failure.exit_code == 1 &
                  ready_probe_path_mtu_failure.process_path_mtu_calls == 1 &
                  ready_probe_path_mtu_failure.wait_calls == 1);

        const auto ready_probe_idle_timeout = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time, base_time},
            .next_wakeup_results =
                {
                    base_time + std::chrono::milliseconds(5),
                    base_time + std::chrono::milliseconds(5),
                    std::nullopt,
                },
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::idle_timeout,
                        .now = base_time,
                    },
                    std::nullopt,
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {true, false},
            .pump_made_progress = {true, false},
        });
        check("backend loop covers ready-probe idle timeouts",
              ready_probe_idle_timeout.exit_code == 1 & ready_probe_idle_timeout.wait_calls == 2 &
                  ready_probe_idle_timeout.pump_calls == 2);

        const auto ready_probe_timer_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time, base_time},
            .next_wakeup_results = {base_time, base_time},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::timer_expired,
                        .now = base_time,
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {true},
            .pump_made_progress = {true},
            .process_wait_timer_results = {false},
        });
        check("backend loop covers ready-probe timer failures when wakeups are already due",
              ready_probe_timer_failure.exit_code == 1 &
                  ready_probe_timer_failure.process_expired_calls == 1 &
                  ready_probe_timer_failure.wait_calls == 1);

        const auto ready_probe_timer_not_due = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time, base_time},
            .next_wakeup_results =
                {
                    base_time + std::chrono::milliseconds(5),
                    base_time + std::chrono::milliseconds(5),
                    std::nullopt,
                },
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::timer_expired,
                        .now = base_time,
                    },
                    std::nullopt,
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {true, false},
            .pump_made_progress = {true, false},
        });
        check("backend loop ignores ready-probe timer events when wakeups are still in the future",
              ready_probe_timer_not_due.exit_code == 1 &
                  ready_probe_timer_not_due.process_expired_calls == 0 &
                  ready_probe_timer_not_due.wait_calls == 2 &
                  ready_probe_timer_not_due.pump_calls == 2);

        const auto ready_probe_shutdown = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time},
            .next_wakeup_results =
                {
                    base_time + std::chrono::milliseconds(5),
                    base_time + std::chrono::milliseconds(5),
                },
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::shutdown,
                        .now = base_time,
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {true},
            .pump_made_progress = {true},
        });
        check("backend loop covers ready-probe shutdown handling",
              ready_probe_shutdown.exit_code == 1 & ready_probe_shutdown.wait_calls == 1);

        const auto main_timer_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time, base_time},
            .next_wakeup_results = {std::nullopt},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::timer_expired,
                        .now = base_time,
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
            .process_wait_timer_results = {false},
        });
        check("backend loop covers main-wait timer failures",
              main_timer_failure.exit_code == 1 & main_timer_failure.process_expired_calls == 1 &
                  main_timer_failure.wait_calls == 1);

        const auto main_datagram_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time, base_time},
            .next_wakeup_results = {std::nullopt},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::rx_datagram,
                        .now = base_time,
                        .datagram =
                            QuicIoRxDatagram{
                                .route_handle = QuicRouteHandle{17},
                                .bytes = {std::byte{0x44}},
                            },
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
            .process_datagram_result = false,
        });
        check("backend loop covers main-wait datagram failures",
              main_datagram_failure.exit_code == 1 &
                  main_datagram_failure.process_datagram_calls == 1 &
                  main_datagram_failure.wait_calls == 1);

        const auto main_missing_path_mtu = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time, base_time},
            .next_wakeup_results = {std::nullopt},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::path_mtu_update,
                        .now = base_time,
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
        });
        check("backend loop covers main-wait path MTU events without payloads",
              main_missing_path_mtu.exit_code == 1 &
                  main_missing_path_mtu.process_path_mtu_calls == 0 &
                  main_missing_path_mtu.wait_calls == 1);

        const auto main_path_mtu_failure = run_backend_loop_script(BackendLoopScriptForTests{
            .current_times = {base_time, base_time, base_time},
            .next_wakeup_results = {std::nullopt},
            .wait_results =
                {
                    QuicIoEvent{
                        .kind = QuicIoEvent::Kind::path_mtu_update,
                        .now = base_time,
                        .path_mtu =
                            QuicIoPathMtuUpdate{
                                .route_handle = QuicRouteHandle{17},
                                .max_udp_payload_size = 1400,
                            },
                    },
                },
            .pump_return_results = {true},
            .pending_work_after_pump = {false},
            .pump_made_progress = {false},
            .process_path_mtu_result = false,
        });
        check("backend loop propagates main-wait path MTU update failures",
              main_path_mtu_failure.exit_code == 1 &
                  main_path_mtu_failure.process_path_mtu_calls == 1 &
                  main_path_mtu_failure.wait_calls == 1);

        const auto default_no_pending_work = [] { return false; };
        const auto default_accept_timer = [](QuicCoreTimePoint) { return true; };
        const auto default_accept_datagram = [](const QuicIoRxDatagram &, QuicCoreTimePoint) {
            return true;
        };
        check("backend loop shared default callbacks remain callable",
              !default_no_pending_work() & default_accept_timer(base_time) &
                  default_accept_datagram(QuicIoRxDatagram{}, base_time));

        {
            std::size_t wait_calls = 0;
            const auto default_path_mtu_driver = ServerBackendLoopDriver{
                .current_time = [base_time] { return base_time; },
                .next_wakeup = [] { return std::optional<QuicCoreTimePoint>{}; },
                .pump_endpoint_work =
                    [](bool &made_progress) {
                        made_progress = false;
                        return true;
                    },
                .has_pending_endpoint_work = default_no_pending_work,
                .wait =
                    [&](const std::optional<QuicCoreTimePoint> &) -> std::optional<QuicIoEvent> {
                    wait_calls += 1;
                    if (wait_calls == 1) {
                        return QuicIoEvent{
                            .kind = QuicIoEvent::Kind::path_mtu_update,
                            .now = base_time,
                            .path_mtu =
                                QuicIoPathMtuUpdate{
                                    .route_handle = QuicRouteHandle{17},
                                    .max_udp_payload_size = 1400,
                                },
                        };
                    }
                    return std::nullopt;
                },
                .process_wait_timer = default_accept_timer,
                .process_datagram = default_accept_datagram,
            };
            check("backend loop default path MTU callback accepts updates",
                  run_server_backend_loop_with_driver(default_path_mtu_driver) == 1 &
                      wait_calls == 2);
        }

        {
            std::size_t wait_calls = 0;
            std::size_t timer_calls = 0;
            std::size_t datagram_calls = 0;
            const auto default_path_mtu_driver = ServerBackendLoopDriver{
                .current_time = [base_time] { return base_time; },
                .next_wakeup = [base_time] { return std::optional<QuicCoreTimePoint>{base_time}; },
                .pump_endpoint_work =
                    [](bool &made_progress) {
                        made_progress = false;
                        return true;
                    },
                .has_pending_endpoint_work = default_no_pending_work,
                .wait =
                    [&](const std::optional<QuicCoreTimePoint> &) -> std::optional<QuicIoEvent> {
                    wait_calls += 1;
                    if (wait_calls == 1) {
                        return QuicIoEvent{
                            .kind = QuicIoEvent::Kind::timer_expired,
                            .now = base_time,
                        };
                    }
                    if (wait_calls == 2) {
                        return QuicIoEvent{
                            .kind = QuicIoEvent::Kind::rx_datagram,
                            .now = base_time,
                            .datagram =
                                QuicIoRxDatagram{
                                    .route_handle = QuicRouteHandle{17},
                                    .bytes = {std::byte{0x44}},
                                },
                        };
                    }
                    return QuicIoEvent{
                        .kind = QuicIoEvent::Kind::shutdown,
                        .now = base_time,
                    };
                },
                .process_wait_timer =
                    [&](QuicCoreTimePoint) {
                        timer_calls += 1;
                        return true;
                    },
                .process_datagram =
                    [&](const QuicIoRxDatagram &, QuicCoreTimePoint) {
                        datagram_calls += 1;
                        return true;
                    },
            };
            check("backend loop default callbacks accept timer and datagram events",
                  run_server_backend_loop_with_driver(default_path_mtu_driver) == 1 &
                      wait_calls == 3 & timer_calls == 1 & datagram_calls == 1);
        }
    }

    {
        ClientIoContext io_context;
        io_context.primary_route_handle = 7;
        io_context.backend = std::make_unique<ScriptedIoBackendForTests>();
        QuicCore core = make_local_error_client_core_for_tests();
        EndpointDriveState state;
        state.next_wakeup = now() - std::chrono::milliseconds(1);
        ClientRuntimePolicyState policy;
        ScriptedEndpointForTests endpoint;
        check("client backend loop covers expired-timer failures before waiting",
              run_http09_client_connection_backend_loop(
                  Http09RuntimeConfig{
                      .mode = Http09RuntimeMode::client,
                  },
                  make_endpoint_driver(endpoint), core, io_context, state, policy,
                  QuicCoreResult{}) == 1);
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        EndpointDriveState transport_state;
        ServerConnectionEndpointMap endpoints;
        ScriptedIoBackendForTests backend;
        QuicCore core(make_runtime_server_endpoint_config(
            Http09RuntimeConfig{
                .mode = Http09RuntimeMode::server,
                .document_root = document_root.path(),
            },
            make_identity()));
        backend.wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = now(),
        });
        check("server backend runtime loop executes timer-expired callbacks on live cores",
              run_http09_server_backend_loop(
                  Http09RuntimeConfig{
                      .mode = Http09RuntimeMode::server,
                      .document_root = document_root.path(),
                  },
                  core, transport_state, endpoints, backend) == 1);
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        EndpointDriveState transport_state;
        ServerConnectionEndpointMap endpoints;
        ScriptedIoBackendForTests backend;
        const auto input_time = now();
        backend.wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::path_mtu_update,
            .now = input_time,
            .path_mtu =
                QuicIoPathMtuUpdate{
                    .route_handle = QuicRouteHandle{17},
                    .max_udp_payload_size = 1400,
                },
        });
        QuicCore core(make_runtime_server_endpoint_config(
            Http09RuntimeConfig{
                .mode = Http09RuntimeMode::server,
                .document_root = document_root.path(),
            },
            make_identity()));
        check("server backend runtime loop applies path MTU callbacks on live cores",
              run_http09_server_backend_loop(
                  Http09RuntimeConfig{
                      .mode = Http09RuntimeMode::server,
                      .document_root = document_root.path(),
                  },
                  core, transport_state, endpoints, backend) == 1 &
                  backend.wait_requests.size() == 2);
    }

    ::unsetenv("COQUIC_RUNTIME_TRACE");
    return ok;
}

bool runtime_server_endpoint_driver_coverage_for_tests() {
    bool ok = true;
    struct RuntimeServerEndpointDriverCheck {
        bool &ok;
        bool operator()(std::string_view, bool condition) const {
            ok &= condition;
            return condition;
        }
    } check{ok};
    const auto make_loopback_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };
    const auto make_identity = [] {
        return TlsIdentity{
            .certificate_pem = read_text_file("tests/fixtures/quic-server-cert.pem"),
            .private_key_pem = read_text_file("tests/fixtures/quic-server-key.pem"),
        };
    };
    const auto accepted_connection_or_default =
        [&](std::string_view label, const std::optional<QuicConnectionHandle> &accepted) {
            check(label, accepted.has_value());
            return accepted.value_or(QuicConnectionHandle{});
        };
    class FailingSendBackendForTests final : public QuicIoBackend {
      public:
        std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &) override {
            return QuicRouteHandle{17};
        }

        std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint>) override {
            return std::nullopt;
        }

        bool send(const QuicIoTxDatagram &) override {
            return false;
        }
    };

    {
        FailingSendBackendForTests backend;
        check("failing send backend helpers return fixed route null waits and failed sends",
              backend.ensure_route(io::QuicIoRemote{
                                       .family = AF_INET,
                                   })
                      .has_value() &
                  !backend.wait(std::nullopt).has_value() &
                  !backend.send(io::QuicIoTxDatagram{
                      .route_handle = 17,
                      .bytes = {},
                  }));
    }

    check("to_connection_command_input rejects inbound datagrams",
          !to_connection_command_input(QuicCoreInboundDatagram{
                                           .bytes =
                                               {
                                                   std::byte{0x01},
                                               },
                                       })
               .has_value());
    check("to_connection_command_input rejects shared stream payloads",
          !to_connection_command_input(QuicCoreSendSharedStreamData{
                                           .stream_id = 3,
                                           .bytes =
                                               quic::SharedBytes{
                                                   std::byte{0x02},
                                               },
                                           .fin = true,
                                       })
               .has_value());
    check("to_connection_command_input rejects timer inputs",
          !to_connection_command_input(QuicCoreTimerExpired{}).has_value());
    check("to_connection_command_input preserves close commands",
          to_connection_command_input(QuicCoreCloseConnection{
                                          .application_error_code = 9,
                                          .reason_phrase = "bye",
                                      })
              .has_value());
    check("to_connection_command_input preserves migration requests",
          to_connection_command_input(QuicCoreRequestConnectionMigration{
                                          .route_handle = 77,
                                          .reason = QuicMigrationRequestReason::preferred_address,
                                      })
              .has_value());

    {
        QuicCore core = make_failing_server_core_for_tests();
        const std::array<QuicCoreInput, 1> unsupported_inputs = {
            QuicCoreInboundDatagram{
                .bytes =
                    {
                        std::byte{0x41},
                    },
            },
        };
        const auto result =
            advance_endpoint_connection_inputs(core, /*connection=*/41, unsupported_inputs, now());
        const auto local_error = result.local_error.value_or(QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        });
        check("advance_endpoint_connection_inputs reports unsupported endpoint-level inputs",
              result.local_error.has_value() &
                  (local_error.connection == QuicConnectionHandle{41}) &
                  (local_error.code == QuicCoreLocalErrorCode::unsupported_operation));
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection = accepted_connection_or_default(
            "live server handshake yields an accepted connection", accepted);

        const std::array<QuicCoreInput, 1> close_inputs = {
            QuicCoreCloseConnection{},
        };
        const auto close_result =
            advance_endpoint_connection_inputs(core, connection, close_inputs, now());
        check("advance_endpoint_connection_inputs stops after connection close effects",
              result_has_send_effects(close_result) & close_result.next_wakeup.has_value());
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        EndpointDriveState transport_state;
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto peer = make_loopback_peer(7443);
        transport_state.route_routes.emplace(kRouteHandle, RuntimeSendRoute{
                                                               .socket_fd = 77,
                                                               .peer = peer,
                                                               .peer_len = sizeof(sockaddr_in),
                                                           });
        QuicCoreTimePoint step_now = now();
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection = accepted_connection_or_default(
            "direct server-result fixture handshake succeeds", accepted);

        {
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                              });
            QuicCoreResult state_only_result;
            state_only_result.effects.emplace_back(QuicCoreStateEvent{
                .connection = connection,
                .change = QuicCoreStateChange::handshake_ready,
            });
            bool observed_send_effects = true;
            check("process_server_endpoint_core_result ignores non-stream effects",
                  process_server_endpoint_core_result(core, transport_state, endpoints,
                                                      document_root.path(), state_only_result,
                                                      /*fallback_socket_fd=*/77, &peer,
                                                      sizeof(sockaddr_in), &observed_send_effects) &
                      endpoints.contains(connection) & !observed_send_effects);
        }

        {
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                                  .has_pending_work = true,
                              });
            QuicCoreResult local_error_result;
            local_error_result.local_error = QuicCoreLocalError{
                .connection = connection,
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
            check(
                "process_server_endpoint_core_result erases endpoints for connection-local errors",
                process_server_endpoint_core_result(
                    core, transport_state, endpoints, document_root.path(), local_error_result,
                    /*fallback_socket_fd=*/77, &peer, sizeof(sockaddr_in)) &
                    !endpoints.contains(connection));
        }

        {
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                                  .has_pending_work = true,
                              });
            QuicCoreResult closed_result;
            closed_result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
                .connection = connection,
                .event = QuicCoreConnectionLifecycle::closed,
            });
            check("process_server_endpoint_core_result drops closed endpoints",
                  process_server_endpoint_core_result(
                      core, transport_state, endpoints, document_root.path(), closed_result,
                      /*fallback_socket_fd=*/77, &peer, sizeof(sockaddr_in)) &
                      !endpoints.contains(connection));
        }

        {
            g_recorded_sendto_for_tests = {};
            g_recorded_sendmsg_for_tests = {};
            const ScopedHttp09RuntimeOpsOverride runtime_ops{
                Http09RuntimeOpsOverride{
                    .sendto_fn = record_sendto_for_tests,
                    .sendmsg_fn = record_sendmsg_for_tests,
                },
            };
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                              });
            QuicCoreResult request_result;
            request_result.effects.emplace_back(QuicCoreReceiveStreamData{
                .connection = connection,
                .stream_id = 0,
                .bytes = bytes_from_string_for_runtime_tests("GET /small.txt\r\n"),
                .fin = true,
            });
            bool observed_send_effects = false;
            check("process_server_endpoint_core_result advances endpoint-generated stream sends",
                  process_server_endpoint_core_result(core, transport_state, endpoints,
                                                      document_root.path(), request_result,
                                                      /*fallback_socket_fd=*/77, &peer,
                                                      sizeof(sockaddr_in), &observed_send_effects) &
                      observed_send_effects &
                      (g_recorded_sendto_for_tests.calls > 0 |
                       g_recorded_sendmsg_for_tests.calls > 0));
        }

        {
            g_recorded_sendmsg_for_tests = {};
            const ScopedHttp09RuntimeOpsOverride runtime_ops{
                Http09RuntimeOpsOverride{
                    .sendmsg_fn = record_sendmsg_for_tests,
                },
            };
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                              });
            QuicCoreResult invalid_request_result;
            invalid_request_result.effects.emplace_back(QuicCoreReceiveStreamData{
                .connection = connection,
                .stream_id = 0,
                .bytes = {},
                .fin = true,
            });
            check("process_server_endpoint_core_result closes failed endpoints",
                  process_server_endpoint_core_result(core, transport_state, endpoints,
                                                      document_root.path(), invalid_request_result,
                                                      /*fallback_socket_fd=*/77, &peer,
                                                      sizeof(sockaddr_in)) &
                      !endpoints.contains(connection));
        }
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        constexpr QuicRouteHandle kRouteHandle = 17;
        ScriptedIoBackendForTests backend;
        EndpointDriveState transport_state;
        QuicCoreTimePoint step_now = now();
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection = accepted_connection_or_default(
            "backend server-result fixture handshake succeeds", accepted);

        {
            ServerConnectionEndpointMap endpoints;
            QuicCoreResult local_error_result;
            local_error_result.local_error = QuicCoreLocalError{
                .connection = std::nullopt,
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
            check("process_server_endpoint_core_result_with_backend rejects transport-wide local "
                  "errors",
                  !process_server_endpoint_core_result_with_backend(
                      core, transport_state, endpoints, document_root.path(), local_error_result,
                      kRouteHandle, backend));
        }

        {
            ServerConnectionEndpointMap endpoints;
            QuicCoreResult missing_endpoint_result;
            missing_endpoint_result.effects.emplace_back(QuicCoreStateEvent{
                .connection = connection,
                .change = QuicCoreStateChange::handshake_ready,
            });
            check("process_server_endpoint_core_result_with_backend tolerates missing endpoints",
                  process_server_endpoint_core_result_with_backend(
                      core, transport_state, endpoints, document_root.path(),
                      missing_endpoint_result, kRouteHandle, backend));
        }

        {
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                                  .has_pending_work = true,
                              });
            QuicCoreResult closed_result;
            closed_result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
                .connection = connection,
                .event = QuicCoreConnectionLifecycle::closed,
            });
            check("process_server_endpoint_core_result_with_backend removes closed endpoints",
                  process_server_endpoint_core_result_with_backend(
                      core, transport_state, endpoints, document_root.path(), closed_result,
                      kRouteHandle, backend) &
                      !endpoints.contains(connection));
        }

        {
            backend.sent_datagrams.clear();
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                              });
            QuicCoreResult request_result;
            request_result.effects.emplace_back(QuicCoreReceiveStreamData{
                .connection = connection,
                .stream_id = 0,
                .bytes = bytes_from_string_for_runtime_tests("GET /small.txt\r\n"),
                .fin = true,
            });
            check("process_server_endpoint_core_result_with_backend routes generated sends through "
                  "the backend",
                  process_server_endpoint_core_result_with_backend(
                      core, transport_state, endpoints, document_root.path(), request_result,
                      kRouteHandle, backend) &
                      !backend.sent_datagrams.empty());
        }

        {
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                              });
            QuicCoreResult invalid_request_result;
            invalid_request_result.effects.emplace_back(QuicCoreReceiveStreamData{
                .connection = connection,
                .stream_id = 0,
                .bytes = {},
                .fin = true,
            });
            check("process_server_endpoint_core_result_with_backend closes failed endpoints",
                  process_server_endpoint_core_result_with_backend(
                      core, transport_state, endpoints, document_root.path(),
                      invalid_request_result, kRouteHandle, backend) &
                      !endpoints.contains(connection));
        }
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("large.bin",
                                 std::string(static_cast<std::size_t>(64) * 1024U, 'x'));
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        EndpointDriveState transport_state;
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto peer = make_loopback_peer(7555);
        transport_state.route_routes.emplace(kRouteHandle, RuntimeSendRoute{
                                                               .socket_fd = 79,
                                                               .peer = peer,
                                                               .peer_len = sizeof(sockaddr_in),
                                                           });
        QuicCoreTimePoint step_now = now();
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection = accepted_connection_or_default(
            "server-endpoint pump fixture handshake succeeds", accepted);

        {
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                                  .has_pending_work = true,
                              });
            bool made_progress = true;
            check("pump_shared_server_endpoint_work clears stale pending flags without work",
                  pump_shared_server_endpoint_work(core, transport_state, endpoints,
                                                   document_root.path(), made_progress) &
                      !made_progress & endpoints.contains(connection) &
                      !endpoints.at(connection).has_pending_work);
        }

        {
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                                  .has_pending_work = false,
                              });
            bool made_progress = true;
            check("pump_shared_server_endpoint_work ignores endpoints without pending work",
                  pump_shared_server_endpoint_work(core, transport_state, endpoints,
                                                   document_root.path(), made_progress) &
                      !made_progress & endpoints.contains(connection));
        }

        {
            g_recorded_sendto_for_tests = {};
            g_recorded_sendmsg_for_tests = {};
            const ScopedHttp09RuntimeOpsOverride runtime_ops{
                Http09RuntimeOpsOverride{
                    .sendto_fn = record_sendto_for_tests,
                    .sendmsg_fn = record_sendmsg_for_tests,
                },
            };
            QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
                .document_root = document_root.path(),
            });
            const auto initial_update = endpoint.on_core_result(
                single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection, ServerConnectionEndpointState{
                                              .endpoint = std::move(endpoint),
                                              .has_pending_work = initial_update.has_pending_work,
                                          });
            bool made_progress = false;
            check("pump_shared_server_endpoint_work advances queued response chunks",
                  pump_shared_server_endpoint_work(core, transport_state, endpoints,
                                                   document_root.path(), made_progress) &
                      made_progress &
                      (g_recorded_sendto_for_tests.calls > 0 |
                       g_recorded_sendmsg_for_tests.calls > 0));
        }

        {
            g_recorded_sendmsg_for_tests = {};
            const ScopedHttp09RuntimeOpsOverride runtime_ops{
                Http09RuntimeOpsOverride{
                    .sendmsg_fn = record_sendmsg_for_tests,
                },
            };
            QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
                .document_root = document_root.path(),
            });
            static_cast<void>(endpoint.on_core_result(
                single_receive_result_for_runtime_tests(0, "", true), now()));
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection, ServerConnectionEndpointState{
                                              .endpoint = std::move(endpoint),
                                              .has_pending_work = true,
                                          });
            bool made_progress = false;
            check("pump_shared_server_endpoint_work closes endpoints whose polls fail",
                  pump_shared_server_endpoint_work(core, transport_state, endpoints,
                                                   document_root.path(), made_progress) &
                      !endpoints.contains(connection));
        }
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("large.bin",
                                 std::string(static_cast<std::size_t>(64) * 1024U, 'x'));
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        ScriptedIoBackendForTests backend;
        EndpointDriveState transport_state;
        constexpr QuicRouteHandle kRouteHandle = 17;
        QuicCoreTimePoint step_now = now();
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection =
            accepted_connection_or_default("backend pump fixture handshake succeeds", accepted);

        {
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection,
                              ServerConnectionEndpointState{
                                  .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                      .document_root = document_root.path(),
                                  }),
                                  .has_pending_work = true,
                              });
            bool made_progress = true;
            check("pump_shared_server_endpoint_work_with_backend clears stale pending flags "
                  "without work",
                  pump_shared_server_endpoint_work_with_backend(core, transport_state, endpoints,
                                                                document_root.path(), backend,
                                                                made_progress) &
                      !made_progress & endpoints.contains(connection) &
                      !endpoints.at(connection).has_pending_work);
        }

        {
            backend.sent_datagrams.clear();
            QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
                .document_root = document_root.path(),
            });
            const auto initial_update = endpoint.on_core_result(
                single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection, ServerConnectionEndpointState{
                                              .endpoint = std::move(endpoint),
                                              .has_pending_work = initial_update.has_pending_work,
                                          });
            bool made_progress = false;
            check("pump_shared_server_endpoint_work_with_backend advances queued response chunks",
                  pump_shared_server_endpoint_work_with_backend(core, transport_state, endpoints,
                                                                document_root.path(), backend,
                                                                made_progress) &
                      made_progress & !backend.sent_datagrams.empty());
        }

        {
            QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
                .document_root = document_root.path(),
            });
            static_cast<void>(endpoint.on_core_result(
                single_receive_result_for_runtime_tests(0, "", true), now()));
            ServerConnectionEndpointMap endpoints;
            endpoints.emplace(connection, ServerConnectionEndpointState{
                                              .endpoint = std::move(endpoint),
                                              .has_pending_work = true,
                                          });
            bool made_progress = false;
            check("pump_shared_server_endpoint_work_with_backend closes endpoints whose polls fail",
                  pump_shared_server_endpoint_work_with_backend(core, transport_state, endpoints,
                                                                document_root.path(), backend,
                                                                made_progress) &
                      !endpoints.contains(connection));
        }
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("large.bin",
                                 std::string(static_cast<std::size_t>(64) * 1024U, 'x'));
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection = accepted_connection_or_default(
            "server-endpoint route-failure fixture handshake succeeds", accepted);
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        const auto initial_update = endpoint.on_core_result(
            single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
        ServerConnectionEndpointMap endpoints;
        endpoints.emplace(connection, ServerConnectionEndpointState{
                                          .endpoint = std::move(endpoint),
                                          .has_pending_work = initial_update.has_pending_work,
                                      });
        EndpointDriveState transport_state;
        bool made_progress = false;
        check("pump_shared_server_endpoint_work fails when pending connection inputs cannot be "
              "routed",
              !pump_shared_server_endpoint_work(core, transport_state, endpoints,
                                                document_root.path(), made_progress));
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("large.bin",
                                 std::string(static_cast<std::size_t>(64) * 1024U, 'x'));
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection = accepted_connection_or_default(
            "server-endpoint close-route-failure fixture handshake succeeds", accepted);
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        static_cast<void>(
            endpoint.on_core_result(single_receive_result_for_runtime_tests(0, "", true), now()));
        ServerConnectionEndpointMap endpoints;
        endpoints.emplace(connection, ServerConnectionEndpointState{
                                          .endpoint = std::move(endpoint),
                                          .has_pending_work = true,
                                      });
        EndpointDriveState transport_state;
        bool made_progress = false;
        check("pump_shared_server_endpoint_work fails when close effects cannot be routed after "
              "poll failure",
              !pump_shared_server_endpoint_work(core, transport_state, endpoints,
                                                document_root.path(), made_progress));
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("large.bin",
                                 std::string(static_cast<std::size_t>(64) * 1024U, 'x'));
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection = accepted_connection_or_default(
            "backend send-failure fixture handshake succeeds", accepted);
        FailingSendBackendForTests failing_backend;
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        const auto initial_update = endpoint.on_core_result(
            single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
        ServerConnectionEndpointMap endpoints;
        endpoints.emplace(connection, ServerConnectionEndpointState{
                                          .endpoint = std::move(endpoint),
                                          .has_pending_work = initial_update.has_pending_work,
                                      });
        EndpointDriveState transport_state;
        bool made_progress = false;
        check("pump_shared_server_endpoint_work_with_backend fails when the backend rejects queued "
              "response sends",
              !pump_shared_server_endpoint_work_with_backend(core, transport_state, endpoints,
                                                             document_root.path(), failing_backend,
                                                             made_progress));
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("large.bin",
                                 std::string(static_cast<std::size_t>(64) * 1024U, 'x'));
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config, make_identity()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        const auto connection = accepted_connection_or_default(
            "backend close-send-failure fixture handshake succeeds", accepted);
        FailingSendBackendForTests failing_backend;
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        static_cast<void>(
            endpoint.on_core_result(single_receive_result_for_runtime_tests(0, "", true), now()));
        ServerConnectionEndpointMap endpoints;
        endpoints.emplace(connection, ServerConnectionEndpointState{
                                          .endpoint = std::move(endpoint),
                                          .has_pending_work = true,
                                      });
        EndpointDriveState transport_state;
        bool made_progress = false;
        check("pump_shared_server_endpoint_work_with_backend fails when the backend rejects close "
              "sends after poll failure",
              !pump_shared_server_endpoint_work_with_backend(core, transport_state, endpoints,
                                                             document_root.path(), failing_backend,
                                                             made_progress));
    }

    {
        g_recorded_recvmsg_for_tests = {};
        g_recorded_recvmsg_for_tests.bytes = {
            std::byte{0x51},
        };
        g_recorded_recvmsg_for_tests.peer = make_loopback_peer(7666);
        g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);
        const ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *, nfds_t, int) -> int { return 0; },
                .recvmsg_fn = &record_recvmsg_for_tests,
            },
        };
        const auto io = make_runtime_server_loop_io();
        const auto current = io.current_time();
        const auto receive = io.receive_datagram(/*socket_fd=*/91, /*flags=*/0, "server");
        const auto wait = io.wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fds = {91, -1},
                .socket_fd_count = 1,
                .idle_timeout_ms = 25,
                .role_name = "server",
            },
            current + std::chrono::milliseconds(25));
        const auto receive_input =
            receive.step.input.value_or(QuicCoreInput{QuicCoreInboundDatagram{}});
        const auto &inbound = std::get<QuicCoreInboundDatagram>(receive_input);
        const auto wait_step = wait.value_or(RuntimeWaitStep{});
        const auto wait_input = wait_step.input.value_or(QuicCoreInput{QuicCoreInboundDatagram{}});
        check("make_runtime_server_loop_io forwards to runtime wait and receive helpers",
              (current.time_since_epoch().count() > 0) &
                  (receive.status == ReceiveDatagramStatus::ok) &
                  (inbound.bytes == g_recorded_recvmsg_for_tests.bytes) & wait.has_value() &
                  wait_step.input.has_value() &
                  std::holds_alternative<QuicCoreTimerExpired>(wait_input));
    }

    return ok;
}

} // namespace test

#if defined(__clang__)
#pragma clang attribute pop
#endif

} // namespace coquic::http09
