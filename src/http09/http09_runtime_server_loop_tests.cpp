#include "src/http09/http09_runtime_test_support.h"

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace coquic::http09 {

namespace test {

bool server_loop_coverage_check(bool &coverage_ok, std::string_view, bool condition) {
    coverage_ok &= condition;
    return condition;
}

void reset_runtime_logging_state_for_tests() {
    runtime_logging_ready_flag() = false;
}

bool runtime_logging_ready_for_tests() {
    return runtime_logging_ready_flag();
}

bool runtime_openssl_available_for_tests() {
    return runtime_has_openssl();
}

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

ServerLoopResultForTests
run_server_loop_script_for_tests(const ScriptedServerLoopCaseForTests &script,
                                 bool include_preferred_socket,
                                 const std::vector<bool> &has_failed_results) {
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
                const auto index = std::min(receive_calls, script.receive_results.size() - 1);
                receive_calls += 1;
                return script.receive_results.at(index);
            },
        .wait_for_socket_or_deadline =
            [&](const RuntimeWaitConfig &,
                const std::optional<QuicCoreTimePoint> &) -> std::optional<RuntimeWaitStep> {
            const auto index = std::min(wait_calls, script.wait_steps.size() - 1);
            wait_calls += 1;
            return script.wait_steps.at(index);
        },
    };
    const auto driver = ServerLoopDriver{
        .earliest_wakeup = [] { return std::optional<QuicCoreTimePoint>{}; },
        .process_expired_timers =
            [&](QuicCoreTimePoint, bool &processed_any) {
                const auto index =
                    std::min(process_expired_calls, script.processed_timers_results.size() - 1);
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
                .preferred_fd = include_preferred_socket ? std::optional<int>{-2} : std::nullopt,
            },
            io, driver),
        .current_time_calls = current_time_calls,
        .receive_calls = receive_calls,
        .wait_calls = wait_calls,
        .process_expired_calls = process_expired_calls,
        .process_datagram_calls = process_datagram_calls,
        .pump_calls = pump_calls,
    };
}

ServerLoopResultForTests
run_backend_loop_script_for_tests(const BackendLoopScriptForTests &script) {
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
                const auto index = std::min(current_time_calls, script.current_times.size() - 1);
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
            const auto index =
                std::min(process_wait_timer_calls, script.process_wait_timer_results.size() - 1);
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
}

struct ExpectedServerLoopResultForTests {
    int exit_code = 1;
    std::optional<std::size_t> receive_calls;
    std::optional<std::size_t> wait_calls;
    std::optional<std::size_t> process_expired_calls;
    std::optional<std::size_t> process_datagram_calls;
    std::optional<std::size_t> process_path_mtu_calls;
    std::optional<std::size_t> pump_calls;
};

bool server_loop_result_matches_for_tests(const ServerLoopResultForTests &result,
                                          const ExpectedServerLoopResultForTests &expected) {
    return result.exit_code == expected.exit_code &&
           (!expected.receive_calls.has_value() ||
            result.receive_calls == *expected.receive_calls) &&
           (!expected.wait_calls.has_value() || result.wait_calls == *expected.wait_calls) &&
           (!expected.process_expired_calls.has_value() ||
            result.process_expired_calls == *expected.process_expired_calls) &&
           (!expected.process_datagram_calls.has_value() ||
            result.process_datagram_calls == *expected.process_datagram_calls) &&
           (!expected.process_path_mtu_calls.has_value() ||
            result.process_path_mtu_calls == *expected.process_path_mtu_calls) &&
           (!expected.pump_calls.has_value() || result.pump_calls == *expected.pump_calls);
}

BackendLoopScriptForTests
backend_loop_top_due_successful_datagram_script_for_tests(QuicCoreTimePoint base_time) {
    return BackendLoopScriptForTests{
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
    };
}

bool result_connection_helpers_cover_effect_variants_for_tests(const QuicCoreResult &result) {
    const auto handles = result_connection_handles(result);
    const auto contains = [&](QuicConnectionHandle handle) {
        return std::find(handles.begin(), handles.end(), handle) != handles.end();
    };
    const auto sliced = slice_result_for_connection(result, 4);
    return contains(1) & contains(2) & contains(3) & contains(4) & contains(5) & contains(6) &
           contains(7) & contains(8) & contains(9) & contains(10) & contains(12) &
           sliced.effects.size() == 1 &
           std::holds_alternative<QuicCorePeerStopSending>(sliced.effects.at(0)) &
           !result_has_connection_lifecycle(result, 4, QuicCoreConnectionLifecycle::accepted);
}

bool transport_wide_error_connection_helpers_for_tests(const QuicCoreResult &result) {
    return result_connection_handles(result) == std::vector<QuicConnectionHandle>{11};
}

sockaddr_storage make_server_loopback_peer_for_tests(std::uint16_t port) {
    sockaddr_storage loopback_peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&loopback_peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return loopback_peer;
}

TlsIdentity make_runtime_tls_identity_for_tests() {
    return TlsIdentity{
        .certificate_pem = read_text_file("tests/fixtures/quic-server-cert.pem"),
        .private_key_pem = read_text_file("tests/fixtures/quic-server-key.pem"),
    };
}

ParsedServerDatagram make_supported_initial_for_tests() {
    return ParsedServerDatagram{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = make_runtime_connection_id(std::byte{0x51}, 1),
        .source_connection_id = make_runtime_connection_id(std::byte{0x61}, 2),
        .token = {},
    };
}

void cover_runtime_retry_helpers_for_tests(bool &coverage_ok,
                                           const ParsedServerDatagram &supported_initial,
                                           const sockaddr_storage &peer) {
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
        server_loop_coverage_check(coverage_ok, "retry helper traces and sends tokenless initials",
                                   retry_result.has_value() & retry_result.value_or(false) &
                                       g_recorded_sendto_for_tests.calls == 1 &
                                       next_connection_index == 10);
    }

    {
        std::optional<PendingRetryToken> retry_context;
        RetryTokenStore retry_tokens;
        ParsedServerDatagram invalid_retry = supported_initial;
        invalid_retry.token = make_runtime_retry_token(0x0102030405060708ull);
        invalid_retry.destination_connection_id = make_runtime_connection_id(std::byte{0x72}, 4);
        server_loop_coverage_check(
            coverage_ok, "invalid retry tokens hit the traced rejection path",
            !populate_retry_context_if_required(/*retry_enabled=*/true, invalid_retry, peer,
                                                sizeof(sockaddr_in), retry_tokens, retry_context) &
                !retry_context.has_value());
    }

    {
        RetryTokenStore retry_tokens;
        ParsedServerDatagram invalid_retry_version = supported_initial;
        invalid_retry_version.version = kVersionNegotiationVersion;
        server_loop_coverage_check(coverage_ok, "retry send covers retry integrity-tag failures",
                                   !send_retry_for_initial(/*fd=*/18, invalid_retry_version, peer,
                                                           sizeof(sockaddr_in), retry_tokens,
                                                           /*connection_index=*/1));
    }
}

void cover_runtime_trace_inputs_for_tests(bool &coverage_ok) {
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
        server_loop_coverage_check(coverage_ok,
                                   "trace coverage can serialize a public server Initial",
                                   server_initial.has_value());
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
}

void cover_runtime_connection_result_helpers_for_tests(bool &coverage_ok,
                                                       const sockaddr_storage &peer) {
    {
        server_loop_coverage_check(
            coverage_ok, "connection command translation covers remaining supported commands",
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
        server_loop_coverage_check(
            coverage_ok, "result connection helpers cover the remaining effect variants",
            result_connection_helpers_cover_effect_variants_for_tests(result));
        server_loop_coverage_check(
            coverage_ok,
            "result connection helpers ignore transport-wide local errors without connections",
            transport_wide_error_connection_helpers_for_tests(transport_error_result));
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
        server_loop_coverage_check(
            coverage_ok,
            "handshake-ready observation treats repeated ready events as already observed",
            result_observes_new_handshake_ready(state, duplicate_ready) &
                !result_observes_new_handshake_ready(state, duplicate_ready));

        std::optional<QuicCoreTimePoint> defer_output_until;
        const auto defer_base_time = now();
        note_server_early_stream_data_deferral(defer_output_until, defer_base_time);
        server_loop_coverage_check(
            coverage_ok, "server early-data deferral records a grace deadline",
            defer_output_until ==
                std::optional<QuicCoreTimePoint>{
                    defer_base_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs)});
    }

    {
        ServerConnectionEndpointMap connection_endpoints;
        connection_endpoints.emplace(
            17, ServerConnectionEndpointState{
                    .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                        .document_root = std::filesystem::path("."),
                    }),
                });
        QuicCoreResult accept_result;
        accept_result.effects.emplace_back(QuicCoreConnectionLifecycleEvent{
            .connection = 17,
            .event = QuicCoreConnectionLifecycle::accepted,
        });
        ensure_server_connection_endpoints_for_accepts(connection_endpoints, accept_result,
                                                       std::filesystem::path("."));
        server_loop_coverage_check(coverage_ok,
                                   "accept handling keeps pre-existing endpoint entries stable",
                                   connection_endpoints.size() == 1);
    }

    {
        QuicCore core = make_failing_server_core_for_tests();
        EndpointDriveState drive_state;
        ServerConnectionEndpointMap connection_endpoints;
        QuicCoreResult transport_error_result;
        transport_error_result.local_error = QuicCoreLocalError{
            .connection = std::nullopt,
            .code = QuicCoreLocalErrorCode::unsupported_operation,
            .stream_id = std::nullopt,
        };
        server_loop_coverage_check(
            coverage_ok, "server endpoint processing rejects transport-wide local errors",
            !process_server_endpoint_core_result(core, drive_state, connection_endpoints,
                                                 std::filesystem::path("."), transport_error_result,
                                                 /*fallback_socket_fd=*/77, &peer,
                                                 sizeof(sockaddr_in)));

        QuicCoreResult send_failure_result;
        send_failure_result.effects.emplace_back(QuicCoreSendDatagram{
            .bytes = {std::byte{0x01}},
        });
        server_loop_coverage_check(
            coverage_ok, "server endpoint processing rejects missing fallback routes",
            !process_server_endpoint_core_result(core, drive_state, connection_endpoints,
                                                 std::filesystem::path("."), send_failure_result,
                                                 /*fallback_socket_fd=*/-1,
                                                 /*fallback_peer=*/nullptr,
                                                 /*fallback_peer_len=*/0));

        QuicCoreResult missing_endpoint_result;
        missing_endpoint_result.effects.emplace_back(QuicCoreStateEvent{
            .connection = 19,
            .change = QuicCoreStateChange::handshake_ready,
        });
        server_loop_coverage_check(
            coverage_ok, "server endpoint processing tolerates missing connection endpoints",
            process_server_endpoint_core_result(core, drive_state, connection_endpoints,
                                                std::filesystem::path("."), missing_endpoint_result,
                                                /*fallback_socket_fd=*/77, &peer,
                                                sizeof(sockaddr_in)));
    }
}

void cover_runtime_server_loop_script_cases_for_tests(bool &coverage_ok) {
    {
        server_loop_coverage_check(
            coverage_ok, "server loop exits immediately when the driver has already failed",
            server_loop_result_matches_for_tests(
                run_server_loop_script_for_tests({}, /*include_preferred_socket=*/false, {true}),
                ExpectedServerLoopResultForTests{
                    .receive_calls = 0,
                    .wait_calls = 0,
                }));

        ScriptedServerLoopCaseForTests inner_timer_failure_case;
        inner_timer_failure_case.processed_timers_results = {false};
        server_loop_coverage_check(
            coverage_ok, "server loop exits when timer processing marks the driver failed",
            server_loop_result_matches_for_tests(
                run_server_loop_script_for_tests(inner_timer_failure_case,
                                                 /*include_preferred_socket=*/false, {false, true}),
                ExpectedServerLoopResultForTests{
                    .receive_calls = 0,
                    .process_expired_calls = 1,
                }));

        ScriptedServerLoopCaseForTests preferred_socket_case;
        preferred_socket_case.receive_results = {
            make_input_receive_for_tests(QuicCoreInboundDatagram{
                .bytes = {std::byte{0x22}},
            }),
            make_error_receive_for_tests(),
        };
        preferred_socket_case.processed_timers_results = {false, false};
        server_loop_coverage_check(
            coverage_ok,
            "server loop covers preferred-socket short-circuiting after a ready datagram",
            server_loop_result_matches_for_tests(
                run_server_loop_script_for_tests(preferred_socket_case,
                                                 /*include_preferred_socket=*/true, {false}),
                ExpectedServerLoopResultForTests{
                    .receive_calls = 2,
                    .process_datagram_calls = 1,
                }));

        ScriptedServerLoopCaseForTests inner_pump_failure_case;
        inner_pump_failure_case.receive_results = {
            make_would_block_receive_for_tests(),
        };
        inner_pump_failure_case.processed_timers_results = {false};
        inner_pump_failure_case.pending_work_after_pump = {false};
        inner_pump_failure_case.pump_made_progress = {false};
        server_loop_coverage_check(
            coverage_ok, "server loop exits when pumping pending work marks the driver failed",
            server_loop_result_matches_for_tests(
                run_server_loop_script_for_tests(inner_pump_failure_case,
                                                 /*include_preferred_socket=*/false,
                                                 {false, false, true}),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 0,
                    .pump_calls = 1,
                }));

        ScriptedServerLoopCaseForTests outer_failure_case;
        outer_failure_case.receive_results = {
            make_would_block_receive_for_tests(),
        };
        outer_failure_case.processed_timers_results = {false, false};
        outer_failure_case.pending_work_after_pump = {false, false};
        outer_failure_case.pump_made_progress = {false, false};
        server_loop_coverage_check(
            coverage_ok, "server loop exits when the outer timer pass marks the driver failed",
            server_loop_result_matches_for_tests(
                run_server_loop_script_for_tests(outer_failure_case,
                                                 /*include_preferred_socket=*/false,
                                                 {false, false, false, true}),
                ExpectedServerLoopResultForTests{
                    .process_expired_calls = 2,
                    .pump_calls = 1,
                }));
        server_loop_coverage_check(coverage_ok,
                                   "server loop exits when the outer pump marks the driver failed",
                                   server_loop_result_matches_for_tests(
                                       run_server_loop_script_for_tests(
                                           outer_failure_case, /*include_preferred_socket=*/false,
                                           {false, false, false, false, true}),
                                       ExpectedServerLoopResultForTests{
                                           .process_expired_calls = 2,
                                           .pump_calls = 2,
                                       }));

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
        server_loop_coverage_check(
            coverage_ok, "server loop continues after idle timeout steps",
            server_loop_result_matches_for_tests(
                run_server_loop_script_for_tests(idle_timeout_case,
                                                 /*include_preferred_socket=*/false, {false}),
                ExpectedServerLoopResultForTests{
                    .receive_calls = 2,
                    .wait_calls = 1,
                }));

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
        server_loop_coverage_check(
            coverage_ok,
            "server loop propagates failures from datagrams returned by blocking waits",
            server_loop_result_matches_for_tests(
                run_server_loop_script_for_tests(wait_datagram_failure_case,
                                                 /*include_preferred_socket=*/false, {false}),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 1,
                    .process_datagram_calls = 1,
                }));
    }
}

void cover_runtime_backend_loop_script_cases_for_tests(bool &coverage_ok) {
    {
        const auto base_time = now();
        server_loop_coverage_check(
            coverage_ok, "backend loop covers top-due wait failures and null event tracing",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(BackendLoopScriptForTests{
                    .current_times = {base_time},
                    .next_wakeup_results = {base_time},
                    .wait_results = {std::nullopt},
                }),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 1,
                }));

        server_loop_coverage_check(
            coverage_ok, "backend loop covers top-due datagrams that arrive without payloads",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(BackendLoopScriptForTests{
                    .current_times = {base_time},
                    .next_wakeup_results = {base_time},
                    .wait_results =
                        {
                            QuicIoEvent{
                                .kind = QuicIoEvent::Kind::rx_datagram,
                                .now = base_time,
                            },
                        },
                }),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 1,
                    .process_datagram_calls = 0,
                }));

        server_loop_coverage_check(
            coverage_ok, "backend loop covers successful top-due datagrams",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(
                    backend_loop_top_due_successful_datagram_script_for_tests(base_time)),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 2,
                    .process_datagram_calls = 1,
                }));

        server_loop_coverage_check(coverage_ok,
                                   "backend loop covers top-due path MTU events without payloads",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
                                           .current_times = {base_time},
                                           .next_wakeup_results = {base_time},
                                           .wait_results =
                                               {
                                                   QuicIoEvent{
                                                       .kind = QuicIoEvent::Kind::path_mtu_update,
                                                       .now = base_time,
                                                   },
                                               },
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                           .process_path_mtu_calls = 0,
                                       }));

        server_loop_coverage_check(coverage_ok,
                                   "backend loop propagates top-due path MTU update failures",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                           .process_path_mtu_calls = 1,
                                       }));

        server_loop_coverage_check(coverage_ok,
                                   "backend loop covers due timer events that fail while tracing",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .process_expired_calls = 1,
                                       }));

        server_loop_coverage_check(coverage_ok,
                                   "backend loop covers successful top-due timer handling",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 2,
                                           .process_expired_calls = 1,
                                       }));

        server_loop_coverage_check(
            coverage_ok, "backend loop buffers top-due shutdown events before consuming them",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                }),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 1,
                    .pump_calls = 1,
                }));

        server_loop_coverage_check(
            coverage_ok, "backend loop buffers top-due idle timeouts before consuming them",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                }),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 2,
                    .pump_calls = 2,
                }));

        server_loop_coverage_check(coverage_ok,
                                   "backend loop exits after pending-work pump failures",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
                                           .current_times = {base_time, base_time},
                                           .next_wakeup_results = {std::nullopt},
                                           .pump_return_results = {false},
                                           .pending_work_after_pump = {false},
                                           .pump_made_progress = {false},
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .pump_calls = 1,
                                       }));

        server_loop_coverage_check(coverage_ok, "backend loop covers ready-probe wait failures",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                           .pump_calls = 1,
                                       }));

        server_loop_coverage_check(
            coverage_ok, "backend loop covers ready-probe datagrams that arrive without payloads",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                }),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 1,
                    .process_datagram_calls = 0,
                }));

        server_loop_coverage_check(
            coverage_ok, "backend loop covers ready-probe path MTU events without payloads",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                }),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 1,
                    .process_path_mtu_calls = 0,
                }));

        server_loop_coverage_check(coverage_ok,
                                   "backend loop propagates ready-probe path MTU update failures",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                           .process_path_mtu_calls = 1,
                                       }));

        server_loop_coverage_check(coverage_ok, "backend loop covers ready-probe idle timeouts",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 2,
                                           .pump_calls = 2,
                                       }));

        server_loop_coverage_check(
            coverage_ok,
            "backend loop covers ready-probe timer failures when wakeups are already due",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                }),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 1,
                    .process_expired_calls = 1,
                }));

        server_loop_coverage_check(
            coverage_ok,
            "backend loop ignores ready-probe timer events when wakeups are still in the future",
            server_loop_result_matches_for_tests(
                run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                }),
                ExpectedServerLoopResultForTests{
                    .wait_calls = 2,
                    .process_expired_calls = 0,
                    .pump_calls = 2,
                }));

        server_loop_coverage_check(coverage_ok, "backend loop covers ready-probe shutdown handling",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                       }));

        server_loop_coverage_check(coverage_ok, "backend loop covers main-wait timer failures",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                           .process_expired_calls = 1,
                                       }));

        server_loop_coverage_check(coverage_ok, "backend loop covers main-wait datagram failures",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                           .process_datagram_calls = 1,
                                       }));

        server_loop_coverage_check(coverage_ok,
                                   "backend loop covers main-wait path MTU events without payloads",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                           .process_path_mtu_calls = 0,
                                       }));

        server_loop_coverage_check(coverage_ok,
                                   "backend loop propagates main-wait path MTU update failures",
                                   server_loop_result_matches_for_tests(
                                       run_backend_loop_script_for_tests(BackendLoopScriptForTests{
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
                                       }),
                                       ExpectedServerLoopResultForTests{
                                           .wait_calls = 1,
                                           .process_path_mtu_calls = 1,
                                       }));

        const auto default_no_pending_work = [] { return false; };
        const auto default_accept_timer = [](QuicCoreTimePoint) { return true; };
        const auto default_accept_datagram = [](const QuicIoRxDatagram &, QuicCoreTimePoint) {
            return true;
        };
        server_loop_coverage_check(coverage_ok,
                                   "backend loop shared default callbacks remain callable",
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
            server_loop_coverage_check(
                coverage_ok, "backend loop default path MTU callback accepts updates",
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
            server_loop_coverage_check(
                coverage_ok, "backend loop default callbacks accept timer and datagram events",
                run_server_backend_loop_with_driver(default_path_mtu_driver) == 1 &
                    wait_calls == 3 & timer_calls == 1 & datagram_calls == 1);
        }
    }
}

void cover_runtime_backend_loop_entry_cases_for_tests(bool &coverage_ok) {
    {
        ClientIoContext io_context;
        io_context.primary_route_handle = 7;
        io_context.backend = std::make_unique<ScriptedIoBackendForTests>();
        QuicCore core = make_local_error_client_core_for_tests();
        EndpointDriveState state;
        state.next_wakeup = now() - std::chrono::milliseconds(1);
        ClientRuntimePolicyState policy;
        ScriptedEndpointForTests endpoint;
        server_loop_coverage_check(
            coverage_ok, "client backend loop covers expired-timer failures before waiting",
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
        EndpointDriveState drive_state;
        ServerConnectionEndpointMap connection_endpoints;
        ScriptedIoBackendForTests backend;
        QuicCore core(make_runtime_server_endpoint_config(
            Http09RuntimeConfig{
                .mode = Http09RuntimeMode::server,
                .document_root = document_root.path(),
            },
            make_runtime_tls_identity_for_tests()));
        backend.wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = now(),
        });
        server_loop_coverage_check(
            coverage_ok,
            "server backend runtime loop executes timer-expired callbacks on live cores",
            run_http09_server_backend_loop(
                Http09RuntimeConfig{
                    .mode = Http09RuntimeMode::server,
                    .document_root = document_root.path(),
                },
                core, drive_state, connection_endpoints, backend) == 1);
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        EndpointDriveState drive_state;
        ServerConnectionEndpointMap connection_endpoints;
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
            make_runtime_tls_identity_for_tests()));
        server_loop_coverage_check(
            coverage_ok, "server backend runtime loop applies path MTU callbacks on live cores",
            run_http09_server_backend_loop(
                Http09RuntimeConfig{
                    .mode = Http09RuntimeMode::server,
                    .document_root = document_root.path(),
                },
                core, drive_state, connection_endpoints, backend) == 1 &
                backend.wait_requests.size() == 2);
    }
}

bool runtime_server_loop_and_trace_coverage_for_tests() {
    bool coverage_ok = true;
    const auto peer = make_server_loopback_peer_for_tests(4443);
    const auto supported_initial = make_supported_initial_for_tests();

    ::setenv("COQUIC_RUNTIME_TRACE", "1", 1);
    cover_runtime_retry_helpers_for_tests(coverage_ok, supported_initial, peer);
    cover_runtime_trace_inputs_for_tests(coverage_ok);
    cover_runtime_connection_result_helpers_for_tests(coverage_ok, peer);
    cover_runtime_server_loop_script_cases_for_tests(coverage_ok);
    cover_runtime_backend_loop_script_cases_for_tests(coverage_ok);
    cover_runtime_backend_loop_entry_cases_for_tests(coverage_ok);
    ::unsetenv("COQUIC_RUNTIME_TRACE");
    return coverage_ok;
}

bool runtime_server_endpoint_driver_coverage_for_tests() {
    bool coverage_ok = true;
    const auto accepted_connection_or_default =
        [&](std::string_view label, const std::optional<QuicConnectionHandle> &accepted) {
            server_loop_coverage_check(coverage_ok, label, accepted.has_value());
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
        server_loop_coverage_check(
            coverage_ok,
            "failing send backend helpers return fixed route null waits and failed sends",
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

    server_loop_coverage_check(coverage_ok, "to_connection_command_input rejects inbound datagrams",
                               !to_connection_command_input(QuicCoreInboundDatagram{
                                                                .bytes =
                                                                    {
                                                                        std::byte{0x01},
                                                                    },
                                                            })
                                    .has_value());
    server_loop_coverage_check(coverage_ok,
                               "to_connection_command_input rejects shared stream payloads",
                               !to_connection_command_input(QuicCoreSendSharedStreamData{
                                                                .stream_id = 3,
                                                                .bytes =
                                                                    quic::SharedBytes{
                                                                        std::byte{0x02},
                                                                    },
                                                                .fin = true,
                                                            })
                                    .has_value());
    server_loop_coverage_check(coverage_ok, "to_connection_command_input rejects timer inputs",
                               !to_connection_command_input(QuicCoreTimerExpired{}).has_value());
    server_loop_coverage_check(coverage_ok, "to_connection_command_input preserves close commands",
                               to_connection_command_input(QuicCoreCloseConnection{
                                                               .application_error_code = 9,
                                                               .reason_phrase = "bye",
                                                           })
                                   .has_value());
    server_loop_coverage_check(
        coverage_ok, "to_connection_command_input preserves migration requests",
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
        server_loop_coverage_check(
            coverage_ok,
            "advance_endpoint_connection_inputs reports unsupported endpoint-level inputs",
            result.local_error.has_value() & (local_error.connection == QuicConnectionHandle{41}) &
                (local_error.code == QuicCoreLocalErrorCode::unsupported_operation));
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection = accepted_connection_or_default(
            "live server handshake yields an accepted connection", accepted);

        const std::array<QuicCoreInput, 1> close_inputs = {
            QuicCoreCloseConnection{},
        };
        auto close_result =
            advance_endpoint_connection_inputs(core, connection, close_inputs, now());
        server_loop_coverage_check(
            coverage_ok, "advance_endpoint_connection_inputs stops after connection close effects",
            result_has_send_effects(close_result) & close_result.next_wakeup.has_value());
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        EndpointDriveState drive_state;
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto peer = make_server_loopback_peer_for_tests(7443);
        drive_state.route_routes.emplace(kRouteHandle, RuntimeSendRoute{
                                                           .socket_fd = 77,
                                                           .peer = peer,
                                                           .peer_len = sizeof(sockaddr_in),
                                                       });
        QuicCoreTimePoint step_now = now();
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection = accepted_connection_or_default(
            "direct server-result fixture handshake succeeds", accepted);

        {
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
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
            server_loop_coverage_check(
                coverage_ok, "process_server_endpoint_core_result ignores non-stream effects",
                process_server_endpoint_core_result(core, drive_state, connection_endpoints,
                                                    document_root.path(), state_only_result,
                                                    /*fallback_socket_fd=*/77, &peer,
                                                    sizeof(sockaddr_in), &observed_send_effects) &
                    connection_endpoints.contains(connection) & !observed_send_effects);
        }

        {
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
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
            server_loop_coverage_check(
                coverage_ok,
                "process_server_endpoint_core_result erases endpoints for connection-local errors",
                process_server_endpoint_core_result(core, drive_state, connection_endpoints,
                                                    document_root.path(), local_error_result,
                                                    /*fallback_socket_fd=*/77, &peer,
                                                    sizeof(sockaddr_in)) &
                    !connection_endpoints.contains(connection));
        }

        {
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
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
            server_loop_coverage_check(
                coverage_ok, "process_server_endpoint_core_result drops closed endpoints",
                process_server_endpoint_core_result(
                    core, drive_state, connection_endpoints, document_root.path(), closed_result,
                    /*fallback_socket_fd=*/77, &peer, sizeof(sockaddr_in)) &
                    !connection_endpoints.contains(connection));
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
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
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
            server_loop_coverage_check(
                coverage_ok,
                "process_server_endpoint_core_result advances endpoint-generated stream sends",
                process_server_endpoint_core_result(
                    core, drive_state, connection_endpoints, document_root.path(), request_result,
                    /*fallback_socket_fd=*/77, &peer, sizeof(sockaddr_in), &observed_send_effects) &
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
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
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
            server_loop_coverage_check(
                coverage_ok, "process_server_endpoint_core_result closes failed endpoints",
                process_server_endpoint_core_result(core, drive_state, connection_endpoints,
                                                    document_root.path(), invalid_request_result,
                                                    /*fallback_socket_fd=*/77, &peer,
                                                    sizeof(sockaddr_in)) &
                    !connection_endpoints.contains(connection));
        }
    }

    {
        ScopedRuntimeTempDirForTests document_root;
        document_root.write_file("small.txt", "hello");
        const Http09RuntimeConfig server_config{
            .mode = Http09RuntimeMode::server,
            .document_root = document_root.path(),
        };
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        constexpr QuicRouteHandle kRouteHandle = 17;
        ScriptedIoBackendForTests backend;
        EndpointDriveState drive_state;
        QuicCoreTimePoint step_now = now();
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection = accepted_connection_or_default(
            "backend server-result fixture handshake succeeds", accepted);

        {
            ServerConnectionEndpointMap connection_endpoints;
            QuicCoreResult local_error_result;
            local_error_result.local_error = QuicCoreLocalError{
                .connection = std::nullopt,
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
            server_loop_coverage_check(
                coverage_ok,
                "process_server_endpoint_core_result_with_backend rejects transport-wide local "
                "errors",
                !process_server_endpoint_core_result_with_backend(
                    core, drive_state, connection_endpoints, document_root.path(),
                    local_error_result, kRouteHandle, backend));
        }

        {
            ServerConnectionEndpointMap connection_endpoints;
            QuicCoreResult missing_endpoint_result;
            missing_endpoint_result.effects.emplace_back(QuicCoreStateEvent{
                .connection = connection,
                .change = QuicCoreStateChange::handshake_ready,
            });
            server_loop_coverage_check(
                coverage_ok,
                "process_server_endpoint_core_result_with_backend tolerates missing endpoints",
                process_server_endpoint_core_result_with_backend(
                    core, drive_state, connection_endpoints, document_root.path(),
                    missing_endpoint_result, kRouteHandle, backend));
        }

        {
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
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
            server_loop_coverage_check(
                coverage_ok,
                "process_server_endpoint_core_result_with_backend removes closed endpoints",
                process_server_endpoint_core_result_with_backend(
                    core, drive_state, connection_endpoints, document_root.path(), closed_result,
                    kRouteHandle, backend) &
                    !connection_endpoints.contains(connection));
        }

        {
            backend.sent_datagrams.clear();
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
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
            server_loop_coverage_check(
                coverage_ok,
                "process_server_endpoint_core_result_with_backend routes generated sends through "
                "the backend",
                process_server_endpoint_core_result_with_backend(
                    core, drive_state, connection_endpoints, document_root.path(), request_result,
                    kRouteHandle, backend) &
                    !backend.sent_datagrams.empty());
        }

        {
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
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
            server_loop_coverage_check(
                coverage_ok,
                "process_server_endpoint_core_result_with_backend closes failed endpoints",
                process_server_endpoint_core_result_with_backend(
                    core, drive_state, connection_endpoints, document_root.path(),
                    invalid_request_result, kRouteHandle, backend) &
                    !connection_endpoints.contains(connection));
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
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        EndpointDriveState drive_state;
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto peer = make_server_loopback_peer_for_tests(7555);
        drive_state.route_routes.emplace(kRouteHandle, RuntimeSendRoute{
                                                           .socket_fd = 79,
                                                           .peer = peer,
                                                           .peer_len = sizeof(sockaddr_in),
                                                       });
        QuicCoreTimePoint step_now = now();
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection = accepted_connection_or_default(
            "server-endpoint pump fixture handshake succeeds", accepted);

        {
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
                                .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                    .document_root = document_root.path(),
                                }),
                                .has_pending_work = true,
                            });
            bool made_progress = true;
            server_loop_coverage_check(
                coverage_ok,
                "pump_shared_server_endpoint_work clears stale pending flags without work",
                pump_shared_server_endpoint_work(core, drive_state, connection_endpoints,
                                                 document_root.path(), made_progress) &
                    !made_progress & connection_endpoints.contains(connection) &
                    !connection_endpoints.at(connection).has_pending_work);
        }

        {
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
                                .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                    .document_root = document_root.path(),
                                }),
                                .has_pending_work = false,
                            });
            bool made_progress = true;
            server_loop_coverage_check(
                coverage_ok,
                "pump_shared_server_endpoint_work ignores endpoints without pending work",
                pump_shared_server_endpoint_work(core, drive_state, connection_endpoints,
                                                 document_root.path(), made_progress) &
                    !made_progress & connection_endpoints.contains(connection));
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
            auto initial_update = endpoint.on_core_result(
                single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(connection,
                                         ServerConnectionEndpointState{
                                             .endpoint = std::move(endpoint),
                                             .has_pending_work = initial_update.has_pending_work,
                                         });
            bool made_progress = false;
            server_loop_coverage_check(
                coverage_ok, "pump_shared_server_endpoint_work advances queued response chunks",
                pump_shared_server_endpoint_work(core, drive_state, connection_endpoints,
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
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(connection, ServerConnectionEndpointState{
                                                         .endpoint = std::move(endpoint),
                                                         .has_pending_work = true,
                                                     });
            bool made_progress = false;
            server_loop_coverage_check(
                coverage_ok, "pump_shared_server_endpoint_work closes endpoints whose polls fail",
                pump_shared_server_endpoint_work(core, drive_state, connection_endpoints,
                                                 document_root.path(), made_progress) &
                    !connection_endpoints.contains(connection));
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
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        ScriptedIoBackendForTests backend;
        EndpointDriveState drive_state;
        constexpr QuicRouteHandle kRouteHandle = 17;
        QuicCoreTimePoint step_now = now();
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection =
            accepted_connection_or_default("backend pump fixture handshake succeeds", accepted);

        {
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(
                connection, ServerConnectionEndpointState{
                                .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                    .document_root = document_root.path(),
                                }),
                                .has_pending_work = true,
                            });
            bool made_progress = true;
            server_loop_coverage_check(
                coverage_ok,
                "pump_shared_server_endpoint_work_with_backend clears stale pending flags "
                "without work",
                pump_shared_server_endpoint_work_with_backend(
                    core, drive_state, connection_endpoints, document_root.path(), backend,
                    made_progress) &
                    !made_progress & connection_endpoints.contains(connection) &
                    !connection_endpoints.at(connection).has_pending_work);
        }

        {
            backend.sent_datagrams.clear();
            QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
                .document_root = document_root.path(),
            });
            auto initial_update = endpoint.on_core_result(
                single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(connection,
                                         ServerConnectionEndpointState{
                                             .endpoint = std::move(endpoint),
                                             .has_pending_work = initial_update.has_pending_work,
                                         });
            bool made_progress = false;
            server_loop_coverage_check(
                coverage_ok,
                "pump_shared_server_endpoint_work_with_backend advances queued response chunks",
                pump_shared_server_endpoint_work_with_backend(
                    core, drive_state, connection_endpoints, document_root.path(), backend,
                    made_progress) &
                    made_progress & !backend.sent_datagrams.empty());
        }

        {
            QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
                .document_root = document_root.path(),
            });
            static_cast<void>(endpoint.on_core_result(
                single_receive_result_for_runtime_tests(0, "", true), now()));
            ServerConnectionEndpointMap connection_endpoints;
            connection_endpoints.emplace(connection, ServerConnectionEndpointState{
                                                         .endpoint = std::move(endpoint),
                                                         .has_pending_work = true,
                                                     });
            bool made_progress = false;
            server_loop_coverage_check(
                coverage_ok,
                "pump_shared_server_endpoint_work_with_backend closes endpoints whose polls fail",
                pump_shared_server_endpoint_work_with_backend(
                    core, drive_state, connection_endpoints, document_root.path(), backend,
                    made_progress) &
                    !connection_endpoints.contains(connection));
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
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection = accepted_connection_or_default(
            "server-endpoint route-failure fixture handshake succeeds", accepted);
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        auto initial_update = endpoint.on_core_result(
            single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
        ServerConnectionEndpointMap connection_endpoints;
        connection_endpoints.emplace(connection,
                                     ServerConnectionEndpointState{
                                         .endpoint = std::move(endpoint),
                                         .has_pending_work = initial_update.has_pending_work,
                                     });
        EndpointDriveState drive_state;
        bool made_progress = false;
        server_loop_coverage_check(
            coverage_ok,
            "pump_shared_server_endpoint_work fails when pending connection inputs cannot be "
            "routed",
            !pump_shared_server_endpoint_work(core, drive_state, connection_endpoints,
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
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection = accepted_connection_or_default(
            "server-endpoint close-route-failure fixture handshake succeeds", accepted);
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        static_cast<void>(
            endpoint.on_core_result(single_receive_result_for_runtime_tests(0, "", true), now()));
        ServerConnectionEndpointMap connection_endpoints;
        connection_endpoints.emplace(connection, ServerConnectionEndpointState{
                                                     .endpoint = std::move(endpoint),
                                                     .has_pending_work = true,
                                                 });
        EndpointDriveState drive_state;
        bool made_progress = false;
        server_loop_coverage_check(
            coverage_ok,
            "pump_shared_server_endpoint_work fails when close effects cannot be routed after "
            "poll failure",
            !pump_shared_server_endpoint_work(core, drive_state, connection_endpoints,
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
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection = accepted_connection_or_default(
            "backend send-failure fixture handshake succeeds", accepted);
        FailingSendBackendForTests failing_backend;
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        auto initial_update = endpoint.on_core_result(
            single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
        ServerConnectionEndpointMap connection_endpoints;
        connection_endpoints.emplace(connection,
                                     ServerConnectionEndpointState{
                                         .endpoint = std::move(endpoint),
                                         .has_pending_work = initial_update.has_pending_work,
                                     });
        EndpointDriveState drive_state;
        bool made_progress = false;
        server_loop_coverage_check(
            coverage_ok,
            "pump_shared_server_endpoint_work_with_backend fails when the backend rejects queued "
            "response sends",
            !pump_shared_server_endpoint_work_with_backend(core, drive_state, connection_endpoints,
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
        QuicCore core(make_runtime_server_endpoint_config(server_config,
                                                          make_runtime_tls_identity_for_tests()));
        QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
        }));
        QuicCoreTimePoint step_now = now();
        constexpr QuicRouteHandle kRouteHandle = 17;
        const auto accepted =
            drive_live_server_endpoint_handshake_for_tests(client, kRouteHandle, core, step_now);
        auto connection = accepted_connection_or_default(
            "backend close-send-failure fixture handshake succeeds", accepted);
        FailingSendBackendForTests failing_backend;
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        static_cast<void>(
            endpoint.on_core_result(single_receive_result_for_runtime_tests(0, "", true), now()));
        ServerConnectionEndpointMap connection_endpoints;
        connection_endpoints.emplace(connection, ServerConnectionEndpointState{
                                                     .endpoint = std::move(endpoint),
                                                     .has_pending_work = true,
                                                 });
        EndpointDriveState drive_state;
        bool made_progress = false;
        server_loop_coverage_check(
            coverage_ok,
            "pump_shared_server_endpoint_work_with_backend fails when the backend rejects close "
            "sends after poll failure",
            !pump_shared_server_endpoint_work_with_backend(core, drive_state, connection_endpoints,
                                                           document_root.path(), failing_backend,
                                                           made_progress));
    }

    {
        g_recorded_recvmsg_for_tests = {};
        g_recorded_recvmsg_for_tests.bytes = {
            std::byte{0x51},
        };
        g_recorded_recvmsg_for_tests.peer = make_server_loopback_peer_for_tests(7666);
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
        auto receive_input = receive.step.input.value_or(QuicCoreInput{QuicCoreInboundDatagram{}});
        const auto &inbound = std::get<QuicCoreInboundDatagram>(receive_input);
        auto wait_step = wait.value_or(RuntimeWaitStep{});
        auto wait_input = wait_step.input.value_or(QuicCoreInput{QuicCoreInboundDatagram{}});
        server_loop_coverage_check(
            coverage_ok, "make_runtime_server_loop_io forwards to runtime wait and receive helpers",
            (current.time_since_epoch().count() > 0) &
                (receive.status == ReceiveDatagramStatus::ok) &
                (inbound.bytes == g_recorded_recvmsg_for_tests.bytes) & wait.has_value() &
                wait_step.input.has_value() &
                std::holds_alternative<QuicCoreTimerExpired>(wait_input));
    }

    return coverage_ok;
}

} // namespace test

#if defined(__clang__)
#pragma clang attribute pop
#endif

} // namespace coquic::http09
