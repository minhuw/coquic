#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicHttp09RuntimeTest, ClientConnectionFailsWhenSocketCreationFailsAfterRemoteDerivation) {
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.socket_fn = &fail_socket},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://127.0.0.1:9443/a.txt",
         .authority = "127.0.0.1:9443",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, requests, 1), 1);
}

TEST(QuicHttp09RuntimeTest, ClientConnectionFreesResolverResultsWhenResolutionFails) {
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .getaddrinfo_fn = &fail_getaddrinfo_with_results,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenInitialSendFails) {
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.sendto_fn = &fail_sendto},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenPollErrors) {
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.poll_fn = &fail_poll},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenSocketBecomesUnreadable) {
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.poll_fn = &unreadable_poll},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenRecvfromFailsAfterReadablePoll) {
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .poll_fn = &readable_poll,
            .recvfrom_fn = &fail_recvfrom,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ServerContinuesAfterIdlePollTimeoutThenFailsOnPollError) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const ScopedTimeoutThenErrorPollReset poll_reset;
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.poll_fn = &timeout_then_error_poll},
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperExtendsClientReceiveTimeoutForMulticonnect) {
    const auto transfer = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
    };
    const auto multiconnect = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::multiconnect,
    };

    EXPECT_EQ(coquic::quic::test::client_receive_timeout_ms_for_tests(transfer), 30000);
    EXPECT_EQ(coquic::quic::test::client_receive_timeout_ms_for_tests(multiconnect), 180000);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperReturnsIdleTimeoutWithoutWakeup) {
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.poll_fn = &timeout_poll},
    };

    const auto step = coquic::quic::test::wait_for_socket_or_deadline_for_tests(
        /*socket_fd=*/-1, /*idle_timeout_ms=*/5, "client", std::nullopt);

    ASSERT_TRUE(step.has_value());
    const auto &wait_step = optional_ref_or_terminate(step);
    EXPECT_TRUE(wait_step.idle_timeout);
    EXPECT_FALSE(wait_step.has_input);
    EXPECT_FALSE(wait_step.has_source);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperReturnsTimerInputWhenWakeupIsDue) {
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {.poll_fn = &timeout_poll},
    };

    const auto step = coquic::quic::test::wait_for_socket_or_deadline_for_tests(
        /*socket_fd=*/-1, /*idle_timeout_ms=*/50, "client", runtime_now());

    ASSERT_TRUE(step.has_value());
    const auto &wait_step = optional_ref_or_terminate(step);
    EXPECT_FALSE(wait_step.idle_timeout);
    EXPECT_TRUE(wait_step.has_input);
    EXPECT_TRUE(wait_step.input_is_timer_expired);
    EXPECT_FALSE(wait_step.has_source);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksSelectEarliestWakeupAcrossEntries) {
    const auto base = runtime_now();
    const std::array<std::optional<coquic::quic::QuicCoreTimePoint>, 4> wakeups = {
        std::nullopt,
        base + std::chrono::milliseconds(30),
        base + std::chrono::milliseconds(5),
        base + std::chrono::milliseconds(15),
    };

    const auto earliest = coquic::quic::test::earliest_runtime_wakeup_for_tests(wakeups);
    ASSERT_TRUE(earliest.has_value());
    EXPECT_EQ(optional_value_or_terminate(earliest), optional_value_or_terminate(wakeups[2]));

    const std::array<std::optional<coquic::quic::QuicCoreTimePoint>, 2> empty_wakeups = {
        std::nullopt,
        std::nullopt,
    };
    EXPECT_FALSE(coquic::quic::test::earliest_runtime_wakeup_for_tests(empty_wakeups).has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksDriveEndpointUntilBlockedFailureCases) {
    const auto handle_core_effects_fail =
        coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
            coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::handle_core_effects_fail);
    EXPECT_FALSE(handle_core_effects_fail.returned);
    EXPECT_TRUE(handle_core_effects_fail.terminal_failure);
    EXPECT_FALSE(handle_core_effects_fail.terminal_success);

    const auto initial_local_error =
        coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
            coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::initial_local_error);
    EXPECT_FALSE(initial_local_error.returned);
    EXPECT_TRUE(initial_local_error.terminal_failure);
    EXPECT_FALSE(initial_local_error.terminal_success);

    const auto initial_local_error_handled =
        coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
            coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::initial_local_error_handled);
    EXPECT_TRUE(initial_local_error_handled.returned);
    EXPECT_FALSE(initial_local_error_handled.terminal_failure);
    EXPECT_FALSE(initial_local_error_handled.terminal_success);

    const auto endpoint_failure = coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
        coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::endpoint_failure);
    EXPECT_FALSE(endpoint_failure.returned);
    EXPECT_TRUE(endpoint_failure.terminal_failure);
    EXPECT_FALSE(endpoint_failure.terminal_success);

    const auto endpoint_inputs_then_core_error =
        coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
            coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::
                endpoint_inputs_then_core_error);
    EXPECT_FALSE(endpoint_inputs_then_core_error.returned);
    EXPECT_TRUE(endpoint_inputs_then_core_error.terminal_failure);
    EXPECT_FALSE(endpoint_inputs_then_core_error.terminal_success);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksDriveEndpointUntilBlockedSuccessCase) {
    const auto success = coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
        coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::endpoint_success);
    EXPECT_TRUE(success.returned);
    EXPECT_TRUE(success.terminal_success);
    EXPECT_FALSE(success.terminal_failure);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksDriveClientConnectionLoopCases) {
    const auto initial_terminal_success =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::initial_terminal_success);
    EXPECT_EQ(initial_terminal_success.exit_code, 0);
    EXPECT_TRUE(initial_terminal_success.terminal_success);
    EXPECT_FALSE(initial_terminal_success.terminal_failure);

    const auto timer_due_then_wait_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::timer_due_then_wait_failure);
    EXPECT_EQ(timer_due_then_wait_failure.exit_code, 1);
    EXPECT_FALSE(timer_due_then_wait_failure.terminal_success);
    EXPECT_FALSE(timer_due_then_wait_failure.terminal_failure);

    const auto timer_due_then_drive_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::timer_due_then_drive_failure);
    EXPECT_EQ(timer_due_then_drive_failure.exit_code, 1);
    EXPECT_TRUE(timer_due_then_drive_failure.terminal_failure);

    const auto outer_timer_then_wait_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::outer_timer_then_wait_failure);
    EXPECT_EQ(outer_timer_then_wait_failure.exit_code, 1);
    EXPECT_FALSE(outer_timer_then_wait_failure.terminal_failure);

    const auto outer_timer_then_drive_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::outer_timer_then_drive_failure);
    EXPECT_EQ(outer_timer_then_drive_failure.exit_code, 1);
    EXPECT_TRUE(outer_timer_then_drive_failure.terminal_failure);

    const auto pending_work_terminal_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::pending_work_terminal_failure);
    EXPECT_EQ(pending_work_terminal_failure.exit_code, 1);
    EXPECT_TRUE(pending_work_terminal_failure.terminal_failure);

    const auto pending_work_default_poll_then_wait_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                pending_work_default_poll_then_wait_failure);
    EXPECT_EQ(pending_work_default_poll_then_wait_failure.exit_code, 1);
    EXPECT_FALSE(pending_work_default_poll_then_wait_failure.terminal_failure);

    const auto pending_work_no_inputs_then_idle_timeout =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                pending_work_no_inputs_then_idle_timeout);
    EXPECT_EQ(pending_work_no_inputs_then_idle_timeout.exit_code, 1);
    EXPECT_FALSE(pending_work_no_inputs_then_idle_timeout.terminal_success);
    EXPECT_FALSE(pending_work_no_inputs_then_idle_timeout.terminal_failure);

    const auto receive_error_after_nonblocking_drain =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                receive_error_after_nonblocking_drain);
    EXPECT_EQ(receive_error_after_nonblocking_drain.exit_code, 1);

    const auto receive_input_then_drive_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::receive_input_then_drive_failure);
    EXPECT_EQ(receive_input_then_drive_failure.exit_code, 1);
    EXPECT_TRUE(receive_input_then_drive_failure.terminal_failure);

    const auto wait_failure = coquic::quic::test::run_client_connection_loop_case_for_tests(
        coquic::quic::test::ClientConnectionLoopCaseForTests::wait_failure);
    EXPECT_EQ(wait_failure.exit_code, 1);
    EXPECT_FALSE(wait_failure.terminal_success);
    EXPECT_FALSE(wait_failure.terminal_failure);

    const auto outer_pump_terminal_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::outer_pump_terminal_failure);
    EXPECT_EQ(outer_pump_terminal_failure.exit_code, 1);
    EXPECT_TRUE(outer_pump_terminal_failure.terminal_failure);

    const auto outer_pump_terminal_success =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::outer_pump_terminal_success);
    EXPECT_EQ(outer_pump_terminal_success.exit_code, 0);
    EXPECT_TRUE(outer_pump_terminal_success.terminal_success);

    const auto wait_input_then_terminal_success =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::wait_input_then_terminal_success);
    EXPECT_EQ(wait_input_then_terminal_success.exit_code, 0);
    EXPECT_TRUE(wait_input_then_terminal_success.terminal_success);
    EXPECT_FALSE(wait_input_then_terminal_success.terminal_failure);

    const auto wait_input_then_terminal_success_with_followup_input =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                wait_input_then_terminal_success_with_followup_input);
    EXPECT_EQ(wait_input_then_terminal_success_with_followup_input.exit_code, 0);
    EXPECT_TRUE(wait_input_then_terminal_success_with_followup_input.terminal_success);
    EXPECT_FALSE(wait_input_then_terminal_success_with_followup_input.terminal_failure);
    EXPECT_GE(wait_input_then_terminal_success_with_followup_input.wait_calls, 2u);

    const auto wait_input_then_drive_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::wait_input_then_drive_failure);
    EXPECT_EQ(wait_input_then_drive_failure.exit_code, 1);
    EXPECT_TRUE(wait_input_then_drive_failure.terminal_failure);

    const auto wait_input_missing_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::wait_input_missing_failure);
    EXPECT_EQ(wait_input_missing_failure.exit_code, 1);
    EXPECT_FALSE(wait_input_missing_failure.terminal_success);
    EXPECT_FALSE(wait_input_missing_failure.terminal_failure);

    const auto peer_input_then_outer_pump_terminal_success =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                peer_input_then_outer_pump_terminal_success);
    EXPECT_EQ(peer_input_then_outer_pump_terminal_success.exit_code, 0);
    EXPECT_TRUE(peer_input_then_outer_pump_terminal_success.terminal_success);
    EXPECT_GE(peer_input_then_outer_pump_terminal_success.current_time_calls, 4u);

    const auto wait_input_then_terminal_success_exits_after_drain_window =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                wait_input_then_terminal_success_exits_after_drain_window);
    EXPECT_EQ(wait_input_then_terminal_success_exits_after_drain_window.exit_code, 0);
    EXPECT_TRUE(wait_input_then_terminal_success_exits_after_drain_window.terminal_success);

    const auto nonblocking_drain_repeats_pending_endpoint_progress =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                nonblocking_drain_repeats_pending_endpoint_progress);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.exit_code, 0);
    EXPECT_TRUE(nonblocking_drain_repeats_pending_endpoint_progress.terminal_success);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.wait_calls, 0u);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.receive_calls, 2u);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksDriveClientConnectionBackendLoopCases) {
    const auto initial_terminal_success =
        coquic::quic::test::run_client_connection_backend_loop_case_for_tests(
            coquic::quic::test::ClientConnectionBackendLoopCaseForTests::initial_terminal_success);
    EXPECT_EQ(initial_terminal_success.exit_code, 0);
    EXPECT_TRUE(initial_terminal_success.terminal_success);
    EXPECT_FALSE(initial_terminal_success.terminal_failure);
    EXPECT_EQ(initial_terminal_success.wait_calls, 0U);

    const auto wait_failure = coquic::quic::test::run_client_connection_backend_loop_case_for_tests(
        coquic::quic::test::ClientConnectionBackendLoopCaseForTests::wait_failure);
    EXPECT_EQ(wait_failure.exit_code, 1);
    EXPECT_FALSE(wait_failure.terminal_success);
    EXPECT_FALSE(wait_failure.terminal_failure);
    EXPECT_EQ(wait_failure.wait_calls, 1U);

    const auto idle_timeout = coquic::quic::test::run_client_connection_backend_loop_case_for_tests(
        coquic::quic::test::ClientConnectionBackendLoopCaseForTests::idle_timeout);
    EXPECT_EQ(idle_timeout.exit_code, 1);
    EXPECT_FALSE(idle_timeout.terminal_success);
    EXPECT_FALSE(idle_timeout.terminal_failure);
    EXPECT_EQ(idle_timeout.wait_calls, 1U);

    const auto shutdown = coquic::quic::test::run_client_connection_backend_loop_case_for_tests(
        coquic::quic::test::ClientConnectionBackendLoopCaseForTests::shutdown);
    EXPECT_EQ(shutdown.exit_code, 1);
    EXPECT_FALSE(shutdown.terminal_success);
    EXPECT_FALSE(shutdown.terminal_failure);
    EXPECT_EQ(shutdown.wait_calls, 1U);

    const auto missing_rx_datagram =
        coquic::quic::test::run_client_connection_backend_loop_case_for_tests(
            coquic::quic::test::ClientConnectionBackendLoopCaseForTests::missing_rx_datagram);
    EXPECT_EQ(missing_rx_datagram.exit_code, 1);
    EXPECT_FALSE(missing_rx_datagram.terminal_success);
    EXPECT_FALSE(missing_rx_datagram.terminal_failure);
    EXPECT_EQ(missing_rx_datagram.wait_calls, 1U);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksCoverServerFailureCleanupAndLoopCases) {
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "trace");
        EXPECT_TRUE(coquic::quic::test::existing_server_session_failure_cleans_up_for_tests());
    }

    EXPECT_TRUE(coquic::quic::test::existing_server_session_failure_cleans_up_for_tests());
    EXPECT_TRUE(coquic::quic::test::existing_server_session_missing_input_fails_for_tests());
    EXPECT_TRUE(coquic::quic::test::expired_server_timer_failure_cleans_up_for_tests());
    EXPECT_TRUE(coquic::quic::test::expired_server_timer_success_preserves_session_for_tests());
    EXPECT_TRUE(coquic::quic::test::pending_server_work_failure_cleans_up_for_tests());
    EXPECT_TRUE(
        coquic::quic::test::version_negotiation_without_source_connection_id_fails_for_tests());

    const auto nonblocking_processed_timers_then_receive_error =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                nonblocking_processed_timers_then_receive_error);
    EXPECT_EQ(nonblocking_processed_timers_then_receive_error.exit_code, 1);
    EXPECT_EQ(nonblocking_processed_timers_then_receive_error.receive_calls, 1U);
    EXPECT_EQ(nonblocking_processed_timers_then_receive_error.wait_calls, 0U);
    EXPECT_EQ(nonblocking_processed_timers_then_receive_error.process_expired_calls, 2U);

    const auto nonblocking_process_datagram_failure =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::nonblocking_process_datagram_failure);
    EXPECT_EQ(nonblocking_process_datagram_failure.exit_code, 1);
    EXPECT_EQ(nonblocking_process_datagram_failure.receive_calls, 1U);
    EXPECT_EQ(nonblocking_process_datagram_failure.wait_calls, 0U);
    EXPECT_EQ(nonblocking_process_datagram_failure.process_expired_calls, 1U);

    const auto blocking_timer_then_receive_error =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::blocking_timer_then_receive_error);
    EXPECT_EQ(blocking_timer_then_receive_error.exit_code, 1);
    EXPECT_EQ(blocking_timer_then_receive_error.receive_calls, 2U);
    EXPECT_EQ(blocking_timer_then_receive_error.wait_calls, 1U);
    EXPECT_EQ(blocking_timer_then_receive_error.process_expired_calls, 4U);

    const auto blocking_processed_timers_then_receive_error =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                blocking_processed_timers_then_receive_error);
    EXPECT_EQ(blocking_processed_timers_then_receive_error.exit_code, 1);
    EXPECT_EQ(blocking_processed_timers_then_receive_error.receive_calls, 2U);
    EXPECT_EQ(blocking_processed_timers_then_receive_error.wait_calls, 0U);
    EXPECT_EQ(blocking_processed_timers_then_receive_error.process_expired_calls, 3U);

    const auto blocking_wait_failure = coquic::quic::test::run_server_loop_case_for_tests(
        coquic::quic::test::ServerLoopCaseForTests::blocking_wait_failure);
    EXPECT_EQ(blocking_wait_failure.exit_code, 1);
    EXPECT_EQ(blocking_wait_failure.receive_calls, 1U);
    EXPECT_EQ(blocking_wait_failure.wait_calls, 1U);
    EXPECT_EQ(blocking_wait_failure.process_expired_calls, 2U);

    const auto blocking_wait_missing_input = coquic::quic::test::run_server_loop_case_for_tests(
        coquic::quic::test::ServerLoopCaseForTests::blocking_wait_missing_input);
    EXPECT_EQ(blocking_wait_missing_input.exit_code, 1);
    EXPECT_EQ(blocking_wait_missing_input.receive_calls, 1U);
    EXPECT_EQ(blocking_wait_missing_input.wait_calls, 1U);
    EXPECT_EQ(blocking_wait_missing_input.process_expired_calls, 2U);

    const auto nonblocking_drain_repeats_pending_endpoint_progress =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                nonblocking_drain_repeats_pending_endpoint_progress);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.exit_code, 1);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.receive_calls, 3U);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.wait_calls, 0U);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.pump_calls, 2U);

    const auto outer_pump_repeats_pending_endpoint_progress =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                outer_pump_repeats_pending_endpoint_progress);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.exit_code, 1);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.receive_calls, 2U);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.wait_calls, 0U);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.process_expired_calls, 3U);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.pump_calls, 2U);

    const auto ready_datagram_preempts_next_pending_work_pump =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                ready_datagram_preempts_next_pending_work_pump);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.exit_code, 1);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.receive_calls, 2U);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.wait_calls, 0U);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.process_expired_calls, 2U);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.pump_calls, 1U);

    const auto pending_endpoint_without_transport_progress_waits_instead_of_spinning =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                pending_endpoint_without_transport_progress_waits_instead_of_spinning);
    EXPECT_EQ(pending_endpoint_without_transport_progress_waits_instead_of_spinning.exit_code, 1);
    EXPECT_EQ(pending_endpoint_without_transport_progress_waits_instead_of_spinning.receive_calls,
              1U);
    EXPECT_EQ(pending_endpoint_without_transport_progress_waits_instead_of_spinning.wait_calls, 1U);
    EXPECT_EQ(pending_endpoint_without_transport_progress_waits_instead_of_spinning.pump_calls, 2U);
}

TEST(QuicHttp09RuntimeTest, RuntimeServerRouteHandlesAreStablePerPeerTuple) {
    EXPECT_TRUE(
        coquic::quic::test::runtime_server_route_handles_are_stable_per_peer_tuple_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeUsesRouteHandleForServerSendEffects) {
    EXPECT_TRUE(coquic::quic::test::runtime_server_send_effect_uses_route_handle_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeLowLevelHooksExerciseSocketAndEcnFallbacks) {
    testing::internal::CaptureStderr();
    const bool covered = coquic::quic::test::runtime_low_level_socket_and_ecn_coverage_for_tests();
    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_TRUE(covered) << stderr_output;
}

TEST(QuicHttp09RuntimeTest, RuntimeTraceHooksCoverIdleTimeoutAndServerFailureBranches) {
    ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");

    testing::internal::CaptureStderr();

    const auto future_wakeup_idle_timeout =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                idle_timeout_with_future_wakeup_trace);
    EXPECT_EQ(future_wakeup_idle_timeout.exit_code, 1);

    const auto elapsed_wakeup_idle_timeout =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                idle_timeout_with_elapsed_wakeup_trace);
    EXPECT_EQ(elapsed_wakeup_idle_timeout.exit_code, 1);

    EXPECT_TRUE(coquic::quic::test::expired_server_timer_failure_cleans_up_for_tests());
    EXPECT_TRUE(coquic::quic::test::pending_server_work_failure_cleans_up_for_tests());

    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_NE(stderr_output.find("http09-client trace: idle-timeout"), std::string::npos);
    EXPECT_NE(stderr_output.find("has_next_wakeup=1"), std::string::npos);
    EXPECT_NE(stderr_output.find("next_wakeup_delta_ms=5"), std::string::npos);
    EXPECT_NE(stderr_output.find("next_wakeup_delta_ms=2"), std::string::npos);
    EXPECT_NE(stderr_output.find("http09-server trace: timer-session-failed"), std::string::npos);
    EXPECT_NE(stderr_output.find("http09-server trace: pending-work-session-failed"),
              std::string::npos);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperFailsWhenReadableSocketRecvfromFails) {
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .poll_fn = &readable_poll,
            .recvfrom_fn = &fail_recvfrom,
        },
    };

    EXPECT_FALSE(coquic::quic::test::wait_for_socket_or_deadline_for_tests(
                     /*socket_fd=*/-1, /*idle_timeout_ms=*/5, "client", std::nullopt)
                     .has_value());
}

TEST(QuicHttp09RuntimeTest,
     RuntimeWaitHelperRetriesRecvfromAfterEintrThenTreatsEwouldblockAsNoStep) {
    g_eintr_then_ewouldblock_recvfrom_calls = 0;
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .poll_fn = &readable_poll,
            .recvfrom_fn = &eintr_then_ewouldblock_recvfrom,
        },
    };

    EXPECT_FALSE(coquic::quic::test::wait_for_socket_or_deadline_for_tests(
                     /*socket_fd=*/-1, /*idle_timeout_ms=*/5, "client", std::nullopt)
                     .has_value());
    EXPECT_EQ(g_eintr_then_ewouldblock_recvfrom_calls, 2);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperRetriesPollAfterEintrBeforeIdleTimeout) {
    g_eintr_then_timeout_poll_calls = 0;
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        {
            .poll_fn = &eintr_then_timeout_poll,
        },
    };

    const auto step = coquic::quic::test::wait_for_socket_or_deadline_for_tests(
        /*socket_fd=*/-1, /*idle_timeout_ms=*/5, "client", std::nullopt);
    ASSERT_TRUE(step.has_value());
    EXPECT_TRUE(optional_ref_or_terminate(step).idle_timeout);
    EXPECT_EQ(g_eintr_then_timeout_poll_calls, 2);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperReceivesInboundDatagram) {
    const int receiver_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(receiver_fd, 0);
    ScopedFd receiver_socket(receiver_fd);

    sockaddr_in receiver_address{};
    receiver_address.sin_family = AF_INET;
    receiver_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    receiver_address.sin_port = htons(0);
    ASSERT_EQ(::bind(receiver_socket.get(), reinterpret_cast<const sockaddr *>(&receiver_address),
                     sizeof(receiver_address)),
              0);

    sockaddr_in bound_address{};
    socklen_t bound_length = sizeof(bound_address);
    ASSERT_EQ(::getsockname(receiver_socket.get(), reinterpret_cast<sockaddr *>(&bound_address),
                            &bound_length),
              0);

    const int sender_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender_fd, 0);
    ScopedFd sender_socket(sender_fd);

    const std::array<std::byte, 3> datagram = {
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
    };
    ASSERT_GE(::sendto(sender_socket.get(), datagram.data(), datagram.size(), 0,
                       reinterpret_cast<const sockaddr *>(&bound_address), sizeof(bound_address)),
              0);

    const auto step = coquic::quic::test::wait_for_socket_or_deadline_for_tests(
        receiver_socket.get(), /*idle_timeout_ms=*/100, "client", std::nullopt);

    ASSERT_TRUE(step.has_value());
    const auto &wait_step = optional_ref_or_terminate(step);
    EXPECT_FALSE(wait_step.idle_timeout);
    EXPECT_TRUE(wait_step.has_input);
    EXPECT_FALSE(wait_step.input_is_timer_expired);
    EXPECT_TRUE(wait_step.has_source);
    EXPECT_EQ(wait_step.inbound_datagram_bytes, datagram.size());
    EXPECT_GT(wait_step.source_len, 0u);
}

} // namespace
