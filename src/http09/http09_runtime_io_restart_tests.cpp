#include "src/http09/http09_runtime_test_support.h"

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace coquic::http09 {

namespace test {

namespace {

bool runtime_io_restart_coverage_check(bool &ok, std::string_view label, bool condition) {
    if (!condition) {
        std::cerr << "http09 runtime io/restart coverage failed: " << label << '\n';
        ok = false;
    }
    return condition;
}

} // namespace

bool runtime_wait_and_receive_coverage_for_tests() {
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

    bool coverage_ok = true;
    const auto make_loopback_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &loopback_ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        loopback_ipv4.sin_family = AF_INET;
        loopback_ipv4.sin_port = htons(port);
        loopback_ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };

    {
        g_recorded_recvmsg_for_tests = {};
        g_recorded_recvmsg_for_tests.ecn = QuicEcnCodepoint::ect0;
        g_recorded_recvmsg_for_tests.bytes = {
            std::byte{0x10},
            std::byte{0x20},
            std::byte{0x30},
        };
        g_recorded_recvmsg_for_tests.peer = make_loopback_peer(6123);
        g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);

        const ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .recvmsg_fn = &record_recvmsg_for_tests,
            },
        };

        const auto received = receive_datagram(/*socket_fd=*/47, "client", /*flags=*/0);
        const auto wrapped = receive_runtime_client_datagram(
            /*context=*/nullptr, /*socket_fd=*/48, MSG_DONTWAIT, "client");

        const auto *received_inbound =
            received.step.input.has_value()
                ? std::get_if<QuicCoreInboundDatagram>(&*received.step.input)
                : nullptr;
        const auto *wrapped_inbound =
            wrapped.step.input.has_value()
                ? std::get_if<QuicCoreInboundDatagram>(&*wrapped.step.input)
                : nullptr;

        runtime_io_restart_coverage_check(
            coverage_ok, "receive_datagram returns inbound bytes with trace enabled",
            received.status == ReceiveDatagramStatus::ok && received.step.has_source &&
                received.step.source_len == sizeof(sockaddr_in) && received_inbound != nullptr &&
                received_inbound->bytes == g_recorded_recvmsg_for_tests.bytes &&
                received_inbound->ecn == QuicEcnCodepoint::ect0);
        runtime_io_restart_coverage_check(
            coverage_ok, "receive_runtime_client_datagram forwards to receive_datagram",
            wrapped.status == ReceiveDatagramStatus::ok && wrapped.step.has_source &&
                wrapped.step.source_len == sizeof(sockaddr_in) && wrapped_inbound != nullptr &&
                wrapped_inbound->bytes == g_recorded_recvmsg_for_tests.bytes);
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *, nfds_t, int) -> int { return 0; },
            },
        };
        const auto step = wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fds = {51, -1},
                .socket_fd_count = 1,
                .idle_timeout_ms = 250,
                .role_name = "client",
            },
            now() + std::chrono::milliseconds(250));
        runtime_io_restart_coverage_check(
            coverage_ok, "wait turns future wakeups into timer inputs",
            step.has_value() && step->input.has_value() &&
                std::holds_alternative<QuicCoreTimerExpired>(*step->input) && !step->idle_timeout &&
                step->socket_fd == 51);
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *, nfds_t, int) -> int {
                    errno = ECANCELED;
                    return -1;
                },
            },
        };
        runtime_io_restart_coverage_check(coverage_ok, "wait returns nullopt when poll is canceled",
                                          !wait_for_socket_or_deadline(
                                               RuntimeWaitConfig{
                                                   .socket_fds = {52, -1},
                                                   .socket_fd_count = 1,
                                                   .idle_timeout_ms = 10,
                                                   .role_name = "client",
                                               },
                                               std::nullopt)
                                               .has_value());
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *, nfds_t, int) -> int {
                    errno = EIO;
                    return -1;
                },
            },
        };
        runtime_io_restart_coverage_check(coverage_ok, "wait returns nullopt on poll errors",
                                          !wait_for_socket_or_deadline(
                                               RuntimeWaitConfig{
                                                   .socket_fds = {53, -1},
                                                   .socket_fd_count = 1,
                                                   .idle_timeout_ms = 10,
                                                   .role_name = "client",
                                               },
                                               std::nullopt)
                                               .has_value());
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *descriptors, nfds_t count, int) -> int {
                    if (count > 0 && descriptors != nullptr) {
                        descriptors[0].revents = POLLOUT;
                    }
                    return 1;
                },
            },
        };
        runtime_io_restart_coverage_check(coverage_ok,
                                          "wait rejects sockets that become unreadable",
                                          !wait_for_socket_or_deadline(
                                               RuntimeWaitConfig{
                                                   .socket_fds = {54, -1},
                                                   .socket_fd_count = 1,
                                                   .idle_timeout_ms = 10,
                                                   .role_name = "client",
                                               },
                                               std::nullopt)
                                               .has_value());
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *, nfds_t, int) -> int { return 1; },
            },
        };
        runtime_io_restart_coverage_check(coverage_ok,
                                          "wait rejects readiness without readable sockets",
                                          !wait_for_socket_or_deadline(
                                               RuntimeWaitConfig{
                                                   .socket_fds = {55, -1},
                                                   .socket_fd_count = 1,
                                                   .idle_timeout_ms = 10,
                                                   .role_name = "client",
                                               },
                                               std::nullopt)
                                               .has_value());
    }

    {
        g_recorded_recvmsg_for_tests = {};
        g_recorded_recvmsg_for_tests.bytes = {
            std::byte{0x40},
        };
        g_recorded_recvmsg_for_tests.peer = make_loopback_peer(7443);
        g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);

        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *, nfds_t, int) -> int { return 0; },
                .recvmsg_fn = &record_recvmsg_for_tests,
            },
        };

        const ClientLoopIo io = make_runtime_client_loop_io();
        const auto current = io.current_time();
        const auto received = io.receive_datagram(/*socket_fd=*/56, /*flags=*/0, "client");
        const auto step = io.wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fds = {56, -1},
                .socket_fd_count = 1,
                .idle_timeout_ms = 25,
                .role_name = "client",
            },
            current + std::chrono::milliseconds(25));
        const auto *inbound = received.step.input.has_value()
                                  ? std::get_if<QuicCoreInboundDatagram>(&*received.step.input)
                                  : nullptr;

        runtime_io_restart_coverage_check(
            coverage_ok, "client loop io wrappers call through to runtime helpers",
            current.time_since_epoch().count() > 0 &&
                received.status == ReceiveDatagramStatus::ok && inbound != nullptr &&
                inbound->bytes == g_recorded_recvmsg_for_tests.bytes && step.has_value() &&
                step->input.has_value() &&
                std::holds_alternative<QuicCoreTimerExpired>(*step->input));
    }

    return coverage_ok;
}

bool runtime_low_level_socket_and_ecn_coverage_for_tests() {
    bool ok = true;

    runtime_io_restart_coverage_check(ok, "not_ect maps to zero traffic class",
                                      linux_traffic_class_for_ecn(QuicEcnCodepoint::not_ect) ==
                                          0x00);
    runtime_io_restart_coverage_check(ok, "unavailable maps to zero traffic class",
                                      linux_traffic_class_for_ecn(QuicEcnCodepoint::unavailable) ==
                                          0x00);
    QuicEcnCodepoint invalid_ecn_codepoint = QuicEcnCodepoint::unavailable;
    const std::uint8_t invalid_ecn_codepoint_raw = 0xff;
    std::memcpy(&invalid_ecn_codepoint, &invalid_ecn_codepoint_raw, sizeof(invalid_ecn_codepoint));
    runtime_io_restart_coverage_check(ok, "unknown codepoint falls back to zero traffic class",
                                      linux_traffic_class_for_ecn(invalid_ecn_codepoint) == 0x00);
    runtime_io_restart_coverage_check(ok, "traffic class 0x01 maps to ect1",
                                      ecn_from_linux_traffic_class(0x01) == QuicEcnCodepoint::ect1);
    runtime_io_restart_coverage_check(ok, "ecn testcase uses transfer semantics",
                                      transfer_semantics_testcase(QuicHttp09Testcase::ecn) ==
                                          QuicHttp09Testcase::transfer);
    runtime_io_restart_coverage_check(
        ok, "connectionmigration testcase uses transfer semantics",
        transfer_semantics_testcase(QuicHttp09Testcase::connectionmigration) ==
            QuicHttp09Testcase::transfer);

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
                .sendmsg_fn = record_sendmsg_for_tests,
            },
        };
        runtime_io_restart_coverage_check(
            ok, "sendto override is not legacy when sendmsg is also overridden",
            !has_legacy_sendto_override());
    }

    {
        g_recorded_setsockopt_for_tests = {};
        int option_value = 7;
        runtime_io_restart_coverage_check(ok, "setsockopt recorder copies full option values",
                                          record_setsockopt_for_tests(/*fd=*/0, IPPROTO_IP, IP_TOS,
                                                                      &option_value,
                                                                      sizeof(option_value)) == 0);
        runtime_io_restart_coverage_check(
            ok, "setsockopt recorder handles short option values",
            record_setsockopt_for_tests(/*fd=*/0, IPPROTO_IPV6, IPV6_RECVTCLASS, &option_value,
                                        sizeof(option_value) - 1) == 0);
        runtime_io_restart_coverage_check(
            ok, "setsockopt recorder handles null option values",
            record_setsockopt_for_tests(/*fd=*/0, SOL_SOCKET, SO_REUSEADDR, nullptr, 0) == 0);
        runtime_io_restart_coverage_check(ok,
                                          "setsockopt recorder stores copied and default values",
                                          g_recorded_setsockopt_for_tests.calls.size() == 3 &&
                                              g_recorded_setsockopt_for_tests.calls[0].value == 7 &&
                                              g_recorded_setsockopt_for_tests.calls[1].value == 0 &&
                                              g_recorded_setsockopt_for_tests.calls[2].value == 0);
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .recvfrom_fn = [](int, void *, size_t, int, sockaddr *, socklen_t *) -> ssize_t {
                    return 0;
                },
                .recvmsg_fn = record_recvmsg_for_tests,
            },
        };
        runtime_io_restart_coverage_check(
            ok, "recvfrom override is not legacy when recvmsg is also overridden",
            !has_legacy_recvfrom_override());
    }

    {
        errno = 0;
        runtime_io_restart_coverage_check(ok, "recvmsg recorder rejects null messages",
                                          record_recvmsg_for_tests(/*fd=*/0, nullptr, 0) == -1 &&
                                              errno == EINVAL);

        msghdr missing_iov{};
        errno = 0;
        runtime_io_restart_coverage_check(
            ok, "recvmsg recorder rejects messages without iov",
            record_recvmsg_for_tests(/*fd=*/0, &missing_iov, 0) == -1 && errno == EINVAL);

        std::array<iovec, 1> zero_iov{};
        msghdr zero_iov_count{};
        zero_iov_count.msg_iov = zero_iov.data();
        zero_iov_count.msg_iovlen = 0;
        errno = 0;
        runtime_io_restart_coverage_check(
            ok, "recvmsg recorder rejects zero iov count",
            record_recvmsg_for_tests(/*fd=*/0, &zero_iov_count, 0) == -1 && errno == EINVAL);
    }

    sockaddr_storage ipv4_peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&ipv4_peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4443);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    runtime_io_restart_coverage_check(ok, "ipv4 peer is not treated as ipv4-mapped ipv6",
                                      !is_ipv4_mapped_ipv6_address(ipv4_peer, sizeof(sockaddr_in)));

    sockaddr_storage short_ipv6_peer{};
    auto &short_ipv6 = *reinterpret_cast<sockaddr_in6 *>(&short_ipv6_peer);
    short_ipv6.sin6_family = AF_INET6;
    runtime_io_restart_coverage_check(
        ok, "short ipv6 peer is not treated as ipv4 mapped",
        !is_ipv4_mapped_ipv6_address(short_ipv6_peer,
                                     static_cast<socklen_t>(sizeof(sockaddr_in6) - 1)));

    {
        QuicIoRemote invalid_remote{};
        invalid_remote.family = AF_UNSPEC;
        runtime_io_restart_coverage_check(ok, "invalid remote family has no peer port",
                                          peer_port_for_remote_for_tests(invalid_remote) == 0);

        QuicIoRemote short_ipv4_remote{};
        short_ipv4_remote.family = AF_INET;
        std::memcpy(&short_ipv4_remote.peer, &ipv4_peer, sizeof(ipv4_peer));
        short_ipv4_remote.peer_len = static_cast<socklen_t>(sizeof(sockaddr_in) - 1);
        runtime_io_restart_coverage_check(ok, "short ipv4 remote has no peer port",
                                          peer_port_for_remote_for_tests(short_ipv4_remote) == 0);

        QuicIoRemote short_ipv6_remote{};
        short_ipv6_remote.family = AF_INET6;
        std::memcpy(&short_ipv6_remote.peer, &short_ipv6_peer, sizeof(short_ipv6_peer));
        short_ipv6_remote.peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6) - 1);
        runtime_io_restart_coverage_check(ok, "short ipv6 remote has no peer port",
                                          peer_port_for_remote_for_tests(short_ipv6_remote) == 0);
    }

    msghdr truncated_message{};
    truncated_message.msg_flags = MSG_CTRUNC;
    runtime_io_restart_coverage_check(ok, "truncated recvmsg control returns unavailable",
                                      recvmsg_ecn_from_control(truncated_message) ==
                                          QuicEcnCodepoint::unavailable);

    {
        std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
        msghdr message{};
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        auto *header = CMSG_FIRSTHDR(&message);
        runtime_io_restart_coverage_check(ok, "ipv6 control header exists", header != nullptr);
        if (header != nullptr) {
            header->cmsg_level = IPPROTO_IPV6;
            header->cmsg_type = IPV6_TCLASS;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            const int traffic_class = 0x03;
            std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
            message.msg_controllen = header->cmsg_len;
            runtime_io_restart_coverage_check(ok, "ipv6 tclass control maps to ce",
                                              recvmsg_ecn_from_control(message) ==
                                                  QuicEcnCodepoint::ce);
        }
    }

    {
        std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
        msghdr message{};
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        auto *header = CMSG_FIRSTHDR(&message);
        runtime_io_restart_coverage_check(ok, "ipv6 unrelated control header exists",
                                          header != nullptr);
        if (header != nullptr) {
            header->cmsg_level = IPPROTO_IPV6;
            header->cmsg_type = IPV6_HOPLIMIT;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            message.msg_controllen = header->cmsg_len;
            runtime_io_restart_coverage_check(ok, "ipv6 unrelated control leaves ecn unavailable",
                                              recvmsg_ecn_from_control(message) ==
                                                  QuicEcnCodepoint::unavailable);
        }
    }

    {
        std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
        msghdr message{};
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        auto *header = CMSG_FIRSTHDR(&message);
        runtime_io_restart_coverage_check(ok, "zero-payload control header exists",
                                          header != nullptr);
        if (header != nullptr) {
            header->cmsg_level = IPPROTO_IP;
            header->cmsg_type = IP_TOS;
            header->cmsg_len = CMSG_LEN(0);
            message.msg_controllen = header->cmsg_len;
            runtime_io_restart_coverage_check(ok, "zero-payload control falls back to not_ect",
                                              recvmsg_ecn_from_control(message) ==
                                                  QuicEcnCodepoint::not_ect);
        }
    }

    {
        std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
        msghdr message{};
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        auto *header = CMSG_FIRSTHDR(&message);
        runtime_io_restart_coverage_check(ok, "unrelated control header exists", header != nullptr);
        if (header != nullptr) {
            header->cmsg_level = IPPROTO_IP;
            header->cmsg_type = IP_TTL;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            message.msg_controllen = header->cmsg_len;
            runtime_io_restart_coverage_check(ok, "unrelated control leaves ecn unavailable",
                                              recvmsg_ecn_from_control(message) ==
                                                  QuicEcnCodepoint::unavailable);
        }
    }

    {
        g_recorded_setsockopt_for_tests = {};
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .setsockopt_fn = record_setsockopt_for_tests,
            },
        };
        runtime_io_restart_coverage_check(
            ok, "unsupported family skips linux ecn socket options",
            configure_linux_ecn_socket_options(LinuxSocketDescriptor{.fd = 0}, AF_UNSPEC));
        runtime_io_restart_coverage_check(ok, "unsupported family leaves setsockopt untouched",
                                          g_recorded_setsockopt_for_tests.calls.empty());
    }

    {
        ScriptedIoBackendForTests backend;
        QuicIoRemote remote{};
        runtime_io_restart_coverage_check(ok, "scripted backend defaults to no route",
                                          !backend.ensure_route(remote).has_value());
    }

    {
        const auto fallback_server_loop_case =
            make_server_loop_case_for_tests(static_cast<ServerLoopCaseForTests>(255));
        const auto fallback_backend_case = make_server_backend_scheduling_case_for_tests(
            static_cast<ServerBackendSchedulingCaseForTests>(255));
        runtime_io_restart_coverage_check(
            ok, "invalid server loop coverage case falls back to default script",
            !fallback_server_loop_case.receive_results.empty());
        runtime_io_restart_coverage_check(
            ok, "invalid backend scheduling coverage case falls back to default script",
            !fallback_backend_case.wait_results.empty());
    }

    {
        const int fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
        runtime_io_restart_coverage_check(ok, "test ipv6 socket opened", fd >= 0);
        if (fd >= 0) {
            ScopedFd socket_guard(fd);
            const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
                Http09RuntimeOpsOverride{
                    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                    .setsockopt_fn = [](int current_fd, int level, int name, const void *value,
                                        socklen_t value_len) -> int {
                        if (level == IPPROTO_IPV6 && name == IPV6_RECVTCLASS) {
                            errno = ENOPROTOOPT;
                            return -1;
                        }
                        return ::setsockopt(current_fd, level, name, value, value_len);
                    },
                },
            };
            runtime_io_restart_coverage_check(
                ok, "ipv6 ecn socket option failure is surfaced",
                !configure_linux_ecn_socket_options(LinuxSocketDescriptor{.fd = fd}, AF_INET6));
        }
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .socket_fn = [](int family, int type, int protocol) -> int {
                    return ::socket(family, type, protocol);
                },
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .setsockopt_fn = [](int current_fd, int level, int name, const void *value,
                                    socklen_t value_len) -> int {
                    if (level == IPPROTO_IPV6 && name == IPV6_V6ONLY) {
                        errno = EINVAL;
                        return -1;
                    }
                    return ::setsockopt(current_fd, level, name, value, value_len);
                },
            },
        };
        runtime_io_restart_coverage_check(ok,
                                          "open udp socket fails when ipv6 v6only disable fails",
                                          (open_udp_socket(AF_INET6) == -1) && (errno == EINVAL));
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .socket_fn = [](int family, int type, int protocol) -> int {
                    return ::socket(family, type, protocol);
                },
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .setsockopt_fn = [](int current_fd, int level, int name, const void *value,
                                    socklen_t value_len) -> int {
                    if (level == IPPROTO_IPV6 && name == IPV6_RECVTCLASS) {
                        errno = ENOPROTOOPT;
                        return -1;
                    }
                    return ::setsockopt(current_fd, level, name, value, value_len);
                },
            },
        };
        runtime_io_restart_coverage_check(ok, "open udp socket fails when ipv6 ecn setup fails",
                                          (open_udp_socket(AF_INET6) == -1) &&
                                              (errno == ENOPROTOOPT));
    }

    {
        sockaddr_storage peer{};
        std::memcpy(&peer, &ipv4_peer, sizeof(ipv4_peer));
        const auto bytes = bytes_from_string_for_runtime_tests("ecn");
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendmsg_fn = [](int, const msghdr *, int) -> ssize_t {
                    errno = EIO;
                    return -1;
                },
            },
        };
        runtime_io_restart_coverage_check(ok, "sendmsg failure returns false",
                                          !send_datagram(/*fd=*/-1, bytes, peer, sizeof(ipv4_peer),
                                                         "client", QuicEcnCodepoint::ect0));
    }

    {
        g_recorded_sendto_for_tests = {};
        sockaddr_storage peer{};
        auto &fallback_ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        fallback_ipv4.sin_family = AF_INET;
        const auto bytes = bytes_from_string_for_runtime_tests("ecn");
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
                .sendmsg_fn = record_sendmsg_for_tests,
            },
        };
        runtime_io_restart_coverage_check(ok, "zero peer length falls back to sendto",
                                          send_datagram(/*fd=*/19, bytes, peer, /*peer_len=*/0,
                                                        "client", QuicEcnCodepoint::ect0));
        runtime_io_restart_coverage_check(ok, "zero peer length uses sendto once",
                                          g_recorded_sendto_for_tests.calls == 1);
    }

    {
        g_recorded_sendto_for_tests = {};
        sockaddr_storage peer{};
        peer.ss_family = AF_UNSPEC;
        const auto bytes = bytes_from_string_for_runtime_tests("ecn");
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendto_fn = record_sendto_for_tests,
                .sendmsg_fn = record_sendmsg_for_tests,
            },
        };
        runtime_io_restart_coverage_check(ok, "unsupported peer family falls back to sendto",
                                          send_datagram(/*fd=*/21, bytes, peer,
                                                        sizeof(sockaddr_storage), "client",
                                                        QuicEcnCodepoint::ect0));
        runtime_io_restart_coverage_check(ok, "unsupported peer family uses sendto once",
                                          g_recorded_sendto_for_tests.calls == 1);
    }

    {
        g_recorded_sendmsg_for_tests = {};
        sockaddr_storage peer{};
        auto &ipv6_peer = *reinterpret_cast<sockaddr_in6 *>(&peer);
        ipv6_peer.sin6_family = AF_INET6;
        ipv6_peer.sin6_port = htons(4434);
        ipv6_peer.sin6_addr = in6addr_loopback;
        const auto bytes = bytes_from_string_for_runtime_tests("ecn");
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .sendmsg_fn = record_sendmsg_for_tests,
            },
        };
        runtime_io_restart_coverage_check(ok, "native ipv6 sendmsg succeeds",
                                          send_datagram(/*fd=*/22, bytes, peer,
                                                        sizeof(sockaddr_in6), "client",
                                                        QuicEcnCodepoint::ect0));
        runtime_io_restart_coverage_check(ok, "native ipv6 sendmsg uses ipv6 tclass",
                                          (g_recorded_sendmsg_for_tests.level == IPPROTO_IPV6) &&
                                              (g_recorded_sendmsg_for_tests.type == IPV6_TCLASS) &&
                                              (g_recorded_sendmsg_for_tests.traffic_class == 0x02));
    }

    {
        const int primary_fd = ::dup(STDOUT_FILENO);
        const int secondary_fd = ::dup(STDOUT_FILENO);
        runtime_io_restart_coverage_check(ok, "client socket dups open",
                                          primary_fd >= 0 && secondary_fd >= 0);
        if (primary_fd >= 0 && secondary_fd >= 0) {
            ClientSocketSet sockets{
                .primary =
                    ClientSocketDescriptor{
                        .fd = primary_fd,
                        .family = AF_INET,
                    },
                .secondary =
                    ClientSocketDescriptor{
                        .fd = secondary_fd,
                        .family = AF_INET6,
                    },
            };
            runtime_io_restart_coverage_check(
                ok, "secondary client socket lookup returns secondary fd",
                client_socket_fd_for_family(sockets, AF_INET6) == secondary_fd);
            {
                ScopedClientSockets close_sockets(sockets);
            }
            errno = 0;
            runtime_io_restart_coverage_check(ok, "secondary client socket was closed",
                                              (::close(secondary_fd) == -1) && (errno == EBADF));
            errno = 0;
            runtime_io_restart_coverage_check(ok, "primary client socket was closed",
                                              (::close(primary_fd) == -1) && (errno == EBADF));
        } else {
            if (primary_fd >= 0) {
                ::close(primary_fd);
            }
            if (secondary_fd >= 0) {
                ::close(secondary_fd);
            }
        }
    }

    {
        const int primary_fd = ::dup(STDOUT_FILENO);
        runtime_io_restart_coverage_check(ok, "shared client socket dup opened", primary_fd >= 0);
        if (primary_fd >= 0) {
            ClientSocketSet sockets{
                .primary =
                    ClientSocketDescriptor{
                        .fd = primary_fd,
                        .family = AF_INET,
                    },
                .secondary =
                    ClientSocketDescriptor{
                        .fd = primary_fd,
                        .family = AF_INET6,
                    },
            };
            {
                ScopedClientSockets close_sockets(sockets);
            }
            errno = 0;
            runtime_io_restart_coverage_check(ok, "shared client socket closes only once",
                                              (::close(primary_fd) == -1) && (errno == EBADF));
        }
    }

    {
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = -1,
                    .family = AF_INET,
                },
        };
        ScopedClientSockets close_sockets(sockets);
        runtime_io_restart_coverage_check(ok, "negative primary client socket is ignored", true);
    }

    {
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 17,
                    .family = AF_INET,
                },
            .secondary =
                ClientSocketDescriptor{
                    .fd = -1,
                    .family = AF_INET6,
                },
        };
        ScopedClientSockets close_sockets(sockets);
        runtime_io_restart_coverage_check(ok, "negative secondary client socket is ignored", true);
    }

    {
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 17,
                    .family = AF_INET,
                },
        };
        runtime_io_restart_coverage_check(
            ok, "unsupported preferred-address family fails",
            !ensure_client_socket_for_family(sockets, AF_UNSPEC, "client").has_value());
    }

    {
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 17,
                    .family = AF_UNSPEC,
                },
            .secondary =
                ClientSocketDescriptor{
                    .fd = 23,
                    .family = AF_INET6,
                },
        };
        runtime_io_restart_coverage_check(
            ok, "occupied secondary slot rejects new preferred-address family",
            !ensure_client_socket_for_family(sockets, AF_INET, "client").has_value());
    }

    {
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 17,
                    .family = AF_INET,
                },
        };
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .socket_fn = [](int, int, int) -> int {
                    errno = EMFILE;
                    return -1;
                },
            },
        };
        runtime_io_restart_coverage_check(
            ok, "preferred-address socket creation failure is reported",
            !ensure_client_socket_for_family(sockets, AF_INET6, "client").has_value());
    }

    const PreferredAddress preferred_ipv4{
        .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
        .ipv4_port = 4444,
        .connection_id = make_runtime_connection_id(std::byte{0x44}, 1),
    };

    {
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 17,
                    .family = AF_UNSPEC,
                },
            .secondary =
                ClientSocketDescriptor{
                    .fd = 23,
                    .family = AF_INET6,
                },
        };
        QuicCoreResult result;
        result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
            .preferred_address = preferred_ipv4,
        });
        runtime_io_restart_coverage_check(
            ok, "preferred-address observation fails when no client socket slot is available",
            !observe_client_runtime_policy_effects(result, state, policy, sockets, "client"));
    }

    {
        ScriptedEndpointForTests endpoint;
        QuicCore core = make_local_error_client_core_for_tests();
        QuicCoreResult result;
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        const Http09RuntimeConfig config{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::connectionmigration,
        };
        runtime_io_restart_coverage_check(
            ok, "drive endpoint fails when policy sockets are missing",
            !drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core, /*fd=*/17,
                                          /*peer=*/nullptr, /*peer_len=*/0, result, state, "client",
                                          &config, &policy,
                                          /*client_sockets=*/nullptr));
        runtime_io_restart_coverage_check(ok, "missing policy sockets mark terminal failure",
                                          state.terminal_failure);
    }

    {
        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientSocketSet sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 17,
                    .family = AF_UNSPEC,
                },
            .secondary =
                ClientSocketDescriptor{
                    .fd = 23,
                    .family = AF_INET6,
                },
        };
        QuicCoreResult result;
        result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
            .preferred_address = preferred_ipv4,
        });
        ScriptedEndpointForTests endpoint;
        QuicCore core = make_local_error_client_core_for_tests();
        const Http09RuntimeConfig config{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::connectionmigration,
        };
        runtime_io_restart_coverage_check(
            ok, "drive endpoint fails when preferred-address observation fails",
            !drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core, /*fd=*/17,
                                          /*peer=*/nullptr, /*peer_len=*/0, result, state, "client",
                                          &config, &policy, &sockets) &&
                state.terminal_failure);
    }

    {
        runtime_low_level_getaddrinfo_calls_for_tests() = 0;
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .socket_fn = [](int family, int type, int protocol) -> int {
                    return ::socket(family, type, protocol);
                },
                .bind_fn = [](int, const sockaddr *, socklen_t) -> int { return 0; },
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .getaddrinfo_fn = [](const char *node, const char *service, const addrinfo *hints,
                                     addrinfo **results) -> int {
                    runtime_low_level_getaddrinfo_calls_for_tests() += 1;
                    if (runtime_low_level_getaddrinfo_calls_for_tests() == 2) {
                        return EAI_FAIL;
                    }
                    return ::getaddrinfo(node, service, hints, results);
                },
                .freeaddrinfo_fn = ::freeaddrinfo,
            },
        };
        const auto server_config = Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        };
        runtime_io_restart_coverage_check(
            ok, "preferred bind resolution failure aborts server before certificate setup",
            run_http09_server(server_config) == 1);
    }

    {
        runtime_low_level_bind_calls_for_tests() = 0;
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .socket_fn = [](int family, int type, int protocol) -> int {
                    return ::socket(family, type, protocol);
                },
                .bind_fn = [](int, const sockaddr *, socklen_t) -> int {
                    runtime_low_level_bind_calls_for_tests() += 1;
                    if (runtime_low_level_bind_calls_for_tests() == 2) {
                        errno = EADDRINUSE;
                        return -1;
                    }
                    return 0;
                },
            },
        };
        const auto server_config = Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        };
        runtime_io_restart_coverage_check(ok, "preferred bind socket failure aborts server",
                                          run_http09_server(server_config) == 1);
    }

    return ok;
}

bool runtime_connectionmigration_failure_paths_for_tests() {
    const bool unofficial_alias_without_preferred_address =
        !runtime_backend_connectionmigration_request_flow_case_for_tests(
            /*official_alias=*/false, /*include_preferred_address=*/false);
    const bool preferred_address_route_failure =
        runtime_backend_preferred_address_route_failure_stops_migration_request_for_tests();
    const bool official_alias_without_preferred_address =
        !runtime_backend_connectionmigration_request_flow_case_for_tests(
            /*official_alias=*/true, /*include_preferred_address=*/false);
    const bool missing_preferred_ids =
        !runtime_registers_all_server_core_connection_ids_case_for_tests(
            /*include_preferred_address=*/false);
    return unofficial_alias_without_preferred_address && preferred_address_route_failure &&
           official_alias_without_preferred_address && missing_preferred_ids;
}

bool runtime_restart_failure_paths_for_tests() {
    const bool version_serialization_failure =
        !core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
            /*force_serialization_failure=*/true);
    const bool version_path_id_mismatch =
        !core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
            /*force_serialization_failure=*/false, /*force_path_id_mismatch=*/true);
    const bool retry_integrity_failure =
        !core_retry_restart_preserves_inbound_path_ids_case_for_tests(
            /*force_integrity_failure=*/true, /*force_serialization_failure=*/false);
    const bool retry_serialization_failure =
        !core_retry_restart_preserves_inbound_path_ids_case_for_tests(
            /*force_integrity_failure=*/false, /*force_serialization_failure=*/true);
    const bool retry_path_id_mismatch =
        !core_retry_restart_preserves_inbound_path_ids_case_for_tests(
            /*force_integrity_failure=*/false, /*force_serialization_failure=*/false,
            /*force_path_id_mismatch=*/true);
    return version_serialization_failure && version_path_id_mismatch && retry_integrity_failure &&
           retry_serialization_failure && retry_path_id_mismatch;
}

ExistingServerSessionDatagramRouteResultForTests route_existing_server_session_datagram_for_tests(
    QuicCore &core, std::span<const RuntimePathSeedForTests> seeded_paths,
    std::span<const std::byte> local_connection_id,
    std::span<const std::byte> initial_destination_connection_id, int inbound_socket_fd,
    const sockaddr_storage &inbound_peer, socklen_t inbound_peer_len, std::vector<std::byte> bytes,
    QuicCoreTimePoint input_time) {
    ExistingServerSessionDatagramRouteResultForTests result;
    g_recorded_sendto_for_tests = {};
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    };

    ScopedRuntimeTempDirForTests document_root;
    ServerSession session{
        .core = std::move(core),
        .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        }),
        .state = EndpointDriveState{},
        .socket_fd = seeded_paths.empty() ? -1 : seeded_paths.back().socket_fd,
        .peer = seeded_paths.empty() ? sockaddr_storage{} : seeded_paths.back().peer,
        .peer_len = seeded_paths.empty() ? 0 : seeded_paths.back().peer_len,
        .local_connection_id_key = connection_id_key(local_connection_id),
        .initial_destination_connection_id_key =
            connection_id_key(initial_destination_connection_id),
    };
    for (std::size_t index = 0; index < seeded_paths.size(); ++index) {
        const auto &seed = seeded_paths[index];
        const auto seeded_path_id =
            remember_runtime_path(session.state, seed.peer, seed.peer_len, seed.socket_fd);
        if (seeded_path_id != static_cast<QuicPathId>(index + 1)) {
            core = std::move(session.core);
            return result;
        }
        const auto seeded_route_handle =
            remember_runtime_route_handle(session.state, seed.peer, seed.peer_len, seed.socket_fd);
        if (!seed_legacy_route_handle_path_for_tests(session.core, seeded_route_handle,
                                                     seeded_path_id)) {
            core = std::move(session.core);
            return result;
        }
    }

    RuntimeWaitStep step{
        .input =
            QuicCoreInboundDatagram{
                .bytes = std::move(bytes),
            },
        .input_time = input_time,
        .socket_fd = inbound_socket_fd,
        .source = inbound_peer,
        .source_len = inbound_peer_len,
        .has_source = true,
    };
    auto parsed_datagram_for_routing = parse_server_datagram_for_routing(
        std::span<const std::byte>(std::get<QuicCoreInboundDatagram>(*step.input).bytes.data(),
                                   std::get<QuicCoreInboundDatagram>(*step.input).bytes.size()));
    if (!parsed_datagram_for_routing.has_value()) {
        core = std::move(session.core);
        return result;
    }

    bool erased = false;
    ServerConnectionIdRouteMap connection_id_routes;
    result.processed = process_existing_server_session_datagram(
        session, step, connection_id_routes, *parsed_datagram_for_routing,
        [&](const std::string &) { erased = true; });
    result.erased = erased;
    if (const auto route_it = session.state.path_routes.find(2);
        route_it != session.state.path_routes.end()) {
        result.has_migrated_path_route = true;
        result.migrated_path_socket_fd = route_it->second.socket_fd;
    }
    result.sendto_calls = g_recorded_sendto_for_tests.calls;
    result.sendto_socket_fd = g_recorded_sendto_for_tests.socket_fd;
    result.sendto_peer_port = g_recorded_sendto_for_tests.peer_port;
    result.sendto_socket_fds = g_recorded_sendto_for_tests.socket_fds;
    result.sendto_peer_ports = g_recorded_sendto_for_tests.peer_ports;
    core = std::move(session.core);
    return result;
}

ExistingServerSessionDatagramRouteResultForTests route_existing_server_session_datagram_for_tests(
    QuicCore &core, int established_socket_fd, const sockaddr_storage &established_peer,
    socklen_t established_peer_len, std::span<const std::byte> local_connection_id,
    std::span<const std::byte> initial_destination_connection_id, int inbound_socket_fd,
    const sockaddr_storage &inbound_peer, socklen_t inbound_peer_len, std::vector<std::byte> bytes,
    QuicCoreTimePoint input_time) {
    const std::array seeded_paths{
        RuntimePathSeedForTests{
            .socket_fd = established_socket_fd,
            .peer = established_peer,
            .peer_len = established_peer_len,
        },
    };
    return route_existing_server_session_datagram_for_tests(
        core, seeded_paths, local_connection_id, initial_destination_connection_id,
        inbound_socket_fd, inbound_peer, inbound_peer_len, std::move(bytes), input_time);
}

bool core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
    bool force_serialization_failure, bool force_path_id_mismatch) {
    const Http09RuntimeConfig runtime_config{
        .mode = Http09RuntimeMode::client,
    };
    auto core_config = make_runtime_client_core_config(runtime_config, /*connection_index=*/3);
    core_config.original_version = kQuicVersion1;
    core_config.initial_version = kQuicVersion1;
    core_config.supported_versions = {kQuicVersion2, kQuicVersion1};
    const auto source_connection_id = core_config.source_connection_id;
    const auto initial_destination_connection_id = core_config.initial_destination_connection_id;
    QuicCore core(std::move(core_config));

    const auto version_negotiation_packet = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = source_connection_id,
        .source_connection_id = initial_destination_connection_id,
        .supported_versions = force_serialization_failure
                                  ? std::vector<std::uint32_t>{}
                                  : std::vector<std::uint32_t>{kQuicVersion2},
    });
    if (!version_negotiation_packet.has_value()) {
        return false;
    }

    constexpr QuicRouteHandle kInboundRouteHandle = 41;
    const auto result = core.advance(
        QuicCoreInboundDatagram{
            .bytes = version_negotiation_packet.value(),
            .route_handle = kInboundRouteHandle,
        },
        now());

    auto effects = result.effects;
    effects.insert(effects.begin(), QuicCoreStateEvent{
                                        .change = QuicCoreStateChange::handshake_ready,
                                    });
    if (force_path_id_mismatch) {
        effects.emplace_back(QuicCoreSendDatagram{
            .route_handle = std::nullopt,
            .bytes = {std::byte{0x01}},
        });
    }
    bool saw_send = false;
    bool all_sends_match_path = true;
    for (const auto &effect : effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }
        saw_send = true;
        if (send->route_handle != std::optional<QuicRouteHandle>{kInboundRouteHandle}) {
            all_sends_match_path = false;
        }
    }
    return saw_send && all_sends_match_path;
}

bool core_version_negotiation_restart_preserves_inbound_path_ids_for_tests() {
    return core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
        /*force_serialization_failure=*/false, /*force_path_id_mismatch=*/false);
}

bool core_retry_restart_preserves_inbound_path_ids_case_for_tests(bool force_integrity_failure,
                                                                  bool force_serialization_failure,
                                                                  bool force_path_id_mismatch) {
    const Http09RuntimeConfig runtime_config{
        .mode = Http09RuntimeMode::client,
    };
    auto core_config = make_runtime_client_core_config(runtime_config, /*connection_index=*/4);
    const auto source_connection_id = core_config.source_connection_id;
    const auto original_destination_connection_id = core_config.initial_destination_connection_id;
    const auto retry_source_connection_id =
        make_runtime_connection_id(std::byte{0x73}, /*sequence=*/9);
    QuicCore core(std::move(core_config));

    RetryPacket retry_packet{
        .version = kQuicVersion1,
        .retry_unused_bits = 0,
        .destination_connection_id = source_connection_id,
        .source_connection_id = retry_source_connection_id,
        .retry_token = {std::byte{0x99}, std::byte{0x98}},
    };
    if (force_integrity_failure) {
        retry_packet.version = kVersionNegotiationVersion;
    }
    const auto retry_integrity =
        compute_retry_integrity_tag(retry_packet, original_destination_connection_id);
    if (!retry_integrity.has_value()) {
        return false;
    }
    retry_packet.retry_integrity_tag = retry_integrity.value();
    if (force_serialization_failure) {
        retry_packet.source_connection_id.assign(21, std::byte{0xaa});
    }
    const auto encoded_retry = serialize_packet(retry_packet);
    if (!encoded_retry.has_value()) {
        return false;
    }

    constexpr QuicRouteHandle kInboundRouteHandle = 52;
    const auto result = core.advance(
        QuicCoreInboundDatagram{
            .bytes = encoded_retry.value(),
            .route_handle = kInboundRouteHandle,
        },
        now());

    auto effects = result.effects;
    effects.insert(effects.begin(), QuicCoreStateEvent{
                                        .change = QuicCoreStateChange::handshake_ready,
                                    });
    if (force_path_id_mismatch) {
        effects.emplace_back(QuicCoreSendDatagram{
            .route_handle = std::nullopt,
            .bytes = {std::byte{0x02}},
        });
    }
    bool saw_send = false;
    bool all_sends_match_path = true;
    for (const auto &effect : effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }
        saw_send = true;
        if (send->route_handle != std::optional<QuicRouteHandle>{kInboundRouteHandle}) {
            all_sends_match_path = false;
        }
    }
    return saw_send && all_sends_match_path;
}

bool core_retry_restart_preserves_inbound_path_ids_for_tests() {
    return core_retry_restart_preserves_inbound_path_ids_case_for_tests(
        /*force_integrity_failure=*/false, /*force_serialization_failure=*/false,
        /*force_path_id_mismatch=*/false);
}

bool drive_endpoint_rejects_unknown_transport_selected_path_for_tests() {
    g_recorded_sendto_for_tests = {};
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    };

    sockaddr_storage fallback_peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&fallback_peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(8555);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    EndpointDriveState state;
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreSendDatagram{
        .route_handle = static_cast<QuicRouteHandle>(404),
        .bytes = {std::byte{0xdd}},
    });

    ScriptedEndpointForTests endpoint;
    QuicCore core = make_local_error_client_core_for_tests();
    return !drive_endpoint_until_blocked(
               make_endpoint_driver(endpoint), core, /*fd=*/18, &fallback_peer,
               static_cast<socklen_t>(sizeof(sockaddr_in)), result, state, "client") &&
           state.terminal_failure && (g_recorded_sendto_for_tests.calls == 0);
}

bool version_negotiation_without_source_connection_id_fails_for_tests() {
    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::unsupported_version_long_header,
        .destination_connection_id = {std::byte{0x83}},
        .source_connection_id = std::nullopt,
    };
    sockaddr_storage peer{};
    return !send_version_negotiation_for_probe(
        /*fd=*/-1, std::vector<std::byte>(kMinimumClientInitialDatagramBytes, std::byte{0x00}),
        parsed, peer,
        /*peer_len=*/0);
}

std::optional<QuicConnectionHandle> seed_live_backend_response_for_tests(
    ScopedRuntimeTempDirForTests &document_root, const Http09RuntimeConfig &config,
    QuicCore &server_core, EndpointDriveState &transport_state,
    ServerConnectionEndpointMap &endpoint_map, ScriptedIoBackendForTests &backend,
    QuicRouteHandle route_handle) {
    document_root.write_file("large.bin", std::string(static_cast<std::size_t>(96) * 1024U, 'x'));
    server_core = QuicCore(make_runtime_server_endpoint_config(
        config, TlsIdentity{
                    .certificate_pem = read_text_file("tests/fixtures/quic-server-cert.pem"),
                    .private_key_pem = read_text_file("tests/fixtures/quic-server-key.pem"),
                }));

    QuicCore client(make_http09_client_core_config(Http09RuntimeConfig{
        .mode = Http09RuntimeMode::client,
    }));
    QuicCoreTimePoint step_now = now();
    const auto accepted_connection =
        drive_live_server_endpoint_handshake_for_tests(client, route_handle, server_core, step_now);
    if (!accepted_connection.has_value()) {
        return std::nullopt;
    }

    backend.ensure_route_results.push_back(route_handle);
    static_cast<void>(backend.ensure_route(QuicIoRemote{
        .family = AF_INET,
    }));
    step_now += std::chrono::milliseconds(1);
    endpoint_map.emplace(*accepted_connection,
                         ServerConnectionEndpointState{
                             .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                 .document_root = document_root.path(),
                             }),
                         });
    static_cast<void>(process_server_endpoint_core_result_with_backend(
        server_core, transport_state, endpoint_map, config.document_root,
        relay_send_datagrams_to_endpoint_core_for_tests(
            client.advance(
                QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_string_for_runtime_tests("GET /large.bin\r\n"),
                    .fin = true,
                },
                step_now),
            server_core, route_handle, step_now),
        route_handle, backend));
    step_now += std::chrono::milliseconds(1);
    step_now += std::chrono::milliseconds(1);
    static_cast<void>(relay_send_datagrams_to_endpoint_core_for_tests(
        relay_backend_sent_datagrams_to_client_core_for_tests(backend.sent_datagrams, client,
                                                              step_now),
        server_core, route_handle, step_now + std::chrono::milliseconds(1)));
    return accepted_connection;
}

std::size_t
count_pending_server_endpoints_for_tests(const ServerConnectionEndpointMap &endpoint_map) {
    return static_cast<std::size_t>(
        std::count_if(endpoint_map.begin(), endpoint_map.end(),
                      [](const auto &entry) { return entry.second.has_pending_work; }));
}

struct ServerBackendLoopInitialStateForTests {
    std::size_t endpoints = 0;
    std::size_t pending_endpoints = 0;
    std::size_t send_calls = 0;
};

ServerBackendLoopInitialStateForTests capture_server_backend_loop_initial_state_for_tests(
    const ServerConnectionEndpointMap &tracked_endpoint_states,
    const ScriptedIoBackendForTests &backend) {
    return ServerBackendLoopInitialStateForTests{
        .endpoints = tracked_endpoint_states.size(),
        .pending_endpoints = count_pending_server_endpoints_for_tests(tracked_endpoint_states),
        .send_calls = backend.sent_datagrams.size(),
    };
}

ServerLoopResultForTests collect_server_backend_loop_result_for_tests(
    const Http09RuntimeConfig &config, QuicCore &server_core, EndpointDriveState &transport_state,
    ServerConnectionEndpointMap &tracked_endpoint_states, ScriptedIoBackendForTests &backend,
    const ServerBackendLoopInitialStateForTests &initial_state) {
    return ServerLoopResultForTests{
        .exit_code = run_http09_server_backend_loop(config, server_core, transport_state,
                                                    tracked_endpoint_states, backend),
        .wait_calls = backend.wait_requests.size(),
        .initial_send_calls = initial_state.send_calls,
        .send_calls = backend.sent_datagrams.size(),
        .initial_endpoints = initial_state.endpoints,
        .initial_pending_endpoints = initial_state.pending_endpoints,
        .remaining_endpoints = tracked_endpoint_states.size(),
        .remaining_pending_endpoints =
            count_pending_server_endpoints_for_tests(tracked_endpoint_states),
    };
}

ServerLoopResultForTests run_server_loop_case_for_tests(ServerLoopCaseForTests case_id) {
    auto script = make_server_loop_case_for_tests(case_id);
    std::size_t current_time_calls = 0;
    std::size_t receive_calls = 0;
    std::size_t wait_calls = 0;
    std::size_t process_expired_calls = 0;
    std::size_t pump_calls = 0;
    bool endpoint_has_pending_work = false;

    const auto io = ServerLoopIo{
        .current_time =
            [&] {
                current_time_calls += 1;
                return now();
            },
        .receive_datagram =
            [&](int, int, std::string_view) { return script.receive_results[receive_calls++]; },
        .wait_for_socket_or_deadline = [&](const RuntimeWaitConfig &,
                                           const std::optional<QuicCoreTimePoint> &)
            -> std::optional<RuntimeWaitStep> { return script.wait_steps[wait_calls++]; },
    };

    const auto driver = ServerLoopDriver{
        .earliest_wakeup = [] { return std::optional<QuicCoreTimePoint>{}; },
        .process_expired_timers =
            [&](QuicCoreTimePoint, bool &processed_any) {
                processed_any = script.processed_timers_results[process_expired_calls++];
            },
        .pump_endpoint_work =
            [&] {
                endpoint_has_pending_work = pump_calls < script.pending_work_after_pump.size()
                                                ? script.pending_work_after_pump[pump_calls]
                                                : false;
                const bool made_progress = pump_calls < script.pump_made_progress.size()
                                               ? script.pump_made_progress[pump_calls]
                                               : endpoint_has_pending_work;
                pump_calls += 1;
                return made_progress;
            },
        .has_pending_endpoint_work = [&] { return endpoint_has_pending_work; },
        .process_datagram = [&](const RuntimeWaitStep &) { return script.process_datagram_result; },
    };

    return ServerLoopResultForTests{
        .exit_code = run_http09_server_loop(
            ServerSocketSet{
                .primary_fd = -1,
                .preferred_fd =
                    case_id == ServerLoopCaseForTests::blocking_wait_failure_with_preferred_socket
                        ? std::optional<int>{-2}
                        : std::nullopt,
            },
            io, driver),
        .current_time_calls = current_time_calls,
        .receive_calls = receive_calls,
        .wait_calls = wait_calls,
        .process_expired_calls = process_expired_calls,
        .pump_calls = pump_calls,
    };
}

ServerLoopResultForTests
run_server_backend_scheduling_case_for_tests(ServerBackendSchedulingCaseForTests case_id) {
    auto script = make_server_backend_scheduling_case_for_tests(case_id);
    std::size_t current_time_calls = 0;
    std::size_t next_wakeup_calls = 0;
    std::size_t wait_calls = 0;
    std::size_t immediate_wait_calls = 0;
    std::vector<long long> wait_request_delta_ms;
    std::size_t process_expired_calls = 0;
    std::size_t process_datagram_calls = 0;
    std::size_t pump_calls = 0;
    std::size_t flush_calls = 0;
    std::optional<QuicCoreTimePoint> defer_output_until = script.defer_output_until;
    bool endpoint_has_pending_work = false;
    QuicCoreTimePoint last_current_time =
        script.current_times.empty() ? now() : script.current_times.front();

    const auto driver = ServerBackendLoopDriver{
        .current_time =
            [&] {
                const auto index =
                    script.current_times.empty()
                        ? std::size_t{0}
                        : std::min(current_time_calls, script.current_times.size() - 1);
                current_time_calls += 1;
                last_current_time =
                    script.current_times.empty() ? now() : script.current_times[index];
                return last_current_time;
            },
        .next_wakeup =
            [&] {
                if (script.next_wakeup_results.empty()) {
                    return std::optional<QuicCoreTimePoint>{};
                }
                const auto index =
                    std::min(next_wakeup_calls, script.next_wakeup_results.size() - 1);
                next_wakeup_calls += 1;
                return script.next_wakeup_results[index];
            },
        .pump_endpoint_work =
            [&](bool &made_progress) {
                endpoint_has_pending_work = pump_calls < script.pending_work_after_pump.size()
                                                ? script.pending_work_after_pump[pump_calls]
                                                : false;
                made_progress = pump_calls < script.pump_made_progress.size()
                                    ? script.pump_made_progress[pump_calls]
                                    : endpoint_has_pending_work;
                pump_calls += 1;
                return true;
            },
        .has_pending_endpoint_work = [&] { return endpoint_has_pending_work; },
        .initial_buffered_event = [&] { return script.initial_buffered_event; },
        .wait =
            [&](const std::optional<QuicCoreTimePoint> &next_wakeup) {
                wait_calls += 1;
                if (!next_wakeup.has_value()) {
                    wait_request_delta_ms.push_back(-1);
                } else {
                    wait_request_delta_ms.push_back(
                        std::chrono::duration_cast<std::chrono::milliseconds>(*next_wakeup -
                                                                              last_current_time)
                            .count());
                }
                if (script.blocking_rx_requires_future_wait) {
                    const bool immediate_wait =
                        next_wakeup.has_value() && next_wakeup.value() <= last_current_time;
                    if (immediate_wait) {
                        immediate_wait_calls += 1;
                        if (script.max_immediate_waits_before_failure != 0 &&
                            immediate_wait_calls > script.max_immediate_waits_before_failure) {
                            return std::optional<QuicIoEvent>{};
                        }
                        return std::optional<QuicIoEvent>(QuicIoEvent{
                            .kind = QuicIoEvent::Kind::timer_expired,
                            .now = last_current_time,
                        });
                    }
                    if (script.blocking_rx_wait_result.has_value()) {
                        return script.blocking_rx_wait_result;
                    }
                    return std::optional<QuicIoEvent>{};
                }
                if (wait_calls > script.wait_results.size()) {
                    return std::optional<QuicIoEvent>{};
                }
                return script.wait_results[wait_calls - 1];
            },
        .process_wait_timer =
            [&](QuicCoreTimePoint) {
                process_expired_calls += 1;
                return script.process_timer_event_result;
            },
        .process_datagram =
            [&](const QuicIoRxDatagram &, QuicCoreTimePoint) {
                process_datagram_calls += 1;
                return script.process_datagram_result;
            },
        .flush_deferred_output =
            [&] {
                flush_calls += 1;
                defer_output_until.reset();
                return true;
            },
        .defer_output_until = [&] { return defer_output_until; },
    };

    return ServerLoopResultForTests{
        .exit_code = run_server_backend_loop_with_driver(driver),
        .current_time_calls = current_time_calls,
        .wait_calls = wait_calls,
        .wait_request_delta_ms = std::move(wait_request_delta_ms),
        .process_expired_calls = process_expired_calls,
        .process_datagram_calls = process_datagram_calls,
        .pump_calls = pump_calls,
        .send_calls = flush_calls,
    };
}

ServerLoopResultForTests
run_server_backend_loop_case_for_tests(ServerBackendLoopCaseForTests case_id) {
    ScopedRuntimeTempDirForTests document_root;
    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::server,
        .document_root = document_root.path(),
    };

    auto backend = std::make_unique<ScriptedIoBackendForTests>();
    auto *backend_ptr = backend.get();
    QuicCore core = make_failing_server_core_for_tests();
    EndpointDriveState transport_state;
    ServerConnectionEndpointMap endpoints;
    switch (case_id) {
    case ServerBackendLoopCaseForTests::wait_failure:
        break;
    case ServerBackendLoopCaseForTests::shutdown:
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = now(),
        });
        break;
    case ServerBackendLoopCaseForTests::missing_rx_datagram:
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = now(),
        });
        break;
    case ServerBackendLoopCaseForTests::idle_timeout_then_shutdown:
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::idle_timeout,
            .now = now(),
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = now(),
        });
        break;
    case ServerBackendLoopCaseForTests::timer_event_then_shutdown:
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = now(),
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = now(),
        });
        break;
    case ServerBackendLoopCaseForTests::rx_datagram_then_shutdown:
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = now(),
            .datagram =
                QuicIoRxDatagram{
                    .route_handle = QuicRouteHandle{17},
                    .bytes = make_unsupported_version_long_header_datagram_for_tests(),
                },
        });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = now(),
        });
        break;
    case ServerBackendLoopCaseForTests::pending_work_failure_then_shutdown: {
        document_root.write_file("large.bin",
                                 std::string(static_cast<std::size_t>(64) * 1024U, 'x'));
        QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        });
        const auto update = endpoint.on_core_result(
            single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());
        endpoints.emplace(QuicConnectionHandle{7}, ServerConnectionEndpointState{
                                                       .endpoint = std::move(endpoint),
                                                       .has_pending_work = update.has_pending_work,
                                                   });
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = now(),
        });
        break;
    }
    case ServerBackendLoopCaseForTests::live_pending_work_sends_response_then_shutdown: {
        constexpr QuicRouteHandle kLiveRouteHandle = 17;
        if (!seed_live_backend_response_for_tests(document_root, config, core, transport_state,
                                                  endpoints, *backend_ptr, kLiveRouteHandle)
                 .has_value()) {
            break;
        }
        backend_ptr->wait_results.push_back(QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = now(),
        });
        break;
    }
    }

    return collect_server_backend_loop_result_for_tests(
        config, core, transport_state, endpoints, *backend_ptr,
        capture_server_backend_loop_initial_state_for_tests(endpoints, *backend_ptr));
}

} // namespace test

#if defined(__clang__)
#pragma clang attribute pop
#endif

} // namespace coquic::http09
