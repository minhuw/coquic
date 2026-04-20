#include "src/io/io_uring_backend.h"

#include "src/io/io_backend_test_hooks.h"
#include "src/io/io_uring_io_engine.h"
#include "src/io/shared_udp_backend_core.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <deque>
#include <initializer_list>
#include <limits>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include <liburing.h>

namespace coquic::io {

IoUringBackend::IoUringBackend(QuicUdpBackendConfig config, std::unique_ptr<QuicIoEngine> engine)
    : core_(std::make_unique<SharedUdpBackendCore>(std::move(config), std::move(engine))) {
}

IoUringBackend::~IoUringBackend() = default;

std::unique_ptr<IoUringBackend> IoUringBackend::create(QuicUdpBackendConfig config) {
    auto engine = make_io_uring_io_engine();
    if (engine == nullptr) {
        return nullptr;
    }
    return std::unique_ptr<IoUringBackend>(
        new IoUringBackend(std::move(config), std::move(engine)));
}

std::optional<QuicIoRemote> IoUringBackend::resolve_remote(std::string_view host,
                                                           std::uint16_t port) {
    return core_->resolve_remote(host, port);
}

bool IoUringBackend::open_listener(std::string_view host, std::uint16_t port) {
    return core_->open_listener(host, port);
}

std::optional<QuicRouteHandle> IoUringBackend::ensure_route(const QuicIoRemote &remote) {
    return core_->ensure_route(remote);
}

std::optional<QuicIoEvent> IoUringBackend::wait(std::optional<QuicCoreTimePoint> next_wakeup) {
    return core_->wait(next_wakeup);
}

bool IoUringBackend::send(const QuicIoTxDatagram &datagram) {
    return core_->send(datagram);
}

std::unique_ptr<IoUringBackend> make_io_uring_backend(QuicUdpBackendConfig config) {
    return IoUringBackend::create(std::move(config));
}

namespace test {

namespace {

using quic::QuicEcnCodepoint;

struct ScriptedCompletion {
    std::uint64_t user_data = 0;
    int res = 0;
    int socket_fd = -1;
    std::vector<std::byte> payload;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
};

struct IoUringTestHarness {
    io_uring_sqe sqe{};
    std::deque<ScriptedCompletion> completions;
    std::unordered_map<int, msghdr *> receive_messages_by_fd;
    std::unordered_map<int, int> receive_arm_count_by_fd;
    int send_submit_calls = 0;
    int last_send_socket_fd = -1;
    std::uint16_t last_send_peer_port = 0;
    io_uring_cqe cqe{};
};

struct IoUringTestConfig {
    int queue_init_rc = 0;
    bool get_sqe_returns_null = false;
    int submit_recv_rc = 0;
    int submit_send_rc = 0;
    int wait_cqe_rc_when_empty = -EAGAIN;
    int wait_cqe_timeout_rc_when_empty = -ETIME;
    bool fail_socket_open = false;
    bool force_zero_last_send_peer_port = false;
    bool suppress_receive_arm_counter = false;
    bool suppress_fallback_sendto_counter = false;
    bool suppress_fallback_poll_counter = false;
    bool force_receive_ecn_unavailable = false;
    bool suppress_received_payload_copy = false;
};

thread_local IoUringTestHarness g_io_uring_test_harness;
thread_local IoUringTestConfig g_io_uring_test_config;
thread_local std::vector<int> g_opened_fds_for_tests;
thread_local int g_fallback_sendto_calls_for_tests = 0;
thread_local int g_fallback_poll_calls_for_tests = 0;

void reset_io_uring_test_harness() {
    g_io_uring_test_harness = {};
    g_opened_fds_for_tests.clear();
    g_fallback_sendto_calls_for_tests = 0;
    g_fallback_poll_calls_for_tests = 0;
}

bool all_true(std::initializer_list<bool> conditions) {
    return std::count(conditions.begin(), conditions.end(), false) == 0;
}

int cqe_result_or(const io_uring_cqe *cqe, int fallback) {
    return cqe == nullptr ? fallback : cqe->res;
}

std::uint16_t peer_port_from_msghdr(const msghdr *message) {
    if (message == nullptr || message->msg_name == nullptr) {
        return 0;
    }

    const auto *address = reinterpret_cast<const sockaddr *>(message->msg_name);
    if (address->sa_family == AF_INET &&
        message->msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        return ntohs(reinterpret_cast<const sockaddr_in *>(address)->sin_port);
    }
    if (address->sa_family == AF_INET6 &&
        message->msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        return ntohs(reinterpret_cast<const sockaddr_in6 *>(address)->sin6_port);
    }
    return 0;
}

void apply_scripted_receive_to_message(msghdr &message, const ScriptedCompletion &completion) {
    if (completion.res < 0) {
        return;
    }

    const auto effective_ecn = g_io_uring_test_config.force_receive_ecn_unavailable
                                   ? QuicEcnCodepoint::unavailable
                                   : completion.ecn;

    if (!g_io_uring_test_config.suppress_received_payload_copy && message.msg_iov != nullptr &&
        message.msg_iovlen > 0 && message.msg_iov[0].iov_base != nullptr) {
        const auto completion_size = static_cast<std::size_t>(completion.res);
        const auto bytes_to_copy =
            std::min({completion.payload.size(),
                      static_cast<std::size_t>(message.msg_iov[0].iov_len), completion_size});
        std::memcpy(message.msg_iov[0].iov_base, completion.payload.data(), bytes_to_copy);
    }

    if (message.msg_name != nullptr &&
        message.msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        std::memcpy(message.msg_name, &completion.peer, sizeof(sockaddr_storage));
        message.msg_namelen = completion.peer_len;
    }

    if (message.msg_control == nullptr || message.msg_controllen < CMSG_SPACE(sizeof(int))) {
        return;
    }
    if (effective_ecn == QuicEcnCodepoint::unavailable) {
        message.msg_controllen = 0;
        return;
    }

    std::memset(message.msg_control, 0, message.msg_controllen);
    auto *header = reinterpret_cast<cmsghdr *>(message.msg_control);
    const bool ipv6 = completion.peer.ss_family == AF_INET6;
    header->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
    header->cmsg_type = ipv6 ? IPV6_TCLASS : IP_TOS;
    header->cmsg_len = CMSG_LEN(sizeof(int));

    const int traffic_class =
        socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests(effective_ecn);
    std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
    message.msg_controllen = header->cmsg_len;
}

void enqueue_receive_completion_for_tests(int socket_fd, std::span<const std::byte> payload,
                                          const sockaddr_storage &peer, socklen_t peer_len,
                                          QuicEcnCodepoint ecn) {
    g_io_uring_test_harness.completions.push_back(ScriptedCompletion{
        .user_data = static_cast<std::uint64_t>(socket_fd),
        .res = static_cast<int>(payload.size()),
        .socket_fd = socket_fd,
        .payload = std::vector<std::byte>(payload.begin(), payload.end()),
        .peer = peer,
        .peer_len = peer_len,
        .ecn = ecn,
    });
}

void enqueue_receive_error_completion_for_tests(int socket_fd, int error_code) {
    g_io_uring_test_harness.completions.push_back(ScriptedCompletion{
        .user_data = static_cast<std::uint64_t>(socket_fd),
        .res = error_code < 0 ? error_code : -error_code,
        .socket_fd = socket_fd,
    });
}

int queue_init_success_for_tests(unsigned, io_uring *, unsigned) {
    return g_io_uring_test_config.queue_init_rc;
}

void queue_exit_noop_for_tests(io_uring *) {
}

io_uring_sqe *get_sqe_for_tests(io_uring *) {
    if (g_io_uring_test_config.get_sqe_returns_null) {
        return nullptr;
    }
    g_io_uring_test_harness.sqe = {};
    return &g_io_uring_test_harness.sqe;
}

int submit_for_tests(io_uring *) {
    const auto opcode = g_io_uring_test_harness.sqe.opcode;
    if (opcode == IORING_OP_RECVMSG) {
        const int socket_fd = g_io_uring_test_harness.sqe.fd;
        auto *message = std::bit_cast<msghdr *>(g_io_uring_test_harness.sqe.addr);
        g_io_uring_test_harness.receive_messages_by_fd[socket_fd] = message;
        if (!g_io_uring_test_config.suppress_receive_arm_counter) {
            g_io_uring_test_harness.receive_arm_count_by_fd[socket_fd] += 1;
        }
        return g_io_uring_test_config.submit_recv_rc;
    }

    if (opcode == IORING_OP_SENDMSG) {
        const int socket_fd = g_io_uring_test_harness.sqe.fd;
        const auto *message = std::bit_cast<const msghdr *>(g_io_uring_test_harness.sqe.addr);
        g_io_uring_test_harness.send_submit_calls += 1;
        g_io_uring_test_harness.last_send_socket_fd = socket_fd;
        g_io_uring_test_harness.last_send_peer_port =
            g_io_uring_test_config.force_zero_last_send_peer_port ? 0
                                                                  : peer_port_from_msghdr(message);

        if (g_io_uring_test_config.submit_send_rc != 0) {
            return g_io_uring_test_config.submit_send_rc;
        }

        const int bytes = message != nullptr && message->msg_iov != nullptr
                              ? static_cast<int>(message->msg_iov[0].iov_len)
                              : 0;
        g_io_uring_test_harness.completions.push_back(ScriptedCompletion{
            .user_data = g_io_uring_test_harness.sqe.user_data,
            .res = bytes,
        });
        return 0;
    }

    return 0;
}

int wait_cqe_for_tests(io_uring *, io_uring_cqe **cqe_ptr) {
    if (g_io_uring_test_harness.completions.empty()) {
        *cqe_ptr = nullptr;
        errno = g_io_uring_test_config.wait_cqe_rc_when_empty < 0
                    ? -g_io_uring_test_config.wait_cqe_rc_when_empty
                    : 0;
        return g_io_uring_test_config.wait_cqe_rc_when_empty;
    }

    const auto completion = g_io_uring_test_harness.completions.front();
    g_io_uring_test_harness.completions.pop_front();

    if (completion.socket_fd >= 0 && completion.res >= 0) {
        const auto message_it =
            g_io_uring_test_harness.receive_messages_by_fd.find(completion.socket_fd);
        if (message_it != g_io_uring_test_harness.receive_messages_by_fd.end() &&
            message_it->second != nullptr) {
            apply_scripted_receive_to_message(*message_it->second, completion);
        }
    }

    g_io_uring_test_harness.cqe = {};
    g_io_uring_test_harness.cqe.user_data = completion.user_data;
    g_io_uring_test_harness.cqe.res = completion.res;
    *cqe_ptr = &g_io_uring_test_harness.cqe;
    return 0;
}

int wait_cqe_timeout_for_tests(io_uring *ring, io_uring_cqe **cqe_ptr, int) {
    if (g_io_uring_test_harness.completions.empty()) {
        *cqe_ptr = nullptr;
        errno = g_io_uring_test_config.wait_cqe_timeout_rc_when_empty < 0
                    ? -g_io_uring_test_config.wait_cqe_timeout_rc_when_empty
                    : 0;
        return g_io_uring_test_config.wait_cqe_timeout_rc_when_empty;
    }
    return wait_cqe_for_tests(ring, cqe_ptr);
}

void cqe_seen_noop_for_tests(io_uring *, io_uring_cqe *) {
}

IoUringBackendOpsOverride io_uring_ops_for_tests() {
    return IoUringBackendOpsOverride{
        .queue_init_fn = &queue_init_success_for_tests,
        .queue_exit_fn = &queue_exit_noop_for_tests,
        .get_sqe_fn = &get_sqe_for_tests,
        .submit_fn = &submit_for_tests,
        .wait_cqe_fn = &wait_cqe_for_tests,
        .wait_cqe_timeout_ms_fn = &wait_cqe_timeout_for_tests,
        .cqe_seen_fn = &cqe_seen_noop_for_tests,
    };
}

int record_socket_family_and_open_for_tests(int family, int type, int protocol) {
    if (g_io_uring_test_config.fail_socket_open) {
        errno = EMFILE;
        return -1;
    }
    const int fd = ::socket(family, type, protocol);
    if (fd >= 0) {
        g_opened_fds_for_tests.push_back(fd);
    }
    return fd;
}

ssize_t sendto_success_for_tests(int, const void *, size_t length, int, const sockaddr *,
                                 socklen_t) {
    if (!g_io_uring_test_config.suppress_fallback_sendto_counter) {
        g_fallback_sendto_calls_for_tests += 1;
    }
    return static_cast<ssize_t>(length);
}

int poll_idle_for_tests(pollfd *fds, nfds_t count, int) {
    if (!g_io_uring_test_config.suppress_fallback_poll_counter) {
        g_fallback_poll_calls_for_tests += 1;
    }
    for (nfds_t index = 0; index < count; ++index) {
        fds[index].revents = 0;
    }
    return 0;
}

sockaddr_storage make_ipv4_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return peer;
}

sockaddr_storage make_ipv6_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(port);
    ipv6.sin6_addr = in6addr_loopback;
    return peer;
}

} // namespace

bool io_uring_backend_route_handles_are_stable_per_peer_tuple_for_tests() {
    reset_io_uring_test_harness();
    const ScopedIoUringBackendOpsOverride io_uring_ops{io_uring_ops_for_tests()};

    auto backend = make_io_uring_backend(QuicUdpBackendConfig{
        .role_name = "server",
    });
    if (backend == nullptr) {
        return false;
    }

    const auto peer = make_ipv4_loopback_peer(4433);
    const auto first = backend->ensure_route(QuicIoRemote{
        .peer = peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });
    const auto second = backend->ensure_route(QuicIoRemote{
        .peer = peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });

    return all_true({
        first.has_value(),
        second.has_value(),
        first == second,
    });
}

bool io_uring_backend_send_uses_route_handle_for_tests() {
    reset_io_uring_test_harness();
    const ScopedIoUringBackendOpsOverride io_uring_ops{io_uring_ops_for_tests()};

    auto backend = make_io_uring_backend(QuicUdpBackendConfig{
        .role_name = "client",
    });
    if (backend == nullptr) {
        return false;
    }

    const auto first_peer = make_ipv4_loopback_peer(8443);
    const auto second_peer = make_ipv4_loopback_peer(9443);

    const auto first = backend->ensure_route(QuicIoRemote{
        .peer = first_peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });
    const auto second = backend->ensure_route(QuicIoRemote{
        .peer = second_peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });
    if (!all_true({
            first.has_value(),
            second.has_value(),
        })) {
        return false;
    }
    const auto second_route = second.value_or(0);

    const bool sent = backend->send(QuicIoTxDatagram{
        .route_handle = second_route,
        .bytes = {std::byte{0x42}},
    });
    return all_true({
        sent,
        g_io_uring_test_harness.send_submit_calls == 1,
        g_io_uring_test_harness.last_send_peer_port == 9443,
    });
}

bool io_uring_backend_wait_returns_second_route_datagram_for_tests() {
    reset_io_uring_test_harness();
    const ScopedIoUringBackendOpsOverride io_uring_ops{io_uring_ops_for_tests()};
    const ScopedSocketIoBackendOpsOverride socket_ops{
        SocketIoBackendOpsOverride{
            .socket_fn = &record_socket_family_and_open_for_tests,
        },
    };

    auto backend = make_io_uring_backend(QuicUdpBackendConfig{
        .role_name = "client",
        .idle_timeout_ms = 5,
    });
    if (backend == nullptr) {
        return false;
    }

    const auto first_peer = make_ipv4_loopback_peer(8443);
    const auto second_peer = make_ipv6_loopback_peer(9443);

    const auto first = backend->ensure_route(QuicIoRemote{
        .peer = first_peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });
    const auto second = backend->ensure_route(QuicIoRemote{
        .peer = second_peer,
        .peer_len = sizeof(sockaddr_in6),
        .family = AF_INET6,
    });
    if (!all_true({
            first.has_value(),
            second.has_value(),
            g_opened_fds_for_tests.size() >= 2,
        })) {
        return false;
    }
    const auto second_route = second.value_or(0);

    constexpr std::array<std::byte, 2> kPayload = {
        std::byte{0x11},
        std::byte{0x22},
    };
    const int second_socket_fd = g_opened_fds_for_tests[1];
    enqueue_receive_completion_for_tests(second_socket_fd, kPayload, second_peer,
                                         sizeof(sockaddr_in6), QuicEcnCodepoint::not_ect);

    const auto event = backend->wait(std::nullopt);
    const auto observed = event.value_or(QuicIoEvent{});
    const auto datagram = observed.datagram.value_or(QuicIoRxDatagram{});
    return all_true({
        event.has_value(),
        observed.kind == QuicIoEvent::Kind::rx_datagram,
        observed.datagram.has_value(),
        datagram.route_handle == second_route,
        datagram.bytes.size() == kPayload.size(),
        g_io_uring_test_harness.receive_arm_count_by_fd[second_socket_fd] >= 2,
    });
}

bool io_uring_backend_rearms_receive_after_completion_for_tests() {
    reset_io_uring_test_harness();
    const ScopedIoUringBackendOpsOverride io_uring_ops{io_uring_ops_for_tests()};

    auto engine = IoUringIoEngine::create();
    if (engine == nullptr) {
        return false;
    }

    constexpr int socket_fd = 77;
    if (!engine->register_socket(socket_fd) ||
        g_io_uring_test_harness.receive_arm_count_by_fd[socket_fd] != 1) {
        return false;
    }

    constexpr std::array<std::byte, 2> kPayload = {
        std::byte{0x01},
        std::byte{0x02},
    };
    const auto peer = make_ipv4_loopback_peer(7443);
    enqueue_receive_completion_for_tests(socket_fd, kPayload, peer, sizeof(sockaddr_in),
                                         QuicEcnCodepoint::ect0);

    const std::array<int, 1> sockets = {
        socket_fd,
    };
    const auto event = engine->wait(sockets, 5, std::nullopt, "client");
    const auto observed = event.value_or(QuicIoEngineEvent{});
    const auto rx = observed.rx.value_or(QuicIoEngineRxCompletion{});
    return all_true({
        event.has_value(),
        observed.kind == QuicIoEngineEvent::Kind::rx_datagram,
        observed.rx.has_value(),
        rx.socket_fd == socket_fd,
        rx.bytes.size() == kPayload.size(),
        rx.ecn == QuicEcnCodepoint::ect0,
        g_io_uring_test_harness.receive_arm_count_by_fd[socket_fd] == 2,
    });
}

bool io_uring_backend_completion_error_is_fatal_for_tests() {
    reset_io_uring_test_harness();
    const ScopedIoUringBackendOpsOverride io_uring_ops{io_uring_ops_for_tests()};

    auto engine = IoUringIoEngine::create();
    if (engine == nullptr) {
        return false;
    }

    constexpr int socket_fd = 88;
    if (!engine->register_socket(socket_fd)) {
        return false;
    }

    enqueue_receive_error_completion_for_tests(socket_fd, -ECONNRESET);

    const std::array<int, 1> sockets = {
        socket_fd,
    };
    const auto event = engine->wait(sockets, 5, std::nullopt, "client");
    const bool second_registration_rejected = !engine->register_socket(socket_fd + 1);
    return all_true({
        !event.has_value(),
        second_registration_rejected,
    });
}

bool io_uring_backend_send_falls_back_after_recv_einval_for_tests() {
    reset_io_uring_test_harness();
    const ScopedIoUringBackendOpsOverride io_uring_ops{io_uring_ops_for_tests()};
    const ScopedSocketIoBackendOpsOverride socket_ops{
        SocketIoBackendOpsOverride{
            .poll_fn = &poll_idle_for_tests,
            .sendto_fn = &sendto_success_for_tests,
        },
    };

    auto engine = IoUringIoEngine::create();
    if (engine == nullptr) {
        return false;
    }

    constexpr int socket_fd = 99;
    if (!engine->register_socket(socket_fd)) {
        return false;
    }

    enqueue_receive_error_completion_for_tests(socket_fd, -EINVAL);

    const std::array<int, 1> sockets = {
        socket_fd,
    };
    const auto event = engine->wait(sockets, 5, std::nullopt, "client");
    const auto observed = event.value_or(QuicIoEngineEvent{});
    if (!all_true({
            event.has_value(),
            observed.kind == QuicIoEngineEvent::Kind::idle_timeout,
            g_fallback_poll_calls_for_tests == 1,
        })) {
        return false;
    }

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x5a},
    };
    const auto peer = make_ipv4_loopback_peer(9443);
    const bool sent = engine->send(socket_fd, peer, sizeof(sockaddr_in), kPayload, "client",
                                   QuicEcnCodepoint::not_ect);
    return all_true({
        sent,
        g_fallback_sendto_calls_for_tests == 1,
        g_io_uring_test_harness.send_submit_calls == 0,
    });
}

bool io_uring_backend_wait_without_completion_yields_idle_timeout_for_tests() {
    reset_io_uring_test_harness();
    const ScopedIoUringBackendOpsOverride io_uring_ops{io_uring_ops_for_tests()};

    auto engine = IoUringIoEngine::create();
    if (engine == nullptr) {
        return false;
    }

    constexpr int socket_fd = 111;
    if (!engine->register_socket(socket_fd)) {
        return false;
    }

    const std::array<int, 1> sockets = {
        socket_fd,
    };
    const auto event = engine->wait(sockets, 5, std::nullopt, "client");
    const auto observed = event.value_or(QuicIoEngineEvent{});
    return all_true({
        event.has_value(),
        observed.kind == QuicIoEngineEvent::Kind::idle_timeout,
    });
}

bool io_uring_backend_wait_prefers_ready_receive_over_due_timer_for_tests() {
    reset_io_uring_test_harness();
    const ScopedIoUringBackendOpsOverride io_uring_ops{io_uring_ops_for_tests()};

    auto engine = IoUringIoEngine::create();
    if (engine == nullptr) {
        return false;
    }

    constexpr int socket_fd = 112;
    if (!engine->register_socket(socket_fd)) {
        return false;
    }

    constexpr std::array<std::byte, 2> kPayload = {
        std::byte{0x11},
        std::byte{0x22},
    };
    const auto peer = make_ipv4_loopback_peer(9443);
    enqueue_receive_completion_for_tests(socket_fd, kPayload, peer, sizeof(sockaddr_in),
                                         QuicEcnCodepoint::not_ect);

    const std::array<int, 1> sockets = {
        socket_fd,
    };
    const auto event = engine->wait(sockets, 5, quic::QuicCoreClock::now(), "client");
    const auto observed = event.value_or(QuicIoEngineEvent{});
    const auto rx = observed.rx.value_or(QuicIoEngineRxCompletion{});
    const auto expected_bytes = std::vector<std::byte>(kPayload.begin(), kPayload.end());
    return all_true({
        event.has_value(),
        observed.kind == QuicIoEngineEvent::Kind::rx_datagram,
        observed.rx.has_value(),
        rx.socket_fd == socket_fd,
        rx.ecn == QuicEcnCodepoint::not_ect,
        rx.bytes == expected_bytes,
    });
}

bool io_uring_backend_internal_coverage_hook_exercises_cold_paths_for_tests() {
    const auto saved_config = g_io_uring_test_config;
    const auto reset_for_case = [] {
        g_io_uring_test_config = {};
        reset_io_uring_test_harness();
    };

    bool ok = true;
    const auto record = [&](bool condition, const char *) { ok &= condition; };
    reset_for_case();

    record(peer_port_from_msghdr(nullptr) == 0, "peer_port null");

    msghdr message{};
    record(peer_port_from_msghdr(&message) == 0, "peer_port missing_name");

    auto ipv6_peer = make_ipv6_loopback_peer(6443);
    message.msg_name = &ipv6_peer;
    message.msg_namelen = sizeof(sockaddr_in6);
    record(peer_port_from_msghdr(&message) == 6443, "peer_port ipv6");

    sockaddr_storage unknown_peer{};
    reinterpret_cast<sockaddr *>(&unknown_peer)->sa_family = AF_UNSPEC;
    message.msg_name = &unknown_peer;
    message.msg_namelen = sizeof(unknown_peer);
    record(peer_port_from_msghdr(&message) == 0, "peer_port unknown_family");

    ScriptedCompletion completion{
        .res = -EIO,
    };
    apply_scripted_receive_to_message(message, completion);

    std::array<std::byte, 1> payload_storage = {
        std::byte{0x00},
    };
    iovec iov{
        .iov_base = payload_storage.data(),
        .iov_len = payload_storage.size(),
    };
    std::array<std::byte, CMSG_SPACE(sizeof(int))> control_storage = {
        std::byte{0x00},
    };
    auto ipv4_peer = make_ipv4_loopback_peer(7443);
    completion = ScriptedCompletion{
        .res = 1,
        .payload = {std::byte{0x01}},
        .peer = ipv4_peer,
        .peer_len = sizeof(sockaddr_in),
        .ecn = QuicEcnCodepoint::ect0,
    };

    message = {};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_name = &ipv4_peer;
    message.msg_namelen = sizeof(sockaddr_storage);
    apply_scripted_receive_to_message(message, completion);

    message = {};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_name = &ipv4_peer;
    message.msg_namelen = sizeof(sockaddr_storage);
    message.msg_control = control_storage.data();
    message.msg_controllen = control_storage.size();
    g_io_uring_test_config.force_receive_ecn_unavailable = true;
    apply_scripted_receive_to_message(message, completion);
    record(message.msg_controllen == 0, "receive unavailable ecn");
    g_io_uring_test_config.force_receive_ecn_unavailable = false;

    g_io_uring_test_harness.sqe = {};
    g_io_uring_test_harness.sqe.opcode = 0;
    record(submit_for_tests(nullptr) == 0, "submit default opcode");

    io_uring_cqe *cqe = reinterpret_cast<io_uring_cqe *>(1);
    const bool wait_empty = wait_cqe_for_tests(nullptr, &cqe) == -EAGAIN;
    record(all_true({
               wait_empty,
               cqe == nullptr,
           }),
           "wait empty");

    reset_for_case();
    g_io_uring_test_config.queue_init_rc = -EPERM;
    record(!io_uring_backend_route_handles_are_stable_per_peer_tuple_for_tests(),
           "queue_init route_stable");
    record(!io_uring_backend_send_uses_route_handle_for_tests(), "queue_init send_route");
    record(!io_uring_backend_wait_returns_second_route_datagram_for_tests(),
           "queue_init wait_second_route");
    record(!io_uring_backend_rearms_receive_after_completion_for_tests(), "queue_init rearm");
    record(!io_uring_backend_completion_error_is_fatal_for_tests(), "queue_init completion_error");
    record(!io_uring_backend_send_falls_back_after_recv_einval_for_tests(),
           "queue_init recv_einval");
    record(!io_uring_backend_wait_without_completion_yields_idle_timeout_for_tests(),
           "queue_init idle_timeout");
    record(!io_uring_backend_wait_prefers_ready_receive_over_due_timer_for_tests(),
           "queue_init ready_over_timer");

    reset_for_case();
    g_io_uring_test_config.fail_socket_open = true;
    record(!io_uring_backend_wait_returns_second_route_datagram_for_tests(),
           "socket_fail wait_second_route");

    reset_for_case();
    g_io_uring_test_config.get_sqe_returns_null = true;
    record(!io_uring_backend_send_uses_route_handle_for_tests(), "null_sqe send_route");
    record(!io_uring_backend_rearms_receive_after_completion_for_tests(), "null_sqe rearm");
    record(!io_uring_backend_completion_error_is_fatal_for_tests(), "null_sqe completion_error");
    record(!io_uring_backend_send_falls_back_after_recv_einval_for_tests(), "null_sqe recv_einval");
    record(!io_uring_backend_wait_without_completion_yields_idle_timeout_for_tests(),
           "null_sqe idle_timeout");
    record(!io_uring_backend_wait_prefers_ready_receive_over_due_timer_for_tests(),
           "null_sqe ready_over_timer");

    reset_for_case();
    g_io_uring_test_config.force_zero_last_send_peer_port = true;
    record(!io_uring_backend_send_uses_route_handle_for_tests(), "wrong_peer_port send_route");

    reset_for_case();
    g_io_uring_test_config.suppress_receive_arm_counter = true;
    record(!io_uring_backend_wait_returns_second_route_datagram_for_tests(),
           "suppress_arm_count wait_second_route");
    record(!io_uring_backend_rearms_receive_after_completion_for_tests(),
           "suppress_arm_count rearm");

    reset_for_case();
    g_io_uring_test_config.suppress_fallback_poll_counter = true;
    record(!io_uring_backend_send_falls_back_after_recv_einval_for_tests(),
           "suppress_poll_counter recv_einval");

    reset_for_case();
    g_io_uring_test_config.suppress_fallback_sendto_counter = true;
    record(!io_uring_backend_send_falls_back_after_recv_einval_for_tests(),
           "suppress_sendto_counter recv_einval");

    reset_for_case();
    g_io_uring_test_config.suppress_received_payload_copy = true;
    record(!io_uring_backend_wait_prefers_ready_receive_over_due_timer_for_tests(),
           "suppress_payload_copy ready_over_timer");

    g_io_uring_test_config = saved_config;
    reset_io_uring_test_harness();
    return ok;
}

bool io_uring_backend_internal_coverage_hook_exercises_remaining_branches_for_tests() {
    const auto saved_config = g_io_uring_test_config;
    const auto reset_for_case = [] {
        g_io_uring_test_config = {};
        reset_io_uring_test_harness();
    };

    bool ok = true;
    const auto record = [&](bool condition, const char *) { ok &= condition; };

    reset_for_case();

    msghdr message{};
    const auto ipv4_peer = make_ipv4_loopback_peer(5443);
    message.msg_name = const_cast<sockaddr_storage *>(&ipv4_peer);
    message.msg_namelen = sizeof(sockaddr_in);
    record(peer_port_from_msghdr(&message) == 5443, "peer_port ipv4");

    message.msg_namelen = sizeof(sockaddr_in) - 1;
    record(peer_port_from_msghdr(&message) == 0, "peer_port ipv4 truncated");

    const auto ipv6_peer = make_ipv6_loopback_peer(6443);
    message.msg_name = const_cast<sockaddr_storage *>(&ipv6_peer);
    message.msg_namelen = sizeof(sockaddr_in6) - 1;
    record(peer_port_from_msghdr(&message) == 0, "peer_port ipv6 truncated");

    std::array<std::byte, 1> payload_storage = {
        std::byte{0x00},
    };
    iovec iov{
        .iov_base = payload_storage.data(),
        .iov_len = payload_storage.size(),
    };
    iovec null_iov{
        .iov_base = nullptr,
        .iov_len = payload_storage.size(),
    };
    std::array<std::byte, CMSG_SPACE(sizeof(int))> control_storage = {
        std::byte{0x00},
    };
    std::array<std::byte, 1> small_control = {
        std::byte{0x00},
    };
    sockaddr_storage name_storage{};
    auto completion = ScriptedCompletion{
        .res = 1,
        .payload = {std::byte{0x7a}},
        .peer = ipv4_peer,
        .peer_len = sizeof(sockaddr_in),
        .ecn = QuicEcnCodepoint::ect0,
    };

    message = {};
    apply_scripted_receive_to_message(message, completion);
    record(payload_storage[0] == std::byte{0x00}, "receive missing iov");

    message = {};
    message.msg_iov = &iov;
    message.msg_iovlen = 0;
    apply_scripted_receive_to_message(message, completion);
    record(payload_storage[0] == std::byte{0x00}, "receive zero iovlen");

    message = {};
    message.msg_iov = &null_iov;
    message.msg_iovlen = 1;
    apply_scripted_receive_to_message(message, completion);
    record(payload_storage[0] == std::byte{0x00}, "receive null iov base");

    message = {};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_name = &name_storage;
    message.msg_namelen = sizeof(sockaddr_in);
    apply_scripted_receive_to_message(message, completion);
    record(message.msg_namelen == sizeof(sockaddr_in), "receive short name len");

    message = {};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_name = &name_storage;
    message.msg_namelen = sizeof(sockaddr_storage);
    message.msg_control = small_control.data();
    message.msg_controllen = small_control.size();
    apply_scripted_receive_to_message(message, completion);
    record(message.msg_controllen == small_control.size(), "receive small control");

    completion.peer = ipv6_peer;
    completion.peer_len = sizeof(sockaddr_in6);
    completion.ecn = QuicEcnCodepoint::ect1;
    message = {};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_name = &name_storage;
    message.msg_namelen = sizeof(sockaddr_storage);
    message.msg_control = control_storage.data();
    message.msg_controllen = control_storage.size();
    apply_scripted_receive_to_message(message, completion);
    auto *header = reinterpret_cast<cmsghdr *>(message.msg_control);
    int traffic_class = 0;
    const auto *traffic_class_data = control_storage.data() + CMSG_ALIGN(sizeof(cmsghdr));
    std::memcpy(&traffic_class, traffic_class_data, sizeof(traffic_class));
    record(all_true({
               header->cmsg_level == IPPROTO_IPV6,
               header->cmsg_type == IPV6_TCLASS,
               traffic_class == socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests(
                                    QuicEcnCodepoint::ect1),
           }),
           "receive ipv6 control");

    reset_for_case();

    msghdr send_message{};
    g_io_uring_test_harness.sqe = {};
    g_io_uring_test_harness.sqe.opcode = IORING_OP_SENDMSG;
    g_io_uring_test_harness.sqe.addr = static_cast<decltype(g_io_uring_test_harness.sqe.addr)>(
        reinterpret_cast<std::uintptr_t>(&send_message));
    g_io_uring_test_config.submit_send_rc = -EIO;
    record(submit_for_tests(nullptr) == -EIO, "submit send error");

    g_io_uring_test_config.submit_send_rc = 0;
    g_io_uring_test_harness.completions.clear();
    g_io_uring_test_harness.sqe.addr = 0;
    record(all_true({
               submit_for_tests(nullptr) == 0,
               !g_io_uring_test_harness.completions.empty(),
               g_io_uring_test_harness.completions.back().res == 0,
           }),
           "submit send null message");

    g_io_uring_test_harness.completions.clear();
    send_message = {};
    g_io_uring_test_harness.sqe.addr = static_cast<decltype(g_io_uring_test_harness.sqe.addr)>(
        reinterpret_cast<std::uintptr_t>(&send_message));
    record(all_true({
               submit_for_tests(nullptr) == 0,
               !g_io_uring_test_harness.completions.empty(),
               g_io_uring_test_harness.completions.back().res == 0,
           }),
           "submit send null iov");

    reset_for_case();

    io_uring_cqe *cqe = reinterpret_cast<io_uring_cqe *>(1);
    g_io_uring_test_config.wait_cqe_rc_when_empty = 0;
    record(all_true({
               wait_cqe_for_tests(nullptr, &cqe) == 0,
               cqe == nullptr,
               cqe_result_or(cqe, 0) == 0,
               errno == 0,
           }),
           "wait empty nonnegative");

    cqe = reinterpret_cast<io_uring_cqe *>(1);
    g_io_uring_test_config.wait_cqe_timeout_rc_when_empty = 0;
    record(all_true({
               wait_cqe_timeout_for_tests(nullptr, &cqe, 1) == 0,
               cqe == nullptr,
               cqe_result_or(cqe, 0) == 0,
               errno == 0,
           }),
           "wait timeout empty nonnegative");

    reset_for_case();

    g_io_uring_test_harness.completions.push_back(ScriptedCompletion{
        .user_data = 11,
        .res = 1,
        .socket_fd = 7,
    });
    cqe = nullptr;
    const auto wait_without_message_entry = wait_cqe_for_tests(nullptr, &cqe);
    record(all_true({
               wait_without_message_entry == 0,
               cqe != nullptr,
               cqe_result_or(cqe, 0) == 1,
           }),
           "wait completion without message entry");

    reset_for_case();

    g_io_uring_test_harness.receive_messages_by_fd[7] = nullptr;
    g_io_uring_test_harness.completions.push_back(ScriptedCompletion{
        .user_data = 12,
        .res = 1,
        .socket_fd = 7,
    });
    cqe = nullptr;
    const auto wait_with_null_message_entry = wait_cqe_for_tests(nullptr, &cqe);
    record(all_true({
               wait_with_null_message_entry == 0,
               cqe != nullptr,
               cqe_result_or(cqe, 0) == 1,
           }),
           "wait completion with null message entry");

    reset_for_case();

    g_io_uring_test_harness.completions.push_back(ScriptedCompletion{
        .user_data = 13,
        .res = -EIO,
        .socket_fd = 7,
    });
    cqe = nullptr;
    const auto wait_negative_result = wait_cqe_for_tests(nullptr, &cqe);
    record(all_true({
               wait_negative_result == 0,
               cqe != nullptr,
               cqe_result_or(cqe, 0) == -EIO,
           }),
           "wait completion negative result");

    reset_for_case();

    enqueue_receive_error_completion_for_tests(9, EIO);
    cqe = nullptr;
    const auto wait_receive_error = wait_cqe_for_tests(nullptr, &cqe);
    record(all_true({
               wait_receive_error == 0,
               cqe != nullptr,
               cqe_result_or(cqe, 0) == -EIO,
           }),
           "enqueue receive error normalizes positive errno");

    reset_for_case();
    record(all_true({
               record_socket_family_and_open_for_tests(-1, SOCK_DGRAM, 0) == -1,
               g_opened_fds_for_tests.empty(),
           }),
           "record socket invalid family");

    g_io_uring_test_config = saved_config;
    reset_io_uring_test_harness();
    return ok;
}

} // namespace test

} // namespace coquic::io
