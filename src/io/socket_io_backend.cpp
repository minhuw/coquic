#include "src/io/socket_io_backend.h"

#include "src/io/io_backend_test_hooks.h"
#include "src/io/poll_io_engine.h"
#include "src/io/shared_udp_backend_core.h"
#include "src/io/socket_io_backend_internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
#include <utility>

namespace coquic::io {

namespace internal {

test::SocketIoBackendOpsOverride make_default_socket_io_backend_ops() {
    return test::SocketIoBackendOpsOverride{
        .socket_fn = ::socket,
        .bind_fn = ::bind,
        .poll_fn = ::poll,
        .setsockopt_fn = ::setsockopt,
        .sendto_fn = ::sendto,
        .sendmsg_fn = ::sendmsg,
        .recvfrom_fn = ::recvfrom,
        .recvmsg_fn = ::recvmsg,
        .getaddrinfo_fn = ::getaddrinfo,
        .freeaddrinfo_fn = ::freeaddrinfo,
        .gethostname_fn = ::gethostname,
    };
}

test::SocketIoBackendOpsOverride &socket_io_backend_ops_state() {
    static thread_local auto ops = make_default_socket_io_backend_ops();
    return ops;
}

void apply_socket_io_backend_ops_override(const test::SocketIoBackendOpsOverride &override_ops) {
    auto &ops = socket_io_backend_ops_state();
    if (override_ops.socket_fn != nullptr) {
        ops.socket_fn = override_ops.socket_fn;
    }
    if (override_ops.bind_fn != nullptr) {
        ops.bind_fn = override_ops.bind_fn;
    }
    if (override_ops.poll_fn != nullptr) {
        ops.poll_fn = override_ops.poll_fn;
    }
    if (override_ops.setsockopt_fn != nullptr) {
        ops.setsockopt_fn = override_ops.setsockopt_fn;
    }
    if (override_ops.sendto_fn != nullptr) {
        ops.sendto_fn = override_ops.sendto_fn;
    }
    if (override_ops.sendmsg_fn != nullptr) {
        ops.sendmsg_fn = override_ops.sendmsg_fn;
    }
    if (override_ops.recvfrom_fn != nullptr) {
        ops.recvfrom_fn = override_ops.recvfrom_fn;
    }
    if (override_ops.recvmsg_fn != nullptr) {
        ops.recvmsg_fn = override_ops.recvmsg_fn;
    }
    if (override_ops.getaddrinfo_fn != nullptr) {
        ops.getaddrinfo_fn = override_ops.getaddrinfo_fn;
    }
    if (override_ops.freeaddrinfo_fn != nullptr) {
        ops.freeaddrinfo_fn = override_ops.freeaddrinfo_fn;
    }
    if (override_ops.gethostname_fn != nullptr) {
        ops.gethostname_fn = override_ops.gethostname_fn;
    }
}

bool has_legacy_sendto_override() {
    const auto defaults = make_default_socket_io_backend_ops();
    return socket_io_backend_ops_state().sendto_fn != defaults.sendto_fn &&
           socket_io_backend_ops_state().sendmsg_fn == defaults.sendmsg_fn;
}

bool has_legacy_recvfrom_override() {
    const auto defaults = make_default_socket_io_backend_ops();
    return socket_io_backend_ops_state().recvfrom_fn != defaults.recvfrom_fn &&
           socket_io_backend_ops_state().recvmsg_fn == defaults.recvmsg_fn;
}

} // namespace internal

SocketIoBackend::SocketIoBackend(QuicUdpBackendConfig config)
    : core_(std::make_unique<SharedUdpBackendCore>(std::move(config),
                                                   std::make_unique<PollIoEngine>())) {
}

SocketIoBackend::~SocketIoBackend() = default;

std::optional<QuicIoRemote> SocketIoBackend::resolve_remote(std::string_view host,
                                                            std::uint16_t port) {
    return core_->resolve_remote(host, port);
}

bool SocketIoBackend::open_listener(std::string_view host, std::uint16_t port) {
    return core_->open_listener(host, port);
}

std::optional<QuicRouteHandle> SocketIoBackend::ensure_route(const QuicIoRemote &remote) {
    return core_->ensure_route(remote);
}

std::optional<QuicIoEvent> SocketIoBackend::wait(std::optional<QuicCoreTimePoint> next_wakeup) {
    return core_->wait(next_wakeup);
}

bool SocketIoBackend::send(const QuicIoTxDatagram &datagram) {
    return core_->send(datagram);
}

std::unique_ptr<QuicIoBackend> make_socket_io_backend(SocketIoBackendConfig config) {
    return std::make_unique<SocketIoBackend>(std::move(config));
}

namespace test {

namespace {

struct RecordedSendToForTests {
    int calls = 0;
    int socket_fd = -1;
    std::uint16_t peer_port = 0;
};

thread_local RecordedSendToForTests g_recorded_sendto_for_tests;

struct MultiSocketBackendTestTrace {
    std::vector<int> opened_families;
    std::vector<int> opened_fds;
    nfds_t last_poll_descriptor_count = 0;
    int last_send_socket_fd = -1;
    int readable_socket_fd = -1;
};

thread_local MultiSocketBackendTestTrace g_multi_socket_backend_test_trace;

ssize_t record_sendto_for_tests(int socket_fd, const void *, size_t length, int,
                                const sockaddr *destination, socklen_t destination_len) {
    g_recorded_sendto_for_tests.calls += 1;
    g_recorded_sendto_for_tests.socket_fd = socket_fd;
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
    return static_cast<ssize_t>(length);
}

int record_socket_family_and_open(int family, int type, int protocol) {
    g_multi_socket_backend_test_trace.opened_families.push_back(family);
    const int fd = ::socket(family, type, protocol);
    if (fd >= 0) {
        g_multi_socket_backend_test_trace.opened_fds.push_back(fd);
    }
    return fd;
}

int record_poll_descriptor_count_and_second_readable(pollfd *descriptors, nfds_t descriptor_count,
                                                     int) {
    g_multi_socket_backend_test_trace.last_poll_descriptor_count = descriptor_count;
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        descriptors[index].revents = 0;
        if (descriptors[index].fd == g_multi_socket_backend_test_trace.readable_socket_fd) {
            descriptors[index].revents = POLLIN;
        }
    }
    return g_multi_socket_backend_test_trace.readable_socket_fd >= 0 ? 1 : 0;
}

ssize_t record_sendto_socket_fd_for_backend_tests(int socket_fd, const void *, size_t length, int,
                                                  const sockaddr *, socklen_t) {
    g_multi_socket_backend_test_trace.last_send_socket_fd = socket_fd;
    return static_cast<ssize_t>(length);
}

ssize_t recvmsg_for_backend_tests(int socket_fd, msghdr *message, int) {
    if (message == nullptr || message->msg_iov == nullptr || message->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    constexpr std::array<std::byte, 2> kPayload = {
        std::byte{0x01},
        std::byte{0x02},
    };
    std::memcpy(message->msg_iov[0].iov_base, kPayload.data(), kPayload.size());

    if (socket_fd == g_multi_socket_backend_test_trace.readable_socket_fd) {
        sockaddr_in6 peer{};
        peer.sin6_family = AF_INET6;
        peer.sin6_port = htons(9443);
        peer.sin6_addr = in6addr_loopback;
        if (message->msg_name != nullptr &&
            message->msg_namelen >= static_cast<socklen_t>(sizeof(peer))) {
            std::memcpy(message->msg_name, &peer, sizeof(peer));
            message->msg_namelen = sizeof(peer);
        }
    } else {
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(8443);
        peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (message->msg_name != nullptr &&
            message->msg_namelen >= static_cast<socklen_t>(sizeof(peer))) {
            std::memcpy(message->msg_name, &peer, sizeof(peer));
            message->msg_namelen = sizeof(peer);
        }
    }
    message->msg_controllen = 0;
    return static_cast<ssize_t>(kPayload.size());
}

sockaddr_storage make_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return peer;
}

} // namespace

SocketIoBackendOpsOverride &socket_io_backend_ops_for_runtime_tests() {
    return internal::socket_io_backend_ops_state();
}

void socket_io_backend_apply_ops_override_for_runtime_tests(
    const SocketIoBackendOpsOverride &override_ops) {
    internal::apply_socket_io_backend_ops_override(override_ops);
}

bool socket_io_backend_has_legacy_sendto_override_for_runtime_tests() {
    return internal::has_legacy_sendto_override();
}

bool socket_io_backend_has_legacy_recvfrom_override_for_runtime_tests() {
    return internal::has_legacy_recvfrom_override();
}

ScopedSocketIoBackendOpsOverride::ScopedSocketIoBackendOpsOverride(
    SocketIoBackendOpsOverride override_ops)
    : previous_(internal::socket_io_backend_ops_state()) {
    internal::apply_socket_io_backend_ops_override(override_ops);
}

ScopedSocketIoBackendOpsOverride::~ScopedSocketIoBackendOpsOverride() {
    internal::socket_io_backend_ops_state() = previous_;
}

bool socket_io_backend_send_uses_route_handle_for_tests() {
    g_recorded_sendto_for_tests = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    };

    SocketIoBackend backend(QuicUdpBackendConfig{
        .role_name = "server",
    });
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    const auto first_peer = make_loopback_peer(8443);
    const auto second_peer = make_loopback_peer(9443);

    const auto first = backend.ensure_route(QuicIoRemote{
        .peer = first_peer,
        .peer_len = peer_len,
        .family = AF_INET,
    });
    const auto second = backend.ensure_route(QuicIoRemote{
        .peer = second_peer,
        .peer_len = peer_len,
        .family = AF_INET,
    });
    if (!first.has_value() || !second.has_value()) {
        return false;
    }

    const bool sent = backend.send(QuicIoTxDatagram{
        .route_handle = *second,
        .bytes = {std::byte{0xaa}},
    });
    return sent && g_recorded_sendto_for_tests.calls == 1 &&
           g_recorded_sendto_for_tests.peer_port == 9443;
}

bool socket_io_backend_wait_returns_second_route_datagram_for_tests() {
    g_multi_socket_backend_test_trace = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .socket_fn = &record_socket_family_and_open,
            .poll_fn = &record_poll_descriptor_count_and_second_readable,
            .recvmsg_fn = &recvmsg_for_backend_tests,
        },
    };

    SocketIoBackend backend(QuicUdpBackendConfig{
        .role_name = "client",
        .idle_timeout_ms = 5,
    });

    sockaddr_storage first_peer{};
    auto &first_ipv4 = *reinterpret_cast<sockaddr_in *>(&first_peer);
    first_ipv4.sin_family = AF_INET;
    first_ipv4.sin_port = htons(8443);
    first_ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sockaddr_storage second_peer{};
    auto &second_ipv6 = *reinterpret_cast<sockaddr_in6 *>(&second_peer);
    second_ipv6.sin6_family = AF_INET6;
    second_ipv6.sin6_port = htons(9443);
    second_ipv6.sin6_addr = in6addr_loopback;

    const auto first = backend.ensure_route(QuicIoRemote{
        .peer = first_peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });
    const auto second = backend.ensure_route(QuicIoRemote{
        .peer = second_peer,
        .peer_len = sizeof(sockaddr_in6),
        .family = AF_INET6,
    });
    if (!first.has_value() || !second.has_value()) {
        return false;
    }

    if (g_multi_socket_backend_test_trace.opened_fds.size() < 2) {
        return false;
    }
    g_multi_socket_backend_test_trace.readable_socket_fd =
        g_multi_socket_backend_test_trace.opened_fds[1];

    const auto event = backend.wait(std::nullopt);
    return event.has_value() && event->kind == QuicIoEvent::Kind::rx_datagram &&
           event->datagram.has_value() && event->datagram->route_handle == *second &&
           g_multi_socket_backend_test_trace.last_poll_descriptor_count == 2u;
}

bool io_backend_route_handles_are_stable_for_tests(QuicIoBackendKind kind) {
    switch (kind) {
    case QuicIoBackendKind::socket:
        return socket_io_backend_route_handles_are_stable_per_peer_tuple_for_tests();
    case QuicIoBackendKind::io_uring:
        return false;
    }
    return false;
}

bool io_backend_send_uses_route_handle_for_tests(QuicIoBackendKind kind) {
    switch (kind) {
    case QuicIoBackendKind::socket:
        return socket_io_backend_send_uses_route_handle_for_tests();
    case QuicIoBackendKind::io_uring:
        return false;
    }
    return false;
}

bool io_backend_wait_returns_second_route_datagram_for_tests(QuicIoBackendKind kind) {
    switch (kind) {
    case QuicIoBackendKind::socket:
        return socket_io_backend_wait_returns_second_route_datagram_for_tests();
    case QuicIoBackendKind::io_uring:
        return false;
    }
    return false;
}

} // namespace test

} // namespace coquic::io
