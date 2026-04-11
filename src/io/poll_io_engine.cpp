#include "src/io/poll_io_engine.h"

#include "src/io/socket_io_backend_internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>

namespace coquic::io {

using quic::QuicCoreClock;
using quic::QuicEcnCodepoint;

namespace {

constexpr std::size_t kMaxDatagramBytes = 65535;

bool is_ect_codepoint(QuicEcnCodepoint ecn) {
    return ecn == QuicEcnCodepoint::ect0 || ecn == QuicEcnCodepoint::ect1;
}

} // namespace

namespace internal {

quic::QuicCoreTimePoint now() {
    return QuicCoreClock::now();
}

int linux_traffic_class_for_ecn(QuicEcnCodepoint ecn) {
    switch (ecn) {
    case QuicEcnCodepoint::ect0:
        return 0x02;
    case QuicEcnCodepoint::ect1:
        return 0x01;
    case QuicEcnCodepoint::ce:
        return 0x03;
    case QuicEcnCodepoint::unavailable:
    case QuicEcnCodepoint::not_ect:
        return 0x00;
    }
    return 0x00;
}

QuicEcnCodepoint ecn_from_linux_traffic_class(int traffic_class) {
    switch (traffic_class & 0x03) {
    case 0x01:
        return QuicEcnCodepoint::ect1;
    case 0x02:
        return QuicEcnCodepoint::ect0;
    case 0x03:
        return QuicEcnCodepoint::ce;
    default:
        return QuicEcnCodepoint::not_ect;
    }
}

bool is_ipv4_mapped_ipv6_address(const sockaddr_storage &peer, socklen_t peer_len) {
    if (peer.ss_family != AF_INET6 || peer_len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        return false;
    }

    const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(&peer);
    return IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr);
}

QuicEcnCodepoint recvmsg_ecn_from_control(const msghdr &message) {
#if defined(__linux__)
    if ((message.msg_flags & MSG_CTRUNC) != 0) {
        return QuicEcnCodepoint::unavailable;
    }
    for (auto *control = CMSG_FIRSTHDR(&message); control != nullptr;
         control = CMSG_NXTHDR(const_cast<msghdr *>(&message), control)) {
        if ((control->cmsg_level == IPPROTO_IP && control->cmsg_type == IP_TOS) ||
            (control->cmsg_level == IPPROTO_IPV6 && control->cmsg_type == IPV6_TCLASS)) {
            int traffic_class = 0;
            const auto payload_size =
                control->cmsg_len > CMSG_LEN(0) ? control->cmsg_len - CMSG_LEN(0) : 0;
            std::memcpy(&traffic_class, CMSG_DATA(control),
                        std::min<std::size_t>(sizeof(traffic_class), payload_size));
            return ecn_from_linux_traffic_class(traffic_class);
        }
    }
#else
    static_cast<void>(message);
#endif
    return QuicEcnCodepoint::unavailable;
}

bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name, QuicEcnCodepoint ecn) {
    const auto *buffer = reinterpret_cast<const void *>(datagram.data());
    const bool use_sendmsg = !has_legacy_sendto_override() && is_ect_codepoint(ecn) &&
                             peer_len > 0 &&
                             (peer.ss_family == AF_INET || peer.ss_family == AF_INET6);
    if (!use_sendmsg) {
        const ssize_t sent = socket_io_backend_ops_state().sendto_fn(
            fd, buffer, datagram.size(), 0, reinterpret_cast<const sockaddr *>(&peer), peer_len);
        if (sent >= 0) {
            return true;
        }

        std::cerr << "io-" << role_name << " failed: sendto error: " << std::strerror(errno)
                  << '\n';
        return false;
    }

    iovec iov{
        .iov_base = const_cast<void *>(buffer),
        .iov_len = datagram.size(),
    };
    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
    msghdr message{};
    message.msg_name = const_cast<sockaddr *>(reinterpret_cast<const sockaddr *>(&peer));
    message.msg_namelen = peer_len;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();

    auto *header = reinterpret_cast<cmsghdr *>(control.data());
    const bool use_ipv4_traffic_class =
        peer.ss_family == AF_INET || is_ipv4_mapped_ipv6_address(peer, peer_len);
    header->cmsg_level = use_ipv4_traffic_class ? IPPROTO_IP : IPPROTO_IPV6;
    header->cmsg_type = use_ipv4_traffic_class ? IP_TOS : IPV6_TCLASS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    const int traffic_class = linux_traffic_class_for_ecn(ecn);
    std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
    message.msg_controllen = header->cmsg_len;

    const ssize_t sent = socket_io_backend_ops_state().sendmsg_fn(fd, &message, 0);
    if (sent >= 0) {
        return true;
    }

    std::cerr << "io-" << role_name << " failed: sendmsg error: " << std::strerror(errno) << '\n';
    return false;
}

ReceiveDatagramResult receive_datagram(int socket_fd, std::string_view role_name, int flags) {
    std::vector<std::byte> inbound(kMaxDatagramBytes);
    sockaddr_storage source{};
    socklen_t source_len = sizeof(source);
    QuicEcnCodepoint inbound_ecn = QuicEcnCodepoint::unavailable;
    ssize_t bytes_read = 0;
    do {
        if (has_legacy_recvfrom_override()) {
            bytes_read = socket_io_backend_ops_state().recvfrom_fn(
                socket_fd, inbound.data(), inbound.size(), flags,
                reinterpret_cast<sockaddr *>(&source), &source_len);
        } else {
            std::array<std::byte, 256> control{};
            iovec iov{
                .iov_base = inbound.data(),
                .iov_len = inbound.size(),
            };
            msghdr message{};
            message.msg_name = &source;
            message.msg_namelen = sizeof(source);
            message.msg_iov = &iov;
            message.msg_iovlen = 1;
            message.msg_control = control.data();
            message.msg_controllen = control.size();
            bytes_read = socket_io_backend_ops_state().recvmsg_fn(socket_fd, &message, flags);
            source_len = static_cast<socklen_t>(message.msg_namelen);
            if (bytes_read >= 0) {
                inbound_ecn = recvmsg_ecn_from_control(message);
            }
        }
    } while (bytes_read < 0 && errno == EINTR);

    if (bytes_read < 0) {
        const bool would_block = (errno == EAGAIN) | (errno == EWOULDBLOCK);
        if (would_block) {
            return ReceiveDatagramResult{
                .status = ReceiveDatagramStatus::would_block,
            };
        }

        std::cerr << "io-" << role_name << " failed: recvmsg error: " << std::strerror(errno)
                  << '\n';
        return ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::error,
        };
    }

    inbound.resize(static_cast<std::size_t>(bytes_read));
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::ok,
        .bytes = std::move(inbound),
        .ecn = inbound_ecn,
        .source = source,
        .source_len = source_len,
        .input_time = now(),
    };
}

} // namespace internal

bool PollIoEngine::register_socket(int socket_fd) {
    static_cast<void>(socket_fd);
    return true;
}

bool PollIoEngine::send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
                        std::span<const std::byte> datagram, std::string_view role_name,
                        quic::QuicEcnCodepoint ecn) {
    return internal::send_datagram(socket_fd, datagram, peer, peer_len, role_name, ecn);
}

std::optional<QuicIoEngineEvent>
PollIoEngine::wait(std::span<const int> socket_fds, int idle_timeout_ms,
                   std::optional<quic::QuicCoreTimePoint> next_wakeup, std::string_view role_name) {
    if (socket_fds.empty()) {
        return std::nullopt;
    }

    const auto current = internal::now();
    int timeout_ms = idle_timeout_ms;
    bool timer_due = false;
    if (next_wakeup.has_value()) {
        if (*next_wakeup <= current) {
            timer_due = true;
            timeout_ms = 0;
        } else {
            const auto remaining = *next_wakeup - current;
            timeout_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              remaining + std::chrono::milliseconds(1))
                                              .count());
        }
    }

    std::vector<pollfd> descriptors(socket_fds.size());
    for (std::size_t index = 0; index < socket_fds.size(); ++index) {
        descriptors[index] = pollfd{
            .fd = socket_fds[index],
            .events = POLLIN,
            .revents = 0,
        };
    }

    int poll_result = 0;
    do {
        poll_result = internal::socket_io_backend_ops_state().poll_fn(
            descriptors.data(), descriptors.size(), timeout_ms);
    } while (poll_result < 0 && errno == EINTR);

    if (poll_result < 0) {
        if (errno == ECANCELED) {
            return QuicIoEngineEvent{
                .kind = QuicIoEngineEvent::Kind::shutdown,
                .now = internal::now(),
            };
        }
        return std::nullopt;
    }

    if (poll_result == 0) {
        if (next_wakeup.has_value()) {
            return QuicIoEngineEvent{
                .kind = QuicIoEngineEvent::Kind::timer_expired,
                .now = timer_due ? current : internal::now(),
            };
        }
        return QuicIoEngineEvent{
            .kind = QuicIoEngineEvent::Kind::idle_timeout,
            .now = internal::now(),
        };
    }

    for (const auto &descriptor : descriptors) {
        if ((descriptor.revents & POLLIN) == 0) {
            continue;
        }

        auto received = internal::receive_datagram(descriptor.fd, role_name, 0);
        if (received.status == internal::ReceiveDatagramStatus::would_block) {
            continue;
        }
        if (received.status != internal::ReceiveDatagramStatus::ok) {
            return std::nullopt;
        }

        return QuicIoEngineEvent{
            .kind = QuicIoEngineEvent::Kind::rx_datagram,
            .now = received.input_time,
            .rx =
                QuicIoEngineRxCompletion{
                    .socket_fd = descriptor.fd,
                    .bytes = std::move(received.bytes),
                    .ecn = received.ecn,
                    .peer = received.source,
                    .peer_len = received.source_len,
                    .now = received.input_time,
                },
        };
    }

    if (std::any_of(descriptors.begin(), descriptors.end(),
                    [](const pollfd &descriptor) { return descriptor.revents != 0; })) {
        return std::nullopt;
    }

    return std::nullopt;
}

namespace test {

namespace {

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
        const int traffic_class =
            internal::linux_traffic_class_for_ecn(g_recorded_recvmsg_for_tests.ecn);
        std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
        message->msg_controllen = header->cmsg_len;
    }

    return static_cast<ssize_t>(bytes_to_copy);
}

} // namespace

int socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests(QuicEcnCodepoint ecn) {
    return internal::linux_traffic_class_for_ecn(ecn);
}

QuicEcnCodepoint
socket_io_backend_ecn_from_linux_traffic_class_for_runtime_tests(int traffic_class) {
    return internal::ecn_from_linux_traffic_class(traffic_class);
}

bool socket_io_backend_is_ipv4_mapped_ipv6_address_for_runtime_tests(const sockaddr_storage &peer,
                                                                     socklen_t peer_len) {
    return internal::is_ipv4_mapped_ipv6_address(peer, peer_len);
}

QuicEcnCodepoint
socket_io_backend_recvmsg_ecn_from_control_for_runtime_tests(const msghdr &message) {
    return internal::recvmsg_ecn_from_control(message);
}

bool socket_io_backend_send_datagram_for_runtime_tests(int fd, std::span<const std::byte> datagram,
                                                       const sockaddr_storage &peer,
                                                       socklen_t peer_len,
                                                       std::string_view role_name,
                                                       QuicEcnCodepoint ecn) {
    return internal::send_datagram(fd, datagram, peer, peer_len, role_name, ecn);
}

SocketIoBackendReceiveDatagramResultForTests
socket_io_backend_receive_datagram_for_runtime_tests(int socket_fd, std::string_view role_name,
                                                     int flags) {
    const auto received = internal::receive_datagram(socket_fd, role_name, flags);
    switch (received.status) {
    case internal::ReceiveDatagramStatus::ok:
        return SocketIoBackendReceiveDatagramResultForTests{
            .status = SocketIoBackendReceiveDatagramStatusForTests::ok,
            .bytes = received.bytes,
            .ecn = received.ecn,
            .source = received.source,
            .source_len = received.source_len,
        };
    case internal::ReceiveDatagramStatus::would_block:
        return SocketIoBackendReceiveDatagramResultForTests{
            .status = SocketIoBackendReceiveDatagramStatusForTests::would_block,
        };
    case internal::ReceiveDatagramStatus::error:
        return SocketIoBackendReceiveDatagramResultForTests{
            .status = SocketIoBackendReceiveDatagramStatusForTests::error,
        };
    }
    return SocketIoBackendReceiveDatagramResultForTests{
        .status = SocketIoBackendReceiveDatagramStatusForTests::error,
    };
}

bool socket_io_backend_sendmsg_uses_outbound_ecn_for_tests() {
    g_recorded_sendmsg_for_tests = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .sendmsg_fn = &record_sendmsg_for_tests,
        },
    };
    const std::array<std::byte, 1> datagram = {
        std::byte{0x01},
    };

    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4433);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    const bool sent =
        internal::send_datagram(17, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in)),
                                "client", QuicEcnCodepoint::ect1);
    return sent && g_recorded_sendmsg_for_tests.calls == 1 &&
           g_recorded_sendmsg_for_tests.socket_fd == 17 &&
           g_recorded_sendmsg_for_tests.level == IPPROTO_IP &&
           g_recorded_sendmsg_for_tests.type == IP_TOS &&
           g_recorded_sendmsg_for_tests.traffic_class == 0x01;
}

bool socket_io_backend_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests() {
    g_recorded_sendmsg_for_tests = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .sendmsg_fn = &record_sendmsg_for_tests,
        },
    };
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

    const bool sent =
        internal::send_datagram(23, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in6)),
                                "server", QuicEcnCodepoint::ect1);
    return sent && g_recorded_sendmsg_for_tests.calls == 1 &&
           g_recorded_sendmsg_for_tests.socket_fd == 23 &&
           g_recorded_sendmsg_for_tests.level == IPPROTO_IP &&
           g_recorded_sendmsg_for_tests.type == IP_TOS &&
           g_recorded_sendmsg_for_tests.traffic_class == 0x01;
}

bool socket_io_backend_recvmsg_maps_ecn_for_tests() {
    g_recorded_recvmsg_for_tests = {};
    g_recorded_recvmsg_for_tests.ecn = QuicEcnCodepoint::ce;
    g_recorded_recvmsg_for_tests.bytes = {std::byte{0xaa}, std::byte{0xbb}};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&g_recorded_recvmsg_for_tests.peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(6121);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);

    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .recvmsg_fn = &record_recvmsg_for_tests,
        },
    };

    const auto received = internal::receive_datagram(29, "client", 0);
    return received.status == internal::ReceiveDatagramStatus::ok &&
           received.bytes == g_recorded_recvmsg_for_tests.bytes &&
           received.ecn == QuicEcnCodepoint::ce;
}

} // namespace test

} // namespace coquic::io
