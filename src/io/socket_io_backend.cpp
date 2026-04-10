#include "src/io/socket_io_backend.h"

#include "src/io/io_backend_test_hooks.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace coquic::io {

using quic::QuicCoreClock;
using quic::QuicCoreTimePoint;
using quic::QuicEcnCodepoint;
using quic::QuicRouteHandle;

namespace {

constexpr std::size_t kMaxDatagramBytes = 65535;

struct ResolvedUdpAddress {
    sockaddr_storage address{};
    socklen_t address_len = 0;
    int family = AF_UNSPEC;
};

struct UdpAddressResolutionQuery {
    std::string_view host;
    std::uint16_t port = 0;
    int extra_flags = 0;
    int family = AF_UNSPEC;
};

struct SocketIoRoute {
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

struct SocketIoSocket {
    int fd = -1;
    int family = AF_UNSPEC;
};

struct SocketIoRouteState {
    std::unordered_map<std::string, QuicRouteHandle> route_handles_by_peer_tuple;
    std::unordered_map<QuicRouteHandle, SocketIoRoute> routes_by_handle;
    QuicRouteHandle next_route_handle = 1;
};

enum class ReceiveDatagramStatus : std::uint8_t {
    ok,
    would_block,
    error,
};

struct ReceiveDatagramResult {
    ReceiveDatagramStatus status = ReceiveDatagramStatus::would_block;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
    sockaddr_storage source{};
    socklen_t source_len = 0;
    QuicCoreTimePoint input_time{};
};

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

QuicCoreTimePoint now() {
    return QuicCoreClock::now();
}

bool is_ect_codepoint(QuicEcnCodepoint ecn) {
    return ecn == QuicEcnCodepoint::ect0 || ecn == QuicEcnCodepoint::ect1;
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

struct LinuxSocketDescriptor {
    int fd = -1;
};

bool configure_linux_ecn_socket_options(LinuxSocketDescriptor socket, int family) {
#if defined(__linux__)
    const auto set_bool_socket_option = [&](int level, int name) {
        const int enabled = 1;
        return socket_io_backend_ops_state().setsockopt_fn(socket.fd, level, name, &enabled,
                                                           sizeof(enabled)) == 0;
    };

    if (family == AF_INET || family == AF_INET6) {
        if (!set_bool_socket_option(IPPROTO_IP, IP_RECVTOS)) {
            return false;
        }
    }
    if (family == AF_INET6) {
        if (!set_bool_socket_option(IPPROTO_IPV6, IPV6_RECVTCLASS)) {
            return false;
        }
    }
#else
    static_cast<void>(socket);
    static_cast<void>(family);
#endif
    return true;
}

int open_udp_socket(int family) {
    const int fd = socket_io_backend_ops_state().socket_fn(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return fd;
    }

    if (family == AF_INET6) {
        const int disabled = 0;
        if (socket_io_backend_ops_state().setsockopt_fn(fd, IPPROTO_IPV6, IPV6_V6ONLY, &disabled,
                                                        sizeof(disabled)) != 0) {
            const int option_errno = errno;
            ::close(fd);
            errno = option_errno;
            return -1;
        }
    }

    if (!configure_linux_ecn_socket_options(LinuxSocketDescriptor{.fd = fd}, family)) {
        const int option_errno = errno;
        ::close(fd);
        errno = option_errno;
        return -1;
    }

    return fd;
}

int preferred_udp_address_family(std::string_view host) {
    const auto host_string = std::string(host);

    in_addr ipv4_address{};
    if (::inet_pton(AF_INET, host_string.c_str(), &ipv4_address) == 1) {
        return AF_INET;
    }

    in6_addr ipv6_address{};
    if (::inet_pton(AF_INET6, host_string.c_str(), &ipv6_address) == 1) {
        return AF_INET6;
    }

    return AF_UNSPEC;
}

bool copy_udp_address(const addrinfo &result, ResolvedUdpAddress &resolved) {
    if (result.ai_addr == nullptr || result.ai_addrlen <= 0 ||
        result.ai_addrlen > static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        return false;
    }
    if (result.ai_family != AF_INET && result.ai_family != AF_INET6) {
        return false;
    }

    resolved = {};
    std::memcpy(&resolved.address, result.ai_addr, static_cast<std::size_t>(result.ai_addrlen));
    resolved.address_len = result.ai_addrlen;
    resolved.family = result.ai_family;
    return true;
}

bool resolve_udp_address(UdpAddressResolutionQuery query, ResolvedUdpAddress &resolved) {
    const int preferred_family =
        query.family != AF_UNSPEC ? query.family : preferred_udp_address_family(query.host);

    addrinfo hints{};
    hints.ai_family = preferred_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV | query.extra_flags;

    addrinfo *results = nullptr;
    const auto service = std::to_string(query.port);
    const auto host_string = std::string(query.host);
    const char *node = query.host.empty() ? nullptr : host_string.c_str();
    const int status =
        socket_io_backend_ops_state().getaddrinfo_fn(node, service.c_str(), &hints, &results);
    const bool resolution_failed = status != 0;
    const bool missing_results = results == nullptr;
    if (resolution_failed || missing_results) {
        if (results != nullptr) {
            socket_io_backend_ops_state().freeaddrinfo_fn(results);
        }
        return false;
    }

    const bool prefer_ipv4_result = preferred_family == AF_UNSPEC;
    addrinfo *selected = nullptr;
    if (prefer_ipv4_result) {
        for (auto *result = results; result != nullptr; result = result->ai_next) {
            if (result->ai_family == AF_INET) {
                selected = result;
                break;
            }
        }
    }
    if (selected == nullptr) {
        selected = results;
    }

    for (auto *result = selected; result != nullptr; result = result->ai_next) {
        if (copy_udp_address(*result, resolved)) {
            socket_io_backend_ops_state().freeaddrinfo_fn(results);
            return true;
        }
    }

    if (selected != results) {
        for (auto *result = results; result != selected; result = result->ai_next) {
            if (copy_udp_address(*result, resolved)) {
                socket_io_backend_ops_state().freeaddrinfo_fn(results);
                return true;
            }
        }
    }

    socket_io_backend_ops_state().freeaddrinfo_fn(results);
    return false;
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
                   socklen_t peer_len, std::string_view role_name,
                   QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect) {
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

std::string peer_tuple_key(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len) {
    const auto encoded_peer_len =
        std::min<std::size_t>(static_cast<std::size_t>(peer_len), sizeof(sockaddr_storage));
    std::string key(sizeof(socket_fd) + sizeof(encoded_peer_len) + encoded_peer_len, '\0');
    std::size_t offset = 0;
    std::memcpy(key.data() + offset, &socket_fd, sizeof(socket_fd));
    offset += sizeof(socket_fd);
    std::memcpy(key.data() + offset, &encoded_peer_len, sizeof(encoded_peer_len));
    offset += sizeof(encoded_peer_len);
    std::memcpy(key.data() + offset, &peer, encoded_peer_len);
    return key;
}

QuicRouteHandle remember_route_handle(SocketIoRouteState &state, const sockaddr_storage &peer,
                                      socklen_t peer_len, int socket_fd) {
    const auto key = peer_tuple_key(socket_fd, peer, peer_len);
    const auto existing = state.route_handles_by_peer_tuple.find(key);
    const auto handle = existing != state.route_handles_by_peer_tuple.end()
                            ? existing->second
                            : state.next_route_handle++;
    if (existing == state.route_handles_by_peer_tuple.end()) {
        state.route_handles_by_peer_tuple.emplace(key, handle);
    }
    state.routes_by_handle[handle] = SocketIoRoute{
        .socket_fd = socket_fd,
        .peer = peer,
        .peer_len = peer_len,
    };
    return handle;
}

struct RecordedSendToForTests {
    int calls = 0;
    int socket_fd = -1;
    std::uint16_t peer_port = 0;
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

sockaddr_storage make_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return peer;
}

} // namespace

struct SocketIoBackend::Impl {
    explicit Impl(SocketIoBackendConfig backend_config) : config(std::move(backend_config)) {
    }

    ~Impl() {
        for (const auto &socket : sockets) {
            if (socket.fd >= 0) {
                ::close(socket.fd);
            }
        }
    }

    int socket_fd_for_family(int family) const {
        const auto socket_it =
            std::find_if(sockets.begin(), sockets.end(),
                         [&](const SocketIoSocket &socket) { return socket.family == family; });
        return socket_it != sockets.end() ? socket_it->fd : -1;
    }

    SocketIoBackendConfig config;
    std::vector<SocketIoSocket> sockets;
    SocketIoRouteState route_state;
};

SocketIoBackend::SocketIoBackend(SocketIoBackendConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {
}

SocketIoBackend::~SocketIoBackend() = default;

std::optional<QuicIoRemote> SocketIoBackend::resolve_remote(std::string_view host,
                                                            std::uint16_t port) {
    ResolvedUdpAddress resolved{};
    if (!resolve_udp_address(
            UdpAddressResolutionQuery{
                .host = host,
                .port = port,
            },
            resolved)) {
        return std::nullopt;
    }

    return QuicIoRemote{
        .peer = resolved.address,
        .peer_len = resolved.address_len,
        .family = resolved.family,
    };
}

bool SocketIoBackend::open_listener(std::string_view host, std::uint16_t port) {
    ResolvedUdpAddress bind_address{};
    if (!resolve_udp_address(
            UdpAddressResolutionQuery{
                .host = host,
                .port = port,
                .extra_flags = AI_PASSIVE,
                .family = preferred_udp_address_family(host),
            },
            bind_address)) {
        std::cerr << "io-" << impl_->config.role_name << " failed: invalid host address\n";
        return false;
    }

    const int socket_fd = open_udp_socket(bind_address.family);
    if (socket_fd < 0) {
        std::cerr << "io-" << impl_->config.role_name
                  << " failed: unable to create UDP socket: " << std::strerror(errno) << '\n';
        return false;
    }

    if (socket_io_backend_ops_state().bind_fn(
            socket_fd, reinterpret_cast<const sockaddr *>(&bind_address.address),
            bind_address.address_len) != 0) {
        const int bind_errno = errno;
        ::close(socket_fd);
        errno = bind_errno;
        std::cerr << "io-" << impl_->config.role_name
                  << " failed: unable to bind UDP socket: " << std::strerror(errno) << '\n';
        return false;
    }

    impl_->sockets.push_back(SocketIoSocket{
        .fd = socket_fd,
        .family = bind_address.family,
    });
    return true;
}

std::optional<QuicRouteHandle> SocketIoBackend::ensure_route(const QuicIoRemote &remote) {
    if (remote.peer_len <= 0 ||
        remote.peer_len > static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        return std::nullopt;
    }

    const int route_family = remote.family != AF_UNSPEC ? remote.family : remote.peer.ss_family;
    if (route_family != AF_INET && route_family != AF_INET6) {
        return std::nullopt;
    }

    int socket_fd = impl_->socket_fd_for_family(route_family);
    if (socket_fd < 0) {
        const int socket_fd = open_udp_socket(route_family);
        if (socket_fd < 0) {
            return std::nullopt;
        }
        impl_->sockets.push_back(SocketIoSocket{
            .fd = socket_fd,
            .family = route_family,
        });
        return remember_route_handle(impl_->route_state, remote.peer, remote.peer_len, socket_fd);
    }

    return remember_route_handle(impl_->route_state, remote.peer, remote.peer_len, socket_fd);
}

std::optional<QuicIoEvent> SocketIoBackend::wait(std::optional<QuicCoreTimePoint> next_wakeup) {
    if (impl_->sockets.empty()) {
        return std::nullopt;
    }

    const auto current = now();
    int timeout_ms = impl_->config.idle_timeout_ms;
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

    std::vector<pollfd> descriptors(impl_->sockets.size());
    for (std::size_t index = 0; index < impl_->sockets.size(); ++index) {
        descriptors[index] = pollfd{
            .fd = impl_->sockets[index].fd,
            .events = POLLIN,
            .revents = 0,
        };
    }
    int poll_result = 0;
    do {
        poll_result = socket_io_backend_ops_state().poll_fn(descriptors.data(), descriptors.size(),
                                                            timeout_ms);
    } while (poll_result < 0 && errno == EINTR);

    if (poll_result < 0) {
        if (errno == ECANCELED) {
            return QuicIoEvent{
                .kind = QuicIoEvent::Kind::shutdown,
                .now = now(),
            };
        }
        return std::nullopt;
    }

    if (poll_result == 0) {
        if (next_wakeup.has_value()) {
            return QuicIoEvent{
                .kind = QuicIoEvent::Kind::timer_expired,
                .now = timer_due ? current : now(),
            };
        }
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::idle_timeout,
            .now = now(),
        };
    }

    for (const auto &descriptor : descriptors) {
        if ((descriptor.revents & POLLIN) == 0) {
            continue;
        }

        auto received = receive_datagram(descriptor.fd, impl_->config.role_name, /*flags=*/0);
        if (received.status == ReceiveDatagramStatus::would_block) {
            continue;
        }
        if (received.status != ReceiveDatagramStatus::ok) {
            return std::nullopt;
        }

        const auto handle = remember_route_handle(impl_->route_state, received.source,
                                                  received.source_len, descriptor.fd);
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::rx_datagram,
            .now = received.input_time,
            .datagram =
                QuicIoRxDatagram{
                    .route_handle = handle,
                    .bytes = std::move(received.bytes),
                    .ecn = received.ecn,
                },
        };
    }

    if (std::any_of(descriptors.begin(), descriptors.end(),
                    [](const pollfd &descriptor) { return descriptor.revents != 0; })) {
        return std::nullopt;
    }

    return std::nullopt;
}

bool SocketIoBackend::send(const QuicIoTxDatagram &datagram) {
    const auto route_it = impl_->route_state.routes_by_handle.find(datagram.route_handle);
    if (route_it == impl_->route_state.routes_by_handle.end()) {
        return false;
    }

    return send_datagram(route_it->second.socket_fd, datagram.bytes, route_it->second.peer,
                         route_it->second.peer_len, impl_->config.role_name, datagram.ecn);
}

std::unique_ptr<QuicIoBackend> make_socket_io_backend(SocketIoBackendConfig config) {
    return std::make_unique<SocketIoBackend>(std::move(config));
}

namespace test {

SocketIoBackendOpsOverride &socket_io_backend_ops_for_runtime_tests() {
    return socket_io_backend_ops_state();
}

void socket_io_backend_apply_ops_override_for_runtime_tests(
    const SocketIoBackendOpsOverride &override_ops) {
    apply_socket_io_backend_ops_override(override_ops);
}

bool socket_io_backend_has_legacy_sendto_override_for_runtime_tests() {
    return has_legacy_sendto_override();
}

bool socket_io_backend_has_legacy_recvfrom_override_for_runtime_tests() {
    return has_legacy_recvfrom_override();
}

int socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests(QuicEcnCodepoint ecn) {
    return linux_traffic_class_for_ecn(ecn);
}

QuicEcnCodepoint
socket_io_backend_ecn_from_linux_traffic_class_for_runtime_tests(int traffic_class) {
    return ecn_from_linux_traffic_class(traffic_class);
}

bool socket_io_backend_configure_linux_ecn_socket_options_for_runtime_tests(int socket_fd,
                                                                            int family) {
    return configure_linux_ecn_socket_options(LinuxSocketDescriptor{.fd = socket_fd}, family);
}

bool socket_io_backend_is_ipv4_mapped_ipv6_address_for_runtime_tests(const sockaddr_storage &peer,
                                                                     socklen_t peer_len) {
    return is_ipv4_mapped_ipv6_address(peer, peer_len);
}

QuicEcnCodepoint
socket_io_backend_recvmsg_ecn_from_control_for_runtime_tests(const msghdr &message) {
    return recvmsg_ecn_from_control(message);
}

int socket_io_backend_preferred_udp_address_family_for_runtime_tests(std::string_view host) {
    return preferred_udp_address_family(host);
}

bool socket_io_backend_resolve_udp_address_for_runtime_tests(
    std::string_view host, std::uint16_t port, int extra_flags, int family,
    SocketIoBackendResolvedUdpAddressForTests &resolved) {
    ResolvedUdpAddress backend_resolved{};
    if (!resolve_udp_address(
            UdpAddressResolutionQuery{
                .host = host,
                .port = port,
                .extra_flags = extra_flags,
                .family = family,
            },
            backend_resolved)) {
        return false;
    }

    resolved.address = backend_resolved.address;
    resolved.address_len = backend_resolved.address_len;
    resolved.family = backend_resolved.family;
    return true;
}

int socket_io_backend_open_udp_socket_for_runtime_tests(int family) {
    return open_udp_socket(family);
}

bool socket_io_backend_send_datagram_for_runtime_tests(int fd, std::span<const std::byte> datagram,
                                                       const sockaddr_storage &peer,
                                                       socklen_t peer_len,
                                                       std::string_view role_name,
                                                       QuicEcnCodepoint ecn) {
    return send_datagram(fd, datagram, peer, peer_len, role_name, ecn);
}

SocketIoBackendReceiveDatagramResultForTests
socket_io_backend_receive_datagram_for_runtime_tests(int socket_fd, std::string_view role_name,
                                                     int flags) {
    const auto received = receive_datagram(socket_fd, role_name, flags);
    switch (received.status) {
    case ReceiveDatagramStatus::ok:
        return SocketIoBackendReceiveDatagramResultForTests{
            .status = SocketIoBackendReceiveDatagramStatusForTests::ok,
            .bytes = received.bytes,
            .ecn = received.ecn,
            .source = received.source,
            .source_len = received.source_len,
        };
    case ReceiveDatagramStatus::would_block:
        return SocketIoBackendReceiveDatagramResultForTests{
            .status = SocketIoBackendReceiveDatagramStatusForTests::would_block,
        };
    case ReceiveDatagramStatus::error:
        return SocketIoBackendReceiveDatagramResultForTests{
            .status = SocketIoBackendReceiveDatagramStatusForTests::error,
        };
    }
    return SocketIoBackendReceiveDatagramResultForTests{
        .status = SocketIoBackendReceiveDatagramStatusForTests::error,
    };
}

ScopedSocketIoBackendOpsOverride::ScopedSocketIoBackendOpsOverride(
    SocketIoBackendOpsOverride override_ops)
    : previous_(socket_io_backend_ops_state()) {
    apply_socket_io_backend_ops_override(override_ops);
}

ScopedSocketIoBackendOpsOverride::~ScopedSocketIoBackendOpsOverride() {
    socket_io_backend_ops_state() = previous_;
}

bool socket_io_backend_route_handles_are_stable_per_peer_tuple_for_tests() {
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    SocketIoRouteState state;

    const auto first = remember_route_handle(state, make_loopback_peer(4444), peer_len, 4);
    const auto second = remember_route_handle(state, make_loopback_peer(4444), peer_len, 4);
    const auto third = remember_route_handle(state, make_loopback_peer(4444), peer_len, 7);

    return first != 0 && first == second && first != third &&
           state.routes_by_handle.at(first).socket_fd == 4 &&
           state.routes_by_handle.at(third).socket_fd == 7;
}

bool socket_io_backend_send_uses_route_handle_for_tests() {
    g_recorded_sendto_for_tests = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    };

    SocketIoBackend backend(SocketIoBackendConfig{
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

bool socket_io_backend_configures_linux_ecn_socket_options_for_tests() {
    g_recorded_setsockopt_for_tests = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .socket_fn = [](int, int, int) { return 41; },
            .setsockopt_fn = &record_setsockopt_for_tests,
        },
    };

    const int fd = open_udp_socket(AF_INET6);
    const bool opened = fd == 41;
    const auto has_call = [](int level, int name, int value) {
        return std::any_of(g_recorded_setsockopt_for_tests.calls.begin(),
                           g_recorded_setsockopt_for_tests.calls.end(),
                           [&](const RecordedSetSockOptForTests::Call &call) {
                               return call.level == level && call.name == name &&
                                      call.value == value;
                           });
    };
    return opened && has_call(IPPROTO_IPV6, IPV6_V6ONLY, 0) &&
           has_call(IPPROTO_IP, IP_RECVTOS, 1) && has_call(IPPROTO_IPV6, IPV6_RECVTCLASS, 1);
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
        send_datagram(/*fd=*/17, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in)),
                      "client", QuicEcnCodepoint::ect1);
    return sent && (g_recorded_sendmsg_for_tests.calls == 1) &&
           (g_recorded_sendmsg_for_tests.socket_fd == 17) &&
           (g_recorded_sendmsg_for_tests.level == IPPROTO_IP) &&
           (g_recorded_sendmsg_for_tests.type == IP_TOS) &&
           (g_recorded_sendmsg_for_tests.traffic_class == 0x01);
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
        send_datagram(/*fd=*/23, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in6)),
                      "server", QuicEcnCodepoint::ect1);
    return sent && (g_recorded_sendmsg_for_tests.calls == 1) &&
           (g_recorded_sendmsg_for_tests.socket_fd == 23) &&
           (g_recorded_sendmsg_for_tests.level == IPPROTO_IP) &&
           (g_recorded_sendmsg_for_tests.type == IP_TOS) &&
           (g_recorded_sendmsg_for_tests.traffic_class == 0x01);
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

    const auto received = receive_datagram(/*socket_fd=*/29, "client", /*flags=*/0);
    return received.status == ReceiveDatagramStatus::ok &&
           received.bytes == g_recorded_recvmsg_for_tests.bytes &&
           received.ecn == QuicEcnCodepoint::ce;
}

} // namespace test

} // namespace coquic::io
