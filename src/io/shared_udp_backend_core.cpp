#include "src/io/shared_udp_backend_core.h"

#include "src/io/socket_io_backend_internal.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#include <algorithm>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <utility>

namespace coquic::io {

namespace {

bool copy_udp_address(const addrinfo &result, internal::ResolvedUdpAddress &resolved) {
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

} // namespace

namespace internal {

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
    if (status != 0 || results == nullptr) {
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

std::size_t SocketIoPeerTupleKeyHash::operator()(const SocketIoPeerTupleKey &key) const {
    std::size_t hash = 1469598103934665603ull;
    const auto mix_byte = [&](std::byte byte) {
        hash ^= static_cast<std::size_t>(std::to_integer<unsigned char>(byte));
        hash *= 1099511628211ull;
    };
    for (const auto byte : std::as_bytes(std::span(&key.socket_fd, 1))) {
        mix_byte(byte);
    }
    for (const auto byte : std::as_bytes(std::span(&key.peer_len, 1))) {
        mix_byte(byte);
    }
    const auto encoded_peer_len =
        std::min<std::size_t>(static_cast<std::size_t>(key.peer_len), key.peer_bytes.size());
    for (std::size_t index = 0; index < encoded_peer_len; ++index) {
        mix_byte(key.peer_bytes[index]);
    }
    return hash;
}

SocketIoPeerTupleKey peer_tuple_key(int socket_fd, const sockaddr_storage &peer,
                                    socklen_t peer_len) {
    SocketIoPeerTupleKey key{};
    key.socket_fd = socket_fd;
    key.peer_len = std::min<socklen_t>(peer_len, sizeof(sockaddr_storage));
    std::memcpy(key.peer_bytes.data(), &peer, static_cast<std::size_t>(key.peer_len));
    return key;
}

QuicRouteHandle remember_route_handle(SocketIoRouteState &state, const sockaddr_storage &peer,
                                      socklen_t peer_len, int socket_fd) {
    const auto key = peer_tuple_key(socket_fd, peer, peer_len);
    if (const auto existing = state.route_handles_by_peer_tuple.find(key);
        existing != state.route_handles_by_peer_tuple.end()) {
        return existing->second;
    }

    const auto handle = state.next_route_handle++;
    state.route_handles_by_peer_tuple.emplace(key, handle);
    state.routes_by_handle.try_emplace(handle, SocketIoRoute{
                                                   .socket_fd = socket_fd,
                                                   .peer = peer,
                                                   .peer_len = peer_len,
                                               });
    return handle;
}

} // namespace internal

struct SharedUdpBackendCore::Impl {
    Impl(QuicUdpBackendConfig backend_config, std::unique_ptr<QuicIoEngine> backend_engine)
        : config(std::move(backend_config)), engine(std::move(backend_engine)) {
    }

    ~Impl() {
        for (const auto &socket : sockets) {
            if (socket.fd >= 0) {
                ::close(socket.fd);
            }
        }
    }

    int socket_fd_for_family(int family) const {
        const auto socket_it = std::find_if(
            sockets.begin(), sockets.end(),
            [&](const internal::SocketIoSocket &socket) { return socket.family == family; });
        return socket_it != sockets.end() ? socket_it->fd : -1;
    }

    QuicUdpBackendConfig config;
    std::unique_ptr<QuicIoEngine> engine;
    std::vector<internal::SocketIoSocket> sockets;
    std::vector<int> socket_fds;
    internal::SocketIoRouteState route_state;
};

SharedUdpBackendCore::SharedUdpBackendCore(QuicUdpBackendConfig config,
                                           std::unique_ptr<QuicIoEngine> engine)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(engine))) {
}

SharedUdpBackendCore::~SharedUdpBackendCore() = default;

std::optional<QuicIoRemote> SharedUdpBackendCore::resolve_remote(std::string_view host,
                                                                 std::uint16_t port) {
    internal::ResolvedUdpAddress resolved{};
    if (!internal::resolve_udp_address(
            internal::UdpAddressResolutionQuery{
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

bool SharedUdpBackendCore::open_listener(std::string_view host, std::uint16_t port) {
    internal::ResolvedUdpAddress bind_address{};
    if (!internal::resolve_udp_address(
            internal::UdpAddressResolutionQuery{
                .host = host,
                .port = port,
                .extra_flags = AI_PASSIVE,
                .family = internal::preferred_udp_address_family(host),
            },
            bind_address)) {
        std::cerr << "io-" << impl_->config.role_name << " failed: invalid host address\n";
        return false;
    }

    const int socket_fd = internal::open_udp_socket(bind_address.family);
    if (socket_fd < 0) {
        std::cerr << "io-" << impl_->config.role_name
                  << " failed: unable to create UDP socket: " << std::strerror(errno) << '\n';
        return false;
    }

    if (internal::socket_io_backend_ops_state().bind_fn(
            socket_fd, reinterpret_cast<const sockaddr *>(&bind_address.address),
            bind_address.address_len) != 0) {
        const int bind_errno = errno;
        ::close(socket_fd);
        errno = bind_errno;
        std::cerr << "io-" << impl_->config.role_name
                  << " failed: unable to bind UDP socket: " << std::strerror(errno) << '\n';
        return false;
    }

    if (!impl_->engine->register_socket(socket_fd)) {
        ::close(socket_fd);
        return false;
    }

    impl_->sockets.push_back(internal::SocketIoSocket{
        .fd = socket_fd,
        .family = bind_address.family,
    });
    impl_->socket_fds.push_back(socket_fd);
    return true;
}

std::optional<QuicRouteHandle> SharedUdpBackendCore::ensure_route(const QuicIoRemote &remote) {
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
        socket_fd = internal::open_udp_socket(route_family);
        if (socket_fd < 0) {
            return std::nullopt;
        }
        if (!impl_->engine->register_socket(socket_fd)) {
            ::close(socket_fd);
            return std::nullopt;
        }
        impl_->sockets.push_back(internal::SocketIoSocket{
            .fd = socket_fd,
            .family = route_family,
        });
        impl_->socket_fds.push_back(socket_fd);
    }

    return internal::remember_route_handle(impl_->route_state, remote.peer, remote.peer_len,
                                           socket_fd);
}

std::optional<QuicIoEvent>
SharedUdpBackendCore::wait(std::optional<QuicCoreTimePoint> next_wakeup) {
    if (impl_->sockets.empty()) {
        return std::nullopt;
    }

    auto event = impl_->engine->wait(impl_->socket_fds, impl_->config.idle_timeout_ms, next_wakeup,
                                     impl_->config.role_name);
    if (!event.has_value()) {
        return std::nullopt;
    }

    switch (event->kind) {
    case QuicIoEngineEvent::Kind::timer_expired:
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = event->now,
        };
    case QuicIoEngineEvent::Kind::idle_timeout:
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::idle_timeout,
            .now = event->now,
        };
    case QuicIoEngineEvent::Kind::shutdown:
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = event->now,
        };
    case QuicIoEngineEvent::Kind::rx_datagram:
        break;
    }

    if (!event->rx.has_value()) {
        return std::nullopt;
    }

    auto completion = std::move(*event->rx);
    const auto handle = internal::remember_route_handle(impl_->route_state, completion.peer,
                                                        completion.peer_len, completion.socket_fd);
    return QuicIoEvent{
        .kind = QuicIoEvent::Kind::rx_datagram,
        .now = completion.now,
        .datagram =
            QuicIoRxDatagram{
                .route_handle = handle,
                .bytes = std::move(completion.bytes),
                .ecn = completion.ecn,
            },
    };
}

bool SharedUdpBackendCore::send(const QuicIoTxDatagram &datagram) {
    const auto route_it = impl_->route_state.routes_by_handle.find(datagram.route_handle);
    if (route_it == impl_->route_state.routes_by_handle.end()) {
        return false;
    }

    return impl_->engine->send(route_it->second.socket_fd, route_it->second.peer,
                               route_it->second.peer_len, datagram.bytes, impl_->config.role_name,
                               datagram.ecn);
}

namespace test {

int socket_io_backend_preferred_udp_address_family_for_runtime_tests(std::string_view host) {
    return internal::preferred_udp_address_family(host);
}

bool socket_io_backend_resolve_udp_address_for_runtime_tests(
    std::string_view host, std::uint16_t port, int extra_flags, int family,
    SocketIoBackendResolvedUdpAddressForTests &resolved) {
    internal::ResolvedUdpAddress backend_resolved{};
    if (!internal::resolve_udp_address(
            internal::UdpAddressResolutionQuery{
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
    return internal::open_udp_socket(family);
}

bool socket_io_backend_configure_linux_ecn_socket_options_for_runtime_tests(int socket_fd,
                                                                            int family) {
    return internal::configure_linux_ecn_socket_options(
        internal::LinuxSocketDescriptor{.fd = socket_fd}, family);
}

namespace {

struct RecordedSetSockOptForTests {
    struct Call {
        int level = 0;
        int name = 0;
        int value = 0;
    };

    std::vector<Call> calls;
};

thread_local RecordedSetSockOptForTests g_recorded_setsockopt_for_tests;

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

sockaddr_storage make_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return peer;
}

} // namespace

bool socket_io_backend_configures_linux_ecn_socket_options_for_tests() {
    g_recorded_setsockopt_for_tests = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .socket_fn = [](int, int, int) { return 41; },
            .setsockopt_fn = &record_setsockopt_for_tests,
        },
    };

    const int fd = internal::open_udp_socket(AF_INET6);
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

bool socket_io_backend_route_handles_are_stable_per_peer_tuple_for_tests() {
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    internal::SocketIoRouteState state;

    const auto first =
        internal::remember_route_handle(state, make_loopback_peer(4444), peer_len, 4);
    const auto second =
        internal::remember_route_handle(state, make_loopback_peer(4444), peer_len, 4);
    const auto third =
        internal::remember_route_handle(state, make_loopback_peer(4444), peer_len, 7);

    return first != 0 && first == second && first != third &&
           state.routes_by_handle.at(first).socket_fd == 4 &&
           state.routes_by_handle.at(third).socket_fd == 7;
}

bool socket_io_backend_duplicate_route_lookup_reuses_cached_route_entry_for_tests() {
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    internal::SocketIoRouteState state;
    const auto peer = make_loopback_peer(4444);

    const auto handle = internal::remember_route_handle(state, peer, peer_len, 4);
    if (handle == 0 || state.routes_by_handle.size() != 1 ||
        state.route_handles_by_peer_tuple.size() != 1) {
        return false;
    }

    auto &cached_route = state.routes_by_handle.at(handle);
    cached_route.socket_fd = -1;
    cached_route.peer_len = 0;
    std::memset(&cached_route.peer, 0x5a, sizeof(cached_route.peer));

    const auto duplicate = internal::remember_route_handle(state, peer, peer_len, 4);
    return duplicate == handle && state.routes_by_handle.size() == 1 &&
           state.route_handles_by_peer_tuple.size() == 1 &&
           state.routes_by_handle.at(handle).socket_fd == -1 &&
           state.routes_by_handle.at(handle).peer_len == 0;
}

} // namespace test

} // namespace coquic::io
