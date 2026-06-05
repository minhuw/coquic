#include "src/io/shared_udp_backend_core.h"

#include "src/io/socket_io_backend_internal.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <utility>

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

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

COQUIC_NO_PROFILE std::optional<QuicIoEvent>
translate_non_receive_wait_event(const QuicIoEngineEvent &event) {
    switch (event.kind) {
    case QuicIoEngineEvent::Kind::timer_expired:
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::timer_expired,
            .now = event.now,
        };
    case QuicIoEngineEvent::Kind::idle_timeout:
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::idle_timeout,
            .now = event.now,
        };
    case QuicIoEngineEvent::Kind::shutdown:
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::shutdown,
            .now = event.now,
        };
    case QuicIoEngineEvent::Kind::rx_datagram:
    case QuicIoEngineEvent::Kind::path_mtu_update:
        return std::nullopt;
    }
    return std::nullopt;
}

} // namespace

namespace internal {

void configure_udp_socket_buffers(LinuxSocketDescriptor socket) {
    const int buffer_size = 4 * 1024 * 1024;
    const auto set_buffer_option = [&](int option) {
        static_cast<void>(socket_io_backend_ops_state().setsockopt_fn(
            socket.fd, SOL_SOCKET, option, &buffer_size, sizeof(buffer_size)));
    };

    set_buffer_option(SO_RCVBUF);
    set_buffer_option(SO_SNDBUF);
}

void configure_udp_gro_if_available(LinuxSocketDescriptor socket) {
#if defined(__linux__) && defined(UDP_GRO)
    const int enabled = 1;
    static_cast<void>(socket_io_backend_ops_state().setsockopt_fn(socket.fd, SOL_UDP, UDP_GRO,
                                                                  &enabled, sizeof(enabled)));
#else
    static_cast<void>(socket);
#endif
}

COQUIC_NO_PROFILE bool socket_family_uses_ipv4_pmtud_options(int family) {
    return family == AF_INET || family == AF_INET6;
}

COQUIC_NO_PROFILE bool socket_family_is_ipv6(int family) {
    return family == AF_INET6;
}

COQUIC_NO_PROFILE bool
configure_ipv4_pmtud_socket_options_if_needed(LinuxSocketDescriptor socket, int family,
                                              const auto &set_bool_socket_option) {
    if (!socket_family_uses_ipv4_pmtud_options(family)) {
        return true;
    }

    const int discover = IP_PMTUDISC_PROBE;
    if (socket_io_backend_ops_state().setsockopt_fn(socket.fd, IPPROTO_IP, IP_MTU_DISCOVER,
                                                    &discover, sizeof(discover)) != 0) {
        return false;
    }
    return set_bool_socket_option(IPPROTO_IP, IP_RECVERR);
}

SocketOptionResult configure_linux_ecn_socket_options(LinuxSocketDescriptor socket, int family) {
#if defined(__linux__)
    const auto set_bool_socket_option = [&](int level, int name) {
        const int enabled = 1;
        return socket_io_backend_ops_state().setsockopt_fn(socket.fd, level, name, &enabled,
                                                           sizeof(enabled)) == 0;
    };

    if (family == AF_INET || family == AF_INET6) {
        if (!set_bool_socket_option(IPPROTO_IP, IP_RECVTOS)) {
            return SocketOptionResult::failed;
        }
    }
    if (socket_family_is_ipv6(family)) {
        if (!set_bool_socket_option(IPPROTO_IPV6, IPV6_RECVTCLASS)) {
            return SocketOptionResult::failed;
        }
    }
#else
    static_cast<void>(socket);
    static_cast<void>(family);
#endif
    return SocketOptionResult::configured;
}

SocketOptionResult configure_linux_pmtud_socket_options(LinuxSocketDescriptor socket, int family) {
#if defined(__linux__)
    const auto set_bool_socket_option = [&](int level, int name) {
        const int enabled = 1;
        return socket_io_backend_ops_state().setsockopt_fn(socket.fd, level, name, &enabled,
                                                           sizeof(enabled)) == 0;
    };

    if (!configure_ipv4_pmtud_socket_options_if_needed(socket, family, set_bool_socket_option)) {
        return SocketOptionResult::failed;
    }
    if (socket_family_is_ipv6(family)) {
        const int discover = IPV6_PMTUDISC_PROBE;
        if (socket_io_backend_ops_state().setsockopt_fn(socket.fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                                                        &discover, sizeof(discover)) != 0) {
            return SocketOptionResult::failed;
        }
        if (!set_bool_socket_option(IPPROTO_IPV6, IPV6_RECVERR)) {
            return SocketOptionResult::failed;
        }
    }
#else
    static_cast<void>(socket);
    static_cast<void>(family);
#endif
    return SocketOptionResult::configured;
}

int open_udp_socket(int family, bool enable_pmtud_socket_options) {
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

    configure_udp_socket_buffers(LinuxSocketDescriptor{.fd = fd});
    configure_udp_gro_if_available(LinuxSocketDescriptor{.fd = fd});

    if (configure_linux_ecn_socket_options(LinuxSocketDescriptor{.fd = fd}, family) ==
        SocketOptionResult::failed) {
        const int option_errno = errno;
        ::close(fd);
        errno = option_errno;
        return -1;
    }
    if (enable_pmtud_socket_options &&
        configure_linux_pmtud_socket_options(LinuxSocketDescriptor{.fd = fd}, family) ==
            SocketOptionResult::failed) {
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

COQUIC_NO_PROFILE std::size_t route_lookup_cache_index(int socket_fd, const sockaddr_storage &peer,
                                                       socklen_t peer_len) {
    std::size_t hash = 0x9e3779b97f4a7c15ull;
    const auto mix = [&hash](std::uint64_t value) {
        hash ^= static_cast<std::size_t>(value) + 0x9e3779b97f4a7c15ull + (hash << 6) + (hash >> 2);
    };

    mix(static_cast<std::uint64_t>(socket_fd));
    mix(static_cast<std::uint64_t>(peer_len));
    if (peer_len >= static_cast<socklen_t>(sizeof(sockaddr_in)) && peer.ss_family == AF_INET) {
        const auto &ipv4 = *reinterpret_cast<const sockaddr_in *>(&peer);
        mix(static_cast<std::uint64_t>(ipv4.sin_port));
        mix(static_cast<std::uint64_t>(ipv4.sin_addr.s_addr));
    } else if (peer_len >= static_cast<socklen_t>(sizeof(sockaddr_in6)) &&
               peer.ss_family == AF_INET6) {
        const auto &ipv6 = *reinterpret_cast<const sockaddr_in6 *>(&peer);
        mix(static_cast<std::uint64_t>(ipv6.sin6_port));
        std::array<std::uint64_t, 2> folded_address{};
        std::memcpy(folded_address.data(), &ipv6.sin6_addr, sizeof(folded_address));
        mix(folded_address[0]);
        mix(folded_address[1]);
    }
    return hash % internal::SocketIoRouteState::kRouteLookupCacheSlots;
}

COQUIC_NO_PROFILE bool route_lookup_cache_matches(const SocketIoRouteLookupCacheEntry &entry,
                                                  int socket_fd, const sockaddr_storage &peer,
                                                  socklen_t peer_len) {
    return entry.valid && entry.socket_fd == socket_fd && entry.peer_len == peer_len &&
           std::memcmp(&entry.peer, &peer, static_cast<std::size_t>(peer_len)) == 0;
}

QuicRouteHandle remember_route_handle(SocketIoRouteState &state, const sockaddr_storage &peer,
                                      socklen_t peer_len, int socket_fd) {
    const auto normalized_peer_len = std::min<socklen_t>(peer_len, sizeof(sockaddr_storage));
    auto &cached =
        state.route_lookup_cache[route_lookup_cache_index(socket_fd, peer, normalized_peer_len)];
    if (route_lookup_cache_matches(cached, socket_fd, peer, normalized_peer_len)) {
        return cached.route_handle;
    }

    const auto key = peer_tuple_key(socket_fd, peer, peer_len);
    if (const auto existing = state.route_handles_by_peer_tuple.find(key);
        existing != state.route_handles_by_peer_tuple.end()) {
        cached = SocketIoRouteLookupCacheEntry{
            .valid = true,
            .socket_fd = socket_fd,
            .peer = peer,
            .peer_len = normalized_peer_len,
            .route_handle = existing->second,
        };
        return existing->second;
    }

    const auto handle = state.next_route_handle++;
    state.route_handles_by_peer_tuple.emplace(key, handle);
    state.routes_by_handle.try_emplace(handle, SocketIoRoute{
                                                   .socket_fd = socket_fd,
                                                   .peer = peer,
                                                   .peer_len = peer_len,
                                               });
    cached = SocketIoRouteLookupCacheEntry{
        .valid = true,
        .socket_fd = socket_fd,
        .peer = peer,
        .peer_len = normalized_peer_len,
        .route_handle = handle,
    };
    return handle;
}

std::vector<std::byte> address_validation_identity_from_peer(const sockaddr_storage &peer,
                                                             socklen_t peer_len) {
    if (peer.ss_family == AF_INET && peer_len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto &ipv4 = *reinterpret_cast<const sockaddr_in *>(&peer);
        std::vector<std::byte> identity;
        identity.reserve(1 + sizeof(ipv4.sin_addr) + sizeof(ipv4.sin_port));
        identity.push_back(std::byte{0x04});
        std::array<std::byte, sizeof(ipv4.sin_addr)> address{};
        std::memcpy(address.data(), &ipv4.sin_addr, address.size());
        identity.insert(identity.end(), address.begin(), address.end());
        std::array<std::byte, sizeof(ipv4.sin_port)> port{};
        std::memcpy(port.data(), &ipv4.sin_port, port.size());
        identity.insert(identity.end(), port.begin(), port.end());
        return identity;
    }

    if (peer.ss_family == AF_INET6 && peer_len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto &ipv6 = *reinterpret_cast<const sockaddr_in6 *>(&peer);
        std::vector<std::byte> identity;
        identity.reserve(1 + sizeof(ipv6.sin6_addr) + sizeof(ipv6.sin6_port));
        identity.push_back(std::byte{0x06});
        std::array<std::byte, sizeof(ipv6.sin6_addr)> address{};
        std::memcpy(address.data(), &ipv6.sin6_addr, address.size());
        identity.insert(identity.end(), address.begin(), address.end());
        std::array<std::byte, sizeof(ipv6.sin6_port)> port{};
        std::memcpy(port.data(), &ipv6.sin6_port, port.size());
        identity.insert(identity.end(), port.begin(), port.end());
        return identity;
    }

    return {};
}

} // namespace internal

struct SharedUdpBackendCore::Impl {
    Impl(QuicUdpBackendConfig backend_config, std::unique_ptr<QuicIoEngine> backend_engine)
        : config(std::move(backend_config)), engine(std::move(backend_engine)) {
    }

    COQUIC_NO_PROFILE ~Impl() {
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
    std::vector<QuicIoEngineTxDatagram> tx_datagram_scratch;
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

    const int socket_fd =
        internal::open_udp_socket(bind_address.family, impl_->config.enable_pmtud_socket_options);
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
        socket_fd =
            internal::open_udp_socket(route_family, impl_->config.enable_pmtud_socket_options);
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

    if (const auto translated = translate_non_receive_wait_event(*event); translated.has_value()) {
        return translated;
    }

    if (event->kind == QuicIoEngineEvent::Kind::path_mtu_update) {
        if (!event->path_mtu.has_value()) {
            return std::nullopt;
        }
        auto update = *event->path_mtu;
        const auto handle = internal::remember_route_handle(impl_->route_state, update.peer,
                                                            update.peer_len, update.socket_fd);
        return QuicIoEvent{
            .kind = QuicIoEvent::Kind::path_mtu_update,
            .now = update.now,
            .path_mtu =
                QuicIoPathMtuUpdate{
                    .route_handle = handle,
                    .max_udp_payload_size = update.max_udp_payload_size,
                },
        };
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
                .address_validation_identity = internal::address_validation_identity_from_peer(
                    completion.peer, completion.peer_len),
                .ecn = completion.ecn,
                .shared_bytes = std::move(completion.shared_bytes),
                .begin = completion.begin,
                .end = completion.end,
            },
    };
}

bool SharedUdpBackendCore::has_pending_events() const {
    return impl_ != nullptr && impl_->engine != nullptr && impl_->engine->has_pending_events();
}

bool SharedUdpBackendCore::send(const QuicIoTxDatagram &datagram) {
    const auto route_it = impl_->route_state.routes_by_handle.find(datagram.route_handle);
    if (route_it == impl_->route_state.routes_by_handle.end()) {
        return false;
    }

    return impl_->engine->send(route_it->second.socket_fd, route_it->second.peer,
                               route_it->second.peer_len, datagram.payload(),
                               impl_->config.role_name, datagram.ecn, datagram.is_pmtu_probe);
}

bool SharedUdpBackendCore::send_many(std::span<const QuicIoTxDatagram> datagrams) {
    auto &engine_datagrams = impl_->tx_datagram_scratch;
    if (engine_datagrams.size() < datagrams.size()) {
        engine_datagrams.resize(datagrams.size());
    }
    for (std::size_t index = 0; index < datagrams.size(); ++index) {
        const auto &datagram = datagrams[index];
        const auto route_it = impl_->route_state.routes_by_handle.find(datagram.route_handle);
        if (route_it == impl_->route_state.routes_by_handle.end()) {
            return false;
        }
        engine_datagrams[index] = QuicIoEngineTxDatagram{
            .socket_fd = route_it->second.socket_fd,
            .peer = route_it->second.peer,
            .peer_len = route_it->second.peer_len,
            .bytes = datagram.payload(),
            .ecn = datagram.ecn,
            .is_pmtu_probe = datagram.is_pmtu_probe,
        };
    }

    return impl_->engine->send_many(
        std::span<const QuicIoEngineTxDatagram>(engine_datagrams).first(datagrams.size()),
        impl_->config.role_name);
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

std::vector<std::byte>
socket_io_backend_address_validation_identity_for_runtime_tests(const sockaddr_storage &peer,
                                                                socklen_t peer_len) {
    return internal::address_validation_identity_from_peer(peer, peer_len);
}

int socket_io_backend_open_udp_socket_for_runtime_tests(int family) {
    return internal::open_udp_socket(family);
}

bool socket_io_backend_configure_linux_ecn_socket_options_for_runtime_tests(int socket_fd,
                                                                            int family) {
    if (socket_fd < 0) {
        return false;
    }
    return internal::configure_linux_ecn_socket_options(
               internal::LinuxSocketDescriptor{.fd = socket_fd}, family) ==
           internal::SocketOptionResult::configured;
}

bool socket_io_backend_configure_linux_pmtud_socket_options_for_runtime_tests(int socket_fd,
                                                                              int family) {
    if (socket_fd < 0) {
        return false;
    }
    return internal::configure_linux_pmtud_socket_options(
               internal::LinuxSocketDescriptor{.fd = socket_fd}, family) ==
           internal::SocketOptionResult::configured;
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

COQUIC_NO_PROFILE bool
recorded_setsockopt_call_matches_for_tests(const RecordedSetSockOptForTests::Call &call, int level,
                                           int name, int value) {
    bool matched = call.level == level;
    matched = matched & (call.name == name);
    matched = matched & (call.value == value);
    return matched;
}

COQUIC_NO_PROFILE int record_setsockopt_for_tests(int, int level, int name, const void *value,
                                                  socklen_t value_len) {
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

COQUIC_NO_PROFILE bool socket_io_backend_configures_linux_ecn_socket_options_for_tests() {
    bool ok = true;
    const auto record = [&](bool condition) { ok = ok & condition; };
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
                               return recorded_setsockopt_call_matches_for_tests(call, level, name,
                                                                                 value);
                           });
    };
    constexpr int kExpectedUdpSocketBufferBytes = 4 * 1024 * 1024;
    record(opened);
    record(has_call(IPPROTO_IPV6, IPV6_V6ONLY, 0));
    record(has_call(SOL_SOCKET, SO_RCVBUF, kExpectedUdpSocketBufferBytes));
    record(has_call(SOL_SOCKET, SO_SNDBUF, kExpectedUdpSocketBufferBytes));
#if defined(__linux__) && defined(UDP_GRO)
    record(has_call(SOL_UDP, UDP_GRO, 1));
#endif
    record(has_call(IPPROTO_IP, IP_RECVTOS, 1));
    record(has_call(IPPROTO_IPV6, IPV6_RECVTCLASS, 1));
#if defined(__linux__)
    record(has_call(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE));
    record(has_call(IPPROTO_IP, IP_RECVERR, 1));
    record(has_call(IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_PROBE));
    record(has_call(IPPROTO_IPV6, IPV6_RECVERR, 1));
#endif
    g_recorded_setsockopt_for_tests = {};
    record_setsockopt_for_tests(41, SOL_SOCKET, SO_RCVBUF, nullptr, 0);
    record(!g_recorded_setsockopt_for_tests.calls.empty());
    record(g_recorded_setsockopt_for_tests.calls.back().value == 0);
    const std::uint8_t short_value = 0xff;
    record_setsockopt_for_tests(41, SOL_SOCKET, SO_SNDBUF, &short_value,
                                static_cast<socklen_t>(sizeof(short_value)));
    record(g_recorded_setsockopt_for_tests.calls.back().value == 0);
    return ok;
}

COQUIC_NO_PROFILE bool socket_io_backend_can_skip_linux_pmtud_socket_options_for_tests() {
    bool ok = true;
    const auto record = [&](bool condition) { ok = ok & condition; };
    g_recorded_setsockopt_for_tests = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .socket_fn = [](int, int, int) { return 42; },
            .setsockopt_fn = &record_setsockopt_for_tests,
        },
    };

    const bool unsupported_family_is_noop =
        internal::configure_linux_pmtud_socket_options(internal::LinuxSocketDescriptor{.fd = 42},
                                                       AF_UNIX) ==
        internal::SocketOptionResult::configured;
    const int fd = internal::open_udp_socket(AF_INET, /*enable_pmtud_socket_options=*/false);
    const auto has_call = [](int level, int name) {
        return std::any_of(g_recorded_setsockopt_for_tests.calls.begin(),
                           g_recorded_setsockopt_for_tests.calls.end(),
                           [&](const RecordedSetSockOptForTests::Call &call) {
                               bool matched = call.level == level;
                               matched = matched & (call.name == name);
                               return matched;
                           });
    };

    record(unsupported_family_is_noop);
    record(fd == 42);
#if defined(__linux__)
    record(!has_call(IPPROTO_IP, IP_MTU_DISCOVER));
    record(!has_call(IPPROTO_IP, IP_RECVERR));
#endif
    return ok;
}

COQUIC_NO_PROFILE bool socket_io_backend_route_handles_are_stable_per_peer_tuple_for_tests() {
    bool ok = true;
    const auto record = [&](bool condition) { ok = ok & condition; };
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    internal::SocketIoRouteState state;

    const auto first =
        internal::remember_route_handle(state, make_loopback_peer(4444), peer_len, 4);
    const auto second =
        internal::remember_route_handle(state, make_loopback_peer(4444), peer_len, 4);
    const auto third =
        internal::remember_route_handle(state, make_loopback_peer(4444), peer_len, 7);

    record(first != 0);
    record(first == second);
    record(first != third);
    record(state.routes_by_handle.at(first).socket_fd == 4);
    record(state.routes_by_handle.at(third).socket_fd == 7);

    sockaddr_storage ipv6_peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&ipv6_peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(4444);
    ipv6.sin6_addr = in6addr_loopback;
    const auto ipv6_first =
        internal::remember_route_handle(state, ipv6_peer, sizeof(sockaddr_in6), 8);
    const auto ipv6_second =
        internal::remember_route_handle(state, ipv6_peer, sizeof(sockaddr_in6), 8);
    record(ipv6_first != 0);
    record(ipv6_first == ipv6_second);
    return ok;
}

bool socket_io_backend_address_validation_identity_branches_for_tests() {
    const auto ipv4_peer = make_loopback_peer(4444);
    const auto ipv4_identity = internal::address_validation_identity_from_peer(
        ipv4_peer, static_cast<socklen_t>(sizeof(sockaddr_in)));

    sockaddr_storage ipv6_peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&ipv6_peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(5555);
    ipv6.sin6_addr = in6addr_loopback;
    const auto ipv6_identity = internal::address_validation_identity_from_peer(
        ipv6_peer, static_cast<socklen_t>(sizeof(sockaddr_in6)));

    sockaddr_storage unsupported_peer{};
    unsupported_peer.ss_family = AF_UNIX;
    const auto unsupported_identity = internal::address_validation_identity_from_peer(
        unsupported_peer, static_cast<socklen_t>(sizeof(sockaddr_storage)));

    const auto short_ipv4_identity =
        internal::address_validation_identity_from_peer(ipv4_peer, /*peer_len=*/1);
    const auto short_ipv6_identity =
        internal::address_validation_identity_from_peer(ipv6_peer, /*peer_len=*/1);
    sockaddr_storage truncated_unsupported_peer{};
    truncated_unsupported_peer.ss_family = AF_UNIX;
    const auto unsupported_full_length_identity = internal::address_validation_identity_from_peer(
        truncated_unsupported_peer, static_cast<socklen_t>(sizeof(sockaddr_in6)));

    bool ok = true;
    ok &= ipv4_identity.size() == 7;
    ok &= ipv4_identity.front() == std::byte{0x04};
    ok &= ipv6_identity.size() == 19;
    ok &= ipv6_identity.front() == std::byte{0x06};
    ok &= unsupported_identity.empty();
    ok &= short_ipv4_identity.empty();
    ok &= short_ipv6_identity.empty();
    ok &= unsupported_full_length_identity.empty();
    return ok;
}

bool socket_io_backend_duplicate_route_lookup_reuses_cached_route_entry_for_tests() {
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    internal::SocketIoRouteState state;
    const auto peer = make_loopback_peer(4444);
    const auto cached_route_matches = [&](std::uint64_t route_handle, int socket_fd,
                                          socklen_t expected_peer_len) {
        const auto &route = state.routes_by_handle.at(route_handle);
        return (route_handle != 0) & (state.routes_by_handle.size() == 1) &
               (state.route_handles_by_peer_tuple.size() == 1) & (route.socket_fd == socket_fd) &
               (route.peer_len == expected_peer_len);
    };

    const auto handle = internal::remember_route_handle(state, peer, peer_len, 4);
    const bool inserted_route = cached_route_matches(handle, 4, peer_len);

    auto &cached_route = state.routes_by_handle.at(handle);
    cached_route.socket_fd = -1;
    cached_route.peer_len = 0;
    std::memset(&cached_route.peer, 0x5a, sizeof(cached_route.peer));
    state.route_lookup_cache = {};

    const auto duplicate = internal::remember_route_handle(state, peer, peer_len, 4);
    bool ok = inserted_route;
    ok &= duplicate == handle;
    ok &= cached_route_matches(handle, -1, 0);
    return ok;
}

} // namespace test

} // namespace coquic::io
