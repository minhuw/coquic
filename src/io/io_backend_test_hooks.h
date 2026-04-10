#pragma once

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include "src/io/io_backend.h"

namespace coquic::io::test {

using quic::QuicEcnCodepoint;

struct SocketIoBackendOpsOverride {
    int (*socket_fn)(int, int, int) = nullptr;
    int (*bind_fn)(int, const sockaddr *, socklen_t) = nullptr;
    int (*poll_fn)(pollfd *, nfds_t, int) = nullptr;
    int (*setsockopt_fn)(int, int, int, const void *, socklen_t) = nullptr;
    ssize_t (*sendto_fn)(int, const void *, size_t, int, const sockaddr *, socklen_t) = nullptr;
    ssize_t (*sendmsg_fn)(int, const msghdr *, int) = nullptr;
    ssize_t (*recvfrom_fn)(int, void *, size_t, int, sockaddr *, socklen_t *) = nullptr;
    ssize_t (*recvmsg_fn)(int, msghdr *, int) = nullptr;
    int (*getaddrinfo_fn)(const char *, const char *, const addrinfo *, addrinfo **) = nullptr;
    void (*freeaddrinfo_fn)(addrinfo *) = nullptr;
    int (*gethostname_fn)(char *, size_t) = nullptr;
};

class ScopedSocketIoBackendOpsOverride {
  public:
    explicit ScopedSocketIoBackendOpsOverride(SocketIoBackendOpsOverride override_ops);
    ~ScopedSocketIoBackendOpsOverride();

    ScopedSocketIoBackendOpsOverride(const ScopedSocketIoBackendOpsOverride &) = delete;
    ScopedSocketIoBackendOpsOverride &operator=(const ScopedSocketIoBackendOpsOverride &) = delete;

  private:
    SocketIoBackendOpsOverride previous_;
};

SocketIoBackendOpsOverride &socket_io_backend_ops_for_runtime_tests();
void socket_io_backend_apply_ops_override_for_runtime_tests(
    const SocketIoBackendOpsOverride &override_ops);
bool socket_io_backend_has_legacy_sendto_override_for_runtime_tests();
bool socket_io_backend_has_legacy_recvfrom_override_for_runtime_tests();

struct SocketIoBackendResolvedUdpAddressForTests {
    sockaddr_storage address{};
    socklen_t address_len = 0;
    int family = AF_UNSPEC;
};

enum class SocketIoBackendReceiveDatagramStatusForTests : std::uint8_t {
    ok,
    would_block,
    error,
};

struct SocketIoBackendReceiveDatagramResultForTests {
    SocketIoBackendReceiveDatagramStatusForTests status =
        SocketIoBackendReceiveDatagramStatusForTests::would_block;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
    sockaddr_storage source{};
    socklen_t source_len = 0;
};

int socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests(QuicEcnCodepoint ecn);
QuicEcnCodepoint
socket_io_backend_ecn_from_linux_traffic_class_for_runtime_tests(int traffic_class);
bool socket_io_backend_configure_linux_ecn_socket_options_for_runtime_tests(int socket_fd,
                                                                            int family);
bool socket_io_backend_is_ipv4_mapped_ipv6_address_for_runtime_tests(const sockaddr_storage &peer,
                                                                     socklen_t peer_len);
QuicEcnCodepoint
socket_io_backend_recvmsg_ecn_from_control_for_runtime_tests(const msghdr &message);
int socket_io_backend_preferred_udp_address_family_for_runtime_tests(std::string_view host);
bool socket_io_backend_resolve_udp_address_for_runtime_tests(
    std::string_view host, std::uint16_t port, int extra_flags, int family,
    SocketIoBackendResolvedUdpAddressForTests &resolved);
int socket_io_backend_open_udp_socket_for_runtime_tests(int family);
bool socket_io_backend_send_datagram_for_runtime_tests(int fd, std::span<const std::byte> datagram,
                                                       const sockaddr_storage &peer,
                                                       socklen_t peer_len,
                                                       std::string_view role_name,
                                                       QuicEcnCodepoint ecn);
SocketIoBackendReceiveDatagramResultForTests
socket_io_backend_receive_datagram_for_runtime_tests(int socket_fd, std::string_view role_name,
                                                     int flags);

bool socket_io_backend_route_handles_are_stable_per_peer_tuple_for_tests();
bool socket_io_backend_send_uses_route_handle_for_tests();
bool socket_io_backend_configures_linux_ecn_socket_options_for_tests();
bool socket_io_backend_sendmsg_uses_outbound_ecn_for_tests();
bool socket_io_backend_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests();
bool socket_io_backend_recvmsg_maps_ecn_for_tests();

} // namespace coquic::io::test
