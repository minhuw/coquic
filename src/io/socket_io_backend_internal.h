#pragma once

#include <netdb.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "src/io/io_backend.h"
#include "src/io/io_backend_test_hooks.h"

namespace coquic::io::internal {

using quic::QuicCoreTimePoint;
using quic::QuicEcnCodepoint;
using quic::QuicRouteHandle;

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

struct LinuxSocketDescriptor {
    int fd = -1;
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

test::SocketIoBackendOpsOverride &socket_io_backend_ops_state();
void apply_socket_io_backend_ops_override(const test::SocketIoBackendOpsOverride &override_ops);
bool has_legacy_sendto_override();
bool has_legacy_recvfrom_override();

QuicCoreTimePoint now();
int linux_traffic_class_for_ecn(QuicEcnCodepoint ecn);
QuicEcnCodepoint ecn_from_linux_traffic_class(int traffic_class);
bool configure_linux_ecn_socket_options(LinuxSocketDescriptor socket, int family);
bool is_ipv4_mapped_ipv6_address(const sockaddr_storage &peer, socklen_t peer_len);
QuicEcnCodepoint recvmsg_ecn_from_control(const msghdr &message);

int preferred_udp_address_family(std::string_view host);
bool resolve_udp_address(UdpAddressResolutionQuery query, ResolvedUdpAddress &resolved);
int open_udp_socket(int family);

bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name, QuicEcnCodepoint ecn);
ReceiveDatagramResult receive_datagram(int socket_fd, std::string_view role_name, int flags);

std::string peer_tuple_key(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len);
QuicRouteHandle remember_route_handle(SocketIoRouteState &state, const sockaddr_storage &peer,
                                      socklen_t peer_len, int socket_fd);

} // namespace coquic::io::internal
