#pragma once

#include <netdb.h>
#include <sys/socket.h>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "src/io/io_backend.h"
#include "src/io/io_backend_test_hooks.h"
#include "src/io/io_engine.h"

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

struct SocketIoPeerTupleKey {
    int socket_fd = -1;
    socklen_t peer_len = 0;
    std::array<std::byte, sizeof(sockaddr_storage)> peer_bytes{};

    bool operator==(const SocketIoPeerTupleKey &) const = default;
};

struct SocketIoPeerTupleKeyHash {
    std::size_t operator()(const SocketIoPeerTupleKey &key) const;
};

struct SocketIoRouteState {
    std::unordered_map<SocketIoPeerTupleKey, QuicRouteHandle, SocketIoPeerTupleKeyHash>
        route_handles_by_peer_tuple;
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
    std::shared_ptr<std::vector<std::byte>> shared_bytes;
    std::size_t begin = 0;
    std::size_t end = 0;
    std::size_t udp_gro_segment_size = 0;

    std::span<const std::byte> payload() const {
        if (shared_bytes != nullptr) {
            const auto clamped_begin = std::min(begin, shared_bytes->size());
            const auto clamped_end = std::min(std::max(end, clamped_begin), shared_bytes->size());
            return std::span<const std::byte>(*shared_bytes)
                .subspan(clamped_begin, clamped_end - clamped_begin);
        }
        return bytes;
    }
};

enum class PathMtuUpdateStatus : std::uint8_t {
    ok,
    none,
    ignored,
    error,
};

struct PathMtuUpdateResult {
    PathMtuUpdateStatus status = PathMtuUpdateStatus::none;
    std::size_t max_udp_payload_size = 0;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    QuicCoreTimePoint input_time{};
};

test::SocketIoBackendOpsOverride &socket_io_backend_ops_state();
test::SocketIoBackendOpsOverride make_default_socket_io_backend_ops();
void apply_socket_io_backend_ops_override(const test::SocketIoBackendOpsOverride &override_ops);
bool has_legacy_sendto_override();
bool has_legacy_recvfrom_override();

QuicCoreTimePoint now();
int linux_traffic_class_for_ecn(QuicEcnCodepoint ecn);
QuicEcnCodepoint ecn_from_linux_traffic_class(int traffic_class);
void configure_udp_socket_buffers(LinuxSocketDescriptor socket);
bool configure_linux_ecn_socket_options(LinuxSocketDescriptor socket, int family);
bool configure_linux_pmtud_socket_options(LinuxSocketDescriptor socket, int family);
bool is_ipv4_mapped_ipv6_address(const sockaddr_storage &peer, socklen_t peer_len);
bool should_apply_ipv6_flow_label(const sockaddr_storage &peer, socklen_t peer_len);
sockaddr_storage peer_with_ipv6_flow_label(const sockaddr_storage &peer, socklen_t peer_len,
                                           std::span<const std::byte> datagram);
QuicEcnCodepoint recvmsg_ecn_from_control(const msghdr &message);
std::size_t recvmsg_udp_gro_segment_size_from_control(const msghdr &message);

int preferred_udp_address_family(std::string_view host);
bool resolve_udp_address(UdpAddressResolutionQuery query, ResolvedUdpAddress &resolved);
int open_udp_socket(int family);

bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name, QuicEcnCodepoint ecn,
                   bool is_pmtu_probe = false);
bool send_datagrams(std::span<const QuicIoEngineTxDatagram> datagrams, std::string_view role_name);
ReceiveDatagramResult receive_datagram(int socket_fd, std::string_view role_name, int flags);
PathMtuUpdateResult receive_path_mtu_update(int socket_fd, std::string_view role_name);

SocketIoPeerTupleKey peer_tuple_key(int socket_fd, const sockaddr_storage &peer,
                                    socklen_t peer_len);
QuicRouteHandle remember_route_handle(SocketIoRouteState &state, const sockaddr_storage &peer,
                                      socklen_t peer_len, int socket_fd);
std::vector<std::byte> address_validation_identity_from_peer(const sockaddr_storage &peer,
                                                             socklen_t peer_len);

} // namespace coquic::io::internal
