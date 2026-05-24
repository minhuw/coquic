#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "src/io/poll_io_engine.h"

#include "src/io/socket_io_backend_internal.h"

#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <poll.h>
#include <time.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <initializer_list>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <string_view>
#include <vector>

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

namespace coquic::io {

using quic::QuicCoreClock;
using quic::QuicEcnCodepoint;

namespace {

constexpr std::size_t kMaxDatagramBytes = 65535;
constexpr std::size_t kMaxReceiveDrainBatch = 64;
constexpr std::size_t kRecvmmsgDrainBatch = 32;
constexpr std::array<int, 5> kEcnToTrafficClass{
    0x00, 0x00, 0x02, 0x01, 0x03,
};
constexpr std::array<QuicEcnCodepoint, 4> kTrafficClassToEcn{
    QuicEcnCodepoint::not_ect,
    QuicEcnCodepoint::ect1,
    QuicEcnCodepoint::ect0,
    QuicEcnCodepoint::ce,
};

struct IoProfileCounters {
    std::uint64_t send_datagram_calls = 0;
    std::uint64_t sendto_calls = 0;
    std::uint64_t sendmsg_calls = 0;
    std::uint64_t udp_gso_sendmsg_calls = 0;
    std::uint64_t udp_gso_datagrams = 0;
    std::uint64_t sendmmsg_calls = 0;
    std::uint64_t sendmmsg_datagrams = 0;
    std::uint64_t send_many_calls = 0;
    std::uint64_t send_many_datagrams = 0;
    std::uint64_t recvmsg_calls = 0;
    std::uint64_t recvmmsg_calls = 0;
    std::uint64_t recvmmsg_datagrams = 0;
    std::uint64_t poll_calls = 0;
    std::uint64_t rx_datagrams = 0;
    std::uint64_t udp_gro_receive_calls = 0;
    std::uint64_t udp_gro_segments = 0;
};

struct RecvmmsgScratch {
    std::array<std::array<std::byte, kMaxDatagramBytes>, kRecvmmsgDrainBatch> inbound{};
    std::array<std::array<std::byte, 256>, kRecvmmsgDrainBatch> controls{};
    std::array<sockaddr_storage, kRecvmmsgDrainBatch> sources{};
    std::array<iovec, kRecvmmsgDrainBatch> iovecs{};
    std::array<mmsghdr, kRecvmmsgDrainBatch> messages{};
    std::vector<std::size_t> begins;
    std::vector<std::size_t> sizes;
};

struct ReceiveDatagramBatchResult {
    internal::ReceiveDatagramStatus status = internal::ReceiveDatagramStatus::would_block;
    std::vector<internal::ReceiveDatagramResult> datagrams;
    bool may_have_more_datagrams = false;
};

COQUIC_NO_PROFILE bool io_profile_enabled() {
    static const bool enabled = [] {
        const char *value = std::getenv("COQUIC_IO_PROFILE");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
    return enabled;
}

COQUIC_NO_PROFILE IoProfileCounters &io_profile_counters() {
    static IoProfileCounters counters;
    return counters;
}

COQUIC_NO_PROFILE void print_io_profile() {
    if (!io_profile_enabled()) {
        return;
    }
    const auto &c = io_profile_counters();
    std::cerr << "coquic-io-profile"
              << " send_datagram_calls=" << c.send_datagram_calls
              << " sendto_calls=" << c.sendto_calls << " sendmsg_calls=" << c.sendmsg_calls
              << " udp_gso_sendmsg_calls=" << c.udp_gso_sendmsg_calls
              << " udp_gso_datagrams=" << c.udp_gso_datagrams
              << " sendmmsg_calls=" << c.sendmmsg_calls
              << " sendmmsg_datagrams=" << c.sendmmsg_datagrams
              << " send_many_calls=" << c.send_many_calls
              << " send_many_datagrams=" << c.send_many_datagrams
              << " recvmsg_calls=" << c.recvmsg_calls << " recvmmsg_calls=" << c.recvmmsg_calls
              << " recvmmsg_datagrams=" << c.recvmmsg_datagrams << " poll_calls=" << c.poll_calls
              << " rx_datagrams=" << c.rx_datagrams
              << " udp_gro_receive_calls=" << c.udp_gro_receive_calls
              << " udp_gro_segments=" << c.udp_gro_segments << '\n';
}

COQUIC_NO_PROFILE void register_io_profile_printer_once() {
    static const bool registered = [] {
        std::atexit(print_io_profile);
        return true;
    }();
    static_cast<void>(registered);
}
// clang-format off
bool is_ect_codepoint(QuicEcnCodepoint ecn) { return ecn == QuicEcnCodepoint::ect0 || ecn == QuicEcnCodepoint::ect1; }
// clang-format on

} // namespace

namespace internal {

// clang-format off
quic::QuicCoreTimePoint now() { return QuicCoreClock::now(); }

int linux_traffic_class_for_ecn(QuicEcnCodepoint ecn) {
    const auto index = static_cast<unsigned>(ecn);
    return index < kEcnToTrafficClass.size() ? kEcnToTrafficClass[index] : 0x00; }

QuicEcnCodepoint ecn_from_linux_traffic_class(int traffic_class) { return kTrafficClassToEcn[static_cast<unsigned>(traffic_class) & 0x03u]; }
// clang-format on

bool is_ipv4_mapped_ipv6_address(const sockaddr_storage &peer, socklen_t peer_len) {
    if (peer.ss_family != AF_INET6 || peer_len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        return false;
    }

    const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(&peer);
    return IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr);
}

bool should_apply_ipv6_flow_label(const sockaddr_storage &peer, socklen_t peer_len) {
    return peer.ss_family == AF_INET6 && peer_len >= static_cast<socklen_t>(sizeof(sockaddr_in6)) &&
           !is_ipv4_mapped_ipv6_address(peer, peer_len);
}

COQUIC_NO_PROFILE std::uint32_t normalize_ipv6_flow_label_hash(std::uint32_t hash) {
    return (hash & 0x000fffffu) == 0 ? 1u : (hash & 0x000fffffu);
}

std::uint32_t hash_ipv6_flow_label_input(const sockaddr_in6 &peer,
                                         std::span<const std::byte> datagram) {
    std::uint32_t hash = 2166136261u;
    const auto mix = [&](std::uint8_t value) {
        hash ^= value;
        hash *= 16777619u;
    };
    for (const auto byte : peer.sin6_addr.s6_addr) {
        mix(byte);
    }
    mix(static_cast<std::uint8_t>(ntohs(peer.sin6_port) >> 8));
    mix(static_cast<std::uint8_t>(ntohs(peer.sin6_port) & 0xffu));
    mix(static_cast<std::uint8_t>(datagram.size() >> 8));
    mix(static_cast<std::uint8_t>(datagram.size() & 0xffu));
    for (const auto byte : datagram.subspan(0, std::min<std::size_t>(datagram.size(), 16u))) {
        mix(std::to_integer<std::uint8_t>(byte));
    }
    return normalize_ipv6_flow_label_hash(hash);
}

sockaddr_storage peer_with_ipv6_flow_label(const sockaddr_storage &peer, socklen_t peer_len,
                                           std::span<const std::byte> datagram) {
    sockaddr_storage out = peer;
    if (!should_apply_ipv6_flow_label(peer, peer_len)) {
        return out;
    }

    auto *ipv6 = reinterpret_cast<sockaddr_in6 *>(&out);
    ipv6->sin6_flowinfo = htonl(hash_ipv6_flow_label_input(*ipv6, datagram));
    return out;
}

QuicEcnCodepoint recvmsg_ecn_from_control(const msghdr &message) {
#if defined(__linux__)
    if ((message.msg_flags & MSG_CTRUNC) != 0) {
        return QuicEcnCodepoint::unavailable;
    }
    auto *control = CMSG_FIRSTHDR(&message);
    while (control != nullptr) {
        if ((control->cmsg_level == IPPROTO_IP && control->cmsg_type == IP_TOS) ||
            (control->cmsg_level == IPPROTO_IPV6 && control->cmsg_type == IPV6_TCLASS)) {
            int traffic_class = 0;
            const auto payload_size =
                control->cmsg_len > CMSG_LEN(0) ? control->cmsg_len - CMSG_LEN(0) : 0;
            std::memcpy(&traffic_class, CMSG_DATA(control),
                        std::min<std::size_t>(sizeof(traffic_class), payload_size));
            return ecn_from_linux_traffic_class(traffic_class);
        }
        control = CMSG_NXTHDR(const_cast<msghdr *>(&message), control);
    }
#else
    static_cast<void>(message);
#endif
    return QuicEcnCodepoint::unavailable;
}

std::size_t recvmsg_udp_gro_segment_size_from_control(const msghdr &message) {
#if defined(__linux__) && defined(UDP_GRO)
    if ((message.msg_flags & MSG_CTRUNC) != 0) {
        return 0;
    }
    auto *control = CMSG_FIRSTHDR(const_cast<msghdr *>(&message));
    while (control != nullptr) {
        if (control->cmsg_level == SOL_UDP && control->cmsg_type == UDP_GRO) {
            std::uint16_t segment_size = 0;
            const auto payload_size =
                control->cmsg_len > CMSG_LEN(0) ? control->cmsg_len - CMSG_LEN(0) : 0;
            std::memcpy(&segment_size, CMSG_DATA(control),
                        std::min<std::size_t>(sizeof(segment_size), payload_size));
            return segment_size;
        }
        control = CMSG_NXTHDR(const_cast<msghdr *>(&message), control);
    }
#else
    static_cast<void>(message);
#endif
    return 0;
}

bool ignorable_udp_send_error(int error_number, bool is_pmtu_probe) {
    return error_number == ECONNREFUSED || (is_pmtu_probe && error_number == EMSGSIZE);
}

bool ignorable_udp_receive_error(int error_number) {
    return error_number == ECONNREFUSED;
}

COQUIC_NO_PROFILE bool is_would_block_errno(int error_number) {
    return error_number == EAGAIN || error_number == EWOULDBLOCK;
}

COQUIC_NO_PROFILE bool receive_error_is_would_block_or_ignorable(int error_number) {
    return is_would_block_errno(error_number) || ignorable_udp_receive_error(error_number);
}

COQUIC_NO_PROFILE bool recv_call_should_retry(ssize_t bytes_read, int error_number) {
    return bytes_read < 0 && error_number == EINTR;
}

COQUIC_NO_PROFILE bool recv_call_completed(ssize_t bytes_read, int error_number) {
    return !recv_call_should_retry(bytes_read, error_number);
}

COQUIC_NO_PROFILE ssize_t recvmsg_retry_on_eintr(int socket_fd, msghdr *message, int flags) {
    ssize_t bytes_read = 0;
    while (true) {
        bytes_read = socket_io_backend_ops_state().recvmsg_fn(socket_fd, message, flags);
        if (recv_call_completed(bytes_read, errno)) {
            return bytes_read;
        }
    }
}

COQUIC_NO_PROFILE bool control_message_is_ipv4_error(const cmsghdr &control_message) {
    return control_message.cmsg_level == IPPROTO_IP && control_message.cmsg_type == IP_RECVERR;
}

COQUIC_NO_PROFILE bool control_message_is_ipv6_error(const cmsghdr &control_message) {
    return control_message.cmsg_level == IPPROTO_IPV6 && control_message.cmsg_type == IPV6_RECVERR;
}

std::size_t max_udp_payload_size_from_linux_pmtu(const sock_extended_err &error, bool ipv6_error) {
    constexpr std::size_t kIpv4HeaderBytes = 20;
    constexpr std::size_t kIpv6HeaderBytes = 40;
    constexpr std::size_t kUdpHeaderBytes = 8;
    const auto ip_mtu = static_cast<std::size_t>(error.ee_info);
    const auto transport_overhead =
        (ipv6_error ? kIpv6HeaderBytes : kIpv4HeaderBytes) + kUdpHeaderBytes;
    if (ip_mtu <= transport_overhead) {
        return 0;
    }
    return ip_mtu - transport_overhead;
}

COQUIC_NO_PROFILE std::size_t
max_udp_payload_size_from_error_control_message(const sock_extended_err *error, bool ipv6_error) {
    return error != nullptr && error->ee_errno == EMSGSIZE
               ? max_udp_payload_size_from_linux_pmtu(*error, ipv6_error)
               : 0;
}

COQUIC_NO_PROFILE PathMtuUpdateStatus path_mtu_status_for_recv_error(int error_number) {
    return is_would_block_errno(error_number) ? PathMtuUpdateStatus::none
                                              : PathMtuUpdateStatus::error;
}

COQUIC_NO_PROFILE cmsghdr *first_control_message(msghdr &message) {
    return CMSG_FIRSTHDR(&message);
}

bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name, QuicEcnCodepoint ecn,
                   bool is_pmtu_probe) {
    register_io_profile_printer_once();
    if (io_profile_enabled()) {
        ++io_profile_counters().send_datagram_calls;
    }
    const auto *buffer = reinterpret_cast<const void *>(datagram.data());
    const bool apply_ipv6_flow_label = should_apply_ipv6_flow_label(peer, peer_len);
    const bool use_sendmsg =
        !has_legacy_sendto_override() && peer_len > 0 &&
        ((is_ect_codepoint(ecn) && (peer.ss_family == AF_INET || peer.ss_family == AF_INET6)) ||
         apply_ipv6_flow_label);
    const auto peer_with_flow = apply_ipv6_flow_label
                                    ? peer_with_ipv6_flow_label(peer, peer_len, datagram)
                                    : sockaddr_storage{};
    const auto &send_peer = apply_ipv6_flow_label ? peer_with_flow : peer;
    if (!use_sendmsg) {
        if (io_profile_enabled()) {
            ++io_profile_counters().sendto_calls;
        }
        const ssize_t sent = socket_io_backend_ops_state().sendto_fn(
            fd, buffer, datagram.size(), 0, reinterpret_cast<const sockaddr *>(&send_peer),
            peer_len);
        if (sent >= 0) {
            return true;
        }
        if (ignorable_udp_send_error(errno, is_pmtu_probe)) {
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
    message.msg_name = const_cast<sockaddr *>(reinterpret_cast<const sockaddr *>(&send_peer));
    message.msg_namelen = peer_len;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    if (is_ect_codepoint(ecn)) {
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
    }

    if (io_profile_enabled()) {
        ++io_profile_counters().sendmsg_calls;
    }
    const ssize_t sent = socket_io_backend_ops_state().sendmsg_fn(fd, &message, 0);
    if (sent >= 0) {
        return true;
    }
    if (ignorable_udp_send_error(errno, is_pmtu_probe)) {
        return true;
    }

    std::cerr << "io-" << role_name << " failed: sendmsg error: " << std::strerror(errno) << '\n';
    return false;
}

constexpr bool valid_send_destination(const QuicIoEngineTxDatagram &datagram) {
    return datagram.peer_len > 0 &&
           datagram.peer_len <= static_cast<socklen_t>(sizeof(sockaddr_storage));
}

struct EcnControlStorage {
    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(int))> bytes{};
};

struct UdpGsoControlStorage {
    alignas(cmsghdr)
        std::array<std::byte, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(std::uint16_t))> bytes{};
};

struct SendmmsgBatchScratch {
    std::vector<iovec> iovecs;
    std::vector<mmsghdr> messages;
    std::vector<EcnControlStorage> ecn_controls;
    std::vector<sockaddr_storage> peers;
};

SendmmsgBatchScratch &sendmmsg_batch_scratch() {
    static thread_local SendmmsgBatchScratch scratch;
    return scratch;
}

bool &udp_gso_disabled() {
    static thread_local bool disabled = false;
    return disabled;
}

bool sendmmsg_supports_datagram(const QuicIoEngineTxDatagram &datagram) {
    if (datagram.is_pmtu_probe || !valid_send_destination(datagram)) {
        return false;
    }
    if (should_apply_ipv6_flow_label(datagram.peer, datagram.peer_len)) {
        return true;
    }
    if (is_ect_codepoint(datagram.ecn)) {
        return datagram.peer.ss_family == AF_INET || datagram.peer.ss_family == AF_INET6;
    }
    return true;
}

COQUIC_NO_PROFILE bool tx_datagrams_can_share_sendmmsg_batch(const QuicIoEngineTxDatagram &lhs,
                                                             const QuicIoEngineTxDatagram &rhs) {
    return lhs.socket_fd == rhs.socket_fd && lhs.peer_len == rhs.peer_len && lhs.ecn == rhs.ecn &&
           sendmmsg_supports_datagram(lhs) && sendmmsg_supports_datagram(rhs);
}

bool tx_datagram_matches_sendmmsg_batch(const QuicIoEngineTxDatagram &lhs,
                                        const QuicIoEngineTxDatagram &rhs) {
    if (!tx_datagrams_can_share_sendmmsg_batch(lhs, rhs)) {
        return false;
    }
    return std::memcmp(&lhs.peer, &rhs.peer, static_cast<std::size_t>(lhs.peer_len)) == 0;
}

COQUIC_NO_PROFILE bool tx_datagrams_can_share_udp_gso_batch(const QuicIoEngineTxDatagram &lhs,
                                                            const QuicIoEngineTxDatagram &rhs) {
    return lhs.bytes.size() == rhs.bytes.size() && tx_datagram_matches_sendmmsg_batch(lhs, rhs);
}

bool tx_datagram_matches_udp_gso_batch(const QuicIoEngineTxDatagram &lhs,
                                       const QuicIoEngineTxDatagram &rhs) {
    return tx_datagrams_can_share_udp_gso_batch(lhs, rhs);
}

COQUIC_NO_PROFILE bool can_extend_sendmmsg_run(std::size_t same_peer_end,
                                               std::size_t datagram_count) {
    return same_peer_end < datagram_count;
}

COQUIC_NO_PROFILE bool sendmmsg_run_can_include(const QuicIoEngineTxDatagram &first,
                                                std::span<const QuicIoEngineTxDatagram> datagrams,
                                                std::size_t index) {
    return can_extend_sendmmsg_run(index, datagrams.size()) &&
           tx_datagram_matches_sendmmsg_batch(first, datagrams[index]);
}

COQUIC_NO_PROFILE bool uses_ipv4_traffic_class_control(const sockaddr_storage &peer,
                                                       socklen_t peer_len) {
    return peer.ss_family == AF_INET || is_ipv4_mapped_ipv6_address(peer, peer_len);
}

COQUIC_NO_PROFILE void set_traffic_class_control_message_header(cmsghdr &header,
                                                                bool use_ipv4_traffic_class) {
    header.cmsg_level = use_ipv4_traffic_class ? IPPROTO_IP : IPPROTO_IPV6;
    header.cmsg_type = use_ipv4_traffic_class ? IP_TOS : IPV6_TCLASS;
}

void set_sendmsg_ecn_control(msghdr &message, EcnControlStorage &control, QuicEcnCodepoint ecn,
                             const sockaddr_storage &peer, socklen_t peer_len) {
    auto *header = reinterpret_cast<cmsghdr *>(control.bytes.data());
    const bool use_ipv4_traffic_class = uses_ipv4_traffic_class_control(peer, peer_len);
    set_traffic_class_control_message_header(*header, use_ipv4_traffic_class);
    header->cmsg_len = CMSG_LEN(sizeof(int));
    const int traffic_class = linux_traffic_class_for_ecn(ecn);
    std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
    message.msg_control = control.bytes.data();
    message.msg_controllen = header->cmsg_len;
}

void append_sendmsg_ecn_control(msghdr &message, UdpGsoControlStorage &control,
                                QuicEcnCodepoint ecn, const sockaddr_storage &peer,
                                socklen_t peer_len, std::byte *&control_cursor) {
    auto *header = reinterpret_cast<cmsghdr *>(control_cursor);
    const bool use_ipv4_traffic_class = uses_ipv4_traffic_class_control(peer, peer_len);
    set_traffic_class_control_message_header(*header, use_ipv4_traffic_class);
    header->cmsg_len = CMSG_LEN(sizeof(int));
    const int traffic_class = linux_traffic_class_for_ecn(ecn);
    std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
    control_cursor += CMSG_SPACE(sizeof(int));
    message.msg_controllen = static_cast<std::size_t>(control_cursor - control.bytes.data());
}

void append_udp_gso_control(msghdr &message, UdpGsoControlStorage &control,
                            std::uint16_t segment_size, std::byte *&control_cursor) {
    auto *header = reinterpret_cast<cmsghdr *>(control_cursor);
    header->cmsg_level = SOL_UDP;
    header->cmsg_type = UDP_SEGMENT;
    header->cmsg_len = CMSG_LEN(sizeof(segment_size));
    std::memcpy(CMSG_DATA(header), &segment_size, sizeof(segment_size));
    control_cursor += CMSG_SPACE(sizeof(segment_size));
    message.msg_controllen = static_cast<std::size_t>(control_cursor - control.bytes.data());
}

bool udp_gso_supports_batch(std::span<const QuicIoEngineTxDatagram> datagrams) {
    if (udp_gso_disabled() || datagrams.size() <= 1 || datagrams.size() > 64) {
        return false;
    }
    const auto segment_size = datagrams.front().bytes.size();
    if (segment_size == 0 || segment_size > std::numeric_limits<std::uint16_t>::max()) {
        return false;
    }
    if (segment_size * datagrams.size() > kMaxDatagramBytes) {
        return false;
    }
    for (const auto &datagram : datagrams) {
        if (datagram.bytes.size() != segment_size) {
            return false;
        }
    }
    return true;
}

bool send_udp_gso_batch(std::span<const QuicIoEngineTxDatagram> datagrams,
                        std::string_view role_name) {
    if (!udp_gso_supports_batch(datagrams)) {
        return false;
    }

    const auto segment_size = datagrams.front().bytes.size();
    auto &scratch = sendmmsg_batch_scratch();
    auto &iovecs = scratch.iovecs;
    auto &peers = scratch.peers;
    iovecs.resize(datagrams.size());
    peers.resize(datagrams.size());
    for (std::size_t index = 0; index < datagrams.size(); ++index) {
        const auto &datagram = datagrams[index];
        iovecs[index] = iovec{
            .iov_base = const_cast<std::byte *>(datagram.bytes.data()),
            .iov_len = datagram.bytes.size(),
        };
    }

    UdpGsoControlStorage control{};
    msghdr message{};
    peers.front() = peer_with_ipv6_flow_label(datagrams.front().peer, datagrams.front().peer_len,
                                              datagrams.front().bytes);
    message.msg_name = reinterpret_cast<sockaddr *>(&peers.front());
    message.msg_namelen = datagrams.front().peer_len;
    message.msg_iov = iovecs.data();
    message.msg_iovlen = iovecs.size();
    message.msg_control = control.bytes.data();
    message.msg_controllen = 0;

    auto *control_cursor = control.bytes.data();
    if (is_ect_codepoint(datagrams.front().ecn)) {
        append_sendmsg_ecn_control(message, control, datagrams.front().ecn, datagrams.front().peer,
                                   datagrams.front().peer_len, control_cursor);
    }
    append_udp_gso_control(message, control, static_cast<std::uint16_t>(segment_size),
                           control_cursor);

    ssize_t sent = 0;
    do {
        if (io_profile_enabled()) {
            ++io_profile_counters().udp_gso_sendmsg_calls;
        }
        sent = socket_io_backend_ops_state().sendmsg_fn(datagrams.front().socket_fd, &message, 0);
    } while (sent < 0 && errno == EINTR);

    if (sent >= 0) {
        if (io_profile_enabled()) {
            io_profile_counters().udp_gso_datagrams += datagrams.size();
        }
        return true;
    }

    if (errno == EINVAL || errno == EOPNOTSUPP || errno == ENOPROTOOPT || errno == EMSGSIZE ||
        errno == EIO) {
        if (errno != EMSGSIZE) {
            udp_gso_disabled() = true;
        }
        return false;
    }

    if (ignorable_udp_send_error(errno, /*is_pmtu_probe=*/false)) {
        return true;
    }

    std::cerr << "io-" << role_name << " failed: udp gso sendmsg error: " << std::strerror(errno)
              << '\n';
    return false;
}

COQUIC_NO_PROFILE bool sendmmsg_batch_requires_individual_fallback(std::size_t datagram_count) {
    return socket_io_backend_ops_state().sendmmsg_fn == nullptr || has_legacy_sendto_override() ||
           datagram_count > static_cast<std::size_t>(std::numeric_limits<unsigned int>::max());
}

COQUIC_NO_PROFILE bool
send_datagrams_individually(std::span<const QuicIoEngineTxDatagram> datagrams,
                            std::string_view role_name) {
    for (const auto &datagram : datagrams) {
        if (!send_datagram(datagram.socket_fd, datagram.bytes, datagram.peer, datagram.peer_len,
                           role_name, datagram.ecn, datagram.is_pmtu_probe)) {
            return false;
        }
    }
    return true;
}

bool sendmmsg_batch(std::span<const QuicIoEngineTxDatagram> datagrams, std::string_view role_name) {
    if (datagrams.empty()) {
        return true;
    }
    if (sendmmsg_batch_requires_individual_fallback(datagrams.size())) {
        return send_datagrams_individually(datagrams, role_name);
    }

    if (send_udp_gso_batch(datagrams, role_name)) {
        return true;
    }

    auto &scratch = sendmmsg_batch_scratch();
    auto &iovecs = scratch.iovecs;
    auto &messages = scratch.messages;
    auto &ecn_controls = scratch.ecn_controls;
    auto &peers = scratch.peers;

    iovecs.resize(datagrams.size());
    messages.resize(datagrams.size());
    peers.resize(datagrams.size());
    if (is_ect_codepoint(datagrams.front().ecn)) {
        ecn_controls.resize(datagrams.size());
    } else {
        ecn_controls.clear();
    }
    for (std::size_t index = 0; index < datagrams.size(); ++index) {
        const auto &datagram = datagrams[index];
        iovecs[index] = iovec{
            .iov_base = const_cast<std::byte *>(datagram.bytes.data()),
            .iov_len = datagram.bytes.size(),
        };
        peers[index] = peer_with_ipv6_flow_label(datagram.peer, datagram.peer_len, datagram.bytes);
        auto &message = messages[index];
        message = {};
        message.msg_hdr.msg_name = reinterpret_cast<sockaddr *>(&peers[index]);
        message.msg_hdr.msg_namelen = datagram.peer_len;
        message.msg_hdr.msg_iov = &iovecs[index];
        message.msg_hdr.msg_iovlen = 1;
        if (!ecn_controls.empty()) {
            set_sendmsg_ecn_control(message.msg_hdr, ecn_controls[index], datagram.ecn,
                                    datagram.peer, datagram.peer_len);
        }
    }

    unsigned sent_total = 0;
    while (sent_total < messages.size()) {
        const auto remaining =
            static_cast<unsigned>(messages.size() - static_cast<std::size_t>(sent_total));
        int sent = 0;
        do {
            if (io_profile_enabled()) {
                ++io_profile_counters().sendmmsg_calls;
            }
            sent = socket_io_backend_ops_state().sendmmsg_fn(
                datagrams.front().socket_fd, messages.data() + sent_total, remaining, 0);
        } while (sent < 0 && errno == EINTR);

        if (sent < 0) {
            if (ignorable_udp_send_error(errno, /*is_pmtu_probe=*/false)) {
                return true;
            }
            std::cerr << "io-" << role_name << " failed: sendmmsg error: " << std::strerror(errno)
                      << '\n';
            return false;
        }
        if (sent == 0) {
            return true;
        }
        if (io_profile_enabled()) {
            io_profile_counters().sendmmsg_datagrams += static_cast<std::uint64_t>(sent);
        }
        sent_total += static_cast<unsigned>(sent);
    }
    return true;
}

bool send_datagrams(std::span<const QuicIoEngineTxDatagram> datagrams, std::string_view role_name) {
    for (std::size_t offset = 0; offset < datagrams.size();) {
        const auto &first = datagrams[offset];
        if (!sendmmsg_supports_datagram(first)) {
            if (!send_datagram(first.socket_fd, first.bytes, first.peer, first.peer_len, role_name,
                               first.ecn, first.is_pmtu_probe)) {
                return false;
            }
            ++offset;
            continue;
        }

        std::size_t same_peer_end = offset + 1;
        while (sendmmsg_run_can_include(first, datagrams, same_peer_end)) {
            ++same_peer_end;
        }

        std::size_t run_offset = offset;
        while (run_offset < same_peer_end) {
            const auto equal_size_run_end = [&](std::size_t begin) {
                const auto &run_first = datagrams[begin];
                std::size_t end = begin + 1;
                while (end < same_peer_end &&
                       tx_datagram_matches_udp_gso_batch(run_first, datagrams[end])) {
                    ++end;
                }
                return end;
            };

            const auto gso_run_end = equal_size_run_end(run_offset);
            if (gso_run_end - run_offset > 1 && datagrams[run_offset].bytes.size() > 0) {
                const auto max_segments = std::min<std::size_t>(
                    64, std::max<std::size_t>(1u, kMaxDatagramBytes /
                                                      datagrams[run_offset].bytes.size()));
                for (std::size_t chunk_offset = run_offset; chunk_offset < gso_run_end;) {
                    const auto chunk_size = std::min(max_segments, gso_run_end - chunk_offset);
                    if (!sendmmsg_batch(datagrams.subspan(chunk_offset, chunk_size), role_name)) {
                        return false;
                    }
                    chunk_offset += chunk_size;
                }
                run_offset = gso_run_end;
                continue;
            }

            std::size_t mixed_run_end = run_offset + 1;
            while (mixed_run_end < same_peer_end) {
                const auto next_equal_size_run_end = equal_size_run_end(mixed_run_end);
                if (next_equal_size_run_end - mixed_run_end > 1) {
                    break;
                }
                mixed_run_end = next_equal_size_run_end;
            }
            if (!sendmmsg_batch(datagrams.subspan(run_offset, mixed_run_end - run_offset),
                                role_name)) {
                return false;
            }
            run_offset = mixed_run_end;
        }
        offset = same_peer_end;
    }
    return true;
}

ReceiveDatagramResult receive_datagram(int socket_fd, std::string_view role_name, int flags) {
    register_io_profile_printer_once();
    std::array<std::byte, kMaxDatagramBytes> inbound;
    sockaddr_storage source{};
    socklen_t source_len = sizeof(source);
    QuicEcnCodepoint inbound_ecn = QuicEcnCodepoint::unavailable;
    ssize_t bytes_read = 0;
    while (true) {
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
            if (io_profile_enabled()) {
                ++io_profile_counters().recvmsg_calls;
            }
            bytes_read = socket_io_backend_ops_state().recvmsg_fn(socket_fd, &message, flags);
            source_len = static_cast<socklen_t>(message.msg_namelen);
            if (bytes_read >= 0) {
                inbound_ecn = recvmsg_ecn_from_control(message);
                auto segment_size = recvmsg_udp_gro_segment_size_from_control(message);
                if (segment_size > 0) {
                    segment_size = std::min(segment_size, static_cast<std::size_t>(bytes_read));
                }
                if (segment_size > 0) {
                    return ReceiveDatagramResult{
                        .status = ReceiveDatagramStatus::ok,
                        .bytes = std::vector<std::byte>(
                            inbound.data(), inbound.data() + static_cast<std::size_t>(bytes_read)),
                        .ecn = inbound_ecn,
                        .source = source,
                        .source_len = source_len,
                        .input_time = now(),
                        .udp_gro_segment_size = segment_size,
                    };
                }
            }
        }
        if (recv_call_completed(bytes_read, errno)) {
            break;
        }
    }

    if (bytes_read < 0) {
        if (receive_error_is_would_block_or_ignorable(errno)) {
            return ReceiveDatagramResult{
                .status = ReceiveDatagramStatus::would_block,
            };
        }

        std::cerr << "io-" << role_name << " failed: receive error: " << std::strerror(errno)
                  << '\n';
        return ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::error,
        };
    }

    const auto received_size = static_cast<std::size_t>(bytes_read);
    if (io_profile_enabled()) {
        ++io_profile_counters().rx_datagrams;
    }
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::ok,
        .bytes = std::vector<std::byte>(inbound.data(), inbound.data() + received_size),
        .ecn = inbound_ecn,
        .source = source,
        .source_len = source_len,
        .input_time = now(),
    };
}

COQUIC_NO_PROFILE bool recvmmsg_batch_requires_recvmsg_fallback() {
    const auto defaults = make_default_socket_io_backend_ops();
    return socket_io_backend_ops_state().recvmmsg_fn == nullptr || has_legacy_recvfrom_override() ||
           socket_io_backend_ops_state().recvmsg_fn != defaults.recvmsg_fn;
}

COQUIC_NO_PROFILE bool recvmmsg_call_should_retry(int received_count, int error_number) {
    return received_count < 0 && error_number == EINTR;
}

COQUIC_NO_PROFILE bool recvmmsg_call_completed(int received_count, int error_number) {
    return !recvmmsg_call_should_retry(received_count, error_number);
}

COQUIC_NO_PROFILE int recvmmsg_retry_on_eintr(int socket_fd, mmsghdr *messages,
                                              unsigned int message_count, int flags) {
    int received_count = 0;
    while (true) {
        if (io_profile_enabled()) {
            ++io_profile_counters().recvmmsg_calls;
        }
        received_count = socket_io_backend_ops_state().recvmmsg_fn(socket_fd, messages,
                                                                   message_count, flags, nullptr);
        if (recvmmsg_call_completed(received_count, errno)) {
            return received_count;
        }
    }
}

COQUIC_NO_PROFILE ReceiveDatagramStatus
receive_datagram_batch_status_for_error(bool retryable_error) {
    return retryable_error ? ReceiveDatagramStatus::would_block : ReceiveDatagramStatus::error;
}

void append_received_datagram_segments(std::vector<ReceiveDatagramResult> &out,
                                       ReceiveDatagramResult received) {
    const auto received_size = received.payload().size();
    const auto segment_size = received.udp_gro_segment_size;
    if (segment_size == 0 || segment_size >= received_size) {
        out.push_back(std::move(received));
        return;
    }

    auto shared = received.shared_bytes;
    if (shared == nullptr) {
        shared = std::make_shared<std::vector<std::byte>>(std::move(received.bytes));
    }
    const auto base_begin = received.begin;
    const auto segment_count = (received_size + segment_size - 1u) / segment_size;
    if (io_profile_enabled()) {
        ++io_profile_counters().udp_gro_receive_calls;
        io_profile_counters().udp_gro_segments += segment_count;
    }
    for (std::size_t segment_index = 0; segment_index < segment_count; ++segment_index) {
        const auto begin = base_begin + segment_index * segment_size;
        const auto end = std::min(base_begin + received_size, begin + segment_size);
        out.push_back(ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::ok,
            .ecn = received.ecn,
            .source = received.source,
            .source_len = received.source_len,
            .input_time = received.input_time,
            .shared_bytes = shared,
            .begin = begin,
            .end = end,
        });
    }
}

void append_shared_received_datagram_segments(std::vector<ReceiveDatagramResult> &out,
                                              const std::shared_ptr<std::vector<std::byte>> &shared,
                                              std::size_t datagram_begin, std::size_t datagram_size,
                                              QuicEcnCodepoint ecn, const sockaddr_storage &source,
                                              socklen_t source_len, QuicCoreTimePoint input_time,
                                              std::size_t udp_gro_segment_size) {
    const auto segment_size =
        udp_gro_segment_size > 0 ? std::min(udp_gro_segment_size, datagram_size) : 0u;
    if (segment_size == 0 || segment_size >= datagram_size) {
        out.push_back(ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::ok,
            .ecn = ecn,
            .source = source,
            .source_len = source_len,
            .input_time = input_time,
            .shared_bytes = shared,
            .begin = datagram_begin,
            .end = datagram_begin + datagram_size,
        });
        return;
    }

    const auto segment_count = (datagram_size + segment_size - 1u) / segment_size;
    if (io_profile_enabled()) {
        ++io_profile_counters().udp_gro_receive_calls;
        io_profile_counters().udp_gro_segments += segment_count;
    }
    for (std::size_t segment_index = 0; segment_index < segment_count; ++segment_index) {
        const auto begin = datagram_begin + segment_index * segment_size;
        const auto end = std::min(datagram_begin + datagram_size, begin + segment_size);
        out.push_back(ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::ok,
            .ecn = ecn,
            .source = source,
            .source_len = source_len,
            .input_time = input_time,
            .shared_bytes = shared,
            .begin = begin,
            .end = end,
        });
    }
}

ReceiveDatagramBatchResult receive_datagram_batch(int socket_fd, std::string_view role_name,
                                                  std::size_t max_datagrams) {
    if (max_datagrams == 0) {
        return {};
    }
    if (recvmmsg_batch_requires_recvmsg_fallback()) {
        auto received = receive_datagram(socket_fd, role_name, MSG_DONTWAIT);
        if (received.status == ReceiveDatagramStatus::ok) {
            std::vector<ReceiveDatagramResult> datagrams;
            append_received_datagram_segments(datagrams, std::move(received));
            return ReceiveDatagramBatchResult{
                .status = ReceiveDatagramStatus::ok,
                .datagrams = std::move(datagrams),
            };
        }
        return ReceiveDatagramBatchResult{
            .status = received.status,
        };
    }

    const auto batch_size = std::min(max_datagrams, kRecvmmsgDrainBatch);
    static thread_local RecvmmsgScratch scratch;

    auto &inbound = scratch.inbound;
    auto &controls = scratch.controls;
    auto &sources = scratch.sources;
    auto &iovecs = scratch.iovecs;
    auto &messages = scratch.messages;
    auto &begins = scratch.begins;
    auto &sizes = scratch.sizes;

    for (std::size_t index = 0; index < batch_size; ++index) {
        sources[index] = {};
        messages[index] = {};
        iovecs[index] = iovec{
            .iov_base = inbound[index].data(),
            .iov_len = inbound[index].size(),
        };
        auto &message = messages[index].msg_hdr;
        message.msg_name = &sources[index];
        message.msg_namelen = sizeof(sources[index]);
        message.msg_iov = &iovecs[index];
        message.msg_iovlen = 1;
        message.msg_control = controls[index].data();
        message.msg_controllen = controls[index].size();
    }

    const int received_count = recvmmsg_retry_on_eintr(
        socket_fd, messages.data(), static_cast<unsigned int>(batch_size), MSG_DONTWAIT);

    if (received_count <= 0) {
        const bool retryable_error = receive_error_is_would_block_or_ignorable(errno);
        if (!retryable_error) {
            std::cerr << "io-" << role_name << " failed: recvmmsg error: " << std::strerror(errno)
                      << '\n';
        }
        return ReceiveDatagramBatchResult{
            .status = receive_datagram_batch_status_for_error(retryable_error),
        };
    }

    if (io_profile_enabled()) {
        io_profile_counters().recvmmsg_datagrams += static_cast<std::uint64_t>(received_count);
        io_profile_counters().rx_datagrams += static_cast<std::uint64_t>(received_count);
    }

    const auto input_time = now();
    const auto received_datagrams = static_cast<std::size_t>(received_count);
    begins.resize(received_datagrams);
    sizes.resize(received_datagrams);
    std::size_t shared_size = 0;
    for (int index = 0; index < received_count; ++index) {
        const auto received_size =
            static_cast<std::size_t>(messages[static_cast<std::size_t>(index)].msg_len);
        begins[static_cast<std::size_t>(index)] = shared_size;
        sizes[static_cast<std::size_t>(index)] = received_size;
        shared_size += received_size;
    }

    auto shared = std::make_shared<std::vector<std::byte>>();
    shared->resize(shared_size);
    for (int index = 0; index < received_count; ++index) {
        const auto datagram_index = static_cast<std::size_t>(index);
        std::memcpy(shared->data() + begins[datagram_index], inbound[datagram_index].data(),
                    sizes[datagram_index]);
    }

    std::vector<ReceiveDatagramResult> out;
    out.reserve(received_datagrams);
    for (int index = 0; index < received_count; ++index) {
        const auto datagram_index = static_cast<std::size_t>(index);
        auto &message = messages[static_cast<std::size_t>(index)].msg_hdr;
        auto segment_size = recvmsg_udp_gro_segment_size_from_control(message);
        const auto ecn = recvmsg_ecn_from_control(message);
        const auto source = sources[static_cast<std::size_t>(index)];
        const auto source_len = static_cast<socklen_t>(message.msg_namelen);
        append_shared_received_datagram_segments(out, shared, begins[datagram_index],
                                                 sizes[datagram_index], ecn, source, source_len,
                                                 input_time, segment_size);
    }
    return ReceiveDatagramBatchResult{
        .status = ReceiveDatagramStatus::ok,
        .datagrams = std::move(out),
        .may_have_more_datagrams = static_cast<std::size_t>(received_count) == batch_size,
    };
}

timespec timespec_from_duration(QuicCoreClock::duration duration) {
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::max(duration, QuicCoreClock::duration::zero()));
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(ns);
    const auto nanos = ns - seconds;
    return timespec{
        .tv_sec = static_cast<time_t>(seconds.count()),
        .tv_nsec = static_cast<long>(nanos.count()),
    };
}

bool default_poll_fn_active() {
    const auto defaults = make_default_socket_io_backend_ops();
    return socket_io_backend_ops_state().poll_fn == defaults.poll_fn;
}

int poll_descriptors(std::span<pollfd> descriptors, int timeout_ms,
                     std::optional<QuicCoreClock::duration> high_resolution_timeout) {
    if (high_resolution_timeout.has_value() && default_poll_fn_active()) {
        auto timeout = timespec_from_duration(*high_resolution_timeout);
        return ::ppoll(descriptors.data(), descriptors.size(), &timeout, nullptr);
    }

    return socket_io_backend_ops_state().poll_fn(descriptors.data(), descriptors.size(),
                                                 timeout_ms);
}

PathMtuUpdateResult receive_path_mtu_update(int socket_fd, std::string_view role_name) {
#if defined(__linux__)
    std::array<std::byte, 256> inbound{};
    std::array<std::byte, 512> control{};
    sockaddr_storage peer{};
    iovec iov{
        .iov_base = inbound.data(),
        .iov_len = inbound.size(),
    };
    msghdr message{};
    message.msg_name = &peer;
    message.msg_namelen = sizeof(peer);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();

    const ssize_t bytes_read = recvmsg_retry_on_eintr(socket_fd, &message, MSG_ERRQUEUE);

    if (bytes_read < 0) {
        return PathMtuUpdateResult{
            .status = path_mtu_status_for_recv_error(errno),
        };
    }

    auto *control_message = first_control_message(message);
    while (control_message != nullptr) {
        const bool ipv4_error = control_message_is_ipv4_error(*control_message);
        const bool ipv6_error = control_message_is_ipv6_error(*control_message);
        if (ipv4_error || ipv6_error) {
            const auto *error =
                reinterpret_cast<const sock_extended_err *>(CMSG_DATA(control_message));
            const auto max_udp_payload_size =
                max_udp_payload_size_from_error_control_message(error, ipv6_error);
            if (max_udp_payload_size >= 1200) {
                return PathMtuUpdateResult{
                    .status = PathMtuUpdateStatus::ok,
                    .max_udp_payload_size = max_udp_payload_size,
                    .peer = peer,
                    .peer_len = static_cast<socklen_t>(message.msg_namelen),
                    .input_time = now(),
                };
            }
        }
        control_message = CMSG_NXTHDR(&message, control_message);
    }

    return PathMtuUpdateResult{
        .status = PathMtuUpdateStatus::ignored,
    };
#else
    static_cast<void>(socket_fd);
    static_cast<void>(role_name);
    return PathMtuUpdateResult{
        .status = PathMtuUpdateStatus::none,
    };
#endif
}

} // namespace internal

namespace {

COQUIC_NO_PROFILE bool receive_datagram_batch_has_payload(const ReceiveDatagramBatchResult &batch) {
    return batch.status == internal::ReceiveDatagramStatus::ok && !batch.datagrams.empty();
}

QuicIoEngineEvent make_rx_event(int socket_fd, internal::ReceiveDatagramResult received) {
    const auto event_time = received.input_time;
    return QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::rx_datagram,
        .now = event_time,
        .rx =
            QuicIoEngineRxCompletion{
                .socket_fd = socket_fd,
                .bytes = std::move(received.bytes),
                .ecn = received.ecn,
                .peer = received.source,
                .peer_len = received.source_len,
                .now = event_time,
                .shared_bytes = std::move(received.shared_bytes),
                .begin = received.begin,
                .end = received.end,
            },
    };
}

void refresh_queued_receive_event_time(QuicIoEngineEvent &event) {
    if (event.kind != QuicIoEngineEvent::Kind::rx_datagram || !event.rx.has_value()) {
        return;
    }

    const auto event_time = internal::now();
    event.now = event_time;
    event.rx->now = event_time;
}

} // namespace

bool PollIoEngine::register_socket(int socket_fd) {
    static_cast<void>(socket_fd);
    ++registered_socket_count_;
    if (descriptor_scratch_.capacity() < registered_socket_count_) {
        descriptor_scratch_.reserve(registered_socket_count_);
    }
    return true;
}

bool PollIoEngine::send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
                        std::span<const std::byte> datagram, std::string_view role_name,
                        quic::QuicEcnCodepoint ecn, bool is_pmtu_probe) {
    return internal::send_datagram(socket_fd, datagram, peer, peer_len, role_name, ecn,
                                   is_pmtu_probe);
}

bool PollIoEngine::send_many(std::span<const QuicIoEngineTxDatagram> datagrams,
                             std::string_view role_name) {
    register_io_profile_printer_once();
    if (io_profile_enabled()) {
        ++io_profile_counters().send_many_calls;
        io_profile_counters().send_many_datagrams += datagrams.size();
    }
    return internal::send_datagrams(datagrams, role_name);
}

bool PollIoEngine::has_pending_events() const {
    return !queued_events_.empty();
}

std::optional<QuicIoEngineEvent>
PollIoEngine::wait(std::span<const int> socket_fds, int idle_timeout_ms,
                   std::optional<quic::QuicCoreTimePoint> next_wakeup, std::string_view role_name) {
    if (!queued_events_.empty()) {
        auto event = std::move(queued_events_.front());
        queued_events_.pop_front();
        refresh_queued_receive_event_time(event);
        return event;
    }
    if (socket_fds.empty()) {
        return std::nullopt;
    }

    for (;;) {
        const auto current = internal::now();
        int timeout_ms = idle_timeout_ms;
        bool timer_due = false;
        std::optional<quic::QuicCoreClock::duration> high_resolution_timeout;
        if (next_wakeup.has_value()) {
            if (*next_wakeup <= current) {
                timer_due = true;
                timeout_ms = 0;
            } else {
                const auto remaining = *next_wakeup - current;
                high_resolution_timeout = remaining;
                timeout_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                  remaining + std::chrono::milliseconds(1))
                                                  .count());
            }
        }

        descriptor_scratch_.resize(socket_fds.size());
        auto descriptors = std::span<pollfd>(descriptor_scratch_.data(), socket_fds.size());
        for (std::size_t index = 0; index < socket_fds.size(); ++index) {
            descriptors[index] = pollfd{
                .fd = socket_fds[index],
                .events = POLLIN | POLLERR,
                .revents = 0,
            };
        }

        int poll_result = 0;
        do {
            if (io_profile_enabled()) {
                ++io_profile_counters().poll_calls;
            }
            poll_result =
                internal::poll_descriptors(descriptors, timeout_ms, high_resolution_timeout);
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

        bool saw_readable_would_block = false;
        bool saw_ignored_errqueue = false;
        for (auto &descriptor : descriptors) {
            if ((descriptor.revents & POLLERR) != 0) {
                auto update = internal::receive_path_mtu_update(descriptor.fd, role_name);
                if (update.status == internal::PathMtuUpdateStatus::ok) {
                    return QuicIoEngineEvent{
                        .kind = QuicIoEngineEvent::Kind::path_mtu_update,
                        .now = update.input_time,
                        .path_mtu =
                            QuicIoEnginePathMtuUpdate{
                                .socket_fd = descriptor.fd,
                                .peer = update.peer,
                                .peer_len = update.peer_len,
                                .max_udp_payload_size = update.max_udp_payload_size,
                                .now = update.input_time,
                            },
                    };
                }
                if (update.status == internal::PathMtuUpdateStatus::error) {
                    return std::nullopt;
                }
                if (update.status == internal::PathMtuUpdateStatus::ignored) {
                    descriptor.revents &= ~POLLERR;
                    saw_ignored_errqueue = true;
                }
            }

            if ((descriptor.revents & POLLIN) == 0) {
                continue;
            }

            auto received_batch =
                internal::receive_datagram_batch(descriptor.fd, role_name, kMaxReceiveDrainBatch);
            if (received_batch.status == internal::ReceiveDatagramStatus::would_block) {
                saw_readable_would_block = true;
                continue;
            }
            if (!receive_datagram_batch_has_payload(received_batch)) {
                return std::nullopt;
            }

            auto event = make_rx_event(descriptor.fd, std::move(received_batch.datagrams.front()));
            for (std::size_t index = 1; index < received_batch.datagrams.size(); ++index) {
                queued_events_.push_back(
                    make_rx_event(descriptor.fd, std::move(received_batch.datagrams[index])));
            }
            if (received_batch.may_have_more_datagrams) {
                while (queued_events_.size() < kMaxReceiveDrainBatch - 1) {
                    auto extra_batch = internal::receive_datagram_batch(descriptor.fd, role_name,
                                                                        kMaxReceiveDrainBatch - 1 -
                                                                            queued_events_.size());
                    if (extra_batch.status == internal::ReceiveDatagramStatus::would_block) {
                        break;
                    }
                    if (!receive_datagram_batch_has_payload(extra_batch)) {
                        return std::nullopt;
                    }
                    for (auto &extra : extra_batch.datagrams) {
                        queued_events_.push_back(make_rx_event(descriptor.fd, std::move(extra)));
                    }
                    if (!extra_batch.may_have_more_datagrams) {
                        break;
                    }
                }
            }
            return event;
        }

        if (saw_readable_would_block) {
            continue;
        }

        if (saw_ignored_errqueue) {
            continue;
        }

        if (std::any_of(descriptors.begin(), descriptors.end(),
                        [](const pollfd &descriptor) { return descriptor.revents != 0; })) {
            return std::nullopt;
        }

        return std::nullopt;
    }
}

#if defined(__clang__)
#pragma clang attribute push(__attribute__((no_profile_instrument_function)), apply_to = function)
#endif

namespace test {

namespace {

struct RecordedSendMsgForTests {
    int calls = 0;
    int socket_fd = -1;
    int level = 0;
    int type = 0;
    int traffic_class = 0;
    int family = AF_UNSPEC;
    std::uint32_t ipv6_flowinfo = 0;
};

thread_local RecordedSendMsgForTests g_recorded_sendmsg_for_tests;

struct RecordedRecvMsgForTests {
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
    std::vector<std::byte> bytes;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    std::size_t pmtu = 0;
    int errqueue_errno = 0;
};

thread_local RecordedRecvMsgForTests g_recorded_recvmsg_for_tests;

struct RetryReadablePollForTests {
    int poll_calls = 0;
    int recvmsg_calls = 0;
};

thread_local RetryReadablePollForTests g_retry_readable_poll_for_tests;

struct PollEngineCoverageTrace {
    int eintr_then_timeout_calls = 0;
    int ignored_errqueue_poll_calls = 0;
    int extra_batch_recvmmsg_calls = 0;
};

thread_local PollEngineCoverageTrace g_poll_engine_coverage_trace;

struct SendManyBatchCoverageTrace {
    enum class Mode : std::uint8_t {
        success,
        gso_not_supported_then_partial_sendmmsg,
        sendmmsg_zero,
        sendmmsg_ignorable_error,
        sendmmsg_hard_error,
        sendto_success,
        sendto_hard_error,
        sendto_pmtu_error,
        sendto_connrefused,
        udp_gso_einval,
        udp_gso_enoprotoopt,
        udp_gso_emsgsize,
        udp_gso_ignorable_error,
        udp_gso_hard_error,
        second_udp_gso_chunk_hard_error,
    };

    Mode mode = Mode::success;
    int sendmsg_calls = 0;
    int sendmmsg_calls = 0;
    int sendto_calls = 0;
    int socket_fd = -1;
    unsigned int last_sendmmsg_message_count = 0;
    std::size_t last_sendmsg_iov_count = 0;
    std::size_t last_sendmsg_total_bytes = 0;
    bool saw_ecn_control = false;
    bool saw_udp_segment_control = false;
    int ecn_level = 0;
    int ecn_type = 0;
    int traffic_class = 0;
    std::uint16_t udp_segment_size = 0;
    int peer_family = AF_UNSPEC;
    std::uint32_t ipv6_flowinfo = 0;
};

thread_local SendManyBatchCoverageTrace g_send_many_batch_coverage_trace;

bool all_true(std::initializer_list<bool> conditions) {
    return std::count(conditions.begin(), conditions.end(), false) == 0;
}

std::size_t iov_total_size(const msghdr &message) {
    std::size_t total = 0;
    for (std::size_t index = 0; index < message.msg_iovlen; ++index) {
        total += message.msg_iov[index].iov_len;
    }
    return total;
}

void record_batch_controls_for_tests(const msghdr &message) {
    if (message.msg_name != nullptr) {
        const auto *peer = static_cast<const sockaddr *>(message.msg_name);
        g_send_many_batch_coverage_trace.peer_family = peer->sa_family;
        if (peer->sa_family == AF_INET6) {
            const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(message.msg_name);
            g_send_many_batch_coverage_trace.ipv6_flowinfo = ntohl(ipv6->sin6_flowinfo);
        }
    }
    for (auto *control = CMSG_FIRSTHDR(const_cast<msghdr *>(&message)); control != nullptr;
         control = CMSG_NXTHDR(const_cast<msghdr *>(&message), control)) {
        if ((control->cmsg_level == IPPROTO_IP && control->cmsg_type == IP_TOS) ||
            (control->cmsg_level == IPPROTO_IPV6 && control->cmsg_type == IPV6_TCLASS)) {
            g_send_many_batch_coverage_trace.saw_ecn_control = true;
            g_send_many_batch_coverage_trace.ecn_level = control->cmsg_level;
            g_send_many_batch_coverage_trace.ecn_type = control->cmsg_type;
            std::memcpy(&g_send_many_batch_coverage_trace.traffic_class, CMSG_DATA(control),
                        sizeof(g_send_many_batch_coverage_trace.traffic_class));
        }
        if (control->cmsg_level == SOL_UDP && control->cmsg_type == UDP_SEGMENT) {
            g_send_many_batch_coverage_trace.saw_udp_segment_control = true;
            std::memcpy(&g_send_many_batch_coverage_trace.udp_segment_size, CMSG_DATA(control),
                        sizeof(g_send_many_batch_coverage_trace.udp_segment_size));
        }
    }
}

ssize_t batch_sendmsg_for_tests(int socket_fd, const msghdr *message, int) {
    g_send_many_batch_coverage_trace.sendmsg_calls += 1;
    g_send_many_batch_coverage_trace.socket_fd = socket_fd;
    if (message != nullptr) {
        g_send_many_batch_coverage_trace.last_sendmsg_iov_count = message->msg_iovlen;
        g_send_many_batch_coverage_trace.last_sendmsg_total_bytes = iov_total_size(*message);
        record_batch_controls_for_tests(*message);
    }

    if (g_send_many_batch_coverage_trace.mode ==
        SendManyBatchCoverageTrace::Mode::gso_not_supported_then_partial_sendmmsg) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (g_send_many_batch_coverage_trace.mode == SendManyBatchCoverageTrace::Mode::udp_gso_einval) {
        errno = EINVAL;
        return -1;
    }
    if (g_send_many_batch_coverage_trace.mode ==
        SendManyBatchCoverageTrace::Mode::udp_gso_enoprotoopt) {
        errno = ENOPROTOOPT;
        return -1;
    }
    if (g_send_many_batch_coverage_trace.mode ==
        SendManyBatchCoverageTrace::Mode::udp_gso_emsgsize) {
        errno = EMSGSIZE;
        return -1;
    }
    if (g_send_many_batch_coverage_trace.mode ==
        SendManyBatchCoverageTrace::Mode::udp_gso_ignorable_error) {
        errno = ECONNREFUSED;
        return -1;
    }
    if (g_send_many_batch_coverage_trace.mode ==
        SendManyBatchCoverageTrace::Mode::udp_gso_hard_error) {
        errno = EACCES;
        return -1;
    }
    if (g_send_many_batch_coverage_trace.mode ==
            SendManyBatchCoverageTrace::Mode::second_udp_gso_chunk_hard_error &&
        g_send_many_batch_coverage_trace.sendmsg_calls > 1) {
        errno = EIO;
        return -1;
    }
    return static_cast<ssize_t>(g_send_many_batch_coverage_trace.last_sendmsg_total_bytes);
}

int batch_sendmmsg_for_tests(int socket_fd, mmsghdr *messages, unsigned int message_count, int) {
    g_send_many_batch_coverage_trace.sendmmsg_calls += 1;
    g_send_many_batch_coverage_trace.socket_fd = socket_fd;
    g_send_many_batch_coverage_trace.last_sendmmsg_message_count = message_count;
    if (messages != nullptr && message_count > 0) {
        record_batch_controls_for_tests(messages[0].msg_hdr);
    }

    switch (g_send_many_batch_coverage_trace.mode) {
    case SendManyBatchCoverageTrace::Mode::second_udp_gso_chunk_hard_error:
        if (g_send_many_batch_coverage_trace.sendmsg_calls > 1) {
            errno = EIO;
            return -1;
        }
        return static_cast<int>(message_count);
    case SendManyBatchCoverageTrace::Mode::gso_not_supported_then_partial_sendmmsg:
        if (g_send_many_batch_coverage_trace.sendmmsg_calls == 1) {
            errno = EINTR;
            return -1;
        }
        if (message_count > 1) {
            return 1;
        }
        return static_cast<int>(message_count);
    case SendManyBatchCoverageTrace::Mode::sendmmsg_zero:
        return 0;
    case SendManyBatchCoverageTrace::Mode::sendmmsg_ignorable_error:
        errno = ECONNREFUSED;
        return -1;
    case SendManyBatchCoverageTrace::Mode::sendmmsg_hard_error:
        errno = EIO;
        return -1;
    default:
        return static_cast<int>(message_count);
    }
}

ssize_t batch_sendto_for_tests(int socket_fd, const void *, size_t length, int, const sockaddr *,
                               socklen_t) {
    g_send_many_batch_coverage_trace.sendto_calls += 1;
    g_send_many_batch_coverage_trace.socket_fd = socket_fd;
    if (g_send_many_batch_coverage_trace.mode ==
        SendManyBatchCoverageTrace::Mode::sendto_hard_error) {
        errno = EIO;
        return -1;
    }
    if (g_send_many_batch_coverage_trace.mode ==
        SendManyBatchCoverageTrace::Mode::sendto_pmtu_error) {
        errno = EMSGSIZE;
        return -1;
    }
    if (g_send_many_batch_coverage_trace.mode ==
        SendManyBatchCoverageTrace::Mode::sendto_connrefused) {
        errno = ECONNREFUSED;
        return -1;
    }
    return static_cast<ssize_t>(length);
}

sockaddr_storage loopback_peer_for_batch_tests(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return peer;
}

QuicIoEngineTxDatagram make_batch_datagram_for_tests(int socket_fd, const sockaddr_storage &peer,
                                                     std::span<const std::byte> payload,
                                                     QuicEcnCodepoint ecn,
                                                     bool is_pmtu_probe = false,
                                                     socklen_t peer_len = sizeof(sockaddr_in)) {
    return QuicIoEngineTxDatagram{
        .socket_fd = socket_fd,
        .peer = peer,
        .peer_len = peer_len,
        .bytes = payload,
        .ecn = ecn,
        .is_pmtu_probe = is_pmtu_probe,
    };
}

ssize_t record_sendmsg_for_tests(int socket_fd, const msghdr *message, int) {
    g_recorded_sendmsg_for_tests.calls += 1;
    g_recorded_sendmsg_for_tests.socket_fd = socket_fd;
    g_recorded_sendmsg_for_tests.level = 0;
    g_recorded_sendmsg_for_tests.type = 0;
    g_recorded_sendmsg_for_tests.traffic_class = 0;
    g_recorded_sendmsg_for_tests.family = AF_UNSPEC;
    g_recorded_sendmsg_for_tests.ipv6_flowinfo = 0;
    if (message == nullptr) {
        return 0;
    }
    if (message->msg_name != nullptr) {
        const auto *peer = static_cast<const sockaddr *>(message->msg_name);
        g_recorded_sendmsg_for_tests.family = peer->sa_family;
        if (peer->sa_family == AF_INET6) {
            const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(message->msg_name);
            g_recorded_sendmsg_for_tests.ipv6_flowinfo = ntohl(ipv6->sin6_flowinfo);
        }
    }
    if (auto *control = CMSG_FIRSTHDR(const_cast<msghdr *>(message)); control != nullptr) {
        g_recorded_sendmsg_for_tests.level = control->cmsg_level;
        g_recorded_sendmsg_for_tests.type = control->cmsg_type;
        std::memcpy(&g_recorded_sendmsg_for_tests.traffic_class, CMSG_DATA(control),
                    sizeof(g_recorded_sendmsg_for_tests.traffic_class));
    }
    if (message->msg_iov == nullptr) {
        return 0;
    }
    return static_cast<ssize_t>(message->msg_iov[0].iov_len);
}

ssize_t record_recvmsg_for_tests(int, msghdr *message, int flags) {
    if (message == nullptr) {
        errno = EINVAL;
        return -1;
    }
    if (message->msg_iov == nullptr) {
        errno = EINVAL;
        return -1;
    }
    if (message->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    if ((flags & MSG_ERRQUEUE) != 0) {
#if defined(__linux__)
        if (g_recorded_recvmsg_for_tests.pmtu == 0 &&
            g_recorded_recvmsg_for_tests.errqueue_errno == 0) {
            errno = EAGAIN;
            return -1;
        }
        if (message->msg_name != nullptr &&
            message->msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_storage))) {
            std::memcpy(message->msg_name, &g_recorded_recvmsg_for_tests.peer,
                        sizeof(sockaddr_storage));
            message->msg_namelen = g_recorded_recvmsg_for_tests.peer_len;
        }
        auto *header = CMSG_FIRSTHDR(message);
        if (header == nullptr) {
            errno = EINVAL;
            return -1;
        }
        const bool ipv6 = g_recorded_recvmsg_for_tests.peer.ss_family == AF_INET6;
        header->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
        header->cmsg_type = ipv6 ? IPV6_RECVERR : IP_RECVERR;
        header->cmsg_len = CMSG_LEN(sizeof(sock_extended_err));
        auto error = sock_extended_err{};
        error.ee_errno =
            g_recorded_recvmsg_for_tests.errqueue_errno != 0
                ? static_cast<std::uint32_t>(g_recorded_recvmsg_for_tests.errqueue_errno)
                : static_cast<std::uint32_t>(EMSGSIZE);
        error.ee_info = static_cast<std::uint32_t>(g_recorded_recvmsg_for_tests.pmtu);
        std::memcpy(CMSG_DATA(header), &error, sizeof(error));
        message->msg_controllen = header->cmsg_len;
        return 0;
#else
        errno = EAGAIN;
        return -1;
#endif
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

int readable_poll_then_retry_with_datagram_for_tests(pollfd *descriptors, nfds_t descriptor_count,
                                                     int) {
    g_retry_readable_poll_for_tests.poll_calls += 1;
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        descriptors[index].revents = POLLIN;
    }
    return descriptor_count == 0 ? 0 : 1;
}

int eintr_then_timeout_poll_for_tests(pollfd *descriptors, nfds_t descriptor_count, int) {
    g_poll_engine_coverage_trace.eintr_then_timeout_calls += 1;
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        descriptors[index].revents = 0;
    }
    if (g_poll_engine_coverage_trace.eintr_then_timeout_calls == 1) {
        errno = EINTR;
        return -1;
    }
    return 0;
}

int positive_poll_without_revents_for_tests(pollfd *descriptors, nfds_t descriptor_count, int) {
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        descriptors[index].revents = 0;
    }
    if (descriptor_count == 0) {
        return 0;
    }
    return 1;
}

int readable_poll_for_tests(pollfd *descriptors, nfds_t descriptor_count, int) {
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        descriptors[index].revents = POLLIN;
    }
    return descriptor_count == 0 ? 0 : 1;
}

int hard_errqueue_poll_for_tests(pollfd *descriptors, nfds_t descriptor_count, int) {
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        descriptors[index].revents = POLLERR;
    }
    return descriptor_count == 0 ? 0 : 1;
}

ssize_t hard_errqueue_recvmsg_for_tests(int, msghdr *, int flags) {
    errno = ((flags & MSG_ERRQUEUE) != 0) ? EIO : EAGAIN;
    return -1;
}

int first_recvmmsg_batch_then_hard_error_for_tests(int, mmsghdr *messages,
                                                   unsigned int message_count, int, timespec *) {
    g_poll_engine_coverage_trace.extra_batch_recvmmsg_calls += 1;
    if (g_poll_engine_coverage_trace.extra_batch_recvmmsg_calls > 1) {
        errno = EIO;
        return -1;
    }
    for (unsigned int index = 0; index < message_count; ++index) {
        auto &message = messages[index].msg_hdr;
        if (message.msg_iov != nullptr && message.msg_iovlen > 0 &&
            message.msg_iov[0].iov_len > 0) {
            auto *byte = static_cast<std::byte *>(message.msg_iov[0].iov_base);
            *byte = static_cast<std::byte>(index & 0xffu);
            messages[index].msg_len = 1;
        }
    }
    return static_cast<int>(message_count);
}

int errqueue_then_timeout_poll_for_tests(pollfd *descriptors, nfds_t descriptor_count, int) {
    g_poll_engine_coverage_trace.ignored_errqueue_poll_calls += 1;
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        descriptors[index].revents =
            g_poll_engine_coverage_trace.ignored_errqueue_poll_calls == 1 ? POLLERR : 0;
    }
    if (descriptor_count == 0 || g_poll_engine_coverage_trace.ignored_errqueue_poll_calls > 1) {
        return 0;
    }
    return 1;
}

ssize_t would_block_then_record_recvmsg_for_wait_retry_tests(int, msghdr *message, int) {
    g_retry_readable_poll_for_tests.recvmsg_calls += 1;
    if (g_retry_readable_poll_for_tests.recvmsg_calls == 1) {
        errno = EAGAIN;
        return -1;
    }

    return record_recvmsg_for_tests(/*socket_fd=*/0, message, /*flags=*/0);
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
                                                       QuicEcnCodepoint ecn, bool is_pmtu_probe) {
    return internal::send_datagram(fd, datagram, peer, peer_len, role_name, ecn, is_pmtu_probe);
}

SocketIoBackendReceiveDatagramResultForTests
socket_io_backend_receive_datagram_for_runtime_tests(int socket_fd, std::string_view role_name,
                                                     int flags) {
    const auto received = internal::receive_datagram(socket_fd, role_name, flags);
    if (received.status == internal::ReceiveDatagramStatus::ok) {
        return SocketIoBackendReceiveDatagramResultForTests{
            .status = SocketIoBackendReceiveDatagramStatusForTests::ok,
            .bytes = received.bytes,
            .address_validation_identity = internal::address_validation_identity_from_peer(
                received.source, received.source_len),
            .ecn = received.ecn,
            .source = received.source,
            .source_len = received.source_len,
        };
    }
    if (received.status == internal::ReceiveDatagramStatus::would_block) {
        return SocketIoBackendReceiveDatagramResultForTests{
            .status = SocketIoBackendReceiveDatagramStatusForTests::would_block,
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
    return all_true({
        sent,
        g_recorded_sendmsg_for_tests.calls == 1,
        g_recorded_sendmsg_for_tests.socket_fd == 17,
        g_recorded_sendmsg_for_tests.level == IPPROTO_IP,
        g_recorded_sendmsg_for_tests.type == IP_TOS,
        g_recorded_sendmsg_for_tests.traffic_class == 0x01,
    });
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
    return all_true({
        sent,
        g_recorded_sendmsg_for_tests.calls == 1,
        g_recorded_sendmsg_for_tests.socket_fd == 23,
        g_recorded_sendmsg_for_tests.level == IPPROTO_IP,
        g_recorded_sendmsg_for_tests.type == IP_TOS,
        g_recorded_sendmsg_for_tests.traffic_class == 0x01,
    });
}

bool socket_io_backend_sendmsg_sets_ipv6_flow_label_for_tests() {
    g_recorded_sendmsg_for_tests = {};
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .sendmsg_fn = &record_sendmsg_for_tests,
        },
    };
    const std::array<std::byte, 4> datagram = {
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
        std::byte{0x04},
    };

    sockaddr_storage peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(4433);
    ipv6.sin6_addr = in6addr_loopback;

    sockaddr_storage ipv4_peer{};
    ipv4_peer.ss_family = AF_INET;
    const bool skipped_non_ipv6 = !internal::should_apply_ipv6_flow_label(
        ipv4_peer, static_cast<socklen_t>(sizeof(sockaddr_in)));
    const bool skipped_short_ipv6 = !internal::should_apply_ipv6_flow_label(peer, 1);
    const bool normalized_zero_hash = internal::normalize_ipv6_flow_label_hash(0x12300000u) == 1u;

    const bool sent =
        internal::send_datagram(29, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in6)),
                                "server", QuicEcnCodepoint::not_ect);
    const bool single_send_applied_flow_label = all_true({
        sent,
        g_recorded_sendmsg_for_tests.calls == 1,
        g_recorded_sendmsg_for_tests.socket_fd == 29,
        g_recorded_sendmsg_for_tests.family == AF_INET6,
        g_recorded_sendmsg_for_tests.level == 0,
        g_recorded_sendmsg_for_tests.type == 0,
        g_recorded_sendmsg_for_tests.ipv6_flowinfo != 0,
        (g_recorded_sendmsg_for_tests.ipv6_flowinfo & ~0x000fffffu) == 0,
    });

    g_send_many_batch_coverage_trace = {};
    const ScopedSocketIoBackendOpsOverride batch_ops{
        SocketIoBackendOpsOverride{
            .sendmsg_fn = &batch_sendmsg_for_tests,
            .sendmmsg_fn = &batch_sendmmsg_for_tests,
        },
    };
    const std::array<std::byte, 2> first_payload = {
        std::byte{0xaa},
        std::byte{0xbb},
    };
    const std::array<std::byte, 2> second_payload = {
        std::byte{0xcc},
        std::byte{0xdd},
    };
    const auto first = QuicIoEngineTxDatagram{
        .socket_fd = 31,
        .peer = peer,
        .peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6)),
        .bytes = first_payload,
        .ecn = QuicEcnCodepoint::not_ect,
    };
    const auto second = QuicIoEngineTxDatagram{
        .socket_fd = 31,
        .peer = peer,
        .peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6)),
        .bytes = second_payload,
        .ecn = QuicEcnCodepoint::not_ect,
    };
    std::array<QuicIoEngineTxDatagram, 2> datagrams = {first, second};

    const bool batched = internal::sendmmsg_batch(datagrams, "server");
    const bool batch_applied_flow_label = all_true({
        batched,
        g_send_many_batch_coverage_trace.sendmsg_calls +
                g_send_many_batch_coverage_trace.sendmmsg_calls >
            0,
        g_send_many_batch_coverage_trace.peer_family == AF_INET6,
        g_send_many_batch_coverage_trace.ipv6_flowinfo != 0,
        (g_send_many_batch_coverage_trace.ipv6_flowinfo & ~0x000fffffu) == 0,
    });

    return skipped_non_ipv6 && skipped_short_ipv6 && normalized_zero_hash &&
           single_send_applied_flow_label && batch_applied_flow_label;
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
    return all_true({
        received.status == internal::ReceiveDatagramStatus::ok,
        received.bytes == g_recorded_recvmsg_for_tests.bytes,
        received.ecn == QuicEcnCodepoint::ce,
    });
}

bool socket_io_backend_wait_retries_after_spurious_readable_poll_for_tests() {
    g_recorded_recvmsg_for_tests = {};
    g_recorded_recvmsg_for_tests.ecn = QuicEcnCodepoint::ect0;
    g_recorded_recvmsg_for_tests.bytes = {std::byte{0xcc}, std::byte{0xdd}};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&g_recorded_recvmsg_for_tests.peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(7443);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);
    g_retry_readable_poll_for_tests = {};

    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .poll_fn = &readable_poll_then_retry_with_datagram_for_tests,
            .recvmsg_fn = &would_block_then_record_recvmsg_for_wait_retry_tests,
        },
    };

    PollIoEngine engine;
    constexpr std::array<int, 1> kSockets = {41};
    const auto event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    const auto observed = event.value_or(QuicIoEngineEvent{});
    const auto received = observed.rx.value_or(QuicIoEngineRxCompletion{});
    return all_true({
        event.has_value(),
        observed.kind == QuicIoEngineEvent::Kind::rx_datagram,
        observed.rx.has_value(),
        received.socket_fd == kSockets.front(),
        received.bytes == g_recorded_recvmsg_for_tests.bytes,
        received.ecn == QuicEcnCodepoint::ect0,
        g_retry_readable_poll_for_tests.poll_calls == 2,
        g_retry_readable_poll_for_tests.recvmsg_calls == 2,
    });
}

bool poll_io_engine_restamps_queued_receive_events_for_tests() {
    PollIoEngine engine;
    const auto first_time = QuicCoreTimePoint{} + std::chrono::microseconds{1};
    const auto queued_time = QuicCoreTimePoint{} + std::chrono::microseconds{2};
    auto shared = std::make_shared<std::vector<std::byte>>(
        std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}});

    engine.queued_events_.push_back(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::rx_datagram,
        .now = first_time,
        .rx =
            QuicIoEngineRxCompletion{
                .socket_fd = 77,
                .bytes = {std::byte{0x01}},
                .now = first_time,
            },
    });
    engine.queued_events_.push_back(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::rx_datagram,
        .now = queued_time,
        .rx =
            QuicIoEngineRxCompletion{
                .socket_fd = 78,
                .shared_bytes = shared,
                .begin = 0,
                .end = shared->size(),
                .now = queued_time,
            },
    });
    engine.queued_events_.push_back(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::timer_expired,
        .now = queued_time,
    });

    constexpr std::array<int, 1> kSockets = {79};
    const auto first = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    const auto second = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    const auto third = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    if (!first.has_value() || !second.has_value() || !third.has_value() || !first->rx.has_value() ||
        !second->rx.has_value()) {
        return false;
    }

    return all_true({
        first->kind == QuicIoEngineEvent::Kind::rx_datagram,
        second->kind == QuicIoEngineEvent::Kind::rx_datagram,
        third->kind == QuicIoEngineEvent::Kind::timer_expired,
        first->now != first_time,
        first->rx->now == first->now,
        second->now != queued_time,
        second->rx->now == second->now,
        third->now == queued_time,
        second->rx->shared_bytes == shared,
    });
}

bool poll_io_engine_internal_coverage_hook_exercises_remaining_branches_for_tests() {
    const auto saved_sendmsg = g_recorded_sendmsg_for_tests;
    const auto saved_recvmsg = g_recorded_recvmsg_for_tests;
    const auto saved_retry = g_retry_readable_poll_for_tests;
    const auto saved_poll_trace = g_poll_engine_coverage_trace;
    const auto saved_udp_gso_disabled = internal::udp_gso_disabled();
    const auto reset_for_case = [] {
        g_recorded_sendmsg_for_tests = {};
        g_recorded_recvmsg_for_tests = {};
        g_retry_readable_poll_for_tests = {};
        g_poll_engine_coverage_trace = {};
        internal::udp_gso_disabled() = false;
    };

    bool ok = true;
    const auto record = [&](bool condition, const char *label) {
        if (!condition) {
            std::cerr << "poll_io_engine_send_many_batching_coverage_for_tests failed: " << label
                      << '\n';
        }
        ok &= condition;
    };

    const auto invalid_ecn = [] {
        const auto raw = static_cast<std::underlying_type_t<QuicEcnCodepoint>>(0xff);
        QuicEcnCodepoint value{};
        std::memcpy(&value, &raw, sizeof(value));
        return value;
    }();
    record(all_true({
               internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::ect0) == 0x02,
               internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::ect1) == 0x01,
               internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::ce) == 0x03,
               internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::unavailable) == 0x00,
               internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::not_ect) == 0x00,
               internal::linux_traffic_class_for_ecn(invalid_ecn) == 0x00,
               internal::ecn_from_linux_traffic_class(0x00) == QuicEcnCodepoint::not_ect,
               internal::ecn_from_linux_traffic_class(0x01) == QuicEcnCodepoint::ect1,
               internal::ecn_from_linux_traffic_class(0x02) == QuicEcnCodepoint::ect0,
               internal::ecn_from_linux_traffic_class(0x03) == QuicEcnCodepoint::ce,
           }),
           "ecn helpers cover every linux traffic class mapping");

    reset_for_case();
    record(all_true({
               record_sendmsg_for_tests(9, nullptr, 0) == 0,
               g_recorded_sendmsg_for_tests.calls == 1,
               g_recorded_sendmsg_for_tests.socket_fd == 9,
           }),
           "record_sendmsg handles null message");

    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn =
                    [](int, const msghdr *, int) {
                        errno = ECONNREFUSED;
                        return static_cast<ssize_t>(-1);
                    },
            },
        };
        const auto peer = loopback_peer_for_batch_tests(7443);
        const std::array<std::byte, 1> bytes{std::byte{0x01}};
        record(socket_io_backend_send_datagram_for_runtime_tests(
                   /*fd=*/5, bytes, peer, static_cast<socklen_t>(sizeof(sockaddr_in)), "test",
                   QuicEcnCodepoint::ect0, /*is_pmtu_probe=*/false),
               "send_datagram ignores connection refused from sendmsg");
    }

    reset_for_case();
    msghdr send_message{};
    record(all_true({
               record_sendmsg_for_tests(9, &send_message, 0) == 0,
               g_recorded_sendmsg_for_tests.calls == 1,
               g_recorded_sendmsg_for_tests.socket_fd == 9,
               g_recorded_sendmsg_for_tests.level == 0,
               g_recorded_sendmsg_for_tests.type == 0,
               g_recorded_sendmsg_for_tests.traffic_class == 0,
           }),
           "record_sendmsg handles missing control and iov");

    std::array<std::byte, 2> send_payload{
        std::byte{0x41},
        std::byte{0x42},
    };
    iovec send_iov{
        .iov_base = send_payload.data(),
        .iov_len = send_payload.size(),
    };
    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(int))> send_control{};
    send_message = {};
    send_message.msg_iov = &send_iov;
    send_message.msg_iovlen = 1;
    send_message.msg_control = send_control.data();
    send_message.msg_controllen = send_control.size();
    auto *send_header = reinterpret_cast<cmsghdr *>(send_control.data());
    send_header->cmsg_level = IPPROTO_IP;
    send_header->cmsg_type = IP_TOS;
    send_header->cmsg_len = CMSG_LEN(sizeof(int));
    const int send_traffic_class = internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::ce);
    std::memcpy(CMSG_DATA(send_header), &send_traffic_class, sizeof(send_traffic_class));
    reset_for_case();
    record(all_true({
               record_sendmsg_for_tests(9, &send_message, 0) == 2,
               g_recorded_sendmsg_for_tests.calls == 1,
               g_recorded_sendmsg_for_tests.socket_fd == 9,
               g_recorded_sendmsg_for_tests.level == IPPROTO_IP,
               g_recorded_sendmsg_for_tests.type == IP_TOS,
               g_recorded_sendmsg_for_tests.traffic_class == send_traffic_class,
           }),
           "record_sendmsg copies ancillary traffic class control data");

    {
        sockaddr_storage ipv6_peer{};
        auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&ipv6_peer);
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(9443);
        ipv6.sin6_addr = in6addr_loopback;

        msghdr ipv6_send_message{};
        internal::UdpGsoControlStorage gso_control{};
        ipv6_send_message.msg_control = gso_control.bytes.data();
        auto *control_cursor = gso_control.bytes.data();
        internal::append_sendmsg_ecn_control(
            ipv6_send_message, gso_control, QuicEcnCodepoint::ect1, ipv6_peer,
            static_cast<socklen_t>(sizeof(sockaddr_in6)), control_cursor);
        auto *header = CMSG_FIRSTHDR(&ipv6_send_message);
        int ancillary_traffic_class = 0;
        if (header != nullptr) {
            std::memcpy(&ancillary_traffic_class, CMSG_DATA(header),
                        sizeof(ancillary_traffic_class));
        }
        record(all_true({
                   header != nullptr,
                   header->cmsg_level == IPPROTO_IPV6,
                   header->cmsg_type == IPV6_TCLASS,
                   ancillary_traffic_class ==
                       internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::ect1),
               }),
               "append_sendmsg_ecn_control emits IPv6 ancillary data");
    }

    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn =
                    [](int, const msghdr *, int) {
                        errno = EACCES;
                        return static_cast<ssize_t>(-1);
                    },
            },
        };
        const auto peer = loopback_peer_for_batch_tests(7444);
        const std::array<std::byte, 1> bytes{std::byte{0x02}};
        record(!socket_io_backend_send_datagram_for_runtime_tests(
                   /*fd=*/6, bytes, peer, static_cast<socklen_t>(sizeof(sockaddr_in)), "test",
                   QuicEcnCodepoint::ect0, /*is_pmtu_probe=*/false),
               "send_datagram reports hard sendmsg errors");
    }

    reset_for_case();
    record(record_recvmsg_for_tests(0, nullptr, 0) == -1, "record_recvmsg rejects null message");

    msghdr invalid_recv_message{};
    reset_for_case();
    record(record_recvmsg_for_tests(0, &invalid_recv_message, 0) == -1,
           "record_recvmsg rejects missing iov");

    std::array<std::byte, 4> payload = {};
    iovec iov{
        .iov_base = payload.data(),
        .iov_len = payload.size(),
    };
    invalid_recv_message.msg_iov = &iov;
    invalid_recv_message.msg_iovlen = 0;
    reset_for_case();
    record(record_recvmsg_for_tests(0, &invalid_recv_message, 0) == -1,
           "record_recvmsg rejects zero iov length");

    g_recorded_recvmsg_for_tests.bytes = {std::byte{0x10}, std::byte{0x20}};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&g_recorded_recvmsg_for_tests.peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(9443);
    ipv6.sin6_addr = in6addr_loopback;
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in6);

    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};

    reset_for_case();
    g_recorded_recvmsg_for_tests.bytes = {std::byte{0x10}, std::byte{0x20}};
    ipv6 = {};
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(9443);
    ipv6.sin6_addr = in6addr_loopback;
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in6);
    msghdr recv_message{};
    recv_message.msg_iov = &iov;
    recv_message.msg_iovlen = 1;
    recv_message.msg_control = control.data();
    recv_message.msg_controllen = control.size();
    record(all_true({
               record_recvmsg_for_tests(0, &recv_message, 0) == 2,
               payload[0] == std::byte{0x10},
               payload[1] == std::byte{0x20},
               recv_message.msg_name == nullptr,
               recv_message.msg_namelen == 0,
               recv_message.msg_controllen == CMSG_LEN(sizeof(int)),
           }),
           "record_recvmsg covers ipv6 ancillary path without name storage");

    reset_for_case();
    g_recorded_recvmsg_for_tests.bytes = {std::byte{0x30}};
    sockaddr_storage name_storage{};
    recv_message = {};
    recv_message.msg_iov = &iov;
    recv_message.msg_iovlen = 1;
    recv_message.msg_name = &name_storage;
    recv_message.msg_namelen = sizeof(sockaddr_storage) - 1;
    record(all_true({
               record_recvmsg_for_tests(0, &recv_message, 0) == 1,
               recv_message.msg_namelen == sizeof(sockaddr_storage) - 1,
           }),
           "record_recvmsg leaves truncated name storage untouched");

    reset_for_case();
    g_recorded_recvmsg_for_tests.bytes = {std::byte{0x40}};
    recv_message = {};
    recv_message.msg_iov = &iov;
    recv_message.msg_iovlen = 1;
    recv_message.msg_control = nullptr;
    recv_message.msg_controllen = 0;
    record(record_recvmsg_for_tests(0, &recv_message, 0) == 1,
           "record_recvmsg covers null ancillary header path");

    alignas(cmsghdr) std::array<std::byte, 2 * CMSG_SPACE(sizeof(int))> multi_control{};
    recv_message = {};
    recv_message.msg_control = multi_control.data();
    recv_message.msg_controllen = multi_control.size();
    auto *first_header = reinterpret_cast<cmsghdr *>(multi_control.data());
    first_header->cmsg_level = SOL_SOCKET;
    first_header->cmsg_type = SCM_RIGHTS;
    first_header->cmsg_len = CMSG_LEN(sizeof(int));
    int ignored_value = 0;
    std::memcpy(CMSG_DATA(first_header), &ignored_value, sizeof(ignored_value));

    auto *second_header =
        reinterpret_cast<cmsghdr *>(multi_control.data() + CMSG_SPACE(sizeof(int)));
    second_header->cmsg_level = IPPROTO_IPV6;
    second_header->cmsg_type = IPV6_TCLASS;
    second_header->cmsg_len = CMSG_LEN(sizeof(int));
    const int traffic_class = internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::ect1);
    std::memcpy(CMSG_DATA(second_header), &traffic_class, sizeof(traffic_class));
    record(internal::recvmsg_ecn_from_control(recv_message) == QuicEcnCodepoint::ect1,
           "recvmsg ecn walk advances past ignored ancillary headers");

    multi_control.fill(std::byte{0});
    recv_message = {};
    recv_message.msg_control = multi_control.data();
    recv_message.msg_controllen = multi_control.size();
    first_header = reinterpret_cast<cmsghdr *>(multi_control.data());
    first_header->cmsg_level = SOL_SOCKET;
    first_header->cmsg_type = SCM_RIGHTS;
    first_header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(first_header), &ignored_value, sizeof(ignored_value));

    second_header = reinterpret_cast<cmsghdr *>(multi_control.data() + CMSG_SPACE(sizeof(int)));
    second_header->cmsg_level = SOL_SOCKET;
    second_header->cmsg_type = SCM_RIGHTS;
    second_header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(second_header), &ignored_value, sizeof(ignored_value));
    record(internal::recvmsg_ecn_from_control(recv_message) == QuicEcnCodepoint::unavailable,
           "recvmsg ecn walk exhausts ignored ancillary headers");

    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(int))> empty_payload_control{};
    recv_message = {};
    recv_message.msg_control = empty_payload_control.data();
    recv_message.msg_controllen = empty_payload_control.size();
    auto *empty_payload_header = reinterpret_cast<cmsghdr *>(empty_payload_control.data());
    empty_payload_header->cmsg_level = IPPROTO_IP;
    empty_payload_header->cmsg_type = IP_TOS;
    empty_payload_header->cmsg_len = CMSG_LEN(0);
    record(internal::recvmsg_ecn_from_control(recv_message) == QuicEcnCodepoint::not_ect,
           "recvmsg ecn handles traffic-class ancillary data with no payload");

#if defined(__linux__) && defined(UDP_GRO)
    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(std::uint16_t))> gro_control{};
    recv_message = {};
    recv_message.msg_control = gro_control.data();
    recv_message.msg_controllen = gro_control.size();
    auto *gro_header = reinterpret_cast<cmsghdr *>(gro_control.data());
    gro_header->cmsg_level = SOL_UDP;
    gro_header->cmsg_type = UDP_GRO;
    gro_header->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
    const std::uint16_t gro_segment_size = 2;
    std::memcpy(CMSG_DATA(gro_header), &gro_segment_size, sizeof(gro_segment_size));
    record(internal::recvmsg_udp_gro_segment_size_from_control(recv_message) == gro_segment_size,
           "recvmsg UDP GRO parser extracts segment size");

    auto gro_source = loopback_peer_for_batch_tests(9443);
    internal::ReceiveDatagramResult gro_received{
        .status = internal::ReceiveDatagramStatus::ok,
        .bytes = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                  std::byte{0x05}},
        .ecn = QuicEcnCodepoint::ect0,
        .source = gro_source,
        .source_len = static_cast<socklen_t>(sizeof(sockaddr_in)),
        .input_time = internal::now(),
        .udp_gro_segment_size = gro_segment_size,
    };
    std::vector<internal::ReceiveDatagramResult> gro_split;
    internal::append_received_datagram_segments(gro_split, std::move(gro_received));
    record(all_true({
               gro_split.size() == 3,
               gro_split[0].payload().size() == 2,
               gro_split[1].payload().size() == 2,
               gro_split[2].payload().size() == 1,
               gro_split[0].shared_bytes != nullptr,
               gro_split[0].shared_bytes == gro_split[1].shared_bytes,
               gro_split[0].ecn == QuicEcnCodepoint::ect0,
           }),
           "receive GRO split preserves datagram-sized shared slices");
#endif

    sock_extended_err pmtu_error{};
    pmtu_error.ee_info = 1280;
    record(internal::max_udp_payload_size_from_linux_pmtu(pmtu_error, true) == 1232,
           "PMTU helper subtracts IPv6 and UDP overhead");
    pmtu_error.ee_info = 20;
    record(internal::max_udp_payload_size_from_linux_pmtu(pmtu_error, false) == 0,
           "PMTU helper rejects values below transport overhead");

    reset_for_case();
    {
        const auto empty_batch = internal::receive_datagram_batch(57, "client", 0);
        record(all_true({
                   empty_batch.status == internal::ReceiveDatagramStatus::would_block,
                   empty_batch.datagrams.empty(),
                   !empty_batch.may_have_more_datagrams,
               }),
               "receive_datagram_batch handles zero max datagrams");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .recvmmsg_fn =
                    [](int, mmsghdr *, unsigned int, int, timespec *) {
                        errno = EIO;
                        return -1;
                    },
            },
        };
        const auto failed_batch = internal::receive_datagram_batch(58, "client", 1);
        record(failed_batch.status == internal::ReceiveDatagramStatus::error,
               "receive_datagram_batch reports hard recvmmsg errors");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .recvmmsg_fn =
                    [](int, mmsghdr *, unsigned int, int, timespec *) {
                        errno = ECONNREFUSED;
                        return -1;
                    },
            },
        };
        const auto ignored_batch = internal::receive_datagram_batch(59, "client", 1);
        record(ignored_batch.status == internal::ReceiveDatagramStatus::would_block,
               "receive_datagram_batch ignores transient connection-refused errors");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .recvmsg_fn = [](int, msghdr *, int) -> ssize_t {
                    errno = EAGAIN;
                    return -1;
                },
            },
        };
        const auto blocked = internal::receive_datagram(60, "client", 0);
        record(blocked.status == internal::ReceiveDatagramStatus::would_block,
               "receive_datagram treats EAGAIN as would-block");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = [](int, const msghdr *, int) -> ssize_t {
                    g_poll_engine_coverage_trace.extra_batch_recvmmsg_calls += 1;
                    if (g_poll_engine_coverage_trace.extra_batch_recvmmsg_calls == 1) {
                        errno = EINTR;
                        return -1;
                    }
                    return 1;
                },
            },
        };
        const auto peer = loopback_peer_for_batch_tests(9444);
        const std::array<std::byte, 1> payload_a{std::byte{0x01}};
        const std::array<std::byte, 1> payload_b{std::byte{0x02}};
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(64, peer, payload_a, QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(64, peer, payload_b, QuicEcnCodepoint::not_ect),
        };
        record(internal::send_udp_gso_batch(datagrams, "client"),
               "UDP GSO send retries after EINTR");
    }

    reset_for_case();
    {
        const auto defaults = internal::make_default_socket_io_backend_ops();
        auto peer = loopback_peer_for_batch_tests(9555);
        const std::array<std::byte, 1> payload_a{std::byte{0x01}};
        const std::array<std::byte, 1> payload_b{std::byte{0x02}};
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(65, peer, payload_a, QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(65, peer, payload_b, QuicEcnCodepoint::not_ect),
        };
        auto too_long_destination = datagrams.front();
        too_long_destination.peer_len = static_cast<socklen_t>(sizeof(sockaddr_storage) + 1u);
        const std::array<std::byte, 2> larger_payload{std::byte{0x03}, std::byte{0x04}};
        auto different_size = datagrams;
        different_size[1].bytes = larger_payload;
        internal::udp_gso_disabled() = true;
        record(
            all_true({
                internal::sendmmsg_supports_datagram(datagrams.front()),
                !internal::sendmmsg_supports_datagram(too_long_destination),
                !internal::tx_datagram_matches_sendmmsg_batch(too_long_destination,
                                                              datagrams.front()),
                !internal::tx_datagram_matches_udp_gso_batch(different_size[0], different_size[1]),
                !internal::udp_gso_supports_batch(datagrams),
                defaults.recvmsg_fn == internal::make_default_socket_io_backend_ops().recvmsg_fn,
            }),
            "batch helper guards reject oversized destinations, mismatched GSO sizes, and disabled "
            "GSO");
    }

    reset_for_case();
    record(readable_poll_then_retry_with_datagram_for_tests(nullptr, 0, 0) == 0,
           "readable poll helper handles empty descriptor list");

    reset_for_case();
    record(positive_poll_without_revents_for_tests(nullptr, 0, 0) == 0,
           "positive poll helper handles empty descriptor list");

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .poll_fn = &eintr_then_timeout_poll_for_tests,
            },
        };
        PollIoEngine engine;
        constexpr std::array<int, 1> kSockets = {51};
        const auto event = engine.wait(kSockets, /*idle_timeout_ms=*/5,
                                       internal::now() + std::chrono::milliseconds(5), "client");
        const auto observed = event.value_or(QuicIoEngineEvent{});
        record(all_true({
                   event.has_value(),
                   observed.kind == QuicIoEngineEvent::Kind::timer_expired,
                   g_poll_engine_coverage_trace.eintr_then_timeout_calls == 2,
               }),
               "poll wait retries after EINTR before future timer expiry");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .poll_fn =
                    [](pollfd *descriptors, nfds_t descriptor_count, int) {
                        for (nfds_t index = 0; index < descriptor_count; ++index) {
                            descriptors[index].revents = 0;
                        }
                        return 0;
                    },
            },
        };
        PollIoEngine engine;
        constexpr std::array<int, 1> kSockets = {52};
        const auto event = engine.wait(kSockets, /*idle_timeout_ms=*/5,
                                       internal::now() - std::chrono::milliseconds(1), "client");
        const auto observed = event.value_or(QuicIoEngineEvent{});
        record(all_true({
                   event.has_value(),
                   observed.kind == QuicIoEngineEvent::Kind::timer_expired,
               }),
               "poll wait returns immediate timer expiry when deadline already passed");
    }

    reset_for_case();
    {
        PollIoEngine engine;
        const std::array<int, 0> kNoSockets = {};
        record(!engine.wait(kNoSockets, /*idle_timeout_ms=*/5, std::nullopt, "client").has_value(),
               "poll wait returns nullopt for empty socket list");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .poll_fn = &positive_poll_without_revents_for_tests,
            },
        };
        PollIoEngine engine;
        constexpr std::array<int, 1> kSockets = {53};
        record(!engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server").has_value(),
               "poll wait returns nullopt when poll reports readiness without revents");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .poll_fn = &hard_errqueue_poll_for_tests,
                .recvmsg_fn = &hard_errqueue_recvmsg_for_tests,
            },
        };
        PollIoEngine engine;
        constexpr std::array<int, 1> kSockets = {54};
        record(!engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server").has_value(),
               "poll wait returns nullopt for hard errqueue receive errors");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .poll_fn = &readable_poll_for_tests,
                .recvmmsg_fn = &first_recvmmsg_batch_then_hard_error_for_tests,
            },
        };
        PollIoEngine engine;
        constexpr std::array<int, 1> kSockets = {55};
        record(!engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server").has_value(),
               "poll wait returns nullopt when queued receive draining reports a hard error");
    }

    reset_for_case();
    {
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .poll_fn = &readable_poll_for_tests,
                .recvmmsg_fn = [](int, mmsghdr *, unsigned int, int, timespec *) { return 0; },
            },
        };
        PollIoEngine engine;
        constexpr std::array<int, 1> kSockets = {56};
        record(!engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server").has_value(),
               "poll wait returns nullopt when recvmmsg reports no datagrams");
    }

    g_recorded_sendmsg_for_tests = saved_sendmsg;
    g_recorded_recvmsg_for_tests = saved_recvmsg;
    g_retry_readable_poll_for_tests = saved_retry;
    g_poll_engine_coverage_trace = saved_poll_trace;
    internal::udp_gso_disabled() = saved_udp_gso_disabled;
    return ok;
}

bool poll_io_engine_send_many_batching_coverage_for_tests() {
    const auto saved_trace = g_send_many_batch_coverage_trace;
    const auto saved_sendmsg = g_recorded_sendmsg_for_tests;
    const auto saved_udp_gso_disabled = internal::udp_gso_disabled();
    const auto reset_trace = [](SendManyBatchCoverageTrace::Mode mode) {
        g_send_many_batch_coverage_trace = {};
        g_send_many_batch_coverage_trace.mode = mode;
        internal::udp_gso_disabled() = false;
    };

    bool ok = true;
    const auto record = [&](bool condition, const char *label) {
        if (!condition) {
            std::cerr << "poll_io_engine_send_many_batching_coverage_for_tests failed: " << label
                      << '\n';
        }
        ok &= condition;
    };

    constexpr int kSocketFd = 77;
    const auto peer = loopback_peer_for_batch_tests(8443);
    sockaddr_storage ipv6_peer{};
    auto &ipv6_loopback = *reinterpret_cast<sockaddr_in6 *>(&ipv6_peer);
    ipv6_loopback.sin6_family = AF_INET6;
    ipv6_loopback.sin6_port = htons(8443);
    ipv6_loopback.sin6_addr = in6addr_loopback;
    sockaddr_storage v4_mapped_peer{};
    auto &v4_mapped_loopback = *reinterpret_cast<sockaddr_in6 *>(&v4_mapped_peer);
    v4_mapped_loopback.sin6_family = AF_INET6;
    v4_mapped_loopback.sin6_port = htons(8443);
    v4_mapped_loopback.sin6_addr.s6_addr[10] = 0xff;
    v4_mapped_loopback.sin6_addr.s6_addr[11] = 0xff;
    v4_mapped_loopback.sin6_addr.s6_addr[12] = 127;
    v4_mapped_loopback.sin6_addr.s6_addr[15] = 1;
    constexpr std::array<std::byte, 4> kSmallPayload{
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
        std::byte{0x04},
    };
    constexpr std::array<std::byte, 3> kOddPayload{
        std::byte{0x05},
        std::byte{0x06},
        std::byte{0x07},
    };
    const std::array<std::byte, 0> kEmptyPayload{};
    constexpr std::array<std::byte, 700> kLargePayload{};

    {
        const auto same_peer_a = make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload,
                                                               QuicEcnCodepoint::not_ect);
        const auto same_peer_b =
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect);
        auto different_socket = same_peer_b;
        different_socket.socket_fd = kSocketFd + 1;
        auto different_peer_len = same_peer_b;
        different_peer_len.peer_len = sizeof(sockaddr_in6);
        auto different_ecn = same_peer_b;
        different_ecn.ecn = QuicEcnCodepoint::ect0;
        auto pmtu_probe = same_peer_b;
        pmtu_probe.is_pmtu_probe = true;
        auto invalid_destination = same_peer_b;
        invalid_destination.peer_len = 0;
        record(all_true({
                   internal::tx_datagram_matches_sendmmsg_batch(same_peer_a, same_peer_b),
                   !internal::tx_datagram_matches_udp_gso_batch(same_peer_a, same_peer_b),
                   !internal::tx_datagram_matches_sendmmsg_batch(same_peer_a, different_socket),
                   !internal::tx_datagram_matches_sendmmsg_batch(same_peer_a, different_peer_len),
                   !internal::tx_datagram_matches_sendmmsg_batch(same_peer_a, different_ecn),
                   !internal::tx_datagram_matches_sendmmsg_batch(same_peer_a, pmtu_probe),
                   !internal::tx_datagram_matches_sendmmsg_batch(same_peer_a, invalid_destination),
                   !internal::sendmmsg_supports_datagram(pmtu_probe),
                   !internal::sendmmsg_supports_datagram(invalid_destination),
               }),
               "sendmmsg batch helpers reject incompatible datagrams");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendto_success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
            },
        };
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload,
                                          QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   internal::sendmmsg_batch(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 2,
               }),
               "sendmmsg_batch uses sendto fallback when the legacy sendto hook is active");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 0,
                   g_send_many_batch_coverage_trace.socket_fd == kSocketFd,
                   g_send_many_batch_coverage_trace.last_sendmsg_iov_count == datagrams.size(),
                   g_send_many_batch_coverage_trace.last_sendmsg_total_bytes ==
                       datagrams.size() * kSmallPayload.size(),
                   g_send_many_batch_coverage_trace.saw_ecn_control,
                   g_send_many_batch_coverage_trace.saw_udp_segment_control,
                   g_send_many_batch_coverage_trace.traffic_class ==
                       internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::ect0),
                   g_send_many_batch_coverage_trace.udp_segment_size == kSmallPayload.size(),
               }),
               "send_many uses UDP GSO for compatible equal-sized datagrams");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, ipv6_peer, kSmallPayload,
                                          QuicEcnCodepoint::ect0, false, sizeof(sockaddr_in6)),
            make_batch_datagram_for_tests(kSocketFd, ipv6_peer, kSmallPayload,
                                          QuicEcnCodepoint::ect0, false, sizeof(sockaddr_in6)),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.ecn_level == IPPROTO_IPV6,
                   g_send_many_batch_coverage_trace.ecn_type == IPV6_TCLASS,
               }),
               "send_many uses IPv6 ECN ancillary data for UDP GSO");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, v4_mapped_peer, kSmallPayload,
                                          QuicEcnCodepoint::ect1, false, sizeof(sockaddr_in6)),
            make_batch_datagram_for_tests(kSocketFd, v4_mapped_peer, kSmallPayload,
                                          QuicEcnCodepoint::ect1, false, sizeof(sockaddr_in6)),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.ecn_level == IPPROTO_IP,
                   g_send_many_batch_coverage_trace.ecn_type == IP_TOS,
               }),
               "send_many treats IPv4-mapped IPv6 peers as IPv4 for ECN ancillary data");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        auto unsupported_peer = peer;
        unsupported_peer.ss_family = AF_UNIX;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, unsupported_peer, kSmallPayload,
                                          QuicEcnCodepoint::ect0, false, sizeof(sockaddr_in)),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendto_calls == 1,
               }),
               "send_many falls back to sendto for ECN datagrams with unsupported peers");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::udp_gso_einval);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "send_many disables GSO on EINVAL before sendmmsg fallback");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::udp_gso_enoprotoopt);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "send_many disables GSO on ENOPROTOOPT before sendmmsg fallback");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::udp_gso_emsgsize);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "send_many keeps GSO enabled after EMSGSIZE fallback");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::udp_gso_ignorable_error);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 0,
               }),
               "send_many accepts ignorable GSO send errors");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::udp_gso_hard_error);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect0),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
                   !internal::udp_gso_disabled(),
               }),
               "send_many falls back to sendmmsg after hard GSO sendmsg errors");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kEmptyPayload,
                                          QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, kEmptyPayload,
                                          QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "send_many skips UDP GSO for empty datagram payloads");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 65> datagrams{};
        for (auto &datagram : datagrams) {
            datagram = make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload,
                                                     QuicEcnCodepoint::not_ect);
        }
        record(all_true({
                   internal::sendmmsg_batch(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "send_many skips UDP GSO when a batch exceeds the segment limit");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 100> datagrams{};
        for (auto &datagram : datagrams) {
            datagram = make_batch_datagram_for_tests(kSocketFd, peer, kLargePayload,
                                                     QuicEcnCodepoint::not_ect);
        }
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 2,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 0,
               }),
               "send_many chunks large equal-size runs for UDP GSO");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::second_udp_gso_chunk_hard_error);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 100> datagrams{};
        for (auto &datagram : datagrams) {
            datagram = make_batch_datagram_for_tests(kSocketFd, peer, kLargePayload,
                                                     QuicEcnCodepoint::not_ect);
        }
        record(all_true({
                   !engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 2,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "send_many reports errors from later UDP GSO chunks");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload,
                                          QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
                   g_send_many_batch_coverage_trace.last_sendmmsg_message_count == 2,
               }),
               "send_many batches mixed singletons until the next equal-size run");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 4> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload,
                                          QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload,
                                          QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 2,
               }),
               "send_many stops a mixed singleton batch before the next GSO run");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        record(internal::sendmmsg_batch(std::span<const QuicIoEngineTxDatagram>{}, "client"),
               "sendmmsg_batch accepts an empty batch directly");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
            },
        };
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload,
                                          QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   internal::sendmmsg_batch(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 2,
               }),
               "sendmmsg_batch falls back to sendto without sendmmsg support");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendto_hard_error);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
            },
        };
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload,
                                          QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   !internal::sendmmsg_batch(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 1,
               }),
               "sendmmsg_batch reports sendto fallback errors");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        std::array<std::byte, 40000> huge_payload{};
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, huge_payload, QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, huge_payload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   internal::sendmmsg_batch(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "sendmmsg_batch skips UDP GSO when the coalesced payload is too large");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        std::array<std::byte, 65536> oversized_payload{};
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, oversized_payload,
                                          QuicEcnCodepoint::not_ect),
            make_batch_datagram_for_tests(kSocketFd, peer, oversized_payload,
                                          QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   internal::sendmmsg_batch(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "sendmmsg_batch skips UDP GSO when a segment exceeds uint16");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::gso_not_supported_then_partial_sendmmsg);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 2> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect1),
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::ect1),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 1,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 3,
                   g_send_many_batch_coverage_trace.last_sendmmsg_message_count == 1,
                   g_send_many_batch_coverage_trace.saw_ecn_control,
                   g_send_many_batch_coverage_trace.saw_udp_segment_control,
                   g_send_many_batch_coverage_trace.traffic_class ==
                       internal::linux_traffic_class_for_ecn(QuicEcnCodepoint::ect1),
               }),
               "send_many falls back from unsupported GSO to partial sendmmsg completion");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendmmsg_zero);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
                   g_send_many_batch_coverage_trace.last_sendmmsg_message_count == 1,
               }),
               "send_many treats sendmmsg zero progress as a soft stop");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendmmsg_ignorable_error);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "send_many ignores connection-refused sendmmsg errors");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendmmsg_hard_error);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kOddPayload, QuicEcnCodepoint::not_ect),
        };
        record(all_true({
                   !engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 1,
               }),
               "send_many reports hard sendmmsg errors");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendto_success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::not_ect,
                                          false, 0),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 1,
               }),
               "send_many falls back to sendto for unsupported destinations");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendto_hard_error);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::not_ect,
                                          false, 0),
        };
        record(all_true({
                   !engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 1,
               }),
               "send_many reports hard sendto fallback errors");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendto_connrefused);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::not_ect,
                                          false, 0),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 1,
               }),
               "send_many ignores connection-refused sendto fallback errors");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::sendto_success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::not_ect,
                                          true),
        };
        record(all_true({
                   engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 1,
               }),
               "send_many sends PMTU probes through the single datagram path");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendmsg_fn = &batch_sendmsg_for_tests,
                .sendmmsg_fn = &batch_sendmmsg_for_tests,
            },
        };
        PollIoEngine engine;
        record(all_true({
                   engine.send_many(std::span<const QuicIoEngineTxDatagram>{}, "client"),
                   g_send_many_batch_coverage_trace.sendmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendmmsg_calls == 0,
                   g_send_many_batch_coverage_trace.sendto_calls == 0,
               }),
               "send_many accepts an empty datagram batch");
    }

    {
        reset_trace(SendManyBatchCoverageTrace::Mode::success);
        const ScopedSocketIoBackendOpsOverride runtime_ops{
            SocketIoBackendOpsOverride{
                .sendto_fn = &batch_sendto_for_tests,
            },
        };
        PollIoEngine engine;
        std::array<QuicIoEngineTxDatagram, 1> datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::not_ect,
                                          true, 0),
        };
        g_send_many_batch_coverage_trace.mode = SendManyBatchCoverageTrace::Mode::sendto_hard_error;
        record(all_true({
                   !engine.send_many(datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 1,
               }),
               "send_many reports hard PMTU probe sendto fallback errors");

        reset_trace(SendManyBatchCoverageTrace::Mode::sendto_pmtu_error);
        std::array<QuicIoEngineTxDatagram, 1> ignorable_datagrams{
            make_batch_datagram_for_tests(kSocketFd, peer, kSmallPayload, QuicEcnCodepoint::not_ect,
                                          true, 0),
        };
        record(all_true({
                   engine.send_many(ignorable_datagrams, "client"),
                   g_send_many_batch_coverage_trace.sendto_calls == 1,
               }),
               "send_many ignores PMTU probe EMSGSIZE fallback errors");
    }

    g_send_many_batch_coverage_trace = saved_trace;
    g_recorded_sendmsg_for_tests = saved_sendmsg;
    internal::udp_gso_disabled() = saved_udp_gso_disabled;
    return ok;
}

bool poll_io_engine_pmtud_coverage_for_tests() {
    g_recorded_recvmsg_for_tests = {};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&g_recorded_recvmsg_for_tests.peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(7443);
    ipv6.sin6_addr = in6addr_loopback;
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in6);
    g_recorded_recvmsg_for_tests.pmtu = 1500;

    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .poll_fn =
                [](pollfd *descriptors, nfds_t descriptor_count, int) {
                    for (nfds_t index = 0; index < descriptor_count; ++index) {
                        descriptors[index].revents = POLLERR;
                    }
                    return descriptor_count == 0 ? 0 : 1;
                },
            .recvmsg_fn = &record_recvmsg_for_tests,
        },
    };

    PollIoEngine engine;
    constexpr std::array<int, 1> kSockets = {61};
    const auto event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    const auto observed = event.value_or(QuicIoEngineEvent{});
    const auto update = observed.path_mtu.value_or(QuicIoEnginePathMtuUpdate{});
    return all_true({
        event.has_value(),
        observed.kind == QuicIoEngineEvent::Kind::path_mtu_update,
        observed.path_mtu.has_value(),
        update.socket_fd == kSockets.front(),
        update.max_udp_payload_size == 1452,
        update.peer.ss_family == AF_INET6,
        update.peer_len == sizeof(sockaddr_in6),
    });
}

bool poll_io_engine_ignores_non_pmtu_errqueue_for_tests() {
    g_recorded_recvmsg_for_tests = {};
    g_poll_engine_coverage_trace = {};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&g_recorded_recvmsg_for_tests.peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(7443);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);
    g_recorded_recvmsg_for_tests.errqueue_errno = ECONNREFUSED;

    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .poll_fn = &errqueue_then_timeout_poll_for_tests,
            .recvmsg_fn = &record_recvmsg_for_tests,
        },
    };

    PollIoEngine engine;
    constexpr std::array<int, 1> kSockets = {62};
    const auto event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    const auto observed = event.value_or(QuicIoEngineEvent{});
    return all_true({
        event.has_value(),
        observed.kind == QuicIoEngineEvent::Kind::idle_timeout,
        g_poll_engine_coverage_trace.ignored_errqueue_poll_calls == 2,
    });
}

bool socket_io_backend_poll_engine_primes_descriptor_cache_for_tests() {
    PollIoEngine engine;
    const auto descriptor_cache_matches = [&](std::size_t expected_count,
                                              std::size_t minimum_capacity, bool expect_empty) {
        return (engine.registered_socket_count_ == expected_count) &
               (engine.descriptor_scratch_.empty() == expect_empty) &
               (engine.descriptor_scratch_.capacity() >= minimum_capacity);
    };

    bool initial_state_ok = engine.descriptor_scratch_.capacity() == 0;
    initial_state_ok &= descriptor_cache_matches(0, 0, true);

    bool first_registration_ok = engine.register_socket(41);
    first_registration_ok &= descriptor_cache_matches(1, 1, true);
    const auto first_capacity = engine.descriptor_scratch_.capacity();

    bool second_registration_ok = engine.register_socket(42);
    second_registration_ok &= descriptor_cache_matches(2, 2, true);
    second_registration_ok &= engine.descriptor_scratch_.capacity() >= first_capacity;

    bool ok = initial_state_ok;
    ok &= first_registration_ok;
    ok &= second_registration_ok;
    return ok;
}

bool poll_io_engine_descriptor_cache_guard_branches_for_tests() {
    PollIoEngine engine;
    bool ok = true;
    struct DescriptorCacheExpectation {
        std::size_t expected_count;
        std::size_t minimum_capacity;
        bool expect_empty;
    };
    const auto descriptor_cache_matches = [&](DescriptorCacheExpectation expected) {
        if (engine.registered_socket_count_ != expected.expected_count) {
            return false;
        }
        if (engine.descriptor_scratch_.empty() != expected.expect_empty) {
            return false;
        }
        return engine.descriptor_scratch_.capacity() >= expected.minimum_capacity;
    };

    ok &= !descriptor_cache_matches(DescriptorCacheExpectation{
        .expected_count = 1,
        .minimum_capacity = 0,
        .expect_empty = true,
    });

    engine.descriptor_scratch_.push_back(pollfd{});
    ok &= !descriptor_cache_matches(DescriptorCacheExpectation{
        .expected_count = 0,
        .minimum_capacity = 0,
        .expect_empty = true,
    });

    engine.descriptor_scratch_.clear();
    engine.descriptor_scratch_.shrink_to_fit();
    ok &= engine.register_socket(41);

    engine.registered_socket_count_ = 0;
    ok &= !descriptor_cache_matches(DescriptorCacheExpectation{
        .expected_count = 1,
        .minimum_capacity = 1,
        .expect_empty = true,
    });

    engine.registered_socket_count_ = 1;
    engine.descriptor_scratch_.push_back(pollfd{});
    ok &= !descriptor_cache_matches(DescriptorCacheExpectation{
        .expected_count = 1,
        .minimum_capacity = 1,
        .expect_empty = true,
    });

    engine.descriptor_scratch_.clear();
    ok &= !descriptor_cache_matches(DescriptorCacheExpectation{
        .expected_count = 1,
        .minimum_capacity = engine.descriptor_scratch_.capacity() + 1,
        .expect_empty = true,
    });
    return ok;
}

} // namespace test

#if defined(__clang__)
#pragma clang attribute pop
#endif

} // namespace coquic::io
