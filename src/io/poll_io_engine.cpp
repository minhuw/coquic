#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "src/io/poll_io_engine.h"

#include "src/io/socket_io_backend_internal.h"
#include "src/quic/object_cache.h"

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
#include <new>
#include <random>
#include <string_view>
#include <vector>

#if defined(__clang__)
#define COQUIC_NO_PROFILE __attribute__((no_profile_instrument_function))
#else
#define COQUIC_NO_PROFILE
#endif

#ifndef COQUIC_PROFILE_HOOKS
#define COQUIC_PROFILE_HOOKS 1
#endif

namespace coquic::io {

using quic::QuicCoreClock;
using quic::QuicEcnCodepoint;

namespace {

constexpr std::size_t kMaxDatagramBytes = 65535;
constexpr std::size_t kMaxReceiveDrainBatch = 64;
constexpr std::size_t kRecvmmsgDrainBatch = 8;
constexpr std::size_t kReceiveByteStoragePoolSlots = kRecvmmsgDrainBatch * 2;
constexpr std::size_t kReceiveScratchCopyMaxBytes = std::size_t{4} * 1024;
constexpr std::size_t kReceiveResultStorageCacheMaxBytes = std::size_t{256} * 1024;
constexpr std::size_t kReceiveResultStorageCacheBucketBytes = std::size_t{4} * 1024;
constexpr std::size_t kReceiveResultStorageCacheSlots = 128;
constexpr std::array<int, 5> kEcnToTrafficClass{
    0x00, 0x00, 0x02, 0x01, 0x03,
};
constexpr std::array<QuicEcnCodepoint, 4> kTrafficClassToEcn{
    QuicEcnCodepoint::not_ect,
    QuicEcnCodepoint::ect1,
    QuicEcnCodepoint::ect0,
    QuicEcnCodepoint::ce,
};
constexpr bool kCoquicProfileHooksEnabled = COQUIC_PROFILE_HOOKS != 0;

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
    std::uint64_t rx_storage_allocations = 0;
    std::uint64_t rx_storage_pool_reuses = 0;
    std::uint64_t rx_storage_scratch_reuses = 0;
    std::uint64_t rx_storage_recycles = 0;
    std::uint64_t rx_storage_drops = 0;
    std::uint64_t rx_storage_pool_high_water = 0;
    std::uint64_t rx_storage_compact_copies = 0;
    std::uint64_t rx_storage_compact_copy_bytes = 0;
};

struct RecvmmsgScratch {
    std::array<std::shared_ptr<std::vector<std::byte>>, kRecvmmsgDrainBatch> inbound{};
    std::array<std::array<std::byte, 256>, kRecvmmsgDrainBatch> controls{};
    std::array<sockaddr_storage, kRecvmmsgDrainBatch> sources{};
    std::array<iovec, kRecvmmsgDrainBatch> iovecs{};
    std::array<mmsghdr, kRecvmmsgDrainBatch> messages{};
    std::vector<std::size_t> begins;
    std::vector<std::size_t> sizes;
};

COQUIC_NO_PROFILE std::size_t receive_result_storage_allocation_bytes(std::size_t bytes) {
    if (bytes == 0 || bytes > kReceiveResultStorageCacheMaxBytes) {
        return bytes;
    }

    return quic::detail::round_up_to_cache_bucket(bytes, kReceiveResultStorageCacheBucketBytes);
}

using ReceiveResultStorageCache =
    quic::detail::FixedAlignedBlockCache<kReceiveResultStorageCacheSlots>;

COQUIC_NO_PROFILE ReceiveResultStorageCache &receive_result_storage_cache() {
    thread_local auto *cache = new ReceiveResultStorageCache;
    return *cache;
}

template <typename T> class ReceiveResultAllocator {
  public:
    using value_type = T;

    ReceiveResultAllocator() = default;

    template <typename U>
    explicit constexpr ReceiveResultAllocator(const ReceiveResultAllocator<U> &) noexcept {
    }

    [[nodiscard]] T *allocate(std::size_t count) {
        if (count > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            throw std::bad_array_new_length();
        }

        const auto bytes = receive_result_storage_allocation_bytes(count * sizeof(T));
        if (auto *cached = receive_result_storage_cache().take(bytes, alignof(T));
            cached != nullptr) {
            return static_cast<T *>(cached);
        }
        return static_cast<T *>(quic::detail::allocate_aligned_cache_storage(bytes, alignof(T)));
    }

    void deallocate(T *pointer, std::size_t count) noexcept {
        if (pointer == nullptr || count == 0) {
            return;
        }

        const auto bytes = receive_result_storage_allocation_bytes(count * sizeof(T));
        if (bytes <= kReceiveResultStorageCacheMaxBytes &&
            receive_result_storage_cache().put(pointer, bytes, alignof(T))) {
            return;
        }
        quic::detail::deallocate_aligned_cache_storage(pointer, alignof(T));
    }

    template <typename U> struct rebind {
        using other = ReceiveResultAllocator<U>;
    };
};

template <typename T, typename U>
constexpr bool operator==(const ReceiveResultAllocator<T> &,
                          const ReceiveResultAllocator<U> &) noexcept {
    return true;
}

using ReceiveDatagramResultVector =
    std::vector<internal::ReceiveDatagramResult,
                ReceiveResultAllocator<internal::ReceiveDatagramResult>>;

struct ReceiveDatagramBatchResult {
    internal::ReceiveDatagramStatus status = internal::ReceiveDatagramStatus::would_block;
    ReceiveDatagramResultVector datagrams;
    bool may_have_more_datagrams = false;
};

using ReceiveByteStoragePool =
    quic::detail::FixedObjectCache<std::vector<std::byte>, kReceiveByteStoragePoolSlots>;

COQUIC_NO_PROFILE bool io_profile_enabled();
COQUIC_NO_PROFILE IoProfileCounters &io_profile_counters();

COQUIC_NO_PROFILE ReceiveByteStoragePool &receive_byte_storage_pool() {
    thread_local auto *pool = new ReceiveByteStoragePool;
    return *pool;
}

COQUIC_NO_PROFILE void recycle_receive_byte_storage(std::vector<std::byte> *storage) noexcept {
    if (storage == nullptr) {
        return;
    }

    auto &pool = receive_byte_storage_pool();
    if (storage->size() != kMaxDatagramBytes) {
        if (io_profile_enabled()) {
            ++io_profile_counters().rx_storage_drops;
        }
        if (pool.owns(storage)) {
            storage->clear();
            static_cast<void>(pool.put(storage));
            return;
        }
        delete storage;
        return;
    }

    if (!pool.owns(storage)) {
        if (io_profile_enabled()) {
            ++io_profile_counters().rx_storage_drops;
        }
        delete storage;
        return;
    }
    if (!pool.put(storage)) {
        if (io_profile_enabled()) {
            ++io_profile_counters().rx_storage_drops;
        }
        return;
    }
    if (io_profile_enabled()) {
        auto &counters = io_profile_counters();
        ++counters.rx_storage_recycles;
        counters.rx_storage_pool_high_water = std::max<std::uint64_t>(
            counters.rx_storage_pool_high_water, static_cast<std::uint64_t>(pool.size()));
    }
}

COQUIC_NO_PROFILE std::shared_ptr<std::vector<std::byte>> acquire_receive_byte_storage() {
    auto &pool = receive_byte_storage_pool();
    std::vector<std::byte> *storage = nullptr;
    if (auto *cached = pool.take(); cached != nullptr) {
        storage = cached;
        if (io_profile_enabled()) {
            ++io_profile_counters().rx_storage_pool_reuses;
        }
    } else {
        storage = new std::vector<std::byte>(kMaxDatagramBytes);
        if (io_profile_enabled()) {
            ++io_profile_counters().rx_storage_allocations;
        }
    }
    if (storage->size() != kMaxDatagramBytes) {
        storage->resize(kMaxDatagramBytes);
    }

    return std::shared_ptr<std::vector<std::byte>>(storage, recycle_receive_byte_storage);
}

COQUIC_NO_PROFILE void
prepare_receive_byte_storage(std::shared_ptr<std::vector<std::byte>> &storage) {
    if (storage != nullptr && storage.use_count() == 1 && storage->size() == kMaxDatagramBytes) {
        if (io_profile_enabled()) {
            ++io_profile_counters().rx_storage_scratch_reuses;
        }
        return;
    }

    storage.reset();
    storage = acquire_receive_byte_storage();
}

COQUIC_NO_PROFILE bool io_profile_enabled() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return false;
    }

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
              << " udp_gro_segments=" << c.udp_gro_segments
              << " rx_storage_allocations=" << c.rx_storage_allocations
              << " rx_storage_pool_reuses=" << c.rx_storage_pool_reuses
              << " rx_storage_scratch_reuses=" << c.rx_storage_scratch_reuses
              << " rx_storage_recycles=" << c.rx_storage_recycles
              << " rx_storage_drops=" << c.rx_storage_drops
              << " rx_storage_pool_high_water=" << c.rx_storage_pool_high_water
              << " rx_storage_compact_copies=" << c.rx_storage_compact_copies
              << " rx_storage_compact_copy_bytes=" << c.rx_storage_compact_copy_bytes << '\n';
}

COQUIC_NO_PROFILE void register_io_profile_printer_once() {
    if constexpr (!kCoquicProfileHooksEnabled) {
        return;
    }

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

QuicEcnCodepoint ecn_from_linux_traffic_class(int linux_traffic_class) { return kTrafficClassToEcn[static_cast<unsigned>(linux_traffic_class) & 0x03u]; }
// clang-format on

bool is_ipv4_mapped_ipv6_address(const sockaddr_storage &peer, socklen_t peer_len) {
    if (peer.ss_family != AF_INET6 || peer_len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        return false;
    }

    const auto *ipv6_peer = reinterpret_cast<const sockaddr_in6 *>(&peer);
    return IN6_IS_ADDR_V4MAPPED(&ipv6_peer->sin6_addr);
}

bool should_apply_ipv6_flow_label(const sockaddr_storage &peer, socklen_t peer_len) {
    return peer.ss_family == AF_INET6 && peer_len >= static_cast<socklen_t>(sizeof(sockaddr_in6)) &&
           !is_ipv4_mapped_ipv6_address(peer, peer_len);
}

COQUIC_NO_PROFILE std::uint32_t normalize_ipv6_flow_label_hash(std::uint32_t hash) {
    return (hash & 0x000fffffu) == 0 ? 1u : (hash & 0x000fffffu);
}

std::uint64_t ipv6_flow_label_secret() {
    static const std::uint64_t secret = [] {
        std::random_device device;
        std::uint64_t value = 0;
        for (unsigned index = 0; index < sizeof(value); ++index) {
            value = (value << 8u) ^ static_cast<std::uint64_t>(device());
        }
        return value == 0 ? 0x9e3779b97f4a7c15ull : value;
    }();
    return secret;
}

std::uint32_t hash_ipv6_flow_label_input(const sockaddr_in6 &peer,
                                         std::span<const std::byte> datagram) {
    std::uint32_t hash = 2166136261u;
    const auto mix = [&](std::uint8_t value) {
        hash ^= value;
        hash *= 16777619u;
    };
    const auto secret = ipv6_flow_label_secret();
    for (unsigned shift = 0; shift < 64; shift += 8) {
        mix(static_cast<std::uint8_t>((secret >> shift) & 0xffu));
    }
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
    sockaddr_storage peer_with_flow_label = peer;
    if (!should_apply_ipv6_flow_label(peer, peer_len)) {
        return peer_with_flow_label;
    }

    auto *ipv6_peer = reinterpret_cast<sockaddr_in6 *>(&peer_with_flow_label);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.7
    // # Endpoints that send data using IPv6 SHOULD apply an IPv6 flow label in
    // # compliance with [RFC6437], unless the local API does not allow setting
    // # IPv6 flow labels.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.7
    // # The flow label generation MUST be designed to minimize the chances of
    // # linkability with a previously used flow label, as a stable flow label
    // # would enable correlating activity on multiple paths; see Section 9.5.
    ipv6_peer->sin6_flowinfo = htonl(hash_ipv6_flow_label_input(*ipv6_peer, datagram));
    return peer_with_flow_label;
}

QuicEcnCodepoint recvmsg_ecn_from_control(const msghdr &message) {
#if defined(__linux__)
    if ((message.msg_flags & MSG_CTRUNC) != 0) {
        return QuicEcnCodepoint::unavailable;
    }
    auto *control_header = CMSG_FIRSTHDR(&message);
    while (control_header != nullptr) {
        if ((control_header->cmsg_level == IPPROTO_IP && control_header->cmsg_type == IP_TOS) ||
            (control_header->cmsg_level == IPPROTO_IPV6 &&
             control_header->cmsg_type == IPV6_TCLASS)) {
            int received_traffic_class = 0;
            const auto payload_size =
                control_header->cmsg_len > CMSG_LEN(0) ? control_header->cmsg_len - CMSG_LEN(0) : 0;
            std::memcpy(&received_traffic_class, CMSG_DATA(control_header),
                        std::min<std::size_t>(sizeof(received_traffic_class), payload_size));
            return ecn_from_linux_traffic_class(received_traffic_class);
        }
        control_header = CMSG_NXTHDR(const_cast<msghdr *>(&message), control_header);
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
    auto *control_header = CMSG_FIRSTHDR(const_cast<msghdr *>(&message));
    while (control_header != nullptr) {
        if (control_header->cmsg_level == SOL_UDP && control_header->cmsg_type == UDP_GRO) {
            std::uint16_t segment_size = 0;
            const auto payload_size =
                control_header->cmsg_len > CMSG_LEN(0) ? control_header->cmsg_len - CMSG_LEN(0) : 0;
            std::memcpy(&segment_size, CMSG_DATA(control_header),
                        std::min<std::size_t>(sizeof(segment_size), payload_size));
            return segment_size;
        }
        control_header = CMSG_NXTHDR(const_cast<msghdr *>(&message), control_header);
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
    while (true) {
        const ssize_t bytes_read =
            socket_io_backend_ops_state().recvmsg_fn(socket_fd, message, flags);
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
        const ssize_t sendto_result = socket_io_backend_ops_state().sendto_fn(
            fd, buffer, datagram.size(), 0, reinterpret_cast<const sockaddr *>(&send_peer),
            peer_len);
        if (sendto_result >= 0) {
            return true;
        }
        if (ignorable_udp_send_error(errno, is_pmtu_probe)) {
            return true;
        }

        std::cerr << "io-" << role_name << " failed: sendto error: " << std::strerror(errno)
                  << '\n';
        return false;
    }

    iovec send_iovec{
        .iov_base = const_cast<void *>(buffer),
        .iov_len = datagram.size(),
    };
    alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(int))> control_storage{};
    msghdr outbound_message{};
    outbound_message.msg_name =
        const_cast<sockaddr *>(reinterpret_cast<const sockaddr *>(&send_peer));
    outbound_message.msg_namelen = peer_len;
    outbound_message.msg_iov = &send_iovec;
    outbound_message.msg_iovlen = 1;
    if (is_ect_codepoint(ecn)) {
        outbound_message.msg_control = control_storage.data();
        outbound_message.msg_controllen = control_storage.size();

        auto *control_header = reinterpret_cast<cmsghdr *>(control_storage.data());
        const bool use_ipv4_traffic_class =
            peer.ss_family == AF_INET || is_ipv4_mapped_ipv6_address(peer, peer_len);
        control_header->cmsg_level = use_ipv4_traffic_class ? IPPROTO_IP : IPPROTO_IPV6;
        control_header->cmsg_type = use_ipv4_traffic_class ? IP_TOS : IPV6_TCLASS;
        control_header->cmsg_len = CMSG_LEN(sizeof(int));
        const int datagram_ecn_tclass = linux_traffic_class_for_ecn(ecn);
        std::memcpy(CMSG_DATA(control_header), &datagram_ecn_tclass, sizeof(datagram_ecn_tclass));
        outbound_message.msg_controllen = control_header->cmsg_len;
    }

    if (io_profile_enabled()) {
        ++io_profile_counters().sendmsg_calls;
    }
    const ssize_t sendmsg_result =
        socket_io_backend_ops_state().sendmsg_fn(fd, &outbound_message, 0);
    if (sendmsg_result >= 0) {
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

template <typename T> void ensure_scratch_size(std::vector<T> &scratch, std::size_t size) {
    if (scratch.size() < size) {
        scratch.resize(size);
    }
}

SendmmsgBatchScratch &sendmmsg_batch_scratch() {
    static thread_local SendmmsgBatchScratch scratch;
    return scratch;
}

bool &udp_gso_disabled() {
    static thread_local bool disabled = [] {
        const char *value = std::getenv("COQUIC_DISABLE_UDP_GSO");
        return value != nullptr && value[0] != '\0' && std::string_view(value) != "0";
    }();
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

COQUIC_NO_PROFILE bool sendmmsg_run_can_include(const QuicIoEngineTxDatagram &first_datagram,
                                                std::span<const QuicIoEngineTxDatagram> datagrams,
                                                std::size_t index) {
    return can_extend_sendmmsg_run(index, datagrams.size()) &&
           tx_datagram_matches_sendmmsg_batch(first_datagram, datagrams[index]);
}

COQUIC_NO_PROFILE bool uses_ipv4_traffic_class_control(const sockaddr_storage &peer,
                                                       socklen_t peer_len) {
    return peer.ss_family == AF_INET || is_ipv4_mapped_ipv6_address(peer, peer_len);
}

COQUIC_NO_PROFILE void set_traffic_class_control_message_header(cmsghdr &control_header,
                                                                bool use_ipv4_traffic_class) {
    control_header.cmsg_level = use_ipv4_traffic_class ? IPPROTO_IP : IPPROTO_IPV6;
    control_header.cmsg_type = use_ipv4_traffic_class ? IP_TOS : IPV6_TCLASS;
}

void set_sendmsg_ecn_control(msghdr &message, EcnControlStorage &control_storage,
                             QuicEcnCodepoint ecn, const sockaddr_storage &peer,
                             socklen_t peer_len) {
    auto *control_header = reinterpret_cast<cmsghdr *>(control_storage.bytes.data());
    const bool use_ipv4_traffic_class = uses_ipv4_traffic_class_control(peer, peer_len);
    set_traffic_class_control_message_header(*control_header, use_ipv4_traffic_class);
    control_header->cmsg_len = CMSG_LEN(sizeof(int));
    const int sendmsg_ecn_tclass = linux_traffic_class_for_ecn(ecn);
    std::memcpy(CMSG_DATA(control_header), &sendmsg_ecn_tclass, sizeof(sendmsg_ecn_tclass));
    message.msg_control = control_storage.bytes.data();
    message.msg_controllen = control_header->cmsg_len;
}

void append_sendmsg_ecn_control(msghdr &message, UdpGsoControlStorage &control_storage,
                                QuicEcnCodepoint ecn, const sockaddr_storage &peer,
                                socklen_t peer_len, std::byte *&control_cursor) {
    auto *control_header = reinterpret_cast<cmsghdr *>(control_cursor);
    const bool use_ipv4_traffic_class = uses_ipv4_traffic_class_control(peer, peer_len);
    set_traffic_class_control_message_header(*control_header, use_ipv4_traffic_class);
    control_header->cmsg_len = CMSG_LEN(sizeof(int));
    const int udp_gso_ecn_tclass = linux_traffic_class_for_ecn(ecn);
    std::memcpy(CMSG_DATA(control_header), &udp_gso_ecn_tclass, sizeof(udp_gso_ecn_tclass));
    control_cursor += CMSG_SPACE(sizeof(int));
    message.msg_controllen =
        static_cast<std::size_t>(control_cursor - control_storage.bytes.data());
}

void append_udp_gso_control(msghdr &message, UdpGsoControlStorage &control_storage,
                            std::uint16_t segment_size, std::byte *&control_cursor) {
    auto *control_header = reinterpret_cast<cmsghdr *>(control_cursor);
    control_header->cmsg_level = SOL_UDP;
    control_header->cmsg_type = UDP_SEGMENT;
    control_header->cmsg_len = CMSG_LEN(sizeof(segment_size));
    std::memcpy(CMSG_DATA(control_header), &segment_size, sizeof(segment_size));
    control_cursor += CMSG_SPACE(sizeof(segment_size));
    message.msg_controllen =
        static_cast<std::size_t>(control_cursor - control_storage.bytes.data());
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
    ensure_scratch_size(iovecs, datagrams.size());
    ensure_scratch_size(peers, 1);
    for (std::size_t index = 0; index < datagrams.size(); ++index) {
        const auto &datagram = datagrams[index];
        iovecs[index] = iovec{
            .iov_base = const_cast<std::byte *>(datagram.bytes.data()),
            .iov_len = datagram.bytes.size(),
        };
    }

    UdpGsoControlStorage gso_control_storage{};
    msghdr gso_send_message{};
    peers.front() = peer_with_ipv6_flow_label(datagrams.front().peer, datagrams.front().peer_len,
                                              datagrams.front().bytes);
    gso_send_message.msg_name = reinterpret_cast<sockaddr *>(&peers.front());
    gso_send_message.msg_namelen = datagrams.front().peer_len;
    gso_send_message.msg_iov = iovecs.data();
    gso_send_message.msg_iovlen = datagrams.size();
    gso_send_message.msg_control = gso_control_storage.bytes.data();
    gso_send_message.msg_controllen = 0;

    auto *control_cursor = gso_control_storage.bytes.data();
    if (is_ect_codepoint(datagrams.front().ecn)) {
        append_sendmsg_ecn_control(gso_send_message, gso_control_storage, datagrams.front().ecn,
                                   datagrams.front().peer, datagrams.front().peer_len,
                                   control_cursor);
    }
    append_udp_gso_control(gso_send_message, gso_control_storage,
                           static_cast<std::uint16_t>(segment_size), control_cursor);

    ssize_t sendmsg_result = 0;
    do {
        if (io_profile_enabled()) {
            ++io_profile_counters().udp_gso_sendmsg_calls;
        }
        sendmsg_result = socket_io_backend_ops_state().sendmsg_fn(datagrams.front().socket_fd,
                                                                  &gso_send_message, 0);
    } while (sendmsg_result < 0 && errno == EINTR);

    if (sendmsg_result >= 0) {
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
    auto &send_messages = scratch.messages;
    auto &ecn_controls = scratch.ecn_controls;
    auto &peers = scratch.peers;

    ensure_scratch_size(iovecs, datagrams.size());
    ensure_scratch_size(send_messages, datagrams.size());
    ensure_scratch_size(peers, datagrams.size());
    const bool has_ecn_control = is_ect_codepoint(datagrams.front().ecn);
    if (has_ecn_control) {
        ensure_scratch_size(ecn_controls, datagrams.size());
    }
    for (std::size_t index = 0; index < datagrams.size(); ++index) {
        const auto &datagram = datagrams[index];
        iovecs[index] = iovec{
            .iov_base = const_cast<std::byte *>(datagram.bytes.data()),
            .iov_len = datagram.bytes.size(),
        };
        peers[index] = peer_with_ipv6_flow_label(datagram.peer, datagram.peer_len, datagram.bytes);
        auto &outbound_message = send_messages[index];
        outbound_message = {};
        outbound_message.msg_hdr.msg_name = reinterpret_cast<sockaddr *>(&peers[index]);
        outbound_message.msg_hdr.msg_namelen = datagram.peer_len;
        outbound_message.msg_hdr.msg_iov = &iovecs[index];
        outbound_message.msg_hdr.msg_iovlen = 1;
        if (has_ecn_control) {
            set_sendmsg_ecn_control(outbound_message.msg_hdr, ecn_controls[index], datagram.ecn,
                                    datagram.peer, datagram.peer_len);
        }
    }

    unsigned sent_message_total = 0;
    while (sent_message_total < datagrams.size()) {
        const auto remaining =
            static_cast<unsigned>(datagrams.size() - static_cast<std::size_t>(sent_message_total));
        int sent_message_count = 0;
        do {
            if (io_profile_enabled()) {
                ++io_profile_counters().sendmmsg_calls;
            }
            sent_message_count = socket_io_backend_ops_state().sendmmsg_fn(
                datagrams.front().socket_fd, send_messages.data() + sent_message_total, remaining,
                0);
        } while (sent_message_count < 0 && errno == EINTR);

        if (sent_message_count < 0) {
            if (ignorable_udp_send_error(errno, /*is_pmtu_probe=*/false)) {
                return true;
            }
            std::cerr << "io-" << role_name << " failed: sendmmsg error: " << std::strerror(errno)
                      << '\n';
            return false;
        }
        if (sent_message_count == 0) {
            return true;
        }
        if (io_profile_enabled()) {
            io_profile_counters().sendmmsg_datagrams +=
                static_cast<std::uint64_t>(sent_message_count);
        }
        sent_message_total += static_cast<unsigned>(sent_message_count);
    }
    return true;
}

bool send_datagrams(std::span<const QuicIoEngineTxDatagram> datagrams, std::string_view role_name) {
    for (std::size_t offset = 0; offset < datagrams.size();) {
        const auto &first_datagram = datagrams[offset];
        if (!sendmmsg_supports_datagram(first_datagram)) {
            if (!send_datagram(first_datagram.socket_fd, first_datagram.bytes, first_datagram.peer,
                               first_datagram.peer_len, role_name, first_datagram.ecn,
                               first_datagram.is_pmtu_probe)) {
                return false;
            }
            ++offset;
            continue;
        }

        std::size_t same_peer_end = offset + 1;
        while (sendmmsg_run_can_include(first_datagram, datagrams, same_peer_end)) {
            ++same_peer_end;
        }

        std::size_t run_offset = offset;
        while (run_offset < same_peer_end) {
            const auto equal_size_run_end = [&](std::size_t begin) {
                const auto &run_first = datagrams[begin];
                std::size_t run_end = begin + 1;
                while (run_end < same_peer_end &&
                       tx_datagram_matches_udp_gso_batch(run_first, datagrams[run_end])) {
                    ++run_end;
                }
                return run_end;
            };

            auto same_size_run_end = equal_size_run_end(run_offset);
            if (same_size_run_end - run_offset > 1 && datagrams[run_offset].bytes.size() > 0) {
                const auto max_segments = std::min<std::size_t>(
                    64, std::max<std::size_t>(1u, kMaxDatagramBytes /
                                                      datagrams[run_offset].bytes.size()));
                for (std::size_t chunk_offset = run_offset; chunk_offset < same_size_run_end;) {
                    const auto chunk_size =
                        std::min(max_segments, same_size_run_end - chunk_offset);
                    if (!sendmmsg_batch(datagrams.subspan(chunk_offset, chunk_size), role_name)) {
                        return false;
                    }
                    chunk_offset += chunk_size;
                }
                run_offset = same_size_run_end;
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
            std::array<std::byte, 256> recv_control_storage{};
            iovec recv_iovec{
                .iov_base = inbound.data(),
                .iov_len = inbound.size(),
            };
            msghdr inbound_message{};
            inbound_message.msg_name = &source;
            inbound_message.msg_namelen = sizeof(source);
            inbound_message.msg_iov = &recv_iovec;
            inbound_message.msg_iovlen = 1;
            inbound_message.msg_control = recv_control_storage.data();
            inbound_message.msg_controllen = recv_control_storage.size();
            if (io_profile_enabled()) {
                ++io_profile_counters().recvmsg_calls;
            }
            bytes_read =
                socket_io_backend_ops_state().recvmsg_fn(socket_fd, &inbound_message, flags);
            source_len = static_cast<socklen_t>(inbound_message.msg_namelen);
            if (bytes_read >= 0) {
                inbound_ecn = recvmsg_ecn_from_control(inbound_message);
#if defined(__linux__) && defined(UDP_GRO)
                auto segment_size = recvmsg_udp_gro_segment_size_from_control(inbound_message);
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
#endif
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
    while (true) {
        if (io_profile_enabled()) {
            ++io_profile_counters().recvmmsg_calls;
        }
        const int received_count = socket_io_backend_ops_state().recvmmsg_fn(
            socket_fd, messages, message_count, flags, nullptr);
        if (recvmmsg_call_completed(received_count, errno)) {
            return received_count;
        }
    }
}

COQUIC_NO_PROFILE ReceiveDatagramStatus
receive_datagram_batch_status_for_error(bool retryable_error) {
    return retryable_error ? ReceiveDatagramStatus::would_block : ReceiveDatagramStatus::error;
}

std::size_t normalized_udp_gro_segment_size(std::size_t udp_gro_segment_size,
                                            std::size_t datagram_size) {
    if (udp_gro_segment_size == 0) {
        return 0;
    }
    return std::min(udp_gro_segment_size, datagram_size);
}

std::size_t received_datagram_segment_count(std::size_t received_size,
                                            std::size_t udp_gro_segment_size) {
    const auto segment_size = normalized_udp_gro_segment_size(udp_gro_segment_size, received_size);
    if (segment_size == 0 || segment_size >= received_size) {
        return 1;
    }
    return (received_size + segment_size - 1u) / segment_size;
}

template <typename OutputDatagrams>
void append_received_datagram_segments(OutputDatagrams &output_datagrams,
                                       ReceiveDatagramResult received) {
    const auto received_size = received.payload().size();
    const auto segment_size = received.udp_gro_segment_size;
    if (segment_size == 0 || segment_size >= received_size) {
        output_datagrams.push_back(std::move(received));
        return;
    }

    auto shared_datagram_storage = received.shared_bytes;
    if (shared_datagram_storage == nullptr) {
        shared_datagram_storage =
            std::make_shared<std::vector<std::byte>>(std::move(received.bytes));
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
        output_datagrams.push_back(ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::ok,
            .ecn = received.ecn,
            .source = received.source,
            .source_len = received.source_len,
            .input_time = received.input_time,
            .shared_bytes = shared_datagram_storage,
            .begin = begin,
            .end = end,
        });
    }
}

template <typename OutputDatagrams>
void append_shared_received_datagram_segments(
    OutputDatagrams &output_datagrams,
    const std::shared_ptr<std::vector<std::byte>> &shared_datagram_storage,
    std::size_t datagram_begin, std::size_t datagram_size, QuicEcnCodepoint ecn,
    const sockaddr_storage &source, socklen_t source_len, QuicCoreTimePoint input_time,
    std::size_t udp_gro_segment_size) {
    const auto segment_size = normalized_udp_gro_segment_size(udp_gro_segment_size, datagram_size);
    if (segment_size == 0 || segment_size >= datagram_size) {
        output_datagrams.push_back(ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::ok,
            .ecn = ecn,
            .source = source,
            .source_len = source_len,
            .input_time = input_time,
            .shared_bytes = shared_datagram_storage,
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
        output_datagrams.push_back(ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::ok,
            .ecn = ecn,
            .source = source,
            .source_len = source_len,
            .input_time = input_time,
            .shared_bytes = shared_datagram_storage,
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
            ReceiveDatagramResultVector datagrams;
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
    auto &recv_messages = scratch.messages;
    auto &begins = scratch.begins;
    auto &sizes = scratch.sizes;

    for (std::size_t index = 0; index < batch_size; ++index) {
        prepare_receive_byte_storage(inbound[index]);
        sources[index] = {};
        recv_messages[index] = {};
        iovecs[index] = iovec{
            .iov_base = inbound[index]->data(),
            .iov_len = inbound[index]->size(),
        };
        auto &inbound_message = recv_messages[index].msg_hdr;
        inbound_message.msg_name = &sources[index];
        inbound_message.msg_namelen = sizeof(sources[index]);
        inbound_message.msg_iov = &iovecs[index];
        inbound_message.msg_iovlen = 1;
        inbound_message.msg_control = controls[index].data();
        inbound_message.msg_controllen = controls[index].size();
    }

    const int received_count = recvmmsg_retry_on_eintr(
        socket_fd, recv_messages.data(), static_cast<unsigned int>(batch_size), MSG_DONTWAIT);

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
    auto received_datagram_count = static_cast<std::size_t>(received_count);
    begins.resize(received_datagram_count);
    sizes.resize(received_datagram_count);
    std::size_t shared_size = 0;
    std::size_t received_result_count = 0;
    for (int index = 0; index < received_count; ++index) {
        const auto datagram_index = static_cast<std::size_t>(index);
        const auto received_size = static_cast<std::size_t>(recv_messages[datagram_index].msg_len);
        auto &inbound_message = recv_messages[datagram_index].msg_hdr;
        begins[datagram_index] = shared_size;
        sizes[datagram_index] = received_size;
        shared_size += received_size;
        received_result_count += received_datagram_segment_count(
            received_size, recvmsg_udp_gro_segment_size_from_control(inbound_message));
    }

    ReceiveDatagramResultVector received_results;
    received_results.reserve(received_result_count);
    for (int index = 0; index < received_count; ++index) {
        const auto datagram_index = static_cast<std::size_t>(index);
        auto &inbound_message = recv_messages[static_cast<std::size_t>(index)].msg_hdr;
        auto segment_size = recvmsg_udp_gro_segment_size_from_control(inbound_message);
        const auto ecn = recvmsg_ecn_from_control(inbound_message);
        const auto source = sources[static_cast<std::size_t>(index)];
        const auto source_len = static_cast<socklen_t>(inbound_message.msg_namelen);
        append_shared_received_datagram_segments(received_results, inbound[datagram_index], 0,
                                                 sizes[datagram_index], ecn, source, source_len,
                                                 input_time, segment_size);
    }
    return ReceiveDatagramBatchResult{
        .status = ReceiveDatagramStatus::ok,
        .datagrams = std::move(received_results),
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
    std::array<std::byte, 512> control_storage{};
    sockaddr_storage peer{};
    iovec recv_iovec{
        .iov_base = inbound.data(),
        .iov_len = inbound.size(),
    };
    msghdr inbound_message{};
    inbound_message.msg_name = &peer;
    inbound_message.msg_namelen = sizeof(peer);
    inbound_message.msg_iov = &recv_iovec;
    inbound_message.msg_iovlen = 1;
    inbound_message.msg_control = control_storage.data();
    inbound_message.msg_controllen = control_storage.size();

    const ssize_t bytes_read = recvmsg_retry_on_eintr(socket_fd, &inbound_message, MSG_ERRQUEUE);

    if (bytes_read < 0) {
        return PathMtuUpdateResult{
            .status = path_mtu_status_for_recv_error(errno),
        };
    }

    auto *control_message = first_control_message(inbound_message);
    while (control_message != nullptr) {
        const bool ipv4_error = control_message_is_ipv4_error(*control_message);
        const bool ipv6_error = control_message_is_ipv6_error(*control_message);
        if (ipv4_error || ipv6_error) {
            const auto *error =
                reinterpret_cast<const sock_extended_err *>(CMSG_DATA(control_message));
            const auto max_udp_payload_size =
                max_udp_payload_size_from_error_control_message(error, ipv6_error);
            //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2.1
            // # An endpoint MUST ignore an ICMP message that claims the PMTU has
            // # decreased below QUIC's smallest allowed maximum datagram size.
            if (max_udp_payload_size >= 1200) {
                std::vector<std::byte> quoted_packet;
                if (bytes_read > 0) {
                    quoted_packet.assign(
                        inbound.begin(),
                        inbound.begin() +
                            static_cast<std::ptrdiff_t>(std::min<std::size_t>(
                                static_cast<std::size_t>(bytes_read), inbound.size())));
                }
                return PathMtuUpdateResult{
                    .status = PathMtuUpdateStatus::ok,
                    .max_udp_payload_size = max_udp_payload_size,
                    .peer = peer,
                    .peer_len = static_cast<socklen_t>(inbound_message.msg_namelen),
                    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2.1
                    // # This validation SHOULD use the quoted packet supplied
                    // # in the payload of an ICMP message to associate the
                    // # message with a corresponding transport connection (see
                    // # Section 4.6.1 of [DPLPMTUD]).
                    .quoted_packet = std::move(quoted_packet),
                    .input_time = now(),
                };
            }
        }
        control_message = CMSG_NXTHDR(&inbound_message, control_message);
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

COQUIC_NO_PROFILE internal::ReceiveDatagramResult
compact_small_receive_storage(internal::ReceiveDatagramResult received) {
    if (received.shared_bytes == nullptr) {
        return received;
    }

    if (received.shared_bytes.use_count() > 2) {
        return received;
    }

    const auto payload = received.payload();
    if (payload.size() > kReceiveScratchCopyMaxBytes) {
        return received;
    }

    received.bytes.assign(payload.begin(), payload.end());
    received.shared_bytes.reset();
    received.begin = 0;
    received.end = 0;
    if (io_profile_enabled()) {
        auto &counters = io_profile_counters();
        ++counters.rx_storage_compact_copies;
        counters.rx_storage_compact_copy_bytes += payload.size();
    }
    return received;
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
    return next_queued_event_index_ < queued_events_.size();
}

PollIoEngine::PollIoEngine() {
    queued_events_.reserve(kMaxReceiveDrainBatch);
}

void PollIoEngine::queue_event(QuicIoEngineEvent event) {
    if (next_queued_event_index_ > 0 && (next_queued_event_index_ == queued_events_.size() ||
                                         queued_events_.size() == queued_events_.capacity())) {
        queued_events_.erase(queued_events_.begin(),
                             queued_events_.begin() +
                                 static_cast<std::ptrdiff_t>(next_queued_event_index_));
        next_queued_event_index_ = 0;
    }
    queued_events_.push_back(std::move(event));
}

std::size_t PollIoEngine::queued_event_count() const {
    return queued_events_.size() - next_queued_event_index_;
}

std::optional<QuicIoEngineEvent> PollIoEngine::pop_queued_event() {
    if (!has_pending_events()) {
        queued_events_.clear();
        next_queued_event_index_ = 0;
        return std::nullopt;
    }

    auto event = std::move(queued_events_[next_queued_event_index_]);
    ++next_queued_event_index_;
    if (next_queued_event_index_ == queued_events_.size()) {
        queued_events_.clear();
        next_queued_event_index_ = 0;
    }
    return event;
}

std::optional<QuicIoEngineEvent>
PollIoEngine::wait(std::span<const int> socket_fds, int idle_timeout_ms,
                   std::optional<quic::QuicCoreTimePoint> next_wakeup, std::string_view role_name) {
    if (auto queued_event = pop_queued_event()) {
        auto event = std::move(*queued_event);
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
                                .quoted_packet = std::move(update.quoted_packet),
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

            auto first_received =
                compact_small_receive_storage(std::move(received_batch.datagrams.front()));
            auto event = make_rx_event(descriptor.fd, std::move(first_received));
            for (std::size_t index = 1; index < received_batch.datagrams.size(); ++index) {
                queue_event(make_rx_event(descriptor.fd, compact_small_receive_storage(std::move(
                                                             received_batch.datagrams[index]))));
            }
            if (received_batch.may_have_more_datagrams) {
                while (queued_event_count() < kMaxReceiveDrainBatch - 1) {
                    auto extra_batch = internal::receive_datagram_batch(
                        descriptor.fd, role_name, kMaxReceiveDrainBatch - 1 - queued_event_count());
                    if (extra_batch.status == internal::ReceiveDatagramStatus::would_block) {
                        break;
                    }
                    if (!receive_datagram_batch_has_payload(extra_batch)) {
                        return std::nullopt;
                    }
                    for (auto &extra : extra_batch.datagrams) {
                        queue_event(make_rx_event(descriptor.fd,
                                                  compact_small_receive_storage(std::move(extra))));
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
    int linux_traffic_class = 0;
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

struct PollEngineTestTrace {
    int eintr_then_timeout_calls = 0;
    int ignored_errqueue_poll_calls = 0;
    int extra_batch_recvmmsg_calls = 0;
};

thread_local PollEngineTestTrace g_poll_engine_test_trace;

struct SendManyBatchTestTrace {
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
    int linux_traffic_class = 0;
    std::uint16_t udp_segment_size = 0;
    int peer_family = AF_UNSPEC;
    std::uint32_t ipv6_flowinfo = 0;
};

thread_local SendManyBatchTestTrace g_send_many_batch_test_trace;

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
        g_send_many_batch_test_trace.peer_family = peer->sa_family;
        if (peer->sa_family == AF_INET6) {
            const auto *ipv6_peer = reinterpret_cast<const sockaddr_in6 *>(message.msg_name);
            g_send_many_batch_test_trace.ipv6_flowinfo = ntohl(ipv6_peer->sin6_flowinfo);
        }
    }
    for (auto *control_header = CMSG_FIRSTHDR(const_cast<msghdr *>(&message));
         control_header != nullptr;
         control_header = CMSG_NXTHDR(const_cast<msghdr *>(&message), control_header)) {
        if ((control_header->cmsg_level == IPPROTO_IP && control_header->cmsg_type == IP_TOS) ||
            (control_header->cmsg_level == IPPROTO_IPV6 &&
             control_header->cmsg_type == IPV6_TCLASS)) {
            g_send_many_batch_test_trace.saw_ecn_control = true;
            g_send_many_batch_test_trace.ecn_level = control_header->cmsg_level;
            g_send_many_batch_test_trace.ecn_type = control_header->cmsg_type;
            std::memcpy(&g_send_many_batch_test_trace.linux_traffic_class,
                        CMSG_DATA(control_header),
                        sizeof(g_send_many_batch_test_trace.linux_traffic_class));
        }
        if (control_header->cmsg_level == SOL_UDP && control_header->cmsg_type == UDP_SEGMENT) {
            g_send_many_batch_test_trace.saw_udp_segment_control = true;
            std::memcpy(&g_send_many_batch_test_trace.udp_segment_size, CMSG_DATA(control_header),
                        sizeof(g_send_many_batch_test_trace.udp_segment_size));
        }
    }
}

ssize_t batch_sendmsg_for_tests(int socket_fd, const msghdr *message, int) {
    g_send_many_batch_test_trace.sendmsg_calls += 1;
    g_send_many_batch_test_trace.socket_fd = socket_fd;
    if (message != nullptr) {
        g_send_many_batch_test_trace.last_sendmsg_iov_count = message->msg_iovlen;
        g_send_many_batch_test_trace.last_sendmsg_total_bytes = iov_total_size(*message);
        record_batch_controls_for_tests(*message);
    }

    if (g_send_many_batch_test_trace.mode ==
        SendManyBatchTestTrace::Mode::gso_not_supported_then_partial_sendmmsg) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (g_send_many_batch_test_trace.mode == SendManyBatchTestTrace::Mode::udp_gso_einval) {
        errno = EINVAL;
        return -1;
    }
    if (g_send_many_batch_test_trace.mode == SendManyBatchTestTrace::Mode::udp_gso_enoprotoopt) {
        errno = ENOPROTOOPT;
        return -1;
    }
    if (g_send_many_batch_test_trace.mode == SendManyBatchTestTrace::Mode::udp_gso_emsgsize) {
        errno = EMSGSIZE;
        return -1;
    }
    if (g_send_many_batch_test_trace.mode ==
        SendManyBatchTestTrace::Mode::udp_gso_ignorable_error) {
        errno = ECONNREFUSED;
        return -1;
    }
    if (g_send_many_batch_test_trace.mode == SendManyBatchTestTrace::Mode::udp_gso_hard_error) {
        errno = EACCES;
        return -1;
    }
    if (g_send_many_batch_test_trace.mode ==
            SendManyBatchTestTrace::Mode::second_udp_gso_chunk_hard_error &&
        g_send_many_batch_test_trace.sendmsg_calls > 1) {
        errno = EIO;
        return -1;
    }
    return static_cast<ssize_t>(g_send_many_batch_test_trace.last_sendmsg_total_bytes);
}

int batch_sendmmsg_for_tests(int socket_fd, mmsghdr *send_messages, unsigned int message_count,
                             int) {
    g_send_many_batch_test_trace.sendmmsg_calls += 1;
    g_send_many_batch_test_trace.socket_fd = socket_fd;
    g_send_many_batch_test_trace.last_sendmmsg_message_count = message_count;
    if (send_messages != nullptr && message_count > 0) {
        record_batch_controls_for_tests(send_messages[0].msg_hdr);
    }

    switch (g_send_many_batch_test_trace.mode) {
    case SendManyBatchTestTrace::Mode::second_udp_gso_chunk_hard_error:
        if (g_send_many_batch_test_trace.sendmsg_calls > 1) {
            errno = EIO;
            return -1;
        }
        return static_cast<int>(message_count);
    case SendManyBatchTestTrace::Mode::gso_not_supported_then_partial_sendmmsg:
        if (g_send_many_batch_test_trace.sendmmsg_calls == 1) {
            errno = EINTR;
            return -1;
        }
        if (message_count > 1) {
            return 1;
        }
        return static_cast<int>(message_count);
    case SendManyBatchTestTrace::Mode::sendmmsg_zero:
        return 0;
    case SendManyBatchTestTrace::Mode::sendmmsg_ignorable_error:
        errno = ECONNREFUSED;
        return -1;
    case SendManyBatchTestTrace::Mode::sendmmsg_hard_error:
        errno = EIO;
        return -1;
    default:
        return static_cast<int>(message_count);
    }
}

ssize_t batch_sendto_for_tests(int socket_fd, const void *, size_t length, int, const sockaddr *,
                               socklen_t) {
    g_send_many_batch_test_trace.sendto_calls += 1;
    g_send_many_batch_test_trace.socket_fd = socket_fd;
    if (g_send_many_batch_test_trace.mode == SendManyBatchTestTrace::Mode::sendto_hard_error) {
        errno = EIO;
        return -1;
    }
    if (g_send_many_batch_test_trace.mode == SendManyBatchTestTrace::Mode::sendto_pmtu_error) {
        errno = EMSGSIZE;
        return -1;
    }
    if (g_send_many_batch_test_trace.mode == SendManyBatchTestTrace::Mode::sendto_connrefused) {
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
    g_recorded_sendmsg_for_tests.linux_traffic_class = 0;
    g_recorded_sendmsg_for_tests.family = AF_UNSPEC;
    g_recorded_sendmsg_for_tests.ipv6_flowinfo = 0;
    if (message == nullptr) {
        return 0;
    }
    if (message->msg_name != nullptr) {
        const auto *peer = static_cast<const sockaddr *>(message->msg_name);
        g_recorded_sendmsg_for_tests.family = peer->sa_family;
        if (peer->sa_family == AF_INET6) {
            const auto *ipv6_peer = reinterpret_cast<const sockaddr_in6 *>(message->msg_name);
            g_recorded_sendmsg_for_tests.ipv6_flowinfo = ntohl(ipv6_peer->sin6_flowinfo);
        }
    }
    if (auto *control_header = CMSG_FIRSTHDR(const_cast<msghdr *>(message));
        control_header != nullptr) {
        g_recorded_sendmsg_for_tests.level = control_header->cmsg_level;
        g_recorded_sendmsg_for_tests.type = control_header->cmsg_type;
        std::memcpy(&g_recorded_sendmsg_for_tests.linux_traffic_class, CMSG_DATA(control_header),
                    sizeof(g_recorded_sendmsg_for_tests.linux_traffic_class));
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
        auto *control_header = CMSG_FIRSTHDR(message);
        if (control_header == nullptr) {
            errno = EINVAL;
            return -1;
        }
        const bool peer_is_ipv6 = g_recorded_recvmsg_for_tests.peer.ss_family == AF_INET6;
        control_header->cmsg_level = peer_is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
        control_header->cmsg_type = peer_is_ipv6 ? IPV6_RECVERR : IP_RECVERR;
        control_header->cmsg_len = CMSG_LEN(sizeof(sock_extended_err));
        auto error = sock_extended_err{};
        error.ee_errno =
            g_recorded_recvmsg_for_tests.errqueue_errno != 0
                ? static_cast<std::uint32_t>(g_recorded_recvmsg_for_tests.errqueue_errno)
                : static_cast<std::uint32_t>(EMSGSIZE);
        error.ee_info = static_cast<std::uint32_t>(g_recorded_recvmsg_for_tests.pmtu);
        std::memcpy(CMSG_DATA(control_header), &error, sizeof(error));
        message->msg_controllen = control_header->cmsg_len;
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

    auto *control_header = CMSG_FIRSTHDR(message);
    if (control_header != nullptr) {
        const bool peer_is_ipv6 = g_recorded_recvmsg_for_tests.peer.ss_family == AF_INET6;
        control_header->cmsg_level = peer_is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
        control_header->cmsg_type = peer_is_ipv6 ? IPV6_TCLASS : IP_TOS;
        control_header->cmsg_len = CMSG_LEN(sizeof(int));
        const int recvmsg_traffic_class =
            internal::linux_traffic_class_for_ecn(g_recorded_recvmsg_for_tests.ecn);
        std::memcpy(CMSG_DATA(control_header), &recvmsg_traffic_class,
                    sizeof(recvmsg_traffic_class));
        message->msg_controllen = control_header->cmsg_len;
    }

    return static_cast<ssize_t>(bytes_to_copy);
}

int readable_poll_then_retry_with_datagram_for_tests(pollfd *poll_descriptors,
                                                     nfds_t descriptor_count, int) {
    g_retry_readable_poll_for_tests.poll_calls += 1;
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        poll_descriptors[index].revents = POLLIN;
    }
    return descriptor_count == 0 ? 0 : 1;
}

int eintr_then_timeout_poll_for_tests(pollfd *poll_descriptors, nfds_t descriptor_count, int) {
    g_poll_engine_test_trace.eintr_then_timeout_calls += 1;
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        poll_descriptors[index].revents = 0;
    }
    if (g_poll_engine_test_trace.eintr_then_timeout_calls == 1) {
        errno = EINTR;
        return -1;
    }
    return 0;
}

int positive_poll_without_revents_for_tests(pollfd *poll_descriptors, nfds_t descriptor_count,
                                            int) {
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        poll_descriptors[index].revents = 0;
    }
    if (descriptor_count == 0) {
        return 0;
    }
    return 1;
}

int readable_poll_for_tests(pollfd *poll_descriptors, nfds_t descriptor_count, int) {
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        poll_descriptors[index].revents = POLLIN;
    }
    return descriptor_count == 0 ? 0 : 1;
}

int hard_errqueue_poll_for_tests(pollfd *poll_descriptors, nfds_t descriptor_count, int) {
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        poll_descriptors[index].revents = POLLERR;
    }
    return descriptor_count == 0 ? 0 : 1;
}

ssize_t hard_errqueue_recvmsg_for_tests(int, msghdr *, int flags) {
    errno = ((flags & MSG_ERRQUEUE) != 0) ? EIO : EAGAIN;
    return -1;
}

int first_recvmmsg_batch_then_hard_error_for_tests(int, mmsghdr *messages,
                                                   unsigned int message_count, int, timespec *) {
    g_poll_engine_test_trace.extra_batch_recvmmsg_calls += 1;
    if (g_poll_engine_test_trace.extra_batch_recvmmsg_calls > 1) {
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

int two_small_recvmmsg_datagrams_for_tests(int, mmsghdr *messages, unsigned int message_count, int,
                                           timespec *) {
    const unsigned int received_count = std::min<unsigned int>(message_count, 2u);
    for (unsigned int index = 0; index < received_count; ++index) {
        auto &message = messages[index].msg_hdr;
        if (message.msg_iov == nullptr || message.msg_iovlen == 0 ||
            message.msg_iov[0].iov_len < 2) {
            errno = EINVAL;
            return -1;
        }
        auto *bytes = static_cast<std::byte *>(message.msg_iov[0].iov_base);
        bytes[0] = static_cast<std::byte>(0xa0u + index);
        bytes[1] = static_cast<std::byte>(0xb0u + index);
        messages[index].msg_len = 2;
    }
    return static_cast<int>(received_count);
}

int two_large_recvmmsg_datagrams_for_tests(int, mmsghdr *messages, unsigned int message_count, int,
                                           timespec *) {
    constexpr std::size_t kLargeDatagramSize = kReceiveScratchCopyMaxBytes + 1;
    const unsigned int received_count = std::min<unsigned int>(message_count, 2u);
    for (unsigned int index = 0; index < received_count; ++index) {
        auto &message = messages[index].msg_hdr;
        if (message.msg_iov == nullptr || message.msg_iovlen == 0 ||
            message.msg_iov[0].iov_len < kLargeDatagramSize) {
            errno = EINVAL;
            return -1;
        }
        auto *bytes = static_cast<std::byte *>(message.msg_iov[0].iov_base);
        bytes[0] = static_cast<std::byte>(0xc0u + index);
        bytes[kLargeDatagramSize - 1] = static_cast<std::byte>(0xd0u + index);
        messages[index].msg_len = kLargeDatagramSize;
    }
    return static_cast<int>(received_count);
}

int one_udp_gro_recvmmsg_datagram_for_tests(int, mmsghdr *messages, unsigned int message_count, int,
                                            timespec *) {
#if defined(__linux__) && defined(UDP_GRO)
    if (message_count == 0) {
        return 0;
    }
    auto &message = messages[0].msg_hdr;
    constexpr std::size_t kCoalescedSize = 6;
    constexpr std::uint16_t kSegmentSize = 2;
    if (message.msg_iov == nullptr || message.msg_iovlen == 0 ||
        message.msg_iov[0].iov_len < kCoalescedSize) {
        errno = EINVAL;
        return -1;
    }
    auto *bytes = static_cast<std::byte *>(message.msg_iov[0].iov_base);
    for (std::size_t index = 0; index < kCoalescedSize; ++index) {
        bytes[index] = static_cast<std::byte>(0xe0u + index);
    }
    auto *control_header = CMSG_FIRSTHDR(&message);
    if (control_header == nullptr) {
        errno = EINVAL;
        return -1;
    }
    control_header->cmsg_level = SOL_UDP;
    control_header->cmsg_type = UDP_GRO;
    control_header->cmsg_len = CMSG_LEN(sizeof(kSegmentSize));
    std::memcpy(CMSG_DATA(control_header), &kSegmentSize, sizeof(kSegmentSize));
    message.msg_controllen = control_header->cmsg_len;
    messages[0].msg_len = kCoalescedSize;
    return 1;
#else
    static_cast<void>(messages);
    static_cast<void>(message_count);
    errno = EAGAIN;
    return -1;
#endif
}

int errqueue_then_timeout_poll_for_tests(pollfd *poll_descriptors, nfds_t descriptor_count, int) {
    g_poll_engine_test_trace.ignored_errqueue_poll_calls += 1;
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        poll_descriptors[index].revents =
            g_poll_engine_test_trace.ignored_errqueue_poll_calls == 1 ? POLLERR : 0;
    }
    if (descriptor_count == 0 || g_poll_engine_test_trace.ignored_errqueue_poll_calls > 1) {
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
socket_io_backend_ecn_from_linux_traffic_class_for_runtime_tests(int linux_traffic_class) {
    return internal::ecn_from_linux_traffic_class(linux_traffic_class);
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

    bool datagram_sent =
        internal::send_datagram(17, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in)),
                                "client", QuicEcnCodepoint::ect1);
    return all_true({
        datagram_sent,
        g_recorded_sendmsg_for_tests.calls == 1,
        g_recorded_sendmsg_for_tests.socket_fd == 17,
        g_recorded_sendmsg_for_tests.level == IPPROTO_IP,
        g_recorded_sendmsg_for_tests.type == IP_TOS,
        g_recorded_sendmsg_for_tests.linux_traffic_class == 0x01,
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
    auto &ipv6_peer = *reinterpret_cast<sockaddr_in6 *>(&peer);
    ipv6_peer.sin6_family = AF_INET6;
    ipv6_peer.sin6_port = htons(4433);
    ipv6_peer.sin6_addr.s6_addr[10] = 0xff;
    ipv6_peer.sin6_addr.s6_addr[11] = 0xff;
    ipv6_peer.sin6_addr.s6_addr[12] = 127;
    ipv6_peer.sin6_addr.s6_addr[15] = 1;

    bool datagram_sent =
        internal::send_datagram(23, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in6)),
                                "server", QuicEcnCodepoint::ect1);
    return all_true({
        datagram_sent,
        g_recorded_sendmsg_for_tests.calls == 1,
        g_recorded_sendmsg_for_tests.socket_fd == 23,
        g_recorded_sendmsg_for_tests.level == IPPROTO_IP,
        g_recorded_sendmsg_for_tests.type == IP_TOS,
        g_recorded_sendmsg_for_tests.linux_traffic_class == 0x01,
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
    auto &ipv6_peer = *reinterpret_cast<sockaddr_in6 *>(&peer);
    ipv6_peer.sin6_family = AF_INET6;
    ipv6_peer.sin6_port = htons(4433);
    ipv6_peer.sin6_addr = in6addr_loopback;

    sockaddr_storage ipv4_peer{};
    ipv4_peer.ss_family = AF_INET;
    bool datagram_sent =
        internal::send_datagram(29, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in6)),
                                "server", QuicEcnCodepoint::not_ect);

    g_send_many_batch_test_trace = {};
    ScopedSocketIoBackendOpsOverride batch_ops{
        SocketIoBackendOpsOverride{
            .sendmsg_fn = &batch_sendmsg_for_tests,
            .sendmmsg_fn = &batch_sendmmsg_for_tests,
        },
    };
    std::array<std::byte, 2> first_payload = {
        std::byte{0xaa},
        std::byte{0xbb},
    };
    std::array<std::byte, 2> second_payload = {
        std::byte{0xcc},
        std::byte{0xdd},
    };
    auto first_flow_label_datagram = QuicIoEngineTxDatagram{
        .socket_fd = 31,
        .peer = peer,
        .peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6)),
        .bytes = first_payload,
        .ecn = QuicEcnCodepoint::not_ect,
    };
    auto second_flow_label_datagram = QuicIoEngineTxDatagram{
        .socket_fd = 31,
        .peer = peer,
        .peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6)),
        .bytes = second_payload,
        .ecn = QuicEcnCodepoint::not_ect,
    };
    std::array<QuicIoEngineTxDatagram, 2> datagrams = {first_flow_label_datagram,
                                                       second_flow_label_datagram};

    bool batched = internal::sendmmsg_batch(datagrams, "server");
    return all_true({
        !internal::should_apply_ipv6_flow_label(ipv4_peer,
                                                static_cast<socklen_t>(sizeof(sockaddr_in))),
        !internal::should_apply_ipv6_flow_label(peer, 1),
        datagram_sent,
        g_recorded_sendmsg_for_tests.calls == 1,
        g_recorded_sendmsg_for_tests.socket_fd == 29,
        g_recorded_sendmsg_for_tests.family == AF_INET6,
        g_recorded_sendmsg_for_tests.level == 0,
        g_recorded_sendmsg_for_tests.type == 0,
        g_recorded_sendmsg_for_tests.ipv6_flowinfo != 0,
        (g_recorded_sendmsg_for_tests.ipv6_flowinfo & ~0x000fffffu) == 0,
        batched,
        g_send_many_batch_test_trace.sendmsg_calls + g_send_many_batch_test_trace.sendmmsg_calls >
            0,
        g_send_many_batch_test_trace.peer_family == AF_INET6,
        g_send_many_batch_test_trace.ipv6_flowinfo != 0,
        (g_send_many_batch_test_trace.ipv6_flowinfo & ~0x000fffffu) == 0,
    });
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
    auto wait_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto observed_event = wait_event.value_or(QuicIoEngineEvent{});
    auto received_completion = observed_event.rx.value_or(QuicIoEngineRxCompletion{});
    return all_true({
        wait_event.has_value(),
        observed_event.kind == QuicIoEngineEvent::Kind::rx_datagram,
        observed_event.rx.has_value(),
        received_completion.socket_fd == kSockets.front(),
        received_completion.bytes == g_recorded_recvmsg_for_tests.bytes,
        received_completion.ecn == QuicEcnCodepoint::ect0,
        g_retry_readable_poll_for_tests.poll_calls == 2,
        g_retry_readable_poll_for_tests.recvmsg_calls == 2,
    });
}

bool poll_io_engine_restamps_queued_receive_events_for_tests() {
    PollIoEngine engine;
    const auto first_time = QuicCoreTimePoint{} + std::chrono::microseconds{1};
    const auto queued_time = QuicCoreTimePoint{} + std::chrono::microseconds{2};
    auto shared_receive_bytes = std::make_shared<std::vector<std::byte>>(
        std::vector<std::byte>{std::byte{0xaa}, std::byte{0xbb}});

    engine.queue_event(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::rx_datagram,
        .now = first_time,
        .rx =
            QuicIoEngineRxCompletion{
                .socket_fd = 77,
                .bytes = {std::byte{0x01}},
                .now = first_time,
            },
    });
    engine.queue_event(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::rx_datagram,
        .now = queued_time,
        .rx =
            QuicIoEngineRxCompletion{
                .socket_fd = 78,
                .now = queued_time,
                .shared_bytes = shared_receive_bytes,
                .begin = 0,
                .end = shared_receive_bytes->size(),
            },
    });
    engine.queue_event(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::timer_expired,
        .now = queued_time,
    });

    constexpr std::array<int, 1> kSockets = {79};
    auto first_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto second_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto third_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    if (!first_event.has_value() || !second_event.has_value() || !third_event.has_value() ||
        !first_event->rx.has_value() || !second_event->rx.has_value()) {
        return false;
    }

    return all_true({
        first_event->kind == QuicIoEngineEvent::Kind::rx_datagram,
        second_event->kind == QuicIoEngineEvent::Kind::rx_datagram,
        third_event->kind == QuicIoEngineEvent::Kind::timer_expired,
        first_event->now != first_time,
        first_event->rx->now == first_event->now,
        second_event->now != queued_time,
        second_event->rx->now == second_event->now,
        third_event->now == queued_time,
        second_event->rx->shared_bytes == shared_receive_bytes,
    });
}

bool poll_io_engine_compacts_queued_small_receive_storage_for_tests() {
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .poll_fn = &readable_poll_for_tests,
            .recvmmsg_fn = &two_small_recvmmsg_datagrams_for_tests,
        },
    };

    PollIoEngine engine;
    constexpr std::array<int, 1> kSockets = {91};
    auto first_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto second_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    if (!first_event.has_value() || !second_event.has_value() || !first_event->rx.has_value() ||
        !second_event->rx.has_value()) {
        return false;
    }

    const auto first_payload = first_event->rx->payload();
    const auto second_payload = second_event->rx->payload();
    return all_true({
        first_event->kind == QuicIoEngineEvent::Kind::rx_datagram,
        second_event->kind == QuicIoEngineEvent::Kind::rx_datagram,
        first_event->rx->shared_bytes == nullptr,
        first_event->rx->bytes.size() == 2,
        first_payload.size() == 2,
        first_payload[0] == std::byte{0xa0},
        second_event->rx->shared_bytes == nullptr,
        second_event->rx->bytes.size() == 2,
        second_payload.size() == 2,
        second_payload[0] == std::byte{0xa1},
    });
}

bool poll_io_engine_keeps_queued_large_receive_storage_shared_for_tests() {
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .poll_fn = &readable_poll_for_tests,
            .recvmmsg_fn = &two_large_recvmmsg_datagrams_for_tests,
        },
    };

    PollIoEngine engine;
    constexpr std::array<int, 1> kSockets = {92};
    auto first_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto second_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    if (!first_event.has_value() || !second_event.has_value() || !second_event->rx.has_value()) {
        return false;
    }

    const auto second_payload = second_event->rx->payload();
    return all_true({
        second_event->kind == QuicIoEngineEvent::Kind::rx_datagram,
        second_event->rx->shared_bytes != nullptr,
        second_event->rx->bytes.empty(),
        second_payload.size() == kReceiveScratchCopyMaxBytes + 1,
        second_payload[0] == std::byte{0xc1},
        second_payload[second_payload.size() - 1] == std::byte{0xd1},
    });
}

bool poll_io_engine_keeps_queued_gro_receive_storage_shared_for_tests() {
#if defined(__linux__) && defined(UDP_GRO)
    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .poll_fn = &readable_poll_for_tests,
            .recvmmsg_fn = &one_udp_gro_recvmmsg_datagram_for_tests,
        },
    };

    PollIoEngine engine;
    constexpr std::array<int, 1> kSockets = {93};
    auto first_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto second_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto third_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    if (!first_event.has_value() || !second_event.has_value() || !third_event.has_value() ||
        !first_event->rx.has_value() || !second_event->rx.has_value() ||
        !third_event->rx.has_value()) {
        return false;
    }

    auto first_payload = first_event->rx->payload();
    auto second_payload = second_event->rx->payload();
    auto third_rx_payload = third_event->rx->payload();
    return all_true({
        first_event->rx->shared_bytes != nullptr,
        second_event->rx->shared_bytes == first_event->rx->shared_bytes,
        third_event->rx->shared_bytes == first_event->rx->shared_bytes,
        first_payload.size() == 2,
        second_payload.size() == 2,
        third_rx_payload.size() == 2,
        first_payload[0] == std::byte{0xe0},
        second_payload[0] == std::byte{0xe2},
        third_rx_payload[0] == std::byte{0xe4},
    });
#else
    return true;
#endif
}

bool poll_io_engine_ignores_non_pmtu_errqueue_for_tests() {
    g_recorded_recvmsg_for_tests = {};
    g_poll_engine_test_trace = {};
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
    auto wait_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto observed_event = wait_event.value_or(QuicIoEngineEvent{});
    return all_true({
        wait_event.has_value(),
        observed_event.kind == QuicIoEngineEvent::Kind::idle_timeout,
        g_poll_engine_test_trace.ignored_errqueue_poll_calls == 2,
    });
}

bool poll_io_engine_ignores_pmtu_decrease_below_quic_floor_for_tests() {
    g_recorded_recvmsg_for_tests = {};
    g_poll_engine_test_trace = {};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&g_recorded_recvmsg_for_tests.peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(7443);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);
    g_recorded_recvmsg_for_tests.pmtu = 1199;

    const ScopedSocketIoBackendOpsOverride runtime_ops{
        SocketIoBackendOpsOverride{
            .poll_fn = &errqueue_then_timeout_poll_for_tests,
            .recvmsg_fn = &record_recvmsg_for_tests,
        },
    };

    PollIoEngine engine;
    constexpr std::array<int, 1> kSockets = {63};
    auto wait_event = engine.wait(kSockets, /*idle_timeout_ms=*/5, std::nullopt, "server");
    auto observed_event = wait_event.value_or(QuicIoEngineEvent{});
    return all_true({
        wait_event.has_value(),
        observed_event.kind == QuicIoEngineEvent::Kind::idle_timeout,
        g_poll_engine_test_trace.ignored_errqueue_poll_calls == 2,
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

    bool cache_state_ok = initial_state_ok;
    cache_state_ok &= first_registration_ok;
    cache_state_ok &= second_registration_ok;
    return cache_state_ok;
}

} // namespace test

#if defined(__clang__)
#pragma clang attribute pop
#endif

} // namespace coquic::io
