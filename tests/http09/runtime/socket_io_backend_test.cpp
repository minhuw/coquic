#include <gtest/gtest.h>

#include "src/quic/io_backend_test_hooks.h"
#include "src/quic/socket_io_backend.h"
#include "tests/support/core/connection_test_fixtures.h"

namespace {

struct MultiSocketBackendTestTrace {
    std::vector<int> opened_families;
    std::vector<int> opened_fds;
    nfds_t last_poll_descriptor_count = 0;
    int last_send_socket_fd = -1;
    int readable_socket_fd = -1;
};

thread_local MultiSocketBackendTestTrace g_multi_socket_backend_test_trace;

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

void reset_multi_socket_backend_test_trace() {
    g_multi_socket_backend_test_trace = {};
}

TEST(SocketIoBackendTest, PublicShellTypesCompileAndConstruct) {
    using namespace coquic::quic;

    QuicIoRemote remote{};
    remote.family = AF_INET;

    QuicIoRxDatagram rx{
        .route_handle = 7,
        .bytes = {std::byte{0x01}},
    };
    QuicIoEvent event{
        .kind = QuicIoEvent::Kind::rx_datagram,
        .now = coquic::quic::test::test_time(0),
        .datagram = rx,
    };

    EXPECT_TRUE(event.datagram.has_value());
    EXPECT_EQ(event.datagram->route_handle, 7u);

    auto backend = coquic::quic::make_socket_io_backend(coquic::quic::SocketIoBackendConfig{
        .role_name = "client",
        .idle_timeout_ms = 5,
    });
    ASSERT_NE(backend, nullptr);
    EXPECT_FALSE(backend->ensure_route(remote).has_value());
    EXPECT_FALSE(backend->wait(std::nullopt).has_value());
    EXPECT_FALSE(backend->send(QuicIoTxDatagram{
        .route_handle = 7,
        .bytes = {std::byte{0x02}},
    }));
}

TEST(SocketIoBackendTest, RouteHandlesStayStablePerPeerTuple) {
    EXPECT_TRUE(
        coquic::quic::test::socket_io_backend_route_handles_are_stable_per_peer_tuple_for_tests());
}

TEST(SocketIoBackendTest, SendUsesRouteHandleRouting) {
    EXPECT_TRUE(coquic::quic::test::socket_io_backend_send_uses_route_handle_for_tests());
}

TEST(SocketIoBackendTest, EnsureRouteOpensAdditionalSocketForIncompatibleFamily) {
    using namespace coquic::quic;

    reset_multi_socket_backend_test_trace();
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        coquic::quic::test::SocketIoBackendOpsOverride{
            .socket_fn = &record_socket_family_and_open,
            .sendto_fn = &record_sendto_socket_fd_for_backend_tests,
        },
    };

    SocketIoBackend backend(SocketIoBackendConfig{
        .role_name = "server",
    });

    sockaddr_storage ipv4_peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&ipv4_peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4433);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sockaddr_storage ipv6_peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&ipv6_peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(4434);
    ipv6.sin6_addr = in6addr_loopback;

    const auto first = backend.ensure_route(QuicIoRemote{
        .peer = ipv4_peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });
    ASSERT_TRUE(first.has_value());

    const auto second = backend.ensure_route(QuicIoRemote{
        .peer = ipv6_peer,
        .peer_len = sizeof(sockaddr_in6),
        .family = AF_INET6,
    });
    ASSERT_TRUE(second.has_value());
    const auto first_handle = coquic::quic::test_support::optional_value_or_terminate(first);
    const auto second_handle = coquic::quic::test_support::optional_value_or_terminate(second);
    EXPECT_NE(first_handle, second_handle);

    EXPECT_TRUE(backend.send(QuicIoTxDatagram{
        .route_handle = first_handle,
        .bytes = {std::byte{0x01}},
    }));
    const int first_socket_fd = g_multi_socket_backend_test_trace.last_send_socket_fd;
    ASSERT_GE(first_socket_fd, 0);

    EXPECT_TRUE(backend.send(QuicIoTxDatagram{
        .route_handle = second_handle,
        .bytes = {std::byte{0x02}},
    }));
    EXPECT_NE(g_multi_socket_backend_test_trace.last_send_socket_fd, first_socket_fd);
    EXPECT_EQ(g_multi_socket_backend_test_trace.opened_families,
              (std::vector<int>{AF_INET, AF_INET6}));
}

TEST(SocketIoBackendTest, WaitPollsAllActiveRouteSocketsAndReturnsSecondRouteDatagram) {
    using namespace coquic::quic;

    reset_multi_socket_backend_test_trace();
    const coquic::quic::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        coquic::quic::test::SocketIoBackendOpsOverride{
            .socket_fn = &record_socket_family_and_open,
            .poll_fn = &record_poll_descriptor_count_and_second_readable,
            .recvmsg_fn = &recvmsg_for_backend_tests,
        },
    };

    SocketIoBackend backend(SocketIoBackendConfig{
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
    ASSERT_TRUE(first.has_value());

    const auto second = backend.ensure_route(QuicIoRemote{
        .peer = second_peer,
        .peer_len = sizeof(sockaddr_in6),
        .family = AF_INET6,
    });
    ASSERT_TRUE(second.has_value());
    const auto second_handle = coquic::quic::test_support::optional_value_or_terminate(second);

    ASSERT_GE(g_multi_socket_backend_test_trace.opened_fds.size(), 2u);
    g_multi_socket_backend_test_trace.readable_socket_fd =
        g_multi_socket_backend_test_trace.opened_fds[1];

    const auto event = backend.wait(std::nullopt);
    ASSERT_TRUE(event.has_value());
    const auto &event_value = coquic::quic::test_support::optional_ref_or_terminate(event);
    EXPECT_EQ(event_value.kind, QuicIoEvent::Kind::rx_datagram);
    ASSERT_TRUE(event_value.datagram.has_value());
    const auto &datagram =
        coquic::quic::test_support::optional_ref_or_terminate(event_value.datagram);
    EXPECT_EQ(datagram.route_handle, second_handle);
    EXPECT_EQ(g_multi_socket_backend_test_trace.last_poll_descriptor_count, 2u);
}

TEST(SocketIoBackendTest, ConfiguresLinuxSocketsForReceivingEcnMetadata) {
    EXPECT_TRUE(
        coquic::quic::test::socket_io_backend_configures_linux_ecn_socket_options_for_tests());
}

TEST(SocketIoBackendTest, UsesSendmsgToApplyOutboundEcnMarkings) {
    EXPECT_TRUE(coquic::quic::test::socket_io_backend_sendmsg_uses_outbound_ecn_for_tests());
}

TEST(SocketIoBackendTest, UsesIpTosForIpv4MappedIpv6OutboundEcnMarkings) {
    EXPECT_TRUE(coquic::quic::test::
                    socket_io_backend_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests());
}

TEST(SocketIoBackendTest, MapsRecvmsgEcnMetadataIntoEvents) {
    EXPECT_TRUE(coquic::quic::test::socket_io_backend_recvmsg_maps_ecn_for_tests());
}

} // namespace
