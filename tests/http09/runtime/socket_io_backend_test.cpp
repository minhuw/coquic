#include <gtest/gtest.h>

#include "src/quic/io_backend_test_hooks.h"
#include "src/quic/socket_io_backend.h"
#include "tests/support/core/connection_test_fixtures.h"

namespace {

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

TEST(SocketIoBackendTest, EnsureRouteRejectsIncompatibleSocketFamilyReuse) {
    using namespace coquic::quic;

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
    EXPECT_FALSE(second.has_value());
}

TEST(SocketIoBackendTest, LinuxEcnHooksStayCoveredAfterExtraction) {
    EXPECT_TRUE(
        coquic::quic::test::socket_io_backend_configures_linux_ecn_socket_options_for_tests());
    EXPECT_TRUE(coquic::quic::test::socket_io_backend_sendmsg_uses_outbound_ecn_for_tests());
    EXPECT_TRUE(coquic::quic::test::
                    socket_io_backend_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests());
    EXPECT_TRUE(coquic::quic::test::socket_io_backend_recvmsg_maps_ecn_for_tests());
}

} // namespace
