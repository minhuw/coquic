#include <gtest/gtest.h>

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

} // namespace
