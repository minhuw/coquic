#include <gtest/gtest.h>

#include "src/io/io_backend_factory.h"

namespace {

TEST(QuicIoBackendFactoryTest, SocketClientBootstrapCreatesPrimaryRoute) {
    const auto bootstrap = coquic::io::bootstrap_client_io_backend(
        coquic::io::QuicIoBackendBootstrapConfig{
            .kind = coquic::io::QuicIoBackendKind::socket,
            .backend =
                coquic::io::QuicUdpBackendConfig{
                    .role_name = "client",
                    .idle_timeout_ms = 5,
                },
        },
        "127.0.0.1", 4433);
    ASSERT_TRUE(bootstrap.has_value());
    if (!bootstrap.has_value()) {
        return;
    }
    const auto &bootstrap_value = bootstrap.value();
    EXPECT_NE(bootstrap_value.backend, nullptr);
    EXPECT_NE(bootstrap_value.primary_route_handle, 0u);
}

TEST(QuicIoBackendFactoryTest, IoUringClientBootstrapFailsFastWhenUnavailable) {
    const auto bootstrap = coquic::io::bootstrap_client_io_backend(
        coquic::io::QuicIoBackendBootstrapConfig{
            .kind = coquic::io::QuicIoBackendKind::io_uring,
            .backend =
                coquic::io::QuicUdpBackendConfig{
                    .role_name = "client",
                    .idle_timeout_ms = 5,
                },
        },
        "127.0.0.1", 4433);
    EXPECT_FALSE(bootstrap.has_value());
}

} // namespace
