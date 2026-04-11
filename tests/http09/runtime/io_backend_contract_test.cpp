#include <gtest/gtest.h>

#include "src/io/io_backend_test_hooks.h"

namespace {

class QuicIoBackendContractTest : public ::testing::TestWithParam<coquic::io::QuicIoBackendKind> {};

bool backend_route_handles_are_stable_for_tests(coquic::io::QuicIoBackendKind kind) {
    switch (kind) {
    case coquic::io::QuicIoBackendKind::socket:
        return coquic::io::test::
            socket_io_backend_route_handles_are_stable_per_peer_tuple_for_tests();
    case coquic::io::QuicIoBackendKind::io_uring:
        return coquic::io::test::
            io_uring_backend_route_handles_are_stable_per_peer_tuple_for_tests();
    }
    return false;
}

bool backend_send_uses_route_handle_for_tests(coquic::io::QuicIoBackendKind kind) {
    switch (kind) {
    case coquic::io::QuicIoBackendKind::socket:
        return coquic::io::test::socket_io_backend_send_uses_route_handle_for_tests();
    case coquic::io::QuicIoBackendKind::io_uring:
        return coquic::io::test::io_uring_backend_send_uses_route_handle_for_tests();
    }
    return false;
}

bool backend_wait_returns_second_route_datagram_for_tests(coquic::io::QuicIoBackendKind kind) {
    switch (kind) {
    case coquic::io::QuicIoBackendKind::socket:
        return coquic::io::test::socket_io_backend_wait_returns_second_route_datagram_for_tests();
    case coquic::io::QuicIoBackendKind::io_uring:
        return coquic::io::test::io_uring_backend_wait_returns_second_route_datagram_for_tests();
    }
    return false;
}

TEST_P(QuicIoBackendContractTest, RouteHandlesStayStablePerPeerTuple) {
    EXPECT_TRUE(backend_route_handles_are_stable_for_tests(GetParam()));
}

TEST_P(QuicIoBackendContractTest, SendUsesRouteHandleRouting) {
    EXPECT_TRUE(backend_send_uses_route_handle_for_tests(GetParam()));
}

TEST_P(QuicIoBackendContractTest, WaitReturnsDatagramFromSecondRoute) {
    EXPECT_TRUE(backend_wait_returns_second_route_datagram_for_tests(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(SocketAndIoUring, QuicIoBackendContractTest,
                         ::testing::Values(coquic::io::QuicIoBackendKind::socket,
                                           coquic::io::QuicIoBackendKind::io_uring));

} // namespace
