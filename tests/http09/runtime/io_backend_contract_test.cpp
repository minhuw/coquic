#include <gtest/gtest.h>

#include "src/io/io_backend_test_hooks.h"

namespace {

class QuicIoBackendContractTest : public ::testing::TestWithParam<coquic::io::QuicIoBackendKind> {};

TEST_P(QuicIoBackendContractTest, RouteHandlesStayStablePerPeerTuple) {
    EXPECT_TRUE(coquic::io::test::io_backend_route_handles_are_stable_for_tests(GetParam()));
}

TEST_P(QuicIoBackendContractTest, SendUsesRouteHandleRouting) {
    EXPECT_TRUE(coquic::io::test::io_backend_send_uses_route_handle_for_tests(GetParam()));
}

TEST_P(QuicIoBackendContractTest, WaitReturnsDatagramFromSecondRoute) {
    EXPECT_TRUE(
        coquic::io::test::io_backend_wait_returns_second_route_datagram_for_tests(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(SocketOnly, QuicIoBackendContractTest,
                         ::testing::Values(coquic::io::QuicIoBackendKind::socket));

} // namespace
