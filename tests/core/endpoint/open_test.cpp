#include <gtest/gtest.h>

#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicCoreEndpointTest, ClientOpenCreatesStableHandleAndTagsInitialSendRoute) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));

    const auto lifecycle = lifecycle_events_from(result);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().connection, 1u);
    EXPECT_EQ(lifecycle.front().event, coquic::quic::QuicCoreConnectionLifecycle::created);

    const auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    EXPECT_EQ(sends.front().connection, 1u);
    EXPECT_EQ(sends.front().route_handle, std::optional<coquic::quic::QuicRouteHandle>{17u});

    ASSERT_TRUE(core.next_wakeup().has_value());
    EXPECT_EQ(core.connection_count(), 1u);
}
} // namespace
