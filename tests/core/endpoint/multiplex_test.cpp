#include <gtest/gtest.h>

#include <type_traits>
#include <utility>

#include "tests/support/core/endpoint_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

template <typename T, typename = void> struct has_public_path_id_member : std::false_type {};

template <typename T>
struct has_public_path_id_member<T, std::void_t<decltype(std::declval<T>().path_id)>>
    : std::true_type {};

template <typename T>
using route_handle_member_type = std::remove_cvref_t<decltype(std::declval<T>().route_handle)>;

TEST(QuicCoreEndpointTest, ConnectionCommandsOnlyAdvanceTheSelectedHandle) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 22,
        },
        coquic::quic::test::test_time(1)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    *core.connections_.at(2).connection = make_connected_client_connection();
    core.connections_.at(1).route_handle_by_path_id.emplace(0, 11);
    core.connections_.at(1).path_id_by_route_handle.emplace(11, 0);
    core.connections_.at(2).route_handle_by_path_id.emplace(0, 22);
    core.connections_.at(2).path_id_by_route_handle.emplace(22, 0);

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 2,
            .input =
                coquic::quic::QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = bytes_from_ints({0x68, 0x69}),
                    .fin = true,
                },
        },
        coquic::quic::test::test_time(2));

    const auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    for (const auto &send : sends) {
        EXPECT_EQ(send.connection, 2u);
        ASSERT_TRUE(send.route_handle.has_value());
        EXPECT_EQ(send.route_handle.value_or(0), 22u);
    }
    EXPECT_EQ(core.connection_count(), 2u);
}

TEST(QuicCoreEndpointTest, EndpointTimerExpiredWalksAllDueConnections) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));
    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(2),
            .initial_route_handle = 22,
        },
        coquic::quic::test::test_time(0)));

    const auto wakeup = core.next_wakeup();
    ASSERT_TRUE(wakeup.has_value());
    const auto result = core.advance_endpoint(coquic::quic::QuicCoreTimerExpired{},
                                              wakeup.value_or(coquic::quic::test::test_time(0)));

    EXPECT_EQ(core.connection_count(), 2u);
    EXPECT_EQ(result.next_wakeup, core.next_wakeup());
}

TEST(QuicCoreEndpointTest, RouteHandleMigrationCommandTargetsSelectedConnection) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(1),
            .initial_route_handle = 11,
        },
        coquic::quic::test::test_time(0)));

    *core.connections_.at(1).connection = make_connected_client_connection();
    EXPECT_FALSE(
        has_public_path_id_member<coquic::quic::QuicCoreRequestConnectionMigration>::value);
    EXPECT_TRUE(
        (std::is_same_v<route_handle_member_type<coquic::quic::QuicCoreRequestConnectionMigration>,
                        coquic::quic::QuicRouteHandle>));

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreRequestConnectionMigration{
                    .route_handle = 29,
                    .reason = coquic::quic::QuicMigrationRequestReason::active,
                },
        },
        coquic::quic::test::test_time(1));

    EXPECT_FALSE(result.local_error.has_value());
}
} // namespace
