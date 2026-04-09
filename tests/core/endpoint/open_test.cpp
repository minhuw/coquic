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

TEST(QuicCoreEndpointTest, ClientOpenSendEffectDoesNotExposePublicPathId) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));

    EXPECT_FALSE(has_public_path_id_member<coquic::quic::QuicCoreInboundDatagram>::value);
    EXPECT_FALSE(has_public_path_id_member<coquic::quic::QuicCoreSendDatagram>::value);

    const auto sends = send_effects_from(result);
    ASSERT_FALSE(sends.empty());
    EXPECT_EQ(sends.front().route_handle, std::optional<coquic::quic::QuicRouteHandle>{17u});
}

TEST(QuicCoreEndpointTest, EndpointCommandUsesConnectionHandleWithoutLegacyFallback) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                coquic::quic::QuicCoreSendStreamData{
                    .stream_id = 0,
                    .bytes = coquic::quic::test::bytes_from_string("hello"),
                    .fin = false,
                },
        },
        coquic::quic::test::test_time(1));

    const auto local_error = result.local_error.value_or(coquic::quic::QuicCoreLocalError{
        .connection = 1,
        .code = coquic::quic::QuicCoreLocalErrorCode::invalid_stream_id,
        .stream_id = std::nullopt,
    });

    EXPECT_TRUE(result.local_error.has_value());
    EXPECT_EQ(local_error.connection, std::optional<coquic::quic::QuicConnectionHandle>{1u});
    EXPECT_EQ(local_error.code, coquic::quic::QuicCoreLocalErrorCode::invalid_stream_id);
    EXPECT_EQ(result.next_wakeup, core.next_wakeup());
    EXPECT_TRUE(core.active_local_connection_ids().empty());
    EXPECT_FALSE(core.is_handshake_complete());
    EXPECT_FALSE(core.has_failed());
}

TEST(QuicCoreEndpointTest, EndpointConstructedCoreRejectsLegacyAdvance) {
    coquic::quic::QuicCore core(make_client_endpoint_config());

    static_cast<void>(core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    const auto result =
        core.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(1));
    const auto local_error = result.local_error.value_or(coquic::quic::QuicCoreLocalError{
        .connection = std::nullopt,
        .code = coquic::quic::QuicCoreLocalErrorCode::invalid_stream_id,
        .stream_id = std::nullopt,
    });

    EXPECT_TRUE(result.local_error.has_value());
    EXPECT_EQ(local_error.connection, std::nullopt);
    EXPECT_EQ(local_error.code, coquic::quic::QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_EQ(result.next_wakeup, core.next_wakeup());
}

TEST(QuicCoreEndpointTest, ServerEndpointRejectsClientOpenConnection) {
    coquic::quic::QuicCore core(make_server_endpoint_config());

    const auto result = core.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));
    const auto local_error = result.local_error.value_or(coquic::quic::QuicCoreLocalError{
        .connection = std::nullopt,
        .code = coquic::quic::QuicCoreLocalErrorCode::invalid_stream_id,
        .stream_id = std::nullopt,
    });

    EXPECT_TRUE(result.local_error.has_value());
    EXPECT_EQ(local_error.connection, std::nullopt);
    EXPECT_EQ(local_error.code, coquic::quic::QuicCoreLocalErrorCode::unsupported_operation);
    EXPECT_TRUE(lifecycle_events_from(result).empty());
    EXPECT_TRUE(send_effects_from(result).empty());
    EXPECT_EQ(core.connection_count(), 0u);
}
} // namespace
