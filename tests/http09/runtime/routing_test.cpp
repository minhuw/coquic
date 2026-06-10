#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::http09::test_support;

TEST(QuicHttp09RuntimeTest, RuntimeAssignsStablePathIdsPerPeerTuple) {
    EXPECT_TRUE(coquic::http09::test::runtime_assigns_stable_path_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, DriveEndpointUsesTransportSelectedPathAndSocket) {
    EXPECT_TRUE(coquic::http09::test::drive_endpoint_uses_transport_selected_path_for_tests());
}

TEST(QuicHttp09RuntimeTest, DeferredReplayPreservesIndividualBufferedPathIds) {
    coquic::quic::QuicConnection connection(coquic::quic::QuicCoreConfig{
        .role = coquic::quic::EndpointRole::client,
        .source_connection_id = {std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x02}},
    });
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto first_deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
    };
    const auto second_deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
    };
    connection.process_inbound_datagram(first_deferred, coquic::quic::test::test_time(1),
                                        /*path_id=*/11);
    connection.process_inbound_datagram(second_deferred, coquic::quic::test::test_time(2),
                                        /*path_id=*/22);
    ASSERT_GE(connection.deferred_protected_packets_.size(), 2u);
    ASSERT_TRUE(connection.deferred_protected_packets_[0].received_at.has_value());
    ASSERT_TRUE(connection.deferred_protected_packets_[1].received_at.has_value());
    EXPECT_EQ(connection.deferred_protected_packets_[0].received_at.value(),
              coquic::quic::test::test_time(1));
    EXPECT_EQ(connection.deferred_protected_packets_[1].received_at.value(),
              coquic::quic::test::test_time(2));

    connection.current_send_path_id_.reset();
    connection.replay_deferred_protected_packets(coquic::quic::test::test_time(3));

    ASSERT_TRUE(connection.current_send_path_id_.has_value());
    EXPECT_EQ(connection.current_send_path_id_.value_or(0), 11u);
}

TEST(QuicHttp09RuntimeTest, DeferredReplayKeepsDistinctPathsForIdenticalPayloads) {
    coquic::quic::QuicConnection connection(coquic::quic::QuicCoreConfig{
        .role = coquic::quic::EndpointRole::client,
        .source_connection_id = {std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x02}},
    });
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x0a}, std::byte{0x0b}, std::byte{0x0c}, std::byte{0x0d},
    };
    connection.process_inbound_datagram(deferred, coquic::quic::test::test_time(1), /*path_id=*/11);
    connection.process_inbound_datagram(deferred, coquic::quic::test::test_time(2), /*path_id=*/22);

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 2u);
    EXPECT_EQ(connection.deferred_protected_packets_[0].bytes, deferred);
    EXPECT_EQ(connection.deferred_protected_packets_[0].path_id, 11u);
    EXPECT_EQ(connection.deferred_protected_packets_[1].bytes, deferred);
    EXPECT_EQ(connection.deferred_protected_packets_[1].path_id, 22u);
}

TEST(QuicHttp09RuntimeTest, RuntimeProcessesPolicyInputsBeforeTerminalSuccess) {
    EXPECT_TRUE(coquic::http09::test::
                    runtime_policy_core_inputs_advance_before_terminal_success_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeRegistersAllServerCoreConnectionIdsForRouting) {
    EXPECT_TRUE(coquic::http09::test::runtime_registers_all_server_core_connection_ids_for_tests());
}

} // namespace
