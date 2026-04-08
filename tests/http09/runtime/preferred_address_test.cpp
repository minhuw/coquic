#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::quic::test_support;

TEST(QuicHttp09RuntimeTest, PreferredAddressCidRoutesToExistingServerSession) {
    EXPECT_TRUE(
        coquic::quic::test::preferred_address_routes_to_existing_server_session_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeQueuesPreferredAddressMigrationRequestAfterHandshakeConfirmed) {
    EXPECT_TRUE(coquic::quic::test::runtime_connectionmigration_request_flow_for_tests());
}

TEST(QuicHttp09RuntimeTest,
     OfficialConnectionMigrationClientRequestQueuesPreferredAddressMigration) {
    EXPECT_TRUE(
        coquic::quic::test::runtime_official_connectionmigration_client_request_flow_for_tests());
}

TEST(QuicHttp09RuntimeTest, CrossFamilyPreferredAddressUsesCompatibleSocket) {
    EXPECT_TRUE(coquic::quic::test::
                    runtime_cross_family_preferred_address_uses_compatible_socket_for_tests());
}

TEST(QuicHttp09RuntimeTest, ClientLoopUsesAllActiveSocketsForPreferredAddress) {
    EXPECT_TRUE(coquic::quic::test::runtime_client_loop_uses_all_active_sockets_for_tests());
}

TEST(QuicHttp09RuntimeTest, RegularTransferDoesNotQueuePreferredAddressMigration) {
    EXPECT_TRUE(
        coquic::quic::test::
            runtime_regular_transfer_does_not_queue_preferred_address_migration_for_tests());
}

} // namespace
