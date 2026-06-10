#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::http09::test_support;

TEST(QuicHttp09RuntimeTest, PreferredAddressCidRoutesToExistingServerSession) {
    EXPECT_TRUE(
        coquic::http09::test::preferred_address_routes_to_existing_server_session_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeQueuesPreferredAddressMigrationRequestAfterHandshakeConfirmed) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.1
    // # Once the handshake is confirmed, the client SHOULD select one of the
    // # two addresses provided by the server and initiate path validation
    // # (see Section 8.2).
    EXPECT_TRUE(coquic::http09::test::runtime_backend_preferred_address_request_flow_for_tests());
}

TEST(QuicHttp09RuntimeTest, CrossFamilyPreferredAddressRequestsIpv6BackendRoute) {
    EXPECT_TRUE(
        coquic::http09::test::
            runtime_backend_cross_family_preferred_address_requests_backend_route_for_tests());
}

TEST(QuicHttp09RuntimeTest, ClientLoopRequestsPreferredAddressRouteFromBackend) {
    EXPECT_TRUE(coquic::http09::test::
                    runtime_client_loop_requests_preferred_address_route_from_backend_for_tests());
}

TEST(QuicHttp09RuntimeTest, PreferredAddressRouteCreationFailureStopsMigrationRequest) {
    EXPECT_TRUE(
        coquic::http09::test::
            runtime_backend_preferred_address_route_failure_stops_migration_request_for_tests());
}

TEST(QuicHttp09RuntimeTest, RegularTransferDoesNotQueuePreferredAddressMigration) {
    EXPECT_TRUE(
        coquic::http09::test::
            runtime_backend_regular_transfer_does_not_queue_preferred_address_migration_for_tests());
}

} // namespace
