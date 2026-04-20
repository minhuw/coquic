#include <gtest/gtest.h>

#include <array>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#include "tests/support/core/endpoint_test_fixtures.h"
#include "src/quic/core_test_hooks.h"

namespace {
using namespace coquic::quic;
using namespace coquic::quic::test_support;

std::vector<std::byte> make_client_initial_datagram() {
    auto client_config = make_client_endpoint_config();
    client_config.application_protocol = "coquic";

    QuicCore client(std::move(client_config));
    const auto opened = client.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));
    const auto sends = send_effects_from(opened);
    EXPECT_FALSE(sends.empty());
    if (sends.empty()) {
        return {};
    }
    return sends.front().bytes;
}

std::vector<std::byte> make_plaintext_initial_datagram_with_token(std::vector<std::byte> token) {
    const auto encoded = serialize_packet(InitialPacket{
        .version = kQuicVersion1,
        .destination_connection_id =
            bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        .source_connection_id = bytes_from_ints({0xc1, 0x01}),
        .token = std::move(token),
        .packet_number_length = 1,
        .truncated_packet_number = 1,
        .frames = {PaddingFrame{}},
    });
    EXPECT_TRUE(encoded.has_value());
    return encoded.has_value() ? encoded.value() : std::vector<std::byte>{};
}

std::vector<std::byte> make_supported_long_header_datagram(
    std::uint32_t version, std::vector<std::byte> destination_connection_id,
    std::vector<std::byte> source_connection_id, std::size_t minimum_size = 1200) {
    std::vector<std::byte> bytes;
    bytes.reserve(minimum_size);
    bytes.push_back(std::byte{0xe0});
    bytes.push_back(static_cast<std::byte>((version >> 24) & 0xffu));
    bytes.push_back(static_cast<std::byte>((version >> 16) & 0xffu));
    bytes.push_back(static_cast<std::byte>((version >> 8) & 0xffu));
    bytes.push_back(static_cast<std::byte>(version & 0xffu));
    bytes.push_back(static_cast<std::byte>(destination_connection_id.size()));
    bytes.insert(bytes.end(), destination_connection_id.begin(), destination_connection_id.end());
    bytes.push_back(static_cast<std::byte>(source_connection_id.size()));
    bytes.insert(bytes.end(), source_connection_id.begin(), source_connection_id.end());
    if (bytes.size() < minimum_size) {
        bytes.resize(minimum_size, std::byte{0x00});
    }
    return bytes;
}

std::vector<std::byte>
make_supported_initial_datagram(std::uint32_t version,
                                std::vector<std::byte> destination_connection_id,
                                std::vector<std::byte> source_connection_id,
                                std::vector<std::byte> token, std::size_t minimum_size = 1200) {
    std::vector<std::byte> bytes;
    bytes.reserve(minimum_size);
    bytes.push_back(std::byte{0xc0});
    bytes.push_back(static_cast<std::byte>((version >> 24) & 0xffu));
    bytes.push_back(static_cast<std::byte>((version >> 16) & 0xffu));
    bytes.push_back(static_cast<std::byte>((version >> 8) & 0xffu));
    bytes.push_back(static_cast<std::byte>(version & 0xffu));
    bytes.push_back(static_cast<std::byte>(destination_connection_id.size()));
    bytes.insert(bytes.end(), destination_connection_id.begin(), destination_connection_id.end());
    bytes.push_back(static_cast<std::byte>(source_connection_id.size()));
    bytes.insert(bytes.end(), source_connection_id.begin(), source_connection_id.end());
    EXPECT_LT(token.size(), 64u);
    bytes.push_back(static_cast<std::byte>(token.size()));
    bytes.insert(bytes.end(), token.begin(), token.end());
    if (bytes.size() < minimum_size) {
        bytes.resize(minimum_size, std::byte{0x00});
    }
    return bytes;
}

// NOLINTBEGIN(clang-analyzer-cplusplus.NewDeleteLeaks)
QuicCore::ConnectionEntry make_server_connection_entry(
    QuicConnectionHandle handle,
    std::optional<std::string> initial_destination_connection_id_key = std::nullopt) {
    return QuicCore::ConnectionEntry{
        .handle = handle,
        .connection =
            std::make_unique<QuicConnection>(coquic::quic::test::make_server_core_config()),
        .initial_destination_connection_id_key = std::move(initial_destination_connection_id_key),
    };
}
// NOLINTEND(clang-analyzer-cplusplus.NewDeleteLeaks)

TEST(QuicCoreEndpointInternalTest, LegacyViewAndLegacyEntryHelpersHandleNullAndMissingCases) {
    QuicCore::LegacyConnectionView detached;
    EXPECT_EQ(detached.get(), nullptr);
    EXPECT_FALSE(static_cast<bool>(detached));
    EXPECT_TRUE(detached == nullptr);
    EXPECT_FALSE(detached != nullptr);

    QuicCore endpoint_core(make_client_endpoint_config());
    EXPECT_EQ(endpoint_core.ensure_legacy_entry(), nullptr);
    endpoint_core.set_legacy_connection(nullptr);
    ASSERT_TRUE(endpoint_core.legacy_connection_handle_.has_value());
    EXPECT_TRUE(endpoint_core.connections_.empty());

    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    if (!legacy_core.legacy_connection_handle_.has_value()) {
        FAIL() << "expected legacy connection handle";
        return;
    }
    const auto legacy_handle = *legacy_core.legacy_connection_handle_;
    legacy_core.connections_.erase(legacy_handle);

    const QuicCore &const_core = legacy_core;
    EXPECT_EQ(legacy_core.legacy_entry(), nullptr);
    EXPECT_EQ(const_core.legacy_entry(), nullptr);
    EXPECT_EQ(legacy_core.connection_.get(), nullptr);
    EXPECT_FALSE(static_cast<bool>(legacy_core.connection_));
    EXPECT_TRUE(legacy_core.connection_ == nullptr);
    EXPECT_FALSE(legacy_core.connection_ != nullptr);
}

TEST(QuicCoreEndpointInternalTest, ParseEndpointDatagramRejectsMalformedInputs) {
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(std::span<const std::byte>{}).has_value());

    const auto invalid_short_header = bytes_from_ints({0x00});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(invalid_short_header).has_value());

    const auto too_short_short_header = bytes_from_ints({0x40, 0, 1, 2});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(too_short_short_header).has_value());

    const auto version_negotiation =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0x00});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(version_negotiation).has_value());

    const auto truncated_destination_connection_id = bytes_from_ints(
        {0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10});
    EXPECT_FALSE(
        QuicCore::parse_endpoint_datagram(truncated_destination_connection_id).has_value());

    const auto truncated_source_connection_id =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xaa, 0x08, 0xbb});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(truncated_source_connection_id).has_value());

    const auto truncated_initial_token_varint =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xaa, 0x01, 0xbb, 0x40});
    EXPECT_FALSE(QuicCore::parse_endpoint_datagram(truncated_initial_token_varint).has_value());

    const auto initial_token_length_exceeds_remaining =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0xaa, 0x01, 0xbb, 0x05});
    EXPECT_FALSE(
        QuicCore::parse_endpoint_datagram(initial_token_length_exceeds_remaining).has_value());
}

TEST(QuicCoreEndpointInternalTest, RetryContextAndPacketBuildersRejectMissingOrMismatchedInputs) {
    QuicCore core(make_server_endpoint_config());

    QuicCore::PendingRetryToken pending{
        .original_destination_connection_id = ConnectionId{std::byte{0x83}, std::byte{0x44}},
        .retry_source_connection_id = ConnectionId{std::byte{0x53}, std::byte{0x01}},
        .original_version = kQuicVersion1,
        .token = bytes_from_ints({0x72, 0x74, 0x72, 0x79}),
        .route_handle = 7,
    };
    core.retry_tokens_.insert_or_assign(QuicCore::connection_id_key(pending.token), pending);

    QuicCore::ParsedEndpointDatagram parsed{
        .kind = QuicCore::ParsedEndpointDatagram::Kind::supported_initial,
        .destination_connection_id = pending.retry_source_connection_id,
        .source_connection_id = ConnectionId{std::byte{0xc1}, std::byte{0x01}},
        .version = pending.original_version,
        .token = pending.token,
    };

    EXPECT_FALSE(core.take_retry_context(parsed, 9).has_value());
    EXPECT_TRUE(core.retry_tokens_.contains(QuicCore::connection_id_key(pending.token)));

    auto no_source = parsed;
    no_source.source_connection_id.reset();
    constexpr std::array<std::uint32_t, 1> supported_versions = {kQuicVersion1};
    EXPECT_TRUE(
        QuicCore::make_version_negotiation_packet_bytes(no_source, supported_versions).empty());
    EXPECT_TRUE(QuicCore::make_retry_packet_bytes(no_source, pending).empty());

    constexpr std::array<std::uint32_t, 0> no_supported_versions = {};
    EXPECT_TRUE(
        QuicCore::make_version_negotiation_packet_bytes(parsed, no_supported_versions).empty());

    auto unsupported_retry = parsed;
    unsupported_retry.version = kVersionNegotiationVersion;
    EXPECT_TRUE(QuicCore::make_retry_packet_bytes(unsupported_retry, pending).empty());
}

TEST(QuicCoreEndpointInternalTest, RouteRefreshRememberPathAndLegacySeedingCoverCollisionPaths) {
    QuicCore server_core(make_server_endpoint_config());

    auto route_entry = make_server_connection_entry(9);
    route_entry.connection->local_connection_ids_.clear();
    route_entry.connection->local_connection_ids_.emplace(0, LocalConnectionIdRecord{
                                                                 .sequence_number = 0,
                                                                 .connection_id = {},
                                                                 .retired = false,
                                                             });
    route_entry.connection->local_connection_ids_.emplace(
        1, LocalConnectionIdRecord{
               .sequence_number = 1,
               .connection_id = ConnectionId{std::byte{0x44}},
               .retired = false,
           });
    route_entry.active_connection_id_keys = {"stale"};
    server_core.connection_id_routes_.emplace("stale", route_entry.handle);
    route_entry.initial_destination_connection_id_key = "old";
    server_core.initial_destination_routes_.emplace("old", route_entry.handle);
    route_entry.connection->client_initial_destination_connection_id_.reset();

    server_core.refresh_server_connection_routes(route_entry);
    route_entry.connection.reset();

    const auto live_key = QuicCore::connection_id_key(ConnectionId{std::byte{0x44}});
    EXPECT_FALSE(server_core.connection_id_routes_.contains("stale"));
    EXPECT_EQ(server_core.connection_id_routes_.at(live_key), route_entry.handle);
    EXPECT_EQ(route_entry.active_connection_id_keys.size(), 1u);
    EXPECT_EQ(route_entry.active_connection_id_keys.front(), live_key);
    EXPECT_FALSE(route_entry.initial_destination_connection_id_key.has_value());
    EXPECT_FALSE(server_core.initial_destination_routes_.contains("old"));

    QuicCore::ConnectionEntry path_entry{};
    path_entry.route_handle_by_path_id.emplace(0, 11);
    path_entry.path_id_by_route_handle.emplace(11, 0);
    path_entry.route_handle_by_path_id.emplace(1, 12);
    path_entry.path_id_by_route_handle.emplace(12, 1);
    path_entry.next_path_id = 1;
    EXPECT_EQ(server_core.remember_inbound_path(path_entry, 13), 2u);

    QuicCore endpoint_core(make_client_endpoint_config());
    EXPECT_FALSE(coquic::quic::test::seed_legacy_route_handle_path_for_tests(endpoint_core, 7, 0));

    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    EXPECT_FALSE(coquic::quic::test::seed_legacy_route_handle_path_for_tests(
        legacy_core, 1, std::numeric_limits<QuicPathId>::max()));
    ASSERT_TRUE(coquic::quic::test::seed_legacy_route_handle_path_for_tests(legacy_core, 11, 1));
    ASSERT_TRUE(coquic::quic::test::seed_legacy_route_handle_path_for_tests(legacy_core, 22, 2));

    auto *legacy_entry = legacy_core.ensure_legacy_entry();
    ASSERT_NE(legacy_entry, nullptr);
    legacy_entry->default_route_handle = 22;
    ASSERT_TRUE(coquic::quic::test::seed_legacy_route_handle_path_for_tests(legacy_core, 11, 2));
    EXPECT_FALSE(legacy_entry->path_id_by_route_handle.contains(22));
    EXPECT_FALSE(legacy_entry->route_handle_by_path_id.contains(1));
    EXPECT_EQ(legacy_entry->default_route_handle, std::optional<QuicRouteHandle>{11u});
    EXPECT_EQ(legacy_entry->path_id_by_route_handle.at(11), 2u);
    EXPECT_EQ(legacy_entry->route_handle_by_path_id.at(2), 11u);
}

TEST(QuicCoreEndpointInternalTest, ConnectionCommandDrainsPendingEndpointEffects) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    entry.connection->pending_peer_reset_effects_.push_back(QuicCorePeerResetStream{
        .stream_id = 9,
        .application_error_code = 21,
        .final_size = 34,
    });
    entry.connection->pending_peer_stop_effects_.push_back(QuicCorePeerStopSending{
        .stream_id = 11,
        .application_error_code = 22,
    });
    entry.connection->pending_preferred_address_effect_ = QuicCorePeerPreferredAddressAvailable{
        .preferred_address = make_test_preferred_address(),
    };
    entry.connection->pending_zero_rtt_status_event_ = QuicCoreZeroRttStatusEvent{
        .status = QuicZeroRttStatus::accepted,
    };

    const auto result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input = QuicCoreRequestKeyUpdate{},
        },
        coquic::quic::test::test_time(1));

    bool saw_reset = false;
    bool saw_stop = false;
    bool saw_preferred = false;
    bool saw_zero_rtt = false;
    for (const auto &effect : result.effects) {
        if (const auto *reset = std::get_if<QuicCorePeerResetStream>(&effect)) {
            saw_reset = true;
            EXPECT_EQ(reset->connection, 1u);
            EXPECT_EQ(reset->stream_id, 9u);
            EXPECT_EQ(reset->application_error_code, 21u);
            EXPECT_EQ(reset->final_size, 34u);
            continue;
        }
        if (const auto *stop = std::get_if<QuicCorePeerStopSending>(&effect)) {
            saw_stop = true;
            EXPECT_EQ(stop->connection, 1u);
            EXPECT_EQ(stop->stream_id, 11u);
            EXPECT_EQ(stop->application_error_code, 22u);
            continue;
        }
        if (const auto *preferred = std::get_if<QuicCorePeerPreferredAddressAvailable>(&effect)) {
            saw_preferred = true;
            EXPECT_EQ(preferred->connection, 1u);
            EXPECT_EQ(preferred->preferred_address.connection_id,
                      make_test_preferred_address().connection_id);
            continue;
        }
        if (const auto *status = std::get_if<QuicCoreZeroRttStatusEvent>(&effect)) {
            saw_zero_rtt = true;
            EXPECT_EQ(status->connection, 1u);
            EXPECT_EQ(status->status, QuicZeroRttStatus::accepted);
        }
    }

    EXPECT_TRUE(saw_reset);
    EXPECT_TRUE(saw_stop);
    EXPECT_TRUE(saw_preferred);
    EXPECT_TRUE(saw_zero_rtt);
}

TEST(QuicCoreEndpointInternalTest, EndpointInternalCoverageHookExercisesRemainingColdPaths) {
    EXPECT_TRUE(coquic::quic::test::core_endpoint_internal_coverage_for_tests());
}

TEST(QuicCoreEndpointInternalTest,
     ExistingInboundDatagramUsesDefaultRouteAndErasesClosedConnection) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));
    const auto initial = make_client_initial_datagram();

    const auto accepted = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial,
            .route_handle = 31,
        },
        coquic::quic::test::test_time(1));
    ASSERT_EQ(server.connection_count(), 1u);
    ASSERT_EQ(lifecycle_events_from(accepted).size(), 1u);

    auto &entry = server.connections_.begin()->second;
    ASSERT_EQ(entry.default_route_handle, std::optional<QuicRouteHandle>{31u});
    entry.connection->pending_terminal_state_ = QuicConnectionTerminalState::closed;

    const auto closed = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = initial,
        },
        coquic::quic::test::test_time(2));

    EXPECT_EQ(server.connection_count(), 0u);
    const auto lifecycle = lifecycle_events_from(closed);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::closed);
    const auto sends = send_effects_from(closed);
    if (!sends.empty()) {
        EXPECT_EQ(sends.front().route_handle, std::optional<QuicRouteHandle>{31u});
    }
}

TEST(QuicCoreEndpointInternalTest, SelfMoveAssignmentLeavesLegacyCoreUsable) {
    QuicCore core(coquic::quic::test::make_client_core_config());

    auto &self = core;
    const auto original_handle = core.legacy_connection_handle_;
    const auto original_count = core.connection_count();
    core = std::move(self);

    EXPECT_EQ(core.legacy_connection_handle_, original_handle);
    EXPECT_EQ(core.connection_count(), original_count);
    EXPECT_EQ(core.connection_.owner, &core);
}

TEST(QuicCoreEndpointInternalTest, InboundEndpointBranchesCoverAcceptDropAndUnknownRetryToken) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));

    const auto accepted = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_client_initial_datagram(),
        },
        coquic::quic::test::test_time(1));

    const auto lifecycle = lifecycle_events_from(accepted);
    ASSERT_FALSE(lifecycle.empty());
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
    const auto accepted_sends = send_effects_from(accepted);
    ASSERT_FALSE(accepted_sends.empty());
    EXPECT_EQ(accepted_sends.front().route_handle, std::nullopt);

    QuicCore client(make_client_endpoint_config());
    const auto ignored = client.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = bytes_from_ints({0x40, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(ignored.effects.empty());
    EXPECT_FALSE(ignored.local_error.has_value());

    auto retry_config = make_server_endpoint_config();
    retry_config.retry_enabled = true;
    QuicCore retry_server(std::move(retry_config));
    const auto dropped = retry_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_plaintext_initial_datagram_with_token(bytes_from_ints({0xaa})),
            .route_handle = 55,
        },
        coquic::quic::test::test_time(3));
    EXPECT_TRUE(dropped.effects.empty());
    EXPECT_EQ(retry_server.connection_count(), 0u);
}

TEST(QuicCoreEndpointInternalTest, EndpointAndLegacyCommandsCoverErrorAndCleanupBranches) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();
    if (!entry.connection->peer_transport_parameters_.has_value()) {
        FAIL() << "expected peer transport parameters";
        return;
    }
    auto &peer_transport_parameters = *entry.connection->peer_transport_parameters_;
    peer_transport_parameters.disable_active_migration = true;

    const auto reset_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreResetStream{
                    .stream_id = 3,
                    .application_error_code = 11,
                },
        },
        coquic::quic::test::test_time(1));
    if (!reset_result.local_error.has_value()) {
        FAIL() << "expected reset local error";
        return;
    }
    const auto &reset_error = *reset_result.local_error;
    EXPECT_EQ(reset_error.connection, std::optional<QuicConnectionHandle>{1u});
    EXPECT_EQ(reset_error.code, QuicCoreLocalErrorCode::invalid_stream_direction);

    const auto stop_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreStopSending{
                    .stream_id = 2,
                    .application_error_code = 12,
                },
        },
        coquic::quic::test::test_time(2));
    if (!stop_result.local_error.has_value()) {
        FAIL() << "expected stop local error";
        return;
    }
    const auto &stop_error = *stop_result.local_error;
    EXPECT_EQ(stop_error.connection, std::optional<QuicConnectionHandle>{1u});
    EXPECT_EQ(stop_error.code, QuicCoreLocalErrorCode::invalid_stream_direction);

    const auto migration_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreRequestConnectionMigration{
                    .route_handle = 29,
                    .reason = QuicMigrationRequestReason::active,
                },
        },
        coquic::quic::test::test_time(3));
    if (!migration_result.local_error.has_value()) {
        FAIL() << "expected migration local error";
        return;
    }
    const auto &migration_error = *migration_result.local_error;
    EXPECT_EQ(migration_error.connection, std::optional<QuicConnectionHandle>{1u});
    EXPECT_EQ(migration_error.code, QuicCoreLocalErrorCode::unsupported_operation);

    QuicCore timer_core(make_client_endpoint_config());
    static_cast<void>(timer_core.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));
    auto &timer_entry = timer_core.connections_.at(1);
    *timer_entry.connection = make_connected_client_connection();
    timer_entry.connection->send_burst_resume_deadline_ = coquic::quic::test::test_time(5);
    timer_entry.connection->pending_terminal_state_ = QuicConnectionTerminalState::closed;

    const auto timeout_result =
        timer_core.advance_endpoint(QuicCoreTimerExpired{}, coquic::quic::test::test_time(5));
    EXPECT_EQ(timer_core.connection_count(), 0u);
    const auto timeout_lifecycle = lifecycle_events_from(timeout_result);
    ASSERT_EQ(timeout_lifecycle.size(), 1u);
    EXPECT_EQ(timeout_lifecycle.front().event, QuicCoreConnectionLifecycle::closed);

    QuicCore missing_legacy(coquic::quic::test::make_client_core_config());
    auto *missing_legacy_entry = missing_legacy.ensure_legacy_entry();
    ASSERT_NE(missing_legacy_entry, nullptr);
    missing_legacy_entry->connection.reset();
    const auto missing_legacy_result =
        missing_legacy.advance(QuicCoreStart{}, coquic::quic::test::test_time(6));
    EXPECT_TRUE(missing_legacy_result.effects.empty());
    EXPECT_FALSE(missing_legacy_result.local_error.has_value());

    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    const auto shared_send_result = legacy_core.advance(
        QuicCoreSendSharedStreamData{
            .stream_id = 0,
            .bytes = SharedBytes(bytes_from_ints({0x68, 0x69})),
            .fin = false,
        },
        coquic::quic::test::test_time(7));
    if (!shared_send_result.local_error.has_value()) {
        FAIL() << "expected shared-send local error";
        return;
    }
    const auto &shared_send_error = *shared_send_result.local_error;
    EXPECT_EQ(shared_send_error.connection, std::nullopt);
    EXPECT_EQ(shared_send_error.code, QuicCoreLocalErrorCode::invalid_stream_id);
}

TEST(QuicCoreEndpointInternalTest, RouteMaintenanceSkipsForeignOwnersAndMissingInitialKeys) {
    QuicCore server_core(make_server_endpoint_config());

    QuicCore::ConnectionEntry erase_entry{
        .handle = 9,
    };
    erase_entry.active_connection_id_keys = {"owned", "foreign", "missing"};
    erase_entry.initial_destination_connection_id_key = "foreign-initial";
    server_core.connection_id_routes_.emplace("owned", erase_entry.handle);
    server_core.connection_id_routes_.emplace("foreign", 77);
    server_core.initial_destination_routes_.emplace("foreign-initial", 77);

    server_core.erase_endpoint_connection_routes(erase_entry);
    EXPECT_FALSE(server_core.connection_id_routes_.contains("owned"));
    EXPECT_EQ(server_core.connection_id_routes_.at("foreign"), 77u);
    EXPECT_EQ(server_core.initial_destination_routes_.at("foreign-initial"), 77u);

    QuicCore::ConnectionEntry no_initial_entry{
        .handle = 10,
    };
    no_initial_entry.active_connection_id_keys = {"owned-no-initial"};
    server_core.connection_id_routes_.emplace("owned-no-initial", no_initial_entry.handle);

    server_core.erase_endpoint_connection_routes(no_initial_entry);
    EXPECT_FALSE(server_core.connection_id_routes_.contains("owned-no-initial"));

    QuicCore::ConnectionEntry missing_initial_entry{
        .handle = 10,
        .initial_destination_connection_id_key = std::string("missing-initial"),
    };
    server_core.erase_endpoint_connection_routes(missing_initial_entry);

    auto refresh_entry = make_server_connection_entry(11, std::string("foreign-refresh-initial"));
    refresh_entry.connection->local_connection_ids_.clear();
    refresh_entry.connection->local_connection_ids_.emplace(
        0, LocalConnectionIdRecord{
               .sequence_number = 0,
               .connection_id = ConnectionId{std::byte{0x44}},
               .retired = false,
           });
    refresh_entry.connection->client_initial_destination_connection_id_ =
        ConnectionId{std::byte{0x83}};
    refresh_entry.active_connection_id_keys = {"owned-refresh", "foreign-refresh",
                                               "missing-refresh"};
    server_core.connection_id_routes_.emplace("owned-refresh", refresh_entry.handle);
    server_core.connection_id_routes_.emplace("foreign-refresh", 88);
    server_core.initial_destination_routes_.emplace("foreign-refresh-initial", 88);

    server_core.refresh_server_connection_routes(refresh_entry);
    refresh_entry.connection.reset();
    EXPECT_FALSE(server_core.connection_id_routes_.contains("owned-refresh"));
    EXPECT_EQ(server_core.connection_id_routes_.at("foreign-refresh"), 88u);
    EXPECT_EQ(server_core.initial_destination_routes_.at("foreign-refresh-initial"), 88u);
    const auto has_refreshed_initial =
        refresh_entry.initial_destination_connection_id_key.has_value();
    EXPECT_TRUE(has_refreshed_initial);
    if (has_refreshed_initial) {
        EXPECT_NE(refresh_entry.initial_destination_connection_id_key.value(),
                  "foreign-refresh-initial");
    }

    auto refresh_missing_initial =
        make_server_connection_entry(12, std::string("missing-refresh-initial"));
    refresh_missing_initial.connection->local_connection_ids_.clear();
    refresh_missing_initial.connection->local_connection_ids_.emplace(
        0, LocalConnectionIdRecord{
               .sequence_number = 0,
               .connection_id = ConnectionId{std::byte{0x45}},
               .retired = false,
           });
    refresh_missing_initial.connection->client_initial_destination_connection_id_ =
        ConnectionId{std::byte{0x84}};
    refresh_missing_initial.active_connection_id_keys = {"missing-refresh-only"};
    server_core.refresh_server_connection_routes(refresh_missing_initial);
    refresh_missing_initial.connection.reset();
}

TEST(QuicCoreEndpointInternalTest,
     SupportedLongHeaderAndRetryGuardsCoverEmptyVersionNegotiationAndRetryReplies) {
    auto empty_versions = make_server_endpoint_config();
    empty_versions.supported_versions.clear();
    QuicCore version_negotiation_server(std::move(empty_versions));

    const auto supported_long_header = make_supported_long_header_datagram(
        kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        bytes_from_ints({0xc1, 0x01}));
    const auto version_negotiation_result = version_negotiation_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = supported_long_header,
            .route_handle = 41,
        },
        coquic::quic::test::test_time(1));
    EXPECT_TRUE(version_negotiation_result.effects.empty());
    EXPECT_FALSE(version_negotiation_result.local_error.has_value());
    EXPECT_EQ(version_negotiation_server.connection_count(), 0u);

    QuicCore short_header_server(make_server_endpoint_config());
    const auto short_header_result = short_header_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = bytes_from_ints({0x40, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
            .route_handle = 42,
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(short_header_result.effects.empty());
    EXPECT_FALSE(short_header_result.local_error.has_value());
    EXPECT_EQ(short_header_server.connection_count(), 0u);

    auto retry_config = make_server_endpoint_config();
    retry_config.retry_enabled = true;
    QuicCore retry_server(std::move(retry_config));

    const auto oversized_source_connection_id =
        bytes_from_ints({0xc1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                         0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14});
    const auto retry_initial = make_supported_initial_datagram(
        kQuicVersion1, bytes_from_ints({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}),
        oversized_source_connection_id, {});
    const auto retry_result = retry_server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = retry_initial,
            .route_handle = 55,
        },
        coquic::quic::test::test_time(2));
    EXPECT_TRUE(retry_result.effects.empty());
    EXPECT_FALSE(retry_result.local_error.has_value());
    EXPECT_EQ(retry_server.connection_count(), 0u);
    EXPECT_EQ(retry_server.retry_tokens_.size(), 1u);
}

TEST(QuicCoreEndpointInternalTest, ParseableButInvalidInitialSkipsAcceptedConnectionInsertion) {
    auto server_config = make_server_endpoint_config();
    server_config.application_protocol = "coquic";
    QuicCore server(std::move(server_config));

    const auto result = server.advance_endpoint(
        QuicCoreInboundDatagram{
            .bytes = make_plaintext_initial_datagram_with_token({}),
            .route_handle = 61,
        },
        coquic::quic::test::test_time(1));

    EXPECT_EQ(server.connection_count(), 0u);
    const auto lifecycle = lifecycle_events_from(result);
    ASSERT_EQ(lifecycle.size(), 1u);
    EXPECT_EQ(lifecycle.front().event, QuicCoreConnectionLifecycle::accepted);
}

TEST(QuicCoreEndpointInternalTest, EndpointCommandsAndTimersCoverSuccessAndCleanupBranches) {
    QuicCore endpoint(make_client_endpoint_config());
    static_cast<void>(endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));

    auto &entry = endpoint.connections_.at(1);
    *entry.connection = make_connected_client_connection();

    const auto reset_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreResetStream{
                    .stream_id = 0,
                    .application_error_code = 13,
                },
        },
        coquic::quic::test::test_time(1));
    EXPECT_FALSE(reset_result.local_error.has_value());
    EXPECT_FALSE(send_effects_from(reset_result).empty());

    auto &stop_entry = endpoint.connections_.at(1);
    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        *stop_entry.connection,
        {coquic::quic::test::make_inbound_application_stream_frame("a", 0, 3)}));
    const auto stop_result = endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input =
                QuicCoreStopSending{
                    .stream_id = 3,
                    .application_error_code = 14,
                },
        },
        coquic::quic::test::test_time(2));
    EXPECT_FALSE(stop_result.local_error.has_value());
    EXPECT_FALSE(send_effects_from(stop_result).empty());

    QuicCore cleanup_endpoint(make_client_endpoint_config());
    static_cast<void>(cleanup_endpoint.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));
    auto &cleanup_entry = cleanup_endpoint.connections_.at(1);
    *cleanup_entry.connection = make_connected_client_connection();
    cleanup_entry.connection->pending_terminal_state_ = QuicConnectionTerminalState::closed;

    const auto cleanup_result = cleanup_endpoint.advance_endpoint(
        QuicCoreConnectionCommand{
            .connection = 1,
            .input = QuicCoreRequestKeyUpdate{},
        },
        coquic::quic::test::test_time(3));
    EXPECT_EQ(cleanup_endpoint.connection_count(), 0u);
    const auto cleanup_lifecycle = lifecycle_events_from(cleanup_result);
    ASSERT_EQ(cleanup_lifecycle.size(), 1u);
    EXPECT_EQ(cleanup_lifecycle.front().event, QuicCoreConnectionLifecycle::closed);

    QuicCore timer_core(make_client_endpoint_config());
    static_cast<void>(timer_core.advance_endpoint(
        QuicCoreOpenConnection{
            .connection = make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0)));
    auto &timer_entry = timer_core.connections_.at(1);
    *timer_entry.connection = make_connected_client_connection();
    timer_entry.connection->send_burst_resume_deadline_ = coquic::quic::test::test_time(5);

    const auto timer_result =
        timer_core.advance_endpoint(QuicCoreTimerExpired{}, coquic::quic::test::test_time(5));
    EXPECT_EQ(timer_core.connection_count(), 1u);
    EXPECT_FALSE(timer_result.local_error.has_value());
    EXPECT_TRUE(lifecycle_events_from(timer_result).empty());
}

TEST(QuicCoreEndpointInternalTest, LegacyAdvanceSuccessfulSharedSendQueuesDatagrams) {
    QuicCore legacy_core(coquic::quic::test::make_client_core_config());
    *legacy_core.connection_ = make_connected_client_connection();

    const auto shared_send_result = legacy_core.advance(
        QuicCoreSendSharedStreamData{
            .stream_id = 0,
            .bytes = SharedBytes(bytes_from_ints({0x68, 0x69})),
            .fin = false,
        },
        coquic::quic::test::test_time(7));
    EXPECT_FALSE(shared_send_result.local_error.has_value());
    EXPECT_FALSE(send_effects_from(shared_send_result).empty());
}

} // namespace
