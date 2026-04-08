#include <gtest/gtest.h>

#include "src/quic/qlog/session.h"
#include "src/quic/qlog/types.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"
#include "tests/support/core/connection_test_fixtures.h"

namespace {

using coquic::quic::test_support::make_connected_client_connection;
using coquic::quic::test_support::make_connected_server_connection;

TEST(QuicCoreTest, ClientQlogStartWritesSequentialPreamble) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto config = coquic::quic::test::make_client_core_config();
    config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    coquic::quic::QuicCore core(std::move(config));

    const auto result =
        core.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    static_cast<void>(result);

    const auto qlog_path = coquic::quic::test::only_sqlog_file_in(qlog_dir.path());
    const auto records = coquic::quic::test::qlog_seq_records_from_file(qlog_path);

    ASSERT_FALSE(records.empty());
    EXPECT_NE(records.front().find("\"file_schema\":\"urn:ietf:params:qlog:file:sequential\""),
              std::string::npos);
    EXPECT_NE(records.front().find("\"type\":\"client\""), std::string::npos);
    EXPECT_FALSE(core.has_failed());
}

TEST(QuicCoreTest, ServerQlogFilenameUsesOriginalDestinationConnectionId) {
    coquic::quic::test::ScopedTempDir qlog_root;
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "client"};
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "server"};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));

    const auto client_start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto datagrams = coquic::quic::test::send_datagrams_from(client_start);
    ASSERT_EQ(datagrams.size(), 1u);

    static_cast<void>(server.advance(coquic::quic::QuicCoreInboundDatagram{datagrams.front()},
                                     coquic::quic::test::test_time(1)));

    const auto server_qlog = coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "server");
    EXPECT_EQ(server_qlog.filename(), std::filesystem::path("8394c8f03e515708_server.sqlog"));
}

TEST(QuicCoreTest, QlogOpenFailureDoesNotFailConnection) {
    auto config = coquic::quic::test::make_client_core_config();
    config.qlog = coquic::quic::QuicQlogConfig{
        .directory = std::filesystem::path("/dev/null/coquic-qlog"),
    };
    coquic::quic::QuicCore core(std::move(config));

    const auto result =
        core.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());

    EXPECT_FALSE(core.has_failed());
    EXPECT_FALSE(result.local_error.has_value());
}

TEST(QuicCoreTest, QlogClientStartEmitsLocalVersionAlpnAndParametersEvents) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto config = coquic::quic::test::make_client_core_config();
    config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    coquic::quic::QuicCore client(std::move(config));

    static_cast<void>(
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time()));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:version_information"), 1u);
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:alpn_information"), 1u);
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:parameters_set"), 1u);
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(records, "\"initiator\":\"local\""));
}

TEST(QuicCoreTest, QlogHandshakeEmitsRemoteParametersAndChosenAlpn) {
    coquic::quic::test::ScopedTempDir qlog_root;
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "client"};
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "server"};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto client_records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "client"));
    const auto server_records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "server"));

    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(client_records,
                                                             "\"name\":\"quic:parameters_set\""));
    EXPECT_TRUE(
        coquic::quic::test::qlog_any_record_contains(client_records, "\"initiator\":\"remote\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(client_records, "\"chosen_alpn\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(server_records, "\"client_alpns\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(server_records, "\"server_alpns\""));
}

TEST(QuicCoreTest, QlogHandshakeAndStreamTrafficEmitPacketSentAndPacketReceived) {
    coquic::quic::test::ScopedTempDir qlog_root;
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "client"};
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_root.path() / "server"};

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto send_result = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = {std::byte{'h'}, std::byte{'i'}},
            .fin = true,
        },
        coquic::quic::test::test_time(10));
    static_cast<void>(coquic::quic::test::relay_send_datagrams_to_peer(
        send_result, server, coquic::quic::test::test_time(11)));

    const auto client_records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "client"));
    const auto server_records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_root.path() / "server"));

    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(client_records,
                                                             "\"name\":\"quic:packet_sent\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(server_records,
                                                             "\"name\":\"quic:packet_received\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(client_records, "\"datagram_id\":"));
    EXPECT_TRUE(
        coquic::quic::test::qlog_any_record_contains(client_records, "\"raw\":{\"length\":"));
}

TEST(QuicCoreTest, QlogDeferredReplayPreservesDatagramIdAndAddsKeysAvailableTrigger) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), coquic::quic::test::test_time());

    const auto packet = coquic::quic::ProtectedOneRttPacket{
        .spin_bit = false,
        .key_phase = false,
        .destination_connection_id = connection.config_.source_connection_id,
        .packet_number_length = 1,
        .packet_number = 1,
        .frames = {coquic::quic::PingFrame{}},
    };
    const auto bytes = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{packet},
        coquic::quic::SerializeProtectionContext{
            .local_role = connection.config_.role == coquic::quic::EndpointRole::client
                              ? coquic::quic::EndpointRole::server
                              : coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(bytes.has_value());

    connection.deferred_protected_packets_.push_back(
        coquic::quic::DeferredProtectedPacket(bytes.value(), 77));
    connection.replay_deferred_protected_packets(coquic::quic::test::test_time(5));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_TRUE(
        coquic::quic::test::qlog_any_record_contains(records, "\"name\":\"quic:packet_received\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(records, "\"datagram_id\":77"));
    EXPECT_TRUE(
        coquic::quic::test::qlog_any_record_contains(records, "\"trigger\":\"keys_available\""));
}

TEST(QuicCoreTest, QlogPacketLostUsesReorderingAndTimeThresholdTriggers) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), coquic::quic::test::test_time());

    auto first = coquic::quic::SentPacketRecord{
        .packet_number = 1,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = true,
        .qlog_packet_snapshot = std::make_shared<coquic::quic::qlog::PacketSnapshot>(
            connection.make_qlog_packet_snapshot(
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 1,
                    .packet_number = 1,
                    .frames = {coquic::quic::PingFrame{}},
                },
                coquic::quic::qlog::PacketSnapshotContext{
                    .raw_length = 27,
                    .datagram_id = 1,
                })),
        .bytes_in_flight = 1200,
    };
    auto second = first;
    second.packet_number = 4;
    second.sent_time = coquic::quic::test::test_time(-1000);
    second.qlog_packet_snapshot =
        std::make_shared<coquic::quic::qlog::PacketSnapshot>(connection.make_qlog_packet_snapshot(
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 4,
                .frames = {coquic::quic::PingFrame{}},
            },
            coquic::quic::qlog::PacketSnapshotContext{
                .raw_length = 27,
                .datagram_id = 1,
            }));

    connection.application_space_.sent_packets.emplace(first.packet_number, first);
    connection.application_space_.sent_packets.emplace(second.packet_number, second);
    connection.application_space_.recovery.on_packet_sent(first);
    connection.application_space_.recovery.on_packet_sent(second);
    connection.application_space_.recovery.on_packet_sent(coquic::quic::SentPacketRecord{
        .packet_number = 5,
        .sent_time = coquic::quic::test::test_time(10),
        .ack_eliciting = true,
        .in_flight = true,
        .bytes_in_flight = 1200,
    });

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = 5,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(20), 3, 25, false)
                    .has_value());
    connection.detect_lost_packets(coquic::quic::test::test_time(2000));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        records, "\"trigger\":\"reordering_threshold\""));
    EXPECT_TRUE(
        coquic::quic::test::qlog_any_record_contains(records, "\"trigger\":\"time_threshold\""));
}

TEST(QuicCoreTest, QlogRecoveryMetricsUpdatedAndPtoProbeTriggerAreEmitted) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), coquic::quic::test::test_time());

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    connection.remaining_pto_probe_datagrams_ = 1;

    static_cast<void>(connection.drain_outbound_datagram(coquic::quic::test::test_time(50)));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(
        records, "\"name\":\"quic:recovery_metrics_updated\""));
    EXPECT_TRUE(coquic::quic::test::qlog_any_record_contains(records, "\"trigger\":\"pto_probe\""));
}

TEST(QuicCoreTest, ConnectionQlogSessionOpenGuardsRespectConfigAndExistingSession) {
    auto connection = make_connected_client_connection();
    const auto odcid = connection.client_initial_destination_connection_id();

    connection.config_.qlog.reset();
    connection.maybe_open_qlog_session(coquic::quic::test::test_time(0), odcid);
    EXPECT_EQ(connection.qlog_session_, nullptr);

    coquic::quic::test::ScopedTempDir qlog_dir;
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.maybe_open_qlog_session(coquic::quic::test::test_time(1), odcid);
    ASSERT_NE(connection.qlog_session_, nullptr);
    auto *existing = connection.qlog_session_.get();

    connection.maybe_open_qlog_session(coquic::quic::test::test_time(2), odcid);
    EXPECT_EQ(connection.qlog_session_.get(), existing);
}

TEST(QuicCoreTest, ConnectionQlogLocalStartupEventsAreIdempotent) {
    auto connection = make_connected_client_connection();
    connection.emit_local_qlog_startup_events(coquic::quic::test::test_time(0));

    coquic::quic::test::ScopedTempDir qlog_dir;
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), coquic::quic::test::test_time(0));
    ASSERT_NE(connection.qlog_session_, nullptr);

    connection.emit_local_qlog_startup_events(coquic::quic::test::test_time(1));
    connection.emit_local_qlog_startup_events(coquic::quic::test::test_time(2));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:version_information"), 1u);
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:alpn_information"), 1u);
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:parameters_set"), 1u);
}

TEST(QuicCoreTest, ConnectionQlogRemoteParametersReturnWhenPeerParametersMissing) {
    auto connection = make_connected_client_connection();

    coquic::quic::test::ScopedTempDir qlog_dir;
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), coquic::quic::test::test_time(0));
    ASSERT_NE(connection.qlog_session_, nullptr);

    connection.peer_transport_parameters_.reset();
    connection.maybe_emit_remote_qlog_parameters(coquic::quic::test::test_time(1));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:parameters_set"), 0u);
}

TEST(QuicCoreTest, ConnectionQlogServerAlpnSelectionEmissionIsIdempotent) {
    auto connection = make_connected_server_connection();
    connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::server,
        .verify_peer = false,
        .server_name = "localhost",
        .application_protocol = connection.config_.application_protocol,
        .identity = connection.config_.identity,
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
        .allowed_tls_cipher_suites = connection.config_.allowed_tls_cipher_suites,
    });

    const auto offered = std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i', 'c'});
    const uint8_t *selected = nullptr;
    std::uint8_t selected_length = 0;
    ASSERT_EQ(coquic::quic::test::TlsAdapterTestPeer::call_static_select_application_protocol(
                  &*connection.tls_, &selected, &selected_length, offered),
              SSL_TLSEXT_ERR_OK);

    coquic::quic::test::ScopedTempDir qlog_dir;
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), coquic::quic::test::test_time(0));
    ASSERT_NE(connection.qlog_session_, nullptr);

    connection.maybe_emit_qlog_alpn_information(coquic::quic::test::test_time(1));
    connection.maybe_emit_qlog_alpn_information(coquic::quic::test::test_time(2));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:alpn_information"), 1u);
}

TEST(QuicCoreTest, ConnectionQlogServerAlpnSelectionSkipsMalformedPeerAlpnList) {
    auto connection = make_connected_server_connection();
    connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::server,
        .verify_peer = false,
        .server_name = "localhost",
        .application_protocol = connection.config_.application_protocol,
        .identity = connection.config_.identity,
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
        .allowed_tls_cipher_suites = connection.config_.allowed_tls_cipher_suites,
    });

    const auto malformed_offered = std::vector<std::uint8_t>({6, 'c', 'o', 'q', 'u', 'i', 'c', 1});
    const std::uint8_t *selected = nullptr;
    std::uint8_t selected_length = 0;
    ASSERT_EQ(coquic::quic::test::TlsAdapterTestPeer::call_static_select_application_protocol(
                  &*connection.tls_, &selected, &selected_length, malformed_offered),
              SSL_TLSEXT_ERR_OK);

    coquic::quic::test::ScopedTempDir qlog_dir;
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), coquic::quic::test::test_time(0));
    ASSERT_NE(connection.qlog_session_, nullptr);

    connection.maybe_emit_qlog_alpn_information(coquic::quic::test::test_time(1));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:alpn_information"), 0u);
}

TEST(QuicCoreTest, ConnectionQlogPacketLostReturnsWhenSessionOrSnapshotMissing) {
    auto connection = make_connected_client_connection();
    auto packet_without_snapshot = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .sent_time = coquic::quic::test::test_time(0),
        .ack_eliciting = true,
        .in_flight = true,
    };

    connection.emit_qlog_packet_lost(packet_without_snapshot, "time_threshold",
                                     coquic::quic::test::test_time(1));

    coquic::quic::test::ScopedTempDir qlog_dir;
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), coquic::quic::test::test_time(0));
    ASSERT_NE(connection.qlog_session_, nullptr);

    connection.emit_qlog_packet_lost(packet_without_snapshot, "time_threshold",
                                     coquic::quic::test::test_time(2));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:packet_lost"), 0u);
}

} // namespace
