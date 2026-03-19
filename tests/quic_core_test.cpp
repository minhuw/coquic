#include <array>

#include <gtest/gtest.h>

#include "src/quic/protected_codec.h"
#include "tests/quic_test_utils.h"

namespace {

template <typename Core>
concept has_receive = requires(Core &core) { core.receive(std::vector<std::byte>{}); };

template <typename Core>
concept has_queue_application_data =
    requires(Core &core) { core.queue_application_data(std::vector<std::byte>{}); };

template <typename Core>
concept has_take_received_application_data =
    requires(Core &core) { core.take_received_application_data(); };

static_assert(!has_receive<coquic::quic::QuicCore>);
static_assert(!has_queue_application_data<coquic::quic::QuicCore>);
static_assert(!has_take_received_application_data<coquic::quic::QuicCore>);

TEST(QuicCoreTest, ClientStartProducesSendEffect) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    const auto config = coquic::quic::test::make_client_core_config();

    const auto result =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto datagrams = coquic::quic::test::send_datagrams_from(result);
    ASSERT_EQ(datagrams.size(), 1u);
    ASSERT_GE(datagrams.front().size(), 1200u);
    EXPECT_FALSE(client.is_handshake_complete());
    EXPECT_TRUE(coquic::quic::test::state_changes_from(result).empty());
    EXPECT_TRUE(result.next_wakeup.has_value());

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        datagrams.front(),
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = config.initial_destination_connection_id,
        });
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded.value().size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedInitialPacket>(&decoded.value()[0]), nullptr);
}

TEST(QuicCoreTest, TwoPeersEmitHandshakeReadyExactlyOnce) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    auto client_events = std::vector<coquic::quic::QuicCoreStateChange>{};
    auto server_events = std::vector<coquic::quic::QuicCoreStateChange>{};
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time(),
                                             &client_events, &server_events);

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
    EXPECT_EQ(coquic::quic::test::count_state_change(
                  client_events, coquic::quic::QuicCoreStateChange::handshake_ready),
              1u);
    EXPECT_EQ(coquic::quic::test::count_state_change(
                  server_events, coquic::quic::QuicCoreStateChange::handshake_ready),
              1u);
}

TEST(QuicCoreTest, TwoPeersExchangeApplicationDataThroughEffects) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto send = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));
    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(1));

    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(received)),
              "ping");
}

TEST(QuicCoreTest, HandshakeRecoversWhenInitialFlightIsDropped) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto dropped =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    EXPECT_TRUE(dropped.next_wakeup.has_value());

    const auto dropped_by_network = coquic::quic::test::relay_send_datagrams_to_peer_except(
        dropped, std::array<std::size_t, 1>{0}, server, coquic::quic::test::test_time(1));
    EXPECT_TRUE(dropped_by_network.effects.empty());

    const auto retry =
        coquic::quic::test::drive_earliest_next_wakeup(client, {dropped.next_wakeup});
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(retry).empty());

    auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        retry, server, coquic::quic::test::test_time(2));
    auto to_server = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(3));

    for (int i = 0; i < 16 && !(client.is_handshake_complete() && server.is_handshake_complete());
         ++i) {
        to_client = coquic::quic::test::relay_send_datagrams_to_peer(
            to_server, server, coquic::quic::test::test_time(4 + i * 2));
        if (client.is_handshake_complete() && server.is_handshake_complete()) {
            break;
        }

        to_server = coquic::quic::test::relay_send_datagrams_to_peer(
            to_client, client, coquic::quic::test::test_time(5 + i * 2));
    }

    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(server.has_failed());
    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
}

TEST(QuicCoreTest, ApplicationDataIsRetransmittedAfterLoss) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto confirm = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("confirm"),
        },
        coquic::quic::test::test_time(1));
    const auto confirm_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        confirm, server, coquic::quic::test::test_time(2));
    const auto confirm_acked = coquic::quic::test::relay_send_datagrams_to_peer(
        confirm_delivered, client, coquic::quic::test::test_time(3));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(confirm_acked).empty());

    const auto sent = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("probe"),
        },
        coquic::quic::test::test_time(4));
    EXPECT_TRUE(sent.next_wakeup.has_value());

    const auto dropped = coquic::quic::test::relay_send_datagrams_to_peer_except(
        sent, std::array<std::size_t, 1>{0}, server, coquic::quic::test::test_time(5));
    EXPECT_TRUE(dropped.effects.empty());

    const auto retry = coquic::quic::test::drive_earliest_next_wakeup(client, {sent.next_wakeup});
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(retry).empty());

    const auto delivered = coquic::quic::test::relay_nth_send_datagram_to_peer(
        retry, 0, server, coquic::quic::test::test_time(6));
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(delivered)),
              "probe");

    const auto acked = coquic::quic::test::relay_send_datagrams_to_peer(
        delivered, client, coquic::quic::test::test_time(7));
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(server.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(acked).empty());
}

TEST(QuicCoreTest, ApplicationPtoWaitsForClientHandshakeConfirmation) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto server_send = server.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("server-probe"),
        },
        coquic::quic::test::test_time(1));
    EXPECT_TRUE(server_send.next_wakeup.has_value());

    const auto client_before_confirmation = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("client-probe"),
        },
        coquic::quic::test::test_time(2));
    EXPECT_EQ(client_before_confirmation.next_wakeup, std::nullopt);

    const auto server_after_client_probe = coquic::quic::test::relay_send_datagrams_to_peer(
        client_before_confirmation, server, coquic::quic::test::test_time(3));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(server_after_client_probe).empty());

    const auto client_after_ack = coquic::quic::test::relay_send_datagrams_to_peer(
        server_after_client_probe, client, coquic::quic::test::test_time(4));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_after_ack).empty());

    const auto client_after_confirmation = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("client-after-ack"),
        },
        coquic::quic::test::test_time(5));
    EXPECT_TRUE(client_after_confirmation.next_wakeup.has_value());
}

TEST(QuicCoreTest, AckProcessingClearsOutstandingDataAndRemovesWakeup) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto confirm = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("confirm"),
        },
        coquic::quic::test::test_time(1));
    const auto confirm_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        confirm, server, coquic::quic::test::test_time(2));
    const auto confirm_acked = coquic::quic::test::relay_send_datagrams_to_peer(
        confirm_delivered, client, coquic::quic::test::test_time(3));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(confirm_acked).empty());

    const auto sent = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("ack-clear"),
        },
        coquic::quic::test::test_time(4));
    EXPECT_TRUE(sent.next_wakeup.has_value());
    ASSERT_FALSE(client.connection_->application_space_.sent_packets.empty());
    EXPECT_TRUE(client.connection_->pending_application_send_.has_outstanding_data());

    const auto server_step = coquic::quic::test::relay_send_datagrams_to_peer(
        sent, server, coquic::quic::test::test_time(5));
    const auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_step, client, coquic::quic::test::test_time(6));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_step).empty());
    EXPECT_TRUE(client.connection_->application_space_.sent_packets.empty());
    EXPECT_FALSE(client.connection_->pending_application_send_.has_pending_data());
    EXPECT_FALSE(client.connection_->pending_application_send_.has_outstanding_data());
    EXPECT_EQ(client_step.next_wakeup, std::nullopt);
}

TEST(QuicCoreTest, AckProcessingUsesLargestNewlyAcknowledgedPacketForRttSample) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = false,
                                     .in_flight = false,
                                 });

    const auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 2,
            .first_ack_range = 1,
        },
        coquic::quic::test::test_time(70), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt,
              std::optional{std::chrono::milliseconds(60)});
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().smoothed_rtt,
              std::chrono::milliseconds(60));
}

TEST(QuicCoreTest, StaleLargestAcknowledgedPacketDoesNotGenerateRttSample) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = false,
                                     .in_flight = false,
                                 });

    const auto first = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 2,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(20), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt, std::nullopt);

    const auto second = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 2,
            .first_ack_range = 1,
        },
        coquic::quic::test::test_time(70), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt, std::nullopt);
}

TEST(QuicCoreTest, PtoBackoffIsConnectionWideAcrossPacketSpaces) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    ASSERT_EQ(connection.pto_deadline(), coquic::quic::test::test_time(999));

    connection.on_timeout(coquic::quic::test::test_time(999));

    EXPECT_EQ(connection.pto_deadline(), std::optional{coquic::quic::test::test_time(1998)});
}

TEST(QuicCoreTest, NewlyAcknowledgedNonAckElicitingPacketsResetPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.pto_count_ = 3;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 7,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = false,
                                     .in_flight = false,
                                 });

    const auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 7,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(40), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
}

TEST(QuicCoreTest, ReceivingAckElicitingPacketsSchedulesAckResponse) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto send = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("ack-me"),
        },
        coquic::quic::test::test_time(1));
    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(1));
    const auto response_datagrams = coquic::quic::test::send_datagrams_from(received);

    ASSERT_FALSE(response_datagrams.empty());

    bool saw_ack = false;
    for (const auto &datagram : response_datagrams) {
        const auto decoded = coquic::quic::deserialize_protected_datagram(
            datagram,
            coquic::quic::DeserializeProtectionContext{
                .peer_role = coquic::quic::EndpointRole::server,
                .client_initial_destination_connection_id =
                    client.connection_->client_initial_destination_connection_id(),
                .handshake_secret = client.connection_->handshake_space_.read_secret,
                .one_rtt_secret = client.connection_->application_space_.read_secret,
                .largest_authenticated_initial_packet_number =
                    client.connection_->initial_space_.largest_authenticated_packet_number,
                .largest_authenticated_handshake_packet_number =
                    client.connection_->handshake_space_.largest_authenticated_packet_number,
                .largest_authenticated_application_packet_number =
                    client.connection_->application_space_.largest_authenticated_packet_number,
                .one_rtt_destination_connection_id_length =
                    client.connection_->config_.source_connection_id.size(),
            });
        ASSERT_TRUE(decoded.has_value());

        for (const auto &packet : decoded.value()) {
            const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }

            for (const auto &frame : one_rtt->frames) {
                if (std::holds_alternative<coquic::quic::AckFrame>(frame)) {
                    saw_ack = true;
                }
            }
        }
    }

    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, ReorderedApplicationPacketsAreDeliveredOnceContiguous) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto first_send = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));
    const auto second_send = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("pong"),
        },
        coquic::quic::test::test_time(2));

    auto datagrams = coquic::quic::test::send_datagrams_from(first_send);
    const auto second_datagrams = coquic::quic::test::send_datagrams_from(second_send);
    datagrams.insert(datagrams.end(), second_datagrams.begin(), second_datagrams.end());
    ASSERT_EQ(datagrams.size(), 2u);

    const auto reordered = coquic::quic::test::relay_datagrams_to_peer(
        datagrams, std::array<std::size_t, 1>{1}, server, coquic::quic::test::test_time(3));
    EXPECT_FALSE(server.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(reordered).empty());

    const auto contiguous = coquic::quic::test::relay_datagrams_to_peer(
        datagrams, std::array<std::size_t, 1>{0}, server, coquic::quic::test::test_time(4));
    EXPECT_FALSE(server.has_failed());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(contiguous)),
              "pingpong");
}

TEST(QuicCoreTest, InboundApplicationAckRetiresOwnedSendRanges) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto send = client.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes = coquic::quic::test::bytes_from_string("retire-me"),
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(client.connection_->application_space_.sent_packets.empty());
    EXPECT_TRUE(client.connection_->pending_application_send_.has_outstanding_data());

    const auto server_step = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(2));
    const auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_step, client, coquic::quic::test::test_time(3));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_step).empty());
    EXPECT_TRUE(client.connection_->application_space_.sent_packets.empty());
    EXPECT_FALSE(client.connection_->pending_application_send_.has_pending_data());
    EXPECT_FALSE(client.connection_->pending_application_send_.has_outstanding_data());
}

TEST(QuicCoreTest, LargeAckOnlyHistoryEmitsTrimmedAckDatagram) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    for (std::uint64_t packet_number = 0; packet_number < 4096; ++packet_number) {
        client.connection_->application_space_.received_packets.record_received(
            packet_number * 3, true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }

    const auto datagram =
        client.connection_->drain_outbound_datagram(coquic::quic::test::test_time(5000));

    EXPECT_FALSE(client.connection_->has_failed());
    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);

    const auto decoded = coquic::quic::deserialize_protected_datagram(
        datagram,
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                client.connection_->client_initial_destination_connection_id(),
            .handshake_secret = client.connection_->handshake_space_.write_secret,
            .one_rtt_secret = client.connection_->application_space_.write_secret,
            .largest_authenticated_initial_packet_number =
                server.connection_->initial_space_.largest_authenticated_packet_number,
            .largest_authenticated_handshake_packet_number =
                server.connection_->handshake_space_.largest_authenticated_packet_number,
            .largest_authenticated_application_packet_number =
                server.connection_->application_space_.largest_authenticated_packet_number,
            .one_rtt_destination_connection_id_length =
                server.connection_->config_.source_connection_id.size(),
        });
    ASSERT_TRUE(decoded.has_value());

    bool saw_ack = false;
    for (const auto &packet : decoded.value()) {
        const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (one_rtt == nullptr) {
            continue;
        }

        for (const auto &frame : one_rtt->frames) {
            if (std::holds_alternative<coquic::quic::AckFrame>(frame)) {
                saw_ack = true;
            }
        }
    }

    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, FailureEventIsEdgeTriggeredAndLaterCallsAreInert) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto failed = server.advance(coquic::quic::QuicCoreInboundDatagram{{std::byte{0x01}}},
                                       coquic::quic::test::test_time());
    const auto after =
        server.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(1));

    EXPECT_EQ(coquic::quic::test::state_changes_from(failed),
              std::vector{coquic::quic::QuicCoreStateChange::failed});
    EXPECT_TRUE(after.effects.empty());
    EXPECT_EQ(after.next_wakeup, std::nullopt);
}

TEST(QuicCoreTest, FailureSuppressesStaleHandshakeReadyInSameResult) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    server.connection_->queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);

    const auto failed = server.advance(coquic::quic::QuicCoreInboundDatagram{{std::byte{0x01}}},
                                       coquic::quic::test::test_time());
    const auto state_changes = coquic::quic::test::state_changes_from(failed);

    EXPECT_EQ(state_changes, std::vector{coquic::quic::QuicCoreStateChange::failed});
}

TEST(QuicCoreTest, InboundApplicationStreamRequiresOffsetAndLengthFlags) {
    coquic::quic::QuicConnection missing_offset_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_offset_connection, coquic::quic::HandshakeStatus::connected);
    const auto missing_offset_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_offset_connection, {coquic::quic::test::make_inbound_application_stream_frame(
                                           "a", 0, 0, false, false, true)});
    EXPECT_FALSE(missing_offset_ok);
    EXPECT_TRUE(missing_offset_connection.has_failed());

    coquic::quic::QuicConnection missing_length_connection(
        coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        missing_length_connection, coquic::quic::HandshakeStatus::connected);
    const auto missing_length_ok =
        coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            missing_length_connection, {coquic::quic::test::make_inbound_application_stream_frame(
                                           "b", 0, 0, false, true, false)});
    EXPECT_FALSE(missing_length_ok);
    EXPECT_TRUE(missing_length_connection.has_failed());
}

TEST(QuicCoreTest, InboundApplicationStreamFailsBeforeHandshakeConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::in_progress);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping")});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.take_received_application_data().empty());
}

TEST(QuicCoreTest, InboundApplicationCryptoFrameIsIgnoredAfterHandshakeConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::CryptoFrame{
                         .offset = 0,
                         .crypto_data = coquic::quic::test::bytes_from_string("ignored"),
                     },
                     coquic::quic::test::make_inbound_application_stream_frame("pong")});

    EXPECT_TRUE(injected);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(connection.take_received_application_data()),
              "pong");
}

TEST(QuicCoreTest, InboundApplicationStreamFailsForNonZeroStreamId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::test::make_inbound_application_stream_frame("ping", 0, 1)});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, InboundApplicationStreamFailsWhenFinSet) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto injected = coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::test::make_inbound_application_stream_frame("ping", 0, 0, true)});

    EXPECT_FALSE(injected);
    EXPECT_TRUE(connection.has_failed());
}

} // namespace
