#include <gtest/gtest.h>
#include "tests/support/core/connection_ack_test_support.h"

namespace {

TEST(QuicCoreTest, CorruptedOneRttRequestWithPendingPostHandshakeDataDoesNotBreakRetransmit) {
    auto connection = make_connected_server_connection();
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    const auto request = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = false,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = 7,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = 0,
                            .stream_data = coquic::quic::test::bytes_from_string(
                                "GET /toasty-vibrant-mesprit\r\n"),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = optional_ref_or_terminate(connection.application_space_.read_secret),
        });
    ASSERT_TRUE(request.has_value());
    if (!request.has_value()) {
        return;
    }

    const auto request_datagram = request.has_value() ? request.value() : std::vector<std::byte>{};
    auto corrupted = request_datagram;
    ASSERT_GT(corrupted.size(), 43u);
    corrupted[43] = std::byte{0xae};

    connection.process_inbound_datagram(corrupted, coquic::quic::test::test_time(1));
    EXPECT_FALSE(connection.has_failed());

    connection.process_inbound_datagram(request_datagram, coquic::quic::test::test_time(2));
    EXPECT_FALSE(connection.has_failed());

    const coquic::quic::QuicCoreReceiveStreamData received_value =
        optional_value_or_terminate(connection.take_received_stream_data());
    if (received_value.stream_id != 0u) {
        ADD_FAILURE() << "unexpected received stream id";
    }
    if (received_value.bytes !=
        coquic::quic::test::bytes_from_string("GET /toasty-vibrant-mesprit\r\n")) {
        ADD_FAILURE() << "unexpected received stream bytes";
    }
    if (!received_value.fin) {
        ADD_FAILURE() << "received stream did not carry FIN";
    }
}

TEST(QuicCoreTest, ApplicationSendRetransmitsLostDataWithoutConnectionCredit) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
            .has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    const auto first_packet = first_tracked_packet(connection.application_space_);

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));
    connection.connection_flow_control_.peer_max_data =
        connection.connection_flow_control_.highest_sent;

    const auto retransmitted = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    if (retransmitted.empty()) {
        ADD_FAILURE() << "missing retransmitted stream datagram";
        return;
    }
    const auto packets = decode_sender_datagram(connection, retransmitted);
    if (packets.size() != 1u) {
        ADD_FAILURE() << "unexpected retransmitted packet count";
        return;
    }
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "retransmitted datagram was not a 1-RTT packet";
        return;
    }

    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        saw_stream = true;
        if (stream->stream_id != 0u) {
            ADD_FAILURE() << "retransmitted stream used the wrong id";
        }
        if (coquic::quic::test::string_from_bytes(stream->stream_data) != "hello") {
            ADD_FAILURE() << "retransmitted stream used the wrong bytes";
        }
    }

    if (!saw_stream) {
        ADD_FAILURE() << "missing retransmitted stream frame";
    }
}

TEST(QuicCoreTest, AckGapsRetransmitLostOffsetsBeforeFreshData) {
    auto connection = make_connected_server_connection();
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(128u) * 1024u, std::byte{0x46});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::vector<std::pair<std::uint64_t, std::uint64_t>> packet_offsets;
    std::uint64_t largest_sent_packet = 0;
    std::uint64_t next_unsent_offset = 0;

    while (true) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
        ASSERT_EQ(packets.size(), 1u);
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        ASSERT_NE(application, nullptr);

        largest_sent_packet = application->packet_number;
        std::optional<std::uint64_t> first_stream_offset;
        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            ASSERT_TRUE(stream->offset.has_value());
            if (!stream->offset.has_value()) {
                continue;
            }

            const auto stream_offset = optional_value_or_terminate(stream->offset);
            if (!first_stream_offset.has_value()) {
                first_stream_offset = stream_offset;
            }
            next_unsent_offset =
                stream_offset + static_cast<std::uint64_t>(stream->stream_data.size());
        }

        ASSERT_TRUE(first_stream_offset.has_value());
        packet_offsets.emplace_back(application->packet_number,
                                    optional_value_or_terminate(first_stream_offset));
    }

    ASSERT_GE(packet_offsets.size(), 8u);

    const auto lookup_offset = [&](std::uint64_t packet_number) -> std::optional<std::uint64_t> {
        for (const auto &[candidate_packet_number, offset] : packet_offsets) {
            if (candidate_packet_number == packet_number) {
                return offset;
            }
        }
        return std::nullopt;
    };

    const auto first_lost_offset = lookup_offset(/*packet_number=*/2);
    const auto second_lost_offset = lookup_offset(/*packet_number=*/6);
    ASSERT_TRUE(first_lost_offset.has_value());
    ASSERT_TRUE(second_lost_offset.has_value());

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = largest_sent_packet,
                                             .first_ack_range = largest_sent_packet - 7,
                                             .additional_ranges =
                                                 {
                                                     coquic::quic::AckRange{
                                                         .gap = 0,
                                                         .range_length = 2,
                                                     },
                                                     coquic::quic::AckRange{
                                                         .gap = 0,
                                                         .range_length = 1,
                                                     },
                                                 },
                                         },
                                         coquic::quic::test::test_time(2),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    ASSERT_TRUE(connection.streams_.contains(0));
    EXPECT_TRUE(connection.streams_.at(0).send_buffer.has_lost_data());

    const std::vector<std::byte> repaired_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    if (repaired_datagram.empty()) {
        ADD_FAILURE() << "missing repaired stream datagram";
        return;
    }

    const std::vector<coquic::quic::ProtectedPacket> repaired_packets =
        decode_sender_datagram(connection, repaired_datagram);
    if (repaired_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected repaired packet count";
        return;
    }
    const auto *application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&repaired_packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "repaired datagram was not a 1-RTT packet";
        return;
    }

    std::vector<std::uint64_t> repaired_offsets;
    for (const auto &frame : application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        if (!stream->offset.has_value()) {
            ADD_FAILURE() << "repaired stream frame did not carry an offset";
            return;
        }
        repaired_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    if (repaired_offsets.empty()) {
        ADD_FAILURE() << "repaired datagram did not carry stream data";
        return;
    }
    if (repaired_offsets.front() != optional_value_or_terminate(first_lost_offset)) {
        ADD_FAILURE() << "repaired datagram did not send the first lost offset first";
    }
    if (repaired_offsets.front() == next_unsent_offset) {
        ADD_FAILURE() << "repaired datagram sent fresh data before lost data";
    }
}

TEST(QuicCoreTest, ApplicationSendRemainsContiguousAfterAcknowledgingInitialFlight) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(200000), std::byte{0x41});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::uint64_t expected_offset = 0;
    std::size_t emitted_packets = 0;
    for (;;) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
        ASSERT_EQ(packets.size(), 1u);
        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        ASSERT_NE(application, nullptr);

        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            if (!stream->offset.has_value()) {
                ADD_FAILURE() << "stream frame did not carry an offset";
                return;
            }
            const auto stream_offset = optional_value_or_terminate(stream->offset);
            if (stream_offset != expected_offset) {
                ADD_FAILURE() << "stream send offset was not contiguous";
            }
            expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
        }

        ++emitted_packets;
    }

    ASSERT_GE(emitted_packets, 2u);
    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto largest_sent_packet =
        last_tracked_packet(connection.application_space_).packet_number;
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = largest_sent_packet,
                                             .first_ack_range = largest_sent_packet,
                                         },
                                         coquic::quic::test::test_time(2),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const std::vector<std::byte> resumed_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    if (resumed_datagram.empty()) {
        ADD_FAILURE() << "missing resumed stream datagram";
        return;
    }
    const std::vector<coquic::quic::ProtectedPacket> resumed_packets =
        decode_sender_datagram(connection, resumed_datagram);
    if (resumed_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected resumed packet count";
        return;
    }
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&resumed_packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "resumed datagram was not a 1-RTT packet";
        return;
    }

    const auto *stream = std::get_if<coquic::quic::StreamFrame>(&application->frames.back());
    if (stream == nullptr) {
        ADD_FAILURE() << "resumed datagram did not end with a stream frame";
        return;
    }
    if (!stream->offset.has_value()) {
        ADD_FAILURE() << "resumed stream frame did not carry an offset";
        return;
    }
    if (optional_value_or_terminate(stream->offset) != expected_offset) {
        ADD_FAILURE() << "resumed datagram did not continue at the expected offset";
    }
}

TEST(QuicCoreTest, ApplicationSendContinuesAcrossCumulativeAckBursts) {
    auto connection = make_connected_client_connection();
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(200000), std::byte{0x42});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::uint64_t expected_offset = 0;
    auto verify_sent_datagram = [&](std::span<const std::byte> datagram) -> std::uint64_t {
        const auto packets = decode_sender_datagram(connection, datagram);
        if (packets.size() != 1u) {
            ADD_FAILURE() << "unexpected sent packet count";
            return 0;
        }

        const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        if (application == nullptr) {
            ADD_FAILURE() << "sent datagram was not a 1-RTT packet";
            return 0;
        }

        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            if (!stream->offset.has_value()) {
                ADD_FAILURE() << "stream frame did not carry an offset";
                return application->packet_number;
            }

            if (*stream->offset != expected_offset) {
                ADD_FAILURE() << "stream send offset was not contiguous";
            }
            expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
        }

        return application->packet_number;
    };

    const auto drain_burst =
        [&](coquic::quic::QuicCoreTimePoint burst_time) -> std::pair<std::size_t, std::uint64_t> {
        std::size_t emitted_packets = 0;
        std::uint64_t largest_sent = 0;
        for (;;) {
            const auto sent_datagram = connection.drain_outbound_datagram(burst_time);
            if (sent_datagram.empty()) {
                break;
            }

            largest_sent = verify_sent_datagram(sent_datagram);
            ++emitted_packets;
        }

        return std::pair{emitted_packets, largest_sent};
    };

    const auto first_burst = drain_burst(coquic::quic::test::test_time(1));
    if (first_burst.first != 10u) {
        ADD_FAILURE() << "unexpected first burst packet count";
        return;
    }
    if (expected_offset == 0u) {
        ADD_FAILURE() << "first burst did not send stream data";
        return;
    }

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = first_burst.second,
                                             .first_ack_range = first_burst.second,
                                         },
                                         coquic::quic::test::test_time(2),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto second_burst = drain_burst(coquic::quic::test::test_time(3));
    if (second_burst.first != 10u) {
        ADD_FAILURE() << "unexpected second burst packet count";
        return;
    }
    if (second_burst.second <= first_burst.second) {
        ADD_FAILURE() << "second burst did not advance packet numbers";
    }

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = second_burst.second,
                                             .first_ack_range = second_burst.second,
                                         },
                                         coquic::quic::test::test_time(4),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto third_burst = drain_burst(coquic::quic::test::test_time(5));
    if (third_burst.first == 0u) {
        ADD_FAILURE() << "third burst did not send packets";
        return;
    }
    if (third_burst.second <= second_burst.second) {
        ADD_FAILURE() << "third burst did not advance packet numbers";
    }
    if (expected_offset <= 30000u) {
        ADD_FAILURE() << "stream data did not advance after cumulative ACK bursts";
    }
}

TEST(QuicCoreTest, ApplicationSendDrainsLargePayloadAcrossRepeatedCumulativeAcks) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(512u) * 1024u, std::byte{0x44});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::uint64_t expected_offset = 0;
    std::size_t total_packets = 0;
    constexpr std::size_t kMaxAckRounds = 2048;

    const auto drain_burst = [&](coquic::quic::QuicCoreTimePoint burst_time) {
        std::size_t emitted_packets = 0;
        std::uint64_t largest_sent = 0;
        for (;;) {
            const auto datagram = connection.drain_outbound_datagram(burst_time);
            if (datagram.empty()) {
                break;
            }

            const auto decoded = coquic::quic::deserialize_protected_datagram(
                datagram, coquic::quic::DeserializeProtectionContext{
                              .peer_role = connection.config_.role,
                              .client_initial_destination_connection_id =
                                  connection.client_initial_destination_connection_id(),
                              .handshake_secret = connection.handshake_space_.write_secret,
                              .one_rtt_secret = connection.application_space_.write_secret,
                              .one_rtt_key_phase = connection.application_write_key_phase_,
                              .largest_authenticated_initial_packet_number =
                                  connection.initial_space_.largest_authenticated_packet_number,
                              .largest_authenticated_handshake_packet_number =
                                  connection.handshake_space_.largest_authenticated_packet_number,
                              .largest_authenticated_application_packet_number =
                                  connection.application_space_.largest_authenticated_packet_number,
                              .one_rtt_destination_connection_id_length =
                                  connection.config_.source_connection_id.size(),
                          });
            EXPECT_TRUE(decoded.has_value());
            if (!decoded.has_value()) {
                continue;
            }

            const auto &packets = decoded.value();
            EXPECT_EQ(packets.size(), 1u);
            if (packets.size() != 1u) {
                continue;
            }

            const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
            EXPECT_NE(application, nullptr);
            if (application == nullptr) {
                continue;
            }

            largest_sent = application->packet_number;
            for (const auto &frame : application->frames) {
                const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
                if (stream == nullptr) {
                    continue;
                }

                EXPECT_TRUE(stream->offset.has_value());
                if (!stream->offset.has_value()) {
                    continue;
                }

                EXPECT_EQ(*stream->offset, expected_offset);
                expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
            }

            ++emitted_packets;
            ++total_packets;
        }

        return std::pair{emitted_packets, largest_sent};
    };

    for (std::size_t round = 0; round < kMaxAckRounds && expected_offset < payload.size();
         ++round) {
        const auto burst_time =
            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 2 + 1));
        const auto [emitted_packets, largest_sent] = drain_burst(burst_time);
        static_cast<void>(largest_sent);
        const auto largest_outstanding =
            tracked_packet_count(connection.application_space_) == 0u
                ? std::optional<std::uint64_t>{}
                : std::optional<std::uint64_t>{
                      last_tracked_packet(connection.application_space_).packet_number,
                  };
        ASSERT_TRUE(emitted_packets > 0u || largest_outstanding.has_value())
            << "round=" << round << " expected_offset=" << expected_offset
            << " total_packets=" << total_packets
            << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
            << " cwnd=" << connection.congestion_controller_.congestion_window()
            << " sent_packets=" << tracked_packet_count(connection.application_space_)
            << " queued_bytes=" << connection.total_queued_stream_bytes()
            << " pending_send=" << connection.has_pending_application_send();
        ASSERT_TRUE(largest_outstanding.has_value());
        const std::uint64_t largest_acknowledged = optional_value_or_terminate(largest_outstanding);

        ASSERT_TRUE(connection
                        .process_inbound_ack(
                            connection.application_space_,
                            coquic::quic::AckFrame{
                                .largest_acknowledged = largest_acknowledged,
                                .first_ack_range = largest_acknowledged,
                            },
                            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 2 + 2)),
                            peer_transport_parameters.ack_delay_exponent,
                            peer_transport_parameters.max_ack_delay,
                            /*suppress_pto_reset=*/false)
                        .has_value());
    }

    EXPECT_EQ(expected_offset, payload.size())
        << "total_packets=" << total_packets
        << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
        << " cwnd=" << connection.congestion_controller_.congestion_window()
        << " sent_packets=" << tracked_packet_count(connection.application_space_)
        << " queued_bytes=" << connection.total_queued_stream_bytes()
        << " pending_send=" << connection.has_pending_application_send();
}

TEST(QuicCoreTest, ApplicationSendUsesConfiguredOutboundDatagramSizeLimit) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.config_.max_outbound_datagram_size = 4096;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = 4096;
    peer_transport_parameters.initial_max_data = std::uint64_t{64} * 1024u;
    peer_transport_parameters.initial_max_stream_data_bidi_remote = std::uint64_t{64} * 1024u;
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = std::size_t{64} * 1024u;

    const auto payload = std::vector<std::byte>(std::size_t{32} * 1024u, std::byte{0x42});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_GT(datagram.size(), 1200u);
    EXPECT_LE(datagram.size(), 4096u);
}

TEST(QuicCoreTest, ApplicationSendStopsAtUnpacedBurstLimitWithoutAckProgress) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(256u) * 1024u, std::byte{0x52});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto send_time = coquic::quic::test::test_time(1);

    std::size_t emitted_packets = 0;
    for (;;) {
        const auto datagram = connection.drain_outbound_datagram(send_time);
        if (datagram.empty()) {
            break;
        }
        ++emitted_packets;
    }

    EXPECT_EQ(emitted_packets, 10u);
    EXPECT_TRUE(connection.has_pending_fresh_application_stream_send());
    EXPECT_TRUE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, BbrPacingBlocksFurtherApplicationSendsUntilPacingWakeup) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.congestion_controller_ = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr,
        std::max<std::size_t>(1200, connection.config_.max_outbound_datagram_size));
    auto &bbr =
        std::get<coquic::quic::BbrCongestionController>(connection.congestion_controller_.storage_);
    bbr.mode_ = coquic::quic::BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};

    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(8u) * 1024u, std::byte{0x55});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto send_time = coquic::quic::test::test_time(1);
    const coquic::quic::DatagramBuffer first_datagram =
        connection.drain_outbound_datagram(send_time);
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing first paced datagram";
        return;
    }
    const coquic::quic::DatagramBuffer second_datagram =
        connection.drain_outbound_datagram(send_time);
    if (second_datagram.empty()) {
        ADD_FAILURE() << "missing second paced datagram";
        return;
    }

    const coquic::quic::DatagramBuffer blocked_datagram =
        connection.drain_outbound_datagram(send_time);
    if (!blocked_datagram.empty()) {
        ADD_FAILURE() << "pacing did not block the third datagram";
    }

    const std::optional<coquic::quic::QuicCoreTimePoint> pacing_deadline =
        connection.congestion_controller_.next_send_time(connection.outbound_datagram_size_limit());
    if (!pacing_deadline.has_value()) {
        ADD_FAILURE() << "missing pacing deadline";
        return;
    }
    const std::optional<coquic::quic::QuicCoreTimePoint> quantum_deadline =
        connection.congestion_controller_.next_send_time(
            connection.congestion_controller_.pacing_send_quantum());
    if (!quantum_deadline.has_value()) {
        ADD_FAILURE() << "missing quantum pacing deadline";
        return;
    }
    if (connection.next_wakeup() != quantum_deadline) {
        ADD_FAILURE() << "next wakeup did not use the quantum deadline";
    }
    if (connection.has_sendable_datagram(send_time + std::chrono::milliseconds(9))) {
        ADD_FAILURE() << "connection became sendable before pacing delay";
    }
    if (connection.has_sendable_datagram(optional_value_or_terminate(pacing_deadline))) {
        ADD_FAILURE() << "connection became sendable at single-datagram pacing deadline";
    }
    if (!connection.has_sendable_datagram(optional_value_or_terminate(quantum_deadline))) {
        ADD_FAILURE() << "connection was not sendable at quantum pacing deadline";
    }
    if (!connection.drain_outbound_datagram(send_time + std::chrono::milliseconds(9)).empty()) {
        ADD_FAILURE() << "connection drained a datagram before pacing delay";
    }
    if (connection.drain_outbound_datagram(optional_value_or_terminate(quantum_deadline)).empty()) {
        ADD_FAILURE() << "connection did not drain at quantum pacing deadline";
    }
}

TEST(QuicCoreTest, BbrPacingWakeupUsesSendQuantumForPureStreamData) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.congestion_controller_ = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr,
        std::max<std::size_t>(1200, connection.config_.max_outbound_datagram_size));
    auto &bbr =
        std::get<coquic::quic::BbrCongestionController>(connection.congestion_controller_.storage_);
    bbr.mode_ = coquic::quic::BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};
    bbr.send_quantum_ = 4800;

    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(32u) * 1024u, std::byte{0x59});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto send_time = coquic::quic::test::test_time(1);
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());

    const std::optional<coquic::quic::QuicCoreTimePoint> single_datagram_deadline =
        connection.congestion_controller_.next_send_time(connection.outbound_datagram_size_limit());
    const std::optional<coquic::quic::QuicCoreTimePoint> quantum_deadline =
        connection.congestion_controller_.next_send_time(
            connection.congestion_controller_.pacing_send_quantum());
    if (!single_datagram_deadline.has_value()) {
        ADD_FAILURE() << "missing single-datagram pacing deadline";
        return;
    }
    if (!quantum_deadline.has_value()) {
        ADD_FAILURE() << "missing quantum pacing deadline";
        return;
    }
    if (optional_value_or_terminate(single_datagram_deadline) >=
        optional_value_or_terminate(quantum_deadline)) {
        ADD_FAILURE() << "single-datagram pacing deadline was not earlier";
    }
    if (connection.pacing_deadline() != quantum_deadline) {
        ADD_FAILURE() << "pacing deadline did not use send quantum";
    }
    if (connection.next_wakeup() != quantum_deadline) {
        ADD_FAILURE() << "next wakeup did not use send quantum";
    }
    if (connection.has_sendable_datagram(optional_value_or_terminate(single_datagram_deadline))) {
        ADD_FAILURE() << "connection became sendable at single-datagram deadline";
    }
    if (!connection.has_sendable_datagram(optional_value_or_terminate(quantum_deadline))) {
        ADD_FAILURE() << "connection was not sendable at quantum deadline";
    }
}

TEST(QuicCoreTest, BbrPacingWakeupUsesSingleDatagramWhenRemainingStreamDataIsSmall) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.congestion_controller_ = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr,
        std::max<std::size_t>(1200, connection.config_.max_outbound_datagram_size));
    auto &bbr =
        std::get<coquic::quic::BbrCongestionController>(connection.congestion_controller_.storage_);
    bbr.mode_ = coquic::quic::BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};
    bbr.send_quantum_ = 4800;

    const auto payload = std::vector<std::byte>(
        static_cast<std::size_t>(5u) * connection.outbound_datagram_size_limit(), std::byte{0x5b});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto send_time = coquic::quic::test::test_time(1);
    for (std::size_t index = 0; index < 4; ++index) {
        ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());
    }

    const std::optional<coquic::quic::QuicCoreTimePoint> single_datagram_deadline =
        connection.congestion_controller_.next_send_time(connection.outbound_datagram_size_limit());
    const std::optional<coquic::quic::QuicCoreTimePoint> quantum_deadline =
        connection.congestion_controller_.next_send_time(
            connection.congestion_controller_.pacing_send_quantum());
    if (!single_datagram_deadline.has_value()) {
        ADD_FAILURE() << "missing single-datagram pacing deadline";
        return;
    }
    if (!quantum_deadline.has_value()) {
        ADD_FAILURE() << "missing quantum pacing deadline";
        return;
    }
    if (optional_value_or_terminate(single_datagram_deadline) >=
        optional_value_or_terminate(quantum_deadline)) {
        ADD_FAILURE() << "single-datagram pacing deadline was not earlier";
    }
    if (connection.pacing_deadline() != single_datagram_deadline) {
        ADD_FAILURE() << "pacing deadline did not use the single-datagram deadline";
    }
    if (connection.next_wakeup() != single_datagram_deadline) {
        ADD_FAILURE() << "next wakeup did not use the single-datagram deadline";
    }
}

TEST(QuicCoreTest, BbrPacingWakeupKeepsFullDatagramMinimumWithSmallCwndRemainder) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.congestion_controller_ = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr,
        std::max<std::size_t>(1200, connection.config_.max_outbound_datagram_size));
    auto &bbr =
        std::get<coquic::quic::BbrCongestionController>(connection.congestion_controller_.storage_);
    bbr.mode_ = coquic::quic::BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};
    bbr.send_quantum_ = 4800;

    const auto payload = std::vector<std::byte>(4096, std::byte{0x5a});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    connection.congestion_controller_.congestion_window_ =
        connection.outbound_datagram_size_limit();
    connection.congestion_controller_.bytes_in_flight_ =
        connection.outbound_datagram_size_limit() - 1u;

    EXPECT_FALSE(connection.has_sendable_datagram(coquic::quic::test::test_time(1)));
    EXPECT_FALSE(connection.pacing_deadline().has_value());
}

TEST(QuicCoreTest, CorePacingWakeupDrainsWithoutRunningConnectionTimeout) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.congestion_controller_ = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr,
        std::max<std::size_t>(1200, connection.config_.max_outbound_datagram_size));
    auto &bbr =
        std::get<coquic::quic::BbrCongestionController>(connection.congestion_controller_.storage_);
    bbr.mode_ = coquic::quic::BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};

    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(8u) * 1024u, std::byte{0x55});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto send_time = coquic::quic::test::test_time(1);
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());

    const std::optional<coquic::quic::QuicCoreTimePoint> pacing_deadline =
        connection.pacing_deadline();
    if (!pacing_deadline.has_value()) {
        ADD_FAILURE() << "missing pacing deadline";
        return;
    }
    const coquic::quic::QuicCoreTimePoint due = optional_value_or_terminate(pacing_deadline);
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/41, /*ack_eliciting=*/true, send_time);
    connection.application_space_.pending_ack_deadline = due + std::chrono::seconds{1};
    ASSERT_FALSE(connection.non_pacing_wakeup_due(due));

    coquic::quic::QuicCore core(coquic::quic::test::make_client_core_config());
    core.connection_ = std::make_unique<coquic::quic::QuicConnection>(std::move(connection));
    auto *entry = core.legacy_entry();
    ASSERT_NE(entry, nullptr);
    ASSERT_FALSE(coquic::quic::QuicCore::should_run_connection_timeout(*entry, due));
    const auto result = core.advance(coquic::quic::QuicCoreTimerExpired{}, due);

    EXPECT_FALSE(result.local_error.has_value());
    EXPECT_FALSE(result.effects.empty());
    EXPECT_TRUE(std::any_of(result.effects.begin(), result.effects.end(), [](const auto &effect) {
        return std::holds_alternative<coquic::quic::QuicCoreSendDatagram>(effect);
    }));
    ASSERT_NE(core.connection_.get(), nullptr);
    EXPECT_FALSE(core.connection_->application_space_.force_ack_send);
}

TEST(QuicCoreTest, CoreTimerStillRunsConnectionTimeoutForDueAckDeadline) {
    auto connection = make_connected_client_connection();
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = 4096;
    peer_transport_parameters.initial_max_stream_data_bidi_remote = 4096;
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/41, /*ack_eliciting=*/true, coquic::quic::test::test_time(1));
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(2);

    coquic::quic::QuicCore core(coquic::quic::test::make_client_core_config());
    core.connection_ = std::make_unique<coquic::quic::QuicConnection>(std::move(connection));
    auto *entry = core.legacy_entry();
    ASSERT_NE(entry, nullptr);
    ASSERT_TRUE(coquic::quic::QuicCore::should_run_connection_timeout(
        *entry, coquic::quic::test::test_time(2)));
    const auto result =
        core.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(2));

    EXPECT_FALSE(result.local_error.has_value());
    ASSERT_NE(core.connection_.get(), nullptr);
    const auto send_it =
        std::find_if(result.effects.begin(), result.effects.end(), [](const auto &effect) {
            return std::holds_alternative<coquic::quic::QuicCoreSendDatagram>(effect);
        });
    ASSERT_NE(send_it, result.effects.end());
    const auto &send = std::get<coquic::quic::QuicCoreSendDatagram>(*send_it);
    EXPECT_TRUE(datagram_has_application_ack(*core.connection_, send.bytes));
    EXPECT_FALSE(core.connection_->application_space_.force_ack_send);
    EXPECT_FALSE(core.connection_->application_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest, HasSendableDatagramRejectsCwndBlockedApplicationStreamData) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(4096, std::byte{0x56});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    ASSERT_TRUE(connection.minimum_pending_application_stream_datagram_bytes().has_value());
    const auto minimum_datagram_bytes =
        optional_value_or_terminate(connection.minimum_pending_application_stream_datagram_bytes());
    ASSERT_GT(connection.outbound_datagram_size_limit(), minimum_datagram_bytes);
    connection.congestion_controller_.congestion_window_ =
        connection.outbound_datagram_size_limit();
    connection.congestion_controller_.bytes_in_flight_ =
        connection.outbound_datagram_size_limit() - minimum_datagram_bytes + 1;

    EXPECT_FALSE(connection.has_sendable_datagram(coquic::quic::test::test_time(1)));
    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, HasSendableDatagramAllowsMinimumApplicationStreamDatagram) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(4096, std::byte{0x56});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    const auto minimum_datagram_bytes =
        optional_value_or_terminate(connection.minimum_pending_application_stream_datagram_bytes());
    ASSERT_GT(connection.outbound_datagram_size_limit(), minimum_datagram_bytes);
    connection.congestion_controller_.congestion_window_ =
        connection.outbound_datagram_size_limit();
    connection.congestion_controller_.bytes_in_flight_ =
        connection.outbound_datagram_size_limit() - minimum_datagram_bytes;

    EXPECT_TRUE(connection.has_sendable_datagram(coquic::quic::test::test_time(1)));
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), minimum_datagram_bytes);
    EXPECT_TRUE(datagram_has_application_stream(connection, datagram));
}

TEST(QuicCoreTest, HasSendableDatagramAllowsFullDatagramApplicationStreamData) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(4096, std::byte{0x58});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    connection.congestion_controller_.congestion_window_ =
        connection.outbound_datagram_size_limit();
    connection.congestion_controller_.bytes_in_flight_ = 0;

    EXPECT_TRUE(connection.has_sendable_datagram(coquic::quic::test::test_time(1)));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, HasSendableDatagramAllowsAckOnlyWhenApplicationStreamDataIsCwndBlocked) {
    auto connection = make_connected_client_connection();
    const auto payload = std::vector<std::byte>(4096, std::byte{0x57});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());
    const auto minimum_datagram_bytes =
        optional_value_or_terminate(connection.minimum_pending_application_stream_datagram_bytes());
    connection.congestion_controller_.congestion_window_ =
        connection.outbound_datagram_size_limit();
    connection.congestion_controller_.bytes_in_flight_ =
        connection.outbound_datagram_size_limit() - minimum_datagram_bytes;
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/41, /*ack_eliciting=*/true, coquic::quic::test::test_time(1));
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(1);

    EXPECT_TRUE(connection.has_sendable_datagram(coquic::quic::test::test_time(2)));
    const coquic::quic::DatagramBuffer datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(datagram.empty());
    EXPECT_TRUE(datagram_has_application_ack(connection, datagram));
}

TEST(QuicCoreTest, AckDueBeforeBbrQuantumDoesNotPullApplicationStreamData) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.congestion_controller_ = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr,
        std::max<std::size_t>(1200, connection.config_.max_outbound_datagram_size));
    auto &bbr =
        std::get<coquic::quic::BbrCongestionController>(connection.congestion_controller_.storage_);
    bbr.mode_ = coquic::quic::BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};
    bbr.send_quantum_ = 4800;

    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(32u) * 1024u, std::byte{0x5c});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto send_time = coquic::quic::test::test_time(1);
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());

    const std::optional<coquic::quic::QuicCoreTimePoint> single_datagram_deadline =
        connection.congestion_controller_.next_send_time(connection.outbound_datagram_size_limit());
    const std::optional<coquic::quic::QuicCoreTimePoint> quantum_deadline =
        connection.congestion_controller_.next_send_time(
            connection.congestion_controller_.pacing_send_quantum());
    ASSERT_TRUE(single_datagram_deadline.has_value());
    ASSERT_TRUE(quantum_deadline.has_value());
    ASSERT_LT(optional_value_or_terminate(single_datagram_deadline),
              optional_value_or_terminate(quantum_deadline));

    const auto ack_due = send_time + std::chrono::milliseconds{1};
    ASSERT_LT(ack_due, optional_value_or_terminate(quantum_deadline));
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/41, /*ack_eliciting=*/true, send_time);
    connection.application_space_.pending_ack_deadline = ack_due;

    EXPECT_TRUE(connection.has_sendable_datagram(ack_due));
    const coquic::quic::DatagramBuffer ack_datagram = connection.drain_outbound_datagram(ack_due);
    ASSERT_FALSE(ack_datagram.empty());
    EXPECT_TRUE(datagram_has_application_ack(connection, ack_datagram));
    EXPECT_FALSE(datagram_has_application_stream(connection, ack_datagram));
    EXPECT_FALSE(connection.last_drained_allows_send_continuation());
    EXPECT_TRUE(connection.has_pending_fresh_application_stream_send());
    EXPECT_FALSE(connection.has_sendable_datagram(ack_due));
    EXPECT_TRUE(connection.has_sendable_datagram(optional_value_or_terminate(quantum_deadline)));

    const coquic::quic::DatagramBuffer stream_datagram =
        connection.drain_outbound_datagram(optional_value_or_terminate(quantum_deadline));
    ASSERT_FALSE(stream_datagram.empty());
    EXPECT_FALSE(datagram_has_application_ack(connection, stream_datagram));
    EXPECT_TRUE(datagram_has_application_stream(connection, stream_datagram));
    EXPECT_TRUE(connection.last_drained_allows_send_continuation());
}

TEST(QuicCoreTest, ContinuedBbrPacedBurstCanSendBeforeNextQuantumDeadline) {
    auto connection = make_connected_client_connection();
    connection.config_.transport.pmtud_enabled = false;
    connection.congestion_controller_ = coquic::quic::QuicCongestionController(
        coquic::quic::QuicCongestionControlAlgorithm::bbr,
        std::max<std::size_t>(1200, connection.config_.max_outbound_datagram_size));
    auto &bbr =
        std::get<coquic::quic::BbrCongestionController>(connection.congestion_controller_.storage_);
    bbr.mode_ = coquic::quic::BbrCongestionController::Mode::probe_bw_cruise;
    bbr.max_bandwidth_bytes_per_second_ = 120000.0;
    bbr.bandwidth_bytes_per_second_ = 120000.0;
    bbr.pacing_rate_bytes_per_second_ = 120000.0;
    bbr.min_rtt_ = std::chrono::milliseconds{100};
    bbr.send_quantum_ = 4800;

    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(32u) * 1024u, std::byte{0x5d});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto send_time = coquic::quic::test::test_time(1);
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());
    ASSERT_FALSE(connection.drain_outbound_datagram(send_time).empty());

    const std::optional<coquic::quic::QuicCoreTimePoint> quantum_deadline =
        connection.congestion_controller_.next_send_time(
            connection.congestion_controller_.pacing_send_quantum());
    ASSERT_TRUE(quantum_deadline.has_value());
    const coquic::quic::QuicCoreTimePoint due = optional_value_or_terminate(quantum_deadline);
    std::size_t normally_paced_datagrams = 0;
    while (connection.has_sendable_datagram(due, /*continue_paced_burst=*/false)) {
        const coquic::quic::DatagramBuffer stream_datagram =
            connection.drain_outbound_datagram(due, /*continue_paced_burst=*/false);
        ASSERT_FALSE(stream_datagram.empty());
        EXPECT_TRUE(datagram_has_application_stream(connection, stream_datagram));
        EXPECT_TRUE(connection.last_drained_allows_send_continuation());
        ++normally_paced_datagrams;
        ASSERT_LT(normally_paced_datagrams, 8u);
    }
    EXPECT_GT(normally_paced_datagrams, 0u);
    ASSERT_TRUE(connection.has_pending_fresh_application_stream_send());
    EXPECT_FALSE(connection.has_sendable_datagram(due));
    EXPECT_TRUE(connection.has_sendable_datagram(due, /*continue_paced_burst=*/true));

    const coquic::quic::DatagramBuffer continued_stream_datagram =
        connection.drain_outbound_datagram(due, /*continue_paced_burst=*/true);
    ASSERT_FALSE(continued_stream_datagram.empty());
    EXPECT_TRUE(datagram_has_application_stream(connection, continued_stream_datagram));
    EXPECT_TRUE(connection.last_drained_allows_send_continuation());
}

TEST(QuicCoreTest, PathResponseCanBeSentWhileApplicationStreamDataIsQueued) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(256u) * 1024u, std::byte{0x53});
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.initial_max_data = payload.size();
    peer_transport_parameters.initial_max_stream_data_bidi_remote = payload.size();
    connection.initialize_peer_flow_control_from_transport_parameters();
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    auto &path =
        connection.ensure_path_state(optional_value_or_terminate(connection.current_send_path_id_));
    path.pending_response =
        std::array{std::byte{0x71}, std::byte{0x72}, std::byte{0x73}, std::byte{0x74},
                   std::byte{0x75}, std::byte{0x76}, std::byte{0x77}, std::byte{0x78}};

    bool saw_path_response = false;
    for (;;) {
        const coquic::quic::DatagramBuffer datagram =
            connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        const std::vector<coquic::quic::ProtectedPacket> packets =
            decode_sender_datagram(connection, datagram);
        ASSERT_EQ(packets.size(), 1u);
        const auto *application =
            std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
        ASSERT_NE(application, nullptr);
        saw_path_response |= std::any_of(
            application->frames.begin(), application->frames.end(), [](const auto &frame) {
                return std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
            });
    }

    EXPECT_TRUE(saw_path_response);
    EXPECT_FALSE(path.pending_response.has_value());
}

TEST(QuicCoreTest, ApplicationProbePacketDoesNotLeaveRetransmittedFragmentPending) {
    auto connection = make_connected_server_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;

    const auto payload = coquic::quic::test::bytes_from_string("probe-fragment");
    stream.send_buffer.append(payload);
    const auto initial_fragments = stream.take_send_fragments(payload.size());
    ASSERT_EQ(initial_fragments.size(), 1u);
    EXPECT_EQ(initial_fragments.front().offset, 0u);
    EXPECT_EQ(initial_fragments.front().bytes, payload);

    stream.mark_send_fragment_lost(initial_fragments.front());
    ASSERT_TRUE(stream.send_buffer.has_lost_data());

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 72,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments = initial_fragments,
    };

    const coquic::quic::DatagramBuffer probe_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(probe_datagram.empty());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());

    const std::vector<coquic::quic::ProtectedPacket> probe_packets =
        decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&probe_packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<coquic::quic::StreamFrame> stream_frames;
    for (const auto &frame : application->frames) {
        const auto *stream_frame = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream_frame != nullptr) {
            stream_frames.push_back(*stream_frame);
        }
    }

    ASSERT_EQ(stream_frames.size(), 1u);
    ASSERT_TRUE(stream_frames.front().offset.has_value());
    EXPECT_EQ(optional_value_or_terminate(stream_frames.front().offset), 0u);
    EXPECT_EQ(stream_frames.front().stream_data, payload);

    EXPECT_FALSE(stream.send_buffer.has_lost_data());
    EXPECT_FALSE(connection.has_pending_application_send());
    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(2)).empty());
}

TEST(QuicCoreTest, ApplicationSendDrainsLargePayloadAcrossDroppedCumulativeAckRounds) {
    auto connection = make_connected_server_connection();
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(128u) * 1024u, std::byte{0x45});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::uint64_t expected_offset = 0;
    std::size_t total_packets = 0;
    std::size_t dropped_ack_rounds = 0;
    constexpr std::size_t kMaxRounds = 1024;

    const auto drain_burst = [&](coquic::quic::QuicCoreTimePoint burst_time) {
        std::size_t emitted_packets = 0;
        std::uint64_t largest_sent = 0;
        for (;;) {
            const auto datagram = connection.drain_outbound_datagram(burst_time);
            if (datagram.empty()) {
                break;
            }

            const auto decoded = coquic::quic::deserialize_protected_datagram(
                datagram, coquic::quic::DeserializeProtectionContext{
                              .peer_role = connection.config_.role,
                              .client_initial_destination_connection_id =
                                  connection.client_initial_destination_connection_id(),
                              .handshake_secret = connection.handshake_space_.write_secret,
                              .one_rtt_secret = connection.application_space_.write_secret,
                              .one_rtt_key_phase = connection.application_write_key_phase_,
                              .largest_authenticated_initial_packet_number =
                                  connection.initial_space_.largest_authenticated_packet_number,
                              .largest_authenticated_handshake_packet_number =
                                  connection.handshake_space_.largest_authenticated_packet_number,
                              .largest_authenticated_application_packet_number =
                                  connection.application_space_.largest_authenticated_packet_number,
                              .one_rtt_destination_connection_id_length =
                                  connection.config_.source_connection_id.size(),
                          });
            EXPECT_TRUE(decoded.has_value());
            if (!decoded.has_value()) {
                continue;
            }

            const auto &packets = decoded.value();
            EXPECT_EQ(packets.size(), 1u);
            if (packets.size() != 1u) {
                continue;
            }

            const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
            EXPECT_NE(application, nullptr);
            if (application == nullptr) {
                continue;
            }

            largest_sent = application->packet_number;
            for (const auto &frame : application->frames) {
                const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
                if (stream == nullptr) {
                    continue;
                }

                EXPECT_TRUE(stream->offset.has_value());
                if (!stream->offset.has_value()) {
                    continue;
                }

                EXPECT_EQ(*stream->offset, expected_offset);
                expected_offset += static_cast<std::uint64_t>(stream->stream_data.size());
            }

            ++emitted_packets;
            ++total_packets;
        }

        return std::pair{emitted_packets, largest_sent};
    };

    for (std::size_t round = 0; round < kMaxRounds && expected_offset < payload.size(); ++round) {
        const auto burst_time =
            coquic::quic::test::test_time(static_cast<std::int64_t>(round * 4 + 1));
        const auto [emitted_packets, largest_sent] = drain_burst(burst_time);
        static_cast<void>(largest_sent);
        const auto largest_outstanding =
            tracked_packet_count(connection.application_space_) == 0u
                ? std::optional<std::uint64_t>{}
                : std::optional<std::uint64_t>{
                      last_tracked_packet(connection.application_space_).packet_number,
                  };
        ASSERT_TRUE(emitted_packets > 0u || largest_outstanding.has_value())
            << "round=" << round << " expected_offset=" << expected_offset
            << " total_packets=" << total_packets << " dropped_ack_rounds=" << dropped_ack_rounds
            << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
            << " cwnd=" << connection.congestion_controller_.congestion_window()
            << " sent_packets=" << tracked_packet_count(connection.application_space_)
            << " queued_bytes=" << connection.total_queued_stream_bytes()
            << " pending_send=" << connection.has_pending_application_send();

        if ((round % 5u) == 2u) {
            ++dropped_ack_rounds;
            continue;
        }

        ASSERT_TRUE(largest_outstanding.has_value());

        ASSERT_TRUE(
            connection
                .process_inbound_ack(
                    connection.application_space_,
                    coquic::quic::AckFrame{
                        .largest_acknowledged = optional_value_or_terminate(largest_outstanding),
                        .first_ack_range = optional_value_or_terminate(largest_outstanding),
                    },
                    coquic::quic::test::test_time(static_cast<std::int64_t>(round * 4 + 2)),
                    peer_transport_parameters.ack_delay_exponent,
                    peer_transport_parameters.max_ack_delay,
                    /*suppress_pto_reset=*/false)
                .has_value());
    }

    EXPECT_EQ(expected_offset, payload.size())
        << "total_packets=" << total_packets << " dropped_ack_rounds=" << dropped_ack_rounds
        << " bytes_in_flight=" << connection.congestion_controller_.bytes_in_flight()
        << " cwnd=" << connection.congestion_controller_.congestion_window()
        << " sent_packets=" << tracked_packet_count(connection.application_space_)
        << " queued_bytes=" << connection.total_queued_stream_bytes()
        << " pending_send=" << connection.has_pending_application_send();
}

TEST(QuicCoreTest, CongestionWindowGatesAckElicitingSendsUntilAckArrives) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(32) * 1024U, std::byte{0x43});

    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::size_t sent_datagrams = 0;
    while (true) {
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        ++sent_datagrams;
    }

    EXPECT_GT(sent_datagrams, 0u);
    EXPECT_TRUE(connection.has_pending_application_send());
    const auto blocked = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    EXPECT_TRUE(blocked.empty());

    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);
    ASSERT_TRUE(connection
                    .process_inbound_ack(
                        connection.application_space_,
                        coquic::quic::AckFrame{
                            .largest_acknowledged =
                                last_tracked_packet(connection.application_space_).packet_number,
                            .first_ack_range =
                                last_tracked_packet(connection.application_space_).packet_number,
                        },
                        coquic::quic::test::test_time(3),
                        /*ack_delay_exponent=*/3,
                        /*max_ack_delay_ms=*/25,
                        /*suppress_pto_reset=*/false)
                    .has_value());

    const coquic::quic::DatagramBuffer after_ack =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(4));
    EXPECT_FALSE(after_ack.empty());
}

TEST(QuicCoreTest, ConnectionNamespaceHelpersCoverEdgeCases) {
    EXPECT_TRUE(coquic::quic::test::connection_helper_edge_cases_for_tests());
}

TEST(QuicCoreTest, ConnectionNamespaceHelpersCoverAckDeadlineAndStreamUtilities) {
    EXPECT_TRUE(coquic::quic::test::connection_ack_deadline_and_stream_utilities_for_tests());
}

TEST(QuicCoreTest, ConnectionNamespaceHelpersCoverInstrumentedPrivateUtilities) {
    EXPECT_TRUE(coquic::quic::test::connection_instrumented_helper_coverage_for_tests());
}

TEST(QuicCoreTest, ConnectionNamespaceHelpersCoverHeaderPacketSpaceUtilities) {
    EXPECT_TRUE(coquic::quic::test::connection_header_packet_space_coverage_for_tests());
}

TEST(QuicCoreTest, ConnectionNamespaceHelpersCoverKeyUpdateAndProbeBranches) {
    EXPECT_TRUE(coquic::quic::test::connection_key_update_and_probe_coverage_for_tests());
}

TEST(QuicCoreTest, ConnectionNamespaceHelpersCoverPmtudBranches) {
    EXPECT_TRUE(coquic::quic::test::connection_pmtud_coverage_for_tests());
}

TEST(QuicCoreTest, PacketSpacePacketMapViewSkipsStaleLiveHandles) {
    coquic::quic::PacketSpaceRecovery recovery;
    coquic::quic::PacketSpacePacketMapView view(
        &recovery, coquic::quic::PacketSpacePacketMapView::Filter::outstanding);

    coquic::quic::test::PacketSpaceRecoveryTestPeer::install_stale_live_slot(recovery, 7);

    EXPECT_TRUE(view.empty());
    EXPECT_EQ(view.size(), 0u);
    EXPECT_FALSE(view.contains(7));
    EXPECT_EQ(view.begin(), view.end());
    EXPECT_EQ(view.rbegin(), view.rend());
}

TEST(QuicCoreTest, AckProcessingAccountsForLateAckedEcnPackets) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::probing;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(3),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 5,
                                     .sent_time = coquic::quic::test::test_time(5),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });
    const coquic::quic::RecoveryPacketHandle late_handle = optional_value_or_terminate(
        connection.application_space_.recovery.handle_for_packet_number(3));
    ASSERT_TRUE(
        connection.mark_lost_packet(connection.application_space_, late_handle).has_value());

    const coquic::quic::CodecResult<bool> processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 5,
                                           .first_ack_range = 0,
                                           .additional_ranges =
                                               {
                                                   coquic::quic::AckRange{
                                                       .gap = 0,
                                                       .range_length = 0,
                                                   },
                                               },
                                           .ecn_counts =
                                               coquic::quic::AckEcnCounts{
                                                   .ect0 = 2,
                                                   .ect1 = 0,
                                                   .ecn_ce = 0,
                                               },
                                       },
                                       coquic::quic::test::test_time(10), /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.recovery.find_packet(3), nullptr);
    EXPECT_EQ(connection.application_space_.recovery.find_packet(5), nullptr);
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 0u);
    EXPECT_FALSE(
        std::ranges::any_of(tracked_packet_snapshot(connection.application_space_),
                            [](const auto &sent_packet) { return sent_packet.declared_lost; }));
}

TEST(QuicCoreTest, CompatibilitySentPacketsViewRefreshesAfterRecoveryMetadataMutation) {
    auto connection = make_connected_client_connection();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 7,
                                     .sent_time = coquic::quic::test::test_time(7),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);
    EXPECT_FALSE(tracked_packet_or_terminate(connection.application_space_, 7).qlog_pto_probe);

    auto *recovery_packet = connection.application_space_.recovery.find_packet(7);
    ASSERT_NE(recovery_packet, nullptr);
    recovery_packet->qlog_pto_probe = true;
    connection.application_space_.recovery.note_packet_metadata_updated();

    EXPECT_TRUE(tracked_packet_or_terminate(connection.application_space_, 7).qlog_pto_probe);
}

TEST(QuicCoreTest, AckProcessingRetiresLateAckedPacketFromRecoveryLedger) {
    auto connection = make_connected_client_connection();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(3),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 5,
                                     .sent_time = coquic::quic::test::test_time(5),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                 });

    const coquic::quic::RecoveryPacketHandle late_handle = optional_value_or_terminate(
        connection.application_space_.recovery.handle_for_packet_number(3));
    EXPECT_TRUE(
        connection.mark_lost_packet(connection.application_space_, late_handle).has_value());

    const coquic::quic::CodecResult<bool> processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 5,
                                           .first_ack_range = 0,
                                           .additional_ranges =
                                               {
                                                   coquic::quic::AckRange{
                                                       .gap = 0,
                                                       .range_length = 0,
                                                   },
                                               },
                                       },
                                       coquic::quic::test::test_time(10),
                                       /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0,
                                       /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.recovery.find_packet(3), nullptr);
    EXPECT_EQ(connection.application_space_.recovery.find_packet(5), nullptr);
}

TEST(QuicCoreTest, AckProcessingDisablesEcnWhenPeerDecreasesEct1OrCeCounts) {
    struct CountCase {
        coquic::quic::AckEcnCounts previous_counts;
        coquic::quic::AckEcnCounts current_counts;
    };

    for (const auto &test_case : std::array{
             CountCase{
                 .previous_counts =
                     {
                         .ect0 = 1,
                         .ect1 = 2,
                         .ecn_ce = 3,
                     },
                 .current_counts =
                     {
                         .ect0 = 1,
                         .ect1 = 1,
                         .ecn_ce = 3,
                     },
             },
             CountCase{
                 .previous_counts =
                     {
                         .ect0 = 1,
                         .ect1 = 1,
                         .ecn_ce = 2,
                     },
                 .current_counts =
                     {
                         .ect0 = 1,
                         .ect1 = 1,
                         .ecn_ce = 1,
                     },
             },
         }) {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.ecn.state = coquic::quic::QuicPathEcnState::capable;
        path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;
        path.ecn.has_last_peer_counts[2] = true;
        path.ecn.last_peer_counts[2] = test_case.previous_counts;

        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(1),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                         .path_id = 0,
                                         .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                     });

        const coquic::quic::CodecResult<bool> processed = connection.process_inbound_ack(
            connection.application_space_,
            coquic::quic::AckFrame{
                .largest_acknowledged = 1,
                .first_ack_range = 0,
                .ecn_counts = test_case.current_counts,
            },
            coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
            /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

        ASSERT_TRUE(processed.has_value());
        EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
    }
}

TEST(QuicCoreTest, AckProcessingDisablesEcnWhenPeerCountsDecrease) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::capable;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;
    path.ecn.has_last_peer_counts[2] = true;
    path.ecn.last_peer_counts[2] = coquic::quic::AckEcnCounts{
        .ect0 = 2,
        .ect1 = 0,
        .ecn_ce = 0,
    };

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });

    const coquic::quic::CodecResult<bool> processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 1,
                                           .first_ack_range = 0,
                                           .ecn_counts =
                                               coquic::quic::AckEcnCounts{
                                                   .ect0 = 1,
                                                   .ect1 = 0,
                                                   .ecn_ce = 0,
                                               },
                                       },
                                       coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
    EXPECT_FALSE(path.ecn.has_last_peer_counts[2]);
    EXPECT_EQ(connection.outbound_ecn_codepoint_for_path(0),
              coquic::quic::QuicEcnCodepoint::not_ect);
}

TEST(QuicCoreTest, AckProcessingDisablesEcnWhenEct1FeedbackIsMissingOrImpossible) {
    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.ecn.state = coquic::quic::QuicPathEcnState::capable;
        path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect1;

        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(1),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                         .path_id = 0,
                                         .ecn = coquic::quic::QuicEcnCodepoint::ect1,
                                     });

        const auto missing_feedback = connection.process_inbound_ack(
            connection.application_space_,
            coquic::quic::AckFrame{
                .largest_acknowledged = 1,
                .first_ack_range = 0,
                .ecn_counts =
                    coquic::quic::AckEcnCounts{
                        .ect0 = 0,
                        .ect1 = 0,
                        .ecn_ce = 0,
                    },
            },
            coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
            /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

        ASSERT_TRUE(missing_feedback.has_value());
        EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
    }

    {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.ecn.state = coquic::quic::QuicPathEcnState::capable;
        path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;

        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(1),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                         .path_id = 0,
                                         .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                     });

        const auto impossible_feedback = connection.process_inbound_ack(
            connection.application_space_,
            coquic::quic::AckFrame{
                .largest_acknowledged = 1,
                .first_ack_range = 0,
                .ecn_counts =
                    coquic::quic::AckEcnCounts{
                        .ect0 = 1,
                        .ect1 = 1,
                        .ecn_ce = 0,
                    },
            },
            coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
            /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

        ASSERT_TRUE(impossible_feedback.has_value());
        EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::failed);
    }
}

TEST(QuicCoreTest, AckProcessingKeepsProbingWhenAckedPacketsWereNotEctMarked) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::probing;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::not_ect,
                                 });

    const auto processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 1,
                                           .first_ack_range = 0,
                                           .ecn_counts =
                                               coquic::quic::AckEcnCounts{
                                                   .ect0 = 0,
                                                   .ect1 = 0,
                                                   .ecn_ce = 0,
                                               },
                                       },
                                       coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::probing);
    EXPECT_EQ(path.ecn.probing_packets_acked, 0u);
}

TEST(QuicCoreTest, AckProcessingPromotesProbingPathWhenAckedProbeCountsOnlyCeMarks) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::probing;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                     .path_id = 0,
                                     .ecn = coquic::quic::QuicEcnCodepoint::ect0,
                                 });

    const auto processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::AckFrame{
                                           .largest_acknowledged = 1,
                                           .first_ack_range = 0,
                                           .ecn_counts =
                                               coquic::quic::AckEcnCounts{
                                                   .ect0 = 0,
                                                   .ect1 = 0,
                                                   .ecn_ce = 1,
                                               },
                                       },
                                       coquic::quic::test::test_time(3), /*ack_delay_exponent=*/0,
                                       /*max_ack_delay_ms=*/0, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::capable);
    EXPECT_EQ(path.ecn.probing_packets_acked, 1u);
}

TEST(QuicCoreTest, MarkLostPacketKeepsEcnProbingWhenProbeLossIsNotConclusive) {
    struct LossCase {
        std::uint64_t probing_packets_sent;
        std::uint64_t probing_packets_acked;
    };

    for (const auto &test_case : std::array{
             LossCase{
                 .probing_packets_sent = 0,
                 .probing_packets_acked = 0,
             },
             LossCase{
                 .probing_packets_sent = 1,
                 .probing_packets_acked = 1,
             },
             LossCase{
                 .probing_packets_sent = 2,
                 .probing_packets_acked = 0,
             },
         }) {
        auto connection = make_connected_client_connection();
        auto &path = connection.ensure_path_state(0);
        path.ecn.state = coquic::quic::QuicPathEcnState::probing;
        path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::ect0;
        path.ecn.probing_packets_sent = test_case.probing_packets_sent;
        path.ecn.probing_packets_acked = test_case.probing_packets_acked;

        const auto packet = coquic::quic::SentPacketRecord{
            .packet_number = 9,
            .sent_time = coquic::quic::test::test_time(1),
            .ack_eliciting = true,
            .in_flight = true,
            .bytes_in_flight = 1200,
            .path_id = 0,
            .ecn = coquic::quic::QuicEcnCodepoint::ect0,
        };
        connection.application_space_.recovery.on_packet_sent(packet);

        connection.mark_lost_packet(
            connection.application_space_,
            optional_value_or_terminate(
                connection.application_space_.recovery.handle_for_packet_number(
                    packet.packet_number)));

        EXPECT_EQ(path.ecn.state, coquic::quic::QuicPathEcnState::probing);
    }
}

TEST(QuicCoreTest, OutboundEcnCodepointReturnsNotEctWhenPathTransmitMarkIsUnmarked) {
    auto connection = make_connected_client_connection();
    auto &path = connection.ensure_path_state(0);
    path.ecn.state = coquic::quic::QuicPathEcnState::capable;
    path.ecn.transmit_mark = coquic::quic::QuicEcnCodepoint::not_ect;

    EXPECT_EQ(connection.outbound_ecn_codepoint_for_path(0),
              coquic::quic::QuicEcnCodepoint::not_ect);
}

TEST(QuicCoreTest, ApplicationCloseDrainReturnsEmptyWithoutOneRttKeys) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 9,
                        .reason_phrase = "closing",
                    })
                    .has_value());
    connection.application_space_.write_secret.reset();

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    EXPECT_TRUE(datagram.empty());
}

TEST(QuicCoreTest, TinyDatagramBudgetTruncatesApplicationCloseReason) {
    auto connection = make_connected_client_connection();
    connection.config_.max_outbound_datagram_size = 48;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = 48;

    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 11,
                        .reason_phrase = std::string(256, 'x'),
                    })
                    .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *packet = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(packet, nullptr);
    const auto close_it =
        std::find_if(packet->frames.begin(), packet->frames.end(), [](const auto &frame) {
            return std::holds_alternative<coquic::quic::ApplicationConnectionCloseFrame>(frame);
        });
    ASSERT_NE(close_it, packet->frames.end());
    const auto &close_frame = std::get<coquic::quic::ApplicationConnectionCloseFrame>(*close_it);
    EXPECT_TRUE(close_frame.reason.bytes.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, TinyDatagramBudgetWithEmptyApplicationCloseReasonFallsBackToEmpty) {
    bool found_budget = false;
    for (std::size_t max_datagram_size = 1200; max_datagram_size >= 1; --max_datagram_size) {
        auto connection = make_connected_client_connection();
        connection.config_.max_outbound_datagram_size = max_datagram_size;
        auto &peer_transport_parameters =
            optional_ref_or_terminate(connection.peer_transport_parameters_);
        peer_transport_parameters.max_udp_payload_size = max_datagram_size;

        ASSERT_TRUE(connection
                        .queue_application_close({
                            .application_error_code = 12,
                            .reason_phrase = "",
                        })
                        .has_value());

        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (!datagram.empty() || connection.has_failed()) {
            if (max_datagram_size == 1) {
                break;
            }
            continue;
        }

        found_budget = true;
        break;
    }

    EXPECT_TRUE(found_budget);
}

TEST(QuicCoreTest, TinyDatagramBudgetFailsWhenApplicationCloseRetryWithoutReasonCannotSerialize) {
    auto connection = make_connected_client_connection();
    connection.config_.max_outbound_datagram_size = 48;
    auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    peer_transport_parameters.max_udp_payload_size = 48;

    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 12,
                        .reason_phrase = std::string(256, 'y'),
                    })
                    .has_value());
    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, AntiAmplificationAccountingSaturatesBudgetAndCounters) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.peer_address_validated_ = false;

    connection.anti_amplification_received_bytes_ =
        (std::numeric_limits<std::uint64_t>::max() / 3u) + 1u;
    EXPECT_EQ(connection.anti_amplification_send_budget(),
              std::numeric_limits<std::uint64_t>::max());

    connection.anti_amplification_received_bytes_ = std::numeric_limits<std::uint64_t>::max() - 4u;
    connection.note_inbound_datagram_bytes(8);
    EXPECT_EQ(connection.anti_amplification_received_bytes_,
              std::numeric_limits<std::uint64_t>::max());

    connection.anti_amplification_sent_bytes_ = std::numeric_limits<std::uint64_t>::max() - 4u;
    connection.note_outbound_datagram_bytes(8);
    EXPECT_EQ(connection.anti_amplification_sent_bytes_, std::numeric_limits<std::uint64_t>::max());
}

TEST(QuicCoreTest, ProcessInboundDatagramDropsOneRttPacketWithoutReadSecret) {
    coquic::quic::QuicConnection connection(make_connected_client_connection());
    const auto one_rtt_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});
    connection.application_space_.read_secret.reset();

    const auto packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 0,
                .frames =
                    {
                        coquic::quic::test::make_inbound_application_stream_frame(
                            "missing-read-secret-packet"),
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = std::nullopt,
            .one_rtt_secret = one_rtt_secret,
        });
    ASSERT_TRUE(packet.has_value()) << static_cast<int>(packet.error().code);

    connection.process_inbound_datagram(packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
}

TEST(QuicCoreTest, ServerDefersOneRttDataUntilHandshakeCompletionWhenKeysAlreadyExist) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        to_server, server, coquic::quic::test::test_time(1));
    const auto client_handshake = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(2));

    const auto request = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("buffer-me"),
            .fin = true,
        },
        coquic::quic::test::test_time(3));

    const auto handshake_datagrams = coquic::quic::test::send_datagrams_from(client_handshake);
    const auto request_datagrams = coquic::quic::test::send_datagrams_from(request);
    ASSERT_FALSE(handshake_datagrams.empty());
    ASSERT_FALSE(request_datagrams.empty());

    const auto find_packet_datagram_index = [&](std::span<const std::vector<std::byte>> datagrams,
                                                auto matches_packet) -> std::optional<std::size_t> {
        for (std::size_t index = 0; index < datagrams.size(); ++index) {
            const auto decoded_packets =
                decode_sender_datagram(*client.connection_, datagrams[index]);
            for (const auto &decoded_packet : decoded_packets) {
                if (matches_packet(decoded_packet)) {
                    return index;
                }
            }
        }

        return std::nullopt;
    };

    const std::optional<std::size_t> has_handshake_datagram =
        find_packet_datagram_index(handshake_datagrams, [](const auto &decoded_packet) {
            return std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(decoded_packet);
        });
    const std::optional<std::size_t> one_rtt_datagram_index =
        find_packet_datagram_index(request_datagrams, [](const auto &decoded_packet) {
            return std::holds_alternative<coquic::quic::ProtectedOneRttPacket>(decoded_packet);
        });
    ASSERT_TRUE(has_handshake_datagram.has_value());
    ASSERT_TRUE(one_rtt_datagram_index.has_value());
    ASSERT_TRUE(server.connection_->application_space_.read_secret.has_value());

    const auto server_before_completion = coquic::quic::test::relay_nth_send_datagram_to_peer(
        request, optional_value_or_terminate(one_rtt_datagram_index), server,
        coquic::quic::test::test_time(4));
    EXPECT_TRUE(
        coquic::quic::test::received_application_data_from(server_before_completion).empty());
    EXPECT_FALSE(server.has_failed());
    ASSERT_EQ(server.connection_->deferred_protected_packets_.size(), 1u);

    const auto server_after_completion = coquic::quic::test::relay_send_datagrams_to_peer(
        client_handshake, server, coquic::quic::test::test_time(5));
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(server_after_completion)),
              "buffer-me");
    EXPECT_FALSE(server.has_failed());
    EXPECT_TRUE(server.connection_->deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramResyncsHandshakeStateBeforeOneRttControls) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    auto &connection = *client.connection_;
    ASSERT_TRUE(connection.tls_.has_value());
    if (!connection.tls_.has_value()) {
        return;
    }
    auto &tls = connection.tls_.value();
    ASSERT_TRUE(tls.handshake_complete());
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_TRUE(connection.peer_transport_parameters_validated_);

    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto
        control_packet =
            coquic::quic::serialize_protected_datagram(
                std::array<coquic::quic::ProtectedPacket, 1>{
                    coquic::quic::ProtectedOneRttPacket{
                        .destination_connection_id = connection.config_.source_connection_id,
                        .packet_number_length = 2,
                        .packet_number = 0,
                        .frames =
                            {
                                coquic::quic::NewConnectionIdFrame{
                                    .sequence_number = 2,
                                    .retire_prior_to = 1,
                                    .connection_id = bytes_from_ints({0x12, 0x34, 0x56, 0x78}),
                                    .stateless_reset_token =
                                        {
                                            std::byte{0x00},
                                            std::byte{0x01},
                                            std::byte{0x02},
                                            std::byte{0x03},
                                            std::byte{0x04},
                                            std::byte{0x05},
                                            std::byte{0x06},
                                            std::byte{0x07},
                                            std::byte{0x08},
                                            std::byte{0x09},
                                            std::byte{0x0a},
                                            std::byte{0x0b},
                                            std::byte{0x0c},
                                            std::byte{0x0d},
                                            std::byte{0x0e},
                                            std::byte{0x0f},
                                        },
                                },
                            },
                    },
                },
                coquic::quic::SerializeProtectionContext{
                    .local_role = coquic::quic::EndpointRole::server,
                    .client_initial_destination_connection_id =
                        connection.client_initial_destination_connection_id(),
                    .handshake_secret = connection.handshake_space_.read_secret,
                    .one_rtt_secret = connection.application_space_.read_secret,
                });
    ASSERT_TRUE(control_packet.has_value());

    connection.process_inbound_datagram(control_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
}

TEST(QuicCoreTest, DuplicateAckElicitingInitialQueuesServerHandshakeRecoveryProbe) {
    coquic::quic::QuicConnection server(coquic::quic::test::make_server_core_config());
    server.started_ = true;
    server.status_ = coquic::quic::HandshakeStatus::in_progress;
    server.initial_space_.received_packets.record_received(7, /*ack_eliciting=*/true,
                                                           coquic::quic::test::test_time(0));
    server.track_sent_packet(server.handshake_space_,
                             coquic::quic::SentPacketRecord{
                                 .packet_number = 3,
                                 .sent_time = coquic::quic::test::test_time(0),
                                 .ack_eliciting = true,
                                 .in_flight = true,
                             });

    const auto processed = server.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = server.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x44, 0x55}),
            .packet_number_length = 2,
            .packet_number = 7,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());
    ASSERT_TRUE(server.handshake_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(optional_value_or_terminate(server.handshake_space_.pending_probe_packet).has_ping);
}

TEST(QuicCoreTest, ClientHandshakeKeepalivePtoDeadlineArmsProbeWithoutInflightPackets) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(0);

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(
        optional_value_or_terminate(connection.initial_space_.pending_probe_packet).has_ping);
    EXPECT_EQ(connection.remaining_pto_probe_datagrams_, 2);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveUsesHandshakeSpaceOnceHandshakeKeysExist) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(0);
    connection.handshake_space_.write_secret = make_test_traffic_secret();

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());

    connection.arm_pto_probe(deadline.value_or(coquic::quic::test::test_time(1000)));

    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    ASSERT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(
        optional_value_or_terminate(connection.handshake_space_.pending_probe_packet).has_ping);

    const auto datagram =
        connection.drain_outbound_datagram(deadline.value_or(coquic::quic::test::test_time(1000)));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front()), nullptr);
}

TEST(QuicCoreTest, ClientHandshakeRecoveryProbeBypassesCongestionForFirstHandshakeResponse) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hs"));
    connection.handshake_space_.received_packets.record_received(
        /*packet_number=*/7, /*ack_eliciting=*/true, coquic::quic::test::test_time(1));
    connection.handshake_space_.pending_ack_deadline = coquic::quic::test::test_time(1);
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.congestion_controller_.congestion_window_ = 2400;
    connection.congestion_controller_.bytes_in_flight_ = 2400;

    const coquic::quic::DatagramBuffer datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.handshake_space_.send_crypto.has_pending_data());
    EXPECT_TRUE(connection.initial_packet_space_discarded_);

    const std::vector<coquic::quic::ProtectedPacket> packets =
        decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front());
    ASSERT_NE(handshake, nullptr);
    EXPECT_NE(std::find_if(handshake->frames.begin(), handshake->frames.end(),
                           [](const auto &frame) {
                               return std::holds_alternative<coquic::quic::CryptoFrame>(frame);
                           }),
              handshake->frames.end());
}

TEST(QuicCoreTest, ClientReceiveKeepalivePtoDeadlineArmsProbeWithoutInflightPackets) {
    auto connection = make_connected_client_connection();
    connection.current_send_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(1).is_current_send_path = true;
    connection.last_validated_path_id_ = 1;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.streams_.emplace(
        0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));

    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto expected_deadline = coquic::quic::compute_pto_deadline(
        connection.shared_recovery_rtt_state(),
        std::chrono::milliseconds(peer_transport_parameters.max_ack_delay),
        coquic::quic::test::test_time(4), 2);
    const auto deadline = connection.pto_deadline();
    EXPECT_EQ(deadline, std::optional{expected_deadline});
    EXPECT_EQ(connection.next_wakeup(), std::optional{expected_deadline});

    const auto deadline_value = optional_value_or_terminate(deadline);
    connection.arm_pto_probe(deadline_value);

    ASSERT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(
        optional_value_or_terminate(connection.application_space_.pending_probe_packet).has_ping);
    EXPECT_EQ(connection.remaining_pto_probe_datagrams_, 2);

    const coquic::quic::DatagramBuffer datagram =
        connection.drain_outbound_datagram(deadline_value);
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{1});
    EXPECT_EQ(connection.last_client_receive_keepalive_probe_time_, std::optional{deadline_value});

    const auto next_expected_deadline = coquic::quic::compute_pto_deadline(
        connection.shared_recovery_rtt_state(),
        std::chrono::milliseconds(peer_transport_parameters.max_ack_delay), deadline_value, 2);
    EXPECT_EQ(connection.pto_deadline(), std::optional{next_expected_deadline});
}

TEST(QuicCoreTest, ClientReceiveKeepalivePtoDeadlineArmsProbeWithApplicationInFlight) {
    auto connection = make_connected_client_connection();
    connection.streams_.emplace(
        0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(1);
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 73,
                                     .sent_time = coquic::quic::test::test_time(2000),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 32,
                                     .path_id = 0,
                                 });

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    const auto regular_application_pto = coquic::quic::compute_pto_deadline(
        connection.shared_recovery_rtt_state(), std::chrono::milliseconds(25),
        coquic::quic::test::test_time(2000), 0);
    EXPECT_TRUE(optional_value_or_terminate(deadline) < regular_application_pto);

    connection.arm_pto_probe(optional_value_or_terminate(deadline));

    ASSERT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(
        optional_value_or_terminate(connection.application_space_.pending_probe_packet).force_ack);

    const coquic::quic::DatagramBuffer datagram =
        connection.drain_outbound_datagram(optional_value_or_terminate(deadline));
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{0});
}

TEST(QuicCoreTest, ClientReceiveKeepaliveSkipsPathChallengeOnUnvalidatedCurrentPath) {
    auto connection = make_connected_client_connection();
    connection.streams_.emplace(
        0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));
    connection.ensure_path_state(0).is_current_send_path = false;
    connection.current_send_path_id_ = 1;
    connection.ensure_path_state(1).validated = false;
    connection.ensure_path_state(1).is_current_send_path = true;
    connection.last_validated_path_id_ = 0;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(0);
    connection.ensure_path_state(1).outstanding_challenge.reset();
    connection.ensure_path_state(1).challenge_pending = false;

    const auto datagram = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 17,
                .frames =
                    {
                        coquic::quic::PingFrame{},
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(datagram.has_value());

    connection.process_inbound_datagram(datagram.value(), coquic::quic::test::test_time(1),
                                        /*path_id=*/1);
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_FALSE(connection.ensure_path_state(1).challenge_pending);

    const coquic::quic::QuicCoreTimePoint ack_deadline =
        optional_value_or_terminate(connection.application_space_.pending_ack_deadline);
    connection.on_timeout(ack_deadline);

    const coquic::quic::DatagramBuffer response = connection.drain_outbound_datagram(ack_deadline);
    ASSERT_FALSE(response.empty());
    EXPECT_EQ(connection.last_drained_path_id(), 1u);

    const std::vector<coquic::quic::ProtectedPacket> packets =
        decode_sender_datagram(connection, response);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool ack_frame_seen = false;
    bool saw_path_challenge = false;
    for (const auto &frame : application->frames) {
        ack_frame_seen = ack_frame_seen || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(ack_frame_seen);
    EXPECT_FALSE(saw_path_challenge);
}

TEST(QuicCoreTest, ClientReceiveKeepaliveSkipsPathChallengeOnValidatedCurrentPath) {
    auto connection = make_connected_client_connection();
    connection.current_send_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(1).is_current_send_path = true;
    connection.last_validated_path_id_ = 1;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.streams_.emplace(
        0, coquic::quic::make_implicit_stream_state(0, connection.config_.role));

    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    const auto deadline = coquic::quic::compute_pto_deadline(
        connection.shared_recovery_rtt_state(),
        std::chrono::milliseconds(peer_transport_parameters.max_ack_delay),
        coquic::quic::test::test_time(4), 2);

    connection.arm_pto_probe(deadline);

    ASSERT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.ensure_path_state(1).challenge_pending);
    EXPECT_FALSE(connection.ensure_path_state(1).outstanding_challenge.has_value());

    const coquic::quic::DatagramBuffer datagram = connection.drain_outbound_datagram(deadline);
    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_client_receive_keepalive_probe_time_, std::optional{deadline});

    const std::vector<coquic::quic::ProtectedPacket> packets =
        decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ping = false;
    bool saw_path_challenge = false;
    for (const auto &frame : application->frames) {
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
    }

    EXPECT_TRUE(saw_ping);
    EXPECT_FALSE(saw_path_challenge);
}

TEST(QuicCoreTest, ClientReceiveKeepalivePtoDeadlineStaysArmedAfterPartialResponseFlow) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto request = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        request, server, coquic::quic::test::test_time(2));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(request_delivered).empty());

    const auto response_payload =
        coquic::quic::test::bytes_from_string(std::string(static_cast<std::size_t>(2048), 'r'));
    const auto response = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = response_payload,
            .fin = false,
        },
        coquic::quic::test::test_time(3));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(response).empty());

    const auto response_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        response, client, coquic::quic::test::test_time(4));
    EXPECT_EQ(coquic::quic::test::received_application_data_from(response_delivered),
              response_payload);

    ASSERT_TRUE(client.connection_->handshake_confirmed_);
    ASSERT_TRUE(client.connection_->streams_.contains(0));
    EXPECT_FALSE(client.connection_->streams_.at(0).peer_fin_delivered);

    const std::optional<coquic::quic::QuicCoreTimePoint> deadline =
        client.connection_->next_wakeup();
    ASSERT_TRUE(deadline.has_value());

    const coquic::quic::QuicCoreResult timeout_result =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, optional_value_or_terminate(deadline));
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(timeout_result).empty());
}

TEST(QuicCoreTest, LargePartialResponseSchedulesAckAndClearsOutstandingRequest) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto request = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        request, server, coquic::quic::test::test_time(2));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(request_delivered).empty());

    const auto response_payload = coquic::quic::test::bytes_from_string(
        std::string(static_cast<std::size_t>(256) * 1024u, 'r'));
    const auto response = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = response_payload,
            .fin = false,
        },
        coquic::quic::test::test_time(3));
    const auto response_datagrams = coquic::quic::test::send_datagrams_from(response);
    ASSERT_FALSE(response_datagrams.empty());

    EXPECT_TRUE(std::any_of(
        response_datagrams.begin(), response_datagrams.end(), [&](const auto &response_datagram) {
            return datagram_has_application_ack(*server.connection_, response_datagram);
        }));

    auto response_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        response, client, coquic::quic::test::test_time(4));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(response_delivered).empty());
    if (coquic::quic::test::send_datagrams_from(response_delivered).empty()) {
        const std::optional<coquic::quic::QuicCoreTimePoint> ack_deadline =
            client.connection_->next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        response_delivered = client.advance(coquic::quic::QuicCoreTimerExpired{},
                                            optional_value_or_terminate(ack_deadline));
    }
    const auto ack_datagrams = coquic::quic::test::send_datagrams_from(response_delivered);
    EXPECT_FALSE(ack_datagrams.empty());
    EXPECT_TRUE(std::any_of(
        ack_datagrams.begin(), ack_datagrams.end(), [&](const auto &client_ack_datagram) {
            return datagram_has_application_ack(*client.connection_, client_ack_datagram);
        }));

    ASSERT_TRUE(client.connection_->handshake_confirmed_);
    ASSERT_TRUE(client.connection_->streams_.contains(0));
    EXPECT_FALSE(client.connection_->streams_.at(0).has_outstanding_send());
}

TEST(QuicCoreTest, ClientTimerAfterLargePartialResponseFlowSendsAckBeforeOrOnProbe) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto request = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("GET /\r\n"),
            .fin = true,
        },
        coquic::quic::test::test_time(1));
    const auto request_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        request, server, coquic::quic::test::test_time(2));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(request_delivered).empty());

    const auto response_payload = coquic::quic::test::bytes_from_string(
        std::string(static_cast<std::size_t>(256) * 1024u, 'r'));
    const auto response = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = response_payload,
            .fin = false,
        },
        coquic::quic::test::test_time(3));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(response).empty());

    const auto response_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        response, client, coquic::quic::test::test_time(4));
    EXPECT_FALSE(coquic::quic::test::received_application_data_from(response_delivered).empty());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(response_delivered).empty());

    struct ClientAckObserver {
        static void note(const coquic::quic::QuicConnection &client_connection,
                         const coquic::quic::QuicCoreResult &core_result, bool &ack_detected) {
            for (const auto &outbound_datagram :
                 coquic::quic::test::send_datagrams_from(core_result)) {
                for (const auto &decoded_packet :
                     decode_sender_datagram(client_connection, outbound_datagram)) {
                    const auto *one_rtt_packet =
                        std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded_packet);
                    if (one_rtt_packet == nullptr) {
                        continue;
                    }
                    for (const auto &frame : one_rtt_packet->frames) {
                        ack_detected =
                            ack_detected || std::holds_alternative<coquic::quic::AckFrame>(frame);
                    }
                }
            }
        }
    };
    bool client_ack_observed = false;
    ClientAckObserver::note(*client.connection_, response_delivered, client_ack_observed);

    ASSERT_TRUE(client.connection_->handshake_confirmed_);
    auto to_server = response_delivered;
    auto to_client = coquic::quic::QuicCoreResult{};
    auto step_now = coquic::quic::test::test_time(5);
    for (int i = 0; i < 64; ++i) {
        if (!coquic::quic::test::send_datagrams_from(to_server).empty()) {
            ClientAckObserver::note(*client.connection_, to_server, client_ack_observed);
            to_client =
                coquic::quic::test::relay_send_datagrams_to_peer(to_server, server, step_now);
            to_server.effects.clear();
            step_now += std::chrono::milliseconds(1);
            continue;
        }

        if (!coquic::quic::test::send_datagrams_from(to_client).empty()) {
            to_server =
                coquic::quic::test::relay_send_datagrams_to_peer(to_client, client, step_now);
            to_client.effects.clear();
            step_now += std::chrono::milliseconds(1);
            continue;
        }

        break;
    }

    const std::vector<coquic::quic::SentPacketRecord> sent_packets =
        tracked_packet_snapshot(client.connection_->application_space_);
    ASSERT_LE(std::count_if(sent_packets.begin(), sent_packets.end(),
                            [](const auto &sent_packet) {
                                return sent_packet.ack_eliciting && sent_packet.in_flight;
                            }),
              std::ptrdiff_t{1});

    const std::optional<coquic::quic::QuicCoreTimePoint> deadline =
        client.connection_->next_wakeup();
    ASSERT_TRUE(deadline.has_value());

    const coquic::quic::QuicCoreResult timeout_result =
        client.advance(coquic::quic::QuicCoreTimerExpired{}, optional_value_or_terminate(deadline));
    const auto timeout_datagrams = coquic::quic::test::send_datagrams_from(timeout_result);
    ASSERT_FALSE(timeout_datagrams.empty());
    ClientAckObserver::note(*client.connection_, timeout_result, client_ack_observed);

    EXPECT_TRUE(client_ack_observed);
}

TEST(QuicCoreTest, SelectPtoProbePrefersRetransmittableCryptoOverPingFallback) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.send_crypto.append(bytes_from_ints({0xaa}));
    const auto crypto_ranges = connection.handshake_space_.send_crypto.take_ranges(1);
    ASSERT_EQ(crypto_ranges.size(), 1u);

    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .crypto_ranges = crypto_ranges,
                                 });

    const coquic::quic::SentPacketRecord probe =
        connection.select_pto_probe(connection.handshake_space_);

    EXPECT_EQ(probe.packet_number, 2u);
    EXPECT_EQ(probe.crypto_ranges.size(), 1u);
}

TEST(QuicCoreTest, AckOnlyOneRttPacketDoesNotScheduleApplicationAckDeadline) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 4,
            .frames =
                {
                    coquic::quic::AckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                    },
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(connection.application_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest, FirstAckElicitingOneRttPacketSchedulesDelayedApplicationAckDeadline) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 4,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_EQ(
        optional_value_or_terminate(connection.application_space_.pending_ack_deadline),
        coquic::quic::test::test_time(
            1 + static_cast<std::int64_t>(connection.local_transport_parameters_.max_ack_delay)));
    EXPECT_FALSE(connection.application_space_.force_ack_send);
}

TEST(QuicCoreTest,
     SecondAckElicitingOneRttPacketMakesApplicationAckDeadlineImmediateWithoutForcingAckOnlySend) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;

    const auto first_processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 4,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(first_processed.has_value());
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());

    const auto second_processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 5,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(2));

    ASSERT_TRUE(second_processed.has_value());
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_EQ(optional_value_or_terminate(connection.application_space_.pending_ack_deadline),
              coquic::quic::test::test_time(2));
    EXPECT_FALSE(connection.application_space_.force_ack_send);
}

TEST(QuicCoreTest, DelayedApplicationAckDeadlineSuppressesImmediateAckOnlySend) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 4,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_EQ(
        optional_value_or_terminate(connection.application_space_.pending_ack_deadline),
        coquic::quic::test::test_time(
            1 + static_cast<std::int64_t>(connection.local_transport_parameters_.max_ack_delay)));
}

TEST(QuicCoreTest, ApplicationSendOversizeWithoutExistingPacketsReturnsEmptyAtAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    for (std::uint64_t stream_index = 0; stream_index < 64; ++stream_index) {
        const auto stream_id = stream_index * 4;
        auto &stream = connection.streams_
                           .emplace(stream_id, coquic::quic::make_implicit_stream_state(
                                                   stream_id, connection.config_.role))
                           .first->second;
        stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
            .stream_id = stream_id,
            .application_protocol_error_code = 1,
            .final_size = 0,
        };
        stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
}

TEST(QuicCoreTest, ConnectionPersistentCongestionPathsAreExercised) {
    auto detect_connection = make_connected_client_connection();
    detect_connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    auto &detect_rtt = detect_connection.application_space_.recovery.rtt_state();
    detect_rtt.latest_rtt = std::chrono::milliseconds(10);
    detect_rtt.min_rtt = std::chrono::milliseconds(10);
    detect_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    detect_rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = detect_connection.congestion_controller_.congestion_window();
    detect_connection.track_sent_packet(detect_connection.application_space_,
                                        coquic::quic::SentPacketRecord{
                                            .packet_number = 1,
                                            .sent_time = coquic::quic::test::test_time(0),
                                            .ack_eliciting = true,
                                            .in_flight = true,
                                            .bytes_in_flight = 1200,
                                        });
    detect_connection.track_sent_packet(detect_connection.application_space_,
                                        coquic::quic::SentPacketRecord{
                                            .packet_number = 2,
                                            .sent_time = coquic::quic::test::test_time(200),
                                            .ack_eliciting = true,
                                            .in_flight = true,
                                            .bytes_in_flight = 1200,
                                        });

    detect_connection.detect_lost_packets(detect_connection.application_space_,
                                          coquic::quic::test::test_time(250));

    EXPECT_LT(detect_connection.congestion_controller_.congestion_window(), initial_window);
    EXPECT_EQ(detect_connection.congestion_controller_.congestion_window(),
              detect_connection.congestion_controller_.minimum_window());

    coquic::quic::QuicConnection ack_connection(coquic::quic::test::make_client_core_config());
    ack_connection.status_ = coquic::quic::HandshakeStatus::connected;
    auto &ack_rtt = ack_connection.application_space_.recovery.rtt_state();
    ack_rtt.latest_rtt = std::chrono::milliseconds(10);
    ack_rtt.min_rtt = std::chrono::milliseconds(10);
    ack_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    ack_rtt.rttvar = std::chrono::milliseconds(1);
    const std::optional<std::size_t> ack_initial_window =
        ack_connection.congestion_controller_.congestion_window();
    ack_connection.track_sent_packet(ack_connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(0),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    ack_connection.track_sent_packet(ack_connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 2,
                                         .sent_time = coquic::quic::test::test_time(200),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    ack_connection.track_sent_packet(ack_connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 3,
                                         .sent_time = coquic::quic::test::test_time(350),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    ack_connection.track_sent_packet(ack_connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 5,
                                         .sent_time = coquic::quic::test::test_time(400),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });

    const coquic::quic::CodecResult<bool> processed = ack_connection.process_inbound_ack(
        ack_connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 5,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(400), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_LT(ack_connection.congestion_controller_.congestion_window(),
              optional_value_or_terminate(ack_initial_window) / 2);
    EXPECT_GE(ack_connection.congestion_controller_.congestion_window(),
              ack_connection.congestion_controller_.minimum_window());
}

TEST(QuicCoreTest, ReceivedAckFrameProcessingMatchesOwnedAckFrameProcessing) {
    auto owned_connection = make_connected_client_connection();
    auto received_connection = make_connected_client_connection();

    const auto configure_connection = [](coquic::quic::QuicConnection &connection) {
        auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
        application_recovery_rtt.latest_rtt = std::chrono::milliseconds(10);
        application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
        application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
        application_recovery_rtt.rttvar = std::chrono::milliseconds(1);

        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 1,
                                         .sent_time = coquic::quic::test::test_time(0),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 2,
                                         .sent_time = coquic::quic::test::test_time(200),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 3,
                                         .sent_time = coquic::quic::test::test_time(350),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 5,
                                         .sent_time = coquic::quic::test::test_time(400),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    };

    configure_connection(owned_connection);
    configure_connection(received_connection);

    const coquic::quic::AckFrame ack{
        .largest_acknowledged = 5,
        .ack_delay = 4,
        .first_ack_range = 0,
    };

    const auto encoded = coquic::quic::serialize_frame(coquic::quic::Frame{ack});
    ASSERT_TRUE(encoded.has_value());
    auto storage = std::make_shared<std::vector<std::byte>>(encoded.value());
    const auto decoded = coquic::quic::deserialize_received_frame(
        coquic::quic::SharedBytes(storage, 0, storage->size()));
    ASSERT_TRUE(decoded.has_value());
    const auto *received_ack = std::get_if<coquic::quic::ReceivedAckFrame>(&decoded.value().frame);
    ASSERT_NE(received_ack, nullptr);

    const coquic::quic::CodecResult<bool> owned_processed = owned_connection.process_inbound_ack(
        owned_connection.application_space_, ack, coquic::quic::test::test_time(400),
        /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25, /*suppress_pto_reset=*/false);
    const coquic::quic::CodecResult<bool> received_processed =
        received_connection.process_inbound_ack(received_connection.application_space_,
                                                *received_ack, coquic::quic::test::test_time(400),
                                                /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
                                                /*suppress_pto_reset=*/false);

    ASSERT_TRUE(owned_processed.has_value());
    ASSERT_TRUE(received_processed.has_value());
    EXPECT_EQ(owned_connection.congestion_controller_.congestion_window(),
              received_connection.congestion_controller_.congestion_window());
    EXPECT_EQ(owned_connection.congestion_controller_.bytes_in_flight(),
              received_connection.congestion_controller_.bytes_in_flight());
    EXPECT_EQ(owned_connection.pto_count_, received_connection.pto_count_);
    EXPECT_EQ(owned_connection.application_space_.recovery.largest_acked_packet_number_,
              received_connection.application_space_.recovery.largest_acked_packet_number_);
    EXPECT_EQ(tracked_packet_count(owned_connection.application_space_),
              tracked_packet_count(received_connection.application_space_));
}

TEST(QuicCoreTest, OneRttReceivedAckOnlyFastPathMatchesGenericApplicationAckProcessing) {
    auto generic_connection = make_connected_client_connection();
    auto fast_connection = make_connected_client_connection();

    const auto configure_connection = [](coquic::quic::QuicConnection &connection) {
        connection.config_.transport.enable_latency_spin_bit = true;
        connection.latency_spin_bit_disabled_ = false;
        connection.paths_.at(0).spin.disabled = false;
        connection.last_peer_activity_time_ = coquic::quic::test::test_time(1);
        connection.application_space_.recovery.rtt_state().latest_rtt =
            std::chrono::milliseconds(10);
        connection.application_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
        connection.application_space_.recovery.rtt_state().smoothed_rtt =
            std::chrono::milliseconds(10);
        connection.application_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(1);
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = 9,
                                         .sent_time = coquic::quic::test::test_time(10),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    };
    configure_connection(generic_connection);
    configure_connection(fast_connection);

    const coquic::quic::AckFrame ack{
        .largest_acknowledged = 9,
        .ack_delay = 4,
        .first_ack_range = 0,
    };
    const auto encoded = coquic::quic::serialize_frame(coquic::quic::Frame{ack});
    ASSERT_TRUE(encoded.has_value());
    auto storage = std::make_shared<std::vector<std::byte>>(encoded.value());
    const auto decoded = coquic::quic::deserialize_received_frame(
        coquic::quic::SharedBytes(storage, 0, storage->size()));
    ASSERT_TRUE(decoded.has_value());
    const auto *received_ack = std::get_if<coquic::quic::ReceivedAckFrame>(&decoded.value().frame);
    ASSERT_NE(received_ack, nullptr);

    const auto make_packet = [&] {
        coquic::quic::ReceivedFrameList frames;
        frames.emplace_back(*received_ack);
        return coquic::quic::ReceivedProtectedPacket{coquic::quic::ReceivedProtectedOneRttPacket{
            .spin_bit = false,
            .packet_number = 44,
            .frames = std::move(frames),
        }};
    };
    std::optional<ScopedEnvVar> trace;
    trace.emplace("COQUIC_PACKET_TRACE", "1");
    const coquic::quic::CodecResult<bool> generic_processed =
        generic_connection.process_inbound_received_packet(
            make_packet(), coquic::quic::test::test_time(20), coquic::quic::QuicEcnCodepoint::ect0);
    trace.reset();
    const coquic::quic::CodecResult<bool> fast_processed =
        fast_connection.process_inbound_received_packet(
            make_packet(), coquic::quic::test::test_time(20), coquic::quic::QuicEcnCodepoint::ect0);

    ASSERT_TRUE(generic_processed.has_value());
    ASSERT_TRUE(fast_processed.has_value());
    EXPECT_TRUE(fast_connection.processed_peer_packet_);
    EXPECT_EQ(fast_connection.last_peer_activity_time_,
              std::optional{coquic::quic::test::test_time(20)});
    EXPECT_TRUE(fast_connection.application_space_.received_packets.contains(44));
    EXPECT_FALSE(fast_connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(generic_connection.congestion_controller_.congestion_window(),
              fast_connection.congestion_controller_.congestion_window());
    EXPECT_EQ(generic_connection.congestion_controller_.bytes_in_flight(),
              fast_connection.congestion_controller_.bytes_in_flight());
    EXPECT_EQ(generic_connection.pto_count_, fast_connection.pto_count_);
    EXPECT_EQ(generic_connection.application_space_.recovery.largest_acked_packet_number_,
              fast_connection.application_space_.recovery.largest_acked_packet_number_);
    EXPECT_EQ(tracked_packet_count(generic_connection.application_space_),
              tracked_packet_count(fast_connection.application_space_));
    EXPECT_EQ(fast_connection.application_space_.largest_authenticated_packet_number, 44u);
    EXPECT_EQ(generic_connection.outbound_spin_bit_for_path(0),
              fast_connection.outbound_spin_bit_for_path(0));
    EXPECT_TRUE(fast_connection.outbound_spin_bit_for_path(0));
}

TEST(QuicCoreTest, ReceivedAckFrameProcessingCoversTraceFormattingAndInvalidCursorPaths) {
    auto connection = make_connected_client_connection();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(399),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 5,
                                     .sent_time = coquic::quic::test::test_time(400),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    const coquic::quic::AckFrame ack{
        .largest_acknowledged = 5,
        .ack_delay = 4,
        .first_ack_range = 0,
        .additional_ranges =
            {
                coquic::quic::AckRange{
                    .gap = 1,
                    .range_length = 0,
                },
            },
    };
    const auto encoded = coquic::quic::serialize_frame(coquic::quic::Frame{ack});
    ASSERT_TRUE(encoded.has_value());
    auto storage = std::make_shared<std::vector<std::byte>>(encoded.value());
    const auto decoded = coquic::quic::deserialize_received_frame(
        coquic::quic::SharedBytes(storage, 0, storage->size()));
    ASSERT_TRUE(decoded.has_value());
    const auto *received_ack = std::get_if<coquic::quic::ReceivedAckFrame>(&decoded.value().frame);
    ASSERT_NE(received_ack, nullptr);

    const ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");
    testing::internal::CaptureStderr();
    const coquic::quic::CodecResult<bool> traced_processed = connection.process_inbound_ack(
        connection.application_space_, *received_ack, coquic::quic::test::test_time(401),
        /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25, /*suppress_pto_reset=*/false);
    const std::string stderr_output = testing::internal::GetCapturedStderr();

    ASSERT_TRUE(traced_processed.has_value());
    EXPECT_NE(stderr_output.find("quic-packet-trace ack scid="), std::string::npos);
    EXPECT_NE(stderr_output.find("ranges=[5-5,2-2]"), std::string::npos);

    const coquic::quic::CodecResult<bool> invalid_processed =
        connection.process_inbound_ack(connection.application_space_,
                                       coquic::quic::ReceivedAckFrame{
                                           .largest_acknowledged = 1,
                                           .first_ack_range = 2,
                                       },
                                       coquic::quic::test::test_time(402), /*ack_delay_exponent=*/3,
                                       /*max_ack_delay_ms=*/25, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(invalid_processed.has_value());
    EXPECT_TRUE(invalid_processed.value());
}

TEST(QuicCoreTest, AckTriggeredLossUsesLossDetectionTimeForRecoveryBoundary) {
    auto connection = make_connected_client_connection();
    auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
    application_recovery_rtt.latest_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.rttvar = std::chrono::milliseconds(1);
    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(8192, 'r')), false)
                    .has_value());

    for (std::uint64_t packet_number = 1; packet_number <= 8; ++packet_number) {
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = packet_number,
                                         .sent_time = coquic::quic::test::test_time(
                                             static_cast<std::int64_t>(100u + packet_number)),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    }

    const coquic::quic::CodecResult<bool> processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 8,
            .first_ack_range = 4,
        },
        coquic::quic::test::test_time(120), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.congestion_controller_.congestion_window(), 6000u);
    EXPECT_EQ(connection.congestion_controller_.bytes_in_flight(), 0u);
}

TEST(QuicCoreTest, AckTriggeredLossDoesNotRestartRecoveryForOlderPackets) {
    auto connection = make_connected_client_connection();
    auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
    application_recovery_rtt.latest_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.rttvar = std::chrono::milliseconds(1);

    for (std::uint64_t packet_number = 1; packet_number <= 12; ++packet_number) {
        connection.track_sent_packet(connection.application_space_,
                                     coquic::quic::SentPacketRecord{
                                         .packet_number = packet_number,
                                         .sent_time = coquic::quic::test::test_time(
                                             static_cast<std::int64_t>(100u + packet_number)),
                                         .ack_eliciting = true,
                                         .in_flight = true,
                                         .bytes_in_flight = 1200,
                                     });
    }

    const coquic::quic::CodecResult<bool> first_ack = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 8,
            .first_ack_range = 4,
        },
        coquic::quic::test::test_time(120), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(first_ack.has_value());
    ASSERT_EQ(connection.congestion_controller_.congestion_window(), 6000u);

    const coquic::quic::CodecResult<bool> second_ack = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 12,
            .first_ack_range = 2,
            .additional_ranges =
                {
                    coquic::quic::AckRange{
                        .gap = 0,
                        .range_length = 4,
                    },
                },
        },
        coquic::quic::test::test_time(130), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(second_ack.has_value());
    EXPECT_EQ(connection.congestion_controller_.congestion_window(), 6000u);
}

TEST(QuicCoreTest, AckTriggeredTimeThresholdLossUsesLatestRttSample) {
    auto connection = make_connected_client_connection();
    auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
    application_recovery_rtt.latest_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = connection.congestion_controller_.congestion_window();

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    const coquic::quic::CodecResult<bool> processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 2,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(80), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt,
              std::optional{std::chrono::milliseconds(80)});
    ASSERT_NE(connection.application_space_.recovery.find_packet(1), nullptr);
    EXPECT_EQ(connection.congestion_controller_.congestion_window(), initial_window + 1200);
}

TEST(QuicCoreTest, StaleLargestAckDoesNotUpdateRttForSparseAckRanges) {
    auto connection = make_connected_client_connection();
    auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
    application_recovery_rtt.latest_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.rttvar = std::chrono::milliseconds(1);

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 4,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    const coquic::quic::CodecResult<bool> first_ack = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 4,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(1), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);
    ASSERT_TRUE(first_ack.has_value());
    ASSERT_NE(connection.application_space_.recovery.find_packet(1), nullptr);

    const coquic::quic::CodecResult<bool> processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 4,
            .first_ack_range = 0,
            .additional_ranges =
                {
                    coquic::quic::AckRange{
                        .gap = 0,
                        .range_length = 1,
                    },
                },
        },
        coquic::quic::test::test_time(80), /*ack_delay_exponent=*/3, /*max_ack_delay_ms=*/25,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.application_space_.recovery.rtt_state().latest_rtt,
              std::optional{std::chrono::milliseconds(1)});
}

TEST(QuicCoreTest, LossDetectionSkipsCongestionResponseForNonAckElicitingLoss) {
    auto connection = make_connected_client_connection();
    connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
    application_recovery_rtt.latest_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = connection.congestion_controller_.congestion_window();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = false,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(800));

    EXPECT_EQ(connection.congestion_controller_.congestion_window(), initial_window);
}

TEST(QuicCoreTest, FullCwndFinalSendIsNotMarkedApplicationLimited) {
    auto connection = make_connected_client_connection();
    connection.congestion_controller_.congestion_window_ = 2400;
    connection.congestion_controller_.bytes_in_flight_ = 1200;
    ASSERT_FALSE(connection.has_pending_application_send());

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1199,
                                 });
    ASSERT_TRUE(connection.application_space_.recovery.handle_for_packet_number(1).has_value());
    EXPECT_TRUE(connection.application_space_.sent_packets.at(1).app_limited);

    connection.congestion_controller_.bytes_in_flight_ = 1200;
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    ASSERT_TRUE(connection.application_space_.recovery.handle_for_packet_number(2).has_value());
    EXPECT_FALSE(connection.application_space_.sent_packets.at(2).app_limited);
}

TEST(QuicCoreTest, LossDetectionUsesDefaultAckDelayButRequiresRttSampleForPersistentCongestion) {
    auto connection = make_connected_client_connection();
    connection.peer_transport_parameters_ = std::nullopt;
    connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
    application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = connection.congestion_controller_.congestion_window();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(700),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(1200));

    EXPECT_LT(connection.congestion_controller_.congestion_window(), initial_window);
    EXPECT_GT(connection.congestion_controller_.congestion_window(),
              connection.congestion_controller_.minimum_window());
}

TEST(QuicCoreTest, LossDetectionSkipsNonAckElicitingPacketsForPersistentCongestionWindow) {
    auto connection = make_connected_client_connection();
    connection.application_space_.recovery.largest_acked_packet_number_ = 5;
    auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
    application_recovery_rtt.latest_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.rttvar = std::chrono::milliseconds(1);
    const auto initial_window = connection.congestion_controller_.congestion_window();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = false,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(200),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1200,
                                 });

    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(250));

    EXPECT_LT(connection.congestion_controller_.congestion_window(), initial_window);
    EXPECT_GT(connection.congestion_controller_.congestion_window(),
              connection.congestion_controller_.minimum_window());
}

TEST(QuicCoreTest, LateAckOfDeclaredLostRetransmissionRetiresApplicationFragment) {
    auto connection = make_connected_client_connection();
    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);

    const auto payload = std::vector<std::byte>(4096, std::byte{0x5a});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(0));
    ASSERT_FALSE(first_datagram.empty());

    const auto first_packet_number =
        first_tracked_packet(connection.application_space_).packet_number;
    const auto first_packet =
        tracked_packet_or_terminate(connection.application_space_, first_packet_number);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(first_packet));
    const auto tracked_offset = first_stream_frame_offset_for_tests(first_packet);
    const auto tracked_length = first_stream_frame_length_for_tests(first_packet);

    auto &application_recovery_rtt = connection.application_space_.recovery.rtt_state();
    application_recovery_rtt.latest_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.min_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.smoothed_rtt = std::chrono::milliseconds(10);
    application_recovery_rtt.rttvar = std::chrono::milliseconds(1);

    connection.application_space_.recovery.largest_acked_packet_number_ = first_packet_number + 5;
    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(20));
    ASSERT_TRUE(connection.streams_.at(0).send_buffer.has_lost_data());

    const coquic::quic::DatagramBuffer retransmit_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(21));
    ASSERT_FALSE(retransmit_datagram.empty());

    const coquic::quic::SentPacketRecord retransmit_packet =
        last_tracked_packet(connection.application_space_);
    ASSERT_GT(retransmit_packet.packet_number, first_packet_number);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(retransmit_packet));
    EXPECT_EQ(first_stream_frame_offset_for_tests(retransmit_packet), tracked_offset);
    EXPECT_EQ(first_stream_frame_length_for_tests(retransmit_packet), tracked_length);

    connection.application_space_.recovery.largest_acked_packet_number_ =
        retransmit_packet.packet_number + 5;
    connection.detect_lost_packets(connection.application_space_,
                                   coquic::quic::test::test_time(41));

    ASSERT_TRUE(
        connection
            .process_inbound_ack(connection.application_space_,
                                 coquic::quic::AckFrame{
                                     .largest_acknowledged = retransmit_packet.packet_number,
                                     .first_ack_range = 0,
                                 },
                                 coquic::quic::test::test_time(42),
                                 peer_transport_parameters.ack_delay_exponent,
                                 peer_transport_parameters.max_ack_delay,
                                 /*suppress_pto_reset=*/false)
            .has_value());

    EXPECT_FALSE(connection.streams_.at(0).send_buffer.has_outstanding_range(tracked_offset,
                                                                             tracked_length));

    const coquic::quic::DatagramBuffer next_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(43));
    ASSERT_FALSE(next_datagram.empty());
    const std::vector<coquic::quic::ProtectedPacket> next_packets =
        decode_sender_datagram(connection, next_datagram);
    ASSERT_EQ(next_packets.size(), 1u);
    const auto *next_application =
        std::get_if<coquic::quic::ProtectedOneRttPacket>(&next_packets.front());
    ASSERT_NE(next_application, nullptr);

    for (const auto &frame : next_application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        EXPECT_NE(optional_value_or_terminate(stream->offset), tracked_offset);
    }
}

TEST(QuicCoreTest, FastCommitStoresSingleStreamFrameMetadataInline) {
    auto connection = make_connected_server_connection();
    const auto payload = std::vector<std::byte>(1024, std::byte{0x5a});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(0));
    ASSERT_FALSE(datagram.empty());
    const auto &packet = last_tracked_packet(connection.application_space_);

    ASSERT_TRUE(packet.first_stream_frame_metadata.has_value());
    const auto &first_stream_frame_metadata =
        optional_ref_or_terminate(packet.first_stream_frame_metadata);
    EXPECT_TRUE(packet.stream_frame_metadata.empty());
    EXPECT_TRUE(packet.stream_fragments.empty());
    EXPECT_EQ(first_stream_frame_metadata.stream_id, 0u);
    EXPECT_EQ(first_stream_frame_metadata.offset, 0u);
    EXPECT_EQ(first_stream_frame_metadata.length, payload.size());
    EXPECT_FALSE(first_stream_frame_metadata.fin);
}

TEST(QuicCoreTest, SelectPtoProbeFiltersControlFramesAgainstCurrentPendingState) {
    auto connection = make_connected_client_connection();

    auto &matching_stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    matching_stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 7,
        .final_size = 11,
    };
    matching_stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    matching_stream.pending_stop_sending_frame = coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
    };
    matching_stream.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    matching_stream.flow_control.pending_max_stream_data_frame = coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 13,
    };
    matching_stream.flow_control.max_stream_data_state =
        coquic::quic::StreamControlFrameState::pending;
    matching_stream.flow_control.pending_stream_data_blocked_frame =
        coquic::quic::StreamDataBlockedFrame{
            .stream_id = 0,
            .maximum_stream_data = 15,
        };
    matching_stream.flow_control.stream_data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;

    auto &missing_pending_stream =
        connection.streams_
            .emplace(4, coquic::quic::make_implicit_stream_state(4, connection.config_.role))
            .first->second;
    missing_pending_stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    missing_pending_stream.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    missing_pending_stream.flow_control.max_stream_data_state =
        coquic::quic::StreamControlFrameState::pending;
    missing_pending_stream.flow_control.stream_data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;

    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 99};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 77};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::acknowledged;

    coquic::quic::PacketSpaceState packet_space;
    connection.track_sent_packet(
        packet_space,
        coquic::quic::SentPacketRecord{
            .packet_number = 7,
            .ack_eliciting = true,
            .in_flight = true,
            .has_handshake_done = true,
            .reset_stream_frames =
                {
                    matching_stream.pending_reset_frame.value(),
                    coquic::quic::ResetStreamFrame{
                        .stream_id = 4,
                        .application_protocol_error_code = 1,
                        .final_size = 0,
                    },
                },
            .stop_sending_frames =
                {
                    matching_stream.pending_stop_sending_frame.value(),
                    coquic::quic::StopSendingFrame{
                        .stream_id = 4,
                        .application_protocol_error_code = 2,
                    },
                },
            .max_data_frame = coquic::quic::MaxDataFrame{.maximum_data = 100},
            .max_stream_data_frames =
                {
                    matching_stream.flow_control.pending_max_stream_data_frame.value(),
                    coquic::quic::MaxStreamDataFrame{
                        .stream_id = 4,
                        .maximum_stream_data = 12,
                    },
                },
            .data_blocked_frame =
                coquic::quic::DataBlockedFrame{
                    .maximum_data = 88,
                },
            .stream_data_blocked_frames =
                {
                    matching_stream.flow_control.pending_stream_data_blocked_frame.value(),
                    coquic::quic::StreamDataBlockedFrame{
                        .stream_id = 4,
                        .maximum_stream_data = 14,
                    },
                },
        });

    const coquic::quic::SentPacketRecord probe = connection.select_pto_probe(packet_space);

    const auto &probe_packet = probe;
    ASSERT_EQ(probe_packet.reset_stream_frames.size(), 1u);
    EXPECT_EQ(probe_packet.reset_stream_frames.front().stream_id, 0u);
    ASSERT_EQ(probe_packet.stop_sending_frames.size(), 1u);
    EXPECT_EQ(probe_packet.stop_sending_frames.front().stream_id, 0u);
    ASSERT_EQ(probe_packet.max_stream_data_frames.size(), 1u);
    EXPECT_EQ(probe_packet.max_stream_data_frames.front().stream_id, 0u);
    ASSERT_EQ(probe_packet.stream_data_blocked_frames.size(), 1u);
    EXPECT_EQ(probe_packet.stream_data_blocked_frames.front().stream_id, 0u);
    EXPECT_FALSE(probe_packet.max_data_frame.has_value());
    EXPECT_FALSE(probe_packet.data_blocked_frame.has_value());
    EXPECT_FALSE(probe_packet.has_handshake_done);
}

TEST(QuicCoreTest, SelectPtoProbeKeepsMatchingConnectionBlockedFrames) {
    auto connection = make_connected_client_connection();
    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 99};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 77};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;

    coquic::quic::PacketSpaceState packet_space;
    connection.track_sent_packet(
        packet_space,
        coquic::quic::SentPacketRecord{
            .packet_number = 7,
            .ack_eliciting = true,
            .in_flight = true,
            .max_data_frame = connection.connection_flow_control_.pending_max_data_frame,
            .data_blocked_frame = connection.connection_flow_control_.pending_data_blocked_frame,
        });

    const coquic::quic::SentPacketRecord probe = connection.select_pto_probe(packet_space);

    const auto &probe_packet = probe;
    ASSERT_TRUE(probe_packet.max_data_frame.has_value());
    const auto &max_data_frame = optional_ref_or_terminate(probe_packet.max_data_frame);
    EXPECT_EQ(max_data_frame.maximum_data, 99u);
    ASSERT_TRUE(probe_packet.data_blocked_frame.has_value());
    const auto &data_blocked_frame = optional_ref_or_terminate(probe_packet.data_blocked_frame);
    EXPECT_EQ(data_blocked_frame.maximum_data, 77u);
}

TEST(QuicCoreTest, SelectPtoProbeKeepsFinOnlyFragmentThatMatchesFinalSize) {
    auto connection = make_connected_client_connection();

    auto &reset_stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    reset_stream.reset_state = coquic::quic::StreamControlFrameState::pending;

    auto &fin_stream =
        connection.streams_
            .emplace(4, coquic::quic::make_implicit_stream_state(4, connection.config_.role))
            .first->second;
    fin_stream.send_fin_state = coquic::quic::StreamSendFinState::pending;
    fin_stream.send_final_size = 5;

    coquic::quic::PacketSpaceState packet_space;
    connection.track_sent_packet(
        packet_space, coquic::quic::SentPacketRecord{
                          .packet_number = 1,
                          .ack_eliciting = true,
                          .in_flight = true,
                          .stream_fragments =
                              {
                                  coquic::quic::StreamFrameSendFragment{
                                      .stream_id = 0,
                                      .offset = 0,
                                      .bytes = coquic::quic::test::bytes_from_string("drop"),
                                      .fin = false,
                                      .consumes_flow_control = false,
                                  },
                                  coquic::quic::StreamFrameSendFragment{
                                      .stream_id = 4,
                                      .offset = 0,
                                      .bytes = coquic::quic::test::bytes_from_string("hello"),
                                      .fin = true,
                                      .consumes_flow_control = false,
                                  },
                              },
                      });

    const coquic::quic::SentPacketRecord probe = connection.select_pto_probe(packet_space);

    const auto &probe_packet = probe;
    ASSERT_EQ(probe_packet.stream_fragments.size(), 1u);
    EXPECT_EQ(probe_packet.stream_fragments.front().stream_id, 4u);
    EXPECT_EQ(probe_packet.stream_fragments.front().bytes,
              coquic::quic::test::bytes_from_string("hello"));
    EXPECT_TRUE(probe_packet.stream_fragments.front().fin);
}

TEST(QuicCoreTest, OnTimeoutForcesInitialAndHandshakeAckWhenDeadlinesExpire) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.pending_ack_deadline = coquic::quic::test::test_time(0);
    connection.handshake_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    connection.on_timeout(coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.initial_space_.force_ack_send);
    EXPECT_TRUE(connection.handshake_space_.force_ack_send);
}

TEST(QuicCoreTest, SharedRecoveryRttStateFallsBackAcrossPacketSpacesAndSynchronizes) {
    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(5);

        const auto &shared = connection.shared_recovery_rtt_state();

        EXPECT_EQ(&shared, &connection.initial_space_.recovery.rtt_state());
        connection.synchronize_recovery_rtt_state();
        EXPECT_EQ(connection.recovery_rtt_state_.latest_rtt, std::chrono::milliseconds(5));
    }

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.handshake_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(7);

        const auto &shared = connection.shared_recovery_rtt_state();

        EXPECT_EQ(&shared, &connection.handshake_space_.recovery.rtt_state());
        connection.synchronize_recovery_rtt_state();
        EXPECT_EQ(connection.recovery_rtt_state_.latest_rtt, std::chrono::milliseconds(7));
    }

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.application_space_.recovery.rtt_state().latest_rtt =
            std::chrono::milliseconds(9);

        connection.synchronize_recovery_rtt_state();

        EXPECT_EQ(connection.recovery_rtt_state_.latest_rtt, std::chrono::milliseconds(9));
        EXPECT_EQ(connection.initial_space_.recovery.rtt_state().latest_rtt,
                  std::chrono::milliseconds(9));
        EXPECT_EQ(connection.handshake_space_.recovery.rtt_state().latest_rtt,
                  std::chrono::milliseconds(9));
    }
}

TEST(QuicCoreTest, MarkLostPacketRequeuesHandshakeDoneWhenItWasNotYetAcknowledged) {
    auto connection = make_connected_server_connection();
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;

    const auto packet = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .has_handshake_done = true,
    };
    connection.track_sent_packet(connection.application_space_, packet);

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(
            connection.application_space_.recovery.handle_for_packet_number(packet.packet_number)));

    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::pending);
}

TEST(QuicCoreTest, ApplicationProbeWithoutCurrentSendPathStillSendsProbePayload) {
    auto connection = make_connected_client_connection();
    connection.current_send_path_id_.reset();
    connection.last_validated_path_id_.reset();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 18,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_path_challenge = false;
    bool saw_path_response = false;
    for (const auto &frame : application->frames) {
        saw_path_challenge =
            saw_path_challenge || std::holds_alternative<coquic::quic::PathChallengeFrame>(frame);
        saw_path_response =
            saw_path_response || std::holds_alternative<coquic::quic::PathResponseFrame>(frame);
    }

    EXPECT_FALSE(saw_path_challenge);
    EXPECT_FALSE(saw_path_response);
}

TEST(QuicCoreTest, ApplicationProbePacketCanSendHandshakeDoneAndAdvanceState) {
    auto connection = make_connected_server_connection();
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 88,
        .ack_eliciting = true,
        .in_flight = true,
        .has_handshake_done = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_handshake_done = false;
    for (const auto &frame : application->frames) {
        saw_handshake_done =
            saw_handshake_done || std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame);
    }

    EXPECT_TRUE(saw_handshake_done);
    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::sent);
}

} // namespace
