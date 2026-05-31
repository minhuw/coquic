#include "tests/support/core/connection_ack_test_support.h"

namespace {

TEST(QuicCoreTest, TimeoutRunsLossDetectionAndArmsPtoProbe) {
    auto connection = make_connected_client_connection();

    connection.initial_space_.recovery.largest_acked_packet_number_ = 5;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("lost"));
    const auto initial_ranges = connection.initial_space_.send_crypto.take_ranges(4);
    ASSERT_EQ(initial_ranges.size(), 1u);
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .crypto_ranges = initial_ranges,
                                 });

    connection.track_sent_packet(
        connection.application_space_,
        coquic::quic::SentPacketRecord{
            .packet_number = 3,
            .sent_time = coquic::quic::test::test_time(0),
            .ack_eliciting = true,
            .in_flight = true,
            .stream_fragments =
                {
                    coquic::quic::StreamFrameSendFragment{
                        .stream_id = 0,
                        .offset = 0,
                        .bytes = coquic::quic::test::bytes_from_string("pto"),
                        .fin = false,
                    },
                },
        });

    connection.on_timeout(coquic::quic::test::test_time(999));

    EXPECT_TRUE(connection.initial_space_.send_crypto.has_pending_data());
    if (!connection.application_space_.pending_probe_packet.has_value()) {
        GTEST_FAIL() << "expected pending application probe packet";
        return;
    }
    EXPECT_EQ(connection.application_space_.pending_probe_packet->packet_number, 3u);
}

TEST(QuicCoreTest, TimeoutBeforeLossAndPtoDeadlinesDoesNothing) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.recovery.largest_acked_packet_number_ = 4;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    connection.on_timeout(coquic::quic::test::test_time(11));

    EXPECT_NE(tracked_packet_or_null(connection.initial_space_, 1), nullptr);
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
}

TEST(QuicCoreTest, ServerProcessingHandshakePacketDiscardsInitialRecoveryState) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 1,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
            .packet_number = 0,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_EQ(connection.initial_space_.pending_ack_deadline, std::nullopt);
}

TEST(QuicCoreTest, ArmPtoProbeReturnsWhenNoPacketSpaceIsDue) {
    auto connection = make_connected_client_connection();

    connection.arm_pto_probe(coquic::quic::test::test_time(10));

    EXPECT_EQ(connection.pto_count_, 0u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ApplicationPtoBypassesCongestionWindowWhenDataIsPending) {
    auto connection = make_connected_client_connection();
    const auto congestion_window = connection.congestion_controller_.congestion_window();
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = congestion_window,
                                 });
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("queued"), false)
            .has_value());

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    const auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);
    const auto datagram = connection.drain_outbound_datagram(timeout);

    ASSERT_FALSE(datagram.empty());
    const auto stream_ids = application_stream_ids_from_datagram(connection, datagram);
    EXPECT_EQ(stream_ids, std::vector<std::uint64_t>({0u}));
}

TEST(QuicCoreTest, ApplicationPtoPrefersRetransmittableProbeOverFreshData) {
    auto connection = make_connected_client_connection();
    const auto payload =
        std::vector<std::byte>(static_cast<std::size_t>(32) * 1024u, std::byte{0x50});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::optional<std::uint64_t> first_sent_offset;
    std::optional<std::uint64_t> last_sent_offset;
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

        for (const auto &frame : application->frames) {
            const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            ASSERT_TRUE(stream->offset.has_value());
            const auto stream_offset = optional_value_or_terminate(stream->offset);
            if (!first_sent_offset.has_value()) {
                first_sent_offset = stream_offset;
            }
            last_sent_offset = stream_offset;
            next_unsent_offset =
                stream_offset + static_cast<std::uint64_t>(stream->stream_data.size());
        }
    }

    ASSERT_TRUE(first_sent_offset.has_value());
    ASSERT_TRUE(last_sent_offset.has_value());
    ASSERT_TRUE(connection.has_pending_application_send());

    const auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    const auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    const auto &pending_probe_packet =
        optional_ref_or_terminate(connection.application_space_.pending_probe_packet);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(pending_probe_packet));

    const auto probe_datagram = connection.drain_outbound_datagram(timeout);
    ASSERT_FALSE(probe_datagram.empty());

    const auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&probe_packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<std::uint64_t> stream_offsets;
    for (const auto &frame : application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        ASSERT_TRUE(stream->offset.has_value());
        stream_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    ASSERT_FALSE(stream_offsets.empty());
    EXPECT_EQ(stream_offsets.front(), optional_value_or_terminate(last_sent_offset));
    EXPECT_NE(stream_offsets.front(), optional_value_or_terminate(first_sent_offset));
    EXPECT_NE(stream_offsets.front(), next_unsent_offset);
}

TEST(QuicCoreTest, ApplicationPtoPrefersNewestRetransmittablePacketOverOlderCryptoOnlyPacket) {
    auto connection = make_connected_server_connection();
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));
    const auto crypto_ranges = connection.application_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(crypto_ranges.empty());

    const auto payload = coquic::quic::test::bytes_from_string("server-response");
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());
    auto &stream = connection.streams_.at(0);
    auto stream_fragments = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = payload.size(),
        .new_bytes = payload.size(),
    });
    ASSERT_EQ(stream_fragments.size(), 1u);

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 10,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .crypto_ranges = crypto_ranges,
                                     .bytes_in_flight = 300,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 11,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = stream_fragments,
                                     .bytes_in_flight = 200,
                                 });

    const auto probe = connection.select_pto_probe(connection.application_space_);

    EXPECT_EQ(probe.packet_number, 11u);
    ASSERT_EQ(probe.stream_fragments.size(), 1u);
    EXPECT_EQ(probe.stream_fragments.front().stream_id, 0u);
    EXPECT_EQ(probe.stream_fragments.front().bytes, payload);
    EXPECT_TRUE(probe.stream_fragments.front().fin);
}

TEST(QuicCoreTest, ApplicationPtoDoesNotResendFullyAckedPrefixOfPartiallyOutstandingFragment) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    stream.flow_control.peer_max_stream_data = 5;
    stream.send_buffer.append(coquic::quic::test::bytes_from_string("hello"));
    stream.send_flow_control_committed = 5;
    connection.refresh_stream_sendable_byte_caches();

    const auto initial_fragments = stream.take_send_fragments(/*max_bytes=*/5);
    ASSERT_EQ(initial_fragments.size(), 1u);
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 72,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = initial_fragments,
                                 });
    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(
            connection.application_space_.recovery.handle_for_packet_number(72)));

    const auto retransmitted_prefix = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 2,
        .new_bytes = 0,
    });
    ASSERT_EQ(retransmitted_prefix.size(), 1u);
    EXPECT_EQ(retransmitted_prefix[0].offset, 0u);
    EXPECT_EQ(retransmitted_prefix[0].bytes, coquic::quic::test::bytes_from_string("he"));
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 73,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = retransmitted_prefix,
                                 });

    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = 73,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(2),
                                         /*ack_delay_exponent=*/0,
                                         /*max_ack_delay_ms=*/0,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    const auto probe = connection.select_pto_probe(connection.application_space_);
    const auto &probe_packet = probe;
    EXPECT_TRUE(probe_packet.stream_fragments.empty());
    EXPECT_TRUE(probe_packet.has_ping);
    connection.application_space_.pending_probe_packet = probe;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1000));
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<coquic::quic::StreamFrame> stream_frames;
    for (const auto &frame : application->frames) {
        if (const auto *stream_frame = std::get_if<coquic::quic::StreamFrame>(&frame)) {
            stream_frames.push_back(*stream_frame);
        }
    }

    ASSERT_EQ(stream_frames.size(), 1u);
    ASSERT_TRUE(stream_frames[0].offset.has_value());
    EXPECT_EQ(optional_value_or_terminate(stream_frames[0].offset), 2u);
    EXPECT_EQ(stream_frames[0].stream_data, coquic::quic::test::bytes_from_string("llo"));
}

TEST(QuicCoreTest, ArmPtoProbeDefersCryptoProbeWhenCryptoSendDataIsAlreadyPending) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hello"));

    connection.arm_pto_probe(coquic::quic::test::test_time(999));

    EXPECT_EQ(connection.pto_count_, 1u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ArmPtoProbeCoalescesHandshakeProbeWithInitialProbe) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    EXPECT_EQ(connection.pto_count_, 1u);
    EXPECT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ServerPtoProbeEmitsTwoDatagramsWhenInitialAndHandshakeAreInFlight) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.source_connection_id = {};
    client_config.server_name = "server4";

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto start_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_EQ(start_datagrams.size(), 1u);

    const auto client_packets =
        decode_sender_datagram(*client.connection_, start_datagrams.front());
    ASSERT_EQ(client_packets.size(), 1u);
    const auto *client_initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&client_packets.front());
    ASSERT_NE(client_initial, nullptr);

    std::size_t client_hello_size = 0;
    for (const auto &frame : client_initial->frames) {
        const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
        if (crypto == nullptr) {
            continue;
        }

        client_hello_size = std::max(client_hello_size, static_cast<std::size_t>(crypto->offset) +
                                                            crypto->crypto_data.size());
    }
    ASSERT_GT(client_hello_size, 128u);

    auto client_hello = std::vector<std::byte>(client_hello_size, std::byte{0x00});
    for (const auto &frame : client_initial->frames) {
        const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
        if (crypto == nullptr) {
            continue;
        }

        std::copy(crypto->crypto_data.begin(), crypto->crypto_data.end(),
                  client_hello.begin() + static_cast<std::ptrdiff_t>(crypto->offset));
    }

    std::size_t prefix = 63u;
    std::size_t gap = 4u;
    std::size_t tail_offset = 1230u;
    if (client_hello.size() <= tail_offset) {
        prefix = std::min<std::size_t>(63u, client_hello.size() / 4u);
        gap = 1u;
        tail_offset = prefix + gap + ((client_hello.size() - (prefix + gap)) / 2u);
    }
    ASSERT_LT(prefix + gap, tail_offset);
    ASSERT_LT(tail_offset, client_hello.size());

    const auto slice_bytes = [&](std::size_t begin, std::size_t end) {
        return std::vector<std::byte>(client_hello.begin() + static_cast<std::ptrdiff_t>(begin),
                                      client_hello.begin() + static_cast<std::ptrdiff_t>(end));
    };

    coquic::quic::ProtectedInitialPacket delivered_packet_one{
        .version = client_initial->version,
        .destination_connection_id = client_initial->destination_connection_id,
        .source_connection_id = client_initial->source_connection_id,
        .token = client_initial->token,
        .packet_number_length = client_initial->packet_number_length,
        .packet_number = 1,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(prefix),
                    .crypto_data = slice_bytes(prefix, prefix + gap),
                },
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(tail_offset),
                    .crypto_data = slice_bytes(tail_offset, client_hello.size()),
                },
            },
    };
    coquic::quic::ProtectedInitialPacket delivered_packet_two{
        .version = client_initial->version,
        .destination_connection_id = client_initial->destination_connection_id,
        .source_connection_id = client_initial->source_connection_id,
        .token = client_initial->token,
        .packet_number_length = client_initial->packet_number_length,
        .packet_number = 2,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(prefix + gap),
                    .crypto_data = slice_bytes(prefix + gap, tail_offset),
                },
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = slice_bytes(0u, prefix),
                },
            },
    };

    const auto pad_initial = [&](coquic::quic::ProtectedInitialPacket packet) {
        auto encoded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{packet},
            coquic::quic::SerializeProtectionContext{
                .local_role = client.connection_->config_.role,
                .client_initial_destination_connection_id =
                    client.connection_->client_initial_destination_connection_id(),
                .handshake_secret = client.connection_->handshake_space_.write_secret,
                .one_rtt_secret = client.connection_->application_space_.write_secret,
                .one_rtt_key_phase = client.connection_->application_write_key_phase_,
            });
        EXPECT_TRUE(encoded.has_value());
        if (!encoded.has_value()) {
            return std::vector<std::byte>{};
        }
        if (encoded.value().size() < 1200u) {
            packet.frames.emplace_back(coquic::quic::PaddingFrame{
                .length = 1200u - encoded.value().size(),
            });
        }
        auto padded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{std::move(packet)},
            coquic::quic::SerializeProtectionContext{
                .local_role = client.connection_->config_.role,
                .client_initial_destination_connection_id =
                    client.connection_->client_initial_destination_connection_id(),
                .handshake_secret = client.connection_->handshake_space_.write_secret,
                .one_rtt_secret = client.connection_->application_space_.write_secret,
                .one_rtt_key_phase = client.connection_->application_write_key_phase_,
            });
        EXPECT_TRUE(padded.has_value());
        if (!padded.has_value()) {
            return std::vector<std::byte>{};
        }
        return padded.value();
    };

    const auto first_datagram = pad_initial(delivered_packet_one);
    const auto server_after_first = server.advance(
        coquic::quic::QuicCoreInboundDatagram{first_datagram}, coquic::quic::test::test_time(1));
    EXPECT_FALSE(server.has_failed());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(server_after_first).empty());

    const auto second_datagram = pad_initial(delivered_packet_two);
    const auto server_after_second = server.advance(
        coquic::quic::QuicCoreInboundDatagram{second_datagram}, coquic::quic::test::test_time(2));
    EXPECT_FALSE(server.has_failed());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(server_after_second).empty());

    const auto next_wakeup = server_after_second.next_wakeup;
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }
    const auto probe = server.advance(coquic::quic::QuicCoreTimerExpired{}, next_wakeup.value());
    const auto probe_datagrams = coquic::quic::test::send_datagrams_from(probe);
    EXPECT_EQ(probe_datagrams.size(), 2u);
}

TEST(QuicCoreTest, ServerPtoProbeWithHandshakeAndApplicationInFlightBeforeConfirmationDoesNotFail) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.next_send_packet_number = 1;

    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 60,
                                 });
    ASSERT_TRUE(
        connection
            .queue_stream_send(0, coquic::quic::test::bytes_from_string("server-probe"), false)
            .has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*next_wakeup);

    const auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(second_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ServerPtoProbeWithOnlyApplicationCryptoInFlightDoesNotFailAcrossBurst) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*next_wakeup);

    const auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(second_probe_datagram.empty() || !second_probe_datagram.empty());
}

TEST(QuicCoreTest, ServerPtoProbeWithHandshakeAndOnlyApplicationCryptoInFlightEmitsSecondDatagram) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.next_send_packet_number = 1;
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 60,
                                 });
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*next_wakeup);

    const auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(second_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest,
     ServerPtoProbeWithHandshakeCryptoAndOnlyApplicationCryptoInFlightEmitsSecondDatagram) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(36), std::byte{0x31}));
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
    if (!next_wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*next_wakeup);

    const auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    ASSERT_FALSE(second_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest,
     LargeHandshakeProbeLeavesRoomForApplicationProbeInSecondPtoDatagramInsteadOfFailing) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;
    connection.remaining_pto_probe_datagrams_ = 2;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    connection.handshake_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(1170), std::byte{0x31}));
    const auto handshake_crypto = connection.handshake_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(handshake_crypto.empty());
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 4,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges = handshake_crypto,
        .bytes_in_flight = 1200,
    };
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .has_handshake_done = true,
        .bytes_in_flight = 21,
    };

    const auto first_probe_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto second_probe_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(second_probe_datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, HandshakeOversizeFinalizesInitialPacketAtAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 400;
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x44});
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.handshake_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(connection.handshake_space_.next_send_packet_number, 1u);

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 2u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front()), nullptr);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.back());
    ASSERT_NE(handshake, nullptr);
    EXPECT_TRUE(std::ranges::any_of(handshake->frames, [](const auto &frame) {
        return std::holds_alternative<coquic::quic::AckFrame>(frame);
    }));
}

TEST(QuicCoreTest, ArmPtoProbeCoalescesHandshakeProbeWhenInitialCryptoIsPending) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hello"));

    connection.arm_pto_probe(coquic::quic::test::test_time(999));

    EXPECT_EQ(connection.pto_count_, 1u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, SelectPtoProbeSkipsPacketsThatCannotBeProbed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    coquic::quic::PacketSpaceState packet_space;
    connection.track_sent_packet(packet_space, coquic::quic::SentPacketRecord{
                                                   .packet_number = 0,
                                                   .sent_time = coquic::quic::test::test_time(0),
                                                   .ack_eliciting = false,
                                                   .in_flight = false,
                                                   .has_ping = true,
                                               });
    connection.track_sent_packet(packet_space, coquic::quic::SentPacketRecord{
                                                   .packet_number = 1,
                                                   .sent_time = coquic::quic::test::test_time(0),
                                                   .ack_eliciting = true,
                                                   .in_flight = false,
                                                   .has_ping = true,
                                               });
    connection.track_sent_packet(packet_space, coquic::quic::SentPacketRecord{
                                                   .packet_number = 2,
                                                   .sent_time = coquic::quic::test::test_time(0),
                                                   .ack_eliciting = true,
                                                   .in_flight = true,
                                                   .has_ping = true,
                                               });

    const auto probe = connection.select_pto_probe(packet_space);

    EXPECT_EQ(probe.packet_number, 2u);
    EXPECT_TRUE(probe.has_ping);
}

TEST(QuicCoreTest, AckDeadlinePrefersEarlierLaterPacketSpaceDeadline) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.pending_ack_deadline = coquic::quic::test::test_time(8);
    connection.handshake_space_.pending_ack_deadline = coquic::quic::test::test_time(3);
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(5);

    EXPECT_EQ(connection.ack_deadline(), std::optional{coquic::quic::test::test_time(3)});
}

TEST(QuicCoreTest, LossDeadlineUsesEarliestEligiblePacketWithinPacketSpace) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.recovery.largest_acked_packet_number_ = 10;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(5),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    EXPECT_EQ(connection.loss_deadline(),
              std::optional{coquic::quic::QuicCoreTimePoint{} + std::chrono::microseconds(11250)});
}

TEST(QuicCoreTest, DeadlineHelpersPreferEarlierCandidatesAndSkipIneligiblePackets) {
    auto connection = make_connected_client_connection();
    connection.initial_space_.recovery.largest_acked_packet_number_ = 6;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(5),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 4,
                                     .sent_time = coquic::quic::test::test_time(2),
                                     .ack_eliciting = true,
                                     .in_flight = false,
                                 });

    const auto loss_deadline = connection.loss_deadline();
    const auto pto_deadline = connection.pto_deadline();

    if (!loss_deadline.has_value() || !pto_deadline.has_value()) {
        GTEST_FAIL() << "expected loss and PTO deadlines";
        return;
    }
    EXPECT_LT(*loss_deadline, *pto_deadline);
}

TEST(QuicCoreTest, DeadlineTrackingCacheRefreshesAfterTrackedPacketsAreRemoved) {
    auto connection = make_connected_client_connection();
    auto &packet_space = connection.initial_space_;
    packet_space.recovery.largest_acked_packet_number_ = 10;

    connection.track_sent_packet(packet_space, coquic::quic::SentPacketRecord{
                                                   .packet_number = 1,
                                                   .sent_time = coquic::quic::test::test_time(5),
                                                   .ack_eliciting = true,
                                                   .in_flight = true,
                                               });
    connection.track_sent_packet(packet_space, coquic::quic::SentPacketRecord{
                                                   .packet_number = 2,
                                                   .sent_time = coquic::quic::test::test_time(9),
                                                   .ack_eliciting = true,
                                                   .in_flight = true,
                                               });
    connection.track_sent_packet(packet_space, coquic::quic::SentPacketRecord{
                                                   .packet_number = 3,
                                                   .sent_time = coquic::quic::test::test_time(7),
                                                   .ack_eliciting = true,
                                                   .in_flight = true,
                                               });

    EXPECT_EQ(
        optional_value_or_terminate(packet_space.recovery.latest_in_flight_ack_eliciting_packet())
            .packet_number,
        2u);
    EXPECT_EQ(
        optional_value_or_terminate(packet_space.recovery.earliest_loss_packet()).packet_number,
        1u);

    connection.retire_acked_packet(
        packet_space,
        optional_value_or_terminate(packet_space.recovery.handle_for_packet_number(2)));

    EXPECT_EQ(
        optional_value_or_terminate(packet_space.recovery.latest_in_flight_ack_eliciting_packet())
            .packet_number,
        3u);

    connection.mark_lost_packet(
        packet_space,
        optional_value_or_terminate(packet_space.recovery.handle_for_packet_number(1)));

    EXPECT_EQ(
        optional_value_or_terminate(packet_space.recovery.earliest_loss_packet()).packet_number,
        3u);
    EXPECT_EQ(
        optional_value_or_terminate(packet_space.recovery.latest_in_flight_ack_eliciting_packet())
            .packet_number,
        3u);
}

TEST(QuicCoreTest, ServerApplicationAckDoesNotConfirmHandshakeBeforeTlsCompletion) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::sent;
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 7,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 60,
                                 });

    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());
    ASSERT_TRUE(connection.streams_.contains(0));
    auto &stream = connection.streams_.at(0);

    auto first_fragment = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 384,
        .new_bytes = 384,
    });
    auto second_fragment = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 383,
        .new_bytes = 383,
    });
    auto tail_fragment = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 512,
        .new_bytes = 512,
    });

    ASSERT_EQ(first_fragment.size(), 1u);
    ASSERT_EQ(second_fragment.size(), 1u);
    ASSERT_EQ(tail_fragment.size(), 1u);
    EXPECT_EQ(first_fragment.front().offset, 0u);
    EXPECT_EQ(second_fragment.front().offset, 384u);
    EXPECT_EQ(tail_fragment.front().offset, 767u);
    EXPECT_TRUE(tail_fragment.front().fin);

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = tail_fragment,
                                     .bytes_in_flight = 320,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 2,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = first_fragment,
                                     .bytes_in_flight = 448,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 3,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .stream_fragments = second_fragment,
                                     .bytes_in_flight = 447,
                                 });

    const auto &peer_transport_parameters =
        optional_ref_or_terminate(connection.peer_transport_parameters_);
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.application_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = 3,
                                             .first_ack_range = 1,
                                         },
                                         coquic::quic::test::test_time(2),
                                         peer_transport_parameters.ack_delay_exponent,
                                         peer_transport_parameters.max_ack_delay,
                                         /*suppress_pto_reset=*/false)
                    .has_value());

    EXPECT_FALSE(connection.handshake_confirmed_);
    connection.confirm_handshake();
    ASSERT_TRUE(connection.next_wakeup().has_value());
    const auto deadline = optional_value_or_terminate(connection.next_wakeup());

    connection.on_timeout(deadline);
    const auto probe_datagram = connection.drain_outbound_datagram(deadline);
    ASSERT_FALSE(probe_datagram.empty());

    const auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&probe_packets[0]);
    ASSERT_NE(application, nullptr);

    std::vector<coquic::quic::StreamFrame> stream_frames;
    for (const auto &frame : application->frames) {
        if (const auto *stream_frame = std::get_if<coquic::quic::StreamFrame>(&frame)) {
            stream_frames.push_back(*stream_frame);
        }
    }

    ASSERT_EQ(stream_frames.size(), 1u);
    ASSERT_TRUE(stream_frames.front().offset.has_value());
    EXPECT_EQ(optional_value_or_terminate(stream_frames.front().offset), 767u);
    EXPECT_EQ(stream_frames.front().stream_data.size(), static_cast<std::size_t>(257));
    EXPECT_TRUE(stream_frames.front().fin);
}

TEST(QuicCoreTest, ArmPtoProbeSkipsPacketSpacesWhoseDeadlineHasNotArrived) {
    auto connection = make_connected_client_connection();
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(10),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    EXPECT_EQ(connection.pto_count_, 0u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakePtoBackoffCapsBeforeHandshakeConfirmation) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.pto_count_ = 4;

    connection.arm_pto_probe(coquic::quic::test::test_time(4000));

    EXPECT_EQ(connection.pto_count_, 5u);
    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakePtoDeadlineCapsBeforeHandshakeConfirmation) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.pto_count_ = 4;

    const auto capped_deadline = std::optional{coquic::quic::compute_pto_deadline(
        connection.recovery_rtt_state_, std::chrono::milliseconds(0),
        coquic::quic::test::test_time(0), 2)};
    const auto uncapped_deadline = std::optional{coquic::quic::compute_pto_deadline(
        connection.recovery_rtt_state_, std::chrono::milliseconds(0),
        coquic::quic::test::test_time(0), connection.pto_count_)};

    EXPECT_EQ(connection.pto_deadline(), capped_deadline);
    EXPECT_EQ(connection.next_wakeup(), capped_deadline);
    EXPECT_NE(connection.pto_deadline(), uncapped_deadline);
}

TEST(QuicCoreTest, ClientHandshakeKeepalivePtoUsesPeerActivityBeforeHandshakeKeysAreReady) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    EXPECT_EQ(connection.pto_deadline(), std::optional{coquic::quic::test::test_time(4000)});
    EXPECT_EQ(connection.next_wakeup(), std::optional{coquic::quic::test::test_time(4000)});

    connection.on_timeout(coquic::quic::test::test_time(4000));

    EXPECT_EQ(connection.pto_count_, 5u);
    EXPECT_TRUE(connection.initial_space_.pending_probe_packet.has_value() &&
                connection.initial_space_.pending_probe_packet->has_ping);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveAckDoesNotResetPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    ASSERT_EQ(connection.pto_deadline(), std::optional{coquic::quic::test::test_time(4000)});

    connection.on_timeout(coquic::quic::test::test_time(4000));

    ASSERT_EQ(connection.pto_count_, 5u);
    EXPECT_TRUE(connection.initial_space_.pending_probe_packet.has_value() &&
                connection.initial_space_.pending_probe_packet->has_ping);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4000));
    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);

    const auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(4100), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 5u);
    const auto next_deadline = connection.pto_deadline();
    EXPECT_TRUE(next_deadline.has_value() &&
                next_deadline.value() > coquic::quic::test::test_time(5000));
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveLateAckDoesNotResetPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    connection.on_timeout(coquic::quic::test::test_time(4000));

    ASSERT_EQ(connection.pto_count_, 5u);
    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value() &&
                connection.initial_space_.pending_probe_packet->has_ping);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4000));
    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);

    const auto late_handle =
        optional_value_or_terminate(connection.initial_space_.recovery.handle_for_packet_number(0));
    ASSERT_TRUE(connection.mark_lost_packet(connection.initial_space_, late_handle).has_value());

    const auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(4100), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 5u);
    const auto next_deadline = connection.pto_deadline();
    EXPECT_TRUE(next_deadline.has_value() &&
                next_deadline.value() > coquic::quic::test::test_time(5000));
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveLateAckOfRetransmittablePacketResetsPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.pto_count_ = 5;

    connection.track_sent_packet(connection.initial_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 0,
                                     .sent_time = coquic::quic::test::test_time(4000),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .crypto_ranges =
                                         {
                                             coquic::quic::ByteRange{
                                                 .offset = 0,
                                                 .bytes = {std::byte{0x01}},
                                             },
                                         },
                                     .has_ping = true,
                                 });

    const auto late_handle =
        optional_value_or_terminate(connection.initial_space_.recovery.handle_for_packet_number(0));
    ASSERT_TRUE(connection.mark_lost_packet(connection.initial_space_, late_handle).has_value());

    const auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(4100), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveAckOnlyPacketDoesNotRefreshPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    connection.on_timeout(coquic::quic::test::test_time(4000));

    ASSERT_EQ(connection.pto_count_, 5u);
    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4000));
    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    ASSERT_EQ(connection.last_client_handshake_keepalive_probe_time_,
              std::optional{coquic::quic::test::test_time(4000)});
    ASSERT_EQ(connection.pto_count_, 5u);

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .destination_connection_id = {},
            .source_connection_id = {std::byte{0x01}},
            .token = {},
            .packet_number = 1,
            .frames =
                {
                    coquic::quic::AckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                    },
                },
        },
        coquic::quic::test::test_time(4100));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 5u);
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    const auto next_deadline = connection.pto_deadline();
    EXPECT_TRUE(next_deadline.has_value() &&
                next_deadline.value() > coquic::quic::test::test_time(5000));
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveUsesMostRecentProbeTimeAsReference) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(10);
    connection.pto_count_ = 4;

    const auto expected = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
                                                             std::chrono::milliseconds(0),
                                                             coquic::quic::test::test_time(10), 2);

    EXPECT_EQ(connection.pto_deadline(), std::optional{expected});
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeArmsFromMostRecentProbeTimeReference) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(10);
    connection.pto_count_ = 4;

    const auto deadline = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
                                                             std::chrono::milliseconds(0),
                                                             coquic::quic::test::test_time(10), 2);

    connection.arm_pto_probe(deadline);

    EXPECT_EQ(connection.pto_count_, 5u);
    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(optional_ref_or_terminate(connection.initial_space_.pending_probe_packet).has_ping);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeRepeatsHandshakeAckAfterAckOnlySend) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.initial_packet_space_discarded_ = true;
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.handshake_space_.received_packets.record_received(
        /*packet_number=*/7, /*ack_eliciting=*/true, coquic::quic::test::test_time(4));

    const auto first_ack_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(5));
    ASSERT_FALSE(first_ack_datagram.empty());
    ASSERT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());

    const auto deadline = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
                                                             std::chrono::milliseconds(0),
                                                             coquic::quic::test::test_time(4), 2);
    connection.arm_pto_probe(deadline);

    ASSERT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(
        optional_ref_or_terminate(connection.handshake_space_.pending_probe_packet).has_ping);

    const auto probe_datagram = connection.drain_outbound_datagram(deadline);
    ASSERT_FALSE(probe_datagram.empty());

    const auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&probe_packets[0]);
    ASSERT_NE(handshake, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (const auto &frame : handshake->frames) {
        if (const auto *ack = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = saw_ack || ack_frame_acks_packet_number_for_tests(*ack, 7);
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_ping);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeRepeatsInitialAckAfterAckOnlySend) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.initial_space_.received_packets.record_received(
        /*packet_number=*/7, /*ack_eliciting=*/true, coquic::quic::test::test_time(4));

    const auto first_ack_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(5));
    ASSERT_FALSE(first_ack_datagram.empty());
    ASSERT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());

    const auto deadline = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
                                                             std::chrono::milliseconds(0),
                                                             coquic::quic::test::test_time(4), 2);
    connection.arm_pto_probe(deadline);

    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(optional_ref_or_terminate(connection.initial_space_.pending_probe_packet).has_ping);

    const auto probe_datagram = connection.drain_outbound_datagram(deadline);
    ASSERT_FALSE(probe_datagram.empty());

    const auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&probe_packets[0]);
    ASSERT_NE(initial, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (const auto &frame : initial->frames) {
        if (const auto *ack = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = saw_ack || ack_frame_acks_packet_number_for_tests(*ack, 7);
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_ping);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeDoesNotArmBeforeDeadline) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    connection.arm_pto_probe(coquic::quic::test::test_time(3999));

    EXPECT_EQ(connection.pto_count_, 4u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ServerInitialAckOnlySendAddsSinglePingWhenNothingIsInFlight) {
    auto config = coquic::quic::test::make_server_core_config();
    config.source_connection_id = bytes_from_hex("5300000000000031");

    coquic::quic::QuicConnection connection(std::move(config));
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.original_version_ = coquic::quic::kQuicVersion1;
    connection.current_version_ = coquic::quic::kQuicVersion1;
    connection.client_initial_destination_connection_id_ = bytes_from_hex("8394c8f03e515708");
    connection.peer_source_connection_id_ = bytes_from_hex("c101");
    connection.anti_amplification_received_bytes_ = 2400;
    connection.initial_space_.received_packets.record_received(
        /*packet_number=*/7, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front());
    ASSERT_NE(initial, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (const auto &frame : initial->frames) {
        if (const auto *ack_frame = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = saw_ack || ack_frame_acks_packet_number_for_tests(*ack_frame, 7);
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_ping);
    const auto tracked_after_first_initial_send = tracked_packet_count(connection.initial_space_);
    ASSERT_NE(tracked_after_first_initial_send, 0u);
    EXPECT_TRUE(last_tracked_packet(connection.initial_space_).has_ping);

    connection.initial_space_.received_packets.record_received(
        /*packet_number=*/9, /*ack_eliciting=*/true, coquic::quic::test::test_time(2));
    const auto second_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(second_datagram.empty());
    const auto second_packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(second_packets.size(), 1u);
    const auto *second_initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&second_packets.front());
    ASSERT_NE(second_initial, nullptr);

    bool saw_second_ack = false;
    bool saw_second_ping = false;
    for (const auto &frame : second_initial->frames) {
        if (const auto *ack_frame = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_second_ack =
                saw_second_ack || ack_frame_acks_packet_number_for_tests(*ack_frame, 9);
        }
        saw_second_ping = saw_second_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_second_ack);
    EXPECT_FALSE(saw_second_ping);
    EXPECT_FALSE(last_tracked_packet(connection.initial_space_).has_ping);
    EXPECT_FALSE(last_tracked_packet(connection.initial_space_).ack_eliciting);
}

TEST(QuicCoreTest, ServerHandshakeAckOnlySendAddsSinglePingWhenNothingIsInFlight) {
    auto config = coquic::quic::test::make_server_core_config();
    config.source_connection_id = bytes_from_hex("5300000000000032");

    coquic::quic::QuicConnection connection(std::move(config));
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.initial_packet_space_discarded_ = true;
    connection.original_version_ = coquic::quic::kQuicVersion1;
    connection.current_version_ = coquic::quic::kQuicVersion1;
    connection.client_initial_destination_connection_id_ = bytes_from_hex("8394c8f03e515709");
    connection.peer_source_connection_id_ = bytes_from_hex("c101");
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.anti_amplification_received_bytes_ = 2400;
    connection.handshake_space_.received_packets.record_received(
        /*packet_number=*/11, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front());
    ASSERT_NE(handshake, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (const auto &frame : handshake->frames) {
        if (const auto *ack_frame = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = saw_ack || ack_frame_acks_packet_number_for_tests(*ack_frame, 11);
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_ping);
    const auto tracked_after_first_handshake_send =
        tracked_packet_count(connection.handshake_space_);
    ASSERT_NE(tracked_after_first_handshake_send, 0u);
    EXPECT_TRUE(last_tracked_packet(connection.handshake_space_).has_ping);

    connection.handshake_space_.received_packets.record_received(
        /*packet_number=*/13, /*ack_eliciting=*/true, coquic::quic::test::test_time(2));
    const auto second_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(second_datagram.empty());
    const auto second_packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(second_packets.size(), 1u);
    const auto *second_handshake =
        std::get_if<coquic::quic::ProtectedHandshakePacket>(&second_packets.front());
    ASSERT_NE(second_handshake, nullptr);

    bool saw_second_ack = false;
    bool saw_second_ping = false;
    for (const auto &frame : second_handshake->frames) {
        if (const auto *ack_frame = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_second_ack =
                saw_second_ack || ack_frame_acks_packet_number_for_tests(*ack_frame, 13);
        }
        saw_second_ping = saw_second_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_second_ack);
    EXPECT_FALSE(saw_second_ping);
    EXPECT_FALSE(last_tracked_packet(connection.handshake_space_).has_ping);
    EXPECT_FALSE(last_tracked_packet(connection.handshake_space_).ack_eliciting);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeDoesNotArmAfterInitialSpaceDiscarded) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.initial_packet_space_discarded_ = true;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;

    EXPECT_FALSE(connection.pto_deadline().has_value());

    connection.arm_pto_probe(coquic::quic::test::test_time(4000));

    EXPECT_EQ(connection.pto_count_, 4u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveProbeDoesNotArmWhileAckElicitingPacketIsInFlight) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    connection.arm_pto_probe(coquic::quic::test::test_time(2));

    EXPECT_EQ(connection.pto_count_, 4u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveTracksHandshakeProbePacketSend) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 9,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto now = coquic::quic::test::test_time(5);
    const auto datagram = connection.drain_outbound_datagram(now);

    ASSERT_FALSE(datagram.empty());
    EXPECT_EQ(connection.last_client_handshake_keepalive_probe_time_, now);
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveTrackingIgnoresRetransmittableProbePackets) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 1,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = {std::byte{0x01}},
                },
            },
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.last_client_handshake_keepalive_probe_time_.has_value());
}

TEST(QuicCoreTest, ClientHandshakeAckOnlyHandshakePacketDoesNotRefreshPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(4000);
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x42});

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .destination_connection_id = {},
            .source_connection_id = {std::byte{0x02}},
            .packet_number = 1,
            .frames =
                {
                    coquic::quic::AckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                    },
                },
        },
        coquic::quic::test::test_time(4100));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    EXPECT_FALSE(connection.handshake_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest, ClientSendsStandaloneHandshakeAckWhileHandshakeInProgress) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x52});

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .destination_connection_id = {},
            .source_connection_id = {std::byte{0x02}},
            .packet_number = 1,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    ASSERT_EQ(connection.handshake_space_.pending_ack_deadline,
              std::optional{coquic::quic::test::test_time(1)});

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets[0]);
    ASSERT_NE(handshake, nullptr);

    const auto ack_it =
        std::find_if(handshake->frames.begin(), handshake->frames.end(), [](const auto &frame) {
            return std::holds_alternative<coquic::quic::AckFrame>(frame);
        });
    EXPECT_NE(ack_it, handshake->frames.end());
}

TEST(QuicCoreTest, ApplicationSpaceAckOfPingOnlyPacketResetsHandshakePtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.pto_count_ = 5;
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 7,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                     .bytes_in_flight = 1,
                                 });

    const auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 7,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(2), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 0u);
}

TEST(QuicCoreTest, ClientHandshakeAckOfRetransmittableProbeResetsPtoBackoff) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.pto_count_ = 5;
    connection.track_sent_packet(
        connection.initial_space_,
        coquic::quic::SentPacketRecord{
            .packet_number = 0,
            .sent_time = coquic::quic::test::test_time(1),
            .ack_eliciting = true,
            .in_flight = true,
            .max_streams_frames =
                {
                    coquic::quic::MaxStreamsFrame{
                        .stream_type = coquic::quic::StreamLimitType::bidirectional,
                        .maximum_streams = 1,
                    },
                },
            .has_ping = true,
            .bytes_in_flight = 1,
        });

    const auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(2), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
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
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ack-me"),
        },
        coquic::quic::test::test_time(1));
    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(1));
    EXPECT_TRUE(server.connection_->next_wakeup().has_value());

    auto response = received;
    auto response_datagrams = coquic::quic::test::send_datagrams_from(response);
    if (response_datagrams.empty()) {
        response = server.advance(coquic::quic::QuicCoreTimerExpired{},
                                  optional_value_or_terminate(server.connection_->next_wakeup()));
        response_datagrams = coquic::quic::test::send_datagrams_from(response);
    }

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
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));
    const auto second_send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
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
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("retire-me"),
        },
        coquic::quic::test::test_time(1));

    ASSERT_NE(tracked_packet_count(client.connection_->application_space_), 0u);
    ASSERT_TRUE(client.connection_->streams_.contains(0));
    EXPECT_TRUE(client.connection_->streams_.at(0).has_outstanding_send());

    const auto server_step = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(2));
    ASSERT_TRUE(server_step.next_wakeup.has_value());

    const auto ack_deadline = optional_value_or_terminate(server_step.next_wakeup);
    const auto server_ack = server.advance(coquic::quic::QuicCoreTimerExpired{}, ack_deadline);
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(server_ack).empty());

    const auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_ack, client, ack_deadline + std::chrono::milliseconds(1));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(client_step).empty());
    EXPECT_EQ(tracked_packet_count(client.connection_->application_space_), 0u);
    EXPECT_FALSE(client.connection_->streams_.at(0).has_pending_send());
    EXPECT_FALSE(client.connection_->streams_.at(0).has_outstanding_send());
}

TEST(QuicCoreTest, ApplicationAckResponsesSendAckFrameAfterDelayedAckDeadline) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto server_send = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ack-me"),
        },
        coquic::quic::test::test_time(1));

    const auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_send, client, coquic::quic::test::test_time(2));

    EXPECT_FALSE(client.has_failed());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(client_step)),
              "ack-me");

    auto ack_step = client_step;
    if (coquic::quic::test::send_datagrams_from(ack_step).empty()) {
        const auto ack_deadline = client.connection_->next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        ack_step = client.advance(coquic::quic::QuicCoreTimerExpired{},
                                  optional_value_or_terminate(ack_deadline));
    }
    const auto ack_datagrams = coquic::quic::test::send_datagrams_from(ack_step);
    EXPECT_FALSE(ack_datagrams.empty());
    EXPECT_TRUE(std::any_of(ack_datagrams.begin(), ack_datagrams.end(), [&](const auto &datagram) {
        return datagram_has_application_ack(*client.connection_, datagram);
    }));
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
    client.connection_->application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

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

TEST(QuicCoreTest, InitialProbePacketCanRetransmitCryptoRanges) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 2,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 7,
                    .bytes = coquic::quic::test::bytes_from_string("hi"),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);

    bool saw_crypto = false;
    for (const auto &frame : initial->frames) {
        const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
        if (crypto == nullptr) {
            continue;
        }

        saw_crypto = true;
        EXPECT_EQ(crypto->offset, 7u);
        EXPECT_EQ(crypto->crypto_data, coquic::quic::test::bytes_from_string("hi"));
    }

    EXPECT_TRUE(saw_crypto);
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    EXPECT_EQ(first_tracked_packet(connection.initial_space_).crypto_ranges.size(), 1u);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, InitialProbePacketCanFallbackToPing) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 3,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    EXPECT_TRUE(first_tracked_packet(connection.initial_space_).has_ping);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, InitialSendPrefersFreshCryptoRangesOverStoredProbeSnapshot) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("live"));
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 30,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 9,
                    .bytes = coquic::quic::test::bytes_from_string("old"),
                },
            },
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    const auto &sent_packet = first_tracked_packet(connection.initial_space_);
    ASSERT_EQ(sent_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].offset, 0u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].bytes, coquic::quic::test::bytes_from_string("live"));
    EXPECT_FALSE(sent_packet.has_ping);
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, HandshakeProbePacketCanRetransmitCryptoRanges) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 4,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 11,
                    .bytes = coquic::quic::test::bytes_from_string("hs"),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets[0]);
    ASSERT_NE(handshake, nullptr);
    ASSERT_EQ(handshake->frames.size(), 1u);
    const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&handshake->frames[0]);
    ASSERT_NE(crypto, nullptr);
    EXPECT_EQ(crypto->offset, 11u);
    ASSERT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
    EXPECT_EQ(first_tracked_packet(connection.handshake_space_).crypto_ranges.size(), 1u);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, HandshakeProbePacketCanFallbackToPing) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 5,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
    EXPECT_TRUE(first_tracked_packet(connection.handshake_space_).has_ping);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, HandshakeProbeTrimLoopCanDropFullyTrimmedProbeRange) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 32,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1300, std::byte{0x51}),
                },
                coquic::quic::ByteRange{
                    .offset = 1300,
                    .bytes = std::vector<std::byte>(1, std::byte{0x52}),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets[0]);
    ASSERT_NE(handshake, nullptr);

    std::vector<const coquic::quic::CryptoFrame *> crypto_frames;
    for (const auto &frame : handshake->frames) {
        if (const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame)) {
            crypto_frames.push_back(crypto);
        }
    }

    ASSERT_EQ(crypto_frames.size(), 1u);
    EXPECT_EQ(crypto_frames.front()->offset, 0u);
    EXPECT_LT(crypto_frames.front()->crypto_data.size(), 1300u);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest,
     HandshakeProbeTrimReserializationFailureMarksConnectionFailedAfterDroppingRange) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 33,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1300, std::byte{0x53}),
                },
                coquic::quic::ByteRange{
                    .offset = 1300,
                    .bytes = std::vector<std::byte>(1, std::byte{0x54}),
                },
            },
    };
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
}

TEST(QuicCoreTest, HandshakeProbeTrimLoopStopsWhenAckStillOverflowsAfterAllProbeCryptoIsRemoved) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 34,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = coquic::quic::test::bytes_from_string("hs"),
                },
            },
    };
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.handshake_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
}

TEST(QuicCoreTest, HandshakeSendPrefersFreshCryptoRangesOverStoredProbeSnapshot) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("live"));
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 31,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 9,
                    .bytes = coquic::quic::test::bytes_from_string("old"),
                },
            },
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
    const auto &sent_packet = first_tracked_packet(connection.handshake_space_);
    ASSERT_EQ(sent_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].offset, 0u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].bytes, coquic::quic::test::bytes_from_string("live"));
    EXPECT_FALSE(sent_packet.has_ping);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ApplicationProbePacketCanIncludeAckAndPing) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/12, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_ping);
    EXPECT_EQ(connection.application_space_.pending_ack_deadline, std::nullopt);
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    EXPECT_TRUE(first_tracked_packet(connection.application_space_).has_ping);
}

TEST(QuicCoreTest, ApplicationProbePacketCanIncludePendingApplicationCryptoAndPing) {
    auto connection = make_connected_server_connection();
    connection.application_space_.send_crypto.append(coquic::quic::test::bytes_from_string("app"));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 78,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_crypto = false;
    bool saw_ping = false;
    for (const auto &frame : application->frames) {
        if (const auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame)) {
            saw_crypto = true;
            EXPECT_EQ(crypto->offset, 0u);
            EXPECT_EQ(crypto->crypto_data, coquic::quic::test::bytes_from_string("app"));
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_crypto);
    EXPECT_TRUE(saw_ping);
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    const auto &sent_packet = first_tracked_packet(connection.application_space_);
    ASSERT_EQ(sent_packet.crypto_ranges.size(), 1u);
    EXPECT_EQ(sent_packet.crypto_ranges[0].bytes, coquic::quic::test::bytes_from_string("app"));
    EXPECT_TRUE(sent_packet.has_ping);
}

TEST(QuicCoreTest, ApplicationCryptoOnlyProbeBurstDoesNotFailWhenLostCryptoIsPending) {
    auto connection = make_connected_server_connection();
    connection.application_space_.send_crypto.append(coquic::quic::test::bytes_from_string("app"));
    auto lost_crypto = connection.application_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_EQ(lost_crypto.size(), 1u);
    const auto &range = lost_crypto.front();
    connection.application_space_.send_crypto.mark_lost(range.offset, range.bytes.size());
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 79,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges = lost_crypto,
    };
    connection.remaining_pto_probe_datagrams_ = 2;

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    static_cast<void>(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)));
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectedConnectionWithoutApplicationWriteSecretSkipsApplicationSend) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/12, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.write_secret = std::nullopt;

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ApplicationProbePathTrimsProbePayloadWhenAckWouldOverflowDatagram) {
    auto connection = make_connected_client_connection();
    for (std::uint64_t packet_number = 0; packet_number < 4096; ++packet_number) {
        connection.application_space_.received_packets.record_received(
            packet_number * 3, true,
            coquic::quic::test::test_time(static_cast<std::int64_t>(packet_number)));
    }
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 8,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1200, std::byte{0x41}),
                    .fin = false,
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(5000));

    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    const auto *stream = std::get_if<coquic::quic::StreamFrame>(&application->frames.back());
    ASSERT_NE(stream, nullptr);
    EXPECT_LT(stream->stream_data.size(), 1200u);
}

TEST(QuicCoreTest, ApplicationProbePathTrimsOversizeProbePayloadToFitDatagramBudget) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 9,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1200, std::byte{0x42}),
                    .fin = false,
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        const auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        saw_stream = true;
        EXPECT_LT(stream->stream_data.size(), 1200u);
    }
    EXPECT_TRUE(saw_stream);
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenPacketSerializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 10,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenAckCandidateSerializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/16, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 17,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePathDropsBaseAckWhenNoAckFallbackFits) {
    const auto payload_size = find_application_probe_payload_size_that_drops_ack();
    ASSERT_TRUE(payload_size.has_value());
    const auto payload_size_value = optional_value_or_terminate(payload_size);

    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/18, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 19,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(payload_size_value, std::byte{0x54}),
                    .fin = false,
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(datagram_has_application_ack(connection, datagram));
    EXPECT_TRUE(datagram_has_application_stream(connection, datagram));
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenNoAckFallbackSerializationFails) {
    const auto payload_size = find_application_probe_payload_size_that_drops_ack();
    ASSERT_TRUE(payload_size.has_value());
    const auto payload_size_value = optional_value_or_terminate(payload_size);

    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/20, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 21,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(payload_size_value, std::byte{0x55}),
                    .fin = false,
                },
            },
    };
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 3);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenTrimLoopReserializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 22,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1200, std::byte{0x56}),
                    .fin = false,
                },
            },
    };
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePathRestoresEmptyAndFullyTrimmedFragments) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    stream.send_buffer.append(std::vector<std::byte>(1201, std::byte{0x57}));

    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 23,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments =
            {
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 0,
                    .bytes = std::vector<std::byte>(1200, std::byte{0x57}),
                    .fin = false,
                },
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 1200,
                    .bytes = std::vector<std::byte>(1, std::byte{0x58}),
                    .fin = false,
                },
                coquic::quic::StreamFrameSendFragment{
                    .stream_id = 0,
                    .offset = 1201,
                    .bytes = {},
                    .fin = true,
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(datagram_has_application_stream(connection, datagram));
    EXPECT_EQ(stream.send_fin_state, coquic::quic::StreamSendFinState::pending);
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenAcklessControlFramesStillExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    for (std::uint64_t stream_index = 0; stream_index < 256; ++stream_index) {
        connection.application_space_.pending_probe_packet =
            connection.application_space_.pending_probe_packet.value_or(
                coquic::quic::SentPacketRecord{
                    .packet_number = 24,
                    .ack_eliciting = true,
                    .in_flight = true,
                });
        connection.application_space_.pending_probe_packet->reset_stream_frames.push_back(
            coquic::quic::ResetStreamFrame{
                .stream_id = stream_index * 4,
                .application_protocol_error_code = 1,
                .final_size = 0,
            });
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbeRestoresCryptoWhenAmplificationBudgetIsTooSmall) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    connection.application_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("probe-crypto"));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 27,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_TRUE(connection.application_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, ApplicationProbeRestoresLostProbeFragmentsWhenAmplificationBudgetIsTooSmall) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    connection.application_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("probe-crypto"));
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    const auto payload = coquic::quic::test::bytes_from_string("probe-fragment");
    stream.send_buffer.append(payload);
    const auto initial_fragments = stream.take_send_fragments(payload.size());
    ASSERT_EQ(initial_fragments.size(), 1u);
    stream.mark_send_fragment_lost(initial_fragments.front());
    ASSERT_TRUE(stream.send_buffer.has_lost_data());
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 28,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments = initial_fragments,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(stream.send_buffer.has_lost_data());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenAckAndControlFramesStillExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/25, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 26,
        .ack_eliciting = true,
        .in_flight = true,
    };
    for (std::uint64_t stream_index = 0; stream_index < 256; ++stream_index) {
        connection.application_space_.pending_probe_packet->reset_stream_frames.push_back(
            coquic::quic::ResetStreamFrame{
                .stream_id = stream_index * 4,
                .application_protocol_error_code = 1,
                .final_size = 0,
            });
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendPathFailsWhenAckCandidateSerializationFails) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/15, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("data"), false)
            .has_value());
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendPathFailsWhenPacketSerializationFails) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("data"), false)
            .has_value());
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, DrainOutboundDatagramReusesAcceptedApplicationCandidateSerialization) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("data"), false)
            .has_value());
    coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 4);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendPathSizesFinOnlyStreamsWithoutTrimReserialization) {
    auto connection = make_connected_client_connection();
    connection.stream_open_limits_.peer_max_bidirectional = 2048;
    for (std::uint64_t stream_index = 0; stream_index < 2048; ++stream_index) {
        ASSERT_TRUE(connection.queue_stream_send(stream_index * 4, {}, true).has_value());
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, ApplicationSendFailsWhenControlFramesAloneExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    for (std::uint64_t stream_index = 0; stream_index < 256; ++stream_index) {
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
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendRestoresUnsentCandidateWhenCongestionBlocked) {
    auto connection = make_connected_client_connection();
    auto &stream =
        connection.streams_
            .emplace(0, coquic::quic::make_implicit_stream_state(0, connection.config_.role))
            .first->second;
    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 20};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    connection.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 21};
    connection.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;
    stream.flow_control.pending_max_stream_data_frame = coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 22,
    };
    stream.flow_control.max_stream_data_state = coquic::quic::StreamControlFrameState::pending;
    stream.flow_control.pending_stream_data_blocked_frame = coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 23,
    };
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::pending;
    stream.pending_reset_frame = coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 1,
        .final_size = 0,
    };
    stream.reset_state = coquic::quic::StreamControlFrameState::pending;
    stream.pending_stop_sending_frame = coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 2,
    };
    stream.stop_sending_state = coquic::quic::StreamControlFrameState::pending;
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("blocked"), false)
            .has_value());

    connection.congestion_controller_.bytes_in_flight_ =
        connection.congestion_controller_.congestion_window();

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
    EXPECT_EQ(connection.connection_flow_control_.highest_sent, 0u);
    EXPECT_EQ(connection.connection_flow_control_.max_data_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(connection.connection_flow_control_.data_blocked_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(stream.flow_control.max_stream_data_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(stream.flow_control.stream_data_blocked_state,
              coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(stream.reset_state, coquic::quic::StreamControlFrameState::pending);
    EXPECT_EQ(stream.stop_sending_state, coquic::quic::StreamControlFrameState::pending);
}

TEST(QuicCoreTest, ApplicationSendDefersAckOnlyFallbackWhenCongestionBlockedBeforeAckDeadline) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/32, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(10);
    connection.application_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("blocked-crypto"));
    connection.congestion_controller_.bytes_in_flight_ =
        connection.congestion_controller_.congestion_window();

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    ASSERT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_EQ(optional_value_or_terminate(connection.application_space_.pending_ack_deadline),
              coquic::quic::test::test_time(10));
}

TEST(QuicCoreTest, ApplicationSendAllowsDueAckOnlyFallbackWhenCongestionBlocked) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/32, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(1);
    connection.application_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("blocked-crypto"));
    connection.congestion_controller_.bytes_in_flight_ =
        connection.congestion_controller_.congestion_window();
    const auto bytes_in_flight_before = connection.congestion_controller_.bytes_in_flight();
    const auto tracked_packets_before = tracked_packet_count(connection.application_space_);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.application_space_.send_crypto.has_pending_data());
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_TRUE(datagram_has_application_ack(connection, datagram));
    EXPECT_FALSE(datagram_has_application_stream(connection, datagram));
    EXPECT_EQ(connection.congestion_controller_.bytes_in_flight(), bytes_in_flight_before);
    EXPECT_EQ(tracked_packet_count(connection.application_space_), tracked_packets_before);
}

TEST(QuicCoreTest, ApplicationAckOnlyFastPathPreservesAdditionalAckRanges) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/40, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/42, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(1);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);
    ASSERT_EQ(application->frames.size(), 1u);
    const auto *ack = std::get_if<coquic::quic::AckFrame>(&application->frames.front());
    ASSERT_NE(ack, nullptr);
    EXPECT_TRUE(ack_frame_acks_packet_number_for_tests(*ack, 42));
    EXPECT_TRUE(ack_frame_acks_packet_number_for_tests(*ack, 40));
    EXPECT_FALSE(ack_frame_acks_packet_number_for_tests(*ack, 41));
    EXPECT_EQ(ack->additional_ranges.size(), 1u);
}

TEST(QuicCoreTest, ApplicationSendPathPreservesAckByTrimmingStreamData) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/27, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(
        connection.queue_stream_send(0, std::vector<std::byte>(1200, std::byte{0x59}), false)
            .has_value());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(datagram_has_application_ack(connection, datagram));
    EXPECT_TRUE(datagram_has_application_stream(connection, datagram));
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ApplicationSendFallsBackToAckOnlyWhenAmplificationBudgetShrinks) {
    bool saw_ack_only_fallback = false;

    for (std::uint64_t received_bytes = 10; received_bytes <= 80; ++received_bytes) {
        auto connection = make_connected_server_connection();
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = received_bytes;
        connection.application_space_.received_packets.record_received(
            /*packet_number=*/33, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
        ASSERT_TRUE(
            connection.queue_stream_send(0, std::vector<std::byte>(256, std::byte{0x60}), false)
                .has_value());

        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (connection.has_failed() || datagram.empty()) {
            continue;
        }

        if (!datagram_has_application_stream(connection, datagram) &&
            datagram_has_application_ack(connection, datagram) &&
            connection.has_pending_application_send()) {
            saw_ack_only_fallback = true;
            break;
        }
    }

    EXPECT_TRUE(saw_ack_only_fallback);
}

TEST(QuicCoreTest, ApplicationSendFailsWhenAckedControlFramesAndDataStillExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    connection.application_space_.received_packets.record_received(
        /*packet_number=*/30, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("x"), false)
                    .has_value());
    for (std::uint64_t stream_index = 1; stream_index <= 256; ++stream_index) {
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
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 0u);
}

TEST(QuicCoreTest, ApplicationSendWithLargeAckStateDoesNotFailPacketBudgetSearch) {
    auto connection = make_connected_server_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(4000), std::byte{0x46});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    for (std::uint64_t packet_number = 0; packet_number < 1200; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_TRUE(saw_ack || connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ApplicationSendOversizeFinalizesHandshakePacketAtAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 400;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x62});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 9,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    for (std::uint64_t stream_index = 0; stream_index < 256; ++stream_index) {
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

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front()), nullptr);
}

TEST(QuicCoreTest, FinalizeExistingHandshakeDatagramFailsWhenSerializationFails) {
    const auto configure_connection = [](coquic::quic::QuicConnection &connection) {
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 400;
        connection.handshake_space_.write_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x6a});
        connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
            .packet_number = 10,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };
        connection.application_space_.write_secret.reset();
    };

    auto control = make_connected_server_connection();
    configure_connection(control);
    const auto control_datagram = control.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(control_datagram.empty());
    EXPECT_FALSE(control.has_failed());
    const auto control_packets = decode_sender_datagram(control, control_datagram);
    ASSERT_EQ(control_packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&control_packets.front()),
              nullptr);

    auto failure = make_connected_server_connection();
    configure_connection(failure);
    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    const auto datagram = failure.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(failure.has_failed());
    EXPECT_EQ(tracked_packet_count(failure.handshake_space_), 1u);
}

TEST(QuicCoreTest, HandshakeOversizeWithoutInitialPacketReturnsEmptyAtAmplificationBudget) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x63});
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.handshake_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
}

TEST(QuicCoreTest, RetransmittedServerResponseStillCarriesAckForRepeatedRequestPacket) {
    auto connection = make_connected_server_connection();

    const auto process_request = [&](std::uint64_t packet_number,
                                     coquic::quic::QuicCoreTimePoint now) {
        const auto processed = connection.process_inbound_packet(
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = false,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 1,
                .packet_number = packet_number,
                .frames =
                    {
                        coquic::quic::StreamFrame{
                            .fin = true,
                            .has_offset = true,
                            .has_length = true,
                            .stream_id = 0,
                            .offset = 0,
                            .stream_data =
                                coquic::quic::test::bytes_from_string("GET /repeat-me\r\n"),
                        },
                    },
            },
            now);
        ASSERT_TRUE(processed.has_value());
    };

    process_request(/*packet_number=*/7, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.take_received_stream_data().has_value());
    ASSERT_TRUE(
        connection
            .queue_stream_send(
                0, std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x52}), true)
            .has_value());

    const auto first_response =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_response.empty());
    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);

    const auto first_packet_number =
        last_tracked_packet(connection.application_space_).packet_number;
    const auto first_packet =
        tracked_packet_or_terminate(connection.application_space_, first_packet_number);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(first_packet));

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));
    ASSERT_TRUE(connection.has_pending_application_send());

    process_request(/*packet_number=*/8, coquic::quic::test::test_time(2));
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const auto retransmitted = connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(retransmitted.empty());

    const auto packets = decode_sender_datagram(connection, retransmitted);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, CongestionBlockedApplicationSendStillEmitsAckOnlyDatagram) {
    auto connection = make_connected_server_connection();
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(2048), std::byte{0x52});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    connection.application_space_.received_packets.record_received(
        77, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    connection.congestion_controller_.on_packet_sent(
        connection.congestion_controller_.congestion_window(), /*ack_eliciting=*/true);
    ASSERT_EQ(connection.congestion_controller_.bytes_in_flight(),
              connection.congestion_controller_.congestion_window());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_FALSE(saw_stream);
    EXPECT_TRUE(connection.has_pending_application_send());
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, LostPostHandshakeCryptoDoesNotStarveRetransmittedServerResponse) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;

    const auto processed = connection.process_inbound_packet(
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
                        .stream_data = coquic::quic::test::bytes_from_string("GET /\r\n"),
                    },
                },
        },
        coquic::quic::test::test_time(0));
    ASSERT_TRUE(processed.has_value());
    ASSERT_TRUE(connection.take_received_stream_data().has_value());

    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));
    const auto payload = std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());

    const auto first_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);

    const auto first_packet_number =
        last_tracked_packet(connection.application_space_).packet_number;
    const auto first_packet =
        tracked_packet_or_terminate(connection.application_space_, first_packet_number);
    EXPECT_FALSE(first_packet.crypto_ranges.empty());

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));
    EXPECT_TRUE(connection.has_pending_application_send());

    const auto second_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(second_datagram.empty());

    const auto packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (const auto &frame : application->frames) {
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_FALSE(connection.has_failed());
}

} // namespace
