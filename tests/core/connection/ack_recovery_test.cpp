#include <gtest/gtest.h>
#include "tests/support/core/connection_ack_test_support.h"
#include "src/quic/connection/connection_internal.h"

namespace {

TEST(QuicCoreTest, SimpleStreamFastPathEligibilityIncludesImplementedControllers) {
    using Algorithm = coquic::quic::QuicCongestionControlAlgorithm;
    for (const auto algorithm :
         {Algorithm::newreno, Algorithm::cubic, Algorithm::bbr, Algorithm::copa}) {
        EXPECT_TRUE(coquic::quic::simple_stream_congestion_batch_algorithm_is_supported(algorithm));
        EXPECT_TRUE(coquic::quic::simple_stream_ack_sample_collection_is_eligible(
            /*has_late_acked_packets=*/false, /*has_lost_packets=*/false,
            coquic::quic::EndpointRole::server, /*qlog_enabled=*/false,
            /*packet_trace_enabled=*/false, algorithm));
        EXPECT_TRUE(coquic::quic::simple_stream_ack_fast_path_is_eligible(
            /*has_late_acked_packets=*/false, /*has_acked_packets=*/false,
            coquic::quic::EndpointRole::server, /*qlog_enabled=*/false,
            /*packet_trace_enabled=*/false, algorithm));
    }

    EXPECT_TRUE(
        coquic::quic::simple_stream_congestion_ack_aggregation_is_supported(Algorithm::newreno));
    EXPECT_TRUE(
        coquic::quic::simple_stream_congestion_ack_aggregation_is_supported(Algorithm::cubic));
    EXPECT_FALSE(
        coquic::quic::simple_stream_congestion_ack_aggregation_is_supported(Algorithm::bbr));
    EXPECT_FALSE(
        coquic::quic::simple_stream_congestion_ack_aggregation_is_supported(Algorithm::copa));
}

TEST(QuicCoreTest, TimeoutRunsLossDetectionAndArmsPtoProbe) {
    auto connection = make_connected_client_connection();

    connection.initial_space_.recovery.largest_acked_packet_number_ = 5;
    connection.initial_space_.recovery.rtt_state().latest_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().min_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().smoothed_rtt = std::chrono::milliseconds(10);
    connection.initial_space_.recovery.rtt_state().rttvar = std::chrono::milliseconds(5);
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("lost"));
    auto initial_ranges = connection.initial_space_.send_crypto.take_ranges(4);
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

TEST(QuicCoreTest, PmtudProbeAckRaisesValidatedDatagramSize) {
    auto connection = make_connected_client_connection();
    connection.config_.max_outbound_datagram_size = 1452;
    connection.config_.transport.pmtud_max_datagram_size = 1452;
    connection.current_send_path_id_ = 0;
    auto &path = connection.ensure_path_state(0);
    path.validated = true;
    path.mtu.enabled = true;
    path.mtu.viable = true;
    path.mtu.base_datagram_size = 1200;
    path.mtu.validated_datagram_size = 1200;
    path.mtu.search_low = 1200;
    path.mtu.probe_ceiling = 1452;
    path.mtu.next_probe_time = coquic::quic::test::test_time(1);

    connection.maybe_arm_pmtu_probe(coquic::quic::test::test_time(1));
    ASSERT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    const auto probe =
        optional_value_or_terminate(connection.application_space_.pending_probe_packet);
    ASSERT_TRUE(probe.is_pmtu_probe);
    EXPECT_GT(probe.pmtu_probe_size, path.mtu.validated_datagram_size);

    connection.note_pmtu_probe_sent(0, /*packet_number=*/42, probe.pmtu_probe_size);
    connection.note_pmtu_probe_acked(
        coquic::quic::SentPacketRecord{
            .packet_number = 42,
            .sent_time = coquic::quic::test::test_time(1),
            .ack_eliciting = true,
            .in_flight = true,
            .path_id = 0,
            .is_pmtu_probe = true,
            .pmtu_probe_size = probe.pmtu_probe_size,
        },
        coquic::quic::test::test_time(2));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.2
    // # An endpoint SHOULD use DPLPMTUD (Section 14.3) or PMTUD (Section
    // # 14.2.1) to determine whether the path to a destination will support a
    // # desired maximum datagram size without fragmentation.
    EXPECT_EQ(path.mtu.validated_datagram_size, probe.pmtu_probe_size);
    EXPECT_EQ(path.mtu.search_low, probe.pmtu_probe_size);
    EXPECT_FALSE(path.mtu.outstanding_probe_packet_number.has_value());
}

TEST(QuicCoreTest, LostPmtudProbeDoesNotTriggerCongestionReaction) {
    auto connection = make_connected_client_connection();
    connection.current_send_path_id_ = 0;
    auto &path = connection.ensure_path_state(0);
    path.validated = true;
    path.mtu.enabled = true;
    path.mtu.viable = true;
    path.mtu.validated_datagram_size = 1200;
    path.mtu.probe_ceiling = 1452;
    path.mtu.outstanding_probe_size = 1400;
    path.mtu.outstanding_probe_packet_number = 7;

    connection.congestion_controller_.congestion_window_ = 16000;
    connection.congestion_controller_.bytes_in_flight_ = 1400;
    const auto congestion_window_before = connection.congestion_controller_.congestion_window();
    const auto bytes_in_flight_before = connection.congestion_controller_.bytes_in_flight();

    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 7,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .bytes_in_flight = 1400,
                                     .path_id = 0,
                                     .is_pmtu_probe = true,
                                     .pmtu_probe_size = 1400,
                                 });
    ASSERT_TRUE(connection
                    .mark_lost_packet(
                        connection.application_space_,
                        optional_value_or_terminate(
                            connection.application_space_.recovery.handle_for_packet_number(7)),
                        /*already_marked_in_recovery=*/false, coquic::quic::test::test_time(3))
                    .has_value());

    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.4
    // # Loss of a QUIC packet that is carried in a PMTU probe is therefore not a
    // # reliable indication of congestion and SHOULD NOT trigger a congestion
    // # control reaction; see Item 7 in Section 3 of [DPLPMTUD].
    EXPECT_EQ(connection.congestion_controller_.congestion_window(), congestion_window_before);
    EXPECT_EQ(connection.congestion_controller_.bytes_in_flight(), bytes_in_flight_before);
    EXPECT_FALSE(path.mtu.outstanding_probe_packet_number.has_value());
    EXPECT_EQ(path.mtu.probe_ceiling, 1399u);
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

    auto processed = connection.process_inbound_packet(
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
    auto congestion_window = connection.congestion_controller_.congestion_window();
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

    auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);
    auto datagram = connection.drain_outbound_datagram(timeout);

    ASSERT_FALSE(datagram.empty());
    auto stream_ids = application_stream_ids_from_datagram(connection, datagram);
    if (stream_ids != std::vector<std::uint64_t>({0u})) {
        ADD_FAILURE() << "PTO did not emit the queued stream data";
    }
}

TEST(QuicCoreTest, ApplicationPtoPrefersRetransmittableProbeOverFreshData) {
    auto connection = make_connected_client_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(32) * 1024u, std::byte{0x50});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    std::optional<std::uint64_t> first_sent_offset;
    std::optional<std::uint64_t> last_sent_offset;
    std::uint64_t next_unsent_offset = 0;
    while (true) {
        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        auto packets = decode_sender_datagram(connection, datagram);
        if (packets.size() != 1u) {
            ADD_FAILURE() << "unexpected drained packet count";
            return;
        }
        auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
        if (application == nullptr) {
            ADD_FAILURE() << "drained packet was not a 1-RTT packet";
            return;
        }

        for (auto &frame : application->frames) {
            auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
            if (stream == nullptr) {
                continue;
            }

            if (!stream->offset.has_value()) {
                ADD_FAILURE() << "stream frame did not carry an offset";
                return;
            }
            auto stream_offset = optional_value_or_terminate(stream->offset);
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

    auto deadline = connection.pto_deadline();
    ASSERT_TRUE(deadline.has_value());
    auto timeout = optional_value_or_terminate(deadline);
    connection.on_timeout(timeout);

    auto &pending_probe_packet =
        optional_ref_or_terminate(connection.application_space_.pending_probe_packet);
    ASSERT_TRUE(sent_packet_has_stream_frames_for_tests(pending_probe_packet));

    auto probe_datagram = connection.drain_outbound_datagram(timeout);
    if (probe_datagram.empty()) {
        ADD_FAILURE() << "missing PTO probe datagram";
        return;
    }

    auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    if (probe_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected PTO probe packet count";
        return;
    }
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&probe_packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "PTO probe was not a 1-RTT packet";
        return;
    }

    std::vector<std::uint64_t> stream_offsets;
    for (auto &frame : application->frames) {
        auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
        if (stream == nullptr) {
            continue;
        }

        if (!stream->offset.has_value()) {
            ADD_FAILURE() << "probe stream frame did not carry an offset";
            return;
        }
        stream_offsets.push_back(optional_value_or_terminate(stream->offset));
    }

    if (stream_offsets.empty()) {
        ADD_FAILURE() << "PTO probe did not include stream frames";
        return;
    }
    if (stream_offsets.front() != optional_value_or_terminate(last_sent_offset)) {
        ADD_FAILURE() << "PTO probe did not retransmit the newest outstanding stream data";
    }
    if (stream_offsets.front() == optional_value_or_terminate(first_sent_offset)) {
        ADD_FAILURE() << "PTO probe retransmitted the oldest stream data";
    }
    if (stream_offsets.front() == next_unsent_offset) {
        ADD_FAILURE() << "PTO probe sent fresh stream data before retransmission";
    }
}

TEST(QuicCoreTest, ApplicationPtoPrefersNewestRetransmittablePacketOverOlderCryptoOnlyPacket) {
    auto connection = make_connected_server_connection();
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));
    auto crypto_ranges = connection.application_space_.send_crypto.take_ranges(
        std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(crypto_ranges.empty());

    auto payload = coquic::quic::test::bytes_from_string("server-response");
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

    auto retransmission_probe = connection.select_pto_probe(connection.application_space_);

    if (retransmission_probe.packet_number != 11u) {
        ADD_FAILURE() << "PTO probe did not choose the newest retransmittable packet";
    }
    if (retransmission_probe.stream_fragments.size() != 1u) {
        ADD_FAILURE() << "PTO probe did not carry the expected stream fragment";
        return;
    }
    if (retransmission_probe.stream_fragments.front().stream_id != 0u) {
        ADD_FAILURE() << "PTO probe stream id changed";
    }
    if (retransmission_probe.stream_fragments.front().bytes != payload) {
        ADD_FAILURE() << "PTO probe stream bytes changed";
    }
    if (!retransmission_probe.stream_fragments.front().fin) {
        ADD_FAILURE() << "PTO probe lost the FIN flag";
    }
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

    auto initial_fragments = stream.take_send_fragments(/*max_bytes=*/5);
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

    auto retransmitted_prefix = stream.take_send_fragments(coquic::quic::StreamSendBudget{
        .packet_bytes = 2,
        .new_bytes = 0,
    });
    ASSERT_EQ(retransmitted_prefix.size(), 1u);
    if (retransmitted_prefix[0].offset != 0u) {
        ADD_FAILURE() << "retransmitted prefix did not start at offset zero";
    }
    if (retransmitted_prefix[0].bytes != coquic::quic::test::bytes_from_string("he")) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
        // # The data at a given offset MUST NOT change if it is sent multiple times
        ADD_FAILURE() << "retransmitted prefix bytes changed";
    }
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

    auto fallback_probe = connection.select_pto_probe(connection.application_space_);
    if (!fallback_probe.stream_fragments.empty()) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        // # A sender SHOULD avoid retransmitting information from packets once
        // # they are acknowledged.
        ADD_FAILURE() << "PTO probe resent an already acknowledged stream prefix";
    }
    if (!fallback_probe.has_ping) {
        ADD_FAILURE() << "PTO probe did not fall back to a PING";
    }
    connection.application_space_.pending_probe_packet = fallback_probe;

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1000));
    if (datagram.empty()) {
        ADD_FAILURE() << "missing fallback PTO datagram";
        return;
    }
    auto packets = decode_sender_datagram(connection, datagram);
    if (packets.size() != 1u) {
        ADD_FAILURE() << "unexpected fallback PTO packet count";
        return;
    }
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "fallback PTO packet was not a 1-RTT packet";
        return;
    }

    std::vector<coquic::quic::StreamFrame> stream_frames;
    for (auto &frame : application->frames) {
        if (auto *stream_frame = std::get_if<coquic::quic::StreamFrame>(&frame)) {
            stream_frames.push_back(*stream_frame);
        }
    }

    if (stream_frames.size() != 1u) {
        ADD_FAILURE() << "fallback PTO datagram did not carry one stream frame";
        return;
    }
    if (!stream_frames[0].offset.has_value()) {
        ADD_FAILURE() << "fallback stream frame did not carry an offset";
        return;
    }
    if (optional_value_or_terminate(stream_frames[0].offset) != 2u) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        // # A sender SHOULD avoid retransmitting information from packets once
        // # they are acknowledged.
        ADD_FAILURE() << "fallback PTO resent the acknowledged prefix";
    }
    if (stream_frames[0].stream_data != coquic::quic::test::bytes_from_string("llo")) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
        // # The data at a given offset MUST NOT change if it is sent multiple times
        ADD_FAILURE() << "fallback PTO stream bytes changed";
    }
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

    auto start = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    auto start_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_EQ(start_datagrams.size(), 1u);

    auto client_packets = decode_sender_datagram(*client.connection_, start_datagrams.front());
    ASSERT_EQ(client_packets.size(), 1u);
    auto *client_initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&client_packets.front());
    ASSERT_NE(client_initial, nullptr);

    std::size_t client_hello_size = 0;
    for (auto &frame : client_initial->frames) {
        auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
        if (crypto == nullptr) {
            continue;
        }

        client_hello_size = std::max(client_hello_size, static_cast<std::size_t>(crypto->offset) +
                                                            crypto->crypto_data.size());
    }
    ASSERT_GT(client_hello_size, 128u);

    auto client_hello = std::vector<std::byte>(client_hello_size, std::byte{0x00});
    for (auto &frame : client_initial->frames) {
        auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
        if (crypto == nullptr) {
            continue;
        }

        std::copy(crypto->crypto_data.begin(), crypto->crypto_data.end(),
                  client_hello.begin() + static_cast<std::ptrdiff_t>(crypto->offset));
    }

    std::size_t prefix = 63u;
    std::size_t crypto_gap_size = 4u;
    std::size_t tail_offset = 1230u;
    if (client_hello.size() <= tail_offset) {
        prefix = std::min<std::size_t>(63u, client_hello.size() / 4u);
        crypto_gap_size = 1u;
        tail_offset =
            prefix + crypto_gap_size + ((client_hello.size() - (prefix + crypto_gap_size)) / 2u);
    }
    ASSERT_LT(prefix + crypto_gap_size, tail_offset);
    ASSERT_LT(tail_offset, client_hello.size());

    auto slice_bytes = [&](std::size_t begin, std::size_t end) {
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
                    .crypto_data = slice_bytes(prefix, prefix + crypto_gap_size),
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
                    .offset = static_cast<std::uint64_t>(prefix + crypto_gap_size),
                    .crypto_data = slice_bytes(prefix + crypto_gap_size, tail_offset),
                },
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = slice_bytes(0u, prefix),
                },
            },
    };

    auto pad_initial = [&](const coquic::quic::ProtectedInitialPacket &source_packet) {
        auto packet = source_packet;
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

    auto first_datagram = pad_initial(delivered_packet_one);
    auto server_after_first = server.advance(coquic::quic::QuicCoreInboundDatagram{first_datagram},
                                             coquic::quic::test::test_time(1));
    if (server.has_failed()) {
        ADD_FAILURE() << "server failed after first split Initial datagram";
    }
    if (coquic::quic::test::send_datagrams_from(server_after_first).empty()) {
        ADD_FAILURE() << "server did not respond after first split Initial datagram";
    }

    auto second_datagram = pad_initial(delivered_packet_two);
    auto server_after_second = server.advance(
        coquic::quic::QuicCoreInboundDatagram{second_datagram}, coquic::quic::test::test_time(2));
    if (server.has_failed()) {
        ADD_FAILURE() << "server failed after second split Initial datagram";
    }
    if (coquic::quic::test::send_datagrams_from(server_after_second).empty()) {
        ADD_FAILURE() << "server did not respond after second split Initial datagram";
    }

    auto next_wakeup = server_after_second.next_wakeup;
    if (!next_wakeup.has_value()) {
        ADD_FAILURE() << "server did not arm PTO wakeup";
        return;
    }
    auto probe = server.advance(coquic::quic::QuicCoreTimerExpired{}, next_wakeup.value());
    auto probe_datagrams = coquic::quic::test::send_datagrams_from(probe);
    if (probe_datagrams.size() != 2u) {
        ADD_FAILURE() << "server PTO did not emit the expected two datagrams";
    }
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

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing first application datagram";
        return;
    }

    auto next_wakeup = connection.next_wakeup();
    if (!next_wakeup.has_value()) {
        ADD_FAILURE() << "server did not arm a PTO wakeup";
        return;
    }

    connection.on_timeout(*next_wakeup);

    auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    if (first_probe_datagram.empty()) {
        ADD_FAILURE() << "missing first PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after first PTO probe datagram";
    }

    auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    if (second_probe_datagram.empty()) {
        ADD_FAILURE() << "missing second PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after second PTO probe datagram";
    }
}

TEST(QuicCoreTest, ServerPtoProbeWithOnlyApplicationCryptoInFlightDoesNotFailAcrossBurst) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;
    connection.application_space_.send_crypto.append(
        std::vector<std::byte>(static_cast<std::size_t>(233), std::byte{0x42}));

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing initial application crypto datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after initial application crypto datagram";
    }

    auto next_wakeup = connection.next_wakeup();
    if (!next_wakeup.has_value()) {
        ADD_FAILURE() << "server did not arm a PTO wakeup";
        return;
    }

    connection.on_timeout(*next_wakeup);

    auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    if (first_probe_datagram.empty()) {
        ADD_FAILURE() << "missing first PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after first PTO probe datagram";
    }

    (void)connection.drain_outbound_datagram(*next_wakeup);
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after PTO burst";
    }
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

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing initial application crypto datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after initial application crypto datagram";
    }

    auto next_wakeup = connection.next_wakeup();
    if (!next_wakeup.has_value()) {
        ADD_FAILURE() << "server did not arm a PTO wakeup";
        return;
    }

    connection.on_timeout(*next_wakeup);

    auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    if (first_probe_datagram.empty()) {
        ADD_FAILURE() << "missing first PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after first PTO probe datagram";
    }

    auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    if (second_probe_datagram.empty()) {
        ADD_FAILURE() << "missing second PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after second PTO probe datagram";
    }
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

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_datagram.empty()) {
        ADD_FAILURE() << "missing initial crypto datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after initial crypto datagram";
    }

    auto next_wakeup = connection.next_wakeup();
    if (!next_wakeup.has_value()) {
        ADD_FAILURE() << "server did not arm a PTO wakeup";
        return;
    }

    connection.on_timeout(*next_wakeup);

    auto first_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    if (first_probe_datagram.empty()) {
        ADD_FAILURE() << "missing first PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after first PTO probe datagram";
    }

    auto second_probe_datagram = connection.drain_outbound_datagram(*next_wakeup);
    if (second_probe_datagram.empty()) {
        ADD_FAILURE() << "missing second PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after second PTO probe datagram";
    }
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
    auto handshake_crypto = connection.handshake_space_.send_crypto.take_ranges(
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

    auto first_probe_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (first_probe_datagram.empty()) {
        ADD_FAILURE() << "missing first PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after first PTO probe datagram";
    }

    auto second_probe_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    if (second_probe_datagram.empty()) {
        ADD_FAILURE() << "missing second PTO probe datagram";
        return;
    }
    if (connection.has_failed()) {
        ADD_FAILURE() << "connection failed after second PTO probe datagram";
    }
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(connection.handshake_space_.next_send_packet_number, 1u);

    auto packets = decode_sender_datagram(connection, datagram);
    if (packets.size() != 2u) {
        ADD_FAILURE() << "handshake oversize datagram did not coalesce two packets";
        return;
    }
    if (std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front()) == nullptr) {
        ADD_FAILURE() << "first coalesced packet was not Initial";
    }
    auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.back());
    if (handshake == nullptr) {
        ADD_FAILURE() << "second coalesced packet was not Handshake";
        return;
    }
    if (!std::ranges::any_of(handshake->frames, [](auto &frame) {
            return std::holds_alternative<coquic::quic::AckFrame>(frame);
        })) {
        ADD_FAILURE() << "Handshake packet did not carry an ACK frame";
    }
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

    auto ping_probe = connection.select_pto_probe(packet_space);

    if (ping_probe.packet_number != 2u) {
        ADD_FAILURE() << "PTO probe did not skip non-probeable packets";
    }
    if (!ping_probe.has_ping) {
        //= https://www.rfc-editor.org/rfc/rfc9002#section-6.2.4
        // # When there is no data to send, the sender SHOULD send
        // # a PING or other ack-eliciting frame in a single packet, rearming the
        // # PTO timer.
        ADD_FAILURE() << "selected PTO probe did not retain PING";
    }
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

    auto loss_deadline = connection.loss_deadline();
    auto pto_deadline = connection.pto_deadline();

    if (!loss_deadline.has_value() || !pto_deadline.has_value()) {
        GTEST_FAIL() << "expected loss and PTO deadlines";
        return;
    }
    if (*loss_deadline >= *pto_deadline) {
        ADD_FAILURE() << "loss deadline was not earlier than PTO deadline";
    }
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

    auto payload = std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53});
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

    auto &peer_transport_parameters =
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
    auto next_wakeup = connection.next_wakeup();
    if (!next_wakeup.has_value()) {
        ADD_FAILURE() << "connection did not arm a PTO wakeup after handshake confirmation";
        return;
    }
    auto deadline = optional_value_or_terminate(next_wakeup);

    connection.on_timeout(deadline);
    auto probe_datagram = connection.drain_outbound_datagram(deadline);
    if (probe_datagram.empty()) {
        ADD_FAILURE() << "missing post-confirmation PTO probe datagram";
        return;
    }

    auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    if (probe_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected post-confirmation PTO packet count";
        return;
    }
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&probe_packets[0]);
    if (application == nullptr) {
        ADD_FAILURE() << "post-confirmation PTO packet was not 1-RTT";
        return;
    }

    std::vector<coquic::quic::StreamFrame> stream_frames;
    for (auto &frame : application->frames) {
        if (auto *stream_frame = std::get_if<coquic::quic::StreamFrame>(&frame)) {
            stream_frames.push_back(*stream_frame);
        }
    }

    if (stream_frames.size() != 1u) {
        ADD_FAILURE() << "post-confirmation PTO probe did not carry one stream frame";
        return;
    }
    if (!stream_frames.front().offset.has_value()) {
        ADD_FAILURE() << "post-confirmation PTO stream frame did not carry an offset";
        return;
    }
    if (optional_value_or_terminate(stream_frames.front().offset) != 767u) {
        ADD_FAILURE() << "post-confirmation PTO retransmitted the wrong fragment";
    }
    if (stream_frames.front().stream_data.size() != static_cast<std::size_t>(257)) {
        ADD_FAILURE() << "post-confirmation PTO stream data length changed";
    }
    if (!stream_frames.front().fin) {
        ADD_FAILURE() << "post-confirmation PTO lost FIN";
    }
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

    auto capped_deadline = std::optional{coquic::quic::compute_pto_deadline(
        connection.recovery_rtt_state_, std::chrono::milliseconds(0),
        coquic::quic::test::test_time(0), 2)};
    auto uncapped_deadline = std::optional{coquic::quic::compute_pto_deadline(
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

    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # To
    // # prevent this deadlock, clients MUST send a packet on a Probe Timeout
    // # (PTO); see Section 6.2 of [QUIC-RECOVERY].
    connection.on_timeout(coquic::quic::test::test_time(4000));

    EXPECT_EQ(connection.pto_count_, 5u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # Specifically, the client
    // # MUST send an Initial packet in a UDP datagram that contains at least
    // # 1200 bytes if it does not have Handshake keys, and otherwise send a
    // # Handshake packet.
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4000));
    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);

    auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(4100), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.pto_count_, 5u);
    auto next_deadline = connection.pto_deadline();
    if (!next_deadline.has_value() ||
        next_deadline.value() <= coquic::quic::test::test_time(5000)) {
        ADD_FAILURE() << "keepalive ACK did not preserve the backed off PTO deadline";
    }
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4000));
    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);

    auto late_handle =
        optional_value_or_terminate(connection.initial_space_.recovery.handle_for_packet_number(0));
    if (!connection.mark_lost_packet(connection.initial_space_, late_handle).has_value()) {
        ADD_FAILURE() << "failed to mark keepalive packet lost";
        return;
    }

    auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(4100), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    if (!processed.has_value()) {
        ADD_FAILURE() << "late keepalive ACK was rejected";
        return;
    }
    EXPECT_EQ(connection.pto_count_, 5u);
    auto next_deadline = connection.pto_deadline();
    if (!next_deadline.has_value() ||
        next_deadline.value() <= coquic::quic::test::test_time(5000)) {
        ADD_FAILURE() << "late keepalive ACK did not preserve the backed off PTO deadline";
    }
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

    auto late_handle =
        optional_value_or_terminate(connection.initial_space_.recovery.handle_for_packet_number(0));
    if (!connection.mark_lost_packet(connection.initial_space_, late_handle).has_value()) {
        ADD_FAILURE() << "failed to mark retransmittable packet lost";
        return;
    }

    auto processed = connection.process_inbound_ack(
        connection.initial_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 0,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(4100), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    if (!processed.has_value()) {
        ADD_FAILURE() << "late retransmittable ACK was rejected";
        return;
    }
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(4000));
    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    ASSERT_EQ(connection.last_client_handshake_keepalive_probe_time_,
              std::optional{coquic::quic::test::test_time(4000)});
    ASSERT_EQ(connection.pto_count_, 5u);

    auto processed = connection.process_inbound_packet(
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
    auto next_deadline = connection.pto_deadline();
    if (!next_deadline.has_value() ||
        next_deadline.value() <= coquic::quic::test::test_time(5000)) {
        ADD_FAILURE() << "ACK-only Initial packet did not preserve the backed off PTO deadline";
    }
}

TEST(QuicCoreTest, ClientHandshakeKeepaliveUsesMostRecentProbeTimeAsReference) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(10);
    connection.pto_count_ = 4;

    auto expected = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
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

    auto deadline = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
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

    auto first_ack_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(5));
    ASSERT_FALSE(first_ack_datagram.empty());
    ASSERT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());

    auto deadline = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
                                                       std::chrono::milliseconds(0),
                                                       coquic::quic::test::test_time(4), 2);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # To
    // # prevent this deadlock, clients MUST send a packet on a Probe Timeout
    // # (PTO); see Section 6.2 of [QUIC-RECOVERY].
    connection.arm_pto_probe(deadline);

    ASSERT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(
        optional_ref_or_terminate(connection.handshake_space_.pending_probe_packet).has_ping);

    auto probe_datagram = connection.drain_outbound_datagram(deadline);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # To
    // # prevent this deadlock, clients MUST send a packet on a Probe Timeout
    // # (PTO); see Section 6.2 of [QUIC-RECOVERY].
    if (probe_datagram.empty()) {
        ADD_FAILURE() << "missing keepalive Handshake PTO probe datagram";
        return;
    }

    auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    if (probe_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected keepalive Handshake PTO packet count";
        return;
    }
    auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&probe_packets[0]);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # Specifically, the client
    // # MUST send an Initial packet in a UDP datagram that contains at least
    // # 1200 bytes if it does not have Handshake keys, and otherwise send a
    // # Handshake packet.
    if (handshake == nullptr) {
        ADD_FAILURE() << "keepalive PTO probe was not a Handshake packet";
        return;
    }

    bool saw_ack = false;
    bool saw_ping = false;
    for (auto &frame : handshake->frames) {
        if (auto *ack = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = saw_ack || ack_frame_acks_packet_number_for_tests(*ack, 7);
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    if (!saw_ack) {
        ADD_FAILURE() << "keepalive Handshake PTO probe did not repeat the ACK";
    }
    if (!saw_ping) {
        ADD_FAILURE() << "keepalive Handshake PTO probe did not include PING";
    }
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

    auto first_ack_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(5));
    ASSERT_FALSE(first_ack_datagram.empty());
    ASSERT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());

    auto deadline = coquic::quic::compute_pto_deadline(connection.shared_recovery_rtt_state(),
                                                       std::chrono::milliseconds(0),
                                                       coquic::quic::test::test_time(4), 2);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # To
    // # prevent this deadlock, clients MUST send a packet on a Probe Timeout
    // # (PTO); see Section 6.2 of [QUIC-RECOVERY].
    connection.arm_pto_probe(deadline);

    ASSERT_TRUE(connection.initial_space_.pending_probe_packet.has_value());
    EXPECT_TRUE(optional_ref_or_terminate(connection.initial_space_.pending_probe_packet).has_ping);

    auto probe_datagram = connection.drain_outbound_datagram(deadline);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # To
    // # prevent this deadlock, clients MUST send a packet on a Probe Timeout
    // # (PTO); see Section 6.2 of [QUIC-RECOVERY].
    if (probe_datagram.empty()) {
        ADD_FAILURE() << "missing keepalive Initial PTO probe datagram";
        return;
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # Specifically, the client
    // # MUST send an Initial packet in a UDP datagram that contains at least
    // # 1200 bytes if it does not have Handshake keys, and otherwise send a
    // # Handshake packet.
    EXPECT_GE(probe_datagram.size(), 1200u);

    auto probe_packets = decode_sender_datagram(connection, probe_datagram);
    if (probe_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected keepalive Initial PTO packet count";
        return;
    }
    auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&probe_packets[0]);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
    // # Specifically, the client
    // # MUST send an Initial packet in a UDP datagram that contains at least
    // # 1200 bytes if it does not have Handshake keys, and otherwise send a
    // # Handshake packet.
    if (initial == nullptr) {
        ADD_FAILURE() << "keepalive PTO probe was not an Initial packet";
        return;
    }

    bool saw_ack = false;
    bool saw_ping = false;
    for (auto &frame : initial->frames) {
        if (auto *ack = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = saw_ack || ack_frame_acks_packet_number_for_tests(*ack, 7);
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    if (!saw_ack) {
        ADD_FAILURE() << "keepalive Initial PTO probe did not repeat the ACK";
    }
    if (!saw_ping) {
        ADD_FAILURE() << "keepalive Initial PTO probe did not include PING";
    }
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front());
    ASSERT_NE(initial, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (auto &frame : initial->frames) {
        if (auto *ack_frame = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = saw_ack || ack_frame_acks_packet_number_for_tests(*ack_frame, 7);
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_ping);
    auto tracked_after_first_initial_send = tracked_packet_count(connection.initial_space_);
    if (tracked_after_first_initial_send == 0u) {
        ADD_FAILURE() << "first Initial ACK-only send was not tracked";
        return;
    }
    if (!last_tracked_packet(connection.initial_space_).has_ping) {
        ADD_FAILURE() << "first Initial ACK-only send did not add PING";
    }

    connection.initial_space_.received_packets.record_received(
        /*packet_number=*/9, /*ack_eliciting=*/true, coquic::quic::test::test_time(2));
    auto second_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    if (second_datagram.empty()) {
        ADD_FAILURE() << "missing second Initial ACK-only datagram";
        return;
    }
    auto second_packets = decode_sender_datagram(connection, second_datagram);
    if (second_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected second Initial ACK-only packet count";
        return;
    }
    auto *second_initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&second_packets.front());
    if (second_initial == nullptr) {
        ADD_FAILURE() << "second ACK-only datagram was not an Initial packet";
        return;
    }

    bool saw_second_ack = false;
    bool saw_second_ping = false;
    for (auto &frame : second_initial->frames) {
        if (auto *ack_frame = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_second_ack =
                saw_second_ack || ack_frame_acks_packet_number_for_tests(*ack_frame, 9);
        }
        saw_second_ping = saw_second_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    if (!saw_second_ack) {
        ADD_FAILURE() << "second Initial ACK-only send did not ACK packet 9";
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
    // # In that case, an endpoint MUST NOT send an ack-eliciting frame in all
    // # packets that would otherwise be non-ack-eliciting, to avoid an infinite
    // # feedback loop of acknowledgments.
    if (saw_second_ping) {
        ADD_FAILURE() << "second Initial ACK-only send added an extra PING";
    }
    if (last_tracked_packet(connection.initial_space_).has_ping) {
        ADD_FAILURE() << "second Initial ACK-only send tracked an extra PING";
    }
    if (last_tracked_packet(connection.initial_space_).ack_eliciting) {
        ADD_FAILURE() << "second Initial ACK-only send was tracked as ack-eliciting";
    }
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front());
    ASSERT_NE(handshake, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (auto &frame : handshake->frames) {
        if (auto *ack_frame = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = saw_ack || ack_frame_acks_packet_number_for_tests(*ack_frame, 11);
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_ping);
    auto tracked_after_first_handshake_send = tracked_packet_count(connection.handshake_space_);
    if (tracked_after_first_handshake_send == 0u) {
        ADD_FAILURE() << "first Handshake ACK-only send was not tracked";
        return;
    }
    if (!last_tracked_packet(connection.handshake_space_).has_ping) {
        ADD_FAILURE() << "first Handshake ACK-only send did not add PING";
    }

    connection.handshake_space_.received_packets.record_received(
        /*packet_number=*/13, /*ack_eliciting=*/true, coquic::quic::test::test_time(2));
    auto second_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    if (second_datagram.empty()) {
        ADD_FAILURE() << "missing second Handshake ACK-only datagram";
        return;
    }
    auto second_packets = decode_sender_datagram(connection, second_datagram);
    if (second_packets.size() != 1u) {
        ADD_FAILURE() << "unexpected second Handshake ACK-only packet count";
        return;
    }
    auto *second_handshake =
        std::get_if<coquic::quic::ProtectedHandshakePacket>(&second_packets.front());
    if (second_handshake == nullptr) {
        ADD_FAILURE() << "second ACK-only datagram was not a Handshake packet";
        return;
    }

    bool saw_second_ack = false;
    bool saw_second_ping = false;
    for (auto &frame : second_handshake->frames) {
        if (auto *ack_frame = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_second_ack =
                saw_second_ack || ack_frame_acks_packet_number_for_tests(*ack_frame, 13);
        }
        saw_second_ping = saw_second_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    if (!saw_second_ack) {
        ADD_FAILURE() << "second Handshake ACK-only send did not ACK packet 13";
    }
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
    // # In that case, an endpoint MUST NOT send an ack-eliciting frame in all
    // # packets that would otherwise be non-ack-eliciting, to avoid an infinite
    // # feedback loop of acknowledgments.
    if (saw_second_ping) {
        ADD_FAILURE() << "second Handshake ACK-only send added an extra PING";
    }
    if (last_tracked_packet(connection.handshake_space_).has_ping) {
        ADD_FAILURE() << "second Handshake ACK-only send tracked an extra PING";
    }
    if (last_tracked_packet(connection.handshake_space_).ack_eliciting) {
        ADD_FAILURE() << "second Handshake ACK-only send was tracked as ack-eliciting";
    }
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

    auto now = coquic::quic::test::test_time(5);
    auto datagram = connection.drain_outbound_datagram(now);

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto processed = connection.process_inbound_packet(
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

    auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .destination_connection_id = {},
            .source_connection_id = {std::byte{0x02}},
            .packet_number = 1,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
    // # An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
    // # packets immediately and all ack-eliciting 0-RTT and 1-RTT packets
    // # within its advertised max_ack_delay, with the following exception.
    ASSERT_EQ(connection.handshake_space_.pending_ack_deadline,
              std::optional{coquic::quic::test::test_time(1)});

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    if (datagram.empty()) {
        ADD_FAILURE() << "missing standalone Handshake ACK datagram";
        return;
    }
    auto packets = decode_sender_datagram(connection, datagram);
    if (packets.size() != 1u) {
        ADD_FAILURE() << "unexpected standalone Handshake ACK packet count";
        return;
    }
    auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets[0]);
    if (handshake == nullptr) {
        ADD_FAILURE() << "standalone ACK datagram was not a Handshake packet";
        return;
    }

    auto ack_it = std::find_if(handshake->frames.begin(), handshake->frames.end(), [](auto &frame) {
        return std::holds_alternative<coquic::quic::AckFrame>(frame);
    });
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
    // # An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
    // # packets immediately and all ack-eliciting 0-RTT and 1-RTT packets
    // # within its advertised max_ack_delay, with the following exception.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.6
    // # ACK frames MUST only be carried in a packet that has the same packet
    // # number space as the packet being acknowledged; see Section 12.1.
    if (ack_it == handshake->frames.end()) {
        ADD_FAILURE() << "standalone Handshake ACK packet did not carry an ACK frame";
    }
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

    auto processed = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = 7,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(2), /*ack_delay_exponent=*/0, /*max_ack_delay_ms=*/0,
        /*suppress_pto_reset=*/false);

    if (!processed.has_value()) {
        ADD_FAILURE() << "application ACK for ping-only packet was rejected";
        return;
    }
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

    auto processed = connection.process_inbound_ack(
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

    auto send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ack-me"),
        },
        coquic::quic::test::test_time(1));
    auto received = coquic::quic::test::relay_send_datagrams_to_peer(
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
    for (auto &response_datagram : response_datagrams) {
        auto decoded = coquic::quic::deserialize_protected_datagram(
            response_datagram,
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

        for (auto &packet : decoded.value()) {
            auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            if (one_rtt == nullptr) {
                continue;
            }

            for (auto &frame : one_rtt->frames) {
                if (std::holds_alternative<coquic::quic::AckFrame>(frame)) {
                    saw_ack = true;
                }
            }
        }
    }

    if (!saw_ack) {
        ADD_FAILURE() << "server response did not include an ACK frame";
    }
}

TEST(QuicCoreTest, ReorderedApplicationPacketsAreDeliveredOnceContiguous) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto first_send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));
    auto second_send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("pong"),
        },
        coquic::quic::test::test_time(2));

    auto datagrams = coquic::quic::test::send_datagrams_from(first_send);
    auto second_datagrams = coquic::quic::test::send_datagrams_from(second_send);
    datagrams.insert(datagrams.end(), second_datagrams.begin(), second_datagrams.end());
    ASSERT_EQ(datagrams.size(), 2u);

    auto reordered = coquic::quic::test::relay_datagrams_to_peer(
        datagrams, std::array<std::size_t, 1>{1}, server, coquic::quic::test::test_time(3));
    if (server.has_failed()) {
        ADD_FAILURE() << "server failed after reordered packet";
    }
    if (!coquic::quic::test::received_application_data_from(reordered).empty()) {
        ADD_FAILURE() << "server delivered application data before stream data was contiguous";
    }

    auto contiguous = coquic::quic::test::relay_datagrams_to_peer(
        datagrams, std::array<std::size_t, 1>{0}, server, coquic::quic::test::test_time(4));
    if (server.has_failed()) {
        ADD_FAILURE() << "server failed after contiguous packet";
    }
    if (coquic::quic::test::string_from_bytes(
            coquic::quic::test::received_application_data_from(contiguous)) != "pingpong") {
        ADD_FAILURE() << "server did not deliver reordered stream data once contiguous";
    }
}

TEST(QuicCoreTest, InboundApplicationAckRetiresOwnedSendRanges) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    auto send = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("retire-me"),
        },
        coquic::quic::test::test_time(1));

    ASSERT_NE(tracked_packet_count(client.connection_->application_space_), 0u);
    ASSERT_TRUE(client.connection_->streams_.contains(0));
    EXPECT_TRUE(client.connection_->streams_.at(0).has_outstanding_send());

    auto server_step = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(2));
    ASSERT_TRUE(server_step.next_wakeup.has_value());

    auto ack_deadline = optional_value_or_terminate(server_step.next_wakeup);
    auto server_ack = server.advance(coquic::quic::QuicCoreTimerExpired{}, ack_deadline);
    if (coquic::quic::test::send_datagrams_from(server_ack).empty()) {
        ADD_FAILURE() << "server did not emit an ACK datagram";
        return;
    }

    auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
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

    auto server_send = server.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("ack-me"),
        },
        coquic::quic::test::test_time(1));

    auto client_step = coquic::quic::test::relay_send_datagrams_to_peer(
        server_send, client, coquic::quic::test::test_time(2));

    EXPECT_FALSE(client.has_failed());
    EXPECT_EQ(coquic::quic::test::string_from_bytes(
                  coquic::quic::test::received_application_data_from(client_step)),
              "ack-me");

    auto ack_step = client_step;
    if (coquic::quic::test::send_datagrams_from(ack_step).empty()) {
        auto ack_deadline = client.connection_->next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        ack_step = client.advance(coquic::quic::QuicCoreTimerExpired{},
                                  optional_value_or_terminate(ack_deadline));
    }
    auto ack_datagrams = coquic::quic::test::send_datagrams_from(ack_step);
    EXPECT_FALSE(ack_datagrams.empty());
    EXPECT_TRUE(std::any_of(ack_datagrams.begin(), ack_datagrams.end(), [&](auto &ack_datagram) {
        return datagram_has_application_ack(*client.connection_, ack_datagram);
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

    auto datagram =
        client.connection_->drain_outbound_datagram(coquic::quic::test::test_time(5000));

    EXPECT_FALSE(client.connection_->has_failed());
    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);

    auto decoded = coquic::quic::deserialize_protected_datagram(
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
    for (auto &packet : decoded.value()) {
        auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (one_rtt == nullptr) {
            continue;
        }

        for (auto &frame : one_rtt->frames) {
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);

    bool saw_crypto = false;
    for (auto &frame : initial->frames) {
        auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame);
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    auto &sent_packet = first_tracked_packet(connection.initial_space_);
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets[0]);
    ASSERT_NE(handshake, nullptr);
    ASSERT_EQ(handshake->frames.size(), 1u);
    auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&handshake->frames[0]);
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets[0]);
    ASSERT_NE(handshake, nullptr);

    std::vector<const coquic::quic::CryptoFrame *> crypto_frames;
    for (auto &frame : handshake->frames) {
        if (auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame)) {
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
    auto &sent_packet = first_tracked_packet(connection.handshake_space_);
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_ping = false;
    for (auto &frame : application->frames) {
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_crypto = false;
    bool saw_ping = false;
    for (auto &frame : application->frames) {
        if (auto *crypto = std::get_if<coquic::quic::CryptoFrame>(&frame)) {
            saw_crypto = true;
            EXPECT_EQ(crypto->offset, 0u);
            EXPECT_EQ(crypto->crypto_data, coquic::quic::test::bytes_from_string("app"));
        }
        saw_ping = saw_ping || std::holds_alternative<coquic::quic::PingFrame>(frame);
    }

    EXPECT_TRUE(saw_crypto);
    EXPECT_TRUE(saw_ping);
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);
    auto &sent_packet = first_tracked_packet(connection.application_space_);
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
    auto &range = lost_crypto.front();
    connection.application_space_.send_crypto.mark_lost(range.offset, range.bytes.size());
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 79,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges = lost_crypto,
    };
    connection.remaining_pto_probe_datagrams_ = 2;

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(5000));

    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());

    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    auto *stream = std::get_if<coquic::quic::StreamFrame>(&application->frames.back());
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.pending_probe_packet.has_value());

    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (auto &frame : application->frames) {
        auto *stream = std::get_if<coquic::quic::StreamFrame>(&frame);
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationProbePathDropsBaseAckWhenNoAckFallbackFits) {
    auto payload_size = find_application_probe_payload_size_that_drops_ack();
    ASSERT_TRUE(payload_size.has_value());
    auto payload_size_value = optional_value_or_terminate(payload_size);

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(datagram_has_application_ack(connection, datagram));
    EXPECT_TRUE(datagram_has_application_stream(connection, datagram));
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ApplicationProbePathFailsWhenNoAckFallbackSerializationFails) {
    auto payload_size = find_application_probe_payload_size_that_drops_ack();
    ASSERT_TRUE(payload_size.has_value());
    auto payload_size_value = optional_value_or_terminate(payload_size);

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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
    auto payload = coquic::quic::test::bytes_from_string("probe-fragment");
    stream.send_buffer.append(payload);
    auto initial_fragments = stream.take_send_fragments(payload.size());
    ASSERT_EQ(initial_fragments.size(), 1u);
    stream.mark_send_fragment_lost(initial_fragments.front());
    ASSERT_TRUE(stream.send_buffer.has_lost_data());
    connection.application_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 28,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_fragments = initial_fragments,
    };

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ApplicationSendPathSizesFinOnlyStreamsWithoutTrimReserialization) {
    auto connection = make_connected_client_connection();
    connection.stream_open_limits_.peer_max_bidirectional = 2048;
    for (std::uint64_t stream_index = 0; stream_index < 2048; ++stream_index) {
        ASSERT_TRUE(connection.queue_stream_send(stream_index * 4, {}, true).has_value());
    }

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
    EXPECT_LE(datagram.size(), 1200u);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());
}

TEST(QuicCoreTest, ApplicationSendFailsWhenControlFramesAloneExceedDatagramBudget) {
    auto connection = make_connected_client_connection();
    for (std::uint64_t stream_index = 0; stream_index < 256; ++stream_index) {
        auto stream_id = stream_index * 4;
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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
    auto bytes_in_flight_before = connection.congestion_controller_.bytes_in_flight();
    auto tracked_packets_before = tracked_packet_count(connection.application_space_);

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());

    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);
    ASSERT_EQ(application->frames.size(), 1u);
    auto *ack = std::get_if<coquic::quic::AckFrame>(&application->frames.front());
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-12.2
    // # An endpoint SHOULD include multiple frames in a single packet if
    // # they are to be sent at the same encryption level, instead of
    // # coalescing multiple packets at the same encryption level.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1
    // # An endpoint SHOULD send an ACK frame with other frames when there are
    // # new ack-eliciting packets to acknowledge.
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

        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
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
        auto stream_id = stream_index * 4;
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 0u);
}

TEST(QuicCoreTest, ApplicationSendWithLargeAckStateDoesNotFailPacketBudgetSearch) {
    auto connection = make_connected_server_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(4000), std::byte{0x46});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    for (std::uint64_t packet_number = 0; packet_number < 1200; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets[0]);
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (auto &frame : application->frames) {
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
        auto stream_id = stream_index * 4;
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());

    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front()), nullptr);
}

TEST(QuicCoreTest, FinalizeExistingHandshakeDatagramFailsWhenSerializationFails) {
    auto configure_connection = [](coquic::quic::QuicConnection &connection) {
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
    auto control_datagram = control.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(control_datagram.empty());
    EXPECT_FALSE(control.has_failed());
    auto control_packets = decode_sender_datagram(control, control_datagram);
    ASSERT_EQ(control_packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&control_packets.front()),
              nullptr);

    auto failure = make_connected_server_connection();
    configure_connection(failure);
    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    auto datagram = failure.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
}

TEST(QuicCoreTest, RetransmittedServerResponseStillCarriesAckForRepeatedRequestPacket) {
    auto connection = make_connected_server_connection();

    auto process_request = [&](std::uint64_t packet_number, coquic::quic::QuicCoreTimePoint now) {
        auto processed = connection.process_inbound_packet(
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

    auto first_response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_response.empty());
    ASSERT_NE(tracked_packet_count(connection.application_space_), 0u);

    auto first_packet_number = last_tracked_packet(connection.application_space_).packet_number;
    auto first_packet =
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

    auto retransmitted = connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
    ASSERT_FALSE(retransmitted.empty());

    auto packets = decode_sender_datagram(connection, retransmitted);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.2
    // # When sending a packet for any reason, an endpoint SHOULD attempt to
    // # include an ACK frame if one has not been sent recently.
    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, CongestionBlockedApplicationSendStillEmitsAckOnlyDatagram) {
    auto connection = make_connected_server_connection();
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(2048), std::byte{0x52});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, false).has_value());

    connection.application_space_.received_packets.record_received(
        77, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    connection.congestion_controller_.on_packet_sent(
        connection.congestion_controller_.congestion_window(), /*ack_eliciting=*/true);
    ASSERT_EQ(connection.congestion_controller_.bytes_in_flight(),
              connection.congestion_controller_.congestion_window());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_stream = false;
    for (auto &frame : application->frames) {
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

    auto processed = connection.process_inbound_packet(
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
    auto payload = std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53});
    ASSERT_TRUE(connection.queue_stream_send(0, payload, true).has_value());

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    ASSERT_EQ(tracked_packet_count(connection.application_space_), 1u);

    auto first_packet_number = last_tracked_packet(connection.application_space_).packet_number;
    auto first_packet =
        tracked_packet_or_terminate(connection.application_space_, first_packet_number);
    EXPECT_FALSE(first_packet.crypto_ranges.empty());

    connection.mark_lost_packet(
        connection.application_space_,
        optional_value_or_terminate(connection.application_space_.recovery.handle_for_packet_number(
            first_packet.packet_number)));
    EXPECT_TRUE(connection.has_pending_application_send());

    auto second_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(second_datagram.empty());

    auto packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(packets.size(), 1u);
    auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_stream = false;
    for (auto &frame : application->frames) {
        saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
    }

    EXPECT_TRUE(saw_stream);
    EXPECT_FALSE(connection.has_failed());
}

} // namespace
