#include <gtest/gtest.h>
#include "tests/support/core/connection_handshake_test_support.h"

namespace {

TEST(QuicCoreTest, PublicConfigAcceptsOpaqueResumptionStateAndZeroRttConfig) {
    auto config = coquic::quic::test::make_client_core_config();
    config.resumption_state = coquic::quic::QuicResumptionState{
        .serialized = {std::byte{0x01}, std::byte{0x02}},
    };
    config.zero_rtt = coquic::quic::QuicZeroRttConfig{
        .attempt = true,
        .allow = false,
        .application_context = {std::byte{0xa0}},
    };

    ASSERT_TRUE(config.resumption_state.has_value());
    EXPECT_EQ(config.resumption_state.value().serialized.size(), 2u);
    EXPECT_TRUE(config.zero_rtt.attempt);
    EXPECT_FALSE(config.zero_rtt.allow);
    EXPECT_EQ(config.zero_rtt.application_context, std::vector{std::byte{0xa0}});
}

TEST(QuicCoreTest, TestUtilsExtractResumptionAndZeroRttEffects) {
    const auto result = coquic::quic::QuicCoreResult{
        .effects =
            {
                coquic::quic::QuicCoreResumptionStateAvailable{
                    .state =
                        coquic::quic::QuicResumptionState{
                            .serialized = {std::byte{0x05}},
                        },
                },
                coquic::quic::QuicCoreZeroRttStatusEvent{
                    .status = coquic::quic::QuicZeroRttStatus::rejected,
                },
            },
    };

    const auto states = coquic::quic::test::resumption_states_from(result);
    const auto statuses = coquic::quic::test::zero_rtt_statuses_from(result);

    ASSERT_EQ(states.size(), 1u);
    EXPECT_EQ(states[0].serialized, std::vector{std::byte{0x05}});
    EXPECT_EQ(statuses, std::vector{coquic::quic::QuicZeroRttStatus::rejected});
}

TEST(QuicCoreTest, CompletedHandshakeEmitsResumptionStateEffect) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto transcript = coquic::quic::test::drive_quic_handshake_with_results(
        client, server, coquic::quic::test::test_time());
    const auto state = coquic::quic::test::last_resumption_state_from(transcript.client_results);

    ASSERT_TRUE(state.has_value());
    if (!state.has_value()) {
        return;
    }
    const auto &resumption_state = *state;
    EXPECT_FALSE(resumption_state.serialized.empty());
}

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

    auto decoded = coquic::quic::deserialize_protected_datagram(
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

TEST(QuicCoreTest, ClientHandshakeReadyEmitsBeforeHandshakeConfirmation) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    auto &connection = *client.connection_;
    ASSERT_TRUE(connection.tls_.has_value());
    if (!connection.tls_.has_value()) {
        return;
    }

    ASSERT_TRUE(connection.tls_->handshake_complete());
    ASSERT_TRUE(connection.peer_transport_parameters_validated_);
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_TRUE(connection.application_space_.write_secret.has_value());

    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.handshake_ready_emitted_ = false;
    connection.pending_state_changes_.clear();

    connection.update_handshake_status();

    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
    ASSERT_EQ(connection.pending_state_changes_.size(), 1u);
    EXPECT_EQ(connection.pending_state_changes_.front(),
              coquic::quic::QuicCoreStateChange::handshake_ready);

    connection.pending_state_changes_.clear();
    connection.confirm_handshake();

    EXPECT_TRUE(connection.pending_state_changes_.empty());
}

TEST(QuicCoreTest, HandshakeExportsConfiguredTransportParametersToPeer) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.transport.max_idle_timeout = 90000;
    client_config.transport.initial_max_data = 7777;
    client_config.transport.initial_max_stream_data_bidi_local = 1234;
    client_config.transport.initial_max_stream_data_bidi_remote = 2345;
    client_config.transport.initial_max_stream_data_uni = 3456;
    client_config.transport.initial_max_streams_bidi = 11;
    client_config.transport.initial_max_streams_uni = 13;

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    const auto &peer_transport_parameters = server.connection_->peer_transport_parameters_;
    ASSERT_TRUE(peer_transport_parameters.has_value());
    if (!peer_transport_parameters.has_value()) {
        return;
    }
    EXPECT_EQ(peer_transport_parameters.value().max_idle_timeout, 90000u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_data, 7777u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_stream_data_bidi_local, 1234u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_stream_data_bidi_remote, 2345u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_stream_data_uni, 3456u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_streams_bidi, 11u);
    EXPECT_EQ(peer_transport_parameters.value().initial_max_streams_uni, 13u);
}

TEST(QuicCoreTest, GreaseQuicBitTransportParameterNegotiatesAndControlsOutgoingQuicBit) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.transport.grease_quic_bit = true;
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.transport.grease_quic_bit = true;

    coquic::quic::QuicCore client(std::move(client_config));
    coquic::quic::QuicCore server(std::move(server_config));
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    ASSERT_TRUE(client.connection_ != nullptr);
    ASSERT_TRUE(server.connection_ != nullptr);
    ASSERT_TRUE(client.connection_->peer_transport_parameters_.has_value());
    ASSERT_TRUE(server.connection_->peer_transport_parameters_.has_value());
    const auto &client_peer_transport_parameters =
        optional_ref_or_terminate(client.connection_->peer_transport_parameters_);
    const auto &server_peer_transport_parameters =
        optional_ref_or_terminate(server.connection_->peer_transport_parameters_);
    EXPECT_TRUE(client.connection_->local_transport_parameters_.grease_quic_bit);
    EXPECT_TRUE(server.connection_->local_transport_parameters_.grease_quic_bit);
    EXPECT_TRUE(client_peer_transport_parameters.grease_quic_bit);
    EXPECT_TRUE(server_peer_transport_parameters.grease_quic_bit);

    auto serialize_context = coquic::quic::SerializeProtectionContext{
        .local_role = client.connection_->config_.role,
        .client_initial_destination_connection_id =
            client.connection_->client_initial_destination_connection_id(),
        .one_rtt_secret = client.connection_->application_space_.write_secret,
        .one_rtt_key_phase = client.connection_->application_write_key_phase_,
        .grease_quic_bit = true,
    };
    auto datagram = coquic::quic::serialize_protected_datagram(
        std::vector<coquic::quic::ProtectedPacket>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = server.connection_->config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 2,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        serialize_context);
    ASSERT_TRUE(datagram.has_value());
    EXPECT_EQ(std::to_integer<std::uint8_t>(datagram.value().front()) & 0x40u, 0u);

    auto strict_context = coquic::quic::DeserializeProtectionContext{
        .peer_role = coquic::quic::EndpointRole::client,
        .one_rtt_secret = server.connection_->application_space_.read_secret,
        .largest_authenticated_application_packet_number = 1,
        .one_rtt_destination_connection_id_length =
            server.connection_->config_.source_connection_id.size(),
    };
    auto strict_decoded =
        coquic::quic::deserialize_protected_datagram(datagram.value(), strict_context);
    ASSERT_FALSE(strict_decoded.has_value());
    EXPECT_EQ(strict_decoded.error().code, coquic::quic::CodecErrorCode::invalid_fixed_bit);

    strict_context.accept_greased_quic_bit = true;
    auto decoded = coquic::quic::deserialize_protected_datagram(datagram.value(), strict_context);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_NE(std::get_if<coquic::quic::ProtectedOneRttPacket>(&decoded.value().front()), nullptr);
}

TEST(QuicCoreTest, ServerAdvertisesInitialStatelessResetToken) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    ASSERT_TRUE(client.connection_ != nullptr);
    ASSERT_TRUE(server.connection_ != nullptr);
    const auto &peer_transport_parameters = client.connection_->peer_transport_parameters_;
    const auto &parameters = optional_ref_or_terminate(peer_transport_parameters);
    const auto stateless_reset_token =
        optional_value_or_terminate(parameters.stateless_reset_token);
    const auto local_tokens = server.connection_->active_local_stateless_reset_tokens();
    ASSERT_FALSE(local_tokens.empty());
    EXPECT_EQ(stateless_reset_token, local_tokens.front().stateless_reset_token);
}

TEST(QuicCoreTest, IdleTimeoutUsesEffectivePeerMinimumAndThreePtoFloor) {
    auto connection = make_connected_client_connection();
    connection.local_transport_parameters_.max_idle_timeout = 5000;
    optional_ref_or_terminate(connection.peer_transport_parameters_).max_idle_timeout = 200;
    connection.note_idle_peer_activity(coquic::quic::test::test_time(100));

    const auto deadline = connection.idle_timeout_deadline();
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
    // # To avoid excessively small idle timeout periods, endpoints MUST
    // # increase the idle timeout period to be at least three times the
    // # current Probe Timeout (PTO).
    EXPECT_EQ(optional_value_or_terminate(deadline), coquic::quic::test::test_time(3097));

    connection.on_timeout(coquic::quic::test::test_time(3096));
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.pending_terminal_state_.has_value());

    connection.on_timeout(coquic::quic::test::test_time(3097));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
    // # If a max_idle_timeout is specified by either endpoint in its
    // # transport parameters (Section 18.2), the connection is silently
    // # closed and its state is discarded when it remains idle for longer
    // # than the minimum of the max_idle_timeout value advertised by both
    // # endpoints.
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(optional_value_or_terminate(connection.pending_terminal_state_),
              coquic::quic::QuicConnectionTerminalState::closed);
    EXPECT_TRUE(connection.pending_state_changes_.empty());
}

TEST(QuicCoreTest, IdleTimeoutResetsOnPeerActivityAndFirstAckElicitingSend) {
    auto connection = make_connected_client_connection();
    connection.local_transport_parameters_.max_idle_timeout = 5000;
    optional_ref_or_terminate(connection.peer_transport_parameters_).max_idle_timeout = 7000;

    connection.note_idle_peer_activity(coquic::quic::test::test_time(10));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
    // # An endpoint restarts its idle timer when a packet from its peer is
    // # received and processed successfully.
    ASSERT_EQ(connection.idle_timeout_deadline(),
              std::optional{coquic::quic::test::test_time(5010)});

    connection.note_idle_ack_eliciting_send(coquic::quic::test::test_time(1000));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
    // # An endpoint also restarts its idle timer when sending an ack-eliciting
    // # packet if no other ack-eliciting packets have been sent since last
    // # receiving and processing a packet.
    EXPECT_EQ(connection.idle_timeout_deadline(),
              std::optional{coquic::quic::test::test_time(6000)});

    connection.note_idle_ack_eliciting_send(coquic::quic::test::test_time(2000));
    EXPECT_EQ(connection.idle_timeout_deadline(),
              std::optional{coquic::quic::test::test_time(6000)});

    connection.note_idle_peer_activity(coquic::quic::test::test_time(2500));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.1
    // # An endpoint restarts its idle timer when a packet from its peer is
    // # received and processed successfully.
    EXPECT_EQ(connection.idle_timeout_deadline(),
              std::optional{coquic::quic::test::test_time(7500)});
}

TEST(QuicCoreTest, MoveConstructionPreservesStartBehavior) {
    coquic::quic::QuicCore source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore moved(std::move(source));

    const auto result =
        moved.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());

    EXPECT_EQ(coquic::quic::test::send_datagrams_from(result).size(), 1u);
}

TEST(QuicCoreTest, MoveAssignmentPreservesStartBehavior) {
    coquic::quic::QuicCore source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore destination(coquic::quic::test::make_client_core_config());
    destination = std::move(source);

    const auto result =
        destination.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());

    EXPECT_EQ(coquic::quic::test::send_datagrams_from(result).size(), 1u);
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

TEST(QuicCoreTest, ServerEmitsHandshakeCryptoAfterOutOfOrderClientInitialRecovery) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
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
    std::size_t crypto_gap = 4u;
    std::size_t tail_offset = 1230u;
    if (client_hello.size() <= tail_offset) {
        prefix = std::min<std::size_t>(63u, client_hello.size() / 4u);
        crypto_gap = 1u;
        tail_offset = prefix + crypto_gap + ((client_hello.size() - (prefix + crypto_gap)) / 2u);
    }
    ASSERT_LT(prefix + crypto_gap, tail_offset);
    ASSERT_LT(tail_offset, client_hello.size());

    const auto slice_bytes = [&](std::size_t begin, std::size_t end) {
        return std::vector<std::byte>(client_hello.begin() + static_cast<std::ptrdiff_t>(begin),
                                      client_hello.begin() + static_cast<std::ptrdiff_t>(end));
    };

    coquic::quic::ProtectedInitialPacket first_initial{
        .version = client_initial->version,
        .destination_connection_id = client_initial->destination_connection_id,
        .source_connection_id = client_initial->source_connection_id,
        .token = client_initial->token,
        .packet_number_length = client_initial->packet_number_length,
        .packet_number = 0,
        .frames =
            {
                coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = slice_bytes(0u, prefix),
                },
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(prefix + crypto_gap),
                    .crypto_data = slice_bytes(prefix + crypto_gap, tail_offset),
                },
            },
    };
    coquic::quic::ProtectedInitialPacket second_initial{
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
                    .crypto_data = slice_bytes(prefix, prefix + crypto_gap),
                },
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(tail_offset),
                    .crypto_data = slice_bytes(tail_offset, client_hello.size()),
                },
            },
    };

    const auto pad_initial = [&](const coquic::quic::ProtectedInitialPacket &initial_packet) {
        auto packet = initial_packet;
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

    const auto second_initial_datagram = pad_initial(second_initial);
    auto server_after_second_initial =
        server.advance(coquic::quic::QuicCoreInboundDatagram{second_initial_datagram},
                       coquic::quic::test::test_time(1));
    EXPECT_FALSE(server.has_failed());

    const auto second_response_datagrams =
        coquic::quic::test::send_datagrams_from(server_after_second_initial);
    ASSERT_FALSE(second_response_datagrams.empty());
    for (const auto &datagram : second_response_datagrams) {
        auto packets = decode_sender_datagram(*server.connection_, datagram);
        for (const auto &packet : packets) {
            const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packet);
            if (initial == nullptr) {
                continue;
            }
            for (const auto &frame : initial->frames) {
                EXPECT_FALSE(std::holds_alternative<coquic::quic::CryptoFrame>(frame));
            }
        }
    }

    const auto first_initial_datagram = pad_initial(first_initial);
    auto server_after_first_initial =
        server.advance(coquic::quic::QuicCoreInboundDatagram{first_initial_datagram},
                       coquic::quic::test::test_time(2));
    EXPECT_FALSE(server.has_failed());

    const auto response_datagrams =
        coquic::quic::test::send_datagrams_from(server_after_first_initial);
    ASSERT_FALSE(response_datagrams.empty());

    bool saw_initial_crypto = false;
    bool saw_handshake_crypto = false;
    for (const auto &datagram : response_datagrams) {
        auto packets = decode_sender_datagram(*server.connection_, datagram);
        for (const auto &packet : packets) {
            if (const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packet)) {
                for (const auto &frame : initial->frames) {
                    if (std::holds_alternative<coquic::quic::CryptoFrame>(frame)) {
                        saw_initial_crypto = true;
                    }
                }
                continue;
            }

            const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packet);
            if (handshake == nullptr) {
                continue;
            }

            for (const auto &frame : handshake->frames) {
                if (std::holds_alternative<coquic::quic::CryptoFrame>(frame)) {
                    saw_handshake_crypto = true;
                }
            }
        }
    }

    EXPECT_TRUE(saw_initial_crypto);
    EXPECT_TRUE(saw_handshake_crypto);
}

TEST(QuicCoreTest, ApplicationDataIsRetransmittedAfterLoss) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_handshake_complete());
    ASSERT_TRUE(server.is_handshake_complete());

    const auto confirm = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
            .bytes = coquic::quic::test::bytes_from_string("confirm"),
        },
        coquic::quic::test::test_time(1));
    const auto confirm_delivered = coquic::quic::test::relay_send_datagrams_to_peer(
        confirm, server, coquic::quic::test::test_time(2));
    const auto confirm_acked = coquic::quic::test::relay_send_datagrams_to_peer(
        confirm_delivered, client, coquic::quic::test::test_time(3));
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(confirm_acked).empty());

    const auto sent = client.advance(
        coquic::quic::QuicCoreSendStreamData{
            .stream_id = 0,
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

TEST(QuicCoreTest, ServerHandshakeCompletionQueuesHandshakeDoneFrame) {
    auto connection = make_connected_server_connection();
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;

    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::pending);

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    bool saw_handshake_done = false;
    for (const auto &packet : decode_sender_datagram(connection, datagram)) {
        const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
        if (one_rtt == nullptr) {
            continue;
        }

        for (const auto &frame : one_rtt->frames) {
            if (std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame)) {
                saw_handshake_done = true;
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.20
    // # Servers MUST NOT send a HANDSHAKE_DONE frame before completing the
    // # handshake.
    EXPECT_TRUE(saw_handshake_done);
    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::sent);

    connection.arm_pto_probe(coquic::quic::test::test_time(1000));
    ASSERT_TRUE(connection.application_space_.pending_probe_packet.has_value());
    const auto &pending_probe_packet =
        optional_ref_or_terminate(connection.application_space_.pending_probe_packet);
    EXPECT_TRUE(pending_probe_packet.has_handshake_done);
}

TEST(QuicCoreTest, InboundHandshakeDoneQueuesApplicationAck) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;
    connection.application_space_.pending_ack_deadline = std::nullopt;

    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection, {coquic::quic::HandshakeDoneFrame{}}, /*packet_number=*/1));

    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_TRUE(connection.handshake_confirmed_);
}

TEST(QuicCoreTest, ApplicationLevelHandshakeDoneFrameConfirmsHandshakeInCryptoPath) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

    const auto processed = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::application,
        std::array<coquic::quic::Frame, 1>{coquic::quic::HandshakeDoneFrame{}},
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(processed.value());
    EXPECT_TRUE(connection.handshake_confirmed_);
}

TEST(QuicCoreTest, ClientHandshakePacketUpdatesCurrentVersionWhenPeerNegotiatesSupportedVersion) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.current_version_ = coquic::quic::kQuicVersion1;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion2,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x44, 0x55}),
            .packet_number_length = 1,
            .packet_number = 1,
            .frames =
                {
                    coquic::quic::CryptoFrame{
                        .offset = 0,
                        .crypto_data = {},
                    },
                },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.current_version_, coquic::quic::kQuicVersion2);
}

TEST(QuicCoreTest, InboundOneRttPacketAcceptsMixedCryptoAndPostHandshakeControlFrames) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.application_space_.pending_ack_deadline = std::nullopt;

    EXPECT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {
            coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = {},
            },
            coquic::quic::NewTokenFrame{
                .token = bytes_from_ints({0xaa, 0xbb, 0xcc}),
            },
            coquic::quic::NewConnectionIdFrame{
                .sequence_number = 1,
                .retire_prior_to = 0,
                .connection_id = bytes_from_ints({0x10, 0x11, 0x12, 0x13}),
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
            coquic::quic::HandshakeDoneFrame{},
        },
        /*packet_number=*/1));

    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.application_space_.pending_ack_deadline.has_value());
    EXPECT_TRUE(connection.handshake_confirmed_);
}

TEST(QuicCoreTest, HandshakePacketAcceptsTransportConnectionCloseFrame) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::connected;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0x44}},
            .packet_number_length = 2,
            .packet_number = 0,
            .frames =
                {
                    coquic::quic::TransportConnectionCloseFrame{
                        .error_code = 0,
                        .frame_type = 0,
                    },
                },
        },
        coquic::quic::test::test_time());

    EXPECT_TRUE(processed.has_value());
}

TEST(QuicCoreTest, OneRttPacketTerminatesOnConnectionCloseFrames) {
    auto connection = make_connected_client_connection();

    EXPECT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::TransportConnectionCloseFrame{
            .error_code = 0,
            .frame_type = 0,
        }},
        /*packet_number=*/1));
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.close_state_active());
    EXPECT_TRUE(connection.next_wakeup().has_value());

    connection = make_connected_client_connection();
    EXPECT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::ApplicationConnectionCloseFrame{
            .error_code = 0,
        }},
        /*packet_number=*/2));
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.close_state_active());
    EXPECT_TRUE(connection.next_wakeup().has_value());
}

TEST(QuicCoreTest, ClosingStateRateLimitsClosePacketRetransmission) {
    auto connection = make_connected_client_connection();
    connection.pending_transport_close_ = coquic::quic::TransportConnectionCloseFrame{
        .error_code =
            static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::protocol_violation),
        .frame_type = 0,
    };
    connection.pending_connection_close_terminal_state_ =
        coquic::quic::QuicConnectionTerminalState::failed;
    connection.enter_closing_state(coquic::quic::test::test_time(1),
                                   coquic::quic::QuicConnectionTerminalState::failed);
    connection.closing_close_packet_pending_ = true;

    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.1
    // # An endpoint SHOULD limit the rate at which it generates packets in
    // # the closing state.
    EXPECT_TRUE(connection.has_sendable_datagram(coquic::quic::test::test_time(1)));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_FALSE(connection.has_sendable_datagram(coquic::quic::test::test_time(2)));

    const auto inbound_datagram = bytes_from_ints({0x40, 0x01, 0x02, 0x03});
    connection.process_inbound_datagram(inbound_datagram, coquic::quic::test::test_time(3));
    EXPECT_FALSE(connection.has_sendable_datagram(coquic::quic::test::test_time(3)));

    connection.process_inbound_datagram(inbound_datagram, coquic::quic::test::test_time(4));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11.1
    // # An endpoint SHOULD be prepared to retransmit a packet containing a
    // # CONNECTION_CLOSE frame if it receives more packets on a terminated
    // # connection.
    EXPECT_TRUE(connection.has_sendable_datagram(coquic::quic::test::test_time(4)));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(4)).empty());

    for (std::int64_t index = 0; index < 3; ++index) {
        connection.process_inbound_datagram(inbound_datagram,
                                            coquic::quic::test::test_time(5 + index));
        EXPECT_FALSE(connection.has_sendable_datagram(coquic::quic::test::test_time(5 + index)));
    }

    connection.process_inbound_datagram(inbound_datagram, coquic::quic::test::test_time(8));
    EXPECT_TRUE(connection.has_sendable_datagram(coquic::quic::test::test_time(8)));
}

TEST(QuicCoreTest, ConnectionCloseFramesDoNotEmitInternalFailureDebugLog) {
    auto connection = make_connected_client_connection();

    testing::internal::CaptureStderr();
    EXPECT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::TransportConnectionCloseFrame{
            .error_code = 0,
            .frame_type = 0,
        }},
        /*packet_number=*/1));
    const auto transport_close_stderr = testing::internal::GetCapturedStderr();

    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(transport_close_stderr.empty());

    connection = make_connected_client_connection();

    testing::internal::CaptureStderr();
    EXPECT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::ApplicationConnectionCloseFrame{
            .error_code = 0,
        }},
        /*packet_number=*/2));
    auto application_close_stderr = testing::internal::GetCapturedStderr();

    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(application_close_stderr.empty());
}

TEST(QuicCoreTest, ClosingTransportErrorUsesOneRttProtectionAfterHandshakeConfirmed) {
    auto connection = make_connected_client_connection();

    connection.queue_transport_close_for_error(
        coquic::quic::test::test_time(1),
        coquic::quic::CodecError{.code = coquic::quic::CodecErrorCode::invalid_varint,
                                 .offset = 0});

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
    // # After the handshake is confirmed (see Section 4.1.2 of [QUIC-TLS]), an
    // # endpoint MUST send any CONNECTION_CLOSE frames in a 1-RTT packet.
    const auto *one_rtt = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(one_rtt, nullptr);
    ASSERT_EQ(one_rtt->frames.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::TransportConnectionCloseFrame>(&one_rtt->frames.front()),
              nullptr);
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 1u);
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
}

TEST(QuicCoreTest, ClosingApplicationCloseConvertsToTransportCloseInHandshakePacket) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 77,
                        .reason_phrase = "private app reason",
                    })
                    .has_value());
    connection.mark_connection_close_frame_sent(
        coquic::quic::Frame{optional_value_or_terminate(connection.pending_application_close_)},
        coquic::quic::test::test_time(1));
    connection.closing_close_packet_pending_ = true;
    connection.application_space_.write_secret.reset();
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x46});

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front());
    ASSERT_NE(handshake, nullptr);
    ASSERT_EQ(handshake->frames.size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
    // # A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE
    // # of type 0x1c when sending the frame in Initial or Handshake packets.
    const auto *close =
        std::get_if<coquic::quic::TransportConnectionCloseFrame>(&handshake->frames.front());
    ASSERT_NE(close, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
    // # Endpoints MUST clear the value of the Reason Phrase field and SHOULD
    // # use the APPLICATION_ERROR code when converting to a CONNECTION_CLOSE of
    // # type 0x1c.
    EXPECT_EQ(close->error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::application_error));
    EXPECT_TRUE(close->reason.bytes.empty());
    EXPECT_TRUE(connection.closing_application_close_.has_value());
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 0u);
}

TEST(QuicCoreTest, ClosingApplicationCloseConvertsToTransportCloseInInitialPacket) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(connection
                    .queue_application_close({
                        .application_error_code = 78,
                        .reason_phrase = "private initial reason",
                    })
                    .has_value());
    connection.mark_connection_close_frame_sent(
        coquic::quic::Frame{optional_value_or_terminate(connection.pending_application_close_)},
        coquic::quic::test::test_time(1));
    connection.closing_close_packet_pending_ = true;
    connection.application_space_.write_secret.reset();
    connection.handshake_space_.write_secret.reset();

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front());
    ASSERT_NE(initial, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
    // # A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE
    // # of type 0x1c when sending the frame in Initial or Handshake packets.
    const auto close = std::find_if(
        initial->frames.begin(), initial->frames.end(), [](const coquic::quic::Frame &frame) {
            return std::holds_alternative<coquic::quic::TransportConnectionCloseFrame>(frame);
        });
    ASSERT_NE(close, initial->frames.end());
    const auto &close_frame = std::get<coquic::quic::TransportConnectionCloseFrame>(*close);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3
    // # Endpoints MUST clear the value of the Reason Phrase field and SHOULD
    // # use the APPLICATION_ERROR code when converting to a CONNECTION_CLOSE of
    // # type 0x1c.
    EXPECT_EQ(close_frame.error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::application_error));
    EXPECT_TRUE(close_frame.reason.bytes.empty());
    EXPECT_TRUE(connection.closing_application_close_.has_value());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 0u);
}

TEST(QuicCoreTest, ClosingAndDrainingStatesPersistForThreePtoIntervals) {
    constexpr auto kPtoInterval = std::chrono::milliseconds(14);
    constexpr auto kClosePeriod = kPtoInterval * 3;

    auto closing = make_connected_client_connection();
    closing.recovery_rtt_state_.latest_rtt = std::chrono::milliseconds(10);
    closing.recovery_rtt_state_.smoothed_rtt = std::chrono::milliseconds(10);
    closing.recovery_rtt_state_.rttvar = std::chrono::milliseconds(1);

    closing.enter_closing_state(coquic::quic::test::test_time(100),
                                coquic::quic::QuicConnectionTerminalState::failed);

    const auto closing_wakeup = closing.next_wakeup();
    ASSERT_TRUE(closing_wakeup.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
    // # These states SHOULD persist for at least three
    // # times the current PTO interval as defined in [QUIC-RECOVERY].
    EXPECT_EQ(coquic::quic::test_support::optional_ref_or_terminate(closing_wakeup),
              coquic::quic::test::test_time(100) + kClosePeriod);
    EXPECT_FALSE(closing.terminal_state_expired(coquic::quic::test::test_time(100) + kClosePeriod -
                                                std::chrono::microseconds(1)));
    EXPECT_TRUE(closing.terminal_state_expired(coquic::quic::test::test_time(100) + kClosePeriod));

    auto draining = make_connected_client_connection();
    draining.recovery_rtt_state_ = closing.recovery_rtt_state_;
    draining.enter_draining_state(coquic::quic::test::test_time(200));

    const auto draining_wakeup = draining.next_wakeup();
    ASSERT_TRUE(draining_wakeup.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.2
    // # These states SHOULD persist for at least three
    // # times the current PTO interval as defined in [QUIC-RECOVERY].
    EXPECT_EQ(coquic::quic::test_support::optional_ref_or_terminate(draining_wakeup),
              coquic::quic::test::test_time(200) + kClosePeriod);
    EXPECT_FALSE(draining.terminal_state_expired(coquic::quic::test::test_time(200) + kClosePeriod -
                                                 std::chrono::microseconds(1)));
    EXPECT_TRUE(draining.terminal_state_expired(coquic::quic::test::test_time(200) + kClosePeriod));
}

TEST(QuicCoreTest, ClientsDoNotQueueNewTokenFrames) {
    auto client = make_connected_client_connection();
    client.queue_new_token(bytes_from_ints({0xaa}));

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.7
    // # Clients MUST NOT send NEW_TOKEN frames.
    EXPECT_TRUE(client.pending_new_token_frames_.empty());

    auto server = make_connected_server_connection();
    server.queue_new_token(bytes_from_ints({0xbb}));

    ASSERT_EQ(server.pending_new_token_frames_.size(), 1u);
    EXPECT_EQ(server.pending_new_token_frames_.front().token, bytes_from_ints({0xbb}));
}

TEST(QuicCoreTest, HandshakeConfirmationSkipsDiscardedHandshakePacketSpaceWhenProbing) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 10,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 11,
                                     .sent_time = coquic::quic::test::test_time(-1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });
    connection.track_sent_packet(connection.application_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 20,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.confirm_handshake();
    connection.arm_pto_probe(coquic::quic::test::test_time(1000));

    EXPECT_EQ(connection.pto_count_, 1u);
    if (!connection.application_space_.pending_probe_packet.has_value()) {
        GTEST_FAIL() << "expected application PTO probe packet";
        return;
    }
    EXPECT_EQ(connection.application_space_.pending_probe_packet->packet_number, 20u);
    EXPECT_FALSE(connection.handshake_space_.pending_probe_packet.has_value());
}

TEST(QuicCoreTest, InitialPaddingSearchCoversZeroDeltaAndAlternatePaths) {
    constexpr std::size_t kMinimumInitialDatagramSizeForTest = 1200;
    auto serialize_initial_without_padding = [](const coquic::quic::QuicConnection &connection,
                                                const coquic::quic::ProtectedInitialPacket &packet)
        -> coquic::quic::CodecResult<std::vector<std::byte>> {
        return coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{packet},
            coquic::quic::SerializeProtectionContext{
                .local_role = connection.config_.role,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .handshake_secret = connection.handshake_space_.write_secret,
                .zero_rtt_secret = connection.zero_rtt_space_.write_secret,
                .one_rtt_secret = connection.application_space_.write_secret,
                .one_rtt_key_phase = connection.application_write_key_phase_,
            });
    };

    bool saw_zero_padding_candidate = false;
    bool saw_alternate_padding = false;

    for (std::size_t crypto_size = 1; crypto_size <= 4096; ++crypto_size) {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.initial_space_.send_crypto.append(
            std::vector<std::byte>(crypto_size, std::byte{0x41}));

        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (connection.has_failed() || datagram.empty()) {
            continue;
        }

        //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
        // # A client MUST expand the payload of all UDP datagrams carrying
        // # Initial packets to at least the smallest allowed maximum datagram
        // # size of 1200 bytes by adding PADDING frames to the Initial packet
        // # or by coalescing the Initial packet; see Section 12.2.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-8.1
        // # Clients MUST ensure that UDP datagrams containing Initial packets
        // # have UDP payloads of at least 1200 bytes, adding PADDING frames as
        // # necessary.
        EXPECT_GE(datagram.size(), kMinimumInitialDatagramSizeForTest);

        auto packets = decode_sender_datagram(connection, datagram);
        if (packets.size() != 1u) {
            continue;
        }

        const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front());
        if (initial == nullptr) {
            continue;
        }

        coquic::quic::ProtectedInitialPacket base_packet = *initial;
        std::optional<std::size_t> padding_length;
        std::vector<coquic::quic::Frame> frames_without_padding;
        frames_without_padding.reserve(base_packet.frames.size());
        for (const auto &frame : base_packet.frames) {
            if (const auto *padding = std::get_if<coquic::quic::PaddingFrame>(&frame)) {
                padding_length = padding->length;
                continue;
            }
            frames_without_padding.push_back(frame);
        }
        if (!padding_length.has_value()) {
            continue;
        }
        base_packet.frames = std::move(frames_without_padding);

        auto base_datagram = serialize_initial_without_padding(connection, base_packet);
        ASSERT_TRUE(base_datagram.has_value());
        if (!base_datagram.has_value()) {
            return;
        }
        if (base_datagram.value().size() >= kMinimumInitialDatagramSizeForTest) {
            continue;
        }

        const auto padding_deficit =
            kMinimumInitialDatagramSizeForTest - base_datagram.value().size();
        if (padding_deficit <= 8) {
            saw_zero_padding_candidate = true;
        }
        if (padding_length.value() != padding_deficit) {
            saw_alternate_padding = true;
        }

        if (saw_zero_padding_candidate && saw_alternate_padding) {
            break;
        }
    }

    EXPECT_TRUE(saw_zero_padding_candidate);
    EXPECT_TRUE(saw_alternate_padding);
}

TEST(QuicCoreTest, HandshakePacketSerializationFailureMarksConnectionFailed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 6,
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

TEST(QuicCoreTest, ClosingTransportErrorUsesHandshakeProtectionWithoutOneRttKeys) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ = {
        std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
        std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08},
    };
    connection.peer_source_connection_id_ = {std::byte{0xc1}, std::byte{0x44}};
    connection.current_send_path_id_ = 0;
    auto &path = connection.ensure_path_state(0);
    path.validated = true;
    path.anti_amplification_received_bytes = 1200;
    connection.peer_address_validated_ = true;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x45});
    connection.queue_transport_close_for_error(
        coquic::quic::test::test_time(1),
        coquic::quic::CodecError{.code = coquic::quic::CodecErrorCode::invalid_varint,
                                 .offset = 0});

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front());
    ASSERT_NE(handshake, nullptr);
    ASSERT_EQ(handshake->frames.size(), 1u);
    const auto *close =
        std::get_if<coquic::quic::TransportConnectionCloseFrame>(&handshake->frames.front());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11.1
    // # Errors that result in the connection being unusable, such as an
    // # obvious violation of protocol semantics or corruption of state that
    // # affects an entire connection, MUST be signaled using a
    // # CONNECTION_CLOSE frame (Section 19.19).
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11
    // # An endpoint that detects an error SHOULD signal the existence of that
    // # error to its peer.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3
    // # An endpoint that wishes to communicate a fatal connection error MUST
    // # use a CONNECTION_CLOSE frame if it is able.
    ASSERT_NE(close, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11
    // # The most appropriate error code (Section 20) SHOULD be included in
    // # the frame that signals the error.
    EXPECT_EQ(close->error_code, static_cast<std::uint64_t>(
                                     coquic::quic::QuicTransportErrorCode::frame_encoding_error));
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
    EXPECT_EQ(tracked_packet_count(connection.application_space_), 0u);
    EXPECT_FALSE(connection.has_sendable_datagram(coquic::quic::test::test_time(2)));
}

TEST(QuicCoreTest, ClosingTransportErrorUsesInitialProtectionWithoutHandshakeKeys) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ = {
        std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
        std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08},
    };
    connection.peer_source_connection_id_ = {std::byte{0xc1}, std::byte{0x45}};
    connection.current_send_path_id_ = 0;
    auto &path = connection.ensure_path_state(0);
    path.validated = true;
    path.anti_amplification_received_bytes = 1200;
    connection.peer_address_validated_ = true;
    connection.queue_transport_close_for_error(
        coquic::quic::test::test_time(1),
        coquic::quic::CodecError{.code = coquic::quic::CodecErrorCode::invalid_varint,
                                 .offset = 0});

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));

    ASSERT_FALSE(datagram.empty());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-14.1
    // # Similarly, a server MUST expand the payload of all UDP datagrams
    // # carrying ack-eliciting Initial packets to at least the smallest
    // # allowed maximum datagram size of 1200 bytes.
    EXPECT_GE(datagram.size(), 1200u);
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets.front());
    ASSERT_NE(initial, nullptr);
    const auto close = std::find_if(
        initial->frames.begin(), initial->frames.end(), [](const coquic::quic::Frame &frame) {
            return std::holds_alternative<coquic::quic::TransportConnectionCloseFrame>(frame);
        });
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11.1
    // # Errors that result in the connection being unusable, such as an
    // # obvious violation of protocol semantics or corruption of state that
    // # affects an entire connection, MUST be signaled using a
    // # CONNECTION_CLOSE frame (Section 19.19).
    //= https://www.rfc-editor.org/rfc/rfc9000#section-11
    // # An endpoint that detects an error SHOULD signal the existence of that
    // # error to its peer.
    ASSERT_NE(close, initial->frames.end());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 1u);
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
    EXPECT_FALSE(connection.has_sendable_datagram(coquic::quic::test::test_time(2)));
}

TEST(QuicCoreTest, ApplicationEmptyCandidateFinalizesExistingHandshakePacket) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 400;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x64});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 11,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    ASSERT_TRUE(connection.queue_stream_send(0, std::vector<std::byte>(16, std::byte{0x65}), false)
                    .has_value());
    connection.congestion_controller_.on_packet_sent(
        connection.congestion_controller_.congestion_window(), /*ack_eliciting=*/true);
    ASSERT_EQ(connection.congestion_controller_.bytes_in_flight(),
              connection.congestion_controller_.congestion_window());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());

    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front()), nullptr);
}

TEST(QuicCoreTest,
     ApplicationAppendToHandshakeDatagramFailsWhenSerializationOfExistingPacketFails) {
    const auto configure_connection = [](coquic::quic::QuicConnection &connection) {
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.handshake_confirmed_ = false;
        connection.peer_address_validated_ = false;
        connection.anti_amplification_received_bytes_ = 1200;
        connection.handshake_space_.write_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x66});
        connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
            .packet_number = 12,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
        };
        ASSERT_TRUE(
            connection.queue_stream_send(0, std::vector<std::byte>(16, std::byte{0x67}), false)
                .has_value());
    };

    auto control = make_connected_server_connection();
    configure_connection(control);
    const auto control_datagram = control.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(control_datagram.empty());
    auto control_packets = decode_sender_datagram(control, control_datagram);
    ASSERT_EQ(control_packets.size(), 2u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&control_packets.front()),
              nullptr);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedOneRttPacket>(&control_packets.back()), nullptr);

    auto failure = make_connected_server_connection();
    configure_connection(failure);
    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    auto faulted_datagram = failure.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(faulted_datagram.empty());
    EXPECT_TRUE(failure.has_failed());
    EXPECT_EQ(tracked_packet_count(failure.handshake_space_), 1u);
    EXPECT_EQ(tracked_packet_count(failure.application_space_), 0u);
}

TEST(QuicCoreTest,
     ApplicationAppendToHandshakeDatagramFailsWhenExistingHandshakePayloadSerializationFails) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x68});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 14,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    ASSERT_TRUE(connection.queue_stream_send(0, std::vector<std::byte>(16, std::byte{0x69}), false)
                    .has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update);

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, HandshakeTrimLoopStopsWhenAckStillOverflowsAfterAllCryptoIsRemoved) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x65});
    connection.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hs"));
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.handshake_space_.received_packets.record_received(
            packet_number,
            /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.handshake_space_.send_crypto.has_pending_data());
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
}

TEST(QuicCoreTest, PendingApplicationCryptoDoesNotStarveQueuedServerResponse) {
    auto connection = make_connected_server_connection();

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
    ASSERT_TRUE(
        connection
            .queue_stream_send(
                0, std::vector<std::byte>(static_cast<std::size_t>(1024), std::byte{0x53}), true)
            .has_value());

    bool saw_ack = false;
    bool saw_crypto = false;
    bool saw_stream = false;
    for (int index = 0; index < 4; ++index) {
        auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (datagram.empty()) {
            break;
        }

        for (const auto &packet : decode_sender_datagram(connection, datagram)) {
            const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packet);
            ASSERT_NE(application, nullptr);
            if (application == nullptr) {
                continue;
            }

            for (const auto &frame : application->frames) {
                saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
                saw_crypto = saw_crypto || std::holds_alternative<coquic::quic::CryptoFrame>(frame);
                saw_stream = saw_stream || std::holds_alternative<coquic::quic::StreamFrame>(frame);
            }
        }
    }

    EXPECT_TRUE(saw_crypto);
    EXPECT_TRUE(saw_stream);
    EXPECT_FALSE(connection.has_pending_application_send());
    EXPECT_TRUE(saw_ack || !connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ConnectionHelperMethodsCoverAdditionalPendingSendAndLimitBranches) {
    auto connection = make_connected_client_connection();
    connection.connection_flow_control_.advertised_max_data = 4;
    connection.connection_flow_control_.delivered_bytes = 5;
    connection.connection_flow_control_.local_receive_window = 2;
    connection.maybe_refresh_connection_receive_credit(/*force=*/false);
    EXPECT_FALSE(connection.connection_flow_control_.pending_max_data_frame.has_value());

    connection.local_stream_limit_state_.advertised_max_streams_uni = 0;
    connection.local_transport_parameters_.initial_max_streams_uni = 7;
    EXPECT_EQ(connection.peer_stream_open_limits().unidirectional, 7u);
    connection.local_transport_parameters_.initial_max_streams_uni = 0;
    EXPECT_EQ(connection.peer_stream_open_limits().unidirectional,
              connection.config_.transport.initial_max_streams_uni);

    auto &stream = connection.streams_
                       .emplace(0, coquic::quic::make_implicit_stream_state(
                                       /*stream_id=*/0, connection.config_.role))
                       .first->second;
    stream.flow_control.pending_stream_data_blocked_frame = coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 1,
    };
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::pending;
    EXPECT_TRUE(connection.has_pending_application_send());

    auto &pending_fin = connection.streams_
                            .emplace(4, coquic::quic::make_implicit_stream_state(
                                            /*stream_id=*/4, connection.config_.role))
                            .first->second;
    pending_fin.send_fin_state = coquic::quic::StreamSendFinState::pending;
    EXPECT_TRUE(connection.has_pending_application_send());
    stream.flow_control.stream_data_blocked_state = coquic::quic::StreamControlFrameState::none;
    stream.flow_control.pending_stream_data_blocked_frame = std::nullopt;
    connection.invalidate_stream_sendability_cache();
    EXPECT_FALSE(connection.has_pending_application_send());
    pending_fin.send_final_size = 1;
    pending_fin.flow_control.peer_max_stream_data = 0;
    connection.invalidate_stream_sendability_cache();
    EXPECT_FALSE(connection.has_pending_application_send());

    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 1};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    EXPECT_FALSE(datagram.empty());
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
    EXPECT_TRUE(after.next_wakeup.has_value());
}

TEST(QuicCoreTest, FailureSuppressesStaleHandshakeReadyInSameResult) {
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    server.connection_->queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);

    const auto failed = server.advance(coquic::quic::QuicCoreInboundDatagram{{std::byte{0x01}}},
                                       coquic::quic::test::test_time());
    const auto state_changes = coquic::quic::test::state_changes_from(failed);

    EXPECT_EQ(state_changes, std::vector{coquic::quic::QuicCoreStateChange::failed});
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
    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    if (!received.has_value()) {
        return;
    }
    const auto &received_stream = *received;
    EXPECT_EQ(coquic::quic::test::string_from_bytes(received_stream.bytes), "pong");
}

TEST(QuicCoreTest, ConnectionParserHelpersRejectMalformedClientInitialHeaders) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection.peek_client_initial_destination_connection_id({}).has_value());

    const auto fixed_bit_missing = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01, 0x00}));
    ASSERT_FALSE(fixed_bit_missing.has_value());
    EXPECT_EQ(fixed_bit_missing.error().code, coquic::quic::CodecErrorCode::invalid_fixed_bit);

    const auto wrong_packet_type = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xf0, 0x00, 0x00, 0x00, 0x01, 0x00}));
    ASSERT_FALSE(wrong_packet_type.has_value());
    EXPECT_EQ(wrong_packet_type.error().code,
              coquic::quic::CodecErrorCode::unsupported_packet_type);

    const auto truncated_version = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00}));
    ASSERT_FALSE(truncated_version.has_value());
    EXPECT_EQ(truncated_version.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto unsupported_version = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x02, 0x00}));
    ASSERT_FALSE(unsupported_version.has_value());
    EXPECT_EQ(unsupported_version.error().code,
              coquic::quic::CodecErrorCode::unsupported_packet_type);

    auto missing_dcid_length = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}));
    ASSERT_FALSE(missing_dcid_length.has_value());
    EXPECT_EQ(missing_dcid_length.error().code, coquic::quic::CodecErrorCode::truncated_input);

    auto oversized_dcid = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}));
    ASSERT_FALSE(oversized_dcid.has_value());
    EXPECT_EQ(oversized_dcid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto truncated_dcid = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x02}));
    ASSERT_FALSE(truncated_dcid.has_value());
    EXPECT_EQ(truncated_dcid.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicCoreTest, ConnectionParserHelpersRejectMalformedPacketLengths) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    EXPECT_FALSE(connection.peek_next_packet_length({}).has_value());

    const auto short_header_fixed_bit_missing =
        connection.peek_next_packet_length(bytes_from_ints({0x20, 0x01, 0x02, 0x03}));
    ASSERT_FALSE(short_header_fixed_bit_missing.has_value());
    EXPECT_EQ(short_header_fixed_bit_missing.error().code,
              coquic::quic::CodecErrorCode::invalid_fixed_bit);

    const auto fixed_bit_missing =
        connection.peek_next_packet_length(bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01}));
    ASSERT_FALSE(fixed_bit_missing.has_value());
    EXPECT_EQ(fixed_bit_missing.error().code, coquic::quic::CodecErrorCode::invalid_fixed_bit);

    const auto unsupported_version =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x02, 0x00}));
    ASSERT_FALSE(unsupported_version.has_value());
    EXPECT_EQ(unsupported_version.error().code,
              coquic::quic::CodecErrorCode::unsupported_packet_type);

    auto truncated_dcid = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x03, 0x01}));
    ASSERT_FALSE(truncated_dcid.has_value());
    EXPECT_EQ(truncated_dcid.error().code, coquic::quic::CodecErrorCode::truncated_input);

    auto oversized_scid = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x15}));
    ASSERT_FALSE(oversized_scid.has_value());
    EXPECT_EQ(oversized_scid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto unsupported_type = connection.peek_next_packet_length(
        bytes_from_ints({0xf0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x00}));
    ASSERT_FALSE(unsupported_type.has_value());
    EXPECT_EQ(unsupported_type.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);

    auto token_too_long = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02}));
    ASSERT_FALSE(token_too_long.has_value());
    EXPECT_EQ(token_too_long.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);

    auto payload_too_long = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x02}));
    ASSERT_FALSE(payload_too_long.has_value());
    EXPECT_EQ(payload_too_long.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);
}

TEST(QuicCoreTest, ConnectionParserHelpersAcceptQuicV2InitialHeaders) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    const auto destination_connection_id = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xd0, 0x6b, 0x33, 0x43, 0xcf, 0x04, 0x01, 0x02, 0x03, 0x04}));
    ASSERT_TRUE(destination_connection_id.has_value());
    EXPECT_EQ(destination_connection_id.value(), (coquic::quic::ConnectionId{
                                                     std::byte{0x01},
                                                     std::byte{0x02},
                                                     std::byte{0x03},
                                                     std::byte{0x04},
                                                 }));

    const auto packet_length = connection.peek_next_packet_length(bytes_from_ints(
        {0xd0, 0x6b, 0x33, 0x43, 0xcf, 0x01, 0xaa, 0x01, 0xbb, 0x00, 0x02, 0x01, 0x02}));
    ASSERT_TRUE(packet_length.has_value());
    EXPECT_EQ(packet_length.value(), 13u);
}

TEST(QuicCoreTest, NativeQuicV2HandshakeCompletes) {
    auto client_config = coquic::quic::test::make_client_core_config();
    client_config.original_version = coquic::quic::kQuicVersion2;
    client_config.initial_version = coquic::quic::kQuicVersion2;
    client_config.supported_versions = {coquic::quic::kQuicVersion2};
    coquic::quic::QuicCore client(std::move(client_config));

    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.original_version = coquic::quic::kQuicVersion2;
    server_config.initial_version = coquic::quic::kQuicVersion2;
    server_config.supported_versions = {coquic::quic::kQuicVersion2};
    coquic::quic::QuicCore server(std::move(server_config));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto start_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(start_datagrams.empty());
    EXPECT_EQ(read_u32_be_at(start_datagrams.front(), 1), coquic::quic::kQuicVersion2);

    coquic::quic::test::drive_quic_handshake_from_results(client, server, start, {},
                                                          coquic::quic::test::test_time());

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(server.is_handshake_complete());
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(server.has_failed());
}

} // namespace
