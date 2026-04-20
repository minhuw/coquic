#include <array>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <type_traits>

#include "src/quic/connection_test_hooks.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/packet_crypto_test_hooks.h"
#include "src/quic/protected_codec.h"
#include "src/quic/protected_codec_test_hooks.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"
#include "src/quic/varint.h"
#include "src/quic/qlog/types.h"
#include "tests/support/core/connection_test_fixtures.h"
#include "tests/support/quic_test_utils.h"
#include "src/http3/http3.h"
#include "src/quic/qlog/session.h"

namespace coquic::quic {
CodecResult<TrafficSecret> derive_next_traffic_secret(const TrafficSecret &secret);
}

namespace {
using coquic::quic::test_support::ack_frame_acks_packet_number_for_tests;
using coquic::quic::test_support::application_stream_ids_from_datagram;
using coquic::quic::test_support::bytes_from_hex;
using coquic::quic::test_support::bytes_from_ints;
using coquic::quic::test_support::datagram_has_application_ack;
using coquic::quic::test_support::datagram_has_application_stream;
using coquic::quic::test_support::decode_sender_datagram;
using coquic::quic::test_support::expect_local_error;
using coquic::quic::test_support::find_application_probe_payload_size_that_drops_ack;
using coquic::quic::test_support::find_application_send_payload_size_that_drops_ack;
using coquic::quic::test_support::first_tracked_packet;
using coquic::quic::test_support::invalid_cipher_suite;
using coquic::quic::test_support::last_tracked_packet;
using coquic::quic::test_support::make_connected_client_connection;
using coquic::quic::test_support::make_connected_server_connection;
using coquic::quic::test_support::make_connected_server_connection_with_preferred_address;
using coquic::quic::test_support::make_test_preferred_address;
using coquic::quic::test_support::make_test_traffic_secret;
using coquic::quic::test_support::optional_ref_or_terminate;
using coquic::quic::test_support::optional_value_or_terminate;
using coquic::quic::test_support::protected_datagram_destination_connection_ids;
using coquic::quic::test_support::protected_datagram_packet_kinds;
using coquic::quic::test_support::protected_next_packet_length;
using coquic::quic::test_support::ProtectedPacketKind;
using coquic::quic::test_support::read_u32_be_at;
using coquic::quic::test_support::ScopedEnvVar;
using coquic::quic::test_support::tracked_packet_count;
using coquic::quic::test_support::tracked_packet_or_null;
using coquic::quic::test_support::tracked_packet_or_terminate;
using coquic::quic::test_support::tracked_packet_snapshot;

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

std::vector<std::byte>
serialize_one_rtt_ack_datagram_for_test(const coquic::quic::QuicConnection &connection,
                                        const coquic::quic::TrafficSecret &secret,
                                        std::uint64_t packet_number, bool key_phase = false) {
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = key_phase,
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = packet_number,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = secret,
            .one_rtt_key_phase = key_phase,
        });
    EXPECT_TRUE(encoded.has_value());
    if (!encoded.has_value()) {
        return {};
    }
    return encoded.value();
}

void enable_qlog_session_for_test(
    coquic::quic::QuicConnection &connection, const std::filesystem::path &directory,
    coquic::quic::QuicCoreTimePoint start_time = coquic::quic::test::test_time()) {
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = directory};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.client_initial_destination_connection_id(), start_time);
    ASSERT_NE(connection.qlog_session_, nullptr);
}

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
                    .offset = static_cast<std::uint64_t>(prefix + gap),
                    .crypto_data = slice_bytes(prefix + gap, tail_offset),
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
                    .crypto_data = slice_bytes(prefix, prefix + gap),
                },
                coquic::quic::CryptoFrame{
                    .offset = static_cast<std::uint64_t>(tail_offset),
                    .crypto_data = slice_bytes(tail_offset, client_hello.size()),
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

    const auto second_initial_datagram = pad_initial(second_initial);
    const auto server_after_second_initial =
        server.advance(coquic::quic::QuicCoreInboundDatagram{second_initial_datagram},
                       coquic::quic::test::test_time(1));
    EXPECT_FALSE(server.has_failed());

    const auto second_response_datagrams =
        coquic::quic::test::send_datagrams_from(server_after_second_initial);
    ASSERT_FALSE(second_response_datagrams.empty());
    for (const auto &datagram : second_response_datagrams) {
        const auto packets = decode_sender_datagram(*server.connection_, datagram);
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
    const auto server_after_first_initial =
        server.advance(coquic::quic::QuicCoreInboundDatagram{first_initial_datagram},
                       coquic::quic::test::test_time(2));
    EXPECT_FALSE(server.has_failed());

    const auto response_datagrams =
        coquic::quic::test::send_datagrams_from(server_after_first_initial);
    ASSERT_FALSE(response_datagrams.empty());

    bool saw_initial_crypto = false;
    bool saw_handshake_crypto = false;
    for (const auto &datagram : response_datagrams) {
        const auto packets = decode_sender_datagram(*server.connection_, datagram);
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

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
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
    EXPECT_EQ(connection.next_wakeup(), std::nullopt);

    connection = make_connected_client_connection();
    EXPECT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        connection,
        {coquic::quic::ApplicationConnectionCloseFrame{
            .error_code = 0,
        }},
        /*packet_number=*/2));
    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(connection.next_wakeup(), std::nullopt);
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
    const auto application_close_stderr = testing::internal::GetCapturedStderr();

    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(application_close_stderr.empty());
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

        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (connection.has_failed() || datagram.empty()) {
            continue;
        }

        const auto packets = decode_sender_datagram(connection, datagram);
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

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_TRUE(connection.has_failed());
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

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.has_pending_application_send());

    const auto packets = decode_sender_datagram(connection, datagram);
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
    const auto control_packets = decode_sender_datagram(control, control_datagram);
    ASSERT_EQ(control_packets.size(), 2u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&control_packets.front()),
              nullptr);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedOneRttPacket>(&control_packets.back()), nullptr);

    auto failure = make_connected_server_connection();
    configure_connection(failure);
    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    const auto faulted_datagram = failure.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

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

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_TRUE(connection.handshake_space_.send_crypto.has_pending_data());
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
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
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
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
    EXPECT_FALSE(connection.has_pending_application_send());
    pending_fin.send_final_size = 1;
    pending_fin.flow_control.peer_max_stream_data = 0;
    EXPECT_FALSE(connection.has_pending_application_send());

    connection.connection_flow_control_.pending_max_data_frame =
        coquic::quic::MaxDataFrame{.maximum_data = 1};
    connection.connection_flow_control_.max_data_state =
        coquic::quic::StreamControlFrameState::pending;
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
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

    const auto missing_dcid_length = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}));
    ASSERT_FALSE(missing_dcid_length.has_value());
    EXPECT_EQ(missing_dcid_length.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto oversized_dcid = connection.peek_client_initial_destination_connection_id(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}));
    ASSERT_FALSE(oversized_dcid.has_value());
    EXPECT_EQ(oversized_dcid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto truncated_dcid = connection.peek_client_initial_destination_connection_id(
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

    const auto truncated_dcid = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x03, 0x01}));
    ASSERT_FALSE(truncated_dcid.has_value());
    EXPECT_EQ(truncated_dcid.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto oversized_scid = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x15}));
    ASSERT_FALSE(oversized_scid.has_value());
    EXPECT_EQ(oversized_scid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto unsupported_type = connection.peek_next_packet_length(
        bytes_from_ints({0xf0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x00}));
    ASSERT_FALSE(unsupported_type.has_value());
    EXPECT_EQ(unsupported_type.error().code, coquic::quic::CodecErrorCode::unsupported_packet_type);

    const auto token_too_long = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02}));
    ASSERT_FALSE(token_too_long.has_value());
    EXPECT_EQ(token_too_long.error().code, coquic::quic::CodecErrorCode::packet_length_mismatch);

    const auto payload_too_long = connection.peek_next_packet_length(
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

TEST(QuicCoreTest, UnexpectedFirstInboundDatagramsFailAndLaterCallsAreInert) {
    coquic::quic::QuicConnection client(coquic::quic::test::make_client_core_config());
    client.process_inbound_datagram(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}),
                                    coquic::quic::test::test_time());
    EXPECT_TRUE(client.has_failed());

    client.start();
    ASSERT_TRUE(client.queue_stream_send(0, coquic::quic::test::bytes_from_string("ignored"), false)
                    .has_value());
    client.status_ = coquic::quic::HandshakeStatus::idle;
    ASSERT_TRUE(client.queue_stream_send(0, {}, false).has_value());
    EXPECT_FALSE(client.streams_.contains(0));
    client.status_ = coquic::quic::HandshakeStatus::failed;
    client.process_inbound_datagram(std::span<const std::byte>{}, coquic::quic::test::test_time(1));
    EXPECT_TRUE(client.drain_outbound_datagram(coquic::quic::test::test_time(2)).empty());
    EXPECT_FALSE(client.take_received_stream_data().has_value());

    coquic::quic::QuicConnection server(coquic::quic::test::make_server_core_config());
    server.process_inbound_datagram(std::span<const std::byte>{}, coquic::quic::test::test_time(3));
    EXPECT_FALSE(server.has_failed());

    server.process_inbound_datagram(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x04}),
                                    coquic::quic::test::test_time(4));
    EXPECT_TRUE(server.has_failed());
}

TEST(QuicCoreTest, ServerStartupFailureReturnsAfterStartingTls) {
    auto server_config = coquic::quic::test::make_server_core_config();
    server_config.identity.reset();
    coquic::quic::QuicConnection server(std::move(server_config));

    server.process_inbound_datagram(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x02}),
        coquic::quic::test::test_time());

    EXPECT_TRUE(server.has_failed());
}

TEST(QuicCoreTest, ConnectionProcessInboundCryptoCoversErrorBranches) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    const auto wrong_frame = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x")},
        coquic::quic::test::test_time());
    ASSERT_FALSE(wrong_frame.has_value());
    EXPECT_EQ(wrong_frame.error().code,
              coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);

    const auto empty_crypto = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 1>{coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time(1));
    EXPECT_TRUE(empty_crypto.has_value());

    const auto overflow =
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::CryptoFrame{
                                                  .offset = (std::uint64_t{1} << 62),
                                                  .crypto_data = {std::byte{0x01}},
                                              },
                                          },
                                          coquic::quic::test::test_time(2));
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto missing_tls =
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::CryptoFrame{
                                                  .offset = 0,
                                                  .crypto_data = {std::byte{0x01}},
                                              },
                                          },
                                          coquic::quic::test::test_time(3));
    ASSERT_FALSE(missing_tls.has_value());
    EXPECT_EQ(missing_tls.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    connection.start_client_if_needed();
    auto &connection_tls = connection.tls_;
    if (!connection_tls.has_value()) {
        ADD_FAILURE() << "expected client startup to initialize TLS state";
        return;
    }
    coquic::quic::test::TlsAdapterTestPeer::set_sticky_error(
        *connection_tls, coquic::quic::CodecErrorCode::invalid_packet_protection_state);
    const auto provided_failure =
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::initial,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::CryptoFrame{
                                                  .offset = 1,
                                                  .crypto_data = {std::byte{0x02}},
                                              },
                                          },
                                          coquic::quic::test::test_time(4));
    ASSERT_FALSE(provided_failure.has_value());
    EXPECT_EQ(provided_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicCoreTest, ConnectionProcessInboundCryptoAcceptsPingBeforeCryptoFrames) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    const auto initial = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::array<coquic::quic::Frame, 2>{coquic::quic::PingFrame{}, coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time());
    ASSERT_TRUE(initial.has_value());

    const auto handshake = connection.process_inbound_crypto(
        coquic::quic::EncryptionLevel::handshake,
        std::array<coquic::quic::Frame, 2>{coquic::quic::PingFrame{}, coquic::quic::CryptoFrame{}},
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(handshake.has_value());
}

TEST(QuicCoreTest, ProcessInboundPacketLeavesInitialAndHandshakeStateUntouchedOnFailure) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    const auto initial_failure = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0xaa}},
            .packet_number_length = 2,
            .packet_number = 0,
            .frames = {coquic::quic::test::make_inbound_application_stream_frame("x")},
        },
        coquic::quic::test::test_time());
    ASSERT_FALSE(initial_failure.has_value());
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());

    connection.handshake_space_.write_secret = make_test_traffic_secret();
    const auto handshake_failure = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 2,
            .packet_number = 1,
            .frames = {coquic::quic::test::make_inbound_application_stream_frame("y")},
        },
        coquic::quic::test::test_time(1));
    ASSERT_FALSE(handshake_failure.has_value());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundPacketIgnoresInitialPacketAfterInitialSpaceDiscard) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.initial_packet_space_discarded_ = true;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0x44}},
            .packet_number_length = 1,
            .packet_number = 1,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(processed.value());
    EXPECT_FALSE(connection.initial_space_.largest_authenticated_packet_number.has_value());
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversAckReorderAndErrorBranches) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        connection, coquic::quic::HandshakeStatus::connected);

    const auto ack_and_padding = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 3>{
            coquic::quic::AckFrame{},
            coquic::quic::PaddingFrame{.length = 2},
            coquic::quic::test::make_inbound_application_stream_frame("ok"),
        },
        coquic::quic::test::test_time());
    ASSERT_TRUE(ack_and_padding.has_value());
    const auto first_received = connection.take_received_stream_data();
    ASSERT_TRUE(first_received.has_value());
    if (!first_received.has_value()) {
        return;
    }
    const auto &first_stream = *first_received;
    EXPECT_EQ(coquic::quic::test::string_from_bytes(first_stream.bytes), "ok");

    const auto reordered = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x", 4),
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(reordered.has_value());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    const auto gap_filled = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("yz", 2),
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(gap_filled.has_value());
    const auto gap_filled_received = connection.take_received_stream_data();
    ASSERT_TRUE(gap_filled_received.has_value());
    if (!gap_filled_received.has_value()) {
        return;
    }
    const auto &gap_filled_stream = *gap_filled_received;
    EXPECT_EQ(coquic::quic::test::string_from_bytes(gap_filled_stream.bytes), "yzx");

    const auto overflow = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x", std::uint64_t{1} << 62),
        },
        coquic::quic::test::test_time(3));
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto missing_offset_value = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::StreamFrame{
                .fin = false,
                .has_offset = true,
                .has_length = true,
                .stream_id = 0,
                .offset = std::nullopt,
                .stream_data = {std::byte{'x'}},
            },
        },
        coquic::quic::test::test_time(4));
    ASSERT_FALSE(missing_offset_value.has_value());
    EXPECT_EQ(missing_offset_value.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, ConnectionPacketLengthParserRejectsRemainingMalformedInputs) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    const auto truncated_version =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00}));
    ASSERT_FALSE(truncated_version.has_value());
    EXPECT_EQ(truncated_version.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto missing_dcid_length =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01}));
    ASSERT_FALSE(missing_dcid_length.has_value());
    EXPECT_EQ(missing_dcid_length.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto oversized_dcid =
        connection.peek_next_packet_length(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x15}));
    ASSERT_FALSE(oversized_dcid.has_value());
    EXPECT_EQ(oversized_dcid.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto truncated_scid = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x02, 0x03}));
    ASSERT_FALSE(truncated_scid.has_value());
    EXPECT_EQ(truncated_scid.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto truncated_token_length = connection.peek_next_packet_length(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02}));
    ASSERT_FALSE(truncated_token_length.has_value());
    EXPECT_EQ(truncated_token_length.error().code, coquic::quic::CodecErrorCode::truncated_input);

    const auto truncated_payload_length = connection.peek_next_packet_length(
        bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02}));
    ASSERT_FALSE(truncated_payload_length.has_value());
    EXPECT_EQ(truncated_payload_length.error().code, coquic::quic::CodecErrorCode::truncated_input);
}

TEST(QuicCoreTest, ConnectionStartupHelpersCoverReentryAndTlsFailure) {
    coquic::quic::QuicConnection server(coquic::quic::test::make_server_core_config());
    server.start_client_if_needed();
    EXPECT_FALSE(server.started_);

    coquic::quic::QuicConnection client(coquic::quic::test::make_client_core_config());
    client.start_client_if_needed();
    ASSERT_TRUE(client.started_);
    const auto original_status = client.status_;
    client.start_client_if_needed();
    EXPECT_EQ(client.status_, original_status);

    const coquic::quic::test::ScopedTlsAdapterFaultInjector injector(
        coquic::quic::test::TlsAdapterFaultPoint::initialize_ctx_new);
    coquic::quic::QuicConnection failing_client(coquic::quic::test::make_client_core_config());
    failing_client.start_client_if_needed();
    EXPECT_TRUE(failing_client.has_failed());

    coquic::quic::QuicConnection second_server(coquic::quic::test::make_server_core_config());
    second_server.start_server_if_needed({std::byte{0x01}, std::byte{0x02}});
    ASSERT_TRUE(second_server.started_);
    const auto initial_dcid = second_server.client_initial_destination_connection_id_;
    second_server.start_server_if_needed({std::byte{0x03}});
    EXPECT_EQ(second_server.client_initial_destination_connection_id_, initial_dcid);
}

TEST(QuicCoreTest, ServerStartupRetainsUnsupportedClientVersionWithoutCompatibleFallback) {
    auto config = coquic::quic::test::make_server_core_config();
    config.supported_versions = {coquic::quic::kQuicVersion1};

    coquic::quic::QuicConnection connection(std::move(config));
    connection.start_server_if_needed({std::byte{0x01}, std::byte{0x02}}, 0xa1b2c3d4u);

    EXPECT_TRUE(connection.started_);
    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.original_version_, 0xa1b2c3d4u);
    EXPECT_EQ(connection.current_version_, 0xa1b2c3d4u);
}

TEST(QuicCoreTest, DeferredProtectedPacketVectorEqualityRejectsMismatchedBytesAndNonzeroIds) {
    const auto bytes = bytes_from_ints({0x01, 0x02});
    EXPECT_FALSE(coquic::quic::DeferredProtectedPacket(bytes, 7) == bytes);
    EXPECT_FALSE(bytes == coquic::quic::DeferredProtectedPacket(bytes, 7));
    EXPECT_FALSE(coquic::quic::DeferredProtectedPacket(bytes, 0) == bytes_from_ints({0x01, 0x03}));
}

TEST(QuicCoreTest, QueueApplicationCloseReturnsSuccessWhenConnectionAlreadyFailed) {
    auto connection = make_connected_client_connection();
    connection.status_ = coquic::quic::HandshakeStatus::failed;

    const auto result = connection.queue_application_close({
        .application_error_code = 7,
        .reason_phrase = "ignored",
    });

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
    EXPECT_FALSE(connection.pending_application_close_.has_value());
}

TEST(QuicCoreTest, ServerCreatedFromRetriedInitialKeepsOriginalVersionValidationContext) {
    auto server_config = coquic::quic::test::make_server_core_config();
    const auto retry_source_connection_id = bytes_from_hex("5300000000000001");
    const auto original_destination_connection_id = bytes_from_hex("8394c8f03e515708");
    const auto client_source_connection_id = bytes_from_hex("1d84ffd8036c94a5");
    server_config.supported_versions = {coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1};
    server_config.initial_destination_connection_id = retry_source_connection_id;
    server_config.original_destination_connection_id = original_destination_connection_id;
    server_config.retry_source_connection_id = retry_source_connection_id;

    coquic::quic::QuicConnection server(std::move(server_config));
    server.start_server_if_needed(retry_source_connection_id, coquic::quic::kQuicVersion1);

    EXPECT_EQ(server.original_version_, coquic::quic::kQuicVersion1);
    EXPECT_EQ(server.current_version_, coquic::quic::kQuicVersion1);
    EXPECT_FALSE(server.local_transport_parameters_.version_information.has_value());

    server.peer_source_connection_id_ = client_source_connection_id;
    const auto context = server.peer_transport_parameters_validation_context();
    ASSERT_TRUE(context.has_value());
    const auto &context_value = optional_ref_or_terminate(context);
    EXPECT_FALSE(context_value.expected_version_information.has_value());

    const auto validation = coquic::quic::validate_peer_transport_parameters(
        coquic::quic::EndpointRole::client,
        coquic::quic::TransportParameters{
            .max_udp_payload_size = 1200,
            .active_connection_id_limit = 8,
            .initial_source_connection_id = client_source_connection_id,
        },
        context_value);
    EXPECT_TRUE(validation.has_value());
}

TEST(QuicCoreTest, ConnectionStartupRejectsInvalidLocalTransportParameters) {
    auto bad_client_config = coquic::quic::test::make_client_core_config();
    bad_client_config.transport.ack_delay_exponent = 21;
    coquic::quic::QuicConnection bad_client(std::move(bad_client_config));
    bad_client.start_client_if_needed();
    EXPECT_TRUE(bad_client.started_);
    EXPECT_TRUE(bad_client.has_failed());
    EXPECT_FALSE(bad_client.tls_.has_value());

    auto bad_server_config = coquic::quic::test::make_server_core_config();
    bad_server_config.transport.max_ack_delay = (1u << 14);
    coquic::quic::QuicConnection bad_server(std::move(bad_server_config));
    bad_server.start_server_if_needed({std::byte{0x01}});
    EXPECT_TRUE(bad_server.started_);
    EXPECT_TRUE(bad_server.has_failed());
    EXPECT_FALSE(bad_server.tls_.has_value());
}

TEST(QuicCoreTest, ConnectionStartupRejectsUnserializableLocalTransportParameters) {
    auto bad_client_config = coquic::quic::test::make_client_core_config();
    bad_client_config.transport.initial_max_data = (std::uint64_t{1} << 62);
    coquic::quic::QuicConnection bad_client(std::move(bad_client_config));
    bad_client.start_client_if_needed();
    EXPECT_TRUE(bad_client.started_);
    EXPECT_TRUE(bad_client.has_failed());
    EXPECT_FALSE(bad_client.tls_.has_value());

    auto bad_server_config = coquic::quic::test::make_server_core_config();
    bad_server_config.transport.initial_max_stream_data_uni = (std::uint64_t{1} << 62);
    coquic::quic::QuicConnection bad_server(std::move(bad_server_config));
    bad_server.start_server_if_needed({std::byte{0x01}});
    EXPECT_TRUE(bad_server.started_);
    EXPECT_TRUE(bad_server.has_failed());
    EXPECT_FALSE(bad_server.tls_.has_value());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsForDecodeAndPacketProcessingErrors) {
    coquic::quic::QuicConnection decode_failure(coquic::quic::test::make_client_core_config());
    decode_failure.start_client_if_needed();
    decode_failure.process_inbound_datagram(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00}),
        coquic::quic::test::test_time());
    EXPECT_TRUE(decode_failure.has_failed());

    coquic::quic::QuicConnection packet_failure(coquic::quic::test::make_server_core_config());
    packet_failure.started_ = true;
    packet_failure.status_ = coquic::quic::HandshakeStatus::connected;
    packet_failure.client_initial_destination_connection_id_ =
        packet_failure.config_.initial_destination_connection_id;
    packet_failure.application_space_.read_secret = make_test_traffic_secret();

    const auto invalid_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = packet_failure.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 0,
                .frames =
                    {
                        coquic::quic::test::make_inbound_application_stream_frame("x", 0, 3),
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                packet_failure.client_initial_destination_connection_id(),
            .handshake_secret = std::nullopt,
            .one_rtt_secret = packet_failure.application_space_.read_secret,
        });
    ASSERT_TRUE(invalid_packet.has_value());
    packet_failure.process_inbound_datagram(invalid_packet.value(),
                                            coquic::quic::test::test_time(1));
    EXPECT_TRUE(packet_failure.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramDropsHandshakePacketWithoutReadSecret) {
    coquic::quic::QuicConnection connection(make_connected_client_connection());
    const auto handshake_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 0,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = handshake_secret,
            .one_rtt_secret = std::nullopt,
        });
    ASSERT_TRUE(packet.has_value());

    connection.process_inbound_datagram(packet.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresInitialPacketsAfterDiscardingInitialSpace) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());

    const auto to_server =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
        to_server, server, coquic::quic::test::test_time(1));
    ASSERT_FALSE(coquic::quic::test::send_datagrams_from(to_client).empty());

    const auto client_handshake = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(2));
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(client_handshake).empty());
    ASSERT_NE(client.connection_, nullptr);
    EXPECT_FALSE(client.connection_->initial_space_.read_secret.has_value());
    EXPECT_FALSE(client.connection_->initial_space_.write_secret.has_value());

    const auto replayed = coquic::quic::test::relay_send_datagrams_to_peer(
        to_client, client, coquic::quic::test::test_time(3));

    EXPECT_FALSE(client.has_failed());
    EXPECT_TRUE(coquic::quic::test::received_application_data_from(replayed).empty());
    ASSERT_NE(client.connection_, nullptr);
    EXPECT_TRUE(client.connection_->deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresHandshakePacketsAfterDiscardingHandshakeSpace) {
    auto connection = make_connected_client_connection();
    connection.discard_handshake_packet_space();

    const auto late_handshake = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_hex("0011223344556677"),
                .packet_number_length = 2,
                .packet_number = 1,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = make_test_traffic_secret(
                coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51}),
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(late_handshake.has_value());

    connection.process_inbound_datagram(late_handshake.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
}

std::vector<std::byte> captured_quic_go_server_first_flight() {
    return bytes_from_hex(
        "c30000000108c10000000000002504c516a3560041cc1deadd79519b2fb4b57443729da026692a0dc7f"
        "4495ca82f945e2dc0ac9a1d8392619cf89b43a7142506dfb58efea1be1331363abac7357ea84a30941b"
        "ec1f9d1b8bd312eb7a2a42fe440a1ddc22c50ab227a566d5364c387804206ae94926141c11a1ecc4517"
        "d7bf4120900bd2dfb914964c2e893b6294a3856990fb9699ff830a5eaf6feb19e6f6d8d920559a3bf78"
        "36f8fe5bdb3762c82b3ea148eb9de532a355460abb753cde6f06e6f2883be9c19a377755f06a3d8232e"
        "ded0c04fd25acdb84d78052a1890517f9db4ff5c634f28b254c19971aaa1c94a6424b2b5c9fa34e4c41"
        "b730ea60e4621dedc2a11060e15d3bf4e788a9763f4791e9f2f2d32738220a0dc97da2253172a77377a"
        "be9c67c21c6e7013cbd372b2259db0b7c50427b4bf6be5320ff41acf1b38e25d5f5e95ecbcde9755eb2"
        "d31fb4c69de9fc4b48af6868a360e5aa064945faaed1ffd478cbf422a6ca712a107c9f449fa682d0757"
        "5624d07929c38fc9937f1b794272a743ef0917c7a7b81a194b22f89fa121ae4e8e8814404f10f238f87"
        "af1930ac85c7533768a1e44e241c6b1117ecb4524132e6c9d86a08e5f8ea9f70b3cdff0f0211be98aa6"
        "380017b98a42b79539b87564e1494057a8240915462c68f7600e50000000108c10000000000002504c5"
        "16a35642d69c355c6679ac9a9f79e36c4ce9ed05c4950c3d96f8f3538294ba93c6570c3c7af1609d4e2"
        "68878ad02bcb4ec6d3d6726810ee4353734bc91e8d24d57b7a9b9d56e815b834eaf85f6fc005a52d6f49"
        "bbe14cfd83bac593dd2805efddc614e5cdceaabdf4ed2558d61118776ec50f9cf0ec65364543cf27ddf"
        "71ab38aa94fc6a4d20e5c239be9bfa3bc1768d3bda0e898c0718411040bc71f8708119ee7240886cf1c"
        "5a01204efaa120c056ed30777d0c64b024c7704142892f54caf3787924ba6256acecf00e2fd08cfe96d"
        "efe0f790578963c1450e8ad395ad892aca310b59b58cca60685a3cea2cf3242ec072c6b8b905ecddc4c"
        "0d08121c184d906752399c9fdc9334b557c20b47d7b5d6ac3580fab59a76fd3d605855e2cc963c67318"
        "4694e141d251075538289546cb6a713454850c22dd308fa8f8cacee9a50a2494b5d995b9a736cc437a1"
        "ae3aac1376083952befcac0d89235969d92cb3f8b832d3af74c1c04a95f1b8feec48fd7f40b0e1ac7fc"
        "b09584d436085c3e279a946ffff9714a359e63c1727f4b6f3d2b140ad3f37666e49d343da95b28f68a3"
        "9c3f59b8a1605941b2af21dfbbfa7ec8a31d8364a6d6663d1d5d052a046dc453e80a6089e0792e78cb7"
        "37c50e835bc50bb1e054b088517e5fed5cd78454a5fd06fdba2602e16438e84b44d3d66cab42897a382"
        "d1c407f2d773b774f8145b790e6aa8b309ec3bdfabc007a2deb984a1c436971be35907cfb024515d4ae"
        "ce019ce45543bde728c9deb8fa640c633388dcae74dee123e08d67cb0e0f190e255eb9826f94ccfbf8b"
        "e65c7b760df36697e315a979a01919e6a80e3f1f7e9f17836cfdc9a552ace0fae5629882bb97acfa1ce"
        "b73863edcd96e34e527fcac22821c129820d8644601727d903ac746411f11854b1067681116bce36620"
        "d3fc12d1e53c0bba977ee8ec08d27057fcf0cdd909b142a97ad547f3432785048cb646c78f5c945484e"
        "ddca1a7164e021e7f5d6e17d12dee1a07f5e1eb7b47901cf9554c100000000000025497da86827cf8147"
        "6875e5177ad6778c56fcc61d249695ffa7f085554cd4d61755fabd13ade985796962");
}

TEST(QuicCoreTest, ProcessCapturedQuicGoServerInitialInstallsHandshakeSecrets) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    connection.initial_space_.next_send_packet_number = 1;
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = captured_quic_go_server_first_flight();

    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);
    const auto handshake_packet_bytes =
        std::span<const std::byte>(server_first_flight).subspan(482, 747);
    const auto initial_decode = coquic::quic::deserialize_protected_datagram(
        initial_packet_bytes,
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id = config.initial_destination_connection_id,
        });
    ASSERT_TRUE(initial_decode.has_value());
    ASSERT_EQ(initial_decode.value().size(), 1u);
    ASSERT_TRUE(std::holds_alternative<coquic::quic::ProtectedInitialPacket>(
        initial_decode.value().front()));

    auto probe_connection = coquic::quic::QuicConnection(config);
    probe_connection.start_client_if_needed();
    ASSERT_FALSE(probe_connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());
    probe_connection.process_inbound_datagram(initial_packet_bytes,
                                              coquic::quic::test::test_time(1));
    ASSERT_FALSE(probe_connection.has_failed());
    ASSERT_TRUE(probe_connection.handshake_space_.read_secret.has_value());
    ASSERT_TRUE(probe_connection.handshake_space_.write_secret.has_value());
    EXPECT_EQ(optional_ref_or_terminate(probe_connection.handshake_space_.read_secret).cipher_suite,
              coquic::quic::CipherSuite::tls_aes_128_gcm_sha256);
    EXPECT_EQ(
        optional_ref_or_terminate(probe_connection.handshake_space_.write_secret).cipher_suite,
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256);
    EXPECT_EQ(
        optional_ref_or_terminate(probe_connection.handshake_space_.read_secret).secret.size(),
        32u);
    EXPECT_EQ(
        optional_ref_or_terminate(probe_connection.handshake_space_.write_secret).secret.size(),
        32u);

    const auto handshake_with_official_server_secret = coquic::quic::deserialize_protected_datagram(
        handshake_packet_bytes,
        coquic::quic::DeserializeProtectionContext{
            .peer_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                probe_connection.client_initial_destination_connection_id(),
            .handshake_secret =
                coquic::quic::TrafficSecret{
                    .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                    .secret = bytes_from_hex(
                        "9f8d726a3e3d755a0a0e1af69344628c46fe4db9c573c554966b35b3ceaa14b1"),
                },
        });
    ASSERT_TRUE(handshake_with_official_server_secret.has_value());
    ASSERT_FALSE(handshake_with_official_server_secret.value().empty());
    ASSERT_TRUE(std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(
        handshake_with_official_server_secret.value().front()));

    // The client handshake secrets are derived from an ephemeral key share, so a captured server
    // flight only stays stable through the Initial packet. Verify those stable Initial-packet
    // properties here, and keep the captured Handshake packet as a fixed codec vector above.
    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("c516a356"));
    ASSERT_TRUE(connection.handshake_space_.write_secret.has_value());

    const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(response.empty());

    const auto packets = decode_sender_datagram(connection, response);
    const auto initial_packet =
        std::find_if(packets.begin(), packets.end(), [](const auto &packet) {
            return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
        });

    EXPECT_NE(initial_packet, packets.end());
    EXPECT_FALSE(connection.initial_packet_space_discarded_);
}

TEST(QuicCoreTest, ClientSendsStandaloneHandshakeAckBeforeHandshakeFlight) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    connection.initial_space_.next_send_packet_number = 1;
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = captured_quic_go_server_first_flight();
    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);

    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));
    ASSERT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.handshake_space_.read_secret.has_value());
    ASSERT_TRUE(connection.handshake_space_.write_secret.has_value());

    ASSERT_NE(tracked_packet_count(connection.initial_space_), 0u);
    const auto initial_packet_number =
        first_tracked_packet(connection.initial_space_).packet_number;
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.initial_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = initial_packet_number,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(1),
                                         /*ack_delay_exponent=*/0,
                                         /*max_ack_delay_ms=*/0,
                                         /*suppress_pto_reset=*/true)
                    .has_value());

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedHandshakePacket{
            .source_connection_id = bytes_from_hex("0011223344556677"),
            .packet_number = 1,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(processed.has_value());

    const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(response.empty());
    EXPECT_TRUE(connection.initial_packet_space_discarded_);

    const auto response_packets = decode_sender_datagram(connection, response);
    EXPECT_NE(std::find_if(
                  response_packets.begin(), response_packets.end(),
                  [](const auto &packet) {
                      return std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(packet);
                  }),
              response_packets.end());
}

TEST(QuicCoreTest, ClientKeepsPtoArmedAfterServerInitialAckWithoutHandshakeFlight) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    connection.initial_space_.next_send_packet_number = 1;
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = captured_quic_go_server_first_flight();
    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);

    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));
    ASSERT_FALSE(connection.has_failed());
    ASSERT_TRUE(connection.handshake_space_.read_secret.has_value());
    ASSERT_TRUE(connection.handshake_space_.write_secret.has_value());

    ASSERT_NE(tracked_packet_count(connection.initial_space_), 0u);
    const auto initial_packet_number =
        first_tracked_packet(connection.initial_space_).packet_number;
    ASSERT_TRUE(connection
                    .process_inbound_ack(connection.initial_space_,
                                         coquic::quic::AckFrame{
                                             .largest_acknowledged = initial_packet_number,
                                             .first_ack_range = 0,
                                         },
                                         coquic::quic::test::test_time(1),
                                         /*ack_delay_exponent=*/0,
                                         /*max_ack_delay_ms=*/0,
                                         /*suppress_pto_reset=*/true)
                    .has_value());
    EXPECT_FALSE(std::ranges::any_of(
        tracked_packet_snapshot(connection.initial_space_),
        [](const auto &packet) { return packet.ack_eliciting && packet.in_flight; }));
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);

    const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(response.empty());

    const auto response_packets = decode_sender_datagram(connection, response);
    EXPECT_NE(std::find_if(response_packets.begin(), response_packets.end(),
                           [](const auto &packet) {
                               return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(
                                   packet);
                           }),
              response_packets.end());
    EXPECT_EQ(std::count_if(
                  response_packets.begin(), response_packets.end(),
                  [](const auto &packet) {
                      return std::holds_alternative<coquic::quic::ProtectedHandshakePacket>(packet);
                  }),
              0);
    EXPECT_FALSE(std::ranges::any_of(
        tracked_packet_snapshot(connection.initial_space_),
        [](const auto &packet) { return packet.ack_eliciting && packet.in_flight; }));
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);

    const auto next_wakeup = connection.next_wakeup();
    ASSERT_TRUE(next_wakeup.has_value());
}

TEST(QuicCoreTest, ClientKeepsHandshakeKeepaliveArmedAfterAckOnlyHandshakeDiscardedInitialSpace) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.initial_packet_space_discarded_ = true;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.pto_count_ = 4;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});

    const auto deadline_opt = connection.pto_deadline();
    ASSERT_TRUE(deadline_opt.has_value());
    const auto deadline = deadline_opt.value_or(coquic::quic::test::test_time());

    connection.arm_pto_probe(deadline);

    ASSERT_TRUE(connection.handshake_space_.pending_probe_packet.has_value());
    EXPECT_FALSE(connection.initial_space_.pending_probe_packet.has_value());

    const auto probe = connection.drain_outbound_datagram(deadline);
    ASSERT_FALSE(probe.empty());

    const auto probe_packets = decode_sender_datagram(connection, probe);
    ASSERT_EQ(probe_packets.size(), 1u);
    const auto *handshake = std::get_if<coquic::quic::ProtectedHandshakePacket>(&probe_packets[0]);
    ASSERT_NE(handshake, nullptr);
    EXPECT_NE(std::find_if(handshake->frames.begin(), handshake->frames.end(),
                           [](const auto &frame) {
                               return std::holds_alternative<coquic::quic::PingFrame>(frame);
                           }),
              handshake->frames.end());
    EXPECT_EQ(connection.last_client_handshake_keepalive_probe_time_, std::optional{deadline});
}

TEST(QuicCoreTest, ProcessInboundDatagramDefersLaterMissingContextPacketAfterValidInitial) {
    auto config = coquic::quic::test::make_client_core_config();
    config.source_connection_id = bytes_from_hex("c100000000000025");
    config.initial_destination_connection_id = bytes_from_hex("8300000000000024");

    coquic::quic::QuicConnection connection(config);
    connection.start_client_if_needed();
    connection.initial_space_.next_send_packet_number = 1;
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto server_first_flight = captured_quic_go_server_first_flight();
    const auto initial_packet_bytes = std::span<const std::byte>(server_first_flight).first(482);
    const auto buffered_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 0,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 0,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = make_test_traffic_secret(
                coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51}),
        });
    ASSERT_TRUE(buffered_packet.has_value()) << static_cast<int>(buffered_packet.error().code);

    std::vector<std::byte> datagram(initial_packet_bytes.begin(), initial_packet_bytes.end());
    datagram.insert(datagram.end(), buffered_packet.value().begin(), buffered_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::in_progress);
    EXPECT_TRUE(connection.handshake_space_.read_secret.has_value());
    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), buffered_packet.value());
}

std::vector<std::byte> captured_picoquic_client_initial_datagram() {
    return bytes_from_hex(
        "ce00000001085398e92f19c3659808825ff16a7a5d8b9f0041409c471d3fbfe46c43389ad82ab17702dc"
        "9686e7157b4dcceaeecc13f61aef037f58b15e94c06417a351f30d50cf1152098bb49ce2b69c3ba80bd5"
        "cb9e1086f9a7f6d2f854b5b5638b23486d23ad1651202d87997ba51cb9f7a14d20bb430b4e6b5e25b940"
        "16b0d7ad981ae8e883a49a461444a531929c5d24044b6964cfeb5b2132e0053a434ecdd0ea2ae8adb8ca"
        "274e2ee7e6d680ea6d4756e4c37268970177613d2f31b6db1cb0799bb2f506830c96de55b72228253a6c"
        "f4d0f3512e5d93b7d8cb262a471ca0ec44eba3ceadd500870849b5cf00782bbb38188c49c95b776c97ae"
        "0fecd918f499525b6b9a61d900fb43844de41cc805abbef8c99b5727003a094b22955c2e582a45057521"
        "9cac4d4b3c51be3a436bae6e032b619c5773547abebf9f63ad9ab519f19c6813411b76e9b040d48c9d94"
        "ef16dd17aaca9bf3cd862e27007aec392281967ec218de253c37c2bc45aec40570b5c1aad297b56e3fcf"
        "aaea35a0bc7c53de7e3d5fe4a7786a02a205421d5aa9a40a4dfcc7df3415d42a96256ed422dfdeda4322"
        "8c84f714b0f312521fd34edb356fd1fc12a5c49e6b77e16cf6198a29e196a0d7afe26a8fb46ecd1215f1"
        "7125619b579e9b13e0a982faaa42605f50f992140560e3011a64248df0a6a7ac87a4b500c70206618c8c"
        "1df51145aebd76773470ca88b8cb2fb2f47bfbeb92736837d9d94dfcc7df3415d42ab2fb517033e41d7e"
        "49f54b4fddd99742ea55c6f02aea1cd3e8e4327f860d7c18c6c455b78b0f5245e98165442b45d00b4272"
        "ca77bae3d14f7e3b68f2a426ef3429eca95eb24cd1ba7c55c7ff46bae3f2614ede6e8b679bde2d52f465"
        "ab4ee9d6a72efd6b9974c9a8cad66100d27e107a7bc695cfb229120dcd21c583eae090e5164faff7db96"
        "1e139012e71c657a89b5b9770e24bbcce8b5f7f9c2a9c0146cbf1512d156bbd182301c01a7eb252a0133"
        "83bcd866859e51ff2e4322839f64f0d0357213b2d610f696fe1bc3b48fa3ad8fd349e1426c6d6c6fec01"
        "acd9304cba80bcfd4bde751f4c76cabd262fee0c15bbfbfccd0c7a547857cd813a4977f6befab20399e8"
        "62e65c0eb81f95e27387f233ef0c82823c62f61da922b268caa09bc585ee26a645b56f735231bf8ca7fe"
        "3f65387fa669c229e7f4ac0115d6da7a5ab3c84c9633a67d8b00bcae2898b8203d9d7d7e04664bc2a782"
        "672ac79f3f8de8bd3cd89730557b0a94ae103b715f221a4713cf04b42b0dd948e9089cedaf267bbbcb40"
        "e06180aa90932ede76825f3e6d6badc2542cc8746986368ce3038a36782c60cf8da7279859cbd92033d6"
        "294238f2fa3a780f5141350c9994ac0ce4814653a4d8acad56eeeeb857cf6e97a5e4542f5e3e56f9f06b"
        "0b351a0cc6bb2a7ed3af43fd69e576e20bf4fb578b83bebb79c984c3f167bb065c745cb0d6e1e83cb620"
        "e9427e6352d431fe3c0fe6a8507155c6c6117cdea8048b6637546140320447dc4b4ce533bde22778023a"
        "6e94413981afd021b3d3d6e34cc91786e95414083731cf1e8efb8e6497734a67021d7e3174391d616388"
        "da325bd70449c0f3f823f1da82c67add7701068e673ef0dba9d912082ffde7aefba917324ace49e22202"
        "fe73854a4d994a2c60696815a474a2510bca2bdec845fe96333be55b5d59e068223510494d812491b7ff"
        "cbb9abb1db0b1dbec9b72a644bf39ef778a68cec4d70120c56d9b3fa7eea849e980f");
}

TEST(QuicCoreTest, ProcessCapturedPicoquicClientInitialPacketStartsServerHandshake) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.client_initial_destination_connection_id(),
              bytes_from_hex("5398e92f19c36598"));
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("825ff16a7a5d8b9f"));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, ServerHandshakeFlightStaysWithinAmplificationBudgetBeforeValidation) {
    auto datagram = captured_picoquic_client_initial_datagram();
    const auto initial_packet_bytes = std::span<const std::byte>(datagram).first(346);

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));
    connection.anti_amplification_received_bytes_ = initial_packet_bytes.size();
    connection.anti_amplification_sent_bytes_ = 0;

    ASSERT_FALSE(connection.has_failed());

    std::size_t total_sent = 0;
    while (true) {
        const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (response.empty()) {
            break;
        }
        total_sent += response.size();
    }

    EXPECT_LE(total_sent, initial_packet_bytes.size() * 3u);
}

TEST(QuicCoreTest, ServerPtoProbeStaysWithinAmplificationBudgetBeforeValidation) {
    auto datagram = captured_picoquic_client_initial_datagram();
    const auto initial_packet_bytes = std::span<const std::byte>(datagram).first(346);

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(initial_packet_bytes, coquic::quic::test::test_time(1));
    connection.anti_amplification_received_bytes_ = initial_packet_bytes.size();
    connection.anti_amplification_sent_bytes_ = 0;

    ASSERT_FALSE(connection.has_failed());

    std::size_t total_sent = 0;
    while (true) {
        const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (response.empty()) {
            break;
        }
        total_sent += response.size();
    }

    const auto wakeup = connection.next_wakeup();
    ASSERT_TRUE(wakeup.has_value());
    if (!wakeup.has_value()) {
        return;
    }

    connection.on_timeout(*wakeup);
    while (true) {
        const auto response = connection.drain_outbound_datagram(*wakeup);
        if (response.empty()) {
            break;
        }
        total_sent += response.size();
    }

    EXPECT_LE(total_sent, initial_packet_bytes.size() * 3u);
}

TEST(QuicCoreTest, DuplicatePicoquicClientInitialRetransmitsHandshakeFlight) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));
    ASSERT_FALSE(connection.has_failed());

    auto first_responses = std::vector<std::vector<std::byte>>{};
    while (true) {
        const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
        if (response.empty()) {
            break;
        }
        first_responses.push_back(response);
    }
    ASSERT_FALSE(first_responses.empty());
    const auto first_handshake_packet_count = tracked_packet_count(connection.handshake_space_);
    ASSERT_GT(first_handshake_packet_count, 0u);
    const auto first_handshake_next_packet_number =
        connection.handshake_space_.next_send_packet_number;

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(2));
    ASSERT_FALSE(connection.has_failed());

    auto second_responses = std::vector<std::vector<std::byte>>{};
    while (true) {
        const auto response = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
        if (response.empty()) {
            break;
        }
        second_responses.push_back(response);
    }
    ASSERT_FALSE(second_responses.empty());
    EXPECT_GT(tracked_packet_count(connection.handshake_space_), first_handshake_packet_count);
    EXPECT_GT(connection.handshake_space_.next_send_packet_number,
              first_handshake_next_packet_number);
}

TEST(QuicCoreTest, AntiAmplificationAccountingIgnoresZeroByteDatagrams) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 12;
    connection.anti_amplification_sent_bytes_ = 15;

    connection.note_inbound_datagram_bytes(0);
    connection.note_outbound_datagram_bytes(0);

    EXPECT_EQ(connection.anti_amplification_received_bytes_, 12u);
    EXPECT_EQ(connection.anti_amplification_sent_bytes_, 15u);
}

TEST(QuicCoreTest, FirstServerInitialCanBeBlockedByAmplificationLimit) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 10;
    connection.anti_amplification_sent_bytes_ = 0;
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 7,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_EQ(connection.initial_space_.next_send_packet_number, 0u);
}

TEST(QuicCoreTest, ProcessCapturedPicoquicClientInitialPacketEmitsInitialCrypto) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    const auto outbound = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(outbound.empty());
    ASSERT_NE(tracked_packet_count(connection.initial_space_), 0u);
    EXPECT_FALSE(first_tracked_packet(connection.initial_space_).crypto_ranges.empty());
}

TEST(QuicCoreTest, ProcessCapturedPicoquicClientInitialIgnoresTrailingDatagramPadding) {
    auto datagram = captured_picoquic_client_initial_datagram();

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.client_initial_destination_connection_id(),
              bytes_from_hex("5398e92f19c36598"));
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("825ff16a7a5d8b9f"));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresMalformedTrailingFragmentAfterValidPacket) {
    auto datagram = captured_picoquic_client_initial_datagram();
    datagram.resize(346);
    const auto trailing_fragment =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x01});
    datagram.insert(datagram.end(), trailing_fragment.begin(), trailing_fragment.end());

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.client_initial_destination_connection_id(),
              bytes_from_hex("5398e92f19c36598"));
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("825ff16a7a5d8b9f"));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresUndecryptableTrailingFragmentAfterValidPacket) {
    auto datagram = captured_picoquic_client_initial_datagram();
    datagram.resize(346);
    const auto trailing_fragment =
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x01, 0x00});
    datagram.insert(datagram.end(), trailing_fragment.begin(), trailing_fragment.end());

    auto config = coquic::quic::test::make_server_core_config();
    config.application_protocol = "hq-interop";
    coquic::quic::QuicConnection connection(std::move(config));
    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.client_initial_destination_connection_id(),
              bytes_from_hex("5398e92f19c36598"));
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_hex("825ff16a7a5d8b9f"));
    EXPECT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenTlsSyncValidationFails) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::connected;
    connection.client_initial_destination_connection_id_ = connection.config_.source_connection_id;
    connection.peer_source_connection_id_ = {std::byte{0xaa}};
    connection.application_space_.read_secret = make_test_traffic_secret();
    connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::server,
        .verify_peer = false,
        .server_name = "localhost",
        .identity = connection.config_.identity,
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                                          {std::byte{0x40}});

    const auto valid_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 0,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = std::nullopt,
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(valid_packet.has_value());
    connection.process_inbound_datagram(valid_packet.value(), coquic::quic::test::test_time());

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionTlsAndValidationHelpersCoverRemainingBranches) {
    coquic::quic::QuicConnection no_tls_validation(coquic::quic::test::make_client_core_config());
    EXPECT_TRUE(no_tls_validation.validate_peer_transport_parameters_if_ready().has_value());

    coquic::quic::QuicConnection no_tls_connection(coquic::quic::test::make_client_core_config());
    no_tls_connection.install_available_secrets();
    no_tls_connection.collect_pending_tls_bytes();
    EXPECT_FALSE(no_tls_connection.initial_space_.send_crypto.has_pending_data());
    EXPECT_FALSE(no_tls_connection.initial_space_.send_crypto.has_outstanding_data());

    coquic::quic::QuicConnection malformed_params_connection(
        coquic::quic::test::make_client_core_config());
    malformed_params_connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    malformed_params_connection.peer_source_connection_id_ = {std::byte{0x01}};
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *malformed_params_connection.tls_, {std::byte{0x40}});
    const auto malformed_params =
        malformed_params_connection.validate_peer_transport_parameters_if_ready();
    ASSERT_FALSE(malformed_params.has_value());
    EXPECT_EQ(malformed_params.error().code, coquic::quic::CodecErrorCode::truncated_input);
    const auto sync_failure = malformed_params_connection.sync_tls_state();
    ASSERT_FALSE(sync_failure.has_value());
    EXPECT_EQ(sync_failure.error().code, coquic::quic::CodecErrorCode::truncated_input);

    coquic::quic::QuicConnection missing_context_connection(
        coquic::quic::test::make_client_core_config());
    missing_context_connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *missing_context_connection.tls_, coquic::quic::test::sample_transport_parameters());
    EXPECT_TRUE(
        missing_context_connection.validate_peer_transport_parameters_if_ready().has_value());
    EXPECT_FALSE(missing_context_connection.peer_transport_parameters_validated_);

    coquic::quic::QuicConnection validation_failure_connection(
        coquic::quic::test::make_client_core_config());
    validation_failure_connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    validation_failure_connection.peer_source_connection_id_ = {std::byte{0x33}};
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *validation_failure_connection.tls_, coquic::quic::test::sample_transport_parameters());
    const auto validation_failure =
        validation_failure_connection.validate_peer_transport_parameters_if_ready();
    ASSERT_FALSE(validation_failure.has_value());
    EXPECT_EQ(validation_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    coquic::quic::QuicConnection preloaded_parameters_connection(
        coquic::quic::test::make_client_core_config());
    preloaded_parameters_connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    preloaded_parameters_connection.peer_source_connection_id_ = {std::byte{0x44}};
    preloaded_parameters_connection.client_initial_destination_connection_id_ =
        preloaded_parameters_connection.config_.initial_destination_connection_id;
    preloaded_parameters_connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .original_destination_connection_id =
            preloaded_parameters_connection.client_initial_destination_connection_id_,
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = preloaded_parameters_connection.peer_source_connection_id_,
    };
    preloaded_parameters_connection.decoded_resumption_state_ =
        coquic::quic::StoredClientResumptionState{
            .tls_state = {},
            .quic_version = coquic::quic::kQuicVersion1,
            .application_protocol = preloaded_parameters_connection.config_.application_protocol,
            .peer_transport_parameters =
                *preloaded_parameters_connection.peer_transport_parameters_,
            .application_context = {},
        };
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        *preloaded_parameters_connection.tls_, coquic::quic::test::sample_transport_parameters());
    EXPECT_TRUE(
        preloaded_parameters_connection.validate_peer_transport_parameters_if_ready().has_value());
    EXPECT_FALSE(preloaded_parameters_connection.peer_transport_parameters_validated_);

    coquic::quic::QuicConnection idle_connection(coquic::quic::test::make_client_core_config());
    idle_connection.update_handshake_status();
    EXPECT_EQ(idle_connection.status_, coquic::quic::HandshakeStatus::idle);

    coquic::quic::QuicConnection missing_tls_connection(
        coquic::quic::test::make_client_core_config());
    missing_tls_connection.started_ = true;
    missing_tls_connection.update_handshake_status();
    EXPECT_EQ(missing_tls_connection.status_, coquic::quic::HandshakeStatus::idle);

    coquic::quic::QuicConnection failed_connection(coquic::quic::test::make_client_core_config());
    failed_connection.status_ = coquic::quic::HandshakeStatus::failed;
    failed_connection.started_ = true;
    failed_connection.update_handshake_status();
    EXPECT_EQ(failed_connection.status_, coquic::quic::HandshakeStatus::failed);

    coquic::quic::QuicCore connected_client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore connected_server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(connected_client, connected_server,
                                             coquic::quic::test::test_time());
    auto &connected_tls = connected_client.connection_->tls_;
    if (!connected_tls.has_value()) {
        ADD_FAILURE() << "expected handshake to retain TLS state";
        return;
    }
    ASSERT_TRUE(connected_tls->handshake_complete());
    const auto read_secret = connected_client.connection_->application_space_.read_secret;
    const auto write_secret = connected_client.connection_->application_space_.write_secret;

    connected_client.connection_->status_ = coquic::quic::HandshakeStatus::in_progress;
    connected_client.connection_->peer_transport_parameters_validated_ = false;
    connected_client.connection_->update_handshake_status();
    EXPECT_EQ(connected_client.connection_->status_, coquic::quic::HandshakeStatus::in_progress);

    connected_client.connection_->peer_transport_parameters_validated_ = true;
    connected_client.connection_->application_space_.read_secret.reset();
    connected_client.connection_->update_handshake_status();
    EXPECT_EQ(connected_client.connection_->status_, coquic::quic::HandshakeStatus::in_progress);

    connected_client.connection_->application_space_.read_secret = read_secret;
    connected_client.connection_->application_space_.write_secret.reset();
    connected_client.connection_->update_handshake_status();
    EXPECT_EQ(connected_client.connection_->status_, coquic::quic::HandshakeStatus::in_progress);

    connected_client.connection_->application_space_.write_secret = write_secret;
}

TEST(QuicCoreTest, ServerHandshakeStatusUpdateDoesNotConfirmHandshakeEarly) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    auto &connection = *server.connection_;
    ASSERT_TRUE(connection.tls_.has_value());
    if (!connection.tls_.has_value()) {
        return;
    }

    ASSERT_TRUE(connection.tls_->handshake_complete());
    ASSERT_TRUE(connection.peer_transport_parameters_validated_);
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    ASSERT_TRUE(connection.application_space_.write_secret.has_value());

    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::none;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 9,
                                     .sent_time = coquic::quic::test::test_time(1),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                     .has_ping = true,
                                 });

    connection.update_handshake_status();

    EXPECT_EQ(connection.status_, coquic::quic::HandshakeStatus::connected);
    EXPECT_EQ(connection.handshake_done_state_, coquic::quic::StreamControlFrameState::pending);
    EXPECT_FALSE(connection.handshake_confirmed_);
    EXPECT_TRUE(connection.handshake_space_.read_secret.has_value());
    EXPECT_TRUE(connection.handshake_space_.write_secret.has_value());
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 1u);
}

TEST(QuicCoreTest, ClientHandshakeMarksEstablishedPathValidated) {
    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time());

    ASSERT_TRUE(client.connection_ != nullptr);
    ASSERT_EQ(client.connection_->status_, coquic::quic::HandshakeStatus::connected);
    ASSERT_TRUE(client.connection_->current_send_path_id_.has_value());

    const auto path_id = optional_value_or_terminate(client.connection_->current_send_path_id_);
    ASSERT_TRUE(client.connection_->paths_.contains(path_id));
    ASSERT_TRUE(client.connection_->last_validated_path_id_.has_value());
    EXPECT_TRUE(client.connection_->peer_address_validated_);
    EXPECT_TRUE(client.connection_->paths_.at(path_id).validated);
    EXPECT_EQ(optional_value_or_terminate(client.connection_->last_validated_path_id_), path_id);
}

TEST(QuicCoreTest, ValidatePeerTransportParametersWaitsForTlsBytesWhenNoneAreAvailable) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.start_client_if_needed();

    ASSERT_TRUE(connection.tls_.has_value());
    EXPECT_FALSE(connection.peer_transport_parameters_.has_value());
    EXPECT_TRUE(connection.validate_peer_transport_parameters_if_ready().has_value());
    EXPECT_FALSE(connection.peer_transport_parameters_validated_);
}

TEST(QuicCoreTest, ProcessInboundCryptoApplicationHandshakeDoneConfirmsHandshake) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_packet_space_discarded_ = false;
    connection.track_sent_packet(connection.handshake_space_,
                                 coquic::quic::SentPacketRecord{
                                     .packet_number = 1,
                                     .sent_time = coquic::quic::test::test_time(0),
                                     .ack_eliciting = true,
                                     .in_flight = true,
                                 });

    const auto processed =
        connection.process_inbound_crypto(coquic::quic::EncryptionLevel::application,
                                          std::array<coquic::quic::Frame, 1>{
                                              coquic::quic::HandshakeDoneFrame{},
                                          },
                                          coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(connection.handshake_confirmed_);
    EXPECT_TRUE(connection.handshake_packet_space_discarded_);
    EXPECT_EQ(tracked_packet_count(connection.handshake_space_), 0u);
}

TEST(QuicCoreTest, ConnectedApplicationControlFramesDoNotTripPreconnectedGuards) {
    const auto run_connected_frame = [](const coquic::quic::Frame &frame) {
        auto connection = make_connected_server_connection();
        const auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(1));
        EXPECT_TRUE(processed.has_value());
    };

    run_connected_frame(coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 7,
        .final_size = 0,
    });
    run_connected_frame(coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
    });
    run_connected_frame(coquic::quic::MaxDataFrame{.maximum_data = 4096});
    run_connected_frame(coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 2048,
    });
    run_connected_frame(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 4,
    });
    run_connected_frame(coquic::quic::DataBlockedFrame{.maximum_data = 0});
    run_connected_frame(coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 0,
    });
    run_connected_frame(coquic::quic::StreamsBlockedFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 1,
    });
}

TEST(QuicCoreTest, ValidatePeerTransportParametersUsesPreloadedParametersWhenTlsBytesAreAbsent) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();

    ASSERT_TRUE(connection.tls_.has_value());
    if (!connection.tls_.has_value()) {
        return;
    }
    auto &tls = connection.tls_.value();
    connection.peer_source_connection_id_ = {std::byte{0x44}};
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .original_destination_connection_id = connection.client_initial_destination_connection_id_,
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = connection.peer_source_connection_id_,
    };
    coquic::quic::test::TlsAdapterTestPeer::clear_peer_transport_parameters(tls);

    const auto validated = connection.validate_peer_transport_parameters_if_ready();

    ASSERT_TRUE(validated.has_value());
    EXPECT_TRUE(connection.peer_transport_parameters_validated_);
}

TEST(QuicCoreTest, ConnectedOnlyApplicationFramesFailBeforeHandshakeCompletes) {
    const auto run_in_progress_frame = [](const coquic::quic::Frame &frame) {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        const auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(1));
        ASSERT_FALSE(processed.has_value());
        EXPECT_EQ(processed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    };

    run_in_progress_frame(coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 7,
        .final_size = 0,
    });
    run_in_progress_frame(coquic::quic::StopSendingFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
    });
    run_in_progress_frame(coquic::quic::MaxDataFrame{.maximum_data = 4096});
    run_in_progress_frame(coquic::quic::MaxStreamDataFrame{
        .stream_id = 0,
        .maximum_stream_data = 2048,
    });
    run_in_progress_frame(coquic::quic::MaxStreamsFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 4,
    });
    run_in_progress_frame(coquic::quic::DataBlockedFrame{.maximum_data = 0});
    run_in_progress_frame(coquic::quic::StreamDataBlockedFrame{
        .stream_id = 0,
        .maximum_stream_data = 0,
    });
    run_in_progress_frame(coquic::quic::StreamsBlockedFrame{
        .stream_type = coquic::quic::StreamLimitType::bidirectional,
        .maximum_streams = 1,
    });
}

TEST(QuicCoreTest, FlushOutboundDatagramReturnsEmptyWhenNothingIsPending) {
    auto connection = make_connected_client_connection();
    connection.application_space_.pending_ack_deadline = std::nullopt;

    EXPECT_TRUE(connection.flush_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresDiscardablePacketLengthErrorsAfterStart) {
    auto connection = make_connected_client_connection();

    connection.process_inbound_datagram(bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01}),
                                        coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsForNonDiscardablePacketLengthErrorsAfterStart) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();
    ASSERT_TRUE(connection.started_);

    connection.process_inbound_datagram(bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x00}),
                                        coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresHandshakePacketsForDiscardedSpace) {
    auto connection = make_connected_client_connection();
    connection.handshake_packet_space_discarded_ = true;
    connection.handshake_space_.read_secret.reset();

    const auto datagram = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = coquic::quic::kQuicVersion1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = bytes_from_ints({0x11, 0x22}),
                .packet_number_length = 2,
                .packet_number = 1,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = make_test_traffic_secret(
                coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x23}),
        });
    ASSERT_TRUE(datagram.has_value());

    connection.process_inbound_datagram(datagram.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionFailureAndStateChangeGuardsAreEdgeTriggered) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());

    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);
    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_ready);
    EXPECT_EQ(connection.pending_state_changes_.size(), 1u);

    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_confirmed);
    connection.queue_state_change(coquic::quic::QuicCoreStateChange::handshake_confirmed);
    EXPECT_EQ(connection.pending_state_changes_.size(), 2u);

    connection.queue_state_change(coquic::quic::QuicCoreStateChange::failed);
    connection.queue_state_change(coquic::quic::QuicCoreStateChange::failed);
    EXPECT_EQ(connection.pending_state_changes_.size(), 3u);

    connection.mark_failed();
    const auto first_failure_events = connection.pending_state_changes_.size();
    connection.mark_failed();
    EXPECT_EQ(connection.pending_state_changes_.size(), first_failure_events);
}

TEST(QuicCoreTest, FlushOutboundDatagramMarksFailuresForSerializationErrors) {
    auto candidate_failure = make_connected_client_connection();
    ASSERT_TRUE(candidate_failure
                    .queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
                    .has_value());
    {
        const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
            coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);
        EXPECT_TRUE(
            candidate_failure.flush_outbound_datagram(coquic::quic::test::test_time()).empty());
    }
    EXPECT_TRUE(candidate_failure.has_failed());

    coquic::quic::QuicConnection final_failure(coquic::quic::test::make_client_core_config());
    final_failure.started_ = true;
    final_failure.status_ = coquic::quic::HandshakeStatus::in_progress;
    final_failure.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hs"));
    final_failure.handshake_space_.write_secret = make_test_traffic_secret();
    {
        const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
            coquic::quic::test::PacketCryptoFaultPoint::seal_length_guard);
        EXPECT_TRUE(
            final_failure.flush_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    }
    EXPECT_TRUE(final_failure.has_failed());

    coquic::quic::QuicConnection missing_handshake_secret(
        coquic::quic::test::make_client_core_config());
    missing_handshake_secret.started_ = true;
    missing_handshake_secret.status_ = coquic::quic::HandshakeStatus::in_progress;
    missing_handshake_secret.handshake_space_.send_crypto.append(
        coquic::quic::test::bytes_from_string("hs"));
    EXPECT_TRUE(
        missing_handshake_secret.flush_outbound_datagram(coquic::quic::test::test_time(2)).empty());
    EXPECT_TRUE(missing_handshake_secret.has_failed());

    auto missing_application_secret = make_connected_client_connection();
    missing_application_secret.application_space_.write_secret.reset();
    ASSERT_TRUE(missing_application_secret
                    .queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
                    .has_value());
    EXPECT_TRUE(missing_application_secret.flush_outbound_datagram(coquic::quic::test::test_time(3))
                    .empty());
    EXPECT_FALSE(missing_application_secret.has_failed());

    coquic::quic::QuicConnection padding_failure(coquic::quic::test::make_client_core_config());
    padding_failure.started_ = true;
    padding_failure.status_ = coquic::quic::HandshakeStatus::in_progress;
    padding_failure.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hi"));
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_length_guard, 2);
    EXPECT_TRUE(padding_failure.flush_outbound_datagram(coquic::quic::test::test_time(4)).empty());
    EXPECT_TRUE(padding_failure.has_failed());
}

TEST(QuicCoreTest, FlushOutboundDatagramReusesAcceptedApplicationCandidateSerialization) {
    auto connection = make_connected_client_connection();
    ASSERT_TRUE(
        connection.queue_stream_send(0, coquic::quic::test::bytes_from_string("hello"), false)
            .has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);
    const auto datagram = connection.flush_outbound_datagram(coquic::quic::test::test_time(5));

    EXPECT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, CoalescedInitialAndHandshakeCandidateSerializationFailureMarksConnectionFailed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.initial_space_.send_crypto.append(coquic::quic::test::bytes_from_string("init"));
    connection.handshake_space_.send_crypto.append(coquic::quic::test::bytes_from_string("hs"));
    connection.handshake_space_.write_secret = make_test_traffic_secret();
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_context_new);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, InitialTrimReserializationFailureMarksConnectionFailed) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.initial_space_.send_crypto.append(std::vector<std::byte>(1500, std::byte{0x5a}));
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, HandshakeTrimReserializationFailureMarksConnectionFailedAfterDroppingRange) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.anti_amplification_received_bytes_ = 400;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x64});
    connection.handshake_space_.send_crypto.append(std::vector<std::byte>(1400, std::byte{0x5b}));
    const auto sent_crypto = connection.handshake_space_.send_crypto.take_ranges(1400);
    ASSERT_EQ(sent_crypto.size(), 1u);
    connection.handshake_space_.send_crypto.mark_lost(0, 1300);
    connection.handshake_space_.send_crypto.mark_unsent(1350, 50);
    const coquic::quic::test::ScopedPacketCryptoFaultInjector injector(
        coquic::quic::test::PacketCryptoFaultPoint::seal_payload_update, 2);

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversRemainingValidationBranches) {
    auto flow_overflow = make_connected_client_connection();
    flow_overflow.connection_flow_control_.advertised_max_data = 0;
    const auto overflow = flow_overflow.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("x"),
        },
        coquic::quic::test::test_time());
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto buffer_failure = make_connected_client_connection();
    auto &buffer_stream = buffer_failure.streams_
                              .emplace(0, coquic::quic::make_implicit_stream_state(
                                              /*stream_id=*/0, buffer_failure.config_.role))
                              .first->second;
    buffer_failure.initialize_stream_flow_control(buffer_stream);
    buffer_stream.flow_control.advertised_max_stream_data =
        std::numeric_limits<std::uint64_t>::max();
    buffer_stream.receive_flow_control_limit = std::numeric_limits<std::uint64_t>::max();
    buffer_failure.connection_flow_control_.advertised_max_data =
        std::numeric_limits<std::uint64_t>::max();
    const auto contiguous_failure = buffer_failure.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("xy",
                                                                      (std::uint64_t{1} << 62) - 1),
        },
        coquic::quic::test::test_time(1));
    ASSERT_FALSE(contiguous_failure.has_value());
    EXPECT_EQ(contiguous_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicConnection gating(coquic::quic::test::make_client_core_config());
    gating.status_ = coquic::quic::HandshakeStatus::in_progress;
    for (const auto &frame : std::vector<coquic::quic::Frame>{
             coquic::quic::ResetStreamFrame{
                 .stream_id = 0,
                 .application_protocol_error_code = 1,
                 .final_size = 0,
             },
             coquic::quic::StopSendingFrame{
                 .stream_id = 0,
                 .application_protocol_error_code = 1,
             },
             coquic::quic::MaxDataFrame{.maximum_data = 1},
             coquic::quic::MaxStreamDataFrame{
                 .stream_id = 0,
                 .maximum_stream_data = 1,
             },
             coquic::quic::MaxStreamsFrame{
                 .stream_type = coquic::quic::StreamLimitType::bidirectional,
                 .maximum_streams = 1,
             },
             coquic::quic::DataBlockedFrame{.maximum_data = 1},
             coquic::quic::StreamDataBlockedFrame{
                 .stream_id = 0,
                 .maximum_stream_data = 1,
             },
             coquic::quic::StreamsBlockedFrame{
                 .stream_type = coquic::quic::StreamLimitType::bidirectional,
                 .maximum_streams = 1,
             },
         }) {
        const auto gated = gating.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(2));
        ASSERT_FALSE(gated.has_value());
        EXPECT_EQ(gated.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    }

    coquic::quic::QuicConnection preconnected_controls(
        coquic::quic::test::make_client_core_config());
    preconnected_controls.status_ = coquic::quic::HandshakeStatus::in_progress;
    for (const auto &frame : std::vector<coquic::quic::Frame>{
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
         }) {
        const auto accepted = preconnected_controls.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{frame}, coquic::quic::test::test_time(2));
        ASSERT_TRUE(accepted.has_value());
    }

    auto preconnected_retire_without_application_secret = make_connected_server_connection();
    preconnected_retire_without_application_secret.status_ =
        coquic::quic::HandshakeStatus::in_progress;
    preconnected_retire_without_application_secret.handshake_confirmed_ = false;
    preconnected_retire_without_application_secret.application_space_.read_secret.reset();
    const auto accepted_retire_without_application_secret =
        preconnected_retire_without_application_secret.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::RetireConnectionIdFrame{
                    .sequence_number = 1,
                },
            },
            coquic::quic::test::test_time(2));
    ASSERT_TRUE(accepted_retire_without_application_secret.has_value());

    auto preconnected_retire_allowed = make_connected_server_connection();
    preconnected_retire_allowed.status_ = coquic::quic::HandshakeStatus::in_progress;
    preconnected_retire_allowed.handshake_confirmed_ = false;
    preconnected_retire_allowed.issue_spare_connection_ids();
    const auto accepted_retire = preconnected_retire_allowed.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 1,
            },
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(accepted_retire.has_value());

    auto connected = make_connected_client_connection();
    connected.connection_flow_control_.advertised_max_data = 10;
    connected.connection_flow_control_.delivered_bytes = 10;
    connected.connection_flow_control_.local_receive_window = 4;
    auto &receive_stream = connected.streams_
                               .emplace(0, coquic::quic::make_implicit_stream_state(
                                               /*stream_id=*/0, connected.config_.role))
                               .first->second;
    connected.initialize_stream_flow_control(receive_stream);
    receive_stream.flow_control.advertised_max_stream_data = 9;
    receive_stream.flow_control.delivered_bytes = 9;
    receive_stream.flow_control.local_receive_window = 3;
    const auto connected_controls = connected.process_inbound_application(
        std::array<coquic::quic::Frame, 4>{
            coquic::quic::MaxStreamsFrame{
                .stream_type = coquic::quic::StreamLimitType::bidirectional,
                .maximum_streams = 32,
            },
            coquic::quic::DataBlockedFrame{.maximum_data = 10},
            coquic::quic::StreamDataBlockedFrame{
                .stream_id = 0,
                .maximum_stream_data = 9,
            },
            coquic::quic::StreamsBlockedFrame{
                .stream_type = coquic::quic::StreamLimitType::bidirectional,
                .maximum_streams = 32,
            },
        },
        coquic::quic::test::test_time(3));
    ASSERT_TRUE(connected_controls.has_value());
    EXPECT_EQ(connected.stream_open_limits_.peer_max_bidirectional, 32u);
    ASSERT_TRUE(connected.connection_flow_control_.pending_max_data_frame.has_value());
    if (connected.connection_flow_control_.pending_max_data_frame.has_value()) {
        EXPECT_EQ(connected.connection_flow_control_.pending_max_data_frame->maximum_data, 14u);
    }
    ASSERT_TRUE(receive_stream.flow_control.pending_max_stream_data_frame.has_value());
    if (receive_stream.flow_control.pending_max_stream_data_frame.has_value()) {
        EXPECT_EQ(receive_stream.flow_control.pending_max_stream_data_frame->maximum_stream_data,
                  12u);
    }

    auto invalid_max_stream_data = make_connected_client_connection();
    const auto max_stream_data_failure = invalid_max_stream_data.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::MaxStreamDataFrame{
                .stream_id = 3,
                .maximum_stream_data = 1,
            },
        },
        coquic::quic::test::test_time(4));
    ASSERT_FALSE(max_stream_data_failure.has_value());
    EXPECT_EQ(max_stream_data_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_stream_data_blocked = make_connected_client_connection();
    const auto stream_data_blocked_failure =
        invalid_stream_data_blocked.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::StreamDataBlockedFrame{
                    .stream_id = 2,
                    .maximum_stream_data = 1,
                },
            },
            coquic::quic::test::test_time(5));
    ASSERT_FALSE(stream_data_blocked_failure.has_value());
    EXPECT_EQ(stream_data_blocked_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_varint);

    auto reset_conflict = make_connected_client_connection();
    auto &conflict_stream = reset_conflict.streams_
                                .emplace(0, coquic::quic::make_implicit_stream_state(
                                                /*stream_id=*/0, reset_conflict.config_.role))
                                .first->second;
    reset_conflict.initialize_stream_flow_control(conflict_stream);
    conflict_stream.highest_received_offset = 6;
    const auto reset_failure = reset_conflict.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::ResetStreamFrame{
                .stream_id = 0,
                .application_protocol_error_code = 1,
                .final_size = 5,
            },
        },
        coquic::quic::test::test_time(6));
    ASSERT_FALSE(reset_failure.has_value());
    EXPECT_EQ(reset_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversOvercommitAndDuplicateFinBranches) {
    auto overcommitted = make_connected_client_connection();
    overcommitted.connection_flow_control_.advertised_max_data = 1;
    overcommitted.connection_flow_control_.received_committed = 2;
    const auto overcommit_failure = overcommitted.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::test::make_inbound_application_stream_frame("", 0, 1, true),
        },
        coquic::quic::test::test_time());
    ASSERT_FALSE(overcommit_failure.has_value());
    EXPECT_EQ(overcommit_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto duplicate_fin = make_connected_client_connection();
    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        duplicate_fin, {coquic::quic::test::make_inbound_application_stream_frame("", 0, 1, true)},
        /*packet_number=*/1));
    ASSERT_EQ(duplicate_fin.pending_stream_receive_effects_.size(), 1u);
    EXPECT_TRUE(duplicate_fin.pending_stream_receive_effects_.front().fin);

    duplicate_fin.pending_stream_receive_effects_.clear();
    ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
        duplicate_fin, {coquic::quic::test::make_inbound_application_stream_frame("", 0, 1, true)},
        /*packet_number=*/2));
    EXPECT_TRUE(duplicate_fin.pending_stream_receive_effects_.empty());
}

TEST(QuicCoreTest, ConnectionProcessInboundApplicationCoversApplicationCryptoBranches) {
    auto offset_overflow = make_connected_client_connection();
    const auto overflow = offset_overflow.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::CryptoFrame{
                .offset = (std::uint64_t{1} << 62) - 1,
                .crypto_data = bytes_from_ints({0x01, 0x02}),
            },
        },
        coquic::quic::test::test_time(1));
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicConnection missing_tls(coquic::quic::test::make_client_core_config());
    missing_tls.started_ = true;
    missing_tls.status_ = coquic::quic::HandshakeStatus::in_progress;
    const auto missing_tls_failure = missing_tls.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = bytes_from_ints({0x03}),
            },
        },
        coquic::quic::test::test_time(2));
    ASSERT_FALSE(missing_tls_failure.has_value());
    EXPECT_EQ(missing_tls_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    auto connected_without_tls = make_connected_client_connection();
    connected_without_tls.tls_.reset();
    const auto ignored_crypto = connected_without_tls.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = bytes_from_ints({0x04}),
            },
        },
        coquic::quic::test::test_time(3));
    ASSERT_TRUE(ignored_crypto.has_value());
    EXPECT_FALSE(connected_without_tls.has_failed());

    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time(4));
    ASSERT_NE(client.connection_, nullptr);
    auto &post_handshake = *client.connection_;
    ASSERT_TRUE(post_handshake.tls_.has_value());
    post_handshake.application_space_.receive_crypto = coquic::quic::ReliableReceiveBuffer{};
    const coquic::quic::test::ScopedTlsAdapterFaultInjector injector(
        coquic::quic::test::TlsAdapterFaultPoint::provide_post_handshake);
    const auto provide_failure = post_handshake.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::CryptoFrame{
                .offset = 0,
                .crypto_data = bytes_from_ints({0x05}),
            },
        },
        coquic::quic::test::test_time(5));
    ASSERT_FALSE(provide_failure.has_value());
    EXPECT_EQ(provide_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicCoreTest, ConnectionProcessInboundReceivedApplicationCoversValidationAndControlBranches) {
    const auto make_received_stream_frame = [](std::string_view text,
                                               std::optional<std::uint64_t> offset = 0,
                                               std::uint64_t stream_id = 0, bool fin = false) {
        return coquic::quic::ReceivedStreamFrame{
            .fin = fin,
            .has_offset = offset.has_value(),
            .has_length = true,
            .stream_id = stream_id,
            .offset = offset,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string(text)),
        };
    };
    const auto make_challenge_data = [](std::uint8_t fill) {
        std::array<std::byte, 8> data{};
        data.fill(static_cast<std::byte>(fill));
        return data;
    };
    const auto make_reset_token = [](std::uint8_t fill) {
        std::array<std::byte, 16> token{};
        token[0] = static_cast<std::byte>(fill);
        return token;
    };

    auto flow_overflow = make_connected_client_connection();
    flow_overflow.connection_flow_control_.advertised_max_data = 0;
    const auto overflow = flow_overflow.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_stream_frame("x")},
        coquic::quic::test::test_time(), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto overcommitted = make_connected_client_connection();
    overcommitted.connection_flow_control_.advertised_max_data = 1;
    overcommitted.connection_flow_control_.received_committed = 2;
    const auto overcommit_failure = overcommitted.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            make_received_stream_frame("", /*offset=*/0, /*stream_id=*/0, /*fin=*/true)},
        coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(overcommit_failure.has_value());
    EXPECT_EQ(overcommit_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto buffer_failure = make_connected_client_connection();
    auto &buffer_stream = buffer_failure.streams_
                              .emplace(0, coquic::quic::make_implicit_stream_state(
                                              /*stream_id=*/0, buffer_failure.config_.role))
                              .first->second;
    buffer_failure.initialize_stream_flow_control(buffer_stream);
    buffer_stream.flow_control.advertised_max_stream_data =
        std::numeric_limits<std::uint64_t>::max();
    buffer_stream.receive_flow_control_limit = std::numeric_limits<std::uint64_t>::max();
    buffer_failure.connection_flow_control_.advertised_max_data =
        std::numeric_limits<std::uint64_t>::max();
    const auto contiguous_failure = buffer_failure.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            make_received_stream_frame("xy", /*offset=*/(std::uint64_t{1} << 62) - 1)},
        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(contiguous_failure.has_value());
    EXPECT_EQ(contiguous_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto gated_path_validation_data = make_challenge_data(0x2a);
    const auto run_gated_frame = [&](const coquic::quic::ReceivedFrame &frame) {
        coquic::quic::QuicConnection gating(coquic::quic::test::make_client_core_config());
        gating.status_ = coquic::quic::HandshakeStatus::in_progress;
        const auto processed = gating.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{frame}, coquic::quic::test::test_time(3),
            /*allow_preconnected_frames=*/false, /*path_id=*/0);
        ASSERT_FALSE(processed.has_value());
        EXPECT_EQ(processed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    };
    for (const auto &frame : std::vector<coquic::quic::ReceivedFrame>{
             coquic::quic::ResetStreamFrame{
                 .stream_id = 0,
                 .application_protocol_error_code = 1,
                 .final_size = 0,
             },
             coquic::quic::StopSendingFrame{
                 .stream_id = 0,
                 .application_protocol_error_code = 1,
             },
             coquic::quic::MaxDataFrame{.maximum_data = 1},
             coquic::quic::MaxStreamDataFrame{
                 .stream_id = 0,
                 .maximum_stream_data = 1,
             },
             coquic::quic::MaxStreamsFrame{
                 .stream_type = coquic::quic::StreamLimitType::bidirectional,
                 .maximum_streams = 1,
             },
             coquic::quic::DataBlockedFrame{.maximum_data = 1},
             coquic::quic::StreamDataBlockedFrame{
                 .stream_id = 0,
                 .maximum_stream_data = 1,
             },
             coquic::quic::StreamsBlockedFrame{
                 .stream_type = coquic::quic::StreamLimitType::bidirectional,
                 .maximum_streams = 1,
             },
             coquic::quic::PingFrame{},
             coquic::quic::PathChallengeFrame{.data = gated_path_validation_data},
             coquic::quic::PathResponseFrame{.data = gated_path_validation_data},
             make_received_stream_frame("x"),
         }) {
        run_gated_frame(frame);
    }

    auto preconnected_controls = make_connected_client_connection();
    preconnected_controls.status_ = coquic::quic::HandshakeStatus::in_progress;
    preconnected_controls.handshake_confirmed_ = false;

    const auto preconnected_ping = preconnected_controls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{coquic::quic::PingFrame{}},
        coquic::quic::test::test_time(4), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_TRUE(preconnected_ping.has_value());

    const auto preconnected_stream = preconnected_controls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_stream_frame("late")},
        coquic::quic::test::test_time(5), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_TRUE(preconnected_stream.has_value());
    ASSERT_EQ(preconnected_controls.pending_stream_receive_effects_.size(), 1u);
    EXPECT_EQ(preconnected_controls.pending_stream_receive_effects_.front().bytes,
              coquic::quic::test::bytes_from_string("late"));

    const auto preconnected_path_data = make_challenge_data(0x6b);
    const auto preconnected_path_challenge =
        preconnected_controls.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{
                coquic::quic::PathChallengeFrame{.data = preconnected_path_data},
            },
            coquic::quic::test::test_time(6), /*allow_preconnected_frames=*/false, /*path_id=*/1);
    ASSERT_TRUE(preconnected_path_challenge.has_value());
    ASSERT_TRUE(preconnected_controls.paths_.contains(1));
    auto &pending_response_opt = preconnected_controls.paths_.at(1).pending_response;
    if (!pending_response_opt.has_value()) {
        FAIL() << "expected pending path response";
        return;
    }
    const auto &pending_response = *pending_response_opt;
    EXPECT_EQ(pending_response, preconnected_path_data);

    const auto preconnected_path_response =
        preconnected_controls.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{
                coquic::quic::PathResponseFrame{.data = preconnected_path_data},
            },
            coquic::quic::test::test_time(7), /*allow_preconnected_frames=*/false, /*path_id=*/1);
    ASSERT_TRUE(preconnected_path_response.has_value());

    auto connected = make_connected_client_connection();
    connected.connection_flow_control_.pending_data_blocked_frame =
        coquic::quic::DataBlockedFrame{.maximum_data = 0};
    connected.connection_flow_control_.data_blocked_state =
        coquic::quic::StreamControlFrameState::pending;
    connected.connection_flow_control_.advertised_max_data = 10;
    connected.connection_flow_control_.delivered_bytes = 10;
    connected.connection_flow_control_.local_receive_window = 4;
    auto &receive_stream = connected.streams_
                               .emplace(0, coquic::quic::make_implicit_stream_state(
                                               /*stream_id=*/0, connected.config_.role))
                               .first->second;
    connected.initialize_stream_flow_control(receive_stream);
    receive_stream.flow_control.advertised_max_stream_data = 9;
    receive_stream.flow_control.delivered_bytes = 9;
    receive_stream.flow_control.local_receive_window = 3;
    const auto connected_controls = connected.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::MaxDataFrame{.maximum_data = 10},
            coquic::quic::MaxStreamsFrame{
                .stream_type = coquic::quic::StreamLimitType::bidirectional,
                .maximum_streams = 32,
            },
            coquic::quic::DataBlockedFrame{.maximum_data = 10},
            coquic::quic::StreamDataBlockedFrame{
                .stream_id = 0,
                .maximum_stream_data = 9,
            },
            coquic::quic::StreamsBlockedFrame{
                .stream_type = coquic::quic::StreamLimitType::bidirectional,
                .maximum_streams = 32,
            },
        },
        coquic::quic::test::test_time(8), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_TRUE(connected_controls.has_value());
    EXPECT_EQ(connected.stream_open_limits_.peer_max_bidirectional, 32u);
    EXPECT_FALSE(connected.connection_flow_control_.pending_data_blocked_frame.has_value());
    EXPECT_EQ(connected.connection_flow_control_.data_blocked_state,
              coquic::quic::StreamControlFrameState::none);
    ASSERT_TRUE(connected.connection_flow_control_.pending_max_data_frame.has_value());
    if (connected.connection_flow_control_.pending_max_data_frame.has_value()) {
        EXPECT_EQ(connected.connection_flow_control_.pending_max_data_frame->maximum_data, 14u);
    }
    ASSERT_TRUE(receive_stream.flow_control.pending_max_stream_data_frame.has_value());
    if (receive_stream.flow_control.pending_max_stream_data_frame.has_value()) {
        EXPECT_EQ(receive_stream.flow_control.pending_max_stream_data_frame->maximum_stream_data,
                  12u);
    }

    auto invalid_reset_stream = make_connected_client_connection();
    const auto reset_open_failure = invalid_reset_stream.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::ResetStreamFrame{
                .stream_id = 2,
                .application_protocol_error_code = 1,
                .final_size = 0,
            },
        },
        coquic::quic::test::test_time(9), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(reset_open_failure.has_value());
    EXPECT_EQ(reset_open_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto reset_conflict = make_connected_client_connection();
    auto &conflict_stream = reset_conflict.streams_
                                .emplace(0, coquic::quic::make_implicit_stream_state(
                                                /*stream_id=*/0, reset_conflict.config_.role))
                                .first->second;
    reset_conflict.initialize_stream_flow_control(conflict_stream);
    conflict_stream.highest_received_offset = 6;
    const auto reset_failure = reset_conflict.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::ResetStreamFrame{
                .stream_id = 0,
                .application_protocol_error_code = 1,
                .final_size = 5,
            },
        },
        coquic::quic::test::test_time(10), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(reset_failure.has_value());
    EXPECT_EQ(reset_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_stop_sending = make_connected_client_connection();
    const auto stop_sending_failure = invalid_stop_sending.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::StopSendingFrame{
                .stream_id = 3,
                .application_protocol_error_code = 1,
            },
        },
        coquic::quic::test::test_time(11), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(stop_sending_failure.has_value());
    EXPECT_EQ(stop_sending_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_max_stream_data = make_connected_client_connection();
    const auto max_stream_data_failure =
        invalid_max_stream_data.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{
                coquic::quic::MaxStreamDataFrame{
                    .stream_id = 3,
                    .maximum_stream_data = 1,
                },
            },
            coquic::quic::test::test_time(12), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(max_stream_data_failure.has_value());
    EXPECT_EQ(max_stream_data_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_stream_data_blocked = make_connected_client_connection();
    const auto stream_data_blocked_failure =
        invalid_stream_data_blocked.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{
                coquic::quic::StreamDataBlockedFrame{
                    .stream_id = 2,
                    .maximum_stream_data = 1,
                },
            },
            coquic::quic::test::test_time(13), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(stream_data_blocked_failure.has_value());
    EXPECT_EQ(stream_data_blocked_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_varint);

    auto invalid_new_connection_id = make_connected_client_connection();
    const auto new_connection_id_failure =
        invalid_new_connection_id.process_inbound_received_application(
            std::vector<coquic::quic::ReceivedFrame>{
                coquic::quic::NewConnectionIdFrame{
                    .sequence_number = 1,
                    .retire_prior_to = 2,
                    .connection_id = bytes_from_ints({0x10, 0x11}),
                    .stateless_reset_token = make_reset_token(0x10),
                },
            },
            coquic::quic::test::test_time(14), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(new_connection_id_failure.has_value());
    EXPECT_EQ(new_connection_id_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest,
     ConnectionProcessInboundReceivedApplicationCoversCryptoTraceAndTerminalBranches) {
    const auto make_received_crypto_frame = [](std::initializer_list<std::uint8_t> bytes,
                                               std::uint64_t offset = 0) {
        return coquic::quic::ReceivedCryptoFrame{
            .offset = offset,
            .crypto_data = coquic::quic::SharedBytes(bytes_from_ints(bytes)),
        };
    };
    const auto make_received_stream_frame = [](std::string_view text,
                                               std::optional<std::uint64_t> offset = 0,
                                               std::uint64_t stream_id = 0, bool fin = false) {
        return coquic::quic::ReceivedStreamFrame{
            .fin = fin,
            .has_offset = offset.has_value(),
            .has_length = true,
            .stream_id = stream_id,
            .offset = offset,
            .stream_data = coquic::quic::SharedBytes(coquic::quic::test::bytes_from_string(text)),
        };
    };
    const auto make_challenge_data = [](std::uint8_t fill) {
        std::array<std::byte, 8> data{};
        data.fill(static_cast<std::byte>(fill));
        return data;
    };

    auto offset_overflow = make_connected_client_connection();
    const auto overflow = offset_overflow.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            make_received_crypto_frame({0x01, 0x02}, (std::uint64_t{1} << 62) - 1)},
        coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(overflow.has_value());
    EXPECT_EQ(overflow.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicConnection missing_tls(coquic::quic::test::make_client_core_config());
    missing_tls.started_ = true;
    missing_tls.status_ = coquic::quic::HandshakeStatus::in_progress;
    const auto missing_tls_failure = missing_tls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame({0x03})},
        coquic::quic::test::test_time(2), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(missing_tls_failure.has_value());
    EXPECT_EQ(missing_tls_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    auto connected_without_tls = make_connected_client_connection();
    connected_without_tls.tls_.reset();
    const auto ignored_crypto = connected_without_tls.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame({0x04})},
        coquic::quic::test::test_time(3), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_TRUE(ignored_crypto.has_value());
    EXPECT_FALSE(connected_without_tls.has_failed());

    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time(4));
    ASSERT_NE(client.connection_, nullptr);
    auto &post_handshake = *client.connection_;
    ASSERT_TRUE(post_handshake.tls_.has_value());
    post_handshake.application_space_.receive_crypto = coquic::quic::ReliableReceiveBuffer{};
    const coquic::quic::test::ScopedTlsAdapterFaultInjector injector(
        coquic::quic::test::TlsAdapterFaultPoint::provide_post_handshake);
    const auto provide_failure = post_handshake.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame({0x05})},
        coquic::quic::test::test_time(5), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(provide_failure.has_value());
    EXPECT_EQ(provide_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);

    auto traced = make_connected_server_connection();
    traced.current_send_path_id_ = 1;
    traced.previous_path_id_ = 0;
    traced.last_validated_path_id_ = 0;
    auto &current_path = traced.ensure_path_state(1);
    current_path.validated = false;
    current_path.is_current_send_path = true;
    const auto challenge_data = make_challenge_data(0x44);
    auto &inbound_path = traced.ensure_path_state(2);
    inbound_path.validated = true;
    inbound_path.outstanding_challenge = challenge_data;
    inbound_path.challenge_pending = true;
    inbound_path.validation_deadline = coquic::quic::test::test_time(10);

    testing::internal::CaptureStderr();
    const ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");
    const auto traced_result = traced.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::PathResponseFrame{.data = challenge_data},
            make_received_stream_frame("x"),
        },
        coquic::quic::test::test_time(6), /*allow_preconnected_frames=*/false, /*path_id=*/2);
    const auto stderr_output = testing::internal::GetCapturedStderr();
    ASSERT_TRUE(traced_result.has_value());
    if (!traced.current_send_path_id_.has_value()) {
        FAIL() << "expected current send path id";
        return;
    }
    EXPECT_EQ(*traced.current_send_path_id_, 2u);
    if (!traced.last_validated_path_id_.has_value()) {
        FAIL() << "expected validated path id";
        return;
    }
    EXPECT_EQ(*traced.last_validated_path_id_, 2u);
    EXPECT_FALSE(traced.paths_.at(2).outstanding_challenge.has_value());
    ASSERT_EQ(traced.pending_stream_receive_effects_.size(), 1u);
    EXPECT_EQ(traced.pending_stream_receive_effects_.front().bytes,
              coquic::quic::test::bytes_from_string("x"));
    EXPECT_NE(stderr_output.find("quic-packet-trace recv-app scid="), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace path-response scid="), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace stream scid="), std::string::npos);

    auto server_new_token = make_connected_server_connection();
    const auto new_token_result = server_new_token.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::NewTokenFrame{
                .token = bytes_from_ints({0xaa, 0xbb}),
            },
        },
        coquic::quic::test::test_time(7), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(new_token_result.has_value());
    EXPECT_EQ(new_token_result.error().code,
              coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);

    auto closing = make_connected_client_connection();
    const auto close_result = closing.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::ApplicationConnectionCloseFrame{
                .error_code = 1,
                .reason =
                    {
                        .bytes = coquic::quic::test::bytes_from_string("bye"),
                    },
            },
        },
        coquic::quic::test::test_time(8), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_TRUE(close_result.has_value());
    EXPECT_TRUE(closing.has_failed());
    if (!closing.pending_terminal_state_.has_value()) {
        FAIL() << "expected pending terminal state after app close";
        return;
    }
    EXPECT_EQ(*closing.pending_terminal_state_, coquic::quic::QuicConnectionTerminalState::closed);

    auto handshake_done = make_connected_server_connection();
    handshake_done.handshake_confirmed_ = false;
    handshake_done.handshake_packet_space_discarded_ = false;
    const auto handshake_done_result = handshake_done.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{coquic::quic::HandshakeDoneFrame{}},
        coquic::quic::test::test_time(9), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_TRUE(handshake_done_result.has_value());
    EXPECT_TRUE(handshake_done.handshake_confirmed_);
    EXPECT_TRUE(handshake_done.handshake_packet_space_discarded_);

    auto invalid_retire = make_connected_client_connection();
    const auto retire_failure = invalid_retire.process_inbound_received_application(
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 99,
            },
        },
        coquic::quic::test::test_time(10), /*allow_preconnected_frames=*/false, /*path_id=*/0);
    ASSERT_FALSE(retire_failure.has_value());
    EXPECT_EQ(retire_failure.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, ReceivedInitialPacketResetsClientHandshakePeerStateOnSourceConnectionIdChange) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_source_connection_id_ = bytes_from_ints({0x01});
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .initial_source_connection_id = bytes_from_ints({0xaa}),
    };
    connection.peer_transport_parameters_validated_ = true;
    connection.peer_connection_ids_[7] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 7,
        .connection_id = bytes_from_ints({0x07}),
    };
    connection.active_peer_connection_id_sequence_ = 7;
    connection.deferred_protected_packets_.push_back(
        coquic::quic::DeferredProtectedPacket(bytes_from_ints({0xee})));
    connection.initial_space_.received_packets.record_received(
        4, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    connection.handshake_space_.received_packets.record_received(
        5, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    connection.zero_rtt_space_.received_packets.record_received(
        6, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    const auto new_source_connection_id = bytes_from_ints({0x02, 0x03});

    const auto processed = connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = new_source_connection_id,
            .packet_number_length = 1,
            .packet_number = 1,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PaddingFrame{.length = 1}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(processed.value());
    EXPECT_EQ(optional_value_or_terminate(connection.peer_source_connection_id_),
              new_source_connection_id);
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
    EXPECT_FALSE(connection.peer_transport_parameters_.has_value());
    EXPECT_FALSE(connection.peer_transport_parameters_validated_);
    EXPECT_EQ(connection.active_peer_connection_id_sequence_, 0u);
    ASSERT_EQ(connection.peer_connection_ids_.size(), 1u);
    EXPECT_EQ(connection.peer_connection_ids_.at(0).connection_id, new_source_connection_id);
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.zero_rtt_space_.received_packets.has_ack_to_send());
}

TEST(
    QuicCoreTest,
    ReceivedHandshakePacketAdoptsVersionAndResetsClientHandshakePeerStateOnSourceConnectionIdChange) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.current_version_ = coquic::quic::kQuicVersion1;
    connection.peer_source_connection_id_ = bytes_from_ints({0x01});
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .initial_source_connection_id = bytes_from_ints({0xbb}),
    };
    connection.peer_transport_parameters_validated_ = true;
    connection.peer_connection_ids_[9] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 9,
        .connection_id = bytes_from_ints({0x09}),
    };
    connection.active_peer_connection_id_sequence_ = 9;
    connection.deferred_protected_packets_.push_back(
        coquic::quic::DeferredProtectedPacket(bytes_from_ints({0xef})));
    connection.initial_space_.received_packets.record_received(
        7, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    connection.handshake_space_.received_packets.record_received(
        8, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    connection.zero_rtt_space_.received_packets.record_received(
        9, true, coquic::quic::test::test_time(0), coquic::quic::QuicEcnCodepoint::unavailable);
    const auto new_source_connection_id = bytes_from_ints({0x04, 0x05});

    const auto processed = connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion2,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = new_source_connection_id,
            .packet_number_length = 1,
            .packet_number = 2,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames = {coquic::quic::PaddingFrame{.length = 1}},
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(processed.value());
    EXPECT_EQ(connection.current_version_, coquic::quic::kQuicVersion2);
    EXPECT_EQ(optional_value_or_terminate(connection.peer_source_connection_id_),
              new_source_connection_id);
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
    EXPECT_FALSE(connection.peer_transport_parameters_.has_value());
    EXPECT_FALSE(connection.peer_transport_parameters_validated_);
    EXPECT_EQ(connection.active_peer_connection_id_sequence_, 0u);
    ASSERT_EQ(connection.peer_connection_ids_.size(), 1u);
    EXPECT_EQ(connection.peer_connection_ids_.at(0).connection_id, new_source_connection_id);
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.handshake_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.zero_rtt_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ReceivedInitialPacketRejectsInvalidCryptoFrameAndDoesNotRecordPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);

    const auto processed = connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x01}),
            .packet_number_length = 1,
            .packet_number = 1,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames =
                {
                    coquic::quic::MaxDataFrame{.maximum_data = 1},
                },
        },
        coquic::quic::test::test_time(5));

    ASSERT_FALSE(processed.has_value());
    EXPECT_EQ(processed.error().code,
              coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
    EXPECT_FALSE(connection.processed_peer_packet_);
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest,
     ReceivedInitialAckOnlyPacketDuringClientHandshakeKeepaliveDoesNotRefreshPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(4000);

    const auto processed = connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedInitialPacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x02}),
            .packet_number_length = 1,
            .packet_number = 1,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames =
                {
                    coquic::quic::ReceivedAckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                        .additional_ranges_validated = true,
                    },
                },
        },
        coquic::quic::test::test_time(4100));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    EXPECT_FALSE(connection.initial_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest,
     ReceivedHandshakeAckOnlyPacketDuringClientHandshakeKeepaliveDoesNotRefreshPeerActivity) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.last_peer_activity_time_ = coquic::quic::test::test_time(4);
    connection.last_client_handshake_keepalive_probe_time_ = coquic::quic::test::test_time(4000);

    const auto processed = connection.process_inbound_received_packet(
        coquic::quic::ReceivedProtectedHandshakePacket{
            .version = coquic::quic::kQuicVersion1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = bytes_from_ints({0x03}),
            .packet_number_length = 1,
            .packet_number = 1,
            .plaintext_storage = std::make_shared<std::vector<std::byte>>(),
            .frames =
                {
                    coquic::quic::ReceivedAckFrame{
                        .largest_acknowledged = 0,
                        .first_ack_range = 0,
                        .additional_ranges_validated = true,
                    },
                },
        },
        coquic::quic::test::test_time(4100));

    ASSERT_TRUE(processed.has_value());
    EXPECT_EQ(connection.last_peer_activity_time_, std::optional{coquic::quic::test::test_time(4)});
    EXPECT_FALSE(connection.handshake_space_.pending_ack_deadline.has_value());
}

TEST(QuicCoreTest, ProcessInboundReceivedCryptoCoversControlAndErrorBranches) {
    const auto make_received_crypto_frame = [](std::initializer_list<std::uint8_t> bytes,
                                               std::uint64_t offset = 0) {
        return coquic::quic::ReceivedCryptoFrame{
            .offset = offset,
            .crypto_data = coquic::quic::SharedBytes(bytes_from_ints(bytes)),
        };
    };

    auto closing = make_connected_client_connection();
    const auto close_result =
        closing.process_inbound_received_crypto(coquic::quic::EncryptionLevel::application,
                                                std::vector<coquic::quic::ReceivedFrame>{
                                                    coquic::quic::TransportConnectionCloseFrame{
                                                        .error_code = 0,
                                                        .frame_type = 0,
                                                    },
                                                },
                                                coquic::quic::test::test_time(1));
    ASSERT_TRUE(close_result.has_value());
    EXPECT_TRUE(closing.has_failed());
    if (!closing.pending_terminal_state_.has_value()) {
        FAIL() << "expected pending terminal state after crypto close";
        return;
    }
    EXPECT_EQ(*closing.pending_terminal_state_, coquic::quic::QuicConnectionTerminalState::closed);

    auto handshake_done = make_connected_server_connection();
    handshake_done.handshake_confirmed_ = false;
    handshake_done.handshake_packet_space_discarded_ = false;
    const auto handshake_done_result = handshake_done.process_inbound_received_crypto(
        coquic::quic::EncryptionLevel::application,
        std::vector<coquic::quic::ReceivedFrame>{coquic::quic::HandshakeDoneFrame{}},
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(handshake_done_result.has_value());
    EXPECT_TRUE(handshake_done.handshake_confirmed_);
    EXPECT_TRUE(handshake_done.handshake_packet_space_discarded_);

    auto invalid_frame = make_connected_client_connection();
    const auto invalid_frame_result = invalid_frame.process_inbound_received_crypto(
        coquic::quic::EncryptionLevel::initial,
        std::vector<coquic::quic::ReceivedFrame>{
            coquic::quic::MaxDataFrame{.maximum_data = 1},
        },
        coquic::quic::test::test_time(3));
    ASSERT_FALSE(invalid_frame_result.has_value());
    EXPECT_EQ(invalid_frame_result.error().code,
              coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);

    auto overflow = make_connected_client_connection();
    const auto overflow_result = overflow.process_inbound_received_crypto(
        coquic::quic::EncryptionLevel::application,
        std::vector<coquic::quic::ReceivedFrame>{
            make_received_crypto_frame({0x01, 0x02}, (std::uint64_t{1} << 62) - 1)},
        coquic::quic::test::test_time(4));
    ASSERT_FALSE(overflow_result.has_value());
    EXPECT_EQ(overflow_result.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    coquic::quic::QuicCore client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicCore server(coquic::quic::test::make_server_core_config());
    coquic::quic::test::drive_quic_handshake(client, server, coquic::quic::test::test_time(5));
    ASSERT_NE(client.connection_, nullptr);
    auto &post_handshake = *client.connection_;
    ASSERT_TRUE(post_handshake.tls_.has_value());
    post_handshake.application_space_.receive_crypto = coquic::quic::ReliableReceiveBuffer{};
    const coquic::quic::test::ScopedTlsAdapterFaultInjector injector(
        coquic::quic::test::TlsAdapterFaultPoint::provide_post_handshake);
    const auto provide_failure = post_handshake.process_inbound_received_crypto(
        coquic::quic::EncryptionLevel::application,
        std::vector<coquic::quic::ReceivedFrame>{make_received_crypto_frame({0x05})},
        coquic::quic::test::test_time(6));
    ASSERT_FALSE(provide_failure.has_value());
    EXPECT_EQ(provide_failure.error().code,
              coquic::quic::CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicCoreTest, ServerRejectsNewTokenFrameInApplicationSpace) {
    auto connection = make_connected_server_connection();

    const auto result = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::NewTokenFrame{
                .token = bytes_from_ints({0xaa, 0xbb}),
            },
        },
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::CodecErrorCode::frame_not_allowed_in_packet_type);
}

TEST(QuicCoreTest, ProcessInboundAckAcceptsAdditionalRangesAndLeavesMalformedRangesUnacknowledged) {
    const auto seed_declared_lost_packet = [](coquic::quic::PacketSpaceState &packet_space,
                                              std::uint64_t packet_number) {
        packet_space.recovery.on_packet_sent(coquic::quic::SentPacketRecord{
            .packet_number = packet_number,
            .sent_time = coquic::quic::test::test_time(0),
            .ack_eliciting = true,
            .in_flight = false,
            .declared_lost = true,
            .has_ping = true,
            .bytes_in_flight = 0,
        });
        packet_space.recovery.on_packet_declared_lost(packet_number);
    };

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 2);
        seed_declared_lost_packet(connection.application_space_, 5);
        seed_declared_lost_packet(connection.application_space_, 8);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 5,
                                                               .first_ack_range = 0,
                                                               .additional_ranges =
                                                                   {
                                                                       coquic::quic::AckRange{
                                                                           .gap = 1,
                                                                           .range_length = 0,
                                                                       },
                                                                   },
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(connection.application_space_.recovery.find_packet(2), nullptr);
        EXPECT_EQ(connection.application_space_.recovery.find_packet(5), nullptr);
        EXPECT_NE(connection.application_space_.recovery.find_packet(8), nullptr);
        EXPECT_EQ(tracked_packet_or_null(connection.application_space_, 2), nullptr);
        EXPECT_EQ(tracked_packet_or_null(connection.application_space_, 5), nullptr);
        const auto *lost_packet = tracked_packet_or_null(connection.application_space_, 8);
        ASSERT_NE(lost_packet, nullptr);
        EXPECT_TRUE(lost_packet->declared_lost);
        EXPECT_FALSE(lost_packet->in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 1);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 0,
                                                               .first_ack_range = 1,
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_NE(connection.application_space_.recovery.find_packet(1), nullptr);
        const auto &lost_packet = tracked_packet_or_terminate(connection.application_space_, 1);
        EXPECT_TRUE(lost_packet.declared_lost);
        EXPECT_FALSE(lost_packet.in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 0);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 1,
                                                               .first_ack_range = 0,
                                                               .additional_ranges =
                                                                   {
                                                                       coquic::quic::AckRange{
                                                                           .gap = 0,
                                                                           .range_length = 0,
                                                                       },
                                                                   },
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_NE(connection.application_space_.recovery.find_packet(0), nullptr);
        const auto &lost_packet = tracked_packet_or_terminate(connection.application_space_, 0);
        EXPECT_TRUE(lost_packet.declared_lost);
        EXPECT_FALSE(lost_packet.in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 0);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 3,
                                                               .first_ack_range = 0,
                                                               .additional_ranges =
                                                                   {
                                                                       coquic::quic::AckRange{
                                                                           .gap = 0,
                                                                           .range_length = 2,
                                                                       },
                                                                   },
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_NE(connection.application_space_.recovery.find_packet(0), nullptr);
        const auto &lost_packet = tracked_packet_or_terminate(connection.application_space_, 0);
        EXPECT_TRUE(lost_packet.declared_lost);
        EXPECT_FALSE(lost_packet.in_flight);
    }

    {
        auto connection = make_connected_client_connection();
        seed_declared_lost_packet(connection.application_space_, 0);

        const auto result = connection.process_inbound_ack(connection.application_space_,
                                                           coquic::quic::AckFrame{
                                                               .largest_acknowledged = 0,
                                                               .first_ack_range = 1,
                                                           },
                                                           coquic::quic::test::test_time(1),
                                                           /*ack_delay_exponent=*/0,
                                                           /*max_ack_delay_ms=*/0,
                                                           /*suppress_pto_reset=*/false);
        ASSERT_TRUE(result.has_value());
        EXPECT_NE(connection.application_space_.recovery.find_packet(0), nullptr);
        const auto &lost_packet = tracked_packet_or_terminate(connection.application_space_, 0);
        EXPECT_TRUE(lost_packet.declared_lost);
        EXPECT_FALSE(lost_packet.in_flight);
    }
}

TEST(QuicCoreTest, ProcessInboundDatagramKeepsDeferredShortHeaderPacketsBufferedUntilConnected) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    const auto deferred_packet = bytes_from_ints({0x40, 0x01, 0x02, 0x03, 0x04});
    connection.deferred_protected_packets_.push_back(deferred_packet);

    connection.process_inbound_datagram(deferred_packet, coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), deferred_packet);
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramDeduplicatesAndEvictsDeferredProtectedPackets) {
    const auto make_deferred_packet = [](coquic::quic::QuicConnection &connection,
                                         std::uint64_t packet_number) {
        const auto encoded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = packet_number,
                    .frames =
                        {
                            coquic::quic::MaxDataFrame{
                                .maximum_data = 1,
                            },
                        },
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
            });
        EXPECT_TRUE(encoded.has_value());
        if (!encoded.has_value()) {
            return std::vector<std::byte>{};
        }
        return encoded.value();
    };

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.application_space_.read_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
        connection.application_space_.write_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});

        const auto deferred_packet = make_deferred_packet(connection, 1);
        connection.deferred_protected_packets_.push_back(deferred_packet);

        connection.process_inbound_datagram(deferred_packet, coquic::quic::test::test_time(1));

        ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
        EXPECT_EQ(connection.deferred_protected_packets_.front(), deferred_packet);
    }

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::in_progress;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.application_space_.read_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
        connection.application_space_.write_secret = make_test_traffic_secret(
            coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});

        for (std::uint8_t index = 0; index < 32; ++index) {
            connection.deferred_protected_packets_.push_back(
                bytes_from_ints({static_cast<std::uint8_t>(0x40u + index),
                                 static_cast<std::uint8_t>(0x80u + index), index}));
        }

        const auto evicted_packet = connection.deferred_protected_packets_.front();
        const auto deferred_packet = make_deferred_packet(connection, 9);

        connection.process_inbound_datagram(deferred_packet, coquic::quic::test::test_time(1));

        ASSERT_EQ(connection.deferred_protected_packets_.size(), 32u);
        EXPECT_NE(connection.deferred_protected_packets_.front(), evicted_packet);
        EXPECT_NE(std::find(connection.deferred_protected_packets_.begin(),
                            connection.deferred_protected_packets_.end(), deferred_packet),
                  connection.deferred_protected_packets_.end());
    }
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenDeferredReplayPacketFailsProcessing) {
    auto connection = make_connected_client_connection();
    connection.deferred_protected_packets_.push_back(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00}));

    connection.process_inbound_datagram(bytes_from_ints({0x01}), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, DrainOutboundDatagramReplaysDeferredProtectedPacketsBeforeFlush) {
    auto connection = make_connected_client_connection();
    const auto deferred_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 7,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(deferred_packet.has_value());
    if (!deferred_packet.has_value()) {
        return;
    }
    connection.deferred_protected_packets_.push_back(deferred_packet.value());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 7u);
    if (datagram.empty()) {
        const auto ack_deadline = connection.next_wakeup();
        ASSERT_TRUE(ack_deadline.has_value());
        datagram = connection.drain_outbound_datagram(optional_value_or_terminate(ack_deadline));
    }
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    for (const auto &frame : application->frames) {
        if (const auto *ack = std::get_if<coquic::quic::AckFrame>(&frame)) {
            saw_ack = true;
            EXPECT_EQ(ack->largest_acknowledged, 7u);
        }
    }
    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, DrainOutboundDatagramFailsWhenDeferredReplayFails) {
    auto connection = make_connected_client_connection();
    connection.deferred_protected_packets_.push_back(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00}));

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
    EXPECT_TRUE(connection.deferred_protected_packets_.empty());
}

TEST(QuicCoreTest, DrainOutboundDatagramFailsWhenSyncTlsStateFails) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.tls_.emplace(coquic::quic::TlsAdapterConfig{
        .role = coquic::quic::EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    });
    connection.peer_source_connection_id_ = {std::byte{0x01}};
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(*connection.tls_,
                                                                          {std::byte{0x40}});

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, DrainOutboundDatagramReturnsEmptyWhenNothingIsPending) {
    auto connection = make_connected_client_connection();

    EXPECT_TRUE(connection.drain_outbound_datagram(coquic::quic::test::test_time(1)).empty());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, PacketTargetsDiscardedLongHeaderSpaceCoversEdgeCases) {
    auto connection = make_connected_client_connection();

    EXPECT_FALSE(connection.packet_targets_discarded_long_header_space(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00})));
    EXPECT_FALSE(connection.packet_targets_discarded_long_header_space(bytes_from_ints({0x40})));

    connection.initial_packet_space_discarded_ = true;
    EXPECT_TRUE(connection.packet_targets_discarded_long_header_space(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01})));

    connection.handshake_packet_space_discarded_ = true;
    EXPECT_TRUE(connection.packet_targets_discarded_long_header_space(
        bytes_from_ints({0xe0, 0x00, 0x00, 0x00, 0x01})));

    EXPECT_FALSE(connection.packet_targets_discarded_long_header_space(
        bytes_from_ints({0xd0, 0x00, 0x00, 0x00, 0x01})));
}

TEST(QuicCoreTest, ProcessInboundApplicationRejectsPingBeforeConnectionCompletes) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto result = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{coquic::quic::PingFrame{}},
        coquic::quic::test::test_time(1));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, coquic::quic::CodecErrorCode::invalid_varint);
}

TEST(QuicCoreTest, UnvalidatedMigratedPathIsAntiAmplificationLimited) {
    auto connection = make_connected_server_connection();
    connection.current_send_path_id_ = 9;
    connection.ensure_path_state(9).anti_amplification_received_bytes = 40;
    connection.ensure_path_state(9).anti_amplification_sent_bytes = 120;

    EXPECT_EQ(connection.outbound_datagram_size_limit(), 0u);
}

TEST(QuicCoreTest, PeerPreferredAddressProducesCoreEffectOnceValidated) {
    auto connection = make_connected_client_connection();
    connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
        .max_udp_payload_size = 1200,
        .active_connection_id_limit = 8,
        .initial_source_connection_id = bytes_from_ints({0xaa}),
        .preferred_address =
            coquic::quic::PreferredAddress{
                .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
                .ipv4_port = 4444,
                .connection_id = bytes_from_ints({0x41, 0x42, 0x43, 0x44}),
            },
    };
    connection.peer_transport_parameters_validated_ = true;

    connection.sync_tls_state();

    ASSERT_TRUE(connection.pending_preferred_address_effect_.has_value());
    EXPECT_EQ(optional_ref_or_terminate(connection.pending_preferred_address_effect_)
                  .preferred_address.ipv4_port,
              4444);
}

TEST(QuicCoreTest,
     ProcessInboundDatagramDiscardsCorruptedShortHeaderPacketWithoutFailingConnection) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 79,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 0,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::open_set_tag);
    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest,
     ProcessInboundDatagramDiscardsShortHeaderPacketLengthMismatchWithoutFailingConnection) {
    auto connection = make_connected_server_connection();

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 79,
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
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    {
        const coquic::quic::test::ScopedProtectedCodecFaultInjector fault(
            coquic::quic::test::ProtectedCodecFaultPoint::
                remove_short_header_packet_length_mismatch);
        connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));
    }

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
    EXPECT_FALSE(connection.take_received_stream_data().has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(2));

    ASSERT_FALSE(connection.has_failed());
    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    if (!received.has_value()) {
        return;
    }

    const auto &received_value = optional_ref_or_terminate(received);
    EXPECT_EQ(received_value.stream_id, 0u);
    EXPECT_EQ(received_value.bytes, coquic::quic::test::bytes_from_string("GET /\r\n"));
    EXPECT_TRUE(received_value.fin);
}

TEST(QuicCoreTest, ProcessInboundAckMalformedRangesDoNotMutateOutstandingInFlightRecoveryState) {
    auto connection = make_connected_client_connection();
    const auto seed_outstanding_packet = [](coquic::quic::PacketSpaceState &packet_space,
                                            std::uint64_t packet_number,
                                            coquic::quic::QuicCoreTimePoint sent_time) {
        packet_space.recovery.on_packet_sent(coquic::quic::SentPacketRecord{
            .packet_number = packet_number,
            .sent_time = sent_time,
            .ack_eliciting = true,
            .in_flight = true,
            .has_ping = true,
            .bytes_in_flight = 1200,
        });
    };

    seed_outstanding_packet(connection.application_space_, 0, coquic::quic::test::test_time(0));
    seed_outstanding_packet(connection.application_space_, 1, coquic::quic::test::test_time(1));
    seed_outstanding_packet(connection.application_space_, 2, coquic::quic::test::test_time(2));

    EXPECT_EQ(connection.application_space_.recovery.tracked_packet_count(), 3u);
    EXPECT_FALSE(connection.application_space_.recovery.largest_acked_packet_number().has_value());

    const auto result = connection.process_inbound_ack(connection.application_space_,
                                                       coquic::quic::AckFrame{
                                                           .largest_acknowledged = 4,
                                                           .first_ack_range = 5,
                                                       },
                                                       coquic::quic::test::test_time(30),
                                                       /*ack_delay_exponent=*/0,
                                                       /*max_ack_delay_ms=*/0,
                                                       /*suppress_pto_reset=*/false);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(connection.application_space_.recovery.tracked_packet_count(), 3u);
    EXPECT_FALSE(connection.application_space_.recovery.largest_acked_packet_number().has_value());
    for (const auto packet_number : std::array<std::uint64_t, 3>{0, 1, 2}) {
        EXPECT_NE(connection.application_space_.recovery.find_packet(packet_number), nullptr);
        const auto &packet =
            tracked_packet_or_terminate(connection.application_space_, packet_number);
        EXPECT_TRUE(packet.in_flight);
        EXPECT_FALSE(packet.declared_lost);
    }
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenSyncTlsStateFailsAfterValidPacket) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();
    ASSERT_TRUE(connection.tls_.has_value());
    auto &tls = optional_ref_or_terminate(connection.tls_);
    connection.peer_transport_parameters_.reset();
    connection.peer_transport_parameters_validated_ = false;
    ASSERT_FALSE(connection.peer_source_connection_id_.has_value());
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        tls, coquic::quic::test::sample_transport_parameters());

    const auto handshake_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.handshake_space_.read_secret = handshake_secret;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 78,
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
            .handshake_secret = handshake_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresLaterHandshakePacketFailure) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x51});

    const auto first_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 20,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 0,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(first_packet.has_value());

    const auto second_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 21,
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
    ASSERT_TRUE(second_packet.has_value());

    auto datagram = first_packet.value();
    datagram.insert(datagram.end(), second_packet.value().begin(), second_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_ints({0xaa}));
}

TEST(QuicCoreTest, ProcessInboundDatagramIgnoresLaterHandshakeCryptoFailure) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});

    const auto first_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 30,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(first_packet.has_value());

    const auto second_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 31,
                .frames =
                    {
                        coquic::quic::CryptoFrame{
                            .offset = 0,
                            .crypto_data = bytes_from_ints({0x01}),
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(second_packet.has_value());

    auto datagram = first_packet.value();
    datagram.insert(datagram.end(), second_packet.value().begin(), second_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_ints({0xaa}));
}

TEST(QuicCoreTest, ProcessInboundDatagramReturnsWhenReplayFailsAfterCurrentPacketSucceeds) {
    auto connection = make_connected_client_connection();
    connection.deferred_protected_packets_.push_back(
        bytes_from_ints({0xc0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x11, 0x01, 0x22, 0x00, 0x00}));

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 79,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 0,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ConnectionMoveConstructionPreservesConnectionStartBehavior) {
    coquic::quic::QuicConnection source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicConnection moved(std::move(source));

    moved.start(coquic::quic::test::test_time(1));
    const auto datagram = moved.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
}

TEST(QuicCoreTest, ConnectionMoveAssignmentPreservesConnectionStartBehavior) {
    coquic::quic::QuicConnection source(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicConnection destination(coquic::quic::test::make_client_core_config());
    destination = std::move(source);

    destination.start(coquic::quic::test::test_time(1));
    const auto datagram = destination.drain_outbound_datagram(coquic::quic::test::test_time(1));

    EXPECT_FALSE(datagram.empty());
}

TEST(QuicCoreTest, ConnectionRemoteQlogParametersAreEmittedAtMostOnce) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    connection.config_.qlog = coquic::quic::QuicQlogConfig{.directory = qlog_dir.path()};
    connection.qlog_session_ = coquic::quic::qlog::Session::try_open(
        *connection.config_.qlog, connection.config_.role,
        connection.config_.initial_destination_connection_id, coquic::quic::test::test_time(0));
    ASSERT_TRUE(connection.qlog_session_ != nullptr);

    connection.maybe_emit_remote_qlog_parameters(coquic::quic::test::test_time(1));
    connection.maybe_emit_remote_qlog_parameters(coquic::quic::test::test_time(2));

    const auto records = coquic::quic::test::qlog_seq_records_from_file(
        coquic::quic::test::only_sqlog_file_in(qlog_dir.path()));
    EXPECT_EQ(coquic::quic::test::qlog_event_count(records, "quic:parameters_set"), 1u);
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathFailsWhenOneRttReadSecretCachePrimeFails) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, optional_ref_or_terminate(connection.application_space_.read_secret), 186);
    ASSERT_FALSE(encoded.empty());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    connection.handshake_space_.read_secret.reset();
    connection.zero_rtt_space_.read_secret.reset();
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xa3});

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathDiscardsUnreadablePacketWithoutNextKeyPhaseRetry) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    connection.application_space_.write_secret.reset();

    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xa4});
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 187);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathDefersProtectedApplicationPacketUntilConnected) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x21});
    connection.application_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x31});
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 188,
                .frames = {coquic::quic::MaxDataFrame{.maximum_data = 1}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), encoded.value());
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathFailsWhenApplicationPacketProcessingFails) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_server_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto invalid_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 189,
                .frames = {coquic::quic::test::make_inbound_application_stream_frame("x", 0, 3)},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(invalid_packet.has_value());

    connection.process_inbound_datagram(invalid_packet.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramKeepsPreviousReadSecretAfterOldPhasePacket) {
    auto connection = make_connected_client_connection();
    const auto old_secret = optional_ref_or_terminate(connection.application_space_.read_secret);
    const auto next_secret = coquic::quic::derive_next_traffic_secret(old_secret);
    ASSERT_TRUE(next_secret.has_value());
    if (!next_secret.has_value()) {
        return;
    }

    connection.previous_application_read_secret_ = old_secret;
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    connection.application_space_.read_secret = next_secret.value();
    connection.application_read_key_phase_ = !connection.application_read_key_phase_;
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, old_secret, 190, connection.previous_application_read_key_phase_);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 190u);
    EXPECT_TRUE(connection.previous_application_read_secret_.has_value());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathKeepsPreviousReadSecretAfterOldPhasePacket) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    const auto old_secret = optional_ref_or_terminate(connection.application_space_.read_secret);
    const auto next_secret = coquic::quic::derive_next_traffic_secret(old_secret);
    ASSERT_TRUE(next_secret.has_value());
    if (!next_secret.has_value()) {
        return;
    }

    connection.previous_application_read_secret_ = old_secret;
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    connection.application_space_.read_secret = next_secret.value();
    connection.application_read_key_phase_ = !connection.application_read_key_phase_;
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, old_secret, 190, connection.previous_application_read_key_phase_);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 190u);
    EXPECT_TRUE(connection.previous_application_read_secret_.has_value());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathFailsWhenSyncTlsStateFailsAfterValidPacket) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();
    ASSERT_TRUE(connection.tls_.has_value());
    enable_qlog_session_for_test(connection, qlog_dir.path());
    auto &tls = optional_ref_or_terminate(connection.tls_);
    connection.peer_transport_parameters_.reset();
    connection.peer_transport_parameters_validated_ = false;
    ASSERT_FALSE(connection.peer_source_connection_id_.has_value());
    coquic::quic::test::TlsAdapterTestPeer::set_peer_transport_parameters(
        tls, coquic::quic::test::sample_transport_parameters());

    const auto handshake_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x42});
    connection.handshake_space_.read_secret = handshake_secret;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 191,
                .frames = {coquic::quic::PingFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = handshake_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathFailsWhenPreviousReadSecretContextPrimeFails) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    const auto current_secret =
        optional_ref_or_terminate(connection.application_space_.read_secret);
    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb1});

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    ASSERT_TRUE(coquic::quic::expand_traffic_secret_cached(current_secret).has_value());

    connection.application_space_.read_secret.reset();
    connection.previous_application_read_secret_ = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb2});
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 192);
    ASSERT_FALSE(encoded.empty());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathAcceptsPeerKeyUpdatePacket) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    ASSERT_TRUE(connection.application_space_.read_secret.has_value());
    if (!connection.application_space_.read_secret.has_value()) {
        return;
    }

    const auto original_read_key_phase = connection.application_read_key_phase_;
    const auto original_write_key_phase = connection.application_write_key_phase_;
    const auto next_read_secret =
        coquic::quic::derive_next_traffic_secret(connection.application_space_.read_secret.value());
    ASSERT_TRUE(next_read_secret.has_value());
    if (!next_read_secret.has_value()) {
        return;
    }

    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, next_read_secret.value(), 193, !original_read_key_phase);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 193u);
    EXPECT_EQ(connection.application_read_key_phase_, !original_read_key_phase);
    EXPECT_EQ(connection.application_write_key_phase_, !original_write_key_phase);
}

TEST(QuicCoreTest,
     ProcessInboundDatagramQlogPathDiscardsPacketWhenPreviousReadSecretRetryStillFails) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    connection.previous_application_read_secret_ = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x41});
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x61});

    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, unrelated_secret, 193, connection.application_read_key_phase_);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest,
     ProcessInboundDatagramQlogPathDefersShortHeaderPacketWhenApplicationReadSecretMissing) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    connection.application_space_.read_secret.reset();

    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection,
        make_test_traffic_secret(coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
                                 std::byte{0xb3}),
        194);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 1u);
    EXPECT_EQ(connection.deferred_protected_packets_.front(), encoded);
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest,
     ProcessInboundDatagramQlogPathFailsOnMalformedLongHeaderPacketAfterLengthParsing) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb4});
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 195,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedProtectedCodecFaultInjector fault(
        coquic::quic::test::ProtectedCodecFaultPoint::remove_long_header_packet_length_mismatch);
    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
    EXPECT_EQ(connection.handshake_space_.largest_authenticated_packet_number, std::nullopt);
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathTracesDiscardedUnreadableShortHeaderPacket) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_client_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());
    connection.application_space_.write_secret.reset();

    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb5});
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 196);
    ASSERT_FALSE(encoded.empty());

    testing::internal::CaptureStderr();
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));
    const auto stderr_output = testing::internal::GetCapturedStderr();

    EXPECT_FALSE(connection.has_failed());
    EXPECT_NE(stderr_output.find("quic-packet-trace discard scid=c101"), std::string::npos);
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathIgnoresLaterHandshakeCryptoFailure) {
    coquic::quic::test::ScopedTempDir qlog_dir;
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.client_initial_destination_connection_id_ =
        connection.config_.initial_destination_connection_id;
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x43});
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto first_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 197,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(first_packet.has_value());

    const auto second_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedHandshakePacket{
                .version = 1,
                .destination_connection_id = connection.config_.source_connection_id,
                .source_connection_id = {std::byte{0xaa}},
                .packet_number_length = 2,
                .packet_number = 198,
                .frames = {coquic::quic::CryptoFrame{
                    .offset = 0,
                    .crypto_data = bytes_from_ints({0x01}),
                }},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .handshake_secret = connection.handshake_space_.read_secret,
        });
    ASSERT_TRUE(second_packet.has_value());

    auto datagram = first_packet.value();
    datagram.insert(datagram.end(), second_packet.value().begin(), second_packet.value().end());

    connection.process_inbound_datagram(datagram, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_ints({0xaa}));
}

TEST(QuicCoreTest, ProcessInboundDatagramQlogPathTracesOneRttProcessingFailure) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    coquic::quic::test::ScopedTempDir qlog_dir;
    auto connection = make_connected_server_connection();
    enable_qlog_session_for_test(connection, qlog_dir.path());

    const auto invalid_packet = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 199,
                .frames = {coquic::quic::test::make_inbound_application_stream_frame("x", 0, 3)},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(invalid_packet.has_value());

    testing::internal::CaptureStderr();
    connection.process_inbound_datagram(invalid_packet.value(), coquic::quic::test::test_time(1));
    const auto stderr_output = testing::internal::GetCapturedStderr();

    EXPECT_TRUE(connection.has_failed());
    EXPECT_NE(stderr_output.find("quic-packet-trace fail scid=5301"), std::string::npos);
}

TEST(QuicCoreTest,
     ProcessInboundDatagramDiscardsUnreadablePacketWithoutNextKeyPhaseRetryWhenWriteSecretMissing) {
    auto connection = make_connected_client_connection();
    connection.application_space_.write_secret.reset();

    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0xb6});
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 200);
    ASSERT_FALSE(encoded.empty());

    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ConnectionDeferredProtectedPacketEqualityDependsOnDatagramId) {
    const auto bytes = bytes_from_ints({0xaa, 0xbb, 0xcc});

    const auto datagram = static_cast<coquic::quic::DeferredProtectedDatagram>(
        coquic::quic::DeferredProtectedPacket(bytes));
    EXPECT_FALSE(datagram.datagram_id.has_value());
    EXPECT_TRUE(coquic::quic::DeferredProtectedPacket(bytes) == bytes);
    EXPECT_TRUE(bytes == coquic::quic::DeferredProtectedPacket(bytes));
    EXPECT_FALSE(coquic::quic::DeferredProtectedPacket(bytes, 7) == bytes);
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsShortHeaderPacketWithHeaderProtectionFailure) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 80,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::header_protection_context_new);
    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsCorruptedLongHeaderPacket) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.started_ = true;
    connection.process_inbound_datagram(bytes_from_ints({0x80, 0x00, 0x00, 0x00, 0x01}),
                                        coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_FALSE(connection.initial_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsShortHeaderPacketWithTooShortHeaderSample) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 81,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());
    ASSERT_GT(encoded.value().size(), 7u);
    auto truncated = encoded.value();
    truncated.resize(7);

    connection.process_inbound_datagram(truncated, coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramDiscardsShortHeaderPacketWithPayloadDecryptFailure) {
    auto connection = make_connected_client_connection();
    connection.handshake_confirmed_ = false;

    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .destination_connection_id = connection.config_.source_connection_id,
                .packet_number_length = 2,
                .packet_number = 82,
                .frames = {coquic::quic::AckFrame{}},
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::server,
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = connection.application_space_.read_secret,
        });
    ASSERT_TRUE(encoded.has_value());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::open_payload_update);
    connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_FALSE(connection.has_failed());
    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, std::nullopt);
    EXPECT_FALSE(connection.application_space_.received_packets.has_ack_to_send());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenHandshakeReadSecretCachePrimeFails) {
    auto connection = make_connected_client_connection();
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, optional_ref_or_terminate(connection.application_space_.read_secret), 83);
    ASSERT_FALSE(encoded.empty());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    connection.handshake_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x91});

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup, 2);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenZeroRttReadSecretCachePrimeFails) {
    auto connection = make_connected_client_connection();
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, optional_ref_or_terminate(connection.application_space_.read_secret), 84);
    ASSERT_FALSE(encoded.empty());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    connection.handshake_space_.read_secret.reset();
    connection.zero_rtt_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x92});

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenOneRttReadSecretCachePrimeFails) {
    auto connection = make_connected_client_connection();
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(
        connection, optional_ref_or_terminate(connection.application_space_.read_secret), 85);
    ASSERT_FALSE(encoded.empty());

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    connection.handshake_space_.read_secret.reset();
    connection.zero_rtt_space_.read_secret.reset();
    connection.application_space_.read_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x93});

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenPreviousReadSecretContextPrimeFails) {
    auto connection = make_connected_client_connection();
    const auto current_secret =
        optional_ref_or_terminate(connection.application_space_.read_secret);
    const auto unrelated_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x61});

    coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
    ASSERT_TRUE(coquic::quic::expand_traffic_secret_cached(current_secret).has_value());

    connection.application_space_.read_secret.reset();
    connection.previous_application_read_secret_ = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x94});
    connection.previous_application_read_key_phase_ = connection.application_read_key_phase_;
    const auto encoded = serialize_one_rtt_ack_datagram_for_test(connection, unrelated_secret, 87);
    ASSERT_FALSE(encoded.empty());

    const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
        coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup);
    connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));

    EXPECT_TRUE(connection.has_failed());
}

TEST(QuicCoreTest, ProcessInboundDatagramFailsWhenNextKeyPhaseContextPrimeFails) {
    bool saw_faulted_failure = false;
    for (std::size_t occurrence = 1; occurrence <= 8; ++occurrence) {
        auto connection = make_connected_client_connection();
        const auto current_secret =
            optional_ref_or_terminate(connection.application_space_.read_secret);
        const auto next_read_secret = coquic::quic::derive_next_traffic_secret(current_secret);
        ASSERT_TRUE(next_read_secret.has_value());
        if (!next_read_secret.has_value()) {
            return;
        }

        const auto encoded = serialize_one_rtt_ack_datagram_for_test(
            connection, next_read_secret.value(), 89, !connection.application_read_key_phase_);
        ASSERT_FALSE(encoded.empty());

        coquic::quic::test::reset_packet_crypto_runtime_caches_for_tests();
        connection.handshake_space_.read_secret.reset();
        connection.zero_rtt_space_.read_secret.reset();
        ASSERT_TRUE(coquic::quic::expand_traffic_secret_cached(current_secret).has_value());

        const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
            coquic::quic::test::PacketCryptoFaultPoint::hkdf_expand_setup, occurrence);
        try {
            connection.process_inbound_datagram(encoded, coquic::quic::test::test_time(1));
        } catch (const std::bad_variant_access &) {
            continue;
        }
        saw_faulted_failure = saw_faulted_failure || connection.has_failed();
    }

    EXPECT_TRUE(saw_faulted_failure);
}

TEST(QuicCoreTest, PacketTraceLogsAppEmptyWhenHandshakePacketFinalizesWithoutApplicationPayload) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.config_.max_outbound_datagram_size = 50;
    optional_ref_or_terminate(connection.peer_transport_parameters_).max_udp_payload_size = 50;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x95});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 13,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    testing::internal::CaptureStderr();
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    const auto stderr_output = testing::internal::GetCapturedStderr();

    ASSERT_FALSE(datagram.empty());
    EXPECT_FALSE(connection.has_failed());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    EXPECT_NE(std::get_if<coquic::quic::ProtectedHandshakePacket>(&packets.front()), nullptr);
    EXPECT_NE(stderr_output.find("quic-packet-trace app-empty scid="), std::string::npos);
}

TEST(QuicCoreTest, PacketTraceFilterMatchesExactSourceConnectionId) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");
    ScopedEnvVar filter("COQUIC_PACKET_TRACE_SCID", "5301");

    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;
    connection.peer_address_validated_ = false;
    connection.config_.max_outbound_datagram_size = 50;
    optional_ref_or_terminate(connection.peer_transport_parameters_).max_udp_payload_size = 50;
    connection.anti_amplification_received_bytes_ = 1200;
    connection.handshake_space_.write_secret = make_test_traffic_secret(
        coquic::quic::CipherSuite::tls_aes_128_gcm_sha256, std::byte{0x96});
    connection.handshake_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 15,
        .ack_eliciting = true,
        .in_flight = true,
        .has_ping = true,
    };
    for (std::uint64_t packet_number = 0; packet_number < 4096; packet_number += 2) {
        connection.application_space_.received_packets.record_received(
            packet_number, /*ack_eliciting=*/true, coquic::quic::test::test_time(0));
    }
    connection.application_space_.pending_ack_deadline = coquic::quic::test::test_time(0);

    testing::internal::CaptureStderr();
    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    const auto stderr_output = testing::internal::GetCapturedStderr();

    ASSERT_FALSE(datagram.empty());
    EXPECT_NE(stderr_output.find("quic-packet-trace app-empty scid=5301"), std::string::npos);
}

TEST(QuicCoreTest, PacketTraceLogsDiscardFailureReceiveAndSendPaths) {
    ScopedEnvVar trace("COQUIC_PACKET_TRACE", "1");

    testing::internal::CaptureStderr();

    {
        auto connection = make_connected_client_connection();
        connection.handshake_confirmed_ = false;

        const auto encoded = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 79,
                    .frames = {coquic::quic::AckFrame{}},
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::server,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
            });
        ASSERT_TRUE(encoded.has_value());

        const coquic::quic::test::ScopedPacketCryptoFaultInjector fault(
            coquic::quic::test::PacketCryptoFaultPoint::open_set_tag);
        connection.process_inbound_datagram(encoded.value(), coquic::quic::test::test_time(1));
        EXPECT_FALSE(connection.has_failed());
    }

    {
        coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
        connection.started_ = true;
        connection.status_ = coquic::quic::HandshakeStatus::connected;
        connection.client_initial_destination_connection_id_ =
            connection.config_.initial_destination_connection_id;
        connection.application_space_.read_secret = make_test_traffic_secret();

        const auto invalid_packet = coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
                coquic::quic::ProtectedOneRttPacket{
                    .destination_connection_id = connection.config_.source_connection_id,
                    .packet_number_length = 2,
                    .packet_number = 0,
                    .frames =
                        {
                            coquic::quic::test::make_inbound_application_stream_frame("x", 0, 3),
                        },
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret = connection.application_space_.read_secret,
            });
        ASSERT_TRUE(invalid_packet.has_value());

        connection.process_inbound_datagram(invalid_packet.value(),
                                            coquic::quic::test::test_time(2));
        EXPECT_TRUE(connection.has_failed());
    }

    {
        auto connection = make_connected_server_connection();
        ASSERT_TRUE(coquic::quic::test::QuicConnectionTestPeer::inject_inbound_one_rtt_frames(
            connection,
            {coquic::quic::test::make_inbound_application_stream_frame("GET /trace\r\n",
                                                                       /*offset=*/0,
                                                                       /*stream_id=*/0,
                                                                       /*fin=*/true)},
            /*packet_number=*/1));
        const auto received = connection.take_received_stream_data();
        ASSERT_TRUE(received.has_value());
    }

    {
        auto connection = make_connected_client_connection();
        ASSERT_TRUE(
            connection
                .queue_stream_send(0, coquic::quic::test::bytes_from_string("trace-send"), false)
                .has_value());
        const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(3));
        ASSERT_FALSE(datagram.empty());
    }

    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_NE(stderr_output.find("quic-packet-trace discard scid=c101"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace fail scid=5301"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace stream scid=5301"), std::string::npos);
    EXPECT_NE(stderr_output.find("quic-packet-trace send scid=c101"), std::string::npos);
}

} // namespace
