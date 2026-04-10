#include <array>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <type_traits>

#include "src/quic/connection_test_hooks.h"
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
using coquic::quic::test_support::invalid_cipher_suite;
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

TEST(QuicCoreTest,
     ServerProcessesOneRttRetireConnectionIdBeforeHandshakeCompletesWhenApplicationKeysExist) {
    auto connection = make_connected_server_connection();
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.handshake_confirmed_ = false;

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .key_phase = false,
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 7,
            .frames =
                {
                    coquic::quic::RetireConnectionIdFrame{
                        .sequence_number = 1,
                    },
                },
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());

    EXPECT_EQ(connection.application_space_.largest_authenticated_packet_number, 7u);
    EXPECT_FALSE(connection.has_failed());
}

TEST(QuicCoreTest, RetireConnectionIdPacketSchedulesApplicationAck) {
    auto connection = make_connected_server_connection();

    const auto processed = connection.process_inbound_packet(
        coquic::quic::ProtectedOneRttPacket{
            .key_phase = false,
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 1,
            .packet_number = 7,
            .frames =
                {
                    coquic::quic::RetireConnectionIdFrame{
                        .sequence_number = 1,
                    },
                },
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
}

TEST(QuicCoreTest, NewConnectionIdPacketSchedulesApplicationAckWhenHandshakeDonePending) {
    auto connection = make_connected_server_connection();
    connection.handshake_confirmed_ = false;
    connection.handshake_done_state_ = coquic::quic::StreamControlFrameState::pending;

    const auto processed = connection
                               .process_inbound_packet(
                                   coquic::quic::ProtectedOneRttPacket{
                                       .key_phase = false,
                                       .destination_connection_id =
                                           connection.config_.source_connection_id,
                                       .packet_number_length = 1,
                                       .packet_number = 7,
                                       .frames =
                                           {
                                               coquic::quic::NewConnectionIdFrame{
                                                   .sequence_number = 1,
                                                   .retire_prior_to = 0,
                                                   .connection_id =
                                                       bytes_from_ints({0x12, 0x34, 0x56, 0x78}),
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
                                   coquic::quic::test::test_time(1));
    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(connection.application_space_.received_packets.has_ack_to_send());

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);

    bool saw_ack = false;
    bool saw_handshake_done = false;
    for (const auto &frame : application->frames) {
        saw_ack = saw_ack || std::holds_alternative<coquic::quic::AckFrame>(frame);
        saw_handshake_done =
            saw_handshake_done || std::holds_alternative<coquic::quic::HandshakeDoneFrame>(frame);
    }

    EXPECT_TRUE(saw_ack);
    EXPECT_TRUE(saw_handshake_done);
}

TEST(QuicCoreTest, NewConnectionIdFrameStoresPeerInventoryAndRetiresOlderEntries) {
    auto connection = make_connected_client_connection();

    connection.peer_connection_ids_.emplace(0, coquic::quic::PeerConnectionIdRecord{
                                                   .sequence_number = 0,
                                                   .connection_id = bytes_from_ints({0xaa}),
                                               });

    const auto processed = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::NewConnectionIdFrame{
                .sequence_number = 2,
                .retire_prior_to = 1,
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
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(connection.peer_connection_ids_.contains(0));
    ASSERT_TRUE(connection.peer_connection_ids_.contains(2));
    EXPECT_EQ(connection.peer_connection_ids_.at(2).connection_id,
              bytes_from_ints({0x10, 0x11, 0x12, 0x13}));
}

TEST(QuicCoreTest, NewConnectionIdFrameQueuesRetireConnectionIdForRetirePriorToRange) {
    auto connection = make_connected_server_connection();

    const auto processed = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::NewConnectionIdFrame{
                .sequence_number = 2,
                .retire_prior_to = 1,
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
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_FALSE(connection.peer_connection_ids_.contains(0));
    ASSERT_TRUE(connection.peer_connection_ids_.contains(2));
    ASSERT_EQ(connection.pending_retire_connection_id_frames_.size(), 1u);
    EXPECT_EQ(connection.pending_retire_connection_id_frames_.front().sequence_number, 0u);

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    EXPECT_TRUE(connection.pending_retire_connection_id_frames_.empty());
}

TEST(QuicCoreTest, NewConnectionIdProcessingRejectsInvalidSequencesConflictsAndLimits) {
    const auto make_token = [](std::uint8_t fill) {
        std::array<std::byte, 16> token{};
        token[0] = static_cast<std::byte>(fill);
        return token;
    };

    {
        auto connection = make_connected_client_connection();
        const auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::NewConnectionIdFrame{
                    .sequence_number = 1,
                    .retire_prior_to = 2,
                    .connection_id = bytes_from_ints({0x10, 0x11}),
                    .stateless_reset_token = make_token(0x10),
                },
            },
            coquic::quic::test::test_time(1));

        ASSERT_FALSE(processed.has_value());
        EXPECT_EQ(processed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_connection_ids_[4] = coquic::quic::PeerConnectionIdRecord{
            .sequence_number = 4,
            .connection_id = bytes_from_ints({0xaa, 0xbb}),
            .stateless_reset_token = make_token(0x20),
        };

        const auto stored =
            connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
                .sequence_number = 4,
                .retire_prior_to = 0,
                .connection_id = bytes_from_ints({0xcc, 0xdd}),
                .stateless_reset_token = make_token(0x20),
            });

        ASSERT_FALSE(stored.has_value());
        EXPECT_EQ(stored.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    }

    {
        auto connection = make_connected_client_connection();
        connection.peer_connection_ids_[1] = coquic::quic::PeerConnectionIdRecord{
            .sequence_number = 1,
            .connection_id = bytes_from_ints({0xaa, 0xbb}),
            .stateless_reset_token = make_token(0x30),
        };

        const auto stored =
            connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
                .sequence_number = 2,
                .retire_prior_to = 0,
                .connection_id = bytes_from_ints({0xaa, 0xbb}),
                .stateless_reset_token = make_token(0x31),
            });

        ASSERT_FALSE(stored.has_value());
        EXPECT_EQ(stored.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    }

    {
        auto connection = make_connected_client_connection();
        connection.local_transport_parameters_.active_connection_id_limit = 1;
        connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
            .sequence_number = 0,
            .connection_id = bytes_from_ints({0xaa}),
            .stateless_reset_token = make_token(0x40),
        };

        const auto stored =
            connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
                .sequence_number = 1,
                .retire_prior_to = 0,
                .connection_id = bytes_from_ints({0x10, 0x11}),
                .stateless_reset_token = make_token(0x41),
            });

        ASSERT_FALSE(stored.has_value());
        EXPECT_EQ(stored.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    }
}

TEST(QuicCoreTest, MatchingDuplicateNewConnectionIdFrameIsAccepted) {
    auto connection = make_connected_client_connection();

    std::array<std::byte, 16> token{};
    token[0] = std::byte{0x44};
    connection.peer_connection_ids_[4] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 4,
        .connection_id = bytes_from_ints({0xaa, 0xbb}),
        .stateless_reset_token = token,
    };

    const auto stored =
        connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
            .sequence_number = 4,
            .retire_prior_to = 0,
            .connection_id = bytes_from_ints({0xaa, 0xbb}),
            .stateless_reset_token = token,
        });

    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(connection.peer_connection_ids_.at(4).connection_id, bytes_from_ints({0xaa, 0xbb}));
}

TEST(QuicCoreTest, OutboundDestinationConnectionIdUsesActivePeerInventoryEntry) {
    auto connection = make_connected_client_connection();

    connection.peer_connection_ids_.emplace(0, coquic::quic::PeerConnectionIdRecord{
                                                   .sequence_number = 0,
                                                   .connection_id = bytes_from_ints({0xaa}),
                                               });
    connection.peer_connection_ids_.emplace(
        3, coquic::quic::PeerConnectionIdRecord{
               .sequence_number = 3,
               .connection_id = bytes_from_ints({0x33, 0x44, 0x55, 0x66}),
           });
    connection.active_peer_connection_id_sequence_ = 3;

    EXPECT_EQ(connection.outbound_destination_connection_id(),
              bytes_from_ints({0x33, 0x44, 0x55, 0x66}));
}

TEST(QuicCoreTest, RetireConnectionIdFrameQueuesReplacementConnectionId) {
    auto connection = make_connected_server_connection();
    connection.issue_spare_connection_ids();

    const auto processed = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 1,
            },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_GE(connection.pending_new_connection_id_frames_.size(), 1u);
}

TEST(QuicCoreTest, RetireConnectionIdProcessingCoversUnknownRetiredAndReplacementPaths) {
    {
        auto connection = make_connected_server_connection();
        const auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::RetireConnectionIdFrame{
                    .sequence_number = 99,
                },
            },
            coquic::quic::test::test_time(1));

        ASSERT_FALSE(processed.has_value());
        EXPECT_EQ(processed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    }

    {
        auto connection = make_connected_server_connection();
        connection.issue_spare_connection_ids();
        ASSERT_TRUE(connection.local_connection_ids_.contains(1));
        connection.local_connection_ids_.at(1).retired = true;

        const auto retired =
            connection.process_retire_connection_id_frame(coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 1,
            });

        ASSERT_TRUE(retired.has_value());
        EXPECT_TRUE(retired.value());
    }

    {
        auto connection = make_connected_server_connection();
        connection.issue_spare_connection_ids();
        connection.local_connection_ids_[0].retired = true;
        connection.local_connection_ids_[2] = coquic::quic::LocalConnectionIdRecord{
            .sequence_number = 2,
            .connection_id = bytes_from_ints({0x22, 0x23}),
            .stateless_reset_token = {},
            .retired = false,
        };
        connection.active_local_connection_id_sequence_ = 1;

        const auto retired =
            connection.process_retire_connection_id_frame(coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 1,
            });

        ASSERT_TRUE(retired.has_value());
        EXPECT_EQ(connection.active_local_connection_id_sequence_, 2u);
    }

    {
        auto connection = make_connected_server_connection();
        connection.pending_new_connection_id_frames_.clear();
        optional_ref_or_terminate(connection.peer_transport_parameters_)
            .active_connection_id_limit = 0;
        const auto next_sequence_number = connection.next_local_connection_id_sequence_;

        connection.issue_spare_connection_ids();

        EXPECT_EQ(connection.next_local_connection_id_sequence_, next_sequence_number);
        EXPECT_TRUE(connection.pending_new_connection_id_frames_.empty());
    }
}

TEST(QuicCoreTest, PreferredAddressCountsTowardIssuedConnectionIdLimit) {
    auto connection = make_connected_server_connection_with_preferred_address();
    optional_ref_or_terminate(connection.peer_transport_parameters_).active_connection_id_limit = 8;

    connection.issue_spare_connection_ids();

    EXPECT_EQ(connection.pending_new_connection_id_frames_.size(), 6u);
}

TEST(QuicCoreTest, PreferredAddressReservesSequenceOneInLocalConnectionIdInventory) {
    auto config = coquic::quic::test::make_server_core_config();
    config.transport.preferred_address = make_test_preferred_address();

    coquic::quic::QuicConnection connection(config);

    ASSERT_TRUE(connection.local_connection_ids_.contains(1));
    EXPECT_EQ(connection.local_connection_ids_.at(1).connection_id,
              config.transport.preferred_address->connection_id);
    EXPECT_EQ(connection.local_connection_ids_.at(1).stateless_reset_token,
              config.transport.preferred_address->stateless_reset_token);
    EXPECT_EQ(connection.next_local_connection_id_sequence_, 2u);
}

TEST(QuicCoreTest, PreferredAddressStartsIssuedConnectionIdsAtSequenceTwo) {
    auto connection = make_connected_server_connection_with_preferred_address();
    optional_ref_or_terminate(connection.peer_transport_parameters_).active_connection_id_limit = 8;

    connection.issue_spare_connection_ids();

    ASSERT_EQ(connection.pending_new_connection_id_frames_.size(), 6u);
    EXPECT_EQ(connection.pending_new_connection_id_frames_.front().sequence_number, 2u);
    EXPECT_EQ(connection.pending_new_connection_id_frames_.back().sequence_number, 7u);
}

TEST(QuicCoreTest, PreferredAddressSequenceOneCanBeRetired) {
    auto connection = make_connected_server_connection_with_preferred_address();

    const auto processed = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 1,
            },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    ASSERT_TRUE(connection.local_connection_ids_.contains(1));
    EXPECT_TRUE(connection.local_connection_ids_.at(1).retired);
}

TEST(QuicCoreTest, CorruptedOneRttRequestConnectionIdBitflipDoesNotBlockValidRetransmit) {
    auto connection = make_connected_server_connection();
    connection.config_.source_connection_id = {
        std::byte{0x53}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x2e},
    };
    connection.local_transport_parameters_.initial_source_connection_id =
        connection.config_.source_connection_id;

    const auto serialize_request = [&](std::uint64_t packet_number) {
        return coquic::quic::serialize_protected_datagram(
            std::array<coquic::quic::ProtectedPacket, 1>{
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
                                .stream_data = coquic::quic::test::bytes_from_string(
                                    "GET /abundant-subtropical-monk\r\n"),
                            },
                            coquic::quic::PaddingFrame{
                                .length = 122,
                            },
                        },
                },
            },
            coquic::quic::SerializeProtectionContext{
                .local_role = coquic::quic::EndpointRole::client,
                .client_initial_destination_connection_id =
                    connection.client_initial_destination_connection_id(),
                .one_rtt_secret =
                    optional_ref_or_terminate(connection.application_space_.read_secret),
            });
    };

    const auto first_request = serialize_request(/*packet_number=*/7);
    ASSERT_TRUE(first_request.has_value());
    auto corrupted = first_request.value();
    ASSERT_GT(corrupted.size(), 3u);
    corrupted[3] ^= std::byte{0x15};

    connection.process_inbound_datagram(corrupted, coquic::quic::test::test_time(1));
    EXPECT_FALSE(connection.has_failed());
    const auto unexpected_received = connection.take_received_stream_data();
    EXPECT_FALSE(unexpected_received.has_value());

    const auto retransmitted_request = serialize_request(/*packet_number=*/8);
    ASSERT_TRUE(retransmitted_request.has_value());
    const auto retransmitted_request_datagram = retransmitted_request.has_value()
                                                    ? retransmitted_request.value()
                                                    : std::vector<std::byte>{};
    connection.process_inbound_datagram(retransmitted_request_datagram,
                                        coquic::quic::test::test_time(2));
    EXPECT_FALSE(connection.has_failed());

    const auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    const auto &received_value = optional_ref_or_terminate(received);
    EXPECT_EQ(received_value.stream_id, 0u);
    EXPECT_EQ(received_value.bytes,
              coquic::quic::test::bytes_from_string("GET /abundant-subtropical-monk\r\n"));
    EXPECT_TRUE(received_value.fin);
}

TEST(QuicCoreTest, InitialRetransmissionsKeepOriginalDestinationConnectionId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.peer_source_connection_id_ = {
        std::byte{0xf1},
        std::byte{0xfd},
        std::byte{0x54},
        std::byte{0xd6},
    };
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 4,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = std::vector<std::byte>(64, std::byte{0x61}),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->destination_connection_id,
              connection.client_initial_destination_connection_id());
    EXPECT_EQ(initial->destination_connection_id.size(), 8u);
}

TEST(QuicCoreTest, ServerInitialPacketsUsePeerSourceConnectionIdAsDestination) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());
    connection.peer_source_connection_id_ = {
        std::byte{0xc1}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x3d},
    };
    connection.client_initial_destination_connection_id_ = {
        std::byte{0x83}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x3c},
    };
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 5,
        .ack_eliciting = true,
        .in_flight = true,
        .crypto_ranges =
            {
                coquic::quic::ByteRange{
                    .offset = 0,
                    .bytes = std::vector<std::byte>(64, std::byte{0x62}),
                },
            },
    };

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->destination_connection_id,
              optional_value_or_terminate(connection.peer_source_connection_id_));
}

TEST(QuicCoreTest, ClientResetsInitialAckHistoryWhenPeerSourceConnectionIdChangesMidHandshake) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.start_client_if_needed();
    ASSERT_FALSE(connection.drain_outbound_datagram(coquic::quic::test::test_time()).empty());

    const auto first_packet = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0xaa}},
            .packet_number_length = 2,
            .packet_number = 2,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(1));
    ASSERT_TRUE(first_packet.has_value());

    const auto second_packet = connection.process_inbound_packet(
        coquic::quic::ProtectedInitialPacket{
            .version = 1,
            .destination_connection_id = connection.config_.source_connection_id,
            .source_connection_id = {std::byte{0xbb}},
            .packet_number_length = 2,
            .packet_number = 0,
            .frames = {coquic::quic::PingFrame{}},
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(second_packet.has_value());

    EXPECT_EQ(connection.peer_source_connection_id_, bytes_from_ints({0xbb}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(datagram.empty());

    const auto packets = decode_sender_datagram(connection, datagram);
    const auto initial = std::find_if(
        packets.begin(), packets.end(), [](const coquic::quic::ProtectedPacket &packet) {
            return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
        });
    ASSERT_NE(initial, packets.end());

    const auto &initial_packet = std::get<coquic::quic::ProtectedInitialPacket>(*initial);
    const auto ack = std::find_if(initial_packet.frames.begin(), initial_packet.frames.end(),
                                  [](const coquic::quic::Frame &frame) {
                                      return std::holds_alternative<coquic::quic::AckFrame>(frame);
                                  });
    ASSERT_NE(ack, initial_packet.frames.end());

    const auto &ack_frame = std::get<coquic::quic::AckFrame>(*ack);
    EXPECT_EQ(ack_frame.largest_acknowledged, 0u);
    EXPECT_EQ(ack_frame.first_ack_range, 0u);
    EXPECT_TRUE(ack_frame.additional_ranges.empty());
}

TEST(QuicCoreTest, PeerTransportParametersValidationContextRequiresPeerConnectionId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    EXPECT_EQ(connection.peer_transport_parameters_validation_context(), std::nullopt);
}

TEST(QuicCoreTest, ProcessInboundApplicationCoversPreconnectedRetireConnectionIdGate) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_client_core_config());
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.application_space_.read_secret = make_test_traffic_secret();

    const auto gated = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{coquic::quic::MaxDataFrame{.maximum_data = 1}},
        coquic::quic::test::test_time(1));
    ASSERT_FALSE(gated.has_value());
    EXPECT_EQ(gated.error().code, coquic::quic::CodecErrorCode::invalid_varint);

    const auto accepted = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 0,
            },
        },
        coquic::quic::test::test_time(2));
    ASSERT_TRUE(accepted.has_value());
}

TEST(QuicCoreTest, ActiveLocalConnectionIdsExcludeRetiredEntries) {
    auto connection = make_connected_server_connection();
    connection.local_connection_ids_[1] = coquic::quic::LocalConnectionIdRecord{
        .sequence_number = 1,
        .connection_id = bytes_from_ints({0x11}),
        .stateless_reset_token = {},
        .retired = false,
    };
    connection.local_connection_ids_[2] = coquic::quic::LocalConnectionIdRecord{
        .sequence_number = 2,
        .connection_id = bytes_from_ints({0x22}),
        .stateless_reset_token = {},
        .retired = true,
    };

    const auto active_connection_ids = connection.active_local_connection_ids();

    ASSERT_EQ(active_connection_ids.size(), 2u);
    EXPECT_EQ(active_connection_ids[0], connection.config_.source_connection_id);
    EXPECT_EQ(active_connection_ids[1], bytes_from_ints({0x11}));
}

} // namespace
