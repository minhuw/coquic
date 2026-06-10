#include <array>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <set>
#include <type_traits>

#include "src/quic/codec/protected_codec.h"
#include "src/quic/codec/varint.h"
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

    auto processed = connection.process_inbound_packet(
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

    auto processed = connection.process_inbound_packet(
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    auto packets = decode_sender_datagram(connection, datagram);
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

    auto processed = connection
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());

    auto packets = decode_sender_datagram(connection, datagram);
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

    auto processed = connection.process_inbound_application(
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
    ASSERT_TRUE(connection.peer_connection_ids_.contains(0));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # Upon receipt of an increased Retire Prior To field, the peer MUST
    // # stop using the corresponding connection IDs and retire them with
    // # RETIRE_CONNECTION_ID frames before adding the newly provided
    // # connection ID to the set of active connection IDs.
    EXPECT_TRUE(connection.peer_connection_ids_.at(0).locally_retired);
    ASSERT_TRUE(connection.peer_connection_ids_.contains(2));
    EXPECT_EQ(connection.peer_connection_ids_.at(2).connection_id,
              bytes_from_ints({0x10, 0x11, 0x12, 0x13}));
    EXPECT_EQ(connection.active_peer_connection_id_sequence_, 2u);
    const auto peer_reset_tokens = connection.peer_stateless_reset_tokens();
    ASSERT_EQ(peer_reset_tokens.size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.1
    // # An endpoint MUST NOT check for any stateless reset tokens associated
    // # with connection IDs it has not used or for connection IDs that have
    // # been retired.
    EXPECT_EQ(peer_reset_tokens.front().connection_id, bytes_from_ints({0x10, 0x11, 0x12, 0x13}));
}

TEST(QuicCoreTest, NewConnectionIdFrameQueuesRetireConnectionIdForRetirePriorToRange) {
    auto connection = make_connected_server_connection();

    auto processed = connection.process_inbound_application(
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
    ASSERT_TRUE(connection.peer_connection_ids_.contains(0));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # Upon receipt of an increased Retire Prior To field, the peer MUST
    // # stop using the corresponding connection IDs and retire them with
    // # RETIRE_CONNECTION_ID frames before adding the newly provided
    // # connection ID to the set of active connection IDs.
    EXPECT_TRUE(connection.peer_connection_ids_.at(0).locally_retired);
    ASSERT_TRUE(connection.peer_connection_ids_.contains(2));
    ASSERT_EQ(connection.pending_retire_connection_id_frames_.size(), 1u);
    EXPECT_EQ(connection.pending_retire_connection_id_frames_.front().sequence_number, 0u);

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    EXPECT_TRUE(connection.pending_retire_connection_id_frames_.empty());
    ASSERT_TRUE(connection.peer_connection_ids_.contains(0));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # An endpoint MUST NOT forget a connection ID without retiring it, though
    // # it MAY choose to treat having connection IDs in need of retirement that
    // # exceed this limit as a connection error of type CONNECTION_ID_LIMIT_ERROR.
    EXPECT_TRUE(connection.peer_connection_ids_.at(0).retire_frame_in_flight);
}

TEST(QuicCoreTest, RetiredPeerConnectionIdIsForgottenAfterRetireAck) {
    auto connection = make_connected_server_connection();

    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0xaa}),
    };
    auto processed = connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
        .sequence_number = 2,
        .retire_prior_to = 1,
        .connection_id = bytes_from_ints({0x10, 0x11}),
        .stateless_reset_token = {},
    });
    ASSERT_TRUE(processed.has_value());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    ASSERT_TRUE(connection.peer_connection_ids_.contains(0));
    ASSERT_TRUE(connection.peer_connection_ids_.at(0).retire_frame_in_flight);
    const auto packet_number = connection.application_space_.next_send_packet_number - 1;

    const auto acked = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = packet_number,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(2), connection.local_transport_parameters_.ack_delay_exponent,
        connection.local_transport_parameters_.max_ack_delay, /*suppress_pto_reset=*/false);

    ASSERT_TRUE(acked.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # An endpoint MUST NOT forget a connection ID without retiring it, though
    // # it MAY choose to treat having connection IDs in need of retirement that
    // # exceed this limit as a connection error of type CONNECTION_ID_LIMIT_ERROR.
    EXPECT_FALSE(connection.peer_connection_ids_.contains(0));
    ASSERT_TRUE(connection.peer_connection_ids_.contains(2));
}

TEST(QuicCoreTest, LostRetireConnectionIdFrameKeepsPeerCidAndRequeuesRetirement) {
    auto connection = make_connected_server_connection();

    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0xaa}),
    };
    auto processed = connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
        .sequence_number = 2,
        .retire_prior_to = 1,
        .connection_id = bytes_from_ints({0x10, 0x11}),
        .stateless_reset_token = {},
    });
    ASSERT_TRUE(processed.has_value());

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    ASSERT_TRUE(connection.peer_connection_ids_.contains(0));
    ASSERT_TRUE(connection.peer_connection_ids_.at(0).retire_frame_in_flight);

    const auto handle = connection.application_space_.recovery.newest_tracked_packet();
    ASSERT_TRUE(handle.has_value());
    auto tracked_handle = optional_value_or_terminate(handle);
    auto lost = connection.mark_lost_packet(connection.application_space_, tracked_handle,
                                            /*already_marked_in_recovery=*/false,
                                            coquic::quic::test::test_time(2));

    ASSERT_TRUE(lost.has_value());
    ASSERT_TRUE(connection.peer_connection_ids_.contains(0));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # An endpoint MUST NOT forget a connection ID without retiring it, though
    // # it MAY choose to treat having connection IDs in need of retirement that
    // # exceed this limit as a connection error of type CONNECTION_ID_LIMIT_ERROR.
    EXPECT_TRUE(connection.peer_connection_ids_.at(0).locally_retired);
    EXPECT_FALSE(connection.peer_connection_ids_.at(0).retire_frame_in_flight);
    ASSERT_EQ(connection.pending_retire_connection_id_frames_.size(), 1u);
    EXPECT_EQ(connection.pending_retire_connection_id_frames_.front().sequence_number, 0u);
}

TEST(QuicCoreTest, NewConnectionIdProcessingRejectsInvalidSequencesConflictsAndLimits) {
    const auto make_token = [](std::uint8_t fill) {
        std::array<std::byte, 16> token{};
        token[0] = static_cast<std::byte>(fill);
        return token;
    };

    {
        auto connection = make_connected_client_connection();
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
        // # The value in the Retire Prior To field MUST be less than or equal
        // # to the value in the Sequence Number field.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
        // # Receiving a value in the Retire Prior To field that is greater
        // # than that in the Sequence Number field MUST be treated as a
        // # connection error of type FRAME_ENCODING_ERROR.
        auto processed = connection.process_inbound_application(
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
        //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
        // # After processing a NEW_CONNECTION_ID frame and adding and retiring
        // # active connection IDs, if the number of active connection IDs
        // # exceeds the value advertised in its active_connection_id_limit
        // # transport parameter, an endpoint MUST close the connection with an
        // # error of type CONNECTION_ID_LIMIT_ERROR.
        EXPECT_TRUE(stored.error().has_transport_error_code);
        EXPECT_EQ(stored.error().transport_error_code,
                  static_cast<std::uint64_t>(
                      coquic::quic::QuicTransportErrorCode::connection_id_limit_error));
        EXPECT_EQ(stored.error().code, coquic::quic::CodecErrorCode::invalid_varint);
    }
}

TEST(QuicCoreTest, NewConnectionIdIgnoresStaleRetirePriorToButStoresUsableSequence) {
    auto connection = make_connected_client_connection();
    connection.local_transport_parameters_.active_connection_id_limit = 4;
    connection.largest_peer_retire_prior_to_ = 4;
    connection.peer_connection_ids_[4] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 4,
        .connection_id = bytes_from_ints({0x44}),
        .stateless_reset_token = {},
    };

    const auto stored =
        connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
            .sequence_number = 5,
            .retire_prior_to = 2,
            .connection_id = bytes_from_ints({0x55}),
            .stateless_reset_token = {},
        });

    ASSERT_TRUE(stored.has_value());
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
    // # A receiver MUST ignore any Retire Prior To fields that do not increase
    // # the largest received Retire Prior To value.
    EXPECT_EQ(connection.largest_peer_retire_prior_to_, 4u);
    ASSERT_TRUE(connection.peer_connection_ids_.contains(5));
    EXPECT_FALSE(connection.peer_connection_ids_.at(5).locally_retired);
    EXPECT_TRUE(connection.pending_retire_connection_id_frames_.empty());
}

TEST(QuicCoreTest, NewConnectionIdBelowPriorRetirePriorToQueuesRetirement) {
    auto connection = make_connected_client_connection();
    connection.local_transport_parameters_.active_connection_id_limit = 4;
    connection.largest_peer_retire_prior_to_ = 4;

    const auto stored =
        connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
            .sequence_number = 3,
            .retire_prior_to = 0,
            .connection_id = bytes_from_ints({0x33}),
            .stateless_reset_token = {},
        });

    ASSERT_TRUE(stored.has_value());
    ASSERT_TRUE(connection.peer_connection_ids_.contains(3));
    EXPECT_TRUE(connection.peer_connection_ids_.at(3).locally_retired);
    ASSERT_EQ(connection.pending_retire_connection_id_frames_.size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
    // # An endpoint that receives a NEW_CONNECTION_ID frame with a sequence
    // # number smaller than the Retire Prior To field of a previously
    // # received NEW_CONNECTION_ID frame MUST send a corresponding
    // # RETIRE_CONNECTION_ID frame that retires the newly received
    // # connection ID, unless it has already done so for that sequence
    // # number.
    EXPECT_EQ(connection.pending_retire_connection_id_frames_.front().sequence_number, 3u);
}

TEST(QuicCoreTest, NewConnectionIdBelowPriorRetirePriorToSkipsAlreadyRetiredSequence) {
    auto connection = make_connected_client_connection();
    connection.local_transport_parameters_.active_connection_id_limit = 4;
    connection.largest_peer_retire_prior_to_ = 4;
    connection.retired_peer_connection_id_sequences_.insert(3);

    const auto stored =
        connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
            .sequence_number = 3,
            .retire_prior_to = 0,
            .connection_id = bytes_from_ints({0x33}),
            .stateless_reset_token = {},
        });

    ASSERT_TRUE(stored.has_value());
    EXPECT_FALSE(connection.peer_connection_ids_.contains(3));
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
    // # An endpoint that receives a NEW_CONNECTION_ID frame with a sequence
    // # number smaller than the Retire Prior To field of a previously
    // # received NEW_CONNECTION_ID frame MUST send a corresponding
    // # RETIRE_CONNECTION_ID frame that retires the newly received
    // # connection ID, unless it has already done so for that sequence
    // # number.
    EXPECT_TRUE(connection.pending_retire_connection_id_frames_.empty());
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

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
    // # Receipt of the same frame multiple times MUST NOT be treated as a
    // # connection error.
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

TEST(QuicCoreTest, NewConnectionIdFrameRejectedWhenPeerRequiresZeroLengthDestinationConnectionId) {
    coquic::quic::QuicConnection connection(coquic::quic::test::make_server_core_config());

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
    // # An endpoint that is sending packets with a zero-length Destination
    // # Connection ID MUST treat receipt of a NEW_CONNECTION_ID frame as a
    // # connection error of type PROTOCOL_VIOLATION.
    const auto processed =
        connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
            .sequence_number = 0,
            .retire_prior_to = 0,
            .connection_id = bytes_from_ints({0x10, 0x11}),
            .stateless_reset_token = {},
        });

    ASSERT_FALSE(processed.has_value());
    EXPECT_TRUE(processed.error().has_transport_error_code);
    EXPECT_EQ(processed.error().transport_error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::protocol_violation));
}

TEST(QuicCoreTest, RetireConnectionIdRejectedWhenEndpointProvidesZeroLengthConnectionId) {
    auto config = coquic::quic::test::make_server_core_config();
    config.source_connection_id.clear();
    coquic::quic::QuicConnection connection(config);

    const auto processed = connection.process_retire_connection_id_frame(
        coquic::quic::RetireConnectionIdFrame{.sequence_number = 0});

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.16
    // # An endpoint that provides a zero-
    // # length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID
    // # frame as a connection error of type PROTOCOL_VIOLATION.
    ASSERT_FALSE(processed.has_value());
    EXPECT_TRUE(processed.error().has_transport_error_code);
    EXPECT_EQ(processed.error().transport_error_code,
              static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::protocol_violation));
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
    EXPECT_EQ(connection.outbound_destination_connection_id(99),
              bytes_from_ints({0x33, 0x44, 0x55, 0x66}));
}

TEST(QuicCoreTest, RetireConnectionIdFrameQueuesReplacementConnectionId) {
    auto connection = make_connected_server_connection();
    connection.issue_spare_connection_ids();

    auto processed = connection.process_inbound_application(
        std::array<coquic::quic::Frame, 1>{
            coquic::quic::RetireConnectionIdFrame{
                .sequence_number = 1,
            },
        },
        coquic::quic::test::test_time(1));

    ASSERT_TRUE(processed.has_value());
    EXPECT_GE(connection.pending_new_connection_id_frames_.size(), 1u);
}

TEST(QuicCoreTest, IssuedConnectionIdsAreUniqueAcrossAdjacentServerConnectionIds) {
    std::set<coquic::quic::ConnectionId> issued_connection_ids;

    for (std::uint64_t base_sequence = 1; base_sequence <= 64; ++base_sequence) {
        auto connection = make_connected_server_connection();
        connection.config_.source_connection_id = {
            std::byte{0x53}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, static_cast<std::byte>(base_sequence),
        };
        connection.local_connection_ids_.clear();
        connection.local_connection_ids_.emplace(
            0, coquic::quic::LocalConnectionIdRecord{
                   .sequence_number = 0,
                   .connection_id = connection.config_.source_connection_id,
                   .retired = false,
               });
        connection.pending_new_connection_id_frames_.clear();
        connection.next_local_connection_id_sequence_ = 1;
        optional_ref_or_terminate(connection.peer_transport_parameters_)
            .active_connection_id_limit = 4;

        connection.issue_spare_connection_ids();

        for (const auto &frame : connection.pending_new_connection_id_frames_) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1
            // # As a trivial example, this means the same connection ID
            // # MUST NOT be issued more than once on the same connection.
            EXPECT_TRUE(issued_connection_ids.insert(frame.connection_id).second)
                << "duplicate issued CID sequence=" << frame.sequence_number
                << " base_sequence=" << base_sequence;
        }
    }
}

TEST(QuicCoreTest, ReceivedApplicationRetireConnectionIdFrameSucceedsForActiveSequence) {
    auto connection = make_connected_server_connection();
    connection.issue_spare_connection_ids();

    auto processed = connection.process_inbound_received_application(
        std::array<coquic::quic::ReceivedFrame, 1>{coquic::quic::RetireConnectionIdFrame{
            .sequence_number = 1,
        }},
        coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false, /*path_id=*/0);

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(connection.local_connection_ids_.contains(1));
    EXPECT_TRUE(connection.local_connection_ids_.at(1).retired);
}

TEST(QuicCoreTest,
     ReceivedApplicationRetireConnectionIdFrameAllowsFollowingFramesAfterSuccessfulRetire) {
    auto connection = make_connected_server_connection();
    connection.issue_spare_connection_ids();

    auto processed = connection.process_inbound_received_application(
        std::array<coquic::quic::ReceivedFrame, 2>{
            coquic::quic::RetireConnectionIdFrame{.sequence_number = 1},
            coquic::quic::PingFrame{},
        },
        coquic::quic::test::test_time(1), /*allow_preconnected_frames=*/false, /*path_id=*/0);

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(connection.local_connection_ids_.contains(1));
    EXPECT_TRUE(connection.local_connection_ids_.at(1).retired);
}

TEST(QuicCoreTest, RetireConnectionIdProcessingCoversUnknownRetiredAndReplacementPaths) {
    {
        auto connection = make_connected_server_connection();
        auto processed = connection.process_inbound_application(
            std::array<coquic::quic::Frame, 1>{
                coquic::quic::RetireConnectionIdFrame{
                    .sequence_number = 99,
                },
            },
            coquic::quic::test::test_time(1));

        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.16
        // # Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number
        // # greater than any previously sent to the peer MUST be treated as a
        // # connection error of type PROTOCOL_VIOLATION.
        ASSERT_FALSE(processed.has_value());
        EXPECT_EQ(processed.error().code, coquic::quic::CodecErrorCode::invalid_varint);
        EXPECT_TRUE(processed.error().has_transport_error_code);
        EXPECT_EQ(
            processed.error().transport_error_code,
            static_cast<std::uint64_t>(coquic::quic::QuicTransportErrorCode::protocol_violation));
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

    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # An endpoint SHOULD ensure that its peer has a sufficient number of
    // # available and unused connection IDs.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # An endpoint MUST NOT provide more connection IDs than the peer's limit.
    EXPECT_EQ(connection.pending_new_connection_id_frames_.size(), 6u);
}

TEST(QuicCoreTest, ClientSkipsSpareConnectionIdsWhenActiveMigrationIsDisabled) {
    auto connection = make_connected_client_connection();
    connection.pending_new_connection_id_frames_.clear();
    connection.local_transport_parameters_.disable_active_migration = true;
    optional_ref_or_terminate(connection.peer_transport_parameters_).active_connection_id_limit = 8;
    const auto next_sequence_number = connection.next_local_connection_id_sequence_;

    connection.issue_spare_connection_ids();

    EXPECT_EQ(connection.next_local_connection_id_sequence_, next_sequence_number);
    EXPECT_TRUE(connection.pending_new_connection_id_frames_.empty());
}

TEST(QuicCoreTest, ZeroLengthSourceConnectionIdSkipsNewConnectionIdFrames) {
    auto connection = make_connected_server_connection();
    connection.config_.source_connection_id.clear();
    connection.local_transport_parameters_.initial_source_connection_id =
        coquic::quic::ConnectionId{};
    optional_ref_or_terminate(connection.peer_transport_parameters_).active_connection_id_limit = 8;
    connection.pending_new_connection_id_frames_.clear();
    const auto next_sequence_number = connection.next_local_connection_id_sequence_;

    connection.issue_spare_connection_ids();

    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.15
    // # An endpoint MUST NOT send this frame if it currently requires that
    // # its peer send packets with a zero-length Destination Connection ID.
    EXPECT_EQ(connection.next_local_connection_id_sequence_, next_sequence_number);
    EXPECT_TRUE(connection.pending_new_connection_id_frames_.empty());
}

TEST(QuicCoreTest, RequestedLocalConnectionIdRetirementStillCountsTowardPeerLimit) {
    auto connection = make_connected_server_connection();
    optional_ref_or_terminate(connection.peer_transport_parameters_).active_connection_id_limit = 2;
    connection.local_connection_ids_[1] = coquic::quic::LocalConnectionIdRecord{
        .sequence_number = 1,
        .connection_id = bytes_from_ints({0x51}),
        .stateless_reset_token = {},
        .retirement_requested = true,
    };
    connection.pending_new_connection_id_frames_.clear();
    connection.next_local_connection_id_sequence_ = 2;

    connection.issue_spare_connection_ids();

    EXPECT_TRUE(connection.pending_new_connection_id_frames_.empty());
}

TEST(QuicCoreTest, RetiringRequestedLocalConnectionIdQueuesReplacement) {
    auto connection = make_connected_server_connection();
    optional_ref_or_terminate(connection.peer_transport_parameters_).active_connection_id_limit = 2;
    connection.local_connection_ids_[1] = coquic::quic::LocalConnectionIdRecord{
        .sequence_number = 1,
        .connection_id = bytes_from_ints({0x51}),
        .stateless_reset_token = {},
        .retirement_requested = true,
    };
    connection.pending_new_connection_id_frames_.clear();
    connection.next_local_connection_id_sequence_ = 2;

    auto processed =
        connection.process_retire_connection_id_frame(coquic::quic::RetireConnectionIdFrame{
            .sequence_number = 1,
        });

    ASSERT_TRUE(processed.has_value());
    ASSERT_EQ(connection.pending_new_connection_id_frames_.size(), 1u);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # An endpoint SHOULD supply a new connection ID when the peer retires a
    // # connection ID.
    EXPECT_EQ(connection.pending_new_connection_id_frames_.front().sequence_number, 2u);
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
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # The sequence number on each newly issued connection ID MUST increase
    // # by 1.
    EXPECT_EQ(connection.pending_new_connection_id_frames_.front().sequence_number, 2u);
    EXPECT_EQ(connection.pending_new_connection_id_frames_.back().sequence_number, 7u);
}

TEST(QuicCoreTest, IssuedConnectionIdsUseDistinctStatelessResetTokens) {
    auto connection = make_connected_server_connection();
    optional_ref_or_terminate(connection.peer_transport_parameters_).active_connection_id_limit = 4;

    connection.issue_spare_connection_ids();

    ASSERT_GE(connection.local_connection_ids_.size(), 2u);
    std::set<std::array<std::byte, 16>> stateless_reset_tokens;
    for (const auto &[sequence_number, record] : connection.local_connection_ids_) {
        static_cast<void>(sequence_number);
        //= https://www.rfc-editor.org/rfc/rfc9000#section-10.3.2
        // # The same stateless reset token MUST NOT be used for multiple
        // # connection IDs.
        EXPECT_TRUE(stateless_reset_tokens.insert(record.stateless_reset_token).second);
    }
}

TEST(QuicCoreTest, PreferredAddressSequenceOneCanBeRetired) {
    auto connection = make_connected_server_connection_with_preferred_address();

    auto processed = connection.process_inbound_application(
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

TEST(QuicCoreTest, RetiredPeerInitialConnectionIdIsNotRecreatedFromSourceConnectionId) {
    auto connection = make_connected_client_connection();
    connection.local_transport_parameters_.active_connection_id_limit = 4;
    connection.peer_source_connection_id_ = bytes_from_ints({0xa1, 0xb2});
    connection.peer_connection_ids_[0] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 0,
        .connection_id = bytes_from_ints({0xa1, 0xb2}),
    };
    connection.peer_connection_ids_[1] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 1,
        .connection_id = bytes_from_ints({0x31}),
    };
    connection.peer_connection_ids_[2] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 2,
        .connection_id = bytes_from_ints({0x32}),
    };
    connection.peer_connection_ids_[3] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 3,
        .connection_id = bytes_from_ints({0x33}),
    };
    connection.queue_peer_connection_id_retirement(0);
    ASSERT_EQ(connection.pending_retire_connection_id_frames_.size(), 1u);

    auto retire_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(retire_datagram.empty());
    ASSERT_TRUE(connection.peer_connection_ids_.contains(0));
    ASSERT_TRUE(connection.peer_connection_ids_.at(0).retire_frame_in_flight);
    auto retire_packet_number = connection.application_space_.next_send_packet_number - 1;

    auto retire_acked = connection.process_inbound_ack(
        connection.application_space_,
        coquic::quic::AckFrame{
            .largest_acknowledged = retire_packet_number,
            .first_ack_range = 0,
        },
        coquic::quic::test::test_time(2), connection.local_transport_parameters_.ack_delay_exponent,
        connection.local_transport_parameters_.max_ack_delay, /*suppress_pto_reset=*/false);
    ASSERT_TRUE(retire_acked.has_value());
    EXPECT_FALSE(connection.peer_connection_ids_.contains(0));

    auto replacement =
        connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
            .sequence_number = 4,
            .retire_prior_to = 0,
            .connection_id = bytes_from_ints({0x34}),
        });

    ASSERT_TRUE(replacement.has_value());
    EXPECT_FALSE(connection.peer_connection_ids_.contains(0));
    ASSERT_TRUE(connection.peer_connection_ids_.contains(4));
    auto active_count =
        std::ranges::count_if(connection.peer_connection_ids_,
                              [](const auto &entry) { return !entry.second.locally_retired; });
    EXPECT_EQ(active_count, 4);
}

TEST(QuicCoreTest, NewConnectionIdRetirePriorToRefreshesCurrentPathPeerConnectionId) {
    auto connection = make_connected_client_connection();
    connection.local_transport_parameters_.active_connection_id_limit = 8;
    connection.paths_.clear();
    connection.current_send_path_id_ = 4;
    connection.last_validated_path_id_ = 4;
    connection.ensure_path_state(4).validated = true;
    connection.ensure_path_state(4).is_current_send_path = true;
    connection.ensure_path_state(4).peer_connection_id_sequence = 8;

    connection.peer_connection_ids_.clear();
    connection.peer_connection_ids_[8] = coquic::quic::PeerConnectionIdRecord{
        .sequence_number = 8,
        .connection_id = bytes_from_ints({0x88}),
    };
    connection.active_peer_connection_id_sequence_ = 8;
    connection.largest_peer_retire_prior_to_ = 7;

    auto processed = connection.process_new_connection_id_frame(coquic::quic::NewConnectionIdFrame{
        .sequence_number = 11,
        .retire_prior_to = 9,
        .connection_id = bytes_from_ints({0x11, 0x11}),
        .stateless_reset_token = {},
    });

    ASSERT_TRUE(processed.has_value());
    EXPECT_TRUE(connection.peer_connection_ids_.at(8).locally_retired);
    EXPECT_EQ(connection.active_peer_connection_id_sequence_, 11u);
    EXPECT_EQ(connection.paths_.at(4).peer_connection_id_sequence, 11u);
    ASSERT_EQ(connection.pending_retire_connection_id_frames_.size(), 1u);
    EXPECT_EQ(connection.pending_retire_connection_id_frames_.front().sequence_number, 8u);
    EXPECT_EQ(connection.outbound_destination_connection_id(4), bytes_from_ints({0x11, 0x11}));

    const auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(datagram.empty());
    const auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *application = std::get_if<coquic::quic::ProtectedOneRttPacket>(&packets.front());
    ASSERT_NE(application, nullptr);
    EXPECT_EQ(application->destination_connection_id, bytes_from_ints({0x11, 0x11}));
    ASSERT_EQ(application->frames.size(), 1u);
    const auto *retire =
        std::get_if<coquic::quic::RetireConnectionIdFrame>(&application->frames.front());
    ASSERT_NE(retire, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.16
    // # The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT
    // # refer to the Destination Connection ID field of the packet in which
    // # the frame is contained.
    EXPECT_EQ(retire->sequence_number, 8u);
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

    auto first_request = serialize_request(/*packet_number=*/7);
    ASSERT_TRUE(first_request.has_value());
    auto corrupted = first_request.value();
    ASSERT_GT(corrupted.size(), 3u);
    corrupted[3] ^= std::byte{0x15};

    connection.process_inbound_datagram(corrupted, coquic::quic::test::test_time(1));
    EXPECT_FALSE(connection.has_failed());
    auto unexpected_received = connection.take_received_stream_data();
    EXPECT_FALSE(unexpected_received.has_value());

    auto retransmitted_request = serialize_request(/*packet_number=*/8);
    ASSERT_TRUE(retransmitted_request.has_value());
    auto retransmitted_request_datagram = retransmitted_request.has_value()
                                              ? retransmitted_request.value()
                                              : std::vector<std::byte>{};
    connection.process_inbound_datagram(retransmitted_request_datagram,
                                        coquic::quic::test::test_time(2));
    EXPECT_FALSE(connection.has_failed());

    auto received = connection.take_received_stream_data();
    ASSERT_TRUE(received.has_value());
    const auto &received_value = optional_ref_or_terminate(received);
    EXPECT_EQ(received_value.stream_id, 0u);
    EXPECT_EQ(received_value.bytes,
              coquic::quic::test::bytes_from_string("GET /abundant-subtropical-monk\r\n"));
    EXPECT_TRUE(received_value.fin);
}

TEST(QuicCoreTest, ClientInitialRetransmissionsUseSameDestinationConnectionIdBeforeServerPacket) {
    auto config = coquic::quic::test::make_client_core_config();
    config.initial_destination_connection_id = bytes_from_hex("8394c8f03e515708");
    coquic::quic::QuicConnection connection(std::move(config));
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 0,
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

    auto first_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(first_datagram.empty());
    connection.initial_space_.pending_probe_packet = coquic::quic::SentPacketRecord{
        .packet_number = 1,
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

    auto second_datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(second_datagram.empty());

    auto first_packets = decode_sender_datagram(connection, first_datagram);
    auto second_packets = decode_sender_datagram(connection, second_datagram);
    ASSERT_EQ(first_packets.size(), 1u);
    ASSERT_EQ(second_packets.size(), 1u);
    const auto *first_initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&first_packets.front());
    const auto *second_initial =
        std::get_if<coquic::quic::ProtectedInitialPacket>(&second_packets.front());
    ASSERT_NE(first_initial, nullptr);
    ASSERT_NE(second_initial, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
    // # Until a packet is received from the server, the client MUST use the
    // # same Destination Connection ID value on all packets in this connection.
    EXPECT_EQ(first_initial->destination_connection_id, second_initial->destination_connection_id);
    EXPECT_EQ(first_initial->destination_connection_id,
              connection.client_initial_destination_connection_id());
}

TEST(QuicCoreTest, ClientInitialRetransmissionsUseServerSourceConnectionIdAfterServerInitial) {
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
    // # A client MUST change the Destination Connection ID it uses for
    // # sending packets in response to only the first received Initial
    // # or Retry packet.
    EXPECT_EQ(initial->destination_connection_id,
              optional_value_or_terminate(connection.peer_source_connection_id_));
    EXPECT_NE(initial->destination_connection_id,
              connection.client_initial_destination_connection_id());
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(1));

    ASSERT_FALSE(datagram.empty());
    auto packets = decode_sender_datagram(connection, datagram);
    ASSERT_EQ(packets.size(), 1u);
    const auto *initial = std::get_if<coquic::quic::ProtectedInitialPacket>(&packets[0]);
    ASSERT_NE(initial, nullptr);
    //= https://www.rfc-editor.org/rfc/rfc9000#section-7.2
    // # A server MUST set the Destination Connection ID it uses for
    // # sending packets based on the first received Initial packet.
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

    auto datagram = connection.drain_outbound_datagram(coquic::quic::test::test_time(2));
    ASSERT_FALSE(datagram.empty());

    auto packets = decode_sender_datagram(connection, datagram);
    const auto initial = std::find_if(
        packets.begin(), packets.end(), [](const coquic::quic::ProtectedPacket &packet) {
            return std::holds_alternative<coquic::quic::ProtectedInitialPacket>(packet);
        });
    ASSERT_NE(initial, packets.end());

    auto initial_packet = &std::get<coquic::quic::ProtectedInitialPacket>(*initial);
    auto ack_frame_it =
        std::find_if(initial_packet->frames.begin(), initial_packet->frames.end(),
                     [](const coquic::quic::Frame &frame) {
                         return std::holds_alternative<coquic::quic::AckFrame>(frame);
                     });
    ASSERT_NE(ack_frame_it, initial_packet->frames.end());

    const auto &ack_frame = std::get<coquic::quic::AckFrame>(*ack_frame_it);
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
        std::array<coquic::quic::Frame, 1>{coquic::quic::MaxStreamDataFrame{
            .stream_id = 0,
            .maximum_stream_data = 1,
        }},
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
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.1
    // # When an endpoint issues a connection ID, it MUST accept packets that
    // # carry this connection ID for the duration of the connection or until
    // # its peer invalidates the connection ID via a RETIRE_CONNECTION_ID
    // # frame (Section 19.16).
    //= https://www.rfc-editor.org/rfc/rfc9000#section-5.1.2
    // # The endpoint SHOULD continue to accept the previously issued connection
    // # IDs until they are retired by the peer.
    EXPECT_EQ(active_connection_ids[0], connection.config_.source_connection_id);
    EXPECT_EQ(active_connection_ids[1], bytes_from_ints({0x11}));
}

} // namespace
