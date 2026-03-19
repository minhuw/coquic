#include <gtest/gtest.h>

#include <cstdint>

#include "src/quic/streams.h"

namespace {

using coquic::quic::classify_stream_id;
using coquic::quic::EndpointRole;
using coquic::quic::is_peer_implicit_stream_open_allowed_by_limits;
using coquic::quic::make_implicit_stream_state;
using coquic::quic::StreamDirection;
using coquic::quic::StreamInitiator;
using coquic::quic::StreamState;
using coquic::quic::StreamStateErrorCode;

void expect_stream_id_info(std::uint64_t stream_id, EndpointRole local_role,
                           StreamInitiator initiator, StreamDirection direction,
                           bool local_can_send, bool local_can_receive) {
    const auto info = classify_stream_id(stream_id, local_role);
    EXPECT_EQ(info.initiator, initiator);
    EXPECT_EQ(info.direction, direction);
    EXPECT_EQ(info.local_can_send, local_can_send);
    EXPECT_EQ(info.local_can_receive, local_can_receive);
}

TEST(QuicStreamsTest, ClassifiesInitiatorAndDirectionFromStreamId) {
    expect_stream_id_info(/*stream_id=*/0, EndpointRole::client, StreamInitiator::local,
                          StreamDirection::bidirectional, /*local_can_send=*/true,
                          /*local_can_receive=*/true);
    expect_stream_id_info(/*stream_id=*/1, EndpointRole::client, StreamInitiator::peer,
                          StreamDirection::bidirectional, /*local_can_send=*/true,
                          /*local_can_receive=*/true);
    expect_stream_id_info(/*stream_id=*/2, EndpointRole::client, StreamInitiator::local,
                          StreamDirection::unidirectional, /*local_can_send=*/true,
                          /*local_can_receive=*/false);
    expect_stream_id_info(/*stream_id=*/3, EndpointRole::client, StreamInitiator::peer,
                          StreamDirection::unidirectional, /*local_can_send=*/false,
                          /*local_can_receive=*/true);

    expect_stream_id_info(/*stream_id=*/0, EndpointRole::server, StreamInitiator::peer,
                          StreamDirection::bidirectional, /*local_can_send=*/true,
                          /*local_can_receive=*/true);
    expect_stream_id_info(/*stream_id=*/1, EndpointRole::server, StreamInitiator::local,
                          StreamDirection::bidirectional, /*local_can_send=*/true,
                          /*local_can_receive=*/true);
    expect_stream_id_info(/*stream_id=*/2, EndpointRole::server, StreamInitiator::peer,
                          StreamDirection::unidirectional, /*local_can_send=*/false,
                          /*local_can_receive=*/true);
    expect_stream_id_info(/*stream_id=*/3, EndpointRole::server, StreamInitiator::local,
                          StreamDirection::unidirectional, /*local_can_send=*/true,
                          /*local_can_receive=*/false);
}

TEST(QuicStreamsTest, RejectsLocalSendOnReceiveOnlyPeerUniStream) {
    auto state = make_implicit_stream_state(/*stream_id=*/2, EndpointRole::server);
    const auto result = state.validate_local_send(/*fin=*/false);
    ASSERT_FALSE(result.has_value());
}

TEST(QuicStreamsTest, FinalSizeCannotChangeOnceKnown) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(state.note_peer_final_size(/*final_size=*/5).has_value());
    const auto conflict = state.note_peer_final_size(/*final_size=*/7);
    ASSERT_FALSE(conflict.has_value());
}

TEST(QuicStreamsTest, ReceiveRangeAcceptsDuplicateFinalSizeAfterFin) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(state.validate_receive_range(/*offset=*/0, /*length=*/5, /*fin=*/true).has_value());
    EXPECT_TRUE(state.peer_send_closed);

    const auto duplicate_fin =
        state.validate_receive_range(/*offset=*/0, /*length=*/5, /*fin=*/true);
    ASSERT_TRUE(duplicate_fin.has_value());

    const auto duplicate_non_fin =
        state.validate_receive_range(/*offset=*/1, /*length=*/3, /*fin=*/false);
    ASSERT_TRUE(duplicate_non_fin.has_value());
}

TEST(QuicStreamsTest, ReceiveRangePastKnownFinalSizeReportsFinalSizeConflict) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(state.validate_receive_range(/*offset=*/0, /*length=*/5, /*fin=*/true).has_value());

    const auto conflict = state.validate_receive_range(/*offset=*/4, /*length=*/2, /*fin=*/false);
    ASSERT_FALSE(conflict.has_value());
    EXPECT_EQ(conflict.error().code, StreamStateErrorCode::final_size_conflict);
}

TEST(QuicStreamsTest, PeerImplicitOpenLimitCheckIgnoresLocalBidiStreams) {
    EXPECT_TRUE(is_peer_implicit_stream_open_allowed_by_limits(
        /*stream_id=*/1, EndpointRole::client, {.bidirectional = 1, .unidirectional = 0}));
    EXPECT_FALSE(is_peer_implicit_stream_open_allowed_by_limits(
        /*stream_id=*/5, EndpointRole::client, {.bidirectional = 1, .unidirectional = 0}));
    EXPECT_TRUE(is_peer_implicit_stream_open_allowed_by_limits(
        /*stream_id=*/3, EndpointRole::client, {.bidirectional = 0, .unidirectional = 1}));
    EXPECT_FALSE(is_peer_implicit_stream_open_allowed_by_limits(
        /*stream_id=*/7, EndpointRole::client, {.bidirectional = 0, .unidirectional = 1}));
    EXPECT_FALSE(is_peer_implicit_stream_open_allowed_by_limits(
        /*stream_id=*/0, EndpointRole::client, {.bidirectional = 8, .unidirectional = 8}));
}

TEST(QuicStreamsTest, StreamStateCarriesFlowControlBookkeepingGroundwork) {
    const auto state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    EXPECT_EQ(state.send_flow_control_limit, 0u);
    EXPECT_EQ(state.send_flow_control_committed, 0u);
    EXPECT_EQ(state.receive_flow_control_limit, 0u);
    EXPECT_EQ(state.receive_flow_control_consumed, 0u);
}

} // namespace
