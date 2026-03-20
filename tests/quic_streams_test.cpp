#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <vector>

#include "src/quic/streams.h"

namespace {

using coquic::quic::classify_stream_id;
using coquic::quic::EndpointRole;
using coquic::quic::is_peer_implicit_stream_open_allowed_by_limits;
using coquic::quic::make_implicit_stream_state;
using coquic::quic::StreamControlFrameState;
using coquic::quic::StreamDirection;
using coquic::quic::StreamInitiator;
using coquic::quic::StreamOpenLimits;
using coquic::quic::StreamSendFinState;
using coquic::quic::StreamState;
using coquic::quic::StreamStateErrorCode;

std::vector<std::byte> bytes_from_string(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const auto character : text) {
        bytes.push_back(static_cast<std::byte>(character));
    }
    return bytes;
}

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

TEST(QuicStreamsTest, LocalImplicitOpenAllowsOnlyLocallyInitiatedSendStreams) {
    EXPECT_TRUE(
        coquic::quic::is_local_implicit_stream_open_allowed(/*stream_id=*/0, EndpointRole::client));
    EXPECT_TRUE(
        coquic::quic::is_local_implicit_stream_open_allowed(/*stream_id=*/4, EndpointRole::client));
    EXPECT_TRUE(
        coquic::quic::is_local_implicit_stream_open_allowed(/*stream_id=*/2, EndpointRole::client));
    EXPECT_FALSE(
        coquic::quic::is_local_implicit_stream_open_allowed(/*stream_id=*/1, EndpointRole::client));
    EXPECT_FALSE(
        coquic::quic::is_local_implicit_stream_open_allowed(/*stream_id=*/3, EndpointRole::client));
}

TEST(QuicStreamsTest, StreamStateCarriesFlowControlBookkeepingGroundwork) {
    const auto state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    EXPECT_EQ(state.send_flow_control_limit, 0u);
    EXPECT_EQ(state.send_flow_control_committed, 0u);
    EXPECT_EQ(state.receive_flow_control_limit, 0u);
    EXPECT_EQ(state.receive_flow_control_consumed, 0u);
}

TEST(QuicStreamsTest, FlowControlBlocksNewBytesAtPeerMaxStreamData) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    state.flow_control.peer_max_stream_data = 4;
    state.send_buffer.append(bytes_from_string("abcdef"));
    state.flow_control.highest_sent = 0;
    state.send_flow_control_committed = 6;

    EXPECT_EQ(state.sendable_bytes(), 4u);
    EXPECT_TRUE(state.should_send_stream_data_blocked());
}

TEST(QuicStreamsTest, MaxStreamsLimitBlocksSecondLocalBidirectionalStream) {
    StreamOpenLimits limits;
    limits.peer_max_bidirectional = 1;

    EXPECT_TRUE(limits.can_open_local_stream(/*stream_id=*/0, EndpointRole::client));
    EXPECT_FALSE(limits.can_open_local_stream(/*stream_id=*/4, EndpointRole::client));
}

TEST(QuicStreamsTest, LocalStreamOpenRejectsPeerInitiatedIds) {
    StreamOpenLimits limits;
    limits.peer_max_bidirectional = 8;
    limits.peer_max_unidirectional = 8;

    EXPECT_FALSE(limits.can_open_local_stream(/*stream_id=*/1, EndpointRole::client));
    EXPECT_FALSE(limits.can_open_local_stream(/*stream_id=*/3, EndpointRole::client));
    EXPECT_TRUE(limits.can_open_local_stream(/*stream_id=*/2, EndpointRole::client));
}

TEST(QuicStreamsTest, TakeSendFragmentsCarriesFinOnFinalFragment) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    state.send_buffer.append(bytes_from_string("hello"));
    state.send_flow_control_committed = 5;
    ASSERT_TRUE(state.validate_local_send(/*fin=*/true).has_value());
    state.send_final_size = 5;
    state.send_fin_state = coquic::quic::StreamSendFinState::pending;

    const auto fragments = state.take_send_fragments(/*max_bytes=*/16);

    ASSERT_EQ(fragments.size(), 1u);
    EXPECT_EQ(fragments[0].stream_id, 0u);
    EXPECT_EQ(fragments[0].offset, 0u);
    EXPECT_EQ(fragments[0].bytes, bytes_from_string("hello"));
    EXPECT_TRUE(fragments[0].fin);
}

TEST(QuicStreamsTest, TakeSendFragmentsSupportsFinOnlySend) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(state.validate_local_send(/*fin=*/true).has_value());
    state.send_final_size = 0;
    state.send_fin_state = coquic::quic::StreamSendFinState::pending;

    const auto fragments = state.take_send_fragments(/*max_bytes=*/16);

    ASSERT_EQ(fragments.size(), 1u);
    EXPECT_EQ(fragments[0].stream_id, 0u);
    EXPECT_EQ(fragments[0].offset, 0u);
    EXPECT_TRUE(fragments[0].bytes.empty());
    EXPECT_TRUE(fragments[0].fin);
}

TEST(QuicStreamsTest, SendAndReceiveValidationCoverClosedAndOverflowPaths) {
    StreamState send_state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(send_state.validate_local_send(/*fin=*/true).has_value());

    const auto send_closed = send_state.validate_local_send(/*fin=*/false);
    ASSERT_FALSE(send_closed.has_value());
    EXPECT_EQ(send_closed.error().code, StreamStateErrorCode::send_side_closed);

    StreamState receive_state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    receive_state.receive_closed = true;
    const auto receive_closed =
        receive_state.validate_receive_range(/*offset=*/0, /*length=*/1, /*fin=*/false);
    ASSERT_FALSE(receive_closed.has_value());
    EXPECT_EQ(receive_closed.error().code, StreamStateErrorCode::receive_side_closed);

    StreamState overflow_state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(overflow_state
                    .validate_receive_range(std::numeric_limits<std::uint64_t>::max() - 2,
                                            /*length=*/8, /*fin=*/true)
                    .has_value());
    EXPECT_EQ(overflow_state.peer_final_size, std::numeric_limits<std::uint64_t>::max());
}

TEST(QuicStreamsTest, FinalSizeConflictPathsPropagateThroughReceiveAndReset) {
    StreamState final_size_state =
        make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    final_size_state.highest_received_offset = 6;
    const auto final_size_conflict = final_size_state.note_peer_final_size(/*final_size=*/5);
    ASSERT_FALSE(final_size_conflict.has_value());
    EXPECT_EQ(final_size_conflict.error().code, StreamStateErrorCode::final_size_conflict);

    StreamState fin_conflict_state =
        make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    fin_conflict_state.highest_received_offset = 10;
    const auto fin_conflict =
        fin_conflict_state.validate_receive_range(/*offset=*/0, /*length=*/5, /*fin=*/true);
    ASSERT_FALSE(fin_conflict.has_value());
    EXPECT_EQ(fin_conflict.error().code, StreamStateErrorCode::final_size_conflict);

    StreamState reset_conflict_state =
        make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    reset_conflict_state.highest_received_offset = 6;
    const auto reset_conflict = reset_conflict_state.note_peer_reset(coquic::quic::ResetStreamFrame{
        .stream_id = 0,
        .application_protocol_error_code = 9,
        .final_size = 5,
    });
    ASSERT_FALSE(reset_conflict.has_value());
    EXPECT_EQ(reset_conflict.error().code, StreamStateErrorCode::final_size_conflict);
}

TEST(QuicStreamsTest, LocalResetQueuesFinalSizeAndStopsRetransmittingStreamData) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    state.send_buffer.append(bytes_from_string("hello"));
    state.send_flow_control_committed = 5;

    ASSERT_TRUE(state.validate_local_reset(/*application_error_code=*/9).has_value());
    ASSERT_TRUE(state.has_pending_send());

    const auto reset = state.take_reset_frame();
    ASSERT_TRUE(reset.has_value());
    if (!reset.has_value()) {
        GTEST_FAIL() << "expected pending reset frame";
        return;
    }
    const auto reset_frame = reset.value();
    EXPECT_EQ(reset_frame.stream_id, 0u);
    EXPECT_EQ(reset_frame.application_protocol_error_code, 9u);
    EXPECT_EQ(reset_frame.final_size, 5u);
    EXPECT_TRUE(state.take_send_fragments(/*max_bytes=*/16).empty());

    state.mark_send_fragment_lost(coquic::quic::StreamFrameSendFragment{
        .stream_id = 0,
        .offset = 0,
        .bytes = bytes_from_string("hello"),
        .fin = false,
    });
    EXPECT_FALSE(state.has_pending_send());

    state.mark_reset_frame_lost(reset_frame);
    EXPECT_TRUE(state.has_pending_send());
    ASSERT_TRUE(state.take_reset_frame().has_value());
}

TEST(QuicStreamsTest, ResetAndStopSendingRemainIdempotentAfterAcknowledgement) {
    StreamState reset_state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    reset_state.send_buffer.append(bytes_from_string("abc"));
    reset_state.send_flow_control_committed = 3;
    ASSERT_TRUE(reset_state.validate_local_reset(/*application_error_code=*/5).has_value());

    const auto reset = reset_state.take_reset_frame();
    ASSERT_TRUE(reset.has_value());
    EXPECT_TRUE(reset_state.has_outstanding_send());
    const auto reset_frame = reset.value_or(coquic::quic::ResetStreamFrame{});
    reset_state.acknowledge_reset_frame(reset_frame);
    EXPECT_FALSE(reset_state.has_pending_send());
    EXPECT_FALSE(reset_state.has_outstanding_send());
    ASSERT_TRUE(reset_state.validate_local_reset(/*application_error_code=*/6).has_value());
    EXPECT_FALSE(reset_state.take_reset_frame().has_value());
    EXPECT_TRUE(reset_state.note_peer_stop_sending(/*application_error_code=*/7).has_value());

    StreamState stop_state = make_implicit_stream_state(/*stream_id=*/3, EndpointRole::client);
    ASSERT_TRUE(stop_state.validate_local_stop_sending(/*application_error_code=*/8).has_value());

    const auto stop = stop_state.take_stop_sending_frame();
    ASSERT_TRUE(stop.has_value());
    EXPECT_TRUE(stop_state.has_outstanding_send());
    const auto stop_frame = stop.value_or(coquic::quic::StopSendingFrame{});
    stop_state.acknowledge_stop_sending_frame(stop_frame);
    EXPECT_FALSE(stop_state.has_pending_send());
    EXPECT_FALSE(stop_state.has_outstanding_send());
    ASSERT_TRUE(stop_state.validate_local_stop_sending(/*application_error_code=*/9).has_value());
    EXPECT_FALSE(stop_state.take_stop_sending_frame().has_value());
    stop_state.peer_send_closed = true;
    EXPECT_TRUE(stop_state.validate_local_stop_sending(/*application_error_code=*/10).has_value());
}

TEST(QuicStreamsTest, MaxStreamDataFramesTransitionThroughPendingSentLostAndAckedStates) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    state.flow_control.advertised_max_stream_data = 10;
    state.receive_flow_control_limit = 10;

    state.queue_max_stream_data(/*maximum_stream_data=*/10);
    EXPECT_FALSE(state.take_max_stream_data_frame().has_value());

    state.queue_max_stream_data(/*maximum_stream_data=*/20);
    EXPECT_TRUE(state.has_pending_send());
    const auto first = state.take_max_stream_data_frame();
    ASSERT_TRUE(first.has_value());
    EXPECT_TRUE(state.has_outstanding_send());

    const auto first_max_stream_data = first.value_or(coquic::quic::MaxStreamDataFrame{});
    state.mark_max_stream_data_frame_lost(first_max_stream_data);
    EXPECT_TRUE(state.has_pending_send());
    const auto resent = state.take_max_stream_data_frame();
    ASSERT_TRUE(resent.has_value());
    const auto resent_max_stream_data = resent.value_or(coquic::quic::MaxStreamDataFrame{});
    state.acknowledge_max_stream_data_frame(resent_max_stream_data);
    EXPECT_FALSE(state.has_pending_send());
    EXPECT_FALSE(state.has_outstanding_send());
}

TEST(QuicStreamsTest, StreamDataBlockedFramesDeduplicateAndClearWhenPeerCreditCatchesUp) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    state.flow_control.peer_max_stream_data = 4;
    state.send_flow_control_limit = 4;
    state.send_flow_control_committed = 10;

    state.note_peer_max_stream_data(/*maximum_stream_data=*/4);
    EXPECT_EQ(state.send_flow_control_limit, 4u);

    state.queue_stream_data_blocked();
    EXPECT_TRUE(state.has_pending_send());
    ASSERT_TRUE(state.flow_control.pending_stream_data_blocked_frame.has_value());
    state.queue_stream_data_blocked();

    const auto first = state.take_stream_data_blocked_frame();
    ASSERT_TRUE(first.has_value());
    EXPECT_TRUE(state.has_outstanding_send());

    const auto first_stream_data_blocked = first.value_or(coquic::quic::StreamDataBlockedFrame{});
    state.mark_stream_data_blocked_frame_lost(first_stream_data_blocked);
    EXPECT_TRUE(state.has_pending_send());
    const auto resent = state.take_stream_data_blocked_frame();
    ASSERT_TRUE(resent.has_value());
    const auto resent_stream_data_blocked = resent.value_or(coquic::quic::StreamDataBlockedFrame{});
    state.acknowledge_stream_data_blocked_frame(resent_stream_data_blocked);
    EXPECT_FALSE(state.has_outstanding_send());
    EXPECT_EQ(state.flow_control.stream_data_blocked_state, StreamControlFrameState::acknowledged);
    EXPECT_FALSE(state.take_stream_data_blocked_frame().has_value());

    state.note_peer_max_stream_data(/*maximum_stream_data=*/8);
    ASSERT_TRUE(state.flow_control.pending_stream_data_blocked_frame.has_value());
    EXPECT_EQ(state.flow_control.stream_data_blocked_state, StreamControlFrameState::acknowledged);

    state.note_peer_max_stream_data(/*maximum_stream_data=*/12);
    EXPECT_FALSE(state.flow_control.pending_stream_data_blocked_frame.has_value());
    EXPECT_EQ(state.flow_control.stream_data_blocked_state, StreamControlFrameState::none);
}

TEST(QuicStreamsTest, LocalStopQueuesControlFrameAndRejectsSendOnlyStreams) {
    StreamState receive_only = make_implicit_stream_state(/*stream_id=*/3, EndpointRole::client);
    ASSERT_TRUE(receive_only.validate_local_stop_sending(/*application_error_code=*/7).has_value());

    const auto stop = receive_only.take_stop_sending_frame();
    ASSERT_TRUE(stop.has_value());
    if (!stop.has_value()) {
        GTEST_FAIL() << "expected pending stop_sending frame";
        return;
    }
    const auto stop_frame = stop.value();
    EXPECT_EQ(stop_frame.stream_id, 3u);
    EXPECT_EQ(stop_frame.application_protocol_error_code, 7u);

    StreamState send_only = make_implicit_stream_state(/*stream_id=*/2, EndpointRole::client);
    const auto invalid = send_only.validate_local_stop_sending(/*application_error_code=*/7);
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, StreamStateErrorCode::invalid_stream_direction);
}

TEST(QuicStreamsTest, FinFragmentsDrivePendingOutstandingAndAcknowledgedState) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(state.validate_local_send(/*fin=*/true).has_value());
    state.send_final_size = 0;
    state.send_fin_state = StreamSendFinState::pending;

    EXPECT_TRUE(state.has_pending_send());
    const auto fragments = state.take_send_fragments(/*max_bytes=*/16);
    ASSERT_EQ(fragments.size(), 1u);
    EXPECT_TRUE(fragments[0].fin);
    EXPECT_TRUE(state.has_outstanding_send());

    state.acknowledge_send_fragment(fragments[0]);
    EXPECT_EQ(state.send_fin_state, StreamSendFinState::acknowledged);
    EXPECT_FALSE(state.has_outstanding_send());
}

TEST(QuicStreamsTest, PeerResetRecordsFinalSizeAndRejectsSendOnlyStreams) {
    StreamState bidirectional = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    ASSERT_TRUE(bidirectional
                    .note_peer_reset(coquic::quic::ResetStreamFrame{
                        .stream_id = 0,
                        .application_protocol_error_code = 11,
                        .final_size = 5,
                    })
                    .has_value());
    EXPECT_TRUE(bidirectional.peer_send_closed);
    EXPECT_EQ(bidirectional.peer_final_size, 5u);

    StreamState send_only = make_implicit_stream_state(/*stream_id=*/2, EndpointRole::client);
    const auto invalid = send_only.note_peer_reset(coquic::quic::ResetStreamFrame{
        .stream_id = 2,
        .application_protocol_error_code = 11,
        .final_size = 0,
    });
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, StreamStateErrorCode::invalid_stream_direction);
}

TEST(QuicStreamsTest, PeerStopQueuesAutomaticResetForActiveSendSide) {
    StreamState state = make_implicit_stream_state(/*stream_id=*/0, EndpointRole::client);
    state.send_buffer.append(bytes_from_string("abc"));
    state.send_flow_control_committed = 3;

    ASSERT_TRUE(state.note_peer_stop_sending(/*application_error_code=*/13).has_value());

    const auto reset = state.take_reset_frame();
    ASSERT_TRUE(reset.has_value());
    if (!reset.has_value()) {
        GTEST_FAIL() << "expected pending reset frame";
        return;
    }
    const auto reset_frame = reset.value();
    EXPECT_EQ(reset_frame.stream_id, 0u);
    EXPECT_EQ(reset_frame.application_protocol_error_code, 13u);
    EXPECT_EQ(reset_frame.final_size, 3u);

    StreamState receive_only = make_implicit_stream_state(/*stream_id=*/3, EndpointRole::client);
    const auto invalid = receive_only.note_peer_stop_sending(/*application_error_code=*/13);
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, StreamStateErrorCode::invalid_stream_direction);
}

} // namespace
