#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

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
