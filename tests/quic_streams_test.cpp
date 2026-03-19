#include <gtest/gtest.h>

#include <cstdint>

#include "src/quic/streams.h"

namespace {

using coquic::quic::classify_stream_id;
using coquic::quic::EndpointRole;
using coquic::quic::is_implicit_stream_open_allowed;
using coquic::quic::make_implicit_stream_state;
using coquic::quic::StreamDirection;
using coquic::quic::StreamInitiator;
using coquic::quic::StreamState;

TEST(QuicStreamsTest, ClassifiesInitiatorAndDirectionFromStreamId) {
    EXPECT_EQ(classify_stream_id(/*stream_id=*/0, EndpointRole::client).initiator,
              StreamInitiator::local);
    EXPECT_EQ(classify_stream_id(/*stream_id=*/0, EndpointRole::client).direction,
              StreamDirection::bidirectional);
    EXPECT_EQ(classify_stream_id(/*stream_id=*/3, EndpointRole::client).direction,
              StreamDirection::unidirectional);
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

TEST(QuicStreamsTest, ImplicitOpenLegalityRespectsPeerStreamLimits) {
    EXPECT_TRUE(is_implicit_stream_open_allowed(/*stream_id=*/1, EndpointRole::client,
                                                {.bidirectional = 1, .unidirectional = 0}));
    EXPECT_FALSE(is_implicit_stream_open_allowed(/*stream_id=*/5, EndpointRole::client,
                                                 {.bidirectional = 1, .unidirectional = 0}));
    EXPECT_TRUE(is_implicit_stream_open_allowed(/*stream_id=*/3, EndpointRole::client,
                                                {.bidirectional = 0, .unidirectional = 1}));
    EXPECT_FALSE(is_implicit_stream_open_allowed(/*stream_id=*/7, EndpointRole::client,
                                                 {.bidirectional = 0, .unidirectional = 1}));
    EXPECT_FALSE(is_implicit_stream_open_allowed(/*stream_id=*/0, EndpointRole::client,
                                                 {.bidirectional = 8, .unidirectional = 8}));
}

} // namespace
