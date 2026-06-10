#include "src/quic/connection/connection.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <tuple>
#include <vector>

namespace coquic::quic {

namespace {

bool max_data_frame_matches(const std::optional<MaxDataFrame> &candidate,
                            const MaxDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

bool data_blocked_frame_matches(const std::optional<DataBlockedFrame> &candidate,
                                const DataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return candidate->maximum_data == frame.maximum_data;
}

bool max_streams_frame_matches(const std::optional<MaxStreamsFrame> &candidate,
                               const MaxStreamsFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_type, candidate->maximum_streams) ==
           std::tie(frame.stream_type, frame.maximum_streams);
}

StreamControlFrameState *max_streams_state_for(LocalStreamLimitState &state,
                                               StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &state.max_streams_bidi_state
                                                         : &state.max_streams_uni_state;
}

std::optional<MaxStreamsFrame> *pending_max_streams_frame_for(LocalStreamLimitState &state,
                                                              StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &state.pending_max_streams_bidi_frame
                                                         : &state.pending_max_streams_uni_frame;
}

} // namespace

std::uint64_t ConnectionFlowControlState::sendable_bytes(std::uint64_t queued_bytes) const {
    const auto remaining_credit = peer_max_data > highest_sent ? peer_max_data - highest_sent : 0;
    const auto unsent_bytes = queued_bytes > highest_sent ? queued_bytes - highest_sent : 0;
    return std::min(remaining_credit, unsent_bytes);
}

bool ConnectionFlowControlState::should_send_data_blocked(std::uint64_t queued_bytes) const {
    return queued_bytes > peer_max_data;
}

void ConnectionFlowControlState::note_peer_max_data(std::uint64_t maximum_data) {
    if (maximum_data <= peer_max_data) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        // # A receiver MUST accept packets containing an outdated frame, such as
        // # a MAX_DATA frame carrying a smaller maximum data value than one found
        // # in an older packet.
        return;
    }

    peer_max_data = maximum_data;
}

void ConnectionFlowControlState::queue_max_data(std::uint64_t maximum_data) {
    if (maximum_data <= advertised_max_data) {
        return;
    }

    advertised_max_data = maximum_data;
    pending_max_data_frame = MaxDataFrame{
        .maximum_data = maximum_data,
    };
    max_data_state = StreamControlFrameState::pending;
}

std::optional<MaxDataFrame> ConnectionFlowControlState::take_max_data_frame() {
    if (max_data_state != StreamControlFrameState::pending || !pending_max_data_frame.has_value()) {
        return std::nullopt;
    }

    max_data_state = StreamControlFrameState::sent;
    return pending_max_data_frame;
}

void ConnectionFlowControlState::acknowledge_max_data_frame(const MaxDataFrame &frame) {
    if (max_data_frame_matches(pending_max_data_frame, frame)) {
        max_data_state = StreamControlFrameState::acknowledged;
    }
}

void ConnectionFlowControlState::mark_max_data_frame_lost(const MaxDataFrame &frame) {
    if (max_data_state != StreamControlFrameState::acknowledged &&
        max_data_frame_matches(pending_max_data_frame, frame)) {
        max_data_state = StreamControlFrameState::pending;
    }
}

void ConnectionFlowControlState::queue_data_blocked(std::uint64_t maximum_data) {
    if (pending_data_blocked_frame.has_value() &&
        pending_data_blocked_frame->maximum_data == maximum_data &&
        data_blocked_state != StreamControlFrameState::none) {
        return;
    }

    pending_data_blocked_frame = DataBlockedFrame{
        .maximum_data = maximum_data,
    };
    data_blocked_state = StreamControlFrameState::pending;
}

std::optional<DataBlockedFrame> ConnectionFlowControlState::take_data_blocked_frame() {
    if (data_blocked_state != StreamControlFrameState::pending ||
        !pending_data_blocked_frame.has_value()) {
        return std::nullopt;
    }

    data_blocked_state = StreamControlFrameState::sent;
    return pending_data_blocked_frame;
}

void ConnectionFlowControlState::acknowledge_data_blocked_frame(const DataBlockedFrame &frame) {
    if (data_blocked_frame_matches(pending_data_blocked_frame, frame)) {
        data_blocked_state = StreamControlFrameState::acknowledged;
    }
}

void ConnectionFlowControlState::mark_data_blocked_frame_lost(const DataBlockedFrame &frame) {
    if (data_blocked_state != StreamControlFrameState::acknowledged &&
        data_blocked_frame_matches(pending_data_blocked_frame, frame)) {
        data_blocked_state = StreamControlFrameState::pending;
    }
}

void LocalStreamLimitState::initialize(PeerStreamOpenLimits limits) {
    advertised_max_streams_bidi = limits.bidirectional;
    advertised_max_streams_uni = limits.unidirectional;
    pending_max_streams_bidi_frame = std::nullopt;
    max_streams_bidi_state = StreamControlFrameState::none;
    pending_max_streams_uni_frame = std::nullopt;
    max_streams_uni_state = StreamControlFrameState::none;
}

void LocalStreamLimitState::queue_max_streams(StreamLimitType stream_type,
                                              std::uint64_t maximum_streams) {
    auto *advertised_limit = &advertised_max_streams_bidi;
    auto *pending_frame = &pending_max_streams_bidi_frame;
    auto *state = &max_streams_bidi_state;
    if (stream_type == StreamLimitType::unidirectional) {
        advertised_limit = &advertised_max_streams_uni;
        pending_frame = &pending_max_streams_uni_frame;
        state = &max_streams_uni_state;
    }

    if (maximum_streams <= *advertised_limit) {
        return;
    }

    *advertised_limit = maximum_streams;
    *pending_frame = MaxStreamsFrame{
        .stream_type = stream_type,
        .maximum_streams = maximum_streams,
    };
    *state = StreamControlFrameState::pending;
}

std::vector<MaxStreamsFrame> LocalStreamLimitState::take_max_streams_frames() {
    std::vector<MaxStreamsFrame> frames;
    if (max_streams_bidi_state == StreamControlFrameState::pending &&
        pending_max_streams_bidi_frame.has_value()) {
        max_streams_bidi_state = StreamControlFrameState::sent;
        frames.push_back(*pending_max_streams_bidi_frame);
    }
    if (max_streams_uni_state == StreamControlFrameState::pending &&
        pending_max_streams_uni_frame.has_value()) {
        max_streams_uni_state = StreamControlFrameState::sent;
        frames.push_back(*pending_max_streams_uni_frame);
    }

    return frames;
}

void LocalStreamLimitState::acknowledge_max_streams_frame(const MaxStreamsFrame &frame) {
    auto *state = max_streams_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none) {
        return;
    }
    const auto *pending_frame = pending_max_streams_frame_for(*this, frame.stream_type);
    if (!max_streams_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::acknowledged;
}

void LocalStreamLimitState::mark_max_streams_frame_lost(const MaxStreamsFrame &frame) {
    auto *state = max_streams_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none ||
        *state == StreamControlFrameState::acknowledged) {
        return;
    }
    const auto *pending_frame = pending_max_streams_frame_for(*this, frame.stream_type);
    if (!max_streams_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::pending;
}

} // namespace coquic::quic
