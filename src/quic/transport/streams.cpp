#include "src/quic/transport/streams.h"

#include <algorithm>
#include <limits>
#include <tuple>

namespace coquic::quic {
namespace {

std::uint64_t saturating_add(std::uint64_t lhs, std::size_t rhs) {
    const auto rhs64 = static_cast<std::uint64_t>(rhs);
    const auto max = std::numeric_limits<std::uint64_t>::max();
    if (rhs64 > max - lhs) {
        return max;
    }

    return lhs + rhs64;
}

bool reset_frame_matches(const std::optional<ResetStreamFrame> &candidate,
                         const ResetStreamFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code,
                    candidate->final_size) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code, frame.final_size);
}

bool stop_sending_frame_matches(const std::optional<StopSendingFrame> &candidate,
                                const StopSendingFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->application_protocol_error_code) ==
           std::tie(frame.stream_id, frame.application_protocol_error_code);
}

bool max_stream_data_frame_matches(const std::optional<MaxStreamDataFrame> &candidate,
                                   const MaxStreamDataFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

bool stream_data_blocked_frame_matches(const std::optional<StreamDataBlockedFrame> &candidate,
                                       const StreamDataBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_id, candidate->maximum_stream_data) ==
           std::tie(frame.stream_id, frame.maximum_stream_data);
}

bool streams_blocked_frame_matches(const std::optional<StreamsBlockedFrame> &candidate,
                                   const StreamsBlockedFrame &frame) {
    if (!candidate.has_value()) {
        return false;
    }

    return std::tie(candidate->stream_type, candidate->maximum_streams) ==
           std::tie(frame.stream_type, frame.maximum_streams);
}

StreamControlFrameState *streams_blocked_state_for(StreamOpenLimits &limits,
                                                   StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional ? &limits.streams_blocked_bidi_state
                                                         : &limits.streams_blocked_uni_state;
}

std::optional<StreamsBlockedFrame> *pending_streams_blocked_frame_for(StreamOpenLimits &limits,
                                                                      StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional
               ? &limits.pending_streams_blocked_bidi_frame
               : &limits.pending_streams_blocked_uni_frame;
}

const std::optional<StreamsBlockedFrame> *
pending_streams_blocked_frame_for(const StreamOpenLimits &limits, StreamLimitType stream_type) {
    return stream_type == StreamLimitType::bidirectional
               ? &limits.pending_streams_blocked_bidi_frame
               : &limits.pending_streams_blocked_uni_frame;
}

} // namespace

bool StreamFrameSendFragment::has_cached_stream_frame_header() const {
    return cached_stream_frame_header_length != 0 &&
           cached_stream_frame_header_stream_id == stream_id &&
           cached_stream_frame_header_offset == offset &&
           cached_stream_frame_header_payload_size == bytes.size() &&
           cached_stream_frame_header_fin == fin;
}

void StreamFrameSendFragment::prime_stream_frame_header_cache() const {
    if (has_cached_stream_frame_header()) {
        return;
    }

    std::size_t header_offset = 0;
    cached_stream_frame_header_bytes[header_offset++] =
        std::byte{static_cast<std::uint8_t>(0x0e | (fin ? 0x01u : 0x00u))};

    const auto append_varint = [&](std::uint64_t value) {
        const auto written =
            encode_varint_into(
                std::span<std::byte>(cached_stream_frame_header_bytes).subspan(header_offset),
                value)
                .value();
        header_offset += written;
    };
    append_varint(stream_id);
    append_varint(offset);
    append_varint(bytes.size());

    cached_stream_frame_header_length = header_offset;
    cached_stream_frame_header_stream_id = stream_id;
    cached_stream_frame_header_offset = offset;
    cached_stream_frame_header_payload_size = bytes.size();
    cached_stream_frame_header_fin = fin;
}

std::span<const std::byte> StreamFrameSendFragment::stream_frame_header_bytes() const {
    prime_stream_frame_header_cache();
    return std::span<const std::byte>(cached_stream_frame_header_bytes.data(),
                                      cached_stream_frame_header_length);
}

std::size_t StreamFrameSendFragment::stream_frame_wire_size() const {
    prime_stream_frame_header_cache();
    return cached_stream_frame_header_length + bytes.size();
}

std::size_t StreamFrameSendMetadata::stream_frame_wire_size() const {
    return std::size_t{1} + encoded_varint_size(stream_id) + encoded_varint_size(offset) +
           encoded_varint_size(length) + length;
}

StreamFrameSendMetadata stream_frame_send_metadata(const StreamFrameSendFragment &fragment) {
    return StreamFrameSendMetadata{
        .stream_id = fragment.stream_id,
        .offset = fragment.offset,
        .length = fragment.bytes.size(),
        .fin = fragment.fin,
        .consumes_flow_control = fragment.consumes_flow_control,
    };
}

StreamIdInfo classify_stream_id(std::uint64_t stream_id, EndpointRole local_role) {
    const auto initiator_bit = (stream_id & 0x01u);
    const auto direction_bit = (stream_id & 0x02u);
    const auto local_is_client = local_role == EndpointRole::client;
    const auto stream_is_client_initiated = initiator_bit == 0;
    const auto local_is_initiator = local_is_client == stream_is_client_initiated;
    const auto direction =
        direction_bit == 0 ? StreamDirection::bidirectional : StreamDirection::unidirectional;

    const auto local_can_send = direction == StreamDirection::bidirectional || local_is_initiator;
    const auto local_can_receive =
        direction == StreamDirection::bidirectional || !local_is_initiator;

    return StreamIdInfo{
        .initiator = local_is_initiator ? StreamInitiator::local : StreamInitiator::peer,
        .direction = direction,
        .local_can_send = local_can_send,
        .local_can_receive = local_can_receive,
    };
}

bool is_local_implicit_stream_open_allowed(std::uint64_t stream_id, EndpointRole local_role) {
    const auto id_info = classify_stream_id(stream_id, local_role);
    return id_info.initiator == StreamInitiator::local;
}

bool is_peer_implicit_stream_open_allowed_by_limits(std::uint64_t stream_id,
                                                    EndpointRole local_role,
                                                    PeerStreamOpenLimits limits) {
    const auto id_info = classify_stream_id(stream_id, local_role);
    if (id_info.initiator != StreamInitiator::peer) {
        return false;
    }

    const auto stream_index = stream_id >> 2u;
    if (id_info.direction == StreamDirection::bidirectional) {
        return stream_index < limits.bidirectional;
    }

    return stream_index < limits.unidirectional;
}

bool StreamOpenLimits::can_open_local_stream(std::uint64_t stream_id,
                                             EndpointRole local_role) const {
    if (!is_local_implicit_stream_open_allowed(stream_id, local_role)) {
        return false;
    }

    const auto id_info = classify_stream_id(stream_id, local_role);
    const auto stream_index = stream_id >> 2u;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # Endpoints MUST NOT exceed the limit set by their peer.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.11
    // # An endpoint MUST NOT open more streams than permitted by the current
    // # stream limit set by its peer.
    if (id_info.direction == StreamDirection::bidirectional) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
        // # Endpoints MUST NOT exceed the limit set by their peer.
        return stream_index < peer_max_bidirectional;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # Endpoints MUST NOT exceed the limit set by their peer.
    return stream_index < peer_max_unidirectional;
}

void StreamOpenLimits::queue_streams_blocked(StreamLimitType stream_type) {
    const auto maximum_streams = stream_type == StreamLimitType::bidirectional
                                     ? peer_max_bidirectional
                                     : peer_max_unidirectional;
    auto *pending_frame = pending_streams_blocked_frame_for(*this, stream_type);
    auto *state = streams_blocked_state_for(*this, stream_type);
    if (pending_frame->has_value() && (*pending_frame)->maximum_streams == maximum_streams &&
        *state != StreamControlFrameState::none) {
        return;
    }

    *pending_frame = StreamsBlockedFrame{
        .stream_type = stream_type,
        .maximum_streams = maximum_streams,
    };
    *state = StreamControlFrameState::pending;
}

std::vector<StreamsBlockedFrame> StreamOpenLimits::take_streams_blocked_frames() {
    std::vector<StreamsBlockedFrame> frames;
    if (streams_blocked_bidi_state == StreamControlFrameState::pending &&
        pending_streams_blocked_bidi_frame.has_value()) {
        streams_blocked_bidi_state = StreamControlFrameState::sent;
        frames.push_back(*pending_streams_blocked_bidi_frame);
    }
    if (streams_blocked_uni_state == StreamControlFrameState::pending &&
        pending_streams_blocked_uni_frame.has_value()) {
        streams_blocked_uni_state = StreamControlFrameState::sent;
        frames.push_back(*pending_streams_blocked_uni_frame);
    }

    return frames;
}

void StreamOpenLimits::acknowledge_streams_blocked_frame(const StreamsBlockedFrame &frame) {
    auto *state = streams_blocked_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none) {
        return;
    }
    const auto *pending_frame = pending_streams_blocked_frame_for(*this, frame.stream_type);
    if (!streams_blocked_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::acknowledged;
}

void StreamOpenLimits::mark_streams_blocked_frame_lost(const StreamsBlockedFrame &frame) {
    auto *state = streams_blocked_state_for(*this, frame.stream_type);
    if (*state == StreamControlFrameState::none ||
        *state == StreamControlFrameState::acknowledged) {
        return;
    }
    const auto *pending_frame = pending_streams_blocked_frame_for(*this, frame.stream_type);
    if (!streams_blocked_frame_matches(*pending_frame, frame)) {
        return;
    }

    *state = StreamControlFrameState::pending;
}

void StreamOpenLimits::note_peer_max_streams(StreamLimitType stream_type,
                                             std::uint64_t maximum_streams) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.6
    // # MAX_STREAMS frames that do not increase the stream limit MUST be
    // # ignored.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.11
    // # MAX_STREAMS frames that do not increase the stream limit MUST be
    // # ignored.
    auto *current_limit = &peer_max_bidirectional;
    if (stream_type == StreamLimitType::unidirectional) {
        current_limit = &peer_max_unidirectional;
    }

    if (maximum_streams <= *current_limit) {
        return;
    }

    *current_limit = maximum_streams;
    const auto *pending_frame = pending_streams_blocked_frame_for(*this, stream_type);
    if (!pending_frame->has_value() || (*pending_frame)->maximum_streams >= maximum_streams) {
        return;
    }

    *pending_streams_blocked_frame_for(*this, stream_type) = std::nullopt;
    *streams_blocked_state_for(*this, stream_type) = StreamControlFrameState::none;
}

StreamStateResult<bool> StreamState::validate_local_send(bool fin) {
    if (!id_info.local_can_send) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::invalid_stream_direction,
                                                stream_id);
    }

    if (send_closed) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
        // # An endpoint MUST NOT send data on a stream at or beyond the final size.
        return StreamStateResult<bool>::failure(StreamStateErrorCode::send_side_closed, stream_id);
    }

    if (fin) {
        send_closed = true;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> StreamState::validate_local_reset(std::uint64_t application_error_code) {
    if (!id_info.local_can_send) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::invalid_stream_direction,
                                                stream_id);
    }

    if (send_fin_state == StreamSendFinState::acknowledged) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::send_side_closed, stream_id);
    }

    if (reset_state == StreamControlFrameState::none) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        // # The content of a RESET_STREAM frame MUST NOT change when it is
        // # sent again.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
        // # If any outstanding data is declared lost, the endpoint SHOULD send
        // # a RESET_STREAM frame instead of retransmitting the data.
        pending_reset_frame = ResetStreamFrame{
            .stream_id = stream_id,
            .application_protocol_error_code = application_error_code,
            .final_size = send_flow_control_committed,
        };
    }
    reset_state = reset_state == StreamControlFrameState::acknowledged
                      ? StreamControlFrameState::acknowledged
                      : StreamControlFrameState::pending;
    send_closed = true;
    send_final_size = send_flow_control_committed;
    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool>
StreamState::validate_local_stop_sending(std::uint64_t application_error_code) {
    if (!id_info.local_can_receive) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::invalid_stream_direction,
                                                stream_id);
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    // # STOP_SENDING SHOULD only be sent for a stream that has not been reset
    // # by the peer.
    if (peer_reset_received || peer_send_closed) {
        return StreamStateResult<bool>::success(true);
    }

    if (stop_sending_state == StreamControlFrameState::none) {
        pending_stop_sending_frame = StopSendingFrame{
            .stream_id = stream_id,
            .application_protocol_error_code = application_error_code,
        };
    }
    stop_sending_state = stop_sending_state == StreamControlFrameState::acknowledged
                             ? StreamControlFrameState::acknowledged
                             : StreamControlFrameState::pending;
    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> StreamState::validate_receive_range(std::uint64_t offset,
                                                            std::size_t length, bool fin) {
    if (!id_info.local_can_receive) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::invalid_stream_direction,
                                                stream_id);
    }

    if (receive_closed) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::receive_side_closed,
                                                stream_id);
    }

    const auto range_end = saturating_add(offset, length);
    if (range_end > flow_control.advertised_max_stream_data) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.10
        // # An endpoint MUST terminate a connection with an error of type
        // # FLOW_CONTROL_ERROR if it receives more data than the largest
        // # maximum stream data that it has sent for the affected stream.
        return StreamStateResult<bool>::failure(StreamStateErrorCode::flow_control_violation,
                                                stream_id);
    }
    if (peer_final_size.has_value() && range_end > *peer_final_size) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::final_size_conflict,
                                                stream_id);
    }

    highest_received_offset = std::max(highest_received_offset, range_end);

    if (fin) {
        const auto final_size_result = note_peer_final_size(range_end);
        if (!final_size_result.has_value()) {
            return final_size_result;
        }
        peer_send_closed = true;
    }

    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> StreamState::note_peer_final_size(std::uint64_t final_size) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # Once a final size for a stream is known, it cannot change.
    if (peer_final_size.has_value() && *peer_final_size != final_size) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
        // # Once a final size for a stream is known, it cannot change.
        return StreamStateResult<bool>::failure(StreamStateErrorCode::final_size_conflict,
                                                stream_id);
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
    // # A receiver SHOULD treat receipt of data at or beyond the final
    // # size as an error of type FINAL_SIZE_ERROR, even after a stream
    // # is closed.
    if (highest_received_offset > final_size) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.5
        // # A receiver SHOULD treat receipt of data at or beyond the
        // # final size as an error of type FINAL_SIZE_ERROR, even after a stream
        // # is closed.
        return StreamStateResult<bool>::failure(StreamStateErrorCode::final_size_conflict,
                                                stream_id);
    }

    peer_final_size = final_size;
    //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
    // # An endpoint SHOULD stop sending MAX_STREAM_DATA frames when the
    // # receiving part of the stream enters a "Size Known" or "Reset Recvd"
    // # state.
    flow_control.pending_max_stream_data_frame = std::nullopt;
    flow_control.max_stream_data_state = StreamControlFrameState::none;
    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> StreamState::note_peer_reset(const ResetStreamFrame &frame) {
    if (!id_info.local_can_receive) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::invalid_stream_direction,
                                                stream_id);
    }

    const auto noted = note_peer_final_size(frame.final_size);
    if (!noted.has_value()) {
        return noted;
    }

    peer_send_closed = true;
    peer_reset_received = true;
    receive_buffer = ReliableReceiveBuffer{};
    pending_stop_sending_frame = std::nullopt;
    stop_sending_state = StreamControlFrameState::none;
    return StreamStateResult<bool>::success(true);
}

StreamStateResult<bool> StreamState::note_peer_stop_sending(std::uint64_t application_error_code) {
    if (!id_info.local_can_send) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::invalid_stream_direction,
                                                stream_id);
    }

    if (reset_state != StreamControlFrameState::none ||
        send_fin_state == StreamSendFinState::acknowledged) {
        return StreamStateResult<bool>::success(true);
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    // # An endpoint that receives a STOP_SENDING frame
    // # MUST send a RESET_STREAM frame if the stream is in the "Ready" or
    // # "Send" state.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.5
    // # An endpoint SHOULD copy the error code from the STOP_SENDING frame to
    // # the RESET_STREAM frame it sends, but it can use any application error
    // # code.
    return validate_local_reset(application_error_code);
}

bool StreamState::has_pending_send() const {
    if (reset_state == StreamControlFrameState::pending ||
        stop_sending_state == StreamControlFrameState::pending ||
        flow_control.max_stream_data_state == StreamControlFrameState::pending ||
        flow_control.stream_data_blocked_state == StreamControlFrameState::pending) {
        return true;
    }

    if (reset_state != StreamControlFrameState::none) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
        // # A sender MUST NOT send any of these frames from a terminal state
        // # ("Data Recvd" or "Reset Recvd").
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
        // # A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for
        // # a stream in the "Reset Sent" state or any terminal state -- that
        // # is, after sending a RESET_STREAM frame.
        return false;
    }

    bool fin_sendable = false;
    if (send_fin_state == StreamSendFinState::pending && send_final_size.has_value()) {
        fin_sendable = *send_final_size <= flow_control.peer_max_stream_data &&
                       !send_buffer.has_pending_data();
    }
    if (send_buffer.has_lost_data()) {
        return true;
    }
    if (sendable_bytes() != 0) {
        return true;
    }

    return fin_sendable;
}

bool StreamState::has_outstanding_send() const {
    if (reset_state == StreamControlFrameState::sent ||
        stop_sending_state == StreamControlFrameState::sent ||
        flow_control.max_stream_data_state == StreamControlFrameState::sent ||
        flow_control.stream_data_blocked_state == StreamControlFrameState::sent) {
        return true;
    }

    if (reset_state != StreamControlFrameState::none) {
        return false;
    }

    return send_buffer.has_outstanding_data() || send_fin_state == StreamSendFinState::sent;
}

std::uint64_t StreamState::sendable_bytes() const {
    const auto remaining_credit =
        flow_control.peer_max_stream_data > flow_control.highest_sent
            ? flow_control.peer_max_stream_data - flow_control.highest_sent
            : 0;
    const auto unsent_bytes = send_flow_control_committed > flow_control.highest_sent
                                  ? send_flow_control_committed - flow_control.highest_sent
                                  : 0;
    return std::min(remaining_credit, unsent_bytes);
}

std::uint64_t StreamState::next_send_offset_for_budget(bool prefer_fresh_data) const {
    if (prefer_fresh_data) {
        if (const auto unsent_offset = send_buffer.first_unsent_offset();
            unsent_offset.has_value()) {
            return *unsent_offset;
        }
        if (const auto lost_offset = send_buffer.first_lost_offset(); lost_offset.has_value()) {
            return *lost_offset;
        }
        return flow_control.highest_sent;
    }

    if (const auto lost_offset = send_buffer.first_lost_offset(); lost_offset.has_value()) {
        return *lost_offset;
    }
    if (const auto unsent_offset = send_buffer.first_unsent_offset(); unsent_offset.has_value()) {
        return *unsent_offset;
    }
    return flow_control.highest_sent;
}

bool StreamState::should_send_stream_data_blocked() const {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
    // # A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for
    // # a stream in the "Reset Sent" state or any terminal state -- that
    // # is, after sending a RESET_STREAM frame.
    return id_info.local_can_send && reset_state == StreamControlFrameState::none &&
           send_flow_control_committed > flow_control.peer_max_stream_data;
}

void StreamState::note_peer_max_stream_data(std::uint64_t maximum_stream_data) {
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
    // # A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames that do
    // # not increase flow control limits.
    if (maximum_stream_data <= flow_control.peer_max_stream_data) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
        // # A sender MUST ignore any MAX_STREAM_DATA or MAX_DATA frames that do
        // # not increase flow control limits.
        return;
    }

    flow_control.peer_max_stream_data = maximum_stream_data;
    send_flow_control_limit = maximum_stream_data;
    if (send_flow_control_committed <= flow_control.peer_max_stream_data) {
        flow_control.pending_stream_data_blocked_frame = std::nullopt;
        flow_control.stream_data_blocked_state = StreamControlFrameState::none;
    }
}

void StreamState::queue_max_stream_data(std::uint64_t maximum_stream_data) {
    if (peer_final_size.has_value() || peer_reset_received) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        // # An endpoint SHOULD stop sending MAX_STREAM_DATA frames when the
        // # receiving part of the stream enters a "Size Known" or "Reset Recvd"
        // # state.
        return;
    }
    if (maximum_stream_data <= flow_control.advertised_max_stream_data) {
        return;
    }

    flow_control.advertised_max_stream_data = maximum_stream_data;
    receive_flow_control_limit = maximum_stream_data;
    flow_control.pending_max_stream_data_frame = MaxStreamDataFrame{
        .stream_id = stream_id,
        .maximum_stream_data = maximum_stream_data,
    };
    flow_control.max_stream_data_state = StreamControlFrameState::pending;
}

std::optional<MaxStreamDataFrame> StreamState::take_max_stream_data_frame() {
    if (flow_control.max_stream_data_state != StreamControlFrameState::pending ||
        !flow_control.pending_max_stream_data_frame.has_value()) {
        return std::nullopt;
    }

    flow_control.max_stream_data_state = StreamControlFrameState::sent;
    return flow_control.pending_max_stream_data_frame;
}

void StreamState::acknowledge_max_stream_data_frame(const MaxStreamDataFrame &frame) {
    if (max_stream_data_frame_matches(flow_control.pending_max_stream_data_frame, frame)) {
        flow_control.max_stream_data_state = StreamControlFrameState::acknowledged;
    }
}

void StreamState::mark_max_stream_data_frame_lost(const MaxStreamDataFrame &frame) {
    if (flow_control.max_stream_data_state != StreamControlFrameState::acknowledged &&
        max_stream_data_frame_matches(flow_control.pending_max_stream_data_frame, frame)) {
        flow_control.max_stream_data_state = StreamControlFrameState::pending;
    }
}

void StreamState::queue_stream_data_blocked() {
    if (!should_send_stream_data_blocked()) {
        return;
    }
    if (flow_control.pending_stream_data_blocked_frame.has_value()) {
        const auto same_maximum =
            flow_control.pending_stream_data_blocked_frame->maximum_stream_data ==
            flow_control.peer_max_stream_data;
        const auto already_tracked =
            flow_control.stream_data_blocked_state != StreamControlFrameState::none;
        if (same_maximum && already_tracked) {
            return;
        }
    }

    flow_control.pending_stream_data_blocked_frame = StreamDataBlockedFrame{
        .stream_id = stream_id,
        .maximum_stream_data = flow_control.peer_max_stream_data,
    };
    //= https://www.rfc-editor.org/rfc/rfc9000#section-19.13
    // # A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it
    // # wishes to send data but is unable to do so due to stream-level flow
    // # control.
    //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
    // # A sender SHOULD send a
    // # STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver
    // # that it has data to write but is blocked by flow control limits.
    flow_control.stream_data_blocked_state = StreamControlFrameState::pending;
}

std::optional<StreamDataBlockedFrame> StreamState::take_stream_data_blocked_frame() {
    if (flow_control.stream_data_blocked_state != StreamControlFrameState::pending ||
        !flow_control.pending_stream_data_blocked_frame.has_value()) {
        return std::nullopt;
    }

    flow_control.stream_data_blocked_state = StreamControlFrameState::sent;
    return flow_control.pending_stream_data_blocked_frame;
}

void StreamState::acknowledge_stream_data_blocked_frame(const StreamDataBlockedFrame &frame) {
    if (stream_data_blocked_frame_matches(flow_control.pending_stream_data_blocked_frame, frame)) {
        flow_control.stream_data_blocked_state = StreamControlFrameState::acknowledged;
    }
}

void StreamState::mark_stream_data_blocked_frame_lost(const StreamDataBlockedFrame &frame) {
    if (flow_control.stream_data_blocked_state != StreamControlFrameState::acknowledged &&
        stream_data_blocked_frame_matches(flow_control.pending_stream_data_blocked_frame, frame)) {
        flow_control.stream_data_blocked_state = StreamControlFrameState::pending;
    }
}

std::optional<ResetStreamFrame> StreamState::take_reset_frame() {
    if (reset_state != StreamControlFrameState::pending || !pending_reset_frame.has_value()) {
        return std::nullopt;
    }

    reset_state = StreamControlFrameState::sent;
    return pending_reset_frame;
}

std::optional<StopSendingFrame> StreamState::take_stop_sending_frame() {
    if (stop_sending_state != StreamControlFrameState::pending ||
        !pending_stop_sending_frame.has_value()) {
        return std::nullopt;
    }

    stop_sending_state = StreamControlFrameState::sent;
    return pending_stop_sending_frame;
}

std::vector<StreamFrameSendFragment> StreamState::take_send_fragments(std::size_t max_bytes) {
    return take_send_fragments(StreamSendBudget{
        .packet_bytes = max_bytes,
    });
}

std::vector<StreamFrameSendFragment> StreamState::take_send_fragments(StreamSendBudget budget) {
    std::vector<StreamFrameSendFragment> fragments;
    append_send_fragments(budget, fragments);
    return fragments;
}

void StreamState::append_send_fragments(StreamSendBudget budget,
                                        std::vector<StreamFrameSendFragment> &fragments) {
    if (reset_state != StreamControlFrameState::none) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
        // # A sender MUST NOT send any of these frames from a terminal state
        // # ("Data Recvd" or "Reset Recvd").
        //= https://www.rfc-editor.org/rfc/rfc9000#section-3.3
        // # A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for
        // # a stream in the "Reset Sent" state or any terminal state -- that
        // # is, after sending a RESET_STREAM frame.
        return;
    }

    const auto initial_fragment_count = fragments.size();
    auto remaining_bytes = budget.packet_bytes;
    const auto append_fragment = [&](ByteRange range, bool consumes_flow_control) {
        const auto range_end = saturating_add(range.offset, range.bytes.size());
        bool fin = false;
        if (send_fin_state == StreamSendFinState::pending && send_final_size.has_value()) {
            fin = range_end == *send_final_size;
        }
        fragments.push_back(StreamFrameSendFragment{
            .stream_id = stream_id,
            .offset = range.offset,
            .bytes = std::move(range.bytes),
            .fin = fin,
            .consumes_flow_control = consumes_flow_control,
        });
        fragments.back().prime_stream_frame_header_cache();
        if (fin) {
            send_fin_state = StreamSendFinState::sent;
        }
    };

    const auto append_lost_ranges = [&]() {
        send_buffer.consume_lost_ranges(remaining_bytes, std::nullopt, [&](ByteRange range) {
            //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
            // # The data at a given offset MUST NOT change if it is sent multiple times
            append_fragment(std::move(range), /*consumes_flow_control=*/false);
        });
    };
    const auto append_new_ranges = [&]() {
        const auto capped_new_bytes =
            std::min<std::uint64_t>(budget.new_bytes, static_cast<std::uint64_t>(remaining_bytes));
        auto new_remaining_bytes = static_cast<std::size_t>(capped_new_bytes);
        //= https://www.rfc-editor.org/rfc/rfc9000#section-2.2
        // # An endpoint MUST NOT send data on any stream without ensuring that it
        // # is within the flow control limits set by its peer.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-4.1
        // # Senders MUST NOT send data in excess of either limit.
        //= https://www.rfc-editor.org/rfc/rfc9000#section-19.10
        // # The data sent on a stream MUST NOT exceed the largest maximum
        // # stream data value advertised by the receiver.
        send_buffer.consume_unsent_ranges(
            new_remaining_bytes, flow_control.peer_max_stream_data, [&](ByteRange range) {
                const auto range_end = saturating_add(range.offset, range.bytes.size());
                flow_control.highest_sent = std::max(flow_control.highest_sent, range_end);
                remaining_bytes -= range.bytes.size();
                append_fragment(std::move(range), /*consumes_flow_control=*/true);
            });
    };

    if (budget.prefer_fresh_data) {
        append_new_ranges();
        append_lost_ranges();
    } else {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        // # Endpoints SHOULD prioritize retransmission of data over sending new
        // # data, unless priorities specified by the application indicate otherwise;
        // # see Section 2.3.
        append_lost_ranges();
        append_new_ranges();
    }

    bool fin_only_sendable = false;
    if (send_fin_state == StreamSendFinState::pending && send_final_size.has_value()) {
        fin_only_sendable = !send_buffer.has_pending_data() &&
                            *send_final_size <= flow_control.peer_max_stream_data;
    }
    if (fragments.size() == initial_fragment_count && fin_only_sendable) {
        fragments.push_back(StreamFrameSendFragment{
            .stream_id = stream_id,
            .offset = *send_final_size,
            .bytes = {},
            .fin = true,
            .consumes_flow_control = false,
        });
        fragments.back().prime_stream_frame_header_cache();
        send_fin_state = StreamSendFinState::sent;
    }
}

void StreamState::acknowledge_reset_frame(const ResetStreamFrame &frame) {
    if (reset_frame_matches(pending_reset_frame, frame)) {
        reset_state = StreamControlFrameState::acknowledged;
    }
}

void StreamState::mark_reset_frame_lost(const ResetStreamFrame &frame) {
    if (reset_state != StreamControlFrameState::acknowledged &&
        reset_frame_matches(pending_reset_frame, frame)) {
        //= https://www.rfc-editor.org/rfc/rfc9000#section-13.3
        // # The content of a RESET_STREAM frame MUST NOT change when it is
        // # sent again.
        reset_state = StreamControlFrameState::pending;
    }
}

void StreamState::acknowledge_stop_sending_frame(const StopSendingFrame &frame) {
    if (stop_sending_frame_matches(pending_stop_sending_frame, frame)) {
        stop_sending_state = StreamControlFrameState::acknowledged;
    }
}

void StreamState::mark_stop_sending_frame_lost(const StopSendingFrame &frame) {
    if (stop_sending_state != StreamControlFrameState::acknowledged &&
        stop_sending_frame_matches(pending_stop_sending_frame, frame)) {
        stop_sending_state = StreamControlFrameState::pending;
    }
}

void StreamState::acknowledge_send_fragment(const StreamFrameSendFragment &fragment) {
    acknowledge_send_metadata(stream_frame_send_metadata(fragment));
}

void StreamState::acknowledge_send_metadata(const StreamFrameSendMetadata &metadata) {
    if (reset_state != StreamControlFrameState::none) {
        return;
    }
    send_buffer.acknowledge(metadata.offset, metadata.length);
    if (metadata.fin) {
        send_fin_state = StreamSendFinState::acknowledged;
    }
}

void StreamState::mark_send_fragment_sent(const StreamFrameSendFragment &fragment) {
    mark_send_metadata_sent(stream_frame_send_metadata(fragment));
}

void StreamState::mark_send_metadata_sent(const StreamFrameSendMetadata &metadata) {
    if (reset_state != StreamControlFrameState::none) {
        return;
    }

    send_buffer.mark_sent(metadata.offset, metadata.length);
    if (metadata.fin && send_fin_state != StreamSendFinState::acknowledged) {
        send_fin_state = StreamSendFinState::sent;
    }
}

void StreamState::mark_send_fragment_lost(const StreamFrameSendFragment &fragment) {
    mark_send_metadata_lost(stream_frame_send_metadata(fragment));
}

void StreamState::mark_send_metadata_lost(const StreamFrameSendMetadata &metadata) {
    if (reset_state != StreamControlFrameState::none) {
        return;
    }
    send_buffer.mark_lost(metadata.offset, metadata.length);
    if (metadata.fin) {
        send_fin_state = StreamSendFinState::pending;
    }
}

void StreamState::restore_send_fragment(const StreamFrameSendFragment &fragment) {
    restore_send_metadata(stream_frame_send_metadata(fragment));
}

void StreamState::restore_send_metadata(const StreamFrameSendMetadata &metadata) {
    if (reset_state != StreamControlFrameState::none) {
        return;
    }

    if (metadata.consumes_flow_control) {
        flow_control.highest_sent -= static_cast<std::uint64_t>(metadata.length);
        send_buffer.mark_unsent(metadata.offset, metadata.length);
    } else {
        send_buffer.mark_lost(metadata.offset, metadata.length);
    }
    if (metadata.fin) {
        send_fin_state = StreamSendFinState::pending;
    }
}

StreamState make_implicit_stream_state(std::uint64_t stream_id, EndpointRole local_role) {
    const auto id_info = classify_stream_id(stream_id, local_role);
    return StreamState{
        .stream_id = stream_id,
        .id_info = id_info,
        .send_closed = !id_info.local_can_send,
        .receive_closed = !id_info.local_can_receive,
        .flow_control =
            StreamFlowControlState{
                .peer_max_stream_data = std::numeric_limits<std::uint64_t>::max(),
                .advertised_max_stream_data = std::numeric_limits<std::uint64_t>::max(),
            },
    };
}

} // namespace coquic::quic
