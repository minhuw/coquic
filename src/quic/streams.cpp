#include "src/quic/streams.h"

#include <algorithm>
#include <limits>

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
    return candidate.has_value() && candidate->stream_id == frame.stream_id &&
           candidate->application_protocol_error_code == frame.application_protocol_error_code &&
           candidate->final_size == frame.final_size;
}

bool stop_sending_frame_matches(const std::optional<StopSendingFrame> &candidate,
                                const StopSendingFrame &frame) {
    return candidate.has_value() && candidate->stream_id == frame.stream_id &&
           candidate->application_protocol_error_code == frame.application_protocol_error_code;
}

} // namespace

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
    return id_info.initiator == StreamInitiator::local && id_info.local_can_send;
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

StreamStateResult<bool> StreamState::validate_local_send(bool fin) {
    if (!id_info.local_can_send) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::invalid_stream_direction,
                                                stream_id);
    }

    if (send_closed) {
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
    if (peer_final_size.has_value() && *peer_final_size != final_size) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::final_size_conflict,
                                                stream_id);
    }

    if (highest_received_offset > final_size) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::final_size_conflict,
                                                stream_id);
    }

    peer_final_size = final_size;
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

    return validate_local_reset(application_error_code);
}

bool StreamState::has_pending_send() const {
    if (reset_state == StreamControlFrameState::pending ||
        stop_sending_state == StreamControlFrameState::pending) {
        return true;
    }

    if (reset_state != StreamControlFrameState::none) {
        return false;
    }

    return send_buffer.has_pending_data() || send_fin_state == StreamSendFinState::pending;
}

bool StreamState::has_outstanding_send() const {
    if (reset_state == StreamControlFrameState::sent ||
        stop_sending_state == StreamControlFrameState::sent) {
        return true;
    }

    if (reset_state != StreamControlFrameState::none) {
        return false;
    }

    return send_buffer.has_outstanding_data() || send_fin_state == StreamSendFinState::sent;
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
    if (reset_state != StreamControlFrameState::none) {
        return {};
    }

    std::vector<StreamFrameSendFragment> fragments;
    for (auto &range : send_buffer.take_ranges(max_bytes)) {
        const auto range_end = saturating_add(range.offset, range.bytes.size());
        const auto fin = send_fin_state == StreamSendFinState::pending &&
                         send_final_size.has_value() && range_end == *send_final_size;
        fragments.push_back(StreamFrameSendFragment{
            .stream_id = stream_id,
            .offset = range.offset,
            .bytes = std::move(range.bytes),
            .fin = fin,
        });
        if (fin) {
            send_fin_state = StreamSendFinState::sent;
        }
    }

    if (fragments.empty() && send_fin_state == StreamSendFinState::pending &&
        send_final_size.has_value() && !send_buffer.has_pending_data()) {
        fragments.push_back(StreamFrameSendFragment{
            .stream_id = stream_id,
            .offset = *send_final_size,
            .bytes = {},
            .fin = true,
        });
        send_fin_state = StreamSendFinState::sent;
    }

    return fragments;
}

void StreamState::acknowledge_reset_frame(const ResetStreamFrame &frame) {
    if (reset_frame_matches(pending_reset_frame, frame)) {
        reset_state = StreamControlFrameState::acknowledged;
    }
}

void StreamState::mark_reset_frame_lost(const ResetStreamFrame &frame) {
    if (reset_state != StreamControlFrameState::acknowledged &&
        reset_frame_matches(pending_reset_frame, frame)) {
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
    if (reset_state != StreamControlFrameState::none) {
        return;
    }
    send_buffer.acknowledge(fragment.offset, fragment.bytes.size());
    if (fragment.fin) {
        send_fin_state = StreamSendFinState::acknowledged;
    }
}

void StreamState::mark_send_fragment_lost(const StreamFrameSendFragment &fragment) {
    if (reset_state != StreamControlFrameState::none) {
        return;
    }
    send_buffer.mark_lost(fragment.offset, fragment.bytes.size());
    if (fragment.fin) {
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
    };
}

} // namespace coquic::quic
