#include "src/quic/streams.h"

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
    if (id_info.direction == StreamDirection::bidirectional) {
        return stream_index < peer_max_bidirectional;
    }

    return stream_index < peer_max_unidirectional;
}

void StreamOpenLimits::note_peer_max_streams(StreamLimitType stream_type,
                                             std::uint64_t maximum_streams) {
    if (stream_type == StreamLimitType::bidirectional) {
        peer_max_bidirectional = std::max(peer_max_bidirectional, maximum_streams);
        return;
    }

    peer_max_unidirectional = std::max(peer_max_unidirectional, maximum_streams);
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
    if (range_end > flow_control.advertised_max_stream_data) {
        return StreamStateResult<bool>::failure(StreamStateErrorCode::final_size_conflict,
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
        stop_sending_state == StreamControlFrameState::pending ||
        flow_control.max_stream_data_state == StreamControlFrameState::pending ||
        flow_control.stream_data_blocked_state == StreamControlFrameState::pending) {
        return true;
    }

    if (reset_state != StreamControlFrameState::none) {
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

bool StreamState::should_send_stream_data_blocked() const {
    return id_info.local_can_send && reset_state == StreamControlFrameState::none &&
           send_flow_control_committed > flow_control.peer_max_stream_data;
}

void StreamState::note_peer_max_stream_data(std::uint64_t maximum_stream_data) {
    if (maximum_stream_data <= flow_control.peer_max_stream_data) {
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
    if (reset_state != StreamControlFrameState::none) {
        return {};
    }

    std::vector<StreamFrameSendFragment> fragments;
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
        if (fin) {
            send_fin_state = StreamSendFinState::sent;
        }
    };

    for (auto &range : send_buffer.take_lost_ranges(remaining_bytes)) {
        remaining_bytes -= range.bytes.size();
        append_fragment(std::move(range), /*consumes_flow_control=*/false);
    }

    const auto capped_new_bytes =
        std::min<std::uint64_t>(budget.new_bytes, static_cast<std::uint64_t>(remaining_bytes));
    auto new_ranges = send_buffer.take_unsent_ranges(static_cast<std::size_t>(capped_new_bytes),
                                                     flow_control.peer_max_stream_data);
    for (auto &range : new_ranges) {
        const auto range_end = saturating_add(range.offset, range.bytes.size());
        flow_control.highest_sent = std::max(flow_control.highest_sent, range_end);
        remaining_bytes -= range.bytes.size();
        append_fragment(std::move(range), /*consumes_flow_control=*/true);
    }

    bool fin_only_sendable = false;
    if (send_fin_state == StreamSendFinState::pending && send_final_size.has_value()) {
        fin_only_sendable = !send_buffer.has_pending_data() &&
                            *send_final_size <= flow_control.peer_max_stream_data;
    }
    if (fragments.empty() && fin_only_sendable) {
        fragments.push_back(StreamFrameSendFragment{
            .stream_id = stream_id,
            .offset = *send_final_size,
            .bytes = {},
            .fin = true,
            .consumes_flow_control = false,
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
        .flow_control =
            StreamFlowControlState{
                .peer_max_stream_data = std::numeric_limits<std::uint64_t>::max(),
                .advertised_max_stream_data = std::numeric_limits<std::uint64_t>::max(),
            },
    };
}

} // namespace coquic::quic
