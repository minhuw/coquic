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

bool StreamState::has_pending_send() const {
    return send_buffer.has_pending_data() || send_fin_state == StreamSendFinState::pending;
}

bool StreamState::has_outstanding_send() const {
    return send_buffer.has_outstanding_data() || send_fin_state == StreamSendFinState::sent;
}

std::vector<StreamFrameSendFragment> StreamState::take_send_fragments(std::size_t max_bytes) {
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
        send_final_size.has_value() && !send_buffer.has_pending_data() &&
        !send_buffer.has_outstanding_data()) {
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

void StreamState::acknowledge_send_fragment(const StreamFrameSendFragment &fragment) {
    send_buffer.acknowledge(fragment.offset, fragment.bytes.size());
    if (fragment.fin) {
        send_fin_state = StreamSendFinState::acknowledged;
    }
}

void StreamState::mark_send_fragment_lost(const StreamFrameSendFragment &fragment) {
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
