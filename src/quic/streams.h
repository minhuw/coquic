#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

#include "src/quic/crypto_stream.h"
#include "src/quic/protected_codec.h"

namespace coquic::quic {

enum class StreamInitiator : std::uint8_t {
    local,
    peer,
};

enum class StreamDirection : std::uint8_t {
    bidirectional,
    unidirectional,
};

struct StreamIdInfo {
    StreamInitiator initiator = StreamInitiator::local;
    StreamDirection direction = StreamDirection::bidirectional;
    bool local_can_send = false;
    bool local_can_receive = false;
};

enum class StreamStateErrorCode : std::uint8_t {
    invalid_stream_id,
    invalid_stream_direction,
    send_side_closed,
    receive_side_closed,
    final_size_conflict,
};

struct StreamStateError {
    StreamStateErrorCode code = StreamStateErrorCode::invalid_stream_id;
    std::uint64_t stream_id = 0;
};

template <typename T> struct StreamStateResult {
    std::variant<T, StreamStateError> storage;

    bool has_value() const {
        return std::holds_alternative<T>(storage);
    }

    T &value() {
        return std::get<T>(storage);
    }

    const T &value() const {
        return std::get<T>(storage);
    }

    StreamStateError &error() {
        return std::get<StreamStateError>(storage);
    }

    const StreamStateError &error() const {
        return std::get<StreamStateError>(storage);
    }

    static StreamStateResult success(T value) {
        return StreamStateResult{
            .storage = std::move(value),
        };
    }

    static StreamStateResult failure(StreamStateErrorCode code, std::uint64_t stream_id) {
        return StreamStateResult{
            .storage =
                StreamStateError{
                    .code = code,
                    .stream_id = stream_id,
                },
        };
    }
};

struct StreamFrameSendFragment {
    std::uint64_t stream_id = 0;
    std::uint64_t offset = 0;
    std::vector<std::byte> bytes;
    bool fin = false;
};

struct StreamSendBudget {
    std::size_t packet_bytes = 0;
    std::uint64_t new_bytes = std::numeric_limits<std::uint64_t>::max();
};

StreamIdInfo classify_stream_id(std::uint64_t stream_id, EndpointRole local_role);
bool is_local_implicit_stream_open_allowed(std::uint64_t stream_id, EndpointRole local_role);

struct PeerStreamOpenLimits {
    std::uint64_t bidirectional = 0;
    std::uint64_t unidirectional = 0;
};

bool is_peer_implicit_stream_open_allowed_by_limits(std::uint64_t stream_id,
                                                    EndpointRole local_role,
                                                    PeerStreamOpenLimits limits);

enum class StreamSendFinState : std::uint8_t {
    none,
    pending,
    sent,
    acknowledged,
};

enum class StreamControlFrameState : std::uint8_t {
    none,
    pending,
    sent,
    acknowledged,
};

struct StreamFlowControlState {
    std::uint64_t peer_max_stream_data = 0;
    std::uint64_t highest_sent = 0;
    std::uint64_t local_receive_window = 0;
    std::uint64_t advertised_max_stream_data = 0;
    std::uint64_t delivered_bytes = 0;
    std::optional<MaxStreamDataFrame> pending_max_stream_data_frame;
    StreamControlFrameState max_stream_data_state = StreamControlFrameState::none;
    std::optional<StreamDataBlockedFrame> pending_stream_data_blocked_frame;
    StreamControlFrameState stream_data_blocked_state = StreamControlFrameState::none;
};

struct StreamOpenLimits {
    std::uint64_t peer_max_bidirectional = 0;
    std::uint64_t peer_max_unidirectional = 0;

    bool can_open_local_stream(std::uint64_t stream_id, EndpointRole local_role) const;
    void note_peer_max_streams(StreamLimitType stream_type, std::uint64_t maximum_streams);
};

struct StreamState {
    std::uint64_t stream_id = 0;
    StreamIdInfo id_info;
    ReliableSendBuffer send_buffer;
    ReliableReceiveBuffer receive_buffer;
    bool send_closed = false;
    bool receive_closed = false;
    bool peer_send_closed = false;
    bool peer_fin_delivered = false;
    std::optional<std::uint64_t> peer_final_size;
    std::optional<std::uint64_t> send_final_size;
    StreamSendFinState send_fin_state = StreamSendFinState::none;
    std::optional<ResetStreamFrame> pending_reset_frame;
    StreamControlFrameState reset_state = StreamControlFrameState::none;
    std::optional<StopSendingFrame> pending_stop_sending_frame;
    StreamControlFrameState stop_sending_state = StreamControlFrameState::none;
    bool peer_reset_received = false;
    std::uint64_t send_flow_control_limit = 0;
    std::uint64_t send_flow_control_committed = 0;
    std::uint64_t receive_flow_control_limit = 0;
    std::uint64_t receive_flow_control_consumed = 0;
    std::uint64_t highest_received_offset = 0;
    StreamFlowControlState flow_control;

    StreamStateResult<bool> validate_local_send(bool fin);
    StreamStateResult<bool> validate_local_reset(std::uint64_t application_error_code);
    StreamStateResult<bool> validate_local_stop_sending(std::uint64_t application_error_code);
    StreamStateResult<bool> validate_receive_range(std::uint64_t offset, std::size_t length,
                                                   bool fin);
    StreamStateResult<bool> note_peer_final_size(std::uint64_t final_size);
    StreamStateResult<bool> note_peer_reset(const ResetStreamFrame &frame);
    StreamStateResult<bool> note_peer_stop_sending(std::uint64_t application_error_code);
    std::uint64_t sendable_bytes() const;
    bool should_send_stream_data_blocked() const;
    bool has_pending_send() const;
    bool has_outstanding_send() const;
    void note_peer_max_stream_data(std::uint64_t maximum_stream_data);
    void queue_max_stream_data(std::uint64_t maximum_stream_data);
    std::optional<MaxStreamDataFrame> take_max_stream_data_frame();
    void acknowledge_max_stream_data_frame(const MaxStreamDataFrame &frame);
    void mark_max_stream_data_frame_lost(const MaxStreamDataFrame &frame);
    void queue_stream_data_blocked();
    std::optional<StreamDataBlockedFrame> take_stream_data_blocked_frame();
    void acknowledge_stream_data_blocked_frame(const StreamDataBlockedFrame &frame);
    void mark_stream_data_blocked_frame_lost(const StreamDataBlockedFrame &frame);
    std::optional<ResetStreamFrame> take_reset_frame();
    std::optional<StopSendingFrame> take_stop_sending_frame();
    std::vector<StreamFrameSendFragment> take_send_fragments(std::size_t max_bytes);
    std::vector<StreamFrameSendFragment> take_send_fragments(StreamSendBudget budget);
    void acknowledge_reset_frame(const ResetStreamFrame &frame);
    void mark_reset_frame_lost(const ResetStreamFrame &frame);
    void acknowledge_stop_sending_frame(const StopSendingFrame &frame);
    void mark_stop_sending_frame_lost(const StopSendingFrame &frame);
    void acknowledge_send_fragment(const StreamFrameSendFragment &fragment);
    void mark_send_fragment_lost(const StreamFrameSendFragment &fragment);
};

StreamState make_implicit_stream_state(std::uint64_t stream_id, EndpointRole local_role);

} // namespace coquic::quic
