#pragma once

#include <cstddef>
#include <cstdint>
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
    invalid_stream_direction,
    send_side_closed,
    receive_side_closed,
    final_size_conflict,
};

struct StreamStateError {
    StreamStateErrorCode code = StreamStateErrorCode::invalid_stream_direction;
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

StreamIdInfo classify_stream_id(std::uint64_t stream_id, EndpointRole local_role);

struct PeerStreamOpenLimits {
    std::uint64_t bidirectional = 0;
    std::uint64_t unidirectional = 0;
};

bool is_implicit_stream_open_allowed(std::uint64_t stream_id, EndpointRole local_role,
                                     PeerStreamOpenLimits limits);

struct StreamState {
    std::uint64_t stream_id = 0;
    StreamIdInfo id_info;
    ReliableSendBuffer send_buffer;
    ReliableReceiveBuffer receive_buffer;
    bool send_closed = false;
    bool receive_closed = false;
    std::optional<std::uint64_t> peer_final_size;
    std::uint64_t highest_received_offset = 0;

    StreamStateResult<bool> validate_local_send(bool fin);
    StreamStateResult<bool> validate_receive_range(std::uint64_t offset, std::size_t length,
                                                   bool fin);
    StreamStateResult<bool> note_peer_final_size(std::uint64_t final_size);
};

StreamState make_implicit_stream_state(std::uint64_t stream_id, EndpointRole local_role);

} // namespace coquic::quic
