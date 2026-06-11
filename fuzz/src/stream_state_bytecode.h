#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace coquic::fuzz::stream_state {

constexpr std::array<std::uint8_t, 5> kMagic = {'c', 'q', 's', 's', '2'};
constexpr std::size_t kMaxInputSize = 4096;
constexpr std::size_t kMaxPayloadSize = 256;
constexpr std::uint64_t kMaxOffset = 1u << 20u;
constexpr std::uint64_t kMaxLimit = 1u << 20u;
constexpr std::size_t kMaxSteps = 96;

enum class Op : std::uint8_t {
    // Converted v1 operations. These preserve the pre-v2 fuzzer behavior, but v2 dispatch
    // uses exact opcode values instead of byte % 15.
    local_send = 0,
    peer_max_stream_data = 1,
    stream_data_blocked_round_trip = 2,
    max_stream_data_round_trip = 3,
    take_send_fragments_with_actions = 4,
    receive_range = 5,
    peer_reset = 6,
    peer_stop_sending = 7,
    local_reset_round_trip = 8,
    local_stop_sending_round_trip = 9,
    peer_final_size = 10,
    classify_stream = 11,
    local_open_limits = 12,
    peer_open_limits = 13,
    snapshot = 14,

    // Recorder-oriented operations. Normal QUIC execution can emit these one event at a time.
    queue_stream_data_blocked = 32,
    take_stream_data_blocked = 33,
    ack_stream_data_blocked = 34,
    lose_stream_data_blocked = 35,
    queue_max_stream_data = 36,
    take_max_stream_data = 37,
    ack_max_stream_data = 38,
    lose_max_stream_data = 39,
    take_send_fragments = 40,
    mark_send_sent = 41,
    ack_send = 42,
    lose_send = 43,
    restore_send = 44,
    local_reset = 45,
    take_reset = 46,
    ack_reset = 47,
    lose_reset = 48,
    local_stop_sending = 49,
    take_stop_sending = 50,
    ack_stop_sending = 51,
    lose_stop_sending = 52,
};

} // namespace coquic::fuzz::stream_state
