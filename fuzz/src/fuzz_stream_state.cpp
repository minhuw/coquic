#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <vector>

#include "fuzz/src/fuzz_support.h"
#include "fuzz/src/stream_state_bytecode.h"
#include "src/quic/transport/streams.h"

namespace {

namespace ss = coquic::fuzz::stream_state;

std::vector<std::byte> payload_from(coquic::fuzz::InputReader &reader) {
    auto payload = reader.read_sized_bytes(ss::kMaxPayloadSize);
    if (payload.empty()) {
        payload.push_back(std::byte{0});
    }
    return payload;
}

bool consume_magic(coquic::fuzz::InputReader &reader) {
    for (const auto byte : ss::kMagic) {
        if (reader.read_u8() != byte) {
            return false;
        }
    }
    return true;
}

coquic::quic::StreamFrameSendMetadata metadata_from(coquic::fuzz::InputReader &reader,
                                                    std::uint64_t stream_id) {
    return coquic::quic::StreamFrameSendMetadata{
        .stream_id = stream_id,
        .offset = reader.read_u64() % (ss::kMaxOffset + 1u),
        .length = reader.read_size(ss::kMaxPayloadSize + 1u),
        .fin = reader.read_bool(),
        .consumes_flow_control = reader.read_bool(),
    };
}

void exercise_fragment(coquic::quic::StreamState &stream,
                       const coquic::quic::StreamFrameSendFragment &fragment, std::uint8_t action) {
    coquic::fuzz::require(fragment.stream_id == stream.stream_id,
                          "send fragment stream id changed");
    coquic::fuzz::require(fragment.stream_frame_wire_size() >= fragment.bytes.size(),
                          "stream frame wire size smaller than payload");

    switch (action % 4u) {
    case 0:
        stream.mark_send_fragment_sent(fragment);
        break;
    case 1:
        stream.acknowledge_send_fragment(fragment);
        break;
    case 2:
        stream.mark_send_fragment_lost(fragment);
        break;
    default:
        stream.restore_send_fragment(fragment);
        break;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    if (size > ss::kMaxInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    coquic::fuzz::InputReader reader(coquic::fuzz::byte_span(bytes));
    if (!consume_magic(reader)) {
        return 0;
    }

    const auto role = reader.read_bool() ? coquic::quic::EndpointRole::server
                                         : coquic::quic::EndpointRole::client;
    const auto stream_id = reader.read_u64() % 64u;
    auto stream = coquic::quic::make_implicit_stream_state(stream_id, role);

    const auto initial_peer_limit = reader.read_u64() % (ss::kMaxLimit + 1u);
    stream.note_peer_max_stream_data(initial_peer_limit);
    stream.queue_max_stream_data(reader.read_u64() % (ss::kMaxLimit + 1u));

    std::optional<coquic::quic::MaxStreamDataFrame> last_max_stream_data;
    std::optional<coquic::quic::StreamDataBlockedFrame> last_stream_data_blocked;
    std::optional<coquic::quic::ResetStreamFrame> last_reset;
    std::optional<coquic::quic::StopSendingFrame> last_stop_sending;

    for (std::size_t step = 0; step < ss::kMaxSteps && !reader.empty(); ++step) {
        switch (static_cast<ss::Op>(reader.read_u8())) {
        case ss::Op::local_send: {
            const auto payload = payload_from(reader);
            stream.send_buffer.append(payload);
            stream.send_flow_control_committed += static_cast<std::uint64_t>(payload.size());
            static_cast<void>(stream.validate_local_send(reader.read_bool()));
            break;
        }
        case ss::Op::peer_max_stream_data: {
            stream.note_peer_max_stream_data(reader.read_u64() % (ss::kMaxLimit + 1u));
            break;
        }
        case ss::Op::stream_data_blocked_round_trip: {
            stream.queue_stream_data_blocked();
            if (const auto frame = stream.take_stream_data_blocked_frame(); frame.has_value()) {
                if (reader.read_bool()) {
                    stream.acknowledge_stream_data_blocked_frame(*frame);
                } else {
                    stream.mark_stream_data_blocked_frame_lost(*frame);
                }
            }
            break;
        }
        case ss::Op::max_stream_data_round_trip: {
            stream.queue_max_stream_data(reader.read_u64() % (ss::kMaxLimit + 1u));
            if (const auto frame = stream.take_max_stream_data_frame(); frame.has_value()) {
                if (reader.read_bool()) {
                    stream.acknowledge_max_stream_data_frame(*frame);
                } else {
                    stream.mark_max_stream_data_frame_lost(*frame);
                }
            }
            break;
        }
        case ss::Op::take_send_fragments_with_actions: {
            const auto budget = coquic::quic::StreamSendBudget{
                .packet_bytes = 1u + reader.read_size(512),
                .new_bytes = reader.read_u64() % 512u,
                .prefer_fresh_data = reader.read_bool(),
            };
            auto fragments = stream.take_send_fragments(budget);
            for (const auto &fragment : fragments) {
                exercise_fragment(stream, fragment, reader.read_u8());
            }
            break;
        }
        case ss::Op::local_reset_round_trip: {
            static_cast<void>(stream.validate_local_reset(reader.read_u64() & 0xffffu));
            if (const auto frame = stream.take_reset_frame(); frame.has_value()) {
                if (reader.read_bool()) {
                    stream.acknowledge_reset_frame(*frame);
                } else {
                    stream.mark_reset_frame_lost(*frame);
                }
            }
            break;
        }
        case ss::Op::local_stop_sending_round_trip: {
            static_cast<void>(stream.validate_local_stop_sending(reader.read_u64() & 0xffffu));
            if (const auto frame = stream.take_stop_sending_frame(); frame.has_value()) {
                if (reader.read_bool()) {
                    stream.acknowledge_stop_sending_frame(*frame);
                } else {
                    stream.mark_stop_sending_frame_lost(*frame);
                }
            }
            break;
        }
        case ss::Op::queue_stream_data_blocked: {
            stream.queue_stream_data_blocked();
            break;
        }
        case ss::Op::take_stream_data_blocked: {
            last_stream_data_blocked = stream.take_stream_data_blocked_frame();
            break;
        }
        case ss::Op::ack_stream_data_blocked: {
            if (last_stream_data_blocked.has_value()) {
                stream.acknowledge_stream_data_blocked_frame(*last_stream_data_blocked);
            }
            break;
        }
        case ss::Op::lose_stream_data_blocked: {
            if (last_stream_data_blocked.has_value()) {
                stream.mark_stream_data_blocked_frame_lost(*last_stream_data_blocked);
            }
            break;
        }
        case ss::Op::queue_max_stream_data: {
            stream.queue_max_stream_data(reader.read_u64() % (ss::kMaxLimit + 1u));
            break;
        }
        case ss::Op::take_max_stream_data: {
            last_max_stream_data = stream.take_max_stream_data_frame();
            break;
        }
        case ss::Op::ack_max_stream_data: {
            if (last_max_stream_data.has_value()) {
                stream.acknowledge_max_stream_data_frame(*last_max_stream_data);
            }
            break;
        }
        case ss::Op::lose_max_stream_data: {
            if (last_max_stream_data.has_value()) {
                stream.mark_max_stream_data_frame_lost(*last_max_stream_data);
            }
            break;
        }
        case ss::Op::take_send_fragments: {
            const auto budget = coquic::quic::StreamSendBudget{
                .packet_bytes = 1u + reader.read_size(512),
                .new_bytes = reader.read_u64() % 512u,
                .prefer_fresh_data = reader.read_bool(),
            };
            auto fragments = stream.take_send_fragments(budget);
            for (const auto &fragment : fragments) {
                stream.mark_send_fragment_sent(fragment);
            }
            break;
        }
        case ss::Op::mark_send_sent: {
            stream.mark_send_metadata_sent(metadata_from(reader, stream.stream_id));
            break;
        }
        case ss::Op::ack_send: {
            stream.acknowledge_send_metadata(metadata_from(reader, stream.stream_id));
            break;
        }
        case ss::Op::lose_send: {
            stream.mark_send_metadata_lost(metadata_from(reader, stream.stream_id));
            break;
        }
        case ss::Op::restore_send: {
            stream.restore_send_metadata(metadata_from(reader, stream.stream_id));
            break;
        }
        case ss::Op::receive_range: {
            const auto offset = reader.read_u64() % (ss::kMaxOffset + 1u);
            const auto length = reader.read_size(256);
            static_cast<void>(stream.validate_receive_range(offset, length, reader.read_bool()));
            break;
        }
        case ss::Op::peer_reset: {
            const coquic::quic::ResetStreamFrame frame{
                .stream_id = stream.stream_id,
                .application_protocol_error_code = reader.read_u64() & 0xffffu,
                .final_size = reader.read_u64() % (ss::kMaxOffset + 1u),
            };
            static_cast<void>(stream.note_peer_reset(frame));
            break;
        }
        case ss::Op::peer_stop_sending: {
            static_cast<void>(stream.note_peer_stop_sending(reader.read_u64() & 0xffffu));
            break;
        }
        case ss::Op::local_reset: {
            static_cast<void>(stream.validate_local_reset(reader.read_u64() & 0xffffu));
            break;
        }
        case ss::Op::take_reset: {
            last_reset = stream.take_reset_frame();
            break;
        }
        case ss::Op::ack_reset: {
            if (last_reset.has_value()) {
                stream.acknowledge_reset_frame(*last_reset);
            }
            break;
        }
        case ss::Op::lose_reset: {
            if (last_reset.has_value()) {
                stream.mark_reset_frame_lost(*last_reset);
            }
            break;
        }
        case ss::Op::local_stop_sending: {
            static_cast<void>(stream.validate_local_stop_sending(reader.read_u64() & 0xffffu));
            break;
        }
        case ss::Op::take_stop_sending: {
            last_stop_sending = stream.take_stop_sending_frame();
            break;
        }
        case ss::Op::ack_stop_sending: {
            if (last_stop_sending.has_value()) {
                stream.acknowledge_stop_sending_frame(*last_stop_sending);
            }
            break;
        }
        case ss::Op::lose_stop_sending: {
            if (last_stop_sending.has_value()) {
                stream.mark_stop_sending_frame_lost(*last_stop_sending);
            }
            break;
        }
        case ss::Op::peer_final_size: {
            static_cast<void>(
                stream.note_peer_final_size(reader.read_u64() % (ss::kMaxOffset + 1u)));
            break;
        }
        case ss::Op::classify_stream: {
            const auto info = coquic::quic::classify_stream_id(reader.read_u64() % 256u, role);
            coquic::fuzz::require(info.local_can_send || info.local_can_receive,
                                  "stream classification has no local direction");
            break;
        }
        case ss::Op::local_open_limits: {
            coquic::quic::StreamOpenLimits limits;
            limits.note_peer_max_streams(coquic::quic::StreamLimitType::bidirectional,
                                         reader.read_u64() % 64u);
            limits.note_peer_max_streams(coquic::quic::StreamLimitType::unidirectional,
                                         reader.read_u64() % 64u);
            static_cast<void>(limits.can_open_local_stream(reader.read_u64() % 256u, role));
            break;
        }
        case ss::Op::peer_open_limits: {
            static_cast<void>(coquic::quic::is_peer_implicit_stream_open_allowed_by_limits(
                reader.read_u64() % 256u, role,
                coquic::quic::PeerStreamOpenLimits{
                    .bidirectional = reader.read_u64() % 64u,
                    .unidirectional = reader.read_u64() % 64u,
                }));
            break;
        }
        case ss::Op::snapshot:
            static_cast<void>(stream.has_pending_send());
            static_cast<void>(stream.has_outstanding_send());
            static_cast<void>(stream.sendable_bytes());
            static_cast<void>(stream.next_send_offset_for_budget(reader.read_bool()));
            break;
        default:
            break;
        }

        coquic::fuzz::require(stream.flow_control.highest_sent <=
                                  stream.send_flow_control_committed,
                              "stream highest_sent exceeds committed send bytes");
    }

    return 0;
}
