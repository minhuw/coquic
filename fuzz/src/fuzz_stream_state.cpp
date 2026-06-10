#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

#include "fuzz/src/fuzz_support.h"
#include "src/quic/transport/streams.h"

namespace {

constexpr std::size_t kMaxInputSize = 4096;
constexpr std::size_t kMaxPayloadSize = 256;
constexpr std::uint64_t kMaxOffset = 1u << 20u;
constexpr std::uint64_t kMaxLimit = 1u << 20u;

std::vector<std::byte> payload_from(coquic::fuzz::InputReader &reader) {
    auto payload = reader.read_sized_bytes(kMaxPayloadSize);
    if (payload.empty()) {
        payload.push_back(std::byte{0});
    }
    return payload;
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
    if (size > kMaxInputSize) {
        return 0;
    }

    const auto bytes = coquic::fuzz::bytes_from_input(data, size);
    coquic::fuzz::InputReader reader(coquic::fuzz::byte_span(bytes));

    const auto role = reader.read_bool() ? coquic::quic::EndpointRole::server
                                         : coquic::quic::EndpointRole::client;
    const auto stream_id = reader.read_u64() % 64u;
    auto stream = coquic::quic::make_implicit_stream_state(stream_id, role);

    const auto initial_peer_limit = reader.read_u64() % (kMaxLimit + 1u);
    stream.note_peer_max_stream_data(initial_peer_limit);
    stream.queue_max_stream_data(reader.read_u64() % (kMaxLimit + 1u));

    for (std::size_t step = 0; step < 96 && !reader.empty(); ++step) {
        switch (reader.read_u8() % 15u) {
        case 0: {
            const auto payload = payload_from(reader);
            stream.send_buffer.append(payload);
            stream.send_flow_control_committed += static_cast<std::uint64_t>(payload.size());
            static_cast<void>(stream.validate_local_send(reader.read_bool()));
            break;
        }
        case 1: {
            stream.note_peer_max_stream_data(reader.read_u64() % (kMaxLimit + 1u));
            break;
        }
        case 2: {
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
        case 3: {
            stream.queue_max_stream_data(reader.read_u64() % (kMaxLimit + 1u));
            if (const auto frame = stream.take_max_stream_data_frame(); frame.has_value()) {
                if (reader.read_bool()) {
                    stream.acknowledge_max_stream_data_frame(*frame);
                } else {
                    stream.mark_max_stream_data_frame_lost(*frame);
                }
            }
            break;
        }
        case 4: {
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
        case 5: {
            const auto offset = reader.read_u64() % (kMaxOffset + 1u);
            const auto length = reader.read_size(256);
            static_cast<void>(stream.validate_receive_range(offset, length, reader.read_bool()));
            break;
        }
        case 6: {
            const coquic::quic::ResetStreamFrame frame{
                .stream_id = stream.stream_id,
                .application_protocol_error_code = reader.read_u64() & 0xffffu,
                .final_size = reader.read_u64() % (kMaxOffset + 1u),
            };
            static_cast<void>(stream.note_peer_reset(frame));
            break;
        }
        case 7: {
            static_cast<void>(stream.note_peer_stop_sending(reader.read_u64() & 0xffffu));
            break;
        }
        case 8: {
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
        case 9: {
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
        case 10: {
            static_cast<void>(stream.note_peer_final_size(reader.read_u64() % (kMaxOffset + 1u)));
            break;
        }
        case 11: {
            const auto info = coquic::quic::classify_stream_id(reader.read_u64() % 256u, role);
            coquic::fuzz::require(info.local_can_send || info.local_can_receive,
                                  "stream classification has no local direction");
            break;
        }
        case 12: {
            coquic::quic::StreamOpenLimits limits;
            limits.note_peer_max_streams(coquic::quic::StreamLimitType::bidirectional,
                                         reader.read_u64() % 64u);
            limits.note_peer_max_streams(coquic::quic::StreamLimitType::unidirectional,
                                         reader.read_u64() % 64u);
            static_cast<void>(limits.can_open_local_stream(reader.read_u64() % 256u, role));
            break;
        }
        case 13: {
            static_cast<void>(coquic::quic::is_peer_implicit_stream_open_allowed_by_limits(
                reader.read_u64() % 256u, role,
                coquic::quic::PeerStreamOpenLimits{
                    .bidirectional = reader.read_u64() % 64u,
                    .unidirectional = reader.read_u64() % 64u,
                }));
            break;
        }
        default:
            static_cast<void>(stream.has_pending_send());
            static_cast<void>(stream.has_outstanding_send());
            static_cast<void>(stream.sendable_bytes());
            static_cast<void>(stream.next_send_offset_for_budget(reader.read_bool()));
            break;
        }

        coquic::fuzz::require(stream.flow_control.highest_sent <=
                                  stream.send_flow_control_committed,
                              "stream highest_sent exceeds committed send bytes");
    }

    return 0;
}
