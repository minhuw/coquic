#include "src/http09/http09_server.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <utility>

#include "src/quic/transport/streams.h"

namespace coquic::http09 {

using quic::classify_stream_id;
using quic::EndpointRole;
using quic::QuicCoreInput;
using quic::QuicCoreReceiveStreamData;
using quic::QuicCoreResetStream;
using quic::QuicCoreResult;
using quic::QuicCoreSendStreamData;
using quic::QuicCoreStateChange;
using quic::QuicCoreStateEvent;
using quic::QuicCoreStopSending;
using quic::QuicCoreTimePoint;
using quic::StreamDirection;
using quic::StreamInitiator;

namespace {

// Keep response bursts large enough for interop measurement cases while still
// yielding regularly so runtime loops can observe migration traffic.
constexpr std::size_t kResponseChunkSize = static_cast<std::size_t>(32) * 1024U;
constexpr std::size_t kResponseChunksPerPoll = 32;
constexpr std::size_t kMaxBufferedRequestBytes = static_cast<std::size_t>(8) * 1024U;
constexpr std::uint64_t kHttp09FileReadErrorCode = 1;

std::optional<std::filesystem::path> &forced_file_open_failure_path_for_tests() {
    static auto *path = new std::optional<std::filesystem::path>();
    return *path;
}

std::ifstream open_response_file(const std::filesystem::path &path) {
    const auto &forced_open_failure_path = forced_file_open_failure_path_for_tests();
    if (forced_open_failure_path.has_value() &&
        forced_open_failure_path.value() == path.lexically_normal()) {
        return std::ifstream{};
    }
    return std::ifstream(path, std::ios::binary);
}

std::optional<std::size_t> find_request_line_terminator(std::span<const std::byte> bytes) {
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (bytes[index] == std::byte{'\n'}) {
            return index;
        }
    }
    return std::nullopt;
}

void queue_stream_local_file_error(std::uint64_t stream_id, std::deque<QuicCoreInput> &out) {
    out.emplace_back(QuicCoreResetStream{
        .stream_id = stream_id,
        .application_error_code = kHttp09FileReadErrorCode,
    });
    out.emplace_back(QuicCoreStopSending{
        .stream_id = stream_id,
        .application_error_code = kHttp09FileReadErrorCode,
    });
}

bool queue_one_response_chunk(std::uint64_t stream_id, std::ifstream &input,
                              std::deque<QuicCoreInput> &out) {
    std::vector<std::byte> chunk;
    chunk.reserve(kResponseChunkSize);
    auto *stream_buffer = input.rdbuf();
    for (std::size_t count = 0; count < kResponseChunkSize; ++count) {
        const auto next = stream_buffer->sbumpc();
        if (next == std::char_traits<char>::eof()) {
            break;
        }
        chunk.push_back(static_cast<std::byte>(static_cast<unsigned char>(next)));
    }

    if (input.bad()) {
        return false;
    }

    if (chunk.empty()) {
        out.emplace_back(QuicCoreSendStreamData{
            .stream_id = stream_id,
            .bytes = {},
            .fin = true,
        });
        return true;
    }

    out.emplace_back(QuicCoreSendStreamData{
        .stream_id = stream_id,
        .bytes = std::move(chunk),
        .fin = input.peek() == std::char_traits<char>::eof(),
    });
    return true;
}

} // namespace

QuicHttp09ServerEndpoint::QuicHttp09ServerEndpoint(QuicHttp09ServerConfig config)
    : config_(std::move(config)) {
}

QuicHttp09EndpointUpdate QuicHttp09ServerEndpoint::on_core_result(const QuicCoreResult &result,
                                                                  QuicCoreTimePoint /*now*/) {
    if (failed_ || result.local_error.has_value()) {
        failed_ = true;
        clear_state();
        return make_failure_update();
    }

    const bool could_send_responses_before = can_send_responses();
    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<QuicCoreStateEvent>(&effect);
            event != nullptr && event->change == QuicCoreStateChange::handshake_ready) {
            handshake_ready_ = true;
        }

        const auto *received = std::get_if<QuicCoreReceiveStreamData>(&effect);
        if (received == nullptr) {
            continue;
        }

        if (!process_receive_stream_data(*received)) {
            failed_ = true;
            clear_state();
            return make_failure_update();
        }
    }

    if (!could_send_responses_before && can_send_responses()) {
        pump_response_chunks(1);
    }
    return drain_pending_inputs();
}

QuicHttp09EndpointUpdate QuicHttp09ServerEndpoint::poll(QuicCoreTimePoint /*now*/) {
    if (failed_) {
        return make_failure_update();
    }

    if (can_send_responses()) {
        pump_response_chunks(kResponseChunksPerPoll);
    }
    return drain_pending_inputs();
}

bool QuicHttp09ServerEndpoint::has_failed() const {
    return failed_;
}

QuicHttp09EndpointUpdate QuicHttp09ServerEndpoint::make_failure_update() const {
    return QuicHttp09EndpointUpdate{
        .terminal_failure = true,
    };
}

QuicHttp09EndpointUpdate QuicHttp09ServerEndpoint::drain_pending_inputs() {
    QuicHttp09EndpointUpdate update;
    while (!pending_core_inputs_.empty()) {
        update.core_inputs.push_back(std::move(pending_core_inputs_.front()));
        pending_core_inputs_.pop_front();
    }
    update.has_pending_work = !pending_responses_.empty() && can_send_responses();
    return update;
}

bool QuicHttp09ServerEndpoint::queue_response_chunk(std::uint64_t stream_id,
                                                    PendingResponse &response) {
    if (!queue_one_response_chunk(stream_id, response.file, pending_core_inputs_)) {
        queue_stream_local_file_error(stream_id, pending_core_inputs_);
        closed_streams_.insert(stream_id);
        return false;
    }

    const auto &send = std::get<QuicCoreSendStreamData>(pending_core_inputs_.back());
    if (send.fin) {
        closed_streams_.insert(stream_id);
        return false;
    }

    return true;
}

void QuicHttp09ServerEndpoint::pump_response_chunks(std::size_t max_chunks) {
    std::size_t emitted_chunks = 0;
    auto it = pending_responses_.begin();
    while (!pending_responses_.empty() && emitted_chunks < max_chunks) {
        if (it == pending_responses_.end()) {
            it = pending_responses_.begin();
        }
        const auto stream_id = it->first;
        auto current = it;
        ++it;
        if (!queue_response_chunk(stream_id, current->second)) {
            pending_responses_.erase(current);
            continue;
        }
        ++emitted_chunks;
    }
}

bool QuicHttp09ServerEndpoint::process_receive_stream_data(
    const QuicCoreReceiveStreamData &received) {
    const auto stream_info = classify_stream_id(received.stream_id, EndpointRole::server);
    if (stream_info.initiator != StreamInitiator::peer ||
        stream_info.direction != StreamDirection::bidirectional) {
        pending_requests_.erase(received.stream_id);
        return false;
    }
    if (closed_streams_.contains(received.stream_id)) {
        pending_requests_.erase(received.stream_id);
        return received.bytes.empty() && received.fin;
    }
    if (pending_responses_.contains(received.stream_id)) {
        return received.bytes.empty() && received.fin;
    }

    auto &pending = pending_requests_[received.stream_id];
    if (received.bytes.empty() && received.fin) {
        pending_requests_.erase(received.stream_id);
        return false;
    }

    pending.request_bytes.insert(pending.request_bytes.end(), received.bytes.begin(),
                                 received.bytes.end());
    if (pending.request_bytes.size() > kMaxBufferedRequestBytes) {
        pending_requests_.erase(received.stream_id);
        return false;
    }

    const auto line_end = find_request_line_terminator(pending.request_bytes);
    if (!line_end.has_value()) {
        if (received.fin) {
            pending_requests_.erase(received.stream_id);
            return false;
        }
        return true;
    }
    if (*line_end + 1 != pending.request_bytes.size()) {
        pending_requests_.erase(received.stream_id);
        return false;
    }

    const auto request_target = parse_http09_request_target(pending.request_bytes);
    if (!request_target.has_value()) {
        pending_requests_.erase(received.stream_id);
        return false;
    }

    const auto resolved_path =
        resolve_http09_path_under_root(config_.document_root, request_target.value());
    if (!resolved_path.has_value()) {
        pending_requests_.erase(received.stream_id);
        return false;
    }

    const auto &resolved_path_value = resolved_path.value();
    if (!std::filesystem::is_regular_file(resolved_path_value)) {
        queue_stream_local_file_error(received.stream_id, pending_core_inputs_);
        closed_streams_.insert(received.stream_id);
        pending_requests_.erase(received.stream_id);
        return true;
    }

    PendingResponse response{
        .file = open_response_file(resolved_path_value),
    };
    if (!response.file.is_open()) {
        queue_stream_local_file_error(received.stream_id, pending_core_inputs_);
        closed_streams_.insert(received.stream_id);
        pending_requests_.erase(received.stream_id);
        return true;
    }

    if (!can_send_responses() || queue_response_chunk(received.stream_id, response)) {
        pending_responses_.insert_or_assign(received.stream_id, std::move(response));
    }
    pending_requests_.erase(received.stream_id);
    return true;
}

bool QuicHttp09ServerEndpoint::can_send_responses() const {
    return !config_.defer_responses_until_handshake_ready || handshake_ready_;
}

void QuicHttp09ServerEndpoint::clear_state() {
    pending_requests_.clear();
    pending_responses_.clear();
    closed_streams_.clear();
    pending_core_inputs_.clear();
}

namespace test {

void server_set_forced_file_open_failure_path_for_tests(const std::filesystem::path &path) {
    forced_file_open_failure_path_for_tests() = path.lexically_normal();
}

void server_clear_forced_file_open_failure_path_for_tests() {
    forced_file_open_failure_path_for_tests().reset();
}

} // namespace test

} // namespace coquic::http09
