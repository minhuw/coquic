#include "src/quic/http09_server.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>

#include "src/quic/streams.h"

namespace coquic::quic {
namespace {

constexpr std::size_t kResponseChunkSize = static_cast<std::size_t>(16) * 1024U;
constexpr std::size_t kMaxBufferedRequestBytes = static_cast<std::size_t>(8) * 1024U;
constexpr std::uint64_t kHttp09FileReadErrorCode = 1;

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
    std::array<char, kResponseChunkSize> buffer{};
    const auto chunk_limit = static_cast<std::streamsize>(std::min(
        kResponseChunkSize, static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())));
    input.read(buffer.data(), chunk_limit);
    const auto count = input.gcount();
    if (input.bad()) {
        return false;
    }

    if (count == 0) {
        out.emplace_back(QuicCoreSendStreamData{
            .stream_id = stream_id,
            .bytes = {},
            .fin = true,
        });
        return true;
    }

    std::vector<std::byte> chunk;
    chunk.reserve(static_cast<std::size_t>(count));
    for (std::streamsize i = 0; i < count; ++i) {
        chunk.push_back(static_cast<std::byte>(
            static_cast<unsigned char>(buffer[static_cast<std::size_t>(i)])));
    }

    const bool fin = input.peek() == std::char_traits<char>::eof();
    if (input.bad()) {
        return false;
    }

    out.emplace_back(QuicCoreSendStreamData{
        .stream_id = stream_id,
        .bytes = std::move(chunk),
        .fin = fin,
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

    for (const auto &effect : result.effects) {
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

    return drain_pending_inputs();
}

QuicHttp09EndpointUpdate QuicHttp09ServerEndpoint::poll(QuicCoreTimePoint /*now*/) {
    if (failed_) {
        return make_failure_update();
    }

    pump_response_chunks(1);
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
    update.has_pending_work = !pending_responses_.empty() || !pending_core_inputs_.empty();
    return update;
}

void QuicHttp09ServerEndpoint::pump_response_chunks(std::size_t max_chunks) {
    std::size_t emitted_chunks = 0;
    for (auto it = pending_responses_.begin();
         it != pending_responses_.end() && emitted_chunks < max_chunks;) {
        const auto stream_id = it->first;
        auto current = it++;
        if (!queue_one_response_chunk(stream_id, current->second.file, pending_core_inputs_)) {
            queue_stream_local_file_error(stream_id, pending_core_inputs_);
            pending_responses_.erase(current);
            continue;
        }

        const auto *send = std::get_if<QuicCoreSendStreamData>(&pending_core_inputs_.back());
        if (send != nullptr && send->fin) {
            pending_responses_.erase(current);
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
    if (pending_responses_.contains(received.stream_id)) {
        pending_requests_.erase(received.stream_id);
        return false;
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

    PendingResponse response{
        .file = std::ifstream(resolved_path.value(), std::ios::binary),
    };
    if (!response.file.is_open()) {
        queue_stream_local_file_error(received.stream_id, pending_core_inputs_);
        pending_requests_.erase(received.stream_id);
        return true;
    }

    if (!queue_one_response_chunk(received.stream_id, response.file, pending_core_inputs_)) {
        queue_stream_local_file_error(received.stream_id, pending_core_inputs_);
        pending_requests_.erase(received.stream_id);
        return true;
    }

    const auto *send = std::get_if<QuicCoreSendStreamData>(&pending_core_inputs_.back());
    if (send == nullptr || !send->fin) {
        pending_responses_.insert_or_assign(received.stream_id, std::move(response));
    }
    pending_requests_.erase(received.stream_id);
    return true;
}

void QuicHttp09ServerEndpoint::clear_state() {
    pending_requests_.clear();
    pending_responses_.clear();
    pending_core_inputs_.clear();
}

} // namespace coquic::quic
