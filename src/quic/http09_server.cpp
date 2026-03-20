#include "src/quic/http09_server.h"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <utility>

#include "src/quic/streams.h"

namespace coquic::quic {
namespace {

constexpr std::size_t kResponseChunkSize = static_cast<std::size_t>(16) * 1024U;

void queue_response_chunks(std::uint64_t stream_id, std::vector<std::byte> bytes,
                           std::deque<QuicCoreInput> &out) {
    if (bytes.empty()) {
        out.emplace_back(QuicCoreSendStreamData{
            .stream_id = stream_id,
            .bytes = {},
            .fin = true,
        });
        return;
    }

    for (std::size_t offset = 0; offset < bytes.size(); offset += kResponseChunkSize) {
        const auto remaining = bytes.size() - offset;
        const auto chunk_size = remaining < kResponseChunkSize ? remaining : kResponseChunkSize;
        std::vector<std::byte> chunk(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                     bytes.begin() +
                                         static_cast<std::ptrdiff_t>(offset + chunk_size));
        out.emplace_back(QuicCoreSendStreamData{
            .stream_id = stream_id,
            .bytes = std::move(chunk),
            .fin = offset + chunk_size == bytes.size(),
        });
    }
}

std::optional<std::vector<std::byte>> read_file_bytes(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.good()) {
        return std::nullopt;
    }

    std::vector<std::byte> bytes;
    for (std::istreambuf_iterator<char> it(input), end; it != end; ++it) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(*it)));
    }

    return bytes;
}

} // namespace

QuicHttp09ServerEndpoint::QuicHttp09ServerEndpoint(QuicHttp09ServerConfig config)
    : config_(std::move(config)) {
}

QuicHttp09EndpointUpdate QuicHttp09ServerEndpoint::on_core_result(const QuicCoreResult &result,
                                                                  QuicCoreTimePoint /*now*/) {
    if (failed_ || result.local_error.has_value()) {
        failed_ = true;
        return make_failure_update();
    }

    for (const auto &effect : result.effects) {
        const auto *received = std::get_if<QuicCoreReceiveStreamData>(&effect);
        if (received == nullptr) {
            continue;
        }

        if (!process_receive_stream_data(*received)) {
            failed_ = true;
            return make_failure_update();
        }
    }

    return drain_pending_inputs();
}

QuicHttp09EndpointUpdate QuicHttp09ServerEndpoint::poll(QuicCoreTimePoint /*now*/) {
    if (failed_) {
        return make_failure_update();
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
    return update;
}

bool QuicHttp09ServerEndpoint::process_receive_stream_data(
    const QuicCoreReceiveStreamData &received) {
    const auto stream_info = classify_stream_id(received.stream_id, EndpointRole::server);
    if (stream_info.initiator != StreamInitiator::peer ||
        stream_info.direction != StreamDirection::bidirectional) {
        return false;
    }

    auto &pending = pending_requests_[received.stream_id];
    if (pending.parsed) {
        return false;
    }

    pending.request_bytes.insert(pending.request_bytes.end(), received.bytes.begin(),
                                 received.bytes.end());

    const auto request_target = parse_http09_request_target(pending.request_bytes);
    if (!request_target.has_value()) {
        return request_target.error().code == CodecErrorCode::truncated_input;
    }

    const auto resolved_path =
        resolve_http09_path_under_root(config_.document_root, request_target.value());
    if (!resolved_path.has_value()) {
        return false;
    }

    auto file_bytes = read_file_bytes(resolved_path.value());
    if (!file_bytes.has_value()) {
        return false;
    }

    pending.parsed = true;
    queue_response_chunks(received.stream_id, std::move(*file_bytes), pending_core_inputs_);
    return true;
}

} // namespace coquic::quic
