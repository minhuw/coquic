#include "src/quic/demo_channel.h"

#include <array>
#include <cstdint>
#include <utility>

namespace coquic::quic {
namespace {

constexpr std::size_t kMessageMaxBytes = static_cast<std::size_t>(64) * 1024U;

std::vector<std::byte> frame_message_bytes(std::vector<std::byte> bytes) {
    const auto size = static_cast<std::uint32_t>(bytes.size());
    std::array<std::byte, 4> header{
        std::byte((size >> 24) & 0xff),
        std::byte((size >> 16) & 0xff),
        std::byte((size >> 8) & 0xff),
        std::byte(size & 0xff),
    };

    std::vector<std::byte> framed;
    framed.reserve(header.size() + bytes.size());
    framed.insert(framed.end(), header.begin(), header.end());
    framed.insert(framed.end(), bytes.begin(), bytes.end());
    return framed;
}

bool decode_complete_messages(std::vector<std::byte> &buffer,
                              std::vector<std::vector<std::byte>> &messages) {
    std::size_t offset = 0;
    while (buffer.size() - offset >= 4) {
        const std::uint32_t size =
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset])) << 24) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 1])) << 16) |
            (static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 2])) << 8) |
            static_cast<std::uint32_t>(std::to_integer<unsigned char>(buffer[offset + 3]));

        if (size > kMessageMaxBytes) {
            return false;
        }

        const auto available = buffer.size() - offset - 4;
        if (available < size) {
            break;
        }

        const auto message_begin = buffer.begin() + static_cast<std::ptrdiff_t>(offset + 4);
        messages.emplace_back(message_begin, message_begin + static_cast<std::ptrdiff_t>(size));
        offset += 4 + size;
    }

    if (offset > 0) {
        buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    return true;
}

} // namespace

QuicDemoChannel::QuicDemoChannel(QuicCoreConfig config) : core_(std::move(config)) {
}

void QuicDemoChannel::send_message(std::vector<std::byte> bytes) {
    if (failed_) {
        return;
    }
    if (bytes.size() > kMessageMaxBytes) {
        failed_ = true;
        return;
    }

    auto framed = frame_message_bytes(std::move(bytes));
    if (core_.is_handshake_complete()) {
        core_.queue_application_data(std::move(framed));
        return;
    }

    pending_send_bytes_.insert(pending_send_bytes_.end(), framed.begin(), framed.end());
}

std::vector<std::byte> QuicDemoChannel::on_datagram(std::vector<std::byte> bytes) {
    if (failed_) {
        return {};
    }

    const bool was_ready = core_.is_handshake_complete();
    if (was_ready && !pending_send_bytes_.empty()) {
        core_.queue_application_data(std::move(pending_send_bytes_));
        pending_send_bytes_.clear();
    }

    auto outbound = core_.receive(std::move(bytes));
    if (core_.has_failed()) {
        failed_ = true;
        return {};
    }

    if (!was_ready && core_.is_handshake_complete() && !pending_send_bytes_.empty()) {
        core_.queue_application_data(std::move(pending_send_bytes_));
        pending_send_bytes_.clear();
        if (outbound.empty()) {
            outbound = core_.receive({});
            if (core_.has_failed()) {
                failed_ = true;
                return {};
            }
        }
    }

    auto raw_inbound = core_.take_received_application_data();
    pending_receive_bytes_.insert(pending_receive_bytes_.end(), raw_inbound.begin(),
                                  raw_inbound.end());
    if (!decode_complete_messages(pending_receive_bytes_, complete_messages_)) {
        failed_ = true;
        complete_messages_.clear();
        pending_receive_bytes_.clear();
        return {};
    }

    return outbound;
}

std::vector<std::vector<std::byte>> QuicDemoChannel::take_messages() {
    if (failed_) {
        complete_messages_.clear();
        return {};
    }

    auto messages = std::move(complete_messages_);
    complete_messages_.clear();
    return messages;
}

bool QuicDemoChannel::is_ready() const {
    return !failed_ && core_.is_handshake_complete();
}

bool QuicDemoChannel::has_failed() const {
    return failed_ || core_.has_failed();
}

} // namespace coquic::quic
