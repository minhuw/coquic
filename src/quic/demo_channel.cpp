#include "src/quic/demo_channel.h"

#include <array>
#include <cstdint>
#include <utility>

namespace coquic::quic {
namespace {

constexpr std::size_t kMessageMaxBytes = static_cast<std::size_t>(64) * 1024U;

template <typename... Ts> struct overloaded : Ts... {
    using Ts::operator()...;
};

template <typename... Ts> overloaded(Ts...) -> overloaded<Ts...>;

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

QuicDemoChannelResult QuicDemoChannel::advance(QuicDemoChannelInput input, QuicCoreTimePoint now) {
    if (has_failed()) {
        return QuicDemoChannelResult{
            .next_wakeup = std::nullopt,
        };
    }

    return std::visit(overloaded{
                          [&](QuicCoreStart start) {
                              const bool was_ready = core_.is_handshake_complete();
                              auto result = process_core_result(core_.advance(start, now));
                              if (!has_failed() && !was_ready && core_.is_handshake_complete() &&
                                  !pending_send_bytes_.empty()) {
                                  merge_result(result, flush_buffered_messages(now));
                              }
                              return result;
                          },
                          [&](QuicCoreInboundDatagram inbound) {
                              const bool was_ready = core_.is_handshake_complete();
                              auto result =
                                  process_core_result(core_.advance(std::move(inbound), now));
                              if (!has_failed() && !was_ready && core_.is_handshake_complete() &&
                                  !pending_send_bytes_.empty()) {
                                  merge_result(result, flush_buffered_messages(now));
                              }
                              return result;
                          },
                          [&](QuicDemoChannelQueueMessage queued) {
                              return queue_message(std::move(queued.bytes), now);
                          },
                          [&](QuicCoreTimerExpired expired) {
                              const bool was_ready = core_.is_handshake_complete();
                              auto result = process_core_result(core_.advance(expired, now));
                              if (!has_failed() && !was_ready && core_.is_handshake_complete() &&
                                  !pending_send_bytes_.empty()) {
                                  merge_result(result, flush_buffered_messages(now));
                              }
                              return result;
                          },
                      },
                      std::move(input));
}

bool QuicDemoChannel::is_ready() const {
    return !has_failed() && core_.is_handshake_complete();
}

bool QuicDemoChannel::has_failed() const {
    return failed_ || core_.has_failed();
}

QuicDemoChannelResult QuicDemoChannel::process_core_result(QuicCoreResult result) {
    next_wakeup_ = result.next_wakeup;
    QuicDemoChannelResult translated{
        .next_wakeup = next_wakeup_,
    };

    for (auto &effect : result.effects) {
        if (auto *send = std::get_if<QuicCoreSendDatagram>(&effect)) {
            translated.effects.emplace_back(QuicCoreSendDatagram{std::move(send->bytes)});
            continue;
        }
        if (auto *received = std::get_if<QuicCoreReceiveApplicationData>(&effect)) {
            if (!translate_receive_application_data(*received, translated)) {
                return fail_channel();
            }
            continue;
        }
        const auto *state_event = std::get_if<QuicCoreStateEvent>(&effect);
        if (state_event != nullptr && !translate_state_event(*state_event, translated)) {
            return fail_channel();
        }
    }

    return translated;
}

void QuicDemoChannel::merge_result(QuicDemoChannelResult &destination,
                                   QuicDemoChannelResult source) {
    destination.effects.insert(destination.effects.end(),
                               std::make_move_iterator(source.effects.begin()),
                               std::make_move_iterator(source.effects.end()));
    destination.next_wakeup = source.next_wakeup;
    next_wakeup_ = destination.next_wakeup;
}

QuicDemoChannelResult QuicDemoChannel::fail_channel() {
    pending_send_bytes_.clear();
    pending_receive_bytes_.clear();
    failed_ = true;
    next_wakeup_ = std::nullopt;

    QuicDemoChannelResult result{
        .next_wakeup = std::nullopt,
    };
    if (!failed_emitted_) {
        failed_emitted_ = true;
        result.effects.emplace_back(QuicDemoChannelStateEvent{
            .change = QuicDemoChannelStateChange::failed,
        });
    }

    return result;
}

QuicDemoChannelResult QuicDemoChannel::queue_message(std::vector<std::byte> bytes,
                                                     QuicCoreTimePoint now) {
    if (bytes.size() > kMessageMaxBytes) {
        return fail_channel();
    }

    auto framed = frame_message_bytes(std::move(bytes));
    if (!core_.is_handshake_complete()) {
        pending_send_bytes_.insert(pending_send_bytes_.end(), framed.begin(), framed.end());
        return QuicDemoChannelResult{
            .next_wakeup = next_wakeup_,
        };
    }

    return process_core_result(core_.advance(
        QuicCoreQueueApplicationData{
            .bytes = std::move(framed),
        },
        now));
}

QuicDemoChannelResult QuicDemoChannel::flush_buffered_messages(QuicCoreTimePoint now) {
    if (pending_send_bytes_.empty()) {
        return {};
    }

    auto bytes = std::move(pending_send_bytes_);
    pending_send_bytes_.clear();
    return process_core_result(core_.advance(
        QuicCoreQueueApplicationData{
            .bytes = std::move(bytes),
        },
        now));
}

bool QuicDemoChannel::translate_state_event(const QuicCoreStateEvent &event,
                                            QuicDemoChannelResult &result) {
    if (event.change == QuicCoreStateChange::handshake_ready) {
        if (ready_emitted_ || has_failed()) {
            return true;
        }
        ready_emitted_ = true;
        result.effects.emplace_back(QuicDemoChannelStateEvent{
            .change = QuicDemoChannelStateChange::ready,
        });
        return true;
    }

    if (event.change == QuicCoreStateChange::failed) {
        auto failed_result = fail_channel();
        merge_result(result, std::move(failed_result));
    }

    return true;
}

bool QuicDemoChannel::translate_receive_application_data(
    const QuicCoreReceiveApplicationData &received, QuicDemoChannelResult &result) {
    pending_receive_bytes_.insert(pending_receive_bytes_.end(), received.bytes.begin(),
                                  received.bytes.end());

    auto messages = std::vector<std::vector<std::byte>>{};
    if (!decode_complete_messages(pending_receive_bytes_, messages)) {
        return false;
    }

    for (auto &message : messages) {
        result.effects.emplace_back(QuicDemoChannelReceiveMessage{
            .bytes = std::move(message),
        });
    }

    return true;
}

} // namespace coquic::quic
