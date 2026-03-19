#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

#include "src/quic/core.h"

namespace coquic::quic {

enum class QuicDemoChannelStateChange : std::uint8_t {
    ready,
    failed,
};

struct QuicDemoChannelQueueMessage {
    std::vector<std::byte> bytes;
};

using QuicDemoChannelInput = std::variant<QuicCoreStart, QuicCoreInboundDatagram,
                                          QuicDemoChannelQueueMessage, QuicCoreTimerExpired>;

struct QuicDemoChannelReceiveMessage {
    std::vector<std::byte> bytes;
};

struct QuicDemoChannelStateEvent {
    QuicDemoChannelStateChange change;
};

using QuicDemoChannelEffect =
    std::variant<QuicCoreSendDatagram, QuicDemoChannelReceiveMessage, QuicDemoChannelStateEvent>;

struct QuicDemoChannelResult {
    std::vector<QuicDemoChannelEffect> effects;
    std::optional<QuicCoreTimePoint> next_wakeup;
};

class QuicDemoChannel {
  public:
    explicit QuicDemoChannel(QuicCoreConfig config);

    QuicDemoChannelResult advance(QuicDemoChannelInput input, QuicCoreTimePoint now);
    bool is_ready() const;
    bool has_failed() const;

  private:
    QuicDemoChannelResult process_core_result(QuicCoreResult result);
    void merge_result(QuicDemoChannelResult &destination, QuicDemoChannelResult source);
    QuicDemoChannelResult fail_channel();
    QuicDemoChannelResult queue_message(std::vector<std::byte> bytes, QuicCoreTimePoint now);
    QuicDemoChannelResult flush_buffered_messages(QuicCoreTimePoint now);
    bool translate_state_event(const QuicCoreStateEvent &event, QuicDemoChannelResult &result);
    bool translate_receive_application_data(const QuicCoreReceiveStreamData &received,
                                            QuicDemoChannelResult &result);

    QuicCore core_;
    std::vector<std::byte> pending_send_bytes_;
    std::vector<std::byte> pending_receive_bytes_;
    bool failed_ = false;
    bool ready_emitted_ = false;
    bool failed_emitted_ = false;
    std::optional<QuicCoreTimePoint> next_wakeup_ = std::nullopt;
};

} // namespace coquic::quic
