#include "src/quic/core.h"

#include <array>
#include <utility>

#include "src/quic/connection.h"
#include "src/quic/streams.h"

namespace coquic::quic {

namespace {

template <typename... Ts> struct overloaded : Ts... {
    using Ts::operator()...;
};

template <typename... Ts> overloaded(Ts...) -> overloaded<Ts...>;

constexpr auto kStreamStateErrorMap = std::to_array<QuicCoreLocalErrorCode>({
    QuicCoreLocalErrorCode::invalid_stream_id,
    QuicCoreLocalErrorCode::invalid_stream_direction,
    QuicCoreLocalErrorCode::send_side_closed,
    QuicCoreLocalErrorCode::receive_side_closed,
    QuicCoreLocalErrorCode::final_size_conflict,
});

static_assert(kStreamStateErrorMap.size() ==
              static_cast<std::size_t>(StreamStateErrorCode::final_size_conflict) + 1);

QuicCoreLocalError stream_state_error_to_local_error(const StreamStateError &error) {
    return QuicCoreLocalError{
        .code = kStreamStateErrorMap[static_cast<std::size_t>(error.code)],
        .stream_id = error.stream_id,
    };
}

} // namespace

QuicCore::QuicCore(QuicCoreConfig config)
    : connection_(std::make_unique<QuicConnection>(std::move(config))) {
}

QuicCore::~QuicCore() = default;

QuicCore::QuicCore(QuicCore &&) noexcept = default;

QuicCore &QuicCore::operator=(QuicCore &&) noexcept = default;

QuicCoreResult QuicCore::advance(QuicCoreInput input, QuicCoreTimePoint now) {
    QuicCoreResult result;
    std::visit(overloaded{
                   [&](const QuicCoreStart &) { connection_->start(); },
                   [&](const QuicCoreInboundDatagram &in) {
                       connection_->process_inbound_datagram(in.bytes, now);
                   },
                   [&](const QuicCoreSendStreamData &in) {
                       const auto queued =
                           connection_->queue_stream_send(in.stream_id, in.bytes, in.fin);
                       if (!queued.has_value()) {
                           result.local_error = stream_state_error_to_local_error(queued.error());
                       }
                   },
                   [&](const QuicCoreResetStream &in) {
                       const auto queued = connection_->queue_stream_reset(LocalResetCommand{
                           .stream_id = in.stream_id,
                           .application_error_code = in.application_error_code,
                       });
                       if (!queued.has_value()) {
                           result.local_error = stream_state_error_to_local_error(queued.error());
                       }
                   },
                   [&](const QuicCoreStopSending &in) {
                       const auto queued = connection_->queue_stop_sending(LocalStopSendingCommand{
                           .stream_id = in.stream_id,
                           .application_error_code = in.application_error_code,
                       });
                       if (!queued.has_value()) {
                           result.local_error = stream_state_error_to_local_error(queued.error());
                       }
                   },
                   [&](const QuicCoreTimerExpired &) { connection_->on_timeout(now); },
               },
               input);

    while (true) {
        auto datagram = connection_->drain_outbound_datagram(now);
        if (datagram.empty()) {
            break;
        }
        result.effects.emplace_back(QuicCoreSendDatagram{std::move(datagram)});
    }
    while (const auto received = connection_->take_received_stream_data()) {
        result.effects.emplace_back(*received);
    }
    while (const auto reset = connection_->take_peer_reset_stream()) {
        result.effects.emplace_back(*reset);
    }
    while (const auto stop = connection_->take_peer_stop_sending()) {
        result.effects.emplace_back(*stop);
    }
    while (const auto event = connection_->take_state_change()) {
        result.effects.emplace_back(QuicCoreStateEvent{*event});
    }
    result.next_wakeup = connection_->next_wakeup();
    return result;
}

bool QuicCore::is_handshake_complete() const {
    return connection_->is_handshake_complete();
}

bool QuicCore::has_failed() const {
    return connection_->has_failed();
}

} // namespace coquic::quic
