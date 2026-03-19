#include "src/quic/core.h"

#include <utility>

#include "src/quic/connection.h"
#include "src/quic/streams.h"

namespace coquic::quic {

namespace {

template <typename... Ts> struct overloaded : Ts... {
    using Ts::operator()...;
};

template <typename... Ts> overloaded(Ts...) -> overloaded<Ts...>;

QuicCoreLocalError unsupported_operation_error(std::uint64_t stream_id) {
    return QuicCoreLocalError{
        .code = QuicCoreLocalErrorCode::unsupported_operation,
        .stream_id = stream_id,
    };
}

QuicCoreLocalError stream_state_error_to_local_error(const StreamStateError &error) {
    auto code = QuicCoreLocalErrorCode::invalid_stream_id;
    switch (error.code) {
    case StreamStateErrorCode::invalid_stream_id:
        code = QuicCoreLocalErrorCode::invalid_stream_id;
        break;
    case StreamStateErrorCode::invalid_stream_direction:
        code = QuicCoreLocalErrorCode::invalid_stream_direction;
        break;
    case StreamStateErrorCode::send_side_closed:
        code = QuicCoreLocalErrorCode::send_side_closed;
        break;
    case StreamStateErrorCode::receive_side_closed:
        code = QuicCoreLocalErrorCode::receive_side_closed;
        break;
    case StreamStateErrorCode::final_size_conflict:
        code = QuicCoreLocalErrorCode::final_size_conflict;
        break;
    }

    return QuicCoreLocalError{
        .code = code,
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
                       result.local_error = unsupported_operation_error(in.stream_id);
                   },
                   [&](const QuicCoreStopSending &in) {
                       result.local_error = unsupported_operation_error(in.stream_id);
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
