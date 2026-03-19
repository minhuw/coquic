#include "src/quic/core.h"

#include <utility>

#include "src/quic/connection.h"

namespace coquic::quic {

namespace {

constexpr std::uint64_t kCompatibleStreamId = 0;

template <typename... Ts> struct overloaded : Ts... {
    using Ts::operator()...;
};

template <typename... Ts> overloaded(Ts...) -> overloaded<Ts...>;

QuicCoreLocalError invalid_stream_id_error(std::uint64_t stream_id) {
    return QuicCoreLocalError{
        .code = QuicCoreLocalErrorCode::invalid_stream_id,
        .stream_id = stream_id,
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
                       if (in.stream_id != kCompatibleStreamId) {
                           result.local_error = invalid_stream_id_error(in.stream_id);
                           return;
                       }
                       if (in.fin) {
                           result.local_error = QuicCoreLocalError{
                               .code = QuicCoreLocalErrorCode::final_size_conflict,
                               .stream_id = in.stream_id,
                           };
                           return;
                       }
                       connection_->queue_application_data(in.bytes);
                   },
                   [&](const QuicCoreResetStream &in) {
                       if (in.stream_id != kCompatibleStreamId) {
                           result.local_error = invalid_stream_id_error(in.stream_id);
                           return;
                       }
                       result.local_error = QuicCoreLocalError{
                           .code = QuicCoreLocalErrorCode::send_side_closed,
                           .stream_id = in.stream_id,
                       };
                   },
                   [&](const QuicCoreStopSending &in) {
                       if (in.stream_id != kCompatibleStreamId) {
                           result.local_error = invalid_stream_id_error(in.stream_id);
                           return;
                       }
                       result.local_error = QuicCoreLocalError{
                           .code = QuicCoreLocalErrorCode::receive_side_closed,
                           .stream_id = in.stream_id,
                       };
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
    if (auto bytes = connection_->take_received_application_data(); !bytes.empty()) {
        result.effects.emplace_back(QuicCoreReceiveStreamData{
            .stream_id = kCompatibleStreamId,
            .bytes = std::move(bytes),
            .fin = false,
        });
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
