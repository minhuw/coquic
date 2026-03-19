#include "src/quic/core.h"

#include <utility>

#include "src/quic/connection.h"

namespace coquic::quic {

namespace {

template <typename... Ts> struct overloaded : Ts... {
    using Ts::operator()...;
};

template <typename... Ts> overloaded(Ts...) -> overloaded<Ts...>;

} // namespace

QuicCore::QuicCore(QuicCoreConfig config)
    : connection_(std::make_unique<QuicConnection>(std::move(config))) {
}

QuicCore::~QuicCore() = default;

QuicCore::QuicCore(QuicCore &&) noexcept = default;

QuicCore &QuicCore::operator=(QuicCore &&) noexcept = default;

QuicCoreResult QuicCore::advance(QuicCoreInput input, QuicCoreTimePoint now) {
    std::visit(overloaded{
                   [&](const QuicCoreStart &) { connection_->start(); },
                   [&](const QuicCoreInboundDatagram &in) {
                       connection_->process_inbound_datagram(in.bytes, now);
                   },
                   [&](const QuicCoreQueueApplicationData &in) {
                       connection_->queue_application_data(in.bytes);
                   },
                   [&](const QuicCoreTimerExpired &) { connection_->on_timeout(now); },
               },
               input);

    QuicCoreResult result;
    while (true) {
        auto datagram = connection_->drain_outbound_datagram(now);
        if (datagram.empty()) {
            break;
        }
        result.effects.emplace_back(QuicCoreSendDatagram{std::move(datagram)});
    }
    if (auto bytes = connection_->take_received_application_data(); !bytes.empty()) {
        result.effects.emplace_back(QuicCoreReceiveApplicationData{std::move(bytes)});
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
