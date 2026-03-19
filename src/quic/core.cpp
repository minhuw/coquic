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
    (void)now;

    std::visit(overloaded{
                   [&](const QuicCoreStart &) { connection_->start(); },
                   [&](const QuicCoreInboundDatagram &in) {
                       connection_->process_inbound_datagram(in.bytes);
                   },
                   [&](const QuicCoreQueueApplicationData &in) {
                       connection_->queue_application_data(in.bytes);
                   },
                   [&](const QuicCoreTimerExpired &) {},
               },
               input);

    QuicCoreResult result;
    while (true) {
        auto datagram = connection_->drain_outbound_datagram();
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

std::vector<std::byte> QuicCore::receive(std::vector<std::byte> bytes) {
    if (bytes.empty()) {
        connection_->start();
    } else {
        connection_->process_inbound_datagram(bytes);
    }
    return connection_->drain_outbound_datagram();
}

void QuicCore::queue_application_data(std::vector<std::byte> bytes) {
    connection_->queue_application_data(bytes);
}

std::vector<std::byte> QuicCore::take_received_application_data() {
    return connection_->take_received_application_data();
}

bool QuicCore::is_handshake_complete() const {
    return connection_->is_handshake_complete();
}

bool QuicCore::has_failed() const {
    return connection_->has_failed();
}

} // namespace coquic::quic
