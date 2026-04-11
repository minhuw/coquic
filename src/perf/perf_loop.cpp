#include "src/perf/perf_loop.h"

namespace coquic::perf {

std::vector<quic::QuicCoreEndpointInput>
make_endpoint_inputs_from_io_event(const io::QuicIoEvent &event) {
    std::vector<quic::QuicCoreEndpointInput> inputs;
    switch (event.kind) {
    case io::QuicIoEvent::Kind::rx_datagram:
        if (event.datagram.has_value()) {
            inputs.push_back(quic::QuicCoreInboundDatagram{
                .bytes = event.datagram->bytes,
                .route_handle = event.datagram->route_handle,
                .ecn = event.datagram->ecn,
            });
        }
        break;
    case io::QuicIoEvent::Kind::timer_expired:
        inputs.push_back(quic::QuicCoreTimerExpired{});
        break;
    case io::QuicIoEvent::Kind::idle_timeout:
    case io::QuicIoEvent::Kind::shutdown:
        break;
    }
    return inputs;
}

bool flush_send_effects(io::QuicIoBackend &backend, const quic::QuicCoreResult &result) {
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<quic::QuicCoreSendDatagram>(&effect)) {
            if (!send->route_handle.has_value()) {
                return false;
            }
            if (!backend.send(io::QuicIoTxDatagram{
                    .route_handle = *send->route_handle,
                    .bytes = send->bytes,
                    .ecn = send->ecn,
                })) {
                return false;
            }
        }
    }
    return true;
}

} // namespace coquic::perf
