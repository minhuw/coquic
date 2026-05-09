#include "src/perf/perf_loop.h"

#include <algorithm>
#include <utility>

namespace coquic::perf {

std::optional<quic::QuicCoreEndpointInput>
make_endpoint_input_from_io_event(io::QuicIoEvent &event) {
    switch (event.kind) {
    case io::QuicIoEvent::Kind::rx_datagram:
        if (event.datagram.has_value()) {
            return quic::QuicCoreInboundDatagram{
                .bytes = std::move(event.datagram->bytes),
                .route_handle = event.datagram->route_handle,
                .ecn = event.datagram->ecn,
            };
        }
        break;
    case io::QuicIoEvent::Kind::path_mtu_update:
        if (event.path_mtu.has_value()) {
            return quic::QuicCorePathMtuUpdate{
                .route_handle = event.path_mtu->route_handle,
                .max_udp_payload_size = event.path_mtu->max_udp_payload_size,
            };
        }
        break;
    case io::QuicIoEvent::Kind::timer_expired:
        return quic::QuicCoreTimerExpired{};
    case io::QuicIoEvent::Kind::idle_timeout:
    case io::QuicIoEvent::Kind::shutdown:
        break;
    }
    return std::nullopt;
}

bool flush_send_effects(io::QuicIoBackend &backend, const quic::QuicCoreResult &result) {
    const auto has_send_datagram =
        std::any_of(result.effects.begin(), result.effects.end(), [](const auto &effect) {
            return std::holds_alternative<quic::QuicCoreSendDatagram>(effect);
        });
    if (!has_send_datagram) {
        return true;
    }

    std::vector<io::QuicIoTxDatagram> datagrams;
    datagrams.reserve(result.effects.size());
    for (const auto &effect : result.effects) {
        if (const auto *send = std::get_if<quic::QuicCoreSendDatagram>(&effect)) {
            if (!send->route_handle.has_value()) {
                return false;
            }
            datagrams.push_back(io::QuicIoTxDatagram{
                .route_handle = *send->route_handle,
                .bytes_view = send->bytes.span(),
                .ecn = send->ecn,
                .is_pmtu_probe = send->is_pmtu_probe,
            });
        }
    }
    return backend.send_many(datagrams);
}

} // namespace coquic::perf
