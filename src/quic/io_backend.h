#pragma once

#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "src/quic/core.h"

namespace coquic::quic {

struct QuicIoRemote {
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    int family = AF_UNSPEC;
};

struct QuicIoRxDatagram {
    QuicRouteHandle route_handle = 0;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
};

struct QuicIoTxDatagram {
    QuicRouteHandle route_handle = 0;
    std::vector<std::byte> bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
};

struct QuicIoEvent {
    enum class Kind : std::uint8_t {
        rx_datagram,
        timer_expired,
        idle_timeout,
        shutdown,
    };

    Kind kind = Kind::idle_timeout;
    QuicCoreTimePoint now{};
    std::optional<QuicIoRxDatagram> datagram;
};

class QuicIoBackend {
  public:
    virtual ~QuicIoBackend() = default;

    virtual std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &remote) = 0;
    virtual std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint> next_wakeup) = 0;
    virtual bool send(const QuicIoTxDatagram &datagram) = 0;
};

} // namespace coquic::quic
