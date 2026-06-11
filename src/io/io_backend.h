#pragma once

#include <sys/socket.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "src/quic/core.h"

namespace coquic::io {

using quic::QuicCoreTimePoint;
using quic::QuicEcnCodepoint;
using quic::QuicRouteHandle;

enum class QuicIoBackendKind : std::uint8_t {
    socket,
    io_uring,
};

struct QuicUdpBackendConfig {
    std::string role_name;
    int idle_timeout_ms = 0;
    bool enable_pmtud_socket_options = true;
};

struct QuicIoRemote {
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    int family = AF_UNSPEC;
};

struct QuicIoRxDatagram {
    QuicRouteHandle route_handle = 0;
    std::vector<std::byte> bytes;
    std::vector<std::byte> address_validation_identity;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
    std::shared_ptr<std::vector<std::byte>> shared_bytes;
    std::size_t begin = 0;
    std::size_t end = 0;

    std::span<const std::byte> payload() const {
        if (shared_bytes != nullptr) {
            const auto clamped_begin = std::min(begin, shared_bytes->size());
            const auto clamped_end = std::min(std::max(end, clamped_begin), shared_bytes->size());
            return std::span<const std::byte>(*shared_bytes)
                .subspan(clamped_begin, clamped_end - clamped_begin);
        }
        return bytes;
    }
};

struct QuicIoPathMtuUpdate {
    QuicRouteHandle route_handle = 0;
    std::size_t max_udp_payload_size = 0;
    std::vector<std::byte> quoted_packet;
};

struct QuicIoTxDatagram {
    QuicRouteHandle route_handle = 0;
    std::span<const std::byte> bytes_view;
    quic::DatagramBuffer bytes;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect;
    bool is_pmtu_probe = false;

    std::span<const std::byte> payload() const {
        return bytes_view.empty() ? bytes.span() : bytes_view;
    }
};

struct QuicIoEvent {
    enum class Kind : std::uint8_t {
        rx_datagram,
        path_mtu_update,
        timer_expired,
        idle_timeout,
        shutdown,
    };

    Kind kind = Kind::idle_timeout;
    QuicCoreTimePoint now{};
    std::optional<QuicIoRxDatagram> datagram;
    std::optional<QuicIoPathMtuUpdate> path_mtu;
};

class QuicIoBackend {
  public:
    virtual ~QuicIoBackend() = default;

    virtual std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &remote) = 0;
    virtual std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint> next_wakeup) = 0;
    virtual bool has_pending_events() const {
        return false;
    }
    virtual bool send(const QuicIoTxDatagram &datagram) = 0;
    virtual bool send_many(std::span<const QuicIoTxDatagram> datagrams) {
        for (const auto &datagram : datagrams) {
            if (!send(datagram)) {
                return false;
            }
        }
        return true;
    }
    virtual bool send_many_on_route(QuicRouteHandle route_handle,
                                    std::span<const QuicIoTxDatagram> datagrams) {
        for (const auto &datagram : datagrams) {
            QuicIoTxDatagram routed_datagram{
                .route_handle = route_handle,
                .bytes_view = datagram.payload(),
                .ecn = datagram.ecn,
                .is_pmtu_probe = datagram.is_pmtu_probe,
            };
            if (!send(routed_datagram)) {
                return false;
            }
        }
        return true;
    }
};

} // namespace coquic::io
