#pragma once

#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "src/io/io_backend.h"

namespace coquic::io {

struct QuicIoEngineTxDatagram {
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    std::span<const std::byte> bytes;
    quic::QuicEcnCodepoint ecn = quic::QuicEcnCodepoint::not_ect;
    bool is_pmtu_probe = false;
};

struct QuicIoEngineRxCompletion {
    int socket_fd = -1;
    std::vector<std::byte> bytes;
    quic::QuicEcnCodepoint ecn = quic::QuicEcnCodepoint::unavailable;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    quic::QuicCoreTimePoint now{};
};

struct QuicIoEnginePathMtuUpdate {
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    std::size_t max_udp_payload_size = 0;
    quic::QuicCoreTimePoint now{};
};

struct QuicIoEngineEvent {
    enum class Kind : std::uint8_t {
        rx_datagram,
        path_mtu_update,
        timer_expired,
        idle_timeout,
        shutdown,
    };

    Kind kind = Kind::idle_timeout;
    quic::QuicCoreTimePoint now{};
    std::optional<QuicIoEngineRxCompletion> rx;
    std::optional<QuicIoEnginePathMtuUpdate> path_mtu;
};

class QuicIoEngine {
  public:
    virtual ~QuicIoEngine() = default;

    virtual bool register_socket(int socket_fd) = 0;
    virtual bool send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
                      std::span<const std::byte> datagram, std::string_view role_name,
                      quic::QuicEcnCodepoint ecn, bool is_pmtu_probe = false) = 0;
    virtual bool send_many(std::span<const QuicIoEngineTxDatagram> datagrams,
                           std::string_view role_name) {
        for (const auto &datagram : datagrams) {
            if (!send(datagram.socket_fd, datagram.peer, datagram.peer_len, datagram.bytes,
                      role_name, datagram.ecn, datagram.is_pmtu_probe)) {
                return false;
            }
        }
        return true;
    }
    virtual std::optional<QuicIoEngineEvent>
    wait(std::span<const int> socket_fds, int idle_timeout_ms,
         std::optional<quic::QuicCoreTimePoint> next_wakeup, std::string_view role_name) = 0;
};

} // namespace coquic::io
