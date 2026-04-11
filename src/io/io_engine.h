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

struct QuicIoEngineRxCompletion {
    int socket_fd = -1;
    std::vector<std::byte> bytes;
    quic::QuicEcnCodepoint ecn = quic::QuicEcnCodepoint::unavailable;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    quic::QuicCoreTimePoint now{};
};

struct QuicIoEngineEvent {
    enum class Kind : std::uint8_t {
        rx_datagram,
        timer_expired,
        idle_timeout,
        shutdown,
    };

    Kind kind = Kind::idle_timeout;
    quic::QuicCoreTimePoint now{};
    std::optional<QuicIoEngineRxCompletion> rx;
};

class QuicIoEngine {
  public:
    virtual ~QuicIoEngine() = default;

    virtual bool register_socket(int socket_fd) = 0;
    virtual bool send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
                      std::span<const std::byte> datagram, std::string_view role_name,
                      quic::QuicEcnCodepoint ecn) = 0;
    virtual std::optional<QuicIoEngineEvent>
    wait(std::span<const int> socket_fds, int idle_timeout_ms,
         std::optional<quic::QuicCoreTimePoint> next_wakeup, std::string_view role_name) = 0;
};

} // namespace coquic::io
