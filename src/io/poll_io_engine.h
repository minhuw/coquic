#pragma once

#include "src/io/io_engine.h"

namespace coquic::io {

class PollIoEngine final : public QuicIoEngine {
  public:
    PollIoEngine() = default;
    ~PollIoEngine() override = default;

    bool register_socket(int socket_fd) override;
    bool send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
              std::span<const std::byte> datagram, std::string_view role_name,
              quic::QuicEcnCodepoint ecn) override;
    std::optional<QuicIoEngineEvent> wait(std::span<const int> socket_fds, int idle_timeout_ms,
                                          std::optional<quic::QuicCoreTimePoint> next_wakeup,
                                          std::string_view role_name) override;
};

} // namespace coquic::io
