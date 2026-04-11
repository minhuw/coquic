#pragma once

#include <memory>
#include <optional>

#include "src/io/io_engine.h"

namespace coquic::io {

class IoUringIoEngine final : public QuicIoEngine {
  public:
    ~IoUringIoEngine() override;

    IoUringIoEngine(const IoUringIoEngine &) = delete;
    IoUringIoEngine &operator=(const IoUringIoEngine &) = delete;

    static std::unique_ptr<IoUringIoEngine> create();

    bool register_socket(int socket_fd) override;
    bool send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
              std::span<const std::byte> datagram, std::string_view role_name,
              quic::QuicEcnCodepoint ecn) override;
    std::optional<QuicIoEngineEvent> wait(std::span<const int> socket_fds, int idle_timeout_ms,
                                          std::optional<quic::QuicCoreTimePoint> next_wakeup,
                                          std::string_view role_name) override;

  private:
    struct Impl;

    IoUringIoEngine();
    bool initialize();

    std::unique_ptr<Impl> impl_;
};

std::unique_ptr<QuicIoEngine> make_io_uring_io_engine();

} // namespace coquic::io
