#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "src/io/io_backend.h"

namespace coquic::io {

struct SocketIoBackendConfig {
    std::string role_name;
    int idle_timeout_ms = 0;
};

class SocketIoBackend final : public QuicIoBackend {
  public:
    explicit SocketIoBackend(SocketIoBackendConfig config);
    ~SocketIoBackend() override;

    SocketIoBackend(const SocketIoBackend &) = delete;
    SocketIoBackend &operator=(const SocketIoBackend &) = delete;

    std::optional<QuicIoRemote> resolve_remote(std::string_view host, std::uint16_t port);
    bool open_listener(std::string_view host, std::uint16_t port);

    std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &remote) override;
    std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint> next_wakeup) override;
    bool send(const QuicIoTxDatagram &datagram) override;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::unique_ptr<QuicIoBackend> make_socket_io_backend(SocketIoBackendConfig config);

} // namespace coquic::io
