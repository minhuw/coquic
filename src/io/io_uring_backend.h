#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include "src/io/io_backend.h"

namespace coquic::io {

class QuicIoEngine;
class SharedUdpBackendCore;

class IoUringBackend final : public QuicIoBackend {
  public:
    ~IoUringBackend() override;

    IoUringBackend(const IoUringBackend &) = delete;
    IoUringBackend &operator=(const IoUringBackend &) = delete;

    static std::unique_ptr<IoUringBackend> create(QuicUdpBackendConfig config);

    std::optional<QuicIoRemote> resolve_remote(std::string_view host, std::uint16_t port);
    bool open_listener(std::string_view host, std::uint16_t port);

    std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &remote) override;
    std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint> next_wakeup) override;
    bool send(const QuicIoTxDatagram &datagram) override;

  private:
    IoUringBackend(QuicUdpBackendConfig config, std::unique_ptr<QuicIoEngine> engine);

    std::unique_ptr<SharedUdpBackendCore> core_;
};

std::unique_ptr<IoUringBackend> make_io_uring_backend(QuicUdpBackendConfig config);

} // namespace coquic::io
