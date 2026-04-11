#pragma once

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "src/io/io_engine.h"

namespace coquic::io {

class SharedUdpBackendCore {
  public:
    SharedUdpBackendCore(QuicUdpBackendConfig config, std::unique_ptr<QuicIoEngine> engine);
    ~SharedUdpBackendCore();

    std::optional<QuicIoRemote> resolve_remote(std::string_view host, std::uint16_t port);
    bool open_listener(std::string_view host, std::uint16_t port);
    std::optional<QuicRouteHandle> ensure_route(const QuicIoRemote &remote);
    std::optional<QuicIoEvent> wait(std::optional<QuicCoreTimePoint> next_wakeup);
    bool send(const QuicIoTxDatagram &datagram);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace coquic::io
