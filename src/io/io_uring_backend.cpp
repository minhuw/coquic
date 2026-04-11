#include "src/io/io_uring_backend.h"

#include "src/io/io_uring_io_engine.h"
#include "src/io/shared_udp_backend_core.h"

#include <memory>
#include <utility>

namespace coquic::io {

IoUringBackend::IoUringBackend(QuicUdpBackendConfig config, std::unique_ptr<QuicIoEngine> engine)
    : core_(std::make_unique<SharedUdpBackendCore>(std::move(config), std::move(engine))) {
}

IoUringBackend::~IoUringBackend() = default;

std::unique_ptr<IoUringBackend> IoUringBackend::create(QuicUdpBackendConfig config) {
    auto engine = make_io_uring_io_engine();
    if (engine == nullptr) {
        return nullptr;
    }
    return std::unique_ptr<IoUringBackend>(
        new IoUringBackend(std::move(config), std::move(engine)));
}

std::optional<QuicIoRemote> IoUringBackend::resolve_remote(std::string_view host,
                                                           std::uint16_t port) {
    return core_->resolve_remote(host, port);
}

bool IoUringBackend::open_listener(std::string_view host, std::uint16_t port) {
    return core_->open_listener(host, port);
}

std::optional<QuicRouteHandle> IoUringBackend::ensure_route(const QuicIoRemote &remote) {
    return core_->ensure_route(remote);
}

std::optional<QuicIoEvent> IoUringBackend::wait(std::optional<QuicCoreTimePoint> next_wakeup) {
    return core_->wait(next_wakeup);
}

bool IoUringBackend::send(const QuicIoTxDatagram &datagram) {
    return core_->send(datagram);
}

std::unique_ptr<IoUringBackend> make_io_uring_backend(QuicUdpBackendConfig config) {
    return IoUringBackend::create(std::move(config));
}

} // namespace coquic::io
