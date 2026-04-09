#include "src/quic/socket_io_backend.h"

#include <utility>

namespace coquic::quic {

struct SocketIoBackend::Impl {
    explicit Impl(SocketIoBackendConfig backend_config) : config(std::move(backend_config)) {
    }

    SocketIoBackendConfig config;
};

SocketIoBackend::SocketIoBackend(SocketIoBackendConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {
}

SocketIoBackend::~SocketIoBackend() = default;

std::optional<QuicIoRemote> SocketIoBackend::resolve_remote(std::string_view, std::uint16_t) {
    return std::nullopt;
}

bool SocketIoBackend::open_listener(std::string_view, std::uint16_t) {
    return false;
}

std::optional<QuicRouteHandle> SocketIoBackend::ensure_route(const QuicIoRemote &) {
    return std::nullopt;
}

std::optional<QuicIoEvent> SocketIoBackend::wait(std::optional<QuicCoreTimePoint>) {
    return std::nullopt;
}

bool SocketIoBackend::send(const QuicIoTxDatagram &) {
    return false;
}

std::unique_ptr<QuicIoBackend> make_socket_io_backend(SocketIoBackendConfig config) {
    return std::make_unique<SocketIoBackend>(std::move(config));
}

} // namespace coquic::quic
