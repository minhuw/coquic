#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

#include "src/io/io_backend.h"

namespace coquic::io {

struct QuicIoBackendBootstrapConfig {
    QuicIoBackendKind kind = QuicIoBackendKind::socket;
    QuicUdpBackendConfig backend;
};

struct QuicClientIoBootstrap {
    std::unique_ptr<QuicIoBackend> backend;
    quic::QuicRouteHandle primary_route_handle = 0;
};

struct QuicServerIoBootstrap {
    std::unique_ptr<QuicIoBackend> backend;
};

std::optional<QuicClientIoBootstrap>
bootstrap_client_io_backend(const QuicIoBackendBootstrapConfig &config, std::string_view host,
                            std::uint16_t port);

std::optional<QuicServerIoBootstrap>
bootstrap_server_io_backend(const QuicIoBackendBootstrapConfig &config, std::string_view host,
                            std::span<const std::uint16_t> ports);

} // namespace coquic::io
