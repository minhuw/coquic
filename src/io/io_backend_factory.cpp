#include "src/io/io_backend_factory.h"

#include "src/io/socket_io_backend.h"

#include <iostream>

namespace coquic::io {

std::optional<QuicClientIoBootstrap>
bootstrap_client_io_backend(const QuicIoBackendBootstrapConfig &config, std::string_view host,
                            std::uint16_t port) {
    switch (config.kind) {
    case QuicIoBackendKind::socket: {
        auto backend = std::make_unique<SocketIoBackend>(SocketIoBackendConfig{
            .role_name = config.backend.role_name,
            .idle_timeout_ms = config.backend.idle_timeout_ms,
        });
        const auto remote = backend->resolve_remote(host, port);
        if (!remote.has_value()) {
            return std::nullopt;
        }
        const auto route_handle = backend->ensure_route(*remote);
        if (!route_handle.has_value()) {
            return std::nullopt;
        }
        return QuicClientIoBootstrap{
            .backend = std::move(backend),
            .primary_route_handle = *route_handle,
        };
    }
    case QuicIoBackendKind::io_uring:
        std::cerr << "io-" << config.backend.role_name << " failed: io_uring backend unavailable\n";
        return std::nullopt;
    }

    return std::nullopt;
}

std::optional<QuicServerIoBootstrap>
bootstrap_server_io_backend(const QuicIoBackendBootstrapConfig &config, std::string_view host,
                            std::span<const std::uint16_t> ports) {
    switch (config.kind) {
    case QuicIoBackendKind::socket: {
        auto backend = std::make_unique<SocketIoBackend>(SocketIoBackendConfig{
            .role_name = config.backend.role_name,
            .idle_timeout_ms = config.backend.idle_timeout_ms,
        });
        for (const auto port : ports) {
            if (!backend->open_listener(host, port)) {
                return std::nullopt;
            }
        }
        return QuicServerIoBootstrap{
            .backend = std::move(backend),
        };
    }
    case QuicIoBackendKind::io_uring:
        std::cerr << "io-" << config.backend.role_name << " failed: io_uring backend unavailable\n";
        return std::nullopt;
    }

    return std::nullopt;
}

} // namespace coquic::io
