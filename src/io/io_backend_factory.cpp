#include "src/io/io_backend_factory.h"

#include "src/io/io_backend_test_hooks.h"
#include "src/io/io_uring_backend.h"
#include "src/io/socket_io_backend.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>

#include <liburing.h>

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
            std::cerr << "io-" << config.backend.role_name << " failed: invalid host address\n";
            return std::nullopt;
        }
        const auto route_handle = backend->ensure_route(*remote);
        if (!route_handle.has_value()) {
            std::cerr << "io-" << config.backend.role_name
                      << " failed: unable to create UDP socket: " << std::strerror(errno) << '\n';
            return std::nullopt;
        }
        return QuicClientIoBootstrap{
            .backend = std::move(backend),
            .primary_route_handle = *route_handle,
        };
    }
    case QuicIoBackendKind::io_uring: {
        auto backend = make_io_uring_backend(QuicUdpBackendConfig{
            .role_name = config.backend.role_name,
            .idle_timeout_ms = config.backend.idle_timeout_ms,
        });
        if (backend == nullptr) {
            std::cerr << "io-" << config.backend.role_name
                      << " failed: unable to initialize io_uring\n";
            return std::nullopt;
        }
        const auto remote = backend->resolve_remote(host, port);
        if (!remote.has_value()) {
            std::cerr << "io-" << config.backend.role_name << " failed: invalid host address\n";
            return std::nullopt;
        }
        const auto route_handle = backend->ensure_route(*remote);
        if (!route_handle.has_value()) {
            std::cerr << "io-" << config.backend.role_name
                      << " failed: unable to create UDP socket: " << std::strerror(errno) << '\n';
            return std::nullopt;
        }
        return QuicClientIoBootstrap{
            .backend = std::move(backend),
            .primary_route_handle = *route_handle,
        };
    }
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
    case QuicIoBackendKind::io_uring: {
        auto backend = make_io_uring_backend(QuicUdpBackendConfig{
            .role_name = config.backend.role_name,
            .idle_timeout_ms = config.backend.idle_timeout_ms,
        });
        if (backend == nullptr) {
            std::cerr << "io-" << config.backend.role_name
                      << " failed: unable to initialize io_uring\n";
            return std::nullopt;
        }
        for (const auto port : ports) {
            if (!backend->open_listener(host, port)) {
                return std::nullopt;
            }
        }
        return QuicServerIoBootstrap{
            .backend = std::move(backend),
        };
    }
    }

    return std::nullopt;
}

namespace test {

namespace {

int queue_init_success_for_factory_tests(unsigned, io_uring *, unsigned) {
    return 0;
}

void queue_exit_noop_for_factory_tests(io_uring *) {
}

io_uring_sqe *get_sqe_for_factory_tests(io_uring *) {
    static thread_local io_uring_sqe sqe{};
    sqe = {};
    return &sqe;
}

int submit_success_for_factory_tests(io_uring *) {
    return 0;
}

int fail_getaddrinfo_for_factory_tests(const char *, const char *, const addrinfo *, addrinfo **) {
    return 1;
}

int fail_socket_for_factory_tests(int, int, int) {
    errno = EMFILE;
    return -1;
}

QuicIoBackendKind invalid_backend_kind_for_factory_tests() {
    constexpr std::uint8_t raw_kind = 0xff;
    auto kind = QuicIoBackendKind::socket;
    std::memcpy(&kind, &raw_kind, sizeof(kind));
    return kind;
}

QuicIoBackendBootstrapConfig make_io_uring_factory_config_for_tests(QuicIoBackendKind kind) {
    return QuicIoBackendBootstrapConfig{
        .kind = kind,
        .backend =
            QuicUdpBackendConfig{
                .role_name = "factory-test",
                .idle_timeout_ms = 5,
            },
    };
}

IoUringBackendOpsOverride deterministic_io_uring_ops_for_factory_tests() {
    return IoUringBackendOpsOverride{
        .queue_init_fn = &queue_init_success_for_factory_tests,
        .queue_exit_fn = &queue_exit_noop_for_factory_tests,
        .get_sqe_fn = &get_sqe_for_factory_tests,
        .submit_fn = &submit_success_for_factory_tests,
    };
}

bool client_bootstrap_is_usable_for_factory_tests(
    const std::optional<QuicClientIoBootstrap> &bootstrap) {
    if (!bootstrap.has_value()) {
        return false;
    }
    return (bootstrap->backend != nullptr) & (bootstrap->primary_route_handle != 0);
}

bool server_bootstrap_is_usable_for_factory_tests(
    const std::optional<QuicServerIoBootstrap> &bootstrap) {
    if (!bootstrap.has_value()) {
        return false;
    }
    return bootstrap->backend != nullptr;
}

} // namespace

bool io_backend_factory_coverage_for_tests() {
    bool covered = true;

    {
        const ScopedIoUringBackendOpsOverride io_uring_ops{
            deterministic_io_uring_ops_for_factory_tests(),
        };
        const ScopedSocketIoBackendOpsOverride socket_ops{
            SocketIoBackendOpsOverride{
                .getaddrinfo_fn = &fail_getaddrinfo_for_factory_tests,
            },
        };
        const auto bootstrap = bootstrap_client_io_backend(
            make_io_uring_factory_config_for_tests(QuicIoBackendKind::io_uring), "invalid-host",
            4433);
        covered =
            static_cast<bool>(covered & !client_bootstrap_is_usable_for_factory_tests(bootstrap));
    }

    {
        const ScopedIoUringBackendOpsOverride io_uring_ops{
            deterministic_io_uring_ops_for_factory_tests(),
        };
        const auto bootstrap = bootstrap_client_io_backend(
            make_io_uring_factory_config_for_tests(QuicIoBackendKind::io_uring), "127.0.0.1", 4433);
        covered =
            static_cast<bool>(covered & client_bootstrap_is_usable_for_factory_tests(bootstrap));
    }

    {
        const ScopedIoUringBackendOpsOverride io_uring_ops{
            deterministic_io_uring_ops_for_factory_tests(),
        };
        const ScopedSocketIoBackendOpsOverride socket_ops{
            SocketIoBackendOpsOverride{
                .socket_fn = &fail_socket_for_factory_tests,
            },
        };
        const std::array<std::uint16_t, 1> ports = {0};
        const auto bootstrap = bootstrap_server_io_backend(
            make_io_uring_factory_config_for_tests(QuicIoBackendKind::io_uring), "127.0.0.1",
            ports);
        covered =
            static_cast<bool>(covered & !server_bootstrap_is_usable_for_factory_tests(bootstrap));
    }

    {
        const ScopedIoUringBackendOpsOverride io_uring_ops{
            deterministic_io_uring_ops_for_factory_tests(),
        };
        const std::array<std::uint16_t, 2> ports = {0, 0};
        const auto bootstrap = bootstrap_server_io_backend(
            make_io_uring_factory_config_for_tests(QuicIoBackendKind::io_uring), "127.0.0.1",
            ports);
        covered =
            static_cast<bool>(covered & server_bootstrap_is_usable_for_factory_tests(bootstrap));
    }

    {
        const auto bootstrap = bootstrap_client_io_backend(
            make_io_uring_factory_config_for_tests(invalid_backend_kind_for_factory_tests()),
            "127.0.0.1", 4433);
        covered =
            static_cast<bool>(covered & !client_bootstrap_is_usable_for_factory_tests(bootstrap));
    }

    const std::array<std::uint16_t, 1> ports = {0};
    {
        const auto bootstrap = bootstrap_server_io_backend(
            make_io_uring_factory_config_for_tests(invalid_backend_kind_for_factory_tests()),
            "127.0.0.1", ports);
        covered =
            static_cast<bool>(covered & !server_bootstrap_is_usable_for_factory_tests(bootstrap));
    }

    return covered;
}

} // namespace test

} // namespace coquic::io
