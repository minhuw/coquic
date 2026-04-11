#include "src/perf/perf_runtime.h"

#include "src/perf/perf_server.h"

#include <charconv>
#include <chrono>
#include <iostream>
#include <limits>
#include <string_view>

namespace coquic::perf {
namespace {
constexpr std::string_view kPerfUsageLine =
    "usage: coquic-perf [server|client] [--host HOST] [--port PORT] "
    "[--io-backend socket|io_uring] [--mode bulk|rr|crr] "
    "[--direction upload|download] [--request-bytes N] [--response-bytes N] "
    "[--streams N] [--connections N] [--requests-in-flight N] [--requests N] "
    "[--total-bytes N] [--warmup 250ms|2s] [--duration 250ms|2s] "
    "[--certificate-chain PATH] [--private-key PATH] [--server-name NAME] "
    "[--verify-peer] [--json-out PATH]";

void print_usage() {
    std::cerr << kPerfUsageLine << '\n';
}

std::optional<std::size_t> parse_size_arg(std::string_view value) {
    std::size_t parsed = 0;
    const auto *begin = value.data();
    const auto *end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<std::chrono::milliseconds> parse_duration_arg(std::string_view value) {
    if (value.ends_with("ms")) {
        const auto count = parse_size_arg(value.substr(0, value.size() - 2));
        if (!count.has_value()) {
            return std::nullopt;
        }
        if (*count > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::nullopt;
        }
        return std::chrono::milliseconds{static_cast<std::int64_t>(*count)};
    }
    if (value.ends_with('s')) {
        const auto count = parse_size_arg(value.substr(0, value.size() - 1));
        if (!count.has_value()) {
            return std::nullopt;
        }
        if (*count > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max() / 1000)) {
            return std::nullopt;
        }
        return std::chrono::milliseconds{static_cast<std::int64_t>(*count * 1000)};
    }
    return std::nullopt;
}

std::optional<QuicPerfMode> parse_mode_arg(std::string_view value) {
    if (value == "bulk") {
        return QuicPerfMode::bulk;
    }
    if (value == "rr") {
        return QuicPerfMode::rr;
    }
    if (value == "crr") {
        return QuicPerfMode::crr;
    }
    return std::nullopt;
}

std::optional<QuicPerfDirection> parse_direction_arg(std::string_view value) {
    if (value == "upload") {
        return QuicPerfDirection::upload;
    }
    if (value == "download") {
        return QuicPerfDirection::download;
    }
    return std::nullopt;
}

} // namespace

std::optional<QuicPerfConfig> parse_perf_runtime_args(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return std::nullopt;
    }

    QuicPerfConfig config;
    bool saw_direction = false;

    const std::string_view role = argv[1];
    if (role == "server") {
        config.role = QuicPerfRole::server;
    } else if (role == "client") {
        config.role = QuicPerfRole::client;
    } else {
        print_usage();
        return std::nullopt;
    }

    int index = 2;
    while (index < argc) {
        const std::string_view arg = argv[index++];
        auto require_value = [&](std::string_view) -> std::optional<std::string_view> {
            if (index >= argc) {
                print_usage();
                return std::nullopt;
            }
            return std::string_view(argv[index++]);
        };

        if (arg == "--verify-peer") {
            config.verify_peer = true;
            continue;
        }
        if (arg == "--host") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.host = std::string(*value);
            continue;
        }
        if (arg == "--port") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value() || *parsed > 65535u) {
                print_usage();
                return std::nullopt;
            }
            config.port = static_cast<std::uint16_t>(*parsed);
            continue;
        }
        if (arg == "--io-backend") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            if (*value == "socket") {
                config.io_backend = io::QuicIoBackendKind::socket;
            } else if (*value == "io_uring") {
                config.io_backend = io::QuicIoBackendKind::io_uring;
            } else {
                print_usage();
                return std::nullopt;
            }
            continue;
        }
        if (arg == "--mode") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_mode_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.mode = *parsed;
            continue;
        }
        if (arg == "--direction") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_direction_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            saw_direction = true;
            config.direction = *parsed;
            continue;
        }
        if (arg == "--request-bytes") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.request_bytes = *parsed;
            continue;
        }
        if (arg == "--response-bytes") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.response_bytes = *parsed;
            continue;
        }
        if (arg == "--streams") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.streams = *parsed;
            continue;
        }
        if (arg == "--connections") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.connections = *parsed;
            continue;
        }
        if (arg == "--requests-in-flight") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.requests_in_flight = *parsed;
            continue;
        }
        if (arg == "--requests") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.requests = parsed;
            continue;
        }
        if (arg == "--total-bytes") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.total_bytes = parsed;
            continue;
        }
        if (arg == "--warmup") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_duration_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.warmup = *parsed;
            continue;
        }
        if (arg == "--duration") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_duration_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.duration = *parsed;
            continue;
        }
        if (arg == "--certificate-chain") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.certificate_chain_path = std::string(*value);
            continue;
        }
        if (arg == "--private-key") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.private_key_path = std::string(*value);
            continue;
        }
        if (arg == "--server-name") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.server_name = std::string(*value);
            continue;
        }
        if (arg == "--json-out") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.json_out = std::filesystem::path(std::string(*value));
            continue;
        }

        print_usage();
        return std::nullopt;
    }

    if (config.mode != QuicPerfMode::bulk && saw_direction) {
        print_usage();
        return std::nullopt;
    }
    if (config.streams == 0 || config.connections == 0 || config.requests_in_flight == 0) {
        print_usage();
        return std::nullopt;
    }
    return config;
}

int run_perf_runtime(const QuicPerfConfig &config) {
    if (config.role == QuicPerfRole::server) {
        return run_perf_server(config);
    }

    std::cerr << "coquic-perf client runtime not implemented yet\n";
    return 1;
}

quic::QuicCoreEndpointConfig make_perf_client_endpoint_config(const QuicPerfConfig &config) {
    return quic::QuicCoreEndpointConfig{
        .role = quic::EndpointRole::client,
        .verify_peer = config.verify_peer,
        .application_protocol = "coquic-perf/1",
    };
}

quic::QuicCoreEndpointConfig make_perf_server_endpoint_config(const QuicPerfConfig &config) {
    return quic::QuicCoreEndpointConfig{
        .role = quic::EndpointRole::server,
        .verify_peer = config.verify_peer,
        .application_protocol = "coquic-perf/1",
    };
}

} // namespace coquic::perf
