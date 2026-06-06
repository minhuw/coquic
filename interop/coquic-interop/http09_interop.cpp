#include "interop/coquic-interop/http09_interop.h"

#include "src/http09/http09_runtime_internal.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace coquic::interop {
namespace {

constexpr std::string_view kUsageLine =
    "usage: coquic [interop-server|interop-client] [--host HOST] [--port PORT] "
    "[--io-backend socket|io_uring] [--congestion-control newreno|cubic|bbr|copa] "
    "[--testcase "
    "handshake|transfer|keyupdate|amplificationlimit|rebind-port|rebind-addr|"
    "connectionmigration|ecn|multiconnect|chacha20|retry|resumption|zerortt|v2] "
    "[--requests URLS] "
    "[--document-root PATH] "
    "[--download-root PATH] [--certificate-chain PATH] [--private-key PATH] "
    "[--server-name NAME] [--verify-peer] [--no-verify-peer] [--retry]";

std::optional<std::string> getenv_string(const char *name) {
    const char *value = std::getenv(name);
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string(value);
}

bool env_flag_enabled(const char *name) {
    const std::string value = getenv_string(name).value_or("");
    return !value.empty() && value != "0";
}

} // namespace

std::optional<http09::Http09RuntimeConfig> parse_http09_interop_args(int argc, char **argv) {
    // Merge interop-runner environment defaults with command-line overrides.
    http09::Http09RuntimeConfig config;
    config.verify_peer = false;
    bool host_specified = false;
    bool server_name_specified = false;

    // The official runner mostly configures endpoints through environment variables.
    if (const auto role = getenv_string("ROLE"); role.has_value()) {
        if (!http09::parse_role_into(config, *role)) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }
    }
    if (const auto testcase = getenv_string("TESTCASE"); testcase.has_value()) {
        if (!http09::apply_testcase_name(config, *testcase)) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }
    }
    if (const auto requests = getenv_string("REQUESTS"); requests.has_value()) {
        config.requests_env = *requests;
    }
    if (const auto host = getenv_string("HOST"); host.has_value()) {
        config.host = *host;
        host_specified = true;
    }
    if (const auto port = getenv_string("PORT"); port.has_value()) {
        const auto parsed = http09::parse_port(*port);
        if (!parsed.has_value()) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }
        config.port = *parsed;
    }
    if (const auto path = getenv_string("DOCUMENT_ROOT"); path.has_value()) {
        config.document_root = *path;
    }
    if (const auto path = getenv_string("DOWNLOAD_ROOT"); path.has_value()) {
        config.download_root = *path;
    }
    if (const auto path = getenv_string("CERTIFICATE_CHAIN_PATH"); path.has_value()) {
        config.certificate_chain_path = *path;
    }
    if (const auto path = getenv_string("PRIVATE_KEY_PATH"); path.has_value()) {
        config.private_key_path = *path;
    }
    if (const auto qlogdir = getenv_string("QLOGDIR"); qlogdir.has_value() && !qlogdir->empty()) {
        config.qlog_directory = std::filesystem::path(*qlogdir);
    }
    if (const auto sslkeylogfile = getenv_string("SSLKEYLOGFILE");
        sslkeylogfile.has_value() && !sslkeylogfile->empty()) {
        config.tls_keylog_path = std::filesystem::path(*sslkeylogfile);
    }
    if (const auto server_name = getenv_string("SERVER_NAME"); server_name.has_value()) {
        config.server_name = *server_name;
        server_name_specified = true;
    }
    if (const auto congestion_control = getenv_string("COQUIC_CONGESTION_CONTROL");
        congestion_control.has_value() && !congestion_control->empty()) {
        const auto parsed = quic::parse_congestion_control_algorithm(*congestion_control);
        if (!parsed.has_value()) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }
        config.congestion_control = *parsed;
    }
    if (env_flag_enabled("RETRY")) {
        config.retry_enabled = true;
    }

    // Positional subcommands and flags override environment-provided defaults.
    int index = 1;
    if (index < argc) {
        const std::string_view subcommand = argv[index];
        if (subcommand == "interop-server") {
            config.mode = http09::Http09RuntimeMode::server;
            ++index;
        } else if (subcommand == "interop-client") {
            config.mode = http09::Http09RuntimeMode::client;
            ++index;
        }
    }

    while (index < argc) {
        const std::string_view arg = argv[index++];
        auto require_value = [&](std::string_view) -> std::optional<std::string_view> {
            if (index >= argc) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            return std::string_view(argv[index++]);
        };

        if (arg == "--verify-peer") {
            config.verify_peer = true;
            continue;
        }
        if (arg == "--no-verify-peer") {
            config.verify_peer = false;
            continue;
        }
        if (arg == "--retry") {
            config.retry_enabled = true;
            continue;
        }

        const bool expects_value = arg == "--host" || arg == "--port" || arg == "--io-backend" ||
                                   arg == "--congestion-control" || arg == "--testcase" ||
                                   arg == "--requests" || arg == "--document-root" ||
                                   arg == "--download-root" || arg == "--certificate-chain" ||
                                   arg == "--private-key" || arg == "--server-name";
        if (!expects_value) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }

        const auto value = require_value(arg);
        if (!value.has_value()) {
            return std::nullopt;
        }
        if (arg == "--host") {
            config.host = std::string(*value);
            host_specified = true;
            continue;
        }
        if (arg == "--port") {
            const auto parsed = http09::parse_port(*value);
            if (!parsed.has_value()) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            config.port = *parsed;
            continue;
        }
        if (arg == "--io-backend") {
            const auto parsed = http09::parse_io_backend_kind(*value);
            if (!parsed.has_value()) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            config.io_backend = *parsed;
            continue;
        }
        if (arg == "--congestion-control") {
            const auto parsed = quic::parse_congestion_control_algorithm(*value);
            if (!parsed.has_value()) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            config.congestion_control = *parsed;
            continue;
        }
        if (arg == "--testcase") {
            if (!http09::apply_testcase_name(config, *value)) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            continue;
        }
        if (arg == "--requests") {
            config.requests_env = std::string(*value);
            continue;
        }
        if (arg == "--document-root") {
            config.document_root = std::string(*value);
            continue;
        }
        if (arg == "--download-root") {
            config.download_root = std::string(*value);
            continue;
        }
        if (arg == "--certificate-chain") {
            config.certificate_chain_path = std::string(*value);
            continue;
        }
        if (arg == "--private-key") {
            config.private_key_path = std::string(*value);
            continue;
        }

        config.server_name = std::string(*value);
        server_name_specified = true;
        continue;
    }

    // Interop clients derive peer authority from REQUESTS unless a caller explicitly overrides it.
    if (config.mode == http09::Http09RuntimeMode::client && config.requests_env.empty()) {
        std::cerr << kUsageLine << '\n';
        return std::nullopt;
    }
    if (config.mode == http09::Http09RuntimeMode::client && !host_specified) {
        config.host.clear();
    }
    if (config.mode == http09::Http09RuntimeMode::client && !server_name_specified) {
        config.server_name.clear();
    }

    return config;
}

} // namespace coquic::interop
