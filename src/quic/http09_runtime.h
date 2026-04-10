#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "src/http09/http09_client.h"
#include "src/http09/http09_server.h"

namespace coquic::quic {

enum class Http09RuntimeMode : std::uint8_t { health_check, client, server };

struct Http09RuntimeConfig {
    Http09RuntimeMode mode = Http09RuntimeMode::health_check;
    std::string host = "127.0.0.1";
    std::uint16_t port = 443;
    http09::QuicHttp09Testcase testcase = http09::QuicHttp09Testcase::handshake;
    bool retry_enabled = false;
    std::filesystem::path document_root = "/www";
    std::filesystem::path download_root = "/downloads";
    std::filesystem::path certificate_chain_path = "/certs/cert.pem";
    std::filesystem::path private_key_path = "/certs/priv.key";
    bool verify_peer = false;
    std::string application_protocol = "hq-interop";
    std::string server_name = "localhost";
    std::string requests_env;
    std::optional<std::filesystem::path> qlog_directory;
    std::optional<std::filesystem::path> tls_keylog_path;
};

struct ParsedHttp09Authority {
    std::string host;
    std::optional<std::uint16_t> port;
};

struct Http09ClientRemote {
    std::string host;
    std::uint16_t port = 443;
    std::string server_name;
};

std::optional<ParsedHttp09Authority> parse_http09_authority(std::string_view authority);
std::optional<Http09ClientRemote>
derive_http09_client_remote(const Http09RuntimeConfig &config,
                            const std::vector<http09::QuicHttp09Request> &requests);
std::optional<Http09RuntimeConfig> parse_http09_runtime_args(int argc, char **argv);
QuicCoreConfig make_http09_client_core_config(const Http09RuntimeConfig &config);
QuicCoreConfig make_http09_server_core_config(const Http09RuntimeConfig &config);
int run_http09_runtime(const Http09RuntimeConfig &config);

} // namespace coquic::quic
