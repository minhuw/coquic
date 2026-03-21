#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

#include "src/quic/http09_client.h"
#include "src/quic/http09_server.h"

namespace coquic::quic {

enum class Http09RuntimeMode : std::uint8_t { health_check, client, server };

struct Http09RuntimeConfig {
    Http09RuntimeMode mode = Http09RuntimeMode::health_check;
    std::string host = "127.0.0.1";
    std::uint16_t port = 443;
    QuicHttp09Testcase testcase = QuicHttp09Testcase::handshake;
    std::filesystem::path document_root = "/www";
    std::filesystem::path download_root = "/downloads";
    std::filesystem::path certificate_chain_path = "/certs/cert.pem";
    std::filesystem::path private_key_path = "/certs/priv.key";
    bool verify_peer = false;
    std::string application_protocol = "hq-interop";
    std::string server_name = "localhost";
    std::string requests_env;
};

std::optional<Http09RuntimeConfig> parse_http09_runtime_args(int argc, char **argv);
QuicCoreConfig make_http09_client_core_config(const Http09RuntimeConfig &config);
QuicCoreConfig make_http09_server_core_config(const Http09RuntimeConfig &config);
int run_http09_runtime(const Http09RuntimeConfig &config);

} // namespace coquic::quic
