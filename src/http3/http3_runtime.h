#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "src/http3/http3.h"
#include "src/io/io_backend.h"

namespace coquic::http3 {

enum class Http3RuntimeMode : std::uint8_t { server, client };

struct Http3RuntimeHeader {
    std::string name;
    std::string value;
};

struct Http3RuntimeConfig {
    Http3RuntimeMode mode = Http3RuntimeMode::server;
    io::QuicIoBackendKind io_backend = io::QuicIoBackendKind::socket;
    std::string host = "127.0.0.1";
    std::uint16_t port = 4433;
    std::uint16_t bootstrap_port = 0;
    std::uint64_t alt_svc_max_age = 60;
    bool enable_bootstrap = true;
    std::filesystem::path document_root = ".";
    std::filesystem::path certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    std::filesystem::path private_key_path = "tests/fixtures/quic-server-key.pem";
    std::string url;
    std::string method;
    std::vector<Http3RuntimeHeader> headers;
    std::optional<std::string> body_text;
    std::optional<std::filesystem::path> body_file_path;
    std::optional<std::filesystem::path> output_path;
    std::string server_name;
    bool verify_peer = false;
};

struct Http3RuntimeTransferJob {
    std::string url;
    std::filesystem::path output_path;
};

std::optional<Http3RuntimeConfig> parse_http3_runtime_args(int argc, char **argv);
std::optional<Http3RuntimeConfig> parse_http3_server_args(int argc, char **argv);
std::optional<Http3RuntimeConfig> parse_http3_client_args(int argc, char **argv);
quic::QuicCoreEndpointConfig make_http3_client_endpoint_config(const Http3RuntimeConfig &config);
std::optional<quic::QuicCoreEndpointConfig>
make_http3_server_endpoint_config(const Http3RuntimeConfig &config);
int run_http3_server(const Http3RuntimeConfig &config);
int run_http3_client(const Http3RuntimeConfig &config);
int run_http3_client_transfers(const Http3RuntimeConfig &config,
                               std::span<const Http3RuntimeTransferJob> jobs);
int run_http3_runtime(const Http3RuntimeConfig &config);

} // namespace coquic::http3
