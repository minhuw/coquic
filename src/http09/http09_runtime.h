#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "src/io/io_backend.h"
#include "src/http09/http09_client.h"
#include "src/http09/http09_server.h"
#include "src/quic/core.h"

namespace coquic::http09 {

enum class Http09RuntimeMode : std::uint8_t { health_check, client, server };

enum class Http09ClientRunMode : std::uint8_t {
    single_connection,
    one_connection_per_request,
    resumption_sequence,
};

struct Http09RuntimeConfig {
    Http09RuntimeMode mode = Http09RuntimeMode::health_check;
    io::QuicIoBackendKind io_backend = io::QuicIoBackendKind::socket;
    std::string host = "127.0.0.1";
    std::uint16_t port = 443;
    bool retry_enabled = false;
    bool request_key_update = false;
    bool attempt_zero_rtt = false;
    bool enable_client_preferred_address_migration = false;
    bool enable_server_preferred_address = false;
    quic::QuicZeroRttConfig server_zero_rtt;
    Http09ClientRunMode client_run_mode = Http09ClientRunMode::single_connection;
    int client_receive_timeout_ms = 30000;
    std::uint32_t original_version = quic::kQuicVersion1;
    std::uint32_t initial_version = quic::kQuicVersion1;
    std::vector<std::uint32_t> supported_versions = {quic::kQuicVersion1};
    quic::QuicTransportConfig client_transport;
    quic::QuicTransportConfig server_transport;
    std::filesystem::path document_root = "/www";
    std::filesystem::path download_root = "/downloads";
    std::filesystem::path certificate_chain_path = "/certs/cert.pem";
    std::filesystem::path private_key_path = "/certs/priv.key";
    bool verify_peer = true;
    std::string application_protocol = "coquic";
    std::string server_name = "localhost";
    std::string requests_env;
    std::optional<std::filesystem::path> qlog_directory;
    std::optional<std::filesystem::path> tls_keylog_path;
    std::vector<quic::CipherSuite> allowed_tls_cipher_suites;
    quic::QuicCongestionControlAlgorithm congestion_control =
        quic::QuicCongestionControlAlgorithm::newreno;
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
std::optional<std::uint16_t> parse_port(std::string_view value);
std::optional<io::QuicIoBackendKind> parse_io_backend_kind(std::string_view value);
bool parse_role_into(Http09RuntimeConfig &config, std::string_view role);
std::optional<Http09ClientRemote>
derive_http09_client_remote(const Http09RuntimeConfig &config,
                            const std::vector<QuicHttp09Request> &requests);
quic::QuicCoreConfig make_http09_client_core_config(const Http09RuntimeConfig &config);
quic::QuicCoreConfig make_http09_server_core_config(const Http09RuntimeConfig &config);
int run_http09_runtime(const Http09RuntimeConfig &config);

} // namespace coquic::http09
