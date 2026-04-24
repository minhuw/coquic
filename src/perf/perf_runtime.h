#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

#include "src/io/io_backend.h"
#include "src/quic/core.h"

namespace coquic::perf {

enum class QuicPerfRole : std::uint8_t { server, client };
enum class QuicPerfMode : std::uint8_t { bulk, rr, crr };
enum class QuicPerfDirection : std::uint8_t { upload, download };

struct QuicPerfConfig {
    QuicPerfRole role = QuicPerfRole::server;
    io::QuicIoBackendKind io_backend = io::QuicIoBackendKind::socket;
    QuicPerfMode mode = QuicPerfMode::bulk;
    QuicPerfDirection direction = QuicPerfDirection::download;
    std::string host = "127.0.0.1";
    std::uint16_t port = 4433;
    std::string server_name = "localhost";
    bool verify_peer = false;
    std::filesystem::path certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    std::filesystem::path private_key_path = "tests/fixtures/quic-server-key.pem";
    std::optional<std::filesystem::path> json_out;
    std::size_t request_bytes = 64;
    std::size_t response_bytes = 64;
    std::size_t streams = 1;
    std::size_t connections = 1;
    std::size_t requests_in_flight = 1;
    std::optional<std::size_t> requests;
    std::optional<std::size_t> total_bytes;
    std::chrono::milliseconds warmup{0};
    std::chrono::milliseconds duration{5000};
    quic::QuicCongestionControlAlgorithm congestion_control =
        quic::QuicCongestionControlAlgorithm::newreno;
};

std::optional<QuicPerfConfig> parse_perf_runtime_args(int argc, char **argv);
int run_perf_runtime(const QuicPerfConfig &config);
quic::QuicCoreEndpointConfig make_perf_client_endpoint_config(const QuicPerfConfig &config);
quic::QuicCoreEndpointConfig make_perf_server_endpoint_config(const QuicPerfConfig &config);

} // namespace coquic::perf
