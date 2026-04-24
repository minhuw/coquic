#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "src/quic/core.h"

namespace coquic::http3 {

enum class Http3InteropMode : std::uint8_t { server, client };

struct Http3InteropConfig {
    Http3InteropMode mode = Http3InteropMode::server;
    std::string testcase;
    std::string host = "127.0.0.1";
    std::uint16_t port = 443;
    std::filesystem::path document_root;
    std::filesystem::path download_root;
    std::filesystem::path certificate_chain_path;
    std::filesystem::path private_key_path;
    std::string server_name;
    std::vector<std::string> requests;
    quic::QuicCongestionControlAlgorithm congestion_control =
        quic::QuicCongestionControlAlgorithm::newreno;
};

std::optional<Http3InteropConfig> parse_http3_interop_args(int argc, char **argv);
int run_http3_interop(const Http3InteropConfig &config);

} // namespace coquic::http3
