#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>

namespace coquic::http3 {

struct Http3BootstrapConfig {
    std::string host = "127.0.0.1";
    std::uint16_t port = 4433;
    std::uint16_t h3_port = 4433;
    std::uint64_t alt_svc_max_age = 60;
    std::filesystem::path document_root = ".";
    std::filesystem::path certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    std::filesystem::path private_key_path = "tests/fixtures/quic-server-key.pem";
};

std::string make_http3_alt_svc_value(const Http3BootstrapConfig &config);
int run_http3_bootstrap_server(const Http3BootstrapConfig &config,
                               const std::atomic<bool> *stop_requested = nullptr,
                               std::atomic<bool> *listener_ready = nullptr);

} // namespace coquic::http3
