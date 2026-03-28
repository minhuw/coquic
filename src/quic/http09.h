#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "src/quic/core.h"
#include "src/quic/varint.h"

namespace coquic::quic {

enum class QuicHttp09Testcase : std::uint8_t {
    handshake,
    transfer,
    multiconnect,
    chacha20,
    v2,
};

struct QuicHttp09Request {
    std::string url;
    std::string authority;
    std::string request_target;
    std::filesystem::path relative_output_path;
};

struct QuicHttp09EndpointUpdate {
    std::vector<QuicCoreInput> core_inputs;
    bool has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
    bool handled_local_error = false;
};

CodecResult<std::vector<QuicHttp09Request>>
parse_http09_requests_env(std::string_view requests_env);

CodecResult<std::string> parse_http09_request_target(std::span<const std::byte> bytes);

CodecResult<std::filesystem::path> resolve_http09_path_under_root(const std::filesystem::path &root,
                                                                  std::string_view request_target);

QuicTransportConfig http09_client_transport_for_testcase(QuicHttp09Testcase testcase);
QuicTransportConfig http09_server_transport_for_testcase(QuicHttp09Testcase testcase);
std::vector<CipherSuite> http09_tls_cipher_suites_for_testcase(QuicHttp09Testcase testcase);

} // namespace coquic::quic
