#include "interop/coquic-interop/http09_interop_profile.h"

#include <algorithm>
#include <cstdint>

namespace coquic::interop {
namespace {

using http09::Http09RuntimeConfig;
using quic::CipherSuite;
using quic::QuicTransportConfig;

constexpr std::uint64_t kHttp09InteropActiveConnectionIdLimit = 8;
// The official multiplexing testcase invokes endpoints with TESTCASE=transfer,
// generates thousands of requests, and rejects server transport parameters
// above 1000 streams. Use that ceiling so peers can open a large first wave of
// request streams while still satisfying the runner's transport-parameter check.
constexpr std::uint64_t kHttp09InteropServerInitialMaxStreamsBidi = 1000;
constexpr int kHttp09InteropClientReceiveTimeoutMs = 30000;
constexpr int kHttp09InteropMulticonnectClientReceiveTimeoutMs = 180000;
constexpr std::string_view kHttp09InteropApplicationProtocol = "hq-interop";

constexpr Http09InteropTestcase transfer_profile_testcase(Http09InteropTestcase testcase) {
    if (testcase == Http09InteropTestcase::keyupdate ||
        testcase == Http09InteropTestcase::rebind_port ||
        testcase == Http09InteropTestcase::rebind_addr || testcase == Http09InteropTestcase::ecn ||
        testcase == Http09InteropTestcase::connectionmigration) {
        return Http09InteropTestcase::transfer;
    }
    return testcase;
}

QuicTransportConfig http09_interop_base_transport() {
    auto config = QuicTransportConfig{};
    config.max_idle_timeout = 180000;
    config.active_connection_id_limit = kHttp09InteropActiveConnectionIdLimit;
    return config;
}

QuicTransportConfig http09_interop_client_transport_for_testcase(Http09InteropTestcase testcase) {
    testcase = transfer_profile_testcase(testcase);
    auto config = http09_interop_base_transport();
    if (testcase == Http09InteropTestcase::transfer) {
        config.initial_max_data = 32ull * 1024ull * 1024ull;
        config.initial_max_stream_data_bidi_local = 16ull * 1024ull * 1024ull;
    }
    if (testcase == Http09InteropTestcase::resumption ||
        testcase == Http09InteropTestcase::zerortt) {
        config.disable_active_migration = true;
    }
    return config;
}

QuicTransportConfig http09_interop_server_transport_for_testcase(Http09InteropTestcase testcase) {
    testcase = transfer_profile_testcase(testcase);
    auto config = http09_interop_base_transport();
    if (testcase == Http09InteropTestcase::transfer) {
        config.initial_max_streams_bidi = kHttp09InteropServerInitialMaxStreamsBidi;
    }
    if (testcase == Http09InteropTestcase::resumption ||
        testcase == Http09InteropTestcase::zerortt) {
        // Official resumed interop cases fan out enough request streams that the
        // default limit of 16 forces extra 1-RTT churn after warmup.
        config.initial_max_streams_bidi = 64;
    }
    return config;
}

std::vector<CipherSuite>
http09_interop_tls_cipher_suites_for_testcase(Http09InteropTestcase testcase) {
    testcase = transfer_profile_testcase(testcase);
    if (testcase == Http09InteropTestcase::chacha20) {
        return {
            CipherSuite::tls_chacha20_poly1305_sha256,
        };
    }
    return {};
}

bool request_targets_official_connectionmigration_server(std::string_view requests_env) {
    if (requests_env.empty()) {
        return false;
    }
    const auto requests = http09::parse_http09_requests_env(requests_env);
    if (!requests.has_value()) {
        return false;
    }
    return std::any_of(requests.value().begin(), requests.value().end(),
                       [](const http09::QuicHttp09Request &request) {
                           const auto authority = http09::parse_http09_authority(request.authority);
                           return authority.has_value() && authority->host == "server46";
                       });
}

} // namespace

std::optional<Http09InteropTestcase> parse_http09_interop_testcase(std::string_view value) {
    if (value == "handshake") {
        return Http09InteropTestcase::handshake;
    }
    if (value == "transfer" || value == "amplificationlimit") {
        return Http09InteropTestcase::transfer;
    }
    if (value == "keyupdate") {
        return Http09InteropTestcase::keyupdate;
    }
    if (value == "rebind-port") {
        return Http09InteropTestcase::rebind_port;
    }
    if (value == "rebind-addr") {
        return Http09InteropTestcase::rebind_addr;
    }
    if (value == "connectionmigration") {
        return Http09InteropTestcase::connectionmigration;
    }
    if (value == "ecn") {
        return Http09InteropTestcase::ecn;
    }
    if (value == "multiconnect") {
        return Http09InteropTestcase::multiconnect;
    }
    if (value == "chacha20") {
        return Http09InteropTestcase::chacha20;
    }
    if (value == "resumption") {
        return Http09InteropTestcase::resumption;
    }
    if (value == "zerortt") {
        return Http09InteropTestcase::zerortt;
    }
    if (value == "v2") {
        return Http09InteropTestcase::v2;
    }
    return std::nullopt;
}

void apply_http09_interop_profile(Http09RuntimeConfig &config, Http09InteropTestcase testcase) {
    config.application_protocol = std::string(kHttp09InteropApplicationProtocol);
    config.client_transport = http09_interop_client_transport_for_testcase(testcase);
    config.server_transport = http09_interop_server_transport_for_testcase(testcase);
    config.allowed_tls_cipher_suites = http09_interop_tls_cipher_suites_for_testcase(testcase);
    config.client_receive_timeout_ms = testcase == Http09InteropTestcase::multiconnect
                                           ? kHttp09InteropMulticonnectClientReceiveTimeoutMs
                                           : kHttp09InteropClientReceiveTimeoutMs;

    config.request_key_update = testcase == Http09InteropTestcase::keyupdate;
    config.enable_server_preferred_address = testcase == Http09InteropTestcase::connectionmigration;
    config.enable_client_preferred_address_migration =
        testcase == Http09InteropTestcase::connectionmigration ||
        request_targets_official_connectionmigration_server(config.requests_env);

    config.client_run_mode = http09::Http09ClientRunMode::single_connection;
    if (testcase == Http09InteropTestcase::multiconnect) {
        config.client_run_mode = http09::Http09ClientRunMode::one_connection_per_request;
    } else if (testcase == Http09InteropTestcase::resumption ||
               testcase == Http09InteropTestcase::zerortt) {
        config.client_run_mode = http09::Http09ClientRunMode::resumption_sequence;
    }

    config.attempt_zero_rtt = testcase == Http09InteropTestcase::zerortt;
    config.server_zero_rtt.allow =
        testcase == Http09InteropTestcase::resumption || testcase == Http09InteropTestcase::zerortt;

    config.original_version = quic::kQuicVersion1;
    config.initial_version = quic::kQuicVersion1;
    config.supported_versions = {quic::kQuicVersion1};
    if (testcase == Http09InteropTestcase::v2) {
        // The interop v2 testcase uses compatible version negotiation: start in
        // v1, advertise v2, then switch to v2 after the server selects it.
        config.supported_versions = {quic::kQuicVersion2, quic::kQuicVersion1};
    }
}

bool apply_http09_interop_testcase(Http09RuntimeConfig &config, std::string_view value) {
    if (value == "retry") {
        config.retry_enabled = true;
        apply_http09_interop_profile(config, Http09InteropTestcase::handshake);
        return true;
    }

    const auto parsed = parse_http09_interop_testcase(value);
    if (!parsed.has_value()) {
        return false;
    }

    apply_http09_interop_profile(config, *parsed);
    return true;
}

} // namespace coquic::interop
