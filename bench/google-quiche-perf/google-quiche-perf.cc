#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "absl/log/initialize.h"
#include "absl/strings/str_cat.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/proof_source_x509.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/crypto/quic_client_session_cache.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_default_proof_providers.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quic_default_client.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_name_lookup.h"
#include "quiche/quic/tools/quic_server.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_reference_counted.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"

namespace {

using Clock = std::chrono::steady_clock;
using Duration = std::chrono::microseconds;

constexpr char kApplicationProtocol[] = "h3";
constexpr uint64_t kDefaultMaxRunRequests = 4096;
constexpr uint64_t kConnectionWindow = 32ULL * 1024ULL * 1024ULL;
constexpr uint64_t kStreamWindow = 16ULL * 1024ULL * 1024ULL;
constexpr uint32_t kMaxStreams = 1'000'000;

struct OptionalU64 {
    uint64_t value = 0;
    bool set = false;
};

struct Config {
    std::string role;
    std::string host = "127.0.0.1";
    uint16_t port = 4433;
    std::string server_name = "localhost";
    bool verify_peer = false;
    std::string io_backend = "socket";
    std::string congestion_control = "default";
    std::string certificate_chain = "tests/fixtures/quic-server-cert.pem";
    std::string private_key = "tests/fixtures/quic-server-key.pem";
    bool disable_pmtud = true;
    std::string mode = "bulk";
    std::string direction = "download";
    uint64_t request_bytes = 64;
    uint64_t response_bytes = 64;
    uint64_t streams = 1;
    uint64_t connections = 1;
    uint64_t requests_in_flight = 1;
    OptionalU64 requests;
    OptionalU64 total_bytes;
    Duration warmup = Duration::zero();
    Duration duration = std::chrono::seconds(5);
    std::string json_out;
};

struct Counters {
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t requests_completed = 0;
    uint64_t skipped_setup_errors = 0;
    std::vector<Duration> latencies;
};

struct LatencySummary {
    uint64_t min_us = 0;
    uint64_t avg_us = 0;
    uint64_t p50_us = 0;
    uint64_t p90_us = 0;
    uint64_t p99_us = 0;
    uint64_t max_us = 0;
};

struct RunSummary {
    std::string status = "ok";
    std::string failure_reason;
    const Config *cfg = nullptr;
    uint64_t elapsed_ms = 0;
    Counters counters;
    LatencySummary latency;
    double throughput_mib_per_s = 0.0;
    double throughput_gbit_per_s = 0.0;
    double requests_per_s = 0.0;
};

std::string TakeValue(const std::vector<std::string> &args, size_t *index, std::string_view arg) {
    ++*index;
    if (*index >= args.size()) {
        throw std::runtime_error(absl::StrCat("missing value for ", arg));
    }
    return args[(*index)++];
}

uint64_t ParseU64(std::string_view text, std::string_view name) {
    size_t parsed = 0;
    uint64_t value = 0;
    try {
        value = std::stoull(std::string(text), &parsed, 10);
    } catch (const std::exception &) {
        throw std::runtime_error(absl::StrCat("invalid ", name, ": ", text));
    }
    if (parsed != text.size()) {
        throw std::runtime_error(absl::StrCat("invalid ", name, ": ", text));
    }
    return value;
}

uint16_t ParsePort(std::string_view text) {
    uint64_t value = ParseU64(text, "port");
    if (value > 65535) {
        throw std::runtime_error(absl::StrCat("invalid port: ", text));
    }
    return static_cast<uint16_t>(value);
}

Duration ParseDuration(std::string_view text) {
    if (text.size() > 2 && text.substr(text.size() - 2) == "ms") {
        return std::chrono::milliseconds(ParseU64(text.substr(0, text.size() - 2), "duration"));
    }
    if (text.size() > 1 && text.back() == 's') {
        return std::chrono::seconds(ParseU64(text.substr(0, text.size() - 1), "duration"));
    }
    throw std::runtime_error(absl::StrCat("invalid duration: ", text));
}

void ValidateConfig(const Config &cfg) {
    if (cfg.mode != "bulk" && cfg.mode != "rr" && cfg.mode != "crr") {
        throw std::runtime_error(absl::StrCat("unsupported mode: ", cfg.mode));
    }
    if (cfg.io_backend != "socket") {
        throw std::runtime_error("google-quiche-perf only supports the socket backend");
    }
    if (cfg.congestion_control != "default") {
        if (cfg.congestion_control == "newreno" || cfg.congestion_control == "reno" ||
            cfg.congestion_control == "cubic" || cfg.congestion_control == "bbr" ||
            cfg.congestion_control == "copa") {
            throw std::runtime_error(
                "google-quiche-perf exposes only the upstream default congestion "
                "control");
        }
        throw std::runtime_error(
            absl::StrCat("unsupported congestion-control label: ", cfg.congestion_control));
    }
    if (cfg.direction != "upload" && cfg.direction != "download" && cfg.direction != "stay") {
        throw std::runtime_error(absl::StrCat("unsupported direction: ", cfg.direction));
    }
    if (cfg.streams == 0 || cfg.connections == 0 || cfg.requests_in_flight == 0) {
        throw std::runtime_error(
            "streams, connections, and requests-in-flight must be greater than "
            "zero");
    }
}

Config ParseArgs(int argc, char **argv) {
    std::vector<std::string> args(argv, argv + argc);
    if (args.size() < 2 || (args[1] != "client" && args[1] != "server")) {
        throw std::runtime_error("usage: google-quiche-perf [client|server] [options]");
    }

    Config cfg;
    cfg.role = args[1];
    size_t index = 2;
    while (index < args.size()) {
        const std::string arg = args[index];
        if (arg == "--verify-peer") {
            cfg.verify_peer = true;
            ++index;
        } else if (arg == "--disable-pmtud") {
            cfg.disable_pmtud = true;
            ++index;
        } else if (arg == "--host") {
            cfg.host = TakeValue(args, &index, arg);
        } else if (arg == "--port") {
            cfg.port = ParsePort(TakeValue(args, &index, arg));
        } else if (arg == "--server-name") {
            cfg.server_name = TakeValue(args, &index, arg);
        } else if (arg == "--io-backend") {
            cfg.io_backend = TakeValue(args, &index, arg);
        } else if (arg == "--congestion-control") {
            cfg.congestion_control = TakeValue(args, &index, arg);
        } else if (arg == "--certificate-chain") {
            cfg.certificate_chain = TakeValue(args, &index, arg);
        } else if (arg == "--private-key") {
            cfg.private_key = TakeValue(args, &index, arg);
        } else if (arg == "--mode") {
            cfg.mode = TakeValue(args, &index, arg);
        } else if (arg == "--direction") {
            cfg.direction = TakeValue(args, &index, arg);
        } else if (arg == "--request-bytes") {
            cfg.request_bytes = ParseU64(TakeValue(args, &index, arg), arg);
        } else if (arg == "--response-bytes") {
            cfg.response_bytes = ParseU64(TakeValue(args, &index, arg), arg);
        } else if (arg == "--streams") {
            cfg.streams = ParseU64(TakeValue(args, &index, arg), arg);
        } else if (arg == "--connections") {
            cfg.connections = ParseU64(TakeValue(args, &index, arg), arg);
        } else if (arg == "--requests-in-flight") {
            cfg.requests_in_flight = ParseU64(TakeValue(args, &index, arg), arg);
        } else if (arg == "--requests") {
            cfg.requests = {ParseU64(TakeValue(args, &index, arg), arg), true};
        } else if (arg == "--total-bytes") {
            cfg.total_bytes = {ParseU64(TakeValue(args, &index, arg), arg), true};
        } else if (arg == "--warmup") {
            cfg.warmup = ParseDuration(TakeValue(args, &index, arg));
        } else if (arg == "--duration") {
            cfg.duration = ParseDuration(TakeValue(args, &index, arg));
        } else if (arg == "--json-out") {
            cfg.json_out = TakeValue(args, &index, arg);
        } else {
            throw std::runtime_error(absl::StrCat("unknown argument: ", arg));
        }
    }

    ValidateConfig(cfg);
    return cfg;
}

uint64_t DurationMicros(Duration duration) {
    return static_cast<uint64_t>(std::max<int64_t>(0, duration.count()));
}

uint64_t DurationMillis(Duration duration) {
    return static_cast<uint64_t>(std::max<int64_t>(
        0, std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()));
}

uint64_t Percentile(const std::vector<uint64_t> &values, size_t pct) {
    if (values.empty()) {
        return 0;
    }
    size_t rank = (values.size() * pct + 99) / 100;
    if (rank == 0) {
        rank = 1;
    }
    return values[std::min(rank, values.size()) - 1];
}

LatencySummary SummarizeLatency(const std::vector<Duration> &samples) {
    if (samples.empty()) {
        return {};
    }
    std::vector<uint64_t> micros;
    micros.reserve(samples.size());
    uint64_t sum = 0;
    for (Duration sample : samples) {
        uint64_t value = DurationMicros(sample);
        micros.push_back(value);
        sum += value;
    }
    std::sort(micros.begin(), micros.end());
    LatencySummary summary;
    summary.min_us = micros.front();
    summary.avg_us = sum / micros.size();
    summary.p50_us = Percentile(micros, 50);
    summary.p90_us = Percentile(micros, 90);
    summary.p99_us = Percentile(micros, 99);
    summary.max_us = micros.back();
    return summary;
}

uint64_t CeilDiv(uint64_t numerator, uint64_t denominator) {
    if (denominator == 0) {
        return 0;
    }
    return (numerator + denominator - 1) / denominator;
}

quic::QuicConfig QuicConfigForPerf() {
    quic::QuicConfig config;
    config.SetInitialSessionFlowControlWindowToSend(kConnectionWindow);
    config.SetInitialStreamFlowControlWindowToSend(kStreamWindow);
    config.SetInitialMaxStreamDataBytesIncomingBidirectionalToSend(kStreamWindow);
    config.SetInitialMaxStreamDataBytesOutgoingBidirectionalToSend(kStreamWindow);
    config.SetInitialMaxStreamDataBytesUnidirectionalToSend(kStreamWindow);
    config.SetMaxBidirectionalStreamsToSend(kMaxStreams);
    config.SetMaxUnidirectionalStreamsToSend(0);
    config.SetIdleNetworkTimeout(quic::QuicTime::Delta::FromSeconds(30));
    config.SetDisableConnectionMigration();
    return config;
}

quic::ParsedQuicVersionVector SupportedVersions() {
    quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();
    for (const quic::ParsedQuicVersion &version : versions) {
        quic::QuicEnableVersion(version);
    }
    return versions;
}

std::unique_ptr<quic::ProofSource> LoadProofSource(const Config &cfg) {
    std::ifstream cert_stream(cfg.certificate_chain, std::ios::binary);
    std::vector<std::string> certs = quic::CertificateView::LoadPemFromStream(&cert_stream);
    if (certs.empty()) {
        throw std::runtime_error(
            absl::StrCat("failed to load certificate chain: ", cfg.certificate_chain));
    }

    std::ifstream key_stream(cfg.private_key, std::ios::binary);
    std::unique_ptr<quic::CertificatePrivateKey> key =
        quic::CertificatePrivateKey::LoadPemFromStream(&key_stream);
    if (key == nullptr) {
        throw std::runtime_error(absl::StrCat("failed to load private key: ", cfg.private_key));
    }

    quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain> chain(
        new quic::ProofSource::Chain({certs}));
    auto proof = quic::ProofSourceX509::Create(chain, std::move(*key));
    if (proof == nullptr) {
        throw std::runtime_error("failed to create Google QUICHE proof source");
    }
    return proof;
}

quic::QuicSocketAddress ResolveRemote(const Config &cfg) {
    quic::QuicSocketAddress addr =
        quic::tools::LookupAddress(AF_UNSPEC, cfg.host, absl::StrCat(cfg.port));
    if (!addr.IsInitialized()) {
        throw std::runtime_error(absl::StrCat("unable to resolve address: ", cfg.host));
    }
    return addr;
}

std::unique_ptr<quic::QuicDefaultClient>
ConnectClient(const Config &cfg, quic::QuicEventLoop *event_loop,
              std::unique_ptr<quic::SessionCache> session_cache = nullptr) {
    std::unique_ptr<quic::ProofVerifier> verifier =
        cfg.verify_peer ? quic::CreateDefaultProofVerifier(cfg.server_name)
                        : std::make_unique<quic::FakeProofVerifier>();
    if (verifier == nullptr) {
        throw std::runtime_error("google-quiche-perf could not create a peer certificate verifier");
    }
    auto client = std::make_unique<quic::QuicDefaultClient>(
        ResolveRemote(cfg), quic::QuicServerId(cfg.server_name, cfg.port), SupportedVersions(),
        QuicConfigForPerf(), event_loop, std::move(verifier), std::move(session_cache));
    client->set_drop_response_body(true);
    client->set_store_response(true);
    client->set_max_inbound_header_list_size(128 * 1024);
    client->set_initial_max_packet_length(quic::kDefaultMaxPacketSize);
    if (!client->Initialize()) {
        throw std::runtime_error("failed to initialize Google QUICHE client");
    }
    if (!client->Connect()) {
        std::ostringstream out;
        out << "failed to connect Google QUICHE client: "
            << quic::QuicErrorCodeToString(client->session()->error()) << " "
            << client->session()->error_details();
        throw std::runtime_error(out.str());
    }
    return client;
}

std::string RequestBody(uint64_t request_bytes) {
    if (request_bytes > 128ULL * 1024ULL * 1024ULL) {
        throw std::runtime_error("request body is too large for google-quiche-perf");
    }
    return std::string(static_cast<size_t>(request_bytes), 'x');
}

quiche::HttpHeaderBlock RequestHeaders(const Config &cfg, uint64_t response_bytes, bool has_body) {
    quiche::HttpHeaderBlock headers;
    headers[":method"] = has_body ? "POST" : "GET";
    headers[":scheme"] = "https";
    headers[":authority"] = absl::StrCat(cfg.server_name, ":", cfg.port);
    headers[":path"] = absl::StrCat("/", response_bytes);
    return headers;
}

void RunRequests(const Config &cfg, uint64_t count, uint64_t response_bytes, uint64_t request_bytes,
                 Counters *counters, bool counts_latency, bool one_connection_per_request,
                 quic::QuicEventLoop *event_loop) {
    count = std::max<uint64_t>(1, std::min<uint64_t>(count, kDefaultMaxRunRequests));
    auto client = ConnectClient(cfg, event_loop,
                                one_connection_per_request && count > 1
                                    ? std::make_unique<quic::QuicClientSessionCache>()
                                    : nullptr);
    std::string body = RequestBody(request_bytes);
    quiche::HttpHeaderBlock headers = RequestHeaders(cfg, response_bytes, !body.empty());
    uint64_t completed = 0;

    for (uint64_t i = 0; i < count; ++i) {
        Clock::time_point start = Clock::now();
        client->SendRequestAndWaitForResponse(headers, body, true);
        if (!client->connected()) {
            throw std::runtime_error(
                absl::StrCat("Google QUICHE request caused connection failure: ",
                             quic::QuicErrorCodeToString(client->session()->error())));
        }
        int code = client->latest_response_code();
        if (code < 200 || code >= 300) {
            throw std::runtime_error(
                absl::StrCat("Google QUICHE request failed with HTTP status ", code));
        }
        ++completed;
        counters->bytes_sent += request_bytes;
        counters->bytes_received += response_bytes;
        counters->requests_completed += 1;
        if (counts_latency) {
            counters->latencies.push_back(
                std::chrono::duration_cast<Duration>(Clock::now() - start));
        }

        if (i + 1 < count) {
            if (one_connection_per_request) {
                client->Disconnect();
                if (!client->Initialize()) {
                    throw std::runtime_error("failed to reinitialize Google QUICHE client");
                }
                if (!client->Connect()) {
                    std::ostringstream out;
                    out << "failed to reconnect Google QUICHE client: "
                        << quic::QuicErrorCodeToString(client->session()->error()) << " "
                        << client->session()->error_details();
                    throw std::runtime_error(out.str());
                }
            } else if (completed >= cfg.requests_in_flight) {
                // QUICHE's HTTP client waits synchronously, so requests-in-flight is a
                // batch-size signal for parity with the old wrapper.
            }
        }
    }
}

void RunBulk(const Config &cfg, Counters *counters, quic::QuicEventLoop *event_loop) {
    uint64_t request_bytes = cfg.request_bytes;
    uint64_t response_bytes = cfg.response_bytes;
    uint64_t unit = std::max<uint64_t>(1, response_bytes);
    if (cfg.direction == "upload") {
        request_bytes = std::max(cfg.request_bytes, cfg.response_bytes);
        response_bytes = 0;
        unit = std::max<uint64_t>(1, request_bytes);
    }

    if (cfg.total_bytes.set) {
        uint64_t count = std::max<uint64_t>(1, CeilDiv(cfg.total_bytes.value, unit));
        RunRequests(cfg, count, response_bytes, request_bytes, counters, false, false, event_loop);
        return;
    }

    Clock::time_point deadline = Clock::now() + cfg.duration;
    while (Clock::now() < deadline) {
        uint64_t count = std::max<uint64_t>(1, cfg.streams * cfg.connections);
        Clock::time_point before = Clock::now();
        RunRequests(cfg, count, response_bytes, request_bytes, counters, false, false, event_loop);
        if (Clock::now() - before > cfg.duration * 2) {
            break;
        }
    }
}

void RunRr(const Config &cfg, Counters *counters, quic::QuicEventLoop *event_loop) {
    if (cfg.requests.set) {
        RunRequests(cfg, cfg.requests.value, cfg.response_bytes, cfg.request_bytes, counters, true,
                    false, event_loop);
        return;
    }

    Clock::time_point deadline = Clock::now() + cfg.duration;
    while (Clock::now() < deadline) {
        uint64_t count = std::max<uint64_t>(
            1, std::min<uint64_t>(cfg.requests_in_flight, kDefaultMaxRunRequests));
        RunRequests(cfg, count, cfg.response_bytes, cfg.request_bytes, counters, true, false,
                    event_loop);
    }
}

void RunCrr(const Config &cfg, Counters *counters, quic::QuicEventLoop *event_loop) {
    if (cfg.requests.set) {
        uint64_t remaining = cfg.requests.value;
        while (remaining > 0) {
            uint64_t batch = std::min<uint64_t>(remaining, cfg.connections);
            RunRequests(cfg, batch, cfg.response_bytes, cfg.request_bytes, counters, true, true,
                        event_loop);
            remaining -= batch;
        }
        return;
    }

    Clock::time_point deadline = Clock::now() + cfg.duration;
    while (Clock::now() < deadline) {
        RunRequests(cfg, std::max<uint64_t>(1, cfg.connections), cfg.response_bytes,
                    cfg.request_bytes, counters, true, true, event_loop);
    }
}

RunSummary MakeSummary(const Config &cfg, Counters counters, Duration elapsed, std::string status,
                       std::string failure_reason) {
    RunSummary summary;
    summary.status = std::move(status);
    summary.failure_reason = std::move(failure_reason);
    summary.cfg = &cfg;
    summary.elapsed_ms = DurationMillis(elapsed);
    summary.latency = SummarizeLatency(counters.latencies);
    summary.counters = std::move(counters);

    double seconds = std::max<double>(summary.elapsed_ms / 1000.0, 0.001);
    uint64_t total_bytes = summary.counters.bytes_sent + summary.counters.bytes_received;
    summary.throughput_mib_per_s = static_cast<double>(total_bytes) / (1024.0 * 1024.0) / seconds;
    summary.throughput_gbit_per_s =
        static_cast<double>(total_bytes) * 8.0 / 1'000'000'000.0 / seconds;
    summary.requests_per_s = static_cast<double>(summary.counters.requests_completed) / seconds;
    return summary;
}

RunSummary RunClient(const Config &cfg) {
    quiche::QuicheSystemEventLoop system_loop("google-quiche-perf-client");
    auto event_loop = quic::GetDefaultEventLoop()->Create(quic::QuicDefaultClock::Get());
    Counters counters;
    Clock::time_point start = Clock::now();
    if (cfg.warmup != Duration::zero() && !cfg.requests.set && !cfg.total_bytes.set) {
        std::this_thread::sleep_for(cfg.warmup);
    }
    Clock::time_point measure_start = Clock::now();
    std::string failure;
    try {
        if (cfg.mode == "bulk") {
            RunBulk(cfg, &counters, event_loop.get());
        } else if (cfg.mode == "rr") {
            RunRr(cfg, &counters, event_loop.get());
        } else {
            RunCrr(cfg, &counters, event_loop.get());
        }
    } catch (const std::exception &ex) {
        failure = ex.what();
    }
    Duration elapsed = std::chrono::duration_cast<Duration>(
        Clock::now() - (cfg.requests.set ? start : measure_start));
    return MakeSummary(cfg, std::move(counters), elapsed, failure.empty() ? "ok" : "failed",
                       std::move(failure));
}

int RunServer(const Config &cfg) {
    quiche::QuicheSystemEventLoop system_loop("google-quiche-perf-server");
    auto backend = std::make_unique<quic::QuicMemoryCacheBackend>();
    backend->GenerateDynamicResponses();
    quic::QuicServer server(LoadProofSource(cfg), nullptr, QuicConfigForPerf(),
                            quic::QuicCryptoServerConfig::ConfigOptions(), SupportedVersions(),
                            backend.get(), quic::kQuicDefaultConnectionIdLength);
    quic::QuicIpAddress host;
    if (!host.FromString(cfg.host)) {
        host = quic::QuicIpAddress::Any6();
    }
    if (!server.CreateUDPSocketAndListen(quic::QuicSocketAddress(host, cfg.port))) {
        std::cerr << "failed to listen on " << cfg.host << ":" << cfg.port << std::endl;
        return 1;
    }
    for (;;) {
        server.WaitForEvents();
    }
}

std::string JsonString(std::string_view value) {
    std::string out = "\"";
    for (char ch : value) {
        switch (ch) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", ch);
                out += buf;
            } else {
                out += ch;
            }
            break;
        }
    }
    out += "\"";
    return out;
}

void WriteSummaryJson(std::ostream &out, const RunSummary &summary) {
    const Config &cfg = *summary.cfg;
    out << "{\n";
    out << "  \"schema_version\": 1,\n";
    out << "  \"status\": " << JsonString(summary.status) << ",\n";
    if (!summary.failure_reason.empty()) {
        out << "  \"failure_reason\": " << JsonString(summary.failure_reason) << ",\n";
    }
    out << "  \"mode\": " << JsonString(cfg.mode) << ",\n";
    out << "  \"direction\": " << JsonString(cfg.direction) << ",\n";
    out << "  \"backend\": " << JsonString(cfg.io_backend) << ",\n";
    out << "  \"congestion_control\": " << JsonString(cfg.congestion_control) << ",\n";
    out << "  \"remote_host\": " << JsonString(cfg.host) << ",\n";
    out << "  \"remote_port\": " << cfg.port << ",\n";
    out << "  \"alpn\": " << JsonString(kApplicationProtocol) << ",\n";
    out << "  \"elapsed_ms\": " << summary.elapsed_ms << ",\n";
    out << "  \"warmup_ms\": " << DurationMillis(cfg.warmup) << ",\n";
    out << "  \"bytes_sent\": " << summary.counters.bytes_sent << ",\n";
    out << "  \"bytes_received\": " << summary.counters.bytes_received << ",\n";
    out << "  \"server_counters\": {\n";
    out << "    \"bytes_sent\": " << summary.counters.bytes_received << ",\n";
    out << "    \"bytes_received\": " << summary.counters.bytes_sent << ",\n";
    out << "    \"requests_completed\": " << summary.counters.requests_completed << "\n";
    out << "  },\n";
    out << "  \"requests_completed\": " << summary.counters.requests_completed << ",\n";
    if (summary.counters.skipped_setup_errors != 0) {
        out << "  \"skipped_setup_errors\": " << summary.counters.skipped_setup_errors << ",\n";
    }
    out << "  \"streams\": " << cfg.streams << ",\n";
    out << "  \"connections\": " << cfg.connections << ",\n";
    out << "  \"requests_in_flight\": " << cfg.requests_in_flight << ",\n";
    out << "  \"request_bytes\": " << cfg.request_bytes << ",\n";
    out << "  \"response_bytes\": " << cfg.response_bytes << ",\n";
    out << "  \"throughput_mib_per_s\": " << summary.throughput_mib_per_s << ",\n";
    out << "  \"throughput_gbit_per_s\": " << summary.throughput_gbit_per_s << ",\n";
    out << "  \"requests_per_s\": " << summary.requests_per_s << ",\n";
    out << "  \"latency\": {\n";
    out << "    \"min_us\": " << summary.latency.min_us << ",\n";
    out << "    \"avg_us\": " << summary.latency.avg_us << ",\n";
    out << "    \"p50_us\": " << summary.latency.p50_us << ",\n";
    out << "    \"p90_us\": " << summary.latency.p90_us << ",\n";
    out << "    \"p99_us\": " << summary.latency.p99_us << ",\n";
    out << "    \"max_us\": " << summary.latency.max_us << "\n";
    out << "  }\n";
    out << "}\n";
}

int EmitSummary(const RunSummary &summary) {
    std::cout << "status=" << summary.status << " mode=" << summary.cfg->mode
              << " cc=" << summary.cfg->congestion_control
              << " direction=" << summary.cfg->direction
              << " throughput_mib/s=" << summary.throughput_mib_per_s
              << " throughput_gbit/s=" << summary.throughput_gbit_per_s
              << " requests/s=" << summary.requests_per_s << std::endl;
    if (!summary.cfg->json_out.empty()) {
        std::ofstream file(summary.cfg->json_out);
        if (!file) {
            std::cerr << "failed to open " << summary.cfg->json_out << std::endl;
            return 1;
        }
        WriteSummaryJson(file, summary);
    }
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    absl::InitializeLog();

    Config cfg;
    try {
        cfg = ParseArgs(argc, argv);
    } catch (const std::exception &ex) {
        std::cerr << ex.what() << std::endl;
        return 2;
    }

    if (cfg.role == "server") {
        try {
            return RunServer(cfg);
        } catch (const std::exception &ex) {
            std::cerr << ex.what() << std::endl;
            return 1;
        }
    }

    RunSummary summary = RunClient(cfg);
    int emit = EmitSummary(summary);
    if (emit != 0) {
        return emit;
    }
    return summary.status == "ok" ? 0 : 1;
}
