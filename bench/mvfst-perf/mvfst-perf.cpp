#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <fizz/backend/openssl/OpenSSL.h>
#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/client/FizzClientContext.h>
#include <fizz/protocol/CertificateVerifier.h>
#include <fizz/server/CertManager.h>
#include <fizz/server/DefaultCertManager.h>
#include <fizz/server/FizzServerContext.h>
#include <folly/FileUtil.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/handshake/QuicFizzFactory.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicServerTransportFactory.h>

using Clock = std::chrono::steady_clock;
using Duration = std::chrono::nanoseconds;

namespace {

constexpr std::string_view kApplicationProtocol = "coquic-perf/1";
constexpr uint32_t kPerfProtocolVersion = 3;
constexpr quic::StreamId kControlStreamId = 0;
constexpr uint8_t kMessageSessionStart = 1;
constexpr uint8_t kMessageSessionReady = 2;
constexpr uint8_t kMessageSessionError = 3;
constexpr uint8_t kModeCodeBulk = 0;
constexpr uint8_t kModeCodeRr = 1;
constexpr uint8_t kModeCodeCrr = 2;
constexpr uint8_t kDirectionCodeUpload = 0;
constexpr uint8_t kDirectionCodeDownload = 1;
constexpr uint64_t kTransferConnectionWindow = 32ull * 1024ull * 1024ull;
constexpr uint64_t kTransferStreamWindow = 16ull * 1024ull * 1024ull;
constexpr size_t kWriteChunkSize = 32 * 1024;
constexpr uint32_t kServerHostId = 1;
constexpr auto kDrainTimeout = std::chrono::seconds(2);

constexpr std::string_view kModeBulk = "bulk";
constexpr std::string_view kModeRr = "rr";
constexpr std::string_view kModeCrr = "crr";
constexpr std::string_view kDirectionUpload = "upload";
constexpr std::string_view kDirectionDownload = "download";
constexpr std::string_view kDirectionStay = "stay";

struct OptionalU64 {
    uint64_t value{0};
    bool set{false};
};

struct Config {
    std::string host{"127.0.0.1"};
    uint16_t port{4433};
    std::string serverName{"localhost"};
    bool verifyPeer{false};
    std::string ioBackend{"socket"};
    std::string congestionControl{"default"};
    std::string certificateChain{"tests/fixtures/quic-server-cert.pem"};
    std::string privateKey{"tests/fixtures/quic-server-key.pem"};
    bool disablePmtud{true};
    std::string mode{"bulk"};
    std::string direction{"download"};
    uint64_t requestBytes{64};
    uint64_t responseBytes{64};
    uint64_t streams{1};
    uint64_t connections{1};
    uint64_t requestsInFlight{1};
    OptionalU64 requests;
    OptionalU64 totalBytes;
    Duration warmup{Duration::zero()};
    Duration duration{std::chrono::seconds(5)};
    std::optional<std::string> jsonOut;
};

struct Counters {
    uint64_t bytesSent{0};
    uint64_t bytesReceived{0};
    uint64_t requestsCompleted{0};
    uint64_t skippedSetupErrors{0};
    std::vector<Duration> latencies;
};

struct LatencySummary {
    uint64_t minUs{0};
    uint64_t avgUs{0};
    uint64_t p50Us{0};
    uint64_t p90Us{0};
    uint64_t p99Us{0};
    uint64_t maxUs{0};
};

struct RunSummary {
    std::string status{"ok"};
    std::string mode;
    std::string direction;
    std::string backend{"mvfst"};
    std::string congestionControl;
    std::string remoteHost;
    uint16_t remotePort{0};
    int64_t elapsedMs{0};
    int64_t warmupMs{0};
    uint64_t bytesSent{0};
    uint64_t bytesReceived{0};
    uint64_t serverBytesSent{0};
    uint64_t serverBytesReceived{0};
    uint64_t serverRequestsCompleted{0};
    uint64_t requestsCompleted{0};
    uint64_t streams{0};
    uint64_t connections{0};
    uint64_t requestsInFlight{0};
    uint64_t requestBytes{0};
    uint64_t responseBytes{0};
    double throughputMibPerS{0};
    double throughputGbitPerS{0};
    double requestsPerS{0};
    LatencySummary latency;
    std::string failureReason;
    uint64_t skippedSetupErrors{0};
};

struct CompletedStream {
    bool counts{false};
    uint64_t requestBytes{0};
    uint64_t received{0};
    Duration latency{Duration::zero()};
};

struct PerfSessionStart {
    bool started{false};
    uint8_t mode{kModeCodeBulk};
    uint8_t direction{kDirectionCodeDownload};
    uint64_t requestBytes{0};
    uint64_t responseBytes{0};
    OptionalU64 totalBytes;
    OptionalU64 requests;
    uint64_t warmupUs{0};
    uint64_t durationUs{0};
    uint64_t streams{1};
    uint64_t connections{1};
    uint64_t requestsInFlight{1};
};

size_t intCap(uint64_t value) {
    return static_cast<size_t>(std::min<uint64_t>(value, std::numeric_limits<size_t>::max()));
}

int64_t durationMillis(Duration duration) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

uint64_t durationMicros(Duration duration) {
    return std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
}

Duration parseDuration(const std::string &value) {
    if (value.ends_with("ms")) {
        return std::chrono::milliseconds(std::stoull(value.substr(0, value.size() - 2)));
    }
    if (value.ends_with("s")) {
        return std::chrono::seconds(std::stoull(value.substr(0, value.size() - 1)));
    }
    throw std::runtime_error("invalid duration: " + value);
}

std::string takeValue(const std::vector<std::string> &args, size_t &index, const std::string &arg) {
    if (index >= args.size()) {
        throw std::runtime_error("missing value for " + arg);
    }
    return args[index++];
}

Config parseArgs(const std::vector<std::string> &args) {
    Config cfg;
    for (size_t index = 0; index < args.size();) {
        std::string arg = args[index++];
        if (arg == "--verify-peer") {
            cfg.verifyPeer = true;
        } else if (arg == "--disable-pmtud") {
            cfg.disablePmtud = true;
        } else if (arg == "--host") {
            cfg.host = takeValue(args, index, arg);
        } else if (arg == "--port") {
            cfg.port = static_cast<uint16_t>(std::stoul(takeValue(args, index, arg)));
        } else if (arg == "--server-name") {
            cfg.serverName = takeValue(args, index, arg);
        } else if (arg == "--io-backend") {
            cfg.ioBackend = takeValue(args, index, arg);
        } else if (arg == "--congestion-control") {
            cfg.congestionControl = takeValue(args, index, arg);
        } else if (arg == "--certificate-chain") {
            cfg.certificateChain = takeValue(args, index, arg);
        } else if (arg == "--private-key") {
            cfg.privateKey = takeValue(args, index, arg);
        } else if (arg == "--mode") {
            cfg.mode = takeValue(args, index, arg);
        } else if (arg == "--direction") {
            cfg.direction = takeValue(args, index, arg);
        } else if (arg == "--request-bytes") {
            cfg.requestBytes = std::stoull(takeValue(args, index, arg));
        } else if (arg == "--response-bytes") {
            cfg.responseBytes = std::stoull(takeValue(args, index, arg));
        } else if (arg == "--streams") {
            cfg.streams = std::stoull(takeValue(args, index, arg));
        } else if (arg == "--connections") {
            cfg.connections = std::stoull(takeValue(args, index, arg));
        } else if (arg == "--requests-in-flight") {
            cfg.requestsInFlight = std::stoull(takeValue(args, index, arg));
        } else if (arg == "--requests") {
            cfg.requests = {std::stoull(takeValue(args, index, arg)), true};
        } else if (arg == "--total-bytes") {
            cfg.totalBytes = {std::stoull(takeValue(args, index, arg)), true};
        } else if (arg == "--warmup") {
            cfg.warmup = parseDuration(takeValue(args, index, arg));
        } else if (arg == "--duration") {
            cfg.duration = parseDuration(takeValue(args, index, arg));
        } else if (arg == "--json-out") {
            cfg.jsonOut = takeValue(args, index, arg);
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }

    if (cfg.mode != kModeBulk && cfg.mode != kModeRr && cfg.mode != kModeCrr) {
        throw std::runtime_error("unsupported mode: " + cfg.mode);
    }
    if (cfg.ioBackend != "socket" && cfg.ioBackend != "io_uring") {
        throw std::runtime_error("unsupported io-backend label: " + cfg.ioBackend);
    }
    if (cfg.ioBackend != "socket") {
        throw std::runtime_error("mvfst-perf only supports the socket backend");
    }
    if (cfg.congestionControl != "default" && cfg.congestionControl != "cubic" &&
        cfg.congestionControl != "bbr" && cfg.congestionControl != "newreno" &&
        cfg.congestionControl != "copa") {
        throw std::runtime_error("unsupported congestion-control label: " + cfg.congestionControl);
    }
    if (cfg.direction != kDirectionUpload && cfg.direction != kDirectionDownload &&
        cfg.direction != kDirectionStay) {
        throw std::runtime_error("unsupported direction: " + cfg.direction);
    }
    if (cfg.streams == 0 || cfg.connections == 0 || cfg.requestsInFlight == 0) {
        throw std::runtime_error(
            "streams, connections, and requests-in-flight must be greater than zero");
    }
    return cfg;
}

using MvfstTransportSettings = quic::TransportSettings;

MvfstTransportSettings transportSettings(const Config &cfg) {
    MvfstTransportSettings settings;
    settings.advertisedInitialConnectionFlowControlWindow = kTransferConnectionWindow;
    settings.advertisedInitialBidiLocalStreamFlowControlWindow = kTransferStreamWindow;
    settings.advertisedInitialBidiRemoteStreamFlowControlWindow = kTransferStreamWindow;
    settings.advertisedInitialUniStreamFlowControlWindow = kTransferStreamWindow;
    settings.advertisedInitialMaxStreamsBidi = 4096;
    settings.advertisedInitialMaxStreamsUni = 0;
    settings.idleTimeout = std::chrono::milliseconds(30000);
    settings.disableMigration = true;
    if (auto cc = quic::congestionControlStrToType(cfg.congestionControl);
        cc.has_value() && cfg.congestionControl != "default") {
        settings.defaultCongestionController = *cc;
    }
    return settings;
}

std::shared_ptr<fizz::server::FizzServerContext> makeServerCtx(const Config &cfg) {
    std::string certData;
    std::string keyData;
    if (!folly::readFile(cfg.certificateChain.c_str(), certData)) {
        throw std::runtime_error("failed to read certificate chain");
    }
    if (!folly::readFile(cfg.privateKey.c_str(), keyData)) {
        throw std::runtime_error("failed to read private key");
    }
    std::unique_ptr<fizz::SelfCert> cert;
    fizz::Error certError;
    if (fizz::openssl::CertUtils::makeSelfCert(cert, certError, certData, keyData) !=
        fizz::Status::Success) {
        throw std::runtime_error("failed to parse certificate chain/private key");
    }
    auto certManager = std::make_shared<fizz::server::DefaultCertManager>();
    certManager->addCertAndSetDefault(std::move(cert));
    auto server_ctx = std::make_shared<fizz::server::FizzServerContext>();
    server_ctx->setFactory(std::make_shared<quic::QuicFizzFactory>());
    server_ctx->setCertManager(std::move(certManager));
    server_ctx->setOmitEarlyRecordLayer(true);
    server_ctx->setClock(std::make_shared<fizz::SystemClock>());
    server_ctx->setSupportedAlpns({std::string(kApplicationProtocol)});
    return server_ctx;
}

std::shared_ptr<quic::ClientHandshakeFactory> makeClientHandshakeCtx() {
    auto clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    clientCtx->setFactory(std::make_shared<quic::QuicFizzFactory>());
    clientCtx->setOmitEarlyRecordLayer(true);
    clientCtx->setClock(std::make_shared<fizz::SystemClock>());
    clientCtx->setSupportedAlpns({std::string(kApplicationProtocol)});
    return quic::FizzClientQuicHandshakeContext::Builder()
        .setCertificateVerifier(
            std::make_shared<fizz::InsecureCertificateVerifier>(fizz::VerificationContext::Client))
        .setFizzClientContext(std::move(clientCtx))
        .build();
}

std::string escapeJson(const std::string &value) {
    std::ostringstream out;
    for (char c : value) {
        switch (c) {
        case '\\':
            out << "\\\\";
            break;
        case '"':
            out << "\\\"";
            break;
        case '\n':
            out << "\\n";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\t':
            out << "\\t";
            break;
        default:
            out << c;
            break;
        }
    }
    return out.str();
}

std::string resolveHostForSocketAddress(const std::string &host, uint16_t port) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo *raw = nullptr;
    int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &raw);
    if (rc != 0) {
        throw std::runtime_error("mvfst resolve host failed for " + host + ": " + gai_strerror(rc));
    }
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> results(raw, freeaddrinfo);
    char out[INET6_ADDRSTRLEN] = {};
    for (addrinfo *ai = results.get(); ai != nullptr; ai = ai->ai_next) {
        const void *addr = nullptr;
        if (ai->ai_family == AF_INET) {
            addr = &reinterpret_cast<sockaddr_in *>(ai->ai_addr)->sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            addr = &reinterpret_cast<sockaddr_in6 *>(ai->ai_addr)->sin6_addr;
        }
        if (addr != nullptr && inet_ntop(ai->ai_family, addr, out, sizeof(out)) != nullptr) {
            return out;
        }
    }
    throw std::runtime_error("mvfst resolve host returned no usable address for " + host);
}

RunSummary newRunSummary(const Config &cfg) {
    RunSummary summary;
    summary.mode = cfg.mode;
    summary.direction = cfg.direction;
    summary.congestionControl = cfg.congestionControl;
    summary.remoteHost = cfg.host;
    summary.remotePort = cfg.port;
    summary.warmupMs = durationMillis(cfg.warmup);
    summary.streams = cfg.streams;
    summary.connections = cfg.connections;
    summary.requestsInFlight = cfg.requestsInFlight;
    summary.requestBytes = cfg.requestBytes;
    summary.responseBytes = cfg.responseBytes;
    return summary;
}

uint64_t percentile(const std::vector<uint64_t> &sorted, double pct) {
    size_t rank = static_cast<size_t>(std::ceil((pct / 100.0) * sorted.size()));
    return sorted[std::min(rank == 0 ? 0 : rank - 1, sorted.size() - 1)];
}

LatencySummary summarizeLatency(const std::vector<Duration> &samples) {
    LatencySummary out;
    if (samples.empty()) {
        return out;
    }
    std::vector<uint64_t> micros;
    micros.reserve(samples.size());
    uint64_t total = 0;
    for (auto sample : samples) {
        uint64_t us = durationMicros(sample);
        total += us;
        micros.push_back(us);
    }
    std::sort(micros.begin(), micros.end());
    out.minUs = micros.front();
    out.avgUs = total / micros.size();
    out.p50Us = percentile(micros, 50.0);
    out.p90Us = percentile(micros, 90.0);
    out.p99Us = percentile(micros, 99.0);
    out.maxUs = micros.back();
    return out;
}

void finalizeSummary(RunSummary &summary) {
    if (summary.elapsedMs == 0) {
        summary.elapsedMs = summary.warmupMs;
    }
    double seconds = std::max(summary.elapsedMs / 1000.0, 0.001);
    uint64_t totalBytes = summary.bytesSent + summary.bytesReceived;
    summary.throughputMibPerS = static_cast<double>(totalBytes) / (1024.0 * 1024.0) / seconds;
    summary.throughputGbitPerS = static_cast<double>(totalBytes) * 8.0 / 1000000000.0 / seconds;
    summary.requestsPerS = static_cast<double>(summary.requestsCompleted) / seconds;
}

void emitSummary(const RunSummary &summary, const std::optional<std::string> &jsonOut) {
    std::cout << "status=" << summary.status << " mode=" << summary.mode
              << " cc=" << summary.congestionControl << " direction=" << summary.direction
              << " throughput_mib/s=" << std::fixed << std::setprecision(3)
              << summary.throughputMibPerS << " throughput_gbit/s=" << summary.throughputGbitPerS
              << " requests/s=" << summary.requestsPerS << "\n";
    if (!jsonOut.has_value()) {
        return;
    }
    std::ofstream out(*jsonOut);
    out << std::fixed << std::setprecision(3);
    out << "{\n";
    out << "  \"schema_version\": 1,\n";
    out << "  \"status\": \"" << escapeJson(summary.status) << "\",\n";
    out << "  \"mode\": \"" << escapeJson(summary.mode) << "\",\n";
    out << "  \"direction\": \"" << escapeJson(summary.direction) << "\",\n";
    out << "  \"backend\": \"" << escapeJson(summary.backend) << "\",\n";
    out << "  \"congestion_control\": \"" << escapeJson(summary.congestionControl) << "\",\n";
    out << "  \"remote_host\": \"" << escapeJson(summary.remoteHost) << "\",\n";
    out << "  \"remote_port\": " << summary.remotePort << ",\n";
    out << "  \"alpn\": \"" << escapeJson(std::string(kApplicationProtocol)) << "\",\n";
    out << "  \"elapsed_ms\": " << summary.elapsedMs << ",\n";
    out << "  \"warmup_ms\": " << summary.warmupMs << ",\n";
    out << "  \"bytes_sent\": " << summary.bytesSent << ",\n";
    out << "  \"bytes_received\": " << summary.bytesReceived << ",\n";
    out << "  \"server_counters\": {\n";
    out << "    \"bytes_sent\": " << summary.serverBytesSent << ",\n";
    out << "    \"bytes_received\": " << summary.serverBytesReceived << ",\n";
    out << "    \"requests_completed\": " << summary.serverRequestsCompleted << "\n";
    out << "  },\n";
    out << "  \"requests_completed\": " << summary.requestsCompleted << ",\n";
    out << "  \"streams\": " << summary.streams << ",\n";
    out << "  \"connections\": " << summary.connections << ",\n";
    out << "  \"requests_in_flight\": " << summary.requestsInFlight << ",\n";
    out << "  \"request_bytes\": " << summary.requestBytes << ",\n";
    out << "  \"response_bytes\": " << summary.responseBytes << ",\n";
    out << "  \"throughput_mib_per_s\": " << summary.throughputMibPerS << ",\n";
    out << "  \"throughput_gbit_per_s\": " << summary.throughputGbitPerS << ",\n";
    out << "  \"requests_per_s\": " << summary.requestsPerS << ",\n";
    out << "  \"latency\": {\n";
    out << "    \"min_us\": " << summary.latency.minUs << ",\n";
    out << "    \"avg_us\": " << summary.latency.avgUs << ",\n";
    out << "    \"p50_us\": " << summary.latency.p50Us << ",\n";
    out << "    \"p90_us\": " << summary.latency.p90Us << ",\n";
    out << "    \"p99_us\": " << summary.latency.p99Us << ",\n";
    out << "    \"max_us\": " << summary.latency.maxUs << "\n";
    out << "  }";
    if (!summary.failureReason.empty()) {
        out << ",\n  \"failure_reason\": \"" << escapeJson(summary.failureReason) << "\"";
    }
    if (summary.skippedSetupErrors != 0) {
        out << ",\n  \"skipped_setup_errors\": " << summary.skippedSetupErrors;
    }
    out << "\n}\n";
}

uint8_t modeCode(const std::string &mode) {
    if (mode == kModeRr) {
        return kModeCodeRr;
    }
    if (mode == kModeCrr) {
        return kModeCodeCrr;
    }
    return kModeCodeBulk;
}

uint8_t directionCode(const std::string &direction) {
    return direction == kDirectionUpload ? kDirectionCodeUpload : kDirectionCodeDownload;
}

uint64_t scenarioRequestBytes(const Config &cfg) {
    if (cfg.mode == kModeBulk && cfg.direction == kDirectionUpload) {
        return std::max(cfg.requestBytes, cfg.responseBytes);
    }
    return cfg.requestBytes;
}

uint64_t scenarioResponseBytes(const Config &cfg) {
    if (cfg.mode == kModeBulk && cfg.direction == kDirectionUpload) {
        return 0;
    }
    return cfg.responseBytes;
}

void appendU32(std::vector<uint8_t> &out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xffu));
    out.push_back(static_cast<uint8_t>(value & 0xffu));
}

void appendU64(std::vector<uint8_t> &out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xffu));
    }
}

uint32_t readU32(const uint8_t *bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) | static_cast<uint32_t>(bytes[3]);
}

uint64_t readU64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

std::vector<uint8_t> frameControlMessage(uint8_t type, const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> out;
    out.reserve(payload.size() + 5);
    out.push_back(type);
    appendU32(out, static_cast<uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

uint64_t rrConnectionTarget(const Config &cfg) {
    if (cfg.mode == kModeRr && cfg.requests.set) {
        return std::min(cfg.connections, cfg.requests.value);
    }
    return cfg.connections;
}

uint64_t rrRequestLimitForConnection(const Config &cfg, uint64_t connectionIndex) {
    uint64_t connections = rrConnectionTarget(cfg);
    if (connections == 0) {
        return 0;
    }
    uint64_t base = cfg.requests.value / connections;
    uint64_t remainder = cfg.requests.value % connections;
    return base + static_cast<uint64_t>(connectionIndex < remainder);
}

bool canStartRrRequest(const Config &cfg, uint64_t started,
                       const std::vector<uint64_t> &startedByConnection, size_t connectionIndex) {
    if (!cfg.requests.set) {
        return true;
    }
    return started < cfg.requests.value &&
           startedByConnection[connectionIndex] <
               rrRequestLimitForConnection(cfg, static_cast<uint64_t>(connectionIndex));
}

Config configWithRrRequestLimit(const Config &cfg, uint64_t connectionIndex) {
    Config connectionCfg = cfg;
    if (cfg.mode == kModeRr && cfg.requests.set) {
        connectionCfg.requests.value = rrRequestLimitForConnection(cfg, connectionIndex);
        connectionCfg.requests.set = true;
    }
    return connectionCfg;
}

std::vector<uint8_t> encodeSessionStart(const Config &cfg) {
    std::vector<uint8_t> payload;
    payload.reserve(79);
    appendU32(payload, kPerfProtocolVersion);
    payload.push_back(modeCode(cfg.mode));
    payload.push_back(directionCode(cfg.direction));
    appendU64(payload, scenarioRequestBytes(cfg));
    appendU64(payload, scenarioResponseBytes(cfg));
    payload.push_back(
        static_cast<uint8_t>((cfg.totalBytes.set ? 0x01 : 0) | (cfg.requests.set ? 0x02 : 0)));
    appendU64(payload, cfg.totalBytes.value);
    appendU64(payload, cfg.requests.value);
    appendU64(payload, durationMicros(cfg.warmup));
    appendU64(payload, durationMicros(cfg.duration));
    appendU64(payload, cfg.streams);
    appendU64(payload, cfg.connections);
    appendU64(payload, cfg.requestsInFlight);
    return frameControlMessage(kMessageSessionStart, payload);
}

std::vector<uint8_t> encodeSessionReady() {
    std::vector<uint8_t> payload;
    appendU32(payload, kPerfProtocolVersion);
    return frameControlMessage(kMessageSessionReady, payload);
}

std::vector<uint8_t> encodeSessionError(const std::string &reason) {
    std::vector<uint8_t> payload;
    appendU32(payload, static_cast<uint32_t>(reason.size()));
    payload.insert(payload.end(), reason.begin(), reason.end());
    return frameControlMessage(kMessageSessionError, payload);
}

std::vector<uint8_t> decodeControlFrame(const std::vector<uint8_t> &input, uint8_t &type) {
    if (input.size() < 5) {
        throw std::runtime_error("short control frame");
    }
    uint32_t len = readU32(input.data() + 1);
    if (input.size() < static_cast<size_t>(len) + 5) {
        throw std::runtime_error("incomplete control frame");
    }
    type = input[0];
    return std::vector<uint8_t>(input.begin() + 5,
                                input.begin() + static_cast<std::ptrdiff_t>(len) + 5);
}

PerfSessionStart decodeSessionStart(const std::vector<uint8_t> &payload) {
    if (payload.size() != 79 || readU32(payload.data()) != kPerfProtocolVersion) {
        throw std::runtime_error("malformed session_start");
    }
    PerfSessionStart start;
    start.started = true;
    start.mode = payload[4];
    start.direction = payload[5];
    start.requestBytes = readU64(payload.data() + 6);
    start.responseBytes = readU64(payload.data() + 14);
    uint8_t flags = payload[22];
    start.totalBytes = {readU64(payload.data() + 23), (flags & 0x01) != 0};
    start.requests = {readU64(payload.data() + 31), (flags & 0x02) != 0};
    start.warmupUs = readU64(payload.data() + 39);
    start.durationUs = readU64(payload.data() + 47);
    start.streams = readU64(payload.data() + 55);
    start.connections = readU64(payload.data() + 63);
    start.requestsInFlight = readU64(payload.data() + 71);
    if ((start.mode != kModeCodeBulk && start.mode != kModeCodeRr && start.mode != kModeCodeCrr) ||
        (start.direction != kDirectionCodeUpload && start.direction != kDirectionCodeDownload) ||
        start.streams == 0 || start.connections == 0 || start.requestsInFlight == 0) {
        throw std::runtime_error("malformed session_start");
    }
    return start;
}

struct ServerStreamState {
    bool isControl{false};
    std::vector<uint8_t> controlIn;
    std::vector<uint8_t> controlOut;
    size_t controlSent{0};
    bool controlFin{false};
    uint64_t requestBytes{0};
    uint64_t responseBytes{0};
    uint64_t requestReceived{0};
    uint64_t responseSent{0};
    bool requestFin{false};
    bool responseFin{false};
};

class PerfServerHandler : public quic::QuicSocket::ConnectionSetupCallback,
                          public quic::QuicSocket::ConnectionCallback,
                          public quic::QuicSocket::ReadCallback,
                          public quic::QuicSocket::WriteCallback {
  public:
    explicit PerfServerHandler(folly::EventBase *evb) : evb_(evb) {
    }

    void setQuicSocket(std::shared_ptr<quic::QuicSocket> sock) {
        sock_ = std::move(sock);
    }

    folly::EventBase *getEventBase() {
        return evb_;
    }

    void onNewBidirectionalStream(quic::StreamId id) noexcept override {
        auto &state = streams_[id];
        state.isControl = id == kControlStreamId;
        if (!state.isControl && !session_.started) {
            if (sock_) {
                sock_->close(quic::QuicError(quic::ApplicationErrorCode(1),
                                             "data stream before session_start"));
            }
            return;
        }
        if (!state.isControl) {
            state.requestBytes = session_.requestBytes;
        }
        auto res = sock_->setReadCallback(id, this);
        if (res.hasError()) {
            std::cerr << "mvfst server setReadCallback failed\n";
        }
    }

    void onNewUnidirectionalStream(quic::StreamId) noexcept override {
    }
    void onStopSending(quic::StreamId, quic::ApplicationErrorCode) noexcept override {
    }
    void onConnectionEnd() noexcept override {
    }
    void onConnectionSetupError(quic::QuicError error) noexcept override {
        onConnectionError(std::move(error));
    }
    void onConnectionError(quic::QuicError error) noexcept override {
        std::cerr << "mvfst server connection error: " << error.message << "\n";
    }

    void readAvailable(quic::StreamId id) noexcept override {
        try {
            auto readData = sock_->read(id, 0);
            if (readData.hasError()) {
                return;
            }
            auto &server_stream_state = streams_[id];
            quic::BufPtr data = std::move(readData->first);
            bool eof = readData->second;
            if (server_stream_state.isControl) {
                if (data) {
                    auto range = data->coalesce();
                    server_stream_state.controlIn.insert(server_stream_state.controlIn.end(),
                                                         range.begin(), range.end());
                }
                if (eof && server_stream_state.controlOut.empty()) {
                    try {
                        uint8_t type = 0;
                        std::vector<uint8_t> payload =
                            decodeControlFrame(server_stream_state.controlIn, type);
                        if (type != kMessageSessionStart) {
                            throw std::runtime_error("expected session_start");
                        }
                        session_ = decodeSessionStart(payload);
                        server_stream_state.controlOut = encodeSessionReady();
                        server_stream_state.controlFin = false;
                    } catch (const std::exception &ex) {
                        server_stream_state.controlOut = encodeSessionError(ex.what());
                        server_stream_state.controlFin = true;
                    }
                    writeControl(id, server_stream_state);
                }
                return;
            }
            if (data) {
                auto range = data->coalesce();
                server_stream_state.requestReceived += range.size();
            }
            if (eof) {
                server_stream_state.requestFin = true;
                bool variableBulkUpload = session_.mode == kModeCodeBulk &&
                                          session_.direction == kDirectionCodeUpload &&
                                          session_.totalBytes.set;
                if (!variableBulkUpload &&
                    server_stream_state.requestReceived != server_stream_state.requestBytes) {
                    sock_->close(quic::QuicError(quic::ApplicationErrorCode(1),
                                                 "unexpected request byte count"));
                    return;
                }
                server_stream_state.responseBytes = responseBytesForNextRequest();
                writeResponse(id, server_stream_state);
                auto cb = sock_->setReadCallback(id, nullptr);
                if (cb.hasError()) {
                    std::cerr << "mvfst server unset read callback failed\n";
                }
            }
        } catch (const std::exception &ex) {
            std::cerr << "mvfst server readAvailable exception: " << ex.what() << "\n";
        }
    }

    void readError(quic::StreamId, quic::QuicError error) noexcept override {
        std::cerr << "mvfst server read error: " << error.message << "\n";
    }

    void onStreamWriteReady(quic::StreamId id, uint64_t) noexcept override {
        auto iter = streams_.find(id);
        if (iter != streams_.end()) {
            if (iter->second.isControl) {
                writeControl(id, iter->second);
            } else {
                writeResponse(id, iter->second);
            }
        }
    }

    void onStreamWriteError(quic::StreamId, quic::QuicError error) noexcept override {
        std::cerr << "mvfst server write error: " << error.message << "\n";
    }

  private:
    void writeControl(quic::StreamId id, ServerStreamState &state) noexcept {
        while (state.controlSent < state.controlOut.size()) {
            size_t remaining = state.controlOut.size() - state.controlSent;
            size_t chunk = std::min(remaining, kWriteChunkSize);
            auto data =
                folly::IOBuf::copyBuffer(state.controlOut.data() + state.controlSent, chunk);
            bool eof = state.controlFin && state.controlSent + chunk == state.controlOut.size();
            auto res = sock_->writeChain(id, std::move(data), eof, nullptr);
            if (res.hasError()) {
                auto notify = sock_->notifyPendingWriteOnStream(id, this);
                if (notify.hasError()) {
                    std::cerr << "mvfst server notifyPendingWriteOnStream failed\n";
                }
                return;
            }
            state.controlSent += chunk;
        }
    }

    uint64_t responseBytesForNextRequest() noexcept {
        ++requestsCompleted_;
        if (session_.mode == kModeCodeBulk && session_.direction == kDirectionCodeDownload &&
            session_.totalBytes.set) {
            uint64_t streamIndex = requestsCompleted_ - 1;
            uint64_t perStream = session_.totalBytes.value / session_.streams;
            uint64_t remainder = session_.totalBytes.value % session_.streams;
            return perStream + static_cast<uint64_t>(streamIndex < remainder);
        }
        if (session_.mode == kModeCodeBulk && session_.direction == kDirectionCodeUpload) {
            return 0;
        }
        return session_.responseBytes;
    }

    void writeResponse(quic::StreamId id, ServerStreamState &state) noexcept {
        if (!state.requestFin || state.responseFin) {
            return;
        }
        while (state.responseSent < state.responseBytes) {
            uint64_t remaining = state.responseBytes - state.responseSent;
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, kWriteChunkSize));
            auto data = folly::IOBuf::create(chunk);
            std::memset(data->writableData(), 0x5a, chunk);
            data->append(chunk);
            bool eof = chunk == remaining;
            auto res = sock_->writeChain(id, std::move(data), eof, nullptr);
            if (res.hasError()) {
                auto notify = sock_->notifyPendingWriteOnStream(id, this);
                if (notify.hasError()) {
                    std::cerr << "mvfst server notifyPendingWriteOnStream failed\n";
                }
                return;
            }
            state.responseSent += chunk;
            if (eof) {
                state.responseFin = true;
                streams_.erase(id);
                return;
            }
        }
        auto res = sock_->writeChain(id, nullptr, true, nullptr);
        if (!res.hasError()) {
            state.responseFin = true;
            streams_.erase(id);
        }
    }

    folly::EventBase *evb_;
    std::shared_ptr<quic::QuicSocket> sock_;
    PerfSessionStart session_;
    uint64_t requestsCompleted_{0};
    std::map<quic::StreamId, ServerStreamState> streams_;
};

class PerfServerTransportFactory : public quic::QuicServerTransportFactory {
  public:
    ~PerfServerTransportFactory() override {
        draining_ = true;
        std::vector<std::unique_ptr<PerfServerHandler>> handlers;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            handlers.swap(handlers_);
        }
        for (auto &handler : handlers) {
            handler->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
                [&] { handler.reset(); });
        }
    }

    quic::QuicServerTransport::Ptr
    make(folly::EventBase *evb, std::unique_ptr<quic::FollyAsyncUDPSocketAlias> sock,
         const folly::SocketAddress &, quic::QuicVersion,
         std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept override {
        if (draining_) {
            return nullptr;
        }
        auto handler = std::make_unique<PerfServerHandler>(evb);
        auto transport = quic::QuicServerTransport::make(evb, std::move(sock), handler.get(),
                                                         handler.get(), std::move(ctx));
        handler->setQuicSocket(transport);
        std::lock_guard<std::mutex> lock(mutex_);
        handlers_.push_back(std::move(handler));
        return transport;
    }

  private:
    std::mutex mutex_;
    std::vector<std::unique_ptr<PerfServerHandler>> handlers_;
    std::atomic_bool draining_{false};
};

void runServer(const Config &cfg) {
    auto server = quic::QuicServer::createQuicServer(transportSettings(cfg));
    server->setHostId(kServerHostId);
    server->setCongestionControllerFactory(
        std::make_shared<quic::ServerCongestionControllerFactory>());
    server->setQuicServerTransportFactory(std::make_unique<PerfServerTransportFactory>());
    server->setFizzContext(makeServerCtx(cfg));
    server->start(folly::SocketAddress(cfg.host.c_str(), cfg.port), 0);
    std::promise<void>().get_future().wait();
}

struct ClientStreamState {
    bool isControl{false};
    std::vector<uint8_t> controlOut;
    std::vector<uint8_t> controlIn;
    size_t sent{0};
    uint64_t requestBytes{0};
    uint64_t responseBytes{0};
    uint64_t requestSent{0};
    uint64_t received{0};
    bool counts{false};
    bool finSent{false};
    Clock::time_point start{Clock::now()};
};

class MvfstClient : public quic::QuicSocket::ConnectionSetupCallback,
                    public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback,
                    public quic::QuicSocket::WriteCallback {
  public:
    explicit MvfstClient(const Config &cfg)
        : cfg_(cfg), networkThread_("mvfst-perf-client"), evb_(networkThread_.getEventBase()),
          qevb_(std::make_shared<quic::FollyQuicEventBase>(evb_)) {
    }

    ~MvfstClient() override {
        close();
    }

    void start() {
        auto peerHost = resolveHostForSocketAddress(cfg_.host, cfg_.port);
        evb_->runInEventBaseThreadAndWait([&] {
            auto sock = std::make_unique<quic::FollyQuicAsyncUDPSocket>(qevb_);
            client_ = std::make_shared<quic::QuicClientTransport>(qevb_, std::move(sock),
                                                                  makeClientHandshakeCtx());
            client_->setHostname(cfg_.serverName);
            client_->addNewPeerAddress(folly::SocketAddress(peerHost.c_str(), cfg_.port));
            client_->setCongestionControllerFactory(
                std::make_shared<quic::DefaultCongestionControllerFactory>());
            client_->setTransportSettings(transportSettings(cfg_));
            client_->start(this, this);
        });
    }

    void waitConnected() {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_.wait_for(lock, std::chrono::seconds(10),
                       [&] { return connected_ || !error_.empty(); });
        if (!connected_) {
            throw std::runtime_error(error_.empty() ? "mvfst handshake timed out" : error_);
        }
        lock.unlock();
        openControlStream();
        waitSessionReady();
    }

    std::vector<CompletedStream> takeCompleted() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<CompletedStream> out;
        out.swap(completed_);
        return out;
    }

    bool hasStreams() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return activeRequestStreamsLocked() != 0;
    }

    size_t streamCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return activeRequestStreamsLocked();
    }

    bool isConnected() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return connected_ && error_.empty();
    }

    std::string error() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return error_;
    }

    void close() {
        evb_->runInEventBaseThreadAndWait([this] {
            if (!client_) {
                return;
            }
            std::vector<quic::StreamId> streams;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (const auto &[id, _] : streams_) {
                    streams.push_back(id);
                }
                streams_.clear();
                connected_ = false;
            }
            auto client = std::move(client_);
            client->setConnectionSetupCallback(nullptr);
            client->setConnectionCallback(nullptr);
            for (auto id : streams) {
                client->setReadCallback(id, nullptr);
                client->unregisterStreamWriteCallback(id);
            }
            client->closeNow(quic::Optional<quic::QuicError>());
        });
    }

    void openRequest(bool counts, uint64_t requestBytes, uint64_t responseBytes) {
        evb_->runInEventBaseThreadAndWait([&, counts, requestBytes, responseBytes] {
            if (!sessionReady_) {
                setError("mvfst session is not ready");
                return;
            }
            auto idResult = client_->createBidirectionalStream();
            if (idResult.hasError()) {
                setError("mvfst createBidirectionalStream failed");
                return;
            }
            quic::StreamId streamId = *idResult;
            ClientStreamState state;
            state.requestBytes = requestBytes;
            state.responseBytes = responseBytes;
            state.counts = counts;
            state.start = Clock::now();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                streams_.emplace(streamId, std::move(state));
            }
            auto cb = client_->setReadCallback(streamId, this);
            if (cb.hasError()) {
                setError("mvfst setReadCallback failed");
                return;
            }
            sendStream(streamId);
        });
    }

    std::vector<CompletedStream> driveUntil(Clock::time_point deadline, bool waitForCompletion) {
        for (;;) {
            auto completed = takeCompleted();
            if (!completed.empty()) {
                return completed;
            }
            auto err = error();
            if (!err.empty()) {
                throw std::runtime_error(err);
            }
            if (!waitForCompletion && Clock::now() >= deadline) {
                return {};
            }
            std::unique_lock<std::mutex> lock(mutex_);
            cond_.wait_until(lock, deadline, [&] {
                return !completed_.empty() || !error_.empty() ||
                       (waitForCompletion ? activeRequestStreamsLocked() == 0 : false);
            });
            bool shouldDrain = (waitForCompletion && activeRequestStreamsLocked() == 0) ||
                               Clock::now() >= deadline;
            lock.unlock();
            if (shouldDrain) {
                return takeCompleted();
            }
        }
    }

    void onTransportReady() noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        connected_ = true;
        cond_.notify_all();
    }

    void onReplaySafe() noexcept override {
    }

    void onConnectionSetupError(quic::QuicError error) noexcept override {
        onConnectionError(std::move(error));
    }

    void onConnectionError(quic::QuicError error) noexcept override {
        setError("mvfst connection error: " + error.message);
    }

    void onConnectionEnd() noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        connected_ = false;
        cond_.notify_all();
    }

    void onNewBidirectionalStream(quic::StreamId id) noexcept override {
        auto cb = client_->setReadCallback(id, this);
        if (cb.hasError()) {
            setError("mvfst setReadCallback for peer stream failed");
        }
    }

    void onNewUnidirectionalStream(quic::StreamId) noexcept override {
    }
    void onStopSending(quic::StreamId, quic::ApplicationErrorCode) noexcept override {
    }

    void readAvailable(quic::StreamId id) noexcept override {
        try {
            auto readData = client_->read(id, 0);
            if (readData.hasError()) {
                return;
            }
            quic::BufPtr data = std::move(readData->first);
            bool eof = readData->second;
            CompletedStream completed;
            bool done = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto iter = streams_.find(id);
                if (iter == streams_.end()) {
                    return;
                }
                if (data) {
                    if (iter->second.isControl) {
                        auto range = data->coalesce();
                        iter->second.controlIn.insert(iter->second.controlIn.end(), range.begin(),
                                                      range.end());
                        handleControlLocked(iter->second);
                    } else {
                        iter->second.received += data->computeChainDataLength();
                    }
                }
                if (eof) {
                    if (iter->second.isControl) {
                        streams_.erase(iter);
                        done = true;
                    } else if (iter->second.received != iter->second.responseBytes) {
                        error_ = "mvfst stream received unexpected byte count";
                        streams_.erase(iter);
                        done = true;
                    } else {
                        completed.counts = iter->second.counts;
                        completed.requestBytes = iter->second.requestBytes;
                        completed.received = iter->second.received;
                        completed.latency = Clock::now() - iter->second.start;
                        completed_.push_back(completed);
                    }
                    streams_.erase(iter);
                    done = true;
                }
            }
            if (done) {
                auto cb = client_->setReadCallback(id, nullptr);
                if (cb.hasError()) {
                    setError("mvfst unset read callback failed");
                }
                cond_.notify_all();
            }
        } catch (const std::exception &ex) {
            setError(std::string("mvfst readAvailable exception: ") + ex.what());
        }
    }

    void readError(quic::StreamId, quic::QuicError error) noexcept override {
        setError("mvfst read error: " + error.message);
    }

    void onStreamWriteReady(quic::StreamId id, uint64_t) noexcept override {
        sendStream(id);
    }

    void onStreamWriteError(quic::StreamId, quic::QuicError error) noexcept override {
        setError("mvfst write error: " + error.message);
    }

  private:
    size_t activeRequestStreamsLocked() const {
        size_t count = 0;
        for (const auto &[_, stream] : streams_) {
            if (!stream.isControl) {
                ++count;
            }
        }
        return count;
    }

    void setError(std::string message) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (error_.empty()) {
            error_ = std::move(message);
        }
        cond_.notify_all();
    }

    void openControlStream() {
        evb_->runInEventBaseThreadAndWait([&] {
            auto idResult = client_->createBidirectionalStream();
            if (idResult.hasError()) {
                setError("mvfst create control stream failed");
                return;
            }
            quic::StreamId streamId = *idResult;
            if (streamId != kControlStreamId) {
                setError("mvfst unexpected control stream id");
                return;
            }
            ClientStreamState state;
            state.isControl = true;
            state.controlOut = encodeSessionStart(cfg_);
            state.start = Clock::now();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                streams_.emplace(streamId, std::move(state));
            }
            auto cb = client_->setReadCallback(streamId, this);
            if (cb.hasError()) {
                setError("mvfst setReadCallback for control failed");
                return;
            }
            sendStream(streamId);
        });
    }

    void waitSessionReady() {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_.wait_for(lock, std::chrono::seconds(10),
                       [&] { return sessionReady_ || !error_.empty(); });
        if (!sessionReady_) {
            throw std::runtime_error(error_.empty() ? "mvfst session_ready timed out" : error_);
        }
    }

    void handleControlLocked(ClientStreamState &state) {
        if (state.controlIn.size() < 5) {
            return;
        }
        uint32_t payloadLen = readU32(state.controlIn.data() + 1);
        if (state.controlIn.size() < static_cast<size_t>(payloadLen) + 5) {
            return;
        }
        uint8_t type = 0;
        std::vector<uint8_t> payload;
        try {
            payload = decodeControlFrame(state.controlIn, type);
        } catch (const std::exception &ex) {
            if (error_.empty()) {
                error_ = ex.what();
            }
            cond_.notify_all();
            return;
        }
        if (type == kMessageSessionReady && payload.size() == 4 &&
            readU32(payload.data()) == kPerfProtocolVersion) {
            sessionReady_ = true;
            cond_.notify_all();
            return;
        }
        if (type == kMessageSessionError) {
            if (payload.size() >= 4) {
                uint32_t len = readU32(payload.data());
                if (payload.size() == static_cast<size_t>(len) + 4) {
                    error_ = "mvfst server reported session_error: " +
                             std::string(payload.begin() + 4, payload.end());
                }
            }
            if (error_.empty()) {
                error_ = "mvfst server reported session_error";
            }
        } else {
            error_ = "mvfst received unexpected control message";
        }
        cond_.notify_all();
    }

    void sendStream(quic::StreamId id) noexcept {
        try {
            for (;;) {
                ClientStreamState snapshot;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    auto iter = streams_.find(id);
                    if (iter == streams_.end() || iter->second.finSent) {
                        return;
                    }
                    snapshot = iter->second;
                }
                size_t chunk = 0;
                bool eof = false;
                quic::BufPtr data;
                if (snapshot.isControl) {
                    size_t remaining = snapshot.controlOut.size() - snapshot.sent;
                    chunk = std::min(remaining, kWriteChunkSize);
                    eof = chunk == remaining;
                    data =
                        folly::IOBuf::copyBuffer(snapshot.controlOut.data() + snapshot.sent, chunk);
                } else {
                    uint64_t remaining = snapshot.requestBytes - snapshot.requestSent;
                    chunk = static_cast<size_t>(std::min<uint64_t>(remaining, kWriteChunkSize));
                    eof = chunk == remaining;
                    data = chunk == 0 ? nullptr : folly::IOBuf::create(chunk);
                    if (chunk != 0) {
                        std::memset(data->writableData(), 0x5a, chunk);
                        data->append(chunk);
                    }
                }
                auto res = client_->writeChain(id, std::move(data), eof, nullptr);
                if (res.hasError()) {
                    auto notify = client_->notifyPendingWriteOnStream(id, this);
                    if (notify.hasError()) {
                        setError("mvfst notifyPendingWriteOnStream failed");
                    }
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    auto iter = streams_.find(id);
                    if (iter == streams_.end()) {
                        return;
                    }
                    if (iter->second.isControl) {
                        iter->second.sent += chunk;
                    } else {
                        iter->second.requestSent += chunk;
                    }
                    if (eof) {
                        iter->second.finSent = true;
                    }
                }
                if (eof) {
                    return;
                }
            }
        } catch (const std::exception &ex) {
            setError(std::string("mvfst send exception: ") + ex.what());
        }
    }

    Config cfg_;
    folly::ScopedEventBaseThread networkThread_;
    folly::EventBase *evb_;
    std::shared_ptr<quic::FollyQuicEventBase> qevb_;
    std::shared_ptr<quic::QuicClientTransport> client_;
    mutable std::mutex mutex_;
    std::condition_variable cond_;
    bool connected_{false};
    bool sessionReady_{false};
    std::string error_;
    std::map<quic::StreamId, ClientStreamState> streams_;
    std::vector<CompletedStream> completed_;
};

std::unique_ptr<MvfstClient> connectClient(const Config &cfg) {
    auto client = std::make_unique<MvfstClient>(cfg);
    client->start();
    client->waitConnected();
    return client;
}

std::vector<std::unique_ptr<MvfstClient>> connectClients(const Config &cfg, uint64_t count = 0) {
    if (count == 0) {
        count = cfg.connections;
    }
    std::vector<std::unique_ptr<MvfstClient>> clients;
    clients.reserve(intCap(count));
    for (uint64_t i = 0; i < count; ++i) {
        clients.push_back(connectClient(configWithRrRequestLimit(cfg, i)));
    }
    return clients;
}

void collectCompleted(const std::vector<CompletedStream> &completed, Counters &counters,
                      Clock::time_point measureStart) {
    for (const auto &stream : completed) {
        if (stream.counts && Clock::now() >= measureStart) {
            counters.bytesSent += stream.requestBytes;
            counters.bytesReceived += stream.received;
            counters.requestsCompleted += 1;
            counters.latencies.push_back(stream.latency);
        }
    }
}

void runTimedBulk(const Config &cfg, Counters &counters) {
    auto clients = connectClients(cfg);
    auto measureStart = Clock::now() + cfg.warmup;
    auto deadline = measureStart + cfg.duration;
    for (auto &client : clients) {
        for (uint64_t i = 0; i < cfg.streams; ++i) {
            client->openRequest(false, scenarioRequestBytes(cfg), scenarioResponseBytes(cfg));
        }
    }
    while (Clock::now() < deadline) {
        for (auto &client : clients) {
            for (const auto &completed : client->driveUntil(deadline, false)) {
                if (completed.counts && Clock::now() >= measureStart) {
                    counters.bytesSent += completed.requestBytes;
                    counters.bytesReceived += completed.received;
                }
            }
        }
        for (auto &client : clients) {
            while (client->isConnected() && Clock::now() < deadline) {
                if (client->streamCount() < intCap(cfg.streams)) {
                    client->openRequest(Clock::now() >= measureStart, scenarioRequestBytes(cfg),
                                        scenarioResponseBytes(cfg));
                } else {
                    break;
                }
            }
        }
    }
    for (auto &client : clients) {
        client->driveUntil(Clock::now() + kDrainTimeout, false);
    }
}

void runFixedBulk(const Config &cfg, Counters &counters) {
    if (!cfg.totalBytes.set) {
        throw std::runtime_error("fixed bulk requires --total-bytes for mvfst client");
    }
    auto clients = connectClients(cfg);
    auto deadline = Clock::now() + cfg.duration + kDrainTimeout;
    uint64_t perStream = cfg.totalBytes.value / cfg.streams;
    uint64_t remainder = cfg.totalBytes.value % cfg.streams;
    for (uint64_t i = 0; i < cfg.streams; ++i) {
        uint64_t target = perStream + static_cast<uint64_t>(i < remainder);
        auto &client = clients[(i % clients.size())];
        if (cfg.direction == kDirectionUpload) {
            client->openRequest(true, target, 0);
        } else {
            client->openRequest(true, scenarioRequestBytes(cfg), target);
        }
    }
    while (std::any_of(clients.begin(), clients.end(),
                       [](const auto &client) { return client->hasStreams(); })) {
        if (Clock::now() >= deadline) {
            throw std::runtime_error("mvfst fixed bulk timed out waiting for stream completion");
        }
        auto waitDeadline = std::min(Clock::now() + std::chrono::seconds(10), deadline);
        for (auto &client : clients) {
            for (const auto &completed : client->driveUntil(waitDeadline, true)) {
                counters.bytesSent += completed.requestBytes;
                counters.bytesReceived += completed.received;
            }
        }
    }
}

void runRr(const Config &cfg, Counters &counters) {
    auto clients = connectClients(cfg, rrConnectionTarget(cfg));
    auto measureStart = Clock::now() + cfg.warmup;
    auto deadline = measureStart + cfg.duration;
    uint64_t started = 0;
    std::vector<uint64_t> startedByConnection(clients.size(), 0);
    for (size_t index = 0; index < clients.size(); ++index) {
        auto &client = clients[index];
        while (client->streamCount() < intCap(cfg.requestsInFlight)) {
            if (!canStartRrRequest(cfg, started, startedByConnection, index)) {
                break;
            }
            client->openRequest(cfg.requests.set || Clock::now() >= measureStart, cfg.requestBytes,
                                cfg.responseBytes);
            ++started;
            ++startedByConnection[index];
        }
    }
    for (;;) {
        if (!cfg.requests.set && Clock::now() >= deadline) {
            break;
        }
        if (cfg.requests.set && started >= cfg.requests.value &&
            std::none_of(clients.begin(), clients.end(),
                         [](const auto &client) { return client->hasStreams(); })) {
            break;
        }
        for (auto &client : clients) {
            collectCompleted(client->driveUntil(deadline, false), counters, measureStart);
        }
        for (size_t index = 0; index < clients.size(); ++index) {
            auto &client = clients[index];
            while (client->streamCount() < intCap(cfg.requestsInFlight)) {
                if (!canStartRrRequest(cfg, started, startedByConnection, index)) {
                    break;
                }
                if (!cfg.requests.set && Clock::now() >= deadline) {
                    break;
                }
                client->openRequest(cfg.requests.set || Clock::now() >= measureStart,
                                    cfg.requestBytes, cfg.responseBytes);
                ++started;
                ++startedByConnection[index];
            }
        }
    }
}

struct MvfstCrrClient {
    std::unique_ptr<MvfstClient> client;
    bool requestOpened{false};
    bool counts{false};
};

void fillCrrClients(const Config &cfg, Counters &counters, Clock::time_point measureStart,
                    Clock::time_point deadline, uint64_t &started,
                    std::vector<MvfstCrrClient> &clients) {
    while (clients.size() < intCap(cfg.connections)) {
        if (cfg.requests.set && started >= cfg.requests.value) {
            break;
        }
        if (!cfg.requests.set && Clock::now() >= deadline) {
            break;
        }
        try {
            bool counts = cfg.requests.set || Clock::now() >= measureStart;
            clients.push_back({connectClient(cfg), false, counts});
            ++started;
        } catch (const std::exception &) {
            if (cfg.requests.set) {
                throw;
            }
            counters.skippedSetupErrors += 1;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
}

void runCrr(const Config &cfg, Counters &counters) {
    auto measureStart = Clock::now() + cfg.warmup;
    auto deadline = measureStart + cfg.duration;
    uint64_t started = 0;
    std::vector<MvfstCrrClient> clients;
    clients.reserve(intCap(cfg.connections));
    fillCrrClients(cfg, counters, measureStart, deadline, started, clients);
    while (!clients.empty() || (cfg.requests.set && started < cfg.requests.value) ||
           (!cfg.requests.set && Clock::now() < deadline)) {
        size_t index = 0;
        while (index < clients.size()) {
            auto &entry = clients[index];
            if (!entry.requestOpened) {
                entry.client->openRequest(entry.counts, cfg.requestBytes, cfg.responseBytes);
                entry.requestOpened = true;
            }
            auto waitDeadline =
                std::min(Clock::now() + std::chrono::seconds(10), deadline + kDrainTimeout);
            collectCompleted(entry.client->driveUntil(waitDeadline, true), counters, measureStart);
            if (entry.requestOpened && !entry.client->hasStreams()) {
                clients.erase(clients.begin() + static_cast<std::ptrdiff_t>(index));
                continue;
            }
            ++index;
        }
        fillCrrClients(cfg, counters, measureStart, deadline, started, clients);
    }
}

RunSummary runClient(const Config &cfg) {
    RunSummary summary = newRunSummary(cfg);
    Counters counters;
    auto runStart = Clock::now();
    Duration elapsed;
    if (cfg.mode == kModeBulk) {
        if (!cfg.totalBytes.set) {
            runTimedBulk(cfg, counters);
            elapsed = cfg.duration;
        } else {
            runFixedBulk(cfg, counters);
            elapsed = Clock::now() - runStart;
        }
    } else if (cfg.mode == kModeRr) {
        runRr(cfg, counters);
        elapsed = cfg.requests.set ? Clock::now() - runStart : cfg.duration;
    } else {
        runCrr(cfg, counters);
        elapsed = cfg.requests.set ? Clock::now() - runStart : cfg.duration;
    }
    summary.elapsedMs = durationMillis(elapsed);
    summary.bytesSent = counters.bytesSent;
    summary.bytesReceived = counters.bytesReceived;
    summary.requestsCompleted = counters.requestsCompleted;
    summary.skippedSetupErrors = counters.skippedSetupErrors;
    summary.serverBytesSent = counters.bytesReceived;
    summary.serverBytesReceived = counters.bytesSent;
    summary.serverRequestsCompleted = counters.requestsCompleted;
    summary.latency = summarizeLatency(counters.latencies);
    return summary;
}

} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 2) {
            std::cerr << "usage: mvfst-perf [client|server] [options]\n";
            return 2;
        }
        std::string role = argv[1];
        if (role != "client" && role != "server") {
            std::cerr << "usage: mvfst-perf [client|server] [options]\n";
            return 2;
        }
        std::vector<std::string> args;
        for (int i = 2; i < argc; ++i) {
            args.emplace_back(argv[i]);
        }
        Config cfg = parseArgs(args);
        if (role == "server") {
            runServer(cfg);
            return 0;
        }

        RunSummary summary = newRunSummary(cfg);
        try {
            summary = runClient(cfg);
        } catch (const std::exception &ex) {
            summary.status = "failed";
            summary.failureReason = ex.what();
        }
        finalizeSummary(summary);
        emitSummary(summary, cfg.jsonOut);
        return summary.status == "ok" ? 0 : 1;
    } catch (const std::exception &ex) {
        std::cerr << ex.what() << "\n";
        return 2;
    }
}
