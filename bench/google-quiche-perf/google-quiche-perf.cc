#include <algorithm>
#include <array>
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
#include <sys/uio.h>
#include <utility>
#include <vector>

#include "absl/log/initialize.h"
#include "absl/strings/str_cat.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/proof_source_x509.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/crypto/quic_client_session_cache.h"
#include "quiche/quic/core/quic_crypto_client_stream.h"
#include "quiche/quic/core/quic_crypto_server_stream_base.h"
#include "quiche/quic/core/quic_crypto_stream.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_dispatcher.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_default_proof_providers.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quic_client_base.h"
#include "quiche/quic/tools/quic_client_default_network_helper.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_name_lookup.h"
#include "quiche/quic/tools/quic_server.h"
#include "quiche/quic/tools/quic_simple_crypto_server_stream_helper.h"
#include "quiche/common/platform/api/quiche_reference_counted.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"

namespace coquic::bench::google_quiche_perf {

using Clock = std::chrono::steady_clock;
using Duration = std::chrono::microseconds;

constexpr char kApplicationProtocol[] = "coquic-perf/1";
constexpr uint32_t kPerfProtocolVersion = 3;
constexpr quic::QuicStreamId kControlStreamId = 0;
constexpr uint8_t kMessageSessionStart = 1;
constexpr uint8_t kMessageSessionReady = 2;
constexpr uint8_t kMessageSessionError = 3;
constexpr uint8_t kModeCodeBulk = 0;
constexpr uint8_t kModeCodeRr = 1;
constexpr uint8_t kModeCodeCrr = 2;
constexpr uint8_t kDirectionCodeUpload = 0;
constexpr uint8_t kDirectionCodeDownload = 1;
constexpr uint64_t kDefaultMaxRunRequests = 4096;
constexpr uint64_t kConnectionWindow = 32ULL * 1024ULL * 1024ULL;
constexpr uint64_t kStreamWindow = 16ULL * 1024ULL * 1024ULL;
constexpr uint32_t kMaxStreams = 1'000'000;
constexpr size_t kWriteChunkSize = 32 * 1024;
constexpr Duration kDrainTimeout = Duration(2'000'000);

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

using GoogleQuicheConfig = quic::QuicConfig;
using GoogleQuicheSocketAddress = quic::QuicSocketAddress;
using GoogleQuicheVersionVector = quic::ParsedQuicVersionVector;

GoogleQuicheConfig QuicConfigForPerf() {
    GoogleQuicheConfig config;
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

GoogleQuicheVersionVector SupportedVersions() {
    GoogleQuicheVersionVector versions = {quic::ParsedQuicVersion::RFCv1()};
    for (const auto &version : versions) {
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

GoogleQuicheSocketAddress ResolveRemote(const Config &cfg) {
    GoogleQuicheSocketAddress address =
        quic::tools::LookupAddress(AF_UNSPEC, cfg.host, absl::StrCat(cfg.port));
    if (!address.IsInitialized()) {
        throw std::runtime_error(absl::StrCat("unable to resolve address: ", cfg.host));
    }
    return address;
}

uint64_t ScenarioRequestBytes(const Config &cfg) {
    if (cfg.mode == "bulk" && cfg.direction == "upload") {
        return std::max(cfg.request_bytes, cfg.response_bytes);
    }
    return cfg.request_bytes;
}

uint64_t ScenarioResponseBytes(const Config &cfg) {
    if (cfg.mode == "bulk" && cfg.direction == "upload") {
        return 0;
    }
    return cfg.response_bytes;
}

uint8_t ModeCode(const std::string &mode) {
    if (mode == "rr") {
        return kModeCodeRr;
    }
    if (mode == "crr") {
        return kModeCodeCrr;
    }
    return kModeCodeBulk;
}

uint8_t DirectionCode(const std::string &direction) {
    return direction == "upload" ? kDirectionCodeUpload : kDirectionCodeDownload;
}

void AppendU32(std::vector<char> *out, uint32_t value) {
    out->push_back(static_cast<char>((value >> 24) & 0xffU));
    out->push_back(static_cast<char>((value >> 16) & 0xffU));
    out->push_back(static_cast<char>((value >> 8) & 0xffU));
    out->push_back(static_cast<char>(value & 0xffU));
}

void AppendU64(std::vector<char> *out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out->push_back(static_cast<char>((value >> shift) & 0xffU));
    }
}

uint32_t ReadU32(const char *bytes) {
    return (static_cast<uint32_t>(static_cast<unsigned char>(bytes[0])) << 24) |
           (static_cast<uint32_t>(static_cast<unsigned char>(bytes[1])) << 16) |
           (static_cast<uint32_t>(static_cast<unsigned char>(bytes[2])) << 8) |
           static_cast<uint32_t>(static_cast<unsigned char>(bytes[3]));
}

uint64_t ReadU64(const char *bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<unsigned char>(bytes[i]);
    }
    return value;
}

std::vector<char> FrameControlMessage(uint8_t type, const std::vector<char> &payload) {
    std::vector<char> out;
    out.reserve(payload.size() + 5);
    out.push_back(static_cast<char>(type));
    AppendU32(&out, static_cast<uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

uint64_t RrConnectionTarget(const Config &cfg) {
    if (cfg.mode == "rr" && cfg.requests.set) {
        return std::min(cfg.connections, cfg.requests.value);
    }
    return cfg.connections;
}

uint64_t RrRequestLimitForConnection(const Config &cfg, uint64_t connection_index) {
    uint64_t connections = RrConnectionTarget(cfg);
    if (connections == 0) {
        return 0;
    }
    uint64_t base = cfg.requests.value / connections;
    uint64_t remainder = cfg.requests.value % connections;
    return base + static_cast<uint64_t>(connection_index < remainder);
}

bool CanStartRrRequest(const Config &cfg, uint64_t started,
                       const std::vector<uint64_t> &started_by_connection,
                       size_t connection_index) {
    if (!cfg.requests.set) {
        return true;
    }
    return started < cfg.requests.value &&
           started_by_connection[connection_index] <
               RrRequestLimitForConnection(cfg, static_cast<uint64_t>(connection_index));
}

Config ConfigWithRrRequestLimit(const Config &cfg, uint64_t connection_index) {
    Config connection_cfg = cfg;
    if (cfg.mode == "rr" && cfg.requests.set) {
        connection_cfg.requests.value = RrRequestLimitForConnection(cfg, connection_index);
        connection_cfg.requests.set = true;
    }
    return connection_cfg;
}

std::vector<char> EncodeSessionStart(const Config &cfg) {
    std::vector<char> payload;
    payload.reserve(79);
    AppendU32(&payload, kPerfProtocolVersion);
    payload.push_back(static_cast<char>(ModeCode(cfg.mode)));
    payload.push_back(static_cast<char>(DirectionCode(cfg.direction)));
    AppendU64(&payload, ScenarioRequestBytes(cfg));
    AppendU64(&payload, ScenarioResponseBytes(cfg));
    payload.push_back(
        static_cast<char>((cfg.total_bytes.set ? 0x01 : 0) | (cfg.requests.set ? 0x02 : 0)));
    AppendU64(&payload, cfg.total_bytes.value);
    AppendU64(&payload, cfg.requests.value);
    AppendU64(&payload, DurationMicros(cfg.warmup));
    AppendU64(&payload, DurationMicros(cfg.duration));
    AppendU64(&payload, cfg.streams);
    AppendU64(&payload, cfg.connections);
    AppendU64(&payload, cfg.requests_in_flight);
    return FrameControlMessage(kMessageSessionStart, payload);
}

std::vector<char> EncodeSessionReady() {
    std::vector<char> payload;
    AppendU32(&payload, kPerfProtocolVersion);
    return FrameControlMessage(kMessageSessionReady, payload);
}

std::vector<char> EncodeSessionError(std::string_view reason) {
    std::vector<char> payload;
    AppendU32(&payload, static_cast<uint32_t>(reason.size()));
    payload.insert(payload.end(), reason.begin(), reason.end());
    return FrameControlMessage(kMessageSessionError, payload);
}

struct PerfSessionStart {
    bool started = false;
    uint8_t mode = kModeCodeBulk;
    uint8_t direction = kDirectionCodeDownload;
    uint64_t request_bytes = 0;
    uint64_t response_bytes = 0;
    OptionalU64 total_bytes;
    OptionalU64 requests;
    uint64_t warmup_us = 0;
    uint64_t duration_us = 0;
    uint64_t streams = 1;
    uint64_t connections = 1;
    uint64_t requests_in_flight = 1;
};

absl::string_view ControlPayload(const std::vector<char> &frame, uint8_t *type) {
    if (frame.size() < 5) {
        throw std::runtime_error("short control frame");
    }
    uint32_t len = ReadU32(frame.data() + 1);
    if (frame.size() < static_cast<size_t>(len) + 5) {
        throw std::runtime_error("incomplete control frame");
    }
    *type = static_cast<uint8_t>(frame[0]);
    return absl::string_view(frame.data() + 5, len);
}

PerfSessionStart DecodeSessionStart(absl::string_view payload) {
    if (payload.size() != 79 || ReadU32(payload.data()) != kPerfProtocolVersion) {
        throw std::runtime_error("malformed session_start");
    }
    PerfSessionStart start;
    start.started = true;
    start.mode = static_cast<uint8_t>(payload[4]);
    start.direction = static_cast<uint8_t>(payload[5]);
    start.request_bytes = ReadU64(payload.data() + 6);
    start.response_bytes = ReadU64(payload.data() + 14);
    uint8_t flags = static_cast<uint8_t>(payload[22]);
    start.total_bytes = {ReadU64(payload.data() + 23), (flags & 0x01) != 0};
    start.requests = {ReadU64(payload.data() + 31), (flags & 0x02) != 0};
    start.warmup_us = ReadU64(payload.data() + 39);
    start.duration_us = ReadU64(payload.data() + 47);
    start.streams = ReadU64(payload.data() + 55);
    start.connections = ReadU64(payload.data() + 63);
    start.requests_in_flight = ReadU64(payload.data() + 71);
    if ((start.mode != kModeCodeBulk && start.mode != kModeCodeRr && start.mode != kModeCodeCrr) ||
        (start.direction != kDirectionCodeUpload && start.direction != kDirectionCodeDownload) ||
        start.streams == 0 || start.connections == 0 || start.requests_in_flight == 0) {
        throw std::runtime_error("malformed session_start");
    }
    return start;
}

absl::string_view ZeroChunk(size_t size) {
    static const std::array<char, kWriteChunkSize> zeros = {};
    return absl::string_view(zeros.data(), size);
}

struct StreamCompletion {
    bool counts = false;
    uint64_t request_bytes = 0;
    uint64_t received = 0;
    Duration latency = Duration::zero();
};

class PerfClientSession;
class PerfServerSession;

class PerfStream : public quic::QuicStream {
  public:
    PerfStream(quic::QuicStreamId id, quic::QuicSession *session, bool is_server,
               PerfClientSession *client_session);

    void StartClientRequest(uint64_t request_bytes, uint64_t response_bytes, bool counts,
                            Clock::time_point start);
    void StartClientControl(std::vector<char> bytes);
    void SetServerSession(PerfServerSession *server_session);

    void OnDataAvailable() override;
    void OnCanWriteNewData() override;
    void OnStreamReset(const quic::QuicRstStreamFrame &frame) override;

  private:
    bool IsControl() const;
    size_t ConsumeServerBytes(absl::string_view data);
    size_t ConsumeClientBytes(absl::string_view data);
    void OnPeerFin();
    void SendMore();
    void SendControl();
    void CompleteClientStream();
    void FailClientStream(std::string message);

    const bool is_server_;
    quic::QuicStreamId stream_id_;
    PerfClientSession *client_session_;
    PerfServerSession *server_session_ = nullptr;
    std::vector<char> control_in_;
    std::vector<char> control_out_;
    size_t control_sent_ = 0;
    bool control_fin_ = false;
    uint64_t request_bytes_ = 0;
    uint64_t response_bytes_ = 0;
    uint64_t request_received_ = 0;
    uint64_t request_sent_ = 0;
    uint64_t response_received_ = 0;
    uint64_t response_sent_ = 0;
    bool request_fin_sent_ = false;
    bool request_complete_ = false;
    bool response_fin_sent_ = false;
    bool peer_fin_read_ = false;
    bool client_done_ = false;
    bool counts_ = false;
    Clock::time_point start_ = Clock::now();
};

class PerfSessionBase : public quic::QuicSession {
  public:
    PerfSessionBase(quic::QuicConnection *connection, bool owns_connection,
                    quic::QuicSession::Visitor *owner, const quic::QuicConfig &config,
                    const quic::ParsedQuicVersionVector &supported_versions)
        : quic::QuicSession(connection, owner, config, supported_versions,
                            /*num_expected_unidirectional_static_streams=*/0),
          owns_connection_(owns_connection) {
    }

    ~PerfSessionBase() override {
        if (owns_connection_) {
            DeleteConnection();
        }
    }

    void Initialize() override {
        crypto_stream_ = CreateCryptoStream();
        quic::QuicSession::Initialize();
    }

    std::vector<std::string> GetAlpnsToOffer() const override {
        return {std::string(kApplicationProtocol)};
    }

    std::vector<absl::string_view>::const_iterator
    SelectAlpn(const std::vector<absl::string_view> &alpns) const override {
        return std::find(alpns.cbegin(), alpns.cend(), absl::string_view(kApplicationProtocol));
    }

    quic::QuicCryptoStream *GetMutableCryptoStream() override {
        return crypto_stream_.get();
    }

    const quic::QuicCryptoStream *GetCryptoStream() const override {
        return crypto_stream_.get();
    }

    bool ShouldKeepConnectionAlive() const override {
        return true;
    }

  protected:
    virtual std::unique_ptr<quic::QuicCryptoStream> CreateCryptoStream() = 0;

  private:
    bool owns_connection_;
    std::unique_ptr<quic::QuicCryptoStream> crypto_stream_;
};

class PerfClientSession : public PerfSessionBase,
                          public quic::QuicCryptoClientStream::ProofHandler {
  public:
    PerfClientSession(quic::QuicConnection *connection, quic::QuicSession::Visitor *owner,
                      const quic::QuicConfig &config,
                      const quic::ParsedQuicVersionVector &supported_versions,
                      const quic::QuicServerId &server_id,
                      quic::QuicCryptoClientConfig *crypto_config)
        : PerfSessionBase(connection, /*owns_connection=*/true, owner, config, supported_versions),
          server_id_(server_id), crypto_config_(crypto_config) {
    }

    void Initialize() override {
        PerfSessionBase::Initialize();
        static_cast<quic::QuicCryptoClientStreamBase *>(GetMutableCryptoStream())->CryptoConnect();
    }

    bool OpenRequest(uint64_t request_bytes, uint64_t response_bytes, bool counts) {
        if (!session_ready_) {
            return false;
        }
        if (!CanOpenNextOutgoingBidirectionalStream()) {
            return false;
        }
        quic::QuicStreamId id = GetNextOutgoingBidirectionalStreamId();
        auto stream = std::make_unique<PerfStream>(id, this, /*is_server=*/false, this);
        PerfStream *request_stream = stream.get();
        ActivateStream(std::move(stream));
        ++active_requests_;
        request_stream->StartClientRequest(request_bytes, response_bytes, counts, Clock::now());
        return true;
    }

    bool OpenControl(const Config &cfg) {
        if (control_opened_ || !CanOpenNextOutgoingBidirectionalStream()) {
            return session_ready_;
        }
        quic::QuicStreamId id = GetNextOutgoingBidirectionalStreamId();
        if (id != kControlStreamId) {
            OnStreamFailed("Google QUICHE opened an unexpected control stream id");
            return false;
        }
        auto stream = std::make_unique<PerfStream>(id, this, /*is_server=*/false, this);
        PerfStream *control_stream = stream.get();
        ActivateStream(std::move(stream));
        control_opened_ = true;
        control_stream->StartClientControl(EncodeSessionStart(cfg));
        return true;
    }

    void OnControlReady() {
        session_ready_ = true;
    }

    bool session_ready() const {
        return session_ready_;
    }

    void OnStreamComplete(uint64_t request_bytes, uint64_t received, bool counts,
                          Clock::time_point start) {
        if (active_requests_ > 0) {
            --active_requests_;
        }
        completed_.push_back({counts, request_bytes, received,
                              std::chrono::duration_cast<Duration>(Clock::now() - start)});
    }

    void OnStreamFailed(std::string message) {
        if (active_requests_ > 0) {
            --active_requests_;
        }
        if (error_message_.empty()) {
            error_message_ = std::move(message);
        }
    }

    std::vector<StreamCompletion> TakeCompletions() {
        std::vector<StreamCompletion> completed;
        completed.swap(completed_);
        return completed;
    }

    uint64_t active_requests() const {
        return active_requests_;
    }

    bool HasActiveRequests() const {
        return active_requests_ > 0 || GetNumActiveStreams() + num_draining_streams() > 0;
    }

    const std::string &error_message() const {
        return error_message_;
    }

    int GetNumSentClientHellos() const {
        return static_cast<const quic::QuicCryptoClientStreamBase *>(GetCryptoStream())
            ->num_sent_client_hellos();
    }

    bool EarlyDataAccepted() const {
        return static_cast<const quic::QuicCryptoClientStreamBase *>(GetCryptoStream())
            ->EarlyDataAccepted();
    }

    bool ReceivedInchoateReject() const {
        return static_cast<const quic::QuicCryptoClientStreamBase *>(GetCryptoStream())
            ->ReceivedInchoateReject();
    }

    int GetNumReceivedServerConfigUpdates() const {
        return static_cast<const quic::QuicCryptoClientStreamBase *>(GetCryptoStream())
            ->num_scup_messages_received();
    }

    void OnProofValid(const quic::QuicCryptoClientConfig::CachedState &) override {
    }

    void OnProofVerifyDetailsAvailable(const quic::ProofVerifyDetails &) override {
    }

    bool OnCertificateRequested(const std::vector<std::string> &) override {
        return false;
    }

  protected:
    std::unique_ptr<quic::QuicCryptoStream> CreateCryptoStream() override {
        std::unique_ptr<quic::ProofVerifyContext> verify_context;
        if (crypto_config_->proof_verifier() != nullptr) {
            verify_context = crypto_config_->proof_verifier()->CreateDefaultContext();
        }
        return std::make_unique<quic::QuicCryptoClientStream>(
            server_id_, this, std::move(verify_context), crypto_config_, this,
            /*has_application_state=*/false);
    }

    quic::QuicStream *CreateIncomingStream(quic::QuicStreamId id) override {
        auto stream = std::make_unique<PerfStream>(id, this, /*is_server=*/false, this);
        PerfStream *incoming_stream = stream.get();
        ActivateStream(std::move(stream));
        return incoming_stream;
    }

  private:
    quic::QuicServerId server_id_;
    quic::QuicCryptoClientConfig *crypto_config_;
    uint64_t active_requests_ = 0;
    bool control_opened_ = false;
    bool session_ready_ = false;
    std::vector<StreamCompletion> completed_;
    std::string error_message_;
};

class PerfServerSession : public PerfSessionBase {
  public:
    PerfServerSession(quic::QuicConnection *connection, quic::QuicSession::Visitor *owner,
                      const quic::QuicConfig &config,
                      const quic::ParsedQuicVersionVector &supported_versions,
                      const quic::QuicCryptoServerConfig *crypto_config,
                      quic::QuicCompressedCertsCache *compressed_certs_cache,
                      quic::QuicCryptoServerStreamBase::Helper *helper)
        : PerfSessionBase(connection, /*owns_connection=*/true, owner, config, supported_versions),
          crypto_config_(crypto_config), compressed_certs_cache_(compressed_certs_cache),
          helper_(helper) {
    }

    bool SessionStarted() const {
        return session_start_.started;
    }

    uint64_t RequestBytes() const {
        return session_start_.request_bytes;
    }

    bool AllowsVariableBulkUpload() const {
        return session_start_.mode == kModeCodeBulk &&
               session_start_.direction == kDirectionCodeUpload && session_start_.total_bytes.set;
    }

    uint64_t ResponseBytesForNextRequest() {
        ++requests_completed_;
        if (session_start_.mode == kModeCodeBulk &&
            session_start_.direction == kDirectionCodeDownload && session_start_.total_bytes.set) {
            uint64_t stream_index = requests_completed_ - 1;
            uint64_t per_stream = session_start_.total_bytes.value / session_start_.streams;
            uint64_t remainder = session_start_.total_bytes.value % session_start_.streams;
            return per_stream + (stream_index < remainder ? 1 : 0);
        }
        if (session_start_.mode == kModeCodeBulk &&
            session_start_.direction == kDirectionCodeUpload) {
            return 0;
        }
        return session_start_.response_bytes;
    }

    std::vector<char> HandleControlFrame(const std::vector<char> &frame, bool *send_fin) {
        *send_fin = false;
        try {
            uint8_t type = 0;
            absl::string_view payload = ControlPayload(frame, &type);
            if (type != kMessageSessionStart) {
                *send_fin = true;
                return EncodeSessionError("expected session_start");
            }
            session_start_ = DecodeSessionStart(payload);
            return EncodeSessionReady();
        } catch (const std::exception &ex) {
            *send_fin = true;
            return EncodeSessionError(ex.what());
        }
    }

  protected:
    std::unique_ptr<quic::QuicCryptoStream> CreateCryptoStream() override {
        return quic::CreateCryptoServerStream(crypto_config_, compressed_certs_cache_, this,
                                              helper_);
    }

    quic::QuicStream *CreateIncomingStream(quic::QuicStreamId id) override {
        auto stream = std::make_unique<PerfStream>(id, this, /*is_server=*/true, nullptr);
        PerfStream *incoming_stream = stream.get();
        incoming_stream->SetServerSession(this);
        ActivateStream(std::move(stream));
        return incoming_stream;
    }

  private:
    const quic::QuicCryptoServerConfig *crypto_config_;
    quic::QuicCompressedCertsCache *compressed_certs_cache_;
    quic::QuicCryptoServerStreamBase::Helper *helper_;
    PerfSessionStart session_start_;
    uint64_t requests_completed_ = 0;
};

PerfStream::PerfStream(quic::QuicStreamId id, quic::QuicSession *session, bool is_server,
                       PerfClientSession *client_session)
    : quic::QuicStream(id, session, /*is_static=*/false, quic::BIDIRECTIONAL),
      is_server_(is_server), stream_id_(id), client_session_(client_session) {
}

void PerfStream::StartClientRequest(uint64_t request_bytes, uint64_t response_bytes, bool counts,
                                    Clock::time_point start) {
    request_bytes_ = request_bytes;
    response_bytes_ = response_bytes;
    counts_ = counts;
    start_ = start;
    SendMore();
}

void PerfStream::StartClientControl(std::vector<char> bytes) {
    control_out_ = std::move(bytes);
    control_fin_ = true;
    SendMore();
}

void PerfStream::SetServerSession(PerfServerSession *server_session) {
    server_session_ = server_session;
}

bool PerfStream::IsControl() const {
    return stream_id_ == kControlStreamId;
}

size_t PerfStream::ConsumeServerBytes(absl::string_view data) {
    if (IsControl()) {
        control_in_.insert(control_in_.end(), data.begin(), data.end());
        return data.size();
    }
    if (server_session_ == nullptr || !server_session_->SessionStarted()) {
        Reset(quic::QUIC_BAD_APPLICATION_PAYLOAD);
        return data.size();
    }
    request_bytes_ = server_session_->RequestBytes();
    request_received_ += data.size();
    if (!server_session_->AllowsVariableBulkUpload() && request_received_ > request_bytes_) {
        Reset(quic::QUIC_BAD_APPLICATION_PAYLOAD);
    }
    return data.size();
}

size_t PerfStream::ConsumeClientBytes(absl::string_view data) {
    if (IsControl()) {
        control_in_.insert(control_in_.end(), data.begin(), data.end());
        if (control_in_.size() >= 5) {
            try {
                uint8_t type = 0;
                absl::string_view payload = ControlPayload(control_in_, &type);
                if (type == kMessageSessionReady && payload.size() == 4 &&
                    ReadU32(payload.data()) == kPerfProtocolVersion) {
                    if (client_session_ != nullptr) {
                        client_session_->OnControlReady();
                    }
                } else if (type == kMessageSessionError) {
                    std::string reason = "Google QUICHE server reported session_error";
                    if (payload.size() >= 4) {
                        uint32_t len = ReadU32(payload.data());
                        if (payload.size() == static_cast<size_t>(len) + 4) {
                            reason.append(": ");
                            reason.append(payload.data() + 4, len);
                        }
                    }
                    FailClientStream(reason);
                } else {
                    FailClientStream("Google QUICHE received an unexpected control message");
                }
            } catch (const std::exception &) {
            }
        }
        return data.size();
    }
    uint64_t remaining = response_bytes_ - response_received_;
    if (static_cast<uint64_t>(data.size()) > remaining) {
        FailClientStream("Google QUICHE stream received more response bytes than requested");
        Reset(quic::QUIC_BAD_APPLICATION_PAYLOAD);
        return data.size();
    }
    response_received_ += data.size();
    return data.size();
}

void PerfStream::OnDataAvailable() {
    while (sequencer()->HasBytesToRead()) {
        iovec region;
        if (!sequencer()->GetReadableRegion(&region)) {
            break;
        }
        absl::string_view data(static_cast<const char *>(region.iov_base), region.iov_len);
        size_t consumed = is_server_ ? ConsumeServerBytes(data) : ConsumeClientBytes(data);
        if (consumed == 0) {
            break;
        }
        sequencer()->MarkConsumed(consumed);
    }

    if (sequencer()->IsClosed() && !peer_fin_read_) {
        peer_fin_read_ = true;
        OnPeerFin();
        OnFinRead();
    }
}

void PerfStream::OnPeerFin() {
    if (IsControl()) {
        if (is_server_) {
            bool send_fin = false;
            control_out_ = server_session_ == nullptr
                               ? EncodeSessionError("missing server session")
                               : server_session_->HandleControlFrame(control_in_, &send_fin);
            control_fin_ = send_fin;
            SendMore();
        }
        return;
    }
    if (is_server_) {
        if (server_session_ == nullptr || !server_session_->SessionStarted()) {
            Reset(quic::QUIC_BAD_APPLICATION_PAYLOAD);
            return;
        }
        request_bytes_ = server_session_->RequestBytes();
        if (!server_session_->AllowsVariableBulkUpload() && request_received_ != request_bytes_) {
            Reset(quic::QUIC_BAD_APPLICATION_PAYLOAD);
            return;
        }
        response_bytes_ = server_session_->ResponseBytesForNextRequest();
        request_complete_ = true;
        SendMore();
        return;
    }

    if (response_received_ != response_bytes_) {
        FailClientStream("Google QUICHE stream received an unexpected response byte count");
        Reset(quic::QUIC_BAD_APPLICATION_PAYLOAD);
        return;
    }
    CompleteClientStream();
}

void PerfStream::SendControl() {
    while (control_sent_ < control_out_.size() && CanWriteNewData()) {
        size_t remaining = control_out_.size() - control_sent_;
        size_t chunk = std::min(remaining, kWriteChunkSize);
        bool send_fin = control_fin_ && control_sent_ + chunk == control_out_.size();
        WriteOrBufferData(absl::string_view(control_out_.data() + control_sent_, chunk), send_fin,
                          nullptr);
        control_sent_ += chunk;
        if (chunk == 0 || !CanWriteNewData()) {
            break;
        }
    }
}

void PerfStream::SendMore() {
    if (IsControl()) {
        SendControl();
        return;
    }
    if (is_server_) {
        while (request_complete_ && !response_fin_sent_ && CanWriteNewData()) {
            uint64_t remaining = response_bytes_ - response_sent_;
            size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, kWriteChunkSize));
            bool send_fin = chunk == remaining;
            WriteOrBufferData(ZeroChunk(chunk), send_fin, nullptr);
            response_sent_ += chunk;
            if (send_fin) {
                response_fin_sent_ = true;
            }
            if (chunk == 0 || !CanWriteNewData()) {
                break;
            }
        }
        return;
    }

    while (!request_fin_sent_ && CanWriteNewData()) {
        uint64_t remaining = request_bytes_ - request_sent_;
        size_t chunk = static_cast<size_t>(std::min<uint64_t>(remaining, kWriteChunkSize));
        bool send_fin = chunk == remaining;
        WriteOrBufferData(ZeroChunk(chunk), send_fin, nullptr);
        request_sent_ += chunk;
        if (send_fin) {
            request_fin_sent_ = true;
        }
        if (chunk == 0 || !CanWriteNewData()) {
            break;
        }
    }
}

void PerfStream::OnCanWriteNewData() {
    SendMore();
}

void PerfStream::OnStreamReset(const quic::QuicRstStreamFrame &frame) {
    if (!is_server_) {
        FailClientStream("Google QUICHE stream was reset");
    }
    quic::QuicStream::OnStreamReset(frame);
}

void PerfStream::CompleteClientStream() {
    if (client_done_) {
        return;
    }
    client_done_ = true;
    if (client_session_ != nullptr) {
        client_session_->OnStreamComplete(request_bytes_, response_received_, counts_, start_);
    }
}

void PerfStream::FailClientStream(std::string message) {
    if (client_done_) {
        return;
    }
    client_done_ = true;
    if (client_session_ != nullptr) {
        client_session_->OnStreamFailed(std::move(message));
    }
}

class PerfClient;

void CheckClient(const PerfClient &client);
std::vector<StreamCompletion> DriveClient(PerfClient *client);

class PerfClient : public quic::QuicClientBase {
  public:
    PerfClient(quic::QuicSocketAddress server_address, const quic::QuicServerId &server_id,
               const quic::ParsedQuicVersionVector &supported_versions,
               const quic::QuicConfig &config, quic::QuicEventLoop *event_loop,
               std::unique_ptr<quic::ProofVerifier> proof_verifier,
               std::unique_ptr<quic::SessionCache> session_cache)
        : quic::QuicClientBase(
              server_id, supported_versions, config, new quic::QuicDefaultConnectionHelper(),
              event_loop->CreateAlarmFactory().release(),
              std::make_unique<quic::QuicClientDefaultNetworkHelper>(event_loop, this),
              std::move(proof_verifier), std::move(session_cache)) {
        set_server_address(server_address);
        crypto_config()->set_alpn(kApplicationProtocol);
    }

    ~PerfClient() override {
        ResetSession();
    }

    PerfClientSession *perf_session() {
        return static_cast<PerfClientSession *>(session());
    }

    const PerfClientSession *perf_session() const {
        return static_cast<const PerfClientSession *>(session());
    }

    bool EarlyDataAccepted() override {
        return perf_session() != nullptr && perf_session()->EarlyDataAccepted();
    }

    bool ReceivedInchoateReject() override {
        return perf_session() != nullptr && perf_session()->ReceivedInchoateReject();
    }

  protected:
    int GetNumSentClientHellosFromSession() override {
        return perf_session() == nullptr ? 0 : perf_session()->GetNumSentClientHellos();
    }

    int GetNumReceivedServerConfigUpdatesFromSession() override {
        return perf_session() == nullptr ? 0 : perf_session()->GetNumReceivedServerConfigUpdates();
    }

    std::unique_ptr<quic::QuicSession>
    CreateQuicClientSession(const quic::ParsedQuicVersionVector &supported_versions,
                            quic::QuicConnection *connection) override {
        return std::make_unique<PerfClientSession>(connection, this, *config(), supported_versions,
                                                   server_id(), crypto_config());
    }

    bool HasActiveRequests() override {
        return perf_session() != nullptr && perf_session()->HasActiveRequests();
    }
};

class PerfDispatcher : public quic::QuicDispatcher {
  public:
    PerfDispatcher(const quic::QuicConfig *config,
                   const quic::QuicCryptoServerConfig *crypto_config,
                   quic::QuicVersionManager *version_manager,
                   std::unique_ptr<quic::QuicConnectionHelperInterface> helper,
                   std::unique_ptr<quic::QuicCryptoServerStreamBase::Helper> session_helper,
                   std::unique_ptr<quic::QuicAlarmFactory> alarm_factory,
                   uint8_t expected_server_connection_id_length,
                   quic::ConnectionIdGeneratorInterface &generator)
        : quic::QuicDispatcher(config, crypto_config, version_manager, std::move(helper),
                               std::move(session_helper), std::move(alarm_factory),
                               expected_server_connection_id_length, generator) {
    }

  protected:
    std::unique_ptr<quic::QuicSession>
    CreateQuicSession(quic::QuicConnectionId connection_id,
                      const quic::QuicSocketAddress &self_address,
                      const quic::QuicSocketAddress &peer_address, absl::string_view,
                      const quic::ParsedQuicVersion &version, const quic::ParsedClientHello &,
                      quic::ConnectionIdGeneratorInterface &connection_id_generator) override {
        quic::QuicConnection *connection = new quic::QuicConnection(
            connection_id, self_address, peer_address, helper(), alarm_factory(), writer(),
            /*owns_writer=*/false, quic::Perspective::IS_SERVER,
            quic::ParsedQuicVersionVector{version}, connection_id_generator);

        auto session = std::make_unique<PerfServerSession>(
            connection, this, config(), GetSupportedVersions(), crypto_config(),
            compressed_certs_cache(), session_helper());
        session->Initialize();
        return session;
    }
};

class PerfServer : public quic::QuicServer {
  public:
    PerfServer(std::unique_ptr<quic::ProofSource> proof_source,
               std::unique_ptr<quic::ProofVerifier> proof_verifier, const quic::QuicConfig &config,
               const quic::QuicCryptoServerConfig::ConfigOptions &crypto_config_options,
               const quic::ParsedQuicVersionVector &supported_versions,
               quic::QuicSimpleServerBackend *backend, uint8_t expected_server_connection_id_length)
        : quic::QuicServer(std::move(proof_source), std::move(proof_verifier), config,
                           crypto_config_options, supported_versions, backend,
                           expected_server_connection_id_length) {
    }

  protected:
    quic::QuicDispatcher *CreateQuicDispatcher() override {
        return new PerfDispatcher(&config(), &crypto_config(), version_manager(),
                                  std::make_unique<quic::QuicDefaultConnectionHelper>(),
                                  std::make_unique<quic::QuicSimpleCryptoServerStreamHelper>(),
                                  event_loop()->CreateAlarmFactory(),
                                  expected_server_connection_id_length(),
                                  connection_id_generator());
    }
};

std::unique_ptr<PerfClient>
ConnectClient(const Config &cfg, quic::QuicEventLoop *event_loop,
              std::unique_ptr<quic::SessionCache> session_cache = nullptr) {
    std::unique_ptr<quic::ProofVerifier> verifier =
        cfg.verify_peer ? quic::CreateDefaultProofVerifier(cfg.server_name)
                        : std::make_unique<quic::FakeProofVerifier>();
    if (verifier == nullptr) {
        throw std::runtime_error("google-quiche-perf could not create a peer certificate verifier");
    }
    auto client = std::make_unique<PerfClient>(
        ResolveRemote(cfg), quic::QuicServerId(cfg.server_name, cfg.port), SupportedVersions(),
        QuicConfigForPerf(), event_loop, std::move(verifier), std::move(session_cache));
    client->set_initial_max_packet_length(quic::kDefaultMaxPacketSize);
    if (!client->Initialize()) {
        throw std::runtime_error("failed to initialize Google QUICHE client");
    }
    if (!client->Connect()) {
        std::ostringstream error_message;
        error_message << "failed to connect Google QUICHE client: "
                      << quic::QuicErrorCodeToString(client->session()->error()) << " "
                      << client->session()->error_details();
        throw std::runtime_error(error_message.str());
    }
    Clock::time_point ready_deadline = Clock::now() + Duration(10'000'000);
    while (!client->perf_session()->session_ready() && Clock::now() < ready_deadline) {
        CheckClient(*client);
        if (!client->perf_session()->OpenControl(cfg)) {
            (void)DriveClient(client.get());
        } else {
            (void)DriveClient(client.get());
        }
    }
    CheckClient(*client);
    if (!client->perf_session()->session_ready()) {
        throw std::runtime_error("Google QUICHE session_ready timed out");
    }
    return client;
}

std::vector<std::unique_ptr<PerfClient>>
ConnectClients(const Config &cfg, quic::QuicEventLoop *event_loop, uint64_t count = 0) {
    std::vector<std::unique_ptr<PerfClient>> clients;
    if (count == 0) {
        count = cfg.connections;
    }
    clients.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        clients.push_back(ConnectClient(ConfigWithRrRequestLimit(cfg, i), event_loop));
    }
    return clients;
}

void CheckClient(const PerfClient &client) {
    const PerfClientSession *session = client.perf_session();
    if (session != nullptr && !session->error_message().empty()) {
        throw std::runtime_error(session->error_message());
    }
    if (!client.connected()) {
        std::ostringstream error_message;
        error_message << "Google QUICHE connection failed";
        if (client.session() != nullptr) {
            error_message << ": " << quic::QuicErrorCodeToString(client.session()->error()) << " "
                          << client.session()->error_details();
        }
        throw std::runtime_error(error_message.str());
    }
}

std::vector<StreamCompletion> DriveClient(PerfClient *client) {
    client->WaitForEvents();
    CheckClient(*client);
    return client->perf_session()->TakeCompletions();
}

void AddCompletion(const StreamCompletion &completion, Counters *counters, bool count_requests,
                   bool count_latency) {
    if (!completion.counts) {
        return;
    }
    counters->bytes_sent += completion.request_bytes;
    counters->bytes_received += completion.received;
    if (count_requests) {
        counters->requests_completed += 1;
    }
    if (count_latency) {
        counters->latencies.push_back(completion.latency);
    }
}

std::vector<StreamCompletion> OpenRequestOrThrow(PerfClient *client, uint64_t request_bytes,
                                                 uint64_t response_bytes, bool counts) {
    std::vector<StreamCompletion> completions;
    while (!client->perf_session()->OpenRequest(request_bytes, response_bytes, counts)) {
        for (const StreamCompletion &completion : DriveClient(client)) {
            completions.push_back(completion);
        }
    }
    CheckClient(*client);
    return completions;
}

void DrainClient(PerfClient *client) {
    Clock::time_point deadline = Clock::now() + kDrainTimeout;
    while (client->perf_session()->active_requests() > 0 && Clock::now() < deadline) {
        (void)DriveClient(client);
    }
}

void RunBulk(const Config &cfg, Counters *counters, quic::QuicEventLoop *event_loop) {
    uint64_t request_bytes = ScenarioRequestBytes(cfg);
    uint64_t response_bytes = ScenarioResponseBytes(cfg);
    auto clients = ConnectClients(cfg, event_loop);
    if (cfg.total_bytes.set) {
        uint64_t per_stream = cfg.total_bytes.value / cfg.streams;
        uint64_t remainder = cfg.total_bytes.value % cfg.streams;
        for (uint64_t i = 0; i < cfg.streams; ++i) {
            uint64_t target = per_stream + (i < remainder ? 1 : 0);
            PerfClient *client = clients[static_cast<size_t>(i % clients.size())].get();
            for (const StreamCompletion &completion :
                 OpenRequestOrThrow(client, cfg.direction == "upload" ? target : request_bytes,
                                    cfg.direction == "upload" ? response_bytes : target, true)) {
                AddCompletion(completion, counters, false, false);
            }
        }
        while (std::any_of(clients.begin(), clients.end(), [](const auto &client) {
            return client->perf_session()->active_requests() > 0;
        })) {
            for (auto &client : clients) {
                for (const StreamCompletion &completion : DriveClient(client.get())) {
                    AddCompletion(completion, counters, false, false);
                }
            }
        }
        return;
    }

    Clock::time_point measure_start = Clock::now() + cfg.warmup;
    Clock::time_point deadline = measure_start + cfg.duration;
    for (auto &client : clients) {
        for (uint64_t i = 0; i < cfg.streams; ++i) {
            for (const StreamCompletion &completion : OpenRequestOrThrow(
                     client.get(), request_bytes, response_bytes, Clock::now() >= measure_start)) {
                AddCompletion(completion, counters, false, false);
            }
        }
    }
    while (Clock::now() < deadline) {
        for (auto &client : clients) {
            for (const StreamCompletion &completion : DriveClient(client.get())) {
                AddCompletion(completion, counters, false, false);
            }
        }
        for (auto &client : clients) {
            while (client->perf_session()->active_requests() < cfg.streams &&
                   Clock::now() < deadline) {
                for (const StreamCompletion &completion :
                     OpenRequestOrThrow(client.get(), request_bytes, response_bytes,
                                        Clock::now() >= measure_start)) {
                    AddCompletion(completion, counters, false, false);
                }
            }
        }
    }
    for (auto &client : clients) {
        DrainClient(client.get());
    }
}

void RunRr(const Config &cfg, Counters *counters, quic::QuicEventLoop *event_loop) {
    auto clients = ConnectClients(cfg, event_loop, RrConnectionTarget(cfg));
    Clock::time_point measure_start = Clock::now() + cfg.warmup;
    Clock::time_point deadline = measure_start + cfg.duration;
    uint64_t started = 0;
    std::vector<uint64_t> started_by_connection(clients.size(), 0);
    for (size_t index = 0; index < clients.size(); ++index) {
        auto &client = clients[index];
        while (client->perf_session()->active_requests() < cfg.requests_in_flight) {
            if (!CanStartRrRequest(cfg, started, started_by_connection, index)) {
                break;
            }
            for (const StreamCompletion &completion :
                 OpenRequestOrThrow(client.get(), cfg.request_bytes, cfg.response_bytes,
                                    cfg.requests.set || Clock::now() >= measure_start)) {
                AddCompletion(completion, counters, true, true);
            }
            ++started;
            ++started_by_connection[index];
        }
    }

    for (;;) {
        if (cfg.requests.set && started >= cfg.requests.value &&
            std::all_of(clients.begin(), clients.end(), [](const auto &client) {
                return client->perf_session()->active_requests() == 0;
            })) {
            break;
        }
        if (!cfg.requests.set && Clock::now() >= deadline) {
            break;
        }

        for (auto &client : clients) {
            for (const StreamCompletion &completion : DriveClient(client.get())) {
                AddCompletion(completion, counters, true, true);
            }
        }

        for (size_t index = 0; index < clients.size(); ++index) {
            auto &client = clients[index];
            while (client->perf_session()->active_requests() < cfg.requests_in_flight) {
                if (!CanStartRrRequest(cfg, started, started_by_connection, index)) {
                    break;
                }
                if (!cfg.requests.set && Clock::now() >= deadline) {
                    break;
                }
                for (const StreamCompletion &completion :
                     OpenRequestOrThrow(client.get(), cfg.request_bytes, cfg.response_bytes,
                                        cfg.requests.set || Clock::now() >= measure_start)) {
                    AddCompletion(completion, counters, true, true);
                }
                ++started;
                ++started_by_connection[index];
            }
        }
    }
    for (auto &client : clients) {
        DrainClient(client.get());
    }
}

struct CrrClient {
    std::unique_ptr<PerfClient> client;
    bool request_opened = false;
    bool counts = false;
};

void FillCrrClients(const Config &cfg, Counters *counters, quic::QuicEventLoop *event_loop,
                    Clock::time_point measure_start, Clock::time_point deadline, uint64_t *started,
                    std::vector<CrrClient> *clients) {
    while (clients->size() < cfg.connections) {
        if (cfg.requests.set && *started >= cfg.requests.value) {
            break;
        }
        if (!cfg.requests.set && Clock::now() >= deadline) {
            break;
        }
        try {
            std::unique_ptr<quic::SessionCache> session_cache;
            if (!cfg.requests.set) {
                session_cache = std::make_unique<quic::QuicClientSessionCache>();
            }
            auto client = ConnectClient(cfg, event_loop, std::move(session_cache));
            bool counts = cfg.requests.set || Clock::now() >= measure_start;
            clients->push_back({std::move(client), false, counts});
            ++*started;
        } catch (const std::exception &) {
            if (cfg.requests.set) {
                throw;
            }
            counters->skipped_setup_errors += 1;
        }
    }
}

void RunCrr(const Config &cfg, Counters *counters, quic::QuicEventLoop *event_loop) {
    Clock::time_point measure_start = Clock::now() + cfg.warmup;
    Clock::time_point run_deadline = measure_start + cfg.duration;
    uint64_t started = 0;
    std::vector<CrrClient> clients;
    clients.reserve(
        static_cast<size_t>(std::min<uint64_t>(cfg.connections, kDefaultMaxRunRequests)));
    FillCrrClients(cfg, counters, event_loop, measure_start, run_deadline, &started, &clients);

    while (!clients.empty() || (cfg.requests.set && started < cfg.requests.value) ||
           (!cfg.requests.set && Clock::now() < run_deadline)) {
        size_t index = 0;
        while (index < clients.size()) {
            CrrClient &entry = clients[index];
            if (!entry.request_opened && entry.client->connected()) {
                for (const StreamCompletion &completion : OpenRequestOrThrow(
                         entry.client.get(), cfg.request_bytes, cfg.response_bytes, entry.counts)) {
                    AddCompletion(completion, counters, true, true);
                }
                entry.request_opened = true;
            }
            for (const StreamCompletion &completion : DriveClient(entry.client.get())) {
                AddCompletion(completion, counters, true, true);
            }
            if (entry.request_opened && entry.client->perf_session()->active_requests() == 0) {
                clients.erase(clients.begin() + static_cast<std::ptrdiff_t>(index));
                continue;
            }
            ++index;
        }
        FillCrrClients(cfg, counters, event_loop, measure_start, run_deadline, &started, &clients);
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
    Duration elapsed;
    if (cfg.requests.set || cfg.total_bytes.set) {
        elapsed = std::chrono::duration_cast<Duration>(Clock::now() - start);
    } else {
        Duration raw_elapsed = std::chrono::duration_cast<Duration>(Clock::now() - measure_start);
        elapsed = raw_elapsed > cfg.warmup ? raw_elapsed - cfg.warmup : Duration::zero();
    }
    return MakeSummary(cfg, std::move(counters), elapsed, failure.empty() ? "ok" : "failed",
                       std::move(failure));
}

int RunServer(const Config &cfg) {
    quiche::QuicheSystemEventLoop system_loop("google-quiche-perf-server");
    auto backend = std::make_unique<quic::QuicMemoryCacheBackend>();
    PerfServer server(LoadProofSource(cfg), nullptr, QuicConfigForPerf(),
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
    std::string json_string = "\"";
    for (char ch : value) {
        switch (ch) {
        case '"':
            json_string += "\\\"";
            break;
        case '\\':
            json_string += "\\\\";
            break;
        case '\n':
            json_string += "\\n";
            break;
        case '\r':
            json_string += "\\r";
            break;
        case '\t':
            json_string += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", ch);
                json_string += buf;
            } else {
                json_string += ch;
            }
            break;
        }
    }
    json_string += "\"";
    return json_string;
}

void WriteSummaryJson(std::ostream &summary_stream, const RunSummary &summary) {
    const Config &cfg = *summary.cfg;
    summary_stream << "{\n";
    summary_stream << "  \"schema_version\": 1,\n";
    summary_stream << "  \"status\": " << JsonString(summary.status) << ",\n";
    if (!summary.failure_reason.empty()) {
        summary_stream << "  \"failure_reason\": " << JsonString(summary.failure_reason) << ",\n";
    }
    summary_stream << "  \"mode\": " << JsonString(cfg.mode) << ",\n";
    summary_stream << "  \"direction\": " << JsonString(cfg.direction) << ",\n";
    summary_stream << "  \"backend\": " << JsonString(cfg.io_backend) << ",\n";
    summary_stream << "  \"congestion_control\": " << JsonString(cfg.congestion_control) << ",\n";
    summary_stream << "  \"remote_host\": " << JsonString(cfg.host) << ",\n";
    summary_stream << "  \"remote_port\": " << cfg.port << ",\n";
    summary_stream << "  \"alpn\": " << JsonString(kApplicationProtocol) << ",\n";
    summary_stream << "  \"elapsed_ms\": " << summary.elapsed_ms << ",\n";
    summary_stream << "  \"warmup_ms\": " << DurationMillis(cfg.warmup) << ",\n";
    summary_stream << "  \"bytes_sent\": " << summary.counters.bytes_sent << ",\n";
    summary_stream << "  \"bytes_received\": " << summary.counters.bytes_received << ",\n";
    summary_stream << "  \"server_counters\": {\n";
    summary_stream << "    \"bytes_sent\": " << summary.counters.bytes_received << ",\n";
    summary_stream << "    \"bytes_received\": " << summary.counters.bytes_sent << ",\n";
    summary_stream << "    \"requests_completed\": " << summary.counters.requests_completed << "\n";
    summary_stream << "  },\n";
    summary_stream << "  \"requests_completed\": " << summary.counters.requests_completed << ",\n";
    if (summary.counters.skipped_setup_errors != 0) {
        summary_stream << "  \"skipped_setup_errors\": " << summary.counters.skipped_setup_errors
                       << ",\n";
    }
    summary_stream << "  \"streams\": " << cfg.streams << ",\n";
    summary_stream << "  \"connections\": " << cfg.connections << ",\n";
    summary_stream << "  \"requests_in_flight\": " << cfg.requests_in_flight << ",\n";
    summary_stream << "  \"request_bytes\": " << cfg.request_bytes << ",\n";
    summary_stream << "  \"response_bytes\": " << cfg.response_bytes << ",\n";
    summary_stream << "  \"throughput_mib_per_s\": " << summary.throughput_mib_per_s << ",\n";
    summary_stream << "  \"throughput_gbit_per_s\": " << summary.throughput_gbit_per_s << ",\n";
    summary_stream << "  \"requests_per_s\": " << summary.requests_per_s << ",\n";
    summary_stream << "  \"latency\": {\n";
    summary_stream << "    \"min_us\": " << summary.latency.min_us << ",\n";
    summary_stream << "    \"avg_us\": " << summary.latency.avg_us << ",\n";
    summary_stream << "    \"p50_us\": " << summary.latency.p50_us << ",\n";
    summary_stream << "    \"p90_us\": " << summary.latency.p90_us << ",\n";
    summary_stream << "    \"p99_us\": " << summary.latency.p99_us << ",\n";
    summary_stream << "    \"max_us\": " << summary.latency.max_us << "\n";
    summary_stream << "  }\n";
    summary_stream << "}\n";
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

} // namespace coquic::bench::google_quiche_perf

int main(int argc, char **argv) {
    using namespace coquic::bench::google_quiche_perf;

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
