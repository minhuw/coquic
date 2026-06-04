#include "bench/coquic-perf/perf_runtime.h"

#include "bench/coquic-perf/perf_server.h"
#include "bench/coquic-perf/perf_client.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <iostream>
#include <limits>
#include <string_view>

namespace coquic::perf {
namespace {
constexpr std::size_t kPerfMinimumUdpPayloadSize = 1200;
constexpr std::uint64_t kPerfTransferConnectionReceiveWindow = 32ull * 1024ull * 1024ull;
constexpr std::uint64_t kPerfTransferStreamReceiveWindow = 16ull * 1024ull * 1024ull;
constexpr std::uint64_t kPerfAckElicitingThreshold = 2;
constexpr std::uint64_t kPerfCopaBulkAckElicitingThreshold = 1;
constexpr std::uint64_t kPerfCopaInteractiveAckElicitingThreshold = 8;
constexpr std::string_view kPerfUsageLine =
    "usage: coquic-perf [server|client] [--host HOST] [--port PORT] "
    "[--io-backend socket|io_uring] [--congestion-control newreno|cubic|bbr|copa] "
    "[--mode bulk|rr|crr] "
    "[--direction upload|download] [--request-bytes N] [--response-bytes N] "
    "[--streams N] [--connections N] [--requests-in-flight N] [--requests N] "
    "[--total-bytes N] [--warmup 250ms|2s] [--duration 250ms|2s] "
    "[--max-outbound-datagram-size N] [--pmtud-max-datagram-size N] "
    "[--certificate-chain PATH] [--private-key PATH] [--server-name NAME] "
    "[--verify-peer] [--json-out PATH]";

void print_usage() {
    std::cerr << kPerfUsageLine << '\n';
}

std::string read_text_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::optional<std::size_t> parse_size_arg(std::string_view value) {
    std::size_t parsed = 0;
    const auto *begin = value.data();
    const auto *end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<quic::QuicCoreDuration> parse_duration_arg(std::string_view value) {
    if (value.ends_with("ms")) {
        const auto count = parse_size_arg(value.substr(0, value.size() - 2));
        if (!count.has_value()) {
            return std::nullopt;
        }
        if (*count > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max() / 1000)) {
            return std::nullopt;
        }
        return quic::QuicCoreDuration{static_cast<std::int64_t>(*count * 1000)};
    }
    if (value.ends_with('s')) {
        const auto count = parse_size_arg(value.substr(0, value.size() - 1));
        if (!count.has_value()) {
            return std::nullopt;
        }
        if (*count > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max() / 1000000)) {
            return std::nullopt;
        }
        return quic::QuicCoreDuration{static_cast<std::int64_t>(*count * 1000000)};
    }
    return std::nullopt;
}

std::optional<QuicPerfMode> parse_mode_arg(std::string_view value) {
    if (value == "bulk") {
        return QuicPerfMode::bulk;
    }
    if (value == "rr") {
        return QuicPerfMode::rr;
    }
    if (value == "crr") {
        return QuicPerfMode::crr;
    }
    return std::nullopt;
}

std::optional<QuicPerfDirection> parse_direction_arg(std::string_view value) {
    if (value == "upload") {
        return QuicPerfDirection::upload;
    }
    if (value == "download") {
        return QuicPerfDirection::download;
    }
    return std::nullopt;
}

constexpr std::uint64_t kPerfServerInitialMaxBidirectionalStreams = 4096;

} // namespace

std::optional<QuicPerfConfig> parse_perf_runtime_args(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return std::nullopt;
    }

    QuicPerfConfig config;
    bool saw_direction = false;

    // The first positional argument selects which side of the perf protocol to run.
    const std::string_view role = argv[1];
    if (role == "server") {
        config.role = QuicPerfRole::server;
    } else if (role == "client") {
        config.role = QuicPerfRole::client;
    } else {
        print_usage();
        return std::nullopt;
    }

    int index = 2;
    while (index < argc) {
        // Options below share this helper so missing values report usage consistently.
        const std::string_view arg = argv[index++];
        auto require_value = [&](std::string_view) -> std::optional<std::string_view> {
            if (index >= argc) {
                print_usage();
                return std::nullopt;
            }
            return std::string_view(argv[index++]);
        };

        if (arg == "--verify-peer") {
            config.verify_peer = true;
            continue;
        }
        if (arg == "--host") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.host = std::string(*value);
            continue;
        }
        if (arg == "--port") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value() || *parsed > 65535u) {
                print_usage();
                return std::nullopt;
            }
            config.port = static_cast<std::uint16_t>(*parsed);
            continue;
        }
        if (arg == "--io-backend") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            // Backend names map to the portable socket path or the Linux io_uring path.
            if (*value == "socket") {
                config.io_backend = io::QuicIoBackendKind::socket;
            } else if (*value == "io_uring") {
                config.io_backend = io::QuicIoBackendKind::io_uring;
            } else {
                print_usage();
                return std::nullopt;
            }
            continue;
        }
        if (arg == "--congestion-control") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = quic::parse_congestion_control_algorithm(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.congestion_control = *parsed;
            continue;
        }
        if (arg == "--mode") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_mode_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.mode = *parsed;
            continue;
        }
        if (arg == "--direction") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_direction_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            saw_direction = true;
            config.direction = *parsed;
            continue;
        }
        // Payload, stream, connection, and request counts are parsed as byte-size style numbers.
        if (arg == "--request-bytes") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.request_bytes = *parsed;
            continue;
        }
        if (arg == "--response-bytes") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.response_bytes = *parsed;
            continue;
        }
        if (arg == "--streams") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.streams = *parsed;
            continue;
        }
        if (arg == "--connections") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.connections = *parsed;
            continue;
        }
        if (arg == "--requests-in-flight") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.requests_in_flight = *parsed;
            continue;
        }
        if (arg == "--requests") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.requests = parsed;
            continue;
        }
        if (arg == "--total-bytes") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.total_bytes = parsed;
            continue;
        }
        if (arg == "--max-outbound-datagram-size") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value() || *parsed < kPerfMinimumUdpPayloadSize) {
                print_usage();
                return std::nullopt;
            }
            config.max_outbound_datagram_size = *parsed;
            continue;
        }
        if (arg == "--pmtud-max-datagram-size") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_size_arg(*value);
            if (!parsed.has_value() || (*parsed != 0 && *parsed < kPerfMinimumUdpPayloadSize)) {
                print_usage();
                return std::nullopt;
            }
            config.pmtud_max_datagram_size = *parsed;
            continue;
        }
        // Warmup and duration accept the same duration suffixes used by perf reports.
        if (arg == "--warmup") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_duration_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.warmup = *parsed;
            continue;
        }
        if (arg == "--duration") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_duration_arg(*value);
            if (!parsed.has_value()) {
                print_usage();
                return std::nullopt;
            }
            config.duration = *parsed;
            continue;
        }
        // TLS identity and peer-name options are carried through to runtime setup unchanged.
        if (arg == "--certificate-chain") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.certificate_chain_path = std::string(*value);
            continue;
        }
        if (arg == "--private-key") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.private_key_path = std::string(*value);
            continue;
        }
        if (arg == "--server-name") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.server_name = std::string(*value);
            continue;
        }
        if (arg == "--json-out") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.json_out = std::filesystem::path(std::string(*value));
            continue;
        }

        print_usage();
        return std::nullopt;
    }

    // Final cross-option checks reject combinations that cannot run a valid perf session.
    if (config.mode != QuicPerfMode::bulk && saw_direction) {
        print_usage();
        return std::nullopt;
    }
    if (config.streams == 0 || config.connections == 0 || config.requests_in_flight == 0) {
        print_usage();
        return std::nullopt;
    }
    return config;
}

std::uint64_t perf_ack_eliciting_threshold(const QuicPerfConfig &config) {
    if (config.congestion_control == quic::QuicCongestionControlAlgorithm::copa) {
        return config.mode == QuicPerfMode::bulk ? kPerfCopaBulkAckElicitingThreshold
                                                 : kPerfCopaInteractiveAckElicitingThreshold;
    }
    return kPerfAckElicitingThreshold;
}

bool perf_enable_hystart_plus_plus(const QuicPerfConfig &config) {
    if (config.mode != QuicPerfMode::bulk) {
        return true;
    }
    return config.congestion_control != quic::QuicCongestionControlAlgorithm::newreno &&
           config.congestion_control != quic::QuicCongestionControlAlgorithm::cubic;
}

bool perf_send_stream_fairness(const QuicPerfConfig &config) {
    return config.mode != QuicPerfMode::bulk;
}

int run_perf_runtime(const QuicPerfConfig &config) {
    if (config.role == QuicPerfRole::server) {
        return run_perf_server(config);
    }

    return run_perf_client(config);
}

quic::QuicCoreEndpointConfig make_perf_client_endpoint_config(const QuicPerfConfig &config) {
    auto endpoint_config = quic::QuicCoreEndpointConfig{
        .role = quic::EndpointRole::client,
        .verify_peer = config.verify_peer,
        .application_protocol = "coquic-perf/1",
        .max_outbound_datagram_size = config.max_outbound_datagram_size,
    };
    endpoint_config.emit_shared_receive_stream_data = true;
    endpoint_config.transport.congestion_control = config.congestion_control;
    endpoint_config.transport.enable_hystart_plus_plus = perf_enable_hystart_plus_plus(config);
    endpoint_config.transport.send_stream_fairness = perf_send_stream_fairness(config);
    endpoint_config.transport.ack_eliciting_threshold = perf_ack_eliciting_threshold(config);
    endpoint_config.transport.pmtud_max_datagram_size = config.pmtud_max_datagram_size;
    endpoint_config.transport.initial_max_data = kPerfTransferConnectionReceiveWindow;
    endpoint_config.transport.initial_max_stream_data_bidi_local = kPerfTransferStreamReceiveWindow;
    endpoint_config.transport.initial_max_stream_data_bidi_remote =
        kPerfTransferStreamReceiveWindow;
    return endpoint_config;
}

quic::QuicCoreEndpointConfig make_perf_server_endpoint_config(const QuicPerfConfig &config) {
    auto endpoint_config = quic::QuicCoreEndpointConfig{
        .role = quic::EndpointRole::server,
        .verify_peer = config.verify_peer,
        .application_protocol = "coquic-perf/1",
        .identity =
            quic::TlsIdentity{
                .certificate_pem = read_text_file(config.certificate_chain_path),
                .private_key_pem = read_text_file(config.private_key_path),
            },
    };
    endpoint_config.emit_shared_receive_stream_data = true;
    endpoint_config.max_outbound_datagram_size = config.max_outbound_datagram_size;
    endpoint_config.transport.congestion_control = config.congestion_control;
    endpoint_config.transport.enable_hystart_plus_plus = perf_enable_hystart_plus_plus(config);
    endpoint_config.transport.send_stream_fairness = perf_send_stream_fairness(config);
    endpoint_config.transport.ack_eliciting_threshold = perf_ack_eliciting_threshold(config);
    endpoint_config.transport.pmtud_max_datagram_size = config.pmtud_max_datagram_size;
    endpoint_config.transport.initial_max_data = kPerfTransferConnectionReceiveWindow;
    endpoint_config.transport.initial_max_stream_data_bidi_local = kPerfTransferStreamReceiveWindow;
    endpoint_config.transport.initial_max_stream_data_bidi_remote =
        kPerfTransferStreamReceiveWindow;
    endpoint_config.transport.initial_max_streams_bidi =
        std::max(endpoint_config.transport.initial_max_streams_bidi,
                 kPerfServerInitialMaxBidirectionalStreams);
    return endpoint_config;
}

} // namespace coquic::perf
