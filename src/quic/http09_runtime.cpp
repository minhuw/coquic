#include "src/quic/http09_runtime.h"
#include "src/quic/packet.h"

#include "src/coquic.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>

namespace coquic::quic {
namespace {

constexpr std::size_t kMaxDatagramBytes = 65535;
constexpr std::size_t kMinimumClientInitialDatagramBytes = 1200;
constexpr std::size_t kRuntimeConnectionIdLength = 8;
constexpr int kClientReceiveTimeoutMs = 30000;
constexpr int kServerIdleTimeoutMs = 1000;
constexpr std::uint32_t kQuicVersion1 = 1;
constexpr std::uint32_t kVersionNegotiationVersion = 0;
constexpr std::string_view kInteropApplicationProtocol = "hq-interop";
constexpr std::string_view kUsageLine =
    "usage: coquic [interop-server|interop-client] [--host HOST] [--port PORT] "
    "[--testcase handshake|transfer|multiconnect] [--requests URLS] [--document-root PATH] "
    "[--download-root PATH] [--certificate-chain PATH] [--private-key PATH] "
    "[--server-name NAME] [--verify-peer]";

class ScopedFd {
  public:
    explicit ScopedFd(int fd) : fd_(fd) {
    }

    ~ScopedFd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

    int get() const {
        return fd_;
    }

  private:
    int fd_ = -1;
};

QuicCoreTimePoint now() {
    return QuicCoreClock::now();
}

std::optional<std::string> getenv_string(const char *name) {
    const char *value = std::getenv(name);
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string(value);
}

std::string read_text_file(const std::filesystem::path &path) {
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::optional<std::string> read_required_text_file(const std::filesystem::path &path,
                                                   std::string_view label) {
    auto content = read_text_file(path);
    if (!content.empty()) {
        return content;
    }

    std::cerr << "http09-server failed: unable to load required TLS " << label << " '"
              << path.string() << "'\n";
    return std::nullopt;
}

std::optional<std::uint16_t> parse_port(std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }

    unsigned long parsed = 0;
    for (const char ch : value) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        parsed = (parsed * 10u) + static_cast<unsigned long>(ch - '0');
        if (parsed > 65535u) {
            return std::nullopt;
        }
    }

    return static_cast<std::uint16_t>(parsed);
}

std::optional<QuicHttp09Testcase> parse_testcase(std::string_view value) {
    if (value == "handshake") {
        return QuicHttp09Testcase::handshake;
    }
    if (value == "transfer") {
        return QuicHttp09Testcase::transfer;
    }
    if (value == "multiconnect") {
        return QuicHttp09Testcase::multiconnect;
    }
    return std::nullopt;
}

bool parse_role_into(Http09RuntimeConfig &config, std::string_view role) {
    if (role == "server") {
        config.mode = Http09RuntimeMode::server;
        return true;
    }
    if (role == "client") {
        config.mode = Http09RuntimeMode::client;
        return true;
    }
    return false;
}

bool make_ipv4_address(std::string_view host, std::uint16_t port, sockaddr_in &address) {
    address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    return ::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) == 1;
}

struct ParsedHttp09Authority {
    std::string host;
    std::optional<std::uint16_t> port;
};

std::optional<ParsedHttp09Authority> parse_http09_authority(std::string_view authority) {
    if (authority.empty()) {
        return std::nullopt;
    }

    ParsedHttp09Authority parsed;
    if (authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string_view::npos || closing == 1) {
            return std::nullopt;
        }
        parsed.host = std::string(authority.substr(1, closing - 1));
        const auto suffix = authority.substr(closing + 1);
        if (suffix.empty()) {
            return parsed;
        }
        if (!suffix.starts_with(':')) {
            return std::nullopt;
        }
        const auto parsed_port = parse_port(suffix.substr(1));
        if (!parsed_port.has_value()) {
            return std::nullopt;
        }
        parsed.port = parsed_port;
        return parsed;
    }

    const auto first_colon = authority.find(':');
    const auto last_colon = authority.rfind(':');
    if (first_colon != std::string_view::npos && first_colon == last_colon) {
        parsed.host = std::string(authority.substr(0, first_colon));
        const auto parsed_port = parse_port(authority.substr(first_colon + 1));
        if (parsed.host.empty() || !parsed_port.has_value()) {
            return std::nullopt;
        }
        parsed.port = parsed_port;
        return parsed;
    }

    parsed.host = std::string(authority);
    if (parsed.host.empty()) {
        return std::nullopt;
    }
    return parsed;
}

struct Http09ClientRemote {
    std::string host;
    std::uint16_t port = 443;
    std::string server_name;
};

std::optional<Http09ClientRemote>
derive_http09_client_remote(const Http09RuntimeConfig &config,
                            const std::vector<QuicHttp09Request> &requests) {
    Http09ClientRemote remote{
        .host = config.host,
        .port = config.port,
        .server_name = config.server_name,
    };

    if (!remote.host.empty() && !remote.server_name.empty()) {
        return remote;
    }

    if (requests.empty()) {
        return std::nullopt;
    }

    const auto parsed_authority = parse_http09_authority(requests.front().authority);
    if (!parsed_authority.has_value()) {
        return std::nullopt;
    }

    if (remote.host.empty()) {
        remote.host = parsed_authority->host;
        if (parsed_authority->port.has_value()) {
            remote.port = *parsed_authority->port;
        }
    }

    if (remote.server_name.empty()) {
        remote.server_name = parsed_authority->host;
    }

    return remote;
}

bool resolve_udp_peer_ipv4(std::string_view host, std::uint16_t port, sockaddr_in &address) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;

    addrinfo *results = nullptr;
    const auto service = std::to_string(port);
    const int status = ::getaddrinfo(std::string(host).c_str(), service.c_str(), &hints, &results);
    if (status != 0 || results == nullptr) {
        if (results != nullptr) {
            ::freeaddrinfo(results);
        }
        return false;
    }

    address = *reinterpret_cast<sockaddr_in *>(results->ai_addr);
    ::freeaddrinfo(results);
    return true;
}

int open_udp_socket() {
    return ::socket(AF_INET, SOCK_DGRAM, 0);
}

QuicCoreConfig make_http09_server_core_config_with_identity(const Http09RuntimeConfig &config,
                                                            TlsIdentity identity) {
    return QuicCoreConfig{
        .role = EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .verify_peer = config.verify_peer,
        .server_name = config.server_name,
        .application_protocol = std::string(kInteropApplicationProtocol),
        .identity = std::move(identity),
    };
}

bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name);

ConnectionId make_runtime_connection_id(std::byte prefix, std::uint64_t sequence) {
    ConnectionId connection_id(kRuntimeConnectionIdLength, std::byte{0x00});
    connection_id.front() = prefix;
    for (std::size_t index = 1; index < connection_id.size(); ++index) {
        const auto shift = static_cast<unsigned>((connection_id.size() - 1 - index) * 8);
        connection_id[index] = static_cast<std::byte>((sequence >> shift) & 0xffu);
    }
    return connection_id;
}

std::string connection_id_key(std::span<const std::byte> connection_id) {
    if (connection_id.empty()) {
        return {};
    }
    return std::string(reinterpret_cast<const char *>(connection_id.data()), connection_id.size());
}

std::uint32_t read_u32_be_at(std::span<const std::byte> bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset])) << 24) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 1])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 2])) << 8) |
           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + 3]));
}

struct ParsedServerDatagram {
    enum class Kind : std::uint8_t {
        short_header,
        supported_initial,
        supported_long_header,
        unsupported_version_long_header,
    };

    Kind kind;
    ConnectionId destination_connection_id;
    std::optional<ConnectionId> source_connection_id;
};

std::optional<ParsedServerDatagram>
parse_server_datagram_for_routing(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }

    const auto first_byte = std::to_integer<std::uint8_t>(bytes.front());
    if ((first_byte & 0x80u) == 0) {
        if ((first_byte & 0x40u) == 0 || bytes.size() < 1 + kRuntimeConnectionIdLength) {
            return std::nullopt;
        }

        return ParsedServerDatagram{
            .kind = ParsedServerDatagram::Kind::short_header,
            .destination_connection_id =
                ConnectionId(bytes.begin() + 1, bytes.begin() + 1 + kRuntimeConnectionIdLength),
            .source_connection_id = std::nullopt,
        };
    }

    if ((first_byte & 0x40u) == 0 || bytes.size() < 7) {
        return std::nullopt;
    }

    const auto version = read_u32_be_at(bytes, 1);
    if (version == kVersionNegotiationVersion) {
        return std::nullopt;
    }

    std::size_t offset = 5;
    const auto destination_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset++]));
    if (offset + destination_connection_id_length + 1 > bytes.size()) {
        return std::nullopt;
    }
    ConnectionId destination_connection_id(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + destination_connection_id_length));
    offset += destination_connection_id_length;

    const auto source_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset++]));
    if (offset + source_connection_id_length > bytes.size()) {
        return std::nullopt;
    }
    ConnectionId source_connection_id(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + source_connection_id_length));

    if (version != kQuicVersion1) {
        return ParsedServerDatagram{
            .kind = ParsedServerDatagram::Kind::unsupported_version_long_header,
            .destination_connection_id = std::move(destination_connection_id),
            .source_connection_id = std::move(source_connection_id),
        };
    }

    const auto type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    return ParsedServerDatagram{
        .kind = type == 0x00 ? ParsedServerDatagram::Kind::supported_initial
                             : ParsedServerDatagram::Kind::supported_long_header,
        .destination_connection_id = std::move(destination_connection_id),
        .source_connection_id = std::move(source_connection_id),
    };
}

bool send_version_negotiation_for_probe(int fd, std::span<const std::byte> datagram,
                                        const sockaddr_storage &peer, socklen_t peer_len) {
    if (datagram.size() < kMinimumClientInitialDatagramBytes) {
        return true;
    }

    const auto parsed = parse_server_datagram_for_routing(datagram);
    if (!parsed.has_value() ||
        parsed->kind != ParsedServerDatagram::Kind::unsupported_version_long_header ||
        !parsed->source_connection_id.has_value()) {
        return true;
    }

    const auto packet = VersionNegotiationPacket{
        .destination_connection_id = *parsed->source_connection_id,
        .source_connection_id = parsed->destination_connection_id,
        .supported_versions = {kQuicVersion1},
    };
    const auto encoded = serialize_packet(packet);
    if (!encoded.has_value()) {
        std::cerr << "http09-server failed: unable to serialize Version Negotiation packet\n";
        return false;
    }

    return send_datagram(fd, encoded.value(), peer, peer_len, "server");
}

bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name) {
    const auto *buffer =
        datagram.empty() ? nullptr : reinterpret_cast<const void *>(datagram.data());
    const ssize_t sent = ::sendto(fd, buffer, datagram.size(), 0,
                                  reinterpret_cast<const sockaddr *>(&peer), peer_len);
    if (sent >= 0) {
        return true;
    }

    std::cerr << "http09-" << role_name << " failed: sendto error: " << std::strerror(errno)
              << '\n';
    return false;
}

struct RuntimeWaitStep {
    std::optional<QuicCoreInput> input;
    QuicCoreTimePoint input_time;
    sockaddr_storage source{};
    socklen_t source_len = 0;
    bool has_source = false;
    bool idle_timeout = false;
};

struct RuntimeWaitConfig {
    int socket_fd = -1;
    int idle_timeout_ms = 0;
    std::string_view role_name;
};

std::optional<RuntimeWaitStep>
wait_for_socket_or_deadline(const RuntimeWaitConfig &config,
                            const std::optional<QuicCoreTimePoint> &next_wakeup) {
    const auto current = now();
    int timeout_ms = config.idle_timeout_ms;
    bool timer_due = false;
    if (next_wakeup.has_value()) {
        if (*next_wakeup <= current) {
            timer_due = true;
            timeout_ms = 0;
        } else {
            const auto remaining = *next_wakeup - current;
            timeout_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                              remaining + std::chrono::milliseconds(1))
                                              .count());
            if (timeout_ms < 1) {
                timeout_ms = 1;
            }
        }
    }

    pollfd descriptor{};
    descriptor.fd = config.socket_fd;
    descriptor.events = POLLIN;

    int poll_result = 0;
    do {
        poll_result = ::poll(&descriptor, 1, timeout_ms);
    } while (poll_result < 0 && errno == EINTR);

    if (poll_result < 0) {
        std::cerr << "http09-" << config.role_name
                  << " failed: poll error: " << std::strerror(errno) << '\n';
        return std::nullopt;
    }

    if (poll_result == 0) {
        if (next_wakeup.has_value()) {
            return RuntimeWaitStep{
                .input = QuicCoreTimerExpired{},
                .input_time = timer_due ? current : now(),
            };
        }

        return RuntimeWaitStep{
            .input_time = now(),
            .idle_timeout = true,
        };
    }

    if ((descriptor.revents & POLLIN) == 0) {
        std::cerr << "http09-" << config.role_name << " failed: socket became unreadable\n";
        return std::nullopt;
    }

    std::vector<std::byte> inbound(kMaxDatagramBytes);
    sockaddr_storage source{};
    socklen_t source_len = sizeof(source);
    ssize_t bytes_read = 0;
    do {
        bytes_read = ::recvfrom(config.socket_fd, inbound.data(), inbound.size(), 0,
                                reinterpret_cast<sockaddr *>(&source), &source_len);
    } while (bytes_read < 0 && errno == EINTR);

    if (bytes_read < 0) {
        std::cerr << "http09-" << config.role_name
                  << " failed: recvfrom error: " << std::strerror(errno) << '\n';
        return std::nullopt;
    }

    inbound.resize(static_cast<std::size_t>(bytes_read));
    return RuntimeWaitStep{
        .input =
            QuicCoreInboundDatagram{
                .bytes = std::move(inbound),
            },
        .input_time = now(),
        .source = source,
        .source_len = source_len,
        .has_source = true,
    };
}

bool handle_core_effects(int fd, const QuicCoreResult &result, const sockaddr_storage *peer,
                         socklen_t peer_len, std::string_view role_name) {
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        if (peer == nullptr) {
            std::cerr << "http09-" << role_name
                      << " failed: cannot send datagram before peer address is known\n";
            return false;
        }

        if (!send_datagram(fd, send->bytes, *peer, peer_len, role_name)) {
            return false;
        }
    }

    return true;
}

QuicCoreResult advance_core_with_inputs(QuicCore &core, std::span<const QuicCoreInput> inputs,
                                        QuicCoreTimePoint step_time) {
    QuicCoreResult combined;
    for (const auto &input : inputs) {
        auto step = core.advance(input, step_time);
        combined.effects.insert(combined.effects.end(),
                                std::make_move_iterator(step.effects.begin()),
                                std::make_move_iterator(step.effects.end()));
        combined.next_wakeup = step.next_wakeup;
        if (step.local_error.has_value()) {
            combined.local_error = step.local_error;
            break;
        }
    }
    return combined;
}

struct EndpointDriveState {
    std::optional<QuicCoreTimePoint> next_wakeup;
    bool terminal_success = false;
    bool terminal_failure = false;
};

struct ServerSession {
    QuicCore core;
    QuicHttp09ServerEndpoint endpoint;
    EndpointDriveState state;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    std::string local_connection_id_key;
    std::string initial_destination_connection_id_key;
};

QuicCoreConfig make_runtime_client_core_config(const Http09RuntimeConfig &config,
                                               std::uint64_t connection_index) {
    auto core_config = make_http09_client_core_config(config);
    core_config.source_connection_id =
        make_runtime_connection_id(std::byte{0xc1}, (connection_index << 1u) | 0x01u);
    core_config.initial_destination_connection_id =
        make_runtime_connection_id(std::byte{0x83}, (connection_index << 1u) | 0x02u);
    return core_config;
}

QuicCoreConfig make_runtime_server_core_config(const Http09RuntimeConfig &config,
                                               const TlsIdentity &identity,
                                               std::uint64_t connection_index) {
    auto core_config = make_http09_server_core_config_with_identity(config, identity);
    core_config.source_connection_id =
        make_runtime_connection_id(std::byte{0x53}, connection_index);
    return core_config;
}

std::optional<QuicCoreTimePoint> earliest_server_session_wakeup(
    const std::unordered_map<std::string, std::unique_ptr<ServerSession>> &sessions) {
    std::optional<QuicCoreTimePoint> next_wakeup;
    for (const auto &[key, session] : sessions) {
        (void)key;
        if (!session->state.next_wakeup.has_value()) {
            continue;
        }
        if (!next_wakeup.has_value() || session->state.next_wakeup.value() < next_wakeup.value()) {
            next_wakeup = session->state.next_wakeup;
        }
    }
    return next_wakeup;
}

template <typename Endpoint>
bool drive_endpoint_until_blocked(Endpoint &endpoint, QuicCore &core, int fd,
                                  const sockaddr_storage *peer, socklen_t peer_len,
                                  const QuicCoreResult &initial_result, EndpointDriveState &state,
                                  std::string_view role_name) {
    QuicCoreResult current_result = initial_result;

    for (;;) {
        if (!handle_core_effects(fd, current_result, peer, peer_len, role_name)) {
            state.terminal_failure = true;
            return false;
        }
        state.next_wakeup = current_result.next_wakeup;
        if (current_result.local_error.has_value()) {
            state.terminal_failure = true;
            return false;
        }

        auto update = endpoint.on_core_result(current_result, now());
        if (update.terminal_failure) {
            state.terminal_failure = true;
            return false;
        }
        if (update.terminal_success) {
            state.terminal_success = true;
            return true;
        }

        while (true) {
            if (!update.core_inputs.empty()) {
                current_result = advance_core_with_inputs(core, update.core_inputs, now());
                break;
            }

            if (!update.has_pending_work) {
                return true;
            }

            update = endpoint.poll(now());
            if (update.terminal_failure) {
                state.terminal_failure = true;
                return false;
            }
            if (update.terminal_success) {
                state.terminal_success = true;
                return true;
            }
        }
    }
}

int run_http09_client_connection(const Http09RuntimeConfig &config,
                                 const std::vector<QuicHttp09Request> &requests,
                                 std::uint64_t connection_index) {
    const auto remote = derive_http09_client_remote(config, requests);
    if (!remote.has_value()) {
        std::cerr << "http09-client failed: invalid request authority\n";
        return 1;
    }

    const int socket_fd = open_udp_socket();
    if (socket_fd < 0) {
        std::cerr << "http09-client failed: unable to create UDP socket: " << std::strerror(errno)
                  << '\n';
        return 1;
    }
    ScopedFd socket_guard(socket_fd);

    sockaddr_in server_address{};
    if (!resolve_udp_peer_ipv4(remote->host, remote->port, server_address)) {
        std::cerr << "http09-client failed: invalid host address\n";
        return 1;
    }

    sockaddr_storage peer{};
    std::memcpy(&peer, &server_address, sizeof(server_address));
    const socklen_t peer_len = sizeof(server_address);

    QuicHttp09ClientEndpoint endpoint(QuicHttp09ClientConfig{
        .requests = requests,
        .download_root = config.download_root,
    });
    auto client_config = config;
    client_config.server_name = remote->server_name;
    QuicCore core(make_runtime_client_core_config(client_config, connection_index));

    EndpointDriveState state;

    auto start_result = core.advance(QuicCoreStart{}, now());
    if (!drive_endpoint_until_blocked(endpoint, core, socket_fd, &peer, peer_len, start_result,
                                      state, "client")) {
        return 1;
    }
    if (state.terminal_success) {
        return 0;
    }

    for (;;) {
        auto step = wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fd = socket_fd,
                .idle_timeout_ms = kClientReceiveTimeoutMs,
                .role_name = "client",
            },
            state.next_wakeup);
        if (!step.has_value()) {
            return 1;
        }
        if (step->idle_timeout) {
            std::cerr << "http09-client failed: timed out waiting for progress\n";
            return 1;
        }
        if (!step->input.has_value()) {
            continue;
        }

        auto step_result = core.advance(std::move(*step->input), step->input_time);
        if (!drive_endpoint_until_blocked(endpoint, core, socket_fd, &peer, peer_len, step_result,
                                          state, "client")) {
            return 1;
        }
        if (state.terminal_success) {
            return 0;
        }
        if (state.terminal_failure) {
            return 1;
        }
    }
}

int run_http09_client(const Http09RuntimeConfig &config) {
    const auto requests = parse_http09_requests_env(config.requests_env);
    if (!requests.has_value()) {
        std::cerr << "http09-client failed: invalid REQUESTS\n";
        return 1;
    }

    if (config.testcase == QuicHttp09Testcase::multiconnect) {
        for (std::size_t index = 0; index < requests.value().size(); ++index) {
            if (run_http09_client_connection(
                    config, std::vector<QuicHttp09Request>{requests.value().at(index)},
                    index + 1) != 0) {
                return 1;
            }
        }
        return 0;
    }

    return run_http09_client_connection(config, requests.value(), 1);
}

int run_http09_server(const Http09RuntimeConfig &config) {
    const int socket_fd = open_udp_socket();
    if (socket_fd < 0) {
        std::cerr << "http09-server failed: unable to create UDP socket: " << std::strerror(errno)
                  << '\n';
        return 1;
    }
    ScopedFd socket_guard(socket_fd);

    sockaddr_in bind_address{};
    if (!make_ipv4_address(config.host, config.port, bind_address)) {
        std::cerr << "http09-server failed: invalid host address\n";
        return 1;
    }
    if (::bind(socket_fd, reinterpret_cast<const sockaddr *>(&bind_address),
               sizeof(bind_address)) != 0) {
        std::cerr << "http09-server failed: unable to bind UDP socket: " << std::strerror(errno)
                  << '\n';
        return 1;
    }

    auto certificate_pem =
        read_required_text_file(config.certificate_chain_path, "certificate chain");
    if (!certificate_pem.has_value()) {
        return 1;
    }
    auto private_key_pem = read_required_text_file(config.private_key_path, "private key");
    if (!private_key_pem.has_value()) {
        return 1;
    }

    const TlsIdentity identity{
        .certificate_pem = std::move(*certificate_pem),
        .private_key_pem = std::move(*private_key_pem),
    };

    std::unordered_map<std::string, std::unique_ptr<ServerSession>> sessions;
    std::unordered_map<std::string, std::string> initial_destination_routes;
    std::uint64_t next_connection_index = 1;

    auto erase_session = [&](const std::string &local_connection_id_key) {
        const auto session_it = sessions.find(local_connection_id_key);
        if (session_it == sessions.end()) {
            return;
        }

        initial_destination_routes.erase(session_it->second->initial_destination_connection_id_key);
        sessions.erase(session_it);
    };

    auto create_session = [&](const ConnectionId &initial_destination_connection_id,
                              const sockaddr_storage &peer, socklen_t peer_len) -> ServerSession & {
        auto core_config =
            make_runtime_server_core_config(config, identity, next_connection_index++);
        const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
        auto session = std::make_unique<ServerSession>(ServerSession{
            .core = QuicCore(std::move(core_config)),
            .endpoint = QuicHttp09ServerEndpoint(
                QuicHttp09ServerConfig{.document_root = config.document_root}),
            .state = EndpointDriveState{},
            .peer = peer,
            .peer_len = peer_len,
            .local_connection_id_key = local_connection_id_key,
            .initial_destination_connection_id_key =
                connection_id_key(initial_destination_connection_id),
        });
        auto *session_ptr = session.get();
        initial_destination_routes.emplace(session_ptr->initial_destination_connection_id_key,
                                           local_connection_id_key);
        sessions.emplace(local_connection_id_key, std::move(session));
        return *session_ptr;
    };

    for (;;) {
        auto step = wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fd = socket_fd,
                .idle_timeout_ms = kServerIdleTimeoutMs,
                .role_name = "server",
            },
            earliest_server_session_wakeup(sessions));
        if (!step.has_value()) {
            return 1;
        }
        if (step->idle_timeout) {
            continue;
        }
        if (!step->input.has_value()) {
            continue;
        }

        if (std::holds_alternative<QuicCoreTimerExpired>(*step->input)) {
            std::vector<std::string> failed_sessions;
            for (const auto &[local_connection_id_key, session] : sessions) {
                if (!session->state.next_wakeup.has_value() ||
                    session->state.next_wakeup.value() > step->input_time) {
                    continue;
                }

                const auto timer_result =
                    session->core.advance(QuicCoreTimerExpired{}, step->input_time);
                if (!drive_endpoint_until_blocked(session->endpoint, session->core, socket_fd,
                                                  &session->peer, session->peer_len, timer_result,
                                                  session->state, "server")) {
                    failed_sessions.push_back(local_connection_id_key);
                }
            }
            for (const auto &local_connection_id_key : failed_sessions) {
                erase_session(local_connection_id_key);
            }
            continue;
        }

        if (!step->has_source) {
            continue;
        }

        const auto *inbound = std::get_if<QuicCoreInboundDatagram>(&*step->input);
        if (inbound == nullptr) {
            continue;
        }

        const auto parsed = parse_server_datagram_for_routing(inbound->bytes);
        if (!parsed.has_value()) {
            continue;
        }

        const auto destination_connection_id_key =
            connection_id_key(parsed->destination_connection_id);
        auto session_it = sessions.find(destination_connection_id_key);
        if (session_it == sessions.end() &&
            parsed->kind == ParsedServerDatagram::Kind::supported_initial) {
            const auto initial_it = initial_destination_routes.find(destination_connection_id_key);
            if (initial_it != initial_destination_routes.end()) {
                session_it = sessions.find(initial_it->second);
            }
        }

        if (session_it != sessions.end()) {
            auto &session = *session_it->second;
            session.peer = step->source;
            session.peer_len = step->source_len;
            const auto session_result =
                session.core.advance(std::move(*step->input), step->input_time);
            if (!drive_endpoint_until_blocked(session.endpoint, session.core, socket_fd,
                                              &session.peer, session.peer_len, session_result,
                                              session.state, "server")) {
                erase_session(session_it->first);
            }
            continue;
        }

        if (parsed->kind == ParsedServerDatagram::Kind::unsupported_version_long_header) {
            if (!send_version_negotiation_for_probe(socket_fd, inbound->bytes, step->source,
                                                    step->source_len)) {
                return 1;
            }
            continue;
        }

        if (parsed->kind != ParsedServerDatagram::Kind::supported_initial) {
            continue;
        }

        auto &session =
            create_session(parsed->destination_connection_id, step->source, step->source_len);
        const auto session_result = session.core.advance(std::move(*step->input), step->input_time);
        if (!drive_endpoint_until_blocked(session.endpoint, session.core, socket_fd, &session.peer,
                                          session.peer_len, session_result, session.state,
                                          "server")) {
            erase_session(session.local_connection_id_key);
        }
    }
}

} // namespace

std::optional<Http09RuntimeConfig> parse_http09_runtime_args(int argc, char **argv) {
    Http09RuntimeConfig config;
    bool host_specified = false;
    bool server_name_specified = false;

    if (const auto role = getenv_string("ROLE"); role.has_value()) {
        if (!parse_role_into(config, *role)) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }
    }
    if (const auto testcase = getenv_string("TESTCASE"); testcase.has_value()) {
        const auto parsed = parse_testcase(*testcase);
        if (!parsed.has_value()) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }
        config.testcase = *parsed;
    }
    if (const auto requests = getenv_string("REQUESTS"); requests.has_value()) {
        config.requests_env = *requests;
    }
    if (const auto host = getenv_string("HOST"); host.has_value()) {
        config.host = *host;
        host_specified = true;
    }
    if (const auto port = getenv_string("PORT"); port.has_value()) {
        const auto parsed = parse_port(*port);
        if (!parsed.has_value()) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }
        config.port = *parsed;
    }
    if (const auto path = getenv_string("DOCUMENT_ROOT"); path.has_value()) {
        config.document_root = *path;
    }
    if (const auto path = getenv_string("DOWNLOAD_ROOT"); path.has_value()) {
        config.download_root = *path;
    }
    if (const auto path = getenv_string("CERTIFICATE_CHAIN_PATH"); path.has_value()) {
        config.certificate_chain_path = *path;
    }
    if (const auto path = getenv_string("PRIVATE_KEY_PATH"); path.has_value()) {
        config.private_key_path = *path;
    }
    if (const auto server_name = getenv_string("SERVER_NAME"); server_name.has_value()) {
        config.server_name = *server_name;
        server_name_specified = true;
    }

    int index = 1;
    if (index < argc) {
        const std::string_view subcommand = argv[index];
        if (subcommand == "interop-server") {
            config.mode = Http09RuntimeMode::server;
            ++index;
        } else if (subcommand == "interop-client") {
            config.mode = Http09RuntimeMode::client;
            ++index;
        }
    }

    while (index < argc) {
        const std::string_view arg = argv[index++];
        auto require_value = [&](std::string_view flag) -> std::optional<std::string_view> {
            if (index >= argc) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            return std::string_view(argv[index++]);
        };

        if (arg == "--host") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.host = std::string(*value);
            host_specified = true;
            continue;
        }
        if (arg == "--port") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_port(*value);
            if (!parsed.has_value()) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            config.port = *parsed;
            continue;
        }
        if (arg == "--testcase") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            const auto parsed = parse_testcase(*value);
            if (!parsed.has_value()) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            config.testcase = *parsed;
            continue;
        }
        if (arg == "--requests") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.requests_env = std::string(*value);
            continue;
        }
        if (arg == "--document-root") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.document_root = std::string(*value);
            continue;
        }
        if (arg == "--download-root") {
            const auto value = require_value(arg);
            if (!value.has_value()) {
                return std::nullopt;
            }
            config.download_root = std::string(*value);
            continue;
        }
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
            server_name_specified = true;
            continue;
        }
        if (arg == "--verify-peer") {
            config.verify_peer = true;
            continue;
        }

        std::cerr << kUsageLine << '\n';
        return std::nullopt;
    }

    if (config.mode == Http09RuntimeMode::client && config.requests_env.empty()) {
        std::cerr << kUsageLine << '\n';
        return std::nullopt;
    }
    if (config.mode == Http09RuntimeMode::client && !host_specified) {
        config.host.clear();
    }
    if (config.mode == Http09RuntimeMode::client && !server_name_specified) {
        config.server_name.clear();
    }

    return config;
}

QuicCoreConfig make_http09_client_core_config(const Http09RuntimeConfig &config) {
    auto core = QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                              std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                              std::byte{0x57}, std::byte{0x08}},
        .verify_peer = config.verify_peer,
        .server_name = config.server_name.empty() ? "localhost" : config.server_name,
        .application_protocol = std::string(kInteropApplicationProtocol),
        .transport = http09_client_transport_for_testcase(config.testcase),
    };
    return core;
}

QuicCoreConfig make_http09_server_core_config(const Http09RuntimeConfig &config) {
    return make_http09_server_core_config_with_identity(
        config, TlsIdentity{
                    .certificate_pem = read_text_file(config.certificate_chain_path),
                    .private_key_pem = read_text_file(config.private_key_path),
                });
}

int run_http09_runtime(const Http09RuntimeConfig &config) {
    coquic::init_logging();

    switch (config.mode) {
    case Http09RuntimeMode::health_check:
        return coquic::project_name().empty() || !coquic::openssl_available() ||
               !coquic::logging_ready();
    case Http09RuntimeMode::client:
        return run_http09_client(config);
    case Http09RuntimeMode::server:
        return run_http09_server(config);
    }

    return 1;
}

} // namespace coquic::quic
