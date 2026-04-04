#include "src/quic/http09_runtime.h"
#include "src/quic/http09_runtime_test_hooks.h"
#include "src/quic/buffer.h"
#include "src/quic/packet.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/version.h"

#include "src/coquic.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
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
constexpr int kDefaultClientReceiveTimeoutMs = 30000;
constexpr int kMulticonnectClientReceiveTimeoutMs = 180000;
constexpr int kClientSuccessDrainWindowMs = 500;
constexpr int kServerIdleTimeoutMs = 1000;
constexpr std::string_view kInteropApplicationProtocol = "hq-interop";
constexpr std::string_view kUsageLine =
    "usage: coquic [interop-server|interop-client] [--host HOST] [--port PORT] "
    "[--testcase "
    "handshake|transfer|keyupdate|amplificationlimit|multiconnect|chacha20|retry|resumption|"
    "zerortt|v2] "
    "[--requests URLS] "
    "[--document-root PATH] "
    "[--download-root PATH] [--certificate-chain PATH] [--private-key PATH] "
    "[--server-name NAME] [--verify-peer] [--retry]";

int client_receive_timeout_ms(const Http09RuntimeConfig &config) {
    if (config.testcase == QuicHttp09Testcase::multiconnect) {
        return kMulticonnectClientReceiveTimeoutMs;
    }
    return kDefaultClientReceiveTimeoutMs;
}

test::Http09RuntimeOpsOverride make_default_runtime_ops() {
    return test::Http09RuntimeOpsOverride{
        .socket_fn = ::socket,
        .bind_fn = ::bind,
        .poll_fn = ::poll,
        .sendto_fn = ::sendto,
        .recvfrom_fn = ::recvfrom,
        .getaddrinfo_fn = ::getaddrinfo,
        .freeaddrinfo_fn = ::freeaddrinfo,
    };
}

test::Http09RuntimeOpsOverride &runtime_ops() {
    static thread_local auto ops = make_default_runtime_ops();
    return ops;
}

void apply_runtime_ops_override(const test::Http09RuntimeOpsOverride &override_ops) {
    auto &ops = runtime_ops();
    if (override_ops.socket_fn != nullptr) {
        ops.socket_fn = override_ops.socket_fn;
    }
    if (override_ops.bind_fn != nullptr) {
        ops.bind_fn = override_ops.bind_fn;
    }
    if (override_ops.poll_fn != nullptr) {
        ops.poll_fn = override_ops.poll_fn;
    }
    if (override_ops.sendto_fn != nullptr) {
        ops.sendto_fn = override_ops.sendto_fn;
    }
    if (override_ops.recvfrom_fn != nullptr) {
        ops.recvfrom_fn = override_ops.recvfrom_fn;
    }
    if (override_ops.getaddrinfo_fn != nullptr) {
        ops.getaddrinfo_fn = override_ops.getaddrinfo_fn;
    }
    if (override_ops.freeaddrinfo_fn != nullptr) {
        ops.freeaddrinfo_fn = override_ops.freeaddrinfo_fn;
    }
}

class ScopedFd {
  public:
    explicit ScopedFd(int fd) : fd_(fd) {
    }

    ~ScopedFd() {
        ::close(fd_);
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

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

bool env_flag_enabled(const char *name) {
    const std::string value = getenv_string(name).value_or("");
    return !value.empty() & (value != "0");
}

bool runtime_trace_enabled() {
    const auto value = getenv_string("COQUIC_RUNTIME_TRACE");
    return value.has_value() && !value->empty() && *value != "0";
}

void with_runtime_trace(const std::function<void(std::ostream &)> &callback) {
    if (!runtime_trace_enabled()) {
        return;
    }
    callback(std::cerr);
}

std::string format_connection_id_hex(std::span<const std::byte> connection_id) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (const auto byte : connection_id) {
        hex << std::setw(2) << static_cast<unsigned>(std::to_integer<std::uint8_t>(byte));
    }
    return hex.str();
}

std::string format_connection_id_key_hex(std::string_view connection_id_key) {
    return format_connection_id_hex(
        std::as_bytes(std::span(connection_id_key.data(), connection_id_key.size())));
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
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
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
    if (value == "keyupdate") {
        return QuicHttp09Testcase::keyupdate;
    }
    if (value == "amplificationlimit") {
        return QuicHttp09Testcase::transfer;
    }
    if (value == "multiconnect") {
        return QuicHttp09Testcase::multiconnect;
    }
    if (value == "chacha20") {
        return QuicHttp09Testcase::chacha20;
    }
    if (value == "resumption") {
        return QuicHttp09Testcase::resumption;
    }
    if (value == "zerortt") {
        return QuicHttp09Testcase::zerortt;
    }
    if (value == "v2") {
        return QuicHttp09Testcase::v2;
    }
    return std::nullopt;
}

constexpr QuicHttp09Testcase transfer_semantics_testcase(QuicHttp09Testcase testcase) {
    // keyupdate is a distinct runtime testcase name but uses transfer transport/TLS profile.
    if (testcase == QuicHttp09Testcase::keyupdate) {
        return QuicHttp09Testcase::transfer;
    }
    return testcase;
}

bool apply_testcase_name(Http09RuntimeConfig &config, std::string_view value) {
    if (value == "retry") {
        config.testcase = QuicHttp09Testcase::handshake;
        config.retry_enabled = true;
        return true;
    }

    const auto parsed = parse_testcase(value);
    if (!parsed.has_value()) {
        return false;
    }

    config.testcase = *parsed;
    return true;
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

struct ResolvedUdpAddress {
    sockaddr_storage address{};
    socklen_t address_len = 0;
    int family = AF_UNSPEC;
};

struct UdpAddressResolutionQuery {
    std::string_view host;
    std::uint16_t port = 0;
    int extra_flags = 0;
};

int preferred_udp_address_family(std::string_view host) {
    const auto host_string = std::string(host);

    in_addr ipv4_address{};
    if (::inet_pton(AF_INET, host_string.c_str(), &ipv4_address) == 1) {
        return AF_INET;
    }

    in6_addr ipv6_address{};
    if (::inet_pton(AF_INET6, host_string.c_str(), &ipv6_address) == 1) {
        return AF_INET6;
    }

    return AF_UNSPEC;
}

bool copy_udp_address(const addrinfo &result, ResolvedUdpAddress &resolved) {
    if (result.ai_addr == nullptr || result.ai_addrlen <= 0 ||
        result.ai_addrlen > static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        return false;
    }
    if (result.ai_family != AF_INET && result.ai_family != AF_INET6) {
        return false;
    }

    resolved = {};
    std::memcpy(&resolved.address, result.ai_addr, static_cast<std::size_t>(result.ai_addrlen));
    resolved.address_len = result.ai_addrlen;
    resolved.family = result.ai_family;
    return true;
}

bool resolve_udp_address(UdpAddressResolutionQuery query, ResolvedUdpAddress &resolved) {
    const int preferred_family = preferred_udp_address_family(query.host);

    addrinfo hints{};
    hints.ai_family = preferred_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV | query.extra_flags;

    addrinfo *results = nullptr;
    const auto service = std::to_string(query.port);
    const auto host_string = std::string(query.host);
    const char *node = query.host.empty() ? nullptr : host_string.c_str();
    const int status = runtime_ops().getaddrinfo_fn(node, service.c_str(), &hints, &results);
    const bool resolution_failed = status != 0;
    const bool missing_results = results == nullptr;
    if (resolution_failed || missing_results) {
        if (results != nullptr) {
            runtime_ops().freeaddrinfo_fn(results);
        }
        return false;
    }

    const bool prefer_ipv4_result = preferred_family == AF_UNSPEC;
    addrinfo *selected = nullptr;
    if (prefer_ipv4_result) {
        for (auto *result = results; result != nullptr; result = result->ai_next) {
            if (result->ai_family == AF_INET) {
                selected = result;
                break;
            }
        }
    }
    if (selected == nullptr) {
        selected = results;
    }

    for (auto *result = selected; result != nullptr; result = result->ai_next) {
        if (copy_udp_address(*result, resolved)) {
            runtime_ops().freeaddrinfo_fn(results);
            return true;
        }
    }

    if (selected != results) {
        for (auto *result = results; result != selected; result = result->ai_next) {
            if (copy_udp_address(*result, resolved)) {
                runtime_ops().freeaddrinfo_fn(results);
                return true;
            }
        }
    }

    runtime_ops().freeaddrinfo_fn(results);
    return false;
}

std::optional<ParsedHttp09Authority> parse_http09_authority_impl(std::string_view authority) {
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
    return parsed;
}

std::optional<Http09ClientRemote>
derive_http09_client_remote_impl(const Http09RuntimeConfig &config,
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

    const auto parsed_authority = parse_http09_authority_impl(requests.front().authority);
    if (!parsed_authority.has_value()) {
        return std::nullopt;
    }

    if (remote.host.empty()) {
        remote.host = parsed_authority->host;
        remote.port = parsed_authority->port.value_or(remote.port);
    }

    if (remote.server_name.empty()) {
        remote.server_name = parsed_authority->host;
    }

    return remote;
}

int open_udp_socket(int family) {
    const int fd = runtime_ops().socket_fn(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return fd;
    }

    if (family == AF_INET6) {
        const int disabled = 0;
        (void)::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &disabled, sizeof(disabled));
    }

    return fd;
}

std::uint32_t runtime_original_quic_version_for_testcase(QuicHttp09Testcase testcase) {
    if (testcase == QuicHttp09Testcase::v2) {
        // The interop v2 testcase uses compatible version negotiation:
        // start in v1, advertise v2, then switch to v2 after the server selects it.
        return kQuicVersion1;
    }
    return kQuicVersion1;
}

std::vector<std::uint32_t>
runtime_supported_quic_versions_for_testcase(QuicHttp09Testcase testcase) {
    if (testcase == QuicHttp09Testcase::v2) {
        return {kQuicVersion2, kQuicVersion1};
    }
    return {kQuicVersion1};
}

QuicCoreConfig make_http09_server_core_config_with_identity(const Http09RuntimeConfig &config,
                                                            TlsIdentity identity) {
    const auto original_version = runtime_original_quic_version_for_testcase(config.testcase);
    const auto transfer_like_testcase = transfer_semantics_testcase(config.testcase);
    return QuicCoreConfig{
        .role = EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .original_version = original_version,
        .initial_version = original_version,
        .supported_versions = runtime_supported_quic_versions_for_testcase(config.testcase),
        .verify_peer = config.verify_peer,
        .server_name = config.server_name,
        .application_protocol = std::string(kInteropApplicationProtocol),
        .identity = std::move(identity),
        .transport = http09_server_transport_for_testcase(transfer_like_testcase),
        .allowed_tls_cipher_suites = http09_tls_cipher_suites_for_testcase(transfer_like_testcase),
        .zero_rtt =
            QuicZeroRttConfig{
                .allow = config.testcase == QuicHttp09Testcase::zerortt,
            },
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
    std::uint32_t version = 0;
    ConnectionId destination_connection_id;
    std::optional<ConnectionId> source_connection_id;
    std::vector<std::byte> token;
};

struct PendingRetryToken {
    ConnectionId original_destination_connection_id;
    ConnectionId retry_source_connection_id;
    std::uint32_t original_version = kQuicVersion1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

using RetryTokenStore = std::unordered_map<std::string, PendingRetryToken>;

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool is_initial_long_header_type(std::uint32_t version, std::uint8_t type) {
    if (version == kQuicVersion2) {
        return type == 0x01u;
    }
    return type == 0x00u;
}

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
            .version = 0,
            .destination_connection_id =
                ConnectionId(bytes.begin() + 1, bytes.begin() + 1 + kRuntimeConnectionIdLength),
            .source_connection_id = std::nullopt,
            .token = {},
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
    offset += source_connection_id_length;

    if (!is_supported_quic_version(version)) {
        return ParsedServerDatagram{
            .kind = ParsedServerDatagram::Kind::unsupported_version_long_header,
            .version = version,
            .destination_connection_id = std::move(destination_connection_id),
            .source_connection_id = std::move(source_connection_id),
            .token = {},
        };
    }

    const auto type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    std::vector<std::byte> token;
    if (is_initial_long_header_type(version, type)) {
        BufferReader reader(bytes.subspan(offset));
        const auto token_length = decode_varint(reader);
        if (!token_length.has_value()) {
            return std::nullopt;
        }
        if (token_length.value().value > static_cast<std::uint64_t>(reader.remaining())) {
            return std::nullopt;
        }
        const auto token_bytes =
            reader.read_exact(static_cast<std::size_t>(token_length.value().value)).value();
        token.assign(token_bytes.begin(), token_bytes.end());
    }
    return ParsedServerDatagram{
        .kind = is_initial_long_header_type(version, type)
                    ? ParsedServerDatagram::Kind::supported_initial
                    : ParsedServerDatagram::Kind::supported_long_header,
        .version = version,
        .destination_connection_id = std::move(destination_connection_id),
        .source_connection_id = std::move(source_connection_id),
        .token = std::move(token),
    };
}

std::vector<std::byte> make_runtime_retry_token(std::uint64_t sequence) {
    std::vector<std::byte> token(16, std::byte{0x00});
    token[0] = std::byte{0x72};
    token[1] = std::byte{0x74};
    token[2] = std::byte{0x72};
    token[3] = std::byte{0x79};
    for (std::size_t index = 0; index < sizeof(sequence); ++index) {
        const auto shift = static_cast<unsigned>((sizeof(sequence) - 1 - index) * 8);
        token[8 + index] = static_cast<std::byte>((sequence >> shift) & 0xffu);
    }
    return token;
}

bool peer_matches_pending_retry(const PendingRetryToken &pending, const sockaddr_storage &peer,
                                socklen_t peer_len) {
    return (pending.peer_len == peer_len) & (pending.peer.ss_family == peer.ss_family) &
           (std::memcmp(&pending.peer, &peer, static_cast<std::size_t>(peer_len)) == 0);
}

std::optional<PendingRetryToken> lookup_retry_context(const ParsedServerDatagram &parsed,
                                                      const sockaddr_storage &peer,
                                                      socklen_t peer_len,
                                                      RetryTokenStore &retry_tokens) {
    const auto it = retry_tokens.find(connection_id_key(parsed.token));
    if (it == retry_tokens.end()) {
        return std::nullopt;
    }

    const auto &pending = it->second;
    if (!peer_matches_pending_retry(pending, peer, peer_len)) {
        return std::nullopt;
    }
    if (parsed.destination_connection_id != pending.retry_source_connection_id) {
        return std::nullopt;
    }
    if (parsed.version != pending.original_version) {
        return std::nullopt;
    }

    auto retry_context = pending;
    retry_tokens.erase(it);
    return retry_context;
}

bool send_retry_for_initial(int fd, const ParsedServerDatagram &parsed,
                            const sockaddr_storage &peer, socklen_t peer_len,
                            RetryTokenStore &retry_tokens, std::uint64_t connection_index) {
    if (!parsed.source_connection_id.has_value()) {
        std::cerr << "http09-server failed: missing source connection id for retry\n";
        return false;
    }

    const auto retry_source_connection_id =
        make_runtime_connection_id(std::byte{0x73}, connection_index);
    const auto token = make_runtime_retry_token(connection_index);
    retry_tokens.emplace(connection_id_key(token),
                         PendingRetryToken{
                             .original_destination_connection_id = parsed.destination_connection_id,
                             .retry_source_connection_id = retry_source_connection_id,
                             .original_version = parsed.version,
                             .peer = peer,
                             .peer_len = peer_len,
                         });

    RetryPacket packet{
        .version = parsed.version,
        .retry_unused_bits = 0,
        .destination_connection_id = *parsed.source_connection_id,
        .source_connection_id = retry_source_connection_id,
        .retry_token = token,
    };
    const auto integrity_tag =
        compute_retry_integrity_tag(packet, parsed.destination_connection_id);
    if (!integrity_tag.has_value()) {
        return false;
    }
    packet.retry_integrity_tag = integrity_tag.value();

    // compute_retry_integrity_tag serializes the same validated RetryPacket image.
    const auto encoded = serialize_packet(packet).value();
    return send_datagram(fd, encoded, peer, peer_len, "server");
}

std::optional<bool> maybe_send_retry_for_supported_initial(bool retry_enabled, int socket_fd,
                                                           const ParsedServerDatagram &parsed,
                                                           const sockaddr_storage &peer,
                                                           socklen_t peer_len,
                                                           RetryTokenStore &retry_tokens,
                                                           std::uint64_t &next_connection_index) {
    if (!retry_enabled || !parsed.token.empty()) {
        return std::nullopt;
    }

    with_runtime_trace([&](std::ostream &stream) {
        stream << "http09-server trace: retry-initial odcid="
               << format_connection_id_hex(parsed.destination_connection_id) << '\n';
    });
    return send_retry_for_initial(socket_fd, parsed, peer, peer_len, retry_tokens,
                                  next_connection_index++);
}

bool populate_retry_context_if_required(bool retry_enabled, const ParsedServerDatagram &parsed,
                                        const sockaddr_storage &peer, socklen_t peer_len,
                                        RetryTokenStore &retry_tokens,
                                        std::optional<PendingRetryToken> &retry_context) {
    retry_context.reset();
    if (!retry_enabled) {
        return true;
    }

    retry_context = lookup_retry_context(parsed, peer, peer_len, retry_tokens);
    if (retry_context.has_value()) {
        return true;
    }

    with_runtime_trace([&](std::ostream &stream) {
        stream << "http09-server trace: ignored-invalid-retry-token dcid="
               << format_connection_id_hex(parsed.destination_connection_id) << '\n';
    });
    return false;
}

struct SupportedInitialRetryPreparation {
    std::optional<bool> immediate_result;
    std::optional<PendingRetryToken> retry_context;
};

SupportedInitialRetryPreparation prepare_supported_initial_retry_handling(
    bool retry_enabled, int socket_fd, const ParsedServerDatagram &parsed,
    const sockaddr_storage &peer, socklen_t peer_len, RetryTokenStore &retry_tokens,
    std::uint64_t &next_connection_index) {
    if (const auto retry_result = maybe_send_retry_for_supported_initial(
            retry_enabled, socket_fd, parsed, peer, peer_len, retry_tokens, next_connection_index);
        retry_result.has_value()) {
        return SupportedInitialRetryPreparation{
            .immediate_result = retry_result,
        };
    }

    SupportedInitialRetryPreparation result{};
    if (!populate_retry_context_if_required(retry_enabled, parsed, peer, peer_len, retry_tokens,
                                            result.retry_context)) {
        result.immediate_result = true;
    }
    return result;
}

bool send_version_negotiation_for_probe(int fd, std::span<const std::byte> datagram,
                                        const ParsedServerDatagram &parsed,
                                        const sockaddr_storage &peer, socklen_t peer_len) {
    if (datagram.size() < kMinimumClientInitialDatagramBytes) {
        return true;
    }
    if (!parsed.source_connection_id.has_value()) {
        std::cerr << "http09-server failed: missing source connection id for version negotiation\n";
        return false;
    }

    const auto packet = VersionNegotiationPacket{
        .destination_connection_id = *parsed.source_connection_id,
        .source_connection_id = parsed.destination_connection_id,
        .supported_versions = std::vector<std::uint32_t>(supported_quic_versions().begin(),
                                                         supported_quic_versions().end()),
    };
    const auto encoded = serialize_packet(packet).value();

    return send_datagram(fd, encoded, peer, peer_len, "server");
}

bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name) {
    const auto *buffer = reinterpret_cast<const void *>(datagram.data());
    const ssize_t sent = runtime_ops().sendto_fn(
        fd, buffer, datagram.size(), 0, reinterpret_cast<const sockaddr *>(&peer), peer_len);
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

enum class ReceiveDatagramStatus : std::uint8_t {
    ok,
    would_block,
    error,
};

struct ReceiveDatagramResult {
    ReceiveDatagramStatus status = ReceiveDatagramStatus::would_block;
    RuntimeWaitStep step;
};

struct ClientLoopIo {
    void *context = nullptr;
    QuicCoreTimePoint (*now_fn)(void *) = nullptr;
    ReceiveDatagramResult (*receive_datagram_fn)(void *, int, int, std::string_view) = nullptr;
    std::optional<RuntimeWaitStep> (*wait_for_socket_or_deadline_fn)(
        void *, const RuntimeWaitConfig &, const std::optional<QuicCoreTimePoint> &) = nullptr;

    QuicCoreTimePoint current_time() const {
        return now_fn(context);
    }

    ReceiveDatagramResult receive_datagram(int socket_fd, int flags,
                                           std::string_view role_name) const {
        return receive_datagram_fn(context, socket_fd, flags, role_name);
    }

    std::optional<RuntimeWaitStep>
    wait_for_socket_or_deadline(const RuntimeWaitConfig &config,
                                const std::optional<QuicCoreTimePoint> &next_wakeup) const {
        return wait_for_socket_or_deadline_fn(context, config, next_wakeup);
    }
};

ReceiveDatagramResult receive_datagram(int socket_fd, std::string_view role_name, int flags) {
    std::vector<std::byte> inbound(kMaxDatagramBytes);
    sockaddr_storage source{};
    socklen_t source_len = sizeof(source);
    ssize_t bytes_read = 0;
    do {
        bytes_read = runtime_ops().recvfrom_fn(socket_fd, inbound.data(), inbound.size(), flags,
                                               reinterpret_cast<sockaddr *>(&source), &source_len);
    } while (bytes_read < 0 && errno == EINTR);

    if (bytes_read < 0) {
        const bool would_block = (errno == EAGAIN) | (errno == EWOULDBLOCK);
        if (would_block) {
            return ReceiveDatagramResult{
                .status = ReceiveDatagramStatus::would_block,
            };
        }

        std::cerr << "http09-" << role_name << " failed: recvfrom error: " << std::strerror(errno)
                  << '\n';
        return ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::error,
        };
    }

    inbound.resize(static_cast<std::size_t>(bytes_read));
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::ok,
        .step =
            RuntimeWaitStep{
                .input =
                    QuicCoreInboundDatagram{
                        .bytes = std::move(inbound),
                    },
                .input_time = now(),
                .source = source,
                .source_len = source_len,
                .has_source = true,
            },
    };
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
ReceiveDatagramResult receive_runtime_client_datagram(void *, int socket_fd, int flags,
                                                      std::string_view role_name) {
    return receive_datagram(socket_fd, role_name, flags);
}

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
        }
    }

    pollfd descriptor{};
    descriptor.fd = config.socket_fd;
    descriptor.events = POLLIN;

    int poll_result = 0;
    do {
        poll_result = runtime_ops().poll_fn(&descriptor, 1, timeout_ms);
    } while (poll_result < 0 && errno == EINTR);

    if (poll_result < 0) {
        if (errno == ECANCELED) {
            return std::nullopt;
        }
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

    const auto receive = receive_datagram(config.socket_fd, config.role_name, /*flags=*/0);
    if (receive.status != ReceiveDatagramStatus::ok) {
        return std::nullopt;
    }
    return receive.step;
}

ClientLoopIo make_runtime_client_loop_io() {
    return ClientLoopIo{
        .now_fn = [](void *) { return now(); },
        .receive_datagram_fn = &receive_runtime_client_datagram,
        .wait_for_socket_or_deadline_fn =
            [](void *, const RuntimeWaitConfig &config,
               const std::optional<QuicCoreTimePoint> &next_wakeup) {
                return wait_for_socket_or_deadline(config, next_wakeup);
            },
    };
}

bool handle_core_effects(int fd, const QuicCoreResult &result, const sockaddr_storage *peer,
                         socklen_t peer_len, std::string_view role_name) {
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
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
    bool endpoint_has_pending_work = false;
    bool terminal_success = false;
    bool terminal_failure = false;
    std::optional<QuicResumptionState> last_resumption_state;
};

void record_resumption_state(EndpointDriveState &state, const QuicCoreResult &result) {
    for (const auto &effect : result.effects) {
        const auto *available = std::get_if<QuicCoreResumptionStateAvailable>(&effect);
        if (available != nullptr) {
            state.last_resumption_state = available->state;
        }
    }
}

bool zero_rtt_definitely_unavailable(const QuicCoreResult &result) {
    for (const auto &effect : result.effects) {
        const auto *status = std::get_if<QuicCoreZeroRttStatusEvent>(&effect);
        if (status == nullptr) {
            continue;
        }
        if (status->status == QuicZeroRttStatus::unavailable ||
            status->status == QuicZeroRttStatus::not_attempted ||
            status->status == QuicZeroRttStatus::rejected) {
            return true;
        }
    }
    return false;
}

bool allow_requests_before_handshake_ready(bool attempt_zero_rtt_requests,
                                           const QuicCoreResult &start_result) {
    return attempt_zero_rtt_requests && !zero_rtt_definitely_unavailable(start_result);
}

struct ClientConnectionRunResult {
    int exit_code = 0;
    std::optional<QuicResumptionState> resumption_state;
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

using ServerSessionMap = std::unordered_map<std::string, std::unique_ptr<ServerSession>>;
using EraseServerSessionFn = std::function<void(const std::string &)>;

void erase_server_session_from_map(ServerSessionMap &sessions,
                                   const std::string &local_connection_id_key) {
    sessions.erase(local_connection_id_key);
}

bool datagram_routes_via_initial_destination(const ParsedServerDatagram &parsed) {
    return parsed.kind == ParsedServerDatagram::Kind::supported_initial ||
           parsed.kind == ParsedServerDatagram::Kind::supported_long_header;
}

ServerSessionMap::iterator find_server_session_for_datagram(
    ServerSessionMap &sessions,
    const std::unordered_map<std::string, std::string> &initial_destination_routes,
    const ParsedServerDatagram &parsed) {
    const auto destination_connection_id_key = connection_id_key(parsed.destination_connection_id);
    auto session_it = sessions.find(destination_connection_id_key);
    if (session_it != sessions.end() || !datagram_routes_via_initial_destination(parsed)) {
        return session_it;
    }

    const auto initial_it = initial_destination_routes.find(destination_connection_id_key);
    if (initial_it == initial_destination_routes.end()) {
        return sessions.end();
    }

    return sessions.find(initial_it->second);
}

struct EndpointDriver {
    void *context = nullptr;
    QuicHttp09EndpointUpdate (*on_core_result_fn)(void *, const QuicCoreResult &,
                                                  QuicCoreTimePoint) = nullptr;
    QuicHttp09EndpointUpdate (*poll_fn)(void *, QuicCoreTimePoint) = nullptr;

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult &result,
                                            QuicCoreTimePoint current) const {
        return on_core_result_fn(context, result, current);
    }

    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint current) const {
        return poll_fn(context, current);
    }
};

template <typename Endpoint> EndpointDriver make_endpoint_driver(Endpoint &endpoint) {
    return EndpointDriver{
        .context = &endpoint,
        .on_core_result_fn =
            [](void *context, const QuicCoreResult &result, QuicCoreTimePoint current) {
                return static_cast<Endpoint *>(context)->on_core_result(result, current);
            },
        .poll_fn =
            [](void *context, QuicCoreTimePoint current) {
                return static_cast<Endpoint *>(context)->poll(current);
            },
    };
}

void assign_runtime_client_connection_ids(QuicCoreConfig &core_config,
                                          std::uint64_t connection_index) {
    core_config.source_connection_id =
        make_runtime_connection_id(std::byte{0xc1}, (connection_index << 1u) | 0x01u);
    core_config.initial_destination_connection_id =
        make_runtime_connection_id(std::byte{0x83}, connection_index << 1u);
}

QuicCoreConfig make_runtime_client_core_config(const Http09RuntimeConfig &config,
                                               std::uint64_t connection_index) {
    auto core_config = make_http09_client_core_config(config);
    assign_runtime_client_connection_ids(core_config, connection_index);
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

template <typename Range, typename Projection>
std::optional<QuicCoreTimePoint> earliest_wakeup_in_range(const Range &range, Projection project) {
    std::optional<QuicCoreTimePoint> next_wakeup;
    for (const auto &entry : range) {
        const auto candidate = project(entry);
        if (!candidate.has_value()) {
            continue;
        }

        const auto wakeup = candidate.value();
        next_wakeup = std::min(next_wakeup.value_or(wakeup), wakeup);
    }
    return next_wakeup;
}

std::optional<QuicCoreTimePoint> earliest_server_session_wakeup(
    const std::unordered_map<std::string, std::unique_ptr<ServerSession>> &sessions) {
    return earliest_wakeup_in_range(
        sessions, [](const auto &entry) { return entry.second->state.next_wakeup; });
}

bool drive_endpoint_until_blocked(const EndpointDriver &endpoint, QuicCore &core, int fd,
                                  const sockaddr_storage *peer, socklen_t peer_len,
                                  const QuicCoreResult &initial_result, EndpointDriveState &state,
                                  std::string_view role_name) {
    QuicCoreResult current_result = initial_result;

    for (;;) {
        record_resumption_state(state, current_result);
        if (!handle_core_effects(fd, current_result, peer, peer_len, role_name)) {
            state.terminal_failure = true;
            return false;
        }
        state.next_wakeup = current_result.next_wakeup;
        auto update = endpoint.on_core_result(current_result, now());
        state.endpoint_has_pending_work = update.has_pending_work;
        if (current_result.local_error.has_value() && !update.handled_local_error) {
            state.terminal_failure = true;
            return false;
        }
        if (update.terminal_failure) {
            state.terminal_failure = true;
            return false;
        }
        if (update.terminal_success) {
            state.terminal_success = true;
            return true;
        }

        if (update.core_inputs.empty()) {
            return true;
        }

        current_result = advance_core_with_inputs(core, update.core_inputs, now());
    }
}

int run_http09_client_connection_loop(const EndpointDriver &endpoint, QuicCore &core, int socket_fd,
                                      int idle_timeout_ms, const sockaddr_storage &peer,
                                      socklen_t peer_len, EndpointDriveState &state,
                                      const ClientLoopIo &io, const QuicCoreResult &start_result) {
    struct PumpEndpointWorkResult {
        bool ok = true;
        bool advanced_core = false;
    };

    bool saw_peer_input = false;
    std::optional<QuicCoreTimePoint> terminal_success_deadline;
    const auto ensure_terminal_success_deadline = [&](QuicCoreTimePoint current) {
        if (!saw_peer_input || terminal_success_deadline.has_value()) {
            return;
        }

        terminal_success_deadline =
            current + std::chrono::milliseconds(kClientSuccessDrainWindowMs);
    };
    const auto refresh_terminal_success_deadline_from_peer_input = [&](QuicCoreTimePoint current) {
        terminal_success_deadline =
            current + std::chrono::milliseconds(kClientSuccessDrainWindowMs);
    };
    const auto success_drain_complete = [&](QuicCoreTimePoint current) {
        return current >= terminal_success_deadline.value_or(QuicCoreTimePoint::max());
    };
    const auto should_exit_after_terminal_success = [&](QuicCoreTimePoint current) {
        if (!saw_peer_input) {
            return true;
        }

        return success_drain_complete(current);
    };
    if (!drive_endpoint_until_blocked(endpoint, core, socket_fd, &peer, peer_len, start_result,
                                      state, "client")) {
        return 1;
    }
    if (state.terminal_success) {
        return 0;
    }

    const auto process_expired_client_timer = [&](QuicCoreTimePoint current,
                                                  bool &processed_any) -> bool {
        processed_any = false;
        const auto next_wakeup = state.next_wakeup;
        if (!next_wakeup.has_value() || next_wakeup.value() > current) {
            return true;
        }

        processed_any = true;
        const auto timer_result = core.advance(QuicCoreTimerExpired{}, current);
        return drive_endpoint_until_blocked(endpoint, core, socket_fd, &peer, peer_len,
                                            timer_result, state, "client");
    };

    const auto pump_client_endpoint_work_once = [&]() -> PumpEndpointWorkResult {
        if (!state.endpoint_has_pending_work) {
            return {};
        }

        const bool pending_before = state.endpoint_has_pending_work;
        auto update = endpoint.poll(now());
        state.endpoint_has_pending_work = update.has_pending_work;
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-client trace: poll pending_before=" << pending_before
                   << " pending_after=" << update.has_pending_work
                   << " core_inputs=" << update.core_inputs.size()
                   << " terminal_success=" << update.terminal_success
                   << " terminal_failure=" << update.terminal_failure << '\n';
        });
        if (update.terminal_failure) {
            state.terminal_failure = true;
            return PumpEndpointWorkResult{
                .ok = false,
            };
        }
        if (update.terminal_success) {
            state.terminal_success = true;
            return {};
        }
        if (update.core_inputs.empty()) {
            return {};
        }

        auto result = advance_core_with_inputs(core, update.core_inputs, now());
        return PumpEndpointWorkResult{
            .ok = drive_endpoint_until_blocked(endpoint, core, socket_fd, &peer, peer_len, result,
                                               state, "client"),
            .advanced_core = true,
        };
    };

    const auto drain_ready_datagrams = [&]() -> bool {
        for (;;) {
            bool processed_timers = false;
            if (!process_expired_client_timer(io.current_time(), processed_timers)) {
                return false;
            }
            if (processed_timers) {
                continue;
            }

            const auto pump_result = pump_client_endpoint_work_once();
            if (!pump_result.ok) {
                return false;
            }
            const bool terminal = state.terminal_success | state.terminal_failure;
            if (terminal) {
                ensure_terminal_success_deadline(io.current_time());
                return true;
            }

            auto receive = io.receive_datagram(socket_fd, /*flags=*/MSG_DONTWAIT,
                                               /*role_name=*/"client");
            if (receive.status == ReceiveDatagramStatus::would_block) {
                with_runtime_trace([&](std::ostream &stream) {
                    stream << "http09-client trace: would-block pending="
                           << state.endpoint_has_pending_work
                           << " advanced_core=" << pump_result.advanced_core
                           << " terminal_success=" << state.terminal_success
                           << " terminal_failure=" << state.terminal_failure << '\n';
                });
                if (pump_result.advanced_core && state.endpoint_has_pending_work) {
                    continue;
                }
                return true;
            }
            if (receive.status == ReceiveDatagramStatus::error) {
                return false;
            }

            auto step_result =
                core.advance(std::move(*receive.step.input), receive.step.input_time);
            saw_peer_input = true;
            if (!drive_endpoint_until_blocked(endpoint, core, socket_fd, &peer, peer_len,
                                              step_result, state, "client")) {
                return false;
            }
            const bool terminal_after_receive = state.terminal_success | state.terminal_failure;
            if (terminal_after_receive) {
                refresh_terminal_success_deadline_from_peer_input(receive.step.input_time);
                return true;
            }
        }
    };

    for (;;) {
        if (!drain_ready_datagrams()) {
            return 1;
        }
        if (state.terminal_success) {
            const auto current = io.current_time();
            if (should_exit_after_terminal_success(current)) {
                return 0;
            }
        }

        bool processed_timers = false;
        if (!process_expired_client_timer(io.current_time(), processed_timers)) {
            return 1;
        }
        if (processed_timers) {
            continue;
        }

        if (!pump_client_endpoint_work_once().ok) {
            return 1;
        }
        if (state.terminal_success) {
            const auto current = io.current_time();
            ensure_terminal_success_deadline(current);
            if (should_exit_after_terminal_success(current)) {
                return 0;
            }
        }

        auto wait_next_wakeup = state.next_wakeup;
        if (terminal_success_deadline.has_value()) {
            wait_next_wakeup = std::min(wait_next_wakeup.value_or(*terminal_success_deadline),
                                        *terminal_success_deadline);
        }
        auto step = io.wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fd = socket_fd,
                .idle_timeout_ms = idle_timeout_ms,
                .role_name = "client",
            },
            wait_next_wakeup);
        if (!step.has_value()) {
            return 1;
        }
        if (step->idle_timeout) {
            if (state.terminal_success) {
                return 0;
            }
            const auto current = io.current_time();
            const auto next_wakeup_delay_ms =
                state.next_wakeup.has_value()
                    ? std::chrono::duration_cast<std::chrono::milliseconds>(
                          state.next_wakeup.value() > current ? state.next_wakeup.value() - current
                                                              : current - state.next_wakeup.value())
                          .count()
                    : -1;
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-client trace: idle-timeout pending="
                       << state.endpoint_has_pending_work
                       << " terminal_success=" << state.terminal_success
                       << " terminal_failure=" << state.terminal_failure
                       << " saw_peer_input=" << saw_peer_input
                       << " has_next_wakeup=" << state.next_wakeup.has_value()
                       << " next_wakeup_delta_ms=" << next_wakeup_delay_ms << '\n';
            });
            std::cerr << "http09-client failed: timed out waiting for progress\n";
            return 1;
        }
        if (!step->input.has_value()) {
            std::cerr << "http09-client failed: runtime step missing input\n";
            return 1;
        }
        auto step_input = std::move(*step->input);
        const bool step_has_peer_input =
            std::holds_alternative<QuicCoreInboundDatagram>(step_input);
        saw_peer_input = step_has_peer_input || saw_peer_input;
        auto step_result = core.advance(std::move(step_input), step->input_time);
        if (!drive_endpoint_until_blocked(endpoint, core, socket_fd, &peer, peer_len, step_result,
                                          state, "client")) {
            return 1;
        }
        if (state.terminal_success) {
            if (step_has_peer_input) {
                refresh_terminal_success_deadline_from_peer_input(step->input_time);
            } else {
                ensure_terminal_success_deadline(step->input_time);
            }
            if (should_exit_after_terminal_success(io.current_time())) {
                return 0;
            }
        }
    }
}

QuicHttp09ClientConfig make_http09_client_endpoint_config(
    const Http09RuntimeConfig &config, const std::vector<QuicHttp09Request> &requests,
    bool attempt_zero_rtt_requests, const QuicCoreResult &start_result) {
    return QuicHttp09ClientConfig{
        .requests = requests,
        .download_root = config.download_root,
        .allow_requests_before_handshake_ready =
            allow_requests_before_handshake_ready(attempt_zero_rtt_requests, start_result),
        .request_key_update = config.testcase == QuicHttp09Testcase::keyupdate,
    };
}

ClientConnectionRunResult run_http09_client_connection_with_core_config(
    const Http09RuntimeConfig &config, const std::vector<QuicHttp09Request> &requests,
    QuicCoreConfig core_config, std::uint64_t connection_index) {
    const auto remote = derive_http09_client_remote_impl(config, requests);
    if (!remote.has_value()) {
        std::cerr << "http09-client failed: invalid request authority\n";
        return ClientConnectionRunResult{
            .exit_code = 1,
        };
    }

    ResolvedUdpAddress peer_address{};
    if (!resolve_udp_address(
            UdpAddressResolutionQuery{
                .host = remote->host,
                .port = remote->port,
            },
            peer_address)) {
        std::cerr << "http09-client failed: invalid host address\n";
        return ClientConnectionRunResult{
            .exit_code = 1,
        };
    }

    const int socket_fd = open_udp_socket(peer_address.family);
    if (socket_fd < 0) {
        std::cerr << "http09-client failed: unable to create UDP socket: " << std::strerror(errno)
                  << '\n';
        return ClientConnectionRunResult{
            .exit_code = 1,
        };
    }
    ScopedFd socket_guard(socket_fd);

    const sockaddr_storage peer = peer_address.address;
    const socklen_t peer_len = peer_address.address_len;

    const bool attempt_zero_rtt_requests = core_config.zero_rtt.attempt;
    core_config.server_name = remote->server_name;
    assign_runtime_client_connection_ids(core_config, connection_index);
    QuicCore core(std::move(core_config));
    EndpointDriveState state;
    const auto start_result = core.advance(QuicCoreStart{}, now());
    record_resumption_state(state, start_result);

    QuicHttp09ClientEndpoint endpoint(make_http09_client_endpoint_config(
        config, requests, attempt_zero_rtt_requests, start_result));
    return ClientConnectionRunResult{
        .exit_code = run_http09_client_connection_loop(
            make_endpoint_driver(endpoint), core, socket_fd, client_receive_timeout_ms(config),
            peer, peer_len, state, make_runtime_client_loop_io(), start_result),
        .resumption_state = state.last_resumption_state,
    };
}

using ClientConnectionRunner = std::function<ClientConnectionRunResult(
    const Http09RuntimeConfig &, const std::vector<QuicHttp09Request> &, QuicCoreConfig,
    std::uint64_t)>;

int run_http09_resumed_client_sequence(const Http09RuntimeConfig &config,
                                       const std::vector<QuicHttp09Request> &requests,
                                       const ClientConnectionRunner &runner) {
    Http09RuntimeConfig warmup_config = config;
    warmup_config.download_root = config.download_root / ".coquic-warmup";
    std::error_code warmup_cleanup_error;
    std::filesystem::remove_all(warmup_config.download_root, warmup_cleanup_error);

    const std::vector<QuicHttp09Request> warmup_requests = {requests.front()};
    auto warmup_core_config = make_runtime_client_core_config(config, 1);
    warmup_core_config.zero_rtt.application_context =
        http09_zero_rtt_application_context(warmup_requests);
    const auto warmup = runner(warmup_config, warmup_requests, std::move(warmup_core_config), 1);
    std::filesystem::remove_all(warmup_config.download_root, warmup_cleanup_error);
    if (warmup.exit_code != 0) {
        return warmup.exit_code;
    }

    auto resumed_core_config = make_runtime_client_core_config(config, 2);
    resumed_core_config.resumption_state = warmup.resumption_state;
    resumed_core_config.zero_rtt = QuicZeroRttConfig{
        .attempt = config.testcase == QuicHttp09Testcase::zerortt,
        .application_context = http09_zero_rtt_application_context(requests),
    };
    return runner(config, requests, std::move(resumed_core_config), 2).exit_code;
}

int run_http09_client_connection(const Http09RuntimeConfig &config,
                                 const std::vector<QuicHttp09Request> &requests,
                                 std::uint64_t connection_index) {
    return run_http09_client_connection_with_core_config(
               config, requests, make_runtime_client_core_config(config, connection_index),
               connection_index)
        .exit_code;
}

int run_http09_client(const Http09RuntimeConfig &config) {
    const auto requests = parse_http09_requests_env(config.requests_env);
    if (!requests.has_value()) {
        std::cerr << "http09-client failed: invalid REQUESTS\n";
        return 1;
    }

    const bool resumed_case = config.testcase == QuicHttp09Testcase::resumption ||
                              config.testcase == QuicHttp09Testcase::zerortt;
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

    if (!resumed_case) {
        return run_http09_client_connection(config, requests.value(), 1);
    }

    return run_http09_resumed_client_sequence(
        config, requests.value(),
        [](const Http09RuntimeConfig &runner_config,
           const std::vector<QuicHttp09Request> &runner_requests, QuicCoreConfig core_config,
           std::uint64_t connection_index) {
            return run_http09_client_connection_with_core_config(
                runner_config, runner_requests, std::move(core_config), connection_index);
        });
}

bool process_existing_server_session_datagram(ServerSession &session, RuntimeWaitStep &step,
                                              const ParsedServerDatagram &parsed, int socket_fd,
                                              const EraseServerSessionFn &erase_session) {
    if (parsed.kind == ParsedServerDatagram::Kind::supported_initial) {
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-server trace: routed-initial-to-existing-session scid="
                   << format_connection_id_key_hex(session.local_connection_id_key)
                   << " odcid=" << format_connection_id_hex(parsed.destination_connection_id)
                   << '\n';
        });
    }
    session.peer = step.source;
    session.peer_len = step.source_len;
    if (!step.input.has_value()) {
        std::cerr << "http09-server failed: runtime step missing input\n";
        return false;
    }
    auto session_input = std::move(*step.input);
    const auto session_result = session.core.advance(std::move(session_input), step.input_time);
    const bool endpoint_failed = !drive_endpoint_until_blocked(
        make_endpoint_driver(session.endpoint), session.core, socket_fd, &session.peer,
        session.peer_len, session_result, session.state, "server");
    const bool core_failed = session.core.has_failed();
    if (endpoint_failed | core_failed) {
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-server trace: session-failed scid="
                   << format_connection_id_key_hex(session.local_connection_id_key)
                   << " odcid=" << format_connection_id_hex(parsed.destination_connection_id)
                   << '\n';
        });
        erase_session(session.local_connection_id_key);
    }
    return true;
}

void process_expired_server_sessions(ServerSessionMap &sessions, int socket_fd,
                                     QuicCoreTimePoint current,
                                     const EraseServerSessionFn &erase_session,
                                     bool &processed_any) {
    processed_any = false;
    std::vector<std::string> failed_sessions;
    for (const auto &[local_connection_id_key, session] : sessions) {
        const auto session_next_wakeup = session->state.next_wakeup;
        if (!session_next_wakeup.has_value() || session_next_wakeup.value() > current) {
            continue;
        }

        processed_any = true;
        const auto timer_result = session->core.advance(QuicCoreTimerExpired{}, current);
        const bool endpoint_failed = !drive_endpoint_until_blocked(
            make_endpoint_driver(session->endpoint), session->core, socket_fd, &session->peer,
            session->peer_len, timer_result, session->state, "server");
        const bool core_failed = session->core.has_failed();
        if (endpoint_failed | core_failed) {
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-server trace: timer-session-failed scid="
                       << format_connection_id_key_hex(local_connection_id_key)
                       << " endpoint_failed=" << endpoint_failed << " core_failed=" << core_failed
                       << '\n';
            });
            failed_sessions.push_back(local_connection_id_key);
        }
    }
    for (const auto &local_connection_id_key : failed_sessions) {
        erase_session(local_connection_id_key);
    }
}

void pump_server_pending_endpoint_work(ServerSessionMap &sessions, int socket_fd,
                                       const EraseServerSessionFn &erase_session) {
    std::vector<std::string> failed_sessions;
    for (const auto &[local_connection_id_key, session] : sessions) {
        if (!session->state.endpoint_has_pending_work) {
            continue;
        }

        const auto endpoint_driver = make_endpoint_driver(session->endpoint);
        auto update = endpoint_driver.poll(now());
        session->state.endpoint_has_pending_work = update.has_pending_work;

        auto result = advance_core_with_inputs(session->core, update.core_inputs, now());
        const bool endpoint_failed =
            !drive_endpoint_until_blocked(endpoint_driver, session->core, socket_fd, &session->peer,
                                          session->peer_len, result, session->state, "server");
        const bool core_failed = session->core.has_failed();
        if (endpoint_failed | core_failed) {
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-server trace: pending-work-session-failed scid="
                       << format_connection_id_key_hex(local_connection_id_key)
                       << " endpoint_failed=" << endpoint_failed << " core_failed=" << core_failed
                       << " terminal_failure=" << update.terminal_failure << '\n';
            });
            failed_sessions.push_back(local_connection_id_key);
        }
    }
    for (const auto &local_connection_id_key : failed_sessions) {
        erase_session(local_connection_id_key);
    }
}

bool has_pending_server_endpoint_work(const ServerSessionMap &sessions) {
    return std::any_of(sessions.begin(), sessions.end(), [](const auto &entry) {
        return entry.second->state.endpoint_has_pending_work;
    });
}

struct ServerLoopIo {
    std::function<QuicCoreTimePoint()> current_time;
    std::function<ReceiveDatagramResult(int, int, std::string_view)> receive_datagram;
    std::function<std::optional<RuntimeWaitStep>(const RuntimeWaitConfig &,
                                                 const std::optional<QuicCoreTimePoint> &)>
        wait_for_socket_or_deadline;
};

struct ServerLoopDriver {
    std::function<std::optional<QuicCoreTimePoint>()> earliest_wakeup;
    std::function<void(QuicCoreTimePoint, bool &)> process_expired_timers;
    std::function<void()> pump_endpoint_work;
    std::function<bool()> has_pending_endpoint_work;
    std::function<bool(RuntimeWaitStep)> process_datagram;
};

ServerLoopIo make_runtime_server_loop_io() {
    return ServerLoopIo{
        .current_time = [] { return now(); },
        .receive_datagram =
            [](int socket_fd, int flags, std::string_view role_name) {
                return receive_datagram(socket_fd, role_name, flags);
            },
        .wait_for_socket_or_deadline =
            [](const RuntimeWaitConfig &config,
               const std::optional<QuicCoreTimePoint> &next_wakeup) {
                return wait_for_socket_or_deadline(config, next_wakeup);
            },
    };
}

int run_http09_server_loop(int socket_fd, const ServerLoopIo &io, const ServerLoopDriver &driver) {
    for (;;) {
        for (;;) {
            bool processed_timers = false;
            driver.process_expired_timers(io.current_time(), processed_timers);
            if (processed_timers) {
                continue;
            }

            driver.pump_endpoint_work();

            auto receive =
                io.receive_datagram(socket_fd, /*flags=*/MSG_DONTWAIT, /*role_name=*/"server");
            if (receive.status == ReceiveDatagramStatus::would_block) {
                if (driver.has_pending_endpoint_work()) {
                    continue;
                }
                break;
            }
            if (receive.status == ReceiveDatagramStatus::error) {
                return 1;
            }
            if (!driver.process_datagram(std::move(receive.step))) {
                return 1;
            }
        }

        bool processed_timers = false;
        driver.process_expired_timers(io.current_time(), processed_timers);
        if (processed_timers) {
            continue;
        }

        driver.pump_endpoint_work();
        if (driver.has_pending_endpoint_work()) {
            continue;
        }

        auto step = io.wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fd = socket_fd,
                .idle_timeout_ms = kServerIdleTimeoutMs,
                .role_name = "server",
            },
            driver.earliest_wakeup());
        if (!step.has_value()) {
            return 1;
        }
        if (step->idle_timeout) {
            continue;
        }
        if (!step->input.has_value()) {
            std::cerr << "http09-server failed: runtime step missing input\n";
            return 1;
        }
        const auto &step_input = *step->input;
        if (std::holds_alternative<QuicCoreTimerExpired>(step_input)) {
            driver.process_expired_timers(step->input_time, processed_timers);
            continue;
        }

        if (!driver.process_datagram(std::move(*step))) {
            return 1;
        }
    }
}

int run_http09_server(const Http09RuntimeConfig &config) {
    ResolvedUdpAddress bind_address{};
    if (!resolve_udp_address(
            UdpAddressResolutionQuery{
                .host = config.host,
                .port = config.port,
                .extra_flags = AI_PASSIVE,
            },
            bind_address)) {
        std::cerr << "http09-server failed: invalid host address\n";
        return 1;
    }

    const int socket_fd = open_udp_socket(bind_address.family);
    if (socket_fd < 0) {
        std::cerr << "http09-server failed: unable to create UDP socket: " << std::strerror(errno)
                  << '\n';
        return 1;
    }
    ScopedFd socket_guard(socket_fd);

    if (runtime_ops().bind_fn(socket_fd, reinterpret_cast<const sockaddr *>(&bind_address.address),
                              bind_address.address_len) != 0) {
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

    ServerSessionMap sessions;
    std::unordered_map<std::string, std::string> initial_destination_routes;
    RetryTokenStore retry_tokens;
    std::uint64_t next_connection_index = 1;

    const EraseServerSessionFn erase_session = [&](const std::string &local_connection_id_key) {
        const auto &session = *sessions.at(local_connection_id_key);
        initial_destination_routes.erase(session.initial_destination_connection_id_key);
        sessions.erase(local_connection_id_key);
    };

    auto create_session =
        [&](const ConnectionId &initial_destination_connection_id, const sockaddr_storage &peer,
            socklen_t peer_len,
            const std::optional<PendingRetryToken> &retry_context) -> ServerSession & {
        auto core_config =
            make_runtime_server_core_config(config, identity, next_connection_index++);
        if (retry_context.has_value()) {
            core_config.source_connection_id = retry_context->retry_source_connection_id;
            core_config.initial_destination_connection_id =
                retry_context->retry_source_connection_id;
            core_config.original_destination_connection_id =
                retry_context->original_destination_connection_id;
            core_config.retry_source_connection_id = retry_context->retry_source_connection_id;
            core_config.original_version = retry_context->original_version;
            core_config.initial_version = retry_context->original_version;
        }
        const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
        const auto &trace_original_destination_connection_id =
            retry_context.has_value() ? retry_context->original_destination_connection_id
                                      : initial_destination_connection_id;
        if (runtime_trace_enabled()) {
            std::cerr << "http09-server trace: create-session scid="
                      << format_connection_id_hex(core_config.source_connection_id) << " odcid="
                      << format_connection_id_hex(trace_original_destination_connection_id) << '\n';
        }
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

    const auto process_server_datagram = [&](RuntimeWaitStep step) -> bool {
        const auto &inbound = std::get<QuicCoreInboundDatagram>(*step.input);

        const auto parsed = parse_server_datagram_for_routing(inbound.bytes);
        if (!parsed.has_value()) {
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-server trace: ignored-unparseable-datagram bytes="
                       << inbound.bytes.size() << '\n';
            });
            return true;
        }

        auto session_it =
            find_server_session_for_datagram(sessions, initial_destination_routes, *parsed);

        if (session_it != sessions.end()) {
            return process_existing_server_session_datagram(*session_it->second, step, *parsed,
                                                            socket_fd, erase_session);
        }

        if (parsed->kind == ParsedServerDatagram::Kind::unsupported_version_long_header) {
            return send_version_negotiation_for_probe(socket_fd, inbound.bytes, *parsed,
                                                      step.source, step.source_len);
        }

        if (parsed->kind != ParsedServerDatagram::Kind::supported_initial) {
            return true;
        }

        auto retry_preparation = prepare_supported_initial_retry_handling(
            config.retry_enabled, socket_fd, *parsed, step.source, step.source_len, retry_tokens,
            next_connection_index);
        if (retry_preparation.immediate_result.has_value()) {
            return *retry_preparation.immediate_result;
        }
        auto retry_context = std::move(retry_preparation.retry_context);

        const auto &trace_original_destination_connection_id =
            retry_context.has_value() ? retry_context->original_destination_connection_id
                                      : parsed->destination_connection_id;
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-server trace: new-initial odcid="
                   << format_connection_id_hex(trace_original_destination_connection_id)
                   << " len=" << parsed->destination_connection_id.size() << '\n';
        });

        auto &session = create_session(parsed->destination_connection_id, step.source,
                                       step.source_len, retry_context);
        auto session_input = std::move(*step.input);
        const auto session_result = session.core.advance(std::move(session_input), step.input_time);
        const bool endpoint_failed = !drive_endpoint_until_blocked(
            make_endpoint_driver(session.endpoint), session.core, socket_fd, &session.peer,
            session.peer_len, session_result, session.state, "server");
        const bool core_failed = session.core.has_failed();
        if (endpoint_failed | core_failed) {
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-server trace: new-session-failed scid="
                       << format_connection_id_key_hex(session.local_connection_id_key)
                       << " odcid=" << format_connection_id_hex(parsed->destination_connection_id)
                       << '\n';
            });
            erase_session(session.local_connection_id_key);
        }
        return true;
    };

    return run_http09_server_loop(
        socket_fd, make_runtime_server_loop_io(),
        ServerLoopDriver{
            .earliest_wakeup = [&] { return earliest_server_session_wakeup(sessions); },
            .process_expired_timers =
                [&](QuicCoreTimePoint current, bool &processed_any) {
                    process_expired_server_sessions(sessions, socket_fd, current, erase_session,
                                                    processed_any);
                },
            .pump_endpoint_work =
                [&] { pump_server_pending_endpoint_work(sessions, socket_fd, erase_session); },
            .has_pending_endpoint_work = [&] { return has_pending_server_endpoint_work(sessions); },
            .process_datagram =
                [&](RuntimeWaitStep step) { return process_server_datagram(std::move(step)); },
        });
}

} // namespace

namespace test {

namespace {

struct ScriptedEndpointForTests {
    std::vector<QuicHttp09EndpointUpdate> on_core_result_updates;
    std::vector<QuicHttp09EndpointUpdate> poll_updates;
    std::size_t next_on_core_result_index = 0;
    std::size_t next_poll_index = 0;

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult &, QuicCoreTimePoint) {
        if (next_on_core_result_index >= on_core_result_updates.size()) {
            return {};
        }
        return on_core_result_updates[next_on_core_result_index++];
    }

    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint) {
        if (next_poll_index >= poll_updates.size()) {
            return {};
        }
        return poll_updates[next_poll_index++];
    }
};

QuicCore make_failing_server_core_for_tests() {
    const auto config = Http09RuntimeConfig{
        .mode = Http09RuntimeMode::server,
    };
    return QuicCore(make_http09_server_core_config(config));
}

QuicCore make_local_error_client_core_for_tests() {
    const auto config = Http09RuntimeConfig{
        .mode = Http09RuntimeMode::client,
    };
    return QuicCore(make_http09_client_core_config(config));
}

struct ScriptedClientLoopIoForTests {
    std::vector<QuicCoreTimePoint> now_values;
    std::vector<ReceiveDatagramResult> receive_results;
    std::vector<std::optional<RuntimeWaitStep>> wait_steps;
    std::size_t next_now_index = 0;
    std::size_t next_receive_index = 0;
    std::size_t next_wait_index = 0;
};

QuicCoreTimePoint scripted_client_loop_now_for_tests(void *context) {
    auto &script = *static_cast<ScriptedClientLoopIoForTests *>(context);
    if (script.next_now_index >= script.now_values.size()) {
        return now();
    }
    return script.now_values[script.next_now_index++];
}

ReceiveDatagramResult scripted_client_loop_receive_for_tests(void *context, int, int,
                                                             std::string_view) {
    auto &script = *static_cast<ScriptedClientLoopIoForTests *>(context);
    if (script.next_receive_index >= script.receive_results.size()) {
        return ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::would_block,
        };
    }
    return std::move(script.receive_results[script.next_receive_index++]);
}

std::optional<RuntimeWaitStep>
scripted_client_loop_wait_for_tests(void *context, const RuntimeWaitConfig &,
                                    const std::optional<QuicCoreTimePoint> &) {
    auto &script = *static_cast<ScriptedClientLoopIoForTests *>(context);
    if (script.next_wait_index >= script.wait_steps.size()) {
        return std::nullopt;
    }
    return std::move(script.wait_steps[script.next_wait_index++]);
}

ClientLoopIo make_scripted_client_loop_io_for_tests(ScriptedClientLoopIoForTests &script) {
    return ClientLoopIo{
        .context = &script,
        .now_fn = &scripted_client_loop_now_for_tests,
        .receive_datagram_fn = &scripted_client_loop_receive_for_tests,
        .wait_for_socket_or_deadline_fn = &scripted_client_loop_wait_for_tests,
    };
}

ReceiveDatagramResult make_would_block_receive_for_tests() {
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::would_block,
    };
}

ReceiveDatagramResult make_error_receive_for_tests() {
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::error,
    };
}

ReceiveDatagramResult make_input_receive_for_tests(QuicCoreInput input) {
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::ok,
        .step =
            RuntimeWaitStep{
                .input = std::move(input),
                .input_time = now(),
            },
    };
}

RuntimeWaitStep make_idle_timeout_wait_step_for_tests() {
    return RuntimeWaitStep{
        .input_time = now(),
        .idle_timeout = true,
    };
}

RuntimeWaitStep make_input_wait_step_for_tests(QuicCoreInput input) {
    return RuntimeWaitStep{
        .input = std::move(input),
        .input_time = now(),
    };
}

struct ScriptedServerLoopCaseForTests {
    std::vector<ReceiveDatagramResult> receive_results;
    std::vector<std::optional<RuntimeWaitStep>> wait_steps;
    std::vector<bool> processed_timers_results;
    std::vector<bool> pending_work_after_pump;
    bool process_datagram_result = true;
};

ScriptedServerLoopCaseForTests
make_nonblocking_processed_timers_then_receive_error_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_error_receive_for_tests(),
            },
        .processed_timers_results = {true, false},
    };
}

ScriptedServerLoopCaseForTests make_nonblocking_process_datagram_failure_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_input_receive_for_tests(QuicCoreTimerExpired{}),
            },
        .processed_timers_results = {false},
        .process_datagram_result = false,
    };
}

ScriptedServerLoopCaseForTests make_blocking_timer_then_receive_error_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .wait_steps =
            {
                make_input_wait_step_for_tests(QuicCoreTimerExpired{}),
            },
        .processed_timers_results = {false, false, false, false},
    };
}

ScriptedServerLoopCaseForTests make_blocking_processed_timers_then_receive_error_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .processed_timers_results = {false, true, false},
    };
}

ScriptedServerLoopCaseForTests make_blocking_wait_failure_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
            },
        .wait_steps =
            {
                std::nullopt,
            },
        .processed_timers_results = {false, false},
    };
}

ScriptedServerLoopCaseForTests make_blocking_wait_missing_input_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
            },
        .wait_steps =
            {
                RuntimeWaitStep{
                    .input_time = now(),
                },
            },
        .processed_timers_results = {false, false},
    };
}

ScriptedServerLoopCaseForTests
make_nonblocking_drain_repeats_pending_endpoint_progress_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .wait_steps =
            {
                std::nullopt,
            },
        .processed_timers_results = {false, false, false},
        .pending_work_after_pump = {true, true, false},
    };
}

ScriptedServerLoopCaseForTests make_outer_pump_repeats_pending_endpoint_progress_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_error_receive_for_tests(),
            },
        .processed_timers_results = {false},
        .pending_work_after_pump = {false, true, false},
    };
}

using ServerLoopCaseFactoryForTests = ScriptedServerLoopCaseForTests (*)();

ServerLoopCaseFactoryForTests server_loop_case_factories_for_tests[] = {
    &make_nonblocking_processed_timers_then_receive_error_case_for_tests,
    &make_nonblocking_process_datagram_failure_case_for_tests,
    &make_blocking_timer_then_receive_error_case_for_tests,
    &make_blocking_processed_timers_then_receive_error_case_for_tests,
    &make_blocking_wait_failure_case_for_tests,
    &make_blocking_wait_missing_input_case_for_tests,
    &make_nonblocking_drain_repeats_pending_endpoint_progress_case_for_tests,
    &make_outer_pump_repeats_pending_endpoint_progress_case_for_tests,
};

std::vector<std::byte> bytes_from_string_for_runtime_tests(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const char ch : text) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    }
    return bytes;
}

struct ScopedRuntimeTempDirForTests {
    ScopedRuntimeTempDirForTests() {
        path_ = std::filesystem::temp_directory_path() /
                ("coquic-runtime-tests-" + std::to_string(::getpid()) + "-" +
                 std::to_string(counter_++));
        std::filesystem::create_directories(path_);
    }

    ~ScopedRuntimeTempDirForTests() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    void write_file(const std::filesystem::path &relative_path, std::string_view contents) const {
        const auto absolute_path = path_ / relative_path;
        std::filesystem::create_directories(absolute_path.parent_path());
        std::ofstream output(absolute_path, std::ios::binary);
        output << contents;
    }

    const std::filesystem::path &path() const {
        return path_;
    }

  private:
    inline static std::uint64_t counter_ = 0;
    std::filesystem::path path_;
};

QuicCoreResult single_receive_result_for_runtime_tests(std::uint64_t stream_id,
                                                       std::string_view text, bool fin) {
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreReceiveStreamData{
        .stream_id = stream_id,
        .bytes = bytes_from_string_for_runtime_tests(text),
        .fin = fin,
    });
    return result;
}

QuicCore make_failed_server_core_for_tests() {
    auto core = make_failing_server_core_for_tests();
    static_cast<void>(core.advance(
        QuicCoreInboundDatagram{
            .bytes = {std::byte{0x00}},
        },
        now()));
    return core;
}

} // namespace

ScopedHttp09RuntimeOpsOverride::ScopedHttp09RuntimeOpsOverride(
    Http09RuntimeOpsOverride override_ops)
    : previous_(runtime_ops()) {
    apply_runtime_ops_override(override_ops);
}

ScopedHttp09RuntimeOpsOverride::~ScopedHttp09RuntimeOpsOverride() {
    runtime_ops() = previous_;
}

bool runtime_trace_enabled_for_tests() {
    return runtime_trace_enabled();
}

std::string format_connection_id_hex_for_tests(std::span<const std::byte> connection_id) {
    return format_connection_id_hex(connection_id);
}

std::string format_connection_id_key_hex_for_tests(std::string_view connection_id_key) {
    return format_connection_id_key_hex(connection_id_key);
}

std::string connection_id_key_for_tests(std::span<const std::byte> connection_id) {
    return connection_id_key(connection_id);
}

int client_receive_timeout_ms_for_tests(const Http09RuntimeConfig &config) {
    return client_receive_timeout_ms(config);
}

QuicHttp09ClientConfig make_http09_client_endpoint_config_for_tests(
    const Http09RuntimeConfig &config, const std::vector<QuicHttp09Request> &requests,
    bool attempt_zero_rtt_requests, const QuicCoreResult &start_result) {
    return make_http09_client_endpoint_config(config, requests, attempt_zero_rtt_requests,
                                              start_result);
}

int run_http09_client_connection_for_tests(const Http09RuntimeConfig &config,
                                           const std::vector<QuicHttp09Request> &requests,
                                           std::uint64_t connection_index) {
    return run_http09_client_connection(config, requests, connection_index);
}

std::optional<RuntimeWaitStepForTests>
wait_for_socket_or_deadline_for_tests(int socket_fd, int idle_timeout_ms,
                                      std::string_view role_name,
                                      const std::optional<QuicCoreTimePoint> &next_wakeup) {
    const auto step = wait_for_socket_or_deadline(
        RuntimeWaitConfig{
            .socket_fd = socket_fd,
            .idle_timeout_ms = idle_timeout_ms,
            .role_name = role_name,
        },
        next_wakeup);
    if (!step.has_value()) {
        return std::nullopt;
    }

    RuntimeWaitStepForTests result{
        .has_input = step->input.has_value(),
        .idle_timeout = step->idle_timeout,
        .has_source = step->has_source,
        .input_is_timer_expired =
            step->input.has_value() && std::holds_alternative<QuicCoreTimerExpired>(*step->input),
        .source_len = step->source_len,
    };
    if (step->input.has_value()) {
        if (const auto *inbound = std::get_if<QuicCoreInboundDatagram>(&*step->input);
            inbound != nullptr) {
            result.inbound_datagram_bytes = inbound->bytes.size();
        }
    }
    return result;
}

std::optional<QuicCoreTimePoint>
earliest_runtime_wakeup_for_tests(std::span<const std::optional<QuicCoreTimePoint>> wakeups) {
    return earliest_wakeup_in_range(
        wakeups, [](const std::optional<QuicCoreTimePoint> &wakeup) { return wakeup; });
}

DriveEndpointUntilBlockedResultForTests
drive_endpoint_until_blocked_case_for_tests(DriveEndpointUntilBlockedCaseForTests case_id) {
    ScriptedEndpointForTests endpoint;
    QuicCore core = make_failing_server_core_for_tests();
    EndpointDriveState state;
    QuicCoreResult initial_result;
    sockaddr_storage peer{};
    const sockaddr_storage *peer_ptr = &peer;

    using DriveEndpointCaseSetupFn =
        void (*)(ScriptedEndpointForTests &, QuicCore &, QuicCoreResult &);
    static const auto kDriveEndpointCaseSetups = std::to_array<DriveEndpointCaseSetupFn>({
        [](ScriptedEndpointForTests &, QuicCore &, QuicCoreResult &setup_result) {
            setup_result.effects.emplace_back(QuicCoreSendDatagram{
                .bytes = {std::byte{0x01}},
            });
        },
        [](ScriptedEndpointForTests &, QuicCore &, QuicCoreResult &setup_result) {
            setup_result.local_error = QuicCoreLocalError{
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, QuicCore &, QuicCoreResult &setup_result) {
            setup_result.local_error = QuicCoreLocalError{
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .handled_local_error = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, QuicCore &, QuicCoreResult &) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, QuicCore &, QuicCoreResult &) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, QuicCore &setup_core, QuicCoreResult &) {
            setup_core = make_local_error_client_core_for_tests();
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .core_inputs =
                    {
                        QuicCoreStopSending{
                            .stream_id = 2,
                            .application_error_code = 7,
                        },
                    },
            });
        },
    });
    kDriveEndpointCaseSetups[static_cast<std::size_t>(case_id)](endpoint, core, initial_result);

    const bool returned =
        drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core,
                                     /*fd=*/-1, peer_ptr,
                                     /*peer_len=*/0, initial_result, state, "client");
    return DriveEndpointUntilBlockedResultForTests{
        .returned = returned,
        .terminal_success = state.terminal_success,
        .terminal_failure = state.terminal_failure,
        .endpoint_has_pending_work = state.endpoint_has_pending_work,
    };
}

ClientConnectionLoopResultForTests
run_client_connection_loop_case_for_tests(ClientConnectionLoopCaseForTests case_id) {
    ScriptedEndpointForTests endpoint;
    ScriptedClientLoopIoForTests io_script;
    QuicCore core = make_local_error_client_core_for_tests();
    EndpointDriveState state;
    QuicCoreResult start_result;
    sockaddr_storage peer{};
    const auto base_time = now();

    using ClientLoopCaseSetupFn =
        void (*)(ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &, QuicCore &,
                 QuicCoreResult &, QuicCoreTimePoint);
    static const auto kClientLoopCaseSetups = std::to_array<ClientLoopCaseSetupFn>({
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time;
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(std::nullopt);
            setup_io.now_values = {setup_base_time, setup_base_time};
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time;
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.now_values = {setup_base_time};
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time + std::chrono::milliseconds(1);
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.now_values = {
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(2),
                setup_base_time + std::chrono::milliseconds(3),
                setup_base_time + std::chrono::milliseconds(4),
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time + std::chrono::milliseconds(1);
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.now_values = {
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(2),
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_io.receive_results.push_back(make_error_receive_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.receive_results.push_back(
                make_input_receive_for_tests(QuicCoreTimerExpired{}));
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &, QuicCore &, QuicCoreResult &,
           QuicCoreTimePoint) {},
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreTimerExpired{}));
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreInboundDatagram{
                .bytes = {std::byte{0x01}},
            }));
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreInboundDatagram{
                .bytes = {std::byte{0x02}},
            }));
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_failure = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(make_input_wait_step_for_tests(QuicCoreTimerExpired{}));
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &, QuicCoreTimePoint) {
            setup_io.wait_steps.push_back(RuntimeWaitStep{
                .input_time = now(),
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint setup_base_time) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(ReceiveDatagramResult{
                .status = ReceiveDatagramStatus::ok,
                .step =
                    RuntimeWaitStep{
                        .input =
                            QuicCoreInboundDatagram{
                                .bytes = {std::byte{0x01}},
                            },
                        .input_time = setup_base_time + std::chrono::milliseconds(1),
                    },
            });
            setup_io.now_values = {
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(2),
                setup_base_time + std::chrono::milliseconds(3),
                setup_base_time + std::chrono::milliseconds(4),
                setup_base_time + std::chrono::milliseconds(5),
                setup_base_time + std::chrono::milliseconds(6),
            };
            setup_io.wait_steps.push_back(RuntimeWaitStep{
                .input_time = setup_base_time + std::chrono::milliseconds(7),
                .idle_timeout = true,
            });
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint setup_base_time) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(ReceiveDatagramResult{
                .status = ReceiveDatagramStatus::ok,
                .step =
                    RuntimeWaitStep{
                        .input =
                            QuicCoreInboundDatagram{
                                .bytes = {std::byte{0x01}},
                            },
                        .input_time = setup_base_time + std::chrono::milliseconds(1),
                    },
            });
            setup_io.now_values = {
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(kClientSuccessDrainWindowMs + 2),
            };
        },
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &, QuicCoreResult &, QuicCoreTimePoint) {
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
                .has_pending_work = true,
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .core_inputs =
                    {
                        QuicCoreTimerExpired{},
                    },
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .core_inputs =
                    {
                        QuicCoreTimerExpired{},
                    },
            });
            setup_endpoint.poll_updates.push_back(QuicHttp09EndpointUpdate{
                .terminal_success = true,
            });
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time + std::chrono::milliseconds(5);
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
            setup_io.now_values = {
                setup_base_time,
                setup_base_time,
                setup_base_time,
            };
        },
        [](ScriptedEndpointForTests &, ScriptedClientLoopIoForTests &setup_io, QuicCore &,
           QuicCoreResult &setup_start_result, QuicCoreTimePoint setup_base_time) {
            setup_start_result.next_wakeup = setup_base_time + std::chrono::milliseconds(1);
            setup_io.wait_steps.push_back(make_idle_timeout_wait_step_for_tests());
            setup_io.now_values = {
                setup_base_time,
                setup_base_time,
                setup_base_time + std::chrono::milliseconds(3),
            };
        },
    });
    kClientLoopCaseSetups[static_cast<std::size_t>(case_id)](endpoint, io_script, core,
                                                             start_result, base_time);

    const int exit_code = run_http09_client_connection_loop(
        make_endpoint_driver(endpoint), core, /*socket_fd=*/-1,
        /*idle_timeout_ms=*/kDefaultClientReceiveTimeoutMs, peer, /*peer_len=*/0, state,
        make_scripted_client_loop_io_for_tests(io_script), start_result);
    return ClientConnectionLoopResultForTests{
        .exit_code = exit_code,
        .terminal_success = state.terminal_success,
        .terminal_failure = state.terminal_failure,
        .endpoint_has_pending_work = state.endpoint_has_pending_work,
        .receive_calls = io_script.next_receive_index,
        .wait_calls = io_script.next_wait_index,
        .current_time_calls = io_script.next_now_index,
    };
}

void record_erased_server_session_key_for_tests(std::string *erased_key,
                                                const std::string &local_connection_id_key) {
    *erased_key = local_connection_id_key;
}

bool existing_server_session_failure_cleans_up_for_tests() {
    auto session = std::make_unique<ServerSession>(ServerSession{
        .core = make_failed_server_core_for_tests(),
        .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = std::filesystem::temp_directory_path(),
        }),
        .state = EndpointDriveState{},
        .peer = {},
        .peer_len = 0,
        .local_connection_id_key = "existing-session",
        .initial_destination_connection_id_key = "initial-route",
    });

    std::string erased_key;
    RuntimeWaitStep step{
        .input = QuicCoreTimerExpired{},
        .input_time = now(),
        .has_source = true,
    };
    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .destination_connection_id = {std::byte{0x83}},
    };
    process_existing_server_session_datagram(
        *session, step, parsed, /*socket_fd=*/-1,
        std::bind_front(&record_erased_server_session_key_for_tests, &erased_key));
    return !erased_key.empty();
}

bool existing_server_session_missing_input_fails_for_tests() {
    auto session = std::make_unique<ServerSession>(ServerSession{
        .core = make_failed_server_core_for_tests(),
        .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = std::filesystem::temp_directory_path(),
        }),
        .state = EndpointDriveState{},
        .peer = {},
        .peer_len = 0,
        .local_connection_id_key = "existing-session",
        .initial_destination_connection_id_key = "initial-route",
    });

    std::string erased_key;
    RuntimeWaitStep step{
        .input_time = now(),
        .has_source = true,
    };
    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .destination_connection_id = {std::byte{0x83}},
    };
    const bool processed = process_existing_server_session_datagram(
        *session, step, parsed, /*socket_fd=*/-1,
        std::bind_front(&record_erased_server_session_key_for_tests, &erased_key));
    return !processed & erased_key.empty();
}

bool supported_long_header_routes_via_initial_destination_for_tests() {
    const ConnectionId initial_destination_connection_id = {std::byte{0x69}};
    const auto initial_destination_connection_id_key =
        connection_id_key(initial_destination_connection_id);

    ServerSessionMap sessions;
    sessions.emplace(
        "existing-session",
        std::make_unique<ServerSession>(ServerSession{
            .core = make_failed_server_core_for_tests(),
            .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                .document_root = std::filesystem::temp_directory_path(),
            }),
            .state = EndpointDriveState{},
            .peer = {},
            .peer_len = 0,
            .local_connection_id_key = "existing-session",
            .initial_destination_connection_id_key = initial_destination_connection_id_key,
        }));

    std::unordered_map<std::string, std::string> initial_destination_routes;
    initial_destination_routes.emplace(initial_destination_connection_id_key, "existing-session");

    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::supported_long_header,
        .destination_connection_id = initial_destination_connection_id,
    };

    return find_server_session_for_datagram(sessions, initial_destination_routes, parsed) !=
           sessions.end();
}

bool expired_server_timer_failure_cleans_up_for_tests() {
    ServerSessionMap sessions;
    sessions.emplace("expired-session",
                     std::make_unique<ServerSession>(ServerSession{
                         .core = make_failed_server_core_for_tests(),
                         .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                             .document_root = std::filesystem::temp_directory_path(),
                         }),
                         .state =
                             EndpointDriveState{
                                 .next_wakeup = now(),
                             },
                         .peer = {},
                         .peer_len = 0,
                         .local_connection_id_key = "expired-session",
                         .initial_destination_connection_id_key = "expired-route",
                     }));
    bool processed_any = false;
    const auto erase_session = std::bind_front(erase_server_session_from_map, std::ref(sessions));
    process_expired_server_sessions(sessions, /*socket_fd=*/-1, now(), erase_session,
                                    processed_any);
    return processed_any & sessions.empty();
}

bool expired_server_timer_success_preserves_session_for_tests() {
    ServerSessionMap sessions;
    sessions.emplace("expired-session",
                     std::make_unique<ServerSession>(ServerSession{
                         .core = QuicCore(make_http09_server_core_config(Http09RuntimeConfig{
                             .mode = Http09RuntimeMode::server,
                         })),
                         .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                             .document_root = std::filesystem::temp_directory_path(),
                         }),
                         .state =
                             EndpointDriveState{
                                 .next_wakeup = now(),
                             },
                         .peer = {},
                         .peer_len = 0,
                         .local_connection_id_key = "expired-session",
                         .initial_destination_connection_id_key = "expired-route",
                     }));
    bool processed_any = false;
    const auto erase_session = std::bind_front(erase_server_session_from_map, std::ref(sessions));
    process_expired_server_sessions(sessions, /*socket_fd=*/-1, now(), erase_session,
                                    processed_any);
    return processed_any & (sessions.size() == 1);
}

bool pending_server_work_failure_cleans_up_for_tests() {
    ScopedRuntimeTempDirForTests document_root;
    document_root.write_file("large.bin", std::string(static_cast<std::size_t>(20) * 1024U, 'x'));

    QuicHttp09ServerEndpoint endpoint(QuicHttp09ServerConfig{
        .document_root = document_root.path(),
    });
    const auto update = endpoint.on_core_result(
        single_receive_result_for_runtime_tests(0, "GET /large.bin\r\n", true), now());

    ServerSessionMap sessions;
    sessions.emplace("pending-session",
                     std::make_unique<ServerSession>(ServerSession{
                         .core = make_failed_server_core_for_tests(),
                         .endpoint = std::move(endpoint),
                         .state =
                             EndpointDriveState{
                                 .endpoint_has_pending_work = update.has_pending_work,
                             },
                         .peer = {},
                         .peer_len = 0,
                         .local_connection_id_key = "pending-session",
                         .initial_destination_connection_id_key = "pending-route",
                     }));
    pump_server_pending_endpoint_work(sessions, /*socket_fd=*/-1,
                                      [&](const std::string &local_connection_id_key) {
                                          sessions.erase(local_connection_id_key);
                                      });
    return update.has_pending_work & sessions.empty();
}

bool retry_context_lookup_for_tests() {
    const auto make_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };

    const auto peer = make_peer(4433);
    const auto mismatched_peer = make_peer(4434);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    const auto token = make_runtime_retry_token(7);
    const auto retry_source_connection_id = make_runtime_connection_id(std::byte{0x73}, 7);
    const auto original_destination_connection_id = make_runtime_connection_id(std::byte{0x83}, 7);

    const auto make_retry_tokens = [&] {
        RetryTokenStore retry_tokens;
        retry_tokens.emplace(
            connection_id_key(token),
            PendingRetryToken{
                .original_destination_connection_id = original_destination_connection_id,
                .retry_source_connection_id = retry_source_connection_id,
                .original_version = kQuicVersion1,
                .peer = peer,
                .peer_len = peer_len,
            });
        return retry_tokens;
    };

    const ParsedServerDatagram matching{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = retry_source_connection_id,
        .source_connection_id = ConnectionId{std::byte{0x01}},
        .token = token,
    };

    auto missing_token_store = make_retry_tokens();
    auto missing_token = matching;
    missing_token.token = {std::byte{0x00}};
    const bool missing_token_rejected =
        !lookup_retry_context(missing_token, peer, peer_len, missing_token_store).has_value() &
        (missing_token_store.size() == 1);

    auto mismatched_peer_store = make_retry_tokens();
    const bool mismatched_peer_rejected =
        !lookup_retry_context(matching, mismatched_peer, peer_len, mismatched_peer_store)
             .has_value() &
        (mismatched_peer_store.size() == 1);

    auto mismatched_dcid_store = make_retry_tokens();
    auto mismatched_dcid = matching;
    mismatched_dcid.destination_connection_id = make_runtime_connection_id(std::byte{0x74}, 7);
    const bool mismatched_dcid_rejected =
        !lookup_retry_context(mismatched_dcid, peer, peer_len, mismatched_dcid_store).has_value() &
        (mismatched_dcid_store.size() == 1);

    auto mismatched_version_store = make_retry_tokens();
    auto mismatched_version = matching;
    mismatched_version.version = kQuicVersion2;
    const bool mismatched_version_rejected =
        !lookup_retry_context(mismatched_version, peer, peer_len, mismatched_version_store)
             .has_value() &
        (mismatched_version_store.size() == 1);

    auto matched_store = make_retry_tokens();
    const auto matched = lookup_retry_context(matching, peer, peer_len, matched_store);
    const auto matched_value = matched.value_or(PendingRetryToken{});
    const bool matched_and_erased =
        matched.has_value() &
        (matched_value.original_destination_connection_id == original_destination_connection_id) &
        (matched_value.retry_source_connection_id == retry_source_connection_id) &
        (matched_value.original_version == kQuicVersion1) & matched_store.empty();
    return missing_token_rejected & mismatched_peer_rejected & mismatched_dcid_rejected &
           mismatched_version_rejected & matched_and_erased;
}

bool invalid_retry_token_server_datagram_path_for_tests() {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4433);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));

    RetryTokenStore retry_tokens;
    std::uint64_t next_connection_index = 1;
    const ParsedServerDatagram invalid_retry{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = make_runtime_connection_id(std::byte{0x91}, 9),
        .source_connection_id = ConnectionId{std::byte{0x02}},
        .token = make_runtime_retry_token(9),
    };

    const auto preparation = prepare_supported_initial_retry_handling(
        /*retry_enabled=*/true, /*socket_fd=*/-1, invalid_retry, peer, peer_len, retry_tokens,
        next_connection_index);
    return preparation.immediate_result.value_or(false) & !preparation.retry_context.has_value() &
           retry_tokens.empty() & (next_connection_index == 1);
}

bool resumed_client_warmup_failure_exits_early_for_tests() {
    const auto requests = parse_http09_requests_env("https://localhost/warmup.txt").value();
    Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
        .testcase = QuicHttp09Testcase::zerortt,
        .download_root = "downloads",
    };

    int calls = 0;
    const int exit_code = run_http09_resumed_client_sequence(
        config, requests,
        [&](const Http09RuntimeConfig &, const std::vector<QuicHttp09Request> &runner_requests,
            const QuicCoreConfig &core_config, std::uint64_t connection_index) {
            ++calls;
            const bool warmup_matches = (calls == 1) & (connection_index == 1) &
                                        (runner_requests.size() == 1) &
                                        (core_config.zero_rtt.application_context ==
                                         http09_zero_rtt_application_context(runner_requests));
            return ClientConnectionRunResult{
                .exit_code = 98 - (static_cast<int>(warmup_matches) * 91),
            };
        });
    return (exit_code == 7) & (calls == 1);
}

bool retry_trace_paths_for_tests() {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4433);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));

    RetryTokenStore retry_tokens;
    std::uint64_t next_connection_index = 1;
    const ParsedServerDatagram retry_initial{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = make_runtime_connection_id(std::byte{0x83}, 1),
        .source_connection_id = ConnectionId{std::byte{0x01}},
        .token = {},
    };
    const auto retry_result = maybe_send_retry_for_supported_initial(
        true, /*socket_fd=*/-1, retry_initial, peer, peer_len, retry_tokens, next_connection_index);
    const bool retry_send_failed = retry_result.has_value() & !retry_result.value_or(true) &
                                   (retry_tokens.size() == 1) & (next_connection_index == 2);

    std::optional<PendingRetryToken> retry_context;
    const ParsedServerDatagram invalid_retry{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = make_runtime_connection_id(std::byte{0x91}, 9),
        .source_connection_id = ConnectionId{std::byte{0x02}},
        .token = make_runtime_retry_token(9),
    };
    const bool invalid_retry_ignored =
        !populate_retry_context_if_required(true, invalid_retry, peer, peer_len, retry_tokens,
                                            retry_context) &
        !retry_context.has_value();
    return retry_send_failed & invalid_retry_ignored;
}

bool send_retry_for_initial_failures_for_tests() {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4433);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));

    RetryTokenStore missing_source_tokens;
    const ParsedServerDatagram missing_source_connection_id{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = make_runtime_connection_id(std::byte{0x83}, 1),
        .source_connection_id = std::nullopt,
        .token = {},
    };
    const bool missing_source_rejected =
        !send_retry_for_initial(/*fd=*/-1, missing_source_connection_id, peer, peer_len,
                                missing_source_tokens, 1) &
        missing_source_tokens.empty();

    RetryTokenStore oversized_source_tokens;
    const ParsedServerDatagram oversized_source_connection_id{
        .kind = ParsedServerDatagram::Kind::supported_initial,
        .version = kQuicVersion1,
        .destination_connection_id = make_runtime_connection_id(std::byte{0x83}, 2),
        .source_connection_id = ConnectionId(21, std::byte{0xaa}),
        .token = {},
    };
    const bool oversized_source_rejected =
        !send_retry_for_initial(/*fd=*/-1, oversized_source_connection_id, peer, peer_len,
                                oversized_source_tokens, 2) &
        (oversized_source_tokens.size() == 1);
    return missing_source_rejected & oversized_source_rejected;
}

bool zero_rtt_request_allowance_for_tests() {
    const auto make_result = [](std::optional<QuicZeroRttStatus> status) {
        QuicCoreResult result;
        if (status.has_value()) {
            result.effects.emplace_back(QuicCoreZeroRttStatusEvent{.status = *status});
        }
        return result;
    };

    const bool unavailable_rejected =
        !allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::unavailable));
    const bool not_attempted_rejected =
        !allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::not_attempted));
    const bool rejected_rejected =
        !allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::rejected));
    const bool attempted_allowed =
        allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::attempted));
    const bool accepted_allowed =
        allow_requests_before_handshake_ready(true, make_result(QuicZeroRttStatus::accepted));
    const bool missing_status_allowed =
        allow_requests_before_handshake_ready(true, make_result(std::nullopt));
    const bool disabled_rejected =
        !allow_requests_before_handshake_ready(false, make_result(QuicZeroRttStatus::accepted));
    return unavailable_rejected & not_attempted_rejected & rejected_rejected & attempted_allowed &
           accepted_allowed & missing_status_allowed & disabled_rejected;
}

bool version_negotiation_without_source_connection_id_fails_for_tests() {
    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::unsupported_version_long_header,
        .destination_connection_id = {std::byte{0x83}},
        .source_connection_id = std::nullopt,
    };
    sockaddr_storage peer{};
    return !send_version_negotiation_for_probe(
        /*fd=*/-1, std::vector<std::byte>(kMinimumClientInitialDatagramBytes, std::byte{0x00}),
        parsed, peer,
        /*peer_len=*/0);
}

ServerLoopResultForTests run_server_loop_case_for_tests(ServerLoopCaseForTests case_id) {
    auto script = server_loop_case_factories_for_tests[static_cast<std::size_t>(case_id)]();
    std::size_t current_time_calls = 0;
    std::size_t receive_calls = 0;
    std::size_t wait_calls = 0;
    std::size_t process_expired_calls = 0;
    std::size_t pump_calls = 0;
    bool endpoint_has_pending_work = false;

    const auto io = ServerLoopIo{
        .current_time =
            [&] {
                current_time_calls += 1;
                return now();
            },
        .receive_datagram =
            [&](int, int, std::string_view) { return script.receive_results[receive_calls++]; },
        .wait_for_socket_or_deadline = [&](const RuntimeWaitConfig &,
                                           const std::optional<QuicCoreTimePoint> &)
            -> std::optional<RuntimeWaitStep> { return script.wait_steps[wait_calls++]; },
    };

    const auto driver = ServerLoopDriver{
        .earliest_wakeup = [] { return std::optional<QuicCoreTimePoint>{}; },
        .process_expired_timers =
            [&](QuicCoreTimePoint, bool &processed_any) {
                processed_any = script.processed_timers_results[process_expired_calls++];
            },
        .pump_endpoint_work =
            [&] {
                endpoint_has_pending_work = pump_calls < script.pending_work_after_pump.size()
                                                ? script.pending_work_after_pump[pump_calls]
                                                : false;
                pump_calls += 1;
            },
        .has_pending_endpoint_work = [&] { return endpoint_has_pending_work; },
        .process_datagram = [&](const RuntimeWaitStep &) { return script.process_datagram_result; },
    };

    return ServerLoopResultForTests{
        .exit_code = run_http09_server_loop(/*socket_fd=*/-1, io, driver),
        .current_time_calls = current_time_calls,
        .receive_calls = receive_calls,
        .wait_calls = wait_calls,
        .process_expired_calls = process_expired_calls,
        .pump_calls = pump_calls,
    };
}

std::optional<ParsedServerDatagramForTests>
parse_server_datagram_for_routing_for_tests(std::span<const std::byte> bytes) {
    const auto parsed = parse_server_datagram_for_routing(bytes);
    if (!parsed.has_value()) {
        return std::nullopt;
    }

    return ParsedServerDatagramForTests{
        .kind =
            std::array{
                ParsedServerDatagramKind::short_header,
                ParsedServerDatagramKind::supported_initial,
                ParsedServerDatagramKind::supported_long_header,
                ParsedServerDatagramKind::unsupported_version_long_header,
            }[static_cast<std::size_t>(parsed->kind)],
        .destination_connection_id = parsed->destination_connection_id,
        .source_connection_id = parsed->source_connection_id,
    };
}

} // namespace test

std::optional<ParsedHttp09Authority> parse_http09_authority(std::string_view authority) {
    return parse_http09_authority_impl(authority);
}

std::optional<Http09ClientRemote>
derive_http09_client_remote(const Http09RuntimeConfig &config,
                            const std::vector<QuicHttp09Request> &requests) {
    return derive_http09_client_remote_impl(config, requests);
}

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
        if (!apply_testcase_name(config, *testcase)) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }
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
    if (env_flag_enabled("RETRY")) {
        config.retry_enabled = true;
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

        if (arg == "--verify-peer") {
            config.verify_peer = true;
            continue;
        }
        if (arg == "--retry") {
            config.retry_enabled = true;
            continue;
        }

        const bool expects_value = arg == "--host" || arg == "--port" || arg == "--testcase" ||
                                   arg == "--requests" || arg == "--document-root" ||
                                   arg == "--download-root" || arg == "--certificate-chain" ||
                                   arg == "--private-key" || arg == "--server-name";
        if (!expects_value) {
            std::cerr << kUsageLine << '\n';
            return std::nullopt;
        }

        const auto value = require_value(arg);
        if (!value.has_value()) {
            return std::nullopt;
        }
        if (arg == "--host") {
            config.host = std::string(*value);
            host_specified = true;
            continue;
        }
        if (arg == "--port") {
            const auto parsed = parse_port(*value);
            if (!parsed.has_value()) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            config.port = *parsed;
            continue;
        }
        if (arg == "--testcase") {
            if (!apply_testcase_name(config, *value)) {
                std::cerr << kUsageLine << '\n';
                return std::nullopt;
            }
            continue;
        }
        if (arg == "--requests") {
            config.requests_env = std::string(*value);
            continue;
        }
        if (arg == "--document-root") {
            config.document_root = std::string(*value);
            continue;
        }
        if (arg == "--download-root") {
            config.download_root = std::string(*value);
            continue;
        }
        if (arg == "--certificate-chain") {
            config.certificate_chain_path = std::string(*value);
            continue;
        }
        if (arg == "--private-key") {
            config.private_key_path = std::string(*value);
            continue;
        }

        config.server_name = std::string(*value);
        server_name_specified = true;
        continue;
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
    const auto original_version = runtime_original_quic_version_for_testcase(config.testcase);
    const auto transfer_like_testcase = transfer_semantics_testcase(config.testcase);
    auto core = QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                              std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                              std::byte{0x57}, std::byte{0x08}},
        .original_version = original_version,
        .initial_version = original_version,
        .supported_versions = runtime_supported_quic_versions_for_testcase(config.testcase),
        .verify_peer = config.verify_peer,
        .server_name = config.server_name.empty() ? "localhost" : config.server_name,
        .application_protocol = std::string(kInteropApplicationProtocol),
        .transport = http09_client_transport_for_testcase(transfer_like_testcase),
        .allowed_tls_cipher_suites = http09_tls_cipher_suites_for_testcase(transfer_like_testcase),
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

    if (config.mode == Http09RuntimeMode::health_check) {
        return coquic::project_name().empty() | !coquic::openssl_available() |
               !coquic::logging_ready();
    }
    if (config.mode == Http09RuntimeMode::client) {
        return run_http09_client(config);
    }
    if (config.mode == Http09RuntimeMode::server) {
        return run_http09_server(config);
    }

    return 1;
}

} // namespace coquic::quic
