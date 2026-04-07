#include "src/quic/http09_runtime.h"
#include "src/quic/http09_runtime_test_hooks.h"
#include "src/quic/buffer.h"
#include "src/quic/packet.h"
#include "src/quic/packet_crypto.h"
#include "src/quic/version.h"

#include "src/coquic.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
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
#include <tuple>
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
    "handshake|transfer|keyupdate|amplificationlimit|rebind-port|rebind-addr|"
    "connectionmigration|ecn|multiconnect|chacha20|retry|resumption|zerortt|v2] "
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
        .setsockopt_fn = ::setsockopt,
        .sendto_fn = ::sendto,
        .sendmsg_fn = ::sendmsg,
        .recvfrom_fn = ::recvfrom,
        .recvmsg_fn = ::recvmsg,
        .getaddrinfo_fn = ::getaddrinfo,
        .freeaddrinfo_fn = ::freeaddrinfo,
        .gethostname_fn = ::gethostname,
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
    if (override_ops.setsockopt_fn != nullptr) {
        ops.setsockopt_fn = override_ops.setsockopt_fn;
    }
    if (override_ops.sendto_fn != nullptr) {
        ops.sendto_fn = override_ops.sendto_fn;
    }
    if (override_ops.sendmsg_fn != nullptr) {
        ops.sendmsg_fn = override_ops.sendmsg_fn;
    }
    if (override_ops.recvfrom_fn != nullptr) {
        ops.recvfrom_fn = override_ops.recvfrom_fn;
    }
    if (override_ops.recvmsg_fn != nullptr) {
        ops.recvmsg_fn = override_ops.recvmsg_fn;
    }
    if (override_ops.getaddrinfo_fn != nullptr) {
        ops.getaddrinfo_fn = override_ops.getaddrinfo_fn;
    }
    if (override_ops.freeaddrinfo_fn != nullptr) {
        ops.freeaddrinfo_fn = override_ops.freeaddrinfo_fn;
    }
    if (override_ops.gethostname_fn != nullptr) {
        ops.gethostname_fn = override_ops.gethostname_fn;
    }
}

bool has_legacy_sendto_override() {
    const auto defaults = make_default_runtime_ops();
    return runtime_ops().sendto_fn != defaults.sendto_fn &&
           runtime_ops().sendmsg_fn == defaults.sendmsg_fn;
}

bool has_legacy_recvfrom_override() {
    const auto defaults = make_default_runtime_ops();
    return runtime_ops().recvfrom_fn != defaults.recvfrom_fn &&
           runtime_ops().recvmsg_fn == defaults.recvmsg_fn;
}

bool is_ect_codepoint(QuicEcnCodepoint ecn) {
    return ecn == QuicEcnCodepoint::ect0 || ecn == QuicEcnCodepoint::ect1;
}

int linux_traffic_class_for_ecn(QuicEcnCodepoint ecn) {
    switch (ecn) {
    case QuicEcnCodepoint::ect0:
        return 0x02;
    case QuicEcnCodepoint::ect1:
        return 0x01;
    case QuicEcnCodepoint::ce:
        return 0x03;
    case QuicEcnCodepoint::unavailable:
    case QuicEcnCodepoint::not_ect:
        return 0x00;
    }
    return 0x00;
}

QuicEcnCodepoint ecn_from_linux_traffic_class(int traffic_class) {
    switch (traffic_class & 0x03) {
    case 0x01:
        return QuicEcnCodepoint::ect1;
    case 0x02:
        return QuicEcnCodepoint::ect0;
    case 0x03:
        return QuicEcnCodepoint::ce;
    default:
        return QuicEcnCodepoint::not_ect;
    }
}

struct LinuxSocketDescriptor {
    int fd = -1;
};

bool configure_linux_ecn_socket_options(LinuxSocketDescriptor socket, int family) {
#if defined(__linux__)
    const auto set_bool_socket_option = [&](int level, int name) {
        const int enabled = 1;
        return runtime_ops().setsockopt_fn(socket.fd, level, name, &enabled, sizeof(enabled)) == 0;
    };

    if (family == AF_INET || family == AF_INET6) {
        if (!set_bool_socket_option(IPPROTO_IP, IP_RECVTOS)) {
            return false;
        }
    }
    if (family == AF_INET6) {
        if (!set_bool_socket_option(IPPROTO_IPV6, IPV6_RECVTCLASS)) {
            return false;
        }
    }
#else
    static_cast<void>(fd);
    static_cast<void>(family);
#endif
    return true;
}

bool is_ipv4_mapped_ipv6_address(const sockaddr_storage &peer, socklen_t peer_len) {
    if (peer.ss_family != AF_INET6 || peer_len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        return false;
    }

    const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(&peer);
    return IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr);
}

QuicEcnCodepoint recvmsg_ecn_from_control(const msghdr &message) {
#if defined(__linux__)
    if ((message.msg_flags & MSG_CTRUNC) != 0) {
        return QuicEcnCodepoint::unavailable;
    }
    for (auto *control = CMSG_FIRSTHDR(&message); control != nullptr;
         control = CMSG_NXTHDR(const_cast<msghdr *>(&message), control)) {
        if ((control->cmsg_level == IPPROTO_IP && control->cmsg_type == IP_TOS) ||
            (control->cmsg_level == IPPROTO_IPV6 && control->cmsg_type == IPV6_TCLASS)) {
            int traffic_class = 0;
            const auto payload_size =
                control->cmsg_len > CMSG_LEN(0) ? control->cmsg_len - CMSG_LEN(0) : 0;
            std::memcpy(&traffic_class, CMSG_DATA(control),
                        std::min<std::size_t>(sizeof(traffic_class), payload_size));
            return ecn_from_linux_traffic_class(traffic_class);
        }
    }
#else
    static_cast<void>(message);
#endif
    return QuicEcnCodepoint::unavailable;
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

std::string format_sockaddr_for_trace(const sockaddr_storage &address, socklen_t address_len) {
    char host[NI_MAXHOST] = {};
    char service[NI_MAXSERV] = {};
    const auto *sockaddr_ptr = reinterpret_cast<const sockaddr *>(&address);
    if (address_len <= 0) {
        return "-";
    }

    const int result = ::getnameinfo(sockaddr_ptr, address_len, host, sizeof(host), service,
                                     sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV);
    if (result != 0) {
        return "-";
    }

    std::ostringstream formatted;
    formatted << host << ':' << service;
    return formatted.str();
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
    if (value == "rebind-port") {
        return QuicHttp09Testcase::rebind_port;
    }
    if (value == "rebind-addr") {
        return QuicHttp09Testcase::rebind_addr;
    }
    if (value == "connectionmigration") {
        return QuicHttp09Testcase::connectionmigration;
    }
    if (value == "ecn") {
        return QuicHttp09Testcase::ecn;
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
    if (testcase == QuicHttp09Testcase::keyupdate || testcase == QuicHttp09Testcase::rebind_port ||
        testcase == QuicHttp09Testcase::rebind_addr || testcase == QuicHttp09Testcase::ecn ||
        testcase == QuicHttp09Testcase::connectionmigration) {
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
    int family = AF_UNSPEC;
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

bool host_is_unspecified(std::string_view host) {
    if (host.empty()) {
        return true;
    }

    const auto host_string = std::string(host);

    in_addr ipv4_address{};
    if (::inet_pton(AF_INET, host_string.c_str(), &ipv4_address) == 1) {
        return ipv4_address.s_addr == htonl(INADDR_ANY);
    }

    in6_addr ipv6_address{};
    if (::inet_pton(AF_INET6, host_string.c_str(), &ipv6_address) == 1) {
        return IN6_IS_ADDR_UNSPECIFIED(&ipv6_address);
    }

    return false;
}

std::optional<std::string> preferred_address_host_for_server(std::string_view host) {
    if (!host_is_unspecified(host)) {
        return std::string(host);
    }

    if (const auto hostname = getenv_string("HOSTNAME");
        hostname.has_value() && !hostname->empty()) {
        return hostname;
    }

    std::array<char, NI_MAXHOST> hostname{};
    if (runtime_ops().gethostname_fn(hostname.data(), hostname.size()) != 0 ||
        hostname.front() == '\0') {
        return std::nullopt;
    }

    hostname.back() = '\0';
    return std::string(hostname.data());
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
    const int preferred_family =
        query.family != AF_UNSPEC ? query.family : preferred_udp_address_family(query.host);

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

PreferredAddress preferred_address_from_resolved_udp_address(const ResolvedUdpAddress &resolved,
                                                             ConnectionId connection_id) {
    PreferredAddress preferred_address{
        .connection_id = std::move(connection_id),
    };
    for (std::size_t index = 0; index < preferred_address.stateless_reset_token.size(); ++index) {
        const auto sequence_shift = static_cast<unsigned>((index % sizeof(std::uint64_t)) * 8u);
        auto mixed = static_cast<std::uint8_t>((1ull >> sequence_shift) & 0xffu);
        mixed ^= static_cast<std::uint8_t>(0xa5u + static_cast<unsigned>(index * 13u));
        if (!preferred_address.connection_id.empty()) {
            mixed ^= std::to_integer<std::uint8_t>(
                preferred_address.connection_id[index % preferred_address.connection_id.size()]);
        }
        preferred_address.stateless_reset_token[index] = std::byte{mixed};
    }
    if (resolved.family == AF_INET) {
        const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(&resolved.address);
        std::memcpy(preferred_address.ipv4_address.data(), &ipv4->sin_addr,
                    preferred_address.ipv4_address.size());
        preferred_address.ipv4_port = ntohs(ipv4->sin_port);
    } else if (resolved.family == AF_INET6) {
        const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(&resolved.address);
        std::memcpy(preferred_address.ipv6_address.data(), &ipv6->sin6_addr,
                    preferred_address.ipv6_address.size());
        preferred_address.ipv6_port = ntohs(ipv6->sin6_port);
    }
    return preferred_address;
}

sockaddr_storage sockaddr_from_preferred_address(const PreferredAddress &preferred_address) {
    sockaddr_storage storage{};
    if (preferred_address.ipv4_port != 0) {
        auto *ipv4 = reinterpret_cast<sockaddr_in *>(&storage);
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(preferred_address.ipv4_port);
        std::memcpy(&ipv4->sin_addr, preferred_address.ipv4_address.data(),
                    preferred_address.ipv4_address.size());
        return storage;
    }

    auto *ipv6 = reinterpret_cast<sockaddr_in6 *>(&storage);
    ipv6->sin6_family = AF_INET6;
    ipv6->sin6_port = htons(preferred_address.ipv6_port);
    std::memcpy(&ipv6->sin6_addr, preferred_address.ipv6_address.data(),
                preferred_address.ipv6_address.size());
    return storage;
}

socklen_t sockaddr_len_from_preferred_address(const PreferredAddress &preferred_address) {
    return preferred_address.ipv4_port != 0 ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
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
        if (runtime_ops().setsockopt_fn(fd, IPPROTO_IPV6, IPV6_V6ONLY, &disabled,
                                        sizeof(disabled)) != 0) {
            const int option_errno = errno;
            ::close(fd);
            errno = option_errno;
            return -1;
        }
    }

    if (!configure_linux_ecn_socket_options(LinuxSocketDescriptor{.fd = fd}, family)) {
        const int option_errno = errno;
        ::close(fd);
        errno = option_errno;
        return -1;
    }

    return fd;
}

int open_and_bind_udp_socket(const ResolvedUdpAddress &bind_address, std::string_view role_name) {
    const int socket_fd = open_udp_socket(bind_address.family);
    if (socket_fd < 0) {
        std::cerr << "http09-" << role_name
                  << " failed: unable to create UDP socket: " << std::strerror(errno) << '\n';
        return -1;
    }

    if (runtime_ops().bind_fn(socket_fd, reinterpret_cast<const sockaddr *>(&bind_address.address),
                              bind_address.address_len) != 0) {
        const int bind_errno = errno;
        ::close(socket_fd);
        errno = bind_errno;
        std::cerr << "http09-" << role_name
                  << " failed: unable to bind UDP socket: " << std::strerror(errno) << '\n';
        return -1;
    }

    return socket_fd;
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

std::optional<PreferredAddress>
runtime_preferred_address_for_server(const Http09RuntimeConfig &config);

QuicCoreConfig make_http09_server_core_config_with_identity(const Http09RuntimeConfig &config,
                                                            TlsIdentity identity) {
    const auto original_version = runtime_original_quic_version_for_testcase(config.testcase);
    const auto transfer_like_testcase = transfer_semantics_testcase(config.testcase);
    auto core = QuicCoreConfig{
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
    if (config.qlog_directory.has_value()) {
        core.qlog = QuicQlogConfig{.directory = *config.qlog_directory};
    }
    core.tls_keylog_path = config.tls_keylog_path;
    core.transport.preferred_address = runtime_preferred_address_for_server(config);
    return core;
}

bool send_datagram(int fd, std::span<const std::byte> datagram, const sockaddr_storage &peer,
                   socklen_t peer_len, std::string_view role_name,
                   QuicEcnCodepoint ecn = QuicEcnCodepoint::not_ect);

ConnectionId make_runtime_connection_id(std::byte prefix, std::uint64_t sequence) {
    ConnectionId connection_id(kRuntimeConnectionIdLength, std::byte{0x00});
    connection_id.front() = prefix;
    for (std::size_t index = 1; index < connection_id.size(); ++index) {
        const auto shift = static_cast<unsigned>((connection_id.size() - 1 - index) * 8);
        connection_id[index] = static_cast<std::byte>((sequence >> shift) & 0xffu);
    }
    return connection_id;
}

std::optional<PreferredAddress>
runtime_preferred_address_for_server(const Http09RuntimeConfig &config) {
    if (config.testcase != QuicHttp09Testcase::connectionmigration) {
        return std::nullopt;
    }

    const auto preferred_host = preferred_address_host_for_server(config.host);
    if (!preferred_host.has_value()) {
        return std::nullopt;
    }

    ResolvedUdpAddress preferred_bind{};
    if (!resolve_udp_address(
            UdpAddressResolutionQuery{
                .host = *preferred_host,
                .port = static_cast<std::uint16_t>(config.port + 1),
                .family = preferred_udp_address_family(config.host),
            },
            preferred_bind)) {
        return std::nullopt;
    }

    return preferred_address_from_resolved_udp_address(
        preferred_bind, make_runtime_connection_id(std::byte{0x5a}, 1));
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
                   socklen_t peer_len, std::string_view role_name, QuicEcnCodepoint ecn) {
    const auto *buffer = reinterpret_cast<const void *>(datagram.data());
    const bool use_sendmsg = !has_legacy_sendto_override() && is_ect_codepoint(ecn) &&
                             peer_len > 0 &&
                             (peer.ss_family == AF_INET || peer.ss_family == AF_INET6);
    if (!use_sendmsg) {
        const ssize_t sent = runtime_ops().sendto_fn(
            fd, buffer, datagram.size(), 0, reinterpret_cast<const sockaddr *>(&peer), peer_len);
        if (sent >= 0) {
            return true;
        }

        std::cerr << "http09-" << role_name << " failed: sendto error: " << std::strerror(errno)
                  << '\n';
        return false;
    }

    iovec iov{
        .iov_base = const_cast<void *>(buffer),
        .iov_len = datagram.size(),
    };
    std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
    msghdr message{};
    message.msg_name = const_cast<sockaddr *>(reinterpret_cast<const sockaddr *>(&peer));
    message.msg_namelen = peer_len;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();

    auto *header = CMSG_FIRSTHDR(&message);
    if (header == nullptr) {
        errno = EINVAL;
        std::cerr << "http09-" << role_name << " failed: sendmsg control setup error\n";
        return false;
    }

    const bool use_ipv4_traffic_class =
        peer.ss_family == AF_INET || is_ipv4_mapped_ipv6_address(peer, peer_len);
    header->cmsg_level = use_ipv4_traffic_class ? IPPROTO_IP : IPPROTO_IPV6;
    header->cmsg_type = use_ipv4_traffic_class ? IP_TOS : IPV6_TCLASS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    const int traffic_class = linux_traffic_class_for_ecn(ecn);
    std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
    message.msg_controllen = header->cmsg_len;

    const ssize_t sent = runtime_ops().sendmsg_fn(fd, &message, 0);
    if (sent >= 0) {
        return true;
    }

    std::cerr << "http09-" << role_name << " failed: sendmsg error: " << std::strerror(errno)
              << '\n';
    return false;
}

struct RuntimeSendRoute {
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

struct ServerSocketSet {
    int primary_fd = -1;
    std::optional<int> preferred_fd;
};

struct ClientSocketDescriptor {
    int fd = -1;
    int family = AF_UNSPEC;
};

struct ClientSocketSet {
    ClientSocketDescriptor primary;
    std::optional<ClientSocketDescriptor> secondary;
};

class ScopedClientSockets {
  public:
    explicit ScopedClientSockets(ClientSocketSet &sockets) : sockets_(&sockets) {
    }

    ~ScopedClientSockets() {
        if (sockets_ == nullptr) {
            return;
        }
        if (sockets_->secondary.has_value() && sockets_->secondary->fd >= 0 &&
            sockets_->secondary->fd != sockets_->primary.fd) {
            ::close(sockets_->secondary->fd);
        }
        if (sockets_->primary.fd >= 0) {
            ::close(sockets_->primary.fd);
        }
    }

    ScopedClientSockets(const ScopedClientSockets &) = delete;
    ScopedClientSockets &operator=(const ScopedClientSockets &) = delete;

  private:
    ClientSocketSet *sockets_ = nullptr;
};

struct RuntimeWaitStep {
    std::optional<QuicCoreInput> input;
    QuicCoreTimePoint input_time;
    int socket_fd = -1;
    sockaddr_storage source{};
    socklen_t source_len = 0;
    bool has_source = false;
    bool idle_timeout = false;
};

struct RuntimeWaitConfig {
    std::array<int, 2> socket_fds = {-1, -1};
    std::size_t socket_fd_count = 0;
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
    QuicEcnCodepoint inbound_ecn = QuicEcnCodepoint::unavailable;
    ssize_t bytes_read = 0;
    do {
        if (has_legacy_recvfrom_override()) {
            bytes_read =
                runtime_ops().recvfrom_fn(socket_fd, inbound.data(), inbound.size(), flags,
                                          reinterpret_cast<sockaddr *>(&source), &source_len);
        } else {
            std::array<std::byte, 256> control{};
            iovec iov{
                .iov_base = inbound.data(),
                .iov_len = inbound.size(),
            };
            msghdr message{};
            message.msg_name = &source;
            message.msg_namelen = sizeof(source);
            message.msg_iov = &iov;
            message.msg_iovlen = 1;
            message.msg_control = control.data();
            message.msg_controllen = control.size();
            bytes_read = runtime_ops().recvmsg_fn(socket_fd, &message, flags);
            source_len = static_cast<socklen_t>(message.msg_namelen);
            if (bytes_read >= 0) {
                inbound_ecn = recvmsg_ecn_from_control(message);
            }
        }
    } while (bytes_read < 0 && errno == EINTR);

    if (bytes_read < 0) {
        const bool would_block = (errno == EAGAIN) | (errno == EWOULDBLOCK);
        if (would_block) {
            return ReceiveDatagramResult{
                .status = ReceiveDatagramStatus::would_block,
            };
        }

        std::cerr << "http09-" << role_name << " failed: recvmsg error: " << std::strerror(errno)
                  << '\n';
        return ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::error,
        };
    }

    inbound.resize(static_cast<std::size_t>(bytes_read));
    with_runtime_trace([&](std::ostream &stream) {
        stream << "http09-" << role_name << " trace: recv-dgram fd=" << socket_fd
               << " bytes=" << inbound.size()
               << " source=" << format_sockaddr_for_trace(source, source_len) << '\n';
    });
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::ok,
        .step =
            RuntimeWaitStep{
                .input =
                    QuicCoreInboundDatagram{
                        .bytes = std::move(inbound),
                        .ecn = inbound_ecn,
                    },
                .input_time = now(),
                .socket_fd = socket_fd,
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
    if (config.socket_fd_count == 0) {
        std::cerr << "http09-" << config.role_name << " failed: no sockets configured\n";
        return std::nullopt;
    }

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

    std::array<pollfd, 2> descriptors{};
    for (std::size_t index = 0; index < config.socket_fd_count; ++index) {
        descriptors[index].fd = config.socket_fds[index];
        descriptors[index].events = POLLIN;
    }

    int poll_result = 0;
    do {
        poll_result = runtime_ops().poll_fn(descriptors.data(), config.socket_fd_count, timeout_ms);
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
                .socket_fd = config.socket_fds.front(),
            };
        }

        return RuntimeWaitStep{
            .input_time = now(),
            .socket_fd = config.socket_fds.front(),
            .idle_timeout = true,
        };
    }

    for (std::size_t index = 0; index < config.socket_fd_count; ++index) {
        if ((descriptors[index].revents & POLLIN) == 0) {
            continue;
        }

        const auto receive =
            receive_datagram(config.socket_fds[index], config.role_name, /*flags=*/0);
        if (receive.status != ReceiveDatagramStatus::ok) {
            return std::nullopt;
        }
        return receive.step;
    }

    if (std::any_of(descriptors.begin(), descriptors.begin() + config.socket_fd_count,
                    [](const pollfd &descriptor) { return descriptor.revents != 0; })) {
        std::cerr << "http09-" << config.role_name << " failed: socket became unreadable\n";
        return std::nullopt;
    }

    std::cerr << "http09-" << config.role_name
              << " failed: poll reported readiness without readable sockets\n";
    return std::nullopt;
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

int client_socket_fd_for_family(const ClientSocketSet &sockets, int family) {
    if (sockets.primary.family == family) {
        return sockets.primary.fd;
    }
    if (sockets.secondary.has_value() && sockets.secondary->family == family) {
        return sockets.secondary->fd;
    }
    return -1;
}

std::array<int, 2> active_client_socket_fds(const ClientSocketSet &sockets) {
    return {
        sockets.primary.fd,
        sockets.secondary.has_value() ? sockets.secondary->fd : -1,
    };
}

std::size_t active_client_socket_count(const ClientSocketSet &sockets) {
    return sockets.secondary.has_value() ? 2u : 1u;
}

std::optional<int> ensure_client_socket_for_family(ClientSocketSet &sockets, int family,
                                                   std::string_view role_name) {
    if (family != AF_INET && family != AF_INET6) {
        std::cerr << "http09-" << role_name << " failed: unsupported preferred-address family\n";
        return std::nullopt;
    }

    if (const int existing_fd = client_socket_fd_for_family(sockets, family); existing_fd >= 0) {
        return existing_fd;
    }

    if (sockets.secondary.has_value()) {
        std::cerr << "http09-" << role_name
                  << " failed: no client socket slot available for preferred-address family\n";
        return std::nullopt;
    }

    const int socket_fd = open_udp_socket(family);
    if (socket_fd < 0) {
        std::cerr << "http09-" << role_name
                  << " failed: unable to create UDP socket: " << std::strerror(errno) << '\n';
        return std::nullopt;
    }

    sockets.secondary = ClientSocketDescriptor{
        .fd = socket_fd,
        .family = family,
    };
    return socket_fd;
}

bool handle_core_effects(int fallback_socket_fd, const QuicCoreResult &result,
                         const sockaddr_storage *fallback_peer, socklen_t fallback_peer_len,
                         const std::unordered_map<QuicPathId, RuntimeSendRoute> &path_routes,
                         std::string_view role_name) {
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        int socket_fd = fallback_socket_fd;
        const sockaddr_storage *peer = fallback_peer;
        socklen_t peer_len = fallback_peer_len;
        if (send->path_id.has_value()) {
            const auto route_it = path_routes.find(*send->path_id);
            if (route_it == path_routes.end()) {
                std::cerr << "http09-" << role_name
                          << " failed: missing route for path_id=" << *send->path_id << '\n';
                return false;
            }
            socket_fd = route_it->second.socket_fd;
            peer = &route_it->second.peer;
            peer_len = route_it->second.peer_len;
        }

        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-" << role_name << " trace: send_effect path_id="
                   << (send->path_id.has_value() ? std::to_string(*send->path_id)
                                                 : std::string{"-"})
                   << " socket_fd=" << socket_fd << " peer_len=" << peer_len;
            stream << " peer=" << format_sockaddr_for_trace(*peer, peer_len);
            stream << " bytes=" << send->bytes.size() << '\n';
        });

        if (!send_datagram(socket_fd, send->bytes, *peer, peer_len, role_name, send->ecn)) {
            return false;
        }
    }

    return true;
}

QuicCoreResult advance_core_with_inputs(QuicCore &core, std::span<const QuicCoreInput> inputs,
                                        QuicCoreTimePoint step_time) {
    QuicCoreResult combined;
    for (const auto &input : inputs) {
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-runtime trace: advance_core input=";
            std::visit(
                [&](const auto &value) {
                    using T = std::decay_t<decltype(value)>;
                    if constexpr (std::is_same_v<T, QuicCoreStart>) {
                        stream << "start";
                    } else if constexpr (std::is_same_v<T, QuicCoreInboundDatagram>) {
                        stream << "inbound path_id=" << value.path_id
                               << " bytes=" << value.bytes.size();
                    } else if constexpr (std::is_same_v<T, QuicCoreSendStreamData>) {
                        stream << "send_stream stream_id=" << value.stream_id
                               << " bytes=" << value.bytes.size() << " fin=" << value.fin;
                    } else if constexpr (std::is_same_v<T, QuicCoreResetStream>) {
                        stream << "reset_stream stream_id=" << value.stream_id;
                    } else if constexpr (std::is_same_v<T, QuicCoreStopSending>) {
                        stream << "stop_sending stream_id=" << value.stream_id;
                    } else if constexpr (std::is_same_v<T, QuicCoreRequestKeyUpdate>) {
                        stream << "key_update";
                    } else if constexpr (std::is_same_v<T, QuicCoreRequestConnectionMigration>) {
                        stream << "migration path_id=" << value.path_id << " reason="
                               << (value.reason == QuicMigrationRequestReason::preferred_address
                                       ? "preferred_address"
                                       : "active");
                    } else if constexpr (std::is_same_v<T, QuicCoreTimerExpired>) {
                        stream << "timer_expired";
                    }
                },
                input);
            stream << '\n';
        });
        auto step = core.advance(input, step_time);
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-runtime trace: advance_core output effects=" << step.effects.size()
                   << " local_error=" << static_cast<int>(step.local_error.has_value())
                   << " has_next_wakeup=" << static_cast<int>(step.next_wakeup.has_value());
            for (const auto &effect : step.effects) {
                if (const auto *send = std::get_if<QuicCoreSendDatagram>(&effect)) {
                    stream << " send_path="
                           << (send->path_id.has_value() ? std::to_string(*send->path_id)
                                                         : std::string{"-"})
                           << " send_bytes=" << send->bytes.size();
                }
            }
            stream << '\n';
        });
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
    std::unordered_map<std::string, QuicPathId> path_ids_by_peer_tuple;
    std::unordered_map<QuicPathId, RuntimeSendRoute> path_routes;
    QuicPathId next_path_id = 1;
};

struct ClientRuntimePolicyState {
    bool handshake_ready_seen = false;
    bool handshake_confirmed_seen = false;
    bool preferred_address_request_queued = false;
    std::optional<QuicPathId> preferred_address_path_id;
};

std::string runtime_peer_tuple_key(int socket_fd, const sockaddr_storage &peer,
                                   socklen_t peer_len) {
    const auto encoded_peer_len =
        std::min<std::size_t>(static_cast<std::size_t>(peer_len), sizeof(sockaddr_storage));
    std::string key(sizeof(socket_fd) + sizeof(encoded_peer_len) + encoded_peer_len, '\0');
    std::size_t offset = 0;
    std::memcpy(key.data() + offset, &socket_fd, sizeof(socket_fd));
    offset += sizeof(socket_fd);
    std::memcpy(key.data() + offset, &encoded_peer_len, sizeof(encoded_peer_len));
    offset += sizeof(encoded_peer_len);
    std::memcpy(key.data() + offset, &peer, encoded_peer_len);
    return key;
}

QuicPathId remember_runtime_path(EndpointDriveState &state, const sockaddr_storage &peer,
                                 socklen_t peer_len, int socket_fd) {
    const auto peer_key = runtime_peer_tuple_key(socket_fd, peer, peer_len);
    const auto existing = state.path_ids_by_peer_tuple.find(peer_key);
    const auto path_id =
        existing != state.path_ids_by_peer_tuple.end() ? existing->second : state.next_path_id++;
    if (existing == state.path_ids_by_peer_tuple.end()) {
        state.path_ids_by_peer_tuple.emplace(peer_key, path_id);
    }
    state.path_routes[path_id] = RuntimeSendRoute{
        .socket_fd = socket_fd,
        .peer = peer,
        .peer_len = peer_len,
    };
    return path_id;
}

std::optional<QuicPathId> assign_runtime_path_for_inbound_step(EndpointDriveState &state,
                                                               RuntimeWaitStep &step) {
    if (!step.input.has_value() || !step.has_source || step.source_len <= 0) {
        return std::nullopt;
    }
    auto *inbound = std::get_if<QuicCoreInboundDatagram>(&*step.input);
    if (inbound == nullptr) {
        return std::nullopt;
    }

    const auto path_id = remember_runtime_path(state, step.source, step.source_len, step.socket_fd);
    inbound->path_id = path_id;
    return path_id;
}

void record_resumption_state(EndpointDriveState &state, const QuicCoreResult &result) {
    for (const auto &effect : result.effects) {
        const auto *available = std::get_if<QuicCoreResumptionStateAvailable>(&effect);
        if (available != nullptr) {
            state.last_resumption_state = available->state;
        }
    }
}

bool observe_client_runtime_policy_effects(const QuicCoreResult &result, EndpointDriveState &state,
                                           ClientRuntimePolicyState &policy,
                                           ClientSocketSet &client_sockets,
                                           std::string_view role_name) {
    for (const auto &effect : result.effects) {
        if (const auto *event = std::get_if<QuicCoreStateEvent>(&effect);
            event != nullptr && event->change == QuicCoreStateChange::handshake_ready) {
            policy.handshake_ready_seen = true;
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-client trace: observed handshake_ready\n";
            });
        }
        if (const auto *event = std::get_if<QuicCoreStateEvent>(&effect);
            event != nullptr && event->change == QuicCoreStateChange::handshake_confirmed) {
            policy.handshake_confirmed_seen = true;
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-client trace: observed handshake_confirmed\n";
            });
        }
        if (const auto *preferred = std::get_if<QuicCorePeerPreferredAddressAvailable>(&effect)) {
            const auto peer = sockaddr_from_preferred_address(preferred->preferred_address);
            const auto peer_len = sockaddr_len_from_preferred_address(preferred->preferred_address);
            const auto preferred_socket_fd =
                ensure_client_socket_for_family(client_sockets, peer.ss_family, role_name);
            if (!preferred_socket_fd.has_value()) {
                return false;
            }
            policy.preferred_address_path_id =
                remember_runtime_path(state, peer, peer_len, *preferred_socket_fd);
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-client trace: observed preferred_address path_id="
                       << *policy.preferred_address_path_id << " socket_fd=" << *preferred_socket_fd
                       << " ipv4_port=" << preferred->preferred_address.ipv4_port
                       << " ipv6_port=" << preferred->preferred_address.ipv6_port << '\n';
            });
        }
    }
    return true;
}

bool runtime_client_should_attempt_preferred_address_migration(const Http09RuntimeConfig &config) {
    if (config.testcase == QuicHttp09Testcase::connectionmigration) {
        return true;
    }
    if ((config.mode != Http09RuntimeMode::client) |
        (config.testcase != QuicHttp09Testcase::transfer) | config.requests_env.empty()) {
        return false;
    }

    const auto requests = parse_http09_requests_env(config.requests_env);
    if (!requests.has_value()) {
        return false;
    }

    const auto &parsed_requests = requests.value();
    return std::any_of(parsed_requests.begin(), parsed_requests.end(),
                       [](const QuicHttp09Request &request) {
                           return parse_http09_authority_impl(request.authority)
                                      .value_or(ParsedHttp09Authority{})
                                      .host == "server46";
                       });
}

void maybe_queue_client_runtime_policy_inputs(const Http09RuntimeConfig &config,
                                              ClientRuntimePolicyState &policy,
                                              std::vector<QuicCoreInput> &core_inputs) {
    if (!runtime_client_should_attempt_preferred_address_migration(config) ||
        !policy.handshake_confirmed_seen || !policy.preferred_address_path_id.has_value() ||
        policy.preferred_address_request_queued) {
        return;
    }

    core_inputs.emplace_back(QuicCoreRequestConnectionMigration{
        .path_id = *policy.preferred_address_path_id,
        .reason = QuicMigrationRequestReason::preferred_address,
    });
    policy.preferred_address_request_queued = true;
    with_runtime_trace([&](std::ostream &stream) {
        stream << "http09-client trace: queued preferred_address migration path_id="
               << *policy.preferred_address_path_id << '\n';
    });
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
    int socket_fd = -1;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    std::string local_connection_id_key;
    std::string initial_destination_connection_id_key;
    std::vector<std::string> alternate_connection_id_keys;
};

using ServerSessionMap = std::unordered_map<std::string, std::unique_ptr<ServerSession>>;
using ServerConnectionIdRouteMap = std::unordered_map<std::string, std::string>;
using EraseServerSessionFn = std::function<void(const std::string &)>;

void refresh_server_session_connection_id_routes(ServerSession &session,
                                                 ServerConnectionIdRouteMap &connection_id_routes) {
    std::vector<std::string> active_route_keys;
    for (const auto &connection_id : session.core.active_local_connection_ids()) {
        const auto route_key = connection_id_key(connection_id);
        if (route_key.empty() | route_key == session.local_connection_id_key) {
            continue;
        }
        connection_id_routes[route_key] = session.local_connection_id_key;
        active_route_keys.push_back(route_key);
    }

    for (const auto &existing_key : session.alternate_connection_id_keys) {
        if (std::find(active_route_keys.begin(), active_route_keys.end(), existing_key) !=
            active_route_keys.end()) {
            continue;
        }
        connection_id_routes.erase(existing_key);
    }

    session.alternate_connection_id_keys = std::move(active_route_keys);
}

void erase_server_session_from_map(ServerSessionMap &sessions,
                                   const std::string &local_connection_id_key) {
    sessions.erase(local_connection_id_key);
}

void erase_server_session_with_routes(
    ServerSessionMap &sessions, ServerConnectionIdRouteMap &connection_id_routes,
    std::unordered_map<std::string, std::string> &initial_destination_routes,
    const std::string &local_connection_id_key) {
    const auto &session = *sessions.at(local_connection_id_key);
    initial_destination_routes.erase(session.initial_destination_connection_id_key);
    for (const auto &alternate_connection_id_key : session.alternate_connection_id_keys) {
        connection_id_routes.erase(alternate_connection_id_key);
    }
    sessions.erase(local_connection_id_key);
}

bool datagram_routes_via_initial_destination(const ParsedServerDatagram &parsed) {
    return parsed.kind == ParsedServerDatagram::Kind::supported_initial ||
           parsed.kind == ParsedServerDatagram::Kind::supported_long_header;
}

ServerSessionMap::iterator find_server_session_for_datagram(
    ServerSessionMap &sessions, const ServerConnectionIdRouteMap &connection_id_routes,
    const std::unordered_map<std::string, std::string> &initial_destination_routes,
    const ParsedServerDatagram &parsed) {
    const auto destination_connection_id_key = connection_id_key(parsed.destination_connection_id);
    auto session_it = sessions.find(destination_connection_id_key);
    if (session_it != sessions.end()) {
        return session_it;
    }

    const auto route_it = connection_id_routes.find(destination_connection_id_key);
    if (route_it != connection_id_routes.end()) {
        return sessions.find(route_it->second);
    }

    if (!datagram_routes_via_initial_destination(parsed)) {
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
                                  std::string_view role_name,
                                  const Http09RuntimeConfig *runtime_config = nullptr,
                                  ClientRuntimePolicyState *client_policy = nullptr,
                                  ClientSocketSet *client_sockets = nullptr,
                                  bool *observed_send_effects = nullptr) {
    QuicCoreResult current_result = initial_result;
    bool pending_terminal_success = false;
    if (observed_send_effects != nullptr) {
        *observed_send_effects = false;
    }

    for (;;) {
        record_resumption_state(state, current_result);
        if ((runtime_config != nullptr) & (client_policy != nullptr)) {
            if (client_sockets == nullptr ||
                !observe_client_runtime_policy_effects(current_result, state, *client_policy,
                                                       *client_sockets, role_name)) {
                state.terminal_failure = true;
                return false;
            }
        }
        if (observed_send_effects != nullptr &&
            std::any_of(current_result.effects.begin(), current_result.effects.end(),
                        [](const auto &effect) {
                            return std::holds_alternative<QuicCoreSendDatagram>(effect);
                        })) {
            *observed_send_effects = true;
        }
        if (!handle_core_effects(fd, current_result, peer, peer_len, state.path_routes,
                                 role_name)) {
            state.terminal_failure = true;
            return false;
        }
        state.next_wakeup = current_result.next_wakeup;
        auto update = endpoint.on_core_result(current_result, now());
        if ((runtime_config != nullptr) & (client_policy != nullptr)) {
            maybe_queue_client_runtime_policy_inputs(*runtime_config, *client_policy,
                                                     update.core_inputs);
        }
        state.endpoint_has_pending_work = update.has_pending_work;
        if (current_result.local_error.has_value() && !update.handled_local_error) {
            state.terminal_failure = true;
            return false;
        }
        if (update.terminal_failure) {
            state.terminal_failure = true;
            return false;
        }
        pending_terminal_success = pending_terminal_success | update.terminal_success;

        if (!update.core_inputs.empty()) {
            current_result = advance_core_with_inputs(core, update.core_inputs, now());
            continue;
        }

        if (pending_terminal_success) {
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-" << role_name
                       << " trace: terminal_success core_inputs=" << update.core_inputs.size()
                       << '\n';
            });
            state.terminal_success = true;
            return true;
        }

        return true;
    }
}

int run_http09_client_connection_loop(const Http09RuntimeConfig &config,
                                      const EndpointDriver &endpoint, QuicCore &core,
                                      ClientSocketSet &client_sockets, int idle_timeout_ms,
                                      const sockaddr_storage &peer, socklen_t peer_len,
                                      EndpointDriveState &state,
                                      ClientRuntimePolicyState &client_policy,
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
    if (!drive_endpoint_until_blocked(endpoint, core, client_sockets.primary.fd, &peer, peer_len,
                                      start_result, state, "client", &config, &client_policy,
                                      &client_sockets)) {
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
        const auto send_count = std::count_if(
            timer_result.effects.begin(), timer_result.effects.end(), [](const auto &effect) {
                return std::holds_alternative<QuicCoreSendDatagram>(effect);
            });
        const bool ok = drive_endpoint_until_blocked(endpoint, core, client_sockets.primary.fd,
                                                     &peer, peer_len, timer_result, state, "client",
                                                     &config, &client_policy, &client_sockets);
        with_runtime_trace([&](std::ostream &stream) {
            const auto next_wakeup_delta_ms =
                state.next_wakeup.has_value()
                    ? std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::abs(state.next_wakeup.value() - current))
                          .count()
                    : -1;
            stream << "http09-client trace: timer-expired send_count=" << send_count
                   << " pending=" << state.endpoint_has_pending_work
                   << " terminal_success=" << state.terminal_success
                   << " terminal_failure=" << state.terminal_failure
                   << " has_next_wakeup=" << state.next_wakeup.has_value()
                   << " next_wakeup_delta_ms=" << next_wakeup_delta_ms << " ok=" << ok << '\n';
        });
        return ok;
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
            .ok = drive_endpoint_until_blocked(endpoint, core, client_sockets.primary.fd, &peer,
                                               peer_len, result, state, "client", &config,
                                               &client_policy, &client_sockets),
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

            bool received_datagram = false;
            bool all_sockets_would_block = true;
            for (const int socket_fd : active_client_socket_fds(client_sockets)) {
                if (socket_fd < 0) {
                    continue;
                }

                auto receive = io.receive_datagram(socket_fd, /*flags=*/MSG_DONTWAIT,
                                                   /*role_name=*/"client");
                if (receive.status == ReceiveDatagramStatus::would_block) {
                    continue;
                }
                all_sockets_would_block = false;
                if (receive.status == ReceiveDatagramStatus::error) {
                    return false;
                }

                assign_runtime_path_for_inbound_step(state, receive.step);
                auto step_result =
                    core.advance(std::move(*receive.step.input), receive.step.input_time);
                saw_peer_input = true;
                if (!drive_endpoint_until_blocked(endpoint, core, client_sockets.primary.fd, &peer,
                                                  peer_len, step_result, state, "client", &config,
                                                  &client_policy, &client_sockets)) {
                    return false;
                }
                received_datagram = true;
                const bool terminal_after_receive = state.terminal_success | state.terminal_failure;
                if (terminal_after_receive) {
                    refresh_terminal_success_deadline_from_peer_input(receive.step.input_time);
                    return true;
                }
                break;
            }

            if (received_datagram) {
                continue;
            }
            if (all_sockets_would_block) {
                with_runtime_trace([&](std::ostream &stream) {
                    const auto current = now();
                    const auto next_wakeup_delay_ms =
                        state.next_wakeup.has_value()
                            ? std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::abs(state.next_wakeup.value() - current))
                                  .count()
                            : -1;
                    stream << "http09-client trace: would-block pending="
                           << state.endpoint_has_pending_work
                           << " advanced_core=" << pump_result.advanced_core
                           << " terminal_success=" << state.terminal_success
                           << " terminal_failure=" << state.terminal_failure
                           << " has_next_wakeup=" << state.next_wakeup.has_value()
                           << " next_wakeup_delta_ms=" << next_wakeup_delay_ms << '\n';
                });
                if (pump_result.advanced_core && state.endpoint_has_pending_work) {
                    continue;
                }
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
        const auto socket_fds = active_client_socket_fds(client_sockets);
        auto step = io.wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fds = socket_fds,
                .socket_fd_count = active_client_socket_count(client_sockets),
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
        assign_runtime_path_for_inbound_step(state, *step);
        auto step_input = std::move(*step->input);
        const bool step_has_peer_input =
            std::holds_alternative<QuicCoreInboundDatagram>(step_input);
        saw_peer_input = step_has_peer_input || saw_peer_input;
        auto step_result = core.advance(std::move(step_input), step->input_time);
        if (!drive_endpoint_until_blocked(endpoint, core, client_sockets.primary.fd, &peer,
                                          peer_len, step_result, state, "client", &config,
                                          &client_policy, &client_sockets)) {
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
    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = socket_fd,
                .family = peer_address.family,
            },
    };
    ScopedClientSockets socket_guard(client_sockets);

    const sockaddr_storage peer = peer_address.address;
    const socklen_t peer_len = peer_address.address_len;

    const bool attempt_zero_rtt_requests = core_config.zero_rtt.attempt;
    core_config.server_name = remote->server_name;
    assign_runtime_client_connection_ids(core_config, connection_index);
    QuicCore core(std::move(core_config));
    EndpointDriveState state;
    ClientRuntimePolicyState client_policy;
    const auto start_result = core.advance(QuicCoreStart{}, now());
    record_resumption_state(state, start_result);

    QuicHttp09ClientEndpoint endpoint(make_http09_client_endpoint_config(
        config, requests, attempt_zero_rtt_requests, start_result));
    return ClientConnectionRunResult{
        .exit_code = run_http09_client_connection_loop(
            config, make_endpoint_driver(endpoint), core, client_sockets,
            client_receive_timeout_ms(config), peer, peer_len, state, client_policy,
            make_runtime_client_loop_io(), start_result),
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
                                              ServerConnectionIdRouteMap &connection_id_routes,
                                              const ParsedServerDatagram &parsed,
                                              const EraseServerSessionFn &erase_session) {
    if (parsed.kind == ParsedServerDatagram::Kind::supported_initial) {
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-server trace: routed-initial-to-existing-session scid="
                   << format_connection_id_key_hex(session.local_connection_id_key)
                   << " odcid=" << format_connection_id_hex(parsed.destination_connection_id)
                   << '\n';
        });
    }
    static_cast<void>(assign_runtime_path_for_inbound_step(session.state, step));
    session.socket_fd = step.socket_fd;
    session.peer = step.source;
    session.peer_len = step.source_len;
    if (!step.input.has_value()) {
        std::cerr << "http09-server failed: runtime step missing input\n";
        return false;
    }
    auto session_input = std::move(*step.input);
    const auto session_result = session.core.advance(std::move(session_input), step.input_time);
    const bool endpoint_failed = !drive_endpoint_until_blocked(
        make_endpoint_driver(session.endpoint), session.core, session.socket_fd, &session.peer,
        session.peer_len, session_result, session.state, "server");
    refresh_server_session_connection_id_routes(session, connection_id_routes);
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

void process_expired_server_sessions(ServerSessionMap &sessions, QuicCoreTimePoint current,
                                     ServerConnectionIdRouteMap &connection_id_routes,
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
            make_endpoint_driver(session->endpoint), session->core, session->socket_fd,
            &session->peer, session->peer_len, timer_result, session->state, "server");
        refresh_server_session_connection_id_routes(*session, connection_id_routes);
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

bool pump_server_pending_endpoint_work(ServerSessionMap &sessions,
                                       ServerConnectionIdRouteMap &connection_id_routes,
                                       const EraseServerSessionFn &erase_session) {
    bool made_progress = false;
    std::vector<std::string> failed_sessions;
    for (const auto &[local_connection_id_key, session] : sessions) {
        if (!session->state.endpoint_has_pending_work) {
            continue;
        }

        const auto endpoint_driver = make_endpoint_driver(session->endpoint);
        auto update = endpoint_driver.poll(now());
        session->state.endpoint_has_pending_work = update.has_pending_work;

        auto result = advance_core_with_inputs(session->core, update.core_inputs, now());
        bool observed_send_effects = false;
        const bool endpoint_failed = !drive_endpoint_until_blocked(
            endpoint_driver, session->core, session->socket_fd, &session->peer, session->peer_len,
            result, session->state, "server", nullptr, nullptr, nullptr, &observed_send_effects);
        made_progress = made_progress | observed_send_effects;
        refresh_server_session_connection_id_routes(*session, connection_id_routes);
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
    return made_progress;
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
    std::function<bool()> pump_endpoint_work;
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

int run_http09_server_loop(const ServerSocketSet &sockets, const ServerLoopIo &io,
                           const ServerLoopDriver &driver) {
    for (;;) {
        for (;;) {
            bool processed_timers = false;
            driver.process_expired_timers(io.current_time(), processed_timers);
            if (processed_timers) {
                continue;
            }

            bool processed_datagram = false;
            bool receive_failed = false;
            const auto try_receive = [&](int socket_fd) {
                if (processed_datagram | receive_failed) {
                    return;
                }

                auto receive =
                    io.receive_datagram(socket_fd, /*flags=*/MSG_DONTWAIT, /*role_name=*/"server");
                if (receive.status == ReceiveDatagramStatus::would_block) {
                    return;
                }
                if (receive.status == ReceiveDatagramStatus::error) {
                    receive_failed = true;
                    return;
                }
                if (!driver.process_datagram(std::move(receive.step))) {
                    receive_failed = true;
                    return;
                }
                processed_datagram = true;
            };

            try_receive(sockets.primary_fd);
            if (sockets.preferred_fd.has_value()) {
                try_receive(*sockets.preferred_fd);
            }

            if (receive_failed) {
                return 1;
            }
            if (processed_datagram) {
                continue;
            }

            const bool pump_made_progress = driver.pump_endpoint_work();
            if (pump_made_progress & driver.has_pending_endpoint_work()) {
                continue;
            }
            break;
        }

        bool processed_timers = false;
        driver.process_expired_timers(io.current_time(), processed_timers);
        if (processed_timers) {
            continue;
        }

        const bool pump_made_progress = driver.pump_endpoint_work();
        if (pump_made_progress & driver.has_pending_endpoint_work()) {
            continue;
        }

        auto step = io.wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fds = {sockets.primary_fd, sockets.preferred_fd.value_or(-1)},
                .socket_fd_count = sockets.preferred_fd.has_value() ? 2u : 1u,
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

    const int primary_socket_fd = open_and_bind_udp_socket(bind_address, "server");
    if (primary_socket_fd < 0) {
        return 1;
    }
    ScopedFd primary_socket_guard(primary_socket_fd);

    ServerSocketSet sockets{
        .primary_fd = primary_socket_fd,
    };

    std::optional<ScopedFd> preferred_socket_guard;
    if (config.testcase == QuicHttp09Testcase::connectionmigration) {
        ResolvedUdpAddress preferred_bind{};
        if (!resolve_udp_address(
                UdpAddressResolutionQuery{
                    .host = config.host,
                    .port = static_cast<std::uint16_t>(config.port + 1),
                    .extra_flags = AI_PASSIVE,
                },
                preferred_bind)) {
            std::cerr << "http09-server failed: invalid host address\n";
            return 1;
        }

        const int preferred_socket_fd = open_and_bind_udp_socket(preferred_bind, "server");
        if (preferred_socket_fd < 0) {
            return 1;
        }
        sockets.preferred_fd = preferred_socket_fd;
        preferred_socket_guard.emplace(preferred_socket_fd);
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
    ServerConnectionIdRouteMap connection_id_routes;
    std::unordered_map<std::string, std::string> initial_destination_routes;
    RetryTokenStore retry_tokens;
    std::uint64_t next_connection_index = 1;

    const EraseServerSessionFn erase_session = [&](const std::string &local_connection_id_key) {
        erase_server_session_with_routes(sessions, connection_id_routes, initial_destination_routes,
                                         local_connection_id_key);
    };

    auto create_session =
        [&](const ConnectionId &initial_destination_connection_id, const sockaddr_storage &peer,
            socklen_t peer_len, int socket_fd,
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
            .socket_fd = socket_fd,
            .peer = peer,
            .peer_len = peer_len,
            .local_connection_id_key = local_connection_id_key,
            .initial_destination_connection_id_key =
                connection_id_key(initial_destination_connection_id),
        });
        auto *session_ptr = session.get();
        refresh_server_session_connection_id_routes(*session_ptr, connection_id_routes);
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

        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-server trace: route-lookup kind="
                   << static_cast<unsigned>(parsed->kind)
                   << " dcid=" << format_connection_id_hex(parsed->destination_connection_id)
                   << " bytes=" << inbound.bytes.size()
                   << " source=" << format_sockaddr_for_trace(step.source, step.source_len) << '\n';
        });

        auto session_it = find_server_session_for_datagram(sessions, connection_id_routes,
                                                           initial_destination_routes, *parsed);

        if (session_it != sessions.end()) {
            with_runtime_trace([&](std::ostream &stream) {
                stream << "http09-server trace: route-hit scid="
                       << format_connection_id_key_hex(session_it->second->local_connection_id_key)
                       << " dcid=" << format_connection_id_hex(parsed->destination_connection_id)
                       << '\n';
            });
            return process_existing_server_session_datagram(
                *session_it->second, step, connection_id_routes, *parsed, erase_session);
        }

        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-server trace: route-miss dcid="
                   << format_connection_id_hex(parsed->destination_connection_id)
                   << " short_header="
                   << static_cast<int>(parsed->kind == ParsedServerDatagram::Kind::short_header)
                   << '\n';
        });

        if (parsed->kind == ParsedServerDatagram::Kind::unsupported_version_long_header) {
            return send_version_negotiation_for_probe(step.socket_fd, inbound.bytes, *parsed,
                                                      step.source, step.source_len);
        }

        if (parsed->kind != ParsedServerDatagram::Kind::supported_initial) {
            return true;
        }

        auto retry_preparation = prepare_supported_initial_retry_handling(
            config.retry_enabled, step.socket_fd, *parsed, step.source, step.source_len,
            retry_tokens, next_connection_index);
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
                                       step.source_len, step.socket_fd, retry_context);
        static_cast<void>(assign_runtime_path_for_inbound_step(session.state, step));
        auto session_input = std::move(*step.input);
        const auto session_result = session.core.advance(std::move(session_input), step.input_time);
        const bool endpoint_failed = !drive_endpoint_until_blocked(
            make_endpoint_driver(session.endpoint), session.core, session.socket_fd, &session.peer,
            session.peer_len, session_result, session.state, "server");
        refresh_server_session_connection_id_routes(session, connection_id_routes);
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
        sockets, make_runtime_server_loop_io(),
        ServerLoopDriver{
            .earliest_wakeup = [&] { return earliest_server_session_wakeup(sessions); },
            .process_expired_timers =
                [&](QuicCoreTimePoint current, bool &processed_any) {
                    process_expired_server_sessions(sessions, current, connection_id_routes,
                                                    erase_session, processed_any);
                },
            .pump_endpoint_work =
                [&] {
                    return pump_server_pending_endpoint_work(sessions, connection_id_routes,
                                                             erase_session);
                },
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

struct RecordedSendToForTests {
    int calls = 0;
    int socket_fd = -1;
    socklen_t peer_len = 0;
    std::uint16_t peer_port = 0;
    std::vector<int> socket_fds;
    std::vector<std::uint16_t> peer_ports;
};

thread_local RecordedSendToForTests g_recorded_sendto_for_tests;

struct RecordedSetSockOptForTests {
    struct Call {
        int level = 0;
        int name = 0;
        int value = 0;
    };

    std::vector<Call> calls;
};

thread_local RecordedSetSockOptForTests g_recorded_setsockopt_for_tests;

struct RecordedSendMsgForTests {
    int calls = 0;
    int socket_fd = -1;
    int level = 0;
    int type = 0;
    int traffic_class = 0;
};

thread_local RecordedSendMsgForTests g_recorded_sendmsg_for_tests;

struct RecordedRecvMsgForTests {
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
    std::vector<std::byte> bytes;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
};

thread_local RecordedRecvMsgForTests g_recorded_recvmsg_for_tests;

ssize_t record_sendto_for_tests(int socket_fd, const void *, size_t length, int,
                                const sockaddr *destination, socklen_t destination_len) {
    g_recorded_sendto_for_tests.calls += 1;
    g_recorded_sendto_for_tests.socket_fd = socket_fd;
    g_recorded_sendto_for_tests.peer_len = destination_len;
    g_recorded_sendto_for_tests.socket_fds.push_back(socket_fd);
    std::uint16_t peer_port = 0;
    if (destination != nullptr && destination->sa_family == AF_INET &&
        destination_len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(destination);
        peer_port = ntohs(ipv4->sin_port);
    } else if (destination != nullptr && destination->sa_family == AF_INET6 &&
               destination_len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(destination);
        peer_port = ntohs(ipv6->sin6_port);
    }
    g_recorded_sendto_for_tests.peer_port = peer_port;
    g_recorded_sendto_for_tests.peer_ports.push_back(peer_port);
    return static_cast<ssize_t>(length);
}

int record_setsockopt_for_tests(int, int level, int name, const void *value, socklen_t value_len) {
    int option_value = 0;
    if (value != nullptr && value_len >= static_cast<socklen_t>(sizeof(option_value))) {
        std::memcpy(&option_value, value, sizeof(option_value));
    }
    g_recorded_setsockopt_for_tests.calls.push_back(RecordedSetSockOptForTests::Call{
        .level = level,
        .name = name,
        .value = option_value,
    });
    return 0;
}

ssize_t record_sendmsg_for_tests(int socket_fd, const msghdr *message, int) {
    g_recorded_sendmsg_for_tests.calls += 1;
    g_recorded_sendmsg_for_tests.socket_fd = socket_fd;
    g_recorded_sendmsg_for_tests.level = 0;
    g_recorded_sendmsg_for_tests.type = 0;
    g_recorded_sendmsg_for_tests.traffic_class = 0;
    for (auto *control = CMSG_FIRSTHDR(const_cast<msghdr *>(message)); control != nullptr;
         control = CMSG_NXTHDR(const_cast<msghdr *>(message), control)) {
        g_recorded_sendmsg_for_tests.level = control->cmsg_level;
        g_recorded_sendmsg_for_tests.type = control->cmsg_type;
        std::memcpy(&g_recorded_sendmsg_for_tests.traffic_class, CMSG_DATA(control),
                    sizeof(g_recorded_sendmsg_for_tests.traffic_class));
        break;
    }
    return message != nullptr && message->msg_iov != nullptr
               ? static_cast<ssize_t>(message->msg_iov[0].iov_len)
               : 0;
}

ssize_t record_recvmsg_for_tests(int, msghdr *message, int) {
    if (message == nullptr || message->msg_iov == nullptr || message->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    const auto bytes_to_copy = std::min<std::size_t>(g_recorded_recvmsg_for_tests.bytes.size(),
                                                     message->msg_iov[0].iov_len);
    std::memcpy(message->msg_iov[0].iov_base, g_recorded_recvmsg_for_tests.bytes.data(),
                bytes_to_copy);
    if (message->msg_name != nullptr &&
        message->msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        std::memcpy(message->msg_name, &g_recorded_recvmsg_for_tests.peer,
                    sizeof(sockaddr_storage));
        message->msg_namelen = g_recorded_recvmsg_for_tests.peer_len;
    }

    auto *header = CMSG_FIRSTHDR(message);
    if (header != nullptr) {
        const bool ipv6 = g_recorded_recvmsg_for_tests.peer.ss_family == AF_INET6;
        header->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
        header->cmsg_type = ipv6 ? IPV6_TCLASS : IP_TOS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        const int traffic_class = linux_traffic_class_for_ecn(g_recorded_recvmsg_for_tests.ecn);
        std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
        message->msg_controllen = header->cmsg_len;
    }

    return static_cast<ssize_t>(bytes_to_copy);
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

struct WaitCaptureClientLoopIoForTests {
    bool wait_called = false;
    std::size_t wait_socket_fd_count = 0;
    std::array<int, 2> wait_socket_fds = {-1, -1};
};

QuicCoreTimePoint wait_capture_client_loop_now_for_tests(void *) {
    return now();
}

ReceiveDatagramResult wait_capture_client_loop_receive_for_tests(void *, int, int,
                                                                 std::string_view) {
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::would_block,
    };
}

std::optional<RuntimeWaitStep>
wait_capture_client_loop_wait_for_tests(void *context, const RuntimeWaitConfig &config,
                                        const std::optional<QuicCoreTimePoint> &) {
    auto &capture = *static_cast<WaitCaptureClientLoopIoForTests *>(context);
    capture.wait_called = true;
    capture.wait_socket_fd_count = config.socket_fd_count;
    capture.wait_socket_fds = config.socket_fds;
    return std::nullopt;
}

ClientLoopIo make_wait_capture_client_loop_io_for_tests(WaitCaptureClientLoopIoForTests &capture) {
    return ClientLoopIo{
        .context = &capture,
        .now_fn = &wait_capture_client_loop_now_for_tests,
        .receive_datagram_fn = &wait_capture_client_loop_receive_for_tests,
        .wait_for_socket_or_deadline_fn = &wait_capture_client_loop_wait_for_tests,
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
    std::vector<bool> pump_made_progress;
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

ScriptedServerLoopCaseForTests
make_ready_datagram_preempts_next_pending_work_pump_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_input_receive_for_tests(QuicCoreTimerExpired{}),
            },
        .processed_timers_results = {false, false},
        .pending_work_after_pump = {true},
        .pump_made_progress = {true},
        .process_datagram_result = false,
    };
}

ScriptedServerLoopCaseForTests
make_pending_endpoint_without_transport_progress_waits_instead_of_spinning_case_for_tests() {
    return ScriptedServerLoopCaseForTests{
        .receive_results =
            {
                make_would_block_receive_for_tests(),
                make_would_block_receive_for_tests(),
                make_would_block_receive_for_tests(),
            },
        .wait_steps =
            {
                std::nullopt,
            },
        .processed_timers_results = {false, false, false, false},
        .pending_work_after_pump = {true, true, false, false},
        .pump_made_progress = {false, false, false, false},
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
    &make_ready_datagram_preempts_next_pending_work_pump_case_for_tests,
    &make_pending_endpoint_without_transport_progress_waits_instead_of_spinning_case_for_tests,
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

bool core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
    bool force_serialization_failure, bool force_path_id_mismatch = false);
bool core_retry_restart_preserves_inbound_path_ids_case_for_tests(
    bool force_integrity_failure, bool force_serialization_failure,
    bool force_path_id_mismatch = false);

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

QuicCoreConfig
make_http09_server_core_config_with_identity_for_tests(const Http09RuntimeConfig &config,
                                                       TlsIdentity identity) {
    return make_http09_server_core_config_with_identity(config, std::move(identity));
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
            .socket_fds = {socket_fd, -1},
            .socket_fd_count = 1,
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
        [](ScriptedEndpointForTests &setup_endpoint, ScriptedClientLoopIoForTests &setup_io,
           QuicCore &setup_core, QuicCoreResult &setup_start_result,
           QuicCoreTimePoint setup_base_time) {
            setup_core = make_local_error_client_core_for_tests();
            setup_start_result = setup_core.advance(QuicCoreStart{}, setup_base_time);
            const auto timer_due = setup_start_result.next_wakeup.value_or(setup_base_time);
            setup_endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});
            setup_io.receive_results.push_back(make_would_block_receive_for_tests());
            setup_io.wait_steps.push_back(std::nullopt);
            setup_io.now_values = {
                timer_due,
                timer_due,
            };
        },
    });
    kClientLoopCaseSetups[static_cast<std::size_t>(case_id)](endpoint, io_script, core,
                                                             start_result, base_time);

    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
    };
    ClientRuntimePolicyState client_policy;
    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = 17,
                .family = AF_UNSPEC,
            },
    };
    g_recorded_sendto_for_tests = {};
    const ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    };
    const int exit_code = run_http09_client_connection_loop(
        config, make_endpoint_driver(endpoint), core, client_sockets,
        /*idle_timeout_ms=*/kDefaultClientReceiveTimeoutMs, peer, /*peer_len=*/0, state,
        client_policy, make_scripted_client_loop_io_for_tests(io_script), start_result);
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
    ServerConnectionIdRouteMap connection_id_routes;
    process_existing_server_session_datagram(
        *session, step, connection_id_routes, parsed,
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
    ServerConnectionIdRouteMap connection_id_routes;
    const bool processed = process_existing_server_session_datagram(
        *session, step, connection_id_routes, parsed,
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

    ServerConnectionIdRouteMap connection_id_routes;
    return find_server_session_for_datagram(sessions, connection_id_routes,
                                            initial_destination_routes, parsed) != sessions.end();
}

bool preferred_address_routes_to_existing_server_session_for_tests() {
    const ConnectionId preferred_connection_id = make_runtime_connection_id(std::byte{0x5a}, 1);
    const auto preferred_connection_id_key = connection_id_key(preferred_connection_id);

    ServerSessionMap sessions;
    sessions.emplace("existing-session",
                     std::make_unique<ServerSession>(ServerSession{
                         .core = make_failed_server_core_for_tests(),
                         .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                             .document_root = std::filesystem::temp_directory_path(),
                         }),
                         .state = EndpointDriveState{},
                         .peer = {},
                         .peer_len = 0,
                         .local_connection_id_key = "existing-session",
                         .initial_destination_connection_id_key = "unused-initial",
                     }));

    std::unordered_map<std::string, std::string> initial_destination_routes;
    ServerConnectionIdRouteMap connection_id_routes;
    connection_id_routes.emplace(preferred_connection_id_key, "existing-session");

    const ParsedServerDatagram parsed{
        .kind = ParsedServerDatagram::Kind::short_header,
        .destination_connection_id = preferred_connection_id,
    };

    return find_server_session_for_datagram(sessions, connection_id_routes,
                                            initial_destination_routes, parsed) != sessions.end();
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
    ServerConnectionIdRouteMap connection_id_routes;
    process_expired_server_sessions(sessions, now(), connection_id_routes, erase_session,
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
    ServerConnectionIdRouteMap connection_id_routes;
    process_expired_server_sessions(sessions, now(), connection_id_routes, erase_session,
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
    ServerConnectionIdRouteMap connection_id_routes;
    pump_server_pending_endpoint_work(sessions, connection_id_routes,
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

bool runtime_assigns_stable_path_ids_for_tests() {
    const auto make_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };

    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    EndpointDriveState state;
    RuntimeWaitStep first{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x01}}},
        .input_time = now(),
        .socket_fd = 4,
        .source = make_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };
    RuntimeWaitStep second{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x02}}},
        .input_time = now(),
        .socket_fd = 4,
        .source = make_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };
    RuntimeWaitStep third{
        .input = QuicCoreInboundDatagram{.bytes = {std::byte{0x03}}},
        .input_time = now(),
        .socket_fd = 7,
        .source = make_peer(4444),
        .source_len = peer_len,
        .has_source = true,
    };

    const auto first_assigned = assign_runtime_path_for_inbound_step(state, first);
    const auto second_assigned = assign_runtime_path_for_inbound_step(state, second);
    const auto third_assigned = assign_runtime_path_for_inbound_step(state, third);
    const auto first_path = std::get<QuicCoreInboundDatagram>(*first.input).path_id;
    const auto second_path = std::get<QuicCoreInboundDatagram>(*second.input).path_id;
    const auto third_path = std::get<QuicCoreInboundDatagram>(*third.input).path_id;
    return first_assigned.has_value() & second_assigned.has_value() & third_assigned.has_value() &
           (first_path != 0) & (first_path == second_path) & (first_path != third_path) &
           (state.path_routes.at(first_path).socket_fd == 4) &
           (state.path_routes.at(third_path).socket_fd == 7);
}

bool runtime_configures_linux_ecn_socket_options_for_tests() {
    g_recorded_setsockopt_for_tests = {};
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .socket_fn = [](int, int, int) { return 41; },
            .setsockopt_fn = &record_setsockopt_for_tests,
        },
    };

    const int fd = open_udp_socket(AF_INET6);
    const bool opened = fd == 41;
    const auto has_call = [](int level, int name, int value) {
        return std::ranges::any_of(g_recorded_setsockopt_for_tests.calls,
                                   [&](const RecordedSetSockOptForTests::Call &call) {
                                       return call.level == level && call.name == name &&
                                              call.value == value;
                                   });
    };
    return opened && has_call(IPPROTO_IPV6, IPV6_V6ONLY, 0) &&
           has_call(IPPROTO_IP, IP_RECVTOS, 1) && has_call(IPPROTO_IPV6, IPV6_RECVTCLASS, 1);
}

bool runtime_sendmsg_uses_outbound_ecn_for_tests() {
    g_recorded_sendmsg_for_tests = {};
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .sendmsg_fn = &record_sendmsg_for_tests,
        },
    };
    const std::array<std::byte, 1> datagram = {
        std::byte{0x01},
    };

    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4433);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    const bool sent =
        send_datagram(/*fd=*/17, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in)),
                      "client", QuicEcnCodepoint::ect1);
    return sent && (g_recorded_sendmsg_for_tests.calls == 1) &&
           (g_recorded_sendmsg_for_tests.socket_fd == 17) &&
           (g_recorded_sendmsg_for_tests.level == IPPROTO_IP) &&
           (g_recorded_sendmsg_for_tests.type == IP_TOS) &&
           (g_recorded_sendmsg_for_tests.traffic_class == 0x01);
}

bool runtime_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests() {
    g_recorded_sendmsg_for_tests = {};
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .sendmsg_fn = &record_sendmsg_for_tests,
        },
    };
    const std::array<std::byte, 1> datagram = {
        std::byte{0x01},
    };

    sockaddr_storage peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(4433);
    ipv6.sin6_addr.s6_addr[10] = 0xff;
    ipv6.sin6_addr.s6_addr[11] = 0xff;
    ipv6.sin6_addr.s6_addr[12] = 127;
    ipv6.sin6_addr.s6_addr[15] = 1;

    const bool sent =
        send_datagram(/*fd=*/23, datagram, peer, static_cast<socklen_t>(sizeof(sockaddr_in6)),
                      "server", QuicEcnCodepoint::ect1);
    return sent && (g_recorded_sendmsg_for_tests.calls == 1) &&
           (g_recorded_sendmsg_for_tests.socket_fd == 23) &&
           (g_recorded_sendmsg_for_tests.level == IPPROTO_IP) &&
           (g_recorded_sendmsg_for_tests.type == IP_TOS) &&
           (g_recorded_sendmsg_for_tests.traffic_class == 0x01);
}

bool runtime_recvmsg_maps_ecn_to_core_input_for_tests() {
    g_recorded_recvmsg_for_tests = {};
    g_recorded_recvmsg_for_tests.ecn = QuicEcnCodepoint::ce;
    g_recorded_recvmsg_for_tests.bytes = {std::byte{0xaa}, std::byte{0xbb}};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&g_recorded_recvmsg_for_tests.peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(6121);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_recorded_recvmsg_for_tests.peer_len = sizeof(sockaddr_in);

    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .recvmsg_fn = &record_recvmsg_for_tests,
        },
    };

    const auto received = receive_datagram(/*socket_fd=*/29, "client", /*flags=*/0);
    if (received.status != ReceiveDatagramStatus::ok || !received.step.input.has_value()) {
        return false;
    }

    const auto *inbound = std::get_if<QuicCoreInboundDatagram>(&*received.step.input);
    return inbound != nullptr && inbound->bytes == g_recorded_recvmsg_for_tests.bytes &&
           inbound->ecn == QuicEcnCodepoint::ce;
}

bool drive_endpoint_uses_transport_selected_path_for_tests() {
    g_recorded_sendto_for_tests = {};
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    };

    const auto make_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };

    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    const auto selected_path_id = static_cast<QuicPathId>(9);
    const int fallback_socket_fd = 31;
    const int selected_socket_fd = 77;
    const auto fallback_peer = make_peer(8443);
    const auto selected_peer = make_peer(9443);

    EndpointDriveState state;
    state.path_routes[selected_path_id] = RuntimeSendRoute{
        .socket_fd = selected_socket_fd,
        .peer = selected_peer,
        .peer_len = peer_len,
    };

    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreSendDatagram{
        .path_id = selected_path_id,
        .bytes = {std::byte{0xaa}},
    });

    ScriptedEndpointForTests endpoint;
    QuicCore core = make_local_error_client_core_for_tests();
    const bool drove =
        drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core, fallback_socket_fd,
                                     &fallback_peer, peer_len, result, state, "client");
    return drove & (g_recorded_sendto_for_tests.calls == 1) &
           (g_recorded_sendto_for_tests.socket_fd == selected_socket_fd) &
           (g_recorded_sendto_for_tests.peer_port == 9443);
}

bool runtime_policy_core_inputs_advance_before_terminal_success_for_tests() {
    ScriptedEndpointForTests endpoint;
    endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{
        .terminal_success = true,
    });
    endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});

    QuicCore core = make_local_error_client_core_for_tests();
    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    QuicCoreResult initial_result;
    initial_result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_ready,
    });
    initial_result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_confirmed,
    });
    initial_result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
        .preferred_address =
            PreferredAddress{
                .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
                .ipv4_port = 4444,
                .connection_id = make_runtime_connection_id(std::byte{0x5a}, 1),
            },
    });

    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
        .testcase = QuicHttp09Testcase::connectionmigration,
    };
    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = 17,
                .family = AF_INET,
            },
    };
    sockaddr_storage peer{};
    const bool drove = drive_endpoint_until_blocked(make_endpoint_driver(endpoint), core, /*fd=*/17,
                                                    &peer, /*peer_len=*/0, initial_result, state,
                                                    "client", &config, &policy, &client_sockets);
    return drove & state.terminal_success & policy.preferred_address_request_queued &
           (endpoint.next_on_core_result_index == 2);
}

bool server_connectionmigration_preferred_address_config_for_tests() {
    const auto inspect_preferred_address = [](const Http09RuntimeConfig &config) {
        const auto core = make_http09_server_core_config(config);
        const bool has_preferred_address = core.transport.preferred_address.has_value();
        const auto preferred_port =
            has_preferred_address ? core.transport.preferred_address->ipv4_port : 0;
        const auto preferred_connection_id = has_preferred_address
                                                 ? core.transport.preferred_address->connection_id
                                                 : ConnectionId{};
        return std::tuple{has_preferred_address, preferred_port, preferred_connection_id};
    };

    const auto [has_preferred_address, preferred_port, preferred_connection_id] =
        inspect_preferred_address(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
        });
    const auto [transfer_has_preferred_address, transfer_preferred_port,
                transfer_preferred_connection_id] = inspect_preferred_address(Http09RuntimeConfig{
        .mode = Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .testcase = QuicHttp09Testcase::transfer,
    });
    return has_preferred_address & (preferred_port == 444) &
           (preferred_connection_id == make_runtime_connection_id(std::byte{0x5a}, 1)) &
           !transfer_has_preferred_address & (transfer_preferred_port == 0) &
           transfer_preferred_connection_id.empty();
}

bool runtime_connectionmigration_request_flow_case_for_tests(bool official_alias,
                                                             bool include_preferred_address,
                                                             bool keep_path_route) {
    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
        .testcase =
            official_alias ? QuicHttp09Testcase::transfer : QuicHttp09Testcase::connectionmigration,
        .requests_env = official_alias ? "https://server46:443/file.bin" : "",
    };

    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = 17,
                .family = AF_INET,
            },
    };
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_ready,
    });
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_confirmed,
    });
    if (include_preferred_address) {
        result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
            .preferred_address =
                PreferredAddress{
                    .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
                    .ipv4_port = 4444,
                    .connection_id = make_runtime_connection_id(std::byte{0x5a}, 1),
                },
        });
    }

    if (!observe_client_runtime_policy_effects(result, state, policy, client_sockets, "client")) {
        return false;
    }
    if (!keep_path_route) {
        state.path_routes.clear();
    }

    std::vector<QuicCoreInput> core_inputs;
    maybe_queue_client_runtime_policy_inputs(config, policy, core_inputs);

    if (!policy.preferred_address_path_id.has_value() || core_inputs.size() != 1) {
        return false;
    }
    const auto preferred_address_path_id = policy.preferred_address_path_id.value_or(QuicPathId{});
    if (!official_alias && !state.path_routes.contains(preferred_address_path_id)) {
        return false;
    }
    const auto &request = std::get<QuicCoreRequestConnectionMigration>(core_inputs.front());
    return policy.handshake_ready_seen && policy.handshake_confirmed_seen &&
           policy.preferred_address_request_queued &&
           (request.path_id == preferred_address_path_id) &&
           (request.reason == QuicMigrationRequestReason::preferred_address) &&
           (official_alias || (state.path_routes.at(preferred_address_path_id).socket_fd == 17));
}

bool runtime_connectionmigration_request_flow_for_tests() {
    return runtime_connectionmigration_request_flow_case_for_tests(
        /*official_alias=*/false, /*include_preferred_address=*/true,
        /*keep_path_route=*/true);
}

bool runtime_official_connectionmigration_client_request_flow_for_tests() {
    return runtime_connectionmigration_request_flow_case_for_tests(
        /*official_alias=*/true, /*include_preferred_address=*/true, /*keep_path_route=*/true);
}

bool runtime_cross_family_preferred_address_uses_compatible_socket_for_tests() {
    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = 17,
                .family = AF_INET,
            },
    };
    QuicCoreResult result;
    result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
        .preferred_address =
            PreferredAddress{
                .ipv6_address =
                    {
                        std::byte{0x20},
                        std::byte{0x01},
                        std::byte{0x0d},
                        std::byte{0xb8},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x46},
                    },
                .ipv6_port = 4444,
                .connection_id = make_runtime_connection_id(std::byte{0x5a}, 1),
            },
    });

    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .socket_fn = [](int family, int, int) -> int {
                if (family != AF_INET6) {
                    errno = EAFNOSUPPORT;
                    return -1;
                }
                return 23;
            },
            .setsockopt_fn = [](int, int, int, const void *, socklen_t) -> int { return 0; },
        },
    };

    if (!observe_client_runtime_policy_effects(result, state, policy, client_sockets, "client")) {
        return false;
    }
    if (!policy.preferred_address_path_id.has_value()) {
        return false;
    }

    const auto route_it = state.path_routes.find(*policy.preferred_address_path_id);
    return route_it != state.path_routes.end() && route_it->second.peer.ss_family == AF_INET6 &&
           route_it->second.socket_fd == 23;
}

bool runtime_client_loop_uses_all_active_sockets_for_tests() {
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .socket_fn = [](int family, int, int) -> int {
                if (family != AF_INET6) {
                    errno = EAFNOSUPPORT;
                    return -1;
                }
                return 23;
            },
            .setsockopt_fn = [](int, int, int, const void *, socklen_t) -> int { return 0; },
        },
    };

    ScriptedEndpointForTests endpoint;
    endpoint.on_core_result_updates.push_back(QuicHttp09EndpointUpdate{});

    QuicCore core = make_local_error_client_core_for_tests();
    QuicCoreResult start_result;
    start_result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
        .preferred_address =
            PreferredAddress{
                .ipv6_address =
                    {
                        std::byte{0x20},
                        std::byte{0x01},
                        std::byte{0x0d},
                        std::byte{0xb8},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x00},
                        std::byte{0x46},
                    },
                .ipv6_port = 4444,
                .connection_id = make_runtime_connection_id(std::byte{0x5a}, 1),
            },
    });

    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(443);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    EndpointDriveState state;
    ClientRuntimePolicyState client_policy;
    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = 17,
                .family = AF_INET,
            },
    };
    WaitCaptureClientLoopIoForTests io_capture;
    const int exit_code = run_http09_client_connection_loop(
        Http09RuntimeConfig{
            .mode = Http09RuntimeMode::client,
            .testcase = QuicHttp09Testcase::connectionmigration,
        },
        make_endpoint_driver(endpoint), core, client_sockets,
        /*idle_timeout_ms=*/kDefaultClientReceiveTimeoutMs, peer,
        static_cast<socklen_t>(sizeof(sockaddr_in)), state, client_policy,
        make_wait_capture_client_loop_io_for_tests(io_capture), start_result);
    return exit_code == 1 && io_capture.wait_called && io_capture.wait_socket_fd_count == 2 &&
           io_capture.wait_socket_fds[0] == 17 && io_capture.wait_socket_fds[1] == 23;
}

bool runtime_regular_transfer_does_not_queue_preferred_address_migration_for_tests() {
    const Http09RuntimeConfig config{
        .mode = Http09RuntimeMode::client,
        .testcase = QuicHttp09Testcase::transfer,
        .requests_env = "https://localhost:443/file.bin",
    };

    EndpointDriveState state;
    ClientRuntimePolicyState policy;
    ClientSocketSet client_sockets{
        .primary =
            ClientSocketDescriptor{
                .fd = 17,
                .family = AF_INET,
            },
    };
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_ready,
    });
    result.effects.emplace_back(QuicCoreStateEvent{
        .change = QuicCoreStateChange::handshake_confirmed,
    });
    result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
        .preferred_address =
            PreferredAddress{
                .ipv4_address = {std::byte{127}, std::byte{0}, std::byte{0}, std::byte{2}},
                .ipv4_port = 4444,
                .connection_id = make_runtime_connection_id(std::byte{0x5a}, 1),
            },
    });

    if (!observe_client_runtime_policy_effects(result, state, policy, client_sockets, "client")) {
        return false;
    }
    std::vector<QuicCoreInput> core_inputs;
    maybe_queue_client_runtime_policy_inputs(config, policy, core_inputs);
    return policy.handshake_ready_seen & policy.handshake_confirmed_seen &
           policy.preferred_address_path_id.has_value() & !policy.preferred_address_request_queued &
           core_inputs.empty();
}

bool runtime_registers_all_server_core_connection_ids_case_for_tests(
    bool include_preferred_address) {
    auto core_config = make_http09_server_core_config(Http09RuntimeConfig{
        .mode = Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .testcase = include_preferred_address ? QuicHttp09Testcase::connectionmigration
                                              : QuicHttp09Testcase::transfer,
    });
    if (!core_config.transport.preferred_address.has_value()) {
        return false;
    }

    const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
    const auto preferred_connection_id_key =
        connection_id_key(core_config.transport.preferred_address->connection_id);

    ServerConnectionIdRouteMap connection_id_routes;
    ServerSession session{
        .core = QuicCore(std::move(core_config)),
        .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = std::filesystem::temp_directory_path(),
        }),
        .state = EndpointDriveState{},
        .socket_fd = -1,
        .peer = {},
        .peer_len = 0,
        .local_connection_id_key = local_connection_id_key,
        .initial_destination_connection_id_key = "unused-initial",
    };

    refresh_server_session_connection_id_routes(session, connection_id_routes);

    const bool has_preferred_connection_id_key = !preferred_connection_id_key.empty();
    const bool has_route = connection_id_routes.contains(preferred_connection_id_key);
    const bool route_matches = has_route & (connection_id_routes.at(preferred_connection_id_key) ==
                                            local_connection_id_key);
    return has_preferred_connection_id_key & has_route & route_matches &
           (session.alternate_connection_id_keys.size() == 1) &
           (session.alternate_connection_id_keys.front() == preferred_connection_id_key);
}

bool runtime_registers_all_server_core_connection_ids_for_tests() {
    return runtime_registers_all_server_core_connection_ids_case_for_tests(
        /*include_preferred_address=*/true);
}

bool runtime_misc_internal_coverage_for_tests() {
    struct ScopedEnvVar {
        std::string name;
        std::optional<std::string> previous;

        ScopedEnvVar(std::string variable, std::optional<std::string> value)
            : name(std::move(variable)) {
            if (const char *existing = std::getenv(name.c_str()); existing != nullptr) {
                previous = std::string(existing);
            }
            if (value.has_value()) {
                ::setenv(name.c_str(), value->c_str(), 1);
            } else {
                ::unsetenv(name.c_str());
            }
        }

        ~ScopedEnvVar() {
            if (previous.has_value()) {
                ::setenv(name.c_str(), previous->c_str(), 1);
            } else {
                ::unsetenv(name.c_str());
            }
        }
    };

    bool ok = true;
    const auto check = [&](std::string_view label, bool condition) {
        if (!condition) {
            std::cerr << "runtime_misc_internal_coverage_for_tests failed: " << label << '\n';
            ok = false;
        }
        return condition;
    };

    {
        static_cast<void>(::setenv("COQUIC_RUNTIME_MISC_RESTORE", "seed", 1));
        {
            ScopedEnvVar unset_existing("COQUIC_RUNTIME_MISC_RESTORE", std::nullopt);
            check("scoped env clears existing variable",
                  std::getenv("COQUIC_RUNTIME_MISC_RESTORE") == nullptr);
        }
        check("scoped env restores previous variable",
              getenv_string("COQUIC_RUNTIME_MISC_RESTORE").value_or("") == "seed");
        static_cast<void>(::unsetenv("COQUIC_RUNTIME_MISC_RESTORE"));
    }

    static_cast<void>(check("expected diagnostic path", false));
    ok = true;

    sockaddr_storage invalid_address{};
    invalid_address.ss_family = AF_UNSPEC;
    check("format trace empty length", format_sockaddr_for_trace(invalid_address, 0) == "-");
    check("format trace invalid family",
          format_sockaddr_for_trace(invalid_address, sizeof(invalid_address)) == "-");

    check("empty host unspecified", host_is_unspecified(""));
    check("named host not unspecified", !host_is_unspecified("interop-server-host"));

    {
        ScopedEnvVar empty_hostname("HOSTNAME", std::string{});
        const auto gethostname_fn = [](char *buffer, size_t length) -> int {
            if (length == 0) {
                errno = EINVAL;
                return -1;
            }
            std::strncpy(buffer, "runtime-host", length);
            buffer[length - 1] = '\0';
            return 0;
        };
        char dummy = '\0';
        check("zero-length gethostname fails",
              (gethostname_fn(&dummy, 0) == -1) & (errno == EINVAL));
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .gethostname_fn = gethostname_fn,
            },
        };
        check("hostname fallback succeeds",
              preferred_address_host_for_server("").value_or("") == "runtime-host");
    }

    {
        ScopedEnvVar unset_hostname("HOSTNAME", std::nullopt);
        const auto gethostname_fn = [](char *buffer, size_t length) -> int {
            if (length == 0) {
                errno = EINVAL;
                return -1;
            }
            buffer[0] = '\0';
            return 0;
        };
        char dummy = '\0';
        check("empty hostname zero-length gethostname fails",
              (gethostname_fn(&dummy, 0) == -1) & (errno == EINVAL));
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .gethostname_fn = gethostname_fn,
            },
        };
        check("hostname fallback empty string returns nullopt",
              !preferred_address_host_for_server("").has_value());
    }

    {
        ScopedEnvVar empty_hostname("HOSTNAME", std::string{});
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .gethostname_fn = [](char *, size_t) -> int {
                    errno = EIO;
                    return -1;
                },
            },
        };
        check("hostname fallback failure returns nullopt",
              !preferred_address_host_for_server("").has_value());
        check("preferred address lookup failure returns nullopt",
              !runtime_preferred_address_for_server(
                   Http09RuntimeConfig{
                       .mode = Http09RuntimeMode::server,
                       .host = "",
                       .port = 443,
                       .testcase = QuicHttp09Testcase::connectionmigration,
                   })
                   .has_value());
    }

    check("invalid host preferred address fails",
          !runtime_preferred_address_for_server(
               Http09RuntimeConfig{
                   .mode = Http09RuntimeMode::server,
                   .host = "invalid host",
                   .port = 443,
                   .testcase = QuicHttp09Testcase::connectionmigration,
               })
               .has_value());

    PreferredAddress ipv6_preferred_address{
        .ipv6_address =
            {
                std::byte{0x20},
                std::byte{0x01},
                std::byte{0x0d},
                std::byte{0xb8},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x09},
            },
        .ipv6_port = 4444,
        .connection_id = make_runtime_connection_id(std::byte{0x5a}, 7),
    };
    const auto ipv6_sockaddr = sockaddr_from_preferred_address(ipv6_preferred_address);
    const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(&ipv6_sockaddr);
    check("preferred address sockaddr family", ipv6->sin6_family == AF_INET6);
    check("preferred address sockaddr port", ntohs(ipv6->sin6_port) == 4444);

    ResolvedUdpAddress ipv4_resolved{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&ipv4_resolved.address);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4443);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ipv4_resolved.address_len = sizeof(sockaddr_in);
    ipv4_resolved.family = AF_INET;
    const auto ipv4_preferred_address =
        preferred_address_from_resolved_udp_address(ipv4_resolved, {});
    check("preferred address ipv4 port", ipv4_preferred_address.ipv4_port == 4443);
    check("preferred address empty cid still mints reset token",
          std::ranges::any_of(ipv4_preferred_address.stateless_reset_token,
                              [](std::byte value) { return value != std::byte{0x00}; }));
    ResolvedUdpAddress unknown_family_resolved{};
    unknown_family_resolved.family = AF_UNSPEC;
    const auto unknown_family_preferred_address =
        preferred_address_from_resolved_udp_address(unknown_family_resolved, {});
    check("preferred address unknown family leaves ports empty",
          (unknown_family_preferred_address.ipv4_port == 0) &
              (unknown_family_preferred_address.ipv6_port == 0));

    check("wait without sockets fails", !wait_for_socket_or_deadline(
                                             RuntimeWaitConfig{
                                                 .socket_fds = {-1, -1},
                                                 .socket_fd_count = 0,
                                                 .idle_timeout_ms = 1,
                                                 .role_name = "client",
                                             },
                                             std::nullopt)
                                             .has_value());

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .poll_fn = [](pollfd *, nfds_t, int) -> int { return 1; },
            },
        };
        check("wait unreadable socket fails", !wait_for_socket_or_deadline(
                                                   RuntimeWaitConfig{
                                                       .socket_fds = {-1, -1},
                                                       .socket_fd_count = 1,
                                                       .idle_timeout_ms = 1,
                                                       .role_name = "client",
                                                   },
                                                   std::nullopt)
                                                   .has_value());
    }

    {
        EndpointDriveState state;
        RuntimeWaitStep step{
            .input = QuicCoreTimerExpired{},
            .input_time = now(),
            .socket_fd = 7,
            .source = ipv6_sockaddr,
            .source_len = sizeof(sockaddr_in6),
            .has_source = true,
        };
        check("timer step does not assign path",
              !assign_runtime_path_for_inbound_step(state, step).has_value());
    }

    check("invalid requests env does not trigger migration",
          !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
              .mode = Http09RuntimeMode::client,
              .testcase = QuicHttp09Testcase::transfer,
              .requests_env = "not-a-valid-request",
          }));
    check("server transfer request never triggers migration",
          !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
              .mode = Http09RuntimeMode::server,
              .testcase = QuicHttp09Testcase::transfer,
              .requests_env = "https://server46:443/file.bin",
          }));
    check("non-server46 transfer request does not trigger migration",
          !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
              .mode = Http09RuntimeMode::client,
              .testcase = QuicHttp09Testcase::transfer,
              .requests_env = "https://example.com:443/file.bin",
          }));

    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
        const auto run_traced_input = [&](QuicCoreInput input) {
            QuicCore trace_core = make_local_error_client_core_for_tests();
            const std::array<QuicCoreInput, 1> inputs = {
                std::move(input),
            };
            static_cast<void>(advance_core_with_inputs(trace_core, inputs, now()));
        };
        run_traced_input(QuicCoreStart{});
        run_traced_input(QuicCoreInboundDatagram{
            .bytes = bytes_from_string_for_runtime_tests("input"),
            .path_id = 4,
        });
        run_traced_input(QuicCoreResetStream{.stream_id = 0, .application_error_code = 1});
        run_traced_input(QuicCoreStopSending{.stream_id = 0, .application_error_code = 2});
        run_traced_input(QuicCoreRequestKeyUpdate{});
        run_traced_input(QuicCoreRequestConnectionMigration{
            .path_id = 9,
            .reason = QuicMigrationRequestReason::preferred_address,
        });
        run_traced_input(QuicCoreRequestConnectionMigration{
            .path_id = 10,
            .reason = QuicMigrationRequestReason::active,
        });
        run_traced_input(QuicCoreTimerExpired{});

        EndpointDriveState state;
        ClientRuntimePolicyState policy;
        ClientSocketSet client_sockets{
            .primary =
                ClientSocketDescriptor{
                    .fd = 17,
                    .family = AF_INET,
                },
        };
        QuicCoreResult result;
        result.effects.emplace_back(QuicCoreStateEvent{
            .change = QuicCoreStateChange::handshake_ready,
        });
        result.effects.emplace_back(QuicCoreStateEvent{
            .change = QuicCoreStateChange::handshake_confirmed,
        });
        result.effects.emplace_back(QuicCorePeerPreferredAddressAvailable{
            .preferred_address = ipv6_preferred_address,
        });
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .socket_fn = [](int family, int, int) -> int {
                    if (family != AF_INET6) {
                        errno = EAFNOSUPPORT;
                        return -1;
                    }
                    return 23;
                },
                .setsockopt_fn = [](int, int, int, const void *, socklen_t) -> int { return 0; },
            },
        };
        check(
            "policy observes cross-family preferred address",
            observe_client_runtime_policy_effects(result, state, policy, client_sockets, "client"));
        std::vector<QuicCoreInput> core_inputs;
        maybe_queue_client_runtime_policy_inputs(
            Http09RuntimeConfig{
                .mode = Http09RuntimeMode::client,
                .testcase = QuicHttp09Testcase::connectionmigration,
            },
            policy, core_inputs);
        check("policy records preferred address path",
              policy.preferred_address_path_id.has_value());
        check("policy queues one migration input", core_inputs.size() == 1);

        const auto client_timer_trace = run_client_connection_loop_case_for_tests(
            ClientConnectionLoopCaseForTests::outer_timer_then_wait_failure);
        check("client timer trace samples time", client_timer_trace.current_time_calls > 0);
        const auto client_timer_send_trace = run_client_connection_loop_case_for_tests(
            ClientConnectionLoopCaseForTests::timer_due_emits_send_trace_with_future_wakeup);
        check("client timer trace records send-count path",
              client_timer_send_trace.current_time_calls > 0);
    }

    {
        g_recorded_sendto_for_tests = {};
        sockaddr_in short_ipv4{};
        short_ipv4.sin_family = AF_INET;
        short_ipv4.sin_port = htons(4445);
        static_cast<void>(record_sendto_for_tests(
            /*socket_fd=*/31, nullptr, /*length=*/5, /*flags=*/0,
            reinterpret_cast<const sockaddr *>(&short_ipv4),
            static_cast<socklen_t>(sizeof(sockaddr_in) - 1)));
        sockaddr_in6 short_ipv6{};
        short_ipv6.sin6_family = AF_INET6;
        short_ipv6.sin6_port = htons(4446);
        static_cast<void>(record_sendto_for_tests(
            /*socket_fd=*/32, nullptr, /*length=*/7, /*flags=*/0,
            reinterpret_cast<const sockaddr *>(&short_ipv6),
            static_cast<socklen_t>(sizeof(sockaddr_in6) - 1)));
        check("short sendto destinations keep peer port zero",
              g_recorded_sendto_for_tests.peer_ports == std::vector<std::uint16_t>{0, 0});
    }

    {
        auto core_config = make_http09_server_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
        });
        const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
        ServerConnectionIdRouteMap connection_id_routes{
            {"stale-route", local_connection_id_key},
        };
        ServerSession session{
            .core = QuicCore(std::move(core_config)),
            .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                .document_root = std::filesystem::temp_directory_path(),
            }),
            .state = EndpointDriveState{},
            .socket_fd = -1,
            .peer = {},
            .peer_len = 0,
            .local_connection_id_key = local_connection_id_key,
            .initial_destination_connection_id_key = "initial-route",
            .alternate_connection_id_keys = {"stale-route"},
        };
        refresh_server_session_connection_id_routes(session, connection_id_routes);
        check("refresh removes stale route", !connection_id_routes.contains("stale-route"));
    }

    {
        auto core_config = make_http09_server_core_config(Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
        });
        const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
        ServerSessionMap sessions;
        ServerConnectionIdRouteMap connection_id_routes{
            {"alternate-route", local_connection_id_key},
        };
        std::unordered_map<std::string, std::string> initial_destination_routes{
            {"initial-route", local_connection_id_key},
        };
        sessions.emplace(local_connection_id_key,
                         std::make_unique<ServerSession>(ServerSession{
                             .core = QuicCore(std::move(core_config)),
                             .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                 .document_root = std::filesystem::temp_directory_path(),
                             }),
                             .state = EndpointDriveState{},
                             .socket_fd = -1,
                             .peer = {},
                             .peer_len = 0,
                             .local_connection_id_key = local_connection_id_key,
                             .initial_destination_connection_id_key = "initial-route",
                             .alternate_connection_id_keys = {"alternate-route"},
                         }));
        erase_server_session_with_routes(sessions, connection_id_routes, initial_destination_routes,
                                         local_connection_id_key);
        check("erase removes session", !sessions.contains(local_connection_id_key));
        check("erase removes alternate route", !connection_id_routes.contains("alternate-route"));
        check("erase removes initial route", !initial_destination_routes.contains("initial-route"));
    }

    {
        const auto server_config = Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "invalid host",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        };
        check("invalid host server fails", run_http09_server(server_config) == 1);
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .socket_fn = [](int, int, int) -> int {
                    static thread_local int next_fd = 760;
                    return next_fd++;
                },
                .bind_fn = [](int, const sockaddr *, socklen_t) -> int { return 0; },
                // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
                .getaddrinfo_fn = [](const char *node, const char *service, const addrinfo *hints,
                                     addrinfo **results) -> int {
                    static thread_local int call_count = 0;
                    ++call_count;
                    if (call_count == 2) {
                        return EAI_FAIL;
                    }
                    return ::getaddrinfo(node, service, hints, results);
                },
                .freeaddrinfo_fn = ::freeaddrinfo,
            },
        };
        const auto server_config = Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        };
        check("preferred bind resolve failure aborts server",
              run_http09_server(server_config) == 1);
    }

    {
        const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            Http09RuntimeOpsOverride{
                .socket_fn = [](int, int, int) -> int {
                    static thread_local int next_fd = 700;
                    return next_fd++;
                },
                .bind_fn = [](int, const sockaddr *, socklen_t) -> int {
                    static thread_local int bind_calls = 0;
                    ++bind_calls;
                    if (bind_calls == 2) {
                        errno = EADDRINUSE;
                        return -1;
                    }
                    return 0;
                },
            },
        };
        const auto server_config = Http09RuntimeConfig{
            .mode = Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = QuicHttp09Testcase::connectionmigration,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        };
        check("second bind failure aborts server", run_http09_server(server_config) == 1);
    }

    {
        auto duplicate_seed_peer = ipv6_sockaddr;
        QuicCore core = make_failed_server_core_for_tests();
        const std::array seeded_paths{
            RuntimePathSeedForTests{
                .socket_fd = 11,
                .peer = duplicate_seed_peer,
                .peer_len = sizeof(sockaddr_in6),
            },
            RuntimePathSeedForTests{
                .socket_fd = 11,
                .peer = duplicate_seed_peer,
                .peer_len = sizeof(sockaddr_in6),
            },
        };
        const auto duplicate_result = route_existing_server_session_datagram_for_tests(
            core, seeded_paths, bytes_from_string_for_runtime_tests("local"),
            bytes_from_string_for_runtime_tests("odcid"),
            /*inbound_socket_fd=*/11, duplicate_seed_peer, sizeof(sockaddr_in6),
            bytes_from_string_for_runtime_tests("payload"), now());
        check("duplicate seeded route is rejected", !duplicate_result.processed);
    }

    {
        QuicCore core = make_failed_server_core_for_tests();
        const auto unparsable_result = route_existing_server_session_datagram_for_tests(
            core, std::span<const RuntimePathSeedForTests>{},
            bytes_from_string_for_runtime_tests("local"),
            bytes_from_string_for_runtime_tests("odcid"), /*inbound_socket_fd=*/11, ipv6_sockaddr,
            sizeof(sockaddr_in6), std::vector<std::byte>{std::byte{0x00}}, now());
        check("unparsable datagram is rejected", !unparsable_result.processed);
    }

    return ok;
}

bool runtime_additional_internal_coverage_for_tests() {
    bool ok = true;
    const auto check = [&](std::string_view label, bool condition) {
        static_cast<void>(label);
        ok &= condition;
        return condition;
    };

    check("empty transfer requests do not trigger migration",
          !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
              .mode = Http09RuntimeMode::client,
              .testcase = QuicHttp09Testcase::transfer,
              .requests_env = "",
          }));
    check("non-server46 transfer request still does not trigger migration",
          !runtime_client_should_attempt_preferred_address_migration(Http09RuntimeConfig{
              .mode = Http09RuntimeMode::client,
              .testcase = QuicHttp09Testcase::transfer,
              .requests_env = "https://example.com:443/file.bin",
          }));

    g_recorded_sendto_for_tests = {};
    static_cast<void>(record_sendto_for_tests(
        /*socket_fd=*/33, nullptr, /*length=*/0, /*flags=*/0, /*destination=*/nullptr,
        /*destination_len=*/0));
    check("null sendto destination keeps peer port zero",
          g_recorded_sendto_for_tests.peer_ports == std::vector<std::uint16_t>{0});

    return ok;
}

bool runtime_connectionmigration_failure_paths_for_tests() {
    return !runtime_connectionmigration_request_flow_case_for_tests(
               /*official_alias=*/false, /*include_preferred_address=*/false,
               /*keep_path_route=*/true) &
           !runtime_connectionmigration_request_flow_case_for_tests(
               /*official_alias=*/false, /*include_preferred_address=*/true,
               /*keep_path_route=*/false) &
           !runtime_connectionmigration_request_flow_case_for_tests(
               /*official_alias=*/true, /*include_preferred_address=*/false,
               /*keep_path_route=*/true) &
           !runtime_registers_all_server_core_connection_ids_case_for_tests(
               /*include_preferred_address=*/false);
}

bool runtime_restart_failure_paths_for_tests() {
    return !core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
               /*force_serialization_failure=*/true) &
           !core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
               /*force_serialization_failure=*/false, /*force_path_id_mismatch=*/true) &
           !core_retry_restart_preserves_inbound_path_ids_case_for_tests(
               /*force_integrity_failure=*/true, /*force_serialization_failure=*/false) &
           !core_retry_restart_preserves_inbound_path_ids_case_for_tests(
               /*force_integrity_failure=*/false, /*force_serialization_failure=*/true) &
           !core_retry_restart_preserves_inbound_path_ids_case_for_tests(
               /*force_integrity_failure=*/false, /*force_serialization_failure=*/false,
               /*force_path_id_mismatch=*/true);
}

ExistingServerSessionDatagramRouteResultForTests route_existing_server_session_datagram_for_tests(
    QuicCore &core, std::span<const RuntimePathSeedForTests> seeded_paths,
    std::span<const std::byte> local_connection_id,
    std::span<const std::byte> initial_destination_connection_id, int inbound_socket_fd,
    const sockaddr_storage &inbound_peer, socklen_t inbound_peer_len, std::vector<std::byte> bytes,
    QuicCoreTimePoint input_time) {
    ExistingServerSessionDatagramRouteResultForTests result;
    g_recorded_sendto_for_tests = {};
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    };

    ScopedRuntimeTempDirForTests document_root;
    ServerSession session{
        .core = std::move(core),
        .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
            .document_root = document_root.path(),
        }),
        .state = EndpointDriveState{},
        .socket_fd = seeded_paths.empty() ? -1 : seeded_paths.back().socket_fd,
        .peer = seeded_paths.empty() ? sockaddr_storage{} : seeded_paths.back().peer,
        .peer_len = seeded_paths.empty() ? 0 : seeded_paths.back().peer_len,
        .local_connection_id_key = connection_id_key(local_connection_id),
        .initial_destination_connection_id_key =
            connection_id_key(initial_destination_connection_id),
    };
    for (std::size_t index = 0; index < seeded_paths.size(); ++index) {
        const auto &seed = seeded_paths[index];
        if (remember_runtime_path(session.state, seed.peer, seed.peer_len, seed.socket_fd) !=
            static_cast<QuicPathId>(index + 1)) {
            core = std::move(session.core);
            return result;
        }
    }

    RuntimeWaitStep step{
        .input =
            QuicCoreInboundDatagram{
                .bytes = std::move(bytes),
            },
        .input_time = input_time,
        .socket_fd = inbound_socket_fd,
        .source = inbound_peer,
        .source_len = inbound_peer_len,
        .has_source = true,
    };
    const auto parsed = parse_server_datagram_for_routing(
        std::span<const std::byte>(std::get<QuicCoreInboundDatagram>(*step.input).bytes.data(),
                                   std::get<QuicCoreInboundDatagram>(*step.input).bytes.size()));
    if (!parsed.has_value()) {
        core = std::move(session.core);
        return result;
    }

    bool erased = false;
    ServerConnectionIdRouteMap connection_id_routes;
    result.processed = process_existing_server_session_datagram(
        session, step, connection_id_routes, *parsed, [&](const std::string &) { erased = true; });
    result.erased = erased;
    if (const auto route_it = session.state.path_routes.find(2);
        route_it != session.state.path_routes.end()) {
        result.has_migrated_path_route = true;
        result.migrated_path_socket_fd = route_it->second.socket_fd;
    }
    result.sendto_calls = g_recorded_sendto_for_tests.calls;
    result.sendto_socket_fd = g_recorded_sendto_for_tests.socket_fd;
    result.sendto_peer_port = g_recorded_sendto_for_tests.peer_port;
    result.sendto_socket_fds = g_recorded_sendto_for_tests.socket_fds;
    result.sendto_peer_ports = g_recorded_sendto_for_tests.peer_ports;
    core = std::move(session.core);
    return result;
}

ExistingServerSessionDatagramRouteResultForTests route_existing_server_session_datagram_for_tests(
    QuicCore &core, int established_socket_fd, const sockaddr_storage &established_peer,
    socklen_t established_peer_len, std::span<const std::byte> local_connection_id,
    std::span<const std::byte> initial_destination_connection_id, int inbound_socket_fd,
    const sockaddr_storage &inbound_peer, socklen_t inbound_peer_len, std::vector<std::byte> bytes,
    QuicCoreTimePoint input_time) {
    const std::array seeded_paths{
        RuntimePathSeedForTests{
            .socket_fd = established_socket_fd,
            .peer = established_peer,
            .peer_len = established_peer_len,
        },
    };
    return route_existing_server_session_datagram_for_tests(
        core, seeded_paths, local_connection_id, initial_destination_connection_id,
        inbound_socket_fd, inbound_peer, inbound_peer_len, std::move(bytes), input_time);
}

bool core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
    bool force_serialization_failure, bool force_path_id_mismatch) {
    const Http09RuntimeConfig runtime_config{
        .mode = Http09RuntimeMode::client,
    };
    auto core_config = make_runtime_client_core_config(runtime_config, /*connection_index=*/3);
    core_config.original_version = kQuicVersion1;
    core_config.initial_version = kQuicVersion1;
    core_config.supported_versions = {kQuicVersion2, kQuicVersion1};
    const auto source_connection_id = core_config.source_connection_id;
    const auto initial_destination_connection_id = core_config.initial_destination_connection_id;
    QuicCore core(std::move(core_config));

    const auto version_negotiation_packet = serialize_packet(VersionNegotiationPacket{
        .destination_connection_id = source_connection_id,
        .source_connection_id = initial_destination_connection_id,
        .supported_versions = force_serialization_failure
                                  ? std::vector<std::uint32_t>{}
                                  : std::vector<std::uint32_t>{kQuicVersion2},
    });
    if (!version_negotiation_packet.has_value()) {
        return false;
    }

    constexpr QuicPathId kInboundPathId = 41;
    const auto result = core.advance(
        QuicCoreInboundDatagram{
            .bytes = version_negotiation_packet.value(),
            .path_id = kInboundPathId,
        },
        now());

    auto effects = result.effects;
    effects.insert(effects.begin(), QuicCoreStateEvent{
                                        .change = QuicCoreStateChange::handshake_ready,
                                    });
    if (force_path_id_mismatch) {
        effects.emplace_back(QuicCoreSendDatagram{
            .path_id = std::nullopt,
            .bytes = {std::byte{0x01}},
        });
    }
    bool saw_send = false;
    bool all_sends_match_path = true;
    for (const auto &effect : effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }
        saw_send = true;
        if (send->path_id != std::optional<QuicPathId>{kInboundPathId}) {
            all_sends_match_path = false;
        }
    }
    return saw_send & all_sends_match_path;
}

bool core_version_negotiation_restart_preserves_inbound_path_ids_for_tests() {
    return core_version_negotiation_restart_preserves_inbound_path_ids_case_for_tests(
        /*force_serialization_failure=*/false);
}

bool core_retry_restart_preserves_inbound_path_ids_case_for_tests(bool force_integrity_failure,
                                                                  bool force_serialization_failure,
                                                                  bool force_path_id_mismatch) {
    const Http09RuntimeConfig runtime_config{
        .mode = Http09RuntimeMode::client,
    };
    auto core_config = make_runtime_client_core_config(runtime_config, /*connection_index=*/4);
    const auto source_connection_id = core_config.source_connection_id;
    const auto original_destination_connection_id = core_config.initial_destination_connection_id;
    const auto retry_source_connection_id =
        make_runtime_connection_id(std::byte{0x73}, /*sequence=*/9);
    QuicCore core(std::move(core_config));

    RetryPacket retry_packet{
        .version = kQuicVersion1,
        .retry_unused_bits = 0,
        .destination_connection_id = source_connection_id,
        .source_connection_id = retry_source_connection_id,
        .retry_token = {std::byte{0x99}, std::byte{0x98}},
    };
    if (force_integrity_failure) {
        retry_packet.version = kVersionNegotiationVersion;
    }
    const auto retry_integrity =
        compute_retry_integrity_tag(retry_packet, original_destination_connection_id);
    if (!retry_integrity.has_value()) {
        return false;
    }
    retry_packet.retry_integrity_tag = retry_integrity.value();
    if (force_serialization_failure) {
        retry_packet.source_connection_id.assign(21, std::byte{0xaa});
    }
    const auto encoded_retry = serialize_packet(retry_packet);
    if (!encoded_retry.has_value()) {
        return false;
    }

    constexpr QuicPathId kInboundPathId = 52;
    const auto result = core.advance(
        QuicCoreInboundDatagram{
            .bytes = encoded_retry.value(),
            .path_id = kInboundPathId,
        },
        now());

    auto effects = result.effects;
    effects.insert(effects.begin(), QuicCoreStateEvent{
                                        .change = QuicCoreStateChange::handshake_ready,
                                    });
    if (force_path_id_mismatch) {
        effects.emplace_back(QuicCoreSendDatagram{
            .path_id = std::nullopt,
            .bytes = {std::byte{0x02}},
        });
    }
    bool saw_send = false;
    bool all_sends_match_path = true;
    for (const auto &effect : effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }
        saw_send = true;
        if (send->path_id != std::optional<QuicPathId>{kInboundPathId}) {
            all_sends_match_path = false;
        }
    }
    return saw_send & all_sends_match_path;
}

bool core_retry_restart_preserves_inbound_path_ids_for_tests() {
    return core_retry_restart_preserves_inbound_path_ids_case_for_tests(
        /*force_integrity_failure=*/false, /*force_serialization_failure=*/false);
}

bool drive_endpoint_rejects_unknown_transport_selected_path_for_tests() {
    g_recorded_sendto_for_tests = {};
    const test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        Http09RuntimeOpsOverride{
            .sendto_fn = &record_sendto_for_tests,
        },
    };

    sockaddr_storage fallback_peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&fallback_peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(8555);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    EndpointDriveState state;
    QuicCoreResult result;
    result.effects.emplace_back(QuicCoreSendDatagram{
        .path_id = static_cast<QuicPathId>(404),
        .bytes = {std::byte{0xdd}},
    });

    ScriptedEndpointForTests endpoint;
    QuicCore core = make_local_error_client_core_for_tests();
    const bool drove = drive_endpoint_until_blocked(
        make_endpoint_driver(endpoint), core, /*fd=*/18, &fallback_peer,
        static_cast<socklen_t>(sizeof(sockaddr_in)), result, state, "client");
    return !drove & state.terminal_failure & (g_recorded_sendto_for_tests.calls == 0);
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
                const bool made_progress = pump_calls < script.pump_made_progress.size()
                                               ? script.pump_made_progress[pump_calls]
                                               : endpoint_has_pending_work;
                pump_calls += 1;
                return made_progress;
            },
        .has_pending_endpoint_work = [&] { return endpoint_has_pending_work; },
        .process_datagram = [&](const RuntimeWaitStep &) { return script.process_datagram_result; },
    };

    return ServerLoopResultForTests{
        .exit_code = run_http09_server_loop(ServerSocketSet{.primary_fd = -1}, io, driver),
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
    if (const auto qlogdir = getenv_string("QLOGDIR"); qlogdir.has_value() && !qlogdir->empty()) {
        config.qlog_directory = std::filesystem::path(*qlogdir);
    }
    if (const auto sslkeylogfile = getenv_string("SSLKEYLOGFILE");
        sslkeylogfile.has_value() && !sslkeylogfile->empty()) {
        config.tls_keylog_path = std::filesystem::path(*sslkeylogfile);
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
    if (config.qlog_directory.has_value()) {
        core.qlog = QuicQlogConfig{.directory = *config.qlog_directory};
    }
    core.tls_keylog_path = config.tls_keylog_path;
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
