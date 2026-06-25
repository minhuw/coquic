#include "src/http09/http09_runtime_internal.h"

namespace coquic::http09 {

bool &runtime_logging_ready_flag() {
    static bool ready = false;
    return ready;
}

void init_runtime_logging() {
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");
    runtime_logging_ready_flag() = spdlog::default_logger() != nullptr;
}

bool runtime_has_openssl() {
    return OpenSSL_version_num() != 0;
}

int client_receive_timeout_ms(const Http09RuntimeConfig &config) {
    return config.client_receive_timeout_ms;
}

test::Http09RuntimeOpsOverride &runtime_ops() {
    return test::socket_io_backend_ops_for_runtime_tests();
}

void apply_runtime_ops_override(const test::Http09RuntimeOpsOverride &override_ops) {
    test::socket_io_backend_apply_ops_override_for_runtime_tests(override_ops);
}

bool has_legacy_sendto_override() {
    return test::socket_io_backend_has_legacy_sendto_override_for_runtime_tests();
}

bool has_legacy_recvfrom_override() {
    return test::socket_io_backend_has_legacy_recvfrom_override_for_runtime_tests();
}

int linux_traffic_class_for_ecn(QuicEcnCodepoint ecn) {
    return test::socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests(ecn);
}

QuicEcnCodepoint ecn_from_linux_traffic_class(int traffic_class) {
    return test::socket_io_backend_ecn_from_linux_traffic_class_for_runtime_tests(traffic_class);
}

bool configure_linux_ecn_socket_options(LinuxSocketDescriptor socket, int family) {
    return test::socket_io_backend_configure_linux_ecn_socket_options_for_runtime_tests(socket.fd,
                                                                                        family);
}

bool is_ipv4_mapped_ipv6_address(const sockaddr_storage &peer, socklen_t peer_length) {
    return test::socket_io_backend_is_ipv4_mapped_ipv6_address_for_runtime_tests(peer, peer_length);
}

QuicEcnCodepoint recvmsg_ecn_from_control(const msghdr &message) {
    return test::socket_io_backend_recvmsg_ecn_from_control_for_runtime_tests(message);
}

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
    return !value.empty() && value != "0";
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

std::optional<io::QuicIoBackendKind> parse_io_backend_kind(std::string_view value) {
    if (value == "socket") {
        return io::QuicIoBackendKind::socket;
    }
    if (value == "io_uring") {
        return io::QuicIoBackendKind::io_uring;
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

int preferred_udp_address_family(std::string_view host) {
    return test::socket_io_backend_preferred_udp_address_family_for_runtime_tests(host);
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

bool resolve_udp_address(UdpAddressResolutionQuery query, ResolvedUdpAddress &resolved) {
    test::SocketIoBackendResolvedUdpAddressForTests backend_resolved{};
    if (!test::socket_io_backend_resolve_udp_address_for_runtime_tests(
            query.host, query.port, query.extra_flags, query.family, backend_resolved)) {
        return false;
    }

    resolved.address = backend_resolved.address;
    resolved.address_len = backend_resolved.address_len;
    resolved.family = backend_resolved.family;
    return true;
}

PreferredAddress preferred_address_with_connection_id(ConnectionId connection_id) {
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
    return preferred_address;
}

void apply_resolved_udp_address_to_preferred_address(PreferredAddress &preferred_address,
                                                     const ResolvedUdpAddress &resolved) {
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
}

PreferredAddress preferred_address_from_resolved_udp_address(const ResolvedUdpAddress &resolved,
                                                             ConnectionId connection_id) {
    auto preferred_address = preferred_address_with_connection_id(std::move(connection_id));
    apply_resolved_udp_address_to_preferred_address(preferred_address, resolved);
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
    if (first_colon != std::string_view::npos && first_colon == authority.rfind(':')) {
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
    return test::socket_io_backend_open_udp_socket_for_runtime_tests(family);
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

std::optional<PreferredAddress>
runtime_preferred_address_for_server(const Http09RuntimeConfig &config);

void configure_runtime_datagram_profile(QuicTransportConfig &transport) {
    transport.pmtud_enabled = true;
    transport.pmtud_base_datagram_size = kRuntimeMaxOutboundDatagramBytes;
    transport.pmtud_max_datagram_size = kRuntimeMaxOutboundDatagramBytes;
    transport.max_udp_payload_size = kRuntimeMaxOutboundDatagramBytes;
}

QuicCoreConfig make_http09_server_core_config_with_identity(const Http09RuntimeConfig &config,
                                                            TlsIdentity identity) {
    auto core = QuicCoreConfig{
        .role = EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .original_version = config.original_version,
        .initial_version = config.initial_version,
        .supported_versions = config.supported_versions,
        .verify_peer = config.verify_peer,
        .server_name = config.server_name,
        .application_protocol = config.application_protocol,
        .identity = std::move(identity),
        .transport = config.server_transport,
        .max_outbound_datagram_size = kRuntimeMaxOutboundDatagramBytes,
        .allowed_tls_cipher_suites = config.allowed_tls_cipher_suites,
        .zero_rtt = config.server_zero_rtt,
    };
    if (config.qlog_directory.has_value()) {
        core.qlog = QuicQlogConfig{.directory = *config.qlog_directory};
    }
    core.transport.congestion_control = config.congestion_control;
    configure_runtime_datagram_profile(core.transport);
    core.tls_keylog_path = config.tls_keylog_path;
    core.transport.preferred_address = runtime_preferred_address_for_server(config);
    return core;
}

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
    if (!config.enable_server_preferred_address) {
        return std::nullopt;
    }

    const auto preferred_host = preferred_address_host_for_server(config.host);
    if (!preferred_host.has_value()) {
        return std::nullopt;
    }

    const auto preferred_port = static_cast<std::uint16_t>(config.port + 1);
    const auto wildcard_host = host_is_unspecified(config.host);
    if (wildcard_host) {
        auto preferred_address =
            preferred_address_with_connection_id(make_runtime_connection_id(std::byte{0x5a}, 1));
        bool resolved_any_address = false;
        for (const auto family : {AF_INET, AF_INET6}) {
            ResolvedUdpAddress resolved{};
            if (resolve_udp_address(
                    UdpAddressResolutionQuery{
                        .host = *preferred_host,
                        .port = preferred_port,
                        .family = family,
                    },
                    resolved)) {
                apply_resolved_udp_address_to_preferred_address(preferred_address, resolved);
                resolved_any_address = true;
            }
        }
        if (!resolved_any_address) {
            return std::nullopt;
        }
        //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.1
        // # Servers MAY communicate a preferred address of each address family
        // # (IPv4 and IPv6) to allow clients to pick the one most suited to
        // # their network attachment.
        return preferred_address;
    }

    ResolvedUdpAddress preferred_bind{};
    if (!resolve_udp_address(
            UdpAddressResolutionQuery{
                .host = *preferred_host,
                .port = preferred_port,
                .family = preferred_udp_address_family(config.host),
            },
            preferred_bind)) {
        return std::nullopt;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-18.2
    // # Servers MAY choose to only send a preferred address of one address
    // # family by sending an all-zero address and port (0.0.0.0:0 or [::]:0)
    // # for the other family.
    auto preferred_address = preferred_address_from_resolved_udp_address(
        preferred_bind, make_runtime_connection_id(std::byte{0x5a}, 1));
    return preferred_address;
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
    auto destination_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset]));
    if (offset + destination_connection_id_length + 2 > bytes.size()) {
        return std::nullopt;
    }
    ConnectionId destination_connection_id(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + 1),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + 1 + destination_connection_id_length));
    offset += destination_connection_id_length + 1;

    auto source_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset]));
    if (offset + source_connection_id_length + 1 > bytes.size()) {
        return std::nullopt;
    }
    ConnectionId source_connection_id(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + 1),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + 1 + source_connection_id_length));
    offset += source_connection_id_length + 1;

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

bool assign_retry_integrity_tag(RetryPacket &packet,
                                const ConnectionId &original_destination_connection_id) {
    const auto tag = compute_retry_integrity_tag(packet, original_destination_connection_id);
    if (!tag.has_value()) {
        return false;
    }
    packet.retry_integrity_tag = tag.value();
    return true;
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
    if (!assign_retry_integrity_tag(packet, parsed.destination_connection_id)) {
        return false;
    }

    // compute_retry_integrity_tag serializes the same validated RetryPacket image.
    return send_datagram(fd, serialize_packet(packet).value(), peer, peer_len, "server");
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
                   socklen_t peer_len, std::string_view role_name, QuicEcnCodepoint ecn,
                   bool is_pmtu_probe) {
    return test::socket_io_backend_send_datagram_for_runtime_tests(fd, datagram, peer, peer_len,
                                                                   role_name, ecn, is_pmtu_probe);
}

ReceiveDatagramResult receive_datagram(int socket_fd, std::string_view role_name, int flags) {
    auto received =
        test::socket_io_backend_receive_datagram_for_runtime_tests(socket_fd, role_name, flags);
    if (received.status == test::SocketIoBackendReceiveDatagramStatusForTests::would_block) {
        return ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::would_block,
        };
    }
    if (received.status == test::SocketIoBackendReceiveDatagramStatusForTests::error) {
        return ReceiveDatagramResult{
            .status = ReceiveDatagramStatus::error,
        };
    }

    with_runtime_trace([&](std::ostream &stream) {
        stream << "http09-" << role_name << " trace: recv-dgram fd=" << socket_fd
               << " bytes=" << received.bytes.size()
               << " source=" << format_sockaddr_for_trace(received.source, received.source_len)
               << '\n';
    });
    return ReceiveDatagramResult{
        .status = ReceiveDatagramStatus::ok,
        .step =
            RuntimeWaitStep{
                .input =
                    QuicCoreInboundDatagram{
                        .bytes = std::move(received.bytes),
                        .address_validation_identity =
                            std::move(received.address_validation_identity),
                        .ecn = received.ecn,
                    },
                .input_time = now(),
                .socket_fd = socket_fd,
                .source = received.source,
                .source_len = received.source_len,
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
    std::array<int, 2> socket_fds{
        sockets.primary.fd,
        -1,
    };
    if (sockets.secondary.has_value()) {
        socket_fds[1] = sockets.secondary->fd;
    }
    return socket_fds;
}

std::size_t active_client_socket_count(const ClientSocketSet &sockets) {
    std::size_t socket_count = 1u;
    if (sockets.secondary.has_value()) {
        socket_count = 2u;
    }
    return socket_count;
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
                         const std::unordered_map<QuicRouteHandle, RuntimeSendRoute> &route_routes,
                         std::string_view role_name) {
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        int socket_fd = fallback_socket_fd;
        const sockaddr_storage *peer = fallback_peer;
        socklen_t peer_len = fallback_peer_len;
        if (send->route_handle.has_value()) {
            const auto route_it = route_routes.find(*send->route_handle);
            if (route_it == route_routes.end()) {
                std::cerr << "http09-" << role_name
                          << " failed: missing route for route_handle=" << *send->route_handle
                          << '\n';
                return false;
            }
            socket_fd = route_it->second.socket_fd;
            peer = &route_it->second.peer;
            peer_len = route_it->second.peer_len;
        }
        if (socket_fd < 0) {
            std::cerr << "http09-" << role_name
                      << " failed: missing fallback route for send effect\n";
            return false;
        }
        if (peer == nullptr) {
            std::cerr << "http09-" << role_name
                      << " failed: missing fallback route for send effect\n";
            return false;
        }

        with_runtime_trace([&](std::ostream &stream) {
            const std::string route_handle = send->route_handle.has_value()
                                                 ? std::to_string(*send->route_handle)
                                                 : std::string{"-"};
            stream << "http09-" << role_name << " trace: send_effect route_handle=" << route_handle
                   << " socket_fd=" << socket_fd << " peer_len=" << peer_len;
            stream << " peer=" << format_sockaddr_for_trace(*peer, peer_len);
            stream << " bytes=" << send->bytes.size() << '\n';
        });

        if (!send_datagram(socket_fd, send->bytes, *peer, peer_len, role_name, send->ecn,
                           send->is_pmtu_probe)) {
            return false;
        }
    }

    return true;
}

COQUIC_NO_PROFILE void write_advance_core_output_trace(std::ostream &stream,
                                                       const QuicCoreResult &step) {
    stream << "http09-runtime trace: advance_core output effects=" << step.effects.size()
           << " local_error=" << static_cast<int>(step.local_error.has_value())
           << " has_next_wakeup=" << static_cast<int>(step.next_wakeup.has_value());
    for (const auto &effect : step.effects) {
        if (const auto *send = std::get_if<QuicCoreSendDatagram>(&effect)) {
            stream << " send_route="
                   << (send->route_handle.has_value() ? std::to_string(*send->route_handle)
                                                      : std::string{"-"})
                   << " send_bytes=" << send->bytes.size();
        } else if (const auto *reset = std::get_if<QuicCorePeerResetStream>(&effect)) {
            stream << " peer_reset_stream=" << reset->stream_id
                   << " app_error=" << reset->application_error_code
                   << " final_size=" << reset->final_size;
        }
    }
    stream << '\n';
}

COQUIC_NO_PROFILE QuicCoreResult advance_core_with_inputs(QuicCore &core,
                                                          std::span<const QuicCoreInput> inputs,
                                                          QuicCoreTimePoint step_time) {
    for (const auto &input : inputs) {
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-runtime trace: advance_core input=";
            std::visit(
                [&](const auto &value) {
                    using T = std::decay_t<decltype(value)>;
                    if constexpr (std::is_same_v<T, QuicCoreStart>) {
                        stream << "start";
                    } else if constexpr (std::is_same_v<T, QuicCoreInboundDatagram>) {
                        stream << "inbound route_handle="
                               << (value.route_handle.has_value()
                                       ? std::to_string(*value.route_handle)
                                       : std::string{"-"})
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
                        stream << "migration route_handle=" << value.route_handle << " reason="
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
    }
    auto combined = core.advance(inputs, step_time);
    with_runtime_trace([&](std::ostream &trace_stream) {
        write_advance_core_output_trace(trace_stream, combined);
    });
    return combined;
}

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
    const auto path_id = existing != state.path_ids_by_peer_tuple.end() ? existing->second : [&] {
        QuicPathId next_path_id = 1;
        while (state.path_routes.contains(next_path_id)) {
            next_path_id += 1;
        }
        return next_path_id;
    }();
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

QuicRouteHandle remember_runtime_route_handle(EndpointDriveState &state,
                                              const sockaddr_storage &peer, socklen_t peer_len,
                                              int socket_fd) {
    const auto peer_key = runtime_peer_tuple_key(socket_fd, peer, peer_len);
    const auto existing = state.route_handles_by_peer_tuple.find(peer_key);
    const auto route_handle = existing != state.route_handles_by_peer_tuple.end()
                                  ? existing->second
                                  : state.next_route_handle++;
    if (existing == state.route_handles_by_peer_tuple.end()) {
        state.route_handles_by_peer_tuple.emplace(peer_key, route_handle);
    }
    state.route_routes[route_handle] = RuntimeSendRoute{
        .socket_fd = socket_fd,
        .peer = peer,
        .peer_len = peer_len,
    };
    return route_handle;
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
    inbound->route_handle =
        remember_runtime_route_handle(state, step.source, step.source_len, step.socket_fd);
    if (inbound->address_validation_identity.empty()) {
        inbound->address_validation_identity =
            test::socket_io_backend_address_validation_identity_for_runtime_tests(step.source,
                                                                                  step.source_len);
    }
    return path_id;
}

QuicCoreInboundDatagram make_inbound_datagram_from_io_event(const QuicIoRxDatagram &datagram) {
    return QuicCoreInboundDatagram{
        .bytes = datagram.bytes,
        .route_handle = datagram.route_handle,
        .address_validation_identity = datagram.address_validation_identity,
        .ecn = datagram.ecn,
        .shared_bytes = datagram.shared_bytes,
        .begin = datagram.begin,
        .end = datagram.end,
    };
}

QuicIoTxDatagram make_owning_tx_datagram(const QuicIoTxDatagram &datagram) {
    return QuicIoTxDatagram{
        .route_handle = datagram.route_handle,
        .bytes = DatagramBuffer(datagram.payload()),
        .ecn = datagram.ecn,
        .is_pmtu_probe = datagram.is_pmtu_probe,
    };
}

bool handle_core_effects_with_backend(const std::optional<QuicRouteHandle> &fallback_route_handle,
                                      QuicIoBackend &backend, const QuicCoreResult &result,
                                      std::string_view role_name,
                                      std::vector<QuicIoTxDatagram> *deferred_output) {
    std::vector<QuicIoTxDatagram> datagrams;
    for (const auto &effect : result.effects) {
        const auto *send = std::get_if<QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }

        std::optional<QuicRouteHandle> route_handle = send->route_handle;
        if (!route_handle.has_value()) {
            route_handle = fallback_route_handle;
        }
        if (!route_handle.has_value()) {
            std::cerr << "http09-" << role_name
                      << " failed: missing fallback route for send effect\n";
            return false;
        }

        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-" << role_name << " trace: send_effect route_handle=" << *route_handle
                   << " bytes=" << send->bytes.size() << '\n';
        });

        datagrams.push_back(QuicIoTxDatagram{
            .route_handle = *route_handle,
            .bytes_view = send->bytes.span(),
            .ecn = send->ecn,
            .is_pmtu_probe = send->is_pmtu_probe,
        });
    }

    if (datagrams.empty()) {
        return true;
    }

    if (deferred_output != nullptr) {
        deferred_output->reserve(deferred_output->size() + datagrams.size());
        for (const auto &datagram : datagrams) {
            deferred_output->push_back(make_owning_tx_datagram(datagram));
        }
        return true;
    }

    return backend.send_many(datagrams);
}

void record_resumption_state(EndpointDriveState &state, const QuicCoreResult &result) {
    for (const auto &effect : result.effects) {
        const auto *available = std::get_if<QuicCoreResumptionStateAvailable>(&effect);
        if (available != nullptr) {
            state.last_resumption_state = available->state;
        }
    }
}

bool result_observes_new_handshake_ready(EndpointDriveState &state, const QuicCoreResult &result) {
    bool observed = false;
    for (const auto &effect : result.effects) {
        const auto *event = std::get_if<QuicCoreStateEvent>(&effect);
        if (event == nullptr || event->change != QuicCoreStateChange::handshake_ready) {
            continue;
        }
        if (state.handshake_ready_connections.insert(event->connection).second) {
            observed = true;
        }
    }
    return observed;
}

bool result_observes_stream_data_before_handshake_ready(const EndpointDriveState &state,
                                                        const QuicCoreResult &result) {
    return std::any_of(result.effects.begin(), result.effects.end(), [&](const auto &effect) {
        const auto *received = std::get_if<QuicCoreReceiveStreamData>(&effect);
        return received != nullptr &&
               !state.handshake_ready_connections.contains(received->connection);
    });
}

COQUIC_NO_PROFILE void
note_server_early_stream_data_deferral(std::optional<QuicCoreTimePoint> &defer_output_until,
                                       QuicCoreTimePoint input_time) {
    defer_output_until =
        std::max(defer_output_until.value_or(input_time),
                 input_time + std::chrono::milliseconds(kServerZeroRttDrainGraceMs));
}

COQUIC_NO_PROFILE void
maybe_note_server_early_stream_data_deferral(bool ok, bool observed_early_stream_data,
                                             std::optional<QuicCoreTimePoint> &defer_output_until,
                                             QuicCoreTimePoint input_time) {
    if (!ok || !observed_early_stream_data) {
        return;
    }

    note_server_early_stream_data_deferral(defer_output_until, input_time);
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
            policy.preferred_address_route_handle =
                remember_runtime_route_handle(state, peer, peer_len, *preferred_socket_fd);
            policy.preferred_address_validation_identity =
                test::socket_io_backend_address_validation_identity_for_runtime_tests(peer,
                                                                                      peer_len);
            static_cast<void>(remember_runtime_path(state, peer, peer_len, *preferred_socket_fd));
            with_runtime_trace([&](std::ostream &trace_stream) {
                trace_stream << "http09-client trace: observed preferred_address route_handle="
                             << *policy.preferred_address_route_handle
                             << " socket_fd=" << *preferred_socket_fd
                             << " ipv4_port=" << preferred->preferred_address.ipv4_port
                             << " ipv6_port=" << preferred->preferred_address.ipv6_port << '\n';
            });
        }
    }
    return true;
}

bool observe_client_runtime_policy_effects_with_backend(const QuicCoreResult &result,
                                                        EndpointDriveState &state,
                                                        ClientRuntimePolicyState &policy,
                                                        ClientIoContext &io_context,
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
            if (io_context.backend == nullptr) {
                return false;
            }

            const auto peer = sockaddr_from_preferred_address(preferred->preferred_address);
            auto preferred_peer_len =
                sockaddr_len_from_preferred_address(preferred->preferred_address);
            io_context.preferred_route_handle = io_context.backend->ensure_route(QuicIoRemote{
                .peer = peer,
                .peer_len = preferred_peer_len,
                .family = peer.ss_family,
            });
            if (!io_context.preferred_route_handle.has_value()) {
                std::cerr << "http09-" << role_name
                          << " failed: unable to create preferred-address route\n";
                return false;
            }

            policy.preferred_address_route_handle = io_context.preferred_route_handle;
            policy.preferred_address_validation_identity =
                test::socket_io_backend_address_validation_identity_for_runtime_tests(
                    peer, preferred_peer_len);
            with_runtime_trace([&](std::ostream &trace_stream) {
                trace_stream << "http09-client trace: observed preferred_address route_handle="
                             << io_context.preferred_route_handle.value()
                             << " ipv4_port=" << preferred->preferred_address.ipv4_port
                             << " ipv6_port=" << preferred->preferred_address.ipv6_port << '\n';
            });
        }
    }
    return true;
}

void maybe_queue_client_runtime_policy_inputs(const Http09RuntimeConfig &config,
                                              ClientRuntimePolicyState &policy,
                                              std::vector<QuicCoreInput> &core_inputs) {
    if (!config.enable_client_preferred_address_migration || !policy.handshake_confirmed_seen ||
        !policy.preferred_address_route_handle.has_value() ||
        policy.preferred_address_request_queued) {
        return;
    }

    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.6.1
    // # Once the handshake is confirmed, the client SHOULD select one of the
    // # two addresses provided by the server and initiate path validation
    // # (see Section 8.2).
    //= https://www.rfc-editor.org/rfc/rfc9000#section-9.5
    // # Changing address can cause a peer to reset its congestion control state
    // # (see Section 9.4), so addresses SHOULD only be changed infrequently.
    core_inputs.emplace_back(QuicCoreRequestConnectionMigration{
        .route_handle = *policy.preferred_address_route_handle,
        .reason = QuicMigrationRequestReason::preferred_address,
        .address_validation_identity = policy.preferred_address_validation_identity,
    });
    policy.preferred_address_request_queued = true;
    with_runtime_trace([&](std::ostream &stream) {
        stream << "http09-client trace: queued preferred_address migration route_handle="
               << *policy.preferred_address_route_handle << '\n';
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

void refresh_server_session_connection_id_routes(ServerSession &session,
                                                 ServerConnectionIdRouteMap &connection_id_routes) {
    std::vector<std::string> active_route_keys;
    for (const auto &connection_id : session.core.active_local_connection_ids()) {
        const auto route_key = connection_id_key(connection_id);
        if ((route_key.empty()) | (route_key == session.local_connection_id_key)) {
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

std::optional<QuicCoreTimePoint> earliest_server_session_wakeup(
    const std::unordered_map<std::string, std::unique_ptr<ServerSession>> &sessions) {
    return earliest_wakeup_in_range(
        sessions, [](const auto &entry) { return entry.second->state.next_wakeup; });
}

bool drive_endpoint_until_blocked(const EndpointDriver &endpoint, QuicCore &core, int fd,
                                  const sockaddr_storage *peer, socklen_t peer_len,
                                  const QuicCoreResult &initial_result, EndpointDriveState &state,
                                  std::string_view role_name,
                                  const Http09RuntimeConfig *runtime_config,
                                  ClientRuntimePolicyState *client_policy,
                                  ClientSocketSet *client_sockets, bool *observed_send_effects) {
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
        if (!handle_core_effects(fd, current_result, peer, peer_len, state.route_routes,
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

bool drive_endpoint_until_blocked_with_backend(
    const EndpointDriver &endpoint, QuicCore &core,
    const std::optional<QuicRouteHandle> &fallback_route_handle, QuicIoBackend &backend,
    const QuicCoreResult &initial_result, EndpointDriveState &state, std::string_view role_name,
    const Http09RuntimeConfig *runtime_config, ClientRuntimePolicyState *client_policy,
    ClientIoContext *client_io, bool *observed_send_effects) {
    QuicCoreResult current_result = initial_result;
    bool pending_terminal_success = false;
    if (observed_send_effects != nullptr) {
        *observed_send_effects = false;
    }

    for (;;) {
        record_resumption_state(state, current_result);
        if ((runtime_config != nullptr) & (client_policy != nullptr)) {
            if (client_io == nullptr ||
                !observe_client_runtime_policy_effects_with_backend(
                    current_result, state, *client_policy, *client_io, role_name)) {
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
        if (!handle_core_effects_with_backend(fallback_route_handle, backend, current_result,
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

int run_http09_client_connection_backend_loop(const Http09RuntimeConfig &config,
                                              const EndpointDriver &endpoint, QuicCore &core,
                                              ClientIoContext &io_context,
                                              EndpointDriveState &state,
                                              ClientRuntimePolicyState &client_policy,
                                              const QuicCoreResult &start_result) {
    if (io_context.backend == nullptr || !io_context.primary_route_handle.has_value()) {
        return 1;
    }

    auto &backend = *io_context.backend;
    bool saw_peer_input = false;
    const auto peer_progress_deadline =
        now() + std::chrono::milliseconds(client_receive_timeout_ms(config));
    std::optional<QuicCoreTimePoint> terminal_success_deadline;
    const auto fail_if_peer_progress_deadline_expired = [&](QuicCoreTimePoint current) {
        if (saw_peer_input || current < peer_progress_deadline) {
            return false;
        }
        std::cerr << "http09-client failed: timed out waiting for progress\n";
        return true;
    };
    const auto ensure_terminal_success_deadline = [&](QuicCoreTimePoint current) {
        if (!saw_peer_input || terminal_success_deadline.has_value()) {
            return;
        }

        terminal_success_deadline =
            current + std::chrono::milliseconds(kClientSuccessDrainWindowMs);
    };
    const auto should_exit_after_terminal_success = [&](QuicCoreTimePoint current) {
        if (!saw_peer_input) {
            return true;
        }
        return current >= terminal_success_deadline.value_or(QuicCoreTimePoint::max());
    };
    const auto drive_result = [&](const QuicCoreResult &core_result,
                                  bool *saw_send_effects = nullptr) {
        return drive_endpoint_until_blocked_with_backend(
            endpoint, core, io_context.primary_route_handle, backend, core_result, state, "client",
            &config, &client_policy, &io_context, saw_send_effects);
    };

    if (!drive_result(start_result)) {
        return 1;
    }
    if (state.terminal_success) {
        return 0;
    }

    struct ClientBackendTimerProcessResult {
        bool ok = true;
        bool processed = false;
        bool deferred_for_backend = false;
    };
    std::size_t immediate_timer_pumps = 0;
    const auto process_expired_client_timer =
        [&](QuicCoreTimePoint current) -> ClientBackendTimerProcessResult {
        const auto next_wakeup = state.next_wakeup;
        if (!next_wakeup.has_value() || next_wakeup.value() > current) {
            immediate_timer_pumps = 0;
            return {};
        }

        if (immediate_timer_pumps >= kClientBackendImmediateTimerBudget) {
            with_runtime_trace([&](std::ostream &trace_stream) {
                trace_stream << "http09-client trace: backend-yield due-timer"
                             << " immediate_timer_pumps=" << immediate_timer_pumps << '\n';
            });
            return ClientBackendTimerProcessResult{
                .deferred_for_backend = true,
            };
        }

        ++immediate_timer_pumps;
        return ClientBackendTimerProcessResult{
            .ok = drive_result(core.advance(QuicCoreTimerExpired{}, current)),
            .processed = true,
        };
    };

    struct PumpEndpointWorkResult {
        bool ok = true;
        bool advanced_core = false;
        bool observed_send_effects = false;
    };
    const auto pump_client_endpoint_work_once = [&]() -> PumpEndpointWorkResult {
        if (!state.endpoint_has_pending_work) {
            return {};
        }

        auto endpoint_update = endpoint.poll(now());
        state.endpoint_has_pending_work = endpoint_update.has_pending_work;
        if (endpoint_update.terminal_failure) {
            state.terminal_failure = true;
            return PumpEndpointWorkResult{
                .ok = false,
            };
        }
        if (endpoint_update.terminal_success) {
            state.terminal_success = true;
            return {};
        }
        if (endpoint_update.core_inputs.empty()) {
            return {};
        }

        bool saw_send_effects = false;
        const auto result = advance_core_with_inputs(core, endpoint_update.core_inputs, now());
        return PumpEndpointWorkResult{
            .ok = drive_result(result, &saw_send_effects),
            .advanced_core = true,
            .observed_send_effects = saw_send_effects,
        };
    };

    for (;;) {
        if (fail_if_peer_progress_deadline_expired(now())) {
            return 1;
        }
        if (state.terminal_success && should_exit_after_terminal_success(now())) {
            return 0;
        }

        const auto timer_result = process_expired_client_timer(now());
        if (!timer_result.ok) {
            return 1;
        }
        if (timer_result.processed) {
            continue;
        }

        if (!timer_result.deferred_for_backend) {
            std::size_t no_send_pumps = 0;
            for (;;) {
                const auto pump_result = pump_client_endpoint_work_once();
                if (!pump_result.ok) {
                    return 1;
                }
                if (state.terminal_success) {
                    const auto current = now();
                    ensure_terminal_success_deadline(current);
                    if (should_exit_after_terminal_success(current)) {
                        return 0;
                    }
                    break;
                }
                if (!pump_result.advanced_core || !state.endpoint_has_pending_work) {
                    break;
                }
                if (pump_result.observed_send_effects) {
                    no_send_pumps = 0;
                } else {
                    ++no_send_pumps;
                }

                const auto followup_timer_result = process_expired_client_timer(now());
                if (!followup_timer_result.ok) {
                    return 1;
                }
                if (followup_timer_result.processed) {
                    continue;
                }
                if (followup_timer_result.deferred_for_backend) {
                    break;
                }
                if (no_send_pumps > kClientBackendNoSendPumpBudget) {
                    with_runtime_trace([&](std::ostream &stream) {
                        stream << "http09-client trace: backend-yield pending="
                               << state.endpoint_has_pending_work
                               << " no_send_pumps=" << no_send_pumps << '\n';
                    });
                    break;
                }
            }
        }

        auto wait_next_wakeup = state.next_wakeup;
        if (terminal_success_deadline.has_value()) {
            wait_next_wakeup = std::min(wait_next_wakeup.value_or(*terminal_success_deadline),
                                        *terminal_success_deadline);
        }
        if (!saw_peer_input) {
            wait_next_wakeup =
                std::min(wait_next_wakeup.value_or(peer_progress_deadline), peer_progress_deadline);
        }
        const auto event = backend.wait(wait_next_wakeup);
        if (!event.has_value()) {
            return 1;
        }
        immediate_timer_pumps = 0;
        if (fail_if_peer_progress_deadline_expired(event->now)) {
            return 1;
        }

        if (event->kind == QuicIoEvent::Kind::idle_timeout) {
            if (state.terminal_success) {
                return 0;
            }
            std::cerr << "http09-client failed: timed out waiting for progress\n";
            return 1;
        }
        if (event->kind == QuicIoEvent::Kind::shutdown) {
            return 1;
        }
        if (event->kind == QuicIoEvent::Kind::timer_expired) {
            if (!drive_result(core.advance(QuicCoreTimerExpired{}, event->now))) {
                return 1;
            }
            if (state.terminal_success) {
                ensure_terminal_success_deadline(event->now);
            }
            continue;
        }
        if (event->kind == QuicIoEvent::Kind::path_mtu_update) {
            if (!event->path_mtu.has_value()) {
                return 1;
            }
            if (!drive_result(core.advance(
                    QuicCorePathMtuUpdate{
                        .route_handle = event->path_mtu->route_handle,
                        .max_udp_payload_size = event->path_mtu->max_udp_payload_size,
                        .quoted_packet = event->path_mtu->quoted_packet,
                    },
                    event->now))) {
                return 1;
            }
            continue;
        }

        if (!event->datagram.has_value()) {
            return 1;
        }
        auto inbound = make_inbound_datagram_from_io_event(*event->datagram);
        saw_peer_input = true;
        if (!drive_result(core.advance(std::move(inbound), event->now))) {
            return 1;
        }
        if (state.terminal_success) {
            ensure_terminal_success_deadline(event->now);
            if (should_exit_after_terminal_success(now())) {
                return 0;
            }
        }
        continue;
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
        auto endpoint_update = endpoint.poll(now());
        state.endpoint_has_pending_work = endpoint_update.has_pending_work;
        with_runtime_trace([&](std::ostream &trace_stream) {
            trace_stream << "http09-client trace: poll pending_before=" << pending_before
                         << " pending_after=" << endpoint_update.has_pending_work
                         << " core_inputs=" << endpoint_update.core_inputs.size()
                         << " terminal_success=" << endpoint_update.terminal_success
                         << " terminal_failure=" << endpoint_update.terminal_failure << '\n';
        });
        if (endpoint_update.terminal_failure) {
            state.terminal_failure = true;
            return PumpEndpointWorkResult{
                .ok = false,
            };
        }
        if (endpoint_update.terminal_success) {
            state.terminal_success = true;
            return {};
        }
        if (endpoint_update.core_inputs.empty()) {
            return {};
        }

        auto result = advance_core_with_inputs(core, endpoint_update.core_inputs, now());
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
            const bool terminal = state.terminal_success || state.terminal_failure;
            if (terminal) {
                ensure_terminal_success_deadline(io.current_time());
                return true;
            }

            bool received_datagram = false;
            for (const int socket_fd : active_client_socket_fds(client_sockets)) {
                if (socket_fd < 0) {
                    continue;
                }

                auto receive = io.receive_datagram(socket_fd, /*flags=*/MSG_DONTWAIT,
                                                   /*role_name=*/"client");
                if (receive.status == ReceiveDatagramStatus::would_block) {
                    continue;
                }
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
                const bool terminal_after_receive =
                    state.terminal_success || state.terminal_failure;
                if (terminal_after_receive) {
                    ensure_terminal_success_deadline(receive.step.input_time);
                    return true;
                }
                break;
            }

            if (received_datagram) {
                continue;
            }
            with_runtime_trace([&](std::ostream &trace_stream) {
                const auto current = now();
                const auto next_wakeup_delay_ms =
                    state.next_wakeup.has_value()
                        ? std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::abs(state.next_wakeup.value() - current))
                              .count()
                        : -1;
                trace_stream << "http09-client trace: would-block pending="
                             << state.endpoint_has_pending_work
                             << " advanced_core=" << pump_result.advanced_core
                             << " terminal_success=" << state.terminal_success
                             << " terminal_failure=" << state.terminal_failure
                             << " has_next_wakeup=" << state.next_wakeup.has_value()
                             << " next_wakeup_delta_ms=" << next_wakeup_delay_ms << '\n';
            });
            if (pump_result.advanced_core) {
                if (state.endpoint_has_pending_work) {
                    continue;
                }
            }
            return true;
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
        if (std::holds_alternative<QuicCoreInboundDatagram>(step_input)) {
            saw_peer_input = true;
            auto step_result = core.advance(std::move(step_input), step->input_time);
            if (!drive_endpoint_until_blocked(endpoint, core, client_sockets.primary.fd, &peer,
                                              peer_len, step_result, state, "client", &config,
                                              &client_policy, &client_sockets)) {
                return 1;
            }
            if (state.terminal_success) {
                ensure_terminal_success_deadline(step->input_time);
                if (should_exit_after_terminal_success(io.current_time())) {
                    return 0;
                }
            }
            continue;
        }
        auto step_result = core.advance(std::move(step_input), step->input_time);
        if (!drive_endpoint_until_blocked(endpoint, core, client_sockets.primary.fd, &peer,
                                          peer_len, step_result, state, "client", &config,
                                          &client_policy, &client_sockets)) {
            return 1;
        }
        if (state.terminal_success) {
            ensure_terminal_success_deadline(step->input_time);
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
        .request_key_update = config.request_key_update,
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

    auto bootstrap = io::bootstrap_client_io_backend(
        io::QuicIoBackendBootstrapConfig{
            .kind = config.io_backend,
            .backend =
                io::QuicUdpBackendConfig{
                    .role_name = "client",
                    .idle_timeout_ms = client_receive_timeout_ms(config),
                },
        },
        remote->host, remote->port);
    if (!bootstrap.has_value()) {
        return ClientConnectionRunResult{
            .exit_code = 1,
        };
    }
    ClientIoContext io_context{
        .backend = std::move(bootstrap->backend),
        .primary_route_handle = bootstrap->primary_route_handle,
        .primary_address_validation_identity =
            std::move(bootstrap->primary_address_validation_identity),
    };

    auto client_core_config = std::move(core_config);
    client_core_config.server_name = remote->server_name;
    assign_runtime_client_connection_ids(client_core_config, connection_index);
    auto attempt_zero_rtt = client_core_config.zero_rtt.attempt;
    QuicCore core(std::move(client_core_config));
    EndpointDriveState state;
    ClientRuntimePolicyState client_policy;
    auto start_result = core.advance(QuicCoreStart{}, now());
    record_resumption_state(state, start_result);

    QuicHttp09ClientEndpoint endpoint(
        make_http09_client_endpoint_config(config, requests, attempt_zero_rtt, start_result));
    return ClientConnectionRunResult{
        .exit_code = run_http09_client_connection_backend_loop(
            config, make_endpoint_driver(endpoint), core, io_context, state, client_policy,
            start_result),
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
        .attempt = config.attempt_zero_rtt,
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

    if (config.client_run_mode == Http09ClientRunMode::one_connection_per_request) {
        for (std::size_t index = 0; index < requests.value().size(); ++index) {
            if (run_http09_client_connection(
                    config, std::vector<QuicHttp09Request>{requests.value().at(index)},
                    index + 1) != 0) {
                return 1;
            }
        }
        return 0;
    }

    if (config.client_run_mode != Http09ClientRunMode::resumption_sequence) {
        return run_http09_client_connection(config, requests.value(), 1);
    }

    return run_http09_resumed_client_sequence(
        config, requests.value(),
        [](const Http09RuntimeConfig &runner_config,
           const std::vector<QuicHttp09Request> &runner_requests,
           QuicCoreConfig resumed_core_config, std::uint64_t connection_index) {
            return run_http09_client_connection_with_core_config(
                runner_config, runner_requests, std::move(resumed_core_config), connection_index);
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
    if (endpoint_failed | session.core.has_failed()) {
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
        if (!session_next_wakeup.has_value()) {
            continue;
        }
        if (session_next_wakeup.value() > current) {
            continue;
        }

        processed_any = true;
        const auto timer_result = session->core.advance(QuicCoreTimerExpired{}, current);
        const bool endpoint_failed = !drive_endpoint_until_blocked(
            make_endpoint_driver(session->endpoint), session->core, session->socket_fd,
            &session->peer, session->peer_len, timer_result, session->state, "server");
        refresh_server_session_connection_id_routes(*session, connection_id_routes);
        const bool core_failed = session->core.has_failed();
        if (endpoint_failed || core_failed) {
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
        if (endpoint_failed || core_failed) {
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

QuicCoreEndpointConfig make_runtime_server_endpoint_config(const Http09RuntimeConfig &config,
                                                           TlsIdentity identity) {
    auto core_config = make_http09_server_core_config_with_identity(config, std::move(identity));
    return QuicCoreEndpointConfig{
        .role = core_config.role,
        .supported_versions = std::move(core_config.supported_versions),
        .verify_peer = core_config.verify_peer,
        .retry_enabled = config.retry_enabled,
        .application_protocol = std::move(core_config.application_protocol),
        .identity = std::move(core_config.identity),
        .transport = std::move(core_config.transport),
        .max_outbound_datagram_size = core_config.max_outbound_datagram_size,
        .allowed_tls_cipher_suites = std::move(core_config.allowed_tls_cipher_suites),
        .zero_rtt = std::move(core_config.zero_rtt),
        .qlog = std::move(core_config.qlog),
        .tls_keylog_path = std::move(core_config.tls_keylog_path),
    };
}

bool result_has_send_effects(const QuicCoreResult &result) {
    return std::any_of(result.effects.begin(), result.effects.end(), [](const auto &effect) {
        return std::holds_alternative<QuicCoreSendDatagram>(effect);
    });
}

QuicConnectionHandle effect_connection_handle(const QuicCoreEffect &effect) {
    return std::visit([](const auto &value) { return value.connection; }, effect);
}

bool result_has_connection_lifecycle(const QuicCoreResult &result, QuicConnectionHandle connection,
                                     QuicCoreConnectionLifecycle lifecycle) {
    return std::any_of(result.effects.begin(), result.effects.end(), [&](const auto &effect) {
        const auto *event = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
        if (event == nullptr) {
            return false;
        }
        return event->connection == connection && event->event == lifecycle;
    });
}

std::vector<QuicConnectionHandle> result_connection_handles(const QuicCoreResult &result) {
    std::vector<QuicConnectionHandle> handles;
    const auto remember = [&](QuicConnectionHandle connection) {
        if (connection == 0 ||
            std::find(handles.begin(), handles.end(), connection) != handles.end()) {
            return;
        }
        handles.push_back(connection);
    };

    if (result.local_error.has_value()) {
        if (result.local_error->connection.has_value()) {
            remember(*result.local_error->connection);
        }
    }
    for (const auto &effect : result.effects) {
        remember(effect_connection_handle(effect));
    }
    return handles;
}

QuicCoreResult slice_result_for_connection(const QuicCoreResult &result,
                                           QuicConnectionHandle connection) {
    QuicCoreResult sliced{
        .next_wakeup = result.next_wakeup,
    };
    if (result.local_error.has_value() && result.local_error->connection == connection) {
        sliced.local_error = result.local_error;
    }
    for (const auto &effect : result.effects) {
        if (effect_connection_handle(effect) == connection) {
            sliced.effects.push_back(effect);
        }
    }
    return sliced;
}

void ensure_server_connection_endpoints_for_accepts(ServerConnectionEndpointMap &endpoints,
                                                    const QuicCoreResult &result,
                                                    const std::filesystem::path &document_root) {
    for (const auto &effect : result.effects) {
        const auto *event = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
        if (event == nullptr || event->event != QuicCoreConnectionLifecycle::accepted ||
            endpoints.contains(event->connection)) {
            continue;
        }

        endpoints.emplace(event->connection,
                          ServerConnectionEndpointState{
                              .endpoint = QuicHttp09ServerEndpoint(QuicHttp09ServerConfig{
                                  .document_root = document_root,
                                  .defer_responses_until_handshake_ready = true,
                              }),
                          });
    }
}

void erase_closed_server_connection_endpoints(ServerConnectionEndpointMap &endpoints,
                                              const QuicCoreResult &result) {
    for (const auto &effect : result.effects) {
        const auto *event = std::get_if<QuicCoreConnectionLifecycleEvent>(&effect);
        if (event != nullptr && event->event == QuicCoreConnectionLifecycle::closed) {
            endpoints.erase(event->connection);
        }
    }
}

std::optional<QuicCoreConnectionInput> to_connection_command_input(const QuicCoreInput &input) {
    if (const auto *send_stream = std::get_if<QuicCoreSendStreamData>(&input)) {
        return *send_stream;
    }
    if (const auto *reset_stream = std::get_if<QuicCoreResetStream>(&input)) {
        return *reset_stream;
    }
    if (const auto *stop_sending = std::get_if<QuicCoreStopSending>(&input)) {
        return *stop_sending;
    }
    if (const auto *close_connection = std::get_if<QuicCoreCloseConnection>(&input)) {
        return *close_connection;
    }
    if (const auto *request_key_update = std::get_if<QuicCoreRequestKeyUpdate>(&input)) {
        return *request_key_update;
    }
    if (const auto *request_migration = std::get_if<QuicCoreRequestConnectionMigration>(&input)) {
        return *request_migration;
    }
    return std::nullopt;
}

COQUIC_NO_PROFILE QuicCoreResult advance_endpoint_connection_inputs(
    QuicCore &core, QuicConnectionHandle connection, std::span<const QuicCoreInput> inputs,
    QuicCoreTimePoint step_time) {
    QuicCoreResult combined;
    for (const auto &input : inputs) {
        auto command_input = to_connection_command_input(input);
        if (!command_input.has_value()) {
            combined.local_error = QuicCoreLocalError{
                .connection = connection,
                .code = QuicCoreLocalErrorCode::unsupported_operation,
                .stream_id = std::nullopt,
            };
            combined.next_wakeup = core.next_wakeup();
            break;
        }

        auto step = core.advance_endpoint(
            QuicCoreConnectionCommand{
                .connection = connection,
                .input = std::move(command_input).value(),
            },
            step_time);
        combined.effects.insert(combined.effects.end(),
                                std::make_move_iterator(step.effects.begin()),
                                std::make_move_iterator(step.effects.end()));
        combined.next_wakeup = step.next_wakeup;
        if (step.local_error.has_value()) {
            combined.local_error = step.local_error;
            break;
        }
        if (result_has_connection_lifecycle(step, connection,
                                            QuicCoreConnectionLifecycle::closed)) {
            break;
        }
    }
    return combined;
}

bool process_server_endpoint_core_result(QuicCore &core, EndpointDriveState &transport_state,
                                         ServerConnectionEndpointMap &endpoints,
                                         const std::filesystem::path &document_root,
                                         QuicCoreResult initial_result, int fallback_socket_fd,
                                         const sockaddr_storage *fallback_peer,
                                         socklen_t fallback_peer_len, bool *observed_send_effects) {
    std::deque<QuicCoreResult> pending_results;
    pending_results.push_back(std::move(initial_result));
    if (observed_send_effects != nullptr) {
        *observed_send_effects = false;
    }

    while (!pending_results.empty()) {
        auto current_result = std::move(pending_results.front());
        pending_results.pop_front();

        if (current_result.local_error.has_value() &&
            !current_result.local_error->connection.has_value()) {
            return false;
        }
        if (observed_send_effects != nullptr) {
            if (result_has_send_effects(current_result)) {
                *observed_send_effects = true;
            }
        }
        if (!handle_core_effects(fallback_socket_fd, current_result, fallback_peer,
                                 fallback_peer_len, transport_state.route_routes, "server")) {
            return false;
        }

        ensure_server_connection_endpoints_for_accepts(endpoints, current_result, document_root);
        for (const auto connection : result_connection_handles(current_result)) {
            auto endpoint_it = endpoints.find(connection);
            if (endpoint_it == endpoints.end()) {
                continue;
            }

            const bool connection_closed = result_has_connection_lifecycle(
                current_result, connection, QuicCoreConnectionLifecycle::closed);
            auto connection_result = slice_result_for_connection(current_result, connection);
            auto update = endpoint_it->second.endpoint.on_core_result(connection_result, now());
            endpoint_it->second.has_pending_work = update.has_pending_work;

            if (connection_result.local_error.has_value()) {
                endpoint_it->second.has_pending_work = false;
                endpoints.erase(endpoint_it);
                continue;
            }
            if (connection_closed) {
                endpoint_it->second.has_pending_work = false;
                continue;
            }
            if (update.terminal_failure) {
                endpoint_it->second.has_pending_work = false;
                pending_results.push_back(core.advance_endpoint(
                    QuicCoreConnectionCommand{
                        .connection = connection,
                        .input = QuicCoreCloseConnection{},
                    },
                    now()));
                endpoints.erase(endpoint_it);
                continue;
            }
            if (update.core_inputs.empty()) {
                continue;
            }

            pending_results.push_back(
                advance_endpoint_connection_inputs(core, connection, update.core_inputs, now()));
        }

        erase_closed_server_connection_endpoints(endpoints, current_result);
    }

    transport_state.next_wakeup = core.next_wakeup();
    return true;
}

bool process_server_endpoint_core_result_with_backend(
    QuicCore &core, EndpointDriveState &transport_state, ServerConnectionEndpointMap &endpoints,
    const std::filesystem::path &document_root, QuicCoreResult initial_result,
    const std::optional<QuicRouteHandle> &fallback_route_handle, QuicIoBackend &backend,
    bool *observed_send_effects, std::vector<QuicIoTxDatagram> *deferred_output,
    bool *observed_early_stream_data) {
    std::deque<QuicCoreResult> pending_results;
    pending_results.push_back(std::move(initial_result));
    if (observed_send_effects != nullptr) {
        *observed_send_effects = false;
    }
    if (observed_early_stream_data != nullptr) {
        *observed_early_stream_data = false;
    }

    while (!pending_results.empty()) {
        auto current_result = std::move(pending_results.front());
        pending_results.pop_front();

        if (current_result.local_error.has_value() &&
            !current_result.local_error->connection.has_value()) {
            return false;
        }
        if (observed_send_effects != nullptr) {
            if (result_has_send_effects(current_result)) {
                *observed_send_effects = true;
            }
        }
        if (observed_early_stream_data != nullptr &&
            result_observes_stream_data_before_handshake_ready(transport_state, current_result)) {
            *observed_early_stream_data = true;
        }
        static_cast<void>(result_observes_new_handshake_ready(transport_state, current_result));
        if (!handle_core_effects_with_backend(fallback_route_handle, backend, current_result,
                                              "server", deferred_output)) {
            return false;
        }

        ensure_server_connection_endpoints_for_accepts(endpoints, current_result, document_root);
        for (const auto connection : result_connection_handles(current_result)) {
            auto endpoint_it = endpoints.find(connection);
            if (endpoint_it == endpoints.end()) {
                continue;
            }

            const bool connection_closed = result_has_connection_lifecycle(
                current_result, connection, QuicCoreConnectionLifecycle::closed);
            auto connection_result = slice_result_for_connection(current_result, connection);
            auto update = endpoint_it->second.endpoint.on_core_result(connection_result, now());
            endpoint_it->second.has_pending_work = update.has_pending_work;

            if (connection_result.local_error.has_value()) {
                endpoint_it->second.has_pending_work = false;
                endpoints.erase(endpoint_it);
                continue;
            }
            if (connection_closed) {
                endpoint_it->second.has_pending_work = false;
                continue;
            }
            if (update.terminal_failure) {
                endpoint_it->second.has_pending_work = false;
                pending_results.push_back(core.advance_endpoint(
                    QuicCoreConnectionCommand{
                        .connection = connection,
                        .input = QuicCoreCloseConnection{},
                    },
                    now()));
                endpoints.erase(endpoint_it);
                continue;
            }
            if (update.core_inputs.empty()) {
                continue;
            }

            pending_results.push_back(
                advance_endpoint_connection_inputs(core, connection, update.core_inputs, now()));
        }

        erase_closed_server_connection_endpoints(endpoints, current_result);
    }

    transport_state.next_wakeup = core.next_wakeup();
    return true;
}

bool pump_shared_server_endpoint_work(QuicCore &core, EndpointDriveState &transport_state,
                                      ServerConnectionEndpointMap &endpoints,
                                      const std::filesystem::path &document_root,
                                      bool &made_progress) {
    made_progress = false;
    std::vector<QuicConnectionHandle> pending_connections;
    for (const auto &[connection, endpoint] : endpoints) {
        if (endpoint.has_pending_work) {
            pending_connections.push_back(connection);
        }
    }

    for (const auto connection : pending_connections) {
        auto &endpoint_state = endpoints.at(connection);

        auto update = endpoint_state.endpoint.poll(now());
        endpoint_state.has_pending_work = update.has_pending_work;

        if (update.terminal_failure) {
            endpoint_state.has_pending_work = false;
            const auto close_result = core.advance_endpoint(
                QuicCoreConnectionCommand{
                    .connection = connection,
                    .input = QuicCoreCloseConnection{},
                },
                now());
            endpoints.erase(connection);
            bool observed_send_effects = false;
            if (!process_server_endpoint_core_result(
                    core, transport_state, endpoints, document_root, close_result,
                    /*fallback_socket_fd=*/-1,
                    /*fallback_peer=*/nullptr,
                    /*fallback_peer_len=*/0, &observed_send_effects)) {
                return false;
            }
            made_progress = made_progress | observed_send_effects;
            continue;
        }
        if (update.core_inputs.empty()) {
            continue;
        }

        bool observed_send_effects = false;
        if (!process_server_endpoint_core_result(
                core, transport_state, endpoints, document_root,
                advance_endpoint_connection_inputs(core, connection, update.core_inputs, now()),
                /*fallback_socket_fd=*/-1, /*fallback_peer=*/nullptr, /*fallback_peer_len=*/0,
                &observed_send_effects)) {
            return false;
        }
        made_progress = made_progress | observed_send_effects;
    }

    return true;
}

bool pump_shared_server_endpoint_work_with_backend(
    QuicCore &core, EndpointDriveState &transport_state, ServerConnectionEndpointMap &endpoints,
    const std::filesystem::path &document_root, QuicIoBackend &backend, bool &made_progress,
    std::vector<QuicIoTxDatagram> *deferred_output, bool *observed_early_stream_data) {
    made_progress = false;
    std::vector<QuicConnectionHandle> pending_connections;
    for (const auto &[connection, endpoint] : endpoints) {
        if (endpoint.has_pending_work) {
            pending_connections.push_back(connection);
        }
    }

    for (const auto connection : pending_connections) {
        auto &endpoint_state = endpoints.at(connection);

        auto update = endpoint_state.endpoint.poll(now());
        endpoint_state.has_pending_work = update.has_pending_work;

        if (update.terminal_failure) {
            endpoint_state.has_pending_work = false;
            const auto close_result = core.advance_endpoint(
                QuicCoreConnectionCommand{
                    .connection = connection,
                    .input = QuicCoreCloseConnection{},
                },
                now());
            endpoints.erase(connection);
            bool observed_send_effects = false;
            if (!process_server_endpoint_core_result_with_backend(
                    core, transport_state, endpoints, document_root, close_result, std::nullopt,
                    backend, &observed_send_effects, deferred_output, observed_early_stream_data)) {
                return false;
            }
            made_progress = made_progress | observed_send_effects;
            continue;
        }
        if (update.core_inputs.empty()) {
            continue;
        }

        bool observed_send_effects = false;
        if (!process_server_endpoint_core_result_with_backend(
                core, transport_state, endpoints, document_root,
                advance_endpoint_connection_inputs(core, connection, update.core_inputs, now()),
                std::nullopt, backend, &observed_send_effects, deferred_output,
                observed_early_stream_data)) {
            return false;
        }
        made_progress = made_progress | observed_send_effects;
    }

    return true;
}

bool has_pending_shared_server_endpoint_work(const ServerConnectionEndpointMap &endpoints) {
    return std::any_of(endpoints.begin(), endpoints.end(),
                       [](const auto &entry) { return entry.second.has_pending_work; });
}

bool process_server_path_mtu_update_with_backend(
    QuicCore &core, EndpointDriveState &transport_state, ServerConnectionEndpointMap &endpoints,
    const std::filesystem::path &document_root, QuicIoBackend &backend,
    std::vector<QuicIoTxDatagram> &deferred_output,
    std::optional<QuicCoreTimePoint> &defer_output_until,
    const QuicIoPathMtuUpdate &path_mtu_update, QuicCoreTimePoint input_time) {
    auto result = core.advance_endpoint(
        QuicCorePathMtuUpdate{
            .route_handle = path_mtu_update.route_handle,
            .max_udp_payload_size = path_mtu_update.max_udp_payload_size,
            .quoted_packet = path_mtu_update.quoted_packet,
        },
        input_time);
    bool observed_early_stream_data = false;
    const bool ok = process_server_endpoint_core_result_with_backend(
        core, transport_state, endpoints, document_root, std::move(result),
        path_mtu_update.route_handle, backend, nullptr, &deferred_output,
        &observed_early_stream_data);
    maybe_note_server_early_stream_data_deferral(ok, observed_early_stream_data, defer_output_until,
                                                 input_time);
    return ok;
}

COQUIC_NO_PROFILE bool process_path_mtu_update_event(const ServerBackendLoopDriver &driver,
                                                     const QuicIoPathMtuUpdate &update,
                                                     QuicCoreTimePoint now) {
    return driver.process_path_mtu_update(update, now);
}

std::optional<QuicCoreTimePoint>
backend_output_wait_deadline(const std::optional<QuicCoreTimePoint> &next_wakeup,
                             const std::optional<QuicCoreTimePoint> &defer_output_until) {
    if (!defer_output_until.has_value()) {
        return next_wakeup;
    }
    if (!next_wakeup.has_value()) {
        return defer_output_until;
    }
    return std::min(*next_wakeup, *defer_output_until);
}

bool backend_deferred_output_flush_ready(
    QuicCoreTimePoint current, const std::optional<QuicCoreTimePoint> &defer_output_until) {
    return !defer_output_until.has_value() || current >= *defer_output_until;
}

bool flush_backend_deferred_output_if_ready(const ServerBackendLoopDriver &driver,
                                            QuicCoreTimePoint current, bool &server_failed) {
    if (!backend_deferred_output_flush_ready(current, driver.defer_output_until())) {
        return true;
    }
    if (!driver.flush_deferred_output()) {
        server_failed = true;
        return false;
    }
    return true;
}

COQUIC_NO_PROFILE void
process_path_mtu_update_event_or_mark_failed(const ServerBackendLoopDriver &driver,
                                             const QuicIoPathMtuUpdate &update,
                                             QuicCoreTimePoint now, bool &server_failed) {
    if (!process_path_mtu_update_event(driver, update, now)) {
        server_failed = true;
    }
}

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
        if (driver.has_failed()) {
            return 1;
        }
        for (;;) {
            bool processed_timers = false;
            driver.process_expired_timers(io.current_time(), processed_timers);
            if (driver.has_failed()) {
                return 1;
            }
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
            if (driver.has_failed()) {
                return 1;
            }
            if (pump_made_progress & driver.has_pending_endpoint_work()) {
                continue;
            }
            break;
        }

        bool processed_timers = false;
        driver.process_expired_timers(io.current_time(), processed_timers);
        if (driver.has_failed()) {
            return 1;
        }
        if (processed_timers) {
            continue;
        }

        const bool pump_made_progress = driver.pump_endpoint_work();
        if (driver.has_failed()) {
            return 1;
        }
        if (pump_made_progress & driver.has_pending_endpoint_work()) {
            continue;
        }

        const bool has_preferred_socket = sockets.preferred_fd.has_value();
        auto step = io.wait_for_socket_or_deadline(
            RuntimeWaitConfig{
                .socket_fds = {sockets.primary_fd, sockets.preferred_fd.value_or(-1)},
                .socket_fd_count = has_preferred_socket ? 2u : 1u,
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

int run_server_backend_loop_with_driver(const ServerBackendLoopDriver &driver) {
    bool server_failed = false;
    std::optional<QuicIoEvent> buffered_event = driver.initial_buffered_event();
    const auto log_wait_request = [&](std::string_view source,
                                      const std::optional<QuicCoreTimePoint> &deadline,
                                      QuicCoreTimePoint current) {
        with_runtime_trace([&](std::ostream &stream) {
            const auto delta_ms =
                deadline.has_value()
                    ? std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - current)
                          .count()
                    : -1;
            stream << "http09-server trace: backend-wait source=" << source
                   << " has_deadline=" << static_cast<int>(deadline.has_value())
                   << " delta_ms=" << delta_ms
                   << " buffered=" << static_cast<int>(buffered_event.has_value()) << '\n';
        });
    };
    const auto log_wait_event = [&](std::string_view source,
                                    const std::optional<QuicIoEvent> &event) {
        with_runtime_trace([&](std::ostream &stream) {
            stream << "http09-server trace: backend-event source=" << source << " kind=";
            if (!event.has_value()) {
                stream << "null";
            } else if (event->kind == QuicIoEvent::Kind::rx_datagram) {
                stream << "rx";
            } else if (event->kind == QuicIoEvent::Kind::path_mtu_update) {
                stream << "pmtu";
            } else if (event->kind == QuicIoEvent::Kind::timer_expired) {
                stream << "timer";
            } else if (event->kind == QuicIoEvent::Kind::idle_timeout) {
                stream << "idle";
            } else {
                stream << "shutdown";
            }
            stream << '\n';
        });
    };

    for (;;) {
        if (server_failed) {
            return 1;
        }

        const auto current = driver.current_time();
        const auto next_wakeup = driver.next_wakeup();
        bool top_due = false;
        if (!buffered_event.has_value()) {
            if (next_wakeup.has_value()) {
                top_due = next_wakeup.value() <= current;
            }
        }
        if (top_due) {
            log_wait_request("top_due", next_wakeup, current);
            if (!driver.process_wait_timer(current)) {
                server_failed = true;
            }
            continue;
        }

        bool made_progress = false;
        if (!driver.pump_endpoint_work(made_progress)) {
            server_failed = true;
            continue;
        }
        if (made_progress) {
            if (driver.has_pending_endpoint_work()) {
                if (!buffered_event.has_value()) {
                    const auto poll_current = driver.current_time();
                    const auto poll_next_wakeup = driver.next_wakeup();
                    // Probe for ready RX without blocking. A zero-timeout wait reports
                    // timer_expired even when no core timer was due, so only treat
                    // that event as real when the wakeup is already due.
                    log_wait_request("ready_probe", poll_current, poll_current);
                    const auto ready_event = driver.wait(poll_current);
                    log_wait_event("ready_probe", ready_event);
                    if (!ready_event.has_value()) {
                        return 1;
                    }
                    if (ready_event->kind == QuicIoEvent::Kind::rx_datagram) {
                        if (!ready_event->datagram.has_value()) {
                            server_failed = true;
                            continue;
                        }
                        if (!driver.process_datagram(*ready_event->datagram, ready_event->now)) {
                            server_failed = true;
                        }
                        continue;
                    }
                    if (ready_event->kind == QuicIoEvent::Kind::path_mtu_update) {
                        if (!ready_event->path_mtu.has_value()) {
                            server_failed = true;
                            continue;
                        }
                        process_path_mtu_update_event_or_mark_failed(
                            driver, *ready_event->path_mtu, ready_event->now, server_failed);
                        continue;
                    }
                    if (ready_event->kind == QuicIoEvent::Kind::timer_expired) {
                        if (poll_next_wakeup.has_value()) {
                            if (poll_next_wakeup.value() <= poll_current) {
                                if (!driver.process_wait_timer(ready_event->now)) {
                                    server_failed = true;
                                }
                                continue;
                            }
                        }
                    } else if (ready_event->kind == QuicIoEvent::Kind::shutdown) {
                        return 1;
                    }
                    // The ready probe did not surface RX, PMTU, shutdown, or a real due timer.
                    // Flush queued output before continuing endpoint work unless an early-data
                    // grace window is still open.
                    static_cast<void>(flush_backend_deferred_output_if_ready(
                        driver, driver.current_time(), server_failed));
                    continue;
                }
            }
        }

        if (!flush_backend_deferred_output_if_ready(driver, driver.current_time(), server_failed)) {
            continue;
        }

        std::optional<QuicIoEvent> event;
        if (buffered_event.has_value()) {
            event = buffered_event;
            buffered_event.reset();
        } else {
            const auto output_defer_deadline = driver.defer_output_until();
            const auto wait_next_wakeup =
                backend_output_wait_deadline(driver.next_wakeup(), output_defer_deadline);
            log_wait_request("main", wait_next_wakeup, driver.current_time());
            event = driver.wait(wait_next_wakeup);
            log_wait_event("main", event);
        }
        if (!event.has_value()) {
            return 1;
        }

        if (event->kind == QuicIoEvent::Kind::idle_timeout) {
            continue;
        }
        if (event->kind == QuicIoEvent::Kind::shutdown) {
            return 1;
        }
        if (event->kind == QuicIoEvent::Kind::timer_expired) {
            if (!driver.process_wait_timer(event->now)) {
                server_failed = true;
            }
            continue;
        }
        if (event->kind == QuicIoEvent::Kind::path_mtu_update) {
            if (!event->path_mtu.has_value()) {
                server_failed = true;
                continue;
            }
            if (!driver.process_path_mtu_update(*event->path_mtu, event->now)) {
                server_failed = true;
            }
            continue;
        }
        if (!event->datagram.has_value()) {
            server_failed = true;
            continue;
        }
        if (!driver.process_datagram(*event->datagram, event->now)) {
            server_failed = true;
        }
        continue;
    }
}

int run_http09_server_backend_loop(const Http09RuntimeConfig &config, QuicCore &core,
                                   EndpointDriveState &transport_state,
                                   ServerConnectionEndpointMap &endpoints, QuicIoBackend &backend) {
    std::vector<QuicIoTxDatagram> deferred_output;
    std::optional<QuicCoreTimePoint> defer_output_until;
    const auto flush_deferred_output = [&]() -> bool {
        if (deferred_output.empty()) {
            defer_output_until.reset();
            return true;
        }
        auto datagrams = std::move(deferred_output);
        deferred_output.clear();
        defer_output_until.reset();
        return backend.send_many(datagrams);
    };
    const auto process_server_datagram = [&](const QuicIoRxDatagram &datagram,
                                             QuicCoreTimePoint input_time) -> bool {
        auto inbound = make_inbound_datagram_from_io_event(datagram);
        auto result = core.advance_endpoint(std::move(inbound), input_time);
        bool observed_early_stream_data = false;
        const bool ok = process_server_endpoint_core_result_with_backend(
            core, transport_state, endpoints, config.document_root, std::move(result),
            datagram.route_handle, backend, nullptr, &deferred_output, &observed_early_stream_data);
        maybe_note_server_early_stream_data_deferral(ok, observed_early_stream_data,
                                                     defer_output_until, input_time);
        return ok;
    };
    return run_server_backend_loop_with_driver(ServerBackendLoopDriver{
        .current_time = [] { return now(); },
        .next_wakeup = [&] { return core.next_wakeup(); },
        .pump_endpoint_work =
            [&](bool &made_progress) {
                return pump_shared_server_endpoint_work_with_backend(
                    core, transport_state, endpoints, config.document_root, backend, made_progress,
                    &deferred_output);
            },
        .has_pending_endpoint_work =
            [&] { return has_pending_shared_server_endpoint_work(endpoints); },
        .wait =
            [&](const std::optional<QuicCoreTimePoint> &next_wakeup) {
                return backend.wait(next_wakeup);
            },
        .process_wait_timer =
            [&](QuicCoreTimePoint current) {
                bool observed_early_stream_data = false;
                const bool ok = process_server_endpoint_core_result_with_backend(
                    core, transport_state, endpoints, config.document_root,
                    core.advance_endpoint(QuicCoreTimerExpired{}, current), std::nullopt, backend,
                    nullptr, &deferred_output, &observed_early_stream_data);
                maybe_note_server_early_stream_data_deferral(ok, observed_early_stream_data,
                                                             defer_output_until, current);
                return ok;
            },
        .process_datagram = process_server_datagram,
        .process_path_mtu_update =
            [&](const QuicIoPathMtuUpdate &path_mtu_update, QuicCoreTimePoint input_time) {
                return process_server_path_mtu_update_with_backend(
                    core, transport_state, endpoints, config.document_root, backend,
                    deferred_output, defer_output_until, path_mtu_update, input_time);
            },
        .flush_deferred_output = flush_deferred_output,
        .defer_output_until = [&] { return defer_output_until; },
    });
}

int run_http09_server(const Http09RuntimeConfig &config) {
    const std::array<std::uint16_t, 2> ports = {
        config.port,
        static_cast<std::uint16_t>(config.port + 1),
    };
    auto bootstrap = io::bootstrap_server_io_backend(
        io::QuicIoBackendBootstrapConfig{
            .kind = config.io_backend,
            .backend =
                io::QuicUdpBackendConfig{
                    .role_name = "server",
                    .idle_timeout_ms = kServerIdleTimeoutMs,
                },
        },
        config.host,
        config.enable_server_preferred_address ? std::span<const std::uint16_t>(ports)
                                               : std::span<const std::uint16_t>(ports.data(), 1));
    if (!bootstrap.has_value()) {
        return 1;
    }
    ServerIoContext io_context{
        .backend = std::move(bootstrap->backend),
    };

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
    QuicCore core(make_runtime_server_endpoint_config(config, identity));
    EndpointDriveState transport_state;
    ServerConnectionEndpointMap endpoints;
    return run_http09_server_backend_loop(config, core, transport_state, endpoints,
                                          *io_context.backend);
}

std::optional<ParsedHttp09Authority> parse_http09_authority(std::string_view authority) {
    return parse_http09_authority_impl(authority);
}

std::optional<Http09ClientRemote>
derive_http09_client_remote(const Http09RuntimeConfig &config,
                            const std::vector<QuicHttp09Request> &requests) {
    return derive_http09_client_remote_impl(config, requests);
}

QuicCoreConfig make_http09_client_core_config(const Http09RuntimeConfig &config) {
    auto core = QuicCoreConfig{
        .role = EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                              std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                              std::byte{0x57}, std::byte{0x08}},
        .original_version = config.original_version,
        .initial_version = config.initial_version,
        .supported_versions = config.supported_versions,
        .verify_peer = config.verify_peer,
        .server_name = config.server_name.empty() ? "localhost" : config.server_name,
        .application_protocol = config.application_protocol,
        .transport = config.client_transport,
        .max_outbound_datagram_size = kRuntimeMaxOutboundDatagramBytes,
        .allowed_tls_cipher_suites = config.allowed_tls_cipher_suites,
    };
    if (config.qlog_directory.has_value()) {
        core.qlog = QuicQlogConfig{.directory = *config.qlog_directory};
    }
    core.transport.congestion_control = config.congestion_control;
    configure_runtime_datagram_profile(core.transport);
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
    init_runtime_logging();

    if (config.mode == Http09RuntimeMode::health_check) {
        return (kProjectName.empty()) | (!runtime_has_openssl()) | (!runtime_logging_ready_flag());
    }
    if (config.mode == Http09RuntimeMode::client) {
        return run_http09_client(config);
    }
    if (config.mode == Http09RuntimeMode::server) {
        return run_http09_server(config);
    }

    return 1;
}

} // namespace coquic::http09
