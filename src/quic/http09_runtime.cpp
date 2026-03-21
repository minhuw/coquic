#include "src/quic/http09_runtime.h"

#include "src/quic/http09_runtime_test_hooks.h"

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
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <variant>

namespace coquic::quic {
namespace {

constexpr std::size_t kMaxDatagramBytes = 65535;
constexpr int kClientReceiveTimeoutMs = 10000;
constexpr int kServerIdleTimeoutMs = 1000;
constexpr std::string_view kInteropApplicationProtocol = "hq-interop";
constexpr std::string_view kUsageLine =
    "usage: coquic [interop-server|interop-client] [--host HOST] [--port PORT] "
    "[--testcase handshake|transfer] [--requests URLS] [--document-root PATH] "
    "[--download-root PATH] [--certificate-chain PATH] [--private-key PATH] "
    "[--server-name NAME] [--verify-peer]";

struct RuntimeFaultState {
    test::RuntimeFaultConfig config;
    std::size_t open_udp_socket_calls = 0;
    std::size_t send_datagram_calls = 0;
    std::size_t drive_endpoint_calls = 0;
};

RuntimeFaultState &runtime_fault_state() {
    static RuntimeFaultState state;
    return state;
}

template <typename Outcome>
std::optional<Outcome> take_scripted_outcome(std::vector<Outcome> &outcomes) {
    if (outcomes.empty()) {
        return std::nullopt;
    }

    auto outcome = std::move(outcomes.front());
    outcomes.erase(outcomes.begin());
    return outcome;
}

int runtime_poll(pollfd *descriptor, int timeout_ms) {
    auto &state = runtime_fault_state();
    if (auto scripted = take_scripted_outcome(state.config.poll_outcomes); scripted.has_value()) {
        descriptor->revents = scripted->revents;
        if (scripted->result < 0) {
            errno = scripted->error;
        }
        return scripted->result;
    }

    return ::poll(descriptor, 1, timeout_ms);
}

ssize_t runtime_recvfrom(int socket_fd, void *buffer, std::size_t buffer_size, int flags,
                         sockaddr *source, socklen_t *source_len) {
    auto &state = runtime_fault_state();
    if (auto scripted = take_scripted_outcome(state.config.recvfrom_outcomes);
        scripted.has_value()) {
        if (scripted->result < 0) {
            errno = scripted->error;
            return -1;
        }

        const auto copied = std::min<std::size_t>(static_cast<std::size_t>(scripted->result),
                                                  scripted->bytes.size());
        if (copied > 0) {
            std::memcpy(buffer, scripted->bytes.data(), copied);
        }
        if (source != nullptr && source_len != nullptr) {
            const auto writable = std::min<socklen_t>(*source_len, scripted->source_len);
            if (writable > 0) {
                std::memcpy(source, &scripted->source, writable);
            }
            *source_len = scripted->source_len;
        }
        return scripted->result;
    }

    return ::recvfrom(socket_fd, buffer, buffer_size, flags, source, source_len);
}

bool runtime_project_name_empty() {
    const auto &state = runtime_fault_state();
    return state.config.project_name_empty.value_or(coquic::project_name().empty());
}

bool runtime_openssl_available() {
    const auto &state = runtime_fault_state();
    return state.config.openssl_available.value_or(coquic::openssl_available());
}

bool runtime_logging_ready() {
    const auto &state = runtime_fault_state();
    return state.config.logging_ready.value_or(coquic::logging_ready());
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
    if (status != 0) {
        return false;
    }

    address = *reinterpret_cast<sockaddr_in *>(results->ai_addr);
    ::freeaddrinfo(results);
    return true;
}

int open_udp_socket() {
    auto &state = runtime_fault_state();
    ++state.open_udp_socket_calls;
    if (state.config.open_udp_socket_failure_occurrence == state.open_udp_socket_calls) {
        errno = EMFILE;
        return -1;
    }

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
                   socklen_t peer_len, std::string_view role_name) {
    auto &state = runtime_fault_state();
    ++state.send_datagram_calls;
    const auto *buffer =
        datagram.empty() ? nullptr : reinterpret_cast<const void *>(datagram.data());
    const bool fail_send =
        state.config.send_datagram_failure_occurrence == state.send_datagram_calls;
    const ssize_t sent = fail_send ? (errno = EIO, -1)
                                   : ::sendto(fd, buffer, datagram.size(), 0,
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
    auto &fault_state = runtime_fault_state();
    if (auto scripted = take_scripted_outcome(fault_state.config.wait_outcomes);
        scripted.has_value()) {
        if (!scripted->has_value()) {
            return std::nullopt;
        }

        const auto &outcome = scripted->value();
        return RuntimeWaitStep{
            .input = outcome.input,
            .input_time = outcome.input_time,
            .source = outcome.source,
            .source_len = outcome.source_len,
            .has_source = outcome.has_source,
            .idle_timeout = outcome.idle_timeout,
        };
    }

    int timeout_ms = config.idle_timeout_ms;
    if (next_wakeup.has_value()) {
        const auto current = now();
        if (*next_wakeup <= current) {
            return RuntimeWaitStep{
                .input = QuicCoreTimerExpired{},
                .input_time = current,
            };
        }

        const auto remaining = *next_wakeup - current;
        timeout_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          remaining + std::chrono::milliseconds(1))
                                          .count());
    }

    pollfd descriptor{};
    descriptor.fd = config.socket_fd;
    descriptor.events = POLLIN;

    int poll_result = 0;
    do {
        poll_result = runtime_poll(&descriptor, timeout_ms);
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
                .input_time = now(),
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
        bytes_read = runtime_recvfrom(config.socket_fd, inbound.data(), inbound.size(), 0,
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

struct EndpointDriver {
    void *endpoint = nullptr;
    QuicHttp09EndpointUpdate (*on_core_result)(void *endpoint, const QuicCoreResult &result,
                                               QuicCoreTimePoint now) = nullptr;
    QuicHttp09EndpointUpdate (*poll)(void *endpoint, QuicCoreTimePoint now) = nullptr;
};

template <typename Endpoint> EndpointDriver make_endpoint_driver(Endpoint &endpoint) {
    return EndpointDriver{
        .endpoint = &endpoint,
        .on_core_result =
            [](void *opaque, const QuicCoreResult &result, QuicCoreTimePoint step_now) {
                return static_cast<Endpoint *>(opaque)->on_core_result(result, step_now);
            },
        .poll =
            [](void *opaque, QuicCoreTimePoint step_now) {
                return static_cast<Endpoint *>(opaque)->poll(step_now);
            },
    };
}

bool drive_endpoint_until_blocked(const EndpointDriver &driver, QuicCore &core, int fd,
                                  const sockaddr_storage *peer, socklen_t peer_len,
                                  const QuicCoreResult &initial_result, EndpointDriveState &state,
                                  std::string_view role_name) {
    auto &fault_state = runtime_fault_state();
    ++fault_state.drive_endpoint_calls;
    if (fault_state.config.drive_endpoint_failure_occurrence == fault_state.drive_endpoint_calls) {
        state.terminal_failure = true;
        return false;
    }

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

        auto update = driver.on_core_result(driver.endpoint, current_result, now());
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

            update = driver.poll(driver.endpoint, now());
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

int run_http09_client(const Http09RuntimeConfig &config) {
    const auto requests = parse_http09_requests_env(config.requests_env);
    if (!requests.has_value()) {
        std::cerr << "http09-client failed: invalid REQUESTS\n";
        return 1;
    }

    const auto remote = derive_http09_client_remote_impl(config, requests.value());
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
        .requests = requests.value(),
        .download_root = config.download_root,
    });
    auto client_config = config;
    client_config.server_name = remote->server_name;
    QuicCore core(make_http09_client_core_config(client_config));

    EndpointDriveState state;
    auto endpoint_driver = make_endpoint_driver(endpoint);

    bool needs_start = true;
    for (;;) {
        QuicCoreResult step_result;
        if (needs_start) {
            needs_start = false;
            step_result = core.advance(QuicCoreStart{}, now());
        } else {
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

            step_result = core.advance(std::move(*step->input), step->input_time);
        }

        if (!drive_endpoint_until_blocked(endpoint_driver, core, socket_fd, &peer, peer_len,
                                          step_result, state, "client")) {
            return 1;
        }
        if (state.terminal_success) {
            return 0;
        }
    }
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

    QuicHttp09ServerEndpoint endpoint(
        QuicHttp09ServerConfig{.document_root = config.document_root});
    QuicCore core(make_http09_server_core_config_with_identity(
        config, TlsIdentity{
                    .certificate_pem = std::move(*certificate_pem),
                    .private_key_pem = std::move(*private_key_pem),
                }));

    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    bool have_peer = false;
    EndpointDriveState state;
    auto endpoint_driver = make_endpoint_driver(endpoint);

    bool needs_start = true;
    for (;;) {
        QuicCoreResult step_result;
        if (needs_start) {
            needs_start = false;
            step_result = core.advance(QuicCoreStart{}, now());
        } else {
            auto step = wait_for_socket_or_deadline(
                RuntimeWaitConfig{
                    .socket_fd = socket_fd,
                    .idle_timeout_ms = kServerIdleTimeoutMs,
                    .role_name = "server",
                },
                state.next_wakeup);
            if (!step.has_value()) {
                return 1;
            }
            if (step->idle_timeout) {
                continue;
            }
            if (!step->input.has_value()) {
                continue;
            }

            if (step->has_source) {
                peer = step->source;
                peer_len = step->source_len;
                have_peer = true;
            }

            step_result = core.advance(std::move(*step->input), step->input_time);
        }

        if (!drive_endpoint_until_blocked(endpoint_driver, core, socket_fd,
                                          have_peer ? &peer : nullptr, peer_len, step_result, state,
                                          "server")) {
            return 1;
        }
    }
}

} // namespace

std::optional<std::uint16_t> parse_http09_runtime_port(std::string_view value) {
    return parse_port(value);
}

std::optional<QuicHttp09Testcase> parse_http09_runtime_testcase(std::string_view value) {
    return parse_testcase(value);
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
        if (runtime_project_name_empty()) {
            return 1;
        }
        if (!runtime_openssl_available()) {
            return 1;
        }
        if (!runtime_logging_ready()) {
            return 1;
        }
        return 0;
    case Http09RuntimeMode::client:
        return run_http09_client(config);
    case Http09RuntimeMode::server:
        return run_http09_server(config);
    }

    return 1;
}

} // namespace coquic::quic

namespace coquic::quic::test {

namespace {

class ScriptedEndpoint {
  public:
    explicit ScriptedEndpoint(std::initializer_list<QuicHttp09EndpointUpdate> scripted_updates)
        : updates_(scripted_updates) {
    }

    QuicHttp09EndpointUpdate on_core_result(const QuicCoreResult & /*result*/,
                                            QuicCoreTimePoint /*now*/) {
        return take_next();
    }

    QuicHttp09EndpointUpdate poll(QuicCoreTimePoint /*now*/) {
        return take_next();
    }

  private:
    QuicHttp09EndpointUpdate take_next() {
        if (next_update_ >= updates_.size()) {
            return {};
        }
        return updates_[next_update_++];
    }

    std::vector<QuicHttp09EndpointUpdate> updates_;
    std::size_t next_update_ = 0;
};

} // namespace

ScopedRuntimeFaultInjector::ScopedRuntimeFaultInjector(RuntimeFaultConfig config) {
    auto &state = runtime_fault_state();
    previous_config_ = std::move(state.config);
    previous_open_udp_socket_calls_ = state.open_udp_socket_calls;
    previous_send_datagram_calls_ = state.send_datagram_calls;
    previous_drive_endpoint_calls_ = state.drive_endpoint_calls;
    state.config = std::move(config);
    state.open_udp_socket_calls = 0;
    state.send_datagram_calls = 0;
    state.drive_endpoint_calls = 0;
}

ScopedRuntimeFaultInjector::~ScopedRuntimeFaultInjector() {
    auto &state = runtime_fault_state();
    state.config = std::move(previous_config_);
    state.open_udp_socket_calls = previous_open_udp_socket_calls_;
    state.send_datagram_calls = previous_send_datagram_calls_;
    state.drive_endpoint_calls = previous_drive_endpoint_calls_;
}

bool Http09RuntimeTestPeer::call_resolve_udp_peer_ipv4(std::string_view host, std::uint16_t port,
                                                       sockaddr_in &address) {
    return resolve_udp_peer_ipv4(host, port, address);
}

bool Http09RuntimeTestPeer::call_send_datagram(int fd, std::span<const std::byte> datagram,
                                               const sockaddr_storage &peer, socklen_t peer_len,
                                               std::string_view role_name) {
    return send_datagram(fd, datagram, peer, peer_len, role_name);
}

ssize_t Http09RuntimeTestPeer::call_runtime_recvfrom(int socket_fd, void *buffer,
                                                     std::size_t buffer_size, int flags,
                                                     sockaddr *source, socklen_t *source_len) {
    return runtime_recvfrom(socket_fd, buffer, buffer_size, flags, source, source_len);
}

RuntimeWaitObservation Http09RuntimeTestPeer::call_wait_for_socket_or_deadline(
    int socket_fd, int idle_timeout_ms, std::string_view role_name,
    const std::optional<QuicCoreTimePoint> &next_wakeup) {
    RuntimeWaitObservation observation;
    const auto step = wait_for_socket_or_deadline(
        RuntimeWaitConfig{
            .socket_fd = socket_fd,
            .idle_timeout_ms = idle_timeout_ms,
            .role_name = role_name,
        },
        next_wakeup);
    if (!step.has_value()) {
        return observation;
    }

    observation.has_value = true;
    observation.input = step->input;
    observation.input_time = step->input_time;
    observation.source = step->source;
    observation.source_len = step->source_len;
    observation.has_source = step->has_source;
    observation.idle_timeout = step->idle_timeout;
    return observation;
}

bool Http09RuntimeTestPeer::call_handle_core_effects(int fd, const QuicCoreResult &result,
                                                     const sockaddr_storage *peer,
                                                     socklen_t peer_len,
                                                     std::string_view role_name) {
    return handle_core_effects(fd, result, peer, peer_len, role_name);
}

QuicCoreResult Http09RuntimeTestPeer::call_advance_core_with_inputs(
    QuicCore &core, std::span<const QuicCoreInput> inputs, QuicCoreTimePoint step_time) {
    return advance_core_with_inputs(core, inputs, step_time);
}

RuntimeDriveObservation Http09RuntimeTestPeer::call_drive_scripted_endpoint_until_blocked(
    QuicCore &core, int fd, const sockaddr_storage *peer, socklen_t peer_len,
    const QuicCoreResult &initial_result,
    std::initializer_list<QuicHttp09EndpointUpdate> scripted_updates, std::string_view role_name) {
    ScriptedEndpoint endpoint(scripted_updates);
    const auto endpoint_driver = make_endpoint_driver(endpoint);
    EndpointDriveState state;
    RuntimeDriveObservation observation;
    observation.returned = drive_endpoint_until_blocked(endpoint_driver, core, fd, peer, peer_len,
                                                        initial_result, state, role_name);
    observation.next_wakeup = state.next_wakeup;
    observation.terminal_success = state.terminal_success;
    observation.terminal_failure = state.terminal_failure;
    return observation;
}

} // namespace coquic::quic::test
