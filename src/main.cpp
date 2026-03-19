#include "src/coquic.h"

#include <arpa/inet.h>
#include <chrono>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

enum class DemoMode : std::uint8_t { health_check, server, client };

struct DemoCliConfig {
    DemoMode mode = DemoMode::health_check;
    std::string host = "127.0.0.1";
    std::uint16_t port = 4444;
    std::string message;
};

constexpr std::size_t kMaxDatagramBytes = 65535;
constexpr int kReceiveTimeoutSeconds = 10;
constexpr const char *kUsageLine = "usage: coquic [demo-server|demo-client <message>]";
constexpr const char *kServerCertPath = "tests/fixtures/quic-server-cert.pem";
constexpr const char *kServerKeyPath = "tests/fixtures/quic-server-key.pem";

using DemoChannel = coquic::quic::QuicDemoChannel;
using DemoTimePoint = coquic::quic::QuicCoreTimePoint;

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
    ScopedFd(ScopedFd &&) = delete;
    ScopedFd &operator=(ScopedFd &&) = delete;

    int get() const {
        return fd_;
    }

  private:
    int fd_ = -1;
};

std::string read_text_file(const char *path) {
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

std::optional<std::string> read_required_text_file(const char *path) {
    std::string content = read_text_file(path);
    if (!content.empty()) {
        return content;
    }
    std::cerr << "demo-server failed: unable to load required TLS fixture '" << path
              << "' (file missing or empty). Run from the repo root.\n";
    return std::nullopt;
}

std::vector<std::byte> bytes_from_string(std::string_view text) {
    std::vector<std::byte> bytes;
    bytes.reserve(text.size());
    for (const auto character : text) {
        bytes.push_back(static_cast<std::byte>(character));
    }
    return bytes;
}

std::string string_from_bytes(const std::vector<std::byte> &bytes) {
    std::string text;
    text.reserve(bytes.size());
    for (const auto byte : bytes) {
        text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return text;
}

std::optional<DemoCliConfig> parse_cli_args(int argc, char **argv) {
    DemoCliConfig config;
    if (argc == 1) {
        config.mode = DemoMode::health_check;
        return config;
    }

    const std::string_view subcommand = argv[1];
    if (subcommand == "demo-server" && argc == 2) {
        config.mode = DemoMode::server;
        return config;
    }
    if (subcommand == "demo-client" && argc == 3) {
        config.mode = DemoMode::client;
        config.message = argv[2];
        return config;
    }

    return std::nullopt;
}

bool make_ipv4_address(std::string_view host, std::uint16_t port, sockaddr_in &address) {
    address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    return ::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) == 1;
}

int open_udp_socket() {
    return ::socket(AF_INET, SOCK_DGRAM, 0);
}

bool send_datagram(int fd, const std::vector<std::byte> &datagram, const sockaddr_storage &peer,
                   socklen_t peer_len) {
    return ::sendto(fd, datagram.data(), datagram.size(), 0,
                    reinterpret_cast<const sockaddr *>(&peer), peer_len) >= 0;
}

DemoTimePoint now() {
    return coquic::quic::QuicCoreClock::now();
}

bool send_effect_datagrams(int fd, const std::vector<coquic::quic::QuicDemoChannelEffect> &effects,
                           const sockaddr_storage &peer, socklen_t peer_len) {
    for (const auto &effect : effects) {
        const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
        if (send == nullptr) {
            continue;
        }
        if (!send_datagram(fd, send->bytes, peer, peer_len)) {
            std::cerr << "demo failed: sendto error: " << std::strerror(errno) << '\n';
            return false;
        }
    }
    return true;
}

std::optional<std::vector<std::byte>>
take_received_message(const std::vector<coquic::quic::QuicDemoChannelEffect> &effects) {
    for (const auto &effect : effects) {
        const auto *received = std::get_if<coquic::quic::QuicDemoChannelReceiveMessage>(&effect);
        if (received != nullptr) {
            return received->bytes;
        }
    }
    return std::nullopt;
}

bool saw_terminal_failure(const std::vector<coquic::quic::QuicDemoChannelEffect> &effects) {
    for (const auto &effect : effects) {
        const auto *state_event = std::get_if<coquic::quic::QuicDemoChannelStateEvent>(&effect);
        if (state_event != nullptr &&
            state_event->change == coquic::quic::QuicDemoChannelStateChange::failed) {
            return true;
        }
    }
    return false;
}

bool has_send_effect(const std::vector<coquic::quic::QuicDemoChannelEffect> &effects) {
    for (const auto &effect : effects) {
        if (std::holds_alternative<coquic::quic::QuicCoreSendDatagram>(effect)) {
            return true;
        }
    }
    return false;
}

struct DemoWaitStep {
    coquic::quic::QuicDemoChannelInput input;
    DemoTimePoint input_time;
    sockaddr_storage source{};
    socklen_t source_len = 0;
    bool has_source = false;
};

std::optional<DemoWaitStep>
wait_for_socket_or_deadline(int fd, const std::optional<DemoTimePoint> &next_wakeup) {
    int timeout_ms = kReceiveTimeoutSeconds * 1000;
    if (next_wakeup.has_value()) {
        const auto current = now();
        if (*next_wakeup <= current) {
            return DemoWaitStep{
                .input = coquic::quic::QuicCoreTimerExpired{},
                .input_time = current,
            };
        }

        const auto remaining = *next_wakeup - current;
        timeout_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          remaining + std::chrono::milliseconds(1))
                                          .count());
        if (timeout_ms < 1) {
            timeout_ms = 1;
        }
    }

    pollfd descriptor{};
    descriptor.fd = fd;
    descriptor.events = POLLIN;

    int poll_result = 0;
    do {
        poll_result = ::poll(&descriptor, 1, timeout_ms);
    } while (poll_result < 0 && errno == EINTR);

    if (poll_result < 0) {
        std::cerr << "demo failed: poll error: " << std::strerror(errno) << '\n';
        return std::nullopt;
    }

    if (poll_result == 0) {
        if (!next_wakeup.has_value()) {
            std::cerr << "demo failed: timed out waiting for inbound datagram\n";
            return std::nullopt;
        }
        return DemoWaitStep{
            .input = coquic::quic::QuicCoreTimerExpired{},
            .input_time = now(),
        };
    }

    if ((descriptor.revents & POLLIN) == 0) {
        std::cerr << "demo failed: socket became unreadable\n";
        return std::nullopt;
    }

    std::vector<std::byte> inbound(kMaxDatagramBytes);
    sockaddr_storage source{};
    socklen_t source_len = sizeof(source);

    ssize_t bytes_read = 0;
    do {
        bytes_read = ::recvfrom(fd, inbound.data(), inbound.size(), 0,
                                reinterpret_cast<sockaddr *>(&source), &source_len);
    } while (bytes_read < 0 && errno == EINTR);

    if (bytes_read < 0) {
        std::cerr << "demo failed: recvfrom error: " << std::strerror(errno) << '\n';
        return std::nullopt;
    }

    inbound.resize(static_cast<std::size_t>(bytes_read));
    return DemoWaitStep{
        .input =
            coquic::quic::QuicCoreInboundDatagram{
                .bytes = std::move(inbound),
            },
        .input_time = now(),
        .source = source,
        .source_len = source_len,
        .has_source = true,
    };
}

coquic::quic::QuicCoreConfig make_client_config() {
    return {
        .role = coquic::quic::EndpointRole::client,
        .source_connection_id = {std::byte{0xc1}, std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x83}, std::byte{0x94}, std::byte{0xc8},
                                              std::byte{0xf0}, std::byte{0x3e}, std::byte{0x51},
                                              std::byte{0x57}, std::byte{0x08}},
        .verify_peer = false,
        .server_name = "localhost",
    };
}

std::optional<coquic::quic::QuicCoreConfig> make_server_config() {
    const auto cert = read_required_text_file(kServerCertPath);
    if (!cert.has_value()) {
        return std::nullopt;
    }
    const auto key = read_required_text_file(kServerKeyPath);
    if (!key.has_value()) {
        return std::nullopt;
    }

    return coquic::quic::QuicCoreConfig{
        .role = coquic::quic::EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .verify_peer = false,
        .server_name = "localhost",
        .identity =
            coquic::quic::TlsIdentity{
                .certificate_pem = *cert,
                .private_key_pem = *key,
            },
    };
}

int run_demo_server(const DemoCliConfig &config) {
    const int socket_fd = open_udp_socket();
    if (socket_fd < 0) {
        std::cerr << "demo-server failed: unable to create UDP socket: " << std::strerror(errno)
                  << '\n';
        return 1;
    }
    ScopedFd socket_guard(socket_fd);

    sockaddr_in bind_address{};
    if (!make_ipv4_address(config.host, config.port, bind_address)) {
        std::cerr << "demo-server failed: invalid host address\n";
        return 1;
    }
    if (::bind(socket_fd, reinterpret_cast<const sockaddr *>(&bind_address),
               sizeof(bind_address)) != 0) {
        std::cerr << "demo-server failed: unable to bind UDP socket: " << std::strerror(errno)
                  << '\n';
        return 1;
    }

    auto server_config = make_server_config();
    if (!server_config.has_value()) {
        return 1;
    }
    DemoChannel channel(std::move(*server_config));
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    bool have_peer = false;
    std::optional<DemoTimePoint> next_wakeup = std::nullopt;

    auto start_result = channel.advance(coquic::quic::QuicCoreStart{}, now());
    if (saw_terminal_failure(start_result.effects) || channel.has_failed()) {
        std::cerr << "demo-server failed: channel entered failure state\n";
        return 1;
    }
    if (has_send_effect(start_result.effects)) {
        std::cerr << "demo-server failed: cannot send datagram before peer is known\n";
        return 1;
    }
    next_wakeup = start_result.next_wakeup;

    for (;;) {
        auto step = wait_for_socket_or_deadline(socket_fd, next_wakeup);
        if (!step.has_value()) {
            return 1;
        }
        if (!have_peer && step->has_source) {
            peer = step->source;
            peer_len = step->source_len;
            have_peer = true;
        }
        auto step_result = channel.advance(std::move(step->input), step->input_time);

        if (saw_terminal_failure(step_result.effects) || channel.has_failed()) {
            std::cerr << "demo-server failed: channel entered failure state\n";
            return 1;
        }
        if (!have_peer && has_send_effect(step_result.effects)) {
            std::cerr << "demo-server failed: cannot send datagram before peer is known\n";
            return 1;
        }
        if (have_peer && !send_effect_datagrams(socket_fd, step_result.effects, peer, peer_len)) {
            return 1;
        }
        next_wakeup = step_result.next_wakeup;

        auto received_message = take_received_message(step_result.effects);
        if (!received_message.has_value()) {
            continue;
        }
        const std::string received = string_from_bytes(*received_message);
        std::cout << "received: " << received << '\n';

        const std::string reply = "echo: " + received;
        auto queued = channel.advance(
            coquic::quic::QuicDemoChannelQueueMessage{
                .bytes = bytes_from_string(reply),
            },
            now());
        if (saw_terminal_failure(queued.effects) || channel.has_failed()) {
            std::cerr << "demo-server failed: channel entered failure state\n";
            return 1;
        }
        if (!send_effect_datagrams(socket_fd, queued.effects, peer, peer_len)) {
            return 1;
        }
        next_wakeup = queued.next_wakeup;

        std::cout << "sent: " << reply << '\n';
        return 0;
    }
}

int run_demo_client(const DemoCliConfig &config) {
    const int socket_fd = open_udp_socket();
    if (socket_fd < 0) {
        std::cerr << "demo-client failed: unable to create UDP socket: " << std::strerror(errno)
                  << '\n';
        return 1;
    }
    ScopedFd socket_guard(socket_fd);

    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    sockaddr_in server_address{};
    if (!make_ipv4_address(config.host, config.port, server_address)) {
        std::cerr << "demo-client failed: invalid host address\n";
        return 1;
    }
    peer = {};
    std::memcpy(&peer, &server_address, sizeof(server_address));
    peer_len = sizeof(server_address);

    DemoChannel channel(make_client_config());
    std::optional<DemoTimePoint> next_wakeup = std::nullopt;

    auto start_result = channel.advance(coquic::quic::QuicCoreStart{}, now());
    if (saw_terminal_failure(start_result.effects) || channel.has_failed()) {
        std::cerr << "demo-client failed: channel entered failure state\n";
        return 1;
    }
    if (!send_effect_datagrams(socket_fd, start_result.effects, peer, peer_len)) {
        return 1;
    }
    next_wakeup = start_result.next_wakeup;

    auto queued = channel.advance(
        coquic::quic::QuicDemoChannelQueueMessage{
            .bytes = bytes_from_string(config.message),
        },
        now());
    if (saw_terminal_failure(queued.effects) || channel.has_failed()) {
        std::cerr << "demo-client failed: channel entered failure state\n";
        return 1;
    }
    if (!send_effect_datagrams(socket_fd, queued.effects, peer, peer_len)) {
        return 1;
    }
    next_wakeup = queued.next_wakeup;

    if (const auto received_message = take_received_message(queued.effects);
        received_message.has_value()) {
        std::cout << string_from_bytes(*received_message) << '\n';
        return 0;
    }

    for (;;) {
        auto step = wait_for_socket_or_deadline(socket_fd, next_wakeup);
        if (!step.has_value()) {
            return 1;
        }
        auto step_result = channel.advance(std::move(step->input), step->input_time);
        if (saw_terminal_failure(step_result.effects) || channel.has_failed()) {
            std::cerr << "demo-client failed: channel entered failure state\n";
            return 1;
        }
        if (!send_effect_datagrams(socket_fd, step_result.effects, peer, peer_len)) {
            return 1;
        }
        next_wakeup = step_result.next_wakeup;

        const auto received_message = take_received_message(step_result.effects);
        if (!received_message.has_value()) {
            continue;
        }
        std::cout << string_from_bytes(*received_message) << '\n';
        return 0;
    }
}

} // namespace

int main(int argc, char **argv) {
    coquic::init_logging();

    const auto config = parse_cli_args(argc, argv);
    if (!config.has_value()) {
        std::cerr << kUsageLine << '\n';
        return 1;
    }

    switch (config->mode) {
    case DemoMode::health_check:
        return coquic::project_name().empty() || !coquic::openssl_available() ||
               !coquic::logging_ready();
    case DemoMode::server:
        return run_demo_server(*config);
    case DemoMode::client:
        return run_demo_client(*config);
    }

    std::cerr << kUsageLine << '\n';
    return 1;
}
