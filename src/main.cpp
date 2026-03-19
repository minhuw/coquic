#include "src/coquic.h"

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
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
constexpr const char *kUsageLine = "usage: coquic [demo-server|demo-client <message>]";

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

bool flush_queued_output(int fd, coquic::quic::QuicDemoChannel &channel,
                         const sockaddr_storage &peer, socklen_t peer_len) {
    for (;;) {
        auto queued = channel.on_datagram({});
        if (channel.has_failed()) {
            return false;
        }
        if (queued.empty()) {
            return true;
        }
        if (!send_datagram(fd, queued, peer, peer_len)) {
            return false;
        }
    }
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

coquic::quic::QuicCoreConfig make_server_config() {
    return {
        .role = coquic::quic::EndpointRole::server,
        .source_connection_id = {std::byte{0x53}, std::byte{0x01}},
        .verify_peer = false,
        .server_name = "localhost",
        .identity =
            coquic::quic::TlsIdentity{
                .certificate_pem = read_text_file("tests/fixtures/quic-server-cert.pem"),
                .private_key_pem = read_text_file("tests/fixtures/quic-server-key.pem"),
            },
    };
}

int run_demo_server(const DemoCliConfig &config) {
    const int socket_fd = open_udp_socket();
    if (socket_fd < 0) {
        std::cerr << "demo-server failed: unable to create UDP socket\n";
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
        std::cerr << "demo-server failed: unable to bind UDP socket\n";
        return 1;
    }

    coquic::quic::QuicDemoChannel channel(make_server_config());
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    bool have_peer = false;

    for (;;) {
        std::vector<std::byte> inbound(kMaxDatagramBytes);
        sockaddr_storage source{};
        socklen_t source_len = sizeof(source);
        const auto bytes_read = ::recvfrom(socket_fd, inbound.data(), inbound.size(), 0,
                                           reinterpret_cast<sockaddr *>(&source), &source_len);
        if (bytes_read < 0) {
            std::cerr << "demo-server failed: recvfrom error\n";
            return 1;
        }
        inbound.resize(static_cast<std::size_t>(bytes_read));

        auto outbound = channel.on_datagram(std::move(inbound));
        if (channel.has_failed()) {
            std::cerr << "demo-server failed: channel entered failure state\n";
            return 1;
        }

        if (!have_peer) {
            peer = source;
            peer_len = source_len;
            have_peer = true;
        }

        if (!outbound.empty() && !send_datagram(socket_fd, outbound, peer, peer_len)) {
            std::cerr << "demo-server failed: sendto error\n";
            return 1;
        }
        if (!flush_queued_output(socket_fd, channel, peer, peer_len)) {
            std::cerr << "demo-server failed: channel flush error\n";
            return 1;
        }

        auto messages = channel.take_messages();
        if (messages.empty()) {
            continue;
        }

        const std::string received = string_from_bytes(messages.front());
        std::cout << "received: " << received << '\n';

        const std::string reply = "echo: " + received;
        channel.send_message(bytes_from_string(reply));
        if (channel.has_failed()) {
            std::cerr << "demo-server failed: unable to queue reply\n";
            return 1;
        }
        if (!flush_queued_output(socket_fd, channel, peer, peer_len)) {
            std::cerr << "demo-server failed: channel flush error\n";
            return 1;
        }

        std::cout << "sent: " << reply << '\n';
        return 0;
    }
}

int run_demo_client(const DemoCliConfig &config) {
    const int socket_fd = open_udp_socket();
    if (socket_fd < 0) {
        std::cerr << "demo-client failed: unable to create UDP socket\n";
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

    coquic::quic::QuicDemoChannel channel(make_client_config());
    channel.send_message(bytes_from_string(config.message));
    if (channel.has_failed()) {
        std::cerr << "demo-client failed: unable to queue message\n";
        return 1;
    }
    if (!flush_queued_output(socket_fd, channel, peer, peer_len)) {
        std::cerr << "demo-client failed: channel flush error\n";
        return 1;
    }

    for (;;) {
        std::vector<std::byte> inbound(kMaxDatagramBytes);
        sockaddr_storage source{};
        socklen_t source_len = sizeof(source);
        const auto bytes_read = ::recvfrom(socket_fd, inbound.data(), inbound.size(), 0,
                                           reinterpret_cast<sockaddr *>(&source), &source_len);
        if (bytes_read < 0) {
            std::cerr << "demo-client failed: recvfrom error\n";
            return 1;
        }
        inbound.resize(static_cast<std::size_t>(bytes_read));

        auto outbound = channel.on_datagram(std::move(inbound));
        if (channel.has_failed()) {
            std::cerr << "demo-client failed: channel entered failure state\n";
            return 1;
        }
        if (!outbound.empty() && !send_datagram(socket_fd, outbound, peer, peer_len)) {
            std::cerr << "demo-client failed: sendto error\n";
            return 1;
        }
        if (!flush_queued_output(socket_fd, channel, peer, peer_len)) {
            std::cerr << "demo-client failed: channel flush error\n";
            return 1;
        }

        auto messages = channel.take_messages();
        if (messages.empty()) {
            continue;
        }
        std::cout << string_from_bytes(messages.front()) << '\n';
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
