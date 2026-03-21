#include <algorithm>
#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "src/quic/packet.h"
#define private public
#include "src/quic/http09_runtime.h"
#undef private
#include "tests/quic_test_utils.h"

namespace {

class ScopedEnvVar {
  public:
    ScopedEnvVar(std::string name, std::optional<std::string> value) : name_(std::move(name)) {
        const char *existing = std::getenv(name_.c_str());
        if (existing != nullptr) {
            previous_ = std::string(existing);
            had_previous_ = true;
        }

        if (value.has_value()) {
            EXPECT_EQ(::setenv(name_.c_str(), value->c_str(), 1), 0);
        } else {
            EXPECT_EQ(::unsetenv(name_.c_str()), 0);
        }
    }

    ~ScopedEnvVar() {
        if (had_previous_) {
            ::setenv(name_.c_str(), previous_.c_str(), 1);
            return;
        }
        ::unsetenv(name_.c_str());
    }

    ScopedEnvVar(const ScopedEnvVar &) = delete;
    ScopedEnvVar &operator=(const ScopedEnvVar &) = delete;

  private:
    std::string name_;
    std::string previous_;
    bool had_previous_ = false;
};

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

class ScopedChildProcess {
  public:
    explicit ScopedChildProcess(pid_t pid) : pid_(pid) {
    }

    ~ScopedChildProcess() {
        terminate();
    }

    ScopedChildProcess(const ScopedChildProcess &) = delete;
    ScopedChildProcess &operator=(const ScopedChildProcess &) = delete;

    std::optional<int> wait_for_exit(std::chrono::milliseconds timeout) {
        if (pid_ <= 0) {
            return cached_status_;
        }

        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            int status = 0;
            const auto result = ::waitpid(pid_, &status, WNOHANG);
            if (result == pid_) {
                pid_ = -1;
                cached_status_ = status;
                return status;
            }
            if (result < 0) {
                pid_ = -1;
                return std::nullopt;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                return std::nullopt;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void terminate() {
        if (pid_ <= 0) {
            return;
        }

        int status = 0;
        const auto waited = ::waitpid(pid_, &status, WNOHANG);
        if (waited == pid_) {
            pid_ = -1;
            cached_status_ = status;
            return;
        }

        ::kill(pid_, SIGTERM);
        if (::waitpid(pid_, &status, 0) == pid_) {
            cached_status_ = status;
        }
        pid_ = -1;
    }

  private:
    pid_t pid_ = -1;
    std::optional<int> cached_status_;
};

ScopedChildProcess launch_runtime_server_process(const coquic::quic::Http09RuntimeConfig &config) {
    const auto pid = ::fork();
    if (pid == 0) {
        ::_exit(coquic::quic::run_http09_runtime(config));
    }
    return ScopedChildProcess(pid);
}

std::uint16_t allocate_udp_loopback_port() {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }
    ScopedFd socket_guard(fd);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);

    if (::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        return 0;
    }

    sockaddr_in bound{};
    socklen_t bound_length = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &bound_length) != 0) {
        return 0;
    }

    return ntohs(bound.sin_port);
}

std::string read_file_bytes(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

bool first_header_is_retry_packet(std::span<const std::byte> datagram) {
    if (datagram.empty()) {
        return false;
    }

    const auto first = std::to_integer<std::uint8_t>(datagram.front());
    const bool is_long_header = (first & 0x80u) != 0;
    if (!is_long_header) {
        return false;
    }

    const std::uint8_t packet_type = (first >> 4) & 0x03u;
    return packet_type == 0x03u;
}

bool has_long_header(std::span<const std::byte> datagram) {
    if (datagram.empty()) {
        return false;
    }
    return (std::to_integer<std::uint8_t>(datagram.front()) & 0x80u) != 0;
}

std::vector<std::byte> make_unsupported_version_probe() {
    std::vector<std::byte> datagram(1200, std::byte{0x00});
    std::size_t offset = 0;
    datagram[offset++] = std::byte{0xc0};
    datagram[offset++] = std::byte{0x57};
    datagram[offset++] = std::byte{0x41};
    datagram[offset++] = std::byte{0x49};
    datagram[offset++] = std::byte{0x54};
    datagram[offset++] = std::byte{0x08};

    const std::array<std::byte, 8> destination_connection_id = {
        std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
        std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08},
    };
    std::copy(destination_connection_id.begin(), destination_connection_id.end(),
              datagram.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += destination_connection_id.size();

    datagram[offset++] = std::byte{0x08};
    const std::array<std::byte, 8> source_connection_id = {
        std::byte{0xc1}, std::byte{0x01}, std::byte{0x12}, std::byte{0x23},
        std::byte{0x34}, std::byte{0x45}, std::byte{0x56}, std::byte{0x67},
    };
    std::copy(source_connection_id.begin(), source_connection_id.end(),
              datagram.begin() + static_cast<std::ptrdiff_t>(offset));
    return datagram;
}

coquic::quic::QuicCoreTimePoint runtime_now() {
    return coquic::quic::QuicCoreClock::now();
}

constexpr std::size_t kRuntimeConnectionIdLength = 8;
constexpr std::uint32_t kQuicVersion1 = 1;

std::string connection_id_key(std::span<const std::byte> connection_id) {
    if (connection_id.empty()) {
        return {};
    }
    return std::string(reinterpret_cast<const char *>(connection_id.data()), connection_id.size());
}

coquic::quic::ConnectionId make_runtime_connection_id(std::byte prefix, std::uint64_t sequence) {
    coquic::quic::ConnectionId connection_id(kRuntimeConnectionIdLength, std::byte{0x00});
    connection_id.front() = prefix;
    for (std::size_t index = 1; index < connection_id.size(); ++index) {
        const auto shift = static_cast<unsigned>((connection_id.size() - 1 - index) * 8);
        connection_id[index] = static_cast<std::byte>((sequence >> shift) & 0xffu);
    }
    return connection_id;
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
    };

    Kind kind;
    coquic::quic::ConnectionId destination_connection_id;
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
            .destination_connection_id = coquic::quic::ConnectionId(
                bytes.begin() + 1, bytes.begin() + 1 + kRuntimeConnectionIdLength),
        };
    }

    if ((first_byte & 0x40u) == 0 || bytes.size() < 7) {
        return std::nullopt;
    }
    if (read_u32_be_at(bytes, 1) != kQuicVersion1) {
        return std::nullopt;
    }

    std::size_t offset = 5;
    const auto destination_connection_id_length =
        static_cast<std::size_t>(std::to_integer<std::uint8_t>(bytes[offset++]));
    if (offset + destination_connection_id_length > bytes.size()) {
        return std::nullopt;
    }

    const auto type = static_cast<std::uint8_t>((first_byte >> 4) & 0x03u);
    return ParsedServerDatagram{
        .kind = type == 0x00 ? ParsedServerDatagram::Kind::supported_initial
                             : ParsedServerDatagram::Kind::supported_long_header,
        .destination_connection_id = coquic::quic::ConnectionId(
            bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            bytes.begin() + static_cast<std::ptrdiff_t>(offset + destination_connection_id_length)),
    };
}

struct ObservingServerResult {
    int exit_code = 1;
    std::size_t handshake_ready_events = 0;
    std::vector<std::uint64_t> request_stream_ids;
    std::size_t inbound_datagrams = 0;
    std::size_t timer_expirations = 0;
    std::size_t sent_datagrams = 0;
    std::size_t sent_bytes = 0;
    bool has_pending_application_send = false;
    std::size_t sent_packets = 0;
    std::size_t bytes_in_flight = 0;
    std::size_t congestion_window = 0;
    bool has_next_wakeup = false;
    std::uint64_t queued_stream_bytes = 0;
};

struct InMemoryHttp09TransferResult {
    bool client_complete = false;
    bool client_failed = false;
    bool server_failed = false;
    bool hit_step_limit = false;
    std::size_t steps = 0;
    std::size_t client_sent_datagrams = 0;
    std::size_t client_sent_bytes = 0;
    std::size_t server_sent_datagrams = 0;
    std::size_t server_sent_bytes = 0;
    std::size_t client_bytes_in_flight = 0;
    std::size_t server_bytes_in_flight = 0;
    std::size_t client_congestion_window = 0;
    std::size_t server_congestion_window = 0;
    std::uint64_t client_queued_stream_bytes = 0;
    std::uint64_t server_queued_stream_bytes = 0;
    bool client_has_next_wakeup = false;
    bool server_has_next_wakeup = false;
};

struct InMemoryHttp09TransferConfig {
    coquic::quic::Http09RuntimeConfig client_config;
    coquic::quic::Http09RuntimeConfig server_config;
};

InMemoryHttp09TransferResult
run_in_memory_http09_transfer(const InMemoryHttp09TransferConfig &transfer_config) {
    InMemoryHttp09TransferResult observed;

    const auto requests =
        coquic::quic::parse_http09_requests_env(transfer_config.client_config.requests_env);
    if (!requests.has_value()) {
        observed.client_failed = true;
        return observed;
    }

    struct ClientSession {
        coquic::quic::QuicHttp09ClientEndpoint endpoint;
        coquic::quic::QuicCore core;
        std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;
        bool terminal_success = false;
        bool terminal_failure = false;
    };

    struct ServerSession {
        coquic::quic::QuicHttp09ServerEndpoint endpoint;
        coquic::quic::QuicCore core;
        std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;
        bool terminal_failure = false;
    };

    ClientSession client{
        .endpoint = coquic::quic::QuicHttp09ClientEndpoint(coquic::quic::QuicHttp09ClientConfig{
            .requests = requests.value(),
            .download_root = transfer_config.client_config.download_root,
        }),
        .core = coquic::quic::QuicCore(
            coquic::quic::make_http09_client_core_config(transfer_config.client_config)),
        .next_wakeup = std::nullopt,
        .terminal_success = false,
        .terminal_failure = false,
    };
    ServerSession server{
        .endpoint = coquic::quic::QuicHttp09ServerEndpoint(coquic::quic::QuicHttp09ServerConfig{
            .document_root = transfer_config.server_config.document_root}),
        .core = coquic::quic::QuicCore(
            coquic::quic::make_http09_server_core_config(transfer_config.server_config)),
        .next_wakeup = std::nullopt,
        .terminal_failure = false,
    };

    std::deque<std::vector<std::byte>> to_client;
    std::deque<std::vector<std::byte>> to_server;

    const auto capture_connection_state = [&]() {
        observed.client_bytes_in_flight =
            client.core.connection_->congestion_controller_.bytes_in_flight();
        observed.server_bytes_in_flight =
            server.core.connection_->congestion_controller_.bytes_in_flight();
        observed.client_congestion_window =
            client.core.connection_->congestion_controller_.congestion_window();
        observed.server_congestion_window =
            server.core.connection_->congestion_controller_.congestion_window();
        observed.client_queued_stream_bytes = client.core.connection_->total_queued_stream_bytes();
        observed.server_queued_stream_bytes = server.core.connection_->total_queued_stream_bytes();
        observed.client_has_next_wakeup = client.next_wakeup.has_value();
        observed.server_has_next_wakeup = server.next_wakeup.has_value();
    };

    const auto drive_client = [&](coquic::quic::QuicCoreResult result,
                                  coquic::quic::QuicCoreTimePoint now) {
        for (;;) {
            client.next_wakeup = result.next_wakeup;
            capture_connection_state();
            if (result.local_error.has_value()) {
                client.terminal_failure = true;
                observed.client_failed = true;
                return false;
            }

            for (const auto &effect : result.effects) {
                const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
                if (send == nullptr) {
                    continue;
                }

                ++observed.client_sent_datagrams;
                observed.client_sent_bytes += send->bytes.size();
                to_server.push_back(send->bytes);
            }

            auto update = client.endpoint.on_core_result(result, now);
            if (update.terminal_failure) {
                client.terminal_failure = true;
                observed.client_failed = true;
                return false;
            }
            if (update.terminal_success) {
                client.terminal_success = true;
                observed.client_complete = true;
                return true;
            }

            while (true) {
                if (!update.core_inputs.empty()) {
                    result = coquic::quic::test::advance_core_with_inputs(client.core,
                                                                          update.core_inputs, now);
                    break;
                }
                if (!update.has_pending_work) {
                    capture_connection_state();
                    return true;
                }

                update = client.endpoint.poll(now);
                if (update.terminal_failure) {
                    client.terminal_failure = true;
                    observed.client_failed = true;
                    return false;
                }
                if (update.terminal_success) {
                    client.terminal_success = true;
                    observed.client_complete = true;
                    return true;
                }
            }
        }
    };

    const auto drive_server = [&](coquic::quic::QuicCoreResult result,
                                  coquic::quic::QuicCoreTimePoint now) {
        for (;;) {
            server.next_wakeup = result.next_wakeup;
            capture_connection_state();
            if (result.local_error.has_value()) {
                server.terminal_failure = true;
                observed.server_failed = true;
                return false;
            }

            for (const auto &effect : result.effects) {
                const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
                if (send == nullptr) {
                    continue;
                }

                ++observed.server_sent_datagrams;
                observed.server_sent_bytes += send->bytes.size();
                to_client.push_back(send->bytes);
            }

            auto update = server.endpoint.on_core_result(result, now);
            if (update.terminal_failure) {
                server.terminal_failure = true;
                observed.server_failed = true;
                return false;
            }

            while (true) {
                if (!update.core_inputs.empty()) {
                    result = coquic::quic::test::advance_core_with_inputs(server.core,
                                                                          update.core_inputs, now);
                    break;
                }
                if (!update.has_pending_work) {
                    capture_connection_state();
                    return true;
                }

                update = server.endpoint.poll(now);
                if (update.terminal_failure) {
                    server.terminal_failure = true;
                    observed.server_failed = true;
                    return false;
                }
            }
        }
    };

    auto now = coquic::quic::test::test_time();
    if (!drive_client(client.core.advance(coquic::quic::QuicCoreStart{}, now), now)) {
        capture_connection_state();
        return observed;
    }

    constexpr std::size_t kStepLimit = 20000;
    while (!client.terminal_success && !client.terminal_failure && !server.terminal_failure &&
           observed.steps < kStepLimit) {
        ++observed.steps;

        if (!to_server.empty()) {
            now += std::chrono::milliseconds(1);
            auto inbound = std::move(to_server.front());
            to_server.pop_front();
            if (!drive_server(server.core.advance(
                                  coquic::quic::QuicCoreInboundDatagram{
                                      .bytes = std::move(inbound),
                                  },
                                  now),
                              now)) {
                break;
            }
            continue;
        }

        if (!to_client.empty()) {
            now += std::chrono::milliseconds(1);
            auto inbound = std::move(to_client.front());
            to_client.pop_front();
            if (!drive_client(client.core.advance(
                                  coquic::quic::QuicCoreInboundDatagram{
                                      .bytes = std::move(inbound),
                                  },
                                  now),
                              now)) {
                break;
            }
            continue;
        }

        const auto next_wakeup =
            coquic::quic::test::earliest_next_wakeup({client.next_wakeup, server.next_wakeup});
        if (!next_wakeup.has_value()) {
            break;
        }

        now = next_wakeup.value();
        if (client.next_wakeup == next_wakeup) {
            if (!drive_client(client.core.advance(coquic::quic::QuicCoreTimerExpired{}, now),
                              now)) {
                break;
            }
            continue;
        }

        if (server.next_wakeup == next_wakeup) {
            if (!drive_server(server.core.advance(coquic::quic::QuicCoreTimerExpired{}, now),
                              now)) {
                break;
            }
            continue;
        }
    }

    capture_connection_state();
    observed.client_complete = client.terminal_success;
    observed.client_failed = client.terminal_failure;
    observed.server_failed = server.terminal_failure;
    observed.hit_step_limit = observed.steps >= kStepLimit && !observed.client_complete &&
                              !observed.client_failed && !observed.server_failed;
    return observed;
}

ObservingServerResult run_observing_http09_server(const coquic::quic::Http09RuntimeConfig &config) {
    ObservingServerResult observed;
    constexpr std::size_t kTimerSpinLimit = 100000;

    const int socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        return observed;
    }
    ScopedFd socket_guard(socket_fd);

    sockaddr_in bind_address{};
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons(config.port);
    if (::inet_pton(AF_INET, config.host.c_str(), &bind_address.sin_addr) != 1) {
        return observed;
    }
    if (::bind(socket_fd, reinterpret_cast<const sockaddr *>(&bind_address),
               sizeof(bind_address)) != 0) {
        return observed;
    }

    struct Session {
        coquic::quic::QuicHttp09ServerEndpoint endpoint;
        coquic::quic::QuicCore core;
        std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;
        bool endpoint_has_pending_work = false;
        sockaddr_storage peer{};
        socklen_t peer_len = 0;
        std::string local_connection_id_key;
        std::string initial_destination_connection_id_key;
    };

    const auto make_session_core_config = [&](std::uint64_t connection_index) {
        auto core_config = coquic::quic::make_http09_server_core_config(config);
        core_config.source_connection_id =
            make_runtime_connection_id(std::byte{0x53}, connection_index);
        return core_config;
    };

    std::unordered_map<std::string, std::unique_ptr<Session>> sessions;
    std::unordered_map<std::string, std::string> initial_routes;
    std::uint64_t next_connection_index = 1;
    bool saw_peer_activity = false;

    auto earliest_wakeup = [&]() -> std::optional<coquic::quic::QuicCoreTimePoint> {
        std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;
        for (const auto &[key, session] : sessions) {
            (void)key;
            const auto session_next_wakeup = session->next_wakeup;
            if (!session_next_wakeup.has_value()) {
                continue;
            }

            const auto session_wakeup = session_next_wakeup.value();
            if (!next_wakeup.has_value()) {
                next_wakeup = session_wakeup;
                continue;
            }
            if (session_wakeup < next_wakeup.value()) {
                next_wakeup = session_wakeup;
            }
        }
        return next_wakeup;
    };

    auto drive = [&](Session &session, coquic::quic::QuicCoreResult result) -> bool {
        const auto capture_transport_state = [&]() {
            observed.has_pending_application_send =
                session.core.connection_->has_pending_application_send();
            observed.sent_packets =
                session.core.connection_->application_space_.sent_packets.size();
            observed.bytes_in_flight =
                session.core.connection_->congestion_controller_.bytes_in_flight();
            observed.congestion_window =
                session.core.connection_->congestion_controller_.congestion_window();
            observed.has_next_wakeup = session.next_wakeup.has_value();
            observed.queued_stream_bytes = session.core.connection_->total_queued_stream_bytes();
        };

        for (;;) {
            session.next_wakeup = result.next_wakeup;
            capture_transport_state();
            if (result.local_error.has_value()) {
                return false;
            }

            for (const auto &effect : result.effects) {
                if (const auto *event = std::get_if<coquic::quic::QuicCoreStateEvent>(&effect)) {
                    if (event->change == coquic::quic::QuicCoreStateChange::handshake_ready) {
                        ++observed.handshake_ready_events;
                    }
                    continue;
                }

                if (const auto *received =
                        std::get_if<coquic::quic::QuicCoreReceiveStreamData>(&effect)) {
                    observed.request_stream_ids.push_back(received->stream_id);
                    continue;
                }

                const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
                if (send == nullptr) {
                    continue;
                }

                ++observed.sent_datagrams;
                observed.sent_bytes += send->bytes.size();
                const auto *buffer = send->bytes.empty()
                                         ? nullptr
                                         : reinterpret_cast<const void *>(send->bytes.data());
                if (::sendto(socket_fd, buffer, send->bytes.size(), 0,
                             reinterpret_cast<const sockaddr *>(&session.peer),
                             session.peer_len) < 0) {
                    return false;
                }
            }

            auto update = session.endpoint.on_core_result(result, runtime_now());
            if (update.terminal_failure) {
                return false;
            }
            session.endpoint_has_pending_work = update.has_pending_work;

            if (update.core_inputs.empty()) {
                return true;
            }

            result = coquic::quic::test::advance_core_with_inputs(session.core, update.core_inputs,
                                                                  runtime_now());
        }
    };

    auto create_session = [&](const coquic::quic::ConnectionId &initial_destination_connection_id,
                              const sockaddr_storage &peer, socklen_t peer_len) -> Session & {
        auto core_config = make_session_core_config(next_connection_index++);
        const auto local_connection_id_key = connection_id_key(core_config.source_connection_id);
        auto session = std::make_unique<Session>(Session{
            .endpoint = coquic::quic::QuicHttp09ServerEndpoint(
                coquic::quic::QuicHttp09ServerConfig{.document_root = config.document_root}),
            .core = coquic::quic::QuicCore(std::move(core_config)),
            .next_wakeup = std::nullopt,
            .peer = peer,
            .peer_len = peer_len,
            .local_connection_id_key = local_connection_id_key,
            .initial_destination_connection_id_key =
                connection_id_key(initial_destination_connection_id),
        });
        auto *session_ptr = session.get();
        initial_routes.emplace(session_ptr->initial_destination_connection_id_key,
                               local_connection_id_key);
        sessions.emplace(local_connection_id_key, std::move(session));
        return *session_ptr;
    };

    const auto process_inbound_datagram = [&](std::vector<std::byte> inbound,
                                              const sockaddr_storage &source,
                                              socklen_t source_len) -> bool {
        saw_peer_activity = true;
        ++observed.inbound_datagrams;

        const auto parsed = parse_server_datagram_for_routing(inbound);
        if (!parsed.has_value()) {
            return true;
        }

        const auto destination_connection_id_key =
            connection_id_key(parsed->destination_connection_id);
        auto session_it = sessions.find(destination_connection_id_key);
        if (session_it == sessions.end() &&
            parsed->kind == ParsedServerDatagram::Kind::supported_initial) {
            const auto initial_it = initial_routes.find(destination_connection_id_key);
            if (initial_it != initial_routes.end()) {
                session_it = sessions.find(initial_it->second);
            }
        }

        if (session_it == sessions.end()) {
            if (parsed->kind != ParsedServerDatagram::Kind::supported_initial) {
                return true;
            }
            auto &session = create_session(parsed->destination_connection_id, source, source_len);
            return drive(session, session.core.advance(
                                      coquic::quic::QuicCoreInboundDatagram{
                                          .bytes = std::move(inbound),
                                      },
                                      runtime_now()));
        }

        session_it->second->peer = source;
        session_it->second->peer_len = source_len;
        return drive(*session_it->second, session_it->second->core.advance(
                                              coquic::quic::QuicCoreInboundDatagram{
                                                  .bytes = std::move(inbound),
                                              },
                                              runtime_now()));
    };

    const auto drain_ready_datagrams = [&]() -> bool {
        while (true) {
            std::vector<std::byte> inbound(65535);
            sockaddr_storage source{};
            socklen_t source_len = sizeof(source);
            ssize_t bytes_read = 0;
            do {
                bytes_read = ::recvfrom(socket_fd, inbound.data(), inbound.size(), MSG_DONTWAIT,
                                        reinterpret_cast<sockaddr *>(&source), &source_len);
            } while (bytes_read < 0 && errno == EINTR);

            if (bytes_read < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return true;
                }
                return false;
            }

            inbound.resize(static_cast<std::size_t>(bytes_read));
            if (!process_inbound_datagram(std::move(inbound), source, source_len)) {
                return false;
            }
        }
    };

    const auto pump_endpoint_work_once = [&]() -> bool {
        for (const auto &[key, session] : sessions) {
            (void)key;
            if (!session->endpoint_has_pending_work) {
                continue;
            }

            auto update = session->endpoint.poll(runtime_now());
            if (update.terminal_failure) {
                return false;
            }

            session->endpoint_has_pending_work = update.has_pending_work;
            if (update.core_inputs.empty()) {
                continue;
            }

            auto result = coquic::quic::test::advance_core_with_inputs(
                session->core, update.core_inputs, runtime_now());
            if (!drive(*session, std::move(result))) {
                return false;
            }
        }
        return true;
    };

    for (;;) {
        if (!drain_ready_datagrams()) {
            return observed;
        }
        if (!pump_endpoint_work_once()) {
            return observed;
        }

        int timeout_ms = 1000;
        const auto next_wakeup = earliest_wakeup();
        if (next_wakeup.has_value()) {
            const auto current = runtime_now();
            if (*next_wakeup <= current) {
                for (const auto &[key, session] : sessions) {
                    (void)key;
                    const auto session_next_wakeup = session->next_wakeup;
                    if (!session_next_wakeup.has_value()) {
                        continue;
                    }

                    if (session_next_wakeup.value() > current) {
                        continue;
                    }
                    ++observed.timer_expirations;
                    if (observed.timer_expirations >= kTimerSpinLimit) {
                        observed.exit_code = 2;
                        return observed;
                    }
                    if (!drive(*session, session->core.advance(coquic::quic::QuicCoreTimerExpired{},
                                                               current))) {
                        return observed;
                    }
                }
                continue;
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
        descriptor.fd = socket_fd;
        descriptor.events = POLLIN;

        int poll_result = 0;
        do {
            poll_result = ::poll(&descriptor, 1, timeout_ms);
        } while (poll_result < 0 && errno == EINTR);

        if (poll_result < 0) {
            return observed;
        }
        if (poll_result == 0) {
            if (next_wakeup.has_value()) {
                const auto current = runtime_now();
                for (const auto &[key, session] : sessions) {
                    (void)key;
                    const auto session_next_wakeup = session->next_wakeup;
                    if (!session_next_wakeup.has_value()) {
                        continue;
                    }

                    if (session_next_wakeup.value() > current) {
                        continue;
                    }
                    ++observed.timer_expirations;
                    if (observed.timer_expirations >= kTimerSpinLimit) {
                        observed.exit_code = 2;
                        return observed;
                    }
                    if (!drive(*session, session->core.advance(coquic::quic::QuicCoreTimerExpired{},
                                                               current))) {
                        return observed;
                    }
                }
                continue;
            }

            observed.exit_code = saw_peer_activity ? 0 : 1;
            return observed;
        }
        if ((descriptor.revents & POLLIN) == 0) {
            return observed;
        }
        if (!drain_ready_datagrams()) {
            return observed;
        }
    }
}

TEST(QuicHttp09RuntimeTest, ClientAndServerTransferSingleFileOverUdpSockets) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-over-udp");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/hello.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-over-udp");
}

TEST(QuicHttp09RuntimeTest, InMemoryClientAndServerTransferLargeFile) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    constexpr std::size_t kLargeBodyBytes = 2ULL * 1024ULL * 1024ULL;
    const std::string large_body(kLargeBodyBytes, 'L');
    document_root.write_file("large.bin", large_body);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/large.bin",
    };

    const auto result = run_in_memory_http09_transfer({
        .client_config = client,
        .server_config = server,
    });

    EXPECT_TRUE(result.client_complete)
        << "steps=" << result.steps << " hit_step_limit=" << result.hit_step_limit
        << " client_failed=" << result.client_failed << " server_failed=" << result.server_failed
        << " client_sent_datagrams=" << result.client_sent_datagrams
        << " client_sent_bytes=" << result.client_sent_bytes
        << " server_sent_datagrams=" << result.server_sent_datagrams
        << " server_sent_bytes=" << result.server_sent_bytes
        << " client_bytes_in_flight=" << result.client_bytes_in_flight
        << " server_bytes_in_flight=" << result.server_bytes_in_flight
        << " client_cwnd=" << result.client_congestion_window
        << " server_cwnd=" << result.server_congestion_window
        << " client_queued_bytes=" << result.client_queued_stream_bytes
        << " server_queued_bytes=" << result.server_queued_stream_bytes
        << " client_next_wakeup=" << result.client_has_next_wakeup
        << " server_next_wakeup=" << result.server_has_next_wakeup;
    EXPECT_FALSE(result.client_failed);
    EXPECT_FALSE(result.server_failed);
    EXPECT_EQ(read_file_bytes(download_root.path() / "large.bin"), large_body);
}

TEST(QuicHttp09RuntimeTest, InMemoryClientAndServerTransferMediumFile) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    constexpr std::size_t kMediumBodyBytes = 256ULL * 1024ULL;
    const std::string body(kMediumBodyBytes, 'M');
    document_root.write_file("medium.bin", body);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/medium.bin",
    };

    const auto result = run_in_memory_http09_transfer({
        .client_config = client,
        .server_config = server,
    });

    EXPECT_TRUE(result.client_complete)
        << "steps=" << result.steps << " hit_step_limit=" << result.hit_step_limit
        << " client_failed=" << result.client_failed << " server_failed=" << result.server_failed
        << " client_sent_datagrams=" << result.client_sent_datagrams
        << " client_sent_bytes=" << result.client_sent_bytes
        << " server_sent_datagrams=" << result.server_sent_datagrams
        << " server_sent_bytes=" << result.server_sent_bytes
        << " client_bytes_in_flight=" << result.client_bytes_in_flight
        << " server_bytes_in_flight=" << result.server_bytes_in_flight
        << " client_cwnd=" << result.client_congestion_window
        << " server_cwnd=" << result.server_congestion_window
        << " client_queued_bytes=" << result.client_queued_stream_bytes
        << " server_queued_bytes=" << result.server_queued_stream_bytes
        << " client_next_wakeup=" << result.client_has_next_wakeup
        << " server_next_wakeup=" << result.server_has_next_wakeup;
    EXPECT_FALSE(result.client_failed);
    EXPECT_FALSE(result.server_failed);
    EXPECT_EQ(read_file_bytes(download_root.path() / "medium.bin"), body);
}

TEST(QuicHttp09RuntimeTest, ClientAndServerTransferLargeFileOverUdpSockets) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    constexpr std::size_t kLargeBodyBytes = 2ULL * 1024ULL * 1024ULL;
    const std::string large_body(kLargeBodyBytes, 'L');
    document_root.write_file("large.bin", large_body);

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/large.bin",
    };

    auto server_future =
        std::async(std::launch::async, [&server]() { return run_observing_http09_server(server); });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const auto client_exit = coquic::quic::run_http09_runtime(client);
    ASSERT_EQ(server_future.wait_for(std::chrono::seconds(15)), std::future_status::ready);
    const auto server_result = server_future.get();

    EXPECT_EQ(client_exit, 0) << "server_inbound=" << server_result.inbound_datagrams
                              << " server_timers=" << server_result.timer_expirations
                              << " server_sent_datagrams=" << server_result.sent_datagrams
                              << " server_sent_bytes=" << server_result.sent_bytes
                              << " server_pending=" << server_result.has_pending_application_send
                              << " server_sent_packets=" << server_result.sent_packets
                              << " server_bytes_in_flight=" << server_result.bytes_in_flight
                              << " server_cwnd=" << server_result.congestion_window
                              << " server_next_wakeup=" << server_result.has_next_wakeup
                              << " server_queued_bytes=" << server_result.queued_stream_bytes;
    EXPECT_EQ(server_result.exit_code, 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "large.bin"), large_body);
}

TEST(QuicHttp09RuntimeTest, ClientDerivesPeerAddressAndServerNameFromRequests) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-from-request-authority");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .port = 443,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .server_name = "",
        .requests_env = "https://localhost:" + std::to_string(port) + "/hello.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-from-request-authority");
}

TEST(QuicHttp09RuntimeTest, ServerDoesNotExitAfterMalformedTraffic) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int client_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(client_fd, 0);
    ScopedFd client_socket(client_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    const std::array<std::byte, 4> garbage = {
        std::byte{0xde},
        std::byte{0xad},
        std::byte{0xbe},
        std::byte{0xef},
    };
    ASSERT_GE(::sendto(client_socket.get(), garbage.data(), garbage.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(1500)).has_value());
}

TEST(QuicHttp09RuntimeTest, ServerFailsFastWhenTlsFilesMissing) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "/no/such/cert.pem",
        .private_key_path = "/no/such/key.pem",
    };

    auto server_process = launch_runtime_server_process(server);
    const auto status = server_process.wait_for_exit(std::chrono::milliseconds(250));
    if (!status.has_value()) {
        FAIL() << "expected child process to exit quickly";
    }
    const auto process_status = *status;
    ASSERT_TRUE(WIFEXITED(process_status));
    EXPECT_EQ(WEXITSTATUS(process_status), 1);
}

TEST(QuicHttp09RuntimeTest, TransferCaseUsesSingleConnectionAndMultipleStreams) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("alpha.txt", "alpha-bytes");
    document_root.write_file("beta.txt", "beta-bytes");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/alpha.txt https://localhost/beta.txt",
    };

    auto server_future =
        std::async(std::launch::async, [&server]() { return run_observing_http09_server(server); });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    ASSERT_EQ(server_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto server_result = server_future.get();
    EXPECT_EQ(server_result.exit_code, 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");

    std::sort(server_result.request_stream_ids.begin(), server_result.request_stream_ids.end());
    server_result.request_stream_ids.erase(std::unique(server_result.request_stream_ids.begin(),
                                                       server_result.request_stream_ids.end()),
                                           server_result.request_stream_ids.end());
    EXPECT_EQ(server_result.handshake_ready_events, 1u);
    EXPECT_EQ(server_result.request_stream_ids, (std::vector<std::uint64_t>{0u, 4u}));
}

TEST(QuicHttp09RuntimeTest, MulticonnectCaseUsesSeparateConnectionPerRequest) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("alpha.txt", "alpha-bytes");
    document_root.write_file("beta.txt", "beta-bytes");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::multiconnect,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::multiconnect,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/alpha.txt https://localhost/beta.txt",
    };

    auto server_future =
        std::async(std::launch::async, [&server]() { return run_observing_http09_server(server); });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    ASSERT_EQ(server_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto server_result = server_future.get();
    EXPECT_EQ(server_result.exit_code, 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");

    std::sort(server_result.request_stream_ids.begin(), server_result.request_stream_ids.end());
    server_result.request_stream_ids.erase(std::unique(server_result.request_stream_ids.begin(),
                                                       server_result.request_stream_ids.end()),
                                           server_result.request_stream_ids.end());
    EXPECT_EQ(server_result.handshake_ready_events, 2u);
    EXPECT_EQ(server_result.request_stream_ids, (std::vector<std::uint64_t>{0u}));
}

TEST(QuicHttp09RuntimeTest, RuntimeBuildsCoreConfigWithInteropAlpnAndRunnerDefaults) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "transfer");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt https://localhost/b.txt");
    ScopedEnvVar host("HOST", std::nullopt);
    ScopedEnvVar port("PORT", std::nullopt);
    ScopedEnvVar document_root("DOCUMENT_ROOT", std::nullopt);
    ScopedEnvVar download_root("DOWNLOAD_ROOT", std::nullopt);
    ScopedEnvVar certificate("CERTIFICATE_CHAIN_PATH", std::nullopt);
    ScopedEnvVar private_key("PRIVATE_KEY_PATH", std::nullopt);

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    if (!parsed.has_value()) {
        FAIL() << "expected runtime config";
    }
    const auto &runtime = *parsed;
    EXPECT_EQ(runtime.mode, coquic::quic::Http09RuntimeMode::client);
    EXPECT_TRUE(runtime.host.empty());
    EXPECT_TRUE(runtime.server_name.empty());
    EXPECT_EQ(runtime.application_protocol, "hq-interop");
    EXPECT_EQ(runtime.document_root, std::filesystem::path("/www"));
    EXPECT_EQ(runtime.download_root, std::filesystem::path("/downloads"));
    EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/certs/cert.pem"));
    EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/certs/priv.key"));

    auto overridden_runtime = runtime;
    overridden_runtime.application_protocol = "not-hq-interop";

    const auto client_core = coquic::quic::make_http09_client_core_config(overridden_runtime);
    EXPECT_EQ(client_core.application_protocol, "hq-interop");
    EXPECT_EQ(client_core.transport.initial_max_data, 32u * 1024u * 1024u);
    EXPECT_EQ(client_core.transport.initial_max_stream_data_bidi_local, 16u * 1024u * 1024u);
    EXPECT_EQ(client_core.transport.initial_max_stream_data_bidi_remote, 256u * 1024u);

    auto server_runtime = overridden_runtime;
    server_runtime.mode = coquic::quic::Http09RuntimeMode::server;
    server_runtime.certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    server_runtime.private_key_path = "tests/fixtures/quic-server-key.pem";
    const auto server_core = coquic::quic::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.application_protocol, "hq-interop");
    if (!server_core.identity.has_value()) {
        FAIL() << "expected server identity";
    }
    const auto &identity = *server_core.identity;
    EXPECT_EQ(identity.certificate_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-cert.pem"));
    EXPECT_EQ(identity.private_key_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-key.pem"));
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialMulticonnectTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "multiconnect");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt https://localhost/b.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
}

TEST(QuicHttp09RuntimeTest, ServerRespondsToUnsupportedVersionProbeAndStillTransfersFile) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-after-version-negotiation");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/hello.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int probe_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe_fd, 0);
    ScopedFd probe_socket(probe_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    const auto probe = make_unsupported_version_probe();
    ASSERT_GE(::sendto(probe_socket.get(), probe.data(), probe.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    pollfd descriptor{};
    descriptor.fd = probe_socket.get();
    descriptor.events = POLLIN;
    ASSERT_EQ(::poll(&descriptor, 1, 1000), 1);
    ASSERT_NE((descriptor.revents & POLLIN), 0);

    std::vector<std::byte> response(65535);
    const auto response_size =
        ::recvfrom(probe_socket.get(), response.data(), response.size(), 0, nullptr, nullptr);
    ASSERT_GT(response_size, 0);
    response.resize(static_cast<std::size_t>(response_size));

    const auto decoded = coquic::quic::deserialize_packet(response, {});
    ASSERT_TRUE(decoded.has_value());
    ASSERT_NE(std::get_if<coquic::quic::VersionNegotiationPacket>(&decoded.value().packet),
              nullptr);
    const auto &version_negotiation =
        std::get<coquic::quic::VersionNegotiationPacket>(decoded.value().packet);
    EXPECT_EQ(version_negotiation.destination_connection_id, (coquic::quic::ConnectionId{
                                                                 std::byte{0xc1},
                                                                 std::byte{0x01},
                                                                 std::byte{0x12},
                                                                 std::byte{0x23},
                                                                 std::byte{0x34},
                                                                 std::byte{0x45},
                                                                 std::byte{0x56},
                                                                 std::byte{0x67},
                                                             }));
    EXPECT_EQ(version_negotiation.source_connection_id, (coquic::quic::ConnectionId{
                                                            std::byte{0x83},
                                                            std::byte{0x94},
                                                            std::byte{0xc8},
                                                            std::byte{0xf0},
                                                            std::byte{0x3e},
                                                            std::byte{0x51},
                                                            std::byte{0x57},
                                                            std::byte{0x08},
                                                        }));
    EXPECT_NE(std::find(version_negotiation.supported_versions.begin(),
                        version_negotiation.supported_versions.end(), 1u),
              version_negotiation.supported_versions.end());

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"),
              "hello-after-version-negotiation");
}

TEST(QuicHttp09RuntimeTest, HandshakeCaseNeverEmitsRetryPackets) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process = launch_runtime_server_process(server_runtime);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int client_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(client_fd, 0);
    ScopedFd client_socket_guard(client_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    auto client_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .requests_env = "https://localhost/hello.txt",
    };
    coquic::quic::QuicCore client(coquic::quic::make_http09_client_core_config(client_runtime));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto client_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(client_datagrams.empty());
    for (const auto &datagram : client_datagrams) {
        ASSERT_GE(::sendto(client_fd, datagram.data(), datagram.size(), 0,
                           reinterpret_cast<const sockaddr *>(&server_address),
                           sizeof(server_address)),
                  0);
    }

    std::vector<std::vector<std::byte>> server_datagrams;
    for (int i = 0; i < 32; ++i) {
        pollfd descriptor{};
        descriptor.fd = client_fd;
        descriptor.events = POLLIN;
        const int poll_result = ::poll(&descriptor, 1, 250);
        ASSERT_GE(poll_result, 0);
        if (poll_result == 0) {
            if (client.is_handshake_complete()) {
                break;
            }
            continue;
        }
        ASSERT_NE((descriptor.revents & POLLIN), 0);

        std::vector<std::byte> buffer(65535);
        const auto bytes_read =
            ::recvfrom(client_fd, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        ASSERT_GT(bytes_read, 0);
        buffer.resize(static_cast<std::size_t>(bytes_read));
        server_datagrams.push_back(std::move(buffer));

        auto step =
            client.advance(coquic::quic::QuicCoreInboundDatagram{.bytes = server_datagrams.back()},
                           coquic::quic::test::test_time(i + 1));
        const auto response_datagrams = coquic::quic::test::send_datagrams_from(step);
        for (const auto &datagram : response_datagrams) {
            ASSERT_GE(::sendto(client_fd, datagram.data(), datagram.size(), 0,
                               reinterpret_cast<const sockaddr *>(&server_address),
                               sizeof(server_address)),
                      0);
        }
    }

    std::vector<std::vector<std::byte>> long_header_datagrams;
    for (const auto &datagram : server_datagrams) {
        if (!has_long_header(datagram)) {
            continue;
        }
        long_header_datagrams.push_back(datagram);
    }

    ASSERT_FALSE(long_header_datagrams.empty());
    for (const auto &datagram : long_header_datagrams) {
        EXPECT_FALSE(first_header_is_retry_packet(datagram));
    }

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

} // namespace
