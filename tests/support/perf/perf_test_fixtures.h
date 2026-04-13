#pragma once

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/perf/perf_runtime.h"
#include "tests/support/quic_test_utils.h"

namespace coquic::perf::test_support {

class ScopedFd {
  public:
    explicit ScopedFd(int fd) : fd_(fd) {
    }
    ~ScopedFd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    int get() const {
        return fd_;
    }

  private:
    int fd_ = -1;
};

inline std::uint16_t allocate_udp_loopback_port() {
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

class ScopedPerfProcess {
  public:
    explicit ScopedPerfProcess(const QuicPerfConfig &config) {
        pid_ = ::fork();
        if (pid_ == 0) {
            _exit(run_perf_runtime(config));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }

    ~ScopedPerfProcess() {
        terminate();
    }

    ScopedPerfProcess(const ScopedPerfProcess &) = delete;
    ScopedPerfProcess &operator=(const ScopedPerfProcess &) = delete;

    std::optional<int> wait_for_exit(std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            int status = 0;
            const pid_t waited = ::waitpid(pid_, &status, WNOHANG);
            if (waited == pid_) {
                pid_ = -1;
                if (WIFEXITED(status)) {
                    return WEXITSTATUS(status);
                }
                return std::nullopt;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        return std::nullopt;
    }

    void terminate() {
        if (pid_ <= 0) {
            return;
        }
        ::kill(pid_, SIGTERM);
        int status = 0;
        ::waitpid(pid_, &status, 0);
        pid_ = -1;
    }

  private:
    pid_t pid_ = -1;
};

inline std::string read_result_text(const std::filesystem::path &path) {
    return quic::test::read_text_file(path);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline std::optional<std::uint64_t> json_u64_field(std::string_view json, std::string_view key) {
    const std::string needle = std::string{"\""} + std::string{key} + "\":";
    const auto pos = json.rfind(needle);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    const auto start = pos + needle.size();
    const auto *begin = json.data() + start;
    const auto *end = json.data() + json.size();
    const auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{}) {
        return std::nullopt;
    }
    return value;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline std::optional<std::uint64_t> json_u64_field_in_object(std::string_view json,
                                                             std::string_view object_key,
                                                             std::string_view field_key) {
    const std::string object_needle = std::string{"\""} + std::string{object_key} + "\":{";
    const auto object_pos = json.find(object_needle);
    if (object_pos == std::string_view::npos) {
        return std::nullopt;
    }

    const auto object_start = object_pos + object_needle.size();
    const auto object_end = json.find('}', object_start);
    if (object_end == std::string_view::npos) {
        return std::nullopt;
    }

    const std::string field_needle = std::string{"\""} + std::string{field_key} + "\":";
    const auto field_pos = json.find(field_needle, object_start);
    if (field_pos == std::string_view::npos || field_pos > object_end) {
        return std::nullopt;
    }

    std::uint64_t value = 0;
    const auto start = field_pos + field_needle.size();
    const auto *begin = json.data() + start;
    const auto *end = json.data() + object_end;
    const auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{}) {
        return std::nullopt;
    }
    return value;
}

} // namespace coquic::perf::test_support
