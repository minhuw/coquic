#pragma once

#include <algorithm>
#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <atomic>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <utility>
#include <vector>

#include "src/quic/packet.h"
#define private public
#include "src/http09/http09_runtime.h"
#include "src/quic/connection.h"
#undef private
#include "src/http09/http09_runtime_test_hooks.h"
#include "tests/support/quic_test_utils.h"

namespace coquic::http09::test_support {

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

template <typename T> T optional_value_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return *value;
}

template <typename T> const T &optional_ref_or_terminate(const std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return *value;
}

template <typename T> T &optional_ref_or_terminate(std::optional<T> &value) {
    if (!value.has_value()) {
        std::abort();
    }
    return *value;
}

inline coquic::http09::Http09RuntimeMode invalid_runtime_mode() {
    constexpr std::uint8_t raw = 0xff;
    coquic::http09::Http09RuntimeMode mode{};
    std::memcpy(&mode, &raw, sizeof(raw));
    return mode;
}

inline thread_local std::atomic<bool> *g_runtime_server_stop_requested = nullptr;

class ScopedRuntimeServerStopFlag {
  public:
    explicit ScopedRuntimeServerStopFlag(std::atomic<bool> &stop_requested)
        : previous_(g_runtime_server_stop_requested) {
        g_runtime_server_stop_requested = &stop_requested;
    }

    ~ScopedRuntimeServerStopFlag() {
        g_runtime_server_stop_requested = previous_;
    }

    ScopedRuntimeServerStopFlag(const ScopedRuntimeServerStopFlag &) = delete;
    ScopedRuntimeServerStopFlag &operator=(const ScopedRuntimeServerStopFlag &) = delete;

  private:
    std::atomic<bool> *previous_ = nullptr;
};

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline int stoppable_poll(pollfd *descriptors, nfds_t descriptor_count, int timeout_ms) {
    if (g_runtime_server_stop_requested != nullptr && g_runtime_server_stop_requested->load()) {
        errno = ECANCELED;
        return -1;
    }

    int bounded_timeout_ms = timeout_ms;
    if (bounded_timeout_ms < 0 || bounded_timeout_ms > 50) {
        bounded_timeout_ms = 50;
    }

    int poll_result = 0;
    do {
        poll_result = ::poll(descriptors, descriptor_count, bounded_timeout_ms);
    } while (
        poll_result < 0 && errno == EINTR &&
        (g_runtime_server_stop_requested == nullptr || !g_runtime_server_stop_requested->load()));

    if (g_runtime_server_stop_requested != nullptr && g_runtime_server_stop_requested->load()) {
        errno = ECANCELED;
        return -1;
    }
    return poll_result;
}

inline void wake_runtime_server(std::string_view host, std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return;
    }
    ScopedFd socket_guard(fd);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, std::string(host).c_str(), &address.sin_addr) != 1) {
        return;
    }

    const std::array<std::byte, 1> wakeup = {std::byte{0x00}};
    ::sendto(fd, wakeup.data(), wakeup.size(), 0, reinterpret_cast<const sockaddr *>(&address),
             sizeof(address));
}

inline int run_http09_runtime_child_process(
    const coquic::http09::Http09RuntimeConfig &config,
    const std::shared_ptr<std::atomic<bool>> &stop_requested,
    coquic::io::test::SocketIoBackendOpsOverride override_ops) noexcept {
    try {
        ScopedRuntimeServerStopFlag stop_flag(*stop_requested);
        if (override_ops.poll_fn == nullptr) {
            override_ops.poll_fn = &stoppable_poll;
        }
        const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
            override_ops,
        };
        return coquic::http09::run_http09_runtime(config);
    } catch (...) {
        std::abort();
    }
}

class ScopedChildProcess {
  public:
    explicit ScopedChildProcess(const coquic::http09::Http09RuntimeConfig &config,
                                coquic::io::test::SocketIoBackendOpsOverride override_ops = {})
        : host_(config.host), port_(config.port),
          stop_requested_(std::make_shared<std::atomic<bool>>(false)),
          future_(std::async(std::launch::async, run_http09_runtime_child_process, config,
                             stop_requested_, override_ops)) {
    }

    ~ScopedChildProcess() {
        terminate();
    }

    ScopedChildProcess(const ScopedChildProcess &) = delete;
    ScopedChildProcess &operator=(const ScopedChildProcess &) = delete;

    std::optional<int> wait_for_exit(std::chrono::milliseconds timeout) {
        if (cached_status_.has_value()) {
            return cached_status_;
        }
        if (!future_.valid()) {
            return std::nullopt;
        }
        if (future_.wait_for(timeout) != std::future_status::ready) {
            return std::nullopt;
        }

        cached_status_ = W_EXITCODE(future_.get(), 0);
        return cached_status_;
    }

    void terminate() {
        if (cached_status_.has_value() || !future_.valid()) {
            return;
        }

        stop_requested_->store(true);
        wake_runtime_server(host_, port_);
        if (future_.wait_for(std::chrono::seconds(5)) == std::future_status::ready) {
            cached_status_ = W_EXITCODE(future_.get(), 0);
            return;
        }
    }

  private:
    std::string host_;
    std::uint16_t port_ = 0;
    std::shared_ptr<std::atomic<bool>> stop_requested_;
    std::future<int> future_;
    std::optional<int> cached_status_;
};

inline int fail_socket(int, int, int) {
    errno = EMFILE;
    return -1;
}

inline int fail_bind(int, const sockaddr *, socklen_t) {
    errno = EADDRINUSE;
    return -1;
}

inline int fail_getaddrinfo(const char *, const char *, const addrinfo *, addrinfo **results) {
    if (results != nullptr) {
        *results = nullptr;
    }
    return EAI_NONAME;
}

inline thread_local int g_freeaddrinfo_calls = 0;
inline thread_local int g_last_socket_family = AF_UNSPEC;
inline thread_local int g_last_getaddrinfo_family = AF_UNSPEC;

struct ServerSocketPollTrace {
    int next_socket_fd = 700;
    std::vector<int> opened_sockets;
    std::vector<std::uint16_t> bound_ports;
    std::vector<nfds_t> poll_descriptor_counts;
};

inline thread_local ServerSocketPollTrace g_server_socket_poll_trace;

inline int missing_results_getaddrinfo(const char *, const char *, const addrinfo *hints,
                                       addrinfo **results) {
    if (results == nullptr || hints == nullptr) {
        return EAI_FAIL;
    }

    *results = nullptr;
    g_last_getaddrinfo_family = hints->ai_family;
    return 0;
}

class ScopedFreeaddrinfoCounterReset {
  public:
    ScopedFreeaddrinfoCounterReset() {
        g_freeaddrinfo_calls = 0;
    }

    ~ScopedFreeaddrinfoCounterReset() {
        g_freeaddrinfo_calls = 0;
    }

    ScopedFreeaddrinfoCounterReset(const ScopedFreeaddrinfoCounterReset &) = delete;
    ScopedFreeaddrinfoCounterReset &operator=(const ScopedFreeaddrinfoCounterReset &) = delete;
};

class ScopedRuntimeAddressFamilyReset {
  public:
    ScopedRuntimeAddressFamilyReset() {
        g_last_socket_family = AF_UNSPEC;
        g_last_getaddrinfo_family = AF_UNSPEC;
    }

    ~ScopedRuntimeAddressFamilyReset() {
        g_last_socket_family = AF_UNSPEC;
        g_last_getaddrinfo_family = AF_UNSPEC;
    }

    ScopedRuntimeAddressFamilyReset(const ScopedRuntimeAddressFamilyReset &) = delete;
    ScopedRuntimeAddressFamilyReset &operator=(const ScopedRuntimeAddressFamilyReset &) = delete;
};

class ScopedServerSocketPollTraceReset {
  public:
    ScopedServerSocketPollTraceReset() {
        g_server_socket_poll_trace = {};
    }

    ~ScopedServerSocketPollTraceReset() {
        g_server_socket_poll_trace = {};
    }

    ScopedServerSocketPollTraceReset(const ScopedServerSocketPollTraceReset &) = delete;
    ScopedServerSocketPollTraceReset &operator=(const ScopedServerSocketPollTraceReset &) = delete;
};

inline int fail_getaddrinfo_with_results(const char *, const char *, const addrinfo *,
                                         addrinfo **results) {
    if (results == nullptr) {
        return EAI_FAIL;
    }

    auto *address = new sockaddr_in{};
    address->sin_family = AF_INET;

    auto *result = new addrinfo{};
    result->ai_family = AF_INET;
    result->ai_socktype = SOCK_DGRAM;
    result->ai_protocol = IPPROTO_UDP;
    result->ai_addrlen = sizeof(sockaddr_in);
    result->ai_addr = reinterpret_cast<sockaddr *>(address);

    *results = result;
    return EAI_FAIL;
}

inline int record_socket_family_then_fail(int family, int, int) {
    g_last_socket_family = family;
    errno = EMFILE;
    return -1;
}

inline int record_server_socket_then_succeed(int, int, int) {
    const int fd = g_server_socket_poll_trace.next_socket_fd++;
    g_server_socket_poll_trace.opened_sockets.push_back(fd);
    return fd;
}

inline int record_server_bind_then_succeed(int, const sockaddr *address, socklen_t address_len) {
    if (address != nullptr && address->sa_family == AF_INET &&
        address_len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(address);
        g_server_socket_poll_trace.bound_ports.push_back(ntohs(ipv4->sin_port));
    } else if (address != nullptr && address->sa_family == AF_INET6 &&
               address_len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(address);
        g_server_socket_poll_trace.bound_ports.push_back(ntohs(ipv6->sin6_port));
    }
    return 0;
}

inline int ipv6_only_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
                                 addrinfo **results) {
    if (results == nullptr) {
        return EAI_FAIL;
    }
    *results = nullptr;
    if (hints == nullptr) {
        return EAI_FAIL;
    }

    g_last_getaddrinfo_family = hints->ai_family;
    if (node == nullptr || std::string_view(node) != "::1" || service == nullptr ||
        std::string_view(service) != "9443") {
        return EAI_NONAME;
    }
    if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET6) {
        return EAI_ADDRFAMILY;
    }
    if (hints->ai_socktype != SOCK_DGRAM || hints->ai_protocol != IPPROTO_UDP) {
        return EAI_SOCKTYPE;
    }

    auto *address = new sockaddr_in6{};
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(9443);
    address->sin6_addr = in6addr_loopback;

    auto *result = new addrinfo{};
    result->ai_family = AF_INET6;
    result->ai_socktype = SOCK_DGRAM;
    result->ai_protocol = IPPROTO_UDP;
    result->ai_addrlen = sizeof(sockaddr_in6);
    result->ai_addr = reinterpret_cast<sockaddr *>(address);

    *results = result;
    return 0;
}

inline void counting_freeaddrinfo(addrinfo *results) {
    ++g_freeaddrinfo_calls;
    while (results != nullptr) {
        auto *next = results->ai_next;
        if (results->ai_addr != nullptr) {
            if (results->ai_family == AF_INET6) {
                delete reinterpret_cast<sockaddr_in6 *>(results->ai_addr);
            } else {
                delete reinterpret_cast<sockaddr_in *>(results->ai_addr);
            }
        }
        delete results;
        results = next;
    }
}

inline addrinfo *make_ipv4_addrinfo_result(std::string_view ip, std::uint16_t port) {
    auto *address = new sockaddr_in{};
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (::inet_pton(AF_INET, std::string(ip).c_str(), &address->sin_addr) != 1) {
        delete address;
        return nullptr;
    }

    auto *result = new addrinfo{};
    result->ai_family = AF_INET;
    result->ai_socktype = SOCK_DGRAM;
    result->ai_protocol = IPPROTO_UDP;
    result->ai_addrlen = sizeof(sockaddr_in);
    result->ai_addr = reinterpret_cast<sockaddr *>(address);
    return result;
}

inline addrinfo *make_ipv6_addrinfo_result(std::string_view ip, std::uint16_t port) {
    auto *address = new sockaddr_in6{};
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(port);
    if (::inet_pton(AF_INET6, std::string(ip).c_str(), &address->sin6_addr) != 1) {
        delete address;
        return nullptr;
    }

    auto *result = new addrinfo{};
    result->ai_family = AF_INET6;
    result->ai_socktype = SOCK_DGRAM;
    result->ai_protocol = IPPROTO_UDP;
    result->ai_addrlen = sizeof(sockaddr_in6);
    result->ai_addr = reinterpret_cast<sockaddr *>(address);
    return result;
}

inline int prefer_ipv4_mixed_getaddrinfo(const char *node, const char *service,
                                         const addrinfo *hints, addrinfo **results) {
    if (results == nullptr || hints == nullptr || node == nullptr || service == nullptr) {
        return EAI_FAIL;
    }
    *results = nullptr;

    g_last_getaddrinfo_family = hints->ai_family;
    if (std::string_view(node) != "localhost" || std::string_view(service) != "443") {
        return EAI_NONAME;
    }

    auto *ipv6 = make_ipv6_addrinfo_result("::1", 443);
    auto *ipv4 = make_ipv4_addrinfo_result("127.0.0.1", 443);
    if (ipv6 == nullptr || ipv4 == nullptr) {
        counting_freeaddrinfo(ipv6);
        counting_freeaddrinfo(ipv4);
        return EAI_FAIL;
    }

    ipv6->ai_next = ipv4;
    *results = ipv6;
    return 0;
}

inline int hostname_ipv6_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
                                     addrinfo **results) {
    if (results == nullptr || hints == nullptr || node == nullptr || service == nullptr) {
        return EAI_FAIL;
    }
    *results = nullptr;

    g_last_getaddrinfo_family = hints->ai_family;
    if (std::string_view(node) != "interop-server-host" || std::string_view(service) != "444") {
        return EAI_NONAME;
    }
    if (hints->ai_family != AF_INET6) {
        return EAI_ADDRFAMILY;
    }
    if (hints->ai_flags != AI_NUMERICSERV) {
        return EAI_BADFLAGS;
    }

    auto *ipv6 = make_ipv6_addrinfo_result("2001:db8::9", 444);
    if (ipv6 == nullptr) {
        return EAI_FAIL;
    }

    *results = ipv6;
    return 0;
}

inline int fallback_to_earlier_valid_result_getaddrinfo(const char *node, const char *service,
                                                        const addrinfo *hints, addrinfo **results) {
    if (results == nullptr || hints == nullptr || node == nullptr || service == nullptr) {
        return EAI_FAIL;
    }
    *results = nullptr;

    g_last_getaddrinfo_family = hints->ai_family;
    if (std::string_view(node) != "localhost" || std::string_view(service) != "443") {
        return EAI_NONAME;
    }

    auto *ipv6 = make_ipv6_addrinfo_result("::1", 443);
    auto *ipv4 = make_ipv4_addrinfo_result("127.0.0.1", 443);
    if (ipv6 == nullptr || ipv4 == nullptr) {
        counting_freeaddrinfo(ipv6);
        counting_freeaddrinfo(ipv4);
        return EAI_FAIL;
    }

    ipv4->ai_addrlen = static_cast<socklen_t>(sizeof(sockaddr_storage) + 1);
    ipv6->ai_next = ipv4;
    *results = ipv6;
    return 0;
}

inline int unsupported_family_getaddrinfo(const char *node, const char *service,
                                          const addrinfo *hints, addrinfo **results) {
    if (results == nullptr || hints == nullptr || node == nullptr || service == nullptr) {
        return EAI_FAIL;
    }
    *results = nullptr;

    if (std::string_view(node) != "localhost" || std::string_view(service) != "443") {
        return EAI_NONAME;
    }

    auto *address = new sockaddr_in{};
    address->sin_family = AF_INET;
    address->sin_port = htons(443);
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    auto *result = new addrinfo{};
    result->ai_family = AF_UNIX;
    result->ai_socktype = SOCK_DGRAM;
    result->ai_protocol = IPPROTO_UDP;
    result->ai_addrlen = sizeof(sockaddr_in);
    result->ai_addr = reinterpret_cast<sockaddr *>(address);
    *results = result;
    return 0;
}

inline int wildcard_ipv4_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
                                     addrinfo **results) {
    if (results == nullptr || hints == nullptr || service == nullptr) {
        return EAI_FAIL;
    }
    *results = nullptr;

    g_last_getaddrinfo_family = hints->ai_family;
    if (node != nullptr || std::string_view(service) != "443") {
        return EAI_NONAME;
    }

    auto *result = make_ipv4_addrinfo_result("127.0.0.1", 443);
    if (result == nullptr) {
        return EAI_FAIL;
    }
    *results = result;
    return 0;
}

inline int no_valid_result_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
                                       addrinfo **results) {
    if (results == nullptr || hints == nullptr || node == nullptr || service == nullptr) {
        return EAI_FAIL;
    }
    *results = nullptr;

    g_last_getaddrinfo_family = hints->ai_family;
    if (std::string_view(node) != "localhost" || std::string_view(service) != "443") {
        return EAI_NONAME;
    }

    auto *ipv6 = make_ipv6_addrinfo_result("::1", 443);
    auto *ipv4 = make_ipv4_addrinfo_result("127.0.0.1", 443);
    if (ipv6 == nullptr || ipv4 == nullptr) {
        counting_freeaddrinfo(ipv6);
        counting_freeaddrinfo(ipv4);
        return EAI_FAIL;
    }

    ipv6->ai_addr = nullptr;
    ipv4->ai_addrlen = 0;
    ipv6->ai_next = ipv4;
    *results = ipv6;
    return 0;
}

inline ssize_t fail_sendto(int, const void *, size_t, int, const sockaddr *, socklen_t) {
    errno = EIO;
    return -1;
}

inline ssize_t fail_recvfrom(int, void *, size_t, int, sockaddr *, socklen_t *) {
    errno = EIO;
    return -1;
}

inline ssize_t would_block_recvfrom(int, void *, size_t, int, sockaddr *, socklen_t *) {
    errno = EWOULDBLOCK;
    return -1;
}

inline int fail_poll(pollfd *, nfds_t, int) {
    errno = EIO;
    return -1;
}

inline int readable_poll(pollfd *descriptors, nfds_t descriptor_count, int) {
    if (descriptor_count > 0) {
        descriptors[0].revents = POLLIN;
    }
    return 1;
}

inline int unreadable_poll(pollfd *descriptors, nfds_t descriptor_count, int) {
    if (descriptor_count > 0) {
        descriptors[0].revents = POLLERR;
    }
    return 1;
}

inline int timeout_poll(pollfd *descriptors, nfds_t descriptor_count, int) {
    if (descriptor_count > 0) {
        descriptors[0].revents = 0;
    }
    return 0;
}

inline int record_poll_descriptor_count_then_cancel(pollfd *, nfds_t descriptor_count, int) {
    g_server_socket_poll_trace.poll_descriptor_counts.push_back(descriptor_count);
    errno = ECANCELED;
    return -1;
}

inline thread_local int g_timeout_then_error_poll_calls = 0;
inline thread_local int g_eintr_then_timeout_poll_calls = 0;
inline thread_local int g_eintr_then_ewouldblock_recvfrom_calls = 0;
inline thread_local bool g_seen_runtime_request_datagram = false;
inline std::atomic<int> g_fail_sendto_after_calls = -1;
inline std::atomic<int> g_fail_sendto_call_count = 0;
inline std::atomic<int> g_small_ack_datagrams_to_drop_after_request = 0;

inline int eintr_then_timeout_poll(pollfd *descriptors, nfds_t descriptor_count, int timeout_ms) {
    ++g_eintr_then_timeout_poll_calls;
    if (g_eintr_then_timeout_poll_calls == 1) {
        errno = EINTR;
        return -1;
    }
    return timeout_poll(descriptors, descriptor_count, timeout_ms);
}

inline ssize_t eintr_then_ewouldblock_recvfrom(int, void *, size_t, int, sockaddr *, socklen_t *) {
    ++g_eintr_then_ewouldblock_recvfrom_calls;
    errno = g_eintr_then_ewouldblock_recvfrom_calls == 1 ? EINTR : EWOULDBLOCK;
    return -1;
}

class ScopedTimeoutThenErrorPollReset {
  public:
    ScopedTimeoutThenErrorPollReset() {
        g_timeout_then_error_poll_calls = 0;
    }

    ~ScopedTimeoutThenErrorPollReset() {
        g_timeout_then_error_poll_calls = 0;
    }

    ScopedTimeoutThenErrorPollReset(const ScopedTimeoutThenErrorPollReset &) = delete;
    ScopedTimeoutThenErrorPollReset &operator=(const ScopedTimeoutThenErrorPollReset &) = delete;
};

class ScopedFailSendtoAfterReset {
  public:
    ScopedFailSendtoAfterReset() {
        g_fail_sendto_after_calls.store(-1);
        g_fail_sendto_call_count.store(0);
    }

    ~ScopedFailSendtoAfterReset() {
        g_fail_sendto_after_calls.store(-1);
        g_fail_sendto_call_count.store(0);
    }

    ScopedFailSendtoAfterReset(const ScopedFailSendtoAfterReset &) = delete;
    ScopedFailSendtoAfterReset &operator=(const ScopedFailSendtoAfterReset &) = delete;
};

class ScopedDropSmallAckDatagramReset {
  public:
    ScopedDropSmallAckDatagramReset() {
        g_small_ack_datagrams_to_drop_after_request.store(0);
        g_seen_runtime_request_datagram = false;
    }

    ~ScopedDropSmallAckDatagramReset() {
        g_small_ack_datagrams_to_drop_after_request.store(0);
        g_seen_runtime_request_datagram = false;
    }

    ScopedDropSmallAckDatagramReset(const ScopedDropSmallAckDatagramReset &) = delete;
    ScopedDropSmallAckDatagramReset &operator=(const ScopedDropSmallAckDatagramReset &) = delete;
};

inline int timeout_then_error_poll(pollfd *descriptors, nfds_t descriptor_count, int) {
    if (descriptor_count > 0) {
        descriptors[0].revents = 0;
    }
    if (g_timeout_then_error_poll_calls++ == 0) {
        return 0;
    }

    errno = EIO;
    return -1;
}

inline ssize_t fail_sendto_after_n_calls(int fd, const void *buffer, size_t length, int flags,
                                         const sockaddr *destination,
                                         socklen_t destination_length) {
    const int call_count = g_fail_sendto_call_count.fetch_add(1) + 1;
    const int fail_after = g_fail_sendto_after_calls.load();
    if (fail_after > 0 && call_count >= fail_after) {
        errno = EIO;
        return -1;
    }

    return ::sendto(fd, buffer, length, flags, destination, destination_length);
}

inline ssize_t drop_nth_small_ack_datagram_after_request(int fd, const void *buffer, size_t length,
                                                         int flags, const sockaddr *destination,
                                                         socklen_t destination_length) {
    if (length >= 48 && length <= 96) {
        g_seen_runtime_request_datagram = true;
    }

    if (g_seen_runtime_request_datagram && length <= 48) {
        const int remaining_to_drop = g_small_ack_datagrams_to_drop_after_request.load();
        if (remaining_to_drop > 0) {
            g_small_ack_datagrams_to_drop_after_request.store(remaining_to_drop - 1);
            return static_cast<ssize_t>(length);
        }
    }

    return ::sendto(fd, buffer, length, flags, destination, destination_length);
}

inline ScopedChildProcess
launch_runtime_server_process(const coquic::http09::Http09RuntimeConfig &config) {
    return ScopedChildProcess(config);
}

inline ScopedChildProcess
launch_runtime_server_process(const coquic::http09::Http09RuntimeConfig &config,
                              coquic::io::test::SocketIoBackendOpsOverride override_ops) {
    return ScopedChildProcess(config, override_ops);
}

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

inline std::string read_file_bytes(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

inline bool first_header_is_retry_packet(std::span<const std::byte> datagram) {
    if (datagram.size() < 5) {
        return false;
    }

    const auto first = std::to_integer<std::uint8_t>(datagram.front());
    const bool is_long_header = (first & 0x80u) != 0;
    if (!is_long_header) {
        return false;
    }

    const std::uint32_t version =
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(datagram[1])) << 24) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(datagram[2])) << 16) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(datagram[3])) << 8) |
        static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(datagram[4]));
    if (version == 0) {
        return false;
    }

    const std::uint8_t packet_type = (first >> 4) & 0x03u;
    const std::uint8_t retry_packet_type = version == coquic::quic::kQuicVersion2 ? 0x00u : 0x03u;
    return packet_type == retry_packet_type;
}

struct RuntimeHandshakeObservation {
    bool client_handshake_complete = false;
    bool saw_retry = false;
    std::vector<std::vector<std::byte>> server_datagrams;
    std::vector<std::vector<std::byte>> client_followup_datagrams;
};

inline bool has_long_header(std::span<const std::byte> datagram) {
    if (datagram.empty()) {
        return false;
    }
    return (std::to_integer<std::uint8_t>(datagram.front()) & 0x80u) != 0;
}

inline RuntimeHandshakeObservation run_retry_enabled_runtime_handshake_observation() {
    RuntimeHandshakeObservation observed;

    const auto port = allocate_udp_loopback_port();
    if (port == 0) {
        return observed;
    }

    const auto server_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::http09::QuicHttp09Testcase::handshake,
        .retry_enabled = true,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process = launch_runtime_server_process(server_runtime);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    const int client_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (client_fd < 0) {
        return observed;
    }
    ScopedFd client_socket_guard(client_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    if (::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) != 1) {
        return observed;
    }

    auto client_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::http09::QuicHttp09Testcase::handshake,
        .requests_env = "https://localhost/hello.txt",
    };
    coquic::quic::QuicCore client(coquic::http09::make_http09_client_core_config(client_runtime));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto client_start_datagrams = coquic::quic::test::send_datagrams_from(start);
    if (client_start_datagrams.empty()) {
        return observed;
    }

    for (const auto &datagram : client_start_datagrams) {
        if (::sendto(client_fd, datagram.data(), datagram.size(), 0,
                     reinterpret_cast<const sockaddr *>(&server_address),
                     sizeof(server_address)) < 0) {
            return observed;
        }
    }

    for (int i = 0; i < 64; ++i) {
        pollfd descriptor{};
        descriptor.fd = client_fd;
        descriptor.events = POLLIN;
        const int poll_result = ::poll(&descriptor, 1, 250);
        if (poll_result < 0) {
            return observed;
        }
        if (poll_result == 0) {
            if (client.is_handshake_complete()) {
                break;
            }
            continue;
        }
        if ((descriptor.revents & POLLIN) == 0) {
            return observed;
        }

        std::vector<std::byte> buffer(65535);
        const auto bytes_read =
            ::recvfrom(client_fd, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        if (bytes_read <= 0) {
            return observed;
        }
        buffer.resize(static_cast<std::size_t>(bytes_read));
        observed.saw_retry = observed.saw_retry || first_header_is_retry_packet(buffer);
        observed.server_datagrams.push_back(std::move(buffer));

        auto step = client.advance(
            coquic::quic::QuicCoreInboundDatagram{.bytes = observed.server_datagrams.back()},
            coquic::quic::test::test_time(i + 1));
        const auto response_datagrams = coquic::quic::test::send_datagrams_from(step);
        observed.client_followup_datagrams.insert(observed.client_followup_datagrams.end(),
                                                  response_datagrams.begin(),
                                                  response_datagrams.end());
        for (const auto &datagram : response_datagrams) {
            if (::sendto(client_fd, datagram.data(), datagram.size(), 0,
                         reinterpret_cast<const sockaddr *>(&server_address),
                         sizeof(server_address)) < 0) {
                return observed;
            }
        }
    }

    observed.client_handshake_complete = client.is_handshake_complete();
    return observed;
}

inline bool run_retry_enabled_server_retry_smoke() {
    const auto observed = run_retry_enabled_runtime_handshake_observation();
    return observed.saw_retry;
}

inline int run_retry_enabled_runtime_handshake() {
    const auto observed = run_retry_enabled_runtime_handshake_observation();
    return observed.saw_retry && observed.client_handshake_complete ? 0 : 1;
}

inline std::vector<std::byte> make_unsupported_version_probe() {
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

inline coquic::quic::QuicCoreTimePoint runtime_now() {
    return coquic::quic::QuicCoreClock::now();
}

inline constexpr std::size_t kRuntimeConnectionIdLength = 8;
inline constexpr std::uint32_t kQuicVersion1 = 1;
inline constexpr std::uint32_t kQuicVersion2 = 0x6b3343cfu;

inline std::string connection_id_key(std::span<const std::byte> connection_id) {
    if (connection_id.empty()) {
        return {};
    }
    return std::string(reinterpret_cast<const char *>(connection_id.data()), connection_id.size());
}

inline coquic::quic::ConnectionId make_runtime_connection_id(std::byte prefix,
                                                             std::uint64_t sequence) {
    coquic::quic::ConnectionId connection_id(kRuntimeConnectionIdLength, std::byte{0x00});
    connection_id.front() = prefix;
    for (std::size_t index = 1; index < connection_id.size(); ++index) {
        const auto shift = static_cast<unsigned>((connection_id.size() - 1 - index) * 8);
        connection_id[index] = static_cast<std::byte>((sequence >> shift) & 0xffu);
    }
    return connection_id;
}

inline std::uint32_t read_u32_be_at(std::span<const std::byte> bytes, std::size_t offset) {
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

inline std::optional<ParsedServerDatagram>
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
    bool response_packet_observed = false;
    bool response_packet_acked = false;
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
    coquic::http09::Http09RuntimeConfig client_config;
    coquic::http09::Http09RuntimeConfig server_config;
    std::unordered_set<std::size_t> dropped_client_datagrams;
    std::unordered_set<std::size_t> dropped_server_datagrams;
};

inline InMemoryHttp09TransferResult
run_in_memory_http09_transfer(const InMemoryHttp09TransferConfig &transfer_config) {
    InMemoryHttp09TransferResult observed;

    const auto requests =
        coquic::http09::parse_http09_requests_env(transfer_config.client_config.requests_env);
    if (!requests.has_value()) {
        observed.client_failed = true;
        return observed;
    }

    struct ClientSession {
        coquic::http09::QuicHttp09ClientEndpoint endpoint;
        coquic::quic::QuicCore core;
        std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;
        bool terminal_success = false;
        bool terminal_failure = false;
    };

    struct ServerSession {
        coquic::http09::QuicHttp09ServerEndpoint endpoint;
        coquic::quic::QuicCore core;
        std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;
        bool terminal_failure = false;
    };

    ClientSession client{
        .endpoint = coquic::http09::QuicHttp09ClientEndpoint(coquic::http09::QuicHttp09ClientConfig{
            .requests = requests.value(),
            .download_root = transfer_config.client_config.download_root,
        }),
        .core = coquic::quic::QuicCore(
            coquic::http09::make_http09_client_core_config(transfer_config.client_config)),
        .next_wakeup = std::nullopt,
        .terminal_success = false,
        .terminal_failure = false,
    };
    ServerSession server{
        .endpoint = coquic::http09::QuicHttp09ServerEndpoint(coquic::http09::QuicHttp09ServerConfig{
            .document_root = transfer_config.server_config.document_root}),
        .core = coquic::quic::QuicCore(
            coquic::http09::make_http09_server_core_config(transfer_config.server_config)),
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
            for (const auto &effect : result.effects) {
                const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
                if (send == nullptr) {
                    continue;
                }

                ++observed.client_sent_datagrams;
                observed.client_sent_bytes += send->bytes.size();
                if (transfer_config.dropped_client_datagrams.contains(
                        observed.client_sent_datagrams)) {
                    continue;
                }
                to_server.push_back(send->bytes);
            }

            auto update = client.endpoint.on_core_result(result, now);
            if (result.local_error.has_value() && !update.handled_local_error) {
                client.terminal_failure = true;
                observed.client_failed = true;
                return false;
            }
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
            for (const auto &effect : result.effects) {
                const auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&effect);
                if (send == nullptr) {
                    continue;
                }

                ++observed.server_sent_datagrams;
                observed.server_sent_bytes += send->bytes.size();
                if (transfer_config.dropped_server_datagrams.contains(
                        observed.server_sent_datagrams)) {
                    continue;
                }
                to_client.push_back(send->bytes);
            }

            auto update = server.endpoint.on_core_result(result, now);
            if (result.local_error.has_value() && !update.handled_local_error) {
                server.terminal_failure = true;
                observed.server_failed = true;
                return false;
            }
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

inline ObservingServerResult
run_observing_http09_server(const coquic::http09::Http09RuntimeConfig &config) {
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
        coquic::http09::QuicHttp09ServerEndpoint endpoint;
        coquic::quic::QuicCore core;
        std::optional<coquic::quic::QuicCoreTimePoint> next_wakeup;
        bool endpoint_has_pending_work = false;
        sockaddr_storage peer{};
        socklen_t peer_len = 0;
        std::string local_connection_id_key;
        std::string initial_destination_connection_id_key;
    };

    const auto make_session_core_config = [&](std::uint64_t connection_index) {
        auto core_config = coquic::http09::make_http09_server_core_config(config);
        core_config.source_connection_id =
            make_runtime_connection_id(std::byte{0x53}, connection_index);
        return core_config;
    };

    std::unordered_map<std::string, std::unique_ptr<Session>> sessions;
    std::unordered_map<std::string, std::string> initial_routes;
    std::uint64_t next_connection_index = 1;
    bool saw_peer_activity = false;
    std::unordered_set<std::uint64_t> response_packet_numbers;

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
        const auto packet_is_response = [](const coquic::quic::SentPacketRecord &packet) {
            return std::ranges::any_of(packet.stream_fragments,
                                       [](const coquic::quic::StreamFrameSendFragment &fragment) {
                                           return fragment.stream_id == 0 && fragment.fin;
                                       });
        };
        const auto track_response_packet_state = [&]() {
            const auto &application_space = session.core.connection_->application_space_;
            for (const auto &[packet_number, packet] : application_space.sent_packets) {
                if (!packet_is_response(packet)) {
                    continue;
                }

                observed.response_packet_observed = true;
                response_packet_numbers.insert(packet_number);
            }
            for (const auto &[packet_number, packet] : application_space.declared_lost_packets) {
                if (!packet_is_response(packet)) {
                    continue;
                }

                observed.response_packet_observed = true;
                response_packet_numbers.insert(packet_number);
            }

            for (auto it = response_packet_numbers.begin(); it != response_packet_numbers.end();) {
                const bool still_tracked = application_space.sent_packets.contains(*it) ||
                                           application_space.declared_lost_packets.contains(*it);
                if (still_tracked) {
                    ++it;
                    continue;
                }

                observed.response_packet_acked = true;
                it = response_packet_numbers.erase(it);
            }
        };

        for (;;) {
            session.next_wakeup = result.next_wakeup;
            capture_transport_state();
            track_response_packet_state();
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
            if (result.local_error.has_value() && !update.handled_local_error) {
                return false;
            }
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
            .endpoint = coquic::http09::QuicHttp09ServerEndpoint(
                coquic::http09::QuicHttp09ServerConfig{.document_root = config.document_root}),
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

    const auto process_expired_timers = [&](coquic::quic::QuicCoreTimePoint current,
                                            bool &processed_any) -> bool {
        processed_any = false;
        for (const auto &[key, session] : sessions) {
            (void)key;
            const auto session_next_wakeup = session->next_wakeup;
            if (!session_next_wakeup.has_value() || session_next_wakeup.value() > current) {
                continue;
            }

            processed_any = true;
            ++observed.timer_expirations;
            if (observed.timer_expirations >= kTimerSpinLimit) {
                observed.exit_code = 2;
                return false;
            }
            if (!drive(*session,
                       session->core.advance(coquic::quic::QuicCoreTimerExpired{}, current))) {
                return false;
            }
        }
        return true;
    };

    for (;;) {
        bool processed_timers = false;
        if (!process_expired_timers(runtime_now(), processed_timers)) {
            return observed;
        }
        if (processed_timers) {
            continue;
        }

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
                if (!process_expired_timers(current, processed_timers)) {
                    return observed;
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
                if (!process_expired_timers(current, processed_timers)) {
                    return observed;
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

} // namespace coquic::http09::test_support
