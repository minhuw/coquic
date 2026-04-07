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
#include <utility>
#include <vector>

#include "src/quic/packet.h"
#define private public
#include "src/quic/http09_runtime.h"
#include "src/quic/connection.h"
#undef private
#include "src/quic/http09_runtime_test_hooks.h"
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

coquic::quic::Http09RuntimeMode invalid_runtime_mode() {
    constexpr std::uint8_t raw = 0xff;
    coquic::quic::Http09RuntimeMode mode{};
    std::memcpy(&mode, &raw, sizeof(raw));
    return mode;
}

thread_local std::atomic<bool> *g_runtime_server_stop_requested = nullptr;

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
int stoppable_poll(pollfd *descriptors, nfds_t descriptor_count, int timeout_ms) {
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

void wake_runtime_server(std::string_view host, std::uint16_t port) {
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

int run_http09_runtime_child_process(
    const coquic::quic::Http09RuntimeConfig &config,
    const std::shared_ptr<std::atomic<bool>> &stop_requested,
    coquic::quic::test::Http09RuntimeOpsOverride override_ops) noexcept {
    try {
        ScopedRuntimeServerStopFlag stop_flag(*stop_requested);
        if (override_ops.poll_fn == nullptr) {
            override_ops.poll_fn = &stoppable_poll;
        }
        const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            override_ops,
        };
        return coquic::quic::run_http09_runtime(config);
    } catch (...) {
        std::abort();
    }
}

class ScopedChildProcess {
  public:
    explicit ScopedChildProcess(const coquic::quic::Http09RuntimeConfig &config,
                                coquic::quic::test::Http09RuntimeOpsOverride override_ops = {})
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

int fail_socket(int, int, int) {
    errno = EMFILE;
    return -1;
}

int fail_bind(int, const sockaddr *, socklen_t) {
    errno = EADDRINUSE;
    return -1;
}

int fail_getaddrinfo(const char *, const char *, const addrinfo *, addrinfo **results) {
    if (results != nullptr) {
        *results = nullptr;
    }
    return EAI_NONAME;
}

thread_local int g_freeaddrinfo_calls = 0;
thread_local int g_last_socket_family = AF_UNSPEC;
thread_local int g_last_getaddrinfo_family = AF_UNSPEC;

struct ServerSocketPollTrace {
    int next_socket_fd = 700;
    std::vector<int> opened_sockets;
    std::vector<std::uint16_t> bound_ports;
    std::vector<nfds_t> poll_descriptor_counts;
};

thread_local ServerSocketPollTrace g_server_socket_poll_trace;

int missing_results_getaddrinfo(const char *, const char *, const addrinfo *hints,
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

int fail_getaddrinfo_with_results(const char *, const char *, const addrinfo *,
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

int record_socket_family_then_fail(int family, int, int) {
    g_last_socket_family = family;
    errno = EMFILE;
    return -1;
}

int record_server_socket_then_succeed(int, int, int) {
    const int fd = g_server_socket_poll_trace.next_socket_fd++;
    g_server_socket_poll_trace.opened_sockets.push_back(fd);
    return fd;
}

int record_server_bind_then_succeed(int, const sockaddr *address, socklen_t address_len) {
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

int ipv6_only_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
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

void counting_freeaddrinfo(addrinfo *results) {
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

addrinfo *make_ipv4_addrinfo_result(std::string_view ip, std::uint16_t port) {
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

addrinfo *make_ipv6_addrinfo_result(std::string_view ip, std::uint16_t port) {
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

int prefer_ipv4_mixed_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
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

    ipv6->ai_next = ipv4;
    *results = ipv6;
    return 0;
}

int hostname_ipv6_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
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

int fallback_to_earlier_valid_result_getaddrinfo(const char *node, const char *service,
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

int unsupported_family_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
                                   addrinfo **results) {
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

int wildcard_ipv4_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
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

int no_valid_result_getaddrinfo(const char *node, const char *service, const addrinfo *hints,
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

ssize_t fail_sendto(int, const void *, size_t, int, const sockaddr *, socklen_t) {
    errno = EIO;
    return -1;
}

ssize_t fail_recvfrom(int, void *, size_t, int, sockaddr *, socklen_t *) {
    errno = EIO;
    return -1;
}

ssize_t would_block_recvfrom(int, void *, size_t, int, sockaddr *, socklen_t *) {
    errno = EWOULDBLOCK;
    return -1;
}

int fail_poll(pollfd *, nfds_t, int) {
    errno = EIO;
    return -1;
}

int readable_poll(pollfd *descriptors, nfds_t descriptor_count, int) {
    if (descriptor_count > 0) {
        descriptors[0].revents = POLLIN;
    }
    return 1;
}

int unreadable_poll(pollfd *descriptors, nfds_t descriptor_count, int) {
    if (descriptor_count > 0) {
        descriptors[0].revents = POLLERR;
    }
    return 1;
}

int timeout_poll(pollfd *descriptors, nfds_t descriptor_count, int) {
    if (descriptor_count > 0) {
        descriptors[0].revents = 0;
    }
    return 0;
}

int record_poll_descriptor_count_then_cancel(pollfd *, nfds_t descriptor_count, int) {
    g_server_socket_poll_trace.poll_descriptor_counts.push_back(descriptor_count);
    errno = ECANCELED;
    return -1;
}

thread_local int g_timeout_then_error_poll_calls = 0;
thread_local int g_eintr_then_timeout_poll_calls = 0;
thread_local int g_eintr_then_ewouldblock_recvfrom_calls = 0;
thread_local bool g_seen_runtime_request_datagram = false;
std::atomic<int> g_fail_sendto_after_calls = -1;
std::atomic<int> g_fail_sendto_call_count = 0;
std::atomic<int> g_small_ack_datagrams_to_drop_after_request = 0;

int eintr_then_timeout_poll(pollfd *descriptors, nfds_t descriptor_count, int timeout_ms) {
    ++g_eintr_then_timeout_poll_calls;
    if (g_eintr_then_timeout_poll_calls == 1) {
        errno = EINTR;
        return -1;
    }
    return timeout_poll(descriptors, descriptor_count, timeout_ms);
}

ssize_t eintr_then_ewouldblock_recvfrom(int, void *, size_t, int, sockaddr *, socklen_t *) {
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

int timeout_then_error_poll(pollfd *descriptors, nfds_t descriptor_count, int) {
    if (descriptor_count > 0) {
        descriptors[0].revents = 0;
    }
    if (g_timeout_then_error_poll_calls++ == 0) {
        return 0;
    }

    errno = EIO;
    return -1;
}

ssize_t fail_sendto_after_n_calls(int fd, const void *buffer, size_t length, int flags,
                                  const sockaddr *destination, socklen_t destination_length) {
    const int call_count = g_fail_sendto_call_count.fetch_add(1) + 1;
    const int fail_after = g_fail_sendto_after_calls.load();
    if (fail_after > 0 && call_count >= fail_after) {
        errno = EIO;
        return -1;
    }

    return ::sendto(fd, buffer, length, flags, destination, destination_length);
}

ssize_t drop_nth_small_ack_datagram_after_request(int fd, const void *buffer, size_t length,
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

ScopedChildProcess launch_runtime_server_process(const coquic::quic::Http09RuntimeConfig &config) {
    return ScopedChildProcess(config);
}

ScopedChildProcess
launch_runtime_server_process(const coquic::quic::Http09RuntimeConfig &config,
                              coquic::quic::test::Http09RuntimeOpsOverride override_ops) {
    return ScopedChildProcess(config, override_ops);
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

bool has_long_header(std::span<const std::byte> datagram) {
    if (datagram.empty()) {
        return false;
    }
    return (std::to_integer<std::uint8_t>(datagram.front()) & 0x80u) != 0;
}

RuntimeHandshakeObservation run_retry_enabled_runtime_handshake_observation() {
    RuntimeHandshakeObservation observed;

    const auto port = allocate_udp_loopback_port();
    if (port == 0) {
        return observed;
    }

    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
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

bool run_retry_enabled_server_retry_smoke() {
    const auto observed = run_retry_enabled_runtime_handshake_observation();
    return observed.saw_retry;
}

int run_retry_enabled_runtime_handshake() {
    const auto observed = run_retry_enabled_runtime_handshake_observation();
    return observed.saw_retry && observed.client_handshake_complete ? 0 : 1;
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
constexpr std::uint32_t kQuicVersion2 = 0x6b3343cfu;

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
    coquic::quic::Http09RuntimeConfig client_config;
    coquic::quic::Http09RuntimeConfig server_config;
    std::unordered_set<std::size_t> dropped_client_datagrams;
    std::unordered_set<std::size_t> dropped_server_datagrams;
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

TEST(QuicHttp09RuntimeTest, ClientAndServerTransferSingleFileAfterConnectionMigration) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-after-migration");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/hello.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-after-migration");
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

TEST(QuicHttp09RuntimeTest,
     InMemoryClientAndServerTransferLargeFileRecoversAfterTransferLossPattern) {
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
        .dropped_client_datagrams = {10},
        .dropped_server_datagrams = {28, 58},
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

TEST(QuicHttp09RuntimeTest, InMemoryClientAndServerTransferManyFilesAcrossRefreshedStreamLimits) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;

    std::ostringstream requests_env;
    std::vector<std::string> file_names;
    file_names.reserve(24);
    for (std::size_t index = 0; index < 24; ++index) {
        const auto file_name = "file-" + std::to_string(index) + ".txt";
        const auto body = "body-" + std::to_string(index);
        document_root.write_file(file_name, body);
        if (index != 0) {
            requests_env << ' ';
        }
        requests_env << "https://localhost/" << file_name;
        file_names.push_back(file_name);
    }

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
        .requests_env = requests_env.str(),
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
    for (const auto &file_name : file_names) {
        EXPECT_EQ(read_file_bytes(download_root.path() / file_name),
                  read_file_bytes(document_root.path() / file_name));
    }
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

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "large.bin"), large_body);
}

TEST(QuicHttp09RuntimeTest,
     ClientRetriesResponseAckAfterDroppingInitialPostRequestAckOnlyDatagrams) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "ack-retry-body");

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

    const ScopedDropSmallAckDatagramReset drop_reset;
    g_small_ack_datagrams_to_drop_after_request.store(2);

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    {
        const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
            {
                .sendto_fn = &drop_nth_small_ack_datagram_after_request,
            },
        };
        EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    }

    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "ack-retry-body");
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
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
    ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");

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

TEST(QuicHttp09RuntimeTest, ServerFailsFastWhenPrivateKeyFileMissing) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "/no/such/key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, ServerFailsWhenSocketCreationFails) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.socket_fn = &fail_socket},
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, ServerFailsWhenSocketBindFails) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.bind_fn = &fail_bind},
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerBindsPreferredSocketAndPollsBothSockets) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const ScopedServerSocketPollTraceReset trace_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .socket_fn = &record_server_socket_then_succeed,
            .bind_fn = &record_server_bind_then_succeed,
            .poll_fn = &record_poll_descriptor_count_then_cancel,
            .setsockopt_fn = [](int, int, int, const void *, socklen_t) { return 0; },
            .recvfrom_fn = &would_block_recvfrom,
        },
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
    ASSERT_EQ(g_server_socket_poll_trace.opened_sockets.size(), 2u);
    ASSERT_EQ(g_server_socket_poll_trace.bound_ports.size(), 2u);
    EXPECT_EQ(g_server_socket_poll_trace.bound_ports[0], port);
    EXPECT_EQ(g_server_socket_poll_trace.bound_ports[1], port + 1);
    ASSERT_FALSE(g_server_socket_poll_trace.poll_descriptor_counts.empty());
    EXPECT_EQ(g_server_socket_poll_trace.poll_descriptor_counts.front(), 2u);
}

TEST(QuicHttp09RuntimeTest, ServerFailsWhenConfiguredHostIsNotIpv4) {
    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "not-an-ipv4-address",
        .port = 443,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
}

TEST(QuicHttp09RuntimeTest, ServerUsesIpv6SocketFamilyForIpv6Host) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.socket_fn = &record_socket_family_then_fail},
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "::1",
        .port = 443,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
    EXPECT_EQ(g_last_socket_family, AF_INET6);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenPeerResolutionFails) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.getaddrinfo_fn = &fail_getaddrinfo},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenResolutionSucceedsWithoutAnyAddrinfoResults) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &missing_results_getaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_UNSPEC);
    EXPECT_EQ(g_last_socket_family, AF_UNSPEC);
}

TEST(QuicHttp09RuntimeTest, ServerResolutionPassesNullNodeForWildcardHost) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &wildcard_ipv4_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "",
        .port = 443,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_UNSPEC);
    EXPECT_EQ(g_last_socket_family, AF_INET);
}

TEST(QuicHttp09RuntimeTest, ClientPrefersIpv4AddrinfoWhenHostnameIsNonNumeric) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &prefer_ipv4_mixed_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_UNSPEC);
    EXPECT_EQ(g_last_socket_family, AF_INET);
}

TEST(QuicHttp09RuntimeTest, ClientConnectionUsesIpv6ResolutionAndSocketFamilyForIpv6Remote) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &ipv6_only_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://[::1]:9443/a.txt",
         .authority = "[::1]:9443",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, requests, 1), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_INET6);
    EXPECT_EQ(g_last_socket_family, AF_INET6);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientFallsBackToEarlierValidAddrinfoWhenPreferredResultIsInvalid) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &fallback_to_earlier_valid_result_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_last_socket_family, AF_INET6);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenAllResolvedAddrinfoEntriesAreInvalid) {
    const ScopedRuntimeAddressFamilyReset address_family_reset;
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .socket_fn = &record_socket_family_then_fail,
            .getaddrinfo_fn = &no_valid_result_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_last_getaddrinfo_family, AF_UNSPEC);
    EXPECT_EQ(g_last_socket_family, AF_UNSPEC);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenAddrinfoFamilyIsUnsupported) {
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .getaddrinfo_fn = &unsupported_family_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "localhost",
        .port = 443,
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientUsesRealIpv6SocketSetupBeforeInitialSend) {
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .sendto_fn = &fail_sendto,
            .getaddrinfo_fn = &ipv6_only_getaddrinfo,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://[::1]:9443/a.txt",
         .authority = "[::1]:9443",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, requests, 1), 1);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientConnectionRejectsInvalidDerivedRequestAuthority) {
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://[::1/a.txt",
         .authority = "[::1",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, requests, 1), 1);
}

TEST(QuicHttp09RuntimeTest, ClientConnectionFailsWhenSocketCreationFailsAfterRemoteDerivation) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.socket_fn = &fail_socket},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://127.0.0.1:9443/a.txt",
         .authority = "127.0.0.1:9443",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, requests, 1), 1);
}

TEST(QuicHttp09RuntimeTest, ClientConnectionFreesResolverResultsWhenResolutionFails) {
    const ScopedFreeaddrinfoCounterReset freeaddrinfo_counter_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .getaddrinfo_fn = &fail_getaddrinfo_with_results,
            .freeaddrinfo_fn = &counting_freeaddrinfo,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .server_name = "localhost",
    };

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 1);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenInitialSendFails) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.sendto_fn = &fail_sendto},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenPollErrors) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.poll_fn = &fail_poll},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenSocketBecomesUnreadable) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.poll_fn = &unreadable_poll},
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenRecvfromFailsAfterReadablePoll) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .poll_fn = &readable_poll,
            .recvfrom_fn = &fail_recvfrom,
        },
    };

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .requests_env = "https://localhost/hello.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ServerContinuesAfterIdlePollTimeoutThenFailsOnPollError) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const ScopedTimeoutThenErrorPollReset poll_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.poll_fn = &timeout_then_error_poll},
    };

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(server), 1);
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

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");
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

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");
}

TEST(QuicHttp09RuntimeTest, MulticonnectCaseSupportsThreeRequestsWithoutRoutingCollisions) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("alpha.txt", "alpha-bytes");
    document_root.write_file("beta.txt", "beta-bytes");
    document_root.write_file("gamma.txt", "gamma-bytes");

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
        .requests_env =
            "https://localhost/alpha.txt https://localhost/beta.txt https://localhost/gamma.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "gamma.txt"), "gamma-bytes");
}

TEST(QuicHttp09RuntimeTest, ClientAndServerTransferSingleFileWithResumptionTestcase) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-after-resumption");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    coquic::quic::Http09RuntimeConfig server;
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "server");
        ScopedEnvVar testcase("TESTCASE", "resumption");
        ScopedEnvVar host("HOST", "127.0.0.1");
        ScopedEnvVar port_env("PORT", std::to_string(port));
        ScopedEnvVar document_root_env("DOCUMENT_ROOT", document_root.path().string());
        ScopedEnvVar certificate("CERTIFICATE_CHAIN_PATH", "tests/fixtures/quic-server-cert.pem");
        ScopedEnvVar private_key("PRIVATE_KEY_PATH", "tests/fixtures/quic-server-key.pem");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        server = optional_value_or_terminate(parsed);
    }

    coquic::quic::Http09RuntimeConfig client;
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "resumption");
        ScopedEnvVar host("HOST", "127.0.0.1");
        ScopedEnvVar port_env("PORT", std::to_string(port));
        ScopedEnvVar download_root_env("DOWNLOAD_ROOT", download_root.path().string());
        ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        client = optional_value_or_terminate(parsed);
    }

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-after-resumption");
}

TEST(QuicHttp09RuntimeTest, ZeroRttRuntimeTransfersWarmupAndFinalRequestsAcrossResumedConnection) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("seed.txt", "seed-body");
    document_root.write_file("final.txt", "final-body");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    coquic::quic::Http09RuntimeConfig server;
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "server");
        ScopedEnvVar testcase("TESTCASE", "zerortt");
        ScopedEnvVar host("HOST", "127.0.0.1");
        ScopedEnvVar port_env("PORT", std::to_string(port));
        ScopedEnvVar document_root_env("DOCUMENT_ROOT", document_root.path().string());
        ScopedEnvVar certificate("CERTIFICATE_CHAIN_PATH", "tests/fixtures/quic-server-cert.pem");
        ScopedEnvVar private_key("PRIVATE_KEY_PATH", "tests/fixtures/quic-server-key.pem");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        server = optional_value_or_terminate(parsed);
    }

    coquic::quic::Http09RuntimeConfig client;
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "zerortt");
        ScopedEnvVar host("HOST", "127.0.0.1");
        ScopedEnvVar port_env("PORT", std::to_string(port));
        ScopedEnvVar download_root_env("DOWNLOAD_ROOT", download_root.path().string());
        ScopedEnvVar requests("REQUESTS", "https://localhost/seed.txt https://localhost/final.txt");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        client = optional_value_or_terminate(parsed);
    }

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "final.txt"), "final-body");
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
    EXPECT_EQ(client_core.original_version, 0x00000001u);
    EXPECT_EQ(client_core.initial_version, 0x00000001u);
    EXPECT_EQ(client_core.supported_versions, (std::vector<std::uint32_t>{0x00000001u}));

    auto server_runtime = overridden_runtime;
    server_runtime.mode = coquic::quic::Http09RuntimeMode::server;
    server_runtime.certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    server_runtime.private_key_path = "tests/fixtures/quic-server-key.pem";
    const auto server_core = coquic::quic::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.application_protocol, "hq-interop");
    EXPECT_EQ(server_core.original_version, 0x00000001u);
    EXPECT_EQ(server_core.initial_version, 0x00000001u);
    EXPECT_EQ(server_core.supported_versions, (std::vector<std::uint32_t>{0x00000001u}));
    if (!server_core.identity.has_value()) {
        FAIL() << "expected server identity";
    }
    const auto &identity = *server_core.identity;
    EXPECT_EQ(identity.certificate_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-cert.pem"));
    EXPECT_EQ(identity.private_key_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-key.pem"));
}

TEST(QuicHttp09RuntimeTest, RuntimeLeavesQlogDisabledWhenQlogdirUnsetOrEmpty) {
    const char *argv[] = {"coquic"};

    {
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar qlogdir("QLOGDIR", std::nullopt);

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_FALSE(runtime.qlog_directory.has_value());
    }

    {
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar qlogdir("QLOGDIR", "");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_FALSE(runtime.qlog_directory.has_value());
    }
}

TEST(QuicHttp09RuntimeTest, RuntimeReadsQlogDirectoryFromEnvironment) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
    ScopedEnvVar qlogdir("QLOGDIR", "/logs/qlog");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    ASSERT_TRUE(runtime.qlog_directory.has_value());
    EXPECT_EQ(optional_ref_or_terminate(runtime.qlog_directory),
              std::filesystem::path("/logs/qlog"));
}

TEST(QuicHttp09RuntimeTest, RuntimePropagatesQlogDirectoryIntoClientAndServerCoreConfigs) {
    const auto qlog_path = std::filesystem::path("/logs/qlog");

    const auto client_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .requests_env = "https://localhost/a.txt",
        .qlog_directory = qlog_path,
    };
    const auto client_core = coquic::quic::make_http09_client_core_config(client_runtime);
    ASSERT_TRUE(client_core.qlog.has_value());
    EXPECT_EQ(optional_ref_or_terminate(client_core.qlog).directory, qlog_path);

    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .qlog_directory = qlog_path,
    };
    const auto server_core =
        coquic::quic::test::make_http09_server_core_config_with_identity_for_tests(
            server_runtime, coquic::quic::TlsIdentity{
                                .certificate_pem = "test-certificate-pem",
                                .private_key_pem = "test-private-key-pem",
                            });
    ASSERT_TRUE(server_core.qlog.has_value());
    EXPECT_EQ(optional_ref_or_terminate(server_core.qlog).directory, qlog_path);
}

TEST(QuicHttp09RuntimeTest, RuntimeRejectsInvalidAndEmptyPortStringsFromEnvironment) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
    ScopedEnvVar invalid_port("PORT", "70000");
    EXPECT_FALSE(coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv)).has_value());

    ScopedEnvVar empty_port("PORT", "");
    EXPECT_FALSE(coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv)).has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeRejectsUnknownTestcaseNamesFromEnvironmentAndCli) {
    {
        const char *env_argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar testcase("TESTCASE", "unknown-case");
        EXPECT_FALSE(
            coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(env_argv)).has_value());
    }

    {
        ScopedEnvVar role("ROLE", std::nullopt);
        ScopedEnvVar requests("REQUESTS", std::nullopt);
        ScopedEnvVar testcase("TESTCASE", std::nullopt);
        const char *cli_argv[] = {"coquic",       "interop-client", "--testcase",
                                  "unknown-case", "--requests",     "https://localhost/a.txt"};
        EXPECT_FALSE(
            coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(cli_argv)).has_value());
    }
}

TEST(QuicHttp09RuntimeTest, RuntimeRejectsInvalidRoleAndUsageDispatchFailures) {
    {
        const char *role_argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "invalid");
        EXPECT_FALSE(
            coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(role_argv)).has_value());
    }

    ScopedEnvVar role("ROLE", std::nullopt);

    const char *bad_subcommand_argv[] = {"coquic", "interop-runner"};
    EXPECT_FALSE(
        coquic::quic::parse_http09_runtime_args(2, const_cast<char **>(bad_subcommand_argv))
            .has_value());

    const char *missing_value_argv[] = {"coquic", "interop-client", "--host"};
    EXPECT_FALSE(coquic::quic::parse_http09_runtime_args(3, const_cast<char **>(missing_value_argv))
                     .has_value());

    const char *unknown_flag_argv[] = {"coquic", "interop-client", "--invalid"};
    EXPECT_FALSE(coquic::quic::parse_http09_runtime_args(3, const_cast<char **>(unknown_flag_argv))
                     .has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeRejectsClientStartupWithoutRequests) {
    const char *argv[] = {"coquic", "interop-client"};
    ScopedEnvVar role("ROLE", std::nullopt);
    ScopedEnvVar requests("REQUESTS", std::nullopt);
    EXPECT_FALSE(coquic::quic::parse_http09_runtime_args(2, const_cast<char **>(argv)).has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialRunnerAliasesViaCliFlags) {
    const char *multiconnect_argv[] = {"coquic",       "interop-client", "--testcase",
                                       "multiconnect", "--requests",     "https://localhost/a.txt"};
    const auto multiconnect =
        coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(multiconnect_argv));
    ASSERT_TRUE(multiconnect.has_value());
    const auto multiconnect_runtime = multiconnect.value_or(coquic::quic::Http09RuntimeConfig{});
    EXPECT_EQ(multiconnect_runtime.testcase, coquic::quic::QuicHttp09Testcase::multiconnect);

    const char *chacha20_argv[] = {"coquic",   "interop-client", "--testcase",
                                   "chacha20", "--requests",     "https://localhost/a.txt"};
    const auto chacha20 =
        coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(chacha20_argv));
    ASSERT_TRUE(chacha20.has_value());
    const auto chacha20_runtime = chacha20.value_or(coquic::quic::Http09RuntimeConfig{});
    EXPECT_EQ(chacha20_runtime.testcase, coquic::quic::QuicHttp09Testcase::chacha20);
}

TEST(QuicHttp09RuntimeTest, RejectsMalformedBracketedAuthority) {
    const auto parsed = coquic::quic::parse_http09_authority("[::1");
    EXPECT_FALSE(parsed.has_value());
}

TEST(QuicHttp09RuntimeTest, RejectsEmptyAndColonOnlyAuthorities) {
    EXPECT_FALSE(coquic::quic::parse_http09_authority("").has_value());
    EXPECT_FALSE(coquic::quic::parse_http09_authority(":443").has_value());
}

TEST(QuicHttp09RuntimeTest, ParsesBracketedAuthoritiesWithAndWithoutPort) {
    const auto without_port = coquic::quic::parse_http09_authority("[::1]");
    ASSERT_TRUE(without_port.has_value());
    const auto &without_port_authority = optional_ref_or_terminate(without_port);
    EXPECT_EQ(without_port_authority.host, "::1");
    EXPECT_FALSE(without_port_authority.port.has_value());

    const auto with_port = coquic::quic::parse_http09_authority("[::1]:8443");
    ASSERT_TRUE(with_port.has_value());
    const auto &with_port_authority = optional_ref_or_terminate(with_port);
    EXPECT_EQ(with_port_authority.host, "::1");
    ASSERT_TRUE(with_port_authority.port.has_value());
    EXPECT_EQ(optional_value_or_terminate(with_port_authority.port), 8443);
}

TEST(QuicHttp09RuntimeTest, RejectsBracketedAuthoritiesWithEmptyHostOrInvalidSuffix) {
    EXPECT_FALSE(coquic::quic::parse_http09_authority("[]:443").has_value());
    EXPECT_FALSE(coquic::quic::parse_http09_authority("[::1]extra").has_value());
    EXPECT_FALSE(coquic::quic::parse_http09_authority("[::1]:bad").has_value());
}

TEST(QuicHttp09RuntimeTest, RejectsMalformedHostPortAuthority) {
    const auto parsed = coquic::quic::parse_http09_authority("localhost:bad");
    EXPECT_FALSE(parsed.has_value());
}

TEST(QuicHttp09RuntimeTest, ParsesHostnamePortAndIpv6LiteralAuthorities) {
    const auto host_port = coquic::quic::parse_http09_authority("localhost:9443");
    ASSERT_TRUE(host_port.has_value());
    const auto &host_port_authority = optional_ref_or_terminate(host_port);
    EXPECT_EQ(host_port_authority.host, "localhost");
    ASSERT_TRUE(host_port_authority.port.has_value());
    EXPECT_EQ(optional_value_or_terminate(host_port_authority.port), 9443);

    const auto ipv6_literal = coquic::quic::parse_http09_authority("2001:db8::1");
    ASSERT_TRUE(ipv6_literal.has_value());
    const auto &ipv6_literal_authority = optional_ref_or_terminate(ipv6_literal);
    EXPECT_EQ(ipv6_literal_authority.host, "2001:db8::1");
    EXPECT_FALSE(ipv6_literal_authority.port.has_value());
}

TEST(QuicHttp09RuntimeTest, DerivesHostPortAndServerNameFromRequestWhenUnset) {
    const auto config = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .port = 443,
        .server_name = "",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://127.0.0.1:8443/a.txt",
         .authority = "127.0.0.1:8443",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };
    const auto derived = coquic::quic::derive_http09_client_remote(config, requests);
    ASSERT_TRUE(derived.has_value());
    const auto remote = derived.value_or(coquic::quic::Http09ClientRemote{});
    EXPECT_EQ(remote.host, "127.0.0.1");
    EXPECT_EQ(remote.port, 8443);
    EXPECT_EQ(remote.server_name, "127.0.0.1");
}

TEST(QuicHttp09RuntimeTest, DerivesOnlyServerNameWhenHostAlreadySpecified) {
    const auto config = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 9443,
        .server_name = "",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://localhost/a.txt",
         .authority = "localhost",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };
    const auto derived = coquic::quic::derive_http09_client_remote(config, requests);
    ASSERT_TRUE(derived.has_value());
    const auto remote = derived.value_or(coquic::quic::Http09ClientRemote{});
    EXPECT_EQ(remote.host, "127.0.0.1");
    EXPECT_EQ(remote.port, 9443);
    EXPECT_EQ(remote.server_name, "localhost");
}

TEST(QuicHttp09RuntimeTest, DerivesOnlyHostWhenServerNameAlreadySpecified) {
    const auto config = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .port = 9443,
        .server_name = "example.test",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://localhost/a.txt",
         .authority = "localhost",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };
    const auto derived = coquic::quic::derive_http09_client_remote(config, requests);
    ASSERT_TRUE(derived.has_value());
    const auto remote = derived.value_or(coquic::quic::Http09ClientRemote{});
    EXPECT_EQ(remote.host, "localhost");
    EXPECT_EQ(remote.port, 9443);
    EXPECT_EQ(remote.server_name, "example.test");
}

TEST(QuicHttp09RuntimeTest, DerivationReturnsConfiguredRemoteWithoutRequestsWhenComplete) {
    const auto config = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "203.0.113.10",
        .port = 9443,
        .server_name = "example.test",
    };

    const auto derived = coquic::quic::derive_http09_client_remote(config, {});
    ASSERT_TRUE(derived.has_value());
    const auto &derived_remote = optional_ref_or_terminate(derived);
    EXPECT_EQ(derived_remote.host, "203.0.113.10");
    EXPECT_EQ(derived_remote.port, 9443);
    EXPECT_EQ(derived_remote.server_name, "example.test");
}

TEST(QuicHttp09RuntimeTest, DerivationFailsForEmptyRequestListWhenFallbackRequired) {
    const auto config = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    EXPECT_FALSE(coquic::quic::derive_http09_client_remote(config, {}).has_value());
}

TEST(QuicHttp09RuntimeTest, DerivationFailsForInvalidRequestAuthority) {
    const auto config = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::quic::QuicHttp09Request> requests = {
        {.url = "https://[::1/a.txt",
         .authority = "[::1",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };
    EXPECT_FALSE(coquic::quic::derive_http09_client_remote(config, requests).has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialMulticonnectTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "multiconnect");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt https://localhost/b.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialV2Testcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "v2");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase, coquic::quic::QuicHttp09Testcase::v2);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialEcnTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "ecn");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase, coquic::quic::QuicHttp09Testcase::ecn);
}

TEST(QuicHttp09RuntimeTest, RuntimeTreatsAmplificationLimitEnvironmentAliasAsTransfer) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "amplificationlimit");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::transfer);
}

TEST(QuicHttp09RuntimeTest, RuntimeTreatsAmplificationLimitCliAliasAsTransfer) {
    const char *argv[] = {"coquic",     "interop-client",
                          "--testcase", "amplificationlimit",
                          "--requests", "https://localhost/a.txt"};

    const auto parsed = coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::transfer);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialResumptionAndZeroRttTestcases) {
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "resumption");
        ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
                  coquic::quic::QuicHttp09Testcase::resumption);
    }

    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "zerortt");
        ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

        const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
                  coquic::quic::QuicHttp09Testcase::zerortt);
    }
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialKeyUpdateTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "keyupdate");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::keyupdate);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsKeyUpdateCliFlag) {
    const char *argv[] = {"coquic",    "interop-client", "--testcase",
                          "keyupdate", "--requests",     "https://localhost/hello.txt"};

    const auto parsed = coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::keyupdate);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialRebindPortTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "rebind-port");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::rebind_port);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsRebindAddrCliFlag) {
    const char *argv[] = {"coquic",      "interop-client", "--testcase",
                          "rebind-addr", "--requests",     "https://localhost/hello.txt"};

    const auto parsed = coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::rebind_addr);
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialConnectionMigrationTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "connectionmigration");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(parsed).testcase,
              coquic::quic::QuicHttp09Testcase::connectionmigration);
}

TEST(QuicHttp09RuntimeTest, MigrationCasesUseTransferTransportProfile) {
    const auto transfer = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto rebind_port = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::rebind_port,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto rebind_addr = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::rebind_addr,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto migration = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        .requests_env = "https://localhost/hello.txt",
    };

    const auto transfer_core = coquic::quic::make_http09_client_core_config(transfer);
    const auto rebind_port_core = coquic::quic::make_http09_client_core_config(rebind_port);
    const auto rebind_addr_core = coquic::quic::make_http09_client_core_config(rebind_addr);
    const auto migration_core = coquic::quic::make_http09_client_core_config(migration);

    EXPECT_EQ(rebind_port_core.transport.initial_max_data,
              transfer_core.transport.initial_max_data);
    EXPECT_EQ(rebind_addr_core.transport.initial_max_data,
              transfer_core.transport.initial_max_data);
    EXPECT_EQ(migration_core.transport.initial_max_data, transfer_core.transport.initial_max_data);
    EXPECT_EQ(rebind_port_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(rebind_addr_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(migration_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(rebind_port_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
    EXPECT_EQ(rebind_addr_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
    EXPECT_EQ(migration_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
}

TEST(QuicHttp09RuntimeTest, KeyUpdateUsesTransferTransportProfile) {
    const auto keyupdate = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::keyupdate,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto transfer = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .requests_env = "https://localhost/hello.txt",
    };

    const auto keyupdate_core = coquic::quic::make_http09_client_core_config(keyupdate);
    const auto transfer_core = coquic::quic::make_http09_client_core_config(transfer);

    EXPECT_EQ(keyupdate_core.transport.max_idle_timeout, transfer_core.transport.max_idle_timeout);
    EXPECT_EQ(keyupdate_core.transport.max_udp_payload_size,
              transfer_core.transport.max_udp_payload_size);
    EXPECT_EQ(keyupdate_core.transport.ack_delay_exponent,
              transfer_core.transport.ack_delay_exponent);
    EXPECT_EQ(keyupdate_core.transport.max_ack_delay, transfer_core.transport.max_ack_delay);
    EXPECT_EQ(keyupdate_core.transport.initial_max_data, transfer_core.transport.initial_max_data);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_bidi_local,
              transfer_core.transport.initial_max_stream_data_bidi_local);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_bidi_remote,
              transfer_core.transport.initial_max_stream_data_bidi_remote);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_uni,
              transfer_core.transport.initial_max_stream_data_uni);
    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_bidi,
              transfer_core.transport.initial_max_streams_bidi);
    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(keyupdate_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
    EXPECT_EQ(coquic::quic::test::client_receive_timeout_ms_for_tests(keyupdate),
              coquic::quic::test::client_receive_timeout_ms_for_tests(transfer));
}

TEST(QuicHttp09RuntimeTest, KeyUpdateRuntimeEnablesClientKeyUpdatePolicy) {
    const auto keyupdate = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::keyupdate,
        .download_root = std::filesystem::path("/downloads"),
        .requests_env = "https://localhost/hello.txt",
    };
    const auto transfer = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .download_root = std::filesystem::path("/downloads"),
        .requests_env = "https://localhost/hello.txt",
    };
    const auto requests = coquic::quic::parse_http09_requests_env("https://localhost/hello.txt");
    ASSERT_TRUE(requests.has_value());

    const auto keyupdate_client_config =
        coquic::quic::test::make_http09_client_endpoint_config_for_tests(
            keyupdate, requests.value(), false, coquic::quic::QuicCoreResult{});
    const auto transfer_client_config =
        coquic::quic::test::make_http09_client_endpoint_config_for_tests(
            transfer, requests.value(), false, coquic::quic::QuicCoreResult{});

    EXPECT_TRUE(keyupdate_client_config.request_key_update);
    EXPECT_FALSE(transfer_client_config.request_key_update);
}

TEST(QuicHttp09RuntimeTest, KeyUpdateUsesTransferTransportProfileOnServerPath) {
    const auto keyupdate = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .testcase = coquic::quic::QuicHttp09Testcase::keyupdate,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto transfer = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    const auto keyupdate_core = coquic::quic::make_http09_server_core_config(keyupdate);
    const auto transfer_core = coquic::quic::make_http09_server_core_config(transfer);

    EXPECT_EQ(keyupdate_core.transport.max_idle_timeout, transfer_core.transport.max_idle_timeout);
    EXPECT_EQ(keyupdate_core.transport.max_udp_payload_size,
              transfer_core.transport.max_udp_payload_size);
    EXPECT_EQ(keyupdate_core.transport.ack_delay_exponent,
              transfer_core.transport.ack_delay_exponent);
    EXPECT_EQ(keyupdate_core.transport.max_ack_delay, transfer_core.transport.max_ack_delay);
    EXPECT_EQ(keyupdate_core.transport.initial_max_data, transfer_core.transport.initial_max_data);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_bidi_local,
              transfer_core.transport.initial_max_stream_data_bidi_local);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_bidi_remote,
              transfer_core.transport.initial_max_stream_data_bidi_remote);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_uni,
              transfer_core.transport.initial_max_stream_data_uni);
    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_bidi,
              transfer_core.transport.initial_max_streams_bidi);
    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(keyupdate_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
}

TEST(QuicHttp09RuntimeTest, RuntimeReadsServerEnvironmentOverrides) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "server");
    ScopedEnvVar testcase("TESTCASE", "handshake");
    ScopedEnvVar requests("REQUESTS", std::nullopt);
    ScopedEnvVar host("HOST", "0.0.0.0");
    ScopedEnvVar port("PORT", "8443");
    ScopedEnvVar document_root("DOCUMENT_ROOT", "/srv/http09");
    ScopedEnvVar download_root("DOWNLOAD_ROOT", "/srv/downloads");
    ScopedEnvVar certificate("CERTIFICATE_CHAIN_PATH", "/tls/cert.pem");
    ScopedEnvVar private_key("PRIVATE_KEY_PATH", "/tls/key.pem");
    ScopedEnvVar server_name("SERVER_NAME", "interop.example");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_EQ(runtime.mode, coquic::quic::Http09RuntimeMode::server);
    EXPECT_EQ(runtime.host, "0.0.0.0");
    EXPECT_EQ(runtime.port, 8443);
    EXPECT_EQ(runtime.testcase, coquic::quic::QuicHttp09Testcase::handshake);
    EXPECT_EQ(runtime.document_root, std::filesystem::path("/srv/http09"));
    EXPECT_EQ(runtime.download_root, std::filesystem::path("/srv/downloads"));
    EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/tls/cert.pem"));
    EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/tls/key.pem"));
    EXPECT_EQ(runtime.server_name, "interop.example");
}

TEST(QuicHttp09RuntimeTest, RuntimeParsesInteropServerSubcommandFlags) {
    const char *argv[] = {"coquic",          "interop-server",  "--host",
                          "0.0.0.0",         "--port",          "9443",
                          "--document-root", "/srv/http09",     "--certificate-chain",
                          "/tls/cert.pem",   "--private-key",   "/tls/key.pem",
                          "--server-name",   "interop.example", "--verify-peer"};
    const auto parsed = coquic::quic::parse_http09_runtime_args(static_cast<int>(std::size(argv)),
                                                                const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_EQ(runtime.mode, coquic::quic::Http09RuntimeMode::server);
    EXPECT_EQ(runtime.host, "0.0.0.0");
    EXPECT_EQ(runtime.port, 9443);
    EXPECT_EQ(runtime.document_root, std::filesystem::path("/srv/http09"));
    EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/tls/cert.pem"));
    EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/tls/key.pem"));
    EXPECT_EQ(runtime.server_name, "interop.example");
    EXPECT_TRUE(runtime.verify_peer);
}

TEST(QuicHttp09RuntimeTest, RuntimeParsesRetryFlagFromEnvironmentAndCli) {
    const char *argv[] = {"coquic", "interop-server", "--retry"};
    ScopedEnvVar role("ROLE", "server");
    ScopedEnvVar retry("RETRY", "1");

    const auto parsed = coquic::quic::parse_http09_runtime_args(static_cast<int>(std::size(argv)),
                                                                const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_TRUE(runtime.retry_enabled);
}

TEST(QuicHttp09RuntimeTest, RuntimeTreatsRetryTestcaseAliasAsHandshakeWithRetryEnabled) {
    {
        const char *env_argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "server");
        ScopedEnvVar testcase("TESTCASE", "retry");

        const auto parsed =
            coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(env_argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_EQ(runtime.testcase, coquic::quic::QuicHttp09Testcase::handshake);
        EXPECT_TRUE(runtime.retry_enabled);
    }

    {
        const char *cli_argv[] = {"coquic", "interop-client", "--testcase",
                                  "retry",  "--requests",     "https://localhost/a.txt"};
        const auto parsed =
            coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(cli_argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_EQ(runtime.testcase, coquic::quic::QuicHttp09Testcase::handshake);
        EXPECT_TRUE(runtime.retry_enabled);
    }
}

TEST(QuicHttp09RuntimeTest, RuntimeCliFlagsOverrideEnvironmentAndKeepExplicitClientRemote) {
    const char *argv[] = {"coquic",
                          "interop-client",
                          "--host",
                          "198.51.100.20",
                          "--port",
                          "9443",
                          "--testcase",
                          "chacha20",
                          "--requests",
                          "https://cli.example/a.txt https://cli.example/b.txt",
                          "--document-root",
                          "/unused/server-root",
                          "--download-root",
                          "/cli/downloads",
                          "--certificate-chain",
                          "/cli/cert.pem",
                          "--private-key",
                          "/cli/key.pem",
                          "--server-name",
                          "cli.example",
                          "--verify-peer"};
    ScopedEnvVar role("ROLE", "server");
    ScopedEnvVar testcase("TESTCASE", "handshake");
    ScopedEnvVar requests("REQUESTS", "https://env.example/env.txt");
    ScopedEnvVar host("HOST", "203.0.113.10");
    ScopedEnvVar port("PORT", "443");
    ScopedEnvVar document_root("DOCUMENT_ROOT", "/env/www");
    ScopedEnvVar download_root("DOWNLOAD_ROOT", "/env/downloads");
    ScopedEnvVar certificate("CERTIFICATE_CHAIN_PATH", "/env/cert.pem");
    ScopedEnvVar private_key("PRIVATE_KEY_PATH", "/env/key.pem");
    ScopedEnvVar server_name("SERVER_NAME", "env.example");

    const auto parsed = coquic::quic::parse_http09_runtime_args(static_cast<int>(std::size(argv)),
                                                                const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_EQ(runtime.mode, coquic::quic::Http09RuntimeMode::client);
    EXPECT_EQ(runtime.host, "198.51.100.20");
    EXPECT_EQ(runtime.port, 9443);
    EXPECT_EQ(runtime.testcase, coquic::quic::QuicHttp09Testcase::chacha20);
    EXPECT_EQ(runtime.requests_env, "https://cli.example/a.txt https://cli.example/b.txt");
    EXPECT_EQ(runtime.document_root, std::filesystem::path("/unused/server-root"));
    EXPECT_EQ(runtime.download_root, std::filesystem::path("/cli/downloads"));
    EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/cli/cert.pem"));
    EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/cli/key.pem"));
    EXPECT_EQ(runtime.server_name, "cli.example");
    EXPECT_TRUE(runtime.verify_peer);
}

TEST(QuicHttp09RuntimeTest, RuntimeRejectsInvalidCliPortString) {
    const char *argv[] = {"coquic",      "interop-client", "--port",
                          "forty-three", "--requests",     "https://localhost/a.txt"};
    EXPECT_FALSE(coquic::quic::parse_http09_runtime_args(6, const_cast<char **>(argv)).has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeAcceptsOfficialChacha20TestcaseAndConstrainsCipherSuites) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "chacha20");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::quic::parse_http09_runtime_args(1, const_cast<char **>(argv));
    if (!parsed.has_value()) {
        FAIL() << "expected runtime config";
    }
    const auto &runtime = *parsed;
    EXPECT_EQ(runtime.testcase, coquic::quic::QuicHttp09Testcase::chacha20);

    const auto client_core = coquic::quic::make_http09_client_core_config(runtime);
    EXPECT_EQ(client_core.allowed_tls_cipher_suites,
              (std::vector<coquic::quic::CipherSuite>{
                  coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
              }));

    auto server_runtime = runtime;
    server_runtime.mode = coquic::quic::Http09RuntimeMode::server;
    server_runtime.certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    server_runtime.private_key_path = "tests/fixtures/quic-server-key.pem";
    const auto server_core = coquic::quic::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.allowed_tls_cipher_suites,
              (std::vector<coquic::quic::CipherSuite>{
                  coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
              }));
}

TEST(QuicHttp09RuntimeTest, RuntimeBuildsV2CoreConfigsWithCompatibleVersionSupport) {
    const auto runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::v2,
        .requests_env = "https://localhost/a.txt",
    };

    const auto client_core = coquic::quic::make_http09_client_core_config(runtime);
    EXPECT_EQ(client_core.original_version, 0x00000001u);
    EXPECT_EQ(client_core.initial_version, 0x00000001u);
    EXPECT_EQ(client_core.supported_versions,
              (std::vector<std::uint32_t>{0x6b3343cfu, 0x00000001u}));

    auto server_runtime = runtime;
    server_runtime.mode = coquic::quic::Http09RuntimeMode::server;
    server_runtime.certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    server_runtime.private_key_path = "tests/fixtures/quic-server-key.pem";
    const auto server_core = coquic::quic::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.original_version, 0x00000001u);
    EXPECT_EQ(server_core.initial_version, 0x00000001u);
    EXPECT_EQ(server_core.supported_versions,
              (std::vector<std::uint32_t>{0x6b3343cfu, 0x00000001u}));
}

TEST(QuicHttp09RuntimeTest, RuntimeBuildsServerCoreConfigWithExtendedIdleTimeoutForMulticonnect) {
    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .testcase = coquic::quic::QuicHttp09Testcase::multiconnect,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    const auto server_core = coquic::quic::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.transport.max_idle_timeout, 180000u);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksExposeTraceAndConnectionIdFormatting) {
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", std::nullopt);
        EXPECT_FALSE(coquic::quic::test::runtime_trace_enabled_for_tests());
    }
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "");
        EXPECT_FALSE(coquic::quic::test::runtime_trace_enabled_for_tests());
    }
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "0");
        EXPECT_FALSE(coquic::quic::test::runtime_trace_enabled_for_tests());
    }
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "trace");
        EXPECT_TRUE(coquic::quic::test::runtime_trace_enabled_for_tests());
    }

    const coquic::quic::ConnectionId connection_id = {
        std::byte{0x00},
        std::byte{0x1f},
        std::byte{0xa0},
        std::byte{0xff},
    };
    EXPECT_EQ(coquic::quic::test::format_connection_id_hex_for_tests(connection_id), "001fa0ff");

    const auto key = coquic::quic::test::connection_id_key_for_tests(connection_id);
    EXPECT_EQ(key.size(), connection_id.size());
    EXPECT_EQ(coquic::quic::test::format_connection_id_key_hex_for_tests(key), "001fa0ff");
    EXPECT_TRUE(coquic::quic::test::connection_id_key_for_tests({}).empty());
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksParseServerDatagramRouting) {
    EXPECT_FALSE(coquic::quic::test::parse_server_datagram_for_routing_for_tests({}).has_value());

    const std::array<std::byte, 1> invalid_short_header = {
        std::byte{0x00},
    };
    EXPECT_FALSE(
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(invalid_short_header)
            .has_value());

    std::vector<std::byte> truncated_short_header(kRuntimeConnectionIdLength, std::byte{0x00});
    truncated_short_header.front() = std::byte{0x40};
    EXPECT_FALSE(
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(truncated_short_header)
            .has_value());

    const std::array<std::byte, 1 + kRuntimeConnectionIdLength> short_header = {
        std::byte{0x40}, std::byte{0x83}, std::byte{0x94}, std::byte{0xc8}, std::byte{0xf0},
        std::byte{0x3e}, std::byte{0x51}, std::byte{0x57}, std::byte{0x08},
    };
    const auto parsed_short =
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(short_header);
    ASSERT_TRUE(parsed_short.has_value());
    const auto &parsed_short_datagram = optional_ref_or_terminate(parsed_short);
    EXPECT_EQ(parsed_short_datagram.kind,
              coquic::quic::test::ParsedServerDatagramKind::short_header);
    EXPECT_EQ(parsed_short_datagram.destination_connection_id, (coquic::quic::ConnectionId{
                                                                   std::byte{0x83},
                                                                   std::byte{0x94},
                                                                   std::byte{0xc8},
                                                                   std::byte{0xf0},
                                                                   std::byte{0x3e},
                                                                   std::byte{0x51},
                                                                   std::byte{0x57},
                                                                   std::byte{0x08},
                                                               }));
    EXPECT_FALSE(parsed_short_datagram.source_connection_id.has_value());

    auto unsupported_version = make_unsupported_version_probe();
    auto invalid_long_header = unsupported_version;
    invalid_long_header[0] = std::byte{0x80};
    EXPECT_FALSE(
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(invalid_long_header)
            .has_value());

    const auto unsupported =
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(unsupported_version);
    ASSERT_TRUE(unsupported.has_value());
    const auto &unsupported_datagram = optional_ref_or_terminate(unsupported);
    EXPECT_EQ(unsupported_datagram.kind,
              coquic::quic::test::ParsedServerDatagramKind::unsupported_version_long_header);
    EXPECT_EQ(unsupported_datagram.destination_connection_id, (coquic::quic::ConnectionId{
                                                                  std::byte{0x83},
                                                                  std::byte{0x94},
                                                                  std::byte{0xc8},
                                                                  std::byte{0xf0},
                                                                  std::byte{0x3e},
                                                                  std::byte{0x51},
                                                                  std::byte{0x57},
                                                                  std::byte{0x08},
                                                              }));
    ASSERT_TRUE(unsupported_datagram.source_connection_id.has_value());
    EXPECT_EQ(optional_ref_or_terminate(unsupported_datagram.source_connection_id),
              (coquic::quic::ConnectionId{
                  std::byte{0xc1},
                  std::byte{0x01},
                  std::byte{0x12},
                  std::byte{0x23},
                  std::byte{0x34},
                  std::byte{0x45},
                  std::byte{0x56},
                  std::byte{0x67},
              }));

    auto supported_initial = unsupported_version;
    supported_initial[1] = std::byte{0x00};
    supported_initial[2] = std::byte{0x00};
    supported_initial[3] = std::byte{0x00};
    supported_initial[4] = std::byte{0x01};
    const auto initial =
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(supported_initial);
    ASSERT_TRUE(initial.has_value());
    EXPECT_EQ(optional_ref_or_terminate(initial).kind,
              coquic::quic::test::ParsedServerDatagramKind::supported_initial);

    auto supported_v2_initial = supported_initial;
    supported_v2_initial[0] = std::byte{0xd0};
    supported_v2_initial[1] = std::byte{0x6b};
    supported_v2_initial[2] = std::byte{0x33};
    supported_v2_initial[3] = std::byte{0x43};
    supported_v2_initial[4] = std::byte{0xcf};
    const auto v2_initial =
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(supported_v2_initial);
    ASSERT_TRUE(v2_initial.has_value());
    EXPECT_EQ(optional_ref_or_terminate(v2_initial).kind,
              coquic::quic::test::ParsedServerDatagramKind::supported_initial);

    auto supported_long_header = supported_initial;
    supported_long_header[0] = std::byte{0xe0};
    const auto long_header =
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(supported_long_header);
    ASSERT_TRUE(long_header.has_value());
    EXPECT_EQ(optional_ref_or_terminate(long_header).kind,
              coquic::quic::test::ParsedServerDatagramKind::supported_long_header);

    auto version_negotiation = supported_initial;
    version_negotiation[1] = std::byte{0x00};
    version_negotiation[2] = std::byte{0x00};
    version_negotiation[3] = std::byte{0x00};
    version_negotiation[4] = std::byte{0x00};
    EXPECT_FALSE(
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(version_negotiation)
            .has_value());

    auto truncated_dcid = supported_initial;
    truncated_dcid.resize(14);
    EXPECT_FALSE(coquic::quic::test::parse_server_datagram_for_routing_for_tests(truncated_dcid)
                     .has_value());

    auto truncated_scid = supported_initial;
    truncated_scid.resize(22);
    EXPECT_FALSE(coquic::quic::test::parse_server_datagram_for_routing_for_tests(truncated_scid)
                     .has_value());

    auto missing_token_length = supported_initial;
    missing_token_length.resize(23);
    EXPECT_FALSE(
        coquic::quic::test::parse_server_datagram_for_routing_for_tests(missing_token_length)
            .has_value());

    auto oversized_token = supported_initial;
    oversized_token.resize(24);
    oversized_token[23] = std::byte{0x02};
    EXPECT_FALSE(coquic::quic::test::parse_server_datagram_for_routing_for_tests(oversized_token)
                     .has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeHealthCheckSucceedsWhenDependenciesAreAvailable) {
    const auto runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::health_check,
    };
    EXPECT_EQ(coquic::quic::run_http09_runtime(runtime), 0);
}

TEST(QuicHttp09RuntimeTest, RuntimeReturnsFailureForUnknownMode) {
    const auto runtime = coquic::quic::Http09RuntimeConfig{
        .mode = invalid_runtime_mode(),
    };

    EXPECT_EXIT(std::exit(coquic::quic::run_http09_runtime(runtime)), ::testing::ExitedWithCode(1),
                "");
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenRequestsEnvIsInvalidAtRuntime) {
    coquic::quic::test::ScopedTempDir download_root;

    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .download_root = download_root.path(),
        .requests_env = "definitely-not-a-url",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientMulticonnectStopsWhenAConnectionFails) {
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "invalid-host-name",
        .port = 443,
        .testcase = coquic::quic::QuicHttp09Testcase::multiconnect,
        .server_name = "localhost",
        .requests_env = "https://localhost/a.txt https://localhost/b.txt",
    };

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientConnectionWithoutRequestsCompletesAfterHandshake) {
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
    const auto client = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .server_name = "localhost",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::test::run_http09_client_connection_for_tests(client, {}, 1), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperExtendsClientReceiveTimeoutForMulticonnect) {
    const auto transfer = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::transfer,
    };
    const auto multiconnect = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::client,
        .testcase = coquic::quic::QuicHttp09Testcase::multiconnect,
    };

    EXPECT_EQ(coquic::quic::test::client_receive_timeout_ms_for_tests(transfer), 30000);
    EXPECT_EQ(coquic::quic::test::client_receive_timeout_ms_for_tests(multiconnect), 180000);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperReturnsIdleTimeoutWithoutWakeup) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.poll_fn = &timeout_poll},
    };

    const auto step = coquic::quic::test::wait_for_socket_or_deadline_for_tests(
        /*socket_fd=*/-1, /*idle_timeout_ms=*/5, "client", std::nullopt);

    ASSERT_TRUE(step.has_value());
    const auto &wait_step = optional_ref_or_terminate(step);
    EXPECT_TRUE(wait_step.idle_timeout);
    EXPECT_FALSE(wait_step.has_input);
    EXPECT_FALSE(wait_step.has_source);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperReturnsTimerInputWhenWakeupIsDue) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {.poll_fn = &timeout_poll},
    };

    const auto step = coquic::quic::test::wait_for_socket_or_deadline_for_tests(
        /*socket_fd=*/-1, /*idle_timeout_ms=*/50, "client", runtime_now());

    ASSERT_TRUE(step.has_value());
    const auto &wait_step = optional_ref_or_terminate(step);
    EXPECT_FALSE(wait_step.idle_timeout);
    EXPECT_TRUE(wait_step.has_input);
    EXPECT_TRUE(wait_step.input_is_timer_expired);
    EXPECT_FALSE(wait_step.has_source);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksSelectEarliestWakeupAcrossEntries) {
    const auto base = runtime_now();
    const std::array<std::optional<coquic::quic::QuicCoreTimePoint>, 4> wakeups = {
        std::nullopt,
        base + std::chrono::milliseconds(30),
        base + std::chrono::milliseconds(5),
        base + std::chrono::milliseconds(15),
    };

    const auto earliest = coquic::quic::test::earliest_runtime_wakeup_for_tests(wakeups);
    ASSERT_TRUE(earliest.has_value());
    EXPECT_EQ(optional_value_or_terminate(earliest), optional_value_or_terminate(wakeups[2]));

    const std::array<std::optional<coquic::quic::QuicCoreTimePoint>, 2> empty_wakeups = {
        std::nullopt,
        std::nullopt,
    };
    EXPECT_FALSE(coquic::quic::test::earliest_runtime_wakeup_for_tests(empty_wakeups).has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimeConfiguresLinuxSocketsForReceivingEcnMetadata) {
    EXPECT_TRUE(coquic::quic::test::runtime_configures_linux_ecn_socket_options_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeUsesSendmsgToApplyOutboundEcnMarkings) {
    EXPECT_TRUE(coquic::quic::test::runtime_sendmsg_uses_outbound_ecn_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeUsesIpTosForIpv4MappedIpv6OutboundEcnMarkings) {
    EXPECT_TRUE(
        coquic::quic::test::runtime_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeMapsRecvmsgEcnMetadataIntoCoreInputs) {
    EXPECT_TRUE(coquic::quic::test::runtime_recvmsg_maps_ecn_to_core_input_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksDriveEndpointUntilBlockedFailureCases) {
    const auto handle_core_effects_fail =
        coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
            coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::handle_core_effects_fail);
    EXPECT_FALSE(handle_core_effects_fail.returned);
    EXPECT_TRUE(handle_core_effects_fail.terminal_failure);
    EXPECT_FALSE(handle_core_effects_fail.terminal_success);

    const auto initial_local_error =
        coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
            coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::initial_local_error);
    EXPECT_FALSE(initial_local_error.returned);
    EXPECT_TRUE(initial_local_error.terminal_failure);
    EXPECT_FALSE(initial_local_error.terminal_success);

    const auto initial_local_error_handled =
        coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
            coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::initial_local_error_handled);
    EXPECT_TRUE(initial_local_error_handled.returned);
    EXPECT_FALSE(initial_local_error_handled.terminal_failure);
    EXPECT_FALSE(initial_local_error_handled.terminal_success);

    const auto endpoint_failure = coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
        coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::endpoint_failure);
    EXPECT_FALSE(endpoint_failure.returned);
    EXPECT_TRUE(endpoint_failure.terminal_failure);
    EXPECT_FALSE(endpoint_failure.terminal_success);

    const auto endpoint_inputs_then_core_error =
        coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
            coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::
                endpoint_inputs_then_core_error);
    EXPECT_FALSE(endpoint_inputs_then_core_error.returned);
    EXPECT_TRUE(endpoint_inputs_then_core_error.terminal_failure);
    EXPECT_FALSE(endpoint_inputs_then_core_error.terminal_success);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksDriveEndpointUntilBlockedSuccessCase) {
    const auto success = coquic::quic::test::drive_endpoint_until_blocked_case_for_tests(
        coquic::quic::test::DriveEndpointUntilBlockedCaseForTests::endpoint_success);
    EXPECT_TRUE(success.returned);
    EXPECT_TRUE(success.terminal_success);
    EXPECT_FALSE(success.terminal_failure);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksDriveClientConnectionLoopCases) {
    const auto initial_terminal_success =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::initial_terminal_success);
    EXPECT_EQ(initial_terminal_success.exit_code, 0);
    EXPECT_TRUE(initial_terminal_success.terminal_success);
    EXPECT_FALSE(initial_terminal_success.terminal_failure);

    const auto timer_due_then_wait_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::timer_due_then_wait_failure);
    EXPECT_EQ(timer_due_then_wait_failure.exit_code, 1);
    EXPECT_FALSE(timer_due_then_wait_failure.terminal_success);
    EXPECT_FALSE(timer_due_then_wait_failure.terminal_failure);

    const auto timer_due_then_drive_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::timer_due_then_drive_failure);
    EXPECT_EQ(timer_due_then_drive_failure.exit_code, 1);
    EXPECT_TRUE(timer_due_then_drive_failure.terminal_failure);

    const auto outer_timer_then_wait_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::outer_timer_then_wait_failure);
    EXPECT_EQ(outer_timer_then_wait_failure.exit_code, 1);
    EXPECT_FALSE(outer_timer_then_wait_failure.terminal_failure);

    const auto outer_timer_then_drive_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::outer_timer_then_drive_failure);
    EXPECT_EQ(outer_timer_then_drive_failure.exit_code, 1);
    EXPECT_TRUE(outer_timer_then_drive_failure.terminal_failure);

    const auto pending_work_terminal_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::pending_work_terminal_failure);
    EXPECT_EQ(pending_work_terminal_failure.exit_code, 1);
    EXPECT_TRUE(pending_work_terminal_failure.terminal_failure);

    const auto pending_work_default_poll_then_wait_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                pending_work_default_poll_then_wait_failure);
    EXPECT_EQ(pending_work_default_poll_then_wait_failure.exit_code, 1);
    EXPECT_FALSE(pending_work_default_poll_then_wait_failure.terminal_failure);

    const auto pending_work_no_inputs_then_idle_timeout =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                pending_work_no_inputs_then_idle_timeout);
    EXPECT_EQ(pending_work_no_inputs_then_idle_timeout.exit_code, 1);
    EXPECT_FALSE(pending_work_no_inputs_then_idle_timeout.terminal_success);
    EXPECT_FALSE(pending_work_no_inputs_then_idle_timeout.terminal_failure);

    const auto receive_error_after_nonblocking_drain =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                receive_error_after_nonblocking_drain);
    EXPECT_EQ(receive_error_after_nonblocking_drain.exit_code, 1);

    const auto receive_input_then_drive_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::receive_input_then_drive_failure);
    EXPECT_EQ(receive_input_then_drive_failure.exit_code, 1);
    EXPECT_TRUE(receive_input_then_drive_failure.terminal_failure);

    const auto wait_failure = coquic::quic::test::run_client_connection_loop_case_for_tests(
        coquic::quic::test::ClientConnectionLoopCaseForTests::wait_failure);
    EXPECT_EQ(wait_failure.exit_code, 1);
    EXPECT_FALSE(wait_failure.terminal_success);
    EXPECT_FALSE(wait_failure.terminal_failure);

    const auto outer_pump_terminal_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::outer_pump_terminal_failure);
    EXPECT_EQ(outer_pump_terminal_failure.exit_code, 1);
    EXPECT_TRUE(outer_pump_terminal_failure.terminal_failure);

    const auto outer_pump_terminal_success =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::outer_pump_terminal_success);
    EXPECT_EQ(outer_pump_terminal_success.exit_code, 0);
    EXPECT_TRUE(outer_pump_terminal_success.terminal_success);

    const auto wait_input_then_terminal_success =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::wait_input_then_terminal_success);
    EXPECT_EQ(wait_input_then_terminal_success.exit_code, 0);
    EXPECT_TRUE(wait_input_then_terminal_success.terminal_success);
    EXPECT_FALSE(wait_input_then_terminal_success.terminal_failure);

    const auto wait_input_then_terminal_success_with_followup_input =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                wait_input_then_terminal_success_with_followup_input);
    EXPECT_EQ(wait_input_then_terminal_success_with_followup_input.exit_code, 0);
    EXPECT_TRUE(wait_input_then_terminal_success_with_followup_input.terminal_success);
    EXPECT_FALSE(wait_input_then_terminal_success_with_followup_input.terminal_failure);
    EXPECT_GE(wait_input_then_terminal_success_with_followup_input.wait_calls, 2u);

    const auto wait_input_then_drive_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::wait_input_then_drive_failure);
    EXPECT_EQ(wait_input_then_drive_failure.exit_code, 1);
    EXPECT_TRUE(wait_input_then_drive_failure.terminal_failure);

    const auto wait_input_missing_failure =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::wait_input_missing_failure);
    EXPECT_EQ(wait_input_missing_failure.exit_code, 1);
    EXPECT_FALSE(wait_input_missing_failure.terminal_success);
    EXPECT_FALSE(wait_input_missing_failure.terminal_failure);

    const auto peer_input_then_outer_pump_terminal_success =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                peer_input_then_outer_pump_terminal_success);
    EXPECT_EQ(peer_input_then_outer_pump_terminal_success.exit_code, 0);
    EXPECT_TRUE(peer_input_then_outer_pump_terminal_success.terminal_success);
    EXPECT_GE(peer_input_then_outer_pump_terminal_success.current_time_calls, 4u);

    const auto wait_input_then_terminal_success_exits_after_drain_window =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                wait_input_then_terminal_success_exits_after_drain_window);
    EXPECT_EQ(wait_input_then_terminal_success_exits_after_drain_window.exit_code, 0);
    EXPECT_TRUE(wait_input_then_terminal_success_exits_after_drain_window.terminal_success);

    const auto nonblocking_drain_repeats_pending_endpoint_progress =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                nonblocking_drain_repeats_pending_endpoint_progress);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.exit_code, 0);
    EXPECT_TRUE(nonblocking_drain_repeats_pending_endpoint_progress.terminal_success);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.wait_calls, 0u);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.receive_calls, 2u);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksCoverServerFailureCleanupAndLoopCases) {
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "trace");
        EXPECT_TRUE(coquic::quic::test::existing_server_session_failure_cleans_up_for_tests());
    }

    EXPECT_TRUE(coquic::quic::test::existing_server_session_failure_cleans_up_for_tests());
    EXPECT_TRUE(coquic::quic::test::existing_server_session_missing_input_fails_for_tests());
    EXPECT_TRUE(
        coquic::quic::test::supported_long_header_routes_via_initial_destination_for_tests());
    EXPECT_TRUE(coquic::quic::test::expired_server_timer_failure_cleans_up_for_tests());
    EXPECT_TRUE(coquic::quic::test::expired_server_timer_success_preserves_session_for_tests());
    EXPECT_TRUE(coquic::quic::test::pending_server_work_failure_cleans_up_for_tests());
    EXPECT_TRUE(
        coquic::quic::test::version_negotiation_without_source_connection_id_fails_for_tests());

    const auto nonblocking_processed_timers_then_receive_error =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                nonblocking_processed_timers_then_receive_error);
    EXPECT_EQ(nonblocking_processed_timers_then_receive_error.exit_code, 1);
    EXPECT_EQ(nonblocking_processed_timers_then_receive_error.receive_calls, 1U);
    EXPECT_EQ(nonblocking_processed_timers_then_receive_error.wait_calls, 0U);
    EXPECT_EQ(nonblocking_processed_timers_then_receive_error.process_expired_calls, 2U);

    const auto nonblocking_process_datagram_failure =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::nonblocking_process_datagram_failure);
    EXPECT_EQ(nonblocking_process_datagram_failure.exit_code, 1);
    EXPECT_EQ(nonblocking_process_datagram_failure.receive_calls, 1U);
    EXPECT_EQ(nonblocking_process_datagram_failure.wait_calls, 0U);
    EXPECT_EQ(nonblocking_process_datagram_failure.process_expired_calls, 1U);

    const auto blocking_timer_then_receive_error =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::blocking_timer_then_receive_error);
    EXPECT_EQ(blocking_timer_then_receive_error.exit_code, 1);
    EXPECT_EQ(blocking_timer_then_receive_error.receive_calls, 2U);
    EXPECT_EQ(blocking_timer_then_receive_error.wait_calls, 1U);
    EXPECT_EQ(blocking_timer_then_receive_error.process_expired_calls, 4U);

    const auto blocking_processed_timers_then_receive_error =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                blocking_processed_timers_then_receive_error);
    EXPECT_EQ(blocking_processed_timers_then_receive_error.exit_code, 1);
    EXPECT_EQ(blocking_processed_timers_then_receive_error.receive_calls, 2U);
    EXPECT_EQ(blocking_processed_timers_then_receive_error.wait_calls, 0U);
    EXPECT_EQ(blocking_processed_timers_then_receive_error.process_expired_calls, 3U);

    const auto blocking_wait_failure = coquic::quic::test::run_server_loop_case_for_tests(
        coquic::quic::test::ServerLoopCaseForTests::blocking_wait_failure);
    EXPECT_EQ(blocking_wait_failure.exit_code, 1);
    EXPECT_EQ(blocking_wait_failure.receive_calls, 1U);
    EXPECT_EQ(blocking_wait_failure.wait_calls, 1U);
    EXPECT_EQ(blocking_wait_failure.process_expired_calls, 2U);

    const auto blocking_wait_missing_input = coquic::quic::test::run_server_loop_case_for_tests(
        coquic::quic::test::ServerLoopCaseForTests::blocking_wait_missing_input);
    EXPECT_EQ(blocking_wait_missing_input.exit_code, 1);
    EXPECT_EQ(blocking_wait_missing_input.receive_calls, 1U);
    EXPECT_EQ(blocking_wait_missing_input.wait_calls, 1U);
    EXPECT_EQ(blocking_wait_missing_input.process_expired_calls, 2U);

    const auto nonblocking_drain_repeats_pending_endpoint_progress =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                nonblocking_drain_repeats_pending_endpoint_progress);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.exit_code, 1);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.receive_calls, 3U);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.wait_calls, 0U);
    EXPECT_EQ(nonblocking_drain_repeats_pending_endpoint_progress.pump_calls, 2U);

    const auto outer_pump_repeats_pending_endpoint_progress =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                outer_pump_repeats_pending_endpoint_progress);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.exit_code, 1);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.receive_calls, 2U);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.wait_calls, 0U);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.process_expired_calls, 3U);
    EXPECT_EQ(outer_pump_repeats_pending_endpoint_progress.pump_calls, 2U);

    const auto ready_datagram_preempts_next_pending_work_pump =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                ready_datagram_preempts_next_pending_work_pump);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.exit_code, 1);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.receive_calls, 2U);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.wait_calls, 0U);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.process_expired_calls, 2U);
    EXPECT_EQ(ready_datagram_preempts_next_pending_work_pump.pump_calls, 1U);

    const auto pending_endpoint_without_transport_progress_waits_instead_of_spinning =
        coquic::quic::test::run_server_loop_case_for_tests(
            coquic::quic::test::ServerLoopCaseForTests::
                pending_endpoint_without_transport_progress_waits_instead_of_spinning);
    EXPECT_EQ(pending_endpoint_without_transport_progress_waits_instead_of_spinning.exit_code, 1);
    EXPECT_EQ(pending_endpoint_without_transport_progress_waits_instead_of_spinning.receive_calls,
              1U);
    EXPECT_EQ(pending_endpoint_without_transport_progress_waits_instead_of_spinning.wait_calls, 1U);
    EXPECT_EQ(pending_endpoint_without_transport_progress_waits_instead_of_spinning.pump_calls, 2U);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksCoverRetryAndZeroRttBranches) {
    testing::internal::CaptureStderr();
    EXPECT_TRUE(coquic::quic::test::retry_context_lookup_for_tests());
    EXPECT_TRUE(coquic::quic::test::invalid_retry_token_server_datagram_path_for_tests());
    EXPECT_TRUE(coquic::quic::test::resumed_client_warmup_failure_exits_early_for_tests());
    ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
    EXPECT_TRUE(coquic::quic::test::retry_trace_paths_for_tests());
    EXPECT_TRUE(coquic::quic::test::send_retry_for_initial_failures_for_tests());
    EXPECT_TRUE(coquic::quic::test::zero_rtt_request_allowance_for_tests());
    static_cast<void>(testing::internal::GetCapturedStderr());
}

TEST(QuicHttp09RuntimeTest, RuntimeAssignsStablePathIdsPerPeerTuple) {
    EXPECT_TRUE(coquic::quic::test::runtime_assigns_stable_path_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, PreferredAddressCidRoutesToExistingServerSession) {
    EXPECT_TRUE(
        coquic::quic::test::preferred_address_routes_to_existing_server_session_for_tests());
}

TEST(QuicHttp09RuntimeTest, DriveEndpointUsesTransportSelectedPathAndSocket) {
    EXPECT_TRUE(coquic::quic::test::drive_endpoint_uses_transport_selected_path_for_tests());
}

TEST(QuicHttp09RuntimeTest, DeferredReplayPreservesIndividualBufferedPathIds) {
    coquic::quic::QuicConnection connection(coquic::quic::QuicCoreConfig{
        .role = coquic::quic::EndpointRole::client,
        .source_connection_id = {std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x02}},
    });
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto first_deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
    };
    const auto second_deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
    };
    connection.process_inbound_datagram(first_deferred, coquic::quic::test::test_time(1),
                                        /*path_id=*/11);
    connection.process_inbound_datagram(second_deferred, coquic::quic::test::test_time(2),
                                        /*path_id=*/22);
    ASSERT_GE(connection.deferred_protected_packets_.size(), 2u);

    connection.current_send_path_id_.reset();
    connection.replay_deferred_protected_packets(coquic::quic::test::test_time(3));

    ASSERT_TRUE(connection.current_send_path_id_.has_value());
    EXPECT_EQ(connection.current_send_path_id_.value_or(0), 11u);
}

TEST(QuicHttp09RuntimeTest, DeferredReplayKeepsDistinctPathsForIdenticalPayloads) {
    coquic::quic::QuicConnection connection(coquic::quic::QuicCoreConfig{
        .role = coquic::quic::EndpointRole::client,
        .source_connection_id = {std::byte{0x01}},
        .initial_destination_connection_id = {std::byte{0x02}},
    });
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;

    const auto deferred = std::vector<std::byte>{
        std::byte{0x40}, std::byte{0x0a}, std::byte{0x0b}, std::byte{0x0c}, std::byte{0x0d},
    };
    connection.process_inbound_datagram(deferred, coquic::quic::test::test_time(1), /*path_id=*/11);
    connection.process_inbound_datagram(deferred, coquic::quic::test::test_time(2), /*path_id=*/22);

    ASSERT_EQ(connection.deferred_protected_packets_.size(), 2u);
    EXPECT_EQ(connection.deferred_protected_packets_[0].bytes, deferred);
    EXPECT_EQ(connection.deferred_protected_packets_[0].path_id, 11u);
    EXPECT_EQ(connection.deferred_protected_packets_[1].bytes, deferred);
    EXPECT_EQ(connection.deferred_protected_packets_[1].path_id, 22u);
}

TEST(QuicHttp09RuntimeTest, CoreVersionNegotiationRestartPreservesInboundPathIds) {
    EXPECT_TRUE(coquic::quic::test::
                    core_version_negotiation_restart_preserves_inbound_path_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, CoreRetryRestartPreservesInboundPathIds) {
    EXPECT_TRUE(coquic::quic::test::core_retry_restart_preserves_inbound_path_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, DriveEndpointRejectsUnknownTransportSelectedPath) {
    EXPECT_TRUE(
        coquic::quic::test::drive_endpoint_rejects_unknown_transport_selected_path_for_tests());
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigAdvertisesPreferredAddress) {
    EXPECT_TRUE(
        coquic::quic::test::server_connectionmigration_preferred_address_config_for_tests());
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigIncludesPreferredAddressResetToken) {
    const auto core =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        });

    ASSERT_TRUE(core.transport.preferred_address.has_value());
    const auto preferred_address =
        core.transport.preferred_address.value_or(coquic::quic::PreferredAddress{});
    EXPECT_FALSE(std::all_of(preferred_address.stateless_reset_token.begin(),
                             preferred_address.stateless_reset_token.end(),
                             [](std::byte byte) { return byte == std::byte{0x00}; }));
}

TEST(QuicHttp09RuntimeTest, ConnectionMigrationServerConfigUsesConcreteAddressForWildcardHost) {
    ScopedEnvVar hostname("HOSTNAME", "interop-server-host");
    ScopedFreeaddrinfoCounterReset freeaddrinfo_counter;
    ScopedRuntimeAddressFamilyReset address_family_reset;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops(
        coquic::quic::test::Http09RuntimeOpsOverride{
            .getaddrinfo_fn = hostname_ipv6_getaddrinfo,
            .freeaddrinfo_fn = counting_freeaddrinfo,
        });

    const auto core =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "::",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::connectionmigration,
        });

    ASSERT_TRUE(core.transport.preferred_address.has_value());
    const auto preferred_address =
        core.transport.preferred_address.value_or(coquic::quic::PreferredAddress{});
    EXPECT_EQ(g_last_getaddrinfo_family, AF_INET6);
    EXPECT_EQ(g_freeaddrinfo_calls, 1);
    EXPECT_EQ(preferred_address.ipv6_port, 444);
    EXPECT_EQ(preferred_address.ipv6_address, (std::array<std::byte, 16>{
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
                                              }));
}

TEST(QuicHttp09RuntimeTest, RuntimeQueuesPreferredAddressMigrationRequestAfterHandshakeConfirmed) {
    EXPECT_TRUE(coquic::quic::test::runtime_connectionmigration_request_flow_for_tests());
}

TEST(QuicHttp09RuntimeTest,
     OfficialConnectionMigrationClientRequestQueuesPreferredAddressMigration) {
    EXPECT_TRUE(
        coquic::quic::test::runtime_official_connectionmigration_client_request_flow_for_tests());
}

TEST(QuicHttp09RuntimeTest, CrossFamilyPreferredAddressUsesCompatibleSocket) {
    EXPECT_TRUE(coquic::quic::test::
                    runtime_cross_family_preferred_address_uses_compatible_socket_for_tests());
}

TEST(QuicHttp09RuntimeTest, ClientLoopUsesAllActiveSocketsForPreferredAddress) {
    EXPECT_TRUE(coquic::quic::test::runtime_client_loop_uses_all_active_sockets_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeProcessesPolicyInputsBeforeTerminalSuccess) {
    EXPECT_TRUE(
        coquic::quic::test::runtime_policy_core_inputs_advance_before_terminal_success_for_tests());
}

TEST(QuicHttp09RuntimeTest, RegularTransferDoesNotQueuePreferredAddressMigration) {
    EXPECT_TRUE(
        coquic::quic::test::
            runtime_regular_transfer_does_not_queue_preferred_address_migration_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeRegistersAllServerCoreConnectionIdsForRouting) {
    EXPECT_TRUE(coquic::quic::test::runtime_registers_all_server_core_connection_ids_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeMiscInternalCoverageHooksExerciseFallbackPaths) {
    testing::internal::CaptureStderr();
    const bool covered = coquic::quic::test::runtime_misc_internal_coverage_for_tests();
    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_TRUE(covered) << stderr_output;
}

TEST(QuicHttp09RuntimeTest, RuntimeInternalCoverageHooksExerciseRemainingBranches) {
    testing::internal::CaptureStderr();
    const bool covered = coquic::quic::test::runtime_additional_internal_coverage_for_tests();
    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_TRUE(covered) << stderr_output;
}

TEST(QuicHttp09RuntimeTest, RuntimeConnectionMigrationFailureHooksExerciseFalseBranches) {
    EXPECT_TRUE(coquic::quic::test::runtime_connectionmigration_failure_paths_for_tests());
}

TEST(QuicHttp09RuntimeTest, RuntimeRestartFailureHooksExerciseRestartFailures) {
    EXPECT_TRUE(coquic::quic::test::runtime_restart_failure_paths_for_tests());
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRouteHelperErasesFailedSession) {
    const auto make_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };
    const auto make_secret = [](std::byte fill) {
        return coquic::quic::TrafficSecret{
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .secret = std::vector<std::byte>(32, fill),
        };
    };
    const auto make_connected_runtime_server_connection =
        [&](const coquic::quic::QuicCoreConfig &config) {
            coquic::quic::QuicConnection connection(config);
            connection.started_ = true;
            connection.status_ = coquic::quic::HandshakeStatus::connected;
            connection.handshake_confirmed_ = true;
            connection.peer_address_validated_ = true;
            connection.peer_source_connection_id_ = make_runtime_connection_id(std::byte{0xc1}, 3);
            connection.client_initial_destination_connection_id_ =
                make_runtime_connection_id(std::byte{0x83}, 2);
            connection.local_transport_parameters_ = coquic::quic::TransportParameters{
                .original_destination_connection_id =
                    connection.client_initial_destination_connection_id_,
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.config_.source_connection_id,
            };
            connection.initialize_local_flow_control();
            connection.application_space_.read_secret = make_secret(std::byte{0x21});
            connection.application_space_.write_secret = make_secret(std::byte{0x31});
            connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.peer_source_connection_id_,
            };
            connection.peer_transport_parameters_validated_ = true;
            connection.initialize_peer_flow_control_from_transport_parameters();
            return connection;
        };

    auto core_config =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_addr,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;

    const auto local_connection_id = connection.config_.source_connection_id;
    const auto initial_destination_connection_id =
        connection.client_initial_destination_connection_id();
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 77,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 0,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    connection.mark_failed();

    const auto peer = make_peer(39968);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, /*established_socket_fd=*/31, peer, peer_len, local_connection_id,
        initial_destination_connection_id, /*inbound_socket_fd=*/31, peer, peer_len,
        encoded.value(), coquic::quic::test::test_time(1));

    EXPECT_TRUE(route.processed);
    EXPECT_TRUE(route.erased);
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRoutesLiveLikeMigrationRetransmitOnNewPath) {
    const auto make_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return peer;
    };
    const auto make_secret = [](std::byte fill) {
        return coquic::quic::TrafficSecret{
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .secret = std::vector<std::byte>(32, fill),
        };
    };
    const auto make_connected_runtime_server_connection =
        [&](const coquic::quic::QuicCoreConfig &config) {
            coquic::quic::QuicConnection connection(config);
            connection.started_ = true;
            connection.status_ = coquic::quic::HandshakeStatus::connected;
            connection.handshake_confirmed_ = true;
            connection.peer_address_validated_ = true;
            connection.peer_source_connection_id_ = make_runtime_connection_id(std::byte{0xc1}, 3);
            connection.client_initial_destination_connection_id_ =
                make_runtime_connection_id(std::byte{0x83}, 2);
            connection.local_transport_parameters_ = coquic::quic::TransportParameters{
                .original_destination_connection_id =
                    connection.client_initial_destination_connection_id_,
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.config_.source_connection_id,
            };
            connection.initialize_local_flow_control();
            connection.application_space_.read_secret = make_secret(std::byte{0x21});
            connection.application_space_.write_secret = make_secret(std::byte{0x31});
            connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.peer_source_connection_id_,
            };
            connection.peer_transport_parameters_validated_ = true;
            connection.initialize_peer_flow_control_from_transport_parameters();
            return connection;
        };

    auto core_config =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "127.0.0.1",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_addr,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 8241;
    connection.last_validated_path_id_ = 1;
    connection.current_send_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(1).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(0,
                                       coquic::quic::test::bytes_from_string(
                                           std::string(static_cast<std::size_t>(512) * 1024u, 'm')),
                                       false)
                    .has_value());

    for (std::size_t i = 0; i < 131; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(static_cast<std::int64_t>(i) + 1));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 1u);
    }
    for (std::size_t i = 0; i < 22; ++i) {
        const auto datagram = connection.drain_outbound_datagram(
            coquic::quic::test::test_time(132 + static_cast<std::int64_t>(i)));
        ASSERT_FALSE(datagram.empty());
        EXPECT_EQ(connection.last_drained_path_id(), 1u);
    }

    const auto first_gap_packet = connection.application_space_.sent_packets.at(8372);
    ASSERT_FALSE(first_gap_packet.stream_fragments.empty());
    const auto tracked_gap_offset = first_gap_packet.stream_fragments.front().offset;

    ASSERT_TRUE(connection
                    .process_inbound_application(
                        std::vector<coquic::quic::Frame>{
                            coquic::quic::AckFrame{
                                .largest_acknowledged = 8371,
                                .first_ack_range = 8371 - 8241,
                            },
                        },
                        coquic::quic::test::test_time(99), /*allow_preconnected_frames=*/false,
                        /*path_id=*/2)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;

    const auto migration_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(100));
    ASSERT_FALSE(migration_datagram.empty());
    ASSERT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{2});
    ASSERT_TRUE(connection.paths_.contains(2));
    ASSERT_TRUE(connection.paths_.at(2).outstanding_challenge.has_value());
    const auto challenge = optional_ref_or_terminate(connection.paths_.at(2).outstanding_challenge);
    ASSERT_EQ(std::prev(connection.application_space_.sent_packets.end())->first, 8394u);

    const auto local_connection_id = connection.config_.source_connection_id;
    const auto initial_destination_connection_id =
        connection.client_initial_destination_connection_id();
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 1759,
                .frames =
                    {
                        coquic::quic::PathResponseFrame{.data = challenge},
                        coquic::quic::AckFrame{
                            .largest_acknowledged = 8394,
                            .first_ack_range = 0,
                            .additional_ranges =
                                {
                                    coquic::quic::AckRange{
                                        .gap = 21,
                                        .range_length = 8371 - 8241,
                                    },
                                },
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    const auto old_peer = make_peer(39968);
    const auto new_peer = make_peer(38910);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in));
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, /*established_socket_fd=*/31, old_peer, peer_len, local_connection_id,
        initial_destination_connection_id, /*inbound_socket_fd=*/77, new_peer, peer_len,
        encoded.value(), coquic::quic::test::test_time(101));

    ASSERT_TRUE(route.processed);
    EXPECT_FALSE(route.erased);
    EXPECT_TRUE(route.has_migrated_path_route);
    EXPECT_EQ(route.migrated_path_socket_fd, 77);
    EXPECT_GT(route.sendto_calls, 0);
    EXPECT_EQ(route.sendto_socket_fd, 77);
    EXPECT_EQ(route.sendto_peer_port, 38910);

    const auto &post_connection = *server.connection_;
    EXPECT_EQ(post_connection.current_send_path_id_, std::optional<coquic::quic::QuicPathId>{2});

    bool saw_retransmit_for_gap_offset = false;
    for (const auto &[packet_number, packet] : post_connection.application_space_.sent_packets) {
        static_cast<void>(packet_number);
        for (const auto &fragment : packet.stream_fragments) {
            if (fragment.offset == tracked_gap_offset) {
                saw_retransmit_for_gap_offset = true;
            }
        }
    }

    EXPECT_TRUE(saw_retransmit_for_gap_offset);
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRoutesSecondRebindToLatestIpv6Peer) {
    const auto make_peer = [](std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(port);
        ipv6.sin6_addr = in6addr_loopback;
        return peer;
    };
    const auto make_secret = [](std::byte fill) {
        return coquic::quic::TrafficSecret{
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .secret = std::vector<std::byte>(32, fill),
        };
    };
    const auto make_connected_runtime_server_connection =
        [&](const coquic::quic::QuicCoreConfig &config) {
            coquic::quic::QuicConnection connection(config);
            connection.started_ = true;
            connection.status_ = coquic::quic::HandshakeStatus::connected;
            connection.handshake_confirmed_ = true;
            connection.peer_address_validated_ = true;
            connection.peer_source_connection_id_ = make_runtime_connection_id(std::byte{0xc1}, 3);
            connection.client_initial_destination_connection_id_ =
                make_runtime_connection_id(std::byte{0x83}, 2);
            connection.local_transport_parameters_ = coquic::quic::TransportParameters{
                .original_destination_connection_id =
                    connection.client_initial_destination_connection_id_,
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.config_.source_connection_id,
            };
            connection.initialize_local_flow_control();
            connection.application_space_.read_secret = make_secret(std::byte{0x21});
            connection.application_space_.write_secret = make_secret(std::byte{0x31});
            connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.peer_source_connection_id_,
            };
            connection.peer_transport_parameters_validated_ = true;
            connection.initialize_peer_flow_control_from_transport_parameters();
            return connection;
        };

    auto core_config =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "::1",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_port,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 900;
    connection.last_validated_path_id_ = 2;
    connection.current_send_path_id_ = 2;
    connection.previous_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(2).validated = true;
    connection.ensure_path_state(2).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'r')), false)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;

    const auto path2_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path2_datagram.empty());
    ASSERT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{2});

    ASSERT_FALSE(connection.application_space_.sent_packets.empty());
    const auto largest_sent_packet =
        std::prev(connection.application_space_.sent_packets.end())->first;

    const auto local_connection_id = connection.config_.source_connection_id;
    const auto initial_destination_connection_id =
        connection.client_initial_destination_connection_id();
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 77,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_packet,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    const auto original_peer = make_peer(38910);
    const auto first_rebind_peer = make_peer(39968);
    const auto second_rebind_peer = make_peer(40926);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6));
    const std::array seeded_paths{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, seeded_paths, local_connection_id, initial_destination_connection_id,
        /*inbound_socket_fd=*/77, second_rebind_peer, peer_len, encoded.value(),
        coquic::quic::test::test_time(2));

    ASSERT_TRUE(route.processed);
    EXPECT_FALSE(route.erased);
    EXPECT_GT(route.sendto_calls, 0);
    EXPECT_EQ(route.sendto_socket_fd, 77);
    EXPECT_EQ(route.sendto_peer_port, 40926);

    ASSERT_TRUE(server.connection_->paths_.contains(3));
    ASSERT_TRUE(server.connection_->paths_.at(3).outstanding_challenge.has_value());
    const auto second_rebind_challenge =
        optional_ref_or_terminate(server.connection_->paths_.at(3).outstanding_challenge);
    const auto largest_sent_after_second_rebind =
        std::prev(server.connection_->application_space_.sent_packets.end())->first;

    const auto path_response_encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = server.connection_->application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 78,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_after_second_rebind,
                            .first_ack_range = 0,
                        },
                        coquic::quic::PathResponseFrame{
                            .data = second_rebind_challenge,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = server.connection_->application_space_.read_secret,
            .one_rtt_key_phase = server.connection_->application_read_key_phase_,
        });
    ASSERT_TRUE(path_response_encoded.has_value());

    const std::array seeded_paths_after_second_rebind{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = second_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto path_response_route =
        coquic::quic::test::route_existing_server_session_datagram_for_tests(
            server, seeded_paths_after_second_rebind, local_connection_id,
            initial_destination_connection_id, /*inbound_socket_fd=*/77, second_rebind_peer,
            peer_len, path_response_encoded.value(), coquic::quic::test::test_time(3));

    ASSERT_TRUE(path_response_route.processed);
    EXPECT_FALSE(path_response_route.erased);
    EXPECT_GT(path_response_route.sendto_calls, 0);
    EXPECT_EQ(path_response_route.sendto_socket_fd, 77);
    EXPECT_EQ(path_response_route.sendto_peer_port, 40926);
    ASSERT_TRUE(server.connection_->paths_.contains(3));
    EXPECT_TRUE(server.connection_->paths_.at(3).validated);
    EXPECT_EQ(server.connection_->current_send_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
    EXPECT_EQ(server.connection_->last_validated_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRoutesSecondRebindToLatestV4MappedPeer) {
    const auto make_peer = [](std::array<std::uint8_t, 4> ipv4_octets, std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(port);
        ipv6.sin6_addr = IN6ADDR_ANY_INIT;
        ipv6.sin6_addr.s6_addr[10] = 0xff;
        ipv6.sin6_addr.s6_addr[11] = 0xff;
        ipv6.sin6_addr.s6_addr[12] = ipv4_octets[0];
        ipv6.sin6_addr.s6_addr[13] = ipv4_octets[1];
        ipv6.sin6_addr.s6_addr[14] = ipv4_octets[2];
        ipv6.sin6_addr.s6_addr[15] = ipv4_octets[3];
        return peer;
    };
    const auto make_secret = [](std::byte fill) {
        return coquic::quic::TrafficSecret{
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .secret = std::vector<std::byte>(32, fill),
        };
    };
    const auto make_connected_runtime_server_connection =
        [&](const coquic::quic::QuicCoreConfig &config) {
            coquic::quic::QuicConnection connection(config);
            connection.started_ = true;
            connection.status_ = coquic::quic::HandshakeStatus::connected;
            connection.handshake_confirmed_ = true;
            connection.peer_address_validated_ = true;
            connection.peer_source_connection_id_ = make_runtime_connection_id(std::byte{0xc1}, 3);
            connection.client_initial_destination_connection_id_ =
                make_runtime_connection_id(std::byte{0x83}, 2);
            connection.local_transport_parameters_ = coquic::quic::TransportParameters{
                .original_destination_connection_id =
                    connection.client_initial_destination_connection_id_,
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.config_.source_connection_id,
            };
            connection.initialize_local_flow_control();
            connection.application_space_.read_secret = make_secret(std::byte{0x21});
            connection.application_space_.write_secret = make_secret(std::byte{0x31});
            connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.peer_source_connection_id_,
            };
            connection.peer_transport_parameters_validated_ = true;
            connection.initialize_peer_flow_control_from_transport_parameters();
            return connection;
        };

    auto core_config =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "::",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_port,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 900;
    connection.last_validated_path_id_ = 2;
    connection.current_send_path_id_ = 2;
    connection.previous_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(2).validated = true;
    connection.ensure_path_state(2).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'r')), false)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;

    const auto path2_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path2_datagram.empty());
    ASSERT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{2});

    ASSERT_FALSE(connection.application_space_.sent_packets.empty());
    const auto largest_sent_packet =
        std::prev(connection.application_space_.sent_packets.end())->first;

    const auto local_connection_id = connection.config_.source_connection_id;
    const auto initial_destination_connection_id =
        connection.client_initial_destination_connection_id();
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 77,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_packet,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    const auto original_peer = make_peer({193, 167, 0, 100}, 38910);
    const auto first_rebind_peer = make_peer({193, 167, 0, 100}, 57607);
    const auto second_rebind_peer = make_peer({193, 167, 0, 100}, 59022);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6));
    const std::array seeded_paths{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, seeded_paths, local_connection_id, initial_destination_connection_id,
        /*inbound_socket_fd=*/77, second_rebind_peer, peer_len, encoded.value(),
        coquic::quic::test::test_time(2));

    ASSERT_TRUE(route.processed);
    EXPECT_FALSE(route.erased);
    EXPECT_GT(route.sendto_calls, 0);
    EXPECT_EQ(route.sendto_socket_fd, 77);
    EXPECT_EQ(route.sendto_peer_port, 59022);
    ASSERT_EQ(route.sendto_socket_fds.size(), route.sendto_peer_ports.size());
    for (const auto socket_fd : route.sendto_socket_fds) {
        EXPECT_EQ(socket_fd, 77);
    }
    for (const auto peer_port : route.sendto_peer_ports) {
        EXPECT_EQ(peer_port, 59022);
    }

    ASSERT_TRUE(server.connection_->paths_.contains(3));
    ASSERT_TRUE(server.connection_->paths_.at(3).outstanding_challenge.has_value());
    const auto second_rebind_challenge =
        optional_ref_or_terminate(server.connection_->paths_.at(3).outstanding_challenge);
    const auto largest_sent_after_second_rebind =
        std::prev(server.connection_->application_space_.sent_packets.end())->first;

    const auto path_response_encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = server.connection_->application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 78,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_after_second_rebind,
                            .first_ack_range = 0,
                        },
                        coquic::quic::PathResponseFrame{
                            .data = second_rebind_challenge,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = server.connection_->application_space_.read_secret,
            .one_rtt_key_phase = server.connection_->application_read_key_phase_,
        });
    ASSERT_TRUE(path_response_encoded.has_value());

    const std::array seeded_paths_after_second_rebind{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = second_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto path_response_route =
        coquic::quic::test::route_existing_server_session_datagram_for_tests(
            server, seeded_paths_after_second_rebind, local_connection_id,
            initial_destination_connection_id, /*inbound_socket_fd=*/77, second_rebind_peer,
            peer_len, path_response_encoded.value(), coquic::quic::test::test_time(3));

    ASSERT_TRUE(path_response_route.processed);
    EXPECT_FALSE(path_response_route.erased);
    EXPECT_GT(path_response_route.sendto_calls, 0);
    EXPECT_EQ(path_response_route.sendto_socket_fd, 77);
    EXPECT_EQ(path_response_route.sendto_peer_port, 59022);
    ASSERT_EQ(path_response_route.sendto_socket_fds.size(),
              path_response_route.sendto_peer_ports.size());
    for (const auto socket_fd : path_response_route.sendto_socket_fds) {
        EXPECT_EQ(socket_fd, 77);
    }
    for (const auto peer_port : path_response_route.sendto_peer_ports) {
        EXPECT_EQ(peer_port, 59022);
    }
    ASSERT_TRUE(server.connection_->paths_.contains(3));
    EXPECT_TRUE(server.connection_->paths_.at(3).validated);
    EXPECT_EQ(server.connection_->current_send_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
    EXPECT_EQ(server.connection_->last_validated_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
}

TEST(QuicHttp09RuntimeTest, ExistingServerSessionRoutesSecondRebindAddrToLatestV4MappedPeer) {
    const auto make_peer = [](std::array<std::uint8_t, 4> ipv4_octets, std::uint16_t port) {
        sockaddr_storage peer{};
        auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(port);
        ipv6.sin6_addr = IN6ADDR_ANY_INIT;
        ipv6.sin6_addr.s6_addr[10] = 0xff;
        ipv6.sin6_addr.s6_addr[11] = 0xff;
        ipv6.sin6_addr.s6_addr[12] = ipv4_octets[0];
        ipv6.sin6_addr.s6_addr[13] = ipv4_octets[1];
        ipv6.sin6_addr.s6_addr[14] = ipv4_octets[2];
        ipv6.sin6_addr.s6_addr[15] = ipv4_octets[3];
        return peer;
    };
    const auto make_secret = [](std::byte fill) {
        return coquic::quic::TrafficSecret{
            .cipher_suite = coquic::quic::CipherSuite::tls_aes_128_gcm_sha256,
            .secret = std::vector<std::byte>(32, fill),
        };
    };
    const auto make_connected_runtime_server_connection =
        [&](const coquic::quic::QuicCoreConfig &config) {
            coquic::quic::QuicConnection connection(config);
            connection.started_ = true;
            connection.status_ = coquic::quic::HandshakeStatus::connected;
            connection.handshake_confirmed_ = true;
            connection.peer_address_validated_ = true;
            connection.peer_source_connection_id_ = make_runtime_connection_id(std::byte{0xc1}, 3);
            connection.client_initial_destination_connection_id_ =
                make_runtime_connection_id(std::byte{0x83}, 2);
            connection.local_transport_parameters_ = coquic::quic::TransportParameters{
                .original_destination_connection_id =
                    connection.client_initial_destination_connection_id_,
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.config_.source_connection_id,
            };
            connection.initialize_local_flow_control();
            connection.application_space_.read_secret = make_secret(std::byte{0x21});
            connection.application_space_.write_secret = make_secret(std::byte{0x31});
            connection.peer_transport_parameters_ = coquic::quic::TransportParameters{
                .max_udp_payload_size = connection.config_.transport.max_udp_payload_size,
                .active_connection_id_limit = 2,
                .ack_delay_exponent = connection.config_.transport.ack_delay_exponent,
                .max_ack_delay = connection.config_.transport.max_ack_delay,
                .initial_max_data = connection.config_.transport.initial_max_data,
                .initial_max_stream_data_bidi_local =
                    connection.config_.transport.initial_max_stream_data_bidi_local,
                .initial_max_stream_data_bidi_remote =
                    connection.config_.transport.initial_max_stream_data_bidi_remote,
                .initial_max_stream_data_uni =
                    connection.config_.transport.initial_max_stream_data_uni,
                .initial_max_streams_bidi = connection.config_.transport.initial_max_streams_bidi,
                .initial_max_streams_uni = connection.config_.transport.initial_max_streams_uni,
                .initial_source_connection_id = connection.peer_source_connection_id_,
            };
            connection.peer_transport_parameters_validated_ = true;
            connection.initialize_peer_flow_control_from_transport_parameters();
            return connection;
        };

    auto core_config =
        coquic::quic::make_http09_server_core_config(coquic::quic::Http09RuntimeConfig{
            .mode = coquic::quic::Http09RuntimeMode::server,
            .host = "::",
            .port = 443,
            .testcase = coquic::quic::QuicHttp09Testcase::rebind_addr,
        });
    core_config.source_connection_id = make_runtime_connection_id(std::byte{0x53}, 1);

    coquic::quic::QuicCore server(core_config);
    server.connection_ = std::make_unique<coquic::quic::QuicConnection>(
        make_connected_runtime_server_connection(core_config));
    auto &connection = *server.connection_;
    connection.application_space_.next_send_packet_number = 900;
    connection.last_validated_path_id_ = 2;
    connection.current_send_path_id_ = 2;
    connection.previous_path_id_ = 1;
    connection.ensure_path_state(1).validated = true;
    connection.ensure_path_state(2).validated = true;
    connection.ensure_path_state(2).is_current_send_path = true;
    connection.congestion_controller_.congestion_window_ = static_cast<std::size_t>(1024) * 1024u;

    ASSERT_TRUE(connection
                    .queue_stream_send(
                        0, coquic::quic::test::bytes_from_string(std::string(4096, 'r')), false)
                    .has_value());
    connection.ensure_path_state(2).anti_amplification_received_bytes = 4000;

    const auto path2_datagram =
        connection.drain_outbound_datagram(coquic::quic::test::test_time(1));
    ASSERT_FALSE(path2_datagram.empty());
    ASSERT_EQ(connection.last_drained_path_id(), std::optional<coquic::quic::QuicPathId>{2});

    ASSERT_FALSE(connection.application_space_.sent_packets.empty());
    const auto largest_sent_packet =
        std::prev(connection.application_space_.sent_packets.end())->first;

    const auto local_connection_id = connection.config_.source_connection_id;
    const auto initial_destination_connection_id =
        connection.client_initial_destination_connection_id();
    const auto encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = connection.application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 77,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_packet,
                            .first_ack_range = 0,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = connection.application_space_.read_secret,
            .one_rtt_key_phase = connection.application_read_key_phase_,
        });
    ASSERT_TRUE(encoded.has_value());

    const auto original_peer = make_peer({193, 167, 0, 100}, 38910);
    const auto first_rebind_peer = make_peer({193, 167, 0, 71}, 39968);
    const auto second_rebind_peer = make_peer({193, 167, 0, 3}, 38910);
    const auto peer_len = static_cast<socklen_t>(sizeof(sockaddr_in6));
    const std::array seeded_paths{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto route = coquic::quic::test::route_existing_server_session_datagram_for_tests(
        server, seeded_paths, local_connection_id, initial_destination_connection_id,
        /*inbound_socket_fd=*/77, second_rebind_peer, peer_len, encoded.value(),
        coquic::quic::test::test_time(2));

    ASSERT_TRUE(route.processed);
    EXPECT_FALSE(route.erased);
    EXPECT_GT(route.sendto_calls, 0);
    EXPECT_EQ(route.sendto_socket_fd, 77);
    EXPECT_EQ(route.sendto_peer_port, 38910);
    ASSERT_EQ(route.sendto_socket_fds.size(), route.sendto_peer_ports.size());
    for (const auto socket_fd : route.sendto_socket_fds) {
        EXPECT_EQ(socket_fd, 77);
    }
    for (const auto peer_port : route.sendto_peer_ports) {
        EXPECT_EQ(peer_port, 38910);
    }

    ASSERT_TRUE(server.connection_->paths_.contains(3));
    ASSERT_TRUE(server.connection_->paths_.at(3).outstanding_challenge.has_value());
    const auto second_rebind_challenge =
        optional_ref_or_terminate(server.connection_->paths_.at(3).outstanding_challenge);
    const auto largest_sent_after_second_rebind =
        std::prev(server.connection_->application_space_.sent_packets.end())->first;

    const auto path_response_encoded = coquic::quic::serialize_protected_datagram(
        std::array<coquic::quic::ProtectedPacket, 1>{
            coquic::quic::ProtectedOneRttPacket{
                .key_phase = server.connection_->application_read_key_phase_,
                .destination_connection_id = local_connection_id,
                .packet_number_length = 2,
                .packet_number = 78,
                .frames =
                    {
                        coquic::quic::AckFrame{
                            .largest_acknowledged = largest_sent_after_second_rebind,
                            .first_ack_range = 0,
                        },
                        coquic::quic::PathResponseFrame{
                            .data = second_rebind_challenge,
                        },
                    },
            },
        },
        coquic::quic::SerializeProtectionContext{
            .local_role = coquic::quic::EndpointRole::client,
            .client_initial_destination_connection_id = initial_destination_connection_id,
            .one_rtt_secret = server.connection_->application_space_.read_secret,
            .one_rtt_key_phase = server.connection_->application_read_key_phase_,
        });
    ASSERT_TRUE(path_response_encoded.has_value());

    const std::array seeded_paths_after_second_rebind{
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 31,
            .peer = original_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = first_rebind_peer,
            .peer_len = peer_len,
        },
        coquic::quic::test::RuntimePathSeedForTests{
            .socket_fd = 77,
            .peer = second_rebind_peer,
            .peer_len = peer_len,
        },
    };
    const auto path_response_route =
        coquic::quic::test::route_existing_server_session_datagram_for_tests(
            server, seeded_paths_after_second_rebind, local_connection_id,
            initial_destination_connection_id, /*inbound_socket_fd=*/77, second_rebind_peer,
            peer_len, path_response_encoded.value(), coquic::quic::test::test_time(3));

    ASSERT_TRUE(path_response_route.processed);
    EXPECT_FALSE(path_response_route.erased);
    EXPECT_GT(path_response_route.sendto_calls, 0);
    EXPECT_EQ(path_response_route.sendto_socket_fd, 77);
    EXPECT_EQ(path_response_route.sendto_peer_port, 38910);
    ASSERT_EQ(path_response_route.sendto_socket_fds.size(),
              path_response_route.sendto_peer_ports.size());
    for (const auto socket_fd : path_response_route.sendto_socket_fds) {
        EXPECT_EQ(socket_fd, 77);
    }
    for (const auto peer_port : path_response_route.sendto_peer_ports) {
        EXPECT_EQ(peer_port, 38910);
    }
    ASSERT_TRUE(server.connection_->paths_.contains(3));
    EXPECT_TRUE(server.connection_->paths_.at(3).validated);
    EXPECT_EQ(server.connection_->current_send_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
    EXPECT_EQ(server.connection_->last_validated_path_id_,
              std::optional<coquic::quic::QuicPathId>{3});
}

TEST(QuicHttp09RuntimeTest, RuntimeTraceHooksCoverIdleTimeoutAndServerFailureBranches) {
    ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");

    testing::internal::CaptureStderr();

    const auto future_wakeup_idle_timeout =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                idle_timeout_with_future_wakeup_trace);
    EXPECT_EQ(future_wakeup_idle_timeout.exit_code, 1);

    const auto elapsed_wakeup_idle_timeout =
        coquic::quic::test::run_client_connection_loop_case_for_tests(
            coquic::quic::test::ClientConnectionLoopCaseForTests::
                idle_timeout_with_elapsed_wakeup_trace);
    EXPECT_EQ(elapsed_wakeup_idle_timeout.exit_code, 1);

    EXPECT_TRUE(coquic::quic::test::expired_server_timer_failure_cleans_up_for_tests());
    EXPECT_TRUE(coquic::quic::test::pending_server_work_failure_cleans_up_for_tests());

    const auto stderr_output = testing::internal::GetCapturedStderr();
    EXPECT_NE(stderr_output.find("http09-client trace: idle-timeout"), std::string::npos);
    EXPECT_NE(stderr_output.find("has_next_wakeup=1"), std::string::npos);
    EXPECT_NE(stderr_output.find("next_wakeup_delta_ms=5"), std::string::npos);
    EXPECT_NE(stderr_output.find("next_wakeup_delta_ms=2"), std::string::npos);
    EXPECT_NE(stderr_output.find("http09-server trace: timer-session-failed"), std::string::npos);
    EXPECT_NE(stderr_output.find("http09-server trace: pending-work-session-failed"),
              std::string::npos);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperFailsWhenReadableSocketRecvfromFails) {
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .poll_fn = &readable_poll,
            .recvfrom_fn = &fail_recvfrom,
        },
    };

    EXPECT_FALSE(coquic::quic::test::wait_for_socket_or_deadline_for_tests(
                     /*socket_fd=*/-1, /*idle_timeout_ms=*/5, "client", std::nullopt)
                     .has_value());
}

TEST(QuicHttp09RuntimeTest,
     RuntimeWaitHelperRetriesRecvfromAfterEintrThenTreatsEwouldblockAsNoStep) {
    g_eintr_then_ewouldblock_recvfrom_calls = 0;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .poll_fn = &readable_poll,
            .recvfrom_fn = &eintr_then_ewouldblock_recvfrom,
        },
    };

    EXPECT_FALSE(coquic::quic::test::wait_for_socket_or_deadline_for_tests(
                     /*socket_fd=*/-1, /*idle_timeout_ms=*/5, "client", std::nullopt)
                     .has_value());
    EXPECT_EQ(g_eintr_then_ewouldblock_recvfrom_calls, 2);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperRetriesPollAfterEintrBeforeIdleTimeout) {
    g_eintr_then_timeout_poll_calls = 0;
    const coquic::quic::test::ScopedHttp09RuntimeOpsOverride runtime_ops{
        {
            .poll_fn = &eintr_then_timeout_poll,
        },
    };

    const auto step = coquic::quic::test::wait_for_socket_or_deadline_for_tests(
        /*socket_fd=*/-1, /*idle_timeout_ms=*/5, "client", std::nullopt);
    ASSERT_TRUE(step.has_value());
    EXPECT_TRUE(optional_ref_or_terminate(step).idle_timeout);
    EXPECT_EQ(g_eintr_then_timeout_poll_calls, 2);
}

TEST(QuicHttp09RuntimeTest, RuntimeWaitHelperReceivesInboundDatagram) {
    const int receiver_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(receiver_fd, 0);
    ScopedFd receiver_socket(receiver_fd);

    sockaddr_in receiver_address{};
    receiver_address.sin_family = AF_INET;
    receiver_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    receiver_address.sin_port = htons(0);
    ASSERT_EQ(::bind(receiver_socket.get(), reinterpret_cast<const sockaddr *>(&receiver_address),
                     sizeof(receiver_address)),
              0);

    sockaddr_in bound_address{};
    socklen_t bound_length = sizeof(bound_address);
    ASSERT_EQ(::getsockname(receiver_socket.get(), reinterpret_cast<sockaddr *>(&bound_address),
                            &bound_length),
              0);

    const int sender_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender_fd, 0);
    ScopedFd sender_socket(sender_fd);

    const std::array<std::byte, 3> datagram = {
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
    };
    ASSERT_GE(::sendto(sender_socket.get(), datagram.data(), datagram.size(), 0,
                       reinterpret_cast<const sockaddr *>(&bound_address), sizeof(bound_address)),
              0);

    const auto step = coquic::quic::test::wait_for_socket_or_deadline_for_tests(
        receiver_socket.get(), /*idle_timeout_ms=*/100, "client", std::nullopt);

    ASSERT_TRUE(step.has_value());
    const auto &wait_step = optional_ref_or_terminate(step);
    EXPECT_FALSE(wait_step.idle_timeout);
    EXPECT_TRUE(wait_step.has_input);
    EXPECT_FALSE(wait_step.input_is_timer_expired);
    EXPECT_TRUE(wait_step.has_source);
    EXPECT_EQ(wait_step.inbound_datagram_bytes, datagram.size());
    EXPECT_GT(wait_step.source_len, 0u);
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
    EXPECT_NE(std::find(version_negotiation.supported_versions.begin(),
                        version_negotiation.supported_versions.end(), 0x6b3343cfu),
              version_negotiation.supported_versions.end());

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"),
              "hello-after-version-negotiation");
}

TEST(QuicHttp09RuntimeTest, ServerIgnoresUnsupportedVersionProbeBelowMinimumInitialSize) {
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

    const int probe_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe_fd, 0);
    ScopedFd probe_socket(probe_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    auto probe = make_unsupported_version_probe();
    probe.resize(64);
    ASSERT_GE(::sendto(probe_socket.get(), probe.data(), probe.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    pollfd descriptor{};
    descriptor.fd = probe_socket.get();
    descriptor.events = POLLIN;
    EXPECT_EQ(::poll(&descriptor, 1, 200), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

TEST(QuicHttp09RuntimeTest, ServerIgnoresSupportedLongHeaderWithoutSession) {
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

    const int probe_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe_fd, 0);
    ScopedFd probe_socket(probe_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    auto datagram = make_unsupported_version_probe();
    datagram[1] = std::byte{0x00};
    datagram[2] = std::byte{0x00};
    datagram[3] = std::byte{0x00};
    datagram[4] = std::byte{0x01};
    datagram[0] = std::byte{0xd0};
    ASSERT_GE(::sendto(probe_socket.get(), datagram.data(), datagram.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    pollfd descriptor{};
    descriptor.fd = probe_socket.get();
    descriptor.events = POLLIN;
    EXPECT_EQ(::poll(&descriptor, 1, 200), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

TEST(QuicHttp09RuntimeTest, ServerFailsWhenVersionNegotiationSendFails) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const ScopedFailSendtoAfterReset sendto_reset;
    g_fail_sendto_after_calls.store(1);

    const auto server = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    auto server_process =
        launch_runtime_server_process(server, {
                                                  .sendto_fn = &fail_sendto_after_n_calls,
                                              });
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

    const auto status = server_process.wait_for_exit(std::chrono::milliseconds(1000));
    ASSERT_TRUE(status.has_value());
    const auto exit_status = optional_value_or_terminate(status);
    ASSERT_TRUE(WIFEXITED(exit_status));
    EXPECT_EQ(WEXITSTATUS(exit_status), 1);
}

TEST(QuicHttp09RuntimeTest, ClientAndRuntimeServerTransferLargeFileOverUdpSockets) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    constexpr std::size_t kLargeBodyBytes = 2ULL * 1024ULL * 1024ULL;
    const std::string large_body(kLargeBodyBytes, 'R');
    document_root.write_file("runtime-large.bin", large_body);

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
        .requests_env = "https://localhost/runtime-large.bin",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "runtime-large.bin"), large_body);
}

TEST(QuicHttp09RuntimeTest, TraceEnabledServerDropsMalformedSupportedInitialAndStillTransfersFile) {
    ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-after-malformed-initial");

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

    const int client_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(client_fd, 0);
    ScopedFd client_socket(client_fd);

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    ASSERT_EQ(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr), 1);

    auto malformed_initial = make_unsupported_version_probe();
    malformed_initial[1] = std::byte{0x00};
    malformed_initial[2] = std::byte{0x00};
    malformed_initial[3] = std::byte{0x00};
    malformed_initial[4] = std::byte{0x01};
    ASSERT_GE(::sendto(client_socket.get(), malformed_initial.data(), malformed_initial.size(), 0,
                       reinterpret_cast<const sockaddr *>(&server_address), sizeof(server_address)),
              0);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(100)).has_value());

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-after-malformed-initial");
}

TEST(QuicHttp09RuntimeTest, ClientAndRuntimeServerMulticonnectThreeFilesOverUdpSockets) {
    ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "1");
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("alpha.txt", "alpha-runtime");
    document_root.write_file("beta.txt", "beta-runtime");
    document_root.write_file("gamma.txt", "gamma-runtime");

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
        .requests_env =
            "https://localhost/alpha.txt https://localhost/beta.txt https://localhost/gamma.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::quic::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-runtime");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-runtime");
    EXPECT_EQ(read_file_bytes(download_root.path() / "gamma.txt"), "gamma-runtime");
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

TEST(QuicHttp09RuntimeTest, RetryEnabledServerSendsRetryBeforeCreatingSession) {
    EXPECT_TRUE(run_retry_enabled_server_retry_smoke());
}

TEST(QuicHttp09RuntimeTest, RetryEnabledServerCompletesHandshakeAfterRetriedInitial) {
    EXPECT_EQ(run_retry_enabled_runtime_handshake(), 0);
}

TEST(QuicHttp09RuntimeTest, V2CaseStartsInQuicV1AndNegotiatesQuicV2LongHeaders) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server_runtime = coquic::quic::Http09RuntimeConfig{
        .mode = coquic::quic::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::quic::QuicHttp09Testcase::v2,
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
        .testcase = coquic::quic::QuicHttp09Testcase::v2,
        .requests_env = "https://localhost/hello.txt",
    };
    coquic::quic::QuicCore client(coquic::quic::make_http09_client_core_config(client_runtime));

    const auto start =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto client_start_datagrams = coquic::quic::test::send_datagrams_from(start);
    ASSERT_FALSE(client_start_datagrams.empty());
    EXPECT_TRUE(std::ranges::all_of(client_start_datagrams, [](const auto &datagram) {
        return has_long_header(datagram) && read_u32_be_at(datagram, 1) == kQuicVersion1;
    }));
    for (const auto &datagram : client_start_datagrams) {
        ASSERT_GE(::sendto(client_fd, datagram.data(), datagram.size(), 0,
                           reinterpret_cast<const sockaddr *>(&server_address),
                           sizeof(server_address)),
                  0);
    }

    std::vector<std::vector<std::byte>> server_datagrams;
    std::vector<std::vector<std::byte>> client_followup_datagrams;
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
        client_followup_datagrams.insert(client_followup_datagrams.end(),
                                         response_datagrams.begin(), response_datagrams.end());
        for (const auto &datagram : response_datagrams) {
            ASSERT_GE(::sendto(client_fd, datagram.data(), datagram.size(), 0,
                               reinterpret_cast<const sockaddr *>(&server_address),
                               sizeof(server_address)),
                      0);
        }
    }

    EXPECT_TRUE(client.is_handshake_complete());
    EXPECT_TRUE(std::ranges::any_of(server_datagrams, [](const auto &datagram) {
        return has_long_header(datagram) && read_u32_be_at(datagram, 1) == kQuicVersion2;
    }));
    EXPECT_TRUE(std::ranges::any_of(client_followup_datagrams, [](const auto &datagram) {
        return has_long_header(datagram) && read_u32_be_at(datagram, 1) == kQuicVersion2;
    }));
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

} // namespace
