#include "src/io/io_uring_io_engine.h"

#include "src/io/io_backend_test_hooks.h"
#include "src/io/poll_io_engine.h"

#include <netinet/in.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <array>
#include <cstring>
#include <limits>
#include <iostream>
#include <memory>
#include <utility>

#include <liburing.h>

namespace coquic::io {

using quic::QuicCoreClock;
using quic::QuicEcnCodepoint;

namespace {

constexpr unsigned kIoUringQueueEntries = 256;
constexpr std::size_t kMaxDatagramBytes = 65535;
constexpr std::uint64_t kSendCompletionUserData = std::numeric_limits<std::uint64_t>::max();

int wait_cqe_timeout_ms(io_uring *ring, io_uring_cqe **cqe, int timeout_ms) {
    if (timeout_ms < 0) {
        return ::io_uring_wait_cqe(ring, cqe);
    }

    __kernel_timespec timeout{
        .tv_sec = timeout_ms / 1000,
        .tv_nsec = static_cast<long>((timeout_ms % 1000) * 1000000),
    };
    return ::io_uring_wait_cqe_timeout(ring, cqe, &timeout);
}

bool should_apply_ecn_control(QuicEcnCodepoint ecn) {
    return ecn != QuicEcnCodepoint::not_ect && ecn != QuicEcnCodepoint::unavailable;
}

} // namespace

namespace internal {

test::IoUringBackendOpsOverride make_default_io_uring_backend_ops() {
    return test::IoUringBackendOpsOverride{
        .queue_init_fn = ::io_uring_queue_init,
        .queue_exit_fn = ::io_uring_queue_exit,
        .get_sqe_fn = ::io_uring_get_sqe,
        .submit_fn = ::io_uring_submit,
        .wait_cqe_fn = ::io_uring_wait_cqe,
        .wait_cqe_timeout_ms_fn = &wait_cqe_timeout_ms,
        .cqe_seen_fn = ::io_uring_cqe_seen,
    };
}

test::IoUringBackendOpsOverride &io_uring_backend_ops_state() {
    static thread_local auto ops = make_default_io_uring_backend_ops();
    return ops;
}

bool using_default_io_uring_backend_ops() {
    const auto defaults = make_default_io_uring_backend_ops();
    const auto &ops = io_uring_backend_ops_state();
    return ops.queue_init_fn == defaults.queue_init_fn &&
           ops.queue_exit_fn == defaults.queue_exit_fn && ops.get_sqe_fn == defaults.get_sqe_fn &&
           ops.submit_fn == defaults.submit_fn && ops.wait_cqe_fn == defaults.wait_cqe_fn &&
           ops.wait_cqe_timeout_ms_fn == defaults.wait_cqe_timeout_ms_fn &&
           ops.cqe_seen_fn == defaults.cqe_seen_fn;
}

void apply_io_uring_backend_ops_override(const test::IoUringBackendOpsOverride &override_ops) {
    auto &ops = io_uring_backend_ops_state();
    if (override_ops.queue_init_fn != nullptr) {
        ops.queue_init_fn = override_ops.queue_init_fn;
    }
    if (override_ops.queue_exit_fn != nullptr) {
        ops.queue_exit_fn = override_ops.queue_exit_fn;
    }
    if (override_ops.get_sqe_fn != nullptr) {
        ops.get_sqe_fn = override_ops.get_sqe_fn;
    }
    if (override_ops.submit_fn != nullptr) {
        ops.submit_fn = override_ops.submit_fn;
    }
    if (override_ops.wait_cqe_fn != nullptr) {
        ops.wait_cqe_fn = override_ops.wait_cqe_fn;
    }
    if (override_ops.wait_cqe_timeout_ms_fn != nullptr) {
        ops.wait_cqe_timeout_ms_fn = override_ops.wait_cqe_timeout_ms_fn;
    }
    if (override_ops.cqe_seen_fn != nullptr) {
        ops.cqe_seen_fn = override_ops.cqe_seen_fn;
    }
}

} // namespace internal

IoUringIoEngine::IoUringIoEngine() : ring_(std::make_unique<io_uring>()) {
}

IoUringIoEngine::~IoUringIoEngine() {
    if (initialized_ && ring_ != nullptr) {
        internal::io_uring_backend_ops_state().queue_exit_fn(ring_.get());
    }
}

std::unique_ptr<IoUringIoEngine> IoUringIoEngine::create() {
    auto engine = std::unique_ptr<IoUringIoEngine>(new IoUringIoEngine());
    if (!engine->initialize()) {
        return nullptr;
    }
    return engine;
}

bool IoUringIoEngine::initialize() {
    if (ring_ == nullptr) {
        return false;
    }

    const int rc =
        internal::io_uring_backend_ops_state().queue_init_fn(kIoUringQueueEntries, ring_.get(), 0);
    if (rc != 0) {
        std::cerr << "io-uring queue_init failed rc=" << rc;
        if (rc < 0) {
            std::cerr << " err=" << std::strerror(-rc);
        }
        std::cerr << "\n";
        return false;
    }

    initialized_ = true;
    healthy_ = true;
    probe_recvmsg_support();
    return true;
}

bool IoUringIoEngine::arm_receive(ReceiveState &state) {
    state.peer = {};
    state.iov = iovec{
        .iov_base = state.data.data(),
        .iov_len = state.data.size(),
    };
    state.message = msghdr{};
    state.message.msg_name = &state.peer;
    state.message.msg_namelen = sizeof(state.peer);
    state.message.msg_iov = &state.iov;
    state.message.msg_iovlen = 1;
    state.message.msg_control = state.control.data();
    state.message.msg_controllen = state.control.size();

    auto *sqe = internal::io_uring_backend_ops_state().get_sqe_fn(ring_.get());
    if (sqe == nullptr) {
        std::cerr << "io-uring arm_receive failed: get_sqe returned null\n";
        return false;
    }

    io_uring_prep_recvmsg(sqe, state.socket_fd, &state.message, 0);
    io_uring_sqe_set_data64(sqe, static_cast<std::uint64_t>(state.socket_fd));
    const int rc = internal::io_uring_backend_ops_state().submit_fn(ring_.get());
    if (rc < 0) {
        std::cerr << "io-uring arm_receive failed: submit rc=" << rc
                  << " err=" << std::strerror(-rc) << " errno=" << errno << "\n";
        return false;
    }
    return true;
}

QuicEcnCodepoint IoUringIoEngine::decode_linux_ecn_from_control(const msghdr &message) const {
    return test::socket_io_backend_recvmsg_ecn_from_control_for_runtime_tests(message);
}

void IoUringIoEngine::apply_linux_ecn_send_control(
    msghdr &message, std::array<std::byte, CMSG_SPACE(sizeof(int))> &control_storage,
    QuicEcnCodepoint ecn, const sockaddr_storage &peer, socklen_t peer_len) const {
    message.msg_control = nullptr;
    message.msg_controllen = 0;
    if (!should_apply_ecn_control(ecn)) {
        return;
    }

    const bool use_ipv4_traffic_class =
        peer.ss_family == AF_INET ||
        test::socket_io_backend_is_ipv4_mapped_ipv6_address_for_runtime_tests(peer, peer_len);
    const int traffic_class =
        test::socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests(ecn);

    control_storage.fill(std::byte{0});
    message.msg_control = control_storage.data();
    message.msg_controllen = control_storage.size();

    auto *header = CMSG_FIRSTHDR(&message);
    if (header == nullptr) {
        message.msg_control = nullptr;
        message.msg_controllen = 0;
        return;
    }

    header->cmsg_level = use_ipv4_traffic_class ? IPPROTO_IP : IPPROTO_IPV6;
    header->cmsg_type = use_ipv4_traffic_class ? IP_TOS : IPV6_TCLASS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
    message.msg_controllen = header->cmsg_len;
}

bool IoUringIoEngine::drain_one_completion(Completion &completion) {
    if (!pending_completions_.empty()) {
        completion = pending_completions_.front();
        pending_completions_.pop_front();
        return true;
    }

    io_uring_cqe *cqe = nullptr;
    if (internal::io_uring_backend_ops_state().wait_cqe_fn(ring_.get(), &cqe) < 0 ||
        cqe == nullptr) {
        return false;
    }

    completion = Completion{
        .user_data = io_uring_cqe_get_data64(cqe),
        .res = cqe->res,
    };
    internal::io_uring_backend_ops_state().cqe_seen_fn(ring_.get(), cqe);
    return true;
}

bool IoUringIoEngine::register_socket(int socket_fd) {
    if (use_poll_receive_) {
        return receive_fallback_ != nullptr && receive_fallback_->register_socket(socket_fd);
    }
    if (!initialized_ || !healthy_) {
        return false;
    }

    auto [it, inserted] = receives_.try_emplace(socket_fd);
    auto &state = it->second;
    state.socket_fd = socket_fd;
    state.data.resize(kMaxDatagramBytes);
    if (!inserted) {
        return true;
    }

    if (!arm_receive(state)) {
        healthy_ = false;
        return false;
    }
    return true;
}

bool IoUringIoEngine::send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
                           std::span<const std::byte> datagram, std::string_view role_name,
                           quic::QuicEcnCodepoint ecn) {
    if (use_poll_receive_) {
        return receive_fallback_ != nullptr &&
               receive_fallback_->send(socket_fd, peer, peer_len, datagram, role_name, ecn);
    }
    static_cast<void>(role_name);
    if (!initialized_ || !healthy_) {
        return false;
    }

    iovec iov{
        .iov_base = const_cast<std::byte *>(datagram.data()),
        .iov_len = datagram.size(),
    };
    msghdr message{};
    message.msg_name = const_cast<sockaddr *>(reinterpret_cast<const sockaddr *>(&peer));
    message.msg_namelen = peer_len;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    apply_linux_ecn_send_control(message, send_control_, ecn, peer, peer_len);

    auto *sqe = internal::io_uring_backend_ops_state().get_sqe_fn(ring_.get());
    if (sqe == nullptr) {
        healthy_ = false;
        return false;
    }

    io_uring_prep_sendmsg(sqe, socket_fd, &message, 0);
    io_uring_sqe_set_data64(sqe, kSendCompletionUserData);
    if (internal::io_uring_backend_ops_state().submit_fn(ring_.get()) < 0) {
        healthy_ = false;
        return false;
    }

    std::deque<Completion> deferred_completions;
    while (true) {
        Completion completion{};
        if (!pending_completions_.empty()) {
            completion = pending_completions_.front();
            pending_completions_.pop_front();
        } else if (!drain_one_completion(completion)) {
            healthy_ = false;
            return false;
        }

        if (completion.user_data != kSendCompletionUserData) {
            deferred_completions.push_back(completion);
            continue;
        }
        if (completion.res < 0) {
            healthy_ = false;
            return false;
        }
        while (!deferred_completions.empty()) {
            pending_completions_.push_front(deferred_completions.back());
            deferred_completions.pop_back();
        }
        return true;
    }
}

std::optional<QuicIoEngineEvent>
IoUringIoEngine::wait(std::span<const int> socket_fds, int idle_timeout_ms,
                      std::optional<quic::QuicCoreTimePoint> next_wakeup,
                      std::string_view role_name) {
    if (use_poll_receive_) {
        return receive_fallback_ != nullptr
                   ? receive_fallback_->wait(socket_fds, idle_timeout_ms, next_wakeup, role_name)
                   : std::nullopt;
    }
    static_cast<void>(role_name);
    if (socket_fds.empty()) {
        return std::nullopt;
    }
    if (!initialized_ || !healthy_) {
        return std::nullopt;
    }

    const auto current = QuicCoreClock::now();
    if (pending_completions_.empty() && next_wakeup.has_value() && *next_wakeup <= current) {
        return QuicIoEngineEvent{
            .kind = QuicIoEngineEvent::Kind::timer_expired,
            .now = current,
        };
    }

    int wait_timeout_ms = idle_timeout_ms;
    if (next_wakeup.has_value()) {
        const auto until_wakeup =
            std::chrono::duration_cast<std::chrono::milliseconds>(*next_wakeup - current);
        const auto wakeup_timeout_ms = static_cast<int>(std::clamp(
            until_wakeup.count(), 0LL, static_cast<long long>(std::numeric_limits<int>::max())));
        if (wait_timeout_ms < 0 || wakeup_timeout_ms < wait_timeout_ms) {
            wait_timeout_ms = wakeup_timeout_ms;
        }
    }

    Completion completion{};
    if (!pending_completions_.empty()) {
        completion = pending_completions_.front();
        pending_completions_.pop_front();
    } else {
        io_uring_cqe *cqe = nullptr;
        int wait_rc = 0;
        wait_rc = internal::io_uring_backend_ops_state().wait_cqe_timeout_ms_fn(ring_.get(), &cqe,
                                                                                wait_timeout_ms);
        if (wait_rc == -ETIME) {
            const auto now = QuicCoreClock::now();
            if (next_wakeup.has_value() && now >= *next_wakeup) {
                return QuicIoEngineEvent{
                    .kind = QuicIoEngineEvent::Kind::timer_expired,
                    .now = now,
                };
            }
            return QuicIoEngineEvent{
                .kind = QuicIoEngineEvent::Kind::idle_timeout,
                .now = now,
            };
        }
        if (wait_rc < 0 || cqe == nullptr) {
            std::cerr << "io-uring wait failed rc=" << wait_rc;
            if (wait_rc < 0) {
                std::cerr << " err=" << std::strerror(-wait_rc);
            }
            std::cerr << "\n";
            return std::nullopt;
        }

        completion = Completion{
            .user_data = io_uring_cqe_get_data64(cqe),
            .res = cqe->res,
        };
        internal::io_uring_backend_ops_state().cqe_seen_fn(ring_.get(), cqe);
    }

    const auto now = QuicCoreClock::now();
    if (completion.user_data == kSendCompletionUserData) {
        if (completion.res < 0) {
            std::cerr << "io-uring send completion failed res=" << completion.res
                      << " err=" << std::strerror(-completion.res) << "\n";
            healthy_ = false;
            return std::nullopt;
        }
        return QuicIoEngineEvent{
            .kind = QuicIoEngineEvent::Kind::idle_timeout,
            .now = now,
        };
    }

    auto receive_it = receives_.find(static_cast<int>(completion.user_data));
    if (receive_it == receives_.end()) {
        std::cerr << "io-uring wait failed: unknown completion user_data=" << completion.user_data
                  << "\n";
        healthy_ = false;
        return std::nullopt;
    }
    if (completion.res < 0) {
        if (completion.res == -EINVAL) {
            std::cerr << "io-uring recv completion failed with EINVAL; falling back to poll I/O\n";
            enable_receive_fallback();
            return receive_fallback_->wait(socket_fds, idle_timeout_ms, next_wakeup, role_name);
        }
        std::cerr << "io-uring recv completion failed res=" << completion.res
                  << " err=" << std::strerror(-completion.res) << "\n";
        healthy_ = false;
        return std::nullopt;
    }

    auto &state = receive_it->second;
    const auto bytes_to_copy =
        std::min<std::size_t>(state.data.size(), static_cast<std::size_t>(completion.res));
    std::vector<std::byte> bytes(bytes_to_copy);
    std::memcpy(bytes.data(), state.data.data(), bytes.size());
    const auto ecn = decode_linux_ecn_from_control(state.message);
    const auto peer = state.peer;
    const auto peer_len = static_cast<socklen_t>(state.message.msg_namelen);
    if (!arm_receive(state)) {
        healthy_ = false;
        return std::nullopt;
    }

    return QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::rx_datagram,
        .now = now,
        .rx =
            QuicIoEngineRxCompletion{
                .socket_fd = state.socket_fd,
                .bytes = std::move(bytes),
                .ecn = ecn,
                .peer = peer,
                .peer_len = peer_len,
                .now = now,
            },
    };
}

void IoUringIoEngine::probe_recvmsg_support() {
    if (!internal::using_default_io_uring_backend_ops()) {
        return;
    }

    const int socket_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (socket_fd < 0) {
        return;
    }

    const int enabled = 1;
    if (::setsockopt(socket_fd, IPPROTO_IP, IP_RECVTOS, &enabled, sizeof(enabled)) != 0) {
        ::close(socket_fd);
        return;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);
    if (::bind(socket_fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        ::close(socket_fd);
        return;
    }

    sockaddr_in bound_address{};
    socklen_t bound_length = sizeof(bound_address);
    if (::getsockname(socket_fd, reinterpret_cast<sockaddr *>(&bound_address), &bound_length) !=
        0) {
        ::close(socket_fd);
        return;
    }

    ReceiveState probe_state;
    probe_state.socket_fd = socket_fd;
    probe_state.data.resize(kMaxDatagramBytes);
    if (!arm_receive(probe_state)) {
        ::close(socket_fd);
        return;
    }

    const int sender_fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sender_fd < 0) {
        ::close(socket_fd);
        return;
    }

    constexpr std::array<std::byte, 1> kProbePayload = {
        std::byte{0x01},
    };
    const auto *payload = reinterpret_cast<const void *>(kProbePayload.data());
    const auto sent =
        ::sendto(sender_fd, payload, kProbePayload.size(), 0,
                 reinterpret_cast<const sockaddr *>(&bound_address), sizeof(bound_address));
    ::close(sender_fd);
    if (sent < 0) {
        ::close(socket_fd);
        return;
    }

    Completion completion{};
    if (!drain_one_completion(completion)) {
        ::close(socket_fd);
        return;
    }

    if (completion.res == -EINVAL) {
        std::cerr << "io-uring recv probe hit EINVAL; enabling poll fallback\n";
        enable_receive_fallback();
    }
    ::close(socket_fd);
}

void IoUringIoEngine::enable_receive_fallback() {
    if (receive_fallback_ == nullptr) {
        receive_fallback_ = std::make_unique<PollIoEngine>();
    }
    use_poll_receive_ = true;
    pending_completions_.clear();
}

std::unique_ptr<QuicIoEngine> make_io_uring_io_engine() {
    return IoUringIoEngine::create();
}

namespace test {

IoUringBackendOpsOverride &io_uring_backend_ops_for_runtime_tests() {
    return internal::io_uring_backend_ops_state();
}

void io_uring_backend_apply_ops_override_for_runtime_tests(
    const IoUringBackendOpsOverride &override_ops) {
    internal::apply_io_uring_backend_ops_override(override_ops);
}

ScopedIoUringBackendOpsOverride::ScopedIoUringBackendOpsOverride(
    IoUringBackendOpsOverride override_ops)
    : previous_(internal::io_uring_backend_ops_state()) {
    internal::apply_io_uring_backend_ops_override(override_ops);
}

ScopedIoUringBackendOpsOverride::~ScopedIoUringBackendOpsOverride() {
    internal::io_uring_backend_ops_state() = previous_;
}

} // namespace test

} // namespace coquic::io
