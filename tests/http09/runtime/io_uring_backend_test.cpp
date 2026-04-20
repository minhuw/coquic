#include <gtest/gtest.h>

#include <arpa/inet.h>

#include <array>
#include <bit>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <thread>
#include <unordered_map>
#include <vector>

#include <liburing.h>

#include <sys/wait.h>
#include <unistd.h>

#include "src/io/io_backend_test_hooks.h"
#include "src/io/io_uring_backend.h"
#define private public
#include "src/io/io_uring_io_engine.h"
#undef private

namespace {

using coquic::quic::QuicEcnCodepoint;

class StubIoEngineForTests final : public coquic::io::QuicIoEngine {
  public:
    bool register_result = true;
    bool send_result = true;
    std::optional<coquic::io::QuicIoEngineEvent> wait_result = std::nullopt;
    int register_calls = 0;
    int send_calls = 0;
    int wait_calls = 0;

    bool register_socket(int) override {
        ++register_calls;
        return register_result;
    }

    bool send(int, const sockaddr_storage &, socklen_t, std::span<const std::byte>,
              std::string_view, QuicEcnCodepoint) override {
        ++send_calls;
        return send_result;
    }

    std::optional<coquic::io::QuicIoEngineEvent>
    wait(std::span<const int>, int, std::optional<coquic::quic::QuicCoreTimePoint>,
         std::string_view) override {
        ++wait_calls;
        return wait_result;
    }
};

struct ScriptedCompletionForTests {
    std::uint64_t user_data = 0;
    int res = 0;
    int socket_fd = -1;
    std::vector<std::byte> payload;
    sockaddr_storage peer{};
    socklen_t peer_len = 0;
    QuicEcnCodepoint ecn = QuicEcnCodepoint::unavailable;
};

thread_local io_uring_sqe g_send_loop_sqe{};
thread_local io_uring_cqe g_send_loop_cqe{};
thread_local std::deque<ScriptedCompletionForTests> g_send_loop_completions;

struct SendObservationForTests {
    int opcode = -1;
    int socket_fd = -1;
    std::uint64_t user_data = 0;
    int cmsg_level = 0;
    int cmsg_type = 0;
    int traffic_class = -1;
};

struct IoUringEngineHarnessForTests {
    io_uring_sqe sqe{};
    io_uring_cqe cqe{};
    std::deque<ScriptedCompletionForTests> completions;
    std::unordered_map<int, msghdr *> receive_messages_by_fd;
    std::unordered_map<int, int> receive_arm_count_by_fd;
    SendObservationForTests last_send{};
    int queue_init_rc = 0;
    bool get_sqe_returns_null = false;
    int submit_rc_for_recv = 0;
    int submit_rc_for_send = 0;
    bool auto_complete_send = true;
    int send_completion_res = std::numeric_limits<int>::min();
    int wait_cqe_rc_when_empty = -EAGAIN;
    int wait_cqe_timeout_rc_when_empty = -ETIME;
    int cqe_seen_count = 0;
};

thread_local IoUringEngineHarnessForTests g_engine_harness{};

void reset_io_uring_engine_harness() {
    g_engine_harness = {};
}

int fail_io_uring_queue_init(unsigned, io_uring *, unsigned) {
    return -EPERM;
}

int queue_init_success_for_send_loop_test(unsigned, io_uring *, unsigned) {
    return 0;
}

void noop_io_uring_queue_exit(io_uring *) {
}

io_uring_sqe *get_sqe_for_send_loop_test(io_uring *) {
    g_send_loop_sqe = {};
    return &g_send_loop_sqe;
}

int submit_success_for_send_loop_test(io_uring *) {
    return 0;
}

int wait_cqe_for_send_loop_test(io_uring *, io_uring_cqe **cqe_ptr) {
    if (g_send_loop_completions.empty()) {
        errno = ETIME;
        return -ETIME;
    }

    const auto completion = g_send_loop_completions.front();
    g_send_loop_completions.pop_front();
    g_send_loop_cqe = {};
    g_send_loop_cqe.user_data = completion.user_data;
    g_send_loop_cqe.res = completion.res;
    *cqe_ptr = &g_send_loop_cqe;
    return 0;
}

void cqe_seen_noop_for_send_loop_test(io_uring *, io_uring_cqe *) {
}

std::uint16_t peer_port_from_msghdr(const msghdr *message) {
    if (message == nullptr || message->msg_name == nullptr) {
        return 0;
    }

    const auto *address = reinterpret_cast<const sockaddr *>(message->msg_name);
    if (address->sa_family == AF_INET &&
        message->msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        return ntohs(reinterpret_cast<const sockaddr_in *>(address)->sin_port);
    }
    if (address->sa_family == AF_INET6 &&
        message->msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        return ntohs(reinterpret_cast<const sockaddr_in6 *>(address)->sin6_port);
    }
    return 0;
}

sockaddr_storage make_ipv4_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return peer;
}

sockaddr_storage make_ipv6_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(port);
    ipv6.sin6_addr = in6addr_loopback;
    return peer;
}

sockaddr_storage make_ipv4_mapped_ipv6_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(port);
    ipv6.sin6_addr = in6addr_any;
    ipv6.sin6_addr.s6_addr[10] = 0xff;
    ipv6.sin6_addr.s6_addr[11] = 0xff;
    ipv6.sin6_addr.s6_addr[12] = 127;
    ipv6.sin6_addr.s6_addr[13] = 0;
    ipv6.sin6_addr.s6_addr[14] = 0;
    ipv6.sin6_addr.s6_addr[15] = 1;
    return peer;
}

void capture_send_message_for_tests(const msghdr *message) {
    g_engine_harness.last_send = {};
    if (message == nullptr || message->msg_control == nullptr) {
        return;
    }

    auto *header = CMSG_FIRSTHDR(const_cast<msghdr *>(message));
    if (header == nullptr) {
        return;
    }

    g_engine_harness.last_send.cmsg_level = header->cmsg_level;
    g_engine_harness.last_send.cmsg_type = header->cmsg_type;
    int traffic_class = -1;
    std::memcpy(&traffic_class, CMSG_DATA(header),
                std::min<std::size_t>(sizeof(traffic_class), header->cmsg_len > CMSG_LEN(0)
                                                                 ? header->cmsg_len - CMSG_LEN(0)
                                                                 : 0));
    g_engine_harness.last_send.traffic_class = traffic_class;
}

void apply_scripted_receive_to_message(msghdr &message,
                                       const ScriptedCompletionForTests &completion) {
    if (completion.res < 0) {
        return;
    }

    if (message.msg_iov != nullptr && message.msg_iovlen > 0 &&
        message.msg_iov[0].iov_base != nullptr) {
        const auto bytes_to_copy = std::min(completion.payload.size(),
                                            static_cast<std::size_t>(message.msg_iov[0].iov_len));
        std::memcpy(message.msg_iov[0].iov_base, completion.payload.data(), bytes_to_copy);
    }

    if (message.msg_name != nullptr &&
        message.msg_namelen >= static_cast<socklen_t>(sizeof(sockaddr_storage))) {
        std::memcpy(message.msg_name, &completion.peer, sizeof(sockaddr_storage));
        message.msg_namelen = completion.peer_len;
    }

    if (message.msg_control == nullptr || message.msg_controllen < CMSG_SPACE(sizeof(int))) {
        return;
    }
    if (completion.ecn == QuicEcnCodepoint::unavailable) {
        message.msg_controllen = 0;
        return;
    }

    std::memset(message.msg_control, 0, message.msg_controllen);
    auto *header = CMSG_FIRSTHDR(&message);
    if (header == nullptr) {
        message.msg_controllen = 0;
        return;
    }

    const bool ipv6 = completion.peer.ss_family == AF_INET6;
    header->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
    header->cmsg_type = ipv6 ? IPV6_TCLASS : IP_TOS;
    header->cmsg_len = CMSG_LEN(sizeof(int));

    const int traffic_class =
        coquic::io::test::socket_io_backend_linux_traffic_class_for_ecn_for_runtime_tests(
            completion.ecn);
    std::memcpy(CMSG_DATA(header), &traffic_class, sizeof(traffic_class));
    message.msg_controllen = header->cmsg_len;
}

void enqueue_receive_completion_for_engine_test(int socket_fd, std::span<const std::byte> payload,
                                                const sockaddr_storage &peer, socklen_t peer_len,
                                                QuicEcnCodepoint ecn) {
    g_engine_harness.completions.push_back(ScriptedCompletionForTests{
        .user_data = static_cast<std::uint64_t>(socket_fd),
        .res = static_cast<int>(payload.size()),
        .socket_fd = socket_fd,
        .payload = std::vector<std::byte>(payload.begin(), payload.end()),
        .peer = peer,
        .peer_len = peer_len,
        .ecn = ecn,
    });
}

void enqueue_completion_for_engine_test(std::uint64_t user_data, int res) {
    g_engine_harness.completions.push_back(ScriptedCompletionForTests{
        .user_data = user_data,
        .res = res,
    });
}

int queue_init_for_engine_test(unsigned, io_uring *, unsigned) {
    return g_engine_harness.queue_init_rc;
}

io_uring_sqe *get_sqe_for_engine_test(io_uring *) {
    if (g_engine_harness.get_sqe_returns_null) {
        return nullptr;
    }
    g_engine_harness.sqe = {};
    return &g_engine_harness.sqe;
}

int submit_for_engine_test(io_uring *) {
    g_engine_harness.last_send = {};
    g_engine_harness.last_send.opcode = g_engine_harness.sqe.opcode;
    g_engine_harness.last_send.socket_fd = g_engine_harness.sqe.fd;
    g_engine_harness.last_send.user_data = g_engine_harness.sqe.user_data;

    if (g_engine_harness.sqe.opcode == IORING_OP_RECVMSG) {
        g_engine_harness.receive_messages_by_fd[g_engine_harness.sqe.fd] =
            std::bit_cast<msghdr *>(g_engine_harness.sqe.addr);
        g_engine_harness.receive_arm_count_by_fd[g_engine_harness.sqe.fd] += 1;
        return g_engine_harness.submit_rc_for_recv;
    }

    if (g_engine_harness.sqe.opcode == IORING_OP_SENDMSG) {
        const auto *message = std::bit_cast<const msghdr *>(g_engine_harness.sqe.addr);
        capture_send_message_for_tests(message);
        if (g_engine_harness.auto_complete_send) {
            const int bytes =
                g_engine_harness.send_completion_res == std::numeric_limits<int>::min()
                    ? static_cast<int>(message != nullptr && message->msg_iov != nullptr
                                           ? message->msg_iov[0].iov_len
                                           : 0)
                    : g_engine_harness.send_completion_res;
            enqueue_completion_for_engine_test(g_engine_harness.sqe.user_data, bytes);
        }
        return g_engine_harness.submit_rc_for_send;
    }

    return 0;
}

int wait_cqe_for_engine_test(io_uring *, io_uring_cqe **cqe_ptr) {
    if (g_engine_harness.completions.empty()) {
        *cqe_ptr = nullptr;
        errno = -g_engine_harness.wait_cqe_rc_when_empty;
        return g_engine_harness.wait_cqe_rc_when_empty;
    }

    const auto completion = g_engine_harness.completions.front();
    g_engine_harness.completions.pop_front();

    if (completion.socket_fd >= 0 && completion.res >= 0) {
        const auto message_it = g_engine_harness.receive_messages_by_fd.find(completion.socket_fd);
        if (message_it != g_engine_harness.receive_messages_by_fd.end() &&
            message_it->second != nullptr) {
            apply_scripted_receive_to_message(*message_it->second, completion);
        }
    }

    g_engine_harness.cqe = {};
    g_engine_harness.cqe.user_data = completion.user_data;
    g_engine_harness.cqe.res = completion.res;
    *cqe_ptr = &g_engine_harness.cqe;
    return 0;
}

int wait_cqe_timeout_for_engine_test(io_uring *ring, io_uring_cqe **cqe_ptr, int) {
    if (g_engine_harness.completions.empty()) {
        *cqe_ptr = nullptr;
        errno = -g_engine_harness.wait_cqe_timeout_rc_when_empty;
        return g_engine_harness.wait_cqe_timeout_rc_when_empty;
    }
    return wait_cqe_for_engine_test(ring, cqe_ptr);
}

void cqe_seen_for_engine_test(io_uring *, io_uring_cqe *) {
    g_engine_harness.cqe_seen_count += 1;
}

coquic::io::test::IoUringBackendOpsOverride io_uring_ops_for_engine_tests() {
    return coquic::io::test::IoUringBackendOpsOverride{
        .queue_init_fn = &queue_init_for_engine_test,
        .queue_exit_fn = &noop_io_uring_queue_exit,
        .get_sqe_fn = &get_sqe_for_engine_test,
        .submit_fn = &submit_for_engine_test,
        .wait_cqe_fn = &wait_cqe_for_engine_test,
        .wait_cqe_timeout_ms_fn = &wait_cqe_timeout_for_engine_test,
        .cqe_seen_fn = &cqe_seen_for_engine_test,
    };
}

bool io_uring_send_returns_when_receive_completion_precedes_send_completion() {
    g_send_loop_completions.clear();

    const pid_t pid = ::fork();
    if (pid < 0) {
        return false;
    }

    if (pid == 0) {
        const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
            coquic::io::test::IoUringBackendOpsOverride{
                .queue_init_fn = &queue_init_success_for_send_loop_test,
                .queue_exit_fn = &noop_io_uring_queue_exit,
                .get_sqe_fn = &get_sqe_for_send_loop_test,
                .submit_fn = &submit_success_for_send_loop_test,
                .wait_cqe_fn = &wait_cqe_for_send_loop_test,
                .cqe_seen_fn = &cqe_seen_noop_for_send_loop_test,
            },
        };

        auto engine = coquic::io::IoUringIoEngine::create();
        if (engine == nullptr) {
            _exit(2);
        }

        constexpr int socket_fd = 77;
        if (!engine->register_socket(socket_fd)) {
            _exit(3);
        }

        g_send_loop_completions.push_back(ScriptedCompletionForTests{
            .user_data = static_cast<std::uint64_t>(socket_fd),
            .res = 1,
        });
        g_send_loop_completions.push_back(ScriptedCompletionForTests{
            .user_data = std::numeric_limits<std::uint64_t>::max(),
            .res = 1,
        });

        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(9443);
        peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sockaddr_storage peer_storage{};
        std::memcpy(&peer_storage, &peer, sizeof(peer));
        constexpr std::array<std::byte, 1> kPayload = {
            std::byte{0x5a},
        };

        const bool sent = engine->send(socket_fd, peer_storage, sizeof(peer), kPayload, "client",
                                       coquic::quic::QuicEcnCodepoint::not_ect);
        _exit(sent ? 0 : 4);
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    ::kill(pid, SIGKILL);
    int status = 0;
    static_cast<void>(::waitpid(pid, &status, 0));
    return false;
}

TEST(IoUringBackendTest, FailsFastWhenRingInitFails) {
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        coquic::io::test::IoUringBackendOpsOverride{
            .queue_init_fn = &fail_io_uring_queue_init,
            .queue_exit_fn = &noop_io_uring_queue_exit,
        },
    };

    auto backend = coquic::io::make_io_uring_backend(coquic::io::QuicUdpBackendConfig{
        .role_name = "client",
        .idle_timeout_ms = 5,
    });
    EXPECT_EQ(backend, nullptr);
}

TEST(IoUringBackendTest, RearmsReceiveAfterCompletion) {
    EXPECT_TRUE(coquic::io::test::io_uring_backend_rearms_receive_after_completion_for_tests());
}

TEST(IoUringBackendTest, CompletionErrorBecomesFailure) {
    EXPECT_TRUE(coquic::io::test::io_uring_backend_completion_error_is_fatal_for_tests());
}

TEST(IoUringBackendTest, RecvEinvalFallsBackToSocketSendPath) {
    EXPECT_TRUE(coquic::io::test::io_uring_backend_send_falls_back_after_recv_einval_for_tests());
}

TEST(IoUringBackendTest, WaitWithoutCompletionYieldsIdleTimeout) {
    EXPECT_TRUE(
        coquic::io::test::io_uring_backend_wait_without_completion_yields_idle_timeout_for_tests());
}

TEST(IoUringBackendTest, WaitPrefersReadyReceiveOverDueTimer) {
    EXPECT_TRUE(
        coquic::io::test::io_uring_backend_wait_prefers_ready_receive_over_due_timer_for_tests());
}

TEST(IoUringBackendTest, SendReturnsWhenReceiveCompletionPrecedesSendCompletion) {
    EXPECT_TRUE(io_uring_send_returns_when_receive_completion_precedes_send_completion());
}

TEST(IoUringBackendTest, RuntimeHooksExposeMutableIoUringOpsState) {
    auto &ops = coquic::io::test::io_uring_backend_ops_for_runtime_tests();
    const auto original = ops;

    coquic::io::test::io_uring_backend_apply_ops_override_for_runtime_tests(
        coquic::io::test::IoUringBackendOpsOverride{
            .queue_init_fn = &fail_io_uring_queue_init,
            .queue_exit_fn = &noop_io_uring_queue_exit,
        });

    EXPECT_EQ(ops.queue_init_fn, &fail_io_uring_queue_init);
    EXPECT_EQ(ops.queue_exit_fn, &noop_io_uring_queue_exit);
    ops = original;
}

TEST(IoUringBackendTest, RuntimeHooksIgnoreEmptyOverride) {
    auto &ops = coquic::io::test::io_uring_backend_ops_for_runtime_tests();
    const auto original = ops;

    coquic::io::test::io_uring_backend_apply_ops_override_for_runtime_tests({});

    EXPECT_EQ(ops.queue_init_fn, original.queue_init_fn);
    EXPECT_EQ(ops.queue_exit_fn, original.queue_exit_fn);
    EXPECT_EQ(ops.get_sqe_fn, original.get_sqe_fn);
    EXPECT_EQ(ops.submit_fn, original.submit_fn);
    EXPECT_EQ(ops.wait_cqe_fn, original.wait_cqe_fn);
    EXPECT_EQ(ops.wait_cqe_timeout_ms_fn, original.wait_cqe_timeout_ms_fn);
    EXPECT_EQ(ops.cqe_seen_fn, original.cqe_seen_fn);
}

TEST(IoUringBackendTest, InitializeFailsWhenRingStorageIsMissing) {
    coquic::io::IoUringIoEngine engine;
    engine.ring_.reset();
    EXPECT_FALSE(engine.initialize());
}

TEST(IoUringBackendTest, DestroyingInitializedEngineWithMissingRingIsSafe) {
    {
        coquic::io::IoUringIoEngine engine;
        engine.initialized_ = true;
        engine.ring_.reset();
    }

    SUCCEED();
}

TEST(IoUringBackendTest, CreateFailsWhenQueueInitReturnsPositiveError) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    g_engine_harness.queue_init_rc = 1;
    EXPECT_EQ(coquic::io::IoUringIoEngine::create(), nullptr);
}

TEST(IoUringBackendTest, RegisterSocketFailsWhenReceiveArmCannotAcquireSqe) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    g_engine_harness.get_sqe_returns_null = true;
    EXPECT_FALSE(engine->register_socket(77));
    EXPECT_FALSE(engine->register_socket(78));
}

TEST(IoUringBackendTest, RegisterSocketFailsWhenReceiveArmSubmitFails) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    g_engine_harness.submit_rc_for_recv = -EIO;
    EXPECT_FALSE(engine->register_socket(92));
    EXPECT_FALSE(engine->register_socket(93));
}

TEST(IoUringBackendTest, RegisterSocketReturnsTrueWhenSocketAlreadyRegistered) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    EXPECT_TRUE(engine->register_socket(79));
    EXPECT_TRUE(engine->register_socket(79));
    EXPECT_EQ(g_engine_harness.receive_arm_count_by_fd[79], 1);
}

TEST(IoUringBackendTest, SendSkipsAncillaryDataWhenEcnIsUnavailable) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x11},
    };
    const auto peer = make_ipv4_loopback_peer(8443);
    EXPECT_TRUE(engine->send(77, peer, sizeof(sockaddr_in), kPayload, "client",
                             QuicEcnCodepoint::unavailable));
    EXPECT_EQ(g_engine_harness.last_send.cmsg_level, 0);
    EXPECT_EQ(g_engine_harness.last_send.cmsg_type, 0);
    EXPECT_EQ(g_engine_harness.last_send.traffic_class, -1);
}

TEST(IoUringBackendTest, SendAppliesIpv4EcnControlWhenMarked) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x12},
    };
    const auto peer = make_ipv4_loopback_peer(8543);
    EXPECT_TRUE(
        engine->send(76, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::ect0));
    EXPECT_EQ(g_engine_harness.last_send.cmsg_level, IPPROTO_IP);
    EXPECT_EQ(g_engine_harness.last_send.cmsg_type, IP_TOS);
    EXPECT_EQ(g_engine_harness.last_send.traffic_class, 0x02);
}

TEST(IoUringBackendTest, SendAppliesIpv6EcnControlWhenMarked) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x22},
    };
    const auto peer = make_ipv6_loopback_peer(9443);
    EXPECT_TRUE(
        engine->send(78, peer, sizeof(sockaddr_in6), kPayload, "client", QuicEcnCodepoint::ce));
    EXPECT_EQ(g_engine_harness.last_send.cmsg_level, IPPROTO_IPV6);
    EXPECT_EQ(g_engine_harness.last_send.cmsg_type, IPV6_TCLASS);
    EXPECT_EQ(g_engine_harness.last_send.traffic_class, 0x03);
}

TEST(IoUringBackendTest, SendUsesIpv4TrafficClassForMappedIpv6Peer) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x33},
    };
    const auto peer = make_ipv4_mapped_ipv6_peer(10443);
    EXPECT_TRUE(
        engine->send(79, peer, sizeof(sockaddr_in6), kPayload, "client", QuicEcnCodepoint::ect1));
    EXPECT_EQ(g_engine_harness.last_send.cmsg_level, IPPROTO_IP);
    EXPECT_EQ(g_engine_harness.last_send.cmsg_type, IP_TOS);
    EXPECT_EQ(g_engine_harness.last_send.traffic_class, 0x01);
}

TEST(IoUringBackendTest, SendFailsWhenSqeIsUnavailable) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x44},
    };
    const auto peer = make_ipv4_loopback_peer(11443);
    g_engine_harness.get_sqe_returns_null = true;
    EXPECT_FALSE(
        engine->send(80, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::not_ect));
    EXPECT_FALSE(engine->register_socket(80));
}

TEST(IoUringBackendTest, SendFailsWhenSubmitFails) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x55},
    };
    const auto peer = make_ipv4_loopback_peer(12443);
    g_engine_harness.submit_rc_for_send = -EIO;
    EXPECT_FALSE(
        engine->send(81, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::not_ect));
    EXPECT_FALSE(engine->register_socket(81));
}

TEST(IoUringBackendTest, SendFailsWhenCompletionDrainFails) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x66},
    };
    const auto peer = make_ipv4_loopback_peer(13443);
    g_engine_harness.auto_complete_send = false;
    g_engine_harness.wait_cqe_rc_when_empty = -EIO;
    EXPECT_FALSE(
        engine->send(82, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::not_ect));
}

TEST(IoUringBackendTest, SendFailsWhenCompletionReportsError) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x77},
    };
    const auto peer = make_ipv4_loopback_peer(14443);
    g_engine_harness.send_completion_res = -ECONNRESET;
    EXPECT_FALSE(
        engine->send(83, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::not_ect));
}

TEST(IoUringBackendTest, SendRestoresDeferredPendingCompletionsAfterSuccess) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    engine->pending_completions_.push_back({
        .user_data = 123,
        .res = 7,
    });

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x78},
    };
    const auto peer = make_ipv4_loopback_peer(14543);
    EXPECT_TRUE(
        engine->send(84, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::not_ect));
    ASSERT_EQ(engine->pending_completions_.size(), 1U);
    EXPECT_EQ(engine->pending_completions_.front().user_data, 123U);
    EXPECT_EQ(engine->pending_completions_.front().res, 7);
}

TEST(IoUringBackendTest, DrainOneCompletionUsesPendingQueueBeforeRingWait) {
    coquic::io::IoUringIoEngine engine;
    engine.pending_completions_.push_back({
        .user_data = 456,
        .res = 9,
    });

    coquic::io::IoUringIoEngine::Completion completion{};
    EXPECT_TRUE(engine.drain_one_completion(completion));
    EXPECT_EQ(completion.user_data, 456U);
    EXPECT_EQ(completion.res, 9);
    EXPECT_TRUE(engine.pending_completions_.empty());
}

TEST(IoUringBackendTest, DrainOneCompletionReturnsFalseWhenRingWaitYieldsNullCqe) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    coquic::io::IoUringIoEngine engine;
    g_engine_harness.wait_cqe_rc_when_empty = 0;

    coquic::io::IoUringIoEngine::Completion completion{};
    EXPECT_FALSE(engine.drain_one_completion(completion));
}

TEST(IoUringBackendTest, WaitReturnsNulloptForEmptySocketSet) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);

    const std::array<int, 0> sockets = {};
    EXPECT_EQ(engine->wait(sockets, 5, std::nullopt, "client"), std::nullopt);
}

TEST(IoUringBackendTest, WaitReturnsTimerExpiredWhenTimeoutHitsDeadline) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(84));

    const std::array<int, 1> sockets = {
        84,
    };
    const auto event = engine->wait(
        sockets, 5, coquic::quic::QuicCoreClock::now() - std::chrono::milliseconds(1), "client");
    ASSERT_TRUE(event.has_value());
    const auto observed = event.value_or(coquic::io::QuicIoEngineEvent{});
    EXPECT_EQ(observed.kind, coquic::io::QuicIoEngineEvent::Kind::timer_expired);
}

TEST(IoUringBackendTest, WaitReturnsIdleTimeoutBeforeFutureWakeupExpires) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(94));

    const std::array<int, 1> sockets = {
        94,
    };
    const auto event = engine->wait(
        sockets, 5, coquic::quic::QuicCoreClock::now() + std::chrono::milliseconds(50), "client");
    ASSERT_TRUE(event.has_value());
    const auto observed = event.value_or(coquic::io::QuicIoEngineEvent{});
    EXPECT_EQ(observed.kind, coquic::io::QuicIoEngineEvent::Kind::idle_timeout);
}

TEST(IoUringBackendTest, WaitWithNegativeIdleTimeoutUsesNextWakeup) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(95));

    const std::array<int, 1> sockets = {
        95,
    };
    const auto event = engine->wait(
        sockets, -1, coquic::quic::QuicCoreClock::now() + std::chrono::milliseconds(50), "client");
    ASSERT_TRUE(event.has_value());
    const auto observed = event.value_or(coquic::io::QuicIoEngineEvent{});
    EXPECT_EQ(observed.kind, coquic::io::QuicIoEngineEvent::Kind::idle_timeout);
}

TEST(IoUringBackendTest, WaitReturnsNulloptWhenTimedWaitFails) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(85));

    g_engine_harness.wait_cqe_timeout_rc_when_empty = -EIO;
    const std::array<int, 1> sockets = {
        85,
    };
    EXPECT_EQ(engine->wait(sockets, 5, std::nullopt, "client"), std::nullopt);
}

TEST(IoUringBackendTest, WaitReturnsNulloptWhenTimedWaitSucceedsWithoutCqe) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(96));

    g_engine_harness.wait_cqe_timeout_rc_when_empty = 0;
    const std::array<int, 1> sockets = {
        96,
    };
    EXPECT_EQ(engine->wait(sockets, 5, std::nullopt, "client"), std::nullopt);
}

TEST(IoUringBackendTest, WaitTreatsSendCompletionAsIdleTimeout) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(86));

    enqueue_completion_for_engine_test(std::numeric_limits<std::uint64_t>::max(), 1);
    const std::array<int, 1> sockets = {
        86,
    };
    const auto event = engine->wait(sockets, 5, std::nullopt, "client");
    ASSERT_TRUE(event.has_value());
    const auto observed = event.value_or(coquic::io::QuicIoEngineEvent{});
    EXPECT_EQ(observed.kind, coquic::io::QuicIoEngineEvent::Kind::idle_timeout);
}

TEST(IoUringBackendTest, WaitReturnsNulloptWhenPendingSendCompletionReportsError) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    engine->pending_completions_.push_back({
        .user_data = std::numeric_limits<std::uint64_t>::max(),
        .res = -ECONNRESET,
    });

    const std::array<int, 1> sockets = {
        97,
    };
    EXPECT_EQ(engine->wait(sockets, 5, std::nullopt, "client"), std::nullopt);
    EXPECT_FALSE(engine->healthy_);
}

TEST(IoUringBackendTest, WaitFailsForUnknownCompletionUserData) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(87));

    enqueue_completion_for_engine_test(999, 1);
    const std::array<int, 1> sockets = {
        87,
    };
    EXPECT_EQ(engine->wait(sockets, 5, std::nullopt, "client"), std::nullopt);
    EXPECT_FALSE(engine->register_socket(88));
}

TEST(IoUringBackendTest, WaitFailsWhenReceiveCannotBeRearmed) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(89));

    constexpr std::array<std::byte, 2> kPayload = {
        std::byte{0x88},
        std::byte{0x99},
    };
    const auto peer = make_ipv4_loopback_peer(15443);
    enqueue_receive_completion_for_engine_test(89, kPayload, peer, sizeof(sockaddr_in),
                                               QuicEcnCodepoint::ect0);
    g_engine_harness.get_sqe_returns_null = true;

    const std::array<int, 1> sockets = {
        89,
    };
    EXPECT_EQ(engine->wait(sockets, 5, std::nullopt, "client"), std::nullopt);
}

TEST(IoUringBackendTest, RegisterSocketDelegatesToPollFallbackAfterRecvEinval) {
    reset_io_uring_engine_harness();
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        io_uring_ops_for_engine_tests(),
    };
    const coquic::io::test::ScopedSocketIoBackendOpsOverride socket_ops{
        coquic::io::test::SocketIoBackendOpsOverride{
            .poll_fn =
                [](pollfd *fds, nfds_t count, int) {
                    for (nfds_t index = 0; index < count; ++index) {
                        fds[index].revents = 0;
                    }
                    return 0;
                },
        },
    };

    auto engine = coquic::io::IoUringIoEngine::create();
    ASSERT_NE(engine, nullptr);
    ASSERT_TRUE(engine->register_socket(90));

    enqueue_completion_for_engine_test(90, -EINVAL);
    const std::array<int, 1> sockets = {
        90,
    };
    const auto event = engine->wait(sockets, 5, std::nullopt, "client");
    ASSERT_TRUE(event.has_value());
    const auto observed = event.value_or(coquic::io::QuicIoEngineEvent{});
    EXPECT_EQ(observed.kind, coquic::io::QuicIoEngineEvent::Kind::idle_timeout);
    EXPECT_TRUE(engine->register_socket(91));
}

TEST(IoUringBackendTest, UninitializedEngineRejectsRegisterSendAndWait) {
    coquic::io::IoUringIoEngine engine;
    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0x99},
    };
    const auto peer = make_ipv4_loopback_peer(16443);
    const std::array<int, 1> sockets = {
        98,
    };

    EXPECT_FALSE(engine.register_socket(98));
    EXPECT_FALSE(
        engine.send(98, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::not_ect));
    EXPECT_EQ(engine.wait(sockets, 5, std::nullopt, "client"), std::nullopt);
}

TEST(IoUringBackendTest, InitializedButUnhealthyEngineRejectsSendAndWait) {
    coquic::io::IoUringIoEngine engine;
    engine.initialized_ = true;
    engine.healthy_ = false;

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0xab},
    };
    const auto peer = make_ipv4_loopback_peer(16943);
    const std::array<int, 1> sockets = {
        108,
    };

    EXPECT_FALSE(
        engine.send(108, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::ect0));
    EXPECT_EQ(engine.wait(sockets, 5, std::nullopt, "client"), std::nullopt);
}

TEST(IoUringBackendTest, RegisterSocketReturnsFalseWhenFallbackEngineIsMissing) {
    coquic::io::IoUringIoEngine engine;
    engine.use_poll_receive_ = true;
    EXPECT_FALSE(engine.register_socket(99));
}

TEST(IoUringBackendTest, RegisterSocketDelegatesFallbackFailures) {
    coquic::io::IoUringIoEngine engine;
    auto fallback = std::make_unique<StubIoEngineForTests>();
    fallback->register_result = false;
    auto *fallback_ptr = fallback.get();
    engine.use_poll_receive_ = true;
    engine.receive_fallback_ = std::move(fallback);

    EXPECT_FALSE(engine.register_socket(100));
    EXPECT_EQ(fallback_ptr->register_calls, 1);
}

TEST(IoUringBackendTest, SendReturnsFalseWhenFallbackEngineIsMissing) {
    coquic::io::IoUringIoEngine engine;
    engine.use_poll_receive_ = true;

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0xaa},
    };
    const auto peer = make_ipv4_loopback_peer(17443);
    EXPECT_FALSE(
        engine.send(101, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::ect0));
}

TEST(IoUringBackendTest, SendDelegatesFallbackFailures) {
    coquic::io::IoUringIoEngine engine;
    auto fallback = std::make_unique<StubIoEngineForTests>();
    fallback->send_result = false;
    auto *fallback_ptr = fallback.get();
    engine.use_poll_receive_ = true;
    engine.receive_fallback_ = std::move(fallback);

    constexpr std::array<std::byte, 1> kPayload = {
        std::byte{0xbb},
    };
    const auto peer = make_ipv4_loopback_peer(18443);
    EXPECT_FALSE(
        engine.send(102, peer, sizeof(sockaddr_in), kPayload, "client", QuicEcnCodepoint::ect1));
    EXPECT_EQ(fallback_ptr->send_calls, 1);
}

TEST(IoUringBackendTest, WaitReturnsNulloptWhenFallbackEngineIsMissing) {
    coquic::io::IoUringIoEngine engine;
    engine.use_poll_receive_ = true;
    const std::array<int, 1> sockets = {
        103,
    };

    EXPECT_EQ(engine.wait(sockets, 5, std::nullopt, "client"), std::nullopt);
}

TEST(IoUringBackendTest, WaitDelegatesToFallbackEngineWhenAlreadyEnabled) {
    coquic::io::IoUringIoEngine engine;
    auto fallback = std::make_unique<StubIoEngineForTests>();
    fallback->wait_result = coquic::io::QuicIoEngineEvent{
        .kind = coquic::io::QuicIoEngineEvent::Kind::idle_timeout,
        .now = coquic::quic::QuicCoreClock::now(),
    };
    auto *fallback_ptr = fallback.get();
    engine.use_poll_receive_ = true;
    engine.receive_fallback_ = std::move(fallback);
    const std::array<int, 1> sockets = {
        104,
    };

    const auto event = engine.wait(sockets, 5, std::nullopt, "client");
    ASSERT_TRUE(event.has_value());
    const auto observed = event.value_or(coquic::io::QuicIoEngineEvent{});
    EXPECT_EQ(observed.kind, coquic::io::QuicIoEngineEvent::Kind::idle_timeout);
    EXPECT_EQ(fallback_ptr->wait_calls, 1);
}

TEST(IoUringBackendTest, EnableReceiveFallbackIsIdempotentAndClearsPendingCompletions) {
    coquic::io::IoUringIoEngine engine;
    engine.pending_completions_.push_back({
        .user_data = 1,
        .res = 1,
    });

    engine.enable_receive_fallback();
    auto *const first_fallback = engine.receive_fallback_.get();
    ASSERT_NE(first_fallback, nullptr);
    EXPECT_TRUE(engine.pending_completions_.empty());

    engine.pending_completions_.push_back({
        .user_data = 2,
        .res = 2,
    });
    engine.enable_receive_fallback();
    EXPECT_EQ(engine.receive_fallback_.get(), first_fallback);
    EXPECT_TRUE(engine.pending_completions_.empty());
}

TEST(IoUringBackendTest, InternalCoverageHookExercisesIoUringBackendColdPaths) {
    EXPECT_TRUE(
        coquic::io::test::io_uring_backend_internal_coverage_hook_exercises_cold_paths_for_tests());
}

TEST(IoUringBackendTest, InternalCoverageHookExercisesIoUringBackendResidualBranches) {
    EXPECT_TRUE(
        coquic::io::test::
            io_uring_backend_internal_coverage_hook_exercises_remaining_branches_for_tests());
}

} // namespace
