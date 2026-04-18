#include <gtest/gtest.h>

#include <arpa/inet.h>

#include <array>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <thread>

#include <liburing.h>

#include <sys/wait.h>
#include <unistd.h>

#include "src/io/io_backend_test_hooks.h"
#include "src/io/io_uring_backend.h"
#include "src/io/io_uring_io_engine.h"

namespace {

struct ScriptedCompletionForTests {
    std::uint64_t user_data = 0;
    int res = 0;
};

thread_local io_uring_sqe g_send_loop_sqe{};
thread_local io_uring_cqe g_send_loop_cqe{};
thread_local std::deque<ScriptedCompletionForTests> g_send_loop_completions;

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

} // namespace
