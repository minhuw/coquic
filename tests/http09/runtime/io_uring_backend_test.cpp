#include <gtest/gtest.h>

#include <cerrno>

#include "src/io/io_backend_test_hooks.h"
#include "src/io/io_uring_backend.h"

namespace {

int fail_io_uring_queue_init(unsigned, io_uring *, unsigned) {
    return -EPERM;
}

void noop_io_uring_queue_exit(io_uring *) {
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

} // namespace
