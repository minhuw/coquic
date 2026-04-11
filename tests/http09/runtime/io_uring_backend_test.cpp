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

} // namespace
