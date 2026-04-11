#include <cerrno>

#include <gtest/gtest.h>

#include "tests/support/perf/perf_test_fixtures.h"

#define private public
#include "src/io/io_backend_test_hooks.h"
#include "src/perf/perf_server.h"
#undef private

namespace {
using namespace coquic::perf;

thread_local int g_perf_io_uring_exit_calls = 0;

int fail_perf_io_uring_queue_init(unsigned, io_uring *, unsigned) {
    return -EPERM;
}

void record_perf_io_uring_queue_exit(io_uring *) {
    ++g_perf_io_uring_exit_calls;
}

TEST(QuicPerfServerTest, RejectsProtocolVersionMismatch) {
    const auto error = validate_perf_session_start(QuicPerfSessionStart{
        .protocol_version = 99,
        .mode = QuicPerfMode::bulk,
        .direction = QuicPerfDirection::download,
        .request_bytes = 0,
        .response_bytes = 0,
        .total_bytes = 65536,
        .requests = std::nullopt,
        .warmup_ms = 0,
        .duration_ms = 1000,
        .streams = 1,
        .connections = 1,
        .requests_in_flight = 1,
    });

    ASSERT_TRUE(error.has_value());
    EXPECT_EQ(error.value_or(""), "unsupported protocol version");
}

TEST(QuicPerfServerTest, RejectsZeroStreams) {
    const auto error = validate_perf_session_start(QuicPerfSessionStart{
        .protocol_version = kQuicPerfProtocolVersion,
        .mode = QuicPerfMode::bulk,
        .direction = QuicPerfDirection::download,
        .request_bytes = 0,
        .response_bytes = 0,
        .total_bytes = 65536,
        .requests = std::nullopt,
        .warmup_ms = 0,
        .duration_ms = 1000,
        .streams = 0,
        .connections = 1,
        .requests_in_flight = 1,
    });

    ASSERT_TRUE(error.has_value());
    EXPECT_EQ(error.value_or(""), "streams must be greater than zero");
}

TEST(QuicPerfServerTest, ServerFailsFastWhenIoUringInitializationFails) {
    const coquic::io::test::ScopedIoUringBackendOpsOverride io_uring_ops{
        coquic::io::test::IoUringBackendOpsOverride{
            .queue_init_fn = &fail_perf_io_uring_queue_init,
            .queue_exit_fn = &record_perf_io_uring_queue_exit,
        },
    };

    const QuicPerfConfig config{
        .role = QuicPerfRole::server,
        .io_backend = coquic::io::QuicIoBackendKind::io_uring,
        .host = "127.0.0.1",
        .port = 9443,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    EXPECT_EQ(run_perf_runtime(config), 1);
}
} // namespace
