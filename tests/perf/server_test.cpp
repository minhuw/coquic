#include <algorithm>
#include <cerrno>

#include <gtest/gtest.h>

#include "tests/support/core/endpoint_test_fixtures.h"
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

class RecordingIoBackend final : public coquic::io::QuicIoBackend {
  public:
    std::optional<coquic::quic::QuicRouteHandle>
    ensure_route(const coquic::io::QuicIoRemote &) override {
        return 17;
    }

    std::optional<coquic::io::QuicIoEvent>
    wait(std::optional<coquic::quic::QuicCoreTimePoint>) override {
        return std::nullopt;
    }

    bool send(const coquic::io::QuicIoTxDatagram &datagram) override {
        sent_datagrams.push_back(datagram);
        return true;
    }

    std::vector<coquic::io::QuicIoTxDatagram> sent_datagrams;
};

QuicPerfSessionStart make_fixed_download_start(std::uint64_t response_bytes) {
    return QuicPerfSessionStart{
        .protocol_version = kQuicPerfProtocolVersion,
        .mode = QuicPerfMode::bulk,
        .direction = QuicPerfDirection::download,
        .request_bytes = 0,
        .response_bytes = response_bytes,
        .total_bytes = std::nullopt,
        .requests = std::nullopt,
        .warmup_ms = 0,
        .duration_ms = 1000,
        .streams = 1,
        .connections = 1,
        .requests_in_flight = 1,
    };
}

coquic::quic::QuicConnectionHandle accept_server_connection_for_test(QuicPerfServer &server) {
    coquic::quic::QuicCore client(make_perf_client_endpoint_config(QuicPerfConfig{
        .role = QuicPerfRole::client,
    }));

    const auto open = client.advance_endpoint(
        coquic::quic::QuicCoreOpenConnection{
            .connection = coquic::quic::test_support::make_client_open_config(),
            .initial_route_handle = 17,
        },
        coquic::quic::test::test_time(0));

    std::optional<coquic::quic::QuicConnectionHandle> accepted_connection;
    for (const auto &datagram : coquic::quic::test::send_datagrams_from(open)) {
        const auto result = server.core_.advance_endpoint(
            coquic::quic::QuicCoreInboundDatagram{
                .bytes = datagram,
                .route_handle = 17,
            },
            coquic::quic::test::test_time(1));
        for (const auto &event : coquic::quic::test_support::lifecycle_events_from(result)) {
            if (event.event == coquic::quic::QuicCoreConnectionLifecycle::accepted) {
                accepted_connection = event.connection;
            }
        }
    }

    EXPECT_TRUE(accepted_connection.has_value());
    return accepted_connection.value_or(0);
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

TEST(QuicPerfServerTest, FixedDownloadPayloadCacheReusesSharedStorageBySize) {
    QuicPerfServer server(QuicPerfConfig{}, nullptr);

    const auto empty = server.cached_download_payload(0);
    const auto first = server.cached_download_payload(4096);
    const auto second = server.cached_download_payload(4096);
    const auto different = server.cached_download_payload(2048);

    EXPECT_TRUE(empty.empty());
    EXPECT_EQ(empty.size(), 0u);

    ASSERT_NE(first.storage(), nullptr);
    ASSERT_NE(different.storage(), nullptr);
    EXPECT_EQ(first.storage(), second.storage());
    EXPECT_NE(first.storage(), different.storage());
    EXPECT_EQ(first.size(), 4096u);
    EXPECT_EQ(different.size(), 2048u);
    EXPECT_TRUE(std::all_of(first.begin(), first.end(),
                            [](std::byte byte) { return byte == std::byte{0x5a}; }));
    EXPECT_TRUE(std::all_of(different.begin(), different.end(),
                            [](std::byte byte) { return byte == std::byte{0x5a}; }));
}

TEST(QuicPerfServerTest, FixedDownloadPayloadCacheBoundsEntriesAndKeepsHotSize) {
    QuicPerfServer server(QuicPerfConfig{}, nullptr);
    const auto hot = server.cached_download_payload(4096);

    std::vector<std::size_t> cold_sizes;
    for (std::size_t i = 0; i + 1 < QuicPerfServer::kMaxDownloadPayloadCacheEntries; ++i) {
        cold_sizes.push_back(8192 + i);
        static_cast<void>(server.cached_download_payload(cold_sizes.back()));
    }

    ASSERT_FALSE(cold_sizes.empty());
    const auto oldest_cold_size = cold_sizes.front();
    ASSERT_TRUE(server.download_payload_cache_.contains(oldest_cold_size));
    ASSERT_EQ(server.download_payload_cache_.size(),
              QuicPerfServer::kMaxDownloadPayloadCacheEntries);

    const auto hot_again = server.cached_download_payload(4096);
    EXPECT_EQ(hot.storage(), hot_again.storage());

    static_cast<void>(server.cached_download_payload(16384));

    EXPECT_EQ(server.download_payload_cache_.size(),
              QuicPerfServer::kMaxDownloadPayloadCacheEntries);
    EXPECT_EQ(server.cached_download_payload(4096).storage(), hot.storage());
    EXPECT_FALSE(server.download_payload_cache_.contains(oldest_cold_size));
}

TEST(QuicPerfServerTest, FixedDownloadRuntimeBranchQueuesCachedSharedPayloadOnStream) {
    auto backend = std::make_unique<RecordingIoBackend>();
    auto *backend_ptr = backend.get();
    QuicPerfServer server(QuicPerfConfig{}, std::move(backend));
    const auto connection = accept_server_connection_for_test(server);

    QuicPerfServer::Session session{
        .connection = connection,
        .start = make_fixed_download_start(4096),
    };

    ASSERT_TRUE(server.handle_stream_data(session,
                                          coquic::quic::QuicCoreReceiveStreamData{
                                              .connection = connection,
                                              .stream_id = kQuicPerfFirstDataStreamId,
                                              .bytes = {},
                                              .fin = true,
                                          },
                                          coquic::quic::test::test_time(2)));

    ASSERT_TRUE(server.download_payload_cache_.contains(4096));
    const auto &cached_payload = server.download_payload_cache_.at(4096);
    const auto &connection_entry = server.core_.connections_.at(connection);
    const auto &stream = connection_entry.connection->streams_.at(kQuicPerfFirstDataStreamId);

    ASSERT_EQ(stream.send_buffer.segments_.size(), 1u);
    EXPECT_EQ(stream.send_buffer.segments_.begin()->second.storage.get(),
              cached_payload.storage().get());
    EXPECT_EQ(stream.send_buffer.segments_.begin()->second.begin, 0u);
    EXPECT_EQ(stream.send_buffer.segments_.begin()->second.end, cached_payload.size());
    EXPECT_TRUE(backend_ptr->sent_datagrams.empty());
    EXPECT_EQ(session.bytes_sent, 4096u);
    EXPECT_EQ(session.requests_completed, 1u);
}
} // namespace
