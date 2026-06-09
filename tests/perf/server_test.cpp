#include <algorithm>
#include <cerrno>

#include <gtest/gtest.h>

#include "tests/support/core/endpoint_test_fixtures.h"
#include "tests/support/perf/perf_test_fixtures.h"

#define private public
#include "src/io/io_backend_test_hooks.h"
#include "bench/coquic-perf/perf_server.h"
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
        operations.push_back("wait");
        if (pending_events.empty()) {
            return std::nullopt;
        }
        auto event = pending_events.front();
        pending_events.erase(pending_events.begin());
        return event;
    }

    bool has_pending_events() const override {
        return !pending_events.empty();
    }

    bool send(const coquic::io::QuicIoTxDatagram &datagram) override {
        operations.push_back("send");
        sent_datagrams.push_back(coquic::io::QuicIoTxDatagram{
            .route_handle = datagram.route_handle,
            .bytes = coquic::quic::DatagramBuffer{datagram.payload()},
            .ecn = datagram.ecn,
            .is_pmtu_probe = datagram.is_pmtu_probe,
        });
        return true;
    }

    bool send_many_on_route(coquic::quic::QuicRouteHandle route_handle,
                            std::span<const coquic::io::QuicIoTxDatagram> datagrams) override {
        operations.push_back("send_many_on_route");
        for (const auto &datagram : datagrams) {
            sent_datagrams.push_back(coquic::io::QuicIoTxDatagram{
                .route_handle = route_handle,
                .bytes = coquic::quic::DatagramBuffer{datagram.payload()},
                .ecn = datagram.ecn,
                .is_pmtu_probe = datagram.is_pmtu_probe,
            });
        }
        return true;
    }

    std::vector<coquic::io::QuicIoEvent> pending_events;
    std::vector<coquic::io::QuicIoTxDatagram> sent_datagrams;
    std::vector<std::string> operations;
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
        .warmup = coquic::quic::QuicCoreDuration{0},
        .duration = coquic::quic::QuicCoreDuration{1000000},
        .streams = 1,
        .connections = 1,
        .requests_in_flight = 1,
    };
}

QuicPerfSessionStart make_validation_start(std::uint32_t protocol_version, std::uint64_t streams) {
    return QuicPerfSessionStart{
        .protocol_version = protocol_version,
        .mode = QuicPerfMode::bulk,
        .direction = QuicPerfDirection::download,
        .request_bytes = 0,
        .response_bytes = 0,
        .total_bytes = 65536,
        .requests = std::nullopt,
        .warmup = coquic::quic::QuicCoreDuration{0},
        .duration = coquic::quic::QuicCoreDuration{1000000},
        .streams = streams,
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
    const auto error = validate_perf_session_start(make_validation_start(99, 1));

    ASSERT_TRUE(error.has_value());
    EXPECT_EQ(error.value_or(""), "unsupported protocol version");
}

TEST(QuicPerfServerTest, RejectsZeroStreams) {
    const auto error =
        validate_perf_session_start(make_validation_start(kQuicPerfProtocolVersion, 0));

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

TEST(QuicPerfServerTest, FixedDownloadPayloadCacheRetainsPreviouslyMaterializedSizes) {
    QuicPerfServer server(QuicPerfConfig{}, nullptr);
    const auto first = server.cached_download_payload(4096);

    for (std::size_t i = 0; i < 16; ++i) {
        static_cast<void>(server.cached_download_payload(8192 + i));
    }

    const auto second = server.cached_download_payload(4096);
    ASSERT_NE(first.storage(), nullptr);
    EXPECT_EQ(first.storage(), second.storage());
    EXPECT_TRUE(server.download_payload_cache_.contains(4096));
}

TEST(QuicPerfServerTest, PerfSendBufferOwnsBufferedDatagramBytesUntilFlush) {
    RecordingIoBackend backend;
    PerfSendBuffer buffer;

    coquic::quic::QuicCoreResult result;
    result.effects.emplace_back(coquic::quic::QuicCoreSendDatagram{
        .connection = 1,
        .route_handle = 17,
        .bytes =
            coquic::quic::DatagramBuffer{std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}}},
    });

    ASSERT_TRUE(buffer.append_or_flush(backend, result));
    EXPECT_EQ(buffer.size(), 1u);
    EXPECT_TRUE(backend.sent_datagrams.empty());

    auto *send = std::get_if<coquic::quic::QuicCoreSendDatagram>(&result.effects.front());
    ASSERT_NE(send, nullptr);
    send->bytes.clear();

    ASSERT_TRUE(buffer.flush(backend));
    EXPECT_EQ(buffer.size(), 0u);
    ASSERT_EQ(backend.sent_datagrams.size(), 1u);
    const auto sent_payload = backend.sent_datagrams.front().payload();
    if (sent_payload.size() != 2u) {
        FAIL() << "buffered datagram payload had unexpected size";
    }
    EXPECT_EQ(sent_payload[0], std::byte{0x01});
    EXPECT_EQ(sent_payload[1], std::byte{0x02});
}

TEST(QuicPerfServerTest, PerfSendBufferReportsBufferedDatagramCount) {
    RecordingIoBackend backend;
    PerfSendBuffer buffer;

    coquic::quic::QuicCoreResult result;
    result.effects.emplace_back(coquic::quic::QuicCoreSendDatagram{
        .connection = 1,
        .route_handle = 17,
        .bytes = coquic::quic::DatagramBuffer{std::vector<std::byte>{std::byte{0x01}}},
    });

    EXPECT_EQ(buffer.size(), 0u);
    ASSERT_TRUE(buffer.append_or_flush(backend, result));
    EXPECT_EQ(buffer.size(), 1u);
    EXPECT_TRUE(backend.sent_datagrams.empty());
    ASSERT_TRUE(buffer.flush(backend));
    EXPECT_EQ(buffer.size(), 0u);
    EXPECT_EQ(backend.sent_datagrams.size(), 1u);
}

TEST(QuicPerfServerTest, PerfSendBufferBoundsDirectSinkDatagrams) {
    RecordingIoBackend backend;
    PerfSendBuffer buffer;
    buffer.set_backend(&backend);

    constexpr std::size_t kBufferedDatagramLimit = 256;
    for (std::size_t index = 0; index < kBufferedDatagramLimit + 1; ++index) {
        ASSERT_TRUE(buffer.on_send_datagram_payload(
            1, 17, coquic::quic::DatagramBuffer{std::vector<std::byte>{std::byte{0x01}}},
            coquic::quic::QuicEcnCodepoint::not_ect, false, 0));
    }

    EXPECT_EQ(buffer.size(), 1u);
    ASSERT_EQ(backend.operations.size(), 1u);
    EXPECT_EQ(backend.operations[0], "send_many_on_route");
    EXPECT_EQ(backend.sent_datagrams.size(), kBufferedDatagramLimit);

    ASSERT_TRUE(buffer.flush(backend));
    EXPECT_EQ(buffer.size(), 0u);
    EXPECT_EQ(backend.sent_datagrams.size(), kBufferedDatagramLimit + 1);
}

TEST(QuicPerfServerTest, PerfSendBufferFlushesRouteRunsWithRouteBatchApi) {
    RecordingIoBackend backend;
    PerfSendBuffer buffer;

    coquic::quic::QuicCoreResult result;
    result.effects.emplace_back(coquic::quic::QuicCoreSendDatagram{
        .connection = 1,
        .route_handle = 17,
        .bytes = coquic::quic::DatagramBuffer{std::vector<std::byte>{std::byte{0x01}}},
    });
    result.effects.emplace_back(coquic::quic::QuicCoreSendDatagram{
        .connection = 1,
        .route_handle = 17,
        .bytes = coquic::quic::DatagramBuffer{std::vector<std::byte>{std::byte{0x02}}},
    });
    result.effects.emplace_back(coquic::quic::QuicCoreSendDatagram{
        .connection = 1,
        .route_handle = 18,
        .bytes = coquic::quic::DatagramBuffer{std::vector<std::byte>{std::byte{0x03}}},
    });

    ASSERT_TRUE(buffer.append_or_flush(backend, result));
    ASSERT_TRUE(buffer.flush(backend));

    ASSERT_EQ(backend.operations.size(), 2u);
    EXPECT_EQ(backend.operations[0], "send_many_on_route");
    EXPECT_EQ(backend.operations[1], "send_many_on_route");
    ASSERT_EQ(backend.sent_datagrams.size(), 3u);
    EXPECT_EQ(backend.sent_datagrams[0].route_handle, 17u);
    EXPECT_EQ(backend.sent_datagrams[1].route_handle, 17u);
    EXPECT_EQ(backend.sent_datagrams[2].route_handle, 18u);
}

TEST(QuicPerfServerTest, FlushSendsBufferedDatagramsBeforeDrainingQueuedBackendEvents) {
    auto backend = std::make_unique<RecordingIoBackend>();
    auto *backend_ptr = backend.get();
    backend_ptr->pending_events.push_back(coquic::io::QuicIoEvent{
        .kind = coquic::io::QuicIoEvent::Kind::timer_expired,
        .now = coquic::quic::test::test_time(1),
    });
    QuicPerfServer server(QuicPerfConfig{}, std::move(backend));
    coquic::quic::QuicCoreResult result;
    result.effects.emplace_back(coquic::quic::QuicCoreSendDatagram{
        .connection = 1,
        .route_handle = 17,
        .bytes = coquic::quic::DatagramBuffer{std::vector<std::byte>{std::byte{0x01}}},
    });

    ASSERT_TRUE(server.send_buffer_.append_or_flush(*backend_ptr, result));
    EXPECT_TRUE(backend_ptr->operations.empty());
    ASSERT_TRUE(server.flush_pending_sends());

    ASSERT_EQ(backend_ptr->operations.size(), 2u);
    EXPECT_EQ(backend_ptr->operations[0], "send_many_on_route");
    EXPECT_EQ(backend_ptr->operations[1], "wait");
    EXPECT_TRUE(backend_ptr->pending_events.empty());
    EXPECT_EQ(backend_ptr->sent_datagrams.size(), 1u);
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
