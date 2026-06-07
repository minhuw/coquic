#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::http09::test_support;

void expect_transfer_complete(const InMemoryHttp09TransferResult &result) {
    if (result.client_complete) {
        return;
    }

    ADD_FAILURE() << "steps=" << result.steps << " hit_step_limit=" << result.hit_step_limit
                  << " client_failed=" << result.client_failed
                  << " server_failed=" << result.server_failed
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
}

TEST(QuicHttp09RuntimeTest, ClientAndServerTransferSingleFileOverUdpSockets) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-over-udp");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/hello.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-over-udp");
}

TEST(QuicHttp09RuntimeTest, ClientAndServerTransferSingleFileAfterConnectionMigration) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-after-migration");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .enable_client_preferred_address_migration = true,
        .enable_server_preferred_address = true,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .enable_client_preferred_address_migration = true,
        .enable_server_preferred_address = true,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/hello.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-after-migration");
}

TEST(QuicHttp09RuntimeTest, InMemoryClientAndServerTransferLargeFile) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    constexpr std::size_t kLargeBodyBytes = 2ULL * 1024ULL * 1024ULL;
    const std::string large_body(kLargeBodyBytes, 'L');
    document_root.write_file("large.bin", large_body);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/large.bin",
    };

    const auto result = run_in_memory_http09_transfer({
        .client_config = client,
        .server_config = server,
    });

    expect_transfer_complete(result);
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

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/large.bin",
    };

    const auto result = run_in_memory_http09_transfer({
        .client_config = client,
        .server_config = server,
        .dropped_client_datagrams = {10},
        .dropped_server_datagrams = {28, 58},
    });

    expect_transfer_complete(result);
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

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/medium.bin",
    };

    const auto result = run_in_memory_http09_transfer({
        .client_config = client,
        .server_config = server,
    });

    expect_transfer_complete(result);
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

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = 443,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .download_root = download_root.path(),
        .requests_env = requests_env.str(),
    };

    const auto result = run_in_memory_http09_transfer({
        .client_config = client,
        .server_config = server,
    });

    expect_transfer_complete(result);
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

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/large.bin",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
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

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/hello.txt",
    };

    const ScopedDropSmallAckDatagramReset drop_reset;
    g_small_ack_datagrams_to_drop_after_request.store(2);

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    {
        const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
            {
                .sendto_fn = &drop_nth_small_ack_datagram_after_request,
            },
        };
        EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    }

    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "ack-retry-body");
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

TEST(QuicHttp09RuntimeTest, SingleConnectionModeUsesMultipleStreams) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("alpha.txt", "alpha-bytes");
    document_root.write_file("beta.txt", "beta-bytes");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/alpha.txt https://localhost/beta.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");
}

TEST(QuicHttp09RuntimeTest, OneConnectionPerRequestModeUsesSeparateConnectionPerRequest) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("alpha.txt", "alpha-bytes");
    document_root.write_file("beta.txt", "beta-bytes");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .client_run_mode = coquic::http09::Http09ClientRunMode::one_connection_per_request,
        .client_receive_timeout_ms = 180000,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .client_run_mode = coquic::http09::Http09ClientRunMode::one_connection_per_request,
        .client_receive_timeout_ms = 180000,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/alpha.txt https://localhost/beta.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");
}

TEST(QuicHttp09RuntimeTest,
     OneConnectionPerRequestModeSupportsThreeRequestsWithoutRoutingCollisions) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("alpha.txt", "alpha-bytes");
    document_root.write_file("beta.txt", "beta-bytes");
    document_root.write_file("gamma.txt", "gamma-bytes");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .client_run_mode = coquic::http09::Http09ClientRunMode::one_connection_per_request,
        .client_receive_timeout_ms = 180000,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .client_run_mode = coquic::http09::Http09ClientRunMode::one_connection_per_request,
        .client_receive_timeout_ms = 180000,
        .download_root = download_root.path(),
        .requests_env =
            "https://localhost/alpha.txt https://localhost/beta.txt https://localhost/gamma.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-bytes");
    EXPECT_EQ(read_file_bytes(download_root.path() / "gamma.txt"), "gamma-bytes");
}

TEST(QuicHttp09RuntimeTest, ClientAndServerTransferSingleFileWithResumptionSequence) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-after-resumption");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .server_zero_rtt = coquic::quic::QuicZeroRttConfig{.allow = true},
        .client_run_mode = coquic::http09::Http09ClientRunMode::resumption_sequence,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .server_zero_rtt = coquic::quic::QuicZeroRttConfig{.allow = true},
        .client_run_mode = coquic::http09::Http09ClientRunMode::resumption_sequence,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/hello.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-after-resumption");
}

TEST(QuicHttp09RuntimeTest, ClientMulticonnectStopsWhenAConnectionFails) {
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "invalid-host-name",
        .port = 443,
        .client_run_mode = coquic::http09::Http09ClientRunMode::one_connection_per_request,
        .client_receive_timeout_ms = 180000,
        .server_name = "localhost",
        .requests_env = "https://localhost/a.txt https://localhost/b.txt",
    };

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientAndRuntimeServerTransferLargeFileOverUdpSockets) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    constexpr std::size_t kLargeBodyBytes = 2ULL * 1024ULL * 1024ULL;
    const std::string large_body(kLargeBodyBytes, 'R');
    document_root.write_file("runtime-large.bin", large_body);

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .download_root = download_root.path(),
        .requests_env = "https://localhost/runtime-large.bin",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "runtime-large.bin"), large_body);
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

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .client_run_mode = coquic::http09::Http09ClientRunMode::one_connection_per_request,
        .client_receive_timeout_ms = 180000,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .client_run_mode = coquic::http09::Http09ClientRunMode::one_connection_per_request,
        .client_receive_timeout_ms = 180000,
        .download_root = download_root.path(),
        .requests_env =
            "https://localhost/alpha.txt https://localhost/beta.txt https://localhost/gamma.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "alpha.txt"), "alpha-runtime");
    EXPECT_EQ(read_file_bytes(download_root.path() / "beta.txt"), "beta-runtime");
    EXPECT_EQ(read_file_bytes(download_root.path() / "gamma.txt"), "gamma-runtime");
}

} // namespace
