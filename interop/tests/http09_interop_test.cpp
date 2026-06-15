#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"
#include "interop/coquic-interop/http09_interop.h"

namespace {
using namespace coquic::http09::test_support;

constexpr std::uint64_t kTransferClientInitialMaxData = 32ull * 1024ull * 1024ull;
constexpr std::uint64_t kTransferClientInitialMaxStreamData = 16ull * 1024ull * 1024ull;
constexpr std::uint64_t kTransferServerInitialMaxStreamsBidi = 64;

void expect_interop_defaults(const coquic::http09::Http09RuntimeConfig &runtime) {
    EXPECT_EQ(runtime.application_protocol, "hq-interop");
    EXPECT_EQ(runtime.client_receive_timeout_ms, 30000);
    EXPECT_EQ(runtime.client_run_mode, coquic::http09::Http09ClientRunMode::single_connection);
    EXPECT_FALSE(runtime.request_key_update);
    EXPECT_FALSE(runtime.attempt_zero_rtt);
    EXPECT_FALSE(runtime.enable_client_preferred_address_migration);
    EXPECT_FALSE(runtime.enable_server_preferred_address);
    EXPECT_FALSE(runtime.server_zero_rtt.allow);
    EXPECT_EQ(runtime.supported_versions,
              (std::vector<std::uint32_t>{coquic::quic::kQuicVersion1}));
}

void expect_transfer_transport_profile(const coquic::http09::Http09RuntimeConfig &runtime) {
    EXPECT_EQ(runtime.client_transport.max_idle_timeout, 180000u);
    EXPECT_EQ(runtime.client_transport.active_connection_id_limit, 8u);
    EXPECT_EQ(runtime.client_transport.initial_max_data, kTransferClientInitialMaxData);
    EXPECT_EQ(runtime.client_transport.initial_max_stream_data_bidi_local,
              kTransferClientInitialMaxStreamData);
    EXPECT_EQ(runtime.server_transport.max_idle_timeout, 180000u);
    EXPECT_EQ(runtime.server_transport.active_connection_id_limit, 8u);
    EXPECT_EQ(runtime.server_transport.initial_max_streams_bidi,
              kTransferServerInitialMaxStreamsBidi);
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsOfficialRunnerAliasesViaCliFlags) {
    const char *multiconnect_argv[] = {"coquic",       "interop-client", "--testcase",
                                       "multiconnect", "--requests",     "https://localhost/a.txt"};
    const auto multiconnect =
        coquic::interop::parse_http09_interop_args(6, const_cast<char **>(multiconnect_argv));
    ASSERT_TRUE(multiconnect.has_value());
    const auto multiconnect_runtime = multiconnect.value_or(coquic::http09::Http09RuntimeConfig{});
    EXPECT_EQ(multiconnect_runtime.client_run_mode,
              coquic::http09::Http09ClientRunMode::one_connection_per_request);
    EXPECT_EQ(multiconnect_runtime.client_receive_timeout_ms, 180000);

    const char *chacha20_argv[] = {"coquic",   "interop-client", "--testcase",
                                   "chacha20", "--requests",     "https://localhost/a.txt"};
    const auto chacha20 =
        coquic::interop::parse_http09_interop_args(6, const_cast<char **>(chacha20_argv));
    ASSERT_TRUE(chacha20.has_value());
    const auto chacha20_runtime = chacha20.value_or(coquic::http09::Http09RuntimeConfig{});
    EXPECT_EQ(chacha20_runtime.allowed_tls_cipher_suites,
              (std::vector<coquic::quic::CipherSuite>{
                  coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
              }));
}

TEST(QuicHttp09InteropTest, BuildsRuntimeConfigWithRunnerDefaultsAndClientFallbackRemote) {
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

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_EQ(runtime.mode, coquic::http09::Http09RuntimeMode::client);
    EXPECT_TRUE(runtime.host.empty());
    EXPECT_TRUE(runtime.server_name.empty());
    EXPECT_EQ(runtime.application_protocol, "hq-interop");
    EXPECT_FALSE(runtime.verify_peer);
    EXPECT_EQ(runtime.document_root, std::filesystem::path("/www"));
    EXPECT_EQ(runtime.download_root, std::filesystem::path("/downloads"));
    EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/certs/cert.pem"));
    EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/certs/priv.key"));
}

TEST(QuicHttp09InteropTest, ReadsDiagnosticsPathsFromEnvironment) {
    const char *argv[] = {"coquic"};

    {
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar qlogdir("QLOGDIR", std::nullopt);
        ScopedEnvVar sslkeylogfile("SSLKEYLOGFILE", std::nullopt);

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_FALSE(runtime.qlog_directory.has_value());
        EXPECT_FALSE(runtime.tls_keylog_path.has_value());
    }

    {
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar qlogdir("QLOGDIR", "");
        ScopedEnvVar sslkeylogfile("SSLKEYLOGFILE", "");

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_FALSE(runtime.qlog_directory.has_value());
        EXPECT_FALSE(runtime.tls_keylog_path.has_value());
    }

    {
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar qlogdir("QLOGDIR", "/logs/qlog");
        ScopedEnvVar sslkeylogfile("SSLKEYLOGFILE", "/logs/keys.log");

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        ASSERT_TRUE(runtime.qlog_directory.has_value());
        ASSERT_TRUE(runtime.tls_keylog_path.has_value());
        EXPECT_EQ(optional_ref_or_terminate(runtime.qlog_directory),
                  std::filesystem::path("/logs/qlog"));
        EXPECT_EQ(optional_ref_or_terminate(runtime.tls_keylog_path),
                  std::filesystem::path("/logs/keys.log"));
    }
}

TEST(QuicHttp09InteropTest, RejectsInvalidPortsRolesUsageAndMissingRequests) {
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar invalid_port("PORT", "70000");
        EXPECT_FALSE(
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv)).has_value());
    }

    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar empty_port("PORT", "");
        EXPECT_FALSE(
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv)).has_value());
    }

    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "invalid");
        EXPECT_FALSE(
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv)).has_value());
    }

    {
        ScopedEnvVar role("ROLE", std::nullopt);
        const char *bad_subcommand_argv[] = {"coquic", "interop-runner"};
        EXPECT_FALSE(
            coquic::interop::parse_http09_interop_args(2, const_cast<char **>(bad_subcommand_argv))
                .has_value());

        const char *missing_value_argv[] = {"coquic", "interop-client", "--host"};
        EXPECT_FALSE(
            coquic::interop::parse_http09_interop_args(3, const_cast<char **>(missing_value_argv))
                .has_value());

        const char *unknown_flag_argv[] = {"coquic", "interop-client", "--invalid"};
        EXPECT_FALSE(
            coquic::interop::parse_http09_interop_args(3, const_cast<char **>(unknown_flag_argv))
                .has_value());

        const char *missing_requests_argv[] = {"coquic", "interop-client"};
        EXPECT_FALSE(coquic::interop::parse_http09_interop_args(
                         2, const_cast<char **>(missing_requests_argv))
                         .has_value());
    }
}

TEST(QuicHttp09InteropTest, RejectsUnknownTestcaseNamesFromEnvironmentAndCli) {
    {
        const char *env_argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar testcase("TESTCASE", "unknown-case");
        EXPECT_FALSE(coquic::interop::parse_http09_interop_args(1, const_cast<char **>(env_argv))
                         .has_value());
    }

    {
        ScopedEnvVar role("ROLE", std::nullopt);
        ScopedEnvVar requests("REQUESTS", std::nullopt);
        ScopedEnvVar testcase("TESTCASE", std::nullopt);
        const char *cli_argv[] = {"coquic",       "interop-client", "--testcase",
                                  "unknown-case", "--requests",     "https://localhost/a.txt"};
        EXPECT_FALSE(coquic::interop::parse_http09_interop_args(6, const_cast<char **>(cli_argv))
                         .has_value());
    }
}

TEST(QuicHttp09InteropTest, ParsesIoBackendSelection) {
    const char *default_argv[] = {
        "coquic",
        "interop-client",
        "--requests",
        "https://localhost/a.txt",
    };
    const auto default_parsed = coquic::interop::parse_http09_interop_args(
        static_cast<int>(std::size(default_argv)), const_cast<char **>(default_argv));
    ASSERT_TRUE(default_parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(default_parsed).io_backend,
              coquic::io::QuicIoBackendKind::socket);

    const char *uring_argv[] = {
        "coquic",       "interop-client", "--requests", "https://localhost/a.txt",
        "--io-backend", "io_uring",
    };
    const auto uring_parsed = coquic::interop::parse_http09_interop_args(
        static_cast<int>(std::size(uring_argv)), const_cast<char **>(uring_argv));
    ASSERT_TRUE(uring_parsed.has_value());
    EXPECT_EQ(optional_ref_or_terminate(uring_parsed).io_backend,
              coquic::io::QuicIoBackendKind::io_uring);

    const char *invalid_argv[] = {
        "coquic", "interop-client", "--requests", "https://localhost/a.txt", "--io-backend", "dpdk",
    };
    EXPECT_FALSE(coquic::interop::parse_http09_interop_args(
                     static_cast<int>(std::size(invalid_argv)), const_cast<char **>(invalid_argv))
                     .has_value());
}

TEST(QuicHttp09InteropTest, ParsesServerEnvironmentAndCliFlags) {
    {
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

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_EQ(runtime.mode, coquic::http09::Http09RuntimeMode::server);
        EXPECT_EQ(runtime.host, "0.0.0.0");
        EXPECT_EQ(runtime.port, 8443);
        expect_interop_defaults(runtime);
        EXPECT_EQ(runtime.document_root, std::filesystem::path("/srv/http09"));
        EXPECT_EQ(runtime.download_root, std::filesystem::path("/srv/downloads"));
        EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/tls/cert.pem"));
        EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/tls/key.pem"));
        EXPECT_EQ(runtime.server_name, "interop.example");
        EXPECT_FALSE(runtime.verify_peer);
    }

    {
        const char *argv[] = {"coquic",          "interop-server",  "--host",
                              "0.0.0.0",         "--port",          "9443",
                              "--document-root", "/srv/http09",     "--certificate-chain",
                              "/tls/cert.pem",   "--private-key",   "/tls/key.pem",
                              "--server-name",   "interop.example", "--verify-peer"};
        const auto parsed = coquic::interop::parse_http09_interop_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_EQ(runtime.mode, coquic::http09::Http09RuntimeMode::server);
        EXPECT_EQ(runtime.host, "0.0.0.0");
        EXPECT_EQ(runtime.port, 9443);
        EXPECT_EQ(runtime.document_root, std::filesystem::path("/srv/http09"));
        EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/tls/cert.pem"));
        EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/tls/key.pem"));
        EXPECT_EQ(runtime.server_name, "interop.example");
        EXPECT_TRUE(runtime.verify_peer);
    }
}

TEST(QuicHttp09InteropTest, ParsesRetryFlagsAndRetryTestcaseAlias) {
    {
        const char *argv[] = {"coquic", "interop-server", "--retry"};
        ScopedEnvVar role("ROLE", "server");
        ScopedEnvVar retry("RETRY", "1");

        const auto parsed = coquic::interop::parse_http09_interop_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_TRUE(optional_ref_or_terminate(parsed).retry_enabled);
    }

    {
        const char *env_argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "server");
        ScopedEnvVar testcase("TESTCASE", "retry");

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(env_argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_TRUE(runtime.retry_enabled);
        expect_interop_defaults(runtime);
    }

    {
        const char *cli_argv[] = {"coquic", "interop-client", "--testcase",
                                  "retry",  "--requests",     "https://localhost/a.txt"};
        const auto parsed =
            coquic::interop::parse_http09_interop_args(6, const_cast<char **>(cli_argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_TRUE(runtime.retry_enabled);
        expect_interop_defaults(runtime);
    }
}

TEST(QuicHttp09InteropTest, ParsesAndRejectsCongestionControlSelection) {
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar congestion_control("COQUIC_CONGESTION_CONTROL", "copa");

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(optional_ref_or_terminate(parsed).congestion_control,
                  coquic::quic::QuicCongestionControlAlgorithm::copa);
    }

    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar congestion_control("COQUIC_CONGESTION_CONTROL", "");

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(optional_ref_or_terminate(parsed).congestion_control,
                  coquic::quic::QuicCongestionControlAlgorithm::newreno);
    }

    {
        const char *argv[] = {"coquic", "interop-client", "--congestion-control",
                              "pcc",    "--requests",     "https://localhost/a.txt"};
        const auto parsed = coquic::interop::parse_http09_interop_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(optional_ref_or_terminate(parsed).congestion_control,
                  coquic::quic::QuicCongestionControlAlgorithm::pcc);
    }

    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");
        ScopedEnvVar congestion_control("COQUIC_CONGESTION_CONTROL", "vegas");

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        EXPECT_FALSE(parsed.has_value());
    }

    {
        const char *argv[] = {"coquic", "interop-client", "--congestion-control",
                              "vegas",  "--requests",     "https://localhost/a.txt"};
        const auto parsed = coquic::interop::parse_http09_interop_args(
            static_cast<int>(std::size(argv)), const_cast<char **>(argv));
        EXPECT_FALSE(parsed.has_value());
    }
}

TEST(QuicHttp09InteropTest, CliFlagsOverrideEnvironmentAndKeepExplicitClientRemote) {
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

    const auto parsed = coquic::interop::parse_http09_interop_args(
        static_cast<int>(std::size(argv)), const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_EQ(runtime.mode, coquic::http09::Http09RuntimeMode::client);
    EXPECT_EQ(runtime.host, "198.51.100.20");
    EXPECT_EQ(runtime.port, 9443);
    EXPECT_EQ(runtime.allowed_tls_cipher_suites,
              (std::vector<coquic::quic::CipherSuite>{
                  coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
              }));
    EXPECT_EQ(runtime.requests_env, "https://cli.example/a.txt https://cli.example/b.txt");
    EXPECT_EQ(runtime.document_root, std::filesystem::path("/unused/server-root"));
    EXPECT_EQ(runtime.download_root, std::filesystem::path("/cli/downloads"));
    EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/cli/cert.pem"));
    EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/cli/key.pem"));
    EXPECT_EQ(runtime.server_name, "cli.example");
    EXPECT_TRUE(runtime.verify_peer);
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsOfficialMulticonnectTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "multiconnect");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt https://localhost/b.txt");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_EQ(runtime.client_run_mode,
              coquic::http09::Http09ClientRunMode::one_connection_per_request);
    EXPECT_EQ(runtime.client_receive_timeout_ms, 180000);
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsOfficialV2Testcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "v2");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_EQ(runtime.original_version, coquic::quic::kQuicVersion1);
    EXPECT_EQ(runtime.initial_version, coquic::quic::kQuicVersion1);
    EXPECT_EQ(
        runtime.supported_versions,
        (std::vector<std::uint32_t>{coquic::quic::kQuicVersion2, coquic::quic::kQuicVersion1}));
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsOfficialEcnTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "ecn");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    expect_transfer_transport_profile(optional_ref_or_terminate(parsed));
}

TEST(QuicHttp09InteropTest, RuntimeTreatsAmplificationLimitEnvironmentAliasAsTransfer) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "amplificationlimit");
    ScopedEnvVar requests("REQUESTS", "https://localhost/a.txt");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    expect_transfer_transport_profile(optional_ref_or_terminate(parsed));
}

TEST(QuicHttp09InteropTest, RuntimeTreatsAmplificationLimitCliAliasAsTransfer) {
    const char *argv[] = {"coquic",     "interop-client",
                          "--testcase", "amplificationlimit",
                          "--requests", "https://localhost/a.txt"};

    const auto parsed = coquic::interop::parse_http09_interop_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    expect_transfer_transport_profile(optional_ref_or_terminate(parsed));
}

TEST(QuicHttp09InteropTest, RuntimeTreatsMultiplexingAliasAsTransfer) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "server");
    ScopedEnvVar testcase("TESTCASE", "multiplexing");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    expect_transfer_transport_profile(optional_ref_or_terminate(parsed));
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsOfficialResumptionAndZeroRttTestcases) {
    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "resumption");
        ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_EQ(runtime.client_run_mode,
                  coquic::http09::Http09ClientRunMode::resumption_sequence);
        EXPECT_FALSE(runtime.attempt_zero_rtt);
        EXPECT_TRUE(runtime.server_zero_rtt.allow);
        EXPECT_TRUE(runtime.client_transport.disable_active_migration);
        EXPECT_EQ(runtime.server_transport.initial_max_streams_bidi, 64u);
    }

    {
        const char *argv[] = {"coquic"};
        ScopedEnvVar role("ROLE", "client");
        ScopedEnvVar testcase("TESTCASE", "zerortt");
        ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

        const auto parsed =
            coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
        ASSERT_TRUE(parsed.has_value());
        const auto &runtime = optional_ref_or_terminate(parsed);
        EXPECT_EQ(runtime.client_run_mode,
                  coquic::http09::Http09ClientRunMode::resumption_sequence);
        EXPECT_TRUE(runtime.attempt_zero_rtt);
        EXPECT_TRUE(runtime.server_zero_rtt.allow);
        EXPECT_TRUE(runtime.client_transport.disable_active_migration);
        EXPECT_EQ(runtime.server_transport.initial_max_streams_bidi, 64u);
    }
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsOfficialKeyUpdateTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "keyupdate");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_TRUE(runtime.request_key_update);
    expect_transfer_transport_profile(runtime);
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsKeyUpdateCliFlag) {
    const char *argv[] = {"coquic",    "interop-client", "--testcase",
                          "keyupdate", "--requests",     "https://localhost/hello.txt"};

    const auto parsed = coquic::interop::parse_http09_interop_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_TRUE(runtime.request_key_update);
    expect_transfer_transport_profile(runtime);
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsOfficialRebindPortTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "rebind-port");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    expect_transfer_transport_profile(optional_ref_or_terminate(parsed));
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsRebindAddrCliFlag) {
    const char *argv[] = {"coquic",      "interop-client", "--testcase",
                          "rebind-addr", "--requests",     "https://localhost/hello.txt"};

    const auto parsed = coquic::interop::parse_http09_interop_args(6, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    expect_transfer_transport_profile(optional_ref_or_terminate(parsed));
}

TEST(QuicHttp09InteropTest, RuntimeAcceptsOfficialConnectionMigrationTestcase) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "connectionmigration");
    ScopedEnvVar requests("REQUESTS", "https://localhost/hello.txt");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_TRUE(runtime.enable_client_preferred_address_migration);
    EXPECT_TRUE(runtime.enable_server_preferred_address);
    expect_transfer_transport_profile(runtime);
}

TEST(QuicHttp09InteropTest, RuntimeEnablesMigrationForOfficialServer46TransferAlias) {
    const char *argv[] = {"coquic"};
    ScopedEnvVar role("ROLE", "client");
    ScopedEnvVar testcase("TESTCASE", "transfer");
    ScopedEnvVar requests("REQUESTS", "https://server46:443/file.bin");

    const auto parsed = coquic::interop::parse_http09_interop_args(1, const_cast<char **>(argv));
    ASSERT_TRUE(parsed.has_value());
    const auto &runtime = optional_ref_or_terminate(parsed);
    EXPECT_TRUE(runtime.enable_client_preferred_address_migration);
    EXPECT_FALSE(runtime.enable_server_preferred_address);
    expect_transfer_transport_profile(runtime);
}

} // namespace
