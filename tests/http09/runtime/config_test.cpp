#include <gtest/gtest.h>

#include "tests/support/http09/runtime_test_fixtures.h"

namespace {
using namespace coquic::http09::test_support;

TEST(QuicHttp09RuntimeTest, ClientDerivesPeerAddressAndServerNameFromRequests) {
    coquic::quic::test::ScopedTempDir document_root;
    coquic::quic::test::ScopedTempDir download_root;
    document_root.write_file("hello.txt", "hello-from-request-authority");

    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::http09::QuicHttp09Testcase::transfer,
        .document_root = document_root.path(),
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .port = 443,
        .testcase = coquic::http09::QuicHttp09Testcase::transfer,
        .download_root = download_root.path(),
        .server_name = "",
        .requests_env = "https://localhost:" + std::to_string(port) + "/hello.txt",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
    EXPECT_EQ(read_file_bytes(download_root.path() / "hello.txt"), "hello-from-request-authority");
}

TEST(QuicHttp09RuntimeTest, ClientConnectionRejectsInvalidDerivedRequestAuthority) {
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::http09::QuicHttp09Request> requests = {
        {.url = "https://[::1/a.txt",
         .authority = "[::1",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };

    EXPECT_EQ(coquic::http09::test::run_http09_client_connection_for_tests(client, requests, 1), 1);
}

TEST(QuicHttp09RuntimeTest, RuntimeBuildsCoreConfigWithInteropAlpnAndDefaults) {
    const auto runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .testcase = coquic::http09::QuicHttp09Testcase::transfer,
        .server_name = "",
        .requests_env = "https://localhost/a.txt https://localhost/b.txt",
    };
    EXPECT_EQ(runtime.mode, coquic::http09::Http09RuntimeMode::client);
    EXPECT_TRUE(runtime.host.empty());
    EXPECT_TRUE(runtime.server_name.empty());
    EXPECT_EQ(runtime.application_protocol, "hq-interop");
    EXPECT_EQ(runtime.document_root, std::filesystem::path("/www"));
    EXPECT_EQ(runtime.download_root, std::filesystem::path("/downloads"));
    EXPECT_EQ(runtime.certificate_chain_path, std::filesystem::path("/certs/cert.pem"));
    EXPECT_EQ(runtime.private_key_path, std::filesystem::path("/certs/priv.key"));

    auto overridden_runtime = runtime;
    overridden_runtime.application_protocol = "not-hq-interop";

    const auto client_core = coquic::http09::make_http09_client_core_config(overridden_runtime);
    EXPECT_EQ(client_core.application_protocol, "hq-interop");
    EXPECT_EQ(client_core.max_outbound_datagram_size, 1452u);
    EXPECT_EQ(client_core.transport.max_udp_payload_size, 1452u);
    EXPECT_EQ(client_core.transport.pmtud_base_datagram_size, 1452u);
    EXPECT_EQ(client_core.transport.pmtud_max_datagram_size, 1452u);
    EXPECT_EQ(client_core.transport.max_idle_timeout, 180000u);
    EXPECT_EQ(client_core.transport.initial_max_data, 32u * 1024u * 1024u);
    EXPECT_EQ(client_core.transport.initial_max_stream_data_bidi_local, 16u * 1024u * 1024u);
    EXPECT_EQ(client_core.transport.initial_max_stream_data_bidi_remote, 256u * 1024u);
    EXPECT_EQ(client_core.original_version, 0x00000001u);
    EXPECT_EQ(client_core.initial_version, 0x00000001u);
    EXPECT_EQ(client_core.supported_versions, (std::vector<std::uint32_t>{0x00000001u}));

    auto server_runtime = overridden_runtime;
    server_runtime.mode = coquic::http09::Http09RuntimeMode::server;
    server_runtime.certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    server_runtime.private_key_path = "tests/fixtures/quic-server-key.pem";
    const auto server_core = coquic::http09::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.application_protocol, "hq-interop");
    EXPECT_EQ(server_core.max_outbound_datagram_size, 1452u);
    EXPECT_EQ(server_core.transport.max_udp_payload_size, 1452u);
    EXPECT_EQ(server_core.transport.pmtud_base_datagram_size, 1452u);
    EXPECT_EQ(server_core.transport.pmtud_max_datagram_size, 1452u);
    EXPECT_EQ(server_core.transport.max_idle_timeout, 180000u);
    EXPECT_EQ(server_core.original_version, 0x00000001u);
    EXPECT_EQ(server_core.initial_version, 0x00000001u);
    EXPECT_EQ(server_core.supported_versions, (std::vector<std::uint32_t>{0x00000001u}));
    if (!server_core.identity.has_value()) {
        FAIL() << "expected server identity";
    }
    const auto &identity = *server_core.identity;
    EXPECT_EQ(identity.certificate_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-cert.pem"));
    EXPECT_EQ(identity.private_key_pem,
              coquic::quic::test::read_text_file("tests/fixtures/quic-server-key.pem"));

    const auto server_endpoint =
        coquic::http09::test::make_runtime_server_endpoint_config_for_tests(
            server_runtime, coquic::quic::TlsIdentity{
                                .certificate_pem = identity.certificate_pem,
                                .private_key_pem = identity.private_key_pem,
                            });
    EXPECT_EQ(server_endpoint.application_protocol, "hq-interop");
    EXPECT_EQ(server_endpoint.max_outbound_datagram_size, 1452u);
    EXPECT_EQ(server_endpoint.transport.max_udp_payload_size, 1452u);
    EXPECT_EQ(server_endpoint.transport.pmtud_base_datagram_size, 1452u);
    EXPECT_EQ(server_endpoint.transport.pmtud_max_datagram_size, 1452u);
    EXPECT_EQ(server_endpoint.supported_versions, (std::vector<std::uint32_t>{0x00000001u}));
    EXPECT_TRUE(server_endpoint.identity.has_value());
}

TEST(QuicHttp09RuntimeTest, RuntimePropagatesQlogDirectoryIntoClientAndServerCoreConfigs) {
    const auto qlog_path = std::filesystem::path("/logs/qlog");

    const auto client_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .requests_env = "https://localhost/a.txt",
        .qlog_directory = qlog_path,
    };
    const auto client_core = coquic::http09::make_http09_client_core_config(client_runtime);
    ASSERT_TRUE(client_core.qlog.has_value());
    EXPECT_EQ(optional_ref_or_terminate(client_core.qlog).directory, qlog_path);

    const auto server_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .qlog_directory = qlog_path,
    };
    const auto server_core =
        coquic::http09::test::make_http09_server_core_config_with_identity_for_tests(
            server_runtime, coquic::quic::TlsIdentity{
                                .certificate_pem = "test-certificate-pem",
                                .private_key_pem = "test-private-key-pem",
                            });
    ASSERT_TRUE(server_core.qlog.has_value());
    EXPECT_EQ(optional_ref_or_terminate(server_core.qlog).directory, qlog_path);
}

TEST(QuicHttp09RuntimeTest, RuntimePropagatesTlsKeylogPathIntoClientAndServerCoreConfigs) {
    const auto keylog_path = std::filesystem::path("/logs/keys.log");

    const auto client_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .requests_env = "https://localhost/a.txt",
        .tls_keylog_path = keylog_path,
    };
    const auto client_core = coquic::http09::make_http09_client_core_config(client_runtime);
    ASSERT_TRUE(client_core.tls_keylog_path.has_value());
    EXPECT_EQ(optional_ref_or_terminate(client_core.tls_keylog_path), keylog_path);

    const auto server_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .tls_keylog_path = keylog_path,
    };
    const auto server_core =
        coquic::http09::test::make_http09_server_core_config_with_identity_for_tests(
            server_runtime, coquic::quic::TlsIdentity{
                                .certificate_pem = "test-certificate-pem",
                                .private_key_pem = "test-private-key-pem",
                            });
    ASSERT_TRUE(server_core.tls_keylog_path.has_value());
    EXPECT_EQ(optional_ref_or_terminate(server_core.tls_keylog_path), keylog_path);
}

TEST(QuicHttp09RuntimeTest, RejectsMalformedBracketedAuthority) {
    const auto parsed = coquic::http09::parse_http09_authority("[::1");
    EXPECT_FALSE(parsed.has_value());
}

TEST(QuicHttp09RuntimeTest, RejectsEmptyAndColonOnlyAuthorities) {
    EXPECT_FALSE(coquic::http09::parse_http09_authority("").has_value());
    EXPECT_FALSE(coquic::http09::parse_http09_authority(":443").has_value());
}

TEST(QuicHttp09RuntimeTest, ParsesBracketedAuthoritiesWithAndWithoutPort) {
    const auto without_port = coquic::http09::parse_http09_authority("[::1]");
    ASSERT_TRUE(without_port.has_value());
    const auto &without_port_authority = optional_ref_or_terminate(without_port);
    EXPECT_EQ(without_port_authority.host, "::1");
    EXPECT_FALSE(without_port_authority.port.has_value());

    const auto with_port = coquic::http09::parse_http09_authority("[::1]:8443");
    ASSERT_TRUE(with_port.has_value());
    const auto &with_port_authority = optional_ref_or_terminate(with_port);
    EXPECT_EQ(with_port_authority.host, "::1");
    ASSERT_TRUE(with_port_authority.port.has_value());
    EXPECT_EQ(optional_value_or_terminate(with_port_authority.port), 8443);
}

TEST(QuicHttp09RuntimeTest, RejectsBracketedAuthoritiesWithEmptyHostOrInvalidSuffix) {
    EXPECT_FALSE(coquic::http09::parse_http09_authority("[]:443").has_value());
    EXPECT_FALSE(coquic::http09::parse_http09_authority("[::1]extra").has_value());
    EXPECT_FALSE(coquic::http09::parse_http09_authority("[::1]:bad").has_value());
}

TEST(QuicHttp09RuntimeTest, RejectsMalformedHostPortAuthority) {
    const auto parsed = coquic::http09::parse_http09_authority("localhost:bad");
    EXPECT_FALSE(parsed.has_value());
}

TEST(QuicHttp09RuntimeTest, ParsesHostnamePortAndIpv6LiteralAuthorities) {
    const auto host_port = coquic::http09::parse_http09_authority("localhost:9443");
    ASSERT_TRUE(host_port.has_value());
    const auto &host_port_authority = optional_ref_or_terminate(host_port);
    EXPECT_EQ(host_port_authority.host, "localhost");
    ASSERT_TRUE(host_port_authority.port.has_value());
    EXPECT_EQ(optional_value_or_terminate(host_port_authority.port), 9443);

    const auto ipv6_literal = coquic::http09::parse_http09_authority("2001:db8::1");
    ASSERT_TRUE(ipv6_literal.has_value());
    const auto &ipv6_literal_authority = optional_ref_or_terminate(ipv6_literal);
    EXPECT_EQ(ipv6_literal_authority.host, "2001:db8::1");
    EXPECT_FALSE(ipv6_literal_authority.port.has_value());
}

TEST(QuicHttp09RuntimeTest, DerivesHostPortAndServerNameFromRequestWhenUnset) {
    const auto config = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .port = 443,
        .server_name = "",
    };
    const std::vector<coquic::http09::QuicHttp09Request> requests = {
        {.url = "https://127.0.0.1:8443/a.txt",
         .authority = "127.0.0.1:8443",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };
    const auto derived = coquic::http09::derive_http09_client_remote(config, requests);
    ASSERT_TRUE(derived.has_value());
    const auto remote = derived.value_or(coquic::http09::Http09ClientRemote{});
    EXPECT_EQ(remote.host, "127.0.0.1");
    EXPECT_EQ(remote.port, 8443);
    EXPECT_EQ(remote.server_name, "127.0.0.1");
}

TEST(QuicHttp09RuntimeTest, DerivesOnlyServerNameWhenHostAlreadySpecified) {
    const auto config = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 9443,
        .server_name = "",
    };
    const std::vector<coquic::http09::QuicHttp09Request> requests = {
        {.url = "https://localhost/a.txt",
         .authority = "localhost",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };
    const auto derived = coquic::http09::derive_http09_client_remote(config, requests);
    ASSERT_TRUE(derived.has_value());
    const auto remote = derived.value_or(coquic::http09::Http09ClientRemote{});
    EXPECT_EQ(remote.host, "127.0.0.1");
    EXPECT_EQ(remote.port, 9443);
    EXPECT_EQ(remote.server_name, "localhost");
}

TEST(QuicHttp09RuntimeTest, DerivesOnlyHostWhenServerNameAlreadySpecified) {
    const auto config = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .port = 9443,
        .server_name = "example.test",
    };
    const std::vector<coquic::http09::QuicHttp09Request> requests = {
        {.url = "https://localhost/a.txt",
         .authority = "localhost",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };
    const auto derived = coquic::http09::derive_http09_client_remote(config, requests);
    ASSERT_TRUE(derived.has_value());
    const auto remote = derived.value_or(coquic::http09::Http09ClientRemote{});
    EXPECT_EQ(remote.host, "localhost");
    EXPECT_EQ(remote.port, 9443);
    EXPECT_EQ(remote.server_name, "example.test");
}

TEST(QuicHttp09RuntimeTest, DerivationReturnsConfiguredRemoteWithoutRequestsWhenComplete) {
    const auto config = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "203.0.113.10",
        .port = 9443,
        .server_name = "example.test",
    };

    const auto derived = coquic::http09::derive_http09_client_remote(config, {});
    ASSERT_TRUE(derived.has_value());
    const auto &derived_remote = optional_ref_or_terminate(derived);
    EXPECT_EQ(derived_remote.host, "203.0.113.10");
    EXPECT_EQ(derived_remote.port, 9443);
    EXPECT_EQ(derived_remote.server_name, "example.test");
}

TEST(QuicHttp09RuntimeTest, DerivationFailsForEmptyRequestListWhenFallbackRequired) {
    const auto config = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    EXPECT_FALSE(coquic::http09::derive_http09_client_remote(config, {}).has_value());
}

TEST(QuicHttp09RuntimeTest, DerivationFailsForInvalidRequestAuthority) {
    const auto config = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "",
        .server_name = "",
    };
    const std::vector<coquic::http09::QuicHttp09Request> requests = {
        {.url = "https://[::1/a.txt",
         .authority = "[::1",
         .request_target = "/a.txt",
         .relative_output_path = "a.txt"},
    };
    EXPECT_FALSE(coquic::http09::derive_http09_client_remote(config, requests).has_value());
}

TEST(QuicHttp09RuntimeTest, MigrationCasesUseTransferTransportProfile) {
    const auto transfer = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::transfer,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto rebind_port = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::rebind_port,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto rebind_addr = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::rebind_addr,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto migration = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::connectionmigration,
        .requests_env = "https://localhost/hello.txt",
    };

    const auto transfer_core = coquic::http09::make_http09_client_core_config(transfer);
    const auto rebind_port_core = coquic::http09::make_http09_client_core_config(rebind_port);
    const auto rebind_addr_core = coquic::http09::make_http09_client_core_config(rebind_addr);
    const auto migration_core = coquic::http09::make_http09_client_core_config(migration);

    EXPECT_EQ(rebind_port_core.transport.initial_max_data,
              transfer_core.transport.initial_max_data);
    EXPECT_EQ(rebind_addr_core.transport.initial_max_data,
              transfer_core.transport.initial_max_data);
    EXPECT_EQ(migration_core.transport.initial_max_data, transfer_core.transport.initial_max_data);
    EXPECT_EQ(rebind_port_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(rebind_addr_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(migration_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(rebind_port_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
    EXPECT_EQ(rebind_addr_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
    EXPECT_EQ(migration_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
}

TEST(QuicHttp09RuntimeTest, KeyUpdateUsesTransferTransportProfile) {
    const auto keyupdate = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::keyupdate,
        .requests_env = "https://localhost/hello.txt",
    };
    const auto transfer = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::transfer,
        .requests_env = "https://localhost/hello.txt",
    };

    const auto keyupdate_core = coquic::http09::make_http09_client_core_config(keyupdate);
    const auto transfer_core = coquic::http09::make_http09_client_core_config(transfer);

    EXPECT_EQ(keyupdate_core.transport.max_idle_timeout, transfer_core.transport.max_idle_timeout);
    EXPECT_EQ(keyupdate_core.transport.max_udp_payload_size,
              transfer_core.transport.max_udp_payload_size);
    EXPECT_EQ(keyupdate_core.transport.ack_delay_exponent,
              transfer_core.transport.ack_delay_exponent);
    EXPECT_EQ(keyupdate_core.transport.max_ack_delay, transfer_core.transport.max_ack_delay);
    EXPECT_EQ(keyupdate_core.transport.initial_max_data, transfer_core.transport.initial_max_data);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_bidi_local,
              transfer_core.transport.initial_max_stream_data_bidi_local);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_bidi_remote,
              transfer_core.transport.initial_max_stream_data_bidi_remote);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_uni,
              transfer_core.transport.initial_max_stream_data_uni);
    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_bidi,
              transfer_core.transport.initial_max_streams_bidi);
    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(keyupdate_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
    EXPECT_EQ(coquic::http09::test::client_receive_timeout_ms_for_tests(keyupdate),
              coquic::http09::test::client_receive_timeout_ms_for_tests(transfer));
}

TEST(QuicHttp09RuntimeTest, KeyUpdateRuntimeEnablesClientKeyUpdatePolicy) {
    const auto keyupdate = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::keyupdate,
        .download_root = std::filesystem::path("/downloads"),
        .requests_env = "https://localhost/hello.txt",
    };
    const auto transfer = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::transfer,
        .download_root = std::filesystem::path("/downloads"),
        .requests_env = "https://localhost/hello.txt",
    };
    const auto requests = coquic::http09::parse_http09_requests_env("https://localhost/hello.txt");
    ASSERT_TRUE(requests.has_value());

    const auto keyupdate_client_config =
        coquic::http09::test::make_http09_client_endpoint_config_for_tests(
            keyupdate, requests.value(), false, coquic::quic::QuicCoreResult{});
    const auto transfer_client_config =
        coquic::http09::test::make_http09_client_endpoint_config_for_tests(
            transfer, requests.value(), false, coquic::quic::QuicCoreResult{});

    EXPECT_TRUE(keyupdate_client_config.request_key_update);
    EXPECT_FALSE(transfer_client_config.request_key_update);
}

TEST(QuicHttp09RuntimeTest, KeyUpdateUsesTransferTransportProfileOnServerPath) {
    const auto keyupdate = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .testcase = coquic::http09::QuicHttp09Testcase::keyupdate,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto transfer = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .testcase = coquic::http09::QuicHttp09Testcase::transfer,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    const auto keyupdate_core = coquic::http09::make_http09_server_core_config(keyupdate);
    const auto transfer_core = coquic::http09::make_http09_server_core_config(transfer);

    EXPECT_EQ(keyupdate_core.transport.max_idle_timeout, transfer_core.transport.max_idle_timeout);
    EXPECT_EQ(keyupdate_core.transport.max_udp_payload_size,
              transfer_core.transport.max_udp_payload_size);
    EXPECT_EQ(keyupdate_core.transport.ack_delay_exponent,
              transfer_core.transport.ack_delay_exponent);
    EXPECT_EQ(keyupdate_core.transport.max_ack_delay, transfer_core.transport.max_ack_delay);
    EXPECT_EQ(keyupdate_core.transport.initial_max_data, transfer_core.transport.initial_max_data);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_bidi_local,
              transfer_core.transport.initial_max_stream_data_bidi_local);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_bidi_remote,
              transfer_core.transport.initial_max_stream_data_bidi_remote);
    EXPECT_EQ(keyupdate_core.transport.initial_max_stream_data_uni,
              transfer_core.transport.initial_max_stream_data_uni);
    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_bidi,
              transfer_core.transport.initial_max_streams_bidi);
    EXPECT_EQ(keyupdate_core.transport.initial_max_streams_uni,
              transfer_core.transport.initial_max_streams_uni);
    EXPECT_EQ(keyupdate_core.allowed_tls_cipher_suites, transfer_core.allowed_tls_cipher_suites);
}

TEST(QuicHttp09RuntimeTest, RuntimePropagatesCongestionControlSelection) {
    const auto client_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .requests_env = "https://localhost/a.txt",
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::copa,
    };
    const auto client_core = coquic::http09::make_http09_client_core_config(client_runtime);
    EXPECT_EQ(client_core.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::copa);

    const auto server_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
        .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::bbr,
    };
    const auto server_core = coquic::http09::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::bbr);
}

TEST(QuicHttp09RuntimeTest, TransferRuntimeKeepsNewRenoAsDefaultCongestionControl) {
    const auto transfer_client =
        coquic::http09::make_http09_client_core_config(coquic::http09::Http09RuntimeConfig{
            .mode = coquic::http09::Http09RuntimeMode::client,
            .testcase = coquic::http09::QuicHttp09Testcase::transfer,
            .requests_env = "https://localhost/a.txt",
        });
    const auto transfer_server =
        coquic::http09::make_http09_server_core_config(coquic::http09::Http09RuntimeConfig{
            .mode = coquic::http09::Http09RuntimeMode::server,
            .testcase = coquic::http09::QuicHttp09Testcase::transfer,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        });
    const auto keyupdate_server =
        coquic::http09::make_http09_server_core_config(coquic::http09::Http09RuntimeConfig{
            .mode = coquic::http09::Http09RuntimeMode::server,
            .testcase = coquic::http09::QuicHttp09Testcase::keyupdate,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
        });
    const auto handshake_client =
        coquic::http09::make_http09_client_core_config(coquic::http09::Http09RuntimeConfig{
            .mode = coquic::http09::Http09RuntimeMode::client,
            .testcase = coquic::http09::QuicHttp09Testcase::handshake,
        });
    const auto explicit_transfer_newreno_server =
        coquic::http09::make_http09_server_core_config(coquic::http09::Http09RuntimeConfig{
            .mode = coquic::http09::Http09RuntimeMode::server,
            .testcase = coquic::http09::QuicHttp09Testcase::transfer,
            .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
            .private_key_path = "tests/fixtures/quic-server-key.pem",
            .congestion_control = coquic::quic::QuicCongestionControlAlgorithm::newreno,
        });

    EXPECT_EQ(transfer_client.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::newreno);
    EXPECT_EQ(transfer_server.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::newreno);
    EXPECT_EQ(keyupdate_server.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::newreno);
    EXPECT_EQ(handshake_client.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::newreno);
    EXPECT_EQ(explicit_transfer_newreno_server.transport.congestion_control,
              coquic::quic::QuicCongestionControlAlgorithm::newreno);
}

TEST(QuicHttp09RuntimeTest, RuntimeChacha20TestcaseConstrainsCipherSuites) {
    const auto runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::chacha20,
        .requests_env = "https://localhost/a.txt",
    };
    const auto client_core = coquic::http09::make_http09_client_core_config(runtime);
    EXPECT_EQ(client_core.allowed_tls_cipher_suites,
              (std::vector<coquic::quic::CipherSuite>{
                  coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
              }));

    auto server_runtime = runtime;
    server_runtime.mode = coquic::http09::Http09RuntimeMode::server;
    server_runtime.certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    server_runtime.private_key_path = "tests/fixtures/quic-server-key.pem";
    const auto server_core = coquic::http09::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.allowed_tls_cipher_suites,
              (std::vector<coquic::quic::CipherSuite>{
                  coquic::quic::CipherSuite::tls_chacha20_poly1305_sha256,
              }));
}

TEST(QuicHttp09RuntimeTest, RuntimeBuildsV2CoreConfigsWithCompatibleVersionSupport) {
    const auto runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .testcase = coquic::http09::QuicHttp09Testcase::v2,
        .requests_env = "https://localhost/a.txt",
    };

    const auto client_core = coquic::http09::make_http09_client_core_config(runtime);
    EXPECT_EQ(client_core.original_version, 0x00000001u);
    EXPECT_EQ(client_core.initial_version, 0x00000001u);
    EXPECT_EQ(client_core.supported_versions,
              (std::vector<std::uint32_t>{0x6b3343cfu, 0x00000001u}));

    auto server_runtime = runtime;
    server_runtime.mode = coquic::http09::Http09RuntimeMode::server;
    server_runtime.certificate_chain_path = "tests/fixtures/quic-server-cert.pem";
    server_runtime.private_key_path = "tests/fixtures/quic-server-key.pem";
    const auto server_core = coquic::http09::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.original_version, 0x00000001u);
    EXPECT_EQ(server_core.initial_version, 0x00000001u);
    EXPECT_EQ(server_core.supported_versions,
              (std::vector<std::uint32_t>{0x6b3343cfu, 0x00000001u}));
}

TEST(QuicHttp09RuntimeTest, RuntimeBuildsServerCoreConfigWithExtendedIdleTimeoutForMulticonnect) {
    const auto server_runtime = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .testcase = coquic::http09::QuicHttp09Testcase::multiconnect,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };

    const auto server_core = coquic::http09::make_http09_server_core_config(server_runtime);
    EXPECT_EQ(server_core.transport.max_idle_timeout, 180000u);
}

TEST(QuicHttp09RuntimeTest, RuntimeHelperHooksExposeTraceAndConnectionIdFormatting) {
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", std::nullopt);
        EXPECT_FALSE(coquic::http09::test::runtime_trace_enabled_for_tests());
    }
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "");
        EXPECT_FALSE(coquic::http09::test::runtime_trace_enabled_for_tests());
    }
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "0");
        EXPECT_FALSE(coquic::http09::test::runtime_trace_enabled_for_tests());
    }
    {
        ScopedEnvVar trace("COQUIC_RUNTIME_TRACE", "trace");
        EXPECT_TRUE(coquic::http09::test::runtime_trace_enabled_for_tests());
    }

    const coquic::quic::ConnectionId connection_id = {
        std::byte{0x00},
        std::byte{0x1f},
        std::byte{0xa0},
        std::byte{0xff},
    };
    EXPECT_EQ(coquic::http09::test::format_connection_id_hex_for_tests(connection_id), "001fa0ff");

    const auto connection_id_key = coquic::http09::test::connection_id_key_for_tests(connection_id);
    EXPECT_EQ(connection_id_key.size(), connection_id.size());
    EXPECT_EQ(coquic::http09::test::format_connection_id_key_hex_for_tests(connection_id_key),
              "001fa0ff");
    EXPECT_TRUE(coquic::http09::test::connection_id_key_for_tests({}).empty());
}

TEST(QuicHttp09RuntimeTest, ClientFailsWhenRequestsEnvIsInvalidAtRuntime) {
    coquic::quic::test::ScopedTempDir download_root;

    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = 443,
        .download_root = download_root.path(),
        .requests_env = "definitely-not-a-url",
    };

    EXPECT_EQ(coquic::http09::run_http09_runtime(client), 1);
}

TEST(QuicHttp09RuntimeTest, ClientConnectionWithoutRequestsCompletesAfterHandshake) {
    const auto port = allocate_udp_loopback_port();
    ASSERT_NE(port, 0);

    const auto server = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::server,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::http09::QuicHttp09Testcase::handshake,
        .certificate_chain_path = "tests/fixtures/quic-server-cert.pem",
        .private_key_path = "tests/fixtures/quic-server-key.pem",
    };
    const auto client = coquic::http09::Http09RuntimeConfig{
        .mode = coquic::http09::Http09RuntimeMode::client,
        .host = "127.0.0.1",
        .port = port,
        .testcase = coquic::http09::QuicHttp09Testcase::handshake,
        .server_name = "localhost",
    };

    auto server_process = launch_runtime_server_process(server);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(coquic::http09::test::run_http09_client_connection_for_tests(client, {}, 1), 0);
    EXPECT_FALSE(server_process.wait_for_exit(std::chrono::milliseconds(250)).has_value());
}

} // namespace
