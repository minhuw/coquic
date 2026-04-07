#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "src/quic/tls_adapter.h"
#include "src/quic/tls_adapter_quictls_test_hooks.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::CipherSuite;
using coquic::quic::CodecErrorCode;
using coquic::quic::EncryptionLevel;
using coquic::quic::EndpointRole;
using coquic::quic::TlsAdapter;
using coquic::quic::TlsAdapterConfig;
using coquic::quic::TlsIdentity;
using coquic::quic::test::ScopedTlsAdapterFaultInjector;
using coquic::quic::test::TlsAdapterFaultPoint;
using coquic::quic::test::TlsAdapterTestPeer;

TlsAdapterConfig make_client_config() {
    return TlsAdapterConfig{
        .role = EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    };
}

TlsAdapterConfig make_server_config() {
    return TlsAdapterConfig{
        .role = EndpointRole::server,
        .verify_peer = false,
        .server_name = "localhost",
        .identity =
            TlsIdentity{
                .certificate_pem =
                    coquic::quic::test::read_text_file("tests/fixtures/quic-server-cert.pem"),
                .private_key_pem =
                    coquic::quic::test::read_text_file("tests/fixtures/quic-server-key.pem"),
            },
        .local_transport_parameters = coquic::quic::test::sample_transport_parameters(),
    };
}

CipherSuite invalid_cipher_suite() {
    constexpr std::uint8_t raw = 0xff;
    CipherSuite cipher_suite{};
    std::memcpy(&cipher_suite, &raw, sizeof(cipher_suite));
    return cipher_suite;
}

void drive_tls_handshake(TlsAdapter &client, TlsAdapter &server) {
    ASSERT_TRUE(client.start().has_value());
    const auto initial_client_flight = client.take_pending(EncryptionLevel::initial);
    ASSERT_FALSE(initial_client_flight.empty());
    ASSERT_TRUE(server.provide(EncryptionLevel::initial, initial_client_flight).has_value());

    for (int i = 0; i < 32 && !(client.handshake_complete() && server.handshake_complete()); ++i) {
        const auto client_initial = client.take_pending(EncryptionLevel::initial);
        if (!client_initial.empty()) {
            ASSERT_TRUE(server.provide(EncryptionLevel::initial, client_initial).has_value());
        }

        const auto server_initial = server.take_pending(EncryptionLevel::initial);
        if (!server_initial.empty()) {
            ASSERT_TRUE(client.provide(EncryptionLevel::initial, server_initial).has_value());
        }

        const auto server_handshake = server.take_pending(EncryptionLevel::handshake);
        if (!server_handshake.empty()) {
            ASSERT_TRUE(client.provide(EncryptionLevel::handshake, server_handshake).has_value());
        }

        const auto client_handshake = client.take_pending(EncryptionLevel::handshake);
        if (!client_handshake.empty()) {
            ASSERT_TRUE(server.provide(EncryptionLevel::handshake, client_handshake).has_value());
        }

        client.poll();
        server.poll();
    }
}

std::optional<std::vector<std::byte>> drive_tls_until_resumption_state(TlsAdapter &client,
                                                                       TlsAdapter &server) {
    drive_tls_handshake(client, server);

    for (int i = 0; i < 16; ++i) {
        const auto server_application = server.take_pending(EncryptionLevel::application);
        if (!server_application.empty()) {
            EXPECT_TRUE(
                client.provide(EncryptionLevel::application, server_application).has_value());
        }

        client.poll();
        server.poll();

        auto state = client.take_resumption_state();
        if (state.has_value()) {
            return state;
        }
    }

    return std::nullopt;
}

std::size_t server_handshake_flight_bytes(const TlsAdapterConfig &server_config) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(server_config);

    EXPECT_TRUE(client.start().has_value());
    const auto initial_client_flight = client.take_pending(EncryptionLevel::initial);
    EXPECT_FALSE(initial_client_flight.empty());
    EXPECT_TRUE(server.provide(EncryptionLevel::initial, initial_client_flight).has_value());

    return server.take_pending(EncryptionLevel::handshake).size();
}

TEST(QuicTlsAdapterContractTest, ClientAndServerExchangeHandshakeBytesAndSecrets) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());

    drive_tls_handshake(client, server);

    EXPECT_TRUE(client.handshake_complete());
    EXPECT_TRUE(server.handshake_complete());
    EXPECT_TRUE(client.peer_transport_parameters().has_value());
    EXPECT_TRUE(server.peer_transport_parameters().has_value());

    const auto client_secrets = client.take_available_secrets();
    const auto server_secrets = server.take_available_secrets();

    EXPECT_TRUE(std::any_of(client_secrets.begin(), client_secrets.end(), [](const auto &secret) {
        return secret.level == EncryptionLevel::handshake;
    }));
    EXPECT_TRUE(std::any_of(server_secrets.begin(), server_secrets.end(), [](const auto &secret) {
        return secret.level == EncryptionLevel::handshake;
    }));
}

TEST(QuicTlsAdapterContractTest, HandshakeWritesTlsKeyLogFilesWhenConfigured) {
    coquic::quic::test::ScopedTempDir dir;
    const auto client_keylog = dir.path() / "client" / "keys.log";
    const auto server_keylog = dir.path() / "server" / "keys.log";

    auto client_config = make_client_config();
    client_config.tls_keylog_path = client_keylog;
    auto server_config = make_server_config();
    server_config.tls_keylog_path = server_keylog;

    TlsAdapter client(std::move(client_config));
    TlsAdapter server(std::move(server_config));

    drive_tls_handshake(client, server);

    ASSERT_TRUE(std::filesystem::exists(client_keylog));
    ASSERT_TRUE(std::filesystem::exists(server_keylog));
    const auto client_log = coquic::quic::test::read_text_file(client_keylog.string());
    const auto server_log = coquic::quic::test::read_text_file(server_keylog.string());
    EXPECT_NE(client_log.find("TRAFFIC_SECRET"), std::string::npos);
    EXPECT_NE(server_log.find("TRAFFIC_SECRET"), std::string::npos);
}

TEST(QuicTlsAdapterContractTest, HandshakeCanBeConstrainedToChaCha20CipherSuite) {
    auto client_config = make_client_config();
    client_config.allowed_tls_cipher_suites = {
        CipherSuite::tls_chacha20_poly1305_sha256,
    };
    auto server_config = make_server_config();
    server_config.allowed_tls_cipher_suites = {
        CipherSuite::tls_chacha20_poly1305_sha256,
    };

    TlsAdapter client(std::move(client_config));
    TlsAdapter server(std::move(server_config));

    drive_tls_handshake(client, server);

    ASSERT_TRUE(client.handshake_complete());
    ASSERT_TRUE(server.handshake_complete());
    ASSERT_TRUE(TlsAdapterTestPeer::cipher_suite_for_ssl(client).has_value());
    EXPECT_EQ(TlsAdapterTestPeer::cipher_suite_for_ssl(client).value(),
              CipherSuite::tls_chacha20_poly1305_sha256);
    ASSERT_TRUE(TlsAdapterTestPeer::cipher_suite_for_ssl(server).has_value());
    EXPECT_EQ(TlsAdapterTestPeer::cipher_suite_for_ssl(server).value(),
              CipherSuite::tls_chacha20_poly1305_sha256);
}

TEST(QuicTlsAdapterContractTest, HandshakeCanBeConstrainedToAesCipherSuites) {
    auto client_config = make_client_config();
    client_config.allowed_tls_cipher_suites = {
        CipherSuite::tls_aes_128_gcm_sha256,
        CipherSuite::tls_aes_256_gcm_sha384,
    };
    auto server_config = make_server_config();
    server_config.allowed_tls_cipher_suites = {
        CipherSuite::tls_aes_128_gcm_sha256,
        CipherSuite::tls_aes_256_gcm_sha384,
    };

    TlsAdapter client(std::move(client_config));
    TlsAdapter server(std::move(server_config));

    drive_tls_handshake(client, server);

    ASSERT_TRUE(client.handshake_complete());
    ASSERT_TRUE(server.handshake_complete());
    ASSERT_TRUE(TlsAdapterTestPeer::cipher_suite_for_ssl(client).has_value());
    ASSERT_TRUE(TlsAdapterTestPeer::cipher_suite_for_ssl(server).has_value());
    const auto client_cipher = TlsAdapterTestPeer::cipher_suite_for_ssl(client).value();
    const auto server_cipher = TlsAdapterTestPeer::cipher_suite_for_ssl(server).value();
    EXPECT_TRUE(client_cipher == CipherSuite::tls_aes_128_gcm_sha256 ||
                client_cipher == CipherSuite::tls_aes_256_gcm_sha384);
    EXPECT_TRUE(server_cipher == CipherSuite::tls_aes_128_gcm_sha256 ||
                server_cipher == CipherSuite::tls_aes_256_gcm_sha384);
}

TEST(QuicTlsAdapterContractTest, AsTlsBytesReturnsStablePointers) {
    const auto empty_bytes = std::span<const std::byte>{};
    EXPECT_NE(TlsAdapterTestPeer::as_tls_bytes(empty_bytes), nullptr);

    const auto non_empty_bytes = coquic::quic::test::sample_transport_parameters();
    EXPECT_EQ(TlsAdapterTestPeer::as_tls_bytes(non_empty_bytes),
              reinterpret_cast<const uint8_t *>(non_empty_bytes.data()));
}

TEST(QuicTlsAdapterContractTest, MapsOsslEncryptionLevelsToInternalLevels) {
    EXPECT_EQ(TlsAdapterTestPeer::to_encryption_level(ssl_encryption_initial),
              EncryptionLevel::initial);
    EXPECT_EQ(TlsAdapterTestPeer::to_encryption_level(ssl_encryption_handshake),
              EncryptionLevel::handshake);
    EXPECT_EQ(TlsAdapterTestPeer::to_encryption_level(ssl_encryption_application),
              EncryptionLevel::application);
    EXPECT_EQ(TlsAdapterTestPeer::to_encryption_level_value(0xff), std::nullopt);
}

TEST(QuicTlsAdapterContractTest, MapsEarlyDataToZeroRttEncryptionLevel) {
    EXPECT_EQ(TlsAdapterTestPeer::to_encryption_level(ssl_encryption_early_data),
              std::optional<EncryptionLevel>(EncryptionLevel::zero_rtt));
}

TEST(QuicTlsAdapterContractTest, ClientExportsOpaqueResumptionStateAfterReceivingTicket) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());

    const auto exported = drive_tls_until_resumption_state(client, server);
    ASSERT_TRUE(exported.has_value());
    if (!exported.has_value()) {
        return;
    }
    const auto &resumption_state = *exported;
    EXPECT_FALSE(resumption_state.empty());
}

TEST(QuicTlsAdapterContractTest, ServerHandshakeFlightGrowsWhenCertificatePemContainsChain) {
    auto single_certificate_server_config = make_server_config();
    auto chained_certificate_server_config = make_server_config();

    ASSERT_TRUE(chained_certificate_server_config.identity.has_value());
    if (!chained_certificate_server_config.identity.has_value()) {
        return;
    }
    auto &identity = *chained_certificate_server_config.identity;
    const std::string leaf_certificate = identity.certificate_pem;
    identity.certificate_pem += leaf_certificate;
    identity.certificate_pem += leaf_certificate;

    const auto single_certificate_flight_bytes =
        server_handshake_flight_bytes(single_certificate_server_config);
    const auto chained_certificate_flight_bytes =
        server_handshake_flight_bytes(chained_certificate_server_config);

    EXPECT_GT(single_certificate_flight_bytes, 0u);
    EXPECT_GT(chained_certificate_flight_bytes, single_certificate_flight_bytes);
}

TEST(QuicTlsAdapterContractTest, ServerIdentityRejectsTrailingGarbageAfterCertificateChain) {
    auto server_config = make_server_config();
    ASSERT_TRUE(server_config.identity.has_value());
    if (!server_config.identity.has_value()) {
        return;
    }
    const auto valid_identity = *server_config.identity;
    server_config.identity = TlsIdentity{
        .certificate_pem = valid_identity.certificate_pem + "-----BEGIN CERTIFICATE-----\nAAAA\n",
        .private_key_pem = valid_identity.private_key_pem,
    };

    TlsAdapter adapter(std::move(server_config));

    EXPECT_FALSE(adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
              CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTlsAdapterContractTest, ClientRestoresResumptionStateAndMarksEarlyDataAttempted) {
    TlsAdapter first_client(make_client_config());
    TlsAdapter first_server(make_server_config());

    const auto exported = drive_tls_until_resumption_state(first_client, first_server);
    ASSERT_TRUE(exported.has_value());
    if (!exported.has_value()) {
        return;
    }
    const auto &resumption_state = *exported;

    auto resumed_client_config = make_client_config();
    resumed_client_config.resumption_state = resumption_state;
    resumed_client_config.attempt_zero_rtt = true;

    TlsAdapter resumed_client(std::move(resumed_client_config));
    ASSERT_TRUE(resumed_client.start().has_value());
    EXPECT_TRUE(resumed_client.early_data_attempted());
}

TEST(QuicTlsAdapterContractTest, ClientIgnoresResumptionStateWhenSslSetSessionFails) {
    TlsAdapter first_client(make_client_config());
    TlsAdapter first_server(make_server_config());

    const auto exported = drive_tls_until_resumption_state(first_client, first_server);
    ASSERT_TRUE(exported.has_value());
    if (!exported.has_value()) {
        return;
    }
    const auto &resumption_state = *exported;

    auto resumed_client_config = make_client_config();
    resumed_client_config.resumption_state = resumption_state;
    resumed_client_config.attempt_zero_rtt = true;

    const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::initialize_set_session);
    TlsAdapter resumed_client(std::move(resumed_client_config));
    ASSERT_TRUE(resumed_client.start().has_value());
    EXPECT_FALSE(resumed_client.resumed_resumption_state().has_value());
    EXPECT_FALSE(resumed_client.early_data_attempted());
}

TEST(QuicTlsAdapterContractTest,
     ClientAttemptingZeroRttEmitsZeroRttWriteSecretWhenSessionAllowsEarlyData) {
    auto first_client_config = make_client_config();
    auto first_server_config = make_server_config();
    first_server_config.accept_zero_rtt = true;
    first_server_config.zero_rtt_context = {std::byte{0x10}};

    TlsAdapter first_client(std::move(first_client_config));
    TlsAdapter first_server(std::move(first_server_config));

    const auto exported = drive_tls_until_resumption_state(first_client, first_server);
    ASSERT_TRUE(exported.has_value());
    if (!exported.has_value()) {
        return;
    }
    const auto &resumption_state = *exported;

    auto resumed_client_config = make_client_config();
    resumed_client_config.resumption_state = resumption_state;
    resumed_client_config.attempt_zero_rtt = true;
    resumed_client_config.zero_rtt_context = {std::byte{0x10}};

    TlsAdapter resumed_client(std::move(resumed_client_config));
    ASSERT_TRUE(resumed_client.start().has_value());

    const auto secrets = resumed_client.take_available_secrets();
    EXPECT_TRUE(std::any_of(secrets.begin(), secrets.end(), [](const auto &secret) {
        return secret.level == EncryptionLevel::zero_rtt && secret.sender == EndpointRole::client;
    }));
}

TEST(QuicTlsAdapterContractTest,
     ResumedServerAcceptingZeroRttInstallsZeroRttReadSecretAndReusesSession) {
    auto first_client_config = make_client_config();
    auto first_server_config = make_server_config();
    first_server_config.accept_zero_rtt = true;
    first_server_config.zero_rtt_context = {std::byte{0x10}};

    TlsAdapter first_client(std::move(first_client_config));
    TlsAdapter first_server(std::move(first_server_config));

    const auto exported = drive_tls_until_resumption_state(first_client, first_server);
    ASSERT_TRUE(exported.has_value());
    if (!exported.has_value()) {
        return;
    }
    const auto &resumption_state = *exported;

    auto resumed_client_config = make_client_config();
    resumed_client_config.resumption_state = resumption_state;
    resumed_client_config.attempt_zero_rtt = true;
    resumed_client_config.zero_rtt_context = {std::byte{0x10}};

    auto resumed_server_config = make_server_config();
    resumed_server_config.accept_zero_rtt = true;
    resumed_server_config.zero_rtt_context = {std::byte{0x10}};

    TlsAdapter resumed_client(std::move(resumed_client_config));
    TlsAdapter resumed_server(std::move(resumed_server_config));

    ASSERT_TRUE(resumed_client.start().has_value());
    const auto resumed_client_initial = resumed_client.take_pending(EncryptionLevel::initial);
    ASSERT_FALSE(resumed_client_initial.empty());
    ASSERT_TRUE(
        resumed_server.provide(EncryptionLevel::initial, resumed_client_initial).has_value());

    const auto early_server_secrets = resumed_server.take_available_secrets();
    EXPECT_TRUE(std::any_of(early_server_secrets.begin(), early_server_secrets.end(),
                            [](const auto &secret) {
                                return secret.level == EncryptionLevel::zero_rtt &&
                                       secret.sender == EndpointRole::client;
                            }));

    for (int i = 0;
         i < 32 && !(resumed_client.handshake_complete() && resumed_server.handshake_complete());
         ++i) {
        const auto client_initial = resumed_client.take_pending(EncryptionLevel::initial);
        if (!client_initial.empty()) {
            ASSERT_TRUE(
                resumed_server.provide(EncryptionLevel::initial, client_initial).has_value());
        }

        const auto server_initial = resumed_server.take_pending(EncryptionLevel::initial);
        if (!server_initial.empty()) {
            ASSERT_TRUE(
                resumed_client.provide(EncryptionLevel::initial, server_initial).has_value());
        }

        const auto server_handshake = resumed_server.take_pending(EncryptionLevel::handshake);
        if (!server_handshake.empty()) {
            ASSERT_TRUE(
                resumed_client.provide(EncryptionLevel::handshake, server_handshake).has_value());
        }

        const auto client_handshake = resumed_client.take_pending(EncryptionLevel::handshake);
        if (!client_handshake.empty()) {
            ASSERT_TRUE(
                resumed_server.provide(EncryptionLevel::handshake, client_handshake).has_value());
        }

        resumed_client.poll();
        resumed_server.poll();
    }

    EXPECT_TRUE(resumed_client.handshake_complete());
    EXPECT_TRUE(resumed_server.handshake_complete());
    EXPECT_TRUE(resumed_server.resumed_resumption_state().has_value());
    EXPECT_EQ(resumed_server.early_data_accepted(), std::optional<bool>(true));
}

TEST(QuicTlsAdapterContractTest, MapsInternalEncryptionLevelsToOsslLevels) {
    EXPECT_EQ(TlsAdapterTestPeer::to_ossl_encryption_level(EncryptionLevel::initial),
              ssl_encryption_initial);
    EXPECT_EQ(TlsAdapterTestPeer::to_ossl_encryption_level(EncryptionLevel::zero_rtt),
              ssl_encryption_early_data);
    EXPECT_EQ(TlsAdapterTestPeer::to_ossl_encryption_level(EncryptionLevel::handshake),
              ssl_encryption_handshake);
    EXPECT_EQ(TlsAdapterTestPeer::to_ossl_encryption_level(EncryptionLevel::application),
              ssl_encryption_application);
    EXPECT_EQ(TlsAdapterTestPeer::to_ossl_encryption_level_value(0xff), ssl_encryption_initial);
}

TEST(QuicTlsAdapterContractTest, MapsCipherSuitesFromProtocolIdsAndStartsIncomplete) {
    EXPECT_FALSE(
        TlsAdapterTestPeer::cipher_suite_for_protocol_ids(std::nullopt, std::nullopt).has_value());
    EXPECT_EQ(TlsAdapterTestPeer::cipher_suite_for_protocol_ids(
                  std::nullopt, std::optional<std::uint16_t>(0x1301))
                  .value(),
              CipherSuite::tls_aes_128_gcm_sha256);
    EXPECT_EQ(TlsAdapterTestPeer::cipher_suite_for_protocol_ids(
                  std::optional<std::uint16_t>(0x1302), std::nullopt)
                  .value(),
              CipherSuite::tls_aes_256_gcm_sha384);
    EXPECT_EQ(TlsAdapterTestPeer::cipher_suite_for_protocol_ids(
                  std::nullopt, std::optional<std::uint16_t>(0x1303))
                  .value(),
              CipherSuite::tls_chacha20_poly1305_sha256);
    EXPECT_FALSE(TlsAdapterTestPeer::cipher_suite_for_protocol_ids(
                     std::optional<std::uint16_t>(0x9999), std::nullopt)
                     .has_value());

    TlsAdapter client(make_client_config());
    EXPECT_FALSE(client.handshake_complete());
}

TEST(QuicTlsAdapterContractTest, InitializationFaultsProduceStickyErrors) {
    const auto expect_init_failure = [](TlsAdapterFaultPoint fault_point, TlsAdapterConfig config) {
        const ScopedTlsAdapterFaultInjector injector(fault_point);
        TlsAdapter adapter(std::move(config));
        EXPECT_FALSE(adapter.start().has_value());
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
                  CodecErrorCode::invalid_packet_protection_state);
    };

    expect_init_failure(TlsAdapterFaultPoint::initialize_ctx_new, make_client_config());
    expect_init_failure(TlsAdapterFaultPoint::initialize_ctx_config, make_client_config());
    auto verify_paths_config = make_client_config();
    verify_paths_config.verify_peer = true;
    expect_init_failure(TlsAdapterFaultPoint::initialize_verify_paths,
                        std::move(verify_paths_config));
    expect_init_failure(TlsAdapterFaultPoint::initialize_ssl_new, make_client_config());
    expect_init_failure(TlsAdapterFaultPoint::initialize_ssl_set_quic_method, make_client_config());
    expect_init_failure(TlsAdapterFaultPoint::initialize_server_name, make_client_config());
    expect_init_failure(TlsAdapterFaultPoint::initialize_transport_params, make_client_config());
    expect_init_failure(TlsAdapterFaultPoint::initialize_server_resumption_context,
                        make_server_config());
}

TEST(QuicTlsAdapterContractTest, InvalidApplicationProtocolConfigProducesStickyError) {
    auto empty_application_protocol = make_client_config();
    empty_application_protocol.application_protocol.clear();
    TlsAdapter empty_protocol_adapter(std::move(empty_application_protocol));
    EXPECT_FALSE(empty_protocol_adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(empty_protocol_adapter),
              CodecErrorCode::invalid_packet_protection_state);

    auto oversized_application_protocol = make_client_config();
    oversized_application_protocol.application_protocol = std::string(256, 'a');
    TlsAdapter oversized_protocol_adapter(std::move(oversized_application_protocol));
    EXPECT_FALSE(oversized_protocol_adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(oversized_protocol_adapter),
              CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTlsAdapterContractTest, InvalidCipherSuiteConfigProducesStickyError) {
    auto invalid_cipher_config = make_client_config();
    invalid_cipher_config.allowed_tls_cipher_suites = {
        invalid_cipher_suite(),
    };

    TlsAdapter invalid_cipher_adapter(std::move(invalid_cipher_config));
    EXPECT_FALSE(invalid_cipher_adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(invalid_cipher_adapter),
              CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTlsAdapterContractTest, ApplicationProtocolHelpersEncodeAndValidateLists) {
    EXPECT_EQ(TlsAdapterTestPeer::encode_application_protocol_list("coquic"),
              std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i', 'c'}));
    EXPECT_TRUE(TlsAdapterTestPeer::encode_application_protocol_list("").empty());
    EXPECT_TRUE(
        TlsAdapterTestPeer::encode_application_protocol_list(std::string(256, 'a')).empty());

    EXPECT_TRUE(TlsAdapterTestPeer::client_offered_application_protocol(
        std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i', 'c'}), "coquic"));
    EXPECT_FALSE(TlsAdapterTestPeer::client_offered_application_protocol(
        std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i'}), "coquic"));
    EXPECT_FALSE(TlsAdapterTestPeer::client_offered_application_protocol(std::vector<uint8_t>({0}),
                                                                         "coquic"));
}

TEST(QuicTlsAdapterContractTest, ClientAlpnHelperCoversEmptyAndFaultedSetup) {
    TlsAdapter adapter(make_client_config());
    EXPECT_TRUE(TlsAdapterTestPeer::call_client_alpn_failed(adapter, ""));

    const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::initialize_client_alpn);
    EXPECT_TRUE(TlsAdapterTestPeer::call_client_alpn_failed(adapter, "coquic"));
}

TEST(QuicTlsAdapterContractTest, ClientAlpnHelperCoversMissingSslAndSetProtosFailure) {
    {
        TlsAdapter adapter(make_client_config());
        TlsAdapterTestPeer::reset_ssl(adapter);
        EXPECT_TRUE(TlsAdapterTestPeer::call_client_alpn_failed(adapter, "coquic"));
    }

    {
        TlsAdapter adapter(make_client_config());
        const ScopedTlsAdapterFaultInjector injector(
            TlsAdapterFaultPoint::initialize_client_alpn_set_protos);
        EXPECT_TRUE(TlsAdapterTestPeer::call_client_alpn_failed(adapter, "coquic"));
    }
}

TEST(QuicTlsAdapterContractTest, ClientAlpnInitializationFaultProducesStickyError) {
    const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::initialize_client_alpn);
    TlsAdapter adapter(make_client_config());
    EXPECT_FALSE(adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
              CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTlsAdapterContractTest, InvalidResumptionStateBytesAreIgnoredDuringClientStart) {
    auto client_config = make_client_config();
    client_config.resumption_state = std::vector<std::byte>{std::byte{0x00}};
    client_config.attempt_zero_rtt = true;

    TlsAdapter client(std::move(client_config));
    EXPECT_TRUE(client.start().has_value());
    EXPECT_FALSE(client.resumed_resumption_state().has_value());
    EXPECT_FALSE(client.early_data_attempted());
}

TEST(QuicTlsAdapterContractTest, NullSessionSerializationReturnsNullopt) {
    EXPECT_EQ(TlsAdapterTestPeer::serialize_session_bytes(nullptr), std::nullopt);
}

TEST(QuicTlsAdapterContractTest, SessionDeserializationRejectsOversizedAndTrailingInputs) {
    const std::byte dummy{0x00};
    const auto huge_size = static_cast<std::size_t>(std::numeric_limits<long>::max()) + 1u;
    const std::span huge_bytes(&dummy, huge_size);
    EXPECT_FALSE(TlsAdapterTestPeer::deserialize_session_bytes(huge_bytes));

    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());
    const auto exported = drive_tls_until_resumption_state(client, server);
    ASSERT_TRUE(exported.has_value());
    if (!exported.has_value()) {
        return;
    }

    auto trailing_bytes = *exported;
    trailing_bytes.push_back(std::byte{0x00});
    EXPECT_FALSE(TlsAdapterTestPeer::deserialize_session_bytes(trailing_bytes));
}

TEST(QuicTlsAdapterContractTest, SessionSerializationFaultReturnsNullopt) {
    const std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> session(SSL_SESSION_new(),
                                                                            &SSL_SESSION_free);
    ASSERT_NE(session, nullptr);

    const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::serialize_session_bytes);
    EXPECT_EQ(TlsAdapterTestPeer::serialize_session_bytes(session.get()), std::nullopt);
}

TEST(QuicTlsAdapterContractTest, SelectApplicationProtocolRejectsNullPointersAndInvalidConfig) {
    TlsAdapter server(make_server_config());
    const auto offered = std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i', 'c'});
    const uint8_t *selected = nullptr;
    uint8_t selected_length = 0;

    EXPECT_EQ(TlsAdapterTestPeer::call_static_select_application_protocol(
                  nullptr, &selected, &selected_length, offered),
              SSL_TLSEXT_ERR_ALERT_FATAL);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_select_application_protocol(
                  &server, nullptr, &selected_length, offered),
              SSL_TLSEXT_ERR_ALERT_FATAL);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_select_application_protocol(&server, &selected,
                                                                          nullptr, offered),
              SSL_TLSEXT_ERR_ALERT_FATAL);

    TlsAdapterTestPeer::set_application_protocol(server, "");
    EXPECT_EQ(TlsAdapterTestPeer::call_static_select_application_protocol(
                  &server, &selected, &selected_length, offered),
              SSL_TLSEXT_ERR_ALERT_FATAL);
}

TEST(QuicTlsAdapterContractTest, SelectApplicationProtocolRejectsMalformedOfferedList) {
    TlsAdapter server(make_server_config());
    const auto malformed = std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i'});
    const uint8_t *selected = nullptr;
    uint8_t selected_length = 0;

    EXPECT_EQ(TlsAdapterTestPeer::call_static_select_application_protocol(
                  &server, &selected, &selected_length, malformed),
              SSL_TLSEXT_ERR_ALERT_FATAL);
}

TEST(QuicTlsAdapterContractTest, QlogTelemetryCapturesServerOfferedAndSelectedApplicationProtocol) {
    TlsAdapter server(make_server_config());
    const auto offered = std::vector<uint8_t>({6, 'c', 'o', 'q', 'u', 'i', 'c'});
    const uint8_t *selected = nullptr;
    uint8_t selected_length = 0;

    ASSERT_EQ(TlsAdapterTestPeer::call_static_select_application_protocol(
                  &server, &selected, &selected_length, offered),
              SSL_TLSEXT_ERR_OK);

    const auto expected = std::vector<std::byte>{
        static_cast<std::byte>('c'), static_cast<std::byte>('o'), static_cast<std::byte>('q'),
        static_cast<std::byte>('u'), static_cast<std::byte>('i'), static_cast<std::byte>('c'),
    };

    ASSERT_EQ(server.peer_offered_application_protocols().size(), 1u);
    EXPECT_EQ(server.peer_offered_application_protocols().front(), expected);
    const auto selected_protocol = server.selected_application_protocol();
    ASSERT_TRUE(selected_protocol.has_value());
    EXPECT_EQ(selected_protocol.value_or(std::vector<std::byte>{}), expected);
}

TEST(QuicTlsAdapterContractTest, QlogTelemetryPublishesSelectedApplicationProtocolAfterHandshake) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());

    drive_tls_handshake(client, server);

    const auto expected = std::vector<std::byte>{
        static_cast<std::byte>('c'), static_cast<std::byte>('o'), static_cast<std::byte>('q'),
        static_cast<std::byte>('u'), static_cast<std::byte>('i'), static_cast<std::byte>('c'),
    };

    const auto client_selected = client.selected_application_protocol();
    const auto server_selected = server.selected_application_protocol();
    ASSERT_TRUE(client_selected.has_value());
    ASSERT_TRUE(server_selected.has_value());
    EXPECT_EQ(client_selected.value_or(std::vector<std::byte>{}), expected);
    EXPECT_EQ(server_selected.value_or(std::vector<std::byte>{}), expected);
}

TEST(QuicTlsAdapterContractTest, FaultInjectorHonorsConfiguredOccurrence) {
    const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::initialize_ctx_new, 2);

    TlsAdapter first(make_client_config());
    EXPECT_TRUE(first.start().has_value());

    TlsAdapter second(make_client_config());
    EXPECT_FALSE(second.start().has_value());
}

TEST(QuicTlsAdapterContractTest, ServerIdentityFailuresProduceStickyErrors) {
    auto missing_identity = make_server_config();
    missing_identity.identity.reset();
    TlsAdapter missing_identity_adapter(std::move(missing_identity));
    EXPECT_FALSE(missing_identity_adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(missing_identity_adapter),
              CodecErrorCode::invalid_packet_protection_state);

    {
        const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::load_identity_cert_bio);
        TlsAdapter adapter(make_server_config());
        EXPECT_FALSE(adapter.start().has_value());
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
                  CodecErrorCode::invalid_packet_protection_state);
    }

    auto invalid_certificate = make_server_config();
    const auto valid_identity = invalid_certificate.identity.value_or(TlsIdentity{});
    invalid_certificate.identity = TlsIdentity{
        .certificate_pem = "invalid certificate",
        .private_key_pem = valid_identity.private_key_pem,
    };
    TlsAdapter invalid_certificate_adapter(std::move(invalid_certificate));
    EXPECT_FALSE(invalid_certificate_adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(invalid_certificate_adapter),
              CodecErrorCode::invalid_packet_protection_state);

    auto malformed_certificate_chain = make_server_config();
    const auto valid_chain_identity = malformed_certificate_chain.identity.value_or(TlsIdentity{});
    malformed_certificate_chain.identity = TlsIdentity{
        .certificate_pem = valid_chain_identity.certificate_pem +
                           "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n",
        .private_key_pem = valid_chain_identity.private_key_pem,
    };
    TlsAdapter malformed_certificate_chain_adapter(std::move(malformed_certificate_chain));
    EXPECT_FALSE(malformed_certificate_chain_adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(malformed_certificate_chain_adapter),
              CodecErrorCode::invalid_packet_protection_state);

    {
        const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::load_identity_key_bio);
        TlsAdapter adapter(make_server_config());
        EXPECT_FALSE(adapter.start().has_value());
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
                  CodecErrorCode::invalid_packet_protection_state);
    }

    auto invalid_private_key = make_server_config();
    const auto valid_private_key_identity = invalid_private_key.identity.value_or(TlsIdentity{});
    invalid_private_key.identity = TlsIdentity{
        .certificate_pem = valid_private_key_identity.certificate_pem,
        .private_key_pem = "invalid private key",
    };
    TlsAdapter invalid_private_key_adapter(std::move(invalid_private_key));
    EXPECT_FALSE(invalid_private_key_adapter.start().has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(invalid_private_key_adapter),
              CodecErrorCode::invalid_packet_protection_state);

    {
        const ScopedTlsAdapterFaultInjector injector(
            TlsAdapterFaultPoint::load_identity_use_certificate);
        TlsAdapter adapter(make_server_config());
        EXPECT_FALSE(adapter.start().has_value());
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
                  CodecErrorCode::invalid_packet_protection_state);
    }
}

TEST(QuicTlsAdapterContractTest, MismatchedApplicationProtocolsFailHandshake) {
    auto client_config = make_client_config();
    client_config.application_protocol = "coquic-client";
    TlsAdapter client(std::move(client_config));

    auto server_config = make_server_config();
    server_config.application_protocol = "coquic-server";
    TlsAdapter server(std::move(server_config));

    ASSERT_TRUE(client.start().has_value());
    const auto initial_client_flight = client.take_pending(EncryptionLevel::initial);
    ASSERT_FALSE(initial_client_flight.empty());

    EXPECT_FALSE(server.provide(EncryptionLevel::initial, initial_client_flight).has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(server),
              CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTlsAdapterContractTest, ProvideAndPollRejectStickyOrMissingSslState) {
    TlsAdapter sticky_adapter(make_client_config());
    EXPECT_FALSE(TlsAdapterTestPeer::has_sticky_error(sticky_adapter));
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(sticky_adapter), std::nullopt);
    TlsAdapterTestPeer::set_sticky_error(sticky_adapter,
                                         CodecErrorCode::invalid_packet_protection_state);
    EXPECT_TRUE(TlsAdapterTestPeer::has_sticky_error(sticky_adapter));
    EXPECT_FALSE(sticky_adapter.provide(EncryptionLevel::initial, {}).has_value());
    sticky_adapter.poll();
    EXPECT_FALSE(TlsAdapterTestPeer::drive_handshake(sticky_adapter).has_value());
    TlsAdapterTestPeer::clear_sticky_error(sticky_adapter);
    EXPECT_FALSE(TlsAdapterTestPeer::has_sticky_error(sticky_adapter));

    TlsAdapter missing_ssl_adapter(make_client_config());
    TlsAdapterTestPeer::reset_ssl(missing_ssl_adapter);
    EXPECT_FALSE(missing_ssl_adapter.handshake_complete());
    EXPECT_FALSE(missing_ssl_adapter.provide(EncryptionLevel::initial, {}).has_value());
    EXPECT_FALSE(TlsAdapterTestPeer::drive_handshake(missing_ssl_adapter).has_value());
}

TEST(QuicTlsAdapterContractTest, HandshakeHelpersClassifyRetryAndProgressStates) {
    EXPECT_TRUE(TlsAdapterTestPeer::should_retry_handshake(false, SSL_ERROR_WANT_READ));
    EXPECT_TRUE(TlsAdapterTestPeer::should_retry_handshake(false, SSL_ERROR_WANT_WRITE));
    EXPECT_FALSE(TlsAdapterTestPeer::should_retry_handshake(true, SSL_ERROR_WANT_READ));
    EXPECT_FALSE(TlsAdapterTestPeer::should_retry_handshake(false, SSL_ERROR_SSL));

    EXPECT_FALSE(TlsAdapterTestPeer::handshake_progressed(false, false, false));
    EXPECT_TRUE(TlsAdapterTestPeer::handshake_progressed(true, false, false));
    EXPECT_TRUE(TlsAdapterTestPeer::handshake_progressed(false, true, false));
    EXPECT_TRUE(TlsAdapterTestPeer::handshake_progressed(false, false, true));
}

TEST(QuicTlsAdapterContractTest,
     ProvideCoversInjectedQuicDataFailureAndApplicationPostHandshakePaths) {
    {
        const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::provide_quic_data);
        TlsAdapter adapter(make_client_config());
        EXPECT_FALSE(adapter.provide(EncryptionLevel::initial, {}).has_value());
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
                  CodecErrorCode::invalid_packet_protection_state);
    }

    {
        TlsAdapter client(make_client_config());
        TlsAdapter server(make_server_config());
        drive_tls_handshake(client, server);
        TlsAdapterTestPeer::clear_peer_transport_parameters(client);
        EXPECT_TRUE(client.provide(EncryptionLevel::application, {}).has_value());
        EXPECT_TRUE(client.peer_transport_parameters().has_value());
        EXPECT_TRUE(TlsAdapterTestPeer::cipher_suite_for_ssl(client).has_value());
    }

    {
        TlsAdapter client(make_client_config());
        TlsAdapter server(make_server_config());
        drive_tls_handshake(client, server);
        const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::provide_post_handshake);
        EXPECT_FALSE(client.provide(EncryptionLevel::application, {}).has_value());
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(client),
                  CodecErrorCode::invalid_packet_protection_state);
    }
}

TEST(QuicTlsAdapterContractTest,
     StaticCallbacksReturnZeroWhenAppDataMissingAndSendAlertWhenPresent) {
    TlsAdapter adapter(make_client_config());
    const std::array<uint8_t, 32> secret{};
    const std::array<uint8_t, 3> data{1, 2, 3};
    const std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> session(SSL_SESSION_new(),
                                                                            &SSL_SESSION_free);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(TlsAdapterTestPeer::call_static_set_read_secret_with_null_app_data(
                  adapter, ssl_encryption_initial, secret.data(), secret.size()),
              0);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_set_write_secret_with_null_app_data(
                  adapter, ssl_encryption_initial, secret.data(), secret.size()),
              0);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_add_handshake_data_with_null_app_data(
                  adapter, ssl_encryption_initial, data.data(), data.size()),
              0);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_flush_flight_with_null_app_data(adapter), 0);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_send_alert_with_null_app_data(
                  adapter, ssl_encryption_initial, 1),
              0);
    EXPECT_EQ(
        TlsAdapterTestPeer::call_static_on_new_session_with_null_app_data(adapter, session.get()),
        0);

    EXPECT_EQ(TlsAdapterTestPeer::call_static_send_alert(adapter, ssl_encryption_initial, 1), 0);
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
              CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTlsAdapterContractTest, NullSslAndDirectSendAlertTestHooksRemainSafe) {
    TlsAdapter adapter(make_client_config());
    EXPECT_EQ(TlsAdapterTestPeer::call_on_send_alert(adapter, ssl_encryption_initial, 1), 0);
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
              CodecErrorCode::invalid_packet_protection_state);

    TlsAdapter missing_ssl_adapter(make_client_config());
    TlsAdapterTestPeer::reset_ssl(missing_ssl_adapter);
    const std::array<uint8_t, 32> secret{};
    EXPECT_EQ(
        TlsAdapterTestPeer::call_static_send_alert(missing_ssl_adapter, ssl_encryption_initial, 1),
        0);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_set_read_secret_with_null_app_data(
                  missing_ssl_adapter, ssl_encryption_initial, secret.data(), secret.size()),
              0);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_set_write_secret_with_null_app_data(
                  missing_ssl_adapter, ssl_encryption_initial, secret.data(), secret.size()),
              0);
}

TEST(QuicTlsAdapterContractTest, SecretCallbackHooksCoverMissingSslAndWriteOnlyNullAppDataPaths) {
    const std::array<uint8_t, 32> secret{};

    {
        TlsAdapter missing_ssl_adapter(make_client_config());
        TlsAdapterTestPeer::reset_ssl(missing_ssl_adapter);
        EXPECT_EQ(TlsAdapterTestPeer::call_on_set_encryption_secrets(
                      missing_ssl_adapter, ssl_encryption_application, nullptr, secret.data(),
                      secret.size()),
                  0);
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(missing_ssl_adapter),
                  CodecErrorCode::unsupported_cipher_suite);
    }

    {
        TlsAdapter adapter(make_client_config());
        EXPECT_EQ(TlsAdapterTestPeer::call_static_set_write_secret_with_null_app_data(
                      adapter, ssl_encryption_application, secret.data(), secret.size()),
                  0);
        EXPECT_EQ(TlsAdapterTestPeer::call_static_set_write_secret_with_null_app_data(
                      adapter, ssl_encryption_application, nullptr, secret.size()),
                  0);
        EXPECT_EQ(TlsAdapterTestPeer::call_static_set_read_secret_with_null_app_data(
                      adapter, ssl_encryption_application, nullptr, secret.size()),
                  0);
    }
}

TEST(QuicTlsAdapterContractTest, SecretCallbackHooksRemainUsableBeforeHandshakeCompletes) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());

    ASSERT_TRUE(client.start().has_value());
    const auto initial_client_flight = client.take_pending(EncryptionLevel::initial);
    ASSERT_FALSE(initial_client_flight.empty());
    ASSERT_TRUE(server.provide(EncryptionLevel::initial, initial_client_flight).has_value());
    static_cast<void>(server.take_available_secrets());

    const std::array<uint8_t, 32> read_secret{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
                                              4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};
    const std::array<uint8_t, 32> write_secret{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                                               3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};

    EXPECT_EQ(TlsAdapterTestPeer::call_static_set_read_secret_with_null_app_data(
                  server, ssl_encryption_handshake, read_secret.data(), read_secret.size()),
              0);
    EXPECT_EQ(TlsAdapterTestPeer::call_on_set_encryption_secrets(server, ssl_encryption_handshake,
                                                                 nullptr, write_secret.data(),
                                                                 write_secret.size()),
              1);
    EXPECT_EQ(TlsAdapterTestPeer::call_static_set_write_secret_with_null_app_data(
                  server, ssl_encryption_handshake, write_secret.data(), write_secret.size()),
              0);
    const auto outbound_secrets = server.take_available_secrets();
    ASSERT_EQ(outbound_secrets.size(), 1u);
    EXPECT_EQ(outbound_secrets[0].sender, EndpointRole::server);
    EXPECT_EQ(outbound_secrets[0].level, EncryptionLevel::handshake);

    EXPECT_TRUE(TlsAdapterTestPeer::pending_or_current_cipher_protocol_id(server).has_value());
}

TEST(QuicTlsAdapterContractTest, CallbacksCaptureSecretsAndHandshakeData) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());
    drive_tls_handshake(client, server);
    static_cast<void>(client.take_available_secrets());

    const std::array<uint8_t, 32> read_secret{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    const std::array<uint8_t, 32> write_secret{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                                               2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
    const std::array<uint8_t, 4> data{9, 8, 7, 6};

    EXPECT_EQ(TlsAdapterTestPeer::call_on_set_encryption_secrets(
                  client, ssl_encryption_early_data, read_secret.data(), write_secret.data(),
                  read_secret.size()),
              1);
    const auto early_data_secrets = client.take_available_secrets();
    ASSERT_EQ(early_data_secrets.size(), 2u);
    EXPECT_TRUE(
        std::any_of(early_data_secrets.begin(), early_data_secrets.end(), [](const auto &secret) {
            return secret.level == EncryptionLevel::zero_rtt &&
                   secret.sender == EndpointRole::server;
        }));
    EXPECT_TRUE(
        std::any_of(early_data_secrets.begin(), early_data_secrets.end(), [](const auto &secret) {
            return secret.level == EncryptionLevel::zero_rtt &&
                   secret.sender == EndpointRole::client;
        }));

    EXPECT_EQ(TlsAdapterTestPeer::call_on_set_encryption_secrets(client, ssl_encryption_application,
                                                                 read_secret.data(), nullptr,
                                                                 read_secret.size()),
              1);
    const auto inbound_secrets = client.take_available_secrets();
    ASSERT_EQ(inbound_secrets.size(), 1u);
    EXPECT_EQ(inbound_secrets[0].sender, EndpointRole::server);
    EXPECT_EQ(inbound_secrets[0].level, EncryptionLevel::application);

    EXPECT_EQ(TlsAdapterTestPeer::call_on_set_encryption_secrets(client, ssl_encryption_application,
                                                                 nullptr, write_secret.data(),
                                                                 write_secret.size()),
              1);
    const auto outbound_secrets = client.take_available_secrets();
    ASSERT_EQ(outbound_secrets.size(), 1u);
    EXPECT_EQ(outbound_secrets[0].sender, EndpointRole::client);
    EXPECT_EQ(outbound_secrets[0].level, EncryptionLevel::application);

    EXPECT_EQ(TlsAdapterTestPeer::call_on_add_handshake_data(client, ssl_encryption_handshake,
                                                             data.data(), data.size()),
              1);
    EXPECT_EQ(client.take_pending(EncryptionLevel::handshake).size(), data.size());
    EXPECT_EQ(TlsAdapterTestPeer::call_on_flush_flight(client), 1);

    {
        TlsAdapter early_data_adapter(make_client_config());
        EXPECT_EQ(TlsAdapterTestPeer::call_on_add_handshake_data(
                      early_data_adapter, ssl_encryption_early_data, data.data(), data.size()),
                  1);
        EXPECT_EQ(early_data_adapter.take_pending(EncryptionLevel::zero_rtt).size(), data.size());
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(early_data_adapter), std::nullopt);
    }

    {
        TlsAdapter unsupported_cipher_adapter(make_client_config());
        const ScopedTlsAdapterFaultInjector injector(
            TlsAdapterFaultPoint::set_encryption_secrets_unsupported_cipher);
        EXPECT_EQ(TlsAdapterTestPeer::call_on_set_encryption_secrets(
                      unsupported_cipher_adapter, ssl_encryption_application, read_secret.data(),
                      nullptr, read_secret.size()),
                  0);
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(unsupported_cipher_adapter),
                  CodecErrorCode::unsupported_cipher_suite);
    }
}

TEST(QuicTlsAdapterContractTest, UnknownEncryptionLevelValueIsIgnoredWhenSettingSecrets) {
    TlsAdapter adapter(make_client_config());
    ASSERT_TRUE(adapter.start().has_value());

    const std::array<uint8_t, 32> secret{};
    EXPECT_EQ(TlsAdapterTestPeer::call_on_set_encryption_secrets_value(
                  adapter, 0xff, secret.data(), secret.data(), secret.size()),
              1);
    EXPECT_TRUE(adapter.take_available_secrets().empty());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter), std::nullopt);
}

TEST(QuicTlsAdapterContractTest, UnknownEncryptionLevelValueFailsWhenAddingHandshakeData) {
    TlsAdapter adapter(make_client_config());
    ASSERT_TRUE(adapter.start().has_value());

    const std::array<uint8_t, 4> data{9, 8, 7, 6};
    EXPECT_EQ(TlsAdapterTestPeer::call_on_add_handshake_data_value(adapter, 0xff, data.data(),
                                                                   data.size()),
              0);
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
              CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTlsAdapterContractTest, DirectOnSetSecretIgnoresNullSecretsAndMissingCipher) {
    const std::array<uint8_t, 32> secret{};

    {
        TlsAdapter adapter(make_client_config());
        EXPECT_EQ(TlsAdapterTestPeer::call_on_set_secret(adapter, ssl_encryption_application,
                                                         EndpointRole::client, nullptr,
                                                         secret.size()),
                  1);
        EXPECT_TRUE(adapter.take_available_secrets().empty());
    }

    {
        TlsAdapter client(make_client_config());
        TlsAdapter server(make_server_config());
        drive_tls_handshake(client, server);
        static_cast<void>(client.take_available_secrets());

        EXPECT_EQ(TlsAdapterTestPeer::call_on_set_secret(client, ssl_encryption_application,
                                                         EndpointRole::server, secret.data(),
                                                         secret.size()),
                  1);
        auto inbound_secrets = client.take_available_secrets();
        ASSERT_EQ(inbound_secrets.size(), 1u);
        EXPECT_EQ(inbound_secrets[0].sender, EndpointRole::server);

        EXPECT_EQ(TlsAdapterTestPeer::call_on_set_secret(client, ssl_encryption_application,
                                                         EndpointRole::client, secret.data(),
                                                         secret.size()),
                  1);
        auto outbound_secrets = client.take_available_secrets();
        ASSERT_EQ(outbound_secrets.size(), 1u);
        EXPECT_EQ(outbound_secrets[0].sender, EndpointRole::client);
    }

    {
        TlsAdapter adapter(make_client_config());
        EXPECT_EQ(TlsAdapterTestPeer::pending_or_current_cipher_protocol_id(adapter), std::nullopt);
    }

    {
        TlsAdapter adapter(make_client_config());
        TlsAdapterTestPeer::reset_ssl(adapter);
        EXPECT_EQ(TlsAdapterTestPeer::call_on_set_secret(adapter, ssl_encryption_application,
                                                         EndpointRole::client, secret.data(),
                                                         secret.size()),
                  0);
        EXPECT_TRUE(adapter.take_available_secrets().empty());
    }

    {
        TlsAdapter adapter(make_client_config());
        TlsAdapterTestPeer::reset_ssl(adapter);
        EXPECT_EQ(TlsAdapterTestPeer::pending_or_current_cipher_protocol_id(adapter), std::nullopt);
    }
}

TEST(QuicTlsAdapterContractTest,
     CapturePeerTransportParametersReturnsWhenSslMissingOrAlreadyCaptured) {
    TlsAdapter missing_ssl_adapter(make_client_config());
    TlsAdapterTestPeer::reset_ssl(missing_ssl_adapter);
    TlsAdapterTestPeer::capture_peer_transport_parameters(missing_ssl_adapter);
    EXPECT_FALSE(missing_ssl_adapter.peer_transport_parameters().has_value());

    TlsAdapter cached_adapter(make_client_config());
    TlsAdapterTestPeer::set_peer_transport_parameters(cached_adapter, {std::byte{0x42}});
    TlsAdapterTestPeer::capture_peer_transport_parameters(cached_adapter);
    EXPECT_EQ(cached_adapter.peer_transport_parameters(),
              std::optional<std::vector<std::byte>>{{std::byte{0x42}}});
}

TEST(QuicTlsAdapterContractTest, CapturePeerTransportParametersRefreshesCachedValueAfterHandshake) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());

    drive_tls_handshake(client, server);

    const auto peer_transport_parameters = client.peer_transport_parameters();
    ASSERT_TRUE(peer_transport_parameters.has_value());
    if (!peer_transport_parameters.has_value()) {
        return;
    }
    const auto &expected = *peer_transport_parameters;

    TlsAdapterTestPeer::set_peer_transport_parameters(client, {std::byte{0x42}});
    TlsAdapterTestPeer::capture_peer_transport_parameters(client);

    EXPECT_EQ(client.peer_transport_parameters(), std::optional<std::vector<std::byte>>(expected));
}

TEST(QuicTlsAdapterContractTest, RuntimeStatusUpdateReturnsWhenSslIsMissing) {
    TlsAdapter adapter(make_client_config());
    TlsAdapterTestPeer::reset_ssl(adapter);

    TlsAdapterTestPeer::update_runtime_status(adapter);
    EXPECT_EQ(adapter.early_data_accepted(), std::nullopt);
}

TEST(QuicTlsAdapterContractTest,
     RuntimeStatusUpdateWithSslAndNoSelectedAlpnKeepsSelectedProtocolEmpty) {
    TlsAdapter adapter(make_client_config());
    ASSERT_TRUE(adapter.start().has_value());
    ASSERT_FALSE(adapter.selected_application_protocol().has_value());

    TlsAdapterTestPeer::update_runtime_status(adapter);

    EXPECT_FALSE(adapter.selected_application_protocol().has_value());
}

TEST(QuicTlsAdapterContractTest,
     NotSentEarlyDataMarksAttemptedHandshakeAsRejectedWhenHandshakeCompletes) {
    TlsAdapter adapter(make_client_config());
    ASSERT_TRUE(adapter.start().has_value());

    TlsAdapterTestPeer::set_early_data_attempted(adapter, true);
    TlsAdapterTestPeer::apply_early_data_status(adapter, SSL_EARLY_DATA_NOT_SENT, true);

    EXPECT_EQ(adapter.early_data_accepted(), std::optional<bool>(false));
}

TEST(QuicTlsAdapterContractTest, UnknownEarlyDataStatusLeavesStateUnchanged) {
    TlsAdapter adapter(make_client_config());
    ASSERT_TRUE(adapter.start().has_value());

    TlsAdapterTestPeer::apply_early_data_status(adapter, 0xff, true);
    EXPECT_EQ(adapter.early_data_accepted(), std::nullopt);
}

TEST(QuicTlsAdapterContractTest, DriveHandshakeFaultAndMoveAssignmentRemainUsable) {
    {
        TlsAdapter adapter(make_client_config());
        const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::drive_handshake);
        EXPECT_FALSE(TlsAdapterTestPeer::drive_handshake(adapter).has_value());
        EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
                  CodecErrorCode::invalid_packet_protection_state);
    }

    TlsAdapter source(make_client_config());
    TlsAdapter destination(make_client_config());
    destination = std::move(source);

    EXPECT_FALSE(destination.handshake_complete());
    EXPECT_TRUE(destination.start().has_value());
}

TEST(QuicTlsAdapterContractTest, DriveHandshakeFaultAfterStartSetsStickyError) {
    TlsAdapter adapter(make_client_config());
    ASSERT_TRUE(adapter.start().has_value());

    const ScopedTlsAdapterFaultInjector injector(TlsAdapterFaultPoint::drive_handshake);
    EXPECT_FALSE(TlsAdapterTestPeer::drive_handshake(adapter).has_value());
    EXPECT_EQ(TlsAdapterTestPeer::sticky_error_code(adapter),
              CodecErrorCode::invalid_packet_protection_state);
}

TEST(QuicTlsAdapterContractTest, MoveConstructionRetainsUsableAdapter) {
    TlsAdapter source(make_client_config());
    TlsAdapter moved(std::move(source));

    EXPECT_FALSE(moved.handshake_complete());
    EXPECT_TRUE(moved.start().has_value());
}

} // namespace
