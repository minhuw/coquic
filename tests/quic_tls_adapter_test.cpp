#include <gtest/gtest.h>

#include "src/quic/tls_adapter.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::EncryptionLevel;
using coquic::quic::EndpointRole;
using coquic::quic::TlsAdapter;
using coquic::quic::TlsAdapterConfig;
using coquic::quic::TlsIdentity;

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

TEST(QuicTlsAdapterTest, ClientAndServerExchangeHandshakeBytesAndSecrets) {
    TlsAdapter client(make_client_config());
    TlsAdapter server(make_server_config());

    ASSERT_TRUE(client.start().has_value());

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

    EXPECT_TRUE(client.handshake_complete());
    EXPECT_TRUE(server.handshake_complete());
    EXPECT_TRUE(client.peer_transport_parameters().has_value());
    EXPECT_TRUE(server.peer_transport_parameters().has_value());
    EXPECT_FALSE(client.take_available_secrets().empty());
    EXPECT_FALSE(server.take_available_secrets().empty());
}

} // namespace
