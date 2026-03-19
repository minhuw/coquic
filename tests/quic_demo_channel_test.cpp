#include <cstring>
#include <type_traits>

#include <gtest/gtest.h>

#define private public
#include "src/quic/demo_channel.h"
#undef private

#include "src/coquic.h"
#include "src/quic/protected_codec.h"
#include "tests/quic_test_utils.h"

namespace {

using coquic::quic::AckFrame;
using coquic::quic::CipherSuite;
using coquic::quic::ConnectionId;
using coquic::quic::EndpointRole;
using coquic::quic::Frame;
using coquic::quic::ProtectedOneRttPacket;
using coquic::quic::ProtectedPacket;
using coquic::quic::SerializeProtectionContext;
using coquic::quic::TlsAdapter;
using coquic::quic::TlsAdapterConfig;
using coquic::quic::TlsIdentity;
using coquic::quic::TrafficSecret;

std::vector<std::byte> framed_message(std::string_view text) {
    std::vector<std::byte> framed{
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
        static_cast<std::byte>(text.size()),
    };
    for (const auto character : text) {
        framed.push_back(static_cast<std::byte>(character));
    }

    return framed;
}

EndpointRole opposite_role(EndpointRole role) {
    return role == EndpointRole::client ? EndpointRole::server : EndpointRole::client;
}

CipherSuite invalid_cipher_suite() {
    const auto raw = static_cast<std::underlying_type_t<CipherSuite>>(0xff);
    CipherSuite cipher_suite{};
    std::memcpy(&cipher_suite, &raw, sizeof(cipher_suite));
    return cipher_suite;
}

TrafficSecret make_traffic_secret(CipherSuite cipher_suite = CipherSuite::tls_aes_128_gcm_sha256) {
    const std::size_t secret_size = cipher_suite == CipherSuite::tls_aes_256_gcm_sha384 ? 48u : 32u;
    return TrafficSecret{
        .cipher_suite = cipher_suite,
        .secret = std::vector<std::byte>(secret_size, std::byte{0x11}),
    };
}

TlsAdapterConfig make_client_tls_config(std::vector<std::byte> local_transport_parameters =
                                            coquic::quic::test::sample_transport_parameters()) {
    return TlsAdapterConfig{
        .role = EndpointRole::client,
        .verify_peer = false,
        .server_name = "localhost",
        .local_transport_parameters = std::move(local_transport_parameters),
    };
}

TlsAdapterConfig make_server_tls_config(std::vector<std::byte> local_transport_parameters =
                                            coquic::quic::test::sample_transport_parameters()) {
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
        .local_transport_parameters = std::move(local_transport_parameters),
    };
}

void drive_tls_handshake(TlsAdapter &client, TlsAdapter &server) {
    ASSERT_TRUE(client.start().has_value());
    auto to_server = client.take_pending(coquic::quic::EncryptionLevel::initial);
    ASSERT_FALSE(to_server.empty());
    ASSERT_TRUE(server.provide(coquic::quic::EncryptionLevel::initial, to_server).has_value());

    for (int i = 0; i < 32 && !(client.handshake_complete() && server.handshake_complete()); ++i) {
        const auto client_initial = client.take_pending(coquic::quic::EncryptionLevel::initial);
        if (!client_initial.empty()) {
            ASSERT_TRUE(
                server.provide(coquic::quic::EncryptionLevel::initial, client_initial).has_value());
        }

        const auto server_initial = server.take_pending(coquic::quic::EncryptionLevel::initial);
        if (!server_initial.empty()) {
            ASSERT_TRUE(
                client.provide(coquic::quic::EncryptionLevel::initial, server_initial).has_value());
        }

        const auto server_handshake = server.take_pending(coquic::quic::EncryptionLevel::handshake);
        if (!server_handshake.empty()) {
            ASSERT_TRUE(client.provide(coquic::quic::EncryptionLevel::handshake, server_handshake)
                            .has_value());
        }

        const auto client_handshake = client.take_pending(coquic::quic::EncryptionLevel::handshake);
        if (!client_handshake.empty()) {
            ASSERT_TRUE(server.provide(coquic::quic::EncryptionLevel::handshake, client_handshake)
                            .has_value());
        }

        client.poll();
        server.poll();
    }

    ASSERT_TRUE(client.handshake_complete());
    ASSERT_TRUE(server.handshake_complete());
}

std::vector<std::byte> make_one_rtt_datagram(coquic::quic::QuicConnection &connection,
                                             std::vector<Frame> frames,
                                             const TrafficSecret &secret) {
    const auto serialized = coquic::quic::serialize_protected_datagram(
        std::vector<ProtectedPacket>{ProtectedOneRttPacket{
            .destination_connection_id = connection.config_.source_connection_id,
            .packet_number_length = 2,
            .packet_number = 0,
            .frames = std::move(frames),
        }},
        SerializeProtectionContext{
            .local_role = opposite_role(connection.config_.role),
            .client_initial_destination_connection_id =
                connection.client_initial_destination_connection_id(),
            .one_rtt_secret = secret,
        });
    EXPECT_TRUE(serialized.has_value());
    if (!serialized.has_value()) {
        return {};
    }

    return serialized.value();
}

TEST(QuicDemoChannelTest, BufferedMessageFlushesAfterHandshake) {
    coquic::quic::QuicDemoChannel client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel server(coquic::quic::test::make_server_core_config());

    client.send_message(coquic::quic::test::bytes_from_string("hello"));
    auto to_server = client.on_datagram({});
    auto to_client = std::vector<std::byte>{};

    for (int i = 0; i < 32 && !(client.is_ready() && server.is_ready()); ++i) {
        if (!to_server.empty()) {
            to_client = server.on_datagram(to_server);
        }
        to_server = client.on_datagram(to_client);
    }

    ASSERT_TRUE(client.is_ready());
    ASSERT_TRUE(server.is_ready());
    ASSERT_FALSE(client.has_failed());
    ASSERT_FALSE(server.has_failed());

    if (!to_server.empty()) {
        to_client = server.on_datagram(to_server);
        to_server = client.on_datagram(to_client);
    }

    coquic::quic::test::flush_demo_channels(client, server);
    const auto messages = server.take_messages();

    ASSERT_EQ(messages.size(), 1u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(messages[0]), "hello");
}

TEST(QuicDemoChannelTest, RejectsOversizedFramedMessage) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_client_core_config());

    channel.send_message(std::vector<std::byte>(65537, std::byte{0x61}));

    EXPECT_TRUE(channel.has_failed());
    EXPECT_TRUE(channel.on_datagram({}).empty());
    EXPECT_TRUE(channel.take_messages().empty());
}

TEST(QuicDemoChannelTest, CoreFailureStateRemainsTerminalForWrapperOperations) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_server_core_config());

    EXPECT_TRUE(channel.on_datagram({std::byte{0x01}}).empty());
    ASSERT_TRUE(channel.has_failed());
    ASSERT_TRUE(channel.core_.has_failed());

    channel.failed_ = false;
    ASSERT_FALSE(channel.failed_);
    ASSERT_TRUE(channel.core_.has_failed());

    channel.send_message(coquic::quic::test::bytes_from_string("ignored"));
    EXPECT_TRUE(channel.pending_send_bytes_.empty());
    EXPECT_TRUE(channel.on_datagram({}).empty());
    EXPECT_FALSE(channel.is_ready());
}

TEST(QuicDemoChannelTest, InboundOversizedLengthPrefixTriggersTerminalFailure) {
    coquic::quic::QuicCore attacker(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel victim(coquic::quic::test::make_server_core_config());

    auto to_victim = attacker.receive({});
    auto to_attacker = std::vector<std::byte>{};

    for (int i = 0; i < 32 && !(attacker.is_handshake_complete() && victim.is_ready()); ++i) {
        if (!to_victim.empty()) {
            to_attacker = victim.on_datagram(to_victim);
        }
        to_victim = attacker.receive(to_attacker);
    }

    ASSERT_TRUE(attacker.is_handshake_complete());
    ASSERT_TRUE(victim.is_ready());

    attacker.queue_application_data({
        std::byte{0x00},
        std::byte{0x01},
        std::byte{0x00},
        std::byte{0x01},
    });
    const auto attack_datagram = attacker.receive({});
    ASSERT_FALSE(attack_datagram.empty());

    EXPECT_TRUE(victim.on_datagram(attack_datagram).empty());
    EXPECT_TRUE(victim.has_failed());
    EXPECT_FALSE(victim.is_ready());
    EXPECT_TRUE(victim.take_messages().empty());

    victim.send_message(coquic::quic::test::bytes_from_string("ignored"));
    EXPECT_TRUE(victim.on_datagram({}).empty());
    EXPECT_TRUE(victim.take_messages().empty());
}

TEST(QuicDemoChannelTest, ReadyChannelQueuesMessageDirectlyToCore) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_client_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        *channel.core_.connection_, coquic::quic::HandshakeStatus::connected);

    channel.send_message(coquic::quic::test::bytes_from_string("hi"));

    EXPECT_TRUE(channel.pending_send_bytes_.empty());
    EXPECT_EQ(channel.core_.connection_->pending_application_send_, framed_message("hi"));
}

TEST(QuicDemoChannelTest, ReadyChannelFlushesBufferedBytesIntoCore) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_client_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        *channel.core_.connection_, coquic::quic::HandshakeStatus::connected);
    channel.pending_send_bytes_ = framed_message("queued");

    EXPECT_FALSE(channel.on_datagram({}).empty());
    EXPECT_TRUE(channel.pending_send_bytes_.empty());
    EXPECT_EQ(channel.core_.connection_->pending_application_send_, framed_message("queued"));
}

TEST(QuicDemoChannelTest, PartialFramedMessageWaitsForCompletion) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_server_core_config());
    coquic::quic::test::QuicConnectionTestPeer::set_handshake_status(
        *channel.core_.connection_, coquic::quic::HandshakeStatus::connected);
    channel.core_.connection_->pending_application_receive_ =
        coquic::quic::test::bytes_from_string(std::string("\0\0\0\5he", 6));

    EXPECT_TRUE(channel.on_datagram({}).empty());
    EXPECT_TRUE(channel.take_messages().empty());
    EXPECT_EQ(channel.pending_receive_bytes_,
              coquic::quic::test::bytes_from_string(std::string("\0\0\0\5he", 6)));

    channel.core_.connection_->pending_application_receive_ =
        coquic::quic::test::bytes_from_string("llo");

    EXPECT_TRUE(channel.on_datagram({}).empty());

    const auto messages = channel.take_messages();
    ASSERT_EQ(messages.size(), 1u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(messages[0]), "hello");
}

TEST(QuicDemoChannelTest, ServerFlushesBufferedMessageWhenHandshakeCompletes) {
    coquic::quic::QuicDemoChannel client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel server(coquic::quic::test::make_server_core_config());

    server.send_message(coquic::quic::test::bytes_from_string("reply"));

    auto to_server = client.on_datagram({});
    auto to_client = std::vector<std::byte>{};
    bool saw_server_ready_transition = false;
    bool saw_immediate_server_reply = false;

    for (int i = 0; i < 32 && !(client.is_ready() && server.is_ready()); ++i) {
        if (!to_server.empty()) {
            const bool server_was_ready = server.is_ready();
            const auto server_outbound = server.on_datagram(to_server);
            if (!server_was_ready && server.is_ready()) {
                saw_server_ready_transition = true;
                if (!server_outbound.empty()) {
                    saw_immediate_server_reply = true;
                }
            }
            to_client = server_outbound;
        }
        to_server = client.on_datagram(to_client);
    }

    ASSERT_TRUE(client.is_ready());
    ASSERT_TRUE(server.is_ready());
    EXPECT_TRUE(saw_server_ready_transition);
    EXPECT_TRUE(saw_immediate_server_reply);

    coquic::quic::test::flush_demo_channels(client, server);
    const auto messages = client.take_messages();

    ASSERT_EQ(messages.size(), 1u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(messages[0]), "reply");
}

TEST(QuicDemoChannelTest, RetryFlushFailureAfterHandshakeCompletionMarksChannelFailed) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_client_core_config());
    channel.pending_send_bytes_ = framed_message("queued");

    auto &connection = *channel.core_.connection_;
    connection.started_ = true;
    connection.status_ = coquic::quic::HandshakeStatus::in_progress;
    connection.peer_transport_parameters_validated_ = true;
    connection.peer_source_connection_id_ = ConnectionId{std::byte{0x53}, std::byte{0x01}};
    connection.application_space_.read_secret = make_traffic_secret();
    connection.application_space_.write_secret = make_traffic_secret(invalid_cipher_suite());

    TlsAdapter client_adapter(make_client_tls_config());
    TlsAdapter server_adapter(make_server_tls_config());
    drive_tls_handshake(client_adapter, server_adapter);
    static_cast<void>(client_adapter.take_available_secrets());
    static_cast<void>(client_adapter.take_pending(coquic::quic::EncryptionLevel::initial));
    static_cast<void>(client_adapter.take_pending(coquic::quic::EncryptionLevel::handshake));
    static_cast<void>(client_adapter.take_pending(coquic::quic::EncryptionLevel::application));
    connection.tls_ = std::move(client_adapter);

    const auto datagram = make_one_rtt_datagram(connection,
                                                {AckFrame{
                                                    .largest_acknowledged = 0,
                                                    .ack_delay = 0,
                                                    .first_ack_range = 0,
                                                }},
                                                connection.application_space_.read_secret.value());

    EXPECT_TRUE(channel.on_datagram(datagram).empty());
    EXPECT_TRUE(channel.has_failed());
    EXPECT_TRUE(channel.take_messages().empty());
}

} // namespace
