#include <gtest/gtest.h>

#define private public
#include "src/quic/demo_channel.h"
#undef private

#include "src/coquic.h"
#include "tests/quic_test_utils.h"

namespace {

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

    auto to_victim =
        coquic::quic::test::send_datagrams_from(
            attacker.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time()))
            .front();
    auto to_attacker = std::vector<std::byte>{};

    for (int i = 0; i < 32 && !(attacker.is_handshake_complete() && victim.is_ready()); ++i) {
        if (!to_victim.empty()) {
            to_attacker = victim.on_datagram(to_victim);
        }

        const auto attacker_result =
            to_attacker.empty()
                ? attacker.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time())
                : attacker.advance(coquic::quic::QuicCoreInboundDatagram{to_attacker},
                                   coquic::quic::test::test_time());
        auto datagrams = coquic::quic::test::send_datagrams_from(attacker_result);
        to_victim = datagrams.empty() ? std::vector<std::byte>{} : std::move(datagrams.front());
    }

    ASSERT_TRUE(attacker.is_handshake_complete());
    ASSERT_TRUE(victim.is_ready());

    auto attack_datagrams = coquic::quic::test::send_datagrams_from(attacker.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes =
                {
                    std::byte{0x00},
                    std::byte{0x01},
                    std::byte{0x00},
                    std::byte{0x01},
                },
        },
        coquic::quic::test::test_time(1)));
    ASSERT_FALSE(attack_datagrams.empty());
    const auto attack_datagram = std::move(attack_datagrams.front());
    ASSERT_FALSE(attack_datagram.empty());

    EXPECT_TRUE(victim.on_datagram(attack_datagram).empty());
    EXPECT_TRUE(victim.has_failed());
    EXPECT_FALSE(victim.is_ready());
    EXPECT_TRUE(victim.take_messages().empty());

    victim.send_message(coquic::quic::test::bytes_from_string("ignored"));
    EXPECT_TRUE(victim.on_datagram({}).empty());
    EXPECT_TRUE(victim.take_messages().empty());
}

} // namespace
