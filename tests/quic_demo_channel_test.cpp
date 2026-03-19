#include <gtest/gtest.h>

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

} // namespace
