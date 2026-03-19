#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#define private public
#include "src/quic/demo_channel.h"
#undef private

#include "src/coquic.h"
#include "src/quic/packet_crypto_test_hooks.h"
#include "tests/quic_test_utils.h"

namespace {

template <typename Channel>
concept has_send_message =
    requires(Channel &channel) { channel.send_message(std::vector<std::byte>{}); };

template <typename Channel>
concept has_on_datagram =
    requires(Channel &channel) { channel.on_datagram(std::vector<std::byte>{}); };

template <typename Channel>
concept has_take_messages = requires(Channel &channel) { channel.take_messages(); };

static_assert(!has_send_message<coquic::quic::QuicDemoChannel>);
static_assert(!has_on_datagram<coquic::quic::QuicDemoChannel>);
static_assert(!has_take_messages<coquic::quic::QuicDemoChannel>);

class ScopedFd {
  public:
    explicit ScopedFd(int fd) : fd_(fd) {
    }

    ~ScopedFd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

    int get() const {
        return fd_;
    }

  private:
    int fd_ = -1;
};

bool set_nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool bind_loopback(int fd, sockaddr_in &bound) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(0);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        return false;
    }

    socklen_t length = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &length) != 0) {
        return false;
    }

    return true;
}

void merge_result(coquic::quic::QuicDemoChannelResult &combined,
                  coquic::quic::QuicDemoChannelResult step) {
    combined.effects.insert(combined.effects.end(), std::make_move_iterator(step.effects.begin()),
                            std::make_move_iterator(step.effects.end()));
    combined.next_wakeup = step.next_wakeup;
}

TEST(QuicDemoChannelTest, ClientStartProducesSendDatagramEffect) {
    coquic::quic::QuicDemoChannel client(coquic::quic::test::make_client_core_config());

    const auto result =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    const auto datagrams = coquic::quic::test::send_datagrams_from(result);

    ASSERT_EQ(datagrams.size(), 1u);
    EXPECT_GE(datagrams.front().size(), 1200u);
    EXPECT_TRUE(coquic::quic::test::state_changes_from(result).empty());
    EXPECT_EQ(result.next_wakeup, std::nullopt);
    EXPECT_FALSE(client.is_ready());
    EXPECT_FALSE(client.has_failed());
}

TEST(QuicDemoChannelTest, QueuedMessageFlushesWhenClientTransitionsToReady) {
    coquic::quic::QuicDemoChannel client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel server(coquic::quic::test::make_server_core_config());

    const auto queued = client.advance(
        coquic::quic::QuicDemoChannelQueueMessage{
            .bytes = coquic::quic::test::bytes_from_string("hello"),
        },
        coquic::quic::test::test_time());
    EXPECT_TRUE(queued.effects.empty());

    auto to_server = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    coquic::quic::QuicDemoChannelResult ready_step;
    bool saw_ready = false;

    for (int i = 0; i < 32 && !saw_ready; ++i) {
        const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
            to_server, server, coquic::quic::test::test_time());
        auto candidate = coquic::quic::test::relay_send_datagrams_to_peer(
            to_client, client, coquic::quic::test::test_time());
        const auto changes = coquic::quic::test::state_changes_from(candidate);
        if (coquic::quic::test::count_state_change(
                changes, coquic::quic::QuicDemoChannelStateChange::ready) == 1u) {
            saw_ready = true;
            ready_step = std::move(candidate);
            break;
        }

        to_server = std::move(candidate);
    }

    ASSERT_TRUE(saw_ready);
    EXPECT_FALSE(coquic::quic::test::send_datagrams_from(ready_step).empty());
    const auto ready_position = std::find_if(
        ready_step.effects.begin(), ready_step.effects.end(),
        [](const coquic::quic::QuicDemoChannelEffect &effect) {
            const auto *state_event = std::get_if<coquic::quic::QuicDemoChannelStateEvent>(&effect);
            return state_event != nullptr &&
                   state_event->change == coquic::quic::QuicDemoChannelStateChange::ready;
        });
    ASSERT_NE(ready_position, ready_step.effects.end());
    EXPECT_EQ(std::find_if(ready_position, ready_step.effects.end(),
                           [](const coquic::quic::QuicDemoChannelEffect &effect) {
                               return std::holds_alternative<coquic::quic::QuicCoreSendDatagram>(
                                   effect);
                           }),
              ready_step.effects.end());

    const auto server_after_ready = coquic::quic::test::relay_send_datagrams_to_peer(
        ready_step, server, coquic::quic::test::test_time(1));
    const auto messages = coquic::quic::test::received_messages_from(server_after_ready);
    ASSERT_EQ(messages.size(), 1u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(messages.front()), "hello");
}

TEST(QuicDemoChannelTest, FailedFlushAfterReadySuppressesStaleReadyStateEvent) {
    coquic::quic::QuicDemoChannel client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel server(coquic::quic::test::make_server_core_config());

    const auto queued = client.advance(
        coquic::quic::QuicDemoChannelQueueMessage{
            .bytes = std::vector<std::byte>(static_cast<std::size_t>(64) * 1024U, std::byte{0x68}),
        },
        coquic::quic::test::test_time());
    EXPECT_TRUE(queued.effects.empty());

    auto to_server = client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    coquic::quic::QuicDemoChannelResult failed_step;
    bool saw_failed = false;

    for (int i = 0; i < 32 && !saw_failed; ++i) {
        const auto to_client = coquic::quic::test::relay_send_datagrams_to_peer(
            to_server, server, coquic::quic::test::test_time(i + 1));
        const coquic::quic::test::ScopedPacketCryptoFaultInjector injector{
            coquic::quic::test::PacketCryptoFaultPoint::seal_length_guard, 8};
        auto candidate = coquic::quic::test::relay_send_datagrams_to_peer(
            to_client, client, coquic::quic::test::test_time(i + 1));
        const auto changes = coquic::quic::test::state_changes_from(candidate);
        if (coquic::quic::test::count_state_change(
                changes, coquic::quic::QuicDemoChannelStateChange::failed) == 1u) {
            failed_step = std::move(candidate);
            saw_failed = true;
            break;
        }

        to_server = std::move(candidate);
    }

    ASSERT_TRUE(saw_failed);
    EXPECT_EQ(coquic::quic::test::state_changes_from(failed_step),
              (std::vector<coquic::quic::QuicDemoChannelStateChange>{
                  coquic::quic::QuicDemoChannelStateChange::failed,
              }));
}

TEST(QuicDemoChannelTest, ReceivedMessagesAreDeliveredThroughEffects) {
    coquic::quic::QuicDemoChannel client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel server(coquic::quic::test::make_server_core_config());

    coquic::quic::test::drive_demo_channel_handshake(client, server,
                                                     coquic::quic::test::test_time());
    ASSERT_TRUE(client.is_ready());
    ASSERT_TRUE(server.is_ready());

    const auto send = client.advance(
        coquic::quic::QuicDemoChannelQueueMessage{
            .bytes = coquic::quic::test::bytes_from_string("ping"),
        },
        coquic::quic::test::test_time(1));
    const auto received = coquic::quic::test::relay_send_datagrams_to_peer(
        send, server, coquic::quic::test::test_time(1));
    const auto messages = coquic::quic::test::received_messages_from(received);

    ASSERT_EQ(messages.size(), 1u);
    EXPECT_EQ(coquic::quic::test::string_from_bytes(messages.front()), "ping");
}

TEST(QuicDemoChannelTest, OversizedQueuedMessageFailsOnceAndLaterCallsAreInert) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_client_core_config());

    const auto failed = channel.advance(
        coquic::quic::QuicDemoChannelQueueMessage{
            .bytes = std::vector<std::byte>(65537, std::byte{0x61}),
        },
        coquic::quic::test::test_time());
    const auto failed_changes = coquic::quic::test::state_changes_from(failed);
    EXPECT_EQ(failed_changes, (std::vector<coquic::quic::QuicDemoChannelStateChange>{
                                  coquic::quic::QuicDemoChannelStateChange::failed,
                              }));
    EXPECT_EQ(failed.next_wakeup, std::nullopt);
    EXPECT_TRUE(channel.has_failed());
    EXPECT_FALSE(channel.is_ready());

    const auto after_start =
        channel.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time(1));
    const auto after_timer =
        channel.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(2));
    EXPECT_TRUE(after_start.effects.empty());
    EXPECT_TRUE(after_timer.effects.empty());
    EXPECT_EQ(after_start.next_wakeup, std::nullopt);
    EXPECT_EQ(after_timer.next_wakeup, std::nullopt);
}

TEST(QuicDemoChannelTest, QueueBeforeHandshakePreservesCurrentWakeup) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_client_core_config());
    channel.next_wakeup_ = coquic::quic::test::test_time(123);

    const auto result = channel.advance(
        coquic::quic::QuicDemoChannelQueueMessage{
            .bytes = coquic::quic::test::bytes_from_string("hello"),
        },
        coquic::quic::test::test_time(1));

    EXPECT_TRUE(result.effects.empty());
    EXPECT_EQ(result.next_wakeup, coquic::quic::test::test_time(123));
}

TEST(QuicDemoChannelTest, LaterInternalStepWakeupReplacesEarlierWakeup) {
    coquic::quic::QuicDemoChannel channel(coquic::quic::test::make_client_core_config());

    coquic::quic::QuicDemoChannelResult first_step{
        .next_wakeup = coquic::quic::test::test_time(10),
    };
    coquic::quic::QuicDemoChannelResult second_step{
        .next_wakeup = std::nullopt,
    };

    channel.merge_result(first_step, std::move(second_step));

    EXPECT_EQ(first_step.next_wakeup, std::nullopt);
}

TEST(QuicDemoChannelTest, InboundOversizedLengthPrefixFailsOnceAndLaterCallsAreInert) {
    coquic::quic::QuicCore attacker(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel victim(coquic::quic::test::make_server_core_config());

    auto to_victim =
        attacker.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    for (int i = 0; i < 32 && !(attacker.is_handshake_complete() && victim.is_ready()); ++i) {
        const auto to_attacker = coquic::quic::test::relay_send_datagrams_to_peer(
            to_victim, victim, coquic::quic::test::test_time());
        if (attacker.is_handshake_complete() && victim.is_ready()) {
            break;
        }
        to_victim = coquic::quic::test::relay_send_datagrams_to_peer(
            to_attacker, attacker, coquic::quic::test::test_time());
    }

    ASSERT_TRUE(attacker.is_handshake_complete());
    ASSERT_TRUE(victim.is_ready());

    const auto attack = attacker.advance(
        coquic::quic::QuicCoreQueueApplicationData{
            .bytes =
                {
                    std::byte{0x00},
                    std::byte{0x01},
                    std::byte{0x00},
                    std::byte{0x01},
                },
        },
        coquic::quic::test::test_time(1));
    const auto failed = coquic::quic::test::relay_send_datagrams_to_peer(
        attack, victim, coquic::quic::test::test_time(1));
    const auto failed_changes = coquic::quic::test::state_changes_from(failed);
    EXPECT_EQ(coquic::quic::test::count_state_change(
                  failed_changes, coquic::quic::QuicDemoChannelStateChange::failed),
              1u);
    EXPECT_TRUE(victim.has_failed());
    EXPECT_FALSE(victim.is_ready());
    EXPECT_EQ(failed.next_wakeup, std::nullopt);

    const auto after =
        victim.advance(coquic::quic::QuicCoreTimerExpired{}, coquic::quic::test::test_time(2));
    EXPECT_TRUE(after.effects.empty());
    EXPECT_EQ(after.next_wakeup, std::nullopt);
}

TEST(QuicDemoChannelTest, SocketBackedPollApiSmokeTestDeliversMessage) {
    const int client_socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(client_socket_fd, 0) << std::strerror(errno);
    const int server_socket_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(server_socket_fd, 0) << std::strerror(errno);
    ScopedFd client_socket(client_socket_fd);
    ScopedFd server_socket(server_socket_fd);

    ASSERT_TRUE(set_nonblocking(client_socket.get())) << std::strerror(errno);
    ASSERT_TRUE(set_nonblocking(server_socket.get())) << std::strerror(errno);

    sockaddr_in client_address{};
    sockaddr_in server_address{};
    ASSERT_TRUE(bind_loopback(client_socket.get(), client_address)) << std::strerror(errno);
    ASSERT_TRUE(bind_loopback(server_socket.get(), server_address)) << std::strerror(errno);

    coquic::quic::QuicDemoChannel client(coquic::quic::test::make_client_core_config());
    coquic::quic::QuicDemoChannel server(coquic::quic::test::make_server_core_config());

    const auto buffered = client.advance(
        coquic::quic::QuicDemoChannelQueueMessage{
            .bytes = coquic::quic::test::bytes_from_string("hello"),
        },
        coquic::quic::test::test_time());
    EXPECT_TRUE(buffered.effects.empty());

    auto client_result =
        client.advance(coquic::quic::QuicCoreStart{}, coquic::quic::test::test_time());
    coquic::quic::QuicDemoChannelResult server_result;
    bool saw_hello = false;

    for (int i = 0; i < 256 && !saw_hello; ++i) {
        for (const auto &datagram : coquic::quic::test::send_datagrams_from(client_result)) {
            const auto sent = ::sendto(client_socket.get(), datagram.data(), datagram.size(), 0,
                                       reinterpret_cast<const sockaddr *>(&server_address),
                                       sizeof(server_address));
            ASSERT_EQ(sent, static_cast<ssize_t>(datagram.size())) << std::strerror(errno);
        }
        for (const auto &datagram : coquic::quic::test::send_datagrams_from(server_result)) {
            const auto sent = ::sendto(server_socket.get(), datagram.data(), datagram.size(), 0,
                                       reinterpret_cast<const sockaddr *>(&client_address),
                                       sizeof(client_address));
            ASSERT_EQ(sent, static_cast<ssize_t>(datagram.size())) << std::strerror(errno);
        }

        client_result = {};
        while (true) {
            std::array<std::byte, 65535> inbound{};
            const auto bytes_read = ::recvfrom(client_socket.get(), inbound.data(), inbound.size(),
                                               0, nullptr, nullptr);
            if (bytes_read < 0) {
                ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK) << std::strerror(errno);
                break;
            }

            auto step = client.advance(
                coquic::quic::QuicCoreInboundDatagram{
                    .bytes = std::vector<std::byte>(
                        inbound.begin(), inbound.begin() + static_cast<std::ptrdiff_t>(bytes_read)),
                },
                coquic::quic::test::test_time(i + 1));
            merge_result(client_result, std::move(step));
        }

        server_result = {};
        while (true) {
            std::array<std::byte, 65535> inbound{};
            const auto bytes_read = ::recvfrom(server_socket.get(), inbound.data(), inbound.size(),
                                               0, nullptr, nullptr);
            if (bytes_read < 0) {
                ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK) << std::strerror(errno);
                break;
            }

            auto step = server.advance(
                coquic::quic::QuicCoreInboundDatagram{
                    .bytes = std::vector<std::byte>(
                        inbound.begin(), inbound.begin() + static_cast<std::ptrdiff_t>(bytes_read)),
                },
                coquic::quic::test::test_time(i + 1));
            for (const auto &message : coquic::quic::test::received_messages_from(step)) {
                if (coquic::quic::test::string_from_bytes(message) == "hello") {
                    saw_hello = true;
                }
            }
            merge_result(server_result, std::move(step));
        }
    }

    EXPECT_TRUE(saw_hello);
    EXPECT_FALSE(client.has_failed());
    EXPECT_FALSE(server.has_failed());
}

} // namespace
