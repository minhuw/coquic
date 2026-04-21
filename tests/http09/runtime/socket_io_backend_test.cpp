#include <gtest/gtest.h>

#include <deque>
#include <memory>

#include "src/io/io_backend_test_hooks.h"
#include "src/io/shared_udp_backend_core.h"
#include "src/io/socket_io_backend.h"
#include "tests/support/core/connection_test_fixtures.h"

namespace {

struct MultiSocketBackendTestTrace {
    std::vector<int> opened_families;
    std::vector<int> opened_fds;
    nfds_t last_poll_descriptor_count = 0;
    int last_send_socket_fd = -1;
    int readable_socket_fd = -1;
};

thread_local MultiSocketBackendTestTrace g_multi_socket_backend_test_trace;

class ScriptedIoEngine final : public coquic::io::QuicIoEngine {
  public:
    bool register_result = true;
    bool send_result = true;
    std::vector<int> registered_sockets;
    std::size_t last_wait_socket_count = 0;
    std::deque<std::optional<coquic::io::QuicIoEngineEvent>> scripted_wait_results;

    bool register_socket(int socket_fd) override {
        registered_sockets.push_back(socket_fd);
        return register_result;
    }

    bool send(int, const sockaddr_storage &, socklen_t, std::span<const std::byte>,
              std::string_view, coquic::quic::QuicEcnCodepoint) override {
        return send_result;
    }

    std::optional<coquic::io::QuicIoEngineEvent>
    wait(std::span<const int> socket_fds, int, std::optional<coquic::quic::QuicCoreTimePoint>,
         std::string_view) override {
        last_wait_socket_count = socket_fds.size();
        if (scripted_wait_results.empty()) {
            return std::nullopt;
        }

        auto result = scripted_wait_results.front();
        scripted_wait_results.pop_front();
        return result;
    }
};

sockaddr_storage make_ipv4_loopback_peer(std::uint16_t port) {
    sockaddr_storage peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return peer;
}

int record_socket_family_and_open(int family, int type, int protocol) {
    g_multi_socket_backend_test_trace.opened_families.push_back(family);
    const int fd = ::socket(family, type, protocol);
    if (fd >= 0) {
        g_multi_socket_backend_test_trace.opened_fds.push_back(fd);
    }
    return fd;
}

int record_poll_descriptor_count_and_second_readable(pollfd *descriptors, nfds_t descriptor_count,
                                                     int) {
    g_multi_socket_backend_test_trace.last_poll_descriptor_count = descriptor_count;
    for (nfds_t index = 0; index < descriptor_count; ++index) {
        descriptors[index].revents = 0;
        if (descriptors[index].fd == g_multi_socket_backend_test_trace.readable_socket_fd) {
            descriptors[index].revents = POLLIN;
        }
    }
    return g_multi_socket_backend_test_trace.readable_socket_fd >= 0 ? 1 : 0;
}

ssize_t record_sendto_socket_fd_for_backend_tests(int socket_fd, const void *, size_t length, int,
                                                  const sockaddr *, socklen_t) {
    g_multi_socket_backend_test_trace.last_send_socket_fd = socket_fd;
    return static_cast<ssize_t>(length);
}

ssize_t recvmsg_for_backend_tests(int socket_fd, msghdr *message, int) {
    if (message == nullptr || message->msg_iov == nullptr || message->msg_iovlen == 0) {
        errno = EINVAL;
        return -1;
    }

    constexpr std::array<std::byte, 2> kPayload = {
        std::byte{0x01},
        std::byte{0x02},
    };
    std::memcpy(message->msg_iov[0].iov_base, kPayload.data(), kPayload.size());

    if (socket_fd == g_multi_socket_backend_test_trace.readable_socket_fd) {
        sockaddr_in6 peer{};
        peer.sin6_family = AF_INET6;
        peer.sin6_port = htons(9443);
        peer.sin6_addr = in6addr_loopback;
        if (message->msg_name != nullptr &&
            message->msg_namelen >= static_cast<socklen_t>(sizeof(peer))) {
            std::memcpy(message->msg_name, &peer, sizeof(peer));
            message->msg_namelen = sizeof(peer);
        }
    } else {
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(8443);
        peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (message->msg_name != nullptr &&
            message->msg_namelen >= static_cast<socklen_t>(sizeof(peer))) {
            std::memcpy(message->msg_name, &peer, sizeof(peer));
            message->msg_namelen = sizeof(peer);
        }
    }
    message->msg_controllen = 0;
    return static_cast<ssize_t>(kPayload.size());
}

void reset_multi_socket_backend_test_trace() {
    g_multi_socket_backend_test_trace = {};
}

TEST(SocketIoBackendTest, PublicShellTypesCompileAndConstruct) {
    using namespace coquic::io;

    QuicIoRemote remote{};
    remote.family = AF_INET;

    QuicIoRxDatagram rx{
        .route_handle = 7,
        .bytes = {std::byte{0x01}},
    };
    QuicIoEvent event{
        .kind = QuicIoEvent::Kind::rx_datagram,
        .now = coquic::quic::test::test_time(0),
        .datagram = rx,
    };

    EXPECT_TRUE(event.datagram.has_value());
    EXPECT_EQ(event.datagram->route_handle, 7u);

    auto backend = coquic::io::make_socket_io_backend(coquic::io::QuicUdpBackendConfig{
        .role_name = "client",
        .idle_timeout_ms = 5,
    });
    ASSERT_NE(backend, nullptr);
    EXPECT_FALSE(backend->ensure_route(remote).has_value());
    EXPECT_FALSE(backend->wait(std::nullopt).has_value());
    EXPECT_FALSE(backend->send(QuicIoTxDatagram{
        .route_handle = 7,
        .bytes = {std::byte{0x02}},
    }));
}

TEST(SocketIoBackendTest, RouteHandlesStayStablePerPeerTuple) {
    EXPECT_TRUE(
        coquic::io::test::socket_io_backend_route_handles_are_stable_per_peer_tuple_for_tests());
}

TEST(SocketIoBackendTest, DuplicateRouteLookupReusesCachedRouteEntry) {
    EXPECT_TRUE(coquic::io::test::
                    socket_io_backend_duplicate_route_lookup_reuses_cached_route_entry_for_tests());
}

TEST(SocketIoBackendTest, SendUsesRouteHandleRouting) {
    EXPECT_TRUE(coquic::io::test::socket_io_backend_send_uses_route_handle_for_tests());
}

TEST(SocketIoBackendTest, EnsureRouteOpensAdditionalSocketForIncompatibleFamily) {
    using namespace coquic::io;

    reset_multi_socket_backend_test_trace();
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        coquic::io::test::SocketIoBackendOpsOverride{
            .socket_fn = &record_socket_family_and_open,
            .sendto_fn = &record_sendto_socket_fd_for_backend_tests,
        },
    };

    SocketIoBackend backend(QuicUdpBackendConfig{
        .role_name = "server",
    });

    sockaddr_storage ipv4_peer{};
    auto &ipv4 = *reinterpret_cast<sockaddr_in *>(&ipv4_peer);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(4433);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sockaddr_storage ipv6_peer{};
    auto &ipv6 = *reinterpret_cast<sockaddr_in6 *>(&ipv6_peer);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(4434);
    ipv6.sin6_addr = in6addr_loopback;

    const auto first = backend.ensure_route(QuicIoRemote{
        .peer = ipv4_peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });
    ASSERT_TRUE(first.has_value());

    const auto second = backend.ensure_route(QuicIoRemote{
        .peer = ipv6_peer,
        .peer_len = sizeof(sockaddr_in6),
        .family = AF_INET6,
    });
    ASSERT_TRUE(second.has_value());
    const auto first_handle = coquic::quic::test_support::optional_value_or_terminate(first);
    const auto second_handle = coquic::quic::test_support::optional_value_or_terminate(second);
    EXPECT_NE(first_handle, second_handle);

    EXPECT_TRUE(backend.send(QuicIoTxDatagram{
        .route_handle = first_handle,
        .bytes = {std::byte{0x01}},
    }));
    const int first_socket_fd = g_multi_socket_backend_test_trace.last_send_socket_fd;
    ASSERT_GE(first_socket_fd, 0);

    EXPECT_TRUE(backend.send(QuicIoTxDatagram{
        .route_handle = second_handle,
        .bytes = {std::byte{0x02}},
    }));
    EXPECT_NE(g_multi_socket_backend_test_trace.last_send_socket_fd, first_socket_fd);
    EXPECT_EQ(g_multi_socket_backend_test_trace.opened_families,
              (std::vector<int>{AF_INET, AF_INET6}));
}

TEST(SocketIoBackendTest, WaitPollsAllActiveRouteSocketsAndReturnsSecondRouteDatagram) {
    using namespace coquic::io;

    reset_multi_socket_backend_test_trace();
    const coquic::io::test::ScopedSocketIoBackendOpsOverride runtime_ops{
        coquic::io::test::SocketIoBackendOpsOverride{
            .socket_fn = &record_socket_family_and_open,
            .poll_fn = &record_poll_descriptor_count_and_second_readable,
            .recvmsg_fn = &recvmsg_for_backend_tests,
        },
    };

    SocketIoBackend backend(QuicUdpBackendConfig{
        .role_name = "client",
        .idle_timeout_ms = 5,
    });

    sockaddr_storage first_peer{};
    auto &first_ipv4 = *reinterpret_cast<sockaddr_in *>(&first_peer);
    first_ipv4.sin_family = AF_INET;
    first_ipv4.sin_port = htons(8443);
    first_ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sockaddr_storage second_peer{};
    auto &second_ipv6 = *reinterpret_cast<sockaddr_in6 *>(&second_peer);
    second_ipv6.sin6_family = AF_INET6;
    second_ipv6.sin6_port = htons(9443);
    second_ipv6.sin6_addr = in6addr_loopback;

    const auto first = backend.ensure_route(QuicIoRemote{
        .peer = first_peer,
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });
    ASSERT_TRUE(first.has_value());

    const auto second = backend.ensure_route(QuicIoRemote{
        .peer = second_peer,
        .peer_len = sizeof(sockaddr_in6),
        .family = AF_INET6,
    });
    ASSERT_TRUE(second.has_value());
    const auto second_handle = coquic::quic::test_support::optional_value_or_terminate(second);

    ASSERT_GE(g_multi_socket_backend_test_trace.opened_fds.size(), 2u);
    g_multi_socket_backend_test_trace.readable_socket_fd =
        g_multi_socket_backend_test_trace.opened_fds[1];

    const auto event = backend.wait(std::nullopt);
    ASSERT_TRUE(event.has_value());
    const auto &event_value = coquic::quic::test_support::optional_ref_or_terminate(event);
    EXPECT_EQ(event_value.kind, QuicIoEvent::Kind::rx_datagram);
    ASSERT_TRUE(event_value.datagram.has_value());
    const auto &datagram =
        coquic::quic::test_support::optional_ref_or_terminate(event_value.datagram);
    EXPECT_EQ(datagram.route_handle, second_handle);
    EXPECT_EQ(g_multi_socket_backend_test_trace.last_poll_descriptor_count, 2u);
}

TEST(SocketIoBackendTest, WaitReturnsSecondRouteDatagramForHooks) {
    EXPECT_TRUE(coquic::io::test::socket_io_backend_wait_returns_second_route_datagram_for_tests());
}

TEST(SocketIoBackendTest, SharedUdpBackendCoreOpenListenerFailsWhenEngineRejectsSocket) {
    using namespace coquic::io;

    auto engine = std::make_unique<ScriptedIoEngine>();
    auto *engine_ptr = engine.get();
    engine_ptr->register_result = false;
    SharedUdpBackendCore backend(
        QuicUdpBackendConfig{
            .role_name = "server",
        },
        std::move(engine));

    EXPECT_FALSE(backend.open_listener("127.0.0.1", 0));
    ASSERT_EQ(engine_ptr->registered_sockets.size(), 1u);
    EXPECT_GE(engine_ptr->registered_sockets.front(), 0);
}

TEST(SocketIoBackendTest, SharedUdpBackendCoreEnsureRouteRejectsUnknownFamily) {
    using namespace coquic::io;

    auto engine = std::make_unique<ScriptedIoEngine>();
    SharedUdpBackendCore backend(
        QuicUdpBackendConfig{
            .role_name = "client",
        },
        std::move(engine));

    auto peer = make_ipv4_loopback_peer(4433);
    peer.ss_family = AF_UNIX;
    const auto route = backend.ensure_route(QuicIoRemote{
        .peer = peer,
        .peer_len = sizeof(sockaddr_storage),
        .family = AF_UNSPEC,
    });

    EXPECT_FALSE(route.has_value());
}

TEST(SocketIoBackendTest, SharedUdpBackendCoreEnsureRouteRejectsOversizedPeerStorage) {
    using namespace coquic::io;

    auto engine = std::make_unique<ScriptedIoEngine>();
    SharedUdpBackendCore backend(
        QuicUdpBackendConfig{
            .role_name = "client",
        },
        std::move(engine));

    const auto route = backend.ensure_route(QuicIoRemote{
        .peer = make_ipv4_loopback_peer(4433),
        .peer_len = static_cast<socklen_t>(sizeof(sockaddr_storage) + 1),
        .family = AF_INET,
    });

    EXPECT_FALSE(route.has_value());
}

TEST(SocketIoBackendTest, SharedUdpBackendCoreEnsureRouteFailsWhenEngineRejectsNewSocket) {
    using namespace coquic::io;

    auto engine = std::make_unique<ScriptedIoEngine>();
    auto *engine_ptr = engine.get();
    engine_ptr->register_result = false;
    SharedUdpBackendCore backend(
        QuicUdpBackendConfig{
            .role_name = "client",
        },
        std::move(engine));

    const auto route = backend.ensure_route(QuicIoRemote{
        .peer = make_ipv4_loopback_peer(4433),
        .peer_len = sizeof(sockaddr_in),
        .family = AF_INET,
    });

    EXPECT_FALSE(route.has_value());
    ASSERT_EQ(engine_ptr->registered_sockets.size(), 1u);
    EXPECT_GE(engine_ptr->registered_sockets.front(), 0);
}

TEST(SocketIoBackendTest, SharedUdpBackendCoreWaitIgnoresReceiveEventWithoutCompletionPayload) {
    using namespace coquic::io;

    auto engine = std::make_unique<ScriptedIoEngine>();
    auto *engine_ptr = engine.get();
    engine_ptr->scripted_wait_results.push_back(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::rx_datagram,
        .now = coquic::quic::test::test_time(7),
    });
    SharedUdpBackendCore backend(
        QuicUdpBackendConfig{
            .role_name = "server",
            .idle_timeout_ms = 5,
        },
        std::move(engine));

    ASSERT_TRUE(backend.open_listener("127.0.0.1", 0));
    EXPECT_FALSE(backend.wait(std::nullopt).has_value());
    EXPECT_EQ(engine_ptr->last_wait_socket_count, 1u);
}

TEST(SocketIoBackendTest, SharedUdpBackendCoreWaitTranslatesNonReceiveEvents) {
    using namespace coquic::io;

    auto engine = std::make_unique<ScriptedIoEngine>();
    auto *engine_ptr = engine.get();
    engine_ptr->scripted_wait_results.push_back(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::timer_expired,
        .now = coquic::quic::test::test_time(11),
    });
    engine_ptr->scripted_wait_results.push_back(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::idle_timeout,
        .now = coquic::quic::test::test_time(12),
    });
    engine_ptr->scripted_wait_results.push_back(QuicIoEngineEvent{
        .kind = QuicIoEngineEvent::Kind::shutdown,
        .now = coquic::quic::test::test_time(13),
    });
    SharedUdpBackendCore backend(
        QuicUdpBackendConfig{
            .role_name = "server",
            .idle_timeout_ms = 5,
        },
        std::move(engine));

    ASSERT_TRUE(backend.open_listener("127.0.0.1", 0));

    const auto timer_event = backend.wait(std::nullopt);
    if (!timer_event.has_value()) {
        FAIL() << "expected timer event";
        return;
    }
    const auto &resolved_timer_event = timer_event.value();
    EXPECT_EQ(resolved_timer_event.kind, QuicIoEvent::Kind::timer_expired);
    EXPECT_EQ(resolved_timer_event.now, coquic::quic::test::test_time(11));

    const auto idle_event = backend.wait(std::nullopt);
    if (!idle_event.has_value()) {
        FAIL() << "expected idle event";
        return;
    }
    const auto &resolved_idle_event = idle_event.value();
    EXPECT_EQ(resolved_idle_event.kind, QuicIoEvent::Kind::idle_timeout);
    EXPECT_EQ(resolved_idle_event.now, coquic::quic::test::test_time(12));

    const auto shutdown_event = backend.wait(std::nullopt);
    if (!shutdown_event.has_value()) {
        FAIL() << "expected shutdown event";
        return;
    }
    const auto &resolved_shutdown_event = shutdown_event.value();
    EXPECT_EQ(resolved_shutdown_event.kind, QuicIoEvent::Kind::shutdown);
    EXPECT_EQ(resolved_shutdown_event.now, coquic::quic::test::test_time(13));

    EXPECT_EQ(engine_ptr->last_wait_socket_count, 1u);
}

TEST(SocketIoBackendTest, ConfiguresLinuxSocketsForReceivingEcnMetadata) {
    EXPECT_TRUE(
        coquic::io::test::socket_io_backend_configures_linux_ecn_socket_options_for_tests());
}

TEST(SocketIoBackendTest, UsesSendmsgToApplyOutboundEcnMarkings) {
    EXPECT_TRUE(coquic::io::test::socket_io_backend_sendmsg_uses_outbound_ecn_for_tests());
}

TEST(SocketIoBackendTest, UsesIpTosForIpv4MappedIpv6OutboundEcnMarkings) {
    EXPECT_TRUE(coquic::io::test::
                    socket_io_backend_sendmsg_uses_ip_tos_for_ipv4_mapped_ipv6_peer_for_tests());
}

TEST(SocketIoBackendTest, MapsRecvmsgEcnMetadataIntoEvents) {
    EXPECT_TRUE(coquic::io::test::socket_io_backend_recvmsg_maps_ecn_for_tests());
}

TEST(SocketIoBackendTest, InternalCoverageHookExercisesColdPaths) {
    EXPECT_TRUE(coquic::io::test::
                    socket_io_backend_internal_coverage_hook_exercises_cold_paths_for_tests());
}

TEST(SocketIoBackendTest, InternalCoverageHookExercisesRemainingBranches) {
    EXPECT_TRUE(
        coquic::io::test::
            socket_io_backend_internal_coverage_hook_exercises_remaining_branches_for_tests());
}

TEST(SocketIoBackendTest, PollIoEngineInternalCoverageHookExercisesRemainingBranches) {
    EXPECT_TRUE(coquic::io::test::
                    poll_io_engine_internal_coverage_hook_exercises_remaining_branches_for_tests());
}

TEST(SocketIoBackendTest, PollIoEngineDescriptorCacheGuardBranchesAreCovered) {
    EXPECT_TRUE(coquic::io::test::poll_io_engine_descriptor_cache_guard_branches_for_tests());
}

TEST(SocketIoBackendTest, DuplicateRouteLookupGuardBranchesAreCovered) {
    EXPECT_TRUE(
        coquic::io::test::socket_io_backend_duplicate_route_lookup_guard_branches_for_tests());
}

} // namespace
