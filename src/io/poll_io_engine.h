#pragma once

#include "src/io/io_engine.h"

#include <poll.h>

#include <cstddef>
#include <deque>
#include <vector>

namespace coquic::io {

namespace test {
bool socket_io_backend_poll_engine_primes_descriptor_cache_for_tests();
bool poll_io_engine_descriptor_cache_guard_branches_for_tests();
} // namespace test

class PollIoEngine final : public QuicIoEngine {
  public:
    PollIoEngine() = default;
    ~PollIoEngine() override = default;

    bool register_socket(int socket_fd) override;
    bool send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
              std::span<const std::byte> datagram, std::string_view role_name,
              quic::QuicEcnCodepoint ecn, bool is_pmtu_probe = false) override;
    bool send_many(std::span<const QuicIoEngineTxDatagram> datagrams,
                   std::string_view role_name) override;
    std::optional<QuicIoEngineEvent> wait(std::span<const int> socket_fds, int idle_timeout_ms,
                                          std::optional<quic::QuicCoreTimePoint> next_wakeup,
                                          std::string_view role_name) override;

  private:
    std::deque<QuicIoEngineEvent> queued_events_;
    std::vector<pollfd> descriptor_scratch_;
    std::size_t registered_socket_count_ = 0;

    friend bool test::socket_io_backend_poll_engine_primes_descriptor_cache_for_tests();
    friend bool test::poll_io_engine_descriptor_cache_guard_branches_for_tests();
};

} // namespace coquic::io
