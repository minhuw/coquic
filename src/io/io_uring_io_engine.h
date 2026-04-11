#pragma once

#include <array>
#include <deque>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "src/io/io_engine.h"

struct io_uring;

namespace coquic::io {

class IoUringIoEngine final : public QuicIoEngine {
  public:
    ~IoUringIoEngine() override;

    IoUringIoEngine(const IoUringIoEngine &) = delete;
    IoUringIoEngine &operator=(const IoUringIoEngine &) = delete;

    static std::unique_ptr<IoUringIoEngine> create();

    bool register_socket(int socket_fd) override;
    bool send(int socket_fd, const sockaddr_storage &peer, socklen_t peer_len,
              std::span<const std::byte> datagram, std::string_view role_name,
              quic::QuicEcnCodepoint ecn) override;
    std::optional<QuicIoEngineEvent> wait(std::span<const int> socket_fds, int idle_timeout_ms,
                                          std::optional<quic::QuicCoreTimePoint> next_wakeup,
                                          std::string_view role_name) override;

  private:
    struct ReceiveState {
        int socket_fd = -1;
        std::vector<std::byte> data;
        std::array<std::byte, 128> control{};
        sockaddr_storage peer{};
        iovec iov{};
        msghdr message{};
    };

    struct Completion {
        std::uint64_t user_data = 0;
        int res = 0;
    };

    IoUringIoEngine();
    bool initialize();
    bool arm_receive(ReceiveState &state);
    quic::QuicEcnCodepoint decode_linux_ecn_from_control(const msghdr &message) const;
    void apply_linux_ecn_send_control(
        msghdr &message, std::array<std::byte, CMSG_SPACE(sizeof(int))> &control_storage,
        quic::QuicEcnCodepoint ecn, const sockaddr_storage &peer, socklen_t peer_len) const;
    bool drain_one_completion(Completion &completion);

    std::unique_ptr<io_uring> ring_;
    bool initialized_ = false;
    bool healthy_ = false;
    std::unordered_map<int, ReceiveState> receives_;
    std::deque<Completion> pending_completions_;
    std::array<std::byte, CMSG_SPACE(sizeof(int))> send_control_{};
};

std::unique_ptr<QuicIoEngine> make_io_uring_io_engine();

} // namespace coquic::io
